//! # Duke — kernel agent-native em Rust
//!
//! Um kernel escrito do zero para **x86_64 e aarch64**, projetado desde o
//! início para ser operado por um agente além de por humanos.
//!
//! ## O que "agent-native" significa aqui
//!
//! Não é um cliente de API embutido no kernel. É um conjunto de decisões de
//! projeto que tornam o sistema legível e operável por máquina:
//!
//! - Um [canal estruturado](agent) JSON-RPC sobre a porta serial, ativo desde
//!   o primeiro milissegundo do boot.
//! - Um [registro de comandos](agent::registry) que descreve a si mesmo, de
//!   modo que o agente descubra a superfície do sistema em vez de adivinhá-la.
//! - [Logging estruturado](log): todo evento é um registro tipado num ring
//!   buffer consultável, não texto solto para parsear com regex.
//! - [Falhas contabilizadas](traps) e um **modo post-mortem**: uma exceção
//!   fatal não mata o canal do agente, que segue respondendo o que aconteceu.
//!
//! No ARM essa premissa deixa de ser conveniência e vira necessidade: a
//! máquina `virt` do QEMU tem uma única porta serial, então o canal do agente
//! é literalmente a *única* interface de depuração do sistema.
//!
//! ## Os dois atributos do topo
//!
//! `#![no_std]` desliga a biblioteca padrão. A `std` assume um sistema
//! operacional por baixo — ela quer threads, arquivos, sockets e um heap
//! prontos. Nós *somos* o sistema operacional, então nada disso existe ainda.
//! Ficamos com a `core`: a parte da std que não depende de SO.
//!
//! `#![no_main]` desliga o ponto de entrada normal do Rust. Um binário comum
//! começa na `main` da libc, que prepara argumentos e ambiente. Não há libc
//! aqui: quem nos chama é o bootloader (x86) ou diretamente o firmware (ARM),
//! e cada caso é tratado no backend de arquitetura correspondente.

#![no_std]
#![no_main]
// Handlers de interrupção do x86 precisam de uma convenção de chamada própria
// (o retorno é `iretq`, não `ret`, e todos os registradores são preservados).
// O `cfg_attr` mantém o atributo fora do build de ARM, onde a ABI não existe
// e declará-la geraria aviso.
#![cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]

// A `alloc` é a parte da biblioteca padrão que depende apenas de um alocador,
// e não de um sistema operacional. Com o heap no ar, ela nos dá `Box`, `Vec`,
// `String` e companhia — o vocabulário normal do Rust, que até aqui estava
// fora de alcance.
extern crate alloc;

mod agent;
mod arch;
mod fios;
mod frames;
mod heap;
mod irq;
mod log;
mod machine;
mod mmio;
mod paginacao;
mod pci;
mod qemu;
mod rede;
mod serial;
mod tarefas;
mod tempo;
#[cfg(feature = "modo-teste")]
mod testes;
mod traps;
mod usuario;
mod virtio;

use core::panic::PanicInfo;

/// O fluxo de boot comum às duas arquiteturas.
///
/// Quando chegamos aqui, o backend de arquitetura já fez o trabalho sujo: as
/// seriais estão abertas e [`machine`] está preenchido com o mapa de memória
/// e o vídeo. Daqui para baixo, nenhuma linha do kernel sabe em que
/// processador está rodando.
///
/// `canal_agente` diz se há um canal do agente disponível.
pub fn inicio_comum(canal_agente: bool) -> ! {
    banner();

    log_info!("boot", "Duke iniciado em {}, fase 0", arch::nome());

    let cpu = arch::identificar_cpu();
    log_info!("cpu", "fabricante: {}", cpu.como_str());

    // Instalar exceções cedo é o que transforma qualquer falha posterior num
    // relatório em vez de num reboot silencioso. Tudo que vem depois desta
    // linha é depurável.
    arch::init_excecoes();

    // Com exceções instaladas, é seguro ligar as interrupções de hardware.
    // A partir daqui o kernel tem noção de tempo, e os registros de log
    // passam a carregar um carimbo de uptime de verdade.
    arch::init_interrupcoes();

    let (utilizavel, total, regioes) = machine::estatisticas();
    log_info!(
        "mem",
        "{} regioes, {} MiB utilizaveis de {} MiB mapeados",
        regioes,
        utilizavel / 1024 / 1024,
        total / 1024 / 1024
    );

    let descartadas = machine::regioes_descartadas();
    if descartadas > 0 {
        // Nunca deixamos um mapa truncado passar em silêncio: um agente não
        // tem como desconfiar de um número que parece plausível.
        log_warn!(
            "mem",
            "{} regioes descartadas por falta de espaco na tabela",
            descartadas
        );
    }

    // O alocador de frames precisa do mapa de memória já traduzido, e das
    // faixas que cada arquitetura sabe estarem ocupadas.
    frames::init();

    // Com frames disponíveis, a paginação pode criar tabelas. No x86 isto
    // assume o controle do que o bootloader montou; no ARM, liga a MMU pela
    // primeira vez.
    arch::init_paginacao();

    // Com a paginação no ar, o heap pode mapear sua faixa. A partir daqui o
    // kernel pode alocar memória dinâmica.
    if let Err(motivo) = heap::init() {
        log_error!("heap", "nao foi possivel inicializar: {}", motivo);
    }

    match machine::video() {
        Some(v) => log_info!(
            "video",
            "framebuffer {}x{} {} ({} bytes/pixel)",
            v.largura,
            v.altura,
            v.formato,
            v.bytes_por_pixel
        ),
        None => log_info!("video", "nenhum framebuffer nesta plataforma"),
    }

    // Com a GDT carregada, o mecanismo de chamadas de sistema pode ser
    // ligado. Precisa vir antes de qualquer processo existir, e depois das
    // exceções: uma chamada atendida com metade da configuração no lugar
    // saltaria para um endereço indefinido.
    //
    // SAFETY: `init_excecoes` já carregou a GDT de onde saem os seletores.
    unsafe { arch::init_usuario() };

    // Com heap e paginação no ar, o escalonador pode adotar o contexto atual
    // como primeiro fio de execução. A partir daqui o kernel é preemptável: o
    // timer pode tirar a CPU de quem estiver rodando.
    fios::init();

    // Com paginação e heap no ar, o barramento pode ser varrido: é a primeira
    // vez que o kernel pergunta ao hardware o que existe em vez de já saber.
    arch::init_pci();
    pci::init();

    // E com o barramento varrido, os dispositivos que ele revelou podem ser
    // ligados. A ordem não é escolha: um driver virtio precisa dos BARs já
    // atribuídos e do decodificador já ligado, que é o que a varredura faz.
    virtio::blk::init();
    virtio::net::init();

    // Com heap e interrupções no ar, a serial do agente pode deixar de ser
    // consultada em laço e passar a avisar quando chega um byte. É o que
    // transforma o canal numa tarefa que dorme de verdade.
    if canal_agente {
        arch::init_interrupcao_serial();
    }

    // Em modo de teste o kernel não atende ninguém: roda a suíte, imprime o
    // relatório e encerra o emulador com um código que o CI interpreta.
    #[cfg(feature = "modo-teste")]
    testes::executar_todos();

    #[cfg(not(feature = "modo-teste"))]
    if canal_agente {
        log_info!("agent", "canal do agente disponivel");
        // A partir daqui o kernel é dirigido pelo escalonador cooperativo, e
        // o canal do agente é apenas uma das tarefas que ele roda. Esta
        // chamada nunca retorna: é o laço principal do sistema.
        let mut executor = tarefas::executor::Executor::novo();
        executor.lancar(tarefas::Tarefa::nova("agent", agent::atender()));
        executor.lancar(tarefas::Tarefa::nova("pulso", pulso()));
        executor.rodar()
    } else {
        log_error!("agent", "nenhuma porta serial para o canal do agente");
        arch::halt_forever()
    }
}

/// Batimento periódico: registra que o sistema está vivo.
///
/// Existe por duas razões. A prática: um agente lendo `log.tail` consegue
/// distinguir "o kernel travou" de "o kernel está ocioso" sem precisar fazer
/// uma pergunta. E a didática: é a segunda tarefa do executor, o que torna a
/// concorrência visível — enquanto ela dorme um minuto inteiro, o canal do
/// agente segue atendendo normalmente, no mesmo núcleo e na mesma pilha.
///
/// O intervalo é longo de propósito. O ring buffer de log tem tamanho fixo, e
/// um batimento frequente empurraria para fora dele justamente os registros
/// do boot, que são os mais úteis.
#[cfg(not(feature = "modo-teste"))]
async fn pulso() {
    const INTERVALO_MS: u64 = 60_000;

    loop {
        tarefas::relogio::por_ms(INTERVALO_MS).await;
        log_debug!("pulso", "vivo ha {} ms", tempo::uptime_ms());
    }
}

/// Cabeçalho no console humano.
///
/// Em plataformas sem console de texto (o ARM, por ora) isto é um no-op
/// silencioso — a mesma informação está nos registros de log, acessíveis via
/// `log.tail` pelo canal do agente.
fn banner() {
    serial_println!();
    serial_println!("=============================================");
    serial_println!("  Duke :: agent-native :: {} :: fase 0", arch::nome());
    serial_println!("=============================================");
}

/// Chamado pelo compilador quando qualquer código do kernel entra em pânico.
///
/// Num programa comum o pânico desenrola a stack e mata a thread. Aqui não há
/// para onde voltar: um pânico no kernel é terminal. O melhor que podemos
/// fazer é registrar o máximo de contexto possível — essa mensagem costuma
/// ser a única evidência disponível de por que a máquina morreu.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Escrevemos direto na serial, sem passar pelo `log`: o caminho de log
    // pega o lock do ring buffer, e se o pânico veio de dentro de uma seção
    // que já o segurava, tentaríamos um lock não reentrante e travaríamos.
    // Perder a mensagem de pânico num deadlock é o pior desfecho possível.
    serial_println!();
    serial_println!("!!! PANICO NO KERNEL !!!");
    serial_println!("{}", info);

    // Na suíte de testes, parar a CPU seria o pior desfecho possível: o
    // emulador ficaria rodando para sempre e o CI penduraria até estourar o
    // tempo do job, sem dizer o que houve. Encerramos com código de falha, que
    // é o que transforma um pânico em "teste falhou" em vez de "trabalho
    // travado".
    #[cfg(feature = "modo-teste")]
    qemu::encerrar(qemu::Resultado::Falha);

    #[cfg(not(feature = "modo-teste"))]
    arch::halt_forever()
}
