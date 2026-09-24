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
mod tela;
mod tempo;
#[cfg(feature = "modo-teste")]
mod testes;
mod traps;
mod usuario;
mod virtio;

use core::panic::PanicInfo;

/// Para o boot quando falta uma base sobre a qual tudo o que vem depois se
/// apoia, e continua respondendo pelo caminho que não depende dela.
///
/// # Por que parar, e não seguir tolerando
///
/// Porque seguir não é tolerância: é adiar a morte e piorar o relato. Os dois
/// chamadores mediram isso.
///
/// Sem **heap**, o kernel atravessava mais vinte linhas de log e morria com
///
///     panicked at library/alloc/src/alloc.rs:673:9:
///     memory allocation of 8 bytes failed
///
/// — uma mensagem que aponta para o primeiro que tentou alocar, e não para a
/// causa, que passou muito antes e ficou para trás no log.
///
/// Sem **frames** é pior, porque a linha seguinte liga a MMU: a tabela de
/// tradução nasce sem mapear nada, a busca da próxima instrução aborta, e o
/// vetor que atenderia esse abort está igualmente desmapeado. Medido, com um
/// device tree ilegível: 21,3 milhões de prefetch aborts em vinte segundos,
/// sem um byte de saída e sem post-mortem.
///
/// # Por que o canal ainda funciona aqui
///
/// Porque [`agent::servir`] é o mesmo caminho direto do modo post-mortem: não
/// aloca, não depende do escalonador, e a serial já está aberta desde o
/// primeiro milissegundo do boot. Parar e continuar respondendo sobre o que
/// aconteceu é incomparavelmente mais útil que morrer adiante.
///
/// Está numa função só porque os dois desfechos precisam ser o mesmo. Duas
/// cópias divergiriam na primeira correção que só uma recebesse — e foi
/// exatamente assim que o caminho de frames ficou para trás do de heap.
//
// `canal_agente` só é consultado fora do modo de teste, onde o desfecho é o
// código de saída e não um canal aberto.
#[cfg_attr(feature = "modo-teste", allow(unused_variables))]
fn parar_sem_base(subsistema: &'static str, motivo: &str, canal_agente: bool) -> ! {
    log_error!(subsistema, "nao foi possivel inicializar: {}", motivo);
    log_error!(
        subsistema,
        "tudo daqui para baixo depende disto; o kernel para nesta linha"
    );

    // A suíte precisa das duas bases para existir, então em modo de teste o
    // desfecho é o código de falha que o CI entende — e não um canal aberto
    // que ninguém vai consultar.
    #[cfg(feature = "modo-teste")]
    qemu::encerrar(qemu::Resultado::Falha);

    #[cfg(not(feature = "modo-teste"))]
    if canal_agente {
        agent::servir()
    } else {
        arch::halt_forever()
    }
}

/// Registra no log a tela que existe, e desenha o indicador de vida.
///
/// Devolve se havia uma. Os dois chamadores precisam saber: o primeiro porque
/// no ARM ninguém procurou ainda, e o segundo porque é ele quem reporta a
/// ausência **depois** de ter procurado.
fn anunciar_tela() -> bool {
    let Some(t) = tela::tela() else {
        return false;
    };

    log_info!(
        "video",
        "framebuffer {}x{} {} ({} bytes/pixel)",
        t.largura,
        t.altura,
        t.formato.como_str(),
        t.bytes_por_pixel
    );
    // O indicador de que há um kernel vivo desenhando. Vem logo depois do
    // log, e não antes, para que uma falha ao desenhar apareça depois de já
    // sabermos que a tela existe.
    tela::banner();
    true
}

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

    let mem = machine::estatisticas();
    log_info!(
        "mem",
        "{} regioes: {} MiB utilizaveis, {} MiB retidos pelo bootloader, {} MiB de espaco descrito",
        mem.regioes,
        mem.utilizavel / 1024 / 1024,
        mem.bootloader / 1024 / 1024,
        mem.descrito / 1024 / 1024
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
    //
    // Sem frames o boot não continua, e a razão é mais dura que a do heap: a
    // linha seguinte liga a MMU, e uma tabela de tradução que não mapeia nada
    // faz a busca da próxima instrução abortar — e o vetor que atenderia esse
    // abort também está desmapeado. Medido, com um device tree ilegível a
    // ponto de não sobrar região nenhuma: 21,3 milhões de prefetch aborts em
    // vinte segundos, sem um byte de saída e sem post-mortem. Um kernel que
    // para aqui, pelo caminho direto que não depende de MMU nem de heap,
    // ainda consegue dizer o que houve.
    if let Err(motivo) = frames::init() {
        parar_sem_base("frames", motivo, canal_agente);
    }

    // Com frames disponíveis, a paginação pode criar tabelas. No x86 isto
    // assume o controle do que o bootloader montou; no ARM, liga a MMU pela
    // primeira vez.
    arch::init_paginacao();

    // Com a paginação no ar, o heap pode mapear sua faixa. A partir daqui o
    // kernel pode alocar memória dinâmica.
    if let Err(motivo) = heap::init() {
        parar_sem_base("heap", motivo, canal_agente);
    }

    // A tela que o firmware entregou pronta, se entregou alguma. É o caso do
    // x86, onde o `bootloader` configura o modo antes de o kernel existir.
    //
    // Não há `else` aqui de propósito: no ARM ninguém entrega nada, e dizer
    // "nenhum framebuffer nesta plataforma" agora seria uma conclusão tirada
    // antes de procurar. Quem procura é [`tela::bochs`], e ele precisa do
    // barramento PCI enumerado — o que só acontece bem mais abaixo.
    anunciar_tela();

    // Com a GDT carregada, o mecanismo de chamadas de sistema pode ser
    // ligado. Precisa vir antes de qualquer processo existir, e depois das
    // exceções: uma chamada atendida com metade da configuração no lugar
    // saltaria para um endereço indefinido.
    //
    // SAFETY: `init_excecoes` já carregou a GDT de onde saem os seletores.
    unsafe { arch::init_usuario() };

    // Com a paginação no ar, o timer provisório do boot pode dar lugar ao
    // definitivo. Antes do escalonador de propósito: é o timer que o
    // preempta, e trocá-lo com fios já rodando seria trocar o chão sob eles.
    arch::init_timer_definitivo();

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
    // Com o barramento enumerado, o adaptador de vídeo pode ser procurado e
    // programado. Só onde ninguém entregou uma tela pronta: no x86, trocar o
    // framebuffer do `bootloader` por outro não consertaria nada.
    if tela::tela().is_none() {
        tela::bochs::init();
        if !anunciar_tela() {
            log_info!("video", "nenhum framebuffer nesta maquina");
        }
    }

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
    // Destravar antes de escrever, exatamente como [`traps::fatal`] faz — e
    // pela mesma razão, que este handler documentava e não aplicava por
    // inteiro.
    //
    // Evitar o `log` cobria uma das duas travas do caminho de saída. A outra
    // é a da própria serial, e um pânico que tenha acontecido com ela na mão
    // — formatando um argumento, por exemplo, que é trabalho feito *dentro*
    // do bloqueio — giraria para sempre em `serial_println!`. O sintoma seria
    // o pior possível: um kernel travado sem uma linha de explicação, que é o
    // oposto do que um handler de pânico existe para dar.
    //
    // SAFETY: o kernel já está em falha irrecuperável, não há outro núcleo
    // rodando, e a alternativa é o deadlock.
    unsafe { serial::destravar() };

    // E para o escalonador, também como no caminho de falha fatal: sem isto o
    // timer continuaria trocando de fio enquanto a mensagem é impressa, e os
    // outros fios rodariam por cima de um estado que já se sabe ruim.
    fios::congelar();

    // Escrevemos direto na serial, sem passar pelo `log`: o caminho de log
    // pega o lock do ring buffer, e se o pânico veio de dentro de uma seção
    // que já o segurava, tentaríamos um lock não reentrante e travaríamos.
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
