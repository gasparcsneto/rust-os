//! # Kernel agent-native em Rust
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

mod agent;
mod arch;
mod log;
mod machine;
mod irq;
mod qemu;
mod serial;
mod tempo;
mod traps;

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

    log_info!("boot", "kernel iniciado em {}, fase 0", arch::nome());

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

    if canal_agente {
        log_info!("agent", "canal do agente disponivel");
        // A partir daqui o kernel é dirigido pelo agente. Esta chamada nunca
        // retorna: ela é o laço principal do sistema nesta fase.
        agent::servir()
    } else {
        log_error!("agent", "nenhuma porta serial para o canal do agente");
        arch::halt_forever()
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
    serial_println!("  kernel agent-native :: {} :: fase 0", arch::nome());
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

    arch::halt_forever()
}
