//! # Kernel agent-native em Rust
//!
//! Um kernel x86_64 escrito do zero, projetado desde o início para ser
//! operado por um agente (Claude) além de por humanos.
//!
//! ## O que "agent-native" significa aqui
//!
//! Não é um cliente de API embutido no kernel. É um conjunto de decisões de
//! projeto que tornam o sistema legível e operável por máquina:
//!
//! - Um [canal estruturado](agent) JSON-RPC sobre a COM2, separado do console
//!   humano, ativo desde o primeiro milissegundo do boot.
//! - Um [registro de comandos](agent::registry) que descreve a si mesmo, de
//!   modo que o agente descubra a superfície do sistema em vez de adivinhá-la.
//! - [Logging estruturado](log): todo evento é um registro tipado num ring
//!   buffer consultável, não texto solto para parsear com regex.
//!
//! ## Os dois atributos do topo
//!
//! `#![no_std]` desliga a biblioteca padrão. A `std` assume um sistema
//! operacional por baixo — ela quer threads, arquivos, sockets e um heap
//! prontos. Nós *somos* o sistema operacional, então nada disso existe ainda.
//! Ficamos com a `core`: a parte da std que não depende de SO (tipos
//! primitivos, `Option`, `Result`, iteradores, formatação).
//!
//! `#![no_main]` desliga o ponto de entrada normal do Rust. Um binário comum
//! começa na `main` da libc, que prepara argumentos e ambiente antes de
//! chamar a sua `main`. Não há libc aqui: quem nos chama é o bootloader, com
//! uma convenção própria, declarada pela macro `entry_point!` abaixo.

#![no_std]
#![no_main]

mod agent;
mod boot;
mod log;
mod qemu;
mod serial;

use core::panic::PanicInfo;

use bootloader_api::BootInfo;

// Declara `kernel_main` como o ponto de entrada do kernel.
//
// A macro gera um símbolo `_start` com a ABI que o bootloader espera e, o
// mais importante, faz uma verificação de tipo da assinatura em tempo de
// compilação. Sem isso, uma divergência entre o que o bootloader passa e o
// que o kernel espera viraria corrupção de memória silenciosa no boot.
//
// (Comentário `//` e não `///` de propósito: rustdoc não documenta invocações
// de macro, e um doc comment aqui vira warning.)
bootloader_api::entry_point!(kernel_main);

/// Primeira função Rust a executar depois do bootloader.
///
/// O `boot_info` é a única fonte de verdade sobre a máquina neste ponto: mapa
/// de memória física, endereço do framebuffer e o offset onde toda a memória
/// física está mapeada. Ele é um `&'static mut` porque o bootloader entrega a
/// posse exclusiva da estrutura ao kernel — não existe mais ninguém rodando.
fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // A serial vem antes de qualquer outra coisa. Sem ela, qualquer falha a
    // partir daqui seria uma tela preta sem diagnóstico.
    let canal_agente = serial::init();

    // Reduzimos de `&'static mut` para `&'static` compartilhado. O kernel não
    // precisa de acesso exclusivo ao BootInfo, e compartilhá-lo permite que
    // vários subsistemas o consultem sem passá-lo por toda chamada.
    //
    // (Quando o driver de framebuffer chegar, ele vai precisar do buffer de
    // pixels em modo exclusivo — nessa hora o framebuffer sai daqui com um
    // `.take()` *antes* deste ponto.)
    let boot_info: &'static BootInfo = boot_info;
    boot::registrar(boot_info);

    banner();

    log_info!("boot", "kernel iniciado, fase 0");

    let regioes = boot_info.memory_regions.len();
    let utilizavel: u64 = boot_info
        .memory_regions
        .iter()
        .filter(|r| r.kind == bootloader_api::info::MemoryRegionKind::Usable)
        .map(|r| r.end - r.start)
        .sum();
    log_info!(
        "mem",
        "{} regioes no mapa, {} MiB utilizaveis",
        regioes,
        utilizavel / 1024 / 1024
    );

    match boot_info.framebuffer.as_ref() {
        Some(fb) => {
            let info = fb.info();
            log_info!(
                "video",
                "framebuffer {}x{} {:?}",
                info.width,
                info.height,
                info.pixel_format
            );
        }
        None => log_warn!("video", "nenhum framebuffer fornecido pelo bootloader"),
    }

    if canal_agente {
        log_info!("agent", "COM2 presente, canal do agente ativo");
        // A partir daqui o kernel é dirigido pelo agente. Esta chamada nunca
        // retorna: ela é o laço principal do sistema nesta fase.
        agent::servir()
    } else {
        // Sem COM2 o kernel ainda é útil como demonstração, mas não há nada
        // para atender. Avisamos alto: rodar sem o canal quase sempre
        // significa que faltou um `-serial` na linha do QEMU.
        log_error!(
            "agent",
            "COM2 ausente; o canal do agente nao pode ser atendido"
        );
        hlt_loop()
    }
}

fn banner() {
    serial_println!();
    serial_println!("=============================================");
    serial_println!("  kernel agent-native :: fase 0");
    serial_println!("  COM1 = console humano | COM2 = canal JSON-RPC");
    serial_println!("=============================================");
}

/// Chamado pelo compilador quando qualquer código do kernel entra em pânico.
///
/// Num programa comum o pânico desenrola a stack e mata a thread. Aqui não há
/// para onde voltar: um pânico no kernel é terminal. O melhor que podemos
/// fazer é registrar o máximo de contexto possível na serial — essa mensagem
/// costuma ser a única evidência disponível de por que a máquina morreu.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Escrevemos direto na serial, sem passar pelo `log`: o caminho de log
    // pega o lock do ring buffer, e se o pânico veio de dentro de uma seção
    // que já o segurava, tentaríamos um lock não reentrante e travaríamos.
    // Perder a mensagem de pânico num deadlock é o pior desfecho possível.
    serial_println!();
    serial_println!("!!! PANICO NO KERNEL !!!");
    serial_println!("{}", info);

    hlt_loop()
}

/// Para a CPU até a próxima interrupção, para sempre.
///
/// Prefira isto a `loop {}`. Um loop vazio mantém o núcleo em 100% de uso
/// girando à toa; `hlt` coloca a CPU em estado de baixo consumo e ela só
/// acorda quando há trabalho de verdade (uma interrupção).
pub fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}
