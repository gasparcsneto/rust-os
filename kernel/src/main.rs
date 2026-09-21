//! # Kernel agent-native em Rust
//!
//! Um kernel x86_64 escrito do zero, projetado desde o início para ser
//! operado por um agente (Claude) além de por humanos.
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
    let canal_agente = serial::init();

    serial_println!();
    serial_println!("=============================================");
    serial_println!("  kernel agent-native :: fase 0 :: boot ok");
    serial_println!("=============================================");

    // Primeira prova concreta de que o contrato com o bootloader funcionou:
    // se estes números fizerem sentido, recebemos o `BootInfo` corretamente.
    let regioes = boot_info.memory_regions.len();
    serial_println!("[boot] regioes de memoria descritas .. {}", regioes);

    let total_utilizavel: u64 = boot_info
        .memory_regions
        .iter()
        .filter(|r| r.kind == bootloader_api::info::MemoryRegionKind::Usable)
        .map(|r| r.end - r.start)
        .sum();
    serial_println!(
        "[boot] memoria utilizavel ............ {} MiB",
        total_utilizavel / 1024 / 1024
    );

    match boot_info.framebuffer.as_ref() {
        Some(fb) => {
            let info = fb.info();
            serial_println!(
                "[boot] framebuffer ................... {}x{} ({:?})",
                info.width,
                info.height,
                info.pixel_format
            );
        }
        None => serial_println!("[boot] framebuffer ................... ausente"),
    }

    serial_println!(
        "[boot] canal do agente (COM2) ............ {}",
        if canal_agente {
            "disponivel"
        } else {
            "ausente"
        }
    );
    serial_println!("[boot] kernel ocioso; aguardando interrupcoes");

    hlt_loop()
}

/// Chamado pelo compilador quando qualquer código do kernel entra em pânico.
///
/// Num programa comum o pânico desenrola a stack e mata a thread. Aqui não há
/// para onde voltar: um pânico no kernel é terminal. O melhor que podemos
/// fazer é registrar o máximo de contexto possível na serial — essa mensagem
/// costuma ser a única evidência disponível de por que a máquina morreu.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Não usamos `without_interrupts` aqui de propósito: se o pânico veio de
    // dentro de um handler de interrupção que já segurava o lock da serial,
    // qualquer tentativa de ser "correto" acabaria em deadlock, e um deadlock
    // engoliria a mensagem de pânico. Perder a mensagem é pior.
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
