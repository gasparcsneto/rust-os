//! Backend de arquitetura para x86_64.
//!
//! No x86 o trabalho pesado de boot já foi feito quando chegamos aqui: o
//! crate `bootloader` cuidou do modo real, da transição para long mode e da
//! montagem das tabelas de página iniciais, e nos entrega um [`BootInfo`]
//! pronto. Este módulo basicamente traduz esse `BootInfo` para as estruturas
//! neutras de [`crate::machine`] e segue para o fluxo comum.

pub mod gdt;
pub mod idt;
pub mod pic;
pub mod uart;

use bootloader_api::BootInfo;
use bootloader_api::info::{MemoryRegionKind, PixelFormat};

use crate::machine::{Regiao, TipoRegiao, Video};

pub use uart::Uart;

/// Nome da arquitetura, exposto no protocolo do agente.
pub const fn nome() -> &'static str {
    "x86_64"
}

// Declara `inicio` como o ponto de entrada do kernel.
//
// A macro gera um símbolo `_start` com a ABI que o bootloader espera e, o
// mais importante, faz uma verificação de tipo da assinatura em tempo de
// compilação. Sem isso, uma divergência entre o que o bootloader passa e o
// que o kernel espera viraria corrupção de memória silenciosa no boot.
bootloader_api::entry_point!(inicio);

/// Primeira função Rust a executar depois do bootloader.
///
/// O `boot_info` é a única fonte de verdade sobre a máquina neste ponto. Ele
/// é um `&'static mut` porque o bootloader entrega a posse exclusiva da
/// estrutura ao kernel — não existe mais ninguém rodando.
fn inicio(boot_info: &'static mut BootInfo) -> ! {
    // A serial vem antes de qualquer outra coisa. Sem ela, qualquer falha a
    // partir daqui seria uma tela preta sem diagnóstico.
    let canal = crate::serial::init();

    for regiao in boot_info.memory_regions.iter() {
        crate::machine::adicionar_regiao(Regiao {
            inicio: regiao.start,
            fim: regiao.end,
            tipo: match regiao.kind {
                MemoryRegionKind::Usable => TipoRegiao::Utilizavel,
                MemoryRegionKind::Bootloader => TipoRegiao::Bootloader,
                // As variantes `UnknownUefi`/`UnknownBios` carregam o código
                // cru do firmware. Do ponto de vista do kernel todas
                // significam a mesma coisa: não é nossa para usar.
                _ => TipoRegiao::Reservada,
            },
        });
    }

    if let Some(fb) = boot_info.framebuffer.as_ref() {
        let info = fb.info();
        crate::machine::definir_video(Video {
            largura: info.width as u64,
            altura: info.height as u64,
            stride: info.stride as u64,
            bytes_por_pixel: info.bytes_per_pixel as u64,
            formato: nome_formato_pixel(info.pixel_format),
        });
    }

    crate::inicio_comum(canal)
}

fn nome_formato_pixel(formato: PixelFormat) -> &'static str {
    match formato {
        PixelFormat::Rgb => "rgb",
        PixelFormat::Bgr => "bgr",
        PixelFormat::U8 => "grayscale8",
        // `PixelFormat` é `non_exhaustive`: versões futuras do bootloader
        // podem adicionar variantes, e o kernel precisa continuar compilando.
        _ => "desconhecido",
    }
}

/// Abre as portas seriais: (console humano, canal do agente).
///
/// O x86 tem o luxo de duas UARTs legadas sempre presentes, então damos uma
/// para cada papel. Separá-las garante que o canal do agente seja um stream
/// NDJSON limpo, sem ruído de log exigindo parsing heurístico.
pub fn init_seriais() -> (Option<Uart>, Option<Uart>) {
    // SAFETY: rodamos antes de qualquer outro código tocar nessas portas, em
    // núcleo único, então o acesso é de fato exclusivo.
    let console = unsafe { Uart::abrir(uart::COM1_BASE) };
    let agente = unsafe { Uart::abrir(uart::COM2_BASE) };
    (console, agente)
}

/// Informa faixas de memória física que o alocador de frames não pode
/// entregar.
///
/// No x86 não há nenhuma: o crate `bootloader` já marca no mapa de memória
/// tudo que ocupou — a imagem do kernel, as tabelas de página iniciais, o
/// próprio `BootInfo` — com o tipo `Bootloader`, e nunca como utilizável. A
/// tradução em [`inicio`] preserva essa distinção, então o alocador já nasce
/// sabendo o que evitar.
pub fn reservar_faixas(_f: impl FnMut(u64, u64)) {}

/// Instala GDT, TSS e IDT.
///
/// Depois desta chamada o processador tem para onde ir quando uma exceção
/// acontece. Antes dela, qualquer falha vira triple fault — reboot sem
/// diagnóstico.
pub fn init_excecoes() {
    // A ordem importa: a IDT referencia a IST, que vive no TSS, que é
    // apontado pela GDT.
    gdt::init();
    idt::init();
}

/// Remapeia o PIC, programa o timer e habilita as interrupções.
///
/// Exige que [`init_excecoes`] já tenha rodado: habilitar interrupções sem
/// IDT instalada entrega o controle a um vetor indefinido.
pub fn init_interrupcoes() {
    /// 100 Hz dá resolução de 10 ms — suficiente para medir uptime e para o
    /// scheduler da fase 1, sem custo perceptível de handler.
    const HZ: u32 = 100;

    // SAFETY: as interrupções ainda estão desabilitadas neste ponto (só as
    // habilitamos no fim) e a IDT já está instalada.
    let efetiva = unsafe {
        pic::init();
        pic::programar_timer(HZ)
    };

    crate::tempo::registrar_frequencia(efetiva);
    crate::irq::nomear(0, "timer-pit");
    crate::irq::nomear(1, "teclado-ps2");

    x86_64::instructions::interrupts::enable();

    crate::log_info!("irq", "PIC remapeado, timer a {} Hz", efetiva);
}

/// Espera pela próxima interrupção, em baixo consumo.
///
/// Devolve o controle imediatamente se as interrupções estiverem
/// desabilitadas: `hlt` sem interrupções pendentes pararia o núcleo para
/// sempre — o sistema morreria no primeiro instante ocioso.
pub fn esperar_interrupcao() {
    if x86_64::instructions::interrupts::are_enabled() {
        x86_64::instructions::hlt();
    } else {
        core::hint::spin_loop();
    }
}

/// Dispara um breakpoint (`int3`), que é tratado e retorna normalmente.
///
/// Existe para que o agente possa verificar, em tempo de execução, que o
/// caminho de exceções está de fato funcionando — ver o comando
/// `debug.trigger`.
pub fn disparar_breakpoint() {
    x86_64::instructions::interrupts::int3();
}

/// Executa `f` com as interrupções mascaradas, restaurando o estado ao sair.
pub fn sem_interrupcoes<R>(f: impl FnOnce() -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(f)
}

/// Para a CPU até a próxima interrupção, para sempre.
///
/// Prefira isto a `loop {}`. Um loop vazio mantém o núcleo em 100% de uso
/// girando à toa; `hlt` coloca a CPU em estado de baixo consumo e ela só
/// acorda quando há trabalho de verdade.
pub fn halt_forever() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

/// Lê a string de fabricante da CPU via `CPUID` folha 0.
///
/// Os 12 caracteres vêm espalhados em três registradores, e a ordem
/// EBX-EDX-ECX não é um engano: é literalmente como a Intel especificou.
pub fn identificar_cpu() -> super::IdCpu {
    // `__cpuid` é seguro: `CPUID` faz parte da linha de base do x86_64, então
    // o compilador sabe que a instrução sempre existe no alvo e não há
    // pré-condição para o chamador garantir.
    let r = core::arch::x86_64::__cpuid(0);

    let mut bytes = [0u8; 12];
    bytes[0..4].copy_from_slice(&r.ebx.to_le_bytes());
    bytes[4..8].copy_from_slice(&r.edx.to_le_bytes());
    bytes[8..12].copy_from_slice(&r.ecx.to_le_bytes());

    super::IdCpu::de_bytes(&bytes)
}

/// Encerra o QEMU pelo dispositivo `isa-debug-exit`.
///
/// Ao escrever um valor na porta configurada, o QEMU termina imediatamente
/// com o código de saída `(valor << 1) | 1`. Os valores evitam 0 e 1 de
/// propósito: assim um código nosso nunca colide com uma saída "natural" do
/// emulador, como um crash do próprio QEMU.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn encerrar_emulador(resultado: crate::qemu::Resultado) -> ! {
    use crate::qemu::Resultado;

    // Precisa casar com o `-device isa-debug-exit,iobase=...` que o xtask
    // passa ao QEMU. `0xf4` é convencional por estar numa faixa que hardware
    // real não usa.
    const PORTA_SAIDA: u16 = 0xf4;

    let codigo: u32 = match resultado {
        Resultado::Sucesso => 0x10, // vira 33 no host
        Resultado::Falha => 0x11,   // vira 35 no host
    };

    // SAFETY: escrever numa porta de I/O é sempre `unsafe` porque o efeito
    // depende do dispositivo. Aqui o efeito é conhecido e desejado. Em
    // hardware real `0xf4` não está mapeada e a escrita é inofensiva.
    unsafe {
        x86_64::instructions::port::Port::new(PORTA_SAIDA).write(codigo);
    }

    // Inalcançável sob o QEMU, mas o kernel também roda em hardware real.
    halt_forever()
}
