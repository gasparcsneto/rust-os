//! O que o Duke precisa saber sobre o aarch64 para ser iniciado.
//!
//! # A porta serial, escrita direto no hardware
//!
//! Pelo mesmo motivo do x86, e com uma diferença de grau: o console do
//! firmware é um serviço de boot, e o trabalho deste programa termina
//! **depois** de `ExitBootServices`, exatamente onde esse console deixa de
//! existir. Um relatório que emudece no passo mais delicado do boot é um
//! relatório que falta quando é mais necessário.
//!
//! A diferença de grau é que no ARM não há tela nenhuma por baixo: o x86
//! ainda teria a VGA, e aqui a serial é tudo.
//!
//! # A UART não é a mesma, e o endereço dela não vem de lugar nenhum
//!
//! No x86 a COM1 está em `0x3F8` desde 1981, e é o processador que entrega
//! as portas de I/O. No ARM não há portas: a UART é memória mapeada, e
//! **onde** ela está é escolha da placa. A máquina `virt` do QEMU põe uma
//! PL011 em `0x0900_0000`, e é isso que este iniciador escreve.
//!
//! Escrever o endereço à mão é o que há de menos satisfatório neste arquivo,
//! e vale dizer por que ele está aqui em vez de vir do device tree. Para ler
//! o device tree é preciso antes achá-lo na tabela de configuração da UEFI,
//! e para relatar que não o achou é preciso já ter uma serial. A dependência
//! é circular, e alguém tem de chutar primeiro.
//!
//! O que **não** é chute é o resto: o iniciador acha o device tree logo em
//! seguida e relata o endereço que ele declara para a UART. Numa placa em
//! que os dois números discordem, a discordância aparece na primeira linha
//! do relatório — em vez de aparecer como silêncio.

use core::fmt;
use core::ptr::{read_volatile, write_volatile};

/// A PL011 da máquina `virt` do QEMU. Ver o cabeçalho deste módulo.
pub const UART: u64 = 0x0900_0000;

// Os registradores, contados em bytes a partir da base.
/// Dados: escrever aqui transmite um byte.
const DADOS: u64 = 0x00;
/// Bandeiras. O bit 5 diz que a fila de transmissão está cheia.
const BANDEIRAS: u64 = 0x18;

/// `TXFF`: não cabe mais nada na fila de transmissão.
const FILA_CHEIA: u32 = 1 << 5;

/// O número que o ELF usa para esta arquitetura.
pub const MAQUINA: u16 = 0xB7;

/// O tipo de relocação que soma a base de carga a um valor.
///
/// `R_AARCH64_RELATIVE`. É a única que uma imagem autocontida e independente
/// de posição produz, e recusar qualquer outra é o que impede este
/// iniciador de aplicar em silêncio uma relocação cujo significado ele não
/// conhece.
///
/// O número é **outro** que o do x86 — 1027 contra 8 —, e isso não é
/// detalhe: cada arquitetura numera as próprias relocações a partir de um,
/// então o `8` do x86 existe aqui também e quer dizer outra coisa
/// (`R_AARCH64_ABS16`). Aplicar a tabela do x86 num ELF de ARM não daria
/// erro; daria um punhado de escritas plausíveis nos lugares errados.
pub const RELOCACAO_RELATIVA: u32 = 1027;

/// O nome desta arquitetura, para o relatório.
pub const fn nome() -> &'static str {
    "aarch64"
}

/// Prepara a UART para o relatório.
///
/// # Por que ela não é reprogramada
///
/// No x86 o iniciador reprograma a COM1 — divisor, formato, FIFO —, porque
/// a configuração herdada é do firmware e um iniciador que dependesse dela
/// emudeceria noutro. Aqui a decisão é a inversa, e por um motivo concreto:
/// a taxa de transmissão de uma PL011 depende do relógio que a placa
/// entrega a ela, e esse número **não está na UART**. Ele está no device
/// tree, que ainda não foi lido.
///
/// Calcular os divisores a partir de um relógio chutado é o jeito mais
/// direto de produzir lixo na linha. O firmware já falou por esta porta
/// para imprimir o próprio banner, então ela está programada e funciona; o
/// que este iniciador faz é continuar usando o que já está de pé.
pub fn init_serial() {}

fn escrever_byte(byte: u8) {
    // SAFETY: a base é a da PL011 desta placa, e somos o único núcleo
    // escrevendo nela. As duas leituras são de registradores de dispositivo,
    // então precisam ser voláteis: um compilador que juntasse as voltas do
    // laço leria a bandeira uma vez só e giraria para sempre.
    unsafe {
        while read_volatile((UART + BANDEIRAS) as *const u32) & FILA_CHEIA != 0 {
            core::hint::spin_loop();
        }
        write_volatile((UART + DADOS) as *mut u32, u32::from(byte));
    }
}

/// O destino de tudo que este programa tem a dizer.
pub struct Serial;

impl fmt::Write for Serial {
    fn write_str(&mut self, texto: &str) -> fmt::Result {
        for byte in texto.bytes() {
            // A UART não conhece `\n` sozinho: um terminal que receba só o
            // avanço de linha continua na coluna em que estava.
            if byte == b'\n' {
                escrever_byte(b'\r');
            }
            escrever_byte(byte);
        }
        Ok(())
    }
}

/// Escreve uma linha do relatório, sempre com o prefixo que a identifica.
///
/// O prefixo não é enfeite: a saída do firmware e a nossa dividem a mesma
/// porta, e é por ele que uma pessoa — ou o `xtask` — separa as duas.
#[macro_export]
macro_rules! relatar {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = writeln!($crate::alvo::Serial, "iniciador: {}", format_args!($($arg)*));
    }};
}

/// Pára o núcleo até a próxima interrupção.
///
/// O equivalente do `hlt` do x86. `wfi` — *wait for interrupt* — suspende o
/// núcleo e acorda com a próxima interrupção pendente, mesmo mascarada.
pub fn dormir() {
    // SAFETY: `wfi` não toca em memória e só suspende o núcleo.
    unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
}
