//! A porta serial, escrita direto no hardware.
//!
//! # Por que não o console do firmware
//!
//! Porque o console do firmware é um serviço de boot, e o trabalho deste
//! programa termina depois de `ExitBootServices` — exatamente onde esse
//! console deixa de existir. Um relatório que emudece no passo mais delicado
//! do boot é um relatório que falta quando é mais necessário.
//!
//! A UART não depende de ninguém: é a mesma COM1 que o kernel abre logo em
//! seguida, programada do mesmo jeito. O iniciador fala pelo canal em que o
//! Duke já fala, o que faz a passagem de um para o outro aparecer como uma
//! conversa só.
//!
//! # O preço, dito em voz alta
//!
//! Escrever numa porta que o firmware também usa mistura as duas saídas. É
//! aceitável porque cada linha nossa é prefixada, e quem lê — pessoa ou
//! `xtask` — procura o prefixo. O contrário — ficar calado para não
//! atrapalhar — trocaria ruído por cegueira.

use core::arch::asm;
use core::fmt;

/// A primeira porta serial do PC, no mesmo endereço desde 1981.
const COM1: u16 = 0x3F8;

// Os registradores, contados a partir da base.
const DADOS: u16 = 0;
const HABILITAR_INTERRUPCOES: u16 = 1;
/// Com o bit de acesso ao divisor ligado, 0 e 1 viram a parte baixa e alta
/// dele.
const DIVISOR_BAIXO: u16 = 0;
const DIVISOR_ALTO: u16 = 1;
const CONTROLE_DA_FIFO: u16 = 2;
const CONTROLE_DA_LINHA: u16 = 3;
const CONTROLE_DO_MODEM: u16 = 4;
const ESTADO_DA_LINHA: u16 = 5;

/// O bit que diz que o registrador de transmissão está vazio.
const PODE_TRANSMITIR: u8 = 1 << 5;

/// # Safety
/// A porta precisa ser de uma UART, e nada mais pode estar escrevendo nela.
unsafe fn escrever_porta(porta: u16, valor: u8) {
    // SAFETY: delegada a quem chama.
    unsafe {
        asm!("out dx, al", in("dx") porta, in("al") valor, options(nomem, nostack, preserves_flags));
    }
}

/// # Safety
/// A porta precisa ser de uma UART.
unsafe fn ler_porta(porta: u16) -> u8 {
    let valor: u8;
    // SAFETY: delegada a quem chama.
    unsafe {
        asm!("in al, dx", out("al") valor, in("dx") porta, options(nomem, nostack, preserves_flags));
    }
    valor
}

/// Programa a COM1 para 38400 bauds, 8N1, sem interrupções.
///
/// O firmware já a deixou utilizável, e este passo existe assim mesmo: a
/// configuração que ele escolheu é dele, não nossa, e um iniciador que
/// dependesse de herdar a velocidade certa funcionaria num firmware e
/// emudeceria noutro.
pub fn init() {
    // SAFETY: núcleo único, antes de qualquer outra coisa nossa tocar a porta.
    unsafe {
        escrever_porta(COM1 + HABILITAR_INTERRUPCOES, 0x00);
        // Bit 7 do controle da linha: os dois primeiros registradores passam a
        // ser o divisor.
        escrever_porta(COM1 + CONTROLE_DA_LINHA, 0x80);
        escrever_porta(COM1 + DIVISOR_BAIXO, 0x03);
        escrever_porta(COM1 + DIVISOR_ALTO, 0x00);
        // E de volta: 8 bits de dados, sem paridade, um bit de parada.
        escrever_porta(COM1 + CONTROLE_DA_LINHA, 0x03);
        escrever_porta(COM1 + CONTROLE_DA_FIFO, 0xC7);
        escrever_porta(COM1 + CONTROLE_DO_MODEM, 0x0B);
    }
}

fn escrever_byte(byte: u8) {
    // SAFETY: a porta é a COM1, programada acima.
    unsafe {
        while ler_porta(COM1 + ESTADO_DA_LINHA) & PODE_TRANSMITIR == 0 {
            core::hint::spin_loop();
        }
        escrever_porta(COM1 + DADOS, byte);
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
        let _ = writeln!($crate::serial::Serial, "iniciador: {}", format_args!($($arg)*));
    }};
}
