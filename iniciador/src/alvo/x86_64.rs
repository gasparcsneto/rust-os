//! O que o Duke precisa saber sobre o x86_64 para ser iniciado.
//!
//! # A porta serial, escrita direto no hardware
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

/// O número que o ELF usa para esta arquitetura.
pub const MAQUINA: u16 = 0x3E;

/// O tipo de relocação que soma a base de carga a um valor.
///
/// `R_X86_64_RELATIVE`. É a única que uma imagem autocontida e independente
/// de posição produz, e recusar qualquer outra é o que impede este
/// iniciador de aplicar em silêncio uma relocação cujo significado ele não
/// conhece.
pub const RELOCACAO_RELATIVA: u32 = 8;

/// O nome desta arquitetura, para o relatório.
pub const fn nome() -> &'static str {
    "x86_64"
}

/// Programa a COM1 para 38400 bauds, 8N1, sem interrupções.
///
/// O firmware já a deixou utilizável, e este passo existe assim mesmo: a
/// configuração que ele escolheu é dele, não nossa, e um iniciador que
/// dependesse de herdar a velocidade certa funcionaria num firmware e
/// emudeceria noutro.
pub fn init_serial() {
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
        let _ = writeln!($crate::alvo::Serial, "iniciador: {}", format_args!($($arg)*));
    }};
}

/// Pára o núcleo até a próxima interrupção.
///
/// É o que o iniciador faz quando não há mais nada a fazer e nem como
/// desligar. Um laço vazio manteria o núcleo em cem por cento girando à toa,
/// o que num emulador é a diferença entre uma máquina parada e uma que
/// parece travada.
pub fn dormir() {
    // SAFETY: `hlt` não toca em memória e só suspende o núcleo.
    unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)) };
}

/// O que o último instante precisa saber, no x86.
pub struct Partida {
    /// Para onde saltar, já no espaço do kernel.
    pub entrada: u64,
    /// O endereço virtual da entrega, que vai no primeiro argumento.
    pub entrega: u64,
    /// A raiz do mapa que o iniciador montou.
    pub raiz: u64,
    /// O topo da pilha do kernel.
    pub pilha: u64,
}

/// Instala o mapa novo e salta. Não retorna.
///
/// # Safety
///
/// O mapa precisa ter sido montado e conferido, e precisa cobrir **este**
/// código por identidade: no instante seguinte ao `mov cr3` o processador
/// busca a próxima instrução, e ela mora num endereço baixo. Sem essa
/// cobertura a busca falha, e uma falha de página sem tabela de exceções é
/// um triple fault — a máquina reiniciando sem nada na tela.
pub unsafe fn partir(p: Partida) -> ! {
    // SAFETY: delegada a quem chama. Nada entre o `cli` e o `jmp` toca
    // memória que o mapa novo não descreva.
    unsafe {
        core::arch::asm!(
            // Interrupções fora antes de qualquer coisa: a IDT que ainda está
            // carregada é a do firmware, e o código dela some com o mapa.
            "cli",
            "mov cr3, {raiz}",
            "mov rsp, {pilha}",
            // O quadro de pilha acaba aqui. Zerar o ponteiro de base é o que
            // faz um depurador parar de desenrolar em vez de seguir por
            // valores que sobraram do firmware.
            "xor rbp, rbp",
            "jmp {entrada}",
            raiz = in(reg) p.raiz,
            pilha = in(reg) p.pilha,
            entrada = in(reg) p.entrada,
            in("rdi") p.entrega,
            options(noreturn)
        );
    }
}
