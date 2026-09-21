//! Controlador de interrupções (GIC v2) e timer genérico do ARM.
//!
//! # O contraste com o x86
//!
//! No x86 herdamos um controlador dos anos 1980 em portas de I/O fixas, e um
//! timer separado que precisa ser programado com um divisor derivado de um
//! cristal de 1,19 MHz.
//!
//! No ARM os dois são bem mais modernos e bem mais integrados:
//!
//! - O **GIC** é mapeado em memória e dividido em duas metades: o
//!   *distribuidor*, que decide quais interrupções existem e para onde vão, e
//!   a *interface de CPU*, por onde cada núcleo reconhece e finaliza as que
//!   recebe.
//! - O **timer genérico** faz parte do próprio processador, acessado por
//!   registradores de sistema em vez de portas. Ele informa a própria
//!   frequência em `CNTFRQ_EL0`, então não precisamos de nenhuma constante
//!   mágica de hardware.

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

/// Distribuidor do GIC na máquina `virt`.
const GICD_BASE: usize = 0x0800_0000;
/// Interface de CPU do GIC na máquina `virt`.
const GICC_BASE: usize = 0x0801_0000;

const GICD_CTLR: usize = 0x000;
const GICD_ISENABLER: usize = 0x100;

const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_IAR: usize = 0x00C;
const GICC_EOIR: usize = 0x010;

/// INTID do timer físico de EL1.
///
/// As interrupções privadas de cada núcleo (PPIs) ocupam os INTIDs 16 a 31; o
/// timer físico não-seguro de EL1 é o PPI 14, ou seja, INTID 30.
pub const INTID_TIMER: u32 = 30;

/// INTID devolvido pelo GIC quando não há interrupção pendente de verdade.
///
/// Reconhecer uma interrupção espúria é normal (pode acontecer quando outra
/// coisa mascara a interrupção entre o disparo e o reconhecimento) e ela
/// **não** deve ser finalizada — sinalizar fim de uma interrupção que nunca
/// começou desregula a contabilidade interna do controlador.
const INTID_ESPURIO: u32 = 1023;

/// Intervalo, em ciclos do timer, entre duas interrupções.
///
/// Guardado porque o timer genérico é *one-shot*: depois de disparar, ele
/// precisa ser rearmado com a mesma contagem, de dentro do handler.
static INTERVALO: AtomicU32 = AtomicU32::new(0);

/// # Safety
/// O endereço precisa ser de um registrador válido do GIC.
unsafe fn escrever(endereco: usize, valor: u32) {
    unsafe { core::ptr::write_volatile(endereco as *mut u32, valor) }
}

/// # Safety
/// O endereço precisa ser de um registrador válido do GIC.
unsafe fn ler(endereco: usize) -> u32 {
    unsafe { core::ptr::read_volatile(endereco as *const u32) }
}

/// Inicializa o GIC e habilita a linha do timer.
///
/// # Safety
///
/// Precisa ser chamada com as interrupções mascaradas e a tabela de vetores
/// já instalada.
pub unsafe fn init() {
    // SAFETY: endereços do GIC da máquina `virt`, com acesso exclusivo.
    unsafe {
        // Distribuidor: liga o encaminhamento de interrupções.
        escrever(GICD_BASE + GICD_CTLR, 1);

        // Máscara de prioridade da interface de CPU. Um valor alto deixa
        // passar tudo: o GIC só entrega interrupções de prioridade
        // *numericamente menor* que a máscara, e 0xFF é o maior valor
        // possível.
        escrever(GICC_BASE + GICC_PMR, 0xFF);

        // Liga a interface de CPU.
        escrever(GICC_BASE + GICC_CTLR, 1);

        // Habilita o INTID do timer no distribuidor. Cada registrador cobre
        // 32 linhas, uma por bit.
        let registrador = GICD_BASE + GICD_ISENABLER + (INTID_TIMER as usize / 32) * 4;
        escrever(registrador, 1 << (INTID_TIMER % 32));
    }
}

/// Reconhece a interrupção pendente e devolve seu INTID.
fn reconhecer() -> u32 {
    // SAFETY: leitura do registrador de reconhecimento da interface de CPU.
    // A leitura tem efeito colateral (marca a interrupção como em
    // atendimento), e é exatamente por isso que precisa ser volátil.
    unsafe { ler(GICC_BASE + GICC_IAR) & 0x3FF }
}

/// Sinaliza o fim do atendimento.
///
/// Sem isto o GIC considera a interrupção ainda ativa e não entrega outra da
/// mesma linha. O sintoma é o timer disparar uma única vez.
fn finalizar(intid: u32) {
    // SAFETY: escrita no registrador de fim de interrupção.
    unsafe { escrever(GICC_BASE + GICC_EOIR, intid) }
}

/// Frequência do timer genérico, em Hz, informada pelo próprio processador.
fn frequencia_do_contador() -> u32 {
    let valor: u64;
    // SAFETY: `CNTFRQ_EL0` é somente leitura.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) valor, options(nomem, nostack)) };
    valor as u32
}

/// Arma o timer para disparar daqui a `ciclos`.
///
/// # Safety
/// Altera o estado do timer do processador.
unsafe fn armar(ciclos: u32) {
    // SAFETY: `CNTP_TVAL_EL0` é gravável a partir de EL1.
    unsafe { asm!("msr cntp_tval_el0, {:x}", in(reg) ciclos as u64, options(nomem, nostack)) };
}

/// Configura o timer para disparar periodicamente na frequência pedida.
///
/// Devolve a frequência efetiva, que pode diferir da pedida porque o
/// intervalo em ciclos é inteiro.
///
/// # Safety
/// Precisa ser chamada com as interrupções mascaradas.
pub unsafe fn init_timer(hz_desejado: u32) -> u32 {
    let frequencia = frequencia_do_contador();
    // Mínimo de 1 para não armar um timer de zero ciclos, que dispararia
    // continuamente e travaria o sistema numa tempestade de interrupções.
    let intervalo = (frequencia / hz_desejado).max(1);
    INTERVALO.store(intervalo, Ordering::Relaxed);

    // SAFETY: registradores do timer, com interrupções mascaradas.
    unsafe {
        armar(intervalo);
        // Bit 0: habilita o timer. Bit 1 mascararia a saída, então fica zero.
        asm!("msr cntp_ctl_el0, {:x}", in(reg) 1u64, options(nomem, nostack));
    }

    frequencia / intervalo
}

/// Atende a interrupção de hardware pendente. Chamado pelo handler de IRQ.
pub fn tratar() {
    let intid = reconhecer();

    // Espúria: nada a atender e, principalmente, nada a finalizar.
    if intid == INTID_ESPURIO {
        return;
    }

    if intid == INTID_TIMER {
        crate::tempo::tick();

        // O timer genérico é one-shot: sem rearmar aqui, esta seria a última
        // interrupção que receberíamos.
        // SAFETY: estamos dentro do handler da própria interrupção do timer.
        unsafe { armar(INTERVALO.load(Ordering::Relaxed)) };
    }

    crate::irq::contabilizar(intid as usize);
    finalizar(intid);
}
