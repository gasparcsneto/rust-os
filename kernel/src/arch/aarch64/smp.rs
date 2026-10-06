//! Vários núcleos no ARM: acordar e parar.
//!
//! # Acordar
//!
//! Aqui não há trampolim de 16 bits: um núcleo ARM acorda em 64 bits, no
//! nível de exceção de quem o chamou. Mas acorda com a **MMU desligada** e
//! sem pilha, e quem o acorda é o firmware, por uma chamada padronizada — a
//! PSCI. O kernel diz "ligue o núcleo de `MPIDR` tal, a partir deste
//! endereço físico, com este valor em `x0`", e o firmware faz o resto.
//!
//! O valor em `x0` é o endereço de um [`BlocoDePartida`]: os registradores
//! de sistema que o primeiro núcleo usa, que o novo copia antes de ligar a
//! MMU — a tabela de atributos, o formato das tabelas, a raiz do kernel e o
//! `SCTLR`. Com a MMU ligada e o mapa sendo de identidade, nada muda de
//! endereço, e o núcleo segue para Rust na pilha do fio ocioso dele.
//!
//! # O que a MMU desligada exige
//!
//! Com ela desligada, os acessos a dados não passam pelo cache: o núcleo
//! novo lê a RAM direto. O primeiro núcleo escreveu o bloco com o cache
//! ligado, e a escrita pode estar só no cache dele. Por isso o bloco é
//! **limpo até o ponto de coerência** antes da chamada ao firmware — sem
//! isso, o núcleo novo leria zeros e saltaria para o endereço zero.
//!
//! # Parar
//!
//! Por uma SGI — uma interrupção que um núcleo manda a outro pelo
//! distribuidor do GIC. Diferente do x86, aqui não há uma interrupção que
//! atravesse a máscara: um núcleo girando com as IRQs mascaradas não ouve o
//! aviso. O caminho de falha espera um prazo e segue sem ele — ver
//! [`parar_os_outros`].
//!
//! # O que não precisa de aviso
//!
//! A TLB. As invalidações deste kernel já são as da família `...is`, que o
//! hardware difunde a todos os núcleos do domínio compartilhável — ver
//! `mmu::invalidar`. O x86 precisa de NMI para a mesma coisa.

use aarch64_cpu::registers::{CNTFRQ_EL0, CNTPCT_EL0};
use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use tock_registers::interfaces::Readable;

use crate::nucleos::MAX_NUCLEOS;

use super::fdt::Conduto;

/// O que um núcleo novo lê com a MMU desligada.
///
/// A ordem dos campos é contrato com [`entrada_secundaria_arm`]: o assembly
/// os alcança por deslocamento.
#[repr(C, align(64))]
struct BlocoDePartida {
    mair: u64,
    tcr: u64,
    ttbr0: u64,
    sctlr: u64,
    vbar: u64,
    /// O índice do núcleo no kernel, que vai para `TPIDR_EL1`.
    indice: u64,
    /// O topo da pilha de exceção dele, que vai para `SP_EL1`.
    pilha_de_excecao: u64,
    /// O topo da pilha do fio ocioso, que vai para `SP_EL0`.
    pilha: u64,
    cpacr: u64,
    /// A função Rust onde ele entra.
    entrada: u64,
}

struct Blocos([UnsafeCell<BlocoDePartida>; MAX_NUCLEOS]);

// SAFETY: o bloco de um núcleo é escrito pelo primeiro núcleo antes da
// partida daquele, e lido pelo núcleo novo uma vez, no começo — os núcleos
// acordam um de cada vez, e cada um tem o seu bloco.
unsafe impl Sync for Blocos {}

static BLOCOS: Blocos = Blocos(
    [const {
        UnsafeCell::new(BlocoDePartida {
            mair: 0,
            tcr: 0,
            ttbr0: 0,
            sctlr: 0,
            vbar: 0,
            indice: 0,
            pilha_de_excecao: 0,
            pilha: 0,
            cpacr: 0,
            entrada: 0,
        })
    }; MAX_NUCLEOS],
);

core::arch::global_asm!(
    r#"
.section .text
.global entrada_secundaria_arm
.balign 4
entrada_secundaria_arm:
    // x0 = o bloco de partida. A MMU está desligada, e as leituras abaixo
    // vão direto à RAM — o primeiro núcleo limpou o bloco até lá.
    ldr     x1, [x0, #0]
    msr     mair_el1, x1
    ldr     x1, [x0, #8]
    msr     tcr_el1, x1
    ldr     x1, [x0, #16]
    msr     ttbr0_el1, x1
    isb
    // A TLB deste núcleo pode ter qualquer coisa do firmware.
    tlbi    vmalle1
    dsb     nsh
    isb

    // O momento crítico, o mesmo do primeiro núcleo: a instrução seguinte
    // já é buscada pela tradução — de identidade, então no mesmo lugar.
    ldr     x1, [x0, #24]
    msr     sctlr_el1, x1
    isb
    ic      iallu
    dsb     nsh
    isb

    ldr     x1, [x0, #32]
    msr     vbar_el1, x1
    ldr     x1, [x0, #40]
    msr     tpidr_el1, x1
    ldr     x1, [x0, #64]
    msr     cpacr_el1, x1
    isb

    // Entramos com SPSel=1: `sp` é SP_EL1, a pilha de exceção deste núcleo.
    ldr     x1, [x0, #48]
    mov     sp, x1
    // E a pilha normal, em SP_EL0, é a do fio ocioso — a mesma separação
    // do primeiro núcleo.
    msr     spsel, #0
    ldr     x1, [x0, #56]
    mov     sp, x1

    ldr     x2, [x0, #72]
    ldr     x0, [x0, #40]
    br      x2
"#
);

unsafe extern "C" {
    fn entrada_secundaria_arm();
}

/// Os códigos de retorno da PSCI que o log precisa nomear.
fn nome_do_erro(codigo: i64) -> &'static str {
    match codigo {
        -1 => "PSCI: nao suportado",
        -2 => "PSCI: parametro invalido",
        -3 => "PSCI: negado",
        -4 => "PSCI: o nucleo ja esta ligado",
        -5 => "PSCI: o nucleo ja esta sendo ligado",
        -6 => "PSCI: o firmware nao esta presente",
        -7 => "PSCI: o firmware nao respondeu",
        -9 => "PSCI: endereco invalido",
        _ => "PSCI: erro desconhecido",
    }
}

/// `CPU_ON` da PSCI 0.2 em diante, na convenção de 64 bits.
const CPU_ON: u64 = 0xC400_0003;

/// Chama a PSCI pelo conduto que o device tree declarou.
///
/// # Safety
///
/// É uma chamada ao firmware: os argumentos precisam ser os da função pedida.
unsafe fn psci(conduto: Conduto, funcao: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let mut x0 = funcao;
    // SAFETY: delegada ao chamador. A convenção de chamada do firmware (SMCCC)
    // pode destruir de x0 a x17; todos vão como saída.
    unsafe {
        match conduto {
            Conduto::Hvc => asm!("hvc #0",
                inout("x0") x0, inout("x1") a1 => _, inout("x2") a2 => _, inout("x3") a3 => _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _, out("x9") _,
                out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _,
                out("x15") _, out("x16") _, out("x17") _, options(nostack)),
            Conduto::Smc => asm!("smc #0",
                inout("x0") x0, inout("x1") a1 => _, inout("x2") a2 => _, inout("x3") a3 => _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _, out("x8") _, out("x9") _,
                out("x10") _, out("x11") _, out("x12") _, out("x13") _, out("x14") _,
                out("x15") _, out("x16") _, out("x17") _, options(nostack)),
        }
    }
    x0 as i64
}

/// O conduto da PSCI, lido do device tree na descoberta.
static CONDUTO: AtomicU8 = AtomicU8::new(0);

/// Chama `f` com o `MPIDR` de cada núcleo que o device tree descreve.
pub fn descobrir(mut f: impl FnMut(u64)) {
    // SAFETY: o ponteiro veio do firmware e foi guardado no boot; o leitor
    // confere a assinatura e trata o nulo.
    let nucleos = unsafe { super::fdt::encontrar_nucleos(super::dtb()) };
    CONDUTO.store(
        match nucleos.psci {
            None => 0,
            Some(Conduto::Hvc) => 1,
            Some(Conduto::Smc) => 2,
        },
        Ordering::Release,
    );
    if nucleos.alem > 0 {
        crate::log_warn!(
            "smp",
            "o device tree descreve {} nucleo(s) alem dos que o leitor guarda",
            nucleos.alem
        );
    }
    for mpidr in &nucleos.mpidr[..nucleos.quantos] {
        f(*mpidr);
    }
}

/// Limpa uma faixa até o ponto de coerência: o que estiver só no cache
/// deste núcleo vai para a RAM, onde um núcleo de MMU desligada o enxerga.
fn limpar_ate_a_ram(inicio: u64, bytes: u64) {
    const LINHA: u64 = 64;
    let mut linha = inicio & !(LINHA - 1);
    while linha < inicio + bytes {
        // SAFETY: manutenção de cache por endereço virtual, sobre memória
        // nossa e mapeada.
        unsafe { asm!("dc cvac, {}", in(reg) linha, options(nostack)) };
        linha += LINHA;
    }
    // SAFETY: barreira, sem efeito além da ordem.
    unsafe { asm!("dsb sy", options(nostack)) };
}

/// Acorda o núcleo de `MPIDR` `hardware` como o núcleo `indice`, na pilha
/// `topo`.
pub fn partir(indice: usize, hardware: u64, topo: u64) -> Result<(), &'static str> {
    let conduto = match CONDUTO.load(Ordering::Acquire) {
        1 => Conduto::Hvc,
        2 => Conduto::Smc,
        _ => return Err("o device tree nao descreve a PSCI"),
    };
    if indice >= MAX_NUCLEOS {
        return Err("nucleo alem do teto");
    }

    // A pilha de exceção, que no primeiro núcleo é a do linker script. Esta
    // vem da área de pilhas, com página de guarda, e nunca é devolvida: o
    // núcleo vive enquanto o sistema viver.
    let excecao = crate::fios::pilha::reservar_de_nucleo(indice)?;

    let bloco = BLOCOS.0[indice].get();
    // SAFETY: o bloco é deste núcleo, e ninguém o lê até a chamada ao
    // firmware logo abaixo — os núcleos acordam um de cada vez.
    unsafe {
        let b = &mut *bloco;
        let (mair, tcr, sctlr, vbar, cpacr): (u64, u64, u64, u64, u64);
        asm!("mrs {}, mair_el1", out(reg) mair, options(nomem, nostack));
        asm!("mrs {}, tcr_el1", out(reg) tcr, options(nomem, nostack));
        asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nomem, nostack));
        asm!("mrs {}, vbar_el1", out(reg) vbar, options(nomem, nostack));
        asm!("mrs {}, cpacr_el1", out(reg) cpacr, options(nomem, nostack));
        // A raiz do **kernel**, e não a ativa: quem está acordando outro
        // núcleo pode estar rodando num processo.
        b.ttbr0 = super::mmu::espaco_do_kernel();
        b.mair = mair;
        b.tcr = tcr;
        b.sctlr = sctlr;
        b.vbar = vbar;
        b.indice = indice as u64;
        b.pilha_de_excecao = excecao.topo() & !0xF;
        b.pilha = topo & !0xF;
        b.cpacr = cpacr;
        let entrada: extern "C" fn(u64) -> ! = entrada_secundaria;
        b.entrada = entrada as *const () as u64;
    }
    limpar_ate_a_ram(bloco as u64, size_of::<BlocoDePartida>() as u64);

    // SAFETY: `CPU_ON` com um `MPIDR` que o device tree descreve, um
    // endereço de entrada que é código do kernel — físico igual a virtual,
    // pelo mapa de identidade — e o bloco como contexto.
    let resposta = unsafe {
        psci(
            conduto,
            CPU_ON,
            hardware,
            entrada_secundaria_arm as *const () as u64,
            bloco as u64,
        )
    };
    if resposta != 0 {
        // O núcleo não vai acordar: a pilha de exceção pode voltar.
        drop(excecao);
        return Err(nome_do_erro(resposta));
    }
    core::mem::forget(excecao);
    Ok(())
}

/// A primeira função Rust de um núcleo secundário.
///
/// Chega aqui com a MMU ligada, os vetores instalados, `TPIDR_EL1` com o
/// índice e a pilha do fio ocioso, IRQs mascaradas.
extern "C" fn entrada_secundaria(indice: u64) -> ! {
    // SAFETY: estamos no núcleo que acabou de acordar, mascarado, com a
    // tabela de vetores instalada pelo bloco de partida.
    unsafe { super::gic::ligar_neste_nucleo() };
    crate::nucleos::entrar_secundario(indice as usize)
}

/// O sistema parou, e todo núcleo que receber a SGI de parada deve parar.
static PARANDO: AtomicBool = AtomicBool::new(false);
/// Quem já parou: um bit por núcleo.
static PARADOS: AtomicU64 = AtomicU64::new(0);

/// Para todos os outros núcleos, para sempre. Chamada pelo caminho de falha.
///
/// Devolve a máscara dos que confirmaram. Um núcleo com as IRQs mascaradas
/// não ouve a SGI, e fica de fora — o que este backend não tem como evitar
/// com o GIC v2 em modo não seguro. O prazo é o que impede que um núcleo
/// assim cale o relatório.
///
/// # Prazo em tempo, não em voltas
///
/// O prazo era de cem milhões de voltas, e com um núcleo mascarado ele é
/// esperado inteiro, sempre. Quanto isso dura depende de quem executa: no
/// kernel de depuração sob o QEMU sem aceleração, passava de cinco
/// segundos, e a tela de falha chegava ao monitor depois de a fumaça
/// desistir de esperá-la — medido, com o núcleo travado da sonda anterior.
/// O contador do timer genérico anda com as IRQs mascaradas e não depende
/// de nada que o caminho de falha destrava, então o prazo é medido nele.
pub fn parar_os_outros() -> crate::nucleos::Mascara {
    PARANDO.store(true, Ordering::Release);
    let eu = super::nucleo_atual();
    let outros = crate::nucleos::mascara_dos_ligados() & !crate::nucleos::bit(eu);
    super::gic::enviar_sgi(outros, super::gic::SGI_PARAR);
    // Um quarto de segundo: um núcleo que ouve a SGI para em microssegundos.
    // As voltas ficam como teto de reserva, para um contador que não ande —
    // o firmware que deixa `CNTFRQ_EL0` em zero é o mesmo que o boot já
    // relata como "sem timer".
    let prazo = (CNTFRQ_EL0.get() / 4).max(1);
    let inicio = CNTPCT_EL0.get();
    const VOLTAS: u64 = 100_000_000;
    for _ in 0..VOLTAS {
        if CNTPCT_EL0.get().wrapping_sub(inicio) >= prazo {
            break;
        }
        if PARADOS.load(Ordering::Acquire) & outros == outros {
            break;
        }
        core::hint::spin_loop();
    }
    PARADOS.load(Ordering::Acquire)
}

/// O que um núcleo faz ao receber a SGI de parada.
pub fn atender_parada() {
    if !PARANDO.load(Ordering::Acquire) {
        return;
    }
    PARADOS.fetch_or(crate::nucleos::bit(super::nucleo_atual()), Ordering::AcqRel);
    parar_este_nucleo()
}

/// Para este núcleo, para sempre, com as IRQs mascaradas.
pub fn parar_este_nucleo() -> ! {
    // SAFETY: mascarar IRQs não tem pré-condição.
    unsafe { asm!("msr daifset, #2", options(nomem, nostack)) };
    loop {
        aarch64_cpu::asm::wfe();
    }
}
