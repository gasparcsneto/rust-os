//! Tabela de vetores de exceção do aarch64.
//!
//! # O contraste com a IDT do x86
//!
//! No x86 a IDT é um array de descritores, cada um contendo o *endereço* de
//! uma função — o processador salta direto para o seu handler e já empilhou o
//! contexto por você.
//!
//! No ARM é diferente em dois aspectos que mudam tudo:
//!
//! 1. A tabela contém **código**, não ponteiros. São 16 entradas de 128 bytes
//!    cada, e o processador simplesmente salta para o início da entrada certa.
//!    Cabe ali um desvio, e é isso que cada entrada faz.
//!
//! 2. O processador **não salva registrador nenhum**. Ele guarda apenas o
//!    endereço de retorno em `ELR_EL1` e o estado em `SPSR_EL1`. Todo o resto
//!    — os 31 registradores de uso geral — é responsabilidade nossa, em
//!    assembly, antes de qualquer código Rust poder rodar.
//!
//! # As 16 entradas
//!
//! São quatro grupos de quatro. Os grupos dizem *de onde* a exceção veio; as
//! quatro entradas de cada grupo dizem *que tipo* ela é (síncrona, IRQ, FIQ,
//! SError).
//!
//! O kernel roda em EL1 usando `SP_EL1`, então o grupo que nos importa hoje é
//! o segundo. O quarto grupo (vindo de EL mais baixo) é o que passará a
//! importar na fase 1, quando houver userspace em EL0 fazendo syscalls.

use aarch64_cpu::asm::barrier;
use aarch64_cpu::registers::{CurrentEL, ESR_EL1, FAR_EL1, VBAR_EL1};
use tock_registers::interfaces::{Readable, Writeable};

/// O contexto salvo por [`SALVAR`] quando uma exceção acontece.
///
/// O layout precisa casar **exatamente** com os deslocamentos usados no
/// assembly abaixo: `x0..x30` contíguos a partir do início, depois `elr` e
/// `spsr`. Qualquer divergência aqui vira corrupção silenciosa de registrador,
/// que é das coisas mais difíceis de depurar num kernel.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Quadro {
    /// Registradores de uso geral `x0` a `x30`.
    pub x: [u64; 31],
    /// Endereço de retorno (`ELR_EL1`): a instrução a executar ao sair.
    ///
    /// Alterá-lo é o que permite retomar a execução *depois* de uma instrução
    /// que falhou — é assim que tratamos `brk` sem entrar em laço infinito.
    pub elr: u64,
    /// Estado do processador salvo (`SPSR_EL1`).
    pub spsr: u64,
}

// A tabela de vetores e o código de entrada/saída das exceções.
//
// As macros SALVAR/RESTAURAR existem porque os quatro tipos de exceção
// precisam do mesmo preâmbulo; escrevê-lo quatro vezes convidaria a uma
// divergência sutil entre eles.
core::arch::global_asm!(
    r#"
.section .text.vetores

// Empilha os 31 registradores de uso geral mais ELR e SPSR.
//
// 272 bytes em vez dos 264 necessários: a ABI do aarch64 exige que SP fique
// sempre alinhado em 16 bytes, e 264 não é múltiplo de 16.
.macro SALVAR
    sub     sp, sp, #272
    stp     x0,  x1,  [sp, #16 * 0]
    stp     x2,  x3,  [sp, #16 * 1]
    stp     x4,  x5,  [sp, #16 * 2]
    stp     x6,  x7,  [sp, #16 * 3]
    stp     x8,  x9,  [sp, #16 * 4]
    stp     x10, x11, [sp, #16 * 5]
    stp     x12, x13, [sp, #16 * 6]
    stp     x14, x15, [sp, #16 * 7]
    stp     x16, x17, [sp, #16 * 8]
    stp     x18, x19, [sp, #16 * 9]
    stp     x20, x21, [sp, #16 * 10]
    stp     x22, x23, [sp, #16 * 11]
    stp     x24, x25, [sp, #16 * 12]
    stp     x26, x27, [sp, #16 * 13]
    stp     x28, x29, [sp, #16 * 14]
    // x0 e x1 já estão salvos, então servem de rascunho a partir daqui.
    mrs     x0, elr_el1
    mrs     x1, spsr_el1
    stp     x30, x0,  [sp, #16 * 15]
    str     x1,       [sp, #16 * 16]
.endm

// Desfaz SALVAR. A ordem é deliberada: ELR e SPSR são restaurados primeiro,
// usando x0/x1 como rascunho, e só depois os valores reais de x0/x1 voltam.
.macro RESTAURAR
    ldr     x1,       [sp, #16 * 16]
    ldp     x30, x0,  [sp, #16 * 15]
    msr     spsr_el1, x1
    msr     elr_el1,  x0
    ldp     x0,  x1,  [sp, #16 * 0]
    ldp     x2,  x3,  [sp, #16 * 1]
    ldp     x4,  x5,  [sp, #16 * 2]
    ldp     x6,  x7,  [sp, #16 * 3]
    ldp     x8,  x9,  [sp, #16 * 4]
    ldp     x10, x11, [sp, #16 * 5]
    ldp     x12, x13, [sp, #16 * 6]
    ldp     x14, x15, [sp, #16 * 7]
    ldp     x16, x17, [sp, #16 * 8]
    ldp     x18, x19, [sp, #16 * 9]
    ldp     x20, x21, [sp, #16 * 10]
    ldp     x22, x23, [sp, #16 * 11]
    ldp     x24, x25, [sp, #16 * 12]
    ldp     x26, x27, [sp, #16 * 13]
    ldp     x28, x29, [sp, #16 * 14]
    add     sp, sp, #272
.endm

// Cada entrada da tabela tem exatamente 128 bytes (.align 7). Só cabe um
// desvio, então o trabalho real fica nos rótulos comuns mais abaixo.
.macro ENTRADA rotulo
    .align 7
    b       \rotulo
.endm

// A tabela inteira precisa de alinhamento de 2 KiB (.align 11): VBAR_EL1
// ignora os 11 bits baixos do endereço que recebe.
.align 11
.global tabela_vetores_el1
tabela_vetores_el1:
    // --- EL atual usando SP0 ---------------------------------------------
    // Não usamos SP0, mas as entradas precisam existir: se uma exceção caísse
    // aqui e encontrasse lixo, o desfecho seria imprevisível.
    ENTRADA .Ltrap_sync
    ENTRADA .Ltrap_irq
    ENTRADA .Ltrap_fiq
    ENTRADA .Ltrap_serror

    // --- EL atual usando SPx --- é aqui que o kernel vive ----------------
    ENTRADA .Ltrap_sync
    ENTRADA .Ltrap_irq
    ENTRADA .Ltrap_fiq
    ENTRADA .Ltrap_serror

    // --- EL mais baixo, AArch64 --- userspace, a partir da fase 1 --------
    ENTRADA .Ltrap_sync
    ENTRADA .Ltrap_irq
    ENTRADA .Ltrap_fiq
    ENTRADA .Ltrap_serror

    // --- EL mais baixo, AArch32 --- não suportamos código de 32 bits -----
    ENTRADA .Ltrap_sync
    ENTRADA .Ltrap_irq
    ENTRADA .Ltrap_fiq
    ENTRADA .Ltrap_serror

.Ltrap_sync:
    SALVAR
    mov     x0, sp
    bl      {sync}
    RESTAURAR
    eret

.Ltrap_irq:
    SALVAR
    mov     x0, sp
    bl      {irq}
    RESTAURAR
    eret

.Ltrap_fiq:
    SALVAR
    mov     x0, sp
    bl      {fiq}
    RESTAURAR
    eret

.Ltrap_serror:
    SALVAR
    mov     x0, sp
    bl      {serror}
    RESTAURAR
    eret
"#,
    sync = sym tratar_sync,
    irq = sym tratar_irq,
    fiq = sym tratar_fiq,
    serror = sym tratar_serror,
);

/// O registrador de síndrome da exceção (`ESR_EL1`), cru.
///
/// É onde o processador descreve *o que* aconteceu. Guardamos o valor inteiro
/// em [`crate::traps`] sem interpretar: qualquer decodificação que fizéssemos
/// perderia bits do campo ISS que podem importar, e o agente tem como
/// consultar o manual.
fn ler_esr() -> u64 {
    ESR_EL1.get()
}

/// A classe da exceção — o campo `EC` do `ESR_EL1`.
///
/// Antes isto era `(esr >> 26) & 0x3F` espalhado pelos handlers. O
/// deslocamento e a máscara estavam corretos, mas eram duas oportunidades de
/// errar em silêncio a cada uso.
fn classe_da_excecao() -> u64 {
    ESR_EL1.read(ESR_EL1::EC)
}

/// Lê o registrador de endereço da falha (`FAR_EL1`).
///
/// Contém o endereço acusado numa falha de acesso a memória — o equivalente
/// ao CR2 do x86. Só é significativo para abortos de dado ou de instrução.
fn ler_far() -> u64 {
    FAR_EL1.get()
}

/// Traduz a classe de exceção (campo EC do ESR) para um nome estável.
///
/// Os códigos vêm do manual de arquitetura ARM (seção sobre ESR_ELx).
const fn nome_da_classe(ec: u64) -> &'static str {
    match ec {
        0x00 => "unknown",
        0x0E => "illegal_execution_state",
        0x15 => "svc",
        0x18 => "msr_mrs_trap",
        0x20 => "instruction_abort_lower_el",
        0x21 => "instruction_abort",
        0x22 => "pc_alignment_fault",
        0x24 => "data_abort_lower_el",
        0x25 => "data_abort",
        0x26 => "sp_alignment_fault",
        0x3C => "breakpoint",
        _ => "sync_desconhecida",
    }
}

/// Handler de exceções síncronas: causadas pela instrução que estava
/// executando (acesso inválido a memória, instrução ilegal, `brk`, `svc`).
#[unsafe(no_mangle)]
extern "C" fn tratar_sync(quadro: &mut Quadro) {
    let esr = ler_esr();
    let ec = classe_da_excecao();
    let nome = nome_da_classe(ec);

    // `SVC` é a chamada de sistema. Hoje tem um único uso: um fio de execução
    // pedindo para ceder a vez. Passa por aqui de propósito — assim a cessão
    // voluntária e a preempção usam exatamente o mesmo caminho de troca, sobre
    // o mesmo quadro montado do mesmo jeito.
    //
    // O `eret` volta para a instrução *seguinte* ao `svc` sem que precisemos
    // ajustar nada: diferente do `brk`, o processador já deixa `ELR_EL1`
    // apontando para depois dela.
    if ec == 0x15 {
        // SAFETY: estamos dentro de um handler de exceção, com as interrupções
        // mascaradas pela própria entrada da exceção.
        unsafe { super::contexto::trocar_no_quadro(quadro) };
        return;
    }

    // `BRK` é a única outra classe que sabemos retomar hoje.
    if ec == 0x3C {
        let seq = crate::traps::registrar(nome, quadro.elr, None, esr);
        crate::log_info!("traps", "breakpoint #{} em pc={:#x}", seq, quadro.elr);

        // Sem este avanço o `eret` voltaria para a *mesma* instrução `brk` e
        // o kernel entraria num laço infinito de exceções. Toda instrução
        // aarch64 tem 4 bytes, então o próximo endereço é sempre elr + 4.
        quadro.elr += 4;
        return;
    }

    // Um endereço acusado só faz sentido para falhas de acesso a memória; nas
    // demais classes o FAR contém lixo de uma falha anterior.
    let endereco = matches!(ec, 0x20 | 0x21 | 0x24 | 0x25).then(ler_far);

    crate::traps::fatal(nome, quadro.elr, endereco, esr)
}

/// Handler de IRQ: interrupção de hardware.
///
/// Delega ao GIC, que identifica a fonte, atende e finaliza. O quadro salvo
/// não é consultado hoje, mas existe e está correto — é dele que o scheduler
/// preemptivo vai precisar na fase 1, quando uma interrupção de timer puder
/// resultar em troca de contexto.
#[unsafe(no_mangle)]
extern "C" fn tratar_irq(quadro: &mut Quadro) {
    let preemptar = super::gic::tratar();

    if preemptar {
        // A troca acontece **depois** de o GIC ter sido avisado do fim do
        // atendimento, lá dentro de `tratar`. Se trocássemos antes, a linha do
        // timer ficaria eternamente em atendimento e o próximo tique nunca
        // chegaria — o sistema trocaria de fio uma única vez.
        //
        // SAFETY: estamos dentro de um handler de exceção, com as interrupções
        // mascaradas pela própria entrada da exceção.
        unsafe { super::contexto::trocar_no_quadro(quadro) };
    }
}

/// Handler de FIQ: interrupção rápida, de prioridade mais alta.
#[unsafe(no_mangle)]
extern "C" fn tratar_fiq(quadro: &mut Quadro) {
    let seq = crate::traps::registrar("fiq", quadro.elr, None, 0);
    crate::log_warn!("traps", "FIQ inesperada #{} em pc={:#x}", seq, quadro.elr);
}

/// Handler de SError: erro assíncrono do sistema.
///
/// Tipicamente sinaliza um problema de barramento ou de memória detectado
/// depois do fato. Como é assíncrono, o `pc` salvo não aponta necessariamente
/// para a instrução culpada — por isso é fatal: não há a que retornar com
/// confiança.
#[unsafe(no_mangle)]
extern "C" fn tratar_serror(quadro: &mut Quadro) {
    crate::traps::fatal("serror", quadro.elr, None, ler_esr())
}

/// Instala a tabela de vetores em `VBAR_EL1`.
pub fn init() {
    // SAFETY: o símbolo é definido pelo assembly acima e tem o alinhamento de
    // 2 KiB que VBAR_EL1 exige.
    unsafe extern "C" {
        static tabela_vetores_el1: u8;
    }

    VBAR_EL1.set(&raw const tabela_vetores_el1 as u64);

    // Obrigatório: sem ele o processador pode continuar usando o VBAR antigo
    // por algumas instruções, e uma exceção nesse intervalo saltaria para o
    // lugar errado.
    barrier::isb(barrier::SY);
}

/// O nível de exceção em que o kernel está rodando.
///
/// Útil no diagnóstico: `VBAR_EL1` só governa exceções tomadas *em* EL1, então
/// se tivéssemos bootado em EL2 a tabela não teria efeito — e isso explicaria
/// um silêncio difícil de entender.
pub fn nivel_de_excecao() -> u8 {
    CurrentEL.read(CurrentEL::EL) as u8
}
