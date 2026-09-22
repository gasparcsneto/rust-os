//! Entrada em EL0 e chamadas de sistema no aarch64.
//!
//! # Muito mais simples que no x86, e por uma boa razão
//!
//! No x86 a instrução `syscall` não troca a pilha, e o ponto de entrada do
//! kernel começa a executar sobre um ponteiro que o processo controla — daí o
//! `swapgs`, os dados por núcleo e toda a coreografia para sair de lá antes de
//! empilhar qualquer coisa.
//!
//! No ARM isso não existe. Uma exceção vinda de EL0 já chega com `SP_EL1`, a
//! pilha de exceção do kernel, selecionada pelo hardware. O `svc` do usuário
//! entra pela mesma tabela de vetores que todas as outras exceções, com o
//! contexto completo salvo do mesmo jeito. Não há nada a preparar.
//!
//! O único trabalho é distinguir de onde veio o `svc` — EL0 é chamada de
//! sistema, EL1 é um fio do kernel cedendo a vez —, e isso está escrito no
//! `SPSR` que o próprio processador salvou.
//!
//! # Descer para EL0
//!
//! Como no x86, não há instrução de "entrar em userspace": usa-se a de
//! retornar de exceção. Montamos um `SPSR` que descreve EL0, apontamos `ELR`
//! para o código do processo, `SP_EL0` para a pilha dele, e o `eret` faz o
//! resto.

use core::arch::asm;

use super::vetores::Quadro;

/// `PSTATE` de um processo em EL0.
///
/// - `M[3:0] = 0b0000`: EL0t. Em EL0 só existe `SP_EL0`, então não há sufixo
///   `h`/`t` para escolher — o `t` é o único valor legal.
/// - `I = 0`: IRQs desmascaradas. Um processo impreemptável travaria a máquina
///   no primeiro laço infinito, e não há nada que o kernel pudesse fazer.
/// - `D`, `A`, `F = 1`: como no resto do kernel.
const SPSR_USUARIO: u64 = (1 << 9) | (1 << 8) | (1 << 6);

/// Máscara do campo de modo dentro do `SPSR`.
const MASCARA_DE_MODO: u64 = 0b1111;
/// Valor do campo de modo para EL0.
const MODO_EL0: u64 = 0b0000;

/// O `svc` veio do anel sem privilégio?
///
/// A pergunta é respondida pelo `SPSR` salvo, que descreve o estado de **quem
/// foi interrompido**. É mais robusto que olhar o imediato do `svc`: o
/// imediato é escolhido pelo processo, e o processo não é confiável.
pub fn veio_de_usuario(quadro: &Quadro) -> bool {
    quadro.spsr & MASCARA_DE_MODO == MODO_EL0
}

/// Atende uma chamada de sistema vinda de EL0, sobre o quadro da exceção.
///
/// A ABI segue a do Linux em aarch64: `x8` traz o número, `x0`–`x2` os
/// argumentos, e o retorno volta em `x0`.
pub fn atender_chamada(quadro: &mut Quadro) {
    let numero = quadro.x[8];
    let (a0, a1, a2) = (quadro.x[0], quadro.x[1], quadro.x[2]);

    // SAFETY: o quadro é o desta exceção; `bifurcar` e `executar` o leem e o
    // reescrevem, e é por isso que ele desce até o despacho.
    let resultado = unsafe {
        crate::usuario::despachar(
            numero,
            a0,
            a1,
            a2,
            quadro as *mut Quadro as *mut core::ffi::c_void,
        )
    };
    quadro.x[0] = resultado as u64;
}

/// Nada a preparar: o mecanismo de chamada de sistema do ARM já está de pé
/// assim que a tabela de vetores está.
///
/// # Safety
///
/// Existe por simetria com o x86, onde esta função escreve quatro
/// registradores de modelo específico. Aqui não há estado a ligar.
pub unsafe fn init() {
    crate::log_info!("usuario", "svc de EL0 atendido pela tabela de vetores");
}

/// Informa a pilha de kernel do fio que vai rodar.
///
/// No ARM não há o que fazer: as exceções têm `SP_EL1` só delas, e o hardware
/// a seleciona sozinho. A função existe para o contrato de [`crate::arch`] ser
/// o mesmo nas duas arquiteturas — no x86 ela alimenta o `RSP0` do TSS e a
/// global que o ponto de entrada de `syscall` consulta.
pub fn definir_pilha_de_kernel(_topo: u64) {}

/// Desce para EL0 e começa a executar em `entrada`. Nunca retorna.
///
/// # Safety
///
/// `entrada` e `pilha` precisam estar mapeados com permissão de EL0.
pub unsafe fn entrar(entrada: u64, pilha: u64) -> ! {
    // SAFETY: o `eret` abaixo consome ELR/SPSR/SP_EL0 que acabamos de escrever
    // e descreve uma volta a EL0 que nunca aconteceu — que é como se entra em
    // userspace pela primeira vez.
    unsafe {
        asm!(
            // Mascarar IRQs até o `eret`. A janela abaixo troca o ponteiro de
            // pilha corrente e escreve os três registradores que definem para
            // onde vamos; uma interrupção no meio disso encontraria um estado
            // pela metade. O `eret` religa as IRQs sozinho, porque o `SPSR`
            // que ele restaura tem o bit `I` zerado.
            "msr daifset, #2",

            // `MSR SP_EL0` é **UNDEFINED** quando o código que a executa já
            // está usando `SP_EL0` como pilha — e é esse o caso: os fios do
            // kernel rodam em EL1t. O processador não trata isso como acesso
            // negado, e sim como instrução inexistente: exceção de classe
            // "unknown", com o `pc` apontando para cá.
            //
            // Passar para `SP_EL1` primeiro resolve, e a pilha de exceção é um
            // lugar perfeitamente válido para as quatro instruções que faltam.
            "msr spsel, #1",

            "msr sp_el0, {pilha}",
            "msr elr_el1, {entrada}",
            "msr spsr_el1, {spsr}",
            "eret",
            pilha = in(reg) pilha,
            entrada = in(reg) entrada,
            spsr = in(reg) SPSR_USUARIO,
            options(noreturn),
        )
    }
}
