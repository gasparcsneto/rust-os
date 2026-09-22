//! Troca de contexto no aarch64.
//!
//! # Por que não é uma troca de pilha, como no x86
//!
//! No x86 o quadro de interrupção é empilhado na pilha do fio interrompido, e
//! trocar de fio é trocar de pilha. Aqui não: este kernel roda os fios em
//! `SP_EL0` e atende exceções em `SP_EL1`, e é essa separação que faz um
//! estouro de pilha virar uma falha diagnosticável em vez de um laço de
//! abortos — o handler sempre tem uma pilha íntegra para trabalhar.
//!
//! Trocar `SP_EL1` de dentro do handler destruiria isso. Mas a separação
//! também **oferece** um caminho melhor: quando o handler roda, o contexto
//! completo do fio interrompido já está salvo num [`Quadro`], montado pela
//! tabela de vetores. Não é preciso salvar nada de novo.
//!
//! Então a troca aqui é literalmente trocar o quadro: guardamos o do fio que
//! sai, escrevemos por cima o do fio que entra, ajustamos `SP_EL0`, e deixamos
//! o `eret` do fim do handler fazer o resto. Ele restaura trinta e um
//! registradores, o `PC` e o estado do processador de uma vez só — trabalho
//! que no x86 teria de ser escrito à mão.
//!
//! # Por que ceder de propósito passa por `svc`
//!
//! Porque assim existe **um** caminho de troca, não dois. Uma cessão
//! voluntária vira uma exceção síncrona, cai no mesmo handler que a
//! preempção, e encontra o mesmo quadro montado do mesmo jeito. Metade dos
//! bugs de escalonador nasce de dois caminhos que deveriam ser equivalentes e
//! não são.
//!
//! De quebra, é o mecanismo que o userspace vai usar para chamadas de sistema
//! na próxima etapa: `svc` já é a instrução certa.

use core::arch::asm;

use super::vetores::Quadro;

/// O estado salvo de um fio que não está executando.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Contexto {
    /// A pilha do fio. Vive em `SP_EL0`, que o hardware troca sozinho na
    /// entrada e na saída da exceção.
    ///
    /// Enquanto o fio executa em EL0, este campo guarda a pilha do **processo**
    /// — é a mesma `SP_EL0`, agora apontando para o espaço do usuário.
    pub sp: u64,
    /// O quadro de exceção completo: registradores, `PC` e `PSTATE`.
    pub quadro: Quadro,
    /// O topo da pilha de kernel deste fio.
    ///
    /// No ARM o kernel não precisa dele para atender exceções — elas têm
    /// `SP_EL1` só delas. Existe para manter o contrato igual ao do x86 e para
    /// o dia em que cada fio tiver sua própria pilha de exceção.
    pub pilha_de_kernel: u64,
}

impl Contexto {
    pub const fn vazio() -> Self {
        Self {
            sp: 0,
            quadro: Quadro {
                x: [0; 31],
                elr: 0,
                spsr: 0,
            },
            pilha_de_kernel: 0,
        }
    }

    pub fn pilha_de_kernel(&self) -> u64 {
        self.pilha_de_kernel
    }
}

/// `PSTATE` de um fio do kernel pronto para rodar.
///
/// - `M[3:0] = 0b0100`: EL1t, ou seja, EL1 usando `SP_EL0`. É o modo em que os
///   fios do kernel rodam — o `t` vem de *thread*.
/// - `I = 0`: IRQs desmascaradas. Sem isto o fio nasceria impreemptável, e o
///   primeiro que entrasse num laço travaria o sistema.
/// - `D`, `A`, `F = 1`: mascaradas, que é o estado em que o kernel já opera
///   desde o boot.
const SPSR_FIO_DO_KERNEL: u64 = (1 << 9) | (1 << 8) | (1 << 6) | 0b0100;

/// Monta o contexto inicial de um fio novo.
///
/// # Safety
///
/// `topo` precisa ser o endereço logo acima de uma pilha mapeada e exclusiva
/// deste fio.
pub unsafe fn preparar_contexto(
    contexto: &mut Contexto,
    topo: u64,
    entrada: extern "C" fn(u64) -> !,
    argumento: u64,
) {
    contexto.sp = topo & !0xF;
    contexto.pilha_de_kernel = topo & !0xF;
    contexto.quadro = Quadro {
        x: [0; 31],
        // O `eret` salta para cá com os argumentos já nos registradores.
        //
        // O caminho por ponteiro de função, em vez do `as usize` direto, é o
        // que o compilador pede: um *item* de função não tem endereço até ser
        // coagido a ponteiro.
        elr: (trampolim_de_fio as extern "C" fn(u64, u64) -> !) as *const () as u64,
        spsr: SPSR_FIO_DO_KERNEL,
    };
    contexto.quadro.x[0] = entrada as *const () as u64;
    contexto.quadro.x[1] = argumento;
}

/// Primeira coisa que um fio novo executa.
///
/// Recebe a função de entrada e o argumento porque foi assim que
/// [`preparar_contexto`] deixou `x0` e `x1`. Não há assembly aqui: a convenção
/// de chamada já põe os dois no lugar certo.
extern "C" fn trampolim_de_fio(entrada: u64, argumento: u64) -> ! {
    // SAFETY: `entrada` foi guardado por `preparar_contexto` a partir de um
    // ponteiro de função com exatamente esta assinatura.
    let entrada: extern "C" fn(u64) -> ! = unsafe { core::mem::transmute(entrada) };
    entrada(argumento)
}

fn ler_sp_el0() -> u64 {
    let valor: u64;
    // SAFETY: `SP_EL0` é acessível a partir de EL1.
    unsafe { asm!("mrs {}, sp_el0", out(reg) valor, options(nomem, nostack)) };
    valor
}

/// # Safety
/// O valor precisa apontar para uma pilha válida e alinhada em 16 bytes; o
/// processador gera exceção de alinhamento ao usar um `SP` torto.
unsafe fn escrever_sp_el0(valor: u64) {
    // SAFETY: delegada ao chamador pelo contrato acima.
    unsafe { asm!("msr sp_el0, {}", in(reg) valor, options(nomem, nostack)) };
}

/// Executa a troca de fio sobre o quadro de exceção corrente.
///
/// Chamada de dentro de um handler, com o quadro que a tabela de vetores
/// montou. Ao retornar, o quadro descreve o **outro** fio, e o `eret` do fim
/// do handler o coloca em execução.
///
/// # Safety
///
/// Precisa ser chamada de dentro de um handler de exceção, com as interrupções
/// mascaradas — o que a entrada da exceção já garante.
pub unsafe fn trocar_no_quadro(quadro: &mut Quadro) {
    // SAFETY: estamos num handler, com as interrupções mascaradas pela própria
    // entrada da exceção, que é o que `selecionar` exige.
    let Some(troca) = (unsafe { crate::fios::selecionar() }) else {
        return;
    };

    // SAFETY: os dois ponteiros vêm da tabela do escalonador e são válidos
    // enquanto as interrupções seguirem mascaradas.
    unsafe {
        (*troca.de).quadro = *quadro;
        (*troca.de).sp = ler_sp_el0();

        *quadro = (*troca.para).quadro;
        escrever_sp_el0((*troca.para).sp);

        // O espaço de endereços do fio que entra. Trocar de dentro do handler
        // é seguro porque as duas raízes carregam as mesmas entradas de topo
        // do kernel — o código que executa esta linha e a pilha de exceção
        // seguem mapeados dos dois lados.
        //
        // Comparar antes de escrever importa mais aqui que no x86: sem ASID,
        // cada troca de TTBR0 obriga a descartar a TLB inteira, e fios do
        // kernel compartilham o espaço.
        if troca.espaco != super::mmu::espaco_atual() {
            super::mmu::trocar_espaco(troca.espaco);
        }
    }
}

/// Cede a CPU ao próximo fio pronto.
///
/// O `svc` levanta uma exceção síncrona, que o handler reconhece e resolve
/// chamando [`trocar_no_quadro`]. O retorno desta função acontece do outro
/// lado da troca — possivelmente muito tempo depois, e só quando este fio for
/// escalonado de novo.
pub fn ceder_cpu() {
    // SAFETY: `svc` é uma chamada de sistema; o handler de exceções síncronas
    // reconhece o imediato 0 como pedido de cessão e retorna normalmente.
    unsafe { asm!("svc #0", options(nomem, nostack)) };
}
