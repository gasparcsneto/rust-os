//! O runtime dos programas de usuário do Duke.
//!
//! # O que um programa precisa, e que o kernel não dá
//!
//! Um programa compilado para `none` não tem `std`, e sem `std` não tem quem
//! o comece, quem fale com o kernel, de onde alocar nem para onde ir quando
//! entra em pânico. Este pacote é essas quatro coisas — e as superfícies, que
//! são o que um programa com janela precisa a mais:
//!
//! - **a entrada** — `_start`, abaixo: alinha a pilha e chama o `principal`
//!   do programa; o que ele devolver é o código de saída;
//! - **as chamadas de sistema** — [`sistema`], com os números de
//!   [`protocolo::usuario`], os mesmos que o kernel inclui;
//! - **o monte** — [`monte`], um alocador que pede páginas ao kernel por
//!   `mapear` e as reparte, e é o que faz `Vec` e `String` funcionarem;
//! - **a saída** — [`escreverln!`], uma linha formatada por chamada;
//! - **as superfícies** — [`superficie`], uma camada do compositor com os
//!   pixels na memória do processo, e o endereço escolhido por ele;
//!   [`desenho`], retângulos e texto com a fonte do console; e [`janela`],
//!   a moldura que o servidor de janelas e o Terminal compartilham.
//!
//! # Como um programa se escreve
//!
//! ```ignore
//! #![no_std]
//! #![no_main]
//!
//! #[unsafe(no_mangle)]
//! fn principal() -> i64 {
//!     programas::escreverln!("ola");
//!     0
//! }
//! ```
//!
//! O nome `principal` é o contrato entre este runtime e o programa: é o que
//! a entrada chama, e o ligador reclama se nenhum programa o definir.
//!
//! # Um processo, um fio
//!
//! Não há fios no espaço do usuário: um processo é um fluxo só, e o kernel
//! não entra no meio dele para rodar outro código do mesmo processo. É por
//! isso que o monte e a saída não têm trava — e é a primeira coisa que muda
//! no dia em que houver fios de usuário.

#![no_std]

extern crate alloc;

pub mod desenho;
pub mod dns;
pub mod janela;
pub mod manifesto;
pub mod monte;
pub mod nativo;
pub mod saida;
pub mod sistema;
pub mod superficie;

// Para a macro `manifesto!`, que monta a nota com o envelope do protocolo.
#[doc(hidden)]
pub use protocolo as __protocolo;

// A função que cada programa define. O nome é o contrato — ver o cabeçalho.
unsafe extern "Rust" {
    fn principal() -> i64;
}

/// Onde o programa começa de verdade, depois de `_start` arrumar a pilha.
extern "C" fn comecar() -> ! {
    // SAFETY: `principal` é definida pelo programa, sem argumentos, e é o que
    // o ligador resolveu para este símbolo.
    let codigo = unsafe { principal() };
    sistema::sair(codigo)
}

// A entrada, antes de haver Rust.
//
// O kernel entrega o controle com a pilha alinhada a 16, e as duas ABIs
// pedem outra coisa na entrada de uma função: no x86, a pilha alinhada a 16
// **antes** do `call`, ou seja, deslocada de 8 depois dele. Um `_start`
// escrito em Rust começaria com a pilha fora do que o compilador supõe. Aqui
// ela é alinhada de novo — o kernel já entrega assim, e realinhar não custa
// nada e não depende disso — e `comecar` é chamada como qualquer função.
//
// O quadro zerado (`rbp`, `x29` e `x30`) marca o fim da cadeia de quadros:
// quem percorrer a pilha para aqui, em vez de seguir lixo.
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".section .text.inicio, \"ax\"",
    ".global _start",
    "_start:",
    "    xor ebp, ebp",
    "    and rsp, -16",
    "    call {comecar}",
    "    ud2",
    comecar = sym comecar,
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".section .text.inicio, \"ax\"",
    ".global _start",
    "_start:",
    "    mov x29, xzr",
    "    mov x30, xzr",
    "    bl {comecar}",
    "    brk #1",
    comecar = sym comecar,
);

/// O código com que um processo sai quando entra em pânico.
///
/// O mesmo do `std` do Rust num `panic = "abort"` que chega ao fim: um valor
/// que quem colhe o processo reconhece, distinto de qualquer código que um
/// programa escolha para dizer o que deu errado.
pub const CODIGO_DE_PANICO: i64 = 101;

#[panic_handler]
fn panico(info: &core::panic::PanicInfo) -> ! {
    // Pela saída de diagnóstico, que o kernel registra como erro: o pânico é
    // a última coisa que o processo diz, e é quem estiver lendo o log quem
    // precisa ver.
    let _ = saida::escrever_linha(
        sistema::DIAGNOSTICO,
        format_args!("panico: {}", info.message()),
    );
    sistema::sair(CODIGO_DE_PANICO)
}
