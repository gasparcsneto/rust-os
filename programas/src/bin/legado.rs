//! Pede ao sistema, não busca a resposta, e troca de imagem pelo `anonimo`
//! — que não pode encontrá-la. A resposta era desta imagem, com o manifesto
//! desta: buscada pela nova, seria a nova lendo o que só esta podia pedir.
//!
//! Sai com o código do `anonimo` quando tudo confere; com um código próprio
//! se o `executar` voltar.

#![no_std]
#![no_main]

programas::manifesto!("legado", "system.read", "process.run");

use programas::sistema;

/// O `anonimo` desta arquitetura.
#[cfg(target_arch = "x86_64")]
const ANONIMO: &str = "/programas/x86_64/anonimo";
#[cfg(target_arch = "aarch64")]
const ANONIMO: &str = "/programas/aarch64/anonimo";

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let pedido = br#"{"jsonrpc":"2.0","id":1,"method":"system.info","params":{}}"#;
    if sistema::pedir(pedido) <= 0 {
        return 1;
    }
    // A resposta fica no kernel, sem ser buscada, e a imagem troca.
    sistema::executar(ANONIMO);
    2
}
