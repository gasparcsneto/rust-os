//! Acesso global às informações de boot.
//!
//! O bootloader entrega o [`BootInfo`] uma única vez, como argumento do ponto
//! de entrada. Mas vários subsistemas precisam dele depois — os comandos do
//! agente, o alocador de frames, o driver de framebuffer — e passá-lo como
//! parâmetro por toda a árvore de chamadas poluiria cada assinatura.
//!
//! Guardamos então uma referência compartilhada num global. A referência é
//! `'static` porque o bootloader garante que a estrutura vive pelo tempo todo
//! de vida do kernel: ela fica numa região de memória que o mapa de memória
//! marca como reservada, justamente para não ser reaproveitada.

use bootloader_api::BootInfo;
use spin::Mutex;

static INFO: Mutex<Option<&'static BootInfo>> = Mutex::new(None);

/// Publica o [`BootInfo`] para o resto do kernel. Chame uma vez, no boot.
pub fn registrar(info: &'static BootInfo) {
    *INFO.lock() = Some(info);
}

/// Executa `f` com o [`BootInfo`], se ele já tiver sido registrado.
///
/// A API é um callback em vez de um getter que devolve a referência porque
/// assim o lock é liberado automaticamente ao fim da closure — não há como
/// esquecer de soltá-lo e travar o kernel.
pub fn com<R>(f: impl FnOnce(&'static BootInfo) -> R) -> Option<R> {
    let guarda = *INFO.lock();
    guarda.map(f)
}
