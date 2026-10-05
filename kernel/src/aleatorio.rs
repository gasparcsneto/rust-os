//! Números aleatórios para o kernel.
//!
//! O gerador é o [`sigilo::Gerador`] — ChaCha20 com apagamento rápido da
//! chave —, semeado com 32 bytes do [`crate::virtio::entropia`] e
//! realimentado por ele de tempos em tempos.
//!
//! # Falhar fechado
//!
//! Sem fonte de entropia não há gerador, e [`preencher`] devolve erro. Quem
//! pede — o aperto de mão das portas, o desafio administrativo — recusa o que
//! ia fazer. A alternativa, semear com o relógio "por enquanto", produziria
//! chaves que parecem chaves e que qualquer um que saiba a hora do boot
//! reproduz. Uma porta que recusa conexões avisa que algo falta; uma que
//! aceita com chaves fracas não avisa nada.
//!
//! # A realimentação
//!
//! A cada [`PEDIDOS_POR_REALIMENTACAO`] pedidos o gerador mistura 32 bytes
//! novos do dispositivo. Não é o que o torna seguro — a semente basta para
//! isso —, é o que limita o estrago de um estado que vazou: dali a alguns
//! pedidos, quem tem o estado antigo não sabe mais o novo.

use crate::trava::Mutex;

/// A cada quantos pedidos o gerador recebe entropia nova.
pub const PEDIDOS_POR_REALIMENTACAO: u32 = 64;

struct Estado {
    gerador: sigilo::Gerador,
    pedidos: u32,
}

static GERADOR: Mutex<Option<Estado>> = Mutex::new(None);

/// Não há fonte de entropia: o gerador não foi semeado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SemEntropia;

/// Semeia o gerador com a fonte, se houver.
pub fn init() {
    let mut semente = [0u8; 32];
    if !crate::virtio::entropia::ler(&mut semente) {
        crate::log_warn!(
            "aleatorio",
            "gerador sem semente: nada que dependa de chave efemera vai funcionar"
        );
        return;
    }
    let gerador = sigilo::Gerador::novo(semente);
    crate::arch::sem_interrupcoes(|| {
        *GERADOR.lock() = Some(Estado {
            gerador,
            pedidos: 0,
        })
    });
    crate::log_info!("aleatorio", "gerador semeado com 32 bytes do virtio-rng");
}

/// Enche `destino` de bytes aleatórios.
pub fn preencher(destino: &mut [u8]) -> Result<(), SemEntropia> {
    // A realimentação lê o dispositivo fora da trava do gerador: as duas
    // travas nunca ficam presas ao mesmo tempo, e a ordem entre elas não
    // precisa de regra.
    let realimentar = crate::arch::sem_interrupcoes(|| {
        let mut guarda = GERADOR.lock();
        let estado = guarda.as_mut().ok_or(SemEntropia)?;
        estado.pedidos += 1;
        Ok(estado.pedidos % PEDIDOS_POR_REALIMENTACAO == 0)
    })?;

    let mut nova = [0u8; 32];
    let veio = realimentar && crate::virtio::entropia::ler(&mut nova);

    let resultado = crate::arch::sem_interrupcoes(|| {
        let mut guarda = GERADOR.lock();
        let estado = guarda.as_mut().ok_or(SemEntropia)?;
        if veio {
            estado.gerador.misturar(&nova);
        }
        estado.gerador.preencher(destino);
        Ok(())
    });
    sigilo::zeroize::Zeroize::zeroize(&mut nova);
    resultado
}

/// Uma chave de 32 bytes: uma efêmera X25519, um nonce.
pub fn chave() -> Result<[u8; 32], SemEntropia> {
    let mut k = [0u8; 32];
    preencher(&mut k)?;
    Ok(k)
}

/// Se o gerador foi semeado.
pub fn semeado() -> bool {
    crate::arch::sem_interrupcoes(|| GERADOR.lock().is_some())
}

/// Destrava o gerador à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        GERADOR.force_unlock();
    }
}
