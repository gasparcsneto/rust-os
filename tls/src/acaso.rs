//! O aleatório do TLS: o gerador do `sigilo`, semeado por quem conecta.
//!
//! # Por que um gerador global
//!
//! O `rustls` pede o aleatório a um `&'static dyn SecureRandom`, e a troca
//! de chaves gera a chave efêmera por conta própria: as duas peças moram em
//! estáticos, e não numa conexão. O gerador mora, então, num estático
//! também, atrás de uma trava.
//!
//! # Por que a semente é de cada conexão
//!
//! [`semear`] **mistura** a semente de uma conexão no gerador — nunca a
//! substitui —, e quem conecta a passa sempre: ver
//! [`crate::Sessao::conectar`]. Um processo que se bifurcou leva para o
//! filho uma cópia do gerador; se o gerador só fosse semeado uma vez, pai e
//! filho tirariam dele a mesma chave efêmera, o mesmo `random`. Com a
//! semente de cada conexão — 32 bytes novos do kernel —, os dois divergem
//! na primeira.
//!
//! Sem semente nenhuma, [`preencher`] falha: o gerador não inventa
//! entropia, e o aperto não começa.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use sigilo::Gerador;
use zeroize::Zeroize;

/// Uma trava de giro. Num programa do Duke não há disputa — um processo é um
/// fio só —; nos testes do hospedeiro, sim, e por isso ela existe.
struct Trava<T> {
    ocupada: AtomicBool,
    valor: UnsafeCell<T>,
}

// SAFETY: o valor só é tocado com a trava tomada — ver [`Trava::com`] —, e
// o que ela guarda (um gerador) pode mudar de fio.
unsafe impl<T: Send> Sync for Trava<T> {}

impl<T> Trava<T> {
    const fn nova(valor: T) -> Self {
        Self {
            ocupada: AtomicBool::new(false),
            valor: UnsafeCell::new(valor),
        }
    }

    fn com<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        while self
            .ocupada
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: a trava foi tomada acima por este fio, e só é solta depois
        // que a referência deixa de existir.
        let r = f(unsafe { &mut *self.valor.get() });
        self.ocupada.store(false, Ordering::Release);
        r
    }
}

static GERADOR: Trava<Option<Gerador>> = Trava::nova(None);

/// Mistura `semente` no gerador — ou o cria com ela, na primeira vez. A
/// semente é apagada.
pub(crate) fn semear(mut semente: [u8; 32]) {
    GERADOR.com(|g| match g {
        Some(g) => g.misturar(&semente),
        None => *g = Some(Gerador::novo(semente)),
    });
    semente.zeroize();
}

/// Enche `destino` de bytes do gerador. `Err` se ele nunca foi semeado.
pub(crate) fn preencher(destino: &mut [u8]) -> Result<(), SemSemente> {
    GERADOR.com(|g| match g {
        Some(g) => {
            g.preencher(destino);
            Ok(())
        }
        None => Err(SemSemente),
    })
}

/// O gerador nunca foi semeado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SemSemente;

/// O aleatório do provedor — ver [`crate::provedor`].
#[derive(Debug)]
pub(crate) struct Acaso;

impl rustls::crypto::SecureRandom for Acaso {
    fn fill(&self, destino: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        preencher(destino).map_err(|_| rustls::crypto::GetRandomFailed)
    }
}
