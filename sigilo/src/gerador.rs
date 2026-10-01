//! O gerador de números aleatórios: ChaCha20 com apagamento rápido da chave.
//!
//! # Por que um gerador, e não a fonte de entropia direto
//!
//! A fonte — o `virtio-rng`, no Duke — é lenta e pode faltar no meio do
//! caminho. O gerador pega 32 bytes dela uma vez e produz quantos forem
//! precisos, indistinguíveis de aleatórios para quem não conhece a chave.
//! Cada aperto de mão consome 32 bytes; um desafio administrativo, 64.
//!
//! # O apagamento rápido da chave
//!
//! A cada pedido, o gerador produz o fluxo do ChaCha20 sob a chave atual e
//! usa os **primeiros 32 bytes como a próxima chave**, antes de entregar o
//! resto. A chave anterior some.
//!
//! O que isso compra é o passado. Se alguém um dia ler a memória do kernel e
//! achar a chave do gerador, não consegue recalcular as efêmeras que já
//! saíram dele — e com elas as sessões já encerradas continuam fechadas. Um
//! gerador que só avançasse um contador sob a mesma chave entregaria toda a
//! história junto com o estado.
//!
//! É a construção descrita por Daniel J. Bernstein ("fast-key-erasure
//! random-number generators", 2017), a mesma do `arc4random` do OpenBSD.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use zeroize::Zeroize;

use crate::resumo::resumir;

/// O rótulo da mistura de entropia nova.
const ROTULO_DA_MISTURA: &[u8] = b"Duke gerador: mistura v1";

/// Quantos bytes cada volta entrega, além da chave seguinte.
const POR_VOLTA: usize = 256;

/// Um gerador semeado.
pub struct Gerador {
    chave: [u8; 32],
}

impl Gerador {
    /// Um gerador a partir de uma semente de 32 bytes de entropia.
    pub fn novo(semente: [u8; 32]) -> Self {
        // A semente passa pelo resumo antes de virar chave: uma fonte com
        // viés produz uma chave sem ele.
        let mut semente = semente;
        let chave = resumir(&[ROTULO_DA_MISTURA, &semente]);
        semente.zeroize();
        Self { chave }
    }

    /// Mistura entropia nova no estado, sem descartar a que já havia.
    pub fn misturar(&mut self, entropia: &[u8]) {
        self.chave = resumir(&[ROTULO_DA_MISTURA, &self.chave, entropia]);
    }

    /// Enche `destino` de bytes aleatórios.
    pub fn preencher(&mut self, destino: &mut [u8]) {
        let mut volta = [0u8; 32 + POR_VOLTA];
        for pedaco in destino.chunks_mut(POR_VOLTA) {
            volta.fill(0);
            // O nonce pode ser fixo: a chave nunca se repete, porque cada
            // volta a substitui.
            let mut cifra = ChaCha20::new(&self.chave.into(), &[0u8; 12].into());
            cifra.apply_keystream(&mut volta[..32 + pedaco.len()]);
            self.chave.copy_from_slice(&volta[..32]);
            pedaco.copy_from_slice(&volta[32..32 + pedaco.len()]);
        }
        volta.zeroize();
    }

    /// Uma chave de 32 bytes, para uso direto como chave privada X25519.
    pub fn chave(&mut self) -> [u8; 32] {
        let mut k = [0u8; 32];
        self.preencher(&mut k);
        k
    }
}

impl Drop for Gerador {
    fn drop(&mut self) {
        self.chave.zeroize();
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    /// A mesma semente dá a mesma sequência; outra, outra.
    #[test]
    fn determinado_pela_semente() {
        let mut a = Gerador::novo([1; 32]);
        let mut b = Gerador::novo([1; 32]);
        let mut c = Gerador::novo([2; 32]);
        let (mut x, mut y, mut z) = ([0u8; 600], [0u8; 600], [0u8; 600]);
        a.preencher(&mut x);
        b.preencher(&mut y);
        c.preencher(&mut z);
        assert_eq!(x, y);
        assert_ne!(x, z);
    }

    /// Dois pedidos seguidos não se repetem, e o estado mudou depois de
    /// cada um: a chave antiga sumiu.
    #[test]
    fn a_chave_e_apagada_a_cada_pedido() {
        let mut g = Gerador::novo([9; 32]);
        let antes = g.chave;
        let primeiro = g.chave();
        let meio = g.chave;
        let segundo = g.chave();
        assert_ne!(primeiro, segundo);
        assert_ne!(antes, meio);
        assert_ne!(meio, g.chave);
        // A saída nunca é a chave que ficou guardada.
        assert_ne!(segundo, g.chave);
    }

    /// Um pedido que não é múltiplo da volta não perde nem repete bytes
    /// entre voltas.
    #[test]
    fn voltas_nao_se_sobrepoem() {
        let mut g = Gerador::novo([3; 32]);
        let mut grande = [0u8; 3 * POR_VOLTA + 17];
        g.preencher(&mut grande);
        for (i, a) in grande.chunks(POR_VOLTA).enumerate() {
            for b in grande.chunks(POR_VOLTA).skip(i + 1) {
                assert_ne!(a[..16], b[..16]);
            }
        }
    }
}
