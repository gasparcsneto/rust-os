//! Os resumos e o HMAC do TLS 1.3: SHA-256 e SHA-384, do RustCrypto.
//!
//! O resumo da transcrição do aperto e o HKDF do escalonamento de chaves
//! (RFC 8446, 7.1) — este, montado pelo próprio `rustls` sobre o HMAC daqui
//! (`HkdfUsingHmac`).
//!
//! A forma segue a do exemplo de provedor do `rustls`
//! (`provider-example/src/hash.rs` e `hmac.rs`) — ver `THIRD_PARTY.md` —,
//! genérica no resumo.

use alloc::boxed::Box;
use core::marker::PhantomData;

use hmac::{Hmac, KeyInit, Mac};
use rustls::crypto::hash::{self, HashAlgorithm};
use rustls::crypto::hmac as rhmac;
use sha2::Digest;

/// Um resumo do `sha2`, com o nome que o `rustls` lhe dá.
pub(crate) struct Resumo<D> {
    algoritmo: HashAlgorithm,
    _d: PhantomData<fn() -> D>,
}

pub(crate) static SHA256: Resumo<sha2::Sha256> = Resumo {
    algoritmo: HashAlgorithm::SHA256,
    _d: PhantomData,
};

pub(crate) static SHA384: Resumo<sha2::Sha384> = Resumo {
    algoritmo: HashAlgorithm::SHA384,
    _d: PhantomData,
};

impl<D> hash::Hash for Resumo<D>
where
    D: Digest + Clone + Send + Sync + 'static,
{
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Contexto(D::new()))
    }

    fn hash(&self, dados: &[u8]) -> hash::Output {
        hash::Output::new(&D::digest(dados))
    }

    fn output_len(&self) -> usize {
        <D as Digest>::output_size()
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.algoritmo
    }
}

struct Contexto<D>(D);

impl<D> hash::Context for Contexto<D>
where
    D: Digest + Clone + Send + Sync + 'static,
{
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Contexto(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize())
    }

    fn update(&mut self, dados: &[u8]) {
        self.0.update(dados);
    }
}

/// O HMAC sobre um resumo do `sha2`.
pub(crate) struct ComChave<D>(PhantomData<fn() -> D>);

pub(crate) static HMAC_SHA256: ComChave<sha2::Sha256> = ComChave(PhantomData);
pub(crate) static HMAC_SHA384: ComChave<sha2::Sha384> = ComChave(PhantomData);

impl rhmac::Hmac for ComChave<sha2::Sha256> {
    fn with_key(&self, chave: &[u8]) -> Box<dyn rhmac::Key> {
        // O HMAC aceita chave de qualquer tamanho: a mais longa que o bloco
        // é resumida, a mais curta é completada.
        Box::new(Chave {
            mac: <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(chave)
                .expect("o HMAC aceita qualquer chave"),
            tamanho: self.hash_output_len(),
        })
    }

    fn hash_output_len(&self) -> usize {
        <sha2::Sha256 as Digest>::output_size()
    }
}

impl rhmac::Hmac for ComChave<sha2::Sha384> {
    fn with_key(&self, chave: &[u8]) -> Box<dyn rhmac::Key> {
        Box::new(Chave {
            mac: <Hmac<sha2::Sha384> as KeyInit>::new_from_slice(chave)
                .expect("o HMAC aceita qualquer chave"),
            tamanho: self.hash_output_len(),
        })
    }

    fn hash_output_len(&self) -> usize {
        <sha2::Sha384 as Digest>::output_size()
    }
}

/// Um HMAC com a chave, e o tamanho da etiqueta — o do resumo.
struct Chave<M> {
    mac: M,
    tamanho: usize,
}

impl<M> rhmac::Key for Chave<M>
where
    M: Mac + Clone + Send + Sync,
{
    fn sign_concat(&self, primeiro: &[u8], meio: &[&[u8]], ultimo: &[u8]) -> rhmac::Tag {
        let mut m = self.mac.clone();
        m.update(primeiro);
        for pedaco in meio {
            m.update(pedaco);
        }
        m.update(ultimo);
        rhmac::Tag::new(&m.finalize().into_bytes())
    }

    fn tag_len(&self) -> usize {
        self.tamanho
    }
}
