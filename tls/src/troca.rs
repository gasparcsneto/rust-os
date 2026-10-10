//! A troca de chaves do aperto (RFC 8446, 4.2.8 e 7.4): X25519, do dalek,
//! e P-256, do RustCrypto.
//!
//! A chave efêmera sai do gerador semeado por quem conecta — ver
//! [`crate::acaso`] —, e não de uma fonte própria: o `rustls` deixa a
//! geração da chave com a troca, e é aqui que ela pede o aleatório.
//!
//! A forma da troca X25519 segue a do exemplo de provedor do `rustls`
//! (`provider-example/src/kx.rs`) — ver `THIRD_PARTY.md`. O que muda: o
//! acaso, e a recusa do ponto que não contribui, que o exemplo aceita.

use alloc::boxed::Box;
use alloc::vec::Vec;

use p256::elliptic_curve::sec1::ToSec1Point;
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved};
use zeroize::Zeroize;

use crate::acaso;

/// X25519 (RFC 7748).
#[derive(Debug)]
pub(crate) struct X25519;

/// P-256 — `secp256r1` —, com o ponto descomprimido da RFC 8446, 4.2.8.2.
#[derive(Debug)]
pub(crate) struct P256;

fn sem_acaso() -> Error {
    Error::FailedToGetRandomBytes
}

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut bytes = [0u8; 32];
        acaso::preencher(&mut bytes).map_err(|_| sem_acaso())?;
        let secreta = x25519_dalek::StaticSecret::from(bytes);
        bytes.zeroize();
        let publica = x25519_dalek::PublicKey::from(&secreta);
        Ok(Box::new(TrocaX25519 { secreta, publica }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct TrocaX25519 {
    secreta: x25519_dalek::StaticSecret,
    publica: x25519_dalek::PublicKey,
}

impl ActiveKeyExchange for TrocaX25519 {
    fn complete(self: Box<Self>, do_par: &[u8]) -> Result<SharedSecret, Error> {
        let do_par: [u8; 32] = do_par
            .try_into()
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let segredo = self
            .secreta
            .diffie_hellman(&x25519_dalek::PublicKey::from(do_par));
        // Um ponto de ordem pequena dá o segredo todo zero: o par escolheu
        // o segredo. A RFC 8446, 7.4.2, manda abortar.
        if !segredo.was_contributory() {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&segredo.as_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        self.publica.as_bytes()
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl SupportedKxGroup for P256 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        // Um escalar uniforme em [1, n): 32 bytes aleatórios caem fora da
        // faixa com probabilidade de 2^-32, e então se tira outro.
        let mut bytes = [0u8; 32];
        let secreta = loop {
            acaso::preencher(&mut bytes).map_err(|_| sem_acaso())?;
            if let Ok(s) = p256::SecretKey::from_slice(&bytes) {
                break s;
            }
        };
        bytes.zeroize();
        let publica = secreta
            .public_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        Ok(Box::new(TrocaP256 { secreta, publica }))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

struct TrocaP256 {
    secreta: p256::SecretKey,
    publica: Vec<u8>,
}

impl ActiveKeyExchange for TrocaP256 {
    fn complete(self: Box<Self>, do_par: &[u8]) -> Result<SharedSecret, Error> {
        // Só a forma descomprimida, como a RFC 8446 pede: 0x04, x e y.
        if do_par.len() != 65 || do_par[0] != 0x04 {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        // A leitura confere que o ponto está na curva e não é o infinito.
        let publica = p256::PublicKey::from_sec1_bytes(do_par)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let segredo =
            p256::ecdh::diffie_hellman(self.secreta.to_nonzero_scalar(), publica.as_affine());
        Ok(SharedSecret::from(&segredo.raw_secret_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.publica
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use alloc::vec;

    /// As duas pontas da mesma troca chegam ao mesmo segredo.
    #[test]
    fn as_duas_pontas_concordam() {
        acaso::semear([1; 32]);
        for grupo in [&X25519 as &dyn SupportedKxGroup, &P256] {
            let a = grupo.start().unwrap();
            let b = grupo.start().unwrap();
            let (pa, pb) = (a.pub_key().to_vec(), b.pub_key().to_vec());
            let sa = a.complete(&pb).unwrap();
            let sb = b.complete(&pa).unwrap();
            assert_eq!(sa.secret_bytes(), sb.secret_bytes());
            assert_ne!(sa.secret_bytes(), &[0u8; 32][..]);
        }
    }

    /// O ponto de ordem pequena do X25519 dá o segredo zero: o par escolheria
    /// o segredo, e a troca é recusada. E a parte do par com outro tamanho.
    #[test]
    fn x25519_recusa_o_ponto_de_ordem_pequena() {
        acaso::semear([2; 32]);
        assert!(X25519.start().unwrap().complete(&[0u8; 32]).is_err());
        // O ponto de ordem 1 (u = 1) também.
        let mut um = [0u8; 32];
        um[0] = 1;
        assert!(X25519.start().unwrap().complete(&um).is_err());
        assert!(X25519.start().unwrap().complete(&[9u8; 31]).is_err());
    }

    /// Da P-256 só a forma descomprimida, e só um ponto da curva.
    #[test]
    fn p256_recusa_o_comprimido_e_o_fora_da_curva() {
        acaso::semear([3; 32]);
        let publica = P256.start().unwrap().pub_key().to_vec();
        assert_eq!(publica.len(), 65);
        assert!(P256.start().unwrap().complete(&publica).is_ok());

        let mut comprimido = vec![0x02 | (publica[64] & 1)];
        comprimido.extend_from_slice(&publica[1..33]);
        assert!(P256.start().unwrap().complete(&comprimido).is_err());

        let mut fora = publica.clone();
        fora[64] ^= 1;
        assert!(P256.start().unwrap().complete(&fora).is_err());

        let mut prefixo = publica;
        prefixo[0] = 0x06;
        assert!(P256.start().unwrap().complete(&prefixo).is_err());
    }

    /// Duas trocas seguidas não repetem a chave efêmera.
    #[test]
    fn a_chave_efemera_nao_se_repete() {
        acaso::semear([4; 32]);
        for grupo in [&X25519 as &dyn SupportedKxGroup, &P256] {
            let a = grupo.start().unwrap().pub_key().to_vec();
            let b = grupo.start().unwrap().pub_key().to_vec();
            assert_ne!(a, b);
        }
    }
}
