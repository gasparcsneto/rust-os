//! O provedor de criptografia do `rustls`: cada peça sobre a primitiva do
//! RustCrypto ou do dalek, e nenhuma outra.
//!
//! | Peça | Daqui |
//! |---|---|
//! | suítes | `TLS13_AES_128_GCM_SHA256`, `TLS13_AES_256_GCM_SHA384`, `TLS13_CHACHA20_POLY1305_SHA256` |
//! | troca de chaves | X25519, `secp256r1` |
//! | assinaturas | `ecdsa_secp256r1_sha256`, `ed25519` |
//! | aleatório | o gerador semeado por quem conecta |
//! | chaves privadas | nenhuma: o cliente não se autentica por certificado |
//!
//! A forma segue a do exemplo de provedor do `rustls`
//! (`provider-example/src/lib.rs`) — ver `THIRD_PARTY.md`. O que muda: só
//! TLS 1.3, o acaso semeado por quem conecta em vez do sistema operacional,
//! P-256 ao lado do X25519, e a verificação de assinatura própria.

use alloc::sync::Arc;
use alloc::vec;

use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{CipherSuiteCommon, CryptoProvider, KeyProvider};
use rustls::pki_types::{PrivateKeyDer, UnixTime};
use rustls::sign::SigningKey;
use rustls::time_provider::TimeProvider;
use rustls::{CipherSuite, Error, SupportedCipherSuite, Tls13CipherSuite};

use crate::{acaso, assinatura, cifra, resumo, troca};

/// `TLS_AES_128_GCM_SHA256` — a que todo TLS 1.3 tem (RFC 8446, 9.1).
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
            hash_provider: &resumo::SHA256,
            // O limite do GCM por chave, antes da troca de chave — ver o
            // rascunho dos limites de AEAD da IRTF, 5.1.1.
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &HkdfUsingHmac(&resumo::HMAC_SHA256),
        aead_alg: &cifra::AES_128_GCM,
        quic: None,
    });

/// `TLS_AES_256_GCM_SHA384`.
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &resumo::SHA384,
            confidentiality_limit: 1 << 24,
        },
        hkdf_provider: &HkdfUsingHmac(&resumo::HMAC_SHA384),
        aead_alg: &cifra::AES_256_GCM,
        quic: None,
    });

/// `TLS_CHACHA20_POLY1305_SHA256`.
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &resumo::SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HkdfUsingHmac(&resumo::HMAC_SHA256),
        aead_alg: &cifra::CHACHA20_POLY1305,
        quic: None,
    });

/// O provedor do perfil. As suítes na ordem de preferência do cliente — o
/// servidor do TLS 1.3 costuma escolher pela dele.
pub fn provedor() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: vec![
            TLS13_AES_128_GCM_SHA256,
            TLS13_CHACHA20_POLY1305_SHA256,
            TLS13_AES_256_GCM_SHA384,
        ],
        kx_groups: vec![&troca::X25519, &troca::P256],
        signature_verification_algorithms: assinatura::ALGORITMOS,
        secure_random: &acaso::Acaso,
        key_provider: &SemChaves,
    }
}

/// O cliente não carrega chave privada nenhuma: não há certificado de
/// cliente no perfil.
#[derive(Debug)]
struct SemChaves;

impl KeyProvider for SemChaves {
    fn load_private_key(
        &self,
        _chave: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General(alloc::string::String::from(
            "o cliente TLS do Duke nao usa chave privada",
        )))
    }
}

/// O relógio de uma conexão: o instante que quem conectou deu, fixo
/// durante o aperto — ver [`crate::Sessao::conectar`]. Zero é "não se
/// sabe", e o `rustls` recusa o aperto em vez de conferir validade sem
/// relógio.
#[derive(Debug)]
pub(crate) struct Relogio(pub(crate) u64);

impl TimeProvider for Relogio {
    fn current_time(&self) -> Option<UnixTime> {
        (self.0 > 0).then(|| UnixTime::since_unix_epoch(core::time::Duration::from_secs(self.0)))
    }
}
