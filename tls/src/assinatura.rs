//! A verificação das assinaturas: a do servidor no `CertificateVerify` e a
//! de cada certificado da cadeia.
//!
//! O `webpki` — o verificador de cadeias do `rustls` — escolhe o algoritmo
//! pelos identificadores do certificado e pede a conta daqui. Um
//! certificado com outro algoritmo não acha conta nenhuma, e a cadeia é
//! recusada: o perfil só aceita o que sabe conferir.
//!
//! | Algoritmo | Na cadeia | No `CertificateVerify` |
//! |---|---|---|
//! | ECDSA P-256 com SHA-256 | sim | `ecdsa_secp256r1_sha256` |
//! | ECDSA P-384 com SHA-384 | sim | `ecdsa_secp384r1_sha384` |
//! | Ed25519 | sim | `ed25519` |
//! | RSA PKCS#1 v1.5 com SHA-256, SHA-384 ou SHA-512 | sim | não: o TLS 1.3 não o aceita no aperto |
//! | RSA-PSS com SHA-256, SHA-384 ou SHA-512, chave `rsaEncryption` | não | `rsa_pss_rsae_sha256`, `_sha384`, `_sha512` |
//!
//! É o que as cadeias das autoridades públicas usam — as raízes e os
//! intermediários da Let's Encrypt e da Google Trust Services, por exemplo,
//! são P-384 ou RSA —, e o que uma folha RSA assina no TLS 1.3. Nada além:
//! nem SHA-1, nem P-521, nem a curva com o hash da outra (P-256 com
//! SHA-384, P-384 com SHA-256), nem o certificado assinado com RSA-PSS —
//! que as regras da CA/Browser Forum permitem e nenhuma dessas cadeias usa.
//!
//! A chave pública também tem perfil: a ECDSA, só o ponto sem compressão,
//! como o *ring* e o `webpki` exigem; a RSA, em DER estrito, de 2048 a 4096
//! bits, múltiplo de 8, com o expoente ímpar de 2^16 + 1 a 2^33 − 1 — ver
//! [`chave_rsa`]. Uma chave fora disso não confere assinatura nenhuma.
//!
//! O RSA aqui só verifica: não há chave privada RSA no Duke, nem cifra RSA,
//! nem geração de chave.

use rsa::traits::PublicKeyParts;
use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};

/// O ponto SEC1 sem compressão — `04`, x e y — de uma curva com
/// coordenadas de `bytes` bytes. O comprimido e o neutro, que o SEC1 também
/// escreve, não vêm num certificado.
fn ponto_sem_compressao(chave: &[u8], bytes: usize) -> Result<&[u8], InvalidSignature> {
    if chave.len() == 1 + 2 * bytes && chave[0] == 0x04 {
        Ok(chave)
    } else {
        Err(InvalidSignature)
    }
}

/// ECDSA sobre a P-256, com o SHA-256: a chave é o ponto SEC1 do
/// certificado, a assinatura vem em DER.
#[derive(Debug)]
struct EcdsaP256Sha256;

impl SignatureVerificationAlgorithm for EcdsaP256Sha256 {
    fn verify_signature(
        &self,
        chave: &[u8],
        mensagem: &[u8],
        assinatura: &[u8],
    ) -> Result<(), InvalidSignature> {
        use p256::ecdsa::signature::Verifier;
        let chave = p256::ecdsa::VerifyingKey::from_sec1_bytes(ponto_sem_compressao(chave, 32)?)
            .map_err(|_| InvalidSignature)?;
        let assinatura =
            p256::ecdsa::Signature::from_der(assinatura).map_err(|_| InvalidSignature)?;
        chave
            .verify(mensagem, &assinatura)
            .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }
}

/// ECDSA sobre a P-384, com o SHA-384 — e só com ele: a regra da CA/Browser
/// Forum para uma chave P-384.
#[derive(Debug)]
struct EcdsaP384Sha384;

impl SignatureVerificationAlgorithm for EcdsaP384Sha384 {
    fn verify_signature(
        &self,
        chave: &[u8],
        mensagem: &[u8],
        assinatura: &[u8],
    ) -> Result<(), InvalidSignature> {
        use p384::ecdsa::signature::Verifier;
        let chave = p384::ecdsa::VerifyingKey::from_sec1_bytes(ponto_sem_compressao(chave, 48)?)
            .map_err(|_| InvalidSignature)?;
        let assinatura =
            p384::ecdsa::Signature::from_der(assinatura).map_err(|_| InvalidSignature)?;
        chave
            .verify(mensagem, &assinatura)
            .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P384
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA384
    }
}

/// Ed25519 (RFC 8032), na verificação estrita: a assinatura com o `S` fora
/// da faixa e a chave de ordem pequena são recusadas.
#[derive(Debug)]
struct Ed25519;

impl SignatureVerificationAlgorithm for Ed25519 {
    fn verify_signature(
        &self,
        chave: &[u8],
        mensagem: &[u8],
        assinatura: &[u8],
    ) -> Result<(), InvalidSignature> {
        let chave: [u8; 32] = chave.try_into().map_err(|_| InvalidSignature)?;
        let chave =
            ed25519_dalek::VerifyingKey::from_bytes(&chave).map_err(|_| InvalidSignature)?;
        let assinatura =
            ed25519_dalek::Signature::from_slice(assinatura).map_err(|_| InvalidSignature)?;
        chave
            .verify_strict(mensagem, &assinatura)
            .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
}

/// O menor módulo RSA do perfil, em bytes: 2048 bits, o piso da CA/Browser
/// Forum.
const MODULO_MINIMO: usize = 256;

/// O maior, em bytes: 4096 bits, o das raízes RSA das autoridades públicas.
const MODULO_MAXIMO: usize = 512;

/// O menor expoente público: 2^16 + 1, o que toda autoridade pública usa e
/// a CA/Browser Forum recomenda.
const EXPOENTE_MINIMO: u64 = (1 << 16) + 1;

/// O maior: 2^33 − 1, o teto do *ring* e do `rsa` — um expoente maior só
/// encarece a verificação.
const EXPOENTE_MAXIMO: u64 = (1 << 33) - 1;

/// A chave pública RSA de um certificado — o `RSAPublicKey` do PKCS#1
/// (RFC 8017, A.1.1) dentro do `subjectPublicKey` —, lida em DER estrito e
/// conferida contra o perfil:
///
/// - nada depois da sequência, e cada inteiro na forma mínima, positivo;
/// - o módulo de 2048 a 4096 bits, e múltiplo de 8 — a regra da CA/Browser
///   Forum —: o primeiro byte com o bit de cima ligado;
/// - o expoente ímpar, de 2^16 + 1 a 2^33 − 1.
///
/// O `rsa` confere o resto: o módulo ímpar, e o expoente menor que ele.
fn chave_rsa(der: &[u8]) -> Result<rsa::RsaPublicKey, InvalidSignature> {
    use der::asn1::UintRef;
    use der::{Reader, SliceReader};
    let mut leitor = SliceReader::new(der).map_err(|_| InvalidSignature)?;
    let (modulo, expoente) = leitor
        .sequence(|r| {
            let modulo: UintRef<'_> = r.decode()?;
            let expoente: UintRef<'_> = r.decode()?;
            Ok::<_, der::Error>((modulo, expoente))
        })
        .map_err(|_| InvalidSignature)?;
    leitor.finish().map_err(|_| InvalidSignature)?;
    let (modulo, expoente) = (modulo.as_bytes(), expoente.as_bytes());

    if !(MODULO_MINIMO..=MODULO_MAXIMO).contains(&modulo.len()) || modulo[0] & 0x80 == 0 {
        return Err(InvalidSignature);
    }
    if expoente.len() > 5 {
        return Err(InvalidSignature);
    }
    let e = expoente.iter().fold(0u64, |e, b| (e << 8) | u64::from(*b));
    if e % 2 == 0 || !(EXPOENTE_MINIMO..=EXPOENTE_MAXIMO).contains(&e) {
        return Err(InvalidSignature);
    }

    let bits = (modulo.len() * 8) as u32;
    let n = rsa::BoxedUint::from_be_slice(modulo, bits).map_err(|_| InvalidSignature)?;
    rsa::RsaPublicKey::new_with_max_size(n, rsa::BoxedUint::from(e), MODULO_MAXIMO * 8)
        .map_err(|_| InvalidSignature)
}

/// O preenchimento de uma assinatura RSA (RFC 8017, 8).
#[derive(Clone, Copy, Debug)]
enum Preenchimento {
    /// `RSASSA-PKCS1-v1_5`: o das cadeias.
    Pkcs1,
    /// `RSASSA-PSS`, com o MGF1 e o sal do tamanho do hash: o do
    /// `CertificateVerify` (RFC 8446, 4.2.3).
    Pss,
}

/// O hash de uma assinatura RSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

/// RSA (RFC 8017) com uma chave `rsaEncryption` — ver [`chave_rsa`].
#[derive(Debug)]
struct Rsa {
    preenchimento: Preenchimento,
    hash: Hash,
}

impl SignatureVerificationAlgorithm for Rsa {
    fn verify_signature(
        &self,
        chave: &[u8],
        mensagem: &[u8],
        assinatura: &[u8],
    ) -> Result<(), InvalidSignature> {
        use rsa::signature::Verifier;
        use sha2::{Sha256, Sha384, Sha512};
        let chave = chave_rsa(chave)?;
        // Do tamanho exato do módulo (RFC 8017, 8.1.2 e 8.2.2, passo 1): o
        // `rsa` aceitaria uma assinatura com o zero da frente cortado.
        if assinatura.len() != chave.size() {
            return Err(InvalidSignature);
        }
        let conferida = match self.preenchimento {
            Preenchimento::Pkcs1 => {
                use rsa::pkcs1v15::{Signature, VerifyingKey};
                let assinatura = Signature::try_from(assinatura).map_err(|_| InvalidSignature)?;
                match self.hash {
                    Hash::Sha256 => {
                        VerifyingKey::<Sha256>::new(chave).verify(mensagem, &assinatura)
                    }
                    Hash::Sha384 => {
                        VerifyingKey::<Sha384>::new(chave).verify(mensagem, &assinatura)
                    }
                    Hash::Sha512 => {
                        VerifyingKey::<Sha512>::new(chave).verify(mensagem, &assinatura)
                    }
                }
            }
            // O `new` do PSS fixa o sal no tamanho do hash.
            Preenchimento::Pss => {
                use rsa::pss::{Signature, VerifyingKey};
                let assinatura = Signature::try_from(assinatura).map_err(|_| InvalidSignature)?;
                match self.hash {
                    Hash::Sha256 => {
                        VerifyingKey::<Sha256>::new(chave).verify(mensagem, &assinatura)
                    }
                    Hash::Sha384 => {
                        VerifyingKey::<Sha384>::new(chave).verify(mensagem, &assinatura)
                    }
                    Hash::Sha512 => {
                        VerifyingKey::<Sha512>::new(chave).verify(mensagem, &assinatura)
                    }
                }
            }
        };
        conferida.map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match (self.preenchimento, self.hash) {
            (Preenchimento::Pkcs1, Hash::Sha256) => alg_id::RSA_PKCS1_SHA256,
            (Preenchimento::Pkcs1, Hash::Sha384) => alg_id::RSA_PKCS1_SHA384,
            (Preenchimento::Pkcs1, Hash::Sha512) => alg_id::RSA_PKCS1_SHA512,
            (Preenchimento::Pss, Hash::Sha256) => alg_id::RSA_PSS_SHA256,
            (Preenchimento::Pss, Hash::Sha384) => alg_id::RSA_PSS_SHA384,
            (Preenchimento::Pss, Hash::Sha512) => alg_id::RSA_PSS_SHA512,
        }
    }
}

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP256Sha256;
static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &EcdsaP384Sha384;
static ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519;
static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &Rsa {
    preenchimento: Preenchimento::Pkcs1,
    hash: Hash::Sha256,
};
static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &Rsa {
    preenchimento: Preenchimento::Pkcs1,
    hash: Hash::Sha384,
};
static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &Rsa {
    preenchimento: Preenchimento::Pkcs1,
    hash: Hash::Sha512,
};
static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &Rsa {
    preenchimento: Preenchimento::Pss,
    hash: Hash::Sha256,
};
static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &Rsa {
    preenchimento: Preenchimento::Pss,
    hash: Hash::Sha384,
};
static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &Rsa {
    preenchimento: Preenchimento::Pss,
    hash: Hash::Sha512,
};

/// Os algoritmos do perfil: os da cadeia (`all`) e, para o
/// `CertificateVerify`, cada esquema do TLS com a sua conta (`mapping`) —
/// é desta lista, na ordem de preferência, que sai a extensão
/// `signature_algorithms` do `ClientHello`. O PKCS#1 v1.5 não está nela: o
/// TLS 1.3 não o aceita no aperto, e o `rustls` o recusaria ali de todo
/// jeito. O PSS não está na cadeia — ver o cabeçalho.
pub(crate) static ALGORITMOS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ECDSA_P256_SHA256,
        ECDSA_P384_SHA384,
        ED25519,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
    ],
    mapping: &[
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256]),
        (SignatureScheme::ECDSA_NISTP384_SHA384, &[ECDSA_P384_SHA384]),
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
    ],
};

#[cfg(test)]
mod testes {
    extern crate std;

    use super::*;
    use alloc::vec::Vec;
    use std::sync::OnceLock;

    /// Uma assinatura Ed25519 de verdade passa: o caso de baixo só vale
    /// se a verificação aceita o que deve.
    #[test]
    fn ed25519_aceita_a_assinatura_valida() {
        use ed25519_dalek::Signer;
        let chave = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let assinatura = chave.sign(b"mensagem do aperto");
        assert!(
            Ed25519
                .verify_signature(
                    chave.verifying_key().as_bytes(),
                    b"mensagem do aperto",
                    &assinatura.to_bytes()
                )
                .is_ok()
        );
        assert!(
            Ed25519
                .verify_signature(
                    chave.verifying_key().as_bytes(),
                    b"outra mensagem",
                    &assinatura.to_bytes()
                )
                .is_err()
        );
    }

    /// A verificação é a estrita: a chave pública de ordem pequena — aqui,
    /// o ponto neutro — com R também neutro e S zero satisfaz a equação de
    /// qualquer mensagem, e a verificação comum a aceita. Uma chave assim
    /// num certificado assinaria tudo.
    #[test]
    fn ed25519_recusa_a_chave_de_ordem_pequena() {
        let mut neutro = [0u8; 32];
        neutro[0] = 1;
        let mut assinatura = [0u8; 64];
        assinatura[..32].copy_from_slice(&neutro);
        for mensagem in [&b"qualquer"[..], b"outra"] {
            assert!(
                Ed25519
                    .verify_signature(&neutro, mensagem, &assinatura)
                    .is_err()
            );
        }
    }

    /// ECDSA: a assinatura de outra mensagem, ou um DER torto, não passa.
    #[test]
    fn ecdsa_recusa_a_outra_mensagem_e_o_der_torto() {
        use p256::ecdsa::signature::Signer;
        let chave = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let assinatura: p256::ecdsa::Signature = chave.sign(b"mensagem do aperto");
        let der = assinatura.to_der();
        let publica = chave.verifying_key().to_sec1_point(false);
        assert!(
            EcdsaP256Sha256
                .verify_signature(publica.as_bytes(), b"mensagem do aperto", der.as_bytes())
                .is_ok()
        );
        assert!(
            EcdsaP256Sha256
                .verify_signature(publica.as_bytes(), b"outra mensagem", der.as_bytes())
                .is_err()
        );
        let mut torto = der.as_bytes().to_vec();
        torto[0] ^= 0xff;
        assert!(
            EcdsaP256Sha256
                .verify_signature(publica.as_bytes(), b"mensagem do aperto", &torto)
                .is_err()
        );
    }

    /// P-384 com SHA-384: a assinatura certa passa; a de outra mensagem, o
    /// DER torto e a assinatura com o hash da P-256 — o SHA-256 —, não.
    #[test]
    fn p384_confere_e_recusa_a_outra_mensagem_e_o_outro_hash() {
        use p384::ecdsa::signature::Signer;
        use p384::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::Digest;
        let chave = p384::ecdsa::SigningKey::from_slice(&[11u8; 48]).unwrap();
        let publica = chave.verifying_key().to_sec1_point(false);
        let assinatura: p384::ecdsa::Signature = chave.sign(b"mensagem do aperto");
        let der = assinatura.to_der();
        assert!(
            EcdsaP384Sha384
                .verify_signature(publica.as_bytes(), b"mensagem do aperto", der.as_bytes())
                .is_ok()
        );
        assert!(
            EcdsaP384Sha384
                .verify_signature(publica.as_bytes(), b"outra mensagem", der.as_bytes())
                .is_err()
        );
        let mut torto = der.as_bytes().to_vec();
        torto[1] ^= 0x01;
        assert!(
            EcdsaP384Sha384
                .verify_signature(publica.as_bytes(), b"mensagem do aperto", &torto)
                .is_err()
        );
        // A mesma chave assinando o SHA-256 da mensagem: a P-384 com o
        // hash da outra curva, fora do perfil.
        let resumo = sha2::Sha256::digest(b"mensagem do aperto");
        let cruzada: p384::ecdsa::Signature = chave.sign_prehash(&resumo).unwrap();
        assert!(
            EcdsaP384Sha384
                .verify_signature(
                    publica.as_bytes(),
                    b"mensagem do aperto",
                    cruzada.to_der().as_bytes()
                )
                .is_err()
        );
        // E a chave de uma curva na conta da outra.
        let p256 = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let publica_p256 = p256.verifying_key().to_sec1_point(false);
        assert!(
            EcdsaP384Sha384
                .verify_signature(
                    publica_p256.as_bytes(),
                    b"mensagem do aperto",
                    der.as_bytes()
                )
                .is_err()
        );
        assert!(
            EcdsaP256Sha256
                .verify_signature(publica.as_bytes(), b"mensagem do aperto", der.as_bytes())
                .is_err()
        );
    }

    /// A chave ECDSA só sem compressão: o mesmo ponto comprimido — que o
    /// SEC1 escreve e o `p256` e o `p384` leriam — é recusado, como o
    /// ponto que não está na curva.
    #[test]
    fn ecdsa_recusa_o_ponto_comprimido_e_o_fora_da_curva() {
        use p256::ecdsa::signature::Signer as _;
        let chave = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
        let assinatura: p256::ecdsa::Signature = chave.sign(b"m");
        let comprimido = chave.verifying_key().to_sec1_point(true);
        assert!(
            EcdsaP256Sha256
                .verify_signature(comprimido.as_bytes(), b"m", assinatura.to_der().as_bytes())
                .is_err()
        );
        let chave = p384::ecdsa::SigningKey::from_slice(&[11u8; 48]).unwrap();
        let assinatura: p384::ecdsa::Signature = p384::ecdsa::signature::Signer::sign(&chave, b"m");
        let comprimido = chave.verifying_key().to_sec1_point(true);
        assert!(
            EcdsaP384Sha384
                .verify_signature(comprimido.as_bytes(), b"m", assinatura.to_der().as_bytes())
                .is_err()
        );
        let mut fora = chave
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let ultimo = fora.len() - 1;
        fora[ultimo] ^= 0x01;
        assert!(
            EcdsaP384Sha384
                .verify_signature(&fora, b"m", assinatura.to_der().as_bytes())
                .is_err()
        );
    }

    // -----------------------------------------------------------------------
    // RSA
    // -----------------------------------------------------------------------

    /// Um ChaCha20 de semente fixa: as chaves dos testes são as mesmas a
    /// cada rodada.
    fn gerador(semente: u8) -> chacha20::ChaCha20Rng {
        use chacha20::rand_core::SeedableRng;
        chacha20::ChaCha20Rng::from_seed([semente; 32])
    }

    /// A chave RSA de 2048 bits dos testes, gerada uma vez.
    fn chave_de_teste() -> &'static rsa::RsaPrivateKey {
        static CHAVE: OnceLock<rsa::RsaPrivateKey> = OnceLock::new();
        CHAVE.get_or_init(|| rsa::RsaPrivateKey::new(&mut gerador(1), 2048).unwrap())
    }

    /// O tamanho em DER, na forma mínima.
    fn tamanho(n: usize) -> Vec<u8> {
        match n {
            0..=0x7f => alloc::vec![n as u8],
            0x80..=0xff => alloc::vec![0x81, n as u8],
            _ => alloc::vec![0x82, (n >> 8) as u8, n as u8],
        }
    }

    /// Um elemento do DER: a etiqueta, o tamanho e o conteúdo como veio.
    fn elemento(etiqueta: u8, conteudo: &[u8]) -> Vec<u8> {
        let mut der = alloc::vec![etiqueta];
        der.extend(tamanho(conteudo.len()));
        der.extend_from_slice(conteudo);
        der
    }

    /// Um `INTEGER` positivo, na forma mínima: o zero da frente só quando o
    /// primeiro byte tem o bit de cima ligado.
    fn inteiro(v: &[u8]) -> Vec<u8> {
        let mut conteudo = Vec::new();
        if v.first().is_some_and(|b| b & 0x80 != 0) {
            conteudo.push(0);
        }
        conteudo.extend_from_slice(v);
        elemento(0x02, &conteudo)
    }

    fn sequencia(elementos: &[Vec<u8>]) -> Vec<u8> {
        elemento(0x30, &elementos.concat())
    }

    /// O `RSAPublicKey` em DER, de um módulo e de um expoente em big-endian.
    fn der_rsa(modulo: &[u8], expoente: &[u8]) -> Vec<u8> {
        sequencia(&[inteiro(modulo), inteiro(expoente)])
    }

    fn publica_de(chave: &rsa::RsaPrivateKey) -> Vec<u8> {
        der_rsa(
            &chave.n().to_be_bytes(),
            &chave.e().to_be_bytes_trimmed_vartime(),
        )
    }

    fn assinar_pkcs1(chave: &rsa::RsaPrivateKey, hash: Hash, mensagem: &[u8]) -> Vec<u8> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        let chave = chave.clone();
        match hash {
            Hash::Sha256 => SigningKey::<sha2::Sha256>::new(chave)
                .sign(mensagem)
                .to_vec(),
            Hash::Sha384 => SigningKey::<sha2::Sha384>::new(chave)
                .sign(mensagem)
                .to_vec(),
            Hash::Sha512 => SigningKey::<sha2::Sha512>::new(chave)
                .sign(mensagem)
                .to_vec(),
        }
    }

    fn assinar_pss(
        chave: &rsa::RsaPrivateKey,
        hash: Hash,
        sal: Option<usize>,
        m: &[u8],
    ) -> Vec<u8> {
        use rsa::pss::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        let chave = chave.clone();
        let mut g = gerador(2);
        macro_rules! com {
            ($h:ty) => {
                match sal {
                    None => SigningKey::<$h>::new(chave)
                        .sign_with_rng(&mut g, m)
                        .to_vec(),
                    Some(s) => SigningKey::<$h>::new_with_salt_len(chave, s)
                        .sign_with_rng(&mut g, m)
                        .to_vec(),
                }
            };
        }
        match hash {
            Hash::Sha256 => com!(sha2::Sha256),
            Hash::Sha384 => com!(sha2::Sha384),
            Hash::Sha512 => com!(sha2::Sha512),
        }
    }

    const HASHES: [Hash; 3] = [Hash::Sha256, Hash::Sha384, Hash::Sha512];

    /// Cada RSA do perfil confere a assinatura certa, e recusa a de outra
    /// mensagem, a de outro hash e a do outro preenchimento.
    #[test]
    fn rsa_confere_cada_hash_e_cada_preenchimento() {
        let chave = chave_de_teste();
        let publica = publica_de(chave);
        let m = b"mensagem do aperto";
        for hash in HASHES {
            let pkcs1 = Rsa {
                preenchimento: Preenchimento::Pkcs1,
                hash,
            };
            let pss = Rsa {
                preenchimento: Preenchimento::Pss,
                hash,
            };
            let a_pkcs1 = assinar_pkcs1(chave, hash, m);
            let a_pss = assinar_pss(chave, hash, None, m);
            assert!(
                pkcs1.verify_signature(&publica, m, &a_pkcs1).is_ok(),
                "{hash:?}"
            );
            assert!(
                pss.verify_signature(&publica, m, &a_pss).is_ok(),
                "{hash:?}"
            );
            assert!(
                pkcs1
                    .verify_signature(&publica, b"outra", &a_pkcs1)
                    .is_err()
            );
            assert!(pss.verify_signature(&publica, b"outra", &a_pss).is_err());
            // O preenchimento trocado.
            assert!(pkcs1.verify_signature(&publica, m, &a_pss).is_err());
            assert!(pss.verify_signature(&publica, m, &a_pkcs1).is_err());
            // O hash trocado.
            for outro in HASHES.into_iter().filter(|h| *h != hash) {
                let errado = Rsa {
                    preenchimento: Preenchimento::Pkcs1,
                    hash: outro,
                };
                assert!(errado.verify_signature(&publica, m, &a_pkcs1).is_err());
                let errado = Rsa {
                    preenchimento: Preenchimento::Pss,
                    hash: outro,
                };
                assert!(errado.verify_signature(&publica, m, &a_pss).is_err());
            }
        }
    }

    /// A assinatura RSA tem o tamanho exato do módulo: sem o zero da frente
    /// — quando ela começa por zero — ou com um a mais, é recusada, ainda
    /// que o número seja o mesmo. E um bit trocado também.
    #[test]
    fn rsa_recusa_a_assinatura_de_outro_tamanho_ou_trocada() {
        let chave = chave_de_teste();
        let publica = publica_de(chave);
        let pkcs1 = Rsa {
            preenchimento: Preenchimento::Pkcs1,
            hash: Hash::Sha256,
        };
        // Uma mensagem cuja assinatura começa por zero — uma em 256.
        let (m, assinatura) = (0u32..)
            .map(|i| {
                let m = i.to_be_bytes();
                (m, assinar_pkcs1(chave, Hash::Sha256, &m))
            })
            .find(|(_, a)| a[0] == 0)
            .unwrap();
        assert!(pkcs1.verify_signature(&publica, &m, &assinatura).is_ok());
        assert!(
            pkcs1
                .verify_signature(&publica, &m, &assinatura[1..])
                .is_err()
        );
        let mut com_zero = alloc::vec![0u8];
        com_zero.extend_from_slice(&assinatura);
        assert!(pkcs1.verify_signature(&publica, &m, &com_zero).is_err());
        let mut trocada = assinatura.clone();
        trocada[100] ^= 0x04;
        assert!(pkcs1.verify_signature(&publica, &m, &trocada).is_err());
        // E o número maior que o módulo, no tamanho certo.
        assert!(pkcs1.verify_signature(&publica, &m, &[0xff; 256]).is_err());
    }

    /// O PSS do TLS 1.3 tem o sal do tamanho do hash (RFC 8446, 4.2.3): uma
    /// assinatura PSS válida com outro sal é recusada.
    #[test]
    fn pss_recusa_o_sal_de_outro_tamanho() {
        let chave = chave_de_teste();
        let publica = publica_de(chave);
        let m = b"mensagem do aperto";
        for (hash, bytes) in [(Hash::Sha256, 32), (Hash::Sha384, 48), (Hash::Sha512, 64)] {
            let pss = Rsa {
                preenchimento: Preenchimento::Pss,
                hash,
            };
            let certo = assinar_pss(chave, hash, Some(bytes), m);
            assert!(pss.verify_signature(&publica, m, &certo).is_ok());
            for sal in [0, 20, bytes - 1, bytes + 1] {
                let outro = assinar_pss(chave, hash, Some(sal), m);
                assert!(
                    pss.verify_signature(&publica, m, &outro).is_err(),
                    "{hash:?} {sal}"
                );
            }
        }
    }

    /// A chave RSA fora do perfil não confere nada, mesmo com a assinatura
    /// certa para ela: 1024 bits, e o expoente 3.
    #[test]
    fn rsa_recusa_a_chave_curta_e_o_expoente_pequeno() {
        let m = b"mensagem do aperto";
        let curta = rsa::RsaPrivateKey::new(&mut gerador(3), 1024).unwrap();
        let tres = rsa::RsaPrivateKey::new_with_exp(&mut gerador(4), 2048, 3u64.into()).unwrap();
        for chave in [&curta, &tres] {
            let assinatura = assinar_pkcs1(chave, Hash::Sha256, m);
            // A assinatura vale para o `rsa` sem o perfil.
            let sem_perfil =
                rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(rsa::RsaPublicKey::from(chave));
            assert!(
                rsa::signature::Verifier::verify(
                    &sem_perfil,
                    m,
                    &rsa::pkcs1v15::Signature::try_from(&assinatura[..]).unwrap()
                )
                .is_ok()
            );
            assert!(
                RSA_PKCS1_SHA256
                    .verify_signature(&publica_de(chave), m, &assinatura)
                    .is_err()
            );
        }
    }

    /// A leitura da chave RSA: o DER estrito, os tamanhos e o expoente.
    #[test]
    fn a_chave_rsa_so_se_le_no_perfil() {
        let n = chave_de_teste().n().to_be_bytes();
        let e = [0x01, 0x00, 0x01];
        assert!(chave_rsa(&der_rsa(&n, &e)).is_ok());

        // O DER torto.
        let certa = der_rsa(&n, &e);
        let mut sobra = certa.clone();
        sobra.push(0);
        assert!(chave_rsa(&sobra).is_err(), "algo depois da sequencia");
        assert!(chave_rsa(&certa[..certa.len() - 1]).is_err(), "cortada");
        assert_eq!(certa[1], 0x82);
        let mut longo = alloc::vec![0x30, 0x83, 0x00];
        longo.extend_from_slice(&certa[2..]);
        assert!(chave_rsa(&longo).is_err(), "tamanho fora da forma minima");
        let zero_a_mais = [&[0x00, 0x00][..], &n].concat();
        assert!(
            chave_rsa(&sequencia(&[elemento(0x02, &zero_a_mais), inteiro(&e)])).is_err(),
            "zero a mais na frente do modulo"
        );
        assert!(
            chave_rsa(&sequencia(&[inteiro(&n), elemento(0x02, &[0, 1, 0, 1])])).is_err(),
            "zero a mais na frente do expoente"
        );
        // Sem o zero da frente, o bit de cima do módulo é o do sinal.
        assert!(
            chave_rsa(&sequencia(&[elemento(0x02, &n), inteiro(&e)])).is_err(),
            "modulo negativo"
        );
        assert!(
            chave_rsa(&sequencia(&[inteiro(&n), elemento(0x02, &[])])).is_err(),
            "expoente vazio"
        );
        assert!(
            chave_rsa(&sequencia(&[inteiro(&n)])).is_err(),
            "sem o expoente"
        );
        assert!(
            chave_rsa(&sequencia(&[inteiro(&n), inteiro(&e), inteiro(&[1])])).is_err(),
            "um inteiro a mais"
        );
        assert!(
            chave_rsa(&[inteiro(&n), inteiro(&e)].concat()).is_err(),
            "sem a sequencia"
        );
        // A `SubjectPublicKeyInfo` inteira no lugar da chave.
        let rsa_encryption = sequencia(&[
            elemento(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
            ),
            elemento(0x05, &[]),
        ]);
        let bits = elemento(0x03, &[&[0x00][..], &certa].concat());
        assert!(
            chave_rsa(&sequencia(&[rsa_encryption, bits])).is_err(),
            "a SubjectPublicKeyInfo"
        );

        // Os tamanhos: 2040 bits, 2047, e o módulo par.
        assert!(chave_rsa(&der_rsa(&n[1..], &e)).is_err(), "2040 bits");
        let mut curto = n.clone();
        curto[0] &= 0x7f;
        assert!(chave_rsa(&der_rsa(&curto, &e)).is_err(), "2047 bits");
        let mut par = n.clone();
        let ultimo = par.len() - 1;
        par[ultimo] &= 0xfe;
        assert!(chave_rsa(&der_rsa(&par, &e)).is_err(), "modulo par");
        // 4096 bits valem; 4104, não.
        let mut grande = alloc::vec![0xffu8; 512];
        assert!(chave_rsa(&der_rsa(&grande, &e)).is_ok(), "4096 bits");
        grande.push(0xff);
        assert!(chave_rsa(&der_rsa(&grande, &e)).is_err(), "4104 bits");

        // O expoente.
        for (expoente, vale) in [
            (&[0x01][..], false),
            (&[0x03][..], false),
            (&[0x01, 0x00, 0x00][..], false),
            (&[0x00, 0xff, 0xff][..], false),
            (&[0x01, 0x00, 0x01][..], true),
            (&[0x01, 0x00, 0x02][..], false),
            (&[0x01, 0xff, 0xff, 0xff, 0xff][..], true),
            (&[0x02, 0x00, 0x00, 0x00, 0x01][..], false),
            (&[0x01, 0x00, 0x00, 0x00, 0x00, 0x01][..], false),
        ] {
            assert_eq!(
                chave_rsa(&der_rsa(&n, expoente)).is_ok(),
                vale,
                "expoente {expoente:02x?}"
            );
        }
    }

    /// A lista do perfil: exatamente estes pares de chave e assinatura na
    /// cadeia, e estes esquemas no aperto — um algoritmo a mais aqui é uma
    /// decisão, e não um acidente.
    #[test]
    fn a_lista_do_perfil_e_exatamente_esta() {
        let cadeia: Vec<_> = ALGORITMOS
            .all
            .iter()
            .map(|a| (a.public_key_alg_id(), a.signature_alg_id()))
            .collect();
        assert_eq!(
            cadeia,
            [
                (alg_id::ECDSA_P256, alg_id::ECDSA_SHA256),
                (alg_id::ECDSA_P384, alg_id::ECDSA_SHA384),
                (alg_id::ED25519, alg_id::ED25519),
                (alg_id::RSA_ENCRYPTION, alg_id::RSA_PKCS1_SHA256),
                (alg_id::RSA_ENCRYPTION, alg_id::RSA_PKCS1_SHA384),
                (alg_id::RSA_ENCRYPTION, alg_id::RSA_PKCS1_SHA512),
            ]
        );
        let aperto: Vec<_> = ALGORITMOS
            .mapping
            .iter()
            .map(|(esquema, contas)| {
                assert_eq!(contas.len(), 1);
                (
                    *esquema,
                    contas[0].public_key_alg_id(),
                    contas[0].signature_alg_id(),
                )
            })
            .collect();
        assert_eq!(
            aperto,
            [
                (
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    alg_id::ECDSA_P256,
                    alg_id::ECDSA_SHA256
                ),
                (
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    alg_id::ECDSA_P384,
                    alg_id::ECDSA_SHA384
                ),
                (SignatureScheme::ED25519, alg_id::ED25519, alg_id::ED25519),
                (
                    SignatureScheme::RSA_PSS_SHA256,
                    alg_id::RSA_ENCRYPTION,
                    alg_id::RSA_PSS_SHA256
                ),
                (
                    SignatureScheme::RSA_PSS_SHA384,
                    alg_id::RSA_ENCRYPTION,
                    alg_id::RSA_PSS_SHA384
                ),
                (
                    SignatureScheme::RSA_PSS_SHA512,
                    alg_id::RSA_ENCRYPTION,
                    alg_id::RSA_PSS_SHA512
                ),
            ]
        );
    }
}
