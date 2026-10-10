//! A verificação das assinaturas: a do servidor no `CertificateVerify` e a
//! de cada certificado da cadeia. ECDSA P-256 com SHA-256, do RustCrypto, e
//! Ed25519, do dalek.
//!
//! O `webpki` — o verificador de cadeias do `rustls` — escolhe o algoritmo
//! pelos identificadores do certificado e pede a conta daqui. Um
//! certificado com outro algoritmo (RSA, P-384) não acha conta nenhuma, e a
//! cadeia é recusada: o perfil só aceita o que sabe conferir.

use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};

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
        let chave =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(chave).map_err(|_| InvalidSignature)?;
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

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP256Sha256;
static ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519;

/// Os algoritmos do perfil: os da cadeia (`all`) e, para o
/// `CertificateVerify`, cada esquema do TLS com a sua conta (`mapping`) —
/// é desta lista que sai a extensão `signature_algorithms` do
/// `ClientHello`.
pub(crate) static ALGORITMOS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[ECDSA_P256_SHA256, ED25519],
    mapping: &[
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256]),
        (SignatureScheme::ED25519, &[ED25519]),
    ],
};

#[cfg(test)]
mod testes {
    use super::*;

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
}
