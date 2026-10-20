//! A assinatura Ed25519 de um nó, pela regra ZIP215.
//!
//! O nó que avaliou uma consulta assina a resposta com a chave Ed25519
//! dele (**especificação**, *Request: Query call*). O `ic-agent` confere
//! com o `ic-ed25519`, que segue a ZIP215: a verificação cofatorada
//! `[8](R' - R) = 0`, com `R' = [s]B - [k]A`, `k = SHA-512(R ‖ A ‖ M)`; o
//! `s` tem de ser canônico (menor que a ordem do grupo), e `R` e `A` são
//! aceitos mesmo em codificação não canônica ou de ordem pequena. São as
//! mesmas vinte linhas daqui, sobre o `curve25519-dalek` 5 que o projeto
//! já usa, conferidas contra o `ic-ed25519` nos casos de borda.
//!
//! A regra é a do lado de lá, e não uma mais estrita, de propósito: uma
//! assinatura que o IC considera válida não pode ser recusada aqui, e uma
//! que ele recusa não pode passar.

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};

/// O tamanho de uma assinatura.
pub const TAMANHO: usize = 64;

/// Se `assinatura` é uma assinatura de `mensagem` pela chave crua `chave`
/// (32 bytes), pela ZIP215.
pub fn verificar(chave: &[u8; 32], mensagem: &[u8], assinatura: &[u8]) -> bool {
    let Ok(assinatura) = <&[u8; TAMANHO]>::try_from(assinatura) else {
        return false;
    };
    let Some(a) = CompressedEdwardsY(*chave).decompress() else {
        return false;
    };
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&assinatura[..32]);
    let Some(r) = CompressedEdwardsY(r_bytes).decompress() else {
        return false;
    };
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&assinatura[32..]);
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };
    // O desafio sobre os bytes como vieram: a ZIP215 usa a codificação
    // original de R e de A, mesmo não canônica.
    let mut h = Sha512::new();
    h.update(r_bytes);
    h.update(chave);
    h.update(mensagem);
    let k = Scalar::from_hash(h);
    let r_linha = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &-a, &s);
    (r_linha - r).mul_by_cofactor().is_identity()
}

#[cfg(test)]
mod testes;
