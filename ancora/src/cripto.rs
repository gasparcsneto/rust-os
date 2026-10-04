//! As primitivas da sessão autenticada, como a especificação do TPM 2.0 as
//! compõe — parte 1, capítulo 11 (as funções de derivação) e capítulo 19
//! (as sessões).
//!
//! As primitivas mesmas — SHA-256, HMAC, AES, P-256 — são do RustCrypto.
//! O que este módulo escreve é a composição que o TPM fixa: o `KDFa` que
//! deriva a chave da sessão e a da cifra de parâmetro, o `KDFe` que tira o
//! sal do segredo do ECDH, e a forma exata do ponto que vai ao TPM. Errar
//! qualquer byte disso não dá erro aqui: dá um TPM que recusa o HMAC — e
//! por isso tudo daqui é conferido contra o `swtpm`.

use aes::Aes128;
use cfb_mode::cipher::KeyIvInit;
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::{AffinePoint, NonZeroScalar, PublicKey, Sec1Point};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{Erro, Sorteio};

/// O tamanho de um resumo, de uma chave de sessão e de um nonce: 32 bytes.
pub const TAM: usize = 32;

/// SHA-256 da concatenação das partes.
pub fn resumo(partes: &[&[u8]]) -> [u8; TAM] {
    let mut h = Sha256::new();
    for p in partes {
        h.update(p);
    }
    h.finalize().into()
}

/// HMAC-SHA256 da concatenação das partes.
pub fn hmac(chave: &[u8], partes: &[&[u8]]) -> [u8; TAM] {
    // O HMAC aceita chave de qualquer tamanho; o erro não acontece.
    let mut m =
        <Hmac<Sha256> as KeyInit>::new_from_slice(chave).expect("HMAC aceita qualquer chave");
    for p in partes {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// `KDFa` (parte 1, 11.4.10.2), em modo contador com HMAC-SHA256: enche
/// `saida` com `HMAC(chave, i ‖ rótulo ‖ 0 ‖ contextoU ‖ contextoV ‖ bits)`
/// para i = 1, 2, … — o rótulo levando o zero que o termina.
pub fn kdfa(chave: &[u8], rotulo: &[u8], u: &[u8], v: &[u8], saida: &mut [u8]) {
    let bits = ((saida.len() * 8) as u32).to_be_bytes();
    let mut feito = 0;
    let mut i = 1u32;
    while feito < saida.len() {
        let mut bloco = hmac(chave, &[&i.to_be_bytes(), rotulo, &[0], u, v, &bits]);
        let n = (saida.len() - feito).min(TAM);
        saida[feito..feito + n].copy_from_slice(&bloco[..n]);
        bloco.zeroize();
        feito += n;
        i += 1;
    }
}

/// `KDFe` (parte 1, 11.4.10.3), de 256 bits: um bloco de SHA-256 sobre
/// `1 ‖ Z ‖ uso ‖ 0 ‖ U ‖ V`.
pub fn kdfe(z: &[u8], uso: &[u8], u: &[u8], v: &[u8]) -> [u8; TAM] {
    resumo(&[&1u32.to_be_bytes(), z, uso, &[0], u, v])
}

/// A chave de uma sessão (parte 1, 19.6.8): `KDFa(sal, "ATH", nonceTPM,
/// nonceCaller)`. Sem vínculo, a chave do `KDFa` é só o sal.
pub fn chave_da_sessao(sal: &[u8; TAM], nonce_tpm: &[u8], nonce_caller: &[u8]) -> [u8; TAM] {
    let mut k = [0; TAM];
    kdfa(sal, b"ATH", nonce_tpm, nonce_caller, &mut k);
    k
}

/// A senha de uma entidade como entra numa chave de HMAC: sem os zeros do
/// fim (parte 1, 19.6.5) — o TPM os tira, e quem não tirar erra o HMAC uma
/// vez em 256.
pub fn sem_zeros_no_fim(senha: &[u8]) -> &[u8] {
    let fim = senha.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &senha[..fim]
}

/// A chave do HMAC de um comando ou resposta: a da sessão seguida da senha
/// da entidade autorizada. Num buffer fixo, apagado por quem usa.
pub struct ChaveDeHmac {
    bytes: [u8; 2 * TAM],
    tam: usize,
}

impl ChaveDeHmac {
    pub fn nova(sessao: &[u8; TAM], senha: &[u8]) -> ChaveDeHmac {
        let senha = sem_zeros_no_fim(senha);
        let mut bytes = [0; 2 * TAM];
        let n = senha.len().min(TAM);
        bytes[..TAM].copy_from_slice(sessao);
        bytes[TAM..TAM + n].copy_from_slice(&senha[..n]);
        ChaveDeHmac {
            bytes,
            tam: TAM + n,
        }
    }

    pub fn como_bytes(&self) -> &[u8] {
        &self.bytes[..self.tam]
    }
}

impl Drop for ChaveDeHmac {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Cifra (ou decifra, com `decifrar`) em AES-128-CFB o primeiro parâmetro
/// de um comando ou resposta (parte 1, 21.4): chave e vetor do
/// `KDFa(chave do HMAC, "CFB", nonce mais novo, nonce mais velho)`.
///
/// Só confidencialidade: quem chama autentica o texto cifrado. O único
/// chamador, a sessão, cifra antes de calcular o `cpHash` que o HMAC
/// cobre.
pub fn cfb(chave: &ChaveDeHmac, novo: &[u8], velho: &[u8], dados: &mut [u8], decifrar: bool) {
    let mut material = [0u8; 32];
    kdfa(chave.como_bytes(), b"CFB", novo, velho, &mut material);
    let (k, iv) = material.split_at(16);
    // Dezesseis bytes cada um, do `split_at` acima: o erro não acontece.
    if decifrar {
        cfb_mode::Decryptor::<Aes128>::new_from_slices(k, iv)
            .expect("16 bytes")
            .decrypt(dados);
    } else {
        cfb_mode::Encryptor::<Aes128>::new_from_slices(k, iv)
            .expect("16 bytes")
            .encrypt(dados);
    }
    material.zeroize();
}

/// O sal de uma sessão e o ponto efêmero que vai ao TPM.
pub struct Sal {
    pub sal: [u8; TAM],
    pub x: [u8; TAM],
    pub y: [u8; TAM],
}

impl Drop for Sal {
    fn drop(&mut self) {
        self.sal.zeroize();
    }
}

/// O sal de uma sessão, cifrado para uma chave ECC P-256 do TPM (parte 1,
/// 11.4.10.3 e C.6.1): um par efêmero, o segredo `Z` do ECDH com o ponto
/// do TPM, e `KDFe(Z, "SECRET", x efêmero, x do TPM)`. Devolve o sal e o
/// ponto efêmero que vai ao TPM — com ele, e só com a chave privada que
/// mora no TPM, o TPM chega ao mesmo sal.
pub fn salgar(x: &[u8; TAM], y: &[u8; TAM], sorteio: &mut dyn Sorteio) -> Result<Sal, Erro> {
    let tpm = ponto(x, y)?;
    let efemero = loop {
        let mut bytes = [0u8; TAM];
        sorteio.sortear(&mut bytes)?;
        // Um escalar fora do grupo, ou zero: sorteia de novo. Acontece com
        // probabilidade desprezível, mas não pode virar erro.
        let e = NonZeroScalar::try_from(&bytes[..]);
        bytes.zeroize();
        if let Ok(e) = e {
            break e;
        }
    };
    let publico = PublicKey::from_secret_scalar(&efemero).to_sec1_point(false);
    let (ex, ey) = (
        publico.x().ok_or(Erro::Transporte("ponto efemero sem x"))?,
        publico.y().ok_or(Erro::Transporte("ponto efemero sem y"))?,
    );
    let segredo = p256::ecdh::diffie_hellman(efemero, tpm);
    let mut sal = Sal {
        sal: kdfe(segredo.raw_secret_bytes(), b"SECRET", ex, x),
        x: [0; TAM],
        y: [0; TAM],
    };
    sal.x.copy_from_slice(ex);
    sal.y.copy_from_slice(ey);
    Ok(sal)
}

/// O ponto `(x, y)`, se for um ponto de P-256. Um ponto fora da curva é a
/// resposta de quem não é o TPM — ou de um TPM que não entendeu o pedido.
pub fn ponto(x: &[u8; TAM], y: &[u8; TAM]) -> Result<AffinePoint, Erro> {
    let codificado = Sec1Point::from_affine_coordinates(x.into(), y.into(), false);
    Option::from(AffinePoint::from_sec1_point(&codificado)).ok_or(Erro::RespostaMalformada(
        "a chave do TPM nao e um ponto de P-256",
    ))
}

/// Compara sem que o tempo diga quantos bytes acertaram.
pub fn iguais(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

#[cfg(test)]
mod testes {
    use super::*;

    /// O `KDFa` contra o vetor da especificação de teste do TCG não existe
    /// publicado; o que se confere aqui é a forma — o rótulo terminado em
    /// zero, os bits no fim, a continuação por contador — contra a mesma
    /// conta escrita à mão. O que diz se está certo de verdade é o `swtpm`.
    #[test]
    fn o_kdfa_e_hmac_em_modo_contador() {
        let mut saida = [0u8; 48];
        kdfa(b"chave", b"ATH", b"u", b"v", &mut saida);
        let a = hmac(
            b"chave",
            &[&[0, 0, 0, 1], b"ATH\0", b"u", b"v", &384u32.to_be_bytes()],
        );
        let b = hmac(
            b"chave",
            &[&[0, 0, 0, 2], b"ATH\0", b"u", b"v", &384u32.to_be_bytes()],
        );
        assert_eq!(&saida[..32], &a);
        assert_eq!(&saida[32..], &b[..16]);
    }

    #[test]
    fn a_senha_entra_no_hmac_sem_os_zeros_do_fim() {
        assert_eq!(sem_zeros_no_fim(&[1, 2, 0, 3, 0, 0]), &[1, 2, 0, 3]);
        assert_eq!(sem_zeros_no_fim(&[0, 0]), &[] as &[u8]);
        let k = ChaveDeHmac::nova(&[7; 32], &[9, 0]);
        assert_eq!(k.como_bytes().len(), 33);
    }

    #[test]
    fn o_cfb_volta() {
        let k = ChaveDeHmac::nova(&[3; 32], b"senha");
        let mut dados = *b"o parametro que vai cifrado no barramento";
        let original = dados;
        cfb(&k, b"novo", b"velho", &mut dados, false);
        assert_ne!(dados, original);
        cfb(&k, b"novo", b"velho", &mut dados, true);
        assert_eq!(dados, original);
    }

    #[test]
    fn a_comparacao_confere_tudo() {
        assert!(iguais(b"abc", b"abc"));
        assert!(!iguais(b"abc", b"abd"));
        assert!(!iguais(b"abc", b"ab"));
    }
}
