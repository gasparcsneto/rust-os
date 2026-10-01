//! O resumo, o HMAC e o HKDF: as três funções de onde saem todas as chaves.
//!
//! # Por que o HMAC é escrito aqui
//!
//! O BLAKE2s tem um modo com chave próprio, e o `blake2` o oferece. O Noise
//! não o usa: a especificação define o HKDF sobre o **HMAC** do resumo, como
//! na RFC 2104, para que a mesma construção valha com qualquer resumo da
//! lista. Usar o modo com chave do BLAKE2s daria chaves diferentes das de
//! qualquer outra implementação — os vetores publicados acusariam na
//! primeira mensagem.
//!
//! O HMAC é uma receita de dez linhas sobre o resumo, e escrevê-la aqui é
//! mais claro do que puxar um pacote para ela. A aritmética continua sendo a
//! do BLAKE2s, que não é escrita aqui.

use blake2::{Blake2s256, Digest};
use zeroize::Zeroize;

/// O tamanho de um resumo, e de toda chave que sai do HKDF.
pub const TAM_RESUMO: usize = 32;

/// O tamanho do bloco do BLAKE2s, que o HMAC usa para alinhar a chave.
const TAM_BLOCO: usize = 64;

/// O resumo de uma sequência de pedaços, como se fossem um só.
pub fn resumir(pedacos: &[&[u8]]) -> [u8; TAM_RESUMO] {
    let mut h = Blake2s256::new();
    for pedaco in pedacos {
        h.update(pedaco);
    }
    h.finalize().into()
}

/// O HMAC-BLAKE2s de uma mensagem em pedaços.
///
/// A chave do Noise tem sempre 32 bytes, menos que o bloco; uma chave maior
/// que o bloco seria resumida antes, como a RFC manda, e é tratada pelo mesmo
/// caminho.
pub fn hmac(chave: &[u8], pedacos: &[&[u8]]) -> [u8; TAM_RESUMO] {
    let mut bloco = [0u8; TAM_BLOCO];
    if chave.len() > TAM_BLOCO {
        bloco[..TAM_RESUMO].copy_from_slice(&resumir(&[chave]));
    } else {
        bloco[..chave.len()].copy_from_slice(chave);
    }

    let mut interna = [0u8; TAM_BLOCO];
    let mut externa = [0u8; TAM_BLOCO];
    for i in 0..TAM_BLOCO {
        interna[i] = bloco[i] ^ 0x36;
        externa[i] = bloco[i] ^ 0x5c;
    }

    let mut h = Blake2s256::new();
    h.update(interna);
    for pedaco in pedacos {
        h.update(pedaco);
    }
    let meio: [u8; TAM_RESUMO] = h.finalize().into();
    let resultado = resumir(&[&externa, &meio]);

    // A chave alinhada e as duas máscaras são a chave em outra forma.
    bloco.zeroize();
    interna.zeroize();
    externa.zeroize();
    resultado
}

/// O HKDF do Noise: duas chaves derivadas de uma chave de encadeamento e de
/// um material novo.
///
/// É a função `HKDF(chaining_key, input_key_material, 2)` da seção 4.3 da
/// especificação. A versão de três saídas só é usada com chaves
/// pré-compartilhadas, que este canal não tem.
pub fn hkdf2(encadeamento: &[u8; TAM_RESUMO], material: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut temporaria = hmac(encadeamento, &[material]);
    let primeira = hmac(&temporaria, &[&[0x01]]);
    let segunda = hmac(&temporaria, &[&primeira, &[0x02]]);
    temporaria.zeroize();
    (primeira, segunda)
}

/// O HKDF da RFC 5869, com uma saída: extrair com o sal, expandir com a
/// informação.
///
/// É o que deriva a chave da prova administrativa — ver
/// [`crate::administracao`]. Difere do HKDF do Noise num ponto que importa
/// aqui: tem o campo de **informação**, e é nele que a chave fica presa ao
/// contexto em que vale.
///
/// A informação vem em pedaços, concatenados como estão: quem chama é que
/// garante que a concatenação não seja ambígua — ver
/// [`crate::administracao`], que põe o tamanho na frente de cada campo.
pub fn hkdf_rfc5869(sal: &[u8], material: &[u8], informacao: &[&[u8]]) -> [u8; TAM_RESUMO] {
    let mut pseudoaleatoria = hmac(sal, &[material]);
    let mut pedacos: [&[u8]; 16] = [&[]; 16];
    assert!(
        informacao.len() < pedacos.len(),
        "informacao em pedacos demais"
    );
    pedacos[..informacao.len()].copy_from_slice(informacao);
    pedacos[informacao.len()] = &[0x01];
    let saida = hmac(&pseudoaleatoria, &pedacos[..=informacao.len()]);
    pseudoaleatoria.zeroize();
    saida
}

#[cfg(test)]
mod testes {
    use super::*;
    use alloc::vec::Vec;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// O HMAC confere com a construção da RFC 2104 calculada por outro
    /// caminho: o modo `SimpleHmac` não existe aqui, mas a definição sim —
    /// `H((K ^ opad) || H((K ^ ipad) || m))` —, e ela é refeita à mão com
    /// os pedaços concatenados, para pegar um erro na divisão em pedaços.
    #[test]
    fn hmac_e_a_receita_da_rfc() {
        let chave = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let mensagem = b"o duke conversa com agentes";
        let mut k = [0u8; 64];
        k[..32].copy_from_slice(&chave);
        let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
        let dentro = resumir(&[&ipad, mensagem]);
        let esperado = resumir(&[&opad, &dentro]);
        assert_eq!(
            hmac(&chave, &[b"o duke ", b"conversa com agentes"]),
            esperado
        );
    }

    /// Uma chave maior que o bloco é resumida antes, e não truncada.
    #[test]
    fn chave_longa_e_resumida() {
        let longa = [7u8; 100];
        let resumida = resumir(&[&longa]);
        assert_eq!(hmac(&longa, &[b"x"]), hmac(&resumida, &[b"x"]));
    }

    /// O HKDF da RFC com informação diferente dá chaves diferentes — é a
    /// propriedade que a prova administrativa usa.
    #[test]
    fn informacao_muda_a_chave() {
        let a = hkdf_rfc5869(b"sal", b"segredo", &[b"agent.register", b"{}"]);
        let b = hkdf_rfc5869(b"sal", b"segredo", &[b"agent.register", b"{ }"]);
        assert_ne!(a, b);
    }
}
