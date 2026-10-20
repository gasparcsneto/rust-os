//! O hash independente de representação — **especificação**,
//! *Representation-independent hashing of structured data*.
//!
//! O id de um pedido e o que um nó assina numa resposta não são bytes de
//! CBOR: são o SHA-256 da estrutura. Um mapa é o hash dos pares
//! `H(chave) · H(valor)` ordenados e concatenados; os bytes são o hash
//! deles; o texto, o dos bytes UTF-8; um número, o do LEB128 mais curto;
//! uma lista, o da concatenação dos hashes dos itens. Um campo opcional
//! ausente simplesmente não entra.

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use super::cbor::Valor;

/// Um SHA-256.
pub type Hash = [u8; 32];

/// O SHA-256 de bytes.
pub fn sha256(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

/// O LEB128 sem sinal, na forma mais curta: no máximo dez bytes para um
/// `u64`. Devolve o buffer e quantos bytes valem.
pub fn leb128(mut n: u64) -> ([u8; 10], usize) {
    let mut saida = [0u8; 10];
    let mut i = 0;
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            saida[i] = byte;
            return (saida, i + 1);
        }
        saida[i] = byte | 0x80;
        i += 1;
    }
}

/// O hash de bytes: eles mesmos.
pub fn de_bytes(b: &[u8]) -> Hash {
    sha256(b)
}

/// O hash de um texto: o dos bytes UTF-8, sem terminador.
pub fn de_texto(t: &str) -> Hash {
    sha256(t.as_bytes())
}

/// O hash de um número natural: o do LEB128 mais curto.
pub fn de_nat(n: u64) -> Hash {
    let (b, tamanho) = leb128(n);
    sha256(&b[..tamanho])
}

/// O hash de uma lista: o da concatenação dos hashes dos itens.
pub fn de_lista(itens: impl IntoIterator<Item = Hash>) -> Hash {
    let mut h = Sha256::new();
    for item in itens {
        h.update(item);
    }
    h.finalize().into()
}

/// O hash de um mapa, dados os hashes de cada chave e de cada valor
/// presentes: os pares `H(chave) · H(valor)` em ordem crescente,
/// concatenados.
pub fn de_mapa(campos: &[(Hash, Hash)]) -> Hash {
    let mut pares: Vec<[u8; 64]> = campos
        .iter()
        .map(|(k, v)| {
            let mut par = [0u8; 64];
            par[..32].copy_from_slice(k);
            par[32..].copy_from_slice(v);
            par
        })
        .collect();
    pares.sort_unstable();
    let mut h = Sha256::new();
    for par in &pares {
        h.update(par);
    }
    h.finalize().into()
}

/// O hash de um valor lido de CBOR, pela mesma regra — um mapa é um mapa,
/// recursivamente. É como se confere o `reply` de uma resposta, que é um
/// mapa inteiro dentro do que o nó assina.
pub fn de_valor(v: &Valor<'_>) -> Hash {
    match v {
        Valor::Nat(n) => de_nat(*n),
        Valor::Bytes(b) => de_bytes(b),
        Valor::Texto(t) => de_texto(t),
        Valor::Lista(itens) => de_lista(itens.iter().map(de_valor)),
        Valor::Mapa(pares) => {
            let campos: Vec<(Hash, Hash)> = pares
                .iter()
                .map(|(k, v)| (de_texto(k), de_valor(v)))
                .collect();
            de_mapa(&campos)
        }
    }
}

#[cfg(test)]
mod testes;
