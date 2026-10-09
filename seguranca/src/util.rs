//! O que os módulos usam e não é de nenhum: hexadecimal, base64, um resumo
//! curto para identificadores, e o texto de uma string JSON.

use alloc::string::String;
use alloc::vec::Vec;

use protocolo::json::Json;

/// Bytes em hexadecimal minúsculo.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITOS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 * bytes.len());
    for b in bytes {
        s.push(DIGITOS[usize::from(b >> 4)] as char);
        s.push(DIGITOS[usize::from(b & 0xF)] as char);
    }
    s
}

/// O caminho de volta de [`hex`], com o tamanho exato.
pub fn de_hex<const N: usize>(texto: &str) -> Option<[u8; N]> {
    let t = texto.as_bytes();
    if t.len() != 2 * N {
        return None;
    }
    let digito = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut saida = [0u8; N];
    for (i, par) in t.as_chunks::<2>().0.iter().enumerate() {
        saida[i] = (digito(par[0])? << 4) | digito(par[1])?;
    }
    Some(saida)
}

/// Base64 (RFC 4648), com o preenchimento. `None` no que não é.
pub fn de_base64(texto: &str) -> Option<Vec<u8>> {
    let t = texto.as_bytes();
    if !t.len().is_multiple_of(4) {
        return None;
    }
    let valor = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let mut saida = Vec::with_capacity(t.len() / 4 * 3);
    for (i, bloco) in t.as_chunks::<4>().0.iter().enumerate() {
        let ultimo = i == t.len() / 4 - 1;
        let preenchidos = bloco.iter().rev().take_while(|&&c| c == b'=').count();
        if preenchidos > 2 || (preenchidos > 0 && !ultimo) {
            return None;
        }
        let mut n = 0u32;
        for &c in &bloco[..4 - preenchidos] {
            n = (n << 6) | valor(c)?;
        }
        n <<= 6 * preenchidos as u32;
        let bytes = n.to_be_bytes();
        saida.extend_from_slice(&bytes[1..4 - preenchidos]);
    }
    Some(saida)
}

/// Base64 (RFC 4648), com o preenchimento.
pub fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for bloco in bytes.chunks(3) {
        let n = (u32::from(bloco[0]) << 16)
            | (u32::from(*bloco.get(1).unwrap_or(&0)) << 8)
            | u32::from(*bloco.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= bloco.len() {
                s.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// O texto de uma string JSON, com os escapes resolvidos. `None` se não é
/// uma string, ou passa de `teto` bytes.
pub fn texto(v: Option<Json>, teto: usize) -> Option<String> {
    let v = v?;
    let mut buffer = alloc::vec![0u8; teto];
    v.desescapar_em(&mut buffer).map(String::from)
}

/// O número de um campo JSON.
pub fn numero(v: Option<Json>) -> Option<u64> {
    v?.as_u64()
}

/// O resumo curto — FNV-1a de 64 bits — que vira identificador: estável,
/// sem segredo, sem pretensão de resistir a ninguém.
pub fn fnv(partes: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for parte in partes {
        for &b in *parte {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        // Um separador, para ("ab","c") e ("a","bc") não coincidirem.
        h ^= 0xFF;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn hex_vai_e_volta() {
        let b = [0u8, 1, 0xAB, 0xFF];
        assert_eq!(hex(&b), "0001abff");
        assert_eq!(de_hex::<4>("0001abff"), Some(b));
        assert_eq!(de_hex::<4>("0001ABFF"), Some(b));
        assert_eq!(de_hex::<4>("0001abf"), None);
        assert_eq!(de_hex::<4>("0001abfg"), None);
    }

    #[test]
    fn base64_vai_e_volta() {
        for n in 0..40usize {
            let b: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let t = base64(&b);
            assert_eq!(de_base64(&t).as_deref(), Some(&b[..]), "{n}");
        }
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(de_base64("TWE"), None);
        assert_eq!(de_base64("T=Fu"), None);
        assert_eq!(de_base64("TW==TWFu"), None);
        assert_eq!(de_base64("TW*u"), None);
    }

    #[test]
    fn o_texto_da_string() {
        let j = Json(br#"{"a":"x\"y","b":3}"#);
        assert_eq!(texto(j.member("a"), 16).as_deref(), Some("x\"y"));
        assert_eq!(texto(j.member("b"), 16), None);
        assert_eq!(texto(j.member("a"), 2), None);
        assert_eq!(numero(j.member("b")), Some(3));
    }

    #[test]
    fn fnv_separa() {
        assert_ne!(fnv(&[b"ab", b"c"]), fnv(&[b"a", b"bc"]));
        assert_eq!(fnv(&[b"x"]), fnv(&[b"x"]));
    }
}
