//! O código de Huffman do HPACK (RFC 7541, 5.2 e Apêndice B): as cadeias de
//! um bloco de cabeça podem vir nele, e as do pedido vão nele quando ficam
//! menores.
//!
//! # A tabela
//!
//! Um código fixo, o mesmo para toda conexão: 257 símbolos — os 256 bytes e
//! o EOS, que não pode aparecer numa cadeia. Ela foi transcrita de duas
//! implementações que não dividem código — o `hpack` do python-hyper e o
//! `h2` do Rust —, conferidas uma contra a outra símbolo a símbolo, e os
//! testes conferem as cadeias da RFC e a ida e volta de cada byte.
//!
//! # Como se decodifica
//!
//! O código é **canônico**: os de um mesmo tamanho são números seguidos, em
//! ordem de símbolo, e o primeiro de cada tamanho sai do último do anterior.
//! Então não há árvore: lido um bit de cada vez, o código parcial de `n`
//! bits é um símbolo exatamente quando cai no intervalo dos códigos de `n`
//! bits ([`POR_TAMANHO`]). O fim da cadeia é o preenchimento: menos de oito
//! bits, todos `1` — o começo do EOS. Outro preenchimento, ou o EOS no
//! meio, é cadeia inválida.

use alloc::vec::Vec;

/// Por que uma cadeia não se decodifica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ErroHuffman {
    /// O EOS no meio da cadeia.
    Eos,
    /// O fim não é o preenchimento: oito bits ou mais, ou um `0` nele.
    Preenchimento,
    /// A cadeia decodificada passou do teto de quem pediu.
    Teto,
}

/// O símbolo do fim da cadeia, que não pode estar nela.
const EOS: u16 = 256;

/// A cadeia `entrada` decodificada, com no máximo `teto` bytes.
pub(crate) fn decodificar(entrada: &[u8], teto: usize) -> Result<Vec<u8>, ErroHuffman> {
    // O código mais curto tem 5 bits: a saída nunca passa de 8/5 da entrada.
    let mut saida = Vec::with_capacity((entrada.len() * 8 / 5).min(teto));
    let mut codigo: u32 = 0;
    let mut bits: usize = 0;
    for &byte in entrada {
        for desloca in (0..8).rev() {
            codigo = (codigo << 1) | u32::from((byte >> desloca) & 1);
            bits += 1;
            let (primeiro, quantos, desde) = POR_TAMANHO[bits - 1];
            if codigo >= primeiro && codigo - primeiro < u32::from(quantos) {
                let simbolo = SIMBOLOS[usize::from(desde) + (codigo - primeiro) as usize];
                if simbolo == EOS {
                    return Err(ErroHuffman::Eos);
                }
                if saida.len() >= teto {
                    return Err(ErroHuffman::Teto);
                }
                saida.push(simbolo as u8);
                codigo = 0;
                bits = 0;
            } else if bits >= POR_TAMANHO.len() {
                // O código é completo: 30 bits sempre fecham um símbolo. Isto
                // não acontece; se acontecesse, não seria uma cadeia.
                return Err(ErroHuffman::Preenchimento);
            }
        }
    }
    // O que sobrou é o preenchimento: o começo do EOS, que é só `1`s.
    if bits > 7 || codigo != (1 << bits) - 1 {
        return Err(ErroHuffman::Preenchimento);
    }
    Ok(saida)
}

/// Quantos bytes `entrada` ocupa codificada.
pub(crate) fn tamanho(entrada: &[u8]) -> usize {
    let bits: usize = entrada
        .iter()
        .map(|&b| usize::from(CODIGOS[usize::from(b)].1))
        .sum();
    bits.div_ceil(8)
}

/// Acrescenta `entrada`, codificada, ao fim de `saida`, com o preenchimento
/// de `1`s.
pub(crate) fn codificar(entrada: &[u8], saida: &mut Vec<u8>) {
    let mut acumulado: u64 = 0;
    let mut bits: u32 = 0;
    for &b in entrada {
        let (codigo, n) = CODIGOS[usize::from(b)];
        acumulado = (acumulado << n) | u64::from(codigo);
        bits += u32::from(n);
        while bits >= 8 {
            bits -= 8;
            saida.push((acumulado >> bits) as u8);
        }
        acumulado &= (1 << bits) - 1;
    }
    if bits > 0 {
        let falta = 8 - bits;
        saida.push(((acumulado << falta) | ((1 << falta) - 1)) as u8);
    }
}

// Gerado de duas transcrições da RFC 7541, Apêndice B, conferidas entre si
// (o `hpack` 4.0.0 do python-hyper e o `h2` 0.4.6): o código e o tamanho de
// cada símbolo, de 0 a 255, e o EOS (256).
pub(crate) const CODIGOS: [(u32, u8); 257] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
    (0x3fffffff, 30),
];

/// A decodificação canônica: para cada tamanho, de 1 a 30 bits, o primeiro
/// código, quantos códigos têm esse tamanho, e onde começam em
/// [`SIMBOLOS`].
pub(crate) const POR_TAMANHO: [(u32, u16, u16); 30] = [
    (0x0, 0, 0),          // 1 bits
    (0x0, 0, 0),          // 2 bits
    (0x0, 0, 0),          // 3 bits
    (0x0, 0, 0),          // 4 bits
    (0x0, 10, 0),         // 5 bits
    (0x14, 26, 10),       // 6 bits
    (0x5c, 32, 36),       // 7 bits
    (0xf8, 6, 68),        // 8 bits
    (0x1fc, 0, 74),       // 9 bits
    (0x3f8, 5, 74),       // 10 bits
    (0x7fa, 3, 79),       // 11 bits
    (0xffa, 2, 82),       // 12 bits
    (0x1ff8, 6, 84),      // 13 bits
    (0x3ffc, 2, 90),      // 14 bits
    (0x7ffc, 3, 92),      // 15 bits
    (0xfffe, 0, 95),      // 16 bits
    (0x1fffc, 0, 95),     // 17 bits
    (0x3fff8, 0, 95),     // 18 bits
    (0x7fff0, 3, 95),     // 19 bits
    (0xfffe6, 8, 98),     // 20 bits
    (0x1fffdc, 13, 106),  // 21 bits
    (0x3fffd2, 26, 119),  // 22 bits
    (0x7fffd8, 29, 145),  // 23 bits
    (0xffffea, 12, 174),  // 24 bits
    (0x1ffffec, 4, 186),  // 25 bits
    (0x3ffffe0, 15, 190), // 26 bits
    (0x7ffffde, 19, 205), // 27 bits
    (0xfffffe2, 29, 224), // 28 bits
    (0x1ffffffe, 0, 253), // 29 bits
    (0x3ffffffc, 4, 253), // 30 bits
];

/// Os símbolos na ordem dos códigos: por tamanho, e dentro de cada um, por
/// código.
pub(crate) const SIMBOLOS: [u16; 257] = [
    48, 49, 50, 97, 99, 101, 105, 111, 115, 116, 32, 37, 45, 46, 47, 51, 52, 53, 54, 55, 56, 57,
    61, 65, 95, 98, 100, 102, 103, 104, 108, 109, 110, 112, 114, 117, 58, 66, 67, 68, 69, 70, 71,
    72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 89, 106, 107, 113, 118, 119,
    120, 121, 122, 38, 42, 44, 59, 88, 90, 33, 34, 40, 41, 63, 39, 43, 124, 35, 62, 0, 36, 64, 91,
    93, 126, 94, 125, 60, 96, 123, 92, 195, 208, 128, 130, 131, 162, 184, 194, 224, 226, 153, 161,
    167, 172, 176, 177, 179, 209, 216, 217, 227, 229, 230, 129, 132, 133, 134, 136, 146, 154, 156,
    160, 163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190, 196, 198, 228, 232, 233, 1,
    135, 137, 138, 139, 140, 141, 143, 147, 149, 150, 151, 152, 155, 157, 158, 165, 166, 168, 174,
    175, 180, 182, 183, 188, 191, 197, 231, 239, 9, 142, 144, 145, 148, 159, 171, 206, 215, 225,
    236, 237, 199, 207, 234, 235, 192, 193, 200, 201, 202, 205, 210, 213, 218, 219, 238, 240, 242,
    243, 255, 203, 204, 211, 212, 214, 221, 222, 223, 241, 244, 245, 246, 247, 248, 250, 251, 252,
    253, 254, 2, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28,
    29, 30, 31, 127, 220, 249, 10, 13, 22, 256,
];
