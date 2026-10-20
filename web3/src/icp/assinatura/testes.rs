//! A ZIP215 daqui contra o `ic-ed25519`, que é a que o IC usa.

use std::vec::Vec;

use ed25519_dalek::{Signer, SigningKey};

use super::*;
use crate::icp::bancada::Sorteio;

fn hex(texto: &str) -> Vec<u8> {
    (0..texto.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&texto[i..i + 2], 16).unwrap())
        .collect()
}

fn chave(texto: &str) -> [u8; 32] {
    hex(texto).try_into().unwrap()
}

fn oficial(chave: &[u8; 32], mensagem: &[u8], assinatura: &[u8]) -> bool {
    ic_ed25519::PublicKey::deserialize_raw(chave)
        .map(|pk| pk.verify_signature(mensagem, assinatura).is_ok())
        .unwrap_or(false)
}

#[test]
fn os_vetores_da_rfc_8032() {
    for (secreta, publica, mensagem, assinatura) in [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ] {
        let publica = chave(publica);
        assert_eq!(
            SigningKey::from_bytes(&chave(secreta))
                .verifying_key()
                .to_bytes(),
            publica
        );
        let (mensagem, assinatura) = (hex(mensagem), hex(assinatura));
        assert!(verificar(&publica, &mensagem, &assinatura));
        assert!(oficial(&publica, &mensagem, &assinatura));
        // Um bit a menos, em qualquer lugar, e não confere.
        let mut errada = assinatura.clone();
        errada[10] ^= 1;
        assert!(!verificar(&publica, &mensagem, &errada));
        let mut outra = mensagem.clone();
        outra.push(0);
        assert!(!verificar(&publica, &outra, &assinatura));
    }
}

#[test]
fn assinaturas_geradas() {
    let mut s = Sorteio::novo(41);
    for _ in 0..300 {
        let k = SigningKey::from_bytes(&s.bytes(32).try_into().unwrap());
        let publica = k.verifying_key().to_bytes();
        let mensagem = s.bytes_ate(100);
        let assinatura = k.sign(&mensagem).to_bytes();
        assert!(verificar(&publica, &mensagem, &assinatura));
        assert!(oficial(&publica, &mensagem, &assinatura));
        let mut errada = assinatura;
        let i = s.ate(64) as usize;
        errada[i] ^= 1 << s.ate(8);
        assert_eq!(
            verificar(&publica, &mensagem, &errada),
            oficial(&publica, &mensagem, &errada)
        );
        assert!(!verificar(&publica, &mensagem, &errada));
    }
}

#[test]
fn o_tamanho_da_assinatura() {
    let k = SigningKey::from_bytes(&[3; 32]);
    let publica = k.verifying_key().to_bytes();
    let assinatura = k.sign(b"m").to_bytes();
    assert!(verificar(&publica, b"m", &assinatura));
    assert!(!verificar(&publica, b"m", &assinatura[..63]));
    let mut longa = assinatura.to_vec();
    longa.push(0);
    assert!(!verificar(&publica, b"m", &longa));
    assert!(!verificar(&publica, b"m", &[]));
}

/// p = 2^255 - 19, em little-endian.
const P: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// As codificações que separam as regras: os oito pontos de ordem
/// pequena, cada `y` não canônico (`y + p`, que ainda cabe em 255 bits),
/// com os dois bits de sinal.
fn codificacoes_de_borda() -> Vec<[u8; 32]> {
    let mut saida = Vec::new();
    for ponto in [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    ] {
        saida.push(chave(ponto));
    }
    for y in 0u8..19 {
        let mut b = P;
        let (soma, vai) = b[0].overflowing_add(y);
        b[0] = soma;
        if vai {
            b[1] = b[1].wrapping_add(1);
        }
        saida.push(b);
    }
    let mut com_sinal: Vec<[u8; 32]> = saida
        .iter()
        .map(|b| {
            let mut c = *b;
            c[31] |= 0x80;
            c
        })
        .collect();
    saida.append(&mut com_sinal);
    saida
}

#[test]
fn os_casos_de_borda_da_zip215_concordam_com_o_oraculo() {
    let mut s = Sorteio::novo(42);
    let bordas = codificacoes_de_borda();
    let mut validas = 0;
    let mut recusadas = 0;
    for a in &bordas {
        for r in &bordas {
            for s_bytes in [
                [0u8; 32],
                {
                    let mut x = [0u8; 32];
                    x[0] = 1;
                    x
                },
                {
                    let mut x: [u8; 32] = s.bytes(32).try_into().unwrap();
                    x[31] &= 0x0f;
                    x
                },
            ] {
                let mut assinatura = [0u8; 64];
                assinatura[..32].copy_from_slice(r);
                assinatura[32..].copy_from_slice(&s_bytes);
                let mensagem = s.bytes(8);
                let nosso = verificar(a, &mensagem, &assinatura);
                assert_eq!(
                    nosso,
                    oficial(a, &mensagem, &assinatura),
                    "A {a:02x?} R {r:02x?}"
                );
                if nosso {
                    validas += 1;
                } else {
                    recusadas += 1;
                }
            }
        }
    }
    // A ZIP215 aceita, por exemplo, R e A de ordem pequena com s = 0, e
    // recusa os que não são pontos da curva.
    assert!(validas > 0 && recusadas > 0, "{validas} {recusadas}");
}

#[test]
fn o_s_nao_canonico_e_recusado() {
    let k = SigningKey::from_bytes(&[9; 32]);
    let publica = k.verifying_key().to_bytes();
    let mut assinatura = k.sign(b"m").to_bytes();
    // s + ℓ: o mesmo escalar, fora da forma canônica.
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut vai = 0u16;
    for i in 0..32 {
        let soma = u16::from(assinatura[32 + i]) + u16::from(l[i]) + vai;
        assinatura[32 + i] = soma as u8;
        vai = soma >> 8;
    }
    assert!(!verificar(&publica, b"m", &assinatura));
    assert!(!oficial(&publica, b"m", &assinatura));
}
