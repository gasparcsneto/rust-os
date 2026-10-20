//! O Principal contra a especificação e contra o `ic_principal`.

use std::format;
use std::string::{String, ToString};
use std::vec::Vec;

use core::cmp::Ordering;

use super::*;
use crate::icp::bancada::Sorteio;

fn hex(texto: &str) -> Vec<u8> {
    (0..texto.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&texto[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn os_exemplos_da_especificacao() {
    // **Especificação**: o canister 0xABCD01 tem CRC 0x233FF206 e o texto
    // em77e-bvlzu-aq.
    assert_eq!(crc32(&[0xab, 0xcd, 0x01]), 0x233f_f206);
    let p = Principal::de_bytes(&[0xab, 0xcd, 0x01]).unwrap();
    assert_eq!(p.texto(), "em77e-bvlzu-aq");
    assert_eq!(Principal::de_texto("em77e-bvlzu-aq"), Ok(p));
    // O anônimo e o canister de gerenciamento.
    assert_eq!(Principal::ANONIMO.texto(), "2vxsx-fae");
    assert_eq!(Principal::GERENCIAMENTO.texto(), "aaaaa-aa");
    assert_eq!(Principal::de_texto("2vxsx-fae"), Ok(Principal::ANONIMO));
    assert_eq!(
        Principal::de_texto("aaaaa-aa"),
        Ok(Principal::GERENCIAMENTO)
    );
    // O ledger da mainnet, e a sub-rede raiz da mainnet (a nota da
    // especificação sobre o `read_state` de sub-rede).
    let ledger = Principal::de_texto("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
    assert_eq!(ledger.bytes(), &hex("00000000000000020101")[..]);
    let raiz =
        Principal::de_texto("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
            .unwrap();
    assert_eq!(raiz.bytes().len(), MAIOR);
    assert_eq!(raiz.classe(), Classe::AutoAutenticado);
}

#[test]
fn as_classes() {
    assert_eq!(Principal::ANONIMO.classe(), Classe::Anonimo);
    assert_eq!(Principal::GERENCIAMENTO.classe(), Classe::Opaco);
    assert_eq!(
        Principal::de_bytes(&[1, 2, 0x7f]).unwrap().classe(),
        Classe::Reservado
    );
    assert_eq!(
        Principal::de_bytes(&[0x7f]).unwrap().classe(),
        Classe::Reservado
    );
    let mut derivado = [7u8; MAIOR];
    derivado[MAIOR - 1] = 0x03;
    assert_eq!(
        Principal::de_bytes(&derivado).unwrap().classe(),
        Classe::Derivado
    );
    // Só com 29 bytes o fim 0x02 é auto-autenticado.
    assert_eq!(
        Principal::de_bytes(&[1, 0x02]).unwrap().classe(),
        Classe::Opaco
    );
    assert_eq!(
        Principal::auto_autenticado(b"chave").classe(),
        Classe::AutoAutenticado
    );
    // Um 0x04 no fim de um Principal maior não é o anônimo.
    assert_eq!(
        Principal::de_bytes(&[1, 0x04]).unwrap().classe(),
        Classe::Opaco
    );
}

#[test]
fn o_auto_autenticado_e_o_do_oraculo() {
    for der in [&b""[..], b"x", &[0u8; 44], &[0xffu8; 133]] {
        let oficial = ic_principal::Principal::self_authenticating(der);
        assert_eq!(Principal::auto_autenticado(der).bytes(), oficial.as_slice());
    }
}

#[test]
fn ida_e_volta_contra_o_oraculo() {
    let mut s = Sorteio::novo(1);
    for _ in 0..2000 {
        let bytes = s.bytes_ate(MAIOR);
        let p = Principal::de_bytes(&bytes).unwrap();
        let oficial = ic_principal::Principal::from_slice(&bytes);
        let texto = p.texto();
        assert_eq!(texto, oficial.to_text(), "{bytes:02x?}");
        assert!(texto.len() <= MAIOR_TEXTO);
        assert_eq!(Principal::de_texto(&texto), Ok(p));
        assert_eq!(format!("{p}"), texto);
        // Sem distinguir maiúsculas, como a especificação manda ler.
        let maiusculas = texto.to_ascii_uppercase();
        assert_eq!(Principal::de_texto(&maiusculas), Ok(p));
        assert!(ic_principal::Principal::from_text(&maiusculas).is_ok());
    }
}

#[test]
fn as_duas_ordens() {
    let mut s = Sorteio::novo(2);
    let mut discordam = 0;
    for _ in 0..2000 {
        let a = s.bytes_ate(MAIOR);
        let b = s.bytes_ate(MAIOR);
        let (pa, pb) = (
            Principal::de_bytes(&a).unwrap(),
            Principal::de_bytes(&b).unwrap(),
        );
        let (oa, ob) = (
            ic_principal::Principal::from_slice(&a),
            ic_principal::Principal::from_slice(&b),
        );
        // A daqui é a da especificação: lexicográfica.
        assert_eq!(pa.cmp(&pb), a.cmp(&b));
        // A oficial é a do oráculo, tamanho primeiro.
        assert_eq!(pa.ordem_oficial(&pb), oa.cmp(&ob));
        // Do mesmo tamanho, as duas são a mesma.
        if a.len() == b.len() {
            assert_eq!(pa.cmp(&pb), pa.ordem_oficial(&pb));
        } else if pa.cmp(&pb) != pa.ordem_oficial(&pb) {
            discordam += 1;
        }
    }
    // E de tamanhos diferentes elas discordam de verdade — é por isso que
    // as faixas exigem as duas.
    assert!(discordam > 0);
    let curto = Principal::de_bytes(&[9]).unwrap();
    let longo = Principal::de_bytes(&[1, 0]).unwrap();
    assert_eq!(curto.cmp(&longo), Ordering::Greater);
    assert_eq!(curto.ordem_oficial(&longo), Ordering::Less);
}

#[test]
fn o_comprimento() {
    assert_eq!(Principal::de_bytes(&[0; 30]), Err(Erro::LongoDemais));
    assert!(Principal::de_bytes(&[0; 29]).is_ok());
    // O maior texto tem 63 caracteres; um a mais é recusado antes de tudo.
    let maior = Principal::de_bytes(&[0xee; 29]).unwrap().texto();
    assert_eq!(maior.len(), MAIOR_TEXTO);
    let mais = format!("{maior}a");
    assert_eq!(Principal::de_texto(&mais), Err(Erro::TextoLongo));
    // 30 bytes bem formados (com CRC certo) são recusados pelo tamanho.
    let trinta = [0x11u8; 30];
    let mut cru = Vec::from(crc32(&trinta).to_be_bytes());
    cru.extend_from_slice(&trinta);
    let mut base = [0u8; 64];
    let n = codificar_base32(&cru, &mut base);
    let texto: String = base[..n]
        .chunks(5)
        .map(|g| core::str::from_utf8(g).unwrap())
        .collect::<Vec<_>>()
        .join("-");
    assert!(texto.len() > MAIOR_TEXTO);
    assert_eq!(Principal::de_texto(&texto), Err(Erro::TextoLongo));
    assert!(ic_principal::Principal::from_text(&texto).is_err());
}

#[test]
fn o_crc_corrompido_e_recusado() {
    let mut s = Sorteio::novo(3);
    for _ in 0..500 {
        let n = 1 + s.ate(MAIOR as u64) as usize;
        let bytes = s.bytes(n);
        let texto = Principal::de_bytes(&bytes).unwrap().texto();
        // Troca um caractere por outro da base32.
        let mut letras: Vec<u8> = texto.bytes().collect();
        let posicoes: Vec<usize> = (0..letras.len()).filter(|&i| letras[i] != b'-').collect();
        let i = posicoes[s.ate(posicoes.len() as u64) as usize];
        let original = letras[i];
        loop {
            let novo = ALFABETO[s.ate(32) as usize];
            if novo != original {
                letras[i] = novo;
                break;
            }
        }
        let errado = String::from_utf8(letras).unwrap();
        let nosso = Principal::de_texto(&errado);
        assert!(nosso.is_err(), "{errado}");
        assert!(
            ic_principal::Principal::from_text(&errado).is_err(),
            "{errado}"
        );
    }
}

#[test]
fn o_texto_malformado() {
    for (texto, erro) in [
        ("", Erro::TextoCurto),
        ("aaaa", Erro::TextoCurto),
        // Cinco caracteres dão três bytes: nem o CRC.
        ("aaaaa", Erro::TextoCurto),
        ("aaaaa-a", Erro::Base32),
        ("2vxsx-fa1", Erro::Base32),
        ("2vxsx_fae", Erro::Base32),
        ("2vxsx fae", Erro::Base32),
        ("2vxsx-fáe", Erro::Base32),
        // O agrupamento é o canônico, e nada mais.
        ("2vxsxfae", Erro::ForaDaForma),
        ("2vx-sxfae", Erro::ForaDaForma),
        ("-2vxsx-fae", Erro::ForaDaForma),
        ("2vxsx-fae-", Erro::ForaDaForma),
        ("2vxsx--fae", Erro::ForaDaForma),
        // Oito caracteres são 40 bits exatos: trocar o último muda os
        // dados, e o CRC não confere.
        ("2vxsx-faf", Erro::Verificacao),
        // Sete caracteres são 35 bits para 32: os 3 de sobra têm de ser
        // zero, e o `b` (00001) os suja.
        ("aaaaa-ab", Erro::Base32),
    ] {
        assert_eq!(Principal::de_texto(texto), Err(erro), "{texto:?}");
        assert!(
            ic_principal::Principal::from_text(texto).is_err(),
            "{texto:?}"
        );
    }
}

#[test]
fn entradas_geradas_contra_o_oraculo() {
    // O oráculo e este lado concordam em toda cadeia: aceitam as mesmas,
    // com os mesmos bytes.
    let mut s = Sorteio::novo(4);
    let alfabeto = b"abcdefghijklmnopqrstuvwxyz234567-ABZ019_ ";
    for _ in 0..20_000 {
        let n = s.ate(66) as usize;
        let texto: String = (0..n)
            .map(|_| char::from(alfabeto[s.ate(alfabeto.len() as u64) as usize]))
            .collect();
        let nosso = Principal::de_texto(&texto);
        let oficial = ic_principal::Principal::from_text(&texto);
        match (nosso, oficial) {
            (Ok(p), Ok(o)) => assert_eq!(p.bytes(), o.as_slice(), "{texto:?}"),
            (Err(_), Err(_)) => {}
            (n, o) => panic!("{texto:?}: daqui {n:?}, oficial {o:?}"),
        }
    }
    // E as cadeias quase certas: um texto válido com uma troca.
    for _ in 0..5000 {
        let bytes = s.bytes_ate(MAIOR);
        let mut texto: Vec<u8> = Principal::de_bytes(&bytes).unwrap().texto().into_bytes();
        match s.ate(3) {
            0 if !texto.is_empty() => {
                let i = s.ate(texto.len() as u64) as usize;
                texto.remove(i);
            }
            1 => {
                let i = s.ate(texto.len() as u64 + 1) as usize;
                texto.insert(i, alfabeto[s.ate(alfabeto.len() as u64) as usize]);
            }
            _ if !texto.is_empty() => {
                let i = s.ate(texto.len() as u64) as usize;
                texto[i] = alfabeto[s.ate(alfabeto.len() as u64) as usize];
            }
            _ => {}
        }
        let texto = String::from_utf8(texto).unwrap();
        let nosso = Principal::de_texto(&texto);
        let oficial = ic_principal::Principal::from_text(&texto);
        match (nosso, oficial) {
            (Ok(p), Ok(o)) => assert_eq!(p.bytes(), o.as_slice(), "{texto:?}"),
            (Err(_), Err(_)) => {}
            (n, o) => panic!("{texto:?}: daqui {n:?}, oficial {o:?}"),
        }
    }
}

#[test]
fn as_mensagens_sao_ascii() {
    for e in [
        Erro::LongoDemais,
        Erro::TextoCurto,
        Erro::TextoLongo,
        Erro::Base32,
        Erro::Verificacao,
        Erro::ForaDaForma,
    ] {
        assert!(e.to_string().is_ascii());
    }
    assert_eq!(format!("{:?}", Principal::ANONIMO), "Principal(2vxsx-fae)");
}
