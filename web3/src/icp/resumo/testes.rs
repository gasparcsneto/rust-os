//! O hash independente de representação: os exemplos da especificação e o
//! `ic-transport-types` como oráculo.

use std::format;
use std::string::String;
use std::vec::Vec;

use super::*;
use crate::icp::bancada::Sorteio;
use crate::icp::cbor;

fn hex(texto: &str) -> Vec<u8> {
    (0..texto.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&texto[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn o_leb128_da_especificacao() {
    let (b, n) = leb128(0);
    assert_eq!(&b[..n], &[0x00]);
    let (b, n) = leb128(624_485);
    assert_eq!(&b[..n], &[0xe5, 0x8e, 0x26]);
    let (b, n) = leb128(u64::MAX);
    assert_eq!(n, 10);
    assert_eq!(
        &b[..n],
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
    );
    let (b, n) = leb128(127);
    assert_eq!(&b[..n], &[0x7f]);
    let (b, n) = leb128(128);
    assert_eq!(&b[..n], &[0x80, 0x01]);
}

#[test]
fn o_id_de_pedido_da_especificacao() {
    // **Especificação**, *Request ids*: o exemplo, passo a passo.
    let campos = [
        (de_texto("request_type"), de_texto("call")),
        (de_texto("sender"), de_bytes(&[0x04])),
        (
            de_texto("ingress_expiry"),
            de_nat(1_685_570_400_000_000_000),
        ),
        (de_texto("canister_id"), de_bytes(&hex("00000000000004d2"))),
        (de_texto("method_name"), de_texto("hello")),
        (de_texto("arg"), de_bytes(b"DIDL\x00\xfd*")),
    ];
    let esperados = [
        (
            "769e6f87bdda39c859642b74ce9763cdd37cb1cd672733e8c54efaa33ab78af9",
            "7edb360f06acaef2cc80dba16cf563f199d347db4443da04da0c8173e3f9e4ed",
        ),
        (
            "0a367b92cf0b037dfd89960ee832d56f7fc151681bb41e53690e776f5786998a",
            "e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71",
        ),
        (
            "26cec6b6a9248a96ab24305b61b9d27e203af14a580a5b1ff2f67575cab4a868",
            "db8e57abc8cda1525d45fdd2637af091bc1f28b35819a40df71517d1501f2c76",
        ),
        (
            "0a3eb2ba16702a387e6321066dd952db7a31f9b5cc92981e0a92dd56802d3df9",
            "4d8c47c3c1c837964011441882d745f7e92d10a40cef0520447c63029eafe396",
        ),
        (
            "293536232cf9231c86002f4ee293176a0179c002daa9fc24be9bb51acdd642b6",
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        ),
        (
            "b25f03dedd69be07f356a06fe35c1b0ddc0de77dcd9066c4be0c6bbde14b23ff",
            "6c0b2ae49718f6995c02ac5700c9c789d7b7862a0d53e6d40a73f1fcd2f70189",
        ),
    ];
    for ((k, v), (ek, ev)) in campos.iter().zip(esperados) {
        assert_eq!(&k[..], &hex(ek)[..]);
        assert_eq!(&v[..], &hex(ev)[..]);
    }
    assert_eq!(
        &de_mapa(&campos)[..],
        &hex("1d1091364d6bb8a6c16b203ee75467d59ead468f523eb058880ae8ec80e2b101")[..]
    );
    // A ordem dos campos não muda nada.
    let mut ao_contrario = campos;
    ao_contrario.reverse();
    assert_eq!(de_mapa(&ao_contrario), de_mapa(&campos));
}

#[test]
fn o_mapa_dentro_do_mapa_da_especificacao() {
    // hash_of_map({ "reply": { "arg": "DIDL\x00\x00" } })
    //   = H(H("reply") · H(H("arg") · H("DIDL\x00\x00")))
    let dentro = sha256(&[de_texto("arg"), de_bytes(b"DIDL\x00\x00")].concat());
    let esperado = sha256(&[de_texto("reply"), dentro].concat());
    let doc = {
        let mut e = cbor::Escritor::novo();
        e.mapa(1);
        e.texto("reply");
        e.mapa(1);
        e.texto("arg");
        e.bytes(b"DIDL\x00\x00");
        e.terminar()
    };
    assert_eq!(de_valor(&cbor::ler(&doc).unwrap()), esperado);
}

/// Um valor gerado, que se serializa nos tipos que o oráculo aceita: o
/// `serde_cbor::Value` escreve inteiros como `i128`, que ele recusa.
enum Gerado {
    Nat(u64),
    Bytes(Vec<u8>),
    Texto(String),
    Lista(Vec<Gerado>),
    Mapa(Vec<(String, Gerado)>),
}

impl serde::Serialize for Gerado {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self {
            Gerado::Nat(n) => s.serialize_u64(*n),
            Gerado::Bytes(b) => s.serialize_bytes(b),
            Gerado::Texto(t) => s.serialize_str(t),
            Gerado::Lista(l) => {
                let mut seq = s.serialize_seq(Some(l.len()))?;
                for item in l {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Gerado::Mapa(m) => {
                let mut mapa = s.serialize_map(Some(m.len()))?;
                for (k, v) in m {
                    mapa.serialize_entry(k, v)?;
                }
                mapa.end()
            }
        }
    }
}

fn gerar(s: &mut Sorteio, nivel: usize) -> Gerado {
    let tipo = if nivel > 3 { s.ate(3) } else { s.ate(5) };
    match tipo {
        0 => Gerado::Nat(match s.ate(3) {
            0 => s.ate(200),
            1 => s.ate(1 << 40),
            _ => s.proximo(),
        }),
        1 => Gerado::Bytes(s.bytes_ate(33)),
        2 => Gerado::Texto(
            (0..s.ate(9))
                .map(|_| ['a', 'b', 'ç', '7'][s.ate(4) as usize])
                .collect::<String>(),
        ),
        3 => Gerado::Lista((0..s.ate(5)).map(|_| gerar(s, nivel + 1)).collect()),
        _ => Gerado::Mapa(
            (0..s.ate(5))
                .map(|i| (format!("c{i}"), gerar(s, nivel + 1)))
                .collect(),
        ),
    }
}

#[test]
fn estruturas_geradas_contra_o_oraculo() {
    let mut s = Sorteio::novo(11);
    for _ in 0..5000 {
        // O oráculo só aceita mapa no topo: o id de um pedido é de um
        // mapa.
        let valor = Gerado::Mapa(
            (0..1 + s.ate(6))
                .map(|i| (format!("campo{i}"), gerar(&mut s, 0)))
                .collect(),
        );
        let oficial = ic_transport_types::to_request_id(&valor).unwrap();
        let doc = serde_cbor::to_vec(&valor).unwrap();
        let nosso = de_valor(&cbor::ler(&doc).unwrap());
        assert_eq!(&nosso[..], oficial.as_slice(), "{doc:02x?}");
    }
}

/// O SHA-256 em pedaços é o de uma vez, em qualquer corte — e o vazio é
/// o do vazio.
#[test]
fn o_sha256_em_pedacos_e_o_de_uma_vez() {
    let mut s = crate::icp::bancada::Sorteio::novo(61);
    for _ in 0..200 {
        let bytes = s.bytes_ate(9000);
        let mut h = Sha256EmPedacos::novo();
        let mut resto = &bytes[..];
        while !resto.is_empty() {
            let n = (s.ate(1500) as usize + 1).min(resto.len());
            h.juntar(&resto[..n]);
            resto = &resto[n..];
        }
        assert_eq!(h.fim(), sha256(&bytes));
    }
    assert_eq!(Sha256EmPedacos::novo().fim(), sha256(&[]));
}
