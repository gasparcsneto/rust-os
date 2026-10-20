//! O CBOR estrito: os casos de borda, e o `serde_cbor` como oráculo.

use std::collections::BTreeMap;
use std::format;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use super::*;
use crate::icp::bancada::Sorteio;

fn hex(texto: &str) -> Vec<u8> {
    let texto: String = texto.chars().filter(|c| !c.is_whitespace()).collect();
    (0..texto.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&texto[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn o_exemplo_da_especificacao() {
    // **Especificação**, *CBOR*: `82 61 61 a1 61 62 61 63` é
    // `["a", {"b": "c"}]`.
    let doc = hex("82 61 61 a1 61 62 61 63");
    let v = ler(&doc).unwrap();
    assert_eq!(
        v,
        Valor::Lista(vec![
            Valor::Texto("a"),
            Valor::Mapa(vec![("b", Valor::Texto("c"))]),
        ])
    );
}

#[test]
fn a_tag_autodescrita_so_na_frente() {
    assert_eq!(ler(&hex("d9d9f7 01")), Ok(Valor::Nat(1)));
    assert_eq!(ler(&hex("01")), Ok(Valor::Nat(1)));
    // Duas vezes, dentro de uma lista, ou outra tag: fora do perfil.
    assert_eq!(ler(&hex("d9d9f7 d9d9f7 01")), Err(Erro::TipoProibido));
    assert_eq!(ler(&hex("81 d9d9f7 01")), Err(Erro::TipoProibido));
    assert_eq!(ler(&hex("c2 41 01")), Err(Erro::TipoProibido));
    assert_eq!(ler(&hex("d9d9f8 01")), Err(Erro::TipoProibido));
    // A tag sozinha não é um documento.
    assert_eq!(ler(&hex("d9d9f7")), Err(Erro::Truncado));
    assert_eq!(ler(&[]), Err(Erro::Truncado));
}

#[test]
fn tipos_fora_do_perfil() {
    for doc in [
        "20",         // -1
        "3818",       // -25
        "f4",         // false
        "f5",         // true
        "f6",         // null
        "f7",         // undefined
        "f818",       // simples de um byte
        "f93c00",     // 1.0, meia precisão
        "fa3f800000", // 1.0, simples
        "fb3ff0000000000000",
        "c249010000000000000000", // bignum
    ] {
        assert_eq!(ler(&hex(doc)), Err(Erro::TipoProibido), "{doc}");
    }
}

#[test]
fn tamanhos_indefinidos() {
    // Listas e mapas, sim: a réplica escreve a resposta da consulta assim.
    let doc = hex("9f 01 9f 02 ff ff");
    assert_eq!(
        ler(&doc),
        Ok(Valor::Lista(vec![
            Valor::Nat(1),
            Valor::Lista(vec![Valor::Nat(2)])
        ]))
    );
    let doc = hex("d9d9f7 bf 6161 01 6162 9f ff ff");
    assert_eq!(
        ler(&doc),
        Ok(Valor::Mapa(vec![
            ("a", Valor::Nat(1)),
            ("b", Valor::Lista(vec![]))
        ]))
    );
    assert_eq!(ler(&hex("bf ff")), Ok(Valor::Mapa(vec![])));
    // Sem o `break`, truncado; o `break` no lugar de um valor, ou de uma
    // chave que não é texto; a chave repetida.
    assert_eq!(ler(&hex("9f 01")), Err(Erro::Truncado));
    assert_eq!(ler(&hex("bf 6161 01")), Err(Erro::Truncado));
    assert_eq!(ler(&hex("bf 6161 ff")), Err(Erro::TipoProibido));
    assert_eq!(ler(&hex("bf 01 02 ff")), Err(Erro::ChaveNaoTexto));
    assert_eq!(ler(&hex("bf 6161 01 6161 02 ff")), Err(Erro::ChaveRepetida));
    assert_eq!(ler(&hex("9f ff 00")), Err(Erro::Sobra));
    // Cadeias em pedaços, não.
    for doc in ["5f41ff", "7f61ff", "5f 4101 ff", "7f 6161 ff"] {
        assert_eq!(ler(&hex(doc)), Err(Erro::Indefinido), "{doc}");
    }
    // O `break` sozinho é do tipo 7, fora do perfil.
    assert_eq!(ler(&hex("ff")), Err(Erro::TipoProibido));
    // Os valores reservados do byte inicial.
    for doc in ["1c", "1d", "1e", "5c", "9d"] {
        assert_eq!(ler(&hex(doc)), Err(Erro::ForaDaForma), "{doc}");
    }
}

#[test]
fn so_a_forma_mais_curta() {
    for doc in [
        "1805",
        "1817",
        "1900ff",
        "1a0000ffff",
        "1b00000000ffffffff",
        "5801 00",
        "780161",
        "980101",
        "b8016161 01",
    ] {
        assert_eq!(ler(&hex(doc)), Err(Erro::ForaDaForma), "{doc}");
    }
    // Os limites de cada forma valem.
    assert_eq!(ler(&hex("17")), Ok(Valor::Nat(23)));
    assert_eq!(ler(&hex("1818")), Ok(Valor::Nat(24)));
    assert_eq!(ler(&hex("190100")), Ok(Valor::Nat(256)));
    assert_eq!(ler(&hex("1a00010000")), Ok(Valor::Nat(65536)));
    assert_eq!(ler(&hex("1b0000000100000000")), Ok(Valor::Nat(1 << 32)));
    assert_eq!(ler(&hex("1bffffffffffffffff")), Ok(Valor::Nat(u64::MAX)));
}

#[test]
fn mapas() {
    assert_eq!(ler(&hex("a2 6161 01 6161 02")), Err(Erro::ChaveRepetida));
    assert_eq!(ler(&hex("a1 01 02")), Err(Erro::ChaveNaoTexto));
    assert_eq!(ler(&hex("a1 4161 02")), Err(Erro::ChaveNaoTexto));
    let doc = hex("a2 6162 02 6161 01");
    let v = ler(&doc).unwrap();
    // A ordem é a de chegada; o IC não ordena as chaves.
    assert_eq!(v.campo("a"), Some(&Valor::Nat(1)));
    assert_eq!(v.campo("b"), Some(&Valor::Nat(2)));
    assert_eq!(v.campo("c"), None);
    assert_eq!(v.mapa().unwrap()[0].0, "b");
}

#[test]
fn texto_que_nao_e_utf8() {
    assert_eq!(ler(&hex("62 c328")), Err(Erro::Utf8));
    assert_eq!(ler(&hex("62 c3a9")), Ok(Valor::Texto("é")));
}

#[test]
fn bytes_depois_do_item() {
    assert_eq!(ler(&hex("01 02")), Err(Erro::Sobra));
    assert_eq!(ler(&hex("d9d9f7 01 00")), Err(Erro::Sobra));
}

#[test]
fn um_tamanho_maior_que_o_resto_nao_reserva_memoria() {
    // Quatro bilhões de itens anunciados em cinco bytes.
    assert_eq!(ler(&hex("9affffffff")), Err(Erro::Truncado));
    assert_eq!(ler(&hex("bbffffffffffffffff")), Err(Erro::Truncado));
    assert_eq!(ler(&hex("5bffffffffffffffff")), Err(Erro::Truncado));
    assert_eq!(ler(&hex("7a00010000 61")), Err(Erro::Truncado));
}

#[test]
fn os_tetos_valem_nas_colecoes_indefinidas() {
    let tetos = Tetos {
        profundidade: 3,
        itens: 10,
        pares: 2,
    };
    assert!(ler_com(&hex("9f9f9f01ffffff"), tetos).is_ok());
    assert_eq!(
        ler_com(&hex("9f9f9f9f01ffffffff"), tetos),
        Err(Erro::Profundo)
    );
    assert_eq!(
        ler_com(&hex("9f 01 01 01 01 01 01 01 01 01 01 ff"), tetos),
        Err(Erro::Grande)
    );
    assert_eq!(
        ler_com(&hex("bf 6161 01 6162 02 6163 03 ff"), tetos),
        Err(Erro::Grande)
    );
    // Uma lista indefinida enorme não passa do teto de itens: a recusa
    // vem antes da memória.
    let mut longa = vec![0x9f];
    longa.extend(std::iter::repeat_n(0x00, 1_000_000));
    longa.push(0xff);
    assert_eq!(ler(&longa), Err(Erro::Grande));
    let mut funda = vec![0x9f; 100_000];
    funda.push(0x01);
    assert_eq!(ler(&funda), Err(Erro::Profundo));
}

#[test]
fn o_mapa_achatado_do_serde_cbor() {
    // O que o `serde_cbor` escreve para uma estrutura com
    // `#[serde(flatten)]` — o caso da resposta da réplica.
    #[derive(serde::Serialize)]
    struct Dentro {
        status: &'static str,
    }
    #[derive(serde::Serialize)]
    struct Fora {
        #[serde(flatten)]
        dentro: Dentro,
        assinaturas: Vec<u8>,
    }
    let doc = serde_cbor::to_vec(&Fora {
        dentro: Dentro { status: "replied" },
        assinaturas: vec![1, 2],
    })
    .unwrap();
    assert_eq!(doc[0], 0xbf);
    let v = ler(&doc).unwrap();
    assert_eq!(v.campo("status"), Some(&Valor::Texto("replied")));
    assert_eq!(
        v.campo("assinaturas"),
        Some(&Valor::Lista(vec![Valor::Nat(1), Valor::Nat(2)]))
    );
}

#[test]
fn listas_aninhadas_nao_reservam_o_anunciado() {
    // Sessenta listas, uma dentro da outra, cada uma anunciando 16 mil
    // itens: o documento tem uns 20 KB, e a leitura falha sem reservar
    // 60 × 16 mil itens.
    let mut doc = Vec::new();
    for _ in 0..60 {
        doc.extend_from_slice(&[0x99, 0x3e, 0x80]);
    }
    doc.extend(std::iter::repeat_n(0x00, 20_000));
    assert!(ler(&doc).is_err());
}

#[test]
fn a_profundidade() {
    let fundo = |n: usize| {
        let mut doc = vec![0x81u8; n];
        doc.push(0x01);
        doc
    };
    assert!(ler(&fundo(TETOS.profundidade)).is_ok());
    assert_eq!(ler(&fundo(TETOS.profundidade + 1)), Err(Erro::Profundo));
    // Mapas contam como listas.
    let mut mapas = Vec::new();
    for _ in 0..=TETOS.profundidade {
        mapas.extend_from_slice(&hex("a1 6161"));
    }
    mapas.push(0x01);
    assert_eq!(ler(&mapas), Err(Erro::Profundo));
    // Um documento fundo demais para a pilha de um programa não a gasta:
    // a recusa vem no teto.
    assert_eq!(ler(&fundo(100_000)), Err(Erro::Profundo));
}

#[test]
fn os_itens_e_os_pares() {
    let tetos = Tetos {
        profundidade: 8,
        itens: 10,
        pares: 2,
    };
    let lista = |n: usize| {
        let mut doc = vec![0x80 | n as u8];
        doc.extend(std::iter::repeat_n(0x01, n));
        doc
    };
    // A lista e os nove itens: dez.
    assert!(ler_com(&lista(9), tetos).is_ok());
    assert_eq!(ler_com(&lista(10), tetos), Err(Erro::Grande));
    assert!(ler_com(&hex("a2 6161 01 6162 02"), tetos).is_ok());
    assert_eq!(
        ler_com(&hex("a3 6161 01 6162 02 6163 03"), tetos),
        Err(Erro::Grande)
    );
    // O teto de pares padrão.
    let mut grande = vec![0xb8, (TETOS.pares + 1) as u8];
    for i in 0..=TETOS.pares {
        let chave = format!("{i:03}");
        grande.push(0x63);
        grande.extend_from_slice(chave.as_bytes());
        grande.push(0x00);
    }
    assert_eq!(ler(&grande), Err(Erro::Grande));
}

#[test]
fn todo_prefixo_e_truncado() {
    let doc = hex("d9d9f7 a3 6474726565 8301 830241 61 820341 62 8204 5820 \
         0000000000000000000000000000000000000000000000000000000000000000 \
         697369676e6174757265 43 010203 63666f6f 9f");
    // O documento inteiro não vale (o `9f` do fim), mas cada prefixo dele
    // até lá também não, e nenhum é aceito pela metade.
    for n in 0..doc.len() {
        assert!(ler(&doc[..n]).is_err(), "{n}");
    }
}

#[test]
fn o_escritor() {
    let mut e = Escritor::novo();
    e.autodescrita();
    e.mapa(2);
    e.texto("a");
    e.lista(3);
    e.nat(0);
    e.nat(24);
    e.nat(u64::MAX);
    e.texto("b");
    e.bytes(&[1, 2, 3]);
    let doc = e.terminar();
    assert_eq!(
        doc,
        hex("d9d9f7 a2 6161 83 00 1818 1bffffffffffffffff 6162 43010203")
    );
    let v = ler(&doc).unwrap();
    assert_eq!(
        v.campo("a"),
        Some(&Valor::Lista(vec![
            Valor::Nat(0),
            Valor::Nat(24),
            Valor::Nat(u64::MAX)
        ]))
    );
}

/// Um valor gerado, dono dos bytes.
#[derive(Clone, Debug, PartialEq)]
enum Gerado {
    Nat(u64),
    Bytes(Vec<u8>),
    Texto(String),
    Lista(Vec<Gerado>),
    Mapa(Vec<(String, Gerado)>),
}

fn gerar(s: &mut Sorteio, nivel: usize) -> Gerado {
    let tipo = if nivel > 4 { s.ate(3) } else { s.ate(5) };
    match tipo {
        0 => Gerado::Nat(match s.ate(4) {
            0 => s.ate(24),
            1 => s.ate(1 << 16),
            2 => s.ate(1 << 32),
            _ => s.proximo(),
        }),
        1 => Gerado::Bytes(s.bytes_ate(40)),
        2 => {
            let n = s.ate(12) as usize;
            Gerado::Texto(
                (0..n)
                    .map(|_| ['a', 'z', 'é', '0', '€', '😀'][s.ate(6) as usize])
                    .collect(),
            )
        }
        3 => {
            let n = s.ate(6) as usize;
            Gerado::Lista((0..n).map(|_| gerar(s, nivel + 1)).collect())
        }
        _ => {
            let n = s.ate(6) as usize;
            let mut pares: Vec<(String, Gerado)> = Vec::new();
            for i in 0..n {
                let chave = format!("k{}{}", i, s.ate(3));
                if pares.iter().all(|(k, _)| *k != chave) {
                    pares.push((chave, gerar(s, nivel + 1)));
                }
            }
            Gerado::Mapa(pares)
        }
    }
}

fn escrever(e: &mut Escritor, g: &Gerado) {
    match g {
        Gerado::Nat(n) => e.nat(*n),
        Gerado::Bytes(b) => e.bytes(b),
        Gerado::Texto(t) => e.texto(t),
        Gerado::Lista(l) => {
            e.lista(l.len());
            for item in l {
                escrever(e, item);
            }
        }
        Gerado::Mapa(m) => {
            e.mapa(m.len());
            for (k, v) in m {
                e.texto(k);
                escrever(e, v);
            }
        }
    }
}

fn igual(v: &Valor<'_>, g: &Gerado) -> bool {
    match (v, g) {
        (Valor::Nat(a), Gerado::Nat(b)) => a == b,
        (Valor::Bytes(a), Gerado::Bytes(b)) => *a == &b[..],
        (Valor::Texto(a), Gerado::Texto(b)) => a == b,
        (Valor::Lista(a), Gerado::Lista(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| igual(x, y))
        }
        (Valor::Mapa(a), Gerado::Mapa(b)) => {
            a.len() == b.len()
                && b.iter()
                    .all(|(k, gv)| a.iter().any(|(ak, av)| *ak == k && igual(av, gv)))
        }
        _ => false,
    }
}

fn do_oraculo(v: &serde_cbor::Value) -> Option<Gerado> {
    use serde_cbor::Value as V;
    Some(match v {
        V::Integer(n) => Gerado::Nat(u64::try_from(*n).ok()?),
        V::Bytes(b) => Gerado::Bytes(b.clone()),
        V::Text(t) => Gerado::Texto(t.clone()),
        V::Array(l) => Gerado::Lista(l.iter().map(do_oraculo).collect::<Option<_>>()?),
        V::Map(m) => Gerado::Mapa(
            m.iter()
                .map(|(k, v)| match k {
                    V::Text(t) => Some((t.clone(), do_oraculo(v)?)),
                    _ => None,
                })
                .collect::<Option<_>>()?,
        ),
        V::Tag(TAG_AUTODESCRITA, v) => do_oraculo(v)?,
        _ => return None,
    })
}

fn para_o_oraculo(g: &Gerado) -> serde_cbor::Value {
    use serde_cbor::Value as V;
    match g {
        Gerado::Nat(n) => V::Integer(i128::from(*n)),
        Gerado::Bytes(b) => V::Bytes(b.clone()),
        Gerado::Texto(t) => V::Text(t.clone()),
        Gerado::Lista(l) => V::Array(l.iter().map(para_o_oraculo).collect()),
        Gerado::Mapa(m) => V::Map(
            m.iter()
                .map(|(k, v)| (V::Text(k.clone()), para_o_oraculo(v)))
                .collect::<BTreeMap<_, _>>(),
        ),
    }
}

#[test]
fn documentos_gerados_contra_o_oraculo() {
    let mut s = Sorteio::novo(7);
    for _ in 0..3000 {
        let g = gerar(&mut s, 0);
        // O que este lado escreve, os dois leem igual.
        let mut e = Escritor::novo();
        if s.ate(2) == 0 {
            e.autodescrita();
        }
        escrever(&mut e, &g);
        let doc = e.terminar();
        assert!(igual(&ler(&doc).unwrap(), &g), "{doc:02x?}");
        let oficial: serde_cbor::Value = serde_cbor::from_slice(&doc).unwrap();
        assert_eq!(
            do_oraculo(&oficial).as_ref().map(comparavel),
            Some(comparavel(&g))
        );
        // O que o oráculo escreve, este lado lê.
        let doc = serde_cbor::to_vec(&para_o_oraculo(&g)).unwrap();
        assert!(igual(&ler(&doc).unwrap(), &g), "{doc:02x?}");
    }
}

/// O valor com os mapas em ordem, para comparar com o do oráculo, que
/// ordena as chaves.
fn comparavel(g: &Gerado) -> Gerado {
    match g {
        Gerado::Lista(l) => Gerado::Lista(l.iter().map(comparavel).collect()),
        Gerado::Mapa(m) => {
            let mut m: Vec<(String, Gerado)> =
                m.iter().map(|(k, v)| (k.clone(), comparavel(v))).collect();
            m.sort_by(|a, b| {
                para_o_oraculo(&Gerado::Texto(a.0.clone()))
                    .cmp(&para_o_oraculo(&Gerado::Texto(b.0.clone())))
            });
            Gerado::Mapa(m)
        }
        outro => outro.clone(),
    }
}

#[test]
fn documentos_mexidos_nunca_passam_do_oraculo() {
    // Um documento estragado que este lado aceita, o oráculo também
    // aceita, com o mesmo valor: este lado nunca é mais permissivo.
    let mut s = Sorteio::novo(8);
    let mut aceitos = 0;
    for _ in 0..20_000 {
        let g = gerar(&mut s, 0);
        let mut e = Escritor::novo();
        escrever(&mut e, &g);
        let mut doc = e.terminar();
        for _ in 0..1 + s.ate(3) {
            if doc.is_empty() {
                break;
            }
            let i = s.ate(doc.len() as u64) as usize;
            match s.ate(3) {
                0 => doc[i] = s.proximo() as u8,
                1 => {
                    doc.remove(i);
                }
                _ => doc.insert(i, s.proximo() as u8),
            }
        }
        if let Ok(v) = ler(&doc) {
            aceitos += 1;
            let oficial: serde_cbor::Value =
                serde_cbor::from_slice(&doc).unwrap_or_else(|e| panic!("{doc:02x?}: {e}"));
            let o = do_oraculo(&oficial).unwrap();
            assert!(igual(&v, &o), "{doc:02x?}");
        }
    }
    assert!(aceitos > 1000, "{aceitos}");
}

#[test]
fn as_mensagens_sao_ascii() {
    for e in [
        Erro::Truncado,
        Erro::Sobra,
        Erro::TipoProibido,
        Erro::Indefinido,
        Erro::ForaDaForma,
        Erro::ChaveNaoTexto,
        Erro::ChaveRepetida,
        Erro::Utf8,
        Erro::Profundo,
        Erro::Grande,
    ] {
        assert!(e.to_string().is_ascii());
    }
}
