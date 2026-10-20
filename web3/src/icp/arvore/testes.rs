//! A árvore de hash contra o exemplo da especificação e contra o
//! `ic-certification`.

use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use ic_certification::hash_tree::{
    HashTree, LookupResult, SubtreeLookupResult, empty, fork, label, leaf, pruned,
};

use super::*;
use crate::icp::bancada::{self, Sorteio};
use crate::icp::cbor;

fn hex(texto: &str) -> Vec<u8> {
    (0..texto.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&texto[i..i + 2], 16).unwrap())
        .collect()
}

const EXEMPLO: &str = "8301830183024161830183018302417882034568656c6c6f810083024179820345776f726c6483024162820344676f6f648301830241638100830241648203476d6f726e696e67";
const PODADO: &str = "83018301830241618301820458201b4feff9bef8131788b0c9dc6dbad6e81e524249c879e9f10f71ce3749f5a63883024179820345776f726c6483024162820458207b32ac0c6ba8ce35ac82c255fc7906f7fc130dab2a090f80fe12f9c2cae83ba6830182045820ec8324b8a1f1ac16bd2e806edba78006479c9877fed4eb464a25485465af601d830241648203476d6f726e696e67";
const RAIZ: &str = "eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0";

fn ler(doc: &[u8]) -> Result<Arvore<'_>, Erro> {
    Arvore::de_cbor(cbor::ler(doc).unwrap())
}

#[test]
fn o_exemplo_da_especificacao() {
    let doc = hex(EXEMPLO);
    let arvore = ler(&doc).unwrap();
    assert_eq!(&arvore.raiz()[..], &hex(RAIZ)[..]);
    assert_eq!(arvore.procurar(&[b"a", b"x"]), Procura::Achou(b"hello"));
    assert_eq!(arvore.procurar(&[b"a", b"y"]), Procura::Achou(b"world"));
    assert_eq!(arvore.procurar(&[b"b"]), Procura::Achou(b"good"));
    assert_eq!(arvore.procurar(&[b"c"]), Procura::Ausente);
    assert_eq!(arvore.procurar(&[b"d"]), Procura::Achou(b"morning"));
    // O caminho que para num rótulo é um erro; o que passa de uma folha,
    // ausente.
    assert_eq!(arvore.procurar(&[b"a"]), Procura::Erro);
    assert_eq!(arvore.procurar(&[]), Procura::Erro);
    assert_eq!(arvore.procurar(&[b"b", b"z"]), Procura::Ausente);
}

#[test]
fn o_exemplo_podado_da_especificacao() {
    let doc = hex(PODADO);
    let arvore = ler(&doc).unwrap();
    // A poda não muda a raiz.
    assert_eq!(&arvore.raiz()[..], &hex(RAIZ)[..]);
    // As oito procuras da especificação.
    assert_eq!(arvore.procurar(&[b"a", b"a"]), Procura::Desconhecida);
    assert_eq!(arvore.procurar(&[b"a", b"y"]), Procura::Achou(b"world"));
    assert_eq!(arvore.procurar(&[b"aa"]), Procura::Ausente);
    assert_eq!(arvore.procurar(&[b"ax"]), Procura::Ausente);
    assert_eq!(arvore.procurar(&[b"b"]), Procura::Desconhecida);
    assert_eq!(arvore.procurar(&[b"bb"]), Procura::Desconhecida);
    assert_eq!(arvore.procurar(&[b"d"]), Procura::Achou(b"morning"));
    assert_eq!(arvore.procurar(&[b"e"]), Procura::Ausente);
}

#[test]
fn as_subarvores() {
    let doc = hex(EXEMPLO);
    let arvore = ler(&doc).unwrap();
    let Sub::Achou(a) = arvore.subarvore(&[b"a"]) else {
        panic!()
    };
    assert_eq!(a.procurar(&[b"x"]), Procura::Achou(b"hello"));
    assert_eq!(arvore.subarvore(&[]), Sub::Achou(&arvore));
    assert_eq!(arvore.subarvore(&[b"e"]), Sub::Ausente);
    let doc = hex(PODADO);
    let podada = ler(&doc).unwrap();
    assert_eq!(podada.subarvore(&[b"bb"]), Sub::Desconhecida);
}

#[test]
fn arvores_mal_formadas() {
    let doc = |e: fn(&mut cbor::Escritor)| {
        let mut w = cbor::Escritor::novo();
        e(&mut w);
        w.terminar()
    };
    let casos: Vec<(Vec<u8>, Erro)> = vec![
        // Rótulos fora de ordem.
        (
            doc(|e| {
                e.lista(3);
                e.nat(1);
                e.lista(3);
                e.nat(2);
                e.bytes(b"b");
                e.lista(1);
                e.nat(0);
                e.lista(3);
                e.nat(2);
                e.bytes(b"a");
                e.lista(1);
                e.nat(0);
            }),
            Erro::MalFormada,
        ),
        // Rótulo repetido.
        (
            doc(|e| {
                e.lista(3);
                e.nat(1);
                e.lista(3);
                e.nat(2);
                e.bytes(b"a");
                e.lista(1);
                e.nat(0);
                e.lista(3);
                e.nat(2);
                e.bytes(b"a");
                e.lista(1);
                e.nat(0);
            }),
            Erro::MalFormada,
        ),
        // Uma folha numa floresta.
        (
            doc(|e| {
                e.lista(3);
                e.nat(1);
                e.lista(2);
                e.nat(3);
                e.bytes(b"v");
                e.lista(3);
                e.nat(2);
                e.bytes(b"a");
                e.lista(1);
                e.nat(0);
            }),
            Erro::MalFormada,
        ),
        // Formas desconhecidas, aridades erradas, tipos errados.
        (
            doc(|e| {
                e.lista(1);
                e.nat(5);
            }),
            Erro::Forma,
        ),
        (
            doc(|e| {
                e.lista(2);
                e.nat(0);
                e.nat(0);
            }),
            Erro::Forma,
        ),
        (
            doc(|e| {
                e.lista(2);
                e.nat(1);
                e.lista(1);
                e.nat(0);
            }),
            Erro::Forma,
        ),
        (
            doc(|e| {
                e.lista(3);
                e.nat(2);
                e.texto("a");
                e.lista(1);
                e.nat(0);
            }),
            Erro::Forma,
        ),
        (
            doc(|e| {
                e.lista(2);
                e.nat(3);
                e.texto("v");
            }),
            Erro::Forma,
        ),
        (
            doc(|e| {
                e.lista(0);
            }),
            Erro::Forma,
        ),
        (
            doc(|e| {
                e.nat(0);
            }),
            Erro::Forma,
        ),
        (
            doc(|e| {
                e.lista(1);
                e.texto("0");
            }),
            Erro::Forma,
        ),
        // O galho podado sem os 32 bytes.
        (
            doc(|e| {
                e.lista(2);
                e.nat(4);
                e.bytes(&[0; 31]);
            }),
            Erro::HashPodado,
        ),
        (
            doc(|e| {
                e.lista(2);
                e.nat(4);
                e.bytes(&[0; 33]);
            }),
            Erro::HashPodado,
        ),
    ];
    for (doc, erro) in casos {
        assert_eq!(ler(&doc), Err(erro), "{doc:02x?}");
    }
    // Uma folha sozinha é bem formada; a vazia também.
    let mut e = cbor::Escritor::novo();
    e.lista(2);
    e.nat(3);
    e.bytes(b"v");
    assert!(ler(&e.terminar()).is_ok());
    for m in [Erro::Forma, Erro::HashPodado, Erro::MalFormada] {
        assert!(m.to_string().is_ascii());
    }
}

/// Uma árvore gerada pelo `ic-certification`, com galhos podados ao acaso.
fn gerar(s: &mut Sorteio, nivel: usize, podar: bool) -> HashTree<Vec<u8>> {
    let arvore = if nivel > 3 || s.ate(4) == 0 {
        leaf(s.bytes_ate(8))
    } else {
        let mut rotulos: Vec<Vec<u8>> = (0..1 + s.ate(5)).map(|_| s.bytes_ate(3)).collect();
        rotulos.sort();
        rotulos.dedup();
        let filhos = rotulos
            .into_iter()
            .map(|r| label(r, gerar(s, nivel + 1, podar)))
            .collect();
        let mut t = bancada::bifurcar(filhos);
        if s.ate(6) == 0 {
            t = fork(t, empty());
        }
        t
    };
    if podar && nivel > 0 && s.ate(5) == 0 {
        pruned(arvore.digest())
    } else {
        arvore
    }
}

fn comparar(nosso: Procura<'_>, oficial: LookupResult<'_>) -> bool {
    match (nosso, oficial) {
        (Procura::Achou(a), LookupResult::Found(b)) => a == b,
        (Procura::Ausente, LookupResult::Absent)
        | (Procura::Desconhecida, LookupResult::Unknown)
        | (Procura::Erro, LookupResult::Error) => true,
        _ => false,
    }
}

#[test]
fn arvores_geradas_contra_o_oraculo() {
    let mut s = Sorteio::novo(31);
    let mut achados = 0;
    let mut desconhecidos = 0;
    for i in 0..1500 {
        let oficial = gerar(&mut s, 0, i % 2 == 1);
        let doc = serde_cbor::to_vec(&oficial).unwrap();
        let nossa = ler(&doc).unwrap();
        assert_eq!(nossa.raiz(), oficial.digest());
        // Os caminhos de verdade, e variações deles: mais curtos, mais
        // longos, com um rótulo trocado.
        let mut caminhos: Vec<Vec<Vec<u8>>> = oficial
            .list_paths()
            .into_iter()
            .map(|p| p.iter().map(|l| l.as_bytes().to_vec()).collect())
            .collect();
        for _ in 0..20 {
            caminhos.push((0..s.ate(4)).map(|_| s.bytes_ate(3)).collect());
        }
        let variacoes: Vec<Vec<Vec<u8>>> = caminhos
            .iter()
            .flat_map(|c| {
                let mut v = vec![c.clone()];
                if !c.is_empty() {
                    v.push(c[..c.len() - 1].to_vec());
                    let mut trocado = c.clone();
                    trocado[0].push(0);
                    v.push(trocado);
                }
                let mut longo = c.clone();
                longo.push(b"x".to_vec());
                v.push(longo);
                v
            })
            .collect();
        for c in &variacoes {
            let fatias: Vec<&[u8]> = c.iter().map(|r| &r[..]).collect();
            let n = nossa.procurar(&fatias);
            let o = oficial.lookup_path(&fatias);
            match n {
                Procura::Achou(_) => achados += 1,
                Procura::Desconhecida => desconhecidos += 1,
                _ => {}
            }
            assert!(comparar(n, o.clone()), "{c:02x?}: {n:?} contra {o:?}");
            let ns = nossa.subarvore(&fatias);
            let os = oficial.lookup_subtree(&fatias);
            match (ns, os) {
                (Sub::Achou(t), SubtreeLookupResult::Found(u)) => assert_eq!(t.raiz(), u.digest()),
                (Sub::Ausente, SubtreeLookupResult::Absent) => {}
                (Sub::Desconhecida, SubtreeLookupResult::Unknown) => {}
                (a, b) => panic!("{c:02x?}: {a:?} contra {b:?}"),
            }
        }
    }
    assert!(
        achados > 1000 && desconhecidos > 100,
        "{achados} {desconhecidos}"
    );
}

#[test]
fn a_arvore_da_bancada_e_a_do_oraculo() {
    // A árvore que a bancada monta para os certificados é bem formada e
    // se procura igual.
    let ic = bancada::Ic::novo();
    let oficial = bancada::arvore(&ic.folhas_da_sub_rede(bancada::AGORA_NS));
    let doc = serde_cbor::to_vec(&oficial).unwrap();
    let nossa = ler(&doc).unwrap();
    assert_eq!(nossa.raiz(), oficial.digest());
    assert_eq!(
        nossa.procurar(&[b"time"]),
        Procura::Achou(&bancada::nat(bancada::AGORA_NS))
    );
    let _: String = String::new();
}
