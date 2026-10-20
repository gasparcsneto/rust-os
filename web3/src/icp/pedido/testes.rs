//! Os pedidos contra o `ic-transport-types`: o mesmo id, e o envelope que
//! ele lê.

use std::borrow::Cow;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use ic_transport_types::{Envelope, EnvelopeContent, to_request_id};

use super::*;
use crate::icp::bancada::Sorteio;
use crate::icp::cbor;

fn principal_oficial(p: &Principal) -> candid::Principal {
    candid::Principal::from_slice(p.bytes())
}

#[test]
fn a_consulta_tem_o_id_do_oraculo() {
    let mut s = Sorteio::novo(21);
    for i in 0..500 {
        let canister = Principal::de_bytes(&s.bytes_ate(29)).unwrap();
        let metodo: String = (0..s.ate(20))
            .map(|_| char::from(b'a' + s.ate(26) as u8))
            .collect();
        let arg = s.bytes_ate(200);
        let nonce = if i % 2 == 0 {
            Some(s.bytes_ate(32))
        } else {
            None
        };
        let vencimento_ns = s.proximo();
        let nossa = Consulta {
            canister,
            metodo: &metodo,
            arg: &arg,
            remetente: Principal::ANONIMO,
            vencimento_ns,
            nonce: nonce.as_deref(),
        };
        let oficial = EnvelopeContent::Query {
            ingress_expiry: vencimento_ns,
            sender: candid::Principal::anonymous(),
            canister_id: principal_oficial(&canister),
            method_name: metodo.clone(),
            arg: arg.clone(),
            nonce: nonce.clone(),
            sender_info: None,
        };
        assert_eq!(&nossa.id().unwrap()[..], oficial.to_request_id().as_slice());
        // O envelope daqui é um envelope que o oráculo lê, com o mesmo
        // conteúdo.
        let envelope = nossa.envelope().unwrap();
        assert!(envelope.starts_with(&[0xd9, 0xd9, 0xf7]));
        let lido: Envelope<'_> = serde_cbor::from_slice(&envelope).unwrap();
        assert!(lido.sender_pubkey.is_none() && lido.sender_sig.is_none());
        assert!(lido.sender_delegation.is_none());
        assert_eq!(lido.content.to_request_id(), oficial.to_request_id());
        // E o CBOR estrito daqui o lê também.
        assert!(cbor::ler(&envelope).is_ok());
    }
}

#[test]
fn a_leitura_de_estado_tem_o_id_do_oraculo() {
    let mut s = Sorteio::novo(22);
    for _ in 0..300 {
        let n = s.ate(4) as usize;
        let caminhos: Vec<Vec<Vec<u8>>> = (0..n)
            .map(|_| (0..s.ate(4)).map(|_| s.bytes_ate(30)).collect())
            .collect();
        let fatias: Vec<Vec<&[u8]>> = caminhos
            .iter()
            .map(|c| c.iter().map(|r| &r[..]).collect())
            .collect();
        let referencias: Vec<&[&[u8]]> = fatias.iter().map(|c| &c[..]).collect();
        let vencimento_ns = s.proximo();
        let nossa = LeituraDeEstado {
            caminhos: &referencias,
            remetente: Principal::ANONIMO,
            vencimento_ns,
        };
        let oficial = EnvelopeContent::ReadState {
            ingress_expiry: vencimento_ns,
            sender: candid::Principal::anonymous(),
            paths: caminhos
                .iter()
                .map(|c| c.iter().map(|r| r.as_slice().into()).collect())
                .collect(),
        };
        assert_eq!(&nossa.id().unwrap()[..], oficial.to_request_id().as_slice());
        let envelope = nossa.envelope().unwrap();
        let lido: Envelope<'_> = serde_cbor::from_slice(&envelope).unwrap();
        assert_eq!(lido.content.to_request_id(), oficial.to_request_id());
    }
}

#[test]
fn o_caminho_do_subnet() {
    // O pedido que o agente faz: `["subnet"]`.
    let caminhos: [&[&[u8]]; 1] = [&[b"subnet"]];
    let nossa = LeituraDeEstado {
        caminhos: &caminhos,
        remetente: Principal::ANONIMO,
        vencimento_ns: 1_792_368_240_000_000_000,
    };
    let oficial = EnvelopeContent::ReadState {
        ingress_expiry: 1_792_368_240_000_000_000,
        sender: candid::Principal::anonymous(),
        paths: vec![vec!["subnet".into()]],
    };
    assert_eq!(&nossa.id().unwrap()[..], oficial.to_request_id().as_slice());
    let lido: Envelope<'_> = serde_cbor::from_slice(&nossa.envelope().unwrap()).unwrap();
    match &*lido.content {
        EnvelopeContent::ReadState { paths, sender, .. } => {
            assert_eq!(*sender, candid::Principal::anonymous());
            assert_eq!(paths.len(), 1);
            assert_eq!(paths[0][0].as_bytes(), b"subnet");
        }
        outro => panic!("{outro:?}"),
    }
}

#[test]
fn so_o_anonimo_e_nonce_curto() {
    let canister = Principal::GERENCIAMENTO;
    let comum = Consulta {
        canister,
        metodo: "m",
        arg: b"DIDL\x00\x00",
        remetente: Principal::ANONIMO,
        vencimento_ns: 1,
        nonce: Some(&[0u8; 32]),
    };
    assert!(comum.id().is_ok());
    let longo = Consulta {
        nonce: Some(&[0u8; 33]),
        ..comum
    };
    assert_eq!(longo.id(), Err(Erro::NonceLongo));
    assert_eq!(longo.envelope(), Err(Erro::NonceLongo));
    // Um remetente com chave não sai daqui sem assinatura: o ICP-1 só
    // monta o anônimo, e não finge outro.
    let outro = Consulta {
        remetente: Principal::auto_autenticado(b"chave"),
        ..comum
    };
    assert_eq!(outro.id(), Err(Erro::RemetenteNaoAnonimo));
    assert_eq!(outro.envelope(), Err(Erro::RemetenteNaoAnonimo));
    let caminhos: [&[&[u8]]; 0] = [];
    let leitura = LeituraDeEstado {
        caminhos: &caminhos,
        remetente: Principal::GERENCIAMENTO,
        vencimento_ns: 1,
    };
    assert_eq!(leitura.id(), Err(Erro::RemetenteNaoAnonimo));
    assert!(Erro::NonceLongo.to_string().is_ascii());
    assert!(Erro::RemetenteNaoAnonimo.to_string().is_ascii());
}

#[test]
fn o_nonce_muda_o_id() {
    let base = Consulta {
        canister: Principal::GERENCIAMENTO,
        metodo: "ola",
        arg: b"DIDL\x00\x00",
        remetente: Principal::ANONIMO,
        vencimento_ns: 7,
        nonce: Some(&[1; 16]),
    };
    let outro = Consulta {
        nonce: Some(&[2; 16]),
        ..base
    };
    let sem = Consulta {
        nonce: None,
        ..base
    };
    assert_ne!(base.id().unwrap(), outro.id().unwrap());
    assert_ne!(base.id().unwrap(), sem.id().unwrap());
    let _: Cow<'_, EnvelopeContent> = Cow::Owned(EnvelopeContent::Query {
        ingress_expiry: 7,
        sender: candid::Principal::anonymous(),
        canister_id: candid::Principal::management_canister(),
        method_name: "ola".into(),
        arg: b"DIDL\x00\x00".to_vec(),
        nonce: None,
        sender_info: None,
    });
    assert_eq!(
        &sem.id().unwrap()[..],
        to_request_id(&EnvelopeContent::Query {
            ingress_expiry: 7,
            sender: candid::Principal::anonymous(),
            canister_id: candid::Principal::management_canister(),
            method_name: "ola".into(),
            arg: b"DIDL\x00\x00".to_vec(),
            nonce: None,
            sender_info: None,
        })
        .unwrap()
        .as_slice()
    );
}
