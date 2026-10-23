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
    // A consulta sem assinatura é só do anônimo: um remetente com chave
    // não sai daqui, e não se finge outro.
    let outro = Consulta {
        remetente: Principal::auto_autenticado(b"chave"),
        ..comum
    };
    assert_eq!(outro.id(), Err(Erro::RemetenteNaoAnonimo));
    assert_eq!(outro.envelope(), Err(Erro::RemetenteNaoAnonimo));
    // A leitura de estado de outro remetente tem id — é o que se assina —,
    // e sem assinatura não sai.
    let caminhos: [&[&[u8]]; 0] = [];
    let leitura = LeituraDeEstado {
        caminhos: &caminhos,
        remetente: Principal::GERENCIAMENTO,
        vencimento_ns: 1,
    };
    assert!(leitura.id().is_ok());
    assert_eq!(leitura.envelope(), Err(Erro::RemetenteNaoAnonimo));
    assert!(Erro::NonceLongo.to_string().is_ascii());
    assert!(Erro::RemetenteNaoAnonimo.to_string().is_ascii());
    assert!(Erro::RemetenteNaoEDaChave.to_string().is_ascii());
}

/// Uma chave Ed25519 de teste e a pública dela em DER.
fn chave(semente: u8) -> (ed25519_dalek::SigningKey, [u8; 44]) {
    let privada = ed25519_dalek::SigningKey::from_bytes(&[semente; 32]);
    let der = der_ed25519(privada.verifying_key().as_bytes());
    (privada, der)
}

/// O DER da pública e o que se assina são os do `ic-ed25519` e do
/// `ic-transport-types`; e o Principal da chave é o do `ic_principal`.
#[test]
fn a_chave_e_o_que_se_assina() {
    let mut s = Sorteio::novo(23);
    for _ in 0..50 {
        let (privada, der) = chave(s.proximo() as u8);
        let publica = privada.verifying_key().to_bytes();
        let oficial = ic_ed25519::PublicKey::deserialize_raw(&publica).unwrap();
        assert_eq!(der.to_vec(), oficial.serialize_rfc8410_der());
        assert_eq!(
            Principal::auto_autenticado(&der).bytes(),
            candid::Principal::self_authenticating(der).as_slice()
        );
        let id: [u8; 32] = s.bytes(32).try_into().unwrap();
        assert_eq!(
            assinavel(&id).to_vec(),
            ic_transport_types::RequestId::new(&id).signable()
        );
    }
}

/// A chamada: o id do oráculo — do anônimo e de quem tem chave —, e o
/// envelope assinado que ele lê, com a chave e a assinatura no lugar, e a
/// assinatura conferida pelo `ic-ed25519` sobre o id dele.
#[test]
fn a_chamada_tem_o_id_e_o_envelope_do_oraculo() {
    let mut s = Sorteio::novo(24);
    for i in 0..300 {
        let canister = Principal::de_bytes(&s.bytes_ate(29)).unwrap();
        let metodo: String = (0..s.ate(20))
            .map(|_| char::from(b'a' + s.ate(26) as u8))
            .collect();
        let arg = s.bytes_ate(200);
        let nonce = if i % 3 == 0 {
            None
        } else {
            Some(s.bytes_ate(32))
        };
        let vencimento_ns = s.proximo();
        let (privada, der) = chave(i as u8);
        let assinada = i % 2 == 0;
        let remetente = if assinada {
            Principal::auto_autenticado(&der)
        } else {
            Principal::ANONIMO
        };
        let nossa = Chamada {
            canister,
            metodo: &metodo,
            arg: &arg,
            remetente,
            vencimento_ns,
            nonce: nonce.as_deref(),
        };
        let oficial = EnvelopeContent::Call {
            nonce: nonce.clone(),
            ingress_expiry: vencimento_ns,
            sender: candid::Principal::from_slice(remetente.bytes()),
            canister_id: principal_oficial(&canister),
            method_name: metodo.clone(),
            arg: arg.clone(),
            sender_info: None,
        };
        let id = nossa.id().unwrap();
        assert_eq!(&id[..], oficial.to_request_id().as_slice());
        let assinatura = ed25519_dalek::Signer::sign(&privada, &assinavel(&id)).to_bytes();
        let autenticacao = Autenticacao {
            chave_der: &der,
            assinatura: &assinatura,
        };
        let envelope = nossa.envelope(assinada.then_some(&autenticacao)).unwrap();
        let lido: Envelope<'_> = serde_cbor::from_slice(&envelope).unwrap();
        assert_eq!(lido.content.to_request_id(), oficial.to_request_id());
        assert!(lido.sender_delegation.is_none());
        if assinada {
            assert_eq!(lido.sender_pubkey.as_deref(), Some(&der[..]));
            assert_eq!(lido.sender_sig.as_deref(), Some(&assinatura[..]));
            let publica = ic_ed25519::PublicKey::deserialize_rfc8410_der(&der).unwrap();
            assert!(
                publica
                    .verify_signature(&lido.content.to_request_id().signable(), &assinatura)
                    .is_ok()
            );
        } else {
            assert!(lido.sender_pubkey.is_none() && lido.sender_sig.is_none());
        }
        assert!(cbor::ler(&envelope).is_ok());
    }
}

/// O remetente é o da chave, ou o anônimo sem ela — na chamada e na
/// leitura de estado; e a leitura assinada é a que o oráculo lê.
#[test]
fn o_remetente_e_o_da_chave() {
    let (privada, der) = chave(1);
    let (_, outra) = chave(2);
    let assinatura = [0u8; 64];
    let a = Autenticacao {
        chave_der: &der,
        assinatura: &assinatura,
    };
    let base = Chamada {
        canister: Principal::GERENCIAMENTO,
        metodo: "contar",
        arg: b"DIDL\x00\x00",
        remetente: Principal::auto_autenticado(&der),
        vencimento_ns: 1,
        nonce: Some(&[1; 8]),
    };
    assert!(base.envelope(Some(&a)).is_ok());
    assert_eq!(base.envelope(None), Err(Erro::RemetenteNaoAnonimo));
    let de_outra = Chamada {
        remetente: Principal::auto_autenticado(&outra),
        ..base
    };
    assert_eq!(de_outra.envelope(Some(&a)), Err(Erro::RemetenteNaoEDaChave));
    let anonima = Chamada {
        remetente: Principal::ANONIMO,
        ..base
    };
    assert_eq!(anonima.envelope(Some(&a)), Err(Erro::RemetenteNaoEDaChave));
    assert!(anonima.envelope(None).is_ok());
    let longa = Chamada {
        nonce: Some(&[0; 33]),
        ..base
    };
    assert_eq!(longa.id(), Err(Erro::NonceLongo));
    assert_eq!(longa.envelope(Some(&a)), Err(Erro::NonceLongo));

    // A leitura da situação de uma chamada: `["request_status", id]`,
    // assinada pela mesma chave.
    let id = base.id().unwrap();
    let caminhos: [&[&[u8]]; 1] = [&[b"request_status", &id]];
    let leitura = LeituraDeEstado {
        caminhos: &caminhos,
        remetente: Principal::auto_autenticado(&der),
        vencimento_ns: 9,
    };
    let oficial = EnvelopeContent::ReadState {
        ingress_expiry: 9,
        sender: candid::Principal::self_authenticating(der),
        paths: vec![vec!["request_status".into(), id.to_vec().into()]],
    };
    let id_da_leitura = leitura.id().unwrap();
    assert_eq!(&id_da_leitura[..], oficial.to_request_id().as_slice());
    let assinatura = ed25519_dalek::Signer::sign(&privada, &assinavel(&id_da_leitura)).to_bytes();
    let a = Autenticacao {
        chave_der: &der,
        assinatura: &assinatura,
    };
    let lido: Envelope<'_> =
        serde_cbor::from_slice(&leitura.envelope_assinado(Some(&a)).unwrap()).unwrap();
    assert_eq!(lido.content.to_request_id(), oficial.to_request_id());
    assert_eq!(lido.sender_sig.as_deref(), Some(&assinatura[..]));
    assert_eq!(leitura.envelope(), Err(Erro::RemetenteNaoAnonimo));
    let b = Autenticacao {
        chave_der: &outra,
        assinatura: &assinatura,
    };
    assert_eq!(
        leitura.envelope_assinado(Some(&b)),
        Err(Erro::RemetenteNaoEDaChave)
    );
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

/// A consulta assinada: o id do oráculo, com o remetente da chave, e o
/// envelope assinado que ele lê, com a chave e a assinatura no lugar, e a
/// assinatura conferida pelo `ic-ed25519` sobre o id dele.
#[test]
fn a_consulta_assinada_tem_o_id_e_o_envelope_do_oraculo() {
    let mut s = Sorteio::novo(25);
    for i in 0..300 {
        let canister = Principal::de_bytes(&s.bytes_ate(29)).unwrap();
        let metodo: String = (0..s.ate(20))
            .map(|_| char::from(b'a' + s.ate(26) as u8))
            .collect();
        let arg = s.bytes_ate(200);
        let nonce = if i % 3 == 0 {
            None
        } else {
            Some(s.bytes_ate(32))
        };
        let vencimento_ns = s.proximo();
        let (privada, der) = chave(i as u8);
        let nossa = Consulta {
            canister,
            metodo: &metodo,
            arg: &arg,
            remetente: Principal::auto_autenticado(&der),
            vencimento_ns,
            nonce: nonce.as_deref(),
        };
        let oficial = EnvelopeContent::Query {
            ingress_expiry: vencimento_ns,
            sender: candid::Principal::self_authenticating(der),
            canister_id: principal_oficial(&canister),
            method_name: metodo.clone(),
            arg: arg.clone(),
            nonce: nonce.clone(),
            sender_info: None,
        };
        let id = nossa.id_assinada(&der).unwrap();
        assert_eq!(&id[..], oficial.to_request_id().as_slice());
        let assinatura = ed25519_dalek::Signer::sign(&privada, &assinavel(&id)).to_bytes();
        let autenticacao = Autenticacao {
            chave_der: &der,
            assinatura: &assinatura,
        };
        let envelope = nossa.envelope_assinado(&autenticacao).unwrap();
        assert!(envelope.starts_with(&[0xd9, 0xd9, 0xf7]));
        let lido: Envelope<'_> = serde_cbor::from_slice(&envelope).unwrap();
        assert_eq!(lido.content.to_request_id(), oficial.to_request_id());
        assert!(lido.sender_delegation.is_none());
        assert_eq!(lido.sender_pubkey.as_deref(), Some(&der[..]));
        assert_eq!(lido.sender_sig.as_deref(), Some(&assinatura[..]));
        let publica = ic_ed25519::PublicKey::deserialize_rfc8410_der(&der).unwrap();
        assert!(
            publica
                .verify_signature(&lido.content.to_request_id().signable(), &assinatura)
                .is_ok()
        );
        assert!(cbor::ler(&envelope).is_ok());
    }
}

/// O remetente da consulta assinada é o da chave: outro Principal, ou o
/// anônimo, não tem id assinado nem envelope; a consulta sem assinatura
/// continua só do anônimo; e o id leva o remetente — a mesma consulta, do
/// anônimo e de cada chave, são pedidos diferentes.
#[test]
fn o_remetente_da_consulta_assinada_e_o_da_chave() {
    let (_, der) = chave(1);
    let (_, outra) = chave(2);
    let assinatura = [0u8; 64];
    let a = Autenticacao {
        chave_der: &der,
        assinatura: &assinatura,
    };
    let b = Autenticacao {
        chave_der: &outra,
        assinatura: &assinatura,
    };
    let base = Consulta {
        canister: Principal::GERENCIAMENTO,
        metodo: "quem_consulta",
        arg: b"DIDL\x00\x00",
        remetente: Principal::auto_autenticado(&der),
        vencimento_ns: 1,
        nonce: Some(&[1; 8]),
    };
    assert!(base.id_assinada(&der).is_ok());
    assert!(base.envelope_assinado(&a).is_ok());
    // A chave de outro não assina por este remetente.
    assert_eq!(base.id_assinada(&outra), Err(Erro::RemetenteNaoEDaChave));
    assert_eq!(base.envelope_assinado(&b), Err(Erro::RemetenteNaoEDaChave));
    // Sem assinatura, um remetente com chave não sai.
    assert_eq!(base.id(), Err(Erro::RemetenteNaoAnonimo));
    assert_eq!(base.envelope(), Err(Erro::RemetenteNaoAnonimo));
    // O anônimo não vai assinado por chave nenhuma.
    let anonima = Consulta {
        remetente: Principal::ANONIMO,
        ..base
    };
    assert_eq!(anonima.id_assinada(&der), Err(Erro::RemetenteNaoEDaChave));
    assert_eq!(
        anonima.envelope_assinado(&a),
        Err(Erro::RemetenteNaoEDaChave)
    );
    assert!(anonima.envelope().is_ok());
    // O nonce longo também não.
    let longa = Consulta {
        nonce: Some(&[0; 33]),
        ..base
    };
    assert_eq!(longa.id_assinada(&der), Err(Erro::NonceLongo));
    assert_eq!(longa.envelope_assinado(&a), Err(Erro::NonceLongo));
    // Três remetentes, três pedidos.
    let de_outra = Consulta {
        remetente: Principal::auto_autenticado(&outra),
        ..base
    };
    let ids = [
        anonima.id().unwrap(),
        base.id_assinada(&der).unwrap(),
        de_outra.id_assinada(&outra).unwrap(),
    ];
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[0], ids[2]);
    assert_ne!(ids[1], ids[2]);
    // E o envelope assinado leva o conteúdo da consulta, não o de uma
    // chamada: o mesmo id que a chamada teria é outro.
    let chamada = Chamada {
        canister: base.canister,
        metodo: base.metodo,
        arg: base.arg,
        remetente: base.remetente,
        vencimento_ns: base.vencimento_ns,
        nonce: base.nonce,
    };
    assert_ne!(chamada.id().unwrap(), ids[1]);
}
