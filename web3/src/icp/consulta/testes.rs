//! A resposta da consulta contra a bancada e o `ic-transport-types`.

use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use ed25519_dalek::Signer;
use ic_transport_types::{QueryResponse, RejectCode, RejectResponse, ReplyResponse, RequestId};

use super::*;
use crate::icp::bancada::{self, AGORA_NS, Ic, chave_de_no};
use crate::icp::certificado;
use crate::icp::pedido::Consulta;

fn pedido(ic: &Ic, nonce: &[u8]) -> Hash {
    Consulta {
        canister: ic.canister,
        metodo: "ola",
        arg: b"DIDL\x00\x00",
        remetente: Principal::ANONIMO,
        vencimento_ns: AGORA_NS + 4 * crate::icp::MINUTO_NS,
        nonce: Some(nonce),
    }
    .id()
    .unwrap()
}

/// Lê, confere o certificado e confere a resposta.
fn conferir(ic: &Ic, corpo: &[u8], id: &Hash, agora_ns: u64) -> Result<Conferida, Erro> {
    let doc = ic.certificado(AGORA_NS);
    let cert = Certificado::ler(&doc).unwrap();
    let autoridade =
        certificado::verificar(&cert, &ic.raiz_de_confianca(), &ic.canister, AGORA_NS).unwrap();
    let resposta = Resposta::ler(corpo)?;
    verificar(&resposta, id, &cert, &autoridade, agora_ns)
}

#[test]
fn a_resposta_assinada_vale() {
    let ic = Ic::novo();
    let id = pedido(&ic, &[7; 16]);
    let arg = b"DIDL\x00\x01\x71\x03ola";
    for quem in [&[0usize][..], &[1, 3], &[0, 1, 2, 3]] {
        let corpo = ic.resposta_de_consulta(id, arg, AGORA_NS, quem);
        let c = conferir(&ic, &corpo, &id, AGORA_NS).unwrap();
        assert_eq!(
            c,
            Conferida {
                assinaturas: quem.len(),
                nos: 4
            }
        );
        let r = Resposta::ler(&corpo).unwrap();
        assert_eq!(r.resultado, Resultado::Respondida { arg });
    }
}

#[test]
fn o_assinavel_e_o_do_oraculo() {
    let ic = Ic::novo();
    let id = pedido(&ic, &[1; 8]);
    let respondida = QueryResponse::Replied {
        reply: ReplyResponse {
            arg: b"DIDL\x00\x00".to_vec(),
        },
        signatures: Vec::new(),
    };
    let recusada = QueryResponse::Rejected {
        reject: RejectResponse {
            reject_code: RejectCode::CanisterReject,
            reject_message: "nao".into(),
            error_code: Some("IC0406".into()),
        },
        signatures: Vec::new(),
    };
    for oficial in [respondida, recusada] {
        let corpo = bancada::cbor(&oficial);
        let nossa = Resposta::ler(&corpo).unwrap();
        for t in [0, 1, AGORA_NS, u64::MAX] {
            assert_eq!(
                &nossa.assinavel(&id, t)[..],
                &oficial.signable(RequestId::new(&id), t)[..]
            );
        }
    }
}

#[test]
fn a_recusa_assinada_tambem_e_verificada() {
    let ic = Ic::novo();
    let id = pedido(&ic, &[2; 8]);
    let mut oficial = QueryResponse::Rejected {
        reject: RejectResponse {
            reject_code: RejectCode::DestinationInvalid,
            reject_message: "canister nao existe".into(),
            error_code: Some("IC0301".into()),
        },
        signatures: Vec::new(),
    };
    ic.assinar_resposta(&mut oficial, id, AGORA_NS, &[2]);
    let corpo = bancada::cbor(&oficial);
    assert!(conferir(&ic, &corpo, &id, AGORA_NS).is_ok());
    assert_eq!(
        Resposta::ler(&corpo).unwrap().resultado,
        Resultado::Recusada {
            codigo: 3,
            mensagem: "canister nao existe",
            erro: Some("IC0301"),
        }
    );
}

/// Uma recusa sem `error_code`, escrita à mão: o `ic-transport-types`
/// escreve `null` no lugar.
fn recusa_sem_codigo(ic: &Ic, id: Hash, assinar_com: Option<&[u8]>) -> Vec<u8> {
    let mut e = crate::icp::cbor::Escritor::novo();
    e.autodescrita();
    e.mapa(4);
    e.texto("status");
    e.texto("rejected");
    e.texto("reject_code");
    e.nat(5);
    e.texto("reject_message");
    e.texto("trap");
    e.texto("signatures");
    e.lista(1);
    e.mapa(3);
    e.texto("timestamp");
    e.nat(AGORA_NS);
    let resposta = Resposta {
        resultado: Resultado::Recusada {
            codigo: 5,
            mensagem: "trap",
            erro: None,
        },
        resumo_do_reply: None,
        assinaturas: Vec::new(),
    };
    let assinavel = match assinar_com {
        Some(outro) => outro.to_vec(),
        None => resposta.assinavel(&id, AGORA_NS).to_vec(),
    };
    e.texto("signature");
    e.bytes(&ic.nos[0].1.sign(&assinavel).to_bytes());
    e.texto("identity");
    e.bytes(ic.nos[0].0.bytes());
    e.terminar()
}

#[test]
fn a_recusa_sem_codigo_de_erro() {
    let ic = Ic::novo();
    let id = pedido(&ic, &[3; 8]);
    let corpo = recusa_sem_codigo(&ic, id, None);
    assert!(conferir(&ic, &corpo, &id, AGORA_NS).is_ok());
    // O que o nó assina sem o campo é o do oráculo sem ele.
    let oficial = QueryResponse::Rejected {
        reject: RejectResponse {
            reject_code: RejectCode::CanisterError,
            reject_message: "trap".into(),
            error_code: None,
        },
        signatures: Vec::new(),
    };
    let assinavel = oficial.signable(RequestId::new(&id), AGORA_NS);
    let corpo = recusa_sem_codigo(&ic, id, Some(&assinavel));
    assert!(conferir(&ic, &corpo, &id, AGORA_NS).is_ok());
    // O `null` que o `ic-transport-types` escreveria não é texto: o CBOR
    // estrito o recusa.
    let corpo = bancada::cbor(&oficial);
    assert_eq!(
        Resposta::ler(&corpo),
        Err(Erro::Cbor(crate::icp::cbor::Erro::TipoProibido))
    );
}

#[test]
fn sem_assinatura_ou_com_assinaturas_demais() {
    let ic = Ic::novo();
    let id = pedido(&ic, &[4; 8]);
    let corpo = ic.resposta_de_consulta(id, b"DIDL\x00\x00", AGORA_NS, &[]);
    assert_eq!(
        conferir(&ic, &corpo, &id, AGORA_NS),
        Err(Erro::SemAssinatura)
    );
    let corpo = ic.resposta_de_consulta(id, b"DIDL\x00\x00", AGORA_NS, &[0, 1, 2, 3, 0]);
    assert_eq!(
        conferir(&ic, &corpo, &id, AGORA_NS),
        Err(Erro::AssinaturasDemais {
            assinaturas: 5,
            nos: 4
        })
    );
}

#[test]
fn a_assinatura_de_um_no_de_fora() {
    let ic = Ic::novo();
    let id = pedido(&ic, &[5; 8]);
    // Um IC de outra sub-rede, com outros nós, assina direitinho — mas o
    // certificado não os põe na sub-rede do canister.
    let mut outro = Ic::novo();
    outro.nos = vec![(
        Principal::auto_autenticado(&bancada::der_ed25519(&chave_de_no(99))),
        chave_de_no(99),
    )];
    let corpo = outro.resposta_de_consulta(id, b"DIDL\x00\x00", AGORA_NS, &[0]);
    assert_eq!(
        conferir(&ic, &corpo, &id, AGORA_NS),
        Err(Erro::NoDeFora(outro.nos[0].0))
    );
    // Um nó da sub-rede com a chave de outro: a identidade é dele, a
    // assinatura não.
    let mut trocado = Ic::novo();
    trocado.nos[0].1 = chave_de_no(99);
    let corpo = trocado.resposta_de_consulta(id, b"DIDL\x00\x00", AGORA_NS, &[0]);
    assert_eq!(
        conferir(&ic, &corpo, &id, AGORA_NS),
        Err(Erro::AssinaturaInvalida(ic.nos[0].0))
    );
}

#[test]
fn a_assinatura_presa_ao_pedido_e_a_resposta() {
    let ic = Ic::novo();
    let id = pedido(&ic, &[6; 8]);
    let outro_id = pedido(&ic, &[7; 8]);
    // A resposta assinada para outro pedido — outro nonce — não vale para
    // este.
    let corpo = ic.resposta_de_consulta(outro_id, b"DIDL\x00\x00", AGORA_NS, &[0]);
    assert_eq!(
        conferir(&ic, &corpo, &id, AGORA_NS),
        Err(Erro::AssinaturaInvalida(ic.nos[0].0))
    );
    // A resposta mexida depois de assinada.
    let assinada = ic.resposta_de_consulta(id, b"DIDL\x00\x01\x71\x03ola", AGORA_NS, &[0]);
    let mut mexida = assinada.clone();
    let i = mexida.windows(3).position(|w| w == b"ola").unwrap();
    mexida[i] = b'O';
    assert_eq!(
        conferir(&ic, &mexida, &id, AGORA_NS),
        Err(Erro::AssinaturaInvalida(ic.nos[0].0))
    );
    // O carimbo trocado, ainda dentro da tolerância: a assinatura é sobre
    // ele também.
    let mut oficial: QueryResponse = serde_cbor::from_slice(&assinada).unwrap();
    if let QueryResponse::Replied { signatures, .. } = &mut oficial {
        signatures[0].timestamp += 1;
    }
    let corpo = bancada::cbor(&oficial);
    assert_eq!(
        conferir(&ic, &corpo, &id, AGORA_NS),
        Err(Erro::AssinaturaInvalida(ic.nos[0].0))
    );
}

#[test]
fn o_carimbo_das_assinaturas() {
    let ic = Ic::novo();
    let id = pedido(&ic, &[8; 8]);
    let tol = crate::icp::TOLERANCIA_NS;
    for (carimbo, esperado) in [
        (AGORA_NS - tol, Ok(())),
        (AGORA_NS + tol, Ok(())),
        (
            AGORA_NS - tol - 1,
            Err(Erro::AssinaturaVelha {
                tempo_ns: AGORA_NS - tol - 1,
                agora_ns: AGORA_NS,
            }),
        ),
        (
            AGORA_NS + tol + 1,
            Err(Erro::AssinaturaDoFuturo {
                tempo_ns: AGORA_NS + tol + 1,
                agora_ns: AGORA_NS,
            }),
        ),
    ] {
        let corpo = ic.resposta_de_consulta(id, b"DIDL\x00\x00", carimbo, &[1]);
        assert_eq!(conferir(&ic, &corpo, &id, AGORA_NS).map(|_| ()), esperado);
    }
}

#[test]
fn o_reply_inteiro_entra_no_que_se_assina() {
    // **Especificação**: o nó assina `reply: R.reply` — o mapa inteiro.
    // Hoje o IC só põe o `arg`; um campo a mais entra na conta.
    let ic = Ic::novo();
    let id = pedido(&ic, &[9; 8]);
    let monta = |assinavel: &[u8]| {
        let mut e = crate::icp::cbor::Escritor::novo();
        e.mapa(3);
        e.texto("status");
        e.texto("replied");
        e.texto("reply");
        e.mapa(2);
        e.texto("arg");
        e.bytes(b"DIDL\x00\x00");
        e.texto("extra");
        e.nat(1);
        e.texto("signatures");
        e.lista(1);
        e.mapa(3);
        e.texto("timestamp");
        e.nat(AGORA_NS);
        e.texto("signature");
        e.bytes(&ic.nos[0].1.sign(assinavel).to_bytes());
        e.texto("identity");
        e.bytes(ic.nos[0].0.bytes());
        e.terminar()
    };
    // Assinado sobre o mapa inteiro: vale.
    let provisoria = monta(&[]);
    let assinavel = Resposta::ler(&provisoria).unwrap().assinavel(&id, AGORA_NS);
    assert!(conferir(&ic, &monta(&assinavel), &id, AGORA_NS).is_ok());
    // Assinado só sobre o `arg`, sem o campo a mais: não vale.
    let so_arg = QueryResponse::Replied {
        reply: ReplyResponse {
            arg: b"DIDL\x00\x00".to_vec(),
        },
        signatures: Vec::new(),
    }
    .signable(RequestId::new(&id), AGORA_NS);
    assert_eq!(
        conferir(&ic, &monta(&so_arg), &id, AGORA_NS),
        Err(Erro::AssinaturaInvalida(ic.nos[0].0))
    );
}

#[test]
fn respostas_fora_da_forma() {
    let doc = |f: &dyn Fn(&mut crate::icp::cbor::Escritor)| {
        let mut e = crate::icp::cbor::Escritor::novo();
        f(&mut e);
        e.terminar()
    };
    let casos: Vec<Vec<u8>> = vec![
        doc(&|e| e.nat(1)),
        doc(&|e| {
            e.mapa(1);
            e.texto("reply");
            e.mapa(0);
        }),
        doc(&|e| {
            e.mapa(1);
            e.texto("status");
            e.texto("processing");
        }),
        doc(&|e| {
            e.mapa(2);
            e.texto("status");
            e.texto("replied");
            e.texto("reply");
            e.bytes(b"x");
        }),
        doc(&|e| {
            e.mapa(2);
            e.texto("status");
            e.texto("replied");
            e.texto("reply");
            e.mapa(1);
            e.texto("arg");
            e.texto("nao e bytes");
        }),
        doc(&|e| {
            e.mapa(3);
            e.texto("status");
            e.texto("rejected");
            e.texto("reject_code");
            e.texto("4");
            e.texto("reject_message");
            e.texto("x");
        }),
        doc(&|e| {
            e.mapa(4);
            e.texto("status");
            e.texto("rejected");
            e.texto("reject_code");
            e.nat(4);
            e.texto("reject_message");
            e.texto("x");
            e.texto("error_code");
            e.nat(7);
        }),
        doc(&|e| {
            e.mapa(3);
            e.texto("status");
            e.texto("replied");
            e.texto("reply");
            e.mapa(1);
            e.texto("arg");
            e.bytes(b"");
            e.texto("signatures");
            e.mapa(0);
        }),
        doc(&|e| {
            e.mapa(3);
            e.texto("status");
            e.texto("replied");
            e.texto("reply");
            e.mapa(1);
            e.texto("arg");
            e.bytes(b"");
            e.texto("signatures");
            e.lista(1);
            e.mapa(2);
            e.texto("timestamp");
            e.nat(1);
            e.texto("signature");
            e.bytes(&[0; 64]);
        }),
        doc(&|e| {
            e.mapa(3);
            e.texto("status");
            e.texto("replied");
            e.texto("reply");
            e.mapa(1);
            e.texto("arg");
            e.bytes(b"");
            e.texto("signatures");
            e.lista(1);
            e.mapa(3);
            e.texto("timestamp");
            e.nat(1);
            e.texto("signature");
            e.bytes(&[0; 64]);
            e.texto("identity");
            e.bytes(&[0; 30]);
        }),
    ];
    for corpo in casos {
        assert_eq!(Resposta::ler(&corpo), Err(Erro::Forma), "{corpo:02x?}");
    }
    assert!(matches!(Resposta::ler(&[0xff]), Err(Erro::Cbor(_))));
}

#[test]
fn as_mensagens_sao_ascii() {
    let p = Principal::ANONIMO;
    for e in [
        Erro::Forma,
        Erro::SemAssinatura,
        Erro::AssinaturasDemais {
            assinaturas: 2,
            nos: 1,
        },
        Erro::AssinaturaVelha {
            tempo_ns: 0,
            agora_ns: 1 << 40,
        },
        Erro::AssinaturaDoFuturo {
            tempo_ns: 1 << 40,
            agora_ns: 0,
        },
        Erro::NoDeFora(p),
        Erro::AssinaturaInvalida(p),
        Erro::Certificado(certificado::Erro::ChaveDoNo),
    ] {
        let texto: String = e.to_string();
        assert!(texto.is_ascii(), "{texto}");
    }
}
