//! A situação de uma chamada: o corpo da chamada contra o que o
//! `ic-transport-types` escreve, e o `request_status` contra árvores do
//! `ic-certification`, nos certificados da bancada.

use std::string::{String, ToString};
use std::vec::Vec;

use ic_certification::hash_tree::{fork, label, leaf, pruned};
use ic_transport_types::{RejectCode, RejectResponse, TransportCallResponse};

use super::*;
use crate::icp::bancada::{AGORA_NS, Ic, cbor, certificado_assinado, nat};

fn certificado(id: &[u8; 32], campos: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    Ic::novo().certificado_da_situacao(id, campos, AGORA_NS, false)
}

fn situacao_de(id: &[u8; 32], campos: &[(&[u8], Vec<u8>)]) -> Result<String, Erro> {
    let bytes = certificado(id, campos);
    let cert = Certificado::ler(&bytes).unwrap();
    ler(&cert, id).map(|s| std::format!("{s:?}"))
}

/// Cada `status`, e os campos de cada um.
#[test]
fn cada_situacao() {
    let id = [9u8; 32];
    for (status, nome) in [
        ("received", "received"),
        ("processing", "processing"),
        ("done", "done"),
    ] {
        let bytes = certificado(&id, &[(b"status", status.as_bytes().to_vec())]);
        let cert = Certificado::ler(&bytes).unwrap();
        let s = ler(&cert, &id).unwrap();
        assert_eq!(s.nome(), nome);
        assert_eq!(s.final_(), status == "done");
    }
    let bytes = certificado(
        &id,
        &[
            (b"status", b"replied".to_vec()),
            (b"reply", b"DIDL\x00\x00".to_vec()),
        ],
    );
    let cert = Certificado::ler(&bytes).unwrap();
    assert_eq!(ler(&cert, &id), Ok(Situacao::Respondida(b"DIDL\x00\x00")));
    // A recusa: o código em LEB128 — também o de mais de um byte —, a
    // mensagem e o erro, que pode faltar.
    for (codigo, erro) in [(4u64, Some("IC0503")), (300, None)] {
        let mut campos: Vec<(&[u8], Vec<u8>)> = std::vec![
            (b"status", b"rejected".to_vec()),
            (b"reject_code", nat(codigo)),
            (b"reject_message", b"nao".to_vec()),
        ];
        if let Some(e) = erro {
            campos.push((b"error_code", e.as_bytes().to_vec()));
        }
        let bytes = certificado(&id, &campos);
        let cert = Certificado::ler(&bytes).unwrap();
        assert_eq!(
            ler(&cert, &id),
            Ok(Situacao::Recusada {
                codigo,
                mensagem: "nao",
                erro,
            })
        );
    }
    // Outro id: desconhecida — o certificado prova que não está.
    let bytes = certificado(&id, &[(b"status", b"replied".to_vec())]);
    let cert = Certificado::ler(&bytes).unwrap();
    assert_eq!(ler(&cert, &[8; 32]), Ok(Situacao::Desconhecida));
    assert_eq!(Situacao::Desconhecida.nome(), "unknown");
}

/// Fora da forma: o status que não é dos cinco, a resposta sem `reply`,
/// a recusa sem mensagem, o código que não é LEB128, o texto que não é
/// UTF-8.
#[test]
fn fora_da_forma() {
    let id = [3u8; 32];
    for campos in [
        std::vec![(b"status".as_slice(), b"pending".to_vec())],
        std::vec![(b"status".as_slice(), b"Replied".to_vec())],
        std::vec![(b"status".as_slice(), b"replied".to_vec())],
        std::vec![
            (b"status".as_slice(), b"rejected".to_vec()),
            (b"reject_code".as_slice(), nat(4)),
        ],
        std::vec![
            (b"status".as_slice(), b"rejected".to_vec()),
            (b"reject_code".as_slice(), std::vec![0x80]),
            (b"reject_message".as_slice(), b"x".to_vec()),
        ],
        std::vec![
            (b"status".as_slice(), b"rejected".to_vec()),
            (b"reject_code".as_slice(), nat(4)),
            (b"reject_message".as_slice(), std::vec![0xff]),
        ],
        std::vec![
            (b"status".as_slice(), b"rejected".to_vec()),
            (b"reject_code".as_slice(), nat(4)),
            (b"reject_message".as_slice(), b"x".to_vec()),
            (b"error_code".as_slice(), std::vec![0xfe]),
        ],
    ] {
        assert_eq!(situacao_de(&id, &campos), Err(Erro::Forma), "{campos:?}");
    }
    assert!(Erro::Forma.to_string().is_ascii() && Erro::Podada.to_string().is_ascii());
}

/// O `request_status` num galho podado: não se sabe — nem que está, nem
/// que não está.
#[test]
fn podada() {
    let ic = Ic::novo();
    let id = [5u8; 32];
    let arvore = fork(
        label(b"request_status".to_vec(), pruned([7u8; 32])),
        label(b"time".to_vec(), leaf(nat(AGORA_NS))),
    );
    let bytes = certificado_assinado(
        arvore,
        &ic.sub_rede,
        Some((ic.id_da_sub_rede.bytes().to_vec(), ic.delegacao(AGORA_NS))),
    );
    let cert = Certificado::ler(&bytes).unwrap();
    assert_eq!(ler(&cert, &id), Err(Erro::Podada));
}

/// O corpo da chamada síncrona, como o `ic-transport-types` o escreve: o
/// certificado, e a recusa não replicada com e sem `error_code`.
#[test]
fn o_corpo_da_chamada() {
    let corpo = cbor(&TransportCallResponse::Replied {
        certificate: std::vec![1, 2, 3],
    });
    assert_eq!(ler_corpo(&corpo), Ok(Corpo::Certificada(&[1, 2, 3])));
    let recusa = |erro: Option<String>| {
        TransportCallResponse::NonReplicatedRejection(RejectResponse {
            reject_code: RejectCode::SysTransient,
            reject_message: String::from("ocupado"),
            error_code: erro,
        })
    };
    let lida = |erro: Option<String>| {
        Ok(Corpo::RecusaNaoReplicada {
            codigo: 2,
            mensagem: String::from("ocupado"),
            erro,
        })
    };
    let erro = Some(String::from("IC0406"));
    assert_eq!(ler_corpo(&cbor(&recusa(erro.clone()))), lida(erro));
    // Sem `error_code`: a especificação o tem como opcional — a chave
    // ausente. O `ic-transport-types` escreve `null` no lugar dela, que o
    // IC não manda, e que este lado recusa: o subconjunto não tem valor
    // simples. A forma da especificação, escrita à mão, o oráculo lê como a
    // recusa sem código, e este lado também.
    #[derive(serde::Serialize)]
    struct SemCodigo {
        status: &'static str,
        reject_code: u8,
        reject_message: &'static str,
    }
    let corpo = cbor(&SemCodigo {
        status: "non_replicated_rejection",
        reject_code: 2,
        reject_message: "ocupado",
    });
    let TransportCallResponse::NonReplicatedRejection(oraculo) =
        serde_cbor::from_slice::<TransportCallResponse>(&corpo).unwrap()
    else {
        panic!("o oraculo nao leu a recusa sem codigo");
    };
    assert_eq!(oraculo.error_code, None);
    assert_eq!(oraculo.reject_code, RejectCode::SysTransient);
    assert_eq!(ler_corpo(&corpo), lida(None));
    assert!(matches!(
        ler_corpo(&cbor(&recusa(None))),
        Err(ErroDoCorpo::Cbor(_))
    ));
    // Fora da forma: outro status, o certificado que falta, o que não é
    // CBOR.
    #[derive(serde::Serialize)]
    struct Status {
        status: &'static str,
    }
    for status in ["accepted", "replied", "non_replicated_rejection", "REPLIED"] {
        assert_eq!(
            ler_corpo(&cbor(&Status { status })),
            Err(ErroDoCorpo::Forma),
            "{status}"
        );
    }
    assert!(matches!(ler_corpo(b"\xff\xff"), Err(ErroDoCorpo::Cbor(_))));
    assert!(ErroDoCorpo::Forma.to_string().is_ascii());
}
