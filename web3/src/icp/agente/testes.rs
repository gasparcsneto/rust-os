//! O agente ponta a ponta contra um IC de mentira — o da bancada, que lê
//! os envelopes com o `ic-transport-types` e assina como a réplica — e os
//! modos adversários de quem está no caminho.

use std::cell::RefCell;
use std::format;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use ic_transport_types::{
    Envelope, EnvelopeContent, QueryResponse, RejectCode, RejectResponse, ReplyResponse,
};

use super::*;
use crate::icp::bancada::{self, AGORA_NS, Ic};
use crate::icp::{MINUTO_NS, certificado, consulta};

/// O que o IC de mentira faz de errado.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Modo {
    Honesto,
    Recusa,
    SemAssinatura,
    RespostaMexida,
    OutroNo,
    CertificadoVelho,
    OutraRaiz,
    DelegacaoAninhada,
    Status(u16),
    Corte,
    CorpoTorto,
}

struct IcDeMentira {
    ic: Ic,
    modo: Modo,
    pedidos: RefCell<Vec<String>>,
}

#[derive(Debug, PartialEq)]
struct Corte;

impl core::fmt::Display for Corte {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("conexao cortada")
    }
}

impl Transporte for &IcDeMentira {
    type Erro = Corte;

    fn post(&mut self, caminho: &str, corpo: &[u8]) -> Result<(u16, Vec<u8>), Corte> {
        self.pedidos.borrow_mut().push(String::from(caminho));
        let base = format!("/api/v3/canister/{}/", self.ic.canister);
        let endpoint = caminho.strip_prefix(&base).expect("caminho do canister");
        if let Modo::Status(s) = self.modo {
            return Ok((s, b"canister \x1b[31mnao\xff existe".to_vec()));
        }
        // O envelope tem de ser um que o oráculo lê.
        let envelope: Envelope<'_> = serde_cbor::from_slice(corpo).expect("envelope");
        assert!(envelope.sender_sig.is_none() && envelope.sender_pubkey.is_none());
        match (endpoint, &*envelope.content) {
            ("read_state", EnvelopeContent::ReadState { paths, sender, .. }) => {
                assert_eq!(*sender, candid::Principal::anonymous());
                assert_eq!(paths.len(), 1);
                assert_eq!(paths[0].len(), 1);
                assert_eq!(paths[0][0].as_bytes(), b"subnet");
                if self.modo == Modo::Corte {
                    return Err(Corte);
                }
                if self.modo == Modo::CorpoTorto {
                    return Ok((200, bancada::cbor(&5u8)));
                }
                let cert = match self.modo {
                    Modo::CertificadoVelho => self.ic.certificado(AGORA_NS - 10 * MINUTO_NS),
                    Modo::OutraRaiz => {
                        let mut outro = Ic::novo();
                        outro.raiz = bancada::chave_bls(77);
                        outro.certificado(AGORA_NS)
                    }
                    Modo::DelegacaoAninhada => {
                        let aninhada = bancada::certificado_assinado(
                            bancada::arvore(&self.ic.folhas_da_delegacao(AGORA_NS)),
                            &self.ic.raiz,
                            Some((
                                self.ic.id_da_sub_rede.bytes().to_vec(),
                                self.ic.delegacao(AGORA_NS),
                            )),
                        );
                        bancada::certificado_assinado(
                            bancada::arvore(&self.ic.folhas_da_sub_rede(AGORA_NS)),
                            &self.ic.sub_rede,
                            Some((self.ic.id_da_sub_rede.bytes().to_vec(), aninhada)),
                        )
                    }
                    _ => self.ic.certificado(AGORA_NS),
                };
                Ok((200, self.ic.resposta_de_leitura(cert)))
            }
            (
                "query",
                conteudo @ EnvelopeContent::Query {
                    method_name,
                    sender,
                    nonce,
                    ..
                },
            ) => {
                assert_eq!(*sender, candid::Principal::anonymous());
                assert!(nonce.is_some());
                let id = *conteudo.to_request_id();
                let mut resposta = match (self.modo, method_name.as_str()) {
                    (Modo::Recusa, _) => QueryResponse::Rejected {
                        reject: RejectResponse {
                            reject_code: RejectCode::CanisterReject,
                            reject_message: "nao quero".into(),
                            error_code: Some("IC0406".into()),
                        },
                        signatures: Vec::new(),
                    },
                    (_, "ola") => QueryResponse::Replied {
                        reply: ReplyResponse {
                            arg: crate::icp::candid::codificar(&[
                                crate::icp::candid::Valor::Texto("ola".into()),
                            ])
                            .unwrap(),
                        },
                        signatures: Vec::new(),
                    },
                    _ => panic!("metodo {method_name}"),
                };
                let quem: &[usize] = match self.modo {
                    Modo::SemAssinatura => &[],
                    _ => &[0, 2],
                };
                if self.modo == Modo::OutroNo {
                    let mut outro = Ic::novo();
                    outro.nos[0].1 = bancada::chave_de_no(66);
                    outro.assinar_resposta(&mut resposta, id, AGORA_NS, &[0]);
                } else {
                    self.ic.assinar_resposta(&mut resposta, id, AGORA_NS, quem);
                }
                if self.modo == Modo::RespostaMexida
                    && let QueryResponse::Replied { reply, .. } = &mut resposta
                {
                    let n = reply.arg.len();
                    reply.arg[n - 1] = b'A';
                }
                Ok((200, bancada::cbor(&resposta)))
            }
            (e, c) => panic!("{e}: {c:?}"),
        }
    }
}

fn mentira(modo: Modo) -> IcDeMentira {
    IcDeMentira {
        ic: Ic::novo(),
        modo,
        pedidos: RefCell::new(Vec::new()),
    }
}

fn consultar_com(ic: &IcDeMentira) -> Result<Verificada, Erro<Corte>> {
    let mut t = ic;
    consultar(
        &mut t,
        &ic.ic.raiz_de_confianca(),
        &ic.ic.canister,
        "ola",
        b"DIDL\x00\x00",
        AGORA_NS,
        &[0x5a; 16],
    )
}

#[test]
fn a_consulta_verificada_ponta_a_ponta() {
    let ic = mentira(Modo::Honesto);
    let v = consultar_com(&ic).unwrap();
    let Desfecho::Respondida(arg) = &v.desfecho else {
        panic!("{v:?}")
    };
    assert_eq!(
        crate::icp::candid::decodificar(arg),
        Ok(vec![crate::icp::candid::Valor::Texto("ola".into())])
    );
    assert_eq!(v.sub_rede, ic.ic.id_da_sub_rede);
    assert!(v.delegada);
    assert_eq!(v.tempo_do_certificado_ns, AGORA_NS);
    assert_eq!((v.assinaturas, v.nos), (2, 4));
    // Primeiro o certificado, depois a consulta; cada um no endpoint v3 do
    // canister, pelo texto do Principal.
    let c = ic.ic.canister.texto();
    assert_eq!(
        *ic.pedidos.borrow(),
        vec![
            format!("/api/v3/canister/{c}/read_state"),
            format!("/api/v3/canister/{c}/query")
        ]
    );
}

#[test]
fn a_recusa_assinada_chega_como_recusa() {
    let ic = mentira(Modo::Recusa);
    let v = consultar_com(&ic).unwrap();
    assert_eq!(
        v.desfecho,
        Desfecho::Recusada {
            codigo: 4,
            mensagem: "nao quero".into(),
            erro: Some("IC0406".into()),
        }
    );
}

/// Um modo, como reconhecer o erro dele, e quantos pedidos saem.
type Caso = (Modo, fn(&Erro<Corte>) -> bool, usize);

#[test]
fn os_modos_adversarios() {
    let casos: Vec<Caso> = vec![
        (
            Modo::SemAssinatura,
            |e| *e == Erro::Consulta(consulta::Erro::SemAssinatura),
            2,
        ),
        (
            Modo::RespostaMexida,
            |e| matches!(e, Erro::Consulta(consulta::Erro::AssinaturaInvalida(_))),
            2,
        ),
        (
            Modo::OutroNo,
            |e| matches!(e, Erro::Consulta(consulta::Erro::AssinaturaInvalida(_))),
            2,
        ),
        (
            Modo::CertificadoVelho,
            |e| matches!(e, Erro::Certificado(certificado::Erro::Velho { .. })),
            1,
        ),
        (
            Modo::OutraRaiz,
            |e| *e == Erro::Certificado(certificado::Erro::AssinaturaDaDelegacao),
            1,
        ),
        (
            Modo::DelegacaoAninhada,
            |e| *e == Erro::Certificado(certificado::Erro::DelegacaoAninhada),
            1,
        ),
        (
            Modo::Corte,
            |e| *e == Erro::Transporte(Etapa::LeituraDeEstado, Corte),
            1,
        ),
        (Modo::CorpoTorto, |e| *e == Erro::LeituraDeEstado, 1),
        (
            Modo::Status(503),
            |e| matches!(e, Erro::Http(Etapa::LeituraDeEstado, 503, _)),
            1,
        ),
    ];
    for (modo, esperado, pedidos) in casos {
        let ic = mentira(modo);
        let e = consultar_com(&ic).unwrap_err();
        assert!(esperado(&e), "{modo:?}: {e:?}");
        // Um certificado que não vale para a consulta antes dela: o pedido
        // nem sai.
        assert_eq!(ic.pedidos.borrow().len(), pedidos, "{modo:?}");
        assert!(e.to_string().is_ascii(), "{e}");
    }
}

#[test]
fn o_corpo_de_um_erro_http_sai_em_ascii() {
    let ic = mentira(Modo::Status(404));
    let e = consultar_com(&ic).unwrap_err();
    let Erro::Http(_, 404, corpo) = &e else {
        panic!("{e:?}")
    };
    assert_eq!(corpo, "canister ?[31mnao? existe");
    assert_eq!(
        e.to_string(),
        "read_state: HTTP 404: canister ?[31mnao? existe"
    );
}

#[test]
fn o_nonce_longo_nao_sai() {
    let ic = mentira(Modo::Honesto);
    let mut t = &ic;
    let e = consultar(
        &mut t,
        &ic.ic.raiz_de_confianca(),
        &ic.ic.canister,
        "ola",
        b"DIDL\x00\x00",
        AGORA_NS,
        &[0; 33],
    )
    .unwrap_err();
    assert_eq!(e, Erro::Pedido(crate::icp::pedido::Erro::NonceLongo));
    // A leitura de estado saiu (não leva nonce); a consulta, não.
    assert_eq!(ic.pedidos.borrow().len(), 1);
}

#[test]
fn a_hora_errada_de_quem_verifica() {
    // Com a hora daqui dez minutos à frente, o certificado é velho, e nada
    // é entregue.
    let ic = mentira(Modo::Honesto);
    let mut t = &ic;
    let e = consultar(
        &mut t,
        &ic.ic.raiz_de_confianca(),
        &ic.ic.canister,
        "ola",
        b"DIDL\x00\x00",
        AGORA_NS + 10 * MINUTO_NS,
        &[1; 8],
    )
    .unwrap_err();
    assert!(
        matches!(e, Erro::Certificado(certificado::Erro::Velho { .. })),
        "{e:?}"
    );
}

#[test]
fn o_caminho() {
    assert_eq!(
        caminho(&Principal::GERENCIAMENTO, "query"),
        "/api/v3/canister/aaaaa-aa/query"
    );
    assert_eq!(Etapa::Consulta.to_string(), "query");
    assert_eq!(Etapa::LeituraDeEstado.to_string(), "read_state");
}
