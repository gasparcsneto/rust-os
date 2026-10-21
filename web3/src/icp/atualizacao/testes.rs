//! A chamada de atualização contra um IC de mentira que confere como o de
//! verdade: o envelope lido pelo `ic-transport-types`, o id do pedido pela
//! conta de lá, e a assinatura pelo `ic-ed25519` — quem assina errado
//! ouve 403, como no IC. Os certificados são os da bancada.

use std::collections::VecDeque;
use std::string::{String, ToString};
use std::vec::Vec;

use ed25519_dalek::{Signer, SigningKey};
use ic_transport_types::{
    Envelope, EnvelopeContent, RejectCode, RejectResponse, TransportCallResponse,
};

use super::*;
use crate::icp::bancada::{AGORA_NS, Ic, cbor};
use crate::icp::pedido::{assinavel, der_ed25519};

/// Uma chave de teste: assina como o kernel do Duke assinaria, e conta.
struct ChaveDeTeste {
    privada: SigningKey,
    der: [u8; 44],
    assinou: usize,
    recusar: bool,
}

impl ChaveDeTeste {
    fn nova(semente: u8) -> ChaveDeTeste {
        let privada = SigningKey::from_bytes(&[semente; 32]);
        let der = der_ed25519(privada.verifying_key().as_bytes());
        ChaveDeTeste {
            privada,
            der,
            assinou: 0,
            recusar: false,
        }
    }

    fn principal(&self) -> Principal {
        Principal::auto_autenticado(&self.der)
    }
}

impl Assinador for ChaveDeTeste {
    type Erro = &'static str;

    fn chave_der(&self) -> &[u8] {
        &self.der
    }

    fn assinar(&mut self, id: &Hash) -> Result<Vec<u8>, &'static str> {
        if self.recusar {
            return Err("DENY_RESOURCE");
        }
        self.assinou += 1;
        Ok(self.privada.sign(&assinavel(id)).to_bytes().to_vec())
    }
}

/// O que a chamada responde.
#[derive(Clone)]
enum Responde {
    /// 200 com o certificado: o `status` e os campos do `request_status`.
    Certificado(Vec<(&'static [u8], Vec<u8>)>),
    /// 200 com a recusa não replicada.
    NaoReplicada,
    /// 202.
    Aceita,
    /// Um status HTTP qualquer.
    Http(u16),
    /// 200 com o certificado de outra sub-rede: o da raiz, sem delegação,
    /// para um canister de aplicação.
    DaRaiz,
}

/// O IC de mentira.
struct IcDeChamadas {
    ic: Ic,
    canister: Principal,
    na_raiz: bool,
    chamada: Responde,
    /// As situações, uma por leitura: os campos do `request_status`.
    situacoes: VecDeque<Vec<(&'static [u8], Vec<u8>)>>,
    tempo_ns: u64,
    /// O que chegou: o caminho, o remetente e o id de cada pedido.
    pedidos: Vec<(String, candid::Principal, [u8; 32])>,
    /// O id da chamada.
    id_da_chamada: Option<[u8; 32]>,
}

fn status(s: &'static str) -> Vec<(&'static [u8], Vec<u8>)> {
    std::vec![(b"status".as_slice(), s.as_bytes().to_vec())]
}

fn respondida(arg: &[u8]) -> Vec<(&'static [u8], Vec<u8>)> {
    std::vec![
        (b"status".as_slice(), b"replied".to_vec()),
        (b"reply".as_slice(), arg.to_vec()),
    ]
}

impl IcDeChamadas {
    fn novo(chamada: Responde) -> IcDeChamadas {
        let ic = Ic::novo();
        let canister = ic.canister;
        IcDeChamadas {
            ic,
            canister,
            na_raiz: false,
            chamada,
            situacoes: VecDeque::new(),
            tempo_ns: AGORA_NS,
            pedidos: Vec::new(),
            id_da_chamada: None,
        }
    }

    fn na_raiz(mut self) -> IcDeChamadas {
        self.na_raiz = true;
        self.canister = self.ic.canister_da_raiz();
        self
    }

    fn situacao(&self, id: &[u8; 32], campos: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
        self.ic
            .certificado_da_situacao(id, campos, self.tempo_ns, self.na_raiz)
    }
}

impl Transporte for IcDeChamadas {
    type Erro = &'static str;

    fn post(&mut self, rota: &str, corpo: &[u8]) -> Result<(u16, Vec<u8>), &'static str> {
        let envelope: Envelope<'_> = serde_cbor::from_slice(corpo).map_err(|_| "cbor")?;
        let id = *envelope.content.to_request_id();
        let remetente = *envelope.content.sender();
        // A autenticação, como o IC confere: a chave é a do remetente, e a
        // assinatura é a do id, no domínio do pedido.
        match (&envelope.sender_pubkey, &envelope.sender_sig) {
            (None, None) if remetente == candid::Principal::anonymous() => {}
            (Some(chave), Some(assinatura)) => {
                let publica =
                    ic_ed25519::PublicKey::deserialize_rfc8410_der(chave).map_err(|_| "der")?;
                let confere = publica
                    .verify_signature(
                        &ic_transport_types::RequestId::new(&id).signable(),
                        assinatura,
                    )
                    .is_ok();
                if !confere || candid::Principal::self_authenticating(chave) != remetente {
                    return Ok((403, b"invalid signature".to_vec()));
                }
            }
            _ => return Ok((403, b"missing signature".to_vec())),
        }
        self.pedidos.push((String::from(rota), remetente, id));
        let esperado = |fim: &str| caminho(&self.canister, fim);
        match &*envelope.content {
            EnvelopeContent::ReadState { paths, .. } => {
                if rota != esperado("read_state") {
                    return Ok((404, Vec::new()));
                }
                let primeiro = paths[0][0].as_bytes();
                let cert = if primeiro == b"subnet" {
                    if self.na_raiz {
                        self.ic.certificado_da_raiz(self.tempo_ns)
                    } else {
                        self.ic.certificado(self.tempo_ns)
                    }
                } else {
                    // A situação só se lê pelo remetente da chamada.
                    let da_chamada = self.id_da_chamada.ok_or("sem chamada")?;
                    if paths[0][1].as_bytes() != da_chamada {
                        return Err("outro request_status");
                    }
                    let campos = self
                        .situacoes
                        .pop_front()
                        .unwrap_or_else(|| status("processing"));
                    self.situacao(&da_chamada, &campos)
                };
                Ok((200, self.ic.resposta_de_leitura(cert)))
            }
            EnvelopeContent::Call { .. } => {
                if rota != std::format!("/api/v4/canister/{}/call", self.canister.texto()) {
                    return Ok((404, Vec::new()));
                }
                self.id_da_chamada = Some(id);
                match self.chamada.clone() {
                    Responde::Certificado(campos) => Ok((
                        200,
                        cbor(&TransportCallResponse::Replied {
                            certificate: self.situacao(&id, &campos),
                        }),
                    )),
                    Responde::DaRaiz => {
                        let certificate = self.ic.certificado_da_situacao(
                            &id,
                            &respondida(b"DIDL\x00\x00"),
                            self.tempo_ns,
                            true,
                        );
                        Ok((200, cbor(&TransportCallResponse::Replied { certificate })))
                    }
                    Responde::NaoReplicada => Ok((
                        200,
                        cbor(&TransportCallResponse::NonReplicatedRejection(
                            RejectResponse {
                                reject_code: RejectCode::CanisterReject,
                                reject_message: String::from("nao aceito"),
                                error_code: Some(String::from("IC0406")),
                            },
                        )),
                    )),
                    Responde::Aceita => Ok((202, Vec::new())),
                    Responde::Http(s) => Ok((s, b"\x00recusado\xff".to_vec())),
                }
            }
            EnvelopeContent::Query { .. } => Err("consulta"),
        }
    }
}

fn chamar_com(
    ic: &mut IcDeChamadas,
    chave: Option<&mut ChaveDeTeste>,
) -> Result<Atualizacao, Erro<&'static str, &'static str>> {
    let raiz = ic.ic.raiz_de_confianca();
    let canister = ic.canister;
    chamar(
        ic,
        chave,
        &raiz,
        &canister,
        "contar",
        b"DIDL\x00\x00",
        AGORA_NS,
        &[7; 16],
    )
}

/// A chamada assinada, respondida na hora: o IC conferiu a assinatura, o
/// remetente é o Principal da chave, e o desfecho é o que o certificado
/// prova.
#[test]
fn a_chamada_assinada_respondida_e_certificada() {
    let mut ic = IcDeChamadas::novo(Responde::Certificado(respondida(b"DIDL\x00\x01\x7c\x01")));
    let mut chave = ChaveDeTeste::nova(3);
    let a = chamar_com(&mut ic, Some(&mut chave)).unwrap();
    assert_eq!(
        a.andamento,
        Andamento::Certificado {
            desfecho: Final::Respondida(b"DIDL\x00\x01\x7c\x01".to_vec()),
            tempo_ns: AGORA_NS,
        }
    );
    assert_eq!(a.remetente, chave.principal());
    assert_eq!(chave.assinou, 1);
    assert!(a.faixas.delegada);
    // Os dois pedidos: as faixas, do anônimo; a chamada, da chave.
    assert_eq!(ic.pedidos.len(), 2);
    assert_eq!(ic.pedidos[0].1, candid::Principal::anonymous());
    assert_eq!(
        ic.pedidos[1].1,
        candid::Principal::self_authenticating(chave.chave_der())
    );
    assert_eq!(ic.pedidos[1].2, a.id_do_pedido);
}

/// O anônimo também chama: sem chave, sem assinatura, e o remetente é o
/// anônimo.
#[test]
fn a_chamada_anonima_continua() {
    let mut ic = IcDeChamadas::novo(Responde::Certificado(respondida(b"DIDL\x00\x00")));
    let a = chamar_com(&mut ic, None::<&mut ChaveDeTeste>).unwrap();
    assert_eq!(a.remetente, Principal::ANONIMO);
    assert!(matches!(a.andamento, Andamento::Certificado { .. }));
    assert_eq!(ic.pedidos[1].1, candid::Principal::anonymous());
}

/// Duas chaves, dois Principais — e cada um é o que o IC calcula.
#[test]
fn duas_identidades_dois_principais() {
    let mut principais = Vec::new();
    for semente in [4u8, 5] {
        let mut ic = IcDeChamadas::novo(Responde::Certificado(respondida(b"DIDL\x00\x00")));
        let mut chave = ChaveDeTeste::nova(semente);
        let a = chamar_com(&mut ic, Some(&mut chave)).unwrap();
        assert_eq!(ic.pedidos[1].1.as_slice(), a.remetente.bytes());
        principais.push(a.remetente);
    }
    assert_ne!(principais[0], principais[1]);
}

/// A 202: pendente, e acompanhada até a resposta — cada leitura assinada
/// de novo, com outro id, pela mesma chave.
#[test]
fn a_202_acompanhada_ate_a_resposta() {
    let mut ic = IcDeChamadas::novo(Responde::Aceita);
    ic.situacoes.extend([
        Vec::new(),
        status("received"),
        status("processing"),
        respondida(b"DIDL\x00\x01\x71\x02ok"),
    ]);
    let mut chave = ChaveDeTeste::nova(6);
    let mut a = chamar_com(&mut ic, Some(&mut chave)).unwrap();
    assert_eq!(a.andamento, Andamento::Pendente("accepted"));
    let raiz = ic.ic.raiz_de_confianca();
    let mut vistos = Vec::new();
    let mut agora = AGORA_NS;
    let fim = loop {
        agora += 500_000_000;
        match acompanhar(&mut ic, Some(&mut chave), &raiz, &mut a, agora).unwrap() {
            Andamento::Pendente(s) => vistos.push(s),
            outro => break outro,
        }
    };
    assert_eq!(vistos, ["unknown", "received", "processing"]);
    assert!(matches!(
        fim,
        Andamento::Certificado { desfecho: Final::Respondida(ref b), .. } if b == b"DIDL\x00\x01\x71\x02ok"
    ));
    // Uma assinatura pela chamada, e uma por leitura; cada leitura, outro
    // pedido.
    assert_eq!(chave.assinou, 5);
    let leituras: Vec<[u8; 32]> = ic.pedidos[2..].iter().map(|p| p.2).collect();
    assert_eq!(leituras.len(), 4);
    for (i, a) in leituras.iter().enumerate() {
        assert!(leituras[i + 1..].iter().all(|b| b != a));
    }
}

/// Duas leituras na mesma hora de quem chama — o Duke a dá em segundos, e
/// a espera entre elas é de meio — são dois pedidos: a validade da segunda
/// vai além da da primeira, e o id muda com ela. Cada uma assinada de novo.
#[test]
fn leituras_na_mesma_hora_sao_pedidos_diferentes() {
    let mut ic = IcDeChamadas::novo(Responde::Aceita);
    ic.situacoes.extend([
        status("received"),
        status("processing"),
        status("processing"),
    ]);
    let mut chave = ChaveDeTeste::nova(6);
    let mut a = chamar_com(&mut ic, Some(&mut chave)).unwrap();
    let raiz = ic.ic.raiz_de_confianca();
    for _ in 0..3 {
        assert!(matches!(
            acompanhar(&mut ic, Some(&mut chave), &raiz, &mut a, AGORA_NS).unwrap(),
            Andamento::Pendente(_)
        ));
    }
    assert_eq!(chave.assinou, 4);
    let leituras: Vec<[u8; 32]> = ic.pedidos[2..].iter().map(|p| p.2).collect();
    assert_eq!(leituras.len(), 3);
    for (i, a) in leituras.iter().enumerate() {
        assert!(leituras[i + 1..].iter().all(|b| b != a));
    }
}

/// A recusa certificada, a concluída e a não replicada: cada uma do jeito
/// dela — a última sem prova nenhuma.
#[test]
fn os_desfechos() {
    let mut ic = IcDeChamadas::novo(Responde::Certificado(std::vec![
        (b"status".as_slice(), b"rejected".to_vec()),
        (b"reject_code".as_slice(), std::vec![4]),
        (b"reject_message".as_slice(), b"nao".to_vec()),
        (b"error_code".as_slice(), b"IC0503".to_vec()),
    ]));
    let a = chamar_com(&mut ic, Some(&mut ChaveDeTeste::nova(7))).unwrap();
    assert_eq!(
        a.andamento,
        Andamento::Certificado {
            desfecho: Final::Recusada {
                codigo: 4,
                mensagem: String::from("nao"),
                erro: Some(String::from("IC0503")),
            },
            tempo_ns: AGORA_NS,
        }
    );
    let mut ic = IcDeChamadas::novo(Responde::Certificado(status("done")));
    let a = chamar_com(&mut ic, Some(&mut ChaveDeTeste::nova(7))).unwrap();
    assert!(matches!(
        a.andamento,
        Andamento::Certificado {
            desfecho: Final::Concluida,
            ..
        }
    ));
    let mut ic = IcDeChamadas::novo(Responde::NaoReplicada);
    let a = chamar_com(&mut ic, Some(&mut ChaveDeTeste::nova(7))).unwrap();
    assert_eq!(
        a.andamento,
        Andamento::RecusaNaoReplicada {
            codigo: 4,
            mensagem: String::from("nao aceito"),
            erro: Some(String::from("IC0406")),
        }
    );
    // A situação de dentro do certificado ainda pendente: segue-se.
    let mut ic = IcDeChamadas::novo(Responde::Certificado(status("processing")));
    let a = chamar_com(&mut ic, Some(&mut ChaveDeTeste::nova(7))).unwrap();
    assert_eq!(a.andamento, Andamento::Pendente("processing"));
}

/// O canister da sub-rede raiz: as faixas vêm da leitura separada, e o
/// certificado da chamada, sem delegação e sem faixas, vale por elas.
#[test]
fn o_canister_da_raiz_pela_leitura_das_faixas() {
    let mut ic = IcDeChamadas::novo(Responde::Certificado(respondida(b"DIDL\x00\x00"))).na_raiz();
    let mut chave = ChaveDeTeste::nova(8);
    let a = chamar_com(&mut ic, Some(&mut chave)).unwrap();
    assert!(!a.faixas.delegada);
    assert_eq!(a.faixas.sub_rede, ic.ic.raiz_de_confianca().sub_rede());
    assert!(matches!(a.andamento, Andamento::Certificado { .. }));
    // E a leitura da situação, também da raiz.
    let mut ic = IcDeChamadas::novo(Responde::Aceita).na_raiz();
    ic.situacoes.push_back(respondida(b"DIDL\x00\x00"));
    let mut a = chamar_com(&mut ic, Some(&mut chave)).unwrap();
    let raiz = ic.ic.raiz_de_confianca();
    assert!(matches!(
        acompanhar(&mut ic, Some(&mut chave), &raiz, &mut a, AGORA_NS).unwrap(),
        Andamento::Certificado { .. }
    ));
}

/// O certificado da chamada de outra sub-rede que a das faixas é
/// recusado: o canister de aplicação respondido pela raiz, sem delegação.
#[test]
fn o_certificado_de_outra_sub_rede() {
    let mut ic = IcDeChamadas::novo(Responde::DaRaiz);
    assert_eq!(
        chamar_com(&mut ic, Some(&mut ChaveDeTeste::nova(9))).unwrap_err(),
        Erro::Certificado(Etapa::Chamada, certificado::Erro::OutraSubRede)
    );
}

/// A hora de quem confere longe da do certificado: nada vale.
#[test]
fn o_certificado_velho() {
    let mut ic = IcDeChamadas::novo(Responde::Certificado(respondida(b"DIDL\x00\x00")));
    ic.tempo_ns = AGORA_NS - 6 * crate::icp::MINUTO_NS;
    let e = chamar_com(&mut ic, Some(&mut ChaveDeTeste::nova(10))).unwrap_err();
    assert!(matches!(
        e,
        Erro::Certificado(Etapa::Faixas, certificado::Erro::Velho { .. })
    ));
}

/// Quem assina recusou: nada sai — nem a chamada.
#[test]
fn a_assinatura_recusada_nao_manda_nada() {
    let mut ic = IcDeChamadas::novo(Responde::Certificado(respondida(b"DIDL\x00\x00")));
    let mut chave = ChaveDeTeste::nova(11);
    chave.recusar = true;
    assert_eq!(
        chamar_com(&mut ic, Some(&mut chave)).unwrap_err(),
        Erro::Assinatura(Etapa::Chamada, "DENY_RESOURCE")
    );
    // Só a leitura das faixas, do anônimo, saiu.
    assert_eq!(ic.pedidos.len(), 1);
}

/// O status HTTP fora do esperado diz o começo do corpo em ASCII; e a
/// leitura da situação por outra chave que a da chamada não se monta.
#[test]
fn http_e_outro_remetente() {
    let mut ic = IcDeChamadas::novo(Responde::Http(403));
    let e = chamar_com(&mut ic, Some(&mut ChaveDeTeste::nova(12))).unwrap_err();
    assert_eq!(
        e,
        Erro::Http(Etapa::Chamada, 403, String::from("?recusado?"))
    );
    assert!(e.to_string().is_ascii());
    let mut ic = IcDeChamadas::novo(Responde::Aceita);
    let mut a = chamar_com(&mut ic, Some(&mut ChaveDeTeste::nova(12))).unwrap();
    let raiz = ic.ic.raiz_de_confianca();
    assert_eq!(
        acompanhar(
            &mut ic,
            Some(&mut ChaveDeTeste::nova(13)),
            &raiz,
            &mut a,
            AGORA_NS
        ),
        Err(Erro::Pedido(pedido::Erro::RemetenteNaoEDaChave))
    );
    assert_eq!(
        acompanhar(&mut ic, None::<&mut ChaveDeTeste>, &raiz, &mut a, AGORA_NS),
        Err(Erro::Pedido(pedido::Erro::RemetenteNaoEDaChave))
    );
}

/// Um IC que assina a chamada com a assinatura errada recusaria — e este
/// lado nunca manda uma: a assinatura de outro id ouve 403 do IC de
/// mentira, como ouviria do de verdade.
#[test]
fn o_ic_de_mentira_confere_a_assinatura() {
    struct Errada(ChaveDeTeste);
    impl Assinador for Errada {
        type Erro = &'static str;
        fn chave_der(&self) -> &[u8] {
            self.0.chave_der()
        }
        fn assinar(&mut self, id: &Hash) -> Result<Vec<u8>, &'static str> {
            let mut outro = *id;
            outro[0] ^= 1;
            self.0.assinar(&outro)
        }
    }
    let mut ic = IcDeChamadas::novo(Responde::Certificado(respondida(b"DIDL\x00\x00")));
    let mut errada = Errada(ChaveDeTeste::nova(14));
    let raiz = ic.ic.raiz_de_confianca();
    let canister = ic.canister;
    let e = chamar(
        &mut ic,
        Some(&mut errada),
        &raiz,
        &canister,
        "contar",
        b"DIDL\x00\x00",
        AGORA_NS,
        &[7; 16],
    )
    .unwrap_err();
    assert!(matches!(e, Erro::Http(Etapa::Chamada, 403, _)));
}
