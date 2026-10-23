//! O agente ponta a ponta contra um IC de mentira — o da bancada, que lê
//! os envelopes com o `ic-transport-types`, confere a assinatura de quem
//! pede como o IC e assina como a réplica — e os modos adversários de quem
//! está no caminho, na consulta do anônimo e na assinada.

use std::cell::RefCell;
use std::format;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use ic_transport_types::{
    Envelope, EnvelopeContent, QueryResponse, RejectCode, RejectResponse, ReplyResponse, RequestId,
};

use super::*;
use crate::icp::bancada::{self, AGORA_NS, Ic};
use crate::icp::candid::{Valor, codificar, decodificar};
use crate::icp::pedido::{assinavel, der_ed25519};
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
    /// Quem a consulta tem de dizer que pede, assinada; `None`, o anônimo,
    /// sem assinatura.
    assinada_por: Option<candid::Principal>,
    /// O remetente e o id de cada pedido que o IC aceitou.
    remetentes: RefCell<Vec<(candid::Principal, [u8; 32])>>,
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
        // O envelope tem de ser um que o oráculo lê. Só a consulta de quem
        // tem chave vai assinada; as faixas, nunca.
        let envelope: Envelope<'_> = serde_cbor::from_slice(corpo).expect("envelope");
        let assinado = envelope.sender_sig.is_some() || envelope.sender_pubkey.is_some();
        assert_eq!(assinado, endpoint == "query" && self.assinada_por.is_some());
        let id = *envelope.content.to_request_id();
        match (
            envelope.sender_pubkey.as_deref(),
            envelope.sender_sig.as_deref(),
        ) {
            (None, None) => {}
            // A autenticação, como o IC confere: a chave é a do remetente,
            // e a assinatura é a do id, no domínio do pedido — quem assina
            // errado ouve 403.
            (Some(chave), Some(assinatura)) => {
                let publica =
                    ic_ed25519::PublicKey::deserialize_rfc8410_der(chave).expect("der da chave");
                let confere = publica
                    .verify_signature(&RequestId::new(&id).signable(), assinatura)
                    .is_ok();
                if !confere
                    || candid::Principal::self_authenticating(chave) != *envelope.content.sender()
                {
                    return Ok((403, b"invalid signature".to_vec()));
                }
            }
            _ => return Ok((403, b"missing signature".to_vec())),
        }
        self.remetentes
            .borrow_mut()
            .push((*envelope.content.sender(), id));
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
                EnvelopeContent::Query {
                    method_name,
                    sender,
                    nonce,
                    ..
                },
            ) => {
                assert_eq!(
                    *sender,
                    self.assinada_por
                        .unwrap_or_else(candid::Principal::anonymous)
                );
                assert!(nonce.is_some());
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
                    // Quem pede: o remetente que o IC conferiu.
                    (_, "quem") => QueryResponse::Replied {
                        reply: ReplyResponse {
                            arg: codificar(&[Valor::Principal(
                                Principal::de_bytes(sender.as_slice()).unwrap(),
                            )])
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
        assinada_por: None,
        remetentes: RefCell::new(Vec::new()),
    }
}

/// O IC de mentira que espera a consulta assinada pela `chave`.
fn mentira_assinada(modo: Modo, chave: &Chave) -> IcDeMentira {
    IcDeMentira {
        assinada_por: Some(chave.principal()),
        ..mentira(modo)
    }
}

/// Quem assina a consulta: uma chave de teste — assina como o kernel do
/// Duke assinaria, e conta.
struct Chave {
    privada: ed25519_dalek::SigningKey,
    der: [u8; 44],
    assinou: usize,
    recusar: bool,
}

impl Chave {
    fn nova(semente: u8) -> Chave {
        let privada = ed25519_dalek::SigningKey::from_bytes(&[semente; 32]);
        let der = der_ed25519(privada.verifying_key().as_bytes());
        Chave {
            privada,
            der,
            assinou: 0,
            recusar: false,
        }
    }

    /// O Principal da chave, pela conta do `ic_principal`.
    fn principal(&self) -> candid::Principal {
        candid::Principal::self_authenticating(self.der)
    }
}

impl Assinador for Chave {
    type Erro = &'static str;

    fn chave_der(&self) -> &[u8] {
        &self.der
    }

    fn assinar(&mut self, id: &Hash) -> Result<Vec<u8>, &'static str> {
        if self.recusar {
            return Err("DENY_RESOURCE");
        }
        self.assinou += 1;
        Ok(ed25519_dalek::Signer::sign(&self.privada, &assinavel(id))
            .to_bytes()
            .to_vec())
    }
}

fn consultar_assinada_com(
    ic: &IcDeMentira,
    chave: &mut Chave,
    metodo: &str,
) -> Result<Verificada, ErroDaAssinada<Corte, &'static str>> {
    let mut t = ic;
    consultar_assinada(
        &mut t,
        chave,
        &ic.ic.raiz_de_confianca(),
        &ic.ic.canister,
        metodo,
        b"DIDL\x00\x00",
        AGORA_NS,
        &[0x5a; 16],
    )
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

/// Os modos adversários: os mesmos para a consulta do anônimo e para a
/// assinada.
fn casos() -> Vec<Caso> {
    vec![
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
    ]
}

#[test]
fn os_modos_adversarios() {
    for (modo, esperado, pedidos) in casos() {
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

/// O transporte que grava o que o IC de mentira respondeu.
struct Gravador<'a> {
    ic: &'a IcDeMentira,
    respostas: Vec<(u16, Vec<u8>)>,
}

impl Transporte for Gravador<'_> {
    type Erro = Corte;

    fn post(&mut self, caminho: &str, corpo: &[u8]) -> Result<(u16, Vec<u8>), Corte> {
        let mut ic = self.ic;
        let r = ic.post(caminho, corpo)?;
        self.respostas.push(r.clone());
        Ok(r)
    }
}

/// O transporte que devolve, na ordem, o que foi gravado.
struct Gravadas(Vec<(u16, Vec<u8>)>);

impl Transporte for Gravadas {
    type Erro = Corte;

    fn post(&mut self, _caminho: &str, _corpo: &[u8]) -> Result<(u16, Vec<u8>), Corte> {
        if self.0.is_empty() {
            return Err(Corte);
        }
        Ok(self.0.remove(0))
    }
}

/// A medida da consulta no hospedeiro, nativa: o mesmo código que o
/// programa roda no emulador, sobre as duas respostas de uma consulta ao IC
/// de mentira, gravadas uma vez — o que se mede é ler e verificar, e não a
/// bancada assinando. O pedido é o mesmo a cada volta (a hora e o nonce
/// fixos), e as assinaturas dos nós continuam presas a ele.
///
/// Só sob demanda, de preferência sem depuração:
/// `cargo test -p web3 --release -- --ignored --nocapture medida`.
#[test]
#[ignore = "medida: --ignored --nocapture, em --release"]
fn medida_da_consulta_no_hospedeiro() {
    const VOLTAS: usize = 50;
    let ic = mentira(Modo::Honesto);
    let raiz = ic.ic.raiz_de_confianca();
    let mut gravador = Gravador {
        ic: &ic,
        respostas: Vec::new(),
    };
    consultar(
        &mut gravador,
        &raiz,
        &ic.ic.canister,
        "ola",
        b"DIDL\x00\x00",
        AGORA_NS,
        &[0x5a; 16],
    )
    .unwrap();
    let respostas = gravador.respostas;
    let mut tempos: Vec<std::time::Duration> = (0..VOLTAS)
        .map(|_| {
            let mut gravadas = Gravadas(respostas.clone());
            let inicio = std::time::Instant::now();
            let v = consultar(
                &mut gravadas,
                &raiz,
                &ic.ic.canister,
                "ola",
                b"DIDL\x00\x00",
                AGORA_NS,
                &[0x5a; 16],
            );
            let tempo = inicio.elapsed();
            assert!(v.is_ok_and(|v| v.assinaturas == 2), "a volta nao verificou");
            tempo
        })
        .collect();
    tempos.sort_unstable();
    std::println!(
        "medida: {VOLTAS} consultas verificadas no hospedeiro ({} nos, 2 assinaturas): mediana {:?}, de {:?} a {:?}",
        ic.ic.nos.len(),
        tempos[VOLTAS / 2],
        tempos[0],
        tempos[VOLTAS - 1]
    );
}

/// A consulta assinada, ponta a ponta: o IC conferiu a assinatura, o
/// remetente é o Principal da chave — a resposta de `quem` o diz —, e uma
/// assinatura só, a da consulta; as faixas foram do anônimo.
#[test]
fn a_consulta_assinada_verificada_ponta_a_ponta() {
    let mut chave = Chave::nova(3);
    let ic = mentira_assinada(Modo::Honesto, &chave);
    let v = consultar_assinada_com(&ic, &mut chave, "quem").unwrap();
    let Desfecho::Respondida(arg) = &v.desfecho else {
        panic!("{v:?}")
    };
    assert_eq!(
        decodificar(arg),
        Ok(vec![Valor::Principal(Principal::auto_autenticado(
            &chave.der
        ))])
    );
    assert_eq!(v.sub_rede, ic.ic.id_da_sub_rede);
    assert!(v.delegada);
    assert_eq!(v.tempo_do_certificado_ns, AGORA_NS);
    assert_eq!((v.assinaturas, v.nos), (2, 4));
    assert_eq!(chave.assinou, 1);
    let c = ic.ic.canister.texto();
    assert_eq!(
        *ic.pedidos.borrow(),
        vec![
            format!("/api/v3/canister/{c}/read_state"),
            format!("/api/v3/canister/{c}/query")
        ]
    );
    let remetentes = ic.remetentes.borrow();
    assert_eq!(remetentes[0].0, candid::Principal::anonymous());
    assert_eq!(remetentes[1], (chave.principal(), v.id_do_pedido));
}

/// A consulta do anônimo continua como era: sem chave, sem assinatura, e
/// `quem` diz o anônimo.
#[test]
fn a_consulta_do_anonimo_diz_o_anonimo() {
    let ic = mentira(Modo::Honesto);
    let mut t = &ic;
    let v = consultar(
        &mut t,
        &ic.ic.raiz_de_confianca(),
        &ic.ic.canister,
        "quem",
        b"DIDL\x00\x00",
        AGORA_NS,
        &[0x5a; 16],
    )
    .unwrap();
    assert_eq!(
        v.desfecho,
        Desfecho::Respondida(codificar(&[Valor::Principal(Principal::ANONIMO)]).unwrap())
    );
    assert!(
        ic.remetentes
            .borrow()
            .iter()
            .all(|(r, _)| *r == candid::Principal::anonymous())
    );
}

/// Duas chaves, dois Principais — cada um o que o IC calcula, e nenhum o
/// anônimo.
#[test]
fn duas_chaves_dois_principais() {
    let mut vistos = Vec::new();
    for semente in [4u8, 5] {
        let mut chave = Chave::nova(semente);
        let ic = mentira_assinada(Modo::Honesto, &chave);
        let v = consultar_assinada_com(&ic, &mut chave, "quem").unwrap();
        let Desfecho::Respondida(arg) = v.desfecho else {
            panic!("{semente}")
        };
        let [Valor::Principal(p)] = &decodificar(&arg).unwrap()[..] else {
            panic!("{semente}")
        };
        assert_eq!(p.bytes(), chave.principal().as_slice());
        assert_ne!(*p, Principal::ANONIMO);
        vistos.push(*p);
    }
    assert_ne!(vistos[0], vistos[1]);
}

/// A recusa assinada pelos nós também chega na consulta assinada, como
/// recusa verificada.
#[test]
fn a_recusa_na_consulta_assinada() {
    let mut chave = Chave::nova(6);
    let ic = mentira_assinada(Modo::Recusa, &chave);
    let v = consultar_assinada_com(&ic, &mut chave, "quem").unwrap();
    assert_eq!(
        v.desfecho,
        Desfecho::Recusada {
            codigo: 4,
            mensagem: "nao quero".into(),
            erro: Some("IC0406".into()),
        }
    );
}

/// Os modos adversários também na assinada: o mesmo erro da do anônimo,
/// os mesmos pedidos — e a chave só assina depois do certificado
/// conferido, quando a consulta vai sair.
#[test]
fn os_modos_adversarios_na_assinada() {
    for (modo, esperado, pedidos) in casos() {
        let mut chave = Chave::nova(7);
        let ic = mentira_assinada(modo, &chave);
        let e = consultar_assinada_com(&ic, &mut chave, "ola").unwrap_err();
        let ErroDaAssinada::Consulta(e) = &e else {
            panic!("{modo:?}: {e:?}")
        };
        assert!(esperado(e), "{modo:?}: {e:?}");
        assert_eq!(ic.pedidos.borrow().len(), pedidos, "{modo:?}");
        assert_eq!(chave.assinou, pedidos - 1, "{modo:?}");
        assert!(e.to_string().is_ascii(), "{e}");
    }
}

/// A consulta de `ola` ao canister de `ic` pelo transporte `t`: do
/// anônimo, sem `chave`, ou assinada por ela.
fn consultar_por<T: Transporte<Erro = Corte>>(
    t: &mut T,
    ic: &IcDeMentira,
    chave: Option<&mut Chave>,
) -> Result<Verificada, ErroDaAssinada<Corte, &'static str>> {
    let raiz = ic.ic.raiz_de_confianca();
    let (canister, arg, nonce) = (&ic.ic.canister, b"DIDL\x00\x00", &[0x5a; 16]);
    match chave {
        None => Ok(consultar(t, &raiz, canister, "ola", arg, AGORA_NS, nonce)?),
        Some(c) => consultar_assinada(t, c, &raiz, canister, "ola", arg, AGORA_NS, nonce),
    }
}

/// A resposta de outra consulta não confere — a do anônimo, ou a de outra
/// chave, à mesma consulta, na mesma hora e com o mesmo nonce: o id leva o
/// remetente, e as assinaturas dos nós prendem a resposta ao id.
#[test]
fn a_resposta_de_outro_remetente_nao_confere() {
    let gravar = |ic: &IcDeMentira, chave: Option<&mut Chave>| {
        let mut gravador = Gravador {
            ic,
            respostas: Vec::new(),
        };
        consultar_por(&mut gravador, ic, chave).unwrap();
        gravador.respostas
    };
    let ic = mentira(Modo::Honesto);
    let do_anonimo = gravar(&ic, None);
    let mut a = Chave::nova(8);
    let de_a = gravar(&mentira_assinada(Modo::Honesto, &a), Some(&mut a));
    // À consulta de b, a resposta do anônimo e a de a; à do anônimo, a de
    // a.
    let mut b = Chave::nova(9);
    for e in [
        consultar_por(&mut Gravadas(do_anonimo), &ic, Some(&mut b)),
        consultar_por(&mut Gravadas(de_a.clone()), &ic, Some(&mut b)),
        consultar_por(&mut Gravadas(de_a), &ic, None),
    ] {
        assert!(
            matches!(
                e,
                Err(ErroDaAssinada::Consulta(Erro::Consulta(
                    consulta::Erro::AssinaturaInvalida(_)
                )))
            ),
            "{e:?}"
        );
    }
}

/// Quem assina recusou — no Duke, o gate recusou o `key.sign` —: a
/// consulta não sai, nem do anônimo no lugar.
#[test]
fn a_assinatura_recusada_nao_manda_a_consulta() {
    let mut chave = Chave::nova(10);
    chave.recusar = true;
    let ic = mentira_assinada(Modo::Honesto, &chave);
    let e = consultar_assinada_com(&ic, &mut chave, "quem").unwrap_err();
    assert_eq!(e, ErroDaAssinada::Assinatura("DENY_RESOURCE"));
    assert_eq!(e.to_string(), "query: assinatura: DENY_RESOURCE");
    // Só a leitura das faixas, do anônimo, saiu.
    assert_eq!(
        *ic.pedidos.borrow(),
        vec![format!(
            "/api/v3/canister/{}/read_state",
            ic.ic.canister.texto()
        )]
    );
    assert_eq!(ic.remetentes.borrow().len(), 1);
}

/// O IC de mentira confere a assinatura como o de verdade: a assinatura de
/// outro id ouve 403, e nada é entregue.
#[test]
fn a_assinatura_de_outro_id_ouve_403() {
    struct Errada(Chave);
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
    let mut errada = Errada(Chave::nova(11));
    let ic = mentira_assinada(Modo::Honesto, &errada.0);
    let mut t = &ic;
    let e = consultar_assinada(
        &mut t,
        &mut errada,
        &ic.ic.raiz_de_confianca(),
        &ic.ic.canister,
        "quem",
        b"DIDL\x00\x00",
        AGORA_NS,
        &[0x5a; 16],
    )
    .unwrap_err();
    assert!(
        matches!(
            e,
            ErroDaAssinada::Consulta(Erro::Http(Etapa::Consulta, 403, _))
        ),
        "{e:?}"
    );
    assert!(e.to_string().is_ascii());
}

/// O nonce longo: o pedido não se monta, e nada se assina.
#[test]
fn o_nonce_longo_nao_se_assina() {
    let mut chave = Chave::nova(12);
    let ic = mentira_assinada(Modo::Honesto, &chave);
    let mut t = &ic;
    let e = consultar_assinada(
        &mut t,
        &mut chave,
        &ic.ic.raiz_de_confianca(),
        &ic.ic.canister,
        "quem",
        b"DIDL\x00\x00",
        AGORA_NS,
        &[0; 33],
    )
    .unwrap_err();
    assert_eq!(
        e,
        ErroDaAssinada::Consulta(Erro::Pedido(crate::icp::pedido::Erro::NonceLongo))
    );
    assert_eq!(chave.assinou, 0);
    assert_eq!(ic.pedidos.borrow().len(), 1);
}
