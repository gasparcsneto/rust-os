//! A malha do Duke, do lado do programa: oferecer uma intenção, achar quem
//! a oferece, mandar, receber e responder.
//!
//! # O que é, daqui
//!
//! Um programa que sabe fazer alguma coisa — guardar uma imagem, anotar um
//! PDF — **oferece** a intenção (`imagem.compartilhar`): o kernel abre um
//! endpoint dele, e o que os outros programas do mesmo titular entregam
//! chega por ele. Um programa que quer que alguém faça **procura** quem
//! oferece, escolhe, e **manda**. Nenhum dos dois conhece o outro: o que os
//! liga é a intenção.
//!
//! Cada passo é um comando do gate — `fabric.offer`, `fabric.discover`,
//! `fabric.send`, `fabric.recv`, `fabric.ack`, `fabric.status`,
//! `fabric.cancel`, `fabric.withdraw` —, com a autoridade de quem lançou o
//! processo, o manifesto dele e a intenção como recurso enumerado na
//! política. Não há atalho: o que este módulo faz, um agente faria pelo
//! canal, com os mesmos parâmetros e a mesma resposta.
//!
//! # O que o kernel garante, e este módulo não precisa conferir
//!
//! - **Quem manda** é o processo, conferido pelo kernel: o nome do
//!   manifesto, o resumo da imagem e o editor que a selou. Um programa não
//!   se diz outro — dois que dizem o mesmo nome aparecem com resumos
//!   diferentes ([`Candidato`], [`Entrega::de`]).
//! - **Só o mesmo titular**: a mesma pessoa, o mesmo agente, o sistema.
//! - **Nenhuma autoridade viaja** com a entrega: o que quem recebe faz com o
//!   texto é decidido pelo papel dele.
//!
//! # Como se usa
//!
//! ```ignore
//! use programas::malha;
//!
//! // Quem atende:
//! let endpoint = malha::oferecer("imagem.compartilhar")?;
//! for e in malha::receber(&endpoint, None, 10_000)? {
//!     malha::confirmar(&e.id, Some("guardada"))?;
//! }
//!
//! // Quem manda:
//! let candidatos = malha::descobrir("imagem.compartilhar")?;
//! let id = malha::enviar(&candidatos[0].endpoint, "imagem.compartilhar", "/foto.png", 1)?;
//! ```
//!
//! # Outro dispositivo
//!
//! Os mesmos passos de quem manda — procurar, mandar, perguntar o estado,
//! cancelar — vão à malha de outro Duke pelo [`Par`]: `dispositivo:<nome>`,
//! como o registro de dispositivos desta máquina o chama, relacionado à
//! pessoa por quem o processo age. O pedido é decidido aqui — a permissão
//! do passo e `fabric.remote` sobre o dispositivo, com o manifesto
//! declarando as duas — e lá, pelo gate de lá, com o papel da relação, o
//! da pessoa de lá e o teto `remoto`. O que volta é a resposta da malha de
//! lá; a recusa, daqui ou de lá, vem com o código de quem recusou.
//!
//! ```ignore
//! let par = malha::Par("dispositivo:par");
//! let candidatos = par.descobrir("imagem.compartilhar")?;
//! let id = par.enviar(&candidatos[0].endpoint, "imagem.compartilhar", "/foto.png", 1)?;
//! let (estado, resposta) = par.estado(&id)?;
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use crate::nativo::{self, Json, Resposta};

/// Por que um passo da malha não aconteceu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Falha {
    /// A chamada de sistema falhou: o pedido nem chegou ao gate.
    Chamada(i64),
    /// O gate, ou a malha, recusou: o código da política — `DENY_PERMISSION`,
    /// `DENY_RESOURCE`, `DENY_REPLAY`, `CONFLICT`… — e o motivo.
    Recusa { codigo: String, motivo: String },
    /// A resposta não tem a forma esperada.
    Resposta,
}

impl Falha {
    /// O código da recusa, ou o que aconteceu, em uma palavra — o que um
    /// programa diz no log.
    pub fn codigo(&self) -> &str {
        match self {
            Falha::Chamada(_) => "CHAMADA",
            Falha::Recusa { codigo, .. } => codigo,
            Falha::Resposta => "RESPOSTA",
        }
    }
}

/// Um programa que oferece uma intenção, como a descoberta o mostra.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidato {
    pub endpoint: String,
    /// O nome que o manifesto diz.
    pub programa: String,
    /// O resumo BLAKE2s da imagem, em hexadecimal: o que ele é.
    pub resumo: String,
    /// A chave de quem o selou, se veio de fora da imagem.
    pub editor: Option<String>,
}

/// Uma entrega lida.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entrega {
    pub id: String,
    pub intencao: String,
    /// O programa que mandou, com o resumo — `None` se foi a sessão do
    /// titular, sem programa, ou outro dispositivo.
    pub de: Option<(String, String)>,
    /// O dispositivo que mandou, `dispositivo:<nome>` como o registro daqui
    /// o chama — `None` se veio desta máquina. O programa de lá não vem: o
    /// kernel daqui não o conferiu.
    pub dispositivo: Option<String>,
    pub corpo: String,
    pub estado: String,
    pub versao: u64,
}

/// O `result` de uma resposta da malha, ou a recusa — a do gate, que vem
/// como erro do envelope, ou a da malha, que vem como `ok: false`.
fn resultado(r: &Resposta) -> Result<Json<'_>, Falha> {
    match r.resultado() {
        Ok(res) if res.member("ok").and_then(|v| v.as_bool()) == Some(true) => Ok(res),
        Ok(res) => Err(Falha::Recusa {
            codigo: texto(res, "code").unwrap_or_default(),
            motivo: texto(res, "error").unwrap_or_default(),
        }),
        Err(recusa) => Err(Falha::Recusa {
            codigo: String::from(recusa.motivo.unwrap_or("ERROR")),
            motivo: String::from(recusa.mensagem),
        }),
    }
}

/// Um campo de texto, desescapado.
fn texto(j: Json, campo: &str) -> Option<String> {
    let v = j.member(campo)?;
    let mut claro = alloc::vec![0u8; v.0.len()];
    v.desescapar_em(&mut claro).map(String::from)
}

fn pedir(
    metodo: &str,
    params: impl FnOnce(&mut nativo::JsonWriter) -> core::fmt::Result,
) -> Result<Resposta, Falha> {
    nativo::pedir(metodo, params).map_err(Falha::Chamada)
}

/// Oferece `intencao`: o endpoint por onde as entregas chegam. O mesmo
/// processo oferecendo a mesma de novo recebe o mesmo.
pub fn oferecer(intencao: &str) -> Result<String, Falha> {
    let r = pedir("fabric.offer", |w| w.field_str("intent", intencao))?;
    let res = resultado(&r)?;
    texto(res, "endpoint").ok_or(Falha::Resposta)
}

/// Fecha o endpoint: o que esperava nele é anulado. Devolve quantas.
pub fn retirar(endpoint: &str) -> Result<u64, Falha> {
    let r = pedir("fabric.withdraw", |w| w.field_str("endpoint", endpoint))?;
    let res = resultado(&r)?;
    res.member("voided")
        .and_then(|v| v.as_u64())
        .ok_or(Falha::Resposta)
}

/// Quem oferece `intencao`, entre os programas do mesmo titular.
pub fn descobrir(intencao: &str) -> Result<Vec<Candidato>, Falha> {
    let r = pedir("fabric.discover", |w| w.field_str("intent", intencao))?;
    candidatos(resultado(&r)?)
}

/// Os candidatos de uma resposta do `fabric.discover`.
fn candidatos(res: Json) -> Result<Vec<Candidato>, Falha> {
    let lista = res.member("endpoints").ok_or(Falha::Resposta)?;
    let mut v = Vec::new();
    for e in (0..).map_while(|i| lista.item(i)) {
        v.push(Candidato {
            endpoint: texto(e, "endpoint").ok_or(Falha::Resposta)?,
            programa: texto(e, "program").ok_or(Falha::Resposta)?,
            resumo: texto(e, "digest").ok_or(Falha::Resposta)?,
            editor: texto(e, "publisher"),
        });
    }
    Ok(v)
}

/// Entrega `corpo` ao `endpoint`, que oferece `intencao`. O `nonce` cresce
/// a cada envio do processo; o mesmo, com o mesmo conteúdo, é o reenvio, e
/// devolve o mesmo id.
pub fn enviar(endpoint: &str, intencao: &str, corpo: &str, nonce: u64) -> Result<String, Falha> {
    let r = pedir("fabric.send", |w| {
        w.field_str("endpoint", endpoint)?;
        w.field_str("intent", intencao)?;
        w.field_str("body", corpo)?;
        w.field_u64("nonce", nonce)
    })?;
    let res = resultado(&r)?;
    texto(res, "id").ok_or(Falha::Resposta)
}

/// As entregas que esperam no `endpoint`, depois de `apos`. Com `espera_ms`
/// maior que zero, sem nada novo, o pedido espera uma chegar — até dez
/// segundos — e é decidido de novo antes de responder.
pub fn receber(endpoint: &str, apos: Option<&str>, espera_ms: u64) -> Result<Vec<Entrega>, Falha> {
    let r = pedir("fabric.recv", |w| {
        w.field_str("endpoint", endpoint)?;
        if let Some(a) = apos {
            w.field_str("after", a)?;
        }
        if espera_ms > 0 {
            w.field_u64("wait", espera_ms)?;
        }
        Ok(())
    })?;
    let res = resultado(&r)?;
    let lista = res.member("deliveries").ok_or(Falha::Resposta)?;
    let mut v = Vec::new();
    for e in (0..).map_while(|i| lista.item(i)) {
        let de = e
            .member("from")
            .filter(|d| !d.is_null())
            .and_then(|d| Some((texto(d, "program")?, texto(d, "digest")?)));
        v.push(Entrega {
            id: texto(e, "id").ok_or(Falha::Resposta)?,
            intencao: texto(e, "intent").ok_or(Falha::Resposta)?,
            de,
            dispositivo: texto(e, "device"),
            corpo: texto(e, "body").ok_or(Falha::Resposta)?,
            estado: texto(e, "state").ok_or(Falha::Resposta)?,
            versao: e
                .member("version")
                .and_then(|v| v.as_u64())
                .ok_or(Falha::Resposta)?,
        });
    }
    Ok(v)
}

/// Confirma uma entrega lida, com a resposta opcional para quem mandou.
pub fn confirmar(id: &str, resposta: Option<&str>) -> Result<(), Falha> {
    let r = pedir("fabric.ack", |w| {
        w.field_str("id", id)?;
        if let Some(t) = resposta {
            w.field_str("reply", t)?;
        }
        Ok(())
    })?;
    resultado(&r).map(|_| ())
}

/// Onde está uma entrega que este processo mandou, e a resposta, se quem
/// recebeu confirmou com uma.
pub fn estado(id: &str) -> Result<(String, Option<String>), Falha> {
    let r = pedir("fabric.status", |w| w.field_str("id", id))?;
    let res = resultado(&r)?;
    Ok((
        texto(res, "state").ok_or(Falha::Resposta)?,
        texto(res, "reply"),
    ))
}

/// Cancela uma entrega que este processo mandou, enquanto ninguém a leu.
pub fn cancelar(id: &str) -> Result<String, Falha> {
    let r = pedir("fabric.cancel", |w| w.field_str("id", id))?;
    let res = resultado(&r)?;
    texto(res, "state").ok_or(Falha::Resposta)
}

/// Outro dispositivo, `dispositivo:<nome>`: os passos de quem manda, levados
/// à malha dele pelo enlace — ver o topo do módulo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Par<'a>(pub &'a str);

/// Quantas vezes perguntar de novo por um pedido a outro dispositivo que
/// ainda está a caminho. Quem espera mais que o prazo da espera ouve
/// `CONFLICT`, com o número do pedido, e o pedido segue: perguntar de novo,
/// com os mesmos parâmetros, é esperar por ele, e não mandar outro.
const PERGUNTAS_A_CAMINHO: u32 = 6;

impl Par<'_> {
    /// O pedido a outro dispositivo, perguntado de novo enquanto ele está
    /// a caminho — ver [`PERGUNTAS_A_CAMINHO`].
    fn pedir(
        &self,
        metodo: &str,
        params: impl Fn(&mut nativo::JsonWriter) -> core::fmt::Result,
    ) -> Result<Resposta, Falha> {
        let mut r = pedir(metodo, &params)?;
        for _ in 0..PERGUNTAS_A_CAMINHO {
            if !a_caminho(&r) {
                break;
            }
            r = pedir(metodo, &params)?;
        }
        Ok(r)
    }

    /// Quem oferece `intencao` lá, entre os programas da pessoa da relação.
    pub fn descobrir(&self, intencao: &str) -> Result<Vec<Candidato>, Falha> {
        let r = self.pedir("fabric.discover", |w| {
            w.field_str("intent", intencao)?;
            w.field_str("device", self.0)
        })?;
        candidatos(de_la(&r)?)
    }

    /// Entrega `corpo` ao `endpoint` de lá. O `nonce` é o deste processo,
    /// como no [`enviar`]: o mesmo, com o mesmo conteúdo, é o reenvio, e
    /// devolve o mesmo id.
    pub fn enviar(
        &self,
        endpoint: &str,
        intencao: &str,
        corpo: &str,
        nonce: u64,
    ) -> Result<String, Falha> {
        let r = self.pedir("fabric.send", |w| {
            w.field_str("endpoint", endpoint)?;
            w.field_str("intent", intencao)?;
            w.field_str("body", corpo)?;
            w.field_u64("nonce", nonce)?;
            w.field_str("device", self.0)
        })?;
        texto(de_la(&r)?, "id").ok_or(Falha::Resposta)
    }

    /// Onde está, lá, uma entrega que este processo mandou, e a resposta de
    /// quem a confirmou.
    pub fn estado(&self, id: &str) -> Result<(String, Option<String>), Falha> {
        let r = self.pedir("fabric.status", |w| {
            w.field_str("id", id)?;
            w.field_str("device", self.0)
        })?;
        let res = de_la(&r)?;
        Ok((
            texto(res, "state").ok_or(Falha::Resposta)?,
            texto(res, "reply"),
        ))
    }

    /// Cancela, lá, uma entrega que este processo mandou, enquanto ninguém a
    /// leu.
    pub fn cancelar(&self, id: &str) -> Result<String, Falha> {
        let r = self.pedir("fabric.cancel", |w| {
            w.field_str("id", id)?;
            w.field_str("device", self.0)
        })?;
        texto(de_la(&r)?, "state").ok_or(Falha::Resposta)
    }
}

/// Se a resposta diz que o pedido a outro dispositivo ainda está a caminho:
/// `CONFLICT`, com o número do pedido.
fn a_caminho(r: &Resposta) -> bool {
    matches!(r.resultado(), Ok(res)
        if res.member("ok").and_then(|v| v.as_bool()) == Some(false)
            && texto(res, "code").as_deref() == Some("CONFLICT")
            && res.member("request").is_some())
}

/// O `remote` de uma resposta a outro dispositivo — o que a malha de lá
/// respondeu —, ou a recusa: a do gate daqui e a do enlace vêm como
/// `ok: false` com o código; a do gate de lá também; a da malha de lá vem
/// dentro de `remote`.
fn de_la(r: &Resposta) -> Result<Json<'_>, Falha> {
    let res = match r.resultado() {
        Ok(res) => res,
        Err(recusa) => {
            return Err(Falha::Recusa {
                codigo: String::from(recusa.motivo.unwrap_or("ERROR")),
                motivo: String::from(recusa.mensagem),
            });
        }
    };
    let la = res.member("remote");
    if res.member("ok").and_then(|v| v.as_bool()) == Some(true) {
        return la.ok_or(Falha::Resposta);
    }
    let recusa = la.unwrap_or(res);
    Err(Falha::Recusa {
        codigo: texto(recusa, "code").unwrap_or_default(),
        motivo: texto(recusa, "error").unwrap_or_default(),
    })
}
