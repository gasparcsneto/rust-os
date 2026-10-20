//! A situação de uma chamada (*update*): o corpo da chamada síncrona e o
//! `request_status` de um certificado — **especificação**, *Request:
//! Call*, *Request status* e *Reject codes*.
//!
//! Uma chamada não responde como a consulta: o IC a recebe, ela passa pelo
//! consenso, executa, e o desfecho fica no estado da sub-rede, sob
//! `request_status/<id>`, certificado. O que se lê dali — e só de um
//! certificado já conferido ([`super::certificado`]):
//!
//! - `status`: `received`, `processing`, `replied`, `rejected` ou `done`;
//!   ausente, o pedido é desconhecido — ainda não chegou, ou já saiu do
//!   estado;
//! - com `replied`, `reply`: os bytes da resposta, em Candid;
//! - com `rejected`, `reject_code` (LEB128), `reject_message` e talvez
//!   `error_code`;
//! - `done`: a resposta já foi podada do estado — chegou tarde para lê-la.
//!
//! # A chamada síncrona
//!
//! `POST /api/v4/canister/<id>/call` (**referência**: o `ic-agent`
//! 0.49.2): com HTTP 200, o corpo é `{status: "replied", certificate}` —
//! o certificado com o `request_status` desta chamada — ou
//! `{status: "non_replicated_rejection", reject_code, reject_message,
//! error_code?}`, a recusa que não passou pelo consenso: **sem
//! certificado, e por isso nunca verificada**, e dita à parte; com HTTP
//! 202, nada: a chamada foi aceita, e a situação se acompanha por
//! `read_state`.

use alloc::string::String;
use core::fmt;

use super::arvore::Procura;
use super::cbor::{self, Valor};
use super::certificado::{Certificado, ler_leb128};
use super::resumo::Hash;

/// O que o certificado diz de uma chamada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Situacao<'a> {
    /// O pedido não está no estado: ainda não chegou, ou já saiu.
    Desconhecida,
    /// Recebido, ainda não executado.
    Recebida,
    /// Executando.
    Processando,
    /// Respondida: os bytes da resposta, em Candid.
    Respondida(&'a [u8]),
    /// Recusada, com a prova do certificado.
    Recusada {
        /// O código da recusa.
        codigo: u64,
        /// A mensagem.
        mensagem: &'a str,
        /// O código de erro da implementação, se veio.
        erro: Option<&'a str>,
    },
    /// Concluída, e a resposta já podada do estado.
    Concluida,
}

impl Situacao<'_> {
    /// Se é a situação final de uma chamada: nada mais muda nela.
    pub fn final_(&self) -> bool {
        matches!(
            self,
            Situacao::Respondida(_) | Situacao::Recusada { .. } | Situacao::Concluida
        )
    }

    /// O nome, como a especificação o escreve — `unknown` para a
    /// desconhecida.
    pub fn nome(&self) -> &'static str {
        match self {
            Situacao::Desconhecida => "unknown",
            Situacao::Recebida => "received",
            Situacao::Processando => "processing",
            Situacao::Respondida(_) => "replied",
            Situacao::Recusada { .. } => "rejected",
            Situacao::Concluida => "done",
        }
    }
}

/// Por que o `request_status` de um certificado não se lê.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// O caminho pode estar num galho podado: o certificado não prova nem
    /// que o pedido está, nem que não está.
    Podada,
    /// Um `status` fora dos cinco, ou um campo que falta ou vem fora da
    /// forma.
    Forma,
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Erro::Podada => "request_status num galho podado",
            Erro::Forma => "request_status fora da forma",
        })
    }
}

/// Um valor de `request_status/<id>/<campo>`.
fn campo<'a>(cert: &Certificado<'a>, id: &Hash, nome: &[u8]) -> Procura<'a> {
    cert.arvore.procurar(&[b"request_status", id, nome])
}

/// Um texto obrigatório de `request_status/<id>/<campo>`.
fn texto<'a>(cert: &Certificado<'a>, id: &Hash, nome: &[u8]) -> Result<&'a str, Erro> {
    match campo(cert, id, nome) {
        Procura::Achou(b) => core::str::from_utf8(b).map_err(|_| Erro::Forma),
        Procura::Desconhecida => Err(Erro::Podada),
        _ => Err(Erro::Forma),
    }
}

/// A situação da chamada `id`, pelo certificado `cert` — que quem chama
/// já conferiu. Nada aqui confere assinatura.
pub fn ler<'a>(cert: &Certificado<'a>, id: &Hash) -> Result<Situacao<'a>, Erro> {
    let status = match campo(cert, id, b"status") {
        Procura::Achou(b) => b,
        Procura::Ausente => return Ok(Situacao::Desconhecida),
        Procura::Desconhecida => return Err(Erro::Podada),
        Procura::Erro => return Err(Erro::Forma),
    };
    match status {
        b"received" => Ok(Situacao::Recebida),
        b"processing" => Ok(Situacao::Processando),
        b"done" => Ok(Situacao::Concluida),
        b"replied" => match campo(cert, id, b"reply") {
            Procura::Achou(arg) => Ok(Situacao::Respondida(arg)),
            Procura::Desconhecida => Err(Erro::Podada),
            _ => Err(Erro::Forma),
        },
        b"rejected" => {
            let codigo = match campo(cert, id, b"reject_code") {
                Procura::Achou(b) => ler_leb128(b).ok_or(Erro::Forma)?,
                Procura::Desconhecida => return Err(Erro::Podada),
                _ => return Err(Erro::Forma),
            };
            let mensagem = texto(cert, id, b"reject_message")?;
            let erro = match campo(cert, id, b"error_code") {
                Procura::Achou(b) => Some(core::str::from_utf8(b).map_err(|_| Erro::Forma)?),
                Procura::Ausente => None,
                Procura::Desconhecida => return Err(Erro::Podada),
                Procura::Erro => return Err(Erro::Forma),
            };
            Ok(Situacao::Recusada {
                codigo,
                mensagem,
                erro,
            })
        }
        _ => Err(Erro::Forma),
    }
}

/// O corpo de uma chamada síncrona, com HTTP 200.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Corpo<'a> {
    /// O certificado com o `request_status` da chamada, ainda não
    /// conferido.
    Certificada(&'a [u8]),
    /// A recusa que não passou pelo consenso: sem certificado, e por isso
    /// sem prova nenhuma.
    RecusaNaoReplicada {
        /// O código da recusa.
        codigo: u64,
        /// A mensagem.
        mensagem: String,
        /// O código de erro da implementação, se veio.
        erro: Option<String>,
    },
}

/// Por que o corpo de uma chamada não se lê.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErroDoCorpo {
    /// O CBOR não se lê.
    Cbor(cbor::Erro),
    /// Um `status` desconhecido, ou um campo que falta ou vem do tipo
    /// errado.
    Forma,
}

impl From<cbor::Erro> for ErroDoCorpo {
    fn from(e: cbor::Erro) -> ErroDoCorpo {
        ErroDoCorpo::Cbor(e)
    }
}

impl fmt::Display for ErroDoCorpo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErroDoCorpo::Cbor(e) => write!(f, "corpo da chamada: {e}"),
            ErroDoCorpo::Forma => f.write_str("corpo da chamada fora da forma"),
        }
    }
}

/// Lê o corpo de uma chamada síncrona respondida com HTTP 200. Campos a
/// mais são ignorados, como nas implementações oficiais.
pub fn ler_corpo(bytes: &[u8]) -> Result<Corpo<'_>, ErroDoCorpo> {
    let valor = cbor::ler(bytes)?;
    let status = valor
        .campo("status")
        .and_then(Valor::texto)
        .ok_or(ErroDoCorpo::Forma)?;
    match status {
        "replied" => Ok(Corpo::Certificada(
            valor
                .campo("certificate")
                .and_then(Valor::bytes)
                .ok_or(ErroDoCorpo::Forma)?,
        )),
        "non_replicated_rejection" => {
            let codigo = valor
                .campo("reject_code")
                .and_then(Valor::nat)
                .ok_or(ErroDoCorpo::Forma)?;
            let mensagem = valor
                .campo("reject_message")
                .and_then(Valor::texto)
                .ok_or(ErroDoCorpo::Forma)?;
            let erro = match valor.campo("error_code") {
                Some(v) => Some(String::from(v.texto().ok_or(ErroDoCorpo::Forma)?)),
                None => None,
            };
            Ok(Corpo::RecusaNaoReplicada {
                codigo,
                mensagem: String::from(mensagem),
                erro,
            })
        }
        _ => Err(ErroDoCorpo::Forma),
    }
}

#[cfg(test)]
mod testes;
