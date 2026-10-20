//! A resposta de uma consulta e as assinaturas dos nós — **especificação**,
//! *Request: Query call* (`verify_node_signatures`).
//!
//! A resposta vem respondida (`replied`, com o `reply`) ou recusada
//! (`rejected`, com o código, a mensagem e talvez o `error_code`), e com
//! as assinaturas dos nós que a avaliaram. Ela só vale depois que:
//!
//! 1. há ao menos uma assinatura, e não mais que os nós da sub-rede que o
//!    certificado mostra (**referência**: `ic-agent`);
//! 2. cada assinatura tem um carimbo a no máximo [`super::TOLERANCIA_NS`]
//!    da hora de quem verifica, para trás ou para a frente;
//! 3. cada assinatura é de um nó que o certificado, já conferido, põe na
//!    sub-rede que hospeda o canister;
//! 4. cada assinatura confere (ZIP215) sobre `"\x0Bic-response" ·
//!    hash_of_map({status, reply | reject_code, reject_message,
//!    error_code?, timestamp, request_id})` — a resposta, o carimbo e o id
//!    **deste** pedido.
//!
//! Uma recusa assinada também é uma resposta verificada: prova que o
//! canister recusou, não que algo falhou no caminho.

use alloc::vec::Vec;
use core::fmt;

use super::TOLERANCIA_NS;
use super::assinatura;
use super::cbor::{self, Valor};
use super::certificado::{self, Autoridade, Certificado};
use super::principal::Principal;
use super::resumo::{self, Hash};

/// O separador do que um nó assina — **especificação**.
pub const SEPARADOR_DA_RESPOSTA: &[u8; 12] = b"\x0Bic-response";

/// O que o canister fez.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resultado<'a> {
    /// Respondeu: o `arg` do `reply`, em Candid.
    Respondida {
        /// Os bytes da resposta.
        arg: &'a [u8],
    },
    /// Recusou.
    Recusada {
        /// O código da recusa — **especificação**, *Reject codes*.
        codigo: u64,
        /// A mensagem.
        mensagem: &'a str,
        /// O código de erro da implementação, se veio.
        erro: Option<&'a str>,
    },
}

/// Uma assinatura de nó.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssinaturaDeNo<'a> {
    /// Quando o nó assinou, em nanossegundos desde 1970.
    pub tempo_ns: u64,
    /// A assinatura Ed25519.
    pub assinatura: &'a [u8],
    /// O nó.
    pub no: Principal,
}

/// Uma resposta de consulta lida, ainda não conferida.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resposta<'a> {
    /// O resultado.
    pub resultado: Resultado<'a>,
    /// O hash do `reply` inteiro, quando respondida: é ele que entra no
    /// que o nó assina.
    resumo_do_reply: Option<Hash>,
    /// As assinaturas.
    pub assinaturas: Vec<AssinaturaDeNo<'a>>,
}

/// Por que uma resposta não vale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// O CBOR não se lê.
    Cbor(cbor::Erro),
    /// Um campo que falta ou vem do tipo errado.
    Forma,
    /// A chave de um nó no certificado não se lê.
    Certificado(certificado::Erro),
    /// Nenhuma assinatura.
    SemAssinatura,
    /// Mais assinaturas que nós.
    AssinaturasDemais {
        /// Quantas vieram.
        assinaturas: usize,
        /// Quantos nós o certificado mostra.
        nos: usize,
    },
    /// Uma assinatura mais velha que a tolerância.
    AssinaturaVelha {
        /// O carimbo.
        tempo_ns: u64,
        /// A hora de quem verificou.
        agora_ns: u64,
    },
    /// Uma assinatura à frente da tolerância.
    AssinaturaDoFuturo {
        /// O carimbo.
        tempo_ns: u64,
        /// A hora de quem verificou.
        agora_ns: u64,
    },
    /// Uma assinatura de um nó que o certificado não põe na sub-rede.
    NoDeFora(Principal),
    /// Uma assinatura que não confere.
    AssinaturaInvalida(Principal),
}

impl From<cbor::Erro> for Erro {
    fn from(e: cbor::Erro) -> Erro {
        Erro::Cbor(e)
    }
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Erro::Cbor(e) => write!(f, "resposta: {e}"),
            Erro::Forma => f.write_str("resposta da consulta fora da forma"),
            Erro::Certificado(e) => write!(f, "resposta: {e}"),
            Erro::SemAssinatura => f.write_str("resposta sem assinatura de no"),
            Erro::AssinaturasDemais { assinaturas, nos } => {
                write!(f, "{assinaturas} assinaturas para {nos} nos")
            }
            Erro::AssinaturaVelha { tempo_ns, agora_ns } => write!(
                f,
                "assinatura de no velha: {} s antes da hora",
                (agora_ns - tempo_ns) / 1_000_000_000
            ),
            Erro::AssinaturaDoFuturo { tempo_ns, agora_ns } => write!(
                f,
                "assinatura de no do futuro: {} s depois da hora",
                (tempo_ns - agora_ns) / 1_000_000_000
            ),
            Erro::NoDeFora(no) => write!(f, "o no {no} nao e da sub-rede do canister"),
            Erro::AssinaturaInvalida(no) => write!(f, "a assinatura do no {no} nao confere"),
        }
    }
}

impl<'a> Resposta<'a> {
    /// Lê o corpo de uma resposta de consulta. Campos a mais no mapa de
    /// fora são ignorados; o `reply` entra inteiro no que se confere.
    pub fn ler(bytes: &'a [u8]) -> Result<Resposta<'a>, Erro> {
        let corpo = cbor::ler(bytes)?;
        if corpo.mapa().is_none() {
            return Err(Erro::Forma);
        }
        let status = corpo
            .campo("status")
            .and_then(Valor::texto)
            .ok_or(Erro::Forma)?;
        let (resultado, resumo_do_reply) = match status {
            "replied" => {
                let reply = corpo.campo("reply").ok_or(Erro::Forma)?;
                if reply.mapa().is_none() {
                    return Err(Erro::Forma);
                }
                let arg = reply
                    .campo("arg")
                    .and_then(Valor::bytes)
                    .ok_or(Erro::Forma)?;
                (Resultado::Respondida { arg }, Some(resumo::de_valor(reply)))
            }
            "rejected" => {
                let codigo = corpo
                    .campo("reject_code")
                    .and_then(Valor::nat)
                    .ok_or(Erro::Forma)?;
                let mensagem = corpo
                    .campo("reject_message")
                    .and_then(Valor::texto)
                    .ok_or(Erro::Forma)?;
                let erro = match corpo.campo("error_code") {
                    None => None,
                    Some(v) => Some(v.texto().ok_or(Erro::Forma)?),
                };
                (
                    Resultado::Recusada {
                        codigo,
                        mensagem,
                        erro,
                    },
                    None,
                )
            }
            _ => return Err(Erro::Forma),
        };
        let mut assinaturas = Vec::new();
        if let Some(lista) = corpo.campo("signatures") {
            for a in lista.lista().ok_or(Erro::Forma)? {
                let tempo_ns = a
                    .campo("timestamp")
                    .and_then(Valor::nat)
                    .ok_or(Erro::Forma)?;
                let assinatura = a
                    .campo("signature")
                    .and_then(Valor::bytes)
                    .ok_or(Erro::Forma)?;
                let no = a
                    .campo("identity")
                    .and_then(Valor::bytes)
                    .ok_or(Erro::Forma)?;
                assinaturas.push(AssinaturaDeNo {
                    tempo_ns,
                    assinatura,
                    no: Principal::de_bytes(no).map_err(|_| Erro::Forma)?,
                });
            }
        }
        Ok(Resposta {
            resultado,
            resumo_do_reply,
            assinaturas,
        })
    }

    /// O que um nó assina para esta resposta, com este carimbo, a este
    /// pedido.
    pub fn assinavel(&self, id_do_pedido: &Hash, tempo_ns: u64) -> [u8; 44] {
        let mut campos = Vec::with_capacity(6);
        campos.push((resumo::de_texto("timestamp"), resumo::de_nat(tempo_ns)));
        campos.push((
            resumo::de_texto("request_id"),
            resumo::de_bytes(id_do_pedido),
        ));
        match self.resultado {
            Resultado::Respondida { .. } => {
                campos.push((resumo::de_texto("status"), resumo::de_texto("replied")));
                // Sempre presente numa resposta respondida, pela leitura.
                let reply = self.resumo_do_reply.unwrap_or_default();
                campos.push((resumo::de_texto("reply"), reply));
            }
            Resultado::Recusada {
                codigo,
                mensagem,
                erro,
            } => {
                campos.push((resumo::de_texto("status"), resumo::de_texto("rejected")));
                campos.push((resumo::de_texto("reject_code"), resumo::de_nat(codigo)));
                campos.push((
                    resumo::de_texto("reject_message"),
                    resumo::de_texto(mensagem),
                ));
                if let Some(e) = erro {
                    campos.push((resumo::de_texto("error_code"), resumo::de_texto(e)));
                }
            }
        }
        let mut assinavel = [0u8; 44];
        assinavel[..12].copy_from_slice(SEPARADOR_DA_RESPOSTA);
        assinavel[12..].copy_from_slice(&resumo::de_mapa(&campos));
        assinavel
    }
}

/// O que uma resposta conferida prova, além do resultado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Conferida {
    /// Quantas assinaturas conferiram.
    pub assinaturas: usize,
    /// Quantos nós o certificado mostra na sub-rede.
    pub nos: usize,
}

/// Confere as assinaturas de uma resposta contra o certificado já
/// conferido da sub-rede do canister ([`certificado::verificar`]).
pub fn verificar(
    resposta: &Resposta<'_>,
    id_do_pedido: &Hash,
    cert: &Certificado<'_>,
    autoridade: &Autoridade,
    agora_ns: u64,
) -> Result<Conferida, Erro> {
    if resposta.assinaturas.is_empty() {
        return Err(Erro::SemAssinatura);
    }
    let nos = certificado::nos_com_chave(cert, &autoridade.sub_rede);
    if resposta.assinaturas.len() > nos {
        return Err(Erro::AssinaturasDemais {
            assinaturas: resposta.assinaturas.len(),
            nos,
        });
    }
    for a in &resposta.assinaturas {
        if a.tempo_ns.saturating_add(TOLERANCIA_NS) < agora_ns {
            return Err(Erro::AssinaturaVelha {
                tempo_ns: a.tempo_ns,
                agora_ns,
            });
        }
        if a.tempo_ns > agora_ns.saturating_add(TOLERANCIA_NS) {
            return Err(Erro::AssinaturaDoFuturo {
                tempo_ns: a.tempo_ns,
                agora_ns,
            });
        }
        let chave = certificado::chave_do_no(cert, &autoridade.sub_rede, &a.no)
            .map_err(Erro::Certificado)?
            .ok_or(Erro::NoDeFora(a.no))?;
        let assinavel = resposta.assinavel(id_do_pedido, a.tempo_ns);
        if !assinatura::verificar(&chave, &assinavel, a.assinatura) {
            return Err(Erro::AssinaturaInvalida(a.no));
        }
    }
    Ok(Conferida {
        assinaturas: resposta.assinaturas.len(),
        nos,
    })
}

#[cfg(test)]
mod testes;
