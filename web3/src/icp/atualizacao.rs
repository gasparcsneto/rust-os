//! A chamada de atualização (*update*), verificada, sobre um transporte de
//! quem chama — do anônimo, ou assinada por uma identidade com chave.
//!
//! É a lógica do `ic-agent` para um *update* (`update_raw`, `wait` e
//! `verify`, **referência**), síncrona e sem rede, em três pedidos:
//!
//! 1. **as faixas**: `POST /api/v3/canister/<canister>/read_state` de
//!    `["subnet"]`, do anônimo — o certificado da sub-rede do canister,
//!    conferido até a raiz, com as faixas ([`certificado::verificar`]).
//!    É a leitura separada que prova de que sub-rede o canister é, também
//!    quando ele é da sub-rede raiz: o certificado de uma chamada da raiz
//!    não traz as faixas, e sem elas não se confere nada;
//! 2. **a chamada**: `POST /api/v4/canister/<canister>/call` com o
//!    envelope ([`pedido::Chamada`]) — assinado, a chave pública e a
//!    assinatura do id, que o [`Assinador`] faz; do anônimo, sem nada.
//!    Com HTTP 200, o certificado do desfecho, ou a recusa que não passou
//!    pelo consenso; com HTTP 202, nada ainda;
//! 3. **a situação**, enquanto pendente: `POST
//!    /api/v3/canister/<canister>/read_state` de `["request_status",
//!    id]` — [`acompanhar`] —, **assinado de novo a cada leitura**: cada
//!    uma é outro pedido, com outro vencimento, e a especificação só deixa
//!    o remetente da chamada ler a situação dela.
//!
//! Cada certificado — o do corpo da chamada e o de cada leitura da
//! situação — é conferido na sub-rede que o passo 1 provou
//! ([`certificado::verificar_na_sub_rede`]), e só então o
//! `request_status` dele é lido ([`situacao`]). Nada é entregue antes.
//!
//! # Quem assina
//!
//! O [`Assinador`] dá a pública e assina o id; este módulo não vê chave
//! privada nenhuma. No Duke, quem assina é o kernel (`key.sign`), por uma
//! decisão do gate a cada assinatura — a da chamada e a de cada leitura
//! da situação.
//!
//! # O que não há aqui
//!
//! O canister de gerenciamento (`aaaaa-aa`), que pede outro canister
//! efetivo no caminho; delegações; outra chave que não Ed25519 em DER.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::VALIDADE_DO_PEDIDO_NS;
use super::agente::{Transporte, caminho, trecho};
use super::cbor::{self, Valor};
use super::certificado::{self, Autoridade, Certificado, Raiz};
use super::pedido::{self, Autenticacao, Chamada, LeituraDeEstado};
use super::principal::Principal;
use super::resumo::Hash;
use super::situacao::{self, Corpo, Situacao};

/// Quem assina os pedidos de uma identidade com chave.
pub trait Assinador {
    /// Por que a assinatura não saiu.
    type Erro: fmt::Display;

    /// A chave pública, em DER: o remetente é o Principal
    /// auto-autenticado dela.
    fn chave_der(&self) -> &[u8];

    /// A assinatura do id de um pedido: a de `domain_sep("ic-request") ·
    /// id` ([`pedido::assinavel`]).
    fn assinar(&mut self, id: &Hash) -> Result<Vec<u8>, Self::Erro>;
}

/// Em que passo uma chamada estava.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Etapa {
    /// A leitura separada das faixas.
    Faixas,
    /// A chamada.
    Chamada,
    /// Uma leitura da situação.
    Situacao,
}

impl fmt::Display for Etapa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Etapa::Faixas => "subnet",
            Etapa::Chamada => "call",
            Etapa::Situacao => "request_status",
        })
    }
}

/// Por que uma chamada não deu um desfecho verificado.
#[derive(Debug, PartialEq, Eq)]
pub enum Erro<T, A> {
    /// O transporte falhou.
    Transporte(Etapa, T),
    /// Um status HTTP fora do esperado, com o começo do corpo, só em
    /// ASCII.
    Http(Etapa, u16, String),
    /// O pedido não se monta.
    Pedido(pedido::Erro),
    /// Quem assina não assinou: a chamada, ou uma leitura da situação.
    Assinatura(Etapa, A),
    /// A resposta de uma leitura de estado fora da forma.
    LeituraDeEstado(Etapa),
    /// O corpo da chamada fora da forma.
    Corpo(situacao::ErroDoCorpo),
    /// Um certificado que não vale.
    Certificado(Etapa, certificado::Erro),
    /// O `request_status` de um certificado que valeu fora da forma.
    Situacao(Etapa, situacao::Erro),
}

impl<T: fmt::Display, A: fmt::Display> fmt::Display for Erro<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Erro::Transporte(etapa, e) => write!(f, "{etapa}: {e}"),
            Erro::Http(etapa, status, corpo) if corpo.is_empty() => {
                write!(f, "{etapa}: HTTP {status}")
            }
            Erro::Http(etapa, status, corpo) => write!(f, "{etapa}: HTTP {status}: {corpo}"),
            Erro::Pedido(e) => write!(f, "pedido: {e}"),
            Erro::Assinatura(etapa, e) => write!(f, "{etapa}: assinatura: {e}"),
            Erro::LeituraDeEstado(etapa) => write!(f, "{etapa}: resposta fora da forma"),
            Erro::Corpo(e) => write!(f, "call: {e}"),
            Erro::Certificado(etapa, e) => write!(f, "{etapa}: verificacao: {e}"),
            Erro::Situacao(etapa, e) => write!(f, "{etapa}: verificacao: {e}"),
        }
    }
}

/// O desfecho final de uma chamada, como um certificado o prova.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Final {
    /// Respondida: os bytes da resposta, em Candid.
    Respondida(Vec<u8>),
    /// Recusada pelo canister ou pelo sistema, com a prova do certificado.
    Recusada {
        /// O código.
        codigo: u64,
        /// A mensagem.
        mensagem: String,
        /// O código de erro da implementação.
        erro: Option<String>,
    },
    /// Executou, e a resposta já foi podada do estado: o certificado
    /// prova que acabou, e não mais o quê.
    Concluida,
}

/// Até onde uma chamada chegou.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Andamento {
    /// O desfecho final, verificado: o certificado e o tempo dele.
    Certificado {
        /// O desfecho.
        desfecho: Final,
        /// O tempo do certificado que o prova.
        tempo_ns: u64,
    },
    /// A recusa que não passou pelo consenso: **nenhuma prova** — o nó que
    /// respondeu poderia dizer qualquer coisa. Dita à parte, nunca como
    /// verificada.
    RecusaNaoReplicada {
        /// O código.
        codigo: u64,
        /// A mensagem.
        mensagem: String,
        /// O código de erro da implementação.
        erro: Option<String>,
    },
    /// Ainda sem desfecho: a situação certificada (`received`,
    /// `processing`), `unknown` — o pedido não está no estado —, ou
    /// `accepted`, a resposta 202 da chamada, que não prova nada. Segue-se
    /// com [`acompanhar`].
    Pendente(&'static str),
}

/// Uma chamada feita.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Atualizacao {
    /// O canister.
    pub canister: Principal,
    /// O id do pedido: o que se assinou, e o que a situação procura.
    pub id_do_pedido: Hash,
    /// Quem chamou: o anônimo, ou o Principal da chave.
    pub remetente: Principal,
    /// A sub-rede do canister, pela leitura separada das faixas.
    pub faixas: Autoridade,
    /// Até onde ela chegou.
    pub andamento: Andamento,
    /// A validade da última leitura da situação: a seguinte vai além dela
    /// — ver [`acompanhar`].
    validade_da_ultima_leitura_ns: u64,
}

/// O certificado de uma resposta de `read_state`.
fn certificado_da_leitura(corpo: &[u8]) -> Option<&[u8]> {
    cbor::ler(corpo)
        .ok()
        .as_ref()
        .and_then(|v| v.campo("certificate"))
        .and_then(Valor::bytes)
}

/// O andamento que um certificado conferido prova.
fn andamento(
    cert: &Certificado<'_>,
    id: &Hash,
    tempo_ns: u64,
) -> Result<Andamento, situacao::Erro> {
    let desfecho = match situacao::ler(cert, id)? {
        Situacao::Respondida(arg) => Final::Respondida(Vec::from(arg)),
        Situacao::Recusada {
            codigo,
            mensagem,
            erro,
        } => Final::Recusada {
            codigo,
            mensagem: String::from(mensagem),
            erro: erro.map(String::from),
        },
        Situacao::Concluida => Final::Concluida,
        outra => return Ok(Andamento::Pendente(outra.nome())),
    };
    Ok(Andamento::Certificado { desfecho, tempo_ns })
}

/// A pública em DER e a assinatura do id, de quem assinou; nada, do
/// anônimo.
type Assinado = Option<(Vec<u8>, Vec<u8>)>;

/// A autenticação de um pedido: o id assinado por `assinador`, ou nada,
/// do anônimo.
fn autenticar<A: Assinador>(assinador: Option<&mut A>, id: &Hash) -> Result<Assinado, A::Erro> {
    match assinador {
        None => Ok(None),
        Some(a) => {
            let assinatura = a.assinar(id)?;
            Ok(Some((Vec::from(a.chave_der()), assinatura)))
        }
    }
}

/// Quem chama: o Principal da chave de `assinador`, ou o anônimo.
fn remetente<A: Assinador>(assinador: &Option<&mut A>) -> Principal {
    match assinador {
        Some(a) => Principal::auto_autenticado(a.chave_der()),
        None => Principal::ANONIMO,
    }
}

/// Chama `metodo` de `canister` com `arg` (Candid) — assinado por
/// `assinador`, ou do anônimo sem ele — e confere o que voltou contra a
/// raiz `raiz` com a hora `agora_ns` (a de quem verifica; no Duke, a da
/// regra de `protocolo::usuario::hora`). `nonce`, bytes aleatórios de
/// quem chama, até 32: duas chamadas iguais no mesmo minuto seriam o mesmo
/// pedido, e executariam uma vez só.
#[allow(clippy::too_many_arguments)]
pub fn chamar<T: Transporte, A: Assinador>(
    t: &mut T,
    assinador: Option<&mut A>,
    raiz: &Raiz,
    canister: &Principal,
    metodo: &str,
    arg: &[u8],
    agora_ns: u64,
    nonce: &[u8],
) -> Result<Atualizacao, Erro<T::Erro, A::Erro>> {
    let vencimento_ns = agora_ns.saturating_add(VALIDADE_DO_PEDIDO_NS);

    // 1. As faixas: de que sub-rede o canister é, provado até a raiz.
    let caminhos: [&[&[u8]]; 1] = [&[b"subnet"]];
    let leitura = LeituraDeEstado {
        caminhos: &caminhos,
        remetente: Principal::ANONIMO,
        vencimento_ns,
    };
    let envelope = leitura.envelope().map_err(Erro::Pedido)?;
    let (status, corpo) = t
        .post(&caminho(canister, "read_state"), &envelope)
        .map_err(|e| Erro::Transporte(Etapa::Faixas, e))?;
    if status != 200 {
        return Err(Erro::Http(Etapa::Faixas, status, trecho(&corpo)));
    }
    let bytes = certificado_da_leitura(&corpo).ok_or(Erro::LeituraDeEstado(Etapa::Faixas))?;
    let cert = Certificado::ler(bytes).map_err(|e| Erro::Certificado(Etapa::Faixas, e))?;
    let faixas = certificado::verificar(&cert, raiz, canister, agora_ns)
        .map_err(|e| Erro::Certificado(Etapa::Faixas, e))?;

    // 2. A chamada, assinada ou do anônimo.
    let remetente = remetente(&assinador);
    let chamada = Chamada {
        canister: *canister,
        metodo,
        arg,
        remetente,
        vencimento_ns,
        nonce: Some(nonce),
    };
    let id_do_pedido = chamada.id().map_err(Erro::Pedido)?;
    let assinado =
        autenticar(assinador, &id_do_pedido).map_err(|e| Erro::Assinatura(Etapa::Chamada, e))?;
    let autenticacao = assinado.as_ref().map(|(chave, assinatura)| Autenticacao {
        chave_der: chave,
        assinatura,
    });
    let envelope = chamada
        .envelope(autenticacao.as_ref())
        .map_err(Erro::Pedido)?;
    let (status, corpo) = t
        .post(&caminho_v4(canister), &envelope)
        .map_err(|e| Erro::Transporte(Etapa::Chamada, e))?;
    let andamento = match status {
        202 => Andamento::Pendente("accepted"),
        200 => match situacao::ler_corpo(&corpo).map_err(Erro::Corpo)? {
            Corpo::RecusaNaoReplicada {
                codigo,
                mensagem,
                erro,
            } => Andamento::RecusaNaoReplicada {
                codigo,
                mensagem,
                erro,
            },
            Corpo::Certificada(bytes) => {
                let cert =
                    Certificado::ler(bytes).map_err(|e| Erro::Certificado(Etapa::Chamada, e))?;
                let a =
                    certificado::verificar_na_sub_rede(&cert, raiz, canister, agora_ns, &faixas)
                        .map_err(|e| Erro::Certificado(Etapa::Chamada, e))?;
                andamento(&cert, &id_do_pedido, a.tempo_ns)
                    .map_err(|e| Erro::Situacao(Etapa::Chamada, e))?
            }
        },
        outro => return Err(Erro::Http(Etapa::Chamada, outro, trecho(&corpo))),
    };
    Ok(Atualizacao {
        canister: *canister,
        id_do_pedido,
        remetente,
        faixas,
        andamento,
        validade_da_ultima_leitura_ns: 0,
    })
}

/// O caminho da chamada síncrona — **referência**: `/api/v4`, o do
/// `ic-agent` 0.49.2.
fn caminho_v4(canister: &Principal) -> String {
    let mut c = String::from("/api/v4/canister/");
    c.push_str(&canister.texto());
    c.push_str("/call");
    c
}

/// Lê a situação de uma chamada pendente, uma vez: o `read_state` de
/// `["request_status", id]`, assinado de novo por `assinador` — que tem de
/// ser o da chamada: a especificação só deixa o remetente dela ler a
/// situação —, ou do anônimo, e o certificado conferido na sub-rede das
/// faixas da chamada. Quem chama decide quantas vezes, e quanto espera
/// entre elas.
///
/// Cada leitura é outro pedido, assinado de novo: a leitura vai sem nonce,
/// como a do `ic-agent` — o `ic-transport-types` nem tem o campo —, e a
/// validade dela vai além da da leitura anterior, um nanossegundo se a hora
/// não andou. Sem isso, duas leituras na mesma hora de quem chama — que o
/// Duke dá em segundos — seriam o mesmo pedido, e a mesma assinatura.
pub fn acompanhar<T: Transporte, A: Assinador>(
    t: &mut T,
    assinador: Option<&mut A>,
    raiz: &Raiz,
    chamada: &mut Atualizacao,
    agora_ns: u64,
) -> Result<Andamento, Erro<T::Erro, A::Erro>> {
    let remetente = remetente(&assinador);
    if remetente != chamada.remetente {
        return Err(Erro::Pedido(pedido::Erro::RemetenteNaoEDaChave));
    }
    let vencimento_ns = agora_ns
        .saturating_add(VALIDADE_DO_PEDIDO_NS)
        .max(chamada.validade_da_ultima_leitura_ns.saturating_add(1));
    chamada.validade_da_ultima_leitura_ns = vencimento_ns;
    let id = &chamada.id_do_pedido;
    let caminhos: [&[&[u8]]; 1] = [&[b"request_status", id]];
    let leitura = LeituraDeEstado {
        caminhos: &caminhos,
        remetente,
        vencimento_ns,
    };
    let id_da_leitura = leitura.id().map_err(Erro::Pedido)?;
    let assinado =
        autenticar(assinador, &id_da_leitura).map_err(|e| Erro::Assinatura(Etapa::Situacao, e))?;
    let autenticacao = assinado.as_ref().map(|(chave, assinatura)| Autenticacao {
        chave_der: chave,
        assinatura,
    });
    let envelope = leitura
        .envelope_assinado(autenticacao.as_ref())
        .map_err(Erro::Pedido)?;
    let (status, corpo) = t
        .post(&caminho(&chamada.canister, "read_state"), &envelope)
        .map_err(|e| Erro::Transporte(Etapa::Situacao, e))?;
    if status != 200 {
        return Err(Erro::Http(Etapa::Situacao, status, trecho(&corpo)));
    }
    let bytes = certificado_da_leitura(&corpo).ok_or(Erro::LeituraDeEstado(Etapa::Situacao))?;
    let cert = Certificado::ler(bytes).map_err(|e| Erro::Certificado(Etapa::Situacao, e))?;
    let a = certificado::verificar_na_sub_rede(
        &cert,
        raiz,
        &chamada.canister,
        agora_ns,
        &chamada.faixas,
    )
    .map_err(|e| Erro::Certificado(Etapa::Situacao, e))?;
    andamento(&cert, id, a.tempo_ns).map_err(|e| Erro::Situacao(Etapa::Situacao, e))
}

#[cfg(test)]
mod testes;
