//! O agente: a consulta verificada, ponta a ponta, sobre um transporte de
//! quem chama — do anônimo ([`consultar`]), ou assinada por quem tem chave
//! ([`consultar_assinada`]).
//!
//! É a lógica do `ic-agent` para uma *query* com as assinaturas conferidas
//! (`query_inner` e `fetch_subnet_by_canister`, **referência**), síncrona
//! e sem rede:
//!
//! 1. `POST /api/v3/canister/<canister>/read_state` com o caminho
//!    `["subnet"]`: o certificado da sub-rede, conferido até a raiz, com as
//!    faixas e o tempo ([`certificado::verificar`]). Dele saem as chaves
//!    dos nós;
//! 2. `POST /api/v3/canister/<canister>/query` com o envelope da consulta;
//! 3. a resposta, conferida contra os nós do certificado
//!    ([`consulta::verificar`]).
//!
//! Nada é entregue antes do passo 3. O transporte é de quem chama: no
//! Duke, o HTTP do programa sobre a conexão que o gate decidiu
//! (`programas::icp`). O agente não sabe de nome, endereço, TLS ou gate, e
//! não decide nada além do que a resposta prova.
//!
//! # A consulta assinada
//!
//! A [`consultar_assinada`] faz os mesmos três passos, com uma diferença
//! só: a consulta do passo 2 vai assinada pelo [`Assinador`] — a pública
//! dele em DER e a assinatura do id —, e o remetente é o Principal da
//! chave dele. O passo 1 continua do anônimo, porque o caminho `subnet` é
//! público, como na chamada ([`super::atualizacao`]): uma assinatura por
//! consulta. O passo 3 é o mesmo: as assinaturas dos nós prendem a
//! resposta ao id, e o id leva o remetente — a resposta de outra consulta,
//! do anônimo ou de outra chave, não confere.
//!
//! Quem assina não assinou: nada sai, e nada vai do anônimo no lugar.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::VALIDADE_DO_PEDIDO_NS;
use super::atualizacao::Assinador;
use super::cbor::{self, Valor};
use super::certificado::{self, Certificado, Raiz};
use super::consulta::{self, Resposta, Resultado};
use super::pedido::{self, Autenticacao, Consulta, LeituraDeEstado};
use super::principal::Principal;
use super::resumo::Hash;

/// Por onde os pedidos vão: um `POST` com corpo `application/cbor`.
pub trait Transporte {
    /// Por que o transporte falhou.
    type Erro: fmt::Display;

    /// Manda `corpo` em `caminho` e devolve o status e o corpo da resposta.
    fn post(&mut self, caminho: &str, corpo: &[u8]) -> Result<(u16, Vec<u8>), Self::Erro>;
}

/// Em que passo uma consulta estava.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Etapa {
    /// A leitura do certificado da sub-rede.
    LeituraDeEstado,
    /// A consulta.
    Consulta,
}

impl fmt::Display for Etapa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Etapa::LeituraDeEstado => "read_state",
            Etapa::Consulta => "query",
        })
    }
}

/// Por que uma consulta não foi entregue.
#[derive(Debug, PartialEq, Eq)]
pub enum Erro<E> {
    /// O transporte falhou.
    Transporte(Etapa, E),
    /// Um status HTTP que não é 200, com o começo do corpo, só em ASCII.
    Http(Etapa, u16, String),
    /// O pedido não se monta.
    Pedido(pedido::Erro),
    /// A resposta da leitura de estado fora da forma.
    LeituraDeEstado,
    /// O certificado não vale.
    Certificado(certificado::Erro),
    /// A resposta da consulta não vale.
    Consulta(consulta::Erro),
}

impl<E: fmt::Display> fmt::Display for Erro<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Erro::Transporte(etapa, e) => write!(f, "{etapa}: {e}"),
            Erro::Http(etapa, status, corpo) if corpo.is_empty() => {
                write!(f, "{etapa}: HTTP {status}")
            }
            Erro::Http(etapa, status, corpo) => write!(f, "{etapa}: HTTP {status}: {corpo}"),
            Erro::Pedido(e) => write!(f, "pedido: {e}"),
            Erro::LeituraDeEstado => f.write_str("read_state: resposta fora da forma"),
            Erro::Certificado(e) => write!(f, "verificacao: {e}"),
            Erro::Consulta(e) => write!(f, "verificacao: {e}"),
        }
    }
}

/// Por que uma consulta assinada não foi entregue: o que a consulta do
/// anônimo também tem, ou a assinatura que não saiu.
#[derive(Debug, PartialEq, Eq)]
pub enum ErroDaAssinada<E, A> {
    /// O que a consulta do anônimo também tem.
    Consulta(Erro<E>),
    /// Quem assina não assinou: a consulta não saiu.
    Assinatura(A),
}

impl<E, A> From<Erro<E>> for ErroDaAssinada<E, A> {
    fn from(e: Erro<E>) -> Self {
        ErroDaAssinada::Consulta(e)
    }
}

impl<E: fmt::Display, A: fmt::Display> fmt::Display for ErroDaAssinada<E, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErroDaAssinada::Consulta(e) => write!(f, "{e}"),
            ErroDaAssinada::Assinatura(e) => write!(f, "{}: assinatura: {e}", Etapa::Consulta),
        }
    }
}

/// O que o canister fez, já conferido.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Desfecho {
    /// Respondeu: os bytes da resposta, em Candid.
    Respondida(Vec<u8>),
    /// Recusou — uma recusa assinada pelos nós também é verificada.
    Recusada {
        /// O código.
        codigo: u64,
        /// A mensagem.
        mensagem: String,
        /// O código de erro da implementação.
        erro: Option<String>,
    },
}

/// Uma consulta verificada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verificada {
    /// O que o canister fez.
    pub desfecho: Desfecho,
    /// O id do pedido, a que as assinaturas estão presas.
    pub id_do_pedido: Hash,
    /// A sub-rede do canister.
    pub sub_rede: Principal,
    /// Se a sub-rede assinou por delegação da raiz.
    pub delegada: bool,
    /// O tempo do certificado.
    pub tempo_do_certificado_ns: u64,
    /// Quantas assinaturas de nó conferiram.
    pub assinaturas: usize,
    /// Quantos nós o certificado mostra.
    pub nos: usize,
}

/// O caminho de um endpoint do canister.
pub fn caminho(canister: &Principal, endpoint: &str) -> String {
    let mut c = String::from("/api/v3/canister/");
    c.push_str(&canister.texto());
    c.push('/');
    c.push_str(endpoint);
    c
}

/// O começo de um corpo de erro, em ASCII imprimível: o que o servidor
/// disse, sem controle nem terminal.
pub(super) fn trecho(corpo: &[u8]) -> String {
    corpo
        .iter()
        .take(120)
        .map(|b| match b {
            b' '..=b'~' => char::from(*b),
            _ => '?',
        })
        .collect()
}

fn post<T: Transporte>(
    t: &mut T,
    etapa: Etapa,
    caminho: &str,
    corpo: &[u8],
) -> Result<Vec<u8>, Erro<T::Erro>> {
    let (status, resposta) = t
        .post(caminho, corpo)
        .map_err(|e| Erro::Transporte(etapa, e))?;
    if status != 200 {
        return Err(Erro::Http(etapa, status, trecho(&resposta)));
    }
    Ok(resposta)
}

/// Consulta `metodo` de `canister` com `arg` (Candid), como o anônimo, e
/// confere tudo antes de devolver. `agora_ns` é a hora de quem verifica
/// (no Duke, a da regra de `protocolo::usuario::hora`); `nonce`, bytes
/// aleatórios de quem chama, até 32.
pub fn consultar<T: Transporte>(
    t: &mut T,
    raiz: &Raiz,
    canister: &Principal,
    metodo: &str,
    arg: &[u8],
    agora_ns: u64,
    nonce: &[u8],
) -> Result<Verificada, Erro<T::Erro>> {
    let vencimento_ns = agora_ns.saturating_add(VALIDADE_DO_PEDIDO_NS);

    // 1. O certificado da sub-rede do canister.
    let caminhos: [&[&[u8]]; 1] = [&[b"subnet"]];
    let leitura = LeituraDeEstado {
        caminhos: &caminhos,
        remetente: Principal::ANONIMO,
        vencimento_ns,
    };
    let envelope = leitura.envelope().map_err(Erro::Pedido)?;
    let corpo = post(
        t,
        Etapa::LeituraDeEstado,
        &caminho(canister, "read_state"),
        &envelope,
    )?;
    let bytes = cbor::ler(&corpo)
        .ok()
        .as_ref()
        .and_then(|v| v.campo("certificate"))
        .and_then(Valor::bytes)
        .ok_or(Erro::LeituraDeEstado)?;
    let cert = Certificado::ler(bytes).map_err(Erro::Certificado)?;
    let autoridade =
        certificado::verificar(&cert, raiz, canister, agora_ns).map_err(Erro::Certificado)?;

    // 2. A consulta.
    let consulta = Consulta {
        canister: *canister,
        metodo,
        arg,
        remetente: Principal::ANONIMO,
        vencimento_ns,
        nonce: Some(nonce),
    };
    let id_do_pedido = consulta.id().map_err(Erro::Pedido)?;
    let envelope = consulta.envelope().map_err(Erro::Pedido)?;
    let corpo = post(t, Etapa::Consulta, &caminho(canister, "query"), &envelope)?;

    // 3. A resposta, contra os nós do certificado.
    let resposta = Resposta::ler(&corpo).map_err(Erro::Consulta)?;
    let conferida = consulta::verificar(&resposta, &id_do_pedido, &cert, &autoridade, agora_ns)
        .map_err(Erro::Consulta)?;
    let desfecho = match resposta.resultado {
        Resultado::Respondida { arg } => Desfecho::Respondida(Vec::from(arg)),
        Resultado::Recusada {
            codigo,
            mensagem,
            erro,
        } => Desfecho::Recusada {
            codigo,
            mensagem: String::from(mensagem),
            erro: erro.map(String::from),
        },
    };
    Ok(Verificada {
        desfecho,
        id_do_pedido,
        sub_rede: autoridade.sub_rede,
        delegada: autoridade.delegada,
        tempo_do_certificado_ns: autoridade.tempo_ns,
        assinaturas: conferida.assinaturas,
        nos: conferida.nos,
    })
}

/// Consulta `metodo` de `canister` com `arg` (Candid), assinada por
/// `assinador` — o remetente é o Principal da chave dele —, e confere tudo
/// antes de devolver. O resto é o da [`consultar`]: as faixas pelo
/// anônimo, a hora `agora_ns` de quem verifica e o `nonce` de quem chama.
/// Uma assinatura só, a da consulta; se ela não sai, a consulta também não.
#[allow(clippy::too_many_arguments)]
pub fn consultar_assinada<T: Transporte, A: Assinador>(
    t: &mut T,
    assinador: &mut A,
    raiz: &Raiz,
    canister: &Principal,
    metodo: &str,
    arg: &[u8],
    agora_ns: u64,
    nonce: &[u8],
) -> Result<Verificada, ErroDaAssinada<T::Erro, A::Erro>> {
    let vencimento_ns = agora_ns.saturating_add(VALIDADE_DO_PEDIDO_NS);

    // 1. O certificado da sub-rede do canister, pelo anônimo.
    let caminhos: [&[&[u8]]; 1] = [&[b"subnet"]];
    let leitura = LeituraDeEstado {
        caminhos: &caminhos,
        remetente: Principal::ANONIMO,
        vencimento_ns,
    };
    let envelope = leitura.envelope().map_err(Erro::Pedido)?;
    let corpo = post(
        t,
        Etapa::LeituraDeEstado,
        &caminho(canister, "read_state"),
        &envelope,
    )?;
    let bytes = cbor::ler(&corpo)
        .ok()
        .as_ref()
        .and_then(|v| v.campo("certificate"))
        .and_then(Valor::bytes)
        .ok_or(Erro::LeituraDeEstado)?;
    let cert = Certificado::ler(bytes).map_err(Erro::Certificado)?;
    let autoridade =
        certificado::verificar(&cert, raiz, canister, agora_ns).map_err(Erro::Certificado)?;

    // 2. A consulta, assinada: o remetente é o Principal da chave.
    let chave_der = Vec::from(assinador.chave_der());
    let consulta = Consulta {
        canister: *canister,
        metodo,
        arg,
        remetente: Principal::auto_autenticado(&chave_der),
        vencimento_ns,
        nonce: Some(nonce),
    };
    let id_do_pedido = consulta.id_assinada(&chave_der).map_err(Erro::Pedido)?;
    let assinatura = assinador
        .assinar(&id_do_pedido)
        .map_err(ErroDaAssinada::Assinatura)?;
    let autenticacao = Autenticacao {
        chave_der: &chave_der,
        assinatura: &assinatura,
    };
    let envelope = consulta
        .envelope_assinado(&autenticacao)
        .map_err(Erro::Pedido)?;
    let corpo = post(t, Etapa::Consulta, &caminho(canister, "query"), &envelope)?;

    // 3. A resposta, contra os nós do certificado: presa a este id, que
    //    leva o remetente.
    let resposta = Resposta::ler(&corpo).map_err(Erro::Consulta)?;
    let conferida = consulta::verificar(&resposta, &id_do_pedido, &cert, &autoridade, agora_ns)
        .map_err(Erro::Consulta)?;
    let desfecho = match resposta.resultado {
        Resultado::Respondida { arg } => Desfecho::Respondida(Vec::from(arg)),
        Resultado::Recusada {
            codigo,
            mensagem,
            erro,
        } => Desfecho::Recusada {
            codigo,
            mensagem: String::from(mensagem),
            erro: erro.map(String::from),
        },
    };
    Ok(Verificada {
        desfecho,
        id_do_pedido,
        sub_rede: autoridade.sub_rede,
        delegada: autoridade.delegada,
        tempo_do_certificado_ns: autoridade.tempo_ns,
        assinaturas: conferida.assinaturas,
        nos: conferida.nos,
    })
}

#[cfg(test)]
mod testes;
