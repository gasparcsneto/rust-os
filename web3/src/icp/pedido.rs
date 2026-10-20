//! Os pedidos: a consulta (*query*) e a leitura de estado (`read_state`),
//! o id de cada um e o envelope em que vão.
//!
//! **Especificação** (*Request: Query call*, *Request: Read state*,
//! *Authentication*, *Request ids*): o corpo HTTP é `55799({"content":
//! {…}})`. O conteúdo traz `request_type`, `sender`, `ingress_expiry` e,
//! conforme o tipo, `canister_id`, `method_name` e `arg`, ou `paths`; o
//! `nonce` é opcional. O id do pedido é o hash independente de
//! representação do conteúdo ([`super::resumo`]).
//!
//! Só o remetente anônimo existe aqui: sem `sender_pubkey`, `sender_sig`
//! nem `sender_delegation` no envelope, que a especificação manda omitir
//! para ele. Uma identidade com chave é outro incremento.
//!
//! # O nonce da consulta
//!
//! A consulta leva um nonce de quem chama (no programa, do `random.read`).
//! Sem ele, duas consultas iguais no mesmo minuto teriam o mesmo id — o
//! `ic-agent` arredonda o vencimento ao minuto e não põe nonce em
//! consulta —, e a assinatura de uma resposta antiga, ainda fresca, valeria
//! para a nova. Com ele, a assinatura do nó fica presa a este pedido.
//! A leitura de estado não precisa: o certificado fala do estado, não do
//! pedido (**referência**: o `ic-agent` também não põe).

use alloc::vec::Vec;

use super::cbor::Escritor;
use super::principal::Principal;
use super::resumo::{self, Hash};

/// O maior nonce — **especificação**: "at most 32 bytes".
pub const MAIOR_NONCE: usize = 32;

/// O conteúdo de uma consulta.
#[derive(Clone, Copy, Debug)]
pub struct Consulta<'a> {
    /// O canister chamado.
    pub canister: Principal,
    /// O método.
    pub metodo: &'a str,
    /// O argumento, em Candid.
    pub arg: &'a [u8],
    /// Quem pede: no ICP-1, sempre o anônimo.
    pub remetente: Principal,
    /// Até quando o pedido vale, em nanossegundos desde 1970.
    pub vencimento_ns: u64,
    /// O nonce, de até [`MAIOR_NONCE`] bytes.
    pub nonce: Option<&'a [u8]>,
}

/// O conteúdo de uma leitura de estado.
#[derive(Clone, Copy, Debug)]
pub struct LeituraDeEstado<'a> {
    /// Os caminhos pedidos: cada um, uma sequência de rótulos.
    pub caminhos: &'a [&'a [&'a [u8]]],
    /// Quem pede: no ICP-1, sempre o anônimo.
    pub remetente: Principal,
    /// Até quando o pedido vale, em nanossegundos desde 1970.
    pub vencimento_ns: u64,
}

/// Por que um pedido não se monta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// O nonce passa de [`MAIOR_NONCE`] bytes.
    NonceLongo,
    /// Um remetente com chave: o ICP-1 só monta o anônimo.
    RemetenteNaoAnonimo,
}

impl core::fmt::Display for Erro {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Erro::NonceLongo => "nonce com mais de 32 bytes",
            Erro::RemetenteNaoAnonimo => "so o remetente anonimo pede sem assinar",
        })
    }
}

impl Consulta<'_> {
    fn conferir(&self) -> Result<(), Erro> {
        if self.nonce.is_some_and(|n| n.len() > MAIOR_NONCE) {
            return Err(Erro::NonceLongo);
        }
        if self.remetente != Principal::ANONIMO {
            return Err(Erro::RemetenteNaoAnonimo);
        }
        Ok(())
    }

    /// O id do pedido: o hash do conteúdo.
    pub fn id(&self) -> Result<Hash, Erro> {
        self.conferir()?;
        let mut campos = Vec::with_capacity(7);
        campos.push((resumo::de_texto("request_type"), resumo::de_texto("query")));
        campos.push((
            resumo::de_texto("canister_id"),
            resumo::de_bytes(self.canister.bytes()),
        ));
        campos.push((
            resumo::de_texto("method_name"),
            resumo::de_texto(self.metodo),
        ));
        campos.push((resumo::de_texto("arg"), resumo::de_bytes(self.arg)));
        campos.push((
            resumo::de_texto("sender"),
            resumo::de_bytes(self.remetente.bytes()),
        ));
        campos.push((
            resumo::de_texto("ingress_expiry"),
            resumo::de_nat(self.vencimento_ns),
        ));
        if let Some(n) = self.nonce {
            campos.push((resumo::de_texto("nonce"), resumo::de_bytes(n)));
        }
        Ok(resumo::de_mapa(&campos))
    }

    /// O corpo HTTP: o envelope, em CBOR.
    pub fn envelope(&self) -> Result<Vec<u8>, Erro> {
        self.conferir()?;
        let mut e = Escritor::novo();
        e.autodescrita();
        e.mapa(1);
        e.texto("content");
        e.mapa(if self.nonce.is_some() { 7 } else { 6 });
        e.texto("request_type");
        e.texto("query");
        e.texto("canister_id");
        e.bytes(self.canister.bytes());
        e.texto("method_name");
        e.texto(self.metodo);
        e.texto("arg");
        e.bytes(self.arg);
        e.texto("sender");
        e.bytes(self.remetente.bytes());
        e.texto("ingress_expiry");
        e.nat(self.vencimento_ns);
        if let Some(n) = self.nonce {
            e.texto("nonce");
            e.bytes(n);
        }
        Ok(e.terminar())
    }
}

impl LeituraDeEstado<'_> {
    fn conferir(&self) -> Result<(), Erro> {
        if self.remetente != Principal::ANONIMO {
            return Err(Erro::RemetenteNaoAnonimo);
        }
        Ok(())
    }

    /// O id do pedido: o hash do conteúdo. Os caminhos são uma lista de
    /// listas de rótulos.
    pub fn id(&self) -> Result<Hash, Erro> {
        self.conferir()?;
        let caminhos = resumo::de_lista(
            self.caminhos
                .iter()
                .map(|c| resumo::de_lista(c.iter().map(|r| resumo::de_bytes(r)))),
        );
        Ok(resumo::de_mapa(&[
            (
                resumo::de_texto("request_type"),
                resumo::de_texto("read_state"),
            ),
            (resumo::de_texto("paths"), caminhos),
            (
                resumo::de_texto("sender"),
                resumo::de_bytes(self.remetente.bytes()),
            ),
            (
                resumo::de_texto("ingress_expiry"),
                resumo::de_nat(self.vencimento_ns),
            ),
        ]))
    }

    /// O corpo HTTP: o envelope, em CBOR.
    pub fn envelope(&self) -> Result<Vec<u8>, Erro> {
        self.conferir()?;
        let mut e = Escritor::novo();
        e.autodescrita();
        e.mapa(1);
        e.texto("content");
        e.mapa(4);
        e.texto("request_type");
        e.texto("read_state");
        e.texto("paths");
        e.lista(self.caminhos.len());
        for caminho in self.caminhos {
            e.lista(caminho.len());
            for rotulo in *caminho {
                e.bytes(rotulo);
            }
        }
        e.texto("sender");
        e.bytes(self.remetente.bytes());
        e.texto("ingress_expiry");
        e.nat(self.vencimento_ns);
        Ok(e.terminar())
    }
}

#[cfg(test)]
mod testes;
