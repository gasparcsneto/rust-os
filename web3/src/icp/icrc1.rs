//! O ICRC-1 — **especificação**: `dfinity/ICRC-1`,
//! `standards/ICRC-1/README.md`; **referência**: `icrc-ledger-types` 0.2.0
//! —: a conta, a transferência e o resultado dela, e o saldo, como um
//! ledger do IC os recebe e devolve em Candid.
//!
//! - [`argumento_da_transferencia`] e [`argumento_do_saldo`] escrevem o
//!   argumento de `icrc1_transfer` (`TransferArg`) e de `icrc1_balance_of`
//!   (`Account`), com o tipo de cada campo ([`candid::codificar_com_tipos`]);
//! - [`ler_transferencia`] e [`ler_saldo`] leem a resposta, os campos pelo
//!   nome: o bloco, ou a recusa do ledger pelo nome do padrão ([`Recusa`]).
//!   O que não tem a forma do ICRC-1 — outro tipo, um caso que o padrão
//!   não tem — é recusado, e nunca vira bloco nem saldo.
//!
//! # A repetição
//!
//! O ledger deduplica uma transferência com `created_at_time`: a mesma —
//! a mesma conta de origem, o mesmo destino, a mesma quantia, a mesma taxa,
//! o mesmo `memo` e o mesmo `created_at_time` — dentro da janela dele
//! (24 h) volta [`Recusa::Duplicada`] com o bloco da primeira, e não
//! executa. Sem `created_at_time`, executa de novo. Quem transfere põe
//! sempre o `created_at_time`, e repete com os mesmos argumentos.
//!
//! Nada aqui assina, conecta ou verifica: a resposta que se lê é a que a
//! chamada verificada entregou ([`super::atualizacao`]).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::candid::{self, Primitivo, Tipo, Valor};
use super::principal::Principal;

/// O tamanho de uma subconta.
pub const SUBCONTA: usize = 32;

/// O maior `memo` que o ledger de ICP aceita — o padrão pede que um ledger
/// aceite ao menos este.
pub const MAIOR_MEMO: usize = 32;

/// Uma conta: o dono e a subconta — sem ela, a de zeros.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Conta {
    /// O dono.
    pub dono: Principal,
    /// A subconta.
    pub subconta: Option<[u8; SUBCONTA]>,
}

/// Uma transferência — `TransferArg`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transferencia {
    /// A subconta de origem, de quem chama.
    pub de_subconta: Option<[u8; SUBCONTA]>,
    /// O destino.
    pub para: Conta,
    /// A quantia, na menor unidade do ledger (e8s no de ICP).
    pub quantia: u128,
    /// A taxa; sem ela, a do ledger.
    pub taxa: Option<u128>,
    /// O `memo`, até [`MAIOR_MEMO`] bytes.
    pub memo: Option<Vec<u8>>,
    /// O `created_at_time`, em nanossegundos desde a época: o que deduplica
    /// a repetição.
    pub criada_em_ns: Option<u64>,
}

/// Por que o ledger recusou uma transferência — `TransferError`, pelo
/// nome do padrão. É a resposta do ledger, provada pelo certificado da
/// chamada: recusada, e verificada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// `BadFee`: a taxa não é a do ledger.
    TaxaErrada {
        /// A do ledger.
        esperada: u128,
    },
    /// `BadBurn`: a queima abaixo do mínimo.
    QueimaPequena {
        /// O mínimo.
        minima: u128,
    },
    /// `InsufficientFunds`: o saldo não cobre a quantia e a taxa.
    SemFundos {
        /// O saldo.
        saldo: u128,
    },
    /// `TooOld`: o `created_at_time` antes da janela.
    Velha,
    /// `CreatedInFuture`: o `created_at_time` depois da hora do ledger.
    NoFuturo {
        /// A hora do ledger, em nanossegundos.
        hora_do_ledger_ns: u64,
    },
    /// `TemporarilyUnavailable`.
    Indisponivel,
    /// `Duplicate`: a mesma transferência já executou, neste bloco.
    Duplicada {
        /// O bloco da primeira.
        bloco: u128,
    },
    /// `GenericError`.
    Generica {
        /// O código.
        codigo: u128,
        /// A mensagem.
        mensagem: String,
    },
}

impl fmt::Display for Recusa {
    /// O nome do padrão e o que o acompanha, em ASCII: a mensagem de um
    /// ledger não escreve controle na saída de um programa.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Recusa::TaxaErrada { esperada } => write!(f, "BadFee expected_fee {esperada}"),
            Recusa::QueimaPequena { minima } => write!(f, "BadBurn min_burn_amount {minima}"),
            Recusa::SemFundos { saldo } => write!(f, "InsufficientFunds balance {saldo}"),
            Recusa::Velha => f.write_str("TooOld"),
            Recusa::NoFuturo { hora_do_ledger_ns } => {
                write!(f, "CreatedInFuture ledger_time {hora_do_ledger_ns}")
            }
            Recusa::Indisponivel => f.write_str("TemporarilyUnavailable"),
            Recusa::Duplicada { bloco } => write!(f, "Duplicate duplicate_of {bloco}"),
            Recusa::Generica { codigo, mensagem } => {
                write!(f, "GenericError error_code {codigo} message ")?;
                fmt::Display::fmt(&Valor::Texto(mensagem.clone()), f)
            }
        }
    }
}

/// Por que um argumento não se escreve, ou uma resposta não se lê.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// Um `memo` de mais de [`MAIOR_MEMO`] bytes: o ledger o recusaria.
    MemoGrande,
    /// A resposta não é Candid.
    Candid(candid::Erro),
    /// A resposta é Candid, mas não tem a forma do ICRC-1.
    Forma,
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Erro::MemoGrande => f.write_str("memo icrc-1 maior que 32 bytes"),
            Erro::Candid(e) => write!(f, "{e}"),
            Erro::Forma => f.write_str("resposta fora da forma do icrc-1"),
        }
    }
}

/// `opt blob`.
fn opt_blob() -> Tipo {
    Tipo::opt(Tipo::blob())
}

/// `Account`: `record { owner : principal; subaccount : opt blob }`.
fn tipo_da_conta() -> Tipo {
    Tipo::record([
        ("owner", Primitivo::Principal.into()),
        ("subaccount", opt_blob()),
    ])
}

/// `TransferArg`.
fn tipo_da_transferencia() -> Tipo {
    Tipo::record([
        ("from_subaccount", opt_blob()),
        ("to", tipo_da_conta()),
        ("amount", Primitivo::Nat.into()),
        ("fee", Tipo::opt(Primitivo::Nat)),
        ("memo", opt_blob()),
        ("created_at_time", Tipo::opt(Primitivo::Nat64)),
    ])
}

/// Um campo pelo nome.
fn campo(nome: &str, v: Valor) -> (u32, Valor) {
    (candid::id_do_campo(nome), v)
}

/// `opt v`.
fn opt(v: Option<Valor>) -> Valor {
    Valor::Opt(v.map(alloc::boxed::Box::new))
}

fn subconta(s: &Option<[u8; SUBCONTA]>) -> Valor {
    opt(s.map(|s| Valor::Blob(Vec::from(s))))
}

fn valor_da_conta(c: &Conta) -> Valor {
    Valor::Record(alloc::vec![
        campo("owner", Valor::Principal(c.dono)),
        campo("subaccount", subconta(&c.subconta)),
    ])
}

/// Escreve o argumento de `icrc1_transfer`: `(TransferArg)`.
pub fn argumento_da_transferencia(t: &Transferencia) -> Result<Vec<u8>, Erro> {
    if t.memo.as_ref().is_some_and(|m| m.len() > MAIOR_MEMO) {
        return Err(Erro::MemoGrande);
    }
    let valor = Valor::Record(alloc::vec![
        campo("from_subaccount", subconta(&t.de_subconta)),
        campo("to", valor_da_conta(&t.para)),
        campo("amount", Valor::Nat(t.quantia)),
        campo("fee", opt(t.taxa.map(Valor::Nat))),
        campo("memo", opt(t.memo.clone().map(Valor::Blob))),
        campo("created_at_time", opt(t.criada_em_ns.map(Valor::Nat64))),
    ]);
    Ok(escrever(tipo_da_transferencia(), valor))
}

/// Escreve o argumento de `icrc1_balance_of`: `(Account)`.
pub fn argumento_do_saldo(c: &Conta) -> Vec<u8> {
    escrever(tipo_da_conta(), valor_da_conta(c))
}

/// Um argumento dos tipos daqui: o valor é sempre do tipo.
fn escrever(tipo: Tipo, valor: Valor) -> Vec<u8> {
    candid::codificar_com_tipos(&[tipo], &[valor]).expect("o valor e do tipo daqui")
}

/// O único valor de uma resposta.
fn unico(resposta: &[u8]) -> Result<Valor, Erro> {
    let mut valores = candid::decodificar(resposta).map_err(Erro::Candid)?;
    match valores.len() {
        1 => Ok(valores.remove(0)),
        _ => Err(Erro::Forma),
    }
}

/// Um `nat`.
fn nat(v: Option<&Valor>) -> Result<u128, Erro> {
    match v {
        Some(Valor::Nat(n)) => Ok(*n),
        _ => Err(Erro::Forma),
    }
}

/// Lê a resposta de `icrc1_balance_of`: `(nat)`.
pub fn ler_saldo(resposta: &[u8]) -> Result<u128, Erro> {
    nat(Some(&unico(resposta)?))
}

/// Lê a resposta de `icrc1_transfer`: `(variant { Ok : nat; Err :
/// TransferError })` — o bloco, ou a recusa do ledger.
pub fn ler_transferencia(resposta: &[u8]) -> Result<Result<u128, Recusa>, Erro> {
    let v = unico(resposta)?;
    if let Some(bloco) = v.caso("Ok") {
        return Ok(Ok(nat(Some(bloco))?));
    }
    let erro = v.caso("Err").ok_or(Erro::Forma)?;
    let recusa = if let Some(r) = erro.caso("BadFee") {
        Recusa::TaxaErrada {
            esperada: nat(r.campo("expected_fee"))?,
        }
    } else if let Some(r) = erro.caso("BadBurn") {
        Recusa::QueimaPequena {
            minima: nat(r.campo("min_burn_amount"))?,
        }
    } else if let Some(r) = erro.caso("InsufficientFunds") {
        Recusa::SemFundos {
            saldo: nat(r.campo("balance"))?,
        }
    } else if erro.caso("TooOld").is_some() {
        Recusa::Velha
    } else if let Some(r) = erro.caso("CreatedInFuture") {
        match r.campo("ledger_time") {
            Some(Valor::Nat64(t)) => Recusa::NoFuturo {
                hora_do_ledger_ns: *t,
            },
            _ => return Err(Erro::Forma),
        }
    } else if erro.caso("TemporarilyUnavailable").is_some() {
        Recusa::Indisponivel
    } else if let Some(r) = erro.caso("Duplicate") {
        Recusa::Duplicada {
            bloco: nat(r.campo("duplicate_of"))?,
        }
    } else if let Some(r) = erro.caso("GenericError") {
        match r.campo("message") {
            Some(Valor::Texto(m)) => Recusa::Generica {
                codigo: nat(r.campo("error_code"))?,
                mensagem: m.clone(),
            },
            _ => return Err(Erro::Forma),
        }
    } else {
        return Err(Erro::Forma);
    };
    Ok(Err(recusa))
}

#[cfg(test)]
mod testes;
