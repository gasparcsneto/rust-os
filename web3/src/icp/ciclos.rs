//! O ledger de cycles — **especificação**: `dfinity/cycles-ledger`, a
//! interface `cycles-ledger.did` —: a criação de um canister pago com os
//! cycles de quem chama (`create_canister`), e a carga de cycles num
//! canister (`withdraw`), em Candid.
//!
//! - [`argumento_da_criacao`] e [`ler_criacao`]: a quantia, o
//!   `created_at_time` e os controladores do canister novo; o canister
//!   criado e o bloco, ou a recusa pelo nome da interface
//!   ([`RecusaDaCriacao`]);
//! - [`argumento_da_carga`] e [`ler_carga`]: o canister que recebe, a
//!   quantia e o `created_at_time`; o bloco, ou a recusa
//!   ([`RecusaDaCarga`]).
//!
//! O que não tem a forma da interface é recusado, e nunca vira canister nem
//! bloco. O saldo e a transferência do ledger de cycles são os do ICRC-1
//! ([`super::icrc1`]).
//!
//! # A repetição
//!
//! O ledger deduplica a criação e a carga pelo `created_at_time`, como o
//! ICRC-1: a mesma, dentro da janela dele, volta `Duplicate` — a criação,
//! com o canister da primeira —, e não executa. Sem `created_at_time`,
//! executa de novo.
//!
//! Nada aqui assina, conecta ou verifica: a resposta que se lê é a que a
//! chamada verificada entregou ([`super::atualizacao`]).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::candid::{self, Primitivo, Tipo, Valor};
use super::principal::Principal;

/// Quantos controladores um canister tem, no máximo — os que o IC aceita.
pub const MAIS_CONTROLADORES: usize = 10;

/// A criação de um canister — `CreateCanisterArgs`, sem subconta de origem
/// e sem escolha de sub-rede.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Criacao {
    /// Os cycles que saem da conta de quem chama: a criação e o que sobra,
    /// que o canister novo recebe. A taxa do ledger sai à parte.
    pub quantia: u128,
    /// O `created_at_time`, em nanossegundos desde a época: o que deduplica
    /// a repetição.
    pub criada_em_ns: Option<u64>,
    /// Os controladores do canister novo, até [`MAIS_CONTROLADORES`]; sem
    /// eles, quem chama.
    pub controladores: Option<Vec<Principal>>,
}

/// Um canister criado: o bloco do ledger e o canister.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Criado {
    /// O bloco.
    pub bloco: u128,
    /// O canister.
    pub canister: Principal,
}

/// Por que o ledger recusou uma criação — `CreateCanisterError`, pelo nome
/// da interface. É a resposta do ledger, provada pelo certificado.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecusaDaCriacao {
    /// `InsufficientFunds`.
    SemFundos {
        /// O saldo.
        saldo: u128,
    },
    /// `TooOld`.
    Velha,
    /// `CreatedInFuture`.
    NoFuturo {
        /// A hora do ledger, em nanossegundos.
        hora_do_ledger_ns: u64,
    },
    /// `TemporarilyUnavailable`.
    Indisponivel,
    /// `Duplicate`: a mesma criação já executou.
    Duplicada {
        /// O bloco da primeira.
        bloco: u128,
        /// O canister que ela criou.
        canister: Option<Principal>,
    },
    /// `FailedToCreate`: o CMC não criou; os cycles voltam pelo bloco da
    /// devolução.
    NaoCriou {
        /// O bloco da taxa.
        bloco_da_taxa: Option<u128>,
        /// O bloco da devolução.
        bloco_da_devolucao: Option<u128>,
        /// O motivo.
        motivo: String,
    },
    /// `GenericError`.
    Generica {
        /// O código.
        codigo: u128,
        /// A mensagem.
        mensagem: String,
    },
}

/// Uma carga de cycles num canister — `WithdrawArgs`, sem subconta de
/// origem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Carga {
    /// O canister que recebe.
    pub para: Principal,
    /// Os cycles; a taxa do ledger sai à parte.
    pub quantia: u128,
    /// O `created_at_time`, em nanossegundos.
    pub criada_em_ns: Option<u64>,
}

/// Por que o ledger recusou uma carga — `WithdrawError`, pelo nome da
/// interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecusaDaCarga {
    /// `BadFee`.
    TaxaErrada {
        /// A do ledger.
        esperada: u128,
    },
    /// `InsufficientFunds`.
    SemFundos {
        /// O saldo.
        saldo: u128,
    },
    /// `TooOld`.
    Velha,
    /// `CreatedInFuture`.
    NoFuturo {
        /// A hora do ledger, em nanossegundos.
        hora_do_ledger_ns: u64,
    },
    /// `TemporarilyUnavailable`.
    Indisponivel,
    /// `Duplicate`: a mesma carga já executou.
    Duplicada {
        /// O bloco da primeira.
        bloco: u128,
    },
    /// `FailedToWithdraw`: o canister não recebeu.
    NaoCarregou {
        /// O bloco da taxa.
        bloco_da_taxa: Option<u128>,
        /// O motivo.
        motivo: String,
    },
    /// `InvalidReceiver`: quem receberia não é um canister.
    DestinoInvalido {
        /// Quem.
        destino: Principal,
    },
    /// `GenericError`.
    Generica {
        /// O código.
        codigo: u128,
        /// A mensagem.
        mensagem: String,
    },
}

/// Um texto de fora, em ASCII: a mensagem de um ledger não escreve
/// controle na saída de um programa.
fn texto(f: &mut fmt::Formatter<'_>, t: &str) -> fmt::Result {
    fmt::Display::fmt(&Valor::Texto(String::from(t)), f)
}

impl fmt::Display for RecusaDaCriacao {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecusaDaCriacao::SemFundos { saldo } => write!(f, "InsufficientFunds balance {saldo}"),
            RecusaDaCriacao::Velha => f.write_str("TooOld"),
            RecusaDaCriacao::NoFuturo { hora_do_ledger_ns } => {
                write!(f, "CreatedInFuture ledger_time {hora_do_ledger_ns}")
            }
            RecusaDaCriacao::Indisponivel => f.write_str("TemporarilyUnavailable"),
            RecusaDaCriacao::Duplicada { bloco, canister } => {
                write!(f, "Duplicate duplicate_of {bloco}")?;
                match canister {
                    Some(c) => write!(f, " canister_id {}", c.texto()),
                    None => Ok(()),
                }
            }
            RecusaDaCriacao::NaoCriou { motivo, .. } => {
                f.write_str("FailedToCreate error ")?;
                texto(f, motivo)
            }
            RecusaDaCriacao::Generica { codigo, mensagem } => {
                write!(f, "GenericError error_code {codigo} message ")?;
                texto(f, mensagem)
            }
        }
    }
}

impl fmt::Display for RecusaDaCarga {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecusaDaCarga::TaxaErrada { esperada } => write!(f, "BadFee expected_fee {esperada}"),
            RecusaDaCarga::SemFundos { saldo } => write!(f, "InsufficientFunds balance {saldo}"),
            RecusaDaCarga::Velha => f.write_str("TooOld"),
            RecusaDaCarga::NoFuturo { hora_do_ledger_ns } => {
                write!(f, "CreatedInFuture ledger_time {hora_do_ledger_ns}")
            }
            RecusaDaCarga::Indisponivel => f.write_str("TemporarilyUnavailable"),
            RecusaDaCarga::Duplicada { bloco } => write!(f, "Duplicate duplicate_of {bloco}"),
            RecusaDaCarga::NaoCarregou { motivo, .. } => {
                f.write_str("FailedToWithdraw rejection_reason ")?;
                texto(f, motivo)
            }
            RecusaDaCarga::DestinoInvalido { destino } => {
                write!(f, "InvalidReceiver receiver {}", destino.texto())
            }
            RecusaDaCarga::Generica { codigo, mensagem } => {
                write!(f, "GenericError error_code {codigo} message ")?;
                texto(f, mensagem)
            }
        }
    }
}

/// Por que um argumento não se escreve, ou uma resposta não se lê.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// Mais de [`MAIS_CONTROLADORES`] controladores: o IC os recusaria.
    Controladores,
    /// A resposta não é Candid.
    Candid(candid::Erro),
    /// A resposta é Candid, mas não tem a forma da interface.
    Forma,
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Erro::Controladores => f.write_str("mais de 10 controladores"),
            Erro::Candid(e) => write!(f, "{e}"),
            Erro::Forma => f.write_str("resposta fora da forma do ledger de cycles"),
        }
    }
}

/// Um campo pelo nome.
fn campo(nome: &str, v: Valor) -> (u32, Valor) {
    (candid::id_do_campo(nome), v)
}

/// `opt v`.
fn opt(v: Option<Valor>) -> Valor {
    Valor::Opt(v.map(Box::new))
}

/// Um argumento dos tipos daqui: o valor é sempre do tipo, e cabe nos
/// tetos da escrita — os controladores vão até [`MAIS_CONTROLADORES`].
fn escrever(tipo: Tipo, valor: Valor) -> Vec<u8> {
    candid::codificar_com_tipos(&[tipo], &[valor]).expect("o valor e do tipo daqui")
}

/// Escreve o argumento de `create_canister`: `(CreateCanisterArgs)`. Os
/// controladores vão em `creation_args.settings.controllers`; os outros
/// campos dos ajustes, e a escolha da sub-rede, ficam de fora — opcionais,
/// o ledger os lê ausentes.
pub fn argumento_da_criacao(c: &Criacao) -> Result<Vec<u8>, Erro> {
    if c.controladores
        .as_ref()
        .is_some_and(|cs| cs.len() > MAIS_CONTROLADORES)
    {
        return Err(Erro::Controladores);
    }
    let ajustes = Tipo::record([("controllers", Tipo::opt(Tipo::vec(Primitivo::Principal)))]);
    let criacao = Tipo::record([("settings", Tipo::opt(ajustes))]);
    let tipo = Tipo::record([
        ("from_subaccount", Tipo::opt(Tipo::blob())),
        ("created_at_time", Tipo::opt(Primitivo::Nat64)),
        ("amount", Primitivo::Nat.into()),
        ("creation_args", Tipo::opt(criacao)),
    ]);
    let criacao = c.controladores.as_ref().map(|cs| {
        let lista = Valor::Vec(cs.iter().map(|p| Valor::Principal(*p)).collect());
        let ajustes = Valor::Record(alloc::vec![campo("controllers", opt(Some(lista)))]);
        Valor::Record(alloc::vec![campo("settings", opt(Some(ajustes)))])
    });
    let valor = Valor::Record(alloc::vec![
        campo("from_subaccount", Valor::Opt(None)),
        campo("created_at_time", opt(c.criada_em_ns.map(Valor::Nat64))),
        campo("amount", Valor::Nat(c.quantia)),
        campo("creation_args", opt(criacao)),
    ]);
    Ok(escrever(tipo, valor))
}

/// Escreve o argumento de `withdraw`: `(WithdrawArgs)`.
pub fn argumento_da_carga(c: &Carga) -> Vec<u8> {
    let tipo = Tipo::record([
        ("from_subaccount", Tipo::opt(Tipo::blob())),
        ("to", Primitivo::Principal.into()),
        ("created_at_time", Tipo::opt(Primitivo::Nat64)),
        ("amount", Primitivo::Nat.into()),
    ]);
    let valor = Valor::Record(alloc::vec![
        campo("from_subaccount", Valor::Opt(None)),
        campo("to", Valor::Principal(c.para)),
        campo("created_at_time", opt(c.criada_em_ns.map(Valor::Nat64))),
        campo("amount", Valor::Nat(c.quantia)),
    ]);
    escrever(tipo, valor)
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

/// Um `opt nat`.
fn opt_nat(v: Option<&Valor>) -> Result<Option<u128>, Erro> {
    match v {
        Some(Valor::Opt(None)) => Ok(None),
        Some(Valor::Opt(Some(n))) => nat(Some(n)).map(Some),
        _ => Err(Erro::Forma),
    }
}

/// Um `principal`.
fn principal(v: Option<&Valor>) -> Result<Principal, Erro> {
    match v {
        Some(Valor::Principal(p)) => Ok(*p),
        _ => Err(Erro::Forma),
    }
}

/// Um `text`.
fn texto_de(v: Option<&Valor>) -> Result<String, Erro> {
    match v {
        Some(Valor::Texto(t)) => Ok(t.clone()),
        _ => Err(Erro::Forma),
    }
}

/// O `ledger_time` de `CreatedInFuture`.
fn hora(r: &Valor) -> Result<u64, Erro> {
    match r.campo("ledger_time") {
        Some(Valor::Nat64(t)) => Ok(*t),
        _ => Err(Erro::Forma),
    }
}

/// Lê a resposta de `create_canister`: `(variant { Ok :
/// CreateCanisterSuccess; Err : CreateCanisterError })`.
pub fn ler_criacao(resposta: &[u8]) -> Result<Result<Criado, RecusaDaCriacao>, Erro> {
    let v = unico(resposta)?;
    if let Some(ok) = v.caso("Ok") {
        return Ok(Ok(Criado {
            bloco: nat(ok.campo("block_id"))?,
            canister: principal(ok.campo("canister_id"))?,
        }));
    }
    let erro = v.caso("Err").ok_or(Erro::Forma)?;
    let recusa = if let Some(r) = erro.caso("InsufficientFunds") {
        RecusaDaCriacao::SemFundos {
            saldo: nat(r.campo("balance"))?,
        }
    } else if erro.caso("TooOld").is_some() {
        RecusaDaCriacao::Velha
    } else if let Some(r) = erro.caso("CreatedInFuture") {
        RecusaDaCriacao::NoFuturo {
            hora_do_ledger_ns: hora(r)?,
        }
    } else if erro.caso("TemporarilyUnavailable").is_some() {
        RecusaDaCriacao::Indisponivel
    } else if let Some(r) = erro.caso("Duplicate") {
        let canister = match r.campo("canister_id") {
            Some(Valor::Opt(None)) => None,
            Some(Valor::Opt(Some(p))) => Some(principal(Some(p))?),
            _ => return Err(Erro::Forma),
        };
        RecusaDaCriacao::Duplicada {
            bloco: nat(r.campo("duplicate_of"))?,
            canister,
        }
    } else if let Some(r) = erro.caso("FailedToCreate") {
        RecusaDaCriacao::NaoCriou {
            bloco_da_taxa: opt_nat(r.campo("fee_block"))?,
            bloco_da_devolucao: opt_nat(r.campo("refund_block"))?,
            motivo: texto_de(r.campo("error"))?,
        }
    } else if let Some(r) = erro.caso("GenericError") {
        RecusaDaCriacao::Generica {
            codigo: nat(r.campo("error_code"))?,
            mensagem: texto_de(r.campo("message"))?,
        }
    } else {
        return Err(Erro::Forma);
    };
    Ok(Err(recusa))
}

/// Lê a resposta de `withdraw`: `(variant { Ok : nat; Err : WithdrawError
/// })`.
pub fn ler_carga(resposta: &[u8]) -> Result<Result<u128, RecusaDaCarga>, Erro> {
    let v = unico(resposta)?;
    if let Some(bloco) = v.caso("Ok") {
        return Ok(Ok(nat(Some(bloco))?));
    }
    let erro = v.caso("Err").ok_or(Erro::Forma)?;
    let recusa = if let Some(r) = erro.caso("BadFee") {
        RecusaDaCarga::TaxaErrada {
            esperada: nat(r.campo("expected_fee"))?,
        }
    } else if let Some(r) = erro.caso("InsufficientFunds") {
        RecusaDaCarga::SemFundos {
            saldo: nat(r.campo("balance"))?,
        }
    } else if erro.caso("TooOld").is_some() {
        RecusaDaCarga::Velha
    } else if let Some(r) = erro.caso("CreatedInFuture") {
        RecusaDaCarga::NoFuturo {
            hora_do_ledger_ns: hora(r)?,
        }
    } else if erro.caso("TemporarilyUnavailable").is_some() {
        RecusaDaCarga::Indisponivel
    } else if let Some(r) = erro.caso("Duplicate") {
        RecusaDaCarga::Duplicada {
            bloco: nat(r.campo("duplicate_of"))?,
        }
    } else if let Some(r) = erro.caso("FailedToWithdraw") {
        RecusaDaCarga::NaoCarregou {
            bloco_da_taxa: opt_nat(r.campo("fee_block"))?,
            motivo: texto_de(r.campo("rejection_reason"))?,
        }
    } else if let Some(r) = erro.caso("InvalidReceiver") {
        RecusaDaCarga::DestinoInvalido {
            destino: principal(r.campo("receiver"))?,
        }
    } else if let Some(r) = erro.caso("GenericError") {
        RecusaDaCarga::Generica {
            codigo: nat(r.campo("error_code"))?,
            mensagem: texto_de(r.campo("message"))?,
        }
    } else {
        return Err(Erro::Forma);
    };
    Ok(Err(recusa))
}

#[cfg(test)]
mod testes;
