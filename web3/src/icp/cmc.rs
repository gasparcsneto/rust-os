//! O CMC — o *cycles minting canister*, que converte ICP em cycles —, no
//! que o ICP-4d usa dele: cunhar cycles no ledger de cycles com ICP
//! (`notify_mint_cycles`). A interface é a do CMC (`cmc.did`); não há
//! crate oficial com os tipos dela, e a bancada a confere contra o CMC de
//! verdade, o da PocketIC.
//!
//! A cunhagem são duas chamadas de quem cunha:
//!
//! 1. a transferência de ICP para a conta de depósito dele no CMC — o dono
//!    é o CMC, e a subconta é a do Principal de quem cunha
//!    ([`conta_de_deposito`]) —, com o `memo` [`MEMO_DE_CUNHAGEM`];
//! 2. o `notify_mint_cycles` com o bloco dela, **pelo mesmo Principal**: o
//!    CMC confere que o depósito é de quem notifica, converte, e deposita
//!    os cycles na conta dele no ledger de cycles.
//!
//! O CMC lembra cada bloco: a mesma notificação de novo devolve o mesmo
//! resultado, e não cunha duas vezes.
//!
//! A recarga de um canister (`notify_top_up`) é a mesma forma, com outra
//! conta e outro memo: o ICP vai para a conta de recarga **do canister** no
//! CMC ([`conta_de_recarga`]) com o memo [`MEMO_DE_RECARGA`], e o
//! `notify_top_up` com o bloco dela converte e deposita os cycles no
//! canister. Qualquer um pode notificar uma recarga — os cycles vão para o
//! canister da subconta, e não para quem notifica.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::candid::{self, Primitivo, Tipo, Valor};
use super::icrc1::{Conta, SUBCONTA};
use super::principal::Principal;

/// O `memo` da cunhagem: `MINT`, o número `0x544e494d` em 8 bytes little
/// endian — o `memo` de 8 bytes que o CMC lê como número.
pub const MEMO_DE_CUNHAGEM: [u8; 8] = 0x544e_494d_u64.to_le_bytes();

/// O `memo` da recarga: `TPUP`, o número `0x50555054` em 8 bytes little
/// endian.
pub const MEMO_DE_RECARGA: [u8; 8] = 0x5055_5054_u64.to_le_bytes();

/// A subconta de um Principal no CMC: o tamanho dele, os bytes, e zeros
/// até [`SUBCONTA`].
pub fn subconta_de(p: &Principal) -> [u8; SUBCONTA] {
    let bytes = p.bytes();
    let mut s = [0u8; SUBCONTA];
    // Um Principal tem até 29 bytes: cabe, com o tamanho na frente.
    s[0] = bytes.len() as u8;
    s[1..1 + bytes.len()].copy_from_slice(bytes);
    s
}

/// A conta de depósito de `quem` no CMC `cmc`: o ICP que vai para ela, com
/// o [`MEMO_DE_CUNHAGEM`], é o que `quem` cunha.
pub fn conta_de_deposito(cmc: &Principal, quem: &Principal) -> Conta {
    Conta {
        dono: *cmc,
        subconta: Some(subconta_de(quem)),
    }
}

/// A conta de recarga do `canister` no CMC `cmc`: o ICP que vai para ela,
/// com o [`MEMO_DE_RECARGA`], vira cycles do `canister`.
pub fn conta_de_recarga(cmc: &Principal, canister: &Principal) -> Conta {
    Conta {
        dono: *cmc,
        subconta: Some(subconta_de(canister)),
    }
}

/// A notificação de uma cunhagem — `NotifyMintCyclesArg`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notificacao {
    /// O bloco da transferência ao CMC.
    pub bloco: u64,
    /// A subconta de destino no ledger de cycles; sem ela, a de zeros.
    pub para_subconta: Option<[u8; SUBCONTA]>,
    /// O `memo` do depósito no ledger de cycles.
    pub memo_do_deposito: Option<Vec<u8>>,
}

/// Os cycles cunhados — `NotifyMintCyclesSuccess`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cunhagem {
    /// Quantos.
    pub cunhados: u128,
    /// O saldo da conta no ledger de cycles, depois do depósito.
    pub saldo: u128,
    /// O bloco do depósito no ledger de cycles.
    pub bloco: u128,
}

/// Por que o CMC não cunhou — `NotifyError`, pelo nome da interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// `Refunded`: o ICP voltou, menos a taxa.
    Devolvida {
        /// O motivo.
        motivo: String,
        /// O bloco da devolução.
        bloco: Option<u64>,
    },
    /// `Processing`: outra notificação do mesmo bloco está em curso.
    Processando,
    /// `TransactionTooOld`: o bloco é anterior ao que o CMC ainda aceita.
    BlocoVelho {
        /// O menor bloco que ele aceita.
        menor: u64,
    },
    /// `InvalidTransaction`: o bloco não é um depósito de quem notifica.
    Invalida {
        /// O motivo.
        motivo: String,
    },
    /// `Other`.
    Outra {
        /// O código.
        codigo: u64,
        /// A mensagem.
        mensagem: String,
    },
}

impl fmt::Display for Recusa {
    /// O nome da interface e o que o acompanha, em ASCII.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let texto =
            |f: &mut fmt::Formatter<'_>, t: &String| fmt::Display::fmt(&Valor::Texto(t.clone()), f);
        match self {
            Recusa::Devolvida { motivo, bloco } => {
                f.write_str("Refunded reason ")?;
                texto(f, motivo)?;
                match bloco {
                    Some(b) => write!(f, " block_index {b}"),
                    None => Ok(()),
                }
            }
            Recusa::Processando => f.write_str("Processing"),
            Recusa::BlocoVelho { menor } => write!(f, "TransactionTooOld {menor}"),
            Recusa::Invalida { motivo } => {
                f.write_str("InvalidTransaction ")?;
                texto(f, motivo)
            }
            Recusa::Outra { codigo, mensagem } => {
                write!(f, "Other error_code {codigo} error_message ")?;
                texto(f, mensagem)
            }
        }
    }
}

/// Por que uma resposta não se lê.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// Um `memo` de depósito de mais de 32 bytes.
    MemoGrande,
    /// A resposta não é Candid.
    Candid(candid::Erro),
    /// A resposta é Candid, mas não tem a forma da interface do CMC.
    Forma,
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Erro::MemoGrande => f.write_str("memo do deposito maior que 32 bytes"),
            Erro::Candid(e) => write!(f, "{e}"),
            Erro::Forma => f.write_str("resposta fora da forma do cmc"),
        }
    }
}

/// Escreve o argumento de `notify_mint_cycles`: `(record { block_index :
/// nat64; to_subaccount : opt blob; deposit_memo : opt blob })`.
pub fn argumento_da_cunhagem(n: &Notificacao) -> Result<Vec<u8>, Erro> {
    if n.memo_do_deposito
        .as_ref()
        .is_some_and(|m| m.len() > super::icrc1::MAIOR_MEMO)
    {
        return Err(Erro::MemoGrande);
    }
    let opt_blob = || Tipo::opt(Tipo::blob());
    let tipo = Tipo::record([
        ("block_index", Primitivo::Nat64.into()),
        ("to_subaccount", opt_blob()),
        ("deposit_memo", opt_blob()),
    ]);
    let opt = |b: Option<Vec<u8>>| Valor::Opt(b.map(|b| alloc::boxed::Box::new(Valor::Blob(b))));
    let valor = Valor::Record(alloc::vec![
        (candid::id_do_campo("block_index"), Valor::Nat64(n.bloco)),
        (
            candid::id_do_campo("to_subaccount"),
            opt(n.para_subconta.map(Vec::from)),
        ),
        (
            candid::id_do_campo("deposit_memo"),
            opt(n.memo_do_deposito.clone()),
        ),
    ]);
    Ok(candid::codificar_com_tipos(&[tipo], &[valor]).expect("o valor e do tipo daqui"))
}

fn nat(v: Option<&Valor>) -> Result<u128, Erro> {
    match v {
        Some(Valor::Nat(n)) => Ok(*n),
        _ => Err(Erro::Forma),
    }
}

fn nat64(v: Option<&Valor>) -> Result<u64, Erro> {
    match v {
        Some(Valor::Nat64(n)) => Ok(*n),
        _ => Err(Erro::Forma),
    }
}

fn texto(v: Option<&Valor>) -> Result<String, Erro> {
    match v {
        Some(Valor::Texto(t)) => Ok(t.clone()),
        _ => Err(Erro::Forma),
    }
}

/// Escreve o argumento de `notify_top_up`: `(record { block_index : nat64;
/// canister_id : principal })` — o bloco da transferência para a conta de
/// recarga do canister.
pub fn argumento_da_recarga(bloco: u64, canister: &Principal) -> Vec<u8> {
    let tipo = Tipo::record([
        ("block_index", Primitivo::Nat64.into()),
        ("canister_id", Primitivo::Principal.into()),
    ]);
    let valor = Valor::Record(alloc::vec![
        (candid::id_do_campo("block_index"), Valor::Nat64(bloco)),
        (
            candid::id_do_campo("canister_id"),
            Valor::Principal(*canister)
        ),
    ]);
    candid::codificar_com_tipos(&[tipo], &[valor]).expect("o valor e do tipo daqui")
}

/// O único valor de uma resposta.
fn unico(resposta: &[u8]) -> Result<Valor, Erro> {
    let mut valores = candid::decodificar(resposta).map_err(Erro::Candid)?;
    if valores.len() != 1 {
        return Err(Erro::Forma);
    }
    Ok(valores.remove(0))
}

/// Lê a resposta de `notify_mint_cycles`: `(variant { Ok :
/// NotifyMintCyclesSuccess; Err : NotifyError })` — os cycles cunhados, ou
/// a recusa do CMC.
pub fn ler_cunhagem(resposta: &[u8]) -> Result<Result<Cunhagem, Recusa>, Erro> {
    let v = unico(resposta)?;
    if let Some(ok) = v.caso("Ok") {
        return Ok(Ok(Cunhagem {
            cunhados: nat(ok.campo("minted"))?,
            saldo: nat(ok.campo("balance"))?,
            bloco: nat(ok.campo("block_index"))?,
        }));
    }
    Ok(Err(ler_recusa(v.caso("Err").ok_or(Erro::Forma)?)?))
}

/// Lê a resposta de `notify_top_up`: `(variant { Ok : nat; Err :
/// NotifyError })` — os cycles depositados no canister, ou a recusa do
/// CMC.
pub fn ler_recarga(resposta: &[u8]) -> Result<Result<u128, Recusa>, Erro> {
    let v = unico(resposta)?;
    if let Some(ok) = v.caso("Ok") {
        return Ok(Ok(nat(Some(ok))?));
    }
    Ok(Err(ler_recusa(v.caso("Err").ok_or(Erro::Forma)?)?))
}

/// `NotifyError`, pelo nome do caso.
fn ler_recusa(erro: &Valor) -> Result<Recusa, Erro> {
    let recusa = if let Some(r) = erro.caso("Refunded") {
        Recusa::Devolvida {
            motivo: texto(r.campo("reason"))?,
            bloco: match r.campo("block_index") {
                Some(Valor::Opt(None)) => None,
                Some(Valor::Opt(Some(b))) => Some(nat64(Some(b))?),
                _ => return Err(Erro::Forma),
            },
        }
    } else if erro.caso("Processing").is_some() {
        Recusa::Processando
    } else if let Some(b) = erro.caso("TransactionTooOld") {
        Recusa::BlocoVelho {
            menor: nat64(Some(b))?,
        }
    } else if let Some(m) = erro.caso("InvalidTransaction") {
        Recusa::Invalida {
            motivo: texto(Some(m))?,
        }
    } else if let Some(r) = erro.caso("Other") {
        Recusa::Outra {
            codigo: nat64(r.campo("error_code"))?,
            mensagem: texto(r.campo("error_message"))?,
        }
    } else {
        return Err(Erro::Forma);
    };
    Ok(recusa)
}

#[cfg(test)]
mod testes;
