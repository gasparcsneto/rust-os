//! Um programa sem manifesto: não exerce permissão nenhuma, nem lançado pelo
//! sistema — ver `programas::manifesto`. Pede um comando e abre um arquivo,
//! e confere que os dois são recusados. Sai com [`CODIGO`] quando confere.
//!
//! É o único programa sem `manifesto!`, de propósito: o padrão é o menor.

#![no_std]
#![no_main]

use programas::nativo;
use programas::sistema::{self, erro};

/// O código de saída quando tudo conferiu.
const CODIGO: i64 = 76;

#[unsafe(no_mangle)]
fn principal() -> i64 {
    match nativo::pedir("system.info", |_| Ok(())) {
        Ok(r) if matches!(r.resultado(), Err(recusa) if recusa.motivo == Some("DENY_PERMISSION")) =>
            {}
        _ => return 1,
    }
    if sistema::abrir("/saudacao.txt") != erro::NEGADO {
        return 2;
    }
    programas::escreverln!("anonimo conferido: sem manifesto, nada");
    CODIGO
}
