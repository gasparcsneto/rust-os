//! Um programa sem manifesto: não exerce permissão nenhuma, nem lançado pelo
//! sistema — ver `programas::manifesto`. Pede um comando e abre um arquivo,
//! e confere que os dois são recusados; e, antes, que nenhuma resposta o
//! esperava — nem a da imagem que o executou. Sai com [`CODIGO`] quando
//! confere.
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
    // Nenhuma resposta espera por ele — nem a de quem executou esta imagem
    // no lugar da sua, como o `legado` faz.
    let mut buffer = [0u8; 64];
    if sistema::resposta(&mut buffer) != erro::NAO_ENCONTRADO {
        return 3;
    }
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
