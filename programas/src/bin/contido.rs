//! Um programa que declara pouco: só `system.read`. Confere de dentro que o
//! manifesto limita o que a autoridade de quem o lançou alcançaria — ver
//! `programas::manifesto`.
//!
//! A suíte o lança pelo sistema, que pode tudo isso, e ele confere:
//!
//! - `system.info`, declarado, passa;
//! - `message.send`, não declarado, é recusado com `DENY_PERMISSION`;
//! - abrir um arquivo e executar um programa, não declarados, são recusados
//!   pelas chamadas de sistema de verdade;
//! - o filho de um `fork` executa a mesma imagem, e herda o mesmo limite.
//!
//! Sai com [`CODIGO`] quando tudo confere.

#![no_std]
#![no_main]

programas::manifesto!("contido", "system.read");

use programas::escreverln;
use programas::nativo;
use programas::sistema::{self, erro};

/// O código de saída quando tudo conferiu.
const CODIGO: i64 = 75;

/// O código com que o filho sai quando as recusas dele conferem.
const DO_FILHO: i64 = 77;

fn decisao(r: &nativo::Resposta) -> Option<&str> {
    match r.resultado() {
        Ok(_) => Some("ALLOW"),
        Err(recusa) => recusa.motivo,
    }
}

fn recusas_do_sistema() -> bool {
    sistema::abrir("/saudacao.txt") == erro::NEGADO && sistema::executar("ola") == erro::NEGADO
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    match nativo::pedir("system.info", |_| Ok(())) {
        Ok(r) if decisao(&r) == Some("ALLOW") => {}
        _ => return 1,
    }
    let envio = nativo::pedir("message.send", |w| {
        w.field_str("to", "serial")?;
        w.field_str("body", "nao declarado")?;
        w.field_u64("nonce", 1)
    });
    match envio {
        Ok(r) if decisao(&r) == Some("DENY_PERMISSION") => {}
        Ok(r) => {
            escreverln!("contido: message.send deu {:?}", decisao(&r));
            return 2;
        }
        Err(_) => return 2,
    }
    if !recusas_do_sistema() {
        return 3;
    }
    match sistema::bifurcar() {
        0 => sistema::sair(if recusas_do_sistema() { DO_FILHO } else { 4 }),
        filho if filho < 0 => return 5,
        _ => {}
    }
    match sistema::esperar(0) {
        Ok((_, Some(DO_FILHO))) => {}
        outro => {
            escreverln!("contido: o filho deu {:?}", outro);
            return 6;
        }
    }
    escreverln!("contido conferido: o manifesto limita o que a autoridade alcanca");
    CODIGO
}
