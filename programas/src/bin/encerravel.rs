//! Um processo que a suíte encerra: o outro lado dos casos `processos:` de
//! `process.terminate`.
//!
//! O programa escuta o primeiro livre dos canais [`CANAIS`] e diz
//! `encerravel: pronto`. Parado,
//! ele espera um evento — é o processo que dorme numa chamada de sistema.
//! A cada evento [`tipo::ACAO`], o `a` diz o que fazer:
//!
//! - [`GIRAR`]: diz `encerravel: girando` e gira para sempre, sem chamada
//!   de sistema nenhuma — só uma interrupção o tira dali;
//! - [`FILHO`]: bifurca um filho que diz `encerravel: filho <id>` e gira, e
//!   espera por ele; quando o filho acaba, diz `encerravel: colheu <id>
//!   saiu <codigo>` ou `encerravel: colheu <id> morto`;
//! - [`ESCREVER`]: cria [`ARQUIVO`] com `b` bytes pelo gate (`fs.write`,
//!   versão esperada zero) e diz `encerravel: escreveu <codigo>`.
//!
//! Sai com [`CODIGO`] quando a suíte pede o fim, e com nenhum quando ela o
//! encerra: o processo encerrado não diz nada — o pai colhe um morto.

#![no_std]
#![no_main]

programas::manifesto!("encerravel", "system.read", "fs.write");

use programas::escreverln;
use programas::nativo;
use programas::sistema;
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 86;

/// Os canais por onde a suíte dita o passo: o primeiro livre. Um canal tem
/// um ouvinte só, e a suíte lança até quatro ao mesmo tempo.
const CANAIS: [&str; 4] = [
    "teste-encerravel",
    "teste-encerravel-1",
    "teste-encerravel-2",
    "teste-encerravel-3",
];

/// Os passos, no `a` de um evento [`tipo::ACAO`].
const GIRAR: i64 = 1;
const FILHO: i64 = 2;
const ESCREVER: i64 = 3;

/// Onde [`ESCREVER`] grava.
const ARQUIVO: &str = "/armazem/compartilhado/encerravel.txt";

/// Gira para sempre, sem chamada de sistema: o que o compilador não pode
/// apagar nem transformar numa espera.
fn girar() -> ! {
    let mut x: u64 = 0;
    loop {
        x = core::hint::black_box(x.wrapping_add(1));
    }
}

/// Bifurca um filho que gira, e espera por ele.
fn filho() -> Result<(), i64> {
    match sistema::bifurcar() {
        0 => {
            escreverln!("encerravel: filho {}", sistema::id());
            girar()
        }
        filho if filho > 0 => {
            let filho = filho as u64;
            match sistema::esperar(filho) {
                Ok((id, Some(codigo))) => {
                    escreverln!("encerravel: colheu {} saiu {}", id, codigo);
                }
                Ok((id, None)) => {
                    escreverln!("encerravel: colheu {} morto", id);
                }
                Err(e) => {
                    escreverln!("encerravel: esperar devolveu {}", e);
                    return Err(4);
                }
            }
            Ok(())
        }
        e => {
            escreverln!("encerravel: bifurcar devolveu {}", e);
            Err(3)
        }
    }
}

/// Grava `n` bytes pelo gate, e diz o código que ouviu.
fn escrever(n: usize) -> Result<(), i64> {
    let dados = [b'e'; 64];
    let n = n.min(dados.len());
    let texto = core::str::from_utf8(&dados[..n]).unwrap_or("");
    let r = nativo::pedir("fs.write", |w| {
        w.field_str("path", ARQUIVO)?;
        w.field_str("content", texto)?;
        w.field_u64("expect_version", 0)
    })?;
    match r.resultado() {
        Ok(_) => {
            escreverln!("encerravel: escreveu ALLOW");
        }
        Err(recusa) => {
            escreverln!("encerravel: escreveu {}", recusa.motivo.unwrap_or("?"));
        }
    }
    Ok(())
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let Some(canal) = CANAIS.iter().map(|c| sistema::escutar(c)).find(|&c| c >= 0) else {
        escreverln!("encerravel: nenhum canal livre");
        return 1;
    };
    escreverln!("encerravel: pronto");
    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("encerravel: a leitura falhou: {}", e);
                return 2;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                escreverln!("encerravel: encerrado");
                return CODIGO;
            }
            let feito = match e.a {
                GIRAR => {
                    escreverln!("encerravel: girando");
                    girar()
                }
                FILHO => filho(),
                ESCREVER => escrever(e.b as usize),
                _ => Ok(()),
            };
            if let Err(codigo) = feito {
                return codigo;
            }
        }
    }
}
