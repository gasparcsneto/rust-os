//! Um processo que a suíte isola e solta: o outro lado do caso
//! `contencao: o processo isolado pede e ouve DENY_CONTAINED`.
//!
//! O programa escuta o canal [`CANAL`] e, a cada evento que chega, faz um
//! pedido `system.info` pelo gate e diz no log o que ouviu —
//! `isolavel: ALLOW`, ou `isolavel: <codigo da recusa>`. Quem dita o
//! passo é a suíte: ela publica, espera a linha, contém ou solta, e
//! publica de novo — sem corrida com o relógio, e sem gastar a taxa de
//! ninguém.
//!
//! Numa recusa `DENY_CONTAINED`, o programa confere também que um isolado
//! não ganha filho livre: o `fork` é recusado, e ele diz
//! `isolavel: sem filho`. Um filho que nascesse sairia com [`DO_FILHO`],
//! e o pai, com 3.
//!
//! Sai com [`CODIGO`] quando a suíte pede o fim.

#![no_std]
#![no_main]

programas::manifesto!("isolavel", "system.read");

use programas::escreverln;
use programas::nativo;
use programas::sistema;
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 84;

/// O código com que sairia um filho que o isolamento deixasse nascer.
const DO_FILHO: i64 = 85;

/// O canal por onde a suíte dita o passo.
const CANAL: &str = "teste-isolavel";

/// Um pedido pelo gate, e a decisão, em uma palavra.
fn pedir() -> Result<(), i64> {
    let r = nativo::pedir("system.info", |_| Ok(()))?;
    match r.resultado() {
        Ok(_) => {
            escreverln!("isolavel: ALLOW");
        }
        Err(recusa) => {
            let codigo = recusa.motivo.unwrap_or("?");
            escreverln!("isolavel: {}", codigo);
            if codigo == "DENY_CONTAINED" {
                match sistema::bifurcar() {
                    0 => sistema::sair(DO_FILHO),
                    filho if filho > 0 => return Err(3),
                    _ => {
                        escreverln!("isolavel: sem filho");
                    }
                }
            }
        }
    }
    Ok(())
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let canal = sistema::escutar(CANAL);
    if canal < 0 {
        escreverln!("isolavel: escutar devolveu {}", canal);
        return 1;
    }
    escreverln!("isolavel: pronto");
    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("isolavel: a leitura falhou: {}", e);
                return 2;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                escreverln!("isolavel: encerrado");
                return CODIGO;
            }
            if let Err(codigo) = pedir() {
                return codigo;
            }
        }
    }
}
