//! Bifurca, e só colhe o filho quando a suíte manda: o outro lado do caso
//! `fios: o zumbi guarda a vaga ate a colheita`.
//!
//! A cada evento ACAO do canal [`CANAL`], o `a` diz o passo:
//!
//! - [`BIFURCAR`]: cria um filho, que sai na hora com [`DO_FILHO`], e diz
//!   `colhedor: bifurcou <filho>`;
//! - [`COLHER`]: colhe um filho qualquer, e diz
//!   `colhedor: colheu <filho> com <codigo>` — ou `colhedor: esperar
//!   <erro>`, se não há filho para colher.
//!
//! Entre os dois passos, o filho é um zumbi: terminou, e o pai ainda não
//! perguntou por ele. Quem decide quanto tempo isso dura é a suíte — sem
//! corrida com o relógio. Sai com [`CODIGO`] quando a suíte pede o fim.

#![no_std]
#![no_main]

programas::manifesto!("colhedor");

use programas::escreverln;
use programas::sistema;
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 72;

/// O código com que o filho sai.
const DO_FILHO: i64 = 71;

/// O canal por onde a suíte dita o passo.
const CANAL: &str = "teste-colhedor";

/// Os passos — a suíte tem as mesmas constantes.
const BIFURCAR: i64 = 1;
const COLHER: i64 = 2;

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let canal = sistema::escutar(CANAL);
    if canal < 0 {
        escreverln!("colhedor: escutar devolveu {}", canal);
        return 1;
    }
    escreverln!("colhedor: pronto");
    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("colhedor: a leitura falhou: {}", e);
                return 2;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                escreverln!("colhedor: encerrado");
                return CODIGO;
            }
            if e.tipo != tipo::ACAO {
                continue;
            }
            match e.a {
                BIFURCAR => match sistema::bifurcar() {
                    0 => sistema::sair(DO_FILHO),
                    filho if filho > 0 => {
                        escreverln!("colhedor: bifurcou {}", filho);
                    }
                    erro => {
                        escreverln!("colhedor: bifurcar {}", erro);
                    }
                },
                COLHER => match sistema::esperar(0) {
                    Ok((filho, Some(codigo))) => {
                        escreverln!("colhedor: colheu {} com {}", filho, codigo);
                    }
                    Ok((filho, None)) => {
                        escreverln!("colhedor: colheu {} morto", filho);
                    }
                    Err(erro) => {
                        escreverln!("colhedor: esperar {}", erro);
                    }
                },
                outro => {
                    escreverln!("colhedor: passo desconhecido {}", outro);
                }
            }
        }
    }
}
