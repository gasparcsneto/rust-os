//! Quem manda: a ponta que entrega nos casos `malha:` da suíte — o
//! "aplicativo A" do primeiro marco da malha.
//!
//! O programa não conhece quem atende: procura quem oferece
//! [`INTENCAO`] e escolhe entre os candidatos que a malha mostra, com a
//! identidade que o kernel conferiu. Escuta o canal [`CANAL`], e cada
//! evento [`tipo::ACAO`] é um passo que a suíte dita — sem corrida com o
//! relógio:
//!
//! - [`DESCOBRIR`]: procura, e diz `fotos: achei <n>` e uma linha
//!   `fotos: candidato <programa> <resumo> <endpoint>` por candidato;
//! - [`MANDAR`]: manda `foto-<n>.png` ao candidato `b` da última procura,
//!   com o nonce seguinte, e diz `fotos: mandei <id>` — ou
//!   `fotos: mandar <código>`;
//! - [`ESTADO`]: o estado da última entrega, e a resposta de quem a
//!   confirmou: `fotos: estado <estado> <resposta>`;
//! - [`REENVIAR`]: o mesmo envio de antes, com o mesmo nonce — o reenvio
//!   —: `fotos: reenvio igual`, se voltou o mesmo id;
//! - [`VELHO`]: outro corpo com um nonce que já passou:
//!   `fotos: velho <código>`;
//! - [`CANCELAR`]: cancela a última entrega: `fotos: cancelar <estado>`, ou
//!   o código.
//!
//! Sai com [`CODIGO`] quando a suíte pede o fim.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!("fotos", "fabric.send");

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use programas::escreverln;
use programas::malha::{self, Candidato};
use programas::sistema;
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 43;

/// O canal por onde a suíte dita o passo.
const CANAL: &str = "teste-fotos";

/// A intenção que o programa procura.
const INTENCAO: &str = "imagem.compartilhar";

/// Os passos — o `a` do evento.
const DESCOBRIR: i64 = 1;
const MANDAR: i64 = 2;
const ESTADO: i64 = 3;
const REENVIAR: i64 = 4;
const VELHO: i64 = 5;
const CANCELAR: i64 = 6;

/// O que o programa lembra entre um passo e outro.
#[derive(Default)]
struct Memoria {
    candidatos: Vec<Candidato>,
    nonce: u64,
    /// O último envio aceito: o destino, o corpo, o nonce e o id.
    ultimo: Option<(String, String, u64, String)>,
}

fn passo(m: &mut Memoria, a: i64, b: i64) {
    match a {
        DESCOBRIR => match malha::descobrir(INTENCAO) {
            Ok(v) => {
                escreverln!("fotos: achei {}", v.len());
                for c in &v {
                    escreverln!(
                        "fotos: candidato {} {} {}",
                        c.programa,
                        c.resumo.get(..8).unwrap_or(&c.resumo),
                        c.endpoint
                    );
                }
                m.candidatos = v;
            }
            Err(f) => {
                escreverln!("fotos: descobrir {}", f.codigo());
            }
        },
        MANDAR => {
            let Some(c) = m.candidatos.get(b as usize) else {
                escreverln!("fotos: mandar SEM_CANDIDATO");
                return;
            };
            let endpoint = c.endpoint.clone();
            m.nonce += 1;
            let corpo = format!("foto-{}.png", m.nonce);
            match malha::enviar(&endpoint, INTENCAO, &corpo, m.nonce) {
                Ok(id) => {
                    escreverln!("fotos: mandei {}", id);
                    m.ultimo = Some((endpoint, corpo, m.nonce, id));
                }
                Err(f) => {
                    escreverln!("fotos: mandar {}", f.codigo());
                }
            }
        }
        ESTADO => {
            let Some((_, _, _, id)) = &m.ultimo else {
                escreverln!("fotos: estado SEM_ENTREGA");
                return;
            };
            match malha::estado(id) {
                Ok((estado, resposta)) => {
                    escreverln!(
                        "fotos: estado {} {}",
                        estado,
                        resposta.as_deref().unwrap_or("-")
                    );
                }
                Err(f) => {
                    escreverln!("fotos: estado {}", f.codigo());
                }
            }
        }
        REENVIAR => {
            let Some((endpoint, corpo, nonce, id)) = &m.ultimo else {
                escreverln!("fotos: reenvio SEM_ENTREGA");
                return;
            };
            match malha::enviar(endpoint, INTENCAO, corpo, *nonce) {
                Ok(de_novo) if de_novo == *id => {
                    escreverln!("fotos: reenvio igual");
                }
                Ok(_) => {
                    escreverln!("fotos: reenvio diferente");
                }
                Err(f) => {
                    escreverln!("fotos: reenvio {}", f.codigo());
                }
            }
        }
        VELHO => {
            let Some((endpoint, _, nonce, _)) = &m.ultimo else {
                escreverln!("fotos: velho SEM_ENTREGA");
                return;
            };
            match malha::enviar(
                endpoint,
                INTENCAO,
                "outra.png",
                nonce.saturating_sub(1).max(1),
            ) {
                Ok(id) => {
                    escreverln!("fotos: velho aceito {}", id);
                }
                Err(f) => {
                    escreverln!("fotos: velho {}", f.codigo());
                }
            }
        }
        CANCELAR => {
            let Some((_, _, _, id)) = &m.ultimo else {
                escreverln!("fotos: cancelar SEM_ENTREGA");
                return;
            };
            match malha::cancelar(id) {
                Ok(estado) => {
                    escreverln!("fotos: cancelar {}", estado);
                }
                Err(f) => {
                    escreverln!("fotos: cancelar {}", f.codigo());
                }
            }
        }
        _ => {
            escreverln!("fotos: passo desconhecido {}", a);
        }
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let canal = sistema::escutar(CANAL);
    if canal < 0 {
        escreverln!("fotos: escutar devolveu {}", canal);
        return 1;
    }
    escreverln!("fotos: pronto");
    let mut memoria = Memoria::default();
    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("fotos: a leitura falhou: {}", e);
                return 2;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                escreverln!("fotos: encerrado");
                return CODIGO;
            }
            if e.tipo == tipo::ACAO {
                passo(&mut memoria, e.a, e.b);
            }
        }
    }
}
