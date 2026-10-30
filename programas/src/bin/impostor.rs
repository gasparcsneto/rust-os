//! O impostor: um programa que **diz** ser o `correio` — o manifesto dele
//! tem o mesmo nome — e tenta, pela malha, o que não é dele. O outro lado
//! dos casos de segurança `malha:` da suíte.
//!
//! O nome é o que o programa diz; o resumo da imagem é o que ele é. A malha
//! mostra os dois, conferidos pelo kernel, e quem procura vê dois `correio`
//! com resumos diferentes. E nada do que é do outro se alcança pelo id:
//! nem ler o que chega ao endpoint dele, nem fechá-lo, nem confirmar ou
//! consultar uma entrega dele — cada tentativa é decidida pelo gate, e a
//! auditoria grava quem tentou.
//!
//! Escuta o canal [`CANAL`]; cada evento [`tipo::ACAO`] é um passo:
//!
//! - [`OFERECER`]: oferece `imagem.compartilhar` — `impostor: endpoint <id>`;
//! - [`DESCOBRIR`]: procura quem oferece — `impostor: achei <n>` e uma
//!   linha `impostor: candidato <programa> <resumo> <endpoint>` por um;
//! - [`LER`]: lê o endpoint do candidato `b`;
//! - [`RETIRAR`]: fecha o endpoint do candidato `b`;
//! - [`CONFIRMAR`]: confirma a entrega de número `b`, nesta época;
//! - [`ESTADO`]: consulta a entrega de número `b`;
//! - [`FORJAR`]: manda ao endpoint de número `b` com uma época inventada;
//! - [`MANDAR_A`]: manda ao endpoint de número `b`, nesta época.
//!
//! Cada passo diz `impostor: <passo> <código>` — o código da recusa, ou
//! `ALLOW` se passou. Sai com [`CODIGO`] quando a suíte pede o fim.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!("correio", "fabric.offer", "fabric.send");

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use programas::escreverln;
use programas::malha::{self, Candidato, Falha};
use programas::sistema;
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 45;

/// O canal por onde a suíte dita o passo.
const CANAL: &str = "teste-impostor";

/// A intenção de todos os passos.
const INTENCAO: &str = "imagem.compartilhar";

/// Os passos — o `a` do evento.
const OFERECER: i64 = 1;
const DESCOBRIR: i64 = 2;
const LER: i64 = 3;
const RETIRAR: i64 = 4;
const CONFIRMAR: i64 = 5;
const ESTADO: i64 = 6;
const FORJAR: i64 = 7;
const MANDAR_A: i64 = 8;

#[derive(Default)]
struct Memoria {
    candidatos: Vec<Candidato>,
    /// A época deste boot, tirada de um id que a malha devolveu.
    epoca: Option<String>,
    nonce: u64,
}

impl Memoria {
    fn lembrar_epoca(&mut self, id: &str) {
        if let Some((e, _)) = id.split_once(':') {
            self.epoca = Some(String::from(e));
        }
    }

    fn id(&self, n: i64) -> String {
        format!(
            "{}:{n}",
            self.epoca.as_deref().unwrap_or("0000000000000000")
        )
    }

    fn endpoint_do_candidato(&self, b: i64) -> String {
        self.candidatos
            .get(b as usize)
            .map_or_else(String::new, |c| c.endpoint.clone())
    }
}

/// O que um passo ouviu, em uma palavra.
fn desfecho<T>(r: &Result<T, Falha>) -> &str {
    match r {
        Ok(_) => "ALLOW",
        Err(f) => f.codigo(),
    }
}

fn passo(m: &mut Memoria, a: i64, b: i64) {
    match a {
        OFERECER => match malha::oferecer(INTENCAO) {
            Ok(e) => {
                m.lembrar_epoca(&e);
                escreverln!("impostor: endpoint {}", e);
            }
            Err(f) => {
                escreverln!("impostor: oferecer {}", f.codigo());
            }
        },
        DESCOBRIR => match malha::descobrir(INTENCAO) {
            Ok(v) => {
                escreverln!("impostor: achei {}", v.len());
                for c in &v {
                    escreverln!(
                        "impostor: candidato {} {} {}",
                        c.programa,
                        c.resumo.get(..8).unwrap_or(&c.resumo),
                        c.endpoint
                    );
                }
                if let Some(c) = v.first() {
                    m.lembrar_epoca(&c.endpoint.clone());
                }
                m.candidatos = v;
            }
            Err(f) => {
                escreverln!("impostor: descobrir {}", f.codigo());
            }
        },
        LER => {
            let r = malha::receber(&m.endpoint_do_candidato(b), None, 0);
            escreverln!("impostor: ler {}", desfecho(&r));
        }
        RETIRAR => {
            let r = malha::retirar(&m.endpoint_do_candidato(b));
            escreverln!("impostor: retirar {}", desfecho(&r));
        }
        CONFIRMAR => {
            let r = malha::confirmar(&m.id(b), Some("roubada"));
            escreverln!("impostor: confirmar {}", desfecho(&r));
        }
        ESTADO => {
            let r = malha::estado(&m.id(b));
            escreverln!("impostor: estado {}", desfecho(&r));
        }
        FORJAR => {
            m.nonce += 1;
            let r = malha::enviar(
                &format!("ffffffffffffffff:{b}"),
                INTENCAO,
                "forjada",
                m.nonce,
            );
            escreverln!("impostor: forjar {}", desfecho(&r));
        }
        MANDAR_A => {
            m.nonce += 1;
            let r = malha::enviar(&m.id(b), INTENCAO, "intrusa", m.nonce);
            escreverln!("impostor: mandar {}", desfecho(&r));
        }
        _ => {
            escreverln!("impostor: passo desconhecido {}", a);
        }
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let canal = sistema::escutar(CANAL);
    if canal < 0 {
        escreverln!("impostor: escutar devolveu {}", canal);
        return 1;
    }
    escreverln!("impostor: pronto");
    let mut memoria = Memoria::default();
    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("impostor: a leitura falhou: {}", e);
                return 2;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                escreverln!("impostor: encerrado");
                return CODIGO;
            }
            if e.tipo == tipo::ACAO {
                passo(&mut memoria, e.a, e.b);
            }
        }
    }
}
