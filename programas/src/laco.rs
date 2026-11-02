//! O laço de eventos: a espera única do processo, no canal de eventos dele —
//! a janela, o pseudo-terminal e a malha, num lugar só.
//!
//! # Por que
//!
//! Um processo do Duke tem um fio só, e um pedido que espera espera **um**
//! objeto: um programa parado num `stream.read` não vê a tecla, o outro
//! fluxo, nem o pedido novo no endpoint. A espera certa é uma só, no canal
//! de eventos do processo — o que o Terminal já faz com o teclado e a saída
//! do console —, e o kernel avisa ali o que ficou pronto:
//!
//! - a janela manda a entrada para o canal ([`Laco::descritor`], com a
//!   operação `ENTRADA` da superfície);
//! - a malha avisa os objetos que o programa pediu com `notify` — o endpoint
//!   de [`crate::malha::oferecer_avisando`], as pontas de
//!   [`crate::fluxo::abrir_avisando`] e de [`crate::fluxo::aceitar_avisando`]
//!   — com um evento [`MALHA`](protocolo::usuario::evento::tipo::MALHA).
//!
//! O aviso só **sinaliza**: diz qual objeto e que prontidão, e nada mais. O
//! que o programa faz com ele é um pedido ao gate — ler, escrever, aceitar,
//! receber —, e o pedido pode não achar nada (outro evento chegou antes) ou
//! ser recusado (a autoridade mudou). Um objeto tem no máximo um aviso não
//! consumido; a próxima operação do programa sobre ele o rearma. Por isso o
//! programa que acorda por um aviso **opera** sobre o objeto — lê até não
//! haver mais, escreve o que tem, aceita o pedido.
//!
//! # Como se usa
//!
//! ```ignore
//! use programas::laco::{Acontecimento, Laco};
//!
//! let mut laco = Laco::novo()?;
//! let endpoint = malha::oferecer_avisando("texto.editar", &laco)?;
//! loop {
//!     for a in laco.esperar()? {
//!         match a {
//!             Acontecimento::Endpoint { numero, prontidao } if prontidao.pedido() => {
//!                 if let Some((f, de)) = fluxo::aceitar_avisando(&endpoint, &laco)? { /* … */ }
//!             }
//!             Acontecimento::Fluxo { numero, prontidao } => { /* ler, escrever */ }
//!             Acontecimento::Evento(e) => { /* teclado, ponteiro, ação */ }
//!             _ => {}
//!         }
//!     }
//! }
//! ```

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::sistema;
use protocolo::usuario::evento::{self, Evento, malha};

/// Os bits de prontidão de um aviso, como o kernel os mandou. Cada
/// pergunta olha um bit que esta versão conhece; um bit que ela não conhece
/// — de um kernel mais novo — não muda nenhuma resposta.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Prontidao(i64);

impl Prontidao {
    fn tem(self, bit: i64) -> bool {
        self.0 & bit != 0
    }

    /// Ponta: há dado para ler, ou o fim do sentido ainda não lido.
    pub fn legivel(self) -> bool {
        self.tem(malha::LEGIVEL)
    }

    /// Ponta: há espaço para escrever, ou a abertura.
    pub fn gravavel(self) -> bool {
        self.tem(malha::GRAVAVEL)
    }

    /// O objeto acabou: a próxima operação diz o motivo. É o último aviso.
    pub fn fim(self) -> bool {
        self.tem(malha::FIM)
    }

    /// Endpoint: um pedido de fluxo esperando o aceite.
    pub fn pedido(self) -> bool {
        self.tem(malha::PEDIDO)
    }

    /// Endpoint: uma entrega pendente.
    pub fn entrega(self) -> bool {
        self.tem(malha::ENTREGA)
    }

    /// Os bits crus, como vieram — também os que esta versão não conhece.
    pub fn bits(self) -> i64 {
        self.0
    }
}

/// O que acordou o laço.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acontecimento {
    /// Um endpoint deste processo ficou pronto: o número do id dele.
    Endpoint { numero: u64, prontidao: Prontidao },
    /// Uma ponta de fluxo deste processo ficou pronta: o número do id dele.
    Fluxo { numero: u64, prontidao: Prontidao },
    /// Outro evento do canal — a janela, o pseudo-terminal, a suíte.
    Evento(Evento),
}

impl Acontecimento {
    /// O acontecimento de um evento do canal. Um aviso da malha com um tipo
    /// de objeto que esta versão não conhece é ignorado: `None`.
    pub fn de(e: Evento) -> Option<Acontecimento> {
        if e.tipo != evento::tipo::MALHA {
            return Some(Acontecimento::Evento(e));
        }
        if e.b < 0 {
            return None;
        }
        let numero = e.b as u64;
        let prontidao = Prontidao(e.c);
        match e.a {
            malha::ENDPOINT => Some(Acontecimento::Endpoint { numero, prontidao }),
            malha::PONTA => Some(Acontecimento::Fluxo { numero, prontidao }),
            _ => None,
        }
    }
}

/// O número de um id da malha, `<época>:<n>` — o mesmo que o aviso leva.
pub fn numero_do_id(id: &str) -> Option<u64> {
    let (_, n) = id.rsplit_once(':')?;
    if n.is_empty() || !n.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
}

/// O laço: o canal de eventos deste processo.
pub struct Laco {
    descritor: u64,
    nome: String,
}

/// Quantos nomes [`Laco::novo`] tenta.
const NOMES: u64 = 16;

impl Laco {
    /// Escuta um canal só deste processo: `laco-<id>`, ou, se outro processo
    /// já tem esse nome, `laco-<id>-1`, `laco-<id>-2`… — o nome é previsível,
    /// e quem o tomasse antes não deve impedir o programa de subir. O erro é
    /// o da última tentativa da chamada `escutar` — `OCUPADO` com os nomes
    /// tomados, sem vaga, ou com o teto do processo.
    pub fn novo() -> Result<Laco, i64> {
        let id = sistema::id();
        let mut r = Laco::com_nome(&format!("laco-{id}"));
        for k in 1..NOMES {
            match r {
                Err(e) if e == protocolo::usuario::erro::OCUPADO => {
                    r = Laco::com_nome(&format!("laco-{id}-{k}"));
                }
                _ => break,
            }
        }
        r
    }

    /// Escuta o canal `nome` — um que só este processo usa.
    pub fn com_nome(nome: &str) -> Result<Laco, i64> {
        let d = sistema::escutar(nome);
        if d < 0 {
            return Err(d);
        }
        Ok(Laco {
            descritor: d as u64,
            nome: String::from(nome),
        })
    }

    /// O descritor do canal: o `notify` dos pedidos, e o argumento de
    /// `ENTRADA` e de `terminal`.
    pub fn descritor(&self) -> u64 {
        self.descritor
    }

    /// O nome do canal.
    pub fn nome(&self) -> &str {
        &self.nome
    }

    /// Espera o próximo evento — o único lugar em que o processo dorme — e
    /// devolve o que chegou, na ordem.
    pub fn esperar(&mut self) -> Result<Vec<Acontecimento>, i64> {
        let mut eventos = [Evento::default(); 16];
        let n = sistema::ler_eventos(self.descritor, &mut eventos)?;
        Ok(eventos[..n]
            .iter()
            .filter_map(|e| Acontecimento::de(*e))
            .collect())
    }
}

#[cfg(test)]
mod testes {
    // O runtime não tem testes no hospedeiro: o alvo é `none`. A conta do
    // laço — o que um evento vira — é a mesma de `politica::aviso`, testada
    // lá (NH07), e o laço inteiro roda na suíte (`sdk:`).
}
