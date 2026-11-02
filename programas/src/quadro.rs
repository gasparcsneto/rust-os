//! Mensagens sobre os bytes de um fluxo: o quadro do SDK, levado ao fluxo.
//!
//! O formato — 4 bytes de comprimento, little-endian, e o corpo — é o de
//! [`protocolo::quadro`], testado no hospedeiro. **Sem número de canal, sem
//! subcanais**: um diálogo por fluxo. Quem quer duas conversas abre dois
//! fluxos, cada um decidido pelo gate, dentro dos tetos de sempre.
//!
//! ```ignore
//! use programas::quadro;
//!
//! // Quem manda:
//! let mut saida = fluxo::EscritaPendente::nova();
//! quadro::juntar(&mut saida, b"ola")?;
//! saida.escoar(&f)?;
//!
//! // Quem recebe, a cada aviso `LEGIVEL`:
//! let mut entrada = quadro::Entrada::nova(4096);
//! while let quadro::Lido::Mensagem(msg) = entrada.ler(&f)? { /* … */ }
//! ```

use alloc::vec::Vec;

use crate::fluxo::{EscritaPendente, Falha, Fluxo, MAIOR_PEDACO};

pub use protocolo::quadro::{CABECALHO, Erro, Leitor, MAIOR_CORPO, quadro};

/// Por que uma mensagem não saiu, ou não chegou.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FalhaDoQuadro {
    /// O fluxo recusou, ou acabou.
    Fluxo(Falha),
    /// O quadro não se monta, ou não se lê: o fluxo deve ser fechado.
    Quadro(Erro),
}

impl From<Falha> for FalhaDoQuadro {
    fn from(f: Falha) -> FalhaDoQuadro {
        FalhaDoQuadro::Fluxo(f)
    }
}

/// Junta a mensagem `corpo`, enquadrada, ao que `saida` vai escrever.
pub fn juntar(saida: &mut EscritaPendente, corpo: &[u8]) -> Result<(), FalhaDoQuadro> {
    let q = quadro(corpo).map_err(FalhaDoQuadro::Quadro)?;
    saida.juntar(&q);
    Ok(())
}

/// O que uma leitura de quadros achou.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lido {
    /// Uma mensagem inteira.
    Mensagem(Vec<u8>),
    /// Falta um pedaço: o próximo aviso `LEGIVEL` traz mais.
    Falta,
    /// O sentido acabou, sem nada pela metade.
    Fim,
}

/// O lado de quem lê quadros de um fluxo: o [`Leitor`] e se o sentido já
/// acabou — depois do fim, o fluxo não se lê de novo.
#[derive(Clone, Debug)]
pub struct Entrada {
    leitor: Leitor,
    acabou: bool,
}

impl Entrada {
    /// Quem lê mensagens de até `teto` bytes.
    pub fn nova(teto: usize) -> Entrada {
        Entrada {
            leitor: Leitor::novo(teto),
            acabou: false,
        }
    }

    /// Lê do fluxo o que já chegou — sem esperar — e devolve a próxima
    /// mensagem inteira, se há. No fim do fluxo, uma mensagem pela metade é
    /// [`Erro::Cortado`].
    pub fn ler(&mut self, f: &Fluxo) -> Result<Lido, FalhaDoQuadro> {
        loop {
            if let Some(m) = self.leitor.proximo().map_err(FalhaDoQuadro::Quadro)? {
                return Ok(Lido::Mensagem(m));
            }
            if self.acabou {
                self.leitor.fim().map_err(FalhaDoQuadro::Quadro)?;
                return Ok(Lido::Fim);
            }
            let (bytes, fim) = f.ler_agora(MAIOR_PEDACO)?;
            self.leitor.juntar(&bytes);
            if fim {
                self.acabou = true;
            } else if bytes.is_empty() {
                return Ok(Lido::Falta);
            }
        }
    }
}
