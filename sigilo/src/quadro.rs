//! Os quadros da porta: o que delimita uma mensagem do Noise no fluxo de
//! bytes.
//!
//! # Por que não mais a quebra de linha
//!
//! Em claro, o canal do agente delimita pedidos pela quebra de linha, e o
//! JSON nunca tem uma solta. Uma mensagem cifrada tem qualquer byte, inclusive
//! `\n`: o delimitador precisa vir de fora do conteúdo. Cada quadro leva o
//! tipo e o tamanho na frente, e o leitor sabe exatamente onde ele acaba sem
//! olhar o que tem dentro.
//!
//! ```text
//! +------+-----------------+-------------------+
//! | tipo | tamanho (u16 BE)| corpo (tamanho)   |
//! +------+-----------------+-------------------+
//! ```
//!
//! Dezesseis bits bastam porque o Noise limita uma mensagem a 65 535 bytes —
//! o tamanho de um quadro é o de uma mensagem.
//!
//! # Os tipos
//!
//! - [`Tipo::Inicio`]: a primeira mensagem do aperto, do agente;
//! - [`Tipo::Resposta`]: a segunda, do Duke;
//! - [`Tipo::Dados`]: uma mensagem do transporte, nos dois sentidos;
//! - [`Tipo::Recusa`]: o Duke recusou o aperto. O corpo é o motivo, em
//!   claro — não há chave com que cifrá-lo, e ele não diz nada que quem
//!   tentou não saiba.
//! - [`Tipo::InicioEnlace`]: a primeira mensagem do aperto de um enlace
//!   entre dois Dukes — com o prólogo do enlace, consultando o registro de
//!   dispositivos, e nunca o de agentes. A vaga do agente recusa este tipo,
//!   e a do enlace recusa o [`Tipo::Inicio`].
//! - [`Tipo::PedidoDaChave`], [`Tipo::ChaveDoDuke`] e
//!   [`Tipo::InicioPareamento`]: a cerimônia de pareamento. O primeiro, vazio,
//!   pede ao Duke que aceita a pública dele; o segundo, em claro, a traz —
//!   com o desafio da janela —; o terceiro é a primeira mensagem do aperto,
//!   com o prólogo da cerimônia. A vaga do enlace só os aceita com uma
//!   janela aberta, e uma sessão de cerimônia nunca vira enlace.

use alloc::vec::Vec;

use crate::{Erro, MAIOR_MENSAGEM};

/// O tamanho do cabeçalho: um byte de tipo, dois de tamanho.
pub const CABECALHO: usize = 3;

/// O que um quadro carrega.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Tipo {
    /// A primeira mensagem do aperto de mão.
    Inicio = 1,
    /// A resposta do Duke ao aperto.
    Resposta = 2,
    /// Uma mensagem do transporte.
    Dados = 3,
    /// O aperto foi recusado; o corpo é o motivo.
    Recusa = 4,
    /// A primeira mensagem do aperto de um enlace entre dispositivos.
    InicioEnlace = 5,
    /// O iniciante de um pareamento pede a pública do Duke que aceita.
    /// Vazio.
    PedidoDaChave = 6,
    /// O anúncio do Duke que aceita: a pública dele (32 bytes) e o desafio
    /// da janela (16), em claro.
    ChaveDoDuke = 7,
    /// A primeira mensagem do aperto de um pareamento.
    InicioPareamento = 8,
}

impl Tipo {
    fn de(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::Inicio,
            2 => Self::Resposta,
            3 => Self::Dados,
            4 => Self::Recusa,
            5 => Self::InicioEnlace,
            6 => Self::PedidoDaChave,
            7 => Self::ChaveDoDuke,
            8 => Self::InicioPareamento,
            _ => return None,
        })
    }
}

/// O cabeçalho de um quadro com `tamanho` bytes de corpo.
pub fn cabecalho(tipo: Tipo, tamanho: usize) -> Result<[u8; CABECALHO], Erro> {
    if tamanho > MAIOR_MENSAGEM {
        return Err(Erro::Grande);
    }
    let t = (tamanho as u16).to_be_bytes();
    Ok([tipo as u8, t[0], t[1]])
}

/// Um quadro inteiro, cabeçalho e corpo, num vetor só.
pub fn montar(tipo: Tipo, corpo: &[u8]) -> Result<Vec<u8>, Erro> {
    let mut v = Vec::with_capacity(CABECALHO + corpo.len());
    v.extend_from_slice(&cabecalho(tipo, corpo.len())?);
    v.extend_from_slice(corpo);
    Ok(v)
}

/// Remonta quadros a partir de bytes que chegam um a um.
pub struct Leitor {
    cabecalho: [u8; CABECALHO],
    lidos: usize,
    corpo: Vec<u8>,
    pronto: bool,
}

impl Default for Leitor {
    fn default() -> Self {
        Self::novo()
    }
}

impl Leitor {
    /// Um leitor no começo de um quadro.
    pub const fn novo() -> Self {
        Self {
            cabecalho: [0; CABECALHO],
            lidos: 0,
            corpo: Vec::new(),
            pronto: false,
        }
    }

    /// Esquece o quadro pela metade: o outro lado reconectou.
    pub fn recomecar(&mut self) {
        self.lidos = 0;
        self.corpo.clear();
        self.pronto = false;
    }

    fn tamanho(&self) -> usize {
        u16::from_be_bytes([self.cabecalho[1], self.cabecalho[2]]) as usize
    }

    /// Mais um byte. Devolve o quadro quando ele se completa.
    ///
    /// Um tipo desconhecido é um erro, e não um quadro a pular: sem saber o
    /// que o quadro é, não se sabe se o resto do fluxo ainda está alinhado.
    pub fn empurrar(&mut self, byte: u8) -> Result<Option<(Tipo, &[u8])>, Erro> {
        if self.pronto {
            self.recomecar();
        }
        if self.lidos < CABECALHO {
            self.cabecalho[self.lidos] = byte;
            self.lidos += 1;
            if self.lidos == 1 && Tipo::de(byte).is_none() {
                self.recomecar();
                return Err(Erro::Quadro);
            }
            if self.lidos < CABECALHO || self.tamanho() > 0 {
                return Ok(None);
            }
        } else {
            self.corpo.push(byte);
            self.lidos += 1;
            if self.corpo.len() < self.tamanho() {
                return Ok(None);
            }
        }
        self.pronto = true;
        let tipo = Tipo::de(self.cabecalho[0]).ok_or(Erro::Quadro)?;
        Ok(Some((tipo, &self.corpo)))
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    fn ler_tudo(bytes: &[u8]) -> Vec<(Tipo, Vec<u8>)> {
        let mut l = Leitor::novo();
        let mut v = Vec::new();
        for &b in bytes {
            if let Some((t, c)) = l.empurrar(b).unwrap() {
                v.push((t, c.to_vec()));
            }
        }
        v
    }

    #[test]
    fn quadros_seguidos_com_quebras_de_linha_dentro() {
        let mut fluxo = montar(Tipo::Dados, b"a\nb\n").unwrap();
        fluxo.extend(montar(Tipo::Recusa, b"").unwrap());
        fluxo.extend(montar(Tipo::Inicio, &[0u8; 300]).unwrap());
        let q = ler_tudo(&fluxo);
        assert_eq!(q.len(), 3);
        assert_eq!(q[0], (Tipo::Dados, b"a\nb\n".to_vec()));
        assert_eq!(q[1], (Tipo::Recusa, Vec::new()));
        assert_eq!(q[2], (Tipo::Inicio, alloc::vec![0u8; 300]));
    }

    #[test]
    fn o_inicio_do_enlace_e_um_tipo_proprio() {
        let q = ler_tudo(&montar(Tipo::InicioEnlace, b"ik").unwrap());
        assert_eq!(q, alloc::vec![(Tipo::InicioEnlace, b"ik".to_vec())]);
        assert_ne!(Tipo::InicioEnlace, Tipo::Inicio);
    }

    #[test]
    fn os_quadros_do_pareamento_sao_tipos_proprios() {
        let mut fluxo = montar(Tipo::PedidoDaChave, b"").unwrap();
        fluxo.extend(montar(Tipo::ChaveDoDuke, &[0x5a; 48]).unwrap());
        fluxo.extend(montar(Tipo::InicioPareamento, b"ik").unwrap());
        assert_eq!(&fluxo[..3], &[6, 0, 0]);
        assert_eq!(&fluxo[3..6], &[7, 0, 48]);
        let q = ler_tudo(&fluxo);
        assert_eq!(
            q,
            alloc::vec![
                (Tipo::PedidoDaChave, Vec::new()),
                (Tipo::ChaveDoDuke, alloc::vec![0x5a; 48]),
                (Tipo::InicioPareamento, b"ik".to_vec()),
            ]
        );
        // Nenhum se confunde com os do agente ou do enlace.
        for t in [
            Tipo::PedidoDaChave,
            Tipo::ChaveDoDuke,
            Tipo::InicioPareamento,
        ] {
            for o in [
                Tipo::Inicio,
                Tipo::Resposta,
                Tipo::Dados,
                Tipo::Recusa,
                Tipo::InicioEnlace,
            ] {
                assert_ne!(t as u8, o as u8);
            }
        }
    }

    #[test]
    fn tipo_desconhecido_e_erro() {
        for b in [0u8, 9, 0xFF] {
            let mut l = Leitor::novo();
            assert_eq!(l.empurrar(b).err(), Some(Erro::Quadro), "{b}");
        }
    }

    #[test]
    fn maior_que_o_noise_nao_monta() {
        assert_eq!(
            montar(Tipo::Dados, &alloc::vec![0; 65_536]).err(),
            Some(Erro::Grande)
        );
        assert!(montar(Tipo::Dados, &alloc::vec![0; 65_535]).is_ok());
    }
}
