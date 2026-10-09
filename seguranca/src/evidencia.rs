//! O cofre de evidências: o que prova cada detecção e cada ação, numa
//! cadeia de resumos própria.
//!
//! # A cadeia
//!
//! A mesma construção da auditoria, com outro rótulo — um elo de um nunca
//! é o elo do outro:
//!
//! ```text
//! elo(n) = BLAKE2s("Duke evidencia v1" || elo(n-1) || codificacao(n))
//! ```
//!
//! Cada item aponta o que prova. Um registro da auditoria entra pela
//! sequência **e pelo elo dele**: o cofre se amarra à cadeia que o gate
//! escreveu, e quem tem os dois confere um contra o outro. Um datagrama
//! entra pelo resumo dos bytes e pelo tamanho — nunca pelo conteúdo. Uma
//! detecção, pela regra e pelos registros que a dispararam; uma ação, pelo
//! pedido, pelo nível e pela decisão do gate que a deixou, ou não,
//! acontecer.
//!
//! # A memória
//!
//! Um anel, como o da auditoria: o item que sai deixa o elo dele como
//! âncora, e a janela que fica continua verificável a partir dela.
//!
//! O cofre complementa a auditoria: não guarda nada que ela devesse
//! guardar, e não a substitui.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use blake2::{Blake2s256, Digest};

/// O rótulo do elo.
const ROTULO: &[u8] = b"Duke evidencia v1";

/// Quantos itens o cofre guarda.
pub const CAPACIDADE: usize = 512;

/// O que um item prova.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prova {
    /// Um registro da auditoria: a sequência e o elo dele.
    Registro { seq: u64, elo: [u8; 32] },
    /// Um datagrama capturado: o número na captura, o destino, o resumo
    /// BLAKE2s dos bytes e o tamanho.
    Datagrama {
        captura: u64,
        destino: String,
        resumo: [u8; 32],
        tamanho: u32,
    },
    /// Uma detecção: a regra e os registros que a dispararam.
    Deteccao {
        regra: &'static str,
        registros: Vec<u64>,
    },
    /// Uma ação: o método e o recurso pedidos, o nível, e o desfecho — o
    /// código e, quando a auditoria já mostrou, a decisão do gate.
    Acao {
        acao: u64,
        metodo: String,
        recurso: String,
        nivel: u8,
        codigo: String,
        decisao: Option<u64>,
    },
}

/// Um item do cofre.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub id: u64,
    pub ts_ms: u64,
    pub incidente: Option<u64>,
    pub prova: Prova,
    pub anterior: [u8; 32],
    pub elo: [u8; 32],
}

/// Um campo variável com o tamanho na frente: dois itens diferentes nunca
/// viram os mesmos bytes.
fn campo(h: &mut Blake2s256, b: &[u8]) {
    h.update((b.len() as u32).to_le_bytes());
    h.update(b);
}

/// O elo de um item, dado o anterior.
pub fn elo(
    anterior: &[u8; 32],
    id: u64,
    ts_ms: u64,
    incidente: Option<u64>,
    prova: &Prova,
) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(ROTULO);
    h.update(anterior);
    h.update(id.to_le_bytes());
    h.update(ts_ms.to_le_bytes());
    match incidente {
        Some(i) => {
            h.update([1]);
            h.update(i.to_le_bytes());
        }
        None => h.update([0]),
    }
    match prova {
        Prova::Registro { seq, elo } => {
            h.update([0]);
            h.update(seq.to_le_bytes());
            h.update(elo);
        }
        Prova::Datagrama {
            captura,
            destino,
            resumo,
            tamanho,
        } => {
            h.update([1]);
            h.update(captura.to_le_bytes());
            campo(&mut h, destino.as_bytes());
            h.update(resumo);
            h.update(tamanho.to_le_bytes());
        }
        Prova::Deteccao { regra, registros } => {
            h.update([2]);
            campo(&mut h, regra.as_bytes());
            h.update((registros.len() as u32).to_le_bytes());
            for r in registros {
                h.update(r.to_le_bytes());
            }
        }
        Prova::Acao {
            acao,
            metodo,
            recurso,
            nivel,
            codigo,
            decisao,
        } => {
            h.update([3]);
            h.update(acao.to_le_bytes());
            campo(&mut h, metodo.as_bytes());
            campo(&mut h, recurso.as_bytes());
            h.update([*nivel]);
            campo(&mut h, codigo.as_bytes());
            match decisao {
                Some(d) => {
                    h.update([1]);
                    h.update(d.to_le_bytes());
                }
                None => h.update([0]),
            }
        }
    }
    h.finalize().into()
}

/// O resumo dos bytes de um datagrama.
pub fn resumo(bytes: &[u8]) -> [u8; 32] {
    Blake2s256::digest(bytes).into()
}

/// O cofre.
#[derive(Clone, Debug)]
pub struct Cofre {
    itens: VecDeque<Item>,
    ancora: [u8; 32],
    proximo: u64,
}

impl Default for Cofre {
    fn default() -> Cofre {
        Cofre {
            itens: VecDeque::new(),
            ancora: [0; 32],
            proximo: 1,
        }
    }
}

impl Cofre {
    pub fn novo() -> Cofre {
        Cofre::default()
    }

    /// O elo do último item; a âncora, sem nenhum.
    pub fn cabeca(&self) -> [u8; 32] {
        self.itens.back().map_or(self.ancora, |i| i.elo)
    }

    /// De onde a janela guardada parte.
    pub fn ancora(&self) -> [u8; 32] {
        self.ancora
    }

    /// Guarda uma prova; devolve o número dela.
    pub fn guardar(&mut self, ts_ms: u64, incidente: Option<u64>, prova: Prova) -> u64 {
        let id = self.proximo;
        self.proximo += 1;
        let anterior = self.cabeca();
        let elo = elo(&anterior, id, ts_ms, incidente, &prova);
        if self.itens.len() == CAPACIDADE
            && let Some(saiu) = self.itens.pop_front()
        {
            self.ancora = saiu.elo;
        }
        self.itens.push_back(Item {
            id,
            ts_ms,
            incidente,
            prova,
            anterior,
            elo,
        });
        id
    }

    /// Um item, pelo número.
    pub fn item(&self, id: u64) -> Option<&Item> {
        self.itens.iter().find(|i| i.id == id)
    }

    /// Os itens de um incidente.
    pub fn do_incidente(&self, incidente: u64) -> impl Iterator<Item = &Item> {
        self.itens
            .iter()
            .filter(move |i| i.incidente == Some(incidente))
    }

    /// Quantos itens a janela guarda.
    pub fn guardados(&self) -> usize {
        self.itens.len()
    }

    /// Refaz a cadeia da âncora à cabeça. `Err` com o primeiro item que
    /// não confere.
    pub fn verificar(&self) -> Result<[u8; 32], u64> {
        let mut anterior = self.ancora;
        for i in &self.itens {
            if i.anterior != anterior
                || elo(&anterior, i.id, i.ts_ms, i.incidente, &i.prova) != i.elo
            {
                return Err(i.id);
            }
            anterior = i.elo;
        }
        Ok(anterior)
    }

    /// Só para os testes: a mão que adultera um item guardado.
    #[cfg(test)]
    pub(crate) fn adulterar(&mut self, id: u64, f: impl FnOnce(&mut Item)) {
        if let Some(i) = self.itens.iter_mut().find(|i| i.id == id) {
            f(i);
        }
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use alloc::string::ToString;

    fn cheio(n: u64) -> Cofre {
        let mut c = Cofre::novo();
        for i in 0..n {
            let prova = match i % 4 {
                0 => Prova::Registro {
                    seq: i,
                    elo: [i as u8; 32],
                },
                1 => Prova::Datagrama {
                    captura: i,
                    destino: "udp:10.0.2.3:53".to_string(),
                    resumo: resumo(&[i as u8]),
                    tamanho: 40,
                },
                2 => Prova::Deteccao {
                    regra: "regra",
                    registros: alloc::vec![i, i + 1],
                },
                _ => Prova::Acao {
                    acao: i,
                    metodo: "net.block".to_string(),
                    recurso: "tcp:10.0.2.100:7".to_string(),
                    nivel: 3,
                    codigo: "ALLOW".to_string(),
                    decisao: Some(i),
                },
            };
            c.guardar(i * 10, (i % 3 == 0).then_some(1), prova);
        }
        c
    }

    #[test]
    fn a_cadeia_se_refaz() {
        let c = cheio(20);
        assert_eq!(c.verificar(), Ok(c.cabeca()));
        assert_eq!(c.do_incidente(1).count(), 7);
    }

    /// Qualquer campo mudado depois de guardado: a verificação aponta o
    /// item.
    #[test]
    fn adulterar_aparece() {
        for alvo in 1..=8 {
            let mut c = cheio(8);
            c.adulterar(alvo, |i| match &mut i.prova {
                Prova::Registro { seq, .. } => *seq += 1,
                Prova::Datagrama { tamanho, .. } => *tamanho += 1,
                Prova::Deteccao { registros, .. } => registros.push(9),
                Prova::Acao { codigo, .. } => *codigo = "DENY_RESOURCE".to_string(),
            });
            assert_eq!(c.verificar(), Err(alvo), "item {alvo}");
        }
        let mut c = cheio(3);
        c.adulterar(2, |i| i.incidente = Some(99));
        assert_eq!(c.verificar(), Err(2));
    }

    /// O anel cheio: a âncora segura a janela que fica.
    #[test]
    fn o_anel() {
        let c = cheio(CAPACIDADE as u64 + 7);
        assert_eq!(c.guardados(), CAPACIDADE);
        assert_ne!(c.ancora(), [0; 32]);
        assert_eq!(c.verificar(), Ok(c.cabeca()));
        assert!(c.item(1).is_none());
        assert!(c.item(CAPACIDADE as u64 + 7).is_some());
    }

    /// O rótulo separa o cofre da auditoria: o mesmo conteúdo, outro elo.
    #[test]
    fn o_rotulo_separa() {
        let p = Prova::Registro {
            seq: 1,
            elo: [1; 32],
        };
        let a = elo(&[0; 32], 1, 1, None, &p);
        let b = elo(&[0; 32], 1, 1, Some(0), &p);
        assert_ne!(a, b);
        assert_ne!(a, [0; 32]);
    }
}
