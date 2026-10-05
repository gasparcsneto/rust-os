//! Versões e arrendamentos: quem mexe num recurso compartilhado, e quando.
//!
//! # O problema
//!
//! Uma pessoa e um agente — ou dois agentes, ou duas pessoas — mexendo no
//! mesmo recurso ao mesmo tempo: a linha de comando, um campo de janela. O
//! `set_value` de um apaga o que o outro digitou, e o `confirm` executa uma
//! linha que nenhum dos dois escreveu inteira. A política diz **quem pode**;
//! isto diz **quem está mexendo agora**, e se o que cada um viu ainda é o
//! que está lá.
//!
//! # Versão
//!
//! Cada recurso tem uma versão, que só cresce, e só numa mudança feita. Quem
//! muda diz a versão que leu (`expect_version`); se não é a de agora,
//! alguém mudou no meio: `CONFLICT`, e nada muda. Dois que leram a versão
//! 10 não mudam os dois a partir dela: o segundo recebe o conflito e lê de
//! novo.
//!
//! # Arrendamento
//!
//! Um titular pode tomar o recurso para si por um tempo: um arrendamento,
//! exclusivo, com prazo. Enquanto ele vale, ninguém mais muda o recurso —
//! nem toma o arrendamento: `CONFLICT`. Ele acaba de quatro jeitos, e só
//! desses:
//!
//! - o titular o solta;
//! - o prazo vence — a atividade do titular o renova;
//! - a sessão ou a identidade do titular acaba — saiu, foi revogada —, e o
//!   arrendamento com ela, na hora;
//! - uma operação administrativa o revoga, com prova.
//!
//! Não há preempção: ninguém toma o arrendamento de outro por ter um papel
//! maior, e pessoa e agente são titulares do mesmo jeito, sem prioridade de
//! um sobre o outro.
//!
//! # O titular
//!
//! Não é um processo nem um console: é a sessão **e** a identidade —
//! [`Titular`]. Uma pessoa que entra de novo é outra sessão, e não herda o
//! arrendamento da anterior; uma chave revogada não segura o dela por
//! continuar com a porta aberta.
//!
//! # Uma tabela, e o resto fora
//!
//! Aqui está só a conta, sem relógio nem auditoria: quem chama diz a hora e
//! grava o que a conta devolveu. A tabela é uma árvore por nome de recurso, e
//! cada recurso tem **um** lugar para um arrendamento: dois arrendamentos
//! válidos no mesmo recurso não são representáveis.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// O menor prazo de um arrendamento, em milissegundos.
pub const MENOR_PRAZO_MS: u64 = 1_000;
/// O maior: cinco minutos. Um arrendamento sem prazo seria um recurso
/// preso por quem esqueceu dele.
pub const MAIOR_PRAZO_MS: u64 = 300_000;

/// Quem pode ter um arrendamento.
///
/// A sessão e a identidade, as duas: [`Titular::Pessoa`] é a sessão de
/// pessoa sorteada no login e o identificador da pessoa; [`Titular::Agente`]
/// é a sessão do canal e a chave que provou o aperto. A serial — sessão do
/// canal sem chave — é um agente sem chave.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Titular {
    Pessoa { sessao: [u8; 8], pessoa: [u8; 8] },
    Agente { sessao: u8, chave: Option<[u8; 32]> },
}

impl Titular {
    /// É uma pessoa?
    pub const fn e_pessoa(&self) -> bool {
        matches!(self, Titular::Pessoa { .. })
    }
}

/// Um arrendamento em vigor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arrendamento {
    pub titular: Titular,
    pub desde_ms: u64,
    pub expira_ms: u64,
    /// O prazo pedido: o quanto a atividade do titular o estende.
    pub prazo_ms: u64,
}

impl Arrendamento {
    fn valido(&self, agora_ms: u64) -> bool {
        agora_ms < self.expira_ms
    }
}

/// O estado de um recurso.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Estado {
    pub versao: u64,
    pub arrendamento: Option<Arrendamento>,
}

/// Por que uma conta recusou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// Outro titular tem o arrendamento.
    Ocupado(Titular),
    /// A versão esperada não é a de agora.
    Versao { esperada: u64, atual: u64 },
    /// A operação pede o arrendamento, e quem pediu não o tem.
    SemArrendamento,
    /// Soltar o que não é seu.
    NaoETitular,
}

impl Recusa {
    /// O código da auditoria.
    pub const fn codigo(self) -> crate::Codigo {
        match self {
            Recusa::Ocupado(_) | Recusa::Versao { .. } => crate::Codigo::Conflict,
            Recusa::SemArrendamento | Recusa::NaoETitular => crate::Codigo::DenyLease,
        }
    }

    pub const fn motivo(self) -> &'static str {
        match self {
            Recusa::Ocupado(_) => "outro titular tem o arrendamento",
            Recusa::Versao { .. } => "a versao esperada nao e a de agora",
            Recusa::SemArrendamento => "a operacao pede o arrendamento",
            Recusa::NaoETitular => "o arrendamento nao e de quem pediu",
        }
    }
}

/// O que aconteceu além do pedido: um arrendamento que venceu no caminho.
/// Quem chama grava.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vencido(pub Arrendamento);

/// A tabela de recursos.
#[derive(Default)]
pub struct Tabela {
    recursos: BTreeMap<String, Estado>,
}

impl Tabela {
    pub const fn nova() -> Tabela {
        Tabela {
            recursos: BTreeMap::new(),
        }
    }

    /// O estado de um recurso agora — um recurso nunca tocado é a versão
    /// zero, livre. Um arrendamento vencido aparece como livre.
    pub fn estado(&self, recurso: &str, agora_ms: u64) -> Estado {
        let mut e = self.recursos.get(recurso).copied().unwrap_or_default();
        if e.arrendamento.is_some_and(|a| !a.valido(agora_ms)) {
            e.arrendamento = None;
        }
        e
    }

    /// Tira o arrendamento vencido de um recurso, e diz qual era.
    fn vencer(&mut self, recurso: &str, agora_ms: u64) -> Option<Vencido> {
        let e = self.recursos.get_mut(recurso)?;
        let a = e.arrendamento?;
        if a.valido(agora_ms) {
            return None;
        }
        e.arrendamento = None;
        Some(Vencido(a))
    }

    /// Toma o arrendamento de um recurso por `prazo_ms` — limitado a
    /// [`MENOR_PRAZO_MS`]..=[`MAIOR_PRAZO_MS`]. Do mesmo titular, renova.
    /// De outro, e válido, `Ocupado`.
    pub fn tomar(
        &mut self,
        recurso: &str,
        titular: Titular,
        agora_ms: u64,
        prazo_ms: u64,
    ) -> (Result<Arrendamento, Recusa>, Option<Vencido>) {
        let vencido = self.vencer(recurso, agora_ms);
        let prazo = prazo_ms.clamp(MENOR_PRAZO_MS, MAIOR_PRAZO_MS);
        let e = self.recursos.entry(String::from(recurso)).or_default();
        let r = match e.arrendamento {
            Some(a) if a.titular != titular => Err(Recusa::Ocupado(a.titular)),
            atual => {
                let novo = Arrendamento {
                    titular,
                    desde_ms: atual.map_or(agora_ms, |a| a.desde_ms),
                    expira_ms: agora_ms.saturating_add(prazo),
                    prazo_ms: prazo,
                };
                e.arrendamento = Some(novo);
                Ok(novo)
            }
        };
        (r, vencido)
    }

    /// Solta o arrendamento, se for de `titular`.
    pub fn soltar(
        &mut self,
        recurso: &str,
        titular: Titular,
        agora_ms: u64,
    ) -> (Result<Arrendamento, Recusa>, Option<Vencido>) {
        let vencido = self.vencer(recurso, agora_ms);
        let r = match self.recursos.get_mut(recurso) {
            Some(e) => match e.arrendamento {
                Some(a) if a.titular == titular => {
                    e.arrendamento = None;
                    Ok(a)
                }
                _ => Err(Recusa::NaoETitular),
            },
            None => Err(Recusa::NaoETitular),
        };
        (r, vencido)
    }

    /// Muda o recurso, em nome de `titular`: confere e, se passar, a versão
    /// cresce de um. Devolve a versão nova.
    ///
    /// - Com o arrendamento de outro, válido: `Ocupado` — com ou sem
    ///   versão esperada, e mesmo que a operação não peça arrendamento: o
    ///   recurso arrendado é de quem o arrendou.
    /// - `exige_arrendamento` e o titular não o tem: `SemArrendamento`.
    /// - `esperada` diferente da de agora: `Versao`.
    ///
    /// Na recusa nada muda: nem a versão, nem o arrendamento. O
    /// arrendamento de quem mudou é renovado pela atividade, pelo mesmo
    /// prazo que ele tinha.
    pub fn mudar(
        &mut self,
        recurso: &str,
        titular: Titular,
        esperada: Option<u64>,
        exige_arrendamento: bool,
        agora_ms: u64,
    ) -> (Result<u64, Recusa>, Option<Vencido>) {
        let vencido = self.vencer(recurso, agora_ms);
        let e = self.recursos.get(recurso).copied().unwrap_or_default();
        let r = match e.arrendamento {
            Some(a) if a.titular != titular => Err(Recusa::Ocupado(a.titular)),
            None if exige_arrendamento => Err(Recusa::SemArrendamento),
            _ => match esperada {
                Some(v) if v != e.versao => Err(Recusa::Versao {
                    esperada: v,
                    atual: e.versao,
                }),
                _ => {
                    let e = self.recursos.entry(String::from(recurso)).or_default();
                    e.versao += 1;
                    if let Some(a) = e.arrendamento.as_mut() {
                        a.expira_ms = a.expira_ms.max(agora_ms.saturating_add(a.prazo_ms));
                    }
                    Ok(e.versao)
                }
            },
        };
        (r, vencido)
    }

    /// Confere só o arrendamento de um recurso, para uma mudança feita em
    /// nome de `titular` — sem a versão desta tabela, que não muda: a
    /// versão do recurso é de quem o guarda (o armazém tem a dele).
    ///
    /// - Com o arrendamento de outro, válido: `Ocupado`.
    /// - Com o de `titular`: passa, e a atividade o renova pelo prazo dele.
    /// - Livre: passa, e continua livre — o arrendamento é opcional.
    ///
    /// Sem titular (`None`) — uma autoridade que não arrenda — só passa
    /// num recurso livre: ela não tem como ser a dona do arrendamento.
    pub fn conferir(
        &mut self,
        recurso: &str,
        titular: Option<Titular>,
        agora_ms: u64,
    ) -> (Result<(), Recusa>, Option<Vencido>) {
        let vencido = self.vencer(recurso, agora_ms);
        let r = match self
            .recursos
            .get_mut(recurso)
            .and_then(|e| e.arrendamento.as_mut())
        {
            None => Ok(()),
            Some(a) if Some(a.titular) == titular => {
                a.expira_ms = a.expira_ms.max(agora_ms.saturating_add(a.prazo_ms));
                Ok(())
            }
            Some(a) => Err(Recusa::Ocupado(a.titular)),
        };
        (r, vencido)
    }

    /// Revoga o arrendamento de um recurso, de quem for. A operação
    /// administrativa — quem chama já conferiu a prova e a permissão.
    pub fn revogar(&mut self, recurso: &str) -> Option<Arrendamento> {
        self.recursos.get_mut(recurso)?.arrendamento.take()
    }

    /// Tira todos os arrendamentos dos titulares que `acabou` diz que
    /// acabaram — uma sessão que saiu, uma chave revogada. Devolve os
    /// recursos e os arrendamentos que saíram, para a auditoria.
    pub fn invalidar(&mut self, acabou: impl Fn(&Titular) -> bool) -> Vec<(String, Arrendamento)> {
        self.invalidar_se(|a| acabou(&a.titular))
    }

    /// Tira os arrendamentos vencidos. Devolve os que saíram.
    pub fn vencer_todos(&mut self, agora_ms: u64) -> Vec<(String, Arrendamento)> {
        self.invalidar_se(|a| !a.valido(agora_ms))
    }

    fn invalidar_se(&mut self, f: impl Fn(&Arrendamento) -> bool) -> Vec<(String, Arrendamento)> {
        let mut saidos = Vec::new();
        for (nome, e) in self.recursos.iter_mut() {
            if let Some(a) = e.arrendamento
                && f(&a)
            {
                e.arrendamento = None;
                saidos.push((nome.clone(), a));
            }
        }
        saidos
    }

    /// Os recursos com arrendamento válido agora, para o relatório.
    pub fn arrendados(&self, agora_ms: u64) -> impl Iterator<Item = (&str, Estado)> {
        self.recursos
            .iter()
            .filter(move |(_, e)| e.arrendamento.is_some_and(|a| a.valido(agora_ms)))
            .map(|(n, e)| (n.as_str(), *e))
    }

    /// Para o invariante: nenhum recurso tem mais de um arrendamento.
    /// Verdadeiro por construção — um lugar por recurso —, e conferido
    /// aqui para que uma mudança na forma da tabela não o quebre calada.
    pub fn um_por_recurso(&self) -> bool {
        self.recursos
            .values()
            .all(|e| e.arrendamento.into_iter().count() <= 1)
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    const LINHA: &str = "linha:console";
    const A: Titular = Titular::Agente {
        sessao: 1,
        chave: Some([1; 32]),
    };
    const B: Titular = Titular::Agente {
        sessao: 2,
        chave: Some([2; 32]),
    };
    const ANA: Titular = Titular::Pessoa {
        sessao: [1; 8],
        pessoa: [0xa; 8],
    };
    const BIA: Titular = Titular::Pessoa {
        sessao: [2; 8],
        pessoa: [0xb; 8],
    };

    /// Uma tabela com o recurso na versão `v`.
    fn na_versao(v: u64) -> Tabela {
        let mut t = Tabela::nova();
        for _ in 0..v {
            t.mudar(LINHA, A, None, false, 0).0.unwrap();
        }
        t
    }

    /// A lê v10, B lê v10, A muda → v11, B muda esperando v10 → CONFLICT, e
    /// nada muda.
    #[test]
    fn duas_leituras_e_uma_vale() {
        let mut t = na_versao(10);
        let lida_a = t.estado(LINHA, 0).versao;
        let lida_b = t.estado(LINHA, 0).versao;
        assert_eq!((lida_a, lida_b), (10, 10));
        assert_eq!(t.mudar(LINHA, A, Some(lida_a), false, 0).0, Ok(11));
        let r = t.mudar(LINHA, B, Some(lida_b), false, 0).0;
        assert_eq!(
            r,
            Err(Recusa::Versao {
                esperada: 10,
                atual: 11
            })
        );
        assert_eq!(r.unwrap_err().codigo(), crate::Codigo::Conflict);
        assert_eq!(t.estado(LINHA, 0).versao, 11);
    }

    /// `conferir` olha só o arrendamento: livre passa e continua livre; o
    /// do titular passa e é renovado; o de outro é `Ocupado` — também para
    /// quem não arrenda. A versão da tabela não anda em nenhum caso.
    #[test]
    fn conferir_so_o_arrendamento() {
        let mut t = na_versao(3);
        assert_eq!(t.conferir(LINHA, Some(A), 0).0, Ok(()));
        assert_eq!(t.conferir(LINHA, None, 0).0, Ok(()));
        assert_eq!(t.estado(LINHA, 0).arrendamento, None);
        t.tomar(LINHA, A, 0, 1_000).0.unwrap();
        assert_eq!(t.conferir(LINHA, Some(B), 1).0, Err(Recusa::Ocupado(A)));
        assert_eq!(t.conferir(LINHA, None, 1).0, Err(Recusa::Ocupado(A)));
        assert_eq!(
            t.conferir(LINHA, Some(B), 1).0.unwrap_err().codigo(),
            crate::Codigo::Conflict
        );
        // A atividade do titular renova.
        assert_eq!(t.conferir(LINHA, Some(A), 900).0, Ok(()));
        assert_eq!(
            t.estado(LINHA, 1_500).arrendamento.map(|a| a.titular),
            Some(A)
        );
        // Vencido, passa para quem vier, e diz qual venceu.
        let (r, vencido) = t.conferir(LINHA, Some(B), 5_000);
        assert_eq!(r, Ok(()));
        assert_eq!(vencido.map(|v| v.0.titular), Some(A));
        assert_eq!(t.estado(LINHA, 5_000).versao, 3);
    }

    /// A toma, B tenta → CONFLICT; A solta, B toma → ALLOW.
    #[test]
    fn exclusivo_ate_soltar() {
        let mut t = Tabela::nova();
        assert!(t.tomar(LINHA, A, 0, 10_000).0.is_ok());
        assert_eq!(t.tomar(LINHA, B, 1, 10_000).0, Err(Recusa::Ocupado(A)));
        assert_eq!(t.soltar(LINHA, B, 2).0, Err(Recusa::NaoETitular));
        assert!(t.soltar(LINHA, A, 3).0.is_ok());
        assert_eq!(t.tomar(LINHA, B, 4, 10_000).0.map(|a| a.titular), Ok(B));
        assert!(t.um_por_recurso());
    }

    /// A tem o arrendamento, A é revogado: o arrendamento sai na hora, e A
    /// não muda mais nada que o peça.
    #[test]
    fn revogado_perde_na_hora() {
        let mut t = Tabela::nova();
        t.tomar(LINHA, A, 0, 60_000).0.unwrap();
        let saidos = t.invalidar(|x| *x == A);
        assert_eq!(saidos.len(), 1);
        assert_eq!(t.estado(LINHA, 1).arrendamento, None);
        assert_eq!(
            t.mudar(LINHA, A, None, true, 1).0,
            Err(Recusa::SemArrendamento)
        );
    }

    /// A tem o arrendamento, ele vence, B toma, e A não muda mais.
    #[test]
    fn vencido_vai_para_outro() {
        let mut t = Tabela::nova();
        t.tomar(LINHA, A, 0, 1_000).0.unwrap();
        let (r, vencido) = t.tomar(LINHA, B, 1_000, 10_000);
        assert_eq!(r.map(|a| a.titular), Ok(B));
        assert_eq!(vencido.map(|v| v.0.titular), Some(A));
        assert_eq!(
            t.mudar(LINHA, A, None, true, 1_001).0,
            Err(Recusa::Ocupado(B))
        );
    }

    /// A tem o arrendamento; B muda por uma operação permitida — depois que
    /// A soltou —; A confirma com a versão velha → CONFLICT.
    #[test]
    fn versao_velha_depois_de_outro_mudar() {
        let mut t = Tabela::nova();
        t.tomar(LINHA, A, 0, 60_000).0.unwrap();
        let lida = t.estado(LINHA, 0).versao;
        t.soltar(LINHA, A, 1).0.unwrap();
        assert_eq!(t.mudar(LINHA, B, None, false, 2).0, Ok(lida + 1));
        t.tomar(LINHA, A, 3, 60_000).0.unwrap();
        assert!(matches!(
            t.mudar(LINHA, A, Some(lida), true, 4).0,
            Err(Recusa::Versao { .. })
        ));
    }

    /// O arrendamento de outro barra a mudança mesmo sem versão e sem
    /// exigência: o recurso arrendado é de quem o arrendou.
    #[test]
    fn arrendado_e_de_quem_arrendou() {
        let mut t = Tabela::nova();
        t.tomar(LINHA, ANA, 0, 60_000).0.unwrap();
        assert_eq!(
            t.mudar(LINHA, A, None, false, 1).0,
            Err(Recusa::Ocupado(ANA))
        );
        assert_eq!(t.estado(LINHA, 1).versao, 0);
        assert_eq!(t.mudar(LINHA, ANA, None, false, 1).0, Ok(1));
    }

    /// Pessoa e agente, sem prioridade: os quatro pares dão conflito do
    /// mesmo jeito.
    #[test]
    fn sem_prioridade_entre_pessoa_e_agente() {
        for (primeiro, segundo) in [(ANA, A), (A, ANA), (A, B), (ANA, BIA)] {
            let mut t = Tabela::nova();
            t.tomar(LINHA, primeiro, 0, 60_000).0.unwrap();
            assert_eq!(
                t.tomar(LINHA, segundo, 1, 60_000).0,
                Err(Recusa::Ocupado(primeiro)),
                "{primeiro:?} contra {segundo:?}"
            );
            assert_eq!(
                t.mudar(LINHA, segundo, None, false, 1).0,
                Err(Recusa::Ocupado(primeiro))
            );
        }
    }

    /// A atividade renova; o prazo é limitado; a revogação administrativa
    /// tira de qualquer um.
    #[test]
    fn renova_limita_e_revoga() {
        let mut t = Tabela::nova();
        let a = t.tomar(LINHA, A, 0, 10).0.unwrap();
        assert_eq!(a.expira_ms, MENOR_PRAZO_MS);
        let a = t.tomar(LINHA, A, 0, u64::MAX).0.unwrap();
        assert_eq!(a.expira_ms, MAIOR_PRAZO_MS);
        t.mudar(LINHA, A, None, true, MAIOR_PRAZO_MS - 1).0.unwrap();
        assert!(t.estado(LINHA, MAIOR_PRAZO_MS + 10).arrendamento.is_some());
        assert_eq!(t.revogar(LINHA).map(|a| a.titular), Some(A));
        assert!(t.tomar(LINHA, B, MAIOR_PRAZO_MS + 10, 1_000).0.is_ok());
    }

    /// A versão só cresce numa mudança feita: nenhuma recusa a mexe.
    #[test]
    fn versao_so_cresce_na_mudanca() {
        let mut t = Tabela::nova();
        t.tomar(LINHA, A, 0, 60_000).0.unwrap();
        for r in [
            t.mudar(LINHA, B, None, false, 1).0,
            t.mudar(LINHA, A, Some(7), true, 1).0,
            t.mudar(LINHA, B, Some(0), true, 1).0,
        ] {
            assert!(r.is_err());
        }
        assert_eq!(t.estado(LINHA, 1).versao, 0);
        assert_eq!(t.vencer_todos(60_000).len(), 1);
        assert!(t.arrendados(60_000).next().is_none());
    }
}
