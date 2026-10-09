//! O incidente: o que se sabe de um ataque possível, junto.
//!
//! Atores, eventos, os registros da auditoria, os recursos afetados, a
//! evidência, o risco, as detecções, o estado e as ações — cada ação com o
//! pedido, o nível, a decisão do gate e a identidade que a autorizou.
//!
//! # Como as detecções se juntam
//!
//! Pela identidade e pelo boot: uma detecção de severidade média ou maior
//! entra no incidente aberto da mesma identidade, ou abre um. Uma de
//! severidade baixa é um fato — entra se há incidente, e não abre nenhum.
//!
//! # O estado
//!
//! `aberto` ao nascer; `contido` quando uma contenção foi permitida pelo
//! gate; `encerrado` depois de [`ENCERRAR_MS`] sem nada novo — pelo tempo
//! dos registros.

use alloc::collections::{BTreeSet, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::evento::Severidade;
use crate::regras::Deteccao;
use crate::resposta::{Acao, Estado as EstadoDaAcao};

/// Quantos incidentes o NSF guarda.
pub const MAIS_INCIDENTES: usize = 32;
/// Quanto tempo sem nada novo encerra um incidente.
pub const ENCERRAR_MS: u64 = 600_000;
/// Quantos registros, recursos e detecções um incidente guarda.
const MAIS_REGISTROS: usize = 128;
const MAIS_RECURSOS: usize = 32;
const MAIS_DETECCOES: usize = 32;
const MAIS_ACOES: usize = 16;

/// O estado de um incidente.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Estado {
    Aberto,
    Contido,
    Encerrado,
}

impl Estado {
    pub const fn nome(self) -> &'static str {
        match self {
            Estado::Aberto => "open",
            Estado::Contido => "contained",
            Estado::Encerrado => "closed",
        }
    }
}

/// Um incidente.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incidente {
    pub id: u64,
    pub epoca: u32,
    /// A identidade de quem o incidente é.
    pub principal: String,
    pub estado: Estado,
    pub severidade: Severidade,
    /// Aberto pela reprodução da história: sem resposta pedida.
    pub historico: bool,
    pub atores: BTreeSet<String>,
    pub registros: BTreeSet<u64>,
    pub recursos: BTreeSet<String>,
    pub deteccoes: Vec<Deteccao>,
    pub evidencias: Vec<u64>,
    pub acoes: Vec<Acao>,
    /// A cadeia causal a que pertence.
    pub correlacao: u64,
    pub aberto_ms: u64,
    pub atualizado_ms: u64,
    /// O gate recusou uma contenção deste incidente: nenhuma outra é pedida.
    pub contencao_negada: bool,
}

impl Incidente {
    /// Se tem uma detecção de severidade `s` ou maior, de outra regra que
    /// não a da saída depois da sondagem.
    pub fn alto(&self) -> bool {
        self.estado != Estado::Encerrado
            && self.deteccoes.iter().any(|d| {
                d.severidade >= Severidade::Alta
                    && d.regra != crate::regras::Regra::SaidaDepoisDeSondagem
            })
    }
}

/// Os incidentes.
#[derive(Clone, Debug)]
pub struct Incidentes {
    lista: VecDeque<Incidente>,
    proximo: u64,
    proxima_acao: u64,
}

impl Default for Incidentes {
    fn default() -> Incidentes {
        Incidentes {
            lista: VecDeque::new(),
            proximo: 1,
            proxima_acao: 1,
        }
    }
}

impl Incidentes {
    pub fn novo() -> Incidentes {
        Incidentes::default()
    }

    /// O incidente aberto (ou contido) de uma identidade no boot `epoca`.
    pub fn vivo_de(&self, epoca: u32, principal: &str) -> Option<&Incidente> {
        self.lista
            .iter()
            .find(|i| i.epoca == epoca && i.principal == principal && i.estado != Estado::Encerrado)
    }

    pub fn get(&self, id: u64) -> Option<&Incidente> {
        self.lista.iter().find(|i| i.id == id)
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut Incidente> {
        self.lista.iter_mut().find(|i| i.id == id)
    }

    pub fn todos(&self) -> impl DoubleEndedIterator<Item = &Incidente> {
        self.lista.iter()
    }

    pub fn todos_mut(&mut self) -> impl Iterator<Item = &mut Incidente> {
        self.lista.iter_mut()
    }

    /// Junta uma detecção: ao incidente vivo da identidade, ou a um novo, se
    /// a severidade é média ou maior. Devolve o incidente, se entrou em um.
    pub fn registrar(&mut self, d: &Deteccao, correlacao: u64, historico: bool) -> Option<u64> {
        let existente = self.lista.iter().position(|i| {
            i.epoca == d.epoca && i.principal == d.principal && i.estado != Estado::Encerrado
        });
        let i = match existente {
            Some(i) => i,
            None if d.severidade >= Severidade::Media => {
                if self.lista.len() == MAIS_INCIDENTES {
                    // Sai o encerrado mais velho; sem nenhum, o mais velho.
                    let velho = self
                        .lista
                        .iter()
                        .position(|i| i.estado == Estado::Encerrado)
                        .unwrap_or(0);
                    self.lista.remove(velho);
                }
                let id = self.proximo;
                self.proximo += 1;
                self.lista.push_back(Incidente {
                    id,
                    epoca: d.epoca,
                    principal: d.principal.clone(),
                    estado: Estado::Aberto,
                    severidade: d.severidade,
                    historico,
                    atores: BTreeSet::new(),
                    registros: BTreeSet::new(),
                    recursos: BTreeSet::new(),
                    deteccoes: Vec::new(),
                    evidencias: Vec::new(),
                    acoes: Vec::new(),
                    correlacao,
                    aberto_ms: d.ts_ms,
                    atualizado_ms: d.ts_ms,
                    contencao_negada: false,
                });
                self.lista.len() - 1
            }
            None => return None,
        };
        let inc = &mut self.lista[i];
        inc.severidade = inc.severidade.max(d.severidade);
        inc.atualizado_ms = inc.atualizado_ms.max(d.ts_ms);
        inc.atores.insert(d.principal.clone());
        for r in &d.registros {
            if inc.registros.len() < MAIS_REGISTROS {
                inc.registros.insert(*r);
            }
        }
        if let Some(alvo) = &d.alvo
            && inc.recursos.len() < MAIS_RECURSOS
        {
            inc.recursos.insert(alvo.destino.clone());
        }
        if inc.deteccoes.len() < MAIS_DETECCOES {
            inc.deteccoes.push(d.clone());
        }
        Some(inc.id)
    }

    /// Um recurso afetado.
    pub fn afetou(&mut self, id: u64, recurso: &str) {
        if let Some(inc) = self.get_mut(id)
            && !recurso.is_empty()
            && inc.recursos.len() < MAIS_RECURSOS
        {
            inc.recursos.insert(recurso.to_string());
        }
    }

    /// Acrescenta uma ação; devolve o número dela.
    pub fn agir(&mut self, id: u64, mut acao: Acao) -> Option<u64> {
        let n = self.proxima_acao;
        let inc = self.lista.iter_mut().find(|i| i.id == id)?;
        if inc.acoes.len() >= MAIS_ACOES {
            return None;
        }
        acao.id = n;
        inc.acoes.push(acao);
        self.proxima_acao += 1;
        Some(n)
    }

    /// Uma ação, pelo número.
    pub fn acao_mut(&mut self, acao: u64) -> Option<(&mut Incidente, usize)> {
        let inc = self
            .lista
            .iter_mut()
            .find(|i| i.acoes.iter().any(|a| a.id == acao))?;
        let k = inc.acoes.iter().position(|a| a.id == acao)?;
        Some((inc, k))
    }

    /// O desfecho de uma ação pedida.
    pub fn desfecho(&mut self, acao: u64, estado: EstadoDaAcao) {
        let Some((inc, k)) = self.acao_mut(acao) else {
            return;
        };
        if matches!(estado, EstadoDaAcao::Negada { .. }) {
            inc.contencao_negada = true;
        }
        if estado == EstadoDaAcao::Permitida && inc.estado == Estado::Aberto {
            inc.estado = Estado::Contido;
        }
        inc.acoes[k].estado = estado;
    }

    /// Encerra o que ficou quieto até `agora`; devolve as identidades dos
    /// encerrados.
    pub fn envelhecer(&mut self, agora: u64) -> Vec<String> {
        let mut encerrados = Vec::new();
        for inc in &mut self.lista {
            if inc.estado != Estado::Encerrado && inc.atualizado_ms + ENCERRAR_MS < agora {
                inc.estado = Estado::Encerrado;
                encerrados.push(inc.principal.clone());
            }
        }
        encerrados
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::evento::Titular;
    use crate::regras::{Alvo, Regra};
    use crate::resposta::Nivel;

    fn det(principal: &str, severidade: Severidade, ts: u64) -> Deteccao {
        Deteccao {
            regra: Regra::ForaDoAlcance,
            severidade,
            principal: principal.to_string(),
            titular: Titular::Agente,
            registros: alloc::vec![ts],
            explicacao: String::new(),
            alvo: None,
            ts_ms: ts,
            epoca: 0,
        }
    }

    #[test]
    fn as_deteccoes_se_juntam() {
        let mut is = Incidentes::novo();
        // Baixa sem incidente: nada.
        assert_eq!(
            is.registrar(&det("a", Severidade::Baixa, 1), 7, false),
            None
        );
        let id = is
            .registrar(&det("a", Severidade::Media, 2), 7, false)
            .unwrap();
        assert_eq!(
            is.registrar(&det("a", Severidade::Alta, 3), 7, false),
            Some(id)
        );
        assert_eq!(
            is.registrar(&det("a", Severidade::Baixa, 4), 7, false),
            Some(id)
        );
        let outro = is
            .registrar(&det("b", Severidade::Media, 5), 8, false)
            .unwrap();
        assert_ne!(id, outro);
        let inc = is.get(id).unwrap();
        assert_eq!(inc.severidade, Severidade::Alta);
        assert_eq!(inc.deteccoes.len(), 3);
        assert_eq!(inc.registros.iter().copied().collect::<Vec<_>>(), [2, 3, 4]);
        assert_eq!((inc.aberto_ms, inc.atualizado_ms), (2, 4));
    }

    #[test]
    fn a_acao_e_o_desfecho() {
        let mut is = Incidentes::novo();
        let mut d = det("a", Severidade::Alta, 1);
        d.alvo = Some(Alvo {
            destino: "tcp:1.2.3.4:5".to_string(),
            dono: "process:1".to_string(),
        });
        let id = is.registrar(&d, 0, false).unwrap();
        assert!(is.get(id).unwrap().recursos.contains("tcp:1.2.3.4:5"));
        let acao = Acao {
            id: 0,
            nivel: Nivel::Contencao,
            metodo: "net.block".to_string(),
            params: String::new(),
            recurso: "tcp:1.2.3.4:5".to_string(),
            estado: EstadoDaAcao::Planejada,
            decisao: None,
            autorizado_por: "service:nsf".to_string(),
            justificativa: String::new(),
        };
        let a = is.agir(id, acao.clone()).unwrap();
        is.desfecho(a, EstadoDaAcao::Permitida);
        assert_eq!(is.get(id).unwrap().estado, Estado::Contido);
        let b = is.agir(id, acao).unwrap();
        is.desfecho(
            b,
            EstadoDaAcao::Negada {
                codigo: "DENY_RESOURCE".to_string(),
            },
        );
        assert!(is.get(id).unwrap().contencao_negada);
        assert_ne!(a, b);
    }

    #[test]
    fn o_tempo_encerra() {
        let mut is = Incidentes::novo();
        let id = is
            .registrar(&det("a", Severidade::Media, 0), 0, false)
            .unwrap();
        assert!(is.envelhecer(ENCERRAR_MS).is_empty());
        assert_eq!(is.envelhecer(ENCERRAR_MS + 1), ["a"]);
        assert_eq!(is.get(id).unwrap().estado, Estado::Encerrado);
        // Encerrado, a próxima detecção abre outro.
        let novo = is
            .registrar(&det("a", Severidade::Media, ENCERRAR_MS + 2), 0, false)
            .unwrap();
        assert_ne!(novo, id);
    }

    #[test]
    fn com_teto() {
        let mut is = Incidentes::novo();
        for i in 0..(MAIS_INCIDENTES as u64 + 3) {
            is.registrar(
                &det(&alloc::format!("p{i}"), Severidade::Media, i),
                0,
                false,
            );
        }
        assert_eq!(is.todos().count(), MAIS_INCIDENTES);
        assert!(is.get(1).is_none());
    }
}
