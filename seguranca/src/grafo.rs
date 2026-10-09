//! O grafo causal: quem lançou quem, quem pediu o quê, que nome levou a que
//! endereço, que regra barrou que destino, que incidente envolve o quê.
//!
//! # A proveniência
//!
//! Cada processo que nasce — pelo `user.run` de alguém, pelo `bifurcar` de
//! outro processo, pelo próprio kernel no boot — entra com o criador e a
//! autoridade. Subir de criador em criador leva à raiz: a pessoa, o agente,
//! a serial ou o sistema que começou a cadeia. Um filho não perde a origem:
//! o neto de um processo que um agente lançou continua sendo do agente.
//!
//! Um processo é `(época, fio)`: o fio 12 de um boot não é o fio 12 do
//! seguinte.
//!
//! # A memória
//!
//! Com teto: as arestas e os processos mais velhos saem primeiro. A cadeia
//! de um processo que perdeu o criador por isso termina num elo
//! "desconhecido", e diz que está incompleta — em vez de inventar uma raiz.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Quantas arestas o grafo guarda.
pub const MAIS_ARESTAS: usize = 2048;

/// Quantos processos o grafo guarda.
pub const MAIS_PROCESSOS: usize = 256;

/// A cadeia mais alta que a proveniência sobe — um teto contra laço, que
/// os dados não deveriam ter.
pub const MAIOR_CADEIA: usize = 32;

/// Um nó.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum No {
    /// Uma identidade — ver [`crate::evento::principal`].
    Principal(String),
    /// Um processo, pelo boot e pelo fio.
    Processo { epoca: u32, fio: u64 },
    /// Um programa: o nome que ele declara e o começo do resumo da imagem.
    Programa(String),
    /// Um recurso que uma decisão nomeou.
    Recurso(String),
    /// Um destino de rede, na forma normal.
    Destino(String),
    /// Um nome que o DNS resolveu.
    Nome(String),
    /// Um endereço IPv4: onde um nome resolvido e uma conexão pedida se
    /// encontram.
    Endereco([u8; 4]),
    /// Uma decisão do gate, pelo número na auditoria.
    Decisao(u64),
    /// Uma regra do firewall.
    Regra(u64),
    /// Um incidente.
    Incidente(u64),
}

impl No {
    /// Como as consultas o escrevem.
    pub fn texto(&self) -> String {
        match self {
            No::Principal(p) => alloc::format!("principal {p}"),
            No::Processo { epoca, fio } => alloc::format!("process {fio} (boot {epoca})"),
            No::Programa(p) => alloc::format!("program {p}"),
            No::Recurso(r) => alloc::format!("resource {r}"),
            No::Destino(d) => alloc::format!("destination {d}"),
            No::Nome(n) => alloc::format!("name {n}"),
            No::Endereco([a, b, c, d]) => alloc::format!("address {a}.{b}.{c}.{d}"),
            No::Decisao(s) => alloc::format!("decision {s}"),
            No::Regra(r) => alloc::format!("rule {r}"),
            No::Incidente(i) => alloc::format!("incident {i}"),
        }
    }
}

/// Uma aresta.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Aresta {
    /// Uma identidade ou um processo lançou um processo.
    Lancou,
    /// Um processo bifurcou.
    Bifurcou,
    /// Um processo executa um programa.
    Executa,
    /// Uma identidade ou um processo pediu uma decisão.
    Pediu,
    /// Uma decisão foi sobre um recurso ou um destino.
    Sobre,
    /// Um dono resolveu um nome.
    Resolveu,
    /// Um nome resolveu para um destino.
    ResolveuPara,
    /// Uma regra barra um destino.
    Barra,
    /// Um incidente envolve um nó.
    Envolve,
}

impl Aresta {
    /// O nome, como as consultas o escrevem.
    pub const fn nome(self) -> &'static str {
        match self {
            Aresta::Lancou => "launched",
            Aresta::Bifurcou => "forked",
            Aresta::Executa => "runs",
            Aresta::Pediu => "requested",
            Aresta::Sobre => "about",
            Aresta::Resolveu => "resolved",
            Aresta::ResolveuPara => "resolved_to",
            Aresta::Barra => "blocks",
            Aresta::Envolve => "involves",
        }
    }
}

/// Quem criou um processo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Criador {
    /// Outro processo do mesmo boot.
    Processo(u64),
    /// Uma identidade — a raiz de uma cadeia.
    Principal(String),
}

/// O que o grafo sabe de um processo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Processo {
    pub criador: Criador,
    /// Por quem o processo age: a identidade da autoridade dele.
    pub autoridade: String,
    /// O último programa que se viu executando nele.
    pub programa: Option<String>,
    /// O registro do nascimento.
    pub seq: u64,
    /// Nasceu de `user.run` (ou do kernel), ou de `bifurcar`.
    pub via: Aresta,
}

/// Um elo da proveniência: um processo e de onde ele veio.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Elo {
    pub fio: u64,
    pub programa: Option<String>,
    pub autoridade: String,
    pub via: Aresta,
    pub seq: u64,
}

/// A cadeia de um processo até a raiz.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proveniencia {
    /// Do processo para cima.
    pub cadeia: Vec<Elo>,
    /// A identidade que começou a cadeia, se se sabe.
    pub raiz: Option<String>,
}

impl Proveniencia {
    /// A cadeia chegou a uma identidade.
    pub fn completa(&self) -> bool {
        self.raiz.is_some()
    }
}

/// O grafo.
#[derive(Clone, Debug, Default)]
pub struct Grafo {
    ordem: VecDeque<(No, Aresta, No)>,
    conjunto: BTreeSet<(No, Aresta, No)>,
    processos: BTreeMap<(u32, u64), Processo>,
    ordem_dos_processos: VecDeque<(u32, u64)>,
}

impl Grafo {
    pub fn novo() -> Grafo {
        Grafo::default()
    }

    /// Liga dois nós. Uma aresta que já existe não se repete.
    pub fn ligar(&mut self, de: No, aresta: Aresta, para: No) {
        let a = (de, aresta, para);
        if self.conjunto.contains(&a) {
            return;
        }
        if self.ordem.len() == MAIS_ARESTAS
            && let Some(velha) = self.ordem.pop_front()
        {
            self.conjunto.remove(&velha);
        }
        self.conjunto.insert(a.clone());
        self.ordem.push_back(a);
    }

    /// Um processo nasceu.
    pub fn nasceu(&mut self, epoca: u32, fio: u64, p: Processo) {
        let criador = match &p.criador {
            Criador::Processo(c) => No::Processo { epoca, fio: *c },
            Criador::Principal(q) => No::Principal(q.clone()),
        };
        self.ligar(criador, p.via, No::Processo { epoca, fio });
        if let Some(prog) = &p.programa {
            self.ligar(
                No::Processo { epoca, fio },
                Aresta::Executa,
                No::Programa(prog.clone()),
            );
        }
        if !self.processos.contains_key(&(epoca, fio)) {
            if self.ordem_dos_processos.len() == MAIS_PROCESSOS
                && let Some(velho) = self.ordem_dos_processos.pop_front()
            {
                self.processos.remove(&velho);
            }
            self.ordem_dos_processos.push_back((epoca, fio));
        }
        self.processos.insert((epoca, fio), p);
    }

    /// Um processo apareceu executando `programa`: o primeiro pedido dele,
    /// ou o primeiro depois de um `executar`.
    pub fn executa(&mut self, epoca: u32, fio: u64, programa: &str) {
        if let Some(p) = self.processos.get_mut(&(epoca, fio)) {
            if p.programa.as_deref() == Some(programa) {
                return;
            }
            p.programa = Some(programa.to_string());
        }
        self.ligar(
            No::Processo { epoca, fio },
            Aresta::Executa,
            No::Programa(programa.to_string()),
        );
    }

    /// O que se sabe de um processo.
    pub fn processo(&self, epoca: u32, fio: u64) -> Option<&Processo> {
        self.processos.get(&(epoca, fio))
    }

    /// A cadeia de um processo até a raiz.
    pub fn proveniencia(&self, epoca: u32, fio: u64) -> Proveniencia {
        let mut cadeia = Vec::new();
        let mut atual = fio;
        for _ in 0..MAIOR_CADEIA {
            let Some(p) = self.processos.get(&(epoca, atual)) else {
                return Proveniencia { cadeia, raiz: None };
            };
            cadeia.push(Elo {
                fio: atual,
                programa: p.programa.clone(),
                autoridade: p.autoridade.clone(),
                via: p.via,
                seq: p.seq,
            });
            match &p.criador {
                Criador::Principal(q) => {
                    return Proveniencia {
                        cadeia,
                        raiz: Some(q.clone()),
                    };
                }
                Criador::Processo(c) => atual = *c,
            }
        }
        Proveniencia { cadeia, raiz: None }
    }

    /// A identidade na raiz da cadeia de um processo — ou, sem a cadeia, a
    /// autoridade dele, se se sabe.
    pub fn raiz(&self, epoca: u32, fio: u64) -> Option<String> {
        let p = self.proveniencia(epoca, fio);
        p.raiz.or_else(|| {
            self.processos
                .get(&(epoca, fio))
                .map(|p| p.autoridade.clone())
        })
    }

    /// Os processos que descendem de `fio`, em ordem de fio.
    pub fn descendentes(&self, epoca: u32, fio: u64) -> Vec<u64> {
        let mut achados: BTreeSet<u64> = BTreeSet::new();
        let mut fila = alloc::vec![fio];
        while let Some(pai) = fila.pop() {
            for (&(e, f), p) in &self.processos {
                if e == epoca && p.criador == Criador::Processo(pai) && achados.insert(f) {
                    fila.push(f);
                }
            }
        }
        achados.into_iter().collect()
    }

    /// Os processos cuja raiz é `principal`, no boot `epoca`.
    pub fn processos_de(&self, epoca: u32, principal: &str) -> Vec<u64> {
        self.processos
            .keys()
            .filter(|(e, _)| *e == epoca)
            .filter(|(_, f)| self.raiz(epoca, *f).as_deref() == Some(principal))
            .map(|(_, f)| *f)
            .collect()
    }

    /// As arestas que tocam `no`: `(aresta, o outro, sai de no)`.
    pub fn vizinhos(&self, no: &No) -> Vec<(Aresta, No, bool)> {
        let mut v = Vec::new();
        for (de, a, para) in &self.ordem {
            if de == no {
                v.push((*a, para.clone(), true));
            } else if para == no {
                v.push((*a, de.clone(), false));
            }
        }
        v
    }

    /// Quantas arestas há.
    pub fn arestas(&self) -> usize {
        self.ordem.len()
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    fn p(criador: Criador, via: Aresta, seq: u64) -> Processo {
        Processo {
            criador,
            autoridade: "agent:aa".to_string(),
            programa: None,
            seq,
            via,
        }
    }

    /// A pessoa lança, o processo lança, o filho bifurca: o neto continua
    /// sendo da pessoa.
    #[test]
    fn a_proveniencia_chega_a_raiz() {
        let mut g = Grafo::novo();
        g.nasceu(
            1,
            10,
            p(Criador::Principal("person:01".into()), Aresta::Lancou, 5),
        );
        g.nasceu(1, 11, p(Criador::Processo(10), Aresta::Lancou, 6));
        g.nasceu(1, 12, p(Criador::Processo(11), Aresta::Bifurcou, 7));
        g.executa(1, 12, "neto 00112233");
        let prov = g.proveniencia(1, 12);
        assert!(prov.completa());
        assert_eq!(prov.raiz.as_deref(), Some("person:01"));
        let fios: Vec<u64> = prov.cadeia.iter().map(|e| e.fio).collect();
        assert_eq!(fios, [12, 11, 10]);
        assert_eq!(prov.cadeia[0].via, Aresta::Bifurcou);
        assert_eq!(prov.cadeia[0].programa.as_deref(), Some("neto 00112233"));
        assert_eq!(g.descendentes(1, 10), [11, 12]);
        assert_eq!(g.processos_de(1, "person:01"), [10, 11, 12]);
        // Outro boot: o fio 12 de lá não é este.
        assert!(!g.proveniencia(2, 12).completa());
        assert!(g.proveniencia(2, 12).cadeia.is_empty());
    }

    /// O criador que saiu da memória: a cadeia para, e diz que parou.
    #[test]
    fn a_cadeia_incompleta_nao_inventa_raiz() {
        let mut g = Grafo::novo();
        g.nasceu(0, 3, p(Criador::Processo(2), Aresta::Lancou, 1));
        let prov = g.proveniencia(0, 3);
        assert!(!prov.completa());
        assert_eq!(prov.cadeia.len(), 1);
        // A raiz, sem cadeia, cai na autoridade do processo.
        assert_eq!(g.raiz(0, 3).as_deref(), Some("agent:aa"));
    }

    /// Um laço nos dados não prende a subida.
    #[test]
    fn um_laco_nao_prende() {
        let mut g = Grafo::novo();
        g.nasceu(0, 1, p(Criador::Processo(2), Aresta::Lancou, 1));
        g.nasceu(0, 2, p(Criador::Processo(1), Aresta::Lancou, 2));
        let prov = g.proveniencia(0, 1);
        assert_eq!(prov.cadeia.len(), MAIOR_CADEIA);
        assert!(!prov.completa());
    }

    #[test]
    fn com_teto() {
        let mut g = Grafo::novo();
        for i in 0..(MAIS_ARESTAS as u64 + 10) {
            g.ligar(No::Decisao(i), Aresta::Sobre, No::Recurso("/x".into()));
        }
        assert_eq!(g.arestas(), MAIS_ARESTAS);
        // A mesma aresta não se repete.
        g.ligar(
            No::Decisao(MAIS_ARESTAS as u64 + 9),
            Aresta::Sobre,
            No::Recurso("/x".into()),
        );
        assert_eq!(g.arestas(), MAIS_ARESTAS);
        for i in 0..(MAIS_PROCESSOS as u64 + 5) {
            g.nasceu(
                0,
                i,
                p(Criador::Principal("serial".into()), Aresta::Lancou, i),
            );
        }
        assert!(g.processo(0, 0).is_none());
        assert!(g.processo(0, MAIS_PROCESSOS as u64 + 4).is_some());
        let vizinhos = g.vizinhos(&No::Recurso("/x".into()));
        assert!(
            vizinhos
                .iter()
                .all(|(a, _, sai)| *a == Aresta::Sobre && !sai)
        );
    }
}
