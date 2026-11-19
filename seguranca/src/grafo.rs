//! O grafo causal: quem lançou quem, quem pediu o quê, que nome levou a que
//! endereço, que regra barrou que destino, que incidente envolve o quê — e
//! quem declarou o quê, sobre que conexão: a declaração é uma alegação, e o
//! destino dela, um fato do kernel.
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
    /// Uma declaração de quem pediu, pelo número na auditoria: uma
    /// alegação — ver [`crate::evento::Declaracao`].
    Declaracao(u64),
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
            No::Declaracao(s) => alloc::format!("declaration {s}"),
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
    /// Uma identidade ou um processo declarou — ver
    /// [`No::Declaracao`].
    Declarou,
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
            Aresta::Declarou => "declared",
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
    /// O registro que pôs o [`Self::programa`] de agora no processo — ver
    /// [`Grafo::executa_no_registro`]: a execução de uma decisão mais velha
    /// que ele não o troca. Zero, nenhum: o processo ainda sem programa, ou
    /// com um que entrou sem o registro ([`Grafo::executa`]).
    pub programa_desde: u64,
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

    /// Um processo nasceu. Devolve se o nascimento entrou.
    ///
    /// Um processo nasce uma vez só em cada boot: o fio nunca se repete. Um
    /// segundo nascimento do mesmo `(época, fio)` é um registro cortado ou
    /// inconsistente — o pedaço do número de outro filho —, e não entra:
    /// nem o criador, nem a autoridade, nem uma aresta mudam, e o primeiro
    /// fica como era. Sem isso, um nascimento falso dava a criação de um
    /// processo antigo, e a raiz dele, a quem não o criou.
    pub fn nasceu(&mut self, epoca: u32, fio: u64, p: Processo) -> bool {
        if self.processos.contains_key(&(epoca, fio)) {
            return false;
        }
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
        if self.ordem_dos_processos.len() == MAIS_PROCESSOS
            && let Some(velho) = self.ordem_dos_processos.pop_front()
        {
            self.processos.remove(&velho);
        }
        self.ordem_dos_processos.push_back((epoca, fio));
        self.processos.insert((epoca, fio), p);
        true
    }

    /// [`Grafo::executa_no_registro`] sem o registro: a ordem não se
    /// confere, e o programa que entra fica sem o registro que o pôs. É o de
    /// quem não sabe de que registro veio o programa — os testes do grafo;
    /// o motor passa sempre o registro.
    pub fn executa(&mut self, epoca: u32, fio: u64, programa: &str) {
        self.executa_no_registro(epoca, fio, programa, 0, None);
    }

    /// Um processo apareceu executando `programa` no registro `seq` — o
    /// primeiro pedido dele, ou o primeiro depois de um `executar` —, que é a
    /// execução da decisão `citada`, se é uma.
    ///
    /// # A descrição abreviada
    ///
    /// Acima do teto do detalhe, a auditoria abrevia a descrição do
    /// programa — `? <resumo> de <editor>`, ver
    /// `politica::auditoria::detalhe_composto` —, e o resumo fica: é ele
    /// que diz qual programa é.
    ///
    /// - Do **mesmo programa** que o grafo conhece no processo — o mesmo
    ///   resumo, a mesma forma do `de` (as duas com ele, o código de fora,
    ///   ou as duas sem, o da imagem) e, quando as duas dizem o editor, o
    ///   mesmo editor ([`o_mesmo_programa`]) —, a abreviada não muda nada.
    /// - De **outro** — outro resumo; o código de fora no lugar do da
    ///   imagem, ou o contrário; outro editor —, é uma troca de verdade — o
    ///   primeiro pedido, abreviado, do programa que o `executar` trouxe —:
    ///   o processo passa a executar o programa da abreviada, como numa
    ///   troca com a descrição inteira. O resumo tem 64 bits — 32 nas
    ///   descrições de antes do A9-RESUMO, ver [`o_mesmo_programa`] —: o
    ///   código de fora com o começo do resumo de um programa da imagem não
    ///   passa por ele — o `de` o separa —, nem um editor por outro (o
    ///   achado 3 do adversário do passo 1).
    /// - A descrição **inteira** que chega depois, do mesmo programa que a
    ///   abreviada que o grafo guardou, é ele, agora com o nome: o processo
    ///   fica com ela, e não há outra troca — nem outra aresta.
    /// - Duas **inteiras** do mesmo programa com o resumo em larguras
    ///   diferentes — a de 8 dígitos de um registro de antes do A9-RESUMO e
    ///   a de 16, ver `o_mesmo_resumo` — também não são troca: o processo
    ///   fica com a de 16, sem aresta.
    ///
    /// De um processo que o grafo não conhece, a abreviada não diz nada que
    /// se compare: não vira nó.
    ///
    /// # A execução de uma decisão de antes
    ///
    /// Uma execução diz o programa de quem pediu **quando o gate decidiu**:
    /// quem ela nomeia é o da decisão que ela cita. A que chega depois de o
    /// processo trocar de imagem não é notícia do programa de agora: o
    /// desfecho do lançamento, gravado pelo fio novo sem esperar a resposta
    /// do comando — quem pediu pela interface nativa ouve `launched: true`,
    /// troca de imagem, e só então o fio novo grava a imagem que não se
    /// mapeou, com o programa de antes (o achado A3 do adversário do lote
    /// A4). A execução que cita uma decisão mais velha que o registro que
    /// pôs o programa de agora no processo ([`Processo::programa_desde`])
    /// não o troca, nem liga aresta: a decisão que ela cita já passou pelo
    /// motor — ele lê em ordem —, com a mesma descrição, e a aresta desse
    /// programa entrou por ela; ligada de novo, uma aresta que o teto do
    /// grafo já tirou voltaria como nova. Os registros não mudam: muda a
    /// leitura do NSF.
    ///
    /// A que cita a decisão que pôs o programa de agora, ou uma depois dela,
    /// troca como sempre: a falha do `exec` depois do ponto sem volta cita a
    /// decisão do `exec`, que a imagem de antes pediu, e já diz a imagem
    /// nova. E o mesmo programa, numa descrição que diz mais — a inteira
    /// depois da abreviada, a de 16 dígitos depois da de 8 —, entra também
    /// pela execução de antes: não é troca.
    pub fn executa_no_registro(
        &mut self,
        epoca: u32,
        fio: u64,
        programa: &str,
        seq: u64,
        citada: Option<u64>,
    ) {
        use politica::auditoria::descricao_abreviada;
        let abreviada = descricao_abreviada(programa);
        let Some(p) = self.processos.get_mut(&(epoca, fio)) else {
            if !abreviada {
                self.ligar(
                    No::Processo { epoca, fio },
                    Aresta::Executa,
                    No::Programa(programa.to_string()),
                );
            }
            return;
        };
        let atual = p.programa.as_deref();
        if atual == Some(programa) {
            return;
        }
        let mesmo = atual.is_some_and(|a| o_mesmo_programa(a, programa));
        if mesmo && abreviada {
            return;
        }
        if mesmo && atual.is_some_and(descricao_abreviada) {
            p.programa = Some(programa.to_string());
            return;
        }
        // As duas inteiras, do mesmo programa, com o resumo em larguras
        // diferentes — o par misturado de [`o_mesmo_resumo`]: a de 8 de um
        // registro de antes do A9-RESUMO e a de 16 do mesmo executável —
        // não são uma troca: o processo fica com a de 16, que diz mais, e
        // não há aresta. Antes, eram uma troca, com um nó e uma aresta a
        // mais (o achado do adversário do lote B do #448).
        let largura = |d: &str| politica::auditoria::resumo_da_descricao(d).map(str::len);
        if mesmo && atual.is_some_and(|a| largura(a) != largura(programa)) {
            if largura(programa) == Some(politica::auditoria::DIGITOS_DO_RESUMO) {
                p.programa = Some(programa.to_string());
            }
            return;
        }
        // A troca de verdade — salvo pela execução de uma decisão de antes
        // do programa de agora (ver acima).
        if citada.is_some_and(|d| d < p.programa_desde) {
            return;
        }
        p.programa = Some(programa.to_string());
        p.programa_desde = seq;
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

/// Se as descrições `a` e `b` — inteiras ou abreviadas, ver
/// `politica::auditoria::detalhe_composto` — dizem o mesmo programa: o
/// mesmo resumo (ver `o_mesmo_resumo`); a mesma forma do `de`, as duas com
/// ele — o código de fora — ou as duas sem — o da imagem —; e, quando as
/// duas dizem o editor (não o [`politica::auditoria::OMITIDO`]), o mesmo
/// editor. Sem resumo, nenhuma é a outra.
///
/// O editor omitido casa com qualquer um: a troca para o código de outro
/// editor com o mesmo começo do resumo — a segunda pré-imagem de 64 bits,
/// desde o A9-RESUMO; eram 32 — não aparece enquanto os registros do
/// programa novo vierem sem o editor. A primeira decisão que permite os
/// separa: ela tem o texto vazio, e acima do teto abrevia só o nome, nunca
/// o editor (com o nome e o editor de 32 bytes e o fio de 20 dígitos, 91
/// bytes com o resumo de 16 dígitos; 83 com o de 8); o editor só sai com um
/// texto maior ou com a citação — a recusa e a execução (o achado 4 do
/// adversário do passo 1b).
pub fn o_mesmo_programa(a: &str, b: &str) -> bool {
    use politica::auditoria::{OMITIDO, editor_da_descricao, resumo_da_descricao};
    let (Some(ra), Some(rb)) = (resumo_da_descricao(a), resumo_da_descricao(b)) else {
        return false;
    };
    let (Some(ea), Some(eb)) = (editor_da_descricao(a), editor_da_descricao(b)) else {
        return false;
    };
    o_mesmo_resumo(ra, rb)
        && ea.is_some() == eb.is_some()
        && match (ea, eb) {
            (Some(x), Some(y)) if x != OMITIDO && y != OMITIDO => x == y,
            _ => true,
        }
}

/// Se os começos de resumo `a` e `b` de duas descrições dizem o mesmo
/// executável. Os dois têm 16 dígitos — o que o kernel escreve desde o
/// A9-RESUMO — ou 8 — o de uma descrição gravada antes, que o journal da
/// auditoria guarda (ver `politica::auditoria::DIGITOS_DO_RESUMO_ANTIGO`):
///
/// - do **mesmo tamanho**, iguais, inteiros;
/// - um de **8** e outro de **16**, os 8 do começo: o de 8 é o começo do de
///   16 do mesmo executável, e é tudo o que ele diz. Como o editor
///   omitido, que casa com qualquer um, a descrição que diz menos é a do
///   mesmo programa quando o pouco que ela diz confere.
///
/// O par misturado não aparece num processo só: num boot o kernel escreve
/// uma largura, e cada boot — o `policy.load` dele — abre outra época, e o
/// grafo guarda o processo pela época e pelo fio. Ele só se forma com o
/// journal de antes do A9-RESUMO lido sem o começo do boot seguinte — a
/// lacuna que tira o `policy.load` do anel antes da leitura —, e então o
/// mesmo fio de dois boots fica na mesma época. Tomá-lo por outro programa
/// daria ao processo uma troca que ele não fez — uma aresta e um nó a mais
/// —; pelos 8 do começo, a comparação é a de antes, com os 32 bits que o
/// registro antigo tem — e só nesse par: dois de 16 se comparam inteiros.
/// E o par de duas descrições **inteiras** do mesmo programa, uma de cada
/// largura, também não vira troca: o processo fica com a de 16, sem aresta
/// (ver [`Grafo::executa_no_registro`]) — antes do lote B2 do #448, as
/// duas inteiras davam o nó e a aresta a mais, que só as abreviadas
/// evitavam.
///
/// Os dois resumos têm 8 ou 16 dígitos — é o que
/// [`politica::auditoria::resumo_da_descricao`] devolve —, e a compilação de
/// depuração o confere.
fn o_mesmo_resumo(a: &str, b: &str) -> bool {
    use politica::auditoria::{DIGITOS_DO_RESUMO, DIGITOS_DO_RESUMO_ANTIGO};
    debug_assert!(
        [a, b]
            .iter()
            .all(|r| matches!(r.len(), DIGITOS_DO_RESUMO | DIGITOS_DO_RESUMO_ANTIGO)),
        "o resumo de uma descricao tem 8 ou 16 digitos: `{a}` e `{b}`"
    );
    let n = a.len().min(b.len());
    a.get(..n).is_some_and(|x| b.get(..n) == Some(x))
}

#[cfg(test)]
mod testes {
    use super::*;

    fn p(criador: Criador, via: Aresta, seq: u64) -> Processo {
        Processo {
            criador,
            autoridade: "agent:aa".to_string(),
            programa: None,
            programa_desde: 0,
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

    /// A descrição que o detalhe de uma execução abreviou acima do teto não
    /// troca o programa do processo nem vira um nó: é o mesmo processo. O
    /// `executar` de verdade troca.
    #[test]
    fn a_descricao_abreviada_nao_troca_o_programa() {
        let mut g = Grafo::novo();
        g.nasceu(
            0,
            7,
            p(Criador::Principal("serial".into()), Aresta::Lancou, 1),
        );
        g.executa(0, 7, "loja abcd1234 de duke-oficial");
        let arestas = g.arestas();
        // As abreviadas que o kernel compõe dela: o nome, e depois o
        // editor, no lugar de `?` — o `de` fica. A `? abcd1234`, sem ele, é
        // a de um código da imagem com o mesmo resumo: outro programa (ver
        // `o_mesmo_resumo_com_outro_de_ou_outro_editor_e_uma_troca`).
        for abreviada in ["? abcd1234 de duke-oficial", "? abcd1234 de ?"] {
            g.executa(0, 7, abreviada);
            // E de um processo que o grafo não conhece, também nada.
            g.executa(0, 8, abreviada);
        }
        assert_eq!(g.arestas(), arestas);
        let programa = |g: &Grafo| g.processo(0, 7).and_then(|p| p.programa.clone());
        assert_eq!(
            programa(&g).as_deref(),
            Some("loja abcd1234 de duke-oficial")
        );
        g.executa(0, 7, "outro 01020304");
        assert_eq!(programa(&g).as_deref(), Some("outro 01020304"));
        assert_eq!(g.arestas(), arestas + 1);
    }

    /// O achado 3 do adversário do passo 1: o resumo tinha 32 bits — tem 64
    /// desde o A9-RESUMO —, e o mesmo resumo não basta para ser o mesmo
    /// programa. O código da imagem e o
    /// de fora — com o `de` e sem ele — são outros programas, e dois
    /// editores também: a abreviada de um deles depois do outro é uma
    /// troca, com a aresta. O editor omitido (`?`) casa com qualquer um, e
    /// o mesmo editor é o mesmo programa.
    #[test]
    fn o_mesmo_resumo_com_outro_de_ou_outro_editor_e_uma_troca() {
        let novo = |g: &mut Grafo, fio: u64| {
            assert!(g.nasceu(
                0,
                fio,
                p(Criador::Principal("agent:aa".into()), Aresta::Lancou, fio),
            ));
        };
        let programa = |g: &Grafo, fio: u64| g.processo(0, fio).and_then(|p| p.programa.clone());
        let mut g = Grafo::novo();
        // O da imagem, e a abreviada do mesmo resumo de código de fora: troca.
        novo(&mut g, 1);
        g.executa(0, 1, "loja abcd1234");
        let arestas = g.arestas();
        g.executa(0, 1, "? abcd1234 de outro");
        assert_eq!(programa(&g, 1).as_deref(), Some("? abcd1234 de outro"));
        assert_eq!(g.arestas(), arestas + 1);
        // O de fora, abreviado, e a inteira do mesmo resumo da imagem: troca.
        novo(&mut g, 2);
        g.executa(0, 2, "? abcd1234 de ?");
        let arestas = g.arestas();
        g.executa(0, 2, "loja abcd1234");
        assert_eq!(programa(&g, 2).as_deref(), Some("loja abcd1234"));
        assert_eq!(g.arestas(), arestas + 1, "da imagem e de fora: uma aresta");
        // Um editor, e outro, com o mesmo resumo: troca.
        novo(&mut g, 3);
        g.executa(0, 3, "? abcd1234 de editor-a");
        let arestas = g.arestas();
        g.executa(0, 3, "x abcd1234 de editor-b");
        assert_eq!(programa(&g, 3).as_deref(), Some("x abcd1234 de editor-b"));
        assert_eq!(g.arestas(), arestas + 1, "outro editor: uma aresta");
        // O controle: o editor omitido casa com qualquer um, e o mesmo
        // editor é o mesmo programa — a inteira que chega depois fica, sem
        // aresta, e a abreviada dela de novo não muda nada.
        novo(&mut g, 4);
        g.executa(0, 4, "? abcd1234 de ?");
        let arestas = g.arestas();
        g.executa(0, 4, "x abcd1234 de editor-b");
        g.executa(0, 4, "? abcd1234 de editor-b");
        g.executa(0, 4, "? abcd1234 de ?");
        assert_eq!(programa(&g, 4).as_deref(), Some("x abcd1234 de editor-b"));
        assert_eq!(g.arestas(), arestas);
        assert!(o_mesmo_programa("x abcd1234 de e", "? abcd1234 de e"));
        assert!(!o_mesmo_programa("x abcd1234", "? abcd1234 de e"));
        assert!(!o_mesmo_programa("kernel", "kernel"));
    }

    /// O A9-RESUMO: o resumo de 16 dígitos separa dois executáveis com os
    /// mesmos 8 primeiros — a segunda pré-imagem de 32 bits não passa mais
    /// pelo grafo —, e o de 8 de uma descrição gravada antes se compara com
    /// o de 16 pelos 8 do começo, que é o que ele diz: o mesmo começo, o
    /// mesmo programa; outro começo, outro. O `de` e o editor, como sempre.
    #[test]
    fn o_resumo_de_16_digitos_e_o_de_8_de_antes() {
        // A comparação dos resumos.
        assert!(o_mesmo_resumo("abcd1234ef567890", "abcd1234ef567890"));
        assert!(!o_mesmo_resumo("abcd1234ef567890", "abcd1234ef567891"));
        assert!(!o_mesmo_resumo("abcd1234ef567890", "abcd1234aaaaaaaa"));
        assert!(o_mesmo_resumo("abcd1234", "abcd1234"));
        assert!(!o_mesmo_resumo("abcd1234", "abcd1235"));
        assert!(o_mesmo_resumo("abcd1234", "abcd1234ef567890"));
        assert!(o_mesmo_resumo("abcd1234ef567890", "abcd1234"));
        assert!(!o_mesmo_resumo("abcd1235", "abcd1234ef567890"));
        assert!(!o_mesmo_resumo("abcd1234ef567890", "abcd1235"));
        // Com 16 dígitos, os mesmos 8 do começo não bastam: a colisão de 32
        // bits que passava, hoje não passa.
        assert!(!o_mesmo_programa(
            "x abcd1234ef567890 de e",
            "? abcd1234aaaaaaaa de e"
        ));
        assert!(!o_mesmo_programa(
            "loja abcd1234ef567890",
            "? abcd1234aaaaaaaa"
        ));
        assert!(o_mesmo_programa(
            "x abcd1234ef567890 de e",
            "? abcd1234ef567890 de ?"
        ));
        // O de 8 e o de 16: pelos 8 do começo, nos dois sentidos — e o `de`
        // e o editor ainda separam.
        for (a, b, mesmo) in [
            ("loja abcd1234", "? abcd1234ef567890", true),
            ("? abcd1234", "loja abcd1234ef567890", true),
            ("x abcd1234 de e", "? abcd1234ef567890 de ?", true),
            ("? abcd1234 de ?", "x abcd1234ef567890 de e", true),
            ("loja abcd1235", "? abcd1234ef567890", false),
            ("loja abcd1234", "? abcd1234ef567890 de e", false),
            ("x abcd1234 de e", "? abcd1234ef567890 de f", false),
        ] {
            assert_eq!(o_mesmo_programa(a, b), mesmo, "{a} / {b}");
            assert_eq!(o_mesmo_programa(b, a), mesmo, "{b} / {a}");
        }
        // No grafo: a abreviada de 16 dígitos de outro executável com o
        // mesmo começo é uma troca, com a aresta.
        let mut g = Grafo::novo();
        let novo = |g: &mut Grafo, fio: u64| {
            assert!(g.nasceu(
                0,
                fio,
                p(Criador::Principal("agent:aa".into()), Aresta::Lancou, fio),
            ));
        };
        let programa = |g: &Grafo, fio: u64| g.processo(0, fio).and_then(|p| p.programa.clone());
        novo(&mut g, 1);
        g.executa(0, 1, "loja abcd1234ef567890 de duke");
        let arestas = g.arestas();
        g.executa(0, 1, "? abcd1234ef567890 de ?");
        assert_eq!(g.arestas(), arestas, "a abreviada do mesmo: nada");
        g.executa(0, 1, "? abcd1234aaaaaaaa de ?");
        assert_eq!(programa(&g, 1).as_deref(), Some("? abcd1234aaaaaaaa de ?"));
        assert_eq!(g.arestas(), arestas + 1, "outro executavel: uma aresta");
        // O processo que o grafo conhece por uma descrição de 8 dígitos: a
        // abreviada de 16 com o mesmo começo não muda nada; a de outro
        // começo é uma troca.
        novo(&mut g, 2);
        g.executa(0, 2, "loja abcd1234 de duke");
        let arestas = g.arestas();
        g.executa(0, 2, "? abcd1234ef567890 de ?");
        assert_eq!(programa(&g, 2).as_deref(), Some("loja abcd1234 de duke"));
        assert_eq!(g.arestas(), arestas);
        g.executa(0, 2, "? 01234567ef567890 de ?");
        assert_eq!(programa(&g, 2).as_deref(), Some("? 01234567ef567890 de ?"));
        assert_eq!(g.arestas(), arestas + 1);
        // E a abreviada de 8 que o grafo guardou, com a inteira de 16 do
        // mesmo começo depois: o processo fica com a inteira, sem aresta.
        novo(&mut g, 3);
        g.executa(0, 3, "? abcd1234 de ?");
        let arestas = g.arestas();
        g.executa(0, 3, "loja abcd1234ef567890 de duke");
        assert_eq!(
            programa(&g, 3).as_deref(),
            Some("loja abcd1234ef567890 de duke")
        );
        assert_eq!(g.arestas(), arestas);
    }

    /// O par misturado de duas descrições **inteiras** do mesmo programa —
    /// o achado do adversário do lote B do #448: a de 8 dígitos, de antes do
    /// A9-RESUMO, e a de 16 do mesmo executável, com o mesmo nome e o mesmo
    /// editor, eram uma troca, com um nó e uma aresta a mais — a troca que
    /// [`o_mesmo_resumo`] diz evitar. Agora o processo fica com a de 16,
    /// sem aresta, nas duas ordens; e o código da imagem também. O de outro
    /// começo, outro editor ou outro `de` continua sendo uma troca.
    #[test]
    fn o_par_misturado_de_duas_inteiras_nao_e_troca() {
        let mut g = Grafo::novo();
        let novo = |g: &mut Grafo, fio: u64| {
            assert!(g.nasceu(
                0,
                fio,
                p(Criador::Principal("agent:aa".into()), Aresta::Lancou, fio),
            ));
        };
        let programa = |g: &Grafo, fio: u64| g.processo(0, fio).and_then(|p| p.programa.clone());
        for (fio, primeira, segunda) in [
            (1, "loja abcd1234 de duke", "loja abcd1234ef567890 de duke"),
            (2, "loja abcd1234ef567890 de duke", "loja abcd1234 de duke"),
            (3, "loja abcd1234", "loja abcd1234ef567890"),
            (4, "loja abcd1234ef567890", "loja abcd1234"),
        ] {
            novo(&mut g, fio);
            g.executa(0, fio, primeira);
            let arestas = g.arestas();
            g.executa(0, fio, segunda);
            assert_eq!(g.arestas(), arestas, "{primeira} / {segunda}");
            let de_16 = if primeira.len() > segunda.len() {
                primeira
            } else {
                segunda
            };
            assert_eq!(
                programa(&g, fio).as_deref(),
                Some(de_16),
                "{primeira} / {segunda}"
            );
            // E de novo a de 8: nada.
            let de_8 = if primeira.len() < segunda.len() {
                primeira
            } else {
                segunda
            };
            g.executa(0, fio, de_8);
            assert_eq!(g.arestas(), arestas);
            assert_eq!(programa(&g, fio).as_deref(), Some(de_16));
        }
        // O que não é o mesmo programa continua sendo uma troca: outro
        // começo do resumo, outro editor, o código da imagem no lugar do de
        // fora — e o nome diferente com o mesmo resumo e o mesmo editor não
        // é o caso: o nome está dentro do executável, e o mesmo resumo de 64
        // bits é o mesmo executável.
        for (fio, primeira, segunda) in [
            (5, "loja abcd1234 de duke", "loja abcd1235ef567890 de duke"),
            (6, "loja abcd1234 de duke", "loja abcd1234ef567890 de outro"),
            (7, "loja abcd1234", "loja abcd1234ef567890 de duke"),
        ] {
            novo(&mut g, fio);
            g.executa(0, fio, primeira);
            let arestas = g.arestas();
            g.executa(0, fio, segunda);
            assert_eq!(g.arestas(), arestas + 1, "{primeira} / {segunda}");
            assert_eq!(programa(&g, fio).as_deref(), Some(segunda));
        }
    }

    /// O achado 5 do adversário do F1: a abreviada de **outro** resumo é
    /// uma troca de verdade — a do primeiro pedido, abreviado, do programa
    /// que a troca trouxe; o kernel gravava assim a execução da troca que
    /// falha depois do ponto sem volta, que desde o F2 do adversário do AE-1
    /// vai em nome do programa que pediu. A inteira que chega depois, do
    /// mesmo programa, não é outra troca; e a mesma abreviada continua sem
    /// mudar nada.
    #[test]
    fn a_abreviada_de_outro_resumo_e_uma_troca() {
        let mut g = Grafo::novo();
        g.nasceu(
            0,
            7,
            p(Criador::Principal("serial".into()), Aresta::Lancou, 1),
        );
        g.executa(0, 7, "loja abcd1234");
        let arestas = g.arestas();
        let programa = |g: &Grafo| g.processo(0, 7).and_then(|p| p.programa.clone());
        // O programa novo, abreviado: a troca entra.
        g.executa(0, 7, "? deadbeef");
        assert_eq!(programa(&g).as_deref(), Some("? deadbeef"));
        assert_eq!(g.arestas(), arestas + 1);
        // A mesma abreviada: nada.
        g.executa(0, 7, "? deadbeef");
        assert_eq!(programa(&g).as_deref(), Some("? deadbeef"));
        assert_eq!(g.arestas(), arestas + 1);
        // A inteira do mesmo resumo: o nome volta, sem outra troca.
        let inteira = alloc::format!("{} deadbeef", "n".repeat(32));
        g.executa(0, 7, &inteira);
        assert_eq!(programa(&g).as_deref(), Some(inteira.as_str()));
        assert_eq!(g.arestas(), arestas + 1);
        // E a abreviada dela de novo: nada.
        g.executa(0, 7, "? deadbeef");
        assert_eq!(programa(&g).as_deref(), Some(inteira.as_str()));
        assert_eq!(g.arestas(), arestas + 1);
        // O primeiro programa que o grafo vê num processo que ele conhece,
        // abreviado — o `pelo` que passa do teto vai sempre abreviado —: é
        // o programa dele, e a inteira que vier depois não é outra troca.
        g.nasceu(
            0,
            8,
            p(Criador::Principal("serial".into()), Aresta::Lancou, 2),
        );
        let arestas = g.arestas();
        g.executa(0, 8, "? cdcdcdcd de editor-longo");
        assert_eq!(
            g.processo(0, 8).and_then(|p| p.programa.as_deref()),
            Some("? cdcdcdcd de editor-longo")
        );
        assert_eq!(g.arestas(), arestas + 1);
        g.executa(0, 8, "programa-longo cdcdcdcd de editor-longo");
        assert_eq!(
            g.processo(0, 8).and_then(|p| p.programa.as_deref()),
            Some("programa-longo cdcdcdcd de editor-longo")
        );
        assert_eq!(g.arestas(), arestas + 1);
    }

    /// O achado 2 do adversário do F1, a defesa no grafo: um processo nasce
    /// uma vez só no boot. O segundo nascimento do mesmo fio — o pedaço do
    /// número de outro filho — não muda o criador, a autoridade nem as
    /// arestas; o primeiro fica. Em outro boot, o mesmo fio nasce de novo.
    #[test]
    fn um_processo_nasce_uma_vez_so() {
        let mut g = Grafo::novo();
        let vitima = Processo {
            autoridade: "person:01".to_string(),
            ..p(Criador::Principal("person:01".into()), Aresta::Lancou, 1)
        };
        assert!(g.nasceu(0, 5, vitima.clone()));
        g.nasceu(
            0,
            1234,
            p(Criador::Principal("agent:aa".into()), Aresta::Lancou, 2),
        );
        let arestas = g.arestas();
        // O nascimento falso: o 5 "bifurcado" pelo 1234.
        assert!(!g.nasceu(0, 5, p(Criador::Processo(1234), Aresta::Bifurcou, 3)));
        assert_eq!(g.processo(0, 5), Some(&vitima));
        assert_eq!(g.arestas(), arestas);
        assert_eq!(g.proveniencia(0, 5).raiz.as_deref(), Some("person:01"));
        assert!(g.descendentes(0, 1234).is_empty());
        // Outro boot: outro processo.
        assert!(g.nasceu(1, 5, p(Criador::Processo(1234), Aresta::Bifurcou, 4)));
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

    /// A execução de uma decisão mais velha que o registro que pôs o
    /// programa de agora não o troca, nem liga aresta (o achado A3 do
    /// adversário do lote A4): o desfecho tardio do lançamento que o
    /// processo pediu rodando X, gravado depois de ele trocar para Y. A que
    /// cita o registro que pôs o programa de agora, ou um depois dele,
    /// troca; o mesmo programa, numa descrição que diz mais, entra também
    /// pela de antes; e o programa dado sem o registro fica sem ele.
    #[test]
    fn a_execucao_de_uma_decisao_de_antes_nao_troca_o_programa() {
        let mut g = Grafo::novo();
        for fio in [40, 41] {
            g.nasceu(
                0,
                fio,
                p(Criador::Principal("agent:aa".into()), Aresta::Lancou, 2),
            );
        }
        // O programa de agora de um processo, e o registro que o pôs.
        fn programa(g: &Grafo, fio: u64) -> Option<(&str, u64)> {
            g.processo(0, fio)
                .map(|p| (p.programa.as_deref().unwrap_or(""), p.programa_desde))
        }
        // X pelo registro 3, a decisão do lançamento que o 40 pede; Y pelo
        // 6, o primeiro pedido dele depois da troca de imagem.
        g.executa_no_registro(0, 40, "x 0a0b0c0d", 3, None);
        g.executa_no_registro(0, 40, "y 01020304", 6, None);
        let arestas = g.arestas();
        assert_eq!(programa(&g, 40), Some(("y 01020304", 6)));
        // O desfecho tardio: o registro 7, a execução da decisão 3, com X.
        g.executa_no_registro(0, 40, "x 0a0b0c0d", 7, Some(3));
        assert_eq!(programa(&g, 40), Some(("y 01020304", 6)));
        assert_eq!(g.arestas(), arestas);
        // A que cita o registro que pôs Y — a falha do `exec` que Y pediu,
        // já com a imagem nova —: troca, com a aresta.
        g.executa_no_registro(0, 40, "z 0f0f0f0f", 8, Some(6));
        assert_eq!(programa(&g, 40), Some(("z 0f0f0f0f", 8)));
        assert_eq!(g.arestas(), arestas + 1);
        // A que cita uma decisão depois dele: troca.
        g.executa_no_registro(0, 40, "w 0e0e0e0e", 10, Some(9));
        assert_eq!(programa(&g, 40), Some(("w 0e0e0e0e", 10)));
        // Sem o registro: o programa entra sem ele.
        g.executa(0, 40, "v 0d0d0d0d");
        assert_eq!(programa(&g, 40), Some(("v 0d0d0d0d", 0)));

        // O mesmo programa, inteiro depois da abreviada: a execução de uma
        // decisão de antes dá o nome, e não é troca — nem aresta.
        g.executa_no_registro(0, 41, "? abcd1234 de ?", 6, None);
        let arestas = g.arestas();
        g.executa_no_registro(0, 41, "loja abcd1234 de duke", 7, Some(3));
        assert_eq!(programa(&g, 41), Some(("loja abcd1234 de duke", 6)));
        assert_eq!(g.arestas(), arestas);
    }
}
