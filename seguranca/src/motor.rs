//! O motor: o caminho inteiro, de uma leitura ao pedido.
//!
//! ```text
//! observação → correlação → detecção → investigação → risco → incidente
//!            → resposta → verificação
//! ```
//!
//! O fio do NSF, no kernel, lê pelo gate e entrega o resultado aqui
//! ([`Motor::ler_captura`], [`Motor::ler_auditoria`]); pega os pedidos que o
//! motor planejou ([`Motor::pedidos`]), pede cada um ao gate, e devolve o
//! desfecho ([`Motor::desfecho`]). O registro que o gate gravar da ação
//! volta na leitura seguinte e fecha o ciclo: a ação ganha o número da
//! decisão, e uma ação do NSF que a auditoria mostre sem um pedido que o
//! motor tenha feito é uma detecção crítica.
//!
//! # A história e o ao vivo
//!
//! Tudo o que o motor lê entra no estado — os registros que o journal repôs
//! do boot anterior também. Mas só pede ação pelo que é **ao vivo**: os
//! registros depois de [`Motor::ao_vivo_depois_de`]. O que é história vira
//! incidente com recomendação, nunca com pedido.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use protocolo::json::Json;

use crate::dns::{Dns, Observado};
use crate::evento::{self, Evento, Registro, Severidade, Tipo, Titular};
use crate::evidencia::{Cofre, Prova};
use crate::grafo::{Aresta, Criador, Grafo, No, Processo};
use crate::incidente::Incidentes;
use crate::invariantes::{Monitor, Violacao};
use crate::regras::{Contexto, Deteccao, Detector, Regra};
use crate::resposta::{self, Acao, Estado as EstadoDaAcao, Nivel};
use crate::ueba::Ueba;
use crate::util;

/// Quantos eventos o motor guarda para a linha do tempo.
pub const MAIS_EVENTOS: usize = 512;

/// Quantos servidores de DNS o motor observa.
pub const MAIS_OBSERVADOS: usize = 8;

/// Um servidor de DNS que o motor quer observar: até onde leu a captura
/// dele, e se o gate recusou a leitura.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Observacao {
    pub lida: u64,
    pub recusada: bool,
}

/// O que o motor contou.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Contadores {
    /// Registros da auditoria lidos.
    pub registros: u64,
    /// Datagramas da captura lidos.
    pub capturas: u64,
    /// Leituras que o gate recusou ao NSF.
    pub leituras_recusadas: u64,
    /// Registros que sumiram antes da leitura.
    pub perdidos: u64,
    /// Registros cujo elo não se refez.
    pub adulterados: u64,
    pub deteccoes: u64,
    /// Ações pedidas ao gate.
    pub pedidos: u64,
    pub permitidos: u64,
    pub negados: u64,
    pub falhos: u64,
}

/// Um pedido que o fio do NSF faz ao gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pedido {
    pub acao: u64,
    pub metodo: String,
    pub params: String,
}

/// O motor.
#[derive(Clone, Debug)]
pub struct Motor {
    pub epoca: u32,
    lido: u64,
    captura_lida: u64,
    ao_vivo: u64,
    eventos: VecDeque<Evento>,
    pub grafo: Grafo,
    pub ueba: Ueba,
    detector: Detector,
    monitor: Monitor,
    pub incidentes: Incidentes,
    pub cofre: Cofre,
    pub dns: Dns,
    correlacoes: BTreeMap<(u32, String), u64>,
    /// Os servidores de DNS que alguém usou, e que o motor quer observar —
    /// aprendidos pela auditoria, não pela política, que o NSF não lê.
    observados: BTreeMap<String, Observacao>,
    pub contadores: Contadores,
}

impl Default for Motor {
    fn default() -> Motor {
        Motor::novo()
    }
}

impl Motor {
    pub fn novo() -> Motor {
        Motor {
            epoca: 0,
            lido: 0,
            captura_lida: 0,
            ao_vivo: 0,
            eventos: VecDeque::new(),
            grafo: Grafo::novo(),
            ueba: Ueba::novo(),
            detector: Detector::novo(),
            monitor: Monitor::novo(),
            incidentes: Incidentes::novo(),
            cofre: Cofre::novo(),
            dns: Dns::novo(),
            correlacoes: BTreeMap::new(),
            observados: BTreeMap::new(),
            contadores: Contadores::default(),
        }
    }

    /// O último registro da auditoria lido.
    pub fn lido(&self) -> u64 {
        self.lido
    }

    /// O último datagrama da captura lido.
    pub fn captura_lida(&self) -> u64 {
        self.captura_lida
    }

    /// Desde quando o motor pede ação.
    pub fn ao_vivo(&self) -> u64 {
        self.ao_vivo
    }

    /// O que vier depois do registro `seq` é ao vivo; o que veio até ele é
    /// história.
    pub fn ao_vivo_depois_de(&mut self, seq: u64) {
        self.ao_vivo = seq;
    }

    /// Começa a leitura depois de `seq`, sem ler o que veio antes — para
    /// quem quer o NSF só do agora em diante (a suíte, entre um caso e
    /// outro).
    pub fn comecar_depois_de(&mut self, seq: u64, captura: u64) {
        self.lido = seq;
        self.ao_vivo = seq;
        self.captura_lida = captura;
        self.monitor = Monitor::novo();
    }

    /// Uma leitura recusada pelo gate.
    pub fn leitura_recusada(&mut self) {
        self.contadores.leituras_recusadas += 1;
    }

    /// Os eventos guardados, do mais velho ao mais novo.
    pub fn eventos(&self) -> impl DoubleEndedIterator<Item = &Evento> {
        self.eventos.iter()
    }

    /// Um evento, pelo número do registro.
    pub fn evento(&self, seq: u64) -> Option<&Evento> {
        self.eventos.iter().find(|e| e.seq == seq)
    }

    /// Os servidores a observar — os que o gate não recusou —, com até onde
    /// a captura de cada um foi lida.
    pub fn a_observar(&self) -> Vec<(String, u64)> {
        self.observados
            .iter()
            .filter(|(_, o)| !o.recusada)
            .map(|(d, o)| (d.clone(), o.lida))
            .collect()
    }

    /// O gate recusou observar `destino`: o motor não pede de novo até a
    /// política mudar.
    pub fn observacao_recusada(&mut self, destino: &str) {
        self.contadores.leituras_recusadas += 1;
        if let Some(o) = self.observados.get_mut(destino) {
            o.recusada = true;
        }
    }

    /// O resultado de um `net.observe` sobre `destino`. Devolve quantos
    /// datagramas novos.
    ///
    /// A resposta do DNS vem antes da conexão que ela leva a pedir, mas a
    /// leitura pode trazê-las na outra ordem — o servidor só passa a ser
    /// observado quando a auditoria mostra alguém o usando, e um programa
    /// rápido resolve e conecta na mesma volta. Por isso a regra olha dos
    /// dois lados: a conexão procura a resolução que a precedeu, e a
    /// resolução procura as conexões que já foram lidas depois dela.
    pub fn ler_captura(&mut self, destino: &str, resultado: &[u8]) -> Result<usize, &'static str> {
        let capturas = crate::dns::capturas(resultado)?;
        Ok(self.ler_capturas(destino, capturas))
    }

    /// Os datagramas de `destino`, já lidos do JSON.
    pub fn ler_capturas(&mut self, destino: &str, capturas: Vec<crate::dns::Captura>) -> usize {
        let mut novos = 0;
        // Só o que o motor quis observar: um servidor que ninguém usou não
        // tem o que dizer.
        let Some(lida) = self.observados.get(destino).map(|o| o.lida) else {
            return 0;
        };
        for c in capturas {
            if c.seq <= lida || c.destino != destino {
                continue;
            }
            if let Some(o) = self.observados.get_mut(destino) {
                o.lida = o.lida.max(c.seq);
            }
            self.captura_lida = self.captura_lida.max(c.seq);
            self.contadores.capturas += 1;
            novos += 1;
            if let Observado::Resposta(r) = self.dns.observar(&c) {
                let dono = self.no_do_dono(&r.dono);
                self.grafo
                    .ligar(dono, Aresta::Resolveu, No::Nome(r.nome.clone()));
                for ip in &r.enderecos {
                    self.grafo.ligar(
                        No::Nome(r.nome.clone()),
                        Aresta::ResolveuPara,
                        No::Endereco(*ip),
                    );
                }
                self.cofre.guardar(
                    c.ts_ms,
                    None,
                    Prova::Datagrama {
                        captura: c.seq,
                        destino: c.destino.clone(),
                        resumo: crate::evidencia::resumo(&c.dados),
                        tamanho: c.dados.len() as u32,
                    },
                );
                self.depois_da_resolucao(&r);
            }
        }
        novos
    }

    /// As conexões recusadas que a resolução `r` precedeu e que o motor já
    /// leu — a auditoria chegou antes da captura. Só as que têm `r` como a
    /// resolução mais nova antes delas: a que as precedeu.
    fn depois_da_resolucao(&mut self, r: &crate::dns::Resolucao) {
        let tardias: Vec<Evento> = self
            .eventos
            .iter()
            .filter(|e| e.seq > r.registro)
            .filter(|e| {
                crate::regras::conexao_recusada(e).is_some_and(|(dono, ip)| {
                    dono == r.dono
                        && self
                            .dns
                            .antes_de(&dono, ip, e.seq)
                            .is_some_and(|x| x.captura == r.captura)
                })
            })
            .cloned()
            .collect();
        for e in tardias {
            if let Some(d) = self.detector.dns_contra_a_politica(&e, r) {
                if let Some(x) = self.eventos.iter_mut().find(|x| x.seq == e.seq) {
                    x.severidade = x.severidade.max(d.severidade);
                }
                self.registrar(d, e.seq <= self.ao_vivo, e.correlacao);
            }
        }
    }

    /// O nó de um dono de fluxo.
    fn no_do_dono(&self, dono: &str) -> No {
        match dono.strip_prefix("process:").and_then(|f| f.parse().ok()) {
            Some(fio) => No::Processo {
                epoca: self.epoca,
                fio,
            },
            None => No::Principal(dono.to_string()),
        }
    }

    /// O resultado de um `audit.tail`. Devolve quantos registros novos.
    pub fn ler_auditoria(&mut self, resultado: &[u8]) -> Result<usize, &'static str> {
        let registros = evento::registros(resultado)?;
        Ok(self.ler_registros(registros))
    }

    /// Os registros de um `audit.tail`, já lidos do JSON — o kernel lê o
    /// JSON fora da trava do motor.
    pub fn ler_registros(&mut self, registros: Vec<Registro>) -> usize {
        let mut novos = 0;
        for r in registros {
            if r.seq <= self.lido {
                continue;
            }
            novos += 1;
            self.contadores.registros += 1;
            for v in self.monitor.conferir(&r) {
                self.violacao(v, &r);
            }
            self.lido = r.seq;
            let mut e = Evento::de(&r, self.epoca);
            if e.tipo == Tipo::Inicio {
                self.epoca += 1;
                e.epoca = self.epoca;
            }
            self.processar(e);
        }
        novos
    }

    /// A raiz da cadeia causal de um evento: a identidade que começou a
    /// cadeia do processo dele, ou a própria identidade.
    fn raiz(&self, e: &Evento) -> String {
        match &e.processo {
            Some((fio, _)) => self
                .grafo
                .raiz(e.epoca, *fio)
                .unwrap_or_else(|| e.principal.clone()),
            None => e.principal.clone(),
        }
    }

    /// O identificador de correlação: o mesmo para todo evento da mesma
    /// raiz no mesmo boot.
    fn correlacao(&mut self, e: &Evento) -> u64 {
        let raiz = self.raiz(e);
        let chave = (e.epoca, raiz);
        if let Some(&c) = self.correlacoes.get(&chave) {
            return c;
        }
        let c = util::fnv(&[&chave.0.to_le_bytes(), chave.1.as_bytes()]);
        if self.correlacoes.len() >= 256 {
            self.correlacoes.clear();
        }
        self.correlacoes.insert(chave, c);
        c
    }

    fn processar(&mut self, mut e: Evento) {
        // O grafo: o processo que nasceu, o programa que roda, a decisão e
        // o que ela nomeou.
        if let Tipo::Nascimento { filho } = e.tipo {
            let criador = match &e.processo {
                Some((p, prog)) => {
                    self.grafo.executa(e.epoca, *p, prog);
                    Criador::Processo(*p)
                }
                None => Criador::Principal(e.principal.clone()),
            };
            let via = if e.metodo == "process.fork" {
                Aresta::Bifurcou
            } else {
                Aresta::Lancou
            };
            self.grafo.nasceu(
                e.epoca,
                filho,
                Processo {
                    criador,
                    autoridade: e.principal.clone(),
                    programa: None,
                    seq: e.seq,
                    via,
                },
            );
        } else if let Some((p, prog)) = &e.processo {
            self.grafo.executa(e.epoca, *p, prog);
        }
        let quem = match &e.processo {
            Some((p, _)) => No::Processo {
                epoca: e.epoca,
                fio: *p,
            },
            None => No::Principal(e.principal.clone()),
        };
        if e.tipo == Tipo::Decisao {
            self.grafo.ligar(quem, Aresta::Pediu, No::Decisao(e.seq));
            if let Some(d) = politica::endereco::ler(&e.recurso) {
                self.grafo
                    .ligar(No::Decisao(e.seq), Aresta::Sobre, No::Destino(d.texto()));
                self.grafo
                    .ligar(No::Decisao(e.seq), Aresta::Sobre, No::Endereco(d.ip));
            } else if !e.recurso.is_empty() {
                self.grafo.ligar(
                    No::Decisao(e.seq),
                    Aresta::Sobre,
                    No::Recurso(e.recurso.clone()),
                );
            }
        }
        e.correlacao = self.correlacao(&e);

        // Um servidor de DNS que alguém usou, com o gate deixando: o motor
        // passa a querer observá-lo — e o gate decide se ele pode.
        if e.metodo == "net.connect"
            && e.tipo == Tipo::Decisao
            && e.codigo.permite()
            && let Some(d) = politica::endereco::ler(&e.recurso)
            && d.protocolo == politica::endereco::Protocolo::Udp
            && d.porta == protocolo::dns::PORTA
            && (self.observados.len() < MAIS_OBSERVADOS || self.observados.contains_key(&d.texto()))
        {
            self.observados.entry(d.texto()).or_default();
        }
        // A política mudou: uma observação recusada pode valer agora.
        if matches!(e.metodo.as_str(), "policy.write" | "policy.assign") && e.codigo.permite() {
            for o in self.observados.values_mut() {
                o.recusada = false;
            }
        }

        // O perfil, e as regras.
        let anomalia = self.ueba.observar(&e);
        let ctx = Contexto {
            dns: &self.dns,
            grafo: &self.grafo,
            anomalia: anomalia.as_ref(),
        };
        let mut deteccoes = self.detector.observar(&e, &ctx);
        if self
            .incidentes
            .vivo_de(e.epoca, &e.principal)
            .is_some_and(|i| i.alto())
            && let Some(d) = self.detector.saida_depois_de_sondagem(&e)
        {
            deteccoes.push(d);
        }

        // O que o próprio NSF fez, e o que outros fizeram pelo próprio
        // papel sobre o que um incidente envolve.
        if e.titular == Titular::Servico && e.tipo != Tipo::Leitura {
            if let Some(d) = self.acao_do_nsf(&e) {
                deteccoes.push(d);
            }
        } else if matches!(e.metodo.as_str(), "net.block" | "net.unblock")
            && e.tipo == Tipo::Decisao
            && e.codigo.permite()
        {
            self.acao_observada(&e);
        }

        e.severidade = deteccoes
            .iter()
            .map(|d| d.severidade)
            .max()
            .unwrap_or(Severidade::Info);
        let historico = e.seq <= self.ao_vivo;
        let correlacao = e.correlacao;
        let ts = e.ts_ms;
        if self.eventos.len() == MAIS_EVENTOS {
            self.eventos.pop_front();
        }
        self.eventos.push_back(e);
        for d in deteccoes {
            self.registrar(d, historico, correlacao);
        }
        for p in self.incidentes.envelhecer(ts) {
            self.detector.esquecer(&p);
        }
    }

    /// Um registro do NSF: casa com a ação pedida, ou é uma ação sem plano.
    fn acao_do_nsf(&mut self, e: &Evento) -> Option<Deteccao> {
        // Uma execução de uma decisão do NSF — a conexão derrubada pelo
        // bloqueio — é efeito da ação, não outra ação.
        if e.decisao.is_some() {
            return None;
        }
        // A história não tem os planos de antes do boot.
        if e.seq <= self.ao_vivo {
            return None;
        }
        let recurso =
            politica::endereco::normalizar(&e.recurso).unwrap_or_else(|| e.recurso.clone());
        for inc in self.incidentes.todos_mut() {
            for a in &mut inc.acoes {
                let pedida = matches!(
                    a.estado,
                    EstadoDaAcao::Pedida
                        | EstadoDaAcao::Permitida
                        | EstadoDaAcao::Negada { .. }
                        | EstadoDaAcao::Falhou { .. }
                );
                if pedida && a.decisao.is_none() && a.metodo == e.metodo && a.recurso == recurso {
                    a.decisao = Some(e.seq);
                    return None;
                }
            }
        }
        Some(Deteccao {
            regra: Regra::AcaoSemPlano,
            severidade: Severidade::Critica,
            principal: e.principal.clone(),
            titular: e.titular,
            registros: alloc::vec![e.seq],
            explicacao: alloc::format!(
                "o NSF fez {} sobre `{}` sem um pedido que o motor tenha planejado",
                e.metodo,
                e.recurso
            ),
            alvo: None,
            ts_ms: e.ts_ms,
            epoca: e.epoca,
        })
    }

    /// Alguém, pelo próprio papel, barrou ou liberou um destino que um
    /// incidente vivo envolve: a ação entra nele.
    fn acao_observada(&mut self, e: &Evento) {
        let Some(recurso) = politica::endereco::normalizar(&e.recurso) else {
            return;
        };
        let alvos: Vec<u64> = self
            .incidentes
            .todos()
            .filter(|i| i.epoca == e.epoca && i.estado != crate::incidente::Estado::Encerrado)
            .filter(|i| i.recursos.contains(&recurso))
            .map(|i| i.id)
            .collect();
        for id in alvos {
            self.incidentes.agir(
                id,
                Acao {
                    id: 0,
                    nivel: Nivel::Autorizada,
                    metodo: e.metodo.clone(),
                    params: String::new(),
                    recurso: recurso.clone(),
                    estado: EstadoDaAcao::Observada,
                    decisao: Some(e.seq),
                    autorizado_por: e.principal.clone(),
                    justificativa: alloc::format!(
                        "{} pelo proprio papel ({})",
                        e.principal,
                        e.papel
                    ),
                },
            );
        }
    }

    /// Uma violação de invariante vira detecção.
    fn violacao(&mut self, v: Violacao, r: &Registro) {
        let (regra, severidade, explicacao) = match v {
            Violacao::Adulterado { seq } => {
                self.contadores.adulterados += 1;
                (
                    Regra::AuditoriaAdulterada,
                    Severidade::Critica,
                    alloc::format!("o registro {seq} nao refaz o elo da auditoria"),
                )
            }
            Violacao::Desencadeado { seq } => (
                Regra::AuditoriaAdulterada,
                Severidade::Critica,
                alloc::format!("o registro {seq} nao continua o elo do anterior"),
            ),
            Violacao::Lacuna { de, ate } => {
                self.contadores.perdidos += ate - de + 1;
                (
                    Regra::LacunaNaLeitura,
                    Severidade::Media,
                    alloc::format!("os registros {de} a {ate} sairam do anel antes da leitura"),
                )
            }
            Violacao::TempoVolta { seq } => (
                Regra::TempoQueVolta,
                Severidade::Alta,
                alloc::format!("o registro {seq} tem tempo menor que o anterior"),
            ),
        };
        let d = Deteccao {
            regra,
            severidade,
            principal: "audit".to_string(),
            titular: Titular::Kernel,
            registros: alloc::vec![r.seq],
            explicacao,
            alvo: None,
            ts_ms: r.ts_ms,
            epoca: self.epoca,
        };
        self.registrar(d, r.seq <= self.ao_vivo, 0);
    }

    /// Uma detecção: o incidente, a evidência, o grafo, e o plano.
    fn registrar(&mut self, d: Deteccao, historico: bool, correlacao: u64) {
        self.contadores.deteccoes += 1;
        let ja: Vec<u64> = self
            .incidentes
            .vivo_de(d.epoca, &d.principal)
            .map(|i| i.registros.iter().copied().collect())
            .unwrap_or_default();
        let Some(id) = self.incidentes.registrar(&d, correlacao, historico) else {
            return;
        };
        // A evidência: cada registro que ainda não estava no incidente, e a
        // detecção.
        let mut ids = Vec::new();
        for &seq in &d.registros {
            if ja.contains(&seq) {
                continue;
            }
            let elo = self.evento(seq).map_or([0; 32], |e| e.elo);
            ids.push(
                self.cofre
                    .guardar(d.ts_ms, Some(id), Prova::Registro { seq, elo }),
            );
            if let Some(recurso) = self.evento(seq).map(|e| e.recurso.clone()) {
                self.incidentes.afetou(id, &recurso);
            }
        }
        ids.push(self.cofre.guardar(
            d.ts_ms,
            Some(id),
            Prova::Deteccao {
                regra: d.regra.nome(),
                registros: d.registros.clone(),
            },
        ));
        let historico_do_incidente =
            historico || self.incidentes.get(id).is_some_and(|i| i.historico);
        let negada = self.incidentes.get(id).is_some_and(|i| i.contencao_negada);
        if let Some(inc) = self.incidentes.get_mut(id) {
            inc.evidencias.extend(ids);
        }
        self.grafo.ligar(
            No::Incidente(id),
            Aresta::Envolve,
            No::Principal(d.principal.clone()),
        );
        if let Some(alvo) = &d.alvo {
            self.grafo.ligar(
                No::Incidente(id),
                Aresta::Envolve,
                No::Destino(alvo.destino.clone()),
            );
        }
        for acao in resposta::planejar(&d, historico_do_incidente, negada) {
            self.incidentes.agir(id, acao);
        }
    }

    /// Os pedidos planejados, para o fio executar agora. Cada um passa a
    /// "pedido": não volta a sair daqui.
    pub fn pedidos(&mut self) -> Vec<Pedido> {
        let mut v = Vec::new();
        for inc in self.incidentes.todos_mut() {
            for a in &mut inc.acoes {
                if a.estado == EstadoDaAcao::Planejada {
                    a.estado = EstadoDaAcao::Pedida;
                    v.push(Pedido {
                        acao: a.id,
                        metodo: a.metodo.clone(),
                        params: a.params.clone(),
                    });
                }
            }
        }
        self.contadores.pedidos += v.len() as u64;
        v
    }

    /// O desfecho de um pedido: o envelope que o comando respondeu.
    pub fn desfecho(&mut self, acao: u64, envelope: &[u8]) {
        let j = Json(envelope);
        let estado = if let Some(erro) = j.member("error") {
            let codigo =
                util::texto(erro.member("data"), 64).unwrap_or_else(|| "ERROR".to_string());
            self.contadores.negados += 1;
            EstadoDaAcao::Negada { codigo }
        } else if let Some(motivo) = j
            .member("result")
            .and_then(|r| util::texto(r.member("error"), 256))
        {
            self.contadores.falhos += 1;
            EstadoDaAcao::Falhou { motivo }
        } else if j.member("result").is_some() {
            self.contadores.permitidos += 1;
            EstadoDaAcao::Permitida
        } else {
            self.contadores.falhos += 1;
            EstadoDaAcao::Falhou {
                motivo: "resposta sem result nem error".to_string(),
            }
        };
        let codigo = match &estado {
            EstadoDaAcao::Negada { codigo } => codigo.clone(),
            EstadoDaAcao::Permitida => "ALLOW".to_string(),
            _ => "ERROR".to_string(),
        };
        let ts = self.eventos.back().map_or(0, |e| e.ts_ms);
        let info = self.incidentes.acao_mut(acao).map(|(inc, k)| {
            let a = &inc.acoes[k];
            (inc.id, a.metodo.clone(), a.recurso.clone(), a.nivel as u8)
        });
        self.incidentes.desfecho(acao, estado);
        if let Some((inc, metodo, recurso, nivel)) = info {
            let id = self.cofre.guardar(
                ts,
                Some(inc),
                Prova::Acao {
                    acao,
                    metodo,
                    recurso,
                    nivel,
                    codigo,
                    decisao: None,
                },
            );
            if let Some(i) = self.incidentes.get_mut(inc) {
                i.evidencias.push(id);
            }
        }
    }

    /// Os eventos de uma identidade, guardados.
    pub fn eventos_de<'a>(&'a self, principal: &'a str) -> impl Iterator<Item = &'a Evento> + 'a {
        self.eventos
            .iter()
            .filter(move |e| e.principal == principal)
    }

    /// O risco de uma identidade, agora.
    pub fn risco(&self, principal: &str) -> crate::risco::Risco {
        let eventos: Vec<&Evento> = self.eventos_de(principal).collect();
        let deteccoes: Vec<Severidade> = self
            .incidentes
            .todos()
            .filter(|i| i.principal == principal && i.estado != crate::incidente::Estado::Encerrado)
            .flat_map(|i| i.deteccoes.iter().map(|d| d.severidade))
            .collect();
        let anomalia = self.ueba.perfil(principal).is_some_and(|p| p.anomalias > 0);
        crate::risco::avaliar(&eventos, &deteccoes, anomalia)
    }
}
