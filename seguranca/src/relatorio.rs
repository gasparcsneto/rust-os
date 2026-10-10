//! O que as consultas `security.*` respondem, em JSON.
//!
//! Escrito daqui, e não do kernel, para que a resposta se confira no
//! hospedeiro. O kernel chama com o motor travado, guarda o texto, solta a
//! trava, e só então o escreve no canal.
//!
//! Nada aqui decide: [`explicar`] interpreta uma decisão que o gate já
//! tomou e gravou — diz o que o código quer dizer e o que o detalhe conta —,
//! e não refaz a conta da política, que o NSF nem lê.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use politica::Codigo;
use protocolo::json::JsonWriter;

use crate::evento::{Evento, Tipo};
use crate::grafo::No;
use crate::incidente::Incidente;
use crate::motor::Motor;
use crate::regras::Deteccao;
use crate::resposta::Acao;
use crate::util;

/// O texto de um IPv4.
fn ip([a, b, c, d]: [u8; 4]) -> String {
    alloc::format!("{a}.{b}.{c}.{d}")
}

fn evento(w: &mut JsonWriter, e: &Evento) -> fmt::Result {
    w.begin_object()?;
    w.field_u64("seq", e.seq)?;
    w.field_u64("ts_ms", e.ts_ms)?;
    w.field_u64("boot", u64::from(e.epoca))?;
    w.field_str("principal", &e.principal)?;
    w.field_str("holder", e.titular.nome())?;
    w.field_str("identity", &e.identificador)?;
    w.field_str("role", &e.papel)?;
    w.field_str("method", &e.metodo)?;
    w.field_str("resource", &e.recurso)?;
    w.field_str("code", e.codigo.nome())?;
    w.key("process")?;
    match &e.processo {
        Some((fio, _)) => w.u64_value(*fio)?,
        None => w.null_value()?,
    }
    w.key("program")?;
    match &e.processo {
        Some((_, p)) => w.str_value(p)?,
        None => w.null_value()?,
    }
    w.key("decision")?;
    match e.decisao {
        Some(d) => w.u64_value(d)?,
        None => w.null_value()?,
    }
    w.field_str("kind", tipo(e.tipo))?;
    w.field_str("correlation", &alloc::format!("{:016x}", e.correlacao))?;
    w.field_str("severity", e.severidade.nome())?;
    w.field_str("detail", &e.detalhe)?;
    w.end_object()
}

fn tipo(t: Tipo) -> &'static str {
    match t {
        Tipo::Decisao => "decision",
        Tipo::Execucao => "execution",
        Tipo::Nascimento { .. } => "birth",
        Tipo::Derrubada { .. } => "teardown",
        Tipo::Firewall { .. } => "firewall",
        Tipo::Leitura => "nsf-read",
        Tipo::Inicio => "boot",
    }
}

fn deteccao(w: &mut JsonWriter, d: &Deteccao) -> fmt::Result {
    w.begin_object()?;
    w.field_str("rule", d.regra.nome())?;
    w.field_str("category", d.regra.categoria().nome())?;
    w.field_str("severity", d.severidade.nome())?;
    w.field_str("confidence", d.confianca.nome())?;
    w.field_str("principal", &d.principal)?;
    w.field_u64("ts_ms", d.ts_ms)?;
    w.key("records")?;
    w.begin_array()?;
    for r in &d.registros {
        w.u64_value(*r)?;
    }
    w.end_array()?;
    w.field_str("explanation", &d.explicacao)?;
    if let Some(alvo) = &d.alvo {
        w.field_str("target", &alvo.destino)?;
        w.field_str("owner", &alvo.dono)?;
    }
    w.end_object()
}

fn acao(w: &mut JsonWriter, a: &Acao) -> fmt::Result {
    w.begin_object()?;
    w.field_u64("id", a.id)?;
    w.field_str("level", a.nivel.nome())?;
    w.field_u64("level_number", a.nivel as u64)?;
    w.field_str("method", &a.metodo)?;
    w.field_str("resource", &a.recurso)?;
    if !a.params.is_empty() {
        w.field_str("params", &a.params)?;
    }
    if !a.dono.is_empty() {
        w.field_str("subject", &a.dono)?;
    }
    w.field_str("state", a.estado.nome())?;
    match &a.estado {
        crate::resposta::Estado::Negada { codigo } => w.field_str("code", codigo)?,
        crate::resposta::Estado::Falhou { motivo } => w.field_str("reason", motivo)?,
        _ => {}
    }
    w.key("decision")?;
    match a.decisao {
        Some(d) => w.u64_value(d)?,
        None => w.null_value()?,
    }
    w.field_str("authorized_by", &a.autorizado_por)?;
    w.field_str("justification", &a.justificativa)?;
    w.end_object()
}

/// O resumo de um incidente, para a lista.
fn resumo(w: &mut JsonWriter, i: &Incidente) -> fmt::Result {
    w.begin_object()?;
    w.field_u64("id", i.id)?;
    w.field_str("state", i.estado.nome())?;
    w.field_str("severity", i.severidade.nome())?;
    w.field_str("confidence", i.confianca.nome())?;
    w.field_str("principal", &i.principal)?;
    w.field_u64("boot", u64::from(i.epoca))?;
    w.field_bool("historical", i.historico)?;
    w.field_bool("recovered", i.recuperada.is_some())?;
    w.key("rules")?;
    w.begin_array()?;
    let mut regras: Vec<&str> = i.deteccoes.iter().map(|d| d.regra.nome()).collect();
    regras.dedup();
    for r in regras {
        w.str_value(r)?;
    }
    w.end_array()?;
    w.field_u64("actions", i.acoes.len() as u64)?;
    w.field_u64("opened_ms", i.aberto_ms)?;
    w.field_u64("updated_ms", i.atualizado_ms)?;
    w.end_object()
}

/// `security.status`.
pub fn status(m: &Motor, w: &mut JsonWriter) -> fmt::Result {
    let c = &m.contadores;
    w.begin_object()?;
    w.field_str("service", "nsf")?;
    // O papel com que o gate decidiu as leituras do NSF: o que ele é, pela
    // auditoria — o NSF não lê a política.
    let papel = m
        .eventos()
        .rev()
        .find(|e| e.tipo == Tipo::Leitura && e.codigo.permite())
        .map(|e| e.papel.clone());
    w.key("role")?;
    match papel {
        Some(p) => w.str_value(&p)?,
        None => w.null_value()?,
    }
    w.field_u64("boot", u64::from(m.epoca))?;
    w.field_u64("audit_read_until", m.lido())?;
    w.field_u64("live_after", m.ao_vivo())?;
    w.field_u64("capture_read_until", m.captura_lida())?;
    w.field_u64("records_read", c.registros)?;
    w.field_u64("datagrams_read", c.capturas)?;
    w.field_u64("reads_denied", c.leituras_recusadas)?;
    w.field_u64("records_lost", c.perdidos)?;
    w.field_u64("records_tampered", c.adulterados)?;
    w.field_u64("detections", c.deteccoes)?;
    w.field_u64("requests", c.pedidos)?;
    w.field_u64("allowed", c.permitidos)?;
    w.field_u64("denied", c.negados)?;
    w.field_u64("failed", c.falhos)?;
    w.field_u64("recovered", c.recuperadas)?;
    w.field_u64("repeated_containments", c.repetidas)?;
    w.field_u64("observations", c.observacoes)?;
    w.field_u64("denials_seen", c.recusas)?;
    w.field_u64("denials_repeated", c.recusas_repetidas)?;
    let abertos = m
        .incidentes
        .todos()
        .filter(|i| i.estado != crate::incidente::Estado::Encerrado)
        .count();
    w.field_u64("incidents_open", abertos as u64)?;
    w.field_u64("incidents", m.incidentes.todos().count() as u64)?;
    w.field_u64("evidence", m.cofre.guardados() as u64)?;
    w.field_u64("dns_malformed", m.dns.malformados)?;
    saude(m, w)?;
    w.end_object()
}

/// A saúde do NSF, como membro `health`: o estado, o código quando
/// degradado, os motivos e o atraso. Nunca uma recusa — o gate não a lê.
fn saude(m: &Motor, w: &mut JsonWriter) -> fmt::Result {
    let s = m.saude();
    w.key("health")?;
    w.begin_object()?;
    w.field_str("state", s.nome())?;
    if let Some(codigo) = s.codigo() {
        w.field_str("code", codigo)?;
    }
    w.key("reasons")?;
    w.begin_array()?;
    for d in &s.motivos {
        w.str_value(d.nome())?;
    }
    w.end_array()?;
    w.field_u64("backlog", s.atraso)?;
    w.end_object()
}

/// Quantas observações a lista de incidentes mostra: as mais novas.
const OBSERVACOES_NA_LISTA: usize = 16;

/// Uma proporção em milésimos; zero sem base.
fn por_mil(parte: u64, todo: u64) -> u64 {
    parte.saturating_mul(1000).checked_div(todo).unwrap_or(0)
}

/// O uso de uma estrutura contra o teto dela.
fn uso(w: &mut JsonWriter, nome: &str, usado: usize, teto: usize) -> fmt::Result {
    w.key(nome)?;
    w.begin_object()?;
    w.field_u64("used", usado as u64)?;
    w.field_u64("cap", teto as u64)?;
    w.end_object()
}

/// A parte do NSF em `security.metrics`: a saúde, a memória de cada
/// estrutura contra o teto dela, e as taxas que dizem o custo da segurança
/// para quem não é ameaça — a contenção desfeita, o alerta que não deu em
/// nada, a recusa repetida, a recusa de quem o NSF não tinha por ameaça.
///
/// As taxas são milésimos, e dizem do que o NSF ainda guarda: os
/// incidentes são os da janela dele.
pub fn metricas(m: &Motor, w: &mut JsonWriter) -> fmt::Result {
    use crate::incidente::Estado;
    use crate::regras::Confianca;
    let c = &m.contadores;
    w.begin_object()?;
    saude(m, w)?;
    w.key("memory")?;
    w.begin_object()?;
    uso(w, "events", m.eventos().count(), crate::motor::MAIS_EVENTOS)?;
    uso(
        w,
        "incidents",
        m.incidentes.todos().count(),
        crate::incidente::MAIS_INCIDENTES,
    )?;
    uso(
        w,
        "observations",
        m.observacoes().count(),
        crate::motor::MAIS_OBSERVACOES,
    )?;
    uso(
        w,
        "evidence",
        m.cofre.guardados(),
        crate::evidencia::CAPACIDADE,
    )?;
    uso(
        w,
        "graph_edges",
        m.grafo.arestas(),
        crate::grafo::MAIS_ARESTAS,
    )?;
    uso(
        w,
        "profiles",
        m.ueba.perfis().count(),
        crate::ueba::MAIS_PERFIS,
    )?;
    uso(
        w,
        "dns_resolutions",
        m.dns.resolucoes().count(),
        crate::dns::MAIS_RESOLUCOES,
    )?;
    w.end_object()?;
    w.field_u64("records_read", c.registros)?;
    w.field_u64("detections", c.deteccoes)?;
    w.field_u64("observations", c.observacoes)?;
    w.field_u64("incidents", m.incidentes.todos().count() as u64)?;
    // A contenção falsa: o que o NSF conteve e alguém, com a autoridade
    // dele, desfez.
    w.field_u64("containments_allowed", c.permitidos)?;
    w.field_u64("containments_recovered", c.recuperadas)?;
    w.field_u64(
        "false_containment_permille",
        por_mil(c.recuperadas, c.permitidos),
    )?;
    // O alerta que não deu em nada: o incidente encerrado sem contenção e
    // sem detecção de confiança alta.
    let encerrados: Vec<&Incidente> = m
        .incidentes
        .todos()
        .filter(|i| i.estado == Estado::Encerrado)
        .collect();
    let vazios = encerrados
        .iter()
        .filter(|i| {
            i.confianca < Confianca::Alta
                && !i.acoes.iter().any(|a| {
                    a.contem()
                        && matches!(
                            a.estado,
                            crate::resposta::Estado::Permitida | crate::resposta::Estado::Observada
                        )
                })
        })
        .count();
    w.field_u64("incidents_closed", encerrados.len() as u64)?;
    w.field_u64(
        "false_positive_permille",
        por_mil(vazios as u64, encerrados.len() as u64),
    )?;
    w.field_u64("decisions_seen", c.decisoes)?;
    w.field_u64("denials_seen", c.recusas)?;
    w.field_u64("denials_repeated", c.recusas_repetidas)?;
    w.field_u64(
        "agent_retry_permille",
        por_mil(c.recusas_repetidas, c.recusas),
    )?;
    w.field_u64(
        "legitimate_denial_permille",
        por_mil(c.recusas_sem_incidente, c.decisoes),
    )?;
    w.end_object()
}

/// `security.incidents` sem `id`: os incidentes — o nível 1 em diante —
/// e as observações mais novas — o nível 0, o que só chamou a atenção.
pub fn incidentes(m: &Motor, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.key("incidents")?;
    w.begin_array()?;
    for i in m.incidentes.todos().rev() {
        resumo(w, i)?;
    }
    w.end_array()?;
    w.key("observations")?;
    w.begin_array()?;
    for d in m.observacoes().rev().take(OBSERVACOES_NA_LISTA) {
        deteccao(w, d)?;
    }
    w.end_array()?;
    w.end_object()
}

/// `security.incidents` com `id`: o incidente inteiro.
pub fn incidente(m: &Motor, id: u64, w: &mut JsonWriter) -> fmt::Result {
    let Some(i) = m.incidentes.get(id) else {
        w.begin_object()?;
        w.field_str("error", "incidente inexistente")?;
        return w.end_object();
    };
    w.begin_object()?;
    w.field_u64("id", i.id)?;
    w.field_str("state", i.estado.nome())?;
    w.field_str("severity", i.severidade.nome())?;
    w.field_str("principal", &i.principal)?;
    w.field_u64("boot", u64::from(i.epoca))?;
    w.field_bool("historical", i.historico)?;
    w.field_str("confidence", i.confianca.nome())?;
    w.field_str("correlation", &alloc::format!("{:016x}", i.correlacao))?;
    w.field_u64("opened_ms", i.aberto_ms)?;
    w.field_u64("updated_ms", i.atualizado_ms)?;
    w.field_bool("containment_denied", i.contencao_negada)?;
    w.key("recovered_by")?;
    match &i.recuperada {
        Some(quem) => w.str_value(quem)?,
        None => w.null_value()?,
    }
    let r = m.risco(&i.principal);
    w.field_u64("risk", u64::from(r.pontos))?;
    w.key("actors")?;
    w.begin_array()?;
    for a in &i.atores {
        w.str_value(a)?;
    }
    w.end_array()?;
    w.key("resources")?;
    w.begin_array()?;
    for rec in &i.recursos {
        w.str_value(rec)?;
    }
    w.end_array()?;
    w.key("detections")?;
    w.begin_array()?;
    for d in &i.deteccoes {
        deteccao(w, d)?;
    }
    w.end_array()?;
    w.key("actions")?;
    w.begin_array()?;
    for a in &i.acoes {
        acao(w, a)?;
    }
    w.end_array()?;
    w.key("records")?;
    w.begin_array()?;
    for seq in &i.registros {
        w.u64_value(*seq)?;
    }
    w.end_array()?;
    w.key("evidence")?;
    w.begin_array()?;
    for id in &i.evidencias {
        if let Some(item) = m.cofre.item(*id) {
            w.begin_object()?;
            w.field_u64("id", item.id)?;
            w.field_str("link", &util::hex(&item.elo))?;
            match &item.prova {
                crate::evidencia::Prova::Registro { seq, elo } => {
                    w.field_str("kind", "audit-record")?;
                    w.field_u64("seq", *seq)?;
                    w.field_str("audit_link", &util::hex(elo))?;
                }
                crate::evidencia::Prova::Datagrama {
                    captura,
                    destino,
                    resumo,
                    tamanho,
                } => {
                    w.field_str("kind", "datagram")?;
                    w.field_u64("capture", *captura)?;
                    w.field_str("to", destino)?;
                    w.field_str("digest", &util::hex(resumo))?;
                    w.field_u64("size", u64::from(*tamanho))?;
                }
                crate::evidencia::Prova::Deteccao { regra, .. } => {
                    w.field_str("kind", "detection")?;
                    w.field_str("rule", regra)?;
                }
                crate::evidencia::Prova::Acao { acao, codigo, .. } => {
                    w.field_str("kind", "action")?;
                    w.field_u64("action", *acao)?;
                    w.field_str("code", codigo)?;
                }
            }
            w.end_object()?;
        }
    }
    w.end_array()?;
    w.end_object()
}

/// `security.events`: a linha do tempo — de uma identidade, de um
/// incidente, ou toda —, até `max`, dos mais novos.
pub fn eventos(
    m: &Motor,
    principal: Option<&str>,
    incidente: Option<u64>,
    max: usize,
    w: &mut JsonWriter,
) -> fmt::Result {
    let registros = incidente
        .and_then(|id| m.incidentes.get(id))
        .map(|i| i.registros.clone());
    let escolhidos: Vec<&Evento> = m
        .eventos()
        .rev()
        .filter(|e| principal.is_none_or(|p| e.principal == p))
        .filter(|e| registros.as_ref().is_none_or(|r| r.contains(&e.seq)))
        .take(max)
        .collect();
    w.begin_object()?;
    w.key("events")?;
    w.begin_array()?;
    for e in escolhidos.into_iter().rev() {
        evento(w, e)?;
    }
    w.end_array()?;
    w.end_object()
}

/// O que um código de recusa quer dizer, para quem lê.
fn significado(c: Codigo) -> &'static str {
    match c {
        Codigo::Allow => {
            "o gate permitiu: o papel tem a permissao, e o recurso esta no alcance dela"
        }
        Codigo::DenyNotAuthenticated => {
            "quem pediu nao tinha uma identidade valida naquele instante: sessao que acabou, chave revogada, ou ninguem entrado"
        }
        Codigo::DenyRole => {
            "a identidade nao tinha papel que a politica conheca — ou o papel e o teto de um administrador, que delega e nao se exerce"
        }
        Codigo::DenyPermission => {
            "o papel nao enumera a permissao que o metodo exige — ou o manifesto do programa nao a declara"
        }
        Codigo::DenyResource => {
            "o papel tem a permissao, mas o recurso pedido esta fora do alcance escrito dela"
        }
        Codigo::DenyPolicy => {
            "uma regra alem do papel recusou: a cota, ou o firewall depois do gate"
        }
        Codigo::RateLimit => "a taxa do papel se esgotou",
        Codigo::InvalidArgument => "o pedido nao chegou a ser um comando valido",
        Codigo::Conflict => {
            "a versao esperada nao era a de agora, ou outro titular tinha o arrendamento"
        }
        Codigo::DenyLease => "a operacao pede o arrendamento, e quem pediu nao o tinha",
        Codigo::DenyReplay => "o pedido repetiu um que ja tinha sido usado",
        Codigo::DenyQuota => "a cota do dono se esgotou",
        Codigo::DenyContained => {
            "quem pediu estava contido (o processo isolado, ou o agente suspenso), por uma contencao reversivel"
        }
        Codigo::DenyCredential => {
            "a credencial de quem pediu estava suspensa: nao autentica, e as sessoes dela nao agem"
        }
        Codigo::Error => "a operacao falhou depois de autorizada",
    }
}

/// `security.explain`: a interpretação de uma decisão gravada.
pub fn explicar(m: &Motor, seq: u64, w: &mut JsonWriter) -> fmt::Result {
    let Some(e) = m.evento(seq) else {
        w.begin_object()?;
        w.field_str("error", "o registro esta fora da janela do NSF")?;
        return w.end_object();
    };
    w.begin_object()?;
    w.key("event")?;
    evento(w, e)?;
    w.field_str("meaning", significado(e.codigo))?;
    w.field_str(
        "note",
        "uma interpretacao do registro: a decisao foi a do gate, e so ele decide",
    )?;
    // O que a mesma identidade fez em volta — o contexto, não a causa.
    w.key("related")?;
    w.begin_array()?;
    for o in m
        .eventos()
        .filter(|o| o.correlacao == e.correlacao && o.seq != e.seq)
        .rev()
        .take(8)
    {
        w.u64_value(o.seq)?;
    }
    w.end_array()?;
    // Uma conexão: a resolução que a precedeu, e se o endereço passou pelo
    // gate.
    if e.metodo == "net.connect"
        && let (Some(d), Some(dono)) = (politica::endereco::ler(&e.recurso), e.dono())
    {
        w.key("dns")?;
        match m.dns.antes_de(&dono, d.ip, e.seq) {
            Some(r) => {
                w.begin_object()?;
                w.field_str("name", &r.nome)?;
                w.field_str("server", &r.servidor)?;
                w.field_u64("capture", r.captura)?;
                w.field_bool("matched_question", r.casada)?;
                w.field_bool("address_decided_by_gate", true)?;
                w.field_str("gate_code", e.codigo.nome())?;
                w.end_object()?;
            }
            None => w.null_value()?,
        }
    }
    let incidentes: Vec<u64> = m
        .incidentes
        .todos()
        .filter(|i| i.registros.contains(&seq))
        .map(|i| i.id)
        .collect();
    w.key("incidents")?;
    w.begin_array()?;
    for i in incidentes {
        w.u64_value(i)?;
    }
    w.end_array()?;
    // O que o NSF viu neste registro — de um incidente ou só observado —,
    // com a categoria e a confiança: o NSF interpretou, e não decidiu.
    w.key("detections")?;
    w.begin_array()?;
    for d in m.deteccoes().filter(|d| d.registros.contains(&seq)) {
        w.begin_object()?;
        w.field_str("rule", d.regra.nome())?;
        w.field_str("category", d.regra.categoria().nome())?;
        w.field_str("severity", d.severidade.nome())?;
        w.field_str("confidence", d.confianca.nome())?;
        w.field_str("explanation", &d.explicacao)?;
        w.end_object()?;
    }
    w.end_array()?;
    w.end_object()
}

/// `security.provenance`: a cadeia de um processo até a raiz, e a rede
/// dele — cada conexão pedida, a decisão do gate, e o DNS que a precedeu.
pub fn proveniencia(m: &Motor, epoca: u32, fio: u64, w: &mut JsonWriter) -> fmt::Result {
    let p = m.grafo.proveniencia(epoca, fio);
    w.begin_object()?;
    w.field_u64("process", fio)?;
    w.field_u64("boot", u64::from(epoca))?;
    w.field_bool("complete", p.completa())?;
    w.key("root")?;
    match &p.raiz {
        Some(r) => w.str_value(r)?,
        None => w.null_value()?,
    }
    w.key("chain")?;
    w.begin_array()?;
    for elo in &p.cadeia {
        w.begin_object()?;
        w.field_u64("process", elo.fio)?;
        w.key("program")?;
        match &elo.programa {
            Some(prog) => w.str_value(prog)?,
            None => w.null_value()?,
        }
        w.field_str("authority", &elo.autoridade)?;
        w.field_str("via", elo.via.nome())?;
        w.field_u64("birth_record", elo.seq)?;
        w.end_object()?;
    }
    w.end_array()?;
    w.key("children")?;
    w.begin_array()?;
    for f in m.grafo.descendentes(epoca, fio) {
        w.u64_value(f)?;
    }
    w.end_array()?;
    // A rede: os pedidos de conexão deste processo.
    let dono = alloc::format!("process:{fio}");
    w.key("network")?;
    w.begin_array()?;
    for e in m.eventos().filter(|e| {
        e.epoca == epoca
            && e.metodo == "net.connect"
            && e.tipo == Tipo::Decisao
            && e.processo.as_ref().is_some_and(|(f, _)| *f == fio)
    }) {
        w.begin_object()?;
        w.field_u64("decision", e.seq)?;
        w.field_str("to", &e.recurso)?;
        w.field_str("code", e.codigo.nome())?;
        if let Some(d) = politica::endereco::ler(&e.recurso) {
            w.field_str("protocol", d.protocolo.prefixo().trim_end_matches(':'))?;
            w.field_u64("port", u64::from(d.porta))?;
            w.field_str("address", &ip(d.ip))?;
            w.key("dns")?;
            match m.dns.antes_de(&dono, d.ip, e.seq) {
                Some(r) => {
                    w.begin_object()?;
                    w.field_str("name", &r.nome)?;
                    w.field_u64("capture", r.captura)?;
                    w.field_bool("matched_question", r.casada)?;
                    w.end_object()?;
                }
                None => w.null_value()?,
            }
            // A regra do firewall que barrou um pedido deste fluxo.
            let regra = m.eventos().find_map(|x| match x.tipo {
                Tipo::Firewall { regra }
                    if x.decisao == Some(e.seq)
                        || (x.recurso == e.recurso && x.processo == e.processo) =>
                {
                    Some(regra)
                }
                _ => None,
            });
            w.key("firewall_rule")?;
            match regra {
                Some(r) => w.u64_value(r)?,
                None => w.null_value()?,
            }
        }
        w.end_object()?;
    }
    w.end_array()?;
    w.end_object()
}

/// `security.risk`: o risco de uma identidade, o perfil dela, e o raio do
/// que ela já tocou — análise, nunca decisão.
pub fn risco(m: &Motor, principal: &str, w: &mut JsonWriter) -> fmt::Result {
    let r = m.risco(principal);
    w.begin_object()?;
    w.field_str("principal", principal)?;
    w.field_u64("risk", u64::from(r.pontos))?;
    w.key("factors")?;
    w.begin_array()?;
    for f in &r.fatores {
        w.begin_object()?;
        w.field_str("name", f.nome)?;
        w.field_u64("points", u64::from(f.pontos))?;
        w.field_str("reason", &f.motivo)?;
        w.end_object()?;
    }
    w.end_array()?;
    w.key("profile")?;
    match m.ueba.perfil(principal) {
        Some(p) => {
            w.begin_object()?;
            w.field_str("holder", p.titular.nome())?;
            w.field_u64("requests", p.pedidos)?;
            w.field_u64("denied", p.recusas)?;
            w.field_u64("anomalies", p.anomalias)?;
            w.field_bool("baseline", p.base.is_some())?;
            w.key("methods")?;
            w.begin_object()?;
            for (metodo, n) in &p.metodos {
                w.field_u64(metodo, *n)?;
            }
            w.end_object()?;
            w.field_str("note", "contexto: o perfil nao autoriza nem recusa nada")?;
            w.end_object()?;
        }
        None => w.null_value()?,
    }
    // O raio: o que a identidade tocou com permissão, os processos que
    // descendem dela, e os destinos com que conversou.
    let epoca = m.epoca;
    let tocados: alloc::collections::BTreeSet<&str> = m
        .eventos_de(principal)
        .filter(|e| e.codigo.permite() && !e.recurso.is_empty() && e.tipo == Tipo::Decisao)
        .map(|e| e.recurso.as_str())
        .collect();
    w.key("blast_radius")?;
    w.begin_object()?;
    w.key("resources")?;
    w.begin_array()?;
    for t in &tocados {
        w.str_value(t)?;
    }
    w.end_array()?;
    w.key("processes")?;
    w.begin_array()?;
    for f in m.grafo.processos_de(epoca, principal) {
        w.u64_value(f)?;
    }
    w.end_array()?;
    w.field_str(
        "note",
        "analise do que ja se observou: nao e o alcance do papel, que o NSF nao le",
    )?;
    w.end_object()?;
    w.end_object()
}

/// `security.verify`: refaz a cadeia do cofre.
pub fn verificar(m: &Motor, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    match m.cofre.verificar() {
        Ok(cabeca) => {
            w.field_bool("ok", true)?;
            w.field_str("head", &util::hex(&cabeca))?;
        }
        Err(id) => {
            w.field_bool("ok", false)?;
            w.field_u64("failed_at", id)?;
        }
    }
    w.field_str("anchor", &util::hex(&m.cofre.ancora()))?;
    w.field_u64("checked", m.cofre.guardados() as u64)?;
    w.end_object()
}

/// O grafo em volta de um nó, para quem investiga.
pub fn vizinhos(m: &Motor, no: &No, w: &mut JsonWriter) -> fmt::Result {
    w.begin_array()?;
    for (a, outro, sai) in m.grafo.vizinhos(no) {
        w.begin_object()?;
        w.field_str("edge", a.nome())?;
        w.field_str("node", &outro.texto())?;
        w.field_bool("outgoing", sai)?;
        w.end_object()?;
    }
    w.end_array()
}
