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
    w.field_str("severity", d.severidade.nome())?;
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
    w.field_str("principal", &i.principal)?;
    w.field_u64("boot", u64::from(i.epoca))?;
    w.field_bool("historical", i.historico)?;
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
    let abertos = m
        .incidentes
        .todos()
        .filter(|i| i.estado != crate::incidente::Estado::Encerrado)
        .count();
    w.field_u64("incidents_open", abertos as u64)?;
    w.field_u64("incidents", m.incidentes.todos().count() as u64)?;
    w.field_u64("evidence", m.cofre.guardados() as u64)?;
    w.field_u64("dns_malformed", m.dns.malformados)?;
    w.end_object()
}

/// `security.incidents` sem `id`.
pub fn incidentes(m: &Motor, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.key("incidents")?;
    w.begin_array()?;
    for i in m.incidentes.todos().rev() {
        resumo(w, i)?;
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
    w.field_str("correlation", &alloc::format!("{:016x}", i.correlacao))?;
    w.field_u64("opened_ms", i.aberto_ms)?;
    w.field_u64("updated_ms", i.atualizado_ms)?;
    w.field_bool("containment_denied", i.contencao_negada)?;
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
        Codigo::Conflict => "a versao ou o arrendamento eram outros",
        Codigo::DenyLease => "outro titular tem o arrendamento do recurso",
        Codigo::DenyReplay => "o pedido repetiu um que ja tinha sido usado",
        Codigo::DenyQuota => "a cota do dono se esgotou",
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
