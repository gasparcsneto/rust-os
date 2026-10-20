//! O motor de ponta a ponta, no hospedeiro: uma auditoria escrita aqui, como
//! o `audit.tail` do kernel a escreve, com os elos feitos pela mesma conta,
//! e o que o motor detecta, abre, pede e verifica.

use politica::Codigo;
use politica::auditoria::{Evento as DaCadeia, Titular, elo};
use protocolo::json::{Json, JsonWriter};
use seguranca::Motor;
use seguranca::evento::{Ancora, Severidade, Tipo};
use seguranca::grafo::{Aresta, No};
use seguranca::incidente::Estado as EstadoDoIncidente;
use seguranca::regras::{Confianca, Regra};
use seguranca::resposta::{Estado as EstadoDaAcao, Nivel};

const CHAVE: [u8; 32] = [0xA1; 32];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Uma auditoria que cresce, com os elos de verdade.
struct Auditoria {
    seq: u64,
    elo: [u8; 32],
    ts: u64,
    /// Quanto o carimbo anda a cada registro: zero é o tempo lógico
    /// parado.
    passo: u64,
    registros: Vec<String>,
}

/// O que muda de um registro para outro.
struct R<'a> {
    titular: Titular,
    agente: &'a str,
    chave: Option<[u8; 32]>,
    papel: &'a str,
    metodo: &'a str,
    recurso: &'a str,
    codigo: Codigo,
    detalhe: &'a str,
}

fn do_agente<'a>(metodo: &'a str, recurso: &'a str, codigo: Codigo, detalhe: &'a str) -> R<'a> {
    R {
        titular: Titular::Agente,
        agente: "explorador",
        chave: Some(CHAVE),
        papel: "operador",
        metodo,
        recurso,
        codigo,
        detalhe,
    }
}

impl Auditoria {
    fn nova() -> Auditoria {
        Auditoria {
            seq: 0,
            elo: [0; 32],
            ts: 10_000,
            passo: 100,
            registros: Vec::new(),
        }
    }

    fn gravar(&mut self, r: R) -> u64 {
        self.seq += 1;
        self.ts += self.passo;
        let e = DaCadeia {
            ts_ms: self.ts,
            titular: r.titular,
            sessao: 1,
            sessao_de_pessoa: None,
            agente: r.agente.to_string(),
            chave: r.chave,
            papel: r.papel.to_string(),
            metodo: r.metodo.to_string(),
            recurso: r.recurso.to_string(),
            codigo: r.codigo,
            parametros: [0; 32],
            detalhe: r.detalhe.to_string(),
        };
        let novo = elo(&self.elo, self.seq, &e);
        let mut s = String::new();
        let mut w = JsonWriter::new(&mut s);
        w.begin_object().unwrap();
        w.field_u64("seq", self.seq).unwrap();
        w.field_u64("ts_ms", e.ts_ms).unwrap();
        w.field_str("holder", e.titular.nome()).unwrap();
        w.field_u64("session", 1).unwrap();
        w.key("person_session").unwrap();
        w.null_value().unwrap();
        w.field_str("agent", &e.agente).unwrap();
        w.key("key").unwrap();
        match &e.chave {
            Some(k) => w.str_value(&hex(k)).unwrap(),
            None => w.null_value().unwrap(),
        }
        w.field_str("role", &e.papel).unwrap();
        w.field_str("method", &e.metodo).unwrap();
        w.field_str("resource", &e.recurso).unwrap();
        w.field_str("result", e.codigo.resultado()).unwrap();
        w.field_str("code", e.codigo.nome()).unwrap();
        w.field_str("params", &hex(&e.parametros)).unwrap();
        w.field_str("detail", &e.detalhe).unwrap();
        w.field_str("prev", &hex(&self.elo)).unwrap();
        w.field_str("link", &hex(&novo)).unwrap();
        w.field_bool("durable", false).unwrap();
        w.end_object().unwrap();
        self.registros.push(s);
        self.elo = novo;
        self.seq
    }

    /// O resultado de um `audit.tail {after}`.
    fn depois_de(&self, after: u64) -> String {
        let corpo: Vec<&str> = self
            .registros
            .iter()
            .skip(after as usize)
            .map(String::as_str)
            .collect();
        format!(r#"{{"durable_seq":0,"records":[{}]}}"#, corpo.join(","))
    }
}

/// Lê tudo o que a auditoria tem de novo.
fn ler(m: &mut Motor, a: &Auditoria) {
    m.ler_auditoria(a.depois_de(m.lido()).as_bytes()).unwrap();
}

/// A sondagem de um agente: três métodos sem permissão.
fn sondar(a: &mut Auditoria) {
    for metodo in ["fs.read", "policy.show", "disk.read"] {
        a.gravar(do_agente(
            metodo,
            "",
            Codigo::DenyPermission,
            "o papel nao tem a permissao",
        ));
    }
}

/// O que o NSF faria: a auditoria grava a decisão do pedido dele.
fn nsf_pediu(a: &mut Auditoria, metodo: &str, recurso: &str, codigo: Codigo) -> u64 {
    a.gravar(R {
        titular: Titular::Servico,
        agente: "nsf",
        chave: None,
        papel: "seguranca",
        metodo,
        recurso,
        codigo,
        detalhe: "pelo processo 7 (kernel)",
    })
}

const ECO: &str = "tcp:10.0.2.100:7";

#[test]
fn da_sondagem_a_contencao_pelo_gate() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    sondar(&mut a);
    ler(&mut m, &a);
    let inc = m
        .incidentes
        .todos()
        .next()
        .expect("a sondagem abre um incidente");
    assert_eq!(inc.severidade, Severidade::Alta);
    assert_eq!(inc.deteccoes[0].regra, Regra::SondagemDePrivilegio);
    assert!(m.pedidos().is_empty(), "sondar nao leva a pedido nenhum");

    // Com o incidente alto aberto, o agente usa a rede — e o gate deixa.
    let conexao = a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
    ler(&mut m, &a);
    let pedidos = m.pedidos();
    assert_eq!(pedidos.len(), 1);
    assert_eq!(pedidos[0].metodo, "net.block");
    let dono = format!("agent:{}", hex(&CHAVE));
    assert_eq!(
        pedidos[0].params,
        format!(r#"{{"to":"{ECO}","owner":"{dono}"}}"#)
    );
    // Uma vez: o pedido não sai de novo.
    assert!(m.pedidos().is_empty());

    // O gate permite; a auditoria grava a decisão do NSF.
    m.desfecho(
        pedidos[0].acao,
        br#"{"jsonrpc":"2.0","id":1,"result":{"rule":1}}"#,
    );
    let decisao = nsf_pediu(&mut a, "net.block", ECO, Codigo::Allow);
    ler(&mut m, &a);
    let inc = m.incidentes.todos().next().unwrap();
    assert_eq!(inc.estado, EstadoDoIncidente::Contido);
    let acao = inc.acoes.iter().find(|x| x.metodo == "net.block").unwrap();
    assert_eq!(acao.estado, EstadoDaAcao::Permitida);
    assert_eq!(
        acao.decisao,
        Some(decisao),
        "a acao ganha o numero da decisao do gate"
    );
    assert_eq!(acao.autorizado_por, "service:nsf");
    assert!(inc.registros.contains(&conexao));
    // Nenhuma ação sem plano: o registro do NSF casou com o pedido.
    assert!(
        m.incidentes
            .todos()
            .all(|i| i.deteccoes.iter().all(|d| d.regra != Regra::AcaoSemPlano))
    );
    // O cofre refaz a cadeia, e tem a ação, a detecção e os registros.
    assert!(m.cofre.verificar().is_ok());
    assert!(inc.evidencias.len() >= 5);
}

/// O gate recusa a contenção: o incidente fica sem contenção automática, e
/// o motor não pede outra — nem com outro alvo, nem de novo.
#[test]
fn a_recusa_encerra_o_objetivo() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    sondar(&mut a);
    a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
    ler(&mut m, &a);
    let p = m.pedidos();
    assert_eq!(p.len(), 1);
    m.desfecho(
        p[0].acao,
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"negado","data":"DENY_RESOURCE"}}"#,
    );
    nsf_pediu(&mut a, "net.block", ECO, Codigo::DenyResource);
    // O agente continua: outro destino, e o mesmo de novo.
    a.gravar(do_agente(
        "net.connect",
        "udp:10.0.2.2:69",
        Codigo::Allow,
        "",
    ));
    a.gravar(do_agente("net.send", ECO, Codigo::Allow, ""));
    ler(&mut m, &a);
    assert!(
        m.pedidos().is_empty(),
        "depois da recusa, nenhum outro pedido"
    );
    let inc = m.incidentes.todos().next().unwrap();
    assert!(inc.contencao_negada);
    assert_eq!(inc.estado, EstadoDoIncidente::Aberto);
    let negada = inc
        .acoes
        .iter()
        .find(|x| x.estado != EstadoDaAcao::Recomendada)
        .unwrap();
    assert_eq!(
        negada.estado,
        EstadoDaAcao::Negada {
            codigo: "DENY_RESOURCE".to_string()
        }
    );
    assert!(negada.decisao.is_some());
    // O que ficou para o novo destino é recomendação para quem tem a
    // autoridade.
    assert!(
        inc.acoes
            .iter()
            .filter(|x| x.recurso == "udp:10.0.2.2:69")
            .all(|x| x.estado == EstadoDaAcao::Recomendada)
    );
}

/// A história — o que veio antes de o motor estar ao vivo — vira
/// incidente com recomendação, nunca com pedido.
#[test]
fn a_historia_nao_pede() {
    let mut a = Auditoria::nova();
    sondar(&mut a);
    a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
    let mut m = Motor::novo();
    m.ao_vivo_depois_de(a.seq);
    ler(&mut m, &a);
    assert!(m.pedidos().is_empty());
    let inc = m.incidentes.todos().next().unwrap();
    assert!(inc.historico);
    assert!(
        inc.acoes
            .iter()
            .all(|x| x.estado == EstadoDaAcao::Recomendada)
    );
}

/// Uma ação do NSF que a auditoria mostra sem pedido do motor: crítica.
#[test]
fn a_acao_sem_plano() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    a.gravar(do_agente("agent.ping", "", Codigo::Allow, ""));
    ler(&mut m, &a);
    nsf_pediu(&mut a, "net.block", ECO, Codigo::Allow);
    ler(&mut m, &a);
    let inc = m
        .incidentes
        .todos()
        .next()
        .expect("incidente da acao sem plano");
    assert_eq!(inc.deteccoes[0].regra, Regra::AcaoSemPlano);
    assert_eq!(inc.severidade, Severidade::Critica);
    assert_eq!(inc.principal, "service:nsf");
}

/// O elo adulterado e a lacuna aparecem.
#[test]
fn a_auditoria_adulterada_e_a_lacuna() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    for _ in 0..3 {
        a.gravar(do_agente("agent.ping", "", Codigo::Allow, ""));
    }
    // O segundo registro, mudado depois do elo.
    a.registros[1] = a.registros[1].replace("agent.ping", "agent.pong");
    ler(&mut m, &a);
    assert_eq!(m.contadores.adulterados, 1);
    let regras: Vec<Regra> = m
        .incidentes
        .todos()
        .flat_map(|i| i.deteccoes.iter().map(|d| d.regra))
        .collect();
    assert!(regras.contains(&Regra::AuditoriaAdulterada));
    // Uma lacuna: o que sumiu do anel antes da leitura.
    for _ in 0..4 {
        a.gravar(do_agente("agent.ping", "", Codigo::Allow, ""));
    }
    let so_o_ultimo = format!(r#"{{"records":[{}]}}"#, a.registros.last().unwrap());
    m.ler_auditoria(so_o_ultimo.as_bytes()).unwrap();
    assert_eq!(m.contadores.perdidos, 3);
}

/// O processo que nasce, o neto que bifurca, e a proveniência até o
/// agente; a correlação é a mesma para a cadeia toda.
#[test]
fn a_proveniencia_pela_auditoria() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    a.gravar(do_agente("user.run", "/programas/x/um", Codigo::Allow, ""));
    a.gravar(do_agente(
        "user.run",
        "/programas/x/um",
        Codigo::Allow,
        "processo 12 lancado; decisao 1",
    ));
    a.gravar(do_agente(
        "user.run",
        "/programas/x/dois",
        Codigo::Allow,
        "pelo processo 12 (um 0a0b0c0d): processo 13 lancado; decisao 2",
    ));
    a.gravar(do_agente(
        "process.fork",
        "",
        Codigo::Allow,
        "pelo processo 13 (dois 01020304): filho 14",
    ));
    a.gravar(do_agente(
        "fs.read",
        "/dados/x",
        Codigo::DenyPermission,
        "pelo processo 14 (dois 01020304): o manifesto nao declara fs.read",
    ));
    ler(&mut m, &a);
    let prov = m.grafo.proveniencia(0, 14);
    assert!(prov.completa());
    assert_eq!(
        prov.raiz.as_deref(),
        Some(format!("agent:{}", hex(&CHAVE)).as_str())
    );
    let cadeia: Vec<u64> = prov.cadeia.iter().map(|e| e.fio).collect();
    assert_eq!(cadeia, [14, 13, 12]);
    assert_eq!(prov.cadeia[1].programa.as_deref(), Some("dois 01020304"));
    let correlacoes: std::collections::BTreeSet<u64> = m.eventos().map(|e| e.correlacao).collect();
    assert_eq!(correlacoes.len(), 1, "a cadeia inteira na mesma correlacao");
    // E o relatório diz a cadeia.
    let mut s = String::new();
    seguranca::relatorio::proveniencia(&m, 0, 14, &mut JsonWriter::new(&mut s)).unwrap();
    let j = Json(s.as_bytes());
    assert_eq!(j.member("complete").and_then(|v| v.as_bool()), Some(true));
    assert!(s.contains(r#""via":"forked""#), "{s}");
}

/// O DNS que levou a um destino recusado: a resolução vem pela captura,
/// a recusa pela auditoria, e a regra liga as duas.
#[test]
fn o_dns_contra_a_politica() {
    use protocolo::dns::{Nome, pergunta, resposta};
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    let dono = "process:9";
    let mut b = [0u8; 512];
    let n = pergunta(5, &Nome::de_texto("proibido.duke").unwrap(), &mut b).unwrap();
    let q = b[..n].to_vec();
    let n = resposta(
        5,
        &Nome::de_texto("proibido.duke").unwrap(),
        &[[10, 0, 2, 99]],
        60,
        0,
        &mut b,
    )
    .unwrap();
    let r = b[..n].to_vec();
    let captura = format!(
        r#"{{"records":[{{"seq":1,"ts_ms":10050,"after_record":1,"connection":3,"owner":"{dono}","to":"udp:10.0.2.53:53","direction":"out","size":{},"data":"{}"}},{{"seq":2,"ts_ms":10060,"after_record":1,"connection":3,"owner":"{dono}","to":"udp:10.0.2.53:53","direction":"in","size":{},"data":"{}"}}]}}"#,
        q.len(),
        seguranca::util::base64(&q),
        r.len(),
        seguranca::util::base64(&r)
    );
    assert_eq!(
        m.ler_captura("udp:10.0.2.53:53", captura.as_bytes()),
        Ok(0),
        "sem ninguem ter usado o servidor, nada a observar"
    );
    assert!(m.a_observar().is_empty());
    // O processo abre a associação com o servidor, e o gate deixa: o motor
    // passa a observá-lo.
    a.gravar(do_agente(
        "net.connect",
        "udp:10.0.2.53:53",
        Codigo::Allow,
        "pelo processo 9 (resolvedor 00000000)",
    ));
    ler(&mut m, &a);
    assert_eq!(m.a_observar(), [("udp:10.0.2.53:53".to_string(), 0)]);
    assert_eq!(m.ler_captura("udp:10.0.2.53:53", captura.as_bytes()), Ok(2));
    assert_eq!(m.a_observar(), [("udp:10.0.2.53:53".to_string(), 2)]);
    // Recusada a leitura, o motor não pede de novo — até a política mudar.
    m.observacao_recusada("udp:10.0.2.53:53");
    assert!(m.a_observar().is_empty());
    let negada = a.gravar(do_agente(
        "net.connect",
        "tcp:10.0.2.99:80",
        Codigo::DenyResource,
        "pelo processo 9 (resolvedor 00000000): recurso fora do alcance do papel",
    ));
    ler(&mut m, &a);
    // Um nome que levou a um destino recusado é de olhar — o alcance
    // estreito de todo dia —: uma observação, sem incidente.
    assert_eq!(m.incidentes.todos().count(), 0);
    let obs = m.observacoes().next().expect("a observacao do dns");
    assert_eq!(obs.regra, Regra::DnsContraAPolitica);
    assert_eq!(obs.confianca, Confianca::Baixa);
    assert!(obs.explicacao.contains("proibido.duke"));
    // A explicação da decisão diz o nome, e que o endereço passou pelo gate
    // — e foi recusado.
    let mut s = String::new();
    seguranca::relatorio::explicar(&m, negada, &mut JsonWriter::new(&mut s)).unwrap();
    assert!(s.contains(r#""name":"proibido.duke""#), "{s}");
    assert!(s.contains(r#""gate_code":"DENY_RESOURCE""#), "{s}");
    assert_eq!(m.dns.resolucoes().next().map(|r| r.casada), Some(true));
}

/// A conversa de uma resolução com o DNS, no formato do `net.observe`:
/// guardada com a auditoria no registro `registro`.
fn conversa(dono: &str, nome: &str, ip: [u8; 4], seq: u64, registro: u64) -> String {
    use protocolo::dns::{Nome, pergunta, resposta};
    let mut b = [0u8; 512];
    let n = pergunta(5, &Nome::de_texto(nome).unwrap(), &mut b).unwrap();
    let q = b[..n].to_vec();
    let n = resposta(5, &Nome::de_texto(nome).unwrap(), &[ip], 60, 0, &mut b).unwrap();
    let r = b[..n].to_vec();
    format!(
        r#"{{"records":[{{"seq":{},"ts_ms":10000,"after_record":{registro},"connection":3,"owner":"{dono}","to":"udp:10.0.2.53:53","direction":"out","size":{},"data":"{}"}},{{"seq":{},"ts_ms":10000,"after_record":{registro},"connection":3,"owner":"{dono}","to":"udp:10.0.2.53:53","direction":"in","size":{},"data":"{}"}}]}}"#,
        seq,
        q.len(),
        seguranca::util::base64(&q),
        seq + 1,
        r.len(),
        seguranca::util::base64(&r)
    )
}

/// A auditoria lida antes da captura — o caso de todo dia: o programa
/// abre o servidor, resolve e conecta antes da volta do NSF, e o servidor
/// só passa a ser observado pela própria auditoria. A resolução, lida
/// depois, encontra a conexão recusada que ela precedeu. E uma resolução
/// de depois da conexão não a precedeu: não liga nada.
#[test]
fn o_dns_lido_depois_da_conexao() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    let dono = "process:9";
    a.gravar(do_agente(
        "net.connect",
        "udp:10.0.2.53:53",
        Codigo::Allow,
        "pelo processo 9 (resolvedor 00000000)",
    ));
    let negada = a.gravar(do_agente(
        "net.connect",
        "tcp:10.0.2.99:80",
        Codigo::DenyResource,
        "pelo processo 9 (resolvedor 00000000): recurso fora do alcance do papel",
    ));
    let outra = a.gravar(do_agente(
        "net.connect",
        "tcp:10.0.2.98:80",
        Codigo::DenyResource,
        "pelo processo 9 (resolvedor 00000000): recurso fora do alcance do papel",
    ));
    ler(&mut m, &a);
    assert_eq!(
        m.incidentes.todos().count(),
        0,
        "sem a resolucao, nada liga"
    );
    // A resolução de proibido.duke foi guardada com a auditoria na abertura
    // (registro 1), antes da recusa (2); a de tarde.duke, com a auditoria
    // já na recusa dela (3) — no mesmo segundo, a ordem é a dos registros.
    let antes = conversa(dono, "proibido.duke", [10, 0, 2, 99], 1, 1);
    assert_eq!(m.ler_captura("udp:10.0.2.53:53", antes.as_bytes()), Ok(2));
    let depois = conversa(dono, "tarde.duke", [10, 0, 2, 98], 3, outra);
    assert_eq!(m.ler_captura("udp:10.0.2.53:53", depois.as_bytes()), Ok(2));
    assert_eq!(m.incidentes.todos().count(), 0);
    let d: Vec<_> = m.deteccoes().collect();
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].regra, Regra::DnsContraAPolitica);
    assert_eq!(d[0].registros, [negada]);
    assert!(
        d[0].explicacao.contains("proibido.duke"),
        "{}",
        d[0].explicacao
    );
    assert!(!d[0].registros.contains(&outra));
    assert_eq!(
        m.evento(negada).map(|e| e.severidade),
        Some(Severidade::Media)
    );
    // A explicação, igual nas duas ordens.
    let mut s = String::new();
    seguranca::relatorio::explicar(&m, negada, &mut JsonWriter::new(&mut s)).unwrap();
    assert!(s.contains(r#""name":"proibido.duke""#), "{s}");
    let mut s = String::new();
    seguranca::relatorio::explicar(&m, outra, &mut JsonWriter::new(&mut s)).unwrap();
    assert!(s.contains(r#""dns":null"#), "{s}");
    // Ler de novo não dispara de novo.
    assert_eq!(m.ler_captura("udp:10.0.2.53:53", antes.as_bytes()), Ok(0));
    assert_eq!(m.deteccoes().count(), 1);
}

/// O motor que começa do agora não lê a captura de antes dele: o servidor
/// que ele passa a observar é lido de onde o agora começou, e não do
/// começo do anel, que guarda a conversa de quem veio antes — com um dono
/// que pode ter o mesmo número de um de agora.
#[test]
fn o_agora_vale_tambem_para_a_captura() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    let velha = conversa("process:9", "velho.duke", [10, 0, 2, 99], 1, 0);
    m.comecar_depois_de(0, 2);
    a.gravar(do_agente(
        "net.connect",
        "udp:10.0.2.53:53",
        Codigo::Allow,
        "pelo processo 9 (resolvedor 00000000)",
    ));
    ler(&mut m, &a);
    assert_eq!(m.a_observar(), [("udp:10.0.2.53:53".to_string(), 2)]);
    assert_eq!(m.ler_captura("udp:10.0.2.53:53", velha.as_bytes()), Ok(0));
    assert_eq!(m.dns.resolucoes().count(), 0);
    let nova = conversa("process:9", "novo.duke", [10, 0, 2, 100], 3, 1);
    assert_eq!(m.ler_captura("udp:10.0.2.53:53", nova.as_bytes()), Ok(2));
    assert_eq!(m.dns.resolucoes().count(), 1);
    // Sem o agora, o anel inteiro: a conversa que veio antes de o servidor
    // ser conhecido é a do programa que acabou de usá-lo.
    let mut m = Motor::novo();
    ler(&mut m, &a);
    assert_eq!(m.a_observar(), [("udp:10.0.2.53:53".to_string(), 0)]);
    assert_eq!(m.ler_captura("udp:10.0.2.53:53", velha.as_bytes()), Ok(2));
}

/// A mesma sequência de uma pessoa e de um agente: as mesmas regras, a
/// mesma severidade — nenhuma exceção para nenhum dos dois.
#[test]
fn pessoa_e_agente_sem_excecao() {
    let rodar = |titular: Titular, agente: &str, chave: Option<[u8; 32]>| {
        let mut a = Auditoria::nova();
        for metodo in ["fs.read", "policy.show", "disk.read", "audit.tail"] {
            a.gravar(R {
                titular,
                agente,
                chave,
                papel: "operador",
                metodo,
                recurso: "",
                codigo: Codigo::DenyPermission,
                detalhe: "",
            });
        }
        let mut m = Motor::novo();
        ler(&mut m, &a);
        m.incidentes
            .todos()
            .flat_map(|i| i.deteccoes.iter().map(|d| (d.regra, d.severidade)))
            .collect::<Vec<_>>()
    };
    let agente = rodar(Titular::Agente, "explorador", Some(CHAVE));
    let pessoa = rodar(Titular::Pessoa, "pessoa:00112233aabbccdd", None);
    assert!(!agente.is_empty());
    assert_eq!(agente, pessoa);
}

/// O programa que pede fora do próprio manifesto não faz de quem o lançou
/// um sondador: a serial roda um programa que confere a atenuação dele —
/// três recusas do manifesto —, e depois conecta, pelo próprio papel. O
/// incidente é do programa fora do manifesto, médio; a saída não é contida.
#[test]
fn o_programa_fora_do_manifesto_nao_contem_quem_o_lancou() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    for metodo in ["fs.open", "message.send", "process.exec"] {
        a.gravar(R {
            titular: Titular::Serial,
            agente: "serial",
            chave: None,
            papel: "sistema",
            metodo,
            recurso: "",
            codigo: Codigo::DenyPermission,
            detalhe: &format!(
                "pelo processo 9 (contido 0a1b2c3d): o manifesto nao declara {metodo}"
            ),
        });
    }
    a.gravar(R {
        titular: Titular::Serial,
        agente: "serial",
        chave: None,
        papel: "sistema",
        metodo: "net.connect",
        recurso: ECO,
        codigo: Codigo::Allow,
        detalhe: "",
    });
    ler(&mut m, &a);
    let regras: Vec<Regra> = m
        .incidentes
        .todos()
        .flat_map(|i| i.deteccoes.iter().map(|d| d.regra))
        .collect();
    assert!(regras.contains(&Regra::ForaDoManifesto), "{regras:?}");
    assert!(!regras.contains(&Regra::SondagemDePrivilegio), "{regras:?}");
    assert!(
        !regras.contains(&Regra::SaidaDepoisDeSondagem),
        "{regras:?}"
    );
    assert!(m.pedidos().is_empty());
}

/// O código cujo selo não confere é um contorno, de uma vez só: o NSF abre
/// o incidente, alto, e alerta — quem pediu pode ser a vítima de uma fonte
/// adulterada, e a contenção fica com quem tem a autoridade. O código sem
/// selo, e o de um editor em que o papel não confia, são a política
/// recusando o que se explica a quem pediu: nada a detectar.
#[test]
fn o_codigo_adulterado_alerta_e_nao_contem() {
    use politica::procedencia::{Falta, nao_confiado};
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    let caminho = "/armazem/compartilhado/codigo/vindo";
    let decisao = a.gravar(do_agente("user.run", caminho, Codigo::Allow, ""));
    for motivo in [
        String::from(Falta::SemSelo.motivo()),
        nao_confiado("outro"),
        String::from(Falta::EditorDesconhecido.motivo()),
    ] {
        a.gravar(do_agente(
            "user.run",
            caminho,
            Codigo::DenyPolicy,
            &format!("{motivo}; decisao {decisao}"),
        ));
    }
    ler(&mut m, &a);
    assert_eq!(
        m.incidentes.todos().count(),
        0,
        "a politica nao e incidente"
    );

    // Pelo processo que executa, depois da decisão do gate.
    let exec = a.gravar(do_agente("process.exec", caminho, Codigo::Allow, ""));
    let adulterado = a.gravar(do_agente(
        "process.exec",
        caminho,
        Codigo::DenyPolicy,
        &format!(
            "pelo processo 41 (instalador 0a1b2c3d): {}; decisao {exec}",
            Falta::NaoConfere.motivo()
        ),
    ));
    ler(&mut m, &a);
    let deteccoes: Vec<_> = m
        .incidentes
        .todos()
        .flat_map(|i| i.deteccoes.iter().cloned())
        .collect();
    let d = deteccoes
        .iter()
        .find(|d| d.regra == Regra::CodigoAdulterado)
        .expect("o codigo adulterado nao foi detectado");
    assert_eq!(d.registros, vec![adulterado]);
    assert_eq!(d.severidade, Severidade::Alta);
    assert_eq!(d.confianca, Confianca::Media);
    assert!(d.explicacao.contains("processo 41"), "{}", d.explicacao);
    // Alertar não é conter: nada pedido ao gate.
    assert!(m.pedidos().is_empty());
    // A segunda vez, da mesma identidade, não abre outra detecção.
    a.gravar(do_agente(
        "process.exec",
        caminho,
        Codigo::DenyPolicy,
        &format!("{}; decisao {exec}", Falta::NaoConfere.motivo()),
    ));
    ler(&mut m, &a);
    let quantas = m
        .incidentes
        .todos()
        .flat_map(|i| i.deteccoes.iter())
        .filter(|d| d.regra == Regra::CodigoAdulterado)
        .count();
    assert_eq!(quantas, 1);
}

/// Só um incidente alto leva a saída a ser contida. Três pedidos distintos
/// fora do alcance — o primeiro degrau — são de olhar: uma observação, sem
/// incidente, e a conexão que vem depois é só registrada. O mesmo pedido
/// recusado repetido nem isso é. Nada é pedido.
#[test]
fn so_o_incidente_alto_leva_a_contencao() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    for arquivo in ["agentes", "pessoas", "chaves"] {
        a.gravar(do_agente(
            "fs.read",
            &format!("/etc/duke/{arquivo}"),
            Codigo::DenyResource,
            "recurso fora do alcance do papel",
        ));
    }
    a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
    ler(&mut m, &a);
    assert_eq!(m.incidentes.todos().count(), 0);
    let obs: Vec<_> = m.observacoes().map(|d| (d.regra, d.confianca)).collect();
    assert_eq!(obs, [(Regra::ForaDoAlcance, Confianca::Baixa)]);
    assert!(m.pedidos().is_empty());
    // A lista diz a observação, e a explicação do registro também — com a
    // categoria e a confiança.
    let mut s = String::new();
    seguranca::relatorio::incidentes(&m, &mut JsonWriter::new(&mut s)).unwrap();
    assert!(
        s.starts_with(r#"{"incidents":[],"observations":[{"rule":"out-of-scope","category":"violation","severity":"medium","confidence":"low""#),
        "{s}"
    );
    let mut s = String::new();
    seguranca::relatorio::explicar(&m, 3, &mut JsonWriter::new(&mut s)).unwrap();
    assert!(
        s.contains(r#""detections":[{"rule":"out-of-scope","category":"violation","severity":"medium","confidence":"low""#),
        "{s}"
    );
    let mut s = String::new();
    seguranca::relatorio::status(&m, &mut JsonWriter::new(&mut s)).unwrap();
    assert!(
        s.contains(r#""health":{"state":"healthy","reasons":[],"backlog":0}"#),
        "{s}"
    );

    // O mesmo pedido, trinta vezes: nem observação.
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    for _ in 0..30 {
        a.gravar(do_agente(
            "fs.read",
            "/etc/duke/agentes",
            Codigo::DenyResource,
            "recurso fora do alcance do papel",
        ));
    }
    a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
    ler(&mut m, &a);
    assert_eq!(m.incidentes.todos().count(), 0);
    assert!(
        m.deteccoes().all(|d| d.regra != Regra::ForaDoAlcance),
        "{:?}",
        m.deteccoes().collect::<Vec<_>>()
    );
    assert!(m.pedidos().is_empty());
    // A repetição é contada — para a taxa de repetição —, e só.
    assert_eq!(
        (m.contadores.recusas, m.contadores.recusas_repetidas),
        (30, 29)
    );
    // E as métricas dizem o custo: quase toda recusa é repetição, e de
    // quem o NSF não tinha por ameaça.
    let mut s = String::new();
    seguranca::relatorio::metricas(&m, &mut JsonWriter::new(&mut s)).unwrap();
    assert!(
        s.contains(r#""decisions_seen":31,"denials_seen":30,"denials_repeated":29,"agent_retry_permille":966,"legitimate_denial_permille":967"#),
        "{s}"
    );
    assert!(s.contains(r#""events":{"used":31,"cap":512}"#), "{s}");
}

/// Detecção não é autorização: o motor só planeja `net.block` — restringir
/// —, nunca um comando que dê acesso, mude a política ou o papel.
#[test]
fn o_motor_so_pede_restricao() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    sondar(&mut a);
    for destino in [ECO, "udp:10.0.2.2:69", "udp:10.0.2.3:53"] {
        a.gravar(do_agente("net.connect", destino, Codigo::Allow, ""));
    }
    for _ in 0..5 {
        a.gravar(do_agente(
            "agent.ping",
            "",
            Codigo::DenyNotAuthenticated,
            "chave revogada",
        ));
    }
    ler(&mut m, &a);
    let pedidos = m.pedidos();
    assert!(!pedidos.is_empty());
    assert!(
        pedidos.iter().all(|p| p.metodo == "net.block"),
        "{pedidos:?}"
    );
    // E o status diz o que o motor contou.
    let mut s = String::new();
    seguranca::relatorio::status(&m, &mut JsonWriter::new(&mut s)).unwrap();
    assert!(s.contains(r#""service":"nsf""#), "{s}");
}

/// O detalhe de um pedido de um processo lançado pelo agente.
const DO_PROCESSO: &str = "pelo processo 9 (cliente 0a0b0c0d)";

/// A escada, e a recuperação respeitada. Quem sondou usa a rede de um
/// processo: o primeiro degrau é o destino, só para o processo. A ameaça
/// continua — o mesmo processo, outro destino, com a contenção valendo —:
/// o degrau seguinte é o processo inteiro, isolado, com o papel dele como
/// recurso. Um administrador o solta, pelo gate: o incidente fica
/// recuperado, e a rede seguinte do processo é só recomendação — o NSF
/// não contém de novo, nem com o risco ainda alto.
#[test]
fn a_escada_e_a_recuperacao() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    sondar(&mut a);
    a.gravar(do_agente("net.connect", ECO, Codigo::Allow, DO_PROCESSO));
    ler(&mut m, &a);
    let p = m.pedidos();
    assert_eq!(p.len(), 1);
    assert_eq!(
        (p[0].metodo.as_str(), p[0].params.as_str()),
        (
            "net.block",
            format!(r#"{{"to":"{ECO}","owner":"process:9"}}"#).as_str()
        )
    );
    m.desfecho(p[0].acao, br#"{"result":{"rule":1}}"#);
    nsf_pediu(&mut a, "net.block", ECO, Codigo::Allow);
    // O mesmo processo, outro destino: a contenção do destino não bastou.
    a.gravar(do_agente(
        "net.connect",
        "udp:10.0.2.2:69",
        Codigo::Allow,
        DO_PROCESSO,
    ));
    ler(&mut m, &a);
    let p = m.pedidos();
    assert_eq!(p.len(), 1, "{p:?}");
    assert_eq!(
        (p[0].metodo.as_str(), p[0].params.as_str()),
        ("process.isolate", r#"{"process":9}"#)
    );
    m.desfecho(p[0].acao, br#"{"result":{"process":9,"changed":true}}"#);
    let isolou = nsf_pediu(&mut a, "process.isolate", "process:9", Codigo::Allow);
    ler(&mut m, &a);
    let inc = m.incidentes.todos().next().unwrap();
    let acao = inc
        .acoes
        .iter()
        .find(|x| x.metodo == "process.isolate")
        .unwrap();
    assert_eq!(
        (
            &acao.estado,
            acao.decisao,
            acao.nivel,
            acao.recurso.as_str()
        ),
        (
            &EstadoDaAcao::Permitida,
            Some(isolou),
            Nivel::Reversivel,
            "process:9"
        )
    );
    assert!(m.deteccoes().all(|d| d.regra != Regra::AcaoSemPlano));

    // Um administrador solta o processo, pelo gate — e o processo usa a
    // rede de novo.
    a.gravar(R {
        titular: Titular::Administrador,
        agente: "adm",
        chave: None,
        papel: "administrador",
        metodo: "process.release",
        recurso: "process:9",
        codigo: Codigo::Allow,
        detalhe: "",
    });
    a.gravar(do_agente(
        "net.connect",
        "udp:10.0.2.3:53",
        Codigo::Allow,
        DO_PROCESSO,
    ));
    ler(&mut m, &a);
    assert!(
        m.pedidos().is_empty(),
        "recuperado, o NSF nao contem de novo"
    );
    let inc = m.incidentes.todos().next().unwrap();
    assert_eq!(inc.recuperada.as_deref(), Some("admin:adm"));
    assert!(
        inc.acoes
            .iter()
            .any(|x| x.metodo == "process.release" && x.estado == EstadoDaAcao::Observada)
    );
    assert_eq!(m.contadores.recuperadas, 1);
    // A contenção falsa, para quem mede: das duas que o gate permitiu ao
    // NSF, uma alguém desfez.
    let mut s = String::new();
    seguranca::relatorio::metricas(&m, &mut JsonWriter::new(&mut s)).unwrap();
    assert!(
        s.contains(r#""containments_allowed":2,"containments_recovered":1,"false_containment_permille":500"#),
        "{s}"
    );
    let rec = inc
        .acoes
        .iter()
        .find(|x| x.estado == EstadoDaAcao::Recomendada)
        .expect("a recomendacao para quem pode");
    assert!(
        rec.justificativa.contains("admin:adm desfez"),
        "{}",
        rec.justificativa
    );
}

/// A escada de um agente para no que a política dá ao NSF. O degrau
/// seguinte ao destino é suspender o agente — e o papel do NSF não tem
/// `agent.suspend`: o gate recusa, e o objetivo acaba. A recusa do pedido
/// do NSF não é sondagem do NSF: a resposta dele não passa pelas regras.
#[test]
fn a_escada_do_agente_para_na_politica() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    sondar(&mut a);
    a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
    ler(&mut m, &a);
    let p = m.pedidos();
    m.desfecho(p[0].acao, br#"{"result":{"rule":1}}"#);
    nsf_pediu(&mut a, "net.block", ECO, Codigo::Allow);
    a.gravar(do_agente(
        "net.connect",
        "udp:10.0.2.2:69",
        Codigo::Allow,
        "",
    ));
    ler(&mut m, &a);
    let p = m.pedidos();
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].metodo, "agent.suspend");
    assert_eq!(p[0].params, format!(r#"{{"key":"{}"}}"#, hex(&CHAVE)));
    m.desfecho(
        p[0].acao,
        br#"{"error":{"code":-32010,"message":"negado","data":"DENY_PERMISSION"}}"#,
    );
    nsf_pediu(
        &mut a,
        "agent.suspend",
        &format!("agent:{}", hex(&CHAVE)),
        Codigo::DenyPermission,
    );
    a.gravar(do_agente(
        "net.connect",
        "udp:10.0.2.3:53",
        Codigo::Allow,
        "",
    ));
    ler(&mut m, &a);
    assert!(m.pedidos().is_empty(), "depois da recusa, nada");
    let inc = m.incidentes.todos().next().unwrap();
    assert!(inc.contencao_negada);
    assert!(
        m.deteccoes().all(|d| d.principal != "service:nsf"),
        "a recusa do pedido do NSF virou deteccao do NSF: {:?}",
        m.deteccoes().collect::<Vec<_>>()
    );
}

/// O NSF degradado continua observando e alertando, e não contém sozinho:
/// com uma lacuna na leitura, a mesma saída depois da sondagem vira
/// recomendação, dizendo por quê. Passada a janela da lacuna, ele volta a
/// conter. O gate nunca soube de nada disso.
#[test]
fn degradado_so_recomenda() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    a.gravar(do_agente("agent.ping", "", Codigo::Allow, ""));
    ler(&mut m, &a);
    assert!(m.saude().saudavel(), "{:?}", m.saude());
    // Três registros que saem do anel antes da leitura.
    for _ in 0..3 {
        a.gravar(do_agente("agent.ping", "", Codigo::Allow, ""));
    }
    sondar(&mut a);
    a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
    let depois = format!(r#"{{"records":[{}]}}"#, a.registros[4..].join(","));
    m.ler_auditoria(depois.as_bytes()).unwrap();
    let saude = m.saude();
    assert_eq!(saude.nome(), "degraded");
    assert_eq!(saude.codigo(), Some("NSF_DEGRADED"));
    assert!(
        m.pedidos().is_empty(),
        "degradado, o NSF nao contem sozinho"
    );
    let mut s = String::new();
    seguranca::relatorio::status(&m, &mut JsonWriter::new(&mut s)).unwrap();
    assert!(
        s.contains(r#""health":{"state":"degraded","code":"NSF_DEGRADED","reasons":["audit-gap"]"#),
        "{s}"
    );
    let inc = m
        .incidentes
        .todos()
        .find(|i| i.principal.starts_with("agent:"))
        .expect("o incidente de quem sondou");
    let rec = inc.acoes.iter().find(|x| x.metodo == "net.block").unwrap();
    assert_eq!(rec.estado, EstadoDaAcao::Recomendada);
    assert!(
        rec.justificativa.contains("degradado"),
        "{}",
        rec.justificativa
    );
    // Passada a janela da lacuna, pelo tempo dos registros: saudável, e a
    // saída para outro destino é contida.
    a.ts += seguranca::motor::LACUNA_MS;
    a.gravar(do_agente(
        "net.connect",
        "udp:10.0.2.2:69",
        Codigo::Allow,
        "",
    ));
    ler(&mut m, &a);
    assert!(m.saude().saudavel(), "{:?}", m.saude());
    let p = m.pedidos();
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].metodo, "net.block");
}

/// O atraso também degrada: a evidência de um registro muito atrás da
/// cabeça da auditoria é velha — pode já ter havido uma recuperação que o
/// NSF não leu.
#[test]
fn o_atraso_degrada() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    m.cabeca_da_auditoria(10_000);
    sondar(&mut a);
    a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
    ler(&mut m, &a);
    let saude = m.saude();
    assert!(
        saude
            .motivos
            .contains(&seguranca::motor::Degradacao::Atraso),
        "{saude:?}"
    );
    assert!(m.pedidos().is_empty());
}

/// Sem cascata: o efeito de uma contenção não é uma ameaça nova. O contido
/// bate de novo no destino barrado — o gate deixa, o firewall barra —, e
/// o gate recusa o que o processo isolado pede: nenhum incidente novo,
/// nenhum pedido novo, nenhuma contenção repetida.
#[test]
fn sem_cascata() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    sondar(&mut a);
    a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
    ler(&mut m, &a);
    let p = m.pedidos();
    m.desfecho(p[0].acao, br#"{"result":{"rule":1}}"#);
    let bloqueou = nsf_pediu(&mut a, "net.block", ECO, Codigo::Allow);
    for _ in 0..20 {
        let pedida = a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
        a.gravar(do_agente(
            "net.connect",
            ECO,
            Codigo::DenyPolicy,
            &format!("bloqueado pelo firewall, regra 1; decisao {pedida}"),
        ));
    }
    for metodo in ["fs.read", "message.send", "process.exec"] {
        a.gravar(do_agente(metodo, "", Codigo::DenyContained, DO_PROCESSO));
    }
    ler(&mut m, &a);
    assert!(m.pedidos().is_empty());
    assert_eq!(
        m.incidentes.todos().count(),
        1,
        "{:?}",
        m.incidentes.todos().collect::<Vec<_>>()
    );
    let inc = m.incidentes.todos().next().unwrap();
    assert_eq!(
        inc.acoes
            .iter()
            .filter(|x| x.estado != EstadoDaAcao::Recomendada)
            .count(),
        1,
        "{:?}",
        inc.acoes
    );
    // Nada do que veio depois da contenção virou detecção.
    assert!(
        m.deteccoes()
            .all(|d| d.registros.iter().all(|r| *r < bloqueou)),
        "{:?}",
        m.deteccoes().collect::<Vec<_>>()
    );
}

/// Um agente legítimo muito ativo — centenas de pedidos permitidos, muitos
/// recursos, muitos processos — não é uma ameaça: nenhum incidente, nenhum
/// pedido. O que chamar a atenção do perfil é observação, de confiança
/// baixa.
#[test]
fn o_agente_ativo_nao_e_ameaca() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    for i in 0..400 {
        let recurso = format!("/projetos/compilacao/{i}.rs");
        a.gravar(do_agente("fs.read", &recurso, Codigo::Allow, ""));
        if i % 4 == 0 {
            a.gravar(do_agente(
                "user.run",
                "/programas/compilador",
                Codigo::Allow,
                &format!("processo {} lancado; decisao {}", 100 + i, a.seq),
            ));
        }
        if i % 50 == 0 {
            a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
        }
        if i == 200 {
            a.ts += 1;
        }
    }
    ler(&mut m, &a);
    assert_eq!(
        m.incidentes.todos().count(),
        0,
        "{:?}",
        m.incidentes.todos().collect::<Vec<_>>()
    );
    assert!(m.pedidos().is_empty());
    // A rajada de processos chamou a atenção — e ficou no nível 0.
    assert!(
        m.observacoes()
            .any(|d| d.regra == Regra::CadeiaDeProcessos && d.confianca == Confianca::Baixa)
    );
    assert!(m.observacoes().all(|d| d.confianca == Confianca::Baixa));
}

/// A pessoa incomum: primeiro uso de um programa, um destino nunca visto,
/// uma cópia grande, pedidos rápidos — tudo permitido. Incomum sem ser
/// malicioso: o perfil marca, e fica na observação.
#[test]
fn a_pessoa_incomum_nao_e_ameaca() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    let pessoa = |metodo: &'static str, recurso: String| R {
        titular: Titular::Pessoa,
        agente: "pessoa:00112233aabbccdd",
        chave: None,
        papel: "operador",
        metodo,
        recurso: Box::leak(recurso.into_boxed_str()),
        codigo: Codigo::Allow,
        detalhe: "",
    };
    // A rotina, devagar: a linha de base, com a taxa.
    for i in 0..40 {
        a.gravar(pessoa("fs.read", format!("/home/ana/{i}")));
        a.ts += 1_000;
    }
    // O dia diferente, depressa.
    a.gravar(pessoa("user.run", "/programas/instalador".to_string()));
    a.gravar(pessoa("net.connect", "tcp:10.0.2.77:443".to_string()));
    for i in 0..200 {
        a.gravar(pessoa("fs.write", format!("/home/ana/copia/{i}")));
    }
    ler(&mut m, &a);
    assert_eq!(m.incidentes.todos().count(), 0);
    assert!(m.pedidos().is_empty());
    assert!(
        m.observacoes()
            .any(|d| d.regra == Regra::ComportamentoAnomalo && d.confianca == Confianca::Baixa),
        "{:?}",
        m.observacoes().collect::<Vec<_>>()
    );
    assert!(m.observacoes().all(|d| d.confianca == Confianca::Baixa));
}

/// Cem conexões e um nome que ninguém resolveu antes: um agente que fala
/// muito com o destino que o papel dá, depois de resolvê-lo por um nome
/// novo. Volume não é ameaça, e um domínio novo que leva a um destino
/// permitido não é nada: nenhum incidente, nenhum pedido.
#[test]
fn cem_conexoes_e_um_nome_novo_nao_sao_ameaca() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    let dono = "process:11";
    let abriu = a.gravar(do_agente(
        "net.connect",
        "udp:10.0.2.53:53",
        Codigo::Allow,
        "pelo processo 11 (resolvedor 00000000)",
    ));
    ler(&mut m, &a);
    let resolucao = conversa(dono, "novo-dominio.duke", [10, 0, 2, 100], 1, abriu);
    assert_eq!(
        m.ler_captura("udp:10.0.2.53:53", resolucao.as_bytes()),
        Ok(2)
    );
    for _ in 0..100 {
        a.gravar(do_agente(
            "net.connect",
            ECO,
            Codigo::Allow,
            "pelo processo 11 (resolvedor 00000000)",
        ));
    }
    ler(&mut m, &a);
    assert_eq!(
        m.incidentes.todos().count(),
        0,
        "{:?}",
        m.incidentes.todos().collect::<Vec<_>>()
    );
    assert!(m.pedidos().is_empty());
    assert!(m.observacoes().all(|d| d.confianca == Confianca::Baixa));
}

/// A contenção é idempotente: a mesma — o mesmo comando, os mesmos
/// parâmetros —, já pedida ou valendo, não sai de novo.
#[test]
fn a_contencao_nao_sai_duas_vezes() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    sondar(&mut a);
    a.gravar(do_agente("net.connect", ECO, Codigo::Allow, DO_PROCESSO));
    ler(&mut m, &a);
    let p = m.pedidos();
    m.desfecho(p[0].acao, br#"{"result":{"rule":1}}"#);
    nsf_pediu(&mut a, "net.block", ECO, Codigo::Allow);
    // Dois destinos novos do mesmo processo na mesma volta: o processo é
    // isolado uma vez.
    a.gravar(do_agente(
        "net.connect",
        "udp:10.0.2.2:69",
        Codigo::Allow,
        DO_PROCESSO,
    ));
    a.gravar(do_agente(
        "net.connect",
        "udp:10.0.2.3:53",
        Codigo::Allow,
        DO_PROCESSO,
    ));
    ler(&mut m, &a);
    let p = m.pedidos();
    assert_eq!(
        p.iter().map(|x| x.metodo.as_str()).collect::<Vec<_>>(),
        ["process.isolate"]
    );
    assert_eq!(m.contadores.repetidas, 1);
}

/// A recusa do pedido do NSF não é comportamento do NSF. Três agentes
/// sondam e saem, cada um para um destino que o papel do NSF não alcança:
/// os três `net.block` são `DENY_RESOURCE` — três pedidos distintos fora
/// do alcance, que de qualquer outro seriam o primeiro degrau. Do NSF, são
/// a política dizendo não a ele: cada objetivo acaba, e nenhuma detecção
/// é do NSF.
#[test]
fn a_recusa_do_nsf_nao_e_comportamento_dele() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    for k in 1..=3u8 {
        let chave = [k; 32];
        let destino = format!("tcp:10.0.2.{}:7", 10 + k);
        for metodo in ["fs.read", "policy.show", "disk.read"] {
            a.gravar(R {
                chave: Some(chave),
                ..do_agente(metodo, "", Codigo::DenyPermission, "")
            });
        }
        a.gravar(R {
            chave: Some(chave),
            ..do_agente("net.connect", &destino, Codigo::Allow, "")
        });
        ler(&mut m, &a);
        let p = m.pedidos();
        assert_eq!(p.len(), 1);
        m.desfecho(
            p[0].acao,
            br#"{"error":{"code":-32010,"message":"negado","data":"DENY_RESOURCE"}}"#,
        );
        nsf_pediu(&mut a, "net.block", &destino, Codigo::DenyResource);
    }
    ler(&mut m, &a);
    assert_eq!(
        m.incidentes.todos().filter(|i| i.contencao_negada).count(),
        3
    );
    assert!(
        m.deteccoes().all(|d| d.principal != "service:nsf"),
        "{:?}",
        m.deteccoes().collect::<Vec<_>>()
    );
}

/// O que o serviço de hora faria: a auditoria grava a decisão — ou a
/// execução — do pedido dele.
fn hora_pediu(
    a: &mut Auditoria,
    metodo: &str,
    recurso: &str,
    codigo: Codigo,
    detalhe: &str,
) -> u64 {
    a.gravar(R {
        titular: Titular::Servico,
        agente: "hora",
        chave: None,
        papel: "tempo",
        metodo,
        recurso,
        codigo,
        detalhe,
    })
}

const FONTE: &str = "udp:10.0.2.2:5319";

/// Os pedidos do serviço de hora não são ações do NSF: nenhum vira "ação
/// sem plano", e nenhum abre incidente.
#[test]
fn o_servico_de_hora_nao_e_acao_do_nsf() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    for _ in 0..3 {
        hora_pediu(
            &mut a,
            "time.request",
            "bancada-a",
            Codigo::Allow,
            "pelo processo 9 (kernel)",
        );
        hora_pediu(
            &mut a,
            "net.connect",
            FONTE,
            Codigo::Allow,
            "pelo processo 9 (kernel)",
        );
        hora_pediu(
            &mut a,
            "net.block",
            FONTE,
            Codigo::Allow,
            "pelo processo 9 (kernel)",
        );
        hora_pediu(
            &mut a,
            "time.sync",
            "7",
            Codigo::Allow,
            "pelo processo 9 (kernel)",
        );
    }
    ler(&mut m, &a);
    assert_eq!(
        m.deteccoes().count(),
        0,
        "{:?}",
        m.deteccoes().collect::<Vec<_>>()
    );
    assert_eq!(m.incidentes.todos().count(), 0);
    assert!(
        m.pedidos().is_empty(),
        "o NSF nao pede nada pelo servico de hora"
    );
}

/// As recusas do serviço de hora — a política tirou `time.sync` do papel
/// dele — não são sondagem, e a saída dele para a fonte depois delas não
/// é a escada de ninguém: o NSF não pede contenção, nem bloqueio da fonte.
#[test]
fn as_recusas_do_servico_de_hora_nao_sao_sondagem() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    for metodo in ["time.request", "time.sync", "fs.read", "policy.show"] {
        hora_pediu(
            &mut a,
            metodo,
            "",
            Codigo::DenyPermission,
            "pelo processo 9 (kernel)",
        );
    }
    hora_pediu(
        &mut a,
        "net.connect",
        FONTE,
        Codigo::Allow,
        "pelo processo 9 (kernel)",
    );
    ler(&mut m, &a);
    assert_eq!(m.incidentes.todos().count(), 0);
    assert!(m.pedidos().is_empty());
    assert!(
        m.contadores.recusas >= 4,
        "as recusas ainda contam: {}",
        m.contadores.recusas
    );
}

/// O tempo que a auditoria conta: os vereditos de cada entrega pela
/// classe, e o estado e as marcas da última rodada que fechou — de
/// qualquer titular.
#[test]
fn o_tempo_pela_auditoria() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    let processo = "pelo processo 9 (kernel)";
    hora_pediu(
        &mut a,
        "time.sync",
        "bancada-a 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        Codigo::Allow,
        &format!("{processo}: aceita midp 1791158400 radi 5 rtt 12; decisao 3"),
    );
    hora_pediu(
        &mut a,
        "time.sync",
        "bancada-b 00",
        Codigo::DenyCredential,
        &format!("{processo}: recusada assinatura_da_resposta 1/4; decisao 5"),
    );
    hora_pediu(
        &mut a,
        "time.sync",
        "bancada-b 01",
        Codigo::DenyReplay,
        &format!("{processo}: recusada nonce 2/4; decisao 6"),
    );
    hora_pediu(
        &mut a,
        "time.sync",
        "bancada-c",
        Codigo::Error,
        &format!("{processo}: sem_resposta; decisao 8"),
    );
    // Uma entrega para um id que não existe não é resposta de fonte.
    hora_pediu(
        &mut a,
        "time.sync",
        "id 99",
        Codigo::InvalidArgument,
        &format!("{processo}: nenhum pedido de hora aberto com este id; decisao 9"),
    );
    let fechou = hora_pediu(
        &mut a,
        "time.sync",
        "civil 1791158400000>1791158400000 logico 1791158400>1791158400 rtc>sincronizado divergente",
        Codigo::Allow,
        &format!("{processo}: r1 acordo 2/2 d+1 u5012 nada; decisao 8"),
    );
    // A decisão do gate, sem execução, não conta.
    hora_pediu(
        &mut a,
        "time.sync",
        "civil 1>2 logico 3>4 rtc>vencido",
        Codigo::Allow,
        processo,
    );
    ler(&mut m, &a);
    let t = &m.tempo;
    assert_eq!(t.estado.as_deref(), Some("sincronizado"));
    assert!(t.divergente && !t.pendente && !t.adiantado);
    assert_eq!(t.rodadas, 1);
    assert_eq!(t.ultima_rodada, Some(fechou));
    assert_eq!(
        (
            t.aceitas,
            t.assinatura_invalida,
            t.repetidas,
            t.malformadas,
            t.sem_resposta
        ),
        (1, 1, 1, 0, 1)
    );
    // Um administrador confirma um salto: conta, e o NSF não faz nada com
    // isso.
    a.gravar(R {
        titular: Titular::Administrador,
        agente: "raiz",
        chave: None,
        papel: "administrador",
        metodo: "time.confirm",
        recurso: "salto +15000 r1 civil 1>2 logico 3>4",
        codigo: Codigo::Allow,
        detalhe: "prova conferida; executada; permissao time.confirm; desafio 4",
    });
    ler(&mut m, &a);
    assert_eq!(m.tempo.saltos_confirmados, 1);
    assert!(m.pedidos().is_empty());
    let mut s = String::new();
    seguranca::relatorio::status(&m, &mut JsonWriter::new(&mut s)).unwrap();
    let tempo = Json(s.as_bytes())
        .member("time")
        .expect("status com o tempo");
    assert_eq!(
        tempo.member("state").and_then(|v| v.as_str()),
        Some("sincronizado")
    );
    assert_eq!(
        tempo.member("confirmed_jumps").and_then(|v| v.as_u64()),
        Some(1)
    );
}

/// O fechamento de uma rodada do serviço de hora, como o kernel o grava:
/// o civil, o lógico, os estados e as marcas no recurso; a rodada, o
/// desfecho e o efeito no detalhe.
fn fechar(a: &mut Auditoria, recurso: &str, codigo: Codigo, detalhe: &str) -> u64 {
    hora_pediu(
        a,
        "time.sync",
        &format!("civil {recurso}"),
        codigo,
        &format!("{detalhe}; decisao 2"),
    )
}

/// O veredito da resposta de uma fonte.
fn veredito(a: &mut Auditoria, fonte: &str, codigo: Codigo, detalhe: &str) -> u64 {
    hora_pediu(
        a,
        "time.sync",
        &format!("{fonte} 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
        codigo,
        &format!("{detalhe}; decisao 2"),
    )
}

/// As detecções de tempo, pela regra, na ordem em que vieram.
fn do_relogio(m: &Motor) -> Vec<(Regra, Severidade, Confianca)> {
    let mut v: Vec<(u64, Regra, Severidade, Confianca)> = m
        .deteccoes()
        .filter(|d| d.principal == seguranca::tempo::PRINCIPAL)
        .map(|d| {
            (
                d.registros[d.registros.len() - 1],
                d.regra,
                d.severidade,
                d.confianca,
            )
        })
        .collect();
    v.sort();
    v.into_iter().map(|(_, r, s, c)| (r, s, c)).collect()
}

/// O `time` do `security.status`.
fn tempo_do_status(m: &Motor) -> String {
    let mut s = String::new();
    seguranca::relatorio::status(m, &mut JsonWriter::new(&mut s)).unwrap();
    String::from_utf8_lossy(Json(s.as_bytes()).member("time").unwrap().0).into_owned()
}

/// As regras de tempo do desenho (§9.3), cada uma uma vez por acontecimento,
/// do relógio — e não do serviço de hora —, e nenhuma pede nada: só
/// registram e recomendam. O salto pendente recomenda o `time.confirm` da
/// rodada a um administrador, e nunca o pede.
#[test]
fn as_regras_de_tempo() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    // Três rodadas sem fonte nenhuma: a hora nunca foi autenticada.
    for r in 1..=3 {
        fechar(
            &mut a,
            "1000>1100 logico 10>10 rtc>rtc",
            Codigo::Error,
            &format!("r{r} sem_quorum 0/3 sem_acordo"),
        );
    }
    // A assinatura de uma fonte não fecha: uma vez, até ela ser aceita de
    // novo.
    for _ in 0..2 {
        veredito(
            &mut a,
            "bancada-b",
            Codigo::DenyCredential,
            "recusada assinatura_da_resposta 1/4",
        );
    }
    veredito(
        &mut a,
        "bancada-b",
        Codigo::Allow,
        "aceita midp 1 radi 5 rtt 12",
    );
    veredito(
        &mut a,
        "bancada-b",
        Codigo::DenyCredential,
        "recusada assinatura_da_delegacao 1/4",
    );
    // A primeira sincronização corrige o RTC uma hora: o salto que o
    // envelope explica — gravidade alta, confiança baixa.
    fechar(
        &mut a,
        "1000>3601000 logico 10>3601 rtc>sincronizado",
        Codigo::Allow,
        "r4 acordo 3/3 d+3600000 u980 salto",
    );
    // Um salto além do envelope.
    fechar(
        &mut a,
        "3700000>4300000 logico 3700>4300 sincronizado>sincronizado",
        Codigo::Allow,
        "r5 acordo 3/3 d+600000 u980 salto_alem",
    );
    // O pendente: duas rodadas, uma detecção, com a rodada.
    let pendente = fechar(
        &mut a,
        "4400000>4400000 logico 4400>4400 sincronizado>sincronizado pendente",
        Codigo::Conflict,
        "r6 acordo 3/3 d+172800000 u980 pendente",
    );
    fechar(
        &mut a,
        "4500000>4500000 logico 4500>4500 sincronizado>sincronizado pendente",
        Codigo::Conflict,
        "r7 acordo 3/3 d+172800000 u980 pendente",
    );
    // A fonte divergente: a evidência são os vereditos da rodada.
    let mut da_rodada = Vec::new();
    for f in ["bancada-a", "bancada-b", "bancada-c"] {
        da_rodada.push(veredito(
            &mut a,
            f,
            Codigo::Allow,
            "aceita midp 1 radi 5 rtt 12",
        ));
    }
    let divergente = fechar(
        &mut a,
        "4600000>4600005 logico 4600>4600 sincronizado>sincronizado divergente",
        Codigo::Allow,
        "r8 acordo 2/3 d+5 u980 nada",
    );
    fechar(
        &mut a,
        "4700000>4700000 logico 4700>4700 sincronizado>sincronizado divergente",
        Codigo::Allow,
        "r9 acordo 2/3 d+0 u980 nada",
    );
    // Vencida: a entrada no estado, uma vez.
    for (r, estados) in [(10, "holdover>vencido"), (11, "vencido>vencido")] {
        fechar(
            &mut a,
            &format!("4800000>4800000 logico 4800>4800 {estados}"),
            Codigo::Error,
            &format!("r{r} sem_quorum 0/3 sem_acordo"),
        );
    }
    // O lógico parado à frente do civil.
    a.passo = 0;
    fechar(
        &mut a,
        "4900000>4780000 logico 4900>4900 vencido>sincronizado adiantado",
        Codigo::Allow,
        "r12 acordo 3/3 d-120000 u980 salto",
    );
    ler(&mut m, &a);

    use Confianca as C;
    use Severidade as S;
    assert_eq!(
        do_relogio(&m),
        [
            (Regra::HoraNaoAutenticada, S::Media, C::Baixa),
            (Regra::AssinaturaDaFonte, S::Alta, C::Media),
            (Regra::AssinaturaDaFonte, S::Alta, C::Media),
            (Regra::SaltoDoRelogio, S::Alta, C::Baixa),
            (Regra::SaltoAlemDoEnvelope, S::Alta, C::Media),
            (Regra::SaltoPendente, S::Alta, C::Media),
            (Regra::FonteDivergente, S::Media, C::Media),
            (Regra::HoraNaoAutenticada, S::Media, C::Media),
            (Regra::SaltoDoRelogio, S::Media, C::Baixa),
            (Regra::LogicoParado, S::Media, C::Media),
        ]
    );
    let divergencia = m
        .deteccoes()
        .find(|d| d.regra == Regra::FonteDivergente)
        .unwrap();
    da_rodada.push(divergente);
    assert_eq!(divergencia.registros, da_rodada);
    // Nada pedido; o incidente é do relógio, e não do serviço de hora.
    assert!(m.pedidos().is_empty());
    assert!(m.incidentes.todos().all(|i| i.principal == "clock"));
    let inc = m.incidentes.todos().next().unwrap();
    // A recomendação do pendente: o `time.confirm` da rodada, por um
    // administrador com prova.
    let confirmar: Vec<_> = inc
        .acoes
        .iter()
        .filter(|x| x.params.contains("time.confirm"))
        .collect();
    assert_eq!(confirmar.len(), 1, "{:?}", inc.acoes);
    assert_eq!(confirmar[0].estado, EstadoDaAcao::Recomendada);
    assert_eq!(confirmar[0].nivel, Nivel::Forte);
    assert_eq!(confirmar[0].metodo, "admin.execute");
    assert_eq!(
        confirmar[0].params,
        r#"{"command":"time.confirm","round":6}"#
    );
    assert_eq!(confirmar[0].origem, pendente);
    assert!(
        inc.acoes
            .iter()
            .all(|x| x.estado == EstadoDaAcao::Recomendada)
    );
    let t = tempo_do_status(&m);
    assert!(t.contains(r#""logical_stopped":true"#), "{t}");
    assert!(t.contains(r#""rate_containment":"suspended""#), "{t}");
}

/// Uma confirmação que leva o civil para trás do lógico para o lógico — e
/// ele volta a andar no primeiro carimbo depois daquele em que parou.
#[test]
fn a_confirmacao_que_para_o_logico() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    // 2026-10-19, em ms: o lógico de uma máquina de verdade.
    a.ts = 1_792_368_000_000;
    a.passo = 0;
    let parado = a.ts / 1000;
    a.gravar(R {
        titular: Titular::Administrador,
        agente: "raiz",
        chave: None,
        papel: "administrador",
        metodo: "time.confirm",
        recurso: &format!(
            "salto -600000 r3 civil {}>{} logico {parado}>{parado}",
            parado * 1000,
            (parado - 600) * 1000
        ),
        codigo: Codigo::Allow,
        detalhe: "prova conferida; executada; permissao time.confirm; desafio 4",
    });
    ler(&mut m, &a);
    assert_eq!(
        do_relogio(&m),
        [(Regra::LogicoParado, Severidade::Media, Confianca::Media)]
    );
    assert!(m.tempo.parado());
    // O mesmo carimbo: parado ainda.
    a.gravar(do_agente("agent.ping", "", Codigo::Allow, ""));
    ler(&mut m, &a);
    assert!(m.tempo.parado());
    // Um carimbo depois: andando.
    a.passo = 1000;
    a.gravar(do_agente("agent.ping", "", Codigo::Allow, ""));
    ler(&mut m, &a);
    assert!(!m.tempo.parado());
    assert!(tempo_do_status(&m).contains(r#""rate_containment":"active""#));
}

const OUTRO: &str = "tcp:10.0.2.100:8";

/// Para o lógico: o fechamento com a marca, e os carimbos parados.
fn parar_o_logico(a: &mut Auditoria) {
    a.passo = 0;
    let s = a.ts / 1000;
    fechar(
        a,
        &format!(
            "{}>{} logico {s}>{s} rtc>sincronizado adiantado",
            s * 1000 + 120_000,
            s * 1000
        ),
        Codigo::Allow,
        "r2 acordo 3/3 d-120000 u980 salto",
    );
}

/// O desenho do tempo (§9.3): com o lógico parado, as detecções continuam
/// registradas, e a contenção automática por taxa fica suspensa. A sondagem
/// lenta cabe na janela só porque os carimbos não andam: ela é registrada,
/// diz isso, e a saída depois dela vira recomendação, com o motivo. E o que
/// a janela contou parada não sustenta contenção nem depois de o lógico
/// voltar a andar.
#[test]
fn com_o_logico_parado_a_contencao_por_taxa_fica_suspensa() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    parar_o_logico(&mut a);
    sondar(&mut a);
    a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
    ler(&mut m, &a);
    assert!(m.tempo.parado());
    let sondagem = m
        .deteccoes()
        .find(|d| d.regra == Regra::SondagemDePrivilegio)
        .expect("a sondagem continua registrada");
    assert!(sondagem.logico_parado);
    assert!(sondagem.explicacao.contains("tempo logico parado"));
    assert!(
        m.deteccoes()
            .any(|d| d.regra == Regra::SaidaDepoisDeSondagem && d.confianca == Confianca::Alta),
        "a saida depois da sondagem continua registrada"
    );
    assert!(
        m.pedidos().is_empty(),
        "parado, a contencao por taxa nao sai"
    );
    let dono = format!("agent:{}", hex(&CHAVE));
    let inc = m.incidentes.vivo_de(0, &dono).unwrap();
    let bloqueio = inc.acoes.iter().find(|x| x.metodo == "net.block").unwrap();
    assert_eq!(bloqueio.estado, EstadoDaAcao::Recomendada);
    assert!(
        bloqueio.justificativa.contains(seguranca::resposta::PARADO),
        "{}",
        bloqueio.justificativa
    );

    // De volta a andar: a janela contada parada ainda não sustenta a
    // contenção.
    a.passo = 100;
    a.ts += 5_000;
    a.gravar(do_agente("net.connect", OUTRO, Codigo::Allow, ""));
    ler(&mut m, &a);
    assert!(!m.tempo.parado());
    assert!(
        m.pedidos().is_empty(),
        "a janela contada parada nao contem depois"
    );
    let inc = m.incidentes.vivo_de(0, &dono).unwrap();
    let outro = inc
        .acoes
        .iter()
        .find(|x| x.recurso == OUTRO)
        .expect("a saida para o outro destino tem a recomendacao");
    assert_eq!(outro.estado, EstadoDaAcao::Recomendada);
    assert!(
        outro
            .justificativa
            .contains(seguranca::resposta::CONTADA_PARADA),
        "{}",
        outro.justificativa
    );
}

/// O que não é janela não se suspende: com o lógico parado, o teto de um
/// administrador exercido — um contorno, uma vez basta — ainda leva a saída
/// depois dele à contenção.
#[test]
fn parado_o_contorno_ainda_contem() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    parar_o_logico(&mut a);
    a.gravar(do_agente(
        "policy.write",
        "",
        Codigo::DenyRole,
        "acima do teto do administrador",
    ));
    a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
    ler(&mut m, &a);
    assert!(m.tempo.parado());
    let pedidos = m.pedidos();
    assert_eq!(pedidos.len(), 1, "o contorno contem, parado ou nao");
    assert_eq!(pedidos[0].metodo, "net.block");
}

/// De volta a andar, a janela conta de novo: a sondagem rápida, com os
/// carimbos andando, leva a saída depois dela à contenção.
#[test]
fn de_volta_a_andar_a_janela_contem() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    parar_o_logico(&mut a);
    a.passo = 100;
    a.ts += 1_000;
    sondar(&mut a);
    a.gravar(do_agente("net.connect", ECO, Codigo::Allow, ""));
    ler(&mut m, &a);
    assert!(!m.tempo.parado());
    let pedidos = m.pedidos();
    assert_eq!(pedidos.len(), 1);
    assert_eq!(pedidos[0].metodo, "net.block");
    assert!(
        m.deteccoes()
            .filter(|d| d.regra == Regra::SondagemDePrivilegio)
            .all(|d| !d.logico_parado)
    );
}

/// A declaração de um programa, pela auditoria: a alegação no recurso, e a
/// conexão e o destino que o kernel escreveu no detalhe. O motor a lê como
/// alegação — o tipo dela, a âncora no grafo, a proveniência do processo —,
/// e a verificação que o programa diz que falhou é só observada: sem
/// incidente, sem pedido, sem recomendação. O que se alega não vira
/// destino, processo nem recurso no grafo: só a âncora, que é do kernel.
#[test]
fn a_declaracao_e_alegacao_observada() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    a.gravar(do_agente("user.run", "/programas/x/icp", Codigo::Allow, ""));
    a.gravar(do_agente(
        "user.run",
        "/programas/x/icp",
        Codigo::Allow,
        "processo 21 lancado; decisao 1",
    ));
    const PELO: &str = "pelo processo 21 (icp 0a0b0c0d)";
    const GATEWAY: &str = "tcp:10.0.2.100:4943";
    a.gravar(do_agente("net.connect", GATEWAY, Codigo::Allow, PELO));
    let declarar = |a: &mut Auditoria, recurso: &str, ancora: &str| {
        let d = a.gravar(do_agente("audit.declare", "", Codigo::Allow, PELO));
        a.gravar(do_agente(
            "audit.declare",
            recurso,
            Codigo::Allow,
            &format!("{PELO}: {ancora}; decisao {d}"),
        ))
    };
    let ancorada = format!("conexao 3 {GATEWAY}");
    let verificada = declarar(&mut a, "icp.query alvo/ola verified", &ancorada);
    let falhas: Vec<u64> = (0..3)
        .map(|_| declarar(&mut a, "icp.query alvo/ola unverified_signature", &ancorada))
        .collect();
    // Uma que alega o que o kernel não confere — um destino, um processo
    // que nasceu —: continua alegação.
    let enganosa = declarar(
        &mut a,
        "x.y tcp:10.0.2.100:7 processo_9_lancado",
        "sem conexao",
    );
    ler(&mut m, &a);

    let e = m.evento(verificada).expect("a declaracao nao foi lida");
    assert_eq!(e.tipo, Tipo::Declaracao { conexao: Some(3) });
    assert_eq!(e.recurso, "", "a alegacao ficou no recurso do evento");
    assert_eq!(e.alegacao.as_deref(), Some("icp.query alvo/ola verified"));
    let d = e.declaracao().unwrap();
    assert_eq!(
        (d.evento.as_str(), d.assunto.as_str(), d.desfecho.as_str()),
        ("icp.query", "alvo/ola", "verified")
    );
    assert_eq!(d.ancora, Some(Ancora::Conexao(3, GATEWAY.to_string())));
    // O grafo: o processo declarou; a declaração, sobre o destino do kernel.
    let vizinhos = m.grafo.vizinhos(&No::Declaracao(verificada));
    assert!(
        vizinhos.contains(&(Aresta::Declarou, No::Processo { epoca: 0, fio: 21 }, false)),
        "{vizinhos:?}"
    );
    assert!(
        vizinhos.contains(&(Aresta::Sobre, No::Destino(GATEWAY.to_string()), true)),
        "{vizinhos:?}"
    );
    // A enganosa: nem destino, nem nascimento, nem recurso.
    assert!(
        m.grafo
            .vizinhos(&No::Declaracao(enganosa))
            .iter()
            .all(|(a, _, _)| *a == Aresta::Declarou)
    );
    assert!(
        m.grafo
            .vizinhos(&No::Destino("tcp:10.0.2.100:7".into()))
            .is_empty()
    );
    assert!(m.grafo.processo(0, 9).is_none());
    // O perfil de quem declarou não conta a alegação como o que ele tocou.
    let perfil = m
        .ueba
        .perfil(&format!("agent:{}", hex(&CHAVE)))
        .expect("o perfil do agente");
    assert!(perfil.recursos.contains(GATEWAY));
    assert!(
        perfil
            .recursos
            .iter()
            .all(|r| !r.contains("icp.query") && !r.contains("x.y")),
        "{:?}",
        perfil.recursos
    );
    // A regra: observada, sem incidente nem pedido.
    let observadas: Vec<_> = m
        .observacoes()
        .filter(|d| d.regra == Regra::VerificacaoDeclaradaFalhou)
        .collect();
    assert_eq!(observadas.len(), 2, "{observadas:?}");
    assert!(
        observadas
            .iter()
            .all(|d| d.confianca == Confianca::Baixa && d.severidade == Severidade::Media)
    );
    assert_eq!(observadas[0].registros, [falhas[0]]);
    assert_eq!(observadas[1].registros, falhas);
    assert_eq!(m.incidentes.todos().count(), 0);
    assert!(m.pedidos().is_empty());
    // A proveniência do processo diz as declarações, com as duas partes.
    let mut s = String::new();
    seguranca::relatorio::proveniencia(&m, 0, 21, &mut JsonWriter::new(&mut s)).unwrap();
    assert!(s.contains(r#""declarations":[{"record":"#), "{s}");
    assert!(
        s.contains(r#""claimed":{"event":"icp.query","subject":"alvo/ola","outcome":"verified"}"#),
        "{s}"
    );
    assert!(
        s.contains(&format!(r#""anchor":{{"connection":3,"to":"{GATEWAY}"}}"#)),
        "{s}"
    );
}

/// A declaração ancorada na decisão de uma assinatura do mesmo processo:
/// o grafo liga a declaração à decisão — o fato do kernel —, e a
/// proveniência diz a decisão e o método dela. A assinatura pedida depois
/// com a chave anulada, que o kernel recusou, é só observada: sem
/// incidente, sem pedido.
#[test]
fn a_declaracao_ancorada_na_assinatura() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    a.gravar(do_agente("user.run", "/programas/x/icp", Codigo::Allow, ""));
    a.gravar(do_agente(
        "user.run",
        "/programas/x/icp",
        Codigo::Allow,
        "processo 21 lancado; decisao 1",
    ));
    const PELO: &str = "pelo processo 21 (icp 0a0b0c0d)";
    let assinou = a.gravar(do_agente("key.sign", "chave:bancada", Codigo::Allow, PELO));
    a.gravar(do_agente(
        "key.sign",
        &format!("chave:bancada ic-request {}", "5a".repeat(32)),
        Codigo::Allow,
        &format!("{PELO}: assinatura ed25519 ab12cd34; decisao {assinou}"),
    ));
    let pedida = a.gravar(do_agente("audit.declare", "", Codigo::Allow, PELO));
    let declarada = a.gravar(do_agente(
        "audit.declare",
        "icp.update alvo/quem verified",
        Codigo::Allow,
        &format!("{PELO}: ancorada em {assinou} key.sign; decisao {pedida}"),
    ));
    let pediu = a.gravar(do_agente("key.sign", "chave:bancada", Codigo::Allow, PELO));
    let recusada = a.gravar(do_agente(
        "key.sign",
        "chave:bancada",
        Codigo::InvalidArgument,
        &format!("{PELO}: a chave foi anulada; decisao {pediu}"),
    ));
    ler(&mut m, &a);

    let e = m.evento(declarada).expect("a declaracao nao foi lida");
    assert_eq!(e.tipo, Tipo::Declaracao { conexao: None });
    assert_eq!(
        e.declaracao().unwrap().ancora,
        Some(Ancora::Decisao(assinou, "key.sign".to_string()))
    );
    let vizinhos = m.grafo.vizinhos(&No::Declaracao(declarada));
    assert!(
        vizinhos.contains(&(Aresta::Sobre, No::Decisao(assinou), true)),
        "{vizinhos:?}"
    );
    let mut s = String::new();
    seguranca::relatorio::proveniencia(&m, 0, 21, &mut JsonWriter::new(&mut s)).unwrap();
    assert!(
        s.contains(&format!(
            r#""anchor":{{"decision":{assinou},"method":"key.sign"}}"#
        )),
        "{s}"
    );
    let observadas: Vec<_> = m
        .observacoes()
        .filter(|d| d.regra == Regra::ChaveMortaUsada)
        .collect();
    assert_eq!(observadas.len(), 1, "{observadas:?}");
    assert_eq!(observadas[0].registros, [recusada]);
    assert_eq!(m.incidentes.todos().count(), 0);
    assert!(m.pedidos().is_empty());
}

/// Com um incidente vivo do mesmo principal, a verificação que o programa
/// diz que falhou entra nele como detecção — a evidência de uma alegação —,
/// e só: a alegação não vira recurso afetado, a severidade e a confiança do
/// incidente não sobem por ela, e nenhuma ação nova é planejada — nem para
/// o destino em que ela se ancorou.
#[test]
fn a_declaracao_no_incidente_vivo() {
    let mut a = Auditoria::nova();
    let mut m = Motor::novo();
    sondar(&mut a);
    ler(&mut m, &a);
    assert!(m.pedidos().is_empty(), "sondar nao leva a pedido nenhum");
    let antes = m
        .incidentes
        .todos()
        .next()
        .cloned()
        .expect("a sondagem abre um incidente");
    let ancorada = format!("conexao 3 {ECO}");
    let falhas: Vec<u64> = (0..3)
        .map(|_| {
            let d = a.gravar(do_agente("audit.declare", "", Codigo::Allow, ""));
            a.gravar(do_agente(
                "audit.declare",
                "icp.query alvo/ola unverified_signature",
                Codigo::Allow,
                &format!("{ancorada}; decisao {d}"),
            ))
        })
        .collect();
    ler(&mut m, &a);
    let inc = m.incidentes.get(antes.id).expect("o incidente vivo");
    let delas: Vec<_> = inc
        .deteccoes
        .iter()
        .filter(|d| d.regra == Regra::VerificacaoDeclaradaFalhou)
        .collect();
    assert_eq!(delas.len(), 2, "{delas:?}");
    assert_eq!(delas[1].registros, falhas);
    assert!(falhas.iter().all(|f| inc.registros.contains(f)));
    assert_eq!(
        inc.recursos, antes.recursos,
        "a alegacao virou recurso afetado"
    );
    assert_eq!(
        (inc.severidade, inc.confianca),
        (antes.severidade, antes.confianca)
    );
    assert_eq!(inc.acoes.len(), antes.acoes.len());
    assert!(m.pedidos().is_empty(), "a alegacao levou a um pedido");
    assert_eq!(m.incidentes.todos().count(), 1);
}
