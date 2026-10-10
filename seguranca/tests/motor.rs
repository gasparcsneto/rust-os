//! O motor de ponta a ponta, no hospedeiro: uma auditoria escrita aqui, como
//! o `audit.tail` do kernel a escreve, com os elos feitos pela mesma conta,
//! e o que o motor detecta, abre, pede e verifica.

use politica::Codigo;
use politica::auditoria::{Evento as DaCadeia, Titular, elo};
use protocolo::json::{Json, JsonWriter};
use seguranca::Motor;
use seguranca::evento::Severidade;
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
            registros: Vec::new(),
        }
    }

    fn gravar(&mut self, r: R) -> u64 {
        self.seq += 1;
        self.ts += 100;
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
