//! O modelo de evento de segurança, e a leitura dos registros da auditoria.
//!
//! # De onde vem cada campo
//!
//! Do registro que o gate escreveu, lido pelo `audit.tail` — e só dele: o
//! NSF não tem outra fonte do que aconteceu. O registro diz quem (titular,
//! sessão, identificador, chave, papel), o quê (método e recurso), a decisão
//! (o código) e o detalhe; o detalhe diz, num formato que o kernel escreve
//! sempre igual, o processo que pediu (`pelo processo N (programa)`), a
//! decisão de que uma execução é execução (`decisao D`), o filho que nasceu
//! e a conexão que caiu.
//!
//! # A cadeia refeita
//!
//! Cada registro traz o elo dele e o do anterior. A leitura refaz o elo com
//! a mesma conta da auditoria (`politica::auditoria::elo`): um registro que
//! não a refaz não foi escrito pelo gate como está — e o monitor de
//! invariantes o diz. O NSF não confia no que lê só porque leu pelo gate.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use politica::Codigo;
pub use politica::auditoria::Titular;
use protocolo::json::Json;

use crate::util;

/// A gravidade de um evento, de uma detecção, de um incidente.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severidade {
    Info,
    Baixa,
    Media,
    Alta,
    Critica,
}

impl Severidade {
    /// O nome, como as consultas o escrevem.
    pub const fn nome(self) -> &'static str {
        match self {
            Severidade::Info => "info",
            Severidade::Baixa => "low",
            Severidade::Media => "medium",
            Severidade::Alta => "high",
            Severidade::Critica => "critical",
        }
    }
}

/// O maior texto de um campo lido: o recurso e o método da auditoria têm
/// 128 bytes, o detalhe 96; uma chave em hexadecimal, 64.
const MAIOR_CAMPO: usize = 256;

/// Um registro da auditoria, como `audit.tail` o mostra.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registro {
    pub seq: u64,
    pub ts_ms: u64,
    pub titular: Titular,
    pub sessao: u8,
    pub sessao_de_pessoa: Option<[u8; 8]>,
    pub agente: String,
    pub chave: Option<[u8; 32]>,
    pub papel: String,
    pub metodo: String,
    pub recurso: String,
    pub codigo: Codigo,
    pub parametros: [u8; 32],
    pub detalhe: String,
    pub anterior: [u8; 32],
    pub elo: [u8; 32],
}

impl Registro {
    /// Um registro do `records` de `audit.tail`.
    pub fn do_json(o: Json) -> Result<Registro, &'static str> {
        let texto = |nome: &str| util::texto(o.member(nome), MAIOR_CAMPO);
        let numero = |nome: &str| util::numero(o.member(nome));
        let hex32 = |nome: &str| texto(nome).and_then(|t| util::de_hex::<32>(&t));
        let opcional = |nome: &str| o.member(nome).filter(|v| !v.is_null());
        Ok(Registro {
            seq: numero("seq").ok_or("registro sem seq")?,
            ts_ms: numero("ts_ms").ok_or("registro sem ts_ms")?,
            titular: texto("holder")
                .and_then(|t| Titular::de_nome(&t))
                .ok_or("registro com titular desconhecido")?,
            sessao: numero("session")
                .and_then(|s| u8::try_from(s).ok())
                .ok_or("registro sem sessao")?,
            sessao_de_pessoa: match opcional("person_session") {
                None => None,
                Some(v) => Some(
                    util::texto(Some(v), MAIOR_CAMPO)
                        .and_then(|t| util::de_hex::<8>(&t))
                        .ok_or("sessao de pessoa invalida")?,
                ),
            },
            agente: texto("agent").ok_or("registro sem agent")?,
            chave: match opcional("key") {
                None => None,
                Some(v) => Some(
                    util::texto(Some(v), MAIOR_CAMPO)
                        .and_then(|t| util::de_hex::<32>(&t))
                        .ok_or("chave invalida")?,
                ),
            },
            papel: texto("role").ok_or("registro sem role")?,
            metodo: texto("method").ok_or("registro sem method")?,
            recurso: texto("resource").ok_or("registro sem resource")?,
            codigo: texto("code")
                .and_then(|c| Codigo::de_nome(&c))
                .ok_or("registro com codigo desconhecido")?,
            parametros: hex32("params").ok_or("registro sem params")?,
            detalhe: texto("detail").ok_or("registro sem detail")?,
            anterior: hex32("prev").ok_or("registro sem prev")?,
            elo: hex32("link").ok_or("registro sem link")?,
        })
    }

    /// O evento como a auditoria o encadeou.
    pub fn evento_da_cadeia(&self) -> politica::auditoria::Evento {
        politica::auditoria::Evento {
            ts_ms: self.ts_ms,
            titular: self.titular,
            sessao: self.sessao,
            sessao_de_pessoa: self.sessao_de_pessoa,
            agente: self.agente.clone(),
            chave: self.chave,
            papel: self.papel.clone(),
            metodo: self.metodo.clone(),
            recurso: self.recurso.clone(),
            codigo: self.codigo,
            parametros: self.parametros,
            detalhe: self.detalhe.clone(),
        }
    }

    /// O elo do registro refaz a conta da auditoria.
    pub fn elo_confere(&self) -> bool {
        politica::auditoria::elo(&self.anterior, self.seq, &self.evento_da_cadeia()) == self.elo
    }
}

/// Os registros do resultado de um `audit.tail`, na ordem em que vieram.
pub fn registros(resultado: &[u8]) -> Result<Vec<Registro>, &'static str> {
    let lista = Json(resultado)
        .member("records")
        .ok_or("o resultado nao tem records")?;
    let mut v = Vec::new();
    let mut i = 0;
    while let Some(o) = lista.item(i) {
        v.push(Registro::do_json(o)?);
        i += 1;
    }
    Ok(v)
}

/// O que o detalhe diz além do texto.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Detalhe {
    /// O processo que pediu: o fio e o programa, como `pelo processo N
    /// (programa)`.
    pub processo: Option<(u64, String)>,
    /// A decisão de que este registro é execução: `decisao D`, no fim.
    pub decisao: Option<u64>,
    /// O que sobra.
    pub resto: String,
}

/// Lê o detalhe no formato do kernel: `[pelo processo N (programa)[: ]]
/// resto[; decisao D]`.
pub fn ler_detalhe(d: &str) -> Detalhe {
    let mut resto = d;
    let mut processo = None;
    if let Some(depois) = resto.strip_prefix("pelo processo ") {
        let fio_fim = depois.find(' ').unwrap_or(depois.len());
        if let Ok(fio) = depois[..fio_fim].parse::<u64>()
            && let Some(prog) = depois[fio_fim..].strip_prefix(" (")
            && let Some(fecha) = prog.find(')')
        {
            processo = Some((fio, prog[..fecha].to_string()));
            let apos = &prog[fecha + 1..];
            resto = apos.strip_prefix(": ").unwrap_or(apos);
        }
    }
    let mut decisao = None;
    if let Some(i) = resto.rfind("; decisao ")
        && let Ok(n) = resto[i + "; decisao ".len()..].parse::<u64>()
    {
        decisao = Some(n);
        resto = &resto[..i];
    } else if let Some(n) = resto.strip_prefix("decisao ").and_then(|n| n.parse().ok()) {
        decisao = Some(n);
        resto = "";
    }
    Detalhe {
        processo,
        decisao,
        resto: resto.to_string(),
    }
}

/// O número depois de `prefixo` no começo de `texto`, até o primeiro espaço
/// ou vírgula.
fn numero_apos(texto: &str, prefixo: &str) -> Option<u64> {
    let depois = texto.strip_prefix(prefixo)?;
    let fim = depois
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(depois.len());
    depois[..fim].parse().ok()
}

/// O que um registro é, para o NSF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tipo {
    /// Uma decisão do gate, permitida ou não.
    Decisao,
    /// O que um comando autorizado fez, ou por que não fez.
    Execucao,
    /// Um processo nasceu: o fio do filho.
    Nascimento { filho: u64 },
    /// Uma conexão caiu: o número dela.
    Derrubada { conexao: u64 },
    /// O firewall recusou o pedido de rede que o gate tinha permitido.
    Firewall { regra: u64 },
    /// Uma leitura do próprio NSF.
    Leitura,
    /// O começo de um boot: o `policy.load` do kernel.
    Inicio,
}

/// Um evento de segurança.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evento {
    /// O número do registro na auditoria — a referência da evidência.
    pub seq: u64,
    /// O elo do registro, que o cofre de evidências amarra.
    pub elo: [u8; 32],
    /// O boot a que pertence: cada `policy.load` do kernel abre outro.
    pub epoca: u32,
    pub ts_ms: u64,
    pub titular: Titular,
    /// A identidade estável de quem responde — ver [`principal`].
    pub principal: String,
    /// Como o registro nomeia quem agiu.
    pub identificador: String,
    pub chave: Option<[u8; 32]>,
    pub sessao: u8,
    pub sessao_de_pessoa: Option<[u8; 8]>,
    /// O papel com que decidiu — o escopo da decisão.
    pub papel: String,
    pub metodo: String,
    pub recurso: String,
    pub codigo: Codigo,
    pub detalhe: String,
    /// O processo que pediu, se foi um: o fio e o programa.
    pub processo: Option<(u64, String)>,
    /// A decisão de que este é execução.
    pub decisao: Option<u64>,
    pub tipo: Tipo,
    /// A cadeia causal a que pertence — ver [`crate::grafo`].
    pub correlacao: u64,
    /// A maior severidade que uma detecção lhe deu.
    pub severidade: Severidade,
}

/// A identidade estável de quem responde por um registro: a mesma para o
/// mesmo agente em qualquer porta e boot (a chave), para a mesma pessoa em
/// qualquer console (o identificador), e para o que alguém alegou ser
/// quando foi recusado na entrada.
pub fn principal(
    titular: Titular,
    agente: &str,
    chave: Option<&[u8; 32]>,
    sessao: u8,
    sessao_de_pessoa: Option<&[u8; 8]>,
) -> String {
    match titular {
        Titular::Kernel => "kernel".to_string(),
        Titular::Sistema => "system".to_string(),
        Titular::Serial => "serial".to_string(),
        Titular::Agente => match chave {
            Some(k) => alloc::format!("agent:{}", util::hex(k)),
            None => alloc::format!("agent-name:{agente}"),
        },
        Titular::Pessoa => match agente.strip_prefix("pessoa:") {
            Some(id) => alloc::format!("person:{id}"),
            None => alloc::format!("person:{agente}"),
        },
        Titular::Administrador => alloc::format!("admin:{agente}"),
        Titular::Servico => alloc::format!("service:{agente}"),
        // Quem foi recusado na entrada: pelo que alegou ser — a chave, o
        // nome, a pessoa que se tentou ser —, ou pela porta e o console.
        Titular::Anonimo => match (chave, agente, sessao_de_pessoa) {
            (Some(k), _, _) => alloc::format!("anonymous:agent:{}", util::hex(k)),
            (None, a, _) if a.starts_with("pessoa:") => {
                alloc::format!("anonymous:person:{}", &a["pessoa:".len()..])
            }
            (None, a, _) if !a.is_empty() => alloc::format!("anonymous:name:{a}"),
            (None, _, Some(s)) => alloc::format!("anonymous:console:{}", util::hex(s)),
            (None, _, None) => alloc::format!("anonymous:session:{sessao}"),
        },
    }
}

impl Evento {
    /// O evento de um registro, na época `epoca`.
    pub fn de(r: &Registro, epoca: u32) -> Evento {
        let d = ler_detalhe(&r.detalhe);
        let tipo = classificar(r, &d);
        Evento {
            seq: r.seq,
            elo: r.elo,
            epoca,
            ts_ms: r.ts_ms,
            titular: r.titular,
            principal: principal(
                r.titular,
                &r.agente,
                r.chave.as_ref(),
                r.sessao,
                r.sessao_de_pessoa.as_ref(),
            ),
            identificador: r.agente.clone(),
            chave: r.chave,
            sessao: r.sessao,
            sessao_de_pessoa: r.sessao_de_pessoa,
            papel: r.papel.clone(),
            metodo: r.metodo.clone(),
            recurso: r.recurso.clone(),
            codigo: r.codigo,
            detalhe: r.detalhe.clone(),
            processo: d.processo,
            decisao: d.decisao,
            tipo,
            correlacao: 0,
            severidade: Severidade::Info,
        }
    }

    /// O gate recusou.
    pub fn negado(&self) -> bool {
        !self.codigo.permite() && self.codigo != Codigo::Error
    }

    /// Uma recusa do manifesto do programa: o papel de quem o lançou tem a
    /// permissão, e o programa não a declarou — a atenuação funcionando.
    /// É um sinal do programa, e não alguém sondando o próprio papel.
    pub fn fora_do_manifesto(&self) -> bool {
        self.codigo == Codigo::DenyPermission && self.detalhe.contains("o manifesto nao declara")
    }

    /// O dono de um fluxo de rede que este evento pede: o processo, se foi
    /// um; senão o agente pela chave, a pessoa pela sessão, ou a serial. É
    /// o mesmo texto da captura e do escopo de uma regra do firewall — ver
    /// [`crate::firewall::Escopo`].
    pub fn dono(&self) -> Option<String> {
        if let Some((fio, _)) = &self.processo {
            return Some(alloc::format!("process:{fio}"));
        }
        match (self.titular, &self.chave, &self.sessao_de_pessoa) {
            (Titular::Agente, Some(k), _) => Some(alloc::format!("agent:{}", util::hex(k))),
            (Titular::Pessoa, _, Some(s)) => Some(alloc::format!("person:{}", util::hex(s))),
            (Titular::Serial, _, _) => Some("serial".to_string()),
            _ => None,
        }
    }

    /// Uma permissão de rede pedida sobre um destino: `net.connect`,
    /// `net.send`, `net.recv`, `net.close` — o recurso é o destino.
    pub fn de_rede(&self) -> bool {
        matches!(
            self.metodo.as_str(),
            "net.connect" | "net.send" | "net.recv" | "net.close"
        )
    }
}

/// O tipo de um registro.
fn classificar(r: &Registro, d: &Detalhe) -> Tipo {
    if r.titular == Titular::Kernel && r.metodo == "policy.load" {
        return Tipo::Inicio;
    }
    if r.titular == Titular::Servico && matches!(r.metodo.as_str(), "audit.tail" | "net.observe") {
        return Tipo::Leitura;
    }
    if let Some(filho) = numero_apos(&d.resto, "processo ")
        && d.resto.contains(" lancado")
    {
        return Tipo::Nascimento { filho };
    }
    if r.metodo == "process.fork"
        && let Some(filho) = numero_apos(&d.resto, "filho ")
    {
        return Tipo::Nascimento { filho };
    }
    if let Some(conexao) = numero_apos(&d.resto, "conexao ")
        && d.resto.contains(" derrubada")
    {
        return Tipo::Derrubada { conexao };
    }
    if let Some(i) = d.resto.find("bloqueado pelo firewall, regra ")
        && let Some(regra) = numero_apos(&d.resto[i..], "bloqueado pelo firewall, regra ")
    {
        return Tipo::Firewall { regra };
    }
    if d.decisao.is_some() {
        return Tipo::Execucao;
    }
    Tipo::Decisao
}

#[cfg(test)]
pub(crate) mod testes {
    use super::*;

    /// Um registro de teste, com o elo feito pela conta da auditoria.
    pub(crate) fn registro(
        seq: u64,
        anterior: [u8; 32],
        f: impl FnOnce(&mut Registro),
    ) -> Registro {
        let mut r = Registro {
            seq,
            ts_ms: 1000 + seq,
            titular: Titular::Agente,
            sessao: 1,
            sessao_de_pessoa: None,
            agente: "ag".to_string(),
            chave: Some([7; 32]),
            papel: "operador".to_string(),
            metodo: "agent.ping".to_string(),
            recurso: String::new(),
            codigo: Codigo::Allow,
            parametros: [0; 32],
            detalhe: String::new(),
            anterior,
            elo: [0; 32],
        };
        f(&mut r);
        r.elo = politica::auditoria::elo(&r.anterior, r.seq, &r.evento_da_cadeia());
        r
    }

    /// O JSON de um registro, como o `audit.tail` do kernel o escreve.
    pub(crate) fn json(r: &Registro) -> String {
        let mut s = String::new();
        let mut w = protocolo::json::JsonWriter::new(&mut s);
        w.begin_object().unwrap();
        w.field_u64("seq", r.seq).unwrap();
        w.field_u64("ts_ms", r.ts_ms).unwrap();
        w.field_str("holder", r.titular.nome()).unwrap();
        w.field_u64("session", u64::from(r.sessao)).unwrap();
        w.key("person_session").unwrap();
        match &r.sessao_de_pessoa {
            Some(s) => w.str_value(&util::hex(s)).unwrap(),
            None => w.null_value().unwrap(),
        }
        w.field_str("agent", &r.agente).unwrap();
        w.key("key").unwrap();
        match &r.chave {
            Some(k) => w.str_value(&util::hex(k)).unwrap(),
            None => w.null_value().unwrap(),
        }
        w.field_str("role", &r.papel).unwrap();
        w.field_str("method", &r.metodo).unwrap();
        w.field_str("resource", &r.recurso).unwrap();
        w.field_str("result", r.codigo.resultado()).unwrap();
        w.field_str("code", r.codigo.nome()).unwrap();
        w.field_str("params", &util::hex(&r.parametros)).unwrap();
        w.field_str("detail", &r.detalhe).unwrap();
        w.field_str("prev", &util::hex(&r.anterior)).unwrap();
        w.field_str("link", &util::hex(&r.elo)).unwrap();
        w.field_bool("durable", false).unwrap();
        w.end_object().unwrap();
        s
    }

    /// O resultado de um `audit.tail` com estes registros.
    pub(crate) fn cauda(rs: &[Registro]) -> String {
        let mut s = String::from(r#"{"durable_seq":0,"records":["#);
        for (i, r) in rs.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&json(r));
        }
        s.push_str("]}");
        s
    }

    #[test]
    fn o_registro_vai_e_volta_e_o_elo_confere() {
        let r = registro(5, [3; 32], |r| {
            r.detalhe = "pelo processo 12 (discador ab12cd34): \"aspas\" é".to_string();
            r.sessao_de_pessoa = Some([9; 8]);
        });
        let lidos = registros(cauda(core::slice::from_ref(&r)).as_bytes()).unwrap();
        assert_eq!(lidos, core::slice::from_ref(&r));
        assert!(lidos[0].elo_confere());
        // Qualquer campo mudado depois do elo: não confere.
        let mut adulterado = r.clone();
        adulterado.recurso = "/outro".to_string();
        assert!(!adulterado.elo_confere());
        let mut adulterado = r;
        adulterado.ts_ms += 1;
        assert!(!adulterado.elo_confere());
    }

    #[test]
    fn o_registro_estragado_nao_se_le() {
        let r = registro(1, [0; 32], |_| {});
        let bom = cauda(&[r]);
        for (de, para) in [
            (r#""holder":"agent""#, r#""holder":"marciano""#),
            (r#""code":"ALLOW""#, r#""code":"TALVEZ""#),
            (r#""session":1"#, r#""session":300"#),
            (r#""seq":1,"#, r#""seq":"um","#),
        ] {
            assert!(bom.contains(de), "{de}");
            assert!(
                registros(bom.replace(de, para).as_bytes()).is_err(),
                "{para}"
            );
        }
        assert!(registros(b"{}").is_err());
        assert_eq!(registros(br#"{"records":[]}"#), Ok(Vec::new()));
    }

    #[test]
    fn o_detalhe() {
        let d =
            ler_detalhe("pelo processo 12 (discador ab12cd34): processo 13 lancado; decisao 77");
        assert_eq!(d.processo, Some((12, "discador ab12cd34".to_string())));
        assert_eq!(d.decisao, Some(77));
        assert_eq!(d.resto, "processo 13 lancado");
        let d = ler_detalhe("pelo processo 7 (kernel)");
        assert_eq!(d.processo, Some((7, "kernel".to_string())));
        assert_eq!((d.decisao, d.resto.as_str()), (None, ""));
        let d = ler_detalhe("o papel nao tem a permissao");
        assert_eq!(
            d,
            Detalhe {
                resto: "o papel nao tem a permissao".to_string(),
                ..Default::default()
            }
        );
        // Um "pelo processo" que não é o formato não vira processo.
        let d = ler_detalhe("pelo processo x (y)");
        assert_eq!(d.processo, None);
        let d = ler_detalhe("conexao 4 derrubada pelo bloqueio; decisao 9");
        assert_eq!(
            (d.decisao, d.resto.as_str()),
            (Some(9), "conexao 4 derrubada pelo bloqueio")
        );
    }

    #[test]
    fn os_tipos() {
        let tipo = |f: fn(&mut Registro)| Evento::de(&registro(1, [0; 32], f), 0).tipo;
        assert_eq!(tipo(|_| {}), Tipo::Decisao);
        assert_eq!(
            tipo(|r| {
                r.titular = Titular::Kernel;
                r.metodo = "policy.load".to_string();
            }),
            Tipo::Inicio
        );
        assert_eq!(
            tipo(|r| {
                r.metodo = "user.run".to_string();
                r.detalhe = "processo 13 lancado; decisao 4".to_string();
            }),
            Tipo::Nascimento { filho: 13 }
        );
        assert_eq!(
            tipo(|r| {
                r.metodo = "process.fork".to_string();
                r.detalhe = "pelo processo 3 (x 00000000): filho 14".to_string();
            }),
            Tipo::Nascimento { filho: 14 }
        );
        assert_eq!(
            tipo(|r| {
                r.metodo = "net.connect".to_string();
                r.detalhe = "bloqueado pelo firewall, regra 2; decisao 8".to_string();
            }),
            Tipo::Firewall { regra: 2 }
        );
        assert_eq!(
            tipo(|r| {
                r.titular = Titular::Kernel;
                r.metodo = "net.close".to_string();
                r.detalhe = "conexao 5 derrubada: o dono acabou".to_string();
            }),
            Tipo::Derrubada { conexao: 5 }
        );
        assert_eq!(
            tipo(|r| {
                r.titular = Titular::Servico;
                r.metodo = "audit.tail".to_string();
            }),
            Tipo::Leitura
        );
        assert_eq!(
            tipo(|r| r.detalhe = "versao 3 gravada; decisao 2".to_string()),
            Tipo::Execucao
        );
    }

    #[test]
    fn o_principal_e_o_dono() {
        let k = [0xAB; 32];
        let hk = util::hex(&k);
        assert_eq!(
            principal(Titular::Agente, "ag", Some(&k), 1, None),
            alloc::format!("agent:{hk}")
        );
        assert_eq!(
            principal(Titular::Pessoa, "pessoa:0011", None, 255, Some(&[1; 8])),
            "person:0011"
        );
        assert_eq!(
            principal(Titular::Servico, "nsf", None, 255, None),
            "service:nsf"
        );
        assert_eq!(
            principal(Titular::Anonimo, "", Some(&k), 2, None),
            alloc::format!("anonymous:agent:{hk}")
        );
        assert_eq!(
            principal(Titular::Anonimo, "pessoa:aa", None, 255, None),
            "anonymous:person:aa"
        );
        assert_eq!(
            principal(Titular::Anonimo, "", None, 3, None),
            "anonymous:session:3"
        );
        // O dono de um fluxo: o processo antes do titular.
        let e = Evento::de(
            &registro(1, [0; 32], |r| {
                r.detalhe = "pelo processo 9 (p 00000000)".to_string()
            }),
            0,
        );
        assert_eq!(e.dono().as_deref(), Some("process:9"));
        let e = Evento::de(&registro(1, [0; 32], |_| {}), 0);
        assert_eq!(
            e.dono(),
            Some(alloc::format!("agent:{}", util::hex(&[7; 32])))
        );
    }
}
