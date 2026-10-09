//! O que o NSF vê do DNS: as perguntas e as respostas trocadas com um
//! servidor observado, lidas da captura pelo gate (`net.observe`).
//!
//! # Para que
//!
//! Para ligar o nome ao endereço, o endereço à conexão que o mesmo dono
//! pede em seguida, e a conexão à decisão do gate: "que resolução precedeu
//! esta conexão — e o endereço passou de novo pelo gate?". Só isso. Uma
//! resolução nunca dá acesso a nada: o NSF não decide, e o gate não a lê.
//!
//! # A conta
//!
//! Cada resposta é lida com o mesmo codec do programa que resolve
//! (`protocolo::dns`) e casada com a pergunta do mesmo dono, pela conexão
//! e pelo número da pergunta. A ordem entre uma resolução e uma conexão é a
//! da auditoria: cada datagrama diz o último registro que havia quando foi
//! guardado, e uma resolução precedeu a decisão de número maior que esse —
//! o relógio, de um segundo, não separaria as duas. Uma resposta sem pergunta é guardada como tal
//! — é o que uma resposta forjada parece. Uma mensagem que não se lê é
//! contada: um canal de DNS cheio de mensagens estranhas é um sinal.

use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use protocolo::json::Json;

use crate::util;

/// Quantas resoluções o NSF guarda.
pub const MAIS_RESOLUCOES: usize = 64;
/// Quantas perguntas sem resposta.
const MAIS_PERGUNTAS: usize = 32;

/// Um datagrama da captura, como `net.observe` o mostra.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Captura {
    pub seq: u64,
    pub ts_ms: u64,
    /// O último registro da auditoria quando o datagrama foi guardado.
    pub registro: u64,
    pub conexao: u64,
    /// O dono da associação: `process:<fio>`, `agent:<chave>`,
    /// `person:<sessão>` ou `serial`.
    pub dono: String,
    /// O destino da associação — o servidor.
    pub destino: String,
    /// O dono mandou (a pergunta), e não recebeu.
    pub saida: bool,
    pub dados: Vec<u8>,
}

/// Os datagramas do resultado de um `net.observe`.
pub fn capturas(resultado: &[u8]) -> Result<Vec<Captura>, &'static str> {
    let lista = Json(resultado)
        .member("records")
        .ok_or("o resultado nao tem records")?;
    let mut v = Vec::new();
    let mut i = 0;
    while let Some(o) = lista.item(i) {
        let texto = |n: &str| util::texto(o.member(n), 256);
        let dados = util::texto(o.member("data"), 4096)
            .and_then(|b| util::de_base64(&b))
            .ok_or("captura sem data")?;
        v.push(Captura {
            seq: util::numero(o.member("seq")).ok_or("captura sem seq")?,
            ts_ms: util::numero(o.member("ts_ms")).ok_or("captura sem ts_ms")?,
            registro: util::numero(o.member("after_record")).ok_or("captura sem after_record")?,
            conexao: util::numero(o.member("connection")).ok_or("captura sem connection")?,
            dono: texto("owner").ok_or("captura sem owner")?,
            destino: texto("to").ok_or("captura sem to")?,
            saida: match texto("direction").as_deref() {
                Some("out") => true,
                Some("in") => false,
                _ => return Err("captura sem direction"),
            },
            dados,
        });
        i += 1;
    }
    Ok(v)
}

/// Uma resolução vista: quem perguntou, o nome, o que veio.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolucao {
    pub dono: String,
    pub servidor: String,
    pub nome: String,
    pub enderecos: Vec<[u8; 4]>,
    pub ttl: u32,
    /// O código de resposta do servidor.
    pub codigo: u8,
    /// A resposta casou com uma pergunta do mesmo dono.
    pub casada: bool,
    /// Registros de endereço de outros nomes, que a leitura deixou de fora.
    pub alheios: usize,
    pub ts_ms: u64,
    /// O datagrama na captura.
    pub captura: u64,
    /// O último registro da auditoria quando a resposta foi guardada.
    pub registro: u64,
}

/// O que um datagrama observado foi.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observado {
    Pergunta { nome: String },
    Resposta(Resolucao),
    Malformado(protocolo::dns::Erro),
}

/// As resoluções e as perguntas abertas.
#[derive(Clone, Debug, Default)]
pub struct Dns {
    resolucoes: VecDeque<Resolucao>,
    perguntas: VecDeque<(String, u64, u16, String)>,
    pub malformados: u64,
}

impl Dns {
    pub fn novo() -> Dns {
        Dns::default()
    }

    /// Lê um datagrama da captura.
    pub fn observar(&mut self, c: &Captura) -> Observado {
        let m = match protocolo::dns::ler(&c.dados) {
            Ok(m) => m,
            Err(e) => {
                self.malformados += 1;
                return Observado::Malformado(e);
            }
        };
        let nome = m.nome().map(|n| n.texto().to_string()).unwrap_or_default();
        if c.saida && !m.resposta {
            if self.perguntas.len() == MAIS_PERGUNTAS {
                self.perguntas.pop_front();
            }
            self.perguntas
                .push_back((c.dono.clone(), c.conexao, m.id, nome.clone()));
            return Observado::Pergunta { nome };
        }
        let pergunta = self.perguntas.iter().position(|(d, conexao, id, n)| {
            *d == c.dono && *conexao == c.conexao && *id == m.id && *n == nome
        });
        let casada = pergunta.is_some();
        if let Some(i) = pergunta {
            self.perguntas.remove(i);
        }
        let r = Resolucao {
            dono: c.dono.clone(),
            servidor: c.destino.clone(),
            nome,
            enderecos: m.enderecos().to_vec(),
            ttl: m.ttl,
            codigo: m.codigo,
            casada,
            alheios: m.alheios,
            ts_ms: c.ts_ms,
            captura: c.seq,
            registro: c.registro,
        };
        if self.resolucoes.len() == MAIS_RESOLUCOES {
            self.resolucoes.pop_front();
        }
        self.resolucoes.push_back(r.clone());
        Observado::Resposta(r)
    }

    /// A resolução mais nova de `dono` que deu `ip` antes do registro
    /// `seq` da auditoria — a que precedeu a decisão `seq`. Uma resolução
    /// guardada depois dela não precedeu nada.
    pub fn antes_de(&self, dono: &str, ip: [u8; 4], seq: u64) -> Option<&Resolucao> {
        self.resolucoes
            .iter()
            .rev()
            .find(|r| r.dono == dono && r.registro < seq && r.enderecos.contains(&ip))
    }

    /// As resoluções guardadas, da mais velha à mais nova.
    pub fn resolucoes(&self) -> impl Iterator<Item = &Resolucao> {
        self.resolucoes.iter()
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use protocolo::dns::{Nome, pergunta, resposta};

    fn cap(seq: u64, dono: &str, saida: bool, dados: Vec<u8>) -> Captura {
        Captura {
            seq,
            ts_ms: seq * 10,
            registro: seq * 2,
            conexao: 4,
            dono: dono.to_string(),
            destino: "udp:10.0.2.3:53".to_string(),
            saida,
            dados,
        }
    }

    fn perg(id: u16, nome: &str) -> Vec<u8> {
        let mut b = [0u8; 512];
        let n = pergunta(id, &Nome::de_texto(nome).unwrap(), &mut b).unwrap();
        b[..n].to_vec()
    }

    fn resp(id: u16, nome: &str, ips: &[[u8; 4]]) -> Vec<u8> {
        let mut b = [0u8; 512];
        let n = resposta(id, &Nome::de_texto(nome).unwrap(), ips, 60, 0, &mut b).unwrap();
        b[..n].to_vec()
    }

    #[test]
    fn a_pergunta_e_a_resposta_casam() {
        let mut d = Dns::novo();
        assert_eq!(
            d.observar(&cap(1, "process:9", true, perg(7, "eco.duke"))),
            Observado::Pergunta {
                nome: "eco.duke".to_string()
            }
        );
        let Observado::Resposta(r) = d.observar(&cap(
            2,
            "process:9",
            false,
            resp(7, "eco.duke", &[[10, 0, 2, 100]]),
        )) else {
            panic!("resposta");
        };
        assert!(r.casada);
        assert_eq!(r.enderecos, [[10, 0, 2, 100]]);
        // A resposta foi guardada com a auditoria no registro 4: precedeu a
        // decisão 5, e não a 4.
        assert_eq!(
            d.antes_de("process:9", [10, 0, 2, 100], 5)
                .map(|r| r.nome.as_str()),
            Some("eco.duke")
        );
        assert!(d.antes_de("process:9", [10, 0, 2, 100], 4).is_none());
        // De outro dono, não.
        assert!(d.antes_de("process:8", [10, 0, 2, 100], 5).is_none());
    }

    /// A resposta sem pergunta — outro número, outro nome, outro dono —
    /// é guardada como não casada.
    #[test]
    fn a_resposta_sem_pergunta() {
        let mut d = Dns::novo();
        d.observar(&cap(1, "process:9", true, perg(7, "eco.duke")));
        for (dono, id, nome) in [
            ("process:9", 8, "eco.duke"),
            ("process:9", 7, "outro.duke"),
            ("process:3", 7, "eco.duke"),
        ] {
            let Observado::Resposta(r) =
                d.observar(&cap(2, dono, false, resp(id, nome, &[[1, 2, 3, 4]])))
            else {
                panic!("resposta");
            };
            assert!(!r.casada, "{dono} {id} {nome}");
        }
    }

    #[test]
    fn o_malformado_e_contado() {
        let mut d = Dns::novo();
        assert!(matches!(
            d.observar(&cap(1, "serial", false, alloc::vec![1, 2, 3])),
            Observado::Malformado(_)
        ));
        assert_eq!(d.malformados, 1);
    }

    #[test]
    fn a_captura_do_json() {
        let dados = perg(1, "a.duke");
        let json = alloc::format!(
            r#"{{"records":[{{"seq":3,"ts_ms":40,"after_record":17,"connection":2,"owner":"process:5","to":"udp:10.0.2.3:53","direction":"out","size":{},"data":"{}"}}],"next":4}}"#,
            dados.len(),
            util::base64(&dados)
        );
        let c = capturas(json.as_bytes()).unwrap();
        assert_eq!(
            c,
            [Captura {
                seq: 3,
                ts_ms: 40,
                registro: 17,
                conexao: 2,
                dono: "process:5".to_string(),
                destino: "udp:10.0.2.3:53".to_string(),
                saida: true,
                dados
            }]
        );
        assert!(capturas(br#"{"records":[{"seq":1}]}"#).is_err());
        assert!(capturas(b"{}").is_err());
    }
}
