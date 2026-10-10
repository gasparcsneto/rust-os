//! O motor de resposta: o que o NSF pede, e o que recomenda.
//!
//! # Pedir não é fazer
//!
//! O motor planeja; quem executa é o fio do NSF, pelo gate, com a
//! identidade do NSF — e o gate decide o pedido como decidiria o de
//! qualquer um. O plano diz o comando e os parâmetros; o desfecho volta
//! como volta para qualquer um: a resposta do comando, e o registro na
//! auditoria, que o NSF lê de volta e casa com o pedido.
//!
//! # Os níveis: o impacto da ação
//!
//! - 0, observar: o registro e o risco. Nada muda para ninguém.
//! - 1, alertar: o incidente, com a recomendação. Nada muda para ninguém.
//! - 2, contenção reversível: barrar um destino de um fluxo, isolar um
//!   processo, suspender um agente, suspender uma credencial — cada uma
//!   com o seu inverso (ver [`CONTENCOES`]).
//! - 3, contenção forte: o que não se desfaz — revogar uma credencial,
//!   encerrar um agente. O NSF **nunca** pede: recomenda a um
//!   administrador, que age com prova.
//!
//! # Quanto maior o impacto, maior a confiança
//!
//! [`nivel_permitido`]: o NSF age sozinho até o nível que a confiança da
//! detecção e a saúde dele permitem. Confiança baixa observa; média
//! alerta; alta contém, de forma reversível — e, com o NSF degradado, só
//! diante de um contorno. Acima do permitido, a ação vira recomendação para
//! quem tem a autoridade, com o motivo de não ter sido pedida.
//!
//! # A escada
//!
//! A menor intervenção que alcança o que a detecção aponta: primeiro o
//! destino, só para o dono do fluxo. Se a ameaça continua depois — o mesmo
//! dono usa a rede para outro destino, com a contenção valendo —, o degrau
//! seguinte é o dono inteiro: o processo isolado, o agente suspenso, a
//! credencial da pessoa suspensa. A serial não tem degrau seguinte: é o
//! console do sistema.
//!
//! # Uma recusa encerra o objetivo; uma recuperação também
//!
//! Se o gate recusa uma contenção, o incidente fica sem contenção
//! automática: o motor não planeja outra — nem com outro comando, nem com
//! outro alvo, nem mais larga. Se alguém desfaz uma contenção do incidente
//! — solta, retoma, tira a regra —, o mesmo: quem desfez decidiu, pelo
//! gate, e o NSF não briga com a decisão. Uma recomendação continua lá
//! para quem tem a autoridade.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use protocolo::json::JsonWriter;

use crate::evento::{Severidade, Titular};
use crate::regras::{Alvo, Categoria, Confianca, Deteccao, Regra};

/// O nível de uma ação: o impacto dela.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Nivel {
    Observar = 0,
    Alertar = 1,
    Reversivel = 2,
    Forte = 3,
}

impl Nivel {
    pub const fn nome(self) -> &'static str {
        match self {
            Nivel::Observar => "observe",
            Nivel::Alertar => "alert",
            Nivel::Reversivel => "reversible-containment",
            Nivel::Forte => "strong-containment",
        }
    }
}

/// As contenções reversíveis, cada uma com o inverso.
pub const CONTENCOES: [(&str, &str); 4] = [
    ("net.block", "net.unblock"),
    ("process.isolate", "process.release"),
    ("agent.suspend", "agent.resume"),
    ("credential.suspend", "credential.resume"),
];

/// O inverso de uma contenção.
pub fn inverso(contencao: &str) -> Option<&'static str> {
    CONTENCOES
        .iter()
        .find(|(c, _)| *c == contencao)
        .map(|(_, i)| *i)
}

/// A contenção que um inverso desfaz.
pub fn desfeita_por(inverso: &str) -> Option<&'static str> {
    CONTENCOES
        .iter()
        .find(|(_, i)| *i == inverso)
        .map(|(c, _)| *c)
}

/// Até que nível o NSF age sozinho: a matriz da confiança contra o
/// impacto. A contenção forte nunca.
pub const fn nivel_permitido(confianca: Confianca, categoria: Categoria, saudavel: bool) -> Nivel {
    match confianca {
        Confianca::Baixa => Nivel::Observar,
        Confianca::Media => Nivel::Alertar,
        Confianca::Alta => {
            if saudavel || matches!(categoria, Categoria::Contorno) {
                Nivel::Reversivel
            } else {
                Nivel::Alertar
            }
        }
    }
}

/// Em que pé está uma ação.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Estado {
    /// Uma recomendação para quem tem a autoridade.
    Recomendada,
    /// Planejada, ainda não pedida.
    Planejada,
    /// Pedida ao gate, sem resposta ainda.
    Pedida,
    /// O gate permitiu, e o comando executou.
    Permitida,
    /// O gate recusou, com o código.
    Negada { codigo: String },
    /// O gate permitiu, e o comando não fez — com o motivo.
    Falhou { motivo: String },
    /// Alguém fez, pelo próprio papel; o NSF viu pela auditoria.
    Observada,
}

impl Estado {
    pub fn nome(&self) -> &'static str {
        match self {
            Estado::Recomendada => "recommended",
            Estado::Planejada => "planned",
            Estado::Pedida => "requested",
            Estado::Permitida => "allowed",
            Estado::Negada { .. } => "denied",
            Estado::Falhou { .. } => "failed",
            Estado::Observada => "observed",
        }
    }
}

/// Uma ação de um incidente.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acao {
    pub id: u64,
    pub nivel: Nivel,
    /// O que se pede, ou se recomenda: o comando…
    pub metodo: String,
    /// …os parâmetros, em JSON…
    pub params: String,
    /// …e o recurso que o gate decide.
    pub recurso: String,
    /// Quem a contenção alcança — o dono do fluxo, o processo, o agente, a
    /// pessoa —, como o NSF o nomeia; vazio quando o NSF não sabe.
    pub dono: String,
    pub estado: Estado,
    /// A decisão do gate, quando a auditoria já a mostrou.
    pub decisao: Option<u64>,
    /// O registro que disparou a detecção que planejou esta ação — de onde
    /// se mede a latência da resposta; zero numa ação observada.
    pub origem: u64,
    /// Quem a autorizou — a identidade cujo papel o gate decidiu —, ou quem
    /// teria de autorizar uma recomendação.
    pub autorizado_por: String,
    pub justificativa: String,
}

impl Acao {
    /// Uma contenção reversível — o que o inverso desfaz.
    pub fn contem(&self) -> bool {
        inverso(&self.metodo).is_some()
    }
}

/// O que se sabe do incidente na hora de planejar.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Situacao {
    /// A detecção é da história — o boot de antes, ou de antes de o motor
    /// estar ao vivo.
    pub historico: bool,
    /// O gate recusou uma contenção deste incidente.
    pub contencao_negada: bool,
    /// Quem desfez uma contenção deste incidente.
    pub recuperada: Option<String>,
    /// O NSF está saudável — ver [`crate::motor::Saude`].
    pub saudavel: bool,
    /// O dono do alvo já está contido neste incidente: a ameaça continuou
    /// depois da contenção.
    pub dono_contido: bool,
}

impl Situacao {
    /// Por que o NSF não pede sozinho uma ação de nível `nivel` por `d`;
    /// `None` se pede.
    pub fn impedimento(&self, d: &Deteccao, nivel: Nivel) -> Option<String> {
        if self.historico {
            return Some("da historia: o NSF so pede pelo que e ao vivo".to_string());
        }
        if self.contencao_negada {
            return Some("o gate recusou uma contencao deste incidente".to_string());
        }
        if let Some(quem) = &self.recuperada {
            return Some(alloc::format!(
                "{quem} desfez uma contencao deste incidente"
            ));
        }
        let permitido = nivel_permitido(d.confianca, d.regra.categoria(), self.saudavel);
        if nivel > permitido {
            return Some(if d.confianca == Confianca::Alta && !self.saudavel {
                "o NSF esta degradado: so contem sozinho diante de um contorno".to_string()
            } else {
                alloc::format!(
                    "confianca {} nao basta para o nivel {}",
                    d.confianca.nome(),
                    nivel.nome()
                )
            });
        }
        None
    }
}

/// Um objeto JSON de um campo de texto.
fn objeto(campo: &str, valor: &str) -> String {
    let mut s = String::new();
    let mut w = JsonWriter::new(&mut s);
    let _ = w.begin_object();
    let _ = w.field_str(campo, valor);
    let _ = w.end_object();
    s
}

/// O primeiro degrau: o destino, só para o dono do fluxo.
fn degrau_do_destino(alvo: &Alvo) -> (&'static str, String, String) {
    let mut s = String::new();
    let mut w = JsonWriter::new(&mut s);
    let _ = w.begin_object();
    let _ = w.field_str("to", &alvo.destino);
    let _ = w.field_str("owner", &alvo.dono);
    let _ = w.end_object();
    ("net.block", s, alvo.destino.clone())
}

/// O degrau seguinte: o dono inteiro — o processo, o agente, a credencial
/// da pessoa. O recurso é o alvo, como a auditoria o grava — `process:<fio>`,
/// `agent:<chave>`, `pessoa:<id>` —; o gate decide pelo papel dele. `None`
/// para a serial.
fn degrau_do_dono(d: &Deteccao, alvo: &Alvo) -> Option<(&'static str, String, String)> {
    if let Some(fio) = alvo.dono.strip_prefix("process:") {
        let fio: u64 = fio.parse().ok()?;
        return Some((
            "process.isolate",
            alloc::format!(r#"{{"process":{fio}}}"#),
            alvo.dono.clone(),
        ));
    }
    if let Some(chave) = alvo.dono.strip_prefix("agent:") {
        return Some(("agent.suspend", objeto("key", chave), alvo.dono.clone()));
    }
    if alvo.dono.starts_with("person:") {
        let id = d.principal.strip_prefix("person:")?;
        let pessoa = alloc::format!("pessoa:{id}");
        return Some(("credential.suspend", objeto("person", &pessoa), pessoa));
    }
    None
}

/// O que o motor faria com uma detecção: ações sem número ainda.
pub fn planejar(d: &Deteccao, s: &Situacao) -> Vec<Acao> {
    let mut v = Vec::new();
    match d.regra {
        Regra::SaidaDepoisDeSondagem => {
            let Some(alvo) = &d.alvo else {
                return v;
            };
            // A escada: o destino; contido o dono e a ameaça continuando,
            // o dono inteiro.
            let (metodo, params, recurso) = if s.dono_contido {
                degrau_do_dono(d, alvo).unwrap_or_else(|| degrau_do_destino(alvo))
            } else {
                degrau_do_destino(alvo)
            };
            let (estado, autorizado_por, justificativa) = match s.impedimento(d, Nivel::Reversivel)
            {
                None => (
                    Estado::Planejada,
                    "service:nsf".to_string(),
                    alloc::format!(
                        "conter {} (papel {}, confianca {}): {}",
                        alvo.dono,
                        alvo.papel,
                        d.confianca.nome(),
                        d.explicacao
                    ),
                ),
                Some(motivo) => (
                    Estado::Recomendada,
                    alloc::format!("quem tem {metodo} sobre {recurso}"),
                    alloc::format!("{metodo} para {}: recomendado, porque {motivo}", alvo.dono),
                ),
            };
            v.push(Acao {
                id: 0,
                nivel: Nivel::Reversivel,
                metodo: metodo.to_string(),
                params,
                recurso,
                dono: alvo.dono.clone(),
                estado,
                decisao: None,
                origem: d.registros.last().copied().unwrap_or(0),
                autorizado_por,
                justificativa,
            });
        }
        // Revogar é definitivo: nunca do NSF, sempre do administrador.
        Regra::AbusoDeCredencial
            if d.titular == Titular::Agente && d.severidade >= Severidade::Alta =>
        {
            v.push(Acao {
                id: 0,
                nivel: Nivel::Forte,
                metodo: "admin.execute".to_string(),
                params: alloc::format!(
                    r#"{{"command":"agent.revoke","principal":"{}"}}"#,
                    d.principal
                ),
                recurso: String::new(),
                dono: d.principal.clone(),
                estado: Estado::Recomendada,
                decisao: None,
                origem: d.registros.last().copied().unwrap_or(0),
                autorizado_por: "um administrador, com prova".to_string(),
                justificativa: "revogar a credencial: so com a prova de um administrador"
                    .to_string(),
            });
        }
        _ => {}
    }
    v
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::regras::Alvo;

    fn det(regra: Regra, alvo: Option<Alvo>, titular: Titular) -> Deteccao {
        Deteccao {
            regra,
            severidade: Severidade::Alta,
            confianca: Confianca::Alta,
            principal: "agent:aa".to_string(),
            titular,
            registros: alloc::vec![1],
            explicacao: "x".to_string(),
            alvo,
            ts_ms: 1,
            epoca: 0,
        }
    }

    fn alvo_de(dono: &str) -> Option<Alvo> {
        Some(Alvo {
            destino: "tcp:10.0.2.100:7".to_string(),
            dono: dono.to_string(),
            papel: "operador".to_string(),
        })
    }

    fn alvo() -> Option<Alvo> {
        alvo_de("process:9")
    }

    fn saudavel() -> Situacao {
        Situacao {
            saudavel: true,
            ..Situacao::default()
        }
    }

    #[test]
    fn a_contencao_so_ao_vivo_e_sem_recusa() {
        let d = det(Regra::SaidaDepoisDeSondagem, alvo(), Titular::Agente);
        let ao_vivo = planejar(&d, &saudavel());
        assert_eq!(ao_vivo.len(), 1);
        assert_eq!(
            (ao_vivo[0].nivel, &ao_vivo[0].estado),
            (Nivel::Reversivel, &Estado::Planejada)
        );
        assert_eq!(ao_vivo[0].metodo, "net.block");
        assert_eq!(
            ao_vivo[0].params,
            r#"{"to":"tcp:10.0.2.100:7","owner":"process:9"}"#
        );
        assert_eq!(ao_vivo[0].dono, "process:9");
        assert_eq!(ao_vivo[0].autorizado_por, "service:nsf");
        // Da história, depois de uma recusa, ou de uma recuperação: só a
        // recomendação, com o motivo.
        for (s, motivo) in [
            (
                Situacao {
                    historico: true,
                    ..saudavel()
                },
                "da historia",
            ),
            (
                Situacao {
                    contencao_negada: true,
                    ..saudavel()
                },
                "o gate recusou",
            ),
            (
                Situacao {
                    recuperada: Some("admin:adm".to_string()),
                    ..saudavel()
                },
                "admin:adm desfez",
            ),
        ] {
            let p = planejar(&d, &s);
            assert_eq!(p.len(), 1);
            assert_eq!(
                (p[0].nivel, &p[0].estado),
                (Nivel::Reversivel, &Estado::Recomendada)
            );
            assert!(
                p[0].justificativa.contains(motivo),
                "{}",
                p[0].justificativa
            );
        }
    }

    /// A matriz: o limiar de confiança cresce com o impacto, e o NSF
    /// degradado só contém diante de um contorno. A contenção forte nunca.
    #[test]
    fn a_confianca_cresce_com_o_impacto() {
        use Categoria::*;
        use Confianca::*;
        for categoria in [Incomum, Risco, Violacao, Contorno] {
            for saudavel in [true, false] {
                assert_eq!(nivel_permitido(Baixa, categoria, saudavel), Nivel::Observar);
                assert_eq!(nivel_permitido(Media, categoria, saudavel), Nivel::Alertar);
                assert!(nivel_permitido(Alta, categoria, saudavel) < Nivel::Forte);
            }
            assert_eq!(nivel_permitido(Alta, categoria, true), Nivel::Reversivel);
        }
        assert_eq!(nivel_permitido(Alta, Violacao, false), Nivel::Alertar);
        assert_eq!(nivel_permitido(Alta, Contorno, false), Nivel::Reversivel);
        // Confiança média, ou o NSF degradado: a saída vira recomendação,
        // e diz por quê.
        let mut d = det(Regra::SaidaDepoisDeSondagem, alvo(), Titular::Agente);
        d.confianca = Media;
        let p = planejar(&d, &saudavel());
        assert_eq!(p[0].estado, Estado::Recomendada);
        assert!(
            p[0].justificativa.contains("confianca medium"),
            "{}",
            p[0].justificativa
        );
        d.confianca = Alta;
        let p = planejar(&d, &Situacao::default());
        assert_eq!(p[0].estado, Estado::Recomendada);
        assert!(
            p[0].justificativa.contains("degradado"),
            "{}",
            p[0].justificativa
        );
    }

    /// A escada: contido o dono e a ameaça continuando, o degrau seguinte é
    /// o dono inteiro — o processo, o agente, a credencial da pessoa —, com
    /// o alvo como recurso. A serial fica no destino.
    #[test]
    fn a_escada() {
        let contido = Situacao {
            dono_contido: true,
            ..saudavel()
        };
        let chave = "ab".repeat(32);
        for (dono, principal, metodo, params, recurso) in [
            (
                "process:9".to_string(),
                "agent:aa",
                "process.isolate",
                r#"{"process":9}"#.to_string(),
                "process:9".to_string(),
            ),
            (
                alloc::format!("agent:{chave}"),
                "agent:aa",
                "agent.suspend",
                alloc::format!(r#"{{"key":"{chave}"}}"#),
                alloc::format!("agent:{chave}"),
            ),
            (
                "person:0102030405060708".to_string(),
                "person:00112233aabbccdd",
                "credential.suspend",
                r#"{"person":"pessoa:00112233aabbccdd"}"#.to_string(),
                "pessoa:00112233aabbccdd".to_string(),
            ),
        ] {
            let mut d = det(
                Regra::SaidaDepoisDeSondagem,
                alvo_de(&dono),
                Titular::Agente,
            );
            d.principal = principal.to_string();
            let p = planejar(&d, &contido);
            assert_eq!(p.len(), 1);
            assert_eq!(
                (
                    p[0].metodo.as_str(),
                    p[0].params.as_str(),
                    p[0].recurso.as_str()
                ),
                (metodo, params.as_str(), recurso.as_str())
            );
            assert_eq!(p[0].dono, dono);
            assert_eq!(p[0].estado, Estado::Planejada);
            assert!(p[0].contem());
            // Sem a contenção de antes, o primeiro degrau: o destino.
            let p = planejar(&d, &saudavel());
            assert_eq!(p[0].metodo, "net.block");
        }
        let d = det(
            Regra::SaidaDepoisDeSondagem,
            alvo_de("serial"),
            Titular::Serial,
        );
        assert_eq!(planejar(&d, &contido)[0].metodo, "net.block");
    }

    #[test]
    fn os_inversos() {
        for (c, i) in CONTENCOES {
            assert_eq!(inverso(c), Some(i));
            assert_eq!(desfeita_por(i), Some(c));
            assert_eq!(inverso(i), None);
        }
        assert_eq!(inverso("agent.revoke"), None);
    }

    /// Revogar é do administrador: o NSF recomenda, nunca pede.
    #[test]
    fn revogar_e_recomendacao() {
        let p = planejar(
            &det(Regra::AbusoDeCredencial, None, Titular::Agente),
            &saudavel(),
        );
        assert_eq!(p.len(), 1);
        assert_eq!(
            (p[0].nivel, &p[0].estado),
            (Nivel::Forte, &Estado::Recomendada)
        );
        // De outra identidade, ou outra regra: nada a pedir.
        assert!(
            planejar(
                &det(Regra::AbusoDeCredencial, None, Titular::Pessoa),
                &saudavel()
            )
            .is_empty()
        );
        for r in Regra::TODAS {
            if r != Regra::SaidaDepoisDeSondagem {
                assert!(
                    planejar(&det(r, alvo(), Titular::Agente), &saudavel())
                        .iter()
                        .all(|a| a.estado != Estado::Planejada),
                    "{}",
                    r.nome()
                );
            }
        }
        // Nenhuma ação planejada é forte.
        for dono_contido in [false, true] {
            let s = Situacao {
                dono_contido,
                ..saudavel()
            };
            for a in planejar(
                &det(Regra::SaidaDepoisDeSondagem, alvo(), Titular::Agente),
                &s,
            ) {
                assert!(a.nivel < Nivel::Forte);
            }
        }
    }
}
