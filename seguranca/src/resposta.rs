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
//! # Os níveis
//!
//! - 0, observar: só o registro.
//! - 1, alertar: o incidente, com a recomendação.
//! - 2, resposta autorizada: alguém com a permissão executa a
//!   recomendação pelo próprio papel; o NSF vê a ação pela auditoria e a
//!   põe no incidente.
//! - 3, contenção automática pré-autorizada: o NSF pede sozinho — e só
//!   consegue o que a política deu ao papel dele.
//!
//! # Uma recusa encerra o objetivo
//!
//! Se o gate recusa uma contenção, o incidente fica sem contenção
//! automática: o motor não planeja outra — nem com outro comando, nem com
//! outro alvo, nem mais larga. Uma recomendação continua lá para quem tem a
//! autoridade.
//!
//! O que só um administrador faz com prova — revogar uma credencial,
//! encerrar a sessão de um agente — é recomendação, nunca pedido: o NSF não
//! tem prova, e o caminho até a operação exige uma.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::evento::Titular;
use crate::regras::{Deteccao, Regra};

/// O nível de uma ação.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Nivel {
    Observar = 0,
    Alertar = 1,
    Autorizada = 2,
    Contencao = 3,
}

impl Nivel {
    pub const fn nome(self) -> &'static str {
        match self {
            Nivel::Observar => "observe",
            Nivel::Alertar => "alert",
            Nivel::Autorizada => "authorized",
            Nivel::Contencao => "containment",
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
    pub estado: Estado,
    /// A decisão do gate, quando a auditoria já a mostrou.
    pub decisao: Option<u64>,
    /// Quem a autorizou — a identidade cujo papel o gate decidiu —, ou quem
    /// teria de autorizar uma recomendação.
    pub autorizado_por: String,
    pub justificativa: String,
}

/// O que o motor faria com uma detecção: ações sem número ainda.
pub fn planejar(d: &Deteccao, historico: bool, contencao_negada: bool) -> Vec<Acao> {
    let mut v = Vec::new();
    let acao = |nivel,
                metodo: &str,
                params: String,
                recurso: &str,
                estado,
                autorizado_por: &str,
                justificativa: String| Acao {
        id: 0,
        nivel,
        metodo: metodo.to_string(),
        params,
        recurso: recurso.to_string(),
        estado,
        decisao: None,
        autorizado_por: autorizado_por.to_string(),
        justificativa,
    };
    match d.regra {
        Regra::SaidaDepoisDeSondagem => {
            let Some(alvo) = &d.alvo else {
                return v;
            };
            let params = alloc::format!(r#"{{"to":"{}","owner":"{}"}}"#, alvo.destino, alvo.dono);
            // A contenção automática: só ao vivo, e só se o gate não
            // recusou uma contenção neste incidente.
            if !historico && !contencao_negada {
                v.push(acao(
                    Nivel::Contencao,
                    "net.block",
                    params,
                    &alvo.destino,
                    Estado::Planejada,
                    "service:nsf",
                    alloc::format!(
                        "conter {} para {}: {}",
                        alvo.destino,
                        alvo.dono,
                        d.explicacao
                    ),
                ));
            } else {
                v.push(acao(
                    Nivel::Autorizada,
                    "net.block",
                    params,
                    &alvo.destino,
                    Estado::Recomendada,
                    "quem tem net.block sobre o destino",
                    alloc::format!("barrar {} para {}", alvo.destino, alvo.dono),
                ));
            }
        }
        Regra::AbusoDeCredencial if d.titular == Titular::Agente => {
            v.push(acao(
                Nivel::Alertar,
                "admin.execute",
                alloc::format!(
                    r#"{{"command":"agent.revoke","principal":"{}"}}"#,
                    d.principal
                ),
                "",
                Estado::Recomendada,
                "um administrador, com prova",
                "revogar a credencial: so com a prova de um administrador".to_string(),
            ));
        }
        _ => {}
    }
    v
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::evento::Severidade;
    use crate::regras::Alvo;

    fn det(regra: Regra, alvo: Option<Alvo>, titular: Titular) -> Deteccao {
        Deteccao {
            regra,
            severidade: Severidade::Alta,
            principal: "agent:aa".to_string(),
            titular,
            registros: alloc::vec![1],
            explicacao: "x".to_string(),
            alvo,
            ts_ms: 1,
            epoca: 0,
        }
    }

    fn alvo() -> Option<Alvo> {
        Some(Alvo {
            destino: "tcp:10.0.2.100:7".to_string(),
            dono: "process:9".to_string(),
        })
    }

    #[test]
    fn a_contencao_so_ao_vivo_e_sem_recusa() {
        let d = det(Regra::SaidaDepoisDeSondagem, alvo(), Titular::Agente);
        let ao_vivo = planejar(&d, false, false);
        assert_eq!(ao_vivo.len(), 1);
        assert_eq!(
            (ao_vivo[0].nivel, &ao_vivo[0].estado),
            (Nivel::Contencao, &Estado::Planejada)
        );
        assert_eq!(ao_vivo[0].metodo, "net.block");
        assert_eq!(
            ao_vivo[0].params,
            r#"{"to":"tcp:10.0.2.100:7","owner":"process:9"}"#
        );
        assert_eq!(ao_vivo[0].autorizado_por, "service:nsf");
        // Da história, ou depois de uma recusa: só a recomendação.
        for (h, n) in [(true, false), (false, true), (true, true)] {
            let p = planejar(&d, h, n);
            assert_eq!(p.len(), 1);
            assert_eq!(
                (p[0].nivel, &p[0].estado),
                (Nivel::Autorizada, &Estado::Recomendada)
            );
        }
    }

    /// Revogar é do administrador: o NSF recomenda, nunca pede.
    #[test]
    fn revogar_e_recomendacao() {
        let p = planejar(
            &det(Regra::AbusoDeCredencial, None, Titular::Agente),
            false,
            false,
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].estado, Estado::Recomendada);
        assert!(p.iter().all(|a| a.estado != Estado::Planejada));
        // De outra identidade, ou outra regra: nada a pedir.
        assert!(
            planejar(
                &det(Regra::AbusoDeCredencial, None, Titular::Pessoa),
                false,
                false
            )
            .is_empty()
        );
        for r in Regra::TODAS {
            if r != Regra::SaidaDepoisDeSondagem {
                assert!(
                    planejar(&det(r, alvo(), Titular::Agente), false, false)
                        .iter()
                        .all(|a| a.estado != Estado::Planejada),
                    "{}",
                    r.nome()
                );
            }
        }
    }
}
