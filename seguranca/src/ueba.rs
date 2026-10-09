//! O perfil de comportamento de cada identidade (UEBA).
//!
//! # A conta
//!
//! Inteira e determinística. Os primeiros [`APRENDIZADO`] pedidos de uma
//! identidade fazem a linha de base — os métodos que ela usa e a proporção
//! de recusas; a taxa, quando a história dela tem [`HISTORIA_PARA_TAXA_MS`]
//! —, e daí em diante a janela de [`JANELA_MS`] é comparada com ela:
//!
//! - métodos que a base nunca viu, [`METODOS_NOVOS`] ou mais na janela;
//! - a proporção de recusas da janela, [`SALTO_DE_RECUSAS`] pontos
//!   percentuais acima da base, com ao menos [`MINIMO_PARA_PROPORCAO`]
//!   pedidos;
//! - a taxa da janela, [`MULTIPLO_DA_TAXA`] vezes a da base (com um piso),
//!   com ao menos [`MINIMO_PARA_TAXA`] pedidos.
//!
//! O tempo é o dos registros, nunca um relógio — e o dos registros é o
//! relógio lógico da auditoria, que anda de segundo em segundo
//! ([`RESOLUCAO_MS`]): uma duração medida nele ganha uma resolução, porque
//! `n` pedidos com o mesmo carimbo cabem num segundo, e não num
//! milissegundo. A rajada dos primeiros pedidos de quem acabou de chegar
//! não é o ritmo dele: a taxa da linha de base espera a história. Uma
//! anomalia não se repete dentro da mesma janela.
//!
//! # O que ela é
//!
//! Contexto. O perfil aparece no incidente, entra no risco e pode levar o
//! NSF a **pedir** algo — que o gate decide como decidiria o pedido de
//! qualquer um. Pessoas e agentes de IA têm o perfil pela mesma conta, sem
//! regra própria para nenhum dos dois. Um modelo aprendido que um dia
//! substitua a conta entra aqui, com a mesma saída e a mesma falta de
//! autoridade.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::evento::{Evento, Tipo, Titular};

/// Quantos pedidos fazem a linha de base.
pub const APRENDIZADO: u64 = 12;
/// A janela da comparação.
pub const JANELA_MS: u64 = 30_000;
/// A resolução do tempo dos registros: o relógio lógico da auditoria.
pub const RESOLUCAO_MS: u64 = 1_000;
/// Quanta história a taxa da linha de base precisa.
pub const HISTORIA_PARA_TAXA_MS: u64 = JANELA_MS;
/// Métodos novos na janela que fazem anomalia.
pub const METODOS_NOVOS: usize = 3;
/// Pontos percentuais de recusa acima da base que fazem anomalia.
pub const SALTO_DE_RECUSAS: u64 = 50;
/// Pedidos na janela para a proporção contar.
pub const MINIMO_PARA_PROPORCAO: usize = 6;
/// Quantas vezes a taxa da base faz anomalia.
pub const MULTIPLO_DA_TAXA: u64 = 4;
/// O piso da taxa da base, por minuto: uma base quieta não faz de qualquer
/// rajada uma anomalia.
pub const PISO_DA_TAXA: u64 = 6;
/// Pedidos na janela para a taxa contar.
pub const MINIMO_PARA_TAXA: usize = 10;
/// Quantos métodos distintos um perfil guarda.
const MAIS_METODOS: usize = 48;
/// Quantos recursos distintos um perfil conta.
const MAIS_RECURSOS: usize = 64;
/// Quantos pedidos a janela guarda.
const MAIS_NA_JANELA: usize = 128;
/// Quantos perfis.
pub const MAIS_PERFIS: usize = 64;

/// A linha de base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Base {
    pub metodos: BTreeSet<String>,
    /// A taxa, quando a história já tem [`HISTORIA_PARA_TAXA_MS`].
    pub por_minuto: Option<u64>,
    pub recusas_pct: u64,
}

/// Uma anomalia, com os motivos.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anomalia {
    pub motivos: Vec<String>,
}

/// O perfil de uma identidade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Perfil {
    pub principal: String,
    pub titular: Titular,
    pub pedidos: u64,
    pub recusas: u64,
    pub metodos: BTreeMap<String, u64>,
    pub recursos: BTreeSet<String>,
    pub primeiro_ms: u64,
    pub ultimo_ms: u64,
    pub base: Option<Base>,
    pub anomalias: u64,
    janela: VecDeque<(u64, String, bool)>,
    ultima_anomalia_ms: Option<u64>,
}

impl Perfil {
    fn novo(principal: &str, titular: Titular, ts: u64) -> Perfil {
        Perfil {
            principal: principal.to_string(),
            titular,
            pedidos: 0,
            recusas: 0,
            metodos: BTreeMap::new(),
            recursos: BTreeSet::new(),
            primeiro_ms: ts,
            ultimo_ms: ts,
            base: None,
            anomalias: 0,
            janela: VecDeque::new(),
            ultima_anomalia_ms: None,
        }
    }

    /// A proporção de recusas, em pontos percentuais.
    fn recusas_pct(pedidos: u64, recusas: u64) -> u64 {
        (recusas * 100).checked_div(pedidos).unwrap_or(0)
    }

    /// Conta um pedido; devolve a anomalia, se a janela saiu da base.
    fn observar(&mut self, e: &Evento) -> Option<Anomalia> {
        let negado = e.negado();
        self.pedidos += 1;
        self.recusas += u64::from(negado);
        self.ultimo_ms = self.ultimo_ms.max(e.ts_ms);
        if self.metodos.len() < MAIS_METODOS || self.metodos.contains_key(&e.metodo) {
            *self.metodos.entry(e.metodo.clone()).or_default() += 1;
        }
        if !e.recurso.is_empty() && self.recursos.len() < MAIS_RECURSOS {
            self.recursos.insert(e.recurso.clone());
        }
        // A janela anda com o tempo dos registros.
        self.janela.push_back((e.ts_ms, e.metodo.clone(), negado));
        while self.janela.len() > MAIS_NA_JANELA
            || self
                .janela
                .front()
                .is_some_and(|(t, _, _)| t + JANELA_MS < e.ts_ms)
        {
            self.janela.pop_front();
        }
        // A história, na resolução do relógio dos registros.
        let historia = self.ultimo_ms.saturating_sub(self.primeiro_ms) + RESOLUCAO_MS;
        let taxa = (historia >= HISTORIA_PARA_TAXA_MS).then(|| self.pedidos * 60_000 / historia);
        let Some(base) = &mut self.base else {
            if self.pedidos >= APRENDIZADO {
                self.base = Some(Base {
                    metodos: self.metodos.keys().cloned().collect(),
                    por_minuto: taxa,
                    recusas_pct: Self::recusas_pct(self.pedidos, self.recusas),
                });
            }
            return None;
        };
        if base.por_minuto.is_none() {
            base.por_minuto = taxa;
        }
        let base = &*base;
        if self
            .ultima_anomalia_ms
            .is_some_and(|t| e.ts_ms < t + JANELA_MS)
        {
            return None;
        }
        let mut motivos = Vec::new();
        let novos: BTreeSet<&str> = self
            .janela
            .iter()
            .map(|(_, m, _)| m.as_str())
            .filter(|m| !base.metodos.contains(*m))
            .collect();
        if novos.len() >= METODOS_NOVOS {
            motivos.push(alloc::format!(
                "{} metodos que a linha de base nunca viu",
                novos.len()
            ));
        }
        let n = self.janela.len();
        let recusas = self.janela.iter().filter(|(_, _, r)| *r).count();
        let pct = Self::recusas_pct(n as u64, recusas as u64);
        if n >= MINIMO_PARA_PROPORCAO && pct >= base.recusas_pct + SALTO_DE_RECUSAS {
            motivos.push(alloc::format!(
                "{pct}% de recusas na janela, contra {}% na linha de base",
                base.recusas_pct
            ));
        }
        if n >= MINIMO_PARA_TAXA
            && let Some(na_base) = base.por_minuto
        {
            let inicio = self.janela.front().map_or(e.ts_ms, |(t, _, _)| *t);
            let duracao = e.ts_ms.saturating_sub(inicio) + RESOLUCAO_MS;
            let por_minuto = n as u64 * 60_000 / duracao;
            let teto = MULTIPLO_DA_TAXA * na_base.max(PISO_DA_TAXA);
            if por_minuto >= teto {
                motivos.push(alloc::format!(
                    "{por_minuto} pedidos por minuto, contra {na_base} na linha de base"
                ));
            }
        }
        if motivos.is_empty() {
            return None;
        }
        self.anomalias += 1;
        self.ultima_anomalia_ms = Some(e.ts_ms);
        Some(Anomalia { motivos })
    }
}

/// Os perfis.
#[derive(Clone, Debug, Default)]
pub struct Ueba {
    perfis: BTreeMap<String, Perfil>,
    ordem: VecDeque<String>,
}

impl Ueba {
    pub fn novo() -> Ueba {
        Ueba::default()
    }

    /// Conta o evento no perfil de quem responde por ele. Só decisões de
    /// quem pede: o kernel, as leituras do próprio NSF e as execuções — que
    /// já foram contadas na decisão — não fazem perfil.
    pub fn observar(&mut self, e: &Evento) -> Option<Anomalia> {
        if e.tipo != Tipo::Decisao || matches!(e.titular, Titular::Kernel) {
            return None;
        }
        if !self.perfis.contains_key(&e.principal) {
            if self.ordem.len() == MAIS_PERFIS
                && let Some(velho) = self.ordem.pop_front()
            {
                self.perfis.remove(&velho);
            }
            self.ordem.push_back(e.principal.clone());
            self.perfis.insert(
                e.principal.clone(),
                Perfil::novo(&e.principal, e.titular, e.ts_ms),
            );
        }
        self.perfis.get_mut(&e.principal)?.observar(e)
    }

    /// O perfil de uma identidade.
    pub fn perfil(&self, principal: &str) -> Option<&Perfil> {
        self.perfis.get(principal)
    }

    /// Todos os perfis.
    pub fn perfis(&self) -> impl Iterator<Item = &Perfil> {
        self.perfis.values()
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::evento::Severidade;
    use politica::Codigo;

    fn ev(principal: &str, titular: Titular, ts: u64, metodo: &str, codigo: Codigo) -> Evento {
        Evento {
            seq: ts,
            elo: [0; 32],
            epoca: 0,
            ts_ms: ts,
            titular,
            principal: principal.to_string(),
            identificador: String::new(),
            chave: None,
            sessao: 0,
            sessao_de_pessoa: None,
            papel: "operador".to_string(),
            metodo: metodo.to_string(),
            recurso: String::new(),
            codigo,
            detalhe: String::new(),
            processo: None,
            decisao: None,
            tipo: Tipo::Decisao,
            correlacao: 0,
            severidade: Severidade::Info,
        }
    }

    /// Uma linha de base calma, e depois uma janela de métodos novos e
    /// recusados.
    fn sequencia(principal: &str, titular: Titular) -> Vec<Option<Anomalia>> {
        let mut u = Ueba::novo();
        let mut saida = Vec::new();
        let mut ts = 0;
        for i in 0..APRENDIZADO {
            ts += 5_000;
            let m = if i % 2 == 0 {
                "agent.ping"
            } else {
                "system.info"
            };
            saida.push(u.observar(&ev(principal, titular, ts, m, Codigo::Allow)));
        }
        for m in [
            "fs.read",
            "policy.show",
            "disk.read",
            "audit.tail",
            "keyboard.read",
            "ui.act",
        ] {
            ts += 1_000;
            saida.push(u.observar(&ev(principal, titular, ts, m, Codigo::DenyPermission)));
        }
        saida
    }

    #[test]
    fn a_linha_de_base_e_a_anomalia() {
        let s = sequencia("agent:aa", Titular::Agente);
        // Nada enquanto aprende.
        assert!(s[..APRENDIZADO as usize].iter().all(Option::is_none));
        let anomalias: Vec<_> = s.iter().flatten().collect();
        // Uma só: dentro da janela ela não se repete.
        assert_eq!(anomalias.len(), 1, "{anomalias:?}");
        assert!(anomalias[0].motivos.iter().any(|m| m.contains("nunca viu")));
    }

    /// A mesma sequência, de uma pessoa e de um agente: a mesma conta.
    #[test]
    fn pessoa_e_agente_pela_mesma_conta() {
        assert_eq!(
            sequencia("agent:aa", Titular::Agente),
            sequencia("person:01", Titular::Pessoa)
        );
    }

    #[test]
    fn a_taxa() {
        let mut u = Ueba::novo();
        let mut ts = 0;
        for _ in 0..APRENDIZADO {
            ts += 10_000;
            assert!(
                u.observar(&ev(
                    "serial",
                    Titular::Serial,
                    ts,
                    "agent.ping",
                    Codigo::Allow
                ))
                .is_none()
            );
        }
        let mut achou = None;
        for _ in 0..MINIMO_PARA_TAXA + 2 {
            ts += 100;
            if let Some(a) = u.observar(&ev(
                "serial",
                Titular::Serial,
                ts,
                "agent.ping",
                Codigo::Allow,
            )) {
                achou = Some(a);
            }
        }
        let a = achou.expect("a rajada e anomalia");
        assert!(a.motivos.iter().any(|m| m.contains("por minuto")), "{a:?}");
        // E o perfil guarda o que viu.
        let p = u.perfil("serial").unwrap();
        assert_eq!(
            p.metodos.get("agent.ping"),
            Some(&(APRENDIZADO + MINIMO_PARA_TAXA as u64 + 2))
        );
        assert_eq!(p.anomalias, 1);
    }

    /// Quem acabou de chegar e pede em rajada — tudo no mesmo segundo do
    /// relógio dos registros — não tem taxa na linha de base ainda: a
    /// rajada não é anomalia. A conta da taxa vem quando a história chega.
    #[test]
    fn a_rajada_de_quem_chegou_nao_e_taxa() {
        let mut u = Ueba::novo();
        for _ in 0..APRENDIZADO + 200 {
            assert!(
                u.observar(&ev(
                    "system",
                    Titular::Sistema,
                    7_000,
                    "system.info",
                    Codigo::Allow
                ))
                .is_none()
            );
        }
        let p = u.perfil("system").unwrap();
        assert_eq!(p.base.as_ref().map(|b| b.por_minuto), Some(None));
        // Com a história, a taxa entra: duzentos e doze pedidos em 31 s.
        assert!(
            u.observar(&ev(
                "system",
                Titular::Sistema,
                37_000,
                "system.info",
                Codigo::Allow
            ))
            .is_none()
        );
        let p = u.perfil("system").unwrap();
        assert_eq!(
            p.base.as_ref().and_then(|b| b.por_minuto),
            Some((APRENDIZADO + 201) * 60_000 / 31_000)
        );
    }

    /// Quem pede dez por segundo, pára, e volta com dez no mesmo segundo
    /// está no ritmo de sempre: no relógio dos registros, dez pedidos com o
    /// mesmo carimbo cabem num segundo — e não num milissegundo.
    #[test]
    fn a_rajada_no_mesmo_segundo_e_o_ritmo_de_sempre() {
        let mut u = Ueba::novo();
        let mut ts = 0;
        // Quarenta segundos a dez por segundo: a linha de base, com a taxa.
        for _ in 0..40 {
            ts += 1_000;
            for _ in 0..10 {
                u.observar(&ev(
                    "serial",
                    Titular::Serial,
                    ts,
                    "agent.ping",
                    Codigo::Allow,
                ));
            }
        }
        assert!(
            u.perfil("serial")
                .and_then(|p| p.base.as_ref())
                .and_then(|b| b.por_minuto)
                .is_some_and(|t| t >= 500),
            "{:?}",
            u.perfil("serial").map(|p| &p.base)
        );
        // Quieto além da janela, e dez de novo, no mesmo segundo.
        ts += JANELA_MS + 5_000;
        for _ in 0..10 {
            assert!(
                u.observar(&ev(
                    "serial",
                    Titular::Serial,
                    ts,
                    "agent.ping",
                    Codigo::Allow
                ))
                .is_none()
            );
        }
    }

    /// As execuções e o kernel não fazem perfil.
    #[test]
    fn so_decisoes_de_quem_pede() {
        let mut u = Ueba::novo();
        let mut e = ev("kernel", Titular::Kernel, 1, "policy.load", Codigo::Allow);
        u.observar(&e);
        e = ev("agent:aa", Titular::Agente, 1, "fs.write", Codigo::Allow);
        e.tipo = Tipo::Execucao;
        u.observar(&e);
        assert_eq!(u.perfis().count(), 0);
    }
}
