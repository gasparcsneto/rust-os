//! O risco de uma identidade: uma soma de fatores, cada um com o motivo.
//!
//! # A conta
//!
//! Sobre os eventos da identidade na janela de [`JANELA_MS`] — pelo tempo
//! dos registros —, as detecções abertas dela e o perfil de comportamento.
//! Cada fator tem peso e teto, e o total tem teto 100. A mesma entrada dá
//! sempre o mesmo número, e o número vem com a lista do que o compôs: um
//! risco sem explicação não serve a quem investiga.
//!
//! # A repetição não infla
//!
//! As recusas, os recursos fora do alcance e os destinos barrados contam
//! **distintos**: um agente repetindo o mesmo pedido recusado não
//! transforma a recusa em risco — a explicação disse a ele que repetir não
//! adianta, e a taxa do papel já o segura. As falhas de autenticação
//! contam todas: o volume é o sinal da força bruta.
//!
//! # O que ele não é
//!
//! Autorização. Nenhum risco abre nada nem fecha nada: o gate não o lê. Ele
//! ordena o que um humano olha, e entra no que o NSF **pede** — e o pedido
//! passa pelo gate como o de qualquer um.

use alloc::string::String;
use alloc::vec::Vec;

use politica::Codigo;

use crate::evento::{Evento, Severidade, Tipo};

/// A janela dos fatores.
pub const JANELA_MS: u64 = 60_000;

/// Um fator do risco.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fator {
    pub nome: &'static str,
    pub pontos: u32,
    pub motivo: String,
}

/// O risco de uma identidade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Risco {
    pub pontos: u32,
    pub fatores: Vec<Fator>,
}

/// Um fator de `n` ocorrências, `peso` cada, até `teto`.
fn fator(
    fatores: &mut Vec<Fator>,
    nome: &'static str,
    n: usize,
    peso: u32,
    teto: u32,
    motivo: String,
) {
    if n == 0 {
        return;
    }
    let pontos = (n as u32).saturating_mul(peso).min(teto);
    fatores.push(Fator {
        nome,
        pontos,
        motivo,
    });
}

/// Quantos distintos há.
fn distintos<T: Ord>(v: impl Iterator<Item = T>) -> usize {
    v.collect::<alloc::collections::BTreeSet<T>>().len()
}

/// O risco, dados os eventos da identidade (qualquer ordem; os da janela
/// contam, medida a partir do mais novo), as severidades das detecções
/// abertas dela, e se o perfil dela está em anomalia.
pub fn avaliar(eventos: &[&Evento], deteccoes: &[Severidade], anomalia: bool) -> Risco {
    let agora = eventos.iter().map(|e| e.ts_ms).max().unwrap_or(0);
    let na_janela: Vec<&&Evento> = eventos
        .iter()
        .filter(|e| e.ts_ms + JANELA_MS >= agora && e.tipo == Tipo::Decisao)
        .collect();
    let conta = |c: Codigo| na_janela.iter().filter(|e| e.codigo == c).count();
    let mut fatores = Vec::new();

    let recusadas: Vec<&&&Evento> = na_janela.iter().filter(|e| e.negado()).collect();
    let distintas = distintos(
        recusadas
            .iter()
            .map(|e| (e.metodo.as_str(), e.recurso.as_str(), e.codigo as u8)),
    );
    fator(
        &mut fatores,
        "denials",
        distintas,
        2,
        20,
        alloc::format!(
            "{distintas} pedidos distintos recusados na janela ({} recusas)",
            recusadas.len()
        ),
    );

    let fora = distintos(
        na_janela
            .iter()
            .filter(|e| e.codigo == Codigo::DenyResource)
            .map(|e| (e.metodo.as_str(), e.recurso.as_str())),
    );
    fator(
        &mut fatores,
        "out_of_scope",
        fora,
        4,
        24,
        alloc::format!("{fora} pedidos distintos fora do alcance"),
    );

    let mut sondadas: Vec<&str> = na_janela
        .iter()
        .filter(|e| e.codigo == Codigo::DenyPermission && !e.fora_do_manifesto())
        .map(|e| e.metodo.as_str())
        .collect();
    sondadas.sort_unstable();
    sondadas.dedup();
    fator(
        &mut fatores,
        "permission_probing",
        sondadas.len(),
        6,
        30,
        alloc::format!("{} metodos sem permissao tentados", sondadas.len()),
    );

    let autenticacao = conta(Codigo::DenyNotAuthenticated);
    fator(
        &mut fatores,
        "authentication",
        autenticacao,
        8,
        32,
        alloc::format!("{autenticacao} pedidos sem autenticacao valida"),
    );

    let firewall = distintos(
        eventos
            .iter()
            .filter(|e| e.ts_ms + JANELA_MS >= agora && matches!(e.tipo, Tipo::Firewall { .. }))
            .map(|e| e.recurso.as_str()),
    );
    fator(
        &mut fatores,
        "firewall",
        firewall,
        10,
        30,
        alloc::format!("{firewall} destinos barrados pelo firewall"),
    );

    let pontos_das_deteccoes: u32 = deteccoes
        .iter()
        .map(|s| match s {
            Severidade::Critica => 40,
            Severidade::Alta => 25,
            Severidade::Media => 10,
            _ => 0,
        })
        .sum();
    if pontos_das_deteccoes > 0 {
        fatores.push(Fator {
            nome: "detections",
            pontos: pontos_das_deteccoes.min(50),
            motivo: alloc::format!("{} deteccoes abertas", deteccoes.len()),
        });
    }

    if anomalia {
        fatores.push(Fator {
            nome: "anomaly",
            pontos: 15,
            motivo: String::from("o perfil de comportamento saiu da linha de base"),
        });
    }

    let pontos = fatores.iter().map(|f| f.pontos).sum::<u32>().min(100);
    Risco { pontos, fatores }
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::evento::Titular;
    use alloc::string::ToString;

    fn ev(ts: u64, metodo: &str, codigo: Codigo, tipo: Tipo) -> Evento {
        Evento {
            seq: ts,
            elo: [0; 32],
            epoca: 0,
            ts_ms: ts,
            titular: Titular::Agente,
            principal: "agent:aa".to_string(),
            identificador: String::new(),
            chave: None,
            sessao: 1,
            sessao_de_pessoa: None,
            papel: "operador".to_string(),
            metodo: metodo.to_string(),
            recurso: String::new(),
            codigo,
            detalhe: String::new(),
            processo: None,
            decisao: None,
            tipo,
            correlacao: 0,
            severidade: Severidade::Info,
        }
    }

    #[test]
    fn os_fatores_explicam_o_numero() {
        let evs = [
            ev(1_000, "fs.read", Codigo::DenyPermission, Tipo::Decisao),
            ev(2_000, "policy.show", Codigo::DenyPermission, Tipo::Decisao),
            ev(3_000, "fs.read", Codigo::DenyPermission, Tipo::Decisao),
            ev(4_000, "net.connect", Codigo::DenyResource, Tipo::Decisao),
            ev(5_000, "agent.ping", Codigo::Allow, Tipo::Decisao),
        ];
        let refs: Vec<&Evento> = evs.iter().collect();
        let r = avaliar(&refs, &[], false);
        let nomes: Vec<&str> = r.fatores.iter().map(|f| f.nome).collect();
        assert_eq!(nomes, ["denials", "out_of_scope", "permission_probing"]);
        // 3 recusas distintas × 2 + 1 fora × 4 + 2 métodos × 6.
        assert_eq!(r.pontos, 6 + 4 + 12);
        assert_eq!(r.pontos, r.fatores.iter().map(|f| f.pontos).sum());
    }

    /// O agente que repete o mesmo pedido recusado cem vezes tem o risco de
    /// quem foi recusado uma vez — e a explicação diz quantas foram.
    #[test]
    fn a_repeticao_nao_infla() {
        let uma = [ev(1_000, "fs.read", Codigo::DenyResource, Tipo::Decisao)];
        let cem: Vec<Evento> = (0..100)
            .map(|i| {
                ev(
                    1_000 + i * 10,
                    "fs.read",
                    Codigo::DenyResource,
                    Tipo::Decisao,
                )
            })
            .collect();
        let r1 = avaliar(&uma.iter().collect::<Vec<_>>(), &[], false);
        let r100 = avaliar(&cem.iter().collect::<Vec<_>>(), &[], false);
        assert_eq!(r1.pontos, r100.pontos);
        assert!(
            r100.fatores[0].motivo.contains("(100 recusas)"),
            "{:?}",
            r100.fatores
        );
    }

    /// O que saiu da janela não conta; o teto segura o total.
    #[test]
    fn janela_e_teto() {
        let velho = ev(0, "x", Codigo::DenyNotAuthenticated, Tipo::Decisao);
        let novo = ev(JANELA_MS + 1, "agent.ping", Codigo::Allow, Tipo::Decisao);
        let r = avaliar(&[&velho, &novo], &[], false);
        assert_eq!(r.pontos, 0);
        let metodos: Vec<String> = (0..50).map(|i| alloc::format!("x{i}")).collect();
        let muitos: Vec<Evento> = metodos
            .iter()
            .enumerate()
            .map(|(i, m)| ev(i as u64, m, Codigo::DenyNotAuthenticated, Tipo::Decisao))
            .collect();
        let refs: Vec<&Evento> = muitos.iter().collect();
        let r = avaliar(&refs, &[Severidade::Critica, Severidade::Alta], true);
        assert_eq!(r.pontos, 100);
    }

    /// A mesma entrada, o mesmo risco — em qualquer ordem.
    #[test]
    fn deterministico() {
        let a = ev(1, "fs.read", Codigo::DenyPermission, Tipo::Decisao);
        let b = ev(2, "x", Codigo::Allow, Tipo::Firewall { regra: 1 });
        assert_eq!(
            avaliar(&[&a, &b], &[Severidade::Media], true),
            avaliar(&[&b, &a], &[Severidade::Media], true)
        );
    }
}
