//! O tempo, como a auditoria o conta: o estado do relógio civil e o que as
//! fontes de hora responderam, lidos dos registros de `time.sync` e
//! `time.confirm` — o NSF lê o tempo dos registros, nunca de um relógio.
//!
//! # O que se lê
//!
//! O kernel grava, a cada `time.sync`, um registro de execução com o
//! veredito da resposta — o código diz a classe: `ALLOW` aceita,
//! `DENY_CREDENTIAL` assinatura ou delegação que a chave fixada não fecha,
//! `DENY_REPLAY` nonce ou pedido que não são deste, `INVALID_ARGUMENT`
//! forma, `ERROR` sem resposta ou vencida. Na última fonte da rodada, outro
//! com o recurso `civil <antes>><depois> logico <antes>><depois>
//! <estado>><estado> [pendente] [divergente] [adiantado]` e o detalhe
//! `r<N> <desfecho> [<cobertura>/<aceitas> d<±Δ> u<u>] <efeito>`. E o
//! `time.confirm` executado, com o recurso `salto <desvio> r<N> civil
//! <antes>><depois> logico <antes>><depois>`. Só o kernel escreve esses
//! recursos: o de uma execução é do tratador, e não de quem pediu.
//!
//! # As regras de tempo
//!
//! As do desenho do tempo (§9.3), cada uma uma vez por acontecimento — o
//! salto da rodada, a entrada no estado, a primeira recusa de uma fonte —,
//! e não uma por rodada que o repete:
//!
//! - [`Regra::SaltoDoRelogio`]: o salto que o envelope explica, ou o da
//!   primeira sincronização — a gravidade pelo tamanho; a confiança é
//!   baixa, porque é o relógio sendo corrigido;
//! - [`Regra::SaltoAlemDoEnvelope`]: o salto que a incerteza não explica —
//!   o contador derivou, ou as fontes se moveram juntas;
//! - [`Regra::SaltoPendente`]: o salto que só uma pessoa confirma, com a
//!   recomendação do `time.confirm` da rodada;
//! - [`Regra::FonteDivergente`]: uma fonte fora do acordo, com os
//!   registros dos vereditos da rodada — os resumos das respostas;
//! - [`Regra::AssinaturaDaFonte`]: uma resposta que a chave fixada não
//!   fecha — forjada, ou a chave da fonte foi trocada;
//! - [`Regra::HoraNaoAutenticada`]: a hora vencida, ou nunca autenticada
//!   em [`RODADAS_SEM_HORA`] rodadas de um boot;
//! - [`Regra::LogicoParado`]: o tempo lógico parado à frente do civil.
//!
//! Elas só registram e recomendam. O NSF não ganha autoridade sobre o
//! relógio, não bloqueia fonte nenhuma — quem forja respostas ruins não
//! escolhe o que o NSF corta —, não cria autorização. O principal delas é
//! [`PRINCIPAL`], o relógio, e não o serviço de hora: o serviço, como
//! titular, não é alvo de regra nem de resposta — ver `crate::motor`.
//!
//! # O lógico parado
//!
//! Quando o civil volta para trás do piso — o salto para trás, a primeira
//! sincronização de um RTC adiantado, a confirmação de um pendente —, o
//! lógico para, e os carimbos da auditoria param com ele. O registro que
//! mostra isso — a marca `adiantado`, ou o lógico depois do civil numa
//! confirmação — dá o carimbo em que ele parou; o primeiro registro com um
//! carimbo maior diz que ele voltou a andar. Enquanto parado, as janelas
//! das regras juntam o que no relógio está separado: o motor marca o que
//! elas contam, e a contenção por taxa fica suspensa — ver
//! [`crate::incidente::Incidente::corroboracao_para_conter`].

use alloc::collections::{BTreeSet, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use politica::Codigo;

use crate::evento::{Evento, Severidade, Tipo, Titular, ler_detalhe};
use crate::regras::{Confianca, Deteccao, Regra};

/// O principal das detecções de tempo: o relógio do sistema, e não quem o
/// move.
pub const PRINCIPAL: &str = "clock";

/// Quantas rodadas fechadas no `rtc`, num boot, dizem que a hora nunca foi
/// autenticada.
pub const RODADAS_SEM_HORA: u64 = 3;

/// O salto a partir do qual a gravidade é média, e alta.
pub const SALTO_MEDIO_MS: u64 = 60_000;
pub const SALTO_GRANDE_MS: u64 = 3_600_000;

/// Quantos vereditos recentes ficam para a evidência de uma rodada: as
/// fontes de duas rodadas — o registro tem até oito.
const MAIS_VEREDITOS: usize = 16;
/// Quantas fontes com a assinatura recusada se acompanham.
const MAIS_FONTES: usize = 8;

/// O tempo que a auditoria conta.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tempo {
    /// O estado do civil depois da última rodada que fechou: `rtc`,
    /// `sincronizado`, `holdover`, `vencido`.
    pub estado: Option<String>,
    /// As marcas da última rodada que fechou.
    pub pendente: bool,
    pub divergente: bool,
    pub adiantado: bool,
    /// Quantas rodadas fecharam, e o registro da última.
    pub rodadas: u64,
    pub ultima_rodada: Option<u64>,
    /// As respostas entregues, pela classe do veredito.
    pub aceitas: u64,
    pub assinatura_invalida: u64,
    pub repetidas: u64,
    pub malformadas: u64,
    pub sem_resposta: u64,
    /// Saltos pendentes que uma pessoa confirmou.
    pub saltos_confirmados: u64,
    /// O carimbo do registro em que o tempo lógico apareceu parado à frente
    /// do civil; `None` com ele andando.
    pub parado_em_ms: Option<u64>,
    /// As fontes com uma assinatura recusada desde a última resposta aceita
    /// de cada uma.
    assinaturas_recusadas: BTreeSet<String>,
    /// Os vereditos recentes, com quem os entregou: a evidência da rodada.
    vereditos: VecDeque<(String, u64)>,
    /// O boot, quantas rodadas dele fecharam no `rtc`, e se a hora já foi
    /// autenticada nele — ou a regra já disse que não.
    sem_hora: (u32, u64, bool),
}

/// O desfecho de uma rodada, como o registro do fechamento o diz.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Fechamento {
    civil_ms: (u64, u64),
    logico_s: (u64, u64),
    antes: String,
    depois: String,
    pendente: bool,
    divergente: bool,
    adiantado: bool,
    rodada: Option<u64>,
    /// `acordo`, `sem_quorum`, `empate`, `invalido`.
    desfecho: String,
    /// `<cobertura>/<aceitas>`, no acordo.
    contagem: Option<String>,
    /// O desvio do acordo, no acordo.
    desvio_ms: Option<i64>,
    /// `nada`, `gradual`, `candidato`, `salto`, `salto_alem`, `pendente`,
    /// `sem_acordo`.
    efeito: String,
}

/// `a>b`, em números.
fn par(texto: &str) -> Option<(u64, u64)> {
    let (a, b) = texto.split_once('>')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

impl Fechamento {
    /// O recurso sem o `civil ` do começo, e o detalhe sem o processo e a
    /// decisão. `None` se o recurso não é o de um fechamento.
    fn ler(recurso: &str, detalhe: &str) -> Option<Fechamento> {
        let mut partes = recurso.split(' ');
        let civil_ms = par(partes.next()?)?;
        if partes.next()? != "logico" {
            return None;
        }
        let logico_s = par(partes.next()?)?;
        let (antes, depois) = partes.next()?.split_once('>')?;
        let (mut pendente, mut divergente, mut adiantado) = (false, false, false);
        for marca in partes {
            match marca {
                "pendente" => pendente = true,
                "divergente" => divergente = true,
                "adiantado" => adiantado = true,
                _ => {}
            }
        }
        let palavras: Vec<&str> = detalhe.split(' ').collect();
        let rodada = palavras
            .first()
            .and_then(|r| r.strip_prefix('r'))
            .and_then(|n| n.parse().ok());
        let desfecho = palavras.get(1).map_or_else(String::new, |d| d.to_string());
        let efeito = match palavras.as_slice() {
            [_, _, .., e] => e.to_string(),
            _ => String::new(),
        };
        let contagem = (desfecho == "acordo")
            .then(|| palavras.get(2).map(|c| c.to_string()))
            .flatten();
        let desvio_ms = palavras
            .iter()
            .find_map(|p| p.strip_prefix('d').filter(|d| d.starts_with(['+', '-'])))
            .and_then(|d| d.strip_prefix('+').unwrap_or(d).parse().ok());
        Some(Fechamento {
            civil_ms,
            logico_s,
            antes: antes.to_string(),
            depois: depois.to_string(),
            pendente,
            divergente,
            adiantado,
            rodada,
            desfecho,
            contagem,
            desvio_ms,
            efeito,
        })
    }

    /// `r<N> `, para as explicações.
    fn nome(&self) -> String {
        self.rodada
            .map_or_else(String::new, |r| alloc::format!("r{r} "))
    }

    /// O tamanho do salto: o desvio do acordo, ou o quanto o civil andou.
    fn salto_ms(&self) -> i64 {
        self.desvio_ms.unwrap_or_else(|| {
            let d = i128::from(self.civil_ms.1) - i128::from(self.civil_ms.0);
            d.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
        })
    }
}

/// `+12.345 s`.
fn segundos(ms: i64) -> String {
    let sinal = if ms < 0 { '-' } else { '+' };
    let a = ms.unsigned_abs();
    alloc::format!("{sinal}{}.{:03} s", a / 1000, a % 1000)
}

/// Uma detecção de tempo do registro `e`.
fn deteccao(
    e: &Evento,
    regra: Regra,
    (severidade, confianca): (Severidade, Confianca),
    registros: Vec<u64>,
    explicacao: String,
) -> Deteccao {
    Deteccao {
        regra,
        severidade,
        confianca,
        principal: PRINCIPAL.to_string(),
        titular: Titular::Kernel,
        registros,
        explicacao,
        alvo: None,
        ts_ms: e.ts_ms,
        epoca: e.epoca,
        logico_parado: false,
        rodada: None,
    }
}

impl Tempo {
    /// Um registro, de qualquer titular: só os de tempo contam. Devolve as
    /// detecções de tempo que ele dá, em ordem.
    pub fn observar(&mut self, e: &Evento) -> Vec<Deteccao> {
        let mut v = Vec::new();
        // Um carimbo depois daquele em que o lógico parou: ele voltou a
        // andar.
        if self.parado_em_ms.is_some_and(|t| e.ts_ms > t) {
            self.parado_em_ms = None;
        }
        match e.metodo.as_str() {
            "time.sync" if e.tipo == Tipo::Execucao => match e.recurso.strip_prefix("civil ") {
                Some(resto) => self.fechamento(e, resto, &mut v),
                None => self.veredito(e, &mut v),
            },
            "time.confirm" if e.codigo == Codigo::Allow && e.recurso.starts_with("salto ") => {
                self.saltos_confirmados += 1;
                self.confirmacao(e, &mut v);
            }
            _ => {}
        }
        v
    }

    /// Se o tempo lógico está parado à frente do civil, pelo que os
    /// registros mostram.
    pub fn parado(&self) -> bool {
        self.parado_em_ms.is_some()
    }

    /// O desfecho de uma rodada, e as regras dele.
    fn fechamento(&mut self, e: &Evento, resto: &str, v: &mut Vec<Deteccao>) {
        let Some(f) = Fechamento::ler(resto, &ler_detalhe(&e.detalhe).resto) else {
            return;
        };
        // Os vereditos desta rodada: os de quem a fechou, desde a anterior.
        let mut da_rodada: Vec<u64> = self
            .vereditos
            .iter()
            .filter(|(p, _)| *p == e.principal)
            .map(|(_, s)| *s)
            .collect();
        self.vereditos.retain(|(p, _)| *p != e.principal);
        da_rodada.push(e.seq);
        let nome = f.nome();
        let contagem = f
            .contagem
            .as_deref()
            .map_or_else(String::new, |c| alloc::format!(", {c} das fontes"));

        match f.efeito.as_str() {
            "salto" => {
                let salto = f.salto_ms();
                let tamanho = salto.unsigned_abs();
                let severidade = if tamanho >= SALTO_GRANDE_MS {
                    Severidade::Alta
                } else if tamanho >= SALTO_MEDIO_MS {
                    Severidade::Media
                } else {
                    Severidade::Baixa
                };
                let porque = if f.antes == "rtc" {
                    "a primeira hora autenticada corrigiu o RTC"
                } else {
                    "dentro do envelope da incerteza"
                };
                v.push(deteccao(
                    e,
                    Regra::SaltoDoRelogio,
                    (severidade, Confianca::Baixa),
                    alloc::vec![e.seq],
                    alloc::format!(
                        "o relogio civil pulou {} na rodada {nome}pelo acordo{contagem}: {porque}",
                        segundos(salto)
                    ),
                ));
            }
            "salto_alem" => v.push(deteccao(
                e,
                Regra::SaltoAlemDoEnvelope,
                (Severidade::Alta, Confianca::Media),
                alloc::vec![e.seq],
                alloc::format!(
                    "o relogio civil pulou {} na rodada {nome}para fora do envelope{contagem}: a hora autenticada estava mais longe do que a incerteza dela dizia — o contador derivou, ou as fontes se moveram juntas",
                    segundos(f.salto_ms())
                ),
            )),
            "pendente" if !self.pendente => {
                let mut d = deteccao(
                    e,
                    Regra::SaltoPendente,
                    (Severidade::Alta, Confianca::Media),
                    alloc::vec![e.seq],
                    alloc::format!(
                        "a rodada {nome}pediu um salto de {} que so uma pessoa confirma{contagem}: acima do teto, ou para tras fora do envelope; o civil nao se move ate um time.confirm com prova",
                        segundos(f.salto_ms())
                    ),
                );
                d.rodada = f.rodada;
                v.push(d);
            }
            _ => {}
        }

        if f.divergente && !self.divergente {
            v.push(deteccao(
                e,
                Regra::FonteDivergente,
                (Severidade::Media, Confianca::Media),
                da_rodada,
                alloc::format!(
                    "na rodada {nome}as fontes nao concordaram todas ({}{}): o civil seguiu o acordo, se houve; os resumos das respostas estao nos registros dos vereditos",
                    f.desfecho,
                    f.contagem
                        .as_deref()
                        .map_or_else(String::new, |c| alloc::format!(" {c}"))
                ),
            ));
        }

        // Vencida: a entrada no estado — vista na rodada, ou antes dela.
        if self.estado.as_deref() != Some("vencido")
            && (f.antes == "vencido" || f.depois == "vencido")
        {
            let quando = if f.depois == "vencido" {
                "TLS e cookies conferem pelo tempo logico ate as fontes voltarem"
            } else {
                "venceu antes da rodada, e a rodada a trouxe de volta"
            };
            v.push(deteccao(
                e,
                Regra::HoraNaoAutenticada,
                (Severidade::Media, Confianca::Media),
                alloc::vec![e.seq],
                alloc::format!(
                    "a hora autenticada venceu: a incerteza passou do teto do registro; {quando}"
                ),
            ));
        }

        // Nunca autenticada: tantas rodadas de um boot, e o civil ainda é o
        // RTC.
        if self.sem_hora.0 != e.epoca {
            self.sem_hora = (e.epoca, 0, false);
        }
        if f.depois != "rtc" {
            self.sem_hora.2 = true;
        } else if !self.sem_hora.2 {
            self.sem_hora.1 += 1;
            if self.sem_hora.1 >= RODADAS_SEM_HORA {
                self.sem_hora.2 = true;
                v.push(deteccao(
                    e,
                    Regra::HoraNaoAutenticada,
                    (Severidade::Media, Confianca::Baixa),
                    alloc::vec![e.seq],
                    alloc::format!(
                        "{} rodadas neste boot, e a hora nunca foi autenticada: o civil e o RTC, e TLS e cookies conferem pelo tempo logico",
                        self.sem_hora.1
                    ),
                ));
            }
        }

        if f.adiantado {
            self.parou(e, f.logico_s.1, f.civil_ms.1, v);
        } else {
            self.parado_em_ms = None;
        }

        self.estado = Some(f.depois);
        self.pendente = f.pendente;
        self.divergente = f.divergente;
        self.adiantado = f.adiantado;
        self.rodadas += 1;
        self.ultima_rodada = Some(e.seq);
    }

    /// O lógico, `logico_s`, à frente do civil, `civil_ms`, no registro
    /// `e`: parado. A regra diz quando ele para, e não a cada registro que
    /// o mostra parado.
    fn parou(&mut self, e: &Evento, logico_s: u64, civil_ms: u64, v: &mut Vec<Deteccao>) {
        let parou_em = e.ts_ms.max(logico_s.saturating_mul(1000));
        if self.parado_em_ms.is_none() {
            let frente = logico_s.saturating_mul(1000).saturating_sub(civil_ms);
            v.push(deteccao(
                e,
                Regra::LogicoParado,
                (Severidade::Media, Confianca::Media),
                alloc::vec![e.seq],
                alloc::format!(
                    "o tempo logico parou {} a frente do civil: os prazos nao vencem, os carimbos da auditoria se repetem, e a contencao por taxa fica suspensa ate ele voltar a andar",
                    segundos(i64::try_from(frente).unwrap_or(i64::MAX)).trim_start_matches('+')
                ),
            ));
        }
        self.parado_em_ms = Some(self.parado_em_ms.map_or(parou_em, |t| t.max(parou_em)));
    }

    /// Um salto pendente confirmado: o civil e o lógico depois dele.
    fn confirmacao(&mut self, e: &Evento, v: &mut Vec<Deteccao>) {
        let mut partes = e.recurso.split(' ');
        let civil = partes
            .position(|p| p == "civil")
            .and_then(|_| partes.next());
        let logico = partes.next().filter(|p| *p == "logico").and(partes.next());
        let (Some((_, civil_ms)), Some((_, logico_s))) =
            (civil.and_then(par), logico.and_then(par))
        else {
            return;
        };
        if logico_s > civil_ms / 1000 {
            self.parou(e, logico_s, civil_ms, v);
        }
    }

    /// O veredito de uma entrega. O registro de uma entrega para um id
    /// que não existe (`id N`) e o de uma rodada descartada (`civil`) não
    /// são respostas de fonte nenhuma.
    fn veredito(&mut self, e: &Evento, v: &mut Vec<Deteccao>) {
        if e.recurso == "civil" {
            // A rodada descartada: os vereditos dela não são de outra.
            self.vereditos.retain(|(p, _)| *p != e.principal);
            return;
        }
        if e.recurso.starts_with("id ") {
            return;
        }
        if self.vereditos.len() == MAIS_VEREDITOS {
            self.vereditos.pop_front();
        }
        self.vereditos.push_back((e.principal.clone(), e.seq));
        let fonte = e.recurso.split(' ').next().unwrap_or_default();
        match e.codigo {
            Codigo::Allow => {
                self.aceitas += 1;
                self.assinaturas_recusadas.remove(fonte);
            }
            Codigo::DenyCredential => {
                self.assinatura_invalida += 1;
                if !self.assinaturas_recusadas.contains(fonte)
                    && self.assinaturas_recusadas.len() < MAIS_FONTES
                {
                    self.assinaturas_recusadas.insert(fonte.to_string());
                    let recusa = ler_detalhe(&e.detalhe)
                        .resto
                        .split(' ')
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    v.push(deteccao(
                        e,
                        Regra::AssinaturaDaFonte,
                        (Severidade::Alta, Confianca::Media),
                        alloc::vec![e.seq],
                        alloc::format!(
                            "a resposta de `{fonte}` nao fecha com a chave fixada no registro ({recusa}): forjada, ou a chave da fonte foi trocada; o NSF nao corta a fonte — quem forja nao escolhe o que ele bloqueia"
                        ),
                    ));
                }
            }
            Codigo::DenyReplay => self.repetidas += 1,
            Codigo::InvalidArgument => self.malformadas += 1,
            Codigo::Error => self.sem_resposta += 1,
            _ => {}
        }
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn o_fechamento_se_le() {
        let f = Fechamento::ler(
            "1000>3601000 logico 5>3601 rtc>sincronizado pendente adiantado",
            "r4 acordo 2/3 d+3600000 u980 salto",
        )
        .unwrap();
        assert_eq!(f.civil_ms, (1000, 3_601_000));
        assert_eq!(f.logico_s, (5, 3601));
        assert_eq!(
            (f.antes.as_str(), f.depois.as_str()),
            ("rtc", "sincronizado")
        );
        assert!(f.pendente && !f.divergente && f.adiantado);
        assert_eq!(f.rodada, Some(4));
        assert_eq!(f.desfecho, "acordo");
        assert_eq!(f.contagem.as_deref(), Some("2/3"));
        assert_eq!(f.desvio_ms, Some(3_600_000));
        assert_eq!(f.efeito, "salto");
        assert_eq!(f.salto_ms(), 3_600_000);
        // Sem acordo, o desvio é o que o civil andou.
        let g = Fechamento::ler(
            "10>5 logico 9>9 holdover>vencido",
            "r7 sem_quorum 1/3 sem_acordo",
        )
        .unwrap();
        assert_eq!(g.contagem, None);
        assert_eq!(g.desvio_ms, None);
        assert_eq!(g.efeito, "sem_acordo");
        assert_eq!(g.salto_ms(), -5);
        let n = Fechamento::ler("1>2 logico 3>4 rtc>rtc", "r1 invalido sem_acordo").unwrap();
        assert_eq!(n.efeito, "sem_acordo");
        // O desvio negativo.
        let t = Fechamento::ler(
            "1>1 logico 1>1 sincronizado>sincronizado",
            "r2 acordo 3/3 d-600000 u7 pendente",
        )
        .unwrap();
        assert_eq!(t.salto_ms(), -600_000);
        // O que não é um fechamento.
        for r in [
            "",
            "1>2",
            "1>2 logo 3>4 a>b",
            "1>2 logico 3>4",
            "x>2 logico 3>4 a>b",
        ] {
            assert_eq!(Fechamento::ler(r, "r1 acordo"), None, "{r}");
        }
    }

    #[test]
    fn os_segundos() {
        assert_eq!(segundos(3_600_000), "+3600.000 s");
        assert_eq!(segundos(-1_500), "-1.500 s");
        assert_eq!(segundos(0), "+0.000 s");
    }
}
