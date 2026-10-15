//! O relógio civil: a melhor estimativa da hora UTC, com a incerteza dela
//! e um estado.
//!
//! Não há relógio aqui dentro. O civil é uma âncora — um valor civil num
//! instante do contador local — mais o tempo que o contador conta desde
//! então, mais a parte já aplicada de uma correção gradual. Quem chama dá os
//! instantes do contador; nada aqui lê hora nenhuma.
//!
//! # O que move o civil
//!
//! Só um [`Acordo`] de pelo menos duas chaves ([`crate::quorum`]). Uma
//! rodada sem acordo não move nada; o tempo passando só faz a incerteza
//! crescer, pela deriva máxima do contador.
//!
//! Com o desvio Δ entre o meio do acordo e o civil, e a incerteza u do
//! acordo:
//!
//! - |Δ| ≤ u: o civil já está dentro do acordo. Nada se move; a incerteza
//!   é reancorada.
//! - u < |Δ| ≤ limiar: ajuste **gradual** — o civil anda até 5% mais rápido
//!   ou mais devagar, e nunca para trás, até absorver Δ.
//! - |Δ| > limiar: um **salto**, só depois de duas rodadas seguidas que
//!   concordam no desvio, com pelo menos alguns segundos entre elas. Mas:
//!   - para a frente, além do teto a partir da referência — o maior entre o
//!     civil e o que quem chama der (o piso persistente, o RTC) —, o salto
//!     fica **pendente**: o piso nunca volta, e o que não se desfaz espera
//!     uma pessoa;
//!   - para trás, depois da primeira sincronização e fora do envelope (o
//!     contador não explica), também fica pendente.
//!
//! O limiar é o maior entre um mínimo e o dobro da incerteza do acordo
//! (D0-4): com raios de segundos, um desvio do tamanho da incerteza não é
//! sinal de nada.
//!
//! # O civil volta?
//!
//! Só em dois casos: num salto para trás — a primeira sincronização trocando
//! o RTC por uma hora autenticada, ou um salto confirmado — e numa
//! confirmação de salto pendente. O ajuste gradual nunca volta: a taxa
//! máxima é menor que um.
//!
//! # O que não está aqui
//!
//! A taxa do contador não é aprendida das amostras: com raios de segundos,
//! separar 100 ppm pediria dias entre rodadas. A deriva máxima entra na
//! incerteza, e a frequência nominal do contador é do kernel.

use crate::intervalo::deriva_em;
use crate::quorum::{Acordo, Desfecho};

/// Os parâmetros da disciplina.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parametros {
    /// O menor limiar entre o ajuste gradual e o salto.
    pub limiar_minimo_ms: u64,
    /// A taxa máxima do ajuste gradual, em milésimos (50 = 5%).
    pub taxa_gradual_por_mil: u64,
    /// O maior salto para a frente sem uma pessoa.
    pub salto_maximo_ms: u64,
    /// A deriva máxima do contador local, em partes por milhão.
    pub deriva_ppm: u64,
    /// Acima desta incerteza, a hora está vencida.
    pub teto_da_incerteza_ms: u64,
    /// Até quanto tempo depois do último acordo o estado é sincronizado.
    pub janela_sincronizado_ms: u64,
    /// O mínimo entre as duas rodadas de um salto.
    pub separacao_minima_ms: u64,
}

impl Parametros {
    /// Os parâmetros iniciais do desenho — a medir na bancada.
    pub const PADRAO: Parametros = Parametros {
        limiar_minimo_ms: 10_000,
        taxa_gradual_por_mil: 50,
        salto_maximo_ms: 86_400_000,
        deriva_ppm: 500,
        teto_da_incerteza_ms: 60_000,
        janela_sincronizado_ms: 2_048_000,
        separacao_minima_ms: 4_000,
    };

    /// Os parâmetros fazem sentido: a taxa gradual é menor que um (o civil
    /// nunca volta no ajuste) e maior que zero (o ajuste acaba).
    pub fn validos(&self) -> bool {
        (1..1000).contains(&self.taxa_gradual_por_mil)
            && self.limiar_minimo_ms > 0
            && self.salto_maximo_ms > 0
            && self.separacao_minima_ms > 0
    }
}

/// O quanto se pode confiar na hora civil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Estado {
    /// Nenhum acordo autenticado ainda: o civil é o RTC.
    Rtc,
    /// Acordo recente.
    Sincronizado,
    /// Sem acordo há um tempo; a incerteza cresce, abaixo do teto.
    Holdover,
    /// A incerteza passou do teto.
    Vencido,
}

impl Estado {
    /// O nome estável, para a auditoria e o `system.info`.
    pub const fn nome(self) -> &'static str {
        match self {
            Estado::Rtc => "rtc",
            Estado::Sincronizado => "sincronizado",
            Estado::Holdover => "holdover",
            Estado::Vencido => "vencido",
        }
    }
}

/// O civil num instante.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leitura {
    /// A estimativa, em milissegundos desde a época Unix.
    pub meio_ms: u64,
    /// A incerteza; nenhuma antes do primeiro acordo.
    pub incerteza_ms: Option<u64>,
    pub estado: Estado,
    /// O desvio de um salto que espera uma pessoa.
    pub pendente_ms: Option<i64>,
    /// A última rodada teve fontes que não concordaram.
    pub divergente: bool,
    /// O último salto foi além do que o contador explica.
    pub alem_do_envelope: bool,
}

/// O que uma rodada fez.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Efeito {
    /// O acordo cabe no civil: nada se move.
    Nada,
    /// Um desvio pequeno, absorvido devagar.
    Gradual { desvio_ms: i64 },
    /// Um desvio grande, visto agora: espera a rodada seguinte.
    Candidato { desvio_ms: i64 },
    /// O salto, depois de duas rodadas que concordam (ou da confirmação).
    Salto {
        desvio_ms: i64,
        alem_do_envelope: bool,
    },
    /// Um salto que só uma pessoa confirma.
    Pendente { desvio_ms: i64 },
    /// A rodada não deu acordo.
    SemAcordo,
}

#[derive(Debug, Clone, Copy)]
struct Candidato {
    desvio_ms: i64,
    incerteza_ms: u64,
    instante_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct SaltoPendente {
    meio_ms: u64,
    incerteza_ms: u64,
    instante_ms: u64,
    desvio_ms: i64,
}

/// O relógio civil.
#[derive(Debug, Clone)]
pub struct Relogio {
    p: Parametros,
    ancora_local_ms: u64,
    ancora_civil_ms: u64,
    /// A correção gradual em curso, a partir da âncora.
    correcao_ms: i64,
    /// A incerteza na âncora; nenhuma antes do primeiro acordo.
    incerteza_ancora_ms: Option<u64>,
    ultimo_acordo_ms: u64,
    candidato: Option<Candidato>,
    pendente: Option<SaltoPendente>,
    divergente: bool,
    alem_do_envelope: bool,
}

fn como_u64(x: i128) -> u64 {
    x.clamp(0, i128::from(u64::MAX)) as u64
}

fn como_i64(x: i128) -> i64 {
    x.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

impl Relogio {
    /// O relógio antes de qualquer acordo: o RTC, em segundos, lido no
    /// instante `local_ms` do contador — ou zero, sem RTC.
    pub fn do_rtc(p: Parametros, rtc_s: Option<u64>, local_ms: u64) -> Relogio {
        Relogio {
            p,
            ancora_local_ms: local_ms,
            ancora_civil_ms: rtc_s.unwrap_or(0).saturating_mul(1000),
            correcao_ms: 0,
            incerteza_ancora_ms: None,
            ultimo_acordo_ms: local_ms,
            candidato: None,
            pendente: None,
            divergente: false,
            alem_do_envelope: false,
        }
    }

    /// Relê o RTC — só antes do primeiro acordo. Depois dele, o RTC não move
    /// mais o civil; devolve se moveu.
    pub fn reler_rtc(&mut self, rtc_s: Option<u64>, local_ms: u64) -> bool {
        if self.incerteza_ancora_ms.is_some() {
            return false;
        }
        self.ancora_local_ms = local_ms;
        self.ancora_civil_ms = rtc_s.unwrap_or(0).saturating_mul(1000);
        self.correcao_ms = 0;
        true
    }

    /// O civil no instante `local_ms` do contador. Antes da âncora, lê como
    /// na âncora.
    pub fn ler(&self, local_ms: u64) -> Leitura {
        let decorrido = local_ms.saturating_sub(self.ancora_local_ms);
        let total = self.correcao_ms.unsigned_abs();
        let possivel = u128::from(decorrido) * u128::from(self.p.taxa_gradual_por_mil) / 1000;
        let aplicado = u64::try_from(possivel).unwrap_or(u64::MAX).min(total);
        let com_sinal = if self.correcao_ms < 0 {
            -i128::from(aplicado)
        } else {
            i128::from(aplicado)
        };
        let meio = como_u64(i128::from(self.ancora_civil_ms) + i128::from(decorrido) + com_sinal);
        let incerteza = self.incerteza_ancora_ms.map(|u| {
            u.saturating_add(total - aplicado)
                .saturating_add(deriva_em(decorrido, self.p.deriva_ppm))
        });
        let estado = match incerteza {
            None => Estado::Rtc,
            Some(i) if i > self.p.teto_da_incerteza_ms => Estado::Vencido,
            Some(_)
                if local_ms.saturating_sub(self.ultimo_acordo_ms)
                    <= self.p.janela_sincronizado_ms =>
            {
                Estado::Sincronizado
            }
            Some(_) => Estado::Holdover,
        };
        Leitura {
            meio_ms: meio,
            incerteza_ms: incerteza,
            estado,
            pendente_ms: self.pendente.map(|p| p.desvio_ms),
            divergente: self.divergente,
            alem_do_envelope: self.alem_do_envelope,
        }
    }

    fn reancorar(&mut self, local_ms: u64, civil_ms: u64, correcao_ms: i64, incerteza_ms: u64) {
        self.ancora_local_ms = local_ms;
        self.ancora_civil_ms = civil_ms;
        self.correcao_ms = correcao_ms;
        self.incerteza_ancora_ms = Some(incerteza_ms);
        self.ultimo_acordo_ms = local_ms;
    }

    /// Uma rodada: o desfecho do quórum, já levado ao instante `local_ms`,
    /// e a referência para o teto do salto (o piso persistente, o RTC — o
    /// maior que quem chama tiver), em milissegundos.
    pub fn rodada(
        &mut self,
        desfecho: &Desfecho,
        local_ms: u64,
        referencia_ms: Option<u64>,
    ) -> Efeito {
        match desfecho {
            Desfecho::Acordo(acordo) => self.com_acordo(acordo, local_ms, referencia_ms),
            Desfecho::Empate { .. } => {
                self.divergente = true;
                self.candidato = None;
                Efeito::SemAcordo
            }
            Desfecho::SemQuorum {
                chaves,
                maior_cobertura,
            } => {
                self.divergente = *chaves >= 2 && maior_cobertura < chaves;
                self.candidato = None;
                Efeito::SemAcordo
            }
            Desfecho::Invalido => {
                self.candidato = None;
                Efeito::SemAcordo
            }
        }
    }

    fn com_acordo(&mut self, acordo: &Acordo, local_ms: u64, referencia_ms: Option<u64>) -> Efeito {
        self.divergente = acordo.divergentes != 0 || acordo.contraditorias != 0;
        let leitura = self.ler(local_ms);
        let meio = acordo.meio_ms();
        let u = acordo.incerteza_ms();
        let desvio = como_i64(i128::from(meio) - i128::from(leitura.meio_ms));
        let tamanho = desvio.unsigned_abs();
        let limiar = self.p.limiar_minimo_ms.max(u.saturating_mul(2));
        let ja_sincronizou = leitura.incerteza_ms.is_some();

        if tamanho <= u {
            let nova = leitura
                .incerteza_ms
                .map_or(u + tamanho, |atual| atual.min(u + tamanho));
            self.reancorar(local_ms, leitura.meio_ms, 0, nova);
            self.candidato = None;
            self.pendente = None;
            return Efeito::Nada;
        }
        if tamanho <= limiar {
            self.reancorar(local_ms, leitura.meio_ms, desvio, u);
            self.candidato = None;
            self.pendente = None;
            return Efeito::Gradual { desvio_ms: desvio };
        }

        // Um desvio grande. Dentro do envelope: o intervalo do civil, com a
        // incerteza dele, toca o acordo. Antes do primeiro acordo não há
        // envelope.
        let dentro = leitura.incerteza_ms.is_none_or(|i| {
            leitura.meio_ms.saturating_sub(i) <= acordo.tarde_ms
                && acordo.cedo_ms <= leitura.meio_ms.saturating_add(i)
        });
        let para_frente = desvio > 0;
        let base = leitura.meio_ms.max(referencia_ms.unwrap_or(0));
        let alem_do_teto = para_frente && meio.saturating_sub(base) > self.p.salto_maximo_ms;
        let para_tras_sem_explicacao = !para_frente && ja_sincronizou && !dentro;
        if alem_do_teto || para_tras_sem_explicacao {
            self.pendente = Some(SaltoPendente {
                meio_ms: meio,
                incerteza_ms: u,
                instante_ms: local_ms,
                desvio_ms: desvio,
            });
            self.candidato = None;
            return Efeito::Pendente { desvio_ms: desvio };
        }

        if let Some(c) = self.candidato {
            let separacao = local_ms.saturating_sub(c.instante_ms);
            if separacao < self.p.separacao_minima_ms {
                return Efeito::Candidato {
                    desvio_ms: c.desvio_ms,
                };
            }
            let folga = u
                .saturating_add(c.incerteza_ms)
                .saturating_add(deriva_em(separacao, self.p.deriva_ppm));
            if (i128::from(desvio) - i128::from(c.desvio_ms)).unsigned_abs() <= u128::from(folga) {
                let alem = ja_sincronizou && !dentro;
                self.reancorar(local_ms, meio, 0, u);
                self.candidato = None;
                self.pendente = None;
                self.alem_do_envelope = alem;
                return Efeito::Salto {
                    desvio_ms: desvio,
                    alem_do_envelope: alem,
                };
            }
        }
        self.candidato = Some(Candidato {
            desvio_ms: desvio,
            incerteza_ms: u,
            instante_ms: local_ms,
        });
        Efeito::Candidato { desvio_ms: desvio }
    }

    /// Uma pessoa confirma o salto pendente: ele se aplica com o meio do
    /// acordo que o pediu, levado até agora pelo contador. Sem pendente,
    /// nada.
    pub fn confirmar(&mut self, local_ms: u64) -> Option<Efeito> {
        let p = self.pendente.take()?;
        let decorrido = local_ms.saturating_sub(p.instante_ms);
        let meio = p.meio_ms.saturating_add(decorrido);
        let incerteza = p
            .incerteza_ms
            .saturating_add(deriva_em(decorrido, self.p.deriva_ppm));
        self.reancorar(local_ms, meio, 0, incerteza);
        self.candidato = None;
        self.alem_do_envelope = true;
        Some(Efeito::Salto {
            desvio_ms: p.desvio_ms,
            alem_do_envelope: true,
        })
    }
}

#[cfg(test)]
mod testes;
