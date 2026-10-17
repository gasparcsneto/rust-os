//! O relógio civil: uma instância só, a de [`hora::disciplina::Relogio`],
//! com a régua de [`super::contador`].
//!
//! # O que o move
//!
//! - Antes do primeiro acordo, o RTC: lido no boot e relido no máximo uma
//!   vez por segundo ([`RELEITURA_MS`]), fora da trava. A releitura só
//!   empurra o civil **para a frente** — o RTC tem resolução de um segundo,
//!   e o contador anda entre duas leituras: um RTC que ainda não virou o
//!   segundo, ou que alguém atrasou, não faz o civil voltar. É o RTC de
//!   sempre, sem o CMOS a cada registro da auditoria.
//! - Depois, só o desfecho de uma rodada ([`rodada`]) — o tratador de
//!   `time.sync`, na última fonte — e a confirmação de um salto pendente
//!   ([`confirmar`]) — o de `time.confirm`. Nada mais escreve aqui: o
//!   `xtask` confere quem chama os dois.
//!
//! O civil volta em dois casos só: na primeira sincronização do boot, e
//! num salto para trás que as regras da disciplina deixam — ver
//! `hora::disciplina`. O ajuste gradual nunca volta.
//!
//! # A trava
//!
//! [`CIVIL`] é folha: com ela na mão, só a régua (atômicos) e contas. Nem
//! o RTC — a releitura toma a trava do CMOS antes, sem esta —, nem a
//! auditoria, nem a persistência: o lógico lê o civil e solta antes de
//! tomar a dele. Quem lê o civil, em qualquer núcleo, lê um instantâneo
//! inteiro: a âncora, a correção e a régua do mesmo momento.
//!
//! # O que não está aqui
//!
//! Decisão. Nenhuma autorização lê o civil — o gate decide pelo relógio do
//! kernel (`crate::tempo`), que nada daqui toca.

use core::sync::atomic::{AtomicBool, Ordering};

use hora::disciplina::{Efeito, Estado, Leitura, Parametros, Relogio};
use hora::quorum::Desfecho;

use crate::trava::Mutex;

/// O intervalo mínimo entre duas leituras do RTC antes do primeiro acordo.
pub const RELEITURA_MS: u64 = 1_000;

struct Civil {
    relogio: Relogio,
    parametros: Parametros,
    /// O civil tem hora: o RTC respondeu alguma vez, ou houve um acordo.
    /// Sem ela, o civil não diz nada, e o lógico fica no piso.
    tem_hora: bool,
    /// Antes de quando o RTC não é relido, na régua.
    releitura_ms: u64,
    /// A rodada que pediu o salto pendente: o registro do `time.confirm`
    /// diz qual evidência ele aplicou.
    pendente_da_rodada: Option<u64>,
}

/// O relógio civil — ver o topo do módulo.
static CIVIL: Mutex<Option<Civil>> = Mutex::new(None);

/// Um fio está relendo o RTC: os outros seguem com o que há.
static RELENDO: AtomicBool = AtomicBool::new(false);

fn com<R>(f: impl FnOnce(&mut Civil) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| CIVIL.lock().as_mut().map(f))
}

/// Liga o civil no RTC, com estes parâmetros. No boot, uma vez, antes da
/// persistência — o lógico já lê o civil quando o journal é aberto.
pub fn iniciar(parametros: Parametros) {
    let rtc = crate::relogio::agora();
    let local = super::contador::agora_ms();
    let civil = Civil {
        relogio: Relogio::do_rtc(parametros, rtc, local),
        parametros,
        tem_hora: rtc.is_some(),
        releitura_ms: local.saturating_add(RELEITURA_MS),
        pendente_da_rodada: None,
    };
    crate::arch::sem_interrupcoes(|| *CIVIL.lock() = Some(civil));
}

/// O civil foi ligado.
pub fn iniciado() -> bool {
    crate::arch::sem_interrupcoes(|| CIVIL.lock().is_some())
}

/// Os parâmetros da disciplina em vigor.
pub fn parametros() -> Option<Parametros> {
    com(|c| c.parametros)
}

/// Relê o RTC, se o civil ainda está nele e passou o intervalo: fora da
/// trava do civil, e por um fio de cada vez.
fn reler_o_rtc() {
    let devida = com(|c| {
        let local = super::contador::agora_ms();
        local >= c.releitura_ms && c.relogio.ler(local).estado == Estado::Rtc
    })
    .unwrap_or(false);
    if !devida || RELENDO.swap(true, Ordering::AcqRel) {
        return;
    }
    let rtc = crate::relogio::agora();
    com(|c| {
        let local = super::contador::agora_ms();
        c.releitura_ms = local.saturating_add(RELEITURA_MS);
        let Some(segundos) = rtc else {
            return;
        };
        let atual = c.relogio.ler(local);
        // Um acordo pode ter chegado entre a pergunta e agora: depois dele,
        // o RTC não move nada.
        if atual.estado != Estado::Rtc {
            return;
        }
        if !c.tem_hora || segundos.saturating_mul(1000) > atual.meio_ms {
            c.relogio.reler_rtc(Some(segundos), local);
            c.tem_hora = true;
        }
    });
    RELENDO.store(false, Ordering::Release);
}

/// O civil agora. `None` antes de ligado.
pub fn ler() -> Option<Leitura> {
    reler_o_rtc();
    com(|c| c.relogio.ler(super::contador::agora_ms()))
}

/// O civil em segundos, para o tempo lógico. `None` sem hora nenhuma.
pub fn em_segundos() -> Option<u64> {
    reler_o_rtc();
    com(|c| {
        c.tem_hora
            .then(|| c.relogio.ler(super::contador::agora_ms()).meio_ms / 1000)
    })
    .flatten()
}

/// O que uma rodada ou uma confirmação fez com o civil: o efeito, e o
/// civil antes e depois, no mesmo instante da régua.
#[derive(Clone, Copy, Debug)]
pub struct Mudanca {
    pub efeito: Efeito,
    pub antes: Leitura,
    pub depois: Leitura,
}

/// O desfecho de uma rodada, aplicado — a rodada `numero`, com a
/// referência do teto do salto (o piso do lógico, em ms). Só o tratador de
/// `time.sync` chega aqui, na última fonte da rodada.
pub(super) fn rodada(
    desfecho: &Desfecho,
    referencia_ms: Option<u64>,
    numero: u64,
) -> Option<Mudanca> {
    com(|c| {
        let local = super::contador::agora_ms();
        let antes = c.relogio.ler(local);
        let efeito = c.relogio.rodada(desfecho, local, referencia_ms);
        let depois = c.relogio.ler(local);
        if depois.incerteza_ms.is_some() {
            c.tem_hora = true;
        }
        match efeito {
            Efeito::Pendente { .. } => c.pendente_da_rodada = Some(numero),
            _ if depois.pendente_ms.is_none() => c.pendente_da_rodada = None,
            _ => {}
        }
        Mudanca {
            efeito,
            antes,
            depois,
        }
    })
}

/// O salto pendente, aplicado: o que o acordo pediu, levado até agora pela
/// régua — nunca uma hora de quem confirma. Só o tratador de
/// `time.confirm` chega aqui. `None` sem salto pendente; com ele, a
/// mudança e a rodada que o pediu.
pub(super) fn confirmar() -> Option<(Mudanca, Option<u64>)> {
    com(|c| {
        let local = super::contador::agora_ms();
        let antes = c.relogio.ler(local);
        let efeito = c.relogio.confirmar(local)?;
        let depois = c.relogio.ler(local);
        c.tem_hora = true;
        let rodada = c.pendente_da_rodada.take();
        Some((
            Mudanca {
                efeito,
                antes,
                depois,
            },
            rodada,
        ))
    })
    .flatten()
}

/// O civil agora, com a rodada que pediu o salto pendente, se há um — do
/// mesmo instante.
pub fn ler_com_o_pendente() -> Option<(Leitura, Option<u64>)> {
    reler_o_rtc();
    com(|c| {
        let l = c.relogio.ler(super::contador::agora_ms());
        let rodada = c.pendente_da_rodada.filter(|_| l.pendente_ms.is_some());
        (l, rodada)
    })
}

/// Só para a suíte: o civil recomeça no estado `rtc`, com outros
/// parâmetros, ancorado no segundo seguinte ao civil de agora — nunca
/// para trás. Os cenários de tempo da suíte apertam os parâmetros (a
/// janela, o teto, o limiar) para caberem em segundos, e devolvem os do
/// registro no fim.
#[cfg(feature = "modo-teste")]
pub fn reiniciar_de_teste(parametros: Parametros) {
    com(|c| {
        let local = super::contador::agora_ms();
        let meio = c.relogio.ler(local).meio_ms;
        c.relogio = Relogio::do_rtc(parametros, Some(meio.div_ceil(1000)), local);
        c.parametros = parametros;
        c.tem_hora = true;
        c.releitura_ms = local.saturating_add(RELEITURA_MS);
        c.pendente_da_rodada = None;
    });
}

/// Destrava o civil, para o caminho de falha fatal.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver `crate::traps::fatal`.
pub unsafe fn destravar() {
    // SAFETY: a garantia de quem chama.
    unsafe { CIVIL.force_unlock() };
}
