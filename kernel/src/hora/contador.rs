//! A régua do relógio civil: o contador do hardware, em milissegundos.
//!
//! # Por que não os tiques
//!
//! O relógio do kernel ([`crate::tempo`]) conta as interrupções do timer, e
//! tique perdido não volta: o emulador junta interrupções quando o
//! processador emulado fica sem vez no hospedeiro, e o relógio anda devagar
//! sem dizer nada — 5% de perda são 51 s de erro em 1024 s, entre duas
//! rodadas. Ele continua sendo a régua das durações (arrendamentos,
//! sessões, taxas, esperas), e nada aqui o toca. O civil precisa de outra.
//!
//! O contador de ciclos ([`crate::arch::ciclos`]) não perde contagem: é
//! lido, e não interrompe. A frequência dele:
//!
//! - no ARM, a que o firmware declara em `CNTFRQ_EL0`;
//! - no x86, medida no boot contra o canal 2 do PIT — ver
//!   `arch::x86_64::pic::calibrar_ciclos` —, com o erro da medida, que
//!   entra na deriva máxima do civil ([`deriva_ppm`]);
//! - sem nenhuma das duas, os tiques, com a deriva deles: uma régua pior,
//!   dita como tal.
//!
//! A frequência **não** é aprendida das amostras: com raios de segundos,
//! separar 100 ppm pediria dias entre rodadas (ver `hora::disciplina`).
//!
//! # Vários núcleos
//!
//! O TSC de núcleos diferentes pode divergir, e um fio muda de núcleo no
//! meio de qualquer coisa. A leitura é guardada: [`agora_ms`] nunca devolve
//! menos do que já devolveu, em núcleo nenhum.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// A frequência do contador, em Hz; zero com a régua nos tiques.
static HZ: AtomicU64 = AtomicU64::new(0);

/// O contador no início da régua.
static BASE: AtomicU64 = AtomicU64::new(0);

/// O relógio do kernel no início da régua — para medir a taxa dele contra
/// o contador ([`mono_ppm`]).
static BASE_DOS_TIQUES_MS: AtomicU64 = AtomicU64::new(0);

/// O erro máximo da frequência, em ppm.
static ERRO_PPM: AtomicU64 = AtomicU64::new(0);

/// De onde vem a frequência — ver [`Origem`].
static ORIGEM: AtomicU8 = AtomicU8::new(Origem::Tiques as u8);

/// O maior valor que [`agora_ms`] já devolveu.
static MAIOR_MS: AtomicU64 = AtomicU64::new(0);

/// A deriva máxima da régua nos tiques: 5%. É o que o desenho mediu de
/// perda sob carga no emulador; um civil nos tiques vence o teto da
/// incerteza em minutos, e diz isso.
pub const DERIVA_DOS_TIQUES_PPM: u64 = 50_000;

/// De onde vem a frequência da régua.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Origem {
    /// Sem frequência: a régua são os tiques do timer.
    Tiques = 0,
    /// A que o processador declara (`CNTFRQ_EL0`).
    Declarada = 1,
    /// A medida no boot contra o PIT (o TSC do x86).
    Calibrada = 2,
}

impl Origem {
    /// O nome estável, para o `system.info`.
    pub const fn nome(self) -> &'static str {
        match self {
            Origem::Tiques => "ticks",
            Origem::Declarada => "declared",
            Origem::Calibrada => "calibrated",
        }
    }
}

/// A origem da régua.
pub fn origem() -> Origem {
    match ORIGEM.load(Ordering::Acquire) {
        1 => Origem::Declarada,
        2 => Origem::Calibrada,
        _ => Origem::Tiques,
    }
}

/// A frequência do contador, em Hz; zero nos tiques.
pub fn hz() -> u64 {
    HZ.load(Ordering::Acquire)
}

/// O erro máximo da frequência, em ppm.
pub fn erro_ppm() -> u64 {
    ERRO_PPM.load(Ordering::Acquire)
}

/// Mede a régua. No boot, uma vez, antes do civil — e com um núcleo só:
/// no x86 a medida usa o PIT, que é um.
pub fn iniciar() {
    let origem = match crate::arch::frequencia_dos_ciclos() {
        Some((hz, erro)) => {
            HZ.store(hz, Ordering::Release);
            ERRO_PPM.store(erro, Ordering::Release);
            if cfg!(target_arch = "aarch64") {
                Origem::Declarada
            } else {
                Origem::Calibrada
            }
        }
        None => Origem::Tiques,
    };
    BASE.store(crate::arch::ciclos(), Ordering::Release);
    BASE_DOS_TIQUES_MS.store(crate::tempo::uptime_ms(), Ordering::Release);
    ORIGEM.store(origem as u8, Ordering::Release);
    match origem {
        Origem::Tiques => crate::log_warn!(
            "hora",
            "o contador de ciclos nao tem frequencia: a regua do civil sao os tiques, com deriva de {} ppm",
            DERIVA_DOS_TIQUES_PPM
        ),
        _ => crate::log_info!(
            "hora",
            "regua do civil: o contador de ciclos a {} Hz ({}, erro de ate {} ppm)",
            hz(),
            origem.nome(),
            erro_ppm()
        ),
    }
}

/// Milissegundos desde o início da régua. Nunca menos do que já devolveu.
pub fn agora_ms() -> u64 {
    let hz = HZ.load(Ordering::Acquire);
    let lido = if hz == 0 {
        crate::tempo::uptime_ms().saturating_sub(BASE_DOS_TIQUES_MS.load(Ordering::Acquire))
    } else {
        let ciclos = crate::arch::ciclos().saturating_sub(BASE.load(Ordering::Acquire));
        u64::try_from(u128::from(ciclos) * 1000 / u128::from(hz)).unwrap_or(u64::MAX)
    };
    let anterior = MAIOR_MS.fetch_max(lido, Ordering::AcqRel);
    lido.max(anterior)
}

/// A deriva máxima da régua, em ppm: a do desenho mais o erro da medida da
/// frequência — ou a dos tiques.
pub fn deriva_ppm(do_desenho: u64) -> u64 {
    match origem() {
        Origem::Tiques => DERIVA_DOS_TIQUES_PPM,
        _ => do_desenho.saturating_add(erro_ppm()),
    }
}

/// A taxa do relógio do kernel contra a régua, em ppm: negativa quando ele
/// perde tiques. Só mede e publica — o relógio do kernel não é corrigido
/// (os arrendamentos medem nele). `None` nos tiques, ou com menos de dez
/// segundos de régua, quando a conta ainda não diz nada.
pub fn mono_ppm() -> Option<i64> {
    if origem() == Origem::Tiques {
        return None;
    }
    let regua = agora_ms();
    if regua < 10_000 {
        return None;
    }
    let mono = crate::tempo::uptime_ms().saturating_sub(BASE_DOS_TIQUES_MS.load(Ordering::Acquire));
    let ppm = (i128::from(mono) - i128::from(regua)) * 1_000_000 / i128::from(regua);
    i64::try_from(ppm).ok()
}
