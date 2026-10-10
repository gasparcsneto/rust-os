//! O custo da segurança, medido — o que `security.metrics` diz.
//!
//! # O que se mede
//!
//! - o gate: cada decisão de [`crate::autorizacao::autorizar`] — quantas,
//!   as recusas por código, e o tempo do pedido à decisão, sem o handler;
//! - a política: a conta da decisão sozinha — o `decidir` de cada recurso;
//! - a auditoria: cada registro, o tempo de montá-lo e anexá-lo à cadeia;
//! - o tecido de segurança (NSF): cada volta, o tempo dela e os registros
//!   que leu — e a parte do tempo da máquina que as voltas tomaram;
//! - a resposta: do registro que disparou a detecção ao pedido do NSF;
//! - os arrendamentos: quantos soltos, por quê, e os que venceram, quanto
//!   depois do prazo saíram.
//!
//! # A régua
//!
//! O contador de tempo da arquitetura ([`crate::arch::ciclos`]), convertido
//! em nanossegundos pela razão entre ele e o relógio do kernel desde o
//! boot — a mesma conta nas duas arquiteturas, sem conhecer a frequência
//! de antemão. Nos primeiros segundos a razão é grosseira; depois de um
//! minuto, o erro é de partes por milhão.
//!
//! # O que não é
//!
//! Decisão. O gate não lê nada daqui: são contadores atômicos, sem trava,
//! que só a consulta lê. Uma medida que perdesse uma corrida perderia uma
//! amostra, nunca uma decisão.

use core::sync::atomic::{AtomicU64, Ordering, fence};

use politica::Codigo;

/// Uma medida: quantas amostras, a soma e o maior valor.
pub struct Medida {
    amostras: AtomicU64,
    soma: AtomicU64,
    maior: AtomicU64,
}

impl Medida {
    pub const fn nova() -> Medida {
        Medida {
            amostras: AtomicU64::new(0),
            soma: AtomicU64::new(0),
            maior: AtomicU64::new(0),
        }
    }

    /// Conta uma amostra.
    pub fn somar(&self, valor: u64) {
        self.amostras.fetch_add(1, Ordering::Relaxed);
        self.soma.fetch_add(valor, Ordering::Relaxed);
        self.maior.fetch_max(valor, Ordering::Relaxed);
    }

    /// Quantas amostras, a média e o maior.
    pub fn ler(&self) -> (u64, u64, u64) {
        let n = self.amostras.load(Ordering::Relaxed);
        let soma = self.soma.load(Ordering::Relaxed);
        (
            n,
            soma.checked_div(n).unwrap_or(0),
            self.maior.load(Ordering::Relaxed),
        )
    }

    /// A soma, para as proporções.
    pub fn soma(&self) -> u64 {
        self.soma.load(Ordering::Relaxed)
    }

    /// Só para a suíte: zera.
    #[cfg(feature = "modo-teste")]
    pub fn zerar(&self) {
        self.amostras.store(0, Ordering::Relaxed);
        self.soma.store(0, Ordering::Relaxed);
        self.maior.store(0, Ordering::Relaxed);
    }
}

/// O gate: do pedido à decisão, em ciclos.
pub static GATE: Medida = Medida::nova();
/// A conta da política, em ciclos.
pub static POLITICA: Medida = Medida::nova();
/// Um registro da auditoria, em ciclos.
pub static AUDITORIA: Medida = Medida::nova();
/// Uma volta do NSF, em ciclos.
pub static VOLTA_DO_NSF: Medida = Medida::nova();
/// Os registros que o NSF leu, por volta.
pub static REGISTROS_DO_NSF: Medida = Medida::nova();
/// Do registro que disparou uma detecção ao pedido do NSF, em
/// milissegundos.
pub static RESPOSTA_MS: Medida = Medida::nova();
/// De quanto depois do prazo um arrendamento vencido saiu, em
/// milissegundos.
pub static VENCIMENTO_MS: Medida = Medida::nova();

/// As decisões do gate por código, na ordem de [`Codigo::TODOS`].
static POR_CODIGO: [AtomicU64; Codigo::TODOS.len()] =
    [const { AtomicU64::new(0) }; Codigo::TODOS.len()];

/// Por que um arrendamento saiu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Saida {
    /// O prazo venceu.
    Vencimento,
    /// A sessão acabou: o login saiu, a porta caiu.
    FimDaSessao,
    /// A chave ou a pessoa foi revogada.
    Revogacao,
    /// O agente ou a credencial foi suspensa.
    Suspensao,
    /// Um administrador o revogou, com prova.
    Administrador,
}

impl Saida {
    pub const TODAS: [Saida; 5] = [
        Saida::Vencimento,
        Saida::FimDaSessao,
        Saida::Revogacao,
        Saida::Suspensao,
        Saida::Administrador,
    ];

    pub const fn nome(self) -> &'static str {
        match self {
            Saida::Vencimento => "expired",
            Saida::FimDaSessao => "session_end",
            Saida::Revogacao => "revocation",
            Saida::Suspensao => "suspension",
            Saida::Administrador => "admin",
        }
    }

    /// A saída pelo motivo que a coordenação grava.
    pub fn do_motivo(motivo: &str) -> Saida {
        if motivo.contains("suspens") {
            Saida::Suspensao
        } else if motivo.contains("revogad") {
            Saida::Revogacao
        } else {
            Saida::FimDaSessao
        }
    }
}

static ARRENDAMENTOS: [AtomicU64; Saida::TODAS.len()] =
    [const { AtomicU64::new(0) }; Saida::TODAS.len()];

/// Conta arrendamentos soltos.
pub fn arrendamentos_soltos(saida: Saida, quantos: usize) {
    ARRENDAMENTOS[saida as usize].fetch_add(quantos as u64, Ordering::Relaxed);
}

/// O contador e o relógio no começo da medida — o boot.
static INICIO_CICLOS: AtomicU64 = AtomicU64::new(0);
static INICIO_MS: AtomicU64 = AtomicU64::new(0);

/// Marca o começo da régua. No boot, uma vez.
pub fn iniciar() {
    INICIO_CICLOS.store(crate::arch::ciclos(), Ordering::Relaxed);
    INICIO_MS.store(crate::tempo::uptime_ms(), Ordering::Relaxed);
}

/// Os ciclos desde o boot e os milissegundos desde o boot.
fn desde_o_inicio() -> (u64, u64) {
    let ciclos = crate::arch::ciclos().saturating_sub(INICIO_CICLOS.load(Ordering::Relaxed));
    let ms = crate::tempo::uptime_ms().saturating_sub(INICIO_MS.load(Ordering::Relaxed));
    (ciclos, ms)
}

/// `ciclos` em nanossegundos, pela razão medida desde o boot.
pub fn nanos(ciclos: u64) -> u64 {
    let (total, ms) = desde_o_inicio();
    if total == 0 || ms == 0 {
        return 0;
    }
    (u128::from(ciclos) * u128::from(ms) * 1_000_000 / u128::from(total)) as u64
}

/// Em partes por milhão, a parte que `ciclos` é do tempo da máquina desde
/// o boot — de um núcleo. Por milhão, e não por mil: o custo da auditoria
/// e o do NSF ficam abaixo de um milésimo, e uma medida que dissesse zero
/// não diria nada.
pub fn ppm_do_tempo(ciclos: u64) -> u64 {
    let (total, _) = desde_o_inicio();
    (u128::from(ciclos) * 1_000_000)
        .checked_div(u128::from(total))
        .unwrap_or(0) as u64
}

/// Os milissegundos desde o começo da régua: a janela das contagens.
pub fn janela_ms() -> u64 {
    desde_o_inicio().1
}

/// Os ciclos desde `inicio`. Um fio que mudou de núcleo no meio da medida
/// pode ler um contador atrás do primeiro: o intervalo negativo conta
/// zero, e nunca um número enorme que estragaria o maior.
pub fn desde(inicio: u64) -> u64 {
    crate::arch::ciclos().saturating_sub(inicio)
}

/// Uma decisão do gate: o código e quantos ciclos levou.
pub fn decisao(codigo: Codigo, ciclos: u64) {
    GATE.somar(ciclos);
    if let Some(i) = Codigo::TODOS.iter().position(|c| *c == codigo) {
        POR_CODIGO[i].fetch_add(1, Ordering::Relaxed);
    }
}

/// As decisões de um código.
pub fn decisoes_de(codigo: Codigo) -> u64 {
    Codigo::TODOS
        .iter()
        .position(|c| *c == codigo)
        .map_or(0, |i| POR_CODIGO[i].load(Ordering::Relaxed))
}

/// Os arrendamentos soltos por uma causa.
pub fn soltos_por(saida: Saida) -> u64 {
    ARRENDAMENTOS[saida as usize].load(Ordering::Relaxed)
}

/// Quantas vagas guardam o momento de cada registro, para a latência da
/// resposta: o anel da auditoria.
const MOMENTOS: usize = crate::autorizacao::CAPACIDADE_DA_AUDITORIA;

/// O momento — no relógio do kernel — em que cada registro recente foi
/// gravado: o número do registro e o milissegundo, na vaga `seq % MOMENTOS`.
static MOMENTO_SEQ: [AtomicU64; MOMENTOS] = [const { AtomicU64::new(0) }; MOMENTOS];
static MOMENTO_MS: [AtomicU64; MOMENTOS] = [const { AtomicU64::new(0) }; MOMENTOS];

/// Um registro gravado agora. O zero é a auditoria que não está no ar: não
/// houve registro.
pub fn registro_gravado(seq: u64, ciclos: u64) {
    if seq == 0 {
        return;
    }
    AUDITORIA.somar(ciclos);
    let i = (seq % MOMENTOS as u64) as usize;
    // Como uma trava de sequência: a vaga fica sem dono enquanto o
    // milissegundo muda, e quem lê confere o dono antes e depois.
    MOMENTO_SEQ[i].store(0, Ordering::Relaxed);
    fence(Ordering::Release);
    MOMENTO_MS[i].store(crate::tempo::uptime_ms(), Ordering::Relaxed);
    MOMENTO_SEQ[i].store(seq, Ordering::Release);
}

/// Quando o registro `seq` foi gravado, se ainda se sabe. O zero não é
/// registro nenhum — e é o que uma vaga nunca usada guarda.
pub fn momento_do_registro(seq: u64) -> Option<u64> {
    if seq == 0 {
        return None;
    }
    let i = (seq % MOMENTOS as u64) as usize;
    if MOMENTO_SEQ[i].load(Ordering::Acquire) != seq {
        return None;
    }
    let ms = MOMENTO_MS[i].load(Ordering::Relaxed);
    fence(Ordering::Acquire);
    // Um registro `MOMENTOS` adiante pode ter tomado a vaga entre as duas
    // leituras: o milissegundo seria o dele.
    (MOMENTO_SEQ[i].load(Ordering::Relaxed) == seq).then_some(ms)
}

/// Só para a suíte: zera as medidas que um caso confere.
#[cfg(feature = "modo-teste")]
pub fn zerar_de_teste() {
    for m in [
        &GATE,
        &POLITICA,
        &AUDITORIA,
        &VOLTA_DO_NSF,
        &REGISTROS_DO_NSF,
        &RESPOSTA_MS,
        &VENCIMENTO_MS,
    ] {
        m.zerar();
    }
    for c in &POR_CODIGO {
        c.store(0, Ordering::Relaxed);
    }
    for c in &ARRENDAMENTOS {
        c.store(0, Ordering::Relaxed);
    }
}
