//! Logging estruturado do kernel.
//!
//! # A diferença entre isto e um `println!`
//!
//! Um kernel que só imprime texto obriga qualquer ferramenta a *adivinhar* o
//! significado do que saiu, tipicamente com expressões regulares frágeis que
//! quebram na primeira mudança de formato. Para um OS projetado para ser
//! operado por um agente, isso é inaceitável.
//!
//! Aqui todo evento vira um [`Record`] tipado, com nível, subsistema e número
//! de sequência. Os registros vão para um **ring buffer** em memória, de onde
//! o agente pode lê-los de forma estruturada pelo comando `log.tail`. O texto
//! legível que aparece na COM1 é apenas uma *renderização* desses registros —
//! não a fonte da verdade.
//!
//! # Por que tamanho fixo
//!
//! O buffer é um array estático de registros com mensagem de capacidade fixa.
//! Isso não é preguiça: nesta fase o kernel ainda não tem heap, e mesmo depois
//! de ter, o caminho de log precisa continuar funcionando *dentro do alocador*
//! e dentro de handlers de pânico — ou seja, exatamente nos lugares onde
//! alocar é proibido ou perigoso. Um buffer estático nunca falha.

use core::fmt::{self, Write as _};

use spin::Mutex;

/// Severidade de um registro.
///
/// A ordem numérica é deliberada: `Error` é 0 e `Trace` é 4, então "nível
/// mínimo `Info`" vira a comparação `nivel <= Info`, que inclui `Error`,
/// `Warn` e `Info`. O `derive(PartialOrd)` segue a ordem de declaração.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl Level {
    /// Nome canônico, usado no protocolo do agente.
    pub const fn nome(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
            Level::Debug => "debug",
            Level::Trace => "trace",
        }
    }

    /// Converte o nome usado no protocolo de volta para o nível.
    pub fn de_nome(s: &str) -> Option<Self> {
        Some(match s {
            "error" => Level::Error,
            "warn" => Level::Warn,
            "info" => Level::Info,
            "debug" => Level::Debug,
            "trace" => Level::Trace,
            _ => return None,
        })
    }
}

/// Quantos registros o ring buffer guarda antes de sobrescrever os antigos.
const CAPACIDADE: usize = 128;

/// Capacidade em bytes da mensagem de cada registro.
const MSG_MAX: usize = 160;

/// Um evento do kernel.
#[derive(Clone, Copy)]
pub struct Record {
    /// Número de sequência global, monotônico desde o boot.
    ///
    /// Serve para o agente detectar registros perdidos: se as sequências
    /// pularem entre duas chamadas de `log.tail`, houve sobrescrita no anel.
    pub seq: u64,
    pub level: Level,
    /// Subsistema de origem (`"boot"`, `"agent"`, `"mem"`, ...).
    pub subsistema: &'static str,
    tam: u16,
    bytes: [u8; MSG_MAX],
}

impl Record {
    const VAZIO: Self = Self {
        seq: 0,
        level: Level::Info,
        subsistema: "",
        tam: 0,
        bytes: [0; MSG_MAX],
    };

    /// A mensagem renderizada.
    pub fn mensagem(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.tam as usize]).unwrap_or("<utf-8 invalido>")
    }
}

struct Anel {
    registros: [Record; CAPACIDADE],
    /// Onde o próximo registro será gravado.
    proximo: usize,
    /// Total de registros já emitidos (não o total guardado).
    total: u64,
}

static ANEL: Mutex<Anel> = Mutex::new(Anel {
    registros: [Record::VAZIO; CAPACIDADE],
    proximo: 0,
    total: 0,
});

/// Escreve dentro de um buffer de tamanho fixo, truncando com segurança.
struct Cursor<'a> {
    buf: &'a mut [u8; MSG_MAX],
    tam: usize,
}

impl fmt::Write for Cursor<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let espaco = self.buf.len() - self.tam;
        let mut n = s.len().min(espaco);

        // Truncar no meio de um caractere multibyte produziria UTF-8 inválido
        // e tornaria a mensagem inteira ilegível. Recuamos até uma fronteira
        // de caractere — nomes de subsistema e mensagens em português têm
        // acentos, então este caso acontece de verdade.
        while n > 0 && !s.is_char_boundary(n) {
            n -= 1;
        }

        self.buf[self.tam..self.tam + n].copy_from_slice(&s.as_bytes()[..n]);
        self.tam += n;
        Ok(())
    }
}

/// Grava um registro. Use as macros [`log_info!`] e companhia.
#[doc(hidden)]
pub fn registrar(nivel: Level, subsistema: &'static str, args: fmt::Arguments) {
    let seq = crate::arch::sem_interrupcoes(|| {
        let mut anel = ANEL.lock();

        let seq = anel.total;
        anel.total += 1;
        let idx = anel.proximo;
        anel.proximo = (idx + 1) % CAPACIDADE;

        let registro = &mut anel.registros[idx];
        registro.seq = seq;
        registro.level = nivel;
        registro.subsistema = subsistema;

        // Escopo para soltar o empréstimo mutável de `bytes` antes de mexer
        // em `tam`.
        let tam = {
            let mut cursor = Cursor {
                buf: &mut registro.bytes,
                tam: 0,
            };
            let _ = cursor.write_fmt(args);
            cursor.tam
        };
        registro.tam = tam as u16;

        seq
    });

    // O eco humano acontece *fora* do lock do anel. Se fizéssemos isso com o
    // anel travado, estaríamos segurando dois locks em ordem fixa — o começo
    // de um deadlock assim que outro caminho pegasse os mesmos locks na ordem
    // inversa.
    // Os argumentos vão todos por posição. Captura implícita (`{seq}`) não
    // funciona aqui: a string de formato chega via `concat!` dentro da macro
    // `serial_println!`, e o `format_args!` se recusa a capturar variáveis do
    // escopo quando o literal veio de uma expansão de macro.
    crate::serial_println!(
        "[{:>5}] {:<5} {:<8} {}",
        seq,
        nivel.nome(),
        subsistema,
        args
    );
}

/// Percorre os registros mais recentes, do mais antigo para o mais novo.
///
/// `max` limita quantos registros são *examinados*; o filtro de nível é
/// aplicado depois, então o callback pode ser chamado menos vezes que `max`.
pub fn ultimos<F: FnMut(&Record)>(max: usize, nivel_minimo: Level, mut f: F) {
    let anel = ANEL.lock();

    let guardados = (anel.total as usize).min(CAPACIDADE);
    let quantos = max.min(guardados);

    for k in (0..quantos).rev() {
        let idx = (anel.proximo + CAPACIDADE - 1 - k) % CAPACIDADE;
        let registro = &anel.registros[idx];
        if registro.level <= nivel_minimo {
            f(registro);
        }
    }
}

/// Destrava o ring buffer à força, para uso exclusivo do caminho de pânico.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Destravar um mutex que alguém ainda usa
/// permite corrida de dados — aqui isso é aceito porque a alternativa é um
/// deadlock que engoliria o relatório da falha.
pub unsafe fn destravar() {
    unsafe { ANEL.force_unlock() }
}

/// Total de registros emitidos desde o boot.
pub fn total_emitidos() -> u64 {
    ANEL.lock().total
}

// As cinco macros são escritas por extenso em vez de geradas por uma
// meta-macro: gerar `macro_rules!` de dentro de `macro_rules!` exige a
// sintaxe `$$`, que ainda não é estável. Repetição explícita é preferível a
// depender de um recurso instável no caminho de log do kernel.

/// Registra um evento de erro: algo falhou e o kernel não pôde cumprir a ação.
#[macro_export]
macro_rules! log_error {
    ($sub:expr, $fmt:expr) => {
        $crate::log::registrar($crate::log::Level::Error, $sub, format_args!($fmt))
    };
    ($sub:expr, $fmt:expr, $($arg:tt)*) => {
        $crate::log::registrar($crate::log::Level::Error, $sub, format_args!($fmt, $($arg)*))
    };
}

/// Registra um aviso: algo inesperado, mas recuperável.
#[macro_export]
macro_rules! log_warn {
    ($sub:expr, $fmt:expr) => {
        $crate::log::registrar($crate::log::Level::Warn, $sub, format_args!($fmt))
    };
    ($sub:expr, $fmt:expr, $($arg:tt)*) => {
        $crate::log::registrar($crate::log::Level::Warn, $sub, format_args!($fmt, $($arg)*))
    };
}

/// Registra um marco normal da operação do kernel.
#[macro_export]
macro_rules! log_info {
    ($sub:expr, $fmt:expr) => {
        $crate::log::registrar($crate::log::Level::Info, $sub, format_args!($fmt))
    };
    ($sub:expr, $fmt:expr, $($arg:tt)*) => {
        $crate::log::registrar($crate::log::Level::Info, $sub, format_args!($fmt, $($arg)*))
    };
}

/// Registra detalhe útil para depuração.
#[macro_export]
macro_rules! log_debug {
    ($sub:expr, $fmt:expr) => {
        $crate::log::registrar($crate::log::Level::Debug, $sub, format_args!($fmt))
    };
    ($sub:expr, $fmt:expr, $($arg:tt)*) => {
        $crate::log::registrar($crate::log::Level::Debug, $sub, format_args!($fmt, $($arg)*))
    };
}

/// Registra rastreamento fino (muito verboso).
#[macro_export]
macro_rules! log_trace {
    ($sub:expr, $fmt:expr) => {
        $crate::log::registrar($crate::log::Level::Trace, $sub, format_args!($fmt))
    };
    ($sub:expr, $fmt:expr, $($arg:tt)*) => {
        $crate::log::registrar($crate::log::Level::Trace, $sub, format_args!($fmt, $($arg)*))
    };
}
