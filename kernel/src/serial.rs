//! Driver das portas seriais (UART 16550).
//!
//! # Por que a serial vem antes de tudo
//!
//! Num kernel, o problema número um é *não ter como ver o que está
//! acontecendo*. Não existe `println!`, não existe debugger acoplado, e se
//! algo falha antes da inicialização gráfica a tela fica simplesmente preta.
//!
//! A porta serial resolve isso: é o dispositivo de I/O mais simples que o x86
//! oferece, funciona desde o primeiro instante após o boot, e o QEMU consegue
//! redirecioná-la para o stdout do host ou para um socket.
//!
//! # As duas portas, e por que são duas
//!
//! Esta é uma decisão de arquitetura central do projeto:
//!
//! - **COM1 (`0x3F8`) — console humano.** Logs em texto, legíveis por pessoas.
//! - **COM2 (`0x2F8`) — canal do agente.** JSON-RPC puro, um objeto por linha,
//!   sem nenhum ruído de log misturado.
//!
//! Separar os dois é o que torna a integração com o agente confiável. Se o
//! protocolo e os logs dividissem a mesma porta, todo cliente precisaria
//! adivinhar por heurística qual linha é resposta e qual é log — exatamente o
//! tipo de parsing frágil que este projeto existe para evitar. Com portas
//! distintas, o canal do agente é um stream limpo: toda linha que sai dele é
//! um objeto JSON válido, sempre.

use core::fmt;

use spin::Mutex;
use uart_16550::{Config, Uart16550, backend::PioBackend};

/// Endereço base da COM1. Fixo no barramento ISA desde o IBM PC original.
pub const COM1_BASE: u16 = 0x3F8;

/// Endereço base da COM2.
pub const COM2_BASE: u16 = 0x2F8;

/// Uma porta serial inicializada.
pub struct Serial(Uart16550<PioBackend>);

impl Serial {
    /// Abre e configura a UART no endereço informado.
    ///
    /// Retorna `None` se não houver dispositivo ali. Isso não é um erro: em
    /// muitas máquinas a COM2 simplesmente não existe, e o kernel precisa
    /// continuar bootando normalmente sem o canal do agente.
    ///
    /// # Safety
    ///
    /// `base` precisa ser o endereço de uma UART 16550 de verdade, e o
    /// chamador precisa garantir acesso exclusivo a ela.
    unsafe fn open(base: u16) -> Option<Self> {
        // SAFETY: delegada ao chamador pelo contrato acima.
        let mut uart = unsafe { Uart16550::new_port(base) }.ok()?;

        // `Config::DEFAULT` é 8-N-1 com FIFO ativado. O FIFO não é opcional
        // na prática: com ele desligado o modelo de dispositivo do QEMU nunca
        // drena os bytes, e o primeiro `send_bytes_exact` trava para sempre.
        uart.init(Config::DEFAULT).ok()?;

        Some(Self(uart))
    }

    /// Envia todos os bytes, aguardando espaço no FIFO conforme necessário.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.0.send_bytes_exact(bytes);
    }

    /// Lê um byte se houver algum disponível, sem bloquear.
    ///
    /// Não-bloqueante de propósito: o laço do agente precisa poder consultar a
    /// porta e seguir em frente quando não há nada, em vez de congelar o
    /// kernel esperando um cliente que talvez nunca conecte.
    pub fn read_byte(&mut self) -> Option<u8> {
        self.0.try_receive_byte().ok()
    }
}

impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}

/// COM1 — saída de log legível por humanos.
///
/// Usamos [`spin::Mutex`] e não `std::sync::Mutex` por um motivo fundamental:
/// um mutex normal *bloqueia a thread* quando está travado, e bloquear exige
/// um scheduler para escolher outra thread. Aqui nós *somos* o scheduler — não
/// existe para quem ceder. Então giramos em busy-wait até o lock liberar.
///
/// O `Option` existe porque [`Uart16550::new_port`] é falível e não é `const`,
/// então não dá para construir a porta direto num `static`. Fica `None` até
/// [`init`] rodar.
pub static CONSOLE: Mutex<Option<Serial>> = Mutex::new(None);

/// COM2 — canal estruturado do agente (JSON-RPC).
pub static AGENT_LINK: Mutex<Option<Serial>> = Mutex::new(None);

/// Inicializa as duas portas. Chame uma vez, o mais cedo possível no boot.
///
/// Retorna `true` se o canal do agente (COM2) estiver disponível.
pub fn init() -> bool {
    // SAFETY: rodamos antes de qualquer outro código tocar nessas portas, em
    // núcleo único, então o acesso é de fato exclusivo.
    *CONSOLE.lock() = unsafe { Serial::open(COM1_BASE) };
    let agente = unsafe { Serial::open(COM2_BASE) };
    let disponivel = agente.is_some();
    *AGENT_LINK.lock() = agente;
    disponivel
}

/// Implementação por trás de [`serial_print!`]. Não chame diretamente.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write as _;
    use x86_64::instructions::interrupts;

    // Este `without_interrupts` previne uma classe de deadlock clássica de
    // kernel: estamos segurando o lock da serial quando chega uma interrupção
    // cujo handler também tenta imprimir. Como o spinlock não é reentrante, o
    // handler giraria para sempre esperando um lock que só *nós* podemos
    // soltar — e nós só voltamos a rodar quando o handler retornar. Deadlock.
    //
    // Desabilitar interrupções durante a seção crítica torna isso impossível.
    interrupts::without_interrupts(|| {
        if let Some(porta) = CONSOLE.lock().as_mut() {
            // Ignoramos o erro: `write_str` nunca falha de verdade aqui, e um
            // `unwrap` no caminho de log viraria um pânico dentro do handler
            // de pânico.
            let _ = porta.write_fmt(args);
        }
    });
}

/// Escreve no console humano (COM1), sem quebra de linha.
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*))
    };
}

/// Escreve no console humano (COM1), com quebra de linha.
#[macro_export]
macro_rules! serial_println {
    () => { $crate::serial_print!("\n") };
    ($fmt:expr) => { $crate::serial_print!(concat!($fmt, "\n")) };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::serial_print!(concat!($fmt, "\n"), $($arg)*)
    };
}
