//! Portas seriais do kernel, independentes de arquitetura.
//!
//! # Por que a serial vem antes de tudo
//!
//! Num kernel, o problema número um é *não ter como ver o que está
//! acontecendo*. Não existe `println!`, não existe debugger acoplado, e se
//! algo falha cedo o sistema fica mudo.
//!
//! A serial resolve isso: é o dispositivo de I/O mais simples que existe,
//! funciona desde o primeiro instante após o boot, e o QEMU consegue
//! redirecioná-la para o stdout do host ou para um socket.
//!
//! # Os dois papéis
//!
//! - **Console** — texto legível por humanos.
//! - **Canal do agente** — JSON-RPC puro, um objeto por linha.
//!
//! Quantas portas físicas atendem esses papéis é decisão de cada arquitetura
//! (ver [`crate::arch`]). O x86 tem duas UARTs legadas e dá uma para cada. A
//! máquina `virt` do ARM tem só uma, que vai para o canal do agente — lá não
//! há console de texto, e os registros de log são lidos por `log.tail`.
//!
//! O que **não** varia é a regra: onde houver canal do agente, ele é um
//! stream limpo. Nada de log em texto se mistura a ele, porque senão todo
//! cliente precisaria adivinhar por heurística qual linha é resposta e qual
//! é ruído — exatamente o tipo de parsing frágil que este projeto evita.

use core::fmt;

use spin::Mutex;

use crate::arch::{self, Uart};

/// Saída de texto legível por humanos, quando a plataforma tem uma.
///
/// Usamos [`spin::Mutex`] e não `std::sync::Mutex` por um motivo fundamental:
/// um mutex normal *bloqueia a thread* quando está travado, e bloquear exige
/// um scheduler para escolher outra thread. Aqui nós *somos* o scheduler — não
/// existe para quem ceder. Então giramos em busy-wait até o lock liberar.
///
/// O `Option` existe porque abrir a porta é falível e não é `const`, então não
/// dá para construí-la direto num `static`. Fica `None` até [`init`] rodar —
/// e permanece `None` em plataformas sem console dedicado.
pub static CONSOLE: Mutex<Option<Uart>> = Mutex::new(None);

/// Canal estruturado do agente (JSON-RPC).
pub static AGENT_LINK: Mutex<Option<Uart>> = Mutex::new(None);

/// Inicializa as portas. Chame uma vez, o mais cedo possível no boot.
///
/// Retorna `true` se o canal do agente estiver disponível.
pub fn init() -> bool {
    let (console, agente) = arch::init_seriais();
    *CONSOLE.lock() = console;

    let disponivel = agente.is_some();
    *AGENT_LINK.lock() = agente;
    disponivel
}

/// Implementação por trás de [`serial_print!`]. Não chame diretamente.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use fmt::Write as _;

    // Este bloqueio de interrupções previne uma classe de deadlock clássica
    // de kernel: estamos segurando o lock da serial quando chega uma
    // interrupção cujo handler também tenta imprimir. Como o spinlock não é
    // reentrante, o handler giraria para sempre esperando um lock que só
    // *nós* podemos soltar — e nós só voltamos a rodar quando o handler
    // retornar. Deadlock.
    arch::sem_interrupcoes(|| {
        if let Some(porta) = CONSOLE.lock().as_mut() {
            // Ignoramos o erro: `write_str` nunca falha de verdade aqui, e um
            // `unwrap` no caminho de log viraria um pânico dentro do handler
            // de pânico.
            let _ = porta.write_fmt(args);
        }
        // Sem console (caso do ARM), isto é um no-op silencioso. Os registros
        // continuam indo para o ring buffer de `crate::log`, então nada se
        // perde: só não há para onde ecoar em texto.
    });
}

/// Escreve no console humano, sem quebra de linha.
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*))
    };
}

/// Escreve no console humano, com quebra de linha.
#[macro_export]
macro_rules! serial_println {
    () => { $crate::serial_print!("\n") };
    ($fmt:expr) => { $crate::serial_print!(concat!($fmt, "\n")) };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::serial_print!(concat!($fmt, "\n"), $($arg)*)
    };
}
