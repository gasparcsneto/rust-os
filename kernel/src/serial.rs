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
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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

/// Bytes de saída que não couberam na FIFO dentro do tempo tolerado.
///
/// # Por que existe
///
/// Porque a alternativa era o kernel travar. A espera por espaço na FIFO era
/// um laço sem saída: enquanto o outro lado não drenasse, o kernel girava ali
/// dentro para sempre — com as interrupções mascaradas, porque `_print` as
/// mascara. Basta um cliente conectar no socket do canal e parar de ler.
///
/// O mesmo arquivo do x86 já enunciava a regra, para o laço de leitura: "uma
/// UART com defeito pode reportar dados disponíveis indefinidamente, e um
/// laço sem saída aqui travaria o boot". Valia igual para a escrita, e a
/// escrita não a aplicava — em nenhuma das duas arquiteturas.
///
/// Descartar byte de log é ruim; o comentário do PL011 dizia, com razão, que
/// "o log some de vez em quando" é caro de diagnosticar. O que ele descrevia
/// era o sumiço **silencioso**, e é isso que este contador desfaz: o log fica
/// incompleto e diz que ficou, em `system.info`.
static BYTES_DE_SAIDA_PERDIDOS: AtomicU64 = AtomicU64::new(0);

/// A porta parou de drenar na última tentativa?
///
/// # Por que um estado, e não só o teto
///
/// Porque o teto sozinho troca um travamento por um rastejo. Medido, com uma
/// FIFO simulada como permanentemente cheia: o kernel sobrevive, e cada linha
/// de log passa a custar o orçamento inteiro — dez milhões de voltas, com as
/// interrupções mascaradas, uma vez por escrita. O kernel não morre e também
/// não serve para nada.
///
/// Com este estado, o orçamento é pago **uma vez**. Depois dele, enquanto a
/// porta continuar parada, cada escrita desiste na primeira conferência.
///
/// A recuperação é automática e não precisa de código: a conferência da FIFO
/// é a condição do laço, então no instante em que ela abrir espaço o byte sai
/// e o estado se limpa. Não há retentativa a agendar nem temporizador a
/// manter.
static SAIDA_TRAVADA: AtomicBool = AtomicBool::new(false);

/// O orçamento de espera para a próxima escrita.
///
/// Zero enquanto a porta estiver dada como parada — ver [`SAIDA_TRAVADA`].
pub fn orcamento_de_saida() -> u32 {
    if SAIDA_TRAVADA.load(Ordering::Relaxed) {
        0
    } else {
        VOLTAS_ESPERANDO_A_FIFO
    }
}

/// Registra que um byte saiu: a porta está drenando.
pub fn saida_fluiu() {
    if SAIDA_TRAVADA.load(Ordering::Relaxed) {
        SAIDA_TRAVADA.store(false, Ordering::Relaxed);
    }
}

/// Contabiliza bytes que a porta não conseguiu enviar.
pub fn perder_saida(quantos: u64) {
    SAIDA_TRAVADA.store(true, Ordering::Relaxed);
    BYTES_DE_SAIDA_PERDIDOS.fetch_add(quantos, Ordering::Relaxed);
}

/// Quantos bytes de saída se perderam desde o boot.
pub fn bytes_de_saida_perdidos() -> u64 {
    BYTES_DE_SAIDA_PERDIDOS.load(Ordering::Relaxed)
}

/// Quantas voltas esperar por espaço na FIFO antes de desistir do resto.
///
/// Orçamento para a chamada inteira, e não por byte: no caminho ruim, um teto
/// por byte multiplicaria a espera pelo tamanho da mensagem.
///
/// Dez milhões é folgado por ordens de grandeza sobre o que uma FIFO leva
/// para abrir espaço — a 115200 baud, um byte sai em cerca de 87 µs — e é
/// pequeno o bastante para que um canal parado não pendure o kernel.
pub const VOLTAS_ESPERANDO_A_FIFO: u32 = 10_000_000;

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

/// Destrava as portas à força, para uso exclusivo do caminho de pânico.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        CONSOLE.force_unlock();
        AGENT_LINK.force_unlock();
    }
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

        // E na tela, que é o console de quem está na frente da máquina em vez
        // de na frente do terminal do hospedeiro.
        //
        // Os dois destinos recebem o **mesmo** texto, e é de propósito: um
        // console que mostrasse outra coisa seria uma segunda verdade para
        // manter. Quem não tem nenhum dos dois não perde nada — os registros
        // vão para o anel de `crate::log` de qualquer forma, e `log.tail` os
        // devolve.
        let _ = crate::tela::console::Saida.write_fmt(args);
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
