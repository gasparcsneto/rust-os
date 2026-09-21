//! Contabilidade e tratamento de falhas, neutra de arquitetura.
//!
//! # O problema
//!
//! Quando um kernel encontra uma exceção que não sabe tratar, o desfecho
//! normal é morrer — e, pior, morrer *mudo*. Num x86 sem handler instalado, um
//! page fault vira double fault, que vira triple fault, que reinicia a máquina
//! sem deixar rastro. É a pior experiência de depuração que existe: a máquina
//! simplesmente some.
//!
//! # A resposta deste kernel
//!
//! Toda falha é contabilizada por tipo e a última é preservada com contexto
//! (endereço da instrução, endereço acusado, código de erro bruto). O agente
//! lê isso por `traps.stats`.
//!
//! E para falhas não recuperáveis existe o **modo post-mortem**: em vez de
//! parar a CPU, o kernel volta a atender o canal do agente. O sistema está
//! morto para qualquer trabalho útil, mas continua capaz de responder o que
//! aconteceu — qual exceção, onde, com que código, e todo o histórico de log
//! que antecedeu. Um cadáver que responde à autópsia.
//!
//! É exatamente o tipo de coisa que só vale a pena construir num OS projetado
//! para ser operado por um agente, e é barata porque o canal já existe.

use spin::Mutex;

/// Quantos tipos distintos de falha conseguimos contabilizar.
const MAX_TIPOS: usize = 32;

#[derive(Clone, Copy)]
struct Contador {
    nome: &'static str,
    total: u64,
}

/// Uma falha, com o contexto que a arquitetura conseguiu fornecer.
#[derive(Clone, Copy)]
pub struct Falha {
    /// Nome canônico do tipo (`"page_fault"`, `"data_abort"`, ...).
    pub nome: &'static str,
    /// Endereço da instrução que falhou.
    pub pc: u64,
    /// Endereço de memória acusado, quando a falha tem um.
    pub endereco: Option<u64>,
    /// Código de erro bruto da arquitetura, preservado sem interpretação.
    ///
    /// Guardamos o valor cru de propósito: qualquer decodificação que
    /// fizéssemos perderia bits que podem importar, e o agente tem como
    /// consultar o manual da arquitetura. Mentir menos é melhor que
    /// interpretar mais.
    pub codigo: u64,
    /// Ordem global desta falha desde o boot.
    pub seq: u64,
}

struct Estado {
    contadores: [Contador; MAX_TIPOS],
    n: usize,
    ultima: Option<Falha>,
    total: u64,
}

static ESTADO: Mutex<Estado> = Mutex::new(Estado {
    contadores: [Contador {
        nome: "",
        total: 0,
    }; MAX_TIPOS],
    n: 0,
    ultima: None,
    total: 0,
});

/// Contabiliza uma falha e devolve seu número de sequência.
pub fn registrar(nome: &'static str, pc: u64, endereco: Option<u64>, codigo: u64) -> u64 {
    let mut estado = ESTADO.lock();

    let seq = estado.total;
    estado.total += 1;

    // Busca linear: com no máximo algumas dezenas de tipos, uma tabela hash
    // custaria mais em complexidade do que economizaria em ciclos — e este
    // caminho roda dentro de um handler de exceção, onde simplicidade vale
    // mais que velocidade.
    let mut achou = false;
    for i in 0..estado.n {
        if estado.contadores[i].nome == nome {
            estado.contadores[i].total += 1;
            achou = true;
            break;
        }
    }
    if !achou && estado.n < MAX_TIPOS {
        let n = estado.n;
        estado.contadores[n] = Contador { nome, total: 1 };
        estado.n = n + 1;
    }

    estado.ultima = Some(Falha {
        nome,
        pc,
        endereco,
        codigo,
        seq,
    });

    seq
}

/// Percorre os contadores por tipo.
pub fn com_contadores<F: FnMut(&'static str, u64)>(mut f: F) {
    let estado = ESTADO.lock();
    for i in 0..estado.n {
        f(estado.contadores[i].nome, estado.contadores[i].total);
    }
}

/// A falha mais recente, se houve alguma.
pub fn ultima() -> Option<Falha> {
    ESTADO.lock().ultima
}

/// Total de falhas desde o boot.
pub fn total() -> u64 {
    ESTADO.lock().total
}

/// Trata uma falha não recuperável: registra, reporta e entra em post-mortem.
///
/// Chamado pelos handlers de exceção de cada arquitetura quando não há como
/// retomar a execução normal.
pub fn fatal(nome: &'static str, pc: u64, endereco: Option<u64>, codigo: u64) -> ! {
    // Antes de qualquer outra coisa, destravamos os locks que precisamos usar.
    //
    // Isto é inseguro no caso geral, e deliberado: a exceção pode ter
    // interrompido uma seção crítica que segurava exatamente estes locks, e um
    // spinlock não é reentrante. Sem isto, a tentativa de *relatar* a falha
    // travaria o kernel — trocaríamos uma morte explicada por um silêncio.
    //
    // O risco é real (podemos observar estado parcialmente escrito), mas
    // aceitável: o sistema já está morto, e um relatório possivelmente
    // inconsistente vale infinitamente mais que nenhum.
    //
    // SAFETY: não há outro núcleo rodando, e a alternativa é o deadlock.
    unsafe {
        ESTADO.force_unlock();
        crate::log::destravar();
        crate::serial::destravar();
    }

    let seq = registrar(nome, pc, endereco, codigo);

    crate::log_error!(
        "traps",
        "FALHA FATAL #{}: {} em pc={:#x} codigo={:#x}",
        seq,
        nome,
        pc,
        codigo
    );
    if let Some(endereco) = endereco {
        crate::log_error!("traps", "endereco acusado: {:#x}", endereco);
    }
    crate::log_warn!(
        "traps",
        "entrando em modo post-mortem; o canal do agente segue respondendo"
    );

    // O sistema não pode mais fazer trabalho útil, mas pode explicar-se.
    crate::agent::servir()
}
