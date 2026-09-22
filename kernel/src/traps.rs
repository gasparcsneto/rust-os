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

use core::sync::atomic::{AtomicU64, Ordering};

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
}

static ESTADO: Mutex<Estado> = Mutex::new(Estado {
    contadores: [Contador { nome: "", total: 0 }; MAX_TIPOS],
    n: 0,
    ultima: None,
});

/// Total de falhas desde o boot.
///
/// Vive fora do `Mutex` de propósito. É o único número que **precisa** estar
/// certo mesmo quando o detalhamento não pôde ser gravado — ver [`registrar`].
static TOTAL: AtomicU64 = AtomicU64::new(0);

/// Falhas cujo detalhamento se perdeu porque a trava estava ocupada.
///
/// Um valor diferente de zero aqui significa que uma exceção aconteceu dentro
/// de uma seção crítica deste módulo. É raro, e é exatamente o tipo de coisa
/// que precisa aparecer em vez de sumir.
static DETALHES_PERDIDOS: AtomicU64 = AtomicU64::new(0);

/// Uma falha que o código em execução espera provocar de propósito.
///
/// Existe para um único caso, e um caso que não teria outra forma de ser
/// testado: verificar que um estouro de pilha realmente é detectado. Não há
/// como retornar de um double fault nem de um abort na guard page — a pilha
/// que permitiria voltar é justamente a que estourou. Então, em vez de
/// retomar, o handler reconhece que esta era a falha esperada e encerra o
/// emulador com sucesso.
static ESPERADA: Mutex<Option<&'static str>> = Mutex::new(None);

/// Declara que a próxima falha fatal com este nome é esperada.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn esperar(nome: &'static str) {
    crate::arch::sem_interrupcoes(|| *ESPERADA.lock() = Some(nome));
}

/// Contabiliza uma falha e devolve seu número de sequência.
///
/// # Por que esta função não pode bloquear
///
/// Ela roda dentro de handlers de exceção, e uma exceção acontece em
/// *qualquer* instrução — inclusive numa que já segure esta trava. Mascarar
/// interrupções, que é a disciplina do resto do kernel, não ajuda aqui:
/// mascarar impede que um *handler de interrupção* preempte o dono da trava,
/// mas não impede uma exceção síncrona. Um `lock()` normal giraria para
/// sempre esperando uma trava que só o código interrompido pode soltar.
///
/// E o desfecho seria o pior possível: o kernel travaria em silêncio
/// exatamente no instante em que deveria relatar a falha.
///
/// A saída tem duas partes. O contador total é atômico, então nunca depende
/// da trava. O detalhamento — contagem por tipo e a última falha — é tentado
/// com `try_lock`, e quando não dá, contabilizamos a perda em vez de esperar.
pub fn registrar(nome: &'static str, pc: u64, endereco: Option<u64>, codigo: u64) -> u64 {
    let seq = TOTAL.fetch_add(1, Ordering::Relaxed);

    // A máscara evita o caso comum de disputa (um handler de interrupção
    // preemptando uma leitura de `traps.stats`); o `try_lock` cobre o caso
    // que a máscara não alcança, que é a exceção síncrona.
    crate::arch::sem_interrupcoes(|| {
        let Some(mut estado) = ESTADO.try_lock() else {
            DETALHES_PERDIDOS.fetch_add(1, Ordering::Relaxed);
            return;
        };

        // Busca linear: com no máximo algumas dezenas de tipos, uma tabela
        // hash custaria mais em complexidade do que economizaria em ciclos — e
        // este caminho roda dentro de um handler de exceção, onde simplicidade
        // vale mais que velocidade.
        let mut achou = false;
        let n = estado.n;
        for contador in estado.contadores[..n].iter_mut() {
            if contador.nome == nome {
                contador.total += 1;
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
    });

    seq
}

/// Percorre os contadores por tipo.
pub fn com_contadores<F: FnMut(&'static str, u64)>(mut f: F) {
    crate::arch::sem_interrupcoes(|| {
        let estado = ESTADO.lock();
        for contador in &estado.contadores[..estado.n] {
            f(contador.nome, contador.total);
        }
    });
}

/// A falha mais recente, se houve alguma.
pub fn ultima() -> Option<Falha> {
    crate::arch::sem_interrupcoes(|| ESTADO.lock().ultima)
}

/// Total de falhas desde o boot.
pub fn total() -> u64 {
    TOTAL.load(Ordering::Relaxed)
}

/// Quantas falhas ficaram sem detalhamento por disputa da trava.
pub fn detalhes_perdidos() -> u64 {
    DETALHES_PERDIDOS.load(Ordering::Relaxed)
}

/// Executa `f` com a trava de detalhamento na mão.
///
/// Existe só para a suíte de testes, e testa algo que de outra forma não teria
/// como ser testado: que [`registrar`] não bloqueia quando a trava está
/// ocupada. Esse é o cenário da exceção que acontece dentro de uma seção
/// crítica deste módulo — raro, impossível de provocar de fora, e exatamente
/// o que travaria o kernel no pior momento possível.
#[cfg(feature = "modo-teste")]
pub fn com_trava_ocupada<R>(f: impl FnOnce() -> R) -> R {
    let _guarda = ESTADO.lock();
    f()
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
        ESPERADA.force_unlock();
        crate::log::destravar();
        crate::serial::destravar();
        crate::tarefas::entrada::destravar();
    }

    // Para o escalonador antes de qualquer outra coisa. Com multitarefa
    // preemptiva, o timer continuaria trocando de fio enquanto montamos o
    // relatório: os outros fios rodariam por cima de um estado que já se sabe
    // corrompido, e disputariam o canal do agente com a própria autópsia.
    //
    // A partir daqui o fio que falhou é o único que roda.
    crate::fios::congelar();

    // Se esta falha era a esperada, ela é o resultado de um teste e não um
    // acidente. Conferimos antes de qualquer registro para que a saída
    // complete a linha que o executor deixou pela metade.
    #[cfg(feature = "modo-teste")]
    if *ESPERADA.lock() == Some(nome) {
        crate::serial_println!("ok");
        crate::qemu::encerrar(crate::qemu::Resultado::Sucesso)
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
