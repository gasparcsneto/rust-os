//! Contabilidade de interrupções de hardware.
//!
//! Saber *quantas* interrupções cada linha gerou é uma das informações mais
//! úteis num kernel: um contador que não sobe denuncia um dispositivo mal
//! configurado, e um que sobe rápido demais denuncia uma tempestade de
//! interrupções — duas falhas que, sem esta visibilidade, se manifestam
//! apenas como "o sistema está lento".
//!
//! O agente lê tudo por `irq.stats`.
//!
//! Como [`crate::tempo`], usamos atômicos e não `Mutex`: este código roda
//! dentro de handlers de interrupção, onde tomar um spinlock que o código
//! preemptado já segurasse seria deadlock.
//!
//! A tabela de nomes é a exceção, e por isso é a única coisa aqui protegida
//! por `Mutex`: ela é escrita uma vez na inicialização e lida pelo canal do
//! agente, nunca de dentro de um handler. Ainda assim, os dois acessos
//! mascaram interrupções — com o escalonador preemptivo, dois fios podem
//! disputá-la, e um fio preemptado segurando um spinlock trava o seguinte.

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;

/// Quantas linhas de interrupção conseguimos contabilizar.
///
/// O PIC do x86 tem 16; o GIC do ARM começa em 32 para periféricos, mas as
/// linhas que usamos hoje (timer) são PPIs de numeração baixa. 64 cobre
/// ambos com folga.
pub const MAX_LINHAS: usize = 64;

static CONTADORES: [AtomicU64; MAX_LINHAS] = [const { AtomicU64::new(0) }; MAX_LINHAS];
static TOTAL: AtomicU64 = AtomicU64::new(0);

/// Nomes legíveis por linha, registrados pelo backend de arquitetura.
///
/// Este `Mutex` é seguro porque só é escrito durante a inicialização, antes
/// de qualquer interrupção ser habilitada, e lido apenas pelo canal do
/// agente — nunca de dentro de um handler.
static NOMES: Mutex<[&'static str; MAX_LINHAS]> = Mutex::new([""; MAX_LINHAS]);

/// Dá nome a uma linha. Chame na inicialização, antes de habilitar
/// interrupções.
pub fn nomear(linha: usize, nome: &'static str) {
    if linha < MAX_LINHAS {
        crate::arch::sem_interrupcoes(|| NOMES.lock()[linha] = nome);
    }
}

/// Contabiliza uma interrupção. Chamado de dentro dos handlers.
pub fn contabilizar(linha: usize) {
    if linha < MAX_LINHAS {
        CONTADORES[linha].fetch_add(1, Ordering::Relaxed);
    }
    TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Percorre as linhas que já dispararam ao menos uma vez.
///
/// Omitir linhas zeradas mantém a resposta do agente enxuta: 64 entradas em
/// que 62 são zero não informam nada.
pub fn com_contadores<F: FnMut(usize, &'static str, u64)>(mut f: F) {
    crate::arch::sem_interrupcoes(|| {
        let nomes = NOMES.lock();
        for linha in 0..MAX_LINHAS {
            let total = CONTADORES[linha].load(Ordering::Relaxed);
            if total > 0 {
                f(linha, nomes[linha], total);
            }
        }
    });
}

/// Quantas interrupções uma linha específica gerou.
///
/// Existe para quem precisa da resposta **de dentro do kernel**, e não do
/// relatório: a conferência do timer do APIC contra o PIT, que compara duas
/// linhas enquanto as duas ainda disparam. [`com_contadores`] não serviria —
/// ela mascara interrupções para percorrer a tabela de nomes, e mascará-las é
/// exatamente o que impediria a medida de acontecer.
///
/// O `allow` é condicionado à arquitetura de propósito: no ARM esta função
/// não tem chamador, porque o timer de lá não precisa ser calibrado contra
/// nada. Um `allow` incondicional esconderia o dia em que ela ficasse sem
/// chamador **no x86** também.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub fn contagem_da_linha(linha: usize) -> u64 {
    if linha >= MAX_LINHAS {
        return 0;
    }
    CONTADORES[linha].load(Ordering::Relaxed)
}

/// Total de interrupções de hardware desde o boot.
pub fn total() -> u64 {
    TOTAL.load(Ordering::Relaxed)
}
