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
/// # Por que 256, e por que 64 deixou de bastar
///
/// O que se contabiliza não é uma "linha" no mesmo sentido nos dois lados. No
/// ARM é o INTID do GIC, e os que este kernel usa cabem folgadamente abaixo de
/// 64. No x86, desde que o APIC local entrou, é o **vetor** — e o vetor de
/// interrupções espúrias que o APIC exige é o 255.
///
/// O teto anterior era 64, com um comentário dizendo que cobria ambos com
/// folga. Ele deixou de cobrir no commit que acrescentou o APIC, e nada
/// reclamou: `nomear` e `contabilizar` descartam em silêncio o que passa do
/// teto. O efeito seria um `irq.stats` com um total que não fecha com a soma
/// das linhas, sem nada explicando a diferença — que é o tipo de número que
/// faz um agente concluir a coisa errada.
///
/// 256 é o espaço de vetores inteiro do x86, então não há como faltar de novo.
/// Custa seis KiB de `.bss` numa máquina com centenas de MiB.
pub const MAX_LINHAS: usize = 256;

static CONTADORES: [AtomicU64; MAX_LINHAS] = [const { AtomicU64::new(0) }; MAX_LINHAS];
static TOTAL: AtomicU64 = AtomicU64::new(0);

/// Interrupções que chegaram numa linha acima do teto e não puderam ser
/// atribuídas a ela.
///
/// Existe para que a diferença entre o total e a soma das linhas tenha nome.
/// Um número que não fecha e não se explica é pior que um número ausente.
static FORA_DO_TETO: AtomicU64 = AtomicU64::new(0);

/// Nomes legíveis por linha, registrados pelo backend de arquitetura.
///
/// Este `Mutex` é seguro porque só é escrito durante a inicialização, antes
/// de qualquer interrupção ser habilitada, e lido apenas pelo canal do
/// agente — nunca de dentro de um handler.
static NOMES: Mutex<[&'static str; MAX_LINHAS]> = Mutex::new([""; MAX_LINHAS]);

/// Dá nome a uma linha. Chame na inicialização, antes de habilitar
/// interrupções.
///
/// Uma linha acima do teto é reportada em vez de descartada calada: foi
/// exatamente esse silêncio que deixou o vetor espúrio do APIC sem nome por
/// um commit inteiro. Ver [`MAX_LINHAS`].
pub fn nomear(linha: usize, nome: &'static str) {
    if linha >= MAX_LINHAS {
        crate::log_warn!(
            "irq",
            "linha {} acima do teto de {}; ficara sem nome",
            linha,
            MAX_LINHAS
        );
        return;
    }
    crate::arch::sem_interrupcoes(|| NOMES.lock()[linha] = nome);
}

/// Contabiliza uma interrupção. Chamado de dentro dos handlers.
///
/// Não reporta uma linha acima do teto, ao contrário de [`nomear`]: aqui
/// estamos dentro de um handler, e registrar dali seria tomar a trava do log
/// no pior lugar possível. O que denuncia o caso é [`FORA_DO_TETO`], que o
/// relatório do agente expõe.
pub fn contabilizar(linha: usize) {
    if linha < MAX_LINHAS {
        CONTADORES[linha].fetch_add(1, Ordering::Relaxed);
    } else {
        FORA_DO_TETO.fetch_add(1, Ordering::Relaxed);
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

/// Quantas chegaram numa linha que o teto não cobre.
pub fn fora_do_teto() -> u64 {
    FORA_DO_TETO.load(Ordering::Relaxed)
}

/// Destrava a tabela de nomes de linha à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { NOMES.force_unlock() };
}
