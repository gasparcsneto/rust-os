//! Fila circular de capacidade fixa, segura dentro de um handler.
//!
//! # Por que não `VecDeque`
//!
//! Esta fila é escrita de dentro de handlers de interrupção e lida de dentro
//! de tarefas. Um `VecDeque` num `Mutex` teria dois defeitos graves nesse
//! papel:
//!
//! - **Ele aloca.** Quando enche, pede memória ao heap. Alocar dentro de um
//!   handler significa tomar o lock do alocador num ponto arbitrário do
//!   programa, e ainda pode falhar ou demorar se o heap estiver fragmentado.
//! - **Ele não tem teto.** Um dispositivo que dispare rápido demais consumiria
//!   memória até o sistema morrer, em vez de descartar o excesso e dizer
//!   quanto perdeu.
//!
//! Uma fila de capacidade fixa não tem nenhum dos dois problemas: o
//! armazenamento é um array, o custo por operação é constante, e o excesso
//! vira um contador de descartes que o agente pode consultar.
//!
//! # Por que não precisamos de uma fila *lock-free*
//!
//! A literatura resolve este problema com estruturas atômicas (a `ArrayQueue`
//! do `crossbeam`, por exemplo), porque um `Mutex` comum aqui seria deadlock:
//! se uma tarefa segura o lock e a interrupção chega, o handler gira para
//! sempre esperando um lock que só a tarefa interrompida pode soltar.
//!
//! Este kernel já resolve essa classe inteira de outro jeito, e de forma mais
//! geral: **todo lock compartilhado com um handler é tomado com as
//! interrupções mascaradas** ([`crate::arch::sem_interrupcoes`]). Com um único
//! núcleo, isso torna o cenário do deadlock impossível de existir — nenhum
//! handler chega a rodar enquanto o lock está na mão de alguém. É a mesma
//! disciplina que já protege o heap, o ring buffer de log e as tabelas de
//! página.
//!
//! Quando houver múltiplos núcleos, mascarar interrupções deixa de bastar e
//! esta é uma das estruturas que terão de virar atômicas de verdade.

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;

/// Uma fila FIFO com capacidade `N`, escrevível de dentro de um handler.
///
/// Os métodos pedem `&self` e não `&mut self` de propósito: a fila vive num
/// `static` ou dentro de um [`alloc::sync::Arc`] compartilhado, onde não há
/// como obter uma referência mutável.
pub struct Fila<T: Copy, const N: usize> {
    interior: Mutex<Anel<T, N>>,
    /// Quantos itens foram descartados por fila cheia.
    ///
    /// Um descarte silencioso é a pior falha possível numa fila: o sintoma
    /// aparece longe da causa, como uma requisição truncada ou uma tecla que
    /// não chegou. Contar torna o problema visível em `tasks.stats`.
    descartados: AtomicU64,
}

struct Anel<T: Copy, const N: usize> {
    itens: [Option<T>; N],
    inicio: usize,
    tam: usize,
}

impl<T: Copy, const N: usize> Fila<T, N> {
    pub const fn nova() -> Self {
        // Capacidade zero tornaria os `% N` das duas operações uma divisão por
        // zero. Como `N` é sempre uma constante escolhida por nós, dá para
        // recusar em tempo de compilação em vez de descobrir com um pânico
        // dentro de um handler de interrupção.
        const { assert!(N > 0, "uma fila precisa de capacidade maior que zero") };

        Self {
            interior: Mutex::new(Anel {
                itens: [const { None }; N],
                inicio: 0,
                tam: 0,
            }),
            descartados: AtomicU64::new(0),
        }
    }

    /// Enfileira um item. Devolve `Err(item)` se a fila estiver cheia.
    pub fn enfileirar(&self, item: T) -> Result<(), T> {
        crate::arch::sem_interrupcoes(|| {
            let mut anel = self.interior.lock();
            if anel.tam == N {
                self.descartados.fetch_add(1, Ordering::Relaxed);
                return Err(item);
            }
            let posicao = (anel.inicio + anel.tam) % N;
            anel.itens[posicao] = Some(item);
            anel.tam += 1;
            Ok(())
        })
    }

    /// Retira o item mais antigo, se houver.
    pub fn desenfileirar(&self) -> Option<T> {
        crate::arch::sem_interrupcoes(|| {
            let mut anel = self.interior.lock();
            if anel.tam == 0 {
                return None;
            }
            let inicio = anel.inicio;
            let item = anel.itens[inicio].take();
            anel.inicio = (inicio + 1) % N;
            anel.tam -= 1;
            item
        })
    }

    pub fn vazia(&self) -> bool {
        crate::arch::sem_interrupcoes(|| self.interior.lock().tam == 0)
    }

    pub fn ocupacao(&self) -> usize {
        crate::arch::sem_interrupcoes(|| self.interior.lock().tam)
    }

    pub const fn capacidade(&self) -> usize {
        N
    }

    pub fn descartados(&self) -> u64 {
        self.descartados.load(Ordering::Relaxed)
    }

    /// Destrava a fila à força, para uso exclusivo do caminho de falha fatal.
    ///
    /// # Safety
    ///
    /// Só pode ser chamada quando o kernel já está em falha irrecuperável e
    /// não há outro núcleo em execução. Ver [`crate::traps::fatal`].
    pub unsafe fn destravar(&self) {
        unsafe { self.interior.force_unlock() }
    }
}
