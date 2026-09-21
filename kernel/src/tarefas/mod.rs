//! Multitarefa cooperativa com `async`/`await`.
//!
//! # As duas formas de multitarefa
//!
//! Na **preemptiva**, o sistema operacional interrompe uma tarefa em qualquer
//! ponto e troca para outra. É o que permite rodar programas em que não se
//! confia — nenhum deles consegue monopolizar a CPU. O preço é alto: cada
//! tarefa precisa da própria pilha, e cada troca exige salvar o estado inteiro
//! do processador.
//!
//! Na **cooperativa**, cada tarefa devolve o controle voluntariamente, em
//! pontos que ela própria escolhe. Não há pilha por tarefa nem salvamento de
//! registradores: a tarefa guarda exatamente o estado de que precisa para
//! continuar, e nada mais. O preço é confiança — uma tarefa que nunca ceda
//! trava o sistema inteiro.
//!
//! Esta é a fase cooperativa. A preemptiva vem depois, junto com o userspace,
//! e as duas vão conviver: cooperativa dentro do kernel, preemptiva entre
//! processos.
//!
//! # `async`/`await` *é* multitarefa cooperativa
//!
//! Não é analogia, é a mesma coisa com outro vocabulário:
//!
//! | multitarefa cooperativa | `async`/`await` |
//! |---|---|
//! | tarefa | [`Future`] |
//! | ceder a CPU | devolver `Poll::Pending` |
//! | estado salvo à mão | campos da máquina de estados gerada |
//! | escalonador | executor |
//!
//! O compilador transforma cada `async fn` numa máquina de estados em que
//! cada `.await` é um estado, e os valores vivos naquele ponto viram campos da
//! struct. É por isso que uma tarefa não precisa de pilha própria: o que
//! sobreviveria na pilha entre dois `.await` está guardado na struct.
//!
//! # O que este módulo tem
//!
//! - [`Tarefa`]: um futuro em `Box`, fixado na memória, com identidade.
//! - [`executor`]: o escalonador, com suporte real a *wakers* — ele não
//!   repolla uma tarefa até ser avisado de que ela tem o que fazer.
//! - [`fila`]: fila de capacidade fixa, escrita de dentro de handlers.
//! - [`relogio`]: [`relogio::Dormir`], o futuro que espera tempo passar.
//! - [`entrada`]: os bytes do canal do agente, entregues por interrupção.
//!
//! # Por que os futuros vão para o heap
//!
//! Um futuro gerado por `async` pode ser **autorreferente**: se um `.await`
//! acontece enquanto existe uma referência a outra variável local, a máquina
//! de estados guarda as duas, e uma aponta para a outra. Mover essa struct
//! invalidaria o ponteiro interno em silêncio.
//!
//! O Rust resolve isso proibindo o movimento, via [`core::pin::Pin`], e a
//! forma mais simples de honrar essa proibição é alocar no heap: o valor
//! nasce num endereço e fica lá até ser destruído. Daí `Pin<Box<dyn Future>>`
//! — e daí também a ordem em que este módulo aparece no kernel, depois do
//! alocador.

pub mod entrada;
pub mod executor;
pub mod fila;
pub mod relogio;

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll};

use alloc::boxed::Box;

/// Devolve o controle ao executor uma vez, sem esperar por nada.
///
/// É o `yield` explícito da multitarefa cooperativa. O `async`/`await` insere
/// pontos de cessão nos `.await`, mas uma tarefa que faça um trabalho longo
/// sem esperar por I/O nenhum não tem onde ceder — e, sendo cooperativa,
/// nenhuma outra tarefa roda enquanto ela não devolver o controle. Um
/// `ceder().await` no meio do laço resolve isso.
pub fn ceder() -> Ceder {
    Ceder { cedeu: false }
}

/// O futuro devolvido por [`ceder`].
pub struct Ceder {
    cedeu: bool,
}

impl Future for Ceder {
    type Output = ();

    fn poll(self: Pin<&mut Self>, contexto: &mut Context) -> Poll<()> {
        let este = self.get_mut();
        if este.cedeu {
            return Poll::Ready(());
        }
        este.cedeu = true;
        // Acordar antes de devolver `Pending` parece contraditório, mas é
        // exatamente o que "quero voltar, só não agora" significa: a tarefa
        // vai para o fim da fila de prontas e roda de novo assim que todas as
        // outras tiverem tido sua vez.
        contexto.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Identidade de uma tarefa, única durante toda a vida do sistema.
///
/// Existe porque um *waker* precisa dizer **qual** tarefa acordar, e uma
/// referência à tarefa não serviria: o waker vive mais que a chamada de
/// `poll`, é clonado e guardado por quem quiser acordá-la depois.
///
/// A ordenação é derivada porque o executor indexa as tarefas por este tipo
/// numa árvore de busca.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IdTarefa(u64);

impl IdTarefa {
    fn novo() -> Self {
        // Começa em 1 para que zero nunca seja um id válido — um campo
        // zerado por engano vira um erro visível em vez de apontar para a
        // primeira tarefa criada.
        static PROXIMO: AtomicU64 = AtomicU64::new(1);
        // `Relaxed` basta: só exigimos unicidade, não ordenação com nenhum
        // outro dado.
        Self(PROXIMO.fetch_add(1, Ordering::Relaxed))
    }

    pub fn numero(self) -> u64 {
        self.0
    }
}

/// Uma tarefa pronta para ser escalonada.
pub struct Tarefa {
    id: IdTarefa,
    /// Nome legível, para que `tasks.list` diga o que está rodando em vez de
    /// devolver uma lista de números.
    nome: &'static str,
    /// O futuro em si.
    ///
    /// `dyn` porque cada `async fn` tem um tipo anônimo próprio e queremos
    /// guardar tarefas diferentes na mesma coleção. `Pin<Box<…>>` porque o
    /// futuro pode ser autorreferente e não pode mudar de endereço.
    futuro: Pin<Box<dyn Future<Output = ()>>>,
}

impl Tarefa {
    /// Envolve um futuro numa tarefa.
    ///
    /// O futuro precisa produzir `()`: tarefas rodam pelo efeito colateral,
    /// não há a quem entregar um valor de retorno. E precisa ser `'static`
    /// porque a tarefa pode viver enquanto o sistema viver.
    pub fn nova(nome: &'static str, futuro: impl Future<Output = ()> + 'static) -> Self {
        Self {
            id: IdTarefa::novo(),
            nome,
            // `Box::pin` aloca e fixa numa operação só.
            futuro: Box::pin(futuro),
        }
    }

    pub fn id(&self) -> IdTarefa {
        self.id
    }

    pub fn nome(&self) -> &'static str {
        self.nome
    }

    /// Avança a tarefa até o próximo ponto de espera.
    ///
    /// Privado ao módulo: só o executor deve chamar, e só com um contexto
    /// cujo waker realmente saiba acordar *esta* tarefa.
    fn avancar(&mut self, contexto: &mut Context) -> Poll<()> {
        self.futuro.as_mut().poll(contexto)
    }
}
