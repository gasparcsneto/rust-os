//! O executor: quem decide qual tarefa roda agora.
//!
//! # O executor ingênuo, e por que ele não serve
//!
//! A versão mais simples possível é uma fila circular: tire a primeira
//! tarefa, chame `poll`, e se vier `Pending` jogue-a no fim da fila. Funciona,
//! e é assim que se começa a entender o assunto.
//!
//! O problema aparece com uma tarefa que espera hardware. O canal do agente
//! passa a quase totalidade do tempo sem byte nenhum para ler; a fila
//! circular a repolla milhões de vezes por segundo para ouvir "ainda não".
//! O núcleo fica em 100% de uso sem fazer absolutamente nada.
//!
//! # A solução: o waker
//!
//! A assinatura de `Future::poll` recebe um [`Waker`]. O contrato é preciso:
//! quem devolve `Pending` **precisa** guardar esse waker em algum lugar e
//! chamá-lo quando o motivo da espera deixar de existir.
//!
//! Isso inverte a relação. O executor para de perguntar e passa a ser
//! avisado: a tarefa do agente guarda seu waker, o handler da interrupção da
//! serial o chama quando um byte chega, e só então a tarefa volta para a fila
//! de prontas. Entre um byte e outro, o executor não tem nada a fazer — e é aí
//! que ele consegue dormir de verdade.
//!
//! # Por que duas coleções
//!
//! As tarefas moram num [`BTreeMap`] indexado por [`IdTarefa`], e a fila de
//! prontas carrega apenas **ids**. Isso porque o waker é chamado de dentro de
//! um handler de interrupção, onde ele não tem — e não pode ter — acesso
//! mutável à coleção de tarefas. Um id é um `u64`: copiá-lo para uma fila é
//! uma operação barata, sem alocação e sem empréstimo.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use super::fila::Fila;
use super::{IdTarefa, Tarefa};

/// Quantas notificações de "acorde" cabem pendentes ao mesmo tempo.
///
/// Notificações duplicadas da mesma tarefa consomem espaço, então a fila
/// precisa de folga em relação ao número de tarefas, não igualdade.
const CAPACIDADE_PRONTAS: usize = 128;

/// Quantas tarefas o inventário visível ao agente consegue registrar.
const MAX_INVENTARIO: usize = 32;

/// Fila de tarefas prontas, compartilhada entre o executor e os wakers.
type FilaProntas = Fila<IdTarefa, CAPACIDADE_PRONTAS>;

pub struct Executor {
    /// Todas as tarefas vivas, indexadas por id.
    tarefas: BTreeMap<IdTarefa, Tarefa>,
    /// Ids que alguém pediu para acordar.
    ///
    /// `Arc` porque a posse é genuinamente compartilhada: cada waker precisa
    /// manter a fila viva, e o executor não tem como saber quantos wakers
    /// seus ainda existem por aí.
    prontas: Arc<FilaProntas>,
    /// Waker de cada tarefa, guardado depois de criado.
    ///
    /// Duas razões. A primeira é custo: criar um waker aloca, e não faz
    /// sentido pagar isso a cada `poll`. A segunda é mais sutil — um waker é
    /// contado por referência, e destruí-lo pode devolver memória ao heap.
    /// Guardando-os aqui, garantimos que nenhuma liberação de memória
    /// aconteça dentro de um handler de interrupção.
    despertadores: BTreeMap<IdTarefa, Waker>,
}

impl Executor {
    pub fn novo() -> Self {
        Self {
            tarefas: BTreeMap::new(),
            prontas: Arc::new(Fila::nova()),
            despertadores: BTreeMap::new(),
        }
    }

    /// Registra uma tarefa e a marca como pronta para rodar.
    pub fn lancar(&mut self, tarefa: Tarefa) {
        let id = tarefa.id();
        let nome = tarefa.nome();

        if self.tarefas.insert(id, tarefa).is_some() {
            // Ids vêm de um contador atômico que nunca repete. Cair aqui é
            // bug de verdade, não condição de corrida esperada.
            crate::log_error!("tarefa", "id {} duplicado ao lancar", id.numero());
            return;
        }

        inventario_registrar(id, nome);
        ESTATISTICAS.lancadas.fetch_add(1, Ordering::Relaxed);

        if self.prontas.enfileirar(id).is_err() {
            // Mesma perda do despertar, e o mesmo contador: esta tarefa foi
            // registrada, contada como lançada, e não vai rodar nenhuma vez.
            ESTATISTICAS.nunca_agendadas.fetch_add(1, Ordering::Relaxed);
            crate::log_error!("tarefa", "fila de prontas cheia ao lancar {}", nome);
        }
    }

    /// Avança todas as tarefas que foram acordadas. Devolve quantas rodaram.
    fn rodar_prontas(&mut self) -> usize {
        // Desestruturamos `self` porque o `entry(...)` do mapa de
        // despertadores precisa emprestar `self.prontas` para dentro da
        // closure, e o verificador de empréstimos não sabe separar campos de
        // `self` através de uma chamada de método.
        let Self {
            tarefas,
            prontas,
            despertadores,
        } = self;

        let mut rodadas = 0usize;

        while let Some(id) = prontas.desenfileirar() {
            let Some(tarefa) = tarefas.get_mut(&id) else {
                // Acordar uma tarefa que não existe mais é normal, não erro.
                // Quem registra um waker o faz *antes* de confirmar que
                // precisa dormir, justamente para não perder um aviso que
                // chegue no meio; o preço é receber avisos tardios de tarefas
                // que já terminaram.
                continue;
            };

            let waker = despertadores
                .entry(id)
                .or_insert_with(|| Despertar::waker(id, prontas.clone()));

            let mut contexto = Context::from_waker(waker);
            rodadas += 1;
            ESTATISTICAS.avancos.fetch_add(1, Ordering::Relaxed);

            match tarefa.avancar(&mut contexto) {
                Poll::Ready(()) => {
                    tarefas.remove(&id);
                    // O waker sai junto: mantê-lo só serviria para segurar
                    // memória de uma tarefa que não existe mais.
                    despertadores.remove(&id);
                    inventario_encerrar(id);
                    ESTATISTICAS.concluidas.fetch_add(1, Ordering::Relaxed);
                }
                Poll::Pending => {
                    // Nada a fazer: quem devolveu `Pending` ficou com a
                    // responsabilidade de nos acordar.
                }
            }
        }

        rodadas
    }

    /// Dorme se não houver nada pronto para rodar.
    ///
    /// A checagem parece redundante logo depois de [`Self::rodar_prontas`],
    /// que só retorna quando a fila esvazia — mas uma interrupção pode ter
    /// chegado entre as duas chamadas e enfileirado alguém.
    ///
    /// A corrida de verdade é outra, e mais traiçoeira: entre *checar* a fila
    /// e *dormir*. Se a interrupção cair nessa fresta, dormimos com trabalho
    /// pendente e só acordamos no próximo evento — no pior caso, uma
    /// requisição do agente fica parada até o timer seguinte. Por isso a
    /// checagem e o adormecer precisam ser atômicos, e é [`crate::arch`] quem
    /// sabe fazer isso em cada processador.
    fn dormir_se_ocioso(&self) {
        crate::arch::dormir_se_ocioso(|| self.prontas.vazia());
    }

    /// O laço principal do sistema. Nunca retorna.
    ///
    /// Sem chamador em modo de teste, pelo mesmo motivo de
    /// [`crate::agent::atender`]: a suíte precisa recuperar o controle, e
    /// daqui não se volta. Os testes usam [`Self::rodar_ate_esvaziar`].
    #[cfg_attr(feature = "modo-teste", allow(dead_code))]
    pub fn rodar(&mut self) -> ! {
        loop {
            self.rodar_prontas();
            self.dormir_se_ocioso();
        }
    }

    /// Roda até que não sobre nenhuma tarefa viva.
    ///
    /// Só existe para a suíte de testes: um teste precisa recuperar o controle
    /// ao fim, e [`Self::rodar`] nunca devolve. O `teto` protege contra uma
    /// tarefa que nunca termine — sem ele, um bug numa tarefa viraria um teste
    /// pendurado, que é o modo de falha mais caro de diagnosticar num CI.
    #[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
    pub fn rodar_ate_esvaziar(&mut self, teto: usize) -> Result<(), &'static str> {
        for _ in 0..teto {
            if self.tarefas.is_empty() {
                return Ok(());
            }
            self.rodar_prontas();
            if self.tarefas.is_empty() {
                return Ok(());
            }
            self.dormir_se_ocioso();
        }
        Err("tarefas nao terminaram dentro do teto de rodadas")
    }

    /// Quantas tarefas ainda estão vivas.
    #[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
    pub fn vivas(&self) -> usize {
        self.tarefas.len()
    }
}

// ---------------------------------------------------------------------------
// O waker
// ---------------------------------------------------------------------------

/// O que um waker deste executor precisa saber: quem acordar, e onde avisar.
struct Despertar {
    id: IdTarefa,
    prontas: Arc<FilaProntas>,
}

impl Despertar {
    /// Cria o waker já convertido para o tipo que `poll` espera.
    ///
    /// A conversão sai de graça: a `alloc` implementa `From<Arc<W>> for Waker`
    /// para todo `W: Wake`, montando a tabela de ponteiros de função que o
    /// [`Waker`] exige por baixo. Escrever essa tabela à mão é possível — e é
    /// `unsafe`, com um punhado de invariantes sobre ponteiros apagados que
    /// não há razão para assumir.
    fn waker(id: IdTarefa, prontas: Arc<FilaProntas>) -> Waker {
        Waker::from(Arc::new(Self { id, prontas }))
    }

    fn acordar(&self) {
        ESTATISTICAS.despertares.fetch_add(1, Ordering::Relaxed);
        if self.prontas.enfileirar(self.id).is_err() {
            // Um aviso perdido não é um aviso atrasado: a tarefa devolveu
            // `Pending` contando com este despertar, e sem ele **nunca mais**
            // roda. É a falha mais grave que este módulo consegue ter, e até
            // aqui a única prova dela era esta linha de log — num anel de cento
            // e vinte e oito registros, que dá a volta.
            //
            // O contador é o que sobrevive à volta do anel. A fila de bytes do
            // agente já tinha o dela, exposta em `tasks.stats` como
            // `input.dropped`, com um comentário explicando por que um número
            // diferente de zero ali importa. A fila de prontas tinha o mesmo
            // contador e ninguém o lia — e o que se perde aqui é pior.
            ESTATISTICAS.nunca_agendadas.fetch_add(1, Ordering::Relaxed);
            crate::log_error!(
                "tarefa",
                "fila de prontas cheia ao acordar {}",
                self.id.numero()
            );
        }
    }
}

impl Wake for Despertar {
    fn wake(self: Arc<Self>) {
        self.acordar();
    }

    /// Acordar sem consumir o `Arc`.
    ///
    /// Implementar isto é opcional, e vale a pena: sem ele, cada aviso
    /// clonaria o `Arc` — um incremento e um decremento de contador dentro de
    /// um handler de interrupção, com o decremento podendo chegar a zero e
    /// devolver memória ao heap ali dentro. Aqui, nada disso acontece.
    fn wake_by_ref(self: &Arc<Self>) {
        self.acordar();
    }
}

// ---------------------------------------------------------------------------
// Visibilidade para o agente
// ---------------------------------------------------------------------------

/// Contadores agregados do escalonador.
struct Estatisticas {
    lancadas: AtomicU64,
    concluidas: AtomicU64,
    avancos: AtomicU64,
    despertares: AtomicU64,
    /// Entradas que não couberam na fila de prontas.
    ///
    /// Conta os dois sítios que enfileiram — o lançamento e o despertar —
    /// porque a consequência é a mesma nos dois: uma tarefa que existe e não
    /// vai rodar. Separá-los daria dois números que o leitor teria de somar
    /// para chegar à única pergunta que importa.
    nunca_agendadas: AtomicU64,
    /// Tarefas que não couberam no inventário.
    ///
    /// Cada uma existe e roda; o que falta é a linha dela em `tasks.list`. Sem
    /// este número, a lista seria mais curta que a verdade sem dizer que é.
    fora_do_inventario: AtomicU64,
}

static ESTATISTICAS: Estatisticas = Estatisticas {
    lancadas: AtomicU64::new(0),
    concluidas: AtomicU64::new(0),
    avancos: AtomicU64::new(0),
    despertares: AtomicU64::new(0),
    nunca_agendadas: AtomicU64::new(0),
    fora_do_inventario: AtomicU64::new(0),
};

/// Uma linha do inventário de tarefas.
#[derive(Clone, Copy)]
pub struct Inscricao {
    pub id: u64,
    pub nome: &'static str,
    pub viva: bool,
}

/// Inventário das tarefas, para o comando `tasks.list`.
///
/// Existe separado do executor porque a tarefa do agente roda *dentro* do
/// executor: ela não tem como pegar emprestado quem a está executando. Uma
/// tabela estática de tamanho fixo resolve isso sem alocar e sem ciclo de
/// empréstimo.
static INVENTARIO: spin::Mutex<[Option<Inscricao>; MAX_INVENTARIO]> =
    spin::Mutex::new([None; MAX_INVENTARIO]);

fn inventario_registrar(id: IdTarefa, nome: &'static str) {
    crate::arch::sem_interrupcoes(|| {
        let mut tabela = INVENTARIO.lock();
        // Reaproveitamos a primeira vaga livre ou a de uma tarefa já
        // encerrada; um sistema de vida longa lança muito mais tarefas do que
        // mantém vivas ao mesmo tempo.
        let vaga = tabela
            .iter()
            .position(|e| e.is_none())
            .or_else(|| tabela.iter().position(|e| e.is_some_and(|i| !i.viva)));

        match vaga {
            Some(vaga) => {
                tabela[vaga] = Some(Inscricao {
                    id: id.numero(),
                    nome,
                    viva: true,
                });
            }
            // A tarefa foi lançada e vai rodar; o que não coube foi a linha
            // dela no relatório. Contamos para que `tasks.list` possa dizer
            // que é mais curta que a verdade — é o mesmo que `pci.list` faz
            // com `count` e `capacity`.
            None => {
                ESTATISTICAS
                    .fora_do_inventario
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    });
}

fn inventario_encerrar(id: IdTarefa) {
    crate::arch::sem_interrupcoes(|| {
        let mut tabela = INVENTARIO.lock();
        for entrada in tabela.iter_mut().flatten() {
            if entrada.id == id.numero() {
                entrada.viva = false;
            }
        }
    });
}

/// Percorre o inventário. Usado pelo canal do agente.
pub fn com_inventario<F: FnMut(Inscricao)>(mut f: F) {
    let tabela = crate::arch::sem_interrupcoes(|| *INVENTARIO.lock());
    for inscricao in tabela.into_iter().flatten() {
        f(inscricao);
    }
}

/// Os contadores do escalonador.
pub struct Contadores {
    pub lancadas: u64,
    pub concluidas: u64,
    pub avancos: u64,
    pub despertares: u64,
    pub nunca_agendadas: u64,
    pub fora_do_inventario: u64,
}

pub fn estatisticas() -> Contadores {
    Contadores {
        lancadas: ESTATISTICAS.lancadas.load(Ordering::Relaxed),
        concluidas: ESTATISTICAS.concluidas.load(Ordering::Relaxed),
        avancos: ESTATISTICAS.avancos.load(Ordering::Relaxed),
        despertares: ESTATISTICAS.despertares.load(Ordering::Relaxed),
        nunca_agendadas: ESTATISTICAS.nunca_agendadas.load(Ordering::Relaxed),
        fora_do_inventario: ESTATISTICAS.fora_do_inventario.load(Ordering::Relaxed),
    }
}

/// Quantas tarefas o inventário comporta.
pub const fn capacidade_do_inventario() -> usize {
    MAX_INVENTARIO
}

/// Quantas entradas a fila de prontas comporta.
///
/// Exposta para a suíte, que precisa do número exato para encher a fila de
/// propósito — um caso que chutasse "muitas tarefas" passaria a testar o
/// chute em vez do teto.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const fn capacidade_da_fila_de_prontas() -> usize {
    CAPACIDADE_PRONTAS
}
