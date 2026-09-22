//! Multitarefa **preemptiva**: fios de execução do kernel.
//!
//! # A diferença para [`crate::tarefas`]
//!
//! As duas convivem, e resolvem problemas diferentes.
//!
//! Uma [tarefa](crate::tarefas) é cooperativa: ela cede a CPU nos `.await`, e
//! só neles. É barata — não tem pilha própria, e o estado que sobrevive entre
//! duas suspensões é a struct que o compilador gera. O preço é confiança: uma
//! tarefa que entre num laço longo sem `.await` trava todas as outras.
//!
//! Um **fio** é preemptivo: o timer o interrompe em qualquer instrução e passa
//! a vez a outro. Não é preciso confiar em ninguém. O preço é uma pilha por
//! fio e uma troca de contexto mais cara.
//!
//! A divisão que este kernel adota é a usual: o executor cooperativo roda
//! dentro de **um** fio, e outros fios existem para trabalho que não dá para
//! escrever como máquina de estados — ou que não se pode confiar que ceda.
//!
//! # Como a troca acontece em cada arquitetura
//!
//! Aqui as duas divergem, e a divergência é deliberada: cada uma usa o
//! mecanismo natural do seu processador, como já acontece com IDT/vetores e
//! IST/`SP_ELx`.
//!
//! No **x86_64** o quadro de interrupção é empilhado na pilha do próprio fio.
//! Trocar de fio é trocar de pilha: a rotina em assembly empilha os
//! registradores que a convenção de chamada manda preservar, troca `rsp`, e
//! retorna — só que na pilha do outro fio, e portanto no ponto em que *ele*
//! tinha parado.
//!
//! No **aarch64** as exceções rodam numa pilha própria (`SP_EL1`), separada da
//! pilha do fio (`SP_EL0`) — é o que dá a detecção de estouro de graça. Trocar
//! a pilha de dentro do handler misturaria as duas. Então lá a troca é outra:
//! o contexto completo já está salvo no [quadro de exceção], e trocar de fio é
//! **trocar o quadro** — guardar o do fio que sai, escrever o do que entra, e
//! deixar o `eret` fazer o resto. A cessão voluntária passa por `svc`
//! justamente para cair nesse mesmo caminho.
//!
//! [quadro de exceção]: crate::arch
//!
//! # Travas e preempção
//!
//! Com preempção, toda trava compartilhada entre fios precisa ser tomada com
//! as interrupções mascaradas — não por elegância, mas porque um spinlock não
//! é reentrante e um fio preemptado segurando a trava faria o próximo girar
//! para sempre. Mascarar interrupções desliga a preempção junto, e é por isso
//! que [`crate::frames`], [`crate::machine`], [`crate::heap`] e companhia
//! fazem todos os seus acessos por dentro de `sem_interrupcoes`.

pub mod pilha;

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;

use crate::arch::Contexto;
use pilha::Pilha;

/// Quantos fios o kernel comporta.
///
/// Fixo para que o escalonador não aloque: ele roda dentro do handler do
/// timer, onde pedir memória seria tomar a trava do heap num ponto arbitrário
/// do programa.
pub const MAX_FIOS: usize = 16;

/// Quantos tiques do timer um fio roda antes de ser preemptado.
///
/// A 100 Hz, 5 tiques são 50 ms. Curto o bastante para o sistema parecer
/// responsivo, longo o bastante para a troca de contexto não dominar o tempo
/// de CPU.
pub const QUANTUM_EM_TIQUES: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Estado {
    /// Pronto para rodar, esperando a vez.
    Pronto,
    /// É o fio que está executando agora.
    Rodando,
    /// Terminou. A vaga pode ser reaproveitada.
    Terminado,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IdFio(u64);

impl IdFio {
    pub fn numero(self) -> u64 {
        self.0
    }
}

/// Tudo que o kernel precisa saber sobre um fio de execução.
struct Fio {
    id: IdFio,
    nome: &'static str,
    estado: Estado,
    /// O estado do processador salvo enquanto este fio não roda.
    contexto: Contexto,
    /// A pilha, quando o fio tem uma própria.
    ///
    /// O fio inicial — aquele em que o kernel já estava rodando quando o
    /// escalonador ligou — não tem: a pilha dele veio do boot e não é nossa
    /// para liberar.
    _pilha: Option<Pilha>,
    /// Quantas vezes este fio já foi escalonado.
    escalonamentos: u64,
}

struct Escalonador {
    fios: [Option<Fio>; MAX_FIOS],
    /// Índice do fio que está executando.
    atual: usize,
    /// Tiques restantes antes de preemptar o fio atual.
    quantum: u32,
    ligado: bool,
}

static ESCALONADOR: Mutex<Escalonador> = Mutex::new(Escalonador {
    fios: [const { None }; MAX_FIOS],
    atual: 0,
    quantum: QUANTUM_EM_TIQUES,
    ligado: false,
});

static PROXIMO_ID: AtomicU64 = AtomicU64::new(1);
static TROCAS: AtomicU64 = AtomicU64::new(0);

/// Quantas vezes o quantum de um fio se esgotou.
///
/// É diferente do número de trocas, e a diferença informa: um quantum que
/// vence sem que haja outro fio pronto não gera troca nenhuma. Comparar os
/// dois números diz se o sistema tem concorrência de verdade ou um fio só.
static QUANTUNS_VENCIDOS: AtomicU64 = AtomicU64::new(0);

fn com_escalonador<R>(f: impl FnOnce(&mut Escalonador) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut ESCALONADOR.lock()))
}

/// Adota o contexto de execução atual como o primeiro fio.
///
/// Precisa rodar antes de qualquer [`criar`]. O fio inicial é especial por um
/// motivo simples: ele já está rodando, então não há contexto para preparar —
/// o contexto dele será escrito na primeira vez que ele ceder a vez.
pub fn init() {
    com_escalonador(|e| {
        if e.ligado {
            return;
        }
        e.fios[0] = Some(Fio {
            id: IdFio(PROXIMO_ID.fetch_add(1, Ordering::Relaxed)),
            nome: "kernel",
            estado: Estado::Rodando,
            contexto: Contexto::vazio(),
            _pilha: None,
            escalonamentos: 1,
        });
        e.atual = 0;
        e.quantum = QUANTUM_EM_TIQUES;
        e.ligado = true;
    });

    crate::log_info!(
        "fios",
        "escalonador preemptivo ativo, quantum de {} tiques",
        QUANTUM_EM_TIQUES
    );
}

/// Cria um fio novo, pronto para rodar.
///
/// `entrada` recebe `argumento` e não deve retornar; se retornar, o fio é
/// encerrado como se tivesse chamado [`terminar`].
// O primeiro consumidor de produção chega com os processos, na próxima etapa
// desta fase: hoje o kernel roda um fio só — aquele em que ele já estava —, e
// quem exercita a criação é a suíte de testes. Anotar aqui é mais honesto que
// inventar um fio de demonstração só para o build ficar limpo.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn criar(
    nome: &'static str,
    entrada: extern "C" fn(u64) -> !,
    argumento: u64,
) -> Result<IdFio, &'static str> {
    // Duas coisas acontecem **fora** da trava do escalonador, e as duas por
    // motivo de ordem de travas.
    //
    // A primeira é retirar o fio morto que ocupava a vaga. Largá-lo aqui
    // dentro faria o `Drop` da pilha dele desmapear páginas — ou seja, tomar
    // as travas da paginação e do alocador de frames — com a do escalonador na
    // mão, e com as interrupções mascaradas. Retiramos sob a trava e soltamos
    // fora dela.
    //
    // A segunda é mapear a pilha nova, pelo mesmo motivo. Aninhar travas é o
    // começo de todo deadlock; manter a ordem trivial é mais barato que provar
    // que a ordem é segura.
    let (vaga, ocupante_morto) = com_escalonador(|e| {
        let vaga = e.vaga_livre()?;
        Ok::<_, &'static str>((vaga, e.fios[vaga].take()))
    })?;
    drop(ocupante_morto);

    let pilha = pilha::reservar(vaga)?;

    let mut contexto = Contexto::vazio();
    // SAFETY: a pilha foi mapeada agora e pertence exclusivamente a este fio;
    // `topo` é o endereço logo acima dela, alinhado em página.
    unsafe { crate::arch::preparar_contexto(&mut contexto, pilha.topo(), entrada, argumento) };

    let id = IdFio(PROXIMO_ID.fetch_add(1, Ordering::Relaxed));

    com_escalonador(|e| {
        e.fios[vaga] = Some(Fio {
            id,
            nome,
            estado: Estado::Pronto,
            contexto,
            _pilha: Some(pilha),
            escalonamentos: 0,
        });
    });

    Ok(id)
}

impl Escalonador {
    /// Uma vaga livre, ou a de um fio já encerrado.
    ///
    /// A vaga do fio **atual** nunca entra na conta, mesmo que ele esteja
    /// marcado como encerrado. Um fio que chamou [`terminar`] segue executando
    /// até ceder a vez, e `e.atual` continua apontando para a vaga dele: se
    /// outro fio a ocupasse nesse intervalo, a próxima troca salvaria o
    /// contexto do moribundo por cima do contexto do recém-criado, e o
    /// recém-criado passaria a retomar num ponto que nunca foi dele.
    fn vaga_livre(&self) -> Result<usize, &'static str> {
        self.fios
            .iter()
            .enumerate()
            .position(|(i, f)| {
                i != self.atual
                    && match f {
                        None => true,
                        Some(fio) => fio.estado == Estado::Terminado,
                    }
            })
            .ok_or("nao ha vaga livre para outro fio")
    }

    /// O próximo fio pronto, em rodízio a partir do atual.
    ///
    /// Rodízio simples: varremos a tabela a partir da posição seguinte à
    /// atual, dando a volta. É O(MAX_FIOS) no pior caso, o que com 16 vagas é
    /// barato o bastante para rodar dentro de um handler.
    fn proximo_pronto(&self) -> Option<usize> {
        (1..=MAX_FIOS)
            .map(|passo| (self.atual + passo) % MAX_FIOS)
            .find(|&i| matches!(&self.fios[i], Some(f) if f.estado == Estado::Pronto))
    }
}

/// O que a troca de contexto precisa saber: de onde sair e para onde ir.
pub struct Troca {
    /// Onde guardar o contexto do fio que está saindo.
    pub de: *mut Contexto,
    /// De onde ler o contexto do fio que está entrando.
    pub para: *const Contexto,
}

/// Escolhe o próximo fio e prepara a troca, ou devolve `None` se não há para
/// quem trocar.
///
/// Só a *escolha* acontece aqui. Executar a troca é trabalho do backend de
/// arquitetura, porque o mecanismo difere entre os dois — ver o cabeçalho
/// deste módulo.
///
/// # Safety
///
/// Precisa ser chamada com as interrupções mascaradas, e os ponteiros
/// devolvidos só valem enquanto elas continuarem mascaradas: eles apontam para
/// dentro da tabela do escalonador.
pub unsafe fn selecionar() -> Option<Troca> {
    let mut escalonador = ESCALONADOR.lock();
    let e = &mut *escalonador;

    if !e.ligado {
        return None;
    }

    let proximo = e.proximo_pronto()?;
    let atual = e.atual;
    if proximo == atual {
        return None;
    }

    // A vaga do fio atual é sempre ocupada enquanto o escalonador está ligado:
    // `init` preenche a zero e `vaga_livre` nunca entrega a vaga corrente. Se
    // ainda assim estiver vazia, é bug nosso, e trocar sem ter onde salvar o
    // contexto perderia o fio para sempre — recusar a troca é o desfecho
    // seguro.
    let fio_atual = e.fios[atual].as_mut()?;
    // O fio que sai volta para a fila, a menos que já tenha se encerrado.
    if fio_atual.estado == Estado::Rodando {
        fio_atual.estado = Estado::Pronto;
    }
    let de: *mut Contexto = &mut fio_atual.contexto;

    let para: *const Contexto = {
        let fio = e.fios[proximo].as_mut().expect("vaga conferida acima");
        fio.estado = Estado::Rodando;
        fio.escalonamentos += 1;
        &fio.contexto
    };

    e.atual = proximo;
    // Quem entra recebe uma fatia inteira, mesmo que a troca tenha vindo de
    // uma cessão voluntária do anterior. Herdar o resto da fatia alheia faria
    // um fio que cede muito punir o seguinte.
    e.quantum = QUANTUM_EM_TIQUES;
    TROCAS.fetch_add(1, Ordering::Relaxed);

    Some(Troca { de, para })
}

/// Cede a CPU voluntariamente.
///
/// Sem consumidor de produção hoje pelo mesmo motivo de [`criar`]: a preempção
/// dá conta sozinha do único fio que existe.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn ceder() {
    crate::arch::ceder_cpu();
}

/// Encerra o fio atual. Nunca retorna.
///
/// Sem consumidor de produção hoje pelo mesmo motivo de [`criar`]: o único fio
/// que existe é o do próprio kernel, e ele não termina.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn terminar() -> ! {
    com_escalonador(|e| {
        let atual = e.atual;
        if let Some(fio) = e.fios[atual].as_mut() {
            fio.estado = Estado::Terminado;
        }
    });

    loop {
        crate::arch::ceder_cpu();
        // Se voltarmos aqui é porque não havia outro fio pronto. Dormir em vez
        // de girar: a próxima interrupção pode trazer alguém.
        crate::arch::esperar_interrupcao();
    }
}

/// Contabiliza um tique do timer e decide se é hora de preemptar.
///
/// Chamada de dentro do handler do timer, antes de ele retornar.
pub fn tique() -> bool {
    let venceu = crate::arch::sem_interrupcoes(|| {
        let Some(mut e) = ESCALONADOR.try_lock() else {
            // A trava está com código que foi interrompido. Não insistimos:
            // perder um tique de quantum é irrelevante, e girar aqui dentro do
            // handler seria fatal.
            return false;
        };
        if !e.ligado {
            return false;
        }

        e.quantum = e.quantum.saturating_sub(1);
        if e.quantum > 0 {
            return false;
        }

        // Recarregamos aqui, e não só quando a troca acontece. Se deixássemos
        // para lá, um quantum vencido sem outro fio pronto ficaria em zero
        // para sempre: o timer pediria uma troca a cada tique, e o contador de
        // vencimentos passaria a medir tiques, não fatias.
        e.quantum = QUANTUM_EM_TIQUES;
        true
    });

    if venceu {
        QUANTUNS_VENCIDOS.fetch_add(1, Ordering::Relaxed);
    }
    venceu
}

// ---------------------------------------------------------------------------
// Visibilidade para o agente
// ---------------------------------------------------------------------------

/// Uma linha de `threads.list`.
#[derive(Clone, Copy)]
pub struct Inscricao {
    pub id: u64,
    pub nome: &'static str,
    pub estado: &'static str,
    pub escalonamentos: u64,
}

pub fn com_inscricoes<F: FnMut(Inscricao)>(mut f: F) {
    let instantaneo = com_escalonador(|e| {
        let mut saida = [None; MAX_FIOS];
        for (destino, fio) in saida.iter_mut().zip(e.fios.iter()) {
            *destino = fio.as_ref().map(|fio| Inscricao {
                id: fio.id.numero(),
                nome: fio.nome,
                estado: match fio.estado {
                    Estado::Pronto => "ready",
                    Estado::Rodando => "running",
                    Estado::Terminado => "done",
                },
                escalonamentos: fio.escalonamentos,
            });
        }
        saida
    });

    for inscricao in instantaneo.into_iter().flatten() {
        f(inscricao);
    }
}

/// `(fios vivos, trocas de contexto, quanta vencidos)`.
pub fn estatisticas() -> (usize, u64, u64) {
    let vivos = com_escalonador(|e| {
        e.fios
            .iter()
            .filter(|f| matches!(f, Some(fio) if fio.estado != Estado::Terminado))
            .count()
    });
    (
        vivos,
        TROCAS.load(Ordering::Relaxed),
        QUANTUNS_VENCIDOS.load(Ordering::Relaxed),
    )
}
