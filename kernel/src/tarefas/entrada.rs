//! Os bytes do canal do agente, entregues por interrupção.
//!
//! # O que muda em relação ao laço antigo
//!
//! Até aqui o canal do agente era um laço que perguntava à UART, byte a byte,
//! se havia chegado alguma coisa. Funcionava, mas tinha dois defeitos: entre
//! uma requisição e outra o kernel só sabia dormir até o próximo tique do
//! timer — até 10 ms de latência por byte —, e no meio de uma requisição ele
//! caía em espera ativa para não pagar esses 10 ms.
//!
//! Agora a UART avisa. O handler da interrupção de recepção faz o mínimo
//! possível — esvazia o FIFO do hardware para esta fila e acorda quem espera —
//! e todo o resto (montar a linha, decodificar o JSON, executar o comando,
//! serializar a resposta) acontece na tarefa, fora do handler.
//!
//! Essa separação é uma regra geral de kernel, não um detalhe deste módulo:
//! um handler roda com interrupções mascaradas e suspende *qualquer* coisa que
//! estivesse rodando, inclusive código crítico. Tudo o que puder esperar deve
//! esperar do lado de fora dele.
//!
//! # A corrida que o registro em duas etapas resolve
//!
//! O contrato de `poll` exige registrar o waker **antes** de concluir que não
//! há trabalho. A ordem importa: se consultássemos a fila, a achássemos vazia,
//! e só então registrássemos o waker, uma interrupção caindo entre as duas
//! operações acordaria um waker que ainda não existe. O aviso se perderia, e
//! a tarefa dormiria até o próximo byte — que talvez nunca venha, porque o
//! cliente está esperando a resposta do byte anterior.
//!
//! Por isso o `poll` abaixo consulta, registra, e **consulta de novo**. O
//! preço é receber despertares espúrios; o contrato do executor já os prevê.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use spin::Mutex;

use super::fila::Fila;

/// Quantos bytes cabem esperando processamento.
///
/// Uma requisição do agente cabe em 2 KiB (ver `agent::LINHA_MAX`); este
/// tamanho dá folga para uma requisição inteira chegar em rajada enquanto a
/// tarefa ainda processa a anterior.
const CAPACIDADE: usize = 4096;

static BYTES: Fila<u8, CAPACIDADE> = Fila::nova();

/// Waker da tarefa que espera bytes.
///
/// Um único lugar porque há um único leitor: o canal do agente. Se um dia
/// houver dois, este tipo vira uma tabela como a de [`super::relogio`].
static DESPERTADOR: Mutex<Option<Waker>> = Mutex::new(None);

/// Esvazia o FIFO da UART do agente para a fila e acorda quem espera.
///
/// Chamado pelo handler da interrupção de recepção. Não deve alocar, não deve
/// bloquear, e não deve fazer nada que possa falhar de forma interessante.
/// Joga fora o que já estiver no FIFO da UART, antes de a recepção entrar no
/// ar. Devolve quantos bytes foram descartados.
///
/// # O defeito que isto conserta
///
/// O socket do canal existe desde antes de o kernel começar a bootar: o QEMU o
/// cria junto com a máquina. Um cliente ansioso conecta e manda a requisição
/// dele enquanto ainda estamos montando GDT, paginação e escalonador.
///
/// Esses bytes vão parar no FIFO da UART, que tem dezesseis posições. Uma
/// requisição típica tem quase sessenta bytes, então a maior parte dela se
/// perde ali mesmo — e o que sobra é um **pedaço de linha**. Quando a recepção
/// finalmente liga, o primeiro byte novo dispara a interrupção, o handler
/// drena o FIFO, e o pedaço velho entra na fila grudado na requisição
/// seguinte. O resultado é o que se via na prática: a primeira chamada depois
/// do boot ficava sem resposta, **e a segunda voltava com `JSON malformado`**
/// sem que o cliente tivesse feito nada de errado.
///
/// Perder a requisição de quem chegou cedo demais é inevitável — ela já estava
/// truncada pelo hardware. Contaminar a próxima não é. Descartar o resto aqui
/// separa as duas coisas.
///
/// O número de bytes descartados vai para o log de propósito: um agente que
/// veja isso sabe que uma requisição dele sumiu, em vez de concluir que o
/// kernel responde errado.
/// Bytes jogados fora na subida do canal, acumulados desde o boot.
///
/// Separado do contador de fila cheia de propósito: as duas perdas têm causas
/// diferentes e remédios diferentes — uma é um cliente que falou cedo demais,
/// a outra é um cliente que fala rápido demais. Somá-las tornaria as duas
/// inúteis.
static DESCARTADOS_NO_BOOT: AtomicU64 = AtomicU64::new(0);

/// Quantos bytes foram descartados por chegarem antes de o canal subir.
///
/// Publicado em `tasks.stats` porque o aviso no log não basta: no ARM a única
/// serial **é** o canal do agente, então não há console onde esse aviso possa
/// ser lido. Sem este número, um agente cujo primeiro pedido sumiu não tem
/// como distinguir "falei cedo demais" de "o kernel ignorou o que pedi".
pub fn descartados_no_boot() -> u64 {
    DESCARTADOS_NO_BOOT.load(Ordering::Relaxed)
}

pub fn descartar_pendentes() -> usize {
    crate::arch::sem_interrupcoes(|| {
        let mut guarda = crate::serial::AGENT_LINK.lock();
        let Some(porta) = guarda.as_mut() else {
            return 0;
        };

        // Mesma ordem de `coletar`, e pela mesma razão.
        porta.reconhecer_recepcao();

        let mut descartados = 0;
        // O mesmo teto de `coletar`, pelo mesmo motivo: uma UART que reporte
        // dados para sempre não pode prender o boot num laço.
        for _ in 0..CAPACIDADE {
            if porta.read_byte().is_none() {
                break;
            }
            descartados += 1;
        }
        DESCARTADOS_NO_BOOT.fetch_add(descartados as u64, Ordering::Relaxed);
        descartados
    })
}

pub fn coletar() {
    let mut chegou = false;

    crate::arch::sem_interrupcoes(|| {
        let mut guarda = crate::serial::AGENT_LINK.lock();
        let Some(porta) = guarda.as_mut() else {
            return;
        };

        // O reconhecimento vem **antes** da drenagem, e a ordem é o conserto
        // de um impasse que travava o canal inteiro no ARM.
        //
        // Reconhecendo depois, um byte que chegasse entre a última leitura e a
        // escrita no registrador de reconhecimento tinha a causa dele apagada
        // junto. A causa de recepção da PL011 é travada por borda: ela só
        // volta a disparar quando a FIFO **cruza** o nível de gatilho de novo.
        // Com a FIFO já cheia daquele byte em diante, o dispositivo parava de
        // aceitar mais dados do hospedeiro, e o kernel parava de receber
        // interrupções. Os dois lados esperando o outro, para sempre.
        //
        // Medido, mandando uma requisição de ~2600 bytes pelo canal do agente
        // no ARM: o canal deixava de responder e não voltava. Com `qemu -d int`
        // e o contador de CPU do processo, o que se via era um kernel **ocioso**
        // — zero tiques de CPU em seis segundos, IRQs de relógio entrando e
        // voltando ao mesmo `wfi` — enquanto o dispositivo segurava os bytes.
        // Não era laço sem saída nem falha: era um despertar perdido.
        //
        // O tamanho importava porque a janela é de duas instruções: era
        // preciso um fluxo grande o bastante para cair dentro dela, e por isso
        // a mesma requisição às vezes passava.
        //
        // Reconhecer antes não perde nada: um byte que chegue durante a
        // drenagem torna a levantar a causa, e o preço é uma interrupção a
        // mais que encontra a FIFO vazia. No 16550 a chamada é um no-op.
        porta.reconhecer_recepcao();

        // Drenamos o FIFO inteiro, e não um byte só. A interrupção é por
        // nível: deixar bytes para trás faria o hardware reinterromper
        // imediatamente, e atenderíamos uma interrupção por byte sem
        // necessidade. O teto vale contra uma UART que reporte dados para
        // sempre — um laço sem saída aqui travaria o sistema inteiro, já que
        // estamos dentro de um handler.
        for _ in 0..CAPACIDADE {
            let Some(byte) = porta.read_byte() else {
                break;
            };
            let _ = BYTES.enfileirar(byte);
            chegou = true;
        }
    });

    if chegou {
        despertar();
    }
}

fn despertar() {
    crate::arch::sem_interrupcoes(|| {
        if let Some(waker) = DESPERTADOR.lock().as_ref() {
            waker.wake_by_ref();
        }
    });
}

/// Um byte do canal do agente, quando houver.
pub fn proximo_byte() -> ProximoByte {
    ProximoByte
}

/// O futuro devolvido por [`proximo_byte`].
///
/// Não guarda estado nenhum: tudo de que precisa está nos `static` do módulo.
pub struct ProximoByte;

impl Future for ProximoByte {
    type Output = u8;

    fn poll(self: Pin<&mut Self>, contexto: &mut Context) -> Poll<u8> {
        // Caminho rápido: com a fila cheia de bytes — o caso comum no meio de
        // uma requisição — nem chegamos a tocar no waker.
        if let Some(byte) = BYTES.desenfileirar() {
            return Poll::Ready(byte);
        }

        registrar(contexto.waker());

        // Segunda consulta, agora com o waker no lugar. Ver a explicação da
        // corrida no cabeçalho do módulo.
        match BYTES.desenfileirar() {
            Some(byte) => {
                limpar();
                Poll::Ready(byte)
            }
            None => Poll::Pending,
        }
    }
}

fn registrar(waker: &Waker) {
    crate::arch::sem_interrupcoes(|| {
        let mut guarda = DESPERTADOR.lock();
        // `will_wake` evita clonar um waker idêntico ao que já está guardado,
        // que é o caso em toda repolagem da mesma tarefa.
        if guarda.as_ref().is_some_and(|atual| atual.will_wake(waker)) {
            return;
        }
        *guarda = Some(waker.clone());
    });
}

fn limpar() {
    crate::arch::sem_interrupcoes(|| *DESPERTADOR.lock() = None);
}

/// Destrava as estruturas do módulo, para o caminho de falha fatal.
///
/// A exceção pode ter interrompido o handler da serial no meio de um
/// `enfileirar`, com o lock da fila na mão. O modo post-mortem consome
/// justamente dessa fila — sem destravá-la, a tentativa de relatar a falha
/// morreria num deadlock, trocando uma morte explicada por um silêncio.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        BYTES.destravar();
        DESPERTADOR.force_unlock();
    }
}

/// Retira um byte da fila, sem esperar.
///
/// O caminho assíncrono normal usa [`proximo_byte`]. Isto existe para o modo
/// post-mortem, que roda depois de uma exceção fatal e **não pode** depender
/// nem do heap nem do escalonador — os dois podem ser justamente o que
/// quebrou. Ele bombeia [`coletar`] e consome daqui, no mesmo laço síncrono
/// que o kernel usava antes de haver tarefas.
pub fn retirar() -> Option<u8> {
    BYTES.desenfileirar()
}

/// Injeta um byte como se tivesse vindo da serial.
///
/// Existe para a suíte de testes, que precisa exercitar o caminho assíncrono
/// sem depender de um cliente conectado do lado de fora do emulador.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn injetar(byte: u8) -> Result<(), u8> {
    let r = BYTES.enfileirar(byte);
    if r.is_ok() {
        despertar();
    }
    r
}

/// Ocupação, capacidade e bytes descartados da fila de entrada.
pub fn estatisticas() -> (usize, usize, u64) {
    (BYTES.ocupacao(), BYTES.capacidade(), BYTES.descartados())
}
