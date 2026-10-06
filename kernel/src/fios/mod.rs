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
//!
//! # Vários núcleos
//!
//! Mascarar interrupções desliga a preempção **neste** núcleo, e mais nada.
//! Com vários, a exclusão mútua passa a ser só da trava — e foi por isso que
//! toda trava deste kernel já era um spinlock de verdade, e não um "desligar
//! interrupções e pronto". O escalonador é uma tabela só, sob uma trava só,
//! e cada núcleo tem nela o **seu** fio atual e o **seu** quantum.
//!
//! O que um núcleo único não precisava e vários precisam:
//!
//! - **Um fio não pode estar em dois núcleos.** O estado `Rodando` não basta
//!   para isso, porque um fio que acabou de perder a vez volta a `Pronto`
//!   antes de o contexto dele estar salvo: a troca acontece fora da trava, em
//!   assembly. Ver [`Fio::na_cpu`].
//! - **A vaga de quem roda em outro núcleo também não é livre.** A regra que
//!   protegia "o fio atual" passa a proteger "todo fio que um núcleo está
//!   usando" — o mesmo campo.
//! - **Cada núcleo tem um fio ocioso.** Um núcleo sem trabalho precisa de
//!   uma pilha onde dormir, e ela não pode ser a de um fio que outro núcleo
//!   queira retomar. O ocioso é fixo no seu núcleo e só é escolhido quando
//!   não há mais nada.

pub mod pilha;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::trava::Mutex;

use crate::arch::Contexto;
use pilha::Pilha;

/// Quantos fios o kernel comporta.
///
/// Fixo para que o escalonador não aloque: ele roda dentro do handler do
/// timer, onde pedir memória seria tomar a trava do heap num ponto arbitrário
/// do programa.
///
/// As vagas de trabalho, mais uma para o fio ocioso de cada núcleo que pode
/// existir além do primeiro — o do primeiro é o fio do boot. Eram trinta e
/// duas no total, e cada núcleo ligado tirava uma do trabalho: o número de
/// núcleos e o de fios não estavam ligados, e com o teto de núcleos maior
/// os ociosos comeriam as vagas todas.
pub const VAGAS_DE_TRABALHO: usize = 32;
pub const MAX_FIOS: usize = VAGAS_DE_TRABALHO + crate::nucleos::MAX_NUCLEOS - 1;

/// Quantos núcleos o escalonador acompanha. É o teto de [`crate::nucleos`].
pub const MAX_NUCLEOS: usize = crate::nucleos::MAX_NUCLEOS;

/// Quantos tiques do timer um fio roda antes de ser preemptado.
///
/// A 100 Hz, 5 tiques são 50 ms. Curto o bastante para o sistema parecer
/// responsivo, longo o bastante para a troca de contexto não dominar o tempo
/// de CPU.
pub const QUANTUM_EM_TIQUES: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Estado {
    /// A vaga foi tomada, mas o fio ainda não tem pilha nem contexto.
    ///
    /// Existe por causa de uma corrida real: [`criar`] precisa escolher a vaga
    /// sob a trava do escalonador e mapear a pilha **fora** dela, porque
    /// mapear toma as travas da paginação e dos frames. Sem marcar a vaga
    /// nesse intervalo, duas criações concorrentes escolheriam a mesma — a
    /// segunda falharia ao tentar mapear por cima da primeira.
    Reservado,
    /// Pronto para rodar, esperando a vez.
    Pronto,
    /// É o fio que está executando agora.
    Rodando,
    /// Esperando um filho terminar, ou um evento chegar a um canal que o
    /// processo escuta.
    ///
    /// Um fio nesta lista não é escolhido por [`Escalonador::proximo_pronto`],
    /// que é o ponto: sem isso, um pai em `esperar` seria escolhido, voltaria
    /// a perguntar, não acharia nada e cederia — queimando um quantum inteiro
    /// por volta e impedindo a máquina de ficar ociosa.
    ///
    /// Quem tira daqui é [`marcar_terminado`], chamada pelo filho ao sair —
    /// e é por isso que ela é o lugar onde o código de saída é registrado:
    /// quem acorda o pai é o mesmo que tem o número que o pai foi esperar —,
    /// ou [`acordar`], chamada por quem publica um evento.
    ///
    /// E quem **põe** aqui são quatro funções, e nenhuma outra:
    /// [`colher_filho`] e [`estacionar_atual`], esta chamada só pela leitura
    /// de um canal de eventos vazio; e [`enfileirar_pedido`] e
    /// [`retomar_pedido`], de `pedir`. Isso não é arrumação: o backend de
    /// arquitetura reexecuta a chamada de sistema quando encontra o fio
    /// neste estado, e reexecutar só é seguro para uma chamada cuja segunda
    /// vez não repete o efeito da primeira. As duas primeiras conferem que
    /// não havia o que colher antes de estacionar; `pedir` guarda no fio
    /// onde o pedido está, e a reexecução continua de lá em vez de pedir de
    /// novo. Com essas escritas, "quais chamadas podem parar aqui" tem uma
    /// resposta que se lê, em vez de uma que se procura.
    ///
    /// # Acordar a mais é inofensivo
    ///
    /// Um pai que também escuta um canal é acordado pela saída de um filho
    /// enquanto espera um evento, e o contrário. Não há o que separar: a
    /// chamada reexecutada confere de novo, e volta a estacionar se ainda
    /// não houver o que ela esperava.
    Esperando,
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
    /// O espaço de endereços próprio, quando o fio hospeda um processo.
    ///
    /// Fios do kernel não têm: eles rodam no espaço do kernel, que é o mesmo
    /// para todos. Guardar o espaço **aqui** é o que faz ele morrer junto com
    /// o fio — quando a vaga é reaproveitada, o `Fio` antigo é largado e o
    /// `Drop` do espaço devolve as tabelas e as páginas do processo.
    ///
    /// # Quem recolhe, e por que não é o escalonador
    ///
    /// Por muito tempo "quando a vaga é reaproveitada" foi literal: um fio
    /// morto segurava o espaço dele até outra criação escolher aquela vaga.
    /// Num kernel que roda um processo de cada vez isso quase não aparece;
    /// num que bifurca, a vaga passa a segurar um espaço de endereços
    /// inteiro — raiz, tabelas e todas as páginas do processo — e o sistema
    /// fica com até dezesseis deles retidos sem nenhum dono vivo.
    ///
    /// Quem recolhe agora é [`recolher_terminados`], chamada por um fio
    /// próprio. O escalonador **não** pode fazê-lo: largar um espaço
    /// desmapeia páginas, ou seja, toma as travas da paginação e do alocador
    /// de frames — e ele trocaria de fio com a trava dele na mão, que é
    /// justamente o aninhamento que este módulo se recusa a criar.
    ///
    /// O `Drop` continua sendo o mecanismo. O coletor só decide **quando**.
    espaco: Option<crate::paginacao::Espaco>,
    /// Os descritores abertos do processo que este fio hospeda.
    ///
    /// # Por que ela mora aqui, e não numa tabela global indexada por id
    ///
    /// Porque assim as duas propriedades que ela precisa ter saem de graça,
    /// sem uma linha para mantê-las: ela **morre junto com o processo**,
    /// porque o `Fio` é largado quando a vaga é reaproveitada; e `bifurcar`
    /// a **herda**, porque bifurcar copia o fio.
    ///
    /// Uma tabela à parte precisaria de uma remoção no caminho de saída — e
    /// de outra no caminho em que o processo morre por falha de página, que
    /// é justamente o que ninguém lembra de escrever.
    ///
    /// Fios do kernel também têm a sua. Eles não fazem chamada de sistema,
    /// então ela fica intocada; o custo é o de três `Option` por vaga, e a
    /// alternativa — um `Option<Tabela>` — trocaria isso por um desembrulho
    /// em todo acesso e por uma pergunta ("este fio é processo?") que o
    /// escalonador não tem por que responder.
    descritores: crate::usuario::descritores::Tabela,
    /// Quantas vezes este fio já foi escalonado.
    escalonamentos: u64,
    /// Quem bifurcou para criar este fio, quando alguém bifurcou.
    ///
    /// `None` em todo fio criado por [`criar`]: um fio do kernel não é filho
    /// de ninguém, e ninguém vai esperar por ele.
    ///
    /// É o que transforma a tabela plana num parentesco, e é o que `esperar`
    /// consulta para não deixar um processo colher o filho de outro.
    pai: Option<IdFio>,
    /// Com que código este fio saiu, quando ele saiu por `sair`.
    ///
    /// `None` cobre dois casos que não precisam ser distinguidos: o fio ainda
    /// roda, ou terminou sem passar por `sair` — um fio do kernel que
    /// retornou, ou um processo morto por falha de página.
    saida: Option<i64>,
    /// O pai já colheu este fio?
    ///
    /// Um fio terminado que **ainda não** foi colhido é um zumbi: a vaga
    /// continua ocupada, mas tudo o que resta dela é o código de saída,
    /// guardado para uma pergunta que ainda não foi feita. Ver
    /// [`recolher_terminados`].
    colhido: bool,
    /// Com que autoridade este fio age: a de quem o lançou.
    ///
    /// Mora aqui pelo mesmo motivo dos descritores: morre com o processo, e
    /// a bifurcação a herda sem uma linha a mais — um filho de um processo
    /// que um agente lançou é tão desse agente quanto o pai. É `Copy`, sem
    /// nada no heap, porque é copiada com a trava do escalonador na mão.
    autoridade: crate::autorizacao::Autoridade,
    /// O núcleo que está usando este fio, se algum está.
    ///
    /// # Por que o estado não basta
    ///
    /// Porque a troca de contexto acontece **fora** da trava. O escalonador
    /// escolhe o próximo, marca o que sai como `Pronto` e solta a trava; só
    /// depois o assembly guarda os registradores do que sai. Nesse
    /// intervalo o fio está `Pronto` com um contexto que ainda não foi
    /// escrito. Com um núcleo só ninguém olhava a tabela nesse intervalo;
    /// com vários, outro núcleo podia escolhê-lo e retomar um contexto
    /// velho — ou o mesmo fio rodaria em dois núcleos ao mesmo tempo, sobre
    /// a mesma pilha.
    ///
    /// Então a posse vai além do estado: é posta quando o núcleo escolhe o
    /// fio, e só sai quando o **próximo** fio daquele núcleo já está de pé —
    /// ver [`troca_concluida`]. Enquanto houver dono, nenhum outro núcleo o
    /// escolhe, e o coletor não recolhe a vaga dele.
    na_cpu: Option<usize>,
    /// O único núcleo em que este fio pode rodar, quando há um.
    ///
    /// Os ociosos são fixos no seu núcleo, e o fio do kernel — o do canal do
    /// agente — no primeiro: é lá que as interrupções de dispositivo chegam
    /// e o relógio anda, e é esse núcleo que o canal precisa ter.
    fixo: Option<usize>,
    /// É o fio ocioso de algum núcleo: só roda quando não há mais nada.
    ocioso: bool,
    /// A chamada de sistema em curso pediu para ser reexecutada — ver
    /// [`tirar_reexecucao`]. Posto junto com [`Estado::Esperando`], na mesma
    /// seção crítica, e só por quem põe o fio nesse estado.
    reexecutar: bool,
    /// O pedido do processo pela interface nativa — ver [`crate::nativo`].
    pedido: EstadoDoPedido,
    /// O programa que o fio executa — ver [`crate::autorizacao::Programa`].
    /// Trocado junto com o espaço de endereços, em [`adotar_imagem`]: a
    /// imagem nova nunca roda com o manifesto da anterior.
    programa: crate::autorizacao::Programa,
}

/// Onde está o pedido que um processo fez pela interface nativa.
///
/// Mora no fio, e não numa tabela à parte, por dois motivos. O primeiro é
/// a corrida de acordar: o processo estaciona e o executor o acorda, e as
/// duas coisas acontecem sob a trava do escalonador — o executor não acha
/// o fio "ainda não esperando" e desiste. O segundo é a vida: o pedido e a
/// resposta morrem com o fio, sem uma tabela que alguém esqueça de limpar.
/// Os textos são `sigiloso::Texto`, que se apaga ao sair: um pedido pode
/// levar o corpo de uma mensagem, e uma resposta também.
#[derive(Default)]
pub enum EstadoDoPedido {
    #[default]
    Livre,
    /// Na fila do executor, com o texto do pedido.
    Enfileirado(politica::sigiloso::Texto),
    /// O executor tomou o pedido e está executando o comando.
    EmCurso,
    /// A resposta pronta, e o processo ainda não voltou para vê-la.
    Pronto(politica::sigiloso::Texto),
    /// O processo viu o tamanho — `pedir` o devolveu —, e a resposta espera
    /// `resposta` a buscar.
    Pendente(politica::sigiloso::Texto),
}

impl Fio {
    /// A raiz de tradução em que este fio precisa rodar.
    ///
    /// Sem espaço próprio, o do kernel: é o caso de todo fio que não hospeda
    /// processo, e também o caminho de volta quando um processo sai de cena.
    fn raiz(&self) -> u64 {
        match &self.espaco {
            Some(espaco) => espaco.raiz(),
            None => crate::arch::espaco_do_kernel(),
        }
    }
}

struct Escalonador {
    fios: [Option<Fio>; MAX_FIOS],
    /// Índice do fio que está executando em cada núcleo.
    ///
    /// `None` num núcleo que ainda não ligou: ele não tem fio, e nada pode
    /// ser escolhido em nome dele.
    atual: [Option<usize>; MAX_NUCLEOS],
    /// O fio que cada núcleo acabou de largar, enquanto a troca não termina.
    ///
    /// Ver [`Fio::na_cpu`]: é por aqui que o núcleo, já no fio novo, sabe de
    /// quem soltar a posse.
    anterior: [Option<usize>; MAX_NUCLEOS],
    /// O fio ocioso de cada núcleo, quando ele tem um.
    ociosos: [Option<usize>; MAX_NUCLEOS],
    ligado: bool,
}

static ESCALONADOR: Mutex<Escalonador> = Mutex::new(Escalonador {
    fios: [const { None }; MAX_FIOS],
    atual: [None; MAX_NUCLEOS],
    anterior: [None; MAX_NUCLEOS],
    ociosos: [None; MAX_NUCLEOS],
    ligado: false,
});

static PROXIMO_ID: AtomicU64 = AtomicU64::new(1);

/// Tiques restantes antes de preemptar o fio atual de cada núcleo.
///
/// # Por que fora da trava do escalonador
///
/// Morava na tabela, e o timer o descontava com um `try_lock` da trava: um
/// handler de interrupção não pode esperar por ela. Com um núcleo só a trava
/// quase nunca estava tomada na hora do tique. Com vários, um fio que cede
/// em laço num núcleo a toma e solta sem parar, o `try_lock` dos outros
/// núcleos perde quase sempre, e o quantum deles para de andar: o fio que
/// estivesse num deles nunca mais era preemptado. Medido na suíte: um
/// lançador fixo num núcleo ficou **pronto** por segundos, com o núcleo
/// vivo, até o fio que cedia em laço no outro sair.
///
/// O quantum de um núcleo só é tocado por ele mesmo — pelo timer dele e
/// pela troca de contexto dele, as duas com as interrupções mascaradas —,
/// então um atômico por núcleo basta, sem trava nenhuma. A troca, quando o
/// quantum vence, continua sob a trava, que é justa, e espera a vez.
static QUANTUM: [AtomicU32; MAX_NUCLEOS] =
    [const { AtomicU32::new(QUANTUM_EM_TIQUES) }; MAX_NUCLEOS];

/// O escalonador está ligado — o espelho de `Escalonador::ligado` que o
/// timer lê sem a trava.
static LIGADO: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Congela o escalonamento. Uma via só: quem congela não descongela.
///
/// Serve ao modo post-mortem. Depois de uma falha fatal o sistema está morto
/// para qualquer trabalho útil, mas o timer continua disparando — e sem isto
/// ele continuaria trocando de fio, deixando os outros rodarem por cima de um
/// estado que já se sabe corrompido, e disputando com o próprio relatório da
/// falha o canal do agente.
///
/// É um atômico, e não um campo do escalonador, justamente porque precisa
/// funcionar quando a trava do escalonador é o que está quebrado.
static CONGELADO: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Para o escalonamento de vez. Chamado pelo caminho de falha fatal.
pub fn congelar() {
    CONGELADO.store(true, Ordering::SeqCst);
}

/// Segura em [`recolher_terminados`] o primeiro fio morto tirado da tabela,
/// antes de largá-lo — com a pilha dele ainda mapeada.
///
/// Existe só para a suíte, pelo mesmo motivo de [`CEDER_AO_ESCOLHER_VAGA`]:
/// a janela entre o coletor tirar o morto e terminar de desmontá-lo é a de
/// desmapear uma pilha, e uma criação em outro núcleo só cai nela por
/// acaso. Armada ([`PAUSA_ARMADA`]), o primeiro coletor que passa a toma
/// ([`PAUSA_SEGURANDO`]) e gira até a suíte a devolver a zero.
#[cfg(feature = "modo-teste")]
pub static PAUSAR_NA_DESMONTAGEM: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);
#[cfg(feature = "modo-teste")]
pub const PAUSA_ARMADA: u8 = 1;
#[cfg(feature = "modo-teste")]
pub const PAUSA_SEGURANDO: u8 = 2;

/// Faz [`criar`] ceder a vez logo depois de escolher a vaga.
///
/// Existe só para a suíte de testes, e testa algo que de outra forma não teria
/// como ser testado de forma determinística: a corrida entre duas criações
/// concorrentes pela mesma vaga. A janela real dura algumas centenas de
/// instruções, e o timer praticamente nunca a acerta.
#[cfg(feature = "modo-teste")]
pub static CEDER_AO_ESCOLHER_VAGA: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
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

/// Em que núcleo estamos.
///
/// Só tem sentido com as interrupções mascaradas: com elas ligadas o fio pode
/// ser preemptado logo depois da leitura e retomado em outro núcleo, e o
/// número lido descreveria onde ele **estava**. Todo uso neste módulo
/// acontece dentro de [`com_escalonador`] ou de um handler.
fn nucleo() -> usize {
    crate::arch::nucleo_atual().min(MAX_NUCLEOS - 1)
}

impl Escalonador {
    /// O índice do fio que roda neste núcleo.
    fn atual_aqui(&self) -> Option<usize> {
        self.atual[nucleo()]
    }

    /// O fio que roda neste núcleo.
    fn fio_atual(&self) -> Option<&Fio> {
        self.fios[self.atual_aqui()?].as_ref()
    }

    /// O fio que roda neste núcleo, para escrever.
    fn fio_atual_mut(&mut self) -> Option<&mut Fio> {
        let i = self.atual_aqui()?;
        self.fios[i].as_mut()
    }

    /// Os núcleos que estão rodando o próprio ocioso agora — ou seja,
    /// dormindo sem nada para fazer.
    ///
    /// É a quem vale cutucar quando um fio fica pronto: os outros já estão
    /// trabalhando, e o timer deles os leva ao escalonador no próximo tique.
    fn nucleos_ociosos(&self) -> crate::nucleos::Mascara {
        let mut mascara: crate::nucleos::Mascara = 0;
        for cpu in 0..MAX_NUCLEOS {
            if self.ociosos[cpu].is_some() && self.atual[cpu] == self.ociosos[cpu] {
                mascara |= 1 << cpu;
            }
        }
        mascara
    }

    /// Solta a posse do fio que este núcleo largou na última troca.
    ///
    /// Qualquer código que rode neste núcleo depois da troca prova que ela
    /// terminou — o contexto do que saiu já foi escrito, porque é ele que o
    /// assembly escreve antes de adotar o novo. Por isso esta função pode
    /// ser chamada de dois lugares: logo depois da troca, que é o caminho
    /// normal, e no começo da próxima escolha, como rede de segurança.
    fn concluir_troca(&mut self, cpu: usize) {
        if let Some(anterior) = self.anterior[cpu].take()
            && let Some(fio) = self.fios[anterior].as_mut()
            && fio.na_cpu == Some(cpu)
        {
            fio.na_cpu = None;
        }
    }
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
        let cpu = nucleo();
        e.fios[0] = Some(Fio {
            id: IdFio(PROXIMO_ID.fetch_add(1, Ordering::Relaxed)),
            nome: "kernel",
            estado: Estado::Rodando,
            contexto: Contexto::vazio(),
            _pilha: None,
            espaco: None,
            descritores: crate::usuario::descritores::Tabela::nova(),
            escalonamentos: 1,
            pai: None,
            saida: None,
            colhido: false,
            autoridade: crate::autorizacao::Autoridade::Sistema,
            na_cpu: Some(cpu),
            // O fio do canal do agente fica no núcleo que recebe as
            // interrupções dos dispositivos e anda o relógio. Solto, ele
            // poderia dormir num núcleo enquanto a interrupção que o
            // acordaria chega em outro — e o canal ganharia a latência de um
            // tique do timer a cada pedido.
            fixo: Some(cpu),
            ocioso: false,
            reexecutar: false,
            pedido: EstadoDoPedido::Livre,
            programa: crate::autorizacao::Programa::Kernel,
        });
        e.por_atual(cpu, 0);
        QUANTUM[cpu].store(QUANTUM_EM_TIQUES, Ordering::Relaxed);
        e.ligado = true;
        LIGADO.store(true, Ordering::Release);
    });

    crate::log_info!(
        "fios",
        "escalonador preemptivo ativo, quantum de {} tiques",
        QUANTUM_EM_TIQUES
    );

    // O coletor nasce junto com o escalonador, e não num passo à parte do
    // boot, porque "há escalonador" e "há quem recolha o que ele deixa para
    // trás" são o mesmo fato. Separá-los deixaria um caminho de inicialização
    // capaz de ter o primeiro sem o segundo — e o sintoma disso não é uma
    // falha, é memória que some devagar.
    match criar("coletor", coletor, 0) {
        Ok(id) => crate::log_info!("fios", "coletor de fios mortos no ar, id {}", id.numero()),
        // Não é fatal: sem coletor o sistema volta a se comportar como antes,
        // segurando o espaço de cada morto até a vaga dele ser reaproveitada.
        // Recusar o boot por causa disso trocaria um desperdício limitado por
        // uma máquina que não sobe.
        Err(motivo) => crate::log_error!("fios", "o coletor nao subiu: {}", motivo),
    }
}

/// Quantos fios já foram recolhidos.
static RECOLHIDOS: AtomicU64 = AtomicU64::new(0);

/// O fio que desmonta o que os outros deixaram.
///
/// # Por que um fio, e não uma tarefa do executor
///
/// Porque o executor cooperativo não existe em modo de teste — lá o kernel
/// roda a suíte e encerra. Um coletor que só existisse em produção seria um
/// coletor que nunca é exercitado, e a primeira evidência de que ele está
/// errado viria de uma máquina em uso.
///
/// # Por que dormir, e não ceder em laço
///
/// Ceder devolveria a CPU imediatamente sempre que não houvesse mais
/// ninguém pronto, e o núcleo nunca chegaria a parar: um coletor que impede
/// a máquina de ficar ociosa custa mais do que a memória que ele recupera.
///
/// Esperar a interrupção põe o processador para dormir até o próximo tique
/// do timer, que já ia acontecer de qualquer forma. A latência máxima entre
/// um fio morrer e o espaço dele voltar ao alocador passa a ser um tique.
extern "C" fn coletor(_argumento: u64) -> ! {
    loop {
        let quantos = recolher_terminados();
        if quantos > 0 {
            crate::log_debug!("fios", "coletor recolheu {} fio(s)", quantos);
        }
        // O aviso de saída do pseudo-terminal é dado daqui, sem tranca na
        // mão — ver `pseudoterminal`, sobre por que o `_print` não o dá.
        crate::pseudoterminal::passada_do_coletor();
        // E os arrendamentos vencidos saem daqui, e vão para a auditoria:
        // um prazo vence sem ninguém pedir nada.
        crate::coordenacao::vencer_todos();
        // E as mensagens vencidas, também sem ninguém pedir.
        crate::mensagens::vencer_todos();
        // E a auditoria que nenhum registro levou ainda vai ao journal, de
        // tempos em tempos: as leituras e as recusas não mudam estado, e
        // não têm registro próprio.
        crate::persistencia::gravar_auditoria_se_preciso();
        // E a região do journal que encheu é compactada aqui: o coletor
        // não está no meio de operação nenhuma.
        crate::persistencia::compactar_se_preciso();
        crate::arch::esperar_interrupcao();
    }
}

/// Tira da tabela os fios que já terminaram e devolve o que eles ocupavam:
/// a pilha de kernel, e o espaço de endereços quando havia um.
///
/// Devolve quantos foram recolhidos.
///
/// # O que um zumbi tem que um morto não tem
///
/// Um filho de `fork` que terminou e cujo pai ainda pode perguntar por ele
/// **não** é recolhido aqui. O que resta dele é um número — o código de
/// saída —, e recolhê-lo antes da pergunta destruiria a única resposta que
/// existe.
///
/// A regra está em [`Escalonador::e_zumbi`], e ela é deliberadamente curta:
/// só é zumbi quem tem pai vivo que ainda não colheu. Um fio sem pai, um
/// cujo pai já morreu, e um já colhido vão embora na mesma volta em que
/// iriam antes — que é o que mantém o coletor recolhendo os fios da suíte
/// como ele sempre recolheu.
///
/// A parte que **não** é opcional é o pai morto liberar o filho. Sem ela, um
/// processo que bifurca e sai sem esperar deixa o filho ocupando uma das
/// dezesseis vagas para sempre, com o espaço de endereços dele junto. É o
/// vazamento que o coletor existe para impedir, de volta por outra porta.
///
/// # A vaga do fio atual nunca entra
///
/// É a mesma regra de [`Escalonador::vaga_livre`], e pelo mesmo motivo: um
/// fio que chamou [`terminar`] **segue executando** até ceder a vez, sobre a
/// própria pilha de kernel. Recolhê-lo ali seria desmapear o chão de quem
/// está de pé nele.
///
/// Um fio encerrado que já não é o atual, por outro lado, nunca mais roda:
/// [`Escalonador::proximo_pronto`] só escolhe quem está `Pronto`. A pilha
/// dele está parada, ainda que o último quadro nela seja o de uma função
/// que "não retornou" — ela não vai retornar.
///
/// # Por que um de cada vez, e largado fora da trava
///
/// Porque largar um fio desmapeia páginas, e isso toma as travas da
/// paginação e do alocador de frames. Cada volta do laço tira **um** fio sob
/// a trava do escalonador e o larga fora dela — a mesma coreografia que
/// [`nascer`] faz com o ocupante da vaga que ele reaproveita, e pelos mesmos
/// dois motivos.
///
/// O primeiro é ordem de travas: fazê-lo por dentro aninharia três numa
/// ordem que nenhum outro ponto do kernel usa, e aninhar é como nascem os
/// travamentos que ninguém reproduz. O segundo é latência: `com_escalonador`
/// roda com as interrupções mascaradas, e desmontar um espaço de endereços
/// ali dentro estenderia a seção crítica pelo tempo de desmapear o processo
/// inteiro.
///
/// # Nenhum caso derruba esta escolha, e não há como escrever um
///
/// Medido, largando o fio por dentro da trava: a suíte inteira passa. Não é
/// falha dos casos — hoje nada abaixo da paginação ou do alocador de frames
/// volta a pedir a trava do escalonador, então a inversão que travaria a
/// máquina não existe ainda. O que se estende de verdade é a seção crítica,
/// e isso um caso não vê.
///
/// A escolha fica porque ela é sobre o kernel de amanhã: o dia em que
/// qualquer coisa nesse caminho precisar perguntar algo ao escalonador — um
/// contador por fio, uma notificação de morte — a versão aninhada trava, e
/// trava num ponto arbitrário do programa.
pub fn recolher_terminados() -> usize {
    let mut quantos = 0;

    loop {
        let morto = com_escalonador(|e| {
            // `na_cpu`, e não "diferente do atual": com vários núcleos há
            // vários atuais, e há também o fio que um núcleo acabou de largar
            // e ainda não terminou de sair de cima da pilha dele.
            let vaga = (0..MAX_FIOS).find(|&i| {
                matches!(&e.fios[i], Some(fio)
                        if fio.estado == Estado::Terminado
                            && fio.na_cpu.is_none()
                            && !e.e_zumbi(i))
            })?;
            let morto = e.fios[vaga].take()?;
            // A vaga fica reservada enquanto o morto é desmontado lá fora.
            // A pilha de kernel de uma vaga mora num endereço fixo dela, e
            // largar o morto é o que a desmapeia: com a vaga vazia nesse
            // intervalo, uma criação em outro núcleo a escolhia e ia mapear a
            // pilha nova por cima da velha — "endereço virtual já mapeado".
            // Medido: uma criação recusada assim no caso da criação
            // concorrente, e o mesmo erro no da cópia na escrita em dois
            // núcleos, que bifurca. Com um núcleo só, a janela existia só se
            // o timer caísse dentro dela.
            //
            // O marcador tem um id próprio, que nenhum fio teve: com o do
            // morto, ele pareceria vivo a quem procura por id — `vivo`, e o
            // pai de um zumbi — durante a desmontagem.
            e.fios[vaga] = Some(Fio {
                id: IdFio(PROXIMO_ID.fetch_add(1, Ordering::Relaxed)),
                nome: "recolhendo",
                estado: Estado::Reservado,
                contexto: Contexto::vazio(),
                _pilha: None,
                espaco: None,
                descritores: crate::usuario::descritores::Tabela::nova(),
                escalonamentos: 0,
                pai: None,
                saida: None,
                colhido: true,
                autoridade: crate::autorizacao::Autoridade::NENHUMA,
                na_cpu: None,
                fixo: None,
                ocioso: false,
                reexecutar: false,
                pedido: EstadoDoPedido::Livre,
                programa: crate::autorizacao::Programa::Kernel,
            });
            let id = e.fios[vaga].as_ref().map(|f| f.id)?;
            Some((vaga, id, morto))
        });

        let Some((vaga, id, morto)) = morto else {
            break;
        };
        #[cfg(feature = "modo-teste")]
        if PAUSAR_NA_DESMONTAGEM
            .compare_exchange(
                PAUSA_ARMADA,
                PAUSA_SEGURANDO,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            while PAUSAR_NA_DESMONTAGEM.load(Ordering::SeqCst) == PAUSA_SEGURANDO {
                core::hint::spin_loop();
            }
        }
        let canal = politica::mensagens::Canal::Processo(morto.id.numero());
        drop(morto);
        // A janela de nonces do processo, se ele mandou mensagens pela
        // interface nativa: o id não se repete, e a janela não serviria a
        // mais ninguém. Fora da trava, como tudo que este laço larga.
        crate::mensagens::canal_acabou(canal);
        // Só agora a vaga volta a ser escolhível. O marcador sai sob a trava
        // e é largado fora dela, como todo fio deste módulo.
        let marcador = com_escalonador(|e| match &e.fios[vaga] {
            Some(f) if f.id == id && f.estado == Estado::Reservado => e.fios[vaga].take(),
            _ => None,
        });
        drop(marcador);
        quantos += 1;
    }

    // As camadas de quem morreu saem da tela na mesma volta: um processo
    // morto não fecha os descritores, e ninguém mais procuraria a camada
    // dele — ver `superficies::recolher_orfas`. Fora do laço e de qualquer
    // tranca, pela mesma razão de largar o fio fora dela.
    crate::superficies::recolher_orfas();

    if quantos > 0 {
        RECOLHIDOS.fetch_add(quantos as u64, Ordering::Relaxed);
    }
    quantos
}

/// Quantos fios o coletor já desmontou.
pub fn recolhidos() -> u64 {
    RECOLHIDOS.load(Ordering::Relaxed)
}

/// Cria um fio novo, pronto para rodar.
///
/// `entrada` recebe `argumento` e não deve retornar; se retornar, o fio é
/// encerrado como se tivesse chamado [`terminar`].
pub fn criar(
    nome: &'static str,
    entrada: extern "C" fn(u64) -> !,
    argumento: u64,
) -> Result<IdFio, &'static str> {
    criar_como(
        nome,
        entrada,
        argumento,
        crate::autorizacao::Autoridade::Sistema,
    )
}

/// Cria um fio que age com a autoridade de outro: um processo que um agente
/// lançou age como o agente — ver [`crate::autorizacao::autorizar_processo`].
pub fn criar_como(
    nome: &'static str,
    entrada: extern "C" fn(u64) -> !,
    argumento: u64,
    autoridade: crate::autorizacao::Autoridade,
) -> Result<IdFio, &'static str> {
    nascer(
        nome,
        Nascimento::Funcao {
            entrada,
            argumento,
            autoridade,
            fixo: None,
        },
        None,
    )
}

/// O que [`nascer`] devolve quando a cota de processos do titular já está
/// cheia. Uma constante, e não um texto qualquer, porque quem lança precisa
/// distinguir esta recusa — que é da política, e vai para a auditoria — de
/// uma falta de vaga ou de memória.
pub const COTA_ESGOTADA: &str = "a cota de processos do papel de quem lanca esta esgotada";

/// [`criar_como`] um processo, contado na cota do titular da `autoridade`:
/// nasce só se o titular tiver menos de `cota` processos vivos.
///
/// # Por que a cota é conferida aqui, e não só no gate
///
/// O gate ([`crate::autorizacao::permitir_processo`]) decide pela política
/// e conta os vivos; a vaga do fio novo é reservada depois, aqui. Com um
/// núcleo só, uma chamada de sistema rodava inteira com as interrupções
/// mascaradas, e nada acontecia entre contar e reservar. Com vários, dois
/// processos do mesmo titular bifurcam juntos, em núcleos diferentes, os
/// dois contam um a menos que a cota, e os dois nascem: a cota passa a ser
/// um teto que se ultrapassa por um a cada núcleo. Contar de novo **na
/// mesma seção crítica que reserva a vaga** fecha a janela: o fio reservado
/// já é contado, e quem conta depois o vê.
pub fn criar_processo(
    nome: &'static str,
    entrada: extern "C" fn(u64) -> !,
    argumento: u64,
    autoridade: crate::autorizacao::Autoridade,
    cota: usize,
) -> Result<IdFio, &'static str> {
    nascer(
        nome,
        Nascimento::Funcao {
            entrada,
            argumento,
            autoridade,
            fixo: None,
        },
        Some(cota),
    )
}

/// Cria um fio do kernel que só roda no núcleo `cpu`.
///
/// Existe para quem precisa de um núcleo **determinado**: a suíte, que põe
/// fios em núcleos diferentes para disputarem a mesma trava de verdade, e o
/// pedido de diagnóstico que trava um núcleo de propósito. Um núcleo que
/// ainda não ligou aceita o fio, que fica pronto até ele ligar.
pub fn criar_no_nucleo(
    nome: &'static str,
    entrada: extern "C" fn(u64) -> !,
    argumento: u64,
    cpu: usize,
) -> Result<IdFio, &'static str> {
    if cpu >= MAX_NUCLEOS {
        return Err("nucleo alem do teto do escalonador");
    }
    nascer(
        nome,
        Nascimento::Funcao {
            entrada,
            argumento,
            autoridade: crate::autorizacao::Autoridade::Sistema,
            fixo: Some(cpu),
        },
        None,
    )
}

/// Como um fio novo recebe o primeiro contexto.
///
/// As duas formas diferem só no que é escrito na pilha nova; todo o resto —
/// escolher a vaga, mapear a pilha, instalar — é idêntico, e é por isso que
/// elas compartilham [`nascer`] em vez de duplicá-lo.
enum Nascimento {
    /// Um fio do kernel, que começa entrando numa função Rust, com a
    /// autoridade que quem o criou lhe deu.
    Funcao {
        entrada: extern "C" fn(u64) -> !,
        argumento: u64,
        autoridade: crate::autorizacao::Autoridade,
        /// O núcleo ao qual o fio fica preso, se algum.
        fixo: Option<usize>,
    },
    /// Um filho de `fork`, que começa **retornando** da chamada de sistema que
    /// o pai fez, com o espaço de endereços que o pai lhe deu.
    Bifurcacao {
        quadro: *const core::ffi::c_void,
        espaco: crate::paginacao::Espaco,
    },
}

/// Cria um fio a partir de um quadro de usuário: o filho de um `fork`,
/// contado na cota do titular da autoridade que ele herda — ver
/// [`criar_processo`].
///
/// # Safety
///
/// `quadro` precisa apontar para o quadro de usuário da chamada de sistema em
/// curso, e `espaco` precisa ser uma cópia do espaço do fio que chamou.
pub unsafe fn bifurcar(
    nome: &'static str,
    quadro: *const core::ffi::c_void,
    espaco: crate::paginacao::Espaco,
    cota: usize,
) -> Result<IdFio, &'static str> {
    nascer(nome, Nascimento::Bifurcacao { quadro, espaco }, Some(cota))
}

/// Faz nascer um fio. Com `cota`, ele é um processo, e nasce só se o
/// titular da autoridade dele tiver menos que isso vivos — ver
/// [`criar_processo`].
fn nascer(
    nome: &'static str,
    nascimento: Nascimento,
    cota: Option<usize>,
) -> Result<IdFio, &'static str> {
    // Depois de uma falha fatal o escalonador está congelado, e um fio criado
    // aqui **nunca** roda: [`selecionar`] desiste antes de olhar a tabela.
    //
    // Recusar é o único desfecho honesto. Medido pelo canal do agente, com o
    // kernel em post-mortem: `user.run` respondia `launched: true` a cada
    // chamada, e os fios ficavam todos em `ready` com `scheduled: 0`,
    // `syscalls: 0`, `context_switches: 0`. Um agente investigando um kernel
    // morto pedia para rodar um programa, ouvia que sim, e esperava por uma
    // saída que não podia existir.
    //
    // Cada chamada ainda custava uma das dezesseis vagas de fio e um espaço de
    // endereços que ninguém iria liberar.
    if CONGELADO.load(Ordering::SeqCst) {
        return Err("o escalonador esta congelado apos uma falha fatal");
    }

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
    let id = IdFio(PROXIMO_ID.fetch_add(1, Ordering::Relaxed));

    // Escolhemos a vaga e a **marcamos** na mesma seção crítica. Marcar é o
    // que impede que outra criação concorrente escolha a mesma vaga no
    // intervalo em que estamos mapeando a pilha lá fora.
    // A tabela de descritores do filho é copiada do fio que está chamando, na
    // mesma seção crítica que escolhe a vaga. Um `fork` que não herdasse os
    // descritores abertos não seria um `fork`: o filho acordaria sem a saída
    // padrão, e a primeira coisa que ele escrevesse sumiria.
    //
    // Um fio do kernel não herda de ninguém — ele começa com a tabela
    // padrão, que é o que `criar` quer dizer.
    let (vaga, ocupante_morto, herdada, pai, autoridade, fixo, programa) = com_escalonador(|e| {
        // O parentesco sai da mesma seção crítica que a tabela de
        // descritores, e pelo mesmo motivo: as duas descrevem a relação com
        // quem está chamando, e lê-las em momentos diferentes seria lê-las
        // de dois fios diferentes se a preempção caísse no meio.
        //
        // Só a bifurcação cria filho. `criar` faz um fio do kernel, que não
        // é de ninguém — e é isso que mantém o coletor recolhendo os fios da
        // suíte como sempre recolheu.
        // A autoridade também: a do pai numa bifurcação, a dada numa
        // criação. Um filho sem pai legível fica com a de sistema só se
        // nasceu de `criar`; de uma bifurcação, sem pai não há o que herdar,
        // e a de sessão nenhuma — a serial sem chave — é a menor que há.
        let (herdada, pai, autoridade) = match nascimento {
            Nascimento::Bifurcacao { .. } => match e.fio_atual() {
                Some(pai) => (pai.descritores.clone(), Some(pai.id), pai.autoridade),
                None => (
                    Default::default(),
                    None,
                    crate::autorizacao::Autoridade::NENHUMA,
                ),
            },
            Nascimento::Funcao { autoridade, .. } => (
                crate::usuario::descritores::Tabela::nova(),
                None,
                autoridade,
            ),
        };
        // O programa: o do pai numa bifurcação — o filho executa a mesma
        // imagem —; nenhum num processo que ainda vai carregar a dele; e o
        // kernel num fio do kernel. Um filho sem pai legível não exerce nada.
        let programa = match nascimento {
            Nascimento::Bifurcacao { .. } => e
                .fio_atual()
                .map_or(crate::autorizacao::Programa::SemImagem, |pai| pai.programa),
            Nascimento::Funcao { .. } if cota.is_some() => crate::autorizacao::Programa::SemImagem,
            Nascimento::Funcao { .. } => crate::autorizacao::Programa::Kernel,
        };
        let fixo = match nascimento {
            Nascimento::Funcao { fixo, .. } => fixo,
            Nascimento::Bifurcacao { .. } => None,
        };
        // A cota, com a vaga ainda por reservar e a trava na mão: quem
        // conferir depois de nós já nos conta — ver `criar_processo`.
        if let Some(cota) = cota
            && e.processos_de(autoridade) >= cota
        {
            return Err(COTA_ESGOTADA);
        }
        let vaga = e.vaga_livre()?;
        let anterior = e.fios[vaga].take();
        e.fios[vaga] = Some(Fio {
            id,
            nome,
            estado: Estado::Reservado,
            contexto: Contexto::vazio(),
            _pilha: None,
            espaco: None,
            descritores: herdada.clone(),
            escalonamentos: 0,
            pai,
            saida: None,
            colhido: false,
            autoridade,
            na_cpu: None,
            fixo,
            ocioso: false,
            reexecutar: false,
            pedido: EstadoDoPedido::Livre,
            programa,
        });
        Ok::<_, &'static str>((vaga, anterior, herdada, pai, autoridade, fixo, programa))
    })?;

    // O fio morto que ocupava a vaga morre aqui fora: o `Drop` da pilha dele
    // desmapeia páginas, ou seja, toma as travas da paginação e dos frames.
    drop(ocupante_morto);

    // Ponto de cessão só para testes: é exatamente aqui que a janela entre
    // escolher a vaga e mapear a pilha fica aberta. Sem forçar a troca, a
    // janela dura algumas centenas de instruções e o timer praticamente nunca
    // a acerta — a corrida existiria, mas nenhum teste a provocaria.
    #[cfg(feature = "modo-teste")]
    if CEDER_AO_ESCOLHER_VAGA.load(Ordering::Relaxed) {
        ceder();
    }

    let pilha = match pilha::reservar(vaga) {
        Ok(pilha) => pilha,
        Err(motivo) => {
            // Devolver a vaga é obrigatório: deixá-la reservada a perderia
            // para sempre, e um erro de mapeamento não deve custar uma vaga.
            //
            // `take` e não `= None` pelo mesmo motivo que o resto do módulo
            // evita: atribuir larga o valor antigo ali mesmo, com a trava na
            // mão. O marcador que está na vaga não tem recursos hoje, então
            // dá na mesma — mas isso é um invariante que ninguém enuncia, e
            // no dia em que o `Fio` ganhar mais um campo com `Drop` a
            // diferença entre as duas formas vira um deadlock.
            let marcador = com_escalonador(|e| e.fios[vaga].take());
            drop(marcador);
            return Err(motivo);
        }
    };

    let mut contexto = Contexto::vazio();
    let espaco = match nascimento {
        Nascimento::Funcao {
            entrada, argumento, ..
        } => {
            // SAFETY: a pilha foi mapeada agora e pertence exclusivamente a
            // este fio; `topo` é o endereço logo acima dela, alinhado em
            // página.
            unsafe {
                crate::arch::preparar_contexto(&mut contexto, pilha.topo(), entrada, argumento)
            };
            None
        }
        Nascimento::Bifurcacao { quadro, espaco } => {
            // SAFETY: o quadro é o da chamada em curso, garantido por quem
            // chamou `bifurcar`; a pilha é nova e exclusiva deste fio.
            unsafe { crate::arch::preparar_contexto_de_fork(&mut contexto, pilha.topo(), quadro) };
            Some(espaco)
        }
    };

    // Mesma regra da devolução acima: o marcador sai sob a trava e é largado
    // fora dela.
    let (marcador, ociosos) = com_escalonador(|e| {
        let marcador = e.fios[vaga].replace(Fio {
            id,
            nome,
            estado: Estado::Pronto,
            contexto,
            _pilha: Some(pilha),
            espaco,
            descritores: herdada,
            escalonamentos: 0,
            pai,
            saida: None,
            colhido: false,
            autoridade,
            na_cpu: None,
            fixo,
            ocioso: false,
            reexecutar: false,
            pedido: EstadoDoPedido::Livre,
            programa,
        });
        (marcador, e.nucleos_ociosos())
    });
    drop(marcador);
    // Um fio novo está pronto: um núcleo dormindo pode pegá-lo agora, em vez
    // de no próximo tique dele.
    crate::nucleos::cutucar(ociosos);

    Ok(id)
}

/// Prepara o fio ocioso do núcleo `cpu`: a vaga, a pilha, e o fio marcado
/// como reservado até o núcleo o adotar.
///
/// Devolve a vaga e o topo da pilha, que é onde o núcleo vai acordar.
///
/// # Por que o ocioso nasce aqui, e não no próprio núcleo
///
/// Porque mapear a pilha toma as travas da paginação e dos frames, e o núcleo
/// que acorda ainda não tem pilha nenhuma para chamar quem quer que seja. É
/// a mesma razão do fio inicial: quem já está de pé prepara, e quem chega
/// adota — ver [`adotar_ocioso`].
pub fn preparar_ocioso(cpu: usize) -> Result<(usize, u64), &'static str> {
    if cpu >= MAX_NUCLEOS {
        return Err("nucleo alem do teto do escalonador");
    }
    let id = IdFio(PROXIMO_ID.fetch_add(1, Ordering::Relaxed));
    let (vaga, ocupante_morto) = com_escalonador(|e| {
        let vaga = e.vaga_livre()?;
        let anterior = e.fios[vaga].take();
        e.fios[vaga] = Some(Fio {
            id,
            nome: "ocioso",
            estado: Estado::Reservado,
            contexto: Contexto::vazio(),
            _pilha: None,
            espaco: None,
            descritores: crate::usuario::descritores::Tabela::nova(),
            escalonamentos: 0,
            pai: None,
            saida: None,
            colhido: false,
            autoridade: crate::autorizacao::Autoridade::Sistema,
            na_cpu: None,
            fixo: Some(cpu),
            ocioso: true,
            reexecutar: false,
            pedido: EstadoDoPedido::Livre,
            programa: crate::autorizacao::Programa::Kernel,
        });
        Ok::<_, &'static str>((vaga, anterior))
    })?;
    drop(ocupante_morto);

    let pilha = match pilha::reservar(vaga) {
        Ok(pilha) => pilha,
        Err(motivo) => {
            let marcador = com_escalonador(|e| e.fios[vaga].take());
            drop(marcador);
            return Err(motivo);
        }
    };
    let topo = pilha.topo();
    let mut contexto = Contexto::vazio();
    contexto.pilha_de_kernel = topo & !0xF;
    com_escalonador(|e| {
        if let Some(fio) = e.fios[vaga].as_mut() {
            fio._pilha = Some(pilha);
            fio.contexto = contexto;
        }
    });
    Ok((vaga, topo))
}

/// O núcleo que acabou de acordar adota o fio ocioso preparado para ele.
///
/// Chamada **no** núcleo novo, já sobre a pilha do ocioso, com as
/// interrupções mascaradas: a partir daqui ele tem um fio atual, e o
/// escalonador pode tirá-lo dali.
pub fn adotar_ocioso(vaga: usize) {
    com_escalonador(|e| {
        let cpu = nucleo();
        if let Some(fio) = e.fios[vaga].as_mut() {
            fio.estado = Estado::Rodando;
            fio.na_cpu = Some(cpu);
            fio.escalonamentos = 1;
        }
        e.por_atual(cpu, vaga);
        e.ociosos[cpu] = Some(vaga);
        QUANTUM[cpu].store(QUANTUM_EM_TIQUES, Ordering::Relaxed);
    });
}

/// Devolve a vaga de um ocioso que não chegou a ser adotado.
///
/// O núcleo pode não acordar — o hardware recusou a partida, ou ele não
/// respondeu no prazo. A vaga e a pilha voltam.
///
/// # Safety
///
/// Quem chama garante que o núcleo **nunca** vai acordar sobre esta pilha:
/// ou a partida não foi enviada, ou o núcleo foi dado como perdido e
/// [`crate::nucleos`] o impede de adotar qualquer coisa. Devolver a pilha de
/// um núcleo que ainda pode acordar seria entregar a ele memória de outro.
pub unsafe fn desistir_do_ocioso(vaga: usize) {
    let marcador = com_escalonador(|e| match &e.fios[vaga] {
        Some(fio) if fio.ocioso && fio.estado == Estado::Reservado => e.fios[vaga].take(),
        _ => None,
    });
    drop(marcador);
}

impl Escalonador {
    /// Os processos vivos com a `autoridade` — reservados também: um fio
    /// que está nascendo já conta. Ver [`processos_de`].
    fn processos_de(&self, autoridade: crate::autorizacao::Autoridade) -> usize {
        self.fios
            .iter()
            .flatten()
            .filter(|f| {
                f.nome == "usuario" && f.estado != Estado::Terminado && f.autoridade == autoridade
            })
            .count()
    }

    /// Uma vaga livre, ou a de um fio já encerrado.
    ///
    /// A vaga do fio **atual** nunca entra na conta, mesmo que ele esteja
    /// marcado como encerrado. Um fio que chamou [`terminar`] segue executando
    /// até ceder a vez, e `e.atual` continua apontando para a vaga dele: se
    /// outro fio a ocupasse nesse intervalo, a próxima troca salvaria o
    /// contexto do moribundo por cima do contexto do recém-criado, e o
    /// recém-criado passaria a retomar num ponto que nunca foi dele.
    ///
    /// Com vários núcleos, "o atual" vira "qualquer fio que um núcleo esteja
    /// usando", e o campo que responde é [`Fio::na_cpu`]: ele cobre o atual
    /// de cada núcleo e também o que um núcleo acabou de largar mas ainda
    /// não terminou de salvar.
    fn vaga_livre(&self) -> Result<usize, &'static str> {
        self.fios
            .iter()
            .position(|f| match f {
                None => true,
                Some(fio) => fio.estado == Estado::Terminado && fio.na_cpu.is_none(),
            })
            .ok_or("nao ha vaga livre para outro fio")
    }

    /// O fio da vaga `i` está esperando ser colhido pelo pai?
    ///
    /// Só é zumbi quem terminou, ainda não foi colhido, e tem um pai que
    /// **ainda pode perguntar**. As três condições importam:
    ///
    /// - terminado, porque um fio vivo não tem código de saída a guardar;
    /// - não colhido, porque depois da pergunta não há mais o que guardar;
    /// - pai vivo, porque um pai que já morreu nunca mais vai perguntar, e
    ///   esperar por ele seria reter a vaga para sempre.
    ///
    /// "Pai vivo" é: existe na tabela, com aquele id, e não terminou. O id
    /// entra na comparação porque a vaga é reaproveitada — sem ele, um fio
    /// novo que caísse na vaga do pai morto herdaria os zumbis dele.
    fn e_zumbi(&self, i: usize) -> bool {
        let Some(fio) = self.fios[i].as_ref() else {
            return false;
        };
        if fio.estado != Estado::Terminado || fio.colhido {
            return false;
        }
        let Some(pai) = fio.pai else {
            return false;
        };
        self.fios
            .iter()
            .flatten()
            .any(|candidato| candidato.id == pai && candidato.estado != Estado::Terminado)
    }

    /// O próximo fio que o núcleo `cpu` pode rodar, em rodízio a partir do
    /// atual dele.
    ///
    /// Rodízio simples: varremos a tabela a partir da posição seguinte à
    /// atual, dando a volta. É O(MAX_FIOS) no pior caso, o que com 95 vagas é
    /// barato o bastante para rodar dentro de um handler.
    ///
    /// Pode rodar aqui quem está `Pronto`, não está nas mãos de outro núcleo
    /// e não é fixo em outro. O ocioso fica de fora da volta: ele só entra se
    /// o fio atual não puder continuar e não houver mais ninguém — senão um
    /// núcleo com trabalho gastaria fatias inteiras dormindo.
    fn proximo_pronto(&self, cpu: usize) -> Option<usize> {
        let de = self.atual[cpu].unwrap_or(0);
        let elegivel = |f: &Fio| {
            f.estado == Estado::Pronto
                && f.na_cpu.is_none()
                && f.fixo.is_none_or(|c| c == cpu)
                && !f.ocioso
        };
        if let Some(i) = (1..=MAX_FIOS)
            .map(|passo| (de + passo) % MAX_FIOS)
            .find(|&i| matches!(&self.fios[i], Some(f) if elegivel(f)))
        {
            return Some(i);
        }

        // Ninguém mais. Se o atual ainda pode correr, ele continua; se não
        // pode — terminou ou espera —, o ocioso deste núcleo o substitui.
        let atual_segue = self.atual[cpu]
            .and_then(|i| self.fios[i].as_ref())
            .is_some_and(|f| f.estado == Estado::Rodando);
        if atual_segue {
            return None;
        }
        let ocioso = self.ociosos[cpu]?;
        matches!(&self.fios[ocioso], Some(f) if f.estado == Estado::Pronto && f.na_cpu.is_none())
            .then_some(ocioso)
    }
}

/// O que a troca de contexto precisa saber: de onde sair e para onde ir.
pub struct Troca {
    /// Onde guardar o contexto do fio que está saindo.
    pub de: *mut Contexto,
    /// De onde ler o contexto do fio que está entrando.
    pub para: *const Contexto,
    /// A raiz de tradução em que o fio que entra precisa rodar.
    ///
    /// Vem resolvida daqui, e não do backend, porque a resposta depende da
    /// tabela do escalonador — que só pode ser lida com a trava na mão. O
    /// backend recebe um número e o instala se for diferente do atual.
    pub espaco: u64,
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
    // Conferido antes de tocar na trava: depois de uma falha fatal, ela pode
    // ser justamente o que está na mão de código que nunca mais vai rodar.
    if CONGELADO.load(Ordering::SeqCst) {
        return None;
    }

    let mut escalonador = ESCALONADOR.lock();
    let e = &mut *escalonador;

    if !e.ligado {
        return None;
    }

    let cpu = nucleo();
    // Rede de segurança: se a troca anterior deste núcleo ainda não soltou a
    // posse do fio que ele largou, solta agora — estarmos aqui, neste núcleo,
    // prova que ela terminou. Sem isto, sobrescrever `anterior` abaixo
    // deixaria aquele fio preso a este núcleo para sempre.
    e.concluir_troca(cpu);

    let atual = e.atual[cpu]?;
    let proximo = e.proximo_pronto(cpu)?;
    if proximo == atual {
        return None;
    }

    // A vaga do fio atual é sempre ocupada enquanto o escalonador está ligado:
    // `init` preenche a zero e `vaga_livre` nunca entrega uma vaga com dono.
    // Se ainda assim estiver vazia, é bug nosso, e trocar sem ter onde salvar
    // o contexto perderia o fio para sempre — recusar a troca é o desfecho
    // seguro.
    let fio_atual = e.fios[atual].as_mut()?;
    // O fio que sai volta para a fila, a menos que já tenha se encerrado.
    if fio_atual.estado == Estado::Rodando {
        fio_atual.estado = Estado::Pronto;
    }
    let de: *mut Contexto = &mut fio_atual.contexto;

    let (para, espaco): (*const Contexto, u64) = {
        let fio = e.fios[proximo].as_mut().expect("vaga conferida acima");
        fio.estado = Estado::Rodando;
        fio.escalonamentos += 1;
        // A posse do que entra começa agora, sob a trava: nenhum outro
        // núcleo o escolhe daqui em diante. A do que sai **continua** — ela
        // só cai em `troca_concluida`, quando o contexto dele estiver
        // escrito.
        fio.na_cpu = Some(cpu);
        (&fio.contexto, fio.raiz())
    };

    e.por_atual(cpu, proximo);
    e.anterior[cpu] = Some(atual);
    // Quem entra recebe uma fatia inteira, mesmo que a troca tenha vindo de
    // uma cessão voluntária do anterior. Herdar o resto da fatia alheia faria
    // um fio que cede muito punir o seguinte.
    QUANTUM[cpu].store(QUANTUM_EM_TIQUES, Ordering::Relaxed);
    TROCAS.fetch_add(1, Ordering::Relaxed);

    Some(Troca { de, para, espaco })
}

/// Avisa que a troca deste núcleo terminou: o fio que ele largou já tem o
/// contexto salvo e pode ser escolhido por qualquer um.
///
/// Chamada pelo fio que **entra**, no primeiro instante em que ele roda —
/// depois do `trocar_contexto` no x86, no fim da troca de quadro no ARM, e
/// nos trampolins dos fios que nunca rodaram. Ver [`Fio::na_cpu`].
pub fn troca_concluida() {
    com_escalonador(|e| {
        let cpu = nucleo();
        e.concluir_troca(cpu);
    });
}

/// Entrega ao fio atual o espaço de endereços em que ele vai rodar.
///
/// Devolve o espaço que estava no lugar, se havia — largá-lo aqui dentro faria
/// o `Drop` dele desmapear páginas com a trava do escalonador na mão, e o
/// módulo inteiro evita aninhar travas por princípio. Quem chama larga o
/// resultado quando quiser.
///
/// O programa troca na mesma seção crítica: daqui em diante o fio executa a
/// imagem nova, e é com o manifesto dela que o gate o decide. E a resposta
/// de um pedido que a imagem anterior não buscou sai junto: era dela, com o
/// manifesto dela — buscada pela nova, seria a imagem nova lendo o que só a
/// anterior podia pedir. Devolvida, com o espaço, para largar fora da trava.
#[must_use = "o espaco anterior e a resposta precisam ser largados fora da trava"]
pub fn adotar_imagem(
    espaco: crate::paginacao::Espaco,
    programa: crate::autorizacao::Programa,
) -> (Option<crate::paginacao::Espaco>, EstadoDoPedido) {
    com_escalonador(|e| match e.fio_atual_mut() {
        Some(fio) => {
            fio.programa = programa;
            let pedido = core::mem::take(&mut fio.pedido);
            (fio.espaco.replace(espaco), pedido)
        }
        None => (Some(espaco), EstadoDoPedido::Livre),
    })
}

/// O identificador do fio que está executando e o programa dele — ver
/// [`crate::autorizacao::Programa`]. Fora de um fio, o kernel.
/// Só para a suíte: os núcleos parados no fio ocioso agora — os que um
/// fio novo precisa cutucar. Ver o caso "smp: o fio novo acorda o ocioso".
#[cfg(feature = "modo-teste")]
pub fn ociosos_de_teste() -> crate::nucleos::Mascara {
    com_escalonador(|e| e.nucleos_ociosos())
}

/// Só para a suíte: uma pausa no ponto exato em que o backend pergunta se a
/// chamada pede para ser reexecutada — depois de a chamada voltar, antes da
/// pergunta. É a janela em que outro núcleo pode acordar o fio, e o caso
/// "fios: a reexecucao e da chamada" a abre de propósito, uma vez, para um
/// programa só. Fora da suíte não existe.
#[cfg(feature = "modo-teste")]
pub mod pausa_de_teste {
    use core::sync::atomic::{AtomicBool, Ordering};

    static ARMADA: AtomicBool = AtomicBool::new(false);
    static PARADA: AtomicBool = AtomicBool::new(false);
    static SOLTA: AtomicBool = AtomicBool::new(false);
    static PROGRAMA: crate::trava::Mutex<&'static str> = crate::trava::Mutex::new("");

    /// A próxima chamada que pedir reexecução, de um processo do programa
    /// `nome`, para antes da pergunta.
    pub fn armar(nome: &'static str) {
        crate::arch::sem_interrupcoes(|| *PROGRAMA.lock() = nome);
        SOLTA.store(false, Ordering::Release);
        PARADA.store(false, Ordering::Release);
        ARMADA.store(true, Ordering::Release);
    }

    /// O fio chegou à pausa.
    pub fn parada() -> bool {
        PARADA.load(Ordering::Acquire)
    }

    /// Solta o fio parado, e desarma.
    pub fn soltar() {
        ARMADA.store(false, Ordering::Release);
        SOLTA.store(true, Ordering::Release);
    }

    /// Chamada pelos dois backends logo antes de `tirar_reexecucao`. Gira,
    /// e não dorme: as interrupções podem estar mascaradas aqui. Um teto de
    /// voltas, para um caso que não soltasse não travar o núcleo para
    /// sempre.
    pub fn talvez_pausar() {
        if !ARMADA.load(Ordering::Acquire) {
            return;
        }
        let pede = super::com_escalonador(|e| e.fio_atual().is_some_and(|f| f.reexecutar));
        let nome = crate::arch::sem_interrupcoes(|| *PROGRAMA.lock());
        let deste = match super::programa_atual().1 {
            crate::autorizacao::Programa::Imagem {
                manifesto: Some(m), ..
            } => m.nome() == nome,
            _ => false,
        };
        if !pede || !deste || !ARMADA.swap(false, Ordering::AcqRel) {
            return;
        }
        PARADA.store(true, Ordering::Release);
        let mut voltas = 0u64;
        while !SOLTA.load(Ordering::Acquire) && voltas < 4_000_000_000 {
            core::hint::spin_loop();
            voltas += 1;
        }
    }
}

pub fn programa_atual() -> (u64, crate::autorizacao::Programa) {
    com_escalonador(|e| {
        e.fio_atual()
            .map_or((0, crate::autorizacao::Programa::Kernel), |f| {
                (f.id.numero(), f.programa)
            })
    })
}

/// Cede a CPU voluntariamente. Quem espera a ordem das gravações da
/// persistência cede em vez de girar: quem a tem pode estar preemptado.
pub fn ceder() {
    crate::arch::ceder_cpu();
}

/// A autoridade do fio que está executando — ver [`Fio::autoridade`].
pub fn autoridade_atual() -> crate::autorizacao::Autoridade {
    com_escalonador(|e| {
        e.fio_atual()
            .map(|f| f.autoridade)
            .unwrap_or(crate::autorizacao::Autoridade::NENHUMA)
    })
}

/// O identificador do fio que está executando.
pub fn id_atual() -> u64 {
    com_escalonador(|e| e.fio_atual().map(|f| f.id.numero()).unwrap_or(0))
}

/// O identificador do fio atual deste núcleo, como [`id_atual`], sem a
/// trava do escalonador: para quem não pode tomá-la — a conferência da
/// ordem das travas, que roda dentro de cada `lock`.
///
/// O valor é escrito com a trava na mão, nos mesmos pontos em que o
/// escalonador troca o fio atual do núcleo: lido do próprio núcleo, é o
/// mesmo que [`id_atual`] daria.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn id_atual_sem_trava() -> u64 {
    ID_NO_NUCLEO[nucleo()].load(Ordering::Acquire)
}

/// O identificador do fio atual de cada núcleo — ver [`id_atual_sem_trava`].
static ID_NO_NUCLEO: [AtomicU64; MAX_NUCLEOS] = [const { AtomicU64::new(0) }; MAX_NUCLEOS];

impl Escalonador {
    /// Põe `vaga` como o fio atual de `cpu`, e o identificador dela onde se
    /// lê sem a trava.
    fn por_atual(&mut self, cpu: usize, vaga: usize) {
        self.atual[cpu] = Some(vaga);
        let id = self.fios[vaga].as_ref().map_or(0, |f| f.id.numero());
        ID_NO_NUCLEO[cpu].store(id, Ordering::Release);
    }
}

/// Dá acesso à tabela de descritores do fio que está executando.
///
/// # A regra de quem chama, e por que ela não é opcional
///
/// `f` roda com a trava do escalonador na mão e as interrupções desligadas.
/// **Nada que vá ao disco, ao heap ou a outra trava pode acontecer lá
/// dentro** — uma leitura de arquivo dali travaria o sistema inteiro pelo
/// tempo do disco, com o escalonador parado.
///
/// É por isso que uma leitura por descritor acontece em três tempos: pega o
/// alvo aqui dentro, lê lá fora, e volta aqui para avançar a posição. O
/// [`Alvo`](crate::usuario::descritores::Alvo) é `Copy` exatamente para que o
/// primeiro tempo possa sair com uma cópia e largar a trava.
///
/// Devolve `None` se não houver fio atual, o que só acontece antes de
/// [`init`].
pub fn com_descritores<R>(
    f: impl FnOnce(&mut crate::usuario::descritores::Tabela) -> R,
) -> Option<R> {
    com_escalonador(|e| e.fio_atual_mut().map(|fio| f(&mut fio.descritores)))
}

/// A pilha de kernel do fio que está executando.
///
/// Usada ao entrar em userspace: é o endereço que o processador precisa
/// adotar quando uma interrupção chegar com o código do usuário rodando.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn pilha_de_kernel_atual() -> u64 {
    com_escalonador(|e| {
        e.fio_atual()
            .map(|f| f.contexto.pilha_de_kernel())
            .unwrap_or(0)
    })
}

/// O que [`colher_filho`] encontrou.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Colheita {
    /// Um filho terminado foi colhido: o id dele, e com que código saiu.
    ///
    /// A saída é `Option` porque nem todo fio sai por `sair` — um processo
    /// morto por falha de página termina sem código nenhum, e inventar zero
    /// ali seria dizer ao pai que o filho terminou bem.
    Colhido(u64, Option<i64>),
    /// Há filhos, mas nenhum terminou ainda.
    Aguardando,
    /// Não há filho que satisfaça o pedido — nenhum, ou nenhum com aquele id.
    SemFilhos,
}

/// Colhe um filho terminado do fio atual, se houver um.
///
/// `alvo` restringe a um id; `None` colhe qualquer filho.
///
/// # Por que a colheita é uma operação do escalonador
///
/// Porque ela precisa ser atômica em relação à tabela: encontrar o filho,
/// ler o código de saída e marcá-lo como colhido são três passos que, se
/// separados, deixam uma janela em que o coletor recolhe a vaga entre o
/// segundo e o terceiro — e o pai recebe um código de um fio que já não
/// existe, ou duas colheitas devolvem o mesmo filho duas vezes.
///
/// # Por que ela também põe o pai para dormir
///
/// Porque decidir "não há o que colher" e "então durma" em duas seções
/// críticas é o despertar perdido clássico, e aqui ele trava a máquina.
///
/// A janela é esta: o pai pergunta, ouve que o filho ainda roda, e **antes**
/// de se marcar como esperando o timer o preempta. O filho roda, sai, e
/// [`marcar_terminado`] procura um pai `Esperando` para acordar — não acha,
/// porque o pai ainda está `Rodando`. O pai volta, marca-se `Esperando`, e
/// dorme para sempre por um filho que já morreu. O escalonador nunca mais o
/// escolhe, e o zumbi nunca é colhido.
///
/// Uma seção crítica só fecha a janela por construção: ou a colheita acha o
/// filho, ou o pai já está `Esperando` quando a trava sai da mão — e o filho
/// que sair depois disso vai achá-lo.
///
/// Medido, não deduzido. Separando os dois passos e forçando uma cessão
/// entre eles — que é escancarar a janela que o timer acertaria sozinho de
/// vez em quando —, o caso do paciente reprova com `a condicao nao se
/// cumpriu dentro do teto de tempo`: o pai dorme e não acorda mais.
pub fn colher_filho(alvo: Option<u64>) -> Colheita {
    com_escalonador(|e| {
        let Some(eu) = e.fio_atual().map(|f| f.id) else {
            return Colheita::SemFilhos;
        };

        let meus = |fio: &Fio| fio.pai == Some(eu) && alvo.is_none_or(|a| fio.id.numero() == a);

        // O terminado primeiro: se há um pronto para colher, a resposta é
        // ele, mesmo que existam outros filhos ainda rodando.
        if let Some(vaga) = (0..MAX_FIOS).find(|&i| {
            matches!(&e.fios[i], Some(fio)
                if meus(fio) && fio.estado == Estado::Terminado && !fio.colhido)
        }) {
            let fio = e.fios[vaga].as_mut().expect("a vaga acabou de casar");
            fio.colhido = true;
            COLHIDOS.fetch_add(1, Ordering::Relaxed);
            return Colheita::Colhido(fio.id.numero(), fio.saida);
        }

        // Nenhum terminado. Ainda há filho vivo pelo qual esperar?
        //
        // Um filho já colhido não conta: ele existe na tabela só até o
        // coletor passar, e contá-lo faria o pai esperar por uma segunda
        // saída que nunca vem.
        if e.fios.iter().flatten().any(|f| meus(f) && !f.colhido) {
            // Na mesma seção crítica: ver o cabeçalho.
            if let Some(fio) = e.fio_atual_mut() {
                fio.estado = Estado::Esperando;
                fio.reexecutar = true;
            }
            Colheita::Aguardando
        } else {
            Colheita::SemFilhos
        }
    })
}

/// Quantos filhos já foram colhidos.
static COLHIDOS: AtomicU64 = AtomicU64::new(0);

/// `(colhidos, zumbis agora)`.
pub fn colheita() -> (u64, usize) {
    let zumbis = com_escalonador(|e| (0..MAX_FIOS).filter(|&i| e.e_zumbi(i)).count());
    (COLHIDOS.load(Ordering::Relaxed), zumbis)
}

/// A chamada de sistema que acabou de rodar pediu para ser reexecutada?
/// Responde uma vez: a pergunta apaga o pedido.
///
/// # Por que perguntar à chamada, e não ao estado do fio
///
/// O backend de arquitetura perguntava se o fio estava esperando — e, se
/// estava, reexecutava a chamada em vez de devolver o resultado, que nesse
/// caminho é um zero sem sentido. Com um núcleo só, entre a chamada pôr o
/// fio em espera e o backend perguntar, nada o acordava: a chamada roda com
/// as interrupções mascaradas. Com vários, o filho sai em outro núcleo
/// exatamente nessa janela e acorda o pai; o backend o encontrava pronto,
/// concluía que a chamada tinha acabado, e o zero chegava ao processo como
/// resposta — `esperar` dizendo que colheu o filho 0, sem código. Medido na
/// suíte do ARM em release: o programa `ponteiros` recebeu `Ok((0, None))`.
///
/// O pedido é posto pela própria chamada, junto com o estado de espera e
/// sob a mesma trava, e ninguém mais o mexe: quem acorda muda o estado, não
/// o pedido. Acordado antes ou depois, o fio reexecuta a chamada — e acordar
/// a mais é inofensivo, ver [`Estado::Esperando`].
pub fn tirar_reexecucao() -> bool {
    com_escalonador(|e| {
        e.fio_atual_mut()
            .is_some_and(|f| core::mem::take(&mut f.reexecutar))
    })
}

/// Tira o fio atual de circulação até [`acordar`] o devolver.
///
/// Para uma chamada de sistema que conferiu, sem efeito nenhum, que não há
/// o que entregar — ver [`Estado::Esperando`] sobre por que isso importa: o
/// backend de arquitetura vai reexecutá-la quando o fio voltar.
pub fn estacionar_atual() {
    com_escalonador(|e| {
        if let Some(fio) = e.fio_atual_mut() {
            fio.estado = Estado::Esperando;
            fio.reexecutar = true;
        }
    });
}

/// O que `pedir` encontra no fio atual — ver [`crate::nativo`].
pub enum Retomada {
    /// Nada em andamento: o pedido é novo.
    Novo,
    /// O pedido ainda não tem resposta: o fio volta a esperar.
    Esperando,
    /// A resposta está pronta, com este tamanho; ela passa a esperar
    /// `resposta` a buscar.
    Pronto(usize),
}

/// O primeiro passo de `pedir`: um pedido em andamento continua — o fio
/// volta a esperar se a resposta não chegou, ou recebe o tamanho dela se
/// chegou.
///
/// É o que torna `pedir` segura de reexecutar: ela é chamada de novo depois
/// de acordar, com os mesmos argumentos, e aqui a chamada reexecutada não é
/// um pedido novo. Um pedido novo só começa com o fio sem nada em andamento
/// — e o processo tem um fio só: enquanto ele espera, não há outro para
/// pedir.
pub fn retomar_pedido() -> Retomada {
    com_escalonador(|e| {
        let Some(fio) = e.fio_atual_mut() else {
            return Retomada::Novo;
        };
        match core::mem::take(&mut fio.pedido) {
            EstadoDoPedido::Pronto(t) => {
                let n = t.len();
                fio.pedido = EstadoDoPedido::Pendente(t);
                Retomada::Pronto(n)
            }
            andamento @ (EstadoDoPedido::Enfileirado(_) | EstadoDoPedido::EmCurso) => {
                fio.pedido = andamento;
                fio.estado = Estado::Esperando;
                fio.reexecutar = true;
                Retomada::Esperando
            }
            // A resposta que não foi buscada fica onde estava: só um pedido
            // novo a descarta, e ele começa em [`enfileirar_pedido`].
            parado => {
                fio.pedido = parado;
                Retomada::Novo
            }
        }
    })
}

/// Põe o pedido `texto` no fio atual e o fio a esperar a resposta. Devolve
/// o que havia — a resposta anterior que não foi buscada —, para quem chama
/// largar fora da trava.
pub fn enfileirar_pedido(texto: politica::sigiloso::Texto) -> EstadoDoPedido {
    com_escalonador(|e| match e.fio_atual_mut() {
        Some(fio) => {
            fio.estado = Estado::Esperando;
            fio.reexecutar = true;
            core::mem::replace(&mut fio.pedido, EstadoDoPedido::Enfileirado(texto))
        }
        None => EstadoDoPedido::Enfileirado(texto),
    })
}

/// Desfaz [`enfileirar_pedido`] quando o pedido não chegou à fila: o fio
/// volta a rodar sem nada em andamento. Devolve o texto para largar fora.
pub fn desfazer_pedido() -> EstadoDoPedido {
    com_escalonador(|e| match e.fio_atual_mut() {
        Some(fio) => {
            fio.estado = Estado::Rodando;
            fio.reexecutar = false;
            core::mem::take(&mut fio.pedido)
        }
        None => EstadoDoPedido::Livre,
    })
}

/// O executor toma o pedido do fio `id`: o texto, a autoridade do fio e o
/// programa dele — com que o comando será decidido. `None` se o fio não existe mais, já
/// terminou, ou não tem pedido na fila.
pub fn tomar_pedido(
    id: u64,
) -> Option<(
    politica::sigiloso::Texto,
    crate::autorizacao::Autoridade,
    crate::autorizacao::Programa,
)> {
    com_escalonador(|e| {
        let fio = e
            .fios
            .iter_mut()
            .flatten()
            .find(|f| f.id.numero() == id && f.estado != Estado::Terminado)?;
        match core::mem::replace(&mut fio.pedido, EstadoDoPedido::EmCurso) {
            EstadoDoPedido::Enfileirado(t) => Some((t, fio.autoridade, fio.programa)),
            outro => {
                fio.pedido = outro;
                None
            }
        }
    })
}

/// O executor entrega a resposta ao fio `id`, e o acorda se ele espera.
/// Devolve a resposta se o fio não está mais lá para recebê-la — morreu
/// enquanto o comando executava —, para quem chama largar fora da trava.
pub fn responder_pedido(
    id: u64,
    resposta: politica::sigiloso::Texto,
) -> Option<politica::sigiloso::Texto> {
    let (sobra, ociosos) = com_escalonador(|e| {
        let Some(fio) = e
            .fios
            .iter_mut()
            .flatten()
            .find(|f| f.id.numero() == id && f.estado != Estado::Terminado)
        else {
            return (Some(resposta), 0);
        };
        if !matches!(fio.pedido, EstadoDoPedido::EmCurso) {
            return (Some(resposta), 0);
        }
        fio.pedido = EstadoDoPedido::Pronto(resposta);
        if fio.estado == Estado::Esperando {
            fio.estado = Estado::Pronto;
            (None, e.nucleos_ociosos())
        } else {
            (None, 0)
        }
    });
    crate::nucleos::cutucar(ociosos);
    sobra
}

/// `resposta`: tira do fio atual a resposta que espera ser buscada.
pub fn tirar_resposta() -> Option<politica::sigiloso::Texto> {
    com_escalonador(|e| {
        let fio = e.fio_atual_mut()?;
        match core::mem::take(&mut fio.pedido) {
            EstadoDoPedido::Pendente(t) => Some(t),
            outro => {
                fio.pedido = outro;
                None
            }
        }
    })
}

/// Devolve ao fio atual a resposta que não coube onde o processo pediu.
pub fn devolver_resposta(t: politica::sigiloso::Texto) {
    com_escalonador(|e| {
        if let Some(fio) = e.fio_atual_mut() {
            fio.pedido = EstadoDoPedido::Pendente(t);
        }
    });
}

/// Devolve à circulação o fio `id`, se ele estiver esperando.
///
/// Quem chama é quem publica num canal de eventos — ver [`crate::eventos`],
/// que ainda só a suíte faz.
///
/// Devolve se ele ainda existe e não terminou — esperando ou não.
pub fn acordar(id: u64) -> bool {
    let (vivo, ociosos) = com_escalonador(|e| {
        let mut acordou = false;
        let mut vivo = false;
        for fio in e.fios.iter_mut().flatten() {
            if fio.id.numero() == id {
                if fio.estado == Estado::Esperando {
                    fio.estado = Estado::Pronto;
                    acordou = true;
                }
                vivo = fio.estado != Estado::Terminado;
                break;
            }
        }
        (vivo, if acordou { e.nucleos_ociosos() } else { 0 })
    });
    crate::nucleos::cutucar(ociosos);
    vivo
}

/// Só para a suíte: se o fio `id` está esperando.
#[cfg(feature = "modo-teste")]
pub fn esperando_de_teste(id: u64) -> bool {
    com_escalonador(|e| {
        e.fios
            .iter()
            .flatten()
            .any(|f| f.id.numero() == id && f.estado == Estado::Esperando)
    })
}

/// Só para a suíte: prende o fio `id` ao núcleo `cpu`, ou o solta com
/// `None`. Devolve se o fio existe.
///
/// # Para que a suíte precisa
///
/// Alguns casos precisam de um processo **parado** por um instante — para
/// encher uma fila que ele esvaziaria, e provar que ela tem teto. Com um
/// núcleo só, mascarar as interrupções bastava: o processo não tinha onde
/// rodar. Com vários, ele roda em outro núcleo enquanto a suíte mascara o
/// seu. Prendê-lo ao núcleo da suíte devolve a propriedade sem fingir que
/// ela existe: mascarado ali, ele não tem onde rodar de novo.
#[cfg(feature = "modo-teste")]
pub fn fixar(id: u64, cpu: Option<usize>) -> bool {
    com_escalonador(|e| {
        for fio in e.fios.iter_mut().flatten() {
            if fio.id.numero() == id && !fio.ocioso {
                fio.fixo = cpu;
                return true;
            }
        }
        false
    })
}

/// Só para a suíte: em que núcleo o fio `id` está agora, se em algum.
#[cfg(feature = "modo-teste")]
pub fn nucleo_de(id: u64) -> Option<usize> {
    com_escalonador(|e| {
        e.fios
            .iter()
            .flatten()
            .find(|f| f.id.numero() == id)
            .and_then(|f| f.na_cpu)
    })
}

/// Quantos processos vivos têm esta autoridade: os fios que hospedam um
/// programa — lançados por `user.run` ou pelo sistema, ou bifurcados — e não
/// terminaram. É a conta da cota de processos do papel — ver
/// [`crate::autorizacao::permitir_processo`].
pub fn processos_de(autoridade: crate::autorizacao::Autoridade) -> usize {
    com_escalonador(|e| e.processos_de(autoridade))
}

/// O fio `id` existe e não terminou?
pub fn vivo(id: u64) -> bool {
    com_escalonador(|e| {
        e.fios
            .iter()
            .flatten()
            .any(|f| f.id.numero() == id && f.estado != Estado::Terminado)
    })
}

/// O fio atual não pode continuar de onde estava?
///
/// Vale para os dois motivos que existem hoje — ele terminou, ou está
/// esperando um filho — e é a pergunta que o backend de arquitetura faz
/// depois de cada chamada de sistema. Uma pergunta só porque a resposta leva
/// ao mesmo lugar: parar de rodar. O que difere é se ele volta.
pub fn atual_parado() -> bool {
    com_escalonador(|e| {
        e.fio_atual()
            .is_some_and(|f| f.estado == Estado::Terminado || f.estado == Estado::Esperando)
    })
}

/// Marca o fio atual como encerrado, sem trocar de contexto.
///
/// Separado de [`terminar`] por causa do ARM. Lá, encerrar de dentro de um
/// handler de exceção — que é onde uma chamada de sistema roda — não pode
/// passar por `ceder`: `ceder` emite um `svc`, e um `svc` de dentro de um
/// handler aninha uma exceção sobre a outra. O quadro aninhado fica numa
/// profundidade da pilha de exceção que não sobrevive a uma troca de fio.
///
/// Então quem roda num handler marca aqui e deixa o próprio handler fazer a
/// troca, sobre o quadro que ele já tem em mãos.
pub fn marcar_terminado(saida: Option<i64>) {
    let ociosos = com_escalonador(|e| {
        let pai = match e.fio_atual_mut() {
            Some(fio) => {
                fio.estado = Estado::Terminado;
                fio.saida = saida;
                fio.pai
            }
            None => return 0,
        };

        // Acordar o pai é a outra metade de terminar, e ela mora aqui pela
        // mesma razão que o código de saída: quem acaba de morrer é o único
        // que sabe, no mesmo instante, que há o que colher.
        //
        // Feito fora daqui — por exemplo no coletor, uma volta depois — a
        // espera ganharia a latência de um tique do timer sem precisar, e
        // ganharia também uma janela: entre o filho sair e o pai acordar,
        // uma segunda saída poderia sobrescrever o que o pai ia ler.
        //
        // Acordamos **sem** conferir por qual filho ele espera. O pai volta,
        // pergunta de novo, e se o filho que saiu não era o dele ele volta a
        // esperar. Uma volta perdida é mais barata que guardar em cada fio o
        // id que ele aguarda — um campo que só poderia divergir do que a
        // chamada de sistema realmente pediu.
        let Some(pai) = pai else { return 0 };
        for fio in e.fios.iter_mut().flatten() {
            if fio.id == pai && fio.estado == Estado::Esperando {
                fio.estado = Estado::Pronto;
                return e.nucleos_ociosos();
            }
        }
        0
    });
    crate::nucleos::cutucar(ociosos);
}

/// Encerra o fio atual. Nunca retorna.
///
/// A pilha do fio **não** é liberada aqui, e não poderia ser: estamos
/// executando em cima dela. Ela sobrevive até a vaga ser reaproveitada por
/// outra criação, que é quando o `Drop` finalmente roda. O desperdício é
/// limitado — no pior caso uma pilha por vaga —, e a alternativa seria um fio
/// coletor só para desmapear pilhas alheias.
///
/// Sem consumidor de produção hoje pelo mesmo motivo de [`criar`]: o único fio
/// que existe é o do próprio kernel, e ele não termina.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn terminar() -> ! {
    // Sem código de saída: um fio do kernel que chega ao fim não saiu por
    // `sair`, e não há número a guardar. Inventar zero diria a quem
    // perguntasse que ele terminou bem — e ninguém pergunta, porque um fio
    // do kernel não tem pai.
    marcar_terminado(None);
    descansar()
}

/// Cede a CPU para sempre. Nunca retorna.
///
/// É a cauda de [`terminar`], separada porque o caminho da chamada de sistema
/// `sair` precisa dela sem a marcação — o handler já marcou.
pub fn descansar() -> ! {
    loop {
        crate::arch::ceder_cpu();
        // Se voltarmos aqui é porque não havia outro fio pronto. Dormir em vez
        // de girar: a próxima interrupção pode trazer alguém.
        //
        // `dormir_parado`, e não `esperar_interrupcao`: este caminho é
        // alcançado de dentro de uma chamada de sistema, e no x86 o
        // `syscall` chega com as interrupções mascaradas. A outra função se
        // recusa a dormir mascarada e gira — e girar aqui é girar para
        // sempre, porque não há outro fio para religá-las.
        crate::arch::dormir_parado();
    }
}

/// Contabiliza um tique do timer e decide se é hora de preemptar.
///
/// Chamada de dentro do handler do timer, antes de ele retornar.
pub fn tique() -> bool {
    if CONGELADO.load(Ordering::SeqCst) {
        return false;
    }

    if !LIGADO.load(Ordering::Acquire) {
        return false;
    }

    // Sem a trava do escalonador — ver `QUANTUM`. Estamos no handler do timer
    // deste núcleo, com as interrupções mascaradas: ninguém mais toca neste
    // quantum agora.
    let quantum = &QUANTUM[nucleo()];
    let restante = quantum.load(Ordering::Relaxed).saturating_sub(1);
    // Recarregamos aqui, e não só quando a troca acontece. Se deixássemos
    // para lá, um quantum vencido sem outro fio pronto ficaria em zero para
    // sempre: o timer pediria uma troca a cada tique, e o contador de
    // vencimentos passaria a medir tiques, não fatias.
    let venceu = restante == 0;
    quantum.store(
        if venceu { QUANTUM_EM_TIQUES } else { restante },
        Ordering::Relaxed,
    );

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
    /// O núcleo em que ele está agora, se algum.
    pub nucleo: Option<usize>,
    /// O único núcleo em que ele pode rodar, se é fixo.
    pub fixo: Option<usize>,
}

pub fn com_inscricoes<F: FnMut(Inscricao)>(mut f: F) {
    let instantaneo = com_escalonador(|e| {
        let mut saida = [None; MAX_FIOS];
        for i in 0..MAX_FIOS {
            // O zumbi é conferido aqui, e não deduzido do estado, porque ele
            // não é um estado: é um terminado que ainda tem quem pergunte por
            // ele. Para um agente a diferença é toda — `done` some na próxima
            // volta do coletor, `zombie` fica até alguém colher, e uma lista
            // cheia de `zombie` é um processo que bifurca e não espera.
            let zumbi = e.e_zumbi(i);
            let Some(fio) = e.fios[i].as_ref() else {
                continue;
            };
            saida[i] = Some(Inscricao {
                id: fio.id.numero(),
                nome: fio.nome,
                estado: match fio.estado {
                    Estado::Reservado => "spawning",
                    Estado::Pronto => "ready",
                    Estado::Rodando => "running",
                    Estado::Esperando => "waiting",
                    Estado::Terminado if zumbi => "zombie",
                    Estado::Terminado => "done",
                },
                escalonamentos: fio.escalonamentos,
                nucleo: fio.na_cpu,
                fixo: fio.fixo,
            });
        }
        saida
    });

    for inscricao in instantaneo.into_iter().flatten() {
        f(inscricao);
    }
}

/// Quantos quanta já venceram, sem a trava do escalonador: é o que a suíte
/// lê enquanto ela mesma segura a trava — ver
/// [`com_a_trava_do_escalonador_de_teste`].
#[cfg(feature = "modo-teste")]
pub fn quantuns_vencidos() -> u64 {
    QUANTUNS_VENCIDOS.load(Ordering::Relaxed)
}

/// Roda `f` segurando a trava do escalonador, com as interrupções
/// mascaradas. Só para a suíte: é como ela prova que o tique não depende
/// dessa trava.
#[cfg(feature = "modo-teste")]
pub fn com_a_trava_do_escalonador_de_teste<R>(f: impl FnOnce() -> R) -> R {
    com_escalonador(|_| f())
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

/// Destrava o escalonador à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { ESCALONADOR.force_unlock() };
}
