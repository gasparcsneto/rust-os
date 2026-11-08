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

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

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

/// O nome dos fios que hospedam um programa — os que `usuario` lança e os
/// que eles bifurcam. É por ele que o escalonador separa um processo de um
/// fio do kernel: só um processo é alvo de `process.isolate`, conta na cota
/// de processos de um papel e aparece em `process.list`.
pub const NOME_DO_PROCESSO: &str = "usuario";

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
    /// Terminou. A vaga volta a ser escolhível só quando o coletor recolhe
    /// o fio, depois de soltar a morte dele — ver [`recolher_terminados`].
    Terminado,
}

/// Onde está a limpeza da morte de um fio — o que [`limpar_a_morte`]
/// solta fora dele.
///
/// Três estados, e não um "já limpo": entre a passada dos zumbis marcar um
/// zumbi e terminar de soltar a morte dele, fora da trava, o pai pode
/// colhê-lo — ou morrer —, e o fio deixa de ser zumbi. Outro coletor que o
/// recolhesse nesse intervalo, achando a limpeza feita, devolveria a vaga
/// com a morte ainda no meio. Com a limpeza em curso, o recolhimento passa
/// por ele, e ele sai numa passada seguinte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Limpeza {
    /// Ninguém começou: quem recolher o fio a faz.
    Devida,
    /// A passada dos zumbis está soltando a morte, fora da trava: ninguém
    /// recolhe o fio até ela acabar.
    EmCurso,
    /// Feita: o recolhimento não a repete.
    Feita,
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
    /// o fio — quando o coletor recolhe a vaga, o `Fio` antigo é largado e o
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
    /// porque o `Fio` é largado quando o coletor recolhe a vaga; e
    /// `bifurcar` a **herda**, porque bifurcar copia o fio.
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
    /// continua ocupada, com o código de saída guardado para uma pergunta
    /// que ainda não foi feita — e com o espaço de endereços e a pilha, que
    /// vão embora com a vaga. O que a morte solta fora do fio já saiu: ver
    /// [`limpeza`](Fio::limpeza) e [`recolher_terminados`].
    colhido: bool,
    /// Onde está a limpeza da morte: a malha — os endpoints, o que
    /// esperava neles, as entregas, as designações e as janelas —, os
    /// fluxos, os pedidos ao enlace e a janela das mensagens (ver
    /// [`limpar_a_morte`]). Mudada só pelo coletor, sob a trava: a passada
    /// dos zumbis a põe em curso e, depois de soltar, feita — a morte, e não
    /// a colheita, é o fim do processo (a DF-1) —; o recolhimento faz a
    /// devida, e não repete a feita.
    limpeza: Limpeza,
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
    /// seção crítica, e só por quem põe o fio nesse estado — ou, sem
    /// estacionar, por [`ceder_e_reexecutar`], junto com o pedido de vez: a
    /// chamada que não pôde seguir agora e ainda não mudou nada.
    reexecutar: bool,
    /// A chamada de sistema em curso pediu a vez para outro fio ao voltar —
    /// ver [`pedir_cessao`]. Posto e tirado pelo próprio fio, dentro da
    /// mesma chamada.
    ceder_ao_voltar: bool,
    /// O pedido do processo pela interface nativa — ver [`crate::nativo`].
    pedido: EstadoDoPedido,
    /// O programa que o fio executa — ver [`crate::autorizacao::Programa`].
    /// Trocado junto com o espaço de endereços, em [`adotar_imagem`]: a
    /// imagem nova nunca roda com o manifesto da anterior.
    programa: crate::autorizacao::Programa,
    /// `process.terminate` pediu o fim deste processo, e ele ainda não
    /// chegou a um ponto seguro — ver [`pedir_termino`].
    ///
    /// # Por que um pedido, e não a morte na hora
    ///
    /// Porque quem pede está em outro fio, talvez em outro núcleo, e o
    /// processo pode estar no meio de uma chamada de sistema — com a trava
    /// do disco, da pilha ou do registro na mão. Marcá-lo como terminado
    /// ali largaria a trava com um dono morto. Os pontos seguros são os de
    /// [`terminar_se_pedido`]: a entrada e a volta de uma chamada de
    /// sistema, e uma interrupção que o pega no anel do usuário — onde ele
    /// não segura nada do kernel. Um processo que só gira, sem chamada
    /// nenhuma, morre no tique seguinte do núcleo dele.
    terminar: bool,
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
    /// Onde começa a busca do próximo morto a recolher: a vaga seguinte à
    /// do último que o recolhimento tirou da tabela. Ver "A ordem do
    /// recolhimento" em [`recolher_terminados`].
    cursor_do_recolhimento: usize,
}

static ESCALONADOR: Mutex<Escalonador> = Mutex::new(Escalonador {
    fios: [const { None }; MAX_FIOS],
    atual: [None; MAX_NUCLEOS],
    anterior: [None; MAX_NUCLEOS],
    ociosos: [None; MAX_NUCLEOS],
    ligado: false,
    cursor_do_recolhimento: 0,
});

static PROXIMO_ID: AtomicU64 = AtomicU64::new(1);

/// Só para a suíte: o id do próximo fio — o de um processo lançado agora,
/// se nenhum outro fio nascer antes.
#[cfg(feature = "modo-teste")]
pub fn proximo_id_de_teste() -> u64 {
    PROXIMO_ID.load(Ordering::Relaxed)
}

/// Só para a suíte: o próximo fio nasce com id `minimo`, pelo menos — o
/// número de um processo de produção, com os dígitos que ele tem depois
/// de o sistema rodar um tempo, para o caso que depende do tamanho do
/// número rodar igual numa rodada filtrada. Os ids só crescem: pular
/// adiante não repete nenhum.
#[cfg(feature = "modo-teste")]
pub fn saltar_ids_de_teste(minimo: u64) {
    PROXIMO_ID.fetch_max(minimo, Ordering::Relaxed);
}

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

/// Faz quem criou um processo esperar esse tanto de tiques logo depois de
/// pô-lo para rodar.
///
/// Existe só para a suíte, pelo mesmo motivo de [`CEDER_AO_ESCOLHER_VAGA`]:
/// o nascimento vai para a auditoria antes de o filho poder rodar — ver
/// `nasceu` em [`criar_processo`] —, e um nascimento gravado depois seria
/// passado pelo primeiro pedido do filho só se o filho corresse antes de
/// quem o criou terminar a chamada, o que quase nunca acontece sozinho.
/// Com a espera, o filho corre noutro núcleo — e a ordem certa tem quem a
/// confira.
///
/// Uma espera ocupada, e não uma cessão: quem cria pode estar numa chamada
/// de sistema — o `fork` —, e no ARM uma chamada de sistema é um handler de
/// exceção, de onde não se cede (ver `arch::aarch64::contexto::ceder_cpu`).
#[cfg(feature = "modo-teste")]
pub static ESPERAR_DEPOIS_DE_NASCER: AtomicU64 = AtomicU64::new(0);
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
            limpeza: Limpeza::Devida,
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
            ceder_ao_voltar: false,
            pedido: EstadoDoPedido::Livre,
            programa: crate::autorizacao::Programa::Kernel,
            terminar: false,
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
        // Não é fatal: sem coletor, a vaga de cada morto fica com ele — o
        // espaço, a pilha e a morte que ele não soltou —, porque só o
        // coletor devolve vaga de morto (ver `vaga_livre`). A máquina sobe,
        // e os fios novos vão sendo recusados conforme a tabela enche de
        // mortos, com o motivo de sempre: não há vaga. Recusar o boot
        // trocaria esse esgotamento lento, e dito no log, por uma máquina
        // que não sobe. No boot a tabela está vazia, e o que faria a criação
        // falhar aqui é a memória da pilha do coletor.
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
/// do timer, que já ia acontecer de qualquer forma. A latência entre um fio
/// morrer e o espaço dele voltar ao alocador passa a ser um tique, com o
/// núcleo livre — mais, com os núcleos ocupados.
///
/// Mas dormir **só** quando não há mais ninguém — ver
/// [`descansar_ate_a_interrupcao`]. Um coletor que dormia de vez com outros
/// fios prontos no mesmo núcleo continuava dono dele: cada tique o acordava
/// sem vencer o quantum, e ele voltava a dormir até o quinto. Com um núcleo
/// só, eram cinquenta milissegundos parados a cada volta do rodízio.
///
/// E uma passada por tique, no máximo: cedendo, ele volta a cada volta do
/// rodízio, e com fios que cedem muito isso seria muitas passadas por tique
/// — mais do que dormindo, que é o ritmo para o qual elas foram escritas.
extern "C" fn coletor(_argumento: u64) -> ! {
    let mut ultima_passada = None;
    loop {
        let agora = crate::tempo::ticks();
        if ultima_passada != Some(agora) {
            ultima_passada = Some(agora);
            passada_do_coletor();
        }
        descansar_ate_a_interrupcao();
    }
}

/// O que o coletor faz a cada tique.
fn passada_do_coletor() {
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
    // E as mensagens vencidas, também sem ninguém pedir — e as entregas da
    // malha.
    crate::mensagens::vencer_todos();
    crate::malha::vencer_todos();
    crate::enlace::vencer_todos();
    // E os fluxos: o prazo do aceite, a inatividade, o desligamento.
    crate::fluxo::passada_do_coletor();
    // E os avisos da malha que o canal cheio deixou devidos, e os que uma
    // operação recusada espaçou.
    crate::aviso::passada_do_coletor();
    // E a cerimônia de pareamento: os prazos dela, a sessão que acabou e
    // o desligamento — e a acabada que ninguém precisa mais sai.
    crate::pareamento::passada_do_coletor();
    // E a auditoria que nenhum registro levou ainda vai ao journal, de
    // tempos em tempos: as leituras e as recusas não mudam estado, e
    // não têm registro próprio.
    crate::persistencia::gravar_auditoria_se_preciso();
    // E a região do journal que encheu é compactada aqui: o coletor
    // não está no meio de operação nenhuma.
    crate::persistencia::compactar_se_preciso();
    // E as conexões de rede de quem acabou — o processo, a sessão —, como
    // as camadas de um processo morto.
    crate::rede::conexoes::recolher_orfas();
    // E o que o canal do agente por TCP deixou: a sessão de uma conexão
    // que acabou, a recusa de um aperto que venceu o prazo. A pilha não
    // pode esperar um disco, e o coletor pode — ver `rede::canal`.
    crate::rede::canal::atender_pendencias();
}

/// Há outro fio que este núcleo poderia rodar agora?
///
/// A mesma escolha de [`selecionar`], sem trocar: é a pergunta de quem não
/// tem o que fazer até a próxima interrupção — ver
/// [`descansar_ate_a_interrupcao`].
pub fn ha_outro_pronto() -> bool {
    com_escalonador(|e| {
        e.ligado && e.atual[nucleo()].is_some() && e.proximo_pronto(nucleo()).is_some()
    })
}

/// Para um fio sem o que fazer até a próxima interrupção: dá a vez a quem
/// estiver pronto neste núcleo, e só dorme se não houver ninguém.
///
/// # Por que não basta dormir
///
/// Porque quem dorme com `esperar_interrupcao` continua sendo o fio atual.
/// O tique o acorda, desconta um do quantum e devolve a ele — e ele dorme de
/// novo, até o quantum vencer. Um fio ocioso no rodízio segurava o núcleo
/// por uma fatia inteira com outros esperando; com um núcleo só, o caso
/// "usuario: varios processos cedem em varios nucleos" levava cinquenta
/// milissegundos por volta, e o executor e o coletor faziam o mesmo a
/// qualquer processo de usuário. Com vários núcleos os outros escondiam.
///
/// # A janela entre a pergunta e o sono
///
/// Um fio que fica pronto depois da pergunta espera o próximo tique — a
/// mesma latência que dormir sempre tinha. O [`acordar`] só cutuca núcleos
/// no ocioso, e este não está.
pub fn descansar_ate_a_interrupcao() {
    if ha_outro_pronto() {
        ceder();
    } else {
        crate::arch::esperar_interrupcao();
    }
}

/// Roda `futuro` até o fim neste fio, fora do rodízio entre um passo e
/// outro: o fio fica esperando, como o que lê um canal de eventos vazio, e
/// quem o devolve à circulação é o waker do futuro — o tique de um prazo, o
/// evento de uma conexão —, que o [`acordar`]ia.
///
/// # Por que não descansar
///
/// Quem descansa ([`descansar_ate_a_interrupcao`]) continua pronto: o
/// núcleo dele não vai para o ocioso, e o [`acordar`] não o cutuca. Com mais
/// fios descansando que núcleos, sempre há um pronto, e eles se revezam sem
/// parar: nenhum núcleo dorme, o emulador gira os processadores inteiros, e
/// quem tem trabalho de verdade espera na volta do rodízio. Medido na
/// fumaça do ARM, com quatro núcleos: o fio do serviço de hora descansando
/// era o quinto, e cada `video.sample` passou de 210 ms a 500 ms.
///
/// # O aviso que chega antes do sono
///
/// O evento pode chegar entre o `Pending` e o fio sair de circulação, e o
/// [`acordar`] dele acharia o fio ainda rodando. O waker marca o
/// [`Sinal`] antes de acordar, e o fio só sai de circulação, com a trava do
/// escalonador na mão, se a marca não estiver lá — e então o [`acordar`],
/// que toma a mesma trava, o acha esperando.
///
/// # Quem volta da cessão, volta rodando
///
/// O primeiro núcleo não tem ocioso — o fio do boot faz as vezes dele —, e
/// quem estaciona ali sem mais ninguém pronto não sai do núcleo: a escolha o
/// deixa correr, ainda esperando, e o laço confere o futuro de novo. Ele
/// pode ficar pronto nessa conferência sem que o waker tenha passado: o
/// prazo que o tique de outro núcleo venceu antes de o tique deste acordar
/// os dormentes — e o `Dormir` pronto já devolveu a vaga dele na tabela;
/// ninguém mais o acorda. Marcado esperando, ele saía de circulação para
/// sempre na primeira troca: a de saída, que o primeiro conserto fechou (a
/// suíte parou assim no CI do ARM, no fio dela, que é o do boot, na rodada
/// de hora com as três fontes mudas), e a do quantum que vencia entre a
/// conferência e a volta a `Rodando`, com outro fio pronto no núcleo (o fio
/// da bancada de hora sumiu assim no CI do ARM, em release).
///
/// Então o fio só fica marcado esperando entre estacionar — com a trava na
/// mão, e o waker do `Pending` registrado — e a troca: quem volta da cessão,
/// trocado ou não, volta rodando antes de conferir o futuro de novo. Uma
/// troca no meio do caminho o tira esperando com o waker no lugar, e o waker
/// o devolve.
///
/// Não se chama com trava na mão nem com as interrupções mascaradas: o fio
/// sai do núcleo. Antes de o escalonador ligar, o futuro é conferido a cada
/// interrupção.
pub fn bloquear_em<F: core::future::Future>(futuro: F) -> F::Output {
    use core::task::{Context, Poll, Waker};
    let sinal = alloc::sync::Arc::new(Sinal {
        fio: id_atual(),
        acordado: core::sync::atomic::AtomicBool::new(false),
    });
    let waker = Waker::from(alloc::sync::Arc::clone(&sinal));
    let mut contexto = Context::from_waker(&waker);
    let mut futuro = core::pin::pin!(futuro);
    loop {
        if let Poll::Ready(valor) = futuro.as_mut().poll(&mut contexto) {
            return valor;
        }
        let estacionou = com_escalonador(|e| {
            if !e.ligado || sinal.acordado.swap(false, Ordering::AcqRel) {
                return false;
            }
            e.fio_atual_mut()
                .map(|f| f.estado = Estado::Esperando)
                .is_some()
        });
        if estacionou {
            ceder();
            // Ver "Quem volta da cessão, volta rodando": esperando, se não
            // saiu do núcleo; pronto, se o waker passou com ele ainda nele.
            com_escalonador(|e| {
                if let Some(f) = e
                    .fio_atual_mut()
                    .filter(|f| matches!(f.estado, Estado::Esperando | Estado::Pronto))
                {
                    f.estado = Estado::Rodando;
                }
            });
        } else if !LIGADO.load(Ordering::Acquire) {
            descansar_ate_a_interrupcao();
        }
    }
}

/// O waker de [`bloquear_em`]: marca, e devolve o fio à circulação.
struct Sinal {
    fio: u64,
    acordado: core::sync::atomic::AtomicBool,
}

impl alloc::task::Wake for Sinal {
    fn wake(self: alloc::sync::Arc<Self>) {
        self.wake_by_ref();
    }

    /// Por referência: o tique acorda os dormentes de dentro do handler, e
    /// ali nenhum `Arc` deve chegar a zero.
    fn wake_by_ref(self: &alloc::sync::Arc<Self>) {
        self.acordado.store(true, Ordering::Release);
        acordar(self.fio);
    }
}

/// Tira da tabela os fios que já terminaram e devolve o que eles ocupavam:
/// a pilha de kernel, e o espaço de endereços quando havia um. Antes, solta
/// o que a morte dos zumbis solta fora do fio — ver abaixo.
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
/// # O zumbi já morreu
///
/// O que fica do zumbi é o código de saída — e a vaga, a pilha e o espaço
/// de endereços, que saem com ela. O resto da morte não espera a colheita:
/// a malha, os fluxos, o enlace e as mensagens dele ([`limpar_a_morte`])
/// saem na primeira passada depois de ele largar o núcleo, como os de um
/// morto sem pai — a DF-1 diz que a morte encerra o fluxo, e a outra ponta
/// não pode ficar esperando um pai que talvez nunca pergunte. Uma vez só:
/// a passada põe a limpeza do zumbi em curso ([`Fio::limpeza`]) sob a
/// trava, solta fora dela, e a dá por feita sob a trava de novo; o
/// recolhimento, quando o pai colher, não solta outra vez. As superfícies,
/// o pseudo-terminal, os canais de eventos, as conexões de rede e a
/// contenção já saíam na morte: perguntam por [`vivo`], que dá o zumbi por
/// morto.
///
/// # A vaga só volta depois da limpeza
///
/// Só este recolhimento tira um morto da tabela, e ele devolve a vaga
/// depois de soltar a morte: até lá a vaga fica com o morto, ou com o
/// marcador que a reserva durante a desmontagem. Um fio que nasce escolhe
/// só vaga vazia ([`Escalonador::vaga_livre`]). Quando um fio que nasce
/// podia ficar com a vaga de um morto ainda não limpo — o filho que o pai
/// acabou de colher, antes da passada —, largava o morto sem a limpeza, e
/// o que a morte dele devia soltar ficava para sempre: a designação do
/// endpoint sobrou assim no caso `sdk: o programa de fora do repositorio,
/// selado, instalado e rodado` (CI 445 e 447).
///
/// E a limpeza em curso numa passada dos zumbis segura a vaga mesmo que o
/// fio deixe de ser zumbi no meio — o pai colheu, ou morreu: o recolhimento
/// de outro coletor passa por ele (ver [`Limpeza`]). Só a suíte chama esta
/// função de fora do coletor, mas chama ao mesmo tempo que ele.
///
/// A parte que **não** é opcional é o pai morto liberar o filho. Sem ela, um
/// processo que bifurca e sai sem esperar deixa o filho ocupando uma vaga
/// da tabela para sempre, com o espaço de endereços dele junto. É o
/// vazamento que o coletor existe para impedir, de volta por outra porta.
///
/// # A vaga do fio atual nunca entra
///
/// Um fio que chamou [`terminar`] **segue executando** até ceder a vez,
/// sobre a própria pilha de kernel. Recolhê-lo ali seria desmapear o chão
/// de quem está de pé nele — e, devolvida a vaga, a próxima troca salvaria
/// o contexto do moribundo por cima do de quem a ocupasse.
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
/// a trava do escalonador e o larga fora dela — a mesma coreografia de todo
/// fio deste módulo, e pelos mesmos dois motivos.
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
///
/// # O teto de cada passada
///
/// Uma chamada recolhe no máximo [`MAX_FIOS`] mortos, e limpa no máximo
/// outros tantos zumbis; o resto fica para a passada seguinte. Todo morto
/// passa por aqui — só este recolhimento devolve a vaga de um morto —, e um
/// fio que faz nascer e morrer outros sem parar, em outro núcleo, mantinha
/// o laço com um morto novo a cada volta: medido na suíte, com um fio do
/// kernel criando fios que saem na hora, uma passada só durou os 300 tiques
/// da medida e recolheu 1324 mortos, e nesse tempo o resto da passada do
/// coletor — a auditoria ao journal, a compactação, os prazos — esperou. O
/// teto é a tabela inteira, mais do que os mortos que cabem nela.
///
/// # A ordem do recolhimento
///
/// A busca do próximo morto começa num cursor — a vaga seguinte à do último
/// recolhido — e dá a volta pela tabela ([`Escalonador::proximo_a_recolher`]).
/// Começava sempre na vaga 0, e o nascimento toma a primeira vaga vazia
/// ([`Escalonador::vaga_livre`]): um titular que bifurca, sai e colhe em
/// laço repunha os mortos dele nas vagas de baixo que o recolhimento acabava
/// de esvaziar, e, se os repusesse tão depressa quanto o coletor os
/// recolhia, os mortos de outro titular, em vagas mais altas, esperavam
/// enquanto o laço durasse — e, com a cota contando os mortos até o
/// recolhimento (a 14.1, alternativa 1), a cota desse outro ficava cheia. Era
/// o achado A1-1.
///
/// Com o cursor, um morto que pode sair espera no máximo uma volta da
/// tabela — menos de [`MAX_FIOS`] recolhimentos —, faça o laço o que fizer:
/// o cursor só anda para a frente, e passa por uma vaga sem recolher só se o
/// morto dela ainda não pode sair (no núcleo, zumbi, ou com a limpeza em
/// curso noutro coletor). Antes de chegar à vaga dele, cada recolhimento
/// tira um morto de uma vaga entre o cursor e a dele, e cada vaga uma vez
/// só: a vaga recolhida fica atrás do cursor, e a busca só volta a ela
/// depois de passar pela dele — o fio que nascer ali, como o do laço que
/// repõe o morto na vaga que o recolhimento acabou de esvaziar, espera a
/// volta. Na passada do coletor, que recolhe até a tabela inteira,
/// isso quer dizer: o morto que já pode sair quando o recolhimento da
/// passada começa sai nela; o que fica pronto no meio dela, com o cursor já
/// depois da vaga dele, sai no máximo na seguinte. Quando a passada roda
/// depende do rodízio, em que o coletor não tem prioridade — como antes.
///
/// O cursor mora na tabela, sob a mesma trava: é lido e avançado na mesma
/// seção crítica que tira o morto, e dois coletores ao mesmo tempo — a suíte
/// e o do kernel — o dividem sem trava nova. Qualquer vaga em que ele pare é
/// segura — ele é guardado sempre módulo [`MAX_FIOS`] —: ele só escolhe por
/// onde a busca começa, e a regra de quem pode sair é a de sempre.
///
/// A passada dos zumbis ([`limpar_os_zumbis`]) segue pela ordem das vagas,
/// sem cursor: ela não esvazia vaga nenhuma — o zumbi fica na dele, com o
/// código de saída —, e cada zumbi é limpo uma vez só. Com um coletor só,
/// como em produção, nenhuma vaga se esvazia enquanto ela corre: os zumbis
/// que nascem durante ela só tomam vagas que já estavam vazias, e ela
/// limpa, antes de acabar, todos os zumbis da tabela que já largaram o
/// núcleo, os de todo titular.
pub fn recolher_terminados() -> usize {
    #[cfg(feature = "modo-teste")]
    let _recolhendo = Recolhendo::entrar();
    #[cfg(feature = "modo-teste")]
    if SEGURAR_O_COLETOR.load(Ordering::SeqCst) {
        return 0;
    }
    passada_do_recolhimento()
}

/// O corpo de [`recolher_terminados`], sem a guarda da suíte: a morte dos
/// zumbis, os mortos a partir do cursor — até a tabela inteira — e as
/// camadas órfãs. Devolve quantos mortos saíram.
fn passada_do_recolhimento() -> usize {
    // A morte dos zumbis primeiro: o que eles soltam fora do fio sai já, e
    // o código de saída fica até a colheita.
    limpar_os_zumbis();

    let mut quantos = 0;
    while quantos < MAX_FIOS && recolher_um().is_some() {
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

/// Um recolhimento: tira da tabela o próximo morto — a partir do cursor, ver
/// "A ordem do recolhimento" em [`recolher_terminados`] —, o desmonta fora
/// da trava, solta a morte dele se ainda é devida, e só então devolve a
/// vaga. A vaga e o id do morto, ou `None` se nenhum podia sair.
fn recolher_um() -> Option<(usize, u64)> {
    let (vaga, id, morto) = com_escalonador(|e| {
        let vaga = e.proximo_a_recolher()?;
        let morto = e.fios[vaga].take()?;
        // O cursor passa para depois da vaga recolhida, na mesma seção
        // crítica: o próximo recolhimento — deste coletor ou de outro —
        // começa ali.
        e.cursor_do_recolhimento = (vaga + 1) % MAX_FIOS;
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
            nome: NOME_DO_MARCADOR,
            estado: Estado::Reservado,
            contexto: Contexto::vazio(),
            _pilha: None,
            espaco: None,
            descritores: crate::usuario::descritores::Tabela::nova(),
            escalonamentos: 0,
            pai: None,
            saida: None,
            colhido: true,
            limpeza: Limpeza::Feita,
            autoridade: crate::autorizacao::Autoridade::NENHUMA,
            na_cpu: None,
            fixo: None,
            ocioso: false,
            reexecutar: false,
            ceder_ao_voltar: false,
            pedido: EstadoDoPedido::Livre,
            programa: crate::autorizacao::Programa::Kernel,
            terminar: false,
        });
        let id = e.fios[vaga].as_ref().map(|f| f.id)?;
        Some((vaga, id, morto))
    })?;

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
    let do_morto = morto.id.numero();
    // O zumbi que o pai colheu já soltou a morte dele: uma vez só. A em
    // curso não chega aqui — a busca passa por ela.
    let devida = morto.limpeza == Limpeza::Devida;
    drop(morto);
    if devida {
        limpar_a_morte(politica::mensagens::Canal::Processo(do_morto));
    }
    // Só agora a vaga volta a ser escolhível: com a morte solta. O
    // marcador sai sob a trava e é largado fora dela, como todo fio
    // deste módulo.
    let marcador = com_escalonador(|e| match &e.fios[vaga] {
        Some(f) if f.id == id && f.estado == Estado::Reservado => e.fios[vaga].take(),
        _ => None,
    });
    drop(marcador);
    Some((vaga, do_morto))
}

/// O nome do marcador que guarda a vaga de um morto enquanto o
/// recolhimento o desmonta e solta a morte dele ([`recolher_terminados`]).
const NOME_DO_MARCADOR: &str = "recolhendo";

/// O que a morte de um processo solta fora do fio, fora da trava do
/// escalonador: a janela de nonces dele, se mandou mensagens pela interface
/// nativa — o id não se repete, e a janela não serviria a mais ninguém —; e
/// a malha: os endpoints dele fecham, com o que esperava neles, os fluxos
/// de que ele é ponta acabam (`o processo acabou`), os pedidos dele a
/// outros dispositivos saem, e as designações e as janelas também (ver
/// `malha::canal_acabou`). Chamada uma vez por fio: pela passada dos
/// zumbis ([`limpar_os_zumbis`]) ou pelo recolhimento — e, nos dois, antes
/// de a vaga dele voltar a ser escolhível.
fn limpar_a_morte(canal: politica::mensagens::Canal) {
    #[cfg(feature = "modo-teste")]
    if let politica::mensagens::Canal::Processo(id) = canal {
        antes_da_limpeza(id);
    }
    crate::mensagens::canal_acabou(canal);
    crate::malha::canal_acabou(canal);
    #[cfg(feature = "modo-teste")]
    if let politica::mensagens::Canal::Processo(id) = canal {
        depois_da_limpeza(id);
    }
}

/// A morte dos zumbis: cada fio terminado, fora de todo núcleo, que o pai
/// ainda pode colher e cuja morte ainda é devida tem a limpeza posta em
/// curso ([`Fio::limpeza`]) sob a trava — um de cada vez, como o
/// recolhimento —, a morte dele sai fora dela ([`limpar_a_morte`]), e a
/// limpeza é dada por feita sob a trava de novo. O fio fica na tabela, com
/// o código de saída. Devolve quantos.
///
/// Fora de todo núcleo pela regra do recolhimento: um fio que acabou de se
/// marcar terminado ainda roda, no kernel, até ceder a vez — e só depois
/// disso nada mais dele pede coisa alguma.
///
/// Entre pôr em curso e dar por feita, o fio fica na vaga mesmo que deixe
/// de ser zumbi: nenhum fio que nasce a escolhe — ela não está vazia —, e o
/// recolhimento de outro coletor passa por ele (ver [`Limpeza`]).
fn limpar_os_zumbis() -> usize {
    let mut quantos = 0;
    // O teto: ver o de `recolher_terminados`.
    while quantos < MAX_FIOS {
        let achado = com_escalonador(|e| {
            let vaga = (0..MAX_FIOS).find(|&i| {
                matches!(&e.fios[i], Some(fio)
                        if fio.estado == Estado::Terminado
                            && fio.na_cpu.is_none()
                            && fio.limpeza == Limpeza::Devida
                            && e.e_zumbi(i))
            })?;
            let fio = e.fios[vaga].as_mut()?;
            fio.limpeza = Limpeza::EmCurso;
            Some((vaga, fio.id))
        });
        let Some((vaga, id)) = achado else {
            break;
        };
        limpar_a_morte(politica::mensagens::Canal::Processo(id.numero()));
        com_escalonador(|e| {
            if let Some(fio) = e.fios[vaga].as_mut().filter(|f| f.id == id) {
                fio.limpeza = Limpeza::Feita;
            }
        });
        quantos += 1;
    }
    quantos
}

/// Segura o coletor: com ela ligada, [`recolher_terminados`] volta sem
/// fazer nada — nem a passada dos zumbis, nem o recolhimento; o resto da
/// passada do coletor segue. Ver [`segurar_o_coletor_de_teste`].
///
/// Existe só para a suíte, pelo motivo de [`CEDER_AO_ESCOLHER_VAGA`]: a
/// janela entre a morte de um processo — ou a colheita dele — e a passada
/// seguinte do coletor dura um tique quando ele ganha a vez — mais, com os
/// núcleos ocupados —, e um nascimento só cai nela por acaso. Na CI 445,
/// caiu.
#[cfg(feature = "modo-teste")]
static SEGURAR_O_COLETOR: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Quantos recolhimentos estão em curso — contados antes de olhar
/// [`SEGURAR_O_COLETOR`], para quem segura saber que nenhum começado antes
/// ainda corre.
#[cfg(feature = "modo-teste")]
static RECOLHENDO: AtomicUsize = AtomicUsize::new(0);

/// Um recolhimento em curso, contado em [`RECOLHENDO`] até sair.
#[cfg(feature = "modo-teste")]
struct Recolhendo;

#[cfg(feature = "modo-teste")]
impl Recolhendo {
    fn entrar() -> Self {
        RECOLHENDO.fetch_add(1, Ordering::SeqCst);
        Recolhendo
    }
}

#[cfg(feature = "modo-teste")]
impl Drop for Recolhendo {
    fn drop(&mut self) {
        RECOLHENDO.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Segura o coletor e espera o recolhimento em curso, se há um, acabar: daí
/// em diante nenhum morto sai da tabela, nem tem a morte solta, até
/// [`soltar_o_coletor_de_teste`]. Não se chama com a limpeza pausada
/// ([`PAUSAR_NA_LIMPEZA`]): o recolhimento pausado não acabaria.
#[cfg(feature = "modo-teste")]
pub fn segurar_o_coletor_de_teste() {
    SEGURAR_O_COLETOR.store(true, Ordering::SeqCst);
    while RECOLHENDO.load(Ordering::SeqCst) != 0 {
        ceder();
    }
}

/// Solta o coletor de [`segurar_o_coletor_de_teste`].
#[cfg(feature = "modo-teste")]
pub fn soltar_o_coletor_de_teste() {
    SEGURAR_O_COLETOR.store(false, Ordering::SeqCst);
}

/// Um recolhimento só, mesmo com o coletor segurado: a vaga e o id do morto
/// que saiu, ou `None`. É o passo com que os casos `recolhimento:` alternam
/// o coletor e o laço de outro titular, um de cada vez — sem o tique, que
/// decide sozinho quem anda primeiro. Contado em `RECOLHENDO`, como o do
/// coletor: quem segura o coletor espera também por ele. Não se chama com
/// uma pausa armada ([`PAUSAR_NA_DESMONTAGEM`], [`PAUSAR_NA_LIMPEZA`]): quem
/// chama a tomaria e giraria nela.
#[cfg(feature = "modo-teste")]
pub fn recolher_um_de_teste() -> Option<(usize, u64)> {
    let _recolhendo = Recolhendo::entrar();
    recolher_um()
}

/// Uma passada inteira do recolhimento, a de produção, mesmo com o coletor
/// segurado: o caso `recolhimento: a passada recolhe a partir do cursor`
/// confere nela, e não só no passo, a ordem do cursor e que ela recolhe
/// todos os mortos que podem sair. Contada em `RECOLHENDO`, e sem pausa
/// armada, como [`recolher_um_de_teste`].
#[cfg(feature = "modo-teste")]
pub fn recolher_terminados_de_teste() -> usize {
    let _recolhendo = Recolhendo::entrar();
    passada_do_recolhimento()
}

/// O cursor do recolhimento: a vaga em que a próxima busca começa.
#[cfg(feature = "modo-teste")]
pub fn cursor_do_recolhimento_de_teste() -> usize {
    com_escalonador(|e| e.cursor_do_recolhimento)
}

/// Põe o cursor do recolhimento em `vaga`: o caso começa a busca de onde
/// quer. Qualquer valor é seguro — o cursor só escolhe por onde a busca
/// começa.
#[cfg(feature = "modo-teste")]
pub fn por_o_cursor_de_teste(vaga: usize) {
    com_escalonador(|e| e.cursor_do_recolhimento = vaga % MAX_FIOS);
}

/// Segura a limpeza da morte do primeiro vigiado ([`vigiar_a_limpeza`]) no
/// começo, antes de soltar qualquer coisa: armada ([`PAUSA_ARMADA`]), o
/// coletor que chega à limpeza dele a toma ([`PAUSA_SEGURANDO`]) e gira até
/// a suíte a devolver a zero. É a janela em que a vaga não pode voltar.
#[cfg(feature = "modo-teste")]
pub static PAUSAR_NA_LIMPEZA: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Quantos processos a suíte vigia de uma vez — mais que a tabela inteira,
/// para o caso que faz nascer e morrer muitos ao mesmo tempo.
#[cfg(feature = "modo-teste")]
const VIGIAS: usize = 512;

/// Os processos cujas limpezas da morte a suíte conta — ver
/// [`vigiar_a_limpeza`] e [`vigiar_tambem`] —, cada um como o id mais um:
/// zero é a posição vazia, e o vetor começa no `.bss`, fora do arquivo do
/// kernel.
#[cfg(feature = "modo-teste")]
static VIGIADOS: [AtomicU64; VIGIAS] = [const { AtomicU64::new(0) }; VIGIAS];

/// Quantas vezes a morte de cada vigiado foi solta.
#[cfg(feature = "modo-teste")]
static LIMPEZAS: [AtomicU64; VIGIAS] = [const { AtomicU64::new(0) }; VIGIAS];

/// Quantas posições de [`VIGIADOS`] já foram dadas.
#[cfg(feature = "modo-teste")]
static VIGIAS_DADAS: AtomicUsize = AtomicUsize::new(0);

/// A limpeza do processo `id` começa: segura, se ele é o primeiro vigiado e
/// a pausa está armada.
#[cfg(feature = "modo-teste")]
fn antes_da_limpeza(id: u64) {
    if VIGIADOS[0].load(Ordering::SeqCst) == id.wrapping_add(1)
        && PAUSAR_NA_LIMPEZA
            .compare_exchange(
                PAUSA_ARMADA,
                PAUSA_SEGURANDO,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    {
        while PAUSAR_NA_LIMPEZA.load(Ordering::SeqCst) == PAUSA_SEGURANDO {
            core::hint::spin_loop();
        }
    }
}

/// A limpeza do processo `id` acabou: conta, se ele é vigiado.
#[cfg(feature = "modo-teste")]
fn depois_da_limpeza(id: u64) {
    let dadas = VIGIAS_DADAS.load(Ordering::SeqCst).min(VIGIAS);
    for i in 0..dadas {
        if VIGIADOS[i].load(Ordering::SeqCst) == id.wrapping_add(1) {
            LIMPEZAS[i].fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// A suíte passa a contar quantas vezes a morte do processo `id` é solta
/// pelo coletor — a passada dos zumbis ou o recolhimento: uma vez só. Os
/// vigiados de antes saem; `u64::MAX` só os tira.
#[cfg(feature = "modo-teste")]
pub fn vigiar_a_limpeza(id: u64) {
    VIGIAS_DADAS.store(0, Ordering::SeqCst);
    for i in 0..VIGIAS {
        VIGIADOS[i].store(0, Ordering::SeqCst);
        LIMPEZAS[i].store(0, Ordering::SeqCst);
    }
    if id != u64::MAX {
        vigiar_tambem(id);
    }
}

/// Mais um vigiado, sem tirar os outros. Falso se não cabe.
#[cfg(feature = "modo-teste")]
pub fn vigiar_tambem(id: u64) -> bool {
    let i = VIGIAS_DADAS.fetch_add(1, Ordering::SeqCst);
    if i >= VIGIAS {
        return false;
    }
    LIMPEZAS[i].store(0, Ordering::SeqCst);
    VIGIADOS[i].store(id.wrapping_add(1), Ordering::SeqCst);
    true
}

/// Quantas vezes a morte do primeiro vigiado foi solta desde
/// [`vigiar_a_limpeza`].
#[cfg(feature = "modo-teste")]
pub fn limpezas_vigiadas() -> u64 {
    LIMPEZAS[0].load(Ordering::SeqCst)
}

/// O vigiado da posição `i` e quantas vezes a morte dele foi solta; `None`
/// passado do último dado.
#[cfg(feature = "modo-teste")]
pub fn vigiado_de_teste(i: usize) -> Option<(u64, u64)> {
    if i >= VIGIAS_DADAS.load(Ordering::SeqCst).min(VIGIAS) {
        return None;
    }
    let id = VIGIADOS[i].load(Ordering::SeqCst).checked_sub(1)?;
    Some((id, LIMPEZAS[i].load(Ordering::SeqCst)))
}

/// Quantas vezes a morte do vigiado `id` foi solta; `None` se ele não é
/// vigiado.
#[cfg(feature = "modo-teste")]
pub fn limpezas_de(id: u64) -> Option<u64> {
    let mut i = 0;
    while let Some((vigiado, limpezas)) = vigiado_de_teste(i) {
        if vigiado == id {
            return Some(limpezas);
        }
        i += 1;
    }
    None
}

/// Quantos marcadores do recolhimento há na tabela: a vaga de um morto que
/// o coletor tirou e ainda desmonta, ou cuja morte ainda solta. Achados
/// pelo nome ([`NOME_DO_MARCADOR`]), que nenhum outro fio tem.
#[cfg(feature = "modo-teste")]
pub fn marcadores_de_teste() -> usize {
    com_escalonador(|e| {
        let mut n = 0;
        for fio in e.fios.iter().flatten() {
            if fio.estado == Estado::Reservado && fio.nome == NOME_DO_MARCADOR {
                n += 1;
            }
        }
        n
    })
}

/// O processo `id` é um zumbi agora: terminou, e o pai — vivo — ainda não
/// o colheu.
#[cfg(feature = "modo-teste")]
pub fn zumbi_de_teste(id: u64) -> bool {
    com_escalonador(|e| {
        (0..MAX_FIOS)
            .any(|i| e.fios[i].as_ref().is_some_and(|f| f.id.numero() == id) && e.e_zumbi(i))
    })
}

/// O fio `id` ainda ocupa uma vaga — vivo, zumbi, ou terminado à espera do
/// coletor.
#[cfg(feature = "modo-teste")]
pub fn na_tabela_de_teste(id: u64) -> bool {
    com_escalonador(|e| e.fios.iter().flatten().any(|f| f.id.numero() == id))
}

/// As vagas que os processos de um titular ocupam, por categoria — a régua
/// dos casos `zumbis:`. Ver `Escalonador::ocupadas_por_categoria`.
#[cfg(feature = "modo-teste")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Categorias {
    /// Os que não terminaram: os vivos e os que estão nascendo.
    pub vivos: usize,
    /// Os terminados que o pai, vivo, ainda pode colher.
    pub zumbis: usize,
    /// Os terminados que não são zumbis — o filho colhido, o órfão, o do
    /// `user.run` —, à espera do coletor.
    pub mortos: usize,
}

/// Quantas vagas os processos com a `autoridade` ocupam agora — os vivos, os
/// que nascem, os zumbis e os mortos ainda não recolhidos —, contadas pela
/// definição, categoria por categoria, e não pela conta da cota. É a régua
/// dos casos `zumbis:`.
#[cfg(feature = "modo-teste")]
pub fn ocupadas_de_teste(autoridade: crate::autorizacao::Autoridade) -> usize {
    com_escalonador(|e| e.ocupadas_pela_definicao(autoridade))
}

/// As vagas do titular por categoria, sob a trava do escalonador.
#[cfg(feature = "modo-teste")]
pub fn ocupadas_por_categoria_de_teste(autoridade: crate::autorizacao::Autoridade) -> Categorias {
    com_escalonador(|e| e.ocupadas_por_categoria(autoridade))
}

/// As duas contas sob a mesma trava: a da cota — a que o gate e o
/// nascimento fazem — e a da definição. Têm de ser sempre iguais; os casos
/// `zumbis:` as comparam.
#[cfg(feature = "modo-teste")]
pub fn contas_da_cota_de_teste(autoridade: crate::autorizacao::Autoridade) -> (usize, usize) {
    com_escalonador(|e| {
        (
            e.processos_de(autoridade),
            e.ocupadas_pela_definicao(autoridade),
        )
    })
}

/// Quantas vagas um fio novo ainda acharia — as que `vaga_livre` daria: as
/// vazias. Só a suíte pergunta.
#[cfg(feature = "modo-teste")]
pub fn vagas_livres_de_teste() -> usize {
    com_escalonador(|e| {
        let mut n = 0;
        for f in &e.fios {
            n += f.is_none() as usize;
        }
        n
    })
}

/// A primeira vaga vazia — a que o próximo fio que nasce escolhe.
#[cfg(feature = "modo-teste")]
pub fn primeira_vaga_vazia_de_teste() -> Option<usize> {
    com_escalonador(|e| e.vaga_livre().ok())
}

/// O que a suíte olha de um fio na tabela — ver [`retrato_de_teste`].
#[cfg(feature = "modo-teste")]
#[derive(Clone, Copy)]
pub struct RetratoDeTeste {
    /// A vaga dele.
    pub vaga: usize,
    /// Terminou e largou o núcleo: o que o coletor espera para soltar a
    /// morte dele.
    pub parado: bool,
    /// A limpeza da morte dele está em curso numa passada dos zumbis.
    pub limpeza_em_curso: bool,
}

/// O fio `id`, se ele ainda ocupa uma vaga.
#[cfg(feature = "modo-teste")]
pub fn retrato_de_teste(id: u64) -> Option<RetratoDeTeste> {
    com_escalonador(|e| {
        for (vaga, f) in e.fios.iter().enumerate() {
            if let Some(f) = f
                && f.id.numero() == id
            {
                return Some(RetratoDeTeste {
                    vaga,
                    parado: f.estado == Estado::Terminado && f.na_cpu.is_none(),
                    limpeza_em_curso: f.limpeza == Limpeza::EmCurso,
                });
            }
        }
        None
    })
}

/// O primeiro filho de `pai` que terminou e largou o núcleo — colhido ou
/// não —, se há um na tabela.
#[cfg(feature = "modo-teste")]
pub fn filho_parado_de_teste(pai: u64) -> Option<u64> {
    com_escalonador(|e| {
        for f in e.fios.iter().flatten() {
            if f.pai == Some(IdFio(pai)) && f.estado == Estado::Terminado && f.na_cpu.is_none() {
                return Some(f.id.numero());
            }
        }
        None
    })
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
        &|_| {},
    )
}

/// O que [`nascer`] devolve quando a cota de processos do titular já está
/// cheia. Uma constante, e não um texto qualquer, porque quem lança precisa
/// distinguir esta recusa — que é da política, e vai para a auditoria — de
/// uma falta de vaga ou de memória.
pub const COTA_ESGOTADA: &str = "a cota de processos do papel de quem lanca esta esgotada";

/// [`criar_como`] um processo, contado na cota do titular da `autoridade`:
/// nasce só se o titular ocupar menos de `cota` vagas da tabela — com os
/// processos vivos, os que estão nascendo, os zumbis e os mortos que o
/// coletor ainda não recolheu (ver [`processos_de`]).
///
/// # Por que a cota é conferida aqui, e não só no gate
///
/// O gate ([`crate::autorizacao::permitir_processo`]) decide pela política
/// e faz a mesma conta; a vaga do fio novo é reservada depois, aqui. Com um
/// núcleo só, uma chamada de sistema rodava inteira com as interrupções
/// mascaradas, e nada acontecia entre contar e reservar. Com vários, dois
/// processos do mesmo titular bifurcam juntos, em núcleos diferentes, os
/// dois contam um a menos que a cota, e os dois nascem: a cota passa a ser
/// um teto que se ultrapassa por um a cada núcleo. Contar de novo **na
/// mesma seção crítica que reserva a vaga** fecha a janela: o fio reservado
/// já é contado, e quem conta depois o vê.
///
/// `nasceu` é chamada com o fio já certo de nascer e antes de ele poder
/// rodar, fora de qualquer trava — o lugar de gravar o nascimento na
/// auditoria: o primeiro pedido do processo nunca chega antes do registro
/// que diz quem o lançou.
pub fn criar_processo(
    nome: &'static str,
    entrada: extern "C" fn(u64) -> !,
    argumento: u64,
    autoridade: crate::autorizacao::Autoridade,
    cota: usize,
    nasceu: &dyn Fn(IdFio),
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
        nasceu,
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
        &|_| {},
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
/// [`criar_processo`], também para `nasceu`.
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
    nasceu: &dyn Fn(IdFio),
) -> Result<IdFio, &'static str> {
    nascer(
        nome,
        Nascimento::Bifurcacao { quadro, espaco },
        Some(cota),
        nasceu,
    )
}

/// Faz nascer um fio. Com `cota`, ele é um processo, e nasce só se o
/// titular da autoridade dele ocupar menos que isso da tabela — os vivos,
/// os que estão nascendo, os zumbis e os mortos ainda não recolhidos; ver
/// [`criar_processo`], também para `nasceu`.
fn nascer(
    nome: &'static str,
    nascimento: Nascimento,
    cota: Option<usize>,
    nasceu: &dyn Fn(IdFio),
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
    // Cada chamada ainda custava uma vaga da tabela de fios e um espaço de
    // endereços que ninguém iria liberar.
    if CONGELADO.load(Ordering::SeqCst) {
        return Err("o escalonador esta congelado apos uma falha fatal");
    }

    // Mapear a pilha nova acontece **fora** da trava do escalonador, por
    // ordem de travas: mapear toma as da paginação e do alocador de frames,
    // e fazê-lo com a do escalonador na mão, e com as interrupções
    // mascaradas, as aninharia. Aninhar travas é o começo de todo deadlock;
    // manter a ordem trivial é mais barato que provar que a ordem é segura.
    //
    // A vaga é sempre uma vazia ([`Escalonador::vaga_livre`]): o fio morto
    // que a ocupava já foi recolhido pelo coletor — desmontado fora da
    // trava, e com a morte solta. Nascer não tira morto nenhum da tabela.
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
    let (vaga, herdada, pai, autoridade, fixo, programa) = com_escalonador(|e| {
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
            limpeza: Limpeza::Devida,
            autoridade,
            na_cpu: None,
            fixo,
            ocioso: false,
            reexecutar: false,
            ceder_ao_voltar: false,
            pedido: EstadoDoPedido::Livre,
            programa,
            terminar: false,
        });
        Ok::<_, &'static str>((vaga, herdada, pai, autoridade, fixo, programa))
    })?;

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

    // Daqui em diante o fio nasce — nada mais falha —, e ainda não pode
    // rodar: a vaga está reservada. É o momento de quem lançou dizer que
    // ele nasceu, fora de qualquer trava.
    nasceu(id);

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
            limpeza: Limpeza::Devida,
            autoridade,
            na_cpu: None,
            fixo,
            ocioso: false,
            reexecutar: false,
            ceder_ao_voltar: false,
            pedido: EstadoDoPedido::Livre,
            programa,
            terminar: false,
        });
        (marcador, e.nucleos_ociosos())
    });
    drop(marcador);
    // Um fio novo está pronto: um núcleo dormindo pode pegá-lo agora, em vez
    // de no próximo tique dele.
    crate::nucleos::cutucar(ociosos);

    // Ponto de espera só para testes: o filho corre noutro núcleo antes de
    // quem o criou voltar — ver `ESPERAR_DEPOIS_DE_NASCER`. O teto de voltas
    // é para um núcleo só, em que o relógio pode não andar.
    #[cfg(feature = "modo-teste")]
    if cota.is_some() {
        let tiques = ESPERAR_DEPOIS_DE_NASCER.load(Ordering::Relaxed);
        if tiques > 0 {
            let ate = crate::tempo::ticks().saturating_add(tiques);
            let mut voltas = 0u64;
            while crate::tempo::ticks() < ate && voltas < 20_000_000 {
                core::hint::spin_loop();
                voltas += 1;
            }
        }
    }

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
    // Uma vaga vazia, como a de todo fio que nasce: ver `nascer`.
    let vaga = com_escalonador(|e| {
        let vaga = e.vaga_livre()?;
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
            limpeza: Limpeza::Devida,
            autoridade: crate::autorizacao::Autoridade::Sistema,
            na_cpu: None,
            fixo: Some(cpu),
            ocioso: true,
            reexecutar: false,
            ceder_ao_voltar: false,
            pedido: EstadoDoPedido::Livre,
            programa: crate::autorizacao::Programa::Kernel,
            terminar: false,
        });
        Ok::<_, &'static str>(vaga)
    })?;

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
    /// Os processos com a `autoridade` que contam na cota de processos do
    /// papel: toda vaga que um processo do titular ocupa na tabela — o vivo,
    /// o que está nascendo (um fio reservado já conta), o zumbi e o morto
    /// que não é zumbi: o filho colhido, o órfão, o do `user.run` —, até o
    /// coletor recolher o morto. Ver [`processos_de`].
    ///
    /// # Por que todo morto conta
    ///
    /// A cota limita o que o titular ocupa da tabela, e não só o que ainda
    /// roda — a decisão 14.1. O zumbi guarda a vaga até a colheita (ver
    /// [`Self::e_zumbi`]), e contar só os vivos deixava um programa que
    /// bifurca e não colhe ocupar a tabela inteira. Mas a vaga de um morto só
    /// volta pelo coletor, depois de soltar a morte dele
    /// ([`Self::vaga_livre`]), e o morto que não é zumbi também a guarda até
    /// a passada. Contando só os vivos, os que nascem e os zumbis, um
    /// programa que bifurca, sai e colhe em laço passava pela cota a cada
    /// filho colhido e, fazendo morrer mais depressa do que o coletor
    /// recolhe, enchia a tabela: daí em diante não nascia fio de ninguém,
    /// nem o do `system.reboot` (o achado A1 do adversário da correção da
    /// vaga do morto). Por isso a conta é de vagas — a alternativa 1 da
    /// decisão sobre o A1, de 8 de novembro de 2026. O preço é de quem
    /// bifurca e colhe depressa: o filho colhido conta até o coletor o
    /// recolher, e a cota recusa até lá.
    ///
    /// # Sem perguntar pelo pai
    ///
    /// O zumbi e o morto que não é zumbi contam do mesmo jeito, e a conta
    /// não pergunta a [`Self::e_zumbi`]: uma volta pela tabela, sem pedir
    /// memória, no caminho de todo `bifurcar` e de todo lançamento. A suíte
    /// confere a conta contra a definição, categoria por categoria (a régua
    /// `ocupadas_por_categoria`, que só existe no modo de teste).
    ///
    /// # O marcador do coletor
    ///
    /// Enquanto o coletor solta a morte de um morto, o morto já saiu da
    /// tabela, e a vaga dele guarda um marcador de ninguém
    /// ([`recolher_terminados`]), que não conta: durante uma limpeza, o
    /// titular pode ocupar uma vaga a mais que a cota — uma por recolhedor.
    fn processos_de(&self, autoridade: crate::autorizacao::Autoridade) -> usize {
        self.fios
            .iter()
            .flatten()
            .filter(|f| f.nome == NOME_DO_PROCESSO && f.autoridade == autoridade)
            .count()
    }

    /// A conta de [`Self::processos_de`] pela definição, categoria por
    /// categoria: os vivos e os que nascem; os zumbis, perguntando a
    /// [`Self::e_zumbi`] por cada terminado; e os mortos que não são zumbis,
    /// até o coletor recolhê-los. Quadrática, e só da suíte — é a régua com
    /// que ela confere a conta da cota.
    #[cfg(feature = "modo-teste")]
    fn ocupadas_por_categoria(&self, autoridade: crate::autorizacao::Autoridade) -> Categorias {
        let mut c = Categorias::default();
        for i in 0..MAX_FIOS {
            let Some(f) = &self.fios[i] else {
                continue;
            };
            if f.nome != NOME_DO_PROCESSO || f.autoridade != autoridade {
                continue;
            }
            if f.estado != Estado::Terminado {
                c.vivos += 1;
            } else if self.e_zumbi(i) {
                c.zumbis += 1;
            } else {
                c.mortos += 1;
            }
        }
        c
    }

    /// A soma de [`Self::ocupadas_por_categoria`].
    #[cfg(feature = "modo-teste")]
    fn ocupadas_pela_definicao(&self, autoridade: crate::autorizacao::Autoridade) -> usize {
        let c = self.ocupadas_por_categoria(autoridade);
        c.vivos + c.zumbis + c.mortos
    }

    /// Uma vaga vazia — a primeira.
    ///
    /// # Por que a de um morto não serve
    ///
    /// Porque a vaga de um morto volta a ser vazia só pelo coletor, e ele a
    /// devolve depois de soltar a morte ([`limpar_a_morte`]): a malha, os
    /// fluxos, os pedidos ao enlace, as designações e a janela de nonces. Um
    /// fio que nascesse na vaga de um morto ainda não limpo largaria o
    /// morto sem essa limpeza, e o que ela solta ficaria para sempre — e
    /// numa corrida comum: o pai colhe o filho e bifurca o seguinte antes da
    /// passada do coletor. Medido assim na CI 445 e na 447, no caso `sdk: o
    /// programa de fora do repositorio, selado, instalado e rodado`: a
    /// variante seguinte ficou com a vaga do cliente do modelo colhido, e a
    /// designação do endpoint dele sobrou.
    ///
    /// Esta regra já cobre as duas que a conta tinha antes, quando a vaga
    /// de um morto servia: a do fio que um núcleo ainda usa — um fio que
    /// chamou [`terminar`] segue executando até ceder a vez, e a próxima
    /// troca salvaria o contexto dele por cima do de quem ocupasse a vaga —
    /// e a do zumbi, que guarda nela o código de saída para a colheita (ver
    /// [`Self::e_zumbi`]). O coletor respeita as duas antes de recolher.
    ///
    /// # O custo
    ///
    /// A vaga de um morto fica fora da conta até o coletor recolhê-lo, na
    /// passada seguinte dele: uma por tique em que ele ganha a vez — mais
    /// tarde, com os núcleos ocupados. Uma tabela cheia de mortos ainda não
    /// recolhidos recusa um fio novo, com o motivo de sempre, até o coletor
    /// passar. O morto que segura a vaga conta na cota do titular dele até
    /// a passada — o zumbi, e também o que não é zumbi: o colhido, o órfão,
    /// o do `user.run` (ver [`Self::processos_de`]) —, e um programa que
    /// bifurca, sai e colhe em laço ouve a recusa da cota antes de passar
    /// dela. E a conta perde a pergunta a `e_zumbi` por vaga, que era
    /// quadrática no tamanho da tabela.
    fn vaga_livre(&self) -> Result<usize, &'static str> {
        self.fios
            .iter()
            .position(|f| f.is_none())
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

    /// A vaga `i` tem um morto que o recolhimento pode tirar da tabela: um
    /// fio terminado, fora de todo núcleo, que não é zumbi e cuja limpeza não
    /// está em curso noutro coletor (ver [`Limpeza`]).
    ///
    /// `na_cpu`, e não "diferente do atual": com vários núcleos há vários
    /// atuais, e há também o fio que um núcleo acabou de largar e ainda não
    /// terminou de sair de cima da pilha dele.
    fn recolhivel(&self, i: usize) -> bool {
        matches!(&self.fios[i], Some(fio)
                if fio.estado == Estado::Terminado
                    && fio.na_cpu.is_none()
                    && fio.limpeza != Limpeza::EmCurso
                    && !self.e_zumbi(i))
    }

    /// O próximo morto que o recolhimento tira da tabela: o primeiro que
    /// pode sair a partir do cursor, dando a volta. Ver "A ordem do
    /// recolhimento" em [`recolher_terminados`].
    ///
    /// Um laço, e não um iterador encadeado: no kernel de teste de
    /// depuração do x86_64, que mora perto do teto do iniciador, cada
    /// adaptador genérico vira código e um nome comprido na tabela de
    /// símbolos.
    fn proximo_a_recolher(&self) -> Option<usize> {
        for passo in 0..MAX_FIOS {
            let i = (self.cursor_do_recolhimento + passo) % MAX_FIOS;
            if self.recolhivel(i) {
                return Some(i);
            }
        }
        None
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

/// Só para a suíte: roda `f` com o programa do fio que executa trocado por
/// `programa`, e põe o de antes de volta. É o fio da suíte pedindo como
/// pediria um processo daquele programa — pela mesma `autorizar_processo`
/// de uma chamada de sistema —, sem precisar de um processo que peça no
/// instante exato em que o caso muda a política.
#[cfg(feature = "modo-teste")]
pub fn com_programa_de_teste<R>(
    programa: crate::autorizacao::Programa,
    f: impl FnOnce() -> R,
) -> R {
    let antes = com_escalonador(|e| {
        e.fio_atual_mut()
            .map(|fio| core::mem::replace(&mut fio.programa, programa))
    });
    let r = f();
    if let Some(antes) = antes {
        com_escalonador(|e| {
            if let Some(fio) = e.fio_atual_mut() {
                fio.programa = antes;
            }
        });
    }
    r
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
#[track_caller]
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

/// Como [`com_descritores`], com a tabela do processo `id` — vivo — em vez
/// da do fio que executa: para o executor, que roda o comando de um processo
/// em nome dele e precisa resolver um descritor dele (o `notify` do aviso da
/// malha). As mesmas regras: `f` roda com a trava do escalonador na mão.
pub fn com_descritores_de<R>(
    id: u64,
    f: impl FnOnce(&mut crate::usuario::descritores::Tabela) -> R,
) -> Option<R> {
    com_escalonador(|e| {
        e.fios
            .iter_mut()
            .flatten()
            .find(|fio| fio.id.numero() == id && fio.estado != Estado::Terminado)
            .map(|fio| f(&mut fio.descritores))
    })
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

/// A chamada de sistema `ceder`: o fio dá a vez **ao voltar** da chamada,
/// e não de dentro dela.
///
/// # Por que não ceder aqui mesmo
///
/// No x86 daria certo: a chamada roda numa cadeia comum sobre a pilha de
/// kernel do fio, e o fio voltaria aqui. No ARM não: a chamada roda dentro
/// do handler de exceção, na pilha de exceção **do núcleo**, e ceder daqui
/// é um `svc` aninhado que salva o fio no meio do handler, com os quadros
/// dele naquela pilha. Retomado noutro núcleo, ele voltava pela pilha de
/// exceção deste — o CI viu a leitura logo acima do topo da do núcleo 1 —,
/// e no mesmo núcleo, depois de outro fio ter feito igual, pelos quadros do
/// outro, devolvendo ao processo o quadro de usuário alheio.
///
/// Então a chamada só pede, e quem atende é o backend, onde ele já troca de
/// fio: no ARM sobre o quadro de fora — o do usuário —, como a preempção;
/// no x86 cedendo de `despachar_chamada`, que roda na pilha do fio. Ver
/// [`tirar_cessao`], e `arch::aarch64::contexto::ceder_cpu`, que recusa ser
/// chamada de dentro de um handler.
pub fn pedir_cessao() {
    com_escalonador(|e| {
        if let Some(fio) = e.fio_atual_mut() {
            fio.ceder_ao_voltar = true;
        }
    });
}

/// A chamada de sistema que acabou de rodar pediu para dar a vez? Responde
/// uma vez: a pergunta apaga o pedido. Ver [`pedir_cessao`].
pub fn tirar_cessao() -> bool {
    com_escalonador(|e| {
        e.fio_atual_mut()
            .is_some_and(|f| core::mem::take(&mut f.ceder_ao_voltar))
    })
}

/// A chamada de sistema em curso não pode seguir agora, e ainda não mudou
/// nada: o fio dá a vez ao voltar, como em [`pedir_cessao`], e a chamada
/// roda de novo quando ele voltar a ser escolhido — ver
/// [`tirar_reexecucao`]. Sem estacionar: ninguém precisa acordá-lo, ele
/// continua pronto.
///
/// É a espera de quem não pode esperar dentro do handler: a ordem das
/// gravações nas mãos de outro fio, na troca de imagem de um processo que é
/// ponta de fluxo — ver `usuario::executar` e
/// [`crate::persistencia::em_ordem_sem_esperar`]. De fora, é o laço de
/// [`crate::persistencia::em_ordem`] — ceder e tentar de novo —, e quem o
/// dá é o backend, onde ele já troca de fio: no x86, `estacionar` cede uma
/// vez e abre uma janela para as interrupções — o despacho roda mascarado —,
/// e o laço do despacho repete a chamada; no ARM, o `svc` recua e o handler
/// troca de fio sobre o quadro de fora, como na cessão, e a volta ao `svc`
/// passa por EL0 com as IRQs ligadas.
///
/// Só para a chamada que, até aqui, não mudou nada que a segunda vez refaça
/// — a regra de [`Estado::Esperando`]. O que ela já gravou na auditoria
/// fica, e diz o que houve: a troca de imagem que decidiu antes de ouvir
/// que a ordem foi para outro fio grava a execução dessa decisão — adiada
/// —, e a segunda vez decide de novo, pela política de então, numa decisão
/// sua.
pub fn ceder_e_reexecutar() {
    com_escalonador(|e| {
        if let Some(fio) = e.fio_atual_mut() {
            fio.reexecutar = true;
            fio.ceder_ao_voltar = true;
        }
    });
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

/// A autoridade e o programa do fio `id`, se ele ainda espera a resposta
/// do pedido que o executor tomou — o pedido suspenso, que vai ser
/// executado de novo com o que o fio tem agora. `None` se o fio acabou, ou
/// não tem pedido em curso.
pub fn pedido_em_curso(
    id: u64,
) -> Option<(crate::autorizacao::Autoridade, crate::autorizacao::Programa)> {
    com_escalonador(|e| {
        let fio = e
            .fios
            .iter()
            .flatten()
            .find(|f| f.id.numero() == id && f.estado != Estado::Terminado)?;
        matches!(fio.pedido, EstadoDoPedido::EmCurso).then_some((fio.autoridade, fio.programa))
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

/// Só para a suíte: quantas vezes o fio que executa já foi escolhido para
/// rodar — sem o retrato da tabela inteira de [`com_inscricoes`], que não
/// cabe na pilha de um fio no perfil de depuração.
#[cfg(feature = "modo-teste")]
pub fn escalonamentos_de_teste() -> u64 {
    com_escalonador(|e| e.fio_atual().map_or(0, |f| f.escalonamentos))
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

/// Quantos processos com esta autoridade contam na cota: toda vaga que um
/// fio que hospeda um programa — lançado por `user.run` ou pelo sistema, ou
/// bifurcado — ocupa na tabela, termine ele ou não, até o coletor recolher
/// o morto. É a conta da cota de processos do papel — ver
/// [`crate::autorizacao::permitir_processo`] e, aqui, o porquê de todo morto
/// contar, em `Escalonador::processos_de`.
pub fn processos_de(autoridade: crate::autorizacao::Autoridade) -> usize {
    com_escalonador(|e| e.processos_de(autoridade))
}

/// A autoridade de um processo vivo — um fio que hospeda um programa,
/// lançado ou bifurcado. `None` para um fio do kernel, ou um que acabou:
/// só um processo é alvo de `process.isolate`.
pub fn autoridade_do_processo(id: u64) -> Option<crate::autorizacao::Autoridade> {
    com_escalonador(|e| {
        e.fios
            .iter()
            .flatten()
            .find(|f| {
                f.id.numero() == id && f.nome == NOME_DO_PROCESSO && f.estado != Estado::Terminado
            })
            .map(|f| f.autoridade)
    })
}

/// A autoridade e o programa de um processo vivo — ver
/// [`autoridade_do_processo`]. `None` para um fio do kernel, ou um que
/// acabou.
pub fn processo(id: u64) -> Option<(crate::autorizacao::Autoridade, crate::autorizacao::Programa)> {
    com_escalonador(|e| {
        e.fios
            .iter()
            .flatten()
            .find(|f| {
                f.id.numero() == id && f.nome == NOME_DO_PROCESSO && f.estado != Estado::Terminado
            })
            .map(|f| (f.autoridade, f.programa))
    })
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

/// Os ids dos fios que existem e não terminaram — os que [`vivo`] diria
/// vivos —, escritos em `destino`; devolve quantos. Uma tomada da trava do
/// escalonador para todos: é a fotografia com que [`crate::eventos`]
/// confere os ouvintes de uma varredura inteira, em vez de uma pergunta — e
/// uma tomada — por canal.
pub fn ids_vivos(destino: &mut [u64; MAX_FIOS]) -> usize {
    com_escalonador(|e| {
        let mut quantos = 0;
        for fio in e.fios.iter().flatten() {
            if fio.estado != Estado::Terminado {
                destino[quantos] = fio.id.numero();
                quantos += 1;
            }
        }
        quantos
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
                // Um pedido de término que não chegou a um ponto seguro —
                // o processo saiu, ou morreu de falha, antes — acaba aqui:
                // morto não espera mais nada, e o contador dos pendentes
                // volta a dizer só o que falta.
                if core::mem::take(&mut fio.terminar) {
                    TERMINOS_PENDENTES.fetch_sub(1, Ordering::Relaxed);
                }
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

/// Quantos processos têm um término pedido e ainda não chegaram a um ponto
/// seguro. É a pergunta barata de [`terminar_se_pedido`]: com zero — o caso
/// de quase todo tique —, nem a trava do escalonador é tomada.
static TERMINOS_PENDENTES: AtomicUsize = AtomicUsize::new(0);

/// Quantos processos morreram por um término pedido, desde o boot.
static TERMINADOS: AtomicU64 = AtomicU64::new(0);

/// Pede o fim do processo `id`: ele morre no próximo ponto seguro — ver
/// [`Fio::terminar`] e [`terminar_se_pedido`]. Devolve o estado em que ele
/// estava; `Err` se `id` não é um processo vivo.
///
/// Um processo que espera — um filho, um evento, a resposta de um pedido —
/// volta a circular agora: é na volta da chamada que ele encontra o pedido.
/// Pedir de novo não muda nada. Os filhos dele seguem: o término é de um
/// processo, e não da árvore.
///
/// Só pela contenção, que isola antes — o `xtask` confere.
pub fn pedir_termino(id: u64) -> Result<&'static str, &'static str> {
    let (estado, ociosos) = com_escalonador(|e| -> Result<_, &'static str> {
        let fio = e
            .fios
            .iter_mut()
            .flatten()
            .find(|f| {
                f.id.numero() == id && f.nome == NOME_DO_PROCESSO && f.estado != Estado::Terminado
            })
            .ok_or("processo inexistente")?;
        let estado = match fio.estado {
            Estado::Reservado => "spawning",
            Estado::Pronto => "ready",
            Estado::Rodando => "running",
            Estado::Esperando => "waiting",
            Estado::Terminado => "zombie",
        };
        if !fio.terminar {
            fio.terminar = true;
            TERMINOS_PENDENTES.fetch_add(1, Ordering::Relaxed);
        }
        if fio.estado == Estado::Esperando {
            fio.estado = Estado::Pronto;
            return Ok((estado, e.nucleos_ociosos()));
        }
        Ok((estado, 0))
    })?;
    crate::nucleos::cutucar(ociosos);
    Ok(estado)
}

/// Se o fio atual tem um término pedido, ele termina aqui: marcado como
/// encerrado, sem código de saída — o pai colhe um morto, como o de uma
/// falha —, e quem chama tira-o de circulação como tira um que saiu.
/// Devolve se terminou.
///
/// Só nos pontos seguros: a entrada e a volta de uma chamada de sistema, e
/// uma interrupção vinda do anel do usuário. Em qualquer um deles o fio não
/// segura trava nenhuma do kernel.
pub fn terminar_se_pedido() -> bool {
    if TERMINOS_PENDENTES.load(Ordering::Relaxed) == 0 {
        return false;
    }
    let pedido = com_escalonador(|e| {
        e.fio_atual()
            .filter(|f| f.terminar && f.estado != Estado::Terminado)
            .map(|f| f.id.numero())
    });
    let Some(id) = pedido else {
        return false;
    };
    marcar_terminado(None);
    TERMINADOS.fetch_add(1, Ordering::Relaxed);
    crate::log_info!("usuario", "processo {} encerrado pelo termino pedido", id);
    true
}

/// `(pedidos ainda pendentes, processos terminados por pedido)`.
pub fn terminos() -> (usize, u64) {
    (
        TERMINOS_PENDENTES.load(Ordering::Relaxed),
        TERMINADOS.load(Ordering::Relaxed),
    )
}

/// Encerra o fio atual. Nunca retorna.
///
/// A pilha do fio **não** é liberada aqui, e não poderia ser: estamos
/// executando em cima dela. Ela sobrevive até o coletor recolher o fio
/// ([`recolher_terminados`]), que é quando o `Drop` finalmente roda — e só
/// então a vaga volta a ser escolhível.
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

/// Uma linha de `process.list`: um fio que hospeda um programa.
#[derive(Clone, Copy)]
pub struct Processo {
    pub id: u64,
    /// Quem bifurcou para criá-lo, se alguém bifurcou.
    pub pai: Option<u64>,
    pub estado: &'static str,
    /// Com que autoridade ele age: a de quem o lançou.
    pub autoridade: crate::autorizacao::Autoridade,
    /// O que ele executa — o manifesto, o resumo, o editor.
    pub programa: crate::autorizacao::Programa,
    pub escalonamentos: u64,
    pub nucleo: Option<usize>,
    /// Quantos descritores ele tem abertos.
    pub descritores: usize,
}

/// Chama `f` com cada processo, vivo ou zumbi, de um retrato tirado de uma
/// vez sob a trava do escalonador. O papel de cada um, e se está contido,
/// quem chama pergunta depois, fora da trava: as duas perguntas tomam as
/// travas do registro e da política.
///
/// # Por que um vetor reservado antes, e não um arranjo na pilha
///
/// Porque um [`Processo`] leva o programa inteiro — o manifesto, o resumo,
/// o editor —, e um arranjo de [`MAX_FIOS`] deles passa de 20 KiB: mais que
/// a pilha de um fio do kernel. Medido: a primeira versão deste retrato
/// estourou a pilha do fio da suíte, com a trava do escalonador na mão, e
/// a máquina caiu numa falha dupla. O vetor é reservado fora da trava, do
/// tamanho da tabela, e sob ela só recebe — nada se aloca lá dentro.
pub fn com_processos<F: FnMut(Processo)>(mut f: F) {
    let mut instantaneo = alloc::vec::Vec::with_capacity(MAX_FIOS);
    com_escalonador(|e| {
        for i in 0..MAX_FIOS {
            let zumbi = e.e_zumbi(i);
            let Some(fio) = e.fios[i].as_ref() else {
                continue;
            };
            // Só quem hospeda um programa, e só o vivo e o zumbi: o
            // terminado que ninguém espera some na passada do coletor. Até
            // lá ele conta na cota do titular (a alternativa 1 da 14.1), sem
            // aparecer aqui.
            if fio.nome != NOME_DO_PROCESSO || (fio.estado == Estado::Terminado && !zumbi) {
                continue;
            }
            instantaneo.push(Processo {
                id: fio.id.numero(),
                pai: fio.pai.map(IdFio::numero),
                estado: match fio.estado {
                    Estado::Reservado => "spawning",
                    Estado::Pronto => "ready",
                    Estado::Rodando => "running",
                    Estado::Esperando => "waiting",
                    Estado::Terminado => "zombie",
                },
                autoridade: fio.autoridade,
                programa: fio.programa,
                escalonamentos: fio.escalonamentos,
                nucleo: fio.na_cpu,
                descritores: fio.descritores.abertos(),
            });
        }
    });

    for processo in instantaneo {
        f(processo);
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
