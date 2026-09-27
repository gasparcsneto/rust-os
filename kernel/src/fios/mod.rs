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
    /// Esperando um filho terminar.
    ///
    /// Um fio nesta lista não é escolhido por [`Escalonador::proximo_pronto`],
    /// que é o ponto: sem isso, um pai em `esperar` seria escolhido, voltaria
    /// a perguntar, não acharia nada e cederia — queimando um quantum inteiro
    /// por volta e impedindo a máquina de ficar ociosa.
    ///
    /// Quem tira daqui é [`marcar_terminado`], chamada pelo filho ao sair. É
    /// a única transição de volta, e é por isso que ela é o lugar onde o
    /// código de saída é registrado: quem acorda o pai é o mesmo que tem o
    /// número que o pai foi esperar.
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
            espaco: None,
            descritores: crate::usuario::descritores::Tabela::nova(),
            escalonamentos: 1,
            pai: None,
            saida: None,
            colhido: false,
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
            let atual = e.atual;
            let vaga = (0..MAX_FIOS).find(|&i| {
                i != atual
                    && matches!(&e.fios[i], Some(fio)
                        if fio.estado == Estado::Terminado && !e.e_zumbi(i))
            })?;
            e.fios[vaga].take()
        });

        let Some(morto) = morto else { break };
        drop(morto);
        quantos += 1;
    }

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
    nascer(nome, Nascimento::Funcao { entrada, argumento })
}

/// Como um fio novo recebe o primeiro contexto.
///
/// As duas formas diferem só no que é escrito na pilha nova; todo o resto —
/// escolher a vaga, mapear a pilha, instalar — é idêntico, e é por isso que
/// elas compartilham [`nascer`] em vez de duplicá-lo.
enum Nascimento {
    /// Um fio do kernel, que começa entrando numa função Rust.
    Funcao {
        entrada: extern "C" fn(u64) -> !,
        argumento: u64,
    },
    /// Um filho de `fork`, que começa **retornando** da chamada de sistema que
    /// o pai fez, com o espaço de endereços que o pai lhe deu.
    Bifurcacao {
        quadro: *const core::ffi::c_void,
        espaco: crate::paginacao::Espaco,
    },
}

/// Cria um fio a partir de um quadro de usuário: o filho de um `fork`.
///
/// # Safety
///
/// `quadro` precisa apontar para o quadro de usuário da chamada de sistema em
/// curso, e `espaco` precisa ser uma cópia do espaço do fio que chamou.
pub unsafe fn bifurcar(
    nome: &'static str,
    quadro: *const core::ffi::c_void,
    espaco: crate::paginacao::Espaco,
) -> Result<IdFio, &'static str> {
    nascer(nome, Nascimento::Bifurcacao { quadro, espaco })
}

fn nascer(nome: &'static str, nascimento: Nascimento) -> Result<IdFio, &'static str> {
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
    let (vaga, ocupante_morto, herdada, pai) = com_escalonador(|e| {
        let vaga = e.vaga_livre()?;
        // O parentesco sai da mesma seção crítica que a tabela de
        // descritores, e pelo mesmo motivo: as duas descrevem a relação com
        // quem está chamando, e lê-las em momentos diferentes seria lê-las
        // de dois fios diferentes se a preempção caísse no meio.
        //
        // Só a bifurcação cria filho. `criar` faz um fio do kernel, que não
        // é de ninguém — e é isso que mantém o coletor recolhendo os fios da
        // suíte como sempre recolheu.
        let (herdada, pai) = match nascimento {
            Nascimento::Bifurcacao { .. } => match e.fios[e.atual].as_ref() {
                Some(pai) => (pai.descritores.clone(), Some(pai.id)),
                None => (Default::default(), None),
            },
            Nascimento::Funcao { .. } => (crate::usuario::descritores::Tabela::nova(), None),
        };
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
        });
        Ok::<_, &'static str>((vaga, anterior, herdada, pai))
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
        Nascimento::Funcao { entrada, argumento } => {
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
    let marcador = com_escalonador(|e| {
        e.fios[vaga].replace(Fio {
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
        })
    });
    drop(marcador);

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

    let (para, espaco): (*const Contexto, u64) = {
        let fio = e.fios[proximo].as_mut().expect("vaga conferida acima");
        fio.estado = Estado::Rodando;
        fio.escalonamentos += 1;
        (&fio.contexto, fio.raiz())
    };

    e.atual = proximo;
    // Quem entra recebe uma fatia inteira, mesmo que a troca tenha vindo de
    // uma cessão voluntária do anterior. Herdar o resto da fatia alheia faria
    // um fio que cede muito punir o seguinte.
    e.quantum = QUANTUM_EM_TIQUES;
    TROCAS.fetch_add(1, Ordering::Relaxed);

    Some(Troca { de, para, espaco })
}

/// Entrega ao fio atual o espaço de endereços em que ele vai rodar.
///
/// Devolve o espaço que estava no lugar, se havia — largá-lo aqui dentro faria
/// o `Drop` dele desmapear páginas com a trava do escalonador na mão, e o
/// módulo inteiro evita aninhar travas por princípio. Quem chama larga o
/// resultado quando quiser.
#[must_use = "o espaco anterior precisa ser largado fora da trava"]
pub fn adotar_espaco(espaco: crate::paginacao::Espaco) -> Option<crate::paginacao::Espaco> {
    com_escalonador(|e| {
        let atual = e.atual;
        e.fios[atual].as_mut()?.espaco.replace(espaco)
    })
}

/// Cede a CPU voluntariamente.
///
/// Sem consumidor de produção hoje pelo mesmo motivo de [`criar`]: a preempção
/// dá conta sozinha do único fio que existe.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn ceder() {
    crate::arch::ceder_cpu();
}

/// O identificador do fio que está executando.
pub fn id_atual() -> u64 {
    com_escalonador(|e| e.fios[e.atual].as_ref().map(|f| f.id.numero()).unwrap_or(0))
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
    com_escalonador(|e| e.fios[e.atual].as_mut().map(|fio| f(&mut fio.descritores)))
}

/// A pilha de kernel do fio que está executando.
///
/// Usada ao entrar em userspace: é o endereço que o processador precisa
/// adotar quando uma interrupção chegar com o código do usuário rodando.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn pilha_de_kernel_atual() -> u64 {
    com_escalonador(|e| {
        e.fios[e.atual]
            .as_ref()
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
        let Some(eu) = e.fios[e.atual].as_ref().map(|f| f.id) else {
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
            let atual = e.atual;
            if let Some(fio) = e.fios[atual].as_mut() {
                fio.estado = Estado::Esperando;
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

/// O fio atual está à espera de um filho?
///
/// Só o ARM pergunta. Lá a chamada de sistema precisa distinguir "o fio saiu"
/// de "o fio espera" para decidir se recua o `ELR_EL1` e reexecuta o `svc`;
/// no x86 a chamada volta de dentro do despacho e a distinção não muda nada.
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub fn atual_esperando() -> bool {
    com_escalonador(|e| {
        e.fios[e.atual]
            .as_ref()
            .is_some_and(|f| f.estado == Estado::Esperando)
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
        e.fios[e.atual]
            .as_ref()
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
    com_escalonador(|e| {
        let atual = e.atual;
        let pai = match e.fios[atual].as_mut() {
            Some(fio) => {
                fio.estado = Estado::Terminado;
                fio.saida = saida;
                fio.pai
            }
            None => return,
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
        let Some(pai) = pai else { return };
        for fio in e.fios.iter_mut().flatten() {
            if fio.id == pai && fio.estado == Estado::Esperando {
                fio.estado = Estado::Pronto;
                break;
            }
        }
    });
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
        crate::arch::esperar_interrupcao();
    }
}

/// Contabiliza um tique do timer e decide se é hora de preemptar.
///
/// Chamada de dentro do handler do timer, antes de ele retornar.
pub fn tique() -> bool {
    if CONGELADO.load(Ordering::SeqCst) {
        return false;
    }

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

/// Destrava o escalonador à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { ESCALONADOR.force_unlock() };
}
