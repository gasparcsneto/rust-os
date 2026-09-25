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
    /// # O adiamento, e o que ele custa agora
    ///
    /// "Quando a vaga é reaproveitada" é literal: um fio morto segura o espaço
    /// dele até outra criação escolher aquela vaga. É a mesma regra da
    /// [`pilha::Pilha`], e pelo mesmo motivo — não há fio coletor para
    /// desmontar o que é dos outros.
    ///
    /// O preço, porém, cresceu. Antes a vaga segurava uma pilha; agora segura
    /// um espaço de endereços inteiro: raiz, tabelas e todas as páginas do
    /// processo. O consumo é **limitado e estável** — no pior caso um espaço
    /// por vaga, e medindo ao vivo ele para de crescer depois da primeira
    /// volta pelas dezesseis —, mas é maior do que parece à primeira vista.
    ///
    /// Recuperar mais cedo exigiria largar o espaço no instante em que o
    /// escalonador troca para fora de um fio encerrado, e isso é trabalho de
    /// paginação com a trava do escalonador na mão — que é exatamente o que
    /// este módulo se recusa a fazer.
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
    let (vaga, ocupante_morto, herdada) = com_escalonador(|e| {
        let vaga = e.vaga_livre()?;
        let herdada = match nascimento {
            Nascimento::Bifurcacao { .. } => e.fios[e.atual]
                .as_ref()
                .map(|pai| pai.descritores.clone())
                .unwrap_or_default(),
            Nascimento::Funcao { .. } => crate::usuario::descritores::Tabela::nova(),
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
        });
        Ok::<_, &'static str>((vaga, anterior, herdada))
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
pub fn marcar_terminado() {
    com_escalonador(|e| {
        let atual = e.atual;
        if let Some(fio) = e.fios[atual].as_mut() {
            fio.estado = Estado::Terminado;
        }
    });
}

/// O fio atual já se encerrou?
pub fn atual_terminou() -> bool {
    com_escalonador(|e| {
        e.fios[e.atual]
            .as_ref()
            .is_some_and(|f| f.estado == Estado::Terminado)
    })
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
    marcar_terminado();
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
        for (destino, fio) in saida.iter_mut().zip(e.fios.iter()) {
            *destino = fio.as_ref().map(|fio| Inscricao {
                id: fio.id.numero(),
                nome: fio.nome,
                estado: match fio.estado {
                    Estado::Reservado => "spawning",
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

/// Destrava o escalonador à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { ESCALONADOR.force_unlock() };
}
