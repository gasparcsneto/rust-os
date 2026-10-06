//! O ponto único de decisão.
//!
//! # A cadeia
//!
//! ```text
//! identidade → sessão → papel → permissão → operação
//! ```
//!
//! Cada pedido que chega a uma operação protegida passa por aqui, e só por
//! aqui:
//!
//! - os comandos do canal do agente, pela serial e pelas portas
//!   ([`crate::agent`]), e os do interpretador, digitados pela pessoa ou
//!   confirmados por um agente no Terminal ([`crate::interpretador`]): os
//!   dois pedem [`autorizar`], e só o [`Autorizado`] que ela devolve chama o
//!   handler. Não há outro caminho até um handler — o `xtask` confere que a
//!   chamada `(…handler)(` só existe neste arquivo;
//! - as chamadas de sistema de um processo lançado por um agente — abrir um
//!   arquivo, executar um programa —, por [`autorizar_processo`], com a
//!   autoridade de quem o lançou;
//! - o aperto de mão das portas, pelo limite de [`permitir_aperto`];
//! - as operações administrativas, que conferem a prova e então pedem
//!   [`decidir_administracao`] com o papel do administrador.
//!
//! # Tudo vai para a auditoria
//!
//! Permitido ou não. Cada decisão vira um registro na cadeia: quem (sessão,
//! agente, chave, papel), o quê (método e recurso), o código, o BLAKE2s dos
//! parâmetros e um detalhe. Ver [`politica::auditoria`].
//!
//! # O sistema decide como os outros
//!
//! A autoridade local — os processos do sistema: o servidor de janelas, o
//! Terminal — é a máxima, e passa pela mesma conta: o papel dela é o da linha `local` da
//! política, o `sistema`, que enumera cada permissão e o alcance de cada uma.
//! Não há `ALLOW` por ser sistema. A única exceção é o boot do próprio
//! kernel, que carrega a chave, o registro e a política antes de haver o que
//! decidir — ver [`crate::identidade::carregar`] e [`carregar`] —, e esse
//! caminho não é alcançável por processo, agente, console, serial ou
//! pseudo-terminal: o `xtask` confere quem chama cada um.
//!
//! # Sem política no disco
//!
//! Se falta, ou não se lê, vale a de emergência, embutida
//! ([`politica::Politica::emergencia`]): o mesmo `sistema`, com as mesmas
//! permissões enumeradas, para a serial e a autoridade local, e o mesmo
//! `administrador`. Os outros papéis não estão nela: um agente de papel
//! `operador` ou `observador` é recusado; um de papel `sistema` continua o
//! que era — ninguém ganha nem perde papel na emergência.

use alloc::string::{String, ToString};
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::trava::Mutex;
use politica::auditoria::{Cadeia, Evento, Titular, resumo_dos_parametros};
use politica::taxa::{Balde, Janela};
use politica::{Codigo, Permissao, Politica};

use crate::agent::json::{Json, JsonWriter};
use alloc::vec::Vec;

use crate::agent::registry::{Acesso, Command, Mais};

/// Onde a política mora no disco.
pub const CAMINHO_DA_POLITICA: &str = "/etc/duke/politica";

/// Quantos registros a auditoria guarda na memória. Os que saem pela ponta
/// deixam o elo como âncora — ver [`politica::auditoria`].
pub const CAPACIDADE_DA_AUDITORIA: usize = 1024;

/// As sessões com balde: a serial e as quatro portas.
const SESSOES: usize = 1 + crate::sessoes::PORTAS;

/// A sessão que a auditoria atribui à autoridade local — a pessoa na frente
/// da máquina e os processos do sistema: ela não é uma sessão do canal.
pub const SESSAO_DA_PESSOA: u8 = u8::MAX;

static POLITICA: Mutex<Option<Politica>> = Mutex::new(None);
/// Se a política em vigor veio do disco, ou é a de emergência.
static DO_DISCO: AtomicBool = AtomicBool::new(false);
static AUDITORIA: Mutex<Option<Cadeia>> = Mutex::new(None);

/// Quantos principais têm balde ao mesmo tempo. Os agentes do registro e a
/// serial cabem com folga; passando disso, sai o balde usado há mais tempo.
const BALDES: usize = 16;

/// O balde de um principal.
///
/// # Por que do principal, e não da vaga de sessão
///
/// Era um por vaga de sessão, com a chave de quem o ocupava: uma chave nova
/// na porta ganhava um balde novo, cheio. Com programas pedindo pela
/// interface nativa, isso virava uma bomba de encher baldes: o processo de
/// um agente que já desconectou pede com a chave dele, pela vaga onde agora
/// está outro agente, e cada pedido trocava o dono — e enchia o balde — dos
/// dois. Do principal, um agente e os processos que ele lançou gastam do
/// mesmo balde, onde quer que estejam; e a mesma chave que reconecta, em
/// qualquer porta, continua com o que tinha.
#[derive(Clone, Copy)]
struct BaldeDe {
    dono: DonoDaTaxa,
    balde: Balde,
    /// Pedidos recusados por taxa desde o último registro de taxa: a
    /// auditoria grava o primeiro e soma os seguintes, para uma enxurrada
    /// não empurrar para fora do anel o que importa.
    suprimidos: u64,
    /// Quando foi usado pela última vez — para saber quem sai.
    uso_ms: u64,
}

/// De quem é um balde: o principal que pede.
///
/// Uma pessoa e o sistema não têm taxa no que pedem por si — ninguém digita
/// na velocidade de uma máquina, e o sistema não pede pelo canal. Mas um
/// **programa** por eles pede na velocidade de uma máquina, e cada decisão
/// vai para a auditoria e para o journal: o processo de uma pessoa gasta o
/// balde da sessão dela, e o do sistema, o do sistema.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DonoDaTaxa {
    /// A chave do agente, ou `None` para a serial.
    Chave(Option<[u8; 32]>),
    /// Os processos lançados na sessão desta pessoa.
    Pessoa([u8; 8]),
    /// Os processos lançados pelo sistema.
    Sistema,
}

struct Taxas {
    baldes: [Option<BaldeDe>; BALDES],
    janelas: [Janela; crate::sessoes::PORTAS],
    apertos_suprimidos: [u64; crate::sessoes::PORTAS],
}

static TAXAS: Mutex<Taxas> = Mutex::new(Taxas {
    baldes: [None; BALDES],
    janelas: [Janela::NOVA; crate::sessoes::PORTAS],
    apertos_suprimidos: [0; crate::sessoes::PORTAS],
});

/// O que roda num fio, para o gate: código do kernel, ou a imagem de um
/// programa com o manifesto dela — ver `politica::manifesto`.
///
/// A autoridade diz **por quem** um processo age; o programa diz **o que**
/// ele pode exercer dessa autoridade. A permissão efetiva de um processo é a
/// interseção do papel de quem o lançou com o manifesto: as duas perguntas
/// são feitas no mesmo ponto de decisão, e uma recusa de qualquer uma é
/// recusa.
///
/// `Copy`, como a autoridade, e pelo mesmo motivo: vai dentro de cada fio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Programa {
    /// Um fio do kernel: não há imagem a atenuar, e quem decide é só a
    /// autoridade.
    Kernel,
    /// Um processo que ainda não carregou a imagem — o fio que
    /// `usuario::lancar` cria, antes de ler o executável. Não exerce nada.
    SemImagem,
    /// A imagem que o processo executa: o manifesto dela, se tem um — sem
    /// manifesto, não exerce nada —, e o resumo BLAKE2s do executável.
    Imagem {
        manifesto: Option<politica::manifesto::Manifesto>,
        resumo: [u8; 32],
    },
}

/// Como a auditoria diz que foi um processo: o fio e o programa.
fn pelo_processo(fio: u64, programa: &Programa) -> String {
    alloc::format!("pelo processo {fio} ({})", programa.descricao())
}

impl Programa {
    /// Se o programa declara `p`. Para um fio do kernel, sempre: o que o
    /// limita é a autoridade.
    pub fn permite(&self, p: Permissao) -> bool {
        match self {
            Programa::Kernel => true,
            Programa::SemImagem => false,
            Programa::Imagem { manifesto, .. } => manifesto.is_some_and(|m| m.permite.contem(p)),
        }
    }

    /// Como a auditoria o nomeia: o nome declarado e o começo do resumo da
    /// imagem — o nome é o que o programa diz ser, e o resumo é o que ele é.
    pub fn descricao(&self) -> String {
        match self {
            Programa::Kernel => String::from("kernel"),
            Programa::SemImagem => String::from("sem imagem"),
            Programa::Imagem { manifesto, resumo } => {
                let nome = manifesto.as_ref().map_or("sem manifesto", |m| m.nome());
                alloc::format!(
                    "{nome} {:02x}{:02x}{:02x}{:02x}",
                    resumo[0],
                    resumo[1],
                    resumo[2],
                    resumo[3]
                )
            }
        }
    }
}

/// Com que autoridade algo roda.
///
/// `Copy`, sem nada no heap: ela vai dentro de cada fio, e é copiada com a
/// trava do escalonador na mão — ver `crate::fios`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Autoridade {
    /// A autoridade local: um processo lançado pelo sistema — o servidor de
    /// janelas, o Terminal. É a máxima, e **não** é um passe livre: decide
    /// pela política como as outras, com o papel da linha `local` — o
    /// `sistema`, que enumera o que pode —, e vai para a auditoria.
    Sistema,
    /// Uma sessão do canal, e o que ela lançou: a serial (`chave` vazia) ou
    /// uma porta, com a chave de quem provou o aperto. O papel não é
    /// guardado, nem o nome: são procurados a cada decisão, para que uma
    /// revogação ou uma troca de papel valham na hora — também para o
    /// processo já lançado.
    Sessao { sessao: u8, chave: Option<[u8; 32]> },
    /// Uma pessoa, pela sessão que ela abriu num console, e o que ela
    /// lançou. Como a de um agente, o papel é procurado a cada decisão: a
    /// sessão que acaba — a pessoa sai, é revogada, o console fecha — leva
    /// junto a autoridade dos processos que ela lançou.
    Pessoa { sessao: crate::pessoas::IdSessao },
}

impl Autoridade {
    /// A menor que há: uma porta sem chave, que papel nenhum tem. Para um
    /// fio cuja origem não se lê — o que não deveria acontecer, e se
    /// acontecer, recusa tudo.
    pub const NENHUMA: Autoridade = Autoridade::Sessao {
        sessao: u8::MAX,
        chave: None,
    };
}

/// O comando em execução num fio: com que autoridade, por que canal foi
/// pedido, e — num `message.send` — para quem a decisão resolveu o
/// destino.
///
/// # Por que o fio faz parte
///
/// Porque a pergunta que isto responde — "com que autoridade o comando
/// **deste** código está rodando?" — é de um fio só. Com todo comando
/// executado pelo fio do executor, a diferença não aparecia: só havia um
/// comando de cada vez, e só quem o executava perguntava. Com vários
/// núcleos, qualquer outro fio que perguntasse durante um comando — um
/// processo, um fio do kernel em outro núcleo — receberia a autoridade de
/// **outro** principal. A resposta só vale para quem executa; os outros
/// recebem [`Autoridade::NENHUMA`], que papel nenhum tem — o lado seguro de
/// uma pergunta feita no lugar errado.
///
/// # Por que uma vaga por fio, e não uma só
///
/// Era uma só, trocada e reposta por [`como_comando`], e funcionava porque
/// todo comando rodava no fio do executor. Um processo que pede um comando
/// pelo próprio fio — a interface nativa, `docs/INTERFACE.md` — roda em
/// qualquer núcleo, ao mesmo tempo que o executor: com uma vaga só, um
/// tomaria a do outro, e o primeiro perderia a autoridade no meio do
/// comando. Cada fio tem a sua, e um fio que executa um comando dentro de
/// outro guarda a anterior e a devolve no fim.
struct EmExecucao {
    fio: u64,
    autoridade: Autoridade,
    /// Quem pediu o comando — ver [`Pedinte`].
    pedinte: Pedinte,
    destino: Option<crate::mensagens::Destino>,
    /// A decisão do gate que autorizou o comando — ver [`Decidido`]. `None`
    /// para o kernel chamando um handler direto, na suíte.
    decidido: Option<Decidido>,
    /// O anexo do pedido: bytes que vieram fora do JSON — ver
    /// [`MAIOR_ANEXO`]. O handler que o usa o tira daqui.
    anexo: Vec<u8>,
}

/// Quantas operações um lote do armazém leva, no máximo.
pub const MAIS_OPS_POR_LOTE: usize = 32;

/// O maior anexo de um pedido: o conteúdo binário que vai junto do JSON,
/// fora dele — de um processo pela chamada de sistema, de um agente pelo
/// canal. O que passa disso vai em pedaços, por um rascunho do armazém. O
/// mesmo número que os programas veem: um só, no protocolo.
pub const MAIOR_ANEXO: usize = protocolo::usuario::nativo::MAIOR_ANEXO;

/// A decisão que o gate tomou para o comando em execução: quem, como a
/// auditoria o gravou, o método e o número da decisão na cadeia.
///
/// Com ela o handler registra o que **fez** em nome do mesmo principal que
/// foi autorizado — ver [`auditar_execucao`] —, sem montar de novo quem
/// pediu: a autoridade não muda entre a decisão e a execução.
struct Decidido {
    quem: Quem,
    metodo: &'static str,
    decisao: u64,
    /// A permissão decidida — `None` numa operação por prova.
    permissao: Option<Permissao>,
    /// Os recursos decididos, crus, como o pedido os trouxe: o handler só
    /// muda o que está aqui — ver [`recurso_decidido`] —, e a reconfirmação
    /// decide de novo sobre eles — ver [`reconfirmar`].
    recursos: Vec<String>,
    /// O programa de quem pediu, se é um processo: o manifesto dele limita
    /// a reconfirmação como limitou a decisão.
    programa: Option<Programa>,
}

/// Quem pediu o comando em execução: a autoridade diz **por quem** ele
/// age; isto diz **por onde** o pedido veio.
///
/// Os dois não se confundem. Um processo lançado por um agente age com a
/// autoridade do agente — mas não é o agente: não fala pelo canal dele, não
/// guarda desafio administrativo na sessão dele, não gasta os nonces dele, e
/// não aperta o Enter no Terminal como ele.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pedinte {
    /// Uma sessão do canal: a serial ou uma porta.
    Canal(u8),
    /// Uma pessoa, no interpretador.
    Pessoa,
    /// Um processo, pela interface nativa — o identificador do fio.
    Processo(u64),
    /// O próprio kernel, chamando um handler com uma autoridade dita —
    /// só a suíte faz isso.
    #[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
    Kernel,
}

/// Uma vaga por fio que está executando um comando agora — no máximo um
/// comando por fio de cada vez, porque o aninhado guarda o anterior.
static EM_EXECUCAO: Mutex<[Option<EmExecucao>; crate::fios::MAX_FIOS]> =
    Mutex::new([const { None }; crate::fios::MAX_FIOS]);

/// Lê, da vaga deste fio, o que `f` tira dela. Fora de um comando, `None`.
fn do_comando_deste_fio<R>(f: impl FnOnce(&EmExecucao) -> R) -> Option<R> {
    let eu = crate::fios::id_atual();
    crate::arch::sem_interrupcoes(|| {
        EM_EXECUCAO
            .lock()
            .iter()
            .flatten()
            .find(|c| c.fio == eu)
            .map(f)
    })
}

/// A autoridade do comando que **este fio** está executando. Fora de um
/// comando, ou em outro fio, [`Autoridade::NENHUMA`].
pub fn autoridade_atual() -> Autoridade {
    do_comando_deste_fio(|c| c.autoridade).unwrap_or(Autoridade::NENHUMA)
}

/// A sessão do canal que pediu o comando que este fio executa — a serial
/// ou uma porta. `None` para o pedido de uma pessoa, de um processo, e fora
/// de um comando: nenhum deles fala por um canal.
pub fn sessao_do_canal() -> Option<u8> {
    match pedinte() {
        Some(Pedinte::Canal(s)) => Some(s),
        _ => None,
    }
}

/// Quem pediu o comando que este fio executa. `None` fora de um comando.
pub fn pedinte() -> Option<Pedinte> {
    do_comando_deste_fio(|c| c.pedinte)
}

/// O destinatário que a decisão de `message.send` resolveu e decidiu, para
/// o handler do comando em execução neste fio — ver
/// [`Autorizado::executar`]. O handler não resolve o destinatário de novo:
/// usa este, que é o que a política viu. `None` fora de um `message.send`
/// autorizado, e em outro fio.
pub fn destino_decidido() -> Option<crate::mensagens::Destino> {
    do_comando_deste_fio(|c| c.destino.clone()).flatten()
}

/// Roda `f` como o comando de `autoridade`, pedido por `pedinte`, neste
/// fio.
///
/// Reentrante: o que este fio estava executando é guardado e volta no fim,
/// para o caso de um comando executar outro.
fn como_comando<R>(
    autoridade: Autoridade,
    pedinte: Pedinte,
    destino: Option<crate::mensagens::Destino>,
    decidido: Option<Decidido>,
    f: impl FnOnce() -> R,
) -> R {
    let fio = crate::fios::id_atual();
    let novo = EmExecucao {
        fio,
        autoridade,
        pedinte,
        destino,
        decidido,
        anexo: Vec::new(),
    };
    // A vaga deste fio, se ele já executava um comando; senão, uma livre.
    // Não falta vaga: há uma por fio, e um fio ocupa no máximo uma.
    let (vaga, anterior) = crate::arch::sem_interrupcoes(|| {
        let mut vagas = EM_EXECUCAO.lock();
        let vaga = vagas
            .iter()
            .position(|c| c.as_ref().is_some_and(|c| c.fio == fio))
            .or_else(|| vagas.iter().position(Option::is_none));
        match vaga {
            Some(v) => (Some(v), vagas[v].replace(novo)),
            None => (None, None),
        }
    });
    let Some(vaga) = vaga else {
        // Não acontece — ver acima. Se acontecesse, o comando rodaria sem
        // vaga, e toda pergunta dele ouviria `NENHUMA`: recusa, e não a
        // autoridade de outro.
        crate::log_error!("autorizacao", "sem vaga para o comando do fio {}", fio);
        return f();
    };
    let r = f();
    let deste = crate::arch::sem_interrupcoes(|| {
        core::mem::replace(&mut EM_EXECUCAO.lock()[vaga], anterior)
    });
    // O que sai é largado fora da trava: o destino pode ter memória no heap.
    drop(deste);
    r
}

/// Só para a suíte: roda `f` como se fosse o comando de `autoridade`, fora
/// de qualquer canal.
#[cfg(feature = "modo-teste")]
pub fn como_comando_de_teste<R>(autoridade: Autoridade, f: impl FnOnce() -> R) -> R {
    // A autoridade de uma pessoa chega a um comando pelo interpretador; as
    // outras, sem canal, são o kernel chamando o handler.
    let pedinte = match autoridade {
        Autoridade::Pessoa { .. } => Pedinte::Pessoa,
        _ => Pedinte::Kernel,
    };
    como_comando(autoridade, pedinte, None, None, f)
}

/// Só para a suíte: roda `f` como o comando de `autoridade` pedido pela
/// sessão `canal` — o que o despachante do canal faz.
#[cfg(feature = "modo-teste")]
pub fn como_canal_de_teste<R>(canal: u8, autoridade: Autoridade, f: impl FnOnce() -> R) -> R {
    como_comando(autoridade, Pedinte::Canal(canal), None, None, f)
}

/// Quem está numa decisão, como a auditoria o grava.
#[derive(Clone)]
struct Quem {
    titular: Titular,
    sessao: u8,
    sessao_de_pessoa: Option<[u8; 8]>,
    agente: String,
    chave: Option<[u8; 32]>,
    papel: Option<String>,
    /// O processo que pediu, quando foi um processo — o fio e o programa
    /// que ele executa, como a auditoria os escreve (ver [`pelo_processo`]):
    /// quem responde por ele é o titular acima — quem o lançou —, e a
    /// auditoria diz também qual programa pediu.
    processo: Option<String>,
}

/// Quem está numa decisão, como a barra o mostra — ver [`crate::atividade`].
/// `None` para quem não aparece: um processo do sistema, que age por quem o
/// lançou, ou ninguém autenticado.
fn ator(quem: &Quem) -> Option<crate::atividade::Ator> {
    use crate::atividade::Ator;
    match quem.titular {
        Titular::Agente => Some(Ator::Agente {
            sessao: quem.sessao,
            chave: quem.chave?,
            nome: quem.agente.clone(),
        }),
        Titular::Serial => Some(Ator::Serial),
        // O nome, e não o identificador da auditoria: é o que a pessoa
        // reconhece na barra.
        Titular::Pessoa => {
            match crate::pessoas::sessao(crate::pessoas::IdSessao(quem.sessao_de_pessoa?)) {
                crate::pessoas::EstadoDaSessao::Ativa { nome, .. } => Some(Ator::Pessoa { nome }),
                _ => None,
            }
        }
        Titular::Administrador => Some(Ator::Administrador {
            nome: quem.agente.clone(),
        }),
        Titular::Kernel | Titular::Sistema | Titular::Anonimo => None,
    }
}

/// Conta, na atividade, o que acabou de ser permitido: `metodo`, por
/// `quem`, exercendo `permissao` — ou nenhuma, num comando por prova, cuja
/// operação conta por si quando executa.
fn contar(quem: &Quem, metodo: &'static str, permissao: Option<Permissao>) {
    let Some(ator) = ator(quem) else {
        return;
    };
    let muda = permissao.is_some_and(Permissao::muda_estado);
    crate::atividade::registrar(ator, quem.papel.as_deref().unwrap_or(""), metodo, muda);
}

/// Roda `f` com a política em vigor.
pub fn com_politica<R>(f: impl FnOnce(&Politica) -> R) -> R {
    crate::arch::sem_interrupcoes(|| match POLITICA.lock().as_ref() {
        Some(p) => f(p),
        None => f(&Politica::emergencia()),
    })
}

/// A versão da política em vigor: cresce a cada troca e a cada mudança.
///
/// Entra no conteúdo que as credenciais de um quórum provam — ver
/// [`sigilo::quorum`]: uma prova feita sob uma política não vale sob outra,
/// e uma mudança no meio de uma operação de quórum a derruba.
static VERSAO_DA_POLITICA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// A versão da política em vigor.
pub fn versao_da_politica() -> u64 {
    VERSAO_DA_POLITICA.load(Ordering::SeqCst)
}

/// Fixa a versão da política na que o journal gravou por último: ela
/// continua de onde parou, e o mesmo número nunca descreve duas políticas
/// em boots diferentes. Só o boot chama, ao reaplicar o journal.
pub fn fixar_versao_da_politica(versao: u64) {
    VERSAO_DA_POLITICA.store(versao, Ordering::SeqCst);
}

/// Põe em vigor uma política que o journal gravou — ou a de antes de uma
/// operação cuja gravação falhou. A versão não muda aqui: no boot quem a
/// fixa é [`fixar_versao_da_politica`], e num desfazer ela já mudou e
/// continua mudada, o que só derruba desafios.
pub fn restaurar_politica(p: Politica) {
    let velha = crate::arch::sem_interrupcoes(|| POLITICA.lock().replace(p));
    drop(velha);
}

/// Troca a política em vigor por outra, já validada. A troca é inteira: a
/// decisão seguinte vê a nova, e a que estava em curso já tinha decidido.
pub fn trocar_politica(nova: Politica) {
    let velha = crate::arch::sem_interrupcoes(|| {
        VERSAO_DA_POLITICA.fetch_add(1, Ordering::SeqCst);
        POLITICA.lock().replace(nova)
    });
    drop(velha);
}

/// Se a política em vigor veio do disco.
pub fn politica_do_disco() -> bool {
    DO_DISCO.load(Ordering::Relaxed)
}

/// Lê a política do disco. No boot, depois do registro de identidades.
pub fn carregar() {
    crate::arch::sem_interrupcoes(|| {
        let mut a = AUDITORIA.lock();
        if a.is_none() {
            *a = Some(Cadeia::nova(CAPACIDADE_DA_AUDITORIA));
        }
    });
    let sistema = Quem {
        titular: Titular::Kernel,
        sessao: SESSAO_DA_PESSOA,
        sessao_de_pessoa: None,
        agente: "kernel".to_string(),
        chave: None,
        papel: None,
        processo: None,
    };
    let (politica, codigo, detalhe, resumo) = match crate::vfs::ler_tudo(CAMINHO_DA_POLITICA) {
        Ok(bytes) => {
            let resumo = bytes.clone();
            match politica_que_vigora(&bytes) {
                Ok(p) => (p, Codigo::Allow, String::new(), resumo),
                Err(motivo) => (Politica::emergencia(), Codigo::DenyPolicy, motivo, resumo),
            }
        }
        Err(e) => (
            Politica::emergencia(),
            Codigo::DenyPolicy,
            e.motivo().to_string(),
            alloc::vec::Vec::new(),
        ),
    };
    let do_disco = codigo.permite();
    if do_disco {
        crate::log_info!(
            "politica",
            "{} papeis, serial como `{}`",
            politica.papeis().len(),
            politica.serial()
        );
    } else {
        crate::log_error!(
            "politica",
            "{}: {}; vale a de emergencia",
            CAMINHO_DA_POLITICA,
            detalhe
        );
    }
    DO_DISCO.store(do_disco, Ordering::Relaxed);
    trocar_politica(politica);
    auditar(
        &sistema,
        "policy.load",
        CAMINHO_DA_POLITICA,
        codigo,
        &resumo,
        &detalhe,
    );
}

/// A política que os bytes do disco descrevem, se ela pode vigorar: texto,
/// bem formada, e cumprindo os invariantes que nenhuma imagem desliga.
///
/// # O alcance ao administrador
///
/// Só o sistema e o próprio administrador o alcançam — ver
/// [`Politica::conferir_alcance_aos_administradores`]. Uma imagem cuja
/// política o dê a outro papel não sobe com ela: vale a de emergência, como
/// para uma política malformada, e a auditoria grava o motivo. Os papéis
/// protegidos são o `administrador` — o de quem tem esse papel numa sessão
/// — e os das chaves do registro de administradores, que o boot já leu.
pub(crate) fn politica_que_vigora(bytes: &[u8]) -> Result<Politica, String> {
    let texto = core::str::from_utf8(bytes).map_err(|_| "a politica nao e texto".to_string())?;
    let politica = Politica::ler(texto).map_err(|e| e.motivo())?;
    let mut protegidos = crate::identidade::papeis_dos_administradores();
    if !protegidos.iter().any(|p| p == PAPEL_DE_ADMINISTRADOR) {
        protegidos.push(PAPEL_DE_ADMINISTRADOR.to_string());
    }
    let nomes: alloc::vec::Vec<&str> = protegidos.iter().map(String::as_str).collect();
    politica.conferir_alcance_aos_administradores(&nomes)?;
    // A serial e a autoridade local exercem o papel delas: nenhum dos dois
    // pode ser um teto — ver [`e_papel_de_teto`].
    politica.conferir_tetos(&nomes)?;
    Ok(politica)
}

/// O papel de administrador que todo boot protege, mesmo sem chave de
/// administrador no registro.
const PAPEL_DE_ADMINISTRADOR: &str = "administrador";

/// Se `papel` é um **teto**: o `administrador`, ou o papel de uma chave de
/// administrador do registro.
///
/// # O teto não é posse
///
/// O papel de um administrador diz o que ele pode **delegar** — o que
/// `cabe_em` confere numa atribuição — e as operações administrativas que
/// ele pode provar. Ele não é um papel que se exerce: nenhuma sessão, de
/// agente ou de pessoa, nem a serial nem a autoridade local, decide por
/// ele. A cadeia é sempre
///
/// ```text
/// teto → permissões possíveis → política → gate → operação
/// ```
///
/// — o teto contém `fs.write` em `/armazem/compartilhado` para que o
/// operador o possa receber; quem recebe é o papel do operador, por uma
/// linha da política, e é a decisão do gate sobre aquele papel que deixa
/// a operação acontecer. Um titular que tivesse o próprio teto como papel
/// exerceria tudo o que ele representa sem linha nenhuma o conceder.
///
/// Por isso: o gate recusa a sessão cujo papel é um teto (`DENY_ROLE`), as
/// operações de atribuição recusam dar um teto a alguém, e uma política em
/// que a serial ou a autoridade local tenham um teto não vigora.
pub fn e_papel_de_teto(papel: &str) -> bool {
    papel == PAPEL_DE_ADMINISTRADOR
        || crate::identidade::papeis_dos_administradores()
            .iter()
            .any(|p| p == papel)
}

/// Se quem pede decidiria por um teto — ver [`e_papel_de_teto`].
fn papel_de_teto(quem: &Quem) -> bool {
    quem.papel.as_deref().is_some_and(e_papel_de_teto)
}

/// A decisão sobre uma sessão cujo papel é um teto.
const TETO_NAO_SE_EXERCE: (Codigo, &str) = (
    Codigo::DenyRole,
    "o papel e o teto de um administrador: delega, nao se exerce",
);

/// O maior recurso que a auditoria grava, em bytes. O recurso vem do pedido
/// — um caminho, um número —, e um pedido hostil poderia mandar um caminho
/// de quinhentos bytes para encher o anel com menos registros.
const MAIOR_RECURSO: usize = 128;

/// Corta um texto em `teto` bytes, numa fronteira de caractere.
fn cortado(texto: &str, teto: usize) -> &str {
    if texto.len() <= teto {
        return texto;
    }
    let mut fim = teto;
    while !texto.is_char_boundary(fim) {
        fim -= 1;
    }
    &texto[..fim]
}

/// Grava uma decisão na cadeia, e devolve o número dela — zero antes de a
/// cadeia existir.
///
/// O tempo é o lógico da persistência: o RTC com o piso do journal, que
/// atravessa boots sem voltar. A cadeia vai ao journal — ver
/// [`crate::persistencia`] —, e um registro com o tempo desde o boot diria
/// pouco no boot seguinte.
fn auditar(
    quem: &Quem,
    metodo: &str,
    recurso: &str,
    codigo: Codigo,
    parametros: &[u8],
    detalhe: &str,
) -> u64 {
    let recurso = cortado(recurso, MAIOR_RECURSO);
    let metodo = cortado(metodo, MAIOR_RECURSO);
    let evento = Evento {
        ts_ms: crate::persistencia::agora_ms(),
        titular: quem.titular,
        sessao: quem.sessao,
        sessao_de_pessoa: quem.sessao_de_pessoa,
        agente: quem.agente.clone(),
        chave: quem.chave,
        papel: quem.papel.clone().unwrap_or_default(),
        metodo: metodo.to_string(),
        recurso: recurso.to_string(),
        codigo,
        parametros: resumo_dos_parametros(parametros),
        detalhe: match &quem.processo {
            // O programa que pediu vai no detalhe: o titular é quem responde
            // por ele, e o formato do registro — que o journal grava — não
            // muda por isso.
            Some(pelo) if detalhe.is_empty() => pelo.clone(),
            Some(pelo) => alloc::format!("{pelo}: {detalhe}"),
            None => detalhe.to_string(),
        },
    };
    crate::arch::sem_interrupcoes(|| AUDITORIA.lock().as_mut().map_or(0, |c| c.anexar(evento)))
}

/// Roda `f` com a cadeia da auditoria.
pub fn com_auditoria<R>(f: impl FnOnce(&Cadeia) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| AUDITORIA.lock().as_ref().map(f))
}

/// Grava um feito do próprio kernel — o desfecho da abertura da
/// persistência, no boot —, em nome dele.
pub fn auditar_do_kernel(metodo: &str, recurso: &str, codigo: Codigo, detalhe: &str) -> u64 {
    let quem = Quem {
        titular: Titular::Kernel,
        sessao: SESSAO_DA_PESSOA,
        sessao_de_pessoa: None,
        agente: "kernel".to_string(),
        chave: None,
        papel: None,
        processo: None,
    };
    auditar(&quem, metodo, recurso, codigo, &[], detalhe)
}

/// Adota a cadeia que o journal refez, no boot: ela passa a ser a
/// auditoria, e o que o boot registrou antes de ler o journal continua
/// depois dela, com as sequências e os elos de lá. Ver
/// [`politica::auditoria::Cadeia::continuar_com`].
pub fn adotar_auditoria(mut do_journal: Cadeia) {
    crate::arch::sem_interrupcoes(|| {
        let mut a = AUDITORIA.lock();
        if let Some(boot) = a.as_ref() {
            do_journal.continuar_com(boot);
        }
        *a = Some(do_journal);
    });
}

/// Quem está na sessão `sessao`. `Err` com o que se sabe, se a sessão não é
/// autenticada — uma porta sem aperto completo.
fn quem_da_sessao(sessao: u8) -> Result<Quem, Quem> {
    if sessao == crate::agent::sessao::SERIAL {
        return Ok(Quem {
            titular: Titular::Serial,
            sessao,
            sessao_de_pessoa: None,
            agente: "serial".to_string(),
            chave: None,
            papel: Some(com_politica(|p| p.serial().to_string())),
            processo: None,
        });
    }
    match crate::sessoes::identidade(sessao) {
        // A chave saiu do registro depois do aperto: a revogação vale na
        // hora, mesmo que a sessão ainda não tenha sido derrubada.
        Some(id) if crate::identidade::agente(&id.chave).is_none() => Err(Quem {
            titular: Titular::Agente,
            sessao,
            sessao_de_pessoa: None,
            agente: id.nome,
            chave: Some(id.chave),
            papel: None,
            processo: None,
        }),
        Some(id) => Ok(Quem {
            titular: Titular::Agente,
            sessao,
            sessao_de_pessoa: None,
            papel: crate::identidade::papel_do_agente(&id.chave),
            agente: id.nome,
            chave: Some(id.chave),
            processo: None,
        }),
        None => Err(Quem {
            titular: Titular::Anonimo,
            sessao,
            sessao_de_pessoa: None,
            agente: String::new(),
            chave: None,
            papel: None,
            processo: None,
        }),
    }
}

/// Quem é uma sessão de pessoa, procurada agora. `Err` com o que se sabe,
/// se a sessão não vale mais.
fn quem_da_pessoa(id: crate::pessoas::IdSessao) -> Result<Quem, Quem> {
    match crate::pessoas::sessao(id) {
        crate::pessoas::EstadoDaSessao::Ativa { pessoa, papel, .. } => Ok(Quem {
            titular: Titular::Pessoa,
            sessao: SESSAO_DA_PESSOA,
            sessao_de_pessoa: Some(id.0),
            agente: pessoa.texto(),
            chave: None,
            papel: Some(papel),
            processo: None,
        }),
        _ => Err(Quem {
            titular: Titular::Anonimo,
            sessao: SESSAO_DA_PESSOA,
            sessao_de_pessoa: Some(id.0),
            agente: crate::pessoas::dona_da_sessao(id)
                .map(|p| p.texto())
                .unwrap_or_default(),
            chave: None,
            papel: None,
            processo: None,
        }),
    }
}

/// Ninguém num console: o titular de um pedido feito antes do login.
fn quem_sem_login() -> Quem {
    Quem {
        titular: Titular::Anonimo,
        sessao: SESSAO_DA_PESSOA,
        sessao_de_pessoa: None,
        agente: String::new(),
        chave: None,
        papel: None,
        processo: None,
    }
}

/// A autoridade local, com o papel que a política dá a ela agora: o dos
/// processos do sistema.
fn quem_local(agente: &str) -> Quem {
    Quem {
        titular: Titular::Sistema,
        sessao: SESSAO_DA_PESSOA,
        sessao_de_pessoa: None,
        agente: agente.to_string(),
        chave: None,
        papel: Some(com_politica(|p| p.local().to_string())),
        processo: None,
    }
}

/// Quem é uma autoridade de sessão, procurado agora: o nome e o papel do
/// registro de hoje. Uma chave revogada não tem nenhum dos dois, e o papel
/// vazio recusa.
fn quem_da_autoridade(sessao: u8, chave: Option<[u8; 32]>) -> Quem {
    match (sessao, chave) {
        (crate::agent::sessao::SERIAL, None) => Quem {
            titular: Titular::Serial,
            sessao,
            sessao_de_pessoa: None,
            agente: "serial".to_string(),
            chave: None,
            papel: Some(com_politica(|p| p.serial().to_string())),
            processo: None,
        },
        (_, Some(k)) => Quem {
            titular: Titular::Agente,
            sessao,
            sessao_de_pessoa: None,
            agente: crate::identidade::agente(&k).unwrap_or_else(|| "(revogado)".to_string()),
            chave: Some(k),
            papel: crate::identidade::papel_do_agente(&k),
            processo: None,
        },
        (_, None) => Quem {
            titular: Titular::Anonimo,
            sessao,
            sessao_de_pessoa: None,
            agente: String::new(),
            chave: None,
            papel: None,
            processo: None,
        },
    }
}

/// Gasta uma ficha do balde da sessão. `Err` se não havia. Na volta de uma
/// sequência recusada, grava quantas foram — ver [`BaldeDe::suprimidos`].
fn passar_pela_taxa(quem: &Quem, metodo: &str, parametros: &[u8]) -> Result<(), Codigo> {
    let Some(papel) = quem.papel.as_deref() else {
        // Sem papel não há taxa a aplicar: a decisão vai recusar.
        return Ok(());
    };
    let taxa = com_politica(|p| p.papel(papel).map(|r| r.taxa));
    let Some(taxa) = taxa else {
        return Ok(());
    };
    // O principal: a chave do agente, ou a serial. A pessoa e o sistema não
    // têm taxa no que pedem por si — só no que os programas deles pedem.
    // Ver [`DonoDaTaxa`].
    let dono = if usize::from(quem.sessao) < SESSOES {
        DonoDaTaxa::Chave(quem.chave)
    } else if quem.processo.is_some() {
        match quem.sessao_de_pessoa {
            Some(sessao) => DonoDaTaxa::Pessoa(sessao),
            None => DonoDaTaxa::Sistema,
        }
    } else {
        return Ok(());
    };
    let agora = crate::tempo::uptime_ms();
    let (passou, suprimidos_antes, primeiro_recusado) = crate::arch::sem_interrupcoes(|| {
        let mut t = TAXAS.lock();
        let vaga = t
            .baldes
            .iter()
            .position(|b| b.is_some_and(|b| b.dono == dono))
            .or_else(|| t.baldes.iter().position(Option::is_none))
            .unwrap_or_else(|| {
                // Todas ocupadas por outros: sai a usada há mais tempo.
                (0..BALDES)
                    .min_by_key(|&i| t.baldes[i].map_or(0, |b| b.uso_ms))
                    .unwrap_or(0)
            });
        let b = match &mut t.baldes[vaga] {
            Some(b) if b.dono == dono => b,
            outro => outro.insert(BaldeDe {
                dono,
                balde: Balde::novo(taxa, agora),
                suprimidos: 0,
                uso_ms: agora,
            }),
        };
        b.uso_ms = agora;
        // O papel mudou de taxa: um balde novo, cheio, com a de agora.
        if b.balde.taxa() != taxa {
            b.balde = Balde::novo(taxa, agora);
        }
        if b.balde.tentar(agora) {
            (true, core::mem::take(&mut b.suprimidos), false)
        } else {
            b.suprimidos += 1;
            (false, 0, b.suprimidos == 1)
        }
    });
    if passou {
        if suprimidos_antes > 1 {
            auditar(
                quem,
                metodo,
                "",
                Codigo::RateLimit,
                &[],
                &alloc::format!("{} pedidos recusados por taxa", suprimidos_antes),
            );
        }
        return Ok(());
    }
    if primeiro_recusado {
        auditar(
            quem,
            metodo,
            "",
            Codigo::RateLimit,
            parametros,
            "taxa do papel esgotada",
        );
    }
    Err(Codigo::RateLimit)
}

/// O recurso de um pedido, como texto: o valor do parâmetro que o comando
/// declarou — **cru**, exatamente como o handler o lê (`as_str`), e não
/// desescapado. A decisão tem de ser sobre o mesmo valor que a operação
/// usa: um caminho com `\u002e` decidido na forma desescapada e aberto na
/// crua seria a diferença por onde um prefixo escaparia. Um valor que não é
/// texto — um número — vai como foi escrito.
fn recurso_do_pedido(comando: &Command, params: Json) -> String {
    let Some(nome) = comando.recurso else {
        return String::new();
    };
    let Some(valor) = params.member(nome) else {
        return String::new();
    };
    match valor.as_str() {
        Some(texto) => texto.to_string(),
        None => core::str::from_utf8(valor.0)
            .unwrap_or("")
            .trim()
            .to_string(),
    }
}

/// Os recursos de um pedido além do primeiro — ver [`Mais`]: crus, como
/// [`recurso_do_pedido`]. Um parâmetro de recurso que não é texto, ou uma
/// lista que não é lista, dá um recurso vazio — que nenhuma permissão de
/// caminho alcança.
fn mais_recursos(comando: &Command, params: Json) -> Vec<String> {
    let texto = |v: Option<Json>| match v.and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => String::new(),
    };
    match comando.mais {
        Mais::Nada => Vec::new(),
        Mais::Parametro(nome) => alloc::vec![texto(params.member(nome))],
        Mais::Lote(campo) => {
            let Some(ops) = params.member(campo) else {
                return alloc::vec![String::new()];
            };
            // Até uma operação além do teto do lote: o handler recusa o lote
            // grande demais, e o gate não varre uma lista sem fim.
            let mut v = Vec::new();
            for op in (0..=MAIS_OPS_POR_LOTE).map_while(|i| ops.item(i)) {
                v.push(texto(op.member("path")));
                if op.member("to").is_some() {
                    v.push(texto(op.member("to")));
                }
            }
            if v.is_empty() {
                v.push(String::new());
            }
            v
        }
    }
}

/// Os recursos que o gate decide: o do parâmetro `recurso`, quando o
/// comando declara um, e os de [`Mais`]. Um comando sem nenhum decide o
/// recurso vazio — que nenhuma permissão de caminho alcança.
fn todos_os_recursos<'r>(
    comando: &Command,
    recurso: &'r str,
    mais: &'r [String],
) -> impl Iterator<Item = &'r str> {
    let primeiro = (comando.recurso.is_some() || mais.is_empty()).then_some(recurso);
    primeiro.into_iter().chain(mais.iter().map(String::as_str))
}

/// A decisão sobre uma permissão e um recurso, com a regra que vale para
/// todo papel: o diretório reservado do kernel não é recurso de ninguém.
fn decidir(papel: Option<&str>, permissao: Permissao, recurso: &str) -> (Codigo, &'static str) {
    if permissao.recurso_e_caminho()
        && politica::caminho::normalizar(recurso).is_some_and(|c| crate::vfs::reservado(&c))
    {
        return (Codigo::DenyResource, "reservado ao kernel");
    }
    let codigo = com_politica(|p| p.decidir(papel, permissao, Some(recurso)));
    let detalhe = match codigo {
        Codigo::DenyRole => "sem papel, ou papel que a politica nao tem",
        Codigo::DenyPermission => "o papel nao tem a permissao",
        Codigo::DenyResource => "recurso fora do alcance do papel",
        _ => "",
    };
    (codigo, detalhe)
}

/// A decisão de uma permissão cujo recurso é o papel de um destinatário —
/// `message.send`. O destinatário é resolvido aqui, e o papel dele é o
/// recurso: `papel:<nome>`, contra o alcance enumerado de quem pede.
///
/// A permissão vem antes da existência: quem não tem `message.send` ouve
/// `DENY_PERMISSION`, e não descobre se o destinatário existe. Quem tem, e
/// pede um destinatário inexistente, revogado ou sem papel, ouve
/// `DENY_RESOURCE` — o mesmo de um fora do alcance —, e a auditoria grava o
/// motivo exato. Devolve o destinatário só quando a decisão permite.
pub fn decidir_destino(
    papel: Option<&str>,
    permissao: Permissao,
    alvo: &str,
) -> (Codigo, &'static str, Option<crate::mensagens::Destino>) {
    match crate::mensagens::resolver(alvo) {
        Ok(d) => {
            let recurso = alloc::format!("{}{}", politica::arquivo::PREFIXO_DE_DESTINO, d.papel);
            let (codigo, detalhe) = decidir(papel, permissao, &recurso);
            let d = codigo.permite().then_some(d);
            (codigo, detalhe, d)
        }
        Err(motivo) => match decidir(papel, permissao, "") {
            (Codigo::DenyResource, _) => (Codigo::DenyResource, motivo, None),
            (codigo, detalhe) => (codigo, detalhe, None),
        },
    }
}

/// Quem pede um comando.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chamador {
    /// Uma sessão do canal: a serial, uma porta, ou um agente confirmando
    /// no Terminal — que age como a sessão dele.
    Sessao(u8),
    /// Uma pessoa, pela sessão que ela abriu num console.
    Pessoa(crate::pessoas::IdSessao),
    /// Um processo, pela interface nativa: o fio que pediu, a autoridade
    /// dele — a de quem o lançou — e o programa que ele executa, lidos do
    /// fio quando o pedido foi feito.
    Processo {
        fio: u64,
        autoridade: Autoridade,
        programa: Programa,
    },
}

/// Os comandos que só um canal do agente pede: os que respondem pelo
/// próprio canal. As operações por prova guardam o desafio na sessão do
/// canal; `debug.trigger` agenda a falha fatal para depois de a resposta
/// sair pelo canal — num processo, ela ficaria agendada para o próximo
/// pedido de um agente, que morreria sem saber por quê.
fn so_do_canal(comando: &Command) -> bool {
    matches!(comando.acesso, Acesso::PorProva) || comando.nome == "debug.trigger"
}

/// A licença para executar um comando: só [`autorizar`] a cria, e só ela
/// chama o handler.
pub struct Autorizado {
    comando: &'static Command,
    autoridade: Autoridade,
    /// Quem pediu.
    pedinte: Pedinte,
    /// O destinatário de um `message.send`, como a decisão o resolveu.
    destino: Option<crate::mensagens::Destino>,
    /// A decisão, para o handler registrar o que fez em nome dela.
    decidido: Decidido,
}

impl Autorizado {
    /// Executa o comando com a autoridade de quem pediu — que `user.run`,
    /// por exemplo, grava no processo que lança.
    pub fn executar(self, params: Json, w: &mut JsonWriter) -> fmt::Result {
        self.executar_com_anexo(params, Vec::new(), w)
    }

    /// [`Autorizado::executar`], com o anexo do pedido — ver
    /// [`MAIOR_ANEXO`] e [`tirar_anexo`].
    pub fn executar_com_anexo(
        self,
        params: Json,
        anexo: Vec<u8>,
        w: &mut JsonWriter,
    ) -> fmt::Result {
        let Autorizado {
            comando,
            autoridade,
            pedinte,
            destino,
            decidido,
        } = self;
        como_comando(autoridade, pedinte, destino, Some(decidido), || {
            if !anexo.is_empty() {
                por_anexo(anexo);
            }
            (comando.handler)(params, w)
        })
    }
}

/// Registra o que o comando em execução neste fio **fez** — ou por que não
/// fez depois de autorizado: o conflito de versão, o arrendamento de outro,
/// a persistência que falta —, em nome do mesmo principal que o gate
/// autorizou, com o método do comando e o número da decisão no detalhe.
/// Devolve o número do registro.
///
/// Não decide nada: a decisão foi a do gate, e esta é a execução dela. Fora
/// de um comando autorizado não registra nada e devolve zero — quem chama
/// trata zero como recusa: uma mudança sem o registro do que foi feito não
/// acontece.
pub fn auditar_execucao(recurso: &str, codigo: Codigo, detalhe: &str) -> u64 {
    let Some((quem, metodo, decisao)) = do_comando_deste_fio(|c| {
        c.decidido
            .as_ref()
            .map(|d| (d.quem.clone(), d.metodo, d.decisao))
    })
    .flatten() else {
        return 0;
    };
    let detalhe = alloc::format!("{detalhe}; decisao {decisao}");
    auditar(&quem, metodo, recurso, codigo, &[], &detalhe)
}

/// Põe o anexo na vaga do comando deste fio.
fn por_anexo(anexo: Vec<u8>) {
    let eu = crate::fios::id_atual();
    crate::arch::sem_interrupcoes(|| {
        if let Some(c) = EM_EXECUCAO
            .lock()
            .iter_mut()
            .flatten()
            .find(|c| c.fio == eu)
        {
            c.anexo = anexo;
        }
    });
}

/// O anexo do pedido do comando em execução neste fio — tirado: um comando
/// o lê uma vez. Vazio fora de um comando, ou num pedido sem anexo.
pub fn tirar_anexo() -> Vec<u8> {
    let eu = crate::fios::id_atual();
    crate::arch::sem_interrupcoes(|| {
        EM_EXECUCAO
            .lock()
            .iter_mut()
            .flatten()
            .find(|c| c.fio == eu)
            .map(|c| core::mem::take(&mut c.anexo))
            .unwrap_or_default()
    })
}

/// Se `caminho` — na forma normal — é um dos recursos que o gate decidiu
/// para o comando em execução neste fio. O handler de uma mutação confere
/// cada caminho que vai mudar: nenhuma mudança alcança um caminho que a
/// decisão não viu, por mais que o handler o tenha montado certo.
pub fn recurso_decidido(caminho: &str) -> bool {
    do_comando_deste_fio(|c| {
        c.decidido.as_ref().is_some_and(|d| {
            d.recursos
                .iter()
                .any(|r| politica::caminho::normalizar(r).as_deref() == Some(caminho))
        })
    })
    .unwrap_or(false)
}

/// Decide de novo, agora, o comando em execução neste fio — a mesma conta
/// do gate, sobre a mesma autoridade, a mesma permissão e os mesmos
/// recursos, com o registro e a política **de agora**.
///
/// # A decisão em curso
///
/// O gate decide antes de a operação começar; entre os dois, uma
/// revogação, uma troca de papel ou uma política nova podem passar. Uma
/// operação que muda estado chama isto no ponto de commit, com a ordem das
/// gravações na mão: as revogações e as mudanças de política gravam com a
/// mesma ordem, então a operação ou as vê — e recusa —, ou vem antes delas
/// inteira. Uma sessão de pessoa que acaba sem passar pela ordem (o
/// `logout`) acaba no instante em que sai do registro: a operação a vê se
/// chegar aqui depois disso.
///
/// Não grava nada: a recusa é o resultado da execução do comando que o
/// gate autorizou, e quem chama a grava assim.
pub fn reconfirmar() -> Result<(), (Codigo, &'static str)> {
    let Some((autoridade, permissao, recursos, programa)) = do_comando_deste_fio(|c| {
        c.decidido
            .as_ref()
            .map(|d| (c.autoridade, d.permissao, d.recursos.clone(), d.programa))
    })
    .flatten() else {
        return Err((Codigo::Error, "fora de um comando autorizado"));
    };
    let Some(permissao) = permissao else {
        return Ok(());
    };
    let quem = match autoridade {
        Autoridade::Sistema => quem_local("sistema"),
        Autoridade::Sessao { sessao, chave } => quem_da_autoridade(sessao, chave),
        Autoridade::Pessoa { sessao } => match quem_da_pessoa(sessao) {
            Ok(q) => q,
            Err(_) => {
                return Err((Codigo::DenyNotAuthenticated, "sessao de pessoa que acabou"));
            }
        },
    };
    if credenciada(autoridade) && crate::persistencia::revogacoes_desconhecidas().is_some() {
        return Err((
            Codigo::DenyNotAuthenticated,
            "journal recusado: as revogacoes nao se sabem",
        ));
    }
    if programa.is_some_and(|p| !p.permite(permissao)) {
        return Err((
            Codigo::DenyPermission,
            "o manifesto nao declara a permissao",
        ));
    }
    if papel_de_teto(&quem) {
        return Err(TETO_NAO_SE_EXERCE);
    }
    // A mesma conta do gate: o destinatário de uma permissão de destino é
    // resolvido de novo — o papel dele agora, e se ele ainda existe —, e um
    // caminho é decidido como caminho.
    for r in &recursos {
        let (c, d) = if permissao.recurso_e_destino() {
            let (c, d, _) = decidir_destino(quem.papel.as_deref(), permissao, r);
            (c, d)
        } else {
            decidir(quem.papel.as_deref(), permissao, r)
        };
        if !c.permite() {
            return Err((c, d));
        }
    }
    Ok(())
}

/// Só para a suíte: o que roda no ponto de commit de uma mensagem ou de uma
/// operação administrativa — com a ordem das gravações na mão — antes de a
/// decisão ser feita de novo. É onde um caso põe a revogação ou a política
/// nova "no meio" da operação.
#[cfg(feature = "modo-teste")]
static ANTES_DA_RECONFIRMACAO: Mutex<Option<fn()>> = Mutex::new(None);

/// Só para a suíte: põe (ou tira) o que roda antes da reconfirmação.
#[cfg(feature = "modo-teste")]
pub fn antes_da_reconfirmacao_de_teste(f: Option<fn()>) {
    crate::arch::sem_interrupcoes(|| *ANTES_DA_RECONFIRMACAO.lock() = f);
}

/// Só para a suíte: roda o que [`antes_da_reconfirmacao_de_teste`] pôs.
#[cfg(feature = "modo-teste")]
pub fn gancho_da_reconfirmacao() {
    if let Some(f) = crate::arch::sem_interrupcoes(|| *ANTES_DA_RECONFIRMACAO.lock()) {
        f();
    }
}

/// O dono, no armazém, de quem o comando em execução neste fio age por: a
/// identidade, e não a sessão — um agente pela chave, uma pessoa pelo
/// identificador dela, o sistema e a serial pelo nome. É quem paga a cota
/// do que grava. `None` para quem não é ninguém.
pub fn dono_no_armazem() -> Option<String> {
    match autoridade_atual() {
        Autoridade::Sistema => Some("sistema".to_string()),
        Autoridade::Sessao {
            sessao: crate::agent::sessao::SERIAL,
            chave: None,
        } => Some("serial".to_string()),
        Autoridade::Sessao { chave: Some(k), .. } => {
            Some(alloc::format!("agente:{}", sigilo::hex(&k)))
        }
        Autoridade::Sessao { chave: None, .. } => None,
        Autoridade::Pessoa { sessao } => {
            crate::pessoas::dona_da_sessao(sessao).map(|id| alloc::format!("pessoa:{}", id.texto()))
        }
    }
}

/// A cota de armazém de quem o comando em execução neste fio age por: a
/// linha `armazem` do papel dele, na política de agora. Sem papel, ou sem
/// a linha, nenhuma.
pub fn cota_no_armazem() -> ::armazem::Cota {
    let quem = match autoridade_atual() {
        Autoridade::Sistema => quem_local("sistema"),
        Autoridade::Sessao { sessao, chave } => quem_da_autoridade(sessao, chave),
        Autoridade::Pessoa { sessao } => match quem_da_pessoa(sessao) {
            Ok(q) | Err(q) => q,
        },
    };
    if papel_de_teto(&quem) {
        return ::armazem::Cota::NENHUMA;
    }
    com_politica(|p| {
        quem.papel
            .as_deref()
            .and_then(|n| p.papel(n))
            .map_or(::armazem::Cota::NENHUMA, |r| ::armazem::Cota {
                bytes: r.armazem.bytes,
                objetos: r.armazem.objetos,
            })
    })
}

/// Decide um comando. `Ok` com a licença para executá-lo; `Err` com o código
/// da recusa. A decisão vai para a auditoria nos dois casos.
pub fn autorizar(
    chamador: Chamador,
    comando: &'static Command,
    params: Json,
) -> Result<Autorizado, Codigo> {
    let parametros = params.0;
    // Quem pede, e com que autoridade o comando roda se passar. A pessoa
    // decide pelo papel dela no registro, procurado agora pela sessão — a
    // mesma conta dos agentes, e a mesma auditoria.
    let (quem, autoridade) = match chamador {
        Chamador::Pessoa(id) => match quem_da_pessoa(id) {
            Ok(q) => (q, Autoridade::Pessoa { sessao: id }),
            Err(q) => {
                auditar(
                    &q,
                    comando.nome,
                    "",
                    Codigo::DenyNotAuthenticated,
                    parametros,
                    "sessao de pessoa que acabou",
                );
                return Err(Codigo::DenyNotAuthenticated);
            }
        },
        Chamador::Processo {
            fio,
            autoridade,
            programa,
        } => {
            let mut q = quem_do_processo(autoridade);
            q.processo = Some(pelo_processo(fio, &programa));
            // Uma pessoa que saiu, ou uma chave revogada, não deixa o
            // processo dela pedir nada — como recusaria o pedido dela.
            if let Autoridade::Pessoa { sessao } = autoridade
                && quem_da_pessoa(sessao).is_err()
            {
                auditar(
                    &q,
                    comando.nome,
                    "",
                    Codigo::DenyNotAuthenticated,
                    parametros,
                    "sessao de pessoa que acabou",
                );
                return Err(Codigo::DenyNotAuthenticated);
            }
            if so_do_canal(comando) {
                auditar(
                    &q,
                    comando.nome,
                    "",
                    Codigo::DenyPermission,
                    parametros,
                    "so um canal do agente pede este comando",
                );
                return Err(Codigo::DenyPermission);
            }
            // O manifesto: o que o programa não declarou ele não exerce,
            // qualquer que seja o papel de quem o lançou.
            if let Acesso::Exige(p) = comando.acesso
                && !programa.permite(p)
            {
                auditar(
                    &q,
                    comando.nome,
                    "",
                    Codigo::DenyPermission,
                    parametros,
                    &alloc::format!("o manifesto nao declara {}", p.nome()),
                );
                return Err(Codigo::DenyPermission);
            }
            (q, autoridade)
        }
        Chamador::Sessao(sessao) => match quem_da_sessao(sessao) {
            Ok(q) => {
                let chave = q.chave;
                (q, Autoridade::Sessao { sessao, chave })
            }
            Err(q) => {
                let detalhe = if q.chave.is_some() {
                    "chave revogada"
                } else {
                    "sessao sem aperto"
                };
                auditar(
                    &q,
                    comando.nome,
                    "",
                    Codigo::DenyNotAuthenticated,
                    parametros,
                    detalhe,
                );
                return Err(Codigo::DenyNotAuthenticated);
            }
        },
    };
    // Um journal recusado: as revogações que ele perdeu não se sabem, e
    // nenhuma credencial vale — ver `persistencia::revogacoes_desconhecidas`.
    if credenciada(autoridade)
        && let Some(motivo) = crate::persistencia::revogacoes_desconhecidas()
    {
        auditar(
            &quem,
            comando.nome,
            "",
            Codigo::DenyNotAuthenticated,
            parametros,
            "journal recusado: as revogacoes nao se sabem",
        );
        crate::log_warn!("autorizacao", "credencial recusada: {}", motivo);
        return Err(Codigo::DenyNotAuthenticated);
    }
    passar_pela_taxa(&quem, comando.nome, parametros)?;

    let recurso = recurso_do_pedido(comando, params);
    // Os outros recursos do pedido — o destino de um rename, os caminhos
    // de um lote —: cada um decidido pela mesma conta, e o primeiro que
    // recusa recusa o pedido inteiro.
    let mais = mais_recursos(comando, params);
    let mut destino = None;
    let (codigo, detalhe) = match comando.acesso {
        // A prova é conferida dentro da operação, e a decisão dela é
        // gravada lá, com o papel do administrador.
        Acesso::PorProva => (Codigo::Allow, "a autorizacao e a prova"),
        Acesso::Exige(_) if papel_de_teto(&quem) => TETO_NAO_SE_EXERCE,
        Acesso::Exige(permissao) if permissao.recurso_e_destino() => {
            let (codigo, detalhe, resolvido) =
                decidir_destino(quem.papel.as_deref(), permissao, &recurso);
            destino = resolvido;
            (codigo, detalhe)
        }
        Acesso::Exige(permissao) => todos_os_recursos(comando, &recurso, &mais)
            .map(|r| decidir(quem.papel.as_deref(), permissao, r))
            .find(|(c, _)| !c.permite())
            .unwrap_or((Codigo::Allow, "")),
    };
    // O recurso da auditoria: todos, em ordem.
    let mut recurso_gravado = String::new();
    for r in todos_os_recursos(comando, &recurso, &mais) {
        if !recurso_gravado.is_empty() {
            recurso_gravado.push_str(" ; ");
        }
        recurso_gravado.push_str(r);
    }
    let decisao = auditar(
        &quem,
        comando.nome,
        &recurso_gravado,
        codigo,
        parametros,
        detalhe,
    );
    if !codigo.permite() {
        return Err(codigo);
    }
    // Depois do `ALLOW`, e só dele: quem foi recusado não agiu.
    let permissao = match comando.acesso {
        Acesso::Exige(p) => Some(p),
        Acesso::PorProva => None,
    };
    contar(&quem, comando.nome, permissao);
    let (pedinte, programa) = match chamador {
        Chamador::Sessao(s) => (Pedinte::Canal(s), None),
        Chamador::Pessoa(_) => (Pedinte::Pessoa, None),
        Chamador::Processo { fio, programa, .. } => (Pedinte::Processo(fio), Some(programa)),
    };
    let recursos: Vec<String> = todos_os_recursos(comando, &recurso, &mais)
        .map(String::from)
        .collect();
    Ok(Autorizado {
        comando,
        autoridade,
        pedinte,
        destino,
        decidido: Decidido {
            quem,
            metodo: comando.nome,
            decisao,
            permissao,
            recursos,
            programa,
        },
    })
}

/// Grava um pedido que não chegou a ser um comando: JSON quebrado, método
/// desconhecido, parâmetros recusados. `INVALID_ARGUMENT`.
///
/// Pela taxa de quem pediu, como um pedido válido: um pedido quebrado custa
/// o mesmo trabalho e o mesmo registro. Sem ela, um programa — que pede na
/// velocidade de uma máquina — enchia a auditoria e o journal de lixo, e a
/// enxurrada empurrava para fora do anel o que importa. Passada a rajada,
/// a taxa grava a primeira recusa e conta as seguintes.
pub fn auditar_invalido(chamador: Chamador, metodo: &str, parametros: &[u8], detalhe: &str) {
    let quem = match chamador {
        Chamador::Pessoa(id) => match quem_da_pessoa(id) {
            Ok(q) | Err(q) => q,
        },
        Chamador::Sessao(s) => match quem_da_sessao(s) {
            Ok(q) | Err(q) => q,
        },
        Chamador::Processo {
            fio,
            autoridade,
            programa,
        } => {
            let mut q = quem_do_processo(autoridade);
            q.processo = Some(pelo_processo(fio, &programa));
            q
        }
    };
    if passar_pela_taxa(&quem, metodo, parametros).is_err() {
        return;
    }
    auditar(
        &quem,
        metodo,
        "",
        Codigo::InvalidArgument,
        parametros,
        detalhe,
    );
}

/// Grava um registro de enchimento, como a serial e sem passar pela taxa:
/// para os casos da auditoria do journal, que precisam de muitos registros
/// — transbordar o anel, empurrar uma decisão — e não de pedidos.
#[cfg(feature = "modo-teste")]
pub fn auditar_enchimento_de_teste(metodo: &str, parametros: &[u8], detalhe: &str) {
    let quem = match quem_da_sessao(crate::agent::sessao::SERIAL) {
        Ok(q) | Err(q) => q,
    };
    auditar(
        &quem,
        metodo,
        "",
        Codigo::InvalidArgument,
        parametros,
        detalhe,
    );
}

/// Decide uma chamada de sistema de um processo: abrir um arquivo, executar
/// um programa, prender-se ao pseudo-terminal. Com a autoridade do processo,
/// que é a de quem o lançou.
///
/// Um processo do sistema — o servidor de janelas, o Terminal, o que a
/// pessoa lançou — decide pelo papel da autoridade local, e vai para a
/// auditoria como os outros: a autoridade dele é a máxima que a política
/// enumera, e não um passe livre. O de um agente decide pelo papel do
/// agente, procurado agora.
pub fn autorizar_processo(permissao: Permissao, recurso: &str, metodo: &str) -> Codigo {
    let mut quem = match crate::fios::autoridade_atual() {
        Autoridade::Sistema => quem_local("sistema"),
        Autoridade::Sessao { sessao, chave } => quem_da_autoridade(sessao, chave),
        // Uma sessão que acabou não tem papel, e o papel vazio recusa.
        Autoridade::Pessoa { sessao } => match quem_da_pessoa(sessao) {
            Ok(q) | Err(q) => q,
        },
    };
    // O programa do fio: um processo é gravado como tal, e o manifesto dele
    // limita o que a autoridade alcançaria. Um fio do kernel não tem
    // imagem a atenuar.
    let (id, programa) = crate::fios::programa_atual();
    if programa != Programa::Kernel {
        quem.processo = Some(pelo_processo(id, &programa));
    }
    let nao_declarada;
    let (codigo, detalhe) = match crate::persistencia::revogacoes_desconhecidas() {
        Some(_) if credenciada(crate::fios::autoridade_atual()) => (
            Codigo::DenyNotAuthenticated,
            "journal recusado: as revogacoes nao se sabem",
        ),
        _ if !programa.permite(permissao) => {
            nao_declarada = alloc::format!("o manifesto nao declara {}", permissao.nome());
            (Codigo::DenyPermission, nao_declarada.as_str())
        }
        _ if papel_de_teto(&quem) => TETO_NAO_SE_EXERCE,
        _ => decidir(quem.papel.as_deref(), permissao, recurso),
    };
    auditar(&quem, metodo, recurso, codigo, &[], detalhe);
    codigo
}

/// Se a autoridade vem de uma credencial que pode ter sido revogada: a
/// chave de um agente, ou uma pessoa. A serial e o `sistema` não.
fn credenciada(a: Autoridade) -> bool {
    matches!(
        a,
        Autoridade::Sessao { chave: Some(_), .. } | Autoridade::Pessoa { .. }
    )
}

/// Quem faz uma transição de mensagem, para a auditoria: a autoridade do
/// comando em execução, um titular que não está agindo — o revogado, o
/// administrador pela prova —, ou o próprio kernel, quando o prazo vence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtorDeMensagem {
    Autoridade(Autoridade),
    Dono(politica::mensagens::Dono),
    Kernel,
}

/// Grava um evento de mensagem — ver [`crate::mensagens`]. Nunca o corpo:
/// o recurso é o id, e o detalhe, o que aconteceu.
pub fn auditar_mensagem(
    ator: AtorDeMensagem,
    metodo: &str,
    recurso: &str,
    codigo: Codigo,
    detalhe: &str,
) {
    auditar(&quem_do_ator(ator), metodo, recurso, codigo, &[], detalhe);
}

/// As cotas de um envio, pela política em vigor: a de remetente do papel
/// de quem manda — resolvido como a auditoria o resolve —, e a de caixa do
/// papel do destinatário, o que a decisão resolveu.
pub fn cotas_de_mensagens(
    ator: AtorDeMensagem,
    papel_do_destinatario: &str,
) -> politica::mensagens::Cotas {
    let remetente = quem_do_ator(ator).papel;
    com_politica(|p| p.cotas_de_mensagens(remetente.as_deref(), Some(papel_do_destinatario)))
}

/// Quem é o ator de uma transição de mensagem, com o papel de agora.
fn quem_do_ator(ator: AtorDeMensagem) -> Quem {
    use politica::mensagens::Dono;
    match ator {
        AtorDeMensagem::Autoridade(Autoridade::Sistema) => quem_local("sistema"),
        AtorDeMensagem::Autoridade(Autoridade::Sessao { sessao, chave }) => {
            quem_da_autoridade(sessao, chave)
        }
        AtorDeMensagem::Autoridade(Autoridade::Pessoa { sessao }) => match quem_da_pessoa(sessao) {
            Ok(q) | Err(q) => q,
        },
        AtorDeMensagem::Dono(Dono::Serial) => {
            quem_da_autoridade(crate::agent::sessao::SERIAL, None)
        }
        AtorDeMensagem::Dono(Dono::Agente(k)) => quem_da_autoridade(SESSAO_DA_PESSOA, Some(k)),
        AtorDeMensagem::Dono(Dono::Pessoa(p)) => {
            let id = sigilo::pessoas::IdPessoa(p);
            Quem {
                titular: Titular::Pessoa,
                sessao: SESSAO_DA_PESSOA,
                sessao_de_pessoa: None,
                agente: id.texto(),
                chave: None,
                papel: crate::pessoas::pessoa(id).map(|p| p.papel),
                processo: None,
            }
        }
        AtorDeMensagem::Dono(Dono::Administrador(k)) => {
            let papel = crate::identidade::papel_do_administrador(&k);
            Quem {
                titular: Titular::Administrador,
                sessao: SESSAO_DA_PESSOA,
                sessao_de_pessoa: None,
                agente: papel.as_ref().map(|(n, _)| n.clone()).unwrap_or_default(),
                chave: Some(k),
                papel: papel.and_then(|(_, p)| p),
                processo: None,
            }
        }
        AtorDeMensagem::Kernel => Quem {
            titular: Titular::Kernel,
            sessao: SESSAO_DA_PESSOA,
            sessao_de_pessoa: None,
            agente: "kernel".to_string(),
            chave: None,
            papel: None,
            processo: None,
        },
    }
}

/// Grava um evento de arrendamento — ver [`crate::coordenacao`] —, em nome
/// de quem o tem ou o pediu: a pessoa pela sessão dela, o agente pela
/// sessão do canal e a chave. Sem titular, ninguém: uma pessoa num console
/// sem login.
pub fn auditar_arrendamento(
    titular: Option<&politica::arrendamento::Titular>,
    metodo: &str,
    recurso: &str,
    codigo: Codigo,
    detalhe: &str,
) {
    use politica::arrendamento::Titular as T;
    let quem = match titular {
        Some(T::Pessoa { sessao, .. }) => match quem_da_pessoa(crate::pessoas::IdSessao(*sessao)) {
            Ok(q) | Err(q) => q,
        },
        Some(T::Agente { sessao, chave }) => quem_da_autoridade(*sessao, *chave),
        None => quem_sem_login(),
    };
    auditar(&quem, metodo, recurso, codigo, &[], detalhe);
}

/// Recusa um pedido feito num console sem ninguém entrado: só `login` e
/// `ajuda` passam antes do login, e o resto — um comando, conhecido ou não —
/// é `DENY_NOT_AUTHENTICATED`, gravado com o console.
pub fn recusar_sem_login(console: crate::pessoas::Console, metodo: &str, parametros: &[u8]) {
    auditar(
        &quem_sem_login(),
        metodo,
        &console.texto(),
        Codigo::DenyNotAuthenticated,
        parametros,
        "ninguem entrou no console",
    );
}

/// Decide uma ação da pessoa de um console na interface — uma tecla de
/// função, um clique num botão da barra —: `ui.act` sobre o elemento, com a
/// sessão de quem está no console. Sem ninguém entrado, ou com uma sessão
/// que acabou, `DENY_NOT_AUTHENTICATED`. Grava nos dois casos.
pub fn autorizar_acao_da_pessoa(
    console: crate::pessoas::Console,
    sessao: Option<crate::pessoas::IdSessao>,
    elemento: u32,
) -> Codigo {
    let recurso = alloc::format!("{} elemento {}", console.texto(), elemento);
    let quem = match sessao.map(quem_da_pessoa) {
        Some(Ok(q)) => q,
        Some(Err(q)) => {
            auditar(
                &q,
                "ui.act",
                &recurso,
                Codigo::DenyNotAuthenticated,
                &[],
                "sessao de pessoa que acabou",
            );
            return Codigo::DenyNotAuthenticated;
        }
        None => {
            auditar(
                &quem_sem_login(),
                "ui.act",
                &recurso,
                Codigo::DenyNotAuthenticated,
                &[],
                "ninguem entrou no console",
            );
            return Codigo::DenyNotAuthenticated;
        }
    };
    let (codigo, detalhe) = if papel_de_teto(&quem) {
        TETO_NAO_SE_EXERCE
    } else {
        decidir(quem.papel.as_deref(), Permissao::UiAct, "")
    };
    auditar(&quem, "ui.act", &recurso, codigo, &[], detalhe);
    if codigo.permite() {
        contar(&quem, "ui.act", Some(Permissao::UiAct));
    }
    codigo
}

/// Pode nascer mais um processo com a autoridade `autoridade`? A cota de
/// processos vivos do papel de quem é a autoridade — a linha `processos` da
/// política —, contada por titular: uma sessão de agente, uma de pessoa, o
/// sistema. Sem papel, nada nasce. Uma recusa vai para a auditoria.
///
/// Devolve a cota, que quem lança passa ao escalonador: a contagem daqui é
/// a resposta rápida, e a que vale é a do nascimento, feita junto com a
/// reserva da vaga — ver [`crate::fios::criar_processo`]. Quando aquela
/// recusa, quem lança chama [`recusar_pela_cota`], e a recusa vai para a
/// auditoria do mesmo jeito.
pub fn permitir_processo(autoridade: Autoridade, metodo: &str) -> Result<usize, Codigo> {
    let quem = quem_do_processo(autoridade);
    let cota = quem
        .papel
        .as_deref()
        .and_then(|papel| com_politica(|p| p.papel(papel).map(|r| r.processos)));
    let Some(cota) = cota else {
        auditar(
            &quem,
            metodo,
            "",
            Codigo::DenyRole,
            &[],
            "sem papel, nenhum processo",
        );
        return Err(Codigo::DenyRole);
    };
    let cota = cota as usize;
    let vivos = crate::fios::processos_de(autoridade);
    if vivos >= cota {
        return Err(recusar_pela_cota_com(&quem, metodo, vivos, cota));
    }
    Ok(cota)
}

/// O escalonador recusou o nascimento porque a cota encheu entre a
/// decisão e a reserva da vaga — outro processo do mesmo titular nasceu,
/// em outro núcleo. Vai para a auditoria como a recusa de
/// [`permitir_processo`].
pub fn recusar_pela_cota(autoridade: Autoridade, metodo: &str, cota: usize) -> Codigo {
    let quem = quem_do_processo(autoridade);
    recusar_pela_cota_com(&quem, metodo, cota, cota)
}

fn recusar_pela_cota_com(quem: &Quem, metodo: &str, vivos: usize, cota: usize) -> Codigo {
    auditar(
        quem,
        metodo,
        "",
        Codigo::DenyPolicy,
        &[],
        &alloc::format!("cota de processos do papel: {vivos} de {cota}"),
    );
    Codigo::DenyPolicy
}

fn quem_do_processo(autoridade: Autoridade) -> Quem {
    match autoridade {
        Autoridade::Sistema => quem_local("sistema"),
        Autoridade::Sessao { sessao, chave } => quem_da_autoridade(sessao, chave),
        Autoridade::Pessoa { sessao } => match quem_da_pessoa(sessao) {
            Ok(q) | Err(q) => q,
        },
    }
}

/// Zera as janelas de apertos de todas as portas, para a suíte: cada caso
/// com agentes começa como um agente que acabou de chegar. Em release a
/// suíte corre mais depressa, e os apertos de casos seguidos caíam na
/// mesma janela da política — a recusa era de outro caso.
#[cfg(feature = "modo-teste")]
pub fn esquecer_apertos() {
    crate::arch::sem_interrupcoes(|| {
        let mut t = TAXAS.lock();
        t.janelas = [Janela::NOVA; crate::sessoes::PORTAS];
        t.apertos_suprimidos = [0; crate::sessoes::PORTAS];
    });
}

/// Conta um aperto de mão na janela da porta `p`. Falso se passou do
/// limite da política — e grava o primeiro da sequência.
pub fn permitir_aperto(p: u8) -> bool {
    let Some(i) = (1..=crate::sessoes::PORTAS as u8)
        .contains(&p)
        .then(|| usize::from(p) - 1)
    else {
        return false;
    };
    let limite = com_politica(|pol| pol.apertos());
    let agora = crate::tempo::uptime_ms();
    let (passou, primeiro) = crate::arch::sem_interrupcoes(|| {
        let mut t = TAXAS.lock();
        if t.janelas[i].contar(limite, agora) {
            t.apertos_suprimidos[i] = 0;
            (true, false)
        } else {
            t.apertos_suprimidos[i] += 1;
            (false, t.apertos_suprimidos[i] == 1)
        }
    });
    if !passou && primeiro {
        let quem = Quem {
            titular: Titular::Anonimo,
            sessao: p,
            sessao_de_pessoa: None,
            agente: String::new(),
            chave: None,
            papel: None,
            processo: None,
        };
        auditar(
            &quem,
            "session.open",
            "",
            Codigo::RateLimit,
            &[],
            "apertos demais na janela",
        );
    }
    passou
}

/// Grava um aperto de mão: o que entrou, ou o que foi recusado e por quê.
pub fn auditar_aperto(p: u8, chave: Option<[u8; 32]>, nome: &str, codigo: Codigo, detalhe: &str) {
    let papel = match (&chave, codigo) {
        (Some(k), Codigo::Allow) => crate::identidade::papel_do_agente(k),
        _ => None,
    };
    // Um aperto que entrou é de um agente; um recusado, de ninguém ainda —
    // o nome e a chave dizem o que ele alegou.
    let titular = if codigo.permite() {
        Titular::Agente
    } else {
        Titular::Anonimo
    };
    let quem = Quem {
        titular,
        sessao: p,
        sessao_de_pessoa: None,
        agente: nome.to_string(),
        chave,
        papel,
        processo: None,
    };
    auditar(&quem, "session.open", "", codigo, &[], detalhe);
}

/// Decide uma operação administrativa, já com a prova conferida: o papel do
/// administrador tem a permissão? Não grava: quem grava é a operação, uma
/// vez, com o desfecho inteiro — ver [`auditar_administracao`].
pub fn decidir_administracao(papel: Option<&str>, permissao: Permissao) -> Codigo {
    com_politica(|p| p.decidir(papel, permissao, None))
}

/// Se o papel tem a permissão, sem olhar recurso: o primeiro passo de uma
/// operação administrativa cujo recurso só se conhece depois de ler os
/// parâmetros — o destinatário de `message.send`, decidido em seguida por
/// [`decidir_destino`], com o papel do administrador.
pub fn papel_tem(papel: Option<&str>, permissao: Permissao) -> Codigo {
    com_politica(|p| match papel.and_then(|n| p.papel(n)) {
        None => Codigo::DenyRole,
        Some(r) if !r.tem(permissao) => Codigo::DenyPermission,
        Some(_) => Codigo::Allow,
    })
}

/// Conta, na atividade, uma operação administrativa que executou: o
/// administrador `nome`, pela prova, com o `papel` dele. Quem chama é a
/// operação, depois de executar — a decisão dela é a prova e o papel, e
/// mora lá.
pub fn contar_administracao(nome: &str, papel: &str, metodo: &'static str, permissao: Permissao) {
    let quem = Quem {
        titular: Titular::Administrador,
        sessao: SESSAO_DA_PESSOA,
        sessao_de_pessoa: None,
        agente: nome.to_string(),
        chave: None,
        papel: Some(papel.to_string()),
        processo: None,
    };
    contar(&quem, metodo, Some(permissao));
}

/// Grava um desfecho de operação administrativa. `administrador` vazio
/// quando a recusa veio antes de se saber quem era.
#[allow(clippy::too_many_arguments)]
pub fn auditar_administracao(
    sessao: u8,
    administrador: Option<(&str, &[u8; 32])>,
    papel: Option<&str>,
    metodo: &str,
    recurso: &str,
    codigo: Codigo,
    parametros: &[u8],
    detalhe: &str,
) -> u64 {
    // Sem administrador conhecido — a prova não conferiu —, ninguém ainda.
    let titular = if administrador.is_some() {
        Titular::Administrador
    } else {
        Titular::Anonimo
    };
    let quem = Quem {
        titular,
        sessao,
        sessao_de_pessoa: None,
        agente: administrador.map(|a| a.0.to_string()).unwrap_or_default(),
        chave: administrador.map(|a| *a.1),
        papel: papel.map(ToString::to_string),
        processo: None,
    };
    auditar(&quem, metodo, recurso, codigo, parametros, detalhe)
}

/// Grava um desfecho de operação de quórum, em nome das credenciais que
/// assinaram — todas, pelo nome, `adm-1+adm-2`. Sem nenhuma conferida
/// ainda, ninguém. As impressões das chaves vão no detalhe: o registro tem
/// lugar para uma chave só.
#[allow(clippy::too_many_arguments)]
pub fn auditar_quorum(
    sessao: u8,
    assinantes: &[&str],
    papel: Option<&str>,
    metodo: &str,
    recurso: &str,
    codigo: Codigo,
    parametros: &[u8],
    detalhe: &str,
) -> u64 {
    let titular = if assinantes.is_empty() {
        Titular::Anonimo
    } else {
        Titular::Administrador
    };
    let quem = Quem {
        titular,
        sessao,
        sessao_de_pessoa: None,
        agente: assinantes.join("+"),
        chave: None,
        papel: papel.map(ToString::to_string),
        processo: None,
    };
    auditar(&quem, metodo, recurso, codigo, parametros, detalhe)
}

/// Grava um desfecho de sessão de pessoa: o login, a saída, uma tentativa
/// recusada por limite. Com a pessoa e a sessão, o titular é a pessoa; sem,
/// é ninguém ainda — um console sem login.
pub fn auditar_pessoa(
    pessoa: Option<(&str, [u8; 8])>,
    papel: Option<&str>,
    metodo: &str,
    recurso: &str,
    codigo: Codigo,
    detalhe: &str,
) {
    let quem = Quem {
        titular: if pessoa.is_some() {
            Titular::Pessoa
        } else {
            Titular::Anonimo
        },
        sessao: SESSAO_DA_PESSOA,
        sessao_de_pessoa: pessoa.map(|p| p.1),
        agente: pessoa.map(|p| p.0.to_string()).unwrap_or_default(),
        chave: None,
        papel: papel.map(ToString::to_string),
        processo: None,
    };
    auditar(&quem, metodo, recurso, codigo, &[], detalhe);
}

/// Grava um login recusado. O titular é ninguém — não houve autenticação —,
/// e o identificador é o da pessoa que se tentou ser, se o nome era de
/// alguém: é o que mostra uma pessoa sendo atacada. Um nome que não é de
/// ninguém não é gravado.
pub fn auditar_pessoa_recusada(alvo: Option<&str>, metodo: &str, recurso: &str, detalhe: &str) {
    let quem = Quem {
        titular: Titular::Anonimo,
        sessao: SESSAO_DA_PESSOA,
        sessao_de_pessoa: None,
        agente: alvo.unwrap_or_default().to_string(),
        chave: None,
        papel: None,
        processo: None,
    };
    auditar(
        &quem,
        metodo,
        recurso,
        Codigo::DenyNotAuthenticated,
        &[],
        detalhe,
    );
}

/// Muda a política em vigor por uma conta sobre ela, numa seção só: ler a
/// de agora, validar a nova e trocar acontecem sem outra mudança no meio.
/// Uma recusa deixa a de agora como estava.
pub fn mudar_politica<E>(f: impl FnOnce(&Politica) -> Result<Politica, E>) -> Result<(), E> {
    let velha = crate::arch::sem_interrupcoes(|| {
        let mut guarda = POLITICA.lock();
        let nova = match guarda.as_ref() {
            Some(p) => f(p),
            None => f(&Politica::emergencia()),
        }?;
        VERSAO_DA_POLITICA.fetch_add(1, Ordering::SeqCst);
        Ok(guarda.replace(nova))
    })?;
    // A velha sai fora da seção: largar uma política é devolver memória.
    drop(velha);
    Ok(())
}

/// Destrava a política, a auditoria e as taxas à força, para uso exclusivo
/// do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        POLITICA.force_unlock();
        AUDITORIA.force_unlock();
        TAXAS.force_unlock();
        EM_EXECUCAO.force_unlock();
        #[cfg(feature = "modo-teste")]
        ANTES_DA_RECONFIRMACAO.force_unlock();
    }
}
