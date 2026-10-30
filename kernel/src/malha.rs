//! A malha do Duke no kernel: os programas de um titular cooperando por
//! intenções, sem se conhecerem — e sem um caminho que contorne o gate.
//!
//! A conta — endpoints, entregas, estados, nonces, cotas — é a de
//! [`politica::malha`]. Aqui ela ganha o relógio, quem pede, a espera de
//! quem recebe e a auditoria:
//!
//! - **Oferecer** é `fabric.offer`, e **mandar** é `fabric.send` — e
//!   procurar quem oferece, `fabric.discover`, também: só procura quem
//!   poderia mandar. As duas permissões passam pelo gate
//!   ([`crate::autorizacao::autorizar`]) com a intenção como recurso
//!   enumerado, `intencao:<espaço>.<nome>`. Os comandos sobre um endpoint
//!   ou uma entrega já existentes nomeiam o endpoint ou a entrega pelo id, e
//!   o gate decide a intenção dele, resolvida **para quem pede**
//!   ([`recurso_do_pedido`]): o id de outro titular, de outro processo, ou
//!   um que não existe, não resolve — e quem tem a permissão ouve
//!   `DENY_RESOURCE`, sem saber qual dos três.
//! - **Quem pede** vem da autoridade e do caminho do comando — o processo e
//!   o programa que o kernel carregou, a sessão autenticada —, e nunca dos
//!   parâmetros ([`Ator::do_comando`]). O programa de um endpoint e o de
//!   uma entrega são os que o kernel conferiu: o nome do manifesto, o
//!   resumo da imagem e o editor que a selou — não o que o programa diz.
//! - **Só o mesmo titular.** Uma entrega vai de um programa a outro da
//!   mesma pessoa, do mesmo agente, do sistema. Entre titulares, a
//!   ferramenta é a mensagem ([`crate::mensagens`]), com o papel do
//!   destinatário como recurso.
//! - **Só um processo oferece e recebe**: o endpoint é dele, e some com ele.
//!   O gate recusa `fabric.offer`, `fabric.withdraw`, `fabric.recv` e
//!   `fabric.ack` de quem não é processo ([`so_de_processo`]).
//! - **O dono ainda recebe.** Um endpoint é um convite: a descoberta só o
//!   mostra, e uma entrega só vai a ele, enquanto o processo dono vive e
//!   exerceria agora `fabric.offer` sobre a intenção dele — o papel de quem
//!   o lançou, o manifesto, a contenção, a sessão da pessoa, a confiança no
//!   editor ([`crate::autorizacao::processo_exerceria`]).
//! - **A decisão em curso.** Cada operação roda com a ordem das gravações
//!   na mão e decide de novo antes de tocar a tabela
//!   ([`crate::autorizacao::reconfirmar`]): uma revogação ou uma política
//!   nova que passou entre o gate e a operação a recusa, e a que vem depois
//!   a encontra inteira — e anula o que ela fez.
//! - **A revogação** de uma chave ou de uma pessoa fecha os endpoints do
//!   titular e anula as entregas vivas dele, na hora ([`anular_titular`]).
//!   O fim de um processo fecha os endpoints dele e anula o que esperava
//!   neles; o que ele mandou continua ([`canal_acabou`]).
//! - **O corpo não é interpretado nem gravado.** Vai para a tabela e volta
//!   para quem lê. A auditoria grava os ids, as intenções, os programas e
//!   os estados — nunca o texto nem a resposta.
//! - **Nenhuma autoridade viaja.** Quem recebe ganha um texto; o que ele
//!   faz com ele é decidido pelo papel dele, pedido a pedido.
//!
//! # Volátil
//!
//! A malha vive na memória, como um canal de eventos: um boot a perde, e
//! não há journal dela. A época, sorteada no primeiro uso, entra em cada id
//! — `<época>:<n>` —, e um id de outro boot não é de nada. Com o
//! desligamento a caminho, nada novo nasce: `fabric.offer` e `fabric.send`
//! são recusados.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::task::Waker;

use crate::agent::json::Json;
use crate::agent::registry::{Acesso, Command};
use crate::autorizacao::{Autoridade, Chamador, Pedinte};
use crate::rede::espera::Desfecho;
use crate::trava::Mutex;
use politica::Codigo;
use politica::Permissao;
use politica::malha::{
    Canal, Endpoint, Enviada, Estado, Lida, Malha, Origem, Programa, Recusa, Titular, Transicao,
    Vista,
};

/// O parâmetro que nomeia a intenção nos comandos que a recebem.
pub const PARAMETRO_DA_INTENCAO: &str = "intent";

/// O prefixo do recurso que o gate decide.
const PREFIXO: &str = politica::arquivo::PREFIXO_DE_INTENCAO;

struct Tabela {
    malha: Malha,
    /// Sorteada no primeiro uso: um id de outro boot não é confundido com
    /// um deste.
    epoca: [u8; 8],
    /// As esperas armadas, por endpoint: o waker de quem espera, depois da
    /// primeira conferência.
    esperas: BTreeMap<u64, Option<Waker>>,
}

static TABELA: Mutex<Option<Tabela>> = Mutex::new(None);

fn com_tabela<R>(f: impl FnOnce(&mut Tabela) -> R) -> R {
    // A época sai do gerador antes da trava: sortear dentro dela seria
    // pedir outra trava com esta na mão.
    let precisa = crate::arch::sem_interrupcoes(|| TABELA.lock().is_none());
    let nova = precisa.then(|| {
        let mut epoca = [0u8; 8];
        if crate::aleatorio::preencher(&mut epoca).is_err() {
            // Sem entropia, o relógio: a época só distingue boots.
            epoca = crate::tempo::uptime_ms().to_le_bytes();
        }
        Tabela {
            malha: Malha::nova(),
            epoca,
            esperas: BTreeMap::new(),
        }
    });
    crate::arch::sem_interrupcoes(|| {
        let mut t = TABELA.lock();
        if t.is_none() {
            *t = nova;
        }
        f(t.as_mut().expect("a tabela acabou de ser criada"))
    })
}

/// Como [`com_tabela`], mas sem criar a tabela: sem ela, nada a fazer — e
/// nenhuma razão para sortear a época. Para quem só limpa: o fim de um
/// canal, a revogação, o coletor.
fn se_ha_tabela<R>(f: impl FnOnce(&mut Tabela) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| TABELA.lock().as_mut().map(f))
}

/// O id de um endpoint ou de uma entrega como a resposta o escreve: a
/// época e o número.
fn id_texto(epoca: &[u8; 8], n: u64) -> String {
    format!("{}:{n}", sigilo::hex_de(epoca))
}

/// O número de um id deste boot. Um id de outra época, ou malformado, não é
/// de nada.
fn ler_id(epoca: &[u8; 8], texto: &str) -> Option<u64> {
    let (e, n) = texto.split_once(':')?;
    (e == sigilo::hex_de(epoca)).then_some(())?;
    n.parse().ok()
}

/// O recurso de um endpoint na auditoria.
fn recurso_do_endpoint(epoca: &[u8; 8], n: u64) -> String {
    format!("endpoint:{}", id_texto(epoca, n))
}

/// O recurso de uma entrega na auditoria.
fn recurso_da_entrega(epoca: &[u8; 8], n: u64) -> String {
    format!("entrega:{}", id_texto(epoca, n))
}

/// O recurso de uma intenção, como o gate o decide.
fn recurso_da_intencao(intencao: &str) -> String {
    format!("{PREFIXO}{intencao}")
}

/// Os comandos que só um processo pede: o endpoint é de um processo, e só
/// ele o abre, o fecha, lê o que chega por ele e confirma. O gate os recusa
/// a qualquer outro chamador.
pub fn so_de_processo(nome: &str) -> bool {
    matches!(
        nome,
        "fabric.offer" | "fabric.withdraw" | "fabric.recv" | "fabric.ack"
    )
}

/// O titular de uma autoridade, para a malha. `None` para quem não é
/// titular de nada: um serviço, uma sessão sem aperto, a sessão de pessoa
/// que acabou.
fn titular_de(autoridade: Autoridade) -> Option<Titular> {
    match autoridade {
        Autoridade::Sistema => Some(Titular::Sistema),
        Autoridade::Sessao {
            sessao: crate::agent::sessao::SERIAL,
            chave: None,
        } => Some(Titular::Serial),
        Autoridade::Sessao { chave: Some(k), .. } => Some(Titular::Agente(k)),
        Autoridade::Sessao { chave: None, .. } => None,
        Autoridade::Pessoa { sessao } => match crate::pessoas::sessao(sessao) {
            crate::pessoas::EstadoDaSessao::Ativa { pessoa, .. } => Some(Titular::Pessoa(pessoa.0)),
            _ => None,
        },
        Autoridade::Servico(_) => None,
    }
}

/// O programa de um processo, como a malha o mostra. `None` para quem não
/// tem uma imagem com manifesto — que não exerce nada.
fn programa_de(p: &crate::autorizacao::Programa) -> Option<Programa> {
    match p {
        crate::autorizacao::Programa::Imagem {
            manifesto: Some(m),
            resumo,
            editor,
            ..
        } => Some(Programa {
            nome: String::from(m.nome()),
            resumo: *resumo,
            editor: *editor,
        }),
        _ => None,
    }
}

/// Quem age na malha: o titular, o canal dos nonces dele e, se é um
/// processo, o fio e o programa. Só se cria pelo comando que está rodando
/// — nunca de um parâmetro.
#[derive(Clone, Debug)]
pub struct Ator {
    titular: Titular,
    canal: Canal,
    processo: Option<(u64, Programa)>,
}

impl Ator {
    /// Quem pediu o comando que este fio executa. `None` sem titular na
    /// malha, ou fora de um comando pedido por alguém.
    pub fn do_comando() -> Option<Ator> {
        let autoridade = crate::autorizacao::autoridade_atual();
        let titular = titular_de(autoridade)?;
        match crate::autorizacao::pedinte()? {
            Pedinte::Processo(fio) => {
                let programa = programa_de(&crate::autorizacao::programa_decidido()?)?;
                Some(Ator {
                    titular,
                    canal: Canal::Processo(fio),
                    processo: Some((fio, programa)),
                })
            }
            Pedinte::Canal(s) => Some(Ator {
                titular,
                canal: Canal::Sessao(s),
                processo: None,
            }),
            Pedinte::Pessoa => match autoridade {
                Autoridade::Pessoa { sessao } => Some(Ator {
                    titular,
                    canal: Canal::Pessoa(sessao.0),
                    processo: None,
                }),
                _ => None,
            },
            Pedinte::Kernel => None,
        }
    }

    fn fio(&self) -> Option<u64> {
        self.processo.as_ref().map(|(f, _)| *f)
    }

    /// O processo e o programa, ou a recusa de quem não é processo: o gate
    /// já recusa os comandos de endpoint a quem não é, e isto é a mesma
    /// conta, do lado da tabela.
    fn processo(&self) -> Result<(u64, &Programa), Falha> {
        self.processo
            .as_ref()
            .map(|(f, p)| (*f, p))
            .ok_or(Falha::SoProcesso)
    }
}

/// Quem pede, pelo chamador que o gate decide — a mesma conta de
/// [`Ator::do_comando`], antes de haver comando: o titular, o canal e o
/// fio, se é um processo.
fn de_quem(chamador: Chamador, chave: Option<[u8; 32]>) -> Option<(Titular, Canal, Option<u64>)> {
    match chamador {
        Chamador::Processo {
            fio, autoridade, ..
        } => Some((titular_de(autoridade)?, Canal::Processo(fio), Some(fio))),
        Chamador::Sessao(sessao) => Some((
            titular_de(Autoridade::Sessao { sessao, chave })?,
            Canal::Sessao(sessao),
            None,
        )),
        Chamador::Pessoa(id) => Some((
            titular_de(Autoridade::Pessoa { sessao: id })?,
            Canal::Pessoa(id.0),
            None,
        )),
    }
}

/// O recurso que o gate decide para um comando da malha: a intenção, como
/// `intencao:<nome>`.
///
/// - O comando que recebe a intenção (`intent`) decide a do pedido, crua —
///   o registro já recusou a que não tem a forma.
/// - O que nomeia um endpoint (`endpoint`) decide a intenção que ele
///   oferece, se ele é **do processo que pede**.
/// - O que nomeia uma entrega (`id`) decide a intenção dela: a que chegou a
///   um endpoint do processo que pede, para quem recebe (`fabric.ack`); a
///   que o canal de quem pede mandou, para quem mandou (`fabric.cancel`,
///   `fabric.status`).
///
/// `Err` com o motivo exato, para a auditoria, quando o id não resolve para
/// quem pede: o gate responde `DENY_RESOURCE` a quem tem a permissão, sem
/// dizer se o id é de outro ou se não existe.
pub fn recurso_do_pedido(
    chamador: Chamador,
    chave: Option<[u8; 32]>,
    comando: &Command,
    params: Json,
) -> Result<String, &'static str> {
    let texto = |nome: &str| params.member(nome).and_then(|v| v.as_str()).unwrap_or("");
    let nome = match comando.recurso {
        Some(PARAMETRO_DA_INTENCAO) => {
            return Ok(recurso_da_intencao(texto(PARAMETRO_DA_INTENCAO)));
        }
        Some(nome @ ("endpoint" | "id")) => nome,
        _ => return Ok(String::new()),
    };
    let (titular, canal, fio) =
        de_quem(chamador, chave).ok_or("quem pede nao tem titular na malha")?;
    let id = texto(nome);
    let quem_recebe = matches!(comando.acesso, Acesso::Exige(Permissao::FabricOffer));
    let intencao = com_tabela(|t| {
        let n = ler_id(&t.epoca, id)?;
        match (nome, quem_recebe) {
            ("endpoint", _) => t.malha.intencao_do_endpoint(titular, fio?, n),
            (_, true) => t.malha.intencao_recebida(titular, fio?, n),
            (_, false) => t.malha.intencao_mandada(titular, canal, n),
        }
        .map(String::from)
    });
    match (intencao, nome) {
        (Some(i), _) => Ok(recurso_da_intencao(&i)),
        (None, "endpoint") => Err("o endpoint nao existe para quem pede"),
        (None, _) => Err("a entrega nao existe para quem pede"),
    }
}

/// Por que uma operação da malha não aconteceu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falha {
    /// A conta da tabela recusou.
    Malha(Recusa),
    /// A decisão de agora, com a ordem das gravações na mão, não é mais a
    /// do gate: uma revogação, uma política nova, a contenção.
    Reconfirmacao(Codigo, &'static str),
    /// A máquina está reiniciando ou desligando: nada novo nasce.
    Desligando,
    /// Quem pede não é titular de nada na malha.
    SemTitular,
    /// Só um processo faz isto.
    SoProcesso,
    /// A intenção do pedido — ou a do endpoint, ou a da entrega — não é a
    /// que o gate decidiu.
    NaoDecidida,
}

impl Falha {
    /// O código da resposta e da auditoria.
    pub fn codigo(self) -> Codigo {
        match self {
            Falha::Malha(r) => r.codigo(),
            Falha::Reconfirmacao(c, _) => c,
            Falha::Desligando => Codigo::Conflict,
            Falha::SemTitular => Codigo::DenyNotAuthenticated,
            Falha::SoProcesso => Codigo::DenyPermission,
            Falha::NaoDecidida => Codigo::DenyResource,
        }
    }

    /// O motivo, para quem pediu.
    pub fn motivo(self) -> &'static str {
        match self {
            Falha::Malha(r) => r.motivo(),
            Falha::Reconfirmacao(_, m) => m,
            Falha::Desligando => "a maquina esta reiniciando ou desligando",
            Falha::SemTitular => "quem pede nao tem titular na malha",
            Falha::SoProcesso => "so um processo oferece e recebe pela malha",
            Falha::NaoDecidida => "a intencao nao e a que o gate decidiu",
        }
    }
}

impl From<Recusa> for Falha {
    fn from(r: Recusa) -> Falha {
        Falha::Malha(r)
    }
}

/// Grava a recusa de uma execução, em nome da decisão do gate, e a devolve.
///
/// # O tamanho do que se grava
///
/// O detalhe de um registro tem teto ([`politica::auditoria::MAIOR_DETALHE`],
/// 96 bytes), e o de uma execução já leva o processo e o programa na
/// frente e a decisão no fim. Por isso os registros da malha põem os ids no
/// recurso — que tem teto maior, e os separa por ` ; ` como os recursos de
/// qualquer pedido — e dizem no detalhe só o que aconteceu: a origem é o
/// processo do registro, o destino é o endpoint do recurso, e o dono dele
/// está no registro da oferta desse endpoint. Uma cadeia de ids, e nenhum
/// pedaço cortado.
fn recusada<T>(recurso: &str, falha: Falha, exato: &str) -> Result<T, Falha> {
    crate::autorizacao::auditar_execucao(recurso, falha.codigo(), exato);
    Err(falha)
}

/// Se `intencao` é a que o gate decidiu para o comando em execução. A malha
/// só age sobre o que a decisão viu, por mais que quem chama tenha montado
/// tudo certo.
fn decidida(intencao: &str) -> bool {
    crate::autorizacao::alvo_decidido(&recurso_da_intencao(intencao))
}

/// Confere que o alvo — o endpoint ou a entrega, pela intenção que `qual`
/// acha na tabela para quem pede — é o que o gate decidiu. Um alvo que a
/// tabela não acha passa: a operação o recusa, com a recusa dela.
fn conferir_alvo(recurso: &str, qual: impl FnOnce(&Tabela) -> Option<String>) -> Result<(), Falha> {
    match com_tabela(|t| qual(t)) {
        Some(i) if !decidida(&i) => {
            recusada(recurso, Falha::NaoDecidida, Falha::NaoDecidida.motivo())
        }
        _ => Ok(()),
    }
}

/// A intenção da pedida, se é a que o gate decidiu.
fn conferir_intencao(recurso: &str, intencao: &str) -> Result<(), Falha> {
    if decidida(intencao) {
        Ok(())
    } else {
        recusada(recurso, Falha::NaoDecidida, Falha::NaoDecidida.motivo())
    }
}

/// Roda `f` com a ordem das gravações na mão, depois de decidir de novo o
/// comando em execução — ver [`crate::autorizacao::reconfirmar`]. A recusa
/// da decisão nova é gravada sobre `recurso`.
fn sob_a_decisao<R>(recurso: &str, f: impl FnOnce() -> Result<R, Falha>) -> Result<R, Falha> {
    crate::persistencia::em_ordem(|| {
        #[cfg(feature = "modo-teste")]
        crate::autorizacao::gancho_da_reconfirmacao();
        if let Err((c, m)) = crate::autorizacao::reconfirmar() {
            return recusada(recurso, Falha::Reconfirmacao(c, m), m);
        }
        f()
    })
}

/// Grava as transições que o kernel fez sozinho — o prazo que venceu, a
/// anulação pelo fim de um processo ou pela revogação —, em nome dele.
fn auditar_do_kernel(epoca: &[u8; 8], ts: &[Transicao], motivo: &str) {
    for t in ts {
        let (metodo, detalhe) = match t.estado {
            Estado::Expirada => ("fabric.expire", "o prazo venceu"),
            Estado::Anulada => ("fabric.void", motivo),
            _ => continue,
        };
        crate::autorizacao::auditar_do_kernel(
            metodo,
            &recurso_da_entrega(epoca, t.id),
            Codigo::Allow,
            &format!("{detalhe}; versao {}", t.versao),
        );
    }
}

/// Grava as transições que a operação em curso fez — a entrega lida, a
/// anulada por quem fechou o endpoint —, em nome da decisão do gate.
fn auditar_na_execucao(epoca: &[u8; 8], ts: &[Transicao]) {
    for t in ts {
        let detalhe = match t.estado {
            Estado::Entregue => "entregue",
            Estado::Confirmada => "confirmada",
            Estado::Cancelada => "cancelada",
            Estado::Anulada => "anulada com o endpoint",
            Estado::Expirada => "vencida",
            _ => continue,
        };
        crate::autorizacao::auditar_execucao(
            &recurso_da_entrega(epoca, t.id),
            Codigo::Allow,
            &format!("{detalhe}; versao {}", t.versao),
        );
    }
}

/// Tira os wakers de quem espera nos endpoints que acabaram, ou que têm o
/// que ler agora. Com a tabela na mão; quem chama os acorda fora dela.
fn acordaveis(t: &mut Tabela) -> Vec<Waker> {
    let prontos: Vec<u64> = t
        .esperas
        .keys()
        .copied()
        .filter(|&e| t.malha.tem_o_que_ler(e))
        .collect();
    prontos
        .into_iter()
        .filter_map(|e| t.esperas.get_mut(&e).and_then(Option::take))
        .collect()
}

fn acordar(wakers: Vec<Waker>) {
    for w in wakers {
        w.wake();
    }
}

/// Os endpoints, dentre `candidatos`, cujo dono ainda receberia por eles:
/// vivo, e exercendo agora `fabric.offer` sobre a intenção. Fora da trava
/// da tabela — a conta do gate toma as dela.
fn com_dono_que_recebe(candidatos: Vec<Endpoint>) -> Vec<Endpoint> {
    candidatos
        .into_iter()
        .filter(|e| {
            crate::autorizacao::processo_exerceria(
                e.processo,
                Permissao::FabricOffer,
                &recurso_da_intencao(&e.intencao),
            )
        })
        .collect()
}

/// `fabric.offer`: abre o endpoint do processo que pede para `intencao`. O
/// mesmo processo oferecendo a mesma intenção de novo recebe o mesmo
/// endpoint, e `false`: nada foi criado.
pub fn oferecer(a: &Ator, intencao: &str) -> Result<(String, bool), Falha> {
    let recurso = recurso_da_intencao(intencao);
    let (fio, programa) = match a.processo() {
        Ok(p) => p,
        Err(f) => return recusada(&recurso, f, f.motivo()),
    };
    conferir_intencao(&recurso, intencao)?;
    sob_a_decisao(&recurso, || {
        if crate::energia::pedida().is_some() {
            return recusada(&recurso, Falha::Desligando, "desligando");
        }
        let agora = crate::tempo::uptime_ms();
        let (epoca, r) = com_tabela(|t| {
            let r = t
                .malha
                .oferecer(a.titular, fio, programa.clone(), intencao, agora);
            (t.epoca, r)
        });
        match r {
            Ok((n, novo)) => {
                // O endpoint e a intenção no recurso; o programa que o abriu
                // é o do registro.
                let detalhe = if novo {
                    format!(
                        "aberto; politica {}",
                        crate::autorizacao::versao_da_politica()
                    )
                } else {
                    String::from("o mesmo endpoint: nada criado")
                };
                crate::autorizacao::auditar_execucao(
                    &format!("{} ; {recurso}", recurso_do_endpoint(&epoca, n)),
                    Codigo::Allow,
                    &detalhe,
                );
                Ok((id_texto(&epoca, n), novo))
            }
            Err(r) => recusada(&recurso, r.into(), r.motivo()),
        }
    })
}

/// `fabric.withdraw`: fecha o endpoint `endpoint` do processo que pede. O
/// que esperava nele é anulado; devolve quantas.
pub fn retirar(a: &Ator, endpoint: &str) -> Result<usize, Falha> {
    let recurso = format!("endpoint:{endpoint}");
    let fio = match a.processo() {
        Ok((f, _)) => f,
        Err(f) => return recusada(&recurso, f, f.motivo()),
    };
    sob_a_decisao(&recurso, || {
        conferir_alvo(&recurso, |t| {
            let n = ler_id(&t.epoca, endpoint)?;
            t.malha
                .intencao_do_endpoint(a.titular, fio, n)
                .map(String::from)
        })?;
        let (epoca, r, wakers) = com_tabela(|t| {
            let r = match ler_id(&t.epoca, endpoint) {
                Some(n) => t.malha.retirar(a.titular, fio, n).map(|ts| (n, ts)),
                None => Err(Recusa::NaoExiste),
            };
            (t.epoca, r, acordaveis(t))
        });
        acordar(wakers);
        match r {
            Ok((n, anuladas)) => {
                crate::autorizacao::auditar_execucao(
                    &recurso_do_endpoint(&epoca, n),
                    Codigo::Allow,
                    &format!("fechado; {} anulada(s)", anuladas.len()),
                );
                auditar_na_execucao(&epoca, &anuladas);
                Ok(anuladas.len())
            }
            Err(r) => recusada(&recurso, r.into(), r.motivo()),
        }
    })
}

/// `fabric.discover`: os endpoints do titular de quem pede que oferecem
/// `intencao`, cujo dono ainda receberia — em ordem de id, com o id.
pub fn descobrir(a: &Ator, intencao: &str) -> Result<Vec<(String, Endpoint)>, Falha> {
    let recurso = recurso_da_intencao(intencao);
    conferir_intencao(&recurso, intencao)?;
    sob_a_decisao(&recurso, || {
        if !politica::malha::intencao_valida(intencao) {
            return recusada(&recurso, Recusa::Intencao.into(), Recusa::Intencao.motivo());
        }
        let (epoca, candidatos) = com_tabela(|t| (t.epoca, t.malha.descobrir(a.titular, intencao)));
        let todos = candidatos.len();
        let vistos = com_dono_que_recebe(candidatos);
        crate::autorizacao::auditar_execucao(
            &recurso,
            Codigo::Allow,
            &format!(
                "{} visto(s); {} sem dono que receba",
                vistos.len(),
                todos - vistos.len()
            ),
        );
        Ok(vistos
            .into_iter()
            .map(|e| (id_texto(&epoca, e.id), e))
            .collect())
    })
}

/// `fabric.send`: entrega `corpo` ao endpoint `endpoint`, que tem de ser do
/// titular de quem pede, oferecer `intencao` e ter um dono que ainda a
/// receba. O `nonce` é o do canal de quem pede.
pub fn enviar(
    a: &Ator,
    endpoint: &str,
    intencao: &str,
    corpo: &str,
    nonce: u64,
    prazo_ms: Option<u64>,
) -> Result<(String, Enviada), Falha> {
    let recurso = recurso_da_intencao(intencao);
    conferir_intencao(&recurso, intencao)?;
    sob_a_decisao(&recurso, || {
        if crate::energia::pedida().is_some() {
            return recusada(&recurso, Falha::Desligando, "desligando");
        }
        // O destino, como a tabela o tem agora — só o do mesmo titular, com
        // a intenção pedida: qualquer outro é a mesma recusa da tabela.
        let (epoca, alvo) = com_tabela(|t| {
            let alvo = ler_id(&t.epoca, endpoint).and_then(|n| {
                t.malha
                    .descobrir(a.titular, intencao)
                    .into_iter()
                    .find(|e| e.id == n)
            });
            (t.epoca, alvo)
        });
        let Some(alvo) = alvo else {
            return recusada(
                &recurso,
                Recusa::NaoExiste.into(),
                "o endpoint nao existe para quem pede",
            );
        };
        // O dono ainda receberia? Antes do nonce: um destino que não recebe
        // não gasta nonce, e ouve o mesmo que um que não existe.
        if com_dono_que_recebe(alloc::vec![alvo.clone()]).is_empty() {
            return recusada(
                &recurso,
                Recusa::NaoExiste.into(),
                "o dono do endpoint nao recebe agora",
            );
        }
        let agora = crate::tempo::uptime_ms();
        let origem = Origem {
            canal: a.canal,
            processo: a.processo.clone(),
        };
        let (r, vencidas, wakers) = com_tabela(|t| {
            let (r, vencidas) = t.malha.enviar(
                a.titular, origem, alvo.id, intencao, corpo, nonce, prazo_ms, agora,
            );
            (r, vencidas, acordaveis(t))
        });
        acordar(wakers);
        auditar_do_kernel(&epoca, &vencidas, "");
        match r {
            Ok(e) => {
                // A entrega e o endpoint de destino no recurso; quem mandou é
                // o processo do registro, e a intenção, a da decisão.
                let detalhe = if e.duplicata {
                    String::from("reenvio: o mesmo id, nada criado")
                } else {
                    format!(
                        "aceita, pendente; politica {}",
                        crate::autorizacao::versao_da_politica()
                    )
                };
                crate::autorizacao::auditar_execucao(
                    &format!(
                        "{} ; {}",
                        recurso_da_entrega(&epoca, e.id),
                        recurso_do_endpoint(&epoca, alvo.id)
                    ),
                    Codigo::Allow,
                    &detalhe,
                );
                Ok((id_texto(&epoca, e.id), e))
            }
            Err(r) => recusada(&recurso, r.into(), r.motivo()),
        }
    })
}

/// `fabric.recv`: até `max` entregas que esperam no endpoint `endpoint` do
/// processo que pede, depois do id `apos`. Ler não consome: a pendente vira
/// entregue, e fica até a confirmação.
pub fn receber(
    a: &Ator,
    endpoint: &str,
    apos: Option<&str>,
    max: usize,
) -> Result<Vec<(String, Lida)>, Falha> {
    let recurso = format!("endpoint:{endpoint}");
    let fio = match a.processo() {
        Ok((f, _)) => f,
        Err(f) => return recusada(&recurso, f, f.motivo()),
    };
    sob_a_decisao(&recurso, || {
        conferir_alvo(&recurso, |t| {
            let n = ler_id(&t.epoca, endpoint)?;
            t.malha
                .intencao_do_endpoint(a.titular, fio, n)
                .map(String::from)
        })?;
        let agora = crate::tempo::uptime_ms();
        let (epoca, r) = com_tabela(|t| {
            let n = ler_id(&t.epoca, endpoint);
            let apos = match apos {
                None => Some(0),
                Some(texto) => ler_id(&t.epoca, texto),
            };
            let r = match (n, apos) {
                (Some(n), Some(apos)) => t.malha.receber(a.titular, fio, n, apos, max, agora),
                _ => (Err(Recusa::NaoExiste), Vec::new()),
            };
            (t.epoca, r)
        });
        let (lidas, transicoes) = r;
        let (lidas_agora, vencidas): (Vec<Transicao>, Vec<Transicao>) = transicoes
            .into_iter()
            .partition(|t| t.estado == Estado::Entregue);
        auditar_do_kernel(&epoca, &vencidas, "");
        auditar_na_execucao(&epoca, &lidas_agora);
        match lidas {
            Ok(lidas) => Ok(lidas
                .into_iter()
                .map(|l| (id_texto(&epoca, l.id), l))
                .collect()),
            Err(r) => recusada(&recurso, r.into(), r.motivo()),
        }
    })
}

/// `fabric.ack`: confirma uma entrega lida, que chegou a um endpoint do
/// processo que pede, com a resposta opcional para quem mandou.
pub fn confirmar(
    a: &Ator,
    id: &str,
    resposta: Option<&str>,
    esperada: Option<u64>,
) -> Result<Transicao, Falha> {
    let recurso = format!("entrega:{id}");
    let fio = match a.processo() {
        Ok((f, _)) => f,
        Err(f) => return recusada(&recurso, f, f.motivo()),
    };
    sobre_uma(
        &recurso,
        id,
        |m, n| m.intencao_recebida(a.titular, fio, n),
        |m, n, agora| m.confirmar(a.titular, fio, n, resposta, esperada, agora),
    )
}

/// `fabric.cancel`: cancela uma entrega que o canal de quem pede mandou,
/// enquanto ninguém a leu.
pub fn cancelar(a: &Ator, id: &str, esperada: Option<u64>) -> Result<Transicao, Falha> {
    let recurso = format!("entrega:{id}");
    sobre_uma(
        &recurso,
        id,
        |m, n| m.intencao_mandada(a.titular, a.canal, n),
        |m, n, agora| m.cancelar(a.titular, a.canal, n, esperada, agora),
    )
}

/// Uma operação sobre uma entrega pelo id: confirmar ou cancelar. `qual` acha
/// a intenção da entrega para quem pede — a que o gate tem de ter decidido.
fn sobre_uma(
    recurso: &str,
    id: &str,
    qual: impl FnOnce(&Malha, u64) -> Option<&str>,
    f: impl FnOnce(&mut Malha, u64, u64) -> (Result<Transicao, Recusa>, Vec<Transicao>),
) -> Result<Transicao, Falha> {
    sob_a_decisao(recurso, || {
        conferir_alvo(recurso, |t| {
            let n = ler_id(&t.epoca, id)?;
            qual(&t.malha, n).map(String::from)
        })?;
        let agora = crate::tempo::uptime_ms();
        let (epoca, (r, vencidas)) = com_tabela(|t| {
            let r = match ler_id(&t.epoca, id) {
                Some(n) => f(&mut t.malha, n, agora),
                None => (Err(Recusa::NaoExiste), Vec::new()),
            };
            (t.epoca, r)
        });
        auditar_do_kernel(&epoca, &vencidas, "");
        match r {
            Ok(t) => {
                auditar_na_execucao(&epoca, &[t]);
                Ok(t)
            }
            Err(r) => recusada(recurso, r.into(), r.motivo()),
        }
    })
}

/// `fabric.status`: onde está uma entrega que o canal de quem pede mandou
/// — viva ou lembrada —, com a resposta de quem a confirmou.
pub fn estado(a: &Ator, id: &str) -> Result<Vista, Falha> {
    let recurso = format!("entrega:{id}");
    sob_a_decisao(&recurso, || {
        conferir_alvo(&recurso, |t| {
            let n = ler_id(&t.epoca, id)?;
            t.malha
                .intencao_mandada(a.titular, a.canal, n)
                .map(String::from)
        })?;
        let agora = crate::tempo::uptime_ms();
        let (epoca, (r, vencidas)) = com_tabela(|t| {
            let r = match ler_id(&t.epoca, id) {
                Some(n) => t.malha.estado(a.titular, a.canal, n, agora),
                None => (Err(Recusa::NaoExiste), Vec::new()),
            };
            (t.epoca, r)
        });
        auditar_do_kernel(&epoca, &vencidas, "");
        r.or_else(|r| recusada(&recurso, r.into(), r.motivo()))
    })
}

/// O número do endpoint `texto` do processo de `a`, se é dele — para armar
/// a espera do `fabric.recv`.
pub fn endpoint_do_processo(a: &Ator, texto: &str) -> Option<u64> {
    let fio = a.fio()?;
    com_tabela(|t| {
        let n = ler_id(&t.epoca, texto)?;
        t.malha.intencao_do_endpoint(a.titular, fio, n).map(|_| n)
    })
}

/// Arma a espera de quem lê o endpoint `n`. `Ok(false)` quando não há o
/// que esperar — já há o que ler, ou o endpoint acabou —; `Err` quando o
/// endpoint já tem quem espere.
pub fn armar_espera(n: u64) -> Result<bool, &'static str> {
    com_tabela(|t| {
        if t.malha.tem_o_que_ler(n) {
            return Ok(false);
        }
        if t.esperas.contains_key(&n) {
            return Err("o endpoint ja tem quem espere");
        }
        t.esperas.insert(n, None);
        Ok(true)
    })
}

/// A espera no endpoint `n` acabou? `Sumiu` se ele fechou, `Chegou` se há o
/// que ler; senão `None`, e `waker`, se veio um, fica para a próxima
/// entrega. A conferência e o registro acontecem sob a trava da tabela, a
/// mesma com que a entrega entra: ela cai antes — e a conferência a vê — ou
/// depois — e acorda o waker registrado.
///
/// Sem a tabela não há endpoint: a espera acabou. E a tabela não nasce
/// aqui — quem confere pode ter outra trava na mão, e sortear a época seria
/// pedir mais uma.
pub fn conferir_espera(n: u64, waker: Option<&Waker>) -> Option<Desfecho> {
    se_ha_tabela(|t| {
        if !t.malha.endpoints().iter().any(|e| e.id == n) {
            return Some(Desfecho::Sumiu);
        }
        if t.malha.tem_o_que_ler(n) {
            return Some(Desfecho::Chegou);
        }
        if let (Some(w), Some(slot)) = (waker, t.esperas.get_mut(&n)) {
            *slot = Some(w.clone());
        }
        None
    })
    .unwrap_or(Some(Desfecho::Sumiu))
}

/// Desarma a espera no endpoint `n`.
pub fn desarmar_espera(n: u64) {
    se_ha_tabela(|t| t.esperas.remove(&n));
}

/// O titular foi revogado: os endpoints dele fecham e as entregas vivas
/// dele são anuladas, cada uma para a auditoria. Chamada por
/// [`crate::identidade::revogar`] e [`crate::pessoas::revogar_pessoa`], ao
/// lado da anulação das mensagens.
pub fn anular_titular(titular: Titular, motivo: &str) {
    let feito = crate::persistencia::em_ordem(|| {
        se_ha_tabela(|t| {
            let fechados: Vec<u64> = t
                .malha
                .endpoints()
                .iter()
                .filter(|e| e.titular == titular)
                .map(|e| e.id)
                .collect();
            let anuladas = t.malha.anular_titular(titular);
            (t.epoca, fechados, anuladas, acordaveis(t))
        })
    });
    let Some((epoca, fechados, anuladas, wakers)) = feito else {
        return;
    };
    acordar(wakers);
    for n in fechados {
        crate::autorizacao::auditar_do_kernel(
            "fabric.withdraw",
            &recurso_do_endpoint(&epoca, n),
            Codigo::Allow,
            &format!("fechado: {motivo}"),
        );
    }
    auditar_do_kernel(&epoca, &anuladas, &format!("anulada: {motivo}"));
}

/// O canal acabou — a sessão fechou, o processo morreu —: a janela de
/// nonces dele sai, e, se era um processo, os endpoints dele fecham e o que
/// esperava neles é anulado. O que ele mandou continua: quem recebe ainda
/// lê e confirma.
pub fn canal_acabou(canal: Canal) {
    let fio = match canal {
        Canal::Processo(f) => Some(f),
        _ => None,
    };
    let feito = se_ha_tabela(|t| {
        t.malha.canal_acabou(canal);
        let fio = fio?;
        let fechados: Vec<u64> = t
            .malha
            .endpoints()
            .iter()
            .filter(|e| e.processo == fio)
            .map(|e| e.id)
            .collect();
        if fechados.is_empty() {
            return None;
        }
        let anuladas = t.malha.podar(|p| p != fio);
        Some((t.epoca, fechados, anuladas, acordaveis(t)))
    })
    .flatten();
    let Some((epoca, fechados, anuladas, wakers)) = feito else {
        return;
    };
    acordar(wakers);
    for n in fechados {
        crate::autorizacao::auditar_do_kernel(
            "fabric.withdraw",
            &recurso_do_endpoint(&epoca, n),
            Codigo::Allow,
            "fechado: o processo que o abriu acabou",
        );
    }
    auditar_do_kernel(&epoca, &anuladas, "anulada: o processo do endpoint acabou");
}

/// As que venceram saem, e vão para a auditoria. Chamada pelo coletor de
/// fios — uma vez por segundo basta.
pub fn vencer_todos() {
    use core::sync::atomic::{AtomicU64, Ordering};
    static ULTIMA: AtomicU64 = AtomicU64::new(0);
    let agora = crate::tempo::uptime_ms();
    if agora.saturating_sub(ULTIMA.load(Ordering::Relaxed)) < 1_000 {
        return;
    }
    ULTIMA.store(agora, Ordering::Relaxed);
    if let Some((epoca, vencidas)) = se_ha_tabela(|t| (t.epoca, t.malha.vencer(agora))) {
        auditar_do_kernel(&epoca, &vencidas, "");
    }
}

/// Quantos endpoints e quantas entregas vivas — para a suíte.
#[cfg(feature = "modo-teste")]
pub fn contagem() -> (usize, usize) {
    se_ha_tabela(|t| (t.malha.endpoints().len(), t.malha.quantas_vivas())).unwrap_or((0, 0))
}

/// Para o invariante da suíte: a tabela nunca quebra as regras dela.
#[cfg(feature = "modo-teste")]
pub fn coerente() -> bool {
    se_ha_tabela(|t| t.malha.coerente()).unwrap_or(true)
}

/// Só para a suíte: se há quem espere no endpoint `n`.
#[cfg(feature = "modo-teste")]
pub fn tem_espera_de_teste(n: u64) -> bool {
    se_ha_tabela(|t| t.esperas.contains_key(&n)).unwrap_or(false)
}

/// Esvazia a tabela, para a suíte: cada caso começa sem endpoints nem
/// entregas. A época continua: um id de um caso não vale no seguinte, porque
/// os números continuam de onde estavam.
#[cfg(feature = "modo-teste")]
pub fn esvaziar_de_teste() {
    let wakers = se_ha_tabela(|t| {
        let titulares: Vec<Titular> = t.malha.endpoints().iter().map(|e| e.titular).collect();
        for ti in titulares {
            t.malha.anular_titular(ti);
        }
        // As vivas vão sempre a um endpoint aberto, e já saíram; o
        // vencimento é a rede de segurança. As janelas de nonces são dos
        // canais, e saem como sairiam com o fim deles.
        t.malha.vencer(u64::MAX);
        t.malha.esquecer_janelas();
        let w: Vec<Waker> = t.esperas.values_mut().filter_map(Option::take).collect();
        w
    })
    .unwrap_or_default();
    acordar(wakers);
}

/// Destrava a tabela à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        TABELA.force_unlock();
    }
}
