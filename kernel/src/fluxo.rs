//! O fluxo da malha no kernel: um canal ordenado de bytes, nos dois
//! sentidos, entre dois processos do mesmo titular — e nenhum caminho que
//! contorne o gate.
//!
//! A conta — estados, sentidos, buffers, crédito, cotas, lápides — é a de
//! [`politica::fluxo`]. Aqui ela ganha o relógio, quem pede, as esperas, os
//! ganchos e a auditoria:
//!
//! - **Abrir, aceitar, escrever e ler são decisões do gate** de quem as
//!   pede, com a permissão `fabric.stream` e a intenção como recurso
//!   enumerado ([`crate::autorizacao::autorizar`]). Os comandos sobre um
//!   fluxo nomeiam o fluxo pelo id, e o gate decide a intenção dele,
//!   resolvida **para quem pede** ([`recurso_do_pedido`]): o id de outro
//!   processo, de outro titular, ou um que não existe, não resolve — e quem
//!   tem a permissão ouve `DENY_RESOURCE`, sem saber qual dos três.
//! - **Quem pede** vem da autoridade e do caminho do comando — o processo e
//!   o programa que o kernel carregou —, nunca dos parâmetros
//!   ([`Ator::do_comando`]). As pontas são processos: só um processo abre,
//!   aceita, escreve e lê ([`so_de_processo`]); a outra ponta de um fluxo
//!   entre dois Dukes é o par, pela relação, decidido como
//!   `Chamador::Remoto` no domínio do fluxo.
//! - **A abertura efetiva é o aceite**, dentro da ordem das gravações: a
//!   decisão de quem aceita é reconfirmada, e a de quem abriu também —
//!   `processo_exerceria`, ou a interseção da relação, de novo, para o par.
//!   O que passou entre o pedido e o aceite recusa aqui.
//! - **Ler e escrever são o plano de dados**: cada pedido é decidido e
//!   gravado, e por um fluxo aberto, vivo e de quem pede, gasta o caminho
//!   da auditoria em vez da ficha da taxa — ver
//!   [`crate::autorizacao`] sobre o orçamento. O fluxo nunca é autorização
//!   permanente: a política nova, a revogação, a contenção valem no pedido
//!   seguinte, e a recusa de uma leitura ou escrita pela política o
//!   encerra ([`recusado_pelo_gate`]).
//! - **Os bytes não são interpretados nem gravados.** A auditoria grava
//!   ids, intenções, programas, motivos e contagens — nunca o conteúdo.
//! - **Nenhuma autoridade viaja.** Quem lê ganha bytes; o que faz com eles
//!   é decidido pelo papel dele, pedido a pedido.
//!
//! # Volátil
//!
//! O fluxo vive na memória: um boot o perde, e não há journal dele. A
//! época, sorteada no primeiro uso, entra em cada id — `<época>:<n>` —, e
//! um id de outro boot não é de nada. Com o desligamento a caminho, nada
//! abre, e os vivos acabam.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::task::Waker;

use crate::agent::json::Json;
use crate::agent::registry::Command;
use crate::autorizacao::{Autoridade, Chamador, Pedinte};
use crate::rede::espera::Desfecho;
use crate::trava::Mutex;
use politica::Codigo;
use politica::Permissao;
use politica::fluxo::{
    Aceito, Encerramento, Fluxos, Lida, Ponta, Quem, Recusa, Titular, Vista, motivo,
};

pub(crate) mod par;

/// O parâmetro que nomeia o fluxo nos comandos sobre ele.
pub const PARAMETRO: &str = "stream";

/// O prefixo do recurso que o gate decide.
const PREFIXO: &str = politica::arquivo::PREFIXO_DE_INTENCAO;

/// O que uma espera de fluxo espera.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Aguardo {
    /// O processo `fio` lê o fluxo `id`: um dado, o fim, o aborto.
    Ler { id: u64, fio: u64 },
    /// O processo `fio` escreve no fluxo `id`: espaço, a abertura, o
    /// aborto.
    Escrever { id: u64, fio: u64 },
    /// O dono do endpoint `endpoint` aceita: um pedido, ou o fim do
    /// endpoint.
    Aceitar { endpoint: u64 },
}

impl Aguardo {
    fn fluxo(self) -> Option<u64> {
        match self {
            Aguardo::Ler { id, .. } | Aguardo::Escrever { id, .. } => Some(id),
            Aguardo::Aceitar { .. } => None,
        }
    }
}

/// A sessão de um fluxo com outro Duke, vista daqui: o fio que a conduz
/// espera aqui o que fazer, e o motivo do fim fica para ele dizer ao par.
#[derive(Default)]
struct Sessao {
    waker: Option<Waker>,
    /// O fluxo acabou daqui, com este motivo: a sessão diz `fechar` e
    /// acaba.
    fim: Option<String>,
}

struct Tabela {
    fluxos: Fluxos,
    /// Sorteada no primeiro uso: um id de outro boot não é confundido com
    /// um deste.
    epoca: [u8; 8],
    /// As esperas armadas: o waker de quem espera, depois da primeira
    /// conferência. A espera que um encerramento tira daqui acabou.
    esperas: BTreeMap<Aguardo, Option<Waker>>,
    /// As sessões com o par, por fluxo remoto.
    sessoes: BTreeMap<u64, Sessao>,
    /// O desligamento já encerrou os vivos.
    desligou: bool,
}

static TABELA: Mutex<Option<Tabela>> = Mutex::new(None);

fn com_tabela<R>(f: impl FnOnce(&mut Tabela) -> R) -> R {
    // A época sai do gerador antes da trava, como a da malha.
    let precisa = crate::arch::sem_interrupcoes(|| TABELA.lock().is_none());
    let nova = precisa.then(|| {
        let mut epoca = [0u8; 8];
        if crate::aleatorio::preencher(&mut epoca).is_err() {
            epoca = crate::tempo::uptime_ms().to_le_bytes();
        }
        Tabela {
            fluxos: Fluxos::nova(),
            epoca,
            esperas: BTreeMap::new(),
            sessoes: BTreeMap::new(),
            desligou: false,
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

/// Como [`com_tabela`], sem criar a tabela: para quem só limpa.
fn se_ha_tabela<R>(f: impl FnOnce(&mut Tabela) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| TABELA.lock().as_mut().map(f))
}

/// O id de um fluxo como a resposta o escreve: a época e o número.
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

/// O recurso de um fluxo na auditoria.
fn recurso_do_fluxo(epoca: &[u8; 8], n: u64) -> String {
    format!("fluxo:{}", id_texto(epoca, n))
}

/// O recurso de uma intenção, como o gate o decide.
fn recurso_da_intencao(intencao: &str) -> String {
    format!("{PREFIXO}{intencao}")
}

/// Os comandos que só um processo pede: as pontas são processos. O gate os
/// recusa a qualquer outro chamador daqui; o par, pelo domínio do fluxo,
/// só chega aos dele — ver [`politica::fluxo::METODOS_REMOTOS`].
pub fn so_de_processo(nome: &str) -> bool {
    matches!(
        nome,
        "stream.open"
            | "stream.accept"
            | "stream.write"
            | "stream.read"
            | "stream.finish"
            | "stream.close"
            | "stream.status"
    )
}

/// Os comandos cuja recusa pela política encerra o fluxo que nomeiam: ler
/// e escrever. A taxa não encerra — é passageira.
fn recusa_encerra(nome: &str, codigo: Codigo) -> bool {
    matches!(nome, "stream.write" | "stream.read") && codigo_encerra(codigo)
}

/// Os códigos de uma recusa pela política — a autoridade, o papel, o
/// recurso, a contenção, a credencial —, e não pela taxa nem pelo estado.
fn codigo_encerra(codigo: Codigo) -> bool {
    matches!(
        codigo,
        Codigo::DenyPermission
            | Codigo::DenyResource
            | Codigo::DenyPolicy
            | Codigo::DenyRole
            | Codigo::DenyContained
            | Codigo::DenyCredential
    )
}

/// O titular de um processo e a ponta dele, pelo chamador que o gate
/// decide — ou o par, pela relação.
fn de_quem(chamador: Chamador) -> Option<(Titular, Quem)> {
    match chamador {
        Chamador::Processo {
            fio, autoridade, ..
        } => Some((crate::malha::titular_de(autoridade)?, Quem::Processo(fio))),
        outro => {
            let (dispositivo, relacao, epoca, _) = outro.remoto()?;
            let titular = crate::malha::titular_de(Autoridade::Remoto {
                dispositivo,
                relacao,
                epoca,
            })?;
            Some((
                titular,
                Quem::Remoto {
                    dispositivo,
                    relacao,
                },
            ))
        }
    }
}

/// Quem age num fluxo: o titular e a ponta — o processo e o programa que o
/// kernel conferiu, ou o par pela relação. Só se cria pelo comando que está
/// rodando — nunca de um parâmetro.
#[derive(Clone, Debug)]
pub struct Ator {
    titular: Titular,
    ponta: Ponta,
}

impl Ator {
    /// Quem pediu o comando que este fio executa. `None` fora de um
    /// processo ou do par, ou sem titular.
    pub fn do_comando() -> Option<Ator> {
        let autoridade = crate::autorizacao::autoridade_atual();
        let titular = crate::malha::titular_de(autoridade)?;
        match crate::autorizacao::pedinte()? {
            Pedinte::Processo(fio) => {
                let programa =
                    crate::malha::programa_de(&crate::autorizacao::programa_decidido()?)?;
                Some(Ator {
                    titular,
                    ponta: Ponta::Processo { fio, programa },
                })
            }
            Pedinte::Enlace => match autoridade {
                Autoridade::Remoto {
                    dispositivo,
                    relacao,
                    ..
                } => Some(Ator {
                    titular,
                    ponta: Ponta::Remota {
                        dispositivo,
                        relacao,
                        programa: crate::autorizacao::programa_atestado().unwrap_or([0; 32]),
                    },
                }),
                _ => None,
            },
            _ => None,
        }
    }

    fn quem(&self) -> Quem {
        self.ponta.quem()
    }

    fn fio(&self) -> Option<u64> {
        match self.ponta {
            Ponta::Processo { fio, .. } => Some(fio),
            Ponta::Remota { .. } => None,
        }
    }
}

/// O recurso que o gate decide para um comando do fluxo: a intenção, como
/// `intencao:<nome>`.
///
/// - `stream.open` decide a intenção do pedido, crua — o registro já
///   recusou a que não tem a forma.
/// - `stream.accept` decide a intenção do endpoint, se ele é **do processo
///   que pede**.
/// - Os comandos sobre um fluxo decidem a intenção dele, se quem pede é uma
///   das pontas — viva, ou a lápide.
///
/// `Err` com o motivo exato, para a auditoria, quando o id não resolve para
/// quem pede: o gate responde `DENY_RESOURCE` a quem tem a permissão, sem
/// dizer se é de outro ou se não existe.
pub fn recurso_do_pedido(
    chamador: Chamador,
    comando: &Command,
    params: Json,
) -> Result<String, &'static str> {
    let texto = |nome: &str| params.member(nome).and_then(|v| v.as_str()).unwrap_or("");
    match comando.recurso {
        Some(crate::malha::PARAMETRO_DA_INTENCAO) => Ok(recurso_da_intencao(texto(
            crate::malha::PARAMETRO_DA_INTENCAO,
        ))),
        Some("endpoint") => {
            let (titular, quem) = de_quem(chamador).ok_or("quem pede nao tem titular")?;
            let Quem::Processo(fio) = quem else {
                return Err("so um processo aceita");
            };
            crate::malha::endpoint_e_intencao(titular, fio, texto("endpoint"))
                .map(|(_, i)| recurso_da_intencao(&i))
                .ok_or("o endpoint nao existe para quem pede")
        }
        Some(PARAMETRO) => {
            let (titular, quem) = de_quem(chamador).ok_or("quem pede nao tem titular")?;
            let id = texto(PARAMETRO);
            com_tabela(|t| {
                let n = ler_id(&t.epoca, id)?;
                t.fluxos
                    .intencao_para(titular, quem, n)
                    .map(recurso_da_intencao)
            })
            .ok_or("o fluxo nao existe para quem pede")
        }
        _ => Ok(String::new()),
    }
}

/// Se o pedido é sobre um fluxo aberto, vivo e de quem pede — o recurso
/// aberto do plano de dados. Ver `autorizacao::orcamento_do_pedido`.
pub fn aberto_para_o_pedido(chamador: Chamador, params: Json) -> bool {
    let Some((titular, quem)) = de_quem(chamador) else {
        return false;
    };
    let id = params
        .member(PARAMETRO)
        .and_then(|v| v.as_str())
        .unwrap_or("");
    se_ha_tabela(|t| ler_id(&t.epoca, id).is_some_and(|n| t.fluxos.aberto_para(titular, quem, n)))
        .unwrap_or(false)
}

/// O dispositivo do pedido que leva o fluxo a outro Duke — a segunda
/// permissão, `fabric.remote`, decidida na mesma decisão: o `device` de
/// quem abre, e o par de um fluxo aberto daqui, a cada escrita e leitura.
/// `None` para o fluxo local.
pub fn dispositivo_do_pedido(
    chamador: Chamador,
    comando: &Command,
    params: Json,
) -> Option<String> {
    match comando.nome {
        // Um `device` que não é texto vai à decisão como o texto vazio, e
        // ela o recusa: nunca passa por local.
        "stream.open" => params
            .member(politica::enlace::PARAMETRO)
            .map(|v| String::from(v.as_str().unwrap_or(""))),
        "stream.write" | "stream.read" => {
            let (titular, quem) = de_quem(chamador)?;
            let Quem::Processo(_) = quem else {
                return None;
            };
            let id = params.member(PARAMETRO).and_then(|v| v.as_str())?;
            let chave = com_tabela(|t| {
                let n = ler_id(&t.epoca, id)?;
                t.fluxos.intencao_para(titular, quem, n)?;
                match t.fluxos.par_de(n)? {
                    Ponta::Remota { dispositivo, .. } => Some(*dispositivo),
                    Ponta::Processo { .. } => None,
                }
            })?;
            let d = crate::dispositivos::dispositivo(&chave)?;
            Some(format!(
                "{}{}",
                politica::arquivo::PREFIXO_DE_DISPOSITIVO,
                d.nome
            ))
        }
        _ => None,
    }
}

/// Por que uma operação do fluxo não aconteceu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Falha {
    /// A conta da tabela recusou.
    Fluxo(Recusa),
    /// A decisão de agora, com a ordem das gravações na mão, não é mais a
    /// do gate.
    Reconfirmacao(Codigo, &'static str),
    /// A máquina está reiniciando ou desligando: nada abre.
    Desligando,
    /// Quem pede não é titular de nada.
    SemTitular,
    /// Só um processo faz isto.
    SoProcesso,
    /// O recurso do pedido não é o que o gate decidiu.
    NaoDecidida,
}

impl Falha {
    /// O código da resposta e da auditoria.
    pub fn codigo(&self) -> Codigo {
        match self {
            Falha::Fluxo(r) => r.codigo(),
            Falha::Reconfirmacao(c, _) => *c,
            Falha::Desligando => Codigo::Conflict,
            Falha::SemTitular => Codigo::DenyNotAuthenticated,
            Falha::SoProcesso => Codigo::DenyPermission,
            Falha::NaoDecidida => Codigo::DenyResource,
        }
    }

    /// O motivo, para quem pediu.
    pub fn motivo(&self) -> &str {
        match self {
            Falha::Fluxo(r) => r.motivo(),
            Falha::Reconfirmacao(_, m) => m,
            Falha::Desligando => "a maquina esta reiniciando ou desligando",
            Falha::SemTitular => "quem pede nao tem titular na malha",
            Falha::SoProcesso => "so um processo e ponta de um fluxo",
            Falha::NaoDecidida => "o recurso nao e o que o gate decidiu",
        }
    }
}

impl From<Recusa> for Falha {
    fn from(r: Recusa) -> Falha {
        Falha::Fluxo(r)
    }
}

/// Grava a recusa de uma execução, em nome da decisão do gate, e a devolve.
fn recusada<T>(recurso: &str, falha: Falha, exato: &str) -> Result<T, Falha> {
    crate::autorizacao::auditar_execucao(recurso, falha.codigo(), exato);
    Err(falha)
}

/// Se `intencao` é a que o gate decidiu para o comando em execução.
fn decidida(intencao: &str) -> bool {
    crate::autorizacao::alvo_decidido(&recurso_da_intencao(intencao))
}

/// Roda `f` com a ordem das gravações na mão, depois de decidir de novo o
/// comando em execução — ver [`crate::autorizacao::reconfirmar`].
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

/// Tira, das esperas, as de `id` — a espera que sai daqui acabou — e os
/// wakers delas, e o da sessão com o par; com a tabela na mão.
fn de_quem_espera(t: &mut Tabela, id: u64) -> Vec<Waker> {
    crate::aviso::tocar_fluxo(id);
    let chaves: Vec<Aguardo> = t
        .esperas
        .keys()
        .copied()
        .filter(|a| a.fluxo() == Some(id))
        .collect();
    let mut w: Vec<Waker> = chaves
        .into_iter()
        .filter_map(|a| t.esperas.remove(&a).flatten())
        .collect();
    if let Some(s) = t.sessoes.get_mut(&id).and_then(|s| s.waker.take()) {
        w.push(s);
    }
    w
}

/// Os wakers de quem espera no fluxo `id`, sem tirar as esperas: elas
/// conferem de novo, e só acabam se há o que fazer.
fn cutucar(t: &mut Tabela, id: u64) -> Vec<Waker> {
    crate::aviso::tocar_fluxo(id);
    let mut w: Vec<Waker> = t
        .esperas
        .iter_mut()
        .filter(|(a, _)| a.fluxo() == Some(id))
        .filter_map(|(_, w)| w.take())
        .collect();
    if let Some(s) = t.sessoes.get_mut(&id).and_then(|s| s.waker.take()) {
        w.push(s);
    }
    w
}

/// O waker de quem espera aceitar no endpoint `endpoint`.
fn cutucar_o_aceite(t: &mut Tabela, endpoint: u64) -> Vec<Waker> {
    crate::aviso::tocar_endpoint(endpoint);
    t.esperas
        .get_mut(&Aguardo::Aceitar { endpoint })
        .and_then(Option::take)
        .into_iter()
        .collect()
}

/// Acorda as esperas, e dá os avisos da malha que as mudanças pediram —
/// fora da tabela, como os wakers.
fn acordar(wakers: Vec<Waker>) {
    for w in wakers {
        w.wake();
    }
    crate::aviso::processar();
}

/// Com a tabela na mão: o que os encerramentos acordam — as esperas deles
/// saem, a sessão com o par fica sabendo o motivo.
fn encerrados_na_tabela(t: &mut Tabela, es: &[Encerramento]) -> Vec<Waker> {
    let mut w = Vec::new();
    for e in es {
        // O fluxo que acaba libera a cota dos processos em que contava — a
        // de quem abriu, sempre; a de quem aceitou, se foi aceito: o pedido
        // que acaba sem aceite não contava na cota do dono do endpoint —: o
        // dono de um endpoint com pedido esperando, que não pôde aceitá-lo
        // por falta de vaga, é avisado na hora. Os outros endpoints não
        // mudaram.
        let liberadas = [Some(&e.abridor), e.aceito.then_some(&e.aceitante)];
        for q in liberadas.into_iter().flatten() {
            if let Quem::Processo(fio) = q {
                crate::aviso::vaga(*fio);
            }
        }
        if let Some(s) = t.sessoes.get_mut(&e.id) {
            s.fim.get_or_insert_with(|| e.motivo.clone());
        }
        w.extend(de_quem_espera(t, e.id));
    }
    w
}

/// Grava os encerramentos, em nome do kernel: o motivo e as contas, nunca
/// o conteúdo.
fn auditar_encerrados(epoca: &[u8; 8], es: &[Encerramento]) {
    for e in es {
        crate::autorizacao::auditar_do_kernel(
            "stream.end",
            &recurso_do_fluxo(epoca, e.id),
            Codigo::Allow,
            &format!(
                "{}; ida {}; volta {}; desc {}",
                e.motivo, e.ida, e.volta, e.descartados
            ),
        );
        #[cfg(feature = "modo-teste")]
        marcar_o_fim_gravado(e.id);
    }
}

/// Encerramentos feitos com a tabela na mão: grava, e só então acorda —
/// quem o fim acorda opera depois dele na cadeia. Só as operações do
/// processo chamam isto, com a ordem das gravações na mão; os fins por fora
/// e os que a sessão com o par conclui gravam com [`gravar_na_ordem`] e
/// acordam com [`acordar_gravados`].
fn depois(epoca: [u8; 8], es: Vec<Encerramento>, wakers: Vec<Waker>) {
    auditar_encerrados(&epoca, &es);
    acordar(wakers);
}

/// Os encerramentos `es`, feitos com a tabela e a ordem das gravações na
/// mão, gravados ali mesmo — quem chama ainda tem a ordem. A operação de um
/// processo sobre o fluxo, que passa pela ordem, vem depois do fim na
/// cadeia: também a que o aviso do fim, dado ao acordar, o fez pedir.
fn gravar_na_ordem(epoca: &[u8; 8], es: &[Encerramento]) {
    auditar_encerrados(epoca, es);
}

/// Acorda quem espera pelos encerramentos `es`, já gravados dentro da ordem
/// ([`gravar_na_ordem`]), com a ordem já solta — ou ainda na mão de quem a
/// reentrou: a troca de imagem a segura até o fim dos fluxos dela voltar
/// (ver [`programa_mudou`]). Quem acorda e pede a ordem espera por ela, e
/// opera depois do fim na cadeia do mesmo jeito.
fn acordar_gravados(es: &[Encerramento], wakers: Vec<Waker>) {
    #[cfg(feature = "modo-teste")]
    conferir_o_fim_na_cadeia(es);
    #[cfg(not(feature = "modo-teste"))]
    let _ = es;
    acordar(wakers);
}

/// A identidade de uma ponta, como as respostas a escrevem.
pub fn escrever_ponta(w: &mut crate::agent::json::JsonWriter, p: &Ponta) -> core::fmt::Result {
    w.begin_object()?;
    match p {
        Ponta::Processo { programa, .. } => {
            w.field_str("program", &programa.nome)?;
            w.field_str("digest", &sigilo::hex(&programa.resumo))?;
            if let Some(e) = &programa.editor {
                w.field_str("publisher", &sigilo::hex(e))?;
            }
        }
        Ponta::Remota {
            dispositivo,
            relacao,
            programa,
        } => {
            // O nome que o registro daqui dá ao dispositivo, a relação e o
            // programa que ele atesta — atestado, e não conferido.
            let nome = crate::dispositivos::dispositivo(dispositivo)
                .map(|d| format!("{}{}", politica::arquivo::PREFIXO_DE_DISPOSITIVO, d.nome))
                .unwrap_or_default();
            w.field_str("device", &nome)?;
            let id = politica::dispositivos::id_texto(relacao);
            w.field_str("relation", &id[..8])?;
            w.field_str("attested", &sigilo::hex(programa))?;
        }
    }
    w.end_object()
}

// ---------------------------------------------------------------------
// Os comandos.
// ---------------------------------------------------------------------

/// `stream.open` contra um endpoint daqui: um pedido de abertura contra o
/// endpoint `endpoint`, que tem de ser do titular de quem pede, oferecer
/// `intencao` e ter um dono que receberia fluxo. Devolve o id.
///
/// Quem pede é um processo daqui, ou o par — o `abrir` que a sessão do
/// fluxo trouxe de outro Duke, que o gate decidiu como o dispositivo, no
/// domínio do fluxo, pela pessoa da relação ([`par`]). O pedido do par
/// nasce com a sessão dele na tabela: ela fica sabendo do aceite e do fim.
pub fn abrir(a: &Ator, endpoint: &str, intencao: &str) -> Result<String, Falha> {
    let recurso = recurso_da_intencao(intencao);
    let do_par = matches!(a.ponta, Ponta::Remota { .. });
    if !decidida(intencao) {
        return recusada(&recurso, Falha::NaoDecidida, Falha::NaoDecidida.motivo());
    }
    sob_a_decisao(&recurso, || {
        if crate::energia::pedida().is_some() {
            return recusada(&recurso, Falha::Desligando, motivo::DESLIGANDO);
        }
        // O endpoint, como a malha o tem agora: só o do mesmo titular, com
        // a intenção pedida — qualquer outro é a mesma recusa.
        let Some((n, dono, programa)) =
            crate::malha::endpoint_para_fluxo(a.titular, endpoint, intencao)
        else {
            return recusada(
                &recurso,
                Recusa::NaoExiste.into(),
                "o endpoint nao existe para quem pede",
            );
        };
        // O dono receberia fluxo agora? A mesma resposta de um que não
        // existe.
        let exerceria = |p| crate::autorizacao::processo_exerceria(dono, p, &recurso);
        if !exerceria(Permissao::FabricStream) || !exerceria(Permissao::FabricOffer) {
            return recusada(
                &recurso,
                Recusa::NaoExiste.into(),
                "o dono do endpoint nao recebe fluxo agora",
            );
        }
        let agora = crate::tempo::uptime_ms();
        let (epoca, r, wakers) = com_tabela(|t| {
            let r = t.fluxos.abrir(
                a.titular,
                a.ponta.clone(),
                n,
                Ponta::Processo {
                    fio: dono,
                    programa,
                },
                intencao,
                agora,
            );
            let w = match r {
                Ok(id) => {
                    if do_par {
                        t.sessoes.insert(id, Sessao::default());
                    }
                    cutucar_o_aceite(t, n)
                }
                Err(_) => Vec::new(),
            };
            (t.epoca, r, w)
        });
        acordar(wakers);
        match r {
            Ok(id) => {
                crate::autorizacao::auditar_execucao(
                    &format!(
                        "{} ; endpoint:{endpoint} ; {recurso}",
                        recurso_do_fluxo(&epoca, id)
                    ),
                    Codigo::Allow,
                    &format!(
                        "{}; politica {}",
                        if do_par { "pedido pelo par" } else { "pedido" },
                        crate::autorizacao::versao_da_politica()
                    ),
                );
                Ok(id_texto(&epoca, id))
            }
            Err(r) => {
                let m = String::from(r.motivo());
                recusada(&recurso, r.into(), &m)
            }
        }
    })
}

/// `stream.open` com `device`: o fluxo a outro Duke da pessoa de quem pede.
///
/// O gate já decidiu as duas permissões — `fabric.stream` sobre a intenção
/// e `fabric.remote` sobre o dispositivo, resolvido no espaço da pessoa
/// ([`crate::autorizacao::dispositivo_decidido`]). Dentro da ordem, com a
/// decisão reconfirmada, a relação ainda tem de ser da pessoa do fluxo e ter
/// endereço; o pedido entra na tabela, com a sessão dele, e o fio do fluxo
/// sobe para levá-lo ao par — sem fio, o fluxo acaba. O endpoint é o de lá,
/// como a descoberta o deu; quem o confere é o gate de lá.
pub fn abrir_no_par(a: &Ator, endpoint: &str, intencao: &str) -> Result<String, Falha> {
    let recurso = recurso_da_intencao(intencao);
    if a.fio().is_none() {
        return recusada(&recurso, Falha::SoProcesso, Falha::SoProcesso.motivo());
    }
    if !decidida(intencao) {
        return recusada(&recurso, Falha::NaoDecidida, Falha::NaoDecidida.motivo());
    }
    let Some(d) = crate::autorizacao::dispositivo_decidido() else {
        return recusada(&recurso, Falha::NaoDecidida, Falha::NaoDecidida.motivo());
    };
    if !par::endpoint_valido(endpoint) {
        return recusada(
            &recurso,
            Recusa::NaoExiste.into(),
            "o endpoint do par nao tem a forma",
        );
    }
    let aberto = sob_a_decisao(&recurso, || {
        if crate::energia::pedida().is_some() {
            return recusada(&recurso, Falha::Desligando, motivo::DESLIGANDO);
        }
        // A relação, agora: ainda ativa, da pessoa do fluxo, com endereço.
        let relacao = crate::dispositivos::relacao(&d.chave, &d.relacao)
            .filter(|(_, r)| Titular::Pessoa(r.pessoa) == a.titular && r.endereco.is_some());
        if relacao.is_none() {
            return recusada(
                &recurso,
                Recusa::NaoExiste.into(),
                "o dispositivo nao existe para quem pede",
            );
        }
        let par = Ponta::Remota {
            dispositivo: d.chave,
            relacao: d.relacao,
            programa: [0; 32],
        };
        let agora = crate::tempo::uptime_ms();
        let (epoca, r) = com_tabela(|t| {
            let r =
                t.fluxos
                    .abrir_no_par(a.titular, a.ponta.clone(), par, endpoint, intencao, agora);
            if let Ok(id) = r {
                t.sessoes.insert(id, Sessao::default());
            }
            (t.epoca, r)
        });
        match r {
            Ok(id) => {
                crate::autorizacao::auditar_execucao(
                    &format!(
                        "{} ; {} ; endpoint:{endpoint} ; {recurso}",
                        recurso_do_fluxo(&epoca, id),
                        d.recurso
                    ),
                    Codigo::Allow,
                    &format!(
                        "pedido ao par; politica {}",
                        crate::autorizacao::versao_da_politica()
                    ),
                );
                Ok((epoca, id))
            }
            Err(r) => {
                let m = String::from(r.motivo());
                recusada(&recurso, r.into(), &m)
            }
        }
    })?;
    let (epoca, id) = aberto;
    // O fio do fluxo, fora da ordem. Sem ele, o fluxo acaba já — e quem
    // pediu o vê acabado, com o motivo.
    if crate::enlace::lancar_o_fluxo(id).is_err() {
        par::sem_fio(id);
    }
    Ok(id_texto(&epoca, id))
}

/// Se a ponta `abridor` de um pedido exerceria ainda `fabric.stream` sobre
/// a intenção: o processo daqui, ou o par, pela interseção da relação.
fn abridor_exerceria(abridor: &Ponta, recurso: &str) -> bool {
    match abridor {
        Ponta::Processo { fio, .. } => {
            crate::autorizacao::processo_exerceria(*fio, Permissao::FabricStream, recurso)
        }
        Ponta::Remota {
            dispositivo,
            relacao,
            ..
        } => crate::autorizacao::remoto_exerceria(
            dispositivo,
            relacao,
            Permissao::FabricStream,
            recurso,
        ),
    }
}

/// `stream.accept`: o pedido mais antigo no endpoint `endpoint` do processo
/// que pede, aberto — a abertura efetiva. As duas decisões são
/// reconfirmadas dentro da ordem: a de quem aceita, e a de quem abriu. O
/// pedido cujo abridor não poderia mais acaba, e o seguinte é tentado.
/// `Ok(None)` sem pedido na fila.
pub fn aceitar(a: &Ator, endpoint: &str) -> Result<Option<(String, Aceito)>, Falha> {
    let r = aceitar_no(a, endpoint);
    // A operação do dono sobre o endpoint: o aviso dele está consumido. A
    // recusada — a cota cheia, a máquina desligando, a reconfirmação — não
    // rearma na hora: o pedido que ainda espera voltaria a avisar e a ser
    // recusado num giro. O aceite sem pedido na fila não mudou nada: não
    // desfaz o rearme espaçado de uma recusa.
    if let (Some(fio), Some(n)) = (a.fio(), politica::aviso::numero_do_id(endpoint)) {
        let obj = crate::aviso::Objeto::Endpoint(n);
        match r {
            Ok(Some(_)) => crate::aviso::operou(obj, fio, false),
            Ok(None) => crate::aviso::consumiu(obj, fio),
            Err(_) => crate::aviso::recusada(obj, fio),
        }
    }
    r
}

fn aceitar_no(a: &Ator, endpoint: &str) -> Result<Option<(String, Aceito)>, Falha> {
    let recurso = format!("endpoint:{endpoint}");
    let Some(fio) = a.fio() else {
        return recusada(&recurso, Falha::SoProcesso, Falha::SoProcesso.motivo());
    };
    sob_a_decisao(&recurso, || {
        if crate::energia::pedida().is_some() {
            return recusada(&recurso, Falha::Desligando, motivo::DESLIGANDO);
        }
        let Some((n, intencao)) = crate::malha::endpoint_e_intencao(a.titular, fio, endpoint)
        else {
            return recusada(
                &recurso,
                Recusa::NaoExiste.into(),
                "o endpoint nao existe para quem pede",
            );
        };
        if !decidida(&intencao) {
            return recusada(&recurso, Falha::NaoDecidida, Falha::NaoDecidida.motivo());
        }
        let alvo = recurso_da_intencao(&intencao);
        loop {
            let pedido = com_tabela(|t| {
                let id = t.fluxos.primeiro_pedido(a.titular, fio, n)?;
                let (abridor, _) = t.fluxos.pedido(id)?;
                Some((t.epoca, id, abridor.clone()))
            });
            let Some((epoca, id, abridor)) = pedido else {
                return Ok(None);
            };
            // A decisão de quem abriu, de novo: o que passou entre o pedido
            // e o aceite recusa aqui.
            if !abridor_exerceria(&abridor, &alvo) {
                let (es, wakers) = com_tabela(|t| {
                    let es: Vec<Encerramento> =
                        t.fluxos.recusar(id, motivo::ABRIDOR).into_iter().collect();
                    let w = encerrados_na_tabela(t, &es);
                    (es, w)
                });
                depois(epoca, es, wakers);
                continue;
            }
            let agora = crate::tempo::uptime_ms();
            let (r, wakers) = com_tabela(|t| {
                let r = t.fluxos.aceitar(a.titular, fio, id, agora);
                let w = if r.is_ok() {
                    cutucar(t, id)
                } else {
                    Vec::new()
                };
                (r, w)
            });
            acordar(wakers);
            return match r {
                Ok(aceito) => {
                    crate::autorizacao::auditar_execucao(
                        &format!(
                            "{} ; endpoint:{endpoint} ; {alvo}",
                            recurso_do_fluxo(&epoca, id)
                        ),
                        Codigo::Allow,
                        &format!("aberto; versao {}", aceito.versao),
                    );
                    Ok(Some((id_texto(&epoca, id), aceito)))
                }
                Err(r) => {
                    let m = String::from(r.motivo());
                    recusada(&recurso, r.into(), &m)
                }
            };
        }
    })
}

/// O fluxo `id` de quem pede, como o gate o decidiu: o número, ou a recusa.
fn alvo(a: &Ator, id: &str) -> Result<(String, u64), Falha> {
    let recurso = format!("fluxo:{id}");
    let numero = com_tabela(|t| {
        let n = ler_id(&t.epoca, id)?;
        let i = t.fluxos.intencao_para(a.titular, a.quem(), n)?;
        Some((n, String::from(i)))
    });
    match numero {
        Some((n, i)) if decidida(&i) => Ok((recurso, n)),
        Some(_) => recusada(&recurso, Falha::NaoDecidida, Falha::NaoDecidida.motivo()),
        None => recusada(
            &recurso,
            Recusa::NaoExiste.into(),
            "o fluxo nao existe para quem pede",
        ),
    }
}

/// A reconfirmação recusou, pela política, a leitura ou a escrita de agora
/// no fluxo `n`: ele acaba, como na recusa do próprio gate — a decisão
/// seguinte encerra, seja ela a do gate ou a de dentro da ordem. Ver
/// [`recusado_pelo_gate`].
fn recusada_na_reconfirmacao<T>(a: &Ator, n: u64, r: &Result<T, Falha>) {
    let Err(Falha::Reconfirmacao(codigo, m)) = r else {
        return;
    };
    if !codigo_encerra(*codigo) {
        return;
    }
    let m = format!("{}: {m}", codigo.nome());
    let (titular, quem) = (a.titular, a.quem());
    encerrar_por_fora(|f| {
        if f.aberto_para(titular, quem, n) {
            f.abortar(n, &m).into_iter().collect()
        } else {
            Vec::new()
        }
    });
}

/// `stream.write`: põe `dados` no sentido de quem pede — o que couber.
/// Devolve quantos bytes entraram; zero com o buffer cheio.
pub fn escrever(a: &Ator, id: &str, dados: &[u8]) -> Result<usize, Falha> {
    let (recurso, n) = alvo(a, id)?;
    let r = escrever_no(a, &recurso, n, dados);
    recusada_na_reconfirmacao(a, n, &r);
    operou(a, n, &r, matches!(r, Ok(k) if k < dados.len()));
    r
}

/// A operação de `a` sobre o fluxo `n` acabou: o aviso da malha dele está
/// consumido, e rearma — ou, se ela ouviu o fim do fluxo, a designação sai;
/// ou, se foi recusada (a reconfirmação, o estado do fluxo), rearma pelo
/// coletor, um tempo depois. `esbarrou` diz que a escrita não coube inteira.
fn operou<T>(a: &Ator, n: u64, r: &Result<T, Falha>, esbarrou: bool) {
    let Some(fio) = a.fio() else {
        return;
    };
    let obj = crate::aviso::Objeto::Ponta { fluxo: n, fio };
    #[cfg(feature = "modo-teste")]
    if matches!(r, Err(Falha::Fluxo(Recusa::Encerrado(_))))
        && FIM_NO_ENCERRADO.swap(false, core::sync::atomic::Ordering::AcqRel)
    {
        vencer_de_teste(u64::MAX);
    }
    match r {
        // O fim — do fluxo, ouvido por ela, ou só do sentido de quem opera,
        // com o fluxo vivo — é uma operação como as outras, e a conta de
        // agora diz o resto: o que ainda há para ler do par avisa; o fim
        // que ela não ouviu (o fluxo acabou depois dela) sai, uma vez; e o
        // que ela ouviu tira a designação, sem aviso.
        Err(Falha::Fluxo(Recusa::Encerrado(_))) => crate::aviso::operou(obj, fio, false),
        Err(_) => crate::aviso::recusada(obj, fio),
        Ok(_) => crate::aviso::operou(obj, fio, esbarrou),
    }
}

/// Só para a suíte: na próxima operação sobre uma ponta que ouvir
/// `Encerrado`, os fluxos acabam ([`vencer_de_teste`]) entre a operação e a
/// conta do aviso — como a inatividade, a revogação ou o desligamento
/// acabariam o fluxo nessa janela.
#[cfg(feature = "modo-teste")]
static FIM_NO_ENCERRADO: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Só para a suíte: arma o fim na próxima operação que ouvir `Encerrado`
/// ([`FIM_NO_ENCERRADO`]).
#[cfg(feature = "modo-teste")]
pub fn acabar_no_proximo_encerrado_de_teste() {
    FIM_NO_ENCERRADO.store(true, core::sync::atomic::Ordering::Release);
}

/// Só para a suíte: o fluxo cujo fim se confere na cadeia na hora de
/// acordar quem espera por ele — o número mais um; zero, nenhum.
#[cfg(feature = "modo-teste")]
static FIM_A_CONFERIR: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Só para a suíte: o que a conferência achou — 1, o fim já na cadeia ao
/// acordar; 2, ainda não; 0, não conferiu.
#[cfg(feature = "modo-teste")]
static FIM_CONFERIDO: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Só para a suíte: o `stream.end` do fluxo a conferir já foi gravado
/// ([`auditar_encerrados`]).
#[cfg(feature = "modo-teste")]
static FIM_GRAVADO: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Só para a suíte: como o `stream.end` do fluxo a conferir foi gravado,
/// antes de acordar quem espera — 1, com a ordem das gravações na mão de
/// quem gravou; 2, sem ela; 0, ainda não foi.
#[cfg(feature = "modo-teste")]
static FIM_NA_ORDEM: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Só para a suíte: como a última troca de imagem chegou ao fim dos fluxos
/// ([`programa_mudou`]) — 1, com a ordem das gravações já na mão, trazida de
/// fora pela troca; 2, sem ela; 0, nenhuma desde a última conferência.
#[cfg(feature = "modo-teste")]
static ORDEM_TRAZIDA_NA_TROCA: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Só para a suíte: na hora de acordar quem espera pelo fim do fluxo `n`
/// ([`acordar_gravados`]), confere se o `stream.end` dele já está na
/// cadeia — e, quando ele é gravado, se com a ordem das gravações na mão.
/// Esquece também como a última troca de imagem chegou ao fim dos fluxos
/// ([`troca_com_a_ordem_trazida_de_teste`]).
#[cfg(feature = "modo-teste")]
pub fn conferir_o_fim_na_cadeia_de_teste(n: u64) {
    use core::sync::atomic::Ordering;
    FIM_CONFERIDO.store(0, Ordering::Release);
    FIM_GRAVADO.store(false, Ordering::Release);
    FIM_NA_ORDEM.store(0, Ordering::Release);
    ORDEM_TRAZIDA_NA_TROCA.store(0, Ordering::Release);
    FIM_A_CONFERIR.store(n.saturating_add(1), Ordering::Release);
}

/// Só para a suíte: se a última troca de imagem chegou ao fim dos fluxos
/// ([`programa_mudou`]) com a ordem das gravações já na mão, trazida de fora
/// — `Some(true)` —, ou sem ela — `Some(false)`. `None`, nenhuma desde
/// [`conferir_o_fim_na_cadeia_de_teste`].
///
/// O fim gravado dentro da ordem ([`fim_gravado_na_ordem_de_teste`]) não
/// basta: sem ela trazida, [`encerrar_por_fora`] a tomaria por conta
/// própria — de dentro do handler, esperando se estivesse com outro.
#[cfg(feature = "modo-teste")]
pub fn troca_com_a_ordem_trazida_de_teste() -> Option<bool> {
    match ORDEM_TRAZIDA_NA_TROCA.load(core::sync::atomic::Ordering::Acquire) {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

/// Só para a suíte: o que a conferência de [`conferir_o_fim_na_cadeia_de_teste`]
/// achou — `Some(true)`, o fim já na cadeia ao acordar.
#[cfg(feature = "modo-teste")]
pub fn fim_na_cadeia_ao_acordar_de_teste() -> Option<bool> {
    match FIM_CONFERIDO.load(core::sync::atomic::Ordering::Acquire) {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

/// Só para a suíte: se o `stream.end` do fluxo de
/// [`conferir_o_fim_na_cadeia_de_teste`] foi gravado, antes de acordar quem
/// espera, com a ordem das gravações na mão — `Some(true)` —, sem ela —
/// `Some(false)` —, ou se não foi gravado antes de acordar — `None`.
#[cfg(feature = "modo-teste")]
pub fn fim_gravado_na_ordem_de_teste() -> Option<bool> {
    match FIM_NA_ORDEM.load(core::sync::atomic::Ordering::Acquire) {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

/// Só para a suíte: o `stream.end` do fluxo `id` acabou de ser gravado — e
/// fica anotado se quem o gravou tinha a ordem das gravações na mão.
#[cfg(feature = "modo-teste")]
fn marcar_o_fim_gravado(id: u64) {
    use core::sync::atomic::Ordering;
    if FIM_A_CONFERIR.load(Ordering::Acquire) == id.saturating_add(1) {
        let na_ordem = crate::persistencia::ordem_na_mao_sem_trava();
        FIM_NA_ORDEM.store(if na_ordem { 1 } else { 2 }, Ordering::Release);
        FIM_GRAVADO.store(true, Ordering::Release);
    }
}

/// Só para a suíte: na hora de acordar, se o fim a conferir está entre os
/// encerramentos `es`, anota se o `stream.end` dele já foi gravado.
#[cfg(feature = "modo-teste")]
fn conferir_o_fim_na_cadeia(es: &[Encerramento]) {
    use core::sync::atomic::Ordering;
    let alvo = FIM_A_CONFERIR.load(Ordering::Acquire);
    let Some(n) = alvo.checked_sub(1) else {
        return;
    };
    if !es.iter().any(|e| e.id == n) {
        return;
    }
    let gravado = FIM_GRAVADO.swap(false, Ordering::AcqRel);
    FIM_CONFERIDO.store(if gravado { 1 } else { 2 }, Ordering::Release);
    FIM_A_CONFERIR.store(0, Ordering::Release);
}

/// Só para a suíte: desarma os pontos da suíte deste módulo — o caso que
/// falha antes de usar o seu não o deixa armado para o caso seguinte.
#[cfg(feature = "modo-teste")]
pub fn desarmar_de_teste() {
    use core::sync::atomic::Ordering;
    FIM_NO_ENCERRADO.store(false, Ordering::Release);
    FIM_A_CONFERIR.store(0, Ordering::Release);
    FIM_GRAVADO.store(false, Ordering::Release);
    FIM_NA_ORDEM.store(0, Ordering::Release);
    ORDEM_TRAZIDA_NA_TROCA.store(0, Ordering::Release);
}

fn escrever_no(a: &Ator, recurso: &str, n: u64, dados: &[u8]) -> Result<usize, Falha> {
    sob_a_decisao(recurso, || {
        let agora = crate::tempo::uptime_ms();
        let (r, wakers) = com_tabela(|t| {
            let r = t.fluxos.escrever(a.titular, a.quem(), n, dados, agora);
            let w = match r {
                Ok(k) if k > 0 => cutucar(t, n),
                _ => Vec::new(),
            };
            (r, w)
        });
        acordar(wakers);
        r.or_else(|r| {
            let m = String::from(r.motivo());
            recusada(recurso, r.into(), &m)
        })
    })
}

/// `stream.read`: até `max` bytes do sentido de quem pede, na ordem, e se
/// o sentido terminou limpo depois deles.
pub fn ler(a: &Ator, id: &str, max: usize) -> Result<Lida, Falha> {
    let (recurso, n) = alvo(a, id)?;
    let r = ler_no(a, &recurso, n, max);
    recusada_na_reconfirmacao(a, n, &r);
    operou(a, n, &r, false);
    r
}

fn ler_no(a: &Ator, recurso: &str, n: u64, max: usize) -> Result<Lida, Falha> {
    sob_a_decisao(recurso, || {
        let agora = crate::tempo::uptime_ms();
        let (epoca, r, es, wakers) = com_tabela(|t| {
            let r = t.fluxos.ler(a.titular, a.quem(), n, max, agora);
            let mut w = Vec::new();
            let mut es = Vec::new();
            if let Ok((l, e)) = &r {
                if !l.dados.is_empty() {
                    w.extend(cutucar(t, n));
                }
                es.extend(e.iter().cloned());
                w.extend(encerrados_na_tabela(t, &es));
            }
            (t.epoca, r, es, w)
        });
        depois(epoca, es, wakers);
        match r {
            Ok((l, _)) => Ok(l),
            Err(r) => {
                let m = String::from(r.motivo());
                recusada(recurso, r.into(), &m)
            }
        }
    })
}

/// `stream.finish` e `stream.close`: termina o sentido de quem pede, ou
/// fecha o fluxo para ele.
pub fn terminar_ou_fechar(a: &Ator, id: &str, fechar: bool) -> Result<(), Falha> {
    let (recurso, n) = alvo(a, id)?;
    let r = terminar_ou_fechar_no(a, &recurso, n, fechar);
    match a.fio() {
        // Quem fecha sai do fluxo: não há mais o que avisar a ele — se o
        // fecho passou, ou ouviu o fim. O fecho recusado (a reconfirmação)
        // deixa o fluxo vivo, e com ele a designação: é uma operação, que
        // consome o aviso e rearma.
        Some(fio) if fechar && matches!(r, Ok(()) | Err(Falha::Fluxo(Recusa::Encerrado(_)))) => {
            let obj = crate::aviso::Objeto::Ponta { fluxo: n, fio };
            #[cfg(feature = "modo-teste")]
            crate::aviso::antes_de_largar_no_fecho_de_teste(obj);
            crate::aviso::largar(obj, fio)
        }
        _ => operou(a, n, &r, false),
    }
    r
}

fn terminar_ou_fechar_no(a: &Ator, recurso: &str, n: u64, fechar: bool) -> Result<(), Falha> {
    sob_a_decisao(recurso, || {
        let agora = crate::tempo::uptime_ms();
        let (epoca, r, es, wakers) = com_tabela(|t| {
            let r = if fechar {
                t.fluxos.fechar(a.titular, a.quem(), n, agora)
            } else {
                t.fluxos.terminar(a.titular, a.quem(), n, agora)
            };
            let mut w = cutucar(t, n);
            let es: Vec<Encerramento> = r.iter().flatten().cloned().collect();
            w.extend(encerrados_na_tabela(t, &es));
            (t.epoca, r, es, w)
        });
        depois(epoca, es, wakers);
        match r {
            Ok(_) => Ok(()),
            Err(r) => {
                let m = String::from(r.motivo());
                recusada(recurso, r.into(), &m)
            }
        }
    })
}

/// `stream.status`: o que quem pede vê do fluxo — vivo ou lembrado.
pub fn estado(a: &Ator, id: &str) -> Result<Vista, Falha> {
    let (recurso, n) = alvo(a, id)?;
    let r = sob_a_decisao(&recurso, || {
        com_tabela(|t| t.fluxos.estado(a.titular, a.quem(), n)).or_else(|r| {
            let m = String::from(r.motivo());
            recusada(&recurso, r.into(), &m)
        })
    });
    operou(a, n, &r, false);
    r
}

/// O que o aviso da malha (DS-1) diz da ponta do processo `fio` no fluxo
/// `n`, agora. Sem tabela, o fluxo não existe: nada a dizer.
pub fn prontidao_da_ponta(n: u64, fio: u64) -> politica::fluxo::Prontidao {
    se_ha_tabela(|t| t.fluxos.prontidao(Quem::Processo(fio), n))
        .unwrap_or(politica::fluxo::Prontidao::Acabou { ja_sabe: true })
}

/// Se há um pedido de fluxo esperando o aceite no endpoint `n`.
pub fn tem_pedido_em(n: u64) -> bool {
    se_ha_tabela(|t| t.fluxos.tem_pedido(n)).unwrap_or(false)
}

// ---------------------------------------------------------------------
// As esperas: a de ler, a de escrever, a de aceitar.
// ---------------------------------------------------------------------

/// O que esperar num `stream.read` ou `stream.write` de quem pede pelo
/// fluxo `id` — se é dele. `None` quando não é, e a resposta de sempre diz
/// por quê.
pub fn aguardo_do_pedido(id: &str, escrever: bool) -> Option<Aguardo> {
    let a = Ator::do_comando()?;
    let fio = a.fio()?;
    com_tabela(|t| {
        let n = ler_id(&t.epoca, id)?;
        t.fluxos.intencao_para(a.titular, a.quem(), n)?;
        Some(if escrever {
            Aguardo::Escrever { id: n, fio }
        } else {
            Aguardo::Ler { id: n, fio }
        })
    })
}

/// O que esperar num `stream.accept` do processo que pede pelo endpoint
/// `endpoint` — se é dele.
pub fn aguardo_do_aceite(endpoint: &str) -> Option<Aguardo> {
    let a = Ator::do_comando()?;
    let fio = a.fio()?;
    let (n, _) = crate::malha::endpoint_e_intencao(a.titular, fio, endpoint)?;
    Some(Aguardo::Aceitar { endpoint: n })
}

/// Se a espera `a` já tem o que dizer.
fn pronta(t: &Tabela, a: Aguardo) -> bool {
    match a {
        Aguardo::Ler { id, fio } => t.fluxos.pode_ler(Quem::Processo(fio), id),
        Aguardo::Escrever { id, fio } => t.fluxos.pode_escrever(Quem::Processo(fio), id),
        Aguardo::Aceitar { endpoint } => t.fluxos.tem_pedido(endpoint),
    }
}

/// Arma a espera `a`. `Ok(false)` quando não há o que esperar — já há o que
/// fazer —; `Err` quando já há quem espere ali: uma espera por sentido, por
/// fluxo, como numa conexão.
pub fn armar_espera(a: Aguardo) -> Result<bool, &'static str> {
    com_tabela(|t| {
        if pronta(t, a) {
            return Ok(false);
        }
        if t.esperas.contains_key(&a) {
            return Err("o fluxo ja tem quem espere neste sentido");
        }
        t.esperas.insert(a, None);
        Ok(true)
    })
}

/// A espera `a` acabou? `Sumiu` se o fluxo ou o endpoint acabou — o
/// encerramento a tirou daqui —; `Chegou` ou `Coube` se há o que fazer;
/// senão `None`, e `waker` fica para o próximo evento. Sob a trava da
/// tabela, a mesma com que cada operação muda o fluxo.
pub fn conferir_espera(a: Aguardo, waker: Option<&Waker>) -> Option<Desfecho> {
    se_ha_tabela(|t| {
        if !t.esperas.contains_key(&a) {
            return Some(Desfecho::Sumiu);
        }
        if pronta(t, a) {
            return Some(match a {
                Aguardo::Escrever { .. } => Desfecho::Coube,
                _ => Desfecho::Chegou,
            });
        }
        if let (Some(w), Some(slot)) = (waker, t.esperas.get_mut(&a)) {
            *slot = Some(w.clone());
        }
        None
    })
    .unwrap_or(Some(Desfecho::Sumiu))
}

/// Desarma a espera `a`.
pub fn desarmar_espera(a: Aguardo) {
    se_ha_tabela(|t| t.esperas.remove(&a));
}

// ---------------------------------------------------------------------
// Os ganchos: o kernel encerra por fora.
// ---------------------------------------------------------------------

/// Encerra, dentro da ordem, os fluxos que `f` diz, e grava os fins ainda
/// dentro dela; depois acorda.
fn encerrar_por_fora(f: impl FnOnce(&mut Fluxos) -> Vec<Encerramento>) {
    let feito = crate::persistencia::em_ordem(|| {
        let (epoca, es, w) = se_ha_tabela(|t| {
            let es = f(&mut t.fluxos);
            let w = encerrados_na_tabela(t, &es);
            (t.epoca, es, w)
        })?;
        gravar_na_ordem(&epoca, &es);
        Some((es, w))
    });
    if let Some((es, w)) = feito {
        acordar_gravados(&es, w);
    }
}

/// O titular foi revogado: os fluxos dele acabam. Chamada pela malha, ao
/// lado dos endpoints e das entregas dele.
pub fn anular_titular(titular: Titular) {
    encerrar_por_fora(|f| f.anular_titular(titular, motivo::REVOGADO));
}

/// O canal acabou: se era um processo, os fluxos de que ele é ponta acabam.
/// Chamada pela malha, no fim de um processo.
pub fn canal_acabou(canal: politica::mensagens::Canal) {
    if let politica::mensagens::Canal::Processo(fio) = canal {
        encerrar_por_fora(|f| f.processo_acabou(fio, motivo::PROCESSO));
    }
}

/// O processo `fio` trocou de imagem: a outra ponta viu outro programa, e
/// os fluxos dele acabam. Chamada pelo `process.exec`, logo depois do ponto
/// sem volta — antes de a imagem nova ser mapeada, e de rodar —, dentro do
/// handler da chamada de sistema e com a ordem das gravações já na mão: quem
/// é ponta ([`processo_e_ponta`]) a toma sem esperar antes do ponto sem
/// volta, e a segura até aqui. [`encerrar_por_fora`] a reentra: nada espera
/// a ordem nem compacta o journal dentro do handler. Sem ela na mão, a
/// espera voltaria — a asserção abaixo é esse erro, na hora, em vez de só
/// quando outro fio tivesse a ordem; e a suíte o confere também fora da
/// depuração (`troca_com_a_ordem_trazida_de_teste`).
pub fn programa_mudou(fio: u64) {
    let trazida = crate::persistencia::ordem_na_mao();
    debug_assert!(
        trazida,
        "o fim dos fluxos da troca de imagem sem a ordem das gravacoes na mao"
    );
    #[cfg(feature = "modo-teste")]
    ORDEM_TRAZIDA_NA_TROCA.store(
        if trazida { 1 } else { 2 },
        core::sync::atomic::Ordering::Release,
    );
    encerrar_por_fora(|f| f.processo_acabou(fio, motivo::PROGRAMA));
}

/// Se o processo `fio` é ponta de algum fluxo vivo: se a troca de imagem ou
/// a morte dele encerraria algum ([`programa_mudou`], [`canal_acabou`]). O
/// `process.exec` só toma a ordem das gravações quando há o que encerrar.
pub fn processo_e_ponta(fio: u64) -> bool {
    se_ha_tabela(|t| t.fluxos.processo_e_ponta(fio)).unwrap_or(false)
}

/// O endpoint `endpoint` acabou: os pedidos que esperavam nele acabam, e a
/// espera de quem aceitava por ele também. Chamada pela malha.
pub fn endpoint_acabou(endpoint: u64) {
    let feito = crate::persistencia::em_ordem(|| {
        let (epoca, es, w) = se_ha_tabela(|t| {
            let es = t.fluxos.endpoint_acabou(endpoint);
            let mut w = encerrados_na_tabela(t, &es);
            if let Some(Some(x)) = t.esperas.remove(&Aguardo::Aceitar { endpoint }) {
                w.push(x);
            }
            (t.epoca, es, w)
        })?;
        gravar_na_ordem(&epoca, &es);
        Some((es, w))
    });
    if let Some((es, w)) = feito {
        acordar_gravados(&es, w);
    }
}

/// O dispositivo saiu — revogado, suspenso —: os fluxos com ele acabam.
/// Chamada pelo enlace.
pub fn anular_dispositivo(chave: &[u8; 32], motivo: &str) {
    encerrar_por_fora(|f| f.anular_remotos(motivo, |d, _| d == chave));
}

/// A relação `relacao` do dispositivo foi desfeita: os fluxos por ela
/// acabam. Chamada pelo enlace.
pub fn anular_relacao(chave: &[u8; 32], relacao: &[u8; 16]) {
    encerrar_por_fora(|f| f.anular_remotos(motivo::RELACAO, |d, r| d == chave && r == relacao));
}

/// O gate recusou, pela política, uma leitura ou escrita do fluxo que o
/// pedido nomeia: o fluxo acaba, com o motivo do gate. A taxa não encerra.
/// Chamada por [`crate::autorizacao::autorizar`].
pub fn recusado_pelo_gate(chamador: Chamador, nome: &str, params: Json, codigo: Codigo, m: &str) {
    if !recusa_encerra(nome, codigo) {
        return;
    }
    let Some((titular, quem)) = de_quem(chamador) else {
        return;
    };
    let Some(n) = params
        .member(PARAMETRO)
        .and_then(|v| v.as_str())
        .and_then(ler_id_global)
    else {
        return;
    };
    let m = format!("{}: {m}", codigo.nome());
    encerrar_por_fora(|f| {
        // Só o vivo de quem pede: a lápide e o de outro não são deste
        // pedido.
        if f.aberto_para(titular, quem, n) {
            f.abortar(n, &m).into_iter().collect()
        } else {
            Vec::new()
        }
    });
}

/// O número de um id deste boot, pela época da tabela — fora dela.
fn ler_id_global(texto: &str) -> Option<u64> {
    let epoca = se_ha_tabela(|t| t.epoca)?;
    ler_id(&epoca, texto)
}

/// Os prazos — o aceite, a inatividade — e o desligamento: o que venceu
/// sai, e vai para a auditoria. Chamada pelo coletor de fios, uma vez por
/// segundo basta.
pub fn passada_do_coletor() {
    use core::sync::atomic::{AtomicU64, Ordering};
    static ULTIMA: AtomicU64 = AtomicU64::new(0);
    let agora = crate::tempo::uptime_ms();
    let desligando = crate::energia::pedida().is_some();
    if !desligando && agora.saturating_sub(ULTIMA.load(Ordering::Relaxed)) < 1_000 {
        return;
    }
    ULTIMA.store(agora, Ordering::Relaxed);
    let Some((vivos, desligou)) = se_ha_tabela(|t| (t.fluxos.contagem().0 > 0, t.desligou)) else {
        return;
    };
    if desligando {
        // Uma vez: o que abre depois já é recusado na abertura.
        if !desligou {
            encerrar_por_fora(|f| f.abortar_todos(motivo::DESLIGANDO));
            se_ha_tabela(|t| t.desligou = true);
        }
        return;
    }
    if desligou {
        // A ação acabou sem a máquina parar — só a suíte vê isto: o
        // próximo desligamento encerra de novo.
        se_ha_tabela(|t| t.desligou = false);
    }
    if vivos {
        encerrar_por_fora(|f| f.vencer(agora));
    }
}

/// Só para a suíte: os prazos como se o relógio marcasse `agora_ms` — o
/// do aceite e o da inatividade vencem sem esperar o tempo de verdade.
#[cfg(feature = "modo-teste")]
pub fn vencer_de_teste(agora_ms: u64) {
    encerrar_por_fora(|f| f.vencer(agora_ms));
}

/// As medidas dos fluxos, para `security.metrics`: os vivos, os que têm
/// uma ponta noutro Duke, e o maior que um buffer de sentido chegou a ter
/// desde o boot — a memória de um sentido nunca passa do teto dele, venha o
/// que vier do par.
pub fn medidas() -> (usize, usize, usize) {
    se_ha_tabela(|t| {
        (
            t.fluxos.contagem().0,
            t.fluxos.remotos_vivos(),
            t.fluxos.pico_do_buffer(),
        )
    })
    .unwrap_or((0, 0, 0))
}

/// Quantos fluxos vivos e quantos pedidos — para a suíte.
#[cfg(feature = "modo-teste")]
pub fn contagem() -> (usize, usize) {
    se_ha_tabela(|t| t.fluxos.contagem()).unwrap_or((0, 0))
}

/// Para o invariante da suíte: a tabela nunca quebra as regras dela.
#[cfg(feature = "modo-teste")]
pub fn coerente() -> bool {
    se_ha_tabela(|t| t.fluxos.coerente()).unwrap_or(true)
}

/// Só para a suíte: se há quem espere em `a`.
#[cfg(feature = "modo-teste")]
pub fn tem_espera_de_teste(a: Aguardo) -> bool {
    se_ha_tabela(|t| t.esperas.contains_key(&a)).unwrap_or(false)
}

/// Só para a suíte: o número de um id deste boot.
#[cfg(feature = "modo-teste")]
pub fn numero_de_teste(texto: &str) -> Option<u64> {
    ler_id_global(texto)
}

/// Esvazia a tabela, para a suíte: cada caso começa sem fluxos. A época
/// continua: um id de um caso não vale no seguinte.
#[cfg(feature = "modo-teste")]
pub fn esvaziar_de_teste() {
    let feito = se_ha_tabela(|t| {
        let es = t.fluxos.abortar_todos("teste");
        // As lápides também saem: cada caso começa limpo.
        let epoca = t.epoca;
        let mut w = encerrados_na_tabela(t, &es);
        w.extend(t.esperas.values_mut().filter_map(Option::take));
        t.esperas.clear();
        t.sessoes.clear();
        t.fluxos.esquecer_lapides();
        t.desligou = false;
        (epoca, w)
    });
    if let Some((_, w)) = feito {
        acordar(w);
    }
    par::esvaziar_de_teste();
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
