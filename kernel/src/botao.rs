//! O botão de energia: um evento do hardware, e não uma autoridade.
//!
//! # O caminho
//!
//! ```text
//!   aperto ─► interrupção: o SCI da ACPI no x86, a do PL061 da tecla no ARM
//!          ─► o tratador do `arch`: lê o estado do hardware e o limpa
//!          ─► [`apertado`]: conta e acorda o fio `botao` — nada mais
//!          ─► o fio `botao`: o aperto na auditoria (`power.button`), e o
//!             pedido `system.poweroff` ao gate, com a autoridade do
//!             próprio fio — a local, a do sistema
//!          ─► o gate: a política decide `system.power` pelo papel da
//!             linha `local`
//!          ─► o handler: o pedido na auditoria e no journal, e a energia
//!          ─► as gravações param, e o firmware desliga (o S5 da ACPI, o
//!             `SYSTEM_OFF` da PSCI)
//! ```
//!
//! Como cada máquina avisa o aperto mora no `arch` — ver
//! `arch::x86_64::botao` e `arch::aarch64::botao`; daqui para a frente, o
//! caminho é o de um `system.poweroff` qualquer.
//!
//! # O botão não é ninguém
//!
//! O aperto não traz identidade: não é uma pessoa, um agente, uma
//! credencial nem um serviço, e não tem papel na política. Quem pede o
//! desligamento é o sistema — a autoridade local, que é a de todo fio do
//! kernel e que a política diz poder desligar (`system.power` no papel da
//! linha `local`). O pedido passa pelo mesmo gate, pela mesma permissão e
//! pelo mesmo handler de um `system.poweroff` de agente: uma política que
//! tire o `system.power` do papel local tira também o botão, e o aperto fica
//! na auditoria, recusado. Nada aqui chama a energia por fora — o `xtask`
//! confere que `energia::preparar` só é chamada pelos handlers e pelas
//! operações administrativas, e que só o `arch` diz um aperto.
//!
//! # Um desligamento, quantos apertos houver
//!
//! O tratador só conta. O fio junta num só pedido os apertos que acha numa
//! rodada; com a máquina já parando — por este botão, por um comando, por
//! uma operação administrativa —, não pede nada: conta os apertos como
//! ignorados. A energia, por sua vez, aceita uma ação de cada vez, por
//! qualquer caminho (ver [`crate::energia`]). Depois de uma rodada que tomou
//! apertos, o fio espera [`INTERVALO_MS`]: um botão que não para de
//! apertar — ou um hardware que mente — não enche a auditoria nem o log.
//!
//! # O que a auditoria diz
//!
//! - o aperto: `power.button`, pelo titular `kernel`, com o recurso dizendo
//!   como a máquina avisou (`acpi`, `gpio-keys`) e o detalhe, quantos
//!   apertos e o fio que pede;
//! - o pedido do sistema: `system.poweroff`, pelo titular `system`, com o
//!   papel da linha `local`, "pelo processo N (kernel)", e a decisão — ou a
//!   recusa e o porquê;
//! - o que a energia fez: o pedido de desligar, no journal antes de a
//!   máquina parar, ou a recusa e o motivo — sem persistência, sem meio no
//!   firmware, outra ação a caminho;
//! - e o botão desligado numa tempestade de interrupções: `power.button`
//!   com o código de erro e o motivo.
//!
//! # Antes de o sistema estar de pé
//!
//! O botão só é ligado depois do journal e da reconciliação da atualização
//! — ver `main.rs` —, e o aperto de antes, o que ligou a máquina inclusive,
//! é limpo no hardware: não pede nada.

use alloc::format;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use core::task::Waker;

use protocolo::json::{Json, JsonWriter};

use crate::autorizacao::Chamador;
use crate::trava::Mutex;

/// A espera do fio entre uma rodada que pediu e a seguinte.
pub const INTERVALO_MS: u64 = 1_000;

/// O pedido que o sistema faz ao gate, o mesmo de um agente.
const PEDIDO: &str = r#"{"jsonrpc":"2.0","id":1,"method":"system.poweroff","params":{}}"#;

/// Como a máquina avisa o aperto — `acpi`, `gpio-keys` —, ou por que não
/// avisa; decidido uma vez, no boot. `None` antes disso.
static MEIO: Mutex<Option<Result<&'static str, &'static str>>> = Mutex::new(None);

fn meio() -> Option<Result<&'static str, &'static str>> {
    crate::arch::sem_interrupcoes(|| *MEIO.lock())
}

/// Os apertos que o hardware disse, contados pelo tratador.
static APERTOS: AtomicU64 = AtomicU64::new(0);

/// Os apertos que uma rodada já tomou.
static VISTOS: AtomicU64 = AtomicU64::new(0);

/// As rodadas que pediram o desligamento ao gate.
static PEDIDOS: AtomicU64 = AtomicU64::new(0);

/// Os apertos que chegaram com a máquina já parando.
static IGNORADOS: AtomicU64 = AtomicU64::new(0);

/// As interrupções da linha do botão sem o botão nem dispositivo que as
/// reclamasse.
static SEM_O_BOTAO: AtomicU64 = AtomicU64::new(0);

/// O botão desligado pelo tratador numa tempestade — o número de um
/// [`Desligamento`], ou zero —, e se o fio já o registrou.
static DESLIGAMENTO: AtomicU8 = AtomicU8::new(0);
static DESLIGAMENTO_REGISTRADO: AtomicBool = AtomicBool::new(false);

/// Uma rodada de cada vez.
static VEZ: AtomicBool = AtomicBool::new(false);

/// Quem acordar quando há o que fazer: o fio `botao`.
static DESPERTADOR: Mutex<Option<Waker>> = Mutex::new(None);

/// Por que o tratador desligou o botão.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Desligamento {
    /// A linha disparou seguidas vezes sem o botão e sem dispositivo que a
    /// reclamasse.
    SemDono = 1,
    /// O estado do botão não se limpa: o hardware o mantém ligado.
    NaoLimpa = 2,
}

impl Desligamento {
    fn de(n: u8) -> Option<Desligamento> {
        match n {
            1 => Some(Desligamento::SemDono),
            2 => Some(Desligamento::NaoLimpa),
            _ => None,
        }
    }

    /// O motivo, como a auditoria e o `system.info` o dizem.
    pub const fn motivo(self) -> &'static str {
        match self {
            Desligamento::SemDono => {
                "a linha do botao disparou seguidas vezes sem ele: o botao foi desligado"
            }
            Desligamento::NaoLimpa => "o estado do botao nao se limpa: o botao foi desligado",
        }
    }
}

/// Acorda o fio, se ele espera. Do tratador: a trava é tomada com as
/// interrupções já mascaradas, e acordar por referência não libera nada —
/// como `tarefas::relogio::tique`.
fn acordar() {
    crate::arch::sem_interrupcoes(|| {
        if let Some(w) = DESPERTADOR.lock().as_ref() {
            w.wake_by_ref();
        }
    });
}

/// O botão foi apertado: o tratador do `arch` leu o estado do hardware e o
/// limpou. Conta e acorda — não decide nem pede nada.
pub fn apertado() {
    APERTOS.fetch_add(1, Ordering::AcqRel);
    acordar();
}

/// Uma interrupção da linha do botão, sem ele.
pub fn sem_o_botao() {
    SEM_O_BOTAO.fetch_add(1, Ordering::Relaxed);
}

/// O tratador desligou o botão, pelo motivo `d`: o fio o registra.
pub fn desligado_pelo_hardware(d: Desligamento) {
    if DESLIGAMENTO
        .compare_exchange(0, d as u8, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        acordar();
    }
}

/// Liga o evento do hardware — uma vez, no boot — e diz como a máquina
/// avisa o aperto, ou por que não avisa.
pub fn ligar() -> Result<&'static str, &'static str> {
    if let Some(meio) = meio() {
        return meio;
    }
    let meio = crate::arch::ligar_o_botao();
    crate::arch::sem_interrupcoes(|| *MEIO.lock() = Some(meio));
    match meio {
        Ok(via) => crate::log_info!("botao", "o botao de energia avisa por {}", via),
        Err(motivo) => crate::log_warn!("botao", "sem botao de energia: {}", motivo),
    }
    meio
}

/// Liga o botão e põe o fio que pede o desligamento ao gate. Na suíte, só
/// o hardware: cada caso faz as rodadas dele, por [`passo`].
pub fn iniciar() {
    let meio = ligar();
    #[cfg(not(feature = "modo-teste"))]
    if meio.is_ok() {
        match crate::fios::criar("botao", laco, 0) {
            Ok(id) => crate::log_info!("botao", "o botao de energia no fio {}", id.numero()),
            Err(motivo) => crate::log_error!(
                "botao",
                "o fio do botao nao subiu: {}; os apertos ficam contados, sem pedido",
                motivo
            ),
        }
    }
    #[cfg(feature = "modo-teste")]
    let _ = meio;
}

/// O fio do botão: espera o que fazer, faz uma rodada e, se ela tomou
/// apertos, espera o intervalo.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
extern "C" fn laco(_argumento: u64) -> ! {
    loop {
        crate::fios::bloquear_em(ProximoAperto);
        if let Passo::Pedido { .. } | Passo::JaParando { .. } = passo() {
            crate::fios::bloquear_em(crate::tarefas::relogio::por_ms(INTERVALO_MS));
        }
    }
}

/// Se há o que fazer: um aperto que nenhuma rodada tomou, ou um
/// desligamento que o fio não registrou.
fn ha_o_que_fazer() -> bool {
    APERTOS.load(Ordering::Acquire) > VISTOS.load(Ordering::Acquire)
        || (DESLIGAMENTO.load(Ordering::Acquire) != 0
            && !DESLIGAMENTO_REGISTRADO.load(Ordering::Acquire))
}

/// Pronto quando [`ha_o_que_fazer`]; o waker fica em [`DESPERTADOR`].
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
struct ProximoAperto;

impl core::future::Future for ProximoAperto {
    type Output = ();

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> core::task::Poll<()> {
        use core::task::Poll;
        if ha_o_que_fazer() {
            return Poll::Ready(());
        }
        let waker = cx.waker().clone();
        crate::arch::sem_interrupcoes(|| *DESPERTADOR.lock() = Some(waker));
        // De novo, com o despertador no lugar: um aperto entre a primeira
        // olhada e o registro não espera o próximo.
        if ha_o_que_fazer() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// O que uma rodada fez — o fio só olha se ela pediu; a suíte, o resto.
#[derive(Debug)]
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub enum Passo {
    /// Nenhum aperto novo.
    Nada,
    /// Outra rodada em curso: ela toma os apertos.
    Ocupado,
    /// Os apertos chegaram com a máquina já parando: nada foi pedido.
    JaParando {
        apertos: u64,
        acao: crate::energia::Acao,
    },
    /// O sistema pediu o desligamento ao gate: o registro do aperto na
    /// auditoria, e o envelope da resposta — o desligamento aceito, ou a
    /// recusa do gate ou da energia.
    Pedido {
        apertos: u64,
        evento: u64,
        envelope: String,
    },
}

/// Libera a vez ao sair da rodada.
struct Vez;

impl Drop for Vez {
    fn drop(&mut self) {
        VEZ.store(false, Ordering::Release);
    }
}

/// Uma rodada: registra o desligamento do botão, se o tratador o desligou;
/// toma os apertos que chegaram; e, se a máquina não está parando, grava o
/// aperto na auditoria e pede `system.poweroff` ao gate com a autoridade
/// do fio que roda a rodada. Só o fio do botão e a suíte chamam — o `xtask`
/// confere.
pub fn passo() -> Passo {
    if VEZ
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Passo::Ocupado;
    }
    let _vez = Vez;
    let via = meio().and_then(|m| m.ok()).unwrap_or("nenhum");

    if let Some(d) = Desligamento::de(DESLIGAMENTO.load(Ordering::Acquire))
        && !DESLIGAMENTO_REGISTRADO.swap(true, Ordering::AcqRel)
    {
        crate::log_error!("botao", "{}", d.motivo());
        crate::autorizacao::auditar_do_kernel(
            "power.button",
            via,
            politica::Codigo::Error,
            d.motivo(),
        );
    }

    let apertos = APERTOS.load(Ordering::Acquire);
    let vistos = VISTOS.load(Ordering::Acquire);
    if apertos <= vistos {
        return Passo::Nada;
    }
    VISTOS.store(apertos, Ordering::Release);
    let novos = apertos - vistos;

    if let Some(acao) = crate::energia::pedida() {
        IGNORADOS.fetch_add(novos, Ordering::Relaxed);
        crate::log_info!(
            "botao",
            "o botao de energia com o {} ja a caminho: nada a pedir",
            acao.nome()
        );
        return Passo::JaParando {
            apertos: novos,
            acao,
        };
    }

    let (fio, programa) = crate::fios::programa_atual();
    let quem = Chamador::Processo {
        fio,
        autoridade: crate::fios::autoridade_atual(),
        programa,
    };
    let evento = crate::autorizacao::auditar_do_kernel(
        "power.button",
        via,
        politica::Codigo::Allow,
        &format!("{novos} aperto(s); o sistema pede o desligamento pelo fio {fio}"),
    );
    PEDIDOS.fetch_add(1, Ordering::Relaxed);
    let resposta = crate::nativo::responder_pelo_kernel(quem, PEDIDO.as_bytes());
    let envelope = String::from_utf8_lossy(resposta.como_bytes()).into_owned();
    relatar(&envelope);
    Passo::Pedido {
        apertos: novos,
        evento,
        envelope,
    }
}

/// O desfecho do pedido, no log: o desligamento a caminho, a recusa da
/// energia, ou a do gate.
fn relatar(envelope: &str) {
    let e = Json(envelope.as_bytes());
    match e.member("result") {
        Some(r) => match r.member("error").and_then(|m| m.as_str()) {
            None => crate::log_warn!(
                "botao",
                "o botao de energia: o sistema desliga a maquina (registro {})",
                r.member("record").and_then(|n| n.as_u64()).unwrap_or(0)
            ),
            Some(motivo) => {
                crate::log_warn!("botao", "o botao de energia: a energia recusou: {}", motivo)
            }
        },
        None => crate::log_warn!(
            "botao",
            "o botao de energia: o gate recusou o desligamento ({})",
            e.member("error")
                .and_then(|x| x.member("data"))
                .and_then(|d| d.as_str())
                .unwrap_or("sem codigo")
        ),
    }
}

/// O botão, para o `system.info`: como a máquina avisa — ou por que não —,
/// se o tratador o desligou, e as contas.
pub fn escrever(w: &mut JsonWriter) -> core::fmt::Result {
    w.begin_object()?;
    match meio() {
        Some(Ok(via)) => {
            w.field_str("via", via)?;
            w.key("reason")?;
            w.null_value()?;
        }
        Some(Err(motivo)) => {
            w.field_str("via", "nenhum")?;
            w.field_str("reason", motivo)?;
        }
        None => {
            w.field_str("via", "nenhum")?;
            w.field_str("reason", "o botao ainda nao foi ligado")?;
        }
    }
    w.key("disabled")?;
    match Desligamento::de(DESLIGAMENTO.load(Ordering::Acquire)) {
        Some(d) => w.str_value(d.motivo())?,
        None => w.null_value()?,
    }
    w.field_u64("presses", APERTOS.load(Ordering::Acquire))?;
    w.field_u64("requests", PEDIDOS.load(Ordering::Relaxed))?;
    w.field_u64("ignored", IGNORADOS.load(Ordering::Relaxed))?;
    w.field_u64("without_button", SEM_O_BOTAO.load(Ordering::Relaxed))?;
    w.end_object()
}

/// Só para a suíte: um aperto, como o tratador o diria depois de ler e
/// limpar o hardware — o ponto em que o evento físico vira contagem.
#[cfg(feature = "modo-teste")]
pub fn apertar_de_teste() {
    apertado();
}

/// Só para a suíte: o tratador desligando o botão por `d` — e o
/// desligamento esquecido, para o caso seguinte, com `None`.
#[cfg(feature = "modo-teste")]
pub fn desligamento_de_teste(d: Option<Desligamento>) {
    match d {
        Some(d) => desligado_pelo_hardware(d),
        None => {
            DESLIGAMENTO.store(0, Ordering::Release);
            DESLIGAMENTO_REGISTRADO.store(false, Ordering::Release);
        }
    }
}

/// Só para a suíte: `(apertos, pedidos, ignorados, sem o botão)`.
#[cfg(feature = "modo-teste")]
pub fn contas_de_teste() -> (u64, u64, u64, u64) {
    (
        APERTOS.load(Ordering::Acquire),
        PEDIDOS.load(Ordering::Relaxed),
        IGNORADOS.load(Ordering::Relaxed),
        SEM_O_BOTAO.load(Ordering::Relaxed),
    )
}

/// Só para a suíte: se há o que uma rodada faria.
#[cfg(feature = "modo-teste")]
pub fn pendente_de_teste() -> bool {
    ha_o_que_fazer()
}

/// Destrava o despertador, para o caminho de falha fatal.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        DESPERTADOR.force_unlock();
        MEIO.force_unlock();
    }
}
