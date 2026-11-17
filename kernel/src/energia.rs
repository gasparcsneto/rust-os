//! Reiniciar e desligar a máquina: `system.reboot` e `system.poweroff`.
//!
//! # A ordem
//!
//! 1. O gate decidiu, pela permissão `system.power` e pelo papel de quem
//!    pede — o `sistema` pelo gate, o administrador pela prova.
//! 2. Quem pede grava o pedido na auditoria — a execução do comando, ou a
//!    autorização da operação administrativa —, e [`preparar`] o leva ao
//!    journal antes de qualquer outra coisa: sem o registro no disco, a
//!    máquina segue ligada (*fail closed*). É a mesma regra da assinatura
//!    — o registro vai antes do efeito.
//! 3. A resposta sai, e o fio `energia`, que [`preparar`] acordou, espera
//!    [`ESPERA_MS`] — o bastante para ela atravessar o canal. Então ele
//!    para as gravações: toma a ordem da persistência, que espera a
//!    operação de autoridade em curso acabar e não deixa outra começar, e a
//!    tranca do disco, que espera a escrita em curso; descarrega o disco;
//!    e, com as duas na mão, entrega a máquina ao firmware — a ACPI no x86,
//!    a PSCI no ARM.
//!
//! Uma gravação que não chegou ao fim antes disso é a mesma de um corte de
//! energia, que o journal e o volume do armazém já tratam; aqui ela não
//! acontece, porque nenhuma fica no meio.
//!
//! # O fio nasce no boot
//!
//! O fio `energia` nasce no boot ([`iniciar`]), parado, como o do botão de
//! energia, e o pedido só o acorda. Nascia a cada pedido, depois de o
//! registro ir ao journal: com a tabela de fios cheia — vários titulares,
//! cada um dentro da cota dele, a enchem —, o pedido gravado no journal
//! falhava sem parar a máquina, justamente quando reiniciar era o remédio.
//! No boot a tabela está vazia; e, se o fio não subir mesmo assim, o
//! pedido é recusado antes do journal, sem efeito nenhum — como no
//! post-mortem, em que o escalonamento congelado não deixa fio nenhum
//! rodar.
//!
//! # O que não é
//!
//! Nem um caminho de autorização — quem decide é o gate, ou a prova —, nem
//! um jeito de pular a auditoria: o pedido que não chega ao journal não
//! reinicia nada. Uma segunda ação, com a primeira a caminho, é recusada.
//! Acordar o fio não decide nada: ele só faz a ação que [`preparar`] pôs
//! a caminho, depois do registro no journal.
//!
//! # Na suíte
//!
//! O fio faz tudo, menos a última chamada: com as travas na mão, ele anota
//! a ação em vez de entregá-la ao firmware, e volta a esperar a próxima. É
//! o que os casos conferem.
//!
//! O caso que pede alguma coisa com a ação a caminho — e espera `CONFLICT`,
//! `desligando` ou `rebooting` — não pode depender do meio segundo: numa
//! suíte carregada, o fio parava as gravações e a ação deixava de estar a
//! caminho antes de o caso pedir. O caso segura o fio (`Segura`, só da
//! suíte) antes da ação: o fio espera o meio segundo, como sempre, e fica
//! parado ali, antes de parar as gravações, até o caso soltar — com a ação
//! a caminho, como na janela. Fora da suíte, o gancho não existe.

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use core::task::Waker;

use crate::trava::Mutex;

/// O que se pede à máquina.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Acao {
    Reiniciar = 1,
    Desligar = 2,
}

impl Acao {
    /// O nome, como a resposta e a auditoria o escrevem.
    pub const fn nome(self) -> &'static str {
        match self {
            Acao::Reiniciar => "reboot",
            Acao::Desligar => "poweroff",
        }
    }

    /// O estado que a resposta diz.
    pub const fn estado(self) -> &'static str {
        match self {
            Acao::Reiniciar => "rebooting",
            Acao::Desligar => "powering_off",
        }
    }

    fn de(n: u64) -> Option<Acao> {
        match n {
            1 => Some(Acao::Reiniciar),
            2 => Some(Acao::Desligar),
            _ => None,
        }
    }
}

/// Quanto o fio espera entre a resposta e o fim das gravações: a resposta
/// atravessa a serial, uma porta virtio ou o canal TCP, cifrada, em
/// milissegundos; meio segundo deixa folga para uma máquina carregada, e
/// é pouco para quem pediu.
pub const ESPERA_MS: u64 = 500;

/// A ação já pedida, ou zero. A segunda é recusada: a máquina já vai.
static PEDIDA: AtomicU8 = AtomicU8::new(0);

/// Só na suíte: a ação que o fio teria entregue ao firmware.
#[cfg(feature = "modo-teste")]
static EXECUTADA: AtomicU8 = AtomicU8::new(0);

/// O fio `energia`, nascido no boot por [`iniciar`]: o número dele, ou zero
/// se ele não nasceu.
static FIO: AtomicU64 = AtomicU64::new(0);

/// Quem acordar quando uma ação é posta a caminho: o fio `energia`, parado.
static DESPERTADOR: Mutex<Option<Waker>> = Mutex::new(None);

/// Põe no ar o fio `energia` — uma vez, no boot —, parado até um pedido:
/// ver "O fio nasce no boot", acima.
///
/// No boot a tabela de fios está vazia, e o que faria a criação falhar aqui
/// é a memória da pilha. Sem o fio, o boot segue — como sem o coletor, em
/// `fios::init` —, o log diz por quê, e cada pedido de reiniciar ou
/// desligar é recusado antes do journal, sem efeito nenhum ([`preparar`]).
pub fn iniciar() {
    if FIO.load(Ordering::Acquire) != 0 {
        return;
    }
    match crate::fios::criar("energia", laco, 0) {
        Ok(id) => {
            FIO.store(id.numero(), Ordering::Release);
            crate::log_info!(
                "energia",
                "o fio da energia no ar, parado, no fio {}",
                id.numero()
            );
        }
        Err(motivo) => crate::log_error!(
            "energia",
            "o fio da energia nao subiu: {}; reiniciar e desligar serao recusados",
            motivo
        ),
    }
}

/// Leva ao journal o registro `registro` — o do pedido de `acao`, que
/// quem chama acabou de gravar na auditoria: a execução do comando, ou a
/// autorização da operação administrativa — e acorda o fio que para a
/// máquina, nascido no boot.
///
/// `Err` sem efeito nenhum: outra ação a caminho, nenhum registro, uma
/// máquina cujo firmware não diz como fazer a ação, o fio que não subiu no
/// boot, o escalonamento congelado por uma falha fatal, a persistência
/// indisponível, o registro que não chegou ao journal. Tudo isso antes do
/// ponto sem volta. Depois do registro no journal, só recusa a outra ação
/// que chegou primeiro — e a máquina para por ela —: acordar o fio não pede
/// vaga nem memória, e não falha. Só os handlers dos comandos — depois do
/// gate — e as operações administrativas — depois da prova — chamam; o
/// `xtask` confere.
pub fn preparar(acao: Acao, registro: u64) -> Result<(), &'static str> {
    if PEDIDA.load(Ordering::Acquire) != 0 {
        return Err("a maquina ja esta reiniciando ou desligando");
    }
    if registro == 0 {
        return Err("fora de um comando autorizado");
    }
    // Sem o meio no firmware, a ação seria aceita, as gravações parariam e
    // a máquina ficaria parada sem desligar: recusada antes, com a máquina
    // seguindo como estava.
    if meio(acao) == "nenhum" {
        return Err(match acao {
            Acao::Reiniciar => "esta maquina nao diz como reiniciar: ela segue ligada",
            Acao::Desligar => {
                "esta maquina nao diz como desligar (nem o S5 da ACPI, nem a PSCI): ela segue ligada"
            }
        });
    }
    // Sem o fio, ninguém pararia a máquina: recusada antes do journal, como
    // sem o meio no firmware.
    if FIO.load(Ordering::Acquire) == 0 {
        return Err("o fio da energia nao subiu no boot: a maquina segue");
    }
    // Nem com o escalonamento congelado por uma falha fatal — o
    // post-mortem, que segue atendendo o canal —: o fio não roda mais, e a
    // resposta diria `rebooting` sem nada acontecer. Recusada antes do
    // journal, com o motivo de quando o fio nascia a cada pedido e a
    // criação dele recusava aqui.
    if crate::fios::congelado() {
        return Err("o escalonador esta congelado apos uma falha fatal");
    }
    crate::persistencia::exigir()
        .map_err(|_| "sem persistencia, a maquina nao para: o pedido nao chegaria ao journal")?;
    crate::persistencia::gravar_auditoria_ate(registro)
        .map_err(|_| "o registro do pedido nao chegou ao journal: a maquina segue")?;
    if PEDIDA
        .compare_exchange(0, acao as u8, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("a maquina ja esta reiniciando ou desligando");
    }
    acordar();
    Ok(())
}

/// Acorda o fio `energia`, se ele espera. Acordar por referência não
/// libera nada com a trava na mão — como no botão.
fn acordar() {
    crate::arch::sem_interrupcoes(|| {
        if let Some(w) = DESPERTADOR.lock().as_ref() {
            w.wake_by_ref();
        }
    });
}

/// Como a máquina faz `acao`, pelo firmware — o `reboot_via` e o
/// `poweroff_via` do `system.info` —, ou `nenhum`.
fn meio(acao: Acao) -> &'static str {
    #[cfg(feature = "modo-teste")]
    if SEM_MEIO.load(Ordering::Acquire) {
        return "nenhum";
    }
    let (reinicio, desligamento) = crate::arch::meios_da_energia();
    match acao {
        Acao::Reiniciar => reinicio,
        Acao::Desligar => desligamento,
    }
}

/// Só na suíte: a máquina como se o firmware não dissesse como reiniciar
/// nem desligar.
#[cfg(feature = "modo-teste")]
static SEM_MEIO: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Só na suíte: liga ou desliga [`SEM_MEIO`].
#[cfg(feature = "modo-teste")]
pub fn sem_meio_de_teste(sem: bool) {
    SEM_MEIO.store(sem, Ordering::Release);
}

/// O detalhe do registro do pedido, como o comando o grava.
pub fn detalhe_do_pedido(acao: Acao) -> alloc::string::String {
    alloc::format!(
        "{}: pedido; as gravacoes param em {} ms",
        acao.nome(),
        ESPERA_MS
    )
}

/// O reinício que a reconciliação da atualização A/B decide no boot — ver
/// [`crate::slots`]: o kernel devolve a máquina ao slot que o controle de
/// boot, regravado pelo journal, diz. Sem pedido de ninguém e sem gate: é
/// o boot recusado, antes de qualquer serviço, e não uma operação. A
/// auditoria até `seq` — a recusa — vai ao journal, se ele está de pé; as
/// gravações param, com a ordem da persistência e a tranca do disco na mão;
/// e o firmware reinicia. Na suíte, só a auditoria: o caso confere o pedido
/// por `slots::reinicio_pedido_de_teste`.
pub fn reiniciar_pela_atualizacao(seq: u64) {
    if crate::persistencia::estado() == crate::persistencia::Estado::Disponivel {
        let _ = crate::persistencia::gravar_auditoria_ate(seq);
    }
    #[cfg(not(feature = "modo-teste"))]
    crate::persistencia::parar_as_gravacoes(|| entregar(Acao::Reiniciar));
}

/// A ação a caminho, se há uma.
pub fn pedida() -> Option<Acao> {
    Acao::de(u64::from(PEDIDA.load(Ordering::Acquire)))
}

/// O fio `energia`: parado desde o boot até [`preparar`] pôr uma ação a
/// caminho e acordá-lo; então espera, para as gravações e entrega a
/// máquina. Fora da suíte, não volta; na suíte, que só anota, volta a
/// esperar a próxima.
extern "C" fn laco(_argumento: u64) -> ! {
    loop {
        let acao = crate::fios::bloquear_em(AcaoPedida);
        parar(acao);
    }
}

/// Pronta com a ação que [`preparar`] pôs a caminho; o waker fica em
/// [`DESPERTADOR`] — o `ProximoAperto` do botão, para a ação.
struct AcaoPedida;

impl core::future::Future for AcaoPedida {
    type Output = Acao;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context,
    ) -> core::task::Poll<Acao> {
        use core::task::Poll;
        if let Some(acao) = pedida() {
            return Poll::Ready(acao);
        }
        // O waker anterior é largado fora da trava: pode ser o último dono
        // dele, e devolver memória toma a trava do alocador.
        let anterior =
            crate::arch::sem_interrupcoes(|| DESPERTADOR.lock().replace(cx.waker().clone()));
        drop(anterior);
        // De novo, com o despertador no lugar: um pedido entre a primeira
        // olhada e o registro não espera o próximo.
        match pedida() {
            Some(acao) => Poll::Ready(acao),
            None => Poll::Pending,
        }
    }
}

/// A ação: espera, para as gravações e entrega a máquina ao firmware.
fn parar(acao: Acao) {
    crate::fios::bloquear_em(crate::tarefas::relogio::por_ms(ESPERA_MS));
    #[cfg(feature = "modo-teste")]
    esperar_a_suite();
    crate::log_warn!("energia", "{}: as gravacoes param agora", acao.nome());
    crate::persistencia::parar_as_gravacoes(|| entregar(acao));
    // Só na suíte se chega aqui — `entregar` não volta fora dela —, sem nada
    // entregue: a próxima ação pode ser pedida.
    PEDIDA.store(0, Ordering::Release);
}

/// Entrega a máquina ao firmware. Na suíte, só anota.
fn entregar(acao: Acao) {
    #[cfg(feature = "modo-teste")]
    EXECUTADA.store(acao as u8, Ordering::Release);
    #[cfg(not(feature = "modo-teste"))]
    match acao {
        Acao::Reiniciar => crate::arch::reiniciar_a_maquina(),
        Acao::Desligar => crate::arch::desligar_a_maquina(),
    }
}

/// Só na suíte: a ação que o fio entregaria, se já chegou lá — e a
/// esquece.
#[cfg(feature = "modo-teste")]
pub fn executada_de_teste() -> Option<Acao> {
    Acao::de(u64::from(EXECUTADA.swap(0, Ordering::AcqRel)))
}

/// Só na suíte: quantas [`Segura`] estão vivas. Com alguma, o fio que
/// acaba a espera fica parado antes de parar as gravações.
#[cfg(feature = "modo-teste")]
static SEGURAS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Só na suíte: o fio está parado no gancho agora.
#[cfg(feature = "modo-teste")]
static PARADO_NA_SUITE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Só na suíte: enquanto viva, o fio `energia` que acabar a espera fica
/// parado antes de parar as gravações — com a ação a caminho, como na
/// janela do meio segundo —, para o caso pedir o que depende dela sem
/// depender do relógio. Tomada **antes** da ação; largada antes de
/// esperar a entrega (`energia_entregue`, na suíte). Largar solta — também
/// o caso que falha no meio não deixa o fio parado para os seguintes.
#[cfg(feature = "modo-teste")]
#[must_use = "largada na hora, a Segura nao segura nada"]
pub struct Segura(());

#[cfg(feature = "modo-teste")]
impl Segura {
    pub fn de_teste() -> Segura {
        SEGURAS.fetch_add(1, Ordering::SeqCst);
        Segura(())
    }
}

#[cfg(feature = "modo-teste")]
impl Drop for Segura {
    fn drop(&mut self) {
        SEGURAS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Só na suíte: o fio está parado no gancho de [`Segura`] — acabou a
/// espera, e não parou as gravações.
#[cfg(feature = "modo-teste")]
pub fn parado_na_suite_de_teste() -> bool {
    PARADO_NA_SUITE.load(Ordering::SeqCst)
}

/// O gancho de [`Segura`]: com alguma viva, o fio fica aqui, dormindo de
/// tique em tique, até a última ser largada.
#[cfg(feature = "modo-teste")]
fn esperar_a_suite() {
    if SEGURAS.load(Ordering::SeqCst) == 0 {
        return;
    }
    PARADO_NA_SUITE.store(true, Ordering::SeqCst);
    while SEGURAS.load(Ordering::SeqCst) > 0 {
        crate::fios::bloquear_em(crate::tarefas::relogio::por_ms(2));
    }
    PARADO_NA_SUITE.store(false, Ordering::SeqCst);
}

/// Destrava o despertador, para o caminho de falha fatal. No post-mortem o
/// pedido é recusado antes de acordar o fio ([`preparar`]), e ninguém o
/// toma; destravado como toda trava que o canal do agente alcança.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        DESPERTADOR.force_unlock();
    }
}
