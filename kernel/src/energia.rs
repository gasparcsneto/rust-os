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
//! 3. A resposta sai, e o fio `energia` espera [`ESPERA_MS`] — o bastante
//!    para ela atravessar o canal. Então ele para as gravações: toma a
//!    ordem da persistência, que espera a operação de autoridade em curso
//!    acabar e não deixa outra começar, e a tranca do disco, que espera a
//!    escrita em curso; descarrega o disco; e, com as duas na mão, entrega
//!    a máquina ao firmware — a ACPI no x86, a PSCI no ARM.
//!
//! Uma gravação que não chegou ao fim antes disso é a mesma de um corte de
//! energia, que o journal e o volume do armazém já tratam; aqui ela não
//! acontece, porque nenhuma fica no meio.
//!
//! # O que não é
//!
//! Nem um caminho de autorização — quem decide é o gate, ou a prova —, nem
//! um jeito de pular a auditoria: o pedido que não chega ao journal não
//! reinicia nada. Uma segunda ação, com a primeira a caminho, é recusada.
//!
//! # Na suíte
//!
//! O fio faz tudo, menos a última chamada: com as travas na mão, ele anota
//! a ação em vez de entregá-la ao firmware, e acaba. É o que os casos
//! conferem.

use core::sync::atomic::{AtomicU8, Ordering};

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

/// Leva ao journal o registro `registro` — o do pedido de `acao`, que
/// quem chama acabou de gravar na auditoria: a execução do comando, ou a
/// autorização da operação administrativa — e lança o fio que para a
/// máquina.
///
/// `Err` sem efeito nenhum: outra ação a caminho, nenhum registro, uma
/// máquina cujo firmware não diz como fazer a ação, a persistência
/// indisponível, o registro que não chegou ao journal, o fio que não
/// subiu. Só os handlers dos comandos — depois do gate — e as operações
/// administrativas — depois da prova — chamam; o `xtask` confere.
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
    if let Err(motivo) = crate::fios::criar("energia", parar, acao as u64) {
        PEDIDA.store(0, Ordering::Release);
        return Err(motivo);
    }
    Ok(())
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

/// A ação a caminho, se há uma.
pub fn pedida() -> Option<Acao> {
    Acao::de(u64::from(PEDIDA.load(Ordering::Acquire)))
}

/// O fio `energia`: espera, para as gravações e entrega a máquina.
extern "C" fn parar(argumento: u64) -> ! {
    let Some(acao) = Acao::de(argumento) else {
        crate::fios::terminar()
    };
    crate::fios::bloquear_em(crate::tarefas::relogio::por_ms(ESPERA_MS));
    crate::log_warn!("energia", "{}: as gravacoes param agora", acao.nome());
    crate::persistencia::parar_as_gravacoes(|| entregar(acao));
    terminar_na_suite()
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

/// O fim do fio na suíte, que não entregou nada: a próxima ação pode ser
/// pedida. Fora da suíte, inalcançável — `entregar` não volta.
fn terminar_na_suite() -> ! {
    PEDIDA.store(0, Ordering::Release);
    crate::fios::terminar()
}

/// Só na suíte: a ação que o fio entregaria, se já chegou lá — e a
/// esquece.
#[cfg(feature = "modo-teste")]
pub fn executada_de_teste() -> Option<Acao> {
    Acao::de(u64::from(EXECUTADA.swap(0, Ordering::AcqRel)))
}
