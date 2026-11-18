//! Os casos `contador:` — o contador de ciclos fora do anel sem privilégio
//! (o #451). O relógio de um programa é o `system.uptime`, decidido pelo
//! gate; o kernel tira o contador do anel 3 em cada núcleo — o `CR4.TSD`
//! ligado e o `CR4.PCE` desligado, no x86; o `CNTKCTL_EL1` e o
//! `PMUSERENR_EL0` em zero, no ARM —, e o processo que o lê morre pela falha
//! de proteção, como um que executa uma instrução privilegiada.
//!
//! Dois casos, nas duas arquiteturas:
//!
//! - o processo que lê o contador — o `contador`, montado à mão em
//!   `usuario::exemplo`, cuja primeira instrução, a da entrada, é a leitura
//!   — cai em cada núcleo ligado: a contabilidade das falhas diz qual
//!   falha e em que instrução, e o log diz que o processo morreu por ela.
//!   Se a leitura passasse, ele sairia com o código dele
//!   (`exemplo::CODIGO_DO_CONTADOR`);
//! - os bits, em cada núcleo, como o kernel os escreveu.
//!
//! O processo roda num fio do kernel preso ao núcleo, que entra no anel 3
//! pelo `usuario::programa::executar` — o caminho do `invasor`, que lê a
//! memória do kernel. Não passa pelo gate: o que se confere é o processador,
//! e não a decisão.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering::SeqCst};

use super::{Resultado, esperar_ate, linhas_do_programa, nucleos_secundarios};

/// Os núcleos ligados: o primeiro e os secundários.
fn nucleos() -> Vec<usize> {
    let mut nucleos = alloc::vec![0];
    nucleos.extend(nucleos_secundarios());
    nucleos
}

/// O núcleo em que o último hospedeiro do contador rodou, ou `u64::MAX`.
static RODOU: AtomicU64 = AtomicU64::new(u64::MAX);

/// O hospedeiro: anota o núcleo e entra no anel 3 com a imagem do contador.
/// Não volta: o processo morre da falha, ou sai.
extern "C" fn hospedar(_argumento: u64) -> ! {
    RODOU.store(crate::arch::nucleo_atual() as u64, SeqCst);
    match crate::usuario::programa::executar(crate::usuario::exemplo::bytes_do_contador()) {
        Ok(_) => unreachable!("executar nao retorna em caso de sucesso"),
        Err(falha) => {
            crate::log_error!(
                "teste",
                "nao foi possivel entrar em userspace: {}",
                falha.motivo()
            );
            crate::fios::terminar()
        }
    }
}

/// O nome da falha com que o processo que lê o contador morre, como a
/// contabilidade das falhas o guarda, e como o log o diz.
#[cfg(target_arch = "x86_64")]
const FALHA: (&str, &str) = ("general_protection_fault", "falha de protecao");
#[cfg(target_arch = "aarch64")]
const FALHA: (&str, &str) = ("msr_mrs_trap", "msr_mrs_trap");

/// O código da falha é o da leitura do contador: no x86, o `#GP` sem código
/// de erro; no ARM, o `ESR_EL1` da exceção síncrona de um `mrs` — a classe
/// 0x18 — com o `CNTVCT_EL0` (`op0` 3, `op1` 3, `CRn` 14, `CRm` 0, `op2` 2),
/// lido para o `x1`.
fn codigo_da_leitura(codigo: u64) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        codigo == 0
    }
    #[cfg(target_arch = "aarch64")]
    {
        const ISS: u64 = (3 << 20) | (2 << 17) | (3 << 14) | (14 << 10) | (1 << 5) | 1;
        (codigo >> 26) & 0x3F == 0x18 && codigo & 0x3F_FFFF == ISS
    }
}

/// O processo que lê o contador de ciclos cai, em cada núcleo ligado: a
/// falha contada é a de proteção — o `#GP` no x86, a exceção síncrona do
/// `mrs` no ARM —, na instrução da entrada, que é a leitura; o processo não
/// sai com o código do contador; e o log diz que ele morreu por ela, no
/// mesmo lugar. Com o `CR4.TSD` desligado, ou o `CNTKCTL_EL1` com o
/// `EL0VCTEN`, a leitura passa, e o processo sai com o código dele.
///
/// A auditoria não diz nada: a morte de um processo por uma falha não é
/// uma decisão, e não tem registro — nem a do `invasor`. Gravá-la seria um
/// registro novo, uma decisão \[C\] (ver o relatório do #451).
pub(super) fn contador_o_processo_que_le_cai() -> Resultado {
    let imagem = crate::usuario::exemplo::bytes_do_contador();
    let entrada = imagem
        .get(24..32)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map(u64::from_le_bytes)
        .ok_or("a imagem do contador nao tem a entrada")?;
    let (nome, motivo) = FALHA;
    for cpu in nucleos() {
        crate::usuario::limpar_ultima_saida();
        RODOU.store(u64::MAX, SeqCst);
        let falhas = crate::traps::total();
        let desde = crate::log::total_emitidos();
        let id = crate::fios::criar_no_nucleo("teste-contador", hospedar, 0, cpu)?.numero();
        // Até ele acabar: pela falha, ou pela saída — a da leitura que
        // passou, que se diz pelo nome, e não pelo prazo.
        esperar_ate(
            || {
                !crate::fios::vivo(id)
                    && (crate::traps::total() > falhas || crate::usuario::ultima_saida().is_some())
            },
            300,
        )
        .map_err(|_| "o processo que le o contador de ciclos nao caiu nem saiu")?;
        if RODOU.load(SeqCst) != cpu as u64 {
            return Err("o processo do contador nao rodou no nucleo dele");
        }
        if crate::usuario::ultima_saida() == Some(crate::usuario::exemplo::CODIGO_DO_CONTADOR) {
            return Err("o processo leu o contador de ciclos e seguiu");
        }
        if crate::traps::total() <= falhas {
            return Err("o processo que le o contador de ciclos nao caiu");
        }
        let falha = crate::traps::ultima().ok_or("a falha do contador nao foi contada")?;
        crate::log_info!(
            "teste",
            "contador: no nucleo {}, {} em pc={:#x}, codigo {:#x}",
            cpu,
            falha.nome,
            falha.pc,
            falha.codigo
        );
        if falha.nome != nome || falha.pc != entrada || !codigo_da_leitura(falha.codigo) {
            return Err("a falha nao foi a da leitura do contador, na instrucao dela");
        }
        let linha = alloc::format!(
            "processo morto por {motivo} #{} em pc={entrada:#x}",
            falha.seq
        );
        if linhas_do_programa(desde, &linha) != 1 {
            crate::log_error!("teste", "esperada `{}`", linha);
            return Err("o log nao diz que o processo morreu pela leitura do contador");
        }
    }
    Ok(())
}

/// O que cada núcleo leu dos próprios controles, mais um — zero é "ainda
/// não leu" —, e o núcleo em que leu.
static LIDOS: [AtomicU64; crate::nucleos::MAX_NUCLEOS] =
    [const { AtomicU64::new(0) }; crate::nucleos::MAX_NUCLEOS];
static ONDE: [AtomicU64; crate::nucleos::MAX_NUCLEOS] =
    [const { AtomicU64::new(u64::MAX) }; crate::nucleos::MAX_NUCLEOS];

/// No x86, os dois bits do `CR4`; no ARM, o `CNTKCTL_EL1` inteiro e o
/// `PMUSERENR_EL0` — ou nenhum, sem a PMU —, num número só: o que o caso
/// confere.
#[cfg(target_arch = "x86_64")]
fn controles() -> u64 {
    let (tsd, pce) = crate::arch::atual::contadores_do_usuario();
    u64::from(tsd) | (u64::from(pce) << 1)
}
#[cfg(target_arch = "aarch64")]
fn controles() -> u64 {
    let (cntkctl, pmuserenr) = crate::arch::atual::usuario::contadores_do_usuario();
    // O `CNTKCTL_EL1` tem os bits até o 17; o `PMUSERENR_EL0`, até o 6.
    (cntkctl & 0xF_FFFF) | (pmuserenr.map_or(1 << 63, |p| (p & 0xFF) << 32))
}

/// O que o kernel escreve: no x86, o `TSD` ligado e o `PCE` desligado; no
/// ARM, o `CNTKCTL_EL1` em zero — nenhum dos `EL0PCTEN`, `EL0VCTEN`,
/// `EL0VTEN` e `EL0PTEN`, nem o fluxo de eventos — e o `PMUSERENR_EL0` em
/// zero, ou nenhum, sem a PMU.
fn como_o_kernel_escreveu(controles: u64) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        controles == 1
    }
    #[cfg(target_arch = "aarch64")]
    {
        controles == 0 || controles == 1 << 63
    }
}

/// Um fio preso a um núcleo lê os controles dele.
extern "C" fn ler_os_controles(cpu: u64) -> ! {
    let i = cpu as usize;
    ONDE[i].store(crate::arch::nucleo_atual() as u64, SeqCst);
    LIDOS[i].store(controles().wrapping_add(1), SeqCst);
    crate::fios::terminar()
}

/// Em cada núcleo ligado, o acesso do anel sem privilégio ao contador está
/// como o kernel o escreveu: um fio preso a cada núcleo lê os controles
/// dele, e confere-se o que o primeiro escreveu no boot e o que cada
/// secundário escreveu ao acordar.
pub(super) fn contador_os_controles_em_cada_nucleo() -> Resultado {
    let nucleos = nucleos();
    for &cpu in &nucleos {
        LIDOS[cpu].store(0, SeqCst);
        ONDE[cpu].store(u64::MAX, SeqCst);
        crate::fios::criar_no_nucleo(
            "teste-contador-controles",
            ler_os_controles,
            cpu as u64,
            cpu,
        )?;
    }
    esperar_ate(
        || nucleos.iter().all(|&cpu| LIDOS[cpu].load(SeqCst) != 0),
        300,
    )
    .map_err(|_| "um nucleo nao leu os controles do contador")?;
    for &cpu in &nucleos {
        let lido = LIDOS[cpu].load(SeqCst).wrapping_sub(1);
        crate::log_info!(
            "teste",
            "contador: os controles do nucleo {}: {:#x}",
            cpu,
            lido
        );
        if ONDE[cpu].load(SeqCst) != cpu as u64 {
            return Err("os controles nao foram lidos no nucleo deles");
        }
        if !como_o_kernel_escreveu(lido) {
            return Err("o acesso do usuario ao contador nao esta como o kernel o escreveu");
        }
    }
    Ok(())
}
