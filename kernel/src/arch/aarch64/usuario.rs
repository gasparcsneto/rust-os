//! Entrada em EL0 e chamadas de sistema no aarch64.
//!
//! # Muito mais simples que no x86, e por uma boa razão
//!
//! No x86 a instrução `syscall` não troca a pilha, e o ponto de entrada do
//! kernel começa a executar sobre um ponteiro que o processo controla — daí o
//! `swapgs`, os dados por núcleo e toda a coreografia para sair de lá antes de
//! empilhar qualquer coisa.
//!
//! No ARM isso não existe. Uma exceção vinda de EL0 já chega com `SP_EL1`, a
//! pilha de exceção do kernel, selecionada pelo hardware. O `svc` do usuário
//! entra pela mesma tabela de vetores que todas as outras exceções, com o
//! contexto completo salvo do mesmo jeito. Não há nada a preparar.
//!
//! O único trabalho é distinguir de onde veio o `svc` — EL0 é chamada de
//! sistema, EL1 é um fio do kernel cedendo a vez —, e isso está escrito no
//! `SPSR` que o próprio processador salvou.
//!
//! # Descer para EL0
//!
//! Como no x86, não há instrução de "entrar em userspace": usa-se a de
//! retornar de exceção. Montamos um `SPSR` que descreve EL0, apontamos `ELR`
//! para o código do processo, `SP_EL0` para a pilha dele, e o `eret` faz o
//! resto.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::vetores::Quadro;

/// `PSTATE` de um processo em EL0, pela primeira entrada ([`entrar`]) e pela
/// troca de imagem (`contexto::redirecionar_para`).
///
/// - `M[3:0] = 0b0000`: EL0t. Em EL0 só existe `SP_EL0`, então não há sufixo
///   `h`/`t` para escolher — o `t` é o único valor legal.
/// - `I = 0`: IRQs desmascaradas. Um processo impreemptável travaria a máquina
///   no primeiro laço infinito, e não há nada que o kernel pudesse fazer.
/// - `D`, `A`, `F = 1`: como no resto do kernel.
/// - E nada mais: o `NZCV` em zero, e os bits das extensões — o `SSBS`, o
///   `DIT`, o `TCO`, o `BTYPE` — também. A troca de imagem não entrega os da
///   imagem que saiu (o achado 1 do adversário do lote B4 do #448).
pub(super) const SPSR_USUARIO: u64 = (1 << 9) | (1 << 8) | (1 << 6);

/// Máscara do campo de modo dentro do `SPSR`.
const MASCARA_DE_MODO: u64 = 0b1111;
/// Valor do campo de modo para EL0.
const MODO_EL0: u64 = 0b0000;

/// O `svc` veio do anel sem privilégio?
///
/// A pergunta é respondida pelo `SPSR` salvo, que descreve o estado de **quem
/// foi interrompido**. É mais robusto que olhar o imediato do `svc`: o
/// imediato é escolhido pelo processo, e o processo não é confiável.
pub fn veio_de_usuario(quadro: &Quadro) -> bool {
    quadro.spsr & MASCARA_DE_MODO == MODO_EL0
}

/// Atende uma chamada de sistema vinda de EL0, sobre o quadro da exceção.
///
/// A ABI segue a do Linux em aarch64: `x8` traz o número, `x0`–`x2` os
/// argumentos, e o retorno volta em `x0`.
pub fn atender_chamada(quadro: &mut Quadro) {
    let numero = quadro.x[8];
    let (a0, a1, a2) = (quadro.x[0], quadro.x[1], quadro.x[2]);

    // SAFETY: o quadro é o desta exceção; `bifurcar` e `executar` o leem e o
    // reescrevem, e é por isso que ele desce até o despacho.
    let resultado = unsafe {
        crate::usuario::despachar(
            numero,
            a0,
            a1,
            a2,
            quadro as *mut Quadro as *mut core::ffi::c_void,
        )
    };

    // A chamada pediu para ser reexecutada: a que estacionou o fio — `esperar`
    // sem filho para colher, a leitura de um canal vazio, `pedir` —, ou a que
    // só pediu a vez e a repetição, sem ter mudado nada
    // (`fios::ceder_e_reexecutar`): a vez, o handler a dá sobre o quadro de
    // fora, como na cessão, e o fio volta no `svc`.
    //
    // # Por que reexecutar o `svc`, e não voltar para dentro do despacho
    //
    // Porque daqui o fio **não volta para dentro do kernel**. Estacioná-lo é
    // [`super::contexto::trocar_no_quadro`], que salva como contexto dele o
    // próprio quadro desta exceção: quando ele for escolhido de novo, o que
    // acontece é um `eret` para EL0. As linhas que viessem depois de um
    // bloqueio aqui dentro nunca rodariam.
    //
    // Então o ponto de retomada tem de estar em EL0, e o único que serve é a
    // própria instrução que nos trouxe. `ELR_EL1` aponta para a seguinte;
    // recuar quatro bytes — o tamanho fixo de uma instrução A64 — faz o fio
    // acordar executando o `svc` de novo, com `x0`, `x1` e `x8` intactos,
    // porque é justamente por isso que não escrevemos `x0` neste caminho.
    //
    // No x86 o mesmo contrato é cumprido de outro jeito, e a diferença não é
    // estilo: lá a chamada roda sobre uma cadeia de chamadas comum, o fio
    // pode ser estacionado sem abandonar a pilha de kernel, e ele volta de
    // dentro do despacho. Ver `arch::x86_64::usuario::despachar_chamada`.
    //
    // A pergunta é à chamada, e não ao estado do fio: com vários núcleos, o
    // filho pode ter acordado o pai entre a chamada estacionar e esta linha —
    // ver [`crate::fios::tirar_reexecucao`]. Acordado antes, o fio não para
    // no handler, e o `eret` já o põe no `svc` de novo.
    #[cfg(feature = "modo-teste")]
    crate::fios::pausa_de_teste::talvez_pausar();
    if crate::fios::tirar_reexecucao() {
        quadro.elr -= 4;
        return;
    }

    quadro.x[0] = resultado as u64;
}

/// O mecanismo de chamada de sistema do ARM já está de pé assim que a
/// tabela de vetores está; o que se prepara aqui é o que o EL0 **não**
/// alcança: os contadores, neste núcleo — ver
/// [`fechar_os_contadores_neste_nucleo`]. Os outros núcleos os fecham ao
/// acordar (`smp::entrada_secundaria`).
///
/// # Safety
///
/// Existe por simetria com o x86, onde esta função escreve quatro
/// registradores de modelo específico. Aqui só escreve registradores de
/// sistema do EL1, antes do primeiro processo.
pub unsafe fn init() {
    escrever_o_regime_deste_nucleo();
    fechar_os_contadores_neste_nucleo();
    crate::log_info!(
        "usuario",
        "o FP/SIMD fora do EL0 e do EL1: CPACR_EL1 em zero, e nunca religado"
    );
    if let Some(r) = regime_do_firmware() {
        crate::log_info!(
            "usuario",
            "o regime que o firmware deixou: SCTLR_EL1 {:#x}, CPACR_EL1 {:#x}, MDSCR_EL1 {:#x}, \
             TPIDRRO_EL0 {:#x}",
            r.sctlr,
            r.cpacr,
            r.mdscr,
            r.tpidrro
        );
    }
    let r = ler_o_regime_deste_nucleo();
    crate::log_info!(
        "usuario",
        "o regime do kernel: SCTLR_EL1 {:#x}, CPACR_EL1 {:#x}, MDSCR_EL1 {:#x}, TPIDRRO_EL0 {:#x}",
        r.sctlr,
        r.cpacr,
        r.mdscr,
        r.tpidrro
    );
    crate::log_info!("usuario", "svc de EL0 atendido pela tabela de vetores");
    crate::log_info!(
        "usuario",
        "os contadores fora do EL0: CNTKCTL_EL1 em zero, PMUSERENR_EL0 {}",
        if pmu_v3() {
            "em zero"
        } else {
            "ausente (sem PMU)"
        }
    );
}

/// Tira os contadores do EL0, **neste** núcleo — o #451, o par do `CR4.TSD`
/// do x86:
///
/// - o `CNTKCTL_EL1` em zero: sem o `EL0PCTEN` e o `EL0VCTEN`, a leitura do
///   `CNTPCT_EL0`, do `CNTVCT_EL0` e do `CNTFRQ_EL0` no EL0 vira uma exceção
///   síncrona para o EL1; sem o `EL0VTEN` e o `EL0PTEN`, a dos registradores
///   dos timers virtual e físico também. O resto do registrador é o fluxo
///   de eventos do contador virtual, que o kernel não usa — os `wfe` dele
///   são as paradas, que um evento a cada tanto só faria girar —, e sai
///   desligado junto;
/// - o `PMUSERENR_EL0` em zero, se o núcleo tem a PMU: o contador de ciclos
///   e os de eventos dela também ficam fora do EL0. O valor de reset dele
///   é desconhecido; sem a PMU (`ID_AA64DFR0_EL1.PMUVer`), o registrador
///   não existe, e escrevê-lo seria uma instrução indefinida no boot.
///
/// # O relógio que não passava pelo gate
///
/// Nem o kernel nem o iniciador escreviam o `CNTKCTL_EL1`: a leitura do
/// contador no EL0 dependia do firmware. O relógio de um programa é o
/// `system.uptime`, decidido pelo gate; o contador no EL0 seria outro, sem
/// decisão nem registro. Agora um processo que o lê morre pela exceção
/// síncrona (`msr_mrs_trap`), como um que executa uma instrução
/// privilegiada, e o log diz qual. O kernel continua lendo o contador no
/// EL1 — a régua das medidas de custo (`ciclos`), o prazo da parada e o do
/// tique (`gic::PRAZO`) —, e o timer físico do EL1, que é o tique: nada
/// disso passa pelo EL0.
///
/// # O que fica de fora: o AMU
///
/// Com a FEAT_AMUv1 — `ID_AA64PFR0_EL1.AMU` diferente de zero —, os
/// contadores de atividade (`AMEVCNTR0<n>_EL0`, o de ciclos entre eles) são
/// legíveis no EL0 com o `AMUSERENR_EL0.EN` ligado, e o valor de reset dele é
/// desconhecido: um relógio fora do gate, como o do timer. O kernel **não**
/// o escreve, e é uma escolha, não um esquecimento (o item 7 do lote B2 do
/// #448):
///
/// - o QEMU do TCG não emula o AMU, e o núcleo da suíte (`cortex-a72`, um
///   ARMv8.0) não o tem: o caminho que escrevesse o registro não roda em
///   nenhuma rodada, nem em nenhuma bancada — código sem teste no caminho
///   de boot de cada núcleo;
/// - com um firmware que prende o acesso ao AMU no EL3 (`CPTR_EL3.TAM`), a
///   própria escrita do EL1 cai no EL3, e o que o firmware faz dela — parar
///   o núcleo, ou devolver uma instrução indefinida ao EL1 — pararia o boot
///   no lugar de fechar um contador.
///
/// A lacuna vale só em hardware com o AMU e um firmware que deixe o
/// `AMUSERENR_EL0` aberto. O fecho, quando entrar, entra com o teste que o
/// exercite: o registro escrito só com o `AMU` declarado, e a armadilha do
/// EL3 conferida antes.
pub fn fechar_os_contadores_neste_nucleo() {
    use aarch64_cpu::registers::CNTKCTL_EL1;
    use tock_registers::interfaces::Writeable;
    CNTKCTL_EL1.set(0);
    if pmu_v3() {
        // SAFETY: o núcleo declarou a PMUv3, e o registrador é de EL0, que
        // o EL1 escreve; zero só tira o acesso do EL0.
        unsafe {
            asm!(
                "msr pmuserenr_el0, xzr",
                options(nomem, nostack, preserves_flags)
            )
        };
    }
    // SAFETY: barreira, sem efeito além da ordem: o EL0 que vier depois já
    // vê os controles escritos.
    unsafe { asm!("isb", options(nomem, nostack, preserves_flags)) };
    #[cfg(feature = "modo-teste")]
    FECHAMENTOS[super::nucleo_atual()].fetch_add(1, core::sync::atomic::Ordering::SeqCst);
}

/// Só para a suíte: quantas vezes cada núcleo tirou os contadores do EL0
/// ([`fechar_os_contadores_neste_nucleo`]) — o primeiro no boot, cada
/// secundário ao acordar.
#[cfg(feature = "modo-teste")]
static FECHAMENTOS: [core::sync::atomic::AtomicU64; crate::nucleos::MAX_NUCLEOS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; crate::nucleos::MAX_NUCLEOS];

/// Só para a suíte: quantas vezes o núcleo `cpu` tirou os contadores do
/// EL0.
#[cfg(feature = "modo-teste")]
pub fn fechamentos_dos_contadores_de_teste(cpu: usize) -> u64 {
    FECHAMENTOS
        .get(cpu)
        .map_or(0, |f| f.load(core::sync::atomic::Ordering::SeqCst))
}

/// Só para a suíte: suja os controles deste núcleo como um firmware que os
/// deixasse abertos — o `CNTKCTL_EL1` com o `EL0PCTEN` e o `EL0VCTEN`, e o
/// `PMUSERENR_EL0` com o `EN`, se há a PMU —, e os fecha de novo por
/// [`fechar_os_contadores_neste_nucleo`]; devolve os controles sujos e os
/// de depois. O QEMU sai do reset com os dois em zero, e o caso que só lê
/// os controles passaria sem as escritas do kernel: sujos aqui, só elas os
/// zeram. Tudo mascarado: nenhum processo roda neste núcleo no meio.
#[cfg(feature = "modo-teste")]
pub fn sujar_e_fechar_os_contadores_de_teste() -> ((u64, Option<u64>), (u64, Option<u64>)) {
    use aarch64_cpu::registers::CNTKCTL_EL1;
    use tock_registers::interfaces::Writeable;
    crate::arch::sem_interrupcoes(|| {
        CNTKCTL_EL1.set(0b11);
        if pmu_v3() {
            // SAFETY: o núcleo declarou a PMUv3; o `EN` só até a linha
            // seguinte, mascarado.
            unsafe {
                asm!(
                    "msr pmuserenr_el0, {}",
                    in(reg) 1u64,
                    options(nomem, nostack, preserves_flags)
                )
            };
        }
        // SAFETY: barreira, sem efeito além da ordem.
        unsafe { asm!("isb", options(nomem, nostack, preserves_flags)) };
        let sujos = contadores_do_usuario();
        fechar_os_contadores_neste_nucleo();
        (sujos, contadores_do_usuario())
    })
}

/// O núcleo tem a PMU da arquitetura, a PMUv3: o `PMUVer` do
/// `ID_AA64DFR0_EL1` entre 1 e 14 — 0 é sem PMU, e 15, uma de outro
/// formato, que o kernel não conhece.
fn pmu_v3() -> bool {
    use aarch64_cpu::registers::ID_AA64DFR0_EL1;
    use tock_registers::interfaces::Readable;
    (1..=0xE).contains(&ID_AA64DFR0_EL1.read(ID_AA64DFR0_EL1::PMUVer))
}

/// Só para a suíte: o `CNTKCTL_EL1` e o `PMUSERENR_EL0` deste núcleo — este
/// `None` sem a PMU —, como [`fechar_os_contadores_neste_nucleo`] os
/// escreveu.
#[cfg(feature = "modo-teste")]
pub fn contadores_do_usuario() -> (u64, Option<u64>) {
    use aarch64_cpu::registers::CNTKCTL_EL1;
    use tock_registers::interfaces::Readable;
    let pmuserenr = pmu_v3().then(|| {
        let valor: u64;
        // SAFETY: leitura de um registrador que o núcleo declarou, sem
        // efeito.
        unsafe {
            asm!("mrs {}, pmuserenr_el0", out(reg) valor, options(nomem, nostack, preserves_flags))
        };
        valor
    });
    (CNTKCTL_EL1.get(), pmuserenr)
}

/// O `CPACR_EL1` do kernel: zero. O `FPEN` em 00 prende o FP/SIMD no EL0 e
/// no EL1 — ver [`escrever_o_regime_deste_nucleo`] —, e o `ZEN` do SVE e o
/// `SMEN` do SME, também em 00, os prendem do mesmo jeito. O `TTA` em 0 não
/// prende os registradores de rastro: no AArch64 eles já são indefinidos no
/// EL0, o kernel não os usa no EL1, e o Duke não roda AArch32 no EL0; num
/// núcleo sem a interface de sistema do rastro, o bit é RES0.
pub const CPACR_DO_KERNEL: u64 = 0;

/// O `MDSCR_EL1` do kernel: só o `TDCC` — ver
/// [`escrever_o_regime_deste_nucleo`]. O `MDE`, o `KDE` e o `SS` desligados:
/// nenhum ponto de parada nem de observação do hardware, nenhuma exceção de
/// depuração no EL1, nenhum passo.
pub const MDSCR_DO_KERNEL: u64 = MDSCR_TDCC;

/// Escreve o regime deste núcleo: o que vale para todo processo que roda
/// nele, e que o kernel não herda do firmware. Chamada por [`init`], no
/// primeiro núcleo, e por `smp::entrada_secundaria`, em cada um que acorda
/// — que já entra com o `SCTLR_EL1` e o `CPACR_EL1` pelo bloco de partida
/// —, antes do primeiro processo.
///
/// - **O `CPACR_EL1` em zero** ([`CPACR_DO_KERNEL`]): o FP/SIMD preso no EL0
///   e no EL1, e nunca religado. O processo que toca um registrador `v`
///   morre da exceção da classe 0x07 (`fp_simd_trap`). Antes o kernel nunca
///   o escrevia: no boot cru, ele sai do reset em zero; pela UEFI, o EDK2 o
///   deixa com o `FPEN` em 11, e o `d0` que um processo deixava chegava ao
///   seguinte no mesmo núcleo — um canal entre titulares, por fora do gate
///   (o achado 2 do adversário do lote B2 do #448). O kernel é
///   *soft-float*, e nenhum programa do contrato usa FP/SIMD (o DS-2).
///   Salvar o estado e liberá-lo aos programas é a R12-SIMD
///   (`docs/DECISOES.md`), que continua aberta.
/// - **O `SCTLR_EL1` inteiro** ([`super::mmu::SCTLR_DO_KERNEL`]), o mesmo
///   que o primeiro núcleo escreveu ao ligar a MMU: o `UMA`, o `UCI`, o
///   `DZE` e o `UCT` desligados, entre outros — ver lá.
/// - **O `MDSCR_EL1` do kernel** ([`MDSCR_DO_KERNEL`]): o `TDCC` ligado
///   prende no EL1 o canal do depurador do EL0 — o `MDCCSR_EL0`, o
///   `DBGDTR_EL0`, o `DBGDTRRX_EL0` e o `DBGDTRTX_EL0` —, e o processo que
///   o toca morre da classe 0x18 (`msr_mrs_trap`). Desligado, sem
///   depurador do outro lado, o `TXfull` que um processo ligasse escrevendo
///   o `DBGDTRTX_EL0` o seguinte via — um bit por núcleo, entre titulares,
///   por fora do gate; é o par do `DR7` do x86 (o item 8 do adversário do
///   lote B3 do #448). O `MDE`, o `KDE` e o `SS` desligados: um firmware ou
///   um depurador que os deixasse ligados não arma nada no kernel.
/// - **O `TPIDRRO_EL0` em zero**, por higiene: o EL0 o lê, e o kernel não o
///   usa — nenhum valor dele vai a um processo.
pub fn escrever_o_regime_deste_nucleo() {
    // SAFETY: os quatro valores são os do kernel: o `SCTLR_EL1` mantém a
    // tradução e os caches ligados, como já estão, e só fecha o que o EL0
    // alcança; o `CPACR_EL1` em zero prende o FP/SIMD, que o kernel
    // *soft-float* não usa; o `MDSCR_EL1` só prende o canal do depurador do
    // EL0 e desliga o que o kernel não usa; o `TPIDRRO_EL0` o kernel não
    // lê. O `isb` faz a instrução seguinte já ver os quatro.
    unsafe {
        asm!(
            "msr cpacr_el1, {cpacr}",
            "msr sctlr_el1, {sctlr}",
            "msr mdscr_el1, {mdscr}",
            "msr tpidrro_el0, xzr",
            "isb",
            cpacr = in(reg) CPACR_DO_KERNEL,
            sctlr = in(reg) super::mmu::SCTLR_DO_KERNEL,
            mdscr = in(reg) MDSCR_DO_KERNEL,
            options(nomem, nostack, preserves_flags)
        )
    };
    #[cfg(feature = "modo-teste")]
    REGIMES[super::nucleo_atual()].fetch_add(1, Ordering::SeqCst);
}

/// Só para a suíte: quantas vezes cada núcleo escreveu o regime
/// ([`escrever_o_regime_deste_nucleo`]) — o primeiro no boot, cada
/// secundário ao acordar.
#[cfg(feature = "modo-teste")]
static REGIMES: [AtomicU64; crate::nucleos::MAX_NUCLEOS] =
    [const { AtomicU64::new(0) }; crate::nucleos::MAX_NUCLEOS];

/// Só para a suíte: quantas vezes o núcleo `cpu` escreveu o regime.
#[cfg(feature = "modo-teste")]
pub fn regimes_escritos_de_teste(cpu: usize) -> u64 {
    REGIMES.get(cpu).map_or(0, |r| r.load(Ordering::SeqCst))
}

/// Só para a suíte: o regime deste núcleo está como o kernel o escreve? Do
/// `SCTLR_EL1`, os bits que ele decide (`mmu::SCTLR_CONFERIDOS`); do
/// `CPACR_EL1`, o `FPEN`, que prende o FP/SIMD; do `MDSCR_EL1`, os quatro
/// do depurador, pelo nome — o `TDCC` ligado, o `MDE`, o `KDE` e o `SS`
/// desligados —; e o `TPIDRRO_EL0` em zero. Devolve o primeiro que diverge.
#[cfg(feature = "modo-teste")]
pub fn regime_como_o_kernel_escreve(r: Regime) -> Result<(), &'static str> {
    const FPEN: u64 = 0b11 << 20;
    let conferidos = super::mmu::SCTLR_CONFERIDOS;
    if r.sctlr & conferidos != super::mmu::SCTLR_DO_KERNEL & conferidos {
        return Err("o SCTLR_EL1");
    }
    if r.cpacr & FPEN != CPACR_DO_KERNEL & FPEN {
        return Err("o FPEN do CPACR_EL1");
    }
    for (nome, bit, ligado) in [
        ("o TDCC do MDSCR_EL1", MDSCR_TDCC, true),
        ("o MDE do MDSCR_EL1", MDSCR_MDE, false),
        ("o KDE do MDSCR_EL1", MDSCR_KDE, false),
        ("o SS do MDSCR_EL1", MDSCR_SS, false),
    ] {
        if (r.mdscr & bit != 0) != ligado {
            return Err(nome);
        }
    }
    if r.tpidrro != 0 {
        return Err("o TPIDRRO_EL0 fora de zero");
    }
    Ok(())
}

/// Só para a suíte: o regime sujo de [`sujar_e_reescrever_o_regime_de_teste`]
/// aparece inteiro na leitura — cada item que ela suja, sujo —, para que o
/// "depois" do caso prove a reescrita de cada um, e não só a do primeiro que
/// diverge; um núcleo, ou um emulador, que ignorasse a escrita de um deles
/// não passa calado. É o par do x86, onde a leitura do `sysenter` passava
/// pela mesma pergunta que a escrita (o achado 2 do adversário do lote B4
/// do #448); aqui nada é condicional. Devolve o primeiro item que não
/// apareceu sujo.
#[cfg(feature = "modo-teste")]
pub fn regime_sujo_inteiro(r: Regime) -> Result<(), &'static str> {
    const FPEN: u64 = 0b11 << 20;
    if r.cpacr & FPEN != FPEN {
        return Err("o CPACR_EL1 sujo sem o FPEN em 11");
    }
    if r.sctlr & SCTLR_ABERTO_DE_TESTE != SCTLR_ABERTO_DE_TESTE {
        return Err("o SCTLR_EL1 sujo sem o UMA, o DZE, o UCT ou o UCI");
    }
    if r.mdscr & (MDSCR_TDCC | MDSCR_MDE | MDSCR_KDE) != MDSCR_MDE | MDSCR_KDE {
        return Err("o MDSCR_EL1 sujo com o TDCC, ou sem o MDE ou o KDE");
    }
    if r.tpidrro != TPIDRRO_SUJO_DE_TESTE {
        return Err("o TPIDRRO_EL0 sujo sem a marca");
    }
    Ok(())
}

/// Só para a suíte: os bits do `SCTLR_EL1` que o regime sujo liga, e que o
/// kernel desliga — o `UMA`, o `DZE`, o `UCT` e o `UCI`.
#[cfg(feature = "modo-teste")]
const SCTLR_ABERTO_DE_TESTE: u64 = (1 << 9) | (1 << 14) | (1 << 15) | (1 << 26);

/// Só para a suíte: a marca do `TPIDRRO_EL0` sujo.
#[cfg(feature = "modo-teste")]
const TPIDRRO_SUJO_DE_TESTE: u64 = 0x5EC4_E7D0_D0E5_A1A1;

/// Só para a suíte: suja o regime deste núcleo como um firmware que o
/// deixasse aberto — o `CPACR_EL1` com o `FPEN` em 11, como o EDK2 o deixa;
/// o `SCTLR_EL1` com o `UMA`, o `UCI`, o `DZE` e o `UCT` ligados; o
/// `MDSCR_EL1` sem o `TDCC` e com o `MDE` e o `KDE`; e o `TPIDRRO_EL0` com
/// uma marca —, e o escreve de novo por [`escrever_o_regime_deste_nucleo`];
/// devolve o regime sujo e o de depois. Tudo mascarado: nenhum processo roda
/// neste núcleo no meio, e o kernel não usa o FP/SIMD, os acessos do EL0
/// nem o depurador — o `D` do `DAIF` segue mascarado no EL1, e nenhum ponto
/// de parada do hardware está armado.
#[cfg(feature = "modo-teste")]
pub fn sujar_e_reescrever_o_regime_de_teste() -> (Regime, Regime) {
    crate::arch::sem_interrupcoes(|| {
        // SAFETY: só até a linha seguinte, mascarado — ver acima. O
        // `SCTLR_EL1` sujo mantém a tradução e os caches como estão.
        unsafe {
            asm!(
                "msr cpacr_el1, {cpacr}",
                "msr sctlr_el1, {sctlr}",
                "msr mdscr_el1, {mdscr}",
                "msr tpidrro_el0, {tpidrro}",
                "isb",
                cpacr = in(reg) 0b11u64 << 20,
                sctlr = in(reg) super::mmu::SCTLR_DO_KERNEL | SCTLR_ABERTO_DE_TESTE,
                mdscr = in(reg) MDSCR_MDE | MDSCR_KDE,
                tpidrro = in(reg) TPIDRRO_SUJO_DE_TESTE,
                options(nomem, nostack, preserves_flags)
            )
        };
        let sujo = ler_o_regime_deste_nucleo();
        escrever_o_regime_deste_nucleo();
        (sujo, ler_o_regime_deste_nucleo())
    })
}

/// O `TDCC` do `MDSCR_EL1`: o acesso do EL0 ao canal do depurador vira uma
/// exceção para o EL1.
const MDSCR_TDCC: u64 = 1 << 12;
/// O `KDE` do `MDSCR_EL1`: as exceções de depuração no próprio EL1.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
const MDSCR_KDE: u64 = 1 << 13;
/// O `MDE` do `MDSCR_EL1`: os pontos de parada e de observação do hardware.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
const MDSCR_MDE: u64 = 1 << 15;
/// O `SS` do `MDSCR_EL1`: o passo do hardware.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
const MDSCR_SS: u64 = 1;

/// O regime de um núcleo do ARM: o que vale para todo processo que roda
/// nele, e que o kernel escreve em vez de herdar — ver
/// [`escrever_o_regime_deste_nucleo`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Regime {
    pub sctlr: u64,
    pub cpacr: u64,
    pub mdscr: u64,
    pub tpidrro: u64,
}

/// O regime deste núcleo, como está agora.
pub fn ler_o_regime_deste_nucleo() -> Regime {
    let (sctlr, cpacr, mdscr, tpidrro): (u64, u64, u64, u64);
    // SAFETY: leituras de três registradores do EL1 e de um do EL0, sem
    // efeito.
    unsafe {
        asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nomem, nostack, preserves_flags));
        asm!("mrs {}, cpacr_el1", out(reg) cpacr, options(nomem, nostack, preserves_flags));
        asm!("mrs {}, mdscr_el1", out(reg) mdscr, options(nomem, nostack, preserves_flags));
        asm!("mrs {}, tpidrro_el0", out(reg) tpidrro, options(nomem, nostack, preserves_flags));
    }
    Regime {
        sctlr,
        cpacr,
        mdscr,
        tpidrro,
    }
}

/// O regime que o primeiro núcleo trouxe do firmware, lido na primeira
/// função Rust (`inicio_aarch64`), antes de a MMU do kernel ligar. Só para
/// o log do boot ([`init`]): no boot cru, é o reset do processador; pela
/// UEFI, o que o EDK2 deixou, menos o `M` e o `C` do `SCTLR_EL1`, que o
/// iniciador desliga antes do salto.
static REGIME_DO_FIRMWARE: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// [`REGIME_DO_FIRMWARE`] já foi guardado?
static REGIME_GUARDADO: AtomicBool = AtomicBool::new(false);

/// Guarda o regime que o firmware deixou neste núcleo — ver
/// [`REGIME_DO_FIRMWARE`]. Chamada uma vez, no começo do boot.
pub fn guardar_o_regime_do_firmware() {
    let r = ler_o_regime_deste_nucleo();
    for (guardado, valor) in REGIME_DO_FIRMWARE
        .iter()
        .zip([r.sctlr, r.cpacr, r.mdscr, r.tpidrro])
    {
        guardado.store(valor, Ordering::Relaxed);
    }
    REGIME_GUARDADO.store(true, Ordering::Release);
}

/// O regime que o firmware deixou — ver [`REGIME_DO_FIRMWARE`].
fn regime_do_firmware() -> Option<Regime> {
    REGIME_GUARDADO.load(Ordering::Acquire).then(|| {
        let [sctlr, cpacr, mdscr, tpidrro] =
            core::array::from_fn(|i| REGIME_DO_FIRMWARE[i].load(Ordering::Relaxed));
        Regime {
            sctlr,
            cpacr,
            mdscr,
            tpidrro,
        }
    })
}

/// Desce para EL0 e começa a executar em `entrada`. Nunca retorna.
///
/// # Safety
///
/// `entrada` e `pilha` precisam estar mapeados com permissão de EL0.
pub unsafe fn entrar(entrada: u64, pilha: u64) -> ! {
    // SAFETY: o `eret` abaixo consome ELR/SPSR/SP_EL0 que acabamos de escrever
    // e descreve uma volta a EL0 que nunca aconteceu — que é como se entra em
    // userspace pela primeira vez.
    unsafe {
        asm!(
            // Mascarar IRQs até o `eret`. A janela abaixo troca o ponteiro de
            // pilha corrente e escreve os três registradores que definem para
            // onde vamos; uma interrupção no meio disso encontraria um estado
            // pela metade. O `eret` religa as IRQs sozinho, porque o `SPSR`
            // que ele restaura tem o bit `I` zerado.
            "msr daifset, #2",

            // `MSR SP_EL0` é **UNDEFINED** quando o código que a executa já
            // está usando `SP_EL0` como pilha — e é esse o caso: os fios do
            // kernel rodam em EL1t. O processador não trata isso como acesso
            // negado, e sim como instrução inexistente: exceção de classe
            // "unknown", com o `pc` apontando para cá.
            //
            // Passar para `SP_EL1` primeiro resolve, e a pilha de exceção é um
            // lugar perfeitamente válido para as instruções que faltam —
            // nenhuma delas usa a pilha.
            "msr spsel, #1",

            "msr sp_el0, {pilha}",
            "msr elr_el1, {entrada}",
            "msr spsr_el1, {spsr}",

            // O processo novo não recebe o que o kernel deixou nos
            // registradores — endereços do kernel, temporários do caminho
            // do fio —, como na troca de imagem
            // (`contexto::redirecionar_para`): o `TPIDR_EL0` e os `x0`–`x30`
            // em zero (o item 5 do adversário do lote B3 do #448). Nenhum
            // programa recebe argumento em registrador na entrada. Os três
            // operandos já foram escritos nos registradores de sistema, e com
            // as IRQs mascaradas nenhuma troca cai entre o zero do
            // `TPIDR_EL0` e o `eret`: o fio o leva zerado.
            "msr tpidr_el0, xzr",
            "mov x0, xzr",
            "mov x1, xzr",
            "mov x2, xzr",
            "mov x3, xzr",
            "mov x4, xzr",
            "mov x5, xzr",
            "mov x6, xzr",
            "mov x7, xzr",
            "mov x8, xzr",
            "mov x9, xzr",
            "mov x10, xzr",
            "mov x11, xzr",
            "mov x12, xzr",
            "mov x13, xzr",
            "mov x14, xzr",
            "mov x15, xzr",
            "mov x16, xzr",
            "mov x17, xzr",
            "mov x18, xzr",
            "mov x19, xzr",
            "mov x20, xzr",
            "mov x21, xzr",
            "mov x22, xzr",
            "mov x23, xzr",
            "mov x24, xzr",
            "mov x25, xzr",
            "mov x26, xzr",
            "mov x27, xzr",
            "mov x28, xzr",
            "mov x29, xzr",
            "mov x30, xzr",
            "eret",
            pilha = in(reg) pilha,
            entrada = in(reg) entrada,
            spsr = in(reg) SPSR_USUARIO,
            options(noreturn),
        )
    }
}
