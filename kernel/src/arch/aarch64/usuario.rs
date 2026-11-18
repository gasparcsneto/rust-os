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

use super::vetores::Quadro;

/// `PSTATE` de um processo em EL0.
///
/// - `M[3:0] = 0b0000`: EL0t. Em EL0 só existe `SP_EL0`, então não há sufixo
///   `h`/`t` para escolher — o `t` é o único valor legal.
/// - `I = 0`: IRQs desmascaradas. Um processo impreemptável travaria a máquina
///   no primeiro laço infinito, e não há nada que o kernel pudesse fazer.
/// - `D`, `A`, `F = 1`: como no resto do kernel.
const SPSR_USUARIO: u64 = (1 << 9) | (1 << 8) | (1 << 6);

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
    fechar_os_contadores_neste_nucleo();
    crate::log_info!("usuario", "svc de EL0 atendido pela tabela de vetores");
    crate::log_info!(
        "usuario",
        "os contadores fora do EL0: CNTKCTL_EL1 em zero, PMUSERENR_EL0 em zero{}",
        if pmu_v3() { "" } else { " (sem PMU)" }
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
/// EL1 — a régua das medidas de custo (`ciclos`), o prazo da parada —, e
/// o timer físico do EL1, que é o tique: nada disso passa pelo EL0.
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

/// Informa a pilha de kernel do fio que vai rodar.
///
/// No ARM não há o que fazer: as exceções têm `SP_EL1` só delas, e o hardware
/// a seleciona sozinho. A função existe para o contrato de [`crate::arch`] ser
/// o mesmo nas duas arquiteturas — no x86 ela alimenta o `RSP0` do TSS e a
/// global que o ponto de entrada de `syscall` consulta.
pub fn definir_pilha_de_kernel(_topo: u64) {}

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
            // lugar perfeitamente válido para as quatro instruções que faltam.
            "msr spsel, #1",

            "msr sp_el0, {pilha}",
            "msr elr_el1, {entrada}",
            "msr spsr_el1, {spsr}",
            "eret",
            pilha = in(reg) pilha,
            entrada = in(reg) entrada,
            spsr = in(reg) SPSR_USUARIO,
            options(noreturn),
        )
    }
}
