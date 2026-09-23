//! Backend de arquitetura para aarch64 (ARM 64 bits).
//!
//! # O contraste com o x86
//!
//! No x86 o crate `bootloader` nos entrega a máquina pronta: já em long mode,
//! com pilha, com tabelas de página e com um mapa de memória estruturado.
//!
//! No ARM não existe esse crate — e nem precisaria existir, porque o
//! protocolo de boot do arm64 é radicalmente mais simples. O QEMU carrega
//! nosso ELF, coloca o endereço do device tree em `x0` e salta para o ponto
//! de entrada. Já estamos em 64 bits, com a MMU desligada. Em troca, tudo o
//! que o bootloader fazia por nós vira trabalho nosso: pilha, limpeza do
//! `.bss` e descoberta de memória.
//!
//! É por isso que este módulo tem assembly e o do x86 não.

pub mod contexto;
mod fdt;
pub mod gic;
pub mod mmu;
pub mod pci;
pub mod uart;
pub mod usuario;
pub mod vetores;

pub use contexto::{
    Contexto, ceder_cpu, preparar_contexto, preparar_contexto_de_fork, redirecionar_para,
};
pub use usuario::{definir_pilha_de_kernel, entrar as entrar_em_usuario, init as init_usuario};

pub use uart::Uart;

use aarch64_cpu::asm::{wfe, wfi};
use aarch64_cpu::registers::{DAIF, MIDR_EL1};
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use tock_registers::interfaces::Readable;

use crate::machine::{Regiao, TipoRegiao};

/// Onde o firmware depositou o device tree, e quanto ele ocupa.
///
/// Guardado no boot porque o alocador de frames precisa saber disso muito
/// depois, e o ponteiro só chega uma vez, em `x0`.
static DTB_INICIO: AtomicU64 = AtomicU64::new(0);
static DTB_TAMANHO: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// O mapa do espaço virtual
// ---------------------------------------------------------------------------
//
// O ARM chega ao mesmo objetivo do x86 por outro caminho. Lá a regra é "metade
// baixa para o usuário, alta para o kernel", porque uma entrada de topo cobre
// 512 GiB e não dá para fatiar mais fino. Aqui não existe metade alta — o
// `TCR_EL1` deste kernel configura 39 bits de endereço virtual e desliga as
// buscas por TTBR1 —, mas também não é preciso: a raiz é uma tabela de nível 1
// e **cada entrada dela cobre 1 GiB**.
//
// Com essa granularidade as regiões já ocupam entradas de topo distintas, sem
// precisar de endereços altos:
//
//   L1[0]    periféricos da máquina `virt` (UART, GIC)
//   L1[1]    imagem do kernel, em 0x4008_0000
//   L1[4]    espaço do usuário
//   L1[64]   heap do kernel
//   L1[128]  pilhas de fio
//   L1[192]  memória de dispositivo mapeada sob demanda
//
// É o que permite montar uma tabela por processo do mesmo jeito nas duas
// arquiteturas: copiam-se as entradas de topo do kernel, e as do usuário ficam
// de fora.

/// Onde a faixa de memória de dispositivo começa. 192 GiB.
///
/// Mapear um BAR aqui, e não confiar no mapa de identidade que já cobre o
/// primeiro GiB como dispositivo, é o que faz o driver ser o mesmo nas duas
/// arquiteturas. O endereço físico continua alcançável pela identidade
/// também; duas traduções para a mesma página, ambas de dispositivo, é algo
/// que a arquitetura permite.
pub const BASE_DE_MMIO: u64 = 0x0000_0030_0000_0000;

/// Onde o heap do kernel começa. 64 GiB.
pub const BASE_DO_HEAP: u64 = 0x0000_0010_0000_0000;

/// Onde a área das pilhas de fio começa. 128 GiB.
pub const BASE_DAS_PILHAS: u64 = 0x0000_0020_0000_0000;

/// Quanto espaço virtual uma entrada da tabela de topo cobre.
///
/// A raiz aqui é uma tabela de nível 1, e cada entrada cobre 1 GiB — 512 vezes
/// mais fino que a PML4 do x86. É por isso que este lado não precisa de
/// endereços altos para separar kernel de usuário.
pub const COBERTURA_DA_ENTRADA_DE_TOPO: u64 = 1024 * 1024 * 1024;

/// Nome da arquitetura, exposto no protocolo do agente.
pub const fn nome() -> &'static str {
    "aarch64"
}

// O ponto de entrada do kernel, em assembly.
//
// Precisa ser assembly porque as três primeiras tarefas são impossíveis de
// expressar em Rust: não há pilha para chamar funções, não há `.bss` zerado
// para os `static` funcionarem, e é preciso decidir o que fazer com os
// núcleos secundários antes que qualquer código Rust rode.
//
// `.text.boot` é uma seção própria que o linker script posiciona no início
// da imagem e marca com KEEP, garantindo que o ponto de entrada seja
// realmente o primeiro byte do kernel.
core::arch::global_asm!(
    r#"
.section .text.boot
.global _start
_start:
    // --- Cabeçalho de imagem arm64 (64 bytes) ---------------------------
    //
    // Este cabeçalho é o que transforma o binário numa imagem inicializável
    // pelo protocolo de boot do arm64. Sem ele, o QEMU trata o arquivo como
    // código solto e NÃO entrega o endereço do device tree — foi exatamente
    // esse o bug que o `log.tail` revelou: x0 chegava zerado.
    //
    // Com o cabeçalho, quem carrega (QEMU, U-Boot ou firmware UEFI) passa a
    // seguir o contrato documentado: device tree em x0, x1-x3 zerados.
    b       .Lprimary           // code0: desvia por cima do cabeçalho
    .long   0                   // code1: reservado
    .quad   0x80000             // text_offset: deslocamento de carga
    .quad   __image_size        // tamanho efetivo, .bss incluído
    .quad   0                   // flags: little-endian, página não fixada
    .quad   0                   // res2
    .quad   0                   // res3
    .quad   0                   // res4
    .ascii  "ARM\x64"          // magic: identifica uma imagem arm64
    .long   0                   // res5

.Lprimary:
    // x0 = endereço físico do device tree, por contrato do boot do arm64.
    // Precisa sobreviver até a chamada em Rust, então só tocamos x1 e x2.

    // Em SMP, todos os núcleos entram aqui. Apenas o núcleo 0 prossegue;
    // os demais ficam estacionados até termos um scheduler para eles.
    mrs     x1, mpidr_el1
    and     x1, x1, #0xFF
    cbnz    x1, .Lestacionar

    // Duas pilhas, e a separação entre elas é o que torna um estouro
    // diagnosticável.
    //
    // Entramos com SPSel=1, ou seja, `sp` é SP_EL1. Apontamos SP_EL1 para a
    // pilha de exceção e então trocamos para SP_EL0, que passa a ser a pilha
    // normal do kernel.
    //
    // O ganho vem de uma regra da arquitetura: ao tomar uma exceção para EL1,
    // o processador usa SP_EL1 automaticamente. Então, quando a pilha do
    // kernel estourar e bater na guard page, o handler já roda numa pilha
    // intacta — sem precisar de nenhum código nosso para trocar. É o
    // equivalente ARM da Interrupt Stack Table do x86.
    adrp    x1, __exc_stack_top
    add     x1, x1, :lo12:__exc_stack_top
    mov     sp, x1

    msr     spsel, #0
    adrp    x1, __stack_top
    add     x1, x1, :lo12:__stack_top
    mov     sp, x1

    // Zerar o .bss. O firmware não garante nada sobre o conteúdo da RAM, e
    // todo `static` do kernel vive aqui — inclusive os spinlocks e o ring
    // buffer de log. Pular este passo produz corrupção não determinística,
    // do tipo mais caro de depurar.
    adrp    x1, __bss_start
    add     x1, x1, :lo12:__bss_start
    adrp    x2, __bss_end
    add     x2, x2, :lo12:__bss_end
.Llimpar_bss:
    cmp     x1, x2
    b.hs    .Lem_rust
    str     xzr, [x1], #8
    b       .Llimpar_bss

.Lem_rust:
    bl      {entrada}

    // `entrada` é divergente, então nunca voltamos. Se voltarmos, algo está
    // profundamente errado e parar é mais seguro que continuar.
.Lestacionar:
    wfe
    b       .Lestacionar
"#,
    entrada = sym inicio_aarch64,
);

/// Primeira função Rust a executar no ARM.
///
/// Recebe em `dtb` o endereço do device tree que o assembly preservou em `x0`.
#[unsafe(no_mangle)]
extern "C" fn inicio_aarch64(dtb: u64) -> ! {
    // A serial vem antes de qualquer outra coisa. Sem ela, qualquer falha a
    // partir daqui seria silêncio absoluto — no ARM nem tela preta existe.
    let canal = crate::serial::init();

    // SAFETY: `dtb` veio do firmware em `x0`, que é exatamente o contrato do
    // boot do arm64. O parser valida a assinatura antes de confiar no resto.
    let resultado = unsafe {
        fdt::percorrer_memoria(dtb as *const u8, |inicio, tamanho| {
            crate::machine::adicionar_regiao(Regiao {
                inicio,
                fim: inicio + tamanho,
                // O device tree descreve a RAM instalada; ele não marca o que
                // já está ocupado. O próprio kernel está dentro de uma dessas
                // faixas — reconciliar isso é tarefa do alocador de frames,
                // que vai usar os símbolos do linker script para se excluir.
                tipo: TipoRegiao::Utilizavel,
            });
        })
    };

    if let Err(erro) = resultado {
        crate::log_error!("fdt", "device tree ilegivel: {}", erro);
    }

    // SAFETY: mesmo ponteiro já validado pelo percurso acima.
    if let Some(tamanho) = unsafe { fdt::tamanho_total(dtb as *const u8) } {
        DTB_INICIO.store(dtb, Ordering::Relaxed);
        DTB_TAMANHO.store(tamanho, Ordering::Relaxed);
    }

    crate::inicio_comum(canal)
}

/// Abre as portas seriais: (console humano, canal do agente).
///
/// A máquina `virt` do QEMU expõe **uma única** PL011 — verificado no device
/// tree que ela mesma gera. (Há uma segunda com `secure=on`, mas ela vive no
/// mundo seguro e fica inacessível a um kernel em EL1 não-seguro.)
///
/// Com uma porta só, a escolha é clara: ela vai para o canal do agente. Não
/// há console humano em texto no ARM, e isso não é uma perda — os registros
/// de log continuam todos no ring buffer, acessíveis por `log.tail`. É o
/// próprio canal estruturado servindo de interface de depuração, que é a
/// premissa do projeto.
pub fn init_seriais() -> (Option<Uart>, Option<Uart>) {
    // SAFETY: rodamos antes de qualquer outro código tocar na PL011, em
    // núcleo único, então o acesso é de fato exclusivo.
    let porta = unsafe { Uart::abrir(uart::PL011_BASE) };

    if cfg!(feature = "modo-teste") {
        // Na suíte de testes não há agente: o que precisamos é ver o relatório
        // em texto. Com uma porta só, ela vira o console.
        (porta, None)
    } else {
        (None, porta)
    }
}

/// Monta o mapa de identidade e liga a MMU.
///
/// Antes desta chamada todo endereço é físico. Depois dela, a tradução está
/// ativa — mas como o mapa é de identidade, nada muda de lugar, que é
/// precisamente o que torna a transição sobrevivível.
pub fn init_paginacao() {
    // SAFETY: chamada uma única vez no boot, com as interrupções ainda
    // mascaradas neste ponto do fluxo.
    unsafe { mmu::init() };
}

/// Só para a suíte: o par de conversões de permissão deste backend.
#[cfg(feature = "modo-teste")]
pub use mmu::permissoes_ida_e_volta;

pub use mmu::{
    acesso_fisico, criar_espaco, desmapear, destruir_espaco, espaco_atual, espaco_do_kernel,
    mapear_frame, percorrer_paginas_do_usuario, traduzir, trocar_espaco,
};

/// O nome da falha que um estouro de pilha produz nesta arquitetura.
///
/// A pilha bate na guard page, que está desmapeada, e o acesso gera uma falha
/// de tradução — que a arquitetura classifica como *data abort* do nível atual.
pub const fn falha_de_estouro_de_pilha() -> &'static str {
    "data_abort"
}

/// Informa faixas de memória física que o alocador de frames não pode
/// entregar.
///
/// No ARM isto não é opcional, e o motivo é uma diferença de fundo em relação
/// ao x86: o device tree descreve a **RAM instalada**, não a RAM *livre*. Ele
/// não tem como saber o que o firmware já colocou ali.
///
/// Duas coisas estão dentro dessa RAM "utilizável" e não podem ser entregues:
///
/// 1. A imagem do kernel, delimitada pelos símbolos do linker script. Inclui
///    o `.bss` e, portanto, a pilha em que estamos rodando agora.
/// 2. O próprio device tree, que o firmware depositou na RAM.
///
/// Sem isto, a primeira alocação de frame devolveria alegremente o pedaço de
/// memória onde o kernel está executando.
pub fn reservar_faixas(mut f: impl FnMut(u64, u64)) {
    // SAFETY: símbolos definidos pelo linker script; só tomamos seus
    // endereços, nunca lemos através deles.
    unsafe extern "C" {
        static __image_start: u8;
        static __image_end: u8;
    }
    let inicio = &raw const __image_start as u64;
    let fim = &raw const __image_end as u64;
    f(inicio, fim);

    let dtb = DTB_INICIO.load(Ordering::Relaxed);
    let tamanho = DTB_TAMANHO.load(Ordering::Relaxed);
    if tamanho > 0 {
        f(dtb, dtb + tamanho);
    }
}

/// Instala a tabela de vetores de exceção em `VBAR_EL1`.
///
/// Antes desta chamada, uma exceção salta para onde quer que o firmware tenha
/// deixado o VBAR apontando — na prática, comportamento indefinido.
pub fn init_excecoes() {
    vetores::init();
    crate::log_info!(
        "traps",
        "vetores instalados, rodando em EL{}",
        vetores::nivel_de_excecao()
    );
}

/// Inicializa o GIC e o timer genérico, e desmascara as IRQs.
///
/// Exige que [`init_excecoes`] já tenha rodado: habilitar interrupções sem
/// tabela de vetores instalada é pedir um salto para lugar nenhum.
pub fn init_interrupcoes() {
    /// 100 Hz dá resolução de 10 ms — suficiente para medir uptime e para o
    /// scheduler da fase 1, sem custo perceptível de handler.
    const HZ: u32 = 100;

    // SAFETY: as IRQs ainda estão mascaradas neste ponto (só as
    // desmascaramos no fim), e a tabela de vetores já está instalada.
    let efetiva = unsafe {
        gic::init();
        gic::init_timer(HZ)
    };

    crate::tempo::registrar_frequencia(efetiva);
    crate::irq::nomear(gic::INTID_TIMER as usize, "timer-generico");

    // Desmascara IRQs (bit I do DAIF). A partir daqui o timer preempta o
    // kernel periodicamente.
    // SAFETY: há tabela de vetores instalada e um handler para toda classe.
    unsafe { asm!("msr daifclr, #2", options(nomem, nostack)) };

    crate::log_info!("irq", "GIC ativo, timer a {} Hz", efetiva);
}

/// Espera pela próxima interrupção, em baixo consumo.
///
/// Devolve o controle imediatamente se as IRQs estiverem mascaradas: `wfi`
/// com interrupções desabilitadas pararia o núcleo para sempre.
pub fn esperar_interrupcao() {
    if interrupcoes_habilitadas() {
        wfi();
    } else {
        core::hint::spin_loop();
    }
}

/// Onde o firmware depositou o device tree.
///
/// Guardado em vez de repassado porque quem precisa dele não está no caminho
/// do boot: a descoberta de interrupção de um dispositivo PCI acontece muito
/// depois, e o ponteiro só chega uma vez, em `x0`.
pub fn dtb() -> *const u8 {
    DTB_INICIO.load(Ordering::Relaxed) as *const u8
}

/// Quanto do ECAM vale mapear: um barramento inteiro.
///
/// Cada função tem 4 KiB de configuração, e um barramento tem 256 funções —
/// 1 MiB. A janela completa que a placa declara cobre os 256 barramentos
/// possíveis (256 MiB), e mapear tudo custaria 65 mil páginas para varrer um.
const TAMANHO_DE_UM_BARRAMENTO: u64 = 1024 * 1024;

/// Descobre onde a configuração PCI está mapeada, lendo o device tree.
///
/// Chamada antes da enumeração. Se a máquina não descrever um barramento — ou
/// se o device tree não chegou —, a enumeração simplesmente não acontece e o
/// kernel diz isso no log, em vez de ler um endereço inventado.
pub fn init_pci() {
    let dtb = dtb();

    // SAFETY: o ponteiro veio do firmware em `x0` e foi guardado no boot;
    // `encontrar_ecam` confere a assinatura antes de olhar qualquer campo, e
    // trata o ponteiro nulo.
    let Some(barramento) = (unsafe { fdt::encontrar_barramento_pci(dtb) }) else {
        crate::log_warn!("pci", "device tree nao descreve barramento PCI");
        return;
    };
    let (base, tamanho) = barramento.ecam;

    // O ECAM fica **fora** do mapa de identidade: a máquina `virt` o coloca em
    // 0x40_1000_0000, muito acima do primeiro GiB que o boot mapeia. Precisa
    // ser mapeado, e como memória de dispositivo — uma leitura de configuração
    // servida pelo cache devolveria um valor velho, e o barramento não avisa.
    //
    // Mapeamos só um barramento, e não a janela inteira que a placa declara:
    // ela cobre os 256 barramentos possíveis, e mapeá-la custaria 65 mil
    // páginas para varrer um.
    let janela = tamanho.min(TAMANHO_DE_UM_BARRAMENTO);
    let onde = match crate::mmio::mapear(base, janela) {
        Ok(onde) => onde,
        Err(motivo) => {
            crate::log_warn!("pci", "ECAM nao pode ser mapeado: {}", motivo);
            return;
        }
    };

    crate::log_info!(
        "pci",
        "ECAM em {:#x}, {} KiB mapeados de {} KiB",
        base,
        janela / 1024,
        tamanho / 1024
    );
    pci::registrar(onde, janela);

    // A janela de MMIO é onde o kernel vai pôr os BARs. Ela não é mapeada
    // aqui: quem precisa de um BAR é o driver daquele dispositivo, e mapear
    // 751 MiB para usar alguns KiB seria 190 mil páginas de desperdício. Ver
    // [`crate::mmio`].
    let Some((no_barramento, na_cpu, tamanho)) = barramento.mmio32 else {
        crate::log_warn!("pci", "device tree nao declara janela de MMIO de 32 bits");
        return;
    };

    crate::log_info!(
        "pci",
        "janela de MMIO em {:#x} (barramento {:#x}), {} MiB",
        na_cpu,
        no_barramento,
        tamanho / (1024 * 1024)
    );
    pci::registrar_janela(no_barramento, na_cpu, tamanho);
}

/// Faz a serial do agente interromper quando chegar um byte.
///
/// Fica separada de [`init_interrupcoes`] porque a ordem importa: só faz
/// sentido liberar a linha depois que existe quem consuma os bytes.
pub fn init_interrupcao_serial() {
    // Antes de ligar a recepção: o FIFO pode ter um pedaço de requisição de
    // quem conectou enquanto o kernel ainda bootava. Ver
    // `tarefas::entrada::descartar_pendentes` — deixá-lo ali contamina a
    // requisição seguinte.
    let descartados = crate::tarefas::entrada::descartar_pendentes();
    if descartados > 0 {
        crate::log_warn!(
            "agent",
            "{} bytes descartados: chegaram antes do canal subir",
            descartados
        );
    }

    sem_interrupcoes(|| {
        let mut guarda = crate::serial::AGENT_LINK.lock();
        let Some(porta) = guarda.as_mut() else {
            return;
        };
        porta.habilitar_interrupcao_recepcao();

        // SAFETY: os vetores e o GIC já estão instalados, e estamos com as
        // interrupções mascaradas.
        unsafe { gic::habilitar_uart() };
    });

    crate::irq::nomear(gic::INTID_UART as usize, "pl011-agente");
    crate::log_info!("irq", "PL011 interrompendo no INTID {}", gic::INTID_UART);
}

/// Dorme até a próxima interrupção, mas só se `ocioso` confirmar que não há
/// trabalho — e sem deixar fresta entre as duas coisas.
///
/// # Por que no ARM isto é mais simples que no x86
///
/// O x86 precisa de um par `sti; hlt` cuidadosamente ordenado para não perder
/// uma interrupção que chegue entre a checagem e o adormecer. No ARM a
/// corrida simplesmente não existe: o manual (Arm ARM, *Wait For Interrupt*)
/// define que uma IRQ pendente é um evento de despertar do `wfi`
/// **independentemente de PSTATE.I** — ou seja, mesmo mascarada, ela acorda o
/// núcleo.
///
/// Isso nos dá a atomicidade de graça. Mascaramos as IRQs, checamos, e
/// dormimos: qualquer interrupção que tenha chegado nesse meio-tempo já está
/// pendente e o `wfi` retorna de imediato. Só depois desmascaramos, e aí ela é
/// entregue.
pub fn dormir_se_ocioso(ocioso: impl FnOnce() -> bool) {
    let estavam_habilitadas = mascarar_irqs();

    if ocioso() {
        wfi();
    }

    restaurar_irqs(estavam_habilitadas);
}

/// As IRQs estão desmascaradas?
pub fn interrupcoes_habilitadas() -> bool {
    DAIF.matches_all(DAIF::I::Unmasked)
}

/// Mascara as IRQs e devolve se elas *estavam* habilitadas.
///
/// # Por que `daifset` à mão, e não o registrador tipado
///
/// Este é o caso em que a versão escrita à mão é melhor, e vale registrar por
/// quê. Escrever `DAIF` pelo caminho tipado emite `msr daif, x`, que grava os
/// quatro bits de uma vez — mexeríamos em D, A e F sem querer. A alternativa
/// tipada que preserva os outros (`modify`) é leitura-modificação-escrita:
/// três instruções onde a arquitetura oferece uma.
///
/// `daifset #2` liga *apenas* o bit I, numa instrução só. Não há aritmética
/// de bits para errar aqui — o `#2` é o seletor de campo que o assembler
/// entende —, então o crate não teria o que melhorar.
fn mascarar_irqs() -> bool {
    let estavam_habilitadas = interrupcoes_habilitadas();
    // SAFETY: mascarar IRQs não tem pré-condição; `nomem`/`nostack` informam
    // ao compilador que não tocamos memória nem pilha.
    unsafe { asm!("msr daifset, #2", options(nomem, nostack)) };
    estavam_habilitadas
}

/// Desmascara as IRQs, mas só se `estavam_habilitadas`.
///
/// Reabilitar incondicionalmente quebraria o aninhamento: um chamador externo
/// que as mascarou de propósito as veria ligadas de volta ao fim da *nossa*
/// seção crítica, e não da dele.
fn restaurar_irqs(estavam_habilitadas: bool) {
    if estavam_habilitadas {
        // SAFETY: mesma justificativa de `mascarar_irqs`.
        unsafe { asm!("msr daifclr, #2", options(nomem, nostack)) };
    }
}

/// Dispara um breakpoint (`brk`), que é tratado e retorna normalmente.
///
/// Existe para que o agente possa verificar, em tempo de execução, que o
/// caminho de exceções está de fato funcionando — ver o comando
/// `debug.trigger`.
pub fn disparar_breakpoint() {
    // SAFETY: `brk` gera uma exceção síncrona que o handler em `vetores`
    // reconhece e da qual retoma, avançando o ELR por cima desta instrução.
    unsafe { asm!("brk #0", options(nomem, nostack)) };
}

/// Endereço garantidamente não mapeado, para provocar uma falha de propósito.
///
/// O mapa de identidade cobre o bloco de dispositivos (o primeiro GiB) e os
/// blocos de 1 GiB que contêm RAM — na máquina `virt`, a partir de
/// `0x4000_0000`. Este endereço cai no quarto bloco, que nunca é mapeado.
const ENDERECO_INVALIDO: u64 = 0xDEAD_0000;

/// Provoca uma falha irrecuperável de propósito. Nunca retorna.
///
/// Serve ao comando `debug.trigger` com `kind: "fatal"`, que existe para
/// exercitar o modo post-mortem sem precisar plantar um defeito no código e
/// recompilar.
pub fn disparar_falha_fatal() -> ! {
    // SAFETY: nenhuma. É deliberadamente inválida — escrever aqui é o ponto.
    // O resultado é um data abort, que os vetores reconhecem e encaminham ao
    // modo post-mortem.
    unsafe { core::ptr::write_volatile(ENDERECO_INVALIDO as *mut u64, 0) };

    // Inalcançável se a MMU estiver funcionando. Se chegarmos aqui, o fato de
    // *não* ter falhado é em si o diagnóstico.
    crate::log_error!(
        "debug",
        "escrita em {:#x} nao falhou; a MMU nao esta protegendo nada",
        ENDERECO_INVALIDO
    );
    halt_forever()
}

/// Executa `f` com as interrupções mascaradas, restaurando o estado ao sair.
///
/// No ARM as máscaras vivem no registrador `DAIF`, um por classe de exceção:
/// **D**ebug, **A**bort (SError), **I**RQ e **F**IQ. Mexemos apenas no bit I,
/// que é o equivalente do `cli`/`sti` do x86.
pub fn sem_interrupcoes<R>(f: impl FnOnce() -> R) -> R {
    let estavam_habilitadas = mascarar_irqs();
    let resultado = f();
    restaurar_irqs(estavam_habilitadas);
    resultado
}

/// Para a CPU até o próximo evento, para sempre.
///
/// `wfe` (*wait for event*) é o análogo do `hlt` do x86: coloca o núcleo em
/// baixo consumo em vez de queimar ciclos num laço vazio.
pub fn halt_forever() -> ! {
    loop {
        wfe();
    }
}

/// Identifica o fabricante da CPU pelo registrador `MIDR_EL1`.
///
/// O ARM não tem nada como o `CPUID` do x86, que devolve uma string pronta.
/// O que existe é um byte de código de fabricante nos bits 31:24, atribuído
/// pela ARM Ltd. e documentado no manual de arquitetura.
pub fn identificar_cpu() -> super::IdCpu {
    let fabricante: &[u8] = match MIDR_EL1.read(MIDR_EL1::Implementer) {
        0x41 => b"ARM Limited",
        0x42 => b"Broadcom",
        0x43 => b"Cavium",
        0x44 => b"Digital Equipment",
        0x46 => b"Fujitsu",
        0x48 => b"HiSilicon",
        0x49 => b"Infineon",
        0x4e => b"NVIDIA",
        0x50 => b"Applied Micro",
        0x51 => b"Qualcomm",
        0x56 => b"Marvell",
        0x61 => b"Apple",
        0x69 => b"Intel",
        0xc0 => b"Ampere",
        _ => b"desconhecido",
    };

    super::IdCpu::de_bytes(fabricante)
}

/// Encerra o QEMU por *semihosting*.
///
/// O ARM não tem nada como o `isa-debug-exit` do x86. O que existe é o
/// semihosting: uma convenção em que o programa executa `hlt #0xF000` e o
/// emulador (ou um depurador conectado) interpreta os registradores como uma
/// chamada de serviço do host. É assim que firmware embarcado imprime em
/// console e termina processos durante testes.
///
/// Requer que o QEMU seja iniciado com `-semihosting-config enable=on`; sem
/// isso a instrução vira uma exceção comum. O xtask cuida disso.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn encerrar_emulador(resultado: crate::qemu::Resultado) -> ! {
    use crate::qemu::Resultado;

    /// `SYS_EXIT_EXTENDED`: permite informar um código de saída arbitrário,
    /// diferente do `SYS_EXIT` simples que só sinaliza "terminou".
    const SYS_EXIT_EXTENDED: u64 = 0x20;

    /// `ADP_Stopped_ApplicationExit`: encerramento normal da aplicação.
    const ADP_STOPPED_APPLICATION_EXIT: u64 = 0x20026;

    let codigo: u64 = match resultado {
        Resultado::Sucesso => 0,
        Resultado::Falha => 1,
    };

    // A operação recebe os argumentos por um bloco em memória, não por
    // registradores: x1 aponta para [motivo, código].
    let bloco: [u64; 2] = [ADP_STOPPED_APPLICATION_EXIT, codigo];

    // SAFETY: com semihosting habilitado, o QEMU intercepta esta instrução e
    // encerra o processo. Com ele desabilitado vira uma exceção, que também
    // interrompe a execução — em nenhum caso corrompemos estado.
    unsafe {
        asm!(
            "hlt #0xF000",
            in("x0") SYS_EXIT_EXTENDED,
            in("x1") bloco.as_ptr(),
            options(nostack),
        );
    }

    // Inalcançável sob o QEMU, mas o kernel também roda em hardware real,
    // onde não há semihosting para atender a chamada.
    halt_forever()
}
