//! Tabela de descritores globais (GDT) e segmento de estado da tarefa (TSS).
//!
//! # Por que ainda existe segmentação no x86_64
//!
//! Em 64 bits a segmentação está praticamente aposentada: os segmentos são
//! fixos em base 0 e não limitam nada. Mas a GDT não pôde ser removida, porque
//! duas coisas ainda dependem dela — o seletor de código que define o nível de
//! privilégio, e o ponteiro para o TSS.
//!
//! # O que o TSS faz aqui
//!
//! Em 32 bits o TSS guardava contexto para troca de tarefas por hardware. Em
//! 64 bits esse mecanismo sumiu e sobrou algo mais útil: a **Interrupt Stack
//! Table**, sete pilhas alternativas que o processador pode trocar
//! automaticamente ao entrar numa exceção.
//!
//! # Por que isso não é opcional
//!
//! Considere um stack overflow do kernel. O guard page é atingido, o
//! processador gera um page fault e tenta empilhar o quadro da exceção — na
//! mesma pilha estourada. Essa escrita falha também, virando double fault. Ao
//! tratar o double fault ele tenta empilhar de novo, falha de novo, e o
//! resultado é **triple fault**: a máquina reinicia sem uma linha de
//! diagnóstico.
//!
//! A IST quebra esse ciclo. Declarando que o handler de double fault usa uma
//! pilha própria, garantimos que ele sempre tenha para onde empilhar — e
//! transformamos um reboot silencioso num relatório completo pelo canal do
//! agente.
//!
//! # Os segmentos de dados também importam
//!
//! Ver o comentário em [`init`] sobre `SS`: em modo longo é tentador deixar os
//! registradores de dados como estão, e isso produz uma falha tardia e
//! confusa no primeiro retorno de interrupção.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU16, Ordering};

use spin::once::Once;
use x86_64::VirtAddr;
use x86_64::instructions::segmentation::{CS, DS, ES, FS, GS, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

use crate::nucleos::MAX_NUCLEOS;

/// Índice, dentro da IST, da pilha reservada ao double fault.
pub const IST_DOUBLE_FAULT: u16 = 0;

/// Índice, dentro da IST, da pilha reservada à NMI.
///
/// # Por que a NMI precisa de uma pilha própria
///
/// Porque ela chega em **qualquer** instrução — é essa a definição de "não
/// mascarável". Inclusive nas três primeiras instruções do ponto de entrada
/// de `syscall`, quando o `RSP` ainda é a pilha do **usuário**: o processador
/// empilharia o quadro da NMI onde o processo mandou. Com uma pilha da IST, a
/// troca é feita pelo hardware antes de qualquer escrita, não importa onde a
/// NMI caia.
///
/// É por NMI que um núcleo avisa os outros de que uma tradução do kernel
/// morreu, e de que o sistema parou — ver [`super::smp`]. As duas coisas
/// precisam alcançar um núcleo que esteja girando com as interrupções
/// desligadas, e só a NMI alcança.
pub const IST_NMI: u16 = 1;

/// Índice, dentro da IST, da pilha reservada ao `#DB`.
///
/// # Por que o `#DB` precisa de uma pilha própria
///
/// Pelo mesmo motivo da NMI: ele pode chegar ao anel 0 numa das instruções
/// do ponto de entrada de `syscall` em que o `RSP` ainda é a pilha do
/// **usuário**. O `TF` do processo é o caminho conhecido — o `SFMask` o apaga
/// na entrada (ver [`super::usuario::ligar_neste_nucleo`]) —, e um aviso de
/// depuração adiado por um `mov ss` até depois da `syscall` é o outro. Sem a
/// pilha da IST, o processador empilharia o quadro onde o processo mandou,
/// numa memória que outro fio dele escreve enquanto o tratador roda; com
/// ela, a troca é feita pelo hardware antes de qualquer escrita.
///
/// O tratador do `#DB` vindo do anel 3 não fica nela: a morte do processo
/// continua na pilha de kernel do fio (ver `idt::depuracao`).
pub const IST_DEPURACAO: u16 = 2;

/// Índice, dentro da IST, da pilha reservada ao `#MC`.
///
/// # Por que o `#MC` não divide a do `#DF`
///
/// Os dois são sempre fatais e não voltam, e por isso dividiam a pilha. Mas
/// um pode chegar no meio do post-mortem do outro: um `#MC` enquanto o
/// relatório de um `#DF` corre — ou o contrário —, e a pilha da IST
/// recomeça no topo, por cima do quadro e do relatório em curso, que
/// sumiam (o item 6 do adversário do lote B2 do #448). Com uma pilha cada,
/// o segundo relata por cima do primeiro, sem apagá-lo.
pub const IST_VERIFICACAO_DA_MAQUINA: u16 = 3;

/// 20 KiB. Não precisa ser grande: quem roda nela é um tratador curto — o
/// que registra a falha e entra em post-mortem, o aviso da NMI, ou o passo
/// do `#DB`, que volta ou passa à pilha do fio.
const TAM_PILHA: usize = 4096 * 5;

/// Uma pilha da IST.
///
/// O `UnsafeCell` não é decoração: um `static` sem mutabilidade interior vai
/// para `.rodata`, que é somente leitura — e o processador precisa *escrever*
/// o quadro da exceção aqui. O `UnsafeCell` é o que faz o linker colocá-la
/// numa seção gravável.
#[repr(align(16))]
struct PilhaEmergencia(UnsafeCell<[u8; TAM_PILHA]>);

// SAFETY: quem escreve em cada uma destas regiões é o processador, ao
// entregar uma exceção ao núcleo **dono** dela — cada núcleo tem as suas, e
// nenhum código Rust as lê ou escreve. A impl existe apenas para permitir
// guardá-las num `static`.
unsafe impl Sync for PilhaEmergencia {}

/// As pilhas de double fault, uma por núcleo.
static PILHAS_DOUBLE_FAULT: [PilhaEmergencia; MAX_NUCLEOS] =
    [const { PilhaEmergencia(UnsafeCell::new([0; TAM_PILHA])) }; MAX_NUCLEOS];

/// As pilhas de NMI, uma por núcleo.
static PILHAS_NMI: [PilhaEmergencia; MAX_NUCLEOS] =
    [const { PilhaEmergencia(UnsafeCell::new([0; TAM_PILHA])) }; MAX_NUCLEOS];

/// As pilhas do `#DB`, uma por núcleo.
static PILHAS_DEPURACAO: [PilhaEmergencia; MAX_NUCLEOS] =
    [const { PilhaEmergencia(UnsafeCell::new([0; TAM_PILHA])) }; MAX_NUCLEOS];

/// As pilhas do `#MC`, uma por núcleo.
static PILHAS_VERIFICACAO_DA_MAQUINA: [PilhaEmergencia; MAX_NUCLEOS] =
    [const { PilhaEmergencia(UnsafeCell::new([0; TAM_PILHA])) }; MAX_NUCLEOS];

/// Um TSS, num `UnsafeCell` porque `privilege_stack_table[0]` precisa mudar.
///
/// Esse campo é o `RSP0`: a pilha que o processador adota automaticamente
/// quando uma interrupção chega enquanto o código do usuário está rodando.
/// Como cada fio de execução tem sua própria pilha de kernel, o valor precisa
/// acompanhar a troca de contexto — daí a mutabilidade.
struct TssMutavel(UnsafeCell<TaskStateSegment>);

// SAFETY: cada TSS é de um núcleo só. O único campo que muda depois do boot é
// `RSP0`, escrito pelo próprio núcleo dono, com as interrupções mascaradas,
// durante a troca de contexto; fora isso, o processador apenas lê.
unsafe impl Sync for TssMutavel {}

/// Um TSS por núcleo.
///
/// # Por que um por núcleo, e não um só
///
/// Porque o TSS carrega duas coisas que são do núcleo e não do sistema: o
/// `RSP0` — a pilha de kernel do fio que **este** núcleo está rodando — e as
/// pilhas da IST. Dois núcleos com o mesmo `RSP0` empilhariam quadros de
/// interrupção na mesma pilha ao mesmo tempo; com a mesma IST, um double
/// fault em cada um escreveria por cima do outro.
///
/// E há um motivo de hardware também: `ltr` marca o descritor como
/// **ocupado**, e carregar um descritor ocupado é `#GP`. O segundo núcleo
/// nem conseguiria adotar o TSS do primeiro.
static TSSS: [TssMutavel; MAX_NUCLEOS] =
    [const { TssMutavel(UnsafeCell::new(TaskStateSegment::new())) }; MAX_NUCLEOS];

/// Os seletores que a GDT publica.
pub struct Seletores {
    pub codigo_kernel: SegmentSelector,
    pub dados_kernel: SegmentSelector,
    pub codigo_usuario: SegmentSelector,
    pub dados_usuario: SegmentSelector,
    tss: [SegmentSelector; MAX_NUCLEOS],
}

/// Quantos descritores cabem: os seis segmentos, e dois por TSS — um
/// descritor de sistema em 64 bits ocupa duas entradas.
#[cfg(not(feature = "modo-teste"))]
const ENTRADAS_DA_GDT: usize = 6 + 2 * MAX_NUCLEOS;

/// Na suíte, mais duas: o descritor do LDT de teste — ver
/// [`carregar_o_ldt_de_teste`]. Depois dos TSS, que não mudam de lugar.
#[cfg(feature = "modo-teste")]
const ENTRADAS_DA_GDT: usize = 6 + 2 * MAX_NUCLEOS + 2;

/// Só para a suíte: a base do LDT de teste — um endereço canônico sem
/// página em espaço nenhum, nem no do kernel, nem no de um processo (o
/// usuário começa em 4 GiB). O descritor do seletor 0x0F estaria em
/// `BASE_DO_LDT_DE_TESTE + 8`.
#[cfg(feature = "modo-teste")]
pub const BASE_DO_LDT_DE_TESTE: u64 = 0xDEAD_0000;

/// Só para a suíte: o seletor do descritor do LDT de teste, ou zero antes de
/// a GDT existir.
#[cfg(feature = "modo-teste")]
static SELETOR_DO_LDT_DE_TESTE: AtomicU16 = AtomicU16::new(0);

/// O descritor de sistema de um LDT de `base` e `limite`, presente, de DPL
/// 0, nas duas palavras que ele ocupa em 64 bits (SDM 3.5 e 7.2.3): na
/// primeira, o limite, a base até o bit 31, o tipo 2 — o LDT — e o `P`; na
/// segunda, a base de cima.
#[cfg(feature = "modo-teste")]
const fn descritor_de_ldt(base: u64, limite: u32) -> (u64, u64) {
    let limite = limite as u64;
    let baixo = (limite & 0xFFFF)
        | ((base & 0xFF_FFFF) << 16)
        | (0x2 << 40)
        | (1 << 47)
        | (((limite >> 16) & 0xF) << 48)
        | (((base >> 24) & 0xFF) << 56);
    (baixo, base >> 32)
}

static GDT: Once<(GlobalDescriptorTable<ENTRADAS_DA_GDT>, Seletores)> = Once::new();

/// O seletor do TSS do núcleo zero, ou zero antes de a GDT existir.
///
/// É a base da conta de [`nucleo_atual`]: os TSS são consecutivos na GDT,
/// dezesseis bytes cada.
static PRIMEIRO_TSS: AtomicU16 = AtomicU16::new(0);

/// Os seletores da GDT. Só é válido depois de [`init`].
pub fn seletores() -> &'static Seletores {
    &GDT.get().expect("a GDT precisa estar carregada").1
}

/// Em que núcleo este código está rodando.
///
/// # Como se responde, e por que assim
///
/// Pelo seletor que está em `TR` — o do TSS que este núcleo carregou. Cada
/// núcleo carrega o seu, e eles são consecutivos na GDT: o índice sai de uma
/// subtração e uma divisão.
///
/// As alternativas óbvias têm cada uma um defeito:
///
/// - **O `GS`**, que é o que os kernels costumam usar, é carregável pelo
///   **usuário**. Um processo que zere o próprio seletor de `GS` faria todo
///   handler de interrupção ler os dados por núcleo do endereço zero. É por
///   isso que o `GS` deste kernel só é tocado na entrada de `syscall`, por
///   `swapgs`, e nunca numa interrupção — ver [`super::usuario`].
/// - **O id do APIC local** exige uma leitura de memória de dispositivo, e o
///   id não é o índice: precisaria de uma tabela de tradução.
/// - **`rdtscp`/`rdpid`** dependem de o processador oferecê-las.
///
/// `TR` só muda por `ltr`, que é privilegiada: o processo não alcança. E
/// `str` existe em todo x86_64.
pub fn nucleo_atual() -> usize {
    let primeiro = PRIMEIRO_TSS.load(Ordering::Relaxed);
    if primeiro == 0 {
        return 0;
    }
    let tr: u16;
    // SAFETY: `str` só lê o registrador de tarefa; não toca memória nem
    // flags.
    unsafe {
        core::arch::asm!("str {0:x}", out(reg) tr, options(nomem, nostack, preserves_flags));
    }
    let indice = (tr.wrapping_sub(primeiro) / 16) as usize;
    if tr < primeiro || indice >= MAX_NUCLEOS {
        0
    } else {
        indice
    }
}

/// O topo de uma pilha da IST.
fn topo(pilha: &PilhaEmergencia) -> VirtAddr {
    // A pilha do x86 cresce para baixo, então o ponteiro que entregamos é o
    // **topo** da região, não o início.
    VirtAddr::from_ptr(pilha.0.get()) + TAM_PILHA as u64
}

/// Monta e carrega a GDT e o TSS do núcleo zero. Chame uma vez, antes da IDT.
///
/// Monta já os TSS de **todos** os núcleos: a GDT é uma só, compartilhada, e
/// não se acrescenta descritor a uma tabela que outros núcleos estão usando.
pub fn init() {
    let (gdt, seletores) = GDT.call_once(|| {
        let mut gdt = GlobalDescriptorTable::<ENTRADAS_DA_GDT>::empty();
        let codigo_kernel = gdt.append(Descriptor::kernel_code_segment());
        let dados_kernel = gdt.append(Descriptor::kernel_data_segment());

        // A ordem dos três próximos descritores **não é escolha nossa**: é o
        // que a instrução `sysret` impõe. Ao retornar para 64 bits ela carrega
        // `SS = STAR[63:48] + 8` e `CS = STAR[63:48] + 16`, sem consultar mais
        // nada. Então precisa existir, nessa sequência exata:
        //
        //   base + 0   um descritor qualquer (o `sysret` de 32 bits usaria)
        //   base + 8   dados de usuário
        //   base + 16  código de usuário
        //
        // Inverter dois deles produz um `#GP` no retorno da primeira chamada
        // de sistema — depois de ela ter funcionado.
        // Este é o `STAR[63:48]` de que o `sysret` parte; nunca é carregado.
        let _base_do_sysret = gdt.append(Descriptor::user_data_segment());
        let dados_usuario = gdt.append(Descriptor::user_data_segment());
        let codigo_usuario = gdt.append(Descriptor::user_code_segment());

        let mut tss = [SegmentSelector(0); MAX_NUCLEOS];
        for (i, seletor) in tss.iter_mut().enumerate() {
            // SAFETY: ainda estamos na inicialização, com um único núcleo e
            // sem interrupções; ninguém mais olha para estes TSS agora. As
            // pilhas da IST são escritas antes do descritor existir, e nunca
            // mais mudam.
            let referencia: &'static TaskStateSegment = unsafe {
                let tss = &mut *TSSS[i].0.get();
                tss.interrupt_stack_table[IST_DOUBLE_FAULT as usize] =
                    topo(&PILHAS_DOUBLE_FAULT[i]);
                tss.interrupt_stack_table[IST_NMI as usize] = topo(&PILHAS_NMI[i]);
                tss.interrupt_stack_table[IST_DEPURACAO as usize] = topo(&PILHAS_DEPURACAO[i]);
                tss.interrupt_stack_table[IST_VERIFICACAO_DA_MAQUINA as usize] =
                    topo(&PILHAS_VERIFICACAO_DA_MAQUINA[i]);
                &*TSSS[i].0.get()
            };
            *seletor = gdt.append(Descriptor::tss_segment(referencia));
        }

        // Na suíte, o descritor do LDT de teste, depois dos TSS.
        #[cfg(feature = "modo-teste")]
        {
            let (baixo, alto) = descritor_de_ldt(BASE_DO_LDT_DE_TESTE, 0xFFFF);
            let seletor = gdt.append(Descriptor::SystemSegment(baixo, alto));
            SELETOR_DO_LDT_DE_TESTE.store(seletor.0, Ordering::Relaxed);
        }

        (
            gdt,
            Seletores {
                codigo_kernel,
                dados_kernel,
                codigo_usuario,
                dados_usuario,
                tss,
            },
        )
    });

    PRIMEIRO_TSS.store(seletores.tss[0].0, Ordering::Relaxed);
    // Os seletores que o firmware deixou no primeiro núcleo, antes de
    // [`carregar`] trocá-los — só para o log do boot: os do `FS` e do `GS`,
    // que nada mais carregava, iam para a primeira troca de contexto.
    crate::log_info!(
        "cpu",
        "os seletores que o firmware deixou: CS {:#x}, SS {:#x}, DS {:#x}, ES {:#x}, FS {:#x}, \
         GS {:#x}",
        CS::get_reg().0,
        SS::get_reg().0,
        DS::get_reg().0,
        ES::get_reg().0,
        FS::get_reg().0,
        GS::get_reg().0
    );
    carregar(gdt, seletores, 0);
}

/// Carrega a GDT neste núcleo e o TSS do núcleo `indice`.
///
/// É o que um núcleo secundário faz logo que acorda: a GDT é a mesma de
/// todos, e o TSS é o dele.
///
/// # Safety
///
/// [`init`] precisa já ter rodado no primeiro núcleo, e `indice` precisa ser
/// o deste núcleo e de nenhum outro — o `ltr` de um TSS já carregado por
/// outro núcleo é `#GP`, e o de um TSS alheio ainda livre faria dois núcleos
/// dividirem `RSP0` e IST.
pub unsafe fn init_secundario(indice: usize) {
    let (gdt, seletores) = GDT.get().expect("a GDT precisa estar montada");
    carregar(gdt, seletores, indice);
}

fn carregar(
    gdt: &'static GlobalDescriptorTable<ENTRADAS_DA_GDT>,
    seletores: &Seletores,
    indice: usize,
) {
    gdt.load();
    let (seletor_codigo, seletor_dados, seletor_tss) = (
        &seletores.codigo_kernel,
        &seletores.dados_kernel,
        &seletores.tss[indice],
    );

    // SAFETY: os seletores vêm da GDT que acabamos de carregar, então apontam
    // para descritores válidos.
    unsafe {
        // Recarregar CS é obrigatório: até aqui ele ainda referencia a GDT do
        // firmware, que deixa de valer quando a nossa entra. O iniciador
        // deste projeto não monta GDT nenhuma — ele salta com a que a UEFI
        // deixou —, então quem herdamos é o EDK II. Num núcleo secundário, é
        // a GDT provisória da página de partida.
        CS::set_reg(*seletor_codigo);

        // Recarregar SS é igualmente obrigatório, por um motivo bem menos
        // óbvio — e que custou um #GP para descobrir.
        //
        // Em modo longo os registradores de dados são praticamente ignorados,
        // o que dá a falsa impressão de que podem ficar como estão. Mas o
        // `iretq` de 64 bits **sempre** repõe SS:RSP, mesmo quando não há
        // troca de privilégio. Se SS ainda contiver o seletor herdado, esse
        // valor passa a indexar a *nossa* GDT, onde ele aponta para outro
        // tipo de descritor.
        //
        // Este comentário já narrou isso no passado, e a troca do crate
        // `bootloader` pelo iniciador deste projeto não o tornou histórico —
        // só trocou o número. Medido hoje: o kernel entra com `cs=0x38
        // ss=0x30 ds=0x30`, deixados pelo EDK II, e a nossa GDT põe o TSS em
        // **0x30**. É a mesma coincidência de antes, quando o seletor
        // herdado era 0x10 e o TSS caía ali.
        //
        // E continua sendo o que separa um kernel de pé de um que morre no
        // primeiro retorno de exceção. Comentando a linha abaixo, a suíte
        // não chega ao primeiro caso:
        //
        //     error traps  FALHA FATAL #0: general_protection_fault
        //                  em pc=0xffff800000046588 codigo=0x30
        //
        // O código de erro do #GP é o próprio seletor ofensor — 0x30, o
        // nosso TSS.
        SS::set_reg(*seletor_dados);
        DS::set_reg(*seletor_dados);
        ES::set_reg(*seletor_dados);

        // E o `FS` e o `GS` nulos. O firmware os deixa com um seletor da GDT
        // dele — o EDK II, o mesmo 0x30 do `SS` e do `DS` —, e desde o lote
        // B4 do #448 a troca de contexto guarda os quatro seletores de dados
        // por fio e os recarrega (`contexto::trocar_contexto`): o fio do boot
        // levaria o 0x30 do `FS` e do `GS` para a primeira troca, e
        // recarregá-los na volta seria `#GP(0x30)` no anel 0 — o `GS`
        // primeiro —; o TSS do núcleo 0 não é um segmento de dados. Nulos,
        // eles são o que um fio novo recebe; o `GS` nulo muda a base ativa
        // dele, e não o `IA32_KERNEL_GS_BASE` do `swapgs`. As bases, o nulo
        // as zera num Intel e no TCG, e não num AMD sem o
        // `NullSelectorClearsBase`: quem as zera em todo processador é o
        // regime do núcleo (`escrever_o_regime_deste_nucleo`), antes do
        // primeiro processo dele.
        FS::set_reg(SegmentSelector(0));
        GS::set_reg(SegmentSelector(0));

        load_tss(*seletor_tss);
    }

    // E o LDT nulo, em todo núcleo — o primeiro, por [`init`], e cada um que
    // acorda, por [`init_secundario`]. O processador sai do reset — e cada
    // secundário, do INIT da partida (`smp`) — com o `LDTR` **válido**, de
    // base 0 e limite 0xFFFF (SDM, tabela 9-1), e nem o firmware, nem o
    // iniciador, nem o trampolim carregam outro. Um seletor com o TI ligado
    // vindo de um processo — o `mov ds` com 0x0F, e também o `mov ss`, o
    // `lsl`, o `lar`, o `verr`, o `retf` — fazia o processador ler o
    // descritor no endereço 0x8 **do processo**, num acesso de supervisor:
    // ali não há página, e a falha de página sem o `U` era tomada por do
    // kernel — `FALHA FATAL page_fault`, `endereco acusado: 0x8`, num `pc`
    // do processo (o achado 1 do adversário do lote B2 do #448). Com o LDT
    // nulo, o `mov` é `#GP` com o seletor no código, e o processo morre dele;
    // o `lsl` só apaga o `ZF`.
    carregar_o_ldt_nulo();
}

/// O `RSP0` do TSS deste núcleo: o topo da pilha de kernel do fio que ele
/// roda, que [`definir_pilha_de_kernel`] acompanha a cada troca — a pilha
/// que o processador adota para uma exceção vinda do anel 3. Zero antes de
/// a GDT existir, ou com o fio inicial.
///
/// Lido sem trava: só este núcleo escreve o dele, com as interrupções
/// mascaradas, e quem lê aqui é um tratador de exceção deste núcleo — ver
/// `idt::depuracao`.
pub fn pilha_de_kernel_deste_nucleo() -> u64 {
    if GDT.get().is_none() {
        return 0;
    }
    // SAFETY: leitura de uma palavra do TSS **deste** núcleo; só ele a
    // escreve, e não pode estar escrevendo agora — ver acima.
    unsafe { (*TSSS[nucleo_atual()].0.get()).privilege_stack_table[0].as_u64() }
}

/// Só para a suíte: o topo da pilha da IST de índice `indice` — contado de
/// 0, como em [`IST_VERIFICACAO_DA_MAQUINA`] — no TSS do núcleo `nucleo`.
#[cfg(feature = "modo-teste")]
pub fn topo_da_ist_de_teste(nucleo: usize, indice: usize) -> u64 {
    TSSS.get(nucleo).map_or(0, |tss| {
        // SAFETY: cópia da tabela da IST do TSS, que só muda no `RSP0` — por
        // valor: o TSS é empacotado, e uma referência ao campo não se alinha.
        let tabela = unsafe { (*tss.0.get()).interrupt_stack_table };
        tabela.get(indice).map_or(0, |t| t.as_u64())
    })
}

/// Aponta o `RSP0` do TSS do núcleo `nucleo` — o deste, lido uma vez só
/// por quem chama — para o topo da pilha de kernel do fio que ele vai rodar.
///
/// É o endereço que o processador adota sozinho quando uma interrupção chega
/// com o código do usuário rodando. Precisa acompanhar a troca de contexto:
/// apontar para a pilha de outro fio faria dois fios empilharem quadros de
/// exceção no mesmo lugar.
///
/// Só com as interrupções mascaradas: entre a leitura do núcleo e a escrita,
/// um fio solto pode ser preemptado e ir para outro núcleo, e a escrita
/// poria a pilha dele no `RSP0` do núcleo de antes — o fio que roda lá
/// empilharia as interrupções do anel 3 na pilha deste, que roda noutro (o
/// item 4 do adversário do lote B2 do #448). O único chamador é a troca de
/// contexto (`contexto::ceder_cpu`), mascarada; o `debug_assert!` faz
/// qualquer outro reprovar a suíte de depuração.
///
/// Um valor zero é ignorado, e é o caso do fio inicial — a pilha dele veio do
/// boot e ele não executa código de usuário.
pub fn definir_pilha_de_kernel(nucleo: usize, topo: u64) {
    debug_assert!(
        !x86_64::instructions::interrupts::are_enabled(),
        "o RSP0 escrito com as interrupcoes ligadas"
    );
    if topo == 0 || GDT.get().is_none() {
        return;
    }
    let tss = &TSSS[nucleo];

    // SAFETY: escrevemos um único campo do TSS **deste** núcleo, com as
    // interrupções mascaradas pelo chamador (a troca de contexto) — o
    // núcleo lido não muda até a escrita. O processador só lê este campo ao
    // entregar uma interrupção a este núcleo, o que não pode acontecer aqui
    // dentro; e nenhum outro núcleo escreve no TSS de outro.
    unsafe {
        (*tss.0.get()).privilege_stack_table[0] = VirtAddr::new(topo);
    }
}

/// Carrega o LDT nulo neste núcleo: o seletor zero no `LDTR`, que o marca
/// inválido. Um seletor com o TI ligado passa a ser `#GP`, com o seletor no
/// código.
fn carregar_o_ldt_nulo() {
    // SAFETY: estamos no anel 0; o seletor nulo não lê a GDT, e o `LDTR`
    // inválido só torna o processador mais estrito — nada deste kernel usa
    // um seletor do LDT.
    unsafe {
        core::arch::asm!(
            "lldt {0:x}",
            in(reg) 0u16,
            options(nomem, nostack, preserves_flags)
        )
    };
}

/// Só para a suíte: carrega neste núcleo o LDT de teste — base em
/// [`BASE_DO_LDT_DE_TESTE`], sem página, limite 0xFFFF —, como o `LDTR` que
/// o processador traz do reset, de base 0, mas num endereço que nenhum
/// espaço mapeia. O seletor 0x0F de um processo, no `mov ds`, faz o
/// processador ler o descritor em `BASE_DO_LDT_DE_TESTE + 8`, num acesso de
/// supervisor, e a falha de página vem sem o `U`: é a culpa pelo `CS` do
/// quadro que mata o processo, e não o código de erro. O núcleo fica com o
/// LDT de teste até [`largar_o_ldt_de_teste`].
#[cfg(feature = "modo-teste")]
pub fn carregar_o_ldt_de_teste() {
    let seletor = SELETOR_DO_LDT_DE_TESTE.load(Ordering::Relaxed);
    if seletor == 0 {
        return;
    }
    // SAFETY: estamos no anel 0, e o seletor é o de um descritor de LDT
    // presente da GDT carregada — o processador o lê dela. Nenhum código do
    // kernel usa um seletor do LDT.
    unsafe {
        core::arch::asm!(
            "lldt {0:x}",
            in(reg) seletor,
            options(readonly, nostack, preserves_flags)
        )
    };
}

/// Só para a suíte: devolve este núcleo ao LDT nulo, depois de
/// [`carregar_o_ldt_de_teste`].
#[cfg(feature = "modo-teste")]
pub fn largar_o_ldt_de_teste() {
    carregar_o_ldt_nulo();
}

/// Só para a suíte: marca ausente (`P` desligado), ou presente de novo, o
/// descritor da base do `sysret` — o da posição logo antes dos dados do
/// usuário, que nada carrega: o `sysretq` de 64 bits parte dele e carrega os
/// dois seguintes (ver [`init`]). É de dados do usuário, de DPL 3: o `mov
/// ds` do seletor dele (0x1B) é `#NP`, e o `mov ss`, `#SS`, os dois com o
/// seletor no código — o grupo com código de erro alcançado do anel 3, que
/// o emulador não alcança de outro jeito. Devolve o descritor de antes.
///
/// A GDT é uma só, de todos os núcleos; o descritor só vale quando um
/// seletor é carregado, e ninguém carrega este.
#[cfg(feature = "modo-teste")]
pub fn marcar_a_base_do_sysret_de_teste(ausente: bool) -> u64 {
    const PRESENTE: u64 = 1 << 47;
    let indice = seletores().dados_usuario.index() as u64 - 1;
    let tabela = x86_64::instructions::tables::sgdt();
    if indice * 8 + 7 > u64::from(tabela.limit) {
        return 0;
    }
    let entrada = (tabela.base.as_u64() + indice * 8) as *mut u64;
    // SAFETY: a entrada está dentro do limite da GDT carregada, que mora
    // numa seção gravável (o `Once` tem mutabilidade interior); nenhum
    // código Rust lê esta entrada, e o processador só a lê na carga do
    // seletor dela, que nada faz.
    unsafe {
        let antes = core::ptr::read_volatile(entrada);
        let depois = if ausente {
            antes & !PRESENTE
        } else {
            antes | PRESENTE
        };
        core::ptr::write_volatile(entrada, depois);
        antes
    }
}
