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
use x86_64::instructions::segmentation::{CS, DS, ES, SS, Segment};
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

/// 20 KiB. Não precisa ser grande: quem roda nela é um handler que só
/// registra a falha e entra em post-mortem.
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
const ENTRADAS_DA_GDT: usize = 6 + 2 * MAX_NUCLEOS;

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
                &*TSSS[i].0.get()
            };
            *seletor = gdt.append(Descriptor::tss_segment(referencia));
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

        load_tss(*seletor_tss);
    }
}

/// Aponta o `RSP0` do TSS para o topo da pilha de kernel do fio atual.
///
/// É o endereço que o processador adota sozinho quando uma interrupção chega
/// com o código do usuário rodando. Precisa acompanhar a troca de contexto:
/// apontar para a pilha de outro fio faria dois fios empilharem quadros de
/// exceção no mesmo lugar.
///
/// Um valor zero é ignorado, e é o caso do fio inicial — a pilha dele veio do
/// boot e ele não executa código de usuário.
pub fn definir_pilha_de_kernel(topo: u64) {
    if topo == 0 || GDT.get().is_none() {
        return;
    }
    let tss = &TSSS[nucleo_atual()];

    // SAFETY: escrevemos um único campo do TSS **deste** núcleo, com as
    // interrupções mascaradas pelo chamador (a troca de contexto). O
    // processador só lê este campo ao entregar uma interrupção a este
    // núcleo, o que não pode acontecer aqui dentro; e nenhum outro núcleo
    // escreve no TSS de outro.
    unsafe {
        (*tss.0.get()).privilege_stack_table[0] = VirtAddr::new(topo);
    }
}
