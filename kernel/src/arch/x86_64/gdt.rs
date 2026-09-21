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

use spin::once::Once;
use x86_64::VirtAddr;
use x86_64::instructions::segmentation::{CS, DS, ES, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

/// Índice, dentro da IST, da pilha reservada ao double fault.
pub const IST_DOUBLE_FAULT: u16 = 0;

/// 20 KiB. Não precisa ser grande: quem roda nela é um handler que só
/// registra a falha e entra em post-mortem.
const TAM_PILHA: usize = 4096 * 5;

/// A pilha de emergência do double fault.
///
/// O `UnsafeCell` não é decoração: um `static` sem mutabilidade interior vai
/// para `.rodata`, que é somente leitura — e o processador precisa *escrever*
/// o quadro da exceção aqui. O `UnsafeCell` é o que faz o linker colocá-la
/// numa seção gravável.
#[repr(align(16))]
struct PilhaEmergencia(UnsafeCell<[u8; TAM_PILHA]>);

// SAFETY: quem escreve nesta região é o processador, ao entregar uma exceção,
// e nunca dois núcleos ao mesmo tempo nesta fase (núcleo único). A impl existe
// apenas para permitir guardá-la num `static`.
unsafe impl Sync for PilhaEmergencia {}

static PILHA_DOUBLE_FAULT: PilhaEmergencia = PilhaEmergencia(UnsafeCell::new([0; TAM_PILHA]));

static TSS: Once<TaskStateSegment> = Once::new();
static GDT: Once<(
    GlobalDescriptorTable,
    SegmentSelector,
    SegmentSelector,
    SegmentSelector,
)> = Once::new();

/// Monta e carrega a GDT e o TSS. Chame uma vez, antes da IDT.
pub fn init() {
    let tss = TSS.call_once(|| {
        let mut tss = TaskStateSegment::new();
        tss.interrupt_stack_table[IST_DOUBLE_FAULT as usize] = {
            let base = VirtAddr::from_ptr(PILHA_DOUBLE_FAULT.0.get());
            // A pilha do x86 cresce para baixo, então o ponteiro que
            // entregamos é o **topo** da região, não o início.
            base + TAM_PILHA as u64
        };
        tss
    });

    let (gdt, seletor_codigo, seletor_dados, seletor_tss) = GDT.call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let seletor_codigo = gdt.append(Descriptor::kernel_code_segment());
        let seletor_dados = gdt.append(Descriptor::kernel_data_segment());
        let seletor_tss = gdt.append(Descriptor::tss_segment(tss));
        (gdt, seletor_codigo, seletor_dados, seletor_tss)
    });

    gdt.load();

    // SAFETY: os seletores vêm da GDT que acabamos de carregar, então apontam
    // para descritores válidos.
    unsafe {
        // Recarregar CS é obrigatório: até aqui ele ainda referencia a GDT
        // provisória do bootloader, que deixa de valer quando a nossa entra.
        CS::set_reg(*seletor_codigo);

        // Recarregar SS é igualmente obrigatório, por um motivo bem menos
        // óbvio — e que custou um #GP para descobrir.
        //
        // Em modo longo os registradores de dados são praticamente ignorados,
        // o que dá a falsa impressão de que podem ficar como estão. Mas o
        // `iretq` de 64 bits **sempre** repõe SS:RSP, mesmo quando não há
        // troca de privilégio. Se SS ainda contiver o seletor herdado do
        // bootloader, esse valor passa a indexar a *nossa* GDT, onde ele
        // provavelmente aponta para outro tipo de descritor.
        //
        // Foi exatamente o que aconteceu aqui: o bootloader deixava SS=0x10,
        // e na nossa GDT 0x10 caía sobre o descritor do TSS. O primeiro
        // `iretq` — o retorno do handler de breakpoint — gerava
        // #GP(0x10). O breakpoint era tratado corretamente e o kernel morria
        // ao *voltar* dele.
        SS::set_reg(*seletor_dados);
        DS::set_reg(*seletor_dados);
        ES::set_reg(*seletor_dados);

        load_tss(*seletor_tss);
    }
}
