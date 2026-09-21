//! Paginação no x86_64.
//!
//! # O oposto do ARM
//!
//! No ARM a MMU chega desligada e precisamos construir tudo. Aqui o crate
//! `bootloader` já entregou a máquina com paginação ativa, tabelas montadas e
//! o kernel mapeado. O trabalho não é ligar nada — é **assumir o controle** do
//! que já está rodando.
//!
//! # O problema de editar tabelas de página
//!
//! Descritores de página contêm endereços *físicos*. Mas a MMU está ligada,
//! então todo acesso que fazemos é *virtual*. Para editar uma tabela cujo
//! endereço físico conhecemos, precisamos de alguma forma de alcançá-la.
//!
//! A saída adotada é pedir ao bootloader que mapeie toda a memória física num
//! deslocamento fixo do espaço virtual. Com isso, `físico + deslocamento` é o
//! endereço virtual por onde enxergamos qualquer byte de RAM — inclusive as
//! próprias tabelas. É o que [`OffsetPageTable`] espera, e é configurado pelo
//! `BootloaderConfig` em [`super::inicio`].
//!
//! No ARM o equivalente é trivial porque o mapa é de identidade: físico e
//! virtual coincidem. Daí a existência de [`acesso_fisico`] nos dois lados.

// Fora dos testes, a paginação ainda não tem consumidor: quem vai mapear
// páginas de verdade é o heap, próximo da fila. O `allow` de módulo evita
// anotar item por item, e sai quando o heap chegar.
#![cfg_attr(not(feature = "modo-teste"), allow(dead_code))]

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;
use x86_64::structures::paging::mapper::{MapToError, TranslateResult, UnmapError};
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
    Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use super::super::Permissoes;

/// Deslocamento onde a memória física inteira está mapeada.
///
/// A sentinela `u64::MAX` distingue "ainda não inicializado" de um
/// deslocamento legítimo igual a zero.
static DESLOCAMENTO: AtomicU64 = AtomicU64::new(u64::MAX);

/// Serializa as alterações de tabela.
///
/// Sem isto, dois caminhos poderiam construir `OffsetPageTable` ao mesmo
/// tempo, cada um com uma referência mutável para a mesma tabela raiz — que é
/// aliasing mutável, comportamento indefinido em Rust antes mesmo de ser um
/// problema de concorrência.
static TRAVA: Mutex<()> = Mutex::new(());

/// Registra o deslocamento e habilita o bit de não-execução.
///
/// # Safety
///
/// `deslocamento` precisa ser o endereço virtual onde o bootloader mapeou a
/// memória física completa.
pub unsafe fn init(deslocamento: u64) {
    DESLOCAMENTO.store(deslocamento, Ordering::Relaxed);

    // Sem `NXE` no EFER, o bit de não-execução dos descritores é *reservado* —
    // e escrever 1 num bit reservado de uma entrada de tabela faz o acesso
    // gerar falha de página. Ou seja, marcar uma página como não executável
    // sem habilitar isto antes produziria exatamente o oposto do pretendido.
    //
    // SAFETY: habilitar NXE é sempre seguro em long mode; o bootloader
    // provavelmente já o fez, e a operação é idempotente.
    unsafe {
        use x86_64::registers::model_specific::{Efer, EferFlags};
        Efer::update(|flags| flags.insert(EferFlags::NO_EXECUTE_ENABLE));
    }

    crate::log_info!("mmu", "memoria fisica mapeada em {:#x}", deslocamento);
}

/// Constrói um mapeador sobre a tabela de página ativa.
///
/// # Safety
///
/// O chamador precisa segurar [`TRAVA`] enquanto usar o resultado: duas
/// instâncias vivas ao mesmo tempo seriam aliasing mutável da tabela raiz.
unsafe fn mapeador() -> Result<OffsetPageTable<'static>, &'static str> {
    let deslocamento = DESLOCAMENTO.load(Ordering::Relaxed);
    if deslocamento == u64::MAX {
        return Err("paginacao ainda nao inicializada");
    }
    let deslocamento = VirtAddr::new(deslocamento);

    // CR3 aponta para a tabela raiz ativa — a fonte da verdade sobre o que
    // está mapeado agora, e não sobre o que nós achamos que mapeamos.
    let (frame, _) = x86_64::registers::control::Cr3::read();
    let virtual_ = deslocamento + frame.start_address().as_u64();
    let raiz: *mut PageTable = virtual_.as_mut_ptr();

    // SAFETY: o ponteiro deriva de CR3 somado ao deslocamento onde toda a
    // memória física está mapeada, então aponta para a tabela raiz válida. A
    // unicidade da referência é garantida pela trava que o chamador segura.
    Ok(unsafe { OffsetPageTable::new(&mut *raiz, deslocamento) })
}

/// Ponte entre o alocador de frames do kernel e o que o crate `x86_64` espera.
struct AlocadorDeFrames;

// SAFETY: `crate::frames::alocar` só entrega frames livres e nunca o mesmo
// duas vezes, que é exatamente a garantia exigida por este trait.
unsafe impl FrameAllocator<Size4KiB> for AlocadorDeFrames {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        crate::frames::alocar().map(|fisico| PhysFrame::containing_address(PhysAddr::new(fisico)))
    }
}

fn flags_de(permissoes: Permissoes) -> PageTableFlags {
    let mut flags = PageTableFlags::PRESENT;
    if permissoes.escrita {
        flags |= PageTableFlags::WRITABLE;
    }
    if !permissoes.executavel {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    if permissoes.dispositivo {
        // Registradores de hardware não podem ser cacheados: uma leitura
        // servida pelo cache devolveria um valor velho, e escritas poderiam
        // ser juntadas ou adiadas.
        flags |= PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH;
    }
    flags
}

/// Mapeia uma página de 4 KiB.
pub fn mapear(virtual_: u64, fisico: u64, permissoes: Permissoes) -> Result<(), &'static str> {
    let _guarda = TRAVA.lock();

    // SAFETY: seguramos a trava por toda a vida do mapeador.
    let mut mapeador = unsafe { mapeador()? };

    let pagina = Page::<Size4KiB>::containing_address(VirtAddr::new(virtual_));
    let frame = PhysFrame::containing_address(PhysAddr::new(fisico));

    // SAFETY: criar um mapeamento novo num endereço virtual até então livre
    // não invalida nenhuma referência existente. O caso perigoso — remapear
    // algo em uso — é rejeitado pelo próprio `map_to`, que devolve
    // `PageAlreadyMapped`.
    let resultado =
        unsafe { mapeador.map_to(pagina, frame, flags_de(permissoes), &mut AlocadorDeFrames) };

    match resultado {
        Ok(flush) => {
            // Sem isto a TLB continuaria servindo a ausência de tradução.
            flush.flush();
            Ok(())
        }
        Err(MapToError::PageAlreadyMapped(_)) => Err("endereco virtual ja mapeado"),
        Err(MapToError::FrameAllocationFailed) => Err("sem frames para tabela de pagina"),
        Err(MapToError::ParentEntryHugePage) => Err("bloco grande no caminho do mapeamento"),
    }
}

/// Remove o mapeamento de uma página de 4 KiB.
pub fn desmapear(virtual_: u64) -> Result<(), &'static str> {
    let _guarda = TRAVA.lock();

    // SAFETY: seguramos a trava por toda a vida do mapeador.
    let mut mapeador = unsafe { mapeador()? };
    let pagina = Page::<Size4KiB>::containing_address(VirtAddr::new(virtual_));

    match mapeador.unmap(pagina) {
        Ok((_frame, flush)) => {
            flush.flush();
            Ok(())
        }
        Err(UnmapError::PageNotMapped) => Err("endereco nao estava mapeado"),
        Err(UnmapError::ParentEntryHugePage) => {
            Err("endereco nao mapeado em granularidade de pagina")
        }
        Err(UnmapError::InvalidFrameAddress(_)) => Err("descritor com endereco invalido"),
    }
}

/// Resolve um endereço virtual para físico, se houver tradução.
pub fn traduzir(virtual_: u64) -> Option<u64> {
    let _guarda = TRAVA.lock();

    // SAFETY: seguramos a trava por toda a vida do mapeador.
    let mapeador = unsafe { mapeador().ok()? };

    match mapeador.translate(VirtAddr::new(virtual_)) {
        TranslateResult::Mapped { frame, offset, .. } => {
            Some(frame.start_address().as_u64() + offset)
        }
        _ => None,
    }
}

/// Endereço virtual por onde o kernel enxerga uma página física.
///
/// Aqui é o deslocamento onde o bootloader mapeou a memória física inteira —
/// diferente do ARM, onde a identidade torna a resposta trivial.
pub fn acesso_fisico(fisico: u64) -> *mut u8 {
    let deslocamento = DESLOCAMENTO.load(Ordering::Relaxed);
    if deslocamento == u64::MAX {
        return core::ptr::null_mut();
    }
    (deslocamento + fisico) as *mut u8
}
