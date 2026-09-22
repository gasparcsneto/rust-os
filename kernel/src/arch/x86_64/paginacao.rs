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
use x86_64::structures::paging::mapper::CleanUp;
use x86_64::structures::paging::mapper::{MapToError, TranslateResult, UnmapError};
use x86_64::structures::paging::{
    FrameAllocator, FrameDeallocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags,
    PhysFrame, Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use super::super::{Permissoes, TAMANHO_PAGINA, validar_alinhamento};

/// Um endereço virtual do x86_64 precisa ser *canônico*: os bits 48 a 63 têm
/// de repetir o bit 47.
///
/// Isto não é detalhe acadêmico. `VirtAddr::new` do crate `x86_64` entra em
/// **pânico** diante de um endereço não-canônico, e um pânico no kernel é
/// terminal. Como o comando `paging.translate` aceita um inteiro arbitrário
/// vindo do canal do agente, sem esta verificação uma única requisição JSON
/// derruba o sistema — o que foi verificado na prática antes de escrever isto.
fn canonico(endereco: u64) -> bool {
    let alto = endereco >> 47;
    alto == 0 || alto == 0x1_FFFF
}

/// O x86_64 limita endereços físicos a 52 bits, e `PhysAddr::new` também entra
/// em pânico acima disso.
fn fisico_valido(endereco: u64) -> bool {
    endereco < (1 << 52)
}

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

// SAFETY: devolvemos ao alocador apenas frames que saíram dele e cujo último
// dono era a tabela de página que acabou de ser descartada.
impl FrameDeallocator<Size4KiB> for AlocadorDeFrames {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        crate::frames::liberar(frame.start_address().as_u64());
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
    if permissoes.usuario {
        flags |= PageTableFlags::USER_ACCESSIBLE;
    }
    flags
}

/// Mapeia uma página de 4 KiB para um frame específico.
///
/// # Safety
///
/// O chamador precisa garantir que `fisico` **não esteja em uso** por nenhum
/// outro mapeamento — é o mesmo contrato que `map_to` exige, e pela mesma
/// razão: duas páginas apontando para o mesmo frame são dois caminhos de
/// escrita para a mesma memória física.
///
/// Para memória comum, prefira [`crate::paginacao::mapear_novo`], que
/// satisfaz esta condição por construção.
pub unsafe fn mapear_frame(
    virtual_: u64,
    fisico: u64,
    permissoes: Permissoes,
) -> Result<(), &'static str> {
    validar_alinhamento(virtual_, fisico)?;
    if !canonico(virtual_) {
        return Err("endereco virtual nao canonico");
    }
    if !fisico_valido(fisico) {
        return Err("endereco fisico fora da faixa de 52 bits");
    }

    // Mascarar interrupções não é zelo excessivo: `TRAVA` é um spinlock, e
    // spinlocks não são reentrantes. Se o timer disparasse no meio de um
    // mapeamento e o handler chegasse aqui, ele giraria para sempre esperando
    // um lock que só nós podemos soltar — e só voltamos a rodar quando ele
    // retornar.
    crate::arch::sem_interrupcoes(|| {
        let _guarda = TRAVA.lock();

        // SAFETY: seguramos a trava por toda a vida do mapeador.
        let mut mapeador = unsafe { mapeador()? };

        // Os endereços já foram validados como alinhados e dentro das faixas
        // que os construtores exigem, então nem `new` entra em pânico nem
        // `containing_address` tem o que arredondar em silêncio.
        let pagina = Page::<Size4KiB>::containing_address(VirtAddr::new(virtual_));
        let frame = PhysFrame::containing_address(PhysAddr::new(fisico));

        // SAFETY: criar um mapeamento novo num endereço virtual até então
        // livre não invalida nenhuma referência existente, e o contrato desta
        // função transfere ao chamador a garantia de que o frame não está em
        // uso. O caso de remapear algo em uso é rejeitado pelo próprio
        // `map_to`, que devolve `PageAlreadyMapped`.
        // `map_to_with_table_flags`, e não `map_to`, por um motivo que falha
        // em silêncio se for esquecido: o processador exige `USER_ACCESSIBLE`
        // em **todos** os níveis da hierarquia, não só na folha. O `map_to`
        // comum cria as tabelas intermediárias com `PRESENT | WRITABLE`, e uma
        // página de usuário pendurada nelas seria mapeada com sucesso e
        // inacessível ao usuário — falha de página no primeiro acesso, longe
        // da causa.
        //
        // Restringir de verdade quem alcança o quê é trabalho da folha: as
        // tabelas intermediárias são permissivas e cada entrada final decide.
        let flags = flags_de(permissoes);
        let flags_de_tabela =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;

        let resultado = unsafe {
            mapeador.map_to_with_table_flags(
                pagina,
                frame,
                flags,
                flags_de_tabela,
                &mut AlocadorDeFrames,
            )
        };

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
    })
}

/// Remove o mapeamento de uma página de 4 KiB e devolve o frame que estava
/// ali.
///
/// As tabelas intermediárias que ficarem vazias são devolvidas ao alocador.
/// Sem isso, cada região de 2 MiB já usada custaria um frame permanente.
pub fn desmapear(virtual_: u64) -> Result<u64, &'static str> {
    if !virtual_.is_multiple_of(TAMANHO_PAGINA) {
        return Err("endereco virtual desalinhado");
    }
    if !canonico(virtual_) {
        return Err("endereco virtual nao canonico");
    }

    crate::arch::sem_interrupcoes(|| {
        let _guarda = TRAVA.lock();

        // SAFETY: seguramos a trava por toda a vida do mapeador.
        let mut mapeador = unsafe { mapeador()? };
        let pagina = Page::<Size4KiB>::containing_address(VirtAddr::new(virtual_));

        match mapeador.unmap(pagina) {
            Ok((frame, flush)) => {
                flush.flush();

                // Recupera as tabelas que esta remoção possa ter esvaziado.
                //
                // A faixa é limitada à página que acabou de sair: o percurso
                // sobe conferindo cada nível e só descarta o que ficou
                // realmente vazio, então restringir mantém o custo baixo sem
                // deixar nada para trás.
                //
                // SAFETY: as tabelas desta hierarquia foram todas criadas por
                // `map_to` com o nosso alocador, nunca são compartilhadas
                // entre faixas e não têm contagem de referência — que é
                // exatamente o que o contrato de `clean_up_addr_range` exige.
                unsafe {
                    mapeador.clean_up_addr_range(
                        Page::range_inclusive(pagina, pagina),
                        &mut AlocadorDeFrames,
                    );
                }

                // Devolver o frame permite ao chamador liberá-lo. Sem isto,
                // quem desmapeia não tem como saber qual memória física ficou
                // órfã.
                Ok(frame.start_address().as_u64())
            }
            Err(UnmapError::PageNotMapped) => Err("endereco nao estava mapeado"),
            Err(UnmapError::ParentEntryHugePage) => {
                Err("endereco nao mapeado em granularidade de pagina")
            }
            Err(UnmapError::InvalidFrameAddress(_)) => Err("descritor com endereco invalido"),
        }
    })
}

/// Resolve um endereço virtual para físico, se houver tradução.
///
/// Um endereço inválido devolve `None` em vez de falhar: para quem pergunta,
/// "não tem tradução" é a resposta correta, e é exatamente o que um endereço
/// impossível merece. Nunca entra em pânico — esta função é alcançável a
/// partir do canal do agente com um inteiro arbitrário.
pub fn traduzir(virtual_: u64) -> Option<u64> {
    if !canonico(virtual_) {
        return None;
    }

    crate::arch::sem_interrupcoes(|| {
        let _guarda = TRAVA.lock();

        // SAFETY: seguramos a trava por toda a vida do mapeador.
        let mapeador = unsafe { mapeador().ok()? };

        match mapeador.translate(VirtAddr::new(virtual_)) {
            TranslateResult::Mapped { frame, offset, .. } => {
                Some(frame.start_address().as_u64() + offset)
            }
            _ => None,
        }
    })
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
