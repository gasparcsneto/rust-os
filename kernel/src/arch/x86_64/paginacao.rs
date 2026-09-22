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

    // A raiz ativa no boot é a do kernel. Guardá-la agora é o que permite
    // criar espaços de processo depois, quando `CR3` já puder estar apontando
    // para a tabela de um processo.
    RAIZ_DO_KERNEL.store(espaco_atual(), Ordering::Release);

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

                // Recupera as tabelas que esta remoção possa ter esvaziado —
                // mas **só** na entrada de topo privada deste espaço.
                //
                // A restrição não é zelo: as demais entradas são cópias das do
                // kernel, e os espaços compartilham as tabelas abaixo delas por
                // referência. Ao esvaziar uma, a limpeza sobe até zerar a
                // entrada de topo e devolver o frame ao alocador — na raiz
                // ativa, que é a única que ela enxerga. As cópias guardadas
                // pelos outros espaços seguiriam apontando para esse frame, e o
                // estrago só apareceria quando ele fosse reaproveitado.
                //
                // O preço de não limpar é uma tabela vazia por região do
                // kernel, para sempre. São poucos frames, e regiões do kernel
                // não vão e voltam.
                //
                // A faixa é limitada à página que acabou de sair: o percurso
                // sobe conferindo cada nível e só descarta o que ficou
                // realmente vazio, então restringir mantém o custo baixo sem
                // deixar nada para trás.
                //
                // SAFETY: dentro da entrada privada, as tabelas desta
                // hierarquia foram todas criadas por `map_to` com o nosso
                // alocador, não são alcançadas por nenhum outro espaço e não
                // têm contagem de referência — que é exatamente o que o
                // contrato de `clean_up_addr_range` exige.
                if crate::arch::e_privado(virtual_) {
                    unsafe {
                        mapeador.clean_up_addr_range(
                            Page::range_inclusive(pagina, pagina),
                            &mut AlocadorDeFrames,
                        );
                    }
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

// ===========================================================================
// Espaços de endereços
// ===========================================================================
//
// Um espaço de endereços é uma tabela raiz. Dar um a cada processo é o que faz
// dois processos poderem usar o *mesmo* endereço virtual apontando para
// memórias físicas diferentes — a definição prática de isolamento.
//
// A construção é a mesma nas duas arquiteturas: a tabela nova recebe uma cópia
// de todas as entradas de topo, menos a do usuário, que fica vazia. Copiar as
// do kernel é o que mantém o kernel mapeado em todo espaço, e sem isso a
// primeira interrupção depois de uma troca não teria para onde ir.
//
// Que as duas coisas caibam em entradas de topo distintas não é acidente: é a
// razão do mapa em `super::BASE_DO_HEAP` e vizinhos, e está conferido em
// tempo de compilação em `crate::usuario`.

/// Bits de endereço físico num descritor (12 a 51).
const MASCARA_ENDERECO: u64 = 0x000F_FFFF_FFFF_F000;
/// O descritor está presente.
const PRESENTE: u64 = 1 << 0;
/// O descritor mapeia uma página grande, e não uma tabela abaixo.
const GRANDE: u64 = 1 << 7;
/// Descritores por tabela.
const ENTRADAS: usize = 512;

/// A raiz do espaço do kernel, capturada no boot.
///
/// Guardada em vez de lida de `CR3` na hora porque `criar_espaco` pode ser
/// chamada com um processo ativo — e aí `CR3` seria a raiz *dele*, e o espaço
/// novo nasceria com o mapa do processo anterior em vez do mapa do kernel.
static RAIZ_DO_KERNEL: AtomicU64 = AtomicU64::new(u64::MAX);

/// A raiz do espaço de endereços ativo agora.
pub fn espaco_atual() -> u64 {
    x86_64::registers::control::Cr3::read()
        .0
        .start_address()
        .as_u64()
}

/// A raiz do espaço do kernel.
pub fn espaco_do_kernel() -> u64 {
    RAIZ_DO_KERNEL.load(Ordering::Acquire)
}

/// Cria um espaço de endereços com o kernel mapeado e `entrada_privada` vazia.
pub fn criar_espaco(entrada_privada: usize) -> Result<u64, &'static str> {
    if entrada_privada >= ENTRADAS {
        return Err("entrada de topo fora da tabela");
    }
    let raiz_do_kernel = espaco_do_kernel();
    if raiz_do_kernel == u64::MAX {
        return Err("paginacao ainda nao inicializada");
    }

    let nova = crate::frames::alocar().ok_or("memoria fisica esgotada")?;

    crate::arch::sem_interrupcoes(|| {
        let _guarda = TRAVA.lock();

        let destino = acesso_fisico(nova) as *mut u64;
        let origem = acesso_fisico(raiz_do_kernel) as *const u64;
        if destino.is_null() || origem.is_null() {
            crate::frames::liberar(nova);
            return Err("memoria fisica nao esta acessivel");
        }

        // SAFETY: as duas raízes são frames de 4 KiB alcançáveis pelo mapa da
        // memória física, e a trava garante que ninguém mais as escreve.
        unsafe {
            for i in 0..ENTRADAS {
                *destino.add(i) = if i == entrada_privada {
                    0
                } else {
                    *origem.add(i)
                };
            }
        }
        Ok(nova)
    })
}

/// Passa a traduzir por `raiz`.
///
/// # Safety
///
/// `raiz` precisa vir de [`criar_espaco`] e ainda não ter sido destruída. O
/// kernel continua mapeado porque a raiz carrega as entradas de topo dele —
/// sem isso, a instrução seguinte a esta função não teria tradução.
pub unsafe fn trocar_espaco(raiz: u64) {
    let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(raiz));

    // Preservar os flags em vez de zerá-los: eles descrevem o regime de cache
    // da própria tabela, e inventar outro aqui mudaria em silêncio o modo como
    // o processador percorre todas as tabelas.
    let (_, flags) = x86_64::registers::control::Cr3::read();

    // SAFETY: delegada ao chamador. Escrever CR3 já descarta as traduções não
    // globais da TLB, então não há invalidação a fazer depois.
    unsafe { x86_64::registers::control::Cr3::write(frame, flags) };
}

/// Devolve ao alocador tudo que pertence a `raiz`: as tabelas do usuário, as
/// páginas que elas mapeiam e a própria raiz.
///
/// # Safety
///
/// `raiz` não pode estar ativa — destruir o espaço em que se executa é ficar
/// sem tradução no meio do caminho.
pub unsafe fn destruir_espaco(raiz: u64, entrada_privada: usize) {
    if entrada_privada >= ENTRADAS {
        return;
    }

    crate::arch::sem_interrupcoes(|| {
        let _guarda = TRAVA.lock();

        let topo = acesso_fisico(raiz) as *mut u64;
        if !topo.is_null() {
            // SAFETY: `raiz` é um frame de 4 KiB alcançável pelo mapa físico, e
            // a trava garante acesso exclusivo. Só descemos pela entrada do
            // usuário: as demais são do kernel e continuam em uso.
            unsafe {
                // Quatro níveis: PML4 -> PDPT -> PD -> PT -> página.
                liberar_subarvore(*topo.add(entrada_privada), 3);
                *topo.add(entrada_privada) = 0;
            }
        }
        crate::frames::liberar(raiz);
    })
}

/// Libera recursivamente o que um descritor alcança.
///
/// `nivel` conta quantos níveis de tabela ainda há abaixo: 3 num descritor de
/// PML4, 0 num de PT (que aponta para a página em si).
///
/// # Safety
///
/// `descritor` precisa ser uma entrada de tabela válida do nível indicado, e
/// tudo abaixo dela precisa ter vindo do alocador de frames.
unsafe fn liberar_subarvore(descritor: u64, nivel: u8) {
    if descritor & PRESENTE == 0 {
        return;
    }
    let endereco = descritor & MASCARA_ENDERECO;

    // Uma página grande não tem tabela abaixo. O espaço do usuário não cria
    // nenhuma, mas conferir é mais barato que confiar: interpretar um bloco
    // como tabela liberaria 512 frames que pertencem a outra pessoa.
    if nivel > 0 && descritor & GRANDE == 0 {
        let tabela = acesso_fisico(endereco) as *const u64;
        if tabela.is_null() {
            return;
        }
        for i in 0..ENTRADAS {
            // SAFETY: `tabela` é uma tabela de 512 descritores do nível
            // abaixo, alcançável pelo mapa da memória física.
            unsafe { liberar_subarvore(*tabela.add(i), nivel - 1) };
        }
    }

    crate::frames::liberar(endereco);
}

/// As permissões que um descritor de página de usuário carrega.
///
/// É a leitura inversa de [`flags_de`], e existe para o `fork`: duplicar um
/// espaço exige recriar cada página **com as permissões que ela tinha**. Sem
/// isto, o filho receberia tudo gravável — e o `W^X` do pai não sobreviveria
/// a ter filhos.
fn permissoes_de(descritor: u64) -> Permissoes {
    let flags = PageTableFlags::from_bits_truncate(descritor);
    Permissoes {
        escrita: flags.contains(PageTableFlags::WRITABLE),
        executavel: !flags.contains(PageTableFlags::NO_EXECUTE),
        dispositivo: flags.contains(PageTableFlags::NO_CACHE),
        usuario: flags.contains(PageTableFlags::USER_ACCESSIBLE),
    }
}

/// Visita cada página de usuário de um espaço.
///
/// Chama `f(virtual, fisico, permissoes)` para cada página mapeada dentro da
/// entrada de topo privada. A ordem é a das tabelas, que é a dos endereços.
///
/// # Safety
///
/// `raiz` precisa ser uma raiz de tradução válida, e as tabelas abaixo dela não
/// podem estar sendo modificadas — chame com as interrupções mascaradas.
pub unsafe fn percorrer_paginas_do_usuario(
    raiz: u64,
    entrada_privada: usize,
    f: &mut dyn FnMut(u64, u64, Permissoes),
) {
    if entrada_privada >= ENTRADAS {
        return;
    }

    /// Lê uma tabela pelo mapa da memória física, ou `None` se ele não existe.
    ///
    /// # Safety
    /// `fisico` precisa ser o endereço de uma tabela de 512 descritores.
    unsafe fn tabela(fisico: u64) -> Option<*const u64> {
        let ponteiro = acesso_fisico(fisico) as *const u64;
        (!ponteiro.is_null()).then_some(ponteiro)
    }

    // SAFETY: delegada ao chamador; cada descida confere presença e recusa
    // páginas grandes, que o espaço do usuário não cria.
    unsafe {
        let Some(p4) = tabela(raiz) else { return };
        let e4 = *p4.add(entrada_privada);
        if e4 & PRESENTE == 0 {
            return;
        }
        let Some(p3) = tabela(e4 & MASCARA_ENDERECO) else {
            return;
        };
        let base4 = (entrada_privada as u64) << 39;

        for i3 in 0..ENTRADAS {
            let e3 = *p3.add(i3);
            if e3 & PRESENTE == 0 || e3 & GRANDE != 0 {
                continue;
            }
            let Some(p2) = tabela(e3 & MASCARA_ENDERECO) else {
                continue;
            };
            let base3 = base4 | ((i3 as u64) << 30);

            for i2 in 0..ENTRADAS {
                let e2 = *p2.add(i2);
                if e2 & PRESENTE == 0 || e2 & GRANDE != 0 {
                    continue;
                }
                let Some(p1) = tabela(e2 & MASCARA_ENDERECO) else {
                    continue;
                };
                let base2 = base3 | ((i2 as u64) << 21);

                for i1 in 0..ENTRADAS {
                    let e1 = *p1.add(i1);
                    if e1 & PRESENTE == 0 {
                        continue;
                    }
                    let virtual_ = base2 | ((i1 as u64) << 12);
                    f(virtual_, e1 & MASCARA_ENDERECO, permissoes_de(e1));
                }
            }
        }
    }
}
