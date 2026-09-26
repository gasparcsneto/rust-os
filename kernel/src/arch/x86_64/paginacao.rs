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
use x86_64::structures::paging::page_table::{FrameError, PageTableEntry};
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

/// Descritores por tabela.
///
/// O crate `x86_64` também sabe disto — [`PageTable`] é indexável e iterável —,
/// mas o número aparece aqui para conferir o índice que vem de fora antes de
/// usá-lo.
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
/// Desmonta a identidade que o iniciador deixou na metade baixa.
///
/// # Por que ela existia, e por que ela não pode ficar
///
/// O iniciador mapeou a RAM duas vezes: uma no deslocamento do kernel, que é
/// por onde o kernel a alcança, e outra por identidade — virtual igual a
/// físico. A segunda existe para um instante só: no `mov cr3`, a instrução
/// seguinte é buscada no código do iniciador, que mora num endereço baixo.
/// Sem essa identidade, a busca falha e a máquina reinicia.
///
/// Passado esse instante ela é um peso. Ela ocupa a entrada de topo que
/// pertence ao **espaço do usuário** — e, pior, faz o endereço zero ser
/// memória legível. Desreferenciar um ponteiro nulo dentro do kernel deixaria
/// de ser uma falha de página e passaria a ler o primeiro frame da máquina,
/// que é onde a tabela de vetores do BIOS e outras relíquias moram.
///
/// Largá-la restaura as duas coisas: a entrada volta a ser do usuário, e
/// zero volta a ser um endereço que não existe.
pub fn largar_a_identidade() {
    // A faixa do usuário e a identidade dividem a entrada de topo zero, e é
    // essa que sai. Perguntar à constante em vez de escrever `0` é o que
    // mantém isto correto se o mapa do usuário se mudar de lugar.
    let entrada = crate::arch::entrada_de_topo(crate::usuario::BASE) as usize;

    crate::arch::sem_interrupcoes(|| {
        let _guarda = TRAVA.lock();
        let raiz = espaco_atual();
        let tabela = acesso_fisico(raiz) as *mut PageTable;
        if tabela.is_null() {
            crate::log_error!("mmu", "a raiz nao esta acessivel; identidade mantida");
            return;
        }

        // SAFETY: a raiz é a tabela ativa, alcançável pelo mapa da memória
        // física, e a trava garante que ninguém mais a escreve.
        let tabela = unsafe { &mut *tabela };
        tabela[entrada].set_unused();

        // O processador guarda traduções num cache próprio, e apagar a
        // entrada não o esvazia. Recarregar o `CR3` esvazia — e é o que torna
        // a mudança efetiva em vez de teórica.
        x86_64::instructions::tlb::flush_all();
    });

    crate::log_info!(
        "mmu",
        "identidade do iniciador largada, entrada {}",
        entrada
    );
}

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

        let destino = acesso_fisico(nova) as *mut PageTable;
        let origem = acesso_fisico(raiz_do_kernel) as *const PageTable;
        if destino.is_null() || origem.is_null() {
            crate::frames::liberar(nova);
            return Err("memoria fisica nao esta acessivel");
        }

        // SAFETY: as duas raízes são frames de 4 KiB alcançáveis pelo mapa da
        // memória física, e a trava garante que ninguém mais as escreve.
        unsafe {
            let destino = &mut *destino;
            destino.zero();
            for (i, entrada) in (*origem).iter().enumerate() {
                if i != entrada_privada {
                    destino[i] = entrada.clone();
                }
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

        let topo = acesso_fisico(raiz) as *mut PageTable;
        if !topo.is_null() {
            // SAFETY: `raiz` é um frame de 4 KiB alcançável pelo mapa físico, e
            // a trava garante acesso exclusivo. Só descemos pela entrada do
            // usuário: as demais são do kernel e continuam em uso.
            unsafe {
                let topo = &mut *topo;
                // Quatro níveis: PML4 -> PDPT -> PD -> PT -> página.
                liberar_subarvore(&topo[entrada_privada], 3);
                topo[entrada_privada].set_unused();
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
unsafe fn liberar_subarvore(entrada: &PageTableEntry, nivel: u8) {
    // `frame()` recusa as duas coisas que não podem ser tratadas como tabela:
    // um descritor ausente e uma página grande. Deixar o crate responder isso
    // vale mais que a máscara e os dois bits escritos à mão que estavam aqui —
    // o endereço físico de um descritor tem doze bits baixos e doze altos que
    // não são endereço, e errar a máscara devolveria um frame errado ao
    // alocador sem nenhum sintoma imediato.
    let frame = match entrada.frame() {
        Ok(frame) => frame.start_address().as_u64(),
        Err(FrameError::FrameNotPresent) => return,
        Err(FrameError::HugeFrame) => {
            // O espaço do usuário não cria páginas grandes. Se uma aparecer,
            // devolvê-la a um alocador de frames de 4 KiB entregaria o
            // primeiro pedaço e perderia o resto — pior que não devolver nada.
            crate::log_error!("mmu", "pagina grande no espaco do usuario, nao devolvida");
            return;
        }
    };

    if nivel > 0 {
        let tabela = acesso_fisico(frame) as *const PageTable;
        if tabela.is_null() {
            return;
        }
        // SAFETY: `tabela` é uma tabela de 512 descritores do nível abaixo,
        // alcançável pelo mapa da memória física.
        for abaixo in unsafe { (*tabela).iter() } {
            // SAFETY: cada entrada pertence à tabela acima, do nível seguinte.
            unsafe { liberar_subarvore(abaixo, nivel - 1) };
        }
    }

    // Aqui as tabelas e as páginas se separam, e a diferença é de dono.
    //
    // Uma tabela pertence a este espaço e a mais ninguém: ela foi criada por
    // `map_to` com o nosso alocador quando este espaço precisou dela, e
    // nenhum outro espaço a alcança — é por isso que só descemos pela entrada
    // privada. Devolvê-la ao alocador é correto sem perguntar nada.
    //
    // Uma **página** pode ter vários donos desde que existe cópia na escrita:
    // o `fork` aponta o filho para os mesmos frames do pai. Devolvê-la com
    // `liberar` entregaria ao alocador memória que o outro processo ainda
    // está lendo e escrevendo, e o estrago só apareceria quando o frame fosse
    // reaproveitado — longe daqui, e sem sintoma que leve de volta.
    if nivel > 0 {
        crate::frames::liberar(frame);
    } else {
        crate::frames::soltar(frame);
    }
}

/// O bit de descritor que marca uma página como cópia na escrita.
///
/// # Por que este bit, e por que ele é seguro de usar
///
/// Os bits 9, 10 e 11 de um descritor são **ignorados pelo processador** e
/// reservados ao sistema operacional justamente para isto: pendurar um
/// significado que o hardware não precisa conhecer. O percorredor de tabelas
/// os carrega junto e não faz nada com eles.
///
/// A alternativa seria uma tabela paralela — "quais páginas de quais espaços
/// são cópia na escrita" — que precisaria ser mantida em sincronia com as
/// tabelas de verdade em todo mapeamento, desmapeamento e destruição de
/// espaço. Aqui a marca viaja **dentro** do descritor: é impossível o
/// descritor existir sem ela ou ela sobreviver ao descritor.
const COPIA_NA_ESCRITA: PageTableFlags = PageTableFlags::BIT_9;

/// Tira a escrita da página e a marca como cópia na escrita.
///
/// Opera sobre o espaço **ativo**, que é onde `fork` encontra o pai e onde
/// ele instala o filho.
///
/// # Por que uma página somente leitura é recusada
///
/// Porque marcá-la abriria um buraco no `W^X`: a resolução da falha devolve
/// a escrita à página, e uma página de código marcada por engano viraria
/// gravável na primeira tentativa de escrever nela. O `fork` só marca o que
/// já era gravável; recusar o resto transforma o engano num erro visível em
/// vez de numa permissão concedida em silêncio.
///
/// Uma página já marcada é aceita sem mudança — é o caso do neto: o pai
/// bifurcou uma vez, e a página dele já saiu de gravável na primeira vez.
pub fn marcar_copia_na_escrita(virtual_: u64) -> Result<(), &'static str> {
    com_descritor_da_folha(virtual_, |descritor| {
        let flags = descritor.flags();
        if flags.contains(COPIA_NA_ESCRITA) {
            return Ok(((), false));
        }
        if !flags.contains(PageTableFlags::WRITABLE) {
            return Err("pagina somente leitura nao vira copia na escrita");
        }
        descritor.set_flags((flags - PageTableFlags::WRITABLE) | COPIA_NA_ESCRITA);
        Ok(((), true))
    })
}

/// O frame e as permissões de uma página marcada como cópia na escrita.
///
/// `None` quando a página não está mapeada ou não carrega a marca — que é o
/// que distingue uma falha de escrita a resolver de uma falha de escrita a
/// punir.
pub fn copia_na_escrita_em(virtual_: u64) -> Option<(u64, Permissoes)> {
    com_descritor_da_folha(virtual_, |descritor| {
        if !descritor.flags().contains(COPIA_NA_ESCRITA) {
            return Err("pagina nao esta marcada para copia na escrita");
        }
        Ok((
            (
                descritor.addr().as_u64(),
                permissoes_de(descritor.flags().bits()),
            ),
            false,
        ))
    })
    .ok()
}

/// Entrega o descritor de folha de `virtual_` no espaço ativo a `f`.
///
/// Concentra aqui a descida pelos quatro níveis porque ela tem um detalhe que
/// erra em silêncio: uma página grande no caminho não é uma folha de 4 KiB, e
/// tratá-la como tal escreveria bits de permissão sobre 2 MiB de memória de
/// outra pessoa. `frame()` recusa esse caso por nós, em todos os níveis.
///
/// `f` devolve o que interessa a quem chamou **e** se mexeu no descritor; é
/// o segundo valor que pede a invalidação da TLB. Deixá-lo explícito, em vez
/// de deduzi-lo do tipo do primeiro, mantém a decisão visível nos dois
/// pontos de uso — e é o descasamento entre mudar o descritor e esquecer a
/// invalidação que produz uma proteção existente na tabela e ausente no
/// hardware.
fn com_descritor_da_folha<R>(
    virtual_: u64,
    f: impl FnOnce(&mut PageTableEntry) -> Result<(R, bool), &'static str>,
) -> Result<R, &'static str> {
    if !virtual_.is_multiple_of(TAMANHO_PAGINA) {
        return Err("endereco virtual desalinhado");
    }
    if !canonico(virtual_) {
        return Err("endereco virtual nao canonico");
    }

    crate::arch::sem_interrupcoes(|| {
        let _guarda = TRAVA.lock();

        let raiz = acesso_fisico(espaco_atual()) as *mut PageTable;
        if raiz.is_null() {
            return Err("memoria fisica nao esta acessivel");
        }

        let indices = [
            (virtual_ >> 39) & 0x1FF,
            (virtual_ >> 30) & 0x1FF,
            (virtual_ >> 21) & 0x1FF,
        ];

        // SAFETY: a raiz é a tabela ativa, alcançável pelo mapa da memória
        // física, e a trava garante que ninguém mais a escreve.
        let folha = unsafe {
            let mut tabela = &mut *raiz;
            for indice in indices {
                let frame = match tabela[indice as usize].frame() {
                    Ok(frame) => frame.start_address().as_u64(),
                    Err(FrameError::FrameNotPresent) => return Err("endereco nao estava mapeado"),
                    Err(FrameError::HugeFrame) => {
                        return Err("bloco grande no caminho do mapeamento");
                    }
                };
                let abaixo = acesso_fisico(frame) as *mut PageTable;
                if abaixo.is_null() {
                    return Err("memoria fisica nao esta acessivel");
                }
                tabela = &mut *abaixo;
            }
            &mut tabela[((virtual_ >> 12) & 0x1FF) as usize]
        };

        if !folha.flags().contains(PageTableFlags::PRESENT) {
            return Err("endereco nao estava mapeado");
        }

        let (resultado, mudou) = f(folha)?;
        if mudou {
            // # A invalidação que nenhum caso derruba, e por quê
            //
            // Medido, apagando-a: a suíte inteira passa. Não é falha dos casos.
            // O único chamador que modifica é o `fork`, e o passo imediatamente
            // anterior ao lado do pai é uma troca de espaço — que recarrega o
            // registrador de raiz e descarta a TLB por inteiro. Quando chegamos
            // aqui não há entrada velha para descartar.
            //
            // Ela fica porque essa é uma propriedade **do chamador de hoje**, e
            // não desta função. Quem marcar uma página sem trocar de espaço
            // antes — um `mprotect`, uma proteção de guarda, qualquer coisa que
            // ainda não existe — receberia do hardware a permissão anterior até
            // a TLB expirar sozinha, e teria uma proteção que existe na tabela e
            // não na máquina. É o modo de falhar mais caro que há: intermitente
            // e dependente de quanto tempo passou.
            x86_64::instructions::tlb::flush(VirtAddr::new(virtual_));
        }
        Ok(resultado)
    })
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

/// Converte permissões em bits de descritor e de volta, para a suíte.
///
/// Ver o equivalente no backend ARM: o par de inversas é a espécie de coisa
/// que passa a não ser sem que nada quebre.
#[cfg(feature = "modo-teste")]
pub fn permissoes_ida_e_volta(permissoes: Permissoes) -> Permissoes {
    permissoes_de(flags_de(permissoes).bits())
}

/// Visita cada página de usuário de um espaço.
///
/// Chama `f` uma vez por página mapeada dentro da entrada de topo privada. A
/// ordem é a das tabelas, que é a dos endereços.
///
/// # Safety
///
/// `raiz` precisa ser uma raiz de tradução válida, e as tabelas abaixo dela não
/// podem estar sendo modificadas — chame com as interrupções mascaradas.
pub unsafe fn percorrer_paginas_do_usuario(
    raiz: u64,
    entrada_privada: usize,
    f: &mut dyn FnMut(crate::arch::PaginaDoUsuario),
) {
    if entrada_privada >= ENTRADAS {
        return;
    }

    /// A tabela que um descritor alcança, ou `None` se ele não alcança uma.
    ///
    /// `frame()` recusa sozinho o descritor ausente e a página grande, que são
    /// justamente os dois casos em que descer seria interpretar dados como
    /// tabela.
    ///
    /// # Safety
    /// `entrada` precisa ser um descritor de PML4, PDPT ou PD.
    unsafe fn descer(entrada: &PageTableEntry) -> Option<&'static PageTable> {
        let frame = entrada.frame().ok()?;
        let ponteiro = acesso_fisico(frame.start_address().as_u64()) as *const PageTable;
        // SAFETY: o ponteiro deriva de um descritor válido somado ao mapa da
        // memória física, então aponta para uma tabela de 512 descritores.
        (!ponteiro.is_null()).then(|| unsafe { &*ponteiro })
    }

    // SAFETY: delegada ao chamador.
    unsafe {
        let ponteiro = acesso_fisico(raiz) as *const PageTable;
        if ponteiro.is_null() {
            return;
        }
        let raiz: &PageTable = &*ponteiro;
        let Some(p3) = descer(&raiz[entrada_privada]) else {
            return;
        };
        let base4 = (entrada_privada as u64) << 39;

        for (i3, e3) in p3.iter().enumerate() {
            let Some(p2) = descer(e3) else { continue };
            let base3 = base4 | ((i3 as u64) << 30);

            for (i2, e2) in p2.iter().enumerate() {
                let Some(p1) = descer(e2) else { continue };
                let base2 = base3 | ((i2 as u64) << 21);

                for (i1, e1) in p1.iter().enumerate() {
                    let Ok(frame) = e1.frame() else { continue };
                    f(crate::arch::PaginaDoUsuario {
                        virtual_: base2 | ((i1 as u64) << 12),
                        fisico: frame.start_address().as_u64(),
                        permissoes: permissoes_de(e1.flags().bits()),
                        copia_na_escrita: e1.flags().contains(COPIA_NA_ESCRITA),
                    });
                }
            }
        }
    }
}

/// Destrava a tabela de páginas à força, para o caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar_paginacao() {
    unsafe { TRAVA.force_unlock() };
}
