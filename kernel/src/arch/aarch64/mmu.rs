//! Unidade de gerência de memória do aarch64.
//!
//! # A diferença que define este módulo
//!
//! No x86 o bootloader já entrega a MMU ligada, com tabelas montadas e a
//! memória física acessível. Aqui ela está **desligada**: todo endereço é
//! físico, e cabe a nós construir as tabelas de tradução e acender o
//! mecanismo.
//!
//! E ligar a MMU é um momento singularmente perigoso. Se o endereço da
//! instrução seguinte não estiver mapeado, o processador não reporta erro
//! algum — ele simplesmente busca lixo e executa. Não há mensagem, não há
//! exceção útil, não há rastro.
//!
//! # A estratégia: identidade antes de tudo
//!
//! A defesa é fazer com que o mapeamento inicial não mude endereço nenhum:
//! todo endereço virtual aponta para o mesmo endereço físico. Assim, no
//! instante em que a MMU liga, tudo que estava válido continua válido — o
//! código, a pilha, os periféricos.
//!
//! E isso sai surpreendentemente barato porque o nível 1 aceita blocos de
//! 1 GiB. A máquina inteira cabe em duas entradas: uma para a faixa de
//! periféricos e outra para a RAM. Uma tabela de 4 KiB, dois descritores.
//!
//! Mapeamentos finos de 4 KiB vêm depois, e aí sim descem por L2 e L3 usando
//! frames do alocador.
//!
//! # Por que a granularidade importa aqui
//!
//! Memória normal e memória de dispositivo não podem receber o mesmo
//! tratamento. A RAM pode ser cacheada e acessada fora de ordem; um registrador
//! de UART não — juntar duas escritas em uma, ou reordená-las, muda o que o
//! dispositivo faz. O tipo de cada faixa é declarado por um índice para o
//! `MAIR_EL1`, que é onde os atributos de memória de verdade moram.

// Fora dos testes, a paginação ainda não tem consumidor: quem vai mapear
// páginas de verdade é o heap, próximo da fila. O `allow` de módulo evita
// anotar item por item, e sai quando o heap chegar.
#![cfg_attr(not(feature = "modo-teste"), allow(dead_code))]

use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use aarch64_cpu::asm::barrier;
use aarch64_cpu::registers::{ID_AA64MMFR0_EL1, MAIR_EL1, SCTLR_EL1, TCR_EL1, TTBR0_EL1};
use spin::Mutex;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

use super::super::{Permissoes, TAMANHO_PAGINA, validar_alinhamento};

/// Serializa as alterações e leituras de tabela.
///
/// Sem isto, `mapear` poderia estar no meio de instalar um descritor enquanto
/// `traduzir` o lê pela metade — ou pior, duas chamadas de `mapear` poderiam
/// criar tabelas concorrentes para o mesmo endereço e uma vazaria.
static TRAVA: Mutex<()> = Mutex::new(());

/// A MMU já foi ligada?
///
/// Mapear antes disso escreveria em tabelas que ninguém consulta, e a falha
/// apareceria muito longe da causa.
static ATIVA: AtomicBool = AtomicBool::new(false);

/// Limite do espaço virtual configurado.
///
/// `T0SZ = 25` dá 39 bits de endereço virtual, e como desligamos as buscas por
/// TTBR1 não existe a metade alta. Qualquer endereço acima disto é inválido —
/// e checar aqui é o que impede que o cálculo de índices o trunque em silêncio
/// para algo dentro da faixa.
const LIMITE_VIRTUAL: u64 = 1 << 39;

/// Os descritores carregam 36 bits de endereço físico (bits 47:12).
const LIMITE_FISICO: u64 = 1 << 48;

/// Entradas por tabela: 4 KiB divididos em descritores de 8 bytes.
const ENTRADAS: usize = 512;

/// Máscara dos bits de endereço de saída num descritor.
const MASCARA_ENDERECO: u64 = 0x0000_FFFF_FFFF_F000;

// --- bits de descritor (manual de arquitetura ARM, formato VMSAv8-64) ------

const VALIDO: u64 = 1 << 0;
/// Com [`VALIDO`]: em L1/L2 indica tabela; em L3 indica página.
/// A ausência deste bit, com [`VALIDO`], indica bloco.
const TABELA: u64 = 1 << 1;

/// Índice de atributo 0 do `MAIR_EL1`: dispositivo.
const ATTR_DISPOSITIVO: u64 = 0 << 2;
/// Índice de atributo 1 do `MAIR_EL1`: memória normal, cacheável.
const ATTR_NORMAL: u64 = 1 << 2;

/// AP[2]: somente leitura. Ausente significa leitura e escrita.
const AP_SOMENTE_LEITURA: u64 = 1 << 7;
/// `AP[1]`: a página é alcançável a partir de EL0.
const AP_USUARIO: u64 = 1 << 6;
/// Compartilhável internamente, exigido para memória normal em SMP.
const SH_INTERNO: u64 = 0b11 << 8;
/// Flag de acesso. Com ela em zero, **todo** acesso gera falha — é um
/// mecanismo para o SO rastrear páginas usadas, e esquecê-la é um erro
/// clássico que faz o primeiro acesso morrer sem explicação óbvia.
const AF: u64 = 1 << 10;
/// Nunca executável em EL1.
const PXN: u64 = 1 << 53;
/// Nunca executável em EL0.
const UXN: u64 = 1 << 54;

/// Programa `MAIR_EL1`, a tabela de atributos de memória.
///
/// Os descritores de página não carregam os atributos de cache: carregam um
/// *índice* de três bits para esta tabela. É aqui que cada índice ganha
/// significado.
///
/// - Atributo 0: dispositivo nGnRnE — sem junção de escritas, sem
///   reordenação, sem confirmação antecipada. É o regime que registradores de
///   hardware exigem: cada acesso precisa chegar ao dispositivo exatamente
///   como foi escrito, na ordem em que foi escrito.
/// - Atributo 1: memória normal, write-back, com alocação em leitura e
///   escrita, interna e externa. É o regime da RAM.
///
/// O valor final é `0xFF00`, mas escrevê-lo assim exigiria confiar que quem
/// lê saiba decompor dois bytes de codificação do manual. Os nomes abaixo
/// dizem a mesma coisa de forma conferível.
fn programar_atributos_de_memoria() {
    MAIR_EL1.write(
        MAIR_EL1::Attr0_Device::nonGathering_nonReordering_noEarlyWriteAck
            + MAIR_EL1::Attr1_Normal_Inner::WriteBack_NonTransient_ReadWriteAlloc
            + MAIR_EL1::Attr1_Normal_Outer::WriteBack_NonTransient_ReadWriteAlloc,
    );
}

/// Uma tabela de tradução.
#[repr(C, align(4096))]
struct Tabela {
    entradas: [u64; ENTRADAS],
}

/// Invólucro para guardar a tabela raiz num `static`.
struct TabelaEstatica(UnsafeCell<Tabela>);

// SAFETY: o kernel é de núcleo único nesta fase e todo acesso à tabela
// acontece com interrupções mascaradas ou antes de elas existirem. O `Sync`
// existe apenas para permitir o `static`.
unsafe impl Sync for TabelaEstatica {}

/// A tabela de nível 1, raiz da tradução.
///
/// Fica num `static` e não num frame alocado de propósito: ela precisa existir
/// e estar correta *antes* de a MMU ligar, e depender do alocador nesse
/// momento criaria um caminho de falha justamente onde não há como reportar
/// nada. As tabelas de L2 e L3, criadas depois com a MMU já funcionando, vêm
/// do alocador normalmente.
static L1: TabelaEstatica = TabelaEstatica(UnsafeCell::new(Tabela {
    entradas: [0; ENTRADAS],
}));

/// Monta o mapa de identidade e liga a MMU.
///
/// # Safety
///
/// Só pode ser chamada uma vez, com a MMU desligada e interrupções
/// mascaradas.
pub unsafe fn init() {
    // SAFETY: núcleo único, MMU desligada, ninguém mais toca na tabela.
    let l1 = unsafe { &mut *L1.0.get() };
    l1.entradas = [0; ENTRADAS];

    // O primeiro GiB concentra os periféricos da máquina `virt`: a PL011 em
    // 0x0900_0000 e o GIC em 0x0800_0000. Marcamos como dispositivo e não
    // executável — nunca queremos buscar instruções de um registrador.
    l1.entradas[0] = bloco(0, ATTR_DISPOSITIVO, PXN | UXN);

    // Cada faixa de RAM vira blocos de 1 GiB de memória normal. Derivamos do
    // mapa em vez de fixar 0x4000_0000 no código: o endereço da RAM é uma
    // característica da placa, não do ARM.
    let mut blocos_de_ram = 0;
    let mut guard_page: Option<u64> = None;
    crate::machine::com_regioes(|regiao| {
        if regiao.tipo != crate::machine::TipoRegiao::Utilizavel {
            return;
        }
        let primeiro = (regiao.inicio >> 30) as usize;
        let ultimo = (((regiao.fim - 1) >> 30) as usize).min(ENTRADAS - 1);
        if primeiro > ultimo {
            return;
        }

        for (deslocamento, entrada) in l1.entradas[primeiro..=ultimo].iter_mut().enumerate() {
            let indice = primeiro + deslocamento;
            if indice == 0 {
                // Bloco 0 já é dispositivo; sobrepor tornaria os periféricos
                // cacheáveis, o que quebraria a UART de formas sutis.
                continue;
            }
            if *entrada == 0 {
                *entrada = bloco((indice as u64) << 30, ATTR_NORMAL, UXN);
                blocos_de_ram += 1;
            }
        }
    });

    // A guard page exige granularidade de 4 KiB numa região que os blocos de
    // 1 GiB cobrem inteira. Refinamos a árvore aqui, **antes** de ligar a MMU.
    //
    // O momento não é detalhe. A arquitetura exige *break-before-make* ao
    // trocar o tamanho de um mapeamento: é preciso invalidar a tradução,
    // limpar a TLB e só então escrever a nova, porque duas entradas de TLB
    // traduzindo o mesmo endereço têm comportamento imprevisível. Fazer isso
    // com a MMU ligada, na região de onde estamos executando, significaria
    // ficar sem tradução no meio do caminho — suicídio.
    //
    // Com a MMU desligada não há nada na TLB, e o `tlbi` que já fazemos antes
    // de ligar cobre o resto. O problema desaparece por construção.
    // SAFETY: a MMU ainda está desligada neste ponto, que é exatamente a
    // pré-condição da função.
    match unsafe { instalar_guard_page(l1) } {
        Ok(endereco) => guard_page = Some(endereco),
        Err(motivo) => crate::log_warn!("mmu", "sem guard page: {}", motivo),
    }

    let raiz = core::ptr::addr_of!(l1.entradas) as u64;

    // A raiz do kernel, guardada para que `criar_espaco` copie dela e não da
    // raiz ativa — que, com um processo rodando, seria a do processo.
    RAIZ_DO_KERNEL.store(raiz, Ordering::Release);

    // SAFETY: a tabela está montada e cobre identicamente o código, a pilha e
    // os periféricos, então a instrução seguinte ao `isb` continua válida.
    unsafe { ligar(raiz) };

    ATIVA.store(true, Ordering::Release);

    crate::log_info!(
        "mmu",
        "identidade ativa: 1 bloco de dispositivo, {} de RAM",
        blocos_de_ram
    );
    match guard_page {
        Some(endereco) => crate::log_info!("mmu", "guard page da pilha em {:#x}", endereco),
        None => crate::log_warn!("mmu", "pilha do kernel sem guard page"),
    }
}

/// Deixa desmapeada a página logo abaixo da pilha do kernel.
///
/// Devolve o endereço protegido.
///
/// # Safety
///
/// Só pode ser chamada com a MMU desligada, antes de qualquer tradução ser
/// cacheada — ver o comentário sobre break-before-make em [`init`].
unsafe fn instalar_guard_page(l1: &mut Tabela) -> Result<u64, &'static str> {
    // SAFETY: símbolo do linker script; só tomamos seu endereço.
    unsafe extern "C" {
        static __guard_page: u8;
    }
    let endereco = &raw const __guard_page as u64;

    let i1 = ((endereco >> 30) & 0x1FF) as usize;
    let i2 = ((endereco >> 21) & 0x1FF) as usize;
    let i3 = ((endereco >> 12) & 0x1FF) as usize;

    // SAFETY: refinamos descritores válidos que nós mesmos acabamos de montar.
    unsafe {
        // 1 GiB -> 512 blocos de 2 MiB.
        let l2 = refinar(&raw mut l1.entradas[i1], (i1 as u64) << 30, 21, false)?;
        // 2 MiB -> 512 páginas de 4 KiB.
        let base_l2 = ((i1 as u64) << 30) | ((i2 as u64) << 21);
        let l3 = refinar(l2.add(i2), base_l2, 12, true)?;

        // E então o buraco: a única entrada que fica inválida.
        *l3.add(i3) = 0;
    }

    Ok(endereco)
}

/// Troca um bloco por uma tabela de entradas menores cobrindo exatamente o
/// mesmo intervalo, com os mesmos atributos.
///
/// `bits` é quantos bits de endereço cada entrada nova cobre (21 para blocos
/// de 2 MiB, 12 para páginas de 4 KiB) e `folha` distingue o nível 3, onde uma
/// página usa VÁLIDO *com* o bit de tabela.
///
/// # Safety
///
/// `entrada` precisa apontar para um descritor de bloco válido, e a MMU
/// precisa estar desligada.
unsafe fn refinar(
    entrada: *mut u64,
    base: u64,
    bits: u32,
    folha: bool,
) -> Result<*mut u64, &'static str> {
    // SAFETY: o chamador garantiu que aponta para um descritor.
    let descritor = unsafe { *entrada };

    if descritor & VALIDO == 0 {
        return Err("descritor ausente onde se esperava um bloco");
    }
    if descritor & TABELA != 0 {
        return Err("descritor ja e uma tabela");
    }

    // Preservar os atributos é o que mantém o refinamento invisível: o mesmo
    // intervalo continua com o mesmo tipo de memória, as mesmas permissões e
    // a mesma flag de acesso.
    let atributos = descritor & !(MASCARA_ENDERECO | VALIDO | TABELA);

    let nova = crate::frames::alocar().ok_or("sem frames para refinar o mapeamento")?;
    // SAFETY: frame recém-alocado, nosso, e com a MMU desligada seu endereço
    // físico é o próprio endereço de acesso.
    unsafe { core::ptr::write_bytes(nova as *mut u8, 0, 4096) };
    let nova = nova as *mut u64;

    let passo = 1u64 << bits;
    for indice in 0..ENTRADAS {
        let alvo = base + indice as u64 * passo;
        let mut novo = (alvo & MASCARA_ENDERECO) | VALIDO | atributos;
        if folha {
            novo |= TABELA;
        }
        // SAFETY: `nova` é uma tabela de 512 entradas e `indice` cabe nela.
        unsafe { *nova.add(indice) = novo };
    }

    // SAFETY: instalamos o descritor de tabela no lugar do bloco.
    unsafe { *entrada = (nova as u64 & MASCARA_ENDERECO) | VALIDO | TABELA };

    Ok(nova)
}

/// Monta um descritor de bloco de 1 GiB no nível 1.
const fn bloco(endereco_fisico: u64, atributo: u64, extras: u64) -> u64 {
    // Bloco = VÁLIDO sem o bit de tabela.
    (endereco_fisico & MASCARA_ENDERECO) | VALIDO | atributo | AF | SH_INTERNO | extras
}

/// Escreve os registradores de controle e acende a MMU.
///
/// # Safety
///
/// `raiz` precisa apontar para uma tabela de nível 1 válida que mapeie, no
/// mínimo, o código em execução e a pilha atual.
unsafe fn ligar(raiz: u64) {
    programar_atributos_de_memoria();
    programar_controle_de_traducao();

    TTBR0_EL1.set_baddr(raiz);

    // Garante que a escrita da tabela na memória esteja visível para o
    // percorredor de tabelas antes de ligá-lo.
    barrier::dsb(barrier::ISH);
    barrier::isb(barrier::SY);

    // SAFETY: manutenção de TLB e de cache, sem pré-condição além de estarmos
    // em EL1. Nenhuma das duas tem equivalente tipado: são instruções, não
    // escritas em registrador.
    unsafe {
        // A TLB pode conter traduções obsoletas do que rodou antes de nós.
        asm!("tlbi vmalle1", "dsb ish", "isb", options(nostack));

        // Vamos ligar o cache de instruções junto com a MMU, e ele pode conter
        // linhas trazidas enquanto a tradução estava desligada. Essas linhas
        // foram buscadas sob outro regime de atributos de memória; deixá-las
        // vivas é arriscar executar instruções obsoletas logo após a
        // transição, que é uma falha sem sintoma legível.
        //
        // `nsh` (non-shareable) basta: a invalidação é do cache deste núcleo.
        asm!("ic iallu", "dsb nsh", "isb", options(nostack));
    }

    // O momento crítico. Entre esta escrita e o `isb` seguinte, a MMU passa a
    // valer: é o mapa de identidade que garante que a busca da próxima
    // instrução ainda encontre o mesmo código.
    SCTLR_EL1.modify(
        SCTLR_EL1::M::Enable      // liga a tradução
            + SCTLR_EL1::C::Cacheable // cache de dados
            + SCTLR_EL1::I::Cacheable, // cache de instruções
    );
    barrier::isb(barrier::SY);
}

/// Programa `TCR_EL1`, que descreve o formato das tabelas de tradução.
///
/// Antes esta função montava um `u64` a partir de deslocamentos copiados do
/// manual. Funcionava, mas um bit trocado ali não gera erro de compilação nem
/// mensagem — gera uma máquina que traduz endereços de um jeito sutilmente
/// errado. Com campos nomeados, cada linha é conferível contra o manual sem
/// contar posições.
fn programar_controle_de_traducao() {
    // A largura de endereço físico suportada varia por implementação. Ler do
    // processador, em vez de fixar, evita configurar mais bits do que ele tem.
    //
    // O teto em 48 bits não é arbitrário: a codificação seguinte (52 bits)
    // depende da extensão FEAT_LPA, que muda o formato dos descritores e do
    // próprio TTBR0. Anunciar 52 bits sem implementar esse formato produziria
    // traduções silenciosamente erradas, então preferimos endereçar menos.
    let ips = ID_AA64MMFR0_EL1
        .read(ID_AA64MMFR0_EL1::PARange)
        .min(ID_AA64MMFR0_EL1::PARange::Bits_48.into());

    TCR_EL1.write(
        // T0SZ = 25 dá 39 bits de endereço virtual, o que faz o nível 1 ser o
        // nível inicial e cada uma de suas entradas cobrir 1 GiB.
        TCR_EL1::T0SZ.val(25)
            + TCR_EL1::TG0::KiB_4
            + TCR_EL1::SH0::Inner
            + TCR_EL1::IRGN0::WriteBack_ReadAlloc_WriteAlloc_Cacheable
            + TCR_EL1::ORGN0::WriteBack_ReadAlloc_WriteAlloc_Cacheable
            // Não usamos a metade alta do espaço virtual, então desligamos as
            // buscas por TTBR1 em vez de deixá-las apontando para lixo.
            + TCR_EL1::EPD1::DisableTTBR1Walks
            // TG1 tem codificação própria, *diferente* da de TG0 — um dos
            // detalhes que justificam não escrever estes campos à mão. Mesmo
            // sem usar TTBR1, deixá-lo num valor reservado é comportamento
            // indefinido.
            + TCR_EL1::TG1::KiB_4
            + TCR_EL1::IPS.val(ips),
    );
}

/// A tabela de nível 1 que a MMU está consultando **agora**.
///
/// Lê `TTBR0_EL1` em vez de devolver [`L1`] direto pelo mesmo motivo que o x86
/// lê `CR3`: a raiz ativa é a fonte da verdade sobre o que está mapeado, e não
/// sobre o que nós achamos que mapeamos. Enquanto houver uma tabela só, os
/// dois coincidem; com uma tabela por processo, deixam de coincidir — e este é
/// o ponto onde a diferença entra sem que os caminhos de mapeamento saibam
/// dela.
///
/// O registrador guarda um endereço **físico**, e aqui físico e virtual
/// coincidem (o mapa é de identidade), então ele serve direto como ponteiro.
///
/// # Safety
///
/// Só pode ser usada com a MMU ligada e [`TRAVA`] na mão: o resultado é um
/// ponteiro mutável para a raiz, e duas escritas concorrentes nela são
/// corrida de dados.
unsafe fn raiz_ativa() -> *mut u64 {
    TTBR0_EL1.get_baddr() as *mut u64
}

/// Índices de tabela para um endereço virtual, com granularidade de 4 KiB.
const fn indices(virtual_: u64) -> (usize, usize, usize) {
    (
        ((virtual_ >> 30) & 0x1FF) as usize,
        ((virtual_ >> 21) & 0x1FF) as usize,
        ((virtual_ >> 12) & 0x1FF) as usize,
    )
}

/// Desce um nível, criando a tabela se ainda não existir.
///
/// # Safety
/// `entrada` precisa apontar para um descritor válido de L1 ou L2.
unsafe fn descer(entrada: *mut u64) -> Result<*mut u64, &'static str> {
    // SAFETY: o chamador garantiu que o ponteiro é de um descritor.
    let atual = unsafe { *entrada };

    if atual & VALIDO != 0 {
        if atual & TABELA == 0 {
            // Há um bloco grande cobrindo este endereço. Fatiá-lo em páginas
            // menores é possível, mas exige realocar o mapeamento inteiro com
            // cuidado; recusamos em vez de fazer pela metade.
            return Err("bloco grande no caminho do mapeamento");
        }
        return Ok((atual & MASCARA_ENDERECO) as *mut u64);
    }

    let frame = crate::frames::alocar().ok_or("sem frames para tabela de pagina")?;

    // Zerar é obrigatório: lixo interpretado como descritor manda o
    // percorredor de tabelas para endereços arbitrários.
    // SAFETY: o frame acabou de ser alocado e, com a identidade ativa, seu
    // endereço físico é também o virtual.
    unsafe { core::ptr::write_bytes(frame as *mut u8, 0, 4096) };

    // SAFETY: instalamos o descritor de tabela apontando para o frame novo.
    unsafe { *entrada = (frame & MASCARA_ENDERECO) | VALIDO | TABELA };

    Ok(frame as *mut u64)
}

/// Traduz os atributos neutros nos bits do descritor.
fn bits_de(permissoes: Permissoes) -> u64 {
    let mut bits = if permissoes.dispositivo {
        ATTR_DISPOSITIVO
    } else {
        ATTR_NORMAL | SH_INTERNO
    };

    if !permissoes.escrita {
        bits |= AP_SOMENTE_LEITURA;
    }

    if permissoes.usuario {
        bits |= AP_USUARIO;

        // Uma página de usuário **nunca** é executável pelo kernel, mesmo
        // sendo executável pelo usuário. Sem isto, um desvio acidental para
        // um endereço de userspace faria o kernel executar código do
        // processo com privilégio total. É a mesma proteção que o x86 chama
        // de SMEP, e aqui ela é um bit por página.
        bits |= PXN;
        if !permissoes.executavel {
            bits |= UXN;
        }
    } else {
        // Páginas do kernel: nunca executáveis por EL0, e executáveis por EL1
        // só quando pedido.
        bits |= UXN;
        if !permissoes.executavel {
            bits |= PXN;
        }
    }

    bits | AF
}

/// Mapeia uma página de 4 KiB para um frame específico.
///
/// # Safety
///
/// O chamador precisa garantir que `fisico` **não esteja em uso** por nenhum
/// outro mapeamento. Apontar duas páginas para o mesmo frame cria dois
/// caminhos de escrita para a mesma memória física — o equivalente a duas
/// referências `&mut` para o mesmo lugar, que é comportamento indefinido em
/// Rust antes mesmo de ser um problema de kernel.
///
/// Para memória comum, prefira [`crate::paginacao::mapear_novo`], que tira o
/// frame do alocador e por isso satisfaz esta condição por construção. Esta
/// função existe para os casos em que o frame é escolhido e não alocado —
/// registradores mapeados em memória, por exemplo.
pub unsafe fn mapear_frame(
    virtual_: u64,
    fisico: u64,
    permissoes: Permissoes,
) -> Result<(), &'static str> {
    validar_endereco(virtual_, fisico)?;

    // Mascarar interrupções não é zelo excessivo: `TRAVA` é um spinlock, e
    // spinlocks não são reentrantes. Se o timer disparasse no meio de um
    // mapeamento e o handler chegasse aqui, ele giraria para sempre esperando
    // um lock que só nós podemos soltar — e só voltamos a rodar quando ele
    // retornar.
    crate::arch::sem_interrupcoes(|| {
        let _guarda = TRAVA.lock();
        let (i1, i2, i3) = indices(virtual_);

        // SAFETY: a trava garante acesso exclusivo à tabela, e a MMU está
        // ligada — `validar_endereco` já recusou o caso contrário.
        let l1 = unsafe { raiz_ativa() };

        // SAFETY: descemos por descritores válidos, criando tabelas conforme
        // necessário.
        let l3 = unsafe {
            let l2 = descer(l1.add(i1))?;
            descer(l2.add(i2))?
        };

        // SAFETY: `l3` é uma tabela de 512 entradas e `i3` está dentro dela.
        unsafe {
            let alvo = l3.add(i3);
            if *alvo & VALIDO != 0 {
                return Err("endereco virtual ja mapeado");
            }
            // No nível 3, uma página usa VÁLIDO *com* o bit de tabela.
            *alvo = (fisico & MASCARA_ENDERECO) | VALIDO | TABELA | bits_de(permissoes);
        }

        // SAFETY: a entrada foi escrita; resta publicá-la.
        unsafe { invalidar(virtual_) };
        Ok(())
    })
}

/// Recusa endereços que não podem ser mapeados nesta configuração.
///
/// A checagem de faixa é o que impede o cálculo de índices de truncar um
/// endereço alto em silêncio para algo dentro do espaço configurado — quem
/// pedisse para mapear `2^40` acabaria mapeando `0`, sem aviso.
fn validar_endereco(virtual_: u64, fisico: u64) -> Result<(), &'static str> {
    if !ATIVA.load(Ordering::Acquire) {
        return Err("mmu ainda nao inicializada");
    }
    validar_alinhamento(virtual_, fisico)?;
    if virtual_ >= LIMITE_VIRTUAL {
        return Err("endereco virtual fora do espaco configurado");
    }
    if fisico >= LIMITE_FISICO {
        return Err("endereco fisico fora da faixa de 48 bits");
    }
    Ok(())
}

/// Remove o mapeamento de uma página de 4 KiB.
pub fn desmapear(virtual_: u64) -> Result<u64, &'static str> {
    if !ATIVA.load(Ordering::Acquire) {
        return Err("mmu ainda nao inicializada");
    }
    if !virtual_.is_multiple_of(TAMANHO_PAGINA) {
        return Err("endereco virtual desalinhado");
    }
    if virtual_ >= LIMITE_VIRTUAL {
        return Err("endereco virtual fora do espaco configurado");
    }

    crate::arch::sem_interrupcoes(|| {
        let _guarda = TRAVA.lock();
        let (i1, i2, i3) = indices(virtual_);

        // SAFETY: a trava garante acesso exclusivo à tabela, e a MMU está
        // ligada — conferido no início da função.
        let l1 = unsafe { raiz_ativa() };

        // SAFETY: percorremos sem criar nada; paramos ao primeiro nível
        // ausente.
        unsafe {
            let e1 = *l1.add(i1);
            if e1 & VALIDO == 0 || e1 & TABELA == 0 {
                return Err("endereco nao mapeado em granularidade de pagina");
            }
            let l2 = (e1 & MASCARA_ENDERECO) as *mut u64;

            let e2 = *l2.add(i2);
            if e2 & VALIDO == 0 || e2 & TABELA == 0 {
                return Err("endereco nao mapeado em granularidade de pagina");
            }
            let l3 = (e2 & MASCARA_ENDERECO) as *mut u64;

            let alvo = l3.add(i3);
            let descritor = *alvo;
            if descritor & VALIDO == 0 {
                return Err("endereco nao estava mapeado");
            }
            *alvo = 0;

            invalidar(virtual_);

            // Recupera as tabelas que esta remoção esvaziou — mas **só** na
            // entrada de topo privada deste espaço. Sem a recuperação, cada
            // região de 2 MiB já usada custaria um frame permanente; sem a
            // restrição, liberaríamos tabelas que os outros espaços alcançam.
            //
            // As demais entradas de topo são cópias das do kernel, e os
            // espaços compartilham as tabelas abaixo delas por referência.
            // Zerar `*l1.add(i1)` aqui alcança só a raiz ativa: as cópias
            // guardadas pelos outros espaços seguiriam apontando para um frame
            // devolvido ao alocador, e o estrago apareceria quando ele fosse
            // reaproveitado — longe daqui, e sem sintoma que leve de volta.
            //
            // As tabelas do mapa de identidade nunca são atingidas por outro
            // motivo, que continua valendo: a L3 que contém a guard page tem
            // 511 entradas válidas, então jamais aparece vazia.
            if crate::arch::e_privado(virtual_) && tabela_vazia(l3) {
                *l2.add(i2) = 0;
                crate::frames::liberar(l3 as u64);

                if tabela_vazia(l2) {
                    *l1.add(i1) = 0;
                    crate::frames::liberar(l2 as u64);
                }

                // Invalidação ampla, e não do endereço: o percorredor de
                // tabelas mantém caches dos *níveis intermediários*, e um
                // `tlbi` por endereço não os alcança. Liberar um frame cuja
                // tradução ainda esteja em cache é corrupção garantida assim
                // que ele for reaproveitado.
                invalidar_tudo();
            }

            // Devolver o frame permite ao chamador liberá-lo. Sem isto, quem
            // desmapeia não tem como saber qual memória física ficou órfã.
            Ok(descritor & MASCARA_ENDERECO)
        }
    })
}

/// Resolve um endereço virtual para físico, se houver tradução.
pub fn traduzir(virtual_: u64) -> Option<u64> {
    // Sem esta checagem, o cálculo de índices mascara os bits altos e um
    // endereço fora do espaço configurado "dobra" para dentro dele — a função
    // devolveria uma tradução plausível para um endereço que não existe. Falso
    // positivo é pior que nenhuma resposta.
    if virtual_ >= LIMITE_VIRTUAL {
        return None;
    }

    let (i1, i2, i3) = indices(virtual_);

    // SAFETY: leitura das tabelas, sem modificá-las.
    unsafe {
        let l1 = raiz_ativa();

        let e1 = *l1.add(i1);
        if e1 & VALIDO == 0 {
            return None;
        }
        if e1 & TABELA == 0 {
            // Bloco de 1 GiB: o deslocamento dentro dele é preservado.
            return Some((e1 & MASCARA_ENDERECO) | (virtual_ & 0x3FFF_FFFF));
        }

        let l2 = (e1 & MASCARA_ENDERECO) as *const u64;
        let e2 = *l2.add(i2);
        if e2 & VALIDO == 0 {
            return None;
        }
        if e2 & TABELA == 0 {
            // Bloco de 2 MiB.
            return Some((e2 & MASCARA_ENDERECO) | (virtual_ & 0x1F_FFFF));
        }

        let l3 = (e2 & MASCARA_ENDERECO) as *const u64;
        let e3 = *l3.add(i3);
        if e3 & VALIDO == 0 {
            return None;
        }
        Some((e3 & MASCARA_ENDERECO) | (virtual_ & 0xFFF))
    }
}

/// Todas as 512 entradas desta tabela estão inválidas?
///
/// # Safety
/// `tabela` precisa apontar para uma tabela de tradução de 512 entradas.
unsafe fn tabela_vazia(tabela: *const u64) -> bool {
    // SAFETY: percorremos exatamente as 512 entradas que a tabela tem.
    (0..ENTRADAS).all(|indice| unsafe { *tabela.add(indice) } == 0)
}

/// Invalida a TLB inteira, incluindo os caches de níveis intermediários.
///
/// # Safety
/// Deve ser chamada logo após descartar uma tabela de tradução.
unsafe fn invalidar_tudo() {
    // SAFETY: manutenção de TLB, sempre válida a partir de EL1.
    unsafe {
        asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack),
        );
    }
}

/// Publica uma alteração de tabela invalidando a TLB do endereço.
///
/// # Safety
/// Deve ser chamada logo após escrever um descritor.
unsafe fn invalidar(virtual_: u64) {
    // SAFETY: sequência de manutenção de TLB exigida pelo manual.
    unsafe {
        asm!(
            // Garante que a escrita do descritor esteja visível ao
            // percorredor antes de invalidar.
            "dsb ishst",
            // Invalida a tradução deste endereço em todos os núcleos do
            // domínio compartilhável.
            "tlbi vaae1is, {}",
            "dsb ish",
            "isb",
            in(reg) virtual_ >> 12,
            options(nostack),
        );
    }
}

/// Endereço virtual por onde o kernel enxerga uma página física.
///
/// Com o mapa de identidade ativo, é o próprio endereço físico. No x86 a
/// resposta é outra, e é por isso que esta função existe.
pub fn acesso_fisico(fisico: u64) -> *mut u8 {
    fisico as *mut u8
}

// ===========================================================================
// Espaços de endereços
// ===========================================================================
//
// Ver o comentário equivalente em `arch::x86_64::paginacao`: a construção é a
// mesma nas duas arquiteturas — a tabela nova recebe uma cópia de todas as
// entradas de topo menos a do usuário, e é isso que mantém o kernel mapeado
// em todo espaço.
//
// A diferença está na granularidade. Aqui a raiz é uma L1 de 512 entradas de
// 1 GiB; lá é uma PML4 de 512 entradas de 512 GiB. Como o código só fala em
// "entrada de topo", ele não precisa saber qual dos dois está rodando.

/// A raiz do espaço do kernel, capturada quando a MMU liga.
static RAIZ_DO_KERNEL: AtomicU64 = AtomicU64::new(u64::MAX);

/// A raiz do espaço de endereços ativo agora.
pub fn espaco_atual() -> u64 {
    TTBR0_EL1.get_baddr()
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
    if !ATIVA.load(Ordering::Acquire) {
        return Err("mmu ainda nao inicializada");
    }
    let raiz_do_kernel = espaco_do_kernel();
    if raiz_do_kernel == u64::MAX {
        return Err("mmu ainda nao inicializada");
    }

    let nova = crate::frames::alocar().ok_or("memoria fisica esgotada")?;

    crate::arch::sem_interrupcoes(|| {
        let _guarda = TRAVA.lock();

        // O mapa é de identidade: o endereço físico serve direto de ponteiro.
        let destino = nova as *mut u64;
        let origem = raiz_do_kernel as *const u64;

        // SAFETY: as duas raízes são tabelas de 512 descritores em memória
        // identicamente mapeada, e a trava garante acesso exclusivo.
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
/// `raiz` precisa vir de [`criar_espaco`] e ainda não ter sido destruída.
pub unsafe fn trocar_espaco(raiz: u64) {
    // SAFETY: delegada ao chamador. Diferente do x86, trocar a raiz aqui
    // **não** descarta a TLB sozinho: sem ASID, traduções do espaço anterior
    // continuariam valendo para os mesmos endereços virtuais — que é
    // exatamente o que dois processos no mesmo endereço produzem.
    unsafe {
        TTBR0_EL1.set_baddr(raiz);
        asm!("dsb ish", "isb", options(nostack));
        invalidar_tudo();
    }
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
        let topo = raiz as *mut u64;

        // SAFETY: `raiz` é uma tabela de 512 descritores em memória
        // identicamente mapeada. Só descemos pela entrada do usuário: as
        // demais são do kernel e continuam em uso.
        unsafe {
            // Dois níveis de tabela abaixo da raiz: L1 -> L2 -> L3 -> página.
            liberar_subarvore(*topo.add(entrada_privada), 2);
            *topo.add(entrada_privada) = 0;
            invalidar_tudo();
        }
        crate::frames::liberar(raiz);
    })
}

/// Libera recursivamente o que um descritor alcança.
///
/// `nivel` conta quantos níveis de tabela ainda há abaixo: 2 num descritor de
/// L1, 0 num de L3 (que aponta para a página em si).
///
/// # Safety
///
/// `descritor` precisa ser uma entrada válida do nível indicado, e tudo abaixo
/// dela precisa ter vindo do alocador de frames.
unsafe fn liberar_subarvore(descritor: u64, nivel: u8) {
    if descritor & VALIDO == 0 {
        return;
    }
    let endereco = descritor & MASCARA_ENDERECO;

    // Em L1 e L2, `TABELA` desligado marca um **bloco** — 1 GiB ou 2 MiB de
    // uma vez, sem tabela abaixo. O espaço do usuário não cria nenhum, mas
    // conferir é mais barato que confiar: tratar um bloco como tabela
    // liberaria 512 frames de outra pessoa.
    if nivel > 0 && descritor & TABELA != 0 {
        let tabela = endereco as *const u64;
        for i in 0..ENTRADAS {
            // SAFETY: `tabela` é uma tabela de 512 descritores do nível
            // abaixo, em memória identicamente mapeada.
            unsafe { liberar_subarvore(*tabela.add(i), nivel - 1) };
        }
    }

    crate::frames::liberar(endereco);
}

/// As permissões que um descritor de página de usuário carrega.
///
/// É a leitura inversa de [`bits_de`], e existe para o `fork`: duplicar um
/// espaço exige recriar cada página **com as permissões que ela tinha**. Sem
/// isto, o filho receberia tudo gravável — e o `W^X` do pai não sobreviveria
/// a ter filhos.
fn permissoes_de(descritor: u64) -> Permissoes {
    Permissoes {
        escrita: descritor & AP_SOMENTE_LEITURA == 0,
        executavel: descritor & UXN == 0,
        dispositivo: descritor & ATTR_NORMAL == 0,
        usuario: descritor & AP_USUARIO != 0,
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

    // SAFETY: delegada ao chamador. O mapa é de identidade, então cada
    // endereço físico de tabela serve direto como ponteiro.
    unsafe {
        let l1 = (raiz as *const u64).add(entrada_privada);
        let e1 = *l1;
        if e1 & VALIDO == 0 || e1 & TABELA == 0 {
            return;
        }
        let base1 = (entrada_privada as u64) << 30;

        let l2 = (e1 & MASCARA_ENDERECO) as *const u64;
        for i2 in 0..ENTRADAS {
            let e2 = *l2.add(i2);
            if e2 & VALIDO == 0 || e2 & TABELA == 0 {
                continue;
            }
            let base2 = base1 | ((i2 as u64) << 21);

            let l3 = (e2 & MASCARA_ENDERECO) as *const u64;
            for i3 in 0..ENTRADAS {
                let e3 = *l3.add(i3);
                // Em L3 uma página válida traz `VALIDO` **com** o bit de
                // tabela; só `VALIDO` ali seria um descritor reservado.
                if e3 & VALIDO == 0 || e3 & TABELA == 0 {
                    continue;
                }
                let virtual_ = base2 | ((i3 as u64) << 12);
                f(virtual_, e3 & MASCARA_ENDERECO, permissoes_de(e3));
            }
        }
    }
}
