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

use super::super::Permissoes;

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

/// `MAIR_EL1`: a tabela de atributos de memória.
///
/// - Atributo 0 = `0x00`: dispositivo nGnRnE. Sem cache, sem junção de
///   escritas, sem reordenação. É o que registradores de hardware exigem.
/// - Atributo 1 = `0xFF`: memória normal, write-back, com alocação em
///   leitura e escrita, interna e externa.
const MAIR: u64 = 0xFF00;

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

    let raiz = core::ptr::addr_of!(l1.entradas) as u64;

    // SAFETY: a tabela está montada e cobre identicamente o código, a pilha e
    // os periféricos, então a instrução seguinte ao `isb` continua válida.
    unsafe { ligar(raiz) };

    crate::log_info!(
        "mmu",
        "identidade ativa: 1 bloco de dispositivo, {} de RAM",
        blocos_de_ram
    );
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
    // A largura de endereço físico suportada varia por implementação. Ler em
    // vez de fixar evita configurar mais bits do que o processador tem.
    let mmfr0: u64;
    // SAFETY: registrador de identificação, somente leitura.
    unsafe { asm!("mrs {}, id_aa64mmfr0_el1", out(reg) mmfr0, options(nomem, nostack)) };
    let ips = (mmfr0 & 0b1111).min(0b101);

    // T0SZ = 25 dá 39 bits de endereço virtual, o que faz o nível 1 ser o
    // nível inicial e cada uma de suas entradas cobrir 1 GiB.
    // Os termos que valem zero ficam escritos para documentar o layout dos
    // campos; sem eles a constante viraria um número sem explicação.
    #[allow(clippy::identity_op)]
    let tcr: u64 = 25
        | (0b01 << 8)   // IRGN0: cache interno write-back
        | (0b01 << 10)  // ORGN0: cache externo write-back
        | (0b11 << 12)  // SH0: compartilhável internamente
        | (0b00 << 14)  // TG0: granularidade de 4 KiB
        | (1 << 23)     // EPD1: desliga as buscas por TTBR1, que não usamos
        | (0b10 << 30)  // TG1: 4 KiB (evita um valor reservado)
        | (ips << 32);

    // SAFETY: valores calculados acima; a sequência de barreiras é a exigida
    // pelo manual de arquitetura.
    unsafe {
        asm!(
            // Garante que a escrita da tabela na memória esteja visível para o
            // percorredor de tabelas antes de apontá-lo para ela.
            "dsb ish",
            "isb",
            "msr mair_el1, {mair}",
            "msr tcr_el1,  {tcr}",
            "msr ttbr0_el1,{raiz}",
            "isb",
            // A TLB pode conter traduções obsoletas do que rodou antes de nós.
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            mair = in(reg) MAIR,
            tcr = in(reg) tcr,
            raiz = in(reg) raiz,
            options(nostack),
        );

        // O momento crítico: entre escrever SCTLR_EL1 e o `isb`, a MMU passa a
        // valer. O mapa de identidade é o que garante que a busca da próxima
        // instrução ainda encontre o mesmo código.
        let mut sctlr: u64;
        asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nomem, nostack));
        sctlr |= 1 << 0; // M: liga a tradução
        sctlr |= 1 << 2; // C: cache de dados
        sctlr |= 1 << 12; // I: cache de instruções
        asm!(
            "msr sctlr_el1, {}",
            "isb",
            in(reg) sctlr,
            options(nostack),
        );
    }
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
    if !permissoes.executavel {
        bits |= PXN;
    }
    // Nada mapeado por aqui é executável por userspace ainda; a fase 1 vai
    // precisar afrouxar isto.
    bits |= UXN;

    bits | AF
}

/// Mapeia uma página de 4 KiB.
pub fn mapear(virtual_: u64, fisico: u64, permissoes: Permissoes) -> Result<(), &'static str> {
    let (i1, i2, i3) = indices(virtual_);

    // SAFETY: núcleo único e chamadas serializadas pelo chamador.
    let l1 = unsafe { &mut *L1.0.get() };

    // SAFETY: descemos por descritores válidos, criando tabelas conforme
    // necessário.
    let l3 = unsafe {
        let l2 = descer(&raw mut l1.entradas[i1])?;
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
}

/// Remove o mapeamento de uma página de 4 KiB.
pub fn desmapear(virtual_: u64) -> Result<(), &'static str> {
    let (i1, i2, i3) = indices(virtual_);

    // SAFETY: núcleo único e chamadas serializadas pelo chamador.
    let l1 = unsafe { &mut *L1.0.get() };

    // SAFETY: percorremos sem criar nada; paramos ao primeiro nível ausente.
    unsafe {
        let e1 = l1.entradas[i1];
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
        if *alvo & VALIDO == 0 {
            return Err("endereco nao estava mapeado");
        }
        *alvo = 0;

        invalidar(virtual_);
    }

    Ok(())
}

/// Resolve um endereço virtual para físico, se houver tradução.
pub fn traduzir(virtual_: u64) -> Option<u64> {
    let (i1, i2, i3) = indices(virtual_);

    // SAFETY: leitura das tabelas, sem modificá-las.
    unsafe {
        let l1 = &*L1.0.get();

        let e1 = l1.entradas[i1];
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
