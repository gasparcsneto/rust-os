//! O mínimo da ACPI para saber quantos núcleos a máquina tem.
//!
//! # Por que a ACPI, e não perguntar ao processador
//!
//! Porque o processador só sabe de si. O `cpuid` diz quantos núcleos **cabem**
//! no pacote dele, não quantos existem, quais o firmware desligou, nem como
//! cada um se chama para o APIC. Quem sabe é o firmware, e a forma como ele
//! conta isso num PC é a tabela MADT da ACPI: uma entrada por APIC local, com
//! o id de cada um e se ele está habilitado.
//!
//! A alternativa clássica — mandar o sinal de partida para **todos** de uma
//! vez, por broadcast, e contar quem responde — acorda também os núcleos que
//! o firmware desligou de propósito, e não diz o id de ninguém.
//!
//! # O caminho até a MADT
//!
//! ```text
//!   RSDP ──► XSDT (ou RSDT) ──► "APIC" (MADT) ──► entradas de APIC local
//! ```
//!
//! A RSDP chega na entrega do iniciador — ver [`protocolo::Entrega::acpi`].
//! Cada tabela tem uma soma de verificação, e cada uma é conferida antes de
//! qualquer campo ser lido: estas tabelas vêm do firmware, e um ponteiro
//! errado aqui não dá erro, dá um número de núcleos inventado.
//!
//! # O que este leitor não faz
//!
//! Não interpreta AML, não acha o APIC de entrada e saída, não lê nenhuma
//! outra tabela. É um leitor de uma pergunta só.

use core::sync::atomic::{AtomicU64, Ordering};

/// Onde a RSDP está, em endereço físico, ou zero.
static RSDP: AtomicU64 = AtomicU64::new(0);

/// Guarda a RSDP que a entrega trouxe.
pub fn registrar_rsdp(fisico: u64) {
    RSDP.store(fisico, Ordering::Relaxed);
}

/// O maior tamanho de tabela que este leitor aceita.
///
/// Uma MADT de uma máquina com centenas de núcleos tem alguns KiB. Um tamanho
/// declarado de megabytes não é uma máquina grande: é um ponteiro errado, e
/// somar a verificação sobre ele seria ler memória de outra coisa.
const MAIOR_TABELA: u32 = 64 * 1024;

/// Lê `bytes` a partir de um endereço físico, se toda a faixa for alcançável.
///
/// A memória física está mapeada no deslocamento que o iniciador escolheu,
/// mas só até onde a RAM vai — e um ponteiro vindo do firmware pode apontar
/// para qualquer lugar. Conferir cada página antes de ler é o que transforma
/// um ponteiro errado num `None` em vez de numa falha de página no boot.
fn faixa(fisico: u64, bytes: usize) -> Option<&'static [u8]> {
    let fim = fisico.checked_add(bytes as u64)?;
    let mut pagina = fisico & !0xFFF;
    while pagina < fim {
        let virtual_ = super::paginacao::acesso_fisico(pagina);
        if virtual_.is_null() || super::paginacao::traduzir(virtual_ as u64).is_none() {
            return None;
        }
        pagina += 4096;
    }
    let inicio = super::paginacao::acesso_fisico(fisico);
    // SAFETY: cada página da faixa tem tradução, e as tabelas da ACPI vivem
    // em memória que o mapa entregou como reservada — ninguém as escreve.
    Some(unsafe { core::slice::from_raw_parts(inicio, bytes) })
}

fn soma_confere(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b)) == 0
}

fn u32_em(bytes: &[u8], em: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(em..em + 4)?.try_into().ok()?))
}

fn u64_em(bytes: &[u8], em: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(em..em + 8)?.try_into().ok()?))
}

/// Uma tabela com cabeçalho padrão, conferida: assinatura, tamanho e soma.
fn tabela(fisico: u64, assinatura: Option<&[u8; 4]>) -> Option<&'static [u8]> {
    const CABECALHO: usize = 36;
    let cabecalho = faixa(fisico, CABECALHO)?;
    if let Some(esperada) = assinatura
        && &cabecalho[0..4] != esperada
    {
        return None;
    }
    let tamanho = u32_em(cabecalho, 4)?;
    if (tamanho as usize) < CABECALHO || tamanho > MAIOR_TABELA {
        return None;
    }
    let inteira = faixa(fisico, tamanho as usize)?;
    soma_confere(inteira).then_some(inteira)
}

/// Acha a MADT pela RSDP.
fn madt() -> Result<&'static [u8], &'static str> {
    let rsdp = RSDP.load(Ordering::Relaxed);
    if rsdp == 0 {
        return Err("a entrega nao trouxe RSDP");
    }
    // Os vinte primeiros bytes são os da ACPI 1.0 e têm soma própria; a
    // extensão da 2.0 tem outra, sobre os trinta e seis.
    let curta = faixa(rsdp, 20).ok_or("a RSDP nao e alcancavel")?;
    if &curta[0..8] != b"RSD PTR " || !soma_confere(curta) {
        return Err("a RSDP nao confere");
    }
    let revisao = curta[15];

    // A XSDT quando há, com ponteiros de 64 bits; a RSDT quando não.
    let (raiz, largura) = if revisao >= 2 {
        let longa = faixa(rsdp, 36).ok_or("a RSDP estendida nao e alcancavel")?;
        if !soma_confere(longa) {
            return Err("a extensao da RSDP nao confere");
        }
        (u64_em(longa, 24).ok_or("RSDP curta")?, 8usize)
    } else {
        (u32_em(curta, 16).ok_or("RSDP curta")? as u64, 4usize)
    };
    let assinatura: &[u8; 4] = if largura == 8 { b"XSDT" } else { b"RSDT" };
    let raiz = tabela(raiz, Some(assinatura)).ok_or("a tabela raiz da ACPI nao confere")?;

    let mut em = 36;
    while em + largura <= raiz.len() {
        let ponteiro = if largura == 8 {
            u64_em(raiz, em)
        } else {
            u32_em(raiz, em).map(u64::from)
        }
        .ok_or("entrada truncada")?;
        if let Some(madt) = tabela(ponteiro, Some(b"APIC")) {
            return Ok(madt);
        }
        em += largura;
    }
    Err("a ACPI nao tem MADT")
}

/// Chama `f` com o id de APIC de cada núcleo habilitado, na ordem da MADT.
///
/// Devolve o erro se não houver MADT legível — e quem chama segue com um
/// núcleo só, que é o que a máquina tinha antes desta fase.
pub fn processadores(mut f: impl FnMut(u32)) -> Result<(), &'static str> {
    /// Entrada de APIC local (ids de 8 bits).
    const APIC_LOCAL: u8 = 0;
    /// Entrada de x2APIC local (ids de 32 bits).
    const X2APIC_LOCAL: u8 = 9;
    /// O núcleo está habilitado.
    const HABILITADO: u32 = 1 << 0;
    /// O núcleo está desligado agora, mas o firmware diz que pode ser ligado.
    ///
    /// Uma máquina com encaixe vago para processador descreve o encaixe com
    /// este bit. Acordar um núcleo que não existe deixaria o primeiro
    /// esperando a resposta até o prazo — por isso só o `HABILITADO` conta.
    const _PODE_SER_LIGADO: u32 = 1 << 1;

    let madt = madt()?;
    // Depois do cabeçalho: o endereço do APIC local e as flags, e então as
    // entradas, cada uma com tipo e tamanho.
    let mut em = 44;
    while em + 2 <= madt.len() {
        let tipo = madt[em];
        let tamanho = madt[em + 1] as usize;
        if tamanho < 2 || em + tamanho > madt.len() {
            return Err("entrada da MADT com tamanho impossivel");
        }
        let entrada = &madt[em..em + tamanho];
        match tipo {
            APIC_LOCAL if tamanho >= 8 => {
                let id = entrada[3] as u32;
                let flags = u32_em(entrada, 4).unwrap_or(0);
                if flags & HABILITADO != 0 {
                    f(id);
                }
            }
            X2APIC_LOCAL if tamanho >= 16 => {
                let id = u32_em(entrada, 4).unwrap_or(u32::MAX);
                let flags = u32_em(entrada, 8).unwrap_or(0);
                // Os ids que cabem em oito bits já vieram nas entradas de
                // APIC local: o firmware descreve cada núcleo uma vez só, mas
                // este kernel fala com o APIC no modo de oito bits e não
                // saberia endereçar um id maior.
                if flags & HABILITADO != 0 && id <= 0xFF {
                    f(id);
                }
            }
            _ => {}
        }
        em += tamanho;
    }
    Ok(())
}
