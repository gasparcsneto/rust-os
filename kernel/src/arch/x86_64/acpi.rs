//! O mínimo da ACPI para saber quantos núcleos a máquina tem — e, desde o
//! reinício e o desligamento, como pedir um e outro ao chipset.
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
//! # Reiniciar e desligar
//!
//! ```text
//!   RSDP ──► XSDT ──► "FACP" (FADT) ──► o registrador de reinício, PM1a/PM1b
//!                                   └─► DSDT ──► o pacote `\_S5`
//! ```
//!
//! A FADT diz onde estão os registradores; o valor que desliga — o
//! `SLP_TYP` do estado S5 — mora na DSDT, como o objeto `\_S5`. Ver
//! [`energia`] e [`s5_do_aml`].
//!
//! # O que este leitor não faz
//!
//! Não interpreta AML: do `\_S5` ele lê o pacote como os bytes que ele é,
//! a declaração de nome mais comum — e se a DSDT o declara de outro jeito
//! (dentro de um método, ou de um `If`), o desligamento pela ACPI não
//! acontece, e a máquina para sem cortar a energia. Não acha o APIC de
//! entrada e saída, nem lê outras tabelas.

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
    tabela_ate(fisico, assinatura, MAIOR_TABELA)
}

/// A DSDT de uma máquina de verdade passa fácil dos 64 KiB — é o AML da
/// placa inteira. Um megabyte ainda separa uma tabela grande de um
/// ponteiro errado.
const MAIOR_DSDT: u32 = 1024 * 1024;

/// [`tabela`], com o teto dado.
fn tabela_ate(fisico: u64, assinatura: Option<&[u8; 4]>, maior: u32) -> Option<&'static [u8]> {
    const CABECALHO: usize = 36;
    let cabecalho = faixa(fisico, CABECALHO)?;
    if let Some(esperada) = assinatura
        && &cabecalho[0..4] != esperada
    {
        return None;
    }
    let tamanho = u32_em(cabecalho, 4)?;
    if (tamanho as usize) < CABECALHO || tamanho > maior {
        return None;
    }
    let inteira = faixa(fisico, tamanho as usize)?;
    soma_confere(inteira).then_some(inteira)
}

/// Acha a MADT pela RSDP.
fn madt() -> Result<&'static [u8], &'static str> {
    da_raiz(b"APIC")?.ok_or("a ACPI nao tem MADT")
}

/// Acha, pela RSDP, a tabela de assinatura `procurada` — `None` se a raiz
/// não a lista.
fn da_raiz(procurada: &[u8; 4]) -> Result<Option<&'static [u8]>, &'static str> {
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
        if let Some(achada) = tabela(ponteiro, Some(procurada)) {
            return Ok(Some(achada));
        }
        em += largura;
    }
    Ok(None)
}

/// O espaço de um registrador genérico da ACPI (GAS): memória.
pub const ESPACO_MEMORIA: u8 = 0;
/// O espaço de um registrador genérico da ACPI (GAS): portas de E/S.
pub const ESPACO_PORTA: u8 = 1;

/// Um registrador genérico da ACPI — o *Generic Address Structure*: em que
/// espaço ele está e o endereço. A largura e o deslocamento de bits, este
/// kernel não precisa: os registradores que ele escreve são os de byte e
/// os de dezesseis bits do PM1, pela especificação.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registrador {
    pub espaco: u8,
    pub endereco: u64,
}

impl Registrador {
    /// O GAS de doze bytes em `em`, se tem endereço.
    fn de(fadt: &[u8], em: usize) -> Option<Registrador> {
        let espaco = *fadt.get(em)?;
        let endereco = u64_em(fadt, em + 4)?;
        (endereco != 0).then_some(Registrador { espaco, endereco })
    }

    /// Um bloco de portas da FADT antiga — trinta e dois bits, sempre E/S.
    fn porta(fadt: &[u8], em: usize) -> Option<Registrador> {
        let endereco = u64::from(u32_em(fadt, em)?);
        (endereco != 0).then_some(Registrador {
            espaco: ESPACO_PORTA,
            endereco,
        })
    }
}

/// O que a FADT e a DSDT dizem sobre reiniciar e desligar.
#[derive(Clone, Copy, Debug, Default)]
pub struct Energia {
    /// O registrador de reinício e o valor que reinicia, quando a FADT diz
    /// que ele existe (`RESET_REG_SUP`).
    pub reinicio: Option<(Registrador, u8)>,
    /// Os registradores de controle `PM1a_CNT` e `PM1b_CNT`.
    pub pm1a: Option<Registrador>,
    pub pm1b: Option<Registrador>,
    /// O `SLP_TYP` do S5 para o PM1a e para o PM1b, do `\_S5` da DSDT.
    pub s5: Option<(u8, u8)>,
    /// Para ligar o modo ACPI quando o firmware não ligou: a porta
    /// `SMI_CMD` e o valor `ACPI_ENABLE`. Zero quando não há o que ligar.
    pub smi_cmd: u32,
    pub acpi_enable: u8,
    /// Numa máquina de hardware reduzido — sem PM1 —, o
    /// `SLEEP_CONTROL_REG`.
    pub controle_de_sono: Option<Registrador>,
}

/// Lê a FADT e o `\_S5` da DSDT. `Err` se não há FADT legível; um campo
/// `None` é o que a máquina não descreve.
pub fn energia() -> Result<Energia, &'static str> {
    /// `RESET_REG_SUP`, nas flags da FADT.
    const REINICIO_SUPORTADO: u32 = 1 << 10;
    /// `HW_REDUCED_ACPI`.
    const HARDWARE_REDUZIDO: u32 = 1 << 20;

    let fadt = da_raiz(b"FACP")?.ok_or("a ACPI nao tem FADT")?;
    let n = fadt.len();
    let flags = u32_em(fadt, 112).unwrap_or(0);
    let mut e = Energia {
        smi_cmd: u32_em(fadt, 48).unwrap_or(0),
        acpi_enable: fadt.get(52).copied().unwrap_or(0),
        ..Energia::default()
    };
    if flags & REINICIO_SUPORTADO != 0 && n >= 129 {
        e.reinicio = Registrador::de(fadt, 116).map(|r| (r, fadt[128]));
    }
    // Os blocos estendidos da ACPI 2.0, quando há; senão os de 32 bits.
    e.pm1a = (n >= 184)
        .then(|| Registrador::de(fadt, 172))
        .flatten()
        .or_else(|| Registrador::porta(fadt, 64));
    e.pm1b = (n >= 196)
        .then(|| Registrador::de(fadt, 184))
        .flatten()
        .or_else(|| Registrador::porta(fadt, 68));
    if flags & HARDWARE_REDUZIDO != 0 && n >= 256 {
        e.controle_de_sono = Registrador::de(fadt, 244);
    }
    let dsdt = (n >= 148)
        .then(|| u64_em(fadt, 140))
        .flatten()
        .filter(|&x| x != 0)
        .or_else(|| u32_em(fadt, 40).map(u64::from))
        .unwrap_or(0);
    if dsdt != 0
        && let Some(dsdt) = tabela_ate(dsdt, Some(b"DSDT"), MAIOR_DSDT)
    {
        e.s5 = s5_do_aml(&dsdt[36..]);
    }
    Ok(e)
}

/// Os `SLP_TYP` do estado S5 — desligado — de um AML: o pacote do objeto
/// `\_S5`, lido como os bytes que ele é, sem interpretar o AML.
///
/// A forma que este leitor reconhece é a declaração de nome com o pacote
/// logo depois:
///
/// ```text
///   08 [5C] 5F 53 35 5F 12 <PkgLength> <NumElements> <a> <b> ...
///   NameOp [\] "_S5_"   PackageOp
/// ```
///
/// Cada elemento é `ZeroOp` (0x00), `OneOp` (0x01) ou um inteiro com
/// prefixo (`BytePrefix` 0x0A, `WordPrefix` 0x0B, `DWordPrefix` 0x0C) — o
/// `SLP_TYP` tem três bits, e só o byte de baixo importa. O segundo, o do
/// PM1b, falta em pacotes curtos, e vale zero.
pub fn s5_do_aml(aml: &[u8]) -> Option<(u8, u8)> {
    const NOME_OP: u8 = 0x08;
    const RAIZ: u8 = b'\\';
    const PACOTE_OP: u8 = 0x12;
    let mut de = 0;
    while let Some(achado) = aml.get(de..)?.windows(4).position(|w| w == b"_S5_") {
        let em = de + achado;
        de = em + 4;
        let declarado = (em >= 1 && aml[em - 1] == NOME_OP)
            || (em >= 2 && aml[em - 1] == RAIZ && aml[em - 2] == NOME_OP);
        if !declarado || aml.get(em + 4) != Some(&PACOTE_OP) {
            continue;
        }
        // O PkgLength: os dois bits altos do primeiro byte dizem quantos
        // bytes seguem; depois dele, o número de elementos.
        let comprimento = *aml.get(em + 5)?;
        let mut p = em + 5 + 1 + usize::from(comprimento >> 6) + 1;
        let a = elemento_inteiro(aml, &mut p)?;
        let b = elemento_inteiro(aml, &mut p).unwrap_or(0);
        return Some((a & 7, b & 7));
    }
    None
}

/// Um elemento inteiro de um pacote AML, e o avanço sobre ele.
fn elemento_inteiro(aml: &[u8], p: &mut usize) -> Option<u8> {
    let (valor, tamanho) = match *aml.get(*p)? {
        0x00 => (0, 1),
        0x01 => (1, 1),
        0x0A => (*aml.get(*p + 1)?, 2),
        0x0B => (*aml.get(*p + 1)?, 3),
        0x0C => (*aml.get(*p + 1)?, 5),
        _ => return None,
    };
    *p += tamanho;
    Some(valor)
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
