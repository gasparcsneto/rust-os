//! Onde parou um firmware que não entregou ao iniciador: o módulo em que
//! cada processador está, pelo endereço dele, e os retornos na pilha — o que
//! [`super::persistencia`] acrescenta ao diagnóstico do boot que não atende.
//!
//! # Por que
//!
//! Na CI 436, o primeiro boot de um cenário da bancada da atualização ficou
//! dois minutos sem andar com o processador 0 girando em `0x6c7e370`, com as
//! interrupções ligadas, e os outros três parados num `hlt` em `0x6c650d1` —
//! no firmware, antes do iniciador. O OVMF da CI é uma compilação de
//! release: não escreve no `debugcon`, e o endereço sozinho não diz o
//! módulo. Com o mesmo firmware aqui (o `ovmf-generic` 2025.11-3ubuntu7.3),
//! a mesma máquina põe as imagens nos mesmos endereços, e eles são
//! `Metronome+0x370` — o laço do `gBS->Stall`, que lê o relógio da ACPI — e
//! `CpuDxe+0xd0d1` — o `CpuSleep` dos processadores estacionados. Quem
//! chamou o `Stall`, só a pilha dizia: na mesma parada, reproduzida aqui,
//! ela tem o `VirtioRngDxe`, que o `Ip4Dxe` chamou — ver *O firmware parado
//! da CI 436* em `docs/PERSISTENCIA.md`.
//!
//! # Como se acha o módulo
//!
//! Cada driver do DXE é uma imagem PE/COFF que o núcleo do DXE carrega
//! numa faixa de páginas: o `MZ` no começo de uma página de 4 KiB, e o
//! `PE\0\0` onde o `e_lfanew` dele diz. A bancada lê a memória abaixo do
//! endereço pelo QMP — o `memsave`, pelas tabelas de páginas do próprio
//! processador —, página a página para baixo, até o cabeçalho da imagem que
//! o contém; o deslocamento é a distância até ele.
//!
//! O nome vem, nesta ordem:
//!
//! 1. do registro CodeView do diretório de depuração da imagem — o caminho
//!    `.pdb` ou `.dll` que o ligador grava: o iniciador, em Rust, grava o
//!    `iniciador.pdb`; um EDK II de depuração, o `.dll` de cada módulo;
//! 2. ou, sem ele, do arquivo do firmware com que a máquina subiu. O OVMF
//!    do Ubuntu — medido no 2024.02 daqui e no 2025.11 da CI — não grava o
//!    diretório de depuração nas imagens. O arquivo tem os volumes de
//!    firmware (FV), os arquivos FFS de cada um, e em cada arquivo a seção
//!    da imagem e a seção UI, com o nome do módulo; a parte que vai para a
//!    memória é comprimida em LZMA, e quem a abre é o `xz` do hospedeiro. A
//!    imagem na memória tem o cabeçalho da do arquivo, menos o `ImageBase`,
//!    que o carregador reescreve com o endereço onde a pôs.
//!
//! # A pilha
//!
//! Os valores da pilha do processador, do topo para baixo, que caem numa
//! imagem — os primeiros costumam ser os retornos: quem chamou o laço em
//! que ele gira, e o que esperava. É uma leitura de bancada, sem tabela de
//! desenrolar: um ponteiro velho que ficou na pilha também cai numa imagem.

use std::io::{BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Uma página: as imagens do DXE começam no começo de uma.
const PAGINA: u64 = 4096;

/// Até onde se procura, abaixo do endereço de um processador, o cabeçalho
/// da imagem que o contém. A maior imagem do OVMF da CI, o `TlsDxe`, tem
/// 1,3 MiB; o iniciador, 250 KiB.
const ATE_ONDE_PROCURAR: u64 = 4 << 20;

/// Quanto cada pedido de memória lê: dezesseis páginas.
const PEDACO: u64 = 64 << 10;

/// Quanto da pilha de um processador se olha, a partir do topo.
const PILHA: usize = 8192;

/// Quantos valores da pilha que caem em imagens o diagnóstico mostra.
const RETORNOS: usize = 8;

/// Quantas procuras de imagem a pilha de um processador pode fazer — cada
/// uma, até [`ATE_ONDE_PROCURAR_PELA_PILHA`] de memória lida. A maior parte
/// dos valores da pilha que parecem endereços são dados — o pool do
/// firmware fica entre as imagens —, e cada procura que não acha imagem
/// deixa marcada a faixa que ela mostrou vazia, para os vizinhos dela não
/// gastarem outra.
const PROCURAS_PELA_PILHA: usize = 32;

/// Até onde se procura o cabeçalho de uma imagem achada pela pilha.
const ATE_ONDE_PROCURAR_PELA_PILHA: u64 = 1 << 20;

/// O GUID da seção comprimida em LZMA do EDK II
/// (`EE4E5898-3914-4259-9D6E-DC7BD79403CF`), como fica nos bytes.
const LZMA: [u8; 16] = [
    0x98, 0x58, 0x4e, 0xee, 0x14, 0x39, 0x59, 0x42, 0x9d, 0x6e, 0xdc, 0x7b, 0xd7, 0x94, 0x03, 0xcf,
];

/// Quantos volumes dentro de volumes se seguem: o OVMF tem dois níveis — o
/// `FVMAIN_COMPACT`, e dentro dele, em LZMA, o `PEIFV` e o `DXEFV`.
const PROFUNDIDADE: u32 = 4;

/// A memória de uma máquina, pelo endereço que um processador vê.
pub(crate) trait Memoria {
    /// `tamanho` bytes a partir de `endereco`, pelas tabelas de páginas do
    /// processador `cpu` — ou `None`, se não se leem inteiros.
    fn ler(&mut self, cpu: u32, endereco: u64, tamanho: usize) -> Option<Vec<u8>>;
}

/// A memória de uma máquina pelo QMP: o `memsave` de cada pedaço num
/// arquivo, lido e apagado.
pub(crate) struct MemoriaPeloQmp<'a> {
    pub(crate) escrita: &'a mut UnixStream,
    pub(crate) leitor: &'a mut BufReader<UnixStream>,
    /// Onde o emulador escreve o pedaço: ao lado do socket do QMP.
    pub(crate) arquivo: PathBuf,
    /// O QMP deixou de responder a um pedido no prazo: não se pergunta mais
    /// nada a ele. As respostas não têm número, e a que chegasse atrasada
    /// seria lida como a do pedido seguinte — e um `memsave` atrasado ainda
    /// estaria escrevendo o arquivo.
    pub(crate) quebrado: bool,
}

impl Memoria for MemoriaPeloQmp<'_> {
    fn ler(&mut self, cpu: u32, endereco: u64, tamanho: usize) -> Option<Vec<u8>> {
        let mut pedido = String::new();
        {
            let mut j = protocolo::json::JsonWriter::new(&mut pedido);
            j.begin_object().ok()?;
            j.field_str("execute", "memsave").ok()?;
            j.key("arguments").ok()?;
            j.begin_object().ok()?;
            // O `val` é um inteiro de 64 bits com sinal: um endereço da
            // metade de cima, o do kernel, vai em complemento de dois.
            j.key("val").ok()?;
            j.i64_value(endereco as i64).ok()?;
            j.field_u64("size", tamanho as u64).ok()?;
            j.field_str("filename", self.arquivo.to_str()?).ok()?;
            j.field_u64("cpu-index", u64::from(cpu)).ok()?;
            j.end_object().ok()?;
            j.end_object().ok()?;
        }
        if self.quebrado {
            return None;
        }
        let resposta = super::qmp_pedir(self.escrita, self.leitor, &pedido);
        self.quebrado = resposta.is_err();
        let resposta = resposta.ok();
        let bytes = std::fs::read(&self.arquivo).ok();
        let _ = std::fs::remove_file(&self.arquivo);
        resposta
            .filter(|r| r.contains("\"return\""))
            .and(bytes)
            .filter(|b| b.len() == tamanho)
    }
}

/// A memória de uma máquina só nas faixas dadas — a RAM e a flash do
/// firmware, ver [`faixas_da_ram`] e [`faixas_da_flash`] —: o pedido que
/// sai delas não se faz.
///
/// # Por que
///
/// A procura das imagens e a leitura da pilha seguem endereços que a
/// máquina tem nos registradores e na pilha, pelas tabelas de páginas
/// dela — que mapeiam os dispositivos também. No ARM, no cenário do
/// incidente da bancada de persistência, um valor da pilha da CPU#0 levou
/// a procura de uma imagem a `0x7ff1000..0x8001000`: o fim da flash e o
/// começo do distribuidor do GIC, no `virt`. O emulador morreu nesse
/// pedido, sem uma linha no erro, e o resto do diagnóstico foi com ele. E
/// ler um registrador de dispositivo não é inócuo em geral: a FIFO de dados
/// do TPM pelo TIS se consome na leitura.
///
/// O que vale aqui é o endereço que a CPU usa, e não o físico: o firmware
/// mapeia a memória na identidade, e é o caso desta procura. Uma imagem só
/// existe na RAM — as do DXE, carregadas — ou na flash — as que rodam dela
/// no começo do boot, cuja leitura não tem efeito.
pub(crate) struct SoNaRam<'a> {
    pub(crate) memoria: &'a mut dyn Memoria,
    /// As faixas da RAM, `[de, ate)`.
    pub(crate) faixas: Vec<(u64, u64)>,
}

impl Memoria for SoNaRam<'_> {
    fn ler(&mut self, cpu: u32, endereco: u64, tamanho: usize) -> Option<Vec<u8>> {
        let fim = endereco.checked_add(tamanho as u64)?;
        if !self
            .faixas
            .iter()
            .any(|&(de, ate)| endereco >= de && fim <= ate)
        {
            return None;
        }
        self.memoria.ler(cpu, endereco, tamanho)
    }
}

/// A flash do firmware de uma máquina da bancada, onde o firmware a mapeia:
/// no `virt` do ARM, os dois bancos de 64 MiB a partir do zero; no `pc` do
/// x86, os 16 MiB abaixo dos 4 GiB — o OVMF fica no topo, e o APIC, o
/// IOAPIC, o HPET e o TPM, abaixo disso.
pub(crate) fn faixas_da_flash(arch: super::Arquitetura) -> Vec<(u64, u64)> {
    match arch {
        super::Arquitetura::Aarch64 => vec![(0, 0x0800_0000)],
        super::Arquitetura::X86_64 => vec![(0xFF00_0000, 1 << 32)],
    }
}

/// As faixas da RAM de uma máquina da bancada com `mib` MiB, nos endereços
/// em que o firmware a vê: no `virt` do ARM, a partir de 1 GiB; no `pc` do
/// x86, a de baixo sem a janela do vídeo e das ROMs (de 640 KiB a 1 MiB),
/// até 3 GiB, e o resto acima de 4 GiB.
pub(crate) fn faixas_da_ram(arch: super::Arquitetura, mib: u32) -> Vec<(u64, u64)> {
    let bytes = u64::from(mib) << 20;
    match arch {
        super::Arquitetura::Aarch64 => vec![(0x4000_0000, 0x4000_0000 + bytes)],
        super::Arquitetura::X86_64 => {
            let baixa = bytes.min(0xC000_0000);
            let mut faixas = vec![(0, 0xA_0000.min(baixa))];
            if baixa > 0x10_0000 {
                faixas.push((0x10_0000, baixa));
            }
            if bytes > baixa {
                faixas.push((1 << 32, (1 << 32) + bytes - baixa));
            }
            faixas
        }
    }
}

fn u16_em(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(i..i.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u24_em(b: &[u8], i: usize) -> Option<usize> {
    let c = b.get(i..i.checked_add(3)?)?;
    Some(usize::from(c[0]) | usize::from(c[1]) << 8 | usize::from(c[2]) << 16)
}

fn u32_em(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(i..i.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_em(b: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(i..i.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// `n` arredondado para cima até um múltiplo de `a`, uma potência de dois.
fn alinhar(n: usize, a: usize) -> usize {
    n.div_ceil(a) * a
}

/// O cabeçalho de uma imagem PE/COFF, lido do começo dela.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pe {
    /// O `SizeOfImage`: quantos bytes a imagem ocupa na memória.
    pub(crate) tamanho: u64,
    /// O diretório de depuração — o RVA e o tamanho —, se ela tem um.
    pub(crate) depuracao: Option<(u32, u32)>,
    /// As seções de código — o começo e o fim, em RVA —: as que o
    /// cabeçalho diz que têm código ou que se executam. Um retorno na pilha
    /// cai numa delas; um ponteiro para os dados da imagem, não.
    pub(crate) codigo: Vec<(u64, u64)>,
    /// O cabeçalho até o fim da tabela de seções, com o `ImageBase` zerado:
    /// o carregador do EDK II reescreve o `ImageBase` com o endereço onde
    /// pôs a imagem, e o resto fica como no arquivo — é o que se compara
    /// com as imagens do arquivo do firmware.
    pub(crate) cabecalho: Vec<u8>,
}

/// O cabeçalho PE/COFF no começo de `bytes`, se é um: o `MZ`, o `PE\0\0`
/// onde o `e_lfanew` diz, um cabeçalho opcional de PE32 ou de PE32+, e a
/// tabela de seções inteira dentro de `bytes`.
pub(crate) fn ler_pe(bytes: &[u8]) -> Option<Pe> {
    if bytes.get(..2)? != b"MZ" {
        return None;
    }
    let pe = usize::try_from(u32_em(bytes, 0x3c)?).ok()?;
    if pe < 0x40 || bytes.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let secoes = usize::from(u16_em(bytes, pe + 6)?);
    let opcional = usize::from(u16_em(bytes, pe + 20)?);
    let o = pe + 24;
    // Onde ficam o `ImageBase` e quantos bytes tem, o `NumberOfRvaAndSizes`
    // e os diretórios, no PE32 e no PE32+.
    let (base, largura, quantos, diretorios) = match u16_em(bytes, o)? {
        0x10b => (o + 28, 4, o + 92, o + 96),
        0x20b => (o + 24, 8, o + 108, o + 112),
        _ => return None,
    };
    if secoes == 0 || secoes > 96 || opcional < diretorios - o {
        return None;
    }
    let tamanho = u64::from(u32_em(bytes, o + 56)?);
    if tamanho == 0 {
        return None;
    }
    // O diretório 6 é o de depuração.
    let depuracao = if u32_em(bytes, quantos)? > 6 && diretorios + 7 * 8 <= o + opcional {
        let rva = u32_em(bytes, diretorios + 48)?;
        let n = u32_em(bytes, diretorios + 52)?;
        (rva != 0 && n != 0).then_some((rva, n))
    } else {
        None
    };
    let fim = o + opcional + 40 * secoes;
    let mut cabecalho = bytes.get(..fim)?.to_vec();
    cabecalho[base..base + largura].fill(0);
    // `IMAGE_SCN_CNT_CODE` e `IMAGE_SCN_MEM_EXECUTE`.
    let codigo = (0..secoes)
        .filter_map(|k| {
            let secao = o + opcional + 40 * k;
            let rva = u64::from(u32_em(bytes, secao + 12)?);
            let n = u64::from(u32_em(bytes, secao + 8)?.max(u32_em(bytes, secao + 16)?));
            let caracteristicas = u32_em(bytes, secao + 36)?;
            (caracteristicas & 0x2000_0020 != 0).then_some((rva, rva + n))
        })
        .collect();
    Some(Pe {
        tamanho,
        depuracao,
        codigo,
        cabecalho,
    })
}

/// O nome do arquivo no registro CodeView `registro` — o `RSDS` do PDB 7.0
/// (o do LLD, o do iniciador), o `NB10` do PDB 2.0 e o `MTOC` que o GenFw
/// do EDK II grava —: o último componente do caminho, sem os diretórios.
pub(crate) fn nome_no_codeview(registro: &[u8]) -> Option<String> {
    let caminho = match registro.get(..4)? {
        b"RSDS" => 24,
        b"NB10" => 16,
        b"MTOC" => 20,
        _ => return None,
    };
    let resto = registro.get(caminho..)?;
    let fim = resto.iter().position(|&b| b == 0)?;
    let caminho = std::str::from_utf8(&resto[..fim]).ok()?;
    let nome = caminho.rsplit(['/', '\\']).next()?;
    (!nome.is_empty() && nome.chars().all(|c| c.is_ascii_graphic() || c == ' '))
        .then(|| nome.to_string())
}

/// O nome que a imagem em `base` grava no diretório de depuração dela: o
/// do primeiro registro CodeView que se lê.
fn nome_pela_depuracao(memoria: &mut dyn Memoria, cpu: u32, base: u64, pe: &Pe) -> Option<String> {
    let (rva, n) = pe.depuracao?;
    // Cada entrada tem 28 bytes; mais de dezesseis não é um diretório.
    let n = usize::try_from(n).ok()?.min(28 * 16);
    let diretorio = memoria.ler(cpu, base.checked_add(u64::from(rva))?, n)?;
    diretorio.as_chunks::<28>().0.iter().find_map(|entrada| {
        // O tipo 2 é o CodeView.
        if u32_em(entrada, 12)? != 2 {
            return None;
        }
        let tamanho = usize::try_from(u32_em(entrada, 16)?).ok()?.min(1024);
        let rva = u64::from(u32_em(entrada, 20)?);
        if rva == 0 || rva >= pe.tamanho || tamanho < 5 {
            return None;
        }
        nome_no_codeview(&memoria.ler(cpu, base + rva, tamanho)?)
    })
}

/// Até `tamanho` bytes a partir de `endereco`: de uma vez, ou, se não se
/// leem inteiros — a pilha no fim da memória —, página a página, até a
/// primeira que não se lê.
pub(crate) fn ler_o_que_der(
    memoria: &mut dyn Memoria,
    cpu: u32,
    endereco: u64,
    tamanho: usize,
) -> Vec<u8> {
    if let Some(bytes) = memoria.ler(cpu, endereco, tamanho) {
        return bytes;
    }
    let mut bytes = Vec::new();
    let mut agora = endereco;
    while bytes.len() < tamanho {
        let ate_a_pagina = (PAGINA - agora % PAGINA) as usize;
        let n = ate_a_pagina.min(tamanho - bytes.len());
        let Some(pedaco) = memoria.ler(cpu, agora, n) else {
            break;
        };
        bytes.extend_from_slice(&pedaco);
        agora += n as u64;
    }
    bytes
}

/// O que há abaixo de um endereço, até onde se procurou.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Achado {
    /// A imagem em `base`, que vai até depois do endereço.
    Imagem { base: u64, pe: Pe },
    /// A imagem mais próxima abaixo, em `base`, acaba antes do endereço: ele
    /// não está numa imagem PE — são os dados de alguém, ou código que não
    /// veio de uma.
    DepoisDe { base: u64, tamanho: u64 },
    /// Nenhum cabeçalho PE nos `ate` bytes abaixo.
    Nenhum { ate: u64 },
    /// A memória deixou de se ler na página `em`, antes de um cabeçalho.
    Ilegivel { em: u64 },
}

/// A imagem que contém `endereco`: o cabeçalho PE mais próximo abaixo dele,
/// no começo de uma página, a até `ate_onde` bytes — lida aos pedaços de
/// [`PEDACO`], e página a página no pedaço que não se lê inteiro.
pub(crate) fn imagem_que_contem(
    memoria: &mut dyn Memoria,
    cpu: u32,
    endereco: u64,
    ate_onde: u64,
) -> Achado {
    let pagina_do_endereco = endereco & !(PAGINA - 1);
    let piso = pagina_do_endereco.saturating_sub(ate_onde.saturating_sub(PAGINA));
    let mut fim = pagina_do_endereco.saturating_add(PAGINA);
    while fim > piso {
        let inicio = fim.saturating_sub(PEDACO).max(piso);
        let pedaco = memoria.ler(cpu, inicio, (fim - inicio) as usize);
        let mut pagina = fim - PAGINA;
        loop {
            let bytes = match &pedaco {
                Some(p) => {
                    let i = (pagina - inicio) as usize;
                    p.get(i..i + PAGINA as usize).map(<[u8]>::to_vec)
                }
                None => memoria.ler(cpu, pagina, PAGINA as usize),
            };
            let Some(bytes) = bytes else {
                return Achado::Ilegivel { em: pagina };
            };
            if let Some(pe) = ler_pe(&bytes) {
                return if endereco - pagina < pe.tamanho {
                    Achado::Imagem { base: pagina, pe }
                } else {
                    Achado::DepoisDe {
                        base: pagina,
                        tamanho: pe.tamanho,
                    }
                };
            }
            if pagina == inicio {
                break;
            }
            pagina -= PAGINA;
        }
        fim = inicio;
    }
    Achado::Nenhum { ate: ate_onde }
}

/// Um módulo do arquivo do firmware: o nome da seção UI dele, e o
/// cabeçalho da imagem, como em [`Pe::cabecalho`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Modulo {
    pub(crate) nome: String,
    pub(crate) cabecalho: Vec<u8>,
}

/// Os módulos de um arquivo de firmware EDK II: os volumes (FV) do arquivo,
/// no começo de páginas; os arquivos FFS de cada volume; e as seções de
/// cada arquivo — a imagem PE (`EFI_SECTION_PE32`), o nome
/// (`EFI_SECTION_USER_INTERFACE`), e os volumes dentro de seções,
/// comprimidos ou não. O que está em LZMA vai para `descomprimir`.
pub(crate) fn modulos_do_firmware(
    arquivo: &[u8],
    descomprimir: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Vec<Modulo> {
    let mut modulos = Vec::new();
    let mut i = 0;
    while i + 0x30 <= arquivo.len() {
        let tamanho = volume(&arquivo[i..], descomprimir, &mut modulos, 0);
        i = alinhar(i + tamanho.max(1), PAGINA as usize);
    }
    modulos
}

/// Os arquivos do volume no começo de `v`, se é um: o tamanho dele, ou
/// zero.
fn volume(
    v: &[u8],
    descomprimir: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
    modulos: &mut Vec<Modulo>,
    profundidade: u32,
) -> usize {
    let tamanho = u64_em(v, 0x20).and_then(|t| usize::try_from(t).ok());
    let Some(tamanho) = tamanho.filter(|&t| {
        profundidade <= PROFUNDIDADE
            && v.get(0x28..0x2c) == Some(b"_FVH")
            && t >= 0x48
            && t <= v.len()
    }) else {
        return 0;
    };
    let v = &v[..tamanho];
    // Os arquivos começam depois do cabeçalho — e do cabeçalho estendido,
    // se há um —, alinhados a oito bytes.
    let estendido = u16_em(v, 0x34).map_or(0, usize::from);
    let mut i = if estendido != 0 {
        estendido + u32_em(v, estendido + 16).map_or(0, |n| n as usize)
    } else {
        u16_em(v, 0x30).map_or(0, usize::from)
    };
    i = alinhar(i, 8);
    while i + 24 <= v.len() {
        // O espaço livre do volume: o cabeçalho inteiro em `0xff`. Só o
        // nome em `0xff` não basta: é o do arquivo de enchimento
        // (`EFI_FV_FILETYPE_FFS_PAD`), que o GenFv põe para alinhar o
        // arquivo seguinte — o AAVMF tem um logo depois do `PeiCore`.
        if v[i..i + 24].iter().all(|&b| b == 0xff) {
            break;
        }
        // O arquivo grande (o atributo 1) diz o tamanho em 64 bits, depois
        // do cabeçalho comum.
        let (n, cabecalho) = if v[i + 19] & 1 != 0 {
            match u64_em(v, i + 24).and_then(|n| usize::try_from(n).ok()) {
                Some(n) => (n, 32),
                None => break,
            }
        } else {
            (u24_em(v, i + 20).unwrap_or(0), 24)
        };
        if n < cabecalho || i + n > v.len() {
            break;
        }
        let mut nome = None;
        let mut imagem = None;
        secoes(
            &v[i + cabecalho..i + n],
            descomprimir,
            modulos,
            profundidade,
            (&mut nome, &mut imagem),
        );
        if let (Some(nome), Some(cabecalho)) = (nome, imagem) {
            modulos.push(Modulo { nome, cabecalho });
        }
        i = alinhar(i + n, 8);
    }
    tamanho
}

/// As seções de um arquivo FFS, alinhadas a quatro bytes: o nome e a
/// imagem vão para `achados`; as seções que guardam outras — a GUID, a de
/// compressão sem compressão e a de volume — são seguidas.
fn secoes(
    s: &[u8],
    descomprimir: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
    modulos: &mut Vec<Modulo>,
    profundidade: u32,
    achados: (&mut Option<String>, &mut Option<Vec<u8>>),
) {
    let (nome, imagem) = achados;
    let mut i = 0;
    while i + 4 <= s.len() {
        // O tamanho em 24 bits; `0xffffff` diz que ele vem em 32, depois.
        let (n, cabecalho) = match u24_em(s, i) {
            Some(0xff_ffff) => (u32_em(s, i + 4).map_or(0, |n| n as usize), 8),
            Some(n) => (n, 4),
            None => return,
        };
        if n < cabecalho || i + n > s.len() {
            return;
        }
        let corpo = &s[i + cabecalho..i + n];
        match s[i + 3] {
            // EFI_SECTION_PE32
            0x10 => {
                if let Some(pe) = ler_pe(corpo) {
                    *imagem = Some(pe.cabecalho);
                }
            }
            // EFI_SECTION_USER_INTERFACE: UTF-16, até o zero.
            0x15 => {
                let unidades: Vec<u16> = corpo
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .take_while(|&u| u != 0)
                    .collect();
                if let Ok(texto) = String::from_utf16(&unidades) {
                    *nome = Some(texto);
                }
            }
            // EFI_SECTION_GUID_DEFINED: o GUID, e onde começam os dados —
            // contado do começo da seção.
            0x02 if profundidade < PROFUNDIDADE => {
                let dados = u16_em(corpo, 16)
                    .map(usize::from)
                    .and_then(|d| s.get(i + d..i + n));
                if let Some(dados) = dados {
                    if corpo.get(..16) == Some(&LZMA[..]) {
                        if let Some(aberto) = descomprimir(dados) {
                            secoes(
                                &aberto,
                                descomprimir,
                                modulos,
                                profundidade + 1,
                                (nome, imagem),
                            );
                        }
                    } else {
                        secoes(
                            dados,
                            descomprimir,
                            modulos,
                            profundidade + 1,
                            (nome, imagem),
                        );
                    }
                }
            }
            // EFI_SECTION_COMPRESSION sem compressão (o tipo 0): as seções
            // vêm depois do tamanho e do tipo.
            0x01 if profundidade < PROFUNDIDADE => {
                if corpo.get(4) == Some(&0) {
                    secoes(
                        &corpo[5..],
                        descomprimir,
                        modulos,
                        profundidade + 1,
                        (nome, imagem),
                    );
                }
            }
            // EFI_SECTION_FIRMWARE_VOLUME_IMAGE
            0x17 => {
                volume(corpo, descomprimir, modulos, profundidade + 1);
            }
            _ => {}
        }
        i = alinhar(i + n, 4);
    }
}

/// Abre uma seção LZMA do EDK II pelo `xz` do hospedeiro: o formato é o do
/// LZMA "alone" — as propriedades, o dicionário, o tamanho, e o fluxo —,
/// que o `xz --format=lzma` lê.
pub(crate) fn descomprimir_pelo_xz(dados: &[u8]) -> Result<Vec<u8>, String> {
    let mut filho = Command::new("xz")
        .args(["--format=lzma", "--decompress", "--stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("o xz nao rodou: {e}"))?;
    let mut entrada = filho.stdin.take().ok_or("o xz sem a entrada")?;
    // A entrada por um fio: o `xz` só termina de ler o que escreve se
    // alguém ler a saída dele.
    let dados = dados.to_vec();
    let escritor = std::thread::spawn(move || entrada.write_all(&dados));
    let saida = filho
        .wait_with_output()
        .map_err(|e| format!("o xz nao terminou: {e}"))?;
    let _ = escritor.join();
    if !saida.status.success() {
        return Err(format!(
            "o xz recusou: {}",
            String::from_utf8_lossy(&saida.stderr).trim()
        ));
    }
    Ok(saida.stdout)
}

/// Os módulos do arquivo de firmware `caminho`, com o LZMA aberto pelo
/// `xz` — ou por que não há.
pub(crate) fn modulos_do_arquivo(caminho: &std::path::Path) -> Result<Vec<Modulo>, String> {
    let arquivo =
        std::fs::read(caminho).map_err(|e| format!("{} nao se le: {e}", caminho.display()))?;
    let mut erro = None;
    let modulos = modulos_do_firmware(&arquivo, &mut |dados| {
        descomprimir_pelo_xz(dados).map_err(|e| erro = Some(e)).ok()
    });
    match (modulos.is_empty(), erro) {
        (true, Some(e)) => Err(e),
        (true, None) => Err(format!("{} nao tem modulos", caminho.display())),
        (false, _) => Ok(modulos),
    }
}

/// Um processador, pelo `info registers -a`: o número, o endereço da
/// instrução e o topo da pilha.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Processador {
    pub(crate) numero: u32,
    pub(crate) instrucao: u64,
    pub(crate) pilha: Option<u64>,
}

/// Os processadores de `registros` — a resposta do `info registers -a` do
/// monitor, com as quebras de linha como vêm do QMP, escapadas, ou não —:
/// o `RIP` e o `RSP` no x86, o `PC` e o `SP` no ARM.
pub(crate) fn processadores(registros: &str) -> Vec<Processador> {
    let texto = registros.replace("\\r", "").replace("\\n", "\n");
    let mut lista: Vec<Processador> = Vec::new();
    for linha in texto.lines() {
        for palavra in linha.split_whitespace() {
            let palavra = palavra.trim_matches(|c: char| c == '"' || c == '{' || c == '}');
            if let Some(n) = palavra.strip_prefix("CPU#") {
                if let Ok(numero) = n.trim_end_matches(':').parse() {
                    lista.push(Processador {
                        numero,
                        instrucao: u64::MAX,
                        pilha: None,
                    });
                }
                continue;
            }
            let Some((nome, valor)) = palavra.split_once('=') else {
                continue;
            };
            let (Some(p), Ok(valor)) = (lista.last_mut(), u64::from_str_radix(valor, 16)) else {
                continue;
            };
            match nome {
                "RIP" | "PC" => p.instrucao = valor,
                "RSP" | "SP" => p.pilha = Some(valor),
                _ => {}
            }
        }
    }
    lista.retain(|p| p.instrucao != u64::MAX);
    lista
}

/// O nome de uma imagem, e de onde ele veio.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Nome {
    /// Do registro CodeView da imagem.
    CodeView(String),
    /// Do módulo de mesmo cabeçalho no arquivo do firmware.
    Firmware(String),
    /// Nenhum: por que.
    Nenhum(String),
}

impl Nome {
    fn curto(&self) -> &str {
        match self {
            Nome::CodeView(n) | Nome::Firmware(n) => n,
            Nome::Nenhum(_) => "uma imagem sem nome",
        }
    }

    fn origem(&self) -> String {
        match self {
            Nome::CodeView(_) => "o nome pelo CodeView".into(),
            Nome::Firmware(_) => "o nome pelo arquivo do firmware".into(),
            Nome::Nenhum(porque) => porque.clone(),
        }
    }
}

/// Uma imagem achada, com o nome.
struct Conhecida {
    base: u64,
    tamanho: u64,
    /// As seções de código, em endereços.
    codigo: Vec<(u64, u64)>,
    nome: Nome,
}

/// Quem nomeia as imagens de um diagnóstico: a memória, e os módulos do
/// arquivo do firmware, pedidos uma vez só, na primeira imagem sem o
/// CodeView.
struct Nomeador<'a> {
    memoria: &'a mut dyn Memoria,
    fonte: &'a mut dyn FnMut() -> Result<Vec<Modulo>, String>,
    modulos: Option<Result<Vec<Modulo>, String>>,
    conhecidas: Vec<Conhecida>,
}

impl Nomeador<'_> {
    fn nomear(&mut self, cpu: u32, base: u64, pe: &Pe) -> Nome {
        if let Some(nome) = nome_pela_depuracao(self.memoria, cpu, base, pe) {
            return Nome::CodeView(nome);
        }
        let modulos = self.modulos.get_or_insert_with(|| (self.fonte)());
        match modulos {
            Err(e) => Nome::Nenhum(format!("sem o CodeView, e os modulos do firmware: {e}")),
            Ok(modulos) => {
                let mut nomes: Vec<&str> = modulos
                    .iter()
                    .filter(|m| m.cabecalho == pe.cabecalho)
                    .map(|m| m.nome.as_str())
                    .collect();
                nomes.dedup();
                if nomes.is_empty() {
                    Nome::Nenhum(format!(
                        "sem o CodeView, e nenhum dos {} modulos do firmware tem este cabecalho",
                        modulos.len()
                    ))
                } else {
                    Nome::Firmware(nomes.join(" ou "))
                }
            }
        }
    }

    /// A imagem que contém `endereco`: das já conhecidas, ou procurada a
    /// até `ate_onde` bytes abaixo — e nomeada. O índice dela, ou o que se
    /// achou no lugar.
    fn achar(&mut self, cpu: u32, endereco: u64, ate_onde: u64) -> Result<usize, Achado> {
        if let Some(i) = self
            .conhecidas
            .iter()
            .position(|c| endereco >= c.base && endereco - c.base < c.tamanho)
        {
            return Ok(i);
        }
        match imagem_que_contem(self.memoria, cpu, endereco, ate_onde) {
            Achado::Imagem { base, pe } => {
                let nome = self.nomear(cpu, base, &pe);
                self.conhecidas.push(Conhecida {
                    base,
                    tamanho: pe.tamanho,
                    codigo: pe
                        .codigo
                        .iter()
                        .map(|&(de, ate)| (base + de, base + ate))
                        .collect(),
                    nome,
                });
                Ok(self.conhecidas.len() - 1)
            }
            outro => Err(outro),
        }
    }

    /// Os valores da pilha de `cpu`, a partir de `topo`, que caem no código
    /// de uma imagem: `nome+deslocamento`, sem repetir o vizinho igual.
    fn pilha(&mut self, cpu: u32, topo: u64) -> Vec<String> {
        let bytes = ler_o_que_der(self.memoria, cpu, topo, PILHA);
        let mut retornos: Vec<String> = Vec::new();
        let mut procuras = 0;
        // As faixas que uma procura mostrou sem imagem: de onde acaba a
        // imagem de baixo até a página do valor; sem cabeçalho nenhum, a
        // janela inteira da procura.
        let mut vazias: Vec<(u64, u64)> = Vec::new();
        for valor in bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c))
        {
            if retornos.len() == RETORNOS {
                break;
            }
            // Um endereço de código: fora da primeira página e da metade de
            // cima do espaço, nas máquinas da bancada só o do kernel.
            if valor < PAGINA || valor >> 47 != 0 {
                continue;
            }
            let conhecida = self
                .conhecidas
                .iter()
                .position(|c| valor >= c.base && valor - c.base < c.tamanho);
            let i = match conhecida {
                Some(i) => i,
                None if procuras < PROCURAS_PELA_PILHA
                    && !vazias.iter().any(|&(de, ate)| valor >= de && valor < ate) =>
                {
                    procuras += 1;
                    let pagina = valor & !(PAGINA - 1);
                    match self.achar(cpu, valor, ATE_ONDE_PROCURAR_PELA_PILHA) {
                        Ok(i) => i,
                        Err(fora) => {
                            vazias.push(match fora {
                                Achado::DepoisDe { base, tamanho } => {
                                    (base + tamanho, pagina + PAGINA)
                                }
                                Achado::Nenhum { ate } => (
                                    pagina.saturating_sub(ate.saturating_sub(PAGINA)),
                                    pagina + PAGINA,
                                ),
                                _ => (pagina, pagina + PAGINA),
                            });
                            continue;
                        }
                    }
                }
                None => continue,
            };
            // Um retorno cai no código da imagem; um ponteiro para os dados
            // dela, não.
            let c = &self.conhecidas[i];
            if !c.codigo.iter().any(|&(de, ate)| valor >= de && valor < ate) {
                continue;
            }
            let texto = format!("{}+{:#x}", c.nome.curto(), valor - c.base);
            if retornos.last() != Some(&texto) {
                retornos.push(texto);
            }
        }
        retornos
    }
}

/// Onde está cada processador de `registros` — a resposta do `info
/// registers -a` —: o módulo e o deslocamento, a imagem e de onde veio o
/// nome, e os valores da pilha que caem no código de uma imagem. Uma linha por
/// endereço; os processadores no mesmo endereço, juntos, com a pilha do
/// primeiro. Os módulos do arquivo do firmware saem de `fonte`, se uma
/// imagem não tem o CodeView.
pub(crate) fn onde_cada_processador(
    registros: &str,
    memoria: &mut dyn Memoria,
    fonte: &mut dyn FnMut() -> Result<Vec<Modulo>, String>,
) -> Vec<String> {
    let mut grupos: Vec<(u64, Vec<Processador>)> = Vec::new();
    for p in processadores(registros) {
        match grupos.iter_mut().find(|(e, _)| *e == p.instrucao) {
            Some((_, g)) => g.push(p),
            None => grupos.push((p.instrucao, vec![p])),
        }
    }
    let mut nomeador = Nomeador {
        memoria,
        fonte,
        modulos: None,
        conhecidas: Vec::new(),
    };
    let mut linhas = Vec::new();
    for (endereco, grupo) in grupos {
        let primeiro = grupo[0];
        let nomes: Vec<String> = grupo.iter().map(|p| format!("CPU#{}", p.numero)).collect();
        let quem = match nomes.split_last() {
            Some((ultimo, resto)) if !resto.is_empty() => {
                format!("{} e {ultimo}", resto.join(", "))
            }
            _ => nomes.join(""),
        };
        let onde = match nomeador.achar(primeiro.numero, endereco, ATE_ONDE_PROCURAR) {
            Ok(i) => {
                let c = &nomeador.conhecidas[i];
                format!(
                    "{}+{:#x} (a imagem em {:#x}, de {:#x} bytes; {})",
                    c.nome.curto(),
                    endereco - c.base,
                    c.base,
                    c.tamanho,
                    c.nome.origem()
                )
            }
            Err(Achado::DepoisDe { base, tamanho }) => format!(
                "fora de uma imagem PE (a mais proxima abaixo, em {base:#x}, acaba em {:#x})",
                base + tamanho
            ),
            Err(Achado::Nenhum { ate }) => {
                format!(
                    "fora de uma imagem PE (nenhum cabecalho nos {} KiB abaixo)",
                    ate >> 10
                )
            }
            Err(Achado::Ilegivel { em }) => {
                format!("sem imagem achada (a memoria abaixo nao se le em {em:#x})")
            }
            Err(Achado::Imagem { .. }) => unreachable!("a imagem achada volta como Ok"),
        };
        let pilha = primeiro
            .pilha
            .map(|topo| nomeador.pilha(primeiro.numero, topo))
            .filter(|r| !r.is_empty())
            .map(|r| format!("; na pilha: {}", r.join(", ")))
            .unwrap_or_default();
        linhas.push(format!("{quem} em {endereco:#x}: {onde}{pilha}"));
    }
    linhas
}

#[cfg(test)]
mod testes_da_ram {
    use super::*;

    struct Toda;

    impl Memoria for Toda {
        fn ler(&mut self, _cpu: u32, _endereco: u64, tamanho: usize) -> Option<Vec<u8>> {
            Some(vec![0; tamanho])
        }
    }

    #[test]
    fn so_a_ram_se_le() {
        let mut toda = Toda;
        let mut m = SoNaRam {
            memoria: &mut toda,
            faixas: faixas_da_ram(super::super::Arquitetura::Aarch64, 128),
        };
        assert!(m.ler(0, 0x4000_0000, 4096).is_some());
        assert!(m.ler(0, 0x4800_0000 - 4096, 4096).is_some());
        // O GIC e a flash do `virt`, abaixo da RAM; e o fim dela.
        assert!(m.ler(0, 0x7ff_1000, 0x1_0000).is_none());
        assert!(m.ler(0, 0x3fff_f000, 4096).is_none());
        assert!(m.ler(0, 0x4800_0000 - 4096, 8192).is_none());
        assert!(m.ler(0, u64::MAX - 10, 4096).is_none());
        // Com a flash: o começo dela se lê, e o que passa do fim, não.
        let mut toda = Toda;
        let mut com_a_flash = SoNaRam {
            memoria: &mut toda,
            faixas: faixas_da_flash(super::super::Arquitetura::Aarch64),
        };
        assert!(com_a_flash.ler(0, 0x1000, 4096).is_some());
        assert!(com_a_flash.ler(0, 0x7ff_1000, 0x1_0000).is_none());
        assert_eq!(
            faixas_da_flash(super::super::Arquitetura::X86_64),
            vec![(0xFF00_0000, 1 << 32)]
        );
        let x86 = faixas_da_ram(super::super::Arquitetura::X86_64, 128);
        assert_eq!(x86, vec![(0, 0xA_0000), (0x10_0000, 128 << 20)]);
        let grande = faixas_da_ram(super::super::Arquitetura::X86_64, 4096);
        assert_eq!(grande[1], (0x10_0000, 0xC000_0000));
        assert_eq!(grande[2], (1 << 32, (1 << 32) + (1 << 30)));
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    /// Uma imagem PE32+ do jeito que o GenFw do EDK II a monta: o `MZ`, o
    /// `PE\0\0` em 0x80, o cabeçalho opcional com os dezesseis diretórios,
    /// uma seção `.text` — de 0x240 até 1 KiB antes do fim — e uma `.data`
    /// no último KiB; e, se `codeview`, o diretório de depuração em 0x900,
    /// com o registro em 0x940.
    fn imagem(tamanho: u32, imagebase: u64, codeview: Option<&[u8]>) -> Vec<u8> {
        let mut b = vec![0u8; tamanho as usize];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe = 0x80;
        b[pe..pe + 4].copy_from_slice(b"PE\0\0");
        b[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        b[pe + 6..pe + 8].copy_from_slice(&2u16.to_le_bytes());
        b[pe + 20..pe + 22].copy_from_slice(&240u16.to_le_bytes());
        let o = pe + 24;
        b[o..o + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[o + 16..o + 20].copy_from_slice(&0x240u32.to_le_bytes());
        b[o + 24..o + 32].copy_from_slice(&imagebase.to_le_bytes());
        b[o + 56..o + 60].copy_from_slice(&tamanho.to_le_bytes());
        b[o + 108..o + 112].copy_from_slice(&16u32.to_le_bytes());
        let secoes = o + 240;
        let dados = tamanho - 0x400;
        for (k, (nome, rva, n, caracteristicas)) in [
            (b".text\0\0\0", 0x240u32, dados - 0x240, 0x6000_0020u32),
            (b".data\0\0\0", dados, 0x400, 0xc000_0040),
        ]
        .iter()
        .enumerate()
        {
            let s = secoes + 40 * k;
            b[s..s + 8].copy_from_slice(*nome);
            b[s + 8..s + 12].copy_from_slice(&n.to_le_bytes());
            b[s + 12..s + 16].copy_from_slice(&rva.to_le_bytes());
            b[s + 36..s + 40].copy_from_slice(&caracteristicas.to_le_bytes());
        }
        if let Some(registro) = codeview {
            // O diretório em 0x900, o registro em 0x940.
            b[o + 112 + 48..o + 112 + 52].copy_from_slice(&0x900u32.to_le_bytes());
            b[o + 112 + 52..o + 112 + 56].copy_from_slice(&28u32.to_le_bytes());
            b[0x900 + 12..0x900 + 16].copy_from_slice(&2u32.to_le_bytes());
            b[0x900 + 16..0x900 + 20].copy_from_slice(&(registro.len() as u32).to_le_bytes());
            b[0x900 + 20..0x900 + 24].copy_from_slice(&0x940u32.to_le_bytes());
            b[0x940..0x940 + registro.len()].copy_from_slice(registro);
        }
        b
    }

    /// Um registro CodeView: a assinatura, `entre` bytes, e o caminho com o
    /// zero.
    fn codeview(assinatura: &[u8; 4], entre: usize, caminho: &str) -> Vec<u8> {
        let mut r = assinatura.to_vec();
        // Letras, e não zeros: o caminho lido do lugar errado sai com elas.
        r.extend(std::iter::repeat_n(b'G', entre));
        r.extend_from_slice(caminho.as_bytes());
        r.push(0);
        r
    }

    /// Uma memória de mentira: pedaços em endereços, e o resto ilegível.
    struct Sintetica {
        pedacos: Vec<(u64, Vec<u8>)>,
        leituras: usize,
    }

    impl Sintetica {
        fn nova() -> Sintetica {
            Sintetica {
                pedacos: Vec::new(),
                leituras: 0,
            }
        }

        fn com(mut self, endereco: u64, bytes: Vec<u8>) -> Sintetica {
            self.pedacos.push((endereco, bytes));
            self
        }
    }

    impl Memoria for Sintetica {
        fn ler(&mut self, _: u32, endereco: u64, tamanho: usize) -> Option<Vec<u8>> {
            self.leituras += 1;
            let fim = endereco.checked_add(tamanho as u64)?;
            // Os pedaços de trás para a frente: o posto antes cobre o posto
            // depois — o fundo de zeros vai por último. Como o `memsave`, a
            // leitura com um byte fora de todos falha inteira.
            let mut saida = vec![0u8; tamanho];
            let mut lido = vec![false; tamanho];
            for (base, bytes) in self.pedacos.iter().rev() {
                let de = endereco.max(*base);
                let ate = fim.min(base + bytes.len() as u64);
                if de >= ate {
                    continue;
                }
                let (i, j) = ((de - endereco) as usize, (ate - endereco) as usize);
                let k = (de - base) as usize;
                saida[i..j].copy_from_slice(&bytes[k..k + (j - i)]);
                lido[i..j].fill(true);
            }
            lido.iter().all(|&l| l).then_some(saida)
        }
    }

    /// O PE32+ do GenFw: o tamanho, o diretório de depuração e o
    /// cabeçalho até o fim das seções, sem o `ImageBase`.
    #[test]
    fn o_cabecalho_pe_sem_o_image_base() {
        let a = ler_pe(&imagem(0xa00, 0, None)).unwrap();
        assert_eq!(a.tamanho, 0xa00);
        assert_eq!(a.depuracao, None);
        assert_eq!(a.cabecalho.len(), 0x80 + 24 + 240 + 80);
        // Carregada em outro endereço, a mesma imagem.
        let b = ler_pe(&imagem(0xa00, 0x06c7_e000, None)).unwrap();
        assert_eq!(a.cabecalho, b.cabecalho);
        // Outro tamanho, outro cabeçalho.
        assert_ne!(
            ler_pe(&imagem(0xb00, 0, None)).unwrap().cabecalho,
            a.cabecalho
        );
        let c = ler_pe(&imagem(0x1000, 0, Some(&codeview(b"RSDS", 20, "x.pdb")))).unwrap();
        assert_eq!(c.depuracao, Some((0x900, 28)));
    }

    /// O que não é um cabeçalho PE não passa: o `MZ` sem o `PE`, o
    /// `e_lfanew` fora dos bytes ou em cima do `MZ`, a assinatura do
    /// cabeçalho opcional que não é de PE32 nem de PE32+, nenhuma seção,
    /// e o tamanho zero.
    #[test]
    fn as_recusas_do_cabecalho() {
        let boa = imagem(0xa00, 0, None);
        assert!(ler_pe(&boa).is_some());
        let estragar = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut b = boa.clone();
            f(&mut b);
            ler_pe(&b)
        };
        assert_eq!(estragar(&|b| b[0] = b'N'), None);
        assert_eq!(estragar(&|b| b[0x80] = b'Q'), None);
        assert_eq!(
            estragar(&|b| b[0x3c..0x40].copy_from_slice(&0xfff0u32.to_le_bytes())),
            None
        );
        assert_eq!(
            estragar(&|b| b[0x3c..0x40].copy_from_slice(&0x10u32.to_le_bytes())),
            None
        );
        assert_eq!(
            estragar(&|b| b[0x98..0x9a].copy_from_slice(&0x107u16.to_le_bytes())),
            None
        );
        assert_eq!(estragar(&|b| b[0x86..0x88].fill(0)), None);
        assert_eq!(estragar(&|b| b[0x98 + 56..0x98 + 60].fill(0)), None);
        // A tabela de seções que passa do fim dos bytes.
        assert_eq!(ler_pe(&boa[..0x80 + 24 + 240 + 79]), None);
        assert_eq!(ler_pe(b"MZ"), None);
        assert_eq!(ler_pe(&[]), None);
    }

    /// O nome do registro CodeView: o `RSDS` do LLD (o iniciador), o `NB10`
    /// e o `MTOC` do GenFw — o caminho onde cada um o põe, e dele o último
    /// componente, com as barras dos dois sistemas.
    #[test]
    fn o_nome_no_codeview() {
        assert_eq!(
            nome_no_codeview(&codeview(b"RSDS", 20, "iniciador.pdb")).as_deref(),
            Some("iniciador.pdb")
        );
        assert_eq!(
            nome_no_codeview(&codeview(b"NB10", 12, "Metronome.dll")).as_deref(),
            Some("Metronome.dll")
        );
        assert_eq!(
            nome_no_codeview(&codeview(b"MTOC", 16, "CpuDxe.dll")).as_deref(),
            Some("CpuDxe.dll")
        );
        assert_eq!(
            nome_no_codeview(&codeview(
                b"NB10",
                12,
                "/build/edk2/Build/OvmfX64/DEBUG_GCC5/X64/MdeModulePkg/Universal/Metronome/Metronome/DEBUG/Metronome.dll"
            ))
            .as_deref(),
            Some("Metronome.dll")
        );
        assert_eq!(
            nome_no_codeview(&codeview(b"MTOC", 16, "C:\\edk2\\Build\\CpuDxe.dll")).as_deref(),
            Some("CpuDxe.dll")
        );
        // Sem o zero no fim, outra assinatura, o caminho que acaba numa
        // barra, o texto que não se imprime e o registro curto.
        let mut sem_zero = codeview(b"RSDS", 20, "a.pdb");
        sem_zero.pop();
        assert_eq!(nome_no_codeview(&sem_zero), None);
        assert_eq!(nome_no_codeview(&codeview(b"RSDT", 20, "a.pdb")), None);
        assert_eq!(nome_no_codeview(&codeview(b"RSDS", 20, "dir/")), None);
        assert_eq!(nome_no_codeview(&codeview(b"RSDS", 20, "a\u{7}.pdb")), None);
        assert_eq!(nome_no_codeview(b"NB10\0\0"), None);
    }

    /// Um processador no meio de uma imagem, numa página que não é a do
    /// cabeçalho: a imagem e o deslocamento, pelo cabeçalho mais próximo
    /// abaixo — o `MZ` fora do começo de uma página e o `MZ` sem `PE` no
    /// caminho não contam.
    #[test]
    fn a_imagem_pelo_cabecalho_abaixo() {
        let mut cpudxe = imagem(0x16d80, 0x06c5_8000, None);
        // Os dados dela: um `MZ` sem `PE` no começo de uma página, e um
        // fora do começo.
        cpudxe[0x5000..0x5002].copy_from_slice(b"MZ");
        cpudxe[0x9010..0x9012].copy_from_slice(b"MZ");
        let mut m = Sintetica::nova()
            .com(0x06c5_8000, cpudxe)
            .com(0x06c0_0000, vec![0; 0x10_0000]);
        let Achado::Imagem { base, pe } =
            imagem_que_contem(&mut m, 1, 0x06c6_50d1, ATE_ONDE_PROCURAR)
        else {
            panic!("a imagem do CpuDxe");
        };
        assert_eq!((base, pe.tamanho), (0x06c5_8000, 0x16d80));
        // A primeira página: o cabeçalho na própria página.
        assert!(matches!(
            imagem_que_contem(&mut m, 0, 0x06c5_8010, ATE_ONDE_PROCURAR),
            Achado::Imagem {
                base: 0x06c5_8000,
                ..
            }
        ));
        // Depois do fim dela: fora de uma imagem.
        assert_eq!(
            imagem_que_contem(&mut m, 0, 0x06c7_0010, ATE_ONDE_PROCURAR),
            Achado::DepoisDe {
                base: 0x06c5_8000,
                tamanho: 0x16d80
            }
        );
        // Só o lixo abaixo, até onde se procura.
        let mut so_lixo = Sintetica::nova().com(0x0010_0000, vec![0u8; 0x10_0000]);
        assert_eq!(
            imagem_que_contem(&mut so_lixo, 0, 0x001f_f123, 0x4_0000),
            Achado::Nenhum { ate: 0x4_0000 }
        );
        // A memória que acaba antes de um cabeçalho: a página onde parou.
        let mut buraco = Sintetica::nova().com(0x0030_0000, vec![0u8; 0x3000]);
        assert_eq!(
            imagem_que_contem(&mut buraco, 0, 0x0030_2010, ATE_ONDE_PROCURAR),
            Achado::Ilegivel { em: 0x002f_f000 }
        );
        // Perto do zero, a procura não passa dele.
        let mut baixo = Sintetica::nova().com(0, vec![0u8; 0x2000]);
        assert_eq!(
            imagem_que_contem(&mut baixo, 0, 0x1fff, ATE_ONDE_PROCURAR),
            Achado::Nenhum {
                ate: ATE_ONDE_PROCURAR
            }
        );
    }

    /// O pedaço que não se lê inteiro — a imagem logo acima de uma página
    /// ilegível — é lido página a página, e o cabeçalho ainda se acha.
    #[test]
    fn o_pedaco_com_uma_pagina_ilegivel() {
        let mut m = Sintetica::nova().com(0x0700_3000, imagem(0x2000, 0, None));
        assert!(matches!(
            imagem_que_contem(&mut m, 0, 0x0700_4abc, ATE_ONDE_PROCURAR),
            Achado::Imagem {
                base: 0x0700_3000,
                ..
            }
        ));
    }

    /// Um volume de firmware com um arquivo: o nome e as seções.
    fn volume_sintetico(arquivos: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![0u8; 0x48];
        v[0x28..0x2c].copy_from_slice(b"_FVH");
        v[0x30..0x32].copy_from_slice(&0x48u16.to_le_bytes());
        for a in arquivos {
            while v.len() % 8 != 0 {
                v.push(0xff);
            }
            v.extend_from_slice(a);
        }
        while v.len() % 8 != 0 {
            v.push(0xff);
        }
        v.extend_from_slice(&[0xff; 24]);
        let n = v.len() as u64;
        v[0x20..0x28].copy_from_slice(&n.to_le_bytes());
        v
    }

    /// Um arquivo FFS com estas seções.
    fn arquivo_ffs(secoes: &[Vec<u8>]) -> Vec<u8> {
        let mut corpo = Vec::new();
        for s in secoes {
            while corpo.len() % 4 != 0 {
                corpo.push(0);
            }
            corpo.extend_from_slice(s);
        }
        let mut a = vec![0x5a; 16];
        a.extend_from_slice(&[0, 0, 0x07, 0]);
        let n = (24 + corpo.len()) as u32;
        a.extend_from_slice(&n.to_le_bytes()[..3]);
        a.push(0xf8);
        a.extend_from_slice(&corpo);
        a
    }

    /// Uma seção: o tamanho em 24 bits, o tipo e o corpo.
    fn secao(tipo: u8, corpo: &[u8]) -> Vec<u8> {
        let n = (4 + corpo.len()) as u32;
        let mut s = n.to_le_bytes()[..3].to_vec();
        s.push(tipo);
        s.extend_from_slice(corpo);
        s
    }

    fn ui(nome: &str) -> Vec<u8> {
        let mut c: Vec<u8> = nome.encode_utf16().flat_map(u16::to_le_bytes).collect();
        c.extend_from_slice(&[0, 0]);
        secao(0x15, &c)
    }

    /// Uma seção GUID: o cabeçalho, `extra` — o CRC de 32 bits da seção
    /// do GUID do CRC32, por exemplo —, e os dados onde o `DataOffset` diz,
    /// contado do começo da seção.
    fn guid(guid: &[u8; 16], extra: &[u8], dados: &[u8]) -> Vec<u8> {
        let mut c = guid.to_vec();
        c.extend_from_slice(&(24 + extra.len() as u16).to_le_bytes());
        c.extend_from_slice(&1u16.to_le_bytes());
        c.extend_from_slice(extra);
        c.extend_from_slice(dados);
        secao(0x02, &c)
    }

    /// O arquivo do firmware como o do OVMF: um volume no começo, com um
    /// módulo à vista, um arquivo de enchimento — o nome todo em `0xff`,
    /// como o espaço livre — e uma seção LZMA que guarda outro volume — o do
    /// DXE —,
    /// com outro módulo; e um segundo volume, numa página adiante, com um
    /// módulo dentro de uma seção GUID que não comprime e tem quatro bytes a
    /// mais no cabeçalho — os dados ficam onde o `DataOffset` diz.
    #[test]
    fn os_modulos_do_arquivo_do_firmware() {
        let metronome = imagem(0xa00, 0, None);
        let cpudxe = imagem(0x16d80, 0, None);
        let terminal = imagem(0x4980, 0, None);
        let dxe = volume_sintetico(&[arquivo_ffs(&[secao(0x10, &metronome), ui("Metronome")])]);
        let comprimido = b"o volume do DXE, comprimido".to_vec();
        // Um arquivo de enchimento: o nome todo em `0xff`, o tipo `0xf0`.
        let mut enchimento = arquivo_ffs(&[secao(0x19, &[0xff; 20])]);
        enchimento[..16].fill(0xff);
        enchimento[18] = 0xf0;
        let externo = volume_sintetico(&[
            arquivo_ffs(&[secao(0x10, &cpudxe), ui("CpuDxe")]),
            enchimento,
            arquivo_ffs(&[guid(&LZMA, &[], &comprimido)]),
        ]);
        let mut arquivo = externo.clone();
        arquivo.resize(alinhar(arquivo.len(), 4096), 0xff);
        let crc = [0x11u8; 16];
        arquivo.extend_from_slice(&volume_sintetico(&[arquivo_ffs(&[guid(
            &crc,
            &[0x5a; 4],
            &[secao(0x10, &terminal), ui("TerminalDxe")].concat(),
        )])]));
        let mut pedidos = Vec::new();
        let modulos = modulos_do_firmware(&arquivo, &mut |dados| {
            pedidos.push(dados.to_vec());
            Some(secao(0x17, &dxe))
        });
        let nomes: Vec<&str> = modulos.iter().map(|m| m.nome.as_str()).collect();
        assert_eq!(nomes, ["CpuDxe", "Metronome", "TerminalDxe"]);
        assert_eq!(pedidos, [comprimido]);
        // A imagem carregada em outro endereço tem o cabeçalho do módulo.
        let carregada = ler_pe(&imagem(0xa00, 0x06c7_e000, None)).unwrap();
        assert_eq!(modulos[1].cabecalho, carregada.cabecalho);
        // Sem descompressor, só os módulos à vista.
        let a_vista = modulos_do_firmware(&arquivo, &mut |_| None);
        assert_eq!(a_vista.len(), 2);
        // Lixo não é volume.
        assert!(modulos_do_firmware(&[0x5a; 0x3000], &mut |_| None).is_empty());
    }

    /// O `xz` do hospedeiro abre o LZMA "alone" do EDK II — o que ele mesmo
    /// escreve com `--format=lzma` —, e recusa o que não é.
    #[test]
    fn o_xz_abre_o_lzma_do_edk2() {
        let original: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut filho = Command::new("xz")
            .args(["--format=lzma", "--compress", "--stdout"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("o xz no hospedeiro");
        let mut entrada = filho.stdin.take().unwrap();
        let copia = original.clone();
        let escritor = std::thread::spawn(move || entrada.write_all(&copia));
        let comprimido = filho.wait_with_output().unwrap().stdout;
        escritor.join().unwrap().unwrap();
        assert_eq!(descomprimir_pelo_xz(&comprimido).unwrap(), original);
        assert!(descomprimir_pelo_xz(b"isto nao e lzma").is_err());
    }

    /// Os processadores da CI 436 — o que o QMP devolveu, com as quebras de
    /// linha escapadas —, e os do ARM.
    #[test]
    fn os_processadores_pelo_info_registers() {
        let x86 = r#"{"return": "CPU#0\r\nRAX=0000000000000000 RBX=0000000000000001 RCX=0000000000000000 RDX=0000000000000000\r\nRSI=0000000000000000 RDI=0000000000000000 RBP=0000000007e59f20 RSP=0000000007e59ee0\r\nR8 =0000000000000000 R9 =0000000000000000\r\nRIP=0000000006c7e370 RFL=00000206 [-----P-] CPL=0 II=0 A20=1 SMM=0 HLT=0\r\nCPU#1\r\nRSP=0000000006c3fef8\r\nRIP=0000000006c650d1 RFL=00000046 [---Z-P-] CPL=0 II=0 A20=1 SMM=0 HLT=1\r\n"}"#;
        assert_eq!(
            processadores(x86),
            [
                Processador {
                    numero: 0,
                    instrucao: 0x06c7_e370,
                    pilha: Some(0x07e5_9ee0)
                },
                Processador {
                    numero: 1,
                    instrucao: 0x06c6_50d1,
                    pilha: Some(0x06c3_fef8)
                },
            ]
        );
        let arm = "CPU#0\n PC=000000005fe1c2a0 X00=0000000000000000 X01=0000000000000001\nX30=000000005fe1c100  SP=000000005ffde9c0\nPSTATE=600003c5 -ZC- EL1h\n";
        assert_eq!(
            processadores(arm),
            [Processador {
                numero: 0,
                instrucao: 0x5fe1_c2a0,
                pilha: Some(0x5ffd_e9c0)
            }]
        );
        assert!(processadores("{\"error\": {}}").is_empty());
    }

    /// A CI 436 de novo, numa memória de mentira com o `Metronome` e o
    /// `CpuDxe` onde o firmware da CI os põe, sem o CodeView, e o `BdsDxe`
    /// que chamou o `Stall` na pilha do processador 0: os nomes pelo
    /// arquivo do firmware, pedido uma vez só; os três estacionados numa
    /// linha só; e a pilha, sem o que não cai numa imagem.
    #[test]
    fn onde_estavam_os_processadores_da_ci_436() {
        let metronome = imagem(0xa00, 0x06c7_e000, None);
        let cpudxe = imagem(0x16d80, 0x06c5_8000, None);
        let bds = imagem(0x15640, 0x0689_4000, None);
        let mut pilha0 = Vec::new();
        // Um número pequeno; o retorno do `WaitForTick`, duas vezes; o do
        // `BdsDxe`; um ponteiro para os dados do `BdsDxe`, que não é retorno;
        // um para o pool, fora das imagens; e outro retorno do `BdsDxe`.
        for v in [
            0x0000_0000_0000_0001u64,
            0x06c7_e3cf,
            0x06c7_e3cf,
            0x0689_5a10,
            0x068a_9400,
            0x0777_0000,
            0x0689_6000,
        ] {
            pilha0.extend_from_slice(&v.to_le_bytes());
        }
        pilha0.resize(PILHA, 0);
        let mut m = Sintetica::nova()
            .com(0x06c5_8000, cpudxe.clone())
            .com(0x06c7_e000, metronome.clone())
            .com(0x0689_4000, bds.clone())
            .com(0x07e5_9ee0, pilha0)
            .com(0x0600_0000, vec![0u8; 0x200_0000]);
        // Os módulos como estão no arquivo do firmware: o `ImageBase` de lá
        // não é o da memória.
        let modulos: Vec<Modulo> = [
            ("Metronome", 0xa00),
            ("CpuDxe", 0x16d80),
            ("BdsDxe", 0x15640),
        ]
        .into_iter()
        .map(|(nome, tamanho)| Modulo {
            nome: nome.into(),
            cabecalho: ler_pe(&imagem(tamanho, 0, None)).unwrap().cabecalho,
        })
        .collect();
        let registros = "CPU#0\r\nRSP=0000000007e59ee0\r\nRIP=0000000006c7e370 HLT=0\r\nCPU#1\r\nRSP=0000000006c3fef8\r\nRIP=0000000006c650d1 HLT=1\r\nCPU#2\r\nRSP=0000000006c47ef8\r\nRIP=0000000006c650d1 HLT=1\r\nCPU#3\r\nRSP=0000000006c4fef8\r\nRIP=0000000006c650d1 HLT=1\r\n";
        let mut pedidos = 0;
        let linhas = onde_cada_processador(registros, &mut m, &mut || {
            pedidos += 1;
            Ok(modulos.clone())
        });
        assert_eq!(pedidos, 1);
        assert_eq!(
            linhas,
            [
                "CPU#0 em 0x6c7e370: Metronome+0x370 (a imagem em 0x6c7e000, de 0xa00 bytes; o nome pelo arquivo do firmware); na pilha: Metronome+0x3cf, BdsDxe+0x1a10, BdsDxe+0x2000",
                "CPU#1, CPU#2 e CPU#3 em 0x6c650d1: CpuDxe+0xd0d1 (a imagem em 0x6c58000, de 0x16d80 bytes; o nome pelo arquivo do firmware)",
            ]
        );
    }

    /// Com o CodeView, o nome vem dele, e o arquivo do firmware nem é
    /// pedido; sem nenhum dos dois, a linha diz por que não há nome; e o
    /// endereço fora de uma imagem diz onde acaba a de baixo.
    #[test]
    fn o_codeview_primeiro_e_as_linhas_sem_nome() {
        let iniciador = imagem(
            0x4000,
            0x0640_0000,
            Some(&codeview(b"RSDS", 20, "iniciador.pdb")),
        );
        let mut m = Sintetica::nova()
            .com(0x0640_0000, iniciador)
            .com(0x0630_0000, vec![0u8; 0x20_0000]);
        let registros = "CPU#0\nRIP=0000000006401234\nCPU#1\nRIP=0000000006404010\n";
        let linhas = onde_cada_processador(registros, &mut m, &mut || panic!("o CodeView basta"));
        assert_eq!(
            linhas,
            [
                "CPU#0 em 0x6401234: iniciador.pdb+0x1234 (a imagem em 0x6400000, de 0x4000 bytes; o nome pelo CodeView)",
                "CPU#1 em 0x6404010: fora de uma imagem PE (a mais proxima abaixo, em 0x6400000, acaba em 0x6404000)",
            ]
        );
        let mut m = Sintetica::nova()
            .com(0x0640_0000, imagem(0x4000, 0, None))
            .com(0x0630_0000, vec![0u8; 0x20_0000]);
        let sem_xz = onde_cada_processador("CPU#0\nRIP=0000000006401000\n", &mut m, &mut || {
            Err("o xz nao rodou: No such file or directory".into())
        });
        assert_eq!(
            sem_xz,
            [
                "CPU#0 em 0x6401000: uma imagem sem nome+0x1000 (a imagem em 0x6400000, de 0x4000 bytes; sem o CodeView, e os modulos do firmware: o xz nao rodou: No such file or directory)"
            ]
        );
        let outro = onde_cada_processador("CPU#0\nRIP=0000000006401000\n", &mut m, &mut || {
            Ok(Vec::new())
        });
        assert!(
            outro[0].ends_with(
                "sem o CodeView, e nenhum dos 0 modulos do firmware tem este cabecalho)"
            ),
            "{outro:?}"
        );
    }

    /// A pilha no fim da memória que se lê: o que se lê dela ainda conta.
    #[test]
    fn a_pilha_no_fim_da_memoria() {
        let metronome = imagem(0xa00, 0x06c7_e000, None);
        let mut pilha = 0x06c7_e3cfu64.to_le_bytes().to_vec();
        pilha.resize(0x100, 0);
        let mut m = Sintetica::nova()
            .com(0x06c7_e000, metronome)
            .com(0x07ff_ff00, pilha)
            .com(0x0600_0000, vec![0u8; 0x1ff_ff00]);
        let modulos = vec![Modulo {
            nome: "Metronome".into(),
            cabecalho: ler_pe(&imagem(0xa00, 0, None)).unwrap().cabecalho,
        }];
        let linhas = onde_cada_processador(
            "CPU#0\nRSP=0000000007ffff00\nRIP=0000000006c7e370\n",
            &mut m,
            &mut || Ok(modulos.clone()),
        );
        assert!(
            linhas[0].ends_with("; na pilha: Metronome+0x3cf"),
            "{linhas:?}"
        );
    }

    /// A pilha cheia de ponteiros para os dados de um driver — o pool do
    /// firmware fica entre as imagens —, em quarenta e sete páginas: a
    /// primeira procura mostra a faixa toda sem imagem, e as outras não
    /// gastam procura; o retorno que vem depois, para o núcleo do DXE, ainda
    /// se acha, com poucas leituras.
    #[test]
    fn a_pilha_nao_gasta_as_procuras_com_os_dados() {
        let pequena = imagem(0x1000, 0x0690_0000, None);
        let nucleo = imagem(0x2_3e80, 0x07e5_b000, None);
        let mut pilha = Vec::new();
        let mut valores = vec![0x0692_f010u64];
        valores.extend((0..46u64).map(|k| 0x0690_1010 + k * 0x1000));
        valores.push(0x07e5_c123);
        for v in valores {
            pilha.extend_from_slice(&v.to_le_bytes());
        }
        pilha.resize(PILHA, 0);
        let mut m = Sintetica::nova()
            .com(0x0690_0000, pequena)
            .com(0x07e5_b000, nucleo)
            .com(0x07f0_0000, pilha)
            .com(0x0600_0000, vec![0u8; 0x200_0000]);
        let modulos: Vec<Modulo> = [("PcRtc", 0x1000), ("DxeCore", 0x2_3e80)]
            .into_iter()
            .map(|(nome, tamanho)| Modulo {
                nome: nome.into(),
                cabecalho: ler_pe(&imagem(tamanho, 0, None)).unwrap().cabecalho,
            })
            .collect();
        let linhas = onde_cada_processador(
            "CPU#0\nRSP=0000000007f00000\nRIP=0000000006900800\n",
            &mut m,
            &mut || Ok(modulos.clone()),
        );
        assert_eq!(
            linhas,
            [
                "CPU#0 em 0x6900800: PcRtc+0x800 (a imagem em 0x6900000, de 0x1000 bytes; o nome pelo arquivo do firmware); na pilha: DxeCore+0x1123"
            ]
        );
        assert!(m.leituras < 100, "{} leituras", m.leituras);
    }
}
