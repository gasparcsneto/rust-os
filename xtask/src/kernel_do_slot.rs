//! O kernel que vai para o slot: a cópia do ELF sem a tabela de símbolos e
//! sem o DWARF — o `--strip-all` do `llvm-objcopy` —, conferida contra o
//! ELF de origem antes de ir para o slot.
//!
//! # Por que sem a tabela de símbolos
//!
//! O iniciador lê o arquivo inteiro do slot para a memória antes de conferir
//! e carregar os segmentos, recusa um kernel de mais de
//! [`MAIOR_KERNEL`](atualizacao::cabecalho::MAIOR_KERNEL), e guarda o
//! arquivo lido até o salto. Nada no boot lê a tabela de símbolos: o
//! iniciador lê os cabeçalhos de programa, os segmentos `PT_LOAD` e, pelo
//! `PT_DYNAMIC`, as relocações — nunca uma seção, ver `iniciador/src/elf.rs`
//! —; e o kernel não lê a própria tabela: ele relata endereços crus, e quem
//! os traduz é o `cargo xtask simbolo`, no hospedeiro. No kernel de teste de
//! depuração do x86_64 ela era 13,5 MB dos 33,5 do arquivo, que estava a
//! 4 824 bytes do teto; e a memória que o iniciador retém com ele faltava a
//! um caso da suíte.
//!
//! O que lê símbolos lê o ELF inteiro, em `target/`, que a cópia não toca:
//! o `cargo xtask simbolo`, o depurador (`cargo xtask debug`), o
//! `cargo xtask asm`, o `cargo xtask elf`, a conferência do estouro da pilha
//! e a do SIMD. O de uma versão publicada, o `publicar` deixa ao lado da
//! imagem do slot, para o `cargo xtask simbolo --elf`.
//!
//! # O que a conferência garante
//!
//! Que o iniciador carrega da cópia o que carregaria do ELF de origem: o
//! mesmo cabeçalho, menos os três campos que descrevem a tabela de seções;
//! os mesmos cabeçalhos de programa; e os mesmos bytes em cada `PT_LOAD` —
//! e, neles, a mesma seção dinâmica e a mesma tabela de relocações, que o
//! iniciador acha pelo `PT_DYNAMIC`. A única diferença na memória são
//! aqueles três campos, onde o cabeçalho cai dentro de um `PT_LOAD`: no
//! x86_64 o primeiro começa no byte 0 do arquivo e leva o cabeçalho junto,
//! e os bytes 0x28–0x2f e 0x3c–0x3f mudam lá também; nada no kernel os lê.
//! No aarch64 o cabeçalho fica fora dos segmentos. E a conferência garante
//! que a cópia não tem a tabela de símbolos, nem seção que nada carregue
//! além da dos nomes, e que as seções carregáveis continuam descritas como
//! na origem.
//!
//! Ela roda a cada cópia, e não só nos testes: o `llvm-objcopy` vem do
//! nightly do `rust-toolchain.toml`, e um que mudasse o que o `--strip-all`
//! faz pararia aqui, com o segmento e o byte, em vez de num boot que não
//! chega ao kernel.

use std::ops::Range;
use std::path::{Path, PathBuf};

/// O que o `llvm-objcopy` faz com o kernel que vai para o slot: tira o que
/// não vai para a memória — a tabela de símbolos, o DWARF, o `.comment` — e
/// mais nada. As seções carregáveis e a tabela de seções ficam: o
/// `llvm-readobj` da sonda do iniciador continua lendo a cópia.
pub(crate) const OPCOES_DO_OBJCOPY: &[&str] = &["--strip-all"];

/// `e_shoff`, `e_shnum` e `e_shstrndx`: os campos do cabeçalho ELF64 que
/// descrevem a tabela de seções, e os únicos dele que a cópia muda.
const CAMPOS_DAS_SECOES: [Range<u64>; 2] = [40..48, 60..64];

/// `PT_LOAD` e `PT_DYNAMIC`.
const CARREGAVEL: u32 = 1;
const DINAMICO: u32 = 2;

/// `SHT_SYMTAB`, e a marca `SHF_ALLOC` das seções que vão para a memória.
const TABELA_DE_SIMBOLOS: u32 = 2;
const CARREGADA: u64 = 2;

/// As etiquetas da seção dinâmica que dizem onde estão as relocações.
const DT_NULL: u64 = 0;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;

/// O tamanho de um `Elf64_Rela`.
const TAMANHO_DA_RELOCACAO: u64 = 24;

/// O que a conferência contou numa cópia que serve.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Conferida {
    /// Quantos `PT_LOAD`, iguais byte a byte aos da origem.
    pub segmentos: usize,
    /// Quantas relocações a tabela do `PT_DYNAMIC` tem — as que o iniciador
    /// do x86 aplica; zero no ARM, ligado num endereço fixo.
    pub relocacoes: u64,
}

/// A cópia de `kernel` que vai para o slot, ao lado dele — `duke.esp.elf` —,
/// feita pelo `llvm-objcopy` com `opcoes` e conferida contra ele
/// ([`conferir_a_copia`]). O kernel de verdade usa [`OPCOES_DO_OBJCOPY`];
/// os testes passam outras, para ver a conferência recusar.
pub(crate) fn copiar(kernel: &Path, opcoes: &[&str]) -> Result<PathBuf, String> {
    let copia = kernel.with_extension("esp.elf");
    let (de, para) = (kernel.display().to_string(), copia.display().to_string());
    let mut args: Vec<&str> = opcoes.to_vec();
    args.extend([de.as_str(), para.as_str()]);
    super::ferramenta(&super::localizar_objcopy()?.display().to_string(), &args)?;
    let ler = |c: &Path| {
        std::fs::read(c).map_err(|e| format!("não foi possível ler {}: {e}", c.display()))
    };
    let (origem, feita) = (ler(kernel)?, ler(&copia)?);
    let c = conferir_a_copia(&origem, &feita)
        .map_err(|m| format!("a cópia para o slot, {para}, não é {de} sem os símbolos: {m}"))?;
    println!(
        "[xtask] {} -> {}: {} KiB -> {} KiB, sem a tabela de símbolos; {} segmentos e {} \
         relocações iguais aos do ELF inteiro",
        kernel.file_name().unwrap_or_default().display(),
        copia.file_name().unwrap_or_default().display(),
        origem.len() / 1024,
        feita.len() / 1024,
        c.segmentos,
        c.relocacoes
    );
    Ok(copia)
}

/// Confere que `copia` é `origem` sem o que não vai para a memória, como o
/// iniciador a lê — ver o começo deste módulo. Devolve quantos segmentos e
/// quantas relocações conferiu; o erro diz o primeiro que não confere.
pub(crate) fn conferir_a_copia(origem: &[u8], copia: &[u8]) -> Result<Conferida, String> {
    let o = Elf::ler(origem, "o ELF de origem")?;
    let c = Elf::ler(copia, "a cópia")?;
    if sem_os_campos_das_secoes(origem)? != sem_os_campos_das_secoes(copia)? {
        return Err("o cabeçalho ELF mudou além dos campos da tabela de seções".into());
    }
    if o.tabela_de_programas()? != c.tabela_de_programas()? {
        return Err("os cabeçalhos de programa mudaram".into());
    }
    // As tabelas de programas são as mesmas: os segmentos da origem são os
    // da cópia, nos mesmos lugares do arquivo.
    let programas = o.programas()?;
    let mut segmentos = 0;
    for (i, p) in programas.iter().enumerate() {
        if p.tipo != CARREGAVEL {
            continue;
        }
        segmentos += 1;
        let de = o.fatia(p.no_arquivo, p.do_arquivo)?;
        let para = c.fatia(p.no_arquivo, p.do_arquivo)?;
        if let Some(byte) = primeira_diferenca(de, para, p.no_arquivo) {
            return Err(format!(
                "o segmento {i} (PT_LOAD em {:#x}) mudou no byte {byte:#x} do arquivo",
                p.endereco
            ));
        }
    }
    // A tabela de relocações, onde o iniciador a acha: na cópia. Os bytes
    // dela já conferiram — ela mora num `PT_LOAD` —; aqui, que ela está
    // inteira num deles e tem a forma que o iniciador aplica.
    let relocacoes = c.relocacoes(&programas)?;
    // Nenhuma tabela de símbolos, nenhuma seção que nada carrega além da dos
    // nomes, e as carregáveis descritas como na origem.
    let secoes = c.secoes()?;
    if secoes.is_empty() {
        return Err("a cópia não tem a tabela de seções".into());
    }
    if let Some(s) = secoes
        .iter()
        .find(|s| s.tipo == TABELA_DE_SIMBOLOS || s.nome == ".symtab" || s.nome == ".strtab")
    {
        return Err(format!(
            "a cópia ainda tem a tabela de símbolos ({})",
            s.nome
        ));
    }
    if let Some(s) = secoes
        .iter()
        .find(|s| s.marcas & CARREGADA == 0 && s.nome != ".shstrtab")
    {
        return Err(format!("a cópia ainda tem {}, que nada carrega", s.nome));
    }
    let carregaveis = |todas: Vec<Secao>| -> Vec<Secao> {
        todas
            .into_iter()
            .filter(|s| s.marcas & CARREGADA != 0)
            .collect()
    };
    if carregaveis(o.secoes()?) != carregaveis(secoes) {
        return Err("as seções carregáveis mudaram".into());
    }
    Ok(Conferida {
        segmentos,
        relocacoes,
    })
}

/// O cabeçalho ELF64 de `bytes`, com os campos da tabela de seções zerados.
fn sem_os_campos_das_secoes(bytes: &[u8]) -> Result<[u8; 64], String> {
    let mut cabecalho: [u8; 64] = bytes
        .get(..64)
        .and_then(|c| c.try_into().ok())
        .ok_or("o arquivo é menor que um cabeçalho ELF64")?;
    for r in &CAMPOS_DAS_SECOES {
        cabecalho[r.start as usize..r.end as usize].fill(0);
    }
    Ok(cabecalho)
}

/// O primeiro byte, contado do começo do arquivo, em que `a` e `b` — o
/// mesmo pedaço, do mesmo tamanho, dos dois arquivos, a partir do byte `em`
/// — diferem, fora dos campos da tabela de seções. `None` se são iguais.
fn primeira_diferenca(a: &[u8], b: &[u8], em: u64) -> Option<u64> {
    if a == b {
        return None;
    }
    a.iter().zip(b).zip(em..).find_map(|((x, y), onde)| {
        (x != y && !CAMPOS_DAS_SECOES.iter().any(|r| r.contains(&onde))).then_some(onde)
    })
}

/// Um ELF64 little-endian, lido sem acreditar em nada: toda posição vem do
/// arquivo, e é conferida contra o tamanho dele antes de virar fatia.
struct Elf<'a> {
    bytes: &'a [u8],
}

/// Um cabeçalho de programa, no que a conferência usa.
#[derive(Clone, Copy)]
struct Programa {
    tipo: u32,
    no_arquivo: u64,
    endereco: u64,
    do_arquivo: u64,
}

/// Uma seção, no que a conferência compara.
#[derive(Debug, PartialEq, Eq)]
struct Secao {
    nome: String,
    tipo: u32,
    marcas: u64,
    endereco: u64,
    no_arquivo: u64,
    tamanho: u64,
}

impl<'a> Elf<'a> {
    fn ler(bytes: &'a [u8], quem: &str) -> Result<Elf<'a>, String> {
        if bytes.get(..6) != Some(b"\x7fELF\x02\x01".as_slice()) {
            return Err(format!("{quem} não é um ELF64 little-endian"));
        }
        let elf = Elf { bytes };
        let tamanho = elf.u16_em(54)?;
        if tamanho != 56 {
            return Err(format!(
                "{quem} tem cabeçalhos de programa de {tamanho} bytes, e os do ELF64 têm 56"
            ));
        }
        Ok(elf)
    }

    /// Os `n` bytes a partir do byte `em`, se estão todos no arquivo.
    fn fatia(&self, em: u64, n: u64) -> Result<&'a [u8], String> {
        usize::try_from(em)
            .ok()
            .zip(usize::try_from(n).ok())
            .and_then(|(de, quantos)| self.bytes.get(de..de.checked_add(quantos)?))
            .ok_or_else(|| {
                format!(
                    "os bytes {em:#x}..+{n:#x} passam do fim do arquivo, de {:#x}",
                    self.bytes.len()
                )
            })
    }

    fn le<const N: usize>(&self, em: u64) -> Result<[u8; N], String> {
        let mut b = [0u8; N];
        b.copy_from_slice(self.fatia(em, N as u64)?);
        Ok(b)
    }

    fn u16_em(&self, em: u64) -> Result<u16, String> {
        self.le(em).map(u16::from_le_bytes)
    }

    fn u32_em(&self, em: u64) -> Result<u32, String> {
        self.le(em).map(u32::from_le_bytes)
    }

    fn u64_em(&self, em: u64) -> Result<u64, String> {
        self.le(em).map(u64::from_le_bytes)
    }

    /// A tabela de cabeçalhos de programa, crua.
    fn tabela_de_programas(&self) -> Result<&'a [u8], String> {
        let quantos = u64::from(self.u16_em(56)?);
        self.fatia(self.u64_em(32)?, quantos * 56)
    }

    fn programas(&self) -> Result<Vec<Programa>, String> {
        let tabela = self.u64_em(32)?;
        (0..u64::from(self.u16_em(56)?))
            .map(|i| -> Result<Programa, String> {
                let p = tabela.saturating_add(i * 56);
                Ok(Programa {
                    tipo: self.u32_em(p)?,
                    no_arquivo: self.u64_em(p.saturating_add(8))?,
                    endereco: self.u64_em(p.saturating_add(16))?,
                    do_arquivo: self.u64_em(p.saturating_add(32))?,
                })
            })
            .collect()
    }

    /// Quantas relocações tem a tabela que o `PT_DYNAMIC` aponta — `DT_RELA`,
    /// `DT_RELASZ` e `DT_RELAENT` —, conferida como o iniciador a usa:
    /// inteira num `PT_LOAD`, em entradas do tamanho do formato. Zero sem
    /// `PT_DYNAMIC` — o kernel do ARM, ligado num endereço fixo — ou sem
    /// `DT_RELA`.
    fn relocacoes(&self, programas: &[Programa]) -> Result<u64, String> {
        let Some(dinamico) = programas.iter().find(|p| p.tipo == DINAMICO) else {
            return Ok(0);
        };
        let (mut onde, mut bytes, mut entrada) = (0, 0, 0);
        for i in 0..dinamico.do_arquivo / 16 {
            let par = dinamico.no_arquivo.saturating_add(16 * i);
            let valor = self.u64_em(par.saturating_add(8))?;
            match self.u64_em(par)? {
                DT_NULL => break,
                DT_RELA => onde = valor,
                DT_RELASZ => bytes = valor,
                DT_RELAENT => entrada = valor,
                _ => {}
            }
        }
        if onde == 0 || bytes == 0 {
            return Ok(0);
        }
        if entrada != TAMANHO_DA_RELOCACAO || !bytes.is_multiple_of(TAMANHO_DA_RELOCACAO) {
            return Err(format!(
                "a tabela de relocações tem {bytes} bytes em entradas de {entrada}, e o \
                 formato tem {TAMANHO_DA_RELOCACAO}"
            ));
        }
        let carregada = programas.iter().any(|p| {
            p.tipo == CARREGAVEL
                && onde >= p.endereco
                && onde
                    .checked_add(bytes)
                    .is_some_and(|fim| fim <= p.endereco.saturating_add(p.do_arquivo))
        });
        if !carregada {
            return Err(format!(
                "a tabela de relocações, em {onde:#x}, não está inteira num segmento carregável"
            ));
        }
        Ok(bytes / TAMANHO_DA_RELOCACAO)
    }

    /// As seções, menos a nula, com o nome de cada uma. Vazia se o arquivo
    /// não tem a tabela de seções.
    fn secoes(&self) -> Result<Vec<Secao>, String> {
        let tabela = self.u64_em(40)?;
        let tamanho = self.u16_em(58)?;
        let quantas = u64::from(self.u16_em(60)?);
        let dos_nomes = u64::from(self.u16_em(62)?);
        if tabela == 0 || quantas == 0 {
            return Ok(Vec::new());
        }
        if tamanho != 64 {
            return Err(format!(
                "cabeçalhos de seção de {tamanho} bytes, e os do ELF64 têm 64"
            ));
        }
        if dos_nomes >= quantas {
            return Err(format!(
                "a seção dos nomes, {dos_nomes}, não está entre as {quantas}"
            ));
        }
        let cabecalho = |i: u64| -> Result<(u32, Secao), String> {
            let s = tabela.saturating_add(i * 64);
            Ok((
                self.u32_em(s)?,
                Secao {
                    nome: String::new(),
                    tipo: self.u32_em(s.saturating_add(4))?,
                    marcas: self.u64_em(s.saturating_add(8))?,
                    endereco: self.u64_em(s.saturating_add(16))?,
                    no_arquivo: self.u64_em(s.saturating_add(24))?,
                    tamanho: self.u64_em(s.saturating_add(32))?,
                },
            ))
        };
        let (_, dos_nomes) = cabecalho(dos_nomes)?;
        let nomes = self.fatia(dos_nomes.no_arquivo, dos_nomes.tamanho)?;
        (1..quantas)
            .map(|i| -> Result<Secao, String> {
                let (nome, mut secao) = cabecalho(i)?;
                secao.nome = usize::try_from(nome)
                    .ok()
                    .and_then(|de| nomes.get(de..))
                    .and_then(|resto| resto.split(|&b| b == 0).next())
                    .and_then(|nome| std::str::from_utf8(nome).ok())
                    .ok_or_else(|| format!("o nome da seção {i} não está na tabela dos nomes"))?
                    .to_string();
                Ok(secao)
            })
            .collect()
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    /// Um diretório só deste teste, nesta execução.
    fn diretorio(nome: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "xtask-kernel-do-slot-{}-{nome}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn por(b: &mut [u8], em: usize, bytes: &[u8]) {
        b[em..em + bytes.len()].copy_from_slice(bytes);
    }

    /// Os campos, na ordem, num registro só.
    fn juntos(campos: &[&[u8]]) -> Vec<u8> {
        campos.concat()
    }

    /// Um kernel de mentira com a forma do do x86_64: um ELF64 independente
    /// de posição (`ET_DYN`), com dois `PT_LOAD` — o de código, que leva o
    /// cabeçalho, a tabela dinâmica de símbolos, as relocações e o `.text`,
    /// e o de dados, com a seção dinâmica, o `.data` e o `.bss` — e o
    /// `PT_DYNAMIC`; duas relocações relativas, de `.data` para `.text`; e,
    /// fora dos segmentos, o `.comment`, um pedaço de DWARF, a tabela de
    /// símbolos com o `_start`, os nomes dela e os das seções.
    ///
    /// ```text
    ///  0x000  cabeçalho, e os três programas em 0x40
    ///  0x100  .dynsym (o símbolo nulo)          0x118  .dynstr
    ///  0x120  .rela.dyn (duas R_X86_64_RELATIVE) 0x200  .text, a entrada
    /// 0x1000  .dynamic                          0x1080 .data
    /// 0x1090  .bss (só na memória); .comment, .debug_str, .symtab, .strtab,
    ///         .shstrtab; e a tabela de seções
    /// ```
    fn elf_de_mentira() -> Vec<u8> {
        let mut b = vec![0u8; 0x1090];
        // As relocações: R_X86_64_RELATIVE (8), de `.data` para `.text`.
        for (i, (onde, adendo)) in [(0x1080u64, 0x200u64), (0x1088, 0x208)].iter().enumerate() {
            let entrada = [onde.to_le_bytes(), 8u64.to_le_bytes(), adendo.to_le_bytes()].concat();
            por(&mut b, 0x120 + 24 * i, &entrada);
        }
        // O `.text`: nops e um `ret`.
        por(&mut b, 0x200, &[0x90; 15]);
        b[0x20F] = 0xC3;
        // A seção dinâmica: DT_RELA, DT_RELASZ, DT_RELAENT, DT_SYMTAB,
        // DT_SYMENT, DT_STRTAB, DT_STRSZ e DT_NULL.
        let dinamica: [(u64, u64); 8] = [
            (7, 0x120),
            (8, 48),
            (9, 24),
            (6, 0x100),
            (11, 24),
            (5, 0x118),
            (10, 1),
            (0, 0),
        ];
        for (i, (etiqueta, valor)) in dinamica.iter().enumerate() {
            let par = [etiqueta.to_le_bytes(), valor.to_le_bytes()].concat();
            por(&mut b, 0x1000 + 16 * i, &par);
        }

        // Fora dos segmentos: o que o `--strip-all` tira, e os nomes das
        // seções, que ficam.
        let comentario: &[u8] = b"Linker: de mentira\0";
        let dwarf: &[u8] = b"o dwarf de mentira\0";
        // O símbolo nulo, e o `_start`: nome 1, global e função (0x12), no
        // `.text` (a seção 4), de 16 bytes.
        let simbolos = [
            [0u8; 24].to_vec(),
            juntos(&[
                &1u32.to_le_bytes(),
                &[0x12, 0],
                &4u16.to_le_bytes(),
                &0x200u64.to_le_bytes(),
                &16u64.to_le_bytes(),
            ]),
        ]
        .concat();
        let nomes_dos_simbolos: &[u8] = b"\0_start\0";
        let mut nomes = vec![0u8];
        let mut nome_de = Vec::new();
        for s in [
            ".dynsym",
            ".dynstr",
            ".rela.dyn",
            ".text",
            ".dynamic",
            ".data",
            ".bss",
            ".comment",
            ".debug_str",
            ".symtab",
            ".strtab",
            ".shstrtab",
        ] {
            nome_de.push(nomes.len() as u32);
            nomes.extend_from_slice(s.as_bytes());
            nomes.push(0);
        }
        let comentario_em = b.len() as u64;
        b.extend_from_slice(comentario);
        let dwarf_em = b.len() as u64;
        b.extend_from_slice(dwarf);
        b.resize(b.len().next_multiple_of(8), 0);
        let simbolos_em = b.len() as u64;
        b.extend_from_slice(&simbolos);
        let nomes_dos_simbolos_em = b.len() as u64;
        b.extend_from_slice(nomes_dos_simbolos);
        let nomes_em = b.len() as u64;
        b.extend_from_slice(&nomes);
        b.resize(b.len().next_multiple_of(8), 0);

        // A tabela de seções: a nula, e as doze, como o `llvm-readobj -S`
        // as mostra — tipo, marcas, endereço, deslocamento, tamanho,
        // ligada, informação, alinhamento e entrada.
        let tabela_de_secoes = b.len() as u64;
        let secoes = [
            (
                11u32, 2u64, 0x100u64, 0x100u64, 24u64, 2u32, 1u32, 8u64, 24u64,
            ),
            (3, 2, 0x118, 0x118, 1, 0, 0, 1, 0),
            (4, 2, 0x120, 0x120, 48, 1, 0, 8, 24),
            (1, 6, 0x200, 0x200, 16, 0, 0, 16, 0),
            (6, 3, 0x1000, 0x1000, 128, 2, 0, 8, 16),
            (1, 3, 0x1080, 0x1080, 16, 0, 0, 8, 0),
            (8, 3, 0x1090, 0x1090, 0x100, 0, 0, 16, 0),
            (
                1,
                0x30,
                0,
                comentario_em,
                comentario.len() as u64,
                0,
                0,
                1,
                1,
            ),
            (1, 0x30, 0, dwarf_em, dwarf.len() as u64, 0, 0, 1, 1),
            (2, 0, 0, simbolos_em, simbolos.len() as u64, 11, 1, 8, 24),
            (
                3,
                0,
                0,
                nomes_dos_simbolos_em,
                nomes_dos_simbolos.len() as u64,
                0,
                0,
                1,
                0,
            ),
            (3, 0, 0, nomes_em, nomes.len() as u64, 0, 0, 1, 0),
        ];
        b.extend_from_slice(&[0u8; 64]);
        for ((tipo, marcas, endereco, em, tamanho, ligada, info, alinhamento, entrada), nome) in
            secoes.iter().zip(&nome_de)
        {
            b.extend_from_slice(&juntos(&[
                &nome.to_le_bytes(),
                &tipo.to_le_bytes(),
                &marcas.to_le_bytes(),
                &endereco.to_le_bytes(),
                &em.to_le_bytes(),
                &tamanho.to_le_bytes(),
                &ligada.to_le_bytes(),
                &info.to_le_bytes(),
                &alinhamento.to_le_bytes(),
                &entrada.to_le_bytes(),
            ]));
        }

        // Os programas, em 0x40: o de código (RX), o de dados (RW, com o
        // `.bss` além do arquivo) e o dinâmico — tipo, marcas, deslocamento
        // (que é também o endereço), no arquivo, na memória e alinhamento.
        let programas: [(u32, u32, u64, u64, u64, u64); 3] = [
            (1, 5, 0, 0x210, 0x210, 0x1000),
            (1, 6, 0x1000, 0x90, 0x190, 0x1000),
            (2, 6, 0x1000, 0x80, 0x80, 8),
        ];
        for (i, (tipo, marcas, em, arquivo, memoria, alinhamento)) in programas.iter().enumerate() {
            let p = juntos(&[
                &tipo.to_le_bytes(),
                &marcas.to_le_bytes(),
                &em.to_le_bytes(),
                &em.to_le_bytes(),
                &em.to_le_bytes(),
                &arquivo.to_le_bytes(),
                &memoria.to_le_bytes(),
                &alinhamento.to_le_bytes(),
            ]);
            por(&mut b, 0x40 + 56 * i, &p);
        }

        // O cabeçalho: ELF64, LE, versão 1, System V; ET_DYN, x86-64; a
        // entrada no `.text`; os programas em 0x40; as seções no fim, treze,
        // a dos nomes por último.
        let cabecalho = juntos(&[
            b"\x7fELF\x02\x01\x01\x00",
            &[0; 8],
            &3u16.to_le_bytes(),
            &62u16.to_le_bytes(),
            &1u32.to_le_bytes(),
            &0x200u64.to_le_bytes(),
            &0x40u64.to_le_bytes(),
            &tabela_de_secoes.to_le_bytes(),
            &0u32.to_le_bytes(),
            &64u16.to_le_bytes(),
            &56u16.to_le_bytes(),
            &3u16.to_le_bytes(),
            &64u16.to_le_bytes(),
            &13u16.to_le_bytes(),
            &12u16.to_le_bytes(),
        ]);
        por(&mut b, 0, &cabecalho);
        b
    }

    /// O caminho do kernel de verdade, sobre o de mentira: a cópia perde a
    /// tabela de símbolos, o DWARF e o `.comment`; guarda o cabeçalho, os
    /// programas, os bytes de cada `PT_LOAD` — as duas relocações e a seção
    /// dinâmica entre eles — e as seções carregáveis; e o ELF de origem, o
    /// da simbolização, não muda.
    #[test]
    fn a_copia_do_slot_perde_os_simbolos_e_guarda_o_que_o_iniciador_carrega() {
        let dir = diretorio("copia");
        let elf = dir.join("duke");
        let origem = elf_de_mentira();
        std::fs::write(&elf, &origem).unwrap();
        let copia = crate::kernel_para_a_esp(&elf).unwrap();
        assert_eq!(copia, dir.join("duke.esp.elf"));
        assert_eq!(std::fs::read(&elf).unwrap(), origem);
        let bytes = std::fs::read(&copia).unwrap();
        assert_eq!(
            conferir_a_copia(&origem, &bytes),
            Ok(Conferida {
                segmentos: 2,
                relocacoes: 2
            })
        );
        assert!(bytes.len() < origem.len());
        let nomes: Vec<String> = Elf::ler(&bytes, "a cópia")
            .unwrap()
            .secoes()
            .unwrap()
            .into_iter()
            .map(|s| s.nome)
            .collect();
        for tirada in [".symtab", ".strtab", ".comment", ".debug_str"] {
            assert!(!nomes.iter().any(|n| n == tirada), "{tirada} em {nomes:?}");
        }
        for ficou in [
            ".dynsym",
            ".dynstr",
            ".rela.dyn",
            ".text",
            ".dynamic",
            ".data",
            ".bss",
            ".shstrtab",
        ] {
            assert!(
                nomes.iter().any(|n| n == ficou),
                "{ficou} fora de {nomes:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A conferência roda em cada cópia, e recusa a que não serve, pelo
    /// motivo: a do `--strip-debug` de antes, que guarda a tabela de
    /// símbolos; a que tira também as relocações, ou a seção dinâmica — o
    /// `llvm-objcopy` zera os bytes delas no segmento, e o iniciador
    /// aplicaria relocações de tipo zero, ou nenhuma —; a que tira a tabela
    /// de seções inteira; a que guarda uma seção que nada carrega; e a que
    /// descreve outra seção carregável.
    #[test]
    fn a_copia_que_nao_serve_e_recusada_pelo_motivo() {
        let dir = diretorio("recusas");
        let elf = dir.join("duke");
        std::fs::write(&elf, elf_de_mentira()).unwrap();
        for (opcoes, motivo) in [
            (&["--strip-debug"][..], "a tabela de símbolos (.symtab)"),
            (
                &["--strip-all", "--remove-section=.rela.dyn"][..],
                "o segmento 0 (PT_LOAD em 0x0) mudou no byte 0x120",
            ),
            (
                &["--strip-all", "--remove-section=.dynamic"][..],
                "o segmento 1 (PT_LOAD em 0x1000) mudou no byte 0x1000",
            ),
            (&["--strip-sections"][..], "tabela de seções"),
            (
                &["--strip-all", "--keep-section=.comment"][..],
                ".comment, que nada carrega",
            ),
            (
                &["--strip-all", "--rename-section=.data=.dados"][..],
                "as seções carregáveis mudaram",
            ),
        ] {
            let r = copiar(&elf, opcoes);
            assert!(
                r.as_ref().is_err_and(|e| e.contains(motivo)),
                "{opcoes:?}: {r:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A conferência sozinha, sobre bytes trocados à mão: o motivo é o do
    /// que mudou — a tabela de símbolos que ficou, um byte num segmento, um
    /// cabeçalho de programa, a entrada, a tabela de seções que falta, a
    /// tabela de relocações fora dos segmentos ou de outro formato, um
    /// arquivo cortado.
    #[test]
    fn a_conferencia_aponta_o_que_mudou() {
        let origem = elf_de_mentira();
        let recusa = |copia: &[u8], motivo: &str| {
            let r = conferir_a_copia(&origem, copia);
            assert!(
                r.as_ref().is_err_and(|e| e.contains(motivo)),
                "{motivo}: {r:?}"
            );
        };
        let trocado = |em: usize, valor: u8| {
            let mut c = origem.clone();
            c[em] = valor;
            c
        };
        // Sem cópia nenhuma: tudo igual, com a tabela de símbolos.
        recusa(&origem, "a tabela de símbolos (.symtab)");
        // A primeira relocação, de outro tipo: 0x128 é o tipo dela.
        recusa(
            &trocado(0x128, 0),
            "o segmento 0 (PT_LOAD em 0x0) mudou no byte 0x128",
        );
        // O `.data`, no segmento de dados.
        recusa(
            &trocado(0x1085, 1),
            "o segmento 1 (PT_LOAD em 0x1000) mudou no byte 0x1085",
        );
        // O tamanho na memória do segmento de dados: o `.bss` encolhe.
        recusa(
            &trocado(0x40 + 56 + 40, 0x80),
            "os cabeçalhos de programa mudaram",
        );
        // A entrada.
        recusa(&trocado(24, 1), "o cabeçalho ELF mudou");
        // Sem a tabela de seções, com o `e_shentsize` de pé — o que o
        // `--strip-sections` não faz: ele zera o tamanho também, e cai no
        // cabeçalho. A recusa diz o motivo, e não só que as seções mudaram.
        let mut sem_secoes = origem.clone();
        por(&mut sem_secoes, 40, &0u64.to_le_bytes());
        por(&mut sem_secoes, 60, &0u16.to_le_bytes());
        recusa(&sem_secoes, "a cópia não tem a tabela de seções");
        // Cortada no meio do segmento de dados.
        recusa(&origem[..0x1040], "passam do fim do arquivo");

        // A tabela de relocações fora dos segmentos, ou em entradas de outro
        // tamanho — nos dois arquivos, que continuam iguais: o iniciador não
        // a acharia, ou a leria com o passo errado.
        for (em, valor, motivo) in [
            (
                0x1008,
                0x5000u64,
                "não está inteira num segmento carregável",
            ),
            (0x1028, 16, "em entradas de 16"),
        ] {
            let mut torta = origem.clone();
            por(&mut torta, em, &valor.to_le_bytes());
            let r = conferir_a_copia(&torta, &torta);
            assert!(
                r.as_ref().is_err_and(|e| e.contains(motivo)),
                "{motivo}: {r:?}"
            );
        }
    }

    /// A tabela de relocações e os cabeçalhos de programa como o iniciador os
    /// lê (`iniciador/src/elf.rs`): a seção dinâmica acaba no primeiro
    /// `DT_NULL`, e o que vem depois dele não conta; a tabela é um número
    /// inteiro de entradas; ela pode começar no começo exato de um segmento e
    /// acabar no fim exato dos bytes dele no arquivo, e não um byte antes nem
    /// um depois. E cabeçalhos de programa de 64 bytes são recusados: o
    /// iniciador anda pela tabela com o `e_phentsize` do arquivo, e a
    /// conferência compara a tabela com o passo do ELF64 — com outro passo,
    /// ela não compararia o que o iniciador lê.
    #[test]
    fn a_tabela_de_relocacoes_e_os_programas_como_o_iniciador_os_le() {
        let origem = elf_de_mentira();
        // Os pares da seção dinâmica, a partir de 0x1000: o `DT_RELA` é o
        // primeiro, e o `DT_RELASZ`, o segundo.
        let com = |pares: &[(usize, u64, u64)]| {
            let mut b = origem.clone();
            for &(i, etiqueta, valor) in pares {
                let par = [etiqueta.to_le_bytes(), valor.to_le_bytes()].concat();
                por(&mut b, 0x1000 + 16 * i, &par);
            }
            b
        };
        let contadas = |b: &[u8]| {
            let elf = Elf::ler(b, "o ELF").unwrap();
            elf.relocacoes(&elf.programas().unwrap())
        };
        assert_eq!(contadas(&origem), Ok(2));
        // Um `DT_NULL` no quarto par, e depois dele um `DT_RELA` fora dos
        // segmentos: o iniciador para no `DT_NULL`, e a conferência também.
        assert_eq!(
            contadas(&com(&[(3, DT_NULL, 0), (4, DT_RELA, 0x5000)])),
            Ok(2)
        );
        // 50 bytes em entradas de 24: duas e um pedaço.
        let r = contadas(&com(&[(1, DT_RELASZ, 50)]));
        assert!(
            r.as_ref()
                .is_err_and(|e| e.contains("50 bytes em entradas de 24")),
            "{r:?}"
        );
        // Os limites, com as 48 bytes da tabela: o segmento de código tem
        // 0x210 bytes no arquivo a partir de 0, e o de dados, 0x90 a partir
        // de 0x1000.
        for (onde, inteira) in [
            (0x1000u64, true),
            (0xFFF, false),
            (0x210 - 48, true),
            (0x210 - 47, false),
        ] {
            let r = contadas(&com(&[(0, DT_RELA, onde)]));
            let esperado = if inteira {
                Ok(2)
            } else {
                Err(format!(
                    "a tabela de relocações, em {onde:#x}, não está inteira num segmento carregável"
                ))
            };
            assert_eq!(r, esperado, "{onde:#x}");
        }
        // Os cabeçalhos de programa de 64 bytes, nos dois arquivos.
        let mut largos = origem.clone();
        por(&mut largos, 54, &64u16.to_le_bytes());
        let r = conferir_a_copia(&largos, &largos);
        assert!(
            r.as_ref().is_err_and(|e| e.contains(
                "o ELF de origem tem cabeçalhos de programa de 64 bytes, e os do ELF64 têm 56"
            )),
            "{r:?}"
        );
    }

    /// No cabeçalho, só os três campos da tabela de seções podem mudar: com
    /// eles trocados, o cabeçalho e o começo do primeiro segmento conferem;
    /// com o `e_shentsize`, que a cópia não muda, não.
    #[test]
    fn so_os_campos_da_tabela_de_secoes_mudam_no_cabecalho() {
        let a = elf_de_mentira();
        let mut b = a.clone();
        for em in [40, 47, 60, 61, 62, 63] {
            b[em] ^= 0xFF;
        }
        assert_eq!(sem_os_campos_das_secoes(&a), sem_os_campos_das_secoes(&b));
        assert_eq!(primeira_diferenca(&a[..0x210], &b[..0x210], 0), None);
        b[58] ^= 0xFF;
        assert_ne!(sem_os_campos_das_secoes(&a), sem_os_campos_das_secoes(&b));
        assert_eq!(primeira_diferenca(&a[..0x210], &b[..0x210], 0), Some(58));
    }
}
