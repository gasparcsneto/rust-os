//! O incidente de uma máquina que parou de andar: o estado de todas as CPUs,
//! guardado e simbolizado com o ELF exato que ela roda — o que
//! [`super::persistencia`] acrescenta ao diagnóstico do boot que não atende.
//!
//! # Por que
//!
//! Na CI 492, um boot da bancada da atualização (x86_64) parou no meio do
//! handler de pânico: a serial com a primeira linha dele, em branco, e não
//! a segunda. O diagnóstico só tinha endereços — a CPU#0 girando em
//! `ffff8000002a7c9f`, com as interrupções desligadas, e as outras três num
//! `hlt` em `ffff8000003d869d` —, e o ELF daquela execução não existia mais
//! fora do runner. Uma compilação local põe as funções em outros lugares: o
//! mesmo `0x3d869d`, aqui, cai num `int3` de enchimento. O endereço sozinho
//! não dizia nada.
//!
//! # O que se guarda
//!
//! Em `target/incidentes/<instante>-<bancada>-<arquitetura>-<n>/`:
//!
//! - `resumo.txt`: o cenário e o motivo; o kernel — o ELF, o SHA-256 dele,
//!   como foi compilado e a conferência na memória —; cada CPU — o
//!   endereço, o endereço no ELF, a função e a linha, as interrupções, o
//!   `hlt` e os retornos na pilha —; alguns estáticos do kernel; a UART; e
//!   onde o boot estava, pela serial;
//! - `registradores.txt`: o `info registers -a` inteiro;
//! - `desmontagem.txt`: o código em volta de cada endereço, com as linhas;
//! - `monitor.txt`: o que o monitor do emulador diz dos controladores — o
//!   APIC de cada CPU, o PIC, as interrupções, a UART;
//! - `serial.txt`: a serial humana do cenário até ali.
//!
//! E o ELF, uma vez por kernel, em `target/incidentes/kernels/`, com o
//! começo do SHA-256 no nome (16 dígitos): com ele, `cargo xtask simbolo
//! --elf` traduz depois qualquer outro endereço, sem recompilar nada — com
//! o `llvm-symbolizer` do sistema, que o componente `llvm-tools` não traz.
//! Na CI, o job que reprova sobe `target/incidentes/` como artefato.
//!
//! # O ELF exato
//!
//! O kernel que a bancada sobe é a cópia sem símbolos de um ELF que este
//! mesmo processo compilou — `kernel_do_slot` confere, byte a byte, que os
//! segmentos são os mesmos. Cada compilação fica registrada aqui
//! ([`registrar_o_kernel`]), e o incidente procura, entre as desta execução
//! e da arquitetura da máquina, a que **está na memória**: o código de cada
//! segmento executável, lido da máquina parada, igual ao do arquivo, com as
//! relocações aplicadas como o iniciador as aplica; e, no x86, o cabeçalho
//! ELF e os cabeçalhos de programa na base do kernel. Sem nenhuma que
//! confira, o incidente diz isso e não simboliza: um nome de função tirado
//! de outro binário é pior que nenhum.
//!
//! Os símbolos e as linhas saem do `llvm-nm` e do `llvm-objdump` do
//! componente `llvm-tools` do `rust-toolchain.toml` — os que todo runner
//! tem. O `llvm-symbolizer` não vem nele (ver [`super::ferramenta_llvm`]),
//! e a CI não instala o do sistema.
//!
//! # O que não faz
//!
//! Lê a máquina já parada, pelo monitor do emulador, do lado do hospedeiro,
//! depois que a bancada desistiu dela — ou, no cenário que confere este
//! módulo, parada de propósito e solta em seguida. Não existe no kernel, no
//! iniciador nem numa imagem: é código do `xtask`, e não abre caminho
//! nenhum para dentro da máquina. Não guarda a memória dela: da pilha, só
//! os retornos que caem no código do kernel — os valores que caem num
//! segmento executável logo depois de uma chamada: uma leitura de bancada,
//! sem tabela de desenrolar, em que um retorno velho que ficou na pilha
//! também aparece —, e, no x86, os quadros de interrupção; dos estáticos,
//! só os de [`ESTATICOS`] — travas, marcas e contadores da serial, dos
//! núcleos, da parada, do escalonador, dos dormentes, do relógio e dos
//! slots. A única leitura com efeito é a do LSR da UART
//! do x86, que limpa as marcas de erro dela (`OE` e `BI`), como a mesma
//! leitura feita pelo kernel.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use protocolo::json::{Json, JsonWriter};
use sha2::{Digest, Sha256};

use super::Arquitetura;
use super::firmware::Memoria;

/// Quanto da pilha de cada CPU se olha, a partir do topo.
const PILHA_DO_KERNEL: usize = 32 << 10;

/// Quantos retornos da pilha de cada CPU o incidente guarda.
const RETORNOS_DO_KERNEL: usize = 24;

/// Quantos retornos de cada CPU o resumo da saída mostra.
const RETORNOS_NO_RESUMO: usize = 8;

/// Quantas instruções antes e depois do endereço a desmontagem mostra.
const INSTRUCOES_ANTES: usize = 24;
const INSTRUCOES_DEPOIS: usize = 8;

/// Quantos bytes do fim da serial o resumo mostra, escapados — o último
/// sinal da máquina, byte a byte.
const ULTIMOS_BYTES: usize = 240;

/// Quantas linhas do fim da serial o `resumo.txt` repete.
const LINHAS_DA_SERIAL: usize = 60;

/// O maior estático que se lê, e quanto dele.
const MAIOR_ESTATICO: u64 = 4096;
const BYTES_DE_UM_ESTATICO: usize = 64;

/// Os estáticos do kernel que o incidente lê, pelo começo do nome: as
/// travas, as marcas e os contadores do caminho que imprime e que para —
/// a serial, os núcleos, a parada por NMI, o escalonador congelado, os
/// slots da atualização —, e as duas travas que o tique do núcleo dos
/// dispositivos toma, a do escalonador e a dos dormentes, com o relógio.
/// Uma trava (`trava::Mutex`) tem a próxima senha e o painel nas duas
/// primeiras palavras no kernel de hoje — a ordem é a do compilador, sem
/// `#[repr(C)]`, e as palavras se guardam como estão. Nenhum guarda
/// segredo.
pub(crate) const ESTATICOS: &[&str] = &[
    "duke::serial::",
    "duke::nucleos::",
    "duke::arch::x86_64::smp::",
    "duke::arch::aarch64::smp::",
    "duke::fios::CONGELADO",
    "duke::fios::LIGADO",
    "duke::fios::TROCAS",
    "duke::fios::ESCALONADOR",
    "duke::tarefas::relogio::DORMENTES",
    "duke::tempo::TICKS",
    "duke::slots::",
];

/// `PT_LOAD`, `PT_DYNAMIC` e a marca de execução de um segmento.
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;

/// As etiquetas da seção dinâmica que dizem onde estão as relocações.
const DT_NULL: u64 = 0;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;

/// As relocações relativas — as únicas que o iniciador aplica.
const R_X86_64_RELATIVE: u32 = 8;
const R_AARCH64_RELATIVE: u32 = 1027;

// ---------------------------------------------------------------------------
// Os kernels desta execução e o cenário
// ---------------------------------------------------------------------------

/// Um kernel que este processo compilou: onde, como, e o arquivo logo
/// depois — para o incidente saber se ele ainda é o da compilação.
#[derive(Clone, Debug)]
struct Compilado {
    arch: Arquitetura,
    elf: PathBuf,
    /// O perfil e as features, para o relatório.
    como: String,
    tamanho: u64,
    modificado: Option<SystemTime>,
}

/// Os kernels compilados por este processo, do mais velho ao mais novo.
static COMPILADOS: Mutex<Vec<Compilado>> = Mutex::new(Vec::new());

/// O cenário que roda agora: a bancada e o nome.
static CENARIO: Mutex<Option<(String, String)>> = Mutex::new(None);

/// O número do incidente seguinte nesta execução.
static INCIDENTES: AtomicU32 = AtomicU32::new(0);

/// Registra o kernel que [`super::compilar_o_kernel`] acaba de pôr em
/// `elf`. Um ELF no mesmo caminho de antes o substitui: o arquivo velho
/// não existe mais.
pub(crate) fn registrar_o_kernel(arch: Arquitetura, release: bool, features: &[&str], elf: &Path) {
    let meta = std::fs::metadata(elf).ok();
    let como = format!(
        "{}{}",
        if release { "release" } else { "depuracao" },
        if features.is_empty() {
            String::new()
        } else {
            format!(", features {}", features.join(","))
        }
    );
    let novo = Compilado {
        arch,
        elf: elf.to_path_buf(),
        como,
        tamanho: meta.as_ref().map_or(0, std::fs::Metadata::len),
        modificado: meta.and_then(|m| m.modified().ok()),
    };
    if let Ok(mut lista) = COMPILADOS.lock() {
        lista.retain(|c| c.elf != novo.elf);
        lista.push(novo);
    }
}

thread_local! {
    /// Quem espera um boot que pode não atender, de propósito — ver
    /// [`sem_incidente`].
    static SEM_INCIDENTE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `f`, sem incidente para a máquina que não atender dentro dela: o boot
/// que pode não atender de propósito — o disco cortado no meio da subida,
/// na bancada da identidade — não é uma falha, e o incidente dele seria só
/// tempo e ruído no artefato de uma falha de verdade.
pub(crate) fn sem_incidente<R>(f: impl FnOnce() -> R) -> R {
    let antes = SEM_INCIDENTE.replace(true);
    let r = f();
    SEM_INCIDENTE.set(antes);
    r
}

/// Se o incidente de uma máquina parada agora se guarda — ver
/// [`sem_incidente`].
pub(crate) fn guardar_agora() -> bool {
    !SEM_INCIDENTE.get()
}

/// O cenário que começa: o incidente de uma máquina dele leva o nome.
pub(crate) fn no_cenario(bancada: &str, nome: &str) {
    if let Ok(mut cenario) = CENARIO.lock() {
        *cenario = Some((bancada.to_string(), nome.to_string()));
    }
}

/// Onde ficam os incidentes: `target/incidentes/`, na raiz do projeto — e
/// não na raiz da máquina, que é por fio (ver [`super::na_raiz`]).
pub(crate) fn raiz_dos_incidentes() -> PathBuf {
    super::raiz_do_projeto().join("target").join("incidentes")
}

// ---------------------------------------------------------------------------
// O emulador
// ---------------------------------------------------------------------------

/// O emulador de uma máquina parada: a memória, pelas tabelas de páginas de
/// cada CPU, e o monitor humano.
pub(crate) trait Emulador: Memoria {
    /// O texto que o monitor responde a `comando`.
    fn monitor(&mut self, comando: &str) -> Result<String, String>;
}

impl Emulador for super::firmware::MemoriaPeloQmp<'_> {
    fn monitor(&mut self, comando: &str) -> Result<String, String> {
        if self.quebrado {
            return Err("o QMP deixou de responder no prazo, e nao se pergunta mais nada".into());
        }
        let pedido = pedido_ao_monitor(comando)
            .ok_or_else(|| "o pedido ao monitor nao se escreveu".to_string())?;
        let resposta = super::qmp_pedir(self.escrita, self.leitor, &pedido);
        self.quebrado = resposta.is_err();
        texto_do_monitor(&resposta?)
    }
}

/// O pedido do QMP que leva `comando` ao monitor humano.
fn pedido_ao_monitor(comando: &str) -> Option<String> {
    let mut pedido = String::new();
    let mut j = JsonWriter::new(&mut pedido);
    j.begin_object().ok()?;
    j.field_str("execute", "human-monitor-command").ok()?;
    j.key("arguments").ok()?;
    j.begin_object().ok()?;
    j.field_str("command-line", comando).ok()?;
    j.end_object().ok()?;
    j.end_object().ok()?;
    Some(pedido)
}

/// O texto de uma resposta do monitor pelo QMP — `{"return": "..."}` —,
/// desescapado e sem os retornos de carro; um erro, com o que veio.
pub(crate) fn texto_do_monitor(resposta: &str) -> Result<String, String> {
    let json = Json(resposta.trim().as_bytes());
    let Some(retorno) = json.member("return") else {
        return Err(format!("o monitor recusou: {}", resposta.trim()));
    };
    let mut destino = vec![0u8; retorno.0.len()];
    retorno
        .desescapar_em(&mut destino)
        .map(|t| t.replace('\r', ""))
        .ok_or_else(|| format!("a resposta do monitor nao e texto: {}", resposta.trim()))
}

// ---------------------------------------------------------------------------
// Os registradores
// ---------------------------------------------------------------------------

/// Uma CPU, pelo `info registers -a`: o número e cada `NOME=valor`, como
/// vieram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cpu {
    pub(crate) numero: u32,
    pub(crate) campos: Vec<(String, String)>,
}

impl Cpu {
    pub(crate) fn campo(&self, nome: &str) -> Option<&str> {
        self.campos
            .iter()
            .find(|(n, _)| n == nome)
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn numero_de(&self, nome: &str) -> Option<u64> {
        u64::from_str_radix(self.campo(nome)?, 16).ok()
    }

    /// O endereço da instrução: o `RIP` no x86, o `PC` no ARM.
    pub(crate) fn instrucao(&self) -> Option<u64> {
        self.numero_de("RIP").or_else(|| self.numero_de("PC"))
    }

    /// O topo da pilha: o `RSP` no x86, o `SP` no ARM.
    pub(crate) fn pilha(&self) -> Option<u64> {
        self.numero_de("RSP").or_else(|| self.numero_de("SP"))
    }
}

/// As CPUs de `registros` — o `info registers -a`, com as quebras de linha
/// como vêm, escapadas ou não. Cada `NOME=valor`, e o `R8 =valor` do x86,
/// com o espaço antes do igual.
pub(crate) fn cpus(registros: &str) -> Vec<Cpu> {
    let texto = registros.replace("\\r", "").replace("\\n", "\n");
    let mut lista: Vec<Cpu> = Vec::new();
    for linha in texto.lines() {
        let palavras: Vec<&str> = linha
            .split_whitespace()
            .map(|p| p.trim_matches(|c: char| c == '"' || c == '{' || c == '}'))
            .collect();
        let mut i = 0;
        while i < palavras.len() {
            let palavra = palavras[i];
            i += 1;
            if let Some(n) = palavra.strip_prefix("CPU#") {
                if let Ok(numero) = n.trim_end_matches(':').parse() {
                    lista.push(Cpu {
                        numero,
                        campos: Vec::new(),
                    });
                }
                continue;
            }
            let Some(cpu) = lista.last_mut() else {
                continue;
            };
            let (nome, valor) = match palavra.split_once('=') {
                Some((nome, valor)) if !nome.is_empty() => (nome, valor),
                None if palavras.get(i).is_some_and(|p| p.starts_with('=')) => {
                    i += 1;
                    (palavra, &palavras[i - 1][1..])
                }
                _ => continue,
            };
            if valor.is_empty()
                || !nome.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                || cpu.campos.iter().any(|(n, _)| n == nome)
            {
                continue;
            }
            cpu.campos.push((nome.to_string(), valor.to_string()));
        }
    }
    lista
}

/// As marcas do `RFLAGS` que estão ligadas, pelos nomes.
pub(crate) fn bandeiras_do_x86(rfl: u64) -> String {
    const NOMES: [(u64, &str); 9] = [
        (0x1, "CF"),
        (0x4, "PF"),
        (0x10, "AF"),
        (0x40, "ZF"),
        (0x80, "SF"),
        (0x100, "TF"),
        (0x200, "IF"),
        (0x400, "DF"),
        (0x800, "OF"),
    ];
    let ligadas: Vec<&str> = NOMES
        .iter()
        .filter(|(b, _)| rfl & b != 0)
        .map(|(_, n)| *n)
        .collect();
    if ligadas.is_empty() {
        "nenhuma".to_string()
    } else {
        ligadas.join(" ")
    }
}

/// O estado de uma CPU, em palavras: as interrupções, o `hlt`, o anel ou o
/// nível de exceção.
pub(crate) fn estado_da_cpu(arch: Arquitetura, cpu: &Cpu) -> String {
    let mut partes: Vec<String> = Vec::new();
    match arch {
        Arquitetura::X86_64 => {
            if let Some(rfl) = cpu.numero_de("RFL") {
                partes.push(
                    if rfl & 0x200 != 0 {
                        "interrupcoes ligadas"
                    } else {
                        "interrupcoes desligadas"
                    }
                    .to_string(),
                );
                partes.push(format!("RFL={rfl:#x} [{}]", bandeiras_do_x86(rfl)));
            }
            match cpu.campo("HLT") {
                Some("1") => partes.push("parada num hlt".into()),
                Some("0") => partes.push("fora de hlt".into()),
                _ => {}
            }
            if let Some(cpl) = cpu.campo("CPL") {
                partes.push(format!("anel {cpl}"));
            }
            if cpu.campo("SMM") == Some("1") {
                partes.push("no SMM".into());
            }
        }
        Arquitetura::Aarch64 => {
            if let Some(pstate) = cpu.numero_de("PSTATE") {
                let mascaradas: Vec<&str> = [(9, "D"), (8, "A"), (7, "I"), (6, "F")]
                    .iter()
                    .filter(|(b, _)| (pstate >> b) & 1 == 1)
                    .map(|(_, n)| *n)
                    .collect();
                partes.push(
                    if (pstate >> 7) & 1 == 1 {
                        "IRQ mascaradas"
                    } else {
                        "IRQ ligadas"
                    }
                    .to_string(),
                );
                partes.push(format!(
                    "PSTATE={pstate:#x} [DAIF mascaradas: {}], EL{}",
                    if mascaradas.is_empty() {
                        "nenhuma".to_string()
                    } else {
                        mascaradas.join("")
                    },
                    (pstate >> 2) & 3
                ));
            }
        }
    }
    partes.join(", ")
}

// ---------------------------------------------------------------------------
// O ELF
// ---------------------------------------------------------------------------

/// Um cabeçalho de programa.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Segmento {
    pub(crate) tipo: u32,
    pub(crate) marcas: u32,
    pub(crate) no_arquivo: u64,
    pub(crate) endereco: u64,
    pub(crate) do_arquivo: u64,
    pub(crate) na_memoria: u64,
}

impl Segmento {
    fn contem(&self, endereco: u64) -> bool {
        endereco >= self.endereco && endereco - self.endereco < self.na_memoria
    }

    fn executavel(&self) -> bool {
        self.tipo == PT_LOAD && self.marcas & PF_X != 0
    }
}

/// Uma relocação `Elf64_Rela`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Relocacao {
    pub(crate) onde: u64,
    pub(crate) tipo: u32,
    pub(crate) parcela: i64,
}

/// O ELF do kernel, no que o incidente usa: os segmentos, a tabela de
/// cabeçalhos de programa e as relocações.
pub(crate) struct Elf {
    pub(crate) bytes: Vec<u8>,
    pub(crate) segmentos: Vec<Segmento>,
    /// A tabela de cabeçalhos de programa: o começo e o tamanho no arquivo.
    pub(crate) programas: (u64, u64),
    pub(crate) relocacoes: Vec<Relocacao>,
}

fn u16_em(b: &[u8], i: u64) -> Option<u16> {
    let i = usize::try_from(i).ok()?;
    Some(u16::from_le_bytes(
        b.get(i..i.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_em(b: &[u8], i: u64) -> Option<u32> {
    let i = usize::try_from(i).ok()?;
    Some(u32::from_le_bytes(
        b.get(i..i.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_em(b: &[u8], i: u64) -> Option<u64> {
    let i = usize::try_from(i).ok()?;
    Some(u64::from_le_bytes(
        b.get(i..i.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// Os `n` bytes de `b` a partir de `de`, se estão todos lá.
fn fatia(b: &[u8], de: u64, n: u64) -> Option<&[u8]> {
    let de = usize::try_from(de).ok()?;
    b.get(de..de.checked_add(usize::try_from(n).ok()?)?)
}

/// Lê `bytes` como um ELF64 little-endian, sem acreditar em nada: toda
/// posição é conferida contra o tamanho antes de virar fatia.
pub(crate) fn ler_elf(bytes: Vec<u8>) -> Result<Elf, String> {
    if bytes.get(..6) != Some(b"\x7fELF\x02\x01".as_slice()) {
        return Err("nao e um ELF64 little-endian".into());
    }
    let curto = || "o cabecalho passa do fim do arquivo".to_string();
    let tabela = u64_em(&bytes, 32).ok_or_else(curto)?;
    if u16_em(&bytes, 54).ok_or_else(curto)? != 56 {
        return Err("os cabecalhos de programa nao tem 56 bytes".into());
    }
    let quantos = u64::from(u16_em(&bytes, 56).ok_or_else(curto)?);
    let mut segmentos = Vec::new();
    for i in 0..quantos {
        let p = tabela.saturating_add(i * 56);
        let campo = |d: u64| u64_em(&bytes, p.saturating_add(d));
        segmentos.push(Segmento {
            tipo: u32_em(&bytes, p).ok_or_else(curto)?,
            marcas: u32_em(&bytes, p.saturating_add(4)).ok_or_else(curto)?,
            no_arquivo: campo(8).ok_or_else(curto)?,
            endereco: campo(16).ok_or_else(curto)?,
            do_arquivo: campo(32).ok_or_else(curto)?,
            na_memoria: campo(40).ok_or_else(curto)?,
        });
    }
    if fatia(&bytes, tabela, quantos * 56).is_none() {
        return Err(curto());
    }
    let relocacoes = relocacoes(&bytes, &segmentos)?;
    Ok(Elf {
        bytes,
        segmentos,
        programas: (tabela, quantos * 56),
        relocacoes,
    })
}

/// O byte do arquivo em que fica o endereço `endereco`, pelos `PT_LOAD`.
fn no_arquivo(segmentos: &[Segmento], endereco: u64) -> Option<u64> {
    segmentos
        .iter()
        .find(|s| s.tipo == PT_LOAD && s.contem(endereco) && endereco - s.endereco < s.do_arquivo)
        .map(|s| s.no_arquivo + (endereco - s.endereco))
}

/// As relocações da tabela que o `PT_DYNAMIC` aponta — nenhuma sem ele, o
/// kernel do ARM, ligado num endereço fixo.
fn relocacoes(bytes: &[u8], segmentos: &[Segmento]) -> Result<Vec<Relocacao>, String> {
    let Some(dinamico) = segmentos.iter().find(|s| s.tipo == PT_DYNAMIC) else {
        return Ok(Vec::new());
    };
    let (mut onde, mut tamanho) = (0, 0);
    for i in 0..dinamico.do_arquivo / 16 {
        let par = dinamico.no_arquivo.saturating_add(16 * i);
        let (Some(etiqueta), Some(valor)) = (u64_em(bytes, par), u64_em(bytes, par + 8)) else {
            return Err("a secao dinamica passa do fim do arquivo".into());
        };
        match etiqueta {
            DT_NULL => break,
            DT_RELA => onde = valor,
            DT_RELASZ => tamanho = valor,
            _ => {}
        }
    }
    if onde == 0 || tamanho == 0 {
        return Ok(Vec::new());
    }
    let inicio = no_arquivo(segmentos, onde)
        .ok_or("a tabela de relocacoes nao esta num segmento carregado")?;
    let tabela = fatia(bytes, inicio, tamanho).ok_or("a tabela de relocacoes passa do fim")?;
    Ok(tabela
        .as_chunks::<24>()
        .0
        .iter()
        .map(|r| Relocacao {
            onde: u64_em(r, 0).unwrap_or(0),
            tipo: u32_em(r, 8).unwrap_or(0),
            parcela: u64_em(r, 16).unwrap_or(0) as i64,
        })
        .collect())
}

impl Elf {
    /// De onde até onde o kernel vai na memória, nos endereços do ELF.
    pub(crate) fn faixa(&self) -> Option<(u64, u64)> {
        let carregados = self.segmentos.iter().filter(|s| s.tipo == PT_LOAD);
        let de = carregados.clone().map(|s| s.endereco).min()?;
        let ate = carregados
            .map(|s| s.endereco.saturating_add(s.na_memoria))
            .max()?;
        Some((de, ate))
    }

    /// O segmento executável que contém `endereco`, um endereço do ELF.
    fn codigo_em(&self, endereco: u64) -> Option<&Segmento> {
        self.segmentos
            .iter()
            .find(|s| s.executavel() && s.contem(endereco) && endereco - s.endereco < s.do_arquivo)
    }

    /// Até `n` bytes do arquivo que acabam no endereço `fim`, do ELF, dentro
    /// do mesmo segmento executável — os que antecedem um retorno.
    fn antes_de(&self, fim: u64, n: u64) -> Option<&[u8]> {
        let s = self.codigo_em(fim.checked_sub(1)?)?;
        let n = n.min(fim - s.endereco);
        fatia(&self.bytes, s.no_arquivo + (fim - s.endereco) - n, n)
    }

    /// Os bytes do segmento `s` como o iniciador os deixa na memória com o
    /// kernel em `base`: os do arquivo, com as relocações relativas
    /// aplicadas; e as posições das que ele não aplicaria, que a
    /// comparação não olha.
    fn como_na_memoria(&self, s: &Segmento, base: u64) -> Option<(Vec<u8>, Vec<u64>)> {
        let mut bytes = fatia(&self.bytes, s.no_arquivo, s.do_arquivo)?.to_vec();
        let mut ignorados = Vec::new();
        for r in &self.relocacoes {
            if r.onde < s.endereco || r.onde.saturating_add(8) > s.endereco + s.do_arquivo {
                continue;
            }
            let i = (r.onde - s.endereco) as usize;
            if matches!(r.tipo, R_X86_64_RELATIVE | R_AARCH64_RELATIVE) {
                let valor = base.wrapping_add(r.parcela as u64);
                bytes[i..i + 8].copy_from_slice(&valor.to_le_bytes());
            } else {
                ignorados.push(r.onde - s.endereco);
            }
        }
        Some((bytes, ignorados))
    }
}

/// O que a leitura da memória disse de um ELF candidato.
#[derive(Debug, Default)]
pub(crate) struct Conferencia {
    /// Uma linha por coisa conferida.
    pub(crate) linhas: Vec<String>,
    /// Tudo confere, e algum código foi comparado.
    pub(crate) confere: bool,
    /// Quantos bytes de código se compararam.
    pub(crate) codigo: u64,
}

/// Lê `n` bytes da memória em `endereco`, pela primeira CPU de `cpus` que
/// consegue — uma CPU num processo pode não ter o mapa que outra tem.
fn ler_por_alguma(
    memoria: &mut dyn Memoria,
    cpus: &[u32],
    endereco: u64,
    n: usize,
) -> Option<Vec<u8>> {
    cpus.iter().find_map(|&cpu| memoria.ler(cpu, endereco, n))
}

/// Confere, pela memória da máquina parada, que `elf` é o kernel que ela
/// roda com a base `base`: no x86 — onde o primeiro `PT_LOAD` começa no
/// byte 0 do arquivo — o cabeçalho ELF e os cabeçalhos de programa na
/// base; e, nas duas, o código de cada segmento executável igual ao do
/// arquivo com as relocações aplicadas.
pub(crate) fn conferir_na_memoria(
    elf: &Elf,
    base: u64,
    memoria: &mut dyn Memoria,
    cpus: &[u32],
) -> Conferencia {
    let mut c = Conferencia {
        confere: true,
        ..Conferencia::default()
    };
    // O cabeçalho: os campos da tabela de seções mudam na cópia sem
    // símbolos — ver `kernel_do_slot` —, e por isso só o começo dele e os
    // cabeçalhos de programa se comparam.
    if let Some(s) = elf
        .segmentos
        .iter()
        .find(|s| s.tipo == PT_LOAD && s.no_arquivo == 0 && s.do_arquivo >= 64)
    {
        let onde = base.wrapping_add(s.endereco);
        let (tabela, tamanho) = elf.programas;
        let esperado = fatia(&elf.bytes, tabela, tamanho);
        let lido = ler_por_alguma(memoria, cpus, onde, 32).zip(ler_por_alguma(
            memoria,
            cpus,
            onde.wrapping_add(tabela),
            tamanho as usize,
        ));
        match (lido, esperado) {
            (None, _) | (_, None) => {
                c.confere = false;
                c.linhas.push(format!(
                    "o cabecalho ELF na base {onde:#x} nao se le: o kernel nao esta la"
                ));
            }
            (Some((cabecalho, programas)), Some(esperado)) => {
                if cabecalho[..] == elf.bytes[..32] && programas == esperado {
                    c.linhas.push(format!(
                        "o cabecalho ELF e os {} cabecalhos de programa estao na base {onde:#x}, iguais aos do arquivo",
                        tamanho / 56
                    ));
                } else {
                    c.confere = false;
                    c.linhas.push(format!(
                        "na base {onde:#x} nao estao o cabecalho ELF e os cabecalhos de programa deste arquivo"
                    ));
                }
            }
        }
    }
    for s in elf.segmentos.iter().filter(|s| s.executavel()) {
        let onde = base.wrapping_add(s.endereco);
        let Some((esperado, ignorados)) = elf.como_na_memoria(s, base) else {
            c.confere = false;
            c.linhas.push(format!(
                "o segmento de codigo em {:#x} passa do fim do arquivo",
                s.endereco
            ));
            continue;
        };
        let Some(lido) = ler_por_alguma(memoria, cpus, onde, esperado.len()) else {
            c.confere = false;
            c.linhas.push(format!(
                "o codigo em {onde:#x} ({} bytes) nao se le na memoria",
                esperado.len()
            ));
            continue;
        };
        let pulado = |i: usize| {
            ignorados
                .iter()
                .any(|&r| (i as u64) >= r && (i as u64) < r + 8)
        };
        let diferentes: Vec<usize> = lido
            .iter()
            .zip(&esperado)
            .enumerate()
            .filter(|&(i, (a, b))| a != b && !pulado(i))
            .map(|(i, _)| i)
            .collect();
        c.codigo += esperado.len() as u64;
        if diferentes.is_empty() {
            c.linhas.push(format!(
                "o codigo em {onde:#x}: {} bytes iguais aos do arquivo{}",
                esperado.len(),
                if ignorados.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", fora {} relocacoes que o iniciador nao aplica",
                        ignorados.len()
                    )
                }
            ));
        } else {
            c.confere = false;
            c.linhas.push(format!(
                "o codigo em {onde:#x} difere do arquivo em {} de {} bytes, o primeiro em +{:#x}",
                diferentes.len(),
                esperado.len(),
                diferentes[0]
            ));
        }
    }
    if c.codigo == 0 {
        c.confere = false;
    }
    c
}

// ---------------------------------------------------------------------------
// Os símbolos e as linhas
// ---------------------------------------------------------------------------

/// Um símbolo do `llvm-nm -n -S --defined-only --demangle`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Simbolo {
    pub(crate) endereco: u64,
    pub(crate) tamanho: u64,
    pub(crate) tipo: char,
    pub(crate) nome: String,
}

/// A tabela do `llvm-nm`: `endereço [tamanho] tipo nome`, o nome com os
/// espaços que tiver. Fora os símbolos de mapeamento do ARM (`$x`, `$d`) e
/// os rótulos locais do LLVM.
pub(crate) fn ler_a_tabela_do_nm(texto: &str) -> Vec<Simbolo> {
    let hex = |s: &str| u64::from_str_radix(s, 16).ok();
    let mut simbolos = Vec::new();
    for linha in texto.lines() {
        let Some((endereco, resto)) = linha.trim().split_once(' ') else {
            continue;
        };
        let Some(endereco) = hex(endereco) else {
            continue;
        };
        let resto = resto.trim_start();
        let Some((segundo, depois)) = resto.split_once(' ') else {
            continue;
        };
        let (tamanho, resto) = match hex(segundo) {
            Some(t) if segundo.len() > 1 => (t, depois.trim_start()),
            _ => (0, resto),
        };
        let Some((tipo, nome)) = resto.split_once(' ') else {
            continue;
        };
        let mut letras = tipo.chars();
        let (Some(tipo), None) = (letras.next(), letras.next()) else {
            continue;
        };
        let nome = nome.trim();
        if nome.is_empty() || nome.starts_with('$') || nome.starts_with(".L") {
            continue;
        }
        simbolos.push(Simbolo {
            endereco,
            tamanho,
            tipo,
            nome: nome.to_string(),
        });
    }
    simbolos.sort_by_key(|s| s.endereco);
    simbolos
}

/// A função de `funcoes` — ordenadas pelo endereço — que contém
/// `endereco`, e o deslocamento dentro dela.
pub(crate) fn funcao_em(funcoes: &[Simbolo], endereco: u64) -> Option<(&Simbolo, u64)> {
    let i = funcoes.partition_point(|s| s.endereco <= endereco);
    let f = funcoes.get(i.checked_sub(1)?)?;
    let deslocamento = endereco - f.endereco;
    (f.tamanho == 0 || deslocamento < f.tamanho).then_some((f, deslocamento))
}

/// Uma instrução de uma listagem do `llvm-objdump -d -l`: o endereço, a
/// linha da listagem, e o arquivo e a linha do código de onde ela veio.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Instrucao {
    pub(crate) endereco: u64,
    pub(crate) linha: usize,
    pub(crate) local: Option<String>,
}

/// Uma listagem do `llvm-objdump -d -l`: as linhas como vieram, e as
/// instruções nelas.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Listagem {
    pub(crate) linhas: Vec<String>,
    pub(crate) instrucoes: Vec<Instrucao>,
}

/// Lê a saída do `llvm-objdump -d -l`. O arquivo e a linha vêm num
/// comentário `; caminho:linha` antes das instruções dela, só quando
/// mudam; o nome de uma função, num `; nome():`, que não é um lugar.
pub(crate) fn ler_a_listagem(texto: &str) -> Listagem {
    let mut l = Listagem::default();
    let mut local: Option<String> = None;
    for (n, linha) in texto.lines().enumerate() {
        l.linhas.push(linha.to_string());
        let limpa = linha.trim();
        if let Some(comentario) = limpa.strip_prefix(';') {
            let comentario = comentario.trim();
            if !comentario.ends_with("():") && comentario.contains(':') {
                local = Some(comentario.to_string());
            }
            continue;
        }
        if limpa.ends_with(">:") {
            // O começo de um símbolo novo: o lugar vem depois.
            local = None;
            continue;
        }
        let Some((endereco, _)) = limpa.split_once(':') else {
            continue;
        };
        if let Ok(endereco) = u64::from_str_radix(endereco, 16) {
            l.instrucoes.push(Instrucao {
                endereco,
                linha: n,
                local: local.clone(),
            });
        }
    }
    l
}

impl Listagem {
    /// A instrução em `endereco`, ou a última antes dele.
    fn em(&self, endereco: u64) -> Option<usize> {
        self.instrucoes
            .partition_point(|i| i.endereco <= endereco)
            .checked_sub(1)
    }

    /// A instrução antes de `endereco`: a chamada, num retorno.
    fn antes_de(&self, endereco: u64) -> Option<usize> {
        self.instrucoes
            .partition_point(|i| i.endereco < endereco)
            .checked_sub(1)
    }

    /// As linhas da listagem em volta da instrução `i`, com `=>` nela.
    fn em_volta(&self, i: usize) -> String {
        let de = self.instrucoes[i.saturating_sub(INSTRUCOES_ANTES)].linha;
        let ate = self
            .instrucoes
            .get(i + INSTRUCOES_DEPOIS)
            .map_or(self.linhas.len(), |x| x.linha + 1);
        let alvo = self.instrucoes[i].linha;
        let mut s = String::new();
        for (n, linha) in self.linhas.iter().enumerate().take(ate).skip(de) {
            let marca = if n == alvo { "=> " } else { "   " };
            let _ = writeln!(s, "{marca}{linha}");
        }
        s
    }
}

/// O caminho de um lugar, curto: o DWARF guarda o caminho de onde o
/// kernel foi compilado — na CI, o do runner. Sem a raiz do projeto; um
/// pacote do registro do cargo, a partir do nome e da versão dele
/// (`x86_64-0.15.5/src/...`); a biblioteca do Rust, a partir dela
/// (`core/src/...`).
pub(crate) fn curto(local: &str) -> String {
    let raiz = format!("{}/", super::raiz_do_projeto().display());
    if let Some(resto) = local.strip_prefix(&raiz) {
        return resto.to_string();
    }
    if let Some((_, depois)) = local.split_once("/registry/src/")
        && let Some((_, pacote)) = depois.split_once('/')
    {
        return pacote.to_string();
    }
    if let Some((_, biblioteca)) = local.split_once("/library/") {
        return biblioteca.to_string();
    }
    local.to_string()
}

// ---------------------------------------------------------------------------
// A pilha
// ---------------------------------------------------------------------------

/// Se os bytes `antes` — os que acabam num endereço de retorno — terminam
/// numa chamada do x86_64: a direta, `E8` e o deslocamento, ou a indireta,
/// `FF /2`, por registrador ou pela memória, com ou sem SIB e
/// deslocamento.
pub(crate) fn chamada_antes_no_x86(antes: &[u8]) -> bool {
    let n = antes.len();
    let b = |k: usize| n.checked_sub(k).map(|i| antes[i]);
    let modrm = |k: usize, m: u8| b(k).is_some_and(|x| x & 0xF8 == m && x & 7 != 4);
    b(5) == Some(0xE8)
        // call *%reg
        || (b(2) == Some(0xFF) && b(1).is_some_and(|x| x & 0xF8 == 0xD0))
        // call *(%reg), fora o SIB e o relativo ao RIP
        || (b(2) == Some(0xFF) && modrm(1, 0x10) && b(1) != Some(0x15))
        // call *(%reg,%idx,s)
        || (b(3) == Some(0xFF) && b(2) == Some(0x14))
        // call *d8(%reg)
        || (b(3) == Some(0xFF) && modrm(2, 0x50))
        // call *d8(%reg,%idx,s)
        || (b(4) == Some(0xFF) && b(3) == Some(0x54))
        // call *d32(%rip)
        || (b(6) == Some(0xFF) && b(5) == Some(0x15))
        // call *d32(%reg)
        || (b(6) == Some(0xFF) && modrm(5, 0x90))
        // call *d32(%reg,%idx,s)
        || (b(7) == Some(0xFF) && b(6) == Some(0x94))
}

/// Se a instrução `antes` — a que antecede um endereço de retorno — é uma
/// chamada do aarch64: `BL` ou `BLR`.
pub(crate) fn chamada_antes_no_arm(antes: u32) -> bool {
    antes & 0xFC00_0000 == 0x9400_0000 || antes & 0xFFFF_FC1F == 0xD63F_0000
}

/// O seletor do código do kernel no x86_64 — o primeiro descritor da GDT
/// depois do nulo, ver `kernel/src/arch/x86_64/gdt.rs` —: o CS de todo
/// quadro que uma interrupção no anel zero empilha.
const CS_DO_KERNEL: u64 = 0x08;

/// O SS de um quadro do anel zero: o dos dados do kernel, ou o nulo, que a
/// CPU põe no SS quando a interrupção vem do anel três, e que o kernel
/// segue usando — a IST troca só a pilha.
const SS_DO_KERNEL: [u64; 2] = [0x10, 0];

/// Quanto da pilha que um quadro interrompeu se olha, e quantos retornos
/// dela se guardam.
const PILHA_INTERROMPIDA: usize = 8 << 10;
const RETORNOS_INTERROMPIDOS: usize = 12;

/// Quantos quadros de interrupção de uma pilha se guardam.
const QUADROS: usize = 4;

/// Um quadro de interrupção do x86_64 na pilha: o que a CPU empilha ao
/// entrar numa interrupção, numa exceção ou numa NMI — o RIP, o CS, o
/// RFLAGS, o RSP e o SS, de baixo para cima.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Quadro {
    /// Onde ele está na pilha.
    pub(crate) em: u64,
    /// A instrução interrompida — a seguinte, numa interrupção.
    pub(crate) rip: u64,
    pub(crate) rflags: u64,
    /// A pilha interrompida.
    pub(crate) rsp: u64,
}

/// Os quadros de interrupção do anel zero em `palavras` — a pilha a partir
/// de `topo` —, com o RIP no código (`no_codigo`), o CS do kernel, um
/// RFLAGS que pode ser — o bit 1 ligado; os reservados 3, 5, 15 e os de 22
/// em diante, desligados —, um RSP canônico e o SS do kernel ou o nulo.
pub(crate) fn quadros_de_interrupcao(
    palavras: &[u64],
    topo: u64,
    no_codigo: impl Fn(u64) -> bool,
) -> Vec<Quadro> {
    palavras
        .windows(5)
        .enumerate()
        .filter(|(_, j)| {
            no_codigo(j[0])
                && j[1] == CS_DO_KERNEL
                && j[2] & 0x2 == 0x2
                && j[2] & 0x8028 == 0
                && j[2] >> 22 == 0
                && (j[3] >> 47 == 0 || j[3] >> 47 == 0x1_ffff)
                && SS_DO_KERNEL.contains(&j[4])
        })
        .map(|(i, j)| Quadro {
            em: topo + 8 * i as u64,
            rip: j[0],
            rflags: j[2],
            rsp: j[3],
        })
        .collect()
}

/// Se `v`, um endereço da máquina, é um retorno para o código do kernel:
/// cai num segmento executável do ELF, logo depois de uma chamada.
fn e_retorno(arch: Arquitetura, elf: &Elf, base: u64, v: u64) -> bool {
    let Some(no_elf) = v.checked_sub(base) else {
        return false;
    };
    match arch {
        Arquitetura::X86_64 => elf.antes_de(no_elf, 7).is_some_and(chamada_antes_no_x86),
        Arquitetura::Aarch64 => elf
            .antes_de(no_elf, 4)
            .and_then(|b| b.try_into().ok())
            .is_some_and(|b: [u8; 4]| chamada_antes_no_arm(u32::from_le_bytes(b))),
    }
}

/// As palavras de 64 bits de `bytes`.
fn palavras(bytes: &[u8]) -> Vec<u64> {
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .collect()
}

/// A pilha de uma CPU, no que diz do kernel.
#[derive(Debug, Default)]
struct PilhaDoKernel {
    /// Os retornos para o código do kernel, do topo até o primeiro quadro
    /// de interrupção: endereços da máquina.
    retornos: Vec<u64>,
    /// No x86, os quadros de interrupção, cada um com os retornos da pilha
    /// que ele interrompeu.
    quadros: Vec<(Quadro, Vec<u64>)>,
}

/// O endereço físico do virtual `virtual_` pelas tabelas de páginas da
/// `cpu`, pelo monitor (`cpu` e `gva2gpa`).
fn fisico(emulador: &mut dyn Emulador, cpu: u32, virtual_: u64) -> Option<u64> {
    emulador.monitor(&format!("cpu {cpu}")).ok()?;
    let resposta = emulador.monitor(&format!("gva2gpa {virtual_:#x}")).ok()?;
    let (_, valor) = resposta.trim().split_once("gpa:")?;
    u64::from_str_radix(valor.trim().trim_start_matches("0x"), 16).ok()
}

/// Até `n` bytes da memória a partir de `de`, pelas tabelas da `cpu`,
/// página a página, enquanto cada página cai na `ram` — as faixas da RAM
/// da máquina, em endereços físicos.
///
/// # Por que pelo endereço físico
///
/// A pilha é a de uma CPU que parou por algum motivo, e o ponteiro dela pode
/// estar estragado: lido sem conferir, ele levaria a leitura a um
/// dispositivo — e, no ARM, a procura das imagens do firmware levou a do
/// GIC, e o emulador morreu ali. O endereço virtual não diz se é RAM — as
/// pilhas do kernel do ARM, por exemplo, ficam acima dela —, e o físico, a
/// tradução da própria CPU, diz.
fn ler_na_ram(
    emulador: &mut dyn Emulador,
    cpu: u32,
    de: u64,
    n: usize,
    ram: &[(u64, u64)],
) -> Vec<u8> {
    const PAGINA: u64 = 4096;
    let mut bytes = Vec::new();
    let mut agora = de;
    while bytes.len() < n {
        let ate_a_pagina = (PAGINA - agora % PAGINA) as usize;
        let k = ate_a_pagina.min(n - bytes.len());
        let na_ram = fisico(emulador, cpu, agora).is_some_and(|f| {
            ram.iter()
                .any(|&(a, b)| f >= a && f.saturating_add(k as u64) <= b)
        });
        let Some(pedaco) = na_ram.then(|| emulador.ler(cpu, agora, k)).flatten() else {
            break;
        };
        bytes.extend_from_slice(&pedaco);
        agora += k as u64;
    }
    bytes
}

/// A pilha de `cpu`: os valores que são retornos para o código do kernel —
/// no ARM, o `X30`, o retorno da função em que ela está, vem primeiro —, e,
/// no x86, os quadros de interrupção. Acima do primeiro quadro está a
/// pilha que ele interrompeu — a mesma pilha, ou, na NMI, a de antes da
/// troca pela IST —, e os retornos dela se leem a partir do RSP dele.
fn pilha_do_kernel(
    arch: Arquitetura,
    elf: &Elf,
    base: u64,
    emulador: &mut dyn Emulador,
    cpu: &Cpu,
    ram: &[(u64, u64)],
) -> PilhaDoKernel {
    let mut p = PilhaDoKernel::default();
    if arch == Arquitetura::Aarch64
        && let Some(lr) = cpu.numero_de("X30")
        && e_retorno(arch, elf, base, lr)
    {
        p.retornos.push(lr);
    }
    let Some(topo) = cpu.pilha().map(|t| t & !7) else {
        return p;
    };
    let lidas = palavras(&ler_na_ram(
        emulador,
        cpu.numero,
        topo,
        PILHA_DO_KERNEL,
        ram,
    ));
    let quadros = if arch == Arquitetura::X86_64 {
        let no_codigo = |v: u64| {
            v.checked_sub(base)
                .is_some_and(|e| elf.codigo_em(e).is_some())
        };
        quadros_de_interrupcao(&lidas, topo, no_codigo)
    } else {
        Vec::new()
    };
    let ate = quadros
        .first()
        .map_or(lidas.len(), |q| ((q.em - topo) / 8) as usize);
    for &v in &lidas[..ate] {
        if p.retornos.len() == RETORNOS_DO_KERNEL {
            break;
        }
        if e_retorno(arch, elf, base, v) {
            p.retornos.push(v);
        }
    }
    for q in quadros.into_iter().take(QUADROS) {
        let interrompida = palavras(&ler_na_ram(
            emulador,
            cpu.numero,
            q.rsp & !7,
            PILHA_INTERROMPIDA,
            ram,
        ));
        let retornos = interrompida
            .into_iter()
            .filter(|&v| e_retorno(arch, elf, base, v))
            .take(RETORNOS_INTERROMPIDOS)
            .collect();
        p.quadros.push((q, retornos));
    }
    p
}

// ---------------------------------------------------------------------------
// A serial
// ---------------------------------------------------------------------------

/// Onde o boot estava, pela serial humana do cenário.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Etapa {
    /// Quantas vezes o firmware carregou a opção de boot — o `BdsDxe` do
    /// EDK II —, e quantas o iniciador começou.
    pub(crate) pelo_firmware: usize,
    pub(crate) pelo_iniciador: usize,
    /// A etapa da última linha que diz alguma: `firmware`, `iniciador`,
    /// `kernel` ou `panico`; vazia sem nenhuma.
    pub(crate) etapa: &'static str,
    /// A última linha de cada etapa, no último boot.
    pub(crate) firmware: Option<String>,
    pub(crate) iniciador: Option<String>,
    pub(crate) kernel: Option<String>,
    pub(crate) panico: Option<String>,
    /// A última linha que não está em branco, e quantas em branco vieram
    /// depois dela.
    pub(crate) ultima: Option<String>,
    pub(crate) em_branco_depois: usize,
}

/// Um passo do kernel: `[    N]    T ms nivel modulo mensagem`.
fn e_passo_do_kernel(linha: &str) -> bool {
    let Some(resto) = linha.trim_start().strip_prefix('[') else {
        return false;
    };
    let Some((numero, _)) = resto.split_once(']') else {
        return false;
    };
    let numero = numero.trim();
    !numero.is_empty() && numero.chars().all(|c| c.is_ascii_digit())
}

/// A etapa do boot pela serial: cada linha é do firmware, do iniciador
/// (`iniciador:`), do kernel (os passos `[ N]`, o cartaz) ou do pânico
/// (o cartaz `!!! PANICO NO KERNEL !!!`, a falha fatal, e o que vem depois
/// até o boot seguinte). Um boot novo começa no `BdsDxe: loading`.
pub(crate) fn etapa_do_boot(texto: &str) -> Etapa {
    let mut e = Etapa::default();
    for linha in texto.lines() {
        let limpa = linha.trim();
        if limpa.is_empty() {
            if e.ultima.is_some() {
                e.em_branco_depois += 1;
            }
            continue;
        }
        e.ultima = Some(limpa.to_string());
        e.em_branco_depois = 0;
        if limpa.contains("BdsDxe: loading") {
            e.pelo_firmware += 1;
            e.iniciador = None;
            e.kernel = None;
            e.panico = None;
            e.firmware = Some(limpa.to_string());
            e.etapa = "firmware";
        } else if limpa.starts_with("iniciador:") {
            if limpa.starts_with("iniciador: vivo em") {
                e.pelo_iniciador += 1;
            }
            e.iniciador = Some(limpa.to_string());
            e.etapa = "iniciador";
        } else if limpa.contains("PANICO NO KERNEL")
            || limpa.contains("FALHA FATAL")
            || e.etapa == "panico"
        {
            e.panico = Some(limpa.to_string());
            e.etapa = "panico";
        } else if e_passo_do_kernel(limpa) {
            e.kernel = Some(limpa.to_string());
            e.etapa = "kernel";
        } else if e.etapa.is_empty() || e.etapa == "firmware" {
            e.firmware = Some(limpa.to_string());
            e.etapa = "firmware";
        }
    }
    e
}

/// Os últimos `n` bytes de `bytes`, com os controles escapados: o último
/// sinal da máquina como ele foi, quebra de linha por quebra de linha.
pub(crate) fn ultimos_bytes(bytes: &[u8], n: usize) -> String {
    let mut s = String::new();
    for &b in &bytes[bytes.len().saturating_sub(n)..] {
        match b {
            b'\r' => s.push_str("\\r"),
            b'\n' => s.push_str("\\n"),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(char::from(b)),
            _ => {
                let _ = write!(s, "\\x{b:02x}");
            }
        }
    }
    s
}

// ---------------------------------------------------------------------------
// O monitor
// ---------------------------------------------------------------------------

/// O LSR de um 16550, em palavras.
pub(crate) fn lsr_em_palavras(lsr: u8) -> String {
    const NOMES: [(u8, &str); 8] = [
        (0x01, "DR"),
        (0x02, "OE"),
        (0x04, "PE"),
        (0x08, "FE"),
        (0x10, "BI"),
        (0x20, "THRE"),
        (0x40, "TEMT"),
        (0x80, "ERR"),
    ];
    let ligadas: Vec<&str> = NOMES
        .iter()
        .filter(|(b, _)| lsr & b != 0)
        .map(|(_, n)| *n)
        .collect();
    let transmissor = match (lsr & 0x20 != 0, lsr & 0x40 != 0) {
        (true, true) => "o transmissor vazio",
        (true, false) => "a fila do transmissor com espaco, o ultimo byte saindo",
        _ => "a fila do transmissor cheia: o byte seguinte espera",
    };
    format!(
        "LSR={lsr:#04x} [{}]: {transmissor}",
        if ligadas.is_empty() {
            "nenhuma".to_string()
        } else {
            ligadas.join(" ")
        }
    )
}

/// O valor de uma leitura de porta do monitor: `portb[0x03fd] = 0x60`.
pub(crate) fn valor_da_porta(texto: &str) -> Option<u8> {
    let (_, valor) = texto.trim().rsplit_once('=')?;
    u8::from_str_radix(valor.trim().trim_start_matches("0x"), 16).ok()
}

/// As perguntas ao monitor sobre os controladores: no x86, o APIC de cada
/// CPU, o PIC e o IOAPIC, as contagens de interrupção e a UART das duas
/// seriais — o LSR, o IER, o LCR e o MCR, que se leem sem efeito, fora o
/// que o LSR limpa (ver o começo do módulo); no ARM, as interrupções e o
/// registrador de marcas da PL011, também sem efeito.
fn perguntas(arch: Arquitetura, cpus: &[Cpu]) -> Vec<String> {
    let mut p = vec!["info cpus".to_string(), "info chardev".to_string()];
    match arch {
        Arquitetura::X86_64 => {
            p.extend(cpus.iter().map(|c| format!("info lapic {}", c.numero)));
            p.extend(
                [
                    "info pic",
                    "info irq",
                    "i /b 0x3fd",
                    "i /b 0x3f9",
                    "i /b 0x3fb",
                    "i /b 0x3fc",
                    "i /b 0x2fd",
                    "i /b 0x2f9",
                ]
                .map(String::from),
            );
        }
        Arquitetura::Aarch64 => {
            p.extend(["info pic", "info irq", "xp /1wx 0x9000018"].map(String::from));
        }
    }
    p
}

// ---------------------------------------------------------------------------
// O incidente
// ---------------------------------------------------------------------------

/// O que a bancada sabe de uma máquina que parou.
pub(crate) struct Parada<'a> {
    pub(crate) arch: Arquitetura,
    /// Por que a bancada desistiu dela.
    pub(crate) motivo: &'a str,
    /// O estado que o QMP disse antes de pará-la: `running`, ou outro.
    pub(crate) status: &'a str,
    /// O `info registers -a`, desescapado.
    pub(crate) registros: &'a str,
    /// A serial humana do cenário.
    pub(crate) serial: Option<&'a Path>,
    /// As faixas da RAM da máquina, em endereços físicos: as pilhas só se
    /// leem nelas — ver [`ler_na_ram`].
    pub(crate) ram: &'a [(u64, u64)],
}

/// O kernel achado na memória.
#[derive(Clone, Debug)]
pub(crate) struct KernelAchado {
    pub(crate) elf: PathBuf,
    /// A cópia guardada com o incidente — ver o começo do módulo.
    pub(crate) copia: Option<PathBuf>,
    pub(crate) sha256: String,
    pub(crate) como: String,
    /// Quantos bytes de código se compararam na memória.
    pub(crate) codigo: u64,
}

/// Onde uma CPU está, no kernel.
#[derive(Clone, Debug)]
pub(crate) struct OndeEsta {
    pub(crate) numero: u32,
    pub(crate) instrucao: u64,
    /// O endereço no ELF, se cai no kernel.
    pub(crate) no_elf: Option<u64>,
    /// `função+deslocamento`.
    pub(crate) funcao: Option<String>,
    /// O arquivo e a linha.
    pub(crate) local: Option<String>,
    pub(crate) estado: String,
    /// Os retornos na pilha, simbolizados.
    pub(crate) retornos: Vec<String>,
    /// No x86, os quadros de interrupção na pilha.
    pub(crate) quadros: Vec<QuadroNomeado>,
}

/// Um quadro de interrupção, simbolizado.
#[derive(Clone, Debug)]
pub(crate) struct QuadroNomeado {
    pub(crate) em: u64,
    /// Onde a CPU estava: `função+deslocamento (arquivo:linha)`.
    pub(crate) interrompida: String,
    pub(crate) rflags: u64,
    pub(crate) rsp: u64,
    /// Os retornos na pilha interrompida.
    pub(crate) retornos: Vec<String>,
}

/// O incidente guardado.
pub(crate) struct Incidente {
    /// O diretório, se se criou.
    pub(crate) dir: Option<PathBuf>,
    pub(crate) kernel: Option<KernelAchado>,
    pub(crate) cpus: Vec<OndeEsta>,
    pub(crate) etapa: Option<Etapa>,
    /// As linhas para a saída da bancada.
    pub(crate) resumo: Vec<String>,
}

/// Acrescenta ao `resumo.txt` do incidente uma parte `titulo`, com
/// `linhas`: o que o diagnóstico acha depois de guardá-lo — onde cada
/// processador está nas imagens do firmware, ver
/// [`super::firmware::onde_cada_processador`].
pub(crate) fn acrescentar(incidente: &Incidente, titulo: &str, linhas: &[String]) {
    use std::io::Write as _;
    let Some(dir) = &incidente.dir else {
        return;
    };
    let Ok(mut arquivo) = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.join("resumo.txt"))
    else {
        return;
    };
    let mut texto = format!("\n# {titulo}\n\n");
    for linha in linhas {
        texto.push_str(linha);
        texto.push('\n');
    }
    let _ = arquivo.write_all(texto.as_bytes());
}

/// O `rustc -Vv` do toolchain que compilou o kernel — o mesmo deste
/// processo, pelo `rust-toolchain.toml` —: o nightly não tem data fixa, e
/// reconstruir um binário igual depois começa por ele.
fn versao_do_rustc() -> String {
    Command::new("rustc")
        .arg("-Vv")
        .current_dir(super::raiz_do_projeto().join("kernel"))
        .output()
        .ok()
        .filter(|s| s.status.success())
        .map_or_else(
            || "o rustc -Vv nao respondeu".to_string(),
            |s| String::from_utf8_lossy(&s.stdout).trim().to_string(),
        )
}

impl Incidente {
    /// O incidente que não se guardou, e por quê.
    pub(crate) fn nenhum(porque: &str) -> Incidente {
        Incidente {
            dir: None,
            kernel: None,
            cpus: Vec::new(),
            etapa: None,
            resumo: vec![porque.to_string()],
        }
    }
}

/// O SHA-256 de `bytes`, em hexadecimal.
fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// O nome de uma função com o deslocamento, e o lugar, de um endereço do
/// ELF — o lugar da própria instrução, ou, num retorno, o da chamada.
struct Simbolizador {
    elf: PathBuf,
    funcoes: Vec<Simbolo>,
    objdump: Option<PathBuf>,
    /// As listagens já feitas, pelo começo da função.
    listagens: Vec<(u64, Listagem)>,
    erro: Option<String>,
}

impl Simbolizador {
    /// A listagem da função `f`, até um pouco depois de `ate`.
    fn listagem(&mut self, f: &Simbolo, ate: u64) -> Option<&Listagem> {
        if let Some(i) = self.listagens.iter().position(|(e, _)| *e == f.endereco) {
            let feita = &self.listagens[i].1;
            if feita.instrucoes.last().is_some_and(|x| x.endereco >= ate) {
                return Some(&self.listagens[i].1);
            }
            self.listagens.remove(i);
        }
        let objdump = self.objdump.as_ref()?;
        let fim = if f.tamanho > 0 {
            f.endereco + f.tamanho
        } else {
            ate + 256
        }
        .min(ate + 256)
        .max(ate + 1);
        let saida = Command::new(objdump)
            .args(["-d", "-l", "--demangle", "--no-show-raw-insn"])
            .arg(format!("--start-address={:#x}", f.endereco))
            .arg(format!("--stop-address={fim:#x}"))
            .arg(&self.elf)
            .output();
        match saida {
            Ok(s) if s.status.success() => {
                let listagem = ler_a_listagem(&String::from_utf8_lossy(&s.stdout));
                self.listagens.push((f.endereco, listagem));
                self.listagens.last().map(|(_, l)| l)
            }
            Ok(s) => {
                self.erro = Some(format!(
                    "o llvm-objdump falhou: {}",
                    String::from_utf8_lossy(&s.stderr).trim()
                ));
                None
            }
            Err(e) => {
                self.erro = Some(format!("o llvm-objdump nao rodou: {e}"));
                None
            }
        }
    }

    /// `função+deslocamento` e o lugar de `endereco`, do ELF; num retorno,
    /// o lugar da chamada antes dele. E a desmontagem em volta, se pedida.
    fn nomear(
        &mut self,
        endereco: u64,
        retorno: bool,
        com_desmontagem: bool,
        com_linha: bool,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let Some((f, deslocamento)) = funcao_em(&self.funcoes, endereco) else {
            return (None, None, None);
        };
        let f = f.clone();
        let nome = format!("{}+{deslocamento:#x}", f.nome);
        if !com_linha {
            return (Some(nome), None, None);
        }
        let Some(listagem) = self.listagem(&f, endereco) else {
            return (Some(nome), None, None);
        };
        let i = if retorno {
            listagem.antes_de(endereco)
        } else {
            listagem.em(endereco)
        };
        let local = i
            .and_then(|i| listagem.instrucoes[i].local.as_deref())
            .map(curto);
        let desmontagem = i.filter(|_| com_desmontagem).map(|i| listagem.em_volta(i));
        (Some(nome), local, desmontagem)
    }
}

/// Um endereço da máquina, simbolizado, numa linha: `função+0x10 (arquivo:linha)`.
fn em_uma_linha(funcao: Option<&str>, local: Option<&str>, endereco: u64) -> String {
    match (funcao, local) {
        (Some(f), Some(l)) => format!("{f} ({l})"),
        (Some(f), None) => f.to_string(),
        _ => format!("{endereco:#x}"),
    }
}

/// Os kernels desta execução que podem ser o da máquina — da arquitetura
/// dela, do mais novo ao mais velho —, e o que se disse dos que não podem.
fn candidatos(arch: Arquitetura) -> (Vec<Compilado>, Vec<String>) {
    let lista = COMPILADOS.lock().map(|l| l.clone()).unwrap_or_default();
    let mut bons = Vec::new();
    let mut ditos = Vec::new();
    for c in lista.into_iter().rev().filter(|c| c.arch == arch) {
        let meta = std::fs::metadata(&c.elf).ok();
        let igual = meta
            .as_ref()
            .is_some_and(|m| m.len() == c.tamanho && m.modified().ok() == c.modificado);
        if igual {
            bons.push(c);
        } else {
            ditos.push(format!(
                "{} ({}): o arquivo mudou ou sumiu depois da compilacao desta execucao",
                c.elf.display(),
                c.como
            ));
        }
    }
    (bons, ditos)
}

/// O nome de um diretório para o incidente: o instante, a bancada, a
/// arquitetura e o número dele nesta execução.
fn nome_do_incidente(arch: Arquitetura, bancada: &str) -> String {
    let agora = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let n = INCIDENTES.fetch_add(1, Ordering::Relaxed) + 1;
    let bancada: String = bancada
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("{agora}-{bancada}-{}-{n}", arch.nome())
}

/// Guarda o incidente de uma máquina parada em `raiz` — ver o começo do
/// módulo — e diz, em linhas, o que a saída da bancada mostra dele. Nada
/// aqui falha: o que não se lê vira uma linha que diz isso.
pub(crate) fn guardar(parada: &Parada, emulador: &mut dyn Emulador, raiz: &Path) -> Incidente {
    let arch = parada.arch;
    let base = arch.base_do_kernel();
    let (bancada, cenario) = CENARIO
        .lock()
        .ok()
        .and_then(|c| c.clone())
        .unwrap_or_else(|| ("bancada".to_string(), "sem cenario".to_string()));
    let dir = raiz.join(nome_do_incidente(arch, &bancada));
    let dir = std::fs::create_dir_all(&dir).ok().map(|()| dir);
    let lista = cpus(parada.registros);
    // Sem registradores, a memória se lê pela CPU 0.
    let numeros: Vec<u32> = if lista.is_empty() {
        vec![0]
    } else {
        lista.iter().map(|c| c.numero).collect()
    };

    let mut resumo: Vec<String> = Vec::new();
    let mut texto = String::new();
    let _ = writeln!(texto, "o incidente de uma maquina parada\n");
    let _ = writeln!(texto, "a bancada: {bancada} ({})", arch.nome());
    let _ = writeln!(texto, "o cenario: {cenario}");
    let _ = writeln!(texto, "o motivo: {}", parada.motivo);
    let _ = writeln!(texto, "o emulador, antes de parado: {}", parada.status);

    // O kernel: o desta execução que está na memória.
    let _ = writeln!(texto, "\n# o kernel\n");
    let (lista_de_candidatos, mudados) = candidatos(arch);
    for m in &mudados {
        let _ = writeln!(texto, "descartado: {m}");
    }
    let mut achado: Option<(KernelAchado, Elf)> = None;
    for c in &lista_de_candidatos {
        let elf = match std::fs::read(&c.elf)
            .map_err(|e| e.to_string())
            .and_then(ler_elf)
        {
            Ok(elf) => elf,
            Err(e) => {
                let _ = writeln!(texto, "{} ({}): nao se le: {e}", c.elf.display(), c.como);
                continue;
            }
        };
        let conferencia = conferir_na_memoria(&elf, base, emulador, &numeros);
        let _ = writeln!(
            texto,
            "{} ({}): {}",
            c.elf.display(),
            c.como,
            if conferencia.confere {
                "e o que esta na memoria"
            } else {
                "nao e o que esta na memoria"
            }
        );
        for linha in &conferencia.linhas {
            let _ = writeln!(texto, "  {linha}");
        }
        if conferencia.confere {
            achado = Some((
                KernelAchado {
                    elf: c.elf.clone(),
                    copia: None,
                    sha256: sha256(&elf.bytes),
                    como: c.como.clone(),
                    codigo: conferencia.codigo,
                },
                elf,
            ));
            break;
        }
    }
    if lista_de_candidatos.is_empty() {
        let _ = writeln!(
            texto,
            "nenhum kernel de {} compilado por esta execucao para conferir",
            arch.nome()
        );
    }

    // O código conferido não basta para dizer que é o kernel que roda: a
    // memória não se apaga num reinício, e a máquina que parou no firmware ou
    // no iniciador, depois de um boot, ainda tem o kernel dele no lugar —
    // no ARM, ligado num endereço fixo. Sem CPU nenhuma dentro dele, os
    // estáticos podem ser os daquele boot, e não se leem.
    let alguma_no_kernel = achado.as_ref().is_some_and(|(_, elf)| {
        elf.faixa().is_some_and(|(de, ate)| {
            lista
                .iter()
                .filter_map(Cpu::instrucao)
                .any(|i| i.checked_sub(base).is_some_and(|e| e >= de && e < ate))
        })
    });
    if achado.is_some() && !alguma_no_kernel {
        let _ = writeln!(
            texto,
            "nenhuma CPU esta no codigo dele: ele pode ser o de um boot anterior, e os estaticos nao se leem"
        );
    }
    // A cópia do ELF, uma vez por kernel, e os símbolos dela.
    let mut simbolizador: Option<Simbolizador> = None;
    if let Some((k, elf)) = achado.as_mut() {
        let kernels = raiz.join("kernels");
        let copia = kernels.join(format!("duke-{}-{}.elf", arch.nome(), &k.sha256[..16]));
        let feita = copia
            .metadata()
            .is_ok_and(|m| m.len() == elf.bytes.len() as u64)
            || (std::fs::create_dir_all(&kernels).is_ok()
                && std::fs::write(&copia, &elf.bytes).is_ok());
        k.copia = feita.then(|| copia.clone());
        let _ = writeln!(texto, "\no ELF: {} ({})", k.elf.display(), k.como);
        let _ = writeln!(texto, "o SHA-256 do ELF: {}", k.sha256);
        let _ = writeln!(
            texto,
            "a copia guardada: {}",
            k.copia
                .as_ref()
                .map_or("nao se escreveu".to_string(), |c| c.display().to_string())
        );
        let _ = writeln!(texto, "a base do kernel: {base:#x}");
        let _ = writeln!(texto, "o compilador:\n{}", versao_do_rustc());
        resumo.push(format!(
            "o kernel: {} ({}), sha256 {}; na memoria o mesmo codigo ({} bytes){}",
            k.elf.display(),
            k.como,
            k.sha256,
            k.codigo,
            if alguma_no_kernel {
                ""
            } else {
                ", mas nenhuma CPU nele: pode ser o de um boot anterior"
            }
        ));
        let copia_do_elf = k.copia.clone().unwrap_or_else(|| k.elf.clone());
        let nm = super::ferramenta_llvm("llvm-nm").and_then(|nm| {
            Command::new(nm)
                .args(["-n", "-S", "--defined-only", "--demangle"])
                .arg(&copia_do_elf)
                .output()
                .map_err(|e| format!("o llvm-nm nao rodou: {e}"))
        });
        let simbolos = match nm {
            Ok(s) if s.status.success() => ler_a_tabela_do_nm(&String::from_utf8_lossy(&s.stdout)),
            Ok(s) => {
                let _ = writeln!(
                    texto,
                    "o llvm-nm falhou: {}",
                    String::from_utf8_lossy(&s.stderr).trim()
                );
                Vec::new()
            }
            Err(e) => {
                let _ = writeln!(texto, "sem os simbolos: {e}");
                Vec::new()
            }
        };
        let (funcoes, dados): (Vec<Simbolo>, Vec<Simbolo>) = simbolos
            .into_iter()
            .partition(|s| matches!(s.tipo, 't' | 'T' | 'w' | 'W'));
        simbolizador = Some(Simbolizador {
            elf: copia_do_elf,
            funcoes,
            objdump: super::ferramenta_llvm("llvm-objdump").ok(),
            listagens: Vec::new(),
            erro: None,
        });
        // Os estáticos.
        let _ = writeln!(texto, "\n# os estaticos do kernel\n");
        for s in dados.iter().filter(|s| {
            alguma_no_kernel
                && matches!(s.tipo, 'b' | 'B' | 'd' | 'D')
                && (1..=MAIOR_ESTATICO).contains(&s.tamanho)
                && ESTATICOS.iter().any(|p| s.nome.starts_with(p))
        }) {
            let n = (s.tamanho as usize).min(BYTES_DE_UM_ESTATICO);
            let onde = base.wrapping_add(s.endereco);
            match ler_por_alguma(emulador, &numeros, onde, n) {
                Some(b) => {
                    let valor = match n {
                        1 => format!(" = {}", b[0]),
                        2 | 4 | 8 => {
                            let mut v = [0u8; 8];
                            v[..n].copy_from_slice(&b);
                            format!(" = {}", u64::from_le_bytes(v))
                        }
                        _ => String::new(),
                    };
                    let hex = if n >= 16 && n % 8 == 0 {
                        let ditas: Vec<String> =
                            palavras(&b).iter().map(|w| format!("{w:#x}")).collect();
                        format!("palavras {}", ditas.join(" "))
                    } else {
                        b.iter().fold(String::new(), |mut h, x| {
                            let _ = write!(h, "{x:02x}");
                            h
                        })
                    };
                    let _ = writeln!(
                        texto,
                        "{} ({} bytes em {onde:#x}): {hex}{}{valor}",
                        s.nome,
                        s.tamanho,
                        if n < s.tamanho as usize { "..." } else { "" }
                    );
                }
                None => {
                    let _ = writeln!(texto, "{} em {onde:#x}: nao se le", s.nome);
                }
            }
        }
    } else {
        resumo.push(
            "o kernel: nenhum desta execucao confere com a memoria da maquina; os enderecos ficam sem nome (ver resumo.txt)"
                .to_string(),
        );
    }

    // Cada CPU.
    let _ = writeln!(texto, "\n# as cpus\n");
    let mut desmontagem = String::new();
    let mut onde_estao: Vec<OndeEsta> = Vec::new();
    let faixa = achado.as_ref().and_then(|(_, elf)| elf.faixa());
    for cpu in &lista {
        let Some(instrucao) = cpu.instrucao() else {
            continue;
        };
        let no_elf = instrucao
            .checked_sub(base)
            .filter(|e| faixa.is_some_and(|(de, ate)| *e >= de && *e < ate));
        let estado = estado_da_cpu(arch, cpu);
        let mesma_antes = onde_estao.iter().any(|o| o.instrucao == instrucao);
        let (funcao, local, volta) = match (no_elf, simbolizador.as_mut()) {
            (Some(e), Some(s)) => s.nomear(e, false, !mesma_antes, true),
            _ => (None, None, None),
        };
        if let Some(volta) = volta {
            let _ = writeln!(
                desmontagem,
                "## {instrucao:#x} ({}), onde esta a CPU#{}\n\n{volta}",
                em_uma_linha(funcao.as_deref(), local.as_deref(), instrucao),
                cpu.numero
            );
        }
        let mut nomeados = Vec::new();
        let mut quadros = Vec::new();
        if let (Some((_, elf)), Some(s)) = (achado.as_ref(), simbolizador.as_mut()) {
            let pilha = pilha_do_kernel(arch, elf, base, emulador, cpu, parada.ram);
            // O arquivo e a linha — uma listagem do `llvm-objdump` por função —
            // só para os primeiros retornos de cada pilha: os outros, só a
            // função, pela tabela do `llvm-nm`.
            let nomear = |s: &mut Simbolizador, (i, &r): (usize, &u64)| {
                let com_linha = i < RETORNOS_NO_RESUMO;
                let (f, l, _) = s.nomear(r.wrapping_sub(base), true, false, com_linha);
                format!("{r:#x} {}", em_uma_linha(f.as_deref(), l.as_deref(), r))
            };
            nomeados = pilha
                .retornos
                .iter()
                .enumerate()
                .map(|x| nomear(s, x))
                .collect();
            for (q, retornos) in &pilha.quadros {
                let (f, l, _) = s.nomear(q.rip.wrapping_sub(base), false, false, true);
                quadros.push(QuadroNomeado {
                    em: q.em,
                    interrompida: em_uma_linha(f.as_deref(), l.as_deref(), q.rip),
                    rflags: q.rflags,
                    rsp: q.rsp,
                    retornos: retornos.iter().enumerate().map(|x| nomear(s, x)).collect(),
                });
            }
        }
        let _ = writeln!(texto, "CPU#{}: {estado}", cpu.numero);
        let _ = writeln!(
            texto,
            "  em {instrucao:#x}{}: {}",
            no_elf.map_or(" (fora do kernel)".to_string(), |e| format!(
                " = {e:#x} no ELF"
            )),
            em_uma_linha(funcao.as_deref(), local.as_deref(), instrucao)
        );
        if let Some(topo) = cpu.pilha() {
            let _ = writeln!(texto, "  a pilha em {topo:#x}");
        }
        if nomeados.is_empty() {
            let _ = writeln!(texto, "  nenhum retorno para o kernel na pilha");
        } else {
            let _ = writeln!(texto, "  os retornos na pilha, do topo para baixo:");
            for n in &nomeados {
                let _ = writeln!(texto, "    {n}");
            }
        }
        for q in &quadros {
            let _ = writeln!(
                texto,
                "  um quadro de interrupcao em {:#x}: interrompida em {}, RFLAGS={:#x} [{}], a pilha em {:#x}",
                q.em,
                q.interrompida,
                q.rflags,
                bandeiras_do_x86(q.rflags),
                q.rsp
            );
            for r in &q.retornos {
                let _ = writeln!(texto, "    {r}");
            }
        }
        onde_estao.push(OndeEsta {
            numero: cpu.numero,
            instrucao,
            no_elf,
            funcao,
            local,
            estado,
            retornos: nomeados,
            quadros,
        });
    }
    if let Some(erro) = simbolizador.as_ref().and_then(|s| s.erro.clone()) {
        let _ = writeln!(texto, "\nas linhas: {erro}");
    }
    // O resumo das CPUs: as do mesmo endereço juntas.
    let mut grupos: Vec<(u64, Vec<&OndeEsta>)> = Vec::new();
    for o in &onde_estao {
        match grupos.iter_mut().find(|(e, _)| *e == o.instrucao) {
            Some((_, g)) => g.push(o),
            None => grupos.push((o.instrucao, vec![o])),
        }
    }
    for (instrucao, grupo) in &grupos {
        let quem: Vec<String> = grupo.iter().map(|o| format!("CPU#{}", o.numero)).collect();
        let o = grupo[0];
        resumo.push(format!(
            "{} em {instrucao:#x}{}: {}; {}",
            quem.join(", "),
            o.no_elf
                .map_or(String::new(), |e| format!(" ({e:#x} no ELF)")),
            em_uma_linha(o.funcao.as_deref(), o.local.as_deref(), *instrucao),
            o.estado
        ));
        let so_o_nome = |r: &String| r.split_once(' ').map_or(r.clone(), |(_, n)| n.to_string());
        if !o.retornos.is_empty() {
            let chamadores: Vec<String> = o
                .retornos
                .iter()
                .take(RETORNOS_NO_RESUMO)
                .map(so_o_nome)
                .collect();
            resumo.push(format!("  chamada por: {}", chamadores.join(" <- ")));
        }
        if let Some(q) = o.quadros.first() {
            let antes: Vec<String> = q
                .retornos
                .iter()
                .take(RETORNOS_NO_RESUMO)
                .map(so_o_nome)
                .collect();
            resumo.push(format!(
                "  numa interrupcao: interrompida em {}, com as interrupcoes {}{}",
                q.interrompida,
                if q.rflags & 0x200 != 0 {
                    "ligadas"
                } else {
                    "desligadas"
                },
                if antes.is_empty() {
                    String::new()
                } else {
                    format!("; antes, chamada por: {}", antes.join(" <- "))
                }
            ));
        }
    }

    // O monitor.
    let mut monitor = String::new();
    for pergunta in perguntas(arch, &lista) {
        let resposta = emulador.monitor(&pergunta);
        let dito = match &resposta {
            Ok(r) | Err(r) => r.as_str(),
        };
        let _ = writeln!(monitor, "(qemu) {pergunta}\n{dito}");
        if let Ok(r) = &resposta
            && pergunta.starts_with("i /b 0x")
            && pergunta.ends_with('d')
            && let Some(lsr) = valor_da_porta(r)
        {
            let porta = if pergunta.contains("0x3fd") {
                "COM1"
            } else {
                "COM2"
            };
            let linha = format!("a UART {porta}: {}", lsr_em_palavras(lsr));
            let _ = writeln!(texto, "{linha}");
            resumo.push(linha);
        }
    }

    // A serial.
    let _ = writeln!(texto, "\n# a serial\n");
    let serial = parada.serial.and_then(|c| std::fs::read(c).ok());
    let etapa = serial.as_ref().map(|b| {
        let limpo = super::persistencia::sem_controles(b);
        let e = etapa_do_boot(&limpo);
        let quantos = format!(
            "{} boot(s) pelo firmware, {} pelo iniciador",
            e.pelo_firmware, e.pelo_iniciador
        );
        let linha = format!(
            "a serial: {quantos}; o ultimo chegou a {}{}; depois da ultima linha, {} em branco",
            if e.etapa.is_empty() { "nada" } else { e.etapa },
            match e.etapa {
                "kernel" => e.kernel.as_deref().map(|l| format!(" ({l})")),
                "panico" => e.panico.as_deref().map(|l| format!(" ({l})")),
                "iniciador" => e.iniciador.as_deref().map(|l| format!(" ({l})")),
                "firmware" => e.firmware.as_deref().map(|l| format!(" ({l})")),
                _ => None,
            }
            .unwrap_or_default(),
            e.em_branco_depois
        );
        let _ = writeln!(texto, "{linha}");
        for (rotulo, valor) in [
            ("o ultimo passo do kernel", &e.kernel),
            ("a ultima linha do panico", &e.panico),
            ("a ultima linha do iniciador", &e.iniciador),
            ("a ultima linha do firmware", &e.firmware),
        ] {
            if let Some(v) = valor {
                let _ = writeln!(texto, "{rotulo}: {v}");
            }
        }
        let fim = ultimos_bytes(b, ULTIMOS_BYTES);
        let _ = writeln!(texto, "os ultimos bytes: {fim}");
        resumo.push(linha);
        resumo.push(format!("os ultimos bytes da serial: {fim}"));
        let _ = writeln!(texto, "\nas ultimas linhas:");
        for l in super::persistencia::ultimas_linhas(&limpo, LINHAS_DA_SERIAL) {
            let _ = writeln!(texto, "  [serial] {l}");
        }
        e
    });
    if etapa.is_none() {
        let _ = writeln!(texto, "sem a serial do cenario");
    }

    // Os arquivos.
    if let Some(d) = &dir {
        let escrever = |nome: &str, conteudo: &[u8]| {
            let _ = std::fs::write(d.join(nome), conteudo);
        };
        escrever("resumo.txt", texto.as_bytes());
        escrever("registradores.txt", parada.registros.as_bytes());
        escrever("monitor.txt", monitor.as_bytes());
        if !desmontagem.is_empty() {
            escrever("desmontagem.txt", desmontagem.as_bytes());
        }
        if let Some(b) = &serial {
            escrever("serial.txt", b);
        }
        resumo.insert(0, format!("o incidente: {}", d.display()));
    } else {
        resumo.insert(
            0,
            format!(
                "o incidente nao se guardou: {} nao se criou",
                raiz.display()
            ),
        );
    }
    Incidente {
        dir,
        kernel: achado.map(|(k, _)| k),
        cpus: onde_estao,
        etapa,
        resumo,
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    /// Uma memória de teste: faixas de bytes em endereços.
    struct MemoriaDeTeste {
        faixas: Vec<(u64, Vec<u8>)>,
        respostas: Vec<(String, String)>,
    }

    impl Memoria for MemoriaDeTeste {
        fn ler(&mut self, _cpu: u32, endereco: u64, tamanho: usize) -> Option<Vec<u8>> {
            self.faixas.iter().find_map(|(de, b)| {
                let i = usize::try_from(endereco.checked_sub(*de)?).ok()?;
                b.get(i..i.checked_add(tamanho)?).map(<[u8]>::to_vec)
            })
        }
    }

    impl Emulador for MemoriaDeTeste {
        fn monitor(&mut self, comando: &str) -> Result<String, String> {
            self.respostas
                .iter()
                .find(|(c, _)| c == comando)
                .map(|(_, r)| r.clone())
                .ok_or_else(|| format!("comando desconhecido: {comando}"))
        }
    }

    /// Um ELF64 mínimo: o cabeçalho; dois `PT_LOAD` — o primeiro do byte 0
    /// ao fim, só leitura, como o do kernel cobre as tabelas; o segundo, de
    /// código —; e um `PT_DYNAMIC` com duas relocações no código: uma
    /// relativa, e uma de outro tipo, que o iniciador não aplicaria.
    fn elf_de_teste() -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[..6].copy_from_slice(b"\x7fELF\x02\x01");
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&3u16.to_le_bytes());
        let programa = |b: &mut Vec<u8>, i: usize, tipo: u32, marcas: u32, de: u64, n: u64| {
            let p = 64 + 56 * i;
            b[p..p + 4].copy_from_slice(&tipo.to_le_bytes());
            b[p + 4..p + 8].copy_from_slice(&marcas.to_le_bytes());
            b[p + 8..p + 16].copy_from_slice(&de.to_le_bytes());
            b[p + 16..p + 24].copy_from_slice(&de.to_le_bytes());
            b[p + 32..p + 40].copy_from_slice(&n.to_le_bytes());
            b[p + 40..p + 48].copy_from_slice(&n.to_le_bytes());
        };
        programa(&mut b, 0, PT_LOAD, 4, 0, 0x400);
        programa(&mut b, 1, PT_LOAD, 5, 0x200, 0x100);
        programa(&mut b, 2, PT_DYNAMIC, 6, 0x300, 0x40);
        // O código: uma chamada direta, e depois dela o retorno em 0x205.
        b[0x200] = 0xE8;
        b[0x210..0x218].fill(0xAA);
        // A seção dinâmica: DT_RELA em 0x380, DT_RELASZ de duas.
        let dinamica = [(DT_RELA, 0x380u64), (DT_RELASZ, 48), (DT_NULL, 0)];
        for (i, (etiqueta, valor)) in dinamica.iter().enumerate() {
            let p = 0x300 + 16 * i;
            b[p..p + 8].copy_from_slice(&etiqueta.to_le_bytes());
            b[p + 8..p + 16].copy_from_slice(&valor.to_le_bytes());
        }
        // Uma relocação relativa no código, em 0x210, e uma de outro tipo
        // em 0x220.
        let relocacao = |b: &mut Vec<u8>, i: usize, onde: u64, tipo: u64, parcela: u64| {
            let p = 0x380 + 24 * i;
            b[p..p + 8].copy_from_slice(&onde.to_le_bytes());
            b[p + 8..p + 16].copy_from_slice(&tipo.to_le_bytes());
            b[p + 16..p + 24].copy_from_slice(&parcela.to_le_bytes());
        };
        relocacao(&mut b, 0, 0x210, u64::from(R_X86_64_RELATIVE), 0x1234);
        relocacao(&mut b, 1, 0x220, 1, 0);
        b
    }

    #[test]
    fn o_elf_se_le_com_os_segmentos_e_as_relocacoes() {
        let elf = ler_elf(elf_de_teste()).unwrap();
        assert_eq!(elf.segmentos.len(), 3);
        assert!(elf.segmentos[1].executavel());
        assert!(!elf.segmentos[0].executavel());
        assert_eq!(elf.programas, (64, 3 * 56));
        assert_eq!(elf.relocacoes.len(), 2);
        assert_eq!(elf.relocacoes[0].onde, 0x210);
        assert_eq!(elf.faixa(), Some((0, 0x400)));
        assert!(ler_elf(b"\x7fELF\x01\x01".to_vec()).is_err());
        assert!(ler_elf(vec![0; 64]).is_err());
        let mut truncado = elf_de_teste();
        truncado.truncate(100);
        assert!(ler_elf(truncado).is_err());
    }

    #[test]
    fn a_conferencia_aceita_o_mesmo_kernel_relocado_e_recusa_outro() {
        let base = 0xffff_8000_0000_0000u64;
        let bytes = elf_de_teste();
        let elf = ler_elf(bytes.clone()).unwrap();
        // A memória como o iniciador a deixa: o arquivo, com a relocação
        // relativa aplicada, e a outra com um valor qualquer.
        let mut memoria = bytes.clone();
        memoria[0x210..0x218].copy_from_slice(&base.wrapping_add(0x1234).to_le_bytes());
        memoria[0x220..0x228].fill(0x77);
        let mut m = MemoriaDeTeste {
            faixas: vec![(base, memoria.clone())],
            respostas: Vec::new(),
        };
        let c = conferir_na_memoria(&elf, base, &mut m, &[0]);
        assert!(c.confere, "{:?}", c.linhas);
        assert_eq!(c.codigo, 0x100);
        // Um byte de código diferente.
        let mut outra = memoria.clone();
        outra[0x2f0] ^= 1;
        let mut m = MemoriaDeTeste {
            faixas: vec![(base, outra)],
            respostas: Vec::new(),
        };
        let c = conferir_na_memoria(&elf, base, &mut m, &[0]);
        assert!(!c.confere);
        assert!(
            c.linhas.iter().any(|l| l.contains("+0xf0")),
            "{:?}",
            c.linhas
        );
        // A relocação sem aplicar: o kernel noutra base.
        let mut m = MemoriaDeTeste {
            faixas: vec![(base, bytes.clone())],
            respostas: Vec::new(),
        };
        assert!(!conferir_na_memoria(&elf, base, &mut m, &[0]).confere);
        // Nada na base.
        let mut m = MemoriaDeTeste {
            faixas: Vec::new(),
            respostas: Vec::new(),
        };
        let c = conferir_na_memoria(&elf, base, &mut m, &[0]);
        assert!(!c.confere);
        assert!(c.linhas[0].contains("nao se le"));
        // Os cabeçalhos de programa de outro ELF na base.
        let mut cabecalho = memoria;
        cabecalho[64] ^= 1;
        let mut m = MemoriaDeTeste {
            faixas: vec![(base, cabecalho)],
            respostas: Vec::new(),
        };
        assert!(!conferir_na_memoria(&elf, base, &mut m, &[0]).confere);
    }

    #[test]
    fn os_registradores_do_x86_e_do_arm_se_leem() {
        let x86 = "CPU#0\\r\\nRAX=0000000000000001 RBX=0000000000000002\\r\\n\
                   R8 =0000000000000008 R9 =0000000000000009\\r\\n\
                   RIP=ffff8000002a7c9f RFL=00000097 [--S-APC] CPL=0 II=0 A20=1 SMM=0 HLT=0\\r\\n\
                   ES =0000 0000000000000000 ffffffff 00c09300\\r\\n\
                   GDT=     ffff800000a00000 0000002f\\r\\n\
                   CPU#1\\r\\nRIP=ffff8000003d869d RFL=00000086 [--S--P-] CPL=0 HLT=1\\r\\nRSP=ffff900000001000";
        let lista = cpus(x86);
        assert_eq!(lista.len(), 2);
        assert_eq!(lista[0].numero_de("R8"), Some(8));
        assert_eq!(lista[0].numero_de("RAX"), Some(1));
        assert_eq!(lista[0].instrucao(), Some(0xffff_8000_002a_7c9f));
        assert_eq!(lista[0].campo("ES"), Some("0000"));
        assert_eq!(lista[0].campo("GDT"), None);
        assert_eq!(lista[1].pilha(), Some(0xffff_9000_0000_1000));
        let estado = estado_da_cpu(Arquitetura::X86_64, &lista[0]);
        assert!(estado.contains("interrupcoes desligadas"), "{estado}");
        assert!(estado.contains("[CF PF AF SF]"), "{estado}");
        assert!(estado.contains("fora de hlt"), "{estado}");
        assert!(estado_da_cpu(Arquitetura::X86_64, &lista[1]).contains("parada num hlt"));
        let arm = "CPU#0\n PC=0000000040081234 X00=0000000000000000 X01=0000000000000001\n\
                   X29=0000000040100000 X30=0000000040080010  SP=0000000040200000\n\
                   PSTATE=600003c5 -ZC- EL1h     FPCR=00000000 FPSR=00000000";
        let lista = cpus(arm);
        assert_eq!(lista[0].instrucao(), Some(0x4008_1234));
        assert_eq!(lista[0].pilha(), Some(0x4020_0000));
        assert_eq!(lista[0].numero_de("X30"), Some(0x4008_0010));
        let estado = estado_da_cpu(Arquitetura::Aarch64, &lista[0]);
        assert!(estado.contains("IRQ mascaradas"), "{estado}");
        assert!(estado.contains("DAIF mascaradas: DAIF"), "{estado}");
        assert!(estado.contains("EL1"), "{estado}");
    }

    #[test]
    fn a_tabela_do_nm_se_le_com_os_nomes_que_tem_espacos() {
        let texto = "0000000000001000 0000000000000020 t duke::serial::_print\n\
                     0000000000001020 0000000000000010 T <duke::X as core::fmt::Write>::write_str\n\
                     0000000000001030 t $x\n\
                     0000000000001040 b duke::serial::SAIDA_TRAVADA\n\
                     0000000000002000 0000000000000001 b duke::serial::SAIDA_TRAVADA2\n\
                                      U indefinido\n";
        let s = ler_a_tabela_do_nm(texto);
        assert_eq!(s.len(), 4, "{s:?}");
        assert_eq!(s[1].nome, "<duke::X as core::fmt::Write>::write_str");
        assert_eq!(s[1].tamanho, 0x10);
        assert_eq!(s[2].tipo, 'b');
        assert_eq!(s[2].tamanho, 0);
        let funcoes: Vec<Simbolo> = s
            .into_iter()
            .filter(|s| s.tipo == 't' || s.tipo == 'T')
            .collect();
        assert_eq!(
            funcao_em(&funcoes, 0x1004).map(|(f, d)| (f.nome.as_str(), d)),
            Some(("duke::serial::_print", 4))
        );
        assert_eq!(funcao_em(&funcoes, 0x1030), None);
        assert_eq!(funcao_em(&funcoes, 0xfff), None);
    }

    #[test]
    fn a_listagem_do_objdump_da_o_lugar_de_cada_instrucao() {
        let texto = "\nkernel: file format elf64-x86-64\n\nDisassembly of section .text:\n\n\
                     00000000002ceb30 <duke::serial::_print>:\n\
                     ; duke::serial::_print():\n\
                     ; /raiz/kernel/src/serial.rs:155\n\
                     \x20 2ceb30:      \tsubq\t$0x18, %rsp\n\
                     \x20 2ceb34:      \tmovq\t%rdi, 0x8(%rsp)\n\
                     ; /raiz/kernel/src/serial.rs:164\n\
                     \x20 2ceb43:      \tcallq\t0x30d930 <duke::arch::x86_64::sem_interrupcoes>\n\
                     ; /raiz/kernel/src/serial.rs:185\n\
                     \x20 2ceb48:      \taddq\t$0x18, %rsp\n";
        let l = ler_a_listagem(texto);
        assert_eq!(l.instrucoes.len(), 4);
        assert_eq!(
            l.instrucoes[0].local.as_deref(),
            Some("/raiz/kernel/src/serial.rs:155")
        );
        // O retorno depois da chamada: o lugar é o da chamada.
        let i = l.antes_de(0x2ceb48).unwrap();
        assert_eq!(
            l.instrucoes[i].local.as_deref(),
            Some("/raiz/kernel/src/serial.rs:164")
        );
        let i = l.em(0x2ceb48).unwrap();
        assert_eq!(
            l.instrucoes[i].local.as_deref(),
            Some("/raiz/kernel/src/serial.rs:185")
        );
        let volta = l.em_volta(l.em(0x2ceb43).unwrap());
        assert!(volta.contains("=> "), "{volta}");
        assert!(
            volta
                .lines()
                .any(|x| x.starts_with("=> ") && x.contains("callq")),
            "{volta}"
        );
    }

    #[test]
    fn as_chamadas_antes_de_um_retorno_se_reconhecem() {
        // call rel32
        assert!(chamada_antes_no_x86(&[0x90, 0xE8, 1, 2, 3, 4]));
        // call *%rax; call *%r11
        assert!(chamada_antes_no_x86(&[0xFF, 0xD0]));
        assert!(chamada_antes_no_x86(&[0x41, 0xFF, 0xD3]));
        // call *(%rax)
        assert!(chamada_antes_no_x86(&[0xFF, 0x10]));
        // call *0x8(%rax); call *0x10(%rsp) (SIB)
        assert!(chamada_antes_no_x86(&[0xFF, 0x50, 0x08]));
        assert!(chamada_antes_no_x86(&[0xFF, 0x54, 0x24, 0x10]));
        // call *0x1234(%rip); call *0x100(%rax)
        assert!(chamada_antes_no_x86(&[0xFF, 0x15, 0x34, 0x12, 0, 0]));
        assert!(chamada_antes_no_x86(&[0xFF, 0x90, 0, 1, 0, 0]));
        // O que não é: um dado qualquer, um jmp, um push.
        assert!(!chamada_antes_no_x86(&[0, 0, 0, 0, 0, 0, 0]));
        assert!(!chamada_antes_no_x86(&[0xE9, 1, 2, 3, 4]));
        assert!(!chamada_antes_no_x86(&[0xFF, 0x20]));
        assert!(!chamada_antes_no_x86(&[]));
        // bl e blr x8; um ret e um b não são.
        assert!(chamada_antes_no_arm(0x9400_0010));
        assert!(chamada_antes_no_arm(0xD63F_0100));
        assert!(!chamada_antes_no_arm(0xD65F_03C0));
        assert!(!chamada_antes_no_arm(0x1400_0010));
    }

    #[test]
    fn a_etapa_do_boot_e_a_do_ultimo_e_conta_as_linhas_em_branco() {
        let serial = "BdsDxe: loading Boot0001\n\
                      iniciador: vivo em x86_64, carregado pelo firmware\n\
                      [    0]        0ms info  boot     Duke iniciado\n\n\
                      !!! PANICO NO KERNEL !!!\n\
                      panicked at src/quedas.rs:331:9:\n\
                      queda: a versao nova cai antes de se confirmar\n\
                      tentativa da versao nova: reiniciando\n\
                      BdsDxe: loading Boot0001\n\
                      iniciador: vivo em x86_64, carregado pelo firmware\n\
                      iniciador: a maquina e do Duke; saltando para 0xffff800000429c30\n\
                      ==========\n\
                      [   65]     4460ms info  smp      4 de 4 nucleo(s) ligado(s)\n\
                      \r\n";
        let e = etapa_do_boot(&super::super::persistencia::sem_controles(
            serial.as_bytes(),
        ));
        assert_eq!(e.pelo_firmware, 2);
        assert_eq!(e.pelo_iniciador, 2);
        assert_eq!(e.etapa, "kernel");
        assert!(e.kernel.as_deref().unwrap().contains("[   65]"));
        assert_eq!(e.panico, None);
        assert_eq!(e.em_branco_depois, 1);
        let no_panico = etapa_do_boot(
            "iniciador: vivo em x\n[ 1] 0ms a\n!!! PANICO NO KERNEL !!!\npanicked at x\n",
        );
        assert_eq!(no_panico.etapa, "panico");
        assert_eq!(no_panico.panico.as_deref(), Some("panicked at x"));
        assert_eq!(etapa_do_boot("").etapa, "");
        assert_eq!(etapa_do_boot("UEFI firmware\n").etapa, "firmware");
        assert!(!e_passo_do_kernel("[abc] x"));
        assert!(e_passo_do_kernel("  [ 12] x"));
    }

    #[test]
    fn os_quadros_de_interrupcao_do_anel_zero_se_acham_na_pilha() {
        let codigo = |v: u64| (0xffff_8000_0010_0000..0xffff_8000_0090_0000).contains(&v);
        let rip = 0xffff_8000_0040_1234;
        let pilha = [
            7,
            rip,
            CS_DO_KERNEL,
            0x246,
            0xffff_9000_0000_1000,
            0x10,
            // Um com o SS nulo, o que o kernel herda do anel três.
            rip + 4,
            CS_DO_KERNEL,
            0x86,
            0xffff_9000_0000_2000,
            0,
        ];
        let q = quadros_de_interrupcao(&pilha, 0x1000, codigo);
        assert_eq!(q.len(), 2, "{q:?}");
        assert_eq!(
            q[0],
            Quadro {
                em: 0x1008,
                rip,
                rflags: 0x246,
                rsp: 0xffff_9000_0000_1000
            }
        );
        assert_eq!(q[1].em, 0x1030);
        assert_eq!(q[1].rflags & 0x200, 0);
        // O que não é: o CS do usuário, o RFLAGS sem o bit 1 ou com um
        // reservado, o RSP que não é canônico, o SS do usuário, o RIP fora
        // do código.
        for estragado in [
            [rip, 0x2b, 0x246, 0x1000, 0x10],
            [rip, CS_DO_KERNEL, 0x244, 0x1000, 0x10],
            [rip, CS_DO_KERNEL, 0x246 | 0x8, 0x1000, 0x10],
            [rip, CS_DO_KERNEL, 0x246 | (1 << 22), 0x1000, 0x10],
            [rip, CS_DO_KERNEL, 0x246, 0x0000_9000_0000_0000, 0x10],
            [rip, CS_DO_KERNEL, 0x246, 0x1000, 0x23],
            [0x1234, CS_DO_KERNEL, 0x246, 0x1000, 0x10],
        ] {
            assert!(
                quadros_de_interrupcao(&estragado, 0, codigo).is_empty(),
                "{estragado:x?}"
            );
        }
    }

    /// Um emulador de teste cujo monitor traduz endereços: o virtual é o
    /// físico mais `deslocamento`, e responde ao `cpu N` sem dizer nada.
    struct Traduzido {
        memoria: MemoriaDeTeste,
        deslocamento: u64,
        perguntas: Vec<String>,
    }

    impl Memoria for Traduzido {
        fn ler(&mut self, cpu: u32, endereco: u64, tamanho: usize) -> Option<Vec<u8>> {
            self.memoria.ler(cpu, endereco, tamanho)
        }
    }

    impl Emulador for Traduzido {
        fn monitor(&mut self, comando: &str) -> Result<String, String> {
            self.perguntas.push(comando.to_string());
            if comando.starts_with("cpu ") {
                return Ok(String::new());
            }
            let v = comando
                .strip_prefix("gva2gpa 0x")
                .and_then(|h| u64::from_str_radix(h, 16).ok())
                .ok_or("comando desconhecido")?;
            Ok(format!("gpa: {:#x}\n", v.wrapping_sub(self.deslocamento)))
        }
    }

    /// A pilha só se lê nas páginas que caem na RAM, pela tradução da
    /// própria CPU: uma pilha toda na RAM vem inteira; a que passa do fim
    /// dela para na página de fora; e a que começa num dispositivo não lê
    /// nada — nem pede a leitura.
    #[test]
    fn a_pilha_so_se_le_na_ram() {
        let ram = [(0x1000_0000, 0x1000_4000)];
        let deslocamento = 0x20_0000_0000;
        let virtual_ = |f: u64| f + deslocamento;
        let mut e = Traduzido {
            memoria: MemoriaDeTeste {
                faixas: vec![(virtual_(0x1000_0000), vec![7; 0x8000])],
                respostas: Vec::new(),
            },
            deslocamento,
            perguntas: Vec::new(),
        };
        assert_eq!(
            ler_na_ram(&mut e, 2, virtual_(0x1000_0000), 0x4000, &ram).len(),
            0x4000
        );
        assert!(e.perguntas.contains(&"cpu 2".to_string()));
        // Do meio da última página da RAM, 8 KiB: só até o fim dela.
        assert_eq!(
            ler_na_ram(&mut e, 0, virtual_(0x1000_3800), 0x2000, &ram).len(),
            0x800
        );
        // Num dispositivo (o físico fora da RAM): nada.
        let mut no_dispositivo = Traduzido {
            memoria: MemoriaDeTeste {
                faixas: vec![(0x0800_0000 + deslocamento, vec![7; 0x1000])],
                respostas: Vec::new(),
            },
            deslocamento,
            perguntas: Vec::new(),
        };
        assert!(
            ler_na_ram(
                &mut no_dispositivo,
                0,
                0x0800_0000 + deslocamento,
                0x1000,
                &ram
            )
            .is_empty()
        );
        // Um monitor que não traduz: nada.
        let mut mudo = MemoriaDeTeste {
            faixas: vec![(0x1000_0000, vec![7; 0x1000])],
            respostas: Vec::new(),
        };
        assert!(ler_na_ram(&mut mudo, 0, 0x1000_0000, 0x1000, &ram).is_empty());
    }

    #[test]
    fn os_caminhos_do_dwarf_ficam_curtos() {
        let raiz = super::super::raiz_do_projeto();
        assert_eq!(
            curto(&format!("{}/kernel/src/main.rs:659", raiz.display())),
            "kernel/src/main.rs:659"
        );
        assert_eq!(
            curto(
                "/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/x86_64-0.15.5/src/instructions/mod.rs:21"
            ),
            "x86_64-0.15.5/src/instructions/mod.rs:21"
        );
        assert_eq!(
            curto("/rustc/0123abcd/library/core/src/cmp.rs:1557"),
            "core/src/cmp.rs:1557"
        );
        assert_eq!(curto("/outro/lugar.rs:1"), "/outro/lugar.rs:1");
    }

    #[test]
    fn os_ultimos_bytes_mostram_os_controles() {
        assert_eq!(ultimos_bytes(b"ab\r\n\x1b[0m", 6), "\\r\\n\\x1b[0m");
        assert_eq!(ultimos_bytes(b"x\\y", 10), "x\\\\y");
    }

    #[test]
    fn a_uart_e_o_monitor_se_leem() {
        assert_eq!(valor_da_porta("portb[0x03fd] = 0x60\n"), Some(0x60));
        assert_eq!(valor_da_porta("sem igual"), None);
        assert!(lsr_em_palavras(0x60).contains("o transmissor vazio"));
        assert!(lsr_em_palavras(0x60).contains("[THRE TEMT]"));
        assert!(lsr_em_palavras(0x00).contains("cheia"));
        assert_eq!(
            texto_do_monitor("{\"return\": \"portb[0x03fd] = 0x60\\r\\n\"}\n").unwrap(),
            "portb[0x03fd] = 0x60\n"
        );
        assert!(texto_do_monitor("{\"error\": {\"class\": \"GenericError\"}}").is_err());
        let pedido = pedido_ao_monitor("info lapic 1").unwrap();
        assert!(
            pedido.contains("\"command-line\":\"info lapic 1\""),
            "{pedido}"
        );
    }

    #[test]
    fn o_incidente_sem_kernel_desta_execucao_diz_isso_e_guarda_o_resto() {
        let raiz = std::env::temp_dir().join(format!("incidente-teste-{}", std::process::id()));
        let serial = raiz.join("serial");
        std::fs::create_dir_all(&raiz).unwrap();
        std::fs::write(&serial, "iniciador: vivo em aarch64\n[ 3] 0ms passo\n").unwrap();
        let mut m = MemoriaDeTeste {
            faixas: Vec::new(),
            respostas: vec![("info cpus".to_string(), "* CPU #0: thread_id=1".to_string())],
        };
        let registros = "CPU#0\n PC=0000000040081234 X30=0000000040080010 SP=0000000040200000\nPSTATE=000003c5 ---- EL1h";
        let i = guardar(
            &Parada {
                arch: Arquitetura::Aarch64,
                motivo: "o teste",
                status: "running",
                registros,
                serial: Some(&serial),
                ram: &[(0x4000_0000, 0x4800_0000)],
            },
            &mut m,
            &raiz,
        );
        let dir = i.dir.clone().expect("o diretorio do incidente");
        assert!(i.kernel.is_none());
        assert_eq!(i.cpus.len(), 1);
        assert_eq!(i.cpus[0].instrucao, 0x4008_1234);
        assert_eq!(i.etapa.as_ref().map(|e| e.etapa), Some("kernel"));
        let resumo = std::fs::read_to_string(dir.join("resumo.txt")).unwrap();
        assert!(resumo.contains("CPU#0"), "{resumo}");
        assert!(resumo.contains("IRQ mascaradas"), "{resumo}");
        assert!(dir.join("registradores.txt").exists());
        assert!(
            std::fs::read_to_string(dir.join("monitor.txt"))
                .unwrap()
                .contains("thread_id")
        );
        assert_eq!(
            std::fs::read(dir.join("serial.txt")).unwrap(),
            std::fs::read(&serial).unwrap()
        );
        assert!(i.resumo[0].starts_with("o incidente: "));
        let _ = std::fs::remove_dir_all(&raiz);
    }
}
