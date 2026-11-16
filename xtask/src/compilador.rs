//! O compilador oficial do Duke OS — a política de "O compilador", no
//! `CLAUDE.md`.
//!
//! O canal é um nightly com data — `nightly-AAAA-MM-DD` —, o mesmo no
//! `rust-toolchain.toml` da raiz e no do modelo do SDK, e só muda por uma
//! promoção. Daqui saem três conferências:
//!
//! - **no começo de todo `cargo xtask`** ([`conferir_ao_iniciar`]): o
//!   compilador que vai compilar é o do canal oficial. O toolchain ativo é o
//!   do sysroot do `rustc` que o cargo chamaria — o mesmo que compilou este
//!   `xtask`, e que compila por ele o kernel, os programas, o iniciador e o
//!   modelo do SDK —, e o nome dele tem de ser o canal com o host. E nada
//!   troca ou embrulha o compilador por fora do `rust-toolchain.toml`: as
//!   variáveis de [`VARIAVEIS_QUE_TROCAM`], e as chaves `build.rustc`,
//!   `build.rustc-wrapper` e `build.rustc-workspace-wrapper` de um
//!   `config.toml` do cargo de fora do repositório (os dele são conferidos
//!   nas fontes). Um desvio recusa o comando, a menos que
//!   `DUKE_OUTRO_COMPILADOR=1` declare a execução **não oficial**: aí ele
//!   avisa alto, e a proveniência dos artefatos (`xtask/src/proveniencia.rs`)
//!   registra `"oficial": false`. Não é uma barreira contra quem quer
//!   contornar — o código está aqui —; é o fim do desvio silencioso: o
//!   `+nightly` de costume, um `rustup override` esquecido, o
//!   `RUSTUP_TOOLCHAIN` de outra sessão, um `sccache` configurado para a
//!   máquina inteira;
//! - **no `cargo xtask invariantes`** ([`conferir_o_canal`]): o canal tem
//!   data e é o mesmo nos dois arquivos; não há outro `rust-toolchain` no
//!   repositório; nenhum `.cargo/config.toml` dele troca o compilador; os
//!   workflows oficiais não sobrepõem o toolchain e conferem o compilador —
//!   a ação `.github/actions/compilador` — depois de cada checkout, antes do
//!   cache e de qualquer `cargo`, com o canal na chave de todo cache; o
//!   canário, o único que sobrepõe — ele testa o candidato —, não usa o
//!   cache da CI nem publica proveniência; e o `xtask` não chama o cargo nem
//!   o rustc com outro toolchain;
//! - **no `cargo xtask compilador`** ([`relatar`]): o canal, o toolchain
//!   ativo, o `rustc -Vv` completo, o `cargo -V` e os desvios — o que todo
//!   relatório de validação cita.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::OnceLock;

/// O opt-in de uma execução não oficial, com outro compilador: só o valor
/// `1` vale.
pub(crate) const OUTRO_COMPILADOR: &str = "DUKE_OUTRO_COMPILADOR";

/// O arquivo que manda no canal.
const TOOLCHAIN_DA_RAIZ: &str = "rust-toolchain.toml";

/// O do modelo do SDK, que segue o da raiz.
const TOOLCHAIN_DO_MODELO: &str = "sdk/modelo/rust-toolchain.toml";

/// As variáveis com que o cargo troca, ou embrulha, o compilador por fora
/// do `rust-toolchain.toml`.
const VARIAVEIS_QUE_TROCAM: [&str; 6] = [
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
];

/// As chaves de um `config.toml` do cargo que fazem o mesmo.
const CHAVES_QUE_TROCAM: [&str; 3] = [
    "build.rustc",
    "build.rustc-wrapper",
    "build.rustc-workspace-wrapper",
];

/// O que, num workflow oficial, sobrepõe ou troca o compilador do
/// `rust-toolchain.toml`. `RUSTC` cobre também `RUSTC_WRAPPER`,
/// `RUSTC_WORKSPACE_WRAPPER` e as `CARGO_BUILD_RUSTC*`.
const SOBREPOSICOES: [&str; 11] = [
    "RUSTUP_TOOLCHAIN",
    "DUKE_OUTRO_COMPILADOR",
    "RUSTC",
    "cargo +",
    "rustc +",
    "rustup default",
    "rustup override",
    "rustup run",
    "rustup toolchain install",
    "dtolnay/rust-toolchain",
    "actions-rs/toolchain",
];

/// O workflow do canário: o único que sobrepõe o compilador.
const CANARIO: &str = ".github/workflows/canario.yml";

/// Onde a política está escrita, com a versão em vigor.
const POLITICA: &str = "CLAUDE.md";

/// A CI oficial, e o job dela cujos comandos o canário repete.
const CI: &str = ".github/workflows/ci.yml";
const JOB_DE_LINTS: &str = "qualidade";

/// O compilador desta execução, como [`observar`] o viu.
pub(crate) struct Compilador {
    /// O canal oficial, do `rust-toolchain.toml` da raiz — ou por que não
    /// há um.
    pub(crate) canal: Result<String, String>,
    /// O toolchain ativo: o nome do diretório do sysroot do `rustc`.
    pub(crate) toolchain: Option<String>,
    /// O sysroot inteiro.
    pub(crate) sysroot: Option<String>,
    /// O `rustc -Vv`, completo.
    pub(crate) rustc: Option<String>,
    /// O `cargo -V` do cargo com que o `xtask` compila.
    pub(crate) cargo: Option<String>,
    /// O que afasta esta execução do compilador oficial. Vazio, ela é
    /// oficial.
    pub(crate) desvios: Vec<String>,
    /// A execução se declarou não oficial: `DUKE_OUTRO_COMPILADOR=1`.
    pub(crate) declarada_nao_oficial: bool,
}

impl Compilador {
    /// O compilador é o oficial, sem desvio nenhum.
    pub(crate) fn oficial(&self) -> bool {
        self.desvios.is_empty()
    }
}

/// O compilador desta execução, observado uma vez.
pub(crate) fn estado() -> &'static Compilador {
    static ESTADO: OnceLock<Compilador> = OnceLock::new();
    ESTADO.get_or_init(observar)
}

/// Observa o compilador: o canal oficial, o toolchain ativo, as versões e
/// os desvios.
fn observar() -> Compilador {
    let raiz = super::raiz_do_projeto();
    let mut desvios = Vec::new();

    let canal = std::fs::read_to_string(raiz.join(TOOLCHAIN_DA_RAIZ))
        .map_err(|e| format!("{TOOLCHAIN_DA_RAIZ}: não se lê: {e}"))
        .and_then(|texto| {
            canal_do_arquivo(&texto).ok_or_else(|| format!("{TOOLCHAIN_DA_RAIZ}: sem `channel`"))
        })
        .and_then(|canal| {
            conferir_a_data(&canal)
                .map(|()| canal)
                .map_err(|e| format!("{TOOLCHAIN_DA_RAIZ}: {e}"))
        });
    if let Err(e) = &canal {
        desvios.push(e.clone());
    }

    // O rustc que o cargo chamaria: o da variável, se houver, ou o do PATH
    // — o proxy do rustup, que resolve o toolchain como resolveu o deste
    // processo (o rustup passa o que resolveu adiante, no
    // `RUSTUP_TOOLCHAIN`).
    let rustc = std::env::var_os("RUSTC")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "rustc".into());
    let saida = |args: &[&str]| {
        Command::new(&rustc)
            .args(args)
            .current_dir(&raiz)
            .output()
            .ok()
            .filter(|s| s.status.success())
            .map(|s| String::from_utf8_lossy(&s.stdout).trim().to_string())
    };
    let sysroot = saida(&["--print", "sysroot"]);
    let vv = saida(&["-Vv"]);
    let toolchain = sysroot
        .as_deref()
        .and_then(|s| Path::new(s).file_name())
        .map(|n| n.to_string_lossy().into_owned());
    match (toolchain.as_deref(), vv.as_deref().and_then(host_do_rustc)) {
        (Some(toolchain), Some(host)) => {
            if let Some(d) = canal
                .as_deref()
                .ok()
                .and_then(|canal| desvio_do_toolchain(canal, toolchain, host))
            {
                desvios.push(d);
            }
        }
        _ => desvios.push(format!(
            "o rustc (`{}`) não respondeu a `--print sysroot` e a `-Vv`",
            rustc.to_string_lossy()
        )),
    }

    desvios.extend(desvios_das_variaveis(|nome| std::env::var(nome).ok()));
    for arquivo in configuracoes_de_fora(&raiz) {
        if let Ok(texto) = std::fs::read_to_string(&arquivo) {
            for chave in chaves_que_trocam_o_compilador(&texto) {
                desvios.push(format!(
                    "{}: `{chave}` troca o compilador do cargo",
                    arquivo.display()
                ));
            }
        }
    }

    let cargo = Command::new(env!("CARGO"))
        .arg("-V")
        .output()
        .ok()
        .filter(|s| s.status.success())
        .map(|s| String::from_utf8_lossy(&s.stdout).trim().to_string());

    Compilador {
        canal,
        toolchain,
        sysroot,
        rustc: vv,
        cargo,
        desvios,
        declarada_nao_oficial: std::env::var(OUTRO_COMPILADOR).is_ok_and(|v| v == "1"),
    }
}

/// O valor de `channel` num `rust-toolchain.toml`, sem as aspas.
pub(crate) fn canal_do_arquivo(texto: &str) -> Option<String> {
    texto
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|linha| {
            let (chave, valor) = linha.split_once('=')?;
            if chave.trim() != "channel" {
                return None;
            }
            let valor = valor.trim();
            let aspa = valor.chars().next().filter(|c| *c == '"' || *c == '\'')?;
            let dentro = &valor[1..];
            dentro.find(aspa).map(|fim| dentro[..fim].to_string())
        })
}

/// O canal é um nightly com data: `nightly-AAAA-MM-DD`, num dia que existe.
pub(crate) fn conferir_a_data(canal: &str) -> Result<(), String> {
    let recusa = || {
        Err(format!(
            "o canal `{canal}` não é um nightly com data (`nightly-AAAA-MM-DD`)"
        ))
    };
    let Some(data) = canal.strip_prefix("nightly-") else {
        return recusa();
    };
    let partes: Vec<&str> = data.split('-').collect();
    let [ano, mes, dia] = partes.as_slice() else {
        return recusa();
    };
    let numero = |texto: &str, digitos: usize| {
        (texto.len() == digitos && texto.bytes().all(|b| b.is_ascii_digit()))
            .then(|| texto.parse::<u32>().ok())
            .flatten()
    };
    let (Some(ano), Some(mes), Some(dia)) = (numero(ano, 4), numero(mes, 2), numero(dia, 2)) else {
        return recusa();
    };
    let bissexto = (ano % 4 == 0 && ano % 100 != 0) || ano % 400 == 0;
    let dias_do_mes = match mes {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if bissexto => 29,
        2 => 28,
        _ => return recusa(),
    };
    if (1..=dias_do_mes).contains(&dia) {
        Ok(())
    } else {
        recusa()
    }
}

/// O host do `rustc -Vv`: a linha `host: ...`.
fn host_do_rustc(vv: &str) -> Option<&str> {
    vv.lines()
        .find_map(|l| l.trim().strip_prefix("host:"))
        .map(str::trim)
        .filter(|h| !h.is_empty())
}

/// O desvio do toolchain ativo, se ele não é o do canal com o host — o nome
/// que o rustup dá ao toolchain que instala do `rust-toolchain.toml`.
fn desvio_do_toolchain(canal: &str, toolchain: &str, host: &str) -> Option<String> {
    let oficial = format!("{canal}-{host}");
    (toolchain != oficial).then(|| {
        format!(
            "o toolchain ativo é `{toolchain}`, e o oficial é `{oficial}` ({TOOLCHAIN_DA_RAIZ})"
        )
    })
}

/// As variáveis de [`VARIAVEIS_QUE_TROCAM`] definidas, como desvios.
fn desvios_das_variaveis(ler: impl Fn(&str) -> Option<String>) -> Vec<String> {
    VARIAVEIS_QUE_TROCAM
        .iter()
        .filter_map(|nome| {
            ler(nome)
                .filter(|v| !v.is_empty())
                .map(|v| format!("a variável `{nome}={v}` troca o compilador do cargo"))
        })
        .collect()
}

/// As chaves de [`CHAVES_QUE_TROCAM`] num `config.toml` do cargo, pelo nome
/// completo — a da tabela `[build]` e a pontuada, `build.rustc = ...`.
fn chaves_que_trocam_o_compilador(texto: &str) -> Vec<String> {
    let mut tabela = String::new();
    let mut achadas = Vec::new();
    for linha in texto.lines().map(str::trim) {
        if linha.is_empty() || linha.starts_with('#') {
            continue;
        }
        if let Some(nome) = linha.strip_prefix('[') {
            tabela = nome.trim_end_matches(']').trim().to_string();
            continue;
        }
        let Some((chave, _)) = linha.split_once('=') else {
            continue;
        };
        let chave = chave.trim().trim_matches('"');
        let completa = if tabela.is_empty() {
            chave.to_string()
        } else {
            format!("{tabela}.{chave}")
        };
        if CHAVES_QUE_TROCAM.contains(&completa.as_str()) {
            achadas.push(completa);
        }
    }
    achadas
}

/// Os `config.toml` do cargo de fora do repositório que valem para os
/// builds dele: os dos diretórios acima da raiz, e o do `CARGO_HOME`.
fn configuracoes_de_fora(raiz: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = raiz.ancestors().skip(1).map(|d| d.join(".cargo")).collect();
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")));
    if let Some(home) = cargo_home
        && !dirs.contains(&home)
    {
        dirs.push(home);
    }
    dirs.iter()
        .flat_map(|d| [d.join("config.toml"), d.join("config")])
        .filter(|a| a.is_file())
        .collect()
}

/// A conferência do começo de todo `cargo xtask` — menos o `compilador`,
/// que a relata, e o `help`.
pub(crate) fn conferir_ao_iniciar() -> Result<(), String> {
    let c = estado();
    if c.oficial() {
        if c.declarada_nao_oficial {
            eprintln!(
                "[xtask] {OUTRO_COMPILADOR}=1, mas o compilador é o oficial: a execução segue oficial"
            );
        }
        return Ok(());
    }
    let lista = c
        .desvios
        .iter()
        .map(|d| format!("  - {d}"))
        .collect::<Vec<_>>()
        .join("\n");
    if c.declarada_nao_oficial {
        eprintln!(
            "[xtask] AVISO: execução NÃO OFICIAL ({OUTRO_COMPILADOR}=1) — o compilador não é o oficial:\n\
             {lista}\n\
             [xtask] nada desta execução vale como validação oficial; a proveniência dos artefatos \
             registra \"oficial\": false"
        );
        Ok(())
    } else {
        Err(format!(
            "o compilador não é o oficial:\n{lista}\n\n\
             O compilador oficial é o canal do {TOOLCHAIN_DA_RAIZ} (ver \"O compilador\" no \
             CLAUDE.md). Rode sem `+toolchain`, sem `RUSTUP_TOOLCHAIN`, sem `rustup override` neste \
             diretório e sem as variáveis e chaves acima: o rustup instala o canal sozinho. \
             `cargo xtask compilador` mostra o estado. Uma execução não oficial, de propósito: \
             {OUTRO_COMPILADOR}=1 cargo xtask ..."
        ))
    }
}

/// `cargo xtask compilador`: o canal oficial, o toolchain ativo, as versões
/// completas e os desvios. Sai com sucesso só com o compilador oficial.
pub(crate) fn relatar() -> Result<ExitCode, String> {
    let c = estado();
    let raiz = super::raiz_do_projeto();
    let do_modelo = std::fs::read_to_string(raiz.join(TOOLCHAIN_DO_MODELO))
        .ok()
        .and_then(|t| canal_do_arquivo(&t));
    let nao = "(não se lê)";
    println!(
        "o canal oficial ({TOOLCHAIN_DA_RAIZ}): {}",
        c.canal.as_deref().unwrap_or(nao)
    );
    println!(
        "o canal do modelo do SDK ({TOOLCHAIN_DO_MODELO}): {}",
        do_modelo.as_deref().unwrap_or(nao)
    );
    println!(
        "o toolchain ativo: {}",
        c.toolchain.as_deref().unwrap_or(nao)
    );
    println!("o sysroot: {}", c.sysroot.as_deref().unwrap_or(nao));
    println!("o rustc -Vv:");
    for linha in c.rustc.as_deref().unwrap_or(nao).lines() {
        println!("    {linha}");
    }
    println!("o cargo -V: {}", c.cargo.as_deref().unwrap_or(nao));
    if c.oficial() {
        println!("os desvios: nenhum — o compilador é o oficial");
        return Ok(ExitCode::SUCCESS);
    }
    println!("os desvios:");
    for d in &c.desvios {
        println!("  - {d}");
    }
    if c.declarada_nao_oficial {
        println!("a execução: NÃO oficial ({OUTRO_COMPILADOR}=1)");
    } else {
        println!(
            "sem {OUTRO_COMPILADOR}=1, os outros comandos do xtask recusam rodar com este compilador"
        );
    }
    Ok(ExitCode::FAILURE)
}

/// O compilador nas fontes — parte do `cargo xtask invariantes`; ver o
/// começo do módulo.
pub(crate) fn conferir_o_canal() -> Result<ExitCode, String> {
    let raiz = super::raiz_do_projeto();
    let ler = |arquivo: &str| {
        std::fs::read_to_string(raiz.join(arquivo))
            .map_err(|e| format!("não foi possível ler {arquivo}: {e}"))
    };
    let mut fora: Vec<String> = Vec::new();

    let canal = canal_do_arquivo(&ler(TOOLCHAIN_DA_RAIZ)?);
    match &canal {
        None => fora.push(format!("{TOOLCHAIN_DA_RAIZ}: sem `channel`")),
        Some(c) => {
            if let Err(e) = conferir_a_data(c) {
                fora.push(format!("{TOOLCHAIN_DA_RAIZ}: {e}"));
            }
            // A política escrita cita a versão em vigor: uma promoção que
            // esquece o CLAUDE.md para aqui.
            if !citada_no_texto(c, &ler(POLITICA)?) {
                fora.push(format!(
                    "{POLITICA}: a seção \"O compilador\" não cita o canal oficial, `{c}`"
                ));
            }
        }
    }
    let do_modelo = canal_do_arquivo(&ler(TOOLCHAIN_DO_MODELO)?);
    if do_modelo != canal {
        fora.push(format!(
            "{TOOLCHAIN_DO_MODELO}: o canal `{}` não é o da raiz, `{}` — uma promoção troca os dois juntos",
            do_modelo.as_deref().unwrap_or("(nenhum)"),
            canal.as_deref().unwrap_or("(nenhum)")
        ));
    }

    let arquivos = arquivos_do_repositorio(&raiz)?;
    let mut workflows = Vec::new();
    for arquivo in &arquivos {
        let nome = Path::new(arquivo)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if (nome == "rust-toolchain" || nome == "rust-toolchain.toml")
            && arquivo != TOOLCHAIN_DA_RAIZ
            && arquivo != TOOLCHAIN_DO_MODELO
        {
            fora.push(format!(
                "{arquivo}: outro rust-toolchain no repositório — o canal é um só, o da raiz"
            ));
        }
        if arquivo.ends_with(".cargo/config.toml") || arquivo.ends_with(".cargo/config") {
            for chave in chaves_que_trocam_o_compilador(&ler(arquivo)?) {
                fora.push(format!("{arquivo}: `{chave}` troca o compilador do cargo"));
            }
        }
        if arquivo.starts_with(".github/workflows/")
            && (arquivo.ends_with(".yml") || arquivo.ends_with(".yaml"))
        {
            workflows.push((arquivo.clone(), ler(arquivo)?));
        }
        if arquivo.starts_with("xtask/src/")
            && arquivo.ends_with(".rs")
            && arquivo != "xtask/src/compilador.rs"
        {
            fora.extend(chamadas_com_outro_toolchain(arquivo, &ler(arquivo)?));
        }
    }
    fora.extend(conferir_os_workflows(&workflows));
    let texto_de = |nome: &str| {
        workflows
            .iter()
            .find(|(n, _)| n == nome)
            .map(|(_, t)| t.as_str())
    };
    if let (Some(ci), Some(canario)) = (texto_de(CI), texto_de(CANARIO)) {
        fora.extend(o_canario_repete_os_lints(ci, canario));
    }

    if fora.is_empty() {
        println!(
            "[xtask] o compilador: o canal {}, com data, nos dois rust-toolchain.toml e no CLAUDE.md; nenhum \
             outro, nenhuma troca nos config.toml do cargo nem no xtask; os workflows oficiais \
             conferem o compilador depois de cada checkout, com o canal na chave de todo cache, \
             e só o canário sobrepõe, sem o cache da CI",
            canal.as_deref().unwrap_or("")
        );
        Ok(ExitCode::SUCCESS)
    } else {
        for f in &fora {
            println!("[xtask] {f}");
        }
        Ok(ExitCode::FAILURE)
    }
}

/// O canal citado em `texto` como ele mesmo — entre crases —, e não como
/// o começo de outro: `nightly-2026-11-15` não vale por
/// `nightly-2026-11-150`.
fn citada_no_texto(canal: &str, texto: &str) -> bool {
    texto.contains(&format!("`{canal}`"))
}

/// Os arquivos do repositório, versionados ou não, menos os ignorados —
/// pelo git, que já sabe o que é do repositório e o que é de build.
fn arquivos_do_repositorio(raiz: &Path) -> Result<Vec<String>, String> {
    let saida = Command::new("git")
        .current_dir(raiz)
        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
        .output()
        .map_err(|e| format!("o git não rodou: {e}"))?;
    if !saida.status.success() {
        return Err(format!(
            "o git ls-files falhou: {}",
            String::from_utf8_lossy(&saida.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&saida.stdout)
        .lines()
        .filter(|a| raiz.join(a).is_file())
        .map(String::from)
        .collect())
}

/// As linhas de uma fonte do `xtask` que chamariam o cargo ou o rustc com
/// outro toolchain: um `+toolchain` ou uma variável que troca o compilador
/// posta no processo filho.
fn chamadas_com_outro_toolchain(arquivo: &str, fonte: &str) -> Vec<String> {
    let mut proibidos: Vec<String> = ["\"+nightly", "\"+stable", "\"+beta"]
        .iter()
        .map(|p| (*p).to_string())
        .collect();
    proibidos.extend(
        VARIAVEIS_QUE_TROCAM
            .iter()
            .chain(&["RUSTUP_TOOLCHAIN"])
            .map(|v| format!(".env(\"{v}\"")),
    );
    fonte
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .filter(|(_, l)| proibidos.iter().any(|p| l.contains(p.as_str())))
        .map(|(n, l)| {
            format!(
                "{arquivo}:{}: `{}` chama o cargo ou o rustc com outro toolchain",
                n + 1,
                l.trim()
            )
        })
        .collect()
}

/// Os workflows: os oficiais não sobrepõem o compilador e o conferem —
/// `./.github/actions/compilador`, com `id: compilador` — depois de cada
/// checkout, antes do cache e de qualquer `cargo`; e toda chave de cache,
/// a principal e as de restauração, leva o canal. O canário sobrepõe, mas
/// não usa o cache nem publica a proveniência.
fn conferir_os_workflows(workflows: &[(String, String)]) -> Vec<String> {
    let mut fora = Vec::new();
    for (nome, texto) in workflows {
        let linhas: Vec<&str> = texto
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .collect();
        if nome == CANARIO {
            if linhas.iter().any(|l| l.contains("actions/cache")) {
                fora.push(format!(
                    "{nome}: o canário usa o actions/cache — ele não toca no cache da CI oficial"
                ));
            }
            if linhas.iter().any(|l| l.contains("target/proveniencia")) {
                fora.push(format!(
                    "{nome}: o canário publica a proveniência — ele não produz artefato oficial"
                ));
            }
            continue;
        }
        for l in &linhas {
            if let Some(p) = SOBREPOSICOES.iter().find(|p| l.contains(*p)) {
                fora.push(format!(
                    "{nome}: `{l}` — `{p}` sobrepõe o compilador do {TOOLCHAIN_DA_RAIZ}"
                ));
            }
        }
        let mut pendente = false;
        for l in &linhas {
            if l.contains("uses: actions/checkout") {
                if pendente {
                    fora.push(format!(
                        "{nome}: um checkout sem a conferência do compilador depois"
                    ));
                }
                pendente = true;
            } else if l.contains("uses: ./.github/actions/compilador") {
                pendente = false;
            } else if pendente && (l.contains("actions/cache") || l.contains("cargo ")) {
                fora.push(format!(
                    "{nome}: `{l}` vem antes da conferência do compilador"
                ));
                pendente = false;
            }
        }
        if pendente {
            fora.push(format!(
                "{nome}: um checkout sem a conferência do compilador depois"
            ));
        }
        let usos = linhas
            .iter()
            .filter(|l| l.contains("uses: ./.github/actions/compilador"))
            .count();
        let ids = linhas.iter().filter(|l| **l == "id: compilador").count();
        if usos != ids {
            fora.push(format!(
                "{nome}: {usos} conferência(s) do compilador e {ids} `id: compilador` — a chave do \
                 cache lê o canal de `steps.compilador`"
            ));
        }
        let mut chaves: Vec<&str> = Vec::new();
        let mut em_bloco = false;
        for l in &linhas {
            if em_bloco {
                if l.is_empty() || l.contains(": ") || l.ends_with(':') || l.starts_with("- ") {
                    em_bloco = false;
                } else {
                    chaves.push(l);
                    continue;
                }
            }
            if let Some(valor) = l
                .strip_prefix("key:")
                .or_else(|| l.strip_prefix("restore-keys:"))
            {
                match valor.trim() {
                    "|" => em_bloco = true,
                    valor => chaves.push(valor),
                }
            }
        }
        for chave in chaves {
            if !chave.contains("steps.compilador.outputs.canal") {
                fora.push(format!(
                    "{nome}: a chave de cache `{chave}` não leva o canal do compilador"
                ));
            }
        }
    }
    fora
}

/// O canário repete os comandos do job de lints da CI oficial: um comando
/// de lá que faltasse aqui seria uma conferência que o candidato não passa,
/// e o canário diria "aprovado" sem ela. Os comandos são as linhas dos
/// `run:` do job que chamam o cargo ou o rustfmt, a instalação dos pacotes
/// e as variáveis dos passos; o canário pode ter mais, e roda os dele com
/// `--no-fail-fast`.
fn o_canario_repete_os_lints(ci: &str, canario: &str) -> Vec<String> {
    let normal = |texto: &str| texto.split_whitespace().collect::<Vec<_>>().join(" ");
    let canario = normal(
        &canario
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .replace(" --no-fail-fast", "");
    let comandos = comandos_do_job(ci, JOB_DE_LINTS);
    if comandos.is_empty() {
        return vec![format!(
            "{CI}: o job `{JOB_DE_LINTS}` não foi achado, ou não tem comando — o canário repete os dele"
        )];
    }
    comandos
        .into_iter()
        .map(|c| normal(&c))
        .filter(|c| !canario.contains(c.as_str()))
        .map(|c| {
            format!(
                "{CANARIO}: não repete `{c}`, do job `{JOB_DE_LINTS}` da CI oficial — quando a CI muda, o canário muda junto"
            )
        })
        .collect()
}

/// Os comandos de um job de um workflow: as linhas dos `run:` que chamam o
/// cargo ou o rustfmt, a instalação dos pacotes, e as variáveis dos passos.
fn comandos_do_job(workflow: &str, job: &str) -> Vec<String> {
    let cabecalho = format!("  {job}:");
    let mut dentro = false;
    let mut comandos = Vec::new();
    for linha in workflow.lines() {
        if !dentro {
            dentro = linha == cabecalho;
            continue;
        }
        // O próximo job: uma chave no recuo dos jobs.
        if linha.starts_with("  ")
            && !linha.starts_with("   ")
            && linha.trim_end().ends_with(':')
            && !linha.trim_start().starts_with('#')
        {
            break;
        }
        let t = linha.trim();
        if t.starts_with('#') {
            continue;
        }
        let t = t.strip_prefix("run: ").unwrap_or(t);
        let variavel = t.split_once(": ").is_some_and(|(nome, _)| {
            !nome.is_empty() && nome.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        });
        if t.contains("cargo ")
            || t.starts_with("rustfmt ")
            || t.starts_with("sudo apt-get install")
            || variavel
        {
            comandos.push(t.to_string());
        }
    }
    comandos
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn o_canal_com_data_passa() {
        for canal in [
            "nightly-2026-11-15",
            "nightly-2024-02-29",
            "nightly-2000-02-29",
        ] {
            assert_eq!(conferir_a_data(canal), Ok(()), "{canal}");
        }
    }

    #[test]
    fn o_canal_sem_data_ou_com_data_que_nao_existe_e_recusado() {
        for canal in [
            "nightly",
            "stable",
            "beta",
            "1.85.0",
            "beta-2026-11-15",
            "nightly-2026-11",
            "nightly-26-11-15",
            "nightly-2026-1-15",
            "nightly-2026-13-01",
            "nightly-2026-00-10",
            "nightly-2026-11-00",
            "nightly-2026-11-31",
            "nightly-2026-02-29",
            "nightly-1900-02-29",
            "nightly-2026-11-15-x86_64-unknown-linux-gnu",
            "nightly-2026-11-15 ",
            "nightly-2026-+1-15",
        ] {
            assert!(conferir_a_data(canal).is_err(), "{canal}");
        }
    }

    #[test]
    fn o_canal_sai_do_arquivo_sem_aspas_nem_comentario() {
        let texto = "# channel = \"nightly\"\n[toolchain]\nchannel = \"nightly-2026-11-15\" # o oficial\nprofile = \"minimal\"\n";
        assert_eq!(
            canal_do_arquivo(texto).as_deref(),
            Some("nightly-2026-11-15")
        );
        assert_eq!(
            canal_do_arquivo("[toolchain]\nchannel = 'nightly-2026-11-15'\n").as_deref(),
            Some("nightly-2026-11-15")
        );
        assert_eq!(
            canal_do_arquivo("[toolchain]\nprofile = \"minimal\"\n"),
            None
        );
        assert_eq!(canal_do_arquivo("[toolchain]\nchannel = nightly\n"), None);
    }

    #[test]
    fn os_dois_arquivos_do_repositorio_tem_o_mesmo_canal_com_data() {
        let raiz = include_str!("../../rust-toolchain.toml");
        let modelo = include_str!("../../sdk/modelo/rust-toolchain.toml");
        let canal = canal_do_arquivo(raiz).expect("o canal da raiz");
        assert_eq!(conferir_a_data(&canal), Ok(()));
        assert_eq!(canal_do_arquivo(modelo), Some(canal));
    }

    #[test]
    fn a_politica_escrita_cita_o_canal_em_vigor() {
        let canal = canal_do_arquivo(include_str!("../../rust-toolchain.toml")).expect("o canal");
        assert!(citada_no_texto(&canal, include_str!("../../CLAUDE.md")));
        assert!(citada_no_texto(
            "nightly-2026-11-15",
            "hoje **`nightly-2026-11-15`**"
        ));
        assert!(!citada_no_texto(
            "nightly-2026-11-15",
            "o `nightly-2026-11-150`"
        ));
        assert!(!citada_no_texto(
            "nightly-2026-11-15",
            "o nightly-2026-11-15 sem crases"
        ));
    }

    #[test]
    fn o_toolchain_ativo_tem_de_ser_o_canal_com_o_host() {
        let host = "x86_64-unknown-linux-gnu";
        let canal = "nightly-2026-11-15";
        assert_eq!(
            desvio_do_toolchain(canal, "nightly-2026-11-15-x86_64-unknown-linux-gnu", host),
            None
        );
        for outro in [
            "nightly-x86_64-unknown-linux-gnu",
            "nightly-2026-11-14-x86_64-unknown-linux-gnu",
            "stable-x86_64-unknown-linux-gnu",
            "nightly-2026-11-15-aarch64-unknown-linux-gnu",
            "nightly-2026-11-15-x86_64-unknown-linux-gnu-meu",
            "usr",
        ] {
            assert!(desvio_do_toolchain(canal, outro, host).is_some(), "{outro}");
        }
    }

    #[test]
    fn o_host_sai_do_rustc_vv() {
        let vv = "rustc 1.102.0-nightly (5f4effd57 2026-11-13)\nbinary: rustc\ncommit-hash: 5f4effd57\ncommit-date: 2026-11-13\nhost: x86_64-unknown-linux-gnu\nrelease: 1.102.0-nightly\n";
        assert_eq!(host_do_rustc(vv), Some("x86_64-unknown-linux-gnu"));
        assert_eq!(host_do_rustc("rustc 1.0\n"), None);
    }

    #[test]
    fn as_variaveis_que_trocam_o_compilador_sao_desvios() {
        let nenhuma = desvios_das_variaveis(|_| None);
        assert!(nenhuma.is_empty());
        let vazia = desvios_das_variaveis(|v| (v == "RUSTC").then(String::new));
        assert!(vazia.is_empty(), "a variável vazia não troca nada");
        for nome in VARIAVEIS_QUE_TROCAM {
            let d = desvios_das_variaveis(|v| (v == nome).then(|| "sccache".to_string()));
            assert_eq!(d.len(), 1, "{nome}");
            assert!(d[0].contains(nome), "{d:?}");
        }
    }

    #[test]
    fn as_chaves_do_config_do_cargo_que_trocam_o_compilador() {
        assert_eq!(
            chaves_que_trocam_o_compilador("[build]\nrustc-wrapper = \"sccache\"\n"),
            ["build.rustc-wrapper"]
        );
        assert_eq!(
            chaves_que_trocam_o_compilador("build.rustc = \"/opt/rustc\"\n"),
            ["build.rustc"]
        );
        assert_eq!(
            chaves_que_trocam_o_compilador(
                "[build]\n# rustc = \"x\"\ntarget = \"x86_64-unknown-none\"\nrustc-workspace-wrapper = \"w\"\n"
            ),
            ["build.rustc-workspace-wrapper"]
        );
        for sem in [
            "[target.x86_64-unknown-none]\nrustc = \"x\"\n",
            "[alias]\nxtask = \"run --quiet --package xtask --\"\n",
            "[build]\nrustflags = [\"-C\", \"relocation-model=static\"]\n",
        ] {
            assert!(chaves_que_trocam_o_compilador(sem).is_empty(), "{sem}");
        }
    }

    #[test]
    fn os_config_do_cargo_do_repositorio_nao_trocam_o_compilador() {
        for texto in [
            include_str!("../../.cargo/config.toml"),
            include_str!("../../kernel/.cargo/config.toml"),
            include_str!("../../programas/.cargo/config.toml"),
            include_str!("../../sdk/modelo/.cargo/config.toml"),
        ] {
            assert!(chaves_que_trocam_o_compilador(texto).is_empty());
        }
    }

    #[test]
    fn o_xtask_nao_chama_o_cargo_com_outro_toolchain() {
        let fonte = "let c = Command::new(env!(\"CARGO\"));\n// .env(\"RUSTUP_TOOLCHAIN\", x) num comentário\n";
        assert!(chamadas_com_outro_toolchain("a.rs", fonte).is_empty());
        for linha in [
            "cargo.arg(\"+nightly\");",
            "cargo.args([\"+stable\", \"build\"]);",
            "cargo.env(\"RUSTUP_TOOLCHAIN\", \"nightly\");",
            "cargo.env(\"RUSTC_WRAPPER\", \"sccache\");",
            "cargo.env(\"RUSTC\", caminho);",
        ] {
            assert_eq!(
                chamadas_com_outro_toolchain("a.rs", linha).len(),
                1,
                "{linha}"
            );
        }
    }

    /// Um workflow oficial como o da CI: o checkout, a conferência, o cache
    /// com o canal, o cargo.
    const OFICIAL: &str = "\
jobs:
  testes:
    steps:
      - uses: actions/checkout@v4

      # A conferência do compilador.
      - name: O compilador
        id: compilador
        uses: ./.github/actions/compilador

      - name: Cache do cargo
        uses: actions/cache@v4
        with:
          key: testes-${{ steps.compilador.outputs.canal }}-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            video-${{ steps.compilador.outputs.canal }}-
            testes-${{ steps.compilador.outputs.canal }}-

      - name: Testes
        run: cargo xtask test
";

    fn um(nome: &str, texto: &str) -> Vec<String> {
        conferir_os_workflows(&[(nome.to_string(), texto.to_string())])
    }

    #[test]
    fn o_workflow_oficial_que_confere_o_compilador_passa() {
        assert_eq!(
            um(".github/workflows/ci.yml", OFICIAL),
            Vec::<String>::new()
        );
    }

    #[test]
    fn o_workflow_oficial_sem_a_conferencia_ou_com_ela_tarde_e_recusado() {
        let sem = OFICIAL.replace(
            "      - name: O compilador\n        id: compilador\n        uses: ./.github/actions/compilador\n",
            "",
        );
        assert!(!um(".github/workflows/ci.yml", &sem).is_empty());

        let tarde = OFICIAL
            .replace(
                "      - name: O compilador\n        id: compilador\n        uses: ./.github/actions/compilador\n",
                "",
            )
            .replace(
                "      - name: Testes\n",
                "      - id: compilador\n        uses: ./.github/actions/compilador\n      - name: Testes\n",
            );
        let fora = um(".github/workflows/ci.yml", &tarde);
        assert!(
            fora.iter().any(|f| f.contains("antes da conferência")),
            "{fora:?}"
        );

        let sem_id = OFICIAL.replace("        id: compilador\n", "");
        assert!(!um(".github/workflows/ci.yml", &sem_id).is_empty());

        let dois_checkouts = OFICIAL.replace(
            "      - name: Testes\n",
            "      - uses: actions/checkout@v4\n      - name: Testes\n",
        );
        assert!(!um(".github/workflows/ci.yml", &dois_checkouts).is_empty());
    }

    #[test]
    fn a_chave_de_cache_sem_o_canal_e_recusada() {
        let principal = OFICIAL.replace(
            "key: testes-${{ steps.compilador.outputs.canal }}-",
            "key: testes-",
        );
        assert_eq!(um(".github/workflows/ci.yml", &principal).len(), 1);
        let restauracao = OFICIAL.replace(
            "            video-${{ steps.compilador.outputs.canal }}-\n",
            "            video-\n",
        );
        assert_eq!(um(".github/workflows/ci.yml", &restauracao).len(), 1);
        let numa_linha = OFICIAL.replace(
            "restore-keys: |\n            video-${{ steps.compilador.outputs.canal }}-\n            testes-${{ steps.compilador.outputs.canal }}-\n",
            "restore-keys: testes-\n",
        );
        assert_eq!(um(".github/workflows/ci.yml", &numa_linha).len(), 1);
    }

    #[test]
    fn o_workflow_oficial_nao_sobrepoe_o_compilador() {
        for linha in [
            "        run: cargo +nightly xtask test\n",
            "        env:\n          RUSTUP_TOOLCHAIN: nightly\n",
            "        env:\n          DUKE_OUTRO_COMPILADOR: 1\n",
            "        env:\n          RUSTC_WRAPPER: sccache\n",
            "        run: rustup override set nightly\n",
            "        run: rustup default nightly\n",
            "      - uses: dtolnay/rust-toolchain@nightly\n",
        ] {
            let texto = format!("{OFICIAL}{linha}");
            assert!(
                !um(".github/workflows/ci.yml", &texto).is_empty(),
                "{linha}"
            );
        }
        // Num comentário, não.
        let comentado = format!("{OFICIAL}      # o canário usa RUSTUP_TOOLCHAIN, e este não\n");
        assert_eq!(
            um(".github/workflows/ci.yml", &comentado),
            Vec::<String>::new()
        );
    }

    #[test]
    fn o_canario_do_repositorio_repete_os_comandos_dos_lints() {
        let ci = include_str!("../../.github/workflows/ci.yml");
        let canario = include_str!("../../.github/workflows/canario.yml");
        let comandos = comandos_do_job(ci, JOB_DE_LINTS);
        // A formatação (5), o apt, os testes, o clippy (6), as invariantes,
        // o RUSTDOCFLAGS e a documentação (5).
        assert!(comandos.len() >= 15, "{comandos:#?}");
        assert!(comandos.iter().any(|c| c == "cargo xtask invariantes"));
        assert!(comandos.iter().any(|c| c.starts_with("RUSTDOCFLAGS: ")));
        assert_eq!(o_canario_repete_os_lints(ci, canario), Vec::<String>::new());
    }

    #[test]
    fn o_canario_que_nao_repete_um_comando_dos_lints_e_recusado() {
        let ci = include_str!("../../.github/workflows/ci.yml");
        let canario = include_str!("../../.github/workflows/canario.yml");
        // Um pacote novo no clippy da CI, que o canário não conhece.
        let mais_um = ci.replacen(
            "cargo clippy -p protocolo --features alloc --all-targets -- -D warnings",
            "cargo clippy -p protocolo --features alloc --all-targets -- -D warnings\n          cargo clippy -p novo -- -D warnings",
            1,
        );
        assert_ne!(mais_um, ci);
        let fora = o_canario_repete_os_lints(&mais_um, canario);
        assert_eq!(fora.len(), 1, "{fora:?}");
        assert!(
            fora[0].contains("cargo clippy -p novo -- -D warnings"),
            "{fora:?}"
        );
        // Um comando que o canário perdeu.
        let sem_invariantes = canario.replace("cargo xtask invariantes", "true");
        assert_eq!(o_canario_repete_os_lints(ci, &sem_invariantes).len(), 1);
        // Num comentário do canário, não vale.
        let comentado = canario.replace(
            "cargo xtask invariantes 2>&1",
            "true 2>&1\n          # cargo xtask invariantes",
        );
        assert_eq!(o_canario_repete_os_lints(ci, &comentado).len(), 1);
        // Sem o job, a regra não passa calada.
        assert_eq!(
            o_canario_repete_os_lints("jobs:\n  outro:\n", canario).len(),
            1
        );
    }

    #[test]
    fn o_canario_sobrepoe_mas_sem_o_cache_da_ci_nem_a_proveniencia() {
        let canario = "\
jobs:
  canario:
    env:
      DUKE_OUTRO_COMPILADOR: 1
    steps:
      - uses: actions/checkout@v4
      - run: echo \"RUSTUP_TOOLCHAIN=$CANAL\" >> \"$GITHUB_ENV\"
      - run: cargo clippy
";
        assert_eq!(um(CANARIO, canario), Vec::<String>::new());
        let com_cache = format!("{canario}      - uses: actions/cache@v4\n");
        assert_eq!(um(CANARIO, &com_cache).len(), 1);
        let com_proveniencia =
            format!("{canario}        with:\n          path: target/proveniencia/\n");
        assert_eq!(um(CANARIO, &com_proveniencia).len(), 1);
    }
}
