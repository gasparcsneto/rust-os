//! O compilador oficial do Duke OS — a política de "O compilador", no
//! `CLAUDE.md`.
//!
//! O canal é um nightly com data — `nightly-AAAA-MM-DD` —, o mesmo no
//! `rust-toolchain.toml` da raiz e no do modelo do SDK, e só muda por uma
//! promoção. Daqui saem três conferências:
//!
//! - **no começo de todo `cargo xtask`** ([`conferir_ao_iniciar`]): o
//!   compilador que vai compilar é o do canal oficial, o mesmo em todo lugar
//!   de onde o `xtask` compila. São desvios:
//!   - o `rust-toolchain.toml` diferente do do commit: uma promoção em
//!     preparo é uma execução não oficial até o commit;
//!   - o toolchain ativo — o do sysroot do `rustc` que o cargo chamaria —
//!     que não é o canal com o host, na raiz ou num diretório de build
//!     ([`DIRETORIOS_DOS_BUILDS`]): o rustup resolve por diretório, e um
//!     `rustup override` num deles trocaria o compilador só ali;
//!   - o cargo com que o `xtask` compila, ou o rustc que compilou o próprio
//!     `xtask` (o `xtask/build.rs` grava o commit dele), que não são os do
//!     toolchain ativo;
//!   - as variáveis com que o cargo troca ou embrulha o compilador
//!     ([`VARIAVEIS_QUE_TROCAM`]: as três do cargo e as três
//!     `CARGO_BUILD_RUSTC*` do config), e as chaves `build.rustc`,
//!     `build.rustc-wrapper` e `build.rustc-workspace-wrapper` do config do
//!     cargo — lido pelo próprio cargo em cada diretório de build, com todo
//!     arquivo que vale ali e toda forma de escrever a chave;
//!   - desde o lote A9, o executor e os apelidos do cargo
//!     ([`desvios_da_configuracao`], [`desvios_do_ambiente_do_cargo`]): um
//!     `runner` em qualquer tabela `target` do config, ou um
//!     `CARGO_TARGET_<alvo>_RUNNER`, e um `[alias]` que não é só o oficial
//!     ([`APELIDO_DO_XTASK`]), ou um `CARGO_ALIAS_<nome>`. O `cargo xtask` é
//!     o `cargo run` do `xtask`, e o `cargo run` passa o binário pelo
//!     executor: um executor do repositório decidiria o que o `cargo xtask
//!     invariantes` diz. Aqui se vê o executor que ainda chama o `xtask` de
//!     verdade; o que não chama nunca roda esta conferência — esse a ação da
//!     CI recusa antes de todo `cargo` ([`ACAO_DO_COMPILADOR`], o passo
//!     [`PASSO_DO_EXECUTOR`]).
//!
//!   Um desvio recusa o comando, a menos que `DUKE_OUTRO_COMPILADOR=1`
//!   declare a execução **não oficial**: aí ela roda com um aviso, e a
//!   proveniência dos artefatos (`xtask/src/proveniencia.rs`) registra
//!   `"oficial": false` — também quando o compilador é o oficial, porque foi
//!   a execução que se declarou não oficial. Não é uma barreira contra quem
//!   quer contornar — o código está aqui —; é o fim do desvio silencioso: o
//!   `+nightly` de costume, um `rustup override` esquecido, o
//!   `RUSTUP_TOOLCHAIN` de outra sessão, um `sccache` configurado para a
//!   máquina inteira;
//! - **no `cargo xtask invariantes`** ([`conferir_o_canal`]): o canal tem
//!   data, é o mesmo nos dois arquivos e o `CLAUDE.md` o cita; não há outro
//!   `rust-toolchain` no repositório; o config do cargo dos diretórios com
//!   `.cargo/` não troca o compilador; o `xtask` não chama o cargo nem o
//!   rustc com outro toolchain; os workflows oficiais só usam as ações de
//!   [`ACOES_OFICIAIS`], não sobrepõem o toolchain e conferem o compilador
//!   — a ação `.github/actions/compilador` — depois de cada checkout, antes
//!   do cache e de qualquer `cargo`, com o canal em toda chave de cache; a
//!   ação tem, desde o lote A9, o passo do executor, que confere o config do
//!   cargo fora do cargo ([`conferir_a_acao`]); e o canário, o único que
//!   sobrepõe — ele testa o candidato —, não roda nos pushes, não usa o cache
//!   da CI, não publica proveniência e repete os comandos do job de lints;
//! - **no `cargo xtask compilador`** ([`relatar`]): o canal, o toolchain
//!   ativo, o `rustc -Vv` completo, o `cargo -V` e os desvios — o que todo
//!   relatório de validação cita.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::OnceLock;

use protocolo::json::Json;

/// O opt-in de uma execução não oficial: só o valor `1` vale.
pub(crate) const OUTRO_COMPILADOR: &str = "DUKE_OUTRO_COMPILADOR";

/// O arquivo que manda no canal.
const TOOLCHAIN_DA_RAIZ: &str = "rust-toolchain.toml";

/// O do modelo do SDK, que segue o da raiz.
const TOOLCHAIN_DO_MODELO: &str = "sdk/modelo/rust-toolchain.toml";

/// Os diretórios de onde o `xtask` chama o cargo, relativos à raiz: ela
/// mesma (o próprio `xtask`, os testes, as ferramentas), o kernel, os
/// programas, o iniciador, o modelo do SDK e a cópia dele que o `sdk-fora`
/// compila. Os que não existem ficam de fora.
const DIRETORIOS_DOS_BUILDS: [&str; 6] = [
    "",
    "kernel",
    "programas",
    "iniciador",
    "sdk/modelo",
    "target/sdk-fora/projeto",
];

/// As variáveis com que o cargo troca, ou embrulha, o compilador: as três
/// que ele lê fora do config, e as três `CARGO_BUILD_RUSTC*`, que são as
/// chaves de [`CHAVES_QUE_TROCAM`] escritas no ambiente. Estas o cargo soma
/// na consulta de uma chave de valor (`build.rustc-wrapper`), e não na de
/// uma tabela inteira, de que ele só as cita ([`config_inteiro`]): a
/// conferência as lê aqui, pelo nome, e o config pela consulta (o item 1 do
/// revisor do lote A8, conferido com o cargo do canal).
const VARIAVEIS_QUE_TROCAM: [&str; 6] = [
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
];

/// As chaves da tabela `[build]` do config do cargo que trocam, ou
/// embrulham, o compilador.
const CHAVES_QUE_TROCAM: [&str; 3] = ["rustc", "rustc-wrapper", "rustc-workspace-wrapper"];

/// O apelido do `cargo xtask`, como o `.cargo/config.toml` da raiz o diz: o
/// único `[alias]` do config do cargo, em todo diretório de build. Outro
/// apelido — ou este com outro valor — decide o que o `cargo xtask` roda.
pub(crate) const APELIDO_DO_XTASK: (&str, &str) = ("xtask", "run --quiet --package xtask --");

/// O passo da ação do compilador ([`ACAO_DO_COMPILADOR`]) que confere o
/// executor, o ligador e os apelidos do cargo fora do cargo — ver
/// [`conferir_a_acao`].
const PASSO_DO_EXECUTOR: &str = "executor";

/// O que o passo do executor tem de conferir, pelo texto do script dele
/// ([`conferir_a_acao`]): a consulta do config do cargo, o apelido, o
/// executor e o ligador de cada tabela `target`, as chaves que trocam o
/// compilador, as variáveis do ambiente e a raiz fechada. O que o script faz
/// com cada um, o teste `a_acao_recusa_o_executor_o_ligador_e_o_apelido`
/// confere rodando-o.
const MARCAS_DO_EXECUTOR: [&str; 8] = [
    "\"config\", \"get\"",
    "\"alias\"",
    "\"runner\"",
    "\"linker\"",
    "\"rustc-wrapper\"",
    "\"CARGO_ALIAS_\"",
    "\"CARGO_TARGET_\"",
    "set(config) - {\"alias\"}",
];

/// O commit do rustc que compilou este `xtask`, gravado pelo `build.rs`.
const COMPILADO_COM: &str = env!("XTASK_RUSTC_COMMIT");

/// O que, num workflow oficial, sobrepõe ou troca o compilador do
/// `rust-toolchain.toml`: as variáveis, os `+toolchain`, o `--config` do
/// cargo, os comandos do rustup que mudam o toolchain, o `PATH` dos passos
/// seguintes e o config do cargo da máquina.
const SOBREPOSICOES: [&str; 18] = [
    "RUSTUP_TOOLCHAIN",
    "RUSTUP_HOME",
    "CARGO_HOME",
    "DUKE_OUTRO_COMPILADOR",
    "RUSTC:",
    "RUSTC=",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC",
    "cargo +",
    "rustc +",
    "--config",
    "rustup default",
    "rustup override",
    "rustup run",
    "rustup toolchain",
    "GITHUB_PATH",
    ".cargo/config",
];

/// As ações que um workflow oficial pode usar: o checkout, o cache, a
/// publicação de artefatos e a conferência do compilador. Outra — uma que
/// instale um toolchain, por exemplo — só entra pondo-a aqui, de propósito.
const ACOES_OFICIAIS: [&str; 4] = [
    "actions/checkout",
    "actions/cache",
    "actions/upload-artifact",
    "./.github/actions/compilador",
];

/// As do canário: sem o cache da CI nem a conferência do oficial.
const ACOES_DO_CANARIO: [&str; 2] = ["actions/checkout", "actions/upload-artifact"];

/// O workflow do canário: o único que sobrepõe o compilador.
const CANARIO: &str = ".github/workflows/canario.yml";

/// A ação que confere o compilador: ela cita as variáveis que recusa, e por
/// isso não passa pela regra das sobreposições.
const ACAO_DO_COMPILADOR: &str = ".github/actions/compilador/action.yml";

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
    /// O que afasta o compilador desta execução do oficial.
    pub(crate) desvios: Vec<String>,
    /// A execução se declarou não oficial: `DUKE_OUTRO_COMPILADOR=1`.
    pub(crate) declarada_nao_oficial: bool,
}

impl Compilador {
    /// A execução é oficial: o compilador é o oficial, sem desvio nenhum, e
    /// ela não se declarou não oficial.
    pub(crate) fn oficial(&self) -> bool {
        self.desvios.is_empty() && !self.declarada_nao_oficial
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
    desvios.extend(desvios_do_commit(&raiz));

    // O rustc que o cargo chamaria: o da variável, se houver, ou o do PATH
    // — o proxy do rustup, que resolve o toolchain pelo `RUSTUP_TOOLCHAIN`
    // que ele mesmo passou a este processo, ou, sem ele, pelo diretório.
    let rustc = std::env::var_os("RUSTC")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "rustc".into());
    let consultar = |dir: &Path, args: &[&str]| {
        Command::new(&rustc)
            .args(args)
            .current_dir(dir)
            .output()
            .ok()
            .filter(|s| s.status.success())
            .map(|s| String::from_utf8_lossy(&s.stdout).trim().to_string())
    };
    let sysroot = consultar(&raiz, &["--print", "sysroot"]);
    let vv = consultar(&raiz, &["-Vv"]);
    let toolchain = sysroot.as_deref().map(nome_do_toolchain);
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

    let diretorios = diretorios_dos_builds(&raiz);
    // O mesmo rustc em todo diretório de build. Com o `RUSTUP_TOOLCHAIN` —
    // o caminho do `cargo xtask` — ou o `RUSTC`, o diretório não muda nada.
    let sem_sobreposicao = std::env::var_os("RUSTUP_TOOLCHAIN").is_none()
        && std::env::var_os("RUSTC").is_none_or(|v| v.is_empty());
    if let (Some(sysroot), true) = (&sysroot, sem_sobreposicao) {
        for (rotulo, dir) in diretorios.iter().skip(1) {
            match consultar(dir, &["--print", "sysroot"]) {
                Some(outro) if outro == *sysroot => {}
                Some(outro) => desvios.push(format!(
                    "em `{rotulo}`, o toolchain é `{}`, e não o da raiz, `{}` — um `rustup override` ali?",
                    nome_do_toolchain(&outro),
                    nome_do_toolchain(sysroot)
                )),
                None => desvios.push(format!("em `{rotulo}`, o rustc não respondeu")),
            }
        }
    }

    // O cargo com que o `xtask` compila, e o rustc que compilou o próprio
    // `xtask`, são os do toolchain ativo.
    if let Some(sysroot) = &sysroot {
        desvios.extend(desvio_do_cargo(
            Path::new(env!("CARGO")),
            Path::new(sysroot),
        ));
    }
    if let Some(d) = vv
        .as_deref()
        .and_then(|vv| desvio_do_xtask(COMPILADO_COM, vv))
    {
        desvios.push(d);
    }

    desvios.extend(desvios_das_variaveis(|nome| std::env::var(nome).ok()));
    desvios.extend(desvios_do_ambiente_do_cargo(std::env::vars_os().map(
        |(nome, valor)| {
            (
                nome.to_string_lossy().into_owned(),
                valor.to_string_lossy().into_owned(),
            )
        },
    )));
    for (rotulo, dir) in &diretorios {
        desvios.extend(desvios_do_config(dir, rotulo));
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

/// Os diretórios de build que existem, com o rótulo de cada um.
fn diretorios_dos_builds(raiz: &Path) -> Vec<(String, PathBuf)> {
    DIRETORIOS_DOS_BUILDS
        .iter()
        .map(|d| {
            let rotulo = if d.is_empty() {
                String::from("./")
            } else {
                format!("{d}/")
            };
            (rotulo, raiz.join(d))
        })
        .filter(|(_, dir)| dir.is_dir())
        .collect()
}

/// O nome do toolchain de um sysroot: o do diretório dele.
fn nome_do_toolchain(sysroot: &str) -> String {
    Path::new(sysroot)
        .file_name()
        .map_or_else(|| sysroot.to_string(), |n| n.to_string_lossy().into_owned())
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

/// As linhas de um arquivo de configuração que valem: sem as vazias e sem os
/// comentários de linha inteira.
fn linhas_que_valem(texto: &str) -> Vec<&str> {
    texto
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Os dois `rust-toolchain.toml` da árvore são os do commit — o que vale é
/// o do commit; os comentários não contam.
fn desvios_do_commit(raiz: &Path) -> Vec<String> {
    let mut desvios = Vec::new();
    for arquivo in [TOOLCHAIN_DA_RAIZ, TOOLCHAIN_DO_MODELO] {
        let no_commit = Command::new("git")
            .current_dir(raiz)
            .args(["show", &format!("HEAD:{arquivo}")])
            .output()
            .ok()
            .filter(|s| s.status.success())
            .map(|s| String::from_utf8_lossy(&s.stdout).into_owned());
        let na_arvore = std::fs::read_to_string(raiz.join(arquivo)).ok();
        if let Some(d) = desvio_do_arquivo(arquivo, no_commit.as_deref(), na_arvore.as_deref()) {
            desvios.push(d);
        }
    }
    desvios
}

/// O desvio de um `rust-toolchain.toml` da árvore contra o do commit.
fn desvio_do_arquivo(
    arquivo: &str,
    no_commit: Option<&str>,
    na_arvore: Option<&str>,
) -> Option<String> {
    match (no_commit, na_arvore) {
        (Some(a), Some(b)) if linhas_que_valem(a) == linhas_que_valem(b) => None,
        (Some(_), Some(_)) => Some(format!(
            "o {arquivo} da árvore difere do do commit: vale o do commit — uma promoção em \
             preparo é uma execução não oficial até o commit"
        )),
        (None, _) => Some(format!(
            "o {arquivo} do commit não se lê (o git não respondeu): o canal não se confere contra o commit"
        )),
        (_, None) => Some(format!("o {arquivo} da árvore não se lê")),
    }
}

/// O host do `rustc -Vv`: a linha `host: ...`.
fn host_do_rustc(vv: &str) -> Option<&str> {
    linha_do_rustc(vv, "host:")
}

/// O commit do `rustc -Vv`: a linha `commit-hash: ...`.
fn commit_do_rustc(vv: &str) -> Option<&str> {
    linha_do_rustc(vv, "commit-hash:")
}

/// O valor de uma linha `chave: valor` do `rustc -Vv`.
fn linha_do_rustc<'a>(vv: &'a str, chave: &str) -> Option<&'a str> {
    vv.lines()
        .find_map(|l| l.trim().strip_prefix(chave))
        .map(str::trim)
        .filter(|v| !v.is_empty())
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

/// O desvio do cargo com que o `xtask` compila, se ele não é o do sysroot
/// do toolchain ativo — o `xtask` foi compilado por outro toolchain e é
/// rodado direto, sem o `cargo xtask`.
fn desvio_do_cargo(cargo: &Path, sysroot: &Path) -> Option<String> {
    let esperado = sysroot.join("bin").join("cargo");
    (cargo != esperado).then(|| {
        format!(
            "o cargo com que o xtask compila é `{}`, e não o do toolchain ativo, `{}`",
            cargo.display(),
            esperado.display()
        )
    })
}

/// O desvio do rustc que compilou o próprio `xtask`, se ele não é o ativo:
/// o `xtask` foi compilado com outro compilador — um `--config build.rustc`,
/// um binário de outro toolchain rodado direto.
fn desvio_do_xtask(compilado_com: &str, vv: &str) -> Option<String> {
    let ativo = commit_do_rustc(vv)?;
    (compilado_com != ativo).then(|| {
        format!(
            "o xtask foi compilado pelo rustc de commit `{compilado_com}`, e o ativo é o de `{ativo}`"
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

/// As variáveis do executor e dos apelidos do cargo em `variaveis` — o
/// ambiente, nome e valor —, como desvios: um `CARGO_TARGET_<alvo>_RUNNER`
/// e um `CARGO_ALIAS_<nome>`, que o cargo lê como o config e que a consulta
/// de uma tabela inteira não soma ([`config_inteiro`]). As vazias não
/// trocam nada.
fn desvios_do_ambiente_do_cargo(
    variaveis: impl IntoIterator<Item = (String, String)>,
) -> Vec<String> {
    let mut desvios: Vec<String> = variaveis
        .into_iter()
        .filter(|(_, valor)| !valor.is_empty())
        .filter_map(|(nome, valor)| {
            if nome.starts_with("CARGO_TARGET_") && nome.ends_with("_RUNNER") {
                Some(format!(
                    "a variável `{nome}={valor}` troca o executor do cargo — o que roda cada \
                     binário, o do `cargo xtask` inclusive"
                ))
            } else if nome.starts_with("CARGO_ALIAS_") {
                Some(format!(
                    "a variável `{nome}={valor}` é um apelido do cargo — o `cargo xtask` roda o \
                     que o apelido dele disser"
                ))
            } else {
                None
            }
        })
        .collect();
    desvios.sort();
    desvios
}

/// O config do cargo de `dir` que troca o compilador, o executor ou o
/// apelido do `cargo xtask` ([`desvios_da_configuracao`]), como o próprio
/// cargo o lê ali ([`config_inteiro`]): todos os arquivos que valem para o
/// diretório — os de cima, o do `CARGO_HOME` — e toda forma de escrever cada
/// chave. As variáveis do ambiente, que a consulta não soma, são de
/// [`desvios_das_variaveis`] e de [`desvios_do_ambiente_do_cargo`]. A
/// consulta é a do cargo nightly (`-Zunstable-options config get`); o
/// canário diz se ela mudar.
fn desvios_do_config(dir: &Path, rotulo: &str) -> Vec<String> {
    match config_inteiro(dir) {
        Ok(config) => desvios_da_configuracao(&config)
            .into_iter()
            .map(|d| format!("em `{rotulo}`, {d}"))
            .collect(),
        Err(e) => vec![format!("em `{rotulo}`, {e}")],
    }
}

/// O que `config` — o config inteiro do cargo, em JSON, como
/// [`config_inteiro`] o devolve — tem que troca o compilador, o executor ou
/// o apelido do `cargo xtask`: as chaves de [`CHAVES_QUE_TROCAM`] na tabela
/// `[build]`; desde o lote A9, um `runner` em qualquer tabela `target` — a de
/// um alvo, a de um `cfg(…)` —; e um `[alias]` que não é só o
/// [`APELIDO_DO_XTASK`], com o valor dele: um apelido a mais, um a menos, ou
/// o do `xtask` com outro valor ou escrito como lista.
///
/// # O executor e o apelido, desde o lote A9
///
/// O `cargo xtask` é o `cargo run --package xtask`, e o `cargo run` passa o
/// binário pelo executor do alvo do hospedeiro: um `[target.'cfg(unix)']
/// runner = "ferramentas/rodar"` no config da raiz, com um script que
/// responde `invariantes` com sucesso e roda o `xtask` de verdade para o
/// resto, fazia o passo das invariantes da CI passar sem guarda nenhuma — e
/// o `cargo test -p xtask` também (o A8 do adversário do lote A8). O
/// apelido é o mesmo ponto (o I3 dele). Aqui se vê o executor que ainda
/// chama o `xtask`; o que nunca o chama, a ação da CI o recusa antes de todo
/// `cargo` ([`PASSO_DO_EXECUTOR`]). O ligador do hospedeiro, que roda ao
/// ligar o `xtask`, também: aqui ele não entra — o config de quem compila
/// pode escolher o seu —, e o do config do kernel é recusado pelo
/// `invariantes` (`config_do_kernel_fora`, no `main.rs`).
fn desvios_da_configuracao(config: &str) -> Vec<String> {
    let config = Json(config.trim().as_bytes());
    let mut desvios = Vec::new();
    if let Some(build) = config.member("build") {
        for chave in chaves_que_trocam(build.raw_str().unwrap_or("")) {
            desvios.push(format!(
                "o config do cargo define `build.{chave}`: troca o compilador"
            ));
        }
    }
    if let Some(alvos) = config.member("target") {
        let mut nomes = Vec::new();
        alvos.para_cada_chave(|alvo| nomes.push(alvo));
        for alvo in nomes {
            if alvos
                .member(alvo)
                .and_then(|tabela| tabela.member("runner"))
                .is_some()
            {
                desvios.push(format!(
                    "o config do cargo define `target.{}.runner`: o executor roda no lugar de \
                     cada binário que o cargo roda — o do `cargo xtask` inclusive —, e decidiria o \
                     que o `cargo xtask invariantes` diz",
                    chave_legivel(alvo)
                ));
            }
        }
    }
    let (nome, valor) = APELIDO_DO_XTASK;
    let oficial = config.member("alias").is_some_and(|apelidos| {
        let mut nomes = Vec::new();
        apelidos.para_cada_chave(|n| nomes.push(n));
        nomes == [nome] && apelidos.member(nome).and_then(|v| v.as_str()) == Some(valor)
    });
    if !oficial {
        desvios.push(format!(
            "o `[alias]` do config do cargo é {}, e não só o oficial (`{nome} = \"{valor}\"`): um \
             apelido decide o que o `cargo {nome}` roda",
            config
                .member("alias")
                .and_then(|a| a.raw_str())
                .unwrap_or("(nenhum)")
        ));
    }
    desvios
}

/// Uma chave do JSON do cargo como o config a escreve, com os escapes
/// resolvidos — a de um `cfg(…)` tem aspas —; a crua, se não se resolver.
fn chave_legivel(chave: &str) -> String {
    let mut destino = [0u8; 512];
    Json(format!("\"{chave}\"").as_bytes())
        .desescapar_em(&mut destino)
        .map_or_else(|| chave.to_string(), str::to_string)
}

/// O config inteiro do cargo de `dir`, em JSON, como o próprio cargo o lê
/// ali — todos os arquivos que valem para o diretório, com a extensão e sem
/// ela, os de cima e o do `CARGO_HOME`, com os escapes do TOML resolvidos;
/// `{}` sem config nenhum. As variáveis `CARGO_*` não entram: a consulta de
/// uma tabela, ou do config inteiro, só as cita, num aviso, e só a de uma
/// chave de valor as soma (ver [`valor_do_config`]). A consulta é a do cargo
/// nightly (`-Zunstable-options config get`); o canário diz se ela mudar.
/// Falha fechada: uma resposta que não se entende é um erro.
fn config_inteiro(dir: &Path) -> Result<String, String> {
    let saida = Command::new(env!("CARGO"))
        .args([
            "-Zunstable-options",
            "config",
            "get",
            "--format",
            "json-value",
        ])
        .current_dir(dir)
        .output()
        .map_err(|e| format!("o cargo não rodou: {e}"))?;
    let texto = String::from_utf8_lossy(&saida.stdout).trim().to_string();
    if saida.status.success() && texto.starts_with('{') {
        return Ok(texto);
    }
    let erro = String::from_utf8_lossy(&saida.stderr);
    // A linha do erro, e não a de um aviso antes dela.
    let linha = erro
        .lines()
        .find(|l| l.starts_with("error"))
        .or_else(|| erro.lines().next())
        .unwrap_or("")
        .trim();
    Err(format!(
        "o cargo não respondeu à consulta do config inteiro: {linha}"
    ))
}

/// O valor de `chave` no config do cargo de `dir`, em JSON, como o próprio
/// cargo o lê ali — todos os arquivos que valem para o diretório, com a
/// extensão e sem ela, os de cima e o do `CARGO_HOME`, com os escapes do
/// TOML resolvidos —; ou `None`, sem a chave em lugar nenhum. As variáveis
/// `CARGO_*` entram na consulta de uma chave de valor
/// (`target.<alvo>.rustflags`, `build.rustflags`), e não na de uma tabela
/// inteira, de que o cargo só as cita. A consulta é a do cargo nightly
/// (`-Zunstable-options config get`); o canário diz se ela mudar. Falha
/// fechada: uma resposta que não se entende é um erro.
pub(crate) fn valor_do_config(dir: &Path, chave: &str) -> Result<Option<String>, String> {
    let saida = Command::new(env!("CARGO"))
        .args([
            "-Zunstable-options",
            "config",
            "get",
            "--format",
            "json-value",
            chave,
        ])
        .current_dir(dir)
        .output()
        .map_err(|e| format!("o cargo não rodou: {e}"))?;
    if saida.status.success() {
        return Ok(Some(
            String::from_utf8_lossy(&saida.stdout).trim().to_string(),
        ));
    }
    let erro = String::from_utf8_lossy(&saida.stderr);
    if erro.contains("is not set") {
        return Ok(None);
    }
    // A linha do erro, e não a de um aviso antes dela.
    let linha = erro
        .lines()
        .find(|l| l.starts_with("error"))
        .or_else(|| erro.lines().next())
        .unwrap_or("")
        .trim();
    Err(format!(
        "o cargo não respondeu à consulta do config (`{chave}`): {linha}"
    ))
}

/// As chaves de [`CHAVES_QUE_TROCAM`] definidas na tabela `[build]` que o
/// cargo devolve em JSON.
fn chaves_que_trocam(build: &str) -> Vec<&'static str> {
    let tabela = Json(build.trim().as_bytes());
    CHAVES_QUE_TROCAM
        .into_iter()
        .filter(|chave| {
            tabela
                .member(chave)
                .is_some_and(|v| !v.is_null() && v.as_str() != Some(""))
        })
        .collect()
}

/// A conferência do começo de todo `cargo xtask` — menos o `compilador`,
/// que a relata, e o `help`.
pub(crate) fn conferir_ao_iniciar() -> Result<(), String> {
    conferir_o_observado(estado())
}

/// O veredito da conferência do começo para o compilador observado `c`: sem
/// desvio, segue; com desvio, recusa, com a lista e o caminho de volta —
/// menos com o opt-in, que segue com o aviso, como execução não oficial.
fn conferir_o_observado(c: &Compilador) -> Result<(), String> {
    if c.desvios.is_empty() {
        if c.declarada_nao_oficial {
            eprintln!(
                "[xtask] {OUTRO_COMPILADOR}=1: a execução é NÃO OFICIAL, como declarada — o \
                 compilador é o oficial, mas a proveniência dos artefatos registra \"oficial\": false"
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
             O compilador oficial é o canal do {TOOLCHAIN_DA_RAIZ} do commit (ver \"O compilador\" \
             no CLAUDE.md). Rode por `cargo xtask`, sem `+toolchain`, sem `RUSTUP_TOOLCHAIN`, sem \
             `rustup override` e sem as variáveis e as chaves acima: o rustup instala o canal \
             sozinho. `cargo xtask compilador` mostra o estado. Uma execução não oficial, de \
             propósito: {OUTRO_COMPILADOR}=1 cargo xtask ..."
        ))
    }
}

/// `cargo xtask compilador`: o canal oficial, o toolchain ativo, as versões
/// completas e os desvios. Sai com sucesso só numa execução oficial.
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
    println!("o xtask, compilado pelo rustc de commit: {COMPILADO_COM}");
    if c.desvios.is_empty() {
        println!("os desvios: nenhum — o compilador é o oficial");
    } else {
        println!("os desvios:");
        for d in &c.desvios {
            println!("  - {d}");
        }
    }
    if c.oficial() {
        return Ok(ExitCode::SUCCESS);
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
    let mut com_config: Vec<String> = Vec::new();
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
        // O diretório de um `.cargo/config*`: o config dele é lido pelo
        // próprio cargo, abaixo.
        if let Some((dir, _)) = arquivo
            .rsplit_once(".cargo/config")
            .filter(|(_, resto)| resto.is_empty() || *resto == ".toml")
            && !com_config.iter().any(|d| d == dir)
        {
            com_config.push(dir.to_string());
        }
        if (arquivo.starts_with(".github/workflows/") || arquivo.starts_with(".github/actions/"))
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
    for dir in &com_config {
        let rotulo = if dir.is_empty() { "./" } else { dir.as_str() };
        fora.extend(desvios_do_config(&raiz.join(dir), rotulo));
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
    match texto_de(ACAO_DO_COMPILADOR) {
        Some(acao) => fora.extend(conferir_a_acao(acao)),
        None => fora.push(format!(
            "{ACAO_DO_COMPILADOR}: a ação que confere o compilador não foi achada"
        )),
    }

    if fora.is_empty() {
        println!(
            "[xtask] o compilador: o canal {}, com data, nos dois rust-toolchain.toml e no \
             CLAUDE.md; nenhum outro, nenhuma troca no config do cargo nem no xtask — nem um \
             executor, nem um apelido além do oficial —; os workflows oficiais só com as ações \
             permitidas, conferindo o compilador depois de cada checkout, com o canal na chave \
             de todo cache, e a ação do compilador com o passo do executor, fora do cargo; e o \
             canário, o único que sobrepõe, fora dos pushes, sem o cache da CI e com os comandos \
             do job de lints",
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
/// outro toolchain: um `+toolchain`, ou uma variável que troca o compilador
/// ou o toolchain posta no processo filho.
fn chamadas_com_outro_toolchain(arquivo: &str, fonte: &str) -> Vec<String> {
    let mut proibidos: Vec<String> = ["\"+nightly", "\"+stable", "\"+beta"]
        .iter()
        .map(|p| (*p).to_string())
        .collect();
    proibidos.extend(
        VARIAVEIS_QUE_TROCAM
            .iter()
            .chain(&["RUSTUP_TOOLCHAIN", "RUSTUP_HOME", "CARGO_HOME"])
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

/// Uma linha de YAML que não é comentário: o recuo e o texto sem as
/// bordas. As vazias ficam, com o recuo zero: um bloco `|` pode tê-las.
struct Linha<'a> {
    recuo: usize,
    texto: &'a str,
}

/// As linhas de código de um YAML, sem os comentários de linha inteira.
fn linhas_de_codigo(texto: &str) -> Vec<Linha<'_>> {
    texto
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| Linha {
            recuo: l.len() - l.trim_start().len(),
            texto: l.trim(),
        })
        .collect()
}

/// A chave e o valor de uma linha `chave: valor` de YAML, com o `- ` de um
/// item de lista e as aspas da chave tirados.
fn chave_e_valor(texto: &str) -> Option<(&str, &str)> {
    let texto = texto.strip_prefix("- ").unwrap_or(texto);
    let (chave, valor) = texto.split_once(':')?;
    let chave = chave.trim().trim_matches(|c| c == '"' || c == '\'');
    // Uma chave de workflow: letras, dígitos, `-` e `_` — e não um pedaço
    // de código de dentro de um `run:`, como `avisos.append(f"aviso`.
    let de_yaml = !chave.is_empty()
        && chave
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    de_yaml.then_some((chave, valor.trim()))
}

/// O nome da ação de um `uses:` — sem as aspas e sem a versão.
fn nome_da_acao(valor: &str) -> &str {
    let valor = valor.trim_matches(|c| c == '"' || c == '\'');
    valor.split('@').next().unwrap_or(valor)
}

/// Os workflows: os oficiais só usam as ações de [`ACOES_OFICIAIS`], não
/// sobrepõem o compilador e o conferem — `./.github/actions/compilador`,
/// com `id: compilador` — depois de cada checkout, antes do cache e de
/// qualquer `cargo`; e toda chave de cache, a principal e as de
/// restauração, leva o canal. Nada em estilo de fluxo (`{ ... }`), que
/// esconderia as chaves desta leitura, e nenhum `uses:` em várias linhas. O
/// canário sobrepõe, mas não roda nos pushes, não usa o cache nem publica a
/// proveniência. As ações locais seguem as regras dos workflows oficiais,
/// menos a que confere o compilador, que cita o que recusa.
fn conferir_os_workflows(workflows: &[(String, String)]) -> Vec<String> {
    let mut fora = Vec::new();
    for (nome, texto) in workflows {
        if nome == ACAO_DO_COMPILADOR {
            continue;
        }
        let linhas = linhas_de_codigo(texto);
        let canario = nome == CANARIO;
        let permitidas: &[&str] = if canario {
            &ACOES_DO_CANARIO
        } else {
            &ACOES_OFICIAIS
        };

        for l in &linhas {
            let Some((chave, valor)) = chave_e_valor(l.texto) else {
                continue;
            };
            if valor.starts_with('{') {
                fora.push(format!(
                    "{nome}: `{}` — o estilo de fluxo esconde as chaves da conferência",
                    l.texto
                ));
            }
            if chave == "uses" {
                if valor.is_empty() || valor.starts_with(['>', '|']) {
                    fora.push(format!(
                        "{nome}: um `uses:` em várias linhas — numa linha só"
                    ));
                } else if !permitidas.contains(&nome_da_acao(valor)) {
                    fora.push(format!(
                        "{nome}: `{}` não é uma ação permitida ({})",
                        nome_da_acao(valor),
                        permitidas.join(", ")
                    ));
                }
            }
        }

        if canario {
            if linhas
                .iter()
                .any(|l| l.texto.contains("target/proveniencia"))
            {
                fora.push(format!(
                    "{nome}: o canário publica a proveniência — ele não produz artefato oficial"
                ));
            }
            fora.extend(gatilhos_de_push(nome, &linhas));
            continue;
        }

        for l in &linhas {
            if let Some(p) = SOBREPOSICOES.iter().find(|p| l.texto.contains(*p)) {
                fora.push(format!(
                    "{nome}: `{}` — `{p}` sobrepõe o compilador do {TOOLCHAIN_DA_RAIZ}",
                    l.texto
                ));
            }
            if l.texto.contains("rust-toolchain")
                && [">", "tee ", "sed -i", "cp ", "mv ", "ln "]
                    .iter()
                    .any(|e| l.texto.contains(e))
            {
                fora.push(format!(
                    "{nome}: `{}` escreve num rust-toolchain — o canal é o do commit",
                    l.texto
                ));
            }
        }
        if nome.starts_with(".github/actions/") {
            continue;
        }

        let mut pendente = false;
        for l in &linhas {
            let acao = chave_e_valor(l.texto)
                .filter(|(chave, _)| *chave == "uses")
                .map(|(_, valor)| nome_da_acao(valor));
            match acao {
                Some("actions/checkout") => {
                    if pendente {
                        fora.push(format!(
                            "{nome}: um checkout sem a conferência do compilador depois"
                        ));
                    }
                    pendente = true;
                }
                Some("./.github/actions/compilador") => pendente = false,
                Some("actions/cache") if pendente => {
                    fora.push(format!(
                        "{nome}: o cache vem antes da conferência do compilador"
                    ));
                    pendente = false;
                }
                _ if pendente && l.texto.contains("cargo ") => {
                    fora.push(format!(
                        "{nome}: `{}` vem antes da conferência do compilador",
                        l.texto
                    ));
                    pendente = false;
                }
                _ => {}
            }
        }
        if pendente {
            fora.push(format!(
                "{nome}: um checkout sem a conferência do compilador depois"
            ));
        }
        let usos = linhas
            .iter()
            .filter(|l| {
                chave_e_valor(l.texto).is_some_and(|(chave, valor)| {
                    chave == "uses" && nome_da_acao(valor) == "./.github/actions/compilador"
                })
            })
            .count();
        let ids = linhas
            .iter()
            .filter(|l| chave_e_valor(l.texto) == Some(("id", "compilador")))
            .count();
        if usos != ids {
            fora.push(format!(
                "{nome}: {usos} conferência(s) do compilador e {ids} `id: compilador` — a chave do \
                 cache lê o canal de `steps.compilador`"
            ));
        }
        for chave in chaves_de_cache(&linhas) {
            if !chave.contains("steps.compilador.outputs.canal") {
                fora.push(format!(
                    "{nome}: a chave de cache `{chave}` não leva o canal do compilador"
                ));
            }
        }
    }
    fora
}

/// As chaves de cache de um workflow: as de `key:` e as de `restore-keys:`,
/// numa linha ou num bloco `|` — as linhas mais recuadas que a chave,
/// mesmo depois de uma vazia.
fn chaves_de_cache<'a>(linhas: &[Linha<'a>]) -> Vec<&'a str> {
    let mut chaves = Vec::new();
    let mut bloco: Option<usize> = None;
    for l in linhas {
        if let Some(recuo) = bloco {
            if l.texto.is_empty() {
                continue;
            }
            if l.recuo > recuo {
                chaves.push(l.texto);
                continue;
            }
            bloco = None;
        }
        if let Some((chave, valor)) = chave_e_valor(l.texto)
            && (chave == "key" || chave == "restore-keys")
        {
            if valor.starts_with(['|', '>']) {
                bloco = Some(l.recuo);
            } else {
                chaves.push(valor);
            }
        }
    }
    chaves
}

/// A ação do compilador — `texto`, o [`ACAO_DO_COMPILADOR`] — tem o passo
/// do executor: o passo `id: executor` ([`PASSO_DO_EXECUTOR`]), depois do
/// `id: conferir` — que confere o canal e instala o toolchain —, em Python
/// (`shell: python3 -I {0}`), com o script que confere cada uma das
/// [`MARCAS_DO_EXECUTOR`]; e a ação não escreve no ambiente dos passos
/// seguintes — o `GITHUB_ENV`, o `GITHUB_PATH` —, que nenhuma regra dos
/// workflows lê nela.
///
/// # Por quê, desde o lote A9
///
/// O executor do config do cargo decide o que o `cargo xtask` roda — e o
/// `cargo test -p xtask` —, e o que nunca chama o `xtask` de verdade nunca
/// roda conferência nenhuma de dentro dele (o A8 do adversário do lote A8):
/// a conferência dele mora fora do cargo, na ação, antes de todo `cargo` da
/// CI. Aqui, que ela continua lá — como [`conferir_os_workflows`] confere que
/// os workflows chamam a ação. O teste
/// `a_acao_recusa_o_executor_o_ligador_e_o_apelido` roda o script.
fn conferir_a_acao(texto: &str) -> Vec<String> {
    let mut fora = Vec::new();
    let linhas = linhas_de_codigo(texto);
    let posicao = |id: &str| {
        linhas
            .iter()
            .position(|l| chave_e_valor(l.texto) == Some(("id", id)))
    };
    match (posicao("conferir"), posicao(PASSO_DO_EXECUTOR)) {
        (Some(conferir), Some(executor)) if conferir < executor => {}
        (_, None) => fora.push(format!(
            "{ACAO_DO_COMPILADOR}: sem o passo `id: {PASSO_DO_EXECUTOR}`, que confere o executor, \
             o ligador e o apelido do cargo fora do cargo"
        )),
        _ => fora.push(format!(
            "{ACAO_DO_COMPILADOR}: o passo `id: {PASSO_DO_EXECUTOR}` vem antes do `id: conferir`, \
             que instala o toolchain que ele consulta"
        )),
    }
    match passo_da_acao(texto, PASSO_DO_EXECUTOR) {
        Some((shell, script)) => {
            if shell != "python3 -I {0}" {
                fora.push(format!(
                    "{ACAO_DO_COMPILADOR}: o passo `{PASSO_DO_EXECUTOR}` roda em `{shell}`, e não \
                     em `python3 -I {{0}}`"
                ));
            }
            let codigo: Vec<&str> = script
                .lines()
                .filter(|l| !l.trim_start().starts_with('#'))
                .collect();
            for marca in MARCAS_DO_EXECUTOR {
                if !codigo.iter().any(|l| l.contains(marca)) {
                    fora.push(format!(
                        "{ACAO_DO_COMPILADOR}: o passo `{PASSO_DO_EXECUTOR}` não confere `{marca}`"
                    ));
                }
            }
            // Todo diretório de build do `xtask`: um novo entra nos dois.
            for dir in DIRETORIOS_DOS_BUILDS {
                let entre_aspas = format!("\"{dir}\"");
                if !codigo.iter().any(|l| l.contains(&entre_aspas)) {
                    fora.push(format!(
                        "{ACAO_DO_COMPILADOR}: o passo `{PASSO_DO_EXECUTOR}` não confere o config \
                         de `{dir}/`, um diretório de build do `xtask`"
                    ));
                }
            }
        }
        // Sem o passo, a mensagem de cima basta.
        None if posicao(PASSO_DO_EXECUTOR).is_some() => fora.push(format!(
            "{ACAO_DO_COMPILADOR}: o passo `{PASSO_DO_EXECUTOR}` sem `shell:` e `run:` que se leiam"
        )),
        None => {}
    }
    for l in &linhas {
        if l.texto.contains("GITHUB_ENV") || l.texto.contains("GITHUB_PATH") {
            fora.push(format!(
                "{ACAO_DO_COMPILADOR}: `{}` — a ação do compilador não escreve no ambiente dos \
                 passos seguintes",
                l.texto
            ));
        }
    }
    fora
}

/// O passo `id` de uma ação composta — `acao`, o texto do `action.yml` —: o
/// `shell:` e o script do `run: |`, sem o recuo dele. O passo vai do item de
/// lista que o contém — a linha com o `- ` no recuo dos passos — ao item
/// seguinte, ou ao que tiver recuo menor; o script, das linhas mais recuadas
/// que o `run:`, as vazias inclusive.
fn passo_da_acao(acao: &str, id: &str) -> Option<(String, String)> {
    let linhas: Vec<&str> = acao.lines().collect();
    let recuo = |l: &str| l.len() - l.trim_start().len();
    let do_id = linhas.iter().position(|l| {
        let t = l.trim();
        chave_e_valor(t) == Some(("id", id))
    })?;
    // O item do passo: o `- ` no id, ou na linha de cima mais próxima com
    // recuo menor.
    let comeco = (0..=do_id)
        .rev()
        .find(|&i| linhas[i].trim_start().starts_with("- "))?;
    let recuo_do_item = recuo(linhas[comeco]);
    let fim = (comeco + 1..linhas.len())
        .find(|&i| {
            let l = linhas[i];
            !l.trim().is_empty()
                && (recuo(l) < recuo_do_item
                    || (recuo(l) == recuo_do_item && l.trim_start().starts_with("- ")))
        })
        .unwrap_or(linhas.len());
    let passo = &linhas[comeco..fim];
    let valor_de = |chave: &str| {
        passo
            .iter()
            .find_map(|l| chave_e_valor(l.trim()).filter(|(c, _)| *c == chave))
            .map(|(_, v)| v.to_string())
    };
    let shell = valor_de("shell")?;
    let run = passo.iter().position(|l| {
        chave_e_valor(l.trim()).is_some_and(|(c, v)| c == "run" && (v == "|" || v == "|-"))
    })?;
    let recuo_do_run = recuo(passo[run]);
    let corpo: Vec<&str> = passo[run + 1..]
        .iter()
        .copied()
        .take_while(|l| l.trim().is_empty() || recuo(l) > recuo_do_run)
        .collect();
    let menor = corpo
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| recuo(l))
        .min()?;
    let script = corpo
        .iter()
        .map(|l| l.get(menor..).unwrap_or("").trim_end())
        .collect::<Vec<_>>()
        .join("\n");
    Some((shell, format!("{script}\n")))
}

/// Os gatilhos de push do canário — ele roda no agendamento e no disparo
/// manual, nunca num push.
fn gatilhos_de_push(nome: &str, linhas: &[Linha<'_>]) -> Vec<String> {
    let mut fora = Vec::new();
    let mut no_on = false;
    for l in linhas {
        if l.recuo == 0 && !l.texto.is_empty() {
            no_on = chave_e_valor(l.texto).is_some_and(|(chave, valor)| {
                if chave == "on" && ["push", "pull_request"].iter().any(|g| valor.contains(g)) {
                    fora.push(format!("{nome}: o canário roda num push (`{}`)", l.texto));
                }
                chave == "on"
            });
            continue;
        }
        if no_on
            && l.recuo == 2
            && let Some((chave, _)) = chave_e_valor(l.texto)
            && ["push", "pull_request", "pull_request_target"].contains(&chave)
        {
            fora.push(format!(
                "{nome}: o canário roda em `{chave}` — só no agendamento e no disparo manual"
            ));
        }
    }
    fora
}

/// O canário repete os comandos do job de lints da CI oficial: um comando
/// de lá que faltasse aqui seria uma conferência que o candidato não passa,
/// e o canário diria "aprovado" sem ela. Os comandos são os de
/// [`comandos_do_job`], no diretório deles, e os laços das arquiteturas; o
/// canário pode ter mais, e roda os testes com `--no-fail-fast`. Não
/// contam os passos em Python do canário — o relatório cita comandos no
/// texto —, nem a linha que neutraliza o comando (`|| true`).
fn o_canario_repete_os_lints(ci: &str, canario: &str) -> Vec<String> {
    let normal = |texto: &str| {
        texto
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .replace(" --no-fail-fast", "")
    };
    let linhas: Vec<String> = linhas_fora_do_python(canario)
        .into_iter()
        .map(normal)
        .filter(|l| !l.contains("|| true") && !l.contains("|| :"))
        .collect();
    let comandos = comandos_do_job(ci, JOB_DE_LINTS);
    if comandos.is_empty() {
        return vec![format!(
            "{CI}: o job `{JOB_DE_LINTS}` não foi achado, ou não tem comando — o canário repete os dele"
        )];
    }
    comandos
        .into_iter()
        .map(|c| normal(&c))
        .filter(|c| !linhas.iter().any(|l| contem_no_lugar(l, c)))
        .map(|c| {
            format!(
                "{CANARIO}: não repete `{c}`, do job `{JOB_DE_LINTS}` da CI oficial — quando a CI muda, o canário muda junto"
            )
        })
        .collect()
}

/// `linha` tem o `comando` no lugar dele: um comando da raiz não vale por
/// um igual dentro de um `cd outro && ...`.
fn contem_no_lugar(linha: &str, comando: &str) -> bool {
    let da_raiz = !comando.starts_with("cd ") && !comando.starts_with("(cd ");
    linha
        .match_indices(comando)
        .any(|(i, _)| !da_raiz || !linha[..i].trim_end().ends_with("&&"))
}

/// As linhas do canário fora dos passos em Python e dos comentários.
fn linhas_fora_do_python(canario: &str) -> Vec<&str> {
    /// Fecha um passo: as linhas dele ficam, se ele não é em Python.
    fn fechar<'a>(passo: &mut Vec<&'a str>, linhas: &mut Vec<&'a str>) {
        if !passo.iter().any(|l| l.trim().starts_with("shell: python")) {
            linhas.append(passo);
        }
        passo.clear();
    }
    let mut linhas = Vec::new();
    let mut passo = Vec::new();
    for l in canario.lines() {
        if l.trim_start().starts_with('#') {
            continue;
        }
        // Um passo novo: um item de lista no recuo dos passos.
        if l.starts_with("      - ") {
            fechar(&mut passo, &mut linhas);
        }
        passo.push(l);
    }
    fechar(&mut passo, &mut linhas);
    linhas
}

/// Os comandos de um job de um workflow: as linhas dos `run:` que chamam o
/// cargo ou o rustfmt — no diretório do `cd` de antes, no mesmo passo —,
/// os laços (`for ... do`), a instalação dos pacotes e as variáveis dos
/// passos.
fn comandos_do_job(workflow: &str, job: &str) -> Vec<String> {
    let cabecalho = format!("  {job}:");
    let mut dentro = false;
    let mut dir: Option<String> = None;
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
        if linha.starts_with("      - ") {
            dir = None;
        }
        let t = linha.trim();
        if t.starts_with('#') {
            continue;
        }
        let t = t.strip_prefix("run: ").unwrap_or(t);
        if let Some(d) = t.strip_prefix("cd ").filter(|d| !d.contains(' ')) {
            dir = Some(d.to_string());
            continue;
        }
        let variavel = t.split_once(": ").is_some_and(|(nome, _)| {
            !nome.is_empty() && nome.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        });
        let laco = t.starts_with("for ") && t.ends_with("; do");
        if t.contains("cargo ") || t.starts_with("rustfmt ") {
            comandos.push(match &dir {
                Some(d) if !t.starts_with("cd ") && !t.starts_with("(cd ") => {
                    format!("cd {d} && {t}")
                }
                _ => t.to_string(),
            });
        } else if t.starts_with("sudo apt-get install") || variavel || laco {
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
        // As do config escritas no ambiente: a consulta da tabela `[build]`
        // não as soma — o cargo só as cita —, e a conferência as lê pelo
        // nome (o item 1 do revisor do lote A8).
        for nome in [
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        ] {
            assert!(VARIAVEIS_QUE_TROCAM.contains(&nome), "{nome}");
        }
    }

    /// O executor e os apelidos do cargo (o A8 e o I3 do adversário do lote
    /// A8, no lote A9): no ambiente, o `CARGO_TARGET_<alvo>_RUNNER` de
    /// qualquer alvo e qualquer `CARGO_ALIAS_<nome>` são desvios — os vazios,
    /// o `CARGO_TARGET_DIR` e o `CARGO_TERM_COLOR`, não —; no config, lido
    /// pelo cargo, o `runner` de um `cfg(…)` e o do hospedeiro, também numa
    /// lista, e o `[alias]` que não é só o oficial — um a mais, o do `xtask`
    /// trocado ou escrito como lista, nenhum. O ligador não é desvio do
    /// começo: o config de quem compila pode escolher o do hospedeiro, e o
    /// do config do kernel é do `invariantes`.
    #[test]
    fn o_executor_e_o_apelido_sao_desvios() {
        let ambiente = |pares: &[(&str, &str)]| {
            desvios_do_ambiente_do_cargo(
                pares
                    .iter()
                    .map(|(n, v)| ((*n).to_string(), (*v).to_string())),
            )
        };
        assert_eq!(
            ambiente(&[
                ("CARGO_TERM_COLOR", "always"),
                ("CARGO_TARGET_DIR", "/x"),
                ("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER", "cc"),
                ("CARGO_ALIAS_X", ""),
            ]),
            Vec::<String>::new()
        );
        for (nome, forma) in [
            (
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
                "troca o executor",
            ),
            (
                "CARGO_TARGET_X86_64_UNKNOWN_NONE_RUNNER",
                "troca o executor",
            ),
            ("CARGO_ALIAS_XTASK", "é um apelido"),
            ("CARGO_ALIAS_B", "é um apelido"),
        ] {
            let d = ambiente(&[(nome, "ferramentas/rodar")]);
            assert!(
                d.len() == 1 && d[0].contains(nome) && d[0].contains(forma),
                "{nome}: {d:?}"
            );
        }
        let (apelido, valor) = APELIDO_DO_XTASK;
        let oficial = format!("[alias]\n{apelido} = \"{valor}\"\n");
        for (nome, texto, esperado) in [
            (
                "executor-cfg",
                format!("{oficial}[target.'cfg(unix)']\nrunner = \"ferramentas/rodar\"\n"),
                "`target.cfg(unix).runner`",
            ),
            (
                "executor-hospedeiro",
                format!(
                    "{oficial}[target.x86_64-unknown-linux-gnu]\nrunner = [\"ferramentas/rodar\", \"-x\"]\n"
                ),
                "`target.x86_64-unknown-linux-gnu.runner`",
            ),
            (
                "apelido-a-mais",
                format!("{oficial}b = \"build\"\n"),
                "\"b\":\"build\"",
            ),
            (
                "apelido-trocado",
                format!("[alias]\n{apelido} = \"run --package outro --\"\n"),
                "o `[alias]` do config do cargo é {\"xtask\":\"run --package outro --\"}",
            ),
            (
                "apelido-em-lista",
                format!(
                    "[alias]\n{apelido} = [\"run\", \"--quiet\", \"--package\", \"xtask\", \"--\"]\n"
                ),
                "e não só o oficial",
            ),
            (
                "sem-apelido",
                String::from("[build]\njobs = 2\n"),
                "o `[alias]` do config do cargo é (nenhum)",
            ),
        ] {
            let dir = com_config_cru(nome, &texto);
            let desvios = desvios_do_config(&dir, nome);
            let _ = std::fs::remove_dir_all(&dir);
            assert!(
                desvios.len() == 1
                    && desvios[0].starts_with(&format!("em `{nome}`, "))
                    && desvios[0].contains(esperado),
                "{nome}: {desvios:?}"
            );
        }
        // O oficial, também com a chave entre aspas, e o ligador do
        // hospedeiro passam.
        for (nome, texto) in [
            ("oficial", oficial.clone()),
            (
                "oficial-com-aspas",
                format!("[alias]\n\"{apelido}\" = \"{valor}\"\n"),
            ),
            (
                "ligador",
                format!("{oficial}[target.x86_64-unknown-linux-gnu]\nlinker = \"cc\"\n"),
            ),
        ] {
            let dir = com_config_cru(nome, &texto);
            let desvios = desvios_do_config(&dir, nome);
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(desvios, Vec::<String>::new(), "{nome}");
        }
    }

    /// A ação do compilador tem o passo do executor (no lote A9): depois do
    /// `id: conferir`, em Python, conferindo cada marca e cada diretório de
    /// build, e sem escrever no ambiente dos passos seguintes. A de verdade
    /// passa; sem o passo, com ele antes, noutro `shell`, sem uma marca, sem
    /// um diretório ou escrevendo no `GITHUB_ENV`, reprova.
    #[test]
    fn a_acao_tem_o_passo_do_executor() {
        let acao = include_str!("../../.github/actions/compilador/action.yml");
        assert_eq!(conferir_a_acao(acao), Vec::<String>::new());
        let (shell, script) = passo_da_acao(acao, PASSO_DO_EXECUTOR).expect("o passo");
        assert_eq!(shell, "python3 -I {0}");
        assert!(script.starts_with("import json\n"), "{script}");
        let cabeca = "    - id: executor\n";
        assert_eq!(acao.matches(cabeca).count(), 1);
        let (antes, depois) = acao.split_at(acao.find(cabeca).unwrap());
        let mut casos: Vec<(&str, String)> = vec![
            ("sem o passo", antes.to_string()),
            (
                "noutro shell",
                acao.replacen("shell: python3 -I {0}", "shell: bash", 1),
            ),
            (
                "sem o executor",
                acao.replace("(\"runner\", \"linker\")", "(\"linker\",)"),
            ),
            (
                "sem a raiz fechada",
                acao.replace("set(config) - {\"alias\"}", "set()"),
            ),
            (
                "sem o kernel",
                acao.replacen("            \"kernel\",\n", "", 1),
            ),
            (
                "escrevendo no ambiente",
                acao.replacen(
                    "echo \"canal=$canal\" >> \"$GITHUB_OUTPUT\"",
                    "echo \"canal=$canal\" >> \"$GITHUB_OUTPUT\"\n        echo \"X=1\" >> \"$GITHUB_ENV\"",
                    1,
                ),
            ),
        ];
        // O passo antes do `id: conferir`.
        let conferir = "    - id: conferir\n";
        let (topo, passos) = antes.split_at(antes.find(conferir).unwrap());
        casos.push(("antes do conferir", format!("{topo}{depois}\n{passos}")));
        for (rotulo, texto) in casos {
            assert_ne!(texto, acao, "{rotulo}");
            assert!(!conferir_a_acao(&texto).is_empty(), "{rotulo}");
        }
    }

    /// O passo do executor da ação, rodado como a CI o roda — o script do
    /// `run:`, em Python, na raiz de uma árvore à parte, com o cargo do canal
    /// e um `CARGO_HOME` vazio (o A8 do adversário do lote A8, no lote A9). A
    /// árvore com o config do repositório passa. Reprovam, cada um com a
    /// mensagem dele: o executor na raiz; um apelido a mais; o ligador do
    /// hospedeiro no config do kernel; o embrulho do compilador no do kernel;
    /// o `[env]` na raiz, que só tem o apelido; e, no ambiente, o apelido, o
    /// executor e o ligador.
    #[test]
    fn a_acao_recusa_o_executor_o_ligador_e_o_apelido() {
        let acao = include_str!("../../.github/actions/compilador/action.yml");
        let (_, script) = passo_da_acao(acao, PASSO_DO_EXECUTOR).expect("o passo");
        let base = std::env::temp_dir().join(format!("xtask-acao-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("a base");
        let arquivo = base.join("executor.py");
        std::fs::write(&arquivo, &script).expect("o script");
        let projeto = super::super::raiz_do_projeto();
        let ler = |relativo: &str| std::fs::read_to_string(projeto.join(relativo)).expect(relativo);
        let da_raiz = ler(".cargo/config.toml");
        let do_kernel = ler("kernel/.cargo/config.toml");
        // O cargo do canal primeiro no PATH, sem o proxy do rustup.
        let caminho = format!(
            "{}:{}",
            Path::new(env!("CARGO")).parent().expect("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let rodar = |nome: &str, raiz: &str, kernel: &str, ambiente: &[(&str, &str)]| {
            let arvore = base.join(nome);
            for pasta in [".cargo", "kernel/.cargo", "casa"] {
                std::fs::create_dir_all(arvore.join(pasta)).expect("a pasta");
            }
            std::fs::write(arvore.join(".cargo/config.toml"), raiz).expect("a raiz");
            std::fs::write(arvore.join("kernel/.cargo/config.toml"), kernel).expect("o kernel");
            let saida = Command::new("python3")
                .arg("-I")
                .arg(&arquivo)
                .current_dir(&arvore)
                .env_clear()
                .env("PATH", &caminho)
                .env("CARGO_HOME", arvore.join("casa"))
                .envs(ambiente.iter().copied())
                .output()
                .expect("o python3");
            (
                saida.status.success(),
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&saida.stdout),
                    String::from_utf8_lossy(&saida.stderr)
                ),
            )
        };
        let (passou, saida) = rodar("limpa", &da_raiz, &do_kernel, &[]);
        assert!(passou, "{saida}");
        assert!(saida.contains("só o apelido oficial"), "{saida}");
        let com_o_kernel = |texto: &str| format!("{do_kernel}\n{texto}");
        // O nome, o config da raiz, o do kernel, o ambiente e o que o passo
        // diz.
        type Caso = (
            &'static str,
            String,
            String,
            &'static [(&'static str, &'static str)],
            &'static str,
        );
        let casos: [Caso; 8] = [
            (
                "executor",
                format!("{da_raiz}\n[target.'cfg(unix)']\nrunner = \"ferramentas/rodar\"\n"),
                do_kernel.clone(),
                &[],
                "em ./, o config do cargo define target.cfg(unix).runner",
            ),
            (
                "apelido",
                format!("{da_raiz}b = \"build\"\n"),
                do_kernel.clone(),
                &[],
                "em ./, o [alias] do config do cargo é {",
            ),
            (
                "ligador",
                da_raiz.clone(),
                com_o_kernel("[target.x86_64-unknown-linux-gnu]\nlinker = \"ferramentas/ligar\"\n"),
                &[],
                "em kernel/, o config do cargo define target.x86_64-unknown-linux-gnu.linker",
            ),
            (
                "embrulho",
                da_raiz.clone(),
                do_kernel.replacen("[build]\n", "[build]\nrustc-wrapper = \"embrulho\"\n", 1),
                &[],
                "em kernel/, o config do cargo define build.rustc-wrapper",
            ),
            (
                "env-na-raiz",
                format!("{da_raiz}\n[env]\nDUKE_DE_FORA = \"1\"\n"),
                do_kernel.clone(),
                &[],
                "na raiz, onde o xtask se compila e roda, o config do cargo tem ['env']",
            ),
            (
                "apelido-no-ambiente",
                da_raiz.clone(),
                do_kernel.clone(),
                &[("CARGO_ALIAS_XTASK", "run --package outro --")],
                "a variável CARGO_ALIAS_XTASK está definida",
            ),
            (
                "executor-no-ambiente",
                da_raiz.clone(),
                do_kernel.clone(),
                &[(
                    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
                    "ferramentas/rodar",
                )],
                "a variável CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER está definida",
            ),
            (
                "ligador-no-ambiente",
                da_raiz.clone(),
                do_kernel.clone(),
                &[(
                    "CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER",
                    "ferramentas/ligar",
                )],
                "a variável CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER está definida",
            ),
        ];
        let mut cegos = Vec::new();
        for (nome, raiz, kernel, ambiente, esperado) in casos {
            let (passou, saida) = rodar(nome, &raiz, &kernel, ambiente);
            if passou || !saida.contains(&format!("::error::{esperado}")) {
                cegos.push(format!("{nome}: {saida}"));
            }
        }
        let _ = std::fs::remove_dir_all(&base);
        assert!(cegos.is_empty(), "{cegos:#?}");
    }

    #[test]
    fn as_chaves_da_tabela_build_que_trocam_o_compilador() {
        assert_eq!(
            chaves_que_trocam("{\"rustc-wrapper\":\"sccache\",\"target-dir\":\"/x\"}"),
            ["rustc-wrapper"]
        );
        assert_eq!(
            chaves_que_trocam("{\"rustc\":\"/opt/rustc\",\"rustc-workspace-wrapper\":\"w\"}"),
            ["rustc", "rustc-workspace-wrapper"]
        );
        assert!(chaves_que_trocam("{\"target\":\"x86_64-unknown-none\"}").is_empty());
        assert!(chaves_que_trocam("{\"rustc-wrapper\":\"\"}").is_empty());
    }

    /// Um diretório temporário com um `.cargo/config.toml` de `texto` e o
    /// apelido oficial do `xtask`, como o da raiz do repositório o dá a todo
    /// diretório de build.
    fn com_config(nome: &str, texto: &str) -> PathBuf {
        let (apelido, valor) = APELIDO_DO_XTASK;
        com_config_cru(
            nome,
            &format!("{texto}\n[alias]\n{apelido} = \"{valor}\"\n"),
        )
    }

    /// Um diretório temporário com um `.cargo/config.toml` de `texto`, e só.
    fn com_config_cru(nome: &str, texto: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("xtask-compilador-{}-{nome}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".cargo")).expect("o diretório");
        std::fs::write(dir.join(".cargo").join("config.toml"), texto).expect("o config");
        dir
    }

    #[test]
    fn o_config_do_cargo_lido_pelo_cargo_pega_toda_forma_de_escrever_a_chave() {
        // As formas que um leitor de texto deixava passar — o comentário
        // depois do cabeçalho, a tabela em linha, o cabeçalho e a chave entre
        // aspas, o ponto com espaços — e a comum, de controle.
        for (nome, texto) in [
            ("comum", "[build]\nrustc-wrapper = \"sccache\"\n"),
            (
                "comentario",
                "[build] # o cache da máquina\nrustc-wrapper = \"sccache\"\n",
            ),
            ("em-linha", "build = { rustc-wrapper = \"sccache\" }\n"),
            ("aspas", "[\"build\"]\n'rustc-wrapper' = \"sccache\"\n"),
            ("pontuada", "build . rustc = \"/opt/rustc\"\n"),
        ] {
            let dir = com_config(nome, texto);
            let desvios = desvios_do_config(&dir, nome);
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(desvios.len(), 1, "{nome}: {desvios:?}");
            assert!(
                desvios[0].contains("troca o compilador"),
                "{nome}: {desvios:?}"
            );
        }
        let dir = com_config("sem", "[build]\ntarget = \"x86_64-unknown-none\"\n");
        let desvios = desvios_do_config(&dir, "sem");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(desvios, Vec::<String>::new());
    }

    #[test]
    fn o_config_que_o_cargo_nao_le_e_um_desvio() {
        // A consulta falha fechada: um config que o cargo não lê — ou uma
        // resposta que mudasse num nightly novo — não passa calado.
        let dir = com_config("quebrado", "[build\nrustc-wrapper = \"sccache\"\n");
        let desvios = desvios_do_config(&dir, "quebrado");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(desvios.len(), 1, "{desvios:?}");
        assert!(desvios[0].contains("não respondeu"), "{desvios:?}");
    }

    #[test]
    fn os_config_do_cargo_do_repositorio_nao_trocam_o_compilador() {
        let raiz = super::super::raiz_do_projeto();
        for dir in ["", "kernel", "programas", "sdk/modelo"] {
            assert_eq!(
                desvios_do_config(&raiz.join(dir), dir),
                Vec::<String>::new(),
                "{dir}"
            );
        }
    }

    #[test]
    fn o_rust_toolchain_da_arvore_e_o_do_commit() {
        let arquivo = "rust-toolchain.toml";
        let commit = "# o oficial\n[toolchain]\nchannel = \"nightly-2026-11-15\"\n";
        // Os comentários não contam.
        let comentado = "[toolchain]\n# outro comentário\nchannel = \"nightly-2026-11-15\"\n\n";
        assert_eq!(
            desvio_do_arquivo(arquivo, Some(commit), Some(comentado)),
            None
        );
        let trocado = "[toolchain]\nchannel = \"nightly-2026-11-01\"\n";
        assert!(desvio_do_arquivo(arquivo, Some(commit), Some(trocado)).is_some());
        assert!(desvio_do_arquivo(arquivo, None, Some(commit)).is_some());
        assert!(desvio_do_arquivo(arquivo, Some(commit), None).is_some());
    }

    #[test]
    fn o_cargo_e_o_xtask_sao_os_do_toolchain_ativo() {
        let sysroot = Path::new("/r/toolchains/nightly-2026-11-15-x86_64-unknown-linux-gnu");
        assert_eq!(
            desvio_do_cargo(&sysroot.join("bin").join("cargo"), sysroot),
            None
        );
        assert!(
            desvio_do_cargo(
                Path::new("/r/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo"),
                sysroot
            )
            .is_some()
        );
        let vv = "rustc 1.102.0-nightly (5f4effd57 2026-11-13)\ncommit-hash: 5f4effd579500175af844241eb179e756190f1e7\nhost: x86_64-unknown-linux-gnu\n";
        assert_eq!(
            commit_do_rustc(vv),
            Some("5f4effd579500175af844241eb179e756190f1e7")
        );
        assert_eq!(
            desvio_do_xtask("5f4effd579500175af844241eb179e756190f1e7", vv),
            None
        );
        assert!(desvio_do_xtask("2d8144b78f00000000000000000000000000000", vv).is_some());
        assert!(desvio_do_xtask("desconhecido", vv).is_some());
        // O xtask desta execução de teste foi compilado pelo rustc do PATH.
        assert_ne!(COMPILADO_COM, "desconhecido");
    }

    #[test]
    fn com_o_opt_in_a_execucao_nunca_e_oficial() {
        assert!(observado(&[], false).oficial());
        assert!(!observado(&[], true).oficial());
        assert!(!observado(&["um desvio"], false).oficial());
        assert!(!observado(&["um desvio"], true).oficial());
    }

    /// Um compilador observado de teste, com os desvios e o opt-in dados.
    fn observado(desvios: &[&str], declarada_nao_oficial: bool) -> Compilador {
        Compilador {
            canal: Ok(String::from("nightly-2026-11-15")),
            toolchain: None,
            sysroot: None,
            rustc: None,
            cargo: None,
            desvios: desvios.iter().map(|d| (*d).to_string()).collect(),
            declarada_nao_oficial,
        }
    }

    #[test]
    fn a_conferencia_do_comeco_recusa_o_desvio_sem_o_opt_in() {
        assert_eq!(conferir_o_observado(&observado(&[], false)), Ok(()));
        // O opt-in sem desvio segue, como execução não oficial.
        assert_eq!(conferir_o_observado(&observado(&[], true)), Ok(()));
        // O desvio sem o opt-in para, com o desvio e o caminho de volta.
        let erro = conferir_o_observado(&observado(&["o desvio de teste"], false))
            .expect_err("o desvio sem o opt-in");
        assert!(erro.contains("  - o desvio de teste"), "{erro}");
        assert!(erro.contains(OUTRO_COMPILADOR), "{erro}");
        // O desvio com o opt-in segue, com o aviso.
        assert_eq!(
            conferir_o_observado(&observado(&["o desvio de teste"], true)),
            Ok(())
        );
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

        // Todo checkout leva a conferência depois, mesmo sem cargo adiante:
        // o último do workflow, e o primeiro de dois seguidos.
        let sem_conferencia = |fora: &[String]| {
            fora.iter()
                .any(|f| f.contains("um checkout sem a conferência do compilador depois"))
        };
        let no_fim = format!(
            "{OFICIAL}  outro:\n    steps:\n      - uses: actions/checkout@v4\n      - run: python3 -I conferir.py\n"
        );
        let fora = um(".github/workflows/ci.yml", &no_fim);
        assert!(sem_conferencia(&fora), "{fora:?}");
        let seguidos = OFICIAL.replacen(
            "      - uses: actions/checkout@v4\n",
            "      - uses: actions/checkout@v4\n      - uses: actions/checkout@v4\n",
            1,
        );
        assert_ne!(seguidos, OFICIAL);
        let fora = um(".github/workflows/ci.yml", &seguidos);
        assert!(sem_conferencia(&fora), "{fora:?}");
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
    #[test]
    fn o_checkout_e_a_conferencia_escritos_de_outro_jeito_nao_escapam() {
        // O checkout entre aspas, com espaço a mais, em várias linhas.
        for checkout in [
            "      - uses: 'actions/checkout@v4'\n",
            "      - uses:  actions/checkout@v4\n",
        ] {
            let texto = format!("{OFICIAL}{checkout}      - run: cargo build\n");
            let fora = um(".github/workflows/ci.yml", &texto);
            assert!(
                fora.iter().any(|f| f.contains("antes da conferência")),
                "{checkout}: {fora:?}"
            );
        }
        let em_linhas = format!("{OFICIAL}      - uses: >-\n          actions/checkout@v4\n");
        let fora = um(".github/workflows/ci.yml", &em_linhas);
        assert!(
            fora.iter().any(|f| f.contains("em várias linhas")),
            "{fora:?}"
        );
        // Uma ação parecida com a do compilador não é ela.
        let parecida = OFICIAL.replace(
            "uses: ./.github/actions/compilador",
            "uses: ./.github/actions/compilador-canario",
        );
        assert!(!um(".github/workflows/ci.yml", &parecida).is_empty());
        // Outra ação de toolchain, fora da lista.
        let outra = format!(
            "{OFICIAL}      - uses: actions-rust-lang/setup-rust-toolchain@v1\n        with:\n          toolchain: nightly\n"
        );
        assert!(!um(".github/workflows/ci.yml", &outra).is_empty());
    }

    #[test]
    fn a_chave_de_cache_escrita_de_outro_jeito_nao_escapa() {
        for (velho, novo) in [
            (
                "          key: testes-${{ steps.compilador.outputs.canal }}-",
                "          key : testes-",
            ),
            (
                "          key: testes-${{ steps.compilador.outputs.canal }}-",
                "          \"key\": testes-",
            ),
            (
                "            testes-${{ steps.compilador.outputs.canal }}-\n",
                "            testes-${{ steps.compilador.outputs.canal }}-\n\n            furtivo-\n",
            ),
        ] {
            let texto = OFICIAL.replace(velho, novo);
            assert_ne!(texto, OFICIAL, "{novo}");
            let fora = um(".github/workflows/ci.yml", &texto);
            assert!(
                fora.iter().any(|f| f.contains("não leva o canal")),
                "{novo}: {fora:?}"
            );
        }
        // O estilo de fluxo esconde as chaves: recusado.
        let fluxo = OFICIAL.replace(
            "        with:\n",
            "        with: { path: target, key: furtivo-, restore-keys: furtivo- }\n        x:\n",
        );
        assert!(
            um(".github/workflows/ci.yml", &fluxo)
                .iter()
                .any(|f| f.contains("estilo de fluxo"))
        );
    }

    #[test]
    fn as_sobreposicoes_de_fora_da_lista_antiga_sao_recusadas() {
        for linha in [
            "        run: cargo --config 'build.rustc-wrapper=\"sccache\"' clippy\n",
            "        run: printf '[build]' >> ~/.cargo/config.toml\n",
            "        run: echo nightly > kernel/rust-toolchain\n",
            "        run: echo /opt/rust/bin >> \"$GITHUB_PATH\"\n",
            "        env:\n          CARGO_HOME: /opt/outro\n",
            "        run: rustup toolchain install nightly\n",
        ] {
            let texto = format!("{OFICIAL}{linha}");
            assert!(
                !um(".github/workflows/ci.yml", &texto).is_empty(),
                "{linha}"
            );
        }
        // Código de dentro de um `run:` não é YAML.
        let codigo = format!(
            "{OFICIAL}        run: |\n          avisos.append(f\"aviso: {{descricao}} tem\")\n"
        );
        assert_eq!(
            um(".github/workflows/ci.yml", &codigo),
            Vec::<String>::new()
        );
        // Uma variável que só começa por RUSTC não troca o compilador.
        let log = format!("{OFICIAL}        env:\n          RUSTC_LOG: rustc_codegen_ssa=info\n");
        assert_eq!(um(".github/workflows/ci.yml", &log), Vec::<String>::new());
    }

    #[test]
    fn uma_acao_local_segue_as_regras_dos_workflows_oficiais() {
        let acao = "runs:\n  using: composite\n  steps:\n    - run: echo \"RUSTUP_TOOLCHAIN=nightly\" >> \"$GITHUB_ENV\"\n      shell: bash\n";
        assert!(!um(".github/actions/outra/action.yml", acao).is_empty());
        let com_cache = "runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n";
        assert_eq!(
            um(".github/actions/outra/action.yml", com_cache),
            Vec::<String>::new()
        );
        // A do compilador cita o que recusa, e fica de fora da regra.
        assert_eq!(um(ACAO_DO_COMPILADOR, acao), Vec::<String>::new());
    }

    #[test]
    fn o_canario_nao_roda_nos_pushes() {
        let base = "on:\n  schedule:\n    - cron: '17 4 * * 1'\n  workflow_dispatch:\njobs:\n  canario:\n    steps:\n      - uses: actions/checkout@v4\n";
        assert_eq!(um(CANARIO, base), Vec::<String>::new());
        let com_push = base.replace(
            "  workflow_dispatch:\n",
            "  push:\n    branches: [x]\n  workflow_dispatch:\n",
        );
        assert_eq!(um(CANARIO, &com_push).len(), 1);
        let em_linha = base.replace(
            "on:\n  schedule:\n    - cron: '17 4 * * 1'\n  workflow_dispatch:\n",
            "on: [push, workflow_dispatch]\n",
        );
        assert_eq!(um(CANARIO, &em_linha).len(), 1);
    }

    #[test]
    fn a_paridade_com_os_lints_olha_o_diretorio_os_lacos_e_o_efeito() {
        let ci = include_str!("../../.github/workflows/ci.yml");
        let canario = include_str!("../../.github/workflows/canario.yml");
        let comandos = comandos_do_job(ci, JOB_DE_LINTS);
        assert!(
            comandos
                .iter()
                .any(|c| c == "cd kernel && cargo clippy --target \"$alvo\" -- -D warnings"),
            "{comandos:#?}"
        );
        assert!(comandos.iter().any(|c| c.starts_with("for alvo in ")));
        // O clippy do kernel some: a linha do iniciador não o substitui.
        let sem_kernel = canario.replace(
            "(cd kernel && cargo clippy --target \"$alvo\" -- -D warnings) \\",
            "true \\",
        );
        assert_ne!(sem_kernel, canario);
        assert_eq!(o_canario_repete_os_lints(ci, &sem_kernel).len(), 1);
        // O comando neutralizado não conta.
        let neutralizado = canario.replace(
            "cargo xtask invariantes 2>&1",
            "cargo xtask invariantes || true; true 2>&1",
        );
        assert_ne!(neutralizado, canario);
        assert_eq!(o_canario_repete_os_lints(ci, &neutralizado).len(), 1);
        // Um comando da raiz que o canário só roda noutro diretório não vale.
        let noutro_diretorio = canario.replace(
            "cargo xtask invariantes 2>&1",
            "cd kernel && cargo xtask invariantes 2>&1",
        );
        assert_ne!(noutro_diretorio, canario);
        assert_eq!(o_canario_repete_os_lints(ci, &noutro_diretorio).len(), 1);
        // Sem os pacotes dos testes do hospedeiro.
        let sem_pacotes = canario.replace(
            "sudo apt-get install -y --no-install-recommends swtpm nghttp2-server",
            "true",
        );
        assert_ne!(sem_pacotes, canario);
        assert_eq!(o_canario_repete_os_lints(ci, &sem_pacotes).len(), 1);
        // Sem o aarch64 nos laços.
        let sem_arm = canario.replace(
            "for alvo in x86_64-unknown-none aarch64-unknown-none-softfloat; do",
            "for alvo in x86_64-unknown-none; do",
        );
        assert!(!o_canario_repete_os_lints(ci, &sem_arm).is_empty());
        // Só no texto de um passo em Python, não vale.
        let so_no_python = canario
            .replace("cargo xtask invariantes 2>&1", "true 2>&1")
            .replace(
                "      - name: O veredito\n",
                "      - name: Um texto\n        shell: python3 -I {0}\n        run: |\n          print(\"cargo xtask invariantes\")\n\n      - name: O veredito\n",
            );
        assert_eq!(o_canario_repete_os_lints(ci, &so_no_python).len(), 1);
    }
}
