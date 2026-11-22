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
//!     ([`VARIAVEIS_QUE_TROCAM`]: as três do cargo, as três
//!     `CARGO_BUILD_RUSTC*` do config e, desde o lote A10, o `RUSTDOC` e o
//!     `CARGO_BUILD_RUSTDOC`, o compilador dos doctests), e as chaves
//!     `build.rustc`, `build.rustc-wrapper`, `build.rustc-workspace-wrapper`
//!     e `build.rustdoc` do config do cargo — lido pelo próprio cargo em cada
//!     diretório de build, com todo arquivo que vale ali e toda forma de
//!     escrever a chave;
//!   - desde o lote A9, o executor e os apelidos do cargo
//!     ([`desvios_da_configuracao`], [`desvios_do_ambiente_do_cargo`]): um
//!     `runner` em qualquer tabela `target` do config, ou um
//!     `CARGO_TARGET_<alvo>_RUNNER`, e um `[alias]` que não é só o oficial
//!     ([`APELIDO_DO_XTASK`]), ou um `CARGO_ALIAS_<nome>`. O `cargo xtask` é
//!     o `cargo run` do `xtask`, e o `cargo run` passa o binário pelo
//!     executor: um executor do repositório decidiria o que o `cargo xtask
//!     invariantes` diz. Aqui se vê o executor que ainda chama o `xtask` de
//!     verdade; o que não chama nunca roda esta conferência — na CI, quem o
//!     recusa é a ação do compilador ([`ACAO_DO_COMPILADOR`]), antes de todo
//!     `cargo` que compila ou roda ([`PASSOS_DA_ACAO`]);
//!   - desde o lote A10, o config de cada diretório de build fechado a uma
//!     lista ([`desvios_da_configuracao`]) — o que os configs do repositório
//!     usam: o apelido, o `build.target` e os rustflags de cada alvo nas
//!     formas de hoje ([`FORMAS_DOS_RUSTFLAGS`]) —, a mesma regra que a ação
//!     aplica fora da raiz, e, desde o lote A11, na raiz, onde o `xtask` se
//!     compila e roda, só o apelido, como na ação ([`TABELAS_DA_RAIZ`]); e
//!     os dois `rust-toolchain.toml` só com as chaves do oficial
//!     ([`desvios_dos_toolchains`]): um `path` faria o rustup rodar o
//!     `cargo` de uma pasta.
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
//!   data, é o mesmo nos dois arquivos, com as chaves do oficial, e o
//!   `CLAUDE.md` o cita; não há outro `rust-toolchain` no repositório; o
//!   config do cargo dos diretórios com `.cargo/` não troca o compilador,
//!   nem o executor, nem o apelido, e fica na lista — na raiz, só o
//!   apelido, como na ação —; o `xtask` não chama o cargo nem o rustc com
//!   outro toolchain; os workflows oficiais só usam as ações de
//!   [`ACOES_OFICIAIS`], não sobrepõem o toolchain e conferem o compilador
//!   — a ação `.github/actions/compilador`, num passo sem `if:` nem
//!   `continue-on-error:`, que, desde o lote A12, a leitura lê inteiro e
//!   falha fechada ([`linhas_que_o_passo_nao_le`]) — depois de cada
//!   checkout, antes do cache e de qualquer `cargo`, com o canal em toda
//!   chave de cache — desde o lote A13, numa leitura que falha fechada no
//!   arquivo inteiro: as quebras de linha que só o YAML vê e, fora do
//!   conteúdo dos blocos, as formas que ela não lê reprovam
//!   ([`quebras_que_a_leitura_nao_ve`], [`forma_que_a_leitura_nao_le`]), e
//!   um checkout escrito numa delas não escapa da ordem —; a ação tem os
//!   passos que conferem, fora do cargo, o
//!   ambiente, o PATH, os `rust-toolchain`, os artefatos e — desde o lote
//!   A12 — os links do commit, e o config do cargo — o do executor desde o
//!   lote A9, os outros desde o lote A10 —, e o das invariantes, que o job
//!   de lints liga pela entrada `invariantes: true` no `with:` do passo dela
//!   ([`conferir_a_acao`], [`as_invariantes_na_acao`]) — desde o lote A13,
//!   cada passo dela só com as chaves que a leitura lê nele, sem `if:`,
//!   `continue-on-error:` nem `env:` a mais
//!   ([`linhas_que_o_passo_da_acao_nao_le`]) —; e o canário, o
//!   único que sobrepõe — ele
//!   testa o candidato —, não roda nos pushes, não usa o cache da CI, não
//!   publica proveniência e repete os comandos do job de lints;
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
///
/// # O rustdoc, desde o lote A10
///
/// O `cargo test` compila e roda os doctests pelo `rustdoc` — o do
/// `RUSTDOC`, do `CARGO_BUILD_RUSTDOC` ou da chave `build.rustdoc`, se
/// houver —, e o `cargo doc` também: um doctest compilado por outro
/// `rustdoc` passava em silêncio numa validação oficial (o IN6 do
/// adversário do lote A9). O `rustdoc` é um compilador do toolchain como o
/// `rustc`: as duas variáveis entram aqui, e a chave, em
/// [`CHAVES_QUE_TROCAM`].
const VARIAVEIS_QUE_TROCAM: [&str; 8] = [
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOC",
    "CARGO_BUILD_RUSTDOC",
];

/// As chaves da tabela `[build]` do config do cargo que trocam, ou
/// embrulham, o compilador — o `rustc` ou, desde o lote A10, o `rustdoc`.
const CHAVES_QUE_TROCAM: [&str; 4] = [
    "rustc",
    "rustc-wrapper",
    "rustc-workspace-wrapper",
    "rustdoc",
];

/// O apelido do `cargo xtask`, como o `.cargo/config.toml` da raiz o diz: o
/// único `[alias]` do config do cargo, em todo diretório de build. Outro
/// apelido — ou este com outro valor — decide o que o `cargo xtask` roda.
pub(crate) const APELIDO_DO_XTASK: (&str, &str) = ("xtask", "run --quiet --package xtask --");

/// As tabelas do config do cargo de um diretório de build, a lista fechada
/// ([`desvios_da_configuracao`]): o apelido, a `[build]` — só o
/// `build.target` — e a `target` — só os `rustflags` de cada alvo. É o que
/// os configs do repositório usam; o resto — o `[env]`, o `[host]`, o
/// `[unstable]`, o `[profile]`, o `paths`, o `[source]`, o `[patch]`, o
/// `target-applies-to-host` — escolhe o programa que roda, ou o código que
/// se compila, e é desvio. Uma nova muda a lista, e a mudança é revisada.
const TABELAS_DO_CONFIG: [&str; 3] = ["alias", "build", "target"];

/// As tabelas do config do cargo na raiz do repositório, onde o `xtask` se
/// compila e roda ([`desvios_da_configuracao`]): só o apelido, como a ação
/// do compilador aceita ali — desde o lote A11.
const TABELAS_DA_RAIZ: [&str; 1] = ["alias"];

/// Os alvos do projeto, os do `rust-toolchain.toml` da raiz: o
/// `build.target` de um diretório de build é um deles — um alvo de um
/// arquivo (`alvo.json`) escolhe o ligador ([`desvios_da_configuracao`]).
/// O teste `os_alvos_do_projeto_sao_os_do_toolchain` confere a lista contra
/// o arquivo.
const ALVOS_DO_PROJETO: [&str; 4] = [
    "x86_64-unknown-none",
    "aarch64-unknown-none-softfloat",
    "x86_64-unknown-uefi",
    "aarch64-unknown-uefi",
];

/// As formas dos rustflags de um diretório de build, a lista fechada
/// ([`desvios_da_configuracao`]): o `--cfg` com qualquer valor, e o `-C`
/// com um destes valores, ou com o script do ligador
/// ([`SCRIPT_DO_LIGADOR`]) — o que os configs do kernel, dos programas e do
/// modelo do SDK usam hoje. Pela lista das formas, e não pelo `-C linker`
/// que se procuraria: o `-C link-arg=-fuse-ld=…` e o `-C link-arg=-B…`
/// também escolhem o programa que liga. Os do kernel, a lista exata, o
/// `invariantes` confere à parte (`RUSTFLAGS_DO_KERNEL`, no `main.rs`). Uma
/// nova muda a lista, e a mudança é revisada.
const FORMAS_DOS_RUSTFLAGS: [&str; 4] = [
    "link-arg=--no-pie",
    "link-arg=-zmax-page-size=4096",
    "relocation-model=static",
    "llvm-args=-align-loops=128",
];

/// O começo do `-C` do script do ligador, a única forma com um valor livre
/// ([`FORMAS_DOS_RUSTFLAGS`]): o script descreve onde o ligador põe as
/// seções, e não escolhe o programa que liga.
const SCRIPT_DO_LIGADOR: &str = "link-arg=-T";

/// As chaves do `[toolchain]` de um `rust-toolchain.toml` do repositório
/// ([`desvios_dos_toolchains`]): as que o oficial usa. Um `path` faz o
/// rustup rodar o `cargo` e o `rustc` de uma pasta — do repositório, com um
/// caminho absoluto — no lugar dos do canal (o F2 do adversário do lote A9).
const CHAVES_DO_TOOLCHAIN: [&str; 4] = ["channel", "components", "targets", "profile"];

/// O passo da ação do compilador ([`ACAO_DO_COMPILADOR`]) que confere o
/// executor, o ligador e os apelidos do cargo fora do cargo — ver
/// [`conferir_a_acao`].
const PASSO_DO_EXECUTOR: &str = "executor";

/// Os passos da ação do compilador, na ordem ([`conferir_a_acao`]): o do
/// ambiente — o ambiente do job, as casas, o PATH, os `rust-toolchain`, os
/// manifestos, os diretórios de saída —, o que confere e instala o canal, o
/// do executor e o das invariantes, que só o job de lints liga. Cada um com
/// o `shell:` dele — os dois em Python pelo `python3` do sistema, e não
/// pelo do PATH, que é o que o primeiro confere — e as marcas do que ele
/// tem de conferir, no texto do script; o que o script faz com cada uma, os
/// testes que o rodam como o runner conferem (`a_acao_roda_como_no_runner`
/// e os `adversario_a9_…` da ação, e `os_manifestos_que_escolhem_o_ligador`).
///
/// # Os manifestos, desde o lote A10
///
/// Um `Cargo.toml` com `cargo-features = ["profile-rustflags"]` liga os
/// `rustflags` de um perfil: com `[profile.dev] rustflags = ["-C",
/// "linker=…"]` no da raiz, o cargo do canal ligaria o `xtask` das
/// invariantes com o programa do repositório — num experimento fora da
/// árvore, com o mesmo cargo, o ligador do perfil montou o binário de um
/// workspace como o da raiz.
/// É o F1 do adversário do lote A9 por outra fonte, e a regra só vale fora
/// do `xtask`: dentro dele chegaria tarde, com o binário já montado pelo
/// ligador do perfil. O passo do ambiente recusa o `cargo-features` em
/// todo manifesto, e os `rustflags` e o `codegen-backend` em todo perfil.
///
/// # Os links, desde o lote A12
///
/// O passo do ambiente recusava o arquivo do commit num diretório de saída
/// do cargo pelo caminho dele, e um `target` que é um link — o modo 120000
/// do índice, sem a barra — para uma pasta do commit passava: os arquivos
/// dela não começam por `target/`, e, num experimento fora da árvore, com
/// as horas dos arquivos postas a favor do ataque, o cargo rodou o `xtask`
/// plantado nela (o achado 3 do adversário do lote A11). O passo recusa
/// todo link do commit, pelo modo do índice — o repositório não tem nenhum
/// —, e todo link no caminho de um diretório de saída, no disco.
const PASSOS_DA_ACAO: [(&str, &str, &[&str]); 4] = [
    (
        "ambiente",
        "/usr/bin/python3 -I {0}",
        &[
            "LEEM = (\"CARGO\", \"RUST\", \"__CARGO\")",
            "PERMITIDAS = (\"CARGO_HOME\", \"CARGO_TERM_COLOR\", \"RUSTUP_HOME\", \"RUST_BACKTRACE\")",
            "PROGRAMAS = (\"cargo\", \"rustc\", \"rustdoc\", \"rustfmt\")",
            "CHAVES = (\"channel\", \"components\", \"targets\", \"profile\")",
            "PERFIL_FORA = (\"rustflags\", \"codegen-backend\")",
            "os.environ.get(\"PATH\"",
            "no_repositorio(valor)",
            "\"ls-files\"",
            "\"cargo-features\" in manifesto",
            "erros.extend(manifesto_fora(arquivo))",
            "os.path.samefile(achado, rustup)",
            "arquivo.startswith(saidas)",
            "if modo == \"120000\":",
            "if os.path.islink(atual):",
        ],
    ),
    (
        "conferir",
        "bash",
        &[
            "git diff --quiet HEAD -- rust-toolchain.toml sdk/modelo/rust-toolchain.toml",
            "export RUSTUP_TOOLCHAIN=\"$canal\"",
            "sysroot=$(rustc --print sysroot)",
        ],
    ),
    (
        PASSO_DO_EXECUTOR,
        "/usr/bin/python3 -I {0}",
        &[
            "\"config\", \"get\"",
            "RUSTUP_TOOLCHAIN=toolchain[\"channel\"]",
            "env=ambiente",
            "\"alias\"",
            "(\"runner\", \"linker\")",
            "\"rustdoc\")",
            "set(config) - {\"alias\"}",
            "set(config) - set(TABELAS)",
            "rustflag_fora(",
            "build[\"target\"] not in ALVOS",
        ],
    ),
    ("invariantes", "bash", &["cargo xtask invariantes"]),
];

/// O commit do rustc que compilou este `xtask`, gravado pelo `build.rs`.
const COMPILADO_COM: &str = env!("XTASK_RUSTC_COMMIT");

/// O que, num workflow oficial, sobrepõe ou troca o compilador do
/// `rust-toolchain.toml`: as variáveis, os `+toolchain`, o `--config` do
/// cargo, os comandos do rustup que mudam o toolchain, o `PATH` dos passos
/// seguintes e o config do cargo da máquina. E, desde o lote A10, o
/// `RUSTDOC` e o `RUSTFMT`, que escolhem o rustdoc e o rustfmt que rodam, e
/// o `PATH` de um passo ou de um job, que escolhe o `cargo` (o F1 e o F2 do
/// adversário do lote A9). Na ação do compilador, que roda antes de todo
/// `cargo`, o ambiente do job se confere por uma lista fechada; aqui, o
/// texto de todo passo, também dos que rodam depois dela.
const SOBREPOSICOES: [&str; 24] = [
    "RUSTUP_TOOLCHAIN",
    "RUSTUP_HOME",
    "CARGO_HOME",
    "DUKE_OUTRO_COMPILADOR",
    "RUSTC:",
    "RUSTC=",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC",
    "RUSTDOC:",
    "RUSTDOC=",
    "CARGO_BUILD_RUSTDOC",
    "RUSTFMT",
    "PATH:",
    "PATH=",
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

/// As chaves que o passo da conferência do compilador não tem, num workflow
/// oficial ([`conferir_os_workflows`]): com o `if:`, a conferência pode não
/// rodar — um `if: false`, um `if: github.event_name == 'push'` —, e o job
/// segue sem ela; com o `continue-on-error:`, o job segue com ela
/// reprovada, e todo `cargo` dele roda depois de uma conferência que
/// recusou. Desde o lote A11 (a nota do revisor do lote A10): nenhuma regra
/// as lia. E, desde o lote A12, a leitura do passo falha fechada
/// ([`linhas_que_o_passo_nao_le`]): uma delas escrita de um jeito que ela
/// não lê — o `"i\x66": false` — reprova como uma linha que ela não lê.
const CHAVES_FORA_DO_PASSO_DA_ACAO: [&str; 2] = ["if", "continue-on-error"];

/// As chaves que a leitura do passo da conferência do compilador aceita, num
/// workflow oficial, na forma simples ([`linhas_que_o_passo_nao_le`]): o
/// nome, o `id` de que a chave do cache lê o canal, a própria ação e as
/// entradas dela. Outra — o `env:`, o `timeout-minutes:` — reprova; uma nova
/// entra aqui, de propósito, com a revisão. Desde o lote A12 (o achado 1 do
/// adversário do lote A11): a leitura falha fechada.
const CHAVES_DO_PASSO_DA_ACAO: [&str; 4] = ["name", "id", "uses", "with"];

/// As chaves que a leitura de um passo da ação do compilador
/// ([`PASSOS_DA_ACAO`]) aceita em todos eles, na forma simples: o nome, o
/// `id` e o `shell`; mais o `run: |` com o script e, só no das invariantes, o
/// `if:` da entrada e o `env:` com o toolchain fixado, que
/// [`conferir_a_acao`] exige. Outra — o `if:` de outro passo, o
/// `continue-on-error:`, um `env:` a mais, o `working-directory:` — reprova
/// ([`linhas_que_o_passo_da_acao_nao_le`]). Desde o lote A13 (o M4 do
/// adversário do lote A12).
const CHAVES_DOS_PASSOS_DA_ACAO: [&str; 3] = ["name", "id", "shell"];

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
    desvios.extend(desvios_dos_toolchains(&raiz));

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
        desvios.extend(desvios_do_config(dir, rotulo, *dir == raiz));
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
            ler(nome).filter(|v| !v.is_empty()).map(|v| {
                format!(
                    "a variável `{nome}={v}` troca o compilador do cargo — o `rustc` ou o \
                         `rustdoc`, que compila e roda os doctests"
                )
            })
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
/// apelido do `cargo xtask`, ou que sai da lista ([`desvios_da_configuracao`]),
/// como o próprio cargo o lê ali ([`config_inteiro`]): todos os arquivos que
/// valem para o diretório — os de cima, o do `CARGO_HOME` — e toda forma de
/// escrever cada chave. As variáveis do ambiente, que a consulta não soma, são de
/// [`desvios_das_variaveis`] e de [`desvios_do_ambiente_do_cargo`]. A
/// consulta é a do cargo nightly (`-Zunstable-options config get`); o
/// canário diz se ela mudar. `na_raiz`: `dir` é a raiz do repositório, onde
/// o `xtask` se compila e roda, e o config é só o apelido
/// ([`TABELAS_DA_RAIZ`]).
fn desvios_do_config(dir: &Path, rotulo: &str, na_raiz: bool) -> Vec<String> {
    match config_inteiro(dir) {
        Ok(config) => desvios_da_configuracao(&config, na_raiz)
            .into_iter()
            .map(|d| format!("em `{rotulo}`, {d}"))
            .collect(),
        Err(e) => vec![format!("em `{rotulo}`, {e}")],
    }
}

/// O que `config` — o config inteiro do cargo, em JSON, como
/// [`config_inteiro`] o devolve — tem que troca o compilador, o executor ou
/// o apelido do `cargo xtask`, ou que sai da lista: as chaves de
/// [`CHAVES_QUE_TROCAM`] na tabela `[build]`; desde o lote A9, um `runner`
/// em qualquer tabela `target` — a de um alvo, a de um `cfg(…)` —; um
/// `[alias]` que não é só o [`APELIDO_DO_XTASK`], com o valor dele: um
/// apelido a mais, um a menos, ou o do `xtask` com outro valor ou escrito
/// como lista; e, desde o lote A10, o resto fora da lista fechada — uma
/// tabela fora de [`TABELAS_DO_CONFIG`], uma chave da `[build]` além do
/// `build.target`, um `build.target` fora de [`ALVOS_DO_PROJETO`], uma
/// chave de uma tabela `target` além dos `rustflags` — o ligador inclusive
/// — e um rustflag fora das formas de [`FORMAS_DOS_RUSTFLAGS`].
///
/// # O executor e o apelido, desde o lote A9
///
/// O `cargo xtask` é o `cargo run --package xtask`, e o `cargo run` passa o
/// binário pelo executor do alvo do hospedeiro: um `[target.'cfg(unix)']
/// runner = "ferramentas/rodar"` no config da raiz, com um script que
/// responde `invariantes` com sucesso e roda o `xtask` de verdade para o
/// resto, fazia o passo das invariantes da CI passar sem guarda nenhuma; e o
/// mesmo executor recebe os binários do `cargo test -p xtask`, que um script
/// que os reconhecesse faria passar também (o A8 do adversário do lote A8).
/// O apelido é o mesmo ponto (o I3 dele). Aqui se vê o executor que ainda
/// chama o `xtask`; o que nunca o chama, na CI, a ação do compilador o
/// recusa antes de todo `cargo` que compila ou roda ([`PASSOS_DA_ACAO`]).
///
/// # O config fechado, desde o lote A10
///
/// Fora da raiz, a ação só lia, do config, o apelido, o executor, o ligador
/// e a `[build]` que troca o compilador: o `[env] PATH` dos programas — que
/// faz o `rustc` ligar os `build.rs` com o `cc` de uma pasta —, o `[host]
/// linker` e o `-C linker=` nos rustflags passavam. O clippy dos programas
/// ligava os `build.rs` e as macros procedurais com os dois primeiros, no
/// job de lints, antes das invariantes, e o terceiro ligaria os programas
/// que a suíte e as bancadas rodam nos outros jobs (o F3 do adversário do
/// lote A9). Pela lista do que os configs do repositório
/// usam, e não pelos nomes do ligador, que são muitos: a mesma regra da
/// ação, aqui no começo de todo comando e no `invariantes`, em todo
/// diretório de build — o config da raiz, só com o apelido na ação, vale
/// também nos de baixo. O config da máquina de quem compila entra na
/// consulta: um `[build] jobs` ou um `[net]` pessoal no `CARGO_HOME` é um
/// desvio, como o apelido pessoal desde o lote A9; quem o tem o tira, ou
/// declara a execução não oficial. O config do kernel tem, além desta, a
/// conferência exata do `invariantes` (`config_do_kernel_fora`, no
/// `main.rs`).
///
/// # A raiz, desde o lote A11
///
/// Na raiz, onde o `xtask` se compila e roda, a ação só aceita o apelido, e
/// esta lista aceitava ali também o `build.target` e os rustflags nas formas
/// dela — o `-C link-arg=-T…` inclusive, cujo script pode trazer objetos à
/// ligação do `xtask` (o `INPUT`) —, a outra nota do revisor do lote A10.
/// Com `na_raiz`, a lista é a de [`TABELAS_DA_RAIZ`], como na ação. Nenhum
/// uso de hoje quebra: o config da raiz só tem o apelido, e os diretórios
/// de baixo, que também o leem, têm o alvo e os rustflags nos configs
/// deles.
fn desvios_da_configuracao(config: &str, na_raiz: bool) -> Vec<String> {
    let config = Json(config.trim().as_bytes());
    let mut desvios = Vec::new();
    let mut tabelas = Vec::new();
    config.para_cada_chave(|tabela| tabelas.push(tabela));
    let lista: &[&str] = if na_raiz {
        &TABELAS_DA_RAIZ
    } else {
        &TABELAS_DO_CONFIG
    };
    for tabela in tabelas
        .iter()
        .filter(|t| !lista.contains(&chave_legivel(t).as_str()))
    {
        desvios.push(if na_raiz {
            format!(
                "o config do cargo tem `{}`, na raiz, onde o `xtask` se compila e roda: ali, só o \
                 apelido oficial ({TABELAS_DA_RAIZ:?}), como na ação do compilador — o alvo, os \
                 rustflags e o script do ligador do hospedeiro mudariam o `xtask` antes de ele \
                 conferir qualquer coisa",
                chave_legivel(tabela)
            )
        } else {
            format!(
                "o config do cargo tem `{}`, fora da lista ({TABELAS_DO_CONFIG:?}): o `[env]`, o \
                 `[host]`, o `[unstable]`, o `[profile]`, o `paths`, o `[source]` e o `[patch]` \
                 escolhem o programa que roda, ou o código que se compila",
                chave_legivel(tabela)
            )
        });
    }
    if let Some(build) = config.member("build") {
        let trocam = chaves_que_trocam(build.raw_str().unwrap_or(""));
        for chave in &trocam {
            desvios.push(format!(
                "o config do cargo define `build.{chave}`: troca o compilador"
            ));
        }
        let mut chaves = Vec::new();
        build.para_cada_chave(|chave| chaves.push(chave));
        for chave in chaves {
            let legivel = chave_legivel(chave);
            if legivel == "target" {
                let alvo = build.member(chave).and_then(|a| a.as_str());
                if !alvo.is_some_and(|a| ALVOS_DO_PROJETO.contains(&a)) {
                    desvios.push(format!(
                        "o config do cargo define `build.target` = {}, e não um dos alvos do \
                         projeto ({ALVOS_DO_PROJETO:?}): um alvo de um arquivo escolhe o ligador",
                        build.member(chave).and_then(|a| a.raw_str()).unwrap_or("?")
                    ));
                }
            } else if !trocam.contains(&legivel.as_str()) {
                desvios.push(format!(
                    "o config do cargo define `build.{legivel}`, fora da lista: da `[build]`, só o \
                     `build.target`"
                ));
            }
        }
    }
    if let Some(alvos) = config.member("target") {
        let mut nomes = Vec::new();
        alvos.para_cada_chave(|alvo| nomes.push(alvo));
        for alvo in nomes {
            let Some(tabela) = alvos.member(alvo) else {
                continue;
            };
            let mut chaves = Vec::new();
            tabela.para_cada_chave(|chave| chaves.push(chave));
            if chaves.is_empty() && tabela.raw_str().is_some_and(|t| !t.starts_with('{')) {
                desvios.push(format!(
                    "o config do cargo define `target.{}` = {}: uma tabela `target` só tem os \
                     `rustflags`",
                    chave_legivel(alvo),
                    tabela.raw_str().unwrap_or("?")
                ));
            }
            for chave in chaves {
                match chave_legivel(chave).as_str() {
                    "rustflags" => {
                        if let Some(fora) =
                            rustflag_fora(tabela.member(chave).and_then(|f| f.raw_str()))
                        {
                            desvios.push(format!(
                                "os rustflags de `target.{}` têm `{fora}`, fora das formas da \
                                 lista (`--cfg`, e `-C` com {FORMAS_DOS_RUSTFLAGS:?} ou o script \
                                 do ligador): um rustflag escolhe o ligador — o `-C linker`, o \
                                 `-fuse-ld` e o `-B` de um `link-arg` — e o que se compila",
                                chave_legivel(alvo)
                            ));
                        }
                    }
                    "runner" => desvios.push(format!(
                        "o config do cargo define `target.{}.runner`: o executor roda no lugar de \
                         cada binário que o cargo roda — o do `cargo xtask` inclusive —, e \
                         decidiria o que o `cargo xtask invariantes` diz",
                        chave_legivel(alvo)
                    )),
                    "linker" => desvios.push(format!(
                        "o config do cargo define `target.{}.linker`: o ligador roda no lugar do \
                         do toolchain, ao ligar cada binário — os `build.rs`, as macros \
                         procedurais, o `xtask` —, fora da lista",
                        chave_legivel(alvo)
                    )),
                    outra => desvios.push(format!(
                        "o config do cargo define `target.{}.{outra}`, fora da lista: de uma \
                         tabela `target`, só os `rustflags`",
                        chave_legivel(alvo)
                    )),
                }
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

/// O primeiro rustflag de `rustflags` — o JSON que o cargo devolve: uma
/// lista de textos, ou um texto só, que o cargo parte nos espaços — fora das
/// formas de [`FORMAS_DOS_RUSTFLAGS`]: o par inteiro, como o cargo o passa;
/// ou o JSON inteiro, se ele não se lê. `None` se todos estão nas formas.
fn rustflag_fora(rustflags: Option<&str>) -> Option<String> {
    let Some(json) = rustflags else {
        return Some(String::from("(nada)"));
    };
    let valor = Json(json.trim().as_bytes());
    let mut destino = [0u8; 1024];
    let mut flags: Vec<String> = Vec::new();
    if let Some(texto) = valor.desescapar_em(&mut destino) {
        flags.extend(texto.split_whitespace().map(str::to_string));
    } else if valor.0.first() == Some(&b'[') {
        while let Some(item) = valor.item(flags.len()) {
            let mut destino = [0u8; 1024];
            match item.desescapar_em(&mut destino) {
                Some(f) => flags.push(f.to_string()),
                None => return Some(json.to_string()),
            }
        }
    } else {
        return Some(json.to_string());
    }
    let mut i = 0;
    while i < flags.len() {
        let par = &flags[i..(i + 2).min(flags.len())];
        let na_lista = match par {
            [cfg, _] if cfg.as_str() == "--cfg" => true,
            [c, valor] if c.as_str() == "-C" => {
                FORMAS_DOS_RUSTFLAGS.contains(&valor.as_str())
                    || valor.starts_with(SCRIPT_DO_LIGADOR)
            }
            _ => false,
        };
        if !na_lista {
            return Some(par.join(" "));
        }
        i += 2;
    }
    None
}

/// Os dois `rust-toolchain.toml` do repositório em `raiz` só com a tabela
/// `[toolchain]`, e nela só as chaves de [`CHAVES_DO_TOOLCHAIN`], como
/// desvios — também no `invariantes`. O texto se lê linha a linha, como o
/// TOML o escreve: uma chave com pontos, entre aspas, numa tabela em linha
/// ou fora da `[toolchain]` não é uma das quatro, e se acusa: a lista é a
/// das que se aceitam, e não a das que se procuram.
///
/// # Por quê, desde o lote A10
///
/// Um `path` no `[toolchain]` faz o rustup rodar o `cargo` e o `rustc` de
/// uma pasta no lugar dos do canal, sem trocar o nome do canal que esta
/// conferência lê: um `kernel/rust-toolchain.toml` com `path`, ou o do
/// modelo do SDK com `path` no lugar do `channel`, fazia a própria ação do
/// compilador rodar um `cargo` do repositório, que plantava um executor no
/// config do `CARGO_HOME` (o F2 do adversário do lote A9). Na CI, a ação o
/// recusa antes de todo `cargo`; aqui, o mesmo no começo de todo comando e
/// no `invariantes`.
fn desvios_dos_toolchains(raiz: &Path) -> Vec<String> {
    let mut desvios = Vec::new();
    for arquivo in [TOOLCHAIN_DA_RAIZ, TOOLCHAIN_DO_MODELO] {
        match std::fs::read_to_string(raiz.join(arquivo)) {
            Ok(texto) => {
                for chave in chaves_fora_do_toolchain(&texto) {
                    desvios.push(format!(
                        "o {arquivo} tem `{chave}`, fora das chaves do oficial \
                         ({CHAVES_DO_TOOLCHAIN:?}, na tabela `[toolchain]`): um `path` faz o \
                         rustup rodar o `cargo` e o `rustc` de uma pasta"
                    ));
                }
            }
            Err(e) => desvios.push(format!("o {arquivo} não se lê: {e}")),
        }
    }
    desvios
}

/// As chaves de `texto` — um `rust-toolchain.toml` — fora de
/// [`CHAVES_DO_TOOLCHAIN`] na tabela `[toolchain]`: as de outra tabela, as de
/// fora de uma tabela, e as que não são as quatro, como estão escritas. Os
/// comentários e o conteúdo das listas de várias linhas não contam.
fn chaves_fora_do_toolchain(texto: &str) -> Vec<String> {
    let mut fora = Vec::new();
    let mut tabela: Option<String> = None;
    let mut nivel = 0usize;
    for linha in texto.lines() {
        // Sem o comentário: o `#` fora de um texto.
        let mut aspa: Option<char> = None;
        let mut fim = linha.len();
        for (i, x) in linha.char_indices() {
            match (aspa, x) {
                (None, '#') => {
                    fim = i;
                    break;
                }
                (None, '"' | '\'') => aspa = Some(x),
                (Some(a), _) if x == a => aspa = None,
                _ => {}
            }
        }
        let linha = linha[..fim].trim();
        if linha.is_empty() {
            continue;
        }
        let abre = linha.matches('[').count();
        let fecha = linha.matches(']').count();
        if nivel > 0 {
            nivel = (nivel + abre).saturating_sub(fecha);
            continue;
        }
        if linha.starts_with('[') {
            tabela = Some(
                linha
                    .trim_matches(|c| c == '[' || c == ']')
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'')
                    .to_string(),
            );
            if tabela.as_deref() != Some("toolchain") {
                fora.push(linha.to_string());
            }
            continue;
        }
        let chave = linha
            .split_once('=')
            .map_or(linha, |(c, _)| c)
            .trim()
            .trim_matches(|c| c == '"' || c == '\'');
        if tabela.as_deref() != Some("toolchain") || !CHAVES_DO_TOOLCHAIN.contains(&chave) {
            fora.push(chave.to_string());
        }
        nivel = abre.saturating_sub(fecha);
    }
    fora
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
    // Desde o lote A10, os dois só com as chaves do oficial: nada de `path`.
    fora.extend(desvios_dos_toolchains(&raiz));

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
        fora.extend(desvios_do_config(&raiz.join(dir), rotulo, dir.is_empty()));
    }
    fora.extend(conferir_os_workflows(&workflows));
    let texto_de = |nome: &str| {
        workflows
            .iter()
            .find(|(n, _)| n == nome)
            .map(|(_, t)| t.as_str())
    };
    let acao = texto_de(ACAO_DO_COMPILADOR);
    match acao {
        Some(acao) => fora.extend(conferir_a_acao(acao)),
        None => fora.push(format!(
            "{ACAO_DO_COMPILADOR}: a ação que confere o compilador não foi achada"
        )),
    }
    if let Some(ci) = texto_de(CI) {
        fora.extend(as_invariantes_na_acao(ci));
    }
    if let (Some(ci), Some(canario), Some(acao)) = (texto_de(CI), texto_de(CANARIO), acao) {
        fora.extend(o_canario_repete_os_lints(ci, canario, acao));
    }

    if fora.is_empty() {
        println!(
            "[xtask] o compilador: o canal {}, com data, nos dois rust-toolchain.toml, só com as \
             chaves do oficial, e no CLAUDE.md; nenhum outro, nenhuma troca no config do cargo nem \
             no xtask — nem um executor, nem um apelido além do oficial, e o config de cada \
             diretório de build na lista —; os workflows oficiais só com as ações permitidas, \
             conferindo o compilador depois de cada checkout, com o canal na chave de todo cache, \
             e a ação do compilador com os passos de fora do cargo — o ambiente, o PATH e os \
             rust-toolchain, o canal fixado, o executor — e o das invariantes, que o job de lints \
             liga antes de todo outro `cargo`; e o canário, o único que sobrepõe, fora dos \
             pushes, sem o cache da CI e com os comandos do job de lints",
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

/// Uma linha de YAML que não é comentário: o recuo, o texto sem as bordas
/// e se ela é do conteúdo de um escalar em bloco (`|`, `>`) — um texto, e
/// não uma chave nem um item do YAML. As vazias ficam, com o recuo zero: um
/// bloco `|` pode tê-las.
struct Linha<'a> {
    recuo: usize,
    texto: &'a str,
    escalar: bool,
}

/// As linhas de código de um YAML, sem os comentários de linha inteira nem
/// o BOM do começo do arquivo, que o YAML pula, com o conteúdo de cada
/// escalar em bloco marcado: as linhas, depois da que o abre, mais recuadas
/// que a chave dele — ou que o `-`, num item que é o bloco —, e as vazias
/// entre elas ([`abre_um_bloco`]).
fn linhas_de_codigo(texto: &str) -> Vec<Linha<'_>> {
    let mut bloco: Option<usize> = None;
    texto
        .strip_prefix('\u{feff}')
        .unwrap_or(texto)
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| {
            let recuo = l.len() - l.trim_start().len();
            let texto = l.trim();
            let escalar = bloco.is_some_and(|coluna| texto.is_empty() || recuo > coluna);
            if !escalar {
                bloco = abre_um_bloco(texto).map(|coluna| recuo + coluna);
            }
            Linha {
                recuo,
                texto,
                escalar,
            }
        })
        .collect()
}

/// Se a linha — o texto dela, sem as bordas — abre um escalar em bloco: o
/// valor dela é `|` ou `>`, com os indicadores de corte e de recuo, e no
/// máximo um comentário depois. Devolve a coluna, a partir do recuo da
/// linha, que o conteúdo passa: a da chave, ou a do último `-`, num item que
/// é o próprio bloco.
///
/// # Por quê, desde o lote A13
///
/// Um passo da ação escrito como o texto de um bloco — numa entrada do
/// `with:` do checkout (`nota: |`), num `run:` que o bash não roda — tinha,
/// para a leitura por linhas, um `-` de item e as chaves dele na coluna
/// certa: [`item_da_linha`] o tomava pelo passo, e
/// [`linhas_que_o_passo_nao_le`] o lia inteiro; e a ordem e a contagem o
/// tomavam pela conferência, que o GitHub não roda — para o YAML, é texto
/// (o M2 do adversário do lote A12).
fn abre_um_bloco(texto: &str) -> Option<usize> {
    let mut corpo = texto;
    let mut traco = None;
    while corpo == "-" || corpo.starts_with("- ") {
        traco = Some(texto.len() - corpo.len());
        corpo = corpo[1..].trim_start();
    }
    let (coluna, valor) = match chave_e_valor(corpo) {
        Some((_, valor)) => (texto.len() - corpo.len(), valor),
        None => (traco?, sem_comentario(corpo)),
    };
    let indicadores = valor.strip_prefix(['|', '>'])?;
    (indicadores.len() <= 2
        && indicadores
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'+' || b == b'-'))
    .then_some(coluna)
}

/// Os caracteres de um workflow, ou de uma ação, que o YAML lê de um jeito e
/// a leitura por linhas daqui ([`linhas_de_codigo`]) de outro, cada um com o
/// número da linha — a contada pelos `\n` — e o nome dele: o CR sozinho,
/// fora do CRLF, o NEL (U+0085), o LS (U+2028) e o PS (U+2029), que o YAML
/// lê como quebras de linha e o `str::lines` não; e o BOM (U+FEFF) fora do
/// começo do arquivo, que a libyaml pula no começo de uma linha e que a
/// leitura daqui não toma por recuo.
///
/// # Por quê, desde o lote A13
///
/// A leitura do passo da ação falha fechada nas linhas que ela vê, e
/// `      - name: O compilador\r        if: false` é uma linha para ela — o
/// `name:` com um valor comprido — e duas para o YAML, com o `if: false` do
/// passo: o PyYAML e a libyaml a leram assim, e o YamlDotNet, que o runner
/// usa para ler a ação, tem as mesmas cinco quebras (`\r`, `\n`, U+0085,
/// U+2028 e U+2029). O `cargo xtask invariantes` passava, e o passo seria
/// pulado, com as conferências que ele faz; numa linha de comentário, que a
/// leitura tira inteira, também (o M1 do adversário do lote A12; o BOM no
/// começo de uma linha do meio é o B1 dele). Sem esses caracteres, o texto
/// tem as mesmas linhas para a leitura daqui, para o YAML 1.1 e para o 1.2.
fn quebras_que_a_leitura_nao_ve(texto: &str) -> Vec<(usize, &'static str)> {
    let mut achados = Vec::new();
    for (n, linha) in texto.split('\n').enumerate() {
        let linha = linha.strip_suffix('\r').unwrap_or(linha);
        for (i, c) in linha.char_indices() {
            let qual = match c {
                '\r' => "um CR sozinho",
                '\u{85}' => "um NEL (U+0085)",
                '\u{2028}' => "um LS (U+2028)",
                '\u{2029}' => "um PS (U+2029)",
                '\u{feff}' if n > 0 || i > 0 => "um BOM (U+FEFF) fora do começo do arquivo",
                _ => continue,
            };
            achados.push((n + 1, qual));
        }
    }
    achados
}

/// A chave e o valor de uma linha `chave: valor` de YAML, com o `- ` de um
/// item de lista e as aspas da chave tirados, e o valor sem o comentário do
/// fim da linha ([`sem_comentario`]).
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
    de_yaml.then_some((chave, sem_comentario(valor.trim())))
}

/// Onde acaba o valor de YAML entre aspas do começo de `valor`: o índice
/// depois da aspa que o fecha — na dupla, a `\` escapa o caractere
/// seguinte; na simples, `''` é uma aspa de dentro —; nenhum, se ele não
/// começa por aspas ou não fecha na linha.
fn fim_das_aspas(valor: &str) -> Option<usize> {
    let b = valor.as_bytes();
    let aspa = b.first().copied().filter(|&c| c == b'"' || c == b'\'')?;
    let mut i = 1;
    while let Some(&c) = b.get(i) {
        match c {
            b'\\' if aspa == b'"' => i += 2,
            b'\'' if aspa == b'\'' && b.get(i + 1) == Some(&b'\'') => i += 2,
            _ if c == aspa => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// O valor de uma linha de YAML sem o comentário do fim dela: o `#` depois
/// de um espaço — ou no começo do valor — e o que vem depois, fora das
/// aspas. Num valor entre aspas, o `#` de dentro é do valor, e o
/// comentário só começa depois da aspa que o fecha; o que não fecha na
/// linha fica inteiro.
///
/// # Por quê, desde o lote A12
///
/// O `invariantes: true  # x`, o `uses: ./.github/actions/compilador  # x`
/// e o `id: compilador  # x` são o YAML que o GitHub lê sem o comentário, e
/// reprovavam o `cargo xtask invariantes` sem defeito nenhum: o comentário
/// entrava no valor que a entrada do `with:`, o nome da ação e a contagem
/// do `id` comparam (o achado 2 do adversário do lote A11). Vale em toda
/// leitura de [`chave_e_valor`] — também na chave de cache, onde um
/// comentário com o canal passava pelo canal que a chave não tem —; a regra
/// das variáveis do cargo na CI (`variaveis_do_cargo_na_ci`, no `main.rs`)
/// lê o texto cru, de propósito, e não muda.
fn sem_comentario(valor: &str) -> &str {
    let desde = if valor.starts_with(['"', '\'']) {
        match fim_das_aspas(valor) {
            Some(fim) => fim,
            None => return valor,
        }
    } else {
        0
    };
    let b = valor.as_bytes();
    (desde..b.len())
        .find(|&i| b[i] == b'#' && (i == 0 || b[i - 1] == b' ' || b[i - 1] == b'\t'))
        .map_or(valor, |i| valor[..i].trim_end())
}

/// A forma do YAML de uma linha de código — `texto`, sem as bordas, fora do
/// conteúdo de um escalar em bloco — que a leitura por linhas não lê, ou
/// nenhuma. Ela lê a chave simples — letras, dígitos, `-` e `_`, sem aspas —
/// com o `:` seguido de um espaço ou do fim; o valor numa linha — sem aspas,
/// entre aspas que fecham nela, um bloco (`|`, `>`), ou uma sequência em
/// estilo de fluxo só de escalares simples (`[x86_64, aarch64]`); e o item
/// de uma lista com um desses. Não lê o item em estilo de fluxo (`- { … }`,
/// `- [ … ]`), a chave complexa (`?`, `:`), a chave entre aspas — com um
/// escape, ela é outra para o YAML (`"u\x73es"`) —, a âncora, o apelido, a
/// etiqueta, a fusão (`<<`), o texto entre aspas em várias linhas, e o valor
/// que começa por outro indicador do YAML — também o estilo de fluxo no
/// valor de uma chave (`chave: { … }`), que a regra de antes recusava nos
/// workflows e nas outras ações, e não na do compilador.
///
/// # Por quê, desde o lote A13
///
/// As regras dos workflows leem as chaves linha a linha
/// ([`chave_e_valor`]), e pulam o que não reconhecem: o checkout escrito em
/// estilo de fluxo, com um escape na chave ou numa chave complexa não pedia
/// a conferência depois dele — a lacuna que o lote A12 deixou relatada —;
/// uma ação de fora de [`ACOES_OFICIAIS`] em estilo de fluxo — uma que
/// instala outro toolchain — passava; e um texto entre aspas em várias
/// linhas esconde dela um `#` que é do valor, ou lhe mostra um passo que o
/// YAML lê como texto. A leitura do passo da ação já falhava fechada (o lote
/// A12); esta é a mesma regra no arquivo inteiro (o M3 do adversário do lote
/// A12).
fn forma_que_a_leitura_nao_le(texto: &str) -> Option<&'static str> {
    let mut corpo = texto;
    let mut traco = false;
    while corpo == "-" || corpo.starts_with("- ") {
        corpo = corpo[1..].trim_start();
        traco = true;
    }
    let b = corpo.as_bytes();
    let separado = |i: usize| b.get(i).is_none_or(|c| *c == b' ' || *c == b'\t');
    let bloco = |v: &str| {
        v.strip_prefix(['|', '>']).is_some_and(|indicadores| {
            indicadores.len() <= 2
                && indicadores
                    .bytes()
                    .all(|c| c.is_ascii_digit() || c == b'+' || c == b'-')
        })
    };
    match b.first() {
        None | Some(b'#') => return None,
        Some(b'|' | b'>') if traco && bloco(sem_comentario(corpo)) => return None,
        Some(b'{' | b'[') => return Some("um nó em estilo de fluxo"),
        Some(b'?' | b':') if separado(1) => return Some("uma chave complexa"),
        Some(b'&' | b'*' | b'!') => return Some("uma âncora, um apelido ou uma etiqueta"),
        Some(b'"' | b'\'') => {
            return match fim_das_aspas(corpo) {
                None => Some("um texto entre aspas que não fecha na linha"),
                Some(fim) if sem_comentario(corpo[fim..].trim()).is_empty() => None,
                Some(_) => Some("uma chave entre aspas"),
            };
        }
        Some(b'%' | b'@' | b'`' | b',' | b']' | b'}' | b'|' | b'>') => {
            return Some("uma linha que começa por um indicador do YAML");
        }
        _ => {}
    }
    // A chave: até o `:` seguido de um espaço, ou no fim, antes de um
    // comentário. Sem ele, é um escalar simples — o valor de um item, ou a
    // continuação de um valor.
    let comentario =
        (0..b.len()).find(|&i| b[i] == b'#' && (i == 0 || b[i - 1] == b' ' || b[i - 1] == b'\t'));
    let dois_pontos = (0..b.len())
        .find(|&i| b[i] == b':' && separado(i + 1))
        .filter(|&i| comentario.is_none_or(|c| i < c))?;
    let chave = corpo[..dois_pontos].trim_end();
    if chave.is_empty()
        || !chave
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Some("uma chave que não é simples — entre aspas, com espaço, a fusão `<<`");
    }
    let valor = sem_comentario(corpo[dois_pontos + 1..].trim());
    let v = valor.as_bytes();
    match v.first() {
        None => None,
        Some(b'|' | b'>') if bloco(valor) => None,
        Some(b'"' | b'\'') => (fim_das_aspas(valor) != Some(valor.len()))
            .then_some("um texto entre aspas que não fecha na linha"),
        Some(b'[') => {
            let simples = valor
                .strip_prefix('[')
                .and_then(|v| v.strip_suffix(']'))
                .is_some_and(|dentro| {
                    dentro.trim().is_empty()
                        || dentro.split(',').all(|item| {
                            let item = item.trim();
                            !item.is_empty()
                                && item.bytes().all(|c| !b"[]{}\"'&*!|>%@`#:?".contains(&c))
                        })
                });
            (!simples)
                .then_some("uma sequência em estilo de fluxo que não é só de escalares simples")
        }
        Some(b'{') => Some("um nó em estilo de fluxo"),
        Some(b'&' | b'*' | b'!') => Some("uma âncora, um apelido ou uma etiqueta"),
        Some(b'%' | b'@' | b'`' | b',' | b']' | b'}' | b'|' | b'>') => {
            Some("um valor que começa por um indicador do YAML")
        }
        Some(b'?' | b'-' | b':') if v.len() == 1 || v[1] == b' ' || v[1] == b'\t' => {
            Some("um valor que começa por um indicador do YAML")
        }
        _ => None,
    }
}

/// O nome da ação de um `uses:` — sem as aspas e sem a versão.
fn nome_da_acao(valor: &str) -> &str {
    let valor = valor.trim_matches(|c| c == '"' || c == '\'');
    valor.split('@').next().unwrap_or(valor)
}

/// A linha usa a ação do compilador: `uses: ./.github/actions/compilador`,
/// também como a primeira chave de um item (`- uses: …`).
fn usa_a_acao_do_compilador(l: &Linha<'_>) -> bool {
    chave_e_valor(l.texto).is_some_and(|(chave, valor)| {
        chave == "uses" && nome_da_acao(valor) == "./.github/actions/compilador"
    })
}

/// Uma chave de um mapa de YAML, numa linha de código: o índice da linha,
/// a coluna da chave, a chave e o valor.
struct Chave<'a> {
    linha: usize,
    coluna: usize,
    chave: &'a str,
    valor: &'a str,
}

/// O item de lista de `linhas` — as de código de um YAML — que tem a linha
/// `i`, um passo: o começo, no `-` mais próximo acima, de recuo menor que o
/// da linha — ou nela mesma —, que não é do conteúdo de um bloco
/// ([`abre_um_bloco`]); o fim, na primeira linha de recuo igual ou
/// menor que o do `-`; e a coluna das chaves dele, a do que vem depois do
/// `-`, na mesma linha, ou a da primeira linha de baixo. Nenhum, se a linha
/// não está num item.
fn item_da_linha(linhas: &[Linha<'_>], i: usize) -> Option<(usize, usize, Option<usize>)> {
    // O `-` do conteúdo de um bloco é texto, e não um item.
    let item = |l: &Linha<'_>| !l.escalar && (l.texto == "-" || l.texto.starts_with("- "));
    let comeco = (0..=i)
        .rev()
        .find(|&j| item(&linhas[j]) && (j == i || linhas[j].recuo < linhas[i].recuo))?;
    let traco = &linhas[comeco];
    let fim = (comeco + 1..linhas.len())
        .find(|&k| !linhas[k].texto.is_empty() && linhas[k].recuo <= traco.recuo)
        .unwrap_or(linhas.len());
    let depois = traco.texto[1..].trim_start();
    let coluna = if depois.is_empty() {
        linhas[comeco + 1..fim]
            .iter()
            .find(|l| !l.texto.is_empty())
            .map(|l| l.recuo)
    } else {
        Some(traco.recuo + traco.texto.len() - depois.len())
    };
    Some((comeco, fim, coluna))
}

/// As chaves do item de lista de `linhas` que tem a linha `i`, um passo
/// ([`item_da_linha`]): a que vem depois do `-`, na mesma linha, e as das
/// linhas na coluna dela; as de dentro do valor de uma chave — um `with:`,
/// um `env:`, um bloco `|` — não. Nenhuma, se a linha não está num item.
fn chaves_do_item<'a>(linhas: &[Linha<'a>], i: usize) -> Vec<Chave<'a>> {
    let Some((comeco, fim, coluna)) = item_da_linha(linhas, i) else {
        return Vec::new();
    };
    let depois = linhas[comeco].texto[1..].trim_start();
    let mut chaves = Vec::new();
    if let Some(coluna) = coluna.filter(|_| !depois.is_empty())
        && let Some((chave, valor)) = chave_e_valor(depois)
    {
        chaves.push(Chave {
            linha: comeco,
            coluna,
            chave,
            valor,
        });
    }
    for (k, l) in linhas.iter().enumerate().take(fim).skip(comeco + 1) {
        if Some(l.recuo) == coluna
            && !l.texto.is_empty()
            && let Some((chave, valor)) = chave_e_valor(l.texto)
        {
            chaves.push(Chave {
                linha: k,
                coluna: l.recuo,
                chave,
                valor,
            });
        }
    }
    chaves
}

/// As chaves de dentro do valor de `chave` — um mapa em bloco, nas linhas
/// abaixo dela, mais recuadas que ela —: as da coluna da primeira, como
/// em [`chaves_do_item`]. Nenhuma, se o valor está na linha da chave.
fn chaves_de_dentro<'a>(linhas: &[Linha<'a>], chave: &Chave<'a>) -> Vec<Chave<'a>> {
    if !chave.valor.is_empty() {
        return Vec::new();
    }
    let dentro: Vec<(usize, &Linha<'a>)> = linhas
        .iter()
        .enumerate()
        .skip(chave.linha + 1)
        .filter(|(_, l)| !l.texto.is_empty())
        .take_while(|(_, l)| l.recuo > chave.coluna)
        .collect();
    let Some(coluna) = dentro.first().map(|(_, l)| l.recuo) else {
        return Vec::new();
    };
    dentro
        .into_iter()
        .filter(|(_, l)| l.recuo == coluna)
        .filter_map(|(k, l)| {
            chave_e_valor(l.texto).map(|(c, valor)| Chave {
                linha: k,
                coluna,
                chave: c,
                valor,
            })
        })
        .collect()
}

/// Uma linha `chave: valor` de YAML na forma simples, a que a leitura do
/// passo da ação aceita ([`linhas_que_o_passo_nao_le`]): a chave sem aspas
/// nem escape — letras, dígitos, `-` e `_` —, o `:` seguido de um espaço ou
/// do fim da linha, e o valor, sem o comentário do fim
/// ([`sem_comentario`]), vazio, entre aspas que fecham na linha, ou sem um
/// indicador de YAML no começo — a âncora (`&`), o apelido (`*`), a
/// etiqueta (`!`), o estilo de fluxo (`{`, `[`), o bloco (`|`, `>`), a
/// chave complexa (`?`) e os outros.
fn chave_simples(texto: &str) -> Option<(&str, &str)> {
    let (chave, resto) = texto.split_once(':')?;
    let chave = chave.trim_end();
    let da_chave = !chave.is_empty()
        && chave
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    let separada = resto.is_empty() || resto.starts_with([' ', '\t']);
    let valor = sem_comentario(resto.trim());
    let do_valor = match valor.as_bytes().first() {
        None => true,
        Some(b'"' | b'\'') => fim_das_aspas(valor) == Some(valor.len()),
        Some(c) => !b"-?:,[]{}#&*!|>%@`".contains(c),
    };
    (da_chave && separada && do_valor).then_some((chave, valor))
}

/// As linhas do passo que usa a ação do compilador — o item de `linhas`
/// que tem a linha `i`, o `uses:` dela ([`item_da_linha`]) — que a leitura
/// não reconhece. Ela falha fechada: reconhece, na forma simples
/// ([`chave_simples`]), as chaves de [`CHAVES_DO_PASSO_DA_ACAO`] — na linha
/// do `-` e na coluna dela, com o `uses:` o da ação — e as entradas do
/// `with:`, na coluna da primeira; e as de [`CHAVES_FORA_DO_PASSO_DA_ACAO`],
/// que a regra delas recusa com a mensagem própria. As vazias e os
/// comentários ficam de fora — os de linha inteira já saíram em
/// [`linhas_de_codigo`], e os do fim saem do valor. O resto é uma linha que
/// a conferência não lê, e que o YAML de verdade pode ler como um `if:` ou
/// um `continue-on-error:` do passo: um escape na chave (`"i\x66": false`),
/// uma chave entre aspas, uma chave complexa (`? if`), uma âncora, um
/// apelido, uma fusão (`<<: *x`), uma chave fora da lista, um valor em
/// várias linhas — e o `uses:` da ação fora da coluna das chaves, como uma
/// entrada do `with:` de outra ação ou uma linha de um bloco `run:`. Se a
/// linha `i` não está num item, ela.
///
/// # Por quê, desde o lote A12
///
/// A leitura ignorava a linha que não reconhecia, e a recusa do `if:` e do
/// `continue-on-error:` do lote A11 só via as chaves que ela reconhecia: o
/// `"i\x66": false` passava pelo `cargo xtask invariantes`, e um parser de
/// YAML conforme o lê como `if: false` (o achado 1 do adversário do lote
/// A11). E uma linha `uses:` da ação do compilador fora da coluna das
/// chaves de um passo — uma entrada do `with:` de outra ação, uma linha de
/// um bloco `run:` — contava como a conferência, que não rodava.
fn linhas_que_o_passo_nao_le<'a>(linhas: &[Linha<'a>], i: usize) -> Vec<&'a str> {
    let Some((comeco, fim, coluna)) = item_da_linha(linhas, i) else {
        return vec![linhas[i].texto];
    };
    // Na coluna das chaves: uma das do passo, na forma simples, com o
    // `uses:` o da ação; ou uma das recusadas, que a regra delas acusa.
    let do_passo = |texto: &'a str| {
        chave_simples(texto)
            .filter(|&(chave, valor)| {
                CHAVES_DO_PASSO_DA_ACAO.contains(&chave)
                    && (chave != "uses" || nome_da_acao(valor) == "./.github/actions/compilador")
            })
            .or_else(|| {
                chave_e_valor(texto)
                    .filter(|(chave, _)| CHAVES_FORA_DO_PASSO_DA_ACAO.contains(chave))
            })
    };
    // As linhas do passo, com a coluna de cada uma — a do `-`, pelo que vem
    // depois dele.
    let depois = linhas[comeco].texto[1..].trim_start();
    let mut passo: Vec<(usize, &'a str, usize)> = Vec::new();
    if let Some(coluna) = coluna.filter(|_| !depois.is_empty()) {
        passo.push((comeco, depois, coluna));
    }
    passo.extend(
        (comeco + 1..fim)
            .filter(|&k| !linhas[k].texto.is_empty())
            .map(|k| (k, linhas[k].texto, linhas[k].recuo)),
    );
    // O `with:` aberto: a coluna da chave dele e a das entradas.
    let mut com: Option<(usize, Option<usize>)> = None;
    let mut fora = Vec::new();
    for (k, texto, recuo) in passo {
        let lida = if Some(recuo) == coluna {
            com = None;
            match do_passo(texto) {
                Some(("with", "")) => {
                    com = Some((recuo, None));
                    true
                }
                outra => outra.is_some(),
            }
        } else {
            // Uma entrada do `with:`, na coluna da primeira — e não o `uses:`
            // da ação, que é uma chave do passo.
            let entrada = match com.as_mut() {
                Some((da_chave, entradas)) if recuo > *da_chave => {
                    *entradas.get_or_insert(recuo) == recuo && chave_simples(texto).is_some()
                }
                _ => false,
            };
            entrada && k != i
        };
        if !lida {
            fora.push(linhas[k].texto);
        }
    }
    fora
}

/// Os workflows: os oficiais só usam as ações de [`ACOES_OFICIAIS`], não
/// sobrepõem o compilador e o conferem — `./.github/actions/compilador`,
/// com `id: compilador` — depois de cada checkout, antes do cache e de
/// qualquer `cargo`, num passo sem as chaves de
/// [`CHAVES_FORA_DO_PASSO_DA_ACAO`] e que a leitura lê inteiro, só com as de
/// [`CHAVES_DO_PASSO_DA_ACAO`], na forma simples
/// ([`linhas_que_o_passo_nao_le`]); e toda chave de cache, a principal e as
/// de restauração, leva o canal. Nenhum `uses:` em várias linhas. O canário
/// sobrepõe, mas não roda nos pushes, não usa o cache nem publica a
/// proveniência. As ações locais seguem as regras dos workflows oficiais,
/// menos a que confere o compilador, que cita o que recusa: nela vale só a
/// leitura que falha fechada, abaixo, e o resto é de [`conferir_a_acao`].
///
/// # A leitura falha fechada no arquivo inteiro, desde o lote A13
///
/// As regras leem o YAML linha a linha. Em todo arquivo — a ação do
/// compilador inclusive —, antes delas, reprova o que essa leitura não lê
/// como o YAML lê: os caracteres que o YAML toma por outra linha
/// ([`quebras_que_a_leitura_nao_ve`]) e, fora do conteúdo dos blocos, as
/// formas que ela não lê ([`forma_que_a_leitura_nao_le`]) — o estilo de
/// fluxo, a chave entre aspas ou com escape, a chave complexa, a âncora, o
/// apelido, a etiqueta, a fusão, o texto entre aspas em várias linhas. Um
/// checkout, ou uma ação de fora da lista, escrito numa delas reprova por
/// ela, e não escapa mais da ordem nem da lista: antes, um checkout em
/// estilo de fluxo ou com um escape na chave não pedia a conferência depois
/// dele (o M3 do adversário do lote A12, e o E1 do revisor da rodada 5).
fn conferir_os_workflows(workflows: &[(String, String)]) -> Vec<String> {
    let mut fora = Vec::new();
    for (nome, texto) in workflows {
        // Antes de toda leitura, e também na ação do compilador: o que o YAML
        // lê como outra linha, e a leitura por linhas não vê.
        for (n, qual) in quebras_que_a_leitura_nao_ve(texto) {
            fora.push(format!(
                "{nome}:{n}: {qual} — o YAML lê ali uma quebra de linha, ou um caractere, que a \
                 leitura por linhas do `xtask` não vê: uma chave do passo, como um `if:`, ou um \
                 checkout, que ela não lê"
            ));
        }
        let linhas = linhas_de_codigo(texto);
        // A forma do YAML que a leitura não lê, fora do conteúdo dos blocos;
        // também na ação do compilador.
        for l in linhas.iter().filter(|l| !l.escalar) {
            if let Some(forma) = forma_que_a_leitura_nao_le(l.texto) {
                fora.push(format!(
                    "{nome}: `{}` — {forma}, que a leitura por linhas do `xtask` não lê: o YAML \
                     pode ler ali um passo, um checkout ou uma chave que as regras dos workflows \
                     não veem",
                    l.texto
                ));
            }
        }
        if nome == ACAO_DO_COMPILADOR {
            continue;
        }
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
        // O passo da conferência roda sempre, e o job para com ela
        // reprovada; e a leitura dele falha fechada: a linha que ela não lê
        // pode ser, para o YAML, uma das chaves recusadas.
        for (i, _) in linhas
            .iter()
            .enumerate()
            .filter(|(_, l)| usa_a_acao_do_compilador(l))
        {
            for c in chaves_do_item(&linhas, i) {
                if CHAVES_FORA_DO_PASSO_DA_ACAO.contains(&c.chave) {
                    fora.push(format!(
                        "{nome}: `{}: {}` no passo da conferência do compilador — com um `if:`, \
                         ela pode não rodar, e o job segue sem ela; com um `continue-on-error:`, \
                         o job segue com ela reprovada",
                        c.chave, c.valor
                    ));
                }
            }
            for linha in linhas_que_o_passo_nao_le(&linhas, i) {
                fora.push(format!(
                    "{nome}: `{linha}` no passo da conferência do compilador, que a conferência \
                     não lê — ela lê nele só o `name:`, o `id:`, o `uses:` da ação e o `with:` com \
                     as entradas, na forma simples: a chave sem aspas nem escape, o valor numa \
                     linha, sem âncora, apelido, etiqueta nem estilo de fluxo. O que ela não lê, o \
                     YAML pode ler como um `if:` ou um `continue-on-error:` — um escape, uma chave \
                     complexa, uma fusão"
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

/// A ação do compilador — `texto`, o [`ACAO_DO_COMPILADOR`] — tem os passos
/// de [`PASSOS_DA_ACAO`], na ordem, cada um com o `shell:` dele, só com as
/// chaves que a leitura lê nele ([`linhas_que_o_passo_da_acao_nao_le`],
/// desde o lote A13) e com cada marca dele numa linha de código do script;
/// nos dois em Python, a tupla
/// `DIRETORIOS` com cada diretório de build do `xtask` como um item
/// ([`DIRETORIOS_DOS_BUILDS`]); no do executor, as formas dos rustflags de
/// [`FORMAS_DOS_RUSTFLAGS`] e as tabelas de [`TABELAS_DO_CONFIG`]; a entrada
/// `invariantes`, e o passo das invariantes só com ela, no toolchain fixado
/// pelo canal; e a ação não escreve no ambiente dos passos seguintes — o
/// `GITHUB_ENV`, o `GITHUB_PATH` —, que nenhuma regra dos workflows lê nela.
///
/// # Por quê, desde o lote A9
///
/// O executor do config do cargo decide o que o `cargo xtask` roda — e o
/// `cargo test -p xtask` —, e o que nunca chama o `xtask` de verdade nunca
/// roda conferência nenhuma de dentro dele (o A8 do adversário do lote A8):
/// a conferência dele mora fora do cargo, na ação, antes de todo `cargo` da
/// CI que compila ou roda. Aqui, que ela continua lá — como
/// [`conferir_os_workflows`] confere que os workflows chamam a ação. O
/// teste `a_acao_roda_como_no_runner` roda o script.
///
/// # E o resto de fora do cargo, desde o lote A10
///
/// O ambiente do job, o PATH e o toolchain de um diretório escolhiam o
/// programa que a própria ação rodava (o F1 e o F2 do adversário do lote
/// A9): o passo do ambiente os confere antes de qualquer programa do
/// toolchain, com o `python3` do sistema, e todo `cargo` da ação roda no
/// toolchain fixado pelo canal. E o passo das invariantes, no job de lints,
/// antes de todo outro `cargo` do job ([`as_invariantes_na_acao`]). Cada
/// diretório como um item da tupla, e não como um texto entre aspas em
/// qualquer linha: o `""` da raiz aparecia noutra linha do script, e tirar
/// a raiz da tupla não se acusava (o E5 do revisor do lote A9).
fn conferir_a_acao(texto: &str) -> Vec<String> {
    let mut fora = Vec::new();
    let linhas = linhas_de_codigo(texto);
    let posicao = |id: &str| {
        linhas
            .iter()
            .position(|l| chave_e_valor(l.texto) == Some(("id", id)))
    };
    let mut anterior: Option<(&str, usize)> = None;
    for (id, shell_esperado, marcas) in PASSOS_DA_ACAO {
        let Some(aqui) = posicao(id) else {
            fora.push(format!(
                "{ACAO_DO_COMPILADOR}: sem o passo `id: {id}`, que confere, fora do cargo, o que \
                 escolhe o programa que o cargo roda"
            ));
            continue;
        };
        if let Some((antes, onde)) = anterior
            && onde > aqui
        {
            fora.push(format!(
                "{ACAO_DO_COMPILADOR}: o passo `id: {id}` vem antes do `id: {antes}`: a ordem é \
                 {:?}",
                PASSOS_DA_ACAO.map(|(id, _, _)| id)
            ));
        }
        anterior = Some((id, aqui));
        for linha in linhas_que_o_passo_da_acao_nao_le(&linhas, aqui, id) {
            fora.push(format!(
                "{ACAO_DO_COMPILADOR}: `{linha}` no passo `{id}`, que a conferência não lê — ela lê \
                 nele só o `name:`, o `id:`, o `shell:` e o `run:`, e, no das invariantes, o `if:` \
                 da entrada e o `env:` com o toolchain fixado: um `if:`, um `continue-on-error:` ou \
                 um `env:` a mais mudam se ele roda, se o job para com ele, e o que ele roda"
            ));
        }
        let Some((shell, script)) = passo_da_acao(texto, id) else {
            fora.push(format!(
                "{ACAO_DO_COMPILADOR}: o passo `{id}` sem `shell:` e `run:` que se leiam"
            ));
            continue;
        };
        if shell != shell_esperado {
            fora.push(format!(
                "{ACAO_DO_COMPILADOR}: o passo `{id}` roda em `{shell}`, e não em \
                 `{shell_esperado}` — o `python3` do sistema, e não o do PATH, que o passo do \
                 ambiente confere"
            ));
        }
        let codigo: Vec<&str> = script
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect();
        for marca in marcas.iter().copied() {
            if !codigo.iter().any(|l| l.contains(marca)) {
                fora.push(format!(
                    "{ACAO_DO_COMPILADOR}: o passo `{id}` não confere `{marca}`"
                ));
            }
        }
        if shell_esperado.contains("python3") {
            // Todo diretório de build do `xtask`, como um item da tupla: um
            // novo entra nos dois.
            let itens = itens_da_tupla(&script, "DIRETORIOS");
            for dir in DIRETORIOS_DOS_BUILDS {
                if !itens.iter().any(|i| i == dir) {
                    fora.push(format!(
                        "{ACAO_DO_COMPILADOR}: o passo `{id}` não confere `{}`, um diretório de \
                         build do `xtask`: a tupla `DIRETORIOS` não o tem",
                        if dir.is_empty() {
                            String::from("./")
                        } else {
                            format!("{dir}/")
                        }
                    ));
                }
            }
        }
        if id == PASSO_DO_EXECUTOR {
            // A mesma lista fechada do config que o `xtask` aplica.
            let formas = itens_da_tupla(&script, "FORMAS");
            let tabelas = itens_da_tupla(&script, "TABELAS");
            if formas != FORMAS_DOS_RUSTFLAGS
                || tabelas != TABELAS_DO_CONFIG
                || !codigo
                    .iter()
                    .any(|l| l.trim() == format!("SCRIPT_DO_LIGADOR = \"{SCRIPT_DO_LIGADOR}\""))
            {
                fora.push(format!(
                    "{ACAO_DO_COMPILADOR}: o passo `{id}` não fecha o config à lista do `xtask` — \
                     as formas dos rustflags {formas:?} e as tabelas {tabelas:?}, e não \
                     {FORMAS_DOS_RUSTFLAGS:?} e {TABELAS_DO_CONFIG:?}, com o script do ligador"
                ));
            }
        }
    }
    // A entrada das invariantes, e o passo só com ela, no toolchain fixado.
    let entrada = linhas.windows(2).any(|par| {
        chave_e_valor(par[0].texto) == Some(("inputs", ""))
            && chave_e_valor(par[1].texto) == Some(("invariantes", ""))
    });
    let do_passo = passo_cru(texto, "invariantes");
    let so_com_a_entrada = do_passo
        .iter()
        .any(|l| l.trim() == "if: inputs.invariantes == 'true'");
    let no_canal_fixado = do_passo
        .iter()
        .any(|l| l.trim() == "RUSTUP_TOOLCHAIN: ${{ steps.conferir.outputs.canal }}");
    if !entrada || !so_com_a_entrada || !no_canal_fixado {
        fora.push(format!(
            "{ACAO_DO_COMPILADOR}: a entrada `invariantes`, logo no começo das `inputs:`, e o passo \
             `invariantes` só com ela (`if: inputs.invariantes == 'true'`) e no toolchain fixado \
             (`RUSTUP_TOOLCHAIN: ${{{{ steps.conferir.outputs.canal }}}}`): o job de lints roda as \
             invariantes ali, antes de todo outro `cargo`"
        ));
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

/// As linhas do passo `id` da ação do compilador — o item de `linhas`, as
/// de código dela, que tem a linha `i`, a do `id:` — que a leitura não
/// reconhece ([`CHAVES_DOS_PASSOS_DA_ACAO`]). Ela falha fechada, como a do
/// passo que usa a ação nos workflows ([`linhas_que_o_passo_nao_le`]).
///
/// # Por quê, desde o lote A13
///
/// [`conferir_a_acao`] conferia que cada passo existe, na ordem, com o
/// `shell:` e as marcas do script, mas nenhuma regra lia as outras chaves
/// dele: um `if: false` no passo do ambiente o pulava, um
/// `continue-on-error: true` no das invariantes deixava o job de lints verde
/// com elas reprovadas, e um `RUSTC_WRAPPER` no `env:` delas escolhia o
/// programa que compila o `xtask` — e o `cargo xtask invariantes` passava. A
/// regra do lote A11 (sem `if:` nem `continue-on-error:`) valia para o passo
/// do workflow que usa a ação, e não para os passos de dentro dela (o M4 do
/// adversário do lote A12). A ação continua a raiz da confiança: um passo
/// novo, ou o script de um deles, muda o que ela faz, com a revisão.
fn linhas_que_o_passo_da_acao_nao_le<'a>(linhas: &[Linha<'a>], i: usize, id: &str) -> Vec<&'a str> {
    let Some((comeco, fim, coluna)) = item_da_linha(linhas, i) else {
        return vec![linhas[i].texto];
    };
    let das_invariantes = id == "invariantes";
    let depois = linhas[comeco].texto[1..].trim_start();
    let mut passo: Vec<(usize, &'a str, usize)> = Vec::new();
    if let Some(coluna) = coluna.filter(|_| !depois.is_empty()) {
        passo.push((comeco, depois, coluna));
    }
    passo.extend(
        (comeco + 1..fim)
            .filter(|&k| !linhas[k].texto.is_empty())
            .map(|k| (k, linhas[k].texto, linhas[k].recuo)),
    );
    // A chave aberta — o `run:` com o script, o `env:` com as entradas — e
    // a coluna dela; e a das entradas do `env:`.
    let mut aberta: Option<(&str, usize)> = None;
    let mut entradas: Option<usize> = None;
    let mut fora = Vec::new();
    for (k, texto, recuo) in passo {
        let lida = if Some(recuo) == coluna {
            aberta = None;
            entradas = None;
            match chave_e_valor(texto) {
                Some(("run", "|" | "|-")) => {
                    aberta = Some(("run", recuo));
                    true
                }
                Some(("env", "")) if das_invariantes => {
                    aberta = Some(("env", recuo));
                    true
                }
                Some(("if", "inputs.invariantes == 'true'")) if das_invariantes => true,
                _ => chave_simples(texto)
                    .is_some_and(|(chave, _)| CHAVES_DOS_PASSOS_DA_ACAO.contains(&chave)),
            }
        } else {
            match aberta {
                Some(("run", da_chave)) => recuo > da_chave,
                Some(("env", da_chave)) if recuo > da_chave => {
                    *entradas.get_or_insert(recuo) == recuo
                        && chave_e_valor(texto)
                            == Some(("RUSTUP_TOOLCHAIN", "${{ steps.conferir.outputs.canal }}"))
                }
                _ => false,
            }
        };
        if !lida {
            fora.push(linhas[k].texto);
        }
    }
    fora
}

/// Os itens da tupla `nome = (…)` de um script em Python — os textos entre
/// aspas, do `(` ao `)` que a fecha, numa linha ou em várias —, na ordem;
/// nenhum, sem a tupla.
fn itens_da_tupla(script: &str, nome: &str) -> Vec<String> {
    let cabeca = format!("{nome} = (");
    let Some(comeco) = script
        .lines()
        .scan(0usize, |onde, l| {
            let aqui = *onde;
            *onde += l.len() + 1;
            Some((aqui, l))
        })
        .find(|(_, l)| l.trim_start().starts_with(&cabeca))
        .map(|(onde, l)| onde + l.len() - l.trim_start().len() + cabeca.len())
    else {
        return Vec::new();
    };
    let dentro = &script[comeco..];
    let dentro = &dentro[..dentro.find(')').unwrap_or(dentro.len())];
    dentro
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

/// O job de lints da CI oficial — `ci`, o [`CI`] — liga as invariantes na
/// ação do compilador: o primeiro passo do job [`JOB_DE_LINTS`] que a usa
/// tem `invariantes: true` no `with:` — uma chave do mapa do `with:` do
/// passo, e não uma linha qualquer dele. As invariantes rodam ali, logo
/// depois das conferências de fora do cargo, antes do cache e de todo outro
/// `cargo` do job.
///
/// # O `with:`, desde o lote A11
///
/// Valia qualquer linha `invariantes: true` do passo, depois do `uses:`: um
/// `env:` com ela passava, a entrada da ação ficava no padrão, `'false'`, e
/// as invariantes não rodavam, sem nada acusar (o E6 do revisor do lote
/// A10). As chaves do passo e as do `with:` se leem pelo recuo
/// ([`chaves_do_item`], [`chaves_de_dentro`]), em qualquer ordem.
///
/// # Por quê, desde o lote A10
///
/// No job de lints, os testes do hospedeiro — com os doctests — e o clippy
/// rodam código do repositório — os `build.rs` e as macros procedurais dos
/// grafos, os testes —, e rodavam antes das invariantes, depois da
/// formatação, que só lê o código. Esse código podia mudar a árvore que as
/// invariantes leem, ou plantar um executor no config do `CARGO_HOME`,
/// depois da ação e antes delas (o IN3 do adversário do lote A9). Na ação,
/// nada do repositório roda entre a conferência e elas, nem o cache.
fn as_invariantes_na_acao(ci: &str) -> Vec<String> {
    let linhas = linhas_de_codigo(ci);
    let cabecalho = format!("{JOB_DE_LINTS}:");
    // O job: da linha dele, no recuo dos jobs, à próxima de recuo igual ou
    // menor.
    let ligada = linhas
        .iter()
        .position(|l| l.recuo == 2 && l.texto == cabecalho)
        .is_some_and(|comeco| {
            let fim = (comeco + 1..linhas.len())
                .find(|&k| !linhas[k].texto.is_empty() && linhas[k].recuo <= 2)
                .unwrap_or(linhas.len());
            let job = &linhas[comeco..fim];
            job.iter()
                .position(|l| usa_a_acao_do_compilador(l))
                .is_some_and(|uso| {
                    chaves_do_item(job, uso)
                        .iter()
                        .filter(|c| c.chave == "with")
                        .flat_map(|c| chaves_de_dentro(job, c))
                        .any(|c| {
                            c.chave == "invariantes"
                                && ["true", "'true'", "\"true\""].contains(&c.valor)
                        })
                })
        });
    if ligada {
        Vec::new()
    } else {
        vec![format!(
            "{CI}: o job `{JOB_DE_LINTS}` não liga as invariantes na ação do compilador \
             (`invariantes: true` no `with:` do primeiro passo do job que a usa — num `env:`, ou \
             noutro passo, não vale): elas rodam ali, antes do cache e de todo outro `cargo` do \
             job — os testes do hospedeiro e o clippy rodam código do repositório"
        )]
    }
}

/// As linhas do passo `id` de uma ação composta — `acao`, o texto do
/// `action.yml` —: do item de lista que o contém — a linha com o `- ` no
/// recuo dos passos — ao item seguinte, ou ao que tiver recuo menor. Nenhuma,
/// sem o passo.
fn passo_cru<'a>(acao: &'a str, id: &str) -> Vec<&'a str> {
    let linhas: Vec<&str> = acao.lines().collect();
    let recuo = |l: &str| l.len() - l.trim_start().len();
    let Some(do_id) = linhas.iter().position(|l| {
        let t = l.trim();
        chave_e_valor(t) == Some(("id", id))
    }) else {
        return Vec::new();
    };
    // O item do passo: o `- ` no id, ou na linha de cima mais próxima com
    // recuo menor.
    let Some(comeco) = (0..=do_id)
        .rev()
        .find(|&i| linhas[i].trim_start().starts_with("- "))
    else {
        return Vec::new();
    };
    let recuo_do_item = recuo(linhas[comeco]);
    let fim = (comeco + 1..linhas.len())
        .find(|&i| {
            let l = linhas[i];
            !l.trim().is_empty()
                && (recuo(l) < recuo_do_item
                    || (recuo(l) == recuo_do_item && l.trim_start().starts_with("- ")))
        })
        .unwrap_or(linhas.len());
    linhas[comeco..fim].to_vec()
}

/// O passo `id` de uma ação composta — `acao`, o texto do `action.yml` —: o
/// `shell:` e o script do `run: |`, sem o recuo dele. O passo é o de
/// [`passo_cru`]; o script, das linhas mais recuadas que o `run:`, as vazias
/// inclusive.
fn passo_da_acao(acao: &str, id: &str) -> Option<(String, String)> {
    let recuo = |l: &str| l.len() - l.trim_start().len();
    let passo = passo_cru(acao, id);
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
/// [`comandos_do_job`], no diretório deles, e os laços das arquiteturas; e,
/// desde o lote A10, os do passo das invariantes da ação do compilador
/// (`acao`), que o job de lints liga ([`as_invariantes_na_acao`]) — o
/// canário não roda a ação, e roda o comando num passo dele. O canário pode
/// ter mais, e roda os testes com `--no-fail-fast`. Não contam os passos em
/// Python do canário — o relatório cita comandos no texto —, nem a linha
/// que neutraliza o comando (`|| true`).
fn o_canario_repete_os_lints(ci: &str, canario: &str, acao: &str) -> Vec<String> {
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
    let mut comandos = comandos_do_job(ci, JOB_DE_LINTS);
    if !comandos.is_empty() && as_invariantes_na_acao(ci).is_empty() {
        let (_, script) = passo_da_acao(acao, "invariantes").unwrap_or_default();
        comandos.extend(
            script
                .lines()
                .map(str::trim)
                .filter(|l| l.contains("cargo "))
                .map(str::to_string),
        );
    }
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
        // nome (o item 1 do revisor do lote A8). E, desde o lote A10, as do
        // rustdoc, que compila e roda os doctests (o IN6 do adversário do
        // lote A9).
        for nome in [
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "RUSTDOC",
            "CARGO_BUILD_RUSTDOC",
        ] {
            assert!(VARIAVEIS_QUE_TROCAM.contains(&nome), "{nome}");
        }
        let dir = com_config("rustdoc", "[build]\nrustdoc = \"ferramentas/rustdoc\"\n");
        let desvios = desvios_do_config(&dir, "rustdoc", false);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            desvios.len() == 1 && desvios[0].contains("`build.rustdoc`: troca o compilador"),
            "{desvios:?}"
        );
    }

    /// O executor e os apelidos do cargo (o A8 e o I3 do adversário do lote
    /// A8, no lote A9): no ambiente, o `CARGO_TARGET_<alvo>_RUNNER` de
    /// qualquer alvo e qualquer `CARGO_ALIAS_<nome>` são desvios — os vazios,
    /// o `CARGO_TARGET_DIR` e o `CARGO_TERM_COLOR`, não —; no config, lido
    /// pelo cargo, o `runner` de um `cfg(…)` e o do hospedeiro, também numa
    /// lista, e o `[alias]` que não é só o oficial — um a mais, o do `xtask`
    /// trocado ou escrito como lista, nenhum. E, desde o lote A10, o ligador
    /// também: o config fechado à lista não tem chave nenhuma de uma tabela
    /// `target` além dos `rustflags`.
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
                "ligador",
                format!("{oficial}[target.x86_64-unknown-linux-gnu]\nlinker = \"cc\"\n"),
                "`target.x86_64-unknown-linux-gnu.linker`: o ligador",
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
                String::from("[build]\ntarget = \"x86_64-unknown-none\"\n"),
                "o `[alias]` do config do cargo é (nenhum)",
            ),
        ] {
            let dir = com_config_cru(nome, &texto);
            let desvios = desvios_do_config(&dir, nome, false);
            let _ = std::fs::remove_dir_all(&dir);
            assert!(
                desvios.len() == 1
                    && desvios[0].starts_with(&format!("em `{nome}`, "))
                    && desvios[0].contains(esperado),
                "{nome}: {desvios:?}"
            );
        }
        // O oficial, também com a chave entre aspas, passa.
        for (nome, texto) in [
            ("oficial", oficial.clone()),
            (
                "oficial-com-aspas",
                format!("[alias]\n\"{apelido}\" = \"{valor}\"\n"),
            ),
        ] {
            let dir = com_config_cru(nome, &texto);
            let desvios = desvios_do_config(&dir, nome, false);
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(desvios, Vec::<String>::new(), "{nome}");
        }
    }

    /// O config de um diretório de build fechado à lista (no lote A10, o F3
    /// e o J do adversário do lote A9): o que os configs do repositório
    /// usam passa — o do kernel e o dos programas, com o apelido da raiz —, e
    /// cada tabela, chave e rustflag de fora se acusa, com a mensagem dela —
    /// o `[env]`, o `[host]`, o `[unstable]`, o `[profile]`, o `paths`, o
    /// `[source]`, o `[patch]`, o `target-applies-to-host`, uma chave da
    /// `[build]` além do alvo, um alvo de um arquivo, e os rustflags que
    /// escolhem o ligador por qualquer opção.
    #[test]
    fn o_config_de_um_diretorio_de_build_fechado_a_lista() {
        let projeto = super::super::raiz_do_projeto();
        let ler = |relativo: &str| std::fs::read_to_string(projeto.join(relativo)).expect(relativo);
        let programas = ler("programas/.cargo/config.toml");
        for (nome, texto) in [
            ("kernel", ler("kernel/.cargo/config.toml")),
            ("programas", programas.clone()),
            ("modelo", ler("sdk/modelo/.cargo/config.toml")),
        ] {
            let dir = com_config(&format!("lista-{nome}"), &texto);
            let desvios = desvios_do_config(&dir, nome, false);
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(desvios, Vec::<String>::new(), "{nome}");
        }
        let flags = |par: &str| {
            programas.replacen(
                "rustflags = [\n",
                &format!("rustflags = [\n    {par},\n"),
                1,
            )
        };
        let casos: Vec<(&str, String, &str)> = vec![
            (
                "env-path",
                format!(
                    "{programas}\n[env]\nPATH = {{ value = \"../ferramentas:/usr/bin:/bin\", \
                     relative = true, force = true }}\n"
                ),
                "o config do cargo tem `env`, fora da lista",
            ),
            (
                "host",
                format!(
                    "{programas}\n[unstable]\nhost-config = true\n\n[host]\nlinker = \"ligar\"\n"
                ),
                "o config do cargo tem `host`, fora da lista",
            ),
            (
                "unstable",
                format!("{programas}\n[unstable]\nbuild-std = [\"core\"]\n"),
                "o config do cargo tem `unstable`, fora da lista",
            ),
            (
                "profile",
                format!("{programas}\n[profile.release]\noverflow-checks = false\n"),
                "o config do cargo tem `profile`, fora da lista",
            ),
            (
                "paths",
                format!("paths = [\"../vendor/bit_field\"]\n{programas}"),
                "o config do cargo tem `paths`, fora da lista",
            ),
            (
                "source",
                format!("{programas}\n[source.crates-io]\nreplace-with = \"v\"\n\n[source.v]\ndirectory = \"v\"\n"),
                "o config do cargo tem `source`, fora da lista",
            ),
            (
                "patch",
                format!("{programas}\n[patch.crates-io]\nspin = {{ path = \"spin\" }}\n"),
                "o config do cargo tem `patch`, fora da lista",
            ),
            (
                "aplica-ao-hospedeiro",
                format!("target-applies-to-host = false\n{programas}"),
                "o config do cargo tem `target-applies-to-host`, fora da lista",
            ),
            (
                "build-jobs",
                programas.replacen("[build]\n", "[build]\njobs = 2\n", 1),
                "`build.jobs`, fora da lista",
            ),
            (
                "alvo-de-arquivo",
                programas.replacen(
                    "target = \"x86_64-unknown-none\"",
                    "target = \"ferramentas/alvo.json\"",
                    1,
                ),
                "`build.target` = \"ferramentas/alvo.json\"",
            ),
            (
                "outra-chave-do-alvo",
                format!("{programas}\n[target.x86_64-unknown-uefi]\nrustdocflags = [\"-Zx\"]\n"),
                "`target.x86_64-unknown-uefi.rustdocflags`, fora da lista",
            ),
            (
                "c-linker",
                flags("\"-C\", \"linker=ferramentas/ligar\""),
                "`-C linker=ferramentas/ligar`",
            ),
            (
                "c-linker-junto",
                flags("\"-Clinker=ferramentas/ligar\""),
                "`-Clinker=ferramentas/ligar",
            ),
            (
                "fuse-ld",
                flags("\"-C\", \"link-arg=-fuse-ld=/tmp/ld\""),
                "`-C link-arg=-fuse-ld=/tmp/ld`",
            ),
            (
                "b-do-cc",
                flags("\"-C\", \"link-arg=-B/tmp\""),
                "`-C link-arg=-B/tmp`",
            ),
            (
                "linker-flavor",
                flags("\"-C\", \"linker-flavor=ld.lld\""),
                "`-C linker-flavor=ld.lld`",
            ),
            (
                "z",
                flags("\"-Z\", \"unstable-options\""),
                "`-Z unstable-options`",
            ),
            (
                "extern",
                flags("\"--extern\", \"core=libcore.rlib\""),
                "`--extern core=libcore.rlib`",
            ),
            (
                "em-texto",
                programas.replacen(
                    "rustflags = [\n    \"-C\", \"link-arg=-Tusuario.ld\",",
                    "rustflags = \"-C linker=ferramentas/ligar\"\nx = [\n    \"-C\", \"link-arg=-Tusuario.ld\",",
                    1,
                ),
                "`-C linker=ferramentas/ligar`",
            ),
        ];
        let mut cegos = Vec::new();
        for (nome, texto, esperado) in &casos {
            assert_ne!(texto, &programas, "{nome}");
            let dir = com_config(&format!("lista-{nome}"), texto);
            let desvios = desvios_do_config(&dir, nome, false);
            let _ = std::fs::remove_dir_all(&dir);
            if !desvios.iter().any(|d| d.contains(esperado)) {
                cegos.push(format!("{nome}: {desvios:?}"));
            }
        }
        assert!(cegos.is_empty(), "{cegos:#?}");
    }

    /// Os dois `rust-toolchain.toml` do repositório só com a tabela
    /// `[toolchain]` e as chaves do oficial (no lote A10, o F2 do adversário
    /// do lote A9): os de verdade passam; o `path`, em toda forma do TOML, e
    /// outra tabela ou outra chave se acusam.
    #[test]
    fn os_rust_toolchain_so_com_as_chaves_do_oficial() {
        let raiz = include_str!("../../rust-toolchain.toml");
        let modelo = include_str!("../../sdk/modelo/rust-toolchain.toml");
        assert_eq!(chaves_fora_do_toolchain(raiz), Vec::<String>::new());
        assert_eq!(chaves_fora_do_toolchain(modelo), Vec::<String>::new());
        assert_eq!(
            desvios_dos_toolchains(&super::super::raiz_do_projeto()),
            Vec::<String>::new()
        );
        for (forma, texto) in [
            ("path", "[toolchain]\npath = \"/x/tc\"\n".to_string()),
            (
                "path com o canal",
                format!("{modelo}path = \"/x/tc\" # depois\n"),
            ),
            (
                "path entre aspas",
                "[toolchain]\n\"path\" = \"/x/tc\"\n".to_string(),
            ),
            (
                "chave com pontos",
                "toolchain.path = \"/x/tc\"\n".to_string(),
            ),
            (
                "tabela em linha",
                "toolchain = { path = \"/x/tc\" }\n".to_string(),
            ),
            (
                "outra tabela",
                format!("{modelo}\n[outra]\nchannel = \"x\"\n"),
            ),
            ("outra chave", modelo.replacen("profile", "perfil", 1)),
            (
                "path escapado",
                "[toolchain]\n\"p\\u0061th\" = \"/x/tc\"\n".to_string(),
            ),
        ] {
            assert!(
                !chaves_fora_do_toolchain(&texto).is_empty(),
                "{forma}: {texto}"
            );
        }
        // O conteúdo de uma lista de várias linhas não é uma chave.
        assert_eq!(
            chaves_fora_do_toolchain(
                "[toolchain]\nchannel = \"c\"\ntargets = [\n    \"a\",\n    # x = 1\n    \"b\",\n]\nprofile = \"minimal\"\n"
            ),
            Vec::<String>::new()
        );
        // A conferência lê os dois arquivos da árvore: o do modelo do SDK
        // com `path`, e o canal igual, se acusa pelo nome dele.
        let arvore = std::env::temp_dir().join(format!("xtask-toolchains-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&arvore);
        std::fs::create_dir_all(arvore.join("sdk/modelo")).expect("a árvore");
        std::fs::write(arvore.join(TOOLCHAIN_DA_RAIZ), raiz).expect("o da raiz");
        std::fs::write(
            arvore.join(TOOLCHAIN_DO_MODELO),
            format!("{modelo}path = \"/x/tc\"\n"),
        )
        .expect("o do modelo");
        let desvios = desvios_dos_toolchains(&arvore);
        let _ = std::fs::remove_dir_all(&arvore);
        assert!(
            desvios.len() == 1
                && desvios[0].starts_with(&format!("o {TOOLCHAIN_DO_MODELO} tem `path`")),
            "{desvios:?}"
        );
    }

    /// Os alvos do projeto são os do `rust-toolchain.toml` da raiz — a
    /// lista com que a `[build]` de um diretório de build se confere.
    #[test]
    fn os_alvos_do_projeto_sao_os_do_toolchain() {
        let texto = include_str!("../../rust-toolchain.toml");
        let lista = &texto[texto.find("targets = [").expect("os alvos")..];
        let lista = &lista[..lista.find(']').expect("o fim da lista")];
        let alvos: Vec<&str> = lista
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .filter_map(|l| l.strip_suffix(',').unwrap_or(l).strip_prefix('"'))
            .filter_map(|l| l.strip_suffix('"'))
            .collect();
        assert_eq!(alvos, ALVOS_DO_PROJETO);
    }

    /// A ação do compilador tem os passos de fora do cargo (no lote A9, o do
    /// executor; no lote A10, o do ambiente, o canal fixado e o das
    /// invariantes): na ordem, cada um no shell dele, com as marcas dele, a
    /// tupla dos diretórios de build em cada passo em Python — a raiz
    /// também, como um item (o E5 do revisor do lote A9) —, a lista fechada
    /// do config igual à do `xtask`, a entrada e o passo das invariantes, e
    /// sem escrever no ambiente dos passos seguintes. A de verdade passa; sem
    /// um passo, fora da ordem, noutro shell, sem uma marca, sem um
    /// diretório, com outra lista, sem a entrada ou escrevendo no
    /// `GITHUB_ENV`, reprova.
    #[test]
    fn a_acao_tem_os_passos_de_fora_do_cargo() {
        let acao = include_str!("../../.github/actions/compilador/action.yml");
        assert_eq!(conferir_a_acao(acao), Vec::<String>::new());
        let (shell, script) = passo_da_acao(acao, PASSO_DO_EXECUTOR).expect("o passo");
        assert_eq!(shell, "/usr/bin/python3 -I {0}");
        assert!(script.starts_with("import json\n"), "{script}");
        for (id, _, _) in PASSOS_DA_ACAO {
            assert_eq!(
                acao.matches(&format!("    - id: {id}\n")).count(),
                1,
                "{id}"
            );
        }
        assert_eq!(itens_da_tupla(&script, "DIRETORIOS"), DIRETORIOS_DOS_BUILDS);
        let cabeca = "    - id: executor\n";
        let (antes, depois) = acao.split_at(acao.find(cabeca).unwrap());
        let do_ambiente = "    - id: ambiente\n";
        let sem_o_ambiente = {
            let comeco = acao.find(do_ambiente).unwrap();
            let fim = acao.find("    - id: conferir\n").unwrap();
            format!("{}{}", &acao[..comeco], &acao[fim..])
        };
        let mut casos: Vec<(&str, String)> = vec![
            (
                "sem o passo do executor",
                format!("{antes}{}", &depois[depois.find("    - id: invariantes\n").unwrap()..]),
            ),
            ("sem o passo do ambiente", sem_o_ambiente),
            (
                "o executor noutro shell",
                acao.replacen(
                    "    - id: executor\n      shell: /usr/bin/python3 -I {0}",
                    "    - id: executor\n      shell: bash",
                    1,
                ),
            ),
            (
                "o ambiente pelo python do PATH",
                acao.replacen(
                    "    - id: ambiente\n      shell: /usr/bin/python3 -I {0}",
                    "    - id: ambiente\n      shell: python3 -I {0}",
                    1,
                ),
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
                "sem a lista fechada do ambiente",
                acao.replacen(", \"RUSTUP_HOME\", \"RUST_BACKTRACE\")", ", \"RUSTUP_HOME\", \"RUST_BACKTRACE\", \"RUSTFLAGS\")", 1),
            ),
            (
                "sem os links do commit",
                acao.replace("if modo == \"120000\":", "if modo == \"0\":"),
            ),
            (
                "sem os links no caminho das saídas",
                acao.replace("if os.path.islink(atual):", "if False:"),
            ),
            (
                "sem o canal fixado no executor",
                acao.replace("env=ambiente,\n", "\n"),
            ),
            (
                "sem o canal fixado no conferir",
                acao.replace("export RUSTUP_TOOLCHAIN=\"$canal\"\n", ""),
            ),
            (
                "sem o kernel",
                acao.replacen("            \"kernel\",\n", "", 1),
            ),
            (
                "sem a raiz na tupla",
                acao.replacen("DIRETORIOS = (\n            \"\",\n", "DIRETORIOS = (\n", 2),
            ),
            (
                "com outra forma de rustflag",
                acao.replace(
                    "            \"relocation-model=static\",\n",
                    "            \"relocation-model=static\",\n            \"linker=ferramentas/ligar\",\n",
                ),
            ),
            (
                "com outra tabela no config",
                acao.replace(
                    "TABELAS = (\"alias\", \"build\", \"target\")",
                    "TABELAS = (\"alias\", \"build\", \"target\", \"env\")",
                ),
            ),
            (
                "as invariantes sem a entrada",
                acao.replace("      if: inputs.invariantes == 'true'\n", ""),
            ),
            (
                "as invariantes sem o canal fixado",
                acao.replace(
                    "      env:\n        RUSTUP_TOOLCHAIN: ${{ steps.conferir.outputs.canal }}\n",
                    "",
                ),
            ),
            (
                "sem a entrada",
                acao.replacen("inputs:\n  invariantes:\n", "inputs:\n  outra:\n", 1),
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
        // O passo do executor antes do `id: conferir`.
        let conferir = "    - id: conferir\n";
        let (topo, passos) = antes.split_at(antes.find(conferir).unwrap());
        let fim_do_executor = depois.find("    - id: invariantes\n").unwrap();
        casos.push((
            "o executor antes do conferir",
            format!(
                "{topo}{}\n{passos}{}",
                &depois[..fim_do_executor],
                &depois[fim_do_executor..]
            ),
        ));
        let mut cegos = Vec::new();
        for (rotulo, texto) in casos {
            assert_ne!(texto, acao, "{rotulo}");
            if conferir_a_acao(&texto).is_empty() {
                cegos.push(rotulo);
            }
        }
        assert!(
            cegos.is_empty(),
            "a conferência da ação não acusou: {cegos:?}"
        );
        // A raiz se rotula `./`.
        let sem_a_raiz =
            acao.replacen("DIRETORIOS = (\n            \"\",\n", "DIRETORIOS = (\n", 2);
        let fora = conferir_a_acao(&sem_a_raiz);
        assert!(
            fora.iter().any(|f| f.contains("não confere `./`")),
            "{fora:?}"
        );
    }

    /// O resultado de rodar os passos da ação: se todos passaram, e o que
    /// disseram.
    struct NaAcao {
        passou: bool,
        saida: String,
    }

    /// Os passos da ação do compilador rodados como o runner os roda, numa
    /// árvore à parte em `base`/`nome`: os `rust-toolchain.toml` e os
    /// configs do cargo do repositório, mais os `arquivos` do caso — no
    /// commit, menos os de `target/`, que o `.gitignore` deixa de fora, a
    /// não ser os `forcados` —, num repositório do git; cada passo, em
    /// ordem, no shell do `shell:` dele — o `bash` como o runner o chama —,
    /// e o primeiro que reprova para os outros; o das invariantes, que só o
    /// job de lints liga, fica de fora. O ambiente é o do runner: o PATH com
    /// o `CARGO_HOME` de um caso — vazio, com os proxies ligados ao rustup de
    /// verdade —, o `RUSTUP_HOME` de verdade, e nada mais que o `ambiente`
    /// do caso; e `antes_no_path`, uma pasta posta na frente do PATH. Os
    /// arquivos de `ferramentas/` — os programas falsos — são executáveis.
    fn rodar_a_acao(
        base: &Path,
        nome: &str,
        arquivos: &[(&str, String)],
        forcados: &[&str],
        ambiente: &[(&str, String)],
        antes_no_path: Option<&str>,
    ) -> NaAcao {
        rodar_a_acao_com_links(base, nome, arquivos, &[], forcados, ambiente, antes_no_path)
    }

    /// Como [`rodar_a_acao`], com os `links` do caso na árvore — o caminho e
    /// para onde ele aponta —, no commit como os arquivos: o `.gitignore`
    /// do caso, se ele tem um, decide.
    fn rodar_a_acao_com_links(
        base: &Path,
        nome: &str,
        arquivos: &[(&str, String)],
        links: &[(&str, &str)],
        forcados: &[&str],
        ambiente: &[(&str, String)],
        antes_no_path: Option<&str>,
    ) -> NaAcao {
        let acao = include_str!("../../.github/actions/compilador/action.yml");
        let projeto = super::super::raiz_do_projeto();
        let arvore = base.join(nome);
        let _ = std::fs::remove_dir_all(&arvore);
        let escrever = |relativo: &str, texto: &str| {
            let caminho = arvore.join(relativo);
            std::fs::create_dir_all(caminho.parent().expect("a pasta")).expect("a pasta");
            std::fs::write(&caminho, texto).expect(relativo);
        };
        for relativo in [
            "rust-toolchain.toml",
            "sdk/modelo/rust-toolchain.toml",
            ".cargo/config.toml",
            "kernel/.cargo/config.toml",
            "programas/.cargo/config.toml",
            "sdk/modelo/.cargo/config.toml",
        ] {
            escrever(
                relativo,
                &std::fs::read_to_string(projeto.join(relativo)).expect(relativo),
            );
        }
        escrever(".gitignore", "target/\n");
        std::fs::create_dir_all(arvore.join("iniciador")).expect("o iniciador");
        for (relativo, texto) in arquivos {
            escrever(relativo, texto);
            // Os programas falsos do caso, executáveis, como num commit com
            // o modo deles.
            if relativo.starts_with("ferramentas/") {
                tornar_executavel(&arvore.join(relativo));
            }
        }
        for (relativo, destino) in links {
            let caminho = arvore.join(relativo);
            std::fs::create_dir_all(caminho.parent().expect("a pasta")).expect("a pasta");
            std::os::unix::fs::symlink(destino, &caminho).expect(relativo);
        }
        let git = |args: &[&str]| {
            let feito = Command::new("git")
                .args(["-c", "user.name=teste", "-c", "user.email=teste@teste"])
                .args(["-c", "commit.gpgsign=false", "-c", "init.defaultBranch=x"])
                .args(args)
                .current_dir(&arvore)
                .output()
                .expect("o git");
            assert!(feito.status.success(), "git {args:?}: {feito:?}");
        };
        git(&["init", "-q"]);
        git(&["add", "-A"]);
        for f in forcados {
            git(&["add", "-f", "--", f]);
        }
        git(&["commit", "-q", "-m", "a árvore do caso"]);
        // O CARGO_HOME do caso, com os proxies ligados ao rustup de verdade,
        // como o rustup os instala.
        let rustup = rustup_de_verdade();
        let rustup_home = std::env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".rustup")))
            .expect("o RUSTUP_HOME");
        let casa = base.join(format!("{nome}-casa"));
        let _ = std::fs::remove_dir_all(&casa);
        std::fs::create_dir_all(casa.join("bin")).expect("a casa");
        for proxy in ["rustup", "cargo", "rustc", "rustdoc", "rustfmt"] {
            std::os::unix::fs::symlink(&rustup, casa.join("bin").join(proxy)).expect("o proxy");
        }
        let mut caminho = format!("{}:/usr/bin:/bin", casa.join("bin").display());
        if let Some(pasta) = antes_no_path {
            caminho = format!("{pasta}:{caminho}");
        }
        let saida_do_github = base.join(format!("{nome}-saida"));
        let mut passou = true;
        let mut saida = String::new();
        for (id, _, _) in PASSOS_DA_ACAO {
            if id == "invariantes" {
                continue;
            }
            let (shell, script) = passo_da_acao(acao, id).expect("o passo");
            let arquivo = base.join(format!("{nome}-{id}.script"));
            std::fs::write(&arquivo, &script).expect("o script");
            let comando: Vec<String> = if shell == "bash" {
                ["bash", "--noprofile", "--norc", "-eo", "pipefail"]
                    .iter()
                    .map(|p| (*p).to_string())
                    .chain([arquivo.display().to_string()])
                    .collect()
            } else {
                shell
                    .split_whitespace()
                    .map(|p| {
                        if p == "{0}" {
                            arquivo.display().to_string()
                        } else {
                            p.to_string()
                        }
                    })
                    .collect()
            };
            let feito = Command::new(&comando[0])
                .args(&comando[1..])
                .current_dir(&arvore)
                .env_clear()
                .env("PATH", &caminho)
                .env("HOME", base)
                .env("CARGO_HOME", &casa)
                .env("RUSTUP_HOME", &rustup_home)
                .env("GITHUB_OUTPUT", &saida_do_github)
                .envs(ambiente.iter().map(|(n, v)| (*n, v.as_str())))
                .output()
                .expect("o passo");
            saida.push_str(&format!(
                "[{id}]\n{}{}",
                String::from_utf8_lossy(&feito.stdout),
                String::from_utf8_lossy(&feito.stderr)
            ));
            if !feito.status.success() {
                passou = false;
                break;
            }
        }
        NaAcao { passou, saida }
    }

    /// O proxy do rustup de verdade — o `rustup` do `CARGO_HOME` de quem roda
    /// o teste —, a que os proxies de um caso se ligam, como o rustup os
    /// instala.
    fn rustup_de_verdade() -> PathBuf {
        let casa = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))
            .expect("o CARGO_HOME");
        let rustup = casa.join("bin").join("rustup");
        assert!(
            rustup.is_file(),
            "o teste roda os passos da ação com o proxy do rustup, como a CI: falta {}",
            rustup.display()
        );
        rustup
    }

    /// Uma pasta à parte para as árvores dos casos de um teste da ação.
    fn base_da_acao(teste: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("xtask-{teste}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("a base");
        base
    }

    /// Os passos da ação rodados como no runner (o A8 do adversário do lote
    /// A8, no lote A9; o proxy do rustup no PATH, no lote A10): a árvore com
    /// os configs do repositório passa. Reprovam, cada um com a mensagem
    /// dele: o executor na raiz; um apelido a mais; o ligador do hospedeiro
    /// no config do kernel; o embrulho do compilador no do kernel; o `[env]`
    /// na raiz, que só tem o apelido; e, no ambiente, o apelido, o executor e
    /// o ligador.
    #[test]
    fn a_acao_roda_como_no_runner() {
        let base = base_da_acao("acao");
        let projeto = super::super::raiz_do_projeto();
        let ler = |relativo: &str| std::fs::read_to_string(projeto.join(relativo)).expect(relativo);
        let da_raiz = ler(".cargo/config.toml");
        let do_kernel = ler("kernel/.cargo/config.toml");
        let limpa = rodar_a_acao(&base, "limpa", &[], &[], &[], None);
        assert!(limpa.passou, "{}", limpa.saida);
        assert!(
            limpa.saida.contains("só o apelido oficial")
                && limpa.saida.contains("o compilador oficial: ")
                && limpa.saida.contains("só as variáveis da lista"),
            "{}",
            limpa.saida
        );
        // O nome, os arquivos, o ambiente e o que o passo diz.
        type Caso = (
            &'static str,
            Vec<(&'static str, String)>,
            Vec<(&'static str, String)>,
            &'static str,
        );
        let casos: Vec<Caso> = vec![
            (
                "executor",
                vec![(
                    ".cargo/config.toml",
                    format!("{da_raiz}\n[target.'cfg(unix)']\nrunner = \"ferramentas/rodar\"\n"),
                )],
                vec![],
                "em ./, o config do cargo define target.cfg(unix).runner",
            ),
            (
                "apelido",
                vec![(".cargo/config.toml", format!("{da_raiz}b = \"build\"\n"))],
                vec![],
                "em ./, o [alias] do config do cargo é {",
            ),
            (
                "ligador",
                vec![(
                    "kernel/.cargo/config.toml",
                    format!(
                        "{do_kernel}\n[target.x86_64-unknown-linux-gnu]\nlinker = \"ferramentas/ligar\"\n"
                    ),
                )],
                vec![],
                "em kernel/, o config do cargo define target.x86_64-unknown-linux-gnu.linker",
            ),
            (
                "embrulho",
                vec![(
                    "kernel/.cargo/config.toml",
                    do_kernel.replacen("[build]\n", "[build]\nrustc-wrapper = \"embrulho\"\n", 1),
                )],
                vec![],
                "em kernel/, o config do cargo define build.rustc-wrapper",
            ),
            (
                "env-na-raiz",
                vec![(
                    ".cargo/config.toml",
                    format!("{da_raiz}\n[env]\nDUKE_DE_FORA = \"1\"\n"),
                )],
                vec![],
                "na raiz, onde o xtask se compila e roda, o config do cargo tem ['env']",
            ),
            (
                "apelido-no-ambiente",
                vec![],
                vec![("CARGO_ALIAS_XTASK", String::from("run --package outro --"))],
                "a variável CARGO_ALIAS_XTASK está no ambiente do job, fora da lista fechada",
            ),
            (
                "executor-no-ambiente",
                vec![],
                vec![(
                    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
                    String::from("ferramentas/rodar"),
                )],
                "a variável CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER está no ambiente do job",
            ),
            (
                "ligador-no-ambiente",
                vec![],
                vec![(
                    "CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER",
                    String::from("ferramentas/ligar"),
                )],
                "a variável CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER está no ambiente do job",
            ),
            (
                "artefato-no-commit",
                vec![("target/debug/xtask", String::from("#!/bin/sh\n"))],
                vec![],
                "target/debug/xtask: um arquivo do commit num diretório de saída do cargo",
            ),
        ];
        let mut cegos = Vec::new();
        for (nome, arquivos, ambiente, esperado) in &casos {
            let forcados: Vec<&str> = arquivos
                .iter()
                .map(|(a, _)| *a)
                .filter(|a| a.starts_with("target/"))
                .collect();
            let r = rodar_a_acao(&base, nome, arquivos, &forcados, ambiente, None);
            if r.passou || !r.saida.contains(&format!("::error::{esperado}")) {
                cegos.push(format!("{nome}: {}", r.saida));
            }
        }
        let _ = std::fs::remove_dir_all(&base);
        assert!(cegos.is_empty(), "{cegos:#?}");
    }

    /// O diretório de saída por um link (no lote A12, o achado 3 do
    /// adversário do lote A11): um `target` que é um link — o modo 120000 do
    /// índice, sem a barra — para uma pasta do commit passava pela regra dos
    /// arquivos do commit num diretório de saída, que casa o caminho, e o
    /// cargo podia tomar o `xtask` plantado nela pelo que compilou. O passo
    /// do ambiente recusa, pelo índice, todo link do commit, e, pelo disco,
    /// todo link no caminho de um diretório de saída: o link `target` e o
    /// `target` de um diretório de build que é um link reprovam pelas duas
    /// regras; o link para dentro de um `target`, só pelo índice; e o link
    /// fora do commit, que o `.gitignore` do caso esconde do índice, só pelo
    /// disco — cada um com os erros dele, e só eles. Os controles — o
    /// `target` de verdade, fora do commit, e nenhum — passam.
    #[test]
    fn adversario_a11_o_diretorio_de_saida_por_um_link() {
        let base = base_da_acao("acao-a11-links");
        let falso = String::from("#!/bin/sh\necho \"o xtask do commit\"\n");
        let no_indice = "um link no commit";
        let no_disco = "o diretório de saída do cargo passa pelo link";
        type Caso = (
            &'static str,
            Vec<(&'static str, String)>,
            Vec<(&'static str, &'static str)>,
            Vec<String>,
        );
        let casos: Vec<Caso> = vec![
            (
                "o-link-target",
                vec![("zz/debug/xtask", falso.clone())],
                vec![("target", "zz")],
                vec![
                    format!("target: {no_indice}"),
                    format!("target: {no_disco} target, para zz"),
                ],
            ),
            (
                "o-link-de-um-diretorio-de-build",
                vec![("zzk/debug/xtask", falso.clone())],
                vec![("kernel/target", "../zzk")],
                vec![
                    format!("kernel/target: {no_indice}"),
                    format!("kernel/target: {no_disco} kernel/target, para ../zzk"),
                ],
            ),
            (
                "o-link-para-dentro-de-um-target",
                vec![],
                vec![("xtask/src/gerado.rs", "../../target/gerado.rs")],
                vec![format!("xtask/src/gerado.rs: {no_indice}")],
            ),
            (
                "o-link-fora-do-commit",
                vec![
                    (".gitignore", String::from("target\n")),
                    ("zz/debug/xtask", falso.clone()),
                ],
                vec![("target", "zz")],
                vec![format!("target: {no_disco} target, para zz")],
            ),
        ];
        let mut cegos = Vec::new();
        for (nome, arquivos, links, esperados) in &casos {
            let r = rodar_a_acao_com_links(&base, nome, arquivos, links, &[], &[], None);
            let erros = r
                .saida
                .lines()
                .filter(|l| l.starts_with("::error::"))
                .count();
            if r.passou
                || erros != esperados.len()
                || !esperados
                    .iter()
                    .all(|e| r.saida.contains(&format!("::error::{e}")))
            {
                cegos.push(format!("{nome}: {}", r.saida));
            }
        }
        for (nome, arquivos) in [
            ("o-target-de-verdade", vec![("target/debug/xtask", falso)]),
            ("sem-link", vec![]),
        ] {
            let r = rodar_a_acao_com_links(&base, nome, &arquivos, &[], &[], &[], None);
            if !r.passou {
                cegos.push(format!("{nome}: {}", r.saida));
            }
        }
        let _ = std::fs::remove_dir_all(&base);
        assert!(cegos.is_empty(), "{cegos:#?}");
    }

    /// F2 (adversário do lote A9): a ação rodava o `cargo` que cada
    /// diretório escolhia — um `rust-toolchain.toml` com `path` num
    /// diretório de build, o do modelo do SDK com `path` no lugar do
    /// `channel`, um `rust-toolchain` sem extensão na raiz, o PATH do job com
    /// uma pasta do repositório, o `CARGO_HOME` ou o `RUSTUP_HOME` dentro
    /// dele —, e esse programa plantava o executor depois. Cada forma
    /// reprova no passo do ambiente, e o `cargo` falso, que grava um rastro,
    /// não roda. E um `cargo` de fora do repositório que não é o proxy do
    /// rustup nem o do toolchain oficial — o de outro toolchain —, uma
    /// entrada relativa no PATH, e um `cargo` na pasta dos proxies que não é
    /// o proxy também reprovam; o do toolchain oficial passa.
    #[test]
    fn adversario_a9_f2_o_toolchain_de_um_diretorio_e_o_path() {
        let base = base_da_acao("acao-a9-f2");
        let rastro = base.join("rastro");
        let falso = format!(
            "#!/bin/sh\necho \"o cargo falso rodou: $*\" >> {}\nexit 0\n",
            rastro.display()
        );
        let mut cegos = Vec::new();
        for (nome, esperado) in [
            (
                "kernel",
                "kernel/rust-toolchain.toml: outro rust-toolchain na árvore",
            ),
            (
                "modelo",
                "o sdk/modelo/rust-toolchain.toml tem toolchain.path",
            ),
            (
                "sem-extensao",
                "rust-toolchain: outro rust-toolchain na árvore",
            ),
            ("path", "uma pasta do repositório"),
            ("cargo-home", "o CARGO_HOME é"),
            ("rustup-home", "o RUSTUP_HOME é"),
        ] {
            let arvore = base.join(nome);
            let tc = arvore.join("ferramentas/tc");
            let toolchain_com_path = format!("[toolchain]\npath = \"{}\"\n", tc.display());
            let mut arquivos: Vec<(&str, String)> = vec![
                ("ferramentas/tc/bin/cargo", falso.clone()),
                ("ferramentas/tc/bin/rustc", falso.clone()),
                ("ferramentas/bin/cargo", falso.clone()),
            ];
            let mut ambiente: Vec<(&str, String)> = Vec::new();
            let mut antes = None;
            let na_arvore = |relativo: &str| arvore.join(relativo).display().to_string();
            match nome {
                "kernel" => arquivos.push(("kernel/rust-toolchain.toml", toolchain_com_path)),
                "modelo" => arquivos.push(("sdk/modelo/rust-toolchain.toml", toolchain_com_path)),
                "sem-extensao" => arquivos.push(("rust-toolchain", toolchain_com_path)),
                "path" => antes = Some(na_arvore("ferramentas/bin")),
                "cargo-home" => ambiente.push(("CARGO_HOME", na_arvore("ferramentas"))),
                _ => ambiente.push(("RUSTUP_HOME", na_arvore("ferramentas"))),
            }
            let r = rodar_a_acao(&base, nome, &arquivos, &[], &ambiente, antes.as_deref());
            if r.passou || !r.saida.contains(esperado) || rastro.exists() {
                cegos.push(format!(
                    "{nome}: rastro {:?}: {}",
                    std::fs::read_to_string(&rastro).ok(),
                    r.saida
                ));
                let _ = std::fs::remove_file(&rastro);
            }
        }
        // Um cargo de fora do repositório que não é o proxy: o de outro
        // toolchain, ou um programa qualquer, na frente do PATH.
        let fora = base.join("fora-do-repositorio");
        std::fs::create_dir_all(&fora).expect("a pasta");
        std::fs::write(fora.join("cargo"), &falso).expect("o falso");
        tornar_executavel(&fora.join("cargo"));
        let r = rodar_a_acao(
            &base,
            "programa-qualquer",
            &[],
            &[],
            &[],
            Some(&fora.display().to_string()),
        );
        if r.passou || !r.saida.contains("e não o proxy do rustup do CARGO_HOME") || rastro.exists()
        {
            cegos.push(format!("programa-qualquer: {}", r.saida));
            let _ = std::fs::remove_file(&rastro);
        }
        // Uma entrada relativa no PATH: ela se resolve no diretório de cada
        // passo, e a que sai da raiz — a pasta de cima do checkout — cai
        // dentro do repositório no passo que roda num diretório de baixo.
        let r = rodar_a_acao(
            &base,
            "path-relativo",
            &[],
            &[],
            &[],
            Some("../relativo/bin"),
        );
        if r.passou
            || !r
                .saida
                .contains("o PATH tem a entrada relativa '../relativo/bin'")
        {
            cegos.push(format!("path-relativo: {}", r.saida));
        }
        // Um `cargo` na pasta dos proxies do CARGO_HOME que não é o proxy do
        // rustup — os outros programas dela, sim: a pasta não basta.
        let outra_casa = base.join("outra-casa");
        std::fs::create_dir_all(outra_casa.join("bin")).expect("a pasta");
        for proxy in ["rustup", "rustc", "rustdoc", "rustfmt"] {
            std::os::unix::fs::symlink(rustup_de_verdade(), outra_casa.join("bin").join(proxy))
                .expect("o proxy");
        }
        std::fs::write(outra_casa.join("bin/cargo"), &falso).expect("o falso");
        tornar_executavel(&outra_casa.join("bin/cargo"));
        let r = rodar_a_acao(
            &base,
            "cargo-que-nao-e-o-proxy",
            &[],
            &[],
            &[("CARGO_HOME", outra_casa.display().to_string())],
            Some(&outra_casa.join("bin").display().to_string()),
        );
        let esperado = format!(
            "o cargo do PATH é {}, e não o proxy do rustup",
            outra_casa.join("bin/cargo").display()
        );
        if r.passou || !r.saida.contains(&esperado) || rastro.exists() {
            cegos.push(format!("cargo-que-nao-e-o-proxy: {}", r.saida));
            let _ = std::fs::remove_file(&rastro);
        }
        // O do toolchain oficial, na frente do PATH, passa.
        let oficial = Path::new(env!("CARGO"))
            .parent()
            .expect("o bin")
            .display()
            .to_string();
        let r = rodar_a_acao(&base, "o-do-toolchain", &[], &[], &[], Some(&oficial));
        if !r.passou {
            cegos.push(format!("o do toolchain oficial reprovou: {}", r.saida));
        }
        let _ = std::fs::remove_dir_all(&base);
        assert!(cegos.is_empty(), "{cegos:#?}");
    }

    /// Torna `arquivo` executável.
    fn tornar_executavel(arquivo: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut permissoes = std::fs::metadata(arquivo).expect("o arquivo").permissions();
        permissoes.set_mode(0o755);
        std::fs::set_permissions(arquivo, permissoes).expect("a permissão");
    }

    /// F1 e F3 (adversário do lote A9): os passos da ação deixavam passar o
    /// que escolhe um programa no lugar do do toolchain por outros nomes —
    /// no ambiente do job, os rustflags com o `-C linker=` (que ligam o
    /// binário do `xtask`), o `RUSTDOC`, o `RUSTDOCFLAGS` e o `RUSTFMT` (que
    /// rodam antes das invariantes); e, no config de um diretório de build
    /// fora da raiz, o `[env] PATH`, o `[host] linker` e o `-C linker=` nos
    /// rustflags. Cada um tem de reprovar. Adaptado ao arnês que roda a ação
    /// com o proxy do rustup, como no runner (o lote A10), com o resto da
    /// lista fechada do config: o `-fuse-ld`, o `paths`, o alvo de um
    /// arquivo, outra chave de uma tabela `target` e outra da `[build]`.
    #[test]
    fn adversario_a9_f1_f3_o_passo_e_os_outros_nomes_do_ligador() {
        let base = base_da_acao("acao-a9-f1-f3");
        let projeto = super::super::raiz_do_projeto();
        let programas = std::fs::read_to_string(projeto.join("programas/.cargo/config.toml"))
            .expect("os programas");
        let com_os_programas = |texto: String| vec![("programas/.cargo/config.toml", texto)];
        let limpa = rodar_a_acao(
            &base,
            "limpa",
            &com_os_programas(programas.clone()),
            &[],
            &[],
            None,
        );
        assert!(limpa.passou, "a árvore limpa: {}", limpa.saida);
        let ligar = String::from("-C linker=ferramentas/ligar");
        let no_ambiente = |nome: &str| format!("a variável {nome} está no ambiente do job");
        // O rótulo, os arquivos, o ambiente e o que o passo diz.
        type Caso<'a> = (
            &'a str,
            Vec<(&'a str, String)>,
            Vec<(&'a str, String)>,
            String,
        );
        let casos: Vec<Caso<'_>> = vec![
            (
                "o RUSTFLAGS",
                vec![],
                vec![("RUSTFLAGS", ligar.clone())],
                no_ambiente("RUSTFLAGS"),
            ),
            (
                "o CARGO_ENCODED_RUSTFLAGS",
                vec![],
                vec![("CARGO_ENCODED_RUSTFLAGS", ligar.clone())],
                no_ambiente("CARGO_ENCODED_RUSTFLAGS"),
            ),
            (
                "o CARGO_BUILD_RUSTFLAGS",
                vec![],
                vec![("CARGO_BUILD_RUSTFLAGS", ligar.clone())],
                no_ambiente("CARGO_BUILD_RUSTFLAGS"),
            ),
            (
                "o CARGO_TARGET_<hospedeiro>_RUSTFLAGS",
                vec![],
                vec![(
                    "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
                    ligar.clone(),
                )],
                no_ambiente("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS"),
            ),
            (
                "o RUSTDOC",
                vec![],
                vec![("RUSTDOC", String::from("ferramentas/rustdoc"))],
                no_ambiente("RUSTDOC"),
            ),
            (
                "o RUSTDOCFLAGS",
                vec![],
                vec![("RUSTDOCFLAGS", ligar.clone())],
                no_ambiente("RUSTDOCFLAGS"),
            ),
            (
                "o RUSTFMT",
                vec![],
                vec![("RUSTFMT", String::from("ferramentas/rustfmt"))],
                no_ambiente("RUSTFMT"),
            ),
            (
                "o __CARGO_TESTS_ONLY_SRC_ROOT",
                vec![],
                vec![(
                    "__CARGO_TESTS_ONLY_SRC_ROOT",
                    String::from("ferramentas/fonte"),
                )],
                no_ambiente("__CARGO_TESTS_ONLY_SRC_ROOT"),
            ),
            (
                "o CARGO",
                vec![],
                vec![("CARGO", String::from("ferramentas/cargo"))],
                no_ambiente("CARGO"),
            ),
            (
                "o RUSTUP_TOOLCHAIN",
                vec![],
                vec![("RUSTUP_TOOLCHAIN", String::from("nightly"))],
                no_ambiente("RUSTUP_TOOLCHAIN"),
            ),
            (
                "o RUSTC_WRAPPER",
                vec![],
                vec![("RUSTC_WRAPPER", String::from("ferramentas/embrulho"))],
                no_ambiente("RUSTC_WRAPPER"),
            ),
            (
                "o [env] PATH dos programas",
                com_os_programas(format!(
                    "{programas}\n[env]\nPATH = {{ value = \"../ferramentas:/usr/bin:/bin\", \
                     relative = true, force = true }}\n"
                )),
                vec![],
                String::from("em programas/, o config do cargo tem env, fora da lista"),
            ),
            (
                "o [host] linker dos programas",
                com_os_programas(format!(
                    "target-applies-to-host = false\n{programas}\n[unstable]\nhost-config = \
                     true\ntarget-applies-to-host = true\n\n[host]\nlinker = \"../ferramentas/ligar\"\n"
                )),
                vec![],
                String::from("em programas/, o config do cargo tem host, fora da lista"),
            ),
            (
                "o -C linker= nos rustflags dos programas",
                com_os_programas(programas.replacen(
                    "rustflags = [\n",
                    "rustflags = [\n    \"-C\", \"linker=ferramentas/ligar\",\n",
                    1,
                )),
                vec![],
                String::from(
                    "em programas/, os rustflags de target.x86_64-unknown-none têm `-C \
                     linker=ferramentas/ligar`",
                ),
            ),
            (
                "o -fuse-ld nos rustflags dos programas",
                com_os_programas(programas.replacen(
                    "rustflags = [\n",
                    "rustflags = [\n    \"-C\", \"link-arg=-fuse-ld=/tmp/ld\",\n",
                    1,
                )),
                vec![],
                String::from(
                    "em programas/, os rustflags de target.x86_64-unknown-none têm `-C \
                     link-arg=-fuse-ld=/tmp/ld`",
                ),
            ),
            (
                "o paths no config do kernel",
                vec![(
                    "kernel/.cargo/config.toml",
                    format!(
                        "paths = [\"../vendor/bit_field\"]\n{}",
                        std::fs::read_to_string(projeto.join("kernel/.cargo/config.toml"))
                            .expect("o kernel")
                    ),
                )],
                vec![],
                String::from("em kernel/, o config do cargo tem paths, fora da lista"),
            ),
            (
                "o alvo de um arquivo nos programas",
                com_os_programas(programas.replacen(
                    "target = \"x86_64-unknown-none\"",
                    "target = \"ferramentas/alvo.json\"",
                    1,
                )),
                vec![],
                String::from("em programas/, o build.target é \"ferramentas/alvo.json\""),
            ),
            (
                "outra chave de um alvo nos programas",
                com_os_programas(format!(
                    "{programas}\n[target.x86_64-unknown-uefi]\nrustdocflags = [\"-Zx\"]\n"
                )),
                vec![],
                String::from(
                    "em programas/, o config do cargo define \
                     target.x86_64-unknown-uefi.rustdocflags, fora da lista",
                ),
            ),
            (
                "outra chave da build nos programas",
                com_os_programas(programas.replacen("[build]\n", "[build]\njobs = 2\n", 1)),
                vec![],
                String::from("em programas/, o config do cargo define build.jobs, fora da lista"),
            ),
        ];
        let mut cegos = Vec::new();
        for (rotulo, arquivos, ambiente, esperado) in &casos {
            let nome = rotulo.replace([' ', '[', ']', '<', '>', '='], "-");
            let r = rodar_a_acao(&base, &nome, arquivos, &[], ambiente, None);
            if r.passou || !r.saida.contains(&format!("::error::{esperado}")) {
                cegos.push(format!("{rotulo}: {}", r.saida));
            }
        }
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            cegos.is_empty(),
            "os passos da ação deixaram passar: {cegos:#?}"
        );
    }

    /// M1 (adversário do lote A9): o passo do executor confere o config de
    /// todo diretório de build, e não só o da raiz e o do kernel — um
    /// executor em cada um dos outros reprova. A mutação que tira os outros
    /// do laço (`DIRETORIOS[:2]`) passava pelo `invariantes` (que só
    /// procurava o nome de cada um entre aspas) e pelo teste do passo (que só
    /// montava a raiz e o kernel); este a pega. O do `target/sdk-fora/`
    /// fica fora do commit, como na máquina de quem compila: o `.gitignore`
    /// do caso o deixa de fora.
    #[test]
    fn adversario_a9_m1_o_passo_le_todo_diretorio_de_build() {
        let base = base_da_acao("acao-a9-m1");
        let executor = String::from("[target.'cfg(unix)']\nrunner = \"ferramentas/rodar\"\n");
        let mut cegos = Vec::new();
        for pasta in DIRETORIOS_DOS_BUILDS.iter().filter(|d| !d.is_empty()) {
            let nome = format!("m1-{}", pasta.replace('/', "-"));
            let arquivo = format!("{pasta}/.cargo/config.toml");
            let r = rodar_a_acao(
                &base,
                &nome,
                &[(arquivo.as_str(), executor.clone())],
                &[],
                &[],
                None,
            );
            if r.passou
                || !r.saida.contains(&format!(
                    "em {pasta}/, o config do cargo define target.cfg(unix).runner"
                ))
            {
                cegos.push(format!("{pasta}: {}", r.saida));
            }
        }
        let _ = std::fs::remove_dir_all(&base);
        assert!(cegos.is_empty(), "o passo não leu: {cegos:#?}");
    }

    /// O achado do lote A10: um `Cargo.toml` com `cargo-features =
    /// ["profile-rustflags"]` liga os `rustflags` de um perfil, e com
    /// `[profile.dev] rustflags = ["-C", "linker=…"]` no da raiz o cargo do
    /// canal liga o `xtask` das invariantes com o programa do repositório. O
    /// passo do ambiente roda como no runner com os manifestos de verdade —
    /// a raiz, o kernel, os programas, o iniciador, o modelo do SDK e o
    /// `xtask` —, e passa; reprova, cada um com a mensagem dele: o
    /// `cargo-features` na raiz — também com o nome escapado — e num membro;
    /// os `rustflags` num perfil, também no de um pacote, e o
    /// `codegen-backend`; e o manifesto que não se lê.
    #[test]
    fn os_manifestos_que_escolhem_o_ligador() {
        let base = base_da_acao("acao-manifestos");
        let projeto = super::super::raiz_do_projeto();
        let ler = |relativo: &str| std::fs::read_to_string(projeto.join(relativo)).expect(relativo);
        let manifestos = [
            "Cargo.toml",
            "kernel/Cargo.toml",
            "programas/Cargo.toml",
            "iniciador/Cargo.toml",
            "sdk/modelo/Cargo.toml",
            "xtask/Cargo.toml",
        ];
        let de_verdade: Vec<(&str, String)> = manifestos.iter().map(|m| (*m, ler(m))).collect();
        let limpa = rodar_a_acao(&base, "limpa", &de_verdade, &[], &[], None);
        assert!(limpa.passou, "os manifestos de verdade: {}", limpa.saida);
        let ligar = "rustflags = [\"-C\", \"linker=ferramentas/ligar\"]\n";
        let trocado = |relativo: &'static str, velho: &str, novo: &str| {
            let texto = ler(relativo);
            assert_eq!(texto.matches(velho).count(), 1, "{relativo}: {velho}");
            (relativo, texto.replacen(velho, novo, 1))
        };
        let casos: Vec<(&str, (&str, String), &str)> = vec![
            (
                "o perfil com o ligador na raiz",
                (
                    "Cargo.toml",
                    format!(
                        "cargo-features = [\"profile-rustflags\"]\n{}\n[profile.dev]\n{ligar}",
                        ler("Cargo.toml")
                    ),
                ),
                "Cargo.toml: cargo-features ['profile-rustflags']",
            ),
            (
                "o cargo-features escapado",
                (
                    "Cargo.toml",
                    format!(
                        "\"cargo\\u002dfeatures\" = [\"profile-rustflags\"]\n{}",
                        ler("Cargo.toml")
                    ),
                ),
                "Cargo.toml: cargo-features ['profile-rustflags']",
            ),
            (
                "o cargo-features num membro",
                trocado(
                    "xtask/Cargo.toml",
                    "[package]\n",
                    "cargo-features = [\"per-package-target\"]\n\n[package]\n",
                ),
                "xtask/Cargo.toml: cargo-features ['per-package-target']",
            ),
            (
                "os rustflags do perfil dos programas",
                trocado(
                    "programas/Cargo.toml",
                    "[profile.dev]\n",
                    &format!("[profile.dev]\n{ligar}"),
                ),
                "programas/Cargo.toml: profile.dev.rustflags",
            ),
            (
                "os rustflags do perfil de um pacote",
                trocado(
                    "Cargo.toml",
                    "[profile.dev.package.rsa]\n",
                    &format!("[profile.dev.package.rsa]\n{ligar}"),
                ),
                "Cargo.toml: profile.dev.package.rsa.rustflags",
            ),
            (
                "o backend do perfil do kernel",
                trocado(
                    "kernel/Cargo.toml",
                    "[profile.dev]\n",
                    "[profile.dev]\ncodegen-backend = \"cranelift\"\n",
                ),
                "kernel/Cargo.toml: profile.dev.codegen-backend",
            ),
            (
                "o manifesto que não se lê",
                ("sdk/modelo/Cargo.toml", String::from("[package\n")),
                "sdk/modelo/Cargo.toml: não se lê como TOML",
            ),
        ];
        let mut cegos = Vec::new();
        for (rotulo, (relativo, texto), esperado) in &casos {
            let relativo: &str = relativo;
            let mut arquivos = de_verdade.clone();
            arquivos.retain(|(m, _)| *m != relativo);
            arquivos.push((relativo, texto.clone()));
            arquivos.push((
                "ferramentas/ligar",
                String::from(
                    "#!/bin/sh\necho o ligador do repositorio rodou >&2\nexec cc \"$@\"\n",
                ),
            ));
            let nome = rotulo.replace(' ', "-");
            let r = rodar_a_acao(&base, &nome, &arquivos, &[], &[], None);
            if r.passou || !r.saida.contains(&format!("::error::{esperado}")) {
                cegos.push(format!("{rotulo}: {}", r.saida));
            }
        }
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            cegos.is_empty(),
            "o passo do ambiente deixou passar: {cegos:#?}"
        );
    }

    /// O job de lints liga as invariantes na ação (no lote A10, o IN3 do
    /// adversário do lote A9): o de verdade passa; sem o `with:`, com
    /// `false`, ou com a entrada noutro passo do job — o do cache — ou noutro
    /// job, reprova. E, desde o lote A11 (o E6 do revisor do lote A10), a
    /// entrada é uma chave do `with:` do passo: num `env:` do passo, ou mais
    /// funda dentro do `with:`, reprova; o `with:` antes do `uses:`, ou com
    /// um comentário dentro, passa.
    #[test]
    fn o_job_de_lints_liga_as_invariantes_na_acao() {
        let ci = include_str!("../../.github/workflows/ci.yml");
        assert_eq!(as_invariantes_na_acao(ci), Vec::<String>::new());
        let ligada = "        with:\n          invariantes: true\n";
        assert_eq!(ci.matches(ligada).count(), 1);
        let uso = "        id: compilador\n        uses: ./.github/actions/compilador\n";
        assert!(ci.contains(&format!("{uso}{ligada}")));
        for (rotulo, texto) in [
            (
                "o with antes do uses",
                ci.replacen(&format!("{uso}{ligada}"), &format!("{ligada}{uso}"), 1),
            ),
            (
                "um comentario no with",
                ci.replacen(
                    ligada,
                    "        with:\n          # so no job de lints\n          invariantes: 'true'\n",
                    1,
                ),
            ),
        ] {
            assert_ne!(texto, ci, "{rotulo}");
            assert_eq!(
                as_invariantes_na_acao(&texto),
                Vec::<String>::new(),
                "{rotulo}"
            );
        }
        let do_cache = "          restore-keys: lints-${{ steps.compilador.outputs.canal }}-\n";
        assert_eq!(ci.matches(do_cache).count(), 1);
        for (rotulo, texto) in [
            ("sem o with", ci.replacen(ligada, "", 1)),
            (
                "com false",
                ci.replacen(ligada, "        with:\n          invariantes: false\n", 1),
            ),
            (
                "num env do passo",
                ci.replacen(ligada, "        env:\n          invariantes: true\n", 1),
            ),
            (
                "fundo no with",
                ci.replacen(
                    ligada,
                    "        with:\n          outra:\n            invariantes: true\n",
                    1,
                ),
            ),
            (
                "noutro passo do job",
                ci.replacen(ligada, "", 1).replacen(
                    do_cache,
                    &format!("{do_cache}          invariantes: true\n"),
                    1,
                ),
            ),
            (
                "noutro job",
                ci.replacen(ligada, "", 1).replacen(
                    "  testes:\n",
                    "  testes:\n    steps:\n      - uses: ./.github/actions/compilador\n        with:\n          invariantes: true\n",
                    1,
                ),
            ),
        ] {
            assert_ne!(texto, ci, "{rotulo}");
            assert_eq!(as_invariantes_na_acao(&texto).len(), 1, "{rotulo}");
        }
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
            let desvios = desvios_do_config(&dir, nome, false);
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(desvios.len(), 1, "{nome}: {desvios:?}");
            assert!(
                desvios[0].contains("troca o compilador"),
                "{nome}: {desvios:?}"
            );
        }
        let dir = com_config("sem", "[build]\ntarget = \"x86_64-unknown-none\"\n");
        let desvios = desvios_do_config(&dir, "sem", false);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(desvios, Vec::<String>::new());
    }

    #[test]
    fn o_config_que_o_cargo_nao_le_e_um_desvio() {
        // A consulta falha fechada: um config que o cargo não lê — ou uma
        // resposta que mudasse num nightly novo — não passa calado.
        let dir = com_config("quebrado", "[build\nrustc-wrapper = \"sccache\"\n");
        let desvios = desvios_do_config(&dir, "quebrado", false);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(desvios.len(), 1, "{desvios:?}");
        assert!(desvios[0].contains("não respondeu"), "{desvios:?}");
    }

    /// A raiz só com o apelido (no lote A11, a outra nota do revisor do lote
    /// A10), como na ação: o alvo e os rustflags nas formas da lista — o
    /// script do ligador inclusive — passam fora da raiz, e na raiz cada
    /// tabela além do `[alias]` se acusa, uma vez; o config da raiz de
    /// verdade passa.
    #[test]
    fn a_raiz_so_com_o_apelido() {
        for (nome, texto, tabela) in [
            (
                "raiz-script",
                "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"link-arg=-Tligar.ld\"]\n",
                "`target`",
            ),
            (
                "raiz-cfg",
                "[target.'cfg(unix)']\nrustflags = [\"--cfg\", \"duke\"]\n",
                "`target`",
            ),
            (
                "raiz-alvo",
                "[build]\ntarget = \"x86_64-unknown-none\"\n",
                "`build`",
            ),
        ] {
            let dir = com_config(nome, texto);
            let fora_da_raiz = desvios_do_config(&dir, nome, false);
            let na_raiz = desvios_do_config(&dir, nome, true);
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(fora_da_raiz, Vec::<String>::new(), "{nome}");
            assert!(
                na_raiz.len() == 1
                    && na_raiz[0].contains(&format!("o config do cargo tem {tabela}, na raiz")),
                "{nome}: {na_raiz:?}"
            );
        }
        let raiz = super::super::raiz_do_projeto();
        assert_eq!(desvios_do_config(&raiz, "./", true), Vec::<String>::new());
    }

    #[test]
    fn os_config_do_cargo_do_repositorio_nao_trocam_o_compilador() {
        let raiz = super::super::raiz_do_projeto();
        for dir in ["", "kernel", "programas", "sdk/modelo"] {
            assert_eq!(
                desvios_do_config(&raiz.join(dir), dir, dir.is_empty()),
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

    /// A ação do compilador do repositório.
    const ACAO: &str = include_str!("../../.github/actions/compilador/action.yml");

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

    /// O passo da conferência sem `if:` nem `continue-on-error:` (no lote
    /// A11, a nota do revisor do lote A10): com um `if:` — depois do `uses:`,
    /// antes dele ou como a primeira chave do item —, a conferência pode não
    /// rodar; com um `continue-on-error:`, o job segue com ela reprovada. Cada
    /// um reprova, com a chave dele, também numa ação local que a usa. Os
    /// mesmos noutro passo, ou um `if` dentro do `with:` da ação, não; e os
    /// workflows de verdade passam.
    #[test]
    fn o_passo_da_conferencia_sem_if_nem_continue_on_error() {
        let passo = "      - name: O compilador\n        id: compilador\n        uses: ./.github/actions/compilador\n";
        assert_eq!(OFICIAL.matches(passo).count(), 1);
        for (rotulo, novo, chave) in [
            (
                "if depois do uses",
                format!("{passo}        if: false\n"),
                "`if: false`",
            ),
            (
                "if antes do uses",
                passo.replacen(
                    "        id: compilador\n",
                    "        if: github.event_name == 'push'\n        id: compilador\n",
                    1,
                ),
                "`if: github.event_name == 'push'`",
            ),
            (
                "if no traco",
                passo.replacen(
                    "      - name: O compilador\n",
                    "      - if: ${{ false }}\n        name: O compilador\n",
                    1,
                ),
                "`if: ${{ false }}`",
            ),
            (
                "continue-on-error",
                format!("{passo}        continue-on-error: true\n"),
                "`continue-on-error: true`",
            ),
        ] {
            let texto = OFICIAL.replacen(passo, &novo, 1);
            assert_ne!(texto, OFICIAL, "{rotulo}");
            let fora = um(".github/workflows/ci.yml", &texto);
            assert!(
                fora.len() == 1
                    && fora[0].contains(chave)
                    && fora[0].contains("no passo da conferência do compilador"),
                "{rotulo}: {fora:?}"
            );
        }
        let local = "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/compilador\n      continue-on-error: true\n";
        assert_eq!(um(".github/actions/outra/action.yml", local).len(), 1);
        for texto in [
            OFICIAL.replacen(
                "      - name: Testes\n",
                "      - name: Testes\n        if: false\n        continue-on-error: true\n",
                1,
            ),
            OFICIAL.replacen(
                passo,
                &format!("{passo}        with:\n          if: false\n"),
                1,
            ),
        ] {
            assert_ne!(texto, OFICIAL);
            assert_eq!(um(".github/workflows/ci.yml", &texto), Vec::<String>::new());
        }
        for (nome, texto) in [
            (
                ".github/workflows/ci.yml",
                include_str!("../../.github/workflows/ci.yml"),
            ),
            (
                ".github/workflows/rede-principal.yml",
                include_str!("../../.github/workflows/rede-principal.yml"),
            ),
        ] {
            assert_eq!(um(nome, texto), Vec::<String>::new(), "{nome}");
        }
    }

    /// O comentário no fim de uma linha estrutural (no lote A12, o achado 2
    /// do adversário do lote A11): no `invariantes: true` do `with:` do job
    /// de lints, no `uses:` e no `id:` do passo da ação, ele é do YAML — o
    /// GitHub não o lê —, e reprovava o `invariantes` sem defeito, porque
    /// entrava no valor. Os três passam, cada um e juntos, no `ci.yml` de
    /// verdade, e em todo passo da ação. Um `#` dentro de aspas continua
    /// parte do valor: a ação entre aspas com ele não é a do compilador, e a
    /// entrada não liga as invariantes. E a chave de cache com o canal só
    /// num comentário reprova.
    #[test]
    fn adversario_a11_o_comentario_no_fim_de_uma_linha_estrutural() {
        let ci = include_str!("../../.github/workflows/ci.yml");
        let entrada = "          invariantes: true\n";
        let uso = "        uses: ./.github/actions/compilador\n";
        let id = "        id: compilador\n";
        assert_eq!(ci.matches(entrada).count(), 1);
        let comentar = |texto: &str, linha: &str, comentario: &str| {
            texto.replacen(linha, &format!("{}  # {comentario}\n", linha.trim_end()), 1)
        };
        let na_entrada = comentar(ci, entrada, "so no job de lints");
        let no_uso = comentar(ci, uso, "a conferencia, antes de todo cargo");
        let no_id = comentar(ci, id, "a chave do cache le o canal daqui");
        let nos_tres = comentar(&comentar(&na_entrada, uso, "a conferencia"), id, "o canal");
        let em_todo_passo = ci
            .replace(
                uso,
                "        uses: ./.github/actions/compilador # a conferencia\n",
            )
            .replace(id, "        id: compilador # o canal\n");
        for (rotulo, texto) in [
            ("na entrada", &na_entrada),
            ("no uses", &no_uso),
            ("no id", &no_id),
            ("nos tres", &nos_tres),
            ("em todo passo", &em_todo_passo),
        ] {
            assert_ne!(texto, ci, "{rotulo}");
            assert_eq!(
                as_invariantes_na_acao(texto),
                Vec::<String>::new(),
                "{rotulo}"
            );
            assert_eq!(um(CI, texto), Vec::<String>::new(), "{rotulo}");
        }
        // O `#` dentro de aspas é do valor.
        let entre_aspas = ci.replacen(
            uso,
            "        uses: './.github/actions/compilador # a conferencia'\n",
            1,
        );
        let fora = um(CI, &entre_aspas);
        assert!(
            fora.iter().any(|f| f.contains(
                "`./.github/actions/compilador # a conferencia` não é uma ação permitida"
            )),
            "{fora:?}"
        );
        let entrada_entre_aspas = ci.replacen(entrada, "          invariantes: 'true # x'\n", 1);
        assert_eq!(as_invariantes_na_acao(&entrada_entre_aspas).len(), 1);
        // O canal só no comentário não está na chave de cache.
        let no_comentario = OFICIAL.replacen(
            "          key: testes-${{ steps.compilador.outputs.canal }}-",
            "          key: testes-  # steps.compilador.outputs.canal ",
            1,
        );
        assert_ne!(no_comentario, OFICIAL);
        let fora = um(CI, &no_comentario);
        assert!(
            fora.len() == 1 && fora[0].contains("não leva o canal"),
            "{fora:?}"
        );
    }

    /// A leitura do passo da ação falha fechada (no lote A12, o achado 1 do
    /// adversário do lote A11): a linha do passo que ela não reconhece
    /// reprova, com a linha na mensagem. O escape na chave (`"i\x66":
    /// false`, que um parser de YAML lê como `if: false`), o do
    /// `continue-on-error`, a chave complexa, a chave entre aspas, a âncora,
    /// a fusão, o apelido no `with:`, uma chave fora da lista — também o
    /// `env:` por uma expressão e em bloco —, o valor em várias linhas e o
    /// `uses:` da ação no `with:` de outra ação, ou num bloco `run:`, que
    /// contavam como a conferência sem ela rodar, reprovam, cada linha uma
    /// vez. O passo de hoje passa, e as formas simples: o `with:` com as
    /// entradas e os comentários, o `uses:` na linha do `-`, o `-` sozinho,
    /// uma linha vazia no meio; e uma ação local com o escape reprova
    /// também.
    #[test]
    fn adversario_a11_a_leitura_do_passo_da_acao_falha_fechada() {
        let passo = "      - name: O compilador\n        id: compilador\n        uses: ./.github/actions/compilador\n";
        assert_eq!(OFICIAL.matches(passo).count(), 1);
        let reprovam: Vec<(&str, String, Vec<&str>)> = vec![
            (
                "o escape do if",
                format!("{passo}        \"i\\x66\": false\n"),
                vec!["\"i\\x66\": false"],
            ),
            (
                "o escape do continue-on-error",
                format!("{passo}        \"continue-on-erro\\x72\": true\n"),
                vec!["\"continue-on-erro\\x72\": true"],
            ),
            (
                "a chave complexa",
                format!("{passo}        ? continue-on-error\n        : true\n"),
                vec!["? continue-on-error", ": true"],
            ),
            (
                "a chave entre aspas",
                passo.replacen("      - name:", "      - \"name\":", 1),
                vec!["- \"name\": O compilador"],
            ),
            (
                "a ancora",
                passo.replacen("      - name:", "      - &passo\n        name:", 1),
                vec!["- &passo"],
            ),
            (
                "a fusao",
                format!("{passo}        <<: *condicao\n"),
                vec!["<<: *condicao"],
            ),
            (
                "o apelido no with",
                format!("{passo}        with: *entradas\n"),
                vec!["with: *entradas"],
            ),
            (
                "uma chave fora da lista",
                format!("{passo}        timeout-minutes: 1\n"),
                vec!["timeout-minutes: 1"],
            ),
            (
                "o env por uma expressao",
                format!("{passo}        env: ${{{{ fromJSON(vars.AMBIENTE) }}}}\n"),
                vec!["env: ${{ fromJSON(vars.AMBIENTE) }}"],
            ),
            (
                "o env em bloco",
                format!("{passo}        env:\n          LD_PRELOAD: ./ferramentas/x.so\n"),
                vec!["env:", "LD_PRELOAD: ./ferramentas/x.so"],
            ),
            (
                "o valor em varias linhas",
                passo.replacen(
                    "      - name: O compilador\n",
                    "      - name: O compilador\n          de fonte\n",
                    1,
                ),
                vec!["de fonte"],
            ),
            (
                "o uses da acao no with de outra",
                "      - name: O compilador\n        id: compilador\n        with:\n          \
                 uses: ./.github/actions/compilador\n          path: x\n          key: \
                 x-${{ steps.compilador.outputs.canal }}\n        uses: actions/cache@v4\n"
                    .to_string(),
                vec![
                    "uses: ./.github/actions/compilador",
                    "uses: actions/cache@v4",
                ],
            ),
            (
                "o uses da acao num bloco run",
                "      - name: O compilador\n        id: compilador\n        run: |\n          \
                 cat > /dev/null <<'FIM'\n          uses: ./.github/actions/compilador\n          \
                 FIM\n"
                    .to_string(),
                vec![
                    "run: |",
                    "cat > /dev/null <<'FIM'",
                    "uses: ./.github/actions/compilador",
                    "FIM",
                ],
            ),
        ];
        for (rotulo, novo, linhas) in &reprovam {
            let texto = OFICIAL.replacen(passo, novo, 1);
            assert_ne!(texto, OFICIAL, "{rotulo}");
            // Só os erros desta leitura: a das formas do arquivo inteiro
            // acusa também algumas destas linhas (desde o lote A13).
            let fora: Vec<String> = um(".github/workflows/ci.yml", &texto)
                .into_iter()
                .filter(|f| f.contains("no passo da conferência do compilador"))
                .collect();
            assert!(
                fora.len() == linhas.len()
                    && fora.iter().zip(linhas).all(|(f, l)| {
                        f.contains(&format!("`{l}` no passo da conferência do compilador"))
                            && f.contains("que a conferência não lê")
                    }),
                "{rotulo}: {fora:#?}"
            );
        }
        let passam = [
            format!("{passo}        with:\n          invariantes: true\n"),
            format!(
                "{passo}        with:  # as entradas\n          # so no job de lints\n          \
                 invariantes: 'true'  # a entrada\n          outra: \"x # y\"\n"
            ),
            "      - uses: ./.github/actions/compilador\n        id: compilador\n        name: O \
             compilador\n"
                .to_string(),
            format!(
                "      -\n{}",
                passo.replacen("      - name:", "        name:", 1)
            ),
            passo.replacen("        id:", "\n        id:", 1),
        ];
        for novo in &passam {
            let texto = OFICIAL.replacen(passo, novo, 1);
            assert_ne!(texto, OFICIAL, "{novo}");
            assert_eq!(
                um(".github/workflows/ci.yml", &texto),
                Vec::<String>::new(),
                "{novo}"
            );
        }
        for (nome, texto) in [
            (CI, include_str!("../../.github/workflows/ci.yml")),
            (
                ".github/workflows/rede-principal.yml",
                include_str!("../../.github/workflows/rede-principal.yml"),
            ),
        ] {
            assert_eq!(um(nome, texto), Vec::<String>::new(), "{nome}");
        }
        let local = "runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/compilador\n      \"i\\x66\": false\n";
        assert_eq!(
            um(".github/actions/outra/action.yml", local)
                .iter()
                .filter(|f| f.contains("no passo da conferência do compilador"))
                .count(),
            1
        );
    }

    /// As quebras de linha que a leitura por linhas não vê (no lote A13, o
    /// M1 e o B1 do adversário do lote A12): o CR sozinho, o NEL, o LS e o
    /// PS escondiam do `xtask` uma linha que o YAML lê — o `if: false` do
    /// passo da ação, depois do `name:` ou de um comentário, e o checkout —,
    /// e o BOM no começo de uma linha do meio a tirava do passo. Cada um
    /// reprova, com a linha, também na ação do compilador; o BOM do começo
    /// do arquivo e o CRLF, que o YAML e a leitura leem igual, passam; e os
    /// arquivos do repositório não têm nenhum.
    #[test]
    fn adversario_a12_as_quebras_que_a_leitura_por_linhas_nao_ve() {
        let nome = ".github/workflows/ci.yml";
        // Só os erros desta regra: as outras podem acusar a mesma linha.
        let quebras = |fora: Vec<String>| -> Vec<String> {
            fora.into_iter()
                .filter(|f| f.contains(" — o YAML lê ali uma quebra de linha"))
                .collect()
        };
        let passo = "      - name: O compilador\n        id: compilador\n";
        assert_eq!(OFICIAL.matches(passo).count(), 1);
        for (quebra, qual) in [
            ("\r", "um CR sozinho"),
            ("\u{85}", "um NEL (U+0085)"),
            ("\u{2028}", "um LS (U+2028)"),
            ("\u{2029}", "um PS (U+2029)"),
        ] {
            // O `if: false` do passo, numa linha que só o YAML vê.
            let texto = OFICIAL.replacen(
                passo,
                &format!(
                    "      - name: O compilador{quebra}        if: false\n        id: compilador\n"
                ),
                1,
            );
            let fora = um(nome, &texto);
            assert!(
                fora.len() == 1 && fora[0].starts_with(&format!("{nome}:7: {qual} — ")),
                "{qual}: {fora:#?}"
            );
            // Num comentário, que a leitura tira inteiro.
            let comentario = OFICIAL.replacen(
                passo,
                &format!("{passo}        # a conferência{quebra}        if: false\n"),
                1,
            );
            let fora = quebras(um(nome, &comentario));
            assert!(
                fora.len() == 1 && fora[0].starts_with(&format!("{nome}:9: {qual}")),
                "{qual}: {fora:#?}"
            );
            // O checkout escondido, sem o passo da ação.
            let checkout = "      - uses: actions/checkout@v4\n";
            let escondido = OFICIAL
                .replacen(
                    "      - name: O compilador\n        id: compilador\n        uses: ./.github/actions/compilador\n",
                    "",
                    1,
                )
                .replacen(checkout, &format!("      - run: echo{quebra}{checkout}"), 1);
            assert_eq!(quebras(um(nome, &escondido)).len(), 1, "{qual}");
            // E na ação do compilador, que o runner lê com o YamlDotNet.
            let acao = ACAO.replacen(
                "    - id: ambiente\n",
                &format!("    - id: ambiente{quebra}      if: false\n"),
                1,
            );
            assert_ne!(acao, ACAO);
            let fora = quebras(um(ACAO_DO_COMPILADOR, &acao));
            assert!(
                fora.len() == 1 && fora[0].contains(qual),
                "{qual}: {fora:#?}"
            );
        }
        // O BOM: no começo do arquivo, o YAML o pula; no começo de uma linha
        // do meio, ele não é recuo para a leitura daqui.
        assert_eq!(
            um(nome, &format!("\u{feff}{OFICIAL}")),
            Vec::<String>::new()
        );
        let bom = OFICIAL.replacen(passo, &format!("{passo}\u{feff}       if: false\n"), 1);
        let fora = quebras(um(nome, &bom));
        assert!(
            fora.len() == 1 && fora[0].starts_with(&format!("{nome}:9: um BOM (U+FEFF)")),
            "{fora:#?}"
        );
        // O CRLF é uma quebra só, para os dois: passa.
        assert_eq!(
            um(nome, &OFICIAL.replace('\n', "\r\n")),
            Vec::<String>::new()
        );
        // Os workflows e a ação do repositório não têm nenhum.
        for texto in [
            include_str!("../../.github/workflows/ci.yml"),
            include_str!("../../.github/workflows/rede-principal.yml"),
            include_str!("../../.github/workflows/canario.yml"),
            ACAO,
        ] {
            assert_eq!(quebras_que_a_leitura_nao_ve(texto), Vec::new());
        }
    }

    /// O passo da ação como o texto de um bloco (no lote A13, o M2 do
    /// adversário do lote A12): o `-`, o `id: compilador` e o `uses:` da ação
    /// no conteúdo de um escalar em bloco — numa entrada do `with:` do
    /// checkout, num `run:` literal que o bash não roda, num dobrado com os
    /// indicadores, num item que é o bloco — contavam como a conferência, que
    /// o GitHub não roda: cada um reprova. O conteúdo fica marcado, com as
    /// vazias entre as linhas dele, e a chave seguinte, na coluna do passo,
    /// não; e um bloco com um item que não é o da ação passa.
    #[test]
    fn adversario_a12_o_passo_da_acao_como_texto_de_um_bloco() {
        let nome = ".github/workflows/ci.yml";
        let passo = "      - name: O compilador\n        id: compilador\n        uses: ./.github/actions/compilador\n";
        assert_eq!(OFICIAL.matches(passo).count(), 1);
        let sem = OFICIAL.replacen(passo, "", 1);
        let checkout = "      - uses: actions/checkout@v4\n";
        let falso = |recuo: &str| {
            format!(
                "{recuo}- name: O compilador\n{recuo}  id: compilador\n{recuo}  uses: ./.github/actions/compilador\n"
            )
        };
        for (rotulo, bloco) in [
            (
                "numa entrada do checkout",
                format!(
                    "{checkout}        with:\n          nota: |\n{}",
                    falso("            ")
                ),
            ),
            (
                "num run que o bash nao roda",
                format!(
                    "{checkout}      - name: Nada\n        run: |\n          : '\n{}          '\n",
                    falso("          ")
                ),
            ),
            (
                "num bloco dobrado, com os indicadores e um comentario",
                format!(
                    "{checkout}      - name: Nada\n        run: >2-  # texto\n{}",
                    falso("          ")
                ),
            ),
            (
                "num item que e o bloco",
                format!("{checkout}      - |\n{}", falso("        ")),
            ),
        ] {
            let texto = sem.replacen(checkout, &bloco, 1);
            assert_ne!(texto, sem, "{rotulo}");
            assert!(!um(nome, &texto).is_empty(), "{rotulo}: passou");
        }
        // As linhas do conteúdo, marcadas, e as vazias entre elas; a chave
        // seguinte, na coluna do passo, não.
        let linhas = linhas_de_codigo(
            "      - name: Nada\n        run: |\n          - x: y\n\n            z\n        if: always()\n",
        );
        assert_eq!(
            linhas.iter().map(|l| l.escalar).collect::<Vec<_>>(),
            [false, false, true, true, true, false]
        );
        // O controle: um bloco com um item que não é o da ação, antes do
        // passo de verdade, passa.
        let com_bloco = OFICIAL.replacen(
            checkout,
            &format!("{checkout}      - name: Lista\n        run: |\n          - item: x\n            outro: y\n"),
            1,
        );
        assert_eq!(um(nome, &com_bloco), Vec::<String>::new());
    }

    /// As formas que a leitura não lê, no arquivo inteiro (no lote A13, o M3
    /// do adversário do lote A12, e a lacuna que o lote A12 deixou relatada):
    /// o checkout em estilo de fluxo, com um escape na chave ou por uma chave
    /// complexa, sem o passo da ação, não pedia a conferência; um passo num
    /// texto entre aspas em várias linhas era lido como um passo; e uma ação
    /// de fora da lista em estilo de fluxo, a âncora, a fusão, a sequência
    /// com um mapa e o item em fluxo passavam. Cada um reprova pela forma — o
    /// estilo de fluxo no valor de uma chave, também na ação do compilador.
    /// O que os workflows usam passa, e nenhuma linha dos workflows e da ação
    /// do repositório é acusada.
    #[test]
    fn adversario_a12_as_formas_que_a_leitura_nao_le_no_arquivo_inteiro() {
        let nome = ".github/workflows/ci.yml";
        let da_forma = |fora: &[String]| {
            fora.iter()
                .any(|f| f.contains("que a leitura por linhas do `xtask` não lê"))
        };
        let passo = "      - name: O compilador\n        id: compilador\n        uses: ./.github/actions/compilador\n";
        assert_eq!(OFICIAL.matches(passo).count(), 1);
        let sem = OFICIAL.replacen(passo, "", 1);
        let checkout = "      - uses: actions/checkout@v4\n";
        // O checkout que a ordem não via, sem o passo da ação; e um passo,
        // como texto, num texto entre aspas em várias linhas.
        for (rotulo, outro) in [
            (
                "em estilo de fluxo",
                "      - { uses: actions/checkout@v4 }\n",
            ),
            (
                "com um escape na chave",
                "      - \"u\\x73es\": actions/checkout@v4\n",
            ),
            (
                "numa chave complexa",
                "      - ? uses\n        : actions/checkout@v4\n",
            ),
            (
                "um passo num texto entre aspas",
                "      - uses: actions/checkout@v4\n      - name: Nada\n        run: \"echo\n          \
                 - name: O compilador\n            id: compilador\n            uses: \
                 ./.github/actions/compilador\n          \"\n",
            ),
        ] {
            let texto = sem.replacen(checkout, outro, 1);
            assert_ne!(texto, sem, "{rotulo}");
            assert!(da_forma(&um(nome, &texto)), "{rotulo}");
        }
        // Uma ação de fora da lista em estilo de fluxo, a âncora, a fusão e a
        // sequência com um mapa dentro.
        for novo in [
            "      - { uses: dtolnay/rust-toolchain@master }\n",
            "      - &x\n        run: echo\n",
            "      - name: x\n        <<: *x\n",
            "      - name: x\n        with:\n          lista: [a: b]\n",
            "      - [ run, echo ]\n",
        ] {
            let texto = format!("{OFICIAL}{novo}");
            assert!(da_forma(&um(nome, &texto)), "{novo}");
        }
        // O estilo de fluxo no valor de uma chave: a regra de antes não o via
        // na ação do compilador, e a leitura o recusa também nela.
        let na_acao = format!("{ACAO}x: {{ y: z }}\n");
        assert!(da_forma(&um(ACAO_DO_COMPILADOR, &na_acao)));
        // O que os workflows usam passa: a sequência de escalares simples, a
        // vazia, o texto entre aspas numa linha, com `: ` e `#` dentro, o
        // bloco com os indicadores, o item só com um comentário.
        let passam = format!(
            "{OFICIAL}      - name: \"a: b # c\"  # d\n        if: ${{{{ !cancelled() }}}}\n        \
             with:\n          lista: [x86_64, aarch64, 1/3]\n          vazia: []\n          texto: \
             '17 4 * * 1'\n          bloco: >-\n            {{ nada: [ disto ] }}\n        uses: \
             actions/cache@v4\n      - # um passo\n        run: echo\n"
        );
        assert_eq!(um(nome, &passam), Vec::<String>::new());
        for (n, texto) in [
            (CI, include_str!("../../.github/workflows/ci.yml")),
            (
                ".github/workflows/rede-principal.yml",
                include_str!("../../.github/workflows/rede-principal.yml"),
            ),
            (CANARIO, include_str!("../../.github/workflows/canario.yml")),
            (ACAO_DO_COMPILADOR, ACAO),
        ] {
            for l in linhas_de_codigo(texto).iter().filter(|l| !l.escalar) {
                assert_eq!(
                    forma_que_a_leitura_nao_le(l.texto),
                    None,
                    "{n}: {}",
                    l.texto
                );
            }
        }
    }

    /// Os passos da própria ação falham fechados (no lote A13, o M4 do
    /// adversário do lote A12): o `if:` no passo do ambiente, o
    /// `continue-on-error:` e o embrulho do compilador no `env:` das
    /// invariantes, o `working-directory:` no do executor, o `env:` no do
    /// conferir e outro `if:` nas invariantes reprovam, cada linha uma vez,
    /// com o passo; a ação de hoje passa.
    #[test]
    fn adversario_a12_os_passos_da_acao_falham_fechados() {
        let lidas = |acao: &str| -> Vec<String> {
            conferir_a_acao(acao)
                .into_iter()
                .filter(|f| f.contains("que a conferência não lê"))
                .collect()
        };
        assert_eq!(lidas(ACAO), Vec::<String>::new());
        for (rotulo, velho, novo, linhas) in [
            (
                "o if no ambiente",
                "    - id: ambiente\n",
                "    - id: ambiente\n      if: false\n",
                vec!["`if: false` no passo `ambiente`"],
            ),
            (
                "o continue-on-error nas invariantes",
                "      if: inputs.invariantes == 'true'\n",
                "      if: inputs.invariantes == 'true'\n      continue-on-error: true\n",
                vec!["`continue-on-error: true` no passo `invariantes`"],
            ),
            (
                "o embrulho no env das invariantes",
                "        RUSTUP_TOOLCHAIN: ${{ steps.conferir.outputs.canal }}\n",
                "        RUSTUP_TOOLCHAIN: ${{ steps.conferir.outputs.canal }}\n        RUSTC_WRAPPER: ./x\n",
                vec!["`RUSTC_WRAPPER: ./x` no passo `invariantes`"],
            ),
            (
                "o diretorio do executor",
                "    - id: executor\n",
                "    - id: executor\n      working-directory: kernel\n",
                vec!["`working-directory: kernel` no passo `executor`"],
            ),
            (
                "o env no conferir",
                "    - id: conferir\n",
                "    - id: conferir\n      env:\n        RUSTFLAGS: -Clinker=./x\n",
                vec![
                    "`env:` no passo `conferir`",
                    "`RUSTFLAGS: -Clinker=./x` no passo `conferir`",
                ],
            ),
            (
                "outro if nas invariantes",
                "      if: inputs.invariantes == 'true'\n",
                "      if: inputs.invariantes == 'true' && false\n",
                vec!["`if: inputs.invariantes == 'true' && false` no passo `invariantes`"],
            ),
        ] {
            let acao = ACAO.replacen(velho, novo, 1);
            assert_ne!(acao, ACAO, "{rotulo}");
            let fora = lidas(&acao);
            assert!(
                fora.len() == linhas.len() && fora.iter().zip(&linhas).all(|(f, l)| f.contains(l)),
                "{rotulo}: {fora:#?}"
            );
        }
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
        let acao = include_str!("../../.github/actions/compilador/action.yml");
        let comandos = comandos_do_job(ci, JOB_DE_LINTS);
        // A formatação (5), o apt, os testes, o clippy (6), o RUSTDOCFLAGS
        // e a documentação (5); as invariantes, desde o lote A10, na ação.
        assert!(comandos.len() >= 14, "{comandos:#?}");
        assert!(
            !comandos
                .iter()
                .any(|c| c.contains("cargo xtask invariantes"))
        );
        assert!(comandos.iter().any(|c| c.starts_with("RUSTDOCFLAGS: ")));
        assert_eq!(
            o_canario_repete_os_lints(ci, canario, acao),
            Vec::<String>::new()
        );
        // O canário que perde as invariantes da ação reprova.
        let sem_invariantes = canario.replace("cargo xtask invariantes", "true");
        let fora = o_canario_repete_os_lints(ci, &sem_invariantes, acao);
        assert!(
            fora.len() == 1 && fora[0].contains("`cargo xtask invariantes`"),
            "{fora:?}"
        );
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
        let fora = o_canario_repete_os_lints(&mais_um, canario, ACAO);
        assert_eq!(fora.len(), 1, "{fora:?}");
        assert!(
            fora[0].contains("cargo clippy -p novo -- -D warnings"),
            "{fora:?}"
        );
        // Um comando que o canário perdeu.
        let sem_invariantes = canario.replace("cargo xtask invariantes", "true");
        assert_eq!(
            o_canario_repete_os_lints(ci, &sem_invariantes, ACAO).len(),
            1
        );
        // Num comentário do canário, não vale.
        let comentado = canario.replace(
            "cargo xtask invariantes 2>&1",
            "true 2>&1\n          # cargo xtask invariantes",
        );
        assert_eq!(o_canario_repete_os_lints(ci, &comentado, ACAO).len(), 1);
        // Sem o job, a regra não passa calada.
        assert_eq!(
            o_canario_repete_os_lints("jobs:\n  outro:\n", canario, ACAO).len(),
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
        assert_eq!(o_canario_repete_os_lints(ci, &sem_kernel, ACAO).len(), 1);
        // O comando neutralizado não conta.
        let neutralizado = canario.replace(
            "cargo xtask invariantes 2>&1",
            "cargo xtask invariantes || true; true 2>&1",
        );
        assert_ne!(neutralizado, canario);
        assert_eq!(o_canario_repete_os_lints(ci, &neutralizado, ACAO).len(), 1);
        // Um comando da raiz que o canário só roda noutro diretório não vale.
        let noutro_diretorio = canario.replace(
            "cargo xtask invariantes 2>&1",
            "cd kernel && cargo xtask invariantes 2>&1",
        );
        assert_ne!(noutro_diretorio, canario);
        assert_eq!(
            o_canario_repete_os_lints(ci, &noutro_diretorio, ACAO).len(),
            1
        );
        // Sem os pacotes dos testes do hospedeiro.
        let sem_pacotes = canario.replace(
            "sudo apt-get install -y --no-install-recommends swtpm nghttp2-server",
            "true",
        );
        assert_ne!(sem_pacotes, canario);
        assert_eq!(o_canario_repete_os_lints(ci, &sem_pacotes, ACAO).len(), 1);
        // Sem o aarch64 nos laços.
        let sem_arm = canario.replace(
            "for alvo in x86_64-unknown-none aarch64-unknown-none-softfloat; do",
            "for alvo in x86_64-unknown-none; do",
        );
        assert!(!o_canario_repete_os_lints(ci, &sem_arm, ACAO).is_empty());
        // Só no texto de um passo em Python, não vale.
        let so_no_python = canario
            .replace("cargo xtask invariantes 2>&1", "true 2>&1")
            .replace(
                "      - name: O veredito\n",
                "      - name: Um texto\n        shell: python3 -I {0}\n        run: |\n          print(\"cargo xtask invariantes\")\n\n      - name: O veredito\n",
            );
        assert_eq!(o_canario_repete_os_lints(ci, &so_no_python, ACAO).len(), 1);
    }
}
