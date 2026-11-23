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
//! - **no `cargo xtask invariantes`** ([`conferir_o_canal`]), as regras
//!   abaixo, cada uma pelo que ela lê. A definição da CI — os workflows e
//!   as ações — é a raiz da confiança, e fica com a revisão: as regras pegam
//!   as formas que elas listam, e uma mudança de workflow que escapa delas
//!   — um nome montado em pedaços, uma linha que a leitura toma por
//!   comentário, um passo depois da ação, o script da ação — é da revisão,
//!   e não da guarda. Desde o lote A15, o texto daqui diz as regras, e não
//!   o que elas garantiriam: três rodadas seguidas do adversário acharam o
//!   texto dizendo mais do que o código fazia — e a rodada 8, seis frases
//!   assim no texto do próprio lote A15, que o lote A16 corrigiu; e a
//!   rodada 9, três do lote A16, que o lote A17 corrigiu.
//!   - o canal tem data, é o mesmo nos dois arquivos, com as chaves do
//!     oficial, e o `CLAUDE.md` o cita; não há outro `rust-toolchain` no
//!     repositório;
//!   - o config do cargo dos diretórios com `.cargo/` não troca o
//!     compilador, nem o executor, nem o apelido, e fica na lista — na
//!     raiz, só o apelido, como na ação —; o `xtask` não chama o cargo nem
//!     o rustc com outro toolchain;
//!   - a leitura de todo workflow e ação — a do compilador inclusive; desde
//!     o lote A16, cada `.yml` e `.yaml` de `.github/workflows/` e de
//!     `.github/actions/` que o git lista, pelo caminho como ele é e com a
//!     extensão em qualquer caixa ([`arquivos_do_repositorio`],
//!     [`da_definicao_da_ci`]) —, linha a linha, antes das outras regras:
//!     reprovam as quebras de linha
//!     que só o YAML vê e, desde o lote A14, os espaços que ele não toma por
//!     espaço e os caracteres que ele não imprime
//!     ([`quebras_que_a_leitura_nao_ve`]); fora do conteúdo dos blocos, as
//!     formas que ela não lê ([`forma_que_a_leitura_nao_le`]), desde o lote
//!     A13; desde o lote A14, um segundo documento
//!     ([`marcadores_de_documento`]); e, desde o lote A17, a raiz do
//!     documento fora da coluna zero ([`raiz_fora_da_coluna_zero`]) e o
//!     texto entre aspas duplas com uma `\`, cujo escape o YAML lê — o
//!     `\n` é uma quebra de linha que a leitura, que confere os caracteres,
//!     não via ([`escape_entre_aspas_duplas`]). A linha que começa por `#`, a leitura
//!     a toma por comentário — também no conteúdo de um bloco, onde o YAML a
//!     lê como texto e um heredoc do bash a roda —, e o que está nela fica
//!     com a revisão; no passo `conferir` da ação, a regra do canal a lê,
//!     desde o lote A16;
//!   - nos workflows oficiais: só as ações de [`ACOES_OFICIAIS`] e, desde o
//!     lote A15, só nas versões de [`USOS_OFICIAIS`]; nenhuma linha com uma
//!     das [`SOBREPOSICOES`] — o `GITHUB_ENV` desde o lote A14, e o
//!     `ACTIONS_ALLOW_UNSECURE_COMMANDS` desde o lote A15 — nem, desde o
//!     lote A15, com os [`COMANDOS_DO_RUNNER`]; nenhum `container:`, desde o
//!     lote A14, nem `services:`, desde o lote A15, e o `env:` do workflow e
//!     o dos jobs só com os nomes de [`VARIAVEIS_DOS_JOBS`]
//!     ([`o_que_o_job_escolhe`]); o checkout só com as chaves de
//!     [`CHAVES_DO_CHECKOUT`]; desde o lote A15, os dois primeiros passos de
//!     cada job são o checkout e a ação ([`o_comeco_dos_jobs`]); a ação
//!     `.github/actions/compilador` depois de cada checkout, antes do cache
//!     e de qualquer `cargo`, num passo sem `if:` nem `continue-on-error:`,
//!     que a leitura lê inteiro ([`linhas_que_o_passo_nao_le`], desde o lote
//!     A12); e o canal em toda chave de cache — desde o lote A16, a
//!     expressão com a saída da ação ([`CANAL_NA_CHAVE`]), que até o lote
//!     A17 se procurava pelo texto na linha, e o `id: compilador` no passo
//!     da ação; desde o lote A17, uma das expressões que o leitor de modelos
//!     do GitHub acha no valor que o YAML lê ([`o_canal_numa_expressao`]) —
//!     o texto dela num literal de outra expressão, ou na linha crua de um
//!     texto entre aspas simples, não conta —, comparada pelo texto, na
//!     forma canônica (outra grafia que o GitHub avalia igual, sem um espaço
//!     ou com a indexação, `outputs['canal']`, reprova, de propósito);
//!   - a ação do compilador ([`conferir_a_acao`]): desde o lote A14, a
//!     forma que o runner lê, sem chave nem passo a mais, e o canal da saída
//!     do passo que o confere ([`forma_da_acao`]); os passos que conferem,
//!     fora do cargo, o ambiente, o PATH, os `rust-toolchain`, os
//!     artefatos — desde o lote A17, numa pasta `target` em qualquer nível,
//!     e o `workspace` de um pacote num manifesto, que leva a raiz do
//!     workspace e o `target/` dela para outra pasta —, os links e os
//!     submódulos do commit e o que não é pasta no
//!     caminho dos diretórios de saída — pelo `git` sem o ambiente do job,
//!     desde o lote A14 —, o config do cargo e o das invariantes, cada um
//!     com as marcas dele no script, só com as chaves que a leitura lê nele
//!     ([`linhas_que_o_passo_da_acao_nao_le`]) e, desde o lote A14, o item
//!     de `runs.steps` com o `id` dele; desde o lote A15, no passo que
//!     confere o canal, as duas primeiras linhas de código são o `set -euo
//!     pipefail` e a que lê o canal do arquivo, o nome `canal`, fora da
//!     expansão, só aparece em linhas iguais a ela ou à que escreve a saída,
//!     e só esta cita o `GITHUB_OUTPUT` — e, desde o lote A16, a da leitura
//!     aparece uma vez, a da saída é a última, nenhuma linha define uma
//!     função ou um apelido, nem tem o `enable`, e as linhas de comentário
//!     também contam ([`o_canal_do_passo_conferir`]); e nenhuma linha de
//!     código dela — fora as de comentário — cita o `GITHUB_ENV`, o
//!     `GITHUB_PATH` nem, desde o lote A15, os [`COMANDOS_DO_RUNNER`], nas
//!     formas que o runner lê;
//!   - o job de lints liga as invariantes pela entrada `invariantes: true`
//!     no `with:` do primeiro passo do `steps:` dele que usa a ação
//!     ([`as_invariantes_na_acao`]); e, desde o lote A16, a CI e o canário,
//!     que essa regra e a de baixo acham pelo nome, existem
//!     ([`workflows_que_faltam`]); e, desde o lote A17, o `on:` da CI tem
//!     o `push`, sem filtro ([`a_ci_nos_pushes`]);
//!   - o canário, o único que sobrepõe — ele testa o candidato —: desde o
//!     lote A16, só os gatilhos de [`GATILHOS_DO_CANARIO`], nas formas do
//!     `on:` da raiz que a leitura lê — o valor na linha, a lista em bloco,
//!     também na coluna do `on:`, e as chaves do mapa —, e, desde o lote
//!     A17, com o `on:` na coluna zero ([`gatilhos_fora_da_lista`]); não
//!     usa a ação do cache e, desde o lote A17, tem o `cache-mode: none` na
//!     raiz, sem outro num job ([`o_modo_do_cache_do_canario`]); só usa as
//!     ações dele nas versões de [`USOS_OFICIAIS`] (desde o lote A16);
//!     nenhuma linha de código dele cita o caminho da proveniência
//!     (`target/proveniencia`), e, desde o lote A17, a publicação dele é só
//!     a pasta dos registros ([`a_publicacao_do_canario`]), comparada pelo
//!     texto, na forma canônica ([`REGISTROS_DO_CANARIO`]); e repete os
//!     comandos do job de lints;
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

/// A linha do passo `conferir` da ação do compilador que lê o canal: o
/// `channel` do `rust-toolchain.toml` da raiz, o arquivo que o passo confere
/// contra o do commit logo depois ([`o_canal_do_passo_conferir`]). Desde o
/// lote A15 — e, desde o lote A16, uma vez só no script.
const LEITURA_DO_CANAL: &str = "canal=$(python3 -I -c 'import tomllib; \
     print(tomllib.load(open(\"rust-toolchain.toml\", \"rb\"))[\"toolchain\"][\"channel\"])')";

/// A linha do passo `conferir` da ação do compilador que escreve a saída
/// `canal`, a de toda chave de cache: uma marca do passo ([`PASSOS_DA_ACAO`])
/// e a única que cita o `GITHUB_OUTPUT` nele — e, desde o lote A16, a
/// última do script ([`o_canal_do_passo_conferir`]).
const SAIDA_DO_CANAL: &str = "echo \"canal=$canal\" >> \"$GITHUB_OUTPUT\"";

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
///
/// # Os submódulos e o que não é pasta, desde o lote A13
///
/// Um submódulo — um gitlink, o modo 160000 do índice — no lugar de um
/// `target` passava pelas duas regras (o I1 do adversário do lote A12):
/// num checkout sem os submódulos, ele é uma pasta vazia, e num com eles,
/// os arquivos de outro repositório, que nenhuma regra daqui vê. E um
/// `target` que é um arquivo do commit também passava, e só o cargo parava
/// depois (o I2 dele). O passo recusa todo submódulo do commit, pelo modo
/// do índice — o repositório não tem nenhum —, e, no caminho de um
/// diretório de saída, o que existe e não é pasta.
///
/// # O `target` de outro workspace, desde o lote A17
///
/// O diretório de saída do cargo é o `target/` da raiz do workspace, e um
/// manifesto escolhe a raiz: o `Cargo.toml` da raiz como um pacote com
/// `workspace = "zz"` a leva para `zz/`, e o `target/` do `xtask` com ela —
/// fora da lista dos diretórios de build, a única que a regra dos arquivos do
/// commit lia. Num brinquedo, com a ação rodada como o runner num checkout
/// novo, as duas marcas do cargo de uma dependência do registro sem
/// dependências (o `zeroize`, cujo fingerprint não leva o caminho do
/// checkout, e sim o do `CARGO_HOME`) e o rlib e o rmeta compilados de uma
/// fonte com uma função no `.init_array`, em `zz/target/`, passaram pelos
/// quatro passos: o cargo tomou o rlib pelo que compilou, o ligador oficial o
/// pôs no `xtask` das invariantes, e a função respondeu por elas (o A1 do
/// adversário do lote A16). O passo recusa o arquivo do commit em toda pasta
/// `target`, em qualquer nível — sem config nem ambiente, que a ação fecha, o
/// diretório de saída se chama `target`, onde quer que a raiz esteja —, e o
/// `workspace` de um pacote em todo manifesto (`package.workspace`, e o da
/// tabela antiga, `project.workspace`, que o cargo do canal ainda lê): o
/// repositório não o usa, e as outras regras daqui supõem a raiz onde ela
/// está.
///
/// # O canal que o passo `conferir` devolve, desde o lote A14
///
/// O `outputs.canal` da ação é a saída `canal` do passo `conferir`
/// ([`forma_da_acao`]), e o passo a escreve com o canal que conferiu e
/// instalou — a linha é uma marca dele ([`SAIDA_DO_CANAL`]): com um valor
/// fixo, no `outputs.canal` ou no `echo` do passo, toda chave de cache
/// levaria o mesmo texto em todo compilador, e "um cache é do compilador que
/// o encheu" deixaria de valer, com o `cargo xtask invariantes` passando (o
/// M2 do adversário do lote A13, e o N3 do revisor da rodada 6). A marca
/// prova que a linha existe, e não o valor: desde o lote A15, a regra do
/// canal ([`o_canal_do_passo_conferir`]) confere, pelo texto do script, que
/// o nome só recebe valor em linhas iguais à que o lê do
/// `rust-toolchain.toml` (o B1 do adversário do lote A14) — e, desde o lote
/// A16, que essa linha aparece uma vez, que a da saída é a última, que
/// nenhuma linha define uma função ou um apelido, nem tem o `enable`, e que
/// as linhas de comentário também contam (o E1 do revisor da rodada 8 e o
/// B1 do adversário do lote A15). O que ela não segue está no doc dela.
///
/// # O git sem o ambiente do job, desde o lote A14
///
/// Os passos do ambiente e do canal leem o índice e a árvore pelo `git`,
/// que lia o ambiente do job: um `GIT_INDEX_FILE` — ou um `GIT_DIR` — no
/// `env:` do job mostrava às regras dos diretórios de saída, dos links e
/// dos submódulos outro índice, e o arquivo do commit num `target/` e o
/// submódulo no lugar dele sumiam da lista (o M5 do adversário do lote
/// A13); e a configuração que o `HOME` ou o `XDG_CONFIG_HOME` do job
/// escolhem — um `.gitconfig` do commit — faz o `git ls-files` e o
/// `git diff` rodarem um programa, o `core.fsmonitor` (o lote A14 o achou
/// na revisão, num brinquedo). Os dois rodam o `git` só com o PATH, que o
/// passo do ambiente confere, e sem a configuração global e a do sistema
/// (`GIT_CONFIG_GLOBAL`, `GIT_CONFIG_NOSYSTEM`): a do repositório, desde o
/// lote A15, é a do checkout — nenhum passo entre eles ([`o_comeco_dos_jobs`]).
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
            "for tabela in (\"package\", \"project\"):",
            "if isinstance(pacote, dict) and \"workspace\" in pacote:",
            "os.path.samefile(achado, rustup)",
            "arquivo.startswith(saidas)",
            "\"target\" in arquivo.split(\"/\")[:-1]",
            "if modo == \"120000\":",
            "if os.path.islink(atual):",
            "if modo == \"160000\":",
            "if os.path.lexists(atual)",
            "SEM_O_GIT = {\"PATH\": os.environ.get(\"PATH\", \"\"), \"GIT_CONFIG_NOSYSTEM\": \"1\", \"GIT_CONFIG_GLOBAL\": os.devnull}",
            "env=SEM_O_GIT",
        ],
    ),
    (
        "conferir",
        "bash",
        &[
            "git diff --quiet HEAD -- rust-toolchain.toml sdk/modelo/rust-toolchain.toml",
            "export RUSTUP_TOOLCHAIN=\"$canal\"",
            "sysroot=$(rustc --print sysroot)",
            SAIDA_DO_CANAL,
            "env -i PATH=\"$PATH\" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git diff",
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
/// texto de todo passo, também dos que rodam depois dela. E, desde o lote
/// A14, o `GITHUB_ENV`, que põe uma variável no ambiente dos passos
/// seguintes — num passo antes da ação, no dos passos dela —, por fora da
/// lista fechada do `env:` dos jobs ([`VARIAVEIS_DOS_JOBS`]).
///
/// # Os comandos do runner, desde o lote A15
///
/// O `GITHUB_ENV` e o `GITHUB_PATH` têm outro nome: os comandos `set-env` e
/// `add-path`, que o runner aceita na saída de um passo cujo contexto `env`
/// tem o `ACTIONS_ALLOW_UNSECURE_COMMANDS` — e o contexto `env` de um passo
/// tem o `env:` dele (o `StepsRunner` e o `SetEnvCommandExtension` do
/// runner). Com essa linha no `env:` de um passo, um `echo` punha uma
/// variável — o `BASH_ENV`, o `LD_PRELOAD` — no ambiente de todo passo
/// seguinte, ou uma pasta na frente do PATH deles (o M1 do adversário do
/// lote A14). O nome entra aqui; os dois comandos, em
/// [`COMANDOS_DO_RUNNER`], nas formas que o runner lê.
const SOBREPOSICOES: [&str; 26] = [
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
    "GITHUB_ENV",
    "ACTIONS_ALLOW_UNSECURE_COMMANDS",
    ".cargo/config",
];

/// Os comandos do runner que escrevem no ambiente ou no PATH dos passos
/// seguintes, como o `GITHUB_ENV` e o `GITHUB_PATH` ([`SOBREPOSICOES`]): a
/// regra os procura nas duas formas que o runner lê na saída de um passo — a
/// `::set-env …::` e a antiga, `##[set-env …]` — e em qualquer caixa
/// ([`comando_do_runner`]), nos workflows oficiais, nas ações locais e na
/// ação do compilador.
///
/// # As formas e a caixa, desde o lote A15
///
/// O adversário do lote A14 os pôs nas sobreposições como `::set-env` e
/// `::add-path`. A fonte do runner lê também a forma antiga — o
/// `ActionCommand.TryParse`, que acha o `##[` em qualquer lugar da linha —,
/// e compara o nome do comando sem a caixa (os comandos registrados num
/// conjunto `OrdinalIgnoreCase`): `##[set-env name=BASH_ENV;]…` e
/// `::SET-ENV name=BASH_ENV::…` escapavam do texto da regra. O comando só
/// roda com o `ACTIONS_ALLOW_UNSECURE_COMMANDS` no contexto `env` do passo,
/// e esse nome, as sobreposições o recusam: esta regra é a segunda.
const COMANDOS_DO_RUNNER: [&str; 2] = ["set-env", "add-path"];

/// As ações que um workflow oficial pode usar: o checkout, o cache, a
/// publicação de artefatos e a conferência do compilador. Outra — uma que
/// instale um toolchain, por exemplo — só entra pondo-a aqui, de propósito.
const ACOES_OFICIAIS: [&str; 4] = [
    "actions/checkout",
    "actions/cache",
    "actions/upload-artifact",
    "./.github/actions/compilador",
];

/// As do canário: sem a ação do cache nem a conferência do oficial — e,
/// desde o lote A16, só nas versões de [`USOS_OFICIAIS`], como nos
/// workflows oficiais.
const ACOES_DO_CANARIO: [&str; 2] = ["actions/checkout", "actions/upload-artifact"];

/// O `uses:` inteiro — a ação com a versão — que os workflows oficiais, as
/// ações locais e, desde o lote A16, o canário usam, a lista
/// fechada ([`conferir_os_workflows`]): as de [`ACOES_OFICIAIS`] nas versões
/// de hoje. Uma versão nova entra aqui, de propósito, com a revisão.
///
/// # Por quê, desde o lote A15
///
/// A regra das ações permitidas lia o nome, sem a versão: o checkout por um
/// commit (`actions/checkout@<sha>`) passava — e o GitHub resolve o commit
/// em toda a rede de forks do repositório da ação, e não só nos ramos e nas
/// etiquetas dele: um commit que só existe num fork roda como a ação (o
/// "commit impostor", publicado em 2023). Um "pin" assim parece um reforço
/// na revisão, e roda outro código antes da conferência do compilador — o
/// checkout vem antes dela, e o `pre:` de uma ação JavaScript roda no
/// começo do job, antes de todo passo (o M4 do adversário do lote A14; o
/// efeito no GitHub não foi rodado aqui). A etiqueta da lista (`@v4`) é a do
/// próprio repositório da ação, e quem a move é o dono dele.
///
/// # O canário, desde o lote A16
///
/// O lote A15 deixou o canário de fora: ele não tem a conferência do
/// compilador, e testa outro. Mas o cache do GitHub é do repositório e do
/// ramo, e não do workflow: o canário roda no agendamento e no disparo
/// manual, que, pela documentação do GitHub, gravam no escopo do ramo
/// padrão — ou no do ramo disparado —, e os jobs da CI restauram de lá, pela
/// chave de cada um e pelo prefixo das chaves de restauração; e toda ação
/// JavaScript recebe o token do job, com que se grava no cache (o
/// `NodeScriptActionHandler` do runner). O checkout do canário por um commit
/// de um fork gravaria, com a chave de um job da CI, o `target/` ou o
/// `~/.cargo` que esse job restaura depois da conferência dele — o mesmo M4,
/// por outro workflow (o M2 do adversário do lote A15; o efeito no GitHub
/// não foi rodado aqui). As versões valem também no canário; o nome, ele
/// segue na lista dele ([`ACOES_DO_CANARIO`]).
const USOS_OFICIAIS: [&str; 4] = [
    "actions/checkout@v4",
    "actions/cache@v4",
    "actions/upload-artifact@v4",
    "./.github/actions/compilador",
];

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

/// As chaves do passo do checkout, num workflow oficial
/// ([`conferir_os_workflows`]): o `uses:` e o `name:`. Um `with:` escolhe
/// outro commit (`ref:`), outro repositório (`repository:`), outro lugar
/// (`path:`) ou o que vem com ele (`submodules:`, `lfs:`) — e a ação do
/// compilador, que é local, viria do que ele trouxe —; um `env:` muda o que
/// o `git` dele grava (`GIT_INDEX_FILE`). Desde o lote A14 (o I3 do
/// adversário do lote A13). O canário, que testa a linha oficial, não segue
/// esta regra.
const CHAVES_DO_CHECKOUT: [&str; 2] = ["uses", "name"];

/// Os nomes do `env:` de um workflow oficial, e do de um job dele — a lista
/// fechada ([`o_que_o_job_escolhe`]): a cor do terminal e o `RUST_BACKTRACE`,
/// de todo job, e os pares e os núcleos das bancadas. Eles chegam aos passos
/// da ação do compilador; um nome novo entra aqui, de propósito, com a
/// revisão. Desde o lote A14 (o I2 do adversário do lote A13).
const VARIAVEIS_DOS_JOBS: [&str; 4] = [
    "CARGO_TERM_COLOR",
    "RUST_BACKTRACE",
    "DUKE_PARES",
    "DUKE_NUCLEOS",
];

/// As chaves de cima da ação do compilador, o que o runner lê nela: o nome,
/// a descrição, as entradas, as saídas e os passos ([`forma_da_acao`]).
/// Outra — o runner aceita qualquer uma, e não a roda — reprova: os passos
/// postos nela passavam por eles (o M2 do adversário do lote A13). Desde o
/// lote A14.
const CHAVES_DA_ACAO: [&str; 5] = ["name", "description", "inputs", "outputs", "runs"];

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
        if da_definicao_da_ci(arquivo) {
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
    fora.extend(conferir_a_definicao_da_ci(&workflows));

    if fora.is_empty() {
        println!(
            "[xtask] o compilador: o canal {}, com data, nos dois rust-toolchain.toml, só com as \
             chaves do oficial, e no CLAUDE.md; nenhum outro, nenhuma troca no config do cargo nem \
             no xtask — nem um executor, nem um apelido além do oficial, e o config de cada \
             diretório de build na lista —; os workflows oficiais só com as ações permitidas, \
             conferindo o compilador depois de cada checkout, com a expressão do canal na chave \
             de todo cache, e a ação do compilador com os passos de fora do cargo — o ambiente, o \
             PATH e os rust-toolchain, o canal fixado, o executor — e o das invariantes, que o job \
             de lints liga antes de todo outro `cargo`; e o canário, o único que sobrepõe, só com \
             os gatilhos da lista no `on:` da raiz — o agendamento e o disparo manual —, sem a \
             ação do cache e com o `cache-mode: none`, com as versões da lista, publicando só a \
             pasta dos registros, e com os comandos do job de lints",
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

/// A definição da CI — `workflows`, cada `.yml` e `.yaml` de
/// `.github/workflows/` e de `.github/actions/` que o git lista, com o texto
/// ([`da_definicao_da_ci`]) — pelas regras de
/// `cargo xtask invariantes` que a leem: as dos workflows
/// ([`conferir_os_workflows`]); a da ação do compilador, que tem de estar lá
/// ([`conferir_a_acao`]); e, desde o lote A16, a da CI e a do canário, que
/// as duas regras seguintes acham pelo nome ([`workflows_que_faltam`]); a do
/// job de lints, que liga as invariantes ([`as_invariantes_na_acao`]); a do
/// canário, que repete os comandos dele ([`o_canario_repete_os_lints`]); e,
/// desde o lote A17, a do `push` no `on:` da CI ([`a_ci_nos_pushes`]).
///
/// # Uma função sem E/S, desde o lote A16
///
/// As chamadas estavam em [`conferir_o_canal`], que lê o repositório de
/// verdade e roda o cargo, e nenhum teste de unidade a chama: tirar uma
/// delas — a de [`workflows_que_faltam`], a de [`as_invariantes_na_acao`] —
/// sobrevivia aos testes, e só o `xtask invariantes` rodado numa árvore com
/// o caso a pegava (a MC7 do adversário do lote A15). Aqui, o teste
/// `adversario_a15_a_ci_e_o_canario_pelo_nome` passa a definição do
/// repositório e as trocas, e cada chamada reprova a dela.
fn conferir_a_definicao_da_ci(workflows: &[(String, String)]) -> Vec<String> {
    let mut fora = conferir_os_workflows(workflows);
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
    // A CI e o canário, que as duas regras abaixo acham pelo nome (desde o
    // lote A16).
    fora.extend(workflows_que_faltam(workflows));
    if let Some(ci) = texto_de(CI) {
        fora.extend(as_invariantes_na_acao(ci));
        // E o `push` no `on:` dela, sem filtro (desde o lote A17).
        fora.extend(a_ci_nos_pushes(ci));
    }
    if let (Some(ci), Some(canario), Some(acao)) = (texto_de(CI), texto_de(CANARIO), acao) {
        fora.extend(o_canario_repete_os_lints(ci, canario, acao));
    }
    fora
}

/// Os workflows que as regras acham pelo nome — a CI oficial, cujo job de
/// lints liga as invariantes ([`as_invariantes_na_acao`]), e o canário, que
/// repete os comandos dele ([`o_canario_repete_os_lints`]) — e que não estão
/// entre os `workflows` lidos, cada um com o erro dele.
///
/// # Por quê, desde o lote A16
///
/// As duas regras só rodavam com o arquivo achado, e nada acusava a falta
/// dele: a CI com outro nome — o `ci.yml` renomeado para `principal.yml`,
/// com o job de lints sem a entrada das invariantes — passava pelo `cargo
/// xtask invariantes`, e as invariantes deixavam de rodar na CI; e, sem o
/// canário, a paridade dele com o job de lints não se conferia (o M3 do
/// adversário do lote A15). A ação do compilador já reprovava assim.
fn workflows_que_faltam(workflows: &[(String, String)]) -> Vec<String> {
    [
        (CI, "a CI oficial, cujo job de lints liga as invariantes"),
        (CANARIO, "o canário, que repete os comandos do job de lints"),
    ]
    .into_iter()
    .filter(|(nome, _)| !workflows.iter().any(|(n, _)| n == nome))
    .map(|(nome, oque)| {
        format!(
            "{nome}: {oque}, não foi achado — as regras que o acham pelo nome não se conferem \
             noutro arquivo"
        )
    })
    .collect()
}

/// O canal citado em `texto` como ele mesmo — entre crases —, e não como
/// o começo de outro: `nightly-2026-11-15` não vale por
/// `nightly-2026-11-150`.
fn citada_no_texto(canal: &str, texto: &str) -> bool {
    texto.contains(&format!("`{canal}`"))
}

/// Se `arquivo` — um caminho do repositório — é um workflow ou uma ação de
/// `.github/`, que as regras dos workflows leem: o `.yml` ou o `.yaml` de
/// `.github/workflows/` ou de `.github/actions/`, com a extensão em
/// qualquer caixa.
///
/// # A extensão em qualquer caixa, desde o lote A16
///
/// Um workflow com a extensão em maiúsculas (`publicacao.YML`) ficava fora
/// da leitura (com o nome que o git cita, o M1 do adversário do lote A15).
/// Se o GitHub o roda, não se rodou aqui — a documentação dele só diz que
/// um workflow tem a extensão `.yml` ou `.yaml` —; o arquivo a mais que se
/// lê passa pelas regras dos workflows, e o que não passa reprova.
fn da_definicao_da_ci(arquivo: &str) -> bool {
    let minusculo = arquivo.to_ascii_lowercase();
    (arquivo.starts_with(".github/workflows/") || arquivo.starts_with(".github/actions/"))
        && (minusculo.ends_with(".yml") || minusculo.ends_with(".yaml"))
}

/// Os arquivos do repositório, versionados ou não, menos os ignorados —
/// pelo git, que já sabe o que é do repositório e o que é de build —, cada
/// um pelo caminho como ele é: a lista separada pelo NUL (`-z`).
///
/// # O caminho como ele é, desde o lote A16
///
/// Sem o `-z`, o git cita o caminho que tem um byte fora do ASCII, uma
/// aspa, uma barra invertida ou um controle (o `core.quotePath`, ligado por
/// padrão): `.github/workflows/publicação.yml` saía como
/// `".github/workflows/publica\303\247\303\243o.yml"`, que não é um arquivo
/// da árvore, e a lista o pulava em silêncio. Um workflow, ou uma ação
/// local, com um nome assim não passava por regra nenhuma dos workflows — e
/// a documentação do GitHub só pede a extensão a um workflow (o M1 do
/// adversário do lote A15; o efeito no GitHub não foi rodado aqui). O passo
/// do ambiente da ação já lia o índice com o `-z`. Um caminho que não é
/// UTF-8 reprova a lista inteira: a leitura daqui não o lê.
fn arquivos_do_repositorio(raiz: &Path) -> Result<Vec<String>, String> {
    let saida = Command::new("git")
        .current_dir(raiz)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()
        .map_err(|e| format!("o git não rodou: {e}"))?;
    if !saida.status.success() {
        return Err(format!(
            "o git ls-files falhou: {}",
            String::from_utf8_lossy(&saida.stderr).trim()
        ));
    }
    let mut arquivos = Vec::new();
    for caminho in saida.stdout.split(|&b| b == 0).filter(|c| !c.is_empty()) {
        let caminho = String::from_utf8(caminho.to_vec()).map_err(|e| {
            format!(
                "o git listou um caminho que não é UTF-8, `{}`: a leitura do repositório não o lê",
                String::from_utf8_lossy(e.as_bytes())
            )
        })?;
        if raiz.join(&caminho).is_file() {
            arquivos.push(caminho);
        }
    }
    Ok(arquivos)
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
    /// O número da linha no texto, a partir de 0, sem o BOM do começo: a
    /// linha crua, com os comentários e o recuo — desde o lote A14, o
    /// script de um passo da ação sai dela ([`passo_da_acao`]).
    numero: usize,
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
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with('#'))
        .map(|(numero, l)| {
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
                numero,
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
/// lê como quebras de linha e o `str::lines` não; o BOM (U+FEFF) fora do
/// começo do arquivo, que a libyaml pula no começo de uma linha e que a
/// leitura daqui não toma por recuo; e, desde o lote A14, os espaços que o
/// `trim` do Rust tira e o YAML guarda no valor, e os caracteres que o YAML
/// não imprime.
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
///
/// # Os espaços que o YAML não toma por espaço, desde o lote A14
///
/// A leitura tira as bordas de cada linha e de cada valor com o `trim` do
/// Rust, que tira todo espaço do Unicode; o YAML só toma por espaço o
/// espaço e o TAB, e guarda os outros no valor. `invariantes: true` com um
/// NBSP (U+00A0) no fim era `true` para a leitura e `true\u{a0}` para o
/// PyYAML e para a libyaml — e, pela fonte, para o YamlDotNet, que o runner
/// usa para ler a ação —: o `if:` do passo das invariantes, que compara a
/// entrada com `'true'`, não as rodava, com o `cargo xtask invariantes`
/// passando; o mesmo NBSP no nome da entrada, na ação, também (o M4 do
/// adversário do lote A13). Um caractere que não se vê no diff. Reprovam,
/// então, os outros espaços — o NBSP, o U+1680, os de U+2000 a U+200A, o
/// U+202F, o U+205F, o U+3000, o VT e o FF —, e os caracteres que o YAML
/// não imprime — os controles, menos o TAB, o LF e o CR, e o U+FFFE e o
/// U+FFFF —: a libyaml e o PyYAML recusam o arquivo, e o YamlDotNet 5.3.0
/// não os confere — guarda-os no valor, e acaba um comentário no NUL (o B1
/// dele). Os invisíveis que não são espaço — o ZWSP, o ZWJ, as marcas de
/// direção — o `trim` não tira: a leitura e o YAML leem o mesmo valor, com
/// eles, e um valor que as regras comparam deixa de ser o que elas esperam.
fn quebras_que_a_leitura_nao_ve(texto: &str) -> Vec<(usize, String)> {
    let mut achados = Vec::new();
    for (n, linha) in texto.split('\n').enumerate() {
        let linha = linha.strip_suffix('\r').unwrap_or(linha);
        for (i, c) in linha.char_indices() {
            let qual = match c {
                '\r' => String::from("um CR sozinho"),
                '\u{85}' => String::from("um NEL (U+0085)"),
                '\u{2028}' => String::from("um LS (U+2028)"),
                '\u{2029}' => String::from("um PS (U+2029)"),
                '\u{feff}' if n > 0 || i > 0 => {
                    String::from("um BOM (U+FEFF) fora do começo do arquivo")
                }
                '\u{feff}' | ' ' | '\t' => continue,
                c if c.is_whitespace() => format!(
                    "um espaço (U+{:04X}) que o YAML não toma por espaço",
                    u32::from(c)
                ),
                c if c.is_control() || c == '\u{fffe}' || c == '\u{ffff}' => format!(
                    "um caractere (U+{:04X}) que o YAML não imprime",
                    u32::from(c)
                ),
                _ => continue,
            };
            achados.push((n + 1, qual));
        }
    }
    achados
}

/// A chave e o valor de uma linha `chave: valor` de YAML, com o `- ` de um
/// item de lista e as aspas da chave tirados, e o valor sem o comentário do
/// fim da linha ([`sem_comentario`]). O `:` da chave é o primeiro seguido
/// de um espaço, de uma tabulação ou do fim da linha, como no YAML.
///
/// # O `:` da chave, desde o lote A14
///
/// Valia o primeiro `:` da linha, e `uses:./.github/actions/compilador` —
/// para o YAML, um escalar simples: a continuação do valor de outra chave,
/// sem espaço depois do `:` — era a chave `uses` da ação para a ordem, para
/// a contagem e para o passo que liga as invariantes no job de lints
/// ([`as_invariantes_na_acao`]) (o M3 do adversário do lote A13).
fn chave_e_valor(texto: &str) -> Option<(&str, &str)> {
    let texto = texto.strip_prefix("- ").unwrap_or(texto);
    let separa = |resto: &str| resto.chars().next().is_none_or(|d| d == ' ' || d == '\t');
    let dois_pontos = texto
        .char_indices()
        .find_map(|(i, c)| (c == ':' && separa(&texto[i + 1..])).then_some(i))?;
    let (chave, valor) = (&texto[..dois_pontos], &texto[dois_pontos + 1..]);
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
/// com o `:` seguido de um espaço, de uma tabulação ou do fim; o valor numa
/// linha — sem aspas, entre aspas que fecham nela, um bloco (`|`, `>`), ou
/// uma sequência em estilo de fluxo só de escalares simples
/// (`[x86_64, aarch64]`); e o item de uma lista com um desses. Não lê o
/// item em estilo de fluxo (`- { … }`, `- [ … ]`), a chave complexa (`?`,
/// `:`), a chave entre aspas — com um escape, ela é outra para o YAML
/// (`"u\x73es"`) —, a âncora, o apelido, a etiqueta, a fusão (`<<`), o texto
/// entre aspas em várias linhas, e o valor que começa por outro indicador
/// do YAML — também o estilo de fluxo no valor de uma chave
/// (`chave: { … }`), que a regra de antes recusava nos workflows e nas
/// outras ações, e não na do compilador.
///
/// # Por quê, desde o lote A13
///
/// As regras dos workflows leem as chaves linha a linha
/// ([`chave_e_valor`]), e pulam o que não reconhecem: o checkout escrito em
/// estilo de fluxo ou com um escape na chave — a lacuna que o lote A12
/// deixou relatada —, ou numa chave complexa — o M3 a achou maior —, não
/// pedia a conferência depois dele;
/// uma ação de fora de [`ACOES_OFICIAIS`] em estilo de fluxo — uma que
/// instala outro toolchain — passava; e um texto entre aspas em várias
/// linhas esconde dela um `#` que é do valor, ou lhe mostra um passo que o
/// YAML lê como texto. A leitura do passo da ação já falhava fechada (o lote
/// A12); esta é a mesma regra no arquivo inteiro (o M3 do adversário do lote
/// A12).
///
/// # O escape num texto entre aspas duplas, desde o lote A17
///
/// A regra recusava o escape na chave, e não no valor: num texto entre aspas
/// duplas, o YAML lê o `\n` como uma quebra de linha e o `\x52` como um `R`,
/// e a leitura por linhas lê as letras. A chave de restauração
/// `"lints-${{ steps.compilador.outputs.canal }}-\nlints-"` tinha o canal
/// para a regra das chaves de cache, e são duas para o `actions/cache` — a
/// segunda, sem o canal, restaura o cache de qualquer compilador (o B2 do
/// adversário do lote A16; o PyYAML e o Psych leem as duas). O texto entre
/// aspas duplas com uma `\`, no valor de uma chave ou num item, reprova
/// ([`escape_entre_aspas_duplas`]); o entre aspas simples, que não tem
/// escape, e o sem `\`, passam.
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
                Some(fim) if sem_comentario(corpo[fim..].trim()).is_empty() => {
                    escape_entre_aspas_duplas(corpo).then_some(ESCAPE_ENTRE_ASPAS)
                }
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
        Some(b'"' | b'\'') if fim_das_aspas(valor) != Some(valor.len()) => {
            Some("um texto entre aspas que não fecha na linha")
        }
        Some(b'"' | b'\'') => escape_entre_aspas_duplas(valor).then_some(ESCAPE_ENTRE_ASPAS),
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

/// A forma do texto entre aspas duplas com um escape
/// ([`forma_que_a_leitura_nao_le`]).
const ESCAPE_ENTRE_ASPAS: &str = "um texto entre aspas duplas com um escape (`\\`) — para o YAML, o \
     `\\n` é uma quebra de linha, e o `\\x52`, um `R`";

/// O texto entre aspas duplas do começo de `valor`, que fecha na linha, tem
/// uma `\`: o YAML a lê como o começo de um escape. Desde o lote A17.
fn escape_entre_aspas_duplas(valor: &str) -> bool {
    valor.starts_with('"') && fim_das_aspas(valor).is_some_and(|fim| valor[..fim].contains('\\'))
}

/// Os marcadores de documento do YAML de `linhas` — as de código de um
/// workflow ou de uma ação —: na coluna zero, o `---` do começo de um
/// documento e o `...` do fim, sozinhos ou seguidos de um espaço; menos o
/// `---` sozinho — com um comentário, no máximo — na primeira linha de
/// código, o começo explícito do único documento, que o YAML e a leitura
/// leem igual.
///
/// # Por quê, desde o lote A14
///
/// A leitura por linhas lia um arquivo com dois documentos como um só: o
/// `---` e o `...` eram, para ela, escalares simples. O runner recusa o
/// segundo documento, e o PyYAML também — o workflow não roda, e falha
/// fechado no GitHub —, e o `cargo xtask invariantes` passava, ou lia como
/// mais um job o que o YAML lê como outro documento (o I4 do adversário do
/// lote A13). O que a leitura não lê com certeza, reprova: um marcador fora
/// do começo, e o do começo com alguma coisa depois (`--- !!map`). Na ação
/// do compilador, a forma dela já recusa toda linha da raiz que não é uma
/// das chaves dela ([`forma_da_acao`]).
fn marcadores_de_documento<'a, 'b>(linhas: &'b [Linha<'a>]) -> Vec<&'b Linha<'a>> {
    let primeira = linhas.iter().position(|l| !l.texto.is_empty());
    linhas
        .iter()
        .enumerate()
        .filter(|(k, l)| {
            let marcador = l.recuo == 0
                && !l.escalar
                && ["---", "..."].iter().any(|m| {
                    l.texto
                        .strip_prefix(m)
                        .is_some_and(|resto| resto.is_empty() || resto.starts_with([' ', '\t']))
                });
            let o_do_comeco = Some(*k) == primeira && sem_comentario(l.texto) == "---";
            marcador && !o_do_comeco
        })
        .map(|(_, l)| l)
        .collect()
}

/// A primeira linha de código de `linhas` — as de um workflow ou de uma
/// ação —, depois do `---` sozinho do começo, se houver, quando ela não está
/// na coluna zero: a raiz do documento recuada. Nenhuma, se a raiz está na
/// coluna zero, ou se não há linha de código.
///
/// # Por quê, desde o lote A17
///
/// O YAML aceita a raiz de um documento em qualquer coluna — as chaves de
/// cima todas na coluna dois são o mesmo mapa, e o PyYAML e o Psych o leem
/// igual —, e as regras daqui leem as chaves de cima na coluna zero: o
/// canário assim, com um `push:` no `on:`, não tinha gatilho nenhum para a
/// regra dos gatilhos, e passava (a pista do revisor da rodada 9, o B1 do
/// adversário do lote A16; se o GitHub aceita a raiz recuada, não se
/// rodou). A leitura reprova a raiz fora da coluna zero, em todo workflow e
/// ação.
fn raiz_fora_da_coluna_zero<'a, 'b>(linhas: &'b [Linha<'a>]) -> Option<&'b Linha<'a>> {
    let mut codigo = linhas.iter().filter(|l| !l.texto.is_empty());
    let primeira = codigo.next()?;
    let raiz = if primeira.recuo == 0 && sem_comentario(primeira.texto) == "---" {
        codigo.next()?
    } else {
        primeira
    };
    (raiz.recuo != 0).then_some(raiz)
}

/// O valor de YAML sem as aspas que o fecham — `'compilador'` e
/// `"compilador"` são o `compilador` do GitHub —, se ele está inteiro entre
/// elas, sem escape nem outra aspa dentro; senão, o próprio valor. Desde o
/// lote A13 (o M5 do adversário do lote A12): o `id: 'compilador'` não
/// contava como o `id` nos workflows, nem o `id: 'ambiente'` achava o passo
/// na ação.
fn sem_aspas(valor: &str) -> &str {
    match valor.as_bytes().first() {
        Some(&aspa @ (b'"' | b'\''))
            if fim_das_aspas(valor) == Some(valor.len())
                && !valor[1..valor.len() - 1].contains(['\\', char::from(aspa)]) =>
        {
            &valor[1..valor.len() - 1]
        }
        _ => valor,
    }
}

/// O nome da ação de um `uses:` — sem as aspas e sem a versão.
fn nome_da_acao(valor: &str) -> &str {
    let valor = valor.trim_matches(|c| c == '"' || c == '\'');
    valor.split('@').next().unwrap_or(valor)
}

/// O comando do runner de [`COMANDOS_DO_RUNNER`] que `texto` cita — depois
/// do `::` ou do `##[`, comparado sem a caixa —, ou nenhum. A comparação é
/// pelas maiúsculas do Unicode, e não só as do ASCII: o `ſ` (U+017F) é o `S`
/// maiúsculo, e uma comparação sem a caixa pode tomá-lo pelo `s`.
fn comando_do_runner(texto: &str) -> Option<&'static str> {
    let maiusculo = texto.to_uppercase();
    COMANDOS_DO_RUNNER.iter().copied().find(|comando| {
        let comando = comando.to_uppercase();
        ["::", "##["]
            .iter()
            .any(|prefixo| maiusculo.contains(&format!("{prefixo}{comando}")))
    })
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
/// ([`abre_um_bloco`]) e cujo item vai até a linha; o fim, na primeira linha
/// de recuo igual ou menor que o do `-`; e a coluna das chaves dele, a do
/// que vem depois do `-`, na mesma linha, ou a da primeira linha de baixo.
/// Nenhum, se a linha não está num item.
///
/// # O item tem a linha, desde o lote A14
///
/// Valia o `-` mais próximo acima, de recuo menor, mesmo quando o item dele
/// já tinha acabado: o `uses:` da ação no texto do `env:` de um job, depois
/// de uma matriz, era lido como uma chave do item da matriz — e, com
/// `with: invariantes: true` nele, ligava as invariantes no job de lints,
/// que rodava sem elas (o M3 do adversário do lote A13).
fn item_da_linha(linhas: &[Linha<'_>], i: usize) -> Option<(usize, usize, Option<usize>)> {
    // O `-` do conteúdo de um bloco é texto, e não um item.
    let item = |l: &Linha<'_>| !l.escalar && (l.texto == "-" || l.texto.starts_with("- "));
    // O fim do item que começa em `j`.
    let fim_de = |j: usize| {
        (j + 1..linhas.len())
            .find(|&k| !linhas[k].texto.is_empty() && linhas[k].recuo <= linhas[j].recuo)
            .unwrap_or(linhas.len())
    };
    let comeco = (0..=i).rev().find(|&j| {
        item(&linhas[j]) && (j == i || (linhas[j].recuo < linhas[i].recuo && fim_de(j) > i))
    })?;
    let traco = &linhas[comeco];
    let fim = fim_de(comeco);
    let depois = traco.texto[1..].trim_start();
    // Um `-` só com um comentário é um `-` sozinho.
    let coluna = if sem_comentario(depois).is_empty() {
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
    if let Some(coluna) = coluna.filter(|_| !sem_comentario(depois).is_empty())
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
/// nem escape — letras, dígitos, `-` e `_` —, o `:` seguido de um espaço, de
/// uma tabulação ou do fim da linha, e o valor, sem o comentário do fim
/// ([`sem_comentario`]), vazio, entre aspas que fecham na linha, ou sem um
/// indicador de YAML no começo — a âncora (`&`), o apelido (`*`), a
/// etiqueta (`!`), o estilo de fluxo (`{`, `[`), o bloco (`|`, `>`), a
/// chave complexa (`?`) e os outros; o `-`, o `?` e o `:` só são
/// indicadores seguidos de um espaço, ou no fim, como no YAML — desde o
/// lote A13, o `name: -- o compilador --` é a forma simples.
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
        // O `-`, o `?` e o `:` só são indicadores seguidos de um espaço.
        Some(b'-' | b'?' | b':') => !matches!(valor.as_bytes().get(1), None | Some(b' ' | b'\t')),
        Some(c) => !b",[]{}#&*!|>%@`".contains(c),
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
    if let Some(coluna) = coluna.filter(|_| !sem_comentario(depois).is_empty()) {
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
/// de restauração, leva o canal. Nenhum `uses:` em várias linhas. Desde o
/// lote A14, nos oficiais, nenhum job tem `container:` — nem, desde o lote
/// A15, `services:`, e as ações permitidas só nas versões de
/// [`USOS_OFICIAIS`] —, o `env:` do workflow e o de cada job só têm os
/// nomes de [`VARIAVEIS_DOS_JOBS`] ([`o_que_o_job_escolhe`]), nenhuma linha
/// cita o `GITHUB_ENV` ([`SOBREPOSICOES`]) — nem, desde o lote A15, o
/// `ACTIONS_ALLOW_UNSECURE_COMMANDS` e os [`COMANDOS_DO_RUNNER`] —, e o
/// checkout só tem as chaves de [`CHAVES_DO_CHECKOUT`]; e, desde o lote A15,
/// os dois primeiros passos de cada job são o checkout e a ação
/// ([`o_comeco_dos_jobs`]). O lote A14 dizia que "nenhum passo escreve no
/// `GITHUB_ENV`" e que o checkout era "só o do commit": as regras liam
/// essas formas, e os comandos do runner e um passo que clona ou troca a
/// pasta da ação escapavam delas (o M1 e o M2 do adversário do lote A14).
/// Cada regra pega as formas que ela lê; o resto da definição da CI é da
/// revisão. O canário
/// sobrepõe, mas só nos gatilhos da lista dele, não usa a ação do cache —
/// e, desde o lote A17, tem o `cache-mode: none` —, nenhuma linha de código
/// dele cita o caminho da proveniência — e, desde o lote A17, a publicação
/// dele é só a pasta dos registros —, e, desde o lote A16, só usa as ações
/// dele nas versões de [`USOS_OFICIAIS`]. As ações locais seguem a leitura
/// do arquivo inteiro, abaixo,
/// e as regras dos workflows oficiais que leem o texto de cada linha — as
/// ações permitidas, as sobreposições, a escrita num `rust-toolchain` e a
/// leitura do passo que usa a ação —, e não as de um workflow: a ordem, a
/// contagem do `id`, as chaves de cache e o que o job escolhe. A que confere
/// o compilador, que cita o que recusa, segue só a leitura, e o resto é de
/// [`conferir_a_acao`].
///
/// # A leitura do arquivo inteiro, desde o lote A13
///
/// As regras leem o YAML linha a linha. Em todo arquivo — a ação do
/// compilador inclusive —, antes delas, reprova o que essa leitura não lê
/// como o YAML lê: os caracteres que o YAML toma por outra linha — e,
/// desde o lote A14, os espaços que ele não toma por espaço, e que a
/// leitura tira com as bordas, e os que ele não imprime
/// ([`quebras_que_a_leitura_nao_ve`]) — e, fora do conteúdo dos blocos, as
/// formas que ela não lê ([`forma_que_a_leitura_nao_le`]) — o estilo de
/// fluxo, a chave entre aspas ou com escape, a chave complexa, a âncora, o
/// apelido, a etiqueta, a fusão, o texto entre aspas em várias linhas — e,
/// desde o lote A14, um marcador de documento fora do começo
/// ([`marcadores_de_documento`]). Um
/// checkout, ou uma ação de fora da lista, escrito numa delas reprova por
/// ela, e não escapa mais da ordem nem da lista: antes, um checkout em
/// estilo de fluxo ou com um escape na chave não pedia a conferência depois
/// dele (o M3 do adversário do lote A12, e o E1 do revisor da rodada 5).
/// A linha que começa por `#`, a leitura a toma por comentário, também no
/// conteúdo de um bloco, onde o YAML a lê como texto: o que está nela fica
/// com a revisão (o "O que fica" do lote A15) — no passo `conferir` da ação,
/// a regra do canal lê toda linha, desde o lote A16. Desde o lote A17,
/// também a raiz do documento fora da coluna zero
/// ([`raiz_fora_da_coluna_zero`]) e, fora do conteúdo dos blocos — onde o
/// YAML não lê escape —, o texto entre aspas duplas com uma `\`
/// ([`escape_entre_aspas_duplas`]): a leitura confere os caracteres, e não
/// os escapes que o YAML lê. E os arquivos lidos são os `.yml` e os `.yaml`
/// de `.github/workflows/` e de `.github/actions/` que o git lista
/// ([`da_definicao_da_ci`]): desde o lote A16, pelo caminho como ele é.
fn conferir_os_workflows(workflows: &[(String, String)]) -> Vec<String> {
    let mut fora = Vec::new();
    for (nome, texto) in workflows {
        // Antes de toda leitura, e também na ação do compilador: o que o YAML
        // lê como outra linha, ou como outro valor, e a leitura por linhas
        // não vê.
        for (n, qual) in quebras_que_a_leitura_nao_ve(texto) {
            fora.push(format!(
                "{nome}:{n}: {qual} — o YAML lê ali uma quebra de linha, um espaço que fica no \
                 valor ou um caractere que ele não imprime, e a leitura por linhas do `xtask` não: \
                 uma chave do passo, como um `if:`, um checkout ou o valor de uma entrada, que ela \
                 lê de outro jeito"
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
        // Um documento só, também na ação do compilador (desde o lote A14).
        for l in marcadores_de_documento(&linhas) {
            fora.push(format!(
                "{nome}: `{}` — um marcador de documento do YAML: a leitura por linhas do `xtask` \
                 lê um documento só, e o runner recusa um segundo; só o `---` sozinho, na \
                 primeira linha de código, passa",
                l.texto
            ));
        }
        // A raiz na coluna zero, também na ação do compilador (desde o lote
        // A17): o YAML aceita a raiz recuada, e as regras leem as chaves de
        // cima na coluna zero.
        if let Some(l) = raiz_fora_da_coluna_zero(&linhas) {
            fora.push(format!(
                "{nome}: `{}` — a raiz do documento fora da coluna zero: o YAML a lê igual, \
                 recuada, e as regras daqui leem as chaves de cima — o `on:`, o `jobs:`, o \
                 `runs:` — na coluna zero; a raiz fica nela",
                l.texto
            ));
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
                } else if !USOS_OFICIAIS.contains(&sem_aspas(valor)) {
                    // A versão também, desde o lote A15 — e, desde o lote
                    // A16, no canário.
                    fora.push(format!(
                        "{nome}: `{}` — a versão de uma ação permitida fora da lista ({}): um \
                         commit (`@<sha>`) pode ser de um fork da rede do repositório da ação, e o \
                         checkout, ou o `pre:` de uma ação JavaScript, roda antes da conferência do \
                         compilador; e toda ação JavaScript recebe o token do job, que grava no \
                         cache que os jobs da CI restauram — também a do canário. Uma versão nova \
                         entra na lista, revisada",
                        sem_aspas(valor),
                        USOS_OFICIAIS.join(", ")
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
            fora.extend(gatilhos_fora_da_lista(nome, &linhas));
            // Sem cache nenhum, pelo token do job (desde o lote A17).
            fora.extend(o_modo_do_cache_do_canario(nome, &linhas));
            // A publicação, só a pasta dos registros (desde o lote A17).
            fora.extend(a_publicacao_do_canario(nome, &linhas));
            continue;
        }

        for l in &linhas {
            if let Some(p) = SOBREPOSICOES.iter().find(|p| l.texto.contains(*p)) {
                fora.push(format!(
                    "{nome}: `{}` — `{p}` sobrepõe o compilador do {TOOLCHAIN_DA_RAIZ}",
                    l.texto
                ));
            }
            // Os comandos do runner, nas formas que ele lê (desde o lote A15).
            if let Some(c) = comando_do_runner(l.texto) {
                fora.push(format!(
                    "{nome}: `{}` — o comando `{c}` do runner (`::{c}`, `##[{c}`, em qualquer \
                     caixa) escreve, como o `GITHUB_ENV` e o `GITHUB_PATH`, no ambiente ou no PATH \
                     dos passos seguintes",
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
        let mut sem_o_id = 0;
        for (i, _) in linhas
            .iter()
            .enumerate()
            .filter(|(_, l)| usa_a_acao_do_compilador(l))
        {
            let chaves = chaves_do_item(&linhas, i);
            for c in &chaves {
                if CHAVES_FORA_DO_PASSO_DA_ACAO.contains(&c.chave) {
                    fora.push(format!(
                        "{nome}: `{}: {}` no passo da conferência do compilador — com um `if:`, \
                         ela pode não rodar, e o job segue sem ela; com um `continue-on-error:`, \
                         o job segue com ela reprovada",
                        c.chave, c.valor
                    ));
                }
            }
            if !chaves
                .iter()
                .any(|c| c.chave == "id" && sem_aspas(c.valor) == "compilador")
            {
                sem_o_id += 1;
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
        // O `id: compilador` no próprio passo da ação (desde o lote A16): a
        // chave de cache lê o canal de `steps.compilador`, e a contagem de
        // baixo aceitava o `id` noutro passo.
        for _ in 0..sem_o_id {
            fora.push(format!(
                "{nome}: o passo da conferência do compilador sem o `id: compilador` — a chave de \
                 todo cache lê o canal de `steps.compilador`: com o `id` noutro passo, ela leva a \
                 saída dele, e não o canal que a ação conferiu"
            ));
        }

        // O que o job escolhe para os passos da ação (desde o lote A14): o
        // `container:`, os `services:` (desde o lote A15) e o `env:` do
        // workflow e o dos jobs fora da lista fechada reprovam.
        fora.extend(o_que_o_job_escolhe(nome, &linhas));
        // Os dois primeiros passos de cada job são o checkout e a ação (desde
        // o lote A15): nenhum outro passo do job roda antes dela.
        fora.extend(o_comeco_dos_jobs(nome, &linhas));

        let mut pendente = false;
        for (i, l) in linhas.iter().enumerate() {
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
                    for c in chaves_do_item(&linhas, i) {
                        if !CHAVES_DO_CHECKOUT.contains(&c.chave) {
                            fora.push(format!(
                                "{nome}: `{}: {}` no checkout — o checkout dos workflows \
                                 oficiais só tem o `uses:` e o `name:`: um `with:` escolhe outro \
                                 commit (`ref:`), outro repositório ou outro lugar, e a ação do \
                                 compilador, que é local, viria dele; um `env:` muda o que o \
                                 `git` dele grava",
                                c.chave, c.valor
                            ));
                        }
                    }
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
            .filter(|l| {
                chave_e_valor(l.texto)
                    .is_some_and(|(chave, valor)| chave == "id" && sem_aspas(valor) == "compilador")
            })
            .count();
        if usos != ids {
            fora.push(format!(
                "{nome}: {usos} conferência(s) do compilador e {ids} `id: compilador` — a chave do \
                 cache lê o canal de `steps.compilador`"
            ));
        }
        // A expressão do canal na chave (desde o lote A16:
        // `${{ 'steps.compilador.outputs.canal' }}` é um texto fixo) — até o
        // lote A17, pelo texto contido na linha; desde ele, entre as
        // expressões que o leitor de modelos do GitHub acha no valor que o
        // YAML lê ([`o_canal_numa_expressao`]), comparada pelo texto, na
        // forma canônica.
        for chave in chaves_de_cache(&linhas) {
            if !o_canal_numa_expressao(&chave) {
                fora.push(format!(
                    "{nome}: a chave de cache `{chave}` não leva o canal do compilador \
                     (`{CANAL_NA_CHAVE}`)"
                ));
            }
        }
    }
    fora
}

/// O que um workflow oficial — `nome`, e `linhas`, as de código dele —
/// escolhe para os passos de um job, e que a ação do compilador não
/// confere: o `container:` de um job, que roda os passos dele numa imagem
/// que o workflow escolhe, os `services:` (desde o lote A15), e o `env:` do
/// workflow e o de cada job, que só têm os nomes de uma lista fechada
/// ([`VARIAVEIS_DOS_JOBS`]) — os três chegam aos passos da ação, que roda
/// com o ambiente do job. O `env:` de um passo — de um item de lista — a
/// regra não lê: ele vale no passo, e o do passo da ação, a leitura dele já
/// recusa ([`linhas_que_o_passo_nao_le`]). O lote A14 dizia que ele "só
/// vale nele", e os comandos do runner que o `ACTIONS_ALLOW_UNSECURE_COMMANDS`
/// dele ligava o levavam aos passos seguintes; desde o lote A15, as
/// sobreposições recusam esse nome e os comandos ([`COMANDOS_DO_RUNNER`]),
/// e o nome montado em pedaços — numa expressão do `env:` de um passo, num
/// `run:` que escreve no `GITHUB_ENV` — fica com a revisão.
///
/// # Por quê, desde o lote A14
///
/// A ação confere o ambiente do job por uma lista fechada dos nomes que o
/// cargo, o rustc e o rustup leem, e não os dos outros programas que o job
/// roda: o carregador (`LD_PRELOAD`), que roda o código dele dentro de todo
/// programa, o `python3` da ação inclusive, antes de qualquer conferência;
/// o compilador de C do `build.rs` do `ring` (`CC`, `CFLAGS`), cujos objetos
/// entram no binário do `xtask` das invariantes — num experimento, o build
/// do `ring` rodou 36 vezes o programa do `CC`; o `git` da ação
/// (`GIT_INDEX_FILE`, e o `HOME`, que escolhe a configuração dele); e o
/// `bash` dos passos dela (`BASH_ENV`, que o `bash` do runner lê antes do
/// script — num experimento, ele trocou o `cargo` por uma função, e o passo
/// saiu com 0). E o `container:` troca todos de uma vez: a ação rodaria com
/// o `python3`, o `git` e o `rustup` da imagem. Uma linha no `env:` ou no
/// job bastava, e o `cargo xtask invariantes` passava (o I1 e o I2 do
/// adversário do lote A13; o `HOME` e o `BASH_ENV`, o lote A14 os achou na
/// revisão). Num job assim a ação pode não acusar nada — o carregador e o
/// `bash` mentem para ela —, e quem acusa é o `cargo xtask invariantes` de
/// fora dele: o local e o do canário.
///
/// # Os serviços, desde o lote A15
///
/// Os `services:` de um job ficavam de fora — "um serviço roda ao lado, e
/// não os passos do job" —, e o runner os sobe no "Initialize containers",
/// antes do primeiro passo, cada um numa imagem que o workflow escolhe, com
/// o `volumes:` montado do runner e o `options:` passado cru ao `docker
/// create` (o `ContainerOperationProvider` e o `DockerCommandManager` do
/// runner): um serviço com o `/usr/bin` ou o `~/.cargo` montado escreve no
/// `python3`, no `git` ou nos proxies do rustup antes de a ação rodar, e
/// passava (o M3 do adversário do lote A14). Reprova como o `container:`,
/// também sem nada montado — a regra não lê o `volumes:` nem o `options:`,
/// que mudam de forma —; o repositório não tem nenhum.
fn o_que_o_job_escolhe(nome: &str, linhas: &[Linha<'_>]) -> Vec<String> {
    let mut fora = Vec::new();
    for (i, l) in linhas.iter().enumerate() {
        if l.escalar {
            continue;
        }
        let Some((chave, valor)) = chave_e_valor(l.texto) else {
            continue;
        };
        if chave == "container" {
            fora.push(format!(
                "{nome}: `{}` — o `container:` de um job roda os passos dele numa imagem que o \
                 workflow escolhe: a ação do compilador rodaria com o `python3`, o `git` e o \
                 `rustup` dela",
                l.texto
            ));
        }
        if chave == "services" {
            fora.push(format!(
                "{nome}: `{}` — os `services:` de um job sobem antes do primeiro passo dele, cada \
                 um numa imagem que o workflow escolhe, e o `volumes:` e o `options:` montam nela \
                 as pastas do runner: o serviço escreveria no `python3`, no `git` e no `rustup` da \
                 ação antes de ela rodar",
                l.texto
            ));
        }
        // O `env:` do workflow, ou o de um job: fora de um item de lista.
        if chave != "env" || item_da_linha(linhas, i).is_some() {
            continue;
        }
        if !valor.is_empty() {
            fora.push(format!(
                "{nome}: `{}` — o `env:` do workflow, ou o de um job, com o valor na linha, que a \
                 leitura não lê: os nomes dele são uma lista fechada",
                l.texto
            ));
            continue;
        }
        // As linhas de dentro: cada uma, uma chave da lista, na coluna da
        // primeira; o conteúdo de um bloco é o valor de uma delas.
        let dentro = linhas[i + 1..]
            .iter()
            .filter(|d| !d.escalar && !d.texto.is_empty())
            .take_while(|d| d.recuo > l.recuo);
        let mut coluna = None;
        for d in dentro {
            let na_coluna = *coluna.get_or_insert(d.recuo) == d.recuo;
            match chave_e_valor(d.texto) {
                Some((c, _)) if na_coluna && VARIAVEIS_DOS_JOBS.contains(&c) => {}
                Some(_) if na_coluna => fora.push(format!(
                    "{nome}: `{}` no `env:` do workflow, ou no de um job — fora da lista ({}): \
                     o ambiente do job chega aos passos da ação do compilador, e uma variável de \
                     fora dela escolhe o programa que roda neles — o carregador (`LD_PRELOAD`), o \
                     compilador de C dos `build.rs` (`CC`), a configuração do `git` (`HOME`), o \
                     `bash` (`BASH_ENV`); uma nova entra na lista, revisada",
                    d.texto,
                    VARIAVEIS_DOS_JOBS.join(", ")
                )),
                _ => fora.push(format!(
                    "{nome}: `{}` no `env:` do workflow, ou no de um job, que não é uma chave na \
                     coluna das dele — a leitura não a lê, e os nomes dele são uma lista fechada",
                    d.texto
                )),
            }
        }
    }
    fora
}

/// Os jobs de um workflow oficial — `nome`, e `linhas`, as de código dele —
/// começam pelo checkout e pela conferência do compilador: os dois
/// primeiros itens do `steps:` de cada um ([`passos_do_job`]) são o
/// `actions/checkout` e a ação `./.github/actions/compilador`. Um workflow
/// sem o `jobs:` em bloco, ou com um job sem os dois, reprova.
///
/// # Por quê, desde o lote A15
///
/// A ordem ([`conferir_os_workflows`]) começava no primeiro checkout, e só
/// recusava, entre ele e a ação, o cache e uma linha com o `cargo`. Passavam,
/// e escolhiam o programa que a ação roda, o commit dela ou o que ela
/// confere — ou a dispensavam —: um passo antes do checkout — o cache que
/// restaura o `~/.rustup`, fora da árvore, que o checkout não apaga, com o
/// canal da chave ainda vazio; um `run:` que troca o `/usr/bin/python3` —;
/// um entre o checkout e a ação — o `git checkout` da pasta da ação de
/// outro commit, um toolchain com o nome do oficial no `~/.rustup`, o
/// `core.fsmonitor` no `.git/config`, que o `git` dela ainda lê, um script
/// do repositório —; e um job sem o `actions/checkout`, que clona o
/// repositório e roda o `cargo` sem a ação (o M2 do adversário do lote
/// A14). Os jobs da CI já começavam assim, e a regra tira do job todo passo
/// antes da ação — a classe que o texto dava como da revisão —; um job sem
/// código — sem o checkout — pede a regra revisada.
///
/// # A sequência compacta, desde o lote A16
///
/// Os itens do `steps:` na coluna da própria chave são o mesmo YAML, e a
/// leitura não os toma por passos ([`passos_do_job`]): o job assim reprova
/// aqui — e, no de lints, também pela regra das invariantes e pela paridade
/// do canário —, sem defeito (o FP1 do adversário do lote A15). É um falso
/// positivo de propósito, que falha fechado: nenhum workflow de hoje usa a
/// forma, e lê-la pede mudar as leituras dos passos; a mensagem a diz.
fn o_comeco_dos_jobs(nome: &str, linhas: &[Linha<'_>]) -> Vec<String> {
    let Some(jobs) = linhas
        .iter()
        .position(|l| !l.escalar && l.recuo == 0 && chave_e_valor(l.texto) == Some(("jobs", "")))
    else {
        return vec![format!(
            "{nome}: sem o `jobs:` em bloco, que a leitura lê — os jobs dos workflows oficiais \
             começam pelo checkout e pela conferência do compilador"
        )];
    };
    // Os jobs: as chaves do `jobs:`, na coluna da primeira linha de dentro,
    // até a próxima chave da raiz.
    let fim_dos_jobs = (jobs + 1..linhas.len())
        .find(|&k| !linhas[k].escalar && !linhas[k].texto.is_empty() && linhas[k].recuo == 0)
        .unwrap_or(linhas.len());
    let dentro: Vec<usize> = (jobs + 1..fim_dos_jobs)
        .filter(|&k| !linhas[k].escalar && !linhas[k].texto.is_empty())
        .collect();
    let Some(coluna) = dentro.first().map(|&k| linhas[k].recuo) else {
        return Vec::new();
    };
    let comecos: Vec<usize> = dentro
        .into_iter()
        .filter(|&k| linhas[k].recuo == coluna)
        .collect();
    let mut fora = Vec::new();
    for (n, &comeco) in comecos.iter().enumerate() {
        let job = &linhas[comeco..comecos.get(n + 1).copied().unwrap_or(fim_dos_jobs)];
        let passos = passos_do_job(job);
        // A ação que o passo `p` usa: o `uses:` dele, sem a versão.
        let usa = |p: Option<&usize>| {
            p.and_then(|&p| {
                chaves_do_item(job, p)
                    .into_iter()
                    .find(|c| c.chave == "uses")
                    .map(|c| nome_da_acao(c.valor))
            })
        };
        if usa(passos.first()) != Some("actions/checkout")
            || usa(passos.get(1)) != Some("./.github/actions/compilador")
        {
            fora.push(format!(
                "{nome}: o job `{}` não começa pelo checkout e pela conferência do compilador — os \
                 dois primeiros passos de um job oficial são o `actions/checkout` e a ação \
                 `./.github/actions/compilador`: um passo antes dela — um cache do `~/.rustup`, um \
                 `run:` — escolhe o programa que ela roda, o commit dela ou o que ela confere, e \
                 um job sem o checkout roda sem ela. Ou os passos do job numa forma que a leitura \
                 não lê: os itens do `steps:` na coluna da própria chave (a sequência compacta do \
                 YAML), que ela não toma por passos — recue-os",
                chave_e_valor(linhas[comeco].texto).map_or(linhas[comeco].texto, |(c, _)| c)
            ));
        }
    }
    fora
}

/// O canal do compilador numa chave de cache: a expressão com a saída da
/// ação, como os workflows a escrevem ([`conferir_os_workflows`]).
///
/// # A expressão, e não o texto, desde o lote A16
///
/// A regra procurava o texto `steps.compilador.outputs.canal` na chave, e
/// `${{ 'steps.compilador.outputs.canal' }}` — uma expressão que vale o
/// próprio texto — passava: a chave levava um texto fixo, e não o canal, e
/// um cache de outro compilador se restaurava pelo prefixo (o B2 do
/// adversário do lote A15). O comentário com o texto já não valia (o lote
/// A12). Outra grafia da mesma expressão — sem um espaço, com a indexação
/// (`outputs['canal']`), com um padrão (`|| 'x'`) — reprova, com a forma na
/// mensagem: a comparação é a do texto, na forma canônica
/// ([`o_canal_numa_expressao`]).
///
/// # O `id` no passo da ação, desde o lote A16
///
/// A expressão lê o canal de `steps.compilador`, e a regra contava as
/// conferências e os `id: compilador` do workflow, sem os ligar: a ação sem
/// o `id`, e um passo depois dela com `id: compilador` que escreve outro
/// canal na saída dele, passavam — a chave levava o canal desse passo (o
/// lote A16 o achou na revisão do patch do adversário). O passo que usa a
/// ação tem o `id` ([`conferir_os_workflows`]); e o GitHub não aceita dois
/// passos com o mesmo `id` num job.
const CANAL_NA_CHAVE: &str = "${{ steps.compilador.outputs.canal }}";

/// Uma das expressões de `chave` — o valor que o YAML lê
/// ([`chaves_de_cache`]) — é [`CANAL_NA_CHAVE`], com as expressões achadas
/// como o leitor de modelos do GitHub as acha: do `${{` ao primeiro `}}` fora
/// de um texto entre aspas simples (o `TemplateReader` do runner, que alterna
/// as aspas a cada `'` — o `''` de dentro de um texto, duas vezes).
///
/// # Por quê, desde o lote A17
///
/// A regra procurava o texto da expressão na chave, e
/// `${{ '${{ steps.compilador.outputs.canal }}' }}` o tem: é uma expressão
/// só, um literal que vale o próprio texto — a chave levava um texto fixo,
/// como no B2 do adversário do lote A15 (o B3 do adversário do lote A16; o
/// efeito no GitHub vem da fonte do runner, e não de um run). E o leitor
/// acha as expressões no valor que o YAML lê: num texto entre aspas
/// simples, o `''` é uma aspa só, que o leitor alterna uma vez e a linha
/// crua, duas — `'${{ ''}}${{ steps.compilador.outputs.canal }}'' }}'` tinha
/// a expressão do canal para a leitura da linha, e um literal para o leitor
/// (o lote A17 o achou na revisão do patch do adversário).
///
/// # A forma canônica, de propósito
///
/// A expressão achada se compara com [`CANAL_NA_CHAVE`] pelo texto, letra a
/// letra. Outra grafia que o GitHub avalia igual — a sem o espaço antes do
/// `}}`, a da indexação (`steps.compilador.outputs['canal']`) — reprova, e
/// falha fechada: a mensagem mostra a forma exigida, os workflows a usam em
/// toda chave, e normalizar a expressão alargaria um comparador da guarda
/// pelo ganho de conveniência (o F1 do adversário da rodada 10, dito desde o
/// lote A18; a regra não mudou).
fn o_canal_numa_expressao(chave: &str) -> bool {
    let mut resto = chave;
    while let Some(i) = resto.find("${{") {
        let depois = &resto[i + 3..];
        let b = depois.as_bytes();
        let mut aspas = false;
        let mut fim = None;
        for j in 0..b.len() {
            if b[j] == b'\'' {
                aspas = !aspas;
            } else if !aspas && j > 0 && b[j] == b'}' && b[j - 1] == b'}' {
                fim = Some(j);
                break;
            }
        }
        let Some(fim) = fim else {
            return false;
        };
        if format!("${{{{{}}}}}", &depois[..fim - 1]) == CANAL_NA_CHAVE {
            return true;
        }
        resto = &depois[fim + 1..];
    }
    false
}

/// O valor de YAML de uma linha — `valor`, sem o comentário — como o YAML o
/// lê: o texto entre aspas simples que fecha no fim, sem elas e com o `''`
/// de dentro como uma aspa; o entre aspas duplas, sem elas — com uma `\`, a
/// leitura já o recusa ([`escape_entre_aspas_duplas`]) —; e o resto, como
/// está. Desde o lote A17 ([`o_canal_numa_expressao`]).
fn valor_do_yaml(valor: &str) -> std::borrow::Cow<'_, str> {
    match valor.as_bytes().first() {
        Some(b'\'') if fim_das_aspas(valor) == Some(valor.len()) && valor.len() >= 2 => {
            std::borrow::Cow::Owned(valor[1..valor.len() - 1].replace("''", "'"))
        }
        Some(b'"') if fim_das_aspas(valor) == Some(valor.len()) && valor.len() >= 2 => {
            std::borrow::Cow::Borrowed(&valor[1..valor.len() - 1])
        }
        _ => std::borrow::Cow::Borrowed(valor),
    }
}

/// As chaves de cache de um workflow: as de `key:` e as de `restore-keys:`,
/// numa linha — o valor como o YAML o lê ([`valor_do_yaml`], desde o lote
/// A17) — ou num bloco `|` — as linhas mais recuadas que a chave, mesmo
/// depois de uma vazia.
fn chaves_de_cache<'a>(linhas: &[Linha<'a>]) -> Vec<std::borrow::Cow<'a, str>> {
    let mut chaves = Vec::new();
    let mut bloco: Option<usize> = None;
    for l in linhas {
        if let Some(recuo) = bloco {
            if l.texto.is_empty() {
                continue;
            }
            if l.recuo > recuo {
                chaves.push(std::borrow::Cow::Borrowed(l.texto));
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
                chaves.push(valor_do_yaml(valor));
            }
        }
    }
    chaves
}

/// A forma da ação do compilador — `linhas`, as de código dela —, fora do
/// conteúdo dos blocos: as chaves de cima, as de [`CHAVES_DA_ACAO`], cada
/// uma uma vez; a entrada `invariantes`, só ela, com a descrição, o
/// `required` e o `default`; a saída `canal`, só ela, com a descrição e o
/// valor do passo `conferir`; e o `runs:` com `using: composite` e os
/// `steps:` — os passos de [`PASSOS_DA_ACAO`], na ordem, e só eles. Devolve
/// o que não confere e, de cada item de `runs.steps`, o `id` e a linha dele.
///
/// # Por quê, desde o lote A14
///
/// [`conferir_a_acao`] achava cada passo pela primeira linha `id:` do
/// arquivo, onde quer que ela estivesse, e não conferia o resto: os quatro
/// passos numa chave a mais da raiz — que o runner aceita e não roda —,
/// com o `runs.steps` de outro passo, ou com o `runs.using` de um programa
/// em JavaScript; um quinto passo, entre o do executor e o das invariantes;
/// e o `outputs.canal` com um valor fixo, que tira o compilador da chave de
/// todo cache, passavam pelo `cargo xtask invariantes` (o M2 do adversário
/// do lote A13). A ação continua a raiz da confiança: o script de um passo,
/// com a revisão.
fn forma_da_acao(linhas: &[Linha<'_>]) -> (Vec<String>, Vec<(String, usize)>) {
    /// As linhas de dentro do valor da chave da linha `k` — ou do arquivo,
    /// sem ela —: as de código, fora do conteúdo dos blocos, mais recuadas
    /// que ela, até a primeira que não é; e, delas, as da coluna da
    /// primeira, cada uma com a chave e o valor — nenhum, se não é uma
    /// chave.
    fn filhos<'a>(
        linhas: &[Linha<'a>],
        k: Option<usize>,
    ) -> Vec<(usize, Option<(&'a str, &'a str)>)> {
        let dentro: Vec<usize> = (k.map_or(0, |k| k + 1)..linhas.len())
            .filter(|&j| !linhas[j].escalar && !linhas[j].texto.is_empty())
            .take_while(|&j| k.is_none_or(|k| linhas[j].recuo > linhas[k].recuo))
            .collect();
        let Some(coluna) = dentro.first().map(|&j| linhas[j].recuo) else {
            return Vec::new();
        };
        dentro
            .into_iter()
            .filter(|&j| linhas[j].recuo == coluna)
            .map(|j| (j, chave_e_valor(linhas[j].texto)))
            .collect()
    }
    /// As chaves de dentro de `k`, que são exatamente as `esperadas`, cada
    /// uma uma vez — ou o erro em `fora`, com `onde` —, com a linha e o valor
    /// de cada uma.
    fn exatas<'a>(
        linhas: &[Linha<'a>],
        k: Option<usize>,
        onde: &str,
        esperadas: &[&str],
        fora: &mut Vec<String>,
    ) -> Vec<(usize, &'a str, &'a str)> {
        let mut chaves = Vec::new();
        for (j, chave) in filhos(linhas, k) {
            match chave {
                Some((c, v)) => chaves.push((j, c, v)),
                None => fora.push(format!(
                    "{ACAO_DO_COMPILADOR}: `{}` em {onde}, que a forma da ação não lê",
                    linhas[j].texto
                )),
            }
        }
        let mut nomes: Vec<&str> = chaves.iter().map(|&(_, c, _)| c).collect();
        nomes.sort_unstable();
        let mut certas = esperadas.to_vec();
        certas.sort_unstable();
        if nomes != certas {
            fora.push(format!(
                "{ACAO_DO_COMPILADOR}: {onde} tem as chaves {nomes:?}, e não {certas:?} — o \
                 runner leria a ação de outra forma que a das regras daqui"
            ));
        }
        chaves
    }
    let mut fora = Vec::new();
    let mut passos = Vec::new();
    let topo = exatas(linhas, None, "a raiz", &CHAVES_DA_ACAO, &mut fora);
    let de = |nome: &str| {
        topo.iter()
            .find(|&&(_, c, _)| c == nome)
            .map(|&(j, _, _)| j)
    };
    if let Some(k) = de("inputs") {
        for (j, _, _) in exatas(linhas, Some(k), "`inputs`", &["invariantes"], &mut fora) {
            let esperadas = ["description", "required", "default"];
            exatas(
                linhas,
                Some(j),
                "`inputs.invariantes`",
                &esperadas,
                &mut fora,
            );
        }
    }
    if let Some(k) = de("outputs") {
        for (j, _, _) in exatas(linhas, Some(k), "`outputs`", &["canal"], &mut fora) {
            let esperadas = ["description", "value"];
            for (_, c, v) in exatas(linhas, Some(j), "`outputs.canal`", &esperadas, &mut fora) {
                if c == "value" && sem_aspas(v) != "${{ steps.conferir.outputs.canal }}" {
                    fora.push(format!(
                        "{ACAO_DO_COMPILADOR}: `outputs.canal` vale `{v}`, e não o canal do \
                         passo `conferir` (`${{{{ steps.conferir.outputs.canal }}}}`): a chave de \
                         todo cache leva o canal do compilador que a encheu"
                    ));
                }
            }
        }
    }
    if let Some(k) = de("runs") {
        for (j, c, v) in exatas(linhas, Some(k), "`runs`", &["using", "steps"], &mut fora) {
            if c == "using" && sem_aspas(v) != "composite" {
                fora.push(format!(
                    "{ACAO_DO_COMPILADOR}: `runs.using` é `{v}`, e não `composite`: o runner \
                     rodaria outro programa no lugar dos passos"
                ));
            }
            if c != "steps" {
                continue;
            }
            for (item, _) in filhos(linhas, Some(j)) {
                let l = &linhas[item];
                let id = (l.texto == "-" || l.texto.starts_with("- "))
                    .then(|| chaves_do_item(linhas, item))
                    .and_then(|chaves| chaves.into_iter().find(|c| c.chave == "id"));
                match id {
                    Some(c) => passos.push((sem_aspas(c.valor).to_string(), c.linha)),
                    None => fora.push(format!(
                        "{ACAO_DO_COMPILADOR}: `{}` em `runs.steps`, que não é um passo com \
                         `id:`",
                        l.texto
                    )),
                }
            }
        }
    }
    let ids: Vec<&str> = passos.iter().map(|(id, _)| id.as_str()).collect();
    let esperados = PASSOS_DA_ACAO.map(|(id, _, _)| id);
    if ids != esperados {
        fora.push(format!(
            "{ACAO_DO_COMPILADOR}: os passos de `runs.steps` são {ids:?}, e não {esperados:?}: \
             um passo a mais, ou noutro lugar, faz o que nenhuma regra daqui lê"
        ));
    }
    (fora, passos)
}

/// A ação do compilador — `texto`, o [`ACAO_DO_COMPILADOR`] — tem a forma
/// que o runner lê como a ação — desde o lote A14 ([`forma_da_acao`]): as
/// chaves de cima, a entrada, o `outputs.canal` do passo `conferir`, o
/// `runs.using: composite` e o `runs.steps` só com os passos daqui — e os
/// passos de [`PASSOS_DA_ACAO`], na ordem — cada um, desde o lote A14, o
/// item de `runs.steps` com o `id` dele, e não o texto de um bloco —, cada
/// um com o `shell:` dele, só com as
/// chaves que a leitura lê nele ([`linhas_que_o_passo_da_acao_nao_le`],
/// desde o lote A13) e com cada marca dele numa linha de código do script;
/// nos dois em Python, a tupla
/// `DIRETORIOS` com cada diretório de build do `xtask` como um item
/// ([`DIRETORIOS_DOS_BUILDS`]); no do executor, as formas dos rustflags de
/// [`FORMAS_DOS_RUSTFLAGS`] e as tabelas de [`TABELAS_DO_CONFIG`]; a entrada
/// `invariantes`, e o passo das invariantes só com ela, no toolchain fixado
/// pelo canal; e nenhuma linha de código dela — fora as de comentário, que
/// os citam — cita o `GITHUB_ENV` nem o `GITHUB_PATH` — nem, desde o lote
/// A15, os comandos de [`COMANDOS_DO_RUNNER`], nas formas que o runner lê
/// ([`comando_do_runner`]) —, que escrevem no ambiente dos passos
/// seguintes, e que nenhuma regra dos workflows lê nela.
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
    let linhas = linhas_de_codigo(texto);
    // Desde o lote A14: a forma da ação, e cada passo, o item de
    // `runs.steps` com o `id` dele — e não a primeira linha `id:` do
    // arquivo, que podia ser o texto de um bloco ([`forma_da_acao`]).
    let (mut fora, passos) = forma_da_acao(&linhas);
    let posicao = |id: &str| passos.iter().find(|(p, _)| p == id).map(|&(_, k)| k);
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
        // O canal que o passo `conferir` escreve é o que ele lê (desde o lote
        // A15): a marca da saída prova que a linha existe, e não o valor.
        if id == "conferir" {
            fora.extend(o_canal_do_passo_conferir(&script));
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
    // A entrada das invariantes, e o passo só com ela, no toolchain fixado —
    // desde o lote A14, pelas chaves do passo, e não por uma linha qualquer
    // do texto dele, que podia ser a do script.
    let entrada = linhas.windows(2).any(|par| {
        !par[0].escalar
            && par[0].recuo == 0
            && chave_e_valor(par[0].texto) == Some(("inputs", ""))
            && chave_e_valor(par[1].texto) == Some(("invariantes", ""))
    });
    let do_passo = posicao("invariantes")
        .map(|k| chaves_do_item(&linhas, k))
        .unwrap_or_default();
    let so_com_a_entrada = do_passo
        .iter()
        .any(|c| c.chave == "if" && c.valor == "inputs.invariantes == 'true'");
    let no_canal_fixado = do_passo
        .iter()
        .filter(|c| c.chave == "env")
        .flat_map(|c| chaves_de_dentro(&linhas, c))
        .any(|c| c.chave == "RUSTUP_TOOLCHAIN" && c.valor == "${{ steps.conferir.outputs.canal }}");
    if !entrada || !so_com_a_entrada || !no_canal_fixado {
        fora.push(format!(
            "{ACAO_DO_COMPILADOR}: a entrada `invariantes`, logo no começo das `inputs:`, e o passo \
             `invariantes` só com ela (`if: inputs.invariantes == 'true'`) e no toolchain fixado \
             (`RUSTUP_TOOLCHAIN: ${{{{ steps.conferir.outputs.canal }}}}`): o job de lints roda as \
             invariantes ali, antes de todo outro `cargo`"
        ));
    }
    for l in &linhas {
        // Desde o lote A15, também os comandos do runner que escrevem nele,
        // nas formas que ele lê ([`comando_do_runner`]).
        if l.texto.contains("GITHUB_ENV")
            || l.texto.contains("GITHUB_PATH")
            || comando_do_runner(l.texto).is_some()
        {
            fora.push(format!(
                "{ACAO_DO_COMPILADOR}: `{}` — a ação do compilador não cita o `GITHUB_ENV`, o \
                 `GITHUB_PATH` nem os comandos `set-env` e `add-path` do runner, que escrevem no \
                 ambiente dos passos seguintes",
                l.texto
            ));
        }
    }
    fora
}

/// A regra do canal do passo `conferir` da ação do compilador — `script`, o
/// dele ([`passo_da_acao`]) —, pelo texto das linhas do script: as duas
/// primeiras de código são o `set -euo pipefail` e a que lê o canal do
/// `rust-toolchain.toml` ([`LEITURA_DO_CANAL`]), e esta aparece uma vez só;
/// o nome `canal`, fora da expansão (`$canal`, `${canal}`), só aparece
/// nela e na que escreve a saída ([`SAIDA_DO_CANAL`]) ([`cita_o_nome`]); o
/// `GITHUB_OUTPUT` aparece uma vez, nesta, que é a última linha do script;
/// e nenhuma linha define uma função ou um apelido, nem tem o `enable`
/// ([`troca_um_comando`]). Desde o lote A16, as três últimas partes leem
/// também as linhas de comentário.
///
/// # Por quê, desde o lote A15
///
/// A marca do `echo` da saída (o lote A14) prova que a linha existe, e não
/// o valor que ela escreve: `canal=nightly-2000-01-01` numa linha antes
/// dela, ou um segundo `echo` depois, que vence o primeiro, punham na chave
/// de todo cache um canal que não é o do compilador que a encheu, e o
/// `cargo xtask invariantes` passava (o B1 do adversário do lote A14).
///
/// # A linha da leitura uma vez, as linhas de comentário e as funções, desde o lote A16
///
/// A regra do lote A15 conferia pela posição só as duas primeiras linhas de
/// código, e as outras pelo texto: uma cópia exata da linha da leitura, mais
/// abaixo — depois de uma função `python3`, de um `PATH` ou de um `cd` —,
/// passava, e o valor da saída era o dessa cópia (o E1 do revisor da rodada
/// 8). E ela tirava as linhas que começam por `#`, que, num texto entre aspas
/// em várias linhas ou num heredoc, o bash roda: `: "` e, embaixo,
/// `#"; canal=nightly-2000-01-01; : "` davam outro valor ao nome, e
/// `#$(echo canal=… >> "$GITHUB_OUTPUT")"` escrevia a saída de novo — com a
/// ação rodada como o runner, o canal falso chegou à saída do passo (o B1 do
/// adversário do lote A15). A regra não sabe onde um texto começa: lê toda
/// linha, e o comentário do passo não cita o nome nem o `GITHUB_OUTPUT`
/// (o `$canal` passa). E uma função `echo` — ou um apelido, ou o `enable -n
/// echo` com outro `echo` no PATH — trocava, sem citar o nome, o que a linha
/// da saída escreve.
///
/// # O que ela não segue
///
/// Pelo texto, a regra não segue o nome montado em pedaços, o texto
/// executado (o `eval`, o `source` e o `.`, outro `bash` sobre o script) nem
/// o caminho do script: um `exit`, um `exec`, um heredoc ou um `trap` antes
/// da linha da saída, ou uma linha que continua nela, a pulariam — a saída
/// ficaria vazia, e a chave de todo cache, sem o canal. É o limite de toda
/// regra de texto: o script da ação é a raiz da confiança, com a revisão.
fn o_canal_do_passo_conferir(script: &str) -> Vec<String> {
    // Toda linha, as de comentário inclusive: num texto em várias linhas, o
    // bash roda a que começa por `#` (desde o lote A16); a posição das duas
    // primeiras se confere nas de código.
    let todas: Vec<&str> = script
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let codigo: Vec<&str> = todas
        .iter()
        .copied()
        .filter(|l| !l.starts_with('#'))
        .collect();
    let mut fora = Vec::new();
    if codigo.get(..2) != Some(&["set -euo pipefail", LEITURA_DO_CANAL][..]) {
        fora.push(format!(
            "{ACAO_DO_COMPILADOR}: o passo `conferir` não começa pelo `set -euo pipefail` e pela \
             linha que lê o canal do `rust-toolchain.toml` (`{LEITURA_DO_CANAL}`): o que roda antes \
             dela — uma função, um `PATH`, um `cd` — escolhe o valor que ela lê"
        ));
    }
    let leituras = todas.iter().filter(|l| **l == LEITURA_DO_CANAL).count();
    if leituras != 1 {
        fora.push(format!(
            "{ACAO_DO_COMPILADOR}: o passo `conferir` tem {leituras} linha(s) iguais à que lê o canal \
             do `rust-toolchain.toml` — uma só, a segunda de código: uma cópia mais abaixo, depois \
             de uma função, de um `PATH` ou de um `cd`, leria outro valor"
        ));
    }
    for linha in &todas {
        if *linha != LEITURA_DO_CANAL && *linha != SAIDA_DO_CANAL && cita_o_nome(linha, "canal") {
            fora.push(format!(
                "{ACAO_DO_COMPILADOR}: `{linha}` no passo `conferir` — o nome `canal`, fora da \
                 expansão (`$canal`), só na linha que o lê do `rust-toolchain.toml` e na que o \
                 escreve na saída, também nas linhas que começam por `#`, que o bash roda num \
                 texto em várias linhas: noutra, ele pode receber outro valor, e a chave de todo \
                 cache levaria um canal que não é o do compilador que a encheu"
            ));
        }
    }
    let citacoes: usize = todas
        .iter()
        .map(|l| l.matches("GITHUB_OUTPUT").count())
        .sum();
    if citacoes != 1 || todas.last().copied() != Some(SAIDA_DO_CANAL) {
        fora.push(format!(
            "{ACAO_DO_COMPILADOR}: o passo `conferir` cita o `GITHUB_OUTPUT` {citacoes} vez(es), ou \
             não termina pela linha da saída — só a linha `{SAIDA_DO_CANAL}`, uma vez e na última \
             linha do script, escreve a saída: uma segunda escrita do canal vence a primeira"
        ));
    }
    // A função, o apelido e o `enable` (desde o lote A16), nas linhas como o
    // bash as junta: a `\` do fim de uma linha a continua na de baixo.
    for linha in script.replace("\\\n", "").lines().map(str::trim) {
        if let Some(qual) = troca_um_comando(linha) {
            fora.push(format!(
                "{ACAO_DO_COMPILADOR}: `{linha}` no passo `conferir` — {qual}: troca, sem citar o \
                 nome `canal`, o comando que outra linha roda — o `echo` da saída, o `python3` da \
                 leitura —, e a regra do canal lê o script pelo texto"
            ));
        }
    }
    fora
}

/// O que, numa linha do script do passo `conferir`, troca o comando que
/// outra linha roda — o `echo` da saída, o `python3` da leitura
/// ([`o_canal_do_passo_conferir`]): a definição de uma função — um par de
/// parênteses vazio, com espaços ou não entre eles, ou a palavra
/// `function` —, um apelido — o `alias`, e também o `expand_aliases` e o
/// `BASH_ALIASES`, em qualquer caixa — e o `enable`, que desliga um comando
/// interno do bash e deixa o do PATH no lugar dele. Nenhum, sem nada disso.
/// Desde o lote A16.
fn troca_um_comando(linha: &str) -> Option<&'static str> {
    let da_palavra = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let palavra = |p: &str| {
        linha.match_indices(p).any(|(i, _)| {
            !linha[..i].ends_with(da_palavra) && !linha[i + p.len()..].starts_with(da_palavra)
        })
    };
    let b = linha.as_bytes();
    let parenteses_vazios = b.iter().enumerate().any(|(i, &c)| {
        c == b'(' && b[i + 1..].iter().find(|&&d| d != b' ' && d != b'\t') == Some(&b')')
    });
    if parenteses_vazios || palavra("function") {
        Some("a definição de uma função")
    } else if linha.to_ascii_lowercase().contains("alias") {
        Some("um apelido do bash")
    } else if palavra("enable") {
        Some("o `enable`, que troca um comando interno do bash pelo do PATH")
    } else {
        None
    }
}

/// `linha` cita `nome` — a palavra inteira, de letras, dígitos e `_` — fora
/// da expansão do shell: sem o `$` antes, nem o `${`, o `${!` e o `${#`; e
/// o `${nome=…}` e o `${nome:=…}`, que dão valor ao nome, também contam.
fn cita_o_nome(linha: &str, nome: &str) -> bool {
    let da_palavra = |c: char| c.is_ascii_alphanumeric() || c == '_';
    linha.match_indices(nome).any(|(i, _)| {
        let antes = &linha[..i];
        let depois = &linha[i + nome.len()..];
        let inteira = !antes.ends_with(da_palavra) && !depois.starts_with(da_palavra);
        let expansao = ["$", "${", "${!", "${#"].iter().any(|p| antes.ends_with(p));
        let atribui =
            antes.ends_with("${") && (depois.starts_with('=') || depois.starts_with(":="));
        inteira && (!expansao || atribui)
    })
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
    // Um `-` só com um comentário é um `-` sozinho.
    if let Some(coluna) = coluna.filter(|_| !sem_comentario(depois).is_empty()) {
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

/// Os passos de um job — `job`, as linhas de código dele, da do nome em
/// diante —, cada um pela linha do `-`: os itens da lista do `steps:`, a
/// chave na coluna das chaves do job, fora do conteúdo dos blocos. Nenhum,
/// sem o `steps:` em bloco. Desde o lote A14: o item de uma matriz, ou o de
/// outra chave do job, não é um passo ([`as_invariantes_na_acao`]).
fn passos_do_job(job: &[Linha<'_>]) -> Vec<usize> {
    // A coluna das chaves do job: a da primeira linha de código depois da do
    // nome dele.
    let Some(coluna) = job
        .iter()
        .skip(1)
        .find(|l| !l.texto.is_empty())
        .map(|l| l.recuo)
    else {
        return Vec::new();
    };
    let Some(steps) = job.iter().position(|l| {
        !l.escalar && l.recuo == coluna && chave_e_valor(l.texto) == Some(("steps", ""))
    }) else {
        return Vec::new();
    };
    let dentro: Vec<usize> = (steps + 1..job.len())
        .filter(|&k| !job[k].escalar && !job[k].texto.is_empty())
        .take_while(|&k| job[k].recuo > coluna)
        .collect();
    let Some(dos_itens) = dentro.first().map(|&k| job[k].recuo) else {
        return Vec::new();
    };
    dentro
        .into_iter()
        .filter(|&k| {
            job[k].recuo == dos_itens && (job[k].texto == "-" || job[k].texto.starts_with("- "))
        })
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
/// # O passo é um item do `steps:` do job, desde o lote A14
///
/// O primeiro "passo que usa a ação" era a primeira linha do job com o
/// `uses:` dela, e podia ser o texto de um bloco — o `uses:` da ação no
/// `env:` do job —, a continuação de um escalar simples (`uses:./…`, sem o
/// espaço) ou o item de uma matriz com as chaves do passo; as chaves dele, as
/// do item de uma matriz acima, com `with: invariantes: true`: o passo de
/// verdade ficava sem a entrada, e o job de lints, sem as invariantes, com o
/// `cargo xtask invariantes` passando (o M3 do adversário do lote A13; o
/// item da matriz com as chaves do passo, o lote A14 o achou na revisão). O
/// passo é o primeiro item da lista do `steps:` do job ([`passos_do_job`])
/// que tem a chave `uses:` da ação ([`chave_e_valor`]), e as chaves, as
/// dele.
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
            // Um passo do job, e não o texto de um bloco nem o item de uma
            // matriz (desde o lote A14).
            passos_do_job(job)
                .into_iter()
                .map(|passo| chaves_do_item(job, passo))
                .find(|chaves| {
                    chaves.iter().any(|c| {
                        c.chave == "uses" && nome_da_acao(c.valor) == "./.github/actions/compilador"
                    })
                })
                .is_some_and(|chaves| {
                    chaves
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
             (`invariantes: true` no `with:` do primeiro passo do `steps:` do job que a usa — num \
             `env:`, noutro passo ou numa matriz, não vale): elas rodam ali, antes do cache e de \
             todo outro `cargo` do job — os testes do hospedeiro e o clippy rodam código do \
             repositório"
        )]
    }
}

/// O passo `id` de uma ação composta — `acao`, o texto do `action.yml` —: o
/// `shell:` e o script do `run: |`, sem o recuo dele. O passo é o item de
/// `runs.steps` com o `id` ([`forma_da_acao`]); o `shell:` e o `run:`, as
/// chaves dele ([`chaves_do_item`]); e o script, o conteúdo do bloco do
/// `run:`, cru — as linhas mais recuadas que ele, as vazias inclusive.
///
/// # O item, e as chaves dele, desde o lote A14
///
/// O passo era o texto do arquivo da primeira linha `id:` ao item seguinte,
/// e o `shell:`, a primeira linha dele com a chave: uma cópia do passo como
/// o texto de um bloco de um passo anterior — uma string do Python, um
/// heredoc —, ou um `shell: bash` como texto no começo do script, com o
/// `shell:` de verdade depois do bloco, eram o passo para as regras; e o de
/// verdade rodava `/bin/true {0}`, ou voltava a aceitar o `if:`, o
/// `continue-on-error:` e o `env:` que o lote A13 recusou (o M1 do
/// adversário do lote A13).
fn passo_da_acao(acao: &str, id: &str) -> Option<(String, String)> {
    let recuo = |l: &str| l.len() - l.trim_start().len();
    let linhas = linhas_de_codigo(acao);
    let cruas: Vec<&str> = acao
        .strip_prefix('\u{feff}')
        .unwrap_or(acao)
        .lines()
        .collect();
    let (_, passos) = forma_da_acao(&linhas);
    let &(_, do_id) = passos.iter().find(|(p, _)| p == id)?;
    let chaves = chaves_do_item(&linhas, do_id);
    let shell = chaves
        .iter()
        .find(|c| c.chave == "shell")?
        .valor
        .to_string();
    let run = chaves
        .iter()
        .find(|c| c.chave == "run" && (c.valor == "|" || c.valor == "|-"))?;
    // O conteúdo do bloco: as linhas cruas da do `run:` à primeira de código
    // fora dele.
    let de = linhas[run.linha].numero;
    let ate = (run.linha + 1..linhas.len())
        .find(|&k| !linhas[k].escalar)
        .map_or(cruas.len(), |k| linhas[k].numero);
    let recuo_do_run = recuo(cruas[de]);
    let corpo: Vec<&str> = cruas[de + 1..ate]
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

/// Os gatilhos do canário, a lista fechada ([`gatilhos_fora_da_lista`]): o
/// agendamento e o disparo manual. Desde o lote A16.
const GATILHOS_DO_CANARIO: [&str; 2] = ["schedule", "workflow_dispatch"];

/// Um gatilho do `on:` da raiz de um workflow ([`gatilhos_do_on`]): o nome,
/// a linha dele e se ele tem alguma coisa dentro — um filtro (`branches:`,
/// `paths-ignore:`), os `types:` — ou um valor na linha da chave.
struct Gatilho<'a> {
    nome: String,
    linha: &'a str,
    com_algo_dentro: bool,
}

/// Os gatilhos do `on:` da raiz de um workflow — `linhas`, as de código
/// dele —, nas formas que o `on:` tem: o valor na linha (`on: push`,
/// `on: [push, …]`), a lista em bloco (`- push`, também na coluna da própria
/// chave, a sequência compacta do YAML) e as chaves do mapa (`push:`), na
/// coluna da primeira linha de dentro dele. Nenhum `on:` na coluna zero, e
/// é `None`. Desde o lote A17, a leitura que a regra dos gatilhos do canário
/// ([`gatilhos_fora_da_lista`]) e a da CI nos pushes ([`a_ci_nos_pushes`])
/// partilham.
fn gatilhos_do_on<'a>(linhas: &[Linha<'a>]) -> Option<Vec<Gatilho<'a>>> {
    let codigo: Vec<&Linha<'a>> = linhas
        .iter()
        .filter(|l| !l.escalar && !l.texto.is_empty())
        .collect();
    let mut gatilhos = Vec::new();
    let mut achou_o_on = false;
    let mut no_on = false;
    let mut coluna: Option<usize> = None;
    for (k, l) in codigo.iter().enumerate() {
        let item = l
            .texto
            .strip_prefix("- ")
            .or((l.texto == "-").then_some(""));
        // Uma linha da raiz é uma chave dela — menos o item de uma lista logo
        // depois do `on:`, na coluna dele, que é um gatilho.
        if l.recuo == 0 && !(no_on && item.is_some()) {
            no_on = false;
            if let Some(("on", valor)) = chave_e_valor(l.texto) {
                achou_o_on = true;
                no_on = true;
                coluna = None;
                let dentro = valor
                    .strip_prefix('[')
                    .and_then(|v| v.strip_suffix(']'))
                    .unwrap_or(valor);
                gatilhos.extend(
                    dentro
                        .split(',')
                        .map(str::trim)
                        .filter(|g| !g.is_empty())
                        .map(|g| Gatilho {
                            nome: sem_aspas(g).to_string(),
                            linha: l.texto,
                            com_algo_dentro: false,
                        }),
                );
            }
            continue;
        }
        if !no_on || *coluna.get_or_insert(l.recuo) != l.recuo {
            continue;
        }
        // Dentro dele: a linha de baixo mais recuada que ele.
        let por_baixo = codigo.get(k + 1).is_some_and(|d| d.recuo > l.recuo);
        let (nome, na_linha) = match item {
            Some(item) => (sem_comentario(item.trim()), false),
            None => chave_e_valor(l.texto).map_or((l.texto, false), |(chave, valor)| {
                (chave, !valor.is_empty())
            }),
        };
        gatilhos.push(Gatilho {
            nome: sem_aspas(nome).to_string(),
            linha: l.texto,
            com_algo_dentro: por_baixo || na_linha,
        });
    }
    achou_o_on.then_some(gatilhos)
}

/// Os gatilhos do canário — `linhas`, as de código dele — fora de
/// [`GATILHOS_DO_CANARIO`]: ele roda no agendamento e no disparo manual,
/// nunca num push. Nas formas que o `on:` tem ([`gatilhos_do_on`]).
///
/// # A lista fechada, desde o lote A16
///
/// A regra procurava o `push` e o `pull_request` no valor da linha, e o
/// `push`, o `pull_request` e o `pull_request_target` nas chaves de recuo
/// dois, e não lia a lista em bloco: com `on:` seguido de `- push`, o canário
/// rodaria em todo push, e o `cargo xtask invariantes` passava; e um gatilho
/// fora dos três — o `workflow_run` depois da CI, que também roda a cada push
/// — passava (o B3 do adversário do lote A15). Agora, o que não é da lista
/// reprova, em qualquer dessas formas; a lista em bloco na coluna do `on:`,
/// o lote A16 a achou na revisão do patch do adversário.
///
/// # O `on:` na coluna zero, desde o lote A17
///
/// A regra acha o `on:` entre as chaves da raiz, na coluna zero, e o YAML
/// aceita a raiz recuada — as chaves de cima todas na coluna dois, o mesmo
/// mapa: com o canário assim, a regra não lia gatilho nenhum, e um `push:`
/// passava (o B1 do adversário do lote A16, a pista do revisor da rodada 9:
/// rc=0 com o `xtask` de `3991a87`, com o Python dos passos pelo caminho do
/// sistema, que a paridade conta). A leitura reprova a raiz fora da coluna
/// zero ([`raiz_fora_da_coluna_zero`]); e o canário sem um `on:` na coluna
/// zero reprova aqui.
fn gatilhos_fora_da_lista(nome: &str, linhas: &[Linha<'_>]) -> Vec<String> {
    let Some(gatilhos) = gatilhos_do_on(linhas) else {
        return vec![format!(
            "{nome}: nenhum `on:` na coluna zero — a regra lê os gatilhos do canário no `on:` da \
             raiz, na coluna zero; uma raiz recuada, que o YAML lê igual, os esconde dela"
        )];
    };
    gatilhos
        .into_iter()
        .filter(|g| !GATILHOS_DO_CANARIO.contains(&g.nome.as_str()))
        .map(|g| {
            format!(
                "{nome}: o canário roda em `{}` (`{}`) — só no agendamento e no disparo manual \
                 ({})",
                g.nome,
                g.linha,
                GATILHOS_DO_CANARIO.join(", ")
            )
        })
        .collect()
}

/// O `on:` da raiz da CI oficial — `ci`, o [`CI`] — tem o `push` sem nada
/// dentro — nem um filtro (`branches:`, `branches-ignore:`, `paths:`,
/// `paths-ignore:`, `tags:`), nem um valor na linha da chave —, em qualquer
/// das formas do `on:` que a leitura dos gatilhos lê ([`gatilhos_do_on`]).
///
/// # Por quê, desde o lote A17
///
/// A regra das invariantes confere que o job de lints as liga
/// ([`as_invariantes_na_acao`]), e a da falta, que a CI existe pelo nome
/// ([`workflows_que_faltam`]); nenhuma lia o `on:` dela: a CI só com o
/// `workflow_dispatch:` passava, e as invariantes deixavam de rodar a cada
/// push, como com a CI renomeada (o I1 do adversário do lote A16). Um filtro
/// do `push` também as tira de uma parte dos pushes, e reprova. O `if:` de
/// um job inteiro, que também as tiraria, fica com a revisão; e o
/// `[skip ci]` na mensagem de um commit, que, pela documentação do GitHub,
/// tira os workflows do `push` daquele push, está fora da definição da CI.
fn a_ci_nos_pushes(ci: &str) -> Vec<String> {
    let linhas = linhas_de_codigo(ci);
    let nos_pushes = gatilhos_do_on(&linhas)
        .unwrap_or_default()
        .iter()
        .any(|g| g.nome == "push" && !g.com_algo_dentro);
    if nos_pushes {
        Vec::new()
    } else {
        vec![format!(
            "{CI}: a CI oficial não roda em todo push — o `on:` da raiz, na coluna zero, sem o \
             `push`, ou com um filtro ou um valor nele: as invariantes do job de lints rodam a \
             cada push"
        )]
    }
}

/// O modo do cache do canário — `linhas`, as de código dele —: o
/// `cache-mode: none` na raiz, uma vez, e nenhuma outra chave `cache-mode` —
/// a de um job (`jobs.<id>.cache-mode`) troca o da raiz para ele. Fora do
/// conteúdo dos blocos, em qualquer coluna.
///
/// # Por quê, desde o lote A17
///
/// O cache do GitHub é do ramo, e não do workflow: um passo do canário que
/// gravasse um cache no ramo em que roda — uma ação, o código do
/// repositório ou o compilador candidato — o deixaria para os jobs da CI
/// oficial restaurarem (o M2 do adversário do lote A15), e o que o impedia
/// era só a falta da ação do cache no canário, que diz o que os passos
/// escolhem. A documentação do GitHub diz que o modo vale pelo token de
/// cache que o job recebe ("enforced with scoped cache tokens") e que, com
/// `none`, nenhum passo restaura nem grava; que o GitHub aceita a chave, o
/// run 5 do canário confirmou — o `abd9253` a pôs na raiz, e o job rodou —;
/// que o token do job fica sem cache, não se rodou. A regra confere a chave,
/// e não o efeito.
fn o_modo_do_cache_do_canario(nome: &str, linhas: &[Linha<'_>]) -> Vec<String> {
    let mut na_raiz = Vec::new();
    let mut fora = Vec::new();
    for l in linhas.iter().filter(|l| !l.escalar) {
        let Some(("cache-mode", valor)) = chave_e_valor(l.texto) else {
            continue;
        };
        if l.recuo == 0 {
            na_raiz.push(sem_aspas(valor));
        } else {
            fora.push(format!(
                "{nome}: `{}` — um `cache-mode` fora da raiz: o de um job troca o da raiz para \
                 ele, e o canário fica sem cache nenhum (`cache-mode: none`, só na raiz)",
                l.texto
            ));
        }
    }
    if na_raiz != ["none"] {
        fora.insert(
            0,
            format!(
                "{nome}: o canário sem o `cache-mode: none` na raiz, uma vez (achados: {na_raiz:?}) \
                 — o cache do GitHub é do ramo, e um passo do canário que gravasse um cache o \
                 deixaria para os jobs da CI oficial; com `none`, o token de cache do job não \
                 restaura nem grava"
            ),
        );
    }
    fora
}

/// A pasta dos registros do canário, a única que ele publica
/// ([`a_publicacao_do_canario`]): o diretório temporário do runner, fora da
/// árvore do projeto, na forma canônica — a regra compara o texto. Desde o
/// lote A17.
const REGISTROS_DO_CANARIO: &str = "${{ runner.temp }}/registros/";

/// A publicação do canário — `linhas`, as de código dele —: todo passo que
/// usa o `actions/upload-artifact` tem, no `with:`, um `path:` só, igual à
/// pasta dos registros ([`REGISTROS_DO_CANARIO`]), numa linha.
///
/// # A forma canônica, de propósito
///
/// O `path:` se compara pelo texto, sem as aspas: o caminho sem a `/` do fim,
/// ou com a expressão sem os espaços (`${{runner.temp}}`), que o GitHub
/// resolve para a mesma pasta, reprova, e falha fechado — a mensagem mostra
/// a forma exigida (o F1 do adversário da rodada 10, dito desde o lote A18;
/// a regra não mudou).
///
/// # Por quê, desde o lote A17
///
/// A regra da proveniência do canário é o texto `target/proveniencia` numa
/// linha de código dele: um `path: target/` na publicação levaria os
/// registros que o `xtask` grava ali sem citar o caminho deles (o E4 do
/// revisor da rodada 9 e o I2 do adversário do lote A16). Aqui, o `path:` é
/// só a pasta dos registros. A cópia de um registro para ela — por um glob
/// (`cp -r target/proven* …`) ou por um nome montado em pedaços — a regra
/// não segue: fica com a revisão, e o registro do canário diz
/// `"oficial": false`.
fn a_publicacao_do_canario(nome: &str, linhas: &[Linha<'_>]) -> Vec<String> {
    let mut fora = Vec::new();
    for (i, l) in linhas.iter().enumerate() {
        let publica = !l.escalar
            && chave_e_valor(l.texto).is_some_and(|(chave, valor)| {
                chave == "uses" && nome_da_acao(valor) == "actions/upload-artifact"
            });
        if !publica {
            continue;
        }
        let caminhos: Vec<&str> = chaves_do_item(linhas, i)
            .iter()
            .filter(|c| c.chave == "with")
            .flat_map(|c| chaves_de_dentro(linhas, c))
            .filter(|c| c.chave == "path")
            .map(|c| sem_aspas(c.valor))
            .collect();
        if caminhos != [REGISTROS_DO_CANARIO] {
            fora.push(format!(
                "{nome}: a publicação de `{}` com o `path:` {caminhos:?} — o canário publica só a \
                 pasta dos registros (`path: {REGISTROS_DO_CANARIO}`), numa linha: a \
                 proveniência e o resto de `target/` não são artefato dele",
                l.texto
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
                "sem toda pasta target",
                acao.replace(" or \"target\" in arquivo.split(\"/\")[:-1]", ""),
            ),
            (
                "sem o workspace de um pacote",
                acao.replace(
                    "if isinstance(pacote, dict) and \"workspace\" in pacote:",
                    "if False:",
                ),
            ),
            (
                "sem o workspace da tabela antiga",
                acao.replace(
                    "for tabela in (\"package\", \"project\"):",
                    "for tabela in (\"package\",):",
                ),
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
                "sem os submódulos do commit",
                acao.replace("if modo == \"160000\":", "if modo == \"0\":"),
            ),
            (
                "sem o que não é pasta no caminho das saídas",
                acao.replace("if os.path.lexists(atual)", "if False"),
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
    /// Desde o lote A17, o toolchain oficial é instalado antes, uma vez só
    /// ([`o_oficial_instalado`]), e a `saida` começa pelo que a instalação
    /// disse.
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
        let caso = ArvoreDoCaso {
            arquivos,
            links,
            forcados,
            submodulos: &[],
        };
        rodar_a_acao_na_arvore(base, nome, &caso, ambiente, antes_no_path)
    }

    /// A árvore de um caso de [`rodar_a_acao_na_arvore`]: os `arquivos`, os
    /// `links` — o caminho e para onde ele aponta —, os `forcados` — os de
    /// `target/`, que o `.gitignore` deixa de fora do commit — e, desde o
    /// lote A13, os `submodulos`: um gitlink (o modo 160000) em cada caminho,
    /// só no índice, como num commit com um submódulo que o checkout não
    /// trouxe.
    struct ArvoreDoCaso<'a> {
        arquivos: &'a [(&'a str, String)],
        links: &'a [(&'a str, &'a str)],
        forcados: &'a [&'a str],
        submodulos: &'a [&'a str],
    }

    /// Como [`rodar_a_acao_com_links`], com a árvore inteira do caso
    /// ([`ArvoreDoCaso`]).
    fn rodar_a_acao_na_arvore(
        base: &Path,
        nome: &str,
        caso: &ArvoreDoCaso<'_>,
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
        for (relativo, texto) in caso.arquivos {
            escrever(relativo, texto);
            // Os programas falsos do caso, executáveis, como num commit com
            // o modo deles.
            if relativo.starts_with("ferramentas/") {
                tornar_executavel(&arvore.join(relativo));
            }
        }
        for (relativo, destino) in caso.links {
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
        for f in caso.forcados {
            git(&["add", "-f", "--", f]);
        }
        // O submódulo: só o gitlink no índice, com um commit que não existe
        // aqui — o checkout sem os submódulos não o traz.
        for s in caso.submodulos {
            let entrada = format!("160000,{},{s}", "1".repeat(40));
            git(&["update-index", "--add", "--cacheinfo", &entrada]);
        }
        git(&["commit", "-q", "-m", "a árvore do caso"]);
        // O CARGO_HOME do caso, com os proxies ligados ao rustup de verdade,
        // como o rustup os instala.
        let rustup = rustup_de_verdade();
        let rustup_home = rustup_home_de_verdade();
        // O toolchain oficial, instalado uma vez só, antes da primeira ação
        // (desde o lote A17): o passo `conferir` só o confere.
        let instalado = match o_oficial_instalado() {
            Ok(instalado) => &instalado.versao,
            Err(e) => panic!("a instalação do toolchain oficial, antes da ação: {e}"),
        };
        let casa = base.join(format!("{nome}-casa"));
        let _ = std::fs::remove_dir_all(&casa);
        casa_com_os_proxies(&casa, &rustup);
        let mut caminho = format!("{}:/usr/bin:/bin", casa.join("bin").display());
        if let Some(pasta) = antes_no_path {
            caminho = format!("{pasta}:{caminho}");
        }
        let saida_do_github = base.join(format!("{nome}-saida"));
        let mut passou = true;
        let mut saida = format!("[instalação de antes] {instalado}\n");
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

    /// O `RUSTUP_HOME` de quem roda o teste — o da variável, ou o
    /// `~/.rustup` —, onde moram os toolchains que os passos da ação rodam.
    fn rustup_home_de_verdade() -> PathBuf {
        std::env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".rustup")))
            .expect("o RUSTUP_HOME")
    }

    /// Um `CARGO_HOME` em `casa`, com os proxies do rustup — o `rustup`, o
    /// `cargo`, o `rustc`, o `rustdoc` e o `rustfmt` — ligados ao `rustup` de
    /// verdade, como o rustup os instala.
    fn casa_com_os_proxies(casa: &Path, rustup: &Path) {
        std::fs::create_dir_all(casa.join("bin")).expect("a casa");
        for proxy in ["rustup", "cargo", "rustc", "rustdoc", "rustfmt"] {
            std::os::unix::fs::symlink(rustup, casa.join("bin").join(proxy)).expect("o proxy");
        }
    }

    /// Os nomes do ambiente de quem roda o teste que levam o rustup à rede,
    /// na instalação de antes da ação ([`o_oficial_instalado`]), se ele os
    /// tem: o proxy, os certificados e o servidor da distribuição. Nenhum
    /// escolhe o toolchain.
    const A_REDE_DO_RUSTUP: [&str; 12] = [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "RUSTUP_DIST_SERVER",
        "RUSTUP_UPDATE_ROOT",
    ];

    /// O ambiente da instalação de antes da ação ([`o_oficial_instalado`]):
    /// o dos passos da ação nos testes ([`rodar_a_acao_na_arvore`]) — o PATH
    /// com os proxies de `casa`, o `HOME`, o `CARGO_HOME` e o `RUSTUP_HOME` —
    /// e, do ambiente de quem roda o teste (`ler`), só os nomes de
    /// [`A_REDE_DO_RUSTUP`]: nem o `RUSTUP_TOOLCHAIN`, que o proxy do rustup
    /// põe no ambiente do cargo — e o canário, no do job, com o candidato —,
    /// nem o `RUSTUP_AUTO_INSTALL`, que o canário desliga para o candidato.
    fn ambiente_da_instalacao(
        casa: &Path,
        home: &Path,
        rustup_home: &Path,
        ler: impl Fn(&str) -> Option<std::ffi::OsString>,
    ) -> Vec<(String, std::ffi::OsString)> {
        let mut ambiente = vec![
            (
                String::from("PATH"),
                format!("{}:/usr/bin:/bin", casa.join("bin").display()).into(),
            ),
            (String::from("HOME"), home.as_os_str().to_owned()),
            (String::from("CARGO_HOME"), casa.as_os_str().to_owned()),
            (
                String::from("RUSTUP_HOME"),
                rustup_home.as_os_str().to_owned(),
            ),
        ];
        for nome in A_REDE_DO_RUSTUP {
            if let Some(valor) = ler(nome) {
                ambiente.push((nome.to_string(), valor));
            }
        }
        ambiente
    }

    /// O toolchain oficial instalado uma vez só, antes da primeira ação
    /// rodada como o runner ([`rodar_a_acao_na_arvore`]), no `RUSTUP_HOME`
    /// dos passos: o mesmo pedido que o passo `conferir` da ação faz — o
    /// `rustc -V` pelo proxy do rustup, numa árvore com o
    /// `rust-toolchain.toml` do repositório, que instala o toolchain do
    /// arquivo, com os componentes e os alvos, na primeira chamada —, no
    /// ambiente de [`ambiente_da_instalacao`]. Devolve o que o `rustc -V`
    /// disse e o toolchain do sysroot, ou por que não rodou; o resultado
    /// fica para todos os testes do processo.
    ///
    /// # Por quê, desde o lote A17
    ///
    /// Os passos da ação nos testes usam o `RUSTUP_HOME` de quem os roda, e o
    /// `rustc -V` do passo `conferir` instala o toolchain do arquivo quando
    /// ele falta. Na CI oficial, a ação do job o instalou antes, e as chamadas
    /// dos testes não instalam nada; no canário, os testes rodam com o
    /// candidato, o oficial não está instalado — o `RUSTUP_AUTO_INSTALL=0`
    /// do job vale para os `cargo` dele, e os passos dos testes rodam sem o
    /// ambiente do job —, e os oito testes que rodam a ação, em paralelo, o
    /// instalavam ao mesmo tempo, no mesmo `RUSTUP_HOME`: os oito reprovaram,
    /// com os erros do rustup ("could not remove 'component' file", no run 5
    /// do canário). Oito `rustc -V` assim, ao mesmo tempo, num `RUSTUP_HOME`
    /// novo, reprovaram sete vezes em oito, em cada uma de duas rodadas, com
    /// os erros do rustup — numa delas, um com o do run 5, noutro componente
    /// —; um só passou.
    /// Aqui, a instalação vem antes, uma vez — o `OnceLock` faz os outros
    /// testes esperarem por ela —, e os passos dos testes acham o toolchain
    /// instalado.
    fn o_oficial_instalado() -> &'static Result<Instalado, String> {
        static INSTALADO: OnceLock<Result<Instalado, String>> = OnceLock::new();
        INSTALADO.get_or_init(|| {
            let projeto = super::super::raiz_do_projeto();
            let base = std::env::temp_dir().join(format!(
                "xtask-instalacao-do-oficial-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&base);
            let arvore = base.join("arvore");
            let casa = base.join("casa");
            std::fs::create_dir_all(&arvore).map_err(|e| format!("a árvore: {e}"))?;
            std::fs::copy(
                projeto.join(TOOLCHAIN_DA_RAIZ),
                arvore.join(TOOLCHAIN_DA_RAIZ),
            )
            .map_err(|e| format!("o {TOOLCHAIN_DA_RAIZ}: {e}"))?;
            casa_com_os_proxies(&casa, &rustup_de_verdade());
            let ambiente = ambiente_da_instalacao(&casa, &base, &rustup_home_de_verdade(), |n| {
                std::env::var_os(n)
            });
            let rodar = |args: &[&str]| {
                let feito = Command::new(casa.join("bin").join("rustc"))
                    .args(args)
                    .current_dir(&arvore)
                    .env_clear()
                    .envs(ambiente.iter().map(|(n, v)| (n, v)))
                    .output()
                    .map_err(|e| format!("o rustc {args:?} não rodou: {e}"))?;
                if !feito.status.success() {
                    return Err(format!(
                        "o rustc {args:?} saiu com {}: {}",
                        feito.status,
                        String::from_utf8_lossy(&feito.stderr).trim()
                    ));
                }
                Ok(String::from_utf8_lossy(&feito.stdout).trim().to_string())
            };
            let versao = rodar(&["-V"]);
            let sysroot = rodar(&["--print", "sysroot"]);
            let _ = std::fs::remove_dir_all(&base);
            let sysroot = sysroot?;
            Ok(Instalado {
                versao: format!("{}, o toolchain {}", versao?, nome_do_toolchain(&sysroot)),
                sysroot: PathBuf::from(sysroot),
            })
        })
    }

    /// O toolchain oficial que a instalação de antes da ação instalou, ou
    /// achou instalado ([`o_oficial_instalado`]): o que o `rustc -V` dele
    /// disse, com o nome do toolchain, e o sysroot — no `RUSTUP_HOME` dos
    /// passos, e não o do cargo que compilou o teste, que no canário é o do
    /// candidato.
    struct Instalado {
        versao: String,
        sysroot: PathBuf,
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
        // A instalação do oficial vem antes da ação (desde o lote A17).
        assert!(
            limpa.saida.starts_with("[instalação de antes] rustc "),
            "{}",
            limpa.saida
        );
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

    /// A instalação do toolchain oficial antes da ação (desde o lote A17: os
    /// testes que rodam a ação disputavam o rustup no canário, no run 5): o
    /// ambiente dela é o dos passos, mais, de quem roda o teste, só os nomes
    /// da rede do rustup ([`A_REDE_DO_RUSTUP`]) — aqui, o proxy, os
    /// certificados e o servidor da distribuição —, e nada que escolha o
    /// toolchain — o `RUSTUP_TOOLCHAIN` do candidato e o
    /// `RUSTUP_AUTO_INSTALL=0` do canário, o `LD_LIBRARY_PATH` e o `CARGO`
    /// que o cargo põe nos testes ficam de fora —; e o toolchain que ela
    /// instala, ou acha instalado, é o do canal oficial com o host.
    #[test]
    fn a_instalacao_de_antes_da_acao_e_a_do_oficial() {
        let de_fora = [
            ("RUSTUP_TOOLCHAIN", "nightly-2000-01-01"),
            ("RUSTUP_AUTO_INSTALL", "0"),
            ("LD_LIBRARY_PATH", "/x/lib"),
            ("CARGO", "/x/bin/cargo"),
            ("HTTPS_PROXY", "http://127.0.0.1:1"),
            ("SSL_CERT_FILE", "/x/certificados.pem"),
            ("RUSTUP_DIST_SERVER", "http://127.0.0.1:2"),
        ];
        let ambiente = ambiente_da_instalacao(
            Path::new("/casa"),
            Path::new("/home"),
            Path::new("/rustup"),
            |nome| {
                de_fora
                    .iter()
                    .find(|(n, _)| *n == nome)
                    .map(|(_, valor)| std::ffi::OsString::from(valor))
            },
        );
        let nomes: Vec<&str> = ambiente.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            nomes,
            [
                "PATH",
                "HOME",
                "CARGO_HOME",
                "RUSTUP_HOME",
                "HTTPS_PROXY",
                "SSL_CERT_FILE",
                "RUSTUP_DIST_SERVER"
            ]
        );
        assert_eq!(ambiente[0].1.to_str(), Some("/casa/bin:/usr/bin:/bin"));
        assert_eq!(ambiente[3].1.to_str(), Some("/rustup"));
        assert_eq!(ambiente[5].1.to_str(), Some("/x/certificados.pem"));
        let canal = canal_do_arquivo(include_str!("../../rust-toolchain.toml")).expect("o canal");
        let instalado = o_oficial_instalado().as_ref().expect("a instalação");
        assert!(
            instalado.versao.starts_with("rustc "),
            "{}",
            instalado.versao
        );
        assert!(
            instalado.versao.contains(&format!("o toolchain {canal}-")),
            "{}",
            instalado.versao
        );
        // O sysroot é o do toolchain oficial no `RUSTUP_HOME` dos passos.
        assert_eq!(
            instalado.sysroot.parent(),
            Some(rustup_home_de_verdade().join("toolchains").as_path()),
            "{}",
            instalado.sysroot.display()
        );
        assert!(
            instalado
                .sysroot
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&format!("{canal}-"))),
            "{}",
            instalado.sysroot.display()
        );
    }

    /// O `target` de outro workspace (o A1 do adversário do lote A16, alto):
    /// o `Cargo.toml` da raiz como um pacote com `workspace = "zz"` leva a
    /// raiz do workspace — e o `target/` do `xtask` — para `zz/`, fora dos
    /// diretórios de build, e o passo do ambiente só recusava o arquivo do
    /// commit no `target/` deles: o rlib de uma dependência, do commit, o
    /// cargo o tomava pelo que compilou. Rodado como o runner: o `workspace`
    /// do pacote — também na tabela antiga, `[project]` — reprova uma vez; o
    /// rlib numa pasta `target` de outro nível, uma vez; os dois juntos, uma
    /// vez cada; e o link `zz/target` para uma pasta do commit com o rlib,
    /// uma vez, pela regra dos links, que vale no commit inteiro. Passam o
    /// `[workspace]` noutra pasta, que nenhum pacote escolhe, e um arquivo
    /// com o nome `target`.
    #[test]
    fn adversario_a16_o_target_de_outro_workspace() {
        let base = base_da_acao("acao-a16-workspace");
        let pacote = |tabela: &str| {
            format!(
                "[{tabela}]\nname = \"raiz\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
                 publish = false\nworkspace = \"zz\"\n\n[lib]\npath = \"zz/raiz.rs\"\n"
            )
        };
        let do_workspace = String::from("[workspace]\nresolver = \"3\"\nmembers = [\"..\"]\n");
        let rlib = "zz/target/debug/build/zeroize/c781be9a644ae917/out/\
                    libzeroize-c781be9a644ae917.rlib";
        let no_target = "um arquivo do commit num diretório de saída do cargo";
        let comuns: Vec<(&str, String)> = vec![
            ("zz/Cargo.toml", do_workspace.clone()),
            ("zz/raiz.rs", String::new()),
            (
                "docs/target",
                String::from("um arquivo com o nome, e não uma pasta\n"),
            ),
        ];
        // O nome, os arquivos a mais e os erros, cada um uma vez.
        type Caso = (&'static str, Vec<(&'static str, String)>, Vec<String>);
        let casos: Vec<Caso> = vec![
            (
                "a-raiz-em-zz",
                vec![("Cargo.toml", pacote("package"))],
                vec![String::from("Cargo.toml: package.workspace 'zz'")],
            ),
            (
                "a-raiz-em-zz-pela-tabela-antiga",
                vec![("Cargo.toml", pacote("project"))],
                vec![String::from("Cargo.toml: project.workspace 'zz'")],
            ),
            (
                "o-rlib-em-zz-target",
                vec![(rlib, String::from("!<arch>\n"))],
                vec![format!("{rlib}: {no_target}")],
            ),
            (
                "os-dois",
                vec![
                    ("Cargo.toml", pacote("package")),
                    (rlib, String::from("!<arch>\n")),
                ],
                vec![
                    String::from("Cargo.toml: package.workspace 'zz'"),
                    format!("{rlib}: {no_target}"),
                ],
            ),
        ];
        let mut cegos = Vec::new();
        for (nome, a_mais, esperados) in &casos {
            let mut arquivos = comuns.clone();
            arquivos.extend(a_mais.iter().cloned());
            let forcados: Vec<&str> = a_mais
                .iter()
                .map(|(a, _)| *a)
                .filter(|a| a.contains("target/"))
                .collect();
            let r = rodar_a_acao(&base, nome, &arquivos, &forcados, &[], None);
            let erros = r.saida.matches("::error::").count();
            let todos = esperados
                .iter()
                .all(|e| r.saida.matches(&format!("::error::{e}")).count() == 1);
            if r.passou || erros != esperados.len() || !todos {
                cegos.push(format!("{nome}: {}", r.saida));
            }
        }
        // Um link `target` para uma pasta do commit não contorna a regra: o
        // link reprova pela regra dos links, em qualquer nível, uma vez; o
        // rlib, na pasta para onde ele aponta, não está numa pasta `target`.
        let mut com_link = comuns.clone();
        com_link.push(("zz/carga/debug/libzeroize.rlib", String::from("!<arch>\n")));
        let r = rodar_a_acao_com_links(
            &base,
            "o-target-por-um-link",
            &com_link,
            &[("zz/target", "carga")],
            &[],
            &[],
            None,
        );
        let link = "::error::zz/target: um link no commit";
        if r.passou
            || r.saida.matches("::error::").count() != 1
            || r.saida.matches(link).count() != 1
        {
            cegos.push(format!("o-target-por-um-link: {}", r.saida));
        }
        // Os controles: o `[workspace]` noutra pasta, que nenhum pacote
        // escolhe, e o arquivo `docs/target`.
        let controle = rodar_a_acao(&base, "controle", &comuns, &[], &[], None);
        if !controle.passou {
            cegos.push(format!("controle: {}", controle.saida));
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

    /// O submódulo e o que não é pasta no caminho de um diretório de saída
    /// (no lote A13, o I1 e o I2 do adversário do lote A12): um gitlink — o
    /// modo 160000 do índice — no lugar do `target`, no do `target` de um
    /// diretório de build ou noutro lugar passava pelo passo do ambiente, e
    /// num checkout com os submódulos traria os arquivos de outro
    /// repositório; e um `target` que é um arquivo do commit também passava,
    /// e só o cargo parava depois. Cada um reprova, pelo script rodado como
    /// o runner o roda, com os erros dele, e só eles; e a árvore sem nenhum
    /// dos dois passa.
    #[test]
    fn adversario_a12_o_submodulo_e_o_que_nao_e_pasta_no_caminho_das_saidas() {
        let base = base_da_acao("acao-a12-submodulos");
        let submodulo = "um submódulo no commit (um gitlink)";
        let nao_e_pasta = "o caminho do diretório de saída do cargo passa por";
        type Caso = (
            &'static str,
            Vec<(&'static str, String)>,
            Vec<&'static str>,
            Vec<String>,
        );
        let casos: Vec<Caso> = vec![
            (
                "o-submodulo-target",
                vec![],
                vec!["target"],
                vec![format!("target: {submodulo}")],
            ),
            (
                "o-submodulo-de-um-diretorio-de-build",
                vec![],
                vec!["kernel/target"],
                vec![format!("kernel/target: {submodulo}")],
            ),
            (
                "o-submodulo-noutro-lugar",
                vec![],
                vec!["vendor/outro"],
                vec![format!("vendor/outro: {submodulo}")],
            ),
            (
                "o-target-arquivo",
                vec![("target", String::from("nada\n"))],
                vec![],
                vec![format!("target: {nao_e_pasta} target, que não é uma pasta")],
            ),
            (
                "o-target-arquivo-de-um-diretorio-de-build",
                vec![("kernel/target", String::from("nada\n"))],
                vec![],
                vec![format!(
                    "kernel/target: {nao_e_pasta} kernel/target, que não é uma pasta"
                )],
            ),
        ];
        let mut cegos = Vec::new();
        for (nome, arquivos, submodulos, esperados) in &casos {
            let caso = ArvoreDoCaso {
                arquivos,
                links: &[],
                forcados: &[],
                submodulos,
            };
            let r = rodar_a_acao_na_arvore(&base, nome, &caso, &[], None);
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
        let nenhum = ArvoreDoCaso {
            arquivos: &[],
            links: &[],
            forcados: &[],
            submodulos: &[],
        };
        let r = rodar_a_acao_na_arvore(&base, "nenhum", &nenhum, &[], None);
        if !r.passou {
            cegos.push(format!("nenhum: {}", r.saida));
        }
        let _ = std::fs::remove_dir_all(&base);
        assert!(cegos.is_empty(), "{cegos:#?}");
    }

    /// O git da ação sem o ambiente do job (no lote A14, o M5 do adversário
    /// do lote A13, e o `HOME` que o lote achou na revisão): com um
    /// `GIT_INDEX_FILE` — um índice vazio — ou um `GIT_DIR` — outro
    /// repositório — no ambiente do job, o arquivo do commit no `target/debug`
    /// e o submódulo no lugar do `target` sumiam da lista do passo do
    /// ambiente, que passava; e, com o `HOME` numa pasta cujo `.gitconfig`
    /// tem um `core.fsmonitor` — ou com o `GIT_CONFIG_COUNT` que o põe —, o
    /// `git ls-files` do passo do ambiente e o `git diff` do passo do canal
    /// rodavam o programa dele. Rodado como o runner, com cada variável: o
    /// arquivo e o submódulo reprovam no passo do ambiente, cada um com o
    /// erro dele; a árvore limpa passa nos três passos — o `git diff` do
    /// canal também não lê o índice do job —; o programa do `fsmonitor` não
    /// roda; e a ação sem as marcas reprova.
    #[test]
    fn adversario_a13_o_git_da_acao_sem_o_ambiente_do_job() {
        let base = base_da_acao("acao-a13-git");
        let no_target = "target/debug/xtask: um arquivo do commit num diretório de saída do cargo";
        let submodulo = "target: um submódulo no commit (um gitlink)";
        let outro = base.join("outro");
        std::fs::create_dir_all(&outro).expect("o outro");
        let feito = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&outro)
            .output()
            .expect("o git");
        assert!(feito.status.success(), "{feito:?}");
        // O programa do `core.fsmonitor`: deixa uma marca, se roda.
        let marca = base.join("o-fsmonitor-rodou");
        let gancho = base.join("gancho");
        std::fs::write(
            &gancho,
            format!("#!/bin/sh\necho \"$@\" >> '{}'\nexit 1\n", marca.display()),
        )
        .expect("o gancho");
        tornar_executavel(&gancho);
        let casa = base.join("casa-do-job");
        std::fs::create_dir_all(&casa).expect("a casa");
        std::fs::write(
            casa.join(".gitconfig"),
            format!("[core]\n\tfsmonitor = {}\n", gancho.display()),
        )
        .expect("o .gitconfig");
        let arquivo = vec![("target/debug/xtask", String::from("#!/bin/sh\nexit 0\n"))];
        let variaveis: Vec<(&str, Vec<(&str, String)>)> = vec![
            (
                "indice",
                vec![(
                    "GIT_INDEX_FILE",
                    base.join("indice-vazio").display().to_string(),
                )],
            ),
            (
                "repositorio",
                vec![("GIT_DIR", outro.join(".git").display().to_string())],
            ),
            ("casa", vec![("HOME", casa.display().to_string())]),
            (
                "config",
                vec![
                    ("GIT_CONFIG_COUNT", String::from("1")),
                    ("GIT_CONFIG_KEY_0", String::from("core.fsmonitor")),
                    ("GIT_CONFIG_VALUE_0", gancho.display().to_string()),
                ],
            ),
        ];
        let mut cegos = Vec::new();
        for (rotulo, ambiente) in &variaveis {
            for (nome, caso, esperado) in [
                (
                    "o-arquivo-no-target",
                    ArvoreDoCaso {
                        arquivos: &arquivo,
                        links: &[],
                        forcados: &["target/debug/xtask"],
                        submodulos: &[],
                    },
                    Some(no_target),
                ),
                (
                    "o-submodulo-target",
                    ArvoreDoCaso {
                        arquivos: &[],
                        links: &[],
                        forcados: &[],
                        submodulos: &["target"],
                    },
                    Some(submodulo),
                ),
                (
                    "nenhum",
                    ArvoreDoCaso {
                        arquivos: &[],
                        links: &[],
                        forcados: &[],
                        submodulos: &[],
                    },
                    None,
                ),
            ] {
                let nome = format!("{rotulo}-{nome}");
                let r = rodar_a_acao_na_arvore(&base, &nome, &caso, ambiente, None);
                let certo = match esperado {
                    Some(erro) => !r.passou && r.saida.contains(&format!("::error::{erro}")),
                    None => r.passou,
                };
                if !certo {
                    cegos.push(format!("{nome}: {}", r.saida));
                }
            }
        }
        let rodou = std::fs::read_to_string(&marca).ok();
        let _ = std::fs::remove_dir_all(&base);
        assert!(cegos.is_empty(), "{cegos:#?}");
        assert_eq!(rodou, None, "o programa do core.fsmonitor rodou");
        for (rotulo, velho, novo) in [
            (
                "o git do ambiente com o ambiente do job",
                "SEM_O_GIT = {\"PATH\": os.environ.get(\"PATH\", \"\"), ",
                "SEM_O_GIT = {**os.environ, ",
            ),
            (
                "o git do canal com o ambiente do job",
                "env -i PATH=\"$PATH\" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git diff",
                "git diff",
            ),
        ] {
            let sem_a_marca = ACAO.replacen(velho, novo, 1);
            assert_ne!(sem_a_marca, ACAO, "{rotulo}");
            assert!(!conferir_a_acao(&sem_a_marca).is_empty(), "{rotulo}");
        }
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
        // O do toolchain oficial, na frente do PATH, passa: o `bin` do sysroot
        // que a instalação de antes da ação achou no `RUSTUP_HOME` dos passos
        // — e não o do cargo que compilou o teste (o `env!("CARGO")`), que no
        // canário é o do candidato, de outro canal (desde o lote A17).
        let oficial = match o_oficial_instalado() {
            Ok(instalado) => instalado.sysroot.join("bin").display().to_string(),
            Err(e) => panic!("a instalação do toolchain oficial, antes da ação: {e}"),
        };
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

    /// Os espaços que o YAML não toma por espaço, e os caracteres que ele não
    /// imprime (no lote A14, o M4 e o B1 do adversário do lote A13):
    /// `invariantes: true` com um NBSP no fim era `true` para a leitura, que
    /// tira as bordas com o `trim` do Rust, e `true\u{a0}` para o YAML — o
    /// passo das invariantes, que compara a entrada com `'true'`, não rodava,
    /// e o `cargo xtask invariantes` passava; o NBSP no nome da entrada, na
    /// ação, também; e um NUL num comentário, onde o YamlDotNet acaba o
    /// comentário. Cada um reprova, com a linha, também na ação; o texto em
    /// português, o travessão, as aspas tipográficas, um emoji, o ZWJ e o
    /// seletor de variação passam; e um invisível que não é espaço, o ZWSP,
    /// fica no valor para os dois — a porta não o acusa, e a regra que lê o
    /// valor, sim.
    #[test]
    fn adversario_a13_os_espacos_que_o_yaml_nao_toma_por_espaco() {
        let ci = include_str!("../../.github/workflows/ci.yml");
        let entrada = "          invariantes: true\n";
        assert_eq!(ci.matches(entrada).count(), 1);
        let n = ci[..ci.find(entrada).expect("a entrada")]
            .matches('\n')
            .count()
            + 1;
        let do_caractere = |fora: &[String]| -> Vec<String> {
            fora.iter()
                .filter(|f| f.contains(" — o YAML lê ali uma quebra de linha"))
                .cloned()
                .collect()
        };
        for c in [
            '\u{a0}', '\u{1680}', '\u{2000}', '\u{2003}', '\u{200a}', '\u{202f}', '\u{205f}',
            '\u{3000}', '\u{b}', '\u{c}', '\u{0}', '\u{1}', '\u{1b}', '\u{7f}', '\u{90}',
            '\u{fffe}',
        ] {
            let qual = format!("U+{:04X}", u32::from(c));
            for texto in [
                ci.replacen(entrada, &format!("          invariantes: true{c}\n"), 1),
                ci.replacen(entrada, &format!("          invariantes: {c}true\n"), 1),
            ] {
                let fora = do_caractere(&um(CI, &texto));
                assert!(
                    fora.len() == 1 && fora[0].starts_with(&format!("{CI}:{n}: ")),
                    "{qual}: {fora:#?}"
                );
                assert!(fora[0].contains(&qual), "{qual}: {fora:#?}");
            }
        }
        // O NBSP no nome da entrada da ação: o `if:` do passo das
        // invariantes lê `inputs.invariantes`, que deixa de existir.
        let acao = ACAO.replacen("  invariantes:\n", "  invariantes\u{a0}:\n", 1);
        assert_ne!(acao, ACAO);
        let fora = do_caractere(&um(ACAO_DO_COMPILADOR, &acao));
        assert!(fora.len() == 1 && fora[0].contains("U+00A0"), "{fora:#?}");
        // O NUL num comentário do passo da ação (o B1): o YamlDotNet acaba
        // ali o comentário, e o resto da linha seria outra coisa.
        let passo = "      - name: O compilador\n        id: compilador\n";
        assert_eq!(OFICIAL.matches(passo).count(), 1);
        let nul = OFICIAL.replacen(
            passo,
            &format!("{passo}        # x\u{0}        if: false\n"),
            1,
        );
        let fora = do_caractere(&um(CI, &nul));
        assert!(
            fora.len() == 1 && fora[0].starts_with(&format!("{CI}:9: um caractere (U+0000)")),
            "{fora:#?}"
        );
        // O ZWSP não é espaço para o Rust nem para o YAML: a porta não o
        // acusa, e o valor `true\u{200b}` não liga as invariantes.
        let zwsp = ci.replacen(entrada, "          invariantes: true\u{200b}\n", 1);
        assert_eq!(do_caractere(&um(CI, &zwsp)), Vec::<String>::new());
        assert_eq!(as_invariantes_na_acao(&zwsp).len(), 1);
        // O texto de verdade passa.
        let nome = "      - name: O compilador\n";
        assert_eq!(OFICIAL.matches(nome).count(), 1);
        for novo in [
            "      - name: O compilador — a conferência “oficial” (ação, órgão)\n",
            "      - name: O compilador \u{1f980}\n        # \u{1f680} \u{2705}\n",
            "      - name: O compilador \u{1f468}\u{200d}\u{1f4bb} \u{2764}\u{fe0f}\n",
        ] {
            let texto = OFICIAL.replacen(nome, novo, 1);
            assert_ne!(texto, OFICIAL);
            assert_eq!(um(CI, &texto), Vec::<String>::new(), "{novo}");
        }
    }

    /// Só um passo do job liga as invariantes (no lote A14, o M3 do
    /// adversário do lote A13): no job de lints, o passo da ação de verdade
    /// sem a entrada, uma matriz com um item de `with: invariantes: true` e o
    /// `uses:` da ação no `env:` do job — num bloco, ou na continuação de um
    /// escalar simples, sem o espaço — passavam: o texto era o primeiro passo
    /// que usa a ação, e as chaves dele, as do item da matriz, que já tinha
    /// acabado; e o item de uma matriz com as chaves do passo — o `uses:` da
    /// ação e o `with:` —, que o lote achou na revisão, era o passo. Reprovam.
    /// E as peças: `uses:./x` não é uma chave, o item de uma linha é o que vai
    /// até ela, e os passos de um job são os itens do `steps:` dele.
    #[test]
    fn adversario_a13_so_um_passo_do_job_liga_as_invariantes() {
        let ci = include_str!("../../.github/workflows/ci.yml");
        let ligada = "        with:\n          invariantes: true\n";
        let cabeca =
            "    name: Formatação e lints\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n";
        assert_eq!(ci.matches(ligada).count(), 1);
        assert_eq!(ci.matches(cabeca).count(), 1);
        let matriz = "    strategy:\n      matrix:\n        include:\n          - name: x\n            \
                      with:\n              invariantes: true\n";
        for (rotulo, env, no_workflow) in [
            (
                "num bloco",
                "    env:\n      nota: |\n            uses: ./.github/actions/compilador\n            \
                 id: compilador\n",
                true,
            ),
            (
                "num escalar simples",
                "    env:\n      nota: x\n            uses:./.github/actions/compilador\n            \
                 id:compilador\n",
                false,
            ),
        ] {
            let texto =
                ci.replacen(ligada, "", 1)
                    .replacen(cabeca, &format!("{cabeca}{matriz}{env}"), 1);
            assert_ne!(texto, ci, "{rotulo}");
            assert_eq!(as_invariantes_na_acao(&texto).len(), 1, "{rotulo}");
            // O `uses:` do bloco fora de um passo: a leitura do passo o acusa.
            let fora: Vec<String> = um(CI, &texto)
                .into_iter()
                .filter(|f| f.contains("no passo da conferência do compilador"))
                .collect();
            assert_eq!(fora.len(), usize::from(no_workflow), "{rotulo}: {fora:#?}");
        }
        // O texto antes do passo de verdade, que liga as invariantes, não é o
        // passo: o de verdade continua o primeiro.
        let antes = ci.replacen(
            cabeca,
            &format!(
                "{cabeca}    env:\n      nota: |\n            uses: ./.github/actions/compilador\n"
            ),
            1,
        );
        assert_ne!(antes, ci);
        assert_eq!(as_invariantes_na_acao(&antes), Vec::<String>::new());
        // O item de uma matriz com as chaves do passo, antes dos passos: o
        // YAML o lê como dados da matriz, e o passo de verdade, sem o `with:`.
        // As outras regras o leem como um passo com as chaves de um passo, e
        // a contagem fica igual: só a das invariantes o acusa.
        let item = "    strategy:\n      matrix:\n        include:\n          - name: O compilador\n            \
                    id: compilador\n            uses: ./.github/actions/compilador\n            with:\n              \
                    invariantes: true\n";
        let na_matriz = ci
            .replacen(ligada, "", 1)
            .replacen(cabeca, &format!("{cabeca}{item}"), 1);
        assert_ne!(na_matriz, ci);
        assert_eq!(as_invariantes_na_acao(&na_matriz).len(), 1);
        assert_eq!(um(CI, &na_matriz), Vec::<String>::new());
        // E com a entrada no passo de verdade, ligada.
        let com_a_entrada = ci.replacen(cabeca, &format!("{cabeca}{item}"), 1);
        assert_eq!(as_invariantes_na_acao(&com_a_entrada), Vec::<String>::new());
        // As peças: o `:` de uma chave, e o item que tem a linha.
        assert_eq!(chave_e_valor("uses:./.github/actions/compilador"), None);
        assert_eq!(chave_e_valor("- uses: ./x"), Some(("uses", "./x")));
        assert_eq!(chave_e_valor("chave:"), Some(("chave", "")));
        assert_eq!(chave_e_valor("chave:\tvalor"), Some(("chave", "valor")));
        assert_eq!(
            chave_e_valor("url: http://x:8080"),
            Some(("url", "http://x:8080"))
        );
        let linhas = linhas_de_codigo("x:\n  - a: 1\n    b: 2\ny: |\n    uses: z\n");
        assert_eq!(
            item_da_linha(&linhas, 2).map(|(c, f, _)| (c, f)),
            Some((1, 3))
        );
        assert!(linhas[4].escalar);
        assert_eq!(item_da_linha(&linhas, 4), None);
        let job = linhas_de_codigo(
            "  x:\n    strategy:\n      matrix:\n        include:\n          - uses: a\n    steps:\n      \
             - uses: b\n\n      - run: c\n        with:\n          - uses: d\n",
        );
        assert_eq!(passos_do_job(&job), vec![6, 8]);
    }

    /// A forma da ação, e cada passo pelo item dele (no lote A14, o M1 e o
    /// M2 do adversário do lote A13). Passavam: uma cópia de um passo, como
    /// o texto de um bloco de um passo anterior — uma string do Python, um
    /// heredoc —,
    /// com o de verdade com `if: false`, `continue-on-error: true` ou um
    /// embrulho no `env:`; o `shell:` de verdade depois do bloco, com o
    /// esperado como texto no começo do script; o `env:` das invariantes só
    /// como texto; os quatro passos numa chave a mais da raiz, com o
    /// `runs.steps` de outro passo, ou com o `runs.using` de um programa; o
    /// `runs.using` de outro tipo, com os passos; um
    /// quinto passo; o `outputs.canal` fixo, ou o canal fixo no `echo` do
    /// passo `conferir` — o N3 do revisor da rodada 6 —; e uma chave a mais
    /// na entrada, com um `id:`. Cada um reprova. A ação do repositório
    /// passa — também
    /// com o CRLF e o BOM do começo —, e o passo é o item de `runs.steps`.
    #[test]
    fn adversario_a13_a_forma_da_acao_e_os_passos_pelo_item() {
        assert_eq!(conferir_a_acao(ACAO), Vec::<String>::new());
        assert_eq!(
            conferir_a_acao(&ACAO.replace('\n', "\r\n")),
            Vec::<String>::new()
        );
        assert_eq!(
            conferir_a_acao(&format!("\u{feff}{ACAO}")),
            Vec::<String>::new()
        );
        let (shell, script) = passo_da_acao(ACAO, "conferir").expect("o passo");
        assert_eq!(shell, "bash");
        assert!(script.starts_with("set -euo pipefail\n"), "{script}");
        let no_ambiente = "        erros = []\n        # O ambiente do job, pela lista fechada.\n";
        let no_executor = "        erros = []\n        for diretorio in DIRETORIOS:\n";
        let do_conferir = "    - id: conferir\n      shell: bash\n      run: |\n";
        assert_eq!(ACAO.matches(no_ambiente).count(), 1);
        assert_eq!(ACAO.matches(no_executor).count(), 1);
        assert_eq!(ACAO.matches(do_conferir).count(), 1);
        // As cópias, como o texto de uma string do Python: as linhas que as
        // regras de antes liam.
        let copia_do_conferir = "        NOTA = \"\"\"\n            - id: conferir\n              shell: \
                                 bash\n              run: |\n                git diff --quiet HEAD -- \
                                 rust-toolchain.toml sdk/modelo/rust-toolchain.toml\n                \
                                 export RUSTUP_TOOLCHAIN=\"$canal\"\n                sysroot=$(rustc \
                                 --print sysroot)\n        \"\"\"\n";
        let copia_das_invariantes = "        NOTA = \"\"\"\n            - id: invariantes\n              \
                                     if: inputs.invariantes == 'true'\n              shell: bash\n              \
                                     env:\n                RUSTUP_TOOLCHAIN: ${{ \
                                     steps.conferir.outputs.canal }}\n              run: |\n                \
                                     cargo xtask invariantes\n        \"\"\"\n";
        let com = |onde: &str, copia: &str| ACAO.replacen(onde, &format!("{copia}{onde}"), 1);
        let entrada = "      if: inputs.invariantes == 'true'\n";
        let canal = "        RUSTUP_TOOLCHAIN: ${{ steps.conferir.outputs.canal }}\n";
        let fim_do_conferir = "        echo \"canal=$canal\" >> \"$GITHUB_OUTPUT\"\n";
        let runs = "runs:\n  using: composite\n  steps:\n";
        let um_passo = "    - id: conferir\n      shell: bash\n      run: |\n        echo \
                        \"canal=nightly-2026-11-15\" >> \"$GITHUB_OUTPUT\"\n";
        let (antes_de_runs, de_runs) = ACAO.split_at(ACAO.find(runs).expect("o runs"));
        let passos = &de_runs["runs:\n  using: composite\n".len()..];
        let casos: Vec<(&str, String)> = vec![
            (
                "o conferir com if: false, e uma copia no ambiente",
                com(no_ambiente, copia_do_conferir).replacen(
                    "\n    - id: conferir\n",
                    "\n    - id: conferir\n      if: false\n",
                    1,
                ),
            ),
            (
                "as invariantes com continue-on-error, e uma copia no executor",
                com(no_executor, copia_das_invariantes).replacen(
                    &format!("\n    - id: invariantes\n{entrada}"),
                    &format!("\n    - id: invariantes\n{entrada}      continue-on-error: true\n"),
                    1,
                ),
            ),
            (
                "as invariantes com um embrulho no env, e uma copia no executor",
                com(no_executor, copia_das_invariantes).replacen(
                    &format!("      env:\n{canal}"),
                    &format!("      env:\n{canal}        RUSTC_WRAPPER: ./x\n"),
                    1,
                ),
            ),
            (
                "o shell do conferir depois do bloco, e o esperado como texto",
                ACAO.replacen(
                    do_conferir,
                    "    - id: conferir\n      run: |\n        : <<'NOTA'\n        shell: bash\n        \
                     NOTA\n",
                    1,
                )
                .replacen(
                    fim_do_conferir,
                    &format!("{fim_do_conferir}      shell: /bin/true {{0}}\n"),
                    1,
                ),
            ),
            (
                "o env das invariantes so como texto",
                ACAO.replacen(
                    &format!("      env:\n{canal}      run: |\n"),
                    &format!("      run: |\n        : <<'NOTA'\n{canal}        NOTA\n"),
                    1,
                ),
            ),
            (
                "os passos numa chave a mais da raiz",
                format!("{antes_de_runs}copia:\n{passos}{runs}{um_passo}"),
            ),
            (
                "o runs de um programa em JavaScript",
                format!("{antes_de_runs}runs:\n  using: node20\n  main: x.js\ncopia:\n{passos}"),
            ),
            (
                "o runs.using de outro tipo, com os passos",
                ACAO.replacen("  using: composite\n", "  using: node20\n", 1),
            ),
            (
                "um quinto passo",
                ACAO.replacen(
                    "    - id: invariantes\n",
                    "    - id: depois\n      shell: bash\n      run: |\n        echo x\n\n    - id: \
                     invariantes\n",
                    1,
                ),
            ),
            (
                "o canal fixo",
                ACAO.replacen(
                    "    value: ${{ steps.conferir.outputs.canal }}\n",
                    "    value: nightly-2026-11-15\n",
                    1,
                ),
            ),
            (
                "o canal fixo no echo do conferir",
                ACAO.replacen(
                    fim_do_conferir,
                    "        echo \"canal=nightly-2026-11-15\" >> \"$GITHUB_OUTPUT\"\n",
                    1,
                ),
            ),
            (
                "uma chave a mais na entrada, com um id",
                ACAO.replacen(
                    "    default: 'false'\n",
                    "    default: 'false'\n    id: ambiente\n",
                    1,
                ),
            ),
        ];
        let mut cegos = Vec::new();
        for (rotulo, texto) in &casos {
            assert_ne!(texto, ACAO, "{rotulo}");
            if conferir_a_acao(texto).is_empty() {
                cegos.push(*rotulo);
            }
        }
        assert!(
            cegos.is_empty(),
            "a conferência da ação não acusou: {cegos:?}"
        );
        // O passo é o de verdade: o `shell:` dele, e não o do texto.
        let (shell, _) = passo_da_acao(&casos[3].1, "conferir").expect("o passo");
        assert_eq!(shell, "/bin/true {0}");
    }

    /// O que o job escolhe para a ação (no lote A14, o I1, o I2 e o I3 do
    /// adversário do lote A13, e o `HOME` e o `BASH_ENV` que o lote achou na
    /// revisão): o `container:` de um job; no `env:` do workflow ou de um
    /// job, o `LD_PRELOAD`, o `CC`, o `HOME`, o `XDG_CONFIG_HOME`, o
    /// `BASH_ENV`, o `GIT_INDEX_FILE` — qualquer nome fora da lista —, o
    /// valor na linha e uma linha que não é chave; o `GITHUB_ENV` de um passo;
    /// e o checkout com um `with:` — outro commit, outro repositório — ou com
    /// um `env:`. Passavam; cada um reprova, com a linha. O `env:` de um passo
    /// fica com ele, o checkout com o `name:` passa, e os workflows do
    /// repositório passam.
    #[test]
    fn adversario_a13_o_container_o_ambiente_e_o_checkout_dos_jobs() {
        let job = "  testes:\n    steps:\n";
        assert_eq!(OFICIAL.matches(job).count(), 1);
        let checkout = "      - uses: actions/checkout@v4\n";
        assert_eq!(OFICIAL.matches(checkout).count(), 1);
        let no_job =
            |linhas: &str| OFICIAL.replacen(job, &format!("  testes:\n{linhas}    steps:\n"), 1);
        let casos: Vec<(&str, String, &str)> = vec![
            (
                "o container de um job",
                no_job("    container: docker.io/library/rust:latest\n"),
                "`container: docker.io/library/rust:latest` — o `container:` de um job",
            ),
            (
                "o container com a imagem",
                no_job("    container:\n      image: docker.io/library/rust:latest\n"),
                "`container:` — o `container:` de um job",
            ),
            (
                "o LD_PRELOAD no env do workflow",
                format!("env:\n  LD_PRELOAD: ./ferramentas/x.so\n{OFICIAL}"),
                "`LD_PRELOAD: ./ferramentas/x.so` no `env:`",
            ),
            (
                "o CC no env do job",
                no_job("    env:\n      CC: ./ferramentas/cc\n"),
                "`CC: ./ferramentas/cc` no `env:`",
            ),
            (
                "o HOME no env do job",
                no_job("    env:\n      HOME: ${{ github.workspace }}/casa\n"),
                "`HOME: ${{ github.workspace }}/casa` no `env:`",
            ),
            (
                "o XDG_CONFIG_HOME no env do job",
                no_job("    env:\n      XDG_CONFIG_HOME: ./casa\n"),
                "`XDG_CONFIG_HOME: ./casa` no `env:`",
            ),
            (
                "o BASH_ENV no env do job",
                no_job("    env:\n      RUST_BACKTRACE: 1\n      BASH_ENV: ./ferramentas/x.sh\n"),
                "`BASH_ENV: ./ferramentas/x.sh` no `env:`",
            ),
            (
                "o GIT_INDEX_FILE no env do job",
                no_job("    env:\n      GIT_INDEX_FILE: /tmp/x\n"),
                "`GIT_INDEX_FILE: /tmp/x` no `env:`",
            ),
            (
                "o env do job com o valor na linha",
                no_job("    env: ${{ fromJSON(vars.AMBIENTE) }}\n"),
                "`env: ${{ fromJSON(vars.AMBIENTE) }}` — o `env:` do workflow, ou o de um job, com o \
                 valor na linha",
            ),
            (
                "uma linha mais funda no env do job",
                no_job("    env:\n      CARGO_TERM_COLOR: always\n        LD_PRELOAD: x\n"),
                "`LD_PRELOAD: x` no `env:` do workflow, ou no de um job, que não é uma chave",
            ),
            (
                "um nome da lista mais fundo no env do job",
                no_job("    env:\n      CARGO_TERM_COLOR: always\n        RUST_BACKTRACE: 1\n"),
                "`RUST_BACKTRACE: 1` no `env:` do workflow, ou no de um job, que não é uma chave",
            ),
            (
                "uma lista no env do job",
                no_job("    env:\n      - LD_PRELOAD=x\n"),
                "`- LD_PRELOAD=x` no `env:` do workflow, ou no de um job, que não é uma chave",
            ),
            (
                "o GITHUB_ENV de um passo",
                OFICIAL.replacen(
                    checkout,
                    &format!("{checkout}      - run: echo \"LD_PRELOAD=x\" >> \"$GITHUB_ENV\"\n"),
                    1,
                ),
                "`GITHUB_ENV` sobrepõe",
            ),
            (
                "o checkout de outro commit",
                OFICIAL.replacen(
                    checkout,
                    &format!("{checkout}        with:\n          ref: 1111111111111111111111111111111111111111\n"),
                    1,
                ),
                "`with: ` no checkout",
            ),
            (
                "o checkout de outro repositorio",
                OFICIAL.replacen(
                    checkout,
                    &format!("{checkout}        with:\n          repository: outro/repositorio\n"),
                    1,
                ),
                "`with: ` no checkout",
            ),
            (
                "o checkout com o env",
                OFICIAL.replacen(
                    checkout,
                    &format!("{checkout}        env:\n          GIT_INDEX_FILE: /tmp/x\n"),
                    1,
                ),
                "`env: ` no checkout",
            ),
        ];
        let mut cegos = Vec::new();
        for (rotulo, texto, esperado) in &casos {
            assert_ne!(texto, OFICIAL, "{rotulo}");
            let fora = um(CI, texto);
            if !fora.iter().any(|f| f.contains(*esperado)) {
                cegos.push(format!("{rotulo}: {fora:#?}"));
            }
        }
        assert!(cegos.is_empty(), "{cegos:#?}");
        // O `env:` de um passo fica com ele; o do job, com os nomes da lista,
        // passa; o checkout com o `name:` também.
        for texto in [
            OFICIAL.replacen(
                "        run: cargo xtask test\n",
                "        run: cargo xtask test\n        env:\n          DUKE_PARTE: 1/2\n",
                1,
            ),
            no_job("    env:\n      DUKE_PARES: x86_64-aarch64\n      DUKE_NUCLEOS: 2\n"),
            OFICIAL.replacen(
                checkout,
                "      - name: O checkout\n        uses: actions/checkout@v4\n",
                1,
            ),
        ] {
            assert_ne!(texto, OFICIAL);
            assert_eq!(um(CI, &texto), Vec::<String>::new(), "{texto}");
        }
        // Os workflows do repositório passam.
        for (nome, texto) in [
            (CI, include_str!("../../.github/workflows/ci.yml")),
            (
                ".github/workflows/rede-principal.yml",
                include_str!("../../.github/workflows/rede-principal.yml"),
            ),
        ] {
            assert_eq!(
                o_que_o_job_escolhe(nome, &linhas_de_codigo(texto)),
                Vec::<String>::new()
            );
        }
    }

    /// Um documento só (no lote A14, o I4 do adversário do lote A13): um
    /// segundo documento — vazio, ou com um job —, o fim do documento e o
    /// começo com alguma coisa depois (`--- !!map`) reprovam, também na ação
    /// do compilador; o `---` sozinho na primeira linha de código — depois
    /// de um comentário, com um comentário — passa, e o `---` do conteúdo de
    /// um bloco é texto. Os workflows e a ação do repositório não têm nenhum.
    #[test]
    fn adversario_a13_um_documento_so() {
        let marcador = |fora: &[String]| {
            fora.iter()
                .filter(|f| f.contains(" — um marcador de documento do YAML"))
                .count()
        };
        for (rotulo, texto) in [
            ("um segundo documento vazio", format!("{OFICIAL}---\n")),
            ("o fim do documento", format!("{OFICIAL}...\n# fim\n")),
            (
                "um segundo documento com um job",
                format!(
                    "{OFICIAL}---\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n"
                ),
            ),
            ("o começo com uma etiqueta", format!("--- !!map\n{OFICIAL}")),
            (
                "o começo depois de uma chave",
                format!("on: push\n---\n{OFICIAL}"),
            ),
        ] {
            assert_eq!(marcador(&um(CI, &texto)), 1, "{rotulo}");
        }
        assert_eq!(
            marcador(&um(ACAO_DO_COMPILADOR, &format!("{ACAO}---\n"))),
            1
        );
        for texto in [
            format!("---\n{OFICIAL}"),
            format!("# O workflow.\n---\n{OFICIAL}"),
            format!("--- # o começo\n{OFICIAL}"),
            OFICIAL.replacen(
                "        run: cargo xtask test\n",
                "        run: |\n          cat <<'FIM'\n          ---\n          ...\n          FIM\n          \
                 cargo xtask test\n",
                1,
            ),
        ] {
            assert_ne!(texto, OFICIAL);
            assert_eq!(um(CI, &texto), Vec::<String>::new(), "{texto}");
        }
        for texto in [
            include_str!("../../.github/workflows/ci.yml"),
            include_str!("../../.github/workflows/rede-principal.yml"),
            include_str!("../../.github/workflows/canario.yml"),
            ACAO,
        ] {
            assert!(marcadores_de_documento(&linhas_de_codigo(texto)).is_empty());
        }
    }

    /// Os comandos do runner, o `GITHUB_ENV` e o `GITHUB_PATH` por outro nome
    /// (o M1 do adversário do lote A14): o `ACTIONS_ALLOW_UNSECURE_COMMANDS`
    /// no `env:` de um passo — antes da ação, ou depois dela —, e o
    /// `::set-env` e o `::add-path` num `run:`, punham uma variável ou uma
    /// pasta do PATH no ambiente de todo passo seguinte, por fora da lista
    /// fechada do `env:` dos jobs, e passavam. Cada um reprova, com a linha,
    /// também numa ação local — e, na revisão do lote A15, também nas formas
    /// que o runner lê e o texto do patch não via: a antiga (`##[set-env …]`)
    /// e outra caixa, também a do `ſ` —; e, na ação do compilador, os dois
    /// comandos, em toda forma. Os outros comandos (`::set-output`,
    /// `::add-mask`, `::error`) e o nome sem o prefixo passam, e os workflows
    /// do repositório também.
    #[test]
    fn adversario_a14_os_comandos_do_runner_sao_o_github_env_por_outro_nome() {
        let checkout = "      - uses: actions/checkout@v4\n";
        assert_eq!(OFICIAL.matches(checkout).count(), 1);
        let fim = "        run: cargo xtask test\n";
        assert_eq!(OFICIAL.matches(fim).count(), 1);
        let set_env = "o comando `set-env` do runner";
        let add_path = "o comando `add-path` do runner";
        let antes = OFICIAL.replacen(
            checkout,
            &format!(
                "{checkout}      - env:\n          ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n        \
                 run: echo \"::set-env name=BASH_ENV::./x.sh\"\n"
            ),
            1,
        );
        // Um passo depois da ação, com a linha no bloco do `run:` — num
        // escalar simples, o ` #` começaria um comentário do YAML.
        let depois = |linha: &str| format!("{OFICIAL}      - run: |\n          {linha}\n");
        let casos: Vec<(&str, String, &str)> = vec![
            (
                "o env de um passo antes da ação",
                antes.clone(),
                "`ACTIONS_ALLOW_UNSECURE_COMMANDS: true` — `ACTIONS_ALLOW_UNSECURE_COMMANDS` sobrepõe",
            ),
            ("o set-env antes da ação", antes, set_env),
            (
                "o env de um passo depois da ação",
                OFICIAL.replacen(
                    fim,
                    &format!(
                        "{fim}        env:\n          ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'\n"
                    ),
                    1,
                ),
                "`ACTIONS_ALLOW_UNSECURE_COMMANDS: 'true'` — `ACTIONS_ALLOW_UNSECURE_COMMANDS` sobrepõe",
            ),
            (
                "o add-path num run",
                depois("echo \"::add-path::/tmp/ferramentas\""),
                add_path,
            ),
            (
                "o set-env na forma antiga",
                depois("echo \"##[set-env name=BASH_ENV;]./x.sh\""),
                set_env,
            ),
            (
                "o add-path na forma antiga, no meio da linha",
                depois("echo \"x ##[add-path]/tmp/ferramentas\""),
                add_path,
            ),
            (
                "o set-env em maiúsculas",
                depois("echo \"::SET-ENV name=BASH_ENV::./x.sh\""),
                set_env,
            ),
            (
                "o add-path em outra caixa",
                depois("echo \"::Add-Path::/tmp/ferramentas\""),
                add_path,
            ),
            (
                "o set-env com o ſ",
                depois("echo \"::\u{17f}et-env name=BASH_ENV::./x.sh\""),
                set_env,
            ),
        ];
        let mut cegos = Vec::new();
        for (rotulo, texto, esperado) in &casos {
            assert_ne!(texto, OFICIAL, "{rotulo}");
            let fora = um(CI, texto);
            if !fora.iter().any(|f| f.contains(*esperado)) {
                cegos.push(format!("{rotulo}: {fora:#?}"));
            }
        }
        assert!(cegos.is_empty(), "{cegos:#?}");
        // Passam: os outros comandos do runner, e o nome sem o prefixo.
        for linha in [
            "echo \"::set-output name=x::y\"",
            "echo \"::add-mask::x\"",
            "echo \"::error::o set-env e o add-path estão desligados\"",
        ] {
            assert_eq!(um(CI, &depois(linha)), Vec::<String>::new(), "{linha}");
        }
        // Numa ação local, as mesmas regras.
        let local = "runs:\n  using: composite\n  steps:\n    - run: echo \"::set-env name=X::y\"\n      \
                     shell: bash\n      env:\n        ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n";
        let fora = um(".github/actions/outra/action.yml", local);
        for esperado in [set_env, "`ACTIONS_ALLOW_UNSECURE_COMMANDS` sobrepõe"] {
            assert!(
                fora.iter().any(|f| f.contains(esperado)),
                "{esperado}: {fora:#?}"
            );
        }
        // Na ação do compilador, os dois comandos, em toda forma.
        let ultima = "        echo \"canal=$canal\" >> \"$GITHUB_OUTPUT\"\n";
        assert_eq!(ACAO.matches(ultima).count(), 1);
        for comando in [
            "echo \"::set-env name=BASH_ENV::x\"",
            "echo \"::add-path::/tmp/x\"",
            "echo \"##[set-env name=BASH_ENV;]x\"",
            "echo \"::ADD-PATH::/tmp/x\"",
        ] {
            let acao = ACAO.replacen(ultima, &format!("{ultima}        {comando}\n"), 1);
            let fora = conferir_a_acao(&acao);
            assert!(
                fora.iter().any(|f| f.contains(
                    "a ação do compilador não cita o `GITHUB_ENV`, o `GITHUB_PATH` nem os comandos"
                )),
                "{comando}: {fora:#?}"
            );
        }
        // Os workflows do repositório passam.
        for (nome, texto) in [
            (CI, include_str!("../../.github/workflows/ci.yml")),
            (
                ".github/workflows/rede-principal.yml",
                include_str!("../../.github/workflows/rede-principal.yml"),
            ),
        ] {
            assert_eq!(um(nome, texto), Vec::<String>::new(), "{nome}");
        }
        assert_eq!(conferir_a_acao(ACAO), Vec::<String>::new());
    }

    /// Os jobs começam pelo checkout e pela ação (o M2 do adversário do lote
    /// A14): um passo entre o checkout e a ação — o `git checkout` da pasta
    /// dela de outro commit, um toolchain com o nome do oficial, o
    /// `core.fsmonitor`, um script do repositório —, um antes do checkout — o
    /// cache do `~/.rustup`, um `run:` com o `sudo` —, um job sem o checkout,
    /// que clona e roda o `cargo`, um job só com o checkout, um job sem passos
    /// e um workflow sem o `jobs:` passavam pela ordem; cada um reprova, uma
    /// vez, com o nome do job — também a ação logo depois de um clone, sem o
    /// checkout. E, na revisão do lote A15, o checkout num bloco `parallel:`,
    /// e o checkout ou a conferência com `background: true`, reprovam, cada
    /// um pela regra dele. O nome no checkout, um segundo job que começa pelos
    /// dois, uma chave da raiz depois do `jobs:` e os workflows do repositório
    /// passam.
    #[test]
    fn adversario_a14_os_jobs_comecam_pelo_checkout_e_pela_acao() {
        let checkout = "      - uses: actions/checkout@v4\n";
        let passos = "    steps:\n";
        assert_eq!(OFICIAL.matches(checkout).count(), 1);
        assert_eq!(OFICIAL.matches(passos).count(), 1);
        let entre = |passo: &str| OFICIAL.replacen(checkout, &format!("{checkout}{passo}"), 1);
        let antes = |passo: &str| OFICIAL.replacen(passos, &format!("{passos}{passo}"), 1);
        let testes = "o job `testes` não começa pelo checkout e pela conferência do compilador";
        let outro = "o job `outro` não começa pelo checkout e pela conferência do compilador";
        let casos: Vec<(&str, String, &str)> = vec![
            (
                "a ação de outro commit",
                entre("      - run: git checkout FETCH_HEAD -- .github/actions/compilador\n"),
                testes,
            ),
            (
                "um toolchain com o nome do oficial",
                entre(
                    "      - run: mkdir -p ~/.rustup/toolchains/nightly-2026-11-15-x86_64-unknown-linux-gnu\n",
                ),
                testes,
            ),
            (
                "o fsmonitor no .git/config",
                entre("      - run: git config core.fsmonitor ./ferramentas/monitor\n"),
                testes,
            ),
            (
                "um script do repositório",
                entre("      - name: Preparar\n        run: ./ferramentas/preparar.sh\n"),
                testes,
            ),
            (
                "o cache do rustup antes do checkout",
                antes(
                    "      - uses: actions/cache@v4\n        with:\n          path: ~/.rustup\n          \
                     key: rustup-${{ steps.compilador.outputs.canal }}\n",
                ),
                testes,
            ),
            (
                "o sudo antes do checkout",
                antes("      - run: sudo install -m 0755 /dev/stdin /usr/bin/python3\n"),
                testes,
            ),
            (
                "um job sem o checkout",
                format!(
                    "{OFICIAL}  outro:\n    steps:\n      - run: git clone https://github.com/x/y . && \
                     cargo xtask test\n"
                ),
                outro,
            ),
            (
                "um job só com o checkout",
                format!("{OFICIAL}  outro:\n    steps:\n      - uses: actions/checkout@v4\n"),
                outro,
            ),
            (
                "a ação depois de um clone, sem o checkout",
                format!(
                    "{OFICIAL}  outro:\n    steps:\n      - run: git clone --branch outro \
                     https://github.com/x/y .\n      - id: compilador\n        uses: \
                     ./.github/actions/compilador\n"
                ),
                outro,
            ),
            (
                "um job sem passos",
                format!("{OFICIAL}  outro:\n    runs-on: ubuntu-latest\n"),
                outro,
            ),
            (
                "um workflow sem o jobs",
                OFICIAL.replacen("jobs:\n", "trabalhos:\n", 1),
                "sem o `jobs:` em bloco",
            ),
            // Na revisão do lote A15, os passos que o esquema dos workflows
            // ganhou — o bloco `parallel:`, que roda os passos dele juntos, e
            // o `background:`, que segue sem esperar o passo —: o primeiro
            // passo não é o checkout, ou um dos dois tem uma chave que a
            // regra dele não aceita.
            (
                "o checkout num bloco parallel, com um script",
                OFICIAL.replacen(
                    checkout,
                    "      - parallel:\n          - uses: actions/checkout@v4\n          - run: \
                     ./ferramentas/preparar.sh\n",
                    1,
                ),
                testes,
            ),
            (
                "o checkout em segundo plano",
                OFICIAL.replacen(
                    checkout,
                    &format!("{checkout}        background: true\n"),
                    1,
                ),
                "`background: true` no checkout",
            ),
            (
                "a conferência em segundo plano",
                OFICIAL.replacen(
                    "        uses: ./.github/actions/compilador\n",
                    "        uses: ./.github/actions/compilador\n        background: true\n",
                    1,
                ),
                "`background: true` no passo da conferência do compilador",
            ),
        ];
        let mut cegos = Vec::new();
        for (rotulo, texto, esperado) in &casos {
            assert_ne!(texto, OFICIAL, "{rotulo}");
            let fora = um(CI, texto);
            if fora.iter().filter(|f| f.contains(*esperado)).count() != 1 {
                cegos.push(format!("{rotulo}: {fora:#?}"));
            }
        }
        assert!(cegos.is_empty(), "{cegos:#?}");
        // Passam: o nome no checkout, e um segundo job que começa pelos dois.
        for texto in [
            OFICIAL.replacen(
                checkout,
                "      - name: O checkout\n        uses: actions/checkout@v4\n",
                1,
            ),
            format!(
                "{OFICIAL}  outro:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: \
                 actions/checkout@v4\n      - id: compilador\n        uses: \
                 ./.github/actions/compilador\n      - run: cargo xtask fumaca\n"
            ),
            format!("{OFICIAL}env:\n  RUST_BACKTRACE: 1\n"),
        ] {
            assert_ne!(texto, OFICIAL);
            assert_eq!(um(CI, &texto), Vec::<String>::new(), "{texto}");
        }
        // Os workflows do repositório passam.
        for (nome, texto) in [
            (CI, include_str!("../../.github/workflows/ci.yml")),
            (
                ".github/workflows/rede-principal.yml",
                include_str!("../../.github/workflows/rede-principal.yml"),
            ),
        ] {
            assert_eq!(
                o_comeco_dos_jobs(nome, &linhas_de_codigo(texto)),
                Vec::<String>::new()
            );
        }
    }

    /// Os serviços de um job (o M3 do adversário do lote A14): o runner sobe
    /// os `services:` antes do primeiro passo, com o `volumes:` montado do
    /// runner e o `options:` cru no `docker create`, e eles passavam — o
    /// `container:` reprovava, e o serviço escreve nas mesmas pastas. Cada
    /// forma reprova, uma vez, com a linha — também o serviço sem nada
    /// montado —; e os workflows do repositório passam.
    #[test]
    fn adversario_a14_os_servicos_dos_jobs() {
        let job = "  testes:\n    steps:\n";
        assert_eq!(OFICIAL.matches(job).count(), 1);
        let no_job =
            |linhas: &str| OFICIAL.replacen(job, &format!("  testes:\n{linhas}    steps:\n"), 1);
        let servico = "`services:` — os `services:` de um job sobem antes do primeiro passo dele";
        for (rotulo, texto) in [
            (
                "o /usr/bin montado",
                no_job(
                    "    services:\n      banco:\n        image: docker.io/library/busybox:1.36\n        \
                     volumes:\n          - /usr/bin:/hospedeiro\n",
                ),
            ),
            (
                "o ~/.cargo pelo options",
                no_job(
                    "    services:\n      banco:\n        image: docker.io/library/busybox:1.36\n        \
                     options: --entrypoint /bin/sh -v /home/runner/.cargo:/casa\n",
                ),
            ),
            (
                "um serviço sem nada montado",
                no_job(
                    "    services:\n      banco:\n        image: docker.io/library/postgres:16\n",
                ),
            ),
        ] {
            assert_ne!(texto, OFICIAL, "{rotulo}");
            let fora = um(CI, &texto);
            assert_eq!(
                fora.iter().filter(|f| f.contains(servico)).count(),
                1,
                "{rotulo}: {fora:#?}"
            );
        }
        for (nome, texto) in [
            (CI, include_str!("../../.github/workflows/ci.yml")),
            (
                ".github/workflows/rede-principal.yml",
                include_str!("../../.github/workflows/rede-principal.yml"),
            ),
        ] {
            assert_eq!(
                o_que_o_job_escolhe(nome, &linhas_de_codigo(texto)),
                Vec::<String>::new()
            );
        }
    }

    /// As versões das ações permitidas (o M4 do adversário do lote A14): o
    /// checkout por um commit — que o GitHub resolve também num
    /// fork da rede do repositório da ação —, o cache por um ramo e a
    /// publicação por outra versão passavam, porque a regra lia só o nome;
    /// cada um reprova, com o `uses:` inteiro, também numa ação local — e a
    /// conferência com uma versão, que a da lista não tem. As versões da
    /// lista, entre aspas ou não, e as do canário passam, e os workflows do
    /// repositório também.
    #[test]
    fn adversario_a14_as_versoes_das_acoes() {
        let checkout = "      - uses: actions/checkout@v4\n";
        let cache = "        uses: actions/cache@v4\n";
        assert_eq!(OFICIAL.matches(checkout).count(), 1);
        assert_eq!(OFICIAL.matches(cache).count(), 1);
        let versao = "a versão de uma ação permitida fora da lista";
        for (rotulo, texto, esperado) in [
            (
                "o checkout por um commit",
                OFICIAL.replacen(
                    checkout,
                    "      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n",
                    1,
                ),
                "`actions/checkout@0123456789abcdef0123456789abcdef01234567` — ",
            ),
            (
                "o cache por um ramo",
                OFICIAL.replacen(cache, "        uses: actions/cache@main\n", 1),
                "`actions/cache@main` — ",
            ),
            (
                "a publicação por outra versão",
                format!("{OFICIAL}      - uses: actions/upload-artifact@v3\n"),
                "`actions/upload-artifact@v3` — ",
            ),
            // Na revisão do lote A15: a ação local, que não tem versão.
            (
                "a conferência com uma versão",
                OFICIAL.replacen(
                    "        uses: ./.github/actions/compilador\n",
                    "        uses: ./.github/actions/compilador@v1\n",
                    1,
                ),
                "`./.github/actions/compilador@v1` — ",
            ),
        ] {
            assert_ne!(texto, OFICIAL, "{rotulo}");
            let fora = um(CI, &texto);
            assert_eq!(
                fora.iter()
                    .filter(|f| f.contains(esperado) && f.contains(versao))
                    .count(),
                1,
                "{rotulo}: {fora:#?}"
            );
        }
        let local = "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@main\n";
        assert!(
            um(".github/actions/outra/action.yml", local)
                .iter()
                .any(|f| f.contains("`actions/checkout@main` — ") && f.contains(versao)),
        );
        // Passam: a versão da lista entre aspas, e as do canário.
        let aspas = OFICIAL.replacen(checkout, "      - uses: 'actions/checkout@v4'\n", 1);
        assert_ne!(aspas, OFICIAL);
        assert_eq!(um(CI, &aspas), Vec::<String>::new());
        for (nome, texto) in [
            (CI, include_str!("../../.github/workflows/ci.yml")),
            (
                ".github/workflows/rede-principal.yml",
                include_str!("../../.github/workflows/rede-principal.yml"),
            ),
            (CANARIO, include_str!("../../.github/workflows/canario.yml")),
        ] {
            assert!(
                !um(nome, texto).iter().any(|f| f.contains(versao)),
                "{nome}"
            );
        }
    }

    /// O canal que o passo `conferir` escreve (o B1 do adversário do lote
    /// A14): a marca da saída provava que a linha existe, e não o valor — o
    /// canal fixo numa linha antes dela, e um segundo `echo` depois, passavam.
    /// Reprovam agora, cada um pela regra do canal: as duas formas dele, e as
    /// outras que dão valor ao nome — o `read`, o `printf -v`, o `declare`, o
    /// `unset` com o padrão da expansão, a aritmética, o `::set-output` —, a
    /// saída escrita pelo `tee` ou na mesma linha da marca, o canal
    /// reatribuído na linha da marca ou numa cópia da linha da leitura — as
    /// duas só valem inteiras —, e uma função, o `PATH` ou a leitura de outro
    /// arquivo antes da linha que lê o canal. As expansões passam, e a ação
    /// do repositório também; os comentários com a palavra, desde o lote A16,
    /// reprovam (`adversario_a15_o_canal_do_passo_conferir_em_toda_linha`).
    #[test]
    fn adversario_a14_o_canal_que_o_passo_conferir_escreve() {
        let saida = format!("        {SAIDA_DO_CANAL}\n");
        let leitura = format!("        {LEITURA_DO_CANAL}\n");
        assert_eq!(ACAO.matches(&saida).count(), 1);
        assert_eq!(ACAO.matches(&leitura).count(), 1);
        let antes_da_saida =
            |linha: &str| ACAO.replacen(&saida, &format!("        {linha}\n{saida}"), 1);
        let depois_da_saida =
            |linha: &str| ACAO.replacen(&saida, &format!("{saida}        {linha}\n"), 1);
        let antes_da_leitura =
            |linha: &str| ACAO.replacen(&leitura, &format!("        {linha}\n{leitura}"), 1);
        let nome = "no passo `conferir` — o nome `canal`, fora da expansão";
        let comeco =
            "o passo `conferir` não começa pelo `set -euo pipefail` e pela linha que lê o canal";
        let escrita = "o passo `conferir` cita o `GITHUB_OUTPUT`";
        let casos: Vec<(&str, String, &str)> = vec![
            (
                "o canal reatribuído antes da saída",
                antes_da_saida("canal=nightly-2000-01-01"),
                nome,
            ),
            (
                "um segundo echo depois da saída",
                depois_da_saida("echo \"canal=nightly-2000-01-01\" >> \"$GITHUB_OUTPUT\""),
                escrita,
            ),
            (
                "o read",
                antes_da_saida("read -r canal <<< nightly-2000-01-01"),
                nome,
            ),
            (
                "o printf -v",
                antes_da_saida("printf -v canal '%s' nightly-2000-01-01"),
                nome,
            ),
            (
                "o declare",
                antes_da_saida("declare canal=nightly-2000-01-01"),
                nome,
            ),
            (
                "o unset e o padrão da expansão",
                antes_da_saida("unset canal; : \"${canal:=nightly-2000-01-01}\""),
                nome,
            ),
            (
                "o padrão da expansão sozinho",
                antes_da_saida(": \"${canal=nightly-2000-01-01}\""),
                nome,
            ),
            ("a aritmética", antes_da_saida("(( canal = 1 ))"), nome),
            (
                "o set-output",
                depois_da_saida("echo \"::set-output name=canal::nightly-2000-01-01\""),
                nome,
            ),
            (
                "o tee",
                depois_da_saida("echo \"x=y\" | tee -a \"$GITHUB_OUTPUT\""),
                escrita,
            ),
            (
                "a saída e outra escrita na mesma linha",
                ACAO.replacen(
                    &saida,
                    &format!("        {SAIDA_DO_CANAL}; echo \"x=y\" >> \"$GITHUB_OUTPUT\"\n"),
                    1,
                ),
                escrita,
            ),
            (
                "o canal reatribuído na linha da saída, antes dela",
                ACAO.replacen(
                    &saida,
                    &format!("        canal=nightly-2000-01-01; {SAIDA_DO_CANAL}\n"),
                    1,
                ),
                nome,
            ),
            (
                "a linha da leitura de novo, com outra atribuição",
                antes_da_saida(&format!("{LEITURA_DO_CANAL}; canal=nightly-2000-01-01")),
                nome,
            ),
            (
                "uma função antes da leitura",
                antes_da_leitura("python3() { echo nightly-2000-01-01; }"),
                comeco,
            ),
            (
                "o PATH antes da leitura",
                antes_da_leitura("PATH=/tmp/falsos:$PATH"),
                comeco,
            ),
            (
                "a leitura de outro arquivo",
                ACAO.replacen(
                    "open(\"rust-toolchain.toml\", \"rb\"))[\"toolchain\"]",
                    "open(\"outro.toml\", \"rb\"))[\"toolchain\"]",
                    1,
                ),
                comeco,
            ),
        ];
        let mut cegos = Vec::new();
        for (rotulo, texto, esperado) in &casos {
            assert_ne!(texto, ACAO, "{rotulo}");
            let fora = conferir_a_acao(texto);
            if fora.iter().filter(|f| f.contains(*esperado)).count() != 1 {
                cegos.push(format!("{rotulo}: {fora:#?}"));
            }
        }
        assert!(cegos.is_empty(), "{cegos:#?}");
        // Passam as expansões do nome.
        let texto = antes_da_saida("echo \"conferido: $canal ${canal} ${#canal} ${canal:-x}\"");
        assert_ne!(texto, ACAO);
        assert_eq!(conferir_a_acao(&texto), Vec::<String>::new(), "{texto}");
        assert_eq!(conferir_a_acao(ACAO), Vec::<String>::new());
        // As peças: o nome inteiro, fora da expansão.
        assert!(cita_o_nome("canal=x", "canal"));
        assert!(cita_o_nome("x \"${canal:=y}\"", "canal"));
        assert!(!cita_o_nome(
            "x $canal ${canal} ${!canal} ${#canal}",
            "canal"
        ));
        assert!(!cita_o_nome("x $canal_novo canais o_canal", "canal"));
    }

    /// O canal do passo `conferir` em toda linha (o E1 do revisor da rodada 8
    /// e o B1 do adversário do lote A15): a regra do lote A15 conferia pela
    /// posição só as duas primeiras linhas de código — uma cópia exata da
    /// linha da leitura, mais abaixo, passava — e tirava as que começam por
    /// `#`, que o bash roda num texto em várias linhas. Reprovam agora, cada
    /// um uma vez, pela parte da regra dele: a cópia exata da leitura, depois
    /// de um `cd` ou sozinha; as duas formas do adversário, com a linha que
    /// começa por `#` dentro de um texto; o comentário com a palavra ou com o
    /// `GITHUB_OUTPUT`; a saída que não é a última linha; e a função — com os
    /// parênteses, com espaços entre eles, numa linha continuada, com a
    /// palavra `function` —, o apelido — o `alias`, o `expand_aliases`, o
    /// `BASH_ALIASES` — e o `enable`, que trocam o `echo` da saída sem citar
    /// o nome. O comentário com o `$canal` passa, e a ação do repositório
    /// também.
    #[test]
    fn adversario_a15_o_canal_do_passo_conferir_em_toda_linha() {
        let saida = format!("        {SAIDA_DO_CANAL}\n");
        let leitura = format!("        {LEITURA_DO_CANAL}\n");
        assert_eq!(ACAO.matches(&saida).count(), 1);
        assert_eq!(ACAO.matches(&leitura).count(), 1);
        let antes_da_saida = |linhas: &str| ACAO.replacen(&saida, &format!("{linhas}{saida}"), 1);
        let uma = |linha: &str| format!("        {linha}\n");
        let nome = "no passo `conferir` — o nome `canal`, fora da expansão";
        let copia = "linha(s) iguais à que lê o canal";
        let escrita = "o passo `conferir` cita o `GITHUB_OUTPUT`";
        let funcao = "a definição de uma função";
        let apelido = "um apelido do bash";
        let enable = "o `enable`, que troca um comando interno";
        let casos: Vec<(&str, String, &str)> = vec![
            (
                "a cópia exata da leitura antes da saída",
                antes_da_saida(&leitura),
                copia,
            ),
            (
                "um cd e a cópia da leitura",
                antes_da_saida(&format!("{}{leitura}", uma("cd /tmp/outro"))),
                copia,
            ),
            (
                "a linha que começa por # num texto, depois da saída",
                ACAO.replacen(
                    &saida,
                    &format!(
                        "{saida}{}{}",
                        uma(": \""),
                        uma("#$(echo canal=nightly-2000-01-01 >> \"$GITHUB_OUTPUT\")\"")
                    ),
                    1,
                ),
                nome,
            ),
            (
                "a atribuição numa linha que começa por # num texto",
                antes_da_saida(&format!(
                    "{}{}{}",
                    uma(": \""),
                    uma("#\"; canal=nightly-2000-01-01; : \""),
                    uma("\"")
                )),
                nome,
            ),
            (
                "o comentário com a palavra",
                antes_da_saida(&uma("# o canal do arquivo, conferido acima")),
                nome,
            ),
            (
                "o comentário com a palavra, antes da leitura",
                ACAO.replacen(
                    &leitura,
                    &format!("{}{leitura}", uma("# o canal sai da linha de baixo")),
                    1,
                ),
                nome,
            ),
            (
                "o comentário com o GITHUB_OUTPUT",
                antes_da_saida(&uma("# a linha de baixo escreve no GITHUB_OUTPUT")),
                escrita,
            ),
            (
                "a saída antes da última linha",
                ACAO.replacen(&saida, &format!("{saida}{}", uma("true")), 1),
                escrita,
            ),
            (
                "uma função echo",
                antes_da_saida(&uma(
                    "echo() { printf '%s=nightly-2000-01-01\\n' \"${1%%=*}\"; }",
                )),
                funcao,
            ),
            (
                "os parênteses com espaços",
                antes_da_saida(&uma("echo ( ) { printf '%s\\n' x; }")),
                funcao,
            ),
            (
                "a função numa linha continuada",
                antes_da_saida(&format!("{}{}", uma("echo (\\"), uma(") { printf x; }"))),
                funcao,
            ),
            (
                "a palavra function",
                antes_da_saida(&uma("function echo { printf x; }")),
                funcao,
            ),
            (
                "o alias",
                antes_da_saida(&uma("alias echo='printf x'")),
                apelido,
            ),
            (
                "o expand_aliases",
                antes_da_saida(&uma("shopt -s expand_aliases")),
                apelido,
            ),
            (
                "o BASH_ALIASES",
                antes_da_saida(&uma("BASH_ALIASES[echo]='printf x'")),
                apelido,
            ),
            ("o enable", antes_da_saida(&uma("enable -n echo")), enable),
        ];
        let mut cegos = Vec::new();
        for (rotulo, texto, esperado) in &casos {
            assert_ne!(texto, ACAO, "{rotulo}");
            let fora = conferir_a_acao(texto);
            if fora.iter().filter(|f| f.contains(*esperado)).count() != 1 {
                cegos.push(format!("{rotulo}: {fora:#?}"));
            }
        }
        assert!(cegos.is_empty(), "{cegos:#?}");
        // Passam: o comentário com o `$canal`, e a ação do repositório.
        let com_expansao = antes_da_saida(&uma("# o $canal, conferido acima, vai para a saída"));
        assert_ne!(com_expansao, ACAO);
        assert_eq!(conferir_a_acao(&com_expansao), Vec::<String>::new());
        assert_eq!(conferir_a_acao(ACAO), Vec::<String>::new());
        // As peças da função, do apelido e do `enable`.
        for linha in [
            "f() {",
            "f ( ) {",
            "function f {",
            "\\alias x=y",
            "enable -n echo",
        ] {
            assert!(troca_um_comando(linha).is_some(), "{linha}");
        }
        for linha in [
            "x=$(rustc -V)",
            "print(open(\"a\", \"rb\"))",
            "functions enabled",
            "# (o core.fsmonitor)",
        ] {
            assert_eq!(troca_um_comando(linha), None, "{linha}");
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
        // passo de verdade, não é lido como o passo — desde o lote A15, um
        // passo antes da ação reprova pela ordem dos jobs
        // ([`o_comeco_dos_jobs`]), e só por ela —; e, depois da ação, passa.
        let lista =
            "      - name: Lista\n        run: |\n          - item: x\n            outro: y\n";
        let com_bloco = OFICIAL.replacen(checkout, &format!("{checkout}{lista}"), 1);
        let fora = um(nome, &com_bloco);
        assert!(
            fora.len() == 1
                && fora[0].contains("o job `testes` não começa pelo checkout e pela conferência"),
            "{fora:#?}"
        );
        let cache = "      - name: Cache do cargo\n";
        assert_eq!(OFICIAL.matches(cache).count(), 1);
        let depois = OFICIAL.replacen(cache, &format!("{lista}{cache}"), 1);
        assert_eq!(um(nome, &depois), Vec::<String>::new());
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

    /// Os falsos positivos do passo da ação (no lote A13, o M5 do adversário
    /// do lote A12): o `id` entre aspas, o `-` só com um comentário e o nome
    /// que começa por `-` são o passo de sempre para o YAML, e passam — na
    /// ação do compilador, também o `id` entre aspas e o `-` com um
    /// comentário; o `- ` seguido de um espaço e o `id` com um escape
    /// continuam reprovando.
    #[test]
    fn adversario_a12_os_falsos_positivos_do_passo_da_acao() {
        let nome = ".github/workflows/ci.yml";
        let passo = "      - name: O compilador\n        id: compilador\n        uses: ./.github/actions/compilador\n";
        assert_eq!(OFICIAL.matches(passo).count(), 1);
        // O YAML que o GitHub lê como o passo de sempre passa.
        for novo in [
            passo.replacen("id: compilador", "id: 'compilador'", 1),
            passo.replacen("id: compilador", "id: \"compilador\"", 1),
            passo.replacen(
                "      - name:",
                "      - # O compilador oficial\n        name:",
                1,
            ),
            passo.replacen("name: O compilador", "name: -- o compilador --", 1),
        ] {
            let texto = OFICIAL.replacen(passo, &novo, 1);
            assert_ne!(texto, OFICIAL, "{novo}");
            assert_eq!(um(nome, &texto), Vec::<String>::new(), "{novo}");
        }
        // O `-` seguido de um espaço continua um indicador; o `id` com um
        // escape, um valor que a leitura não lê como o `compilador`.
        for novo in [
            passo.replacen("name: O compilador", "name: - o compilador", 1),
            passo.replacen("id: compilador", "id: \"compil\\x61dor\"", 1),
        ] {
            let texto = OFICIAL.replacen(passo, &novo, 1);
            assert!(!um(nome, &texto).is_empty(), "{novo}");
        }
        // Na ação do compilador, o mesmo: o `id` entre aspas acha o passo, e
        // o `-` só com um comentário é um `-` sozinho.
        let acao = ACAO
            .replacen("    - id: ambiente\n", "    - id: 'ambiente'\n", 1)
            .replacen(
                "    - id: executor\n",
                "    - # o executor\n      id: executor\n",
                1,
            );
        assert_ne!(acao, ACAO);
        assert_eq!(conferir_a_acao(&acao), Vec::<String>::new());
        assert_eq!(um(ACAO_DO_COMPILADOR, &acao), Vec::<String>::new());
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
on: workflow_dispatch
cache-mode: none
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
        let base = "on:\n  schedule:\n    - cron: '17 4 * * 1'\n  workflow_dispatch:\ncache-mode: none\njobs:\n  canario:\n    steps:\n      - uses: actions/checkout@v4\n";
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

    /// O nome que o git cita (o M1 do adversário do lote A15): sem o `-z`, o
    /// `git ls-files` punha entre aspas, com os bytes em octal, o caminho com
    /// um acento — e com uma aspa ou uma barra invertida —, e a lista dos
    /// arquivos do repositório o pulava: um workflow `publicação.yml`, no
    /// índice ou fora dele, não passava por regra nenhuma. A lista tem cada
    /// caminho como ele é, e o workflow, lido, reprova pelas regras dele; a
    /// extensão em maiúsculas conta; um caminho que não é UTF-8 reprova a
    /// lista inteira.
    #[test]
    fn adversario_a15_o_nome_que_o_git_cita() {
        use std::os::unix::ffi::OsStrExt;
        let arvore =
            std::env::temp_dir().join(format!("xtask-nomes-citados-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&arvore);
        std::fs::create_dir_all(arvore.join(".github/workflows")).expect("a pasta");
        let git = |args: &[&str]| {
            let feito = Command::new("git")
                .args(["-c", "init.defaultBranch=x"])
                .args(args)
                .current_dir(&arvore)
                .output()
                .expect("o git");
            assert!(feito.status.success(), "git {args:?}: {feito:?}");
        };
        git(&["init", "-q"]);
        let fora = "jobs:\n  publicar:\n    steps:\n      - uses: actions/checkout@main\n";
        let nomes = [
            ".github/workflows/publicação.yml",
            ".github/workflows/aspas\"no nome.yml",
            ".github/workflows/barra\\invertida.yml",
            ".github/workflows/ci.yml",
        ];
        for nome in nomes {
            std::fs::write(arvore.join(nome), fora).expect(nome);
        }
        git(&["add", "--", "."]);
        // Um fora do índice, com acento também: o `--others` o lista.
        std::fs::write(arvore.join(".github/workflows/rascunho-ação.yml"), fora).expect("o novo");
        let lista = arquivos_do_repositorio(&arvore).expect("a lista");
        for nome in nomes
            .iter()
            .copied()
            .chain([".github/workflows/rascunho-ação.yml"])
        {
            assert!(lista.iter().any(|a| a == nome), "{nome}: {lista:?}");
            let texto = std::fs::read_to_string(arvore.join(nome)).expect(nome);
            assert!(
                um(nome, &texto)
                    .iter()
                    .any(|f| f.contains("`actions/checkout@main` — ")),
                "{nome}"
            );
        }
        assert!(!lista.iter().any(|a| a.starts_with('"')), "{lista:?}");
        // A lista dos workflows, da lista do repositório: o nome citado e a
        // extensão em maiúsculas também.
        for nome in nomes.iter().copied().chain([
            ".github/workflows/maiusculas.YML",
            ".github/actions/ação/action.Yaml",
        ]) {
            assert!(da_definicao_da_ci(nome), "{nome}");
        }
        for nome in [
            ".github/workflows/notas.md",
            "docs/ci.yml",
            ".github/ci.yml",
        ] {
            assert!(!da_definicao_da_ci(nome), "{nome}");
        }
        // Um caminho que não é UTF-8 reprova a lista.
        let latino = std::ffi::OsStr::from_bytes(b".github/workflows/publica\xe7\xe3o.yml");
        std::fs::write(arvore.join(latino), fora).expect("o latino");
        let erro = arquivos_do_repositorio(&arvore).expect_err("o caminho que não é UTF-8");
        assert!(erro.contains("não é UTF-8"), "{erro}");
        let _ = std::fs::remove_dir_all(&arvore);
    }

    /// As versões das ações no canário (o M2 do adversário do lote A15): o
    /// lote A15 o deixou de fora da lista das versões, e o checkout ou a
    /// publicação dele por um commit — que pode ser de um fork — ou por um
    /// ramo passavam; o canário grava no cache do ramo em que roda, que os
    /// jobs da CI restauram. Reprovam agora, uma vez cada, pela regra das
    /// versões; o canário do repositório passa, e o nome de uma ação fora da
    /// lista dele continua reprovando pela regra do nome.
    #[test]
    fn adversario_a15_as_versoes_do_canario() {
        let canario = include_str!("../../.github/workflows/canario.yml");
        let checkout = "        uses: actions/checkout@v4\n";
        let publicacao = "        uses: actions/upload-artifact@v4\n";
        assert_eq!(canario.matches(checkout).count(), 1);
        assert_eq!(canario.matches(publicacao).count(), 1);
        let versao = "a versão de uma ação permitida fora da lista";
        let commit = "0123456789abcdef0123456789abcdef01234567";
        for (rotulo, texto, esperado) in [
            (
                "o checkout por um commit",
                canario.replacen(
                    checkout,
                    &format!("        uses: actions/checkout@{commit}\n"),
                    1,
                ),
                format!("`actions/checkout@{commit}` — "),
            ),
            (
                "a publicação por um commit",
                canario.replacen(
                    publicacao,
                    &format!("        uses: actions/upload-artifact@{commit}\n"),
                    1,
                ),
                format!("`actions/upload-artifact@{commit}` — "),
            ),
            (
                "o checkout por um ramo",
                canario.replacen(checkout, "        uses: actions/checkout@main\n", 1),
                String::from("`actions/checkout@main` — "),
            ),
        ] {
            assert_ne!(texto, canario, "{rotulo}");
            let fora = um(CANARIO, &texto);
            assert_eq!(
                fora.iter()
                    .filter(|f| f.contains(&esperado) && f.contains(versao))
                    .count(),
                1,
                "{rotulo}: {fora:#?}"
            );
        }
        assert!(!um(CANARIO, canario).iter().any(|f| f.contains(versao)));
        // O cache, que a lista das versões tem, continua fora do canário pelo
        // nome.
        let com_cache = canario.replacen(checkout, "        uses: actions/cache@v4\n", 1);
        let fora = um(CANARIO, &com_cache);
        assert!(
            fora.iter()
                .any(|f| f.contains("`actions/cache` não é uma ação permitida")),
            "{fora:#?}"
        );
        assert!(!fora.iter().any(|f| f.contains(versao)), "{fora:#?}");
    }

    /// A CI e o canário achados pelo nome (o M3 do adversário do lote A15):
    /// a regra que confere que o job de lints liga as invariantes, e a que
    /// confere que o canário repete os comandos dele, só rodavam com o
    /// arquivo achado — a CI renomeada, sem a entrada, passava. A falta de
    /// cada um reprova, uma vez; com os dois, nada. E a definição da CI do
    /// repositório, pelas regras que a leem ([`conferir_a_definicao_da_ci`]):
    /// passa inteira, e cada troca — a CI renomeada sem a entrada, o canário
    /// ou a ação apagados, a CI sem a entrada, o canário sem um comando do
    /// job de lints, o checkout da rede principal por um commit, a ação com o
    /// canal reatribuído — reprova uma vez, pela regra dela: tirar uma
    /// chamada de lá reprova aqui (a MC7 do adversário).
    #[test]
    fn adversario_a15_a_ci_e_o_canario_pelo_nome() {
        let ci = (CI.to_string(), OFICIAL.to_string());
        let canario = (CANARIO.to_string(), String::new());
        let outro = (
            ".github/workflows/principal.yml".to_string(),
            OFICIAL.to_string(),
        );
        assert_eq!(
            workflows_que_faltam(&[ci.clone(), canario.clone()]),
            Vec::<String>::new()
        );
        for (rotulo, workflows, falta) in [
            ("a CI renomeada", vec![outro.clone(), canario.clone()], CI),
            ("sem o canário", vec![ci.clone(), outro.clone()], CANARIO),
        ] {
            let fora = workflows_que_faltam(&workflows);
            assert_eq!(fora.len(), 1, "{rotulo}: {fora:#?}");
            assert!(
                fora[0].starts_with(&format!("{falta}: ")),
                "{rotulo}: {fora:#?}"
            );
            assert!(fora[0].contains("não foi achado"), "{rotulo}: {fora:#?}");
        }
        assert_eq!(workflows_que_faltam(&[outro]).len(), 2);

        // A definição da CI do repositório, inteira, e as trocas.
        let ci = include_str!("../../.github/workflows/ci.yml");
        let canario = include_str!("../../.github/workflows/canario.yml");
        let rede = include_str!("../../.github/workflows/rede-principal.yml");
        let definicao = |trocas: &[(&str, Option<&str>)]| -> Vec<String> {
            let mut workflows: Vec<(String, String)> = [
                (CI, ci),
                (CANARIO, canario),
                (".github/workflows/rede-principal.yml", rede),
                (ACAO_DO_COMPILADOR, ACAO),
            ]
            .into_iter()
            .map(|(nome, texto)| (nome.to_string(), texto.to_string()))
            .collect();
            for &(nome, texto) in trocas {
                workflows.retain(|(n, _)| n != nome);
                if let Some(texto) = texto {
                    workflows.push((nome.to_string(), texto.to_string()));
                }
            }
            conferir_a_definicao_da_ci(&workflows)
        };
        assert_eq!(definicao(&[]), Vec::<String>::new());
        let entrada = "        with:\n          invariantes: true\n";
        assert_eq!(ci.matches(entrada).count(), 1);
        let sem_a_entrada = ci.replacen(entrada, "", 1);
        let sem_o_comando = canario.replace("cargo xtask invariantes", "true");
        assert_ne!(sem_o_comando, canario);
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let rede_por_um_commit = rede.replacen(
            "      - uses: actions/checkout@v4\n",
            &format!("      - uses: actions/checkout@{commit}\n"),
            1,
        );
        assert_ne!(rede_por_um_commit, rede);
        let saida = format!("        {SAIDA_DO_CANAL}\n");
        let acao_reatribuida = ACAO.replacen(
            &saida,
            &format!("        canal=nightly-2000-01-01\n{saida}"),
            1,
        );
        assert_ne!(acao_reatribuida, ACAO);
        let gatilhos = "on:\n  push:\n  pull_request:\n";
        assert_eq!(ci.matches(gatilhos).count(), 1);
        let so_no_disparo = ci.replacen(gatilhos, "on:\n  workflow_dispatch:\n", 1);
        for (rotulo, trocas, esperado) in [
            (
                "a CI renomeada, sem a entrada",
                vec![
                    (CI, None),
                    (
                        ".github/workflows/principal.yml",
                        Some(sem_a_entrada.as_str()),
                    ),
                ],
                format!("{CI}: a CI oficial"),
            ),
            (
                "o canário apagado",
                vec![(CANARIO, None)],
                format!("{CANARIO}: o canário"),
            ),
            (
                "a ação apagada",
                vec![(ACAO_DO_COMPILADOR, None)],
                format!("{ACAO_DO_COMPILADOR}: a ação que confere o compilador não foi achada"),
            ),
            (
                "a CI sem a entrada",
                vec![(CI, Some(sem_a_entrada.as_str()))],
                format!("{CI}: o job `{JOB_DE_LINTS}` não liga as invariantes"),
            ),
            (
                "o canário sem um comando do job de lints",
                vec![(CANARIO, Some(sem_o_comando.as_str()))],
                format!("{CANARIO}: não repete `cargo xtask invariantes`"),
            ),
            (
                "a rede principal com o checkout por um commit",
                vec![(
                    ".github/workflows/rede-principal.yml",
                    Some(rede_por_um_commit.as_str()),
                )],
                format!(".github/workflows/rede-principal.yml: `actions/checkout@{commit}` — "),
            ),
            (
                "a ação com o canal reatribuído",
                vec![(ACAO_DO_COMPILADOR, Some(acao_reatribuida.as_str()))],
                format!("{ACAO_DO_COMPILADOR}: `canal=nightly-2000-01-01` no passo `conferir`"),
            ),
            (
                "a CI só no disparo manual (o lote A17)",
                vec![(CI, Some(so_no_disparo.as_str()))],
                format!("{CI}: a CI oficial não roda em todo push"),
            ),
        ] {
            let fora = definicao(&trocas);
            assert!(
                fora.len() == 1 && fora[0].starts_with(&esperado),
                "{rotulo}: {fora:#?}"
            );
        }
    }

    /// A CI em todo push (o I1 do adversário do lote A16): a CI só no disparo
    /// manual passava, e as invariantes do job de lints deixavam de rodar a
    /// cada push. O `on:` da CI do repositório passa, e o `push` nas formas do
    /// `on:` — o valor na linha, a lista em bloco, a chave do mapa —; sem o
    /// `push`, com um filtro dentro dele ou com um valor na linha da chave, e
    /// com a raiz recuada, reprova uma vez. O filtro legítimo também — o
    /// `paths-ignore:` que pularia a CI numa mudança só de documentação, em
    /// bloco ou em fluxo —: reprova de propósito, porque tiraria as
    /// invariantes de uma parte dos pushes (o F2 do adversário da rodada 10,
    /// desde o lote A18 neste teste).
    #[test]
    fn adversario_a16_a_ci_nos_pushes() {
        let ci = include_str!("../../.github/workflows/ci.yml");
        assert_eq!(a_ci_nos_pushes(ci), Vec::<String>::new());
        let gatilhos = "on:\n  push:\n  pull_request:\n";
        assert_eq!(ci.matches(gatilhos).count(), 1);
        for passa in [
            "on: push\n",
            "on: [push, pull_request]\n",
            "on:\n  - pull_request\n  - push\n",
            "on:\n- push\n",
            "on:\n  pull_request:\n    types: [opened]\n  push: # todo push\n",
        ] {
            assert_eq!(
                a_ci_nos_pushes(&ci.replacen(gatilhos, passa, 1)),
                Vec::<String>::new(),
                "{passa}"
            );
        }
        for reprova in [
            "on:\n  workflow_dispatch:\n",
            "on: [pull_request]\n",
            "on:\n  push:\n    branches-ignore: ['**']\n  pull_request:\n",
            "on:\n  push:\n    paths:\n      - kernel/**\n",
            "on:\n  push: {}\n",
            "on:\n  - push:\n      branches: [x]\n",
            "on:\n  push:\n    paths-ignore:\n      - '**.md'\n  pull_request:\n",
            "on:\n  push:\n    paths-ignore: ['**.md']\n  pull_request:\n",
        ] {
            let fora = a_ci_nos_pushes(&ci.replacen(gatilhos, reprova, 1));
            assert!(
                fora.len() == 1 && fora[0].contains("não roda em todo push"),
                "{reprova}: {fora:#?}"
            );
        }
        let recuada: String = ci
            .lines()
            .map(|l| {
                if l.trim().is_empty() {
                    String::from("\n")
                } else {
                    format!("  {l}\n")
                }
            })
            .collect();
        assert_eq!(a_ci_nos_pushes(&recuada).len(), 1);
    }

    /// Os gatilhos do canário (o B3 do adversário do lote A15): a regra não
    /// lia a lista em bloco do `on:`, e o `- push` passava; nem um gatilho
    /// fora do `push`, do `pull_request` e do `pull_request_target` — o
    /// `workflow_run` depois da CI, o `merge_group`. Reprovam agora, uma vez
    /// cada, pela lista fechada — também a lista em bloco na coluna do `on:`,
    /// que o lote A16 achou na revisão do patch —; o agendamento e o disparo
    /// manual passam, nas formas do `on:`, e o canário do repositório também.
    #[test]
    fn adversario_a15_os_gatilhos_do_canario() {
        let base = "on:\n  schedule:\n    - cron: '17 4 * * 1'\n  workflow_dispatch:\ncache-mode: none\njobs:\n  canario:\n    steps:\n      - uses: actions/checkout@v4\n";
        let on = "on:\n  schedule:\n    - cron: '17 4 * * 1'\n  workflow_dispatch:\n";
        assert_eq!(um(CANARIO, base), Vec::<String>::new());
        for (rotulo, novo, gatilho) in [
            (
                "a lista em bloco",
                "on:\n  - push\n  - workflow_dispatch\n",
                "push",
            ),
            (
                "a lista em bloco com aspas e comentário",
                "on:\n  - 'push' # x\n  - workflow_dispatch\n",
                "push",
            ),
            (
                "o workflow_run depois da CI",
                "on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\n  schedule:\n    - cron: '17 4 * * 1'\n",
                "workflow_run",
            ),
            (
                "o merge_group",
                "on:\n  merge_group:\n  workflow_dispatch:\n",
                "merge_group",
            ),
            ("o valor na linha", "on: pull_request\n", "pull_request"),
            (
                "a lista em bloco na coluna do `on:` (a sequência compacta)",
                "on:\n- push\n- workflow_dispatch\n",
                "push",
            ),
        ] {
            let texto = base.replace(on, novo);
            assert_ne!(texto, base, "{rotulo}");
            let fora = um(CANARIO, &texto);
            assert_eq!(fora.len(), 1, "{rotulo}: {fora:#?}");
            assert!(
                fora[0].contains(&format!("o canário roda em `{gatilho}`")),
                "{rotulo}: {fora:#?}"
            );
        }
        for passa in [
            "on:\n  - workflow_dispatch\n",
            "on:\n- workflow_dispatch\n",
            "on: [workflow_dispatch]\n",
            "on: workflow_dispatch\n",
        ] {
            assert_eq!(
                um(CANARIO, &base.replace(on, passa)),
                Vec::<String>::new(),
                "{passa}"
            );
        }
        let canario = include_str!("../../.github/workflows/canario.yml");
        assert!(
            !um(CANARIO, canario)
                .iter()
                .any(|f| f.contains("o canário roda em"))
        );
    }

    /// O canário com a raiz recuada (o B1 do adversário do lote A16, a pista
    /// do revisor da rodada 9): as chaves de cima na coluna dois são o mesmo
    /// YAML, e a regra dos gatilhos não achava o `on:`, nem o `push:` dele.
    /// Reprova agora pela leitura — a raiz fora da coluna zero — e pela regra
    /// dos gatilhos — nenhum `on:` na coluna zero —, uma vez cada, com o
    /// `push:` ou sem ele, e também depois de um `---` (e, recuado, o
    /// `cache-mode` sai da raiz); o canário do repositório passa.
    #[test]
    fn adversario_a16_o_canario_com_a_raiz_recuada() {
        let base = "on:\n  schedule:\n    - cron: '17 4 * * 1'\n  workflow_dispatch:\ncache-mode: none\njobs:\n  canario:\n    steps:\n      - uses: actions/checkout@v4\n";
        let recuar = |texto: &str| -> String {
            texto
                .lines()
                .map(|l| format!("  {l}\n"))
                .collect::<String>()
        };
        assert_eq!(um(CANARIO, base), Vec::<String>::new());
        let com_push = base.replace("  workflow_dispatch:\n", "  push:\n  workflow_dispatch:\n");
        for (rotulo, texto) in [
            ("a raiz recuada, com o push", recuar(&com_push)),
            ("a raiz recuada, sem gatilho novo", recuar(base)),
            (
                "o `---` e a raiz recuada",
                format!("---\n{}", recuar(&com_push)),
            ),
        ] {
            let fora = um(CANARIO, &texto);
            for regra in [
                "a raiz do documento fora da coluna zero",
                "nenhum `on:` na coluna zero",
            ] {
                assert_eq!(
                    fora.iter().filter(|f| f.contains(regra)).count(),
                    1,
                    "{rotulo}: {regra}: {fora:#?}"
                );
            }
            assert!(
                !fora.iter().any(|f| f.contains("o canário roda em")),
                "{rotulo}: {fora:#?}"
            );
        }
        // Sem o `on:`, com a raiz na coluna zero: só a regra dos gatilhos.
        let sem_on = base.replace(
            "on:\n  schedule:\n    - cron: '17 4 * * 1'\n  workflow_dispatch:\n",
            "",
        );
        let fora = um(CANARIO, &sem_on);
        assert!(
            fora.len() == 1 && fora[0].contains("nenhum `on:` na coluna zero"),
            "{fora:#?}"
        );
        let canario = include_str!("../../.github/workflows/canario.yml");
        assert!(
            !um(CANARIO, canario)
                .iter()
                .any(|f| f.contains("coluna zero"))
        );
    }

    /// Os falsos positivos de propósito das regras do lote A16 no passo
    /// `conferir` (o adversário do lote A16, rodada 9): quatro formas
    /// plausíveis, sem defeito, que a regra do canal reprova, uma vez cada, e
    /// que falham fechadas — o resumo do job depois da linha da saída (a
    /// saída na última linha), um `()` num comentário e uma lista vazia do
    /// bash (`faltam=()`, a definição de uma função), e uma palavra com
    /// `alias` dentro (`avaliasse`, o apelido). A mensagem diz a linha — a do
    /// comentário, a da lista, a da palavra —, e, na regra da saída, a que tem
    /// de ser a última. O quinto — um arquivo não versionado com o nome em
    /// Latin-1 na árvore de quem roda — reprova a lista dos arquivos do
    /// repositório, e o teste `adversario_a15_o_nome_que_o_git_cita` o tem. O
    /// custo é aceitável: a linha muda, e a regra fica larga de propósito.
    #[test]
    fn adversario_a16_os_falsos_positivos_de_proposito() {
        let instala = "        rustc -V > /dev/null\n";
        let saida = format!("        {SAIDA_DO_CANAL}\n");
        let git =
            "        # O arquivo do commit, pelo git sem o ambiente do job — só o PATH, que\n";
        for (trecho, vezes) in [(instala, 1), (saida.as_str(), 1), (git, 1)] {
            assert_eq!(ACAO.matches(trecho).count(), vezes, "{trecho}");
        }
        for (rotulo, texto, regra, linha) in [
            (
                "o resumo do job depois da saída",
                ACAO.replacen(
                    &saida,
                    &format!(
                        "{saida}        echo \"o compilador oficial: $ativo\" >> \"$GITHUB_STEP_SUMMARY\"\n"
                    ),
                    1,
                ),
                "não termina pela linha da saída",
                SAIDA_DO_CANAL,
            ),
            (
                "um `()` num comentário",
                ACAO.replacen(
                    instala,
                    &format!(
                        "        # A versão sai do tomllib.load() do Python, como o rustup a lê.\n{instala}"
                    ),
                    1,
                ),
                "a definição de uma função",
                "# A versão sai do tomllib.load() do Python, como o rustup a lê.",
            ),
            (
                "uma lista vazia do bash",
                ACAO.replacen(instala, &format!("        faltam=()\n{instala}"), 1),
                "a definição de uma função",
                "faltam=()",
            ),
            (
                "uma palavra com `alias` dentro",
                ACAO.replacen(
                    git,
                    &format!(
                        "        # O git não avaliasse o índice do job: sem o ambiente dele.\n{git}"
                    ),
                    1,
                ),
                "um apelido do bash",
                "# O git não avaliasse o índice do job: sem o ambiente dele.",
            ),
        ] {
            assert_ne!(texto, ACAO, "{rotulo}");
            let fora = conferir_a_acao(&texto);
            assert!(
                fora.len() == 1
                    && fora[0].contains(regra)
                    && fora[0].contains(&format!("`{linha}`")),
                "{rotulo}: {fora:#?}"
            );
        }
    }

    /// A publicação do canário só com a pasta dos registros (o I2 do
    /// adversário do lote A16 e o E4 do revisor da rodada 9): a regra da
    /// proveniência é o texto `target/proveniencia`, e um `path:` mais largo
    /// levaria os registros do `xtask` sem citá-lo. O canário do repositório
    /// passa — também com o caminho entre aspas —; o `path:` do `target/`, o
    /// da pasta de cima e o de um bloco com a pasta dos registros e mais uma
    /// reprovam uma vez cada, pela regra da publicação. O caminho se compara
    /// pelo texto, na forma canônica: o sem a `/` do fim e o da expressão sem
    /// os espaços, que o GitHub resolve para a mesma pasta, reprovam de
    /// propósito (o F1 do adversário da rodada 10, desde o lote A18 neste
    /// teste).
    #[test]
    fn adversario_a16_a_publicacao_do_canario() {
        let canario = include_str!("../../.github/workflows/canario.yml");
        let caminho = "          path: ${{ runner.temp }}/registros/\n";
        assert_eq!(canario.matches(caminho).count(), 1);
        assert!(
            !um(CANARIO, canario)
                .iter()
                .any(|f| f.contains("a publicação de")),
            "{:#?}",
            um(CANARIO, canario)
        );
        for (rotulo, novo) in [
            ("o target", "          path: target/\n"),
            ("a pasta de cima", "          path: ${{ runner.temp }}/\n"),
            (
                "um bloco com mais uma pasta",
                "          path: |\n            ${{ runner.temp }}/registros/\n            target/\n",
            ),
            (
                "sem a `/` do fim (o F1 da rodada 10)",
                "          path: ${{ runner.temp }}/registros\n",
            ),
            (
                "a expressão sem os espaços (o F1 da rodada 10)",
                "          path: ${{runner.temp}}/registros/\n",
            ),
        ] {
            let texto = canario.replacen(caminho, novo, 1);
            assert_ne!(texto, canario, "{rotulo}");
            let fora = um(CANARIO, &texto);
            assert!(
                fora.len() == 1 && fora[0].contains("a publicação de"),
                "{rotulo}: {fora:#?}"
            );
        }
        let entre_aspas = canario.replacen(
            caminho,
            "          path: '${{ runner.temp }}/registros/'\n",
            1,
        );
        assert_eq!(um(CANARIO, &entre_aspas), Vec::<String>::new());
    }

    /// O canário sem cache nenhum (o lote A17, a recomendação do M2 do
    /// adversário do lote A15, depois do run 5 do canário): o canário do
    /// repositório tem o `cache-mode: none` na raiz, e passa — também com a
    /// chave entre aspas ou com um comentário. Sem ela, com outro valor, com
    /// duas na raiz e com a de um job (`jobs.<id>.cache-mode`), reprova uma
    /// vez, pela regra do modo do cache.
    #[test]
    fn o_canario_sem_cache_nenhum() {
        let canario = include_str!("../../.github/workflows/canario.yml");
        let modo = "cache-mode: none\n";
        assert_eq!(canario.matches(modo).count(), 1);
        assert!(
            !um(CANARIO, canario)
                .iter()
                .any(|f| f.contains("cache-mode")),
            "{:#?}",
            um(CANARIO, canario)
        );
        let job = "    timeout-minutes: 150\n";
        assert_eq!(canario.matches(job).count(), 1);
        for (rotulo, texto) in [
            ("sem a chave", canario.replacen(modo, "", 1)),
            (
                "com outro valor",
                canario.replacen(modo, "cache-mode: write\n", 1),
            ),
            (
                "duas na raiz",
                canario.replacen(modo, "cache-mode: none\ncache-mode: read\n", 1),
            ),
            (
                "a de um job",
                canario.replacen(job, "    timeout-minutes: 150\n    cache-mode: write\n", 1),
            ),
        ] {
            assert_ne!(texto, canario, "{rotulo}");
            let fora = um(CANARIO, &texto);
            assert!(
                fora.len() == 1 && fora[0].contains("cache-mode"),
                "{rotulo}: {fora:#?}"
            );
        }
        for passa in ["cache-mode: 'none'\n", "cache-mode: none # sem cache\n"] {
            assert_eq!(
                um(CANARIO, &canario.replacen(modo, passa, 1)),
                Vec::<String>::new(),
                "{passa}"
            );
        }
    }

    /// A raiz na coluna zero, em todo workflow e ação (o lote A17, a forma
    /// geral do B1 do adversário do lote A16): cada arquivo da definição da
    /// CI do repositório, com a raiz dois espaços para dentro — o mesmo YAML
    /// —, reprova uma vez pela leitura; o `---` sozinho antes da raiz na
    /// coluna zero, e os arquivos como estão, passam.
    #[test]
    fn adversario_a16_a_raiz_na_coluna_zero() {
        let recuar = |texto: &str| -> String {
            texto
                .lines()
                .map(|l| {
                    if l.trim().is_empty() {
                        String::from("\n")
                    } else {
                        format!("  {l}\n")
                    }
                })
                .collect::<String>()
        };
        let leitura = "a raiz do documento fora da coluna zero";
        for (nome, texto) in [
            (CI, include_str!("../../.github/workflows/ci.yml")),
            (
                ".github/workflows/rede-principal.yml",
                include_str!("../../.github/workflows/rede-principal.yml"),
            ),
            (CANARIO, include_str!("../../.github/workflows/canario.yml")),
            (
                ACAO_DO_COMPILADOR,
                include_str!("../../.github/actions/compilador/action.yml"),
            ),
            (
                ".github/actions/outra/action.yml",
                "name: Outra\nruns:\n  using: composite\n  steps:\n    - run: echo\n      shell: bash\n",
            ),
        ] {
            assert!(
                !um(nome, texto).iter().any(|f| f.contains(leitura)),
                "{nome}"
            );
            let fora = um(nome, &recuar(texto));
            assert_eq!(
                fora.iter().filter(|f| f.contains(leitura)).count(),
                1,
                "{nome}: {fora:#?}"
            );
            let explicito = format!("---\n{texto}");
            assert!(
                !um(nome, &explicito).iter().any(|f| f.contains(leitura)),
                "{nome}"
            );
        }
    }

    /// O escape num texto entre aspas duplas (o B2 do adversário do lote
    /// A16): a chave de restauração do job de lints com o `\n` do YAML levava
    /// o canal para a regra das chaves de cache e, para o `actions/cache`, uma
    /// segunda chave sem ele; e o `\x52` escondia um nome das sobreposições.
    /// Reprovam, uma vez cada, pela forma; o texto entre aspas simples e o
    /// entre aspas duplas sem `\` passam, e os workflows do repositório
    /// também.
    #[test]
    fn adversario_a16_o_escape_num_texto_entre_aspas_duplas() {
        let ci = include_str!("../../.github/workflows/ci.yml");
        let chave = "          restore-keys: lints-${{ steps.compilador.outputs.canal }}-\n";
        assert_eq!(ci.matches(chave).count(), 1);
        for (rotulo, novo) in [
            (
                "a chave de restauração com o \\n",
                "          restore-keys: \"lints-${{ steps.compilador.outputs.canal }}-\\nlints-\"\n",
            ),
            (
                "o nome com o \\x52 num run",
                "          restore-keys: lints-${{ steps.compilador.outputs.canal }}-\n      - run: \"\\x52USTC_WRAPPER=sccache cargo build\"\n",
            ),
            (
                "um item com o \\t",
                "          restore-keys: lints-${{ steps.compilador.outputs.canal }}-\n          lista:\n            - \"a\\tb\"\n",
            ),
        ] {
            let texto = ci.replacen(chave, novo, 1);
            assert_ne!(texto, ci, "{rotulo}");
            let fora = um(CI, &texto);
            assert_eq!(fora.len(), 1, "{rotulo}: {fora:#?}");
            assert!(fora[0].contains(ESCAPE_ENTRE_ASPAS), "{rotulo}: {fora:#?}");
        }
        for passa in [
            "          restore-keys: \"lints-${{ steps.compilador.outputs.canal }}-\"\n",
            "          restore-keys: 'lints-${{ steps.compilador.outputs.canal }}-\\n'\n",
        ] {
            assert_eq!(
                um(CI, &ci.replacen(chave, passa, 1)),
                Vec::<String>::new(),
                "{passa}"
            );
        }
        assert_eq!(um(CI, ci), Vec::<String>::new());
    }

    /// O canal na chave de cache pela expressão (o B2 do adversário do lote
    /// A15): o texto `steps.compilador.outputs.canal` numa expressão
    /// que o devolve — ou fora de uma — passava, e a chave levava um texto
    /// fixo. Reprovam agora o texto numa expressão, o texto fora dela e a
    /// expressão com um padrão, na chave, e o texto numa expressão, na de
    /// restauração; e o passo da ação sem o `id: compilador`, com o `id`
    /// noutro passo, também (o lote A16, na revisão). Desde o lote A17 (o B3
    /// do adversário do lote A16), também o texto da expressão num literal de
    /// outra, na chave e na de restauração, e a chave entre aspas simples
    /// cujo `''` a linha crua lia como duas aspas; e as expressões como o
    /// leitor de modelos do GitHub as acha e o valor como o YAML o lê, pelas
    /// formas. A expressão passa, também numa chave entre aspas, e os
    /// workflows do repositório também. A expressão achada se compara pelo
    /// texto, na forma canônica: a sem o espaço antes do `}}` e a da
    /// indexação (`outputs['canal']`), que o GitHub avalia igual, reprovam de
    /// propósito, na chave e pela função (o F1 do adversário da rodada 10,
    /// desde o lote A18 neste teste).
    #[test]
    fn adversario_a15_o_canal_na_chave_pela_expressao() {
        let chave = "          key: testes-${{ steps.compilador.outputs.canal }}-";
        assert_eq!(OFICIAL.matches(chave).count(), 1);
        for (rotulo, novo) in [
            (
                "o texto numa expressão",
                "          key: testes-${{ 'steps.compilador.outputs.canal' }}-",
            ),
            (
                "o texto fora da expressão",
                "          key: testes-steps.compilador.outputs.canal-",
            ),
            (
                "a expressão com um padrão",
                "          key: testes-${{ steps.compilador.outputs.canal || 'x' }}-",
            ),
            (
                "o texto da expressão num literal de outra (o B3 do lote A16)",
                "          key: testes-${{ '${{ steps.compilador.outputs.canal }}' }}-",
            ),
            (
                "o texto da expressão num literal com aspas dentro",
                "          key: testes-${{ 'a''${{ steps.compilador.outputs.canal }}' }}-",
            ),
            (
                "a expressão sem o espaço antes do `}}` (o F1 da rodada 10)",
                "          key: testes-${{ steps.compilador.outputs.canal}}-",
            ),
            (
                "a expressão com a indexação (o F1 da rodada 10)",
                "          key: testes-${{ steps.compilador.outputs['canal'] }}-",
            ),
        ] {
            let texto = OFICIAL.replacen(chave, novo, 1);
            assert_ne!(texto, OFICIAL, "{rotulo}");
            let fora = um(CI, &texto);
            assert!(
                fora.len() == 1 && fora[0].contains("não leva o canal"),
                "{rotulo}: {fora:?}"
            );
        }
        // O valor como o YAML o lê (o lote A17, na revisão do patch do
        // adversário): entre aspas simples, o `''` é uma aspa só, e a linha
        // crua tinha a expressão do canal onde o leitor do GitHub tem um
        // literal. Reprova; a chave entre aspas, simples ou duplas, com a
        // expressão, passa.
        let linha = "          key: testes-${{ steps.compilador.outputs.canal }}-${{ hashFiles('**/Cargo.lock') }}\n";
        assert_eq!(OFICIAL.matches(linha).count(), 1);
        let aninhada = OFICIAL.replacen(
            linha,
            "          key: '${{ ''}}${{ steps.compilador.outputs.canal }}'' }}-${{ hashFiles(''**/Cargo.lock'') }}'\n",
            1,
        );
        let fora = um(CI, &aninhada);
        assert!(
            fora.len() == 1 && fora[0].contains("não leva o canal"),
            "{fora:?}"
        );
        for passa in [
            "          key: 'testes-${{ steps.compilador.outputs.canal }}-${{ hashFiles(''**/Cargo.lock'') }}'\n",
            "          key: \"testes-${{ steps.compilador.outputs.canal }}-${{ hashFiles('**/Cargo.lock') }}\"\n",
        ] {
            assert_eq!(
                um(CI, &OFICIAL.replacen(linha, passa, 1)),
                Vec::<String>::new(),
                "{passa}"
            );
        }
        let restauracao = OFICIAL.replacen(
            "            video-${{ steps.compilador.outputs.canal }}-\n",
            "            video-${{ 'steps.compilador.outputs.canal' }}-\n",
            1,
        );
        assert_ne!(restauracao, OFICIAL);
        assert_eq!(um(CI, &restauracao).len(), 1);
        let aninhada = OFICIAL.replacen(
            "            video-${{ steps.compilador.outputs.canal }}-\n",
            "            video-${{ '${{ steps.compilador.outputs.canal }}' }}-\n",
            1,
        );
        assert_ne!(aninhada, OFICIAL);
        assert_eq!(um(CI, &aninhada).len(), 1);
        // As expressões como o leitor de modelos do GitHub as acha.
        for (chave, tem) in [
            ("x-${{ steps.compilador.outputs.canal }}-y", true),
            (
                "${{ hashFiles('a}}b') }}-${{ steps.compilador.outputs.canal }}",
                true,
            ),
            ("${{ '${{ steps.compilador.outputs.canal }}' }}", false),
            ("${{ 'b}}${{ steps.compilador.outputs.canal }}' }}", false),
            ("${{ steps.compilador.outputs.canal", false),
            ("x-${{ steps.compilador.outputs.canal }}}-y", true),
            // A forma canônica, pelo texto (o F1 da rodada 10): as outras
            // grafias que o GitHub avalia igual falham fechadas.
            ("${{ steps.compilador.outputs.canal}}", false),
            ("${{steps.compilador.outputs.canal}}", false),
            ("${{ steps.compilador.outputs['canal'] }}", false),
        ] {
            assert_eq!(o_canal_numa_expressao(chave), tem, "{chave}");
        }
        // O valor como o YAML o lê.
        for (valor, lido) in [
            ("'a''b'", "a'b"),
            ("\"a'b\"", "a'b"),
            ("a''b", "a''b"),
            ("'a", "'a"),
        ] {
            assert_eq!(valor_do_yaml(valor), lido, "{valor}");
        }
        // O `id: compilador` noutro passo, que escreve outro canal na saída
        // dele, e a ação sem o `id` (o lote A16, na revisão): a contagem
        // passava; o passo da ação sem o `id` reprova, uma vez.
        let passo = "        id: compilador\n        uses: ./.github/actions/compilador\n";
        assert_eq!(OFICIAL.matches(passo).count(), 1);
        let noutro = OFICIAL.replacen(
            passo,
            "        uses: ./.github/actions/compilador\n\n      - id: compilador\n        \
             run: echo \"canal=nightly-2000-01-01\" >> \"$GITHUB_OUTPUT\"\n",
            1,
        );
        assert_ne!(noutro, OFICIAL);
        let fora = um(CI, &noutro);
        assert!(
            fora.len() == 1 && fora[0].contains("sem o `id: compilador`"),
            "{fora:#?}"
        );
        for (nome, texto) in [
            (CI, include_str!("../../.github/workflows/ci.yml")),
            (
                ".github/workflows/rede-principal.yml",
                include_str!("../../.github/workflows/rede-principal.yml"),
            ),
        ] {
            assert!(
                !um(nome, texto)
                    .iter()
                    .any(|f| f.contains("não leva o canal") || f.contains("sem o `id: compilador`")),
                "{nome}"
            );
        }
    }

    /// Os falsos positivos de propósito (o FP1 a FP3 do adversário do lote
    /// A15): três formas legítimas que as regras reprovam, e que falham
    /// fechadas — nenhum workflow de hoje as usa, e lê-las é uma decisão de
    /// um lote. A sequência compacta do YAML — os itens do `steps:` na
    /// coluna da chave — reprova uma vez, pelo começo dos jobs, e a mensagem
    /// diz a forma; a referência `$/` ao próprio repositório, que o GitHub
    /// recomenda no lugar do `./`, reprova pelo nome da ação; e o checkout
    /// por um commit, o "pin" que a política do GitHub pode exigir, reprova
    /// uma vez, pela versão — a lista ganha o commit, revisada.
    #[test]
    fn adversario_a15_os_falsos_positivos_de_proposito() {
        let steps = "    steps:\n";
        assert_eq!(OFICIAL.matches(steps).count(), 1);
        let (antes, depois) = OFICIAL.split_at(OFICIAL.find(steps).expect("o steps") + steps.len());
        let compacta = format!(
            "{antes}{}",
            depois
                .split_inclusive('\n')
                .map(|l| l
                    .strip_prefix("  ")
                    .filter(|_| l.starts_with("      "))
                    .unwrap_or(l))
                .collect::<String>()
        );
        assert!(compacta.contains("    steps:\n    - uses: actions/checkout@v4\n"));
        let fora = um(CI, &compacta);
        assert!(
            fora.len() == 1
                && fora[0].contains("não começa pelo checkout")
                && fora[0].contains("a sequência compacta do YAML"),
            "{fora:#?}"
        );
        let uso = "        uses: ./.github/actions/compilador\n";
        assert_eq!(OFICIAL.matches(uso).count(), 1);
        let dolar = OFICIAL.replacen(uso, "        uses: $/.github/actions/compilador\n", 1);
        assert!(
            um(CI, &dolar)
                .iter()
                .any(|f| f.contains("`$/.github/actions/compilador` não é uma ação permitida")),
            "{:#?}",
            um(CI, &dolar)
        );
        let checkout = "      - uses: actions/checkout@v4\n";
        assert_eq!(OFICIAL.matches(checkout).count(), 1);
        let pin = OFICIAL.replacen(
            checkout,
            "      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v4.2.2\n",
            1,
        );
        let fora = um(CI, &pin);
        assert!(
            fora.len() == 1 && fora[0].contains("a versão de uma ação permitida fora da lista"),
            "{fora:#?}"
        );
    }
}
