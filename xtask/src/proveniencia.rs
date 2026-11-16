//! A proveniência dos artefatos compilados.
//!
//! Todo artefato que o `xtask` compila — o kernel, o iniciador, cada
//! programa, o modelo do SDK — deixa um registro em `target/proveniencia/`,
//! um JSON por artefato, que liga os bytes dele (o SHA-256 e o tamanho) a
//! como ele foi feito:
//!
//! - **o compilador**: o `rustc -Vv` completo, o `cargo -V`, o toolchain
//!   ativo e o canal oficial; e se a execução foi oficial — sem desvio
//!   nenhum, ver [`super::compilador`] — ou não, com os desvios e o opt-in;
//! - **a compilação**: o alvo, a arquitetura, o perfil e as features pedidas
//!   ao cargo (nenhum dos pacotes compilados tem features padrão);
//! - **a fonte**: o commit, se a árvore estava limpa, e o SHA-256 do
//!   `Cargo.lock` que resolveu as dependências do artefato;
//! - **a execução da CI** que o produziu — o repositório, o workflow, o run,
//!   a tentativa, o job, o endereço e a imagem do runner —, ou `null`, numa
//!   máquina de desenvolvimento.
//!
//! O nome do arquivo termina no começo do SHA-256 do artefato: de um ELF —
//! achado num incidente, ao lado de uma imagem publicada —, o registro sai
//! pelo resumo ([`do_artefato`]); o incidente guarda o do kernel que
//! capturou. A CI publica o diretório como artefato de cada job
//! (`proveniencia-*`), pelo mesmo mecanismo dos incidentes, e o apaga depois
//! de restaurar o cache: o registro de uma rodada não aparece no artefato de
//! outra. Registrar não é opcional: um registro que não se grava reprova o
//! build.
//!
//! **Proveniência não é reprodução.** O registro diz com que compilador, de
//! que fonte e em que execução o artefato saiu; não garante que compilar de
//! novo dê os mesmos bytes. Os caminhos absolutos da máquina — o do checkout
//! e o do registro do cargo — entram nas localizações de pânico do
//! `.rodata`, e nada aqui foi feito para tirá-los.
//!
//! Os derivados — a cópia sem símbolos do kernel que vai para a ESP e o
//! slot, a imagem crua do arm64, as imagens de disco — não têm registro
//! próprio: saem do artefato registrado por cópia e montagem do `xtask`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use protocolo::json::JsonWriter;
use sha2::{Digest, Sha256};

/// A versão do formato do registro.
const FORMATO: &str = "duke-proveniencia-1";

/// Um artefato que acaba de ser compilado.
pub(crate) struct Compilado<'a> {
    /// `kernel`, `iniciador`, `programa` ou `modelo-do-sdk`.
    pub(crate) tipo: &'a str,
    /// O nome do binário.
    pub(crate) nome: &'a str,
    /// O arquivo, onde o cargo o pôs.
    pub(crate) arquivo: &'a Path,
    /// O alvo do rustc.
    pub(crate) alvo: &'a str,
    /// A arquitetura do Duke.
    pub(crate) arquitetura: &'a str,
    /// `debug` ou `release`.
    pub(crate) perfil: &'a str,
    /// As features pedidas ao cargo.
    pub(crate) features: &'a [&'a str],
    /// O `Cargo.lock` que resolveu as dependências.
    pub(crate) lock: &'a Path,
}

/// Onde ficam os registros: `target/proveniencia/`, na raiz do projeto.
pub(crate) fn diretorio() -> PathBuf {
    super::raiz_do_projeto().join("target").join("proveniencia")
}

/// Registra a proveniência de `c`, e devolve o caminho do registro.
pub(crate) fn registrar(c: &Compilado) -> Result<PathBuf, String> {
    registrar_em(&diretorio(), c)
}

/// [`registrar`] em `dir`.
fn registrar_em(dir: &Path, c: &Compilado) -> Result<PathBuf, String> {
    let bytes = std::fs::read(c.arquivo)
        .map_err(|e| format!("a proveniência: não se lê {}: {e}", c.arquivo.display()))?;
    let resumo = sha256(&bytes);
    let lock = std::fs::read(c.lock).ok().map(|b| sha256(&b));
    let agora = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let texto = registro(c, &resumo, bytes.len() as u64, lock.as_deref(), agora)
        .map_err(|_| String::from("a proveniência: o registro não se escreve"))?;

    std::fs::create_dir_all(dir)
        .map_err(|e| format!("a proveniência: não se cria {}: {e}", dir.display()))?;
    let destino = dir.join(nome_do_registro(c, &resumo));
    // Escrito ao lado e renomeado: quem lê — o incidente, o upload da CI —
    // nunca vê um registro pela metade.
    let provisorio = destino.with_extension(format!("json.{}", std::process::id()));
    std::fs::write(&provisorio, texto)
        .and_then(|()| std::fs::rename(&provisorio, &destino))
        .map_err(|e| format!("a proveniência: não se grava {}: {e}", destino.display()))?;
    Ok(destino)
}

/// O registro de um artefato com o SHA-256 `sha256` — o mais novo, se há
/// mais de um.
pub(crate) fn do_artefato(sha256: &str) -> Option<PathBuf> {
    do_artefato_em(&diretorio(), sha256)
}

/// [`do_artefato`] em `dir`.
fn do_artefato_em(dir: &Path, sha256: &str) -> Option<PathBuf> {
    let fim = format!("-{}.json", sha256.get(..16)?);
    let campo = format!("\"sha256\":\"{sha256}\"");
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(&fim))
        })
        .filter(|p| std::fs::read_to_string(p).is_ok_and(|t| t.contains(&campo)))
        .max_by_key(|p| p.metadata().and_then(|m| m.modified()).ok())
}

/// O nome do registro: o tipo, o nome, a arquitetura, o perfil, as
/// features e o começo do resumo.
fn nome_do_registro(c: &Compilado, resumo: &str) -> String {
    let mut nome = c.tipo.to_string();
    if c.nome != c.tipo {
        nome.push('-');
        nome.push_str(c.nome);
    }
    nome.push('-');
    nome.push_str(c.arquitetura);
    nome.push('-');
    nome.push_str(c.perfil);
    if !c.features.is_empty() {
        nome.push('-');
        nome.push_str(&c.features.join("+"));
    }
    format!("{nome}-{}.json", &resumo[..16])
}

/// O JSON do registro, numa linha.
fn registro(
    c: &Compilado,
    resumo: &str,
    tamanho: u64,
    lock: Option<&str>,
    agora: u64,
) -> Result<String, std::fmt::Error> {
    let compilador = super::compilador::estado();
    let fonte = fonte();
    let raiz = super::raiz_do_projeto();
    let relativo = |p: &Path| {
        p.strip_prefix(&raiz)
            .unwrap_or(p)
            .to_string_lossy()
            .into_owned()
    };
    let opcional = |j: &mut JsonWriter, chave: &str, valor: Option<&str>| {
        j.key(chave)?;
        match valor {
            Some(v) => j.str_value(v),
            None => j.null_value(),
        }
    };

    let mut texto = String::new();
    let mut j = JsonWriter::new(&mut texto);
    j.begin_object()?;
    j.field_str("formato", FORMATO)?;

    j.key("artefato")?;
    j.begin_object()?;
    j.field_str("tipo", c.tipo)?;
    j.field_str("nome", c.nome)?;
    j.field_str("arquivo", &relativo(c.arquivo))?;
    j.field_str("sha256", resumo)?;
    j.field_u64("bytes", tamanho)?;
    j.end_object()?;

    j.key("compilacao")?;
    j.begin_object()?;
    j.field_str("alvo", c.alvo)?;
    j.field_str("arquitetura", c.arquitetura)?;
    j.field_str("perfil", c.perfil)?;
    j.key("features")?;
    j.begin_array()?;
    for f in c.features {
        j.str_value(f)?;
    }
    j.end_array()?;
    j.end_object()?;

    j.key("compilador")?;
    j.begin_object()?;
    j.field_bool("oficial", compilador.oficial())?;
    opcional(&mut j, "canal_oficial", compilador.canal.as_deref().ok())?;
    opcional(&mut j, "toolchain", compilador.toolchain.as_deref())?;
    opcional(&mut j, "rustc", compilador.rustc.as_deref())?;
    opcional(&mut j, "cargo", compilador.cargo.as_deref())?;
    j.key("desvios")?;
    j.begin_array()?;
    for d in &compilador.desvios {
        j.str_value(d)?;
    }
    j.end_array()?;
    j.field_bool("declarada_nao_oficial", compilador.declarada_nao_oficial)?;
    j.end_object()?;

    j.key("fonte")?;
    j.begin_object()?;
    opcional(&mut j, "commit", fonte.commit.as_deref())?;
    j.key("arvore_limpa")?;
    match fonte.arvore_limpa {
        Some(limpa) => j.bool_value(limpa)?,
        None => j.null_value()?,
    }
    j.field_str("cargo_lock", &relativo(c.lock))?;
    opcional(&mut j, "cargo_lock_sha256", lock)?;
    j.end_object()?;

    j.key("ci")?;
    match &fonte.ci {
        Some(campos) => {
            j.begin_object()?;
            for (chave, valor) in campos {
                j.field_str(chave, valor)?;
            }
            j.end_object()?;
        }
        None => j.null_value()?,
    }

    let segundos = i64::try_from(agora).unwrap_or(i64::MAX);
    j.field_str(
        "registrado_em",
        &format!("{}Z", super::tempo::data_de(segundos)),
    )?;
    j.end_object()?;
    texto.push('\n');
    Ok(texto)
}

/// A fonte e a execução, iguais para todo artefato da mesma execução do
/// `xtask`.
struct Fonte {
    /// O commit do checkout.
    commit: Option<String>,
    /// Sem mudança nenhuma, nem arquivo novo fora dos ignorados.
    arvore_limpa: Option<bool>,
    /// Os campos da execução da CI, numa CI.
    ci: Option<Vec<(&'static str, String)>>,
}

/// A [`Fonte`] desta execução, lida uma vez.
fn fonte() -> &'static Fonte {
    static FONTE: OnceLock<Fonte> = OnceLock::new();
    FONTE.get_or_init(|| {
        let raiz = super::raiz_do_projeto();
        let git = |args: &[&str]| {
            Command::new("git")
                .current_dir(&raiz)
                .args(args)
                .output()
                .ok()
                .filter(|s| s.status.success())
                .map(|s| String::from_utf8_lossy(&s.stdout).trim().to_string())
        };
        Fonte {
            commit: git(&["rev-parse", "HEAD"]),
            arvore_limpa: git(&["status", "--porcelain"]).map(|s| s.is_empty()),
            ci: execucao_da_ci(|nome| std::env::var(nome).ok()),
        }
    })
}

/// A execução da CI, das variáveis do GitHub Actions — ou nenhuma, fora
/// dela.
fn execucao_da_ci(ler: impl Fn(&str) -> Option<String>) -> Option<Vec<(&'static str, String)>> {
    if ler("GITHUB_ACTIONS").as_deref() != Some("true") {
        return None;
    }
    let valor = |nome: &str| ler(nome).unwrap_or_default();
    let mut campos = vec![
        ("repositorio", valor("GITHUB_REPOSITORY")),
        ("workflow", valor("GITHUB_WORKFLOW")),
        ("evento", valor("GITHUB_EVENT_NAME")),
        ("ref", valor("GITHUB_REF_NAME")),
        ("sha", valor("GITHUB_SHA")),
        ("run_id", valor("GITHUB_RUN_ID")),
        ("run_number", valor("GITHUB_RUN_NUMBER")),
        ("tentativa", valor("GITHUB_RUN_ATTEMPT")),
        ("job", valor("GITHUB_JOB")),
    ];
    campos.push((
        "endereco",
        format!(
            "{}/{}/actions/runs/{}/attempts/{}",
            valor("GITHUB_SERVER_URL"),
            valor("GITHUB_REPOSITORY"),
            valor("GITHUB_RUN_ID"),
            valor("GITHUB_RUN_ATTEMPT")
        ),
    ));
    campos.push((
        "runner",
        format!(
            "{} {} {}",
            valor("RUNNER_OS"),
            valor("ImageOS"),
            valor("ImageVersion")
        )
        .trim()
        .to_string(),
    ));
    Some(campos)
}

/// O SHA-256 de `bytes`, em hexadecimal.
fn sha256(bytes: &[u8]) -> String {
    sigilo::hex_de(&Sha256::digest(bytes))
}

#[cfg(test)]
mod testes {
    use super::*;
    use protocolo::json::Json;

    fn compilado<'a>(arquivo: &'a Path, lock: &'a Path, features: &'a [&'a str]) -> Compilado<'a> {
        Compilado {
            tipo: "kernel",
            nome: "duke",
            arquivo,
            alvo: "x86_64-unknown-none",
            arquitetura: "x86_64",
            perfil: "release",
            features,
            lock,
        }
    }

    #[test]
    fn o_nome_do_registro_leva_a_configuracao_e_o_resumo() {
        let arquivo = Path::new("kernel/target/x86_64-unknown-none/release/duke");
        let lock = Path::new("kernel/Cargo.lock");
        let resumo = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            nome_do_registro(&compilado(arquivo, lock, &[]), resumo),
            "kernel-duke-x86_64-release-0123456789abcdef.json"
        );
        assert_eq!(
            nome_do_registro(&compilado(arquivo, lock, &["modo-teste", "outra"]), resumo),
            "kernel-duke-x86_64-release-modo-teste+outra-0123456789abcdef.json"
        );
        let iniciador = Compilado {
            tipo: "iniciador",
            nome: "iniciador",
            ..compilado(arquivo, lock, &[])
        };
        assert_eq!(
            nome_do_registro(&iniciador, resumo),
            "iniciador-x86_64-release-0123456789abcdef.json"
        );
    }

    #[test]
    fn o_registro_liga_os_bytes_ao_compilador_a_fonte_e_a_ci() {
        let raiz = super::super::raiz_do_projeto();
        let arquivo = raiz.join("kernel/target/x86_64-unknown-none/release/duke");
        let lock = raiz.join("kernel/Cargo.lock");
        let resumo = sha256(b"duke");
        let texto = registro(
            &compilado(&arquivo, &lock, &["modo-teste"]),
            &resumo,
            4,
            Some("ab"),
            1_763_251_200,
        )
        .expect("o registro");
        assert!(texto.ends_with('\n'));
        let json = Json(texto.trim_end().as_bytes());
        let campo = |caminho: &[&str]| {
            caminho
                .iter()
                .try_fold(json, |j, c| j.member(c))
                .unwrap_or_else(|| panic!("{caminho:?} em {texto}"))
        };
        assert_eq!(campo(&["formato"]).as_str(), Some(FORMATO));
        assert_eq!(
            campo(&["artefato", "sha256"]).as_str(),
            Some(resumo.as_str())
        );
        assert_eq!(campo(&["artefato", "bytes"]).as_u64(), Some(4));
        assert_eq!(
            campo(&["artefato", "arquivo"]).as_str(),
            Some("kernel/target/x86_64-unknown-none/release/duke")
        );
        assert_eq!(
            campo(&["compilacao", "features"])
                .item(0)
                .and_then(|f| f.as_str()),
            Some("modo-teste")
        );
        assert_eq!(
            campo(&["compilacao", "alvo"]).as_str(),
            Some("x86_64-unknown-none")
        );
        assert_eq!(
            campo(&["fonte", "cargo_lock"]).as_str(),
            Some("kernel/Cargo.lock")
        );
        assert_eq!(campo(&["fonte", "cargo_lock_sha256"]).as_str(), Some("ab"));
        // Oficial é sem desvio nenhum.
        let oficial = campo(&["compilador", "oficial"])
            .as_bool()
            .expect("oficial");
        assert_eq!(oficial, campo(&["compilador", "desvios"]).item(0).is_none());
        assert_eq!(
            campo(&["registrado_em"]).as_str(),
            Some("2025-11-16T00:00:00Z")
        );
        // O `rustc -Vv` vai inteiro, com as quebras de linha escapadas.
        let rustc = campo(&["compilador", "rustc"]);
        assert!(rustc.is_null() || rustc.raw_str().is_some_and(|r| r.contains("\\n")));
    }

    #[test]
    fn o_registro_gravado_se_acha_pelo_resumo_do_artefato() {
        let dir = std::env::temp_dir().join(format!("xtask-proveniencia-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("o diretório");
        let arquivo = dir.join("duke");
        let lock = dir.join("Cargo.lock");
        std::fs::write(&arquivo, b"o kernel").expect("o artefato");
        std::fs::write(&lock, b"version = 4\n").expect("o lock");
        let registros = dir.join("proveniencia");
        let c = compilado(&arquivo, &lock, &[]);
        let registro = registrar_em(&registros, &c).expect("o registro");
        let resumo = sha256(b"o kernel");
        assert_eq!(
            registro.file_name().and_then(|n| n.to_str()),
            Some(format!("kernel-duke-x86_64-release-{}.json", &resumo[..16]).as_str())
        );
        let texto = std::fs::read_to_string(&registro).expect("o registro se lê");
        assert!(
            texto.contains(&format!("\"sha256\":\"{resumo}\"")),
            "{texto}"
        );
        assert!(texto.contains(&format!(
            "\"cargo_lock_sha256\":\"{}\"",
            sha256(b"version = 4\n")
        )));
        // Nada ficou pela metade ao lado.
        let nomes: Vec<_> = std::fs::read_dir(&registros)
            .expect("o diretório dos registros")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(nomes.len(), 1);

        assert_eq!(do_artefato_em(&registros, &resumo), Some(registro.clone()));
        // O mesmo começo, outro resumo: não é dele.
        let outro = format!("{}{}", &resumo[..16], "0".repeat(48));
        assert_eq!(do_artefato_em(&registros, &outro), None);
        assert_eq!(do_artefato_em(&registros, "curto"), None);
        assert_eq!(do_artefato_em(&dir.join("nao-existe"), &resumo), None);

        // O artefato que não se lê não deixa registro, e reprova.
        let sumido = dir.join("sumido");
        assert!(registrar_em(&registros, &compilado(&sumido, &lock, &[])).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_execucao_da_ci_sai_das_variaveis_do_github() {
        assert!(execucao_da_ci(|_| None).is_none());
        assert!(execucao_da_ci(|v| (v == "GITHUB_ACTIONS").then(|| "false".into())).is_none());
        let ci = execucao_da_ci(|v| {
            Some(
                match v {
                    "GITHUB_ACTIONS" => "true",
                    "GITHUB_SERVER_URL" => "https://github.com",
                    "GITHUB_REPOSITORY" => "dono/duke",
                    "GITHUB_RUN_ID" => "42",
                    "GITHUB_RUN_ATTEMPT" => "2",
                    "GITHUB_JOB" => "testes",
                    _ => return None,
                }
                .to_string(),
            )
        })
        .expect("na CI");
        let campo = |nome: &str| ci.iter().find(|(c, _)| *c == nome).map(|(_, v)| v.as_str());
        assert_eq!(campo("run_id"), Some("42"));
        assert_eq!(campo("tentativa"), Some("2"));
        assert_eq!(campo("job"), Some("testes"));
        assert_eq!(
            campo("endereco"),
            Some("https://github.com/dono/duke/actions/runs/42/attempts/2")
        );
        assert_eq!(campo("workflow"), Some(""));
    }
}
