//! A bancada do Internet Computer: a PocketIC, fixada, o canister da
//! bancada e o proxy TLS que a suíte usa para mentir.
//!
//! # A PocketIC
//!
//! O IC de verdade da bancada: a [`VERSAO`] da PocketIC, o binário da
//! release oficial da DFINITY, baixado uma vez para `target/pocketic/` e
//! **conferido pelo SHA-256** ([`SHA256`]) antes de rodar — um binário que
//! não confere não roda. Ela escuta em `127.0.0.1`, numa porta que ela
//! escolhe, e nada de fora a alcança.
//!
//! [`Bancada::ligar`] sobe o servidor e roda `bancada/icp.py preparar`: a
//! instância (a NNS e duas sub-redes de aplicação), o canister da bancada e
//! o gateway HTTP dela — ver o cabeçalho do script. A PocketIC deriva as
//! chaves das sub-redes de sementes fixas: a raiz e o canister são os
//! mesmos a cada instância desta versão, e a bancada confere que são
//! [`RAIZ`] e [`CANISTER`]. Uma PocketIC que mudou é um erro aqui, e não um
//! caso da suíte falhando sem dizer por quê.
//!
//! # O proxy, sem porta aberta no hospedeiro
//!
//! Como o eco TLS: um `guestfwd` do emulador roda, a **cada conexão** para
//! `10.0.2.100:4943`, o script em modo `proxy` — o TLS 1.3 com o
//! certificado de `icp.duke` e `*.icp.duke` da raiz da bancada, e cada
//! pedido HTTP repassado ao gateway. O nome que o TLS provou escolhe o que
//! o proxy faz com a resposta: nada, atrasar, ou mentir de um jeito.
//!
//! # As redes na imagem
//!
//! `/dados/icp/redes` ([`redes`]): uma rede por modo do proxy, todas com a
//! raiz da PocketIC — menos a `raiz-errada`, com a da rede principal do IC,
//! que é de outra rede. O gate decide um destino só, `tcp:10.0.2.100:4943`,
//! para todas: os nomes são do TLS e do programa, e não autorizam nada.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

/// A versão da PocketIC da bancada.
pub(crate) const VERSAO: &str = "16.1.0";

/// O binário da release oficial.
const URL: &str =
    "https://github.com/dfinity/pocketic/releases/download/16.1.0/pocket-ic-x86_64-linux.gz";

/// O SHA-256 do arquivo da release, conferido antes de rodar.
const SHA256: &str = "131219d90dcf9bf6f3ed8ee02d8f55504ea24a6db382f5680675b7bd6b7ed3bf";

/// O script da bancada, no repositório.
pub(crate) const SCRIPT: &str = "xtask/bancada/icp.py";

/// Onde as redes moram na imagem — o caminho que `web3::icp::registro` lê.
pub(crate) const REDES_NA_IMAGEM: &str = "dados/icp/redes";

/// A chave da raiz da PocketIC da [`VERSAO`], em DER: a da sub-rede NNS,
/// a mesma a cada instância.
pub(crate) const RAIZ: &str = "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100a587ac27884f235a91ddd86927eec11e09872417231b41ab8fb95605c633af9702849c0ad6929613392b39c715fc232c0a0d8eb00a1ea91985b3e440bc9d0b78a5872f96dae753f395cd6602516ad58748d698958976c6c25b86c55aa30a3af9";

/// O canister da bancada: o primeiro da primeira sub-rede de aplicação.
/// O programa `icp` tem o mesmo.
pub(crate) const CANISTER: &str = "pi33i-pt777-77776-aaaaa-cai";

/// O canister da bancada na NNS, a sub-rede raiz: o mesmo módulo, e a
/// prova sem delegação — a raiz assina, e as faixas vêm da leitura à parte
/// de `["subnet"]`. O programa `icp` tem o mesmo.
pub(crate) const CANISTER_DA_RAIZ: &str = "xp3jw-ot777-77777-aaaaa-cai";

/// A sub-rede do canister: a suíte confere que a prova veio dela.
const SUB_REDE: &str = "753q6-ah42a-rm7md-yb6nn-3egqb-e2tyy-zdjgf-ind25-haovq-fe74w-pqe";

/// A chave da raiz da rede principal do IC — pública, e de outra rede: a
/// da `raiz-errada`.
const RAIZ_DE_OUTRA_REDE: &str = "308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae";

/// As redes da imagem, na ordem do programa `icp`: o nome, e se o host
/// vai pelo DNS — senão, o endereço fixo da bancada. A `bancada` passa
/// pelo DNS da suíte; as outras, direto — e a `direta` é a honesta sem
/// DNS, a da fumaça: a imagem de produção não tem o DNS da suíte.
pub(crate) const REDES: [(&str, bool); 13] = [
    ("bancada", true),
    ("lenta", false),
    ("raiz-errada", false),
    ("bls-invalida", false),
    ("sem-assinatura", false),
    ("no-de-fora", false),
    ("assinatura-errada", false),
    ("pedido-trocado", false),
    ("aninhada", false),
    ("faixa-errada", false),
    ("velho", false),
    ("direta", false),
    ("assincrona", false),
];

/// O conteúdo de `/dados/icp/redes`.
pub(crate) fn redes() -> String {
    // Curto: o arquivo inteiro cabe num pedaço do `fs.read`.
    let mut texto =
        String::from("# A PocketIC da bancada, um modo do proxy por rede (xtask/src/icp.rs).\n");
    for (nome, dns) in REDES {
        let host = if nome == "bancada" {
            String::from("icp.duke")
        } else {
            format!("{nome}.icp.duke")
        };
        let endereco = if dns { "dns" } else { "10.0.2.100" };
        let raiz = if nome == "raiz-errada" {
            RAIZ_DE_OUTRA_REDE
        } else {
            RAIZ
        };
        texto.push_str(&format!(
            "rede {nome} https://{host}:4943 {endereco} bls:{raiz}\n"
        ));
    }
    texto
}

/// O diretório da bancada: o estado da instância, a resposta velha e os
/// registros do proxy.
pub(crate) fn diretorio() -> PathBuf {
    super::raiz_do_projeto().join("target").join("bancada-icp")
}

/// O `guestfwd` do proxy: o destino e o comando que o emulador roda a cada
/// conexão. Sem a bancada ligada, cada conexão cai — o proxy não acha o
/// estado —, e só os casos do IC dependem dela.
pub(crate) fn guestfwd() -> Result<String, String> {
    let script = super::raiz_do_projeto().join(SCRIPT);
    let tls = super::tls::preparar()?;
    let dir = diretorio();
    let (script, dir, tls) = (
        script.display().to_string(),
        dir.display().to_string(),
        tls.display().to_string(),
    );
    for caminho in [&script, &dir, &tls] {
        if caminho.contains([',', ' ']) {
            return Err(format!(
                "o caminho da bancada do IC não cabe na opção do emulador: {caminho}"
            ));
        }
    }
    Ok(format!(
        "guestfwd=tcp:10.0.2.100:4943-cmd:python3 -I {script} proxy {dir} {tls}"
    ))
}

/// O SHA-256 de `bytes`, em hexadecimal.
fn resumo(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// O binário da PocketIC, conferido: baixado na primeira vez, e
/// desempacotado de um arquivo cujo SHA-256 é o fixado.
fn pocketic() -> Result<PathBuf, String> {
    let dir = super::raiz_do_projeto()
        .join("target")
        .join("pocketic")
        .join(VERSAO);
    let binario = dir.join("pocket-ic");
    let marca = dir.join("pocket-ic.sha256");
    if binario.is_file() && std::fs::read_to_string(&marca).ok().as_deref() == Some(SHA256) {
        return Ok(binario);
    }
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("não foi possível criar {}: {e}", dir.display()))?;
    let arquivo = dir.join("pocket-ic-x86_64-linux.gz");
    if !arquivo.is_file() {
        println!("[xtask] baixando a PocketIC {VERSAO}");
        let parcial = dir.join("pocket-ic-x86_64-linux.gz.parcial");
        let status = Command::new("curl")
            .args(["-fsSL", "--retry", "3", "-o"])
            .arg(&parcial)
            .arg(URL)
            .status()
            .map_err(|e| format!("não foi possível rodar o curl: {e}"))?;
        if !status.success() {
            return Err(format!("o download da PocketIC falhou ({status}): {URL}"));
        }
        std::fs::rename(&parcial, &arquivo)
            .map_err(|e| format!("não foi possível guardar {}: {e}", arquivo.display()))?;
    }
    let bytes = std::fs::read(&arquivo)
        .map_err(|e| format!("não foi possível ler {}: {e}", arquivo.display()))?;
    let obtido = resumo(&bytes);
    if obtido != SHA256 {
        let _ = std::fs::remove_file(&arquivo);
        return Err(format!(
            "a PocketIC baixada não confere: SHA-256 {obtido}, e o fixado é {SHA256}"
        ));
    }
    let saida = std::fs::File::create(&binario)
        .map_err(|e| format!("não foi possível criar {}: {e}", binario.display()))?;
    let status = Command::new("gzip")
        .arg("-dc")
        .arg(&arquivo)
        .stdout(saida)
        .status()
        .map_err(|e| format!("não foi possível rodar o gzip: {e}"))?;
    if !status.success() {
        return Err(format!("o gzip não desempacotou a PocketIC ({status})"));
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&binario, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("não foi possível marcar {}: {e}", binario.display()))?;
    std::fs::write(&marca, SHA256)
        .map_err(|e| format!("não foi possível gravar {}: {e}", marca.display()))?;
    Ok(binario)
}

/// Um campo de texto do `estado.json` do script.
fn campo(estado: &str, nome: &str) -> Option<String> {
    let j = protocolo::json::Json(estado.as_bytes());
    j.member(nome)?.as_str().map(String::from)
}

/// A PocketIC ligada, com a instância da bancada pronta. Largada, o
/// servidor sai.
pub(crate) struct Bancada {
    servidor: Child,
}

impl Bancada {
    /// Sobe a PocketIC e prepara a instância — ver o cabeçalho do módulo.
    pub(crate) fn ligar() -> Result<Bancada, String> {
        let binario = pocketic()?;
        let dir = diretorio();
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("não foi possível criar {}: {e}", dir.display()))?;
        let porta = dir.join("porta");
        let _ = std::fs::remove_file(&porta);
        let _ = std::fs::remove_file(dir.join("estado.json"));
        let registro = std::fs::File::create(dir.join("pocketic.log"))
            .map_err(|e| format!("não foi possível criar o registro da PocketIC: {e}"))?;
        let servidor = Command::new(&binario)
            .arg("--port-file")
            .arg(&porta)
            // Ociosa por seis horas, ela sai sozinha: um `xtask` morto sem
            // largar a bancada não a deixa para sempre — e a suíte mais
            // lenta chega aos casos do IC muito antes.
            .args(["--ttl", "21600"])
            .stdout(Stdio::null())
            .stderr(registro)
            .spawn()
            .map_err(|e| format!("não foi possível iniciar a PocketIC: {e}"))?;
        let mut bancada = Bancada { servidor };
        let inicio = Instant::now();
        let numero = loop {
            if let Ok(texto) = std::fs::read_to_string(&porta)
                && let Ok(n) = texto.trim().parse::<u16>()
            {
                break n;
            }
            if let Ok(Some(status)) = bancada.servidor.try_wait() {
                return Err(format!(
                    "a PocketIC saiu antes de escutar ({status}); ver {}",
                    dir.join("pocketic.log").display()
                ));
            }
            if inicio.elapsed() > Duration::from_secs(60) {
                return Err("a PocketIC não escutou em 60s".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        bancada.preparar(numero, &dir)?;
        Ok(bancada)
    }

    fn preparar(&mut self, porta: u16, dir: &Path) -> Result<(), String> {
        let script = super::raiz_do_projeto().join(SCRIPT);
        let saida = Command::new("python3")
            .arg("-I")
            .arg(&script)
            .arg("preparar")
            .arg(format!("http://127.0.0.1:{porta}"))
            .arg(dir)
            .output()
            .map_err(|e| format!("não foi possível rodar o script da bancada do IC: {e}"))?;
        if !saida.status.success() {
            return Err(format!(
                "a bancada do IC não se preparou ({}):\n{}",
                saida.status,
                String::from_utf8_lossy(&saida.stderr)
            ));
        }
        let estado = std::fs::read_to_string(dir.join("estado.json"))
            .map_err(|e| format!("a bancada do IC não deixou o estado: {e}"))?;
        let raiz = campo(&estado, "raiz").unwrap_or_default();
        let canister = campo(&estado, "canister").unwrap_or_default();
        let sub_rede = campo(&estado, "sub_rede").unwrap_or_default();
        let da_raiz = campo(&estado, "canister_da_raiz").unwrap_or_default();
        if raiz != RAIZ
            || canister != CANISTER
            || sub_rede != SUB_REDE
            || da_raiz != CANISTER_DA_RAIZ
        {
            return Err(format!(
                "a PocketIC {VERSAO} não é a fixada: raiz {raiz}, canister {canister}, sub-rede {sub_rede}, canister da raiz {da_raiz}"
            ));
        }
        println!("[xtask] bancada do IC: PocketIC {VERSAO}, canister {canister}");
        Ok(())
    }
}

impl Drop for Bancada {
    fn drop(&mut self) {
        let _ = self.servidor.kill();
        let _ = self.servidor.wait();
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    /// As redes da imagem são as que o registro do programa lê: os nomes,
    /// os hosts, as chaves — e o arquivo inteiro vale.
    #[test]
    fn as_redes_da_imagem() {
        let texto = redes();
        let lidas = web3::icp::registro::ler(&texto).expect("o arquivo da imagem não vale");
        assert_eq!(lidas.len(), REDES.len());
        for ((nome, dns), rede) in REDES.iter().zip(&lidas) {
            assert_eq!(rede.nome, *nome);
            assert_eq!(rede.porta, 4943);
            assert_eq!(rede.endereco.is_none(), *dns);
            assert!(rede.host == "icp.duke" || rede.host == format!("{nome}.icp.duke"));
        }
        let raiz = |n: &str| lidas.iter().find(|r| r.nome == n).unwrap().raiz;
        assert_ne!(raiz("raiz-errada"), raiz("bancada"));
        assert_eq!(raiz("velho"), raiz("bancada"));
        assert_eq!(raiz("direta"), raiz("bancada"));
        assert_eq!(raiz("assincrona"), raiz("bancada"));
        // O programa lê o arquivo em pedaços de 4 KiB do `fs.read`, uma
        // decisão do gate cada: dois, com as treze redes — a suíte conta
        // pelo tamanho.
        assert!(texto.len() <= 2 * 4096, "{} bytes", texto.len());
    }
}
