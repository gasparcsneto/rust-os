//! A bancada TLS: o servidor com que o cliente TLS do Duke conversa na
//! suíte e na fumaça, e os certificados dele.
//!
//! # Uma implementação de fora
//!
//! O cliente do Duke é o `rustls`, com o provedor do pacote `tls`. O
//! servidor da bancada é o **OpenSSL**, pelo módulo `ssl` do Python — outra
//! implementação inteira do protocolo, como o `snow` é do Noise e o `swtpm`
//! do TPM: uma implementação só concorda consigo mesma mesmo errada.
//!
//! # Sem porta aberta no hospedeiro
//!
//! Como o eco TCP: um `guestfwd` do emulador roda, a **cada conexão** para
//! `10.0.2.100:443`, o [`SERVIDOR`] — um script Python que recebe a
//! conexão nos descritores 0, 1 e 2 (o `libslirp` os liga a um par de
//! sockets), faz o aperto e devolve o que chegar. Nenhum servidor escuta
//! no hospedeiro, e nada de fora alcança a bancada.
//!
//! # Vários nomes, um destino
//!
//! O servidor escolhe o certificado pelo nome que o cliente pede (SNI):
//!
//! | nome | certificado |
//! |---|---|
//! | `bancada.duke` (e qualquer outro) | o de `bancada.duke`, da raiz da bancada |
//! | `estranho.duke` | o de `estranho.duke`, de **outra** raiz |
//! | `vencido.duke` | o de `vencido.duke`, da raiz da bancada, vencido em 2021 |
//!
//! O gate decide um destino só, `tcp:10.0.2.100:443`; os nomes são do TLS.
//! É a bancada que mostra que o nome não autoriza nada: o mesmo destino,
//! decidido uma vez pela política, serve um nome que o programa aceita e
//! três que ele recusa.
//!
//! # As chaves
//!
//! Geradas aqui, em `target/bancada-tls`, na primeira vez — nunca no
//! repositório. A chave da raiz nem chega ao disco: assina as folhas e
//! some. O que vai para a imagem é só o certificado da raiz, em
//! `/dados/tls/bancada.pem`: a âncora em que o programa confia.

use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

/// O script do servidor, no repositório.
pub(crate) const SERVIDOR: &str = "xtask/bancada/tls.py";

/// Onde a âncora da bancada mora na imagem — o mesmo caminho que o programa
/// `cifrado` lê.
pub(crate) const ANCORA_NA_IMAGEM: &str = "dados/tls/bancada.pem";

/// A versão do formato do diretório: um diretório de outra versão é
/// refeito inteiro.
const VERSAO: &str = "bancada-tls v1\n";

/// O diretório da bancada, com os certificados e as chaves das folhas.
pub(crate) fn diretorio() -> PathBuf {
    super::raiz_do_projeto().join("target").join("bancada-tls")
}

/// Os arquivos que o servidor e a imagem leem.
const ARQUIVOS: [&str; 7] = [
    "raiz.pem",
    "bancada.pem",
    "bancada.chave",
    "estranho.pem",
    "estranho.chave",
    "vencido.pem",
    "vencido.chave",
];

/// Prepara a bancada, se ainda não está pronta, e devolve o diretório.
pub(crate) fn preparar() -> Result<PathBuf, String> {
    let dir = diretorio();
    let pronta = std::fs::read_to_string(dir.join("versao")).ok().as_deref() == Some(VERSAO)
        && ARQUIVOS.iter().all(|a| dir.join(a).is_file());
    if pronta {
        return Ok(dir);
    }
    gerar(&dir)?;
    Ok(dir)
}

/// O certificado da raiz da bancada, em PEM: a âncora da imagem.
pub(crate) fn ancora() -> Result<Vec<u8>, String> {
    let caminho = preparar()?.join("raiz.pem");
    std::fs::read(&caminho).map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))
}

/// Uma raiz: o certificado autoassinado e quem assina com ela.
fn raiz(nome: &str) -> Result<CertifiedIssuer<'static, KeyPair>, String> {
    let mut p = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, nome);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = rcgen::date_time_ymd(2024, 1, 1);
    p.not_after = rcgen::date_time_ymd(2045, 1, 1);
    let chave = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    CertifiedIssuer::self_signed(p, chave).map_err(|e| e.to_string())
}

/// Uma folha para `nome`, assinada por `raiz`, valendo de `de` a `ate`
/// (1º de janeiro de cada ano): o certificado e a chave, em PEM.
fn folha(
    raiz: &CertifiedIssuer<'static, KeyPair>,
    nome: &str,
    de: i32,
    ate: i32,
) -> Result<(String, String), String> {
    let mut p = CertificateParams::new(vec![nome.to_string()]).map_err(|e| e.to_string())?;
    p.distinguished_name.push(DnType::CommonName, nome);
    p.not_before = rcgen::date_time_ymd(de, 1, 1);
    p.not_after = rcgen::date_time_ymd(ate, 1, 1);
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let chave = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let certificado = p.signed_by(&chave, raiz).map_err(|e| e.to_string())?;
    Ok((certificado.pem(), chave.serialize_pem()))
}

/// Gera a bancada inteira num diretório novo e o põe no lugar do antigo.
fn gerar(dir: &Path) -> Result<(), String> {
    let pai = dir.parent().ok_or("o diretório da bancada não tem pai")?;
    std::fs::create_dir_all(pai)
        .map_err(|e| format!("não foi possível criar {}: {e}", pai.display()))?;
    let novo = pai.join(format!("bancada-tls.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&novo);
    std::fs::create_dir_all(&novo)
        .map_err(|e| format!("não foi possível criar {}: {e}", novo.display()))?;

    let da_bancada = raiz("Raiz da bancada do Duke")?;
    let estranha = raiz("Raiz estranha")?;
    let (bancada, bancada_chave) = folha(&da_bancada, "bancada.duke", 2025, 2040)?;
    let (estranho, estranho_chave) = folha(&estranha, "estranho.duke", 2025, 2040)?;
    let (vencido, vencido_chave) = folha(&da_bancada, "vencido.duke", 2020, 2021)?;

    let escrever = |nome: &str, conteudo: &str, privado: bool| -> Result<(), String> {
        let caminho = novo.join(nome);
        std::fs::write(&caminho, conteudo)
            .map_err(|e| format!("não foi possível gravar {}: {e}", caminho.display()))?;
        if privado {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&caminho, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("não foi possível proteger {}: {e}", caminho.display()))?;
        }
        Ok(())
    };
    escrever("raiz.pem", &da_bancada.pem(), false)?;
    escrever("bancada.pem", &bancada, false)?;
    escrever("bancada.chave", &bancada_chave, true)?;
    escrever("estranho.pem", &estranho, false)?;
    escrever("estranho.chave", &estranho_chave, true)?;
    escrever("vencido.pem", &vencido, false)?;
    escrever("vencido.chave", &vencido_chave, true)?;
    escrever("versao", VERSAO, false)?;

    let _ = std::fs::remove_dir_all(dir);
    std::fs::rename(&novo, dir).map_err(|e| {
        format!(
            "não foi possível pôr a bancada TLS em {}: {e}",
            dir.display()
        )
    })
}

/// O `guestfwd` do eco TLS: o destino e o comando que o emulador roda a
/// cada conexão. O emulador corta as opções nas vírgulas e o comando nos
/// espaços: um caminho com um dos dois não cabe.
pub(crate) fn guestfwd() -> Result<String, String> {
    let dir = preparar()?;
    let script = super::raiz_do_projeto().join(SERVIDOR);
    let (dir, script) = (dir.display().to_string(), script.display().to_string());
    for caminho in [&dir, &script] {
        if caminho.contains([',', ' ']) {
            return Err(format!(
                "o caminho da bancada TLS não cabe na opção do emulador: {caminho}"
            ));
        }
    }
    Ok(format!(
        "guestfwd=tcp:10.0.2.100:443-cmd:python3 {script} {dir}"
    ))
}

/// Confere que o hospedeiro tem o que o servidor precisa: o Python 3 com o
/// módulo `ssl` e TLS 1.3. Sem ele, cada conexão ao eco TLS cairia sem
/// explicação; aqui o erro diz o quê.
pub(crate) fn conferir_o_hospedeiro() -> Result<(), String> {
    let saida = std::process::Command::new("python3")
        .args([
            "-c",
            "import ssl; assert ssl.HAS_TLSv1_3; print(ssl.OPENSSL_VERSION)",
        ])
        .output()
        .map_err(|e| format!("a bancada TLS precisa do python3 no hospedeiro: {e}"))?;
    if !saida.status.success() {
        return Err(format!(
            "o python3 do hospedeiro não tem o módulo ssl com TLS 1.3: {}",
            String::from_utf8_lossy(&saida.stderr)
        ));
    }
    Ok(())
}
