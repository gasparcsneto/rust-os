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
//! | `futuro.duke` | o de `futuro.duke`, da raiz da bancada, que só vale de 2042 a 2044 |
//! | `antigo.duke` | o de `antigo.duke`, da raiz da bancada |
//! | `icp.duke` e `*.icp.duke` | o do proxy da bancada do IC, da raiz da bancada — ver [`super::icp`] |
//! | `p384.duke` | P-384, por um intermediário P-384 da raiz P-384 |
//! | `rsa.duke` | RSA de 2048 bits, por um intermediário RSA de 2048 da raiz RSA de 4096 |
//! | `misto.duke` | P-256, por um intermediário P-384 que a raiz RSA assina — a forma da cadeia ECDSA da Let's Encrypt pela raiz X1 |
//! | `intruso.duke` | o de `intruso.duke`, de uma raiz RSA que o programa **não** tem — e que o servidor manda junto |
//! | `falso-p384.duke` | P-256, pelo intermediário P-384 de `misto.duke`, com um bit da assinatura trocado |
//! | `falso-rsa.duke` | P-256, pelo intermediário RSA de `rsa.duke`, com um bit da assinatura trocado |
//!
//! O gate decide um destino só, `tcp:10.0.2.100:443`; os nomes são do TLS.
//! É a bancada que mostra que o nome não autoriza nada: o mesmo destino,
//! decidido uma vez pela política, serve um nome que o programa aceita e
//! outros que ele recusa. O `futuro.duke` ainda não vale em nenhuma hora da
//! bancada de tempo — a mais adiantada é o RTC em 2041 —: é o certificado
//! que a hora certa recusa por ser cedo. O `antigo.duke` é do servidor
//! HTTP: por ele, o ALPN só oferece o HTTP/1.1, como um servidor que não
//! fala HTTP/2.
//!
//! # As cadeias das autoridades públicas
//!
//! As cadeias de `p384.duke`, `rsa.duke` e `misto.duke` têm a forma das
//! públicas: um intermediário entre a folha e a raiz, a P-384 e o RSA nos
//! elos — as raízes e os intermediários da Let's Encrypt e da Google Trust
//! Services são P-384 ou RSA —, o PKCS#1 v1.5 nas assinaturas da cadeia e,
//! na folha RSA, o PSS no aperto. O servidor manda a folha e o
//! intermediário; a raiz, o programa tem. O `intruso.duke` é o contrário:
//! a raiz vem do servidor, e o programa não a aprende — `TLS_UNTRUSTED`. E
//! os dois `falso-*.duke` têm a cadeia certa e a assinatura da folha
//! estragada — a do intermediário P-384 e a do RSA, uma de cada conta —:
//! `TLS_UNTRUSTED` também, e só a verificação da assinatura os recusa.
//!
//! # As chaves
//!
//! Geradas aqui, em `target/bancada-tls`, na primeira vez — nunca no
//! repositório. As chaves das raízes e dos intermediários nem chegam ao
//! disco: assinam e somem. As RSA vêm do pacote `rsa`, de um ChaCha20
//! semeado pelo sistema — o *ring*, que o `rcgen` usa, não gera chave RSA.
//! O que vai para a imagem são só os certificados das três raízes da
//! bancada — a P-256, a RSA e a P-384 —, em `/dados/tls/bancada.pem`: as
//! âncoras em que o programa confia.

use std::io::Read;
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SignatureAlgorithm,
};

/// O script do servidor, no repositório.
pub(crate) const SERVIDOR: &str = "xtask/bancada/tls.py";

/// O script do servidor HTTP da bancada, no repositório: o claro e o
/// cifrado — este com os mesmos certificados do eco TLS. Ver
/// [`guestfwd_http`].
pub(crate) const SERVIDOR_HTTP: &str = "xtask/bancada/http.py";

/// Onde a âncora da bancada mora na imagem — o mesmo caminho que o programa
/// `cifrado` lê.
pub(crate) const ANCORA_NA_IMAGEM: &str = "dados/tls/bancada.pem";

/// A versão do formato do diretório: um diretório de outra versão é
/// refeito inteiro.
const VERSAO: &str = "bancada-tls v5\n";

/// O diretório da bancada, com os certificados e as chaves das folhas.
pub(crate) fn diretorio() -> PathBuf {
    super::raiz_do_projeto().join("target").join("bancada-tls")
}

/// Os arquivos que o servidor e a imagem leem.
const ARQUIVOS: [&str; 25] = [
    "ancoras.pem",
    "bancada.pem",
    "bancada.chave",
    "estranho.pem",
    "estranho.chave",
    "vencido.pem",
    "vencido.chave",
    "futuro.pem",
    "futuro.chave",
    "antigo.pem",
    "antigo.chave",
    "icp.pem",
    "icp.chave",
    "p384.pem",
    "p384.chave",
    "rsa.pem",
    "rsa.chave",
    "misto.pem",
    "misto.chave",
    "intruso.pem",
    "intruso.chave",
    "falso-p384.pem",
    "falso-p384.chave",
    "falso-rsa.pem",
    "falso-rsa.chave",
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

/// Os certificados das raízes da bancada, em PEM: as âncoras da imagem.
pub(crate) fn ancora() -> Result<Vec<u8>, String> {
    let caminho = preparar()?.join("ancoras.pem");
    std::fs::read(&caminho).map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))
}

/// Uma chave nova de `alg`. A RSA, de `bits` bits, vem do `rsa`, de um
/// ChaCha20 semeado pelo sistema; as outras, do *ring*.
fn chave(alg: &'static SignatureAlgorithm, bits: usize) -> Result<KeyPair, String> {
    if alg != &rcgen::PKCS_RSA_SHA256 {
        return KeyPair::generate_for(alg).map_err(|e| e.to_string());
    }
    use chacha20::rand_core::SeedableRng;
    use rsa::pkcs8::EncodePrivateKey;
    let mut semente = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut semente))
        .map_err(|e| format!("sem o aleatório do sistema para a chave RSA: {e}"))?;
    let rsa = rsa::RsaPrivateKey::new(&mut chacha20::ChaCha20Rng::from_seed(semente), bits)
        .map_err(|e| e.to_string())?;
    let der = rsa.to_pkcs8_der().map_err(|e| e.to_string())?;
    KeyPair::try_from(der.as_bytes()).map_err(|e| e.to_string())
}

/// O que uma autoridade tem no certificado.
fn autoridade(nome: &str) -> Result<CertificateParams, String> {
    let mut p = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, nome);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = rcgen::date_time_ymd(2024, 1, 1);
    p.not_after = rcgen::date_time_ymd(2045, 1, 1);
    Ok(p)
}

/// Uma raiz: o certificado autoassinado e quem assina com ela.
fn raiz(nome: &str, chave: KeyPair) -> Result<CertifiedIssuer<'static, KeyPair>, String> {
    CertifiedIssuer::self_signed(autoridade(nome)?, chave).map_err(|e| e.to_string())
}

/// Um intermediário assinado por `acima`: o certificado e quem assina com
/// ele.
fn intermediario(
    acima: &Issuer<'static, KeyPair>,
    nome: &str,
    chave: KeyPair,
) -> Result<CertifiedIssuer<'static, KeyPair>, String> {
    CertifiedIssuer::signed_by(autoridade(nome)?, chave, acima).map_err(|e| e.to_string())
}

/// Uma folha para `nomes` — o primeiro é o nome comum —, com a chave
/// `chave`, assinada por `emissor`, valendo de `de` a `ate` (1º de janeiro
/// de cada ano): o certificado e a chave, em PEM.
fn folha_com(
    emissor: &Issuer<'static, KeyPair>,
    chave: KeyPair,
    nomes: &[&str],
    de: i32,
    ate: i32,
) -> Result<(String, String), String> {
    let mut p = CertificateParams::new(nomes.iter().map(|n| n.to_string()).collect::<Vec<_>>())
        .map_err(|e| e.to_string())?;
    p.distinguished_name.push(DnType::CommonName, nomes[0]);
    p.not_before = rcgen::date_time_ymd(de, 1, 1);
    p.not_after = rcgen::date_time_ymd(ate, 1, 1);
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let certificado = p.signed_by(&chave, emissor).map_err(|e| e.to_string())?;
    Ok((certificado.pem(), chave.serialize_pem()))
}

/// O certificado em PEM com o último bit trocado: o fim de um certificado
/// é o fim da assinatura dele, que deixa de conferir — e o resto, a forma
/// e a chave, fica igual.
fn com_a_assinatura_trocada(certificado: &str) -> Result<String, String> {
    let lido = pem::parse(certificado).map_err(|e| e.to_string())?;
    let mut der = lido.contents().to_vec();
    let ultimo = der.last_mut().ok_or("certificado vazio")?;
    *ultimo ^= 0x01;
    Ok(pem::encode_config(
        &pem::Pem::new("CERTIFICATE", der),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    ))
}

/// Uma folha P-256 — ver [`folha_com`].
fn folha(
    emissor: &Issuer<'static, KeyPair>,
    nomes: &[&str],
    de: i32,
    ate: i32,
) -> Result<(String, String), String> {
    let p256 = chave(&rcgen::PKCS_ECDSA_P256_SHA256, 0)?;
    folha_com(emissor, p256, nomes, de, ate)
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

    let p256 = || chave(&rcgen::PKCS_ECDSA_P256_SHA256, 0);
    let p384 = || chave(&rcgen::PKCS_ECDSA_P384_SHA384, 0);
    let rsa = |bits| chave(&rcgen::PKCS_RSA_SHA256, bits);
    let da_bancada = raiz("Raiz da bancada do Duke", p256()?)?;
    let estranha = raiz("Raiz estranha", p256()?)?;
    let (bancada, bancada_chave) = folha(&da_bancada, &["bancada.duke"], 2025, 2040)?;
    let (estranho, estranho_chave) = folha(&estranha, &["estranho.duke"], 2025, 2040)?;
    let (vencido, vencido_chave) = folha(&da_bancada, &["vencido.duke"], 2020, 2021)?;
    let (futuro, futuro_chave) = folha(&da_bancada, &["futuro.duke"], 2042, 2044)?;
    let (antigo, antigo_chave) = folha(&da_bancada, &["antigo.duke"], 2025, 2040)?;
    // O proxy da bancada do IC: um nome por modo, todos sob `icp.duke`.
    let (icp, icp_chave) = folha(&da_bancada, &["icp.duke", "*.icp.duke"], 2025, 2040)?;
    // As cadeias das autoridades públicas: a folha e o intermediário, num
    // arquivo só — é o que o servidor manda.
    let raiz_rsa = raiz("Raiz RSA da bancada do Duke", rsa(4096)?)?;
    let raiz_p384 = raiz("Raiz P-384 da bancada do Duke", p384()?)?;
    let meio_p384 = intermediario(&raiz_p384, "Intermediario P-384 da bancada", p384()?)?;
    let meio_rsa = intermediario(&raiz_rsa, "Intermediario RSA da bancada", rsa(2048)?)?;
    let meio_misto = intermediario(&raiz_rsa, "Intermediario misto da bancada", p384()?)?;
    let intrusa = raiz("Raiz intrusa", rsa(2048)?)?;
    let com = |(folha, chave): (String, String), acima: String| (folha + &acima, chave);
    let (p384_pem, p384_chave) = com(
        folha_com(&meio_p384, p384()?, &["p384.duke"], 2025, 2040)?,
        meio_p384.pem(),
    );
    let (rsa_pem, rsa_chave) = com(
        folha_com(&meio_rsa, rsa(2048)?, &["rsa.duke"], 2025, 2040)?,
        meio_rsa.pem(),
    );
    let (misto, misto_chave) = com(
        folha(&meio_misto, &["misto.duke"], 2025, 2040)?,
        meio_misto.pem(),
    );
    let (intruso, intruso_chave) = com(
        folha(&intrusa, &["intruso.duke"], 2025, 2040)?,
        intrusa.pem(),
    );
    let falsa = |emissor: &Issuer<'static, KeyPair>, nome: &str| {
        folha(emissor, &[nome], 2025, 2040)
            .and_then(|(f, chave)| Ok((com_a_assinatura_trocada(&f)?, chave)))
    };
    let (falso_p384, falso_p384_chave) =
        com(falsa(&meio_misto, "falso-p384.duke")?, meio_misto.pem());
    let (falso_rsa, falso_rsa_chave) = com(falsa(&meio_rsa, "falso-rsa.duke")?, meio_rsa.pem());
    let ancoras = da_bancada.pem() + &raiz_rsa.pem() + &raiz_p384.pem();

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
    escrever("ancoras.pem", &ancoras, false)?;
    escrever("bancada.pem", &bancada, false)?;
    escrever("bancada.chave", &bancada_chave, true)?;
    escrever("estranho.pem", &estranho, false)?;
    escrever("estranho.chave", &estranho_chave, true)?;
    escrever("vencido.pem", &vencido, false)?;
    escrever("vencido.chave", &vencido_chave, true)?;
    escrever("futuro.pem", &futuro, false)?;
    escrever("futuro.chave", &futuro_chave, true)?;
    escrever("antigo.pem", &antigo, false)?;
    escrever("antigo.chave", &antigo_chave, true)?;
    escrever("icp.pem", &icp, false)?;
    escrever("icp.chave", &icp_chave, true)?;
    escrever("p384.pem", &p384_pem, false)?;
    escrever("p384.chave", &p384_chave, true)?;
    escrever("rsa.pem", &rsa_pem, false)?;
    escrever("rsa.chave", &rsa_chave, true)?;
    escrever("misto.pem", &misto, false)?;
    escrever("misto.chave", &misto_chave, true)?;
    escrever("intruso.pem", &intruso, false)?;
    escrever("intruso.chave", &intruso_chave, true)?;
    escrever("falso-p384.pem", &falso_p384, false)?;
    escrever("falso-p384.chave", &falso_p384_chave, true)?;
    escrever("falso-rsa.pem", &falso_rsa, false)?;
    escrever("falso-rsa.chave", &falso_rsa_chave, true)?;
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

/// Os `guestfwd` do servidor HTTP da bancada: `10.0.2.100:80`, o HTTP
/// claro, e `10.0.2.100:8443`, o mesmo servidor atrás do TLS — com os
/// certificados e a escolha pelo nome do eco TLS. Como ele, um processo do
/// script a cada conexão, sem porta aberta no hospedeiro.
///
/// Dois destinos, e não um com dois nomes: o esquema é parte do que o
/// programa pede, e o destino é o que o gate decide — cada um enumerado na
/// política. O caminho, o método, o `Host` e o status são do protocolo, e
/// não aparecem para o gate.
pub(crate) fn guestfwd_http() -> Result<String, String> {
    let dir = preparar()?;
    let script = super::raiz_do_projeto().join(SERVIDOR_HTTP);
    let (dir, script) = (dir.display().to_string(), script.display().to_string());
    for caminho in [&dir, &script] {
        if caminho.contains([',', ' ']) {
            return Err(format!(
                "o caminho da bancada HTTP não cabe na opção do emulador: {caminho}"
            ));
        }
    }
    Ok(format!(
        "guestfwd=tcp:10.0.2.100:80-cmd:python3 {script} {dir},\
         guestfwd=tcp:10.0.2.100:8443-cmd:python3 {script} {dir} tls"
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
