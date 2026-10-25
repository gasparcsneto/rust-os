//! A fumaça real da rede principal do IC — `cargo xtask mainnet`: à mão, e
//! fora da CI, que não depende da rede principal (ver `docs/ICP.md`, *A
//! rede principal*). Só leitura: uma consulta anônima ao livro-razão do
//! ICP, e as duas consultas assinadas do [`GESTOR`] — o saldo de uma chave
//! nova, sem fundos, no ledger de ICP e no de cycles —, e nada que mude
//! estado, nem que mova valor, na rede principal.
//!
//! # O que precisa
//!
//! Uma máquina com a rede de verdade: DNS por UDP e TCP na porta 443, sem
//! proxy que reabra o TLS. O TLS do programa confere a cadeia verdadeira de
//! `icp-api.io` pelas âncoras públicas da imagem, e a de um proxy é
//! recusada (`TLS_UNTRUSTED`), como deve. O emulador faz o DNS (`10.0.2.3`)
//! e o TCP pela rede do hospedeiro.
//!
//! # Os passos
//!
//! 1. **O pré-voo, no hospedeiro**: os IPv4 de `icp-api.io` pelos dois
//!    caminhos do hospedeiro — o resolvedor do sistema e a pergunta da
//!    máquina, ver *A janela do DNS* — ou os de `--enderecos`, e a cadeia
//!    TLS que cada um apresenta, pelo `openssl s_client`, lida como dado:
//!    cada certificado com a chave e o algoritmo da assinatura, contra o
//!    perfil do TLS do programa e as âncoras da imagem. Um algoritmo fora do
//!    perfil para a fumaça com `TLS_PROFILE_GAP`, e uma raiz fora das
//!    âncoras, com `TLS_ANCHOR_GAP`: os dois são o relatório de uma decisão
//!    que falta, e nenhum amplia nada. O pré-voo não é a verificação —
//!    quem verifica é o programa, na máquina;
//! 2. **a imagem**: a de produção, com os IPv4 no teto — `tcp:<ipv4>:443`
//!    no `net.connect` e no `net.block` do `sistema` e do `administrador`,
//!    e no `net.block` do `seguranca` —, enumerados, como todo destino. O
//!    operador não os tem: quem os dá é o administrador, pelo
//!    `policy.write`, com prova;
//! 3. **o gate antes do transporte**: o agente da porta 2, do papel
//!    `operador`, lança o [`PROGRAMA`]; o nome resolve, e o `net.connect`
//!    é `DENY_RESOURCE` — nenhum byte vai à rede principal. E cria a chave
//!    `chave:bancada`, pelo gate, no domínio do pedido do IC, grava o pedido
//!    do saldo no armazém e lança o [`GESTOR`]: recusado do mesmo jeito,
//!    sem assinatura nenhuma;
//! 4. **a política**: o `policy.write` da linha do operador com os IPv4,
//!    com a prova do administrador da imagem;
//! 5. **a consulta**: de novo o programa — o DNS, o destino pelo gate, o TLS
//!    real, o `read_state` e o `query`, a verificação pela raiz da rede
//!    principal —, e o símbolo, `ICP`; e de novo o gestor: as duas
//!    consultas assinadas pela chave nova — `key.sign`, uma decisão do gate
//!    cada —, verificadas pela mesma raiz, e os dois saldos;
//! 6. **a auditoria**: cada decisão de cada processo; a declaração da
//!    consulta anônima ancorada na conexão, com o destino real que o kernel
//!    viu, e as duas do gestor, cada uma na decisão da sua assinatura;
//! 7. **a revogação**: a linha do operador de volta, e o programa e o
//!    gestor de novo — `DENY_RESOURCE`, sem assinatura;
//! 8. **o relatório**, em `target/mainnet/`: o endpoint, a hora, os IPv4, a
//!    cadeia, o destino, a suíte do TLS, a medida de cada parte, a prova e a
//!    resposta; e, do gestor, a impressão da chave, a resposta no armazém —
//!    o Principal dela, no caminho do registro — e a auditoria.
//!
//! # A janela do DNS
//!
//! A máquina pergunta o nome ao DNS do emulador (`10.0.2.3`), que repassa
//! a pergunta ao primeiro `nameserver` IPv4 do `/etc/resolv.conf` do
//! hospedeiro, e conecta ao primeiro endereço da resposta; a política só
//! tem os que o pré-voo leu. Duas coisas cuidam de que sejam os mesmos:
//!
//! - **a mesma pergunta**: o pré-voo faz, do hospedeiro, a pergunta que a
//!   máquina vai fazer — os mesmos bytes, de `protocolo::dns`, ao mesmo
//!   servidor —, além da do resolvedor do sistema, e a política leva as
//!   duas respostas. Elas não são iguais: na primeira fumaça num runner do
//!   GitHub, o resolvedor do sistema deu um nó, e a máquina, nas três
//!   rodadas e nos dois runners, sempre outro;
//! - **a mesma hora**: a máquina é compilada antes do pré-voo. Compilada
//!   depois, a frio — num runner, são minutos —, a resposta que o pré-voo
//!   leu já teria saído do cache do resolvedor quando a máquina
//!   perguntasse.
//!
//! Um endereço que o pré-voo não leu continua recusado pelo gate
//! (`DENY_RESOURCE`): a falha é fechada, e a auditoria do relatório diz o
//! destino recusado.
//!
//! A máquina sobe sobre o estado zerado — o do disco e o do TPM, como em
//! toda bancada — e sem servidor de hora, como a fumaça principal: a hora
//! do programa é a do tempo lógico, que vem do RTC do emulador — o relógio
//! do hospedeiro —, e o programa diz isso (`hora rtc`).
//!
//! `--ensaio` pula o pré-voo e não espera a rede principal: confere a
//! máquina, a política, o programa e a auditoria onde a rede não chega, e
//! diz até onde foi. **Não é a fumaça real**, e diz isso.
//!
//! O fluxo `.github/workflows/rede-principal.yml` roda este comando num
//! runner do GitHub, quando alguém o pede: a CI não o roda.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use super::persistencia::Ligada;
use super::tempo::{administrar, auditoria, campo, data_de, ultimo_do_log};
use super::{AgenteNaPorta, Ambiente, Arquitetura, Artefato, ObjetoPlano, zerar_o_estado};

/// O programa que consulta, e o código com que ele sai quando o símbolo
/// verificado é `ICP` — ver `programas/src/bin/livro.rs`.
pub(crate) const PROGRAMA: &str = "livro";
const CODIGO: u32 = 85;

/// O endpoint, e o assunto que o programa declara.
const ENDPOINT: &str = "icp-api.io";
const ASSUNTO: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai/icrc1_symbol";

/// As linhas da política padrão que ganham os destinos da rede principal:
/// o teto — o `sistema` e o `administrador` — e o `net.block` do tecido.
const LINHAS_DO_TETO: [&str; 5] = [
    "recurso sistema net.connect ",
    "recurso sistema net.block ",
    "recurso administrador net.connect ",
    "recurso administrador net.block ",
    "recurso seguranca net.block ",
];

/// A linha do operador, que o `policy.write` troca.
const LINHA_DO_OPERADOR: &str = "recurso operador net.connect ";

/// Quanto o programa tem para uma rodada: o DNS, o TLS e a verificação no
/// emulador sem aceleração, com folga para a rede.
const TETO_DA_RODADA: Duration = Duration::from_secs(180);

/// O gestor de canisters — `programas/src/bin/gestor.rs` —, com a chave do
/// operador, criada por ele pelo gate na máquina zerada: o pedido do saldo
/// no armazém, e o código com que ele sai quando o pedido foi feito. Só
/// leitura: duas consultas assinadas, ao ledger de ICP e ao de cycles, de
/// uma chave nova, sem fundos — nada que mude estado, nem que mova valor.
pub(crate) const GESTOR: &str = "gestor";
const GESTOR_FEITO: u32 = 90;
const CHAVE_DO_GESTOR: &str = "chave:bancada";
const PEDIDO_DO_GESTOR: &str = "/armazem/compartilhado/gestor/pedido";
const RESPOSTA_DO_GESTOR: &str = "/armazem/compartilhado/gestor/resposta";
/// O pedido, como valor de uma cadeia JSON: as quebras de linha escapadas.
const PEDIDO_DO_SALDO: &str = "acao saldo\\nrede mainnet\\nchave chave:bancada\\n";
const ASSUNTOS_DO_SALDO: [&str; 2] = [
    "ryjl3-tyaaa-aaaaa-aaaba-cai/icrc1_balance_of",
    "um5iw-rqaaa-aaaaq-qaaba-cai/icrc1_balance_of",
];

/// `cargo xtask mainnet` — ver o cabeçalho do módulo.
pub(crate) fn mainnet(
    arch: Arquitetura,
    release: bool,
    enderecos: Option<&str>,
    ensaio: bool,
) -> Result<ExitCode, String> {
    let quando = data_de(super::servidor_de_hora::agora_ms().div_euclid(1000));
    println!(
        "[xtask] mainnet: a rede principal do IC, de verdade ({}{}), {quando} UTC",
        arch.nome(),
        if ensaio { ", ENSAIO" } else { "" }
    );
    let mut relatorio = Relatorio::novo(&quando, arch, release, ensaio);

    // A máquina compilada antes do pré-voo — ver o cabeçalho, *A janela do
    // DNS*.
    let preparo = preparar(arch, release)?;

    // 1. O pré-voo.
    let (ips, origem) = match enderecos {
        Some(lista) => (ler_enderecos(lista)?, String::from("os de --enderecos")),
        None => resolver_no_hospedeiro()?,
    };
    relatorio.ips = ips.clone();
    relatorio.origem = origem;
    println!(
        "[xtask] mainnet: {ENDPOINT} -> {} ({})",
        texto_dos(&ips),
        relatorio.origem
    );
    if !ensaio {
        let mut lacuna = None;
        for ip in &ips {
            let com = texto_dos(&[*ip]);
            match aperto_real(ip) {
                Ok(aperto) => {
                    println!(
                        "[xtask] mainnet: o aperto real com {com}: {}",
                        aperto.negociado
                    );
                    let conferida = conferir_a_cadeia(&aperto.cadeia);
                    relatorio.apertos.push((
                        *ip,
                        aperto.negociado,
                        aperto.cadeia.iter().map(Elo::resumo).collect(),
                    ));
                    if let Err(e) = conferida {
                        lacuna = Some(format!("{e} (com {com})"));
                        break;
                    }
                }
                Err(e) => {
                    lacuna = Some(format!("{e} (com {com})"));
                    break;
                }
            }
        }
        if let Some(lacuna) = lacuna {
            relatorio.veredito = format!("o pre-voo parou: {lacuna}");
            let caminho = relatorio.gravar()?;
            println!("[xtask] mainnet: {lacuna}");
            println!("[xtask] mainnet: relatorio em {}", caminho.display());
            return Ok(ExitCode::FAILURE);
        }
        println!(
            "[xtask] mainnet: o aperto real de cada IPv4 fecha no perfil do programa, e cada cadeia sobe a uma ancora da imagem"
        );
    }

    // 2. A imagem, e a máquina.
    let (disco, artefato) = imagem_com_os_destinos(arch, preparo, &ips)?;
    // Um disco novo sobre o TPM de outro comando seria um journal que a
    // âncora não conhece, e nenhuma credencial valeria.
    zerar_o_estado(arch)?;
    let ambiente = Ambiente::ligar(arch, None)?.com_disco(disco);
    let mut m = Ligada::subir_com(arch, &artefato, ambiente)?;
    let r = (|| -> Result<ExitCode, String> {
        let mut operador = AgenteNaPorta::conectar(arch, 2)?;

        // 3. O gate antes do transporte — da consulta anônima, e da
        // assinada do gestor, com a chave que o operador cria agora.
        let antes = rodar(&mut m, &mut operador, arch)?;
        relatorio
            .rodadas
            .push(("sem os destinos na linha do operador", antes.clone()));
        let negada = antes.desfecho().ends_with("denied DENY_RESOURCE");
        if !negada && !ensaio {
            return Err(format!(
                "mainnet: sem o destino no alcance do operador, o programa nao foi recusado pelo gate\n  {}",
                antes.linhas.join("\n  ")
            ));
        }
        relatorio.impressao = preparar_o_gestor(&mut operador)?;
        let inicio = auditoria(&mut m, 0)?.1;
        let gestor_antes = rodar_o_gestor(&mut m, &mut operador, arch)?;
        let (registros, _) = auditoria(&mut m, inicio)?;
        let assinou_antes = assinaturas_do_processo(&registros, gestor_antes.rodada.processo);
        relatorio
            .gestor
            .push(("sem os destinos na linha do operador", gestor_antes.clone()));
        let gestor_negado = gestor_antes.rodada.codigo != GESTOR_FEITO && assinou_antes == 0;

        // 4. A política: o administrador dá os destinos ao operador.
        let original = linha_do_operador()?;
        let com = format!("{original}{}", destinos(&ips));
        let r = administrar(&mut m, "policy.write", &linha_em_json(&com))?;
        if !r.contains(r#""executed":true"#) {
            return Err(format!("mainnet: o policy.write nao executou\n  {r}"));
        }

        // 5. A consulta, e 6. a auditoria.
        let inicio = auditoria(&mut m, 0)?.1;
        let consulta = rodar(&mut m, &mut operador, arch)?;
        relatorio
            .rodadas
            .push(("com os destinos, pelo policy.write", consulta.clone()));
        let (registros, _) = auditoria(&mut m, inicio)?;
        relatorio.auditoria = auditoria_da_consulta(&registros, &consulta, &ips);

        // 5b. O saldo do gestor, pelas consultas assinadas.
        let inicio = auditoria(&mut m, 0)?.1;
        let saldo = rodar_o_gestor(&mut m, &mut operador, arch)?;
        let (registros, _) = auditoria(&mut m, inicio)?;
        relatorio.auditoria_do_gestor = auditoria_do_gestor(&registros, &saldo, &ips);
        relatorio
            .gestor
            .push(("com os destinos, pelo policy.write", saldo.clone()));

        // 7. A revogação.
        let r = administrar(&mut m, "policy.write", &linha_em_json(&original))?;
        if !r.contains(r#""executed":true"#) {
            return Err(format!(
                "mainnet: o policy.write de volta nao executou\n  {r}"
            ));
        }
        let depois = rodar(&mut m, &mut operador, arch)?;
        relatorio
            .rodadas
            .push(("revogados os destinos", depois.clone()));
        let inicio = auditoria(&mut m, 0)?.1;
        let gestor_depois = rodar_o_gestor(&mut m, &mut operador, arch)?;
        let (registros, _) = auditoria(&mut m, inicio)?;
        let assinou_depois = assinaturas_do_processo(&registros, gestor_depois.rodada.processo);
        relatorio
            .gestor
            .push(("revogados os destinos", gestor_depois.clone()));
        let gestor_revogado = gestor_depois.rodada.codigo != GESTOR_FEITO && assinou_depois == 0;

        // O veredito.
        let verificou = consulta.codigo == CODIGO;
        let revogou = depois.desfecho().ends_with("denied DENY_RESOURCE");
        let o_gestor = saldo.rodada.codigo == GESTOR_FEITO
            && saldo.resposta.contains("\ndesfecho verified\n")
            && relatorio.auditoria_do_gestor.ok
            && gestor_negado
            && gestor_revogado;
        relatorio.veredito = match (ensaio, verificou && negada && revogou && o_gestor) {
            (false, true) => String::from(
                "a fumaca real fechou: o simbolo verificado e ICP; os dois saldos da chave nova, pelas consultas assinadas do gestor, verificados; o gate recusou os dois antes da politica e depois da revogacao",
            ),
            (false, false) => format!(
                "a fumaca real NAO fechou: antes {}, a consulta {}, depois {}; o gestor saiu com {} ({}) — antes {}, depois {}",
                antes.desfecho(),
                consulta.desfecho(),
                depois.desfecho(),
                saldo.rodada.codigo,
                saldo.desfecho(),
                gestor_antes.rodada.codigo,
                gestor_depois.rodada.codigo
            ),
            (true, _) => format!(
                "ENSAIO, nao e a fumaca real: a maquina, a politica e os programas responderam; antes {}, a consulta {}, depois {}; o gestor saiu com {} ({})",
                antes.desfecho(),
                consulta.desfecho(),
                depois.desfecho(),
                saldo.rodada.codigo,
                saldo.desfecho()
            ),
        };
        let ok = ensaio || (verificou && negada && revogou && relatorio.auditoria.ok && o_gestor);
        Ok(if ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        })
    })();
    let _ = m.cortar_a_energia();
    if let Err(e) = &r {
        relatorio.veredito = format!("a fumaca parou: {e}");
    }
    let caminho = relatorio.gravar()?;
    println!("[xtask] mainnet: {}", relatorio.veredito);
    println!("[xtask] mainnet: relatorio em {}", caminho.display());
    // O estado fica zerado para quem vier depois, como todo comando o deixa.
    zerar_o_estado(arch)?;
    r
}

// ---------------------------------------------------------------------------
// O pré-voo
// ---------------------------------------------------------------------------

/// Os IPv4 de `--enderecos`: separados por vírgula.
fn ler_enderecos(lista: &str) -> Result<Vec<[u8; 4]>, String> {
    let mut ips = Vec::new();
    for parte in lista.split(',') {
        let ip: std::net::Ipv4Addr = parte
            .trim()
            .parse()
            .map_err(|_| format!("--enderecos: `{parte}` nao e um IPv4"))?;
        ips.push(ip.octets());
    }
    ips.sort_unstable();
    ips.dedup();
    if ips.is_empty() {
        return Err("--enderecos: nenhum IPv4".into());
    }
    Ok(ips)
}

/// Os IPv4 de [`ENDPOINT`] pelos dois caminhos do hospedeiro — o
/// resolvedor do sistema e [`perguntar_como_a_maquina`] —, juntos, e de
/// onde cada um veio, para o relatório. Ver o cabeçalho, *A janela do DNS*.
fn resolver_no_hospedeiro() -> Result<(Vec<[u8; 4]>, String), String> {
    let do_sistema: Result<Vec<[u8; 4]>, String> = (ENDPOINT, 443)
        .to_socket_addrs()
        .map(|enderecos| {
            enderecos
                .filter_map(|a| match a.ip() {
                    IpAddr::V4(v4) => Some(v4.octets()),
                    IpAddr::V6(_) => None,
                })
                .collect()
        })
        .map_err(|e| e.to_string());
    let servidor = std::fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|texto| servidor_do_emulador(&texto));
    let da_maquina = match servidor {
        Some(s) => perguntar_como_a_maquina(SocketAddrV4::new(s, 53)),
        None => Err("sem nameserver IPv4 no /etc/resolv.conf".into()),
    };
    let dito = |r: &Result<Vec<[u8; 4]>, String>| match r {
        Ok(ips) if ips.is_empty() => String::from("nenhum IPv4"),
        Ok(ips) => texto_dos(ips),
        Err(e) => e.clone(),
    };
    let origem = format!(
        "o resolvedor do sistema deu {}; a pergunta da maquina, a {}, deu {}",
        dito(&do_sistema),
        servidor.map_or_else(|| String::from("nenhum servidor"), |s| s.to_string()),
        dito(&da_maquina)
    );
    let mut ips: Vec<[u8; 4]> = do_sistema
        .iter()
        .chain(da_maquina.iter())
        .flatten()
        .copied()
        .collect();
    ips.sort_unstable();
    ips.dedup();
    if ips.is_empty() {
        return Err(format!(
            "mainnet: o hospedeiro nao resolve {ENDPOINT} em IPv4, e o Duke so conecta IPv4 ({origem}) — a fumaca real precisa de DNS e da rede de verdade"
        ));
    }
    Ok((ips, origem))
}

/// O servidor a que o DNS do emulador (`10.0.2.3`) repassa a pergunta da
/// máquina: o primeiro `nameserver` IPv4 do `/etc/resolv.conf` do
/// hospedeiro, lido como a `libslirp` do QEMU o lê no Linux — a palavra no
/// começo da linha, um espaço ou tab, e o primeiro endereço que é IPv4.
fn servidor_do_emulador(resolv_conf: &str) -> Option<Ipv4Addr> {
    resolv_conf.lines().find_map(|linha| {
        let resto = linha.strip_prefix("nameserver")?;
        if !resto.starts_with([' ', '\t']) {
            return None;
        }
        resto.split_whitespace().next()?.parse().ok()
    })
}

/// A pergunta que o `livro` faz pelo nome — os mesmos bytes, de
/// `protocolo::dns`: o tipo `A`, a recursão pedida, sem EDNS —, feita do
/// hospedeiro ao `servidor` do emulador. A resposta é lida como o programa
/// a lê: só os endereços do nome perguntado e dos apelidos dele.
fn perguntar_como_a_maquina(servidor: SocketAddrV4) -> Result<Vec<[u8; 4]>, String> {
    use protocolo::dns;
    let nome = dns::Nome::de_texto(ENDPOINT).map_err(|e| e.motivo().to_string())?;
    let id = (super::servidor_de_hora::agora_ms() & 0xffff) as u16;
    let mut b = [0u8; dns::MAIOR_MENSAGEM];
    let n = dns::pergunta(id, &nome, &mut b).map_err(|e| e.motivo().to_string())?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    socket
        .send_to(&b[..n], servidor)
        .map_err(|e| e.to_string())?;
    let mut r = [0u8; dns::MAIOR_MENSAGEM];
    let (tamanho, de) = socket
        .recv_from(&mut r)
        .map_err(|e| format!("sem resposta ({e})"))?;
    if de != SocketAddr::V4(servidor) {
        return Err(format!("a resposta veio de {de}"));
    }
    let m = dns::ler(&r[..tamanho]).map_err(|e| e.motivo().to_string())?;
    if m.id != id || !m.resposta || m.nome() != Some(&nome) {
        return Err("a resposta nao e desta pergunta".into());
    }
    if m.codigo != dns::SEM_ERRO {
        return Err(format!("o codigo {}", m.codigo));
    }
    Ok(m.enderecos().to_vec())
}

fn texto_dos(ips: &[[u8; 4]]) -> String {
    ips.iter()
        .map(|[a, b, c, d]| format!("{a}.{b}.{c}.{d}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Um certificado da cadeia real, como o `openssl` o lê: o que o perfil
/// confere.
#[derive(Clone, Debug)]
struct Elo {
    sujeito: String,
    emissor: String,
    validade: String,
    /// `rsaEncryption` ou `id-ecPublicKey`, ou `ED25519`.
    chave: String,
    /// O tamanho da chave RSA, em bits.
    bits: Option<u32>,
    /// A curva da chave ECDSA: `P-256`, `P-384`.
    curva: Option<String>,
    /// O algoritmo da assinatura do emissor sobre este certificado.
    assinatura: String,
}

impl Elo {
    fn resumo(&self) -> String {
        format!(
            "{} | emissor {} | chave {}{}{} | assinado com {} | {}",
            self.sujeito,
            self.emissor,
            self.chave,
            self.bits.map(|b| format!(" {b} bits")).unwrap_or_default(),
            self.curva
                .as_deref()
                .map(|c| format!(" {c}"))
                .unwrap_or_default(),
            self.assinatura,
            self.validade
        )
    }

    /// A curva ou o tamanho da chave, para dizer o perfil.
    fn chave_no_perfil(&self) -> Result<(), String> {
        match (self.chave.as_str(), self.bits, self.curva.as_deref()) {
            ("rsaEncryption", Some(b), _) if (2048..=4096).contains(&b) && b % 8 == 0 => Ok(()),
            ("id-ecPublicKey", _, Some("P-256" | "P-384")) => Ok(()),
            ("ED25519", _, _) => Ok(()),
            _ => Err(format!(
                "a chave de `{}` ({} {:?} {:?}) esta fora do perfil: RSA de 2048 a 4096 bits, P-256, P-384 ou Ed25519",
                self.sujeito, self.chave, self.bits, self.curva
            )),
        }
    }
}

/// O perfil do aperto do programa, dito ao `openssl s_client` — o de
/// `tls/src/provedor.rs`: só o TLS 1.3, as três suítes, as duas trocas e as
/// assinaturas do aperto.
const PERFIL_DO_APERTO: [&str; 7] = [
    "-tls1_3",
    "-ciphersuites",
    "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
    "-groups",
    "X25519:P-256",
    "-sigalgs",
    "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ed25519:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512",
];

/// O que o `openssl s_client` oferece para dizer o que o servidor fecha
/// fora do perfil: as suítes do TLS 1.3 que ele conhece, e o resto como
/// ele faz sem opção nenhuma — o TLS 1.2 junto.
const FORA_DO_PERFIL: [&str; 2] = [
    "-ciphersuites",
    "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256",
];

/// O aperto real, lido no hospedeiro.
struct Aperto {
    /// A cadeia que o servidor mandou, da folha para cima.
    cadeia: Vec<Elo>,
    /// O que se negociou: a suíte, a troca e a assinatura do servidor.
    negociado: String,
}

/// O aperto que `ip` fecha para [`ENDPOINT`] dentro do [`PERFIL_DO_APERTO`],
/// pelo `openssl s_client`, sem confiar em nada dele: a cadeia só lida,
/// certificado a certificado. Um servidor que não fecha dentro do perfil é
/// `TLS_PROFILE_GAP`, com o que ele fecha fora.
fn aperto_real(ip: &[u8; 4]) -> Result<Aperto, String> {
    let [a, b, c, d] = ip;
    let no_perfil = s_client(ip, &PERFIL_DO_APERTO)?;
    let blocos = pem::parse_many(no_perfil.as_bytes())
        .map_err(|e| format!("mainnet: a cadeia de {ENDPOINT} nao se le: {e}"))?;
    if blocos.is_empty() {
        let livre = s_client(ip, &FORA_DO_PERFIL)?;
        if !livre.contains("-----BEGIN CERTIFICATE-----") {
            return Err(format!(
                "mainnet: {ENDPOINT} ({a}.{b}.{c}.{d}) nao fechou aperto nenhum — a rede de verdade chega la?"
            ));
        }
        return Err(format!(
            "TLS_PROFILE_GAP: {ENDPOINT} nao fecha o aperto no perfil do programa (TLS 1.3; {}; {}; {}); fora dele, fecha com {}",
            PERFIL_DO_APERTO[2],
            PERFIL_DO_APERTO[4],
            PERFIL_DO_APERTO[6],
            negociado(&livre)
        ));
    }
    Ok(Aperto {
        cadeia: blocos
            .iter()
            .map(|b| elo(&pem::encode(b)))
            .collect::<Result<_, _>>()?,
        negociado: negociado(&no_perfil),
    })
}

/// O `openssl s_client` com `ip`, o nome de [`ENDPOINT`] e as opções de
/// `perfil`: o que ele escreveu.
fn s_client(ip: &[u8; 4], perfil: &[&str]) -> Result<String, String> {
    let [a, b, c, d] = ip;
    let saida = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("{a}.{b}.{c}.{d}:443"),
            "-servername",
            ENDPOINT,
            "-showcerts",
        ])
        .args(perfil)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("mainnet: o openssl nao rodou: {e}"))?;
    Ok(String::from_utf8_lossy(&saida.stdout).into_owned())
}

/// O que o `openssl s_client` diz que negociou: a versão e a suíte, a
/// troca e a assinatura do servidor.
fn negociado(saida: &str) -> String {
    const MARCAS: [&str; 5] = [
        "New, ",
        "Server Temp Key: ",
        "Negotiated TLS1.3 group: ",
        "Peer signature type: ",
        "Peer signing digest: ",
    ];
    saida
        .lines()
        .map(str::trim)
        .filter(|l| MARCAS.iter().any(|m| l.starts_with(m)))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Um certificado, pelo `openssl x509 -text`.
fn elo(pem: &str) -> Result<Elo, String> {
    use std::io::Write as _;
    let mut filho = Command::new("openssl")
        .args([
            "x509",
            "-noout",
            "-text",
            "-nameopt",
            "oneline",
            "-certopt",
            "no_header,no_version,no_serial,no_extensions,no_sigdump",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("mainnet: o openssl nao rodou: {e}"))?;
    filho
        .stdin
        .take()
        .ok_or("mainnet: sem a entrada do openssl")?
        .write_all(pem.as_bytes())
        .map_err(|e| format!("mainnet: o openssl nao leu o certificado: {e}"))?;
    let saida = filho
        .wait_with_output()
        .map_err(|e| format!("mainnet: o openssl nao respondeu: {e}"))?;
    let texto = String::from_utf8_lossy(&saida.stdout).to_string();
    let depois = |marca: &str| {
        texto
            .lines()
            .find_map(|l| l.trim().strip_prefix(marca).map(|v| v.trim().to_string()))
            .unwrap_or_default()
    };
    let bits = texto.lines().find_map(|l| {
        let l = l.trim();
        let dentro = l.strip_prefix("Public-Key: (")?;
        dentro.split(' ').next()?.parse().ok()
    });
    let curva = texto.lines().find_map(|l| {
        l.trim()
            .strip_prefix("NIST CURVE: ")
            .map(|c| c.trim().to_string())
    });
    Ok(Elo {
        sujeito: depois("Subject:"),
        emissor: depois("Issuer:"),
        validade: format!("de {} a {}", depois("Not Before:"), depois("Not After :")),
        chave: depois("Public Key Algorithm:"),
        bits: if depois("Public Key Algorithm:") == "rsaEncryption" {
            bits
        } else {
            None
        },
        curva,
        assinatura: depois("Signature Algorithm:"),
    })
}

/// A cadeia real contra o perfil do TLS do programa e as âncoras da imagem
/// — o mesmo perfil de `tls/src/assinatura.rs`, dito de novo aqui só para
/// dizer **por que** uma cadeia não passaria: quem decide é o programa.
fn conferir_a_cadeia(cadeia: &[Elo]) -> Result<(), String> {
    let ancoras = ancoras_da_imagem()?;
    for (i, e) in cadeia.iter().enumerate() {
        e.chave_no_perfil()
            .map_err(|m| format!("TLS_PROFILE_GAP: {m}"))?;
        // O emissor: o próximo da cadeia, ou uma âncora.
        let emissor = cadeia
            .get(i + 1)
            .filter(|p| p.sujeito == e.emissor)
            .or_else(|| ancoras.iter().find(|a| a.sujeito == e.emissor));
        let Some(emissor) = emissor else {
            if i + 1 == cadeia.len() {
                return Err(format!(
                    "TLS_ANCHOR_GAP: a cadeia real sobe a `{}`, e as ancoras da imagem sao {}",
                    e.emissor,
                    ancoras
                        .iter()
                        .map(|a| format!("`{}`", a.sujeito))
                        .collect::<Vec<_>>()
                        .join(" e ")
                ));
            }
            return Err(format!(
                "TLS_PROFILE_GAP: `{}` nao e emitido pelo seguinte da cadeia, `{}`",
                e.sujeito,
                cadeia[i + 1].sujeito
            ));
        };
        let par = (
            emissor.chave.as_str(),
            emissor.curva.as_deref(),
            e.assinatura.as_str(),
        );
        let no_perfil = matches!(
            par,
            ("id-ecPublicKey", Some("P-256"), "ecdsa-with-SHA256")
                | ("id-ecPublicKey", Some("P-384"), "ecdsa-with-SHA384")
                | ("ED25519", _, "ED25519")
                | (
                    "rsaEncryption",
                    _,
                    "sha256WithRSAEncryption"
                        | "sha384WithRSAEncryption"
                        | "sha512WithRSAEncryption"
                )
        );
        if !no_perfil {
            return Err(format!(
                "TLS_PROFILE_GAP: `{}` e assinado com {} por uma chave {} {:?}; o perfil confere ECDSA P-256 com SHA-256, P-384 com SHA-384, Ed25519 e RSA PKCS#1 v1.5 com SHA-2",
                e.sujeito, e.assinatura, emissor.chave, emissor.curva
            ));
        }
        if ancoras.iter().any(|a| a.sujeito == emissor.sujeito) {
            return Ok(());
        }
    }
    Err("TLS_ANCHOR_GAP: a cadeia real acabou sem chegar a uma ancora da imagem".into())
}

/// As âncoras públicas da imagem, lidas como os elos.
fn ancoras_da_imagem() -> Result<Vec<Elo>, String> {
    let pem = super::tls::publicas()?;
    pem::parse_many(&pem)
        .map_err(|e| format!("as ancoras publicas nao se leem: {e}"))?
        .iter()
        .map(|b| elo(&pem::encode(b)))
        .collect()
}

// ---------------------------------------------------------------------------
// A imagem
// ---------------------------------------------------------------------------

/// `tcp:<ipv4>:443` de cada IPv4, cada um com um espaço na frente.
fn destinos(ips: &[[u8; 4]]) -> String {
    ips.iter()
        .map(|[a, b, c, d]| format!(" tcp:{a}.{b}.{c}.{d}:443"))
        .collect()
}

/// A política padrão com os destinos da rede principal no teto — ver o
/// cabeçalho —, conferida como a imagem confere a dela.
fn politica_com_os_destinos(ips: &[[u8; 4]]) -> Result<String, String> {
    let mais = destinos(ips);
    let mut texto = String::new();
    let mut trocadas = 0;
    for linha in politica::PADRAO.lines() {
        texto.push_str(linha);
        if LINHAS_DO_TETO.iter().any(|l| linha.starts_with(l)) {
            texto.push_str(&mais);
            trocadas += 1;
        }
        texto.push('\n');
    }
    if trocadas != LINHAS_DO_TETO.len() {
        return Err(format!(
            "a politica padrao mudou: {trocadas} das {} linhas do teto",
            LINHAS_DO_TETO.len()
        ));
    }
    let p = politica::Politica::ler(&texto)
        .map_err(|e| format!("a politica com a rede principal nao se le: {}", e.motivo()))?;
    p.conferir_alcance_aos_administradores(&["administrador"])
        .map_err(|m| {
            format!("a politica com a rede principal viola o alcance ao administrador: {m}")
        })?;
    p.conferir_tetos(&["administrador"])
        .map_err(|m| format!("a politica com a rede principal exerce um teto: {m}"))?;
    super::conferir_o_tempo_da_politica(&p)?;
    Ok(texto)
}

/// A linha do operador na política padrão.
fn linha_do_operador() -> Result<String, String> {
    politica::PADRAO
        .lines()
        .find(|l| l.starts_with(LINHA_DO_OPERADOR))
        .map(String::from)
        .ok_or_else(|| "a politica padrao nao tem a linha do operador".into())
}

/// Os parâmetros de um `policy.write` da `linha`.
fn linha_em_json(linha: &str) -> String {
    format!(r#"{{"line":"{linha}"}}"#)
}

/// A máquina antes dos endereços: o kernel, os programas e o iniciador
/// compilados, e os arquivos da imagem de sempre — os programas, as chaves,
/// as redes do IC, as âncoras. Só a política espera o pré-voo.
struct Preparo {
    base: Artefato,
    arquivos: Vec<(String, Vec<u8>)>,
    /// O iniciador UEFI e o kernel para a ESP, quando a máquina sobe pelo
    /// disco.
    esp: Option<(std::path::PathBuf, std::path::PathBuf)>,
}

fn preparar(arch: Arquitetura, release: bool) -> Result<Preparo, String> {
    let base = super::build(arch, release, false)?;
    let mut arquivos = super::programas_do_disco()?;
    arquivos.extend(super::chaves::Chaves::garantir()?.arquivos()?);
    arquivos.push((
        super::tls::ANCORA_NA_IMAGEM.to_string(),
        super::tls::ancora()?,
    ));
    arquivos.push((
        super::icp::REDES_NA_IMAGEM.to_string(),
        super::icp::redes().into_bytes(),
    ));
    arquivos.push((
        super::tls::PUBLICAS_NA_IMAGEM.to_string(),
        super::tls::publicas()?,
    ));
    let esp = match &base {
        Artefato::Binario(_) => None,
        Artefato::Disco(_) => {
            let perfil = if release { "release" } else { "debug" };
            let elf = super::raiz_do_projeto()
                .join("kernel")
                .join("target")
                .join(arch.alvo())
                .join(perfil)
                .join(super::NOME_DO_BINARIO);
            let efi = super::build_do_iniciador(arch, release)?;
            Some((efi, super::kernel_para_a_esp(&elf)?))
        }
    };
    Ok(Preparo {
        base,
        arquivos,
        esp,
    })
}

/// A imagem de produção com a política de [`politica_com_os_destinos`] no
/// lugar da padrão — o resto é o do [`Preparo`]. Mora em `target/mainnet/`.
fn imagem_com_os_destinos(
    arch: Arquitetura,
    preparo: Preparo,
    ips: &[[u8; 4]],
) -> Result<(std::path::PathBuf, Artefato), String> {
    let dir = super::raiz_do_projeto().join("target").join("mainnet");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let caminho = dir.join("disco.img");
    let mut arquivos = preparo.arquivos;
    let Some((_, padrao)) = arquivos
        .iter_mut()
        .find(|(nome, _)| nome == "etc/duke/politica")
    else {
        return Err("a imagem nao tem etc/duke/politica".into());
    };
    *padrao = politica_com_os_destinos(ips)?.into_bytes();
    super::montar_disco(&caminho, &arquivos)?;
    let artefato = match preparo.esp {
        None => preparo.base,
        Some((efi, kernel)) => {
            super::instalar_iniciador(arch, &caminho, &efi, &kernel)?;
            Artefato::Disco(caminho.clone())
        }
    };
    Ok((caminho, artefato))
}

// ---------------------------------------------------------------------------
// A máquina
// ---------------------------------------------------------------------------

/// Uma rodada do programa: o que ele disse, o código com que saiu, e o
/// número do processo.
#[derive(Clone, Debug, Default)]
struct Rodada {
    programa: &'static str,
    processo: u64,
    codigo: u32,
    linhas: Vec<String>,
    duracao_ms: u128,
}

impl Rodada {
    /// A linha que começa com `<programa>: <trecho>`, sem o começo.
    fn linha(&self, trecho: &str) -> Option<&str> {
        self.linhas
            .iter()
            .find_map(|l| l.strip_prefix(&format!("{}: {trecho}", self.programa)))
    }

    /// O desfecho da consulta, como o programa o disse.
    fn desfecho(&self) -> String {
        self.linha("icrc1_symbol: ")
            .map(String::from)
            .unwrap_or_else(|| format!("sem desfecho (codigo {})", self.codigo))
    }
}

/// Lança o [`PROGRAMA`] pelo agente `operador`, e lê do log, desde o
/// lançamento, o que ele disse e o código com que saiu.
fn rodar(
    m: &mut Ligada,
    operador: &mut AgenteNaPorta,
    arch: Arquitetura,
) -> Result<Rodada, String> {
    rodar_programa(m, operador, arch, PROGRAMA)
}

/// [`rodar`], com o `programa` dado.
fn rodar_programa(
    m: &mut Ligada,
    operador: &mut AgenteNaPorta,
    arch: Arquitetura,
    programa: &'static str,
) -> Result<Rodada, String> {
    let desde = ultimo_do_log(m)?;
    let comeco = Instant::now();
    let lancado = operador.pedir(
        "user.run",
        &format!(r#"{{"path":"/programas/{}/{programa}"}}"#, arch.nome()),
    )?;
    let processo = super::numero_no_caminho(&lancado, &["thread_id"])
        .filter(|_| lancado.contains(r#""launched":true"#))
        .ok_or_else(|| format!("mainnet: o operador nao lancou o {programa}\n  {lancado}"))?;
    let mut rodada = Rodada {
        programa,
        processo,
        ..Rodada::default()
    };
    let mut visto = desde;
    loop {
        let r = m.pedir("log.tail", r#"{"count":64}"#)?;
        let registros = super::objetos_planos(
            super::apos(&r, r#""records":["#).ok_or("log.tail sem registros")?,
        )?;
        for registro in &registros {
            let seq: u64 = campo(registro, "seq").parse().unwrap_or(0);
            if seq <= visto {
                continue;
            }
            visto = seq;
            let mensagem = campo(registro, "message");
            if mensagem.starts_with(&format!("{programa}: ")) {
                rodada.linhas.push(mensagem);
            } else if let Some(c) = mensagem.strip_prefix("processo encerrou com codigo ") {
                rodada.codigo = c.trim().parse().unwrap_or(0);
                rodada.duracao_ms = comeco.elapsed().as_millis();
                for l in &rodada.linhas {
                    println!("  {l}");
                }
                println!("  saiu com {} em {} ms", rodada.codigo, rodada.duracao_ms);
                return Ok(rodada);
            }
        }
        if comeco.elapsed() > TETO_DA_RODADA {
            return Err(format!(
                "mainnet: o programa nao terminou em {} s\n  {}",
                TETO_DA_RODADA.as_secs(),
                rodada.linhas.join("\n  ")
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// O que a auditoria tem da consulta verificada.
#[derive(Clone, Debug, Default)]
struct Auditoria {
    ok: bool,
    linhas: Vec<String>,
}

/// As decisões do processo da `consulta`: todas `ALLOW`, só do que a
/// consulta pede — o DNS e um dos IPv4 —, e a declaração ancorada na
/// conexão, com o destino real que o kernel viu. Nada do IC fora dela.
fn auditoria_da_consulta(
    registros: &[ObjetoPlano],
    consulta: &Rodada,
    ips: &[[u8; 4]],
) -> Auditoria {
    let do_processo = format!("pelo processo {} (", consulta.processo);
    let deles: Vec<&ObjetoPlano> = registros
        .iter()
        .filter(|r| campo(r, "detail").starts_with(&do_processo))
        .collect();
    let mut a = Auditoria::default();
    let mut contas: std::collections::BTreeMap<(String, String), (usize, usize)> =
        std::collections::BTreeMap::new();
    for r in &deles {
        let chave = (campo(r, "method"), campo(r, "resource"));
        let e = contas.entry(chave).or_default();
        if campo(r, "code") == "ALLOW" {
            e.0 += 1;
        } else {
            e.1 += 1;
        }
    }
    for ((metodo, recurso), (deixadas, recusadas)) in &contas {
        a.linhas.push(format!(
            "{metodo} {}: {deixadas} deixadas, {recusadas} recusadas",
            if recurso.is_empty() { "-" } else { recurso }
        ));
    }
    let recusadas = contas.values().map(|(_, r)| r).sum::<usize>();
    let conectados: Vec<String> = contas
        .keys()
        .filter(|(m, _)| m == "net.connect")
        .map(|(_, r)| r.clone())
        .collect();
    let dos_ips: Vec<String> = ips
        .iter()
        .map(|[a, b, c, d]| format!("tcp:{a}.{b}.{c}.{d}:443"))
        .collect();
    let so_o_que_pede = conectados
        .iter()
        .all(|d| d == "udp:10.0.2.3:53" || dos_ips.contains(d));
    let declaracao = deles.iter().find(|r| {
        campo(r, "method") == "audit.declare"
            && campo(r, "resource") == format!("icp.query {ASSUNTO} verified")
    });
    let ancorada = declaracao.is_some_and(|r| {
        let d = campo(r, "detail");
        dos_ips
            .iter()
            .any(|ip| d.contains(&format!(" {ip}; decisao ")))
    });
    let do_ic = ["ryjl3", "icrc1", "icp-api.io"];
    let fora = deles
        .iter()
        .filter(|r| !(campo(r, "method") == "audit.declare" && !campo(r, "resource").is_empty()))
        .filter(|r| do_ic.iter().any(|t| format!("{r:?}").contains(t)))
        .count();
    if let Some(r) = declaracao {
        a.linhas.push(format!(
            "a declaracao: {} | {}",
            campo(r, "resource"),
            campo(r, "detail")
        ));
    }
    a.linhas.push(format!(
        "{} registros do processo; recusadas {recusadas}; so o DNS e os IPv4 {so_o_que_pede}; declaracao ancorada no destino real {ancorada}; registros com o IC fora da alegacao {fora}",
        deles.len()
    ));
    a.ok = consulta.codigo == CODIGO && recusadas == 0 && so_o_que_pede && ancorada && fora == 0;
    a
}

// ---------------------------------------------------------------------------
// O gestor
// ---------------------------------------------------------------------------

/// O que o gestor fez numa rodada: o que ele disse e o código, e a resposta
/// que gravou no armazém.
#[derive(Clone, Debug, Default)]
struct DoGestor {
    rodada: Rodada,
    resposta: String,
}

impl DoGestor {
    /// O desfecho da resposta.
    fn desfecho(&self) -> String {
        self.resposta
            .lines()
            .find_map(|l| l.strip_prefix("desfecho "))
            .map(String::from)
            .unwrap_or_else(|| format!("sem resposta (codigo {})", self.rodada.codigo))
    }
}

/// A chave do gestor, criada pelo operador pelo gate — no domínio do pedido
/// do IC —, e o diretório do pedido no armazém. Devolve a impressão da
/// chave.
fn preparar_o_gestor(operador: &mut AgenteNaPorta) -> Result<String, String> {
    let r = operador.pedir(
        "key.create",
        &format!(r#"{{"key":"{CHAVE_DO_GESTOR}","domain":"ic-request"}}"#),
    )?;
    if !r.contains(r#""created":true"#) {
        return Err(format!("mainnet: o operador nao criou a chave\n  {r}"));
    }
    let impressao = super::campo_simples(&r, "fingerprint").unwrap_or_default();
    // Já existir não é erro: a gravação do pedido diz se falta.
    let _ = operador.pedir("fs.mkdir", r#"{"path":"/armazem/compartilhado/gestor"}"#)?;
    Ok(impressao)
}

/// Grava o pedido do saldo pelo operador — o dono do pedido é o que lança o
/// gestor — e lança o gestor por ele; lê do log o que ele disse e o código,
/// e do armazém a resposta.
fn rodar_o_gestor(
    m: &mut Ligada,
    operador: &mut AgenteNaPorta,
    arch: Arquitetura,
) -> Result<DoGestor, String> {
    let estado = operador.pedir("fs.stat", &format!(r#"{{"path":"{PEDIDO_DO_GESTOR}"}}"#))?;
    let versao = super::numero_no_caminho(&estado, &["version"]).unwrap_or(0);
    let r = operador.pedir(
        "fs.write",
        &format!(
            r#"{{"path":"{PEDIDO_DO_GESTOR}","content":"{PEDIDO_DO_SALDO}","expect_version":{versao}}}"#
        ),
    )?;
    if !r.contains(r#""ok":true"#) {
        return Err(format!(
            "mainnet: o pedido do gestor nao foi gravado\n  {r}"
        ));
    }
    let rodada = rodar_programa(m, operador, arch, GESTOR)?;
    let lida = operador.pedir(
        "fs.read",
        &format!(r#"{{"path":"{RESPOSTA_DO_GESTOR}","max":4096}}"#),
    )?;
    let resposta = super::apos(&lida, r#""content":""#)
        .and_then(|c| c.split('"').next())
        .map(|c| c.replace("\\n", "\n"))
        .unwrap_or_default();
    Ok(DoGestor { rodada, resposta })
}

/// Quantas assinaturas do processo `processo` a auditoria tem: as execuções
/// do `key.sign`.
fn assinaturas_do_processo(registros: &[ObjetoPlano], processo: u64) -> usize {
    let do_processo = format!("pelo processo {processo} (");
    registros
        .iter()
        .filter(|r| {
            campo(r, "method") == "key.sign"
                && campo(r, "code") == "ALLOW"
                && campo(r, "detail").starts_with(&do_processo)
                && campo(r, "detail").contains("): assinatura ed25519 ")
        })
        .count()
}

/// As decisões do processo do saldo: todas `ALLOW`; as conexões só com o DNS
/// e os IPv4; duas assinaturas, a decisão do gate sobre a chave do
/// operador; e as duas declarações `icp.query`, uma por ledger, cada uma
/// ancorada na decisão de uma assinatura. Nada do IC fora delas.
fn auditoria_do_gestor(registros: &[ObjetoPlano], saldo: &DoGestor, ips: &[[u8; 4]]) -> Auditoria {
    let do_processo = format!("pelo processo {} (", saldo.rodada.processo);
    let deles: Vec<&ObjetoPlano> = registros
        .iter()
        .filter(|r| campo(r, "detail").starts_with(&do_processo))
        .collect();
    let mut a = Auditoria::default();
    let recusadas = deles.iter().filter(|r| campo(r, "code") != "ALLOW").count();
    let dos_ips: Vec<String> = ips
        .iter()
        .map(|[a, b, c, d]| format!("tcp:{a}.{b}.{c}.{d}:443"))
        .collect();
    let so_o_que_pede = deles
        .iter()
        .filter(|r| campo(r, "method") == "net.connect")
        .all(|r| {
            let d = campo(r, "resource");
            d == "udp:10.0.2.3:53" || dos_ips.contains(&d)
        });
    let assinaturas = assinaturas_do_processo(registros, saldo.rodada.processo);
    let decisoes: Vec<String> = deles
        .iter()
        .filter(|r| campo(r, "method") == "key.sign" && campo(r, "code") == "ALLOW")
        .filter_map(|r| {
            campo(r, "detail")
                .rsplit_once("; decisao ")
                .map(|(_, d)| d.to_string())
        })
        .collect();
    let mut declaradas = 0;
    for assunto in ASSUNTOS_DO_SALDO {
        let declaracao = deles.iter().find(|r| {
            campo(r, "method") == "audit.declare"
                && campo(r, "resource") == format!("icp.query {assunto} verified")
        });
        if let Some(r) = declaracao {
            let d = campo(r, "detail");
            let ancorada = decisoes
                .iter()
                .any(|n| d.contains(&format!("): ancorada em {n} key.sign; decisao ")));
            if ancorada {
                declaradas += 1;
            }
            a.linhas
                .push(format!("a declaracao: {} | {}", campo(r, "resource"), d));
        }
    }
    let do_ic = ["ryjl3", "um5iw", "icrc1", "icp-api.io"];
    let fora = deles
        .iter()
        .filter(|r| !(campo(r, "method") == "audit.declare" && !campo(r, "resource").is_empty()))
        .filter(|r| do_ic.iter().any(|t| format!("{r:?}").contains(t)))
        .count();
    a.linhas.push(format!(
        "{} registros do processo; recusadas {recusadas}; so o DNS e os IPv4 {so_o_que_pede}; assinaturas {assinaturas}; declaracoes ancoradas numa assinatura {declaradas}; registros com o IC fora da alegacao {fora}",
        deles.len()
    ));
    a.ok = recusadas == 0 && so_o_que_pede && assinaturas == 2 && declaradas == 2 && fora == 0;
    a
}

// ---------------------------------------------------------------------------
// O relatório
// ---------------------------------------------------------------------------

/// O que o `livro` confere antes de dizer o símbolo, para quem lê o
/// relatório sem o código — ver `programas/src/icp.rs` e o `web3`.
const O_QUE_SE_CONFERE: [&str; 5] = [
    "o TLS 1.3 de `icp-api.io` pelas âncoras públicas da imagem (ISRG Root X1 e X2): a cadeia, a validade pela hora do programa e o nome — nada que o servidor mande vira âncora",
    "o certificado do `read_state` da sub-rede do canister: a assinatura BLS pela chave da raiz de `/dados/icp/redes` — nunca a que a rede anuncia —, sem delegação ou com uma só, e o tempo dele a no máximo cinco minutos da hora do programa",
    "o canister nas faixas da sub-rede que o certificado prova — o livro-razão é da sub-rede raiz, e as faixas vêm em `/subnet/<raiz>/canister_ranges`",
    "a resposta da consulta: a assinatura Ed25519 de um nó da sub-rede, pela chave dele no certificado, sobre a resposta deste pedido — o nonce do `random.read` entra no id do pedido",
    "o Candid da resposta, com tetos: um texto, `ICP`; só então o símbolo é dito, e a declaração vai para a auditoria ancorada na conexão",
];

struct Relatorio {
    quando: String,
    arch: Arquitetura,
    release: bool,
    ensaio: bool,
    ips: Vec<[u8; 4]>,
    /// De onde vieram os IPv4: cada caminho do DNS do hospedeiro e o que
    /// ele deu, ou `--enderecos`.
    origem: String,
    /// O aperto real de cada IPv4, lido no hospedeiro: o endereço, o que se
    /// negociou e a cadeia, da folha para cima.
    apertos: Vec<([u8; 4], String, Vec<String>)>,
    rodadas: Vec<(&'static str, Rodada)>,
    auditoria: Auditoria,
    /// A impressão da chave do gestor, e cada rodada dele.
    impressao: String,
    gestor: Vec<(&'static str, DoGestor)>,
    auditoria_do_gestor: Auditoria,
    veredito: String,
}

impl Relatorio {
    fn novo(quando: &str, arch: Arquitetura, release: bool, ensaio: bool) -> Relatorio {
        Relatorio {
            quando: quando.to_string(),
            arch,
            release,
            ensaio,
            ips: Vec::new(),
            origem: String::new(),
            apertos: Vec::new(),
            rodadas: Vec::new(),
            auditoria: Auditoria::default(),
            impressao: String::new(),
            gestor: Vec::new(),
            auditoria_do_gestor: Auditoria::default(),
            veredito: String::new(),
        }
    }

    /// Grava o relatório em `target/mainnet/`, e devolve o caminho.
    fn gravar(&self) -> Result<std::path::PathBuf, String> {
        let mut t = String::new();
        let _ = writeln!(
            t,
            "# A rede principal do IC{}\n",
            if self.ensaio {
                " — ENSAIO, não é a fumaça real"
            } else {
                ""
            }
        );
        let _ = writeln!(t, "- quando: {} UTC", self.quando);
        let _ = writeln!(
            t,
            "- máquina: {}, kernel de produção {}",
            self.arch.nome(),
            if self.release { "release" } else { "debug" }
        );
        let _ = writeln!(
            t,
            "- endpoint: https://{ENDPOINT} (a rede `mainnet` de `/dados/icp/redes`)"
        );
        let _ = writeln!(t, "- IPv4 no teto da política: {}", texto_dos(&self.ips));
        if !self.origem.is_empty() {
            let _ = writeln!(t, "- de onde vieram: {}", self.origem);
        }
        let _ = writeln!(t, "- veredito: {}\n", self.veredito);
        if !self.apertos.is_empty() {
            let _ = writeln!(t, "## O aperto real, lido no hospedeiro\n");
            for (ip, negociado, cadeia) in &self.apertos {
                let _ = writeln!(
                    t,
                    "Com {}, no perfil do programa: {negociado}. A cadeia, da folha para cima:\n",
                    texto_dos(&[*ip])
                );
                for e in cadeia {
                    let _ = writeln!(t, "- {e}");
                }
                let _ = writeln!(t);
            }
        }
        for (quando, r) in &self.rodadas {
            let _ = writeln!(
                t,
                "## O programa, {quando}\n\nprocesso {}, saiu com {} em {} ms\n\n```text",
                r.processo, r.codigo, r.duracao_ms
            );
            for l in &r.linhas {
                let _ = writeln!(t, "{l}");
            }
            let _ = writeln!(t, "```\n");
        }
        if !self.auditoria.linhas.is_empty() {
            let _ = writeln!(t, "## A auditoria da consulta\n");
            for l in &self.auditoria.linhas {
                let _ = writeln!(t, "- {l}");
            }
            let _ = writeln!(t);
        }
        if !self.gestor.is_empty() {
            let _ = writeln!(
                t,
                "## O gestor: os saldos de uma chave nova, por consultas assinadas\n\nA chave `{CHAVE_DO_GESTOR}` do operador, criada por ele pelo gate na máquina zerada — impressão `{}` —, e o pedido `acao saldo` na rede `mainnet`, gravado por ele no armazém.\n",
                self.impressao
            );
            for (quando, g) in &self.gestor {
                let r = &g.rodada;
                let _ = writeln!(
                    t,
                    "### {quando}\n\nprocesso {}, saiu com {} em {} ms\n\n```text",
                    r.processo, r.codigo, r.duracao_ms
                );
                for l in &r.linhas {
                    let _ = writeln!(t, "{l}");
                }
                let _ = writeln!(
                    t,
                    "```\n\nA resposta no armazém:\n\n```text\n{}```\n",
                    g.resposta
                );
            }
            if !self.auditoria_do_gestor.linhas.is_empty() {
                let _ = writeln!(t, "### A auditoria do saldo\n");
                for l in &self.auditoria_do_gestor.linhas {
                    let _ = writeln!(t, "- {l}");
                }
                let _ = writeln!(t);
            }
        }
        let _ = writeln!(t, "## O que o programa confere antes de entregar\n");
        for l in O_QUE_SE_CONFERE {
            let _ = writeln!(t, "- {l}");
        }
        let dir = super::raiz_do_projeto().join("target").join("mainnet");
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let caminho = dir.join(format!(
            "relatorio-{}{}.md",
            self.quando.replace(':', ""),
            if self.ensaio { "-ensaio" } else { "" }
        ));
        std::fs::write(&caminho, t).map_err(|e| format!("{}: {e}", caminho.display()))?;
        Ok(caminho)
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    /// A política com os destinos: as cinco linhas do teto ganham os IPv4,
    /// o operador não, e ela passa nas conferências da imagem.
    #[test]
    fn a_politica_com_os_destinos() {
        let ips = [[203, 0, 113, 7], [198, 51, 100, 9]];
        let texto = politica_com_os_destinos(&ips).unwrap();
        for linha in texto.lines() {
            let tem = linha.ends_with(" tcp:203.0.113.7:443 tcp:198.51.100.9:443");
            assert_eq!(
                tem,
                LINHAS_DO_TETO.iter().any(|l| linha.starts_with(l)),
                "{linha}"
            );
        }
        let p = politica::Politica::ler(&texto).unwrap();
        // O operador não alcança, e o administrador pode dar.
        let operador = linha_do_operador().unwrap();
        assert!(!operador.contains("203.0.113.7"));
        let dada = format!("{operador}{}", destinos(&ips));
        assert!(
            p.com_linha(&dada, "administrador", &["administrador", "sistema"])
                .is_ok()
        );
        // Sem os destinos no teto, não pode.
        let padrao = politica::Politica::ler(politica::PADRAO).unwrap();
        assert!(
            padrao
                .com_linha(&dada, "administrador", &["administrador", "sistema"])
                .is_err()
        );
    }

    #[test]
    fn os_enderecos_dados() {
        assert_eq!(
            ler_enderecos("203.0.113.7, 198.51.100.9,203.0.113.7").unwrap(),
            [[198, 51, 100, 9], [203, 0, 113, 7]]
        );
        assert!(ler_enderecos("icp-api.io").is_err());
        assert!(ler_enderecos("2001:db8::1").is_err());
    }

    /// O servidor do emulador é o primeiro `nameserver` IPv4, como a
    /// `libslirp` o lê: o IPv6 e o que não começa a linha ficam de fora.
    #[test]
    fn o_servidor_do_emulador() {
        let resolv = "# gerado\nsearch exemplo.internal\nnameserver ::1\n nameserver 192.0.2.1\nnameserver\t127.0.0.53\nnameserver 8.8.8.8\n";
        assert_eq!(
            servidor_do_emulador(resolv),
            Some(Ipv4Addr::new(127, 0, 0, 53))
        );
        assert_eq!(servidor_do_emulador("nameserver fe80::1%eth0\n"), None);
        assert_eq!(
            servidor_do_emulador("#nameserver 192.0.2.1\nnameservers 192.0.2.2\n"),
            None
        );
    }

    /// A pergunta da máquina contra um servidor de mentira no hospedeiro:
    /// os bytes que chegam são os da pergunta do `livro`, e a resposta é
    /// lida como ele a lê — o registro de outro nome fica de fora.
    #[test]
    fn a_pergunta_da_maquina() {
        use protocolo::dns;
        let servidor = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let SocketAddr::V4(endereco) = servidor.local_addr().unwrap() else {
            unreachable!()
        };
        let atendente = std::thread::spawn(move || {
            let mut b = [0u8; dns::MAIOR_MENSAGEM];
            let (n, de) = servidor.recv_from(&mut b).unwrap();
            let pergunta = dns::ler(&b[..n]).unwrap();
            let nome = *pergunta.nome().unwrap();
            assert_eq!(nome, dns::Nome::de_texto(ENDPOINT).unwrap());
            let mut do_livro = [0u8; dns::MAIOR_MENSAGEM];
            let m = dns::pergunta(pergunta.id, &nome, &mut do_livro).unwrap();
            assert_eq!(&b[..n], &do_livro[..m]);
            let mut r = [0u8; dns::MAIOR_MENSAGEM];
            let k = dns::resposta(
                pergunta.id,
                &nome,
                &[[203, 0, 113, 7], [198, 51, 100, 9]],
                60,
                dns::SEM_ERRO,
                &mut r,
            )
            .unwrap();
            servidor.send_to(&r[..k], de).unwrap();
        });
        assert_eq!(
            perguntar_como_a_maquina(endereco).unwrap(),
            [[203, 0, 113, 7], [198, 51, 100, 9]]
        );
        atendente.join().unwrap();
    }

    /// O perfil da cadeia: a forma da Let's Encrypt pela X1 e pela X2
    /// passa; a curva com o hash da outra, a chave RSA pequena e a raiz que
    /// não é âncora param a fumaça, cada uma com o nome dela.
    #[test]
    fn a_cadeia_contra_o_perfil() {
        let elo = |sujeito: &str,
                   emissor: &str,
                   chave: &str,
                   bits,
                   curva: Option<&str>,
                   assinatura: &str| Elo {
            sujeito: sujeito.into(),
            emissor: emissor.into(),
            validade: String::new(),
            chave: chave.into(),
            bits,
            curva: curva.map(String::from),
            assinatura: assinatura.into(),
        };
        let ancoras = ancoras_da_imagem().unwrap();
        let x1 = ancoras[0].sujeito.clone();
        let x2 = ancoras[1].sujeito.clone();
        let folha = |emissor: &str, assinatura: &str| {
            elo(
                "CN = icp-api.io",
                emissor,
                "id-ecPublicKey",
                None,
                Some("P-256"),
                assinatura,
            )
        };
        // ECDSA pela X2: folha P-256 assinada com SHA-384 pelo E-intermediário P-384.
        let e7 = elo(
            "CN = E7",
            &x2,
            "id-ecPublicKey",
            None,
            Some("P-384"),
            "ecdsa-with-SHA384",
        );
        assert!(conferir_a_cadeia(&[folha("CN = E7", "ecdsa-with-SHA384"), e7.clone()]).is_ok());
        // RSA pela X1.
        let r12 = elo(
            "CN = R12",
            &x1,
            "rsaEncryption",
            Some(2048),
            None,
            "sha256WithRSAEncryption",
        );
        let folha_rsa = elo(
            "CN = icp-api.io",
            "CN = R12",
            "rsaEncryption",
            Some(2048),
            None,
            "sha256WithRSAEncryption",
        );
        assert!(conferir_a_cadeia(&[folha_rsa, r12]).is_ok());
        // A curva com o hash da outra.
        let r = conferir_a_cadeia(&[folha("CN = E7", "ecdsa-with-SHA256"), e7]);
        assert!(r.is_err_and(|m| m.starts_with("TLS_PROFILE_GAP")));
        // A chave RSA de 1024 bits.
        let pequena = elo(
            "CN = icp-api.io",
            &x1,
            "rsaEncryption",
            Some(1024),
            None,
            "sha256WithRSAEncryption",
        );
        assert!(conferir_a_cadeia(&[pequena]).is_err_and(|m| m.starts_with("TLS_PROFILE_GAP")));
        // A raiz que não é âncora.
        let gts = elo(
            "CN = WE1",
            "C = US, O = Google Trust Services LLC, CN = GTS Root R4",
            "id-ecPublicKey",
            None,
            Some("P-256"),
            "ecdsa-with-SHA384",
        );
        assert!(
            conferir_a_cadeia(&[folha("CN = WE1", "ecdsa-with-SHA256"), gts])
                .is_err_and(|m| m.starts_with("TLS_ANCHOR_GAP"))
        );
    }
}
