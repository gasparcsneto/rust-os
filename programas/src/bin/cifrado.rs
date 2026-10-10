//! Conversa TLS com o eco da bancada, e confere de dentro o que o TLS do
//! Duke promete — e o que ele **não** faz: dar acesso.
//!
//! - o destino é decidido pelo gate antes do primeiro byte do TLS: a porta
//!   ao lado do eco TLS não está no alcance de papel nenhum desta imagem, e
//!   a recusa é `DENY_RESOURCE` — o código do gate, e não um do TLS; o
//!   `ClientHello` nem é montado;
//! - a âncora é um arquivo da imagem, [`ANCORAS`], lido por `fs.read`, pelo
//!   gate; a semente de cada conexão vem do `random.read`, e o relógio, do
//!   tempo lógico — os dois pelo gate também;
//! - `bancada.duke` no eco TLS, `tcp:10.0.2.100:443`: o aperto fecha, e o
//!   segredo vai e volta cifrado — o kernel só vê bytes cifrados indo para
//!   um destino que a política enumera. Depois, três registros inteiros de
//!   uma vez: mais que o buffer de saída da conexão, e o `net.send` espera
//!   espaço em vez de girar;
//! - no **mesmo** destino, os nomes que o servidor não prova: `outro.duke`
//!   (ele apresenta o certificado de `bancada.duke`: `TLS_NAME_MISMATCH`),
//!   `estranho.duke` (de uma raiz em que o programa não confia:
//!   `TLS_UNTRUSTED`) e `vencido.duke` (`TLS_EXPIRED`). O gate deixou cada
//!   uma dessas conexões — o destino está no alcance —, e é o programa que
//!   as recusa: o nome não é recurso da política, e o certificado não
//!   autoriza nada;
//! - o eco TCP, `tcp:10.0.2.100:7`, não fala TLS: devolve o `ClientHello`,
//!   e o aperto falha com `TLS_HANDSHAKE_FAILED`.
//!
//! O segredo nunca vai para a saída do programa: a suíte do kernel o
//! procura na auditoria e no log, e não pode achá-lo.
//!
//! Sai com [`CODIGO`] quando tudo confere, e com um código menor que diz o
//! quê, quando não.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "cifrado",
    "net.connect",
    "random.read",
    "system.read",
    "fs.read"
);

use alloc::vec::Vec;
use programas::escreverln;
use programas::nativo;
use programas::tls::{self, Ancoras, Falha};

/// Tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 86;
/// As âncoras não se leram — ou o gate recusou o arquivo.
const SEM_ANCORAS: i64 = 61;
/// O destino fora do alcance não foi recusado pelo gate.
const FORA_PASSOU: i64 = 62;
/// O aperto com `bancada.duke` não fechou.
const APERTO: i64 = 63;
/// O eco não voltou igual.
const ECO: i64 = 64;
/// Um nome que o servidor não prova foi aceito, ou recusado pelo motivo
/// errado.
const NOME_ACEITO: i64 = 65;
/// O par que não fala TLS não foi recusado como tal.
const SEM_TLS: i64 = 66;
/// O fecho não saiu.
const FECHO: i64 = 67;

/// A raiz da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// O eco TLS da bancada.
const ECO_TLS: &str = "tcp:10.0.2.100:443";

/// O eco TCP da bancada, que não fala TLS.
const ECO_TCP: &str = "tcp:10.0.2.100:7";

/// A porta ao lado do eco TLS: fora do alcance de qualquer papel.
const FORA: &str = "tcp:10.0.2.100:444";

/// O nome que o eco TLS prova.
const NOME: &str = "bancada.duke";

/// O que vai e volta cifrado. A suíte do kernel tem a mesma constante.
const SEGREDO: &[u8] = b"segredo-cifrado-da-bancada-7f3a";

/// O tempo desde o boot, em milissegundos — para dizer quanto o aperto e o
/// eco levaram. Zero, se o relógio não respondeu.
fn agora_ms() -> u64 {
    nativo::pedir("system.uptime", |_| Ok(()))
        .ok()
        .and_then(|r| r.resultado().ok()?.member("uptime_ms")?.as_u64())
        .unwrap_or(0)
}

/// Manda `texto` e lê o eco inteiro.
fn eco(sessao: &mut tls::Sessao<tls::Conexao>, texto: &[u8]) -> Result<(), Falha> {
    sessao.mandar(texto)?;
    let mut voltou = Vec::new();
    let mut buf = alloc::vec![0u8; 4096];
    while voltou.len() < texto.len() {
        let n = sessao.receber(&mut buf)?;
        if n == 0 {
            return Err(Falha::Interrompida);
        }
        voltou.extend_from_slice(&buf[..n]);
    }
    if voltou != texto {
        escreverln!(
            "cifrado: o eco voltou com {} bytes diferentes",
            voltou.len()
        );
        return Err(Falha::Interna);
    }
    Ok(())
}

/// Um nome que o servidor não prova: o gate deixa a conexão, e o TLS a
/// recusa pelo motivo `esperado`.
fn recusado(ancoras: &Ancoras, nome: &str, esperado: Falha) -> Result<(), i64> {
    match tls::conectar(ECO_TLS, nome, ancoras) {
        Err(f) if f == esperado => {
            escreverln!("cifrado: {} -> {}: o programa recusou", nome, f.codigo());
            Ok(())
        }
        Err(f) => {
            escreverln!(
                "cifrado: {} deu {}, e nao {}",
                nome,
                f.codigo(),
                esperado.codigo()
            );
            Err(NOME_ACEITO)
        }
        Ok(_) => {
            escreverln!("cifrado: {} foi ACEITO", nome);
            Err(NOME_ACEITO)
        }
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("cifrado: as ancoras nao se leram: {}", f.codigo());
            return SEM_ANCORAS;
        }
    };

    // O destino fora do alcance: a recusa é do gate, antes do TLS.
    match tls::conectar(FORA, NOME, &ancoras) {
        Err(f) if f.codigo() == "DENY_RESOURCE" => {
            escreverln!(
                "cifrado: {} -> DENY_RESOURCE: o gate recusou antes do TLS",
                FORA
            );
        }
        Err(f) => {
            escreverln!("cifrado: {} deu {}", FORA, f.codigo());
            return FORA_PASSOU;
        }
        Ok(_) => {
            escreverln!("cifrado: {} PASSOU", FORA);
            return FORA_PASSOU;
        }
    }

    // O nome que o servidor prova.
    let comeco = agora_ms();
    let mut sessao = match tls::conectar(ECO_TLS, NOME, &ancoras) {
        Ok(s) => s,
        Err(f) => {
            escreverln!("cifrado: o aperto com {} falhou: {}", NOME, f.codigo());
            return APERTO;
        }
    };
    escreverln!(
        "cifrado: {} provou ser {} ({}, {}) em {} ms",
        ECO_TLS,
        NOME,
        sessao.suite().unwrap_or("?"),
        sessao.grupo().unwrap_or("?"),
        agora_ms().saturating_sub(comeco)
    );
    if let Err(f) = eco(&mut sessao, SEGREDO) {
        escreverln!("cifrado: o eco falhou: {}", f.codigo());
        return ECO;
    }
    // Três registros de uma vez: mais que o buffer de saída da conexão.
    let grande: Vec<u8> = (0..3 * tls::CLARO_POR_REGISTRO)
        .map(|i| (i % 251) as u8)
        .collect();
    let comeco = agora_ms();
    if let Err(f) = eco(&mut sessao, &grande) {
        escreverln!("cifrado: o eco grande falhou: {}", f.codigo());
        return ECO;
    }
    escreverln!(
        "cifrado: o segredo e {} bytes foram e voltaram cifrados em {} ms",
        grande.len(),
        agora_ms().saturating_sub(comeco)
    );
    if let Err(f) = sessao.fechar() {
        escreverln!("cifrado: o fecho falhou: {}", f.codigo());
        return FECHO;
    }

    // No mesmo destino, os nomes que o servidor não prova.
    for (nome, esperado) in [
        ("outro.duke", Falha::NomeErrado),
        ("estranho.duke", Falha::NaoConfiavel),
        ("vencido.duke", Falha::Vencido),
    ] {
        if let Err(codigo) = recusado(&ancoras, nome, esperado) {
            return codigo;
        }
    }

    // O par que não fala TLS.
    match tls::conectar(ECO_TCP, NOME, &ancoras) {
        Err(Falha::Aperto) => {
            escreverln!("cifrado: {} nao fala TLS: TLS_HANDSHAKE_FAILED", ECO_TCP);
        }
        Err(f) => {
            escreverln!("cifrado: {} deu {}", ECO_TCP, f.codigo());
            return SEM_TLS;
        }
        Ok(_) => {
            escreverln!("cifrado: {} foi ACEITO como TLS", ECO_TCP);
            return SEM_TLS;
        }
    }
    CODIGO
}
