//! O TLS de um programa: o pacote `tls` sobre a interface nativa.
//!
//! O que o pacote pede a quem o usa, aqui vem do registro, cada coisa pelo
//! gate, como qualquer pedido do programa:
//!
//! - a **semente** de cada conexão: 32 bytes do `random.read`;
//! - o **relógio**: o tempo lógico do `system.info` — o relógio civil com
//!   o piso do journal, que nunca volta: um RTC atrasado de propósito não
//!   ressuscita um certificado vencido. O civil é o RTC até o primeiro
//!   acordo das fontes de hora, e a hora autenticada depois; o estado e a
//!   incerteza dele não entram aqui;
//! - as **âncoras**: um arquivo PEM lido por `fs.read`;
//! - o **transporte**: a conexão do `net.connect` — o destino inteiro, que
//!   a política enumera —, com cada `net.send` e cada `net.recv` decididos
//!   de novo, e os dois esperando pelo evento da pilha (`wait`), sem girar:
//!   ver [`crate::conexao`]. As falhas dela passam pelo TLS com o código de
//!   quem falhou — a recusa do gate, o firewall, a conexão recusada ou
//!   derrubada, o prazo —, e não viram um código do TLS.
//!
//! A ordem de [`conectar`] é a de quem falha fechado: a semente e o relógio
//! antes de qualquer conexão — sem eles, nada sai —, e o destino decidido
//! pelo gate antes do primeiro byte do TLS. Um destino fora do alcance é a
//! recusa do gate, com o código dele, e o `ClientHello` nem é montado.

use alloc::vec::Vec;

pub use tls::{Ancoras, CLARO_POR_REGISTRO, Codigo, Falha, Sessao};

use crate::conexao;
pub use crate::conexao::{Conexao, Prazo};
use crate::nativo::{self, Resposta, conteudo};

/// O maior arquivo de âncoras que se lê.
const MAIOR_ANCORAS: u64 = 16 * 1024;

// Um registro que sai é um `net.send`: o registro cifrado inteiro é o
// buffer da conexão.
const _: () = assert!(
    CLARO_POR_REGISTRO + tls::SOBRA_DO_REGISTRO == protocolo::usuario::nativo::BUFFER_DA_CONEXAO
);

/// A recusa do gate, com o código dele, ou a falha da chamada.
fn do_pedido(r: Result<Resposta, i64>) -> Result<Resposta, Falha> {
    let r = r.map_err(|_| Falha::Transporte(Codigo::de("TECHNICAL_ERROR")))?;
    if let Err(recusa) = r.resultado() {
        return Err(Falha::Transporte(Codigo::de(
            recusa.motivo.unwrap_or("TECHNICAL_ERROR"),
        )));
    }
    Ok(r)
}

/// O `code` de uma falha depois do gate — o firewall, a rede —, ou o
/// `error` sem código, que é técnico.
fn falha_depois_do_gate(r: &Resposta) -> Option<Falha> {
    let resultado = r.resultado().ok()?;
    if let Some(codigo) = resultado.member("code").and_then(|c| c.as_str()) {
        return Some(Falha::Transporte(Codigo::de(codigo)));
    }
    resultado
        .member("error")
        .map(|_| Falha::Transporte(Codigo::de("TECHNICAL_ERROR")))
}

/// A semente de uma conexão: 32 bytes do `random.read`, pelo gate. Sem
/// ela, não há conexão.
pub fn semente() -> Result<[u8; 32], Falha> {
    let r = do_pedido(nativo::pedir("random.read", |w| w.field_u64("bytes", 32)))?;
    if let Some(f) = falha_depois_do_gate(&r) {
        // Sem entropia no kernel: o TLS não começa.
        return Err(match f {
            Falha::Transporte(c) if c.como_str() == "ENTROPY_UNAVAILABLE" => Falha::SemAcaso,
            outra => outra,
        });
    }
    let resultado = r.resultado().map_err(|_| Falha::SemAcaso)?;
    let hex = resultado
        .member("content")
        .and_then(|c| c.as_str())
        .filter(|h| h.len() == 64)
        .ok_or(Falha::SemAcaso)?;
    let mut semente = [0u8; 32];
    for (i, par) in hex.as_bytes().chunks(2).enumerate() {
        let alto = (par[0] as char).to_digit(16).ok_or(Falha::SemAcaso)?;
        let baixo = (par[1] as char).to_digit(16).ok_or(Falha::SemAcaso)?;
        semente[i] = (alto * 16 + baixo) as u8;
    }
    Ok(semente)
}

/// O relógio: o tempo lógico, em segundos desde 1970, do `system.info`.
/// Zero — sem RTC e sem piso — é falta de relógio.
pub fn relogio() -> Result<u64, Falha> {
    let r = do_pedido(nativo::pedir("system.info", |_| Ok(())))?;
    r.resultado()
        .ok()
        .and_then(|i| i.member("persistence")?.member("clock")?.as_u64())
        .filter(|&s| s > 0)
        .ok_or(Falha::SemRelogio)
}

/// As âncoras do arquivo PEM `caminho`, lido por `fs.read`, pelo gate.
pub fn ancoras(caminho: &str) -> Result<Ancoras, Falha> {
    let mut pem = Vec::new();
    loop {
        let r = do_pedido(nativo::pedir("fs.read", |w| {
            w.field_str("path", caminho)?;
            w.field_u64("offset", pem.len() as u64)?;
            w.field_u64("max", 4096)
        }))?;
        let resultado = r.resultado().map_err(|_| Falha::Ancoras)?;
        if resultado.member("error").is_some() {
            return Err(Falha::Ancoras);
        }
        let tamanho = resultado
            .member("size")
            .and_then(|v| v.as_u64())
            .ok_or(Falha::Ancoras)?;
        if tamanho > MAIOR_ANCORAS {
            return Err(Falha::Ancoras);
        }
        let pedaco = conteudo(&r).ok_or(Falha::Ancoras)?;
        if pedaco.is_empty() {
            break;
        }
        pem.extend_from_slice(&pedaco);
        if pem.len() as u64 >= tamanho {
            break;
        }
    }
    Ancoras::de_pem(&pem)
}

/// Conecta ao `destino` — `tcp:<ipv4>:<porta>`, decidido pelo gate —, e
/// conversa TLS com quem prova ser `nome`, pelas `ancoras`.
pub fn conectar(destino: &str, nome: &str, ancoras: &Ancoras) -> Result<Sessao<Conexao>, Falha> {
    // Antes de qualquer conexão: sem semente ou sem relógio, nada sai.
    let semente = semente()?;
    let agora = relogio()?;
    // O destino, pelo gate: a recusa vem com o código dele, e o TLS nem
    // começa.
    let conexao = conexao::abrir(destino, Prazo::PADRAO).map_err(conexao::Falha::para_o_tls)?;
    Sessao::conectar(conexao, nome, ancoras, agora, semente)
}
