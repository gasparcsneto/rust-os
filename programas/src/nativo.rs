//! A interface nativa do Duke, do lado do programa.
//!
//! # O que um programa pede, e a quem
//!
//! Ao sistema, um comando do registro: o mesmo `system.info`, o mesmo
//! `message.send`, o mesmo `ui.claim` que um agente pede pelo canal e uma
//! pessoa pelo interpretador, com os mesmos parâmetros e a mesma resposta.
//! O kernel decide pelo mesmo gate, com a autoridade do processo — a de
//! quem o lançou —, e grava a decisão na mesma auditoria, dizendo que foi
//! pelo processo. Não há uma segunda API para programas, nem um atalho:
//! um programa é um cidadão do sistema como os outros, e é por isso que
//! ele pode usar tudo que os outros usam — e nada além.
//!
//! O que um programa **não** pede por aqui, porque é de um canal: a prova
//! administrativa (`admin.challenge`/`admin.execute`) e `debug.trigger`.
//! Ver `docs/INTERFACE.md`.
//!
//! # Como se usa
//!
//! ```ignore
//! use programas::nativo;
//!
//! let r = nativo::pedir("system.info", |_| Ok(()))?;
//! match r.resultado() {
//!     Ok(info) => { /* info.member("native_interface") … */ }
//!     Err(recusa) => { /* recusa.motivo == Some("DENY_PERMISSION") … */ }
//! }
//! ```
//!
//! O leitor e o escritor de JSON são os de [`protocolo::json`] — os mesmos
//! do kernel. Um programa não acha num envelope um campo que o kernel não
//! escreveu, nem o contrário.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

pub use protocolo::json::{Json, JsonWriter};
pub use protocolo::usuario::nativo::{MAIOR_PEDIDO, VERSAO};

use crate::sistema;

/// O `id` do próximo pedido. Só serve para o programa casar a resposta com
/// o pedido: o kernel o ecoa e não o interpreta.
static PROXIMO_ID: AtomicU64 = AtomicU64::new(1);

/// O envelope que o kernel devolveu. Os bytes são zerados quando ela sai de
/// cena: uma resposta pode trazer o corpo de uma mensagem, e o monte
/// reaproveita a memória.
pub struct Resposta {
    bytes: Vec<u8>,
}

/// O `error` de um envelope: o pedido não chegou ao comando, ou o gate o
/// recusou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recusa<'a> {
    /// O código JSON-RPC: `-32700` JSON quebrado, `-32601` método
    /// desconhecido, `-32602` parâmetro errado, e os de recusa do gate.
    pub codigo: i64,
    /// A mensagem do código.
    pub mensagem: &'a str,
    /// O motivo, quando há: o nome do código da política
    /// (`DENY_PERMISSION`, `DENY_RATE`…), ou o campo que não valeu.
    pub motivo: Option<&'a str>,
}

impl Resposta {
    /// O envelope inteiro.
    pub fn envelope(&self) -> Json<'_> {
        Json(&self.bytes)
    }

    /// Os bytes do envelope, como o kernel os escreveu.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// O `result`, ou a recusa.
    pub fn resultado(&self) -> Result<Json<'_>, Recusa<'_>> {
        let envelope = self.envelope();
        if let Some(resultado) = envelope.member("result") {
            return Ok(resultado);
        }
        let erro = envelope.member("error");
        let codigo = erro
            .and_then(|e| e.member("code"))
            .and_then(|c| c.raw_str())
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let mensagem = erro
            .and_then(|e| e.member("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("");
        let motivo = erro.and_then(|e| e.member("data")).and_then(|d| d.as_str());
        Err(Recusa {
            codigo,
            mensagem,
            motivo,
        })
    }
}

impl Drop for Resposta {
    fn drop(&mut self) {
        for b in self.bytes.iter_mut() {
            // SAFETY: o byte é deste vetor, vivo e alinhado.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }
}

/// Pede `metodo` com os campos que `params` escreve dentro do objeto dos
/// parâmetros — `|_| Ok(())` para nenhum. A resposta, ou o erro da chamada
/// de sistema.
///
/// ```ignore
/// nativo::pedir("message.send", |w| {
///     w.field_str("to", "serial")?;
///     w.field_str("body", "oi")?;
///     w.field_u64("nonce", 1)
/// })
/// ```
pub fn pedir(
    metodo: &str,
    params: impl FnOnce(&mut JsonWriter) -> fmt::Result,
) -> Result<Resposta, i64> {
    let mut linha = String::new();
    let id = PROXIMO_ID.fetch_add(1, Ordering::Relaxed);
    let montado = (|| {
        let mut w = JsonWriter::new(&mut linha);
        w.begin_object()?;
        w.field_str("jsonrpc", "2.0")?;
        w.key("id")?;
        w.u64_value(id)?;
        w.field_str("method", metodo)?;
        w.key("params")?;
        w.begin_object()?;
        params(&mut w)?;
        w.end_object()?;
        w.end_object()
    })();
    // Escrever numa `String` não falha; um parâmetro que falhou é do
    // programa, e o pedido não sai pela metade.
    if montado.is_err() {
        return Err(sistema::erro::TAMANHO_INVALIDO);
    }
    pedir_cru(linha.as_bytes())
}

/// [`pedir`], com um anexo: bytes que vão junto, fora do JSON — o conteúdo
/// binário de um arquivo do armazém. Ver
/// `protocolo::usuario::numero::PEDIR_COM_ANEXO`.
pub fn pedir_com_anexo(
    metodo: &str,
    params: impl FnOnce(&mut JsonWriter) -> fmt::Result,
    anexo: &[u8],
) -> Result<Resposta, i64> {
    let mut linha = String::new();
    let id = PROXIMO_ID.fetch_add(1, Ordering::Relaxed);
    let montado = (|| {
        let mut w = JsonWriter::new(&mut linha);
        w.begin_object()?;
        w.field_str("jsonrpc", "2.0")?;
        w.key("id")?;
        w.u64_value(id)?;
        w.field_str("method", metodo)?;
        w.key("params")?;
        w.begin_object()?;
        params(&mut w)?;
        w.end_object()?;
        w.end_object()
    })();
    if montado.is_err() {
        return Err(sistema::erro::TAMANHO_INVALIDO);
    }
    let tamanho = sistema::pedir_com_anexo(linha.as_bytes(), anexo);
    receber(tamanho)
}

/// Pede com a linha já montada — para quem quer mandar o JSON como está,
/// inclusive quebrado. A resposta, ou o erro da chamada de sistema.
pub fn pedir_cru(linha: &[u8]) -> Result<Resposta, i64> {
    let tamanho = sistema::pedir(linha);
    receber(tamanho)
}

/// A resposta de um pedido que devolveu `tamanho`.
fn receber(tamanho: i64) -> Result<Resposta, i64> {
    if tamanho < 0 {
        return Err(tamanho);
    }
    let mut bytes = alloc::vec![0u8; tamanho as usize];
    let lidos = sistema::resposta(&mut bytes);
    if lidos < 0 {
        return Err(lidos);
    }
    // O tamanho é o que `pedir` devolveu, e a resposta não muda entre as
    // duas chamadas: um processo é um fio só.
    bytes.truncate(lidos as usize);
    Ok(Resposta { bytes })
}
