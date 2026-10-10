//! Por que uma conversa TLS não aconteceu, ou acabou.
//!
//! Três famílias que não se confundem — a regra da seção 24 do incremento
//! de usabilidade, `docs/USABILIDADE.md`:
//!
//! - a do **transporte**: o gate recusou um pedido da conexão
//!   (`DENY_RESOURCE`, `DENY_CONTAINED`, `RATE_LIMIT`…), o firewall barrou
//!   (`FIREWALL_BLOCKED`), a rede não está (`NETWORK_UNAVAILABLE`), a
//!   chamada não voltou (`TECHNICAL_ERROR`). O código é o de quem
//!   implementa o [`crate::Transporte`], e passa por aqui sem tradução: uma
//!   recusa do gate no meio de uma sessão TLS continua sendo do gate;
//! - a do **TLS**: o servidor não provou ser quem o nome diz, não fala o
//!   protocolo, ou não respondeu — os códigos `TLS_*`, como o
//!   `TLS_UNAVAILABLE` do par mudo, irmão do `DNS_UNAVAILABLE` do
//!   resolvedor. Não é recusa do gate: o gate deixou
//!   a conexão; quem recusou foi o programa, porque do outro lado não estava
//!   quem devia;
//! - a do **que falta aqui**: sem aleatório (`ENTROPY_UNAVAILABLE`), sem
//!   relógio (`CLOCK_UNAVAILABLE`), um nome que não se escreve
//!   (`INVALID_REQUEST`), âncoras que não se leem (`TLS_ANCHORS_INVALID`),
//!   uma falha interna (`TECHNICAL_ERROR`).

use core::fmt;

/// O código de uma falha do transporte, como quem o implementa o deu: um
/// texto curto, em ASCII.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Codigo {
    bytes: [u8; 32],
    tamanho: u8,
}

impl Codigo {
    /// O código `texto`. Um texto que não é um código — vazio, longo
    /// demais, fora de `A-Z`, `0-9` e `_` — vira `TECHNICAL_ERROR`: a
    /// falha não se perde, e o texto de fora não passa adiante.
    pub fn de(texto: &str) -> Codigo {
        let valido = !texto.is_empty()
            && texto.len() <= 32
            && texto
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        let texto = if valido { texto } else { "TECHNICAL_ERROR" };
        let mut bytes = [0u8; 32];
        bytes[..texto.len()].copy_from_slice(texto.as_bytes());
        Codigo {
            bytes,
            tamanho: texto.len() as u8,
        }
    }

    pub fn como_str(&self) -> &str {
        // Só ASCII entra em `de`.
        core::str::from_utf8(&self.bytes[..usize::from(self.tamanho)]).unwrap_or("TECHNICAL_ERROR")
    }
}

impl fmt::Debug for Codigo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.como_str())
    }
}

/// Por que uma conversa TLS não aconteceu, ou acabou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falha {
    /// O transporte falhou — ver o cabeçalho.
    Transporte(Codigo),
    /// Sem aleatório: o gerador não inventa entropia.
    SemAcaso,
    /// Sem relógio: a validade de um certificado não se confere.
    SemRelogio,
    /// O nome do servidor não se escreve como nome DNS nem como endereço.
    Nome,
    /// As âncoras dadas não se leem: nenhum certificado, ou um que não é.
    Ancoras,
    /// A cadeia não chega a uma âncora: emissor desconhecido, assinatura
    /// que não confere, algoritmo fora do perfil, certificado malformado ou
    /// para outro uso.
    NaoConfiavel,
    /// O certificado é válido, mas não para este nome.
    NomeErrado,
    /// O certificado venceu.
    Vencido,
    /// O certificado ainda não vale.
    AindaNaoValido,
    /// O par não fala TLS 1.3 no perfil, mandou um alerta, ou se comportou
    /// fora do protocolo: o aperto não fecha.
    Aperto,
    /// Um registro não conferiu: adulterado no caminho, ou de outra chave.
    Adulterado,
    /// O par fechou a conexão sem `close_notify` — no meio do aperto, ou
    /// depois: o que chegou pode estar cortado.
    Interrompida,
    /// O par não respondeu — nem aceitou o que se mandou — dentro do prazo
    /// de quem implementa o transporte.
    SemResposta,
    /// Uma falha daqui: um buffer que não cresce, uma sequência esgotada.
    Interna,
}

impl Falha {
    /// O código da falha — ver o cabeçalho.
    pub fn codigo(&self) -> &str {
        match self {
            Falha::Transporte(c) => c.como_str(),
            Falha::SemAcaso => "ENTROPY_UNAVAILABLE",
            Falha::SemRelogio => "CLOCK_UNAVAILABLE",
            Falha::Nome => "INVALID_REQUEST",
            Falha::Ancoras => "TLS_ANCHORS_INVALID",
            Falha::NaoConfiavel => "TLS_UNTRUSTED",
            Falha::NomeErrado => "TLS_NAME_MISMATCH",
            Falha::Vencido => "TLS_EXPIRED",
            Falha::AindaNaoValido => "TLS_NOT_YET_VALID",
            Falha::Aperto => "TLS_HANDSHAKE_FAILED",
            Falha::Adulterado => "TLS_TAMPERED",
            Falha::Interrompida => "TLS_INTERRUPTED",
            Falha::SemResposta => "TLS_UNAVAILABLE",
            Falha::Interna => "TECHNICAL_ERROR",
        }
    }

    /// A falha de um erro do `rustls`.
    pub(crate) fn do_rustls(e: &rustls::Error) -> Falha {
        use rustls::{CertificateError as C, Error as E};
        match e {
            E::InvalidCertificate(c) => match c {
                C::Expired | C::ExpiredContext { .. } => Falha::Vencido,
                C::NotValidYet | C::NotValidYetContext { .. } => Falha::AindaNaoValido,
                C::NotValidForName | C::NotValidForNameContext { .. } => Falha::NomeErrado,
                _ => Falha::NaoConfiavel,
            },
            E::NoCertificatesPresented => Falha::NaoConfiavel,
            E::DecryptError => Falha::Adulterado,
            E::FailedToGetRandomBytes => Falha::SemAcaso,
            E::FailedToGetCurrentTime => Falha::SemRelogio,
            E::UnsupportedNameType => Falha::Nome,
            E::EncryptError | E::General(_) => Falha::Interna,
            // O resto é do par: um alerta, uma mensagem fora de ordem ou
            // malformada, nenhuma versão, suíte ou grupo em comum.
            _ => Falha::Aperto,
        }
    }
}

impl fmt::Display for Falha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.codigo())
    }
}
