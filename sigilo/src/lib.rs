//! O canal seguro do Duke.
//!
//! # O que há aqui
//!
//! - [`aperto`]: o aperto de mão `Noise_IK_25519_ChaChaPoly_BLAKE2s` e o
//!   transporte cifrado que sai dele. É por ele que um agente fala com o
//!   Duke pelas portas: autenticado pela chave dele, e cifrado;
//! - [`administracao`]: a prova das operações administrativas, por desafio
//!   e resposta, que vale em qualquer sessão — inclusive na serial, que é
//!   aberta;
//! - [`gerador`]: o gerador de números aleatórios de onde saem as chaves
//!   efêmeras;
//! - [`quadro`]: como as mensagens se delimitam no fluxo de bytes da porta;
//! - [`registro`]: o formato dos arquivos de chaves autorizadas;
//! - [`resumo`] e [`cifra`]: as peças do Noise — o BLAKE2s, o HMAC, o HKDF
//!   e o ChaCha20-Poly1305 com o contador.
//!
//! # A identidade é a chave
//!
//! Um agente é a sua chave pública X25519. Não há senha nem nome que ele
//! declare: ele prova, no aperto de mão, que tem a chave privada que
//! corresponde a uma pública, e é essa pública que o registro do Duke
//! conhece. O nome que aparece nos relatórios vem do registro, e não dele.
//!
//! # Por que o Noise, e não o TLS
//!
//! O TLS resolve um problema maior — negociar entre programas que nunca se
//! viram, com certificados emitidos por terceiros —, e traz junto o tamanho
//! disso. Aqui os dois lados já se conhecem pelas chaves, que foram
//! provisionadas. O Noise é um padrão de aperto de mão, uma escolha de
//! primitivas e nada mais: cabe num arquivo que se lê inteiro, e é o mesmo
//! do WireGuard.

#![no_std]

extern crate alloc;

pub mod administracao;
pub mod aperto;
pub mod cifra;
pub mod credencial;
pub mod gerador;
pub mod pessoas;
pub mod quadro;
pub mod registro;
pub mod resumo;

pub use aperto::{Aguardando, Iniciador, Recebido, Respondedor, Transporte, publica_de};
pub use gerador::Gerador;

/// Para quem usa este pacote apagar os próprios segredos do mesmo jeito.
pub use zeroize;

/// O nome do protocolo, exatamente como entra no resumo inicial.
pub const NOME_DO_PROTOCOLO: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// O prólogo do canal do Duke: entra no resumo do aperto nos dois lados, e
/// um agente que use outro prólogo — outra versão do protocolo — não
/// consegue completar o aperto, em vez de completá-lo e se desentender
/// depois.
pub const PROLOGO: &[u8] = b"Duke canal do agente v1";

/// O tamanho de uma chave X25519, pública ou privada.
pub const TAM_CHAVE: usize = 32;

/// A maior mensagem do Noise, em bytes.
pub const MAIOR_MENSAGEM: usize = 65_535;

/// O que pode dar errado no canal seguro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// A mensagem é curta demais para o que precisa conter.
    Curta,
    /// A mensagem passaria do limite do Noise.
    Grande,
    /// O espaço de saída não cabe o resultado.
    Espaco,
    /// A etiqueta não conferiu: a mensagem foi adulterada, repetida, ou
    /// cifrada com outra chave.
    Autenticacao,
    /// O Diffie-Hellman deu zero: uma chave pública de ordem baixa.
    ChaveFraca,
    /// O contador de mensagens chegou ao fim; a sessão tem de acabar.
    Contador,
    /// Um quadro com um tipo que não existe.
    Quadro,
    /// Um passo fora do lugar.
    Estado,
}

impl Erro {
    /// Uma frase curta, para o log e para o motivo de uma recusa.
    pub const fn motivo(self) -> &'static str {
        match self {
            Erro::Curta => "mensagem curta demais",
            Erro::Grande => "mensagem maior que o limite do Noise",
            Erro::Espaco => "sem espaco para o resultado",
            Erro::Autenticacao => "a autenticacao falhou",
            Erro::ChaveFraca => "chave publica de ordem baixa",
            Erro::Contador => "o contador de mensagens acabou",
            Erro::Quadro => "quadro de tipo desconhecido",
            Erro::Estado => "passo fora de ordem",
        }
    }
}

/// Uma chave em hexadecimal, como ela aparece nos arquivos e no relatório.
pub fn hex(chave: &[u8; TAM_CHAVE]) -> alloc::string::String {
    hex_de(chave)
}

/// Bytes quaisquer em hexadecimal, dois dígitos minúsculos por byte.
pub fn hex_de(bytes: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::with_capacity(2 * bytes.len());
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Uma chave a partir do hexadecimal. `None` se não forem exatamente 64
/// dígitos.
pub fn de_hex(texto: &str) -> Option<[u8; TAM_CHAVE]> {
    de_hex_fixo(texto.trim())
}

/// `N` bytes a partir de exatamente `2N` dígitos hexadecimais, sem espaço
/// em volta.
pub fn de_hex_fixo<const N: usize>(texto: &str) -> Option<[u8; N]> {
    if texto.len() != 2 * N || !texto.is_ascii() {
        return None;
    }
    let mut saida = [0u8; N];
    for (i, b) in saida.iter_mut().enumerate() {
        *b = u8::from_str_radix(&texto[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(saida)
}
