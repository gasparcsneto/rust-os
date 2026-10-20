//! As redes do IC em que um programa confia: `/dados/icp/redes`.
//!
//! Cada rede tem um nome, o endpoint HTTPS e a chave da raiz — a âncora da
//! verificação ([`super::certificado::Raiz`]). O arquivo é da imagem, como
//! as âncoras TLS em `/dados/tls`: o programa o lê por `fs.read`, ninguém o
//! escreve em execução, e trocar de rede ou de chave é uma imagem nova. A
//! chave da raiz **nunca** se aprende da rede: o `/api/v2/status` de uma
//! réplica a anuncia, e a especificação manda não confiar nele.
//!
//! # O formato
//!
//! ```text
//! # comentário
//! rede bancada https://icp.duke:4943 dns bls:308182301d…
//! rede local https://icp.duke:4943 10.0.2.100 bls:308182301d…
//! ```
//!
//! - `rede <nome> <url> <endereço> <chave>`, até [`MAIS_REDES`]:
//!   - o nome: minúsculas, dígitos e `-`, até 32, sem repetir;
//!   - a URL: `https://<host>[:<porta>]`, sem caminho. O host é o nome que
//!     o TLS prova e que vai no `Host`;
//!   - o endereço: `dns`, para resolver o host pelo DNS do programa, ou um
//!     IPv4, para quando não há DNS que conheça o nome (a imagem de
//!     produção e a bancada fora da suíte);
//!   - a chave: `bls:` e o DER da chave BLS da raiz em hexadecimal
//!     minúsculo — os 133 bytes com o prefixo que a especificação define.
//!
//! **Qualquer erro recusa o arquivo inteiro**, com a linha: uma rede meio
//! lida seria uma confiança que ninguém escreveu.
//!
//! O arquivo não é política. O endpoint de uma rede não autoriza nada:
//! quem pode falar com ele é quem o gate deixa conectar ao destino, a cada
//! pedido.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::certificado::{CHAVE_BLS_DER, Raiz};

/// O caminho do arquivo na imagem.
pub const CAMINHO: &str = "/dados/icp/redes";

/// Quantas redes cabem no arquivo.
pub const MAIS_REDES: usize = 16;

/// O maior arquivo.
pub const MAIOR_ARQUIVO: usize = 16 * 1024;

/// Uma rede em que se confia.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rede {
    /// O nome.
    pub nome: String,
    /// O host do endpoint.
    pub host: String,
    /// A porta do endpoint.
    pub porta: u16,
    /// O endereço fixo, ou `None` para o DNS.
    pub endereco: Option<[u8; 4]>,
    /// A raiz de confiança.
    pub raiz: Raiz,
}

/// Por que o arquivo não vale: a linha (a partir de 1) e o motivo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Erro {
    /// A linha; zero é o arquivo inteiro.
    pub linha: usize,
    /// O motivo.
    pub motivo: &'static str,
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.linha == 0 {
            write!(f, "{}: {}", CAMINHO, self.motivo)
        } else {
            write!(f, "{}, linha {}: {}", CAMINHO, self.linha, self.motivo)
        }
    }
}

fn nome_valido(nome: &str) -> bool {
    (1..=32).contains(&nome.len())
        && nome
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn host_valido(host: &str) -> bool {
    (1..=253).contains(&host.len())
        && host.split('.').all(|rotulo| {
            (1..=63).contains(&rotulo.len())
                && !rotulo.starts_with('-')
                && !rotulo.ends_with('-')
                && rotulo
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// `https://<host>[:<porta>]`.
fn url(texto: &str) -> Option<(String, u16)> {
    let resto = texto.strip_prefix("https://")?;
    let (host, porta) = match resto.split_once(':') {
        Some((host, porta)) => {
            if porta.is_empty() || porta.len() > 5 || !porta.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            match porta.parse::<u16>() {
                Ok(p) if p != 0 => (host, p),
                _ => return None,
            }
        }
        None => (resto, 443),
    };
    host_valido(host).then(|| (String::from(host), porta))
}

/// Um IPv4 na forma de quatro decimais, sem zero à esquerda.
fn ipv4(texto: &str) -> Option<[u8; 4]> {
    let mut saida = [0u8; 4];
    let mut partes = texto.split('.');
    for byte in &mut saida {
        let parte = partes.next()?;
        if parte.is_empty()
            || parte.len() > 3
            || (parte.len() > 1 && parte.starts_with('0'))
            || !parte.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        *byte = parte.parse().ok()?;
    }
    partes.next().is_none().then_some(saida)
}

fn chave(texto: &str) -> Option<Raiz> {
    let hex = texto.strip_prefix("bls:")?;
    if hex.len() != 2 * CHAVE_BLS_DER {
        return None;
    }
    let mut der = [0u8; CHAVE_BLS_DER];
    for (i, byte) in der.iter_mut().enumerate() {
        let par = &hex.as_bytes()[2 * i..2 * i + 2];
        let digito = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        *byte = digito(par[0])? << 4 | digito(par[1])?;
    }
    Raiz::de_der(&der).ok()
}

/// Lê o arquivo.
pub fn ler(texto: &str) -> Result<Vec<Rede>, Erro> {
    let erro = |linha, motivo| Erro { linha, motivo };
    if texto.len() > MAIOR_ARQUIVO {
        return Err(erro(0, "arquivo grande demais"));
    }
    let mut redes: Vec<Rede> = Vec::new();
    for (i, linha) in texto.lines().enumerate() {
        let n = i + 1;
        let linha = linha.trim();
        if linha.is_empty() || linha.starts_with('#') {
            continue;
        }
        let campos: Vec<&str> = linha.split_ascii_whitespace().collect();
        let [palavra, nome, endpoint, endereco, raiz] = campos[..] else {
            return Err(erro(n, "a linha nao tem os cinco campos"));
        };
        if palavra != "rede" {
            return Err(erro(n, "linha desconhecida"));
        }
        if !nome_valido(nome) {
            return Err(erro(n, "nome de rede invalido"));
        }
        if redes.iter().any(|r| r.nome == nome) {
            return Err(erro(n, "nome de rede repetido"));
        }
        let (host, porta) =
            url(endpoint).ok_or(erro(n, "url invalida: so https://host[:porta]"))?;
        let endereco = match endereco {
            "dns" => None,
            ip => Some(ipv4(ip).ok_or(erro(n, "endereco invalido: dns ou um ipv4"))?),
        };
        let raiz = chave(raiz).ok_or(erro(n, "chave invalida: bls: e o DER em hexadecimal"))?;
        if redes.len() == MAIS_REDES {
            return Err(erro(n, "redes demais"));
        }
        redes.push(Rede {
            nome: String::from(nome),
            host,
            porta,
            endereco,
            raiz,
        });
    }
    Ok(redes)
}

#[cfg(test)]
mod testes;
