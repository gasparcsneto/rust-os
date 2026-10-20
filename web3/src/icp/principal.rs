//! O Principal do IC: o identificador de canisters, de usuários e de nós.
//!
//! Para quase tudo é um blob opaco de 0 a 29 bytes (**especificação**,
//! *Principals*). A forma textual é `Grouped(Base32(CRC32(b) · b))`: o
//! CRC32 (ISO 3309) em big-endian, a Base32 da RFC 4648 sem preenchimento,
//! em minúsculas, com um `-` a cada cinco caracteres. A leitura não
//! distingue maiúsculas de minúsculas (**especificação**), mas recusa
//! qualquer outro agrupamento: o texto, em minúsculas, tem de ser
//! exatamente o que este lado escreveria (**referência**:
//! `ic_principal::Principal::from_text`). Um texto de fora — da rede, de
//! um arquivo, de quem chama — nunca é confiável antes disso.
//!
//! # O que um Principal não é
//!
//! Identidade do Duke. Um Principal nomeia alguém no IC, e nada mais: o
//! anônimo, o de um canister ou o de uma chave não vira titular, papel nem
//! alcance aqui, e o gate nunca o lê.

use alloc::string::String;
use core::cmp::Ordering;
use core::fmt;

use sha2::{Digest, Sha224};

/// O maior Principal, em bytes.
pub const MAIOR: usize = 29;

/// O maior texto de um Principal: dez grupos de cinco e um de três, com
/// dez separadores — **especificação**.
pub const MAIOR_TEXTO: usize = 63;

/// Um Principal: até [`MAIOR`] bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Principal {
    bytes: [u8; MAIOR],
    tamanho: u8,
}

/// O que a forma de um Principal diz dele — **especificação**, *Special
/// forms of Principals*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Classe {
    /// Gerado pelo IC, sem estrutura de interesse — um canister, um nó, uma
    /// sub-rede. O vazio, `aaaaa-aa`, é o canister de gerenciamento.
    Opaco,
    /// `SHA-224(chave pública) · 0x02`, 29 bytes: o de quem tem a chave.
    AutoAutenticado,
    /// `SHA-224(…) · 0x03`, 29 bytes.
    Derivado,
    /// `0x04`: o anônimo, que pede sem assinar.
    Anonimo,
    /// `blob · 0x7f`: não endereça canister nem usuário.
    Reservado,
}

/// Por que um Principal não se lê.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// Mais de [`MAIOR`] bytes.
    LongoDemais,
    /// O texto não tem nem o CRC.
    TextoCurto,
    /// O texto passa do maior possível.
    TextoLongo,
    /// Um caractere fora da Base32, ou um comprimento que a Base32 sem
    /// preenchimento não produz.
    Base32,
    /// O CRC32 não confere com os bytes.
    Verificacao,
    /// Os bytes conferem, mas o texto não é a forma canônica: o
    /// agrupamento, os separadores ou os bits de sobra.
    ForaDaForma,
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Erro::LongoDemais => "principal com mais de 29 bytes",
            Erro::TextoCurto => "texto de principal curto demais",
            Erro::TextoLongo => "texto de principal longo demais",
            Erro::Base32 => "texto de principal fora da base32",
            Erro::Verificacao => "o CRC do principal nao confere",
            Erro::ForaDaForma => "texto de principal fora da forma canonica",
        })
    }
}

impl Principal {
    /// O anônimo, `2vxsx-fae`.
    pub const ANONIMO: Principal = Principal::de_constante(&[0x04]);

    /// O canister de gerenciamento, `aaaaa-aa`: o vazio.
    pub const GERENCIAMENTO: Principal = Principal::de_constante(&[]);

    const fn de_constante(b: &[u8]) -> Principal {
        let mut bytes = [0u8; MAIOR];
        let mut i = 0;
        while i < b.len() {
            bytes[i] = b[i];
            i += 1;
        }
        Principal {
            bytes,
            tamanho: b.len() as u8,
        }
    }

    /// O Principal destes bytes.
    pub fn de_bytes(b: &[u8]) -> Result<Principal, Erro> {
        if b.len() > MAIOR {
            return Err(Erro::LongoDemais);
        }
        Ok(Principal::de_constante(b))
    }

    /// O Principal auto-autenticado de uma chave pública na codificação DER
    /// — **especificação**: `SHA-224(chave) · 0x02`. É também o id da
    /// sub-rede raiz, pela chave da raiz (**referência**: o `ic-agent`
    /// obtém assim a sub-rede de um certificado sem delegação).
    pub fn auto_autenticado(chave_der: &[u8]) -> Principal {
        let mut bytes = [0u8; MAIOR];
        bytes[..28].copy_from_slice(&Sha224::digest(chave_der));
        bytes[28] = 0x02;
        Principal {
            bytes,
            tamanho: MAIOR as u8,
        }
    }

    /// Os bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.tamanho as usize]
    }

    /// O que a forma diz dele.
    pub fn classe(&self) -> Classe {
        let b = self.bytes();
        match b {
            [0x04] => Classe::Anonimo,
            [.., 0x7f] => Classe::Reservado,
            [.., 0x02] if b.len() == MAIOR => Classe::AutoAutenticado,
            [.., 0x03] if b.len() == MAIOR => Classe::Derivado,
            _ => Classe::Opaco,
        }
    }

    /// O Principal de um texto, que vem de fora: sem distinguir maiúsculas,
    /// e só na forma canônica.
    pub fn de_texto(texto: &str) -> Result<Principal, Erro> {
        if texto.len() > MAIOR_TEXTO {
            return Err(Erro::TextoLongo);
        }
        // A Base32 sem os separadores: no máximo 51 caracteres, que dão os
        // 33 bytes do CRC e do maior Principal.
        let mut valores = [0u8; MAIOR_TEXTO];
        let mut n = 0;
        for c in texto.bytes() {
            if c == b'-' {
                continue;
            }
            valores[n] = valor_base32(c).ok_or(Erro::Base32)?;
            n += 1;
        }
        let mut cru = [0u8; 4 + MAIOR + 8];
        let tamanho = decodificar_base32(&valores[..n], &mut cru).ok_or(Erro::Base32)?;
        if tamanho < 4 {
            return Err(Erro::TextoCurto);
        }
        let dados = &cru[4..tamanho];
        if dados.len() > MAIOR {
            return Err(Erro::TextoLongo);
        }
        if crc32(dados).to_be_bytes() != cru[..4] {
            return Err(Erro::Verificacao);
        }
        let p = Principal::de_constante(dados);
        // A forma canônica: o que este lado escreveria, em minúsculas.
        let mut canonico = [0u8; MAIOR_TEXTO];
        let escrito = p.escrever_texto(&mut canonico);
        let igual = escrito.len() == texto.len()
            && escrito
                .iter()
                .zip(texto.bytes())
                .all(|(a, b)| *a == b.to_ascii_lowercase());
        if !igual {
            return Err(Erro::ForaDaForma);
        }
        Ok(p)
    }

    /// O texto canônico.
    pub fn texto(&self) -> String {
        let mut buf = [0u8; MAIOR_TEXTO];
        let escrito = self.escrever_texto(&mut buf);
        // Só ASCII da Base32 e `-`.
        String::from(core::str::from_utf8(escrito).unwrap_or(""))
    }

    /// Escreve o texto canônico em `buf` e devolve a parte escrita.
    fn escrever_texto<'b>(&self, buf: &'b mut [u8; MAIOR_TEXTO]) -> &'b [u8] {
        let dados = self.bytes();
        let mut cru = [0u8; 4 + MAIOR];
        cru[..4].copy_from_slice(&crc32(dados).to_be_bytes());
        cru[4..4 + dados.len()].copy_from_slice(dados);
        let cru = &cru[..4 + dados.len()];
        let mut base = [0u8; 56];
        let n = codificar_base32(cru, &mut base);
        let mut escrito = 0;
        for (i, c) in base[..n].iter().enumerate() {
            if i > 0 && i % 5 == 0 {
                buf[escrito] = b'-';
                escrito += 1;
            }
            buf[escrito] = *c;
            escrito += 1;
        }
        &buf[..escrito]
    }
}

impl Principal {
    /// A ordem do `ic_principal` 0.1.5, que as implementações oficiais
    /// usam nas faixas de canister: o tamanho primeiro, depois os bytes (a
    /// ordem derivada de `(len, bytes)`). Difere da [lexicográfica](Ord)
    /// da especificação só entre Principals de tamanhos diferentes — ver
    /// [`super::certificado::faixas_contem`], que exige as duas.
    pub fn ordem_oficial(&self, outro: &Self) -> Ordering {
        (self.tamanho, self.bytes()).cmp(&(outro.tamanho, outro.bytes()))
    }
}

impl Ord for Principal {
    /// A ordem lexicográfica dos bytes — a das faixas de canister
    /// (**especificação**, *Subnet information*: "ordered
    /// lexicographically").
    fn cmp(&self, outro: &Self) -> Ordering {
        self.bytes().cmp(outro.bytes())
    }
}

impl PartialOrd for Principal {
    fn partial_cmp(&self, outro: &Self) -> Option<Ordering> {
        Some(self.cmp(outro))
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; MAIOR_TEXTO];
        let escrito = self.escrever_texto(&mut buf);
        f.write_str(core::str::from_utf8(escrito).map_err(|_| fmt::Error)?)
    }
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Principal({self})")
    }
}

/// O CRC32 da ISO 3309 (o do zlib e do PNG): polinômio refletido
/// `0xEDB88320`, começo e fim invertidos.
pub(crate) fn crc32(dados: &[u8]) -> u32 {
    const TABELA: [u32; 256] = {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
    let mut c = 0xFFFF_FFFFu32;
    for b in dados {
        c = TABELA[((c ^ u32::from(*b)) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

const ALFABETO: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn valor_base32(c: u8) -> Option<u8> {
    match c {
        b'a'..=b'z' => Some(c - b'a'),
        b'A'..=b'Z' => Some(c - b'A'),
        b'2'..=b'7' => Some(c - b'2' + 26),
        _ => None,
    }
}

/// A Base32 da RFC 4648, sem preenchimento, em minúsculas.
fn codificar_base32(dados: &[u8], saida: &mut [u8]) -> usize {
    let mut n = 0;
    let mut acumulado: u32 = 0;
    let mut bits = 0;
    for b in dados {
        acumulado = (acumulado << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            saida[n] = ALFABETO[((acumulado >> bits) & 31) as usize];
            n += 1;
        }
    }
    if bits > 0 {
        saida[n] = ALFABETO[((acumulado << (5 - bits)) & 31) as usize];
        n += 1;
    }
    n
}

/// O caminho de volta: `None` para um comprimento que a codificação sem
/// preenchimento não produz, ou para bits de sobra que não são zero — um
/// texto assim não é a forma de bytes nenhum.
fn decodificar_base32(valores: &[u8], saida: &mut [u8]) -> Option<usize> {
    if matches!(valores.len() % 8, 1 | 3 | 6) {
        return None;
    }
    let bytes = valores.len() * 5 / 8;
    if bytes > saida.len() {
        return None;
    }
    let mut n = 0;
    let mut acumulado: u32 = 0;
    let mut bits = 0;
    for v in valores {
        acumulado = (acumulado << 5) | u32::from(*v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            saida[n] = (acumulado >> bits) as u8;
            n += 1;
            acumulado &= (1 << bits) - 1;
        }
    }
    if acumulado != 0 {
        return None;
    }
    Some(n)
}

#[cfg(test)]
mod testes;
