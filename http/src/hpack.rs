//! O HPACK (RFC 7541): como os cabeçalhos do HTTP/2 vão comprimidos.
//!
//! # O que um bloco de cabeça carrega
//!
//! Uma sequência de representações, cada uma um campo (nome e valor):
//!
//! - **indexado**: um número, que aponta para a tabela estática (1 a 61) ou
//!   para a dinâmica (62 em diante);
//! - **literal com indexação**: o nome (por índice, ou escrito) e o valor
//!   escrito — e o campo entra na tabela dinâmica;
//! - **literal sem indexação**, e **literal nunca indexado**: o mesmo, sem
//!   entrar na tabela; o segundo diz a quem repassa que também não indexe;
//! - **atualização do tamanho** da tabela dinâmica, só no começo do bloco, e
//!   nunca acima do que este lado anunciou.
//!
//! # A tabela dinâmica é estado da conexão
//!
//! Cada bloco que chega muda a tabela, e o bloco seguinte depende dela: um
//! bloco largado no meio deixaria o próximo apontando para outra coisa. Por
//! isso o [`Decodificador`] lê o bloco inteiro mesmo quando a lista passa do
//! teto de quem pediu — a lista não cresce, a tabela continua certa —, e um
//! bloco que não se decodifica estraga a conexão inteira (quem chama manda
//! `COMPRESSION_ERROR` e fecha).
//!
//! # O que este lado manda
//!
//! O [`Codificador`] não indexa nada: cada campo vai literal sem indexação
//! — ou indexado, quando o par inteiro está na tabela estática —, e a tabela
//! dinâmica do servidor nunca ganha um campo deste cliente. O `cookie` vai
//! como **nunca indexado** (RFC 7541, 7.1.3): um valor secreto não fica numa
//! tabela de onde um vizinho poderia adivinhá-lo pelo tamanho. As cadeias
//! vão em Huffman quando ficam menores ([`crate::huffman`]).

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::huffman;

/// Quanto um campo ocupa na tabela dinâmica: o nome, o valor e 32
/// (RFC 7541, 4.1).
pub(crate) const fn ocupa(nome: usize, valor: usize) -> usize {
    32 + nome + valor
}

/// O maior inteiro que se aceita num bloco: mais que qualquer índice,
/// tamanho de cadeia ou de tabela que este lado anuncia — e pouco o bastante
/// para nenhuma conta transbordar.
const MAIOR_INTEIRO: u64 = 1 << 28;

/// Por que um bloco de cabeça não se decodifica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErroHpack {
    /// O bloco acabou no meio de uma representação.
    Cortado,
    /// Um inteiro grande demais (RFC 7541, 5.1).
    Inteiro,
    /// O índice zero, ou um além das duas tabelas.
    Indice,
    /// Uma cadeia em Huffman que não é: o EOS no meio, ou o fim que não é o
    /// preenchimento.
    Huffman,
    /// Uma atualização do tamanho da tabela acima do que este lado
    /// anunciou, ou depois do primeiro campo do bloco.
    Tamanho,
}

/// Um campo decodificado.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Campo {
    pub nome: Vec<u8>,
    pub valor: Vec<u8>,
}

/// Lê o inteiro com prefixo de `prefixo` bits (1 a 8) que começa em `*pos`.
pub(crate) fn inteiro(bloco: &[u8], pos: &mut usize, prefixo: u32) -> Result<usize, ErroHpack> {
    let mascara = ((1u16 << prefixo) - 1) as u8;
    let primeiro = *bloco.get(*pos).ok_or(ErroHpack::Cortado)?;
    *pos += 1;
    let mut valor = u64::from(primeiro & mascara);
    if valor < u64::from(mascara) {
        return Ok(valor as usize);
    }
    let mut desloca = 0u32;
    loop {
        let b = *bloco.get(*pos).ok_or(ErroHpack::Cortado)?;
        *pos += 1;
        valor += u64::from(b & 0x7f) << desloca;
        if valor > MAIOR_INTEIRO {
            return Err(ErroHpack::Inteiro);
        }
        if b & 0x80 == 0 {
            return Ok(valor as usize);
        }
        desloca += 7;
        // Zeros de continuação também contam: sem isto, um bloco de `0x80`
        // seguidos andaria sem fim aparente.
        if desloca > 28 {
            return Err(ErroHpack::Inteiro);
        }
    }
}

/// Lê a cadeia que começa em `*pos`, decodificando o Huffman, com no
/// máximo `teto` bytes decodificados.
fn cadeia(bloco: &[u8], pos: &mut usize, teto: usize) -> Result<Vec<u8>, ErroHpack> {
    let em_huffman = *bloco.get(*pos).ok_or(ErroHpack::Cortado)? & 0x80 != 0;
    let n = inteiro(bloco, pos, 7)?;
    let fim = pos
        .checked_add(n)
        .filter(|&f| f <= bloco.len())
        .ok_or(ErroHpack::Cortado)?;
    let bytes = &bloco[*pos..fim];
    *pos = fim;
    if em_huffman {
        huffman::decodificar(bytes, teto).map_err(|_| ErroHpack::Huffman)
    } else {
        Ok(bytes.to_vec())
    }
}

/// O decodificador de uma conexão: a tabela dinâmica que os blocos do
/// servidor vão montando.
pub(crate) struct Decodificador {
    /// A tabela dinâmica: na frente, o mais novo (índice 62).
    dinamica: VecDeque<(Vec<u8>, Vec<u8>)>,
    /// O que a tabela ocupa (RFC 7541, 4.1).
    ocupado: usize,
    /// O tamanho máximo de agora, que o servidor pode baixar e subir até o
    /// teto.
    maximo: usize,
    /// O que este lado anunciou (`SETTINGS_HEADER_TABLE_SIZE`).
    teto: usize,
}

impl Decodificador {
    pub fn novo(teto: usize) -> Decodificador {
        Decodificador {
            dinamica: VecDeque::new(),
            ocupado: 0,
            maximo: teto,
            teto,
        }
    }

    /// Quantos campos a tabela dinâmica tem, e quanto ocupa.
    #[cfg(test)]
    pub fn tabela(&self) -> (usize, usize) {
        (self.dinamica.len(), self.ocupado)
    }

    fn por_indice(&self, i: usize) -> Result<(&[u8], &[u8]), ErroHpack> {
        match i {
            0 => Err(ErroHpack::Indice),
            1..=61 => {
                let (n, v) = ESTATICA[i - 1];
                Ok((n.as_bytes(), v.as_bytes()))
            }
            _ => self
                .dinamica
                .get(i - 62)
                .map(|(n, v)| (n.as_slice(), v.as_slice()))
                .ok_or(ErroHpack::Indice),
        }
    }

    fn inserir(&mut self, nome: Vec<u8>, valor: Vec<u8>) {
        let tamanho = ocupa(nome.len(), valor.len());
        // Um campo maior que a tabela inteira a esvazia, e não entra
        // (RFC 7541, 4.4).
        while self.ocupado + tamanho > self.maximo {
            match self.dinamica.pop_back() {
                Some((n, v)) => self.ocupado -= ocupa(n.len(), v.len()),
                None => break,
            }
        }
        if tamanho <= self.maximo {
            self.dinamica.push_front((nome, valor));
            self.ocupado += tamanho;
        }
    }

    fn redimensionar(&mut self, maximo: usize) {
        self.maximo = maximo;
        while self.ocupado > self.maximo {
            match self.dinamica.pop_back() {
                Some((n, v)) => self.ocupado -= ocupa(n.len(), v.len()),
                None => break,
            }
        }
    }

    /// Decodifica `bloco` inteiro. Os campos entram na lista enquanto ela
    /// couber em `limite` — contados como a tabela os conta, nome, valor e
    /// 32 —; os de depois não entram, e a tabela continua sendo mantida. O
    /// segundo valor diz se a lista passou.
    pub fn decodificar(
        &mut self,
        bloco: &[u8],
        limite: usize,
    ) -> Result<(Vec<Campo>, bool), ErroHpack> {
        let mut campos = Vec::new();
        let mut gasto = 0usize;
        let mut passou = false;
        let mut algum_campo = false;
        // Uma cadeia decodificada não passa do bloco inteiro em Huffman: o
        // código mais curto tem 5 bits.
        let teto_da_cadeia = bloco.len() * 8 / 5 + 1;
        let mut pos = 0;
        while pos < bloco.len() {
            let b = bloco[pos];
            let (nome, valor) = if b & 0x80 != 0 {
                // Indexado.
                let i = inteiro(bloco, &mut pos, 7)?;
                let (n, v) = self.por_indice(i)?;
                (n.to_vec(), v.to_vec())
            } else if b & 0xc0 == 0x40 {
                // Literal com indexação.
                let i = inteiro(bloco, &mut pos, 6)?;
                let nome = match i {
                    0 => cadeia(bloco, &mut pos, teto_da_cadeia)?,
                    _ => self.por_indice(i)?.0.to_vec(),
                };
                let valor = cadeia(bloco, &mut pos, teto_da_cadeia)?;
                self.inserir(nome.clone(), valor.clone());
                (nome, valor)
            } else if b & 0xe0 == 0x20 {
                // A atualização do tamanho: só antes do primeiro campo, e
                // nunca acima do anunciado.
                let n = inteiro(bloco, &mut pos, 5)?;
                if algum_campo || n > self.teto {
                    return Err(ErroHpack::Tamanho);
                }
                self.redimensionar(n);
                continue;
            } else {
                // Literal sem indexação (0000) ou nunca indexado (0001).
                let i = inteiro(bloco, &mut pos, 4)?;
                let nome = match i {
                    0 => cadeia(bloco, &mut pos, teto_da_cadeia)?,
                    _ => self.por_indice(i)?.0.to_vec(),
                };
                let valor = cadeia(bloco, &mut pos, teto_da_cadeia)?;
                (nome, valor)
            };
            algum_campo = true;
            gasto = gasto.saturating_add(ocupa(nome.len(), valor.len()));
            if gasto > limite {
                passou = true;
            } else {
                campos.push(Campo { nome, valor });
            }
        }
        Ok((campos, passou))
    }
}

/// Escreve `valor` com prefixo de `prefixo` bits, com os bits de cima do
/// primeiro byte em `bandeiras`.
pub(crate) fn por_inteiro(valor: usize, prefixo: u32, bandeiras: u8, saida: &mut Vec<u8>) {
    let maximo = (1usize << prefixo) - 1;
    if valor < maximo {
        saida.push(bandeiras | valor as u8);
        return;
    }
    saida.push(bandeiras | maximo as u8);
    let mut resto = valor - maximo;
    while resto >= 0x80 {
        saida.push((resto & 0x7f) as u8 | 0x80);
        resto >>= 7;
    }
    saida.push(resto as u8);
}

/// Escreve uma cadeia: em Huffman quando fica menor.
fn por_cadeia(bytes: &[u8], saida: &mut Vec<u8>) {
    let em_huffman = huffman::tamanho(bytes);
    if em_huffman < bytes.len() {
        por_inteiro(em_huffman, 7, 0x80, saida);
        huffman::codificar(bytes, saida);
    } else {
        por_inteiro(bytes.len(), 7, 0, saida);
        saida.extend_from_slice(bytes);
    }
}

/// Como um campo vai no bloco de um pedido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Representacao {
    /// Sem entrar na tabela de ninguém.
    SemIndexar,
    /// Sem entrar, e marcado para que ninguém no caminho o indexe.
    NuncaIndexar,
}

/// O codificador dos pedidos: sem estado, porque nada entra na tabela
/// dinâmica do servidor — ver o cabeçalho do módulo.
pub(crate) struct Codificador;

impl Codificador {
    /// Acrescenta o campo `nome: valor` ao bloco `saida`. O nome já vem em
    /// minúsculas.
    pub fn campo(nome: &str, valor: &[u8], como: Representacao, saida: &mut Vec<u8>) {
        if como == Representacao::SemIndexar
            && let Some(i) = ESTATICA
                .iter()
                .position(|&(n, v)| n == nome && v.as_bytes() == valor)
        {
            por_inteiro(i + 1, 7, 0x80, saida);
            return;
        }
        let bandeiras = match como {
            Representacao::SemIndexar => 0x00,
            Representacao::NuncaIndexar => 0x10,
        };
        match ESTATICA.iter().position(|&(n, _)| n == nome) {
            Some(i) => por_inteiro(i + 1, 4, bandeiras, saida),
            None => {
                por_inteiro(0, 4, bandeiras, saida);
                por_cadeia(nome.as_bytes(), saida);
            }
        }
        por_cadeia(valor, saida);
    }
}

/// A tabela estática (RFC 7541, Apêndice A), transcrita de duas
/// implementações independentes e conferida entre elas.
pub(crate) const ESTATICA: [(&str, &str); 61] = [
    (":authority", ""),                   // 1
    (":method", "GET"),                   // 2
    (":method", "POST"),                  // 3
    (":path", "/"),                       // 4
    (":path", "/index.html"),             // 5
    (":scheme", "http"),                  // 6
    (":scheme", "https"),                 // 7
    (":status", "200"),                   // 8
    (":status", "204"),                   // 9
    (":status", "206"),                   // 10
    (":status", "304"),                   // 11
    (":status", "400"),                   // 12
    (":status", "404"),                   // 13
    (":status", "500"),                   // 14
    ("accept-charset", ""),               // 15
    ("accept-encoding", "gzip, deflate"), // 16
    ("accept-language", ""),              // 17
    ("accept-ranges", ""),                // 18
    ("accept", ""),                       // 19
    ("access-control-allow-origin", ""),  // 20
    ("age", ""),                          // 21
    ("allow", ""),                        // 22
    ("authorization", ""),                // 23
    ("cache-control", ""),                // 24
    ("content-disposition", ""),          // 25
    ("content-encoding", ""),             // 26
    ("content-language", ""),             // 27
    ("content-length", ""),               // 28
    ("content-location", ""),             // 29
    ("content-range", ""),                // 30
    ("content-type", ""),                 // 31
    ("cookie", ""),                       // 32
    ("date", ""),                         // 33
    ("etag", ""),                         // 34
    ("expect", ""),                       // 35
    ("expires", ""),                      // 36
    ("from", ""),                         // 37
    ("host", ""),                         // 38
    ("if-match", ""),                     // 39
    ("if-modified-since", ""),            // 40
    ("if-none-match", ""),                // 41
    ("if-range", ""),                     // 42
    ("if-unmodified-since", ""),          // 43
    ("last-modified", ""),                // 44
    ("link", ""),                         // 45
    ("location", ""),                     // 46
    ("max-forwards", ""),                 // 47
    ("proxy-authenticate", ""),           // 48
    ("proxy-authorization", ""),          // 49
    ("range", ""),                        // 50
    ("referer", ""),                      // 51
    ("refresh", ""),                      // 52
    ("retry-after", ""),                  // 53
    ("server", ""),                       // 54
    ("set-cookie", ""),                   // 55
    ("strict-transport-security", ""),    // 56
    ("transfer-encoding", ""),            // 57
    ("user-agent", ""),                   // 58
    ("vary", ""),                         // 59
    ("via", ""),                          // 60
    ("www-authenticate", ""),             // 61
];
