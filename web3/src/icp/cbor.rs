//! O CBOR das mensagens do IC: o subconjunto estrito que elas usam.
//!
//! O IC fala CBOR (RFC 8949) com um perfil pequeno (**especificação**,
//! *CBOR encoding of requests and responses* e *Encoding of certificates*):
//! inteiros sem sinal, bytes, texto, listas, mapas com chaves de texto e a
//! tag 55799 (*self-describe*) na frente. Este lado lê só isso:
//!
//! - **sem** inteiro negativo, ponto flutuante, valor simples (`true`,
//!   `null`…), *bignum* ou outra tag — nenhuma mensagem do ICP-1 os usa;
//! - listas e mapas de tamanho **indefinido** aceitos, terminados pelo
//!   `break`: a réplica escreve assim a resposta de uma consulta
//!   (**referência**: `HttpSignedQueryResponse`, em `dfinity/ic`, tem um
//!   `#[serde(flatten)]`, e o `serde_cbor` escreve o mapa sem tamanho).
//!   Cadeias de bytes ou de texto em pedaços, não: ninguém do lado de lá
//!   as escreve;
//! - inteiros e tamanhos **na forma mais curta**, que é a que o IC escreve
//!   (o `serde_cbor` do lado de lá não escreve outra);
//! - mapas com chave de texto, **sem chave repetida** (**especificação**:
//!   "Duplicate keys are prohibited");
//! - a tag 55799 só na frente do documento, e opcional: a especificação a
//!   escreve, e as implementações oficiais a aceitam ausente;
//! - **nada** depois do item.
//!
//! E com tetos, para que uma resposta hostil não gaste o que o programa
//! não tem: a profundidade (a pilha de um programa é de 64 KiB), o número
//! de itens (a memória) e o tamanho de um mapa. Uma lista ou um mapa que
//! anuncia mais itens do que os bytes que restam é recusado antes de
//! qualquer reserva de memória.
//!
//! Um valor lido empresta os bytes da entrada: nada é copiado.

use alloc::vec::Vec;
use core::fmt;

/// A tag *self-describe* — **especificação**: as mensagens são
/// `55799(…)`.
pub const TAG_AUTODESCRITA: u64 = 55799;

/// Um item lido.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Valor<'a> {
    /// Um inteiro sem sinal.
    Nat(u64),
    /// Uma cadeia de bytes.
    Bytes(&'a [u8]),
    /// Uma cadeia de texto, já conferida como UTF-8.
    Texto(&'a str),
    /// Uma lista.
    Lista(Vec<Valor<'a>>),
    /// Um mapa com chaves de texto, na ordem em que vieram.
    Mapa(Vec<(&'a str, Valor<'a>)>),
}

impl<'a> Valor<'a> {
    /// O inteiro, se for um.
    pub fn nat(&self) -> Option<u64> {
        match self {
            Valor::Nat(n) => Some(*n),
            _ => None,
        }
    }

    /// Os bytes, se for uma cadeia de bytes.
    pub fn bytes(&self) -> Option<&'a [u8]> {
        match self {
            Valor::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// O texto, se for um.
    pub fn texto(&self) -> Option<&'a str> {
        match self {
            Valor::Texto(t) => Some(t),
            _ => None,
        }
    }

    /// Os itens, se for uma lista.
    pub fn lista(&self) -> Option<&[Valor<'a>]> {
        match self {
            Valor::Lista(l) => Some(l),
            _ => None,
        }
    }

    /// Os pares, se for um mapa.
    pub fn mapa(&self) -> Option<&[(&'a str, Valor<'a>)]> {
        match self {
            Valor::Mapa(m) => Some(m),
            _ => None,
        }
    }

    /// O valor de uma chave, se for um mapa que a tem.
    pub fn campo(&self, chave: &str) -> Option<&Valor<'a>> {
        self.mapa()?
            .iter()
            .find(|(k, _)| *k == chave)
            .map(|(_, v)| v)
    }
}

/// Por que um documento não se lê.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// Acabou no meio de um item.
    Truncado,
    /// Sobraram bytes depois do item.
    Sobra,
    /// Um tipo fora do perfil: inteiro negativo, ponto flutuante, valor
    /// simples, ou uma tag que não a 55799 na frente.
    TipoProibido,
    /// Uma cadeia de bytes ou de texto de tamanho indefinido.
    Indefinido,
    /// Um inteiro ou um tamanho fora da forma mais curta, ou um dos
    /// valores reservados do byte inicial.
    ForaDaForma,
    /// Uma chave de mapa que não é texto.
    ChaveNaoTexto,
    /// Uma chave repetida no mesmo mapa.
    ChaveRepetida,
    /// Um texto que não é UTF-8.
    Utf8,
    /// Mais fundo que o teto.
    Profundo,
    /// Mais itens, ou um mapa maior, que o teto.
    Grande,
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Erro::Truncado => "cbor truncado",
            Erro::Sobra => "bytes depois do item cbor",
            Erro::TipoProibido => "tipo cbor fora do perfil do IC",
            Erro::Indefinido => "cadeia cbor de tamanho indefinido",
            Erro::ForaDaForma => "inteiro cbor fora da forma mais curta",
            Erro::ChaveNaoTexto => "chave de mapa cbor que nao e texto",
            Erro::ChaveRepetida => "chave repetida num mapa cbor",
            Erro::Utf8 => "texto cbor que nao e utf-8",
            Erro::Profundo => "cbor mais fundo que o teto",
            Erro::Grande => "cbor com mais itens que o teto",
        })
    }
}

/// Os tetos de uma leitura.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tetos {
    /// Quantas listas e mapas, um dentro do outro.
    pub profundidade: usize,
    /// Quantos itens no documento inteiro, contando listas e mapas.
    pub itens: usize,
    /// Quantos pares num mapa.
    pub pares: usize,
}

/// Os tetos das mensagens do ICP-1. A árvore de um certificado de
/// `read_state` com as chaves dos nós de uma sub-rede da mainnet (umas 50
/// sub-redes, uns 40 nós) tem por volta de 30 níveis e uns poucos milhares
/// de itens; os mapas do IC têm menos de dez chaves.
pub const TETOS: Tetos = Tetos {
    profundidade: 64,
    itens: 16_384,
    pares: 64,
};

/// Quantos itens uma lista reserva antes de lê-los.
const RESERVA: usize = 16;

/// Lê um documento: a tag 55799 opcional na frente, um item, e mais nada.
pub fn ler(entrada: &[u8]) -> Result<Valor<'_>, Erro> {
    ler_com(entrada, TETOS)
}

/// [`ler`] com outros tetos.
pub fn ler_com(entrada: &[u8], tetos: Tetos) -> Result<Valor<'_>, Erro> {
    let mut l = Leitor {
        entrada,
        pos: 0,
        itens: 0,
        tetos,
    };
    // A tag na frente, uma vez só.
    if l.olhar()? >> 5 == 6 {
        let (_, tag) = l.cabeca()?;
        if tag != TAG_AUTODESCRITA {
            return Err(Erro::TipoProibido);
        }
    }
    let v = l.item(0)?;
    if l.pos != entrada.len() {
        return Err(Erro::Sobra);
    }
    Ok(v)
}

struct Leitor<'a> {
    entrada: &'a [u8],
    pos: usize,
    itens: usize,
    tetos: Tetos,
}

impl<'a> Leitor<'a> {
    fn resto(&self) -> usize {
        self.entrada.len() - self.pos
    }

    fn olhar(&self) -> Result<u8, Erro> {
        self.entrada.get(self.pos).copied().ok_or(Erro::Truncado)
    }

    fn tomar(&mut self, n: usize) -> Result<&'a [u8], Erro> {
        if n > self.resto() {
            return Err(Erro::Truncado);
        }
        let fatia = &self.entrada[self.pos..self.pos + n];
        self.pos += n;
        Ok(fatia)
    }

    /// O tipo maior e o argumento do cabeçalho, na forma mais curta.
    fn cabeca(&mut self) -> Result<(u8, u64), Erro> {
        let inicial = self.tomar(1)?[0];
        let maior = inicial >> 5;
        let info = inicial & 0x1f;
        let (valor, piso) = match info {
            0..=23 => return Ok((maior, u64::from(info))),
            24 => (u64::from(self.tomar(1)?[0]), 24),
            25 => {
                let b = self.tomar(2)?;
                (u64::from(u16::from_be_bytes([b[0], b[1]])), 0x100)
            }
            26 => {
                let b = self.tomar(4)?;
                (
                    u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
                    0x1_0000,
                )
            }
            27 => {
                let b = self.tomar(8)?;
                let mut x = [0u8; 8];
                x.copy_from_slice(b);
                (u64::from_be_bytes(x), 0x1_0000_0000)
            }
            31 if (2..=5).contains(&maior) => return Err(Erro::Indefinido),
            // 28 a 30 são reservados; 31 fora das coleções é o `break` ou
            // o indefinido de um tipo fora do perfil.
            _ => return Err(Erro::ForaDaForma),
        };
        if valor < piso {
            return Err(Erro::ForaDaForma);
        }
        Ok((maior, valor))
    }

    /// Um tamanho que cabe nos bytes que restam: cada item ocupa ao menos
    /// um byte, então um tamanho maior que o resto já é truncado.
    fn tamanho(&self, n: u64, bytes_por_item: usize) -> Result<usize, Erro> {
        let n = usize::try_from(n).map_err(|_| Erro::Truncado)?;
        match n.checked_mul(bytes_por_item) {
            Some(minimo) if minimo <= self.resto() => Ok(n),
            _ => Err(Erro::Truncado),
        }
    }

    fn contar(&mut self) -> Result<(), Erro> {
        self.itens += 1;
        if self.itens > self.tetos.itens {
            return Err(Erro::Grande);
        }
        Ok(())
    }

    fn item(&mut self, nivel: usize) -> Result<Valor<'a>, Erro> {
        self.contar()?;
        // 1: negativo; 6: uma tag fora da frente; 7: simples, flutuante e
        // o `break` fora de uma coleção indefinida.
        let inicial = self.olhar()?;
        if matches!(inicial >> 5, 1 | 6 | 7) {
            return Err(Erro::TipoProibido);
        }
        if inicial == 0x9f || inicial == 0xbf {
            self.pos += 1;
            return self.indefinida(inicial == 0xbf, nivel);
        }
        let (maior, arg) = self.cabeca()?;
        match maior {
            0 => Ok(Valor::Nat(arg)),
            2 => {
                let n = self.tamanho(arg, 1)?;
                Ok(Valor::Bytes(self.tomar(n)?))
            }
            3 => {
                let n = self.tamanho(arg, 1)?;
                let b = self.tomar(n)?;
                core::str::from_utf8(b)
                    .map(Valor::Texto)
                    .map_err(|_| Erro::Utf8)
            }
            4 => {
                if nivel >= self.tetos.profundidade {
                    return Err(Erro::Profundo);
                }
                let n = self.tamanho(arg, 1)?;
                if n > self.tetos.itens {
                    return Err(Erro::Grande);
                }
                // A reserva cresce com os itens lidos, e não com o tamanho
                // anunciado: listas aninhadas que anunciam milhares de itens
                // cada uma reservariam a soma antes do primeiro.
                let mut itens = Vec::with_capacity(n.min(RESERVA));
                for _ in 0..n {
                    itens.push(self.item(nivel + 1)?);
                }
                Ok(Valor::Lista(itens))
            }
            5 => {
                if nivel >= self.tetos.profundidade {
                    return Err(Erro::Profundo);
                }
                let n = self.tamanho(arg, 2)?;
                if n > self.tetos.pares {
                    return Err(Erro::Grande);
                }
                let mut pares: Vec<(&'a str, Valor<'a>)> = Vec::with_capacity(n);
                for _ in 0..n {
                    let chave = match self.item(nivel + 1)? {
                        Valor::Texto(t) => t,
                        _ => return Err(Erro::ChaveNaoTexto),
                    };
                    if pares.iter().any(|(k, _)| *k == chave) {
                        return Err(Erro::ChaveRepetida);
                    }
                    let valor = self.item(nivel + 1)?;
                    pares.push((chave, valor));
                }
                Ok(Valor::Mapa(pares))
            }
            _ => Err(Erro::TipoProibido),
        }
    }

    /// Uma lista ou um mapa de tamanho indefinido: os itens até o `break`
    /// (`0xff`), com os mesmos tetos.
    fn indefinida(&mut self, mapa: bool, nivel: usize) -> Result<Valor<'a>, Erro> {
        if nivel >= self.tetos.profundidade {
            return Err(Erro::Profundo);
        }
        let mut itens = Vec::new();
        let mut pares: Vec<(&'a str, Valor<'a>)> = Vec::new();
        loop {
            if self.olhar()? == 0xff {
                self.pos += 1;
                break;
            }
            if !mapa {
                itens.push(self.item(nivel + 1)?);
                continue;
            }
            if pares.len() == self.tetos.pares {
                return Err(Erro::Grande);
            }
            let chave = match self.item(nivel + 1)? {
                Valor::Texto(t) => t,
                _ => return Err(Erro::ChaveNaoTexto),
            };
            if pares.iter().any(|(k, _)| *k == chave) {
                return Err(Erro::ChaveRepetida);
            }
            let valor = self.item(nivel + 1)?;
            pares.push((chave, valor));
        }
        Ok(if mapa {
            Valor::Mapa(pares)
        } else {
            Valor::Lista(itens)
        })
    }
}

/// Escreve CBOR na forma mais curta — o que os envelopes dos pedidos
/// precisam, e nada mais.
#[derive(Default)]
pub struct Escritor {
    saida: Vec<u8>,
}

impl Escritor {
    /// Um escritor vazio.
    pub fn novo() -> Escritor {
        Escritor::default()
    }

    fn cabeca(&mut self, maior: u8, valor: u64) {
        let m = maior << 5;
        if valor < 24 {
            self.saida.push(m | valor as u8);
        } else if valor <= 0xff {
            self.saida.extend_from_slice(&[m | 24, valor as u8]);
        } else if valor <= 0xffff {
            self.saida.push(m | 25);
            self.saida.extend_from_slice(&(valor as u16).to_be_bytes());
        } else if valor <= 0xffff_ffff {
            self.saida.push(m | 26);
            self.saida.extend_from_slice(&(valor as u32).to_be_bytes());
        } else {
            self.saida.push(m | 27);
            self.saida.extend_from_slice(&valor.to_be_bytes());
        }
    }

    /// A tag 55799.
    pub fn autodescrita(&mut self) {
        self.cabeca(6, TAG_AUTODESCRITA);
    }

    /// Um inteiro sem sinal.
    pub fn nat(&mut self, n: u64) {
        self.cabeca(0, n);
    }

    /// Uma cadeia de bytes.
    pub fn bytes(&mut self, b: &[u8]) {
        self.cabeca(2, b.len() as u64);
        self.saida.extend_from_slice(b);
    }

    /// Uma cadeia de texto.
    pub fn texto(&mut self, t: &str) {
        self.cabeca(3, t.len() as u64);
        self.saida.extend_from_slice(t.as_bytes());
    }

    /// O começo de uma lista de `n` itens, que vêm a seguir.
    pub fn lista(&mut self, n: usize) {
        self.cabeca(4, n as u64);
    }

    /// O começo de um mapa de `n` pares, que vêm a seguir, chave e valor.
    pub fn mapa(&mut self, n: usize) {
        self.cabeca(5, n as u64);
    }

    /// Os bytes escritos.
    pub fn terminar(self) -> Vec<u8> {
        self.saida
    }
}

#[cfg(test)]
mod testes;
