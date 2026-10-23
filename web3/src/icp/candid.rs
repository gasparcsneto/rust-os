//! O Candid: a tabela de tipos inteira, os valores de um subconjunto —
//! **especificação**: `dfinity/candid`, `spec/Candid.md`, *Binary Format*.
//!
//! Uma mensagem é `DIDL`, a tabela de tipos (`T*`), os tipos dos
//! argumentos (`I*`) e os valores (`M`). Este lado:
//!
//! - lê e confere a **tabela inteira**, com todos os tipos que a
//!   especificação define — `opt`, `vec`, `record`, `variant`, `func`,
//!   `service` e os tipos futuros (opcode menor que -24, que trazem o
//!   próprio tamanho). Uma referência fora da tabela, um tipo primitivo
//!   como entrada, campos fora de ordem ou repetidos, um método de serviço
//!   que não é `func`: recusados;
//! - decodifica os **valores** de `null`, `bool`, `nat`, `int`,
//!   `nat8`–`nat64`, `int8`–`int64`, `text`, `reserved`, `principal`,
//!   `opt`, `vec` (com `vec nat8` como `blob`), `record` e `variant`. Os de
//!   `float32`, `float64`, `func`, `service`, de um tipo futuro e o
//!   principal por referência opaca são recusados **pelo nome**; o de
//!   `empty` não existe;
//! - **não** faz a coerção para um tipo esperado: devolve os valores nos
//!   tipos que vieram na mensagem, e quem chama decide o que fazer com eles;
//! - mede o que gasta, como a especificação recomenda ("self-meter"): um
//!   teto de profundidade (a pilha), de valores (a memória e o tempo — um
//!   `vec null` de 2^60 itens ocupa três bytes) e de tamanho da tabela.
//!   Um `vec` que anuncia mais itens do que o orçamento recusa antes de
//!   reservar memória;
//! - um `nat` cabe em 128 bits e um `int` também, com sinal: além disso,
//!   recusa ([`Erro::Transborda`]);
//! - não aceita bytes depois dos valores.
//!
//! A codificação é a de um subconjunto menor: os valores que se escrevem
//! sem tipo de fora — os primitivos, `principal` e `blob`. É o que um
//! argumento do ICP-1 precisa.
//!
//! Com o tipo dado ([`codificar_com_tipos`]), escreve também `opt`, `vec`,
//! `record` e `variant` — um `opt` vazio, um `vec` vazio e o caso de um
//! `variant` só se escrevem com o tipo —: é o que o argumento de um ledger
//! precisa (ICP-4d). Os campos vão pelo id do nome ([`id_do_campo`]), em
//! ordem crescente, e cada composto entra uma vez na tabela. O que a
//! leitura daqui recusaria ([`TETOS`]) também não se escreve.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::principal::{self, Principal};

/// A mágica do começo.
pub const MAGICA: &[u8; 4] = b"DIDL";

/// Um tipo primitivo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Primitivo {
    /// `null`.
    Null,
    /// `bool`.
    Bool,
    /// `nat`.
    Nat,
    /// `int`.
    Int,
    /// `nat8`.
    Nat8,
    /// `nat16`.
    Nat16,
    /// `nat32`.
    Nat32,
    /// `nat64`.
    Nat64,
    /// `int8`.
    Int8,
    /// `int16`.
    Int16,
    /// `int32`.
    Int32,
    /// `int64`.
    Int64,
    /// `float32`.
    Float32,
    /// `float64`.
    Float64,
    /// `text`.
    Text,
    /// `reserved`.
    Reserved,
    /// `empty`.
    Empty,
    /// `principal`.
    Principal,
}

impl Primitivo {
    const TODOS: [Primitivo; 18] = [
        Primitivo::Null,
        Primitivo::Bool,
        Primitivo::Nat,
        Primitivo::Int,
        Primitivo::Nat8,
        Primitivo::Nat16,
        Primitivo::Nat32,
        Primitivo::Nat64,
        Primitivo::Int8,
        Primitivo::Int16,
        Primitivo::Int32,
        Primitivo::Int64,
        Primitivo::Float32,
        Primitivo::Float64,
        Primitivo::Text,
        Primitivo::Reserved,
        Primitivo::Empty,
        Primitivo::Principal,
    ];

    /// O opcode — **especificação**, `T(<primtype>)`.
    pub const fn opcode(self) -> i64 {
        match self {
            Primitivo::Null => -1,
            Primitivo::Bool => -2,
            Primitivo::Nat => -3,
            Primitivo::Int => -4,
            Primitivo::Nat8 => -5,
            Primitivo::Nat16 => -6,
            Primitivo::Nat32 => -7,
            Primitivo::Nat64 => -8,
            Primitivo::Int8 => -9,
            Primitivo::Int16 => -10,
            Primitivo::Int32 => -11,
            Primitivo::Int64 => -12,
            Primitivo::Float32 => -13,
            Primitivo::Float64 => -14,
            Primitivo::Text => -15,
            Primitivo::Reserved => -16,
            Primitivo::Empty => -17,
            Primitivo::Principal => -24,
        }
    }

    fn de_opcode(op: i64) -> Option<Primitivo> {
        Primitivo::TODOS.into_iter().find(|p| p.opcode() == op)
    }

    /// O nome, como na especificação.
    pub const fn nome(self) -> &'static str {
        match self {
            Primitivo::Null => "null",
            Primitivo::Bool => "bool",
            Primitivo::Nat => "nat",
            Primitivo::Int => "int",
            Primitivo::Nat8 => "nat8",
            Primitivo::Nat16 => "nat16",
            Primitivo::Nat32 => "nat32",
            Primitivo::Nat64 => "nat64",
            Primitivo::Int8 => "int8",
            Primitivo::Int16 => "int16",
            Primitivo::Int32 => "int32",
            Primitivo::Int64 => "int64",
            Primitivo::Float32 => "float32",
            Primitivo::Float64 => "float64",
            Primitivo::Text => "text",
            Primitivo::Reserved => "reserved",
            Primitivo::Empty => "empty",
            Primitivo::Principal => "principal",
        }
    }
}

/// Uma referência a um tipo: um primitivo, ou uma entrada da tabela —
/// **especificação**, `I(<datatype>)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ref {
    /// Um primitivo, pelo opcode.
    Primitivo(Primitivo),
    /// Uma entrada da tabela.
    Tabela(usize),
}

/// Uma entrada da tabela de tipos.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Composto {
    /// `opt t`.
    Opt(Ref),
    /// `vec t`.
    Vec(Ref),
    /// `record { id: t; … }`, os ids em ordem crescente.
    Record(Vec<(u32, Ref)>),
    /// `variant { id: t; … }`, os ids em ordem crescente.
    Variant(Vec<(u32, Ref)>),
    /// `func (…) -> (…)`: lida e conferida; o valor é recusado.
    Func,
    /// `service { … }`: lido e conferido; o valor é recusado. Os tipos dos
    /// métodos, que têm de ser `func`.
    Service(Vec<Ref>),
    /// Um tipo futuro, pelo opcode: pulado; o valor é recusado.
    Futuro(i64),
}

/// Um valor decodificado, no tipo em que veio.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Valor {
    /// `null`.
    Null,
    /// `bool`.
    Bool(bool),
    /// `nat`, até 128 bits.
    Nat(u128),
    /// `int`, até 128 bits com sinal.
    Int(i128),
    /// `nat8`.
    Nat8(u8),
    /// `nat16`.
    Nat16(u16),
    /// `nat32`.
    Nat32(u32),
    /// `nat64`.
    Nat64(u64),
    /// `int8`.
    Int8(i8),
    /// `int16`.
    Int16(i16),
    /// `int32`.
    Int32(i32),
    /// `int64`.
    Int64(i64),
    /// `text`.
    Texto(String),
    /// `reserved`: o valor não carrega nada.
    Reservado,
    /// `principal`, pela forma transparente.
    Principal(Principal),
    /// `opt t`.
    Opt(Option<Box<Valor>>),
    /// `vec t`, de um `t` que não é `nat8`.
    Vec(Vec<Valor>),
    /// `vec nat8`.
    Blob(Vec<u8>),
    /// `record`, os campos pelo id, na ordem do tipo.
    Record(Vec<(u32, Valor)>),
    /// `variant`: o id do campo escolhido e o valor dele.
    Variant(u32, Box<Valor>),
}

/// Por que uma mensagem não se lê, ou um valor não se escreve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// Sem `DIDL` no começo.
    Magica,
    /// Acabou no meio.
    Truncado,
    /// Bytes depois dos valores.
    Sobra,
    /// Um LEB128 que não cabe: um tamanho em 64 bits, um `nat` ou um
    /// `int` em 128.
    Transborda,
    /// Um opcode que não vale onde está: um primitivo como entrada da
    /// tabela, ou um composto como referência.
    Tipo,
    /// Uma referência fora da tabela, ou um método de serviço que não é
    /// `func`.
    Referencia,
    /// Um id de campo repetido, fora de ordem ou maior que 32 bits.
    Campo,
    /// Uma anotação de `func` desconhecida.
    Anotacao,
    /// Um nome de método fora de ordem, repetido, ou que não é UTF-8.
    Metodo,
    /// Um `bool` que não é 0 nem 1.
    Bool,
    /// Um `opt` que não começa por 0 nem por 1.
    Opt,
    /// Um `variant` com um índice além dos campos.
    Variante,
    /// Um `text` que não é UTF-8.
    Utf8,
    /// Um `principal` fora da forma, ou com mais de 29 bytes.
    PrincipalForma,
    /// Um valor do tipo `empty`, que não existe.
    Empty,
    /// Um valor de um tipo fora do subconjunto, pelo nome.
    Recusado(&'static str),
    /// Mais fundo que o teto.
    Profundo,
    /// Maior que um teto.
    Grande,
    /// Um valor que [`codificar`] não escreve sem um tipo de fora.
    NaoCodificavel,
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Erro::Magica => f.write_str("candid sem DIDL"),
            Erro::Truncado => f.write_str("candid truncado"),
            Erro::Sobra => f.write_str("bytes depois dos valores candid"),
            Erro::Transborda => f.write_str("leb128 candid que transborda"),
            Erro::Tipo => f.write_str("opcode candid fora do lugar"),
            Erro::Referencia => f.write_str("referencia candid fora da tabela"),
            Erro::Campo => f.write_str("campo candid repetido ou fora de ordem"),
            Erro::Anotacao => f.write_str("anotacao de func desconhecida"),
            Erro::Metodo => f.write_str("metodo de service fora de ordem"),
            Erro::Bool => f.write_str("bool candid fora de 0 e 1"),
            Erro::Opt => f.write_str("opt candid fora de 0 e 1"),
            Erro::Variante => f.write_str("indice de variant alem dos campos"),
            Erro::Utf8 => f.write_str("text candid que nao e utf-8"),
            Erro::PrincipalForma => f.write_str("principal candid fora da forma"),
            Erro::Empty => f.write_str("valor do tipo empty"),
            Erro::Recusado(nome) => write!(f, "valor candid de {nome}: fora do subconjunto"),
            Erro::Profundo => f.write_str("candid mais fundo que o teto"),
            Erro::Grande => f.write_str("candid maior que o teto"),
            Erro::NaoCodificavel => f.write_str("valor que nao se codifica sem tipo"),
        }
    }
}

/// Os tetos de uma decodificação.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tetos {
    /// Entradas da tabela de tipos.
    pub tabela: usize,
    /// Campos de um `record` ou `variant`, argumentos e resultados de uma
    /// `func`, métodos de um `service`.
    pub campos: usize,
    /// Argumentos da mensagem.
    pub argumentos: usize,
    /// `opt`, `vec`, `record` e `variant`, um dentro do outro.
    pub profundidade: usize,
    /// Valores decodificados, contando cada item de cada `vec`.
    pub valores: usize,
}

/// Os tetos do ICP-1: folgados para as respostas de um canister comum, e
/// apertados para a pilha de 64 KiB e a memória de um programa.
pub const TETOS: Tetos = Tetos {
    tabela: 256,
    campos: 256,
    argumentos: 64,
    profundidade: 32,
    valores: 16_384,
};

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn resto(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn byte(&mut self) -> Result<u8, Erro> {
        let b = *self.bytes.get(self.pos).ok_or(Erro::Truncado)?;
        self.pos += 1;
        Ok(b)
    }

    fn tomar(&mut self, n: usize) -> Result<&'a [u8], Erro> {
        if n > self.resto() {
            return Err(Erro::Truncado);
        }
        let fatia = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(fatia)
    }

    fn fixo<const N: usize>(&mut self) -> Result<[u8; N], Erro> {
        let mut b = [0u8; N];
        b.copy_from_slice(self.tomar(N)?);
        Ok(b)
    }

    /// Um LEB128 sem sinal de até 128 bits: no 19º byte só cabem dois.
    fn nat(&mut self) -> Result<u128, Erro> {
        let mut valor: u128 = 0;
        let mut deslocamento = 0u32;
        loop {
            let b = self.byte()?;
            let parte = u128::from(b & 0x7f);
            if deslocamento == 126 {
                if b & 0x80 != 0 || parte > 3 {
                    return Err(Erro::Transborda);
                }
                return Ok(valor | parte << 126);
            }
            valor |= parte << deslocamento;
            if b & 0x80 == 0 {
                return Ok(valor);
            }
            deslocamento += 7;
        }
    }

    /// Um LEB128 com sinal de até 128 bits: no 19º byte, dois bits de
    /// valor e o resto é o sinal.
    fn int(&mut self) -> Result<i128, Erro> {
        let mut valor: i128 = 0;
        let mut deslocamento = 0u32;
        loop {
            let b = self.byte()?;
            let parte = b & 0x7f;
            if deslocamento == 126 {
                if b & 0x80 != 0 || !matches!(parte, 0x00 | 0x01 | 0x7e | 0x7f) {
                    return Err(Erro::Transborda);
                }
                return Ok(valor | i128::from(parte & 0x03) << 126);
            }
            valor |= i128::from(parte) << deslocamento;
            deslocamento += 7;
            if b & 0x80 == 0 {
                if b & 0x40 != 0 {
                    valor |= -1i128 << deslocamento;
                }
                return Ok(valor);
            }
        }
    }

    /// Um tamanho ou um id: um LEB128 que cabe em 64 bits.
    fn tamanho(&mut self) -> Result<u64, Erro> {
        u64::try_from(self.nat()?).map_err(|_| Erro::Transborda)
    }

    /// Um tamanho de coisas que ocupam ao menos um byte cada.
    fn contagem(&mut self, teto: usize) -> Result<usize, Erro> {
        let n = self.tamanho()?;
        let n = usize::try_from(n).map_err(|_| Erro::Grande)?;
        if n > teto {
            return Err(Erro::Grande);
        }
        if n > self.resto() {
            return Err(Erro::Truncado);
        }
        Ok(n)
    }

    /// Um opcode ou uma referência: um LEB128 com sinal que cabe em 64
    /// bits.
    fn opcode(&mut self) -> Result<i64, Erro> {
        i64::try_from(self.int()?).map_err(|_| Erro::Transborda)
    }

    /// `I(<datatype>)`: um primitivo ou um índice da tabela.
    fn referencia(&mut self) -> Result<Ref, Erro> {
        let op = self.opcode()?;
        if op >= 0 {
            return Ok(Ref::Tabela(
                usize::try_from(op).map_err(|_| Erro::Referencia)?,
            ));
        }
        Primitivo::de_opcode(op)
            .map(Ref::Primitivo)
            .ok_or(Erro::Tipo)
    }

    /// Os campos de um `record` ou `variant`: ids estritamente crescentes,
    /// de 32 bits.
    fn campos(&mut self, teto: usize) -> Result<Vec<(u32, Ref)>, Erro> {
        let n = self.contagem(teto)?;
        let mut campos: Vec<(u32, Ref)> = Vec::with_capacity(n);
        for _ in 0..n {
            let id = u32::try_from(self.tamanho()?).map_err(|_| Erro::Campo)?;
            if campos.last().is_some_and(|(anterior, _)| *anterior >= id) {
                return Err(Erro::Campo);
            }
            campos.push((id, self.referencia()?));
        }
        Ok(campos)
    }

    /// Uma entrada da tabela: só tipos compostos.
    fn composto(&mut self, tetos: &Tetos) -> Result<Composto, Erro> {
        let op = self.opcode()?;
        Ok(match op {
            -18 => Composto::Opt(self.referencia()?),
            -19 => Composto::Vec(self.referencia()?),
            -20 => Composto::Record(self.campos(tetos.campos)?),
            -21 => Composto::Variant(self.campos(tetos.campos)?),
            -22 => {
                for _ in 0..2 {
                    let n = self.contagem(tetos.campos)?;
                    for _ in 0..n {
                        self.referencia()?;
                    }
                }
                let n = self.contagem(tetos.campos)?;
                for _ in 0..n {
                    if !matches!(self.byte()?, 1..=3) {
                        return Err(Erro::Anotacao);
                    }
                }
                Composto::Func
            }
            -23 => {
                let n = self.contagem(tetos.campos)?;
                let mut metodos = Vec::with_capacity(n);
                let mut anterior: Option<&[u8]> = None;
                for _ in 0..n {
                    let tamanho = self.contagem(usize::MAX)?;
                    let nome = self.tomar(tamanho)?;
                    if core::str::from_utf8(nome).is_err() || anterior.is_some_and(|a| a >= nome) {
                        return Err(Erro::Metodo);
                    }
                    anterior = Some(nome);
                    metodos.push(self.referencia()?);
                }
                Composto::Service(metodos)
            }
            op if op < -24 => {
                let tamanho = self.contagem(usize::MAX)?;
                self.tomar(tamanho)?;
                Composto::Futuro(op)
            }
            _ => return Err(Erro::Tipo),
        })
    }
}

/// Decodifica uma mensagem com os [`TETOS`].
pub fn decodificar(bytes: &[u8]) -> Result<Vec<Valor>, Erro> {
    decodificar_com(bytes, TETOS)
}

/// [`decodificar`] com outros tetos.
pub fn decodificar_com(bytes: &[u8], tetos: Tetos) -> Result<Vec<Valor>, Erro> {
    if !bytes.starts_with(MAGICA) {
        return Err(Erro::Magica);
    }
    let mut c = Cursor { bytes, pos: 4 };
    let n = c.contagem(tetos.tabela)?;
    let mut tabela = Vec::with_capacity(n);
    for _ in 0..n {
        tabela.push(c.composto(&tetos)?);
    }
    let dentro = |r: &Ref| match r {
        Ref::Tabela(i) => *i < n,
        Ref::Primitivo(_) => true,
    };
    for entrada in &tabela {
        let valida = match entrada {
            Composto::Opt(r) | Composto::Vec(r) => dentro(r),
            Composto::Record(campos) | Composto::Variant(campos) => {
                campos.iter().all(|(_, r)| dentro(r))
            }
            Composto::Service(metodos) => metodos.iter().all(
                |r| matches!(r, Ref::Tabela(i) if matches!(tabela.get(*i), Some(Composto::Func))),
            ),
            Composto::Func | Composto::Futuro(_) => true,
        };
        if !valida {
            return Err(Erro::Referencia);
        }
    }
    let m = c.contagem(tetos.argumentos)?;
    let mut tipos = Vec::with_capacity(m);
    for _ in 0..m {
        let r = c.referencia()?;
        if !dentro(&r) {
            return Err(Erro::Referencia);
        }
        tipos.push(r);
    }
    let mut d = Decodificador {
        tabela: &tabela,
        tetos,
        gastos: 0,
    };
    let mut valores = Vec::with_capacity(m);
    for tipo in tipos {
        valores.push(d.valor(&mut c, tipo, 0)?);
    }
    if c.resto() != 0 {
        return Err(Erro::Sobra);
    }
    Ok(valores)
}

struct Decodificador<'t> {
    tabela: &'t [Composto],
    tetos: Tetos,
    gastos: usize,
}

impl Decodificador<'_> {
    fn gastar(&mut self, n: usize) -> Result<(), Erro> {
        match self.gastos.checked_add(n) {
            Some(g) if g <= self.tetos.valores => {
                self.gastos = g;
                Ok(())
            }
            _ => Err(Erro::Grande),
        }
    }

    fn valor(&mut self, c: &mut Cursor<'_>, tipo: Ref, nivel: usize) -> Result<Valor, Erro> {
        self.gastar(1)?;
        let i = match tipo {
            Ref::Primitivo(p) => return primitivo(c, p),
            Ref::Tabela(i) => i,
        };
        if nivel >= self.tetos.profundidade {
            return Err(Erro::Profundo);
        }
        Ok(match &self.tabela[i] {
            Composto::Opt(t) => match c.byte()? {
                0 => Valor::Opt(None),
                1 => Valor::Opt(Some(Box::new(self.valor(c, *t, nivel + 1)?))),
                _ => return Err(Erro::Opt),
            },
            Composto::Vec(Ref::Primitivo(Primitivo::Nat8)) => {
                let n = c.contagem(usize::MAX)?;
                Valor::Blob(Vec::from(c.tomar(n)?))
            }
            Composto::Vec(t) => {
                let n = usize::try_from(c.tamanho()?).map_err(|_| Erro::Grande)?;
                // Cada item custa ao menos um, mesmo o de zero bytes.
                if n > self.tetos.valores - self.gastos {
                    return Err(Erro::Grande);
                }
                // A reserva cresce com os itens lidos: `vec`s aninhados que
                // anunciam o orçamento inteiro cada um não o reservam juntos.
                let mut itens = Vec::with_capacity(n.min(16));
                for _ in 0..n {
                    itens.push(self.valor(c, *t, nivel + 1)?);
                }
                Valor::Vec(itens)
            }
            Composto::Record(campos) => {
                let mut valores = Vec::with_capacity(campos.len());
                for (id, t) in campos {
                    valores.push((*id, self.valor(c, *t, nivel + 1)?));
                }
                Valor::Record(valores)
            }
            Composto::Variant(campos) => {
                let indice = usize::try_from(c.tamanho()?).map_err(|_| Erro::Variante)?;
                let (id, t) = *campos.get(indice).ok_or(Erro::Variante)?;
                Valor::Variant(id, Box::new(self.valor(c, t, nivel + 1)?))
            }
            Composto::Func => return Err(Erro::Recusado("func")),
            Composto::Service(_) => return Err(Erro::Recusado("service")),
            Composto::Futuro(_) => return Err(Erro::Recusado("tipo futuro")),
        })
    }
}

fn primitivo(c: &mut Cursor<'_>, p: Primitivo) -> Result<Valor, Erro> {
    Ok(match p {
        Primitivo::Null => Valor::Null,
        Primitivo::Bool => match c.byte()? {
            0 => Valor::Bool(false),
            1 => Valor::Bool(true),
            _ => return Err(Erro::Bool),
        },
        Primitivo::Nat => Valor::Nat(c.nat()?),
        Primitivo::Int => Valor::Int(c.int()?),
        Primitivo::Nat8 => Valor::Nat8(c.byte()?),
        Primitivo::Nat16 => Valor::Nat16(u16::from_le_bytes(c.fixo()?)),
        Primitivo::Nat32 => Valor::Nat32(u32::from_le_bytes(c.fixo()?)),
        Primitivo::Nat64 => Valor::Nat64(u64::from_le_bytes(c.fixo()?)),
        Primitivo::Int8 => Valor::Int8(i8::from_le_bytes(c.fixo()?)),
        Primitivo::Int16 => Valor::Int16(i16::from_le_bytes(c.fixo()?)),
        Primitivo::Int32 => Valor::Int32(i32::from_le_bytes(c.fixo()?)),
        Primitivo::Int64 => Valor::Int64(i64::from_le_bytes(c.fixo()?)),
        Primitivo::Float32 | Primitivo::Float64 => return Err(Erro::Recusado(p.nome())),
        Primitivo::Text => {
            let n = c.contagem(usize::MAX)?;
            let b = c.tomar(n)?;
            Valor::Texto(String::from(
                core::str::from_utf8(b).map_err(|_| Erro::Utf8)?,
            ))
        }
        Primitivo::Reserved => Valor::Reservado,
        Primitivo::Empty => return Err(Erro::Empty),
        Primitivo::Principal => match c.byte()? {
            1 => {
                let n = c.tamanho()?;
                if n > principal::MAIOR as u64 {
                    return Err(Erro::PrincipalForma);
                }
                let n = n as usize;
                Valor::Principal(
                    Principal::de_bytes(c.tomar(n)?).map_err(|_| Erro::PrincipalForma)?,
                )
            }
            0 => return Err(Erro::Recusado("principal por referencia opaca")),
            _ => return Err(Erro::PrincipalForma),
        },
    })
}

fn escrever_nat(saida: &mut Vec<u8>, mut n: u128) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            saida.push(byte);
            return;
        }
        saida.push(byte | 0x80);
    }
}

fn escrever_int(saida: &mut Vec<u8>, mut n: i128) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if (n == 0 && byte & 0x40 == 0) || (n == -1 && byte & 0x40 != 0) {
            saida.push(byte);
            return;
        }
        saida.push(byte | 0x80);
    }
}

/// Codifica argumentos que se escrevem sem um tipo de fora: os
/// primitivos, `principal` e `blob` (`vec nat8`, a única entrada da tabela
/// que se escreve).
pub fn codificar(valores: &[Valor]) -> Result<Vec<u8>, Erro> {
    let mut saida = Vec::from(*MAGICA);
    let com_blob = valores.iter().any(|v| matches!(v, Valor::Blob(_)));
    if com_blob {
        // Uma entrada: `vec nat8`.
        escrever_nat(&mut saida, 1);
        escrever_int(&mut saida, -19);
        escrever_int(&mut saida, Primitivo::Nat8.opcode().into());
    } else {
        escrever_nat(&mut saida, 0);
    }
    escrever_nat(&mut saida, valores.len() as u128);
    for v in valores {
        let tipo: i128 = match v {
            Valor::Blob(_) => 0,
            Valor::Null => Primitivo::Null.opcode().into(),
            Valor::Bool(_) => Primitivo::Bool.opcode().into(),
            Valor::Nat(_) => Primitivo::Nat.opcode().into(),
            Valor::Int(_) => Primitivo::Int.opcode().into(),
            Valor::Nat8(_) => Primitivo::Nat8.opcode().into(),
            Valor::Nat16(_) => Primitivo::Nat16.opcode().into(),
            Valor::Nat32(_) => Primitivo::Nat32.opcode().into(),
            Valor::Nat64(_) => Primitivo::Nat64.opcode().into(),
            Valor::Int8(_) => Primitivo::Int8.opcode().into(),
            Valor::Int16(_) => Primitivo::Int16.opcode().into(),
            Valor::Int32(_) => Primitivo::Int32.opcode().into(),
            Valor::Int64(_) => Primitivo::Int64.opcode().into(),
            Valor::Texto(_) => Primitivo::Text.opcode().into(),
            Valor::Reservado => Primitivo::Reserved.opcode().into(),
            Valor::Principal(_) => Primitivo::Principal.opcode().into(),
            Valor::Opt(_) | Valor::Vec(_) | Valor::Record(_) | Valor::Variant(..) => {
                return Err(Erro::NaoCodificavel);
            }
        };
        escrever_int(&mut saida, tipo);
    }
    for v in valores {
        match v {
            Valor::Null | Valor::Reservado => {}
            Valor::Bool(b) => saida.push(u8::from(*b)),
            Valor::Nat(n) => escrever_nat(&mut saida, *n),
            Valor::Int(n) => escrever_int(&mut saida, *n),
            Valor::Nat8(n) => saida.push(*n),
            Valor::Nat16(n) => saida.extend_from_slice(&n.to_le_bytes()),
            Valor::Nat32(n) => saida.extend_from_slice(&n.to_le_bytes()),
            Valor::Nat64(n) => saida.extend_from_slice(&n.to_le_bytes()),
            Valor::Int8(n) => saida.extend_from_slice(&n.to_le_bytes()),
            Valor::Int16(n) => saida.extend_from_slice(&n.to_le_bytes()),
            Valor::Int32(n) => saida.extend_from_slice(&n.to_le_bytes()),
            Valor::Int64(n) => saida.extend_from_slice(&n.to_le_bytes()),
            Valor::Texto(t) => {
                escrever_nat(&mut saida, t.len() as u128);
                saida.extend_from_slice(t.as_bytes());
            }
            Valor::Principal(p) => {
                saida.push(1);
                escrever_nat(&mut saida, p.bytes().len() as u128);
                saida.extend_from_slice(p.bytes());
            }
            Valor::Blob(b) => {
                escrever_nat(&mut saida, b.len() as u128);
                saida.extend_from_slice(b);
            }
            Valor::Opt(_) | Valor::Vec(_) | Valor::Record(_) | Valor::Variant(..) => {
                return Err(Erro::NaoCodificavel);
            }
        }
    }
    Ok(saida)
}

/// O id de um campo de `record` ou `variant` pelo nome — **especificação**,
/// `idl_hash`: `h · 223 + b`, byte a byte do UTF-8, módulo 2^32.
pub fn id_do_campo(nome: &str) -> u32 {
    nome.bytes()
        .fold(0u32, |h, b| h.wrapping_mul(223).wrapping_add(u32::from(b)))
}

/// Um tipo, para escrever o que não se escreve sozinho — ver
/// [`codificar_com_tipos`]. Os campos de `record` e `variant` vão pelo id,
/// em qualquer ordem: a escrita os ordena.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tipo {
    /// Um primitivo.
    Primitivo(Primitivo),
    /// `opt t`.
    Opt(Box<Tipo>),
    /// `vec t`; `vec nat8` é o `blob`.
    Vec(Box<Tipo>),
    /// `record { id: t; … }`.
    Record(Vec<(u32, Tipo)>),
    /// `variant { id: t; … }`.
    Variant(Vec<(u32, Tipo)>),
}

impl From<Primitivo> for Tipo {
    fn from(p: Primitivo) -> Tipo {
        Tipo::Primitivo(p)
    }
}

impl Tipo {
    /// `opt t`.
    pub fn opt(t: impl Into<Tipo>) -> Tipo {
        Tipo::Opt(Box::new(t.into()))
    }

    /// `vec t`.
    pub fn vec(t: impl Into<Tipo>) -> Tipo {
        Tipo::Vec(Box::new(t.into()))
    }

    /// `blob`: `vec nat8`.
    pub fn blob() -> Tipo {
        Tipo::vec(Primitivo::Nat8)
    }

    /// `record`, com os campos pelo nome.
    pub fn record<'a>(campos: impl IntoIterator<Item = (&'a str, Tipo)>) -> Tipo {
        Tipo::Record(
            campos
                .into_iter()
                .map(|(nome, t)| (id_do_campo(nome), t))
                .collect(),
        )
    }

    /// `variant`, com os casos pelo nome.
    pub fn variant<'a>(casos: impl IntoIterator<Item = (&'a str, Tipo)>) -> Tipo {
        Tipo::Variant(
            casos
                .into_iter()
                .map(|(nome, t)| (id_do_campo(nome), t))
                .collect(),
        )
    }
}

impl Valor {
    /// O campo `nome` de um `record`, pelo id dele ([`id_do_campo`]).
    pub fn campo(&self, nome: &str) -> Option<&Valor> {
        let Valor::Record(campos) = self else {
            return None;
        };
        let id = id_do_campo(nome);
        campos.iter().find(|(i, _)| *i == id).map(|(_, v)| v)
    }

    /// O valor do caso `nome`, se este `variant` é ele.
    pub fn caso(&self, nome: &str) -> Option<&Valor> {
        match self {
            Valor::Variant(id, v) if *id == id_do_campo(nome) => Some(v),
            _ => None,
        }
    }
}

/// Por que um valor não se escreve no tipo dado — ver
/// [`codificar_com_tipos`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErroDaEscrita {
    /// O valor não é do tipo: outro primitivo, outro composto, um campo que
    /// falta ou que sobra, um caso que o `variant` não tem, um tipo sem
    /// valor (`empty`, os de ponto flutuante), ou tipos e valores em
    /// números diferentes.
    ForaDoTipo,
    /// Um id de campo repetido num `record` ou `variant` do tipo.
    CampoRepetido,
    /// Compostos, um dentro do outro, além do teto da leitura.
    Profundo,
    /// Argumentos ou entradas da tabela além do teto da leitura.
    Grande,
}

impl fmt::Display for ErroDaEscrita {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErroDaEscrita::ForaDoTipo => "valor candid fora do tipo",
            ErroDaEscrita::CampoRepetido => "campo candid repetido no tipo",
            ErroDaEscrita::Profundo => "tipo candid mais fundo que o teto",
            ErroDaEscrita::Grande => "candid maior que o teto",
        })
    }
}

/// Escreve `valores`, cada um no tipo de `tipos` na mesma posição: a tabela
/// com os compostos — cada um uma vez, os campos pelo id em ordem
/// crescente —, os tipos dos argumentos e os valores. Nada se escreve se um
/// valor não é do tipo.
pub fn codificar_com_tipos(tipos: &[Tipo], valores: &[Valor]) -> Result<Vec<u8>, ErroDaEscrita> {
    if tipos.len() != valores.len() {
        return Err(ErroDaEscrita::ForaDoTipo);
    }
    if tipos.len() > TETOS.argumentos {
        return Err(ErroDaEscrita::Grande);
    }
    let mut tabela = Tabela {
        entradas: Vec::new(),
    };
    let mut referencias = Vec::with_capacity(tipos.len());
    for t in tipos {
        // A leitura conta os compostos de cada argumento a partir dele.
        if profundidade(t) > TETOS.profundidade {
            return Err(ErroDaEscrita::Profundo);
        }
        referencias.push(tabela.referencia(t)?);
    }
    if tabela.entradas.len() > TETOS.tabela {
        return Err(ErroDaEscrita::Grande);
    }
    let mut saida = Vec::from(*MAGICA);
    escrever_nat(&mut saida, tabela.entradas.len() as u128);
    for (_, entrada) in &tabela.entradas {
        saida.extend_from_slice(entrada);
    }
    escrever_nat(&mut saida, referencias.len() as u128);
    for r in referencias {
        escrever_int(&mut saida, r.into());
    }
    let mut escrita = Escrita { saida, valores: 0 };
    for (t, v) in tipos.iter().zip(valores) {
        escrita.valor(t, v)?;
    }
    Ok(escrita.saida)
}

/// A tabela de tipos que se escreve: cada composto, com a entrada dele.
struct Tabela<'t> {
    entradas: Vec<(&'t Tipo, Vec<u8>)>,
}

impl<'t> Tabela<'t> {
    /// `I(t)`: o opcode de um primitivo, ou o índice do composto na tabela
    /// — posto nela, depois dos que ele usa, se ainda não estava.
    fn referencia(&mut self, t: &'t Tipo) -> Result<i64, ErroDaEscrita> {
        if let Tipo::Primitivo(p) = t {
            return Ok(p.opcode());
        }
        if let Some(i) = self.entradas.iter().position(|(x, _)| *x == t) {
            return Ok(i as i64);
        }
        let mut entrada = Vec::new();
        match t {
            Tipo::Opt(d) | Tipo::Vec(d) => {
                let r = self.referencia(d)?;
                escrever_int(
                    &mut entrada,
                    if matches!(t, Tipo::Opt(_)) { -18 } else { -19 },
                );
                escrever_int(&mut entrada, r.into());
            }
            Tipo::Record(campos) | Tipo::Variant(campos) => {
                if campos.len() > TETOS.campos {
                    return Err(ErroDaEscrita::Grande);
                }
                let campos = em_ordem(campos)?;
                escrever_int(
                    &mut entrada,
                    if matches!(t, Tipo::Record(_)) {
                        -20
                    } else {
                        -21
                    },
                );
                escrever_nat(&mut entrada, campos.len() as u128);
                for (id, tipo) in campos {
                    let r = self.referencia(tipo)?;
                    escrever_nat(&mut entrada, u128::from(*id));
                    escrever_int(&mut entrada, r.into());
                }
            }
            Tipo::Primitivo(_) => unreachable!("o primitivo voltou antes"),
        }
        self.entradas.push((t, entrada));
        Ok((self.entradas.len() - 1) as i64)
    }
}

/// Quantos compostos há, um dentro do outro, no caminho mais fundo de `t`.
fn profundidade(t: &Tipo) -> usize {
    match t {
        Tipo::Primitivo(_) => 0,
        Tipo::Opt(d) | Tipo::Vec(d) => 1 + profundidade(d),
        Tipo::Record(campos) | Tipo::Variant(campos) => {
            1 + campos
                .iter()
                .map(|(_, t)| profundidade(t))
                .max()
                .unwrap_or(0)
        }
    }
}

/// Os campos de um `record` ou `variant` pelo id, em ordem crescente; um
/// id repetido é recusado.
fn em_ordem(campos: &[(u32, Tipo)]) -> Result<Vec<&(u32, Tipo)>, ErroDaEscrita> {
    let mut ordem: Vec<&(u32, Tipo)> = campos.iter().collect();
    ordem.sort_by_key(|(id, _)| *id);
    if ordem.windows(2).any(|par| par[0].0 == par[1].0) {
        return Err(ErroDaEscrita::CampoRepetido);
    }
    Ok(ordem)
}

/// Os valores que se escrevem, contados como a leitura os conta: cada
/// valor um, cada item de um `vec` também, e o `blob` inteiro um.
struct Escrita {
    saida: Vec<u8>,
    valores: usize,
}

impl Escrita {
    /// `M(v : t)`: o valor no tipo, ou um erro se não é dele.
    fn valor(&mut self, t: &Tipo, v: &Valor) -> Result<(), ErroDaEscrita> {
        self.valores += 1;
        if self.valores > TETOS.valores {
            return Err(ErroDaEscrita::Grande);
        }
        let saida = &mut self.saida;
        match (t, v) {
            (Tipo::Primitivo(p), v) => escrever_primitivo(saida, *p, v),
            (Tipo::Opt(_), Valor::Opt(None)) => {
                saida.push(0);
                Ok(())
            }
            (Tipo::Opt(d), Valor::Opt(Some(x))) => {
                saida.push(1);
                self.valor(d, x)
            }
            (Tipo::Vec(d), Valor::Blob(b)) if **d == Tipo::Primitivo(Primitivo::Nat8) => {
                escrever_nat(saida, b.len() as u128);
                saida.extend_from_slice(b);
                Ok(())
            }
            (Tipo::Vec(d), Valor::Vec(itens)) => {
                escrever_nat(saida, itens.len() as u128);
                itens.iter().try_for_each(|x| self.valor(d, x))
            }
            (Tipo::Record(campos), Valor::Record(valores)) => {
                if valores.len() != campos.len() {
                    return Err(ErroDaEscrita::ForaDoTipo);
                }
                for (id, tipo) in em_ordem(campos)? {
                    let (_, x) = valores
                        .iter()
                        .find(|(i, _)| i == id)
                        .ok_or(ErroDaEscrita::ForaDoTipo)?;
                    self.valor(tipo, x)?;
                }
                Ok(())
            }
            (Tipo::Variant(casos), Valor::Variant(id, x)) => {
                let casos = em_ordem(casos)?;
                let indice = casos
                    .iter()
                    .position(|(c, _)| c == id)
                    .ok_or(ErroDaEscrita::ForaDoTipo)?;
                escrever_nat(saida, indice as u128);
                self.valor(&casos[indice].1, x)
            }
            _ => Err(ErroDaEscrita::ForaDoTipo),
        }
    }
}

/// O valor de um primitivo, se é dele.
fn escrever_primitivo(saida: &mut Vec<u8>, p: Primitivo, v: &Valor) -> Result<(), ErroDaEscrita> {
    match (p, v) {
        (Primitivo::Null, Valor::Null) | (Primitivo::Reserved, Valor::Reservado) => {}
        (Primitivo::Bool, Valor::Bool(b)) => saida.push(u8::from(*b)),
        (Primitivo::Nat, Valor::Nat(n)) => escrever_nat(saida, *n),
        (Primitivo::Int, Valor::Int(n)) => escrever_int(saida, *n),
        (Primitivo::Nat8, Valor::Nat8(n)) => saida.push(*n),
        (Primitivo::Nat16, Valor::Nat16(n)) => saida.extend_from_slice(&n.to_le_bytes()),
        (Primitivo::Nat32, Valor::Nat32(n)) => saida.extend_from_slice(&n.to_le_bytes()),
        (Primitivo::Nat64, Valor::Nat64(n)) => saida.extend_from_slice(&n.to_le_bytes()),
        (Primitivo::Int8, Valor::Int8(n)) => saida.extend_from_slice(&n.to_le_bytes()),
        (Primitivo::Int16, Valor::Int16(n)) => saida.extend_from_slice(&n.to_le_bytes()),
        (Primitivo::Int32, Valor::Int32(n)) => saida.extend_from_slice(&n.to_le_bytes()),
        (Primitivo::Int64, Valor::Int64(n)) => saida.extend_from_slice(&n.to_le_bytes()),
        (Primitivo::Text, Valor::Texto(t)) => {
            escrever_nat(saida, t.len() as u128);
            saida.extend_from_slice(t.as_bytes());
        }
        (Primitivo::Principal, Valor::Principal(p)) => {
            saida.push(1);
            escrever_nat(saida, p.bytes().len() as u128);
            saida.extend_from_slice(p.bytes());
        }
        _ => return Err(ErroDaEscrita::ForaDoTipo),
    }
    Ok(())
}

/// Um texto entre aspas, só em ASCII: o que não é ASCII imprimível sai
/// como `\u{…}`. Uma resposta de canister não escreve controle nem
/// terminal na saída de um programa.
fn escrever_texto(f: &mut fmt::Formatter<'_>, t: &str) -> fmt::Result {
    f.write_str("\"")?;
    for ch in t.chars() {
        match ch {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            ' '..='~' => write!(f, "{ch}")?,
            outro => write!(f, "\\u{{{:x}}}", u32::from(outro))?,
        }
    }
    f.write_str("\"")
}

/// A forma textual do Candid, em ASCII: `"ola"`, `42 : nat`,
/// `principal "aaaaa-aa"`, `blob "\de\ad"`, `opt …`, `vec { … }`,
/// `record { 1 = …; }`, `variant { 3 = … }`. Os campos saem pelo id: a
/// mensagem não traz os nomes.
impl fmt::Display for Valor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Valor::Null => f.write_str("null"),
            Valor::Bool(b) => write!(f, "{b}"),
            Valor::Nat(n) => write!(f, "{n} : nat"),
            Valor::Int(n) => write!(f, "{n} : int"),
            Valor::Nat8(n) => write!(f, "{n} : nat8"),
            Valor::Nat16(n) => write!(f, "{n} : nat16"),
            Valor::Nat32(n) => write!(f, "{n} : nat32"),
            Valor::Nat64(n) => write!(f, "{n} : nat64"),
            Valor::Int8(n) => write!(f, "{n} : int8"),
            Valor::Int16(n) => write!(f, "{n} : int16"),
            Valor::Int32(n) => write!(f, "{n} : int32"),
            Valor::Int64(n) => write!(f, "{n} : int64"),
            Valor::Texto(t) => escrever_texto(f, t),
            Valor::Reservado => f.write_str("reserved"),
            Valor::Principal(p) => write!(f, "principal \"{p}\""),
            Valor::Opt(None) => f.write_str("null"),
            Valor::Opt(Some(v)) => write!(f, "opt {v}"),
            Valor::Blob(b) => {
                f.write_str("blob \"")?;
                for byte in b {
                    write!(f, "\\{byte:02x}")?;
                }
                f.write_str("\"")
            }
            Valor::Vec(itens) => {
                f.write_str("vec {")?;
                for item in itens {
                    write!(f, " {item};")?;
                }
                f.write_str(" }")
            }
            Valor::Record(campos) => {
                f.write_str("record {")?;
                for (id, v) in campos {
                    write!(f, " {id} = {v};")?;
                }
                f.write_str(" }")
            }
            Valor::Variant(id, v) => write!(f, "variant {{ {id} = {v} }}"),
        }
    }
}

#[cfg(test)]
mod testes;
