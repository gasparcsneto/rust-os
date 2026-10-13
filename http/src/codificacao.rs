//! A codificação de conteúdo (RFC 9110, 8.4): o corpo que o servidor
//! comprimiu, devolvido a quem pediu como era.
//!
//! # Onde ela mora
//!
//! Aqui, no protocolo, e em nenhum outro lugar. O gate decide a conexão e
//! cada envio e cada leitura pelo destino e por quem pede: os bytes que
//! passam são bytes para ele, comprimidos ou não — e com TLS ele nem os vê.
//! Nada da compressão vira permissão, recurso ou regra: o pedido comprimido
//! e o claro são o mesmo pedido para a política, com a mesma decisão, e
//! nenhum é deixado nem recusado pelo algoritmo.
//!
//! # A negociação
//!
//! O pedido diz o que o cliente decodifica ([`Aceitas`], no
//! `Accept-Encoding`), e a resposta diz o que o servidor aplicou
//! (`Content-Encoding`). O cliente decodifica o que pediu, e só: uma
//! codificação que o pedido não aceitou, uma que ninguém conhece, ou mais
//! de uma empilhada são [`Defeito::Codificacao`] — o corpo comprimido não é
//! entregue como se fosse o conteúdo, e o cliente não adivinha. A
//! codificação se confere pela cabeça, antes de o corpo ser lido.
//!
//! # Os limites, antes de descomprimir
//!
//! - o corpo como veio passa pelo limite do corpo ([`crate::Limites`])
//!   enquanto chega, e só inteiro é decodificado;
//! - o que sai do decodificador tem um teto próprio
//!   ([`crate::Limites::descomprimido`]), fixado antes do primeiro byte
//!   sair: a saída cresce dobrando até ele, e para ali. O tamanho que o
//!   gzip anuncia no fim é conferido, e nunca reserva memória — quem
//!   reserva é o que de fato saiu;
//! - as tabelas do DEFLATE têm tamanho fixo, uns 8 KiB, e a janela dele é
//!   a própria saída: nada cresce com o que o servidor anuncia;
//! - uma codificação só.
//!
//! O corpo que se expande além do teto — a bomba de descompressão — custa
//! o teto, e não mais: a memória e o trabalho param nele, e a resposta é
//! [`Limite::Descomprimido`]. A saída ocupa no máximo o teto; no instante
//! em que dobra, a anterior e a nova convivem, e somam no máximo uma vez e
//! meia o teto. O corpo que veio, as tabelas e isso: é a memória inteira
//! de uma decodificação.
//!
//! # O que se confere
//!
//! - **gzip** (RFC 1952): a assinatura, o método 8, os bits reservados
//!   zerados, os campos opcionais, o CRC da cabeça quando ela traz um, o
//!   DEFLATE, e o CRC-32 e o tamanho de cada membro. Membros seguidos são o
//!   formato (RFC 1952, 2.2); depois do último, nada;
//! - **deflate** (RFC 9110, 8.4.1.2): o formato zlib (RFC 1950) — o método
//!   8, a janela de até 32 KiB, o `FCHECK`, sem dicionário preestabelecido
//!   —, o DEFLATE e o Adler-32; depois, nada. O DEFLATE cru que alguns
//!   servidores antigos mandam como `deflate` é recusado: adivinhar o
//!   formato é o que a RFC tirou de cena.
//!
//! O DEFLATE é o de `inflar.rs`, daqui também.

use alloc::string::String;
use alloc::vec::Vec;

use crate::erro::{Defeito, Erro, Limite};
use crate::inflar::{self, Parada, Saida, Tabelas};
use crate::resposta::lista;

/// Uma codificação de conteúdo que o cliente decodifica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codificacao {
    /// `gzip` — e `x-gzip`, que a RFC 9110, 8.4.1.3, manda ler como ele.
    Gzip,
    /// `deflate`: o formato zlib.
    Deflate,
}

impl Codificacao {
    pub const fn nome(self) -> &'static str {
        match self {
            Codificacao::Gzip => "gzip",
            Codificacao::Deflate => "deflate",
        }
    }
}

/// As codificações que um pedido aceita: o `Accept-Encoding` que ele leva,
/// e o que o cliente decodifica na resposta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aceitas {
    pub gzip: bool,
    pub deflate: bool,
}

impl Aceitas {
    /// As duas: o padrão de um pedido.
    pub const TODAS: Aceitas = Aceitas {
        gzip: true,
        deflate: true,
    };

    /// Nenhuma: só o corpo como é (`identity`). Para quem pede uma faixa
    /// (`Range`): a faixa é da representação codificada, e um pedaço de um
    /// gzip não se decodifica.
    pub const NENHUMA: Aceitas = Aceitas {
        gzip: false,
        deflate: false,
    };

    pub const fn aceita(self, c: Codificacao) -> bool {
        match c {
            Codificacao::Gzip => self.gzip,
            Codificacao::Deflate => self.deflate,
        }
    }

    /// O valor do `Accept-Encoding`. Sem nenhuma, `identity`: um pedido
    /// sem o cabeçalho aceitaria qualquer codificação (RFC 9110, 12.5.3).
    pub(crate) const fn cabecalho(self) -> &'static str {
        match (self.gzip, self.deflate) {
            (true, true) => "gzip, deflate",
            (true, false) => "gzip",
            (false, true) => "deflate",
            (false, false) => "identity",
        }
    }
}

impl Default for Aceitas {
    fn default() -> Aceitas {
        Aceitas::TODAS
    }
}

/// A codificação que a resposta diz ter, se o pedido a aceitou — ver o
/// cabeçalho do módulo. `None`: o corpo veio como é.
pub(crate) fn da_resposta(
    cabecalhos: &[(String, String)],
    aceitas: Aceitas,
) -> Result<Option<Codificacao>, Defeito> {
    let mut achada = None;
    for nome in lista(cabecalhos, "content-encoding") {
        let c = if nome.eq_ignore_ascii_case("identity") {
            // `identity` não codifica nada: não é uma camada.
            continue;
        } else if nome.eq_ignore_ascii_case("gzip") || nome.eq_ignore_ascii_case("x-gzip") {
            Codificacao::Gzip
        } else if nome.eq_ignore_ascii_case("deflate") {
            Codificacao::Deflate
        } else {
            return Err(Defeito::Codificacao);
        };
        if achada.is_some() || !aceitas.aceita(c) {
            return Err(Defeito::Codificacao);
        }
        achada = Some(c);
    }
    Ok(achada)
}

/// O conteúdo de `corpo`, que veio em `codificacao`, com no máximo `teto`
/// bytes — ver o cabeçalho do módulo.
pub(crate) fn decodificar<F>(
    codificacao: Codificacao,
    corpo: &[u8],
    teto: usize,
) -> Result<Vec<u8>, Erro<F>> {
    let mut saida = Saida::nova(teto, corpo.len());
    let mut tabelas = Tabelas::novas();
    let feito = match codificacao {
        Codificacao::Gzip => gzip(corpo, &mut saida, &mut tabelas),
        Codificacao::Deflate => zlib(corpo, &mut saida, &mut tabelas),
    };
    match feito {
        Ok(()) => Ok(saida.entregar()),
        Err(Parada::Teto) => Err(Erro::Limite(Limite::Descomprimido)),
        Err(Parada::Defeito(d)) => Err(Erro::Conteudo(d)),
    }
}

/// O método de compressão do gzip e do zlib: o DEFLATE.
const DEFLATE: u8 = 8;

/// O começo de um membro gzip.
const ASSINATURA: [u8; 2] = [0x1f, 0x8b];

/// Os bits de `FLG`, na cabeça de um membro gzip.
const FHCRC: u8 = 1 << 1;
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;
const RESERVADOS: u8 = 0b1110_0000;

/// A cabeça de um membro gzip: quantos bytes ela ocupa.
fn cabeca_gzip(entrada: &[u8]) -> Result<usize, Defeito> {
    // A assinatura e o método, até onde chegaram: o que já não confere não
    // é um gzip cortado, é outra coisa.
    for (i, esperado) in [ASSINATURA[0], ASSINATURA[1], DEFLATE]
        .into_iter()
        .enumerate()
    {
        if entrada.get(i).is_some_and(|&b| b != esperado) {
            return Err(Defeito::Cabecalho);
        }
    }
    let fixa = entrada.get(..10).ok_or(Defeito::Cortado)?;
    let flg = fixa[3];
    if flg & RESERVADOS != 0 {
        return Err(Defeito::Cabecalho);
    }
    let mut pos = 10;
    if flg & FEXTRA != 0 {
        let xlen = entrada.get(pos..pos + 2).ok_or(Defeito::Cortado)?;
        pos += 2 + usize::from(u16::from_le_bytes([xlen[0], xlen[1]]));
        if pos > entrada.len() {
            return Err(Defeito::Cortado);
        }
    }
    // O nome e o comentário acabam num zero, e não são guardados.
    for campo in [FNAME, FCOMMENT] {
        if flg & campo != 0 {
            let zero = entrada[pos..]
                .iter()
                .position(|&b| b == 0)
                .ok_or(Defeito::Cortado)?;
            pos += zero + 1;
        }
    }
    if flg & FHCRC != 0 {
        let lido = entrada.get(pos..pos + 2).ok_or(Defeito::Cortado)?;
        // Os 16 bits de baixo do CRC-32 da cabeça até aqui.
        if crc32(&entrada[..pos]) as u16 != u16::from_le_bytes([lido[0], lido[1]]) {
            return Err(Defeito::Soma);
        }
        pos += 2;
    }
    Ok(pos)
}

/// Os membros gzip de `entrada`, um depois do outro.
fn gzip(entrada: &[u8], saida: &mut Saida, tabelas: &mut Tabelas) -> Result<(), Parada> {
    let mut resto = entrada;
    loop {
        let cabeca = cabeca_gzip(resto)?;
        let inicio = saida.len();
        let fim = cabeca + inflar::inflar(&resto[cabeca..], saida, tabelas)?;
        let rodape = resto.get(fim..fim + 8).ok_or(Defeito::Cortado)?;
        let crc = u32::from_le_bytes([rodape[0], rodape[1], rodape[2], rodape[3]]);
        let tamanho = u32::from_le_bytes([rodape[4], rodape[5], rodape[6], rodape[7]]);
        let membro = &saida.bytes()[inicio..];
        // O tamanho é o do membro módulo 2³² (RFC 1952, 2.3.1).
        if crc32(membro) != crc || membro.len() as u32 != tamanho {
            return Err(Defeito::Soma.into());
        }
        resto = &resto[fim + 8..];
        if resto.is_empty() {
            return Ok(());
        }
        // Outro membro — ou o que não é gzip, e sobra.
        if resto[0] != ASSINATURA[0] || resto.get(1).is_some_and(|&b| b != ASSINATURA[1]) {
            return Err(Defeito::Sobra.into());
        }
    }
}

/// O fluxo zlib de `entrada`.
fn zlib(entrada: &[u8], saida: &mut Saida, tabelas: &mut Tabelas) -> Result<(), Parada> {
    // O método e a janela, até onde chegaram.
    if entrada
        .first()
        .is_some_and(|&cmf| cmf & 0x0f != DEFLATE || cmf >> 4 > 7)
    {
        return Err(Defeito::Cabecalho.into());
    }
    let cabeca = entrada.get(..2).ok_or(Defeito::Cortado)?;
    let (cmf, flg) = (cabeca[0], cabeca[1]);
    // `FCHECK`: os dois bytes, como número, são múltiplo de 31. `FDICT`:
    // o dicionário preestabelecido, que o HTTP não tem como combinar.
    if !(u16::from(cmf) << 8 | u16::from(flg)).is_multiple_of(31) || flg & 0x20 != 0 {
        return Err(Defeito::Cabecalho.into());
    }
    let fim = 2 + inflar::inflar(&entrada[2..], saida, tabelas)?;
    let soma = entrada.get(fim..fim + 4).ok_or(Defeito::Cortado)?;
    if adler32(saida.bytes()) != u32::from_be_bytes([soma[0], soma[1], soma[2], soma[3]]) {
        return Err(Defeito::Soma.into());
    }
    if entrada.len() > fim + 4 {
        return Err(Defeito::Sobra.into());
    }
    Ok(())
}

/// A tabela do CRC-32 do gzip (ISO 3309): o polinômio `0xEDB88320`, com os
/// bits refletidos.
const TABELA_DO_CRC: [u32; 256] = {
    let mut tabela = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        tabela[i] = c;
        i += 1;
    }
    tabela
};

/// O CRC-32 do gzip (RFC 1952, 8).
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in bytes {
        c = TABELA_DO_CRC[usize::from(c as u8 ^ b)] ^ (c >> 8);
    }
    !c
}

/// O Adler-32 do zlib (RFC 1950, 8.2).
pub(crate) fn adler32(bytes: &[u8]) -> u32 {
    const BASE: u32 = 65_521;
    // O maior pedaço em que a segunda soma não passa de 32 bits antes do
    // módulo.
    const PEDACO: usize = 5552;
    let (mut a, mut b) = (1u32, 0u32);
    for pedaco in bytes.chunks(PEDACO) {
        for &x in pedaco {
            a += u32::from(x);
            b += a;
        }
        a %= BASE;
        b %= BASE;
    }
    b << 16 | a
}
