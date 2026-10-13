//! O DEFLATE (RFC 1951): o formato comprimido de dentro do gzip e do zlib.
//!
//! Escrito aqui, como o resto do pacote, e pela mesma razão: o que importa
//! num decodificador que lê o que um servidor qualquer mandou é o que ele
//! recusa. E o pacote não depende de ninguém — o `xtask` confere.
//!
//! # De uma vez, e com teto
//!
//! A entrada já está inteira na memória — o corpo, lido com o limite dele
//! —, e a saída cresce até o teto de quem chama ([`Saida`]). A janela de
//! 32 KiB do DEFLATE é a própria saída, e uma distância nunca aponta para
//! antes do começo do fluxo. As tabelas de Huffman têm tamanho fixo
//! ([`Tabelas`]), e o trabalho é linear na entrada e na saída: cada símbolo
//! gasta pelo menos um bit da entrada, e cada bloco também.
//!
//! # O que se recusa
//!
//! O que a RFC 1951 não define, e o que o zlib recusa:
//!
//! - o bloco de tipo 3;
//! - o bloco guardado com `LEN` e `NLEN` que não são o complemento um do
//!   outro;
//! - mais de 286 comprimentos de literal, ou mais de 30 de distância;
//! - um código de Huffman com mais códigos do que os bits comportam; um
//!   incompleto, salvo o que tem no máximo um código, de um bit, que a RFC
//!   permite; e o código dos comprimentos de código, que tem de ser
//!   completo;
//! - a repetição do comprimento anterior sem um anterior, e a repetição que
//!   passa do número de comprimentos;
//! - o código de literal sem o fim de bloco (256);
//! - os símbolos 286 e 287 e as distâncias 30 e 31, que o código fixo tem
//!   e a RFC proíbe;
//! - a distância que aponta para antes do começo.
//!
//! O fluxo que acaba antes do último bloco é [`Defeito::Cortado`]; o resto,
//! [`Defeito::Dados`].

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::erro::Defeito;

/// Por que a decodificação parou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Parada {
    /// O fluxo não se decodifica.
    Defeito(Defeito),
    /// A saída passaria do teto: o resto não é escrito.
    Teto,
}

impl From<Defeito> for Parada {
    fn from(d: Defeito) -> Parada {
        Parada::Defeito(d)
    }
}

/// O menor espaço que a saída reserva de uma vez.
const MENOR_RESERVA: usize = 16 * 1024;

/// A saída: cresce dobrando, e nunca passa do teto — nem no que reserva.
pub(crate) struct Saida {
    bytes: Vec<u8>,
    teto: usize,
    /// A primeira reserva.
    dica: usize,
}

impl Saida {
    /// Uma saída de no máximo `teto` bytes, para uma entrada de `entrada`
    /// bytes. A primeira reserva vem do que de fato chegou — e não de um
    /// tamanho que o fluxo anuncia.
    pub(crate) fn nova(teto: usize, entrada: usize) -> Saida {
        Saida {
            bytes: Vec::new(),
            teto,
            dica: entrada.saturating_mul(2).max(MENOR_RESERVA),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn entregar(self) -> Vec<u8> {
        self.bytes
    }

    /// Espaço para mais `n` bytes, sem passar do teto.
    fn garantir(&mut self, n: usize) -> Result<(), Parada> {
        let total = self.bytes.len().checked_add(n).ok_or(Parada::Teto)?;
        if total > self.teto {
            return Err(Parada::Teto);
        }
        if total > self.bytes.capacity() {
            // A reserva é o teto dividido por uma potência de dois: a menor
            // que serve. Crescendo assim, a anterior é no máximo metade da
            // nova, e no instante da cópia as duas somam no máximo uma vez
            // e meia o teto. E exata: a que dobra por conta própria
            // passaria dele.
            let minimo = total.max(self.dica);
            let mut reserva = self.teto;
            while reserva / 2 >= minimo {
                reserva /= 2;
            }
            self.bytes.reserve_exact(reserva - self.bytes.len());
        }
        Ok(())
    }

    fn literal(&mut self, b: u8) -> Result<(), Parada> {
        self.garantir(1)?;
        self.bytes.push(b);
        Ok(())
    }

    fn guardados(&mut self, b: &[u8]) -> Result<(), Parada> {
        self.garantir(b.len())?;
        self.bytes.extend_from_slice(b);
        Ok(())
    }

    /// `comprimento` bytes copiados de `distancia` para trás, sem passar do
    /// começo do fluxo, em `inicio`. A distância pode ser menor que o
    /// comprimento: o que se copia vai sendo escrito, e se repete.
    fn copia(&mut self, distancia: usize, comprimento: usize, inicio: usize) -> Result<(), Parada> {
        if distancia > self.bytes.len() - inicio {
            return Err(Parada::Defeito(Defeito::Dados));
        }
        self.garantir(comprimento)?;
        let de = self.bytes.len() - distancia;
        let mut faltam = comprimento;
        while faltam > 0 {
            // De `de` até o fim já é a repetição: copiá-la de uma vez dobra
            // o pedaço a cada volta.
            let k = faltam.min(self.bytes.len() - de);
            self.bytes.extend_from_within(de..de + k);
            faltam -= k;
        }
        Ok(())
    }
}

/// A entrada, bit a bit: do bit menos significativo de cada byte para o
/// mais.
struct Bits<'a> {
    entrada: &'a [u8],
    /// O próximo byte que entra no acumulador.
    pos: usize,
    acumulado: u64,
    quantos: u32,
}

impl<'a> Bits<'a> {
    fn nova(entrada: &'a [u8]) -> Bits<'a> {
        Bits {
            entrada,
            pos: 0,
            acumulado: 0,
            quantos: 0,
        }
    }

    fn encher(&mut self) {
        while self.quantos <= 56 {
            let Some(&b) = self.entrada.get(self.pos) else {
                return;
            };
            self.acumulado |= u64::from(b) << self.quantos;
            self.pos += 1;
            self.quantos += 8;
        }
    }

    /// Os próximos `n` bits sem consumi-los, completados com zeros depois
    /// do fim da entrada — e quantos deles são de verdade.
    fn olhar(&mut self, n: u32) -> (usize, u32) {
        if self.quantos < n {
            self.encher();
        }
        (
            (self.acumulado & ((1 << n) - 1)) as usize,
            self.quantos.min(n),
        )
    }

    fn consumir(&mut self, n: u32) {
        self.acumulado >>= n;
        self.quantos -= n;
    }

    /// Os próximos `n` bits, até 16.
    fn ler(&mut self, n: u32) -> Result<u32, Defeito> {
        if self.quantos < n {
            self.encher();
            if self.quantos < n {
                return Err(Defeito::Cortado);
            }
        }
        let v = (self.acumulado & ((1 << n) - 1)) as u32;
        self.consumir(n);
        Ok(v)
    }

    /// Vai ao começo do byte seguinte: os bits que sobram do byte atual
    /// ficam para trás, e os bytes inteiros do acumulador voltam à
    /// entrada.
    fn alinhar(&mut self) {
        self.pos -= (self.quantos / 8) as usize;
        self.acumulado = 0;
        self.quantos = 0;
    }

    /// Onde o fluxo acabou: o byte depois do último bit lido.
    fn fim(&self) -> usize {
        self.pos - (self.quantos / 8) as usize
    }
}

/// O maior comprimento de um código de Huffman.
const MAIOR_CODIGO: usize = 15;

/// Os bits da tabela rápida: um código de até tantos bits sai numa
/// consulta.
const RAPIDOS: u32 = 9;

/// Quantos símbolos um código tem, no máximo: os 288 do código fixo de
/// literal e comprimento.
const SIMBOLOS: usize = 288;

/// Um código de Huffman canônico (RFC 1951, 3.2.2).
struct Huffman {
    /// Quantos códigos de cada comprimento.
    contagem: [u16; MAIOR_CODIGO + 1],
    /// Os símbolos, na ordem dos códigos.
    simbolos: [u16; SIMBOLOS],
    /// Para os próximos [`RAPIDOS`] bits da entrada, o comprimento e o
    /// símbolo do código que eles começam — `comprimento << RAPIDOS |
    /// símbolo` —, ou zero: um código mais longo, ou nenhum.
    rapida: [u16; 1 << RAPIDOS],
}

impl Huffman {
    const VAZIO: Huffman = Huffman {
        contagem: [0; MAIOR_CODIGO + 1],
        simbolos: [0; SIMBOLOS],
        rapida: [0; 1 << RAPIDOS],
    };

    /// Monta o código dos `comprimentos`, um por símbolo — zero é o
    /// símbolo sem código —, e diz se ele é completo. Com mais códigos do
    /// que os bits comportam, ele não se monta.
    fn montar(&mut self, comprimentos: &[u8]) -> Result<bool, Defeito> {
        self.contagem = [0; MAIOR_CODIGO + 1];
        for &c in comprimentos {
            self.contagem[usize::from(c)] += 1;
        }
        // Quantos códigos ainda cabem em cada comprimento.
        let mut sobra: i32 = 1;
        for &n in &self.contagem[1..] {
            sobra = (sobra << 1) - i32::from(n);
            if sobra < 0 {
                return Err(Defeito::Dados);
            }
        }
        let mut proximo = [0u16; MAIOR_CODIGO + 2];
        for c in 1..=MAIOR_CODIGO {
            proximo[c + 1] = proximo[c] + self.contagem[c];
        }
        for (simbolo, &c) in comprimentos.iter().enumerate() {
            if c != 0 {
                let c = usize::from(c);
                self.simbolos[usize::from(proximo[c])] = simbolo as u16;
                proximo[c] += 1;
            }
        }
        // O código chega pelo bit mais significativo, e a entrada é lida
        // pelo menos significativo: a tabela é indexada pelo código
        // invertido, repetido em cada valor dos bits que sobram.
        self.rapida = [0; 1 << RAPIDOS];
        let (mut codigo, mut indice) = (0u32, 0usize);
        for c in 1..=RAPIDOS {
            let n = usize::from(self.contagem[c as usize]);
            for k in 0..n {
                let invertido = (codigo + k as u32).reverse_bits() >> (32 - c);
                let entrada = (c as u16) << RAPIDOS | self.simbolos[indice + k];
                let mut i = invertido as usize;
                while i < 1 << RAPIDOS {
                    self.rapida[i] = entrada;
                    i += 1 << c;
                }
            }
            codigo = (codigo + n as u32) << 1;
            indice += n;
        }
        Ok(sobra == 0)
    }

    /// O próximo símbolo da entrada.
    fn decodificar(&self, bits: &mut Bits<'_>) -> Result<u16, Defeito> {
        let (olhado, reais) = bits.olhar(RAPIDOS);
        let e = self.rapida[olhado];
        if e != 0 {
            let c = u32::from(e >> RAPIDOS);
            // O código saiu dos zeros depois do fim: a entrada acabou no
            // meio dele.
            if c > reais {
                return Err(Defeito::Cortado);
            }
            bits.consumir(c);
            return Ok(e & ((1 << RAPIDOS) - 1));
        }
        // Mais longo que a tabela: bit a bit, como o `puff` do zlib.
        let (mut codigo, mut primeiro, mut indice) = (0i32, 0i32, 0i32);
        for c in 1..=MAIOR_CODIGO {
            codigo |= bits.ler(1)? as i32;
            let n = i32::from(self.contagem[c]);
            if codigo - n < primeiro {
                return Ok(self.simbolos[(indice + codigo - primeiro) as usize]);
            }
            indice += n;
            primeiro = (primeiro + n) << 1;
            codigo <<= 1;
        }
        // Um código que não existe: o de um código incompleto.
        Err(Defeito::Dados)
    }
}

/// As tabelas de um fluxo, montadas uma vez por bloco — e as do código
/// fixo, uma vez por fluxo: um bloco fixo de dez bits não paga a montagem.
pub(crate) struct Tabelas {
    literal: Huffman,
    distancia: Huffman,
    /// O código dos comprimentos de código, de um bloco dinâmico.
    comprimentos: Huffman,
    literal_fixo: Huffman,
    distancia_fixa: Huffman,
    fixas_prontas: bool,
}

impl Tabelas {
    /// No monte: são uns 8 KiB, e a pilha de um programa tem 64.
    pub(crate) fn novas() -> Box<Tabelas> {
        Box::new(Tabelas {
            literal: Huffman::VAZIO,
            distancia: Huffman::VAZIO,
            comprimentos: Huffman::VAZIO,
            literal_fixo: Huffman::VAZIO,
            distancia_fixa: Huffman::VAZIO,
            fixas_prontas: false,
        })
    }

    /// O código fixo (RFC 1951, 3.2.6).
    fn fixas(&mut self) -> Result<(), Defeito> {
        if !self.fixas_prontas {
            let mut literal = [8u8; SIMBOLOS];
            literal[144..256].fill(9);
            literal[256..280].fill(7);
            self.literal_fixo.montar(&literal)?;
            self.distancia_fixa.montar(&[5; 32])?;
            self.fixas_prontas = true;
        }
        Ok(())
    }

    /// O código de um bloco dinâmico (RFC 1951, 3.2.7).
    fn dinamicas(&mut self, bits: &mut Bits<'_>) -> Result<(), Defeito> {
        /// A ordem em que chegam os comprimentos do código de comprimentos.
        const ORDEM: [usize; 19] = [
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
        ];
        let literais = bits.ler(5)? as usize + 257;
        let distancias = bits.ler(5)? as usize + 1;
        let quantos = bits.ler(4)? as usize + 4;
        if literais > MAIS_LITERAIS || distancias > MAIS_DISTANCIAS {
            return Err(Defeito::Dados);
        }
        let mut cc = [0u8; 19];
        for &s in &ORDEM[..quantos] {
            cc[s] = bits.ler(3)? as u8;
        }
        if !self.comprimentos.montar(&cc)? {
            return Err(Defeito::Dados);
        }
        let total = literais + distancias;
        let mut comprimentos = [0u8; MAIS_LITERAIS + MAIS_DISTANCIAS];
        let mut i = 0;
        while i < total {
            let (valor, vezes) = match self.comprimentos.decodificar(bits)? {
                s @ 0..=15 => (s as u8, 1),
                16 => {
                    let anterior = *comprimentos[..i].last().ok_or(Defeito::Dados)?;
                    (anterior, 3 + bits.ler(2)? as usize)
                }
                17 => (0, 3 + bits.ler(3)? as usize),
                18 => (0, 11 + bits.ler(7)? as usize),
                _ => return Err(Defeito::Dados),
            };
            if i + vezes > total {
                return Err(Defeito::Dados);
            }
            comprimentos[i..i + vezes].fill(valor);
            i += vezes;
        }
        if comprimentos[FIM_DE_BLOCO] == 0 {
            return Err(Defeito::Dados);
        }
        usavel(&mut self.literal, &comprimentos[..literais])?;
        usavel(&mut self.distancia, &comprimentos[literais..total])
    }
}

/// Monta um código de literal ou de distância: completo, ou com no máximo
/// um código, de um bit — ou nenhum, o bloco só de literais (RFC 1951,
/// 3.2.7).
fn usavel(h: &mut Huffman, comprimentos: &[u8]) -> Result<(), Defeito> {
    if !h.montar(comprimentos)? && comprimentos.iter().any(|&c| c > 1) {
        return Err(Defeito::Dados);
    }
    Ok(())
}

/// Quantos comprimentos de literal e de distância um bloco dinâmico pode
/// trazer.
const MAIS_LITERAIS: usize = 286;
const MAIS_DISTANCIAS: usize = 30;

const FIM_DE_BLOCO: usize = 256;

/// O comprimento de cada símbolo de 257 a 285: a base e os bits a mais.
const BASE_DO_COMPRIMENTO: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const EXTRA_DO_COMPRIMENTO: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// A distância de cada símbolo de 0 a 29.
const BASE_DA_DISTANCIA: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const EXTRA_DA_DISTANCIA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Um bloco guardado: sem compressão, alinhado ao byte.
fn guardado(bits: &mut Bits<'_>, saida: &mut Saida) -> Result<(), Parada> {
    bits.alinhar();
    let cabeca = bits
        .entrada
        .get(bits.pos..bits.pos + 4)
        .ok_or(Defeito::Cortado)?;
    let n = u16::from_le_bytes([cabeca[0], cabeca[1]]);
    if n != !u16::from_le_bytes([cabeca[2], cabeca[3]]) {
        return Err(Defeito::Dados.into());
    }
    let comeco = bits.pos + 4;
    let dados = bits
        .entrada
        .get(comeco..comeco + usize::from(n))
        .ok_or(Defeito::Cortado)?;
    saida.guardados(dados)?;
    bits.pos = comeco + usize::from(n);
    Ok(())
}

/// Os símbolos de um bloco comprimido, até o fim de bloco.
fn comprimido(
    literal: &Huffman,
    distancia: &Huffman,
    bits: &mut Bits<'_>,
    saida: &mut Saida,
    inicio: usize,
) -> Result<(), Parada> {
    loop {
        let s = usize::from(literal.decodificar(bits)?);
        if s < FIM_DE_BLOCO {
            saida.literal(s as u8)?;
            continue;
        }
        if s == FIM_DE_BLOCO {
            return Ok(());
        }
        let s = s - FIM_DE_BLOCO - 1;
        if s >= BASE_DO_COMPRIMENTO.len() {
            return Err(Defeito::Dados.into());
        }
        let comprimento = usize::from(BASE_DO_COMPRIMENTO[s])
            + bits.ler(u32::from(EXTRA_DO_COMPRIMENTO[s]))? as usize;
        let d = usize::from(distancia.decodificar(bits)?);
        if d >= BASE_DA_DISTANCIA.len() {
            return Err(Defeito::Dados.into());
        }
        let distancia = usize::from(BASE_DA_DISTANCIA[d])
            + bits.ler(u32::from(EXTRA_DA_DISTANCIA[d]))? as usize;
        saida.copia(distancia, comprimento, inicio)?;
    }
}

/// Decodifica o fluxo DEFLATE do começo de `entrada` para o fim de
/// `saida`, e diz quantos bytes de `entrada` ele ocupou — o que vem depois
/// é de quem chama.
pub(crate) fn inflar(
    entrada: &[u8],
    saida: &mut Saida,
    tabelas: &mut Tabelas,
) -> Result<usize, Parada> {
    let inicio = saida.len();
    let mut bits = Bits::nova(entrada);
    loop {
        let ultimo = bits.ler(1)? == 1;
        match bits.ler(2)? {
            0 => guardado(&mut bits, saida)?,
            1 => {
                tabelas.fixas()?;
                comprimido(
                    &tabelas.literal_fixo,
                    &tabelas.distancia_fixa,
                    &mut bits,
                    saida,
                    inicio,
                )?;
            }
            2 => {
                tabelas.dinamicas(&mut bits)?;
                comprimido(
                    &tabelas.literal,
                    &tabelas.distancia,
                    &mut bits,
                    saida,
                    inicio,
                )?;
            }
            _ => return Err(Defeito::Dados.into()),
        }
        if ultimo {
            return Ok(bits.fim());
        }
    }
}
