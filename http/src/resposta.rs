//! A resposta: lida do transporte, linha a linha e depois o corpo, com os
//! limites de quem chama (RFC 9112).
//!
//! # Onde a resposta acaba
//!
//! É a parte do HTTP/1.1 que importa, porque é por ela que um pedido
//! entra dentro de outro. Na ordem da RFC 9112, 6.3:
//!
//! 1. a resposta a um `HEAD`, uma informativa (1xx), um `204` ou um `304`
//!    não tem corpo, diga o que disser o `Content-Length`;
//! 2. `Transfer-Encoding` só pode ser `chunked`, e sozinho: outra
//!    codificação o cliente não decodifica, e com um `Content-Length` junto
//!    cada lado poderia delimitar o corpo por um — os dois casos são
//!    recusados, e não adivinhados;
//! 3. `Content-Length`: um número decimal, e se vier mais de um, todos
//!    iguais;
//! 4. sem nenhum dos dois, o corpo vai até o servidor fechar — e a conexão
//!    não leva outro pedido.
//!
//! # O que não se aceita
//!
//! Linha que não acaba em CRLF, cabeçalho dobrado, espaço antes dos
//! dois-pontos, controle no valor, versão que não é 1.0 nem 1.1, status
//! fora de 100 a 599, troca de protocolo (101). E o servidor que fecha
//! antes do fim é [`Erro::Fechada`]: o que chegou não é entregue.
//!
//! # O corpo codificado
//!
//! Com um `Content-Encoding` que o pedido aceitou, o corpo é lido inteiro
//! com os limites de sempre e decodificado depois, com o teto do corpo
//! decodificado — ver [`crate::codificacao`]. A codificação se confere pela
//! cabeça, antes de ler o corpo.

use alloc::string::String;
use alloc::vec::Vec;

use crate::cliente::Fluxo;
use crate::codificacao::{self, Aceitas, Codificacao};
use crate::cookies::Guardados;
use crate::erro::{Erro, Limite, Motivo};
use crate::pedido::{Metodo, tchar};

/// Quantas respostas informativas (1xx) se aceitam antes da final.
const MAIS_INFORMATIVAS: usize = 8;

/// O maior pedaço que se pede ao transporte de uma vez: o buffer de uma
/// conexão do Duke, o que um `net.recv` traz numa decisão do gate.
const LEITURA: usize = 16 * 1024;

/// A maior linha de tamanho de um pedaço, com as extensões.
const MAIOR_LINHA_DE_PEDACO: usize = 1024;

/// Os limites de uma resposta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limites {
    /// A maior linha, sem o CRLF: a de status, um cabeçalho, o tamanho de
    /// um pedaço.
    pub linha: usize,
    /// A cabeça inteira, com os CRLF: status e cabeçalhos — e, à parte, os
    /// *trailers* de um corpo em pedaços.
    pub cabeca: usize,
    /// Quantos cabeçalhos.
    pub cabecalhos: usize,
    /// O corpo como veio, em bytes — comprimido ou não.
    pub corpo: usize,
    /// O corpo decodificado, em bytes: o teto do que sai do decodificador
    /// quando o corpo veio comprimido. O corpo que veio como é não passa
    /// pelo decodificador, e o limite dele é o `corpo`.
    pub descomprimido: usize,
}

impl Default for Limites {
    fn default() -> Limites {
        Limites {
            linha: 8 * 1024,
            cabeca: 16 * 1024,
            cabecalhos: 64,
            corpo: 1024 * 1024,
            descomprimido: 4 * 1024 * 1024,
        }
    }
}

/// A versão da resposta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Versao {
    Http10,
    Http11,
}

/// Como o corpo foi delimitado — ver o cabeçalho do módulo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enquadramento {
    /// Sem corpo.
    Nenhum,
    /// `Content-Length`.
    Tamanho(u64),
    /// `Transfer-Encoding: chunked`.
    Pedacos,
    /// Até o servidor fechar.
    AteFechar,
}

/// Uma resposta inteira.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resposta {
    pub versao: Versao,
    pub status: u16,
    pub motivo: String,
    /// Os cabeçalhos na ordem em que vieram, com o nome em minúsculas. O
    /// `Content-Length` e o `Content-Encoding` falam do corpo como veio.
    pub cabecalhos: Vec<(String, String)>,
    /// O conteúdo: já decodificado, quando veio comprimido.
    pub corpo: Vec<u8>,
    /// A codificação que o cliente tirou do corpo — `None`, quando ele veio
    /// como é.
    pub codificacao: Option<Codificacao>,
    /// O tamanho do corpo como veio, antes de decodificado.
    pub no_fio: usize,
    /// O que os `Set-Cookie` fizeram no pote, numa troca com pote; zero
    /// sem ele.
    pub cookies: Guardados,
    pub enquadramento: Enquadramento,
    /// A conexão pode levar o pedido seguinte: HTTP/1.1 sem
    /// `Connection: close`, um corpo com fim certo, e nada a mais depois
    /// dele — o que já chegou colado à resposta, sem pedido que o explique,
    /// é um servidor dessincronizado, e não o começo da resposta seguinte.
    pub reutilizavel: bool,
}

impl Resposta {
    /// O valor do primeiro cabeçalho `nome`, sem diferença de maiúsculas.
    pub fn cabecalho(&self, nome: &str) -> Option<&str> {
        self.cabecalhos
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(nome))
            .map(|(_, v)| v.as_str())
    }
}

/// O transporte e o que já chegou dele sem ter sido lido.
struct Entrada<'a, F: Fluxo> {
    fluxo: &'a mut F,
    buffer: &'a mut Vec<u8>,
}

impl<F: Fluxo> Entrada<'_, F> {
    /// Mais bytes do transporte. `false`: o outro lado fechou.
    fn encher(&mut self) -> Result<bool, Erro<F::Falha>> {
        // Direto no fim do buffer, e não num pedaço na pilha: a pilha de um
        // programa do Duke tem 64 KiB, e uma leitura é um quarto disso.
        let inicio = self.buffer.len();
        self.buffer.resize(inicio + LEITURA, 0);
        let lido = self.fluxo.receber(&mut self.buffer[inicio..]);
        let n = match lido {
            Ok(n) => n.min(LEITURA),
            Err(e) => {
                self.buffer.truncate(inicio);
                return Err(Erro::Baixo(e));
            }
        };
        self.buffer.truncate(inicio + n);
        Ok(n > 0)
    }

    /// Uma linha, sem o CRLF, de no máximo `maximo` bytes.
    fn linha(&mut self, maximo: usize) -> Result<Vec<u8>, Erro<F::Falha>> {
        let mut varrido = 0;
        loop {
            if let Some(i) = self.buffer[varrido..].iter().position(|&b| b == b'\n') {
                let i = varrido + i;
                if i == 0 || self.buffer[i - 1] != b'\r' {
                    return Err(Erro::Protocolo(Motivo::FimDeLinha));
                }
                let fim = i - 1;
                if fim > maximo {
                    return Err(Erro::Limite(Limite::Linha));
                }
                if self.buffer[..fim].contains(&b'\r') {
                    return Err(Erro::Protocolo(Motivo::FimDeLinha));
                }
                let linha = self.buffer[..fim].to_vec();
                self.buffer.drain(..=i);
                return Ok(linha);
            }
            varrido = self.buffer.len();
            // Sem fim de linha em mais que `maximo` bytes — o CR do fim,
            // que pode ter chegado sem o LF, conta à parte.
            if self.buffer.len() > maximo + 1 {
                return Err(Erro::Limite(Limite::Linha));
            }
            if !self.encher()? {
                return Err(Erro::Fechada);
            }
        }
    }

    /// Exatamente `n` bytes, para o fim de `destino`.
    fn exatos(&mut self, n: usize, destino: &mut Vec<u8>) -> Result<(), Erro<F::Falha>> {
        let mut faltam = n;
        while faltam > 0 {
            if self.buffer.is_empty() && !self.encher()? {
                return Err(Erro::Fechada);
            }
            let k = faltam.min(self.buffer.len());
            destino.extend_from_slice(&self.buffer[..k]);
            self.buffer.drain(..k);
            faltam -= k;
        }
        Ok(())
    }

    /// O CRLF que fecha o dado de um pedaço.
    fn crlf(&mut self) -> Result<(), Erro<F::Falha>> {
        while self.buffer.len() < 2 {
            if !self.encher()? {
                return Err(Erro::Fechada);
            }
        }
        if self.buffer[..2] != *b"\r\n" {
            return Err(Erro::Protocolo(Motivo::Pedaco));
        }
        self.buffer.drain(..2);
        Ok(())
    }
}

/// O valor sem o espaço opcional das pontas (`OWS`).
fn sem_ows(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', resto @ ..] = v {
        v = resto;
    }
    while let [resto @ .., b' ' | b'\t'] = v {
        v = resto;
    }
    v
}

/// Um byte que pode estar num valor de cabeçalho: visível, espaço,
/// tabulação, ou acima do ASCII (`obs-text`).
fn de_valor(b: u8) -> bool {
    b == b' ' || b == b'\t' || b.is_ascii_graphic() || b >= 0x80
}

fn ler_status(linha: &[u8]) -> Result<(Versao, u16, String), Motivo> {
    let versao = match linha.get(..8) {
        Some(b"HTTP/1.1") => Versao::Http11,
        Some(b"HTTP/1.0") => Versao::Http10,
        Some(v) if v.starts_with(b"HTTP/") => return Err(Motivo::Versao),
        _ => return Err(Motivo::LinhaDeStatus),
    };
    if linha.get(8) != Some(&b' ') {
        return Err(Motivo::LinhaDeStatus);
    }
    let digitos = linha.get(9..12).ok_or(Motivo::LinhaDeStatus)?;
    if !digitos.iter().all(u8::is_ascii_digit) {
        return Err(Motivo::LinhaDeStatus);
    }
    let status = digitos
        .iter()
        .fold(0u16, |n, d| n * 10 + u16::from(d - b'0'));
    if !(100..=599).contains(&status) {
        return Err(Motivo::Status);
    }
    let motivo = match linha.get(12) {
        None => &[][..],
        Some(b' ') => &linha[13..],
        Some(_) => return Err(Motivo::LinhaDeStatus),
    };
    if !motivo.iter().all(|&b| de_valor(b)) {
        return Err(Motivo::LinhaDeStatus);
    }
    Ok((versao, status, String::from_utf8_lossy(motivo).into_owned()))
}

fn ler_cabecalho(linha: &[u8]) -> Result<(String, String), Motivo> {
    if let [b' ' | b'\t', ..] = linha {
        return Err(Motivo::Dobra);
    }
    let dois = linha
        .iter()
        .position(|&b| b == b':')
        .ok_or(Motivo::Cabecalho)?;
    let nome = &linha[..dois];
    // Um espaço antes dos dois-pontos não é `tchar`: a RFC 9112, 5.1,
    // manda recusar — um intermediário poderia ler outro nome.
    if nome.is_empty() || !nome.iter().all(|&b| tchar(b)) {
        return Err(Motivo::Cabecalho);
    }
    let valor = sem_ows(&linha[dois + 1..]);
    if !valor.iter().all(|&b| de_valor(b)) {
        return Err(Motivo::Cabecalho);
    }
    Ok((
        String::from_utf8_lossy(nome).to_ascii_lowercase(),
        String::from_utf8_lossy(valor).into_owned(),
    ))
}

/// Os valores de todos os cabeçalhos `nome`, partidos nas vírgulas, sem o
/// espaço das pontas e sem os vazios.
pub(crate) fn lista<'a>(
    cabecalhos: &'a [(String, String)],
    nome: &'a str,
) -> impl Iterator<Item = &'a str> + 'a {
    cabecalhos
        .iter()
        .filter(move |(n, _)| n == nome)
        .flat_map(|(_, v)| v.split(','))
        .map(|p| p.trim_matches([' ', '\t']))
        .filter(|p| !p.is_empty())
}

/// A cabeça: status e cabeçalhos.
type Cabeca = (Versao, u16, String, Vec<(String, String)>);

fn ler_cabeca<F: Fluxo>(
    entrada: &mut Entrada<'_, F>,
    limites: &Limites,
) -> Result<Cabeca, Erro<F::Falha>> {
    let status = entrada.linha(limites.linha)?;
    let mut gasto = status.len() + 2;
    if gasto > limites.cabeca {
        return Err(Erro::Limite(Limite::Cabeca));
    }
    let (versao, codigo, motivo) = ler_status(&status).map_err(Erro::Protocolo)?;
    let mut cabecalhos = Vec::new();
    loop {
        let linha = entrada.linha(limites.linha)?;
        gasto += linha.len() + 2;
        if gasto > limites.cabeca {
            return Err(Erro::Limite(Limite::Cabeca));
        }
        if linha.is_empty() {
            return Ok((versao, codigo, motivo, cabecalhos));
        }
        if cabecalhos.len() >= limites.cabecalhos {
            return Err(Erro::Limite(Limite::Cabecalhos));
        }
        cabecalhos.push(ler_cabecalho(&linha).map_err(Erro::Protocolo)?);
    }
}

/// Onde o corpo acaba — ver o cabeçalho do módulo.
fn enquadrar<F>(
    metodo: Metodo,
    status: u16,
    cabecalhos: &[(String, String)],
    limites: &Limites,
) -> Result<Enquadramento, Erro<F>> {
    if metodo == Metodo::Head || (100..200).contains(&status) || status == 204 || status == 304 {
        return Ok(Enquadramento::Nenhum);
    }
    let codificado = cabecalhos.iter().any(|(n, _)| n == "transfer-encoding");
    let medido = cabecalhos.iter().any(|(n, _)| n == "content-length");
    if codificado {
        if medido {
            return Err(Erro::Protocolo(Motivo::Ambiguo));
        }
        let mut codificacoes = lista(cabecalhos, "transfer-encoding");
        return match (codificacoes.next(), codificacoes.next()) {
            (Some(c), None) if c.eq_ignore_ascii_case("chunked") => Ok(Enquadramento::Pedacos),
            _ => Err(Erro::Protocolo(Motivo::Codificacao)),
        };
    }
    if !medido {
        return Ok(Enquadramento::AteFechar);
    }
    let mut tamanho = None;
    for parte in cabecalhos
        .iter()
        .filter(|(n, _)| n == "content-length")
        .flat_map(|(_, v)| v.split(','))
    {
        let parte = parte.trim_matches([' ', '\t']);
        if parte.is_empty() || !parte.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Erro::Protocolo(Motivo::Tamanho));
        }
        // Um número que não cabe em 64 bits passa de qualquer limite.
        let n = parte
            .bytes()
            .try_fold(0u64, |n, d| {
                n.checked_mul(10)?.checked_add(u64::from(d - b'0'))
            })
            .ok_or(Erro::Limite(Limite::Corpo))?;
        match tamanho {
            None => tamanho = Some(n),
            Some(t) if t == n => {}
            Some(_) => return Err(Erro::Protocolo(Motivo::Tamanho)),
        }
    }
    let n = tamanho.ok_or(Erro::Protocolo(Motivo::Tamanho))?;
    if n > limites.corpo as u64 {
        return Err(Erro::Limite(Limite::Corpo));
    }
    Ok(Enquadramento::Tamanho(n))
}

/// O tamanho de um pedaço: hexadecimal, e as extensões depois de `;`,
/// conferidas e ignoradas.
fn tamanho_do_pedaco<F>(linha: &[u8]) -> Result<u64, Erro<F>> {
    let fim = linha.iter().position(|&b| b == b';').unwrap_or(linha.len());
    let (hex, extensoes) = linha.split_at(fim);
    // O espaço antes do `;` é permitido (`BWS`); antes do número, não.
    let hex = sem_ows(hex);
    if hex.is_empty() || linha[0] == b' ' || linha[0] == b'\t' {
        return Err(Erro::Protocolo(Motivo::Pedaco));
    }
    if !extensoes.iter().all(|&b| de_valor(b)) {
        return Err(Erro::Protocolo(Motivo::Pedaco));
    }
    let mut n: u64 = 0;
    for &d in hex {
        let v = (d as char)
            .to_digit(16)
            .ok_or(Erro::Protocolo(Motivo::Pedaco))?;
        n = n
            .checked_mul(16)
            .and_then(|n| n.checked_add(u64::from(v)))
            .ok_or(Erro::Limite(Limite::Corpo))?;
    }
    Ok(n)
}

fn ler_pedacos<F: Fluxo>(
    entrada: &mut Entrada<'_, F>,
    limites: &Limites,
) -> Result<Vec<u8>, Erro<F::Falha>> {
    let mut corpo = Vec::new();
    loop {
        let linha = entrada.linha(MAIOR_LINHA_DE_PEDACO.min(limites.linha))?;
        let tamanho = tamanho_do_pedaco(&linha)?;
        if tamanho == 0 {
            break;
        }
        if corpo.len() as u64 + tamanho > limites.corpo as u64 {
            return Err(Erro::Limite(Limite::Corpo));
        }
        entrada.exatos(tamanho as usize, &mut corpo)?;
        entrada.crlf()?;
    }
    // Os *trailers*: conferidos como cabeçalhos, com os limites da cabeça,
    // e largados — nenhum deles muda o que já foi lido.
    let mut gasto = 0;
    let mut quantos = 0;
    loop {
        let linha = entrada.linha(limites.linha)?;
        gasto += linha.len() + 2;
        if gasto > limites.cabeca {
            return Err(Erro::Limite(Limite::Cabeca));
        }
        if linha.is_empty() {
            return Ok(corpo);
        }
        quantos += 1;
        if quantos > limites.cabecalhos {
            return Err(Erro::Limite(Limite::Cabecalhos));
        }
        ler_cabecalho(&linha).map_err(Erro::Protocolo)?;
    }
}

fn ler_corpo<F: Fluxo>(
    entrada: &mut Entrada<'_, F>,
    enquadramento: Enquadramento,
    limites: &Limites,
) -> Result<Vec<u8>, Erro<F::Falha>> {
    match enquadramento {
        Enquadramento::Nenhum => Ok(Vec::new()),
        Enquadramento::Tamanho(n) => {
            // `n` já passou pelo limite do corpo.
            let mut corpo = Vec::with_capacity(n as usize);
            entrada.exatos(n as usize, &mut corpo)?;
            Ok(corpo)
        }
        Enquadramento::Pedacos => ler_pedacos(entrada, limites),
        Enquadramento::AteFechar => {
            let mut corpo = Vec::new();
            loop {
                if corpo.len() + entrada.buffer.len() > limites.corpo {
                    return Err(Erro::Limite(Limite::Corpo));
                }
                corpo.append(entrada.buffer);
                if !entrada.encher()? {
                    return Ok(corpo);
                }
            }
        }
    }
}

/// Lê a resposta ao pedido `metodo`, que aceitou as codificações
/// `aceitas`, de `fluxo`, começando pelo que já está em `buffer` — o que
/// sobrar fica nele.
pub(crate) fn ler<F: Fluxo>(
    fluxo: &mut F,
    buffer: &mut Vec<u8>,
    metodo: Metodo,
    aceitas: Aceitas,
    limites: &Limites,
) -> Result<Resposta, Erro<F::Falha>> {
    let mut entrada = Entrada { fluxo, buffer };
    let mut informativas = 0;
    loop {
        let (versao, status, motivo, cabecalhos) = ler_cabeca(&mut entrada, limites)?;
        if status == 101 {
            return Err(Erro::Protocolo(Motivo::Troca));
        }
        if (100..200).contains(&status) {
            informativas += 1;
            if informativas > MAIS_INFORMATIVAS {
                return Err(Erro::Protocolo(Motivo::Informativas));
            }
            continue;
        }
        let enquadramento = enquadrar(metodo, status, &cabecalhos, limites)?;
        // Sem corpo, não há o que decodificar: o `Content-Encoding` de um
        // `HEAD` ou de um `304` fala da representação, e não desta resposta.
        let codificacao = match enquadramento {
            Enquadramento::Nenhum => None,
            _ => codificacao::da_resposta(&cabecalhos, aceitas).map_err(Erro::Conteudo)?,
        };
        let como_veio = ler_corpo(&mut entrada, enquadramento, limites)?;
        let no_fio = como_veio.len();
        let corpo = match codificacao {
            // O corpo vazio é a representação vazia: não há fluxo para
            // conferir, nem conteúdo para cortar.
            Some(c) if no_fio > 0 => {
                codificacao::decodificar(c, &como_veio, limites.descomprimido)?
            }
            _ => como_veio,
        };
        let conexao =
            |token: &str| lista(&cabecalhos, "connection").any(|t| t.eq_ignore_ascii_case(token));
        let manter = match versao {
            Versao::Http11 => !conexao("close"),
            Versao::Http10 => conexao("keep-alive") && !conexao("close"),
        };
        let reutilizavel =
            manter && enquadramento != Enquadramento::AteFechar && entrada.buffer.is_empty();
        return Ok(Resposta {
            versao,
            status,
            motivo,
            cabecalhos,
            corpo,
            codificacao,
            no_fio,
            cookies: Guardados::default(),
            enquadramento,
            reutilizavel,
        });
    }
}
