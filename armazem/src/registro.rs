//! As entradas do journal do armazém: como cada [`Mudanca`] vai para um
//! registro, e volta.
//!
//! Cada entrada é uma lista de campos (`diario::estado::campos`): o tipo,
//! em dois bytes, e os campos dele.
//!
//! | tipo | campos |
//! |---|---|
//! | [`tipo::ARQUIVO`] | caminho, versão (8), tamanho (8), dono, extensões |
//! | [`tipo::DIRETORIO`] | caminho, versão (8), dono |
//! | [`tipo::REMOVIDO`] | caminho, versão (8) |
//! | [`tipo::MOVIDO`] | origem, destino, versão (8) |
//! | [`tipo::PROXIMA`] | versão (8) — só na base |
//! | [`tipo::VOLUME`] | id (16), setores (8), setores do journal (8) |
//!
//! As extensões vão juntas num campo, cada uma em 36 bytes: o bloco (8), a
//! quantidade (4), o id da escrita (16) e o índice lógico (8).

use alloc::string::String;
use alloc::vec::Vec;

use diario::estado::{campos, ler_campos};

use crate::{Conteudo, Extensao, MAIS_EXTENSOES, Mudanca, No};

/// Os tipos de entrada.
pub mod tipo {
    pub const ARQUIVO: u16 = 1;
    pub const DIRETORIO: u16 = 2;
    pub const REMOVIDO: u16 = 3;
    pub const MOVIDO: u16 = 4;
    pub const PROXIMA: u16 = 5;
    pub const VOLUME: u16 = 6;
}

/// O tamanho de uma extensão no registro.
pub const TAM_EXTENSAO: usize = 36;

/// A geometria e a identidade de um volume: o que a abertura do journal
/// dele diz, e o que o journal de estado guarda para conferir no boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Volume {
    pub id: [u8; 16],
    /// Quantos setores o volume tem: a partição inteira.
    pub setores: u64,
    /// Quantos setores do começo são do journal; o resto, da área de dados.
    pub setores_do_diario: u64,
}

/// O que uma entrada diz.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entrada {
    Mudanca(Mudanca),
    Proxima(u64),
    Volume(Volume),
}

fn com_tipo(t: u16, resto: &[&[u8]]) -> Result<Vec<u8>, &'static str> {
    let t = t.to_le_bytes();
    let mut todos: Vec<&[u8]> = Vec::with_capacity(resto.len() + 1);
    todos.push(&t);
    todos.extend_from_slice(resto);
    campos(&todos)
}

fn extensoes(c: &Conteudo) -> Vec<u8> {
    let mut v = Vec::with_capacity(c.extensoes.len() * TAM_EXTENSAO);
    for e in &c.extensoes {
        v.extend_from_slice(&e.bloco.to_le_bytes());
        v.extend_from_slice(&e.quantos.to_le_bytes());
        v.extend_from_slice(&e.id);
        v.extend_from_slice(&e.indice.to_le_bytes());
    }
    v
}

/// A entrada de uma mudança.
pub fn codificar(m: &Mudanca) -> Result<Vec<u8>, &'static str> {
    match m {
        Mudanca::Arquivo {
            caminho,
            versao,
            conteudo,
            dono,
        } => arquivo(caminho, *versao, conteudo, dono),
        Mudanca::Diretorio {
            caminho,
            versao,
            dono,
        } => com_tipo(
            tipo::DIRETORIO,
            &[caminho.as_bytes(), &versao.to_le_bytes(), dono.as_bytes()],
        ),
        Mudanca::Removido { caminho, versao } => {
            com_tipo(tipo::REMOVIDO, &[caminho.as_bytes(), &versao.to_le_bytes()])
        }
        Mudanca::Movido { de, para, versao } => com_tipo(
            tipo::MOVIDO,
            &[de.as_bytes(), para.as_bytes(), &versao.to_le_bytes()],
        ),
    }
}

fn arquivo(caminho: &str, versao: u64, c: &Conteudo, dono: &str) -> Result<Vec<u8>, &'static str> {
    if c.extensoes.len() > MAIS_EXTENSOES {
        return Err("extensoes demais num arquivo");
    }
    com_tipo(
        tipo::ARQUIVO,
        &[
            caminho.as_bytes(),
            &versao.to_le_bytes(),
            &c.tamanho.to_le_bytes(),
            dono.as_bytes(),
            &extensoes(c),
        ],
    )
}

/// A entrada de um nó, para a base de uma compactação: o mesmo formato da
/// mudança que o criaria.
pub fn codificar_no(caminho: &str, no: &No) -> Result<Vec<u8>, &'static str> {
    match no {
        No::Arquivo {
            versao,
            conteudo,
            dono,
        } => arquivo(caminho, *versao, conteudo, dono),
        No::Diretorio { versao, dono } => com_tipo(
            tipo::DIRETORIO,
            &[caminho.as_bytes(), &versao.to_le_bytes(), dono.as_bytes()],
        ),
    }
}

/// A entrada da próxima versão, na base.
pub fn proxima(n: u64) -> Result<Vec<u8>, &'static str> {
    com_tipo(tipo::PROXIMA, &[&n.to_le_bytes()])
}

/// A entrada do volume, na abertura e no fecho de uma base.
pub fn volume(v: &Volume) -> Result<Vec<u8>, &'static str> {
    com_tipo(
        tipo::VOLUME,
        &[
            &v.id,
            &v.setores.to_le_bytes(),
            &v.setores_do_diario.to_le_bytes(),
        ],
    )
}

fn u64_de(b: &[u8]) -> Result<u64, &'static str> {
    Ok(u64::from_le_bytes(
        b.try_into().map_err(|_| "numero que nao tem 8 bytes")?,
    ))
}

fn texto(b: &[u8]) -> Result<String, &'static str> {
    core::str::from_utf8(b)
        .map(String::from)
        .map_err(|_| "texto que nao e utf-8")
}

fn extensoes_de(b: &[u8]) -> Result<Vec<Extensao>, &'static str> {
    let (pedacos, sobra) = b.as_chunks::<TAM_EXTENSAO>();
    if !sobra.is_empty() || pedacos.len() > MAIS_EXTENSOES {
        return Err("campo de extensoes de tamanho impossivel");
    }
    Ok(pedacos
        .iter()
        .map(|e| Extensao {
            bloco: u64::from_le_bytes(e[0..8].try_into().unwrap_or_default()),
            quantos: u32::from_le_bytes(e[8..12].try_into().unwrap_or_default()),
            id: e[12..28].try_into().unwrap_or_default(),
            indice: u64::from_le_bytes(e[28..36].try_into().unwrap_or_default()),
        })
        .collect())
}

/// O que uma entrada diz. Recusa a que não se lê exatamente.
pub fn decodificar(entrada: &[u8]) -> Result<Entrada, &'static str> {
    let f = ler_campos(entrada)?;
    let (t, resto) = f.split_first().ok_or("entrada vazia")?;
    let t = u16::from_le_bytes((*t).try_into().map_err(|_| "tipo sem 2 bytes")?);
    Ok(match (t, resto) {
        (tipo::ARQUIVO, [c, v, n, d, e]) => Entrada::Mudanca(Mudanca::Arquivo {
            caminho: texto(c)?,
            versao: u64_de(v)?,
            conteudo: Conteudo {
                tamanho: u64_de(n)?,
                extensoes: extensoes_de(e)?,
            },
            dono: texto(d)?,
        }),
        (tipo::DIRETORIO, [c, v, d]) => Entrada::Mudanca(Mudanca::Diretorio {
            caminho: texto(c)?,
            versao: u64_de(v)?,
            dono: texto(d)?,
        }),
        (tipo::REMOVIDO, [c, v]) => Entrada::Mudanca(Mudanca::Removido {
            caminho: texto(c)?,
            versao: u64_de(v)?,
        }),
        (tipo::MOVIDO, [de, para, v]) => Entrada::Mudanca(Mudanca::Movido {
            de: texto(de)?,
            para: texto(para)?,
            versao: u64_de(v)?,
        }),
        (tipo::PROXIMA, [v]) => Entrada::Proxima(u64_de(v)?),
        (tipo::VOLUME, [id, s, d]) => Entrada::Volume(Volume {
            id: (*id).try_into().map_err(|_| "id de volume sem 16 bytes")?,
            setores: u64_de(s)?,
            setores_do_diario: u64_de(d)?,
        }),
        _ => return Err("entrada do armazem desconhecida, ou com os campos errados"),
    })
}

/// O conteúdo de um registro de lote: as entradas das mudanças, uma por
/// campo.
pub fn lote(mudancas: &[Mudanca]) -> Result<Vec<u8>, &'static str> {
    let entradas = mudancas
        .iter()
        .map(codificar)
        .collect::<Result<Vec<_>, _>>()?;
    campos(&entradas.iter().map(Vec::as_slice).collect::<Vec<_>>())
}

/// As entradas de um registro.
pub fn entradas(conteudo: &[u8]) -> Result<Vec<Entrada>, &'static str> {
    ler_campos(conteudo)?.into_iter().map(decodificar).collect()
}
