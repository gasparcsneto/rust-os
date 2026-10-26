//! O pacote: os arquivos que vêm com a imagem — os programas e os dados
//! públicos —, num índice simples.
//!
//! # Por que não um Btrfs
//!
//! Porque o `mkfs.btrfs` não faz um volume com menos de 109 MiB: pedido
//! menor, ele estende o arquivo calado. Um slot com um Btrfs dentro teria
//! isso só de piso, para alguns mebibytes de programas. O pacote é o que o
//! slot precisa e nada mais: uma lista de arquivos só de leitura, que o
//! kernel monta por cima da raiz.
//!
//! # O formato
//!
//! ```text
//!    0  "DUKEPAC1"        a magia
//!    8  versão u16 LE     hoje 1
//!   10  reservado u16     zero
//!   12  quantos u32 LE    arquivos
//!   16  índice u32 LE     bytes do cabeçalho e das entradas
//!   20  reservado         zeros até 32
//!   32  entradas, cada uma: [tamanho do caminho u16][caminho]
//!                            [deslocamento u64][tamanho u64]
//!       os dados, um arquivo depois do outro, a partir do fim do índice
//! ```
//!
//! # Uma escrita só
//!
//! As entradas vêm em ordem estrita de caminho; os dados, na mesma ordem,
//! colados — o primeiro começa no fim do índice, cada um onde o anterior
//! acaba, e o último acaba no fim do pacote. Um caminho é relativo, de
//! partes de `[A-Za-z0-9._+-]` que não são `.` nem `..`, com de duas a
//! [`MAIS_NIVEIS`] partes; um arquivo não é também diretório de outro.
//!
//! Duas partes no mínimo porque o kernel monta cada diretório do topo em
//! `/<nome>`, por cima da raiz: um arquivo solto no topo não teria onde
//! ser montado, e ficaria no pacote sem ninguém o ver.
//!
//! E nada em `etc/`: a configuração e a identidade da máquina moram na
//! raiz, e uma atualização não as troca.

use crate::TAM_SETOR;

/// A magia.
pub const MAGIA: [u8; 8] = *b"DUKEPAC1";

/// A versão do formato.
pub const VERSAO: u16 = 1;

/// O cabeçalho, antes das entradas.
pub const TAM_CABECALHO: usize = 32;

/// O maior número de arquivos.
pub const MAIS_ARQUIVOS: usize = 4096;

/// O maior índice: o cabeçalho e as entradas.
pub const MAIOR_INDICE: usize = 1024 * 1024;

/// O maior caminho.
pub const MAIOR_CAMINHO: usize = 255;

/// A profundidade máxima de um caminho.
pub const MAIS_NIVEIS: usize = 8;

/// O que o pacote não pode ter no topo.
const PROIBIDO_NO_TOPO: &str = "etc";

/// Uma entrada do índice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entrada<'a> {
    pub caminho: &'a str,
    /// Desde o começo do pacote.
    pub deslocamento: u64,
    pub tamanho: u64,
}

/// O que o cabeçalho diz: quantos arquivos, e o tamanho do índice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cabecalho {
    pub quantos: u32,
    pub indice: u32,
}

/// Lê o cabeçalho dos primeiros [`TAM_CABECALHO`] bytes.
pub fn cabecalho(b: &[u8]) -> Result<Cabecalho, &'static str> {
    let b = b.get(..TAM_CABECALHO).ok_or("pacote sem cabecalho")?;
    if b[..8] != MAGIA {
        return Err("o pacote nao tem a magia");
    }
    if u16::from_le_bytes([b[8], b[9]]) != VERSAO {
        return Err("o pacote e de outra versao");
    }
    if b[10..12] != [0, 0] || b[20..32].iter().any(|&x| x != 0) {
        return Err("o pacote tem reservado sujo");
    }
    let quantos = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
    let indice = u32::from_le_bytes([b[16], b[17], b[18], b[19]]);
    if quantos as usize > MAIS_ARQUIVOS {
        return Err("o pacote tem arquivos demais");
    }
    if (indice as usize) < TAM_CABECALHO || indice as usize > MAIOR_INDICE {
        return Err("o indice do pacote tem tamanho implausivel");
    }
    Ok(Cabecalho { quantos, indice })
}

/// Se `caminho` é um caminho de pacote.
pub fn caminho_valido(caminho: &str) -> bool {
    if caminho.is_empty() || caminho.len() > MAIOR_CAMINHO {
        return false;
    }
    let mut niveis = 0;
    for (i, parte) in caminho.split('/').enumerate() {
        niveis += 1;
        if parte.is_empty()
            || parte == "."
            || parte == ".."
            || !parte
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'+' | b'-'))
            || (i == 0 && parte == PROIBIDO_NO_TOPO)
        {
            return false;
        }
    }
    (2..=MAIS_NIVEIS).contains(&niveis)
}

/// As entradas de um índice — `indice` é o cabeçalho e as entradas,
/// inteiros —, conferidas uma a uma contra as regras do formato (ver o
/// começo deste módulo) e um pacote de `total` bytes. Uma entrada que não
/// confere é o último item, um `Err`.
pub fn entradas(indice: &[u8], total: u64) -> Entradas<'_> {
    Entradas::nova(indice, total)
}

/// O iterador de [`entradas`].
pub struct Entradas<'a> {
    indice: &'a [u8],
    total: u64,
    quantos: u32,
    lidas: u32,
    em: usize,
    /// Onde o próximo arquivo tem de começar.
    proximo: u64,
    anterior: Option<&'a str>,
    falhou: bool,
}

impl<'a> Entradas<'a> {
    fn nova(indice: &'a [u8], total: u64) -> Entradas<'a> {
        let (quantos, proximo, falhou) = match cabecalho(indice) {
            Ok(c) if c.indice as usize == indice.len() && u64::from(c.indice) <= total => {
                (c.quantos, u64::from(c.indice), false)
            }
            _ => (0, 0, true),
        };
        Entradas {
            indice,
            total,
            quantos,
            lidas: 0,
            em: TAM_CABECALHO,
            proximo,
            anterior: None,
            falhou,
        }
    }

    fn ler(&mut self) -> Result<Option<Entrada<'a>>, &'static str> {
        if self.falhou {
            return Err("o cabecalho do pacote nao confere com o indice");
        }
        if self.lidas == self.quantos {
            if self.em != self.indice.len() {
                return Err("o indice do pacote tem bytes depois da ultima entrada");
            }
            if self.proximo != self.total {
                return Err("os dados do pacote nao acabam no fim dele");
            }
            return Ok(None);
        }
        let b = self.indice;
        let n = b
            .get(self.em..self.em + 2)
            .map(|t| u16::from_le_bytes([t[0], t[1]]) as usize)
            .ok_or("entrada do pacote cortada")?;
        let caminho = b
            .get(self.em + 2..self.em + 2 + n)
            .and_then(|c| core::str::from_utf8(c).ok())
            .ok_or("caminho do pacote cortado ou nao e texto")?;
        let numeros = b
            .get(self.em + 2 + n..self.em + 2 + n + 16)
            .ok_or("entrada do pacote cortada")?;
        let deslocamento = u64::from_le_bytes(numeros[..8].try_into().unwrap_or([0; 8]));
        let tamanho = u64::from_le_bytes(numeros[8..].try_into().unwrap_or([0; 8]));
        if !caminho_valido(caminho) {
            return Err("caminho do pacote fora da regra");
        }
        if let Some(anterior) = self.anterior {
            if caminho <= anterior {
                return Err("os caminhos do pacote nao estao em ordem estrita");
            }
            // Um arquivo não é diretório de outro: `a/b` e `a/b/c`.
            if caminho
                .strip_prefix(anterior)
                .is_some_and(|resto| resto.starts_with('/'))
            {
                return Err("um arquivo do pacote e diretorio de outro");
            }
        }
        if deslocamento != self.proximo {
            return Err("os dados do pacote nao estao colados na ordem do indice");
        }
        let fim = deslocamento
            .checked_add(tamanho)
            .filter(|&f| f <= self.total)
            .ok_or("um arquivo do pacote passa do fim dele")?;
        self.em += 2 + n + 16;
        self.lidas += 1;
        self.proximo = fim;
        self.anterior = Some(caminho);
        Ok(Some(Entrada {
            caminho,
            deslocamento,
            tamanho,
        }))
    }
}

impl<'a> Iterator for Entradas<'a> {
    type Item = Result<Entrada<'a>, &'static str>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.falhou && self.lidas > self.quantos {
            return None;
        }
        match self.ler() {
            Ok(Some(e)) => Some(Ok(e)),
            Ok(None) => None,
            Err(m) => {
                // Depois de um erro, nada mais.
                self.falhou = true;
                self.lidas = self.quantos + 1;
                Some(Err(m))
            }
        }
    }
}

/// Confere um índice inteiro: `Ok(quantos)` se cada entrada confere e os
/// dados fecham o pacote.
pub fn conferir(indice: &[u8], total: u64) -> Result<usize, &'static str> {
    let mut n = 0;
    for e in entradas(indice, total) {
        e?;
        n += 1;
    }
    Ok(n)
}

/// Um pacote vazio: só o cabeçalho, nenhum arquivo.
pub const fn vazio() -> [u8; TAM_CABECALHO] {
    let mut b = [0u8; TAM_CABECALHO];
    let mut i = 0;
    while i < 8 {
        b[i] = MAGIA[i];
        i += 1;
    }
    let v = VERSAO.to_le_bytes();
    b[8] = v[0];
    b[9] = v[1];
    let t = (TAM_CABECALHO as u32).to_le_bytes();
    b[16] = t[0];
    b[17] = t[1];
    b[18] = t[2];
    b[19] = t[3];
    b
}

/// Monta um pacote de `arquivos` — `(caminho, conteúdo)`, em qualquer
/// ordem —, arredondado ao setor só no slot, não aqui: o tamanho do pacote
/// é o que o manifesto diz.
#[cfg(feature = "alloc")]
pub fn montar(arquivos: &[(&str, &[u8])]) -> Result<alloc::vec::Vec<u8>, &'static str> {
    use alloc::vec::Vec;
    if arquivos.len() > MAIS_ARQUIVOS {
        return Err("arquivos demais para um pacote");
    }
    let mut ordem: Vec<&(&str, &[u8])> = arquivos.iter().collect();
    ordem.sort_by(|a, b| a.0.cmp(b.0));
    let indice = TAM_CABECALHO + ordem.iter().map(|(c, _)| 2 + c.len() + 16).sum::<usize>();
    if indice > MAIOR_INDICE {
        return Err("indice grande demais para um pacote");
    }
    let mut v = Vec::with_capacity(indice + ordem.iter().map(|(_, d)| d.len()).sum::<usize>());
    v.extend_from_slice(&vazio());
    v[12..16].copy_from_slice(&(ordem.len() as u32).to_le_bytes());
    v[16..20].copy_from_slice(&(indice as u32).to_le_bytes());
    let mut deslocamento = indice as u64;
    for (caminho, dados) in &ordem {
        if !caminho_valido(caminho) {
            return Err("caminho fora da regra do pacote");
        }
        v.extend_from_slice(&(caminho.len() as u16).to_le_bytes());
        v.extend_from_slice(caminho.as_bytes());
        v.extend_from_slice(&deslocamento.to_le_bytes());
        v.extend_from_slice(&(dados.len() as u64).to_le_bytes());
        deslocamento += dados.len() as u64;
    }
    for (_, dados) in &ordem {
        v.extend_from_slice(dados);
    }
    conferir(&v[..indice], v.len() as u64)?;
    Ok(v)
}

/// Quantos setores um pacote de `bytes` ocupa.
pub const fn setores(bytes: u64) -> u64 {
    bytes.div_ceil(TAM_SETOR as u64)
}

#[cfg(all(test, feature = "alloc"))]
mod testes {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    fn exemplo() -> Vec<u8> {
        montar(&[
            ("programas/x86_64/livro", b"livro"),
            ("dados/tls/publicas.pem", b"pem"),
            ("programas/x86_64/gestor", b"gestor!"),
        ])
        .unwrap()
    }

    #[test]
    fn ida_e_volta_em_ordem() {
        let p = exemplo();
        let c = cabecalho(&p).unwrap();
        let indice = &p[..c.indice as usize];
        let lidas: Vec<_> = entradas(indice, p.len() as u64)
            .map(|e| e.unwrap())
            .collect();
        let caminhos: Vec<_> = lidas.iter().map(|e| e.caminho).collect();
        assert_eq!(
            caminhos,
            [
                "dados/tls/publicas.pem",
                "programas/x86_64/gestor",
                "programas/x86_64/livro"
            ]
        );
        let gestor = lidas[1];
        let d = gestor.deslocamento as usize;
        assert_eq!(&p[d..d + gestor.tamanho as usize], b"gestor!");
        assert_eq!(conferir(indice, p.len() as u64), Ok(3));
    }

    #[test]
    fn o_vazio_confere() {
        let v = vazio();
        assert_eq!(conferir(&v, v.len() as u64), Ok(0));
    }

    #[test]
    fn recusa_caminhos_fora_da_regra() {
        for ruim in [
            "",
            "/abs",
            "a//b",
            "a/./b",
            "a/../b",
            "etc/duke/politica",
            "etc",
            "a b",
            "a/b/c/d/e/f/g/h/i",
            "solto",
        ] {
            assert!(!caminho_valido(ruim), "{ruim}");
            assert!(montar(&[(ruim, b"x")]).is_err());
        }
        assert!(caminho_valido("dados/etc/ok"));
        assert!(caminho_valido("programas/x86_64/gestor"));
    }

    #[test]
    fn recusa_o_arquivo_que_e_diretorio_de_outro() {
        assert!(montar(&[("a/b", b"1"), ("a/b/c", b"2")]).is_err());
        assert!(montar(&[("a/b", b"1"), ("a/b", b"2")]).is_err());
        assert!(montar(&[("a/b", b"1"), ("a/bc", b"2")]).is_ok());
    }

    #[test]
    fn recusa_dados_fora_do_lugar() {
        let p = exemplo();
        let c = cabecalho(&p).unwrap();
        let n = c.indice as usize;
        // Um byte a mais no fim: os dados não acabam no fim do pacote.
        assert!(conferir(&p[..n], p.len() as u64 + 1).is_err());
        // Um deslocamento trocado: os dados não estão colados.
        let mut ruim = p.clone();
        let primeira = TAM_CABECALHO + 2 + "dados/tls/publicas.pem".len();
        ruim[primeira] ^= 1;
        assert!(conferir(&ruim[..n], ruim.len() as u64).is_err());
        // Uma entrada a menos no cabeçalho: sobram bytes no índice.
        let mut menos = p.clone();
        menos[12..16].copy_from_slice(&2u32.to_le_bytes());
        assert!(conferir(&menos[..n], menos.len() as u64).is_err());
        // O índice maior que o pacote.
        assert!(conferir(&p[..n], 10).is_err());
        // A magia trocada.
        let mut magia = p;
        magia[0] ^= 1;
        assert!(conferir(&magia[..n], magia.len() as u64).is_err());
    }
}
