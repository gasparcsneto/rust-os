//! Os itens da árvore de arquivos: inodes, diretórios e extensões.
//!
//! # O que cada um responde
//!
//! O `INODE_ITEM` diz o que um objeto é e quanto ele ocupa. O `DIR_ITEM` liga
//! um **nome** ao número do inode dele, e é o que uma busca de caminho
//! consulta. O `EXTENT_DATA` diz onde os bytes moram — e num arquivo pequeno
//! a resposta é "aqui dentro", porque o Btrfs guarda o conteúdo no próprio
//! item em vez de gastar um bloco inteiro para vinte e nove bytes.
//!
//! # Como os itens são alcançados
//!
//! Por [`super::Volume::percorrer`], que desce pelas chaves e atravessa
//! folhas. Este módulo interpreta os bytes de cada item; quem os encontra é
//! a árvore.
//!
//! Por muito tempo ele leu **uma folha** — o que bastava enquanto o disco
//! tinha meia dúzia de arquivos e a árvore cabia num nó. O limite estava
//! escrito e conferido: um nó interno era recusado em vez de lido como
//! folha, porque um leitor que ignorasse o nível devolveria os arquivos do
//! primeiro nó e nada dos outros — um sistema de arquivos que parece
//! funcionar e esconde a maior parte do conteúdo.
//!
//! # O limite que fica
//!
//! Ele lê **uma extensão por arquivo**: o `achar` devolve o primeiro
//! `EXTENT_DATA` do inode, que é o que começa no byte zero. Um arquivo
//! escrito em pedaços tem um item por pedaço, com o deslocamento na chave, e
//! deste leitor sairia só o primeiro — truncado, não corrompido, porque o
//! tamanho da extensão limita a leitura e o laço do `ler_tudo` para quando
//! ela acaba. Um arquivo de até 128 MiB gravado de uma vez, como os que o
//! `mkfs.btrfs` põe na imagem, tem uma extensão só.
//!
//! Agora que a descida existe, escolher a extensão pelo deslocamento é uma
//! mudança pequena — trocar a chave procurada por `(inode, EXTENSAO, off)`.
//! Ela entra quando houver na imagem um arquivo que precise dela, porque um
//! caminho que nenhum arquivo percorre é um caminho que nenhum caso prova.

use super::folha;
use super::{Passo, Volume};

/// Os tipos de item que a árvore de arquivos usa.
pub mod tipo {
    pub const INODE: u8 = 1;
    pub const DIRETORIO: u8 = 84;
    pub const EXTENSAO: u8 = 108;
}

/// O número da árvore de arquivos dentro da árvore de raízes.
pub const ARVORE_DE_ARQUIVOS: u64 = 5;

/// Deslocamentos dentro de um `btrfs_inode_item`.
mod inode {
    pub const TAMANHO: usize = 16;
    pub const MODO: usize = 52;
}

/// Deslocamentos dentro de uma entrada de `btrfs_dir_item`.
///
/// Um item pode conter **mais de uma** entrada: a chave delas é um resumo do
/// nome, e dois nomes que colidem moram no mesmo item, um depois do outro.
/// Ler só a primeira acharia um dos dois e diria que o outro não existe.
mod diretorio {
    pub const OBJETO: usize = 0;
    pub const TIPO_DA_CHAVE: usize = 8;
    pub const TAMANHO_DO_DADO: usize = 25;
    pub const TAMANHO_DO_NOME: usize = 27;
    pub const CABECALHO: usize = 30;
}

/// Deslocamentos dentro de um `btrfs_file_extent_item`.
mod extensao {
    pub const COMPRESSAO: usize = 16;
    pub const TIPO: usize = 20;
    /// Onde os bytes começam, quando a extensão é embutida.
    pub const EMBUTIDA_EM: usize = 21;
    /// Os campos de uma extensão normal.
    pub const ENDERECO: usize = 21;
    pub const DESLOCAMENTO: usize = 37;
    pub const QUANTOS: usize = 45;
}

/// Uma extensão embutida guarda o conteúdo no próprio item.
const EXTENSAO_EMBUTIDA: u8 = 0;
/// Uma normal aponta para um endereço lógico.
const EXTENSAO_NORMAL: u8 = 1;

/// O que um inode é.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Especie {
    Arquivo,
    Diretorio,
    Outro,
}

/// O que o item de inode diz.
///
/// O número do inode não está aqui de propósito: quem chama já o tem na mão
/// — foi por ele que o item foi achado. Guardá-lo seria uma segunda cópia da
/// mesma verdade, com a chance de as duas divergirem.
#[derive(Clone, Copy, Debug)]
pub struct Inode {
    pub tamanho: u64,
    pub especie: Especie,
}

fn u64_em(bytes: &[u8], em: usize) -> Option<u64> {
    let fatia = bytes.get(em..em + 8)?;
    Some(u64::from_le_bytes(fatia.try_into().ok()?))
}

fn u32_em(bytes: &[u8], em: usize) -> Option<u32> {
    let fatia = bytes.get(em..em + 4)?;
    Some(u32::from_le_bytes(fatia.try_into().ok()?))
}

fn u16_em(bytes: &[u8], em: usize) -> Option<u16> {
    let fatia = bytes.get(em..em + 2)?;
    Some(u16::from_le_bytes(fatia.try_into().ok()?))
}

/// Interpreta um item de inode.
pub fn ler_inode(dados: &[u8]) -> Option<Inode> {
    let tamanho = u64_em(dados, inode::TAMANHO)?;
    let modo = u32_em(dados, inode::MODO)?;
    // Os quatro bits altos do modo são o tipo do objeto, como em todo Unix.
    let especie = match modo & 0xF000 {
        0x8000 => Especie::Arquivo,
        0x4000 => Especie::Diretorio,
        _ => Especie::Outro,
    };
    Some(Inode { tamanho, especie })
}

/// Uma entrada de diretório: um nome e para onde ele aponta.
pub struct Entrada<'i> {
    pub nome: &'i [u8],
    /// O número do inode.
    pub objeto: u64,
    /// O tipo da chave para onde a entrada aponta. Só `INODE_ITEM` é seguido.
    pub tipo_da_chave: u8,
}

/// Percorre as entradas de um item de diretório.
///
/// Devolve `None` no fim, e para no primeiro campo que não fizer sentido: um
/// tamanho de nome que passe do item faria a fatia do nome sair do item e
/// entrar no vizinho.
pub fn entradas(dados: &[u8]) -> impl Iterator<Item = Entrada<'_>> {
    let mut em = 0usize;
    core::iter::from_fn(move || {
        let resto = dados.get(em..)?;
        if resto.len() < diretorio::CABECALHO {
            return None;
        }

        let tamanho_do_nome = u16_em(resto, diretorio::TAMANHO_DO_NOME)? as usize;
        let tamanho_do_dado = u16_em(resto, diretorio::TAMANHO_DO_DADO)? as usize;
        let fim = diretorio::CABECALHO.checked_add(tamanho_do_nome)?;
        let nome = resto.get(diretorio::CABECALHO..fim)?;

        let entrada = Entrada {
            nome,
            objeto: u64_em(resto, diretorio::OBJETO)?,
            tipo_da_chave: resto[diretorio::TIPO_DA_CHAVE],
        };
        em += fim + tamanho_do_dado;
        Some(entrada)
    })
}

/// Onde os bytes de um arquivo estão.
#[derive(Clone, Copy, Debug)]
pub enum Conteudo {
    /// Dentro do próprio item, a partir deste deslocamento.
    Embutido { em: usize, quantos: usize },
    /// Num endereço lógico, que precisa ser traduzido.
    Normal { endereco: u64, quantos: u64 },
    /// Um buraco: o arquivo tem tamanho ali e não há bloco nenhum.
    ///
    /// Acontece num arquivo esparso, e o conteúdo certo são zeros — não um
    /// erro, e não os bytes que estiverem no endereço zero.
    Buraco { quantos: u64 },
}

/// Interpreta um item de extensão.
pub fn ler_extensao(dados: &[u8]) -> Result<Conteudo, &'static str> {
    let compressao = *dados.get(extensao::COMPRESSAO).ok_or("extensao truncada")?;
    if compressao != 0 {
        // Descomprimir é um algoritmo inteiro por método, e um leitor que
        // entregasse os bytes comprimidos como se fossem o arquivo seria pior
        // que um que recusa.
        return Err("extensao comprimida, que este leitor nao descomprime");
    }

    let tipo = *dados.get(extensao::TIPO).ok_or("extensao truncada")?;
    match tipo {
        EXTENSAO_EMBUTIDA => Ok(Conteudo::Embutido {
            em: extensao::EMBUTIDA_EM,
            quantos: dados.len().saturating_sub(extensao::EMBUTIDA_EM),
        }),
        EXTENSAO_NORMAL => {
            let endereco = u64_em(dados, extensao::ENDERECO).ok_or("extensao truncada")?;
            let quantos = u64_em(dados, extensao::QUANTOS).ok_or("extensao truncada")?;
            if endereco == 0 {
                return Ok(Conteudo::Buraco { quantos });
            }
            let deslocamento = u64_em(dados, extensao::DESLOCAMENTO).ok_or("extensao truncada")?;
            Ok(Conteudo::Normal {
                endereco: endereco
                    .checked_add(deslocamento)
                    .ok_or("extensao com endereco impossivel")?,
                quantos,
            })
        }
        _ => Err("extensao pre-alocada, que este leitor nao le"),
    }
}

/// Para onde uma entrada de diretório aponta, sem emprestar o item.
///
/// A [`Entrada`] traz o nome como fatia do próprio item, que morre com a
/// folha em que ele estava. Quem sobrevive ao percurso é isto.
pub struct Achada {
    pub objeto: u64,
    pub tipo_da_chave: u8,
}

/// Procura um nome dentro de um diretório.
///
/// # Por que percorrer em vez de buscar pela chave do nome
///
/// Porque a chave de um `DIR_ITEM` é um **resumo** do nome, calculado com
/// crc32c e uma semente específica. Buscá-lo direto exigiria reproduzir esse
/// resumo aqui, e uma segunda implementação de um cálculo é uma segunda
/// chance de ele divergir — com o sintoma "este arquivo não existe" para um
/// arquivo que existe.
///
/// O que a descida já resolve, e é o que importava, é não ler a árvore
/// inteira: o percurso começa na primeira chave do diretório e **para** na
/// primeira que sai dele. Os itens de um diretório são contíguos na ordem
/// das chaves, então o custo é proporcional ao tamanho do diretório, e não
/// ao do sistema de arquivos.
pub fn procurar(
    volume: &Volume,
    raiz: u64,
    diretorio: u64,
    nome: &str,
) -> Result<Option<Achada>, &'static str> {
    let mut achada = None;
    volume.percorrer(
        raiz,
        folha::Chave::primeira_de(diretorio, tipo::DIRETORIO),
        |item| {
            if item.chave.objeto != diretorio || item.chave.tipo != tipo::DIRETORIO {
                return Passo::Para;
            }
            for entrada in entradas(item.dados) {
                if entrada.nome == nome.as_bytes() {
                    achada = Some(Achada {
                        objeto: entrada.objeto,
                        tipo_da_chave: entrada.tipo_da_chave,
                    });
                    return Passo::Para;
                }
            }
            Passo::Segue
        },
    )?;
    Ok(achada)
}

/// Chama `f` para cada entrada de um diretório, até ela pedir para parar.
///
/// `f` devolve `true` para continuar. É o que permite a quem procura a
/// n-ésima entrada parar ao achá-la, em vez de atravessar todas as folhas do
/// diretório a cada chamada.
pub fn listar<F: FnMut(&Entrada) -> bool>(
    volume: &Volume,
    raiz: u64,
    diretorio: u64,
    mut f: F,
) -> Result<(), &'static str> {
    volume.percorrer(
        raiz,
        folha::Chave::primeira_de(diretorio, tipo::DIRETORIO),
        |item| {
            if item.chave.objeto != diretorio || item.chave.tipo != tipo::DIRETORIO {
                return Passo::Para;
            }
            for entrada in entradas(item.dados) {
                if !f(&entrada) {
                    return Passo::Para;
                }
            }
            Passo::Segue
        },
    )?;
    Ok(())
}
