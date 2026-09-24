//! Os programas embutidos no kernel, vistos como um sistema de arquivos.
//!
//! # Por que isto existe
//!
//! Porque o VFS precisa de um cliente de verdade antes do Btrfs, e havia um
//! esperando: `executar` procurava o programa numa tabela estática, com uma
//! busca linear escrita à mão. Era o único jeito enquanto não havia disco, e
//! o README já dizia o que mudaria quando houvesse — *"o que muda é onde a
//! busca acontece; a chamada de sistema continua a mesma"*.
//!
//! Este módulo é essa frase virando código. A tabela continua igual, e quem a
//! consulta passa a ser um sistema de arquivos montado em `/bin`. Quando o
//! Btrfs entrar, ele é montado por cima e `executar` não muda uma linha.
//!
//! # O que ele é por dentro
//!
//! Um diretório com três arquivos, todos em memória, todos somente leitura. O
//! `id` de um nó é o índice na tabela — não há inode para inventar, e o
//! índice é estável porque a tabela é `static`.

extern crate alloc;

use alloc::string::ToString;

use super::{Entrada, Erro, No, SistemaDeArquivos, Tipo};

/// O `id` do diretório raiz deste sistema de arquivos.
///
/// Fora da faixa dos índices da tabela, e no topo do `u64`, para que uma
/// confusão entre os dois vire um índice inválido em vez de um arquivo
/// plausível.
const ID_DA_RAIZ: u64 = u64::MAX;

pub struct Programas;

impl SistemaDeArquivos for Programas {
    fn raiz(&self) -> No {
        No {
            tipo: Tipo::Diretorio,
            id: ID_DA_RAIZ,
            tamanho: 0,
        }
    }

    fn procurar(&self, _dir: &No, nome: &str) -> Result<No, Erro> {
        // Sem conferir que `dir` é diretório: quem resolve o caminho já
        // conferiu, e este sistema de arquivos tem um diretório só. Ver a
        // nota em [`SistemaDeArquivos::procurar`] sobre por que a invariante
        // mora num lugar só.
        let (indice, imagem) =
            crate::usuario::programa::embutido_com_indice(nome).ok_or(Erro::NaoEncontrado)?;
        Ok(No {
            tipo: Tipo::Arquivo,
            id: indice as u64,
            tamanho: imagem.len() as u64,
        })
    }

    fn ler(&self, no: &No, deslocamento: u64, destino: &mut [u8]) -> Result<usize, Erro> {
        let imagem = crate::usuario::programa::embutido_por_indice(no.id as usize)
            .ok_or(Erro::NaoEncontrado)?;

        // Um deslocamento além do fim devolve zero bytes, e não erro: é o que
        // uma leitura sequencial encontra ao chegar ao fim do arquivo, e
        // tratá-lo como falha obrigaria todo chamador a distinguir os dois.
        let Ok(inicio) = usize::try_from(deslocamento) else {
            return Ok(0);
        };
        if inicio >= imagem.len() {
            return Ok(0);
        }

        let quanto = destino.len().min(imagem.len() - inicio);
        destino[..quanto].copy_from_slice(&imagem[inicio..inicio + quanto]);
        Ok(quanto)
    }

    fn listar(&self, _dir: &No, indice: usize) -> Result<Option<Entrada>, Erro> {
        Ok(
            crate::usuario::programa::nome_por_indice(indice).map(|nome| Entrada {
                nome: nome.to_string(),
                tipo: Tipo::Arquivo,
            }),
        )
    }
}
