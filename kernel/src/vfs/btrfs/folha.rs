//! Os itens de uma folha.
//!
//! # Como um nó é disposto
//!
//! Como um diretório de banco de dados, e pela mesma razão: os descritores
//! têm tamanho fixo e os dados não. Depois do cabeçalho vem um vetor de
//! descritores crescendo para frente, e os dados dos itens crescem a partir
//! do **fim** do nó, um por um, na direção contrária. O espaço livre é o que
//! sobra no meio, e é por isso que o `dump-tree` imprime um `free space`.
//!
//! Cada descritor traz a chave, o deslocamento do dado e o tamanho dele. O
//! deslocamento é contado a partir do fim do cabeçalho, e não do começo do
//! nó — somar errado dá um item que existe, com bytes de outro.
//!
//! # O que este módulo não faz
//!
//! Não percorre nó interno. Num nível acima de zero os descritores são outros
//! — chave mais endereço do filho — e quem os segue é a busca na árvore, que
//! vem depois. Ler um nó interno como folha daria itens montados a partir de
//! ponteiros, e é por isso que o nível é conferido antes.

/// Onde acaba o cabeçalho e começam os descritores.
const CABECALHO: usize = 101;

/// Quanto ocupa um descritor: a chave e os dois números.
const DESCRITOR: usize = 25;

/// Deslocamentos dentro de um descritor.
const CHAVE_OBJETO: usize = 0;
const CHAVE_TIPO: usize = 8;
const CHAVE_OFFSET: usize = 9;
const ITEM_EM: usize = 17;
const ITEM_TAMANHO: usize = 21;

/// A chave de um item.
///
/// Os três campos juntos ordenam a árvore inteira, nessa precedência. O que
/// cada um significa depende do tipo — num item de pedaço o `offset` é um
/// endereço lógico; num de diretório é um resumo do nome — e é por isso que
/// eles são guardados crus em vez de interpretados aqui.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chave {
    pub objeto: u64,
    pub tipo: u8,
    pub offset: u64,
}

/// Os tipos de item que este leitor reconhece.
pub mod tipo {
    /// Um pedaço: a tradução de uma faixa lógica para o disco.
    pub const PEDACO: u8 = 228;
    /// A raiz de uma árvore.
    pub const RAIZ: u8 = 132;
}

/// Um item da folha: a chave e os bytes dele.
pub struct Item<'n> {
    pub chave: Chave,
    pub dados: &'n [u8],
}

/// Percorre os itens de uma folha, conferindo cada descritor.
///
/// # Por que conferir cada um
///
/// Porque os deslocamentos vêm do disco. Um nó corrompido — ou um nó lido do
/// lugar errado, que é o mesmo do ponto de vista deste código — traz
/// deslocamentos que apontam para fora do nó, e segui-los leria memória
/// vizinha como se fosse conteúdo do sistema de arquivos.
///
/// A soma de verificação já pegou a corrupção antes daqui. Isto é a segunda
/// linha: ela vale para o caso em que a soma confere e o conteúdo ainda não
/// faz sentido, que é o que acontece quando se lê um nó interno como folha.
pub fn itens(no: &[u8]) -> Result<Percurso<'_>, &'static str> {
    if no.len() < CABECALHO {
        return Err("o no nao tem nem cabecalho");
    }
    if no[100] != 0 {
        return Err("este no nao e uma folha");
    }

    let quantos = u32::from_le_bytes([no[96], no[97], no[98], no[99]]) as usize;
    // Os descritores precisam caber no nó. Sem isto, um número absurdo faria
    // a iteração ler para além do fim.
    if CABECALHO + quantos * DESCRITOR > no.len() {
        return Err("a folha diz ter mais itens do que cabem nela");
    }

    Ok(Percurso {
        no,
        quantos,
        proximo: 0,
    })
}

/// O estado de uma passada pelos itens.
pub struct Percurso<'n> {
    no: &'n [u8],
    quantos: usize,
    proximo: usize,
}

impl<'n> Iterator for Percurso<'n> {
    type Item = Result<Item<'n>, &'static str>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.proximo >= self.quantos {
            return None;
        }
        let descritor = CABECALHO + self.proximo * DESCRITOR;
        self.proximo += 1;

        let ler_u64 = |em: usize| -> u64 {
            let mut v = [0u8; 8];
            v.copy_from_slice(&self.no[em..em + 8]);
            u64::from_le_bytes(v)
        };
        let ler_u32 = |em: usize| -> u32 {
            let mut v = [0u8; 4];
            v.copy_from_slice(&self.no[em..em + 4]);
            u32::from_le_bytes(v)
        };

        let chave = Chave {
            objeto: ler_u64(descritor + CHAVE_OBJETO),
            tipo: self.no[descritor + CHAVE_TIPO],
            offset: ler_u64(descritor + CHAVE_OFFSET),
        };

        // O deslocamento é contado a partir do fim do cabeçalho.
        let em = CABECALHO + ler_u32(descritor + ITEM_EM) as usize;
        let tamanho = ler_u32(descritor + ITEM_TAMANHO) as usize;

        let Some(fim) = em.checked_add(tamanho) else {
            return Some(Err("o item transborda ao somar o tamanho"));
        };
        if fim > self.no.len() || em < CABECALHO {
            return Some(Err("o item aponta para fora do no"));
        }

        Some(Ok(Item {
            chave,
            dados: &self.no[em..fim],
        }))
    }
}
