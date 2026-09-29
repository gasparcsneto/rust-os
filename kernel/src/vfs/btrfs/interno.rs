//! Os ponteiros de um nó interno, e a escolha de por onde descer.
//!
//! # O que muda acima do nível zero
//!
//! Numa folha, cada descritor traz a chave e onde o **dado** dela mora dentro
//! do próprio nó. Num nó interno, cada descritor traz a chave e o **endereço
//! lógico de outro nó** — mais a geração dele, que serve para detectar um
//! ponteiro para uma versão antiga da árvore.
//!
//! Os dois descritores têm tamanhos diferentes e significados diferentes, e é
//! por isso que ler um nó interno como folha não devolve lixo óbvio: devolve
//! itens plausíveis, montados a partir de endereços. Um leitor assim
//! entregaria nomes de arquivo feitos de ponteiros.
//!
//! # A regra da descida
//!
//! As chaves de um nó interno estão em ordem, e a chave `i` é a **menor**
//! chave do filho `i`. Para achar onde uma chave alvo mora, procura-se o
//! último `i` cuja chave seja menor ou igual ao alvo.
//!
//! Quando o alvo é menor que a chave zero, o alvo não está na árvore — mas a
//! descida vai para o filho zero mesmo assim, e de propósito: quem procura
//! "o primeiro item a partir desta chave" precisa aterrissar na folha das
//! menores chaves, e quem procura uma chave exata simplesmente não a acha
//! lá. As duas perguntas se respondem com a mesma descida, e ter uma só
//! evita que elas discordem.

use super::folha::Chave;

/// Onde acaba o cabeçalho e começam os ponteiros. É o mesmo da folha: o
/// cabeçalho de um nó não muda com o nível.
const CABECALHO: usize = 101;

/// Quanto ocupa um ponteiro: a chave, o endereço do filho e a geração.
const PONTEIRO: usize = 33;

/// Deslocamentos dentro de um ponteiro.
const CHAVE_OBJETO: usize = 0;
const CHAVE_TIPO: usize = 8;
const CHAVE_OFFSET: usize = 9;
const BLOCO: usize = 17;

/// Quantos níveis um nó pode ter abaixo de si.
///
/// O Btrfs limita a árvore a oito níveis, e o campo tem um byte só. O teto
/// existe para que uma árvore corrompida — ou um nó apontando para si mesmo —
/// termine em erro em vez de laço infinito, e para que a recusa diga o que
/// aconteceu.
pub const MAX_NIVEL: u8 = 8;

fn u64_em(no: &[u8], em: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&no[em..em + 8]);
    u64::from_le_bytes(v)
}

/// Quantos ponteiros (ou itens) o cabeçalho declara.
fn quantos(no: &[u8]) -> usize {
    u32::from_le_bytes([no[96], no[97], no[98], no[99]]) as usize
}

/// A chave do ponteiro `i`.
fn chave_em(no: &[u8], i: usize) -> Chave {
    let base = CABECALHO + i * PONTEIRO;
    Chave {
        objeto: u64_em(no, base + CHAVE_OBJETO),
        tipo: no[base + CHAVE_TIPO],
        offset: u64_em(no, base + CHAVE_OFFSET),
    }
}

/// O endereço lógico do filho por onde a busca de `alvo` continua.
///
/// # Por que a busca é binária
///
/// Porque um nó interno de 16 KiB comporta quase quinhentos ponteiros, e a
/// descida acontece uma vez por folha visitada. Varrer linearmente seria o
/// suficiente para este disco e transformaria a listagem de um diretório
/// grande num custo quadrático — e o ponto de descer pela árvore é
/// justamente não ler tudo.
///
/// Ela também é o lugar onde um erro de um índice não aparece: escolher o
/// filho seguinte devolve uma folha cujas chaves começam **depois** do alvo,
/// e a resposta vira "não existe" para um arquivo que existe.
// A suíte a usa sobre nós montados à mão; a descida de produção precisa
// também da vizinha, e chama a de baixo.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn descer_para(no: &[u8], alvo: Chave) -> Result<u64, &'static str> {
    descer_para_com_vizinha(no, alvo).map(|(filho, _)| filho)
}

/// Como [`descer_para`], e também a chave do ponteiro **seguinte** ao
/// escolhido, se houver um — que é a menor chave da subárvore vizinha à
/// direita.
///
/// É o que diz ao percurso onde a próxima folha começa. Deduzi-lo da última
/// chave da folha, como se fazia, erra quando o alvo cai no vão entre duas
/// folhas — ver [`super::Volume::percorrer`].
pub fn descer_para_com_vizinha(
    no: &[u8],
    alvo: Chave,
) -> Result<(u64, Option<Chave>), &'static str> {
    if no.len() < CABECALHO {
        return Err("o no nao tem nem cabecalho");
    }
    if no[100] == 0 {
        return Err("este no e uma folha, nao tem por onde descer");
    }

    let quantos = quantos(no);
    if quantos == 0 {
        return Err("no interno sem ponteiro nenhum");
    }
    // Os ponteiros precisam caber no nó. Sem isto, um número absurdo faria a
    // busca ler para além do fim — e no meio de uma busca binária o índice
    // de leitura nem é previsível.
    if CABECALHO + quantos * PONTEIRO > no.len() {
        return Err("o no diz ter mais ponteiros do que cabem nele");
    }

    // Invariante: `escolhido` é sempre um índice cuja chave já se sabe menor
    // ou igual ao alvo, ou zero quando nenhuma é. Começar em zero é o que
    // implementa a regra do "alvo menor que tudo desce pelo primeiro".
    let mut escolhido = 0usize;
    let (mut baixo, mut alto) = (0usize, quantos);
    while baixo < alto {
        let meio = baixo + (alto - baixo) / 2;
        if chave_em(no, meio) <= alvo {
            escolhido = meio;
            baixo = meio + 1;
        } else {
            alto = meio;
        }
    }

    let vizinha = (escolhido + 1 < quantos).then(|| chave_em(no, escolhido + 1));
    Ok((
        u64_em(no, CABECALHO + escolhido * PONTEIRO + BLOCO),
        vizinha,
    ))
}

/// Os ponteiros de um nó interno, em ordem: a chave e o endereço lógico de
/// cada filho.
///
/// Para a suíte, que percorre a árvore pela estrutura — nó a nó, filho a
/// filho — e confere que o percurso por chave entrega o mesmo. É uma
/// segunda leitura da árvore que não passa pela descida, e é por isso que
/// ela serve de referência: um defeito na descida não aparece nas duas.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn ponteiros(no: &[u8]) -> Result<alloc::vec::Vec<(Chave, u64)>, &'static str> {
    if no.len() < CABECALHO || no[100] == 0 {
        return Err("so um no interno tem ponteiros");
    }
    let quantos = quantos(no);
    if CABECALHO + quantos * PONTEIRO > no.len() {
        return Err("o no diz ter mais ponteiros do que cabem nele");
    }
    Ok((0..quantos)
        .map(|i| {
            (
                chave_em(no, i),
                u64_em(no, CABECALHO + i * PONTEIRO + BLOCO),
            )
        })
        .collect())
}
