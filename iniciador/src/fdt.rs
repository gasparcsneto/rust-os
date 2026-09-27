//! O mínimo de device tree para conferir um endereço escrito à mão.
//!
//! # Por que um leitor, e não o do kernel
//!
//! Porque são dois programas, em dois workspaces, compilados para alvos
//! diferentes: o kernel não é dependência do iniciador nem o contrário. O
//! que os dois compartilham mora em `protocolo/`, e um leitor de device
//! tree não é contrato entre eles — é uma leitura que cada um faz por
//! conta.
//!
//! # Por que tão pouco
//!
//! Porque a única pergunta que este programa tem é uma: **onde está a
//! UART?** Ele já escreve nela desde a primeira linha, num endereço fixado
//! no código, e o que falta é confirmar que aquele número é o desta placa.
//!
//! Um leitor completo — tipos de propriedade, `#address-cells`
//! herdado por nível, referências por `phandle` — seria muito mais código
//! para responder a mesma coisa, e código que ninguém exercita é código que
//! não se sabe se funciona. O que está aqui percorre o bloco de estrutura
//! uma vez, de cabo a rabo, e para no primeiro nó que se declara compatível
//! com uma PL011.
//!
//! # O que ele não resolve, dito em voz alta
//!
//! A dependência circular continua: para relatar que o device tree diz
//! outro endereço, é preciso já estar falando por **algum** endereço.
//! Alguém tem de chutar primeiro. O que muda é que o chute deixa de ser
//! silencioso — numa placa em que os dois números discordem, a discordância
//! aparece no relatório em vez de aparecer como uma serial muda.

/// O cabeçalho de um device tree achatado, nos campos que interessam.
///
/// Todos os números do formato são **big-endian**: ele nasceu no PowerPC, e
/// essa é a pegadinha que faz um leitor desatento ler tamanhos absurdos.
mod cabecalho {
    pub const MAGICA: usize = 0;
    pub const TOTAL: usize = 4;
    pub const ESTRUTURA_EM: usize = 8;
    pub const CADEIAS_EM: usize = 12;
    pub const ESTRUTURA_BYTES: usize = 36;
    /// Quanto o cabeçalho ocupa na versão que este leitor entende.
    pub const TAMANHO: usize = 40;
}

/// Os marcadores do bloco de estrutura.
mod marca {
    pub const NO_COMECA: u32 = 1;
    pub const NO_ACABA: u32 = 2;
    pub const PROPRIEDADE: u32 = 3;
    pub const NADA: u32 = 4;
    pub const FIM: u32 = 9;
}

/// `0xd00dfeed`, a assinatura do formato.
pub const MAGICA: u32 = 0xd00d_feed;

/// Teto de marcadores percorridos.
///
/// O bloco de estrutura vem do firmware, e um tamanho corrompido faria o
/// laço andar por memória arbitrária. O device tree da máquina `virt` tem
/// algumas centenas de marcadores; dezesseis mil é folga de duas ordens de
/// grandeza, e ainda assim é um número em vez de "até acabar".
const MAX_MARCAS: usize = 16 * 1024;

fn u32_em(bytes: &[u8], em: usize) -> Option<u32> {
    let fatia = bytes.get(em..em + 4)?;
    Some(u32::from_be_bytes(fatia.try_into().ok()?))
}

fn u64_em(bytes: &[u8], em: usize) -> Option<u64> {
    let fatia = bytes.get(em..em + 8)?;
    Some(u64::from_be_bytes(fatia.try_into().ok()?))
}

/// O blob inteiro, como fatia, a partir do ponteiro que o firmware deu.
///
/// # Safety
///
/// `em` precisa apontar para um device tree que o firmware publicou, na
/// memória que ele mapeou por identidade.
pub unsafe fn blob<'a>(em: u64) -> Option<&'a [u8]> {
    if em == 0 || !em.is_multiple_of(4) {
        return None;
    }
    // SAFETY: delegada a quem chama. Lemos primeiro só o cabeçalho, que é o
    // mínimo que qualquer blob tem, e é ele que diz o tamanho do resto.
    let inicio = unsafe { core::slice::from_raw_parts(em as *const u8, cabecalho::TAMANHO) };
    if u32_em(inicio, cabecalho::MAGICA)? != MAGICA {
        return None;
    }
    let total = u32_em(inicio, cabecalho::TOTAL)? as usize;
    // Um tamanho absurdo é o jeito mais direto de este leitor ler memória
    // que não é dele. Trinta e dois megabytes são muito mais que qualquer
    // device tree real e muito menos que "qualquer coisa".
    if !(cabecalho::TAMANHO..=32 * 1024 * 1024).contains(&total) {
        return None;
    }
    // SAFETY: o cabeçalho confere e declara este tamanho.
    Some(unsafe { core::slice::from_raw_parts(em as *const u8, total) })
}

/// O endereço da primeira UART PL011 que o device tree descreve.
///
/// Devolve `None` quando não há nenhuma, ou quando o blob não faz sentido —
/// que para quem chama é a mesma coisa: não há segunda opinião a comparar.
pub fn uart_pl011(blob: &[u8]) -> Option<u64> {
    let estrutura_em = u32_em(blob, cabecalho::ESTRUTURA_EM)? as usize;
    let estrutura_bytes = u32_em(blob, cabecalho::ESTRUTURA_BYTES)? as usize;
    let cadeias_em = u32_em(blob, cabecalho::CADEIAS_EM)? as usize;
    let estrutura = blob.get(estrutura_em..estrutura_em.checked_add(estrutura_bytes)?)?;

    // O que se sabe do nó que está sendo percorrido agora. As duas
    // propriedades chegam em ordem arbitrária — a especificação não ordena
    // as propriedades dentro de um nó, e no blob do QEMU o `reg` vem
    // **antes** do `compatible` —, então é preciso guardar as duas e decidir
    // no fim do nó.
    let mut compativel = false;
    let mut reg: Option<u64> = None;

    let mut em = 0usize;
    for _ in 0..MAX_MARCAS {
        let marca = u32_em(estrutura, em)?;
        em += 4;

        match marca {
            marca::NADA => {}
            marca::FIM => return None,

            marca::NO_COMECA => {
                // O nome do nó, terminado em zero e preenchido até a
                // fronteira de quatro bytes. Não olhamos para ele: o nome
                // de um nó de UART varia com a placa, e o `compatible` é o
                // que a especificação manda usar.
                let resto = estrutura.get(em..)?;
                let fim = resto.iter().position(|b| *b == 0)?;
                em += (fim + 1).next_multiple_of(4);
                compativel = false;
                reg = None;
            }

            marca::NO_ACABA => {
                if compativel && let Some(endereco) = reg {
                    return Some(endereco);
                }
                compativel = false;
                reg = None;
            }

            marca::PROPRIEDADE => {
                let bytes = u32_em(estrutura, em)? as usize;
                let nome_em = u32_em(estrutura, em + 4)? as usize;
                em += 8;
                let dados = estrutura.get(em..em.checked_add(bytes)?)?;
                em += bytes.next_multiple_of(4);

                let nome = cadeia_em(blob, cadeias_em + nome_em)?;
                match nome {
                    // `compatible` é uma lista de cadeias terminadas em
                    // zero, e basta uma delas casar.
                    b"compatible" => {
                        compativel = dados.split(|b| *b == 0).any(|c| c == b"arm,pl011");
                    }
                    // `reg` é uma sequência de pares endereço/tamanho, com
                    // quantas células cada um usa vindo do nó pai. Na `virt`
                    // são duas células para cada, e é o único formato que
                    // este leitor aceita — os outros devolvem `None`, que
                    // vira "sem segunda opinião" em vez de um número errado.
                    b"reg" if dados.len() >= 16 => reg = u64_em(dados, 0),
                    _ => {}
                }
            }

            // Um marcador que não existe quer dizer que o passo saiu de
            // sincronia, e daí em diante tudo que for lido é lixo.
            _ => return None,
        }
    }
    None
}

/// Uma cadeia terminada em zero, no bloco de cadeias.
fn cadeia_em(blob: &[u8], em: usize) -> Option<&[u8]> {
    let resto = blob.get(em..)?;
    let fim = resto.iter().position(|b| *b == 0)?;
    resto.get(..fim)
}
