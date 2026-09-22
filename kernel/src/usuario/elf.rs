//! Leitor de ELF64: o formato em que um programa chega ao kernel.
//!
//! # Por que um formato, e não bytes soltos
//!
//! Até aqui um programa era um punhado de instruções copiadas para uma página
//! e executadas a partir do primeiro byte. Isso bastou para provar a travessia
//! de privilégio, mas cobra um preço que cresce: o programa não pode dizer
//! onde quer ser carregado, nem separar código de dados, nem pedir memória
//! zerada. Tudo isso fica implícito num acordo entre o programa e o kernel que
//! nada verifica.
//!
//! Um ELF torna esse acordo explícito e conferível. O cabeçalho diz onde
//! começa a execução; cada segmento diz onde quer morar, quanto ocupa no
//! arquivo, quanto ocupa na memória e com que permissões.
//!
//! # A regra que vale para cada campo
//!
//! **Nada aqui é confiável.** Hoje a imagem vem de dentro do próprio kernel,
//! mas o ponto de um carregador é justamente aceitar programas de fora — e o
//! código não deve precisar mudar quando isso acontecer.
//!
//! Por isso cada leitura é limitada ao tamanho da fatia, cada soma é
//! saturante ou conferida, e todo campo é validado antes de virar decisão. Um
//! ELF malformado devolve erro; nenhum deles pode causar pânico, e um pânico
//! no kernel é terminal.

use super::{BASE, TETO};

/// Os oito primeiros bytes de qualquer ELF64 little-endian.
///
/// `\x7fELF` é a assinatura; depois vêm classe (2 = 64 bits), codificação
/// (1 = little-endian) e versão (1). Conferir os seis de uma vez é mais curto
/// e mais difícil de errar que seis comparações separadas.
const ASSINATURA: [u8; 7] = [0x7F, b'E', b'L', b'F', 2, 1, 1];

/// `ET_EXEC`: executável com endereços já resolvidos.
///
/// Um `ET_DYN` (executável independente de posição) exigiria relocação, que é
/// outro assunto — e aceitá-lo em silêncio carregaria o programa no lugar
/// errado, que é o pior desfecho possível.
const TIPO_EXECUTAVEL: u16 = 2;

/// `PT_LOAD`: o único tipo de segmento que este carregador entende.
///
/// Os outros (`PT_DYNAMIC`, `PT_INTERP`, `PT_NOTE`, ...) são ignorados de
/// propósito: não carregá-los é correto, e recusar o arquivo por causa deles
/// recusaria executáveis perfeitamente válidos.
const SEGMENTO_CARREGAVEL: u32 = 1;

/// Máquina esperada, segundo a arquitetura em que este kernel foi compilado.
#[cfg(target_arch = "x86_64")]
const MAQUINA: u16 = 0x3E;
#[cfg(target_arch = "aarch64")]
const MAQUINA: u16 = 0xB7;

const TAMANHO_DO_CABECALHO: usize = 64;
const TAMANHO_DO_SEGMENTO: usize = 56;

/// Quantos segmentos carregáveis aceitamos.
///
/// Um teto explícito existe porque `e_phnum` vem do arquivo: sem ele, um
/// cabeçalho pedindo 65535 segmentos faria o kernel percorrer a tabela inteira
/// dentro de uma única chamada.
pub const MAX_SEGMENTOS: usize = 8;

/// Permissões que um segmento pede, como o ELF as codifica.
const PF_EXECUTAVEL: u32 = 1;
const PF_ESCRITA: u32 = 2;

/// Um segmento a carregar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segmento {
    /// Onde o conteúdo começa dentro da imagem.
    pub deslocamento: usize,
    /// Onde o segmento quer morar no espaço do usuário.
    pub destino: u64,
    /// Quantos bytes vêm da imagem.
    pub bytes_no_arquivo: usize,
    /// Quanto o segmento ocupa na memória.
    ///
    /// Pode ser maior que [`Self::bytes_no_arquivo`]: a diferença é a `.bss`, e
    /// **precisa** chegar zerada ao programa. Não é higiene — é a diferença
    /// entre uma variável global que começa em zero e uma que começa com o que
    /// o dono anterior daquele frame deixou lá.
    pub bytes_na_memoria: usize,
    /// O segmento pede permissão de escrita?
    pub escrita: bool,
    /// O segmento pede permissão de execução?
    pub executavel: bool,
}

/// Um ELF já validado, pronto para ser carregado.
pub struct Imagem<'a> {
    bytes: &'a [u8],
    entrada: u64,
    segmentos: [Segmento; MAX_SEGMENTOS],
    total: usize,
}

impl<'a> Imagem<'a> {
    /// Onde a execução começa.
    pub fn entrada(&self) -> u64 {
        self.entrada
    }

    /// Os segmentos carregáveis, na ordem em que aparecem no arquivo.
    pub fn segmentos(&self) -> &[Segmento] {
        &self.segmentos[..self.total]
    }

    /// O conteúdo de um segmento, já conferido contra o tamanho da imagem.
    pub fn conteudo(&self, segmento: &Segmento) -> &'a [u8] {
        // O `validar` já garantiu a faixa; este `get` existe para que um erro
        // futuro vire fatia vazia em vez de pânico.
        let fim = segmento.deslocamento + segmento.bytes_no_arquivo;
        self.bytes
            .get(segmento.deslocamento..fim)
            .unwrap_or(&[][..])
    }
}

/// Lê um `u16` little-endian, ou `None` se ele não couber.
fn u16_em(bytes: &[u8], deslocamento: usize) -> Option<u16> {
    let fim = deslocamento.checked_add(2)?;
    let fatia = bytes.get(deslocamento..fim)?;
    Some(u16::from_le_bytes([fatia[0], fatia[1]]))
}

/// Lê um `u32` little-endian, ou `None` se ele não couber.
fn u32_em(bytes: &[u8], deslocamento: usize) -> Option<u32> {
    let fim = deslocamento.checked_add(4)?;
    let fatia = bytes.get(deslocamento..fim)?;
    Some(u32::from_le_bytes([fatia[0], fatia[1], fatia[2], fatia[3]]))
}

/// Lê um `u64` little-endian, ou `None` se ele não couber.
fn u64_em(bytes: &[u8], deslocamento: usize) -> Option<u64> {
    let fim = deslocamento.checked_add(8)?;
    let fatia = bytes.get(deslocamento..fim)?;
    let mut octeto = [0u8; 8];
    octeto.copy_from_slice(fatia);
    Some(u64::from_le_bytes(octeto))
}

/// Confere a imagem inteira e devolve o que é preciso para carregá-la.
///
/// Devolve erro na primeira coisa que não fecha. A mensagem nomeia o campo,
/// porque um "ELF invalido" genérico não ajuda ninguém a descobrir se o
/// problema é o compilador, o script do linker ou o carregador.
pub fn validar(bytes: &[u8]) -> Result<Imagem<'_>, &'static str> {
    if bytes.len() < TAMANHO_DO_CABECALHO {
        return Err("imagem menor que um cabecalho ELF");
    }
    if bytes[..ASSINATURA.len()] != ASSINATURA {
        return Err("nao e um ELF64 little-endian");
    }
    if u16_em(bytes, 16) != Some(TIPO_EXECUTAVEL) {
        return Err("o ELF nao e um executavel de endereco fixo");
    }
    if u16_em(bytes, 18) != Some(MAQUINA) {
        return Err("o ELF e de outra arquitetura");
    }

    let entrada = u64_em(bytes, 24).ok_or("cabecalho truncado no ponto de entrada")?;
    if !(BASE..TETO).contains(&entrada) {
        return Err("o ponto de entrada esta fora do espaco do usuario");
    }

    let tabela = u64_em(bytes, 32).ok_or("cabecalho truncado na tabela de segmentos")? as usize;
    let tamanho_da_entrada = u16_em(bytes, 54).ok_or("cabecalho truncado")? as usize;
    let quantos = u16_em(bytes, 56).ok_or("cabecalho truncado")? as usize;

    // O tamanho da entrada vem do arquivo e é usado para avançar o cursor.
    // Aceitar outro valor faria a leitura seguinte cair no meio de um campo.
    if tamanho_da_entrada != TAMANHO_DO_SEGMENTO {
        return Err("tabela de segmentos com entradas de tamanho inesperado");
    }

    let mut segmentos = [Segmento {
        deslocamento: 0,
        destino: 0,
        bytes_no_arquivo: 0,
        bytes_na_memoria: 0,
        escrita: false,
        executavel: false,
    }; MAX_SEGMENTOS];
    let mut total = 0;

    for i in 0..quantos {
        let base = tabela
            .checked_add(i.checked_mul(TAMANHO_DO_SEGMENTO).ok_or("tabela absurda")?)
            .ok_or("tabela de segmentos fora da imagem")?;

        if u32_em(bytes, base).ok_or("tabela de segmentos fora da imagem")? != SEGMENTO_CARREGAVEL {
            continue;
        }
        if total == MAX_SEGMENTOS {
            return Err("segmentos carregaveis demais");
        }

        let permissoes = u32_em(bytes, base + 4).ok_or("segmento truncado")?;
        let deslocamento = u64_em(bytes, base + 8).ok_or("segmento truncado")?;
        let destino = u64_em(bytes, base + 16).ok_or("segmento truncado")?;
        let no_arquivo = u64_em(bytes, base + 32).ok_or("segmento truncado")?;
        let na_memoria = u64_em(bytes, base + 40).ok_or("segmento truncado")?;

        let escrita = permissoes & PF_ESCRITA != 0;
        let executavel = permissoes & PF_EXECUTAVEL != 0;

        // `W^X`: uma página que o usuário possa escrever **e** executar
        // transforma qualquer escrita descuidada em execução de código
        // arbitrário. Recusar aqui é mais honesto que carregar e rezar.
        if escrita && executavel {
            return Err("segmento pede escrita e execucao ao mesmo tempo");
        }

        // O conteúdo precisa caber na imagem, e a soma não pode transbordar —
        // os dois números vêm do arquivo.
        let fim_no_arquivo = deslocamento
            .checked_add(no_arquivo)
            .ok_or("segmento com deslocamento que transborda")?;
        if fim_no_arquivo > bytes.len() as u64 {
            return Err("segmento aponta para fora da imagem");
        }
        if no_arquivo > na_memoria {
            return Err("segmento ocupa menos memoria do que traz do arquivo");
        }

        // O destino inteiro precisa caber no espaço do usuário.
        let fim_na_memoria = destino
            .checked_add(na_memoria)
            .ok_or("segmento com destino que transborda")?;
        if destino < BASE || fim_na_memoria > TETO {
            return Err("segmento quer morar fora do espaco do usuario");
        }

        segmentos[total] = Segmento {
            deslocamento: deslocamento as usize,
            destino,
            bytes_no_arquivo: no_arquivo as usize,
            bytes_na_memoria: na_memoria as usize,
            escrita,
            executavel,
        };
        total += 1;
    }

    if total == 0 {
        return Err("o ELF nao tem nenhum segmento carregavel");
    }

    Ok(Imagem {
        bytes,
        entrada,
        segmentos,
        total,
    })
}
