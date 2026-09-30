//! A tipografia do Duke: a fonte, os estilos, e como uma letra vira pixels.
//!
//! # Por que um pacote
//!
//! Porque dois lados desenham texto: o kernel — o console, a barra — e os
//! programas — o servidor de janelas. Enquanto cada um declarava a fonte por
//! conta própria, eram duas respostas para "como uma letra fica na tela", e
//! elas já tinham divergido: a mistura da cobertura do glifo com o fundo
//! truncava de um lado e arredondava do outro, e a mesma letra saía com
//! pixels diferentes numa janela e no console. Aqui mora a resposta, uma vez.
//!
//! # A fonte
//!
//! Noto Sans Mono, já rasterizada — um byte de cobertura por pixel. Vem de
//! biblioteca porque uma fonte é massa de dados, e rasterizar uma vetorial em
//! tempo de execução pediria ponto flutuante, que o alvo ARM do kernel não
//! tem. Monoespaçada, e isso não é detalhe: o console é uma grade, e a
//! árvore semântica mede um texto multiplicando o número de letras.
//!
//! # O que foi escolhido, e o que ficou de fora
//!
//! - **Dois pesos**, regular e negrito. O negrito é para o que se lê
//!   primeiro — o nome do sistema na barra, o título de uma janela. O leve
//!   ficou de fora: numa tela sem suavização além da da própria fonte, um
//!   traço fino some.
//! - **Duas alturas**, 16 e 24 pixels. A de 16 é a do texto; a de 24, a de
//!   um título dentro de uma janela, e fica atrás da feature `titulo`: só os
//!   programas a usam, e o kernel não carrega a massa de dados dela. As de
//!   20 e 32 não teriam quem as usasse.
//! - **Dois blocos**: o latim básico e o suplemento Latin-1, que é onde
//!   moram as letras do português — `á`, `ã`, `ç`, `é`, `ô` e as outras. Até
//!   aqui só o primeiro existia, e o texto do sistema era escrito sem acento
//!   para não sair `?` na tela. O latim estendido, de outras línguas
//!   europeias, ficou de fora: é massa de dados sem quem a leia.
//!
//! O que não tem glifo sai como [`SUBSTITUTO`]. Desenhar nada deixaria um
//! buraco que ninguém distingue de um espaço; o `?` diz que havia algo ali
//! que a fonte não sabe mostrar.

#![cfg_attr(not(test), no_std)]

use noto_sans_mono_bitmap::{FontWeight, RasterHeight, get_raster, get_raster_width};

/// O peso do traço.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peso {
    Regular,
    Negrito,
}

/// A altura da linha.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tamanho {
    /// 16 pixels: o console, a barra, o conteúdo das janelas.
    Texto,
    /// 24 pixels: um título dentro de uma janela. Só com a feature
    /// `titulo`, que o kernel não liga.
    #[cfg(feature = "titulo")]
    Titulo,
}

/// Um estilo de texto: o peso e a altura.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Estilo {
    pub peso: Peso,
    pub tamanho: Tamanho,
}

impl Estilo {
    /// O texto de todo dia.
    pub const TEXTO: Estilo = Estilo {
        peso: Peso::Regular,
        tamanho: Tamanho::Texto,
    };
    /// O que se lê primeiro, na altura do texto: o nome na barra, o título
    /// de uma janela.
    pub const NEGRITO: Estilo = Estilo {
        peso: Peso::Negrito,
        tamanho: Tamanho::Texto,
    };
    /// Um título grande, dentro de uma janela.
    #[cfg(feature = "titulo")]
    pub const TITULO: Estilo = Estilo {
        peso: Peso::Negrito,
        tamanho: Tamanho::Titulo,
    };

    const fn peso_da_fonte(self) -> FontWeight {
        match self.peso {
            Peso::Regular => FontWeight::Regular,
            Peso::Negrito => FontWeight::Bold,
        }
    }

    const fn altura_da_fonte(self) -> RasterHeight {
        match self.tamanho {
            Tamanho::Texto => RasterHeight::Size16,
            #[cfg(feature = "titulo")]
            Tamanho::Titulo => RasterHeight::Size24,
        }
    }

    /// A largura de uma letra, em pixels — a mesma para todas: a fonte é
    /// monoespaçada.
    pub const fn largura(self) -> u32 {
        get_raster_width(self.peso_da_fonte(), self.altura_da_fonte()) as u32
    }

    /// A altura de uma linha, em pixels.
    pub const fn altura(self) -> u32 {
        self.altura_da_fonte().val() as u32
    }
}

/// O que sai no lugar de uma letra que a fonte não tem.
pub const SUBSTITUTO: char = '?';

/// A fonte tem um glifo para `c` neste estilo?
pub fn tem_glifo(c: char, estilo: Estilo) -> bool {
    get_raster(c, estilo.peso_da_fonte(), estilo.altura_da_fonte()).is_some()
}

/// As linhas de cobertura do glifo de `c` — ou do [`SUBSTITUTO`], se a
/// fonte não o tem. Um byte por pixel, de 0 (fundo) a 255 (tinta).
///
/// `None` só se nem o substituto existisse, o que o bloco básico do latim
/// garante que não acontece; devolver `Option`, e não entrar em pânico, é
/// porque quem chama inclui o caminho de falha fatal do kernel.
pub fn glifo(c: char, estilo: Estilo) -> Option<&'static [&'static [u8]]> {
    let (peso, altura) = (estilo.peso_da_fonte(), estilo.altura_da_fonte());
    get_raster(c, peso, altura)
        .or_else(|| get_raster(SUBSTITUTO, peso, altura))
        .map(|g| g.raster())
}

/// Quantos pixels `texto` ocupa na horizontal.
pub fn largura_do_texto(texto: &str, estilo: Estilo) -> u32 {
    texto.chars().count() as u32 * estilo.largura()
}

/// A cor de um pixel com cobertura parcial de tinta, no formato
/// `0xAARRGGBB`; o alfa é o do papel.
///
/// # A conta
///
/// Inteira de ponta a ponta — o ARM do kernel é `softfloat` —, dividindo por
/// 255 e não deslocando 8, e arredondando: cobertura zero dá exatamente o
/// papel, e 255 exatamente a tinta. Com o deslocamento, texto branco nunca
/// sairia branco; sem o arredondamento, os meios-tons puxariam para o
/// escuro. Era aqui que os dois lados divergiam.
pub const fn misturar(papel: u32, tinta: u32, cobertura: u8) -> u32 {
    (papel & 0xFF00_0000)
        | misturar_canal(papel, tinta, cobertura, 16)
        | misturar_canal(papel, tinta, cobertura, 8)
        | misturar_canal(papel, tinta, cobertura, 0)
}

const fn misturar_canal(papel: u32, tinta: u32, cobertura: u8, deslocamento: u32) -> u32 {
    let c = cobertura as u32;
    let p = (papel >> deslocamento) & 0xFF;
    let t = (tinta >> deslocamento) & 0xFF;
    ((p * (255 - c) + t * c + 127) / 255) << deslocamento
}

/// Chama `f` com cada pixel do glifo de `c` — a coluna, a linha e a
/// cobertura —, inclusive os de cobertura zero.
///
/// Para quem desenha num destino que não é uma fatia de pixels: o console
/// do kernel escreve pela tela, que sabe o formato de cada adaptador.
pub fn percorrer(c: char, estilo: Estilo, mut f: impl FnMut(u32, u32, u8)) {
    let Some(linhas) = glifo(c, estilo) else {
        return;
    };
    for (linha, pixels) in linhas.iter().enumerate() {
        for (coluna, &cobertura) in pixels.iter().enumerate() {
            f(coluna as u32, linha as u32, cobertura);
        }
    }
}

/// Escreve `texto` numa memória de pixels `0xAARRGGBB` com `largura` pixels
/// por linha, com o canto superior esquerdo em `(x, y)`.
///
/// Pinta também o que não tem tinta, com o `papel`: quem escreve numa camada
/// não tem o fundo já pintado embaixo, e redesenhar um texto sobre o
/// anterior — um relógio — precisa apagar o que havia. Recorta no que couber
/// na largura e no fim da memória. Devolve onde o texto acabou.
pub fn escrever(
    pixels: &mut [u32],
    largura: u32,
    (x, y): (u32, u32),
    texto: &str,
    estilo: Estilo,
    tinta: u32,
    papel: u32,
) -> u32 {
    let mut x = x;
    for c in texto.chars() {
        percorrer(c, estilo, |coluna, linha, cobertura| {
            let (px, py) = (x + coluna, y + linha);
            if px >= largura {
                return;
            }
            let i = py as usize * largura as usize + px as usize;
            if let Some(pixel) = pixels.get_mut(i) {
                *pixel = misturar(papel, tinta, cobertura);
            }
        });
        x += estilo.largura();
    }
    x
}

#[cfg(test)]
mod testes {
    use super::*;

    const ESTILOS: [Estilo; 3] = [Estilo::TEXTO, Estilo::NEGRITO, Estilo::TITULO];

    #[test]
    fn o_portugues_tem_glifo_em_todo_estilo() {
        for estilo in ESTILOS {
            for c in "áàâãéêíóôõúüçÁÀÂÃÉÊÍÓÔÕÚÜÇºª«»".chars() {
                assert!(tem_glifo(c, estilo), "sem glifo para {c:?} em {estilo:?}");
            }
        }
    }

    #[test]
    fn o_que_nao_tem_glifo_sai_como_substituto() {
        let substituto = glifo(SUBSTITUTO, Estilo::TEXTO).unwrap();
        assert!(!tem_glifo('漢', Estilo::TEXTO));
        assert_eq!(glifo('漢', Estilo::TEXTO).unwrap(), substituto);
        // E uma letra com glifo não é o substituto.
        assert_ne!(glifo('ç', Estilo::TEXTO).unwrap(), substituto);
    }

    #[test]
    fn os_estilos_sao_diferentes_de_verdade() {
        assert_ne!(glifo('A', Estilo::TEXTO), glifo('A', Estilo::NEGRITO));
        assert!(Estilo::TITULO.altura() > Estilo::TEXTO.altura());
        assert!(Estilo::TITULO.largura() > Estilo::TEXTO.largura());
        // Cada glifo tem as dimensões que o estilo diz.
        for estilo in ESTILOS {
            let g = glifo('W', estilo).unwrap();
            assert_eq!(g.len() as u32, estilo.altura());
            assert!(g.iter().all(|l| l.len() as u32 == estilo.largura()));
        }
    }

    #[test]
    fn a_mistura_e_exata_nos_extremos_e_arredonda_no_meio() {
        let (papel, tinta) = (0xFF10_2030, 0x00F0_E0D0);
        assert_eq!(misturar(papel, tinta, 0), 0xFF10_2030);
        assert_eq!(misturar(papel, tinta, 255), 0xFFF0_E0D0);
        // Um fio de tinta sobre o preto: 200 * 1 / 255 = 0,78. Arredondado,
        // é 1; truncado, seria 0 — e o meio-tom mais claro de uma letra
        // sumiria.
        assert_eq!(misturar(0, 0x00C8_C8C8, 1) & 0xFF, 1);
    }

    #[test]
    fn escrever_recorta_e_devolve_onde_acabou() {
        let largura = 20;
        let mut pixels = [0u32; 20 * 16];
        let fim = escrever(&mut pixels, largura, (0, 0), "ção", Estilo::TEXTO, !0, 0);
        assert_eq!(fim, 3 * Estilo::TEXTO.largura());
        // Algo foi pintado, e nada passou da memória.
        assert!(pixels.iter().any(|&p| p != 0));
        assert_eq!(largura_do_texto("ção", Estilo::TEXTO), fim);
    }
}
