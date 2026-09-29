//! Desenhar numa memória de pixels: retângulos e texto.
//!
//! Os pixels são os de uma [`Superficie`](crate::superficie::Superficie):
//! `0xAARRGGBB`, linha a linha. O texto usa a fonte do console do kernel —
//! a mesma biblioteca, o mesmo peso e a mesma altura —, com a cobertura de
//! cada pixel misturada entre a tinta e o papel, como o kernel faz: uma
//! letra limiarizada em "tem tinta ou não" sai serrilhada.

use noto_sans_mono_bitmap::{FontWeight, RasterHeight, get_raster, get_raster_width};

const PESO: FontWeight = FontWeight::Regular;
const ALTURA: RasterHeight = RasterHeight::Size16;

/// A largura de um caractere e a altura de uma linha, em pixels.
pub fn tamanho_do_caractere() -> (u32, u32) {
    (get_raster_width(PESO, ALTURA) as u32, ALTURA.val() as u32)
}

/// Quantos pixels `texto` ocupa na horizontal.
pub fn largura_do_texto(texto: &str) -> u32 {
    texto.chars().count() as u32 * tamanho_do_caractere().0
}

/// Uma memória de pixels com a largura de cada linha.
pub struct Tela<'a> {
    pub pixels: &'a mut [u32],
    pub largura: u32,
}

impl Tela<'_> {
    fn altura(&self) -> u32 {
        (self.pixels.len() / self.largura.max(1) as usize) as u32
    }

    /// Pinta o retângulo, recortado à memória.
    pub fn retangulo(&mut self, x: u32, y: u32, largura: u32, altura: u32, cor: u32) {
        let x1 = x.saturating_add(largura).min(self.largura);
        let y1 = y.saturating_add(altura).min(self.altura());
        for linha in y..y1 {
            let inicio = (linha * self.largura) as usize;
            if x < x1 {
                self.pixels[inicio + x as usize..inicio + x1 as usize].fill(cor);
            }
        }
    }

    /// Escreve `texto` com o canto superior esquerdo em `(x, y)`, com os
    /// pixels sem tinta pintados de `papel`. Recorta no que couber. Devolve
    /// onde o texto acabou.
    pub fn texto(&mut self, x: u32, y: u32, texto: &str, tinta: u32, papel: u32) -> u32 {
        let (largura_do_glifo, _) = tamanho_do_caractere();
        let altura = self.altura();
        let mut x = x;
        for c in texto.chars() {
            let glifo = get_raster(c, PESO, ALTURA).or_else(|| get_raster('?', PESO, ALTURA));
            if let Some(glifo) = glifo {
                for (linha, cobertura) in glifo.raster().iter().enumerate() {
                    let py = y + linha as u32;
                    if py >= altura {
                        break;
                    }
                    for (coluna, &c) in cobertura.iter().enumerate() {
                        let px = x + coluna as u32;
                        if px >= self.largura {
                            break;
                        }
                        self.pixels[(py * self.largura + px) as usize] = misturar(papel, tinta, c);
                    }
                }
            }
            x += largura_do_glifo;
        }
        x
    }
}

/// A cor de um pixel com cobertura parcial de tinta, com o alfa de `papel`.
///
/// Aritmética inteira, e divisão por 255: cobertura cheia dá exatamente a
/// tinta, e zero exatamente o papel.
pub fn misturar(papel: u32, tinta: u32, cobertura: u8) -> u32 {
    let c = cobertura as u32;
    let canal = |deslocamento: u32| {
        let p = (papel >> deslocamento) & 0xFF;
        let t = (tinta >> deslocamento) & 0xFF;
        ((p * (255 - c) + t * c + 127) / 255) << deslocamento
    };
    (papel & 0xFF00_0000) | canal(16) | canal(8) | canal(0)
}
