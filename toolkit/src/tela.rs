//! Uma memória de pixels onde os widgets desenham.

use crate::Retangulo;
use tipografia::Estilo;

/// Uma memória de pixels `0xAARRGGBB`, linha a linha, com a largura de cada
/// linha. É a de uma superfície do compositor, num processo; num teste do
/// hospedeiro, um `Vec`.
pub struct Tela<'a> {
    pub pixels: &'a mut [u32],
    pub largura: u32,
}

impl Tela<'_> {
    pub fn altura(&self) -> u32 {
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

    /// O mesmo, com um [`Retangulo`].
    pub fn preencher(&mut self, r: Retangulo, cor: u32) {
        self.retangulo(r.x, r.y, r.largura, r.altura, cor);
    }

    /// Escreve `texto` no `estilo` com o canto superior esquerdo em `(x, y)`,
    /// com os pixels sem tinta pintados de `papel`. Recorta no que couber.
    /// Devolve onde o texto acabou.
    pub fn texto(
        &mut self,
        (x, y): (u32, u32),
        texto: &str,
        estilo: Estilo,
        (tinta, papel): (u32, u32),
    ) -> u32 {
        tipografia::escrever(
            self.pixels,
            self.largura,
            (x, y),
            texto,
            estilo,
            tinta,
            papel,
        )
    }

    /// O pixel em `(x, y)`, se estiver na memória.
    pub fn pixel(&self, x: u32, y: u32) -> Option<u32> {
        if x >= self.largura {
            return None;
        }
        self.pixels
            .get(y as usize * self.largura as usize + x as usize)
            .copied()
    }
}
