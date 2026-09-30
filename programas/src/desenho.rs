//! Desenhar numa memória de pixels: retângulos e texto.
//!
//! Os pixels são os de uma [`Superficie`](crate::superficie::Superficie):
//! `0xAARRGGBB`, linha a linha. O texto é o da `tipografia` — a mesma fonte,
//! os mesmos estilos e a mesma mistura que o kernel usa no console e na
//! barra: uma letra numa janela e no console saem com os mesmos pixels.

pub use tipografia::{Estilo, largura_do_texto};

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
}
