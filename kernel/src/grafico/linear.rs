//! O adaptador linear: um framebuffer que se escreve e aparece.
//!
//! # De onde vem
//!
//! Porte de `vesad`, de `redox-os/drivers` — o arquivo
//! `graphics/vesad/src/scheme.rs`, em especial `GraphicScreen::sync`. MIT,
//! Copyright (c) 2017 Redox OS; ver `THIRD_PARTY.md` na raiz do projeto.
//!
//! É o adaptador de toda máquina que tem uma tela e nenhum dispositivo para
//! conversar sobre ela: o framebuffer que o firmware entregou pela UEFI, o
//! `ramfb`, o `bochs-display`. Desenhar é escrever na memória; o que o
//! adaptador acrescenta é o **buffer de fundo** — compor fora da tela e copiar
//! para ela só o retângulo que mudou.
//!
//! # O que mudou no porte
//!
//! - O `vesad` só conhece quatro bytes por pixel: ele copia `u32` a `u32`. Um
//!   framebuffer de três bytes por pixel sairia inclinado. Aqui a escrita
//!   passa por [`Tela::copiar_linha`], que sabe os dois tamanhos e os três
//!   formatos — e que é o único lugar do kernel que sabe.
//! - O recorte é o de [`Dano::recortar`], que não herda a soma que dá a volta.
//! - O `vesad` recorta contra a superfície e copia para a tela confiando que
//!   as duas têm o mesmo tamanho. Aqui o recorte é contra a **menor** das
//!   duas: uma superfície maior que a tela não escreve fora dela, e uma menor
//!   não é lida além do fim.

use super::memoria::Memoria;
use super::{AdaptadorGrafico, Dano, Superficie};
use crate::tela::Tela;

/// Um framebuffer linear, e mais nada.
pub struct AdaptadorLinear {
    tela: Tela,
}

impl AdaptadorLinear {
    pub fn novo(tela: Tela) -> AdaptadorLinear {
        AdaptadorLinear { tela }
    }
}

/// Uma superfície deste adaptador: pixels em memória própria.
pub struct SuperficieLinear {
    memoria: Memoria,
    largura: u32,
    altura: u32,
}

impl Superficie for SuperficieLinear {
    fn largura(&self) -> u32 {
        self.largura
    }

    fn altura(&self) -> u32 {
        self.altura
    }

    fn pixels(&self) -> &[u32] {
        &self.memoria.pixels()[..(self.largura as usize * self.altura as usize)]
    }

    fn pixels_mut(&mut self) -> &mut [u32] {
        let quantos = self.largura as usize * self.altura as usize;
        &mut self.memoria.pixels_mut()[..quantos]
    }

    fn bytes(&self) -> u64 {
        self.memoria.bytes()
    }
}

impl AdaptadorGrafico for AdaptadorLinear {
    type Superficie = SuperficieLinear;

    fn nome(&self) -> &'static str {
        "linear"
    }

    fn telas(&self) -> usize {
        1
    }

    fn tamanho_da_tela(&self, tela: usize) -> Option<(u32, u32)> {
        (tela == 0).then_some((self.tela.largura, self.tela.altura))
    }

    fn criar_superficie(
        &mut self,
        largura: u32,
        altura: u32,
    ) -> Result<SuperficieLinear, &'static str> {
        if largura == 0 || altura == 0 {
            return Err("superficie sem area");
        }
        let bytes = (largura as u64)
            .checked_mul(altura as u64)
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or("superficie grande demais")?;
        Ok(SuperficieLinear {
            memoria: Memoria::nova(bytes)?,
            largura,
            altura,
        })
    }

    fn atualizar(
        &mut self,
        tela: usize,
        superficie: &SuperficieLinear,
        dano: Dano,
    ) -> Result<Dano, &'static str> {
        if tela != 0 {
            return Err("esta maquina tem uma tela so");
        }

        let largura = superficie.largura().min(self.tela.largura);
        let altura = superficie.altura().min(self.tela.altura);
        let dano = dano.recortar(largura, altura);
        if dano.vazio() {
            return Ok(dano);
        }

        let pixels = superficie.pixels();
        let linha_da_superficie = superficie.largura() as usize;
        for y in dano.y..dano.y + dano.altura {
            let comeco = y as usize * linha_da_superficie + dano.x as usize;
            let fim = comeco + dano.largura as usize;
            self.tela.copiar_linha(dano.x, y, &pixels[comeco..fim]);
        }
        Ok(dano)
    }
}
