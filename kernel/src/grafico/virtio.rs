//! O segundo adaptador: o `virtio-gpu`, atrás do mesmo trait do linear.
//!
//! # O que o trait ganha com ele
//!
//! O compositor que vier desenha numa superfície e entrega o retângulo que
//! mudou, sem saber qual adaptador está embaixo. Com o linear, o retângulo é
//! copiado da superfície para o framebuffer. Com este, a superfície **é** a
//! memória de apoio de um recurso do dispositivo, e nada é copiado pelo
//! kernel: o retângulo é transferido e descarregado, e só ele atravessa.
//!
//! E a troca de página: apresentar uma superfície que não está na tela põe o
//! recurso dela na varredura, de uma vez. É o que um compositor usa para não
//! mostrar um quadro pela metade.
//!
//! Porte do `virtio-gpud` do Redox (MIT, ver `THIRD_PARTY.md`), com as
//! mudanças escritas em [`crate::virtio::gpu`]: o dano chega ao dispositivo
//! em vez do quadro inteiro, e uma recusa dele é um erro em vez de um pânico.

use super::memoria::Memoria;
use super::{AdaptadorGrafico, Dano, Superficie};
use crate::virtio::gpu::{self, Retangulo};

pub struct AdaptadorVirtio;

/// Uma superfície que é um recurso do dispositivo.
pub struct SuperficieVirtio {
    // A ordem dos campos não importa para a destruição — ver o `Drop` —, mas
    // a memória precisa sobreviver ao recurso, e o `Drop` desfaz o recurso
    // antes de os campos serem soltos.
    memoria: Memoria,
    recurso: u32,
    largura: u32,
    altura: u32,
}

impl SuperficieVirtio {
    /// O identificador do recurso no dispositivo. Para a suíte.
    #[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
    pub fn recurso(&self) -> u32 {
        self.recurso
    }
}

impl Superficie for SuperficieVirtio {
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

impl Drop for SuperficieVirtio {
    /// Desfaz o recurso antes de a memória ser devolvida.
    ///
    /// A ordem é a que importa: enquanto o recurso existir com esta memória
    /// anexada, o dispositivo tem o direito de lê-la. Devolver as páginas
    /// antes seria deixá-lo ler o que o alocador já entregou a outro dono.
    fn drop(&mut self) {
        if let Err(motivo) = gpu::desfazer_recurso(self.recurso) {
            crate::log_error!(
                "grafico",
                "o recurso {} nao foi desfeito: {}",
                self.recurso,
                motivo
            );
        }
    }
}

impl AdaptadorVirtio {
    /// Cria uma superfície com cada página física numa entrada própria do
    /// anexo, sem fundir as vizinhas.
    ///
    /// É o pior caso do anexo, e existe para a suíte exercitá-lo de
    /// propósito: logo depois do boot, as páginas de uma superfície costumam
    /// ser fisicamente vizinhas, e o caminho de várias páginas de entradas
    /// nunca rodaria.
    #[cfg(feature = "modo-teste")]
    pub fn criar_superficie_fragmentada(
        &mut self,
        largura: u32,
        altura: u32,
    ) -> Result<SuperficieVirtio, &'static str> {
        criar(largura, altura, false)
    }
}

fn criar(largura: u32, altura: u32, fundir: bool) -> Result<SuperficieVirtio, &'static str> {
    if largura == 0 || altura == 0 {
        return Err("superficie sem area");
    }
    let bytes = (largura as u64)
        .checked_mul(altura as u64)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or("superficie grande demais")?;
    let memoria = Memoria::nova(bytes)?;
    let recurso = gpu::criar_recurso(largura, altura, &memoria, fundir)?;
    Ok(SuperficieVirtio {
        memoria,
        recurso,
        largura,
        altura,
    })
}

impl AdaptadorGrafico for AdaptadorVirtio {
    type Superficie = SuperficieVirtio;

    fn nome(&self) -> &'static str {
        "virtio-gpu"
    }

    fn telas(&self) -> usize {
        usize::from(gpu::tamanho_da_tela().is_some())
    }

    fn tamanho_da_tela(&self, tela: usize) -> Option<(u32, u32)> {
        (tela == 0).then(gpu::tamanho_da_tela).flatten()
    }

    fn criar_superficie(
        &mut self,
        largura: u32,
        altura: u32,
    ) -> Result<SuperficieVirtio, &'static str> {
        criar(largura, altura, true)
    }

    fn atualizar(
        &mut self,
        tela: usize,
        superficie: &SuperficieVirtio,
        dano: Dano,
    ) -> Result<Dano, &'static str> {
        let (largura_da_tela, altura_da_tela) = self
            .tamanho_da_tela(tela)
            .ok_or("tela inexistente neste adaptador")?;

        // O recorte que não dá a volta — ver [`Dano::recortar`]. Contra a
        // superfície e contra a tela: o dispositivo recusa um retângulo que
        // passe de qualquer um dos dois, e a recusa seria uma resposta de
        // "parâmetro inválido" sem dizer qual.
        let dano = dano
            .recortar(superficie.largura, superficie.altura)
            .recortar(largura_da_tela, altura_da_tela);
        let visivel = (
            superficie.largura.min(largura_da_tela),
            superficie.altura.min(altura_da_tela),
        );

        gpu::apresentar(
            superficie.recurso,
            superficie.largura,
            visivel,
            Retangulo {
                x: dano.x,
                y: dano.y,
                largura: dano.largura,
                altura: dano.altura,
            },
        )?;
        Ok(dano)
    }
}
