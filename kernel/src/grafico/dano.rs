//! Um retângulo da tela que precisa ser atualizado.
//!
//! # De onde vem
//!
//! Porte de `Damage`, de `redox-os/drivers` — o arquivo
//! `graphics/graphics-ipc/src/common.rs`. MIT, Copyright (c) 2017 Redox OS;
//! ver `THIRD_PARTY.md` na raiz do projeto.
//!
//! # O que mudou no porte, e por quê
//!
//! Uma soma. O original recorta assim:
//!
//! ```text
//! let x2 = self.x + self.width;
//! self.x = cmp::min(self.x, width);
//! if x2 > width {
//!     self.width = width - self.x;
//! }
//! ```
//!
//! Com `x` perto do fim do `u32`, `x2` dá a volta e fica **pequeno**: a
//! condição falha, a largura original sobrevive, e o retângulo "recortado"
//! começa na borda direita e segue além dela. Compilado e medido no
//! hospedeiro com o código deles: um dano em `x = u32::MAX - 1` com largura
//! 10, numa tela de 1280, sai do recorte como `x = 1280, largura = 10` — dez
//! colunas fora da tela. O `vesad` copia o que o recorte devolve, então isso
//! é escrita além do fim de cada linha, e além do fim do framebuffer na
//! última. E o dano chega ali vindo de um cliente do display.
//!
//! Aqui a soma satura. E há uma segunda razão para ela não poder ser a do
//! original, que é deste kernel: o perfil de release liga `overflow-checks`,
//! e a mesma soma seria pânico — o kernel inteiro caindo por causa de um
//! retângulo.

/// Um retângulo, em pixels.
///
/// Sem `#[repr(C, packed)]`, que o original tem porque atravessa IPC entre
/// processos. Aqui ele não sai do kernel, e `packed` só traria o problema de
/// não se poder pegar referência para os campos.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dano {
    pub x: u32,
    pub y: u32,
    pub largura: u32,
    pub altura: u32,
}

impl Dano {
    pub const fn novo(x: u32, y: u32, largura: u32, altura: u32) -> Dano {
        Dano {
            x,
            y,
            largura,
            altura,
        }
    }

    /// Uma área inteira, a partir da origem.
    // O compositor recompõe o que muda, nunca a tela inteira de propósito;
    // hoje só a suíte pede uma área inteira.
    #[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
    pub const fn inteiro(largura: u32, altura: u32) -> Dano {
        Dano::novo(0, 0, largura, altura)
    }

    /// Não cobre pixel nenhum.
    pub const fn vazio(&self) -> bool {
        self.largura == 0 || self.altura == 0
    }

    /// Recorta o retângulo a uma área de `largura` por `altura`.
    ///
    /// Depois do recorte, `x + largura <= largura_da_area` e o mesmo para o
    /// eixo vertical — **sempre**, para qualquer entrada. É a propriedade que
    /// o original perde com a soma que dá a volta, e é a única que importa a
    /// quem copia pixels a partir do resultado.
    #[must_use]
    pub fn recortar(self, largura: u32, altura: u32) -> Dano {
        let (x, largura_) = recortar_eixo(self.x, self.largura, largura);
        let (y, altura_) = recortar_eixo(self.y, self.altura, altura);
        Dano::novo(x, y, largura_, altura_)
    }

    /// O menor retângulo que contém os dois.
    ///
    /// É o que o compositor do Orbital faz com os pedidos de redesenho que
    /// se acumulam num quadro: em vez de uma lista, um retângulo só que
    /// cobre todos. Perde precisão — dois cantos opostos viram a tela
    /// inteira —, e ganha em troca que o quadro custa uma cópia por linha, e
    /// não uma por pedido.
    ///
    /// Um retângulo vazio não expande o outro: unir com nada é não mudar.
    #[must_use]
    pub fn unir(self, outro: Dano) -> Dano {
        if self.vazio() {
            return outro;
        }
        if outro.vazio() {
            return self;
        }
        let x = self.x.min(outro.x);
        let y = self.y.min(outro.y);
        let fim_x = self
            .x
            .saturating_add(self.largura)
            .max(outro.x.saturating_add(outro.largura));
        let fim_y = self
            .y
            .saturating_add(self.altura)
            .max(outro.y.saturating_add(outro.altura));
        Dano::novo(x, y, fim_x - x, fim_y - y)
    }
}

/// Recorta um eixo: começo e comprimento, contra um limite.
///
/// A mesma lógica do original, com a soma saturada. O começo é empurrado
/// para dentro do limite; o fim é o menor entre o do retângulo e o limite; e
/// o comprimento é a diferença — que não pode ser negativa, porque o começo
/// já foi trazido para antes do limite.
fn recortar_eixo(inicio: u32, comprimento: u32, limite: u32) -> (u32, u32) {
    let fim = inicio.saturating_add(comprimento).min(limite);
    let inicio = inicio.min(limite);
    (inicio, fim - inicio)
}
