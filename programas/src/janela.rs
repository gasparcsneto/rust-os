//! Uma janela: uma superfície com moldura, que se arrasta e se fecha.
//!
//! # Por que no runtime
//!
//! Porque mais de um processo tem janela: o servidor de janelas e o
//! Terminal. Enquanto a moldura morava no servidor, uma janela de outro
//! processo teria de copiá-la — a barra de título, a caixa de fechar, o
//! arrasto —, e as duas cópias divergiriam na primeira mudança. Aqui mora a
//! janela uma vez; o que cada programa decide é o que vai dentro dela, e o
//! que fazer quando a pessoa a fecha.
//!
//! # O que ela sabe, e o que não sabe
//!
//! Sabe desenhar a moldura — a borda, a barra de título com o nome em
//! negrito e a caixa de fechar —, dizer onde um ponto da tela cai nela, e
//! levar a si mesma pela barra de título enquanto o botão estiver apertado.
//! Diz à árvore semântica o título e a caixa de fechar, e o programa
//! acrescenta o resto.
//!
//! Não sabe das outras janelas: a ordem de empilhamento e qual delas tem o
//! foco são de quem as tem — o servidor, com várias; o Terminal, com uma.

use alloc::string::String;
use core::fmt::Write;

use protocolo::usuario::descricao;

use crate::desenho::{Estilo, Tela};
use crate::superficie::Superficie;

/// A altura da barra de título.
pub const ALTURA_DO_TITULO: u32 = 22;
/// O lado da caixa de fechar, na ponta direita da barra de título.
pub const LADO_DO_FECHAR: u32 = 16;
/// A borda em volta da janela.
pub const BORDA: u32 = 1;

// A paleta do kernel — a da barra superior e a do acento —, para a janela
// parecer da mesma máquina. Com o byte alto cheio: as janelas se misturam
// por alfa, e um pixel de alfa zero não apareceria.
pub const ACENTO: u32 = 0xFF3A_8FD0;
pub const TITULO_APAGADO: u32 = 0xFF2A_3C58;
pub const TEXTO_DO_TITULO: u32 = 0xFFF4_F6FA;
pub const BORDA_COR: u32 = 0xFF10_1828;

/// O que um aperto do botão numa janela foi.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aperto {
    /// Na caixa de fechar: quem tem a janela decide o que é fechar.
    Fechar,
    /// Na barra de título: o arrasto começou, e a janela acompanha o
    /// ponteiro até o botão soltar — ver [`Janela::arrastar`].
    Arrasto,
    /// No conteúdo, em coordenadas do conteúdo.
    Conteudo(i64, i64),
}

/// Uma superfície com moldura.
pub struct Janela {
    superficie: Superficie,
    titulo: &'static str,
    /// Onde o canto superior esquerdo está na tela.
    x: i32,
    y: i32,
    /// O arrasto em curso: onde o ponteiro pegou a janela, nela.
    pega: Option<(i64, i64)>,
}

impl Janela {
    /// Uma janela de `largura` por `altura`, moldura incluída, em `(x, y)` —
    /// ainda invisível: desenhe, e então [`Janela::mostrar`].
    pub fn nova(
        titulo: &'static str,
        largura: u32,
        altura: u32,
        x: i32,
        y: i32,
    ) -> Result<Janela, i64> {
        let superficie = Superficie::nova(largura, altura)?;
        superficie.transparente(true)?;
        superficie.mover(x, y)?;
        Ok(Janela {
            superficie,
            titulo,
            x,
            y,
            pega: None,
        })
    }

    /// Mostra a janela.
    pub fn mostrar(&self) -> Result<(), i64> {
        self.superficie.mostrar()
    }

    pub fn superficie(&mut self) -> &mut Superficie {
        &mut self.superficie
    }

    pub fn descritor(&self) -> u64 {
        self.superficie.descritor()
    }

    pub fn titulo(&self) -> &'static str {
        self.titulo
    }

    pub fn largura(&self) -> u32 {
        self.superficie.largura()
    }

    pub fn altura(&self) -> u32 {
        self.superficie.altura()
    }

    pub fn posicao(&self) -> (i32, i32) {
        (self.x, self.y)
    }

    /// O retângulo do conteúdo, `(x, y, largura, altura)` na janela: tudo
    /// menos a borda e a barra de título.
    pub fn conteudo(&self) -> (u32, u32, u32, u32) {
        (
            BORDA,
            ALTURA_DO_TITULO,
            self.largura() - 2 * BORDA,
            self.altura() - ALTURA_DO_TITULO - BORDA,
        )
    }

    /// `(x, y)` da tela cai na janela?
    pub fn contem(&self, x: i64, y: i64) -> bool {
        let (x0, y0) = (self.x as i64, self.y as i64);
        x >= x0 && y >= y0 && x < x0 + self.largura() as i64 && y < y0 + self.altura() as i64
    }

    /// `(x, y)` da tela, em coordenadas da janela.
    pub fn local(&self, x: i64, y: i64) -> (i64, i64) {
        (x - self.x as i64, y - self.y as i64)
    }

    /// A caixa de fechar: `(x, y, lado)` em coordenadas da janela.
    pub fn caixa_de_fechar(&self) -> (u32, u32, u32) {
        let lado = LADO_DO_FECHAR;
        (
            self.largura() - BORDA - 3 - lado,
            (ALTURA_DO_TITULO - lado) / 2,
            lado,
        )
    }

    fn no_fechar(&self, lx: i64, ly: i64) -> bool {
        let (cx, cy, lado) = self.caixa_de_fechar();
        lx >= cx as i64 && ly >= cy as i64 && lx < (cx + lado) as i64 && ly < (cy + lado) as i64
    }

    /// O que um aperto em `(x, y)` da tela, dentro da janela, é. Na barra de
    /// título, começa o arrasto.
    pub fn apertar(&mut self, x: i64, y: i64) -> Aperto {
        let (lx, ly) = self.local(x, y);
        if self.no_fechar(lx, ly) {
            Aperto::Fechar
        } else if ly < ALTURA_DO_TITULO as i64 {
            self.pega = Some((lx, ly));
            Aperto::Arrasto
        } else {
            let (cx, cy, _, _) = self.conteudo();
            Aperto::Conteudo(lx - cx as i64, ly - cy as i64)
        }
    }

    /// Há um arrasto em curso?
    pub fn arrastando(&self) -> bool {
        self.pega.is_some()
    }

    /// O ponteiro está em `(x, y)` durante um arrasto: a janela vai com
    /// ele. Com `soltou`, o arrasto acaba, e a posição final volta.
    pub fn arrastar(&mut self, x: i64, y: i64, soltou: bool) -> Option<(i32, i32)> {
        let (dx, dy) = self.pega?;
        self.x = (x - dx) as i32;
        self.y = (y - dy) as i32;
        let _ = self.superficie.mover(self.x, self.y);
        if soltou {
            self.pega = None;
            return Some((self.x, self.y));
        }
        None
    }

    /// Desenha a moldura — a borda, a barra de título acesa ou apagada, a
    /// caixa de fechar — e devolve a tela para o conteúdo ser desenhado.
    /// Quem desenha acusa o dano.
    pub fn desenhar_moldura(&mut self, com_foco: bool) -> Tela<'_> {
        let (largura, altura) = (self.largura(), self.altura());
        let (cx, cy, lado) = self.caixa_de_fechar();
        let cor_do_titulo = if com_foco { ACENTO } else { TITULO_APAGADO };
        let titulo = self.titulo;
        let mut tela = Tela {
            pixels: self.superficie.pixels(),
            largura,
        };
        tela.retangulo(0, 0, largura, altura, BORDA_COR);
        tela.retangulo(
            BORDA,
            BORDA,
            largura - 2 * BORDA,
            ALTURA_DO_TITULO - BORDA,
            cor_do_titulo,
        );
        // O título em negrito: é o que se lê primeiro numa janela.
        tela.texto(
            (8, (ALTURA_DO_TITULO - Estilo::NEGRITO.altura()) / 2),
            titulo,
            Estilo::NEGRITO,
            (TEXTO_DO_TITULO, cor_do_titulo),
        );
        // A caixa de fechar: um quadrado mais claro com um x no meio.
        tela.retangulo(cx, cy, lado, lado, TITULO_APAGADO);
        tela.texto(
            (cx + (lado - Estilo::TEXTO.largura()) / 2, cy),
            "x",
            Estilo::TEXTO,
            (TEXTO_DO_TITULO, TITULO_APAGADO),
        );
        tela
    }

    /// Começa a descrição da janela para a árvore semântica: o título, e a
    /// caixa de fechar com o identificador `fechar`. Quem descreve
    /// acrescenta o conteúdo — ver [`protocolo::usuario::descricao`].
    pub fn descrever_moldura(&self, fechar: i64, d: &mut String) {
        let (cx, cy, lado) = self.caixa_de_fechar();
        let _ = write!(d, "janela\t");
        let _ = descricao::escapar(self.titulo, d);
        let _ = write!(
            d,
            "\nbotao\t{}\t{}\t{}\t{}\t{}\tFechar",
            fechar, cx, cy, lado, lado
        );
    }
}
