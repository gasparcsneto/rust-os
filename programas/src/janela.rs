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
//! Diz à árvore semântica o título e a caixa de fechar.
//!
//! E pode hospedar uma [`Interface`] do toolkit: a janela se mede por ela,
//! a desenha e a descreve dentro da moldura, e leva a ela o aperto, a tecla
//! e a ação de um agente — ver [`Janela::com_interface`]. O que volta ao
//! programa é um [`Gesto`]: fechar, redesenhar, ou o código do botão
//! acionado, venha do ponteiro, do teclado ou do agente.
//!
//! Não sabe das outras janelas: a ordem de empilhamento e qual delas tem o
//! foco são de quem as tem — o servidor, com várias; o Terminal, com uma.

use protocolo::usuario::descricao::{Escritor, Retangulo, Tipo};
use protocolo::usuario::evento::acao;
use toolkit::{Interface, Resposta};

use crate::desenho::{Estilo, Tela};
use crate::superficie::Superficie;

const ESTILO_DO_TITULO: Estilo = aparencia::texto::TITULO_DA_JANELA;

// As medidas e as cores da moldura são as da linguagem visual — as mesmas
// da barra do kernel, para a janela parecer da mesma máquina. Ver
// `aparencia`. As cores vão com o byte alto cheio: as janelas se misturam
// por alfa, e um pixel de alfa zero não apareceria.
pub use aparencia::medidas::{ALTURA_DO_TITULO, BORDA, LADO_DO_FECHAR};
use aparencia::medidas::{RECUO_DO_FECHAR, RECUO_DO_TITULO};
use aparencia::uso;

const TITULO_COM_FOCO: u32 = uso::TITULO_COM_FOCO.argb();
const TITULO_SEM_FOCO: u32 = uso::TITULO_SEM_FOCO.argb();
const TEXTO_DO_TITULO: u32 = uso::TEXTO_DO_TITULO.argb();
const CAIXA_DE_FECHAR: u32 = uso::CAIXA_DE_FECHAR.argb();
const BORDA_DA_JANELA: u32 = uso::BORDA_DA_JANELA.argb();

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
/// O que o que chegou a uma janela com interface significa para o
/// programa.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gesto {
    /// Nada que o programa precise saber.
    Nada,
    /// A janela mudou: ela foi redesenhada e redescrita, e o programa não
    /// precisa fazer nada — o gesto existe para quem quiser saber.
    Redesenhada,
    /// A caixa de fechar foi acionada — pelo ponteiro ou pelo agente. O que
    /// é fechar é do programa.
    Fechar,
    /// Um botão foi acionado; o código é o que o programa lhe deu.
    Acionado(u32),
    /// O arrasto acabou, com a janela aqui.
    Arrastada(i32, i32),
}

pub struct Janela {
    superficie: Superficie,
    titulo: &'static str,
    /// Onde o canto superior esquerdo está na tela.
    x: i32,
    y: i32,
    /// O arrasto em curso: onde o ponteiro pegou a janela, nela.
    pega: Option<(i64, i64)>,
    /// A árvore de widgets, numa janela feita com
    /// [`Janela::com_interface`].
    interface: Option<Interface>,
    /// A base dos identificadores na árvore semântica: a caixa de fechar é
    /// a base, e o widget de índice `i` é `base + 1 + i`.
    base: i64,
    /// A janela tem o foco — a barra de título acesa.
    foco: bool,
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
            interface: None,
            base: 0,
            foco: false,
        })
    }

    /// Uma janela com a `interface` dentro, do tamanho que ela pede mais a
    /// moldura, em `(x, y)`. `base` separa os identificadores desta janela
    /// dos de outras do mesmo processo — ver [`Janela::acao`].
    ///
    /// Desenhada e descrita, e ainda invisível: [`Janela::mostrar`].
    pub fn com_interface(
        titulo: &'static str,
        interface: Interface,
        base: i64,
        x: i32,
        y: i32,
    ) -> Result<Janela, i64> {
        let (l, a) = interface.medir();
        let largura = l + 2 * BORDA;
        let altura = a + ALTURA_DO_TITULO + BORDA;
        let mut janela = Janela::nova(titulo, largura, altura, x, y)?;
        janela.interface = Some(interface);
        janela.base = base;
        janela.redesenhar();
        Ok(janela)
    }

    /// A interface, numa janela que tem uma.
    pub fn interface(&self) -> Option<&Interface> {
        self.interface.as_ref()
    }

    /// A área do conteúdo, na janela.
    pub fn area_do_conteudo(&self) -> Retangulo {
        let (x, y, largura, altura) = self.conteudo();
        Retangulo {
            x,
            y,
            largura,
            altura,
        }
    }

    /// A barra de título acende ou apaga.
    pub fn focar(&mut self, foco: bool) {
        if self.foco != foco {
            self.foco = foco;
            self.redesenhar();
        }
    }

    /// Desenha a moldura e a interface, acusa o dano e descreve a janela.
    /// Numa janela sem interface, só a moldura.
    pub fn redesenhar(&mut self) {
        let area = self.area_do_conteudo();
        let foco = self.foco;
        let interface = self.interface.take();
        {
            let mut tela = self.desenhar_moldura(foco);
            if let Some(ui) = &interface {
                ui.desenhar(&mut tela, area);
            }
        }
        self.interface = interface;
        let _ = self.superficie.danificar_tudo();
        if let Err(motivo) = self.descrever() {
            crate::escreverln!("janela: a descricao de {} falhou: {}", self.titulo, motivo);
        }
    }

    /// Diz ao kernel o que a janela é: a moldura, e a interface gerada da
    /// árvore. Devolve o erro, se a descrição não coube nos limites.
    pub fn descrever(&self) -> Result<(), &'static str> {
        let mut e = self.descrever_moldura(self.base);
        if let Some(ui) = &self.interface {
            ui.descrever(self.area_do_conteudo(), self.base + 1, &mut e);
        }
        let texto = e.terminar()?;
        match crate::sistema::descrever(self.descritor(), &texto) {
            0 => Ok(()),
            _ => Err("o kernel recusou a descricao"),
        }
    }

    /// O botão do ponteiro apertado em `(x, y)` da tela, dentro da janela:
    /// a caixa de fechar, o arrasto pela barra de título, ou a interface.
    pub fn apertar_em(&mut self, x: i64, y: i64) -> Gesto {
        match self.apertar(x, y) {
            Aperto::Fechar => Gesto::Fechar,
            Aperto::Arrasto => Gesto::Nada,
            Aperto::Conteudo(lx, ly) => {
                let area = self.area_do_conteudo();
                let (px, py) = (area.x as i64 + lx, area.y as i64 + ly);
                let resposta = match &mut self.interface {
                    Some(ui) => ui.apertar(area, px as u32, py as u32),
                    None => Resposta::Nada,
                };
                self.depois(resposta)
            }
        }
    }

    /// Uma tecla, com o foco nesta janela.
    pub fn tecla(&mut self, c: char) -> Gesto {
        let resposta = match &mut self.interface {
            Some(ui) => ui.tecla(c),
            None => Resposta::Nada,
        };
        self.depois(resposta)
    }

    /// Uma ação da árvore semântica — o `press` de um agente — no
    /// elemento `id`. Devolve `None` se o `id` não é desta janela.
    pub fn acao(&mut self, id: i64, qual: i64) -> Option<Gesto> {
        if id == self.base {
            return Some(if qual == acao::PRESSIONAR {
                Gesto::Fechar
            } else {
                Gesto::Nada
            });
        }
        let ui = self.interface.as_mut()?;
        let indice = u32::try_from(id - self.base - 1).ok()?;
        let resposta = ui.acao(indice, qual);
        Some(self.depois(resposta))
    }

    fn depois(&mut self, resposta: Resposta) -> Gesto {
        match resposta {
            Resposta::Nada => Gesto::Nada,
            Resposta::Redesenhar => {
                self.redesenhar();
                Gesto::Redesenhada
            }
            Resposta::Acionado(codigo) => Gesto::Acionado(codigo),
        }
    }

    /// A janela não tem pixel transparente: o compositor a copia, em vez de
    /// misturá-la com o que está embaixo — e copiar é mais barato. Para quem
    /// redesenha muito, como o Terminal.
    pub fn opaca(&self) -> Result<(), i64> {
        self.superficie.transparente(false)
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
            self.largura() - BORDA - RECUO_DO_FECHAR - lado,
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
        let cor_do_titulo = if com_foco {
            TITULO_COM_FOCO
        } else {
            TITULO_SEM_FOCO
        };
        let titulo = self.titulo;
        let mut tela = Tela {
            pixels: self.superficie.pixels(),
            largura,
        };
        tela.retangulo(0, 0, largura, altura, BORDA_DA_JANELA);
        tela.retangulo(
            BORDA,
            BORDA,
            largura - 2 * BORDA,
            ALTURA_DO_TITULO - BORDA,
            cor_do_titulo,
        );
        // O título em negrito: é o que se lê primeiro numa janela.
        tela.texto(
            (
                RECUO_DO_TITULO,
                (ALTURA_DO_TITULO - ESTILO_DO_TITULO.altura()) / 2,
            ),
            titulo,
            ESTILO_DO_TITULO,
            (TEXTO_DO_TITULO, cor_do_titulo),
        );
        // A caixa de fechar: um quadrado mais claro com um x no meio.
        tela.retangulo(cx, cy, lado, lado, CAIXA_DE_FECHAR);
        tela.texto(
            (cx + (lado - Estilo::TEXTO.largura()) / 2, cy),
            "x",
            Estilo::TEXTO,
            (TEXTO_DO_TITULO, CAIXA_DE_FECHAR),
        );
        tela
    }

    /// Começa a descrição da janela para a árvore semântica: o título, e a
    /// caixa de fechar com o identificador `fechar`. Quem descreve
    /// acrescenta o conteúdo pelo escritor, e o termina.
    pub fn descrever_moldura(&self, fechar: i64) -> Escritor {
        let (cx, cy, lado) = self.caixa_de_fechar();
        let mut e = Escritor::nova(self.titulo);
        e.elemento(
            Tipo::Botao,
            fechar,
            Retangulo {
                x: cx,
                y: cy,
                largura: lado,
                altura: lado,
            },
            "Fechar",
            "",
        );
        e
    }
}
