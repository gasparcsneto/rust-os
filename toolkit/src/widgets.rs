//! Os widgets: o texto, o botão, e as duas formas de pôr um ao lado do
//! outro.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use aparencia::{medidas, texto, uso};
use protocolo::usuario::descricao::{Retangulo, Tipo};
use tipografia::Estilo;

use crate::{Semantica, Tela, Widget};

/// Texto que se lê: uma linha ou várias, separadas por `\n`.
///
/// Tem um **nome**, além do texto: é o rótulo dele na árvore, o que diz a
/// quem lê o que aquele texto é — "conteúdo", "versão" —, e o texto vai
/// como valor.
pub struct Rotulo {
    nome: String,
    texto: String,
    estilo: Estilo,
    tinta: u32,
    papel: u32,
}

impl Rotulo {
    /// Texto de corpo, escuro sobre o conteúdo claro de uma janela.
    pub fn novo(nome: &str, texto: &str) -> Rotulo {
        Rotulo {
            nome: String::from(nome),
            texto: String::from(texto),
            estilo: texto::CORPO,
            tinta: uso::TEXTO_DO_CONTEUDO.argb(),
            papel: uso::FUNDO_DO_CONTEUDO.argb(),
        }
    }

    /// Um título grande, no alto do conteúdo.
    pub fn titulo(nome: &str, texto: &str) -> Rotulo {
        Rotulo {
            estilo: texto::CABECALHO,
            ..Rotulo::novo(nome, texto)
        }
    }

    /// Outras cores: a tinta e o papel, `0xAARRGGBB`.
    pub fn com_cores(mut self, tinta: u32, papel: u32) -> Rotulo {
        self.tinta = tinta;
        self.papel = papel;
        self
    }

    pub fn texto(&self) -> &str {
        &self.texto
    }

    pub fn definir_texto(&mut self, texto: &str) {
        self.texto.clear();
        self.texto.push_str(texto);
    }

    fn linhas(&self) -> impl Iterator<Item = &str> {
        self.texto.split('\n')
    }
}

impl Widget for Rotulo {
    fn medir(&self) -> (u32, u32) {
        let largura = self
            .linhas()
            .map(|l| tipografia::largura_do_texto(l, self.estilo))
            .max()
            .unwrap_or(0);
        (largura, self.linhas().count() as u32 * self.estilo.altura())
    }

    /// Linha a linha, cortado no que couber na área: a fonte é
    /// monoespaçada, e quantas letras cabem é uma divisão.
    fn desenhar(&self, tela: &mut Tela, area: Retangulo) {
        let (lc, altura) = (self.estilo.largura(), self.estilo.altura());
        let cabem = (area.largura / lc.max(1)) as usize;
        for (i, linha) in self.linhas().enumerate() {
            let y = area.y + i as u32 * altura;
            if y + altura > area.y + area.altura {
                break;
            }
            let fim = linha
                .char_indices()
                .nth(cabem)
                .map_or(linha.len(), |(i, _)| i);
            tela.texto(
                (area.x, y),
                &linha[..fim],
                self.estilo,
                (self.tinta, self.papel),
            );
        }
    }

    fn semantica(&self) -> Option<Semantica<'_>> {
        Some(Semantica {
            tipo: Tipo::Texto,
            rotulo: &self.nome,
            valor: &self.texto,
        })
    }
}

/// Algo que se aciona.
pub struct Botao {
    rotulo: String,
}

impl Botao {
    pub fn novo(rotulo: &str) -> Botao {
        Botao {
            rotulo: String::from(rotulo),
        }
    }

    pub fn rotulo(&self) -> &str {
        &self.rotulo
    }
}

impl Widget for Botao {
    /// O texto e uma folga de cada lado, na altura dos botões da barra: o
    /// botão de uma janela é o mesmo botão.
    fn medir(&self) -> (u32, u32) {
        (
            tipografia::largura_do_texto(&self.rotulo, texto::CORPO) + 2 * medidas::FOLGA_DO_BOTAO,
            medidas::ALTURA_DO_BOTAO,
        )
    }

    fn desenhar(&self, tela: &mut Tela, area: Retangulo) {
        let fundo = uso::FUNDO_DO_BOTAO.argb();
        tela.preencher(area, fundo);
        let y = area.y + area.altura.saturating_sub(texto::CORPO.altura()) / 2;
        tela.texto(
            (area.x + medidas::FOLGA_DO_BOTAO, y),
            &self.rotulo,
            texto::CORPO,
            (uso::TEXTO_DA_BARRA.argb(), fundo),
        );
    }

    fn semantica(&self) -> Option<Semantica<'_>> {
        Some(Semantica {
            tipo: Tipo::Botao,
            rotulo: &self.rotulo,
            valor: "",
        })
    }
}

/// Em que direção uma [`Pilha`] põe os filhos.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direcao {
    Vertical,
    Horizontal,
}

/// Os filhos um depois do outro, com um espaço entre eles e um recuo em
/// volta. Cada filho recebe o tamanho que pede, cortado ao que sobra — um
/// botão numa coluna não se estica até a borda.
pub struct Pilha {
    direcao: Direcao,
    filhos: Vec<Box<dyn Widget>>,
    espaco: u32,
    recuo: u32,
    fundo: Option<u32>,
}

/// Os filhos de cima para baixo.
pub struct Coluna;

/// Os filhos da esquerda para a direita.
pub struct Linha;

impl Coluna {
    #[allow(clippy::new_ret_no_self)]
    pub fn nova() -> Pilha {
        Pilha::nova(Direcao::Vertical)
    }
}

impl Linha {
    #[allow(clippy::new_ret_no_self)]
    pub fn nova() -> Pilha {
        Pilha::nova(Direcao::Horizontal)
    }
}

impl Pilha {
    fn nova(direcao: Direcao) -> Pilha {
        Pilha {
            direcao,
            filhos: Vec::new(),
            espaco: 0,
            recuo: 0,
            fundo: None,
        }
    }

    /// Acrescenta um filho, no fim.
    pub fn com(mut self, filho: impl Widget + 'static) -> Pilha {
        self.filhos.push(Box::new(filho));
        self
    }

    /// O espaço entre dois filhos.
    pub fn espaco(mut self, espaco: u32) -> Pilha {
        self.espaco = espaco;
        self
    }

    /// O recuo em volta de todos.
    pub fn recuo(mut self, recuo: u32) -> Pilha {
        self.recuo = recuo;
        self
    }

    /// Uma cor pintada na área inteira, antes dos filhos.
    pub fn fundo(mut self, cor: u32) -> Pilha {
        self.fundo = Some(cor);
        self
    }
}

impl Widget for Pilha {
    fn medir(&self) -> (u32, u32) {
        let (mut ao_longo, mut atravessado) = (0u32, 0u32);
        for (i, filho) in self.filhos.iter().enumerate() {
            let (l, a) = filho.medir();
            let (longo, largo) = match self.direcao {
                Direcao::Vertical => (a, l),
                Direcao::Horizontal => (l, a),
            };
            ao_longo += longo + if i > 0 { self.espaco } else { 0 };
            atravessado = atravessado.max(largo);
        }
        let (longo, largo) = (ao_longo + 2 * self.recuo, atravessado + 2 * self.recuo);
        match self.direcao {
            Direcao::Vertical => (largo, longo),
            Direcao::Horizontal => (longo, largo),
        }
    }

    fn desenhar(&self, tela: &mut Tela, area: Retangulo) {
        if let Some(cor) = self.fundo {
            tela.preencher(area, cor);
        }
    }

    fn filhos(&self) -> &[Box<dyn Widget>] {
        &self.filhos
    }

    fn filhos_mut(&mut self) -> &mut [Box<dyn Widget>] {
        &mut self.filhos
    }

    fn dispor(&self, area: Retangulo) -> Vec<Retangulo> {
        let (x0, y0) = (area.x + self.recuo, area.y + self.recuo);
        let (x1, y1) = (
            (area.x + area.largura).saturating_sub(self.recuo),
            (area.y + area.altura).saturating_sub(self.recuo),
        );
        let (mut x, mut y) = (x0, y0);
        let mut areas = Vec::with_capacity(self.filhos.len());
        for filho in &self.filhos {
            let (l, a) = filho.medir();
            let r = Retangulo {
                x,
                y,
                largura: l.min(x1.saturating_sub(x)),
                altura: a.min(y1.saturating_sub(y)),
            };
            match self.direcao {
                Direcao::Vertical => y += a + self.espaco,
                Direcao::Horizontal => x += l + self.espaco,
            }
            areas.push(r);
        }
        areas
    }
}
