//! Os widgets: o texto, o botão, e as duas formas de pôr um ao lado do
//! outro.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use aparencia::{medidas, texto, uso};
use protocolo::usuario::descricao::{MAIOR_TEXTO, Retangulo, Tipo};
use tipografia::Estilo;

use protocolo::usuario::evento::acao;

use crate::arvore::{Entrada, Resposta};
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
    fn desenhar(&self, tela: &mut Tela, area: Retangulo, _foco: bool) {
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
///
/// Pelo ponteiro, pelo Enter ou pelo espaço com o foco nele, ou pelo `press`
/// de um agente na árvore — os três respondem [`Resposta::Acionado`] com o
/// código que o programa deu ao botão. Não há um caminho do agente e outro
/// da pessoa: o agente aperta o mesmo botão.
pub struct Botao {
    rotulo: String,
    codigo: u32,
}

impl Botao {
    /// Um botão com `rotulo`, que responde `codigo` quando acionado.
    pub fn novo(rotulo: &str, codigo: u32) -> Botao {
        Botao {
            rotulo: String::from(rotulo),
            codigo,
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

    /// Com o foco, um anel no acento em volta — o que diz a quem usa o
    /// teclado onde o Enter vai cair.
    fn desenhar(&self, tela: &mut Tela, area: Retangulo, foco: bool) {
        let fundo = uso::FUNDO_DO_BOTAO.argb();
        tela.preencher(area, fundo);
        if foco {
            let anel = uso::TITULO_COM_FOCO.argb();
            let (x, y, l, a) = (area.x, area.y, area.largura, area.altura);
            tela.retangulo(x, y, l, 2, anel);
            tela.retangulo(x, (y + a).saturating_sub(2), l, 2, anel);
            tela.retangulo(x, y, 2, a, anel);
            tela.retangulo((x + l).saturating_sub(2), y, 2, a, anel);
        }
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

    fn focavel(&self) -> bool {
        true
    }

    fn tratar(&mut self, entrada: Entrada) -> Resposta {
        match entrada {
            Entrada::Aperto { .. }
            | Entrada::Tecla('\n' | ' ')
            | Entrada::Acao(acao::PRESSIONAR) => Resposta::Acionado(self.codigo),
            _ => Resposta::Nada,
        }
    }
}

/// Uma linha de texto que se edita.
///
/// A pessoa digita com o foco nele, apaga com o backspace, põe o cursor com
/// o aperto, e confirma com o Enter; o agente confirma, esvazia e troca o
/// valor pela árvore — `confirm`, `cancel` e `set_value`. Os dois caminhos
/// chegam aqui pelo mesmo [`Widget::tratar`], e o confirmar responde o
/// código que o programa deu ao campo, venha de quem vier.
pub struct Campo {
    nome: String,
    valor: String,
    /// Onde o cursor está, em caracteres.
    cursor: usize,
    /// Quantas letras cabem à vista.
    letras: u32,
    codigo: u32,
}

impl Campo {
    /// Um campo vazio com `letras` de largura, que responde `codigo` quando
    /// confirmado. O `nome` é o rótulo dele na árvore.
    pub fn novo(nome: &str, letras: u32, codigo: u32) -> Campo {
        Campo {
            nome: String::from(nome),
            valor: String::new(),
            cursor: 0,
            letras: letras.max(1),
            codigo,
        }
    }

    pub fn valor(&self) -> &str {
        &self.valor
    }

    fn caracteres(&self) -> usize {
        self.valor.chars().count()
    }

    /// O byte onde o caractere `n` começa.
    fn byte(&self, n: usize) -> usize {
        self.valor
            .char_indices()
            .nth(n)
            .map_or(self.valor.len(), |(i, _)| i)
    }

    /// O primeiro caractere à vista: o texto rola para o cursor não sair
    /// dela, deixando uma coluna para ele depois do fim.
    fn inicio(&self) -> usize {
        self.cursor.saturating_sub(self.letras as usize - 1)
    }

    fn borda(foco: bool) -> u32 {
        if foco { 2 } else { 1 }
    }
}

impl Widget for Campo {
    fn medir(&self) -> (u32, u32) {
        (
            self.letras * texto::CORPO.largura() + 2 * (medidas::FOLGA_DO_CAMPO + 2),
            medidas::ALTURA_DO_CAMPO,
        )
    }

    fn desenhar(&self, tela: &mut Tela, area: Retangulo, foco: bool) {
        let papel = uso::FUNDO_DO_CONTEUDO.argb();
        let (cor, b) = if foco {
            (uso::BORDA_COM_FOCO.argb(), Campo::borda(true))
        } else {
            (uso::BORDA_DO_CAMPO.argb(), Campo::borda(false))
        };
        tela.preencher(area, cor);
        let dentro = Retangulo {
            x: area.x + b,
            y: area.y + b,
            largura: area.largura.saturating_sub(2 * b),
            altura: area.altura.saturating_sub(2 * b),
        };
        tela.preencher(dentro, papel);
        let lc = texto::CORPO.largura();
        let x0 = area.x + 2 + medidas::FOLGA_DO_CAMPO;
        let y = area.y + area.altura.saturating_sub(texto::CORPO.altura()) / 2;
        let inicio = self.inicio();
        let visivel: String = self
            .valor
            .chars()
            .skip(inicio)
            .take(self.letras as usize)
            .collect();
        tela.texto(
            (x0, y),
            &visivel,
            texto::CORPO,
            (uso::TEXTO_DO_CONTEUDO.argb(), papel),
        );
        if foco {
            let x = x0 + (self.cursor - inicio) as u32 * lc;
            tela.retangulo(x, y, 2, texto::CORPO.altura(), uso::CURSOR_DE_TEXTO.argb());
        }
    }

    fn semantica(&self) -> Option<Semantica<'_>> {
        Some(Semantica {
            tipo: Tipo::Campo,
            rotulo: &self.nome,
            valor: &self.valor,
        })
    }

    fn focavel(&self) -> bool {
        true
    }

    fn tratar(&mut self, entrada: Entrada) -> Resposta {
        match entrada {
            Entrada::Tecla('\n') | Entrada::Acao(acao::CONFIRMAR) => {
                Resposta::Acionado(self.codigo)
            }
            Entrada::Acao(acao::CANCELAR) => {
                self.valor.clear();
                self.cursor = 0;
                Resposta::Redesenhar
            }
            Entrada::Tecla('\u{8}') => {
                if self.cursor == 0 {
                    return Resposta::Nada;
                }
                self.cursor -= 1;
                let i = self.byte(self.cursor);
                self.valor.remove(i);
                Resposta::Redesenhar
            }
            Entrada::Tecla(c) if !c.is_control() => {
                if self.valor.len() + c.len_utf8() > MAIOR_TEXTO {
                    return Resposta::Nada;
                }
                let i = self.byte(self.cursor);
                self.valor.insert(i, c);
                self.cursor += 1;
                Resposta::Redesenhar
            }
            Entrada::Aperto { x, .. } => {
                let coluna = x.saturating_sub(2 + medidas::FOLGA_DO_CAMPO) / texto::CORPO.largura();
                let cursor = (self.inicio() + coluna as usize).min(self.caracteres());
                if cursor == self.cursor {
                    return Resposta::Nada;
                }
                self.cursor = cursor;
                Resposta::Redesenhar
            }
            _ => Resposta::Nada,
        }
    }

    /// O valor inteiro trocado, cortado no teto de um valor da árvore, com
    /// o cursor no fim — onde a pessoa continuaria digitando.
    fn definir_valor(&mut self, valor: &str) -> Resposta {
        let mut fim = valor.len().min(MAIOR_TEXTO);
        while !valor.is_char_boundary(fim) {
            fim -= 1;
        }
        self.valor.clear();
        self.valor.push_str(&valor[..fim]);
        self.cursor = self.caracteres();
        Resposta::Redesenhar
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
    /// O menor tamanho que a pilha pede, ainda que os filhos peçam menos.
    minimo: (u32, u32),
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
            minimo: (0, 0),
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

    /// Pede ao menos `largura` por `altura`: uma janela de um tamanho
    /// dado, com os filhos no alto e o resto do fundo.
    pub fn minimo(mut self, largura: u32, altura: u32) -> Pilha {
        self.minimo = (largura, altura);
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
        let (l, a) = match self.direcao {
            Direcao::Vertical => (largo, longo),
            Direcao::Horizontal => (longo, largo),
        };
        (l.max(self.minimo.0), a.max(self.minimo.1))
    }

    fn desenhar(&self, tela: &mut Tela, area: Retangulo, _foco: bool) {
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
