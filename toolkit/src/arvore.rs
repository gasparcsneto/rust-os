//! O trait dos widgets, e as três viagens pela árvore: desenhar, descrever e
//! achar um widget pelo índice.
//!
//! # Uma árvore, três leitores
//!
//! O desenho, a descrição e a entrada percorrem a **mesma** árvore, na
//! **mesma** ordem, com as **mesmas** áreas — as que [`Widget::dispor`] dá.
//! É o que faz um botão estar na árvore semântica exatamente onde está na
//! tela: as duas coisas saem de uma conta só. Se a descrição fosse escrita
//! ao lado do desenho, como era, um botão mudado de lugar num lugar e não no
//! outro faria o agente clicar no vazio.

use alloc::boxed::Box;
use alloc::vec::Vec;

use protocolo::usuario::descricao::{Escritor, Retangulo, Tipo};

use crate::Tela;

/// Onde um widget está na árvore: a ordem dele numa visita em
/// profundidade, contando a raiz como zero.
///
/// # Por que a posição, e não um nome
///
/// Porque é estável sem que ninguém o mantenha: enquanto a forma da árvore
/// for a mesma, o botão "OK" é sempre o mesmo índice, e o agente que o leu
/// numa árvore o aciona na seguinte. Um nome dado à mão seria mais uma
/// coisa para duas pessoas escreverem igual.
pub type Indice = u32;

/// O que chega a um widget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entrada {
    /// O botão do ponteiro apertado em `(x, y)`, na área do widget.
    Aperto { x: u32, y: u32 },
    /// Uma tecla, com o foco no widget.
    Tecla(char),
    /// Uma ação da árvore semântica — o `press` de um agente —, com o
    /// número dela: ver `protocolo::usuario::evento::acao`.
    Acao(i64),
}

/// O que um widget responde ao que chegou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resposta {
    /// Nada mudou.
    Nada,
    /// O widget mudou e precisa ser redesenhado.
    Redesenhar,
    /// O widget foi acionado, e o código é o que o programa lhe deu: é
    /// assim que o programa sabe que o "OK" foi apertado, pelo ponteiro,
    /// pela tecla ou pelo agente — os três chegam aqui do mesmo jeito.
    Acionado(u32),
}

impl Resposta {
    /// A mais importante das duas: acionar vence redesenhar, que vence
    /// nada.
    pub fn e(self, outra: Resposta) -> Resposta {
        match (self, outra) {
            (Resposta::Acionado(c), _) | (_, Resposta::Acionado(c)) => Resposta::Acionado(c),
            (Resposta::Redesenhar, _) | (_, Resposta::Redesenhar) => Resposta::Redesenhar,
            _ => Resposta::Nada,
        }
    }
}

/// O que um widget é, para a árvore semântica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Semantica<'a> {
    pub tipo: Tipo,
    /// O nome do elemento: o texto de um botão, ou o que um texto é.
    pub rotulo: &'a str,
    /// O conteúdo, nos tipos que o têm — ver [`Tipo::tem_valor`].
    pub valor: &'a str,
}

/// Uma coisa numa janela: sabe o tamanho que pede, se desenha na área que
/// recebe, e diz o que é.
pub trait Widget {
    /// A largura e a altura que o widget pede.
    fn medir(&self) -> (u32, u32);

    /// Desenha o widget em `area`; `foco` diz se é ele quem tem o foco da
    /// janela. Os filhos são desenhados depois, por cima — quem os
    /// percorre é [`desenhar`], e não o widget.
    fn desenhar(&self, _tela: &mut Tela, _area: Retangulo, _foco: bool) {}

    /// O widget recebe o foco — é parado pelo Tab, e pelo aperto?
    fn focavel(&self) -> bool {
        false
    }

    /// O que chegou a ele.
    fn tratar(&mut self, _entrada: Entrada) -> Resposta {
        Resposta::Nada
    }

    /// O que o widget é na árvore semântica. `None` para o que só organiza
    /// os outros, como uma coluna: ela não é nada que alguém leia ou acione.
    fn semantica(&self) -> Option<Semantica<'_>> {
        None
    }

    /// Os filhos, na ordem em que são desenhados.
    fn filhos(&self) -> &[Box<dyn Widget>] {
        &[]
    }

    fn filhos_mut(&mut self) -> &mut [Box<dyn Widget>] {
        &mut []
    }

    /// A área de cada filho, dada a área deste — na ordem de
    /// [`Widget::filhos`].
    fn dispor(&self, _area: Retangulo) -> Vec<Retangulo> {
        Vec::new()
    }
}

/// Visita a árvore em profundidade — o widget antes dos filhos —, com o
/// índice e a área de cada um.
pub fn percorrer<'a>(
    raiz: &'a dyn Widget,
    area: Retangulo,
    f: &mut impl FnMut(Indice, &'a dyn Widget, Retangulo),
) {
    let mut proximo = 0;
    visitar(raiz, area, &mut proximo, f);
}

fn visitar<'a>(
    w: &'a dyn Widget,
    area: Retangulo,
    proximo: &mut Indice,
    f: &mut impl FnMut(Indice, &'a dyn Widget, Retangulo),
) {
    f(*proximo, w, area);
    *proximo += 1;
    let areas = w.dispor(area);
    for (filho, area) in w.filhos().iter().zip(areas) {
        visitar(filho.as_ref(), area, proximo, f);
    }
}

/// Desenha a árvore inteira em `area`, com o foco no widget `foco`.
pub fn desenhar(raiz: &dyn Widget, tela: &mut Tela, area: Retangulo, foco: Option<Indice>) {
    percorrer(raiz, area, &mut |i, w, r| {
        w.desenhar(tela, r, foco == Some(i))
    });
}

/// Acrescenta ao escritor cada widget que é alguma coisa na árvore, com o
/// identificador `base + índice`.
///
/// `base` é o que separa as janelas de um mesmo processo: o identificador
/// volta a ele numa ação da árvore, e é por ele que o processo sabe de
/// qual janela e de qual widget ela é.
pub fn descrever(raiz: &dyn Widget, area: Retangulo, base: i64, escritor: &mut Escritor) {
    percorrer(raiz, area, &mut |i, w, r| {
        if let Some(s) = w.semantica() {
            escritor.elemento(s.tipo, base + i as i64, r, s.rotulo, s.valor);
        }
    });
}

/// A área do widget de índice `indice`, se a árvore o tem.
pub fn area_de(raiz: &dyn Widget, area: Retangulo, indice: Indice) -> Option<Retangulo> {
    let mut achada = None;
    percorrer(raiz, area, &mut |i, _, r| {
        if i == indice {
            achada = Some(r);
        }
    });
    achada
}

/// Entrega a `f` o widget de índice `indice`, para mudá-lo.
pub fn com_widget_mut<R>(
    raiz: &mut dyn Widget,
    indice: Indice,
    f: impl FnOnce(&mut dyn Widget) -> R,
) -> Option<R> {
    let mut proximo = 0;
    let mut f = Some(f);
    achar_mut(raiz, indice, &mut proximo, &mut f)
}

fn achar_mut<R, F: FnOnce(&mut dyn Widget) -> R>(
    w: &mut dyn Widget,
    indice: Indice,
    proximo: &mut Indice,
    f: &mut Option<F>,
) -> Option<R> {
    if *proximo == indice {
        return f.take().map(|f| f(w));
    }
    *proximo += 1;
    for filho in w.filhos_mut() {
        if let Some(r) = achar_mut(filho.as_mut(), indice, proximo, f) {
            return Some(r);
        }
    }
    None
}
