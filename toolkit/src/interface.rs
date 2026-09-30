//! A árvore de uma janela, com o foco: onde a entrada chega aos widgets.
//!
//! # Três caminhos, uma chegada
//!
//! A pessoa aperta o botão do ponteiro, ou digita; o agente pede uma ação
//! na árvore semântica. Os três chegam ao mesmo widget, pelo mesmo
//! [`Widget::tratar`], e o que o widget responde não depende de quem foi:
//! o "OK" acionado pelo agente é o "OK" acionado pela pessoa. Achar o widget
//! usa as mesmas áreas do desenho e da descrição — ver [`crate::arvore`] —,
//! então o ponto onde a pessoa aperta, a moldura que o agente lê e o botão
//! desenhado são o mesmo retângulo.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::any::Any;

use protocolo::usuario::descricao::{Escritor, Retangulo};

use crate::Tela;
use crate::arvore::{self, Entrada, Indice, Resposta, Widget, com_widget_mut, percorrer};

/// A árvore de uma janela, e o widget com o foco.
pub struct Interface {
    raiz: Box<dyn Widget>,
    foco: Option<Indice>,
}

impl Interface {
    /// A interface de `raiz`, com o foco no primeiro widget que o recebe.
    pub fn nova(raiz: impl Widget + 'static) -> Interface {
        let mut i = Interface {
            raiz: Box::new(raiz),
            foco: None,
        };
        i.foco = i.focaveis().first().copied();
        i
    }

    /// O tamanho que a árvore pede.
    pub fn medir(&self) -> (u32, u32) {
        self.raiz.medir()
    }

    pub fn raiz(&self) -> &dyn Widget {
        self.raiz.as_ref()
    }

    /// O widget com o foco, se algum.
    pub fn foco(&self) -> Option<Indice> {
        self.foco
    }

    /// Os widgets que recebem o foco, na ordem do Tab — a da árvore.
    pub fn focaveis(&self) -> Vec<Indice> {
        let mut todos = Vec::new();
        percorrer(self.raiz.as_ref(), Retangulo::default(), &mut |i, w, _| {
            if w.focavel() {
                todos.push(i);
            }
        });
        todos
    }

    /// Desenha a árvore em `area`. `ativa` diz se a janela tem o foco: o
    /// anel de um botão e o cursor de um campo só aparecem na janela que
    /// recebe as teclas — é onde a tecla vai cair.
    pub fn desenhar(&self, tela: &mut Tela, area: Retangulo, ativa: bool) {
        arvore::desenhar(self.raiz.as_ref(), tela, area, self.foco.filter(|_| ativa));
    }

    /// Desenha só o que mudou no widget `indice`, e diz onde — ver
    /// [`Widget::desenhar_mudado`]. `None` quando ele não sabe dizer, ou
    /// não existe: aí se redesenha tudo.
    pub fn desenhar_mudado(
        &self,
        indice: Indice,
        tela: &mut Tela,
        area: Retangulo,
        ativa: bool,
    ) -> Option<Retangulo> {
        let foco = self.foco.filter(|_| ativa);
        let mut dano = None;
        percorrer(self.raiz.as_ref(), area, &mut |i, w, r| {
            if i == indice {
                dano = w.desenhar_mudado(tela, r, foco == Some(i));
            }
        });
        dano
    }

    /// Entrega a `f` o widget `indice` com o tipo `T` que o programa pôs
    /// ali — para mudá-lo por fora da entrada, como a saída que chega a um
    /// terminal. `None` se o índice não existe, ou se o widget é de outro
    /// tipo.
    ///
    /// Quem muda um widget por aqui pede o desenho depois: a interface não
    /// sabe o que mudou.
    pub fn com_widget<T: Widget, R>(
        &mut self,
        indice: Indice,
        f: impl FnOnce(&mut T) -> R,
    ) -> Option<R> {
        com_widget_mut(self.raiz.as_mut(), indice, |w| {
            let w: &mut dyn Any = w;
            w.downcast_mut::<T>().map(f)
        })
        .flatten()
    }

    /// Acrescenta a árvore ao escritor, com os identificadores
    /// `base + índice`.
    pub fn descrever(&self, area: Retangulo, base: i64, escritor: &mut Escritor) {
        arvore::descrever(self.raiz.as_ref(), area, base, escritor);
    }

    /// O botão do ponteiro apertado em `(x, y)`, nas coordenadas de `area`.
    ///
    /// Vai ao widget mais fundo que contém o ponto — o último da visita, que
    /// é o que está desenhado por cima. Se ele recebe o foco, o foco vai
    /// para ele: apertar um botão é também escolhê-lo.
    pub fn apertar(&mut self, area: Retangulo, x: u32, y: u32) -> Resposta {
        let mut alvo = None;
        percorrer(self.raiz.as_ref(), area, &mut |i, w, r| {
            let dentro = x >= r.x && y >= r.y && x < r.x + r.largura && y < r.y + r.altura;
            if dentro {
                alvo = Some((i, r, w.focavel()));
            }
        });
        let Some((indice, r, focavel)) = alvo else {
            return Resposta::Nada;
        };
        let mut resposta = Resposta::Nada;
        if focavel && self.foco != Some(indice) {
            self.foco = Some(indice);
            resposta = Resposta::Redesenhar;
        }
        let entrada = Entrada::Aperto {
            x: x - r.x,
            y: y - r.y,
        };
        let tratada = com_widget_mut(self.raiz.as_mut(), indice, |w| w.tratar(entrada))
            .unwrap_or(Resposta::Nada);
        resposta.e(tratada)
    }

    /// Uma tecla. O Tab leva o foco ao próximo widget que o recebe, dando a
    /// volta; o resto vai ao widget com o foco.
    pub fn tecla(&mut self, c: char) -> Resposta {
        if c == '\t' {
            let focaveis = self.focaveis();
            let proximo = match self
                .foco
                .and_then(|f| focaveis.iter().position(|&i| i == f))
            {
                Some(p) => focaveis.get((p + 1) % focaveis.len()).copied(),
                None => focaveis.first().copied(),
            };
            if proximo == self.foco {
                return Resposta::Nada;
            }
            self.foco = proximo;
            return Resposta::Redesenhar;
        }
        let Some(foco) = self.foco else {
            return Resposta::Nada;
        };
        com_widget_mut(self.raiz.as_mut(), foco, |w| w.tratar(Entrada::Tecla(c)))
            .unwrap_or(Resposta::Nada)
    }

    /// Um valor novo para o widget `indice`, pedido por um agente pela
    /// árvore. Como [`Interface::acao`], não mexe no foco.
    pub fn definir_valor(&mut self, indice: Indice, valor: &str) -> Resposta {
        com_widget_mut(self.raiz.as_mut(), indice, |w| w.definir_valor(valor))
            .unwrap_or(Resposta::Nada)
    }

    /// Uma ação da árvore semântica no widget `indice` — o `press` de um
    /// agente. Não mexe no foco: o agente aciona sem escolher, como quem
    /// aperta um atalho.
    pub fn acao(&mut self, indice: Indice, acao: i64) -> Resposta {
        com_widget_mut(self.raiz.as_mut(), indice, |w| {
            w.tratar(Entrada::Acao(acao))
        })
        .unwrap_or(Resposta::Nada)
    }
}
