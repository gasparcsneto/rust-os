//! A área de texto: uma grade de letras que se escreve de fora, como a tela
//! de um terminal.
//!
//! # O que ela é
//!
//! Colunas por linhas de texto monoespaçado, e um cursor que anda só na
//! última. A linha que sai por cima é esquecida: não há rolagem para trás,
//! e guardar o que ninguém lê seria memória sem leitor. Quem escreve nela é o
//! programa — [`AreaDeTexto::receber`] —, com o que chega de fora: o
//! Terminal escreve a saída do interpretador. A pessoa lê a grade; o agente
//! lê o mesmo pela árvore — o fim dela, onde a resposta acabou de chegar.
//!
//! O que se escreve é texto, a quebra de linha, o retorno, o apagar e a
//! tabulação. O `\u{8}` volta uma coluna sem apagar, e quem apaga escreve
//! um espaço por cima, como num terminal de verdade. A linha longa quebra na
//! borda.
//!
//! # O que muda, e o que se redesenha
//!
//! Um eco muda uma linha só: a do cursor. [`Widget::desenhar_mudado`]
//! redesenha só ela — a não ser que a grade tenha rolado, e aí é tudo.
//! Medido no Terminal da fase 11: redesenhar a grade inteira a cada eco
//! fazia o compositor recompor a janela inteira a cada tecla, e no ARM
//! emulado isso demorava mais do que a folga do teclado virtio. A fumaça
//! digitava `agent.ping`, e chegavam `agent.` e o Enter.
//!
//! # A linha de comando
//!
//! Uma área pode ter uma [`LinhaDeComando`]: o que se está digitando depois
//! do prompt, publicado na árvore como um campo — o mesmo par que o console
//! do kernel publica, a área de texto e a linha de comando dentro dela. O
//! valor é lido da grade, e não guardado à parte: é o que está na tela, seja
//! quem for que digitou. E as ações do agente nela não mexem na grade: viram
//! o que o programa tem de digitar — ver [`LinhaDeComando::tirar_pedido`] —,
//! pelo mesmo caminho das teclas da pessoa.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::any::Any;
use core::cell::Cell;

use aparencia::{medidas, texto, uso};
use protocolo::usuario::descricao::{MAIOR_TEXTO, Retangulo, Tipo};
use protocolo::usuario::evento::acao;
use protocolo::usuario::terminal::{APAGAR_A_LINHA, CONFIRMAR_PELO_AGENTE};

use crate::arvore::{Entrada, Resposta};
use crate::{Semantica, Tela, Widget};

/// Uma grade de texto escrita pelo programa.
pub struct AreaDeTexto {
    nome: String,
    colunas: usize,
    visiveis: usize,
    /// As linhas à vista, no máximo `visiveis`; a grade sempre tem uma —
    /// nasce com uma, e quebrar põe a nova antes de tirar a mais velha.
    linhas: Vec<Vec<char>>,
    /// A coluna do cursor, na última linha.
    coluna: usize,
    /// Os bytes de um caractere que chegou partido entre duas entregas.
    partido: [u8; 4],
    partidos: usize,
    /// A grade rolou — ou nunca foi desenhada — desde o último desenho:
    /// o próximo é inteiro. Numa célula porque desenhar não muda o widget,
    /// só o que ele sabe do que já está na tela.
    rolou: Cell<bool>,
    /// O fim da grade, como vai para a árvore — ver
    /// [`AreaDeTexto::receber`].
    na_arvore: String,
    /// A linha de comando, se a área tem uma: o único filho.
    filhos: Vec<Box<dyn Widget>>,
    /// O prompt dela, para achá-la na grade.
    prompt: Vec<char>,
}

impl AreaDeTexto {
    /// Uma grade vazia de `colunas` por `linhas`. O `nome` é o rótulo
    /// dela na árvore.
    pub fn nova(nome: &str, colunas: usize, linhas: usize) -> AreaDeTexto {
        AreaDeTexto {
            nome: String::from(nome),
            colunas: colunas.max(1),
            visiveis: linhas.max(1),
            linhas: alloc::vec![Vec::new()],
            coluna: 0,
            partido: [0; 4],
            partidos: 0,
            rolou: Cell::new(true),
            na_arvore: String::new(),
            filhos: Vec::new(),
            prompt: Vec::new(),
        }
    }

    /// A área com a `linha` de comando dentro — ver o cabeçalho do módulo.
    pub fn com_linha_de_comando(mut self, linha: LinhaDeComando) -> AreaDeTexto {
        self.prompt = linha.prompt.chars().collect();
        self.filhos = alloc::vec![Box::new(linha)];
        self.refazer_a_arvore();
        self
    }

    /// Onde a linha de comando está: a linha da grade em que o prompt
    /// começa, e o que foi digitado depois dele, até o cursor. `None` se a
    /// linha do cursor não é a do prompt, nem a continuação dela — um
    /// comando rodando, ou saída que não é prompt.
    ///
    /// A linha longa quebra na borda: o prompt pode estar algumas linhas
    /// acima, e as do meio estão cheias.
    fn achar_a_linha(&self) -> Option<(usize, String)> {
        if self.prompt.is_empty() {
            return None;
        }
        let ultima = self.linhas.len() - 1;
        let mut i = ultima;
        loop {
            if self.linhas[i].starts_with(&self.prompt) {
                let mut digitado = String::new();
                for (j, linha) in self.linhas[i..].iter().enumerate() {
                    let de = if j == 0 { self.prompt.len() } else { 0 };
                    let ate = if i + j == ultima {
                        self.coluna.min(linha.len())
                    } else {
                        linha.len()
                    };
                    if de < ate {
                        digitado.extend(&linha[de..ate]);
                    }
                }
                return Some((i, digitado));
            }
            if i == 0 || self.linhas[i - 1].len() < self.colunas {
                return None;
            }
            i -= 1;
        }
    }

    fn quebrar(&mut self) {
        self.rolou.set(true);
        self.linhas.push(Vec::new());
        if self.linhas.len() > self.visiveis {
            self.linhas.remove(0);
        }
        self.coluna = 0;
    }

    fn escrever(&mut self, c: char) {
        match c {
            '\n' => self.quebrar(),
            '\r' => self.coluna = 0,
            '\u{8}' => self.coluna = self.coluna.saturating_sub(1),
            '\t' => {
                let proxima = (self.coluna / 8 + 1) * 8;
                while self.coluna < proxima.min(self.colunas) {
                    self.escrever(' ');
                }
            }
            c if c.is_control() => {}
            c => {
                if self.coluna >= self.colunas {
                    self.quebrar();
                }
                let coluna = self.coluna;
                if let Some(linha) = self.linhas.last_mut() {
                    if coluna < linha.len() {
                        linha[coluna] = c;
                    } else {
                        linha.resize(coluna, ' ');
                        linha.push(c);
                    }
                }
                self.coluna += 1;
            }
        }
    }

    /// Escreve os bytes que chegaram. Um caractere partido no fim fica
    /// guardado até a próxima entrega; um byte que não é UTF-8 vira `?`.
    ///
    /// E refaz o texto da árvore: as linhas de baixo que cabem no valor de
    /// um elemento, sem os espaços do fim — o teto é o de
    /// [`MAIOR_TEXTO`], e o que interessa a quem lê é o que está embaixo.
    pub fn receber(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.partido[self.partidos] = b;
            self.partidos += 1;
            match core::str::from_utf8(&self.partido[..self.partidos]) {
                Ok(s) => {
                    let c = s.chars().next().unwrap_or('?');
                    self.partidos = 0;
                    self.escrever(c);
                }
                Err(e) if e.error_len().is_none() && self.partidos < 4 => {}
                Err(_) => {
                    self.partidos = 0;
                    self.escrever('?');
                }
            }
        }
        self.refazer_a_arvore();
    }

    fn refazer_a_arvore(&mut self) {
        let visiveis = self.linhas_visiveis();
        let mut usados = 0;
        let mut primeira = visiveis.len();
        for (i, linha) in visiveis.iter().enumerate().rev() {
            // A linha, e a quebra que a separa da seguinte.
            let custo = linha_sem_o_fim(linha).len() + usize::from(i + 1 < visiveis.len());
            if usados + custo > MAIOR_TEXTO {
                break;
            }
            usados += custo;
            primeira = i;
        }
        let mut texto = String::with_capacity(usados);
        for (i, linha) in visiveis[primeira..].iter().enumerate() {
            if i > 0 {
                texto.push('\n');
            }
            texto.push_str(&linha_sem_o_fim(linha));
        }
        self.na_arvore = texto;
        let digitado = self.achar_a_linha().map(|(_, d)| d).unwrap_or_default();
        if let Some(linha) = self.filhos.first_mut() {
            let linha: &mut dyn Any = linha.as_mut();
            if let Some(linha) = linha.downcast_mut::<LinhaDeComando>() {
                linha.valor = digitado;
            }
        }
    }

    fn linhas_visiveis(&self) -> &[Vec<char>] {
        &self.linhas
    }

    /// O texto à vista, linha a linha — o que a pessoa lê.
    pub fn texto_visivel(&self) -> Vec<String> {
        self.linhas_visiveis()
            .iter()
            .map(|l| l.iter().collect())
            .collect()
    }

    /// Onde o cursor está: a linha, entre as visíveis, e a coluna.
    pub fn cursor(&self) -> (usize, usize) {
        (
            self.linhas_visiveis().len() - 1,
            self.coluna.min(self.colunas - 1),
        )
    }

    /// Onde a grade começa, na área.
    fn origem(area: Retangulo) -> (u32, u32) {
        (
            area.x + medidas::FOLGA_DA_GRADE,
            area.y + medidas::FOLGA_DA_GRADE,
        )
    }

    fn desenhar_linha(&self, tela: &mut Tela, area: Retangulo, i: usize) {
        let (x0, y0) = AreaDeTexto::origem(area);
        let Some(linha) = self.linhas_visiveis().get(i) else {
            return;
        };
        let texto: String = linha.iter().collect();
        tela.texto(
            (x0, y0 + i as u32 * texto::CORPO.altura()),
            &texto,
            texto::CORPO,
            (uso::TEXTO_DO_CONSOLE.argb(), uso::FUNDO_DO_CONSOLE.argb()),
        );
    }

    /// O cursor: um bloco com a letra de baixo, com o foco; um traço
    /// embaixo dela, sem ele.
    fn desenhar_cursor(&self, tela: &mut Tela, area: Retangulo, foco: bool) {
        let (x0, y0) = AreaDeTexto::origem(area);
        let (lc, ac) = (texto::CORPO.largura(), texto::CORPO.altura());
        let (linha, coluna) = self.cursor();
        let (x, y) = (x0 + coluna as u32 * lc, y0 + linha as u32 * ac);
        let cursor = uso::CURSOR_DE_TEXTO.argb();
        if foco {
            let sob = self
                .linhas_visiveis()
                .get(linha)
                .and_then(|l| l.get(coluna))
                .copied()
                .unwrap_or(' ');
            let mut um = [0u8; 4];
            tela.texto(
                (x, y),
                sob.encode_utf8(&mut um),
                texto::CORPO,
                (uso::FUNDO_DO_CONSOLE.argb(), cursor),
            );
        } else {
            tela.retangulo(x, y + ac - 2, lc, 2, cursor);
        }
    }

    /// A faixa da linha `i`, de uma borda à outra da área.
    fn faixa(area: Retangulo, i: usize) -> Retangulo {
        let (_, y0) = AreaDeTexto::origem(area);
        let ac = texto::CORPO.altura();
        Retangulo {
            x: area.x,
            y: y0 + i as u32 * ac,
            largura: area.largura,
            altura: ac,
        }
    }
}

/// A linha como texto, sem os espaços do fim: o que sobra de uma linha
/// apagada não é conteúdo.
fn linha_sem_o_fim(linha: &[char]) -> String {
    let fim = linha.iter().rposition(|&c| c != ' ').map_or(0, |i| i + 1);
    linha[..fim].iter().collect()
}

impl Widget for AreaDeTexto {
    /// A grade inteira, e a folga em volta.
    fn medir(&self) -> (u32, u32) {
        let folga = 2 * medidas::FOLGA_DA_GRADE;
        (
            self.colunas as u32 * texto::CORPO.largura() + folga,
            self.visiveis as u32 * texto::CORPO.altura() + folga,
        )
    }

    fn desenhar(&self, tela: &mut Tela, area: Retangulo, foco: bool) {
        self.rolou.set(false);
        tela.preencher(area, uso::FUNDO_DO_CONSOLE.argb());
        for i in 0..self.linhas_visiveis().len() {
            self.desenhar_linha(tela, area, i);
        }
        self.desenhar_cursor(tela, area, foco);
    }

    /// Só a linha do cursor, se a grade não rolou: é só nela que se
    /// escreve.
    fn desenhar_mudado(&self, tela: &mut Tela, area: Retangulo, foco: bool) -> Option<Retangulo> {
        if self.rolou.get() {
            return None;
        }
        let (linha, _) = self.cursor();
        let faixa = AreaDeTexto::faixa(area, linha);
        tela.preencher(faixa, uso::FUNDO_DO_CONSOLE.argb());
        self.desenhar_linha(tela, area, linha);
        self.desenhar_cursor(tela, area, foco);
        Some(faixa)
    }

    fn semantica(&self) -> Option<Semantica<'_>> {
        Some(Semantica {
            tipo: Tipo::Area,
            rotulo: &self.nome,
            valor: &self.na_arvore,
        })
    }

    fn filhos(&self) -> &[Box<dyn Widget>] {
        &self.filhos
    }

    fn filhos_mut(&mut self) -> &mut [Box<dyn Widget>] {
        &mut self.filhos
    }

    /// A linha de comando fica onde está na grade: depois do prompt, na
    /// linha dele; ou das linhas dele até a do cursor, inteiras, quando ela
    /// quebrou na borda. Sem prompt à vista, a linha do cursor.
    fn dispor(&self, area: Retangulo) -> Vec<Retangulo> {
        if self.filhos.is_empty() {
            return Vec::new();
        }
        let (x0, y0) = AreaDeTexto::origem(area);
        let (lc, ac) = (texto::CORPO.largura(), texto::CORPO.altura());
        let ultima = self.linhas.len() - 1;
        let largura_da_grade = self.colunas as u32 * lc;
        let r = match self.achar_a_linha() {
            Some((i, _)) if i == ultima => {
                let dentro = self.prompt.len() as u32 * lc;
                Retangulo {
                    x: x0 + dentro,
                    y: y0 + i as u32 * ac,
                    largura: largura_da_grade.saturating_sub(dentro),
                    altura: ac,
                }
            }
            Some((i, _)) => Retangulo {
                x: x0,
                y: y0 + i as u32 * ac,
                largura: largura_da_grade,
                altura: (ultima - i + 1) as u32 * ac,
            },
            None => Retangulo {
                x: x0,
                y: y0 + ultima as u32 * ac,
                largura: largura_da_grade,
                altura: ac,
            },
        };
        alloc::vec![r]
    }

    /// Recebe o foco: o cursor diz se a janela é a que recebe as teclas. As
    /// teclas mesmo não são dela — o programa as leva para onde quiser.
    fn focavel(&self) -> bool {
        true
    }
}

/// A linha de comando de uma [`AreaDeTexto`]: o que se está digitando
/// depois do prompt, como um campo da árvore.
///
/// Ela não se desenha — o que está digitado já está na grade — e não se
/// edita por dentro: o valor é o que a área leu da grade. As ações do agente
/// viram o que o programa tem de digitar, para chegar ao interpretador pelo
/// mesmo caminho das teclas da pessoa:
///
/// - `set_value`: apagar a linha inteira, e digitar o texto;
/// - `cancel`: apagar a linha inteira;
/// - `confirm`: o Enter — o do agente, que o log atribui a ele.
///
/// Cada uma responde [`Resposta::Acionado`] com o código da linha: é o
/// aviso de que há o que digitar, em [`LinhaDeComando::tirar_pedido`]. O
/// valor novo aparece na árvore quando o eco chega à grade.
pub struct LinhaDeComando {
    nome: String,
    prompt: String,
    codigo: u32,
    valor: String,
    pedido: String,
}

impl LinhaDeComando {
    /// A linha que começa depois de `prompt`, com o `nome` na árvore, e que
    /// responde `codigo` quando há o que digitar.
    pub fn nova(nome: &str, prompt: &str, codigo: u32) -> LinhaDeComando {
        LinhaDeComando {
            nome: String::from(nome),
            prompt: String::from(prompt),
            codigo,
            valor: String::new(),
            pedido: String::new(),
        }
    }

    /// O que está digitado, como a grade mostra.
    pub fn valor(&self) -> &str {
        &self.valor
    }

    /// O que as ações pediram para digitar, na ordem, e esvazia o pedido.
    pub fn tirar_pedido(&mut self) -> String {
        core::mem::take(&mut self.pedido)
    }
}

impl Widget for LinhaDeComando {
    /// Nada: a área a põe onde o prompt está.
    fn medir(&self) -> (u32, u32) {
        (0, 0)
    }

    fn semantica(&self) -> Option<Semantica<'_>> {
        Some(Semantica {
            tipo: Tipo::Campo,
            rotulo: &self.nome,
            valor: &self.valor,
        })
    }

    fn tratar(&mut self, entrada: Entrada) -> Resposta {
        match entrada {
            Entrada::Acao(acao::CONFIRMAR) => self.pedido.push(CONFIRMAR_PELO_AGENTE),
            Entrada::Acao(acao::CANCELAR) => self.pedido.push(APAGAR_A_LINHA),
            _ => return Resposta::Nada,
        }
        Resposta::Acionado(self.codigo)
    }

    fn definir_valor(&mut self, valor: &str) -> Resposta {
        self.pedido.push(APAGAR_A_LINHA);
        self.pedido.push_str(valor);
        Resposta::Acionado(self.codigo)
    }
}
