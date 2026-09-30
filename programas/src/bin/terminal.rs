//! O Terminal: o interpretador do kernel numa janela.
//!
//! # O que ele é
//!
//! Uma [`Janela`] do runtime com uma grade de texto dentro, e o
//! pseudo-terminal do kernel do outro lado — ver
//! [`TERMINAL`](protocolo::usuario::numero::TERMINAL). O que se digita na
//! janela é escrito no pseudo-terminal, e chega ao interpretador como se
//! tivesse sido digitado na máquina; o que o kernel imprime — o eco, as
//! respostas, o log — é lido do pseudo-terminal e desenhado na grade.
//!
//! Não há um segundo interpretador: o Terminal é outra janela sobre o mesmo.
//! O console do kernel continua embaixo, desenhando o mesmo texto: ele é o
//! fundo, e a reserva — o que se vê no boot, sem Terminal, e na falha.
//!
//! # Uma espera só
//!
//! Tudo chega pelo canal [`CANAL_DO_TERMINAL`]: o ponteiro e as teclas da
//! janela — a entrada da superfície aponta para ele —, o aviso de que o
//! pseudo-terminal tem saída, e o pedido da barra para vir para a frente. O
//! programa dorme na leitura do canal, e o pseudo-terminal se lê sem
//! bloquear, até ele devolver zero.
//!
//! # A grade
//!
//! Uma [`AreaDeTexto`] do toolkit, de [`COLUNAS`] por [`LINHAS`]: a grade
//! que o Terminal tinha, e que agora é um widget como os outros — ela se desenha, se descreve para
//! a árvore com o fim do que está nela, e redesenha só a linha que mudou.
//! O programa só escreve nela o que o pseudo-terminal entrega, e pede o
//! desenho do que mudou: [`Janela::atualizar`].
//!
//! As teclas não são da grade: vão ao pseudo-terminal, e voltam como eco.
//!
//! Cada coisa que o programa faz de notável vira uma linha no log,
//! `terminal: ...`: é por elas que a suíte acompanha o que aconteceu.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;

use programas::escreverln;
use programas::janela::{Gesto, Janela};
use programas::sistema;

use protocolo::usuario::evento::{BOTAO_ESQUERDO, CANAL_DO_TERMINAL, Evento, janela, tipo};
use toolkit::{AreaDeTexto, Indice, Interface};

/// A grade: colunas e linhas.
const COLUNAS: usize = 80;
const LINHAS: usize = 24;

/// Onde a janela abre.
const X: i32 = 24;
const Y: i32 = 40;

/// A base dos identificadores na árvore: a caixa de fechar é a base, e a
/// grade, o primeiro widget, a seguinte.
const BASE: i64 = 1;
/// A grade, na interface.
const GRADE: Indice = 0;

struct Terminal {
    janela: Janela,
    pty: u64,
    botoes: i64,
    /// O que foi digitado e o pseudo-terminal ainda não aceitou: a fila do
    /// teclado do kernel estava cheia.
    pendente: String,
}

impl Terminal {
    /// Lê o que o kernel imprimiu, até o pseudo-terminal devolver zero, e
    /// escreve na grade. Devolve se veio alguma coisa.
    fn ler_a_saida(&mut self) -> bool {
        let mut bytes = [0u8; 512];
        let mut veio = false;
        loop {
            let n = sistema::ler(self.pty, &mut bytes);
            if n <= 0 {
                return veio;
            }
            self.janela
                .com_widget::<AreaDeTexto, _>(GRADE, |g| g.receber(&bytes[..n as usize]));
            veio = true;
        }
    }

    /// Digita no interpretador o que estiver pendente.
    fn digitar_pendente(&mut self) {
        if self.pendente.is_empty() {
            return;
        }
        let aceitos = sistema::escrever(self.pty, self.pendente.as_bytes());
        if aceitos > 0 {
            self.pendente.drain(..aceitos as usize);
        }
    }

    fn tecla(&mut self, codigo: i64) {
        if let Some(c) = u32::try_from(codigo).ok().and_then(char::from_u32) {
            self.pendente.push(c);
            self.digitar_pendente();
        }
    }

    /// A barra de título acende; e o log diz, se ela estava apagada.
    fn focar(&mut self) {
        if !self.janela.com_foco() {
            self.janela.focar(true);
            escreverln!("terminal: foco");
        }
    }

    /// Devolve se a pessoa fechou a janela.
    fn ponteiro(&mut self, x: i64, y: i64, botoes: i64) -> bool {
        let apertou = botoes & BOTAO_ESQUERDO != 0 && self.botoes & BOTAO_ESQUERDO == 0;
        let soltou = botoes & BOTAO_ESQUERDO == 0 && self.botoes & BOTAO_ESQUERDO != 0;
        self.botoes = botoes;
        if self.janela.arrastando() {
            if let Some((jx, jy)) = self.janela.arrastar(x, y, soltou) {
                escreverln!("terminal: arrastado para {} {}", jx, jy);
            }
            return false;
        }
        if !apertou || !self.janela.contem(x, y) {
            return false;
        }
        // O aperto já trouxe o foco — o kernel o dá —, e traz a janela para
        // a frente.
        let _ = self.janela.superficie().trazer_para_frente();
        self.focar();
        self.janela.apertar_em(x, y) == Gesto::Fechar
    }

    /// A barra pediu o Terminal: para a frente, com o foco.
    fn vir_para_a_frente(&mut self) {
        let _ = self.janela.superficie().trazer_para_frente();
        let _ = self.janela.superficie().focar();
        self.focar();
        escreverln!("terminal: frente");
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    // O que veio de quem o lançou — o servidor de janelas bifurca e troca
    // de imagem — não é deste programa.
    for descritor in 3..16 {
        sistema::fechar(descritor);
    }

    let canal = sistema::escutar(CANAL_DO_TERMINAL);
    if canal < 0 {
        // `OCUPADO`: já há um Terminal, e é ele que atende.
        escreverln!("terminal: ja ha um terminal no ar ({})", canal);
        return 1;
    }
    let canal = canal as u64;
    let pty = sistema::terminal(canal);
    if pty < 0 {
        escreverln!("terminal: o pseudo-terminal nao abriu: {}", pty);
        return 2;
    }

    let grade = AreaDeTexto::nova("terminal", COLUNAS, LINHAS);
    let mut janela = match Janela::com_interface("Terminal", Interface::nova(grade), BASE, X, Y) {
        Ok(j) => j,
        Err(e) => {
            escreverln!("terminal: sem janela: {}", e);
            return 3;
        }
    };
    if janela.opaca().is_err() || janela.superficie().entrada(canal).is_err() {
        return 4;
    }
    janela.focar(true);
    let mut t = Terminal {
        janela,
        pty: pty as u64,
        botoes: 0,
        pendente: String::new(),
    };
    // O que o kernel já tinha impresso — o boot inteiro, se couber no anel.
    t.ler_a_saida();
    t.janela.atualizar(GRADE);
    if t.janela.mostrar().is_err() || t.janela.superficie().focar().is_err() {
        return 5;
    }
    escreverln!("terminal: pronto");

    let mut eventos = [Evento::default(); 16];
    loop {
        let n = match sistema::ler_eventos(canal, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("terminal: a leitura do canal falhou: {}", e);
                return 6;
            }
        };
        let mut mudou = false;
        for e in &eventos[..n] {
            match e.tipo {
                tipo::SAIDA => mudou |= t.ler_a_saida(),
                tipo::TECLA => t.tecla(e.a),
                tipo::PONTEIRO => {
                    if t.ponteiro(e.a, e.b, e.c) {
                        escreverln!("terminal: fechado");
                        return 0;
                    }
                }
                tipo::FOCO_PERDIDO => t.janela.focar(false),
                tipo::ABRIR if e.a == janela::TERMINAL => t.vir_para_a_frente(),
                // O `press` do agente na caixa de fechar: o mesmo fechar do
                // clique.
                tipo::ACAO => {
                    if t.janela.acao(e.a, e.b) == Some(Gesto::Fechar) {
                        escreverln!("terminal: fechado");
                        return 0;
                    }
                }
                tipo::ENCERRAR => {
                    escreverln!("terminal: encerrado");
                    return 0;
                }
                _ => {}
            }
        }
        // O que ficou pendente numa fila cheia: o interpretador já andou.
        t.digitar_pendente();
        if mudou {
            t.janela.atualizar(GRADE);
        }
    }
}
