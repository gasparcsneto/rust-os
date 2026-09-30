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
//! [`COLUNAS`] por [`LINHAS`], com as últimas [`GUARDADAS`] linhas guardadas.
//! O cursor anda só na última: o que o kernel manda é texto, a quebra de
//! linha, o retorno e o apagar — o `\u{8}` volta uma coluna sem apagar, e o
//! interpretador apaga escrevendo um espaço por cima, como num terminal de
//! verdade. A linha longa quebra na borda.
//!
//! Cada coisa que o programa faz de notável vira uma linha no log,
//! `terminal: ...`: é por elas que a suíte acompanha o que aconteceu.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use programas::desenho::Estilo;
use programas::escreverln;
use programas::janela::{Aperto, Janela};
use programas::sistema;

use protocolo::usuario::descricao;
use protocolo::usuario::evento::acao as evento_acao;
use protocolo::usuario::evento::{BOTAO_ESQUERDO, CANAL_DO_TERMINAL, Evento, janela, tipo};

/// A grade: colunas e linhas visíveis, e quantas linhas se guardam.
const COLUNAS: usize = 80;
const LINHAS: usize = 24;
const GUARDADAS: usize = 200;

/// A folga entre a moldura e a grade.
const FOLGA: u32 = aparencia::medidas::FOLGA_DA_GRADE;
/// O estilo da grade: o do console.
const ESTILO: Estilo = aparencia::texto::CORPO;
/// Onde a janela abre.
const X: i32 = 24;
const Y: i32 = 40;

// A paleta do console do kernel, para o Terminal ser o mesmo console.
const FUNDO: u32 = aparencia::uso::FUNDO_DO_CONSOLE.argb();
const TINTA: u32 = aparencia::uso::TEXTO_DO_CONSOLE.argb();
const CURSOR: u32 = aparencia::uso::CURSOR_DE_TEXTO.argb();

/// Os elementos da janela, na árvore.
const ELEMENTO_FECHAR: i64 = 1;
const ELEMENTO_TEXTO: i64 = 2;

/// Quantos bytes do fim da grade vão para a árvore: o valor de um elemento
/// tem um teto — ver [`descricao::MAIOR_TEXTO`] —, e o que interessa a quem
/// lê é o que está embaixo, onde a resposta acabou de chegar.
const TEXTO_NA_ARVORE: usize = descricao::MAIOR_TEXTO - 64;

/// O texto: as linhas guardadas, e a coluna do cursor na última.
struct Grade {
    linhas: Vec<Vec<char>>,
    coluna: usize,
    /// Houve quebra de linha desde o último desenho: a grade rolou, e tudo
    /// tem de ser redesenhado. Sem quebra, só a última linha mudou — é nela
    /// que o cursor anda, e só nela que se escreve.
    quebrou: bool,
    /// Os bytes de um caractere que chegou partido entre duas leituras.
    partido: [u8; 4],
    partidos: usize,
}

impl Grade {
    fn nova() -> Grade {
        Grade {
            linhas: alloc::vec![Vec::new()],
            coluna: 0,
            quebrou: true,
            partido: [0; 4],
            partidos: 0,
        }
    }

    fn quebrar(&mut self) {
        self.quebrou = true;
        self.linhas.push(Vec::new());
        if self.linhas.len() > GUARDADAS {
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
                while self.coluna < proxima.min(COLUNAS) {
                    self.escrever(' ');
                }
            }
            c if c.is_control() => {}
            c => {
                if self.coluna >= COLUNAS {
                    self.quebrar();
                }
                let coluna = self.coluna;
                // A grade sempre tem uma linha: nasce com uma, e quebrar
                // põe a nova antes de tirar a mais velha.
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

    /// Escreve os bytes que o pseudo-terminal entregou. Um caractere partido
    /// no fim fica guardado até a próxima leitura; um byte que não é UTF-8
    /// vira o substituto.
    fn receber(&mut self, bytes: &[u8]) {
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
    }

    /// As linhas visíveis: as últimas [`LINHAS`].
    fn visiveis(&self) -> &[Vec<char>] {
        &self.linhas[self.linhas.len().saturating_sub(LINHAS)..]
    }
}

struct Terminal {
    janela: Janela,
    grade: Grade,
    pty: u64,
    foco: bool,
    /// A moldura mudou desde o último desenho — o foco veio ou foi.
    moldura_mudou: bool,
    botoes: i64,
    /// O que foi digitado e o pseudo-terminal ainda não aceitou: a fila do
    /// teclado do kernel estava cheia.
    pendente: String,
}

impl Terminal {
    /// Desenha o que mudou e acusa o dano.
    ///
    /// # Por que não redesenhar tudo sempre
    ///
    /// Porque cada tecla ecoa, e cada eco é uma saída nova. Redesenhar a
    /// grade inteira a cada uma fazia o compositor recompor a janela inteira
    /// a cada tecla — e, no ARM emulado, isso demorava mais do que a folga
    /// do teclado virtio, que guarda duas teclas entre duas colheitas do
    /// relógio. Medido na fumaça: de `agent.ping` digitado a vinte
    /// milissegundos por tecla, chegaram `agent.` e o Enter, e o `ping` se
    /// perdeu. Uma tecla muda uma linha só, e é ela que se redesenha.
    fn desenhar(&mut self) {
        let (cx, cy, cl, ca) = self.janela.conteudo();
        let (lc, ac) = (ESTILO.largura(), ESTILO.altura());
        let visiveis: Vec<String> = self
            .grade
            .visiveis()
            .iter()
            .map(|l| l.iter().collect())
            .collect();
        let linha_do_cursor = visiveis.len().saturating_sub(1);
        let coluna_do_cursor = self.grade.coluna.min(COLUNAS - 1);
        let foco = self.foco;
        let tudo = self.grade.quebrou || self.moldura_mudou;
        self.grade.quebrou = false;
        self.moldura_mudou = false;
        let (x0, y0) = (cx + FOLGA, cy + FOLGA);
        let mut tela = if tudo {
            let mut tela = self.janela.desenhar_moldura(foco);
            tela.retangulo(cx, cy, cl, ca, FUNDO);
            tela
        } else {
            let largura = self.janela.largura();
            let mut tela = programas::desenho::Tela {
                pixels: self.janela.superficie().pixels(),
                largura,
            };
            tela.retangulo(cx, y0 + linha_do_cursor as u32 * ac, cl, ac, FUNDO);
            tela
        };
        let primeira = if tudo { 0 } else { linha_do_cursor };
        for (i, linha) in visiveis.iter().enumerate().skip(primeira) {
            tela.texto((x0, y0 + i as u32 * ac), linha, ESTILO, (TINTA, FUNDO));
        }
        // O cursor: um bloco com o foco, um traço sem ele.
        let (x, y) = (
            x0 + coluna_do_cursor as u32 * lc,
            y0 + linha_do_cursor as u32 * ac,
        );
        if foco {
            let sob = visiveis
                .get(linha_do_cursor)
                .and_then(|l| l.chars().nth(coluna_do_cursor))
                .unwrap_or(' ');
            let mut um = [0u8; 4];
            tela.texto((x, y), sob.encode_utf8(&mut um), ESTILO, (FUNDO, CURSOR));
        } else {
            tela.retangulo(x, y + ac - 2, lc, 2, CURSOR);
        }
        let _ = if tudo {
            self.janela.superficie().danificar_tudo()
        } else {
            self.janela
                .superficie()
                .danificar(cx as u16, y as u16, cl as u16, ac as u16)
        };
        self.descrever(&visiveis);
    }

    /// Diz à árvore o que a janela é: a moldura, e o texto de baixo da
    /// grade.
    fn descrever(&self, visiveis: &[String]) {
        let mut d = String::new();
        self.janela.descrever_moldura(ELEMENTO_FECHAR, &mut d);
        let (cx, cy, cl, ca) = self.janela.conteudo();
        let _ = write!(
            d,
            "\ntexto\t{}\t{}\t{}\t{}\t{}\tterminal\t",
            ELEMENTO_TEXTO, cx, cy, cl, ca
        );
        // As linhas de baixo que cabem, na ordem.
        let mut usados = 0;
        let mut primeira = visiveis.len();
        for (i, linha) in visiveis.iter().enumerate().rev() {
            let custo = linha.trim_end().len() + 1;
            if usados + custo > TEXTO_NA_ARVORE {
                break;
            }
            usados += custo;
            primeira = i;
        }
        let texto: Vec<&str> = visiveis[primeira..].iter().map(|l| l.trim_end()).collect();
        let _ = descricao::escapar(&texto.join("\n"), &mut d);
        let r = sistema::descrever(self.janela.descritor(), &d);
        if r != 0 {
            escreverln!("terminal: a descricao foi recusada: {}", r);
        }
    }

    /// Lê o que o kernel imprimiu, até o pseudo-terminal devolver zero.
    /// Devolve se veio alguma coisa.
    fn ler_a_saida(&mut self) -> bool {
        let mut bytes = [0u8; 512];
        let mut veio = false;
        loop {
            let n = sistema::ler(self.pty, &mut bytes);
            if n <= 0 {
                return veio;
            }
            self.grade.receber(&bytes[..n as usize]);
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
        if !self.foco {
            self.foco = true;
            self.moldura_mudou = true;
            self.desenhar();
            escreverln!("terminal: foco");
        }
        self.janela.apertar(x, y) == Aperto::Fechar
    }

    /// A barra pediu o Terminal: para a frente, com o foco.
    fn vir_para_a_frente(&mut self) {
        let _ = self.janela.superficie().trazer_para_frente();
        let _ = self.janela.superficie().focar();
        if !self.foco {
            self.foco = true;
            self.moldura_mudou = true;
        }
        self.desenhar();
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

    let (lc, ac) = (ESTILO.largura(), ESTILO.altura());
    let largura = 2 * programas::janela::BORDA + 2 * FOLGA + COLUNAS as u32 * lc;
    let altura = programas::janela::ALTURA_DO_TITULO
        + programas::janela::BORDA
        + 2 * FOLGA
        + LINHAS as u32 * ac;
    let mut janela = match Janela::nova("Terminal", largura, altura, X, Y) {
        Ok(j) => j,
        Err(e) => {
            escreverln!("terminal: sem janela: {}", e);
            return 3;
        }
    };
    if janela.opaca().is_err() || janela.superficie().entrada(canal).is_err() {
        return 4;
    }
    let mut t = Terminal {
        janela,
        grade: Grade::nova(),
        pty: pty as u64,
        foco: true,
        moldura_mudou: true,
        botoes: 0,
        pendente: String::new(),
    };
    // O que o kernel já tinha impresso — o boot inteiro, se couber no anel.
    t.ler_a_saida();
    t.desenhar();
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
                tipo::FOCO_PERDIDO => {
                    t.foco = false;
                    t.moldura_mudou = true;
                    mudou = true;
                }
                tipo::ABRIR if e.a == janela::TERMINAL => t.vir_para_a_frente(),
                tipo::ACAO if e.a == ELEMENTO_FECHAR && e.b == evento_acao::PRESSIONAR => {
                    escreverln!("terminal: fechado");
                    return 0;
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
            t.desenhar();
        }
    }
}
