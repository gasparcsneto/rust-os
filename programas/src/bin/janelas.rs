//! O servidor de janelas do Duke.
//!
//! # A divisão com o kernel
//!
//! O kernel compõe; o servidor decide. O kernel guarda as camadas, desenha o
//! cursor e a barra, e leva à tela o que mudou; o servidor decide o que é
//! uma janela, desenha a moldura dela, e responde ao que a pessoa faz —
//! foco, arrastar, trazer para a frente, fechar. É o arranjo do Orbital, o
//! compositor do Redox, com a composição do lado de lá da fronteira: aqui
//! ela ficou no kernel, onde já estava, e o que atravessou foi a decisão.
//!
//! # O que chega a ele
//!
//! Tudo pelo canal [`CANAL_DAS_JANELAS`], como eventos de 32 bytes:
//!
//! - **o ponteiro**, quando está sobre uma janela, ou arrastando uma — o
//!   kernel olha que camada está debaixo dele e só publica quando é de
//!   processo;
//! - **as teclas**, quando uma janela tem o foco;
//! - **os pedidos de abrir** uma janela, da barra do kernel ou da suíte;
//! - **o foco perdido**, quando a pessoa clica fora de toda janela;
//! - **o pedido de encerrar**, que fecha todas e sai.
//!
//! O servidor não pergunta nada: dorme na leitura do canal e acorda quando
//! há o que fazer.
//!
//! # Uma janela
//!
//! Uma [`Superficie`] com moldura: a barra de título, com o nome e a caixa
//! de fechar, e o conteúdo embaixo. A barra da janela com o foco tem a cor
//! de acento do kernel; as outras, apagada. A ordem de empilhamento é a do
//! vetor — a última é a de cima —, e o compositor é avisado a cada mudança.
//!
//! Cada coisa que o servidor faz vira uma linha no log, `janelas: ...`: é
//! por elas que a suíte acompanha o que aconteceu do lado de cá.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use programas::desenho::{Tela, tamanho_do_caractere};
use programas::escreverln;
use programas::sistema;
use programas::superficie::Superficie;
use protocolo::usuario::evento::{BOTAO_ESQUERDO, CANAL_DAS_JANELAS, Evento, janela, tipo};
use protocolo::usuario::superficie::operacao;

/// A altura da barra de título.
const ALTURA_DO_TITULO: u32 = 22;
/// O lado da caixa de fechar, na ponta direita da barra de título.
const LADO_DO_FECHAR: u32 = 16;
/// A borda em volta da janela.
const BORDA: u32 = 1;

// A paleta do kernel — a da barra superior e a do acento —, para a janela
// parecer da mesma máquina. Com o byte alto cheio: as janelas se misturam
// por alfa, e um pixel de alfa zero não apareceria.
const ACENTO: u32 = 0xFF3A_8FD0;
const TITULO_APAGADO: u32 = 0xFF2A_3C58;
const TEXTO_DO_TITULO: u32 = 0xFFF4_F6FA;
const CONTEUDO: u32 = 0xFFF4_F6FA;
const TEXTO: u32 = 0xFF1A_2436;
const BORDA_COR: u32 = 0xFF10_1828;

struct Janela {
    id: u32,
    superficie: Superficie,
    titulo: &'static str,
    /// Onde o canto superior esquerdo está na tela.
    x: i32,
    y: i32,
    /// O que se digitou nela.
    texto: String,
}

impl Janela {
    fn largura(&self) -> u32 {
        self.superficie.largura()
    }

    fn altura(&self) -> u32 {
        self.superficie.altura()
    }

    fn contem(&self, x: i64, y: i64) -> bool {
        let (x0, y0) = (self.x as i64, self.y as i64);
        x >= x0 && y >= y0 && x < x0 + self.largura() as i64 && y < y0 + self.altura() as i64
    }

    /// `(x, y)` da tela, em coordenadas da janela.
    fn local(&self, x: i64, y: i64) -> (i64, i64) {
        (x - self.x as i64, y - self.y as i64)
    }

    fn na_barra_de_titulo(&self, x: i64, y: i64) -> bool {
        let (_, ly) = self.local(x, y);
        ly < ALTURA_DO_TITULO as i64
    }

    /// A caixa de fechar: `(x, y, lado)` em coordenadas da janela.
    fn caixa_de_fechar(&self) -> (u32, u32, u32) {
        let lado = LADO_DO_FECHAR;
        (
            self.largura() - BORDA - 3 - lado,
            (ALTURA_DO_TITULO - lado) / 2,
            lado,
        )
    }

    fn no_fechar(&self, x: i64, y: i64) -> bool {
        let (lx, ly) = self.local(x, y);
        let (cx, cy, lado) = self.caixa_de_fechar();
        lx >= cx as i64 && ly >= cy as i64 && lx < (cx + lado) as i64 && ly < (cy + lado) as i64
    }

    /// Desenha a janela inteira e acusa o dano.
    fn desenhar(&mut self, com_foco: bool) {
        let (largura, altura) = (self.largura(), self.altura());
        let (cx, cy, lado) = self.caixa_de_fechar();
        let (_, altura_da_linha) = tamanho_do_caractere();
        let cor_do_titulo = if com_foco { ACENTO } else { TITULO_APAGADO };
        let titulo = self.titulo;
        let texto = self.texto.clone();

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
        tela.texto(
            8,
            (ALTURA_DO_TITULO - altura_da_linha) / 2,
            titulo,
            TEXTO_DO_TITULO,
            cor_do_titulo,
        );
        // A caixa de fechar: um quadrado mais claro com um x no meio.
        tela.retangulo(cx, cy, lado, lado, TITULO_APAGADO);
        let (largura_do_x, _) = tamanho_do_caractere();
        tela.texto(
            cx + (lado - largura_do_x) / 2,
            cy,
            "x",
            TEXTO_DO_TITULO,
            TITULO_APAGADO,
        );
        tela.retangulo(
            BORDA,
            ALTURA_DO_TITULO,
            largura - 2 * BORDA,
            altura - ALTURA_DO_TITULO - BORDA,
            CONTEUDO,
        );
        // O texto, linha a linha, cortado no que couber.
        let mut y = ALTURA_DO_TITULO + 8;
        for linha in texto.split('\n') {
            if y + altura_da_linha > altura - BORDA {
                break;
            }
            tela.texto(10, y, linha, TEXTO, CONTEUDO);
            y += altura_da_linha;
        }
        let _ = self.superficie.danificar_tudo();
    }
}

struct Servidor {
    /// De baixo para cima: a última é a de cima.
    janelas: Vec<Janela>,
    /// A janela com o foco, pelo identificador.
    foco: Option<u32>,
    /// A janela sendo arrastada, e onde o ponteiro a pegou.
    arrasto: Option<(u32, i64, i64)>,
    botoes: i64,
    proximo_id: u32,
}

impl Servidor {
    fn indice(&self, id: u32) -> Option<usize> {
        self.janelas.iter().position(|j| j.id == id)
    }

    fn redesenhar(&mut self, id: u32) {
        let foco = self.foco == Some(id);
        if let Some(i) = self.indice(id) {
            self.janelas[i].desenhar(foco);
        }
    }

    /// Dá o foco a `id` — a barra dela acende, a da anterior apaga — e pede
    /// ao kernel as teclas.
    fn focar(&mut self, id: u32) {
        let anterior = self.foco.replace(id);
        if anterior == Some(id) {
            return;
        }
        if let Some(anterior) = anterior {
            self.redesenhar(anterior);
        }
        self.redesenhar(id);
        if let Some(i) = self.indice(id) {
            let fd = self.janelas[i].superficie.descritor();
            sistema::controlar(fd, operacao::FOCO, 1);
        }
        escreverln!("janelas: foco {}", id);
    }

    fn abrir(&mut self, qual: i64, largura_da_tela: i64, altura_da_tela: i64) {
        let (titulo, largura, altura) = match qual {
            janela::TESTE => ("Teste", 320, 160),
            _ => {
                escreverln!("janelas: pedido de janela desconhecida {}", qual);
                return;
            }
        };
        let superficie = match Superficie::nova(largura, altura) {
            Ok(s) => s,
            Err(e) => {
                escreverln!("janelas: sem superficie para {}: {}", titulo, e);
                return;
            }
        };
        // No centro da tela, e cada uma um pouco abaixo e à direita da
        // anterior: duas janelas iguais uma sobre a outra pareceriam uma.
        let degrau = 24 * self.janelas.len() as i64;
        let x = (largura_da_tela - largura as i64) / 2 + degrau;
        let y = (altura_da_tela - altura as i64) / 2 + degrau;
        let id = self.proximo_id;
        self.proximo_id += 1;
        let mut j = Janela {
            id,
            superficie,
            titulo,
            x: x as i32,
            y: y as i32,
            texto: String::new(),
        };
        j.desenhar(false);
        if j.superficie.transparente(true).is_err()
            || j.superficie.mover(j.x, j.y).is_err()
            || j.superficie.mostrar().is_err()
        {
            escreverln!("janelas: a janela {} nao pode ser mostrada", id);
            return;
        }
        self.janelas.push(j);
        escreverln!("janelas: aberta {} {} em {} {}", id, titulo, x, y);
        self.focar(id);
    }

    fn fechar(&mut self, id: u32) {
        let Some(i) = self.indice(id) else {
            return;
        };
        // Largar a superfície tira a camada da tela; o foco dela volta ao
        // kernel junto.
        drop(self.janelas.remove(i));
        if self.foco == Some(id) {
            self.foco = None;
        }
        escreverln!("janelas: fechada {}", id);
    }

    fn trazer_para_frente(&mut self, id: u32) {
        let Some(i) = self.indice(id) else {
            return;
        };
        if i + 1 == self.janelas.len() {
            return;
        }
        let j = self.janelas.remove(i);
        let _ = j.superficie.trazer_para_frente();
        self.janelas.push(j);
        escreverln!("janelas: frente {}", id);
    }

    fn ponteiro(&mut self, x: i64, y: i64, botoes: i64) {
        let apertou = botoes & BOTAO_ESQUERDO != 0 && self.botoes & BOTAO_ESQUERDO == 0;
        let soltou = botoes & BOTAO_ESQUERDO == 0 && self.botoes & BOTAO_ESQUERDO != 0;
        self.botoes = botoes;

        if let Some((id, dx, dy)) = self.arrasto {
            let Some(i) = self.indice(id) else {
                self.arrasto = None;
                return;
            };
            let j = &mut self.janelas[i];
            j.x = (x - dx) as i32;
            j.y = (y - dy) as i32;
            let _ = j.superficie.mover(j.x, j.y);
            if soltou {
                self.arrasto = None;
                escreverln!("janelas: arrastada {} para {} {}", id, j.x, j.y);
            }
            return;
        }

        if !apertou {
            return;
        }
        // A de cima que contém o ponto.
        let Some(id) = self
            .janelas
            .iter()
            .rev()
            .find(|j| j.contem(x, y))
            .map(|j| j.id)
        else {
            return;
        };
        self.trazer_para_frente(id);
        self.focar(id);
        let Some(i) = self.indice(id) else {
            return;
        };
        let j = &self.janelas[i];
        if j.no_fechar(x, y) {
            self.fechar(id);
        } else if j.na_barra_de_titulo(x, y) {
            let (lx, ly) = j.local(x, y);
            self.arrasto = Some((id, lx, ly));
        }
    }

    fn tecla(&mut self, codigo: i64) {
        let Some(id) = self.foco else {
            return;
        };
        let Some(c) = u32::try_from(codigo).ok().and_then(char::from_u32) else {
            return;
        };
        let Some(i) = self.indice(id) else {
            return;
        };
        let texto = &mut self.janelas[i].texto;
        match c {
            '\u{8}' => {
                texto.pop();
            }
            c if c == '\n' || !c.is_control() => texto.push(c),
            _ => return,
        }
        self.redesenhar(id);
        escreverln!("janelas: tecla {} em {}", codigo, id);
    }

    fn foco_perdido(&mut self) {
        if let Some(anterior) = self.foco.take() {
            self.redesenhar(anterior);
            escreverln!("janelas: foco devolvido");
        }
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let canal = sistema::escutar(CANAL_DAS_JANELAS);
    if canal < 0 {
        escreverln!("janelas: o canal nao pode ser escutado: {}", canal);
        return 1;
    }
    let mut servidor = Servidor {
        janelas: Vec::new(),
        foco: None,
        arrasto: None,
        botoes: 0,
        proximo_id: 1,
    };
    escreverln!("janelas: pronto");

    let mut eventos = [Evento::default(); 16];
    loop {
        let quantos = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("janelas: a leitura do canal falhou: {}", e);
                return 2;
            }
        };
        for e in &eventos[..quantos] {
            match e.tipo {
                tipo::PONTEIRO => servidor.ponteiro(e.a, e.b, e.c),
                tipo::TECLA => servidor.tecla(e.a),
                tipo::ABRIR => servidor.abrir(e.a, e.b, e.c),
                tipo::FOCO_PERDIDO => servidor.foco_perdido(),
                tipo::ENCERRAR => {
                    while let Some(j) = servidor.janelas.last() {
                        let id = j.id;
                        servidor.fechar(id);
                    }
                    escreverln!("janelas: encerrado");
                    return 0;
                }
                _ => {}
            }
        }
    }
}
