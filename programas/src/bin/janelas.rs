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
//! Tudo pelo canal [`CANAL_DAS_JANELAS`], como eventos de 32 bytes — o
//! canal de entrada de toda superfície que não escolheu outro:
//!
//! - **o ponteiro**, quando está sobre uma janela, ou arrastando uma — o
//!   kernel olha que camada está debaixo dele e só publica quando é deste
//!   servidor. Um aperto já chega com o foco dado pelo kernel;
//! - **as teclas**, quando uma janela tem o foco;
//! - **os pedidos de abrir** uma janela, da barra do kernel ou da suíte;
//! - **o foco perdido**, quando a pessoa clica fora de toda janela, ou na de
//!   outro processo;
//! - **as ações da árvore semântica** — o `press` do agente num elemento
//!   que o servidor descreveu;
//! - **o pedido de encerrar**, que fecha todas e sai.
//!
//! # O que sai dele, além dos pixels
//!
//! A descrição de cada janela, para a árvore semântica: o título, a caixa
//! de fechar e o texto. Gerada do mesmo estado que o desenho, a cada vez
//! que ele muda — o agente lê a janela pela árvore, e aciona a caixa de
//! fechar pelo mesmo caminho do clique.
//!
//! O servidor não pergunta nada: dorme na leitura do canal e acorda quando
//! há o que fazer.
//!
//! # Uma janela
//!
//! Uma [`Janela`] do runtime — a moldura, a barra de título com o nome e a
//! caixa de fechar, e o arrasto, os mesmos do Terminal —, e o conteúdo que
//! o servidor desenha dentro dela. A barra da janela com o foco tem a cor de
//! acento do kernel; as outras, apagada. A ordem de empilhamento é a do
//! vetor — a última é a de cima —, e o compositor é avisado a cada mudança.
//!
//! Cada coisa que o servidor faz vira uma linha no log, `janelas: ...`: é
//! por elas que a suíte acompanha o que aconteceu do lado de cá.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use core::fmt::Write;
use programas::desenho::{Estilo, largura_do_texto};
use programas::escreverln;
use programas::janela::{Aperto, Janela};
use programas::sistema;

use protocolo::usuario::descricao;
use protocolo::usuario::evento::acao as evento_acao;
use protocolo::usuario::evento::{BOTAO_ESQUERDO, CANAL_DAS_JANELAS, Evento, janela, tipo};
use protocolo::usuario::superficie::operacao;

// O conteúdo, na paleta do kernel — a moldura é a do runtime, ver
// `programas::janela`.
const CONTEUDO: u32 = 0xFFF4_F6FA;
const TEXTO: u32 = 0xFF1A_2436;

/// Uma janela aberta pelo servidor: a moldura, e o que vai dentro.
struct Aberta {
    id: u32,
    janela: Janela,
    /// Um título grande no alto do conteúdo, se ela tiver um.
    cabecalho: Option<&'static str>,
    /// O que ela mostra: o que se digitou, ou o texto fixo dela.
    texto: String,
    /// Que janela é, de [`janela`] — a de teste aceita digitação; a
    /// "Sobre o Duke", não.
    qual: i64,
}

impl Aberta {
    /// Desenha a janela inteira e acusa o dano.
    fn desenhar(&mut self, com_foco: bool) {
        let (cx, cy, cl, ca) = self.janela.conteudo();
        let altura_da_linha = Estilo::TEXTO.altura();
        let texto = self.texto.clone();
        let cabecalho = self.cabecalho;
        let mut tela = self.janela.desenhar_moldura(com_foco);
        tela.retangulo(cx, cy, cl, ca, CONTEUDO);
        // O cabeçalho, se houver, no estilo de título; e o texto, linha a
        // linha, cortado no que couber.
        let mut y = cy + 8;
        if let Some(cabecalho) = cabecalho {
            tela.texto((10, y), cabecalho, Estilo::TITULO, (TEXTO, CONTEUDO));
            y += Estilo::TITULO.altura() + 6;
        }
        for linha in texto.split('\n') {
            if y + altura_da_linha > cy + ca {
                break;
            }
            tela.texto((10, y), linha, Estilo::TEXTO, (TEXTO, CONTEUDO));
            y += altura_da_linha;
        }
        let _ = self.janela.superficie().danificar_tudo();
        self.descrever();
    }

    /// Os identificadores que esta janela dá aos seus elementos na árvore:
    /// o da janela vezes dezesseis, mais o elemento. É o que volta num
    /// evento de ação, e o que diz de qual janela ele é.
    fn id_do_elemento(&self, elemento: u32) -> i64 {
        (self.id * ELEMENTOS_POR_JANELA + elemento) as i64
    }

    /// Diz ao kernel o que a janela é: o título, a caixa de fechar e o
    /// texto — o mesmo que acabou de ser desenhado, gerado do mesmo estado.
    fn descrever(&self) {
        let mut d = String::new();
        self.janela
            .descrever_moldura(self.id_do_elemento(ELEMENTO_FECHAR), &mut d);
        let (cx, cy, cl, ca) = self.janela.conteudo();
        let _ = write!(
            d,
            "\ntexto\t{}\t{}\t{}\t{}\t{}\tconteudo\t",
            self.id_do_elemento(ELEMENTO_CONTEUDO),
            cx,
            cy,
            cl,
            ca
        );
        let _ = descricao::escapar(&self.texto, &mut d);
        // O cabeçalho, depois do conteúdo: a posição de cada elemento na
        // descrição é o que dá o identificador dele na árvore, e o da caixa
        // e o do conteúdo não mudam de uma janela para a outra.
        if let Some(cabecalho) = self.cabecalho {
            let _ = write!(
                d,
                "\ntexto\t{}\t10\t{}\t{}\t{}\tcabeçalho\t",
                self.id_do_elemento(ELEMENTO_CABECALHO),
                cy + 8,
                largura_do_texto(cabecalho, Estilo::TITULO),
                Estilo::TITULO.altura()
            );
            let _ = descricao::escapar(cabecalho, &mut d);
        }
        let r = sistema::descrever(self.janela.descritor(), &d);
        if r != 0 {
            escreverln!(
                "janelas: a descricao da janela {} foi recusada: {}",
                self.id,
                r
            );
        }
    }
}

/// O que a janela "Sobre o Duke" diz, abaixo do cabeçalho. Com acento: a
/// `tipografia` tem o bloco Latin-1, onde moram as letras do português.
#[cfg(target_arch = "x86_64")]
const SOBRE: &str = "Um sistema operacional didático, escrito\n\
em Rust, rodando em x86_64.\n\n\
Esta janela é desenhada por um processo:\n\
o servidor de janelas, fora do kernel.";
#[cfg(target_arch = "aarch64")]
const SOBRE: &str = "Um sistema operacional didático, escrito\n\
em Rust, rodando em aarch64.\n\n\
Esta janela é desenhada por um processo:\n\
o servidor de janelas, fora do kernel.";

/// Quantos identificadores de elemento cada janela reserva.
const ELEMENTOS_POR_JANELA: u32 = 16;
/// Os elementos de uma janela, na árvore.
const ELEMENTO_FECHAR: u32 = 1;
const ELEMENTO_CONTEUDO: u32 = 2;
const ELEMENTO_CABECALHO: u32 = 3;

struct Servidor {
    /// De baixo para cima: a última é a de cima.
    janelas: Vec<Aberta>,
    /// A janela com o foco, pelo identificador.
    foco: Option<u32>,
    /// A janela sendo arrastada — onde o ponteiro a pegou, ela sabe.
    arrasto: Option<u32>,
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

    /// Dá o foco a `id`: a barra dela acende, a da anterior apaga.
    ///
    /// `pedir` é se o kernel precisa ser pedido. Num aperto do ponteiro, não
    /// precisa: o kernel dá o foco à janela em que a pessoa apertou, antes
    /// de o evento chegar aqui, e um pedido feito agora chegaria atrasado —
    /// se a pessoa já tivesse clicado fora, ele retomaria o foco. Numa
    /// janela que acabou de abrir, precisa: ninguém apertou nada nela.
    fn focar(&mut self, id: u32, pedir: bool) {
        let anterior = self.foco.replace(id);
        if anterior == Some(id) {
            return;
        }
        if let Some(anterior) = anterior {
            self.redesenhar(anterior);
        }
        self.redesenhar(id);
        if pedir && let Some(i) = self.indice(id) {
            let fd = self.janelas[i].janela.descritor();
            sistema::controlar(fd, operacao::FOCO, 1);
        }
        escreverln!("janelas: foco {}", id);
    }

    fn abrir(&mut self, qual: i64, largura_da_tela: i64, altura_da_tela: i64) {
        if qual == janela::TERMINAL {
            lancar_o_terminal();
            return;
        }
        // Uma "Sobre o Duke" só: pedir de novo traz a aberta para a frente.
        if qual == janela::SOBRE
            && let Some(id) = self.janelas.iter().find(|j| j.qual == qual).map(|j| j.id)
        {
            self.trazer_para_frente(id);
            self.focar(id, true);
            escreverln!("janelas: ja aberta {}", id);
            return;
        }
        let (titulo, largura, altura, cabecalho, texto) = match qual {
            janela::TESTE => ("Teste", 320, 160, None, String::new()),
            janela::SOBRE => ("Sobre o Duke", 400, 190, Some("Duke"), String::from(SOBRE)),
            _ => {
                escreverln!("janelas: pedido de janela desconhecida {}", qual);
                return;
            }
        };
        // No centro da tela, e cada uma um pouco abaixo e à direita da
        // anterior: duas janelas iguais uma sobre a outra pareceriam uma.
        let degrau = 24 * self.janelas.len() as i64;
        let x = (largura_da_tela - largura as i64) / 2 + degrau;
        let y = (altura_da_tela - altura as i64) / 2 + degrau;
        let janela = match Janela::nova(titulo, largura, altura, x as i32, y as i32) {
            Ok(j) => j,
            Err(e) => {
                escreverln!("janelas: sem superficie para {}: {}", titulo, e);
                return;
            }
        };
        let id = self.proximo_id;
        self.proximo_id += 1;
        let mut j = Aberta {
            id,
            janela,
            cabecalho,
            texto,
            qual,
        };
        j.desenhar(false);
        if j.janela.mostrar().is_err() {
            escreverln!("janelas: a janela {} nao pode ser mostrada", id);
            return;
        }
        self.janelas.push(j);
        escreverln!("janelas: aberta {} {} em {} {}", id, titulo, x, y);
        self.focar(id, true);
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
        let mut j = self.janelas.remove(i);
        let _ = j.janela.superficie().trazer_para_frente();
        self.janelas.push(j);
        escreverln!("janelas: frente {}", id);
    }

    fn ponteiro(&mut self, x: i64, y: i64, botoes: i64) {
        let apertou = botoes & BOTAO_ESQUERDO != 0 && self.botoes & BOTAO_ESQUERDO == 0;
        let soltou = botoes & BOTAO_ESQUERDO == 0 && self.botoes & BOTAO_ESQUERDO != 0;
        self.botoes = botoes;

        if let Some(id) = self.arrasto {
            let Some(i) = self.indice(id) else {
                self.arrasto = None;
                return;
            };
            if let Some((jx, jy)) = self.janelas[i].janela.arrastar(x, y, soltou) {
                self.arrasto = None;
                escreverln!("janelas: arrastada {} para {} {}", id, jx, jy);
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
            .find(|j| j.janela.contem(x, y))
            .map(|j| j.id)
        else {
            return;
        };
        self.trazer_para_frente(id);
        self.focar(id, false);
        let Some(i) = self.indice(id) else {
            return;
        };
        match self.janelas[i].janela.apertar(x, y) {
            Aperto::Fechar => self.fechar(id),
            Aperto::Arrasto => self.arrasto = Some(id),
            Aperto::Conteudo(..) => {}
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
        // O texto do "Sobre o Duke" é fixo.
        if self.janelas[i].qual != janela::TESTE {
            return;
        }
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

    /// Uma ação pela árvore semântica: o `press` do agente num elemento que
    /// o servidor descreveu. Faz o que o clique faria.
    fn acao(&mut self, elemento: i64, acao: i64) {
        let Ok(elemento) = u32::try_from(elemento) else {
            return;
        };
        let (id, qual) = (
            elemento / ELEMENTOS_POR_JANELA,
            elemento % ELEMENTOS_POR_JANELA,
        );
        escreverln!(
            "janelas: acao {} no elemento {} da janela {}",
            acao,
            qual,
            id
        );
        if acao == evento_acao::PRESSIONAR && qual == ELEMENTO_FECHAR {
            self.fechar(id);
        }
    }

    /// O foco saiu das janelas deste servidor: a pessoa clicou fora de
    /// todas, ou na de outro processo.
    ///
    /// # Por que soltar o foco aqui, se o kernel já o tomou
    ///
    /// Porque um pedido de foco deste servidor pode ter chegado ao kernel
    /// **depois** que ele o tomou de volta. Uma janela que acabou de abrir
    /// faz o servidor pedir o foco; se a pessoa clica fora antes de o pedido
    /// chegar, o kernel devolve o foco, e o pedido atrasado o retoma. Sem
    /// soltar aqui, o servidor acharia que não tem o foco e o kernel acharia
    /// que tem — e as teclas viriam para cá, para serem jogadas fora.
    /// Medido, quando o clique também pedia o foco: uma vez em poucas
    /// execuções no x86, o caso da suíte via o foco ativo depois de o
    /// servidor dizer que o devolveu.
    ///
    /// Soltar é pela superfície: o kernel só solta se o foco for dela, e um
    /// que já voltou ao kernel fica onde está.
    fn foco_perdido(&mut self) {
        if let Some(anterior) = self.foco.take() {
            if let Some(i) = self.indice(anterior) {
                let fd = self.janelas[i].janela.descritor();
                sistema::controlar(fd, operacao::FOCO, 0);
            }
            self.redesenhar(anterior);
            escreverln!("janelas: foco devolvido");
        }
    }
}

/// Onde o Terminal está no disco — ver `DIRETORIO_DOS_COMPILADOS`, no
/// kernel.
#[cfg(target_arch = "x86_64")]
const TERMINAL: &str = "/programas/x86_64/terminal";
#[cfg(target_arch = "aarch64")]
const TERMINAL: &str = "/programas/aarch64/terminal";

/// Lança o Terminal: ele é outro programa, com a janela dele, e o servidor
/// não o desenha — só decide abri-lo.
///
/// # Por que bifurcar duas vezes
///
/// Porque este processo não espera ninguém: ele dorme no canal das janelas.
/// Um filho que saísse ficaria zumbi até o pai perguntar por ele, e o pai
/// nunca pergunta. Então o filho bifurca de novo e sai na hora — o servidor
/// o colhe logo —, e o neto, que troca de imagem para o Terminal, fica sem
/// pai vivo: quando sair, o coletor do kernel o recolhe sozinho.
fn lancar_o_terminal() {
    match sistema::bifurcar() {
        0 => {
            if sistema::bifurcar() == 0 {
                let r = sistema::executar(TERMINAL);
                escreverln!("janelas: o terminal nao foi executado: {}", r);
                sistema::sair(1);
            }
            sistema::sair(0);
        }
        filho if filho < 0 => {
            escreverln!("janelas: o terminal nao foi lancado: {}", filho);
        }
        filho => {
            let _ = sistema::esperar(filho as u64);
            escreverln!("janelas: terminal lancado");
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
                tipo::ACAO => servidor.acao(e.a, e.b),
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
