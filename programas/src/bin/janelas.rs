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
//! - **as ações da árvore semântica** — o `press`, o `confirm`, o `cancel`
//!   e o `set_value` do agente num elemento de uma janela dele;
//! - **o pedido de encerrar**, que fecha todas e sai.
//!
//! # O que sai dele, além dos pixels
//!
//! A descrição de cada janela, para a árvore semântica — e o servidor não
//! a escreve: cada janela é uma árvore de widgets do toolkit, e a descrição
//! é gerada dela, pelo mesmo percurso que a desenha. O agente lê a janela
//! pela árvore, e aciona o que está nela — a caixa de fechar, o OK, o campo
//! — pelo mesmo caminho do clique e da tecla.
//!
//! O servidor não pergunta nada: dorme na leitura do canal e acorda quando
//! há o que fazer.
//!
//! # Uma janela
//!
//! Uma [`Janela`] do runtime com uma [`Interface`] do toolkit dentro: a
//! moldura, a barra de título com o nome e a caixa de fechar, e o arrasto,
//! os mesmos do Terminal; e os widgets, que se desenham, se descrevem e
//! recebem o que chega. A barra da janela com o foco tem a cor de acento do
//! kernel; as outras, apagada. A ordem de empilhamento é a do vetor — a
//! última é a de cima —, e o compositor é avisado a cada mudança.
//!
//! Cada coisa que o servidor faz vira uma linha no log, `janelas: ...`: é
//! por elas que a suíte acompanha o que aconteceu do lado de cá.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use programas::escreverln;
use programas::janela::{Gesto, Janela};
use programas::sistema;

use protocolo::usuario::evento::acao as evento_acao;
use protocolo::usuario::evento::{BOTAO_ESQUERDO, CANAL_DAS_JANELAS, Evento, janela, tipo};
use protocolo::usuario::superficie::operacao;
use toolkit::{Botao, Campo, Coluna, Indice, Interface, Rotulo};

use aparencia::medidas::{ALTURA_DO_TITULO, BORDA, ESPACO_DO_CONTEUDO, RECUO_DO_CONTEUDO};

/// Uma janela aberta pelo servidor.
struct Aberta {
    id: u32,
    janela: Janela,
    /// Que janela é, de [`janela`].
    qual: i64,
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

/// Os códigos que o servidor dá ao que se aciona nas janelas dele — o que
/// volta num [`Gesto::Acionado`], do clique, da tecla ou do agente.
const OK: u32 = 1;
const LIMPAR: u32 = 2;
const ESCRITO: u32 = 3;

/// A janela de teste tem o tamanho de sempre, com a moldura: é o que a
/// suíte conhece, e onde ela aperta.
const LARGURA_DO_TESTE: u32 = 320;
const ALTURA_DO_TESTE: u32 = 160;
/// O campo da janela de teste, na interface dela: depois da coluna.
const CAMPO_DO_TESTE: Indice = 1;

/// O conteúdo de uma janela: uma coluna no fundo claro, com o recuo e o
/// espaço da linguagem visual.
fn conteudo() -> toolkit::Pilha {
    Coluna::nova()
        .recuo(RECUO_DO_CONTEUDO)
        .espaco(ESPACO_DO_CONTEUDO)
        .fundo(aparencia::uso::FUNDO_DO_CONTEUDO.argb())
}

/// O "Sobre o Duke": o nome, o que ele é, e o OK que fecha.
fn sobre() -> Interface {
    Interface::nova(
        conteudo()
            .com(Rotulo::titulo("cabeçalho", "Duke"))
            .com(Rotulo::novo("conteudo", SOBRE))
            .com(Botao::novo("OK", OK)),
    )
}

/// A janela de teste: um campo onde se digita, e o botão que o esvazia.
fn teste() -> Interface {
    Interface::nova(
        conteudo()
            .minimo(
                LARGURA_DO_TESTE - 2 * BORDA,
                ALTURA_DO_TESTE - ALTURA_DO_TITULO - BORDA,
            )
            .com(Campo::novo("texto", 30, ESCRITO))
            .com(Botao::novo("Limpar", LIMPAR)),
    )
}

/// Quantos identificadores de elemento cada janela reserva.
const ELEMENTOS_POR_JANELA: u32 = 16;

/// A base dos identificadores da janela `id` na árvore: a caixa de fechar
/// é a base, e o widget de índice `i`, a base mais um mais `i` — ver
/// [`Janela::com_interface`]. É o que volta num evento de ação, e o que
/// diz de qual janela ele é.
fn base(id: u32) -> i64 {
    (id * ELEMENTOS_POR_JANELA) as i64
}

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

    /// A barra de título de `id` acende ou apaga.
    fn acender(&mut self, id: u32, foco: bool) {
        if let Some(i) = self.indice(id) {
            self.janelas[i].janela.focar(foco);
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
            self.acender(anterior, false);
        }
        self.acender(id, true);
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
        let (titulo, interface) = match qual {
            janela::TESTE => ("Teste", teste()),
            janela::SOBRE => ("Sobre o Duke", sobre()),
            _ => {
                escreverln!("janelas: pedido de janela desconhecida {}", qual);
                return;
            }
        };
        // No centro da tela, e cada uma um pouco abaixo e à direita da
        // anterior: duas janelas iguais uma sobre a outra pareceriam uma.
        let (largura, altura) = Janela::tamanho_para(&interface);
        let degrau = 24 * self.janelas.len() as i64;
        let x = (largura_da_tela - largura as i64) / 2 + degrau;
        let y = (altura_da_tela - altura as i64) / 2 + degrau;
        let id = self.proximo_id;
        let janela = match Janela::com_interface(titulo, interface, base(id), x as i32, y as i32) {
            Ok(j) => j,
            Err(e) => {
                escreverln!("janelas: sem superficie para {}: {}", titulo, e);
                return;
            }
        };
        self.proximo_id += 1;
        if janela.mostrar().is_err() {
            escreverln!("janelas: a janela {} nao pode ser mostrada", id);
            return;
        }
        self.janelas.push(Aberta { id, janela, qual });
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
        if self.arrasto == Some(id) {
            self.arrasto = None;
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
        // A caixa de fechar, a barra de título — que começa o arrasto — ou
        // um widget: a janela sabe.
        let gesto = self.janelas[i].janela.apertar_em(x, y);
        if self.janelas[i].janela.arrastando() {
            self.arrasto = Some(id);
        }
        self.atender(id, gesto);
    }

    /// Uma tecla, com o foco numa janela: vai ao widget com o foco nela.
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
        escreverln!("janelas: tecla {} em {}", codigo, id);
        let gesto = self.janelas[i].janela.tecla(c);
        self.atender(id, gesto);
    }

    /// Uma ação pela árvore semântica: o `press`, o `confirm`, o `cancel`
    /// ou o `set_value` do agente num elemento de uma janela. Vai ao mesmo
    /// widget do clique e da tecla.
    fn acao(&mut self, elemento: i64, acao: i64) {
        let Ok(id) = u32::try_from(elemento / ELEMENTOS_POR_JANELA as i64) else {
            return;
        };
        escreverln!(
            "janelas: acao {} no elemento {} da janela {}",
            acao,
            elemento % ELEMENTOS_POR_JANELA as i64,
            id
        );
        let Some(i) = self.indice(id) else {
            return;
        };
        if let Some(gesto) = self.janelas[i].janela.acao(elemento, acao) {
            self.atender(id, gesto);
        }
    }

    /// O que a janela `id` disse que aconteceu nela.
    fn atender(&mut self, id: u32, gesto: Gesto) {
        let Some(i) = self.indice(id) else {
            return;
        };
        match gesto {
            Gesto::Fechar | Gesto::Acionado(OK) => self.fechar(id),
            // Esvaziar o campo é o `cancel` dele: o mesmo caminho do agente.
            Gesto::Acionado(LIMPAR) => {
                let campo = base(id) + 1 + CAMPO_DO_TESTE as i64;
                self.janelas[i].janela.acao(campo, evento_acao::CANCELAR);
                escreverln!("janelas: limpa {}", id);
            }
            Gesto::Acionado(ESCRITO) => {
                let texto = self.janelas[i]
                    .janela
                    .com_widget::<Campo, _>(CAMPO_DO_TESTE, |c| String::from(c.valor()))
                    .unwrap_or_default();
                escreverln!("janelas: escrito {} [{}]", id, texto);
            }
            _ => {}
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
            self.acender(anterior, false);
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
