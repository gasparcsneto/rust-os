//! A barra superior: o nome do sistema, o primeiro botão e o tempo ligado.
//!
//! # O que ela é
//!
//! Uma camada do compositor no topo da tela, acima do console. É a primeira
//! camada de produção — até ela, só a suíte criava alguma —, e o primeiro
//! elemento da árvore semântica que aceita `press`: o botão **Limpar**, que
//! apaga o console e recomeça do topo.
//!
//! # Um botão, dois caminhos, uma ação
//!
//! A pessoa aperta F1; o agente pede `ui.act` com `press`. Os dois chegam em
//! [`crate::ui::agir`], com a origem de cada um, e dali na mesma função. É a
//! regra que a árvore semântica segue desde o começo: agir é passar pelo
//! caminho da pessoa, e o log diz quem foi. O clique chega pelo mesmo lugar
//! quando houver mouse.
//!
//! # O relógio
//!
//! O tempo desde o boot, à direita, redesenhado a cada segundo por uma
//! tarefa do executor. Não é hora do dia: este kernel ainda não lê o relógio
//! de parede da máquina. A árvore publica o texto que está desenhado, e não
//! o tempo de agora — ela descreve a tela.

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;

use crate::grafico::compositor::Camada;
use crate::tela::console::{desenhar_texto_em, largura_do_texto};
use crate::tela::{ALTURA_DA_BARRA, Cor};
use crate::ui::Moldura;

pub const FUNDO: Cor = Cor::nova(0x1A, 0x24, 0x36);
pub const TEXTO: Cor = Cor::nova(0xD8, 0xDE, 0xE8);
const FUNDO_DO_BOTAO: Cor = Cor::nova(0x2A, 0x3C, 0x58);

/// A linha de acento sob a barra: o indicador de que há um kernel vivo, que
/// antes era a faixa do banner no topo da tela e ficou debaixo da barra.
const ALTURA_DO_ACENTO: u32 = 2;

pub const NOME: &str = "Duke";
/// O rótulo do botão na árvore. Na tela ele leva a tecla junto.
pub const ROTULO_DO_BOTAO: &str = "Limpar";
const TEXTO_DO_BOTAO: &str = "Limpar (F1)";

const MARGEM: u32 = 8;
/// Onde o texto começa na vertical: centrado nos 22 pixels acima do acento,
/// com glifos de 16.
const TEXTO_Y: u32 = 3;
/// O botão, na vertical: dois pixels de folga em cima e embaixo.
const BOTAO_Y: u32 = 2;
const BOTAO_ALTURA: u32 = 18;
const BOTAO_FOLGA: u32 = 6;

/// A camada da barra, se ela existe. Sem compositor não há barra.
// A tomada desta tranca passa por `sem_interrupcoes`, como toda tranca deste
// kernel, e é solta no caminho fatal.
static BARRA: Mutex<Option<Camada>> = Mutex::new(None);

/// O segundo que o relógio da barra mostra agora. `u64::MAX` antes do
/// primeiro desenho.
static SEGUNDO_DESENHADO: AtomicU64 = AtomicU64::new(u64::MAX);

/// Quantas vezes o botão foi pressionado, por qualquer um dos caminhos.
static PRESSIONADO: AtomicU64 = AtomicU64::new(0);

fn com_barra<R>(f: impl FnOnce(&Option<Camada>) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&BARRA.lock()))
}

/// Põe a barra no topo da tela, se há compositor.
pub fn iniciar() {
    let Some(tela) = crate::tela::tela_fisica() else {
        return;
    };
    if !crate::tela::console_desviado() {
        crate::log_info!("barra", "sem compositor, sem barra superior");
        return;
    }
    let camada = match Camada::nova("barra", 0, 0, tela.largura, ALTURA_DA_BARRA) {
        Ok(c) => c,
        Err(motivo) => {
            crate::log_error!("barra", "a barra superior nao foi criada: {}", motivo);
            return;
        }
    };
    let largura = tela.largura;
    let segundo = crate::tempo::uptime_ms() / 1000;
    let desenhada = camada.pintar(|pixels, _, _| {
        desenhar_tudo(pixels, largura, segundo);
    });
    if let Err(motivo) = desenhada {
        crate::log_error!("barra", "a barra superior nao foi desenhada: {}", motivo);
        return;
    }
    SEGUNDO_DESENHADO.store(segundo, Ordering::Relaxed);
    crate::arch::sem_interrupcoes(|| *BARRA.lock() = Some(camada));
    crate::ui::mudou();
    crate::log_info!(
        "barra",
        "barra superior no ar, com o botao {}",
        ROTULO_DO_BOTAO
    );
}

/// A barra está na tela?
pub fn ativa() -> bool {
    com_barra(|b| b.is_some())
}

/// O identificador da camada da barra no compositor, para quem lista as
/// camadas saber que esta não é uma janela.
pub fn camada() -> Option<u32> {
    com_barra(|b| b.as_ref().map(Camada::id))
}

/// Redesenha o relógio, se o segundo mudou.
///
/// Devolve se redesenhou. Quem chama em produção é a tarefa `relogio`; a suíte chama
/// direto, porque em modo de teste não há executor.
pub fn atualizar_relogio() -> bool {
    let segundo = crate::tempo::uptime_ms() / 1000;
    if SEGUNDO_DESENHADO.load(Ordering::Relaxed) == segundo {
        return false;
    }
    let redesenhou = com_barra(|b| {
        let Some(camada) = b else {
            return false;
        };
        camada
            .pintar(|pixels, largura, _| desenhar_relogio(pixels, largura, segundo))
            .is_ok()
    });
    if redesenhou {
        SEGUNDO_DESENHADO.store(segundo, Ordering::Relaxed);
        crate::ui::mudou();
    }
    redesenhou
}

/// A tarefa que mantém o relógio da barra andando.
#[cfg(not(feature = "modo-teste"))]
pub async fn relogio() {
    loop {
        atualizar_relogio();
        crate::tarefas::relogio::por_ms(1000).await;
    }
}

/// O que o botão faz: limpar o console.
///
/// Quem chama é [`crate::ui::agir`], que já conferiu que o botão existe e
/// aceita `press`, e que registra no log quem pressionou.
pub fn pressionar() {
    PRESSIONADO.fetch_add(1, Ordering::Relaxed);
    crate::interpretador::limpar();
}

/// Quantas vezes o botão foi pressionado desde o boot. Para a suíte.
#[cfg(feature = "modo-teste")]
pub fn pressionado() -> u64 {
    PRESSIONADO.load(Ordering::Relaxed)
}

/// A moldura da barra inteira, se ela existe.
pub fn moldura() -> Option<Moldura> {
    let tela = crate::tela::tela_fisica()?;
    ativa().then_some(Moldura {
        x: 0,
        y: 0,
        largura: tela.largura,
        altura: ALTURA_DA_BARRA,
    })
}

/// A moldura do botão, se a barra existe.
pub fn moldura_do_botao() -> Option<Moldura> {
    ativa().then(|| {
        let (x, largura) = posicao_do_botao();
        Moldura {
            x,
            y: BOTAO_Y,
            largura,
            altura: BOTAO_ALTURA,
        }
    })
}

/// A moldura do nome, se a barra existe.
pub fn moldura_do_nome() -> Option<Moldura> {
    ativa().then(|| Moldura {
        x: MARGEM,
        y: TEXTO_Y,
        largura: largura_do_texto(NOME),
        altura: crate::tela::console::altura_do_texto(),
    })
}

/// A moldura do relógio, e o texto que ele mostra, se a barra existe.
pub fn relogio_na_tela() -> Option<(Moldura, alloc::string::String)> {
    let tela = crate::tela::tela_fisica()?;
    if !ativa() {
        return None;
    }
    let segundo = SEGUNDO_DESENHADO.load(Ordering::Relaxed);
    let texto = texto_do_relogio(segundo);
    let largura = largura_do_texto(&texto);
    Some((
        Moldura {
            x: tela.largura.saturating_sub(MARGEM + largura),
            y: TEXTO_Y,
            largura,
            altura: crate::tela::console::altura_do_texto(),
        },
        texto,
    ))
}

/// `ligado h:mm:ss`.
pub fn texto_do_relogio(segundo: u64) -> alloc::string::String {
    alloc::format!(
        "ligado {}:{:02}:{:02}",
        segundo / 3600,
        segundo / 60 % 60,
        segundo % 60
    )
}

/// Onde o botão começa e quanto ele ocupa, na horizontal.
fn posicao_do_botao() -> (u32, u32) {
    let x = MARGEM + largura_do_texto(NOME) + 2 * MARGEM;
    (x, largura_do_texto(TEXTO_DO_BOTAO) + 2 * BOTAO_FOLGA)
}

fn pintar_retangulo(pixels: &mut [u32], largura: u32, m: Moldura, cor: Cor) {
    let valor = cor.para_u32();
    for y in m.y..m.y + m.altura {
        let inicio = (y * largura + m.x.min(largura)) as usize;
        let fim = (y * largura + (m.x + m.largura).min(largura)) as usize;
        if let Some(linha) = pixels.get_mut(inicio..fim) {
            linha.fill(valor);
        }
    }
}

fn desenhar_tudo(pixels: &mut [u32], largura: u32, segundo: u64) {
    pixels.fill(FUNDO.para_u32());
    pintar_retangulo(
        pixels,
        largura,
        Moldura {
            x: 0,
            y: ALTURA_DA_BARRA - ALTURA_DO_ACENTO,
            largura,
            altura: ALTURA_DO_ACENTO,
        },
        Cor::ACENTO,
    );
    desenhar_texto_em(pixels, largura, MARGEM, TEXTO_Y, NOME, TEXTO, FUNDO);

    let (x, largura_do_botao) = posicao_do_botao();
    pintar_retangulo(
        pixels,
        largura,
        Moldura {
            x,
            y: BOTAO_Y,
            largura: largura_do_botao,
            altura: BOTAO_ALTURA,
        },
        FUNDO_DO_BOTAO,
    );
    desenhar_texto_em(
        pixels,
        largura,
        x + BOTAO_FOLGA,
        TEXTO_Y,
        TEXTO_DO_BOTAO,
        TEXTO,
        FUNDO_DO_BOTAO,
    );

    desenhar_relogio(pixels, largura, segundo);
}

/// Redesenha o relógio sobre o anterior.
///
/// Limpa antes a faixa inteira que um relógio pode ocupar, e não só a do
/// texto novo: `ligado 9:59:59` tem um dígito a menos que `ligado 10:00:00`,
/// e o dígito que sobrasse ficaria desenhado.
fn desenhar_relogio(pixels: &mut [u32], largura: u32, segundo: u64) {
    let texto = texto_do_relogio(segundo);
    let reservado = largura_do_texto("ligado 0000:00:00");
    pintar_retangulo(
        pixels,
        largura,
        Moldura {
            x: largura.saturating_sub(MARGEM + reservado),
            y: 0,
            largura: reservado,
            altura: ALTURA_DA_BARRA - ALTURA_DO_ACENTO,
        },
        FUNDO,
    );
    let x = largura.saturating_sub(MARGEM + largura_do_texto(&texto));
    desenhar_texto_em(pixels, largura, x, TEXTO_Y, &texto, TEXTO, FUNDO);
}

/// Destrava a barra à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { BARRA.force_unlock() };
}
