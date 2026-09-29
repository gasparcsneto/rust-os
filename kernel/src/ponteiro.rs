//! O ponteiro: onde o mouse está, o cursor na tela, e o clique.
//!
//! # De onde vem o movimento
//!
//! De três dispositivos, e o que cada um entrega é diferente. Um tablet — o
//! `virtio-tablet` do ARM — diz **onde** o ponteiro está, numa escala dele;
//! um mouse — o PS/2 do x86, o mouse USB nas duas — diz **quanto** ele
//! andou. Os drivers traduzem o formato de cada um e chamam [`absoluto`] ou
//! [`relativo`]; daqui para cima não se sabe qual dos dois chegou.
//!
//! # O cursor
//!
//! Uma camada do compositor, transparente fora da seta, fixa no topo de
//! todas. Aparece no primeiro movimento: uma máquina sem mouse não mostra um
//! ponteiro que ninguém move.
//!
//! # O clique
//!
//! Vai pelo caminho da tecla: entra na fila do interpretador — a tarefa que
//! atende quem está na frente da máquina — e ele o entrega a
//! [`tratar_clique`], que pergunta à interface o que está debaixo do ponteiro
//! e, se aceitar `press`, o aciona por [`crate::ui::agir`], com a origem da
//! pessoa. É o mesmo lugar onde chegam a F1 e o `press` do agente. Pela
//! fila, e não aqui: quem chama estas funções são handlers de interrupção, e
//! o que um clique aciona pode ser limpar a tela inteira.
//!
//! # Sobre uma janela
//!
//! Quando o que está debaixo do ponteiro é a superfície de um processo — uma
//! janela do servidor de janelas —, o movimento e o botão não são do kernel:
//! vão como eventos para o canal das janelas, e o servidor decide o que
//! fazem. Um aperto sobre uma janela **captura** o ponteiro até o botão
//! soltar: arrastando depressa, o ponteiro sai da janela antes de ela
//! acompanhar, e sem a captura o servidor perderia o resto do arrasto.
//!
//! Um aperto fora de toda janela devolve o foco do teclado ao kernel, e o
//! servidor é avisado — sempre, mesmo com o foco já no kernel: um pedido de
//! foco do servidor pode estar a caminho.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use spin::Mutex;

use crate::grafico::compositor::{Camada, Mistura};
use protocolo::usuario::evento::{BOTAO_ESQUERDO, CANAL_DAS_JANELAS, Evento, tipo};

/// Onde o ponteiro está, em pixels da tela.
static X: AtomicU32 = AtomicU32::new(0);
static Y: AtomicU32 = AtomicU32::new(0);

/// O botão esquerdo, como estava no último evento.
static ESQUERDO: AtomicBool = AtomicBool::new(false);

/// O botão foi apertado sobre uma janela e ainda não soltou: tudo o que o
/// ponteiro fizer vai para o servidor.
static CAPTURADO: AtomicBool = AtomicBool::new(false);

/// Quantos eventos de ponteiro foram para o servidor de janelas.
static PARA_AS_JANELAS: AtomicU64 = AtomicU64::new(0);

/// O ponteiro andou desde a última vez que o cursor foi posto no lugar.
static ANDOU: AtomicBool = AtomicBool::new(false);

/// Onde foi o último clique, `x << 32 | y`. Lido pelo interpretador quando o
/// clique chega a ele pela fila.
static ULTIMO_CLIQUE: AtomicU64 = AtomicU64::new(0);

/// Quantos cliques chegaram, e quantos movimentos.
static CLIQUES: AtomicU64 = AtomicU64::new(0);
static MOVIMENTOS: AtomicU64 = AtomicU64::new(0);

/// A camada do cursor, depois do primeiro movimento.
// A tomada desta tranca passa por `sem_interrupcoes`, como toda tranca deste
// kernel, e é solta no caminho fatal.
static CURSOR: Mutex<Option<Camada>> = Mutex::new(None);

/// A seta: `#` é contorno, `o` é miolo, espaço é transparente. A ponta é o
/// canto de cima à esquerda, que é onde o ponteiro está.
const SETA: [&str; 19] = [
    "#           ",
    "##          ",
    "#o#         ",
    "#oo#        ",
    "#ooo#       ",
    "#oooo#      ",
    "#ooooo#     ",
    "#oooooo#    ",
    "#ooooooo#   ",
    "#oooooooo#  ",
    "#ooooooooo# ",
    "#oooooo#####",
    "#ooo#oo#    ",
    "#oo##oo#    ",
    "#o#  #oo#   ",
    "##   #oo#   ",
    "#     #oo#  ",
    "      #oo#  ",
    "       ##   ",
];
const LARGURA_DA_SETA: u32 = 12;
const ALTURA_DA_SETA: u32 = 19;
pub const CONTORNO: u32 = 0xFF10_1010;
const MIOLO: u32 = 0xFFF4_F4F4;

/// Onde o ponteiro está agora.
pub fn posicao() -> (u32, u32) {
    (X.load(Ordering::Relaxed), Y.load(Ordering::Relaxed))
}

/// Quantos cliques e movimentos chegaram desde o boot.
pub fn contadores() -> (u64, u64) {
    (
        CLIQUES.load(Ordering::Relaxed),
        MOVIMENTOS.load(Ordering::Relaxed),
    )
}

/// Um tablet disse onde o ponteiro está: `x` e `y` numa escala de `0` a
/// `maximo`, que vira a da tela.
pub fn absoluto(x: u32, y: u32, maximo_x: u32, maximo_y: u32) {
    let Some(tela) = crate::tela::tela_fisica() else {
        return;
    };
    let escala = |v: u32, maximo: u32, lado: u32| -> u32 {
        if maximo == 0 {
            return 0;
        }
        let v = v.min(maximo) as u64;
        ((v * (lado.saturating_sub(1)) as u64) / maximo as u64) as u32
    };
    X.store(escala(x, maximo_x, tela.largura), Ordering::Relaxed);
    Y.store(escala(y, maximo_y, tela.altura), Ordering::Relaxed);
    ANDOU.store(true, Ordering::Relaxed);
}

/// Um mouse disse quanto andou. `dy` positivo é para baixo, como na tela.
pub fn relativo(dx: i32, dy: i32) {
    let Some(tela) = crate::tela::tela_fisica() else {
        return;
    };
    let mover = |atual: &AtomicU32, delta: i32, lado: u32| {
        let novo = (atual.load(Ordering::Relaxed) as i64 + delta as i64)
            .clamp(0, lado.saturating_sub(1) as i64);
        atual.store(novo as u32, Ordering::Relaxed);
    };
    mover(&X, dx, tela.largura);
    mover(&Y, dy, tela.altura);
    ANDOU.store(true, Ordering::Relaxed);
}

/// O botão esquerdo, pressionado ou não. O clique é o apertar.
pub fn botao(pressionado: bool) {
    let antes = ESQUERDO.swap(pressionado, Ordering::Relaxed);
    let (x, y) = posicao();
    if pressionado && !antes {
        ULTIMO_CLIQUE.store((x as u64) << 32 | y as u64, Ordering::Relaxed);
        CLIQUES.fetch_add(1, Ordering::Relaxed);
        if sobre_uma_janela(x, y) && para_as_janelas(x, y) {
            CAPTURADO.store(true, Ordering::Relaxed);
            return;
        }
        // Fora de toda janela: o clique é do kernel, e o teclado também.
        //
        // O aviso ao servidor vai **sempre**, e não só quando o kernel via o
        // foco numa janela. Um clique numa janela seguido de um clique fora,
        // antes de o servidor rodar, é o caso: no segundo clique o foco ainda
        // é do kernel — o pedido do servidor está a caminho —, e sem o aviso
        // o pedido chegaria depois e ficaria com o foco, sem ninguém saber
        // que a pessoa clicou fora. O servidor recebe o aviso depois do
        // próprio pedido, e solta o foco. Sem janela com o foco, o aviso não
        // muda nada do lado de lá.
        crate::superficies::devolver_foco();
        publicar(Evento {
            tipo: tipo::FOCO_PERDIDO,
            ..Evento::default()
        });
        crate::teclado::clique();
    } else if !pressionado && antes && CAPTURADO.swap(false, Ordering::Relaxed) {
        para_as_janelas(x, y);
    }
}

/// O que está debaixo de `(x, y)` é a superfície de um processo?
fn sobre_uma_janela(x: u32, y: u32) -> bool {
    crate::grafico::camada_em(x, y).is_some_and(|c| c.nome == crate::superficies::NOME_DA_CAMADA)
}

/// Manda ao servidor de janelas onde o ponteiro está e os botões. Falso se
/// não havia quem escutasse — e então o ponteiro é do kernel.
fn para_as_janelas(x: u32, y: u32) -> bool {
    let botoes = if ESQUERDO.load(Ordering::Relaxed) {
        BOTAO_ESQUERDO
    } else {
        0
    };
    let foi = publicar(Evento {
        tipo: tipo::PONTEIRO,
        a: x as i64,
        b: y as i64,
        c: botoes,
    });
    if foi {
        PARA_AS_JANELAS.fetch_add(1, Ordering::Relaxed);
    }
    foi
}

/// Publica no canal das janelas. Uma fila cheia conta como entregue: o
/// servidor existe, e o canal contou o que recusou.
fn publicar(evento: Evento) -> bool {
    !matches!(
        crate::eventos::publicar(CANAL_DAS_JANELAS, evento),
        Err(crate::eventos::NaoPublicado::SemOuvinte)
    )
}

/// Quantos eventos de ponteiro foram para o servidor de janelas.
pub fn para_as_janelas_contados() -> u64 {
    PARA_AS_JANELAS.load(Ordering::Relaxed)
}

/// Fim de um lote de eventos: põe o cursor onde o ponteiro está.
///
/// Os dispositivos mandam x, y e botões como eventos separados e fecham o
/// lote com um sincronismo; mover o cursor a cada eixo o faria andar em
/// escada. Um mouse PS/2 manda os três num pacote, e chama isto no fim dele.
pub fn sincronizar() {
    if !ANDOU.swap(false, Ordering::Relaxed) {
        return;
    }
    MOVIMENTOS.fetch_add(1, Ordering::Relaxed);
    let (x, y) = posicao();
    crate::arch::sem_interrupcoes(|| {
        let mut cursor = CURSOR.lock();
        if cursor.is_none() {
            *cursor = criar_cursor(x, y);
        }
        if let Some(camada) = cursor.as_ref() {
            let _ = camada.mover(x as i32, y as i32);
        }
    });
    crate::ui::mudou();
    // Andando sobre uma janela, ou arrastando uma: é do servidor.
    if CAPTURADO.load(Ordering::Relaxed) || sobre_uma_janela(x, y) {
        para_as_janelas(x, y);
    }
}

/// A camada da seta, fixa no topo. `None` sem compositor.
fn criar_cursor(x: u32, y: u32) -> Option<Camada> {
    let camada = Camada::nova(
        "cursor",
        x as i32,
        y as i32,
        LARGURA_DA_SETA,
        ALTURA_DA_SETA,
    )
    .ok()?;
    camada.definir_mistura(Mistura::Alfa).ok()?;
    camada
        .pintar(|pixels, largura, _| {
            for (linha, texto) in SETA.iter().enumerate() {
                for (coluna, c) in texto.bytes().enumerate() {
                    pixels[linha * largura as usize + coluna] = match c {
                        b'#' => CONTORNO,
                        b'o' => MIOLO,
                        _ => 0,
                    };
                }
            }
        })
        .ok()?;
    camada.fixar_no_topo().ok()?;
    Some(camada)
}

/// O identificador da camada do cursor, se ele já apareceu. Para quem lista
/// as camadas saber que esta não é uma janela.
pub fn camada() -> Option<u32> {
    crate::arch::sem_interrupcoes(|| CURSOR.lock().as_ref().map(Camada::id))
}

/// Onde foi o último clique.
pub fn ultimo_clique() -> (u32, u32) {
    let v = ULTIMO_CLIQUE.load(Ordering::Relaxed);
    ((v >> 32) as u32, v as u32)
}

/// O que um clique em `(x, y)` faz: aciona o que estiver debaixo dele, se
/// aceitar `press`.
///
/// Quem chama é o interpretador, quando o clique chega a ele pela fila —
/// ver o cabeçalho do módulo. Devolve o elemento acionado.
pub fn tratar_clique(x: u32, y: u32) -> Option<u32> {
    let id = crate::ui::acionavel_em(x, y)?;
    crate::ui::agir(
        id,
        crate::ui::Acao::Pressionar,
        None,
        crate::ui::Origem::Pessoa,
    )
    .ok()?;
    Some(id)
}

/// Destrava o cursor à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { CURSOR.force_unlock() };
}
