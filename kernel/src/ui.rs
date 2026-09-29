//! A árvore semântica: o que está na tela, e o que se pode fazer com cada
//! coisa.
//!
//! # O problema
//!
//! Um agente que opera uma interface gráfica hoje, em quase todo sistema,
//! tira uma captura da tela e adivinha onde está o botão. Funciona até o tema
//! mudar, a janela abrir noutro lugar ou o texto ser traduzido — e aí quebra
//! sem dizer por quê. O agente está lendo a renderização em vez da coisa.
//!
//! # A resposta, e de onde ela vem
//!
//! A mesma que o macOS dá à acessibilidade: cada elemento da interface é um
//! nó com **papel**, **rótulo**, **valor**, **moldura** e uma lista de
//! **ações** que ele aceita — o `AXUIElement`, com `AXRole`, `AXValue` e
//! `AXPress`. Um leitor de tela e um teste automatizado leem a mesma árvore
//! que o agente lê, e agem pelas mesmas ações.
//!
//! O vocabulário das ações é o da Apple, e o formato é o deste projeto: a
//! árvore sai pelo canal do agente em `ui.tree`, e as ações entram por
//! `ui.act`. Nada do código deles está aqui — só o desenho, que é público.
//!
//! # A regra que a faz valer alguma coisa
//!
//! A árvore é **gerada** do estado que produz a tela, e nunca escrita à mão.
//! O texto do console é o que [`crate::tela::console`] guardou ao desenhar; a
//! linha de comando é o buffer que o interpretador edita; as molduras saem da
//! geometria da tela. Uma árvore mantida ao lado da interface seria a segunda
//! superfície que este projeto existe para não ter — e divergiria na primeira
//! mudança que só uma das duas recebesse.
//!
//! # O que existe hoje
//!
//! Pouco, porque a interface é pouca: a tela, o console de texto sobre ela, a
//! linha de comando do interpretador, e a barra superior com o nome, o
//! relógio e o botão **Limpar** — o primeiro elemento que aceita `press`. Ele
//! é acionado por três caminhos, e todos chegam em [`agir`]: o `ui.act` do
//! agente, a F1 e o clique da pessoa. As camadas do compositor acima do
//! console aparecem como janelas — as do servidor de janelas, e as que a
//! suíte cria.

use core::sync::atomic::{AtomicU64, Ordering};

/// O que um elemento é. O nome é o que a árvore publica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Papel {
    /// A tela inteira: a raiz.
    Tela,
    /// Texto que se lê e não se edita — o console.
    AreaDeTexto,
    /// Texto que se edita e se confirma — a linha de comando.
    CampoDeTexto,
    /// Uma camada do compositor acima do console: o que um dia será uma
    /// janela, e hoje só a suíte cria.
    Janela,
    /// A barra no topo da tela — `AXMenuBar`.
    BarraSuperior,
    /// Algo que se aciona — `AXButton`.
    Botao,
    /// Texto que só se lê, dentro de outro elemento — `AXStaticText`.
    Texto,
}

impl Papel {
    pub const fn nome(self) -> &'static str {
        match self {
            Papel::Tela => "screen",
            Papel::AreaDeTexto => "text_area",
            Papel::CampoDeTexto => "text_field",
            Papel::Janela => "window",
            Papel::BarraSuperior => "menu_bar",
            Papel::Botao => "button",
            Papel::Texto => "static_text",
        }
    }
}

/// O que se pode fazer com um elemento.
///
/// Os nomes são os das ações de acessibilidade do macOS, sem o prefixo `AX`:
/// quem conhece aquele vocabulário reconhece este.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acao {
    /// `AXPress`: acionar, como um clique num botão.
    Pressionar,
    /// `AXConfirm`: confirmar, como o Enter num campo.
    Confirmar,
    /// `AXCancel`: desistir, como o Esc — aqui, esvaziar o campo.
    Cancelar,
    /// Trocar o valor, como escrever `AXValue`.
    DefinirValor,
}

impl Acao {
    pub const TODAS: [Acao; 4] = [
        Acao::Pressionar,
        Acao::Confirmar,
        Acao::Cancelar,
        Acao::DefinirValor,
    ];

    pub const fn nome(self) -> &'static str {
        match self {
            Acao::Pressionar => "press",
            Acao::Confirmar => "confirm",
            Acao::Cancelar => "cancel",
            Acao::DefinirValor => "set_value",
        }
    }

    pub fn de_nome(nome: &str) -> Option<Acao> {
        Acao::TODAS.into_iter().find(|a| a.nome() == nome)
    }
}

/// Quem pediu uma ação.
///
/// Vai para o log junto com o que foi feito. É o começo do que a fase 12 do
/// roteiro chama de auditoria: se um agente pode fazer tudo que uma pessoa
/// faz, o registro precisa dizer qual dos dois fez.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origem {
    Pessoa,
    Agente,
}

impl Origem {
    pub const fn nome(self) -> &'static str {
        match self {
            Origem::Pessoa => "pessoa",
            Origem::Agente => "agente",
        }
    }
}

/// Os identificadores dos elementos que existem hoje.
///
/// Fixos, e não gerados a cada leitura: um agente que leu a árvore e agiu
/// sobre o elemento 3 precisa que o 3 continue sendo a linha de comando na
/// chamada seguinte. As camadas do compositor nascem e morrem, e o
/// identificador delas vem de quem as cria: o do compositor, somado a
/// [`ID_DAS_CAMADAS`]. Ele não se repete enquanto o kernel vive, então um
/// agente que guardou o de uma janela que fechou recebe "não existe", e não
/// a janela que veio depois.
pub const ID_DA_TELA: u32 = 1;
pub const ID_DO_CONSOLE: u32 = 2;
pub const ID_DA_LINHA_DE_COMANDO: u32 = 3;
pub const ID_DA_BARRA: u32 = 4;
pub const ID_DO_BOTAO_LIMPAR: u32 = 5;
pub const ID_DO_NOME: u32 = 6;
pub const ID_DO_RELOGIO: u32 = 7;
pub const ID_DAS_CAMADAS: u32 = 1000;

/// O identificador na árvore de uma camada do compositor.
pub const fn id_da_camada(camada: u32) -> u32 {
    ID_DAS_CAMADAS.saturating_add(camada)
}

/// Onde começam os identificadores dos elementos **dentro** de uma janela —
/// os que o processo dono dela descreveu.
///
/// O identificador carrega a camada e a posição do elemento na descrição:
/// `BASE | camada << 5 | índice`. Derivado, e não guardado, pelo motivo dos
/// da camada: ele vale enquanto a janela vive, e o de uma janela que fechou
/// não aponta para a seguinte, porque a camada seguinte tem outro número.
/// Cabe enquanto a camada for menor que 2^26 — sessenta e sete milhões de
/// janelas abertas no mesmo boot.
pub const BASE_DOS_ELEMENTOS: u32 = 0x8000_0000;

/// Quantos elementos por janela os cinco bits do índice alcançam.
const ELEMENTOS_POR_JANELA: usize = 32;

const _: () = assert!(protocolo::usuario::descricao::MAIS_ELEMENTOS <= ELEMENTOS_POR_JANELA);

/// O identificador do elemento `indice` da janela da `camada`.
pub fn id_do_elemento(camada: u32, indice: usize) -> Option<u32> {
    if camada >= 1 << 26 || indice >= ELEMENTOS_POR_JANELA {
        return None;
    }
    Some(BASE_DOS_ELEMENTOS | camada << 5 | indice as u32)
}

/// A camada e o índice de um identificador de elemento.
pub fn elemento_de(id: u32) -> Option<(u32, usize)> {
    (id & BASE_DOS_ELEMENTOS != 0).then_some(((id & !BASE_DOS_ELEMENTOS) >> 5, (id & 31) as usize))
}

/// O elemento descrito com este identificador, entregue a `f`.
fn com_elemento<R>(id: u32, f: impl FnOnce(&crate::superficies::Elemento) -> R) -> Option<R> {
    let (camada, indice) = elemento_de(id)?;
    crate::superficies::com_descricao(camada, |d| d.elementos.get(indice).map(f)).flatten()
}

/// Um retângulo na tela, em pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Moldura {
    pub x: u32,
    pub y: u32,
    pub largura: u32,
    pub altura: u32,
}

/// Quantas vezes o que a árvore descreve mudou desde o boot.
///
/// Um agente que queira saber se algo mudou compara dois números em vez de
/// duas árvores. É o que o compositor fará com o dano, dito no nível dos
/// elementos: não "que pixels", mas "a árvore que você leu está velha".
static REVISAO: AtomicU64 = AtomicU64::new(0);

/// Registra que o que a árvore descreve mudou.
///
/// Atômico e sem trava, porque quem chama inclui o console — alcançável do
/// caminho de falha fatal.
pub fn mudou() {
    REVISAO.fetch_add(1, Ordering::Relaxed);
}

pub fn revisao() -> u64 {
    REVISAO.load(Ordering::Relaxed)
}

/// A moldura da tela inteira, se houver tela.
pub fn moldura_da_tela() -> Option<Moldura> {
    let tela = crate::tela::tela()?;
    Some(Moldura {
        x: 0,
        y: 0,
        largura: tela.largura,
        altura: tela.altura,
    })
}

/// A moldura do console: a região que ele limpa e onde escreve.
pub fn moldura_do_console() -> Option<Moldura> {
    let tela = crate::tela::tela()?;
    let topo = crate::tela::ALTURA_DA_BARRA;
    Some(Moldura {
        x: 0,
        y: topo,
        largura: tela.largura,
        altura: tela.altura.saturating_sub(topo),
    })
}

/// A moldura da linha de comando: do começo do que se digita até o cursor,
/// estendida até a margem direita.
///
/// Uma linha que quebrou ocupa mais de uma linha de texto, e a moldura cobre
/// todas elas. `None` sem tela ou sem interpretador.
pub fn moldura_da_linha_de_comando() -> Option<Moldura> {
    let g = crate::tela::console::geometria()?;
    let (coluna, linha) = crate::interpretador::inicio_do_campo()?;
    let (_, linha_do_cursor) = crate::tela::console::cursor_em_celulas();
    let linhas = linha_do_cursor.saturating_sub(linha) + 1;
    let (x, largura) = if linhas == 1 {
        (
            g.margem_x + coluna * g.largura_da_celula,
            g.colunas.saturating_sub(coluna) * g.largura_da_celula,
        )
    } else {
        (g.margem_x, g.colunas * g.largura_da_celula)
    };
    Some(Moldura {
        x,
        y: g.margem_y + linha * g.altura_da_celula,
        largura,
        altura: linhas * g.altura_da_celula,
    })
}

/// As ações que um elemento aceita.
pub fn acoes_de(id: u32) -> &'static [Acao] {
    match id {
        ID_DA_LINHA_DE_COMANDO => &[Acao::Confirmar, Acao::Cancelar, Acao::DefinirValor],
        ID_DO_BOTAO_LIMPAR => &[Acao::Pressionar],
        // Um botão que um processo descreveu. O que ele faz é do processo;
        // o kernel só leva o pedido.
        id if com_elemento(id, |e| e.tipo == crate::superficies::Tipo::Botao) == Some(true) => {
            &[Acao::Pressionar]
        }
        _ => &[],
    }
}

/// O elemento que aceita `press` no ponto `(x, y)` da tela, se houver um.
///
/// É o que um clique aciona. Hoje só o botão da barra superior aceita; a
/// pergunta é pela moldura que a árvore publica, para que o clique e o
/// agente concordem sobre onde o botão está.
pub fn acionavel_em(x: u32, y: u32) -> Option<u32> {
    let dentro = |m: Moldura| x >= m.x && x < m.x + m.largura && y >= m.y && y < m.y + m.altura;
    crate::barra::moldura_do_botao()
        .filter(|&m| dentro(m))
        .map(|_| ID_DO_BOTAO_LIMPAR)
}

/// O elemento existe agora?
pub fn existe(id: u32) -> bool {
    match id {
        ID_DA_TELA | ID_DO_CONSOLE => crate::tela::tela().is_some(),
        ID_DA_LINHA_DE_COMANDO => {
            crate::tela::tela().is_some() && crate::interpretador::inicio_do_campo().is_some()
        }
        ID_DA_BARRA | ID_DO_BOTAO_LIMPAR | ID_DO_NOME | ID_DO_RELOGIO => crate::barra::ativa(),
        // Antes das camadas: os identificadores de elemento também são
        // maiores que o delas.
        id if elemento_de(id).is_some() => com_elemento(id, |_| ()).is_some(),
        id if id > ID_DAS_CAMADAS => {
            // A camada da barra não é uma janela: ela está na árvore com o
            // papel dela, e não uma segunda vez como camada.
            let barra = crate::barra::camada();
            let cursor = crate::ponteiro::camada();
            let mut achou = false;
            crate::grafico::camadas(|c| {
                achou |= Some(c.id) != barra && Some(c.id) != cursor && id_da_camada(c.id) == id;
            });
            achou
        }
        _ => false,
    }
}

/// O que uma ação produziu.
pub enum Efeito {
    /// O valor do elemento mudou.
    ValorDefinido,
    /// O campo foi esvaziado.
    Cancelado,
    /// A linha foi executada — com o nome do comando, ou vazia se não havia
    /// nada para executar.
    Executado(alloc::string::String),
    /// O botão foi acionado.
    Pressionado,
}

/// Age sobre um elemento, pelo mesmo caminho de quem está na frente da
/// máquina.
///
/// # Mesmo caminho, e não um atalho
///
/// Confirmar a linha de comando executa o que está nela exatamente como o
/// Enter de uma pessoa: pelo interpretador, que despacha pelo registro do
/// canal, desenha a resposta na tela e registra no log — com a origem
/// dizendo que foi o agente. A pessoa vê o comando aparecer e a resposta ser
/// desenhada; nada acontece por trás da tela.
///
/// # O que é recusado
///
/// Elemento que não existe, ação que ele não aceita, valor que não caberia
/// na linha ou que uma pessoa não conseguiria digitar. Recusar antes de
/// mexer em qualquer coisa: uma ação recusada não deixa rastro na tela.
pub fn agir(
    id: u32,
    acao: Acao,
    valor: Option<&str>,
    origem: Origem,
) -> Result<Efeito, &'static str> {
    let desfecho = executar(id, acao, valor, origem);
    // Registrado **depois**, com o desfecho. Antes da ação, uma recusa por
    // valor inválido ficava no log como ação feita — e isto é o começo de uma
    // trilha de auditoria, onde afirmar o que não aconteceu é pior que calar.
    match &desfecho {
        Ok(_) => crate::log_info!(
            "ui",
            "{}: {} no elemento {}",
            origem.nome(),
            acao.nome(),
            id
        ),
        Err(motivo) => crate::log_info!(
            "ui",
            "{}: {} no elemento {} recusado: {}",
            origem.nome(),
            acao.nome(),
            id,
            motivo
        ),
    }
    desfecho
}

fn executar(
    id: u32,
    acao: Acao,
    valor: Option<&str>,
    origem: Origem,
) -> Result<Efeito, &'static str> {
    // No post-mortem a interface não age. Toda ação muda a tela — limpar o
    // console, redesenhar a barra, digitar no prompt —, e a tela é a de
    // falha, a única coisa que uma pessoa na frente da máquina vê. Medido:
    // antes desta recusa, um `press` do agente a apagava inteira.
    if crate::traps::em_post_mortem() {
        return Err("o kernel esta em post-mortem; a interface nao age sobre a tela de falha");
    }
    if !existe(id) {
        return Err("nao ha elemento com este id");
    }
    if !acoes_de(id).contains(&acao) {
        return Err("o elemento nao aceita esta acao");
    }
    match acao {
        Acao::DefinirValor => {
            let valor = valor.ok_or("set_value precisa de `value`")?;
            crate::interpretador::definir(valor)?;
            Ok(Efeito::ValorDefinido)
        }
        Acao::Cancelar => {
            crate::interpretador::definir("")?;
            Ok(Efeito::Cancelado)
        }
        Acao::Confirmar => Ok(Efeito::Executado(crate::interpretador::confirmar(origem))),
        // O botão da barra, ou um que um processo descreveu: a conferência
        // acima já recusou os outros.
        Acao::Pressionar => {
            if let Some(do_processo) = com_elemento(id, |e| e.id) {
                pressionar_no_processo(do_processo)?;
            } else {
                crate::barra::pressionar();
            }
            Ok(Efeito::Pressionado)
        }
    }
}

/// Leva ao processo dono da janela o `press` num elemento que ele descreveu,
/// com o identificador que ele deu.
///
/// Pelo canal das janelas, como o clique da pessoa: quem decide o que o
/// botão faz é o servidor, e ele o faz pelo mesmo caminho do clique — o
/// agente e a pessoa acionam a mesma coisa.
fn pressionar_no_processo(id_do_processo: i64) -> Result<(), &'static str> {
    use protocolo::usuario::evento::{CANAL_DAS_JANELAS, Evento, acao, tipo};
    match crate::eventos::publicar(
        CANAL_DAS_JANELAS,
        Evento {
            tipo: tipo::ACAO,
            a: id_do_processo,
            b: acao::PRESSIONAR,
            c: 0,
        },
    ) {
        Ok(()) => Ok(()),
        Err(crate::eventos::NaoPublicado::SemOuvinte) => {
            Err("o servidor de janelas nao escuta o canal")
        }
        Err(crate::eventos::NaoPublicado::Cheio) => Err("a fila do servidor de janelas esta cheia"),
    }
}
