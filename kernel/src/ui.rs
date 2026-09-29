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
//! Pouco, porque a interface é pouca: a tela, o console de texto sobre ela e
//! a linha de comando do interpretador. Nenhum deles é um botão, então
//! `press` existe no vocabulário e nenhum elemento o aceita ainda — a árvore
//! diz isso em vez de fingir. O primeiro botão vem com o compositor e o
//! toolkit do roteiro; quando vier, ele entra por aqui, e o agente o encontra
//! pelo mesmo `ui.tree`.

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
}

impl Papel {
    pub const fn nome(self) -> &'static str {
        match self {
            Papel::Tela => "screen",
            Papel::AreaDeTexto => "text_area",
            Papel::CampoDeTexto => "text_field",
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
/// chamada seguinte. Quando houver janelas que nascem e morrem, o
/// identificador passa a vir de quem cria o elemento.
pub const ID_DA_TELA: u32 = 1;
pub const ID_DO_CONSOLE: u32 = 2;
pub const ID_DA_LINHA_DE_COMANDO: u32 = 3;

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
    let topo = crate::tela::ALTURA_DO_ACENTO;
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
        _ => &[],
    }
}

/// O elemento existe agora?
pub fn existe(id: u32) -> bool {
    match id {
        ID_DA_TELA | ID_DO_CONSOLE => crate::tela::tela().is_some(),
        ID_DA_LINHA_DE_COMANDO => {
            crate::tela::tela().is_some() && crate::interpretador::inicio_do_campo().is_some()
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
    if !existe(id) {
        return Err("nao ha elemento com este id");
    }
    if !acoes_de(id).contains(&acao) {
        return Err("o elemento nao aceita esta acao");
    }
    crate::log_info!(
        "ui",
        "{}: {} no elemento {}",
        origem.nome(),
        acao.nome(),
        id
    );
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
        // Nenhum elemento de hoje aceita, e a conferência acima já recusou.
        Acao::Pressionar => Err("o elemento nao aceita esta acao"),
    }
}
