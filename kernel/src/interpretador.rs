//! O interpretador: operar o Duke digitando, num console.
//!
//! # Por que ele não tem comandos próprios
//!
//! Porque já existe uma lista de comandos, e ela é a mesma que o canal do
//! agente publica em `agent.describe`. Um interpretador com o seu próprio
//! conjunto seria uma segunda superfície para manter — e as duas divergiriam
//! na primeira que alguém esquecesse de atualizar, com o sintoma de uma
//! pessoa e um agente vendo máquinas diferentes.
//!
//! Aqui o que se digita é despachado pelo **mesmo** registro, com os mesmos
//! handlers. O que muda é só a renderização: o agente lê uma linha de JSON
//! compacto, e uma pessoa lê o mesmo JSON quebrado em linhas. As exceções
//! são as palavras do próprio console — `login`, `logout` e `ajuda`, que
//! não são operações do sistema: dizem quem está no console —, e `senha`,
//! a troca da própria senha: ela é uma operação, decidida pelo gate como
//! `credential.change_self`, mas pede senhas, e uma senha não se digita
//! numa linha de comando — ela ecoaria, entraria no histórico do teclado e
//! na árvore semântica. Por isso o diálogo dela é do console, como o do
//! login, e não um comando do registro: nenhum agente, processo ou canal a
//! alcança.
//!
//! # Um console é uma sessão
//!
//! Há o console físico — o teclado e a tela da máquina — e um para cada
//! Terminal aberto, pelo pseudo-terminal dele ([`crate::pseudoterminal`]).
//! Cada um tem a sua linha, o seu modo e a sua sessão de pessoa: o que se
//! digita num não aparece no outro, e a mesma pessoa em dois consoles são
//! duas sessões. A saída de cada um vai para o lugar dele: a do físico para
//! a tela e a COM1, a de um Terminal para o anel do pseudo-terminal dele.
//!
//! ```text
//! pessoa → sessão → console → comando → decisão → auditoria
//! ```
//!
//! # Antes do login, nada além de entrar
//!
//! Um console sem ninguém entrado aceita `login` e `ajuda`. Todo o resto —
//! um comando, uma tecla de função, um clique — é recusado com
//! `DENY_NOT_AUTHENTICATED` e vai para a auditoria: o comando com o nome e
//! o resumo dos parâmetros, se ele existe; senão, com o marcador
//! [`autorizacao::COMANDO_DESCONHECIDO`], sem resumo — uma linha que não é
//! comando pode ser uma senha digitada no lugar errado, e não vai ao
//! registro, nem em claro nem num resumo que se adivinha fora da máquina.
//! A resposta é a mesma nos dois casos. Depois do login, cada
//! comando passa pela decisão com o papel que o registro dá à pessoa
//! **agora**: uma revogação vale no comando seguinte, e o console volta a
//! pedir o login.
//!
//! A senha não ecoa, não aparece na árvore semântica, não entra no
//! histórico do teclado, e o buffer dela é apagado depois da conferência. No
//! console físico, a tecla entra no histórico quando o console a consome, já
//! sabendo se a linha pede uma senha: a senha digitada adiantado — antes de
//! o console tratar o Enter que a pede — também fica de fora.
//! Vale para as três da troca da própria senha — a atual, a nova e a nova
//! de novo —, guardadas só até a última, e apagadas em toda saída.
//!
//! # A linha de comando do físico tem dois donos, e um caminho
//!
//! Quem está na frente da máquina edita a linha pelo teclado; um agente, pela
//! árvore semântica ([`crate::ui`]), com `set_value` e `confirm`. Os dois
//! passam pelas **mesmas** funções deste módulo — [`definir`], [`confirmar`]
//! —, que editam o mesmo buffer, desenham na mesma tela e registram no mesmo
//! log, com a origem dizendo quem foi. Um agente que confirma uma linha age
//! como a sessão **dele**, com o papel dele — nunca como a pessoa do
//! console. E não digita o login de ninguém: a linha que pede nome ou senha
//! só se edita pelo teclado.
//!
//! # A linha da pessoa, no físico e em cada Terminal
//!
//! A árvore alcança também a linha de cada Terminal: o campo da janela
//! dele, que o programa digita no pseudo-terminal. A regra da linha que pede
//! o nome, uma senha ou um passo do pareamento — [`pode_editar_pela_arvore`]
//! e [`pode_confirmar_pela_arvore`] — vale quando a ação **entra**, em
//! [`crate::ui`], com quem pediu conhecido: a mesma para as duas linhas, e
//! antes do arrendamento do campo. E vale de novo onde o caractere é
//! consumido: entre a entrada e o console há o programa e a fila do
//! pseudo-terminal, e o Enter da Pessoa que já ia a caminho pode, nesse
//! meio-tempo, mudar a linha. O Terminal digita marcado o que veio da
//! árvore, a interface reserva no console a edição que entregou, e o console
//! confere a regra contra a linha de agora — ver [`pela_arvore`]. Um Enter
//! de agente, o console reconhece pelo caractere, e só vale o que a árvore
//! pediu ([`pedir_enter_do_agente`]).

// Em `modo-teste` o laço do agente é trocado pelo executor da suíte, e o
// interpretador — que é uma tarefa desse laço — não é lançado. O resto do
// módulo existe nas duas compilações: a suíte abre os consoles à mão e age
// sobre eles pelo mesmo caminho que o agente e a pessoa usam em produção.
use core::fmt;

use crate::trava::Mutex;

use crate::agent::json::{Json, JsonWriter};
use crate::agent::registry;
use crate::agent::sessao::Amarrada;
use crate::autorizacao::{self, Chamador};
use crate::pessoas::{Console, EstadoDaSessao, IdSessao};
use crate::ui::Origem;

/// O maior comando que se pode digitar.
///
/// Não há heap no caminho de uma tecla, então a linha é um buffer fixo. Cento
/// e vinte caracteres cobrem o maior comando com parâmetros que este kernel
/// tem; o que passar disso é recusado com aviso, e não truncado em silêncio.
pub const LINHA_MAX: usize = 120;

/// O maior nome que o login aceita: o de [`sigilo::registro::nome_valido`].
const NOME_MAX: usize = 32;

/// Quantos consoles há: o físico e um por pseudo-terminal.
pub const CONSOLES: usize = 1 + crate::pseudoterminal::TERMINAIS;

/// O que aparece antes do que se digita. No protocolo, porque o Terminal o
/// procura na saída para achar a linha de comando.
use protocolo::usuario::terminal::PROMPT;

/// O que aparece no lugar do prompt enquanto o console pede o nome.
pub const PROMPT_DO_NOME: &str = "nome: ";
/// E a senha.
pub const PROMPT_DA_SENHA: &str = "senha: ";
/// Na troca da própria senha: a atual, a nova, e a nova de novo.
pub const PROMPT_DA_ATUAL: &str = "senha atual: ";
pub const PROMPT_DA_NOVA: &str = "senha nova: ";
pub const PROMPT_DE_NOVO: &str = "a nova de novo: ";
/// Na cerimônia de pareamento: enquanto ela espera o outro, o código que o
/// outro mostra, e a senha de novo.
pub const PROMPT_DO_PAREAMENTO: &str = "pareamento (linha vazia desiste): ";
pub const PROMPT_DO_CODIGO: &str = "codigo do outro: ";

/// O que a linha de um console está pedindo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modo {
    /// Um comando.
    Comando,
    /// O nome de quem vai entrar.
    Nome,
    /// A senha. O que se digita não ecoa.
    Senha,
    /// Na troca da própria senha, a atual — a prova. Não ecoa.
    SenhaAtual,
    /// A nova. Não ecoa.
    SenhaNova,
    /// A nova de novo, para conferir o que se digitou sem ver. Não ecoa.
    SenhaDeNovo,
    /// A cerimônia de pareamento deste console espera o outro dispositivo:
    /// uma linha vazia desiste. Só pelo teclado, como o login.
    Pareando,
    /// O código que o **outro** dispositivo mostra. Ecoa — não é segredo —,
    /// mas só o teclado o edita e o confirma.
    CodigoDoPar,
    /// A senha de quem está pareando, de novo. Não ecoa.
    SenhaDoPareamento,
}

impl Modo {
    /// O que se digita neste modo é uma senha: não ecoa, não aparece na
    /// árvore semântica, não entra no histórico do teclado, e a linha é
    /// apagada byte a byte.
    pub const fn secreto(self) -> bool {
        !matches!(
            self,
            Modo::Comando | Modo::Nome | Modo::Pareando | Modo::CodigoDoPar
        )
    }

    /// Um passo da cerimônia de pareamento.
    const fn do_pareamento(self) -> bool {
        matches!(
            self,
            Modo::Pareando | Modo::CodigoDoPar | Modo::SenhaDoPareamento
        )
    }

    /// O modo da linha que a cerimônia de pareamento pede.
    fn da_cerimonia(linha: crate::pareamento::Linha) -> Modo {
        use crate::pareamento::Linha;
        match linha {
            Linha::Comando => Modo::Comando,
            Linha::Esperando => Modo::Pareando,
            Linha::Codigo => Modo::CodigoDoPar,
            Linha::Senha => Modo::SenhaDoPareamento,
        }
    }

    /// A linha da cerimônia que este modo pede, se é um passo dela.
    fn linha_da_cerimonia(self) -> Option<crate::pareamento::Linha> {
        use crate::pareamento::Linha;
        match self {
            Modo::Pareando => Some(Linha::Esperando),
            Modo::CodigoDoPar => Some(Linha::Codigo),
            Modo::SenhaDoPareamento => Some(Linha::Senha),
            _ => None,
        }
    }

    /// Um passo da troca da própria senha.
    const fn da_troca(self) -> bool {
        matches!(self, Modo::SenhaAtual | Modo::SenhaNova | Modo::SenhaDeNovo)
    }

    /// O que aparece antes do que se digita.
    const fn prompt(self) -> &'static str {
        match self {
            Modo::Comando => PROMPT,
            Modo::Nome => PROMPT_DO_NOME,
            Modo::Senha => PROMPT_DA_SENHA,
            Modo::SenhaAtual => PROMPT_DA_ATUAL,
            Modo::SenhaNova => PROMPT_DA_NOVA,
            Modo::SenhaDeNovo => PROMPT_DE_NOVO,
            Modo::Pareando => PROMPT_DO_PAREAMENTO,
            Modo::CodigoDoPar => PROMPT_DO_CODIGO,
            Modo::SenhaDoPareamento => PROMPT_DA_SENHA,
        }
    }
}

/// Um console: a linha, o modo e quem está nele.
struct Estado {
    bytes: [u8; LINHA_MAX],
    tam: usize,
    /// Se o console está atendendo. O físico, desde que o interpretador
    /// começa; um Terminal, enquanto o pseudo-terminal dele está aberto.
    aberto: bool,
    /// Onde o campo começa na tela, em células — logo depois do prompt. Só
    /// do físico, e `None` enquanto não há campo: antes de atender, e
    /// enquanto um comando roda.
    inicio: Option<(u32, u32)>,
    /// Quantas vezes o console físico tinha rolado quando o campo começou. O
    /// campo sobe uma linha a cada rolagem desde então — ver
    /// [`crate::tela::console::rolagens`].
    rolagens: u32,
    modo: Modo,
    /// O nome digitado, enquanto a senha é pedida.
    nome: [u8; NOME_MAX],
    nome_tam: usize,
    /// A sessão de quem entrou.
    sessao: Option<IdSessao>,
    /// Quantas vezes o console abriu ou fechou. O login guarda a de quando
    /// a senha foi digitada, e só entra se ela não mudou — ver o modo
    /// [`Modo::Senha`] em [`tratar`].
    abertura: u64,
    /// A troca da própria senha em curso: a sessão que a pediu, e as
    /// senhas já digitadas — a atual e a nova — até a confirmação. Apagadas
    /// em toda saída: a troca feita ou recusada, a desistência, o console
    /// que fecha ou reabre. Ver [`Estado::largar_troca`].
    troca: Option<IdSessao>,
    atual: [u8; LINHA_MAX],
    atual_tam: usize,
    nova: [u8; LINHA_MAX],
    nova_tam: usize,
    /// Uma linha confirmada está sendo executada: o aviso da cerimônia de
    /// pareamento que chega no meio escreve, e o prompt fica para o fim
    /// dela — ver [`aviso_do_pareamento`].
    executando: bool,
    /// Os Enter de agente que a árvore entregou ao Terminal deste console e
    /// que o pseudo-terminal ainda não trouxe — cada um amarrado à conexão e
    /// à chave de quem o pediu. Ver [`pedir_enter_do_agente`].
    enter_pedido: [Option<Amarrada>; ENTER_PEDIDOS],
    /// A linha pedia uma senha, e a cerimônia de pareamento acabou por fora
    /// com ela parada no meio: até o Enter seguinte da Pessoa, o que se
    /// digita é o resto da senha, e é descartado — sem eco, fora da linha,
    /// da árvore e do histórico do teclado. Ver [`aviso_do_pareamento`] e
    /// [`engolir`].
    engolindo: bool,
    /// Num Terminal que engole: o Enter que acaba o engolir já passou pela
    /// janela dele, a caminho do console. As teclas da janela até ele são o
    /// resto da senha, e não passam pela coordenação; as de depois, o
    /// console não engole, e passam. Ver [`engolida_na_janela`].
    enter_na_janela: bool,
    /// O `press` que a árvore entregou na caixa de fechar da janela do
    /// Terminal deste console, e de quem: o registro do `logout` diz quem
    /// fechou. Ver [`press_pela_arvore`] e [`quem_fechou`].
    press_pela_arvore: Option<PressAnotado>,
    /// As edições da árvore — o `set_value` e o `cancel` no campo da janela
    /// do Terminal deste console — que a interface entregou ao programa e
    /// que o pseudo-terminal ainda não trouxe: quem pediu, e o que cada uma
    /// fez no arrendamento do campo. Ver [`reservar_edicao_da_arvore`].
    edicoes: [Option<EdicaoPedida>; EDICOES_PEDIDAS],
    /// A edição da árvore que o console está consumindo agora: o que veio
    /// marcado desde o último apagar marcado. Ver [`pela_arvore`].
    na_arvore: Option<EmCurso>,
    /// O estado do campo deixado pela última edição de uma sequência de
    /// edições da árvore recusadas no consumo, que começou tomando o
    /// arrendamento dele: a seguinte que começar dali é da mesma sequência.
    /// Ver [`pela_arvore`].
    recusadas: Option<politica::arrendamento::Estado>,
    /// O número da cerimônia de pareamento que este console abriu e que
    /// ainda não acabou para ele — guardado pelo `aceitar`, pelo `parear` e
    /// pelo Enter numa linha dela, e esquecido quando a linha volta a pedir
    /// um comando. O aviso de outra não muda a linha: ver
    /// [`aviso_do_pareamento`].
    cerimonia: Option<u64>,
    /// O passo da cerimônia que a linha mostra — ver
    /// [`crate::pareamento::passo_de`]. O aviso e o Enter leem o passo fora
    /// da trava do console e o escrevem dentro dela: quem leu um passo de
    /// antes do que a linha já mostra não a volta (o achado 3 do adversário
    /// do passo 1b).
    passo_da_cerimonia: u8,
    /// O maior número de cerimônia que este console viu acabar: o Enter ou
    /// o `aceitar` que leu uma delas viva, e escreve depois do fim dela, não
    /// a põe de volta na linha.
    cerimonia_encerrada: u64,
}

/// Quantas edições da árvore um console guarda à espera do pseudo-terminal.
/// Com todas ocupadas, a seguinte é recusada quando entra, antes da conta
/// da coordenação: ver [`reservar_edicao_da_arvore`].
const EDICOES_PEDIDAS: usize = 8;

/// A recusa de uma edição da árvore com as reservas do console cheias.
pub const EDICOES_DEMAIS: &str = "o console ja espera edicoes da arvore demais";

/// Uma edição que a interface entregou ao Terminal de um console — ver
/// [`reservar_edicao_da_arvore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EdicaoPedida {
    /// O número da reserva: um por edição, desde o boot. É a ordem em que o
    /// console as espera, e o que [`anotar_a_edicao_da_arvore`] e
    /// [`desistir_da_edicao_da_arvore`] procuram.
    numero: u64,
    /// O campo da janela do Terminal — o elemento da árvore —, quem pediu,
    /// e o quê: o recurso do arrendamento, e o log da recusa.
    campo: u32,
    origem: Origem,
    acao: crate::ui::Acao,
    /// Quem pediu — o agente, amarrado à conexão e à chave que o gate
    /// decidiu, como o Enter dele ([`pedir_enter_do_agente`]); ou a pessoa,
    /// pela sessão de onde pediu —, conferido de novo quando o console
    /// consome a edição: a de quem já não vale — saiu da conexão ou da
    /// sessão, ou foi contido — é descartada ([`quem_ja_nao_vale`]).
    quem: QuemPediu,
    /// O que a conta da coordenação fez no campo — anotado depois dela;
    /// `None` até lá.
    rastro: Option<crate::coordenacao::Rastro>,
    /// Recusada antes de chegar: a linha passou a pedir a pessoa com ela a
    /// caminho — ver [`recusar_as_edicoes_a_caminho`]. O que chegar marcado
    /// dela é descartado.
    recusada: bool,
}

/// Quem pediu uma edição da árvore, para as perguntas do consumo — ver
/// [`quem_ja_nao_vale`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuemPediu {
    /// O agente, amarrado à conexão de onde pediu e à chave que o gate
    /// decidiu.
    Agente(Amarrada),
    /// A pessoa, pela sessão de onde pediu, e quem é ela: a sessão tem de
    /// estar ainda aberta, e ser dela.
    Pessoa(IdSessao, sigilo::pessoas::IdPessoa),
}

/// O que o console está consumindo da árvore — ver [`pela_arvore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EmCurso {
    /// A reserva que o apagar marcado apontou; `None` para o que veio
    /// marcado sem reserva.
    pedida: Option<EdicaoPedida>,
    /// A regra da linha da pessoa já recusou um caractere dela: o resto é
    /// descartado também, mesmo que a linha volte a pedir um comando.
    recusada: bool,
}

/// Uma anotação de [`press_pela_arvore`]: quem apertou, e um número que é
/// só dela — o desfazer confere que a anotação do console ainda é a sua.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PressAnotado {
    origem: Origem,
    numero: u64,
}

impl Estado {
    const NOVO: Estado = Estado {
        bytes: [0; LINHA_MAX],
        tam: 0,
        aberto: false,
        inicio: None,
        rolagens: 0,
        modo: Modo::Comando,
        nome: [0; NOME_MAX],
        nome_tam: 0,
        sessao: None,
        abertura: 0,
        troca: None,
        atual: [0; LINHA_MAX],
        atual_tam: 0,
        nova: [0; LINHA_MAX],
        nova_tam: 0,
        executando: false,
        enter_pedido: [None; ENTER_PEDIDOS],
        engolindo: false,
        enter_na_janela: false,
        press_pela_arvore: None,
        edicoes: [None; EDICOES_PEDIDAS],
        na_arvore: None,
        recusadas: None,
        cerimonia: None,
        passo_da_cerimonia: 0,
        cerimonia_encerrada: 0,
    };

    /// Esquece as edições da árvore: as reservadas, a que estava sendo
    /// consumida e a sequência das recusadas. O console abriu ou fechou.
    fn largar_edicoes(&mut self) {
        self.edicoes = [None; EDICOES_PEDIDAS];
        self.na_arvore = None;
        self.recusadas = None;
    }

    /// Esquece a troca da própria senha em curso, e apaga as senhas que
    /// ela guardava — os bytes, e não só os tamanhos.
    fn largar_troca(&mut self) {
        self.troca = None;
        sigilo::zeroize::Zeroize::zeroize(&mut self.atual);
        sigilo::zeroize::Zeroize::zeroize(&mut self.nova);
        self.atual_tam = 0;
        self.nova_tam = 0;
    }

    fn texto(&self) -> &str {
        // Só entram na linha caracteres ASCII, filtrados em [`digitar_em`] e
        // em [`definir`]: o `unwrap_or` existe para que um dia em que isso
        // mude vire uma linha vazia, e não um pânico.
        core::str::from_utf8(&self.bytes[..self.tam]).unwrap_or("")
    }

    /// Apaga a linha — os bytes também, e não só o tamanho: pode ter sido
    /// uma senha.
    fn zerar(&mut self) {
        self.bytes = [0; LINHA_MAX];
        self.tam = 0;
    }

    /// O console para de engolir: o Enter da Pessoa chegou — ver
    /// [`engolir`]. E a linha se apaga, por defesa: o fim da cerimônia a
    /// deixou vazia, e nada a edita enquanto ela engole — o texto e o
    /// apagar conferem o engolir na mesma seção que editam, em [`tratar`]
    /// —; o que entrasse nela por outro caminho seria o resto da senha, e
    /// iria à frente do comando seguinte.
    fn parar_de_engolir(&mut self) {
        self.engolindo = false;
        self.enter_na_janela = false;
        self.zerar();
    }
}

// A tomada desta tranca passa por `sem_interrupcoes`, pelo motivo de toda
// tranca deste kernel, e nunca atravessa a execução de um comando: um comando
// pode ser `ui.tree`, que lê a linha do físico.
//
// E o desenho mora **dentro** da seção crítica, junto com a mudança que ele
// desenha. Separados, havia uma janela entre os dois: o timer podia passar a
// vez a um processo de usuário, o processo registrar uma linha no log, e
// [`por_cima`] redesenhar a linha com um caractere que ainda não tinha sido
// desenhado — que em seguida era desenhado de novo. Com as interrupções
// mascaradas não há troca de fio no meio, e a tela e o buffer mudam juntos.
//
// A suíte não consegue falsificar isto: a janela é de algumas instruções, e
// nenhum caso provoca a preempção nela. Fica escrito aqui, onde quem for
// separar os dois vai ler.
static ESTADOS: Mutex<[Estado; CONSOLES]> = Mutex::new([const { Estado::NOVO }; CONSOLES]);

/// Um comando de console que suspendeu — ver [`crate::rede::espera`]: a
/// linha, executada de novo quando a espera acabar; quem a confirmou — e,
/// se foi um agente, a conexão dele ([`Amarrada`]); a abertura do console
/// quando ela foi confirmada — reaberto ou fechado, o console não espera
/// mais por ela —; e a espera.
struct Suspenso {
    abertura: u64,
    linha: politica::sigiloso::Texto,
    origem: Origem,
    amarrada: Option<Amarrada>,
    espera: crate::rede::espera::Espera,
}

/// O comando suspenso de cada console. Enquanto há um, o console espera
/// por ele: não lê a entrada dele — o que se digita fica na fila — e não
/// confirma outra linha. Os outros consoles e as janelas seguem atendidos.
///
/// Nunca tomada junto com [`ESTADOS`]: a abertura é lida antes, numa tomada
/// à parte.
static SUSPENSOS: Mutex<[Option<Suspenso>; CONSOLES]> = Mutex::new([const { None }; CONSOLES]);

/// A posição de um console na tabela.
fn indice(console: Console) -> Option<usize> {
    match console {
        Console::Fisico => Some(0),
        Console::Terminal(i) => {
            let i = usize::from(i);
            (i < crate::pseudoterminal::TERMINAIS).then_some(1 + i)
        }
    }
}

/// O console da posição `i` da tabela — o inverso de [`indice`].
fn console_na(i: usize) -> Console {
    match i {
        0 => Console::Fisico,
        i => Console::Terminal((i - 1) as u16),
    }
}

/// O console espera um comando que suspendeu?
pub fn ocupado(console: Console) -> bool {
    indice(console).is_some_and(|i| crate::arch::sem_interrupcoes(|| SUSPENSOS.lock()[i].is_some()))
}

fn com_estado<R>(console: Console, f: impl FnOnce(&mut Estado) -> R) -> Option<R> {
    let i = indice(console)?;
    Some(crate::arch::sem_interrupcoes(|| f(&mut ESTADOS.lock()[i])))
}

fn com_fisico<R>(f: impl FnOnce(&mut Estado) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut ESTADOS.lock()[0]))
}

/// Escreve na saída de um console: a tela e a COM1 para o físico, o anel do
/// pseudo-terminal para um Terminal.
fn escrever(console: Console, args: fmt::Arguments) {
    match console {
        Console::Fisico => crate::serial::_print(args),
        Console::Terminal(i) => {
            let _ = fmt::Write::write_fmt(&mut crate::pseudoterminal::Saida(i as u8), args);
        }
    }
}

macro_rules! saida {
    ($console:expr, $($arg:tt)*) => {
        escrever($console, format_args!($($arg)*))
    };
}

macro_rules! saidaln {
    ($console:expr) => {
        escrever($console, format_args!("\n"))
    };
    ($console:expr, $($arg:tt)*) => {{
        escrever($console, format_args!($($arg)*));
        escrever($console, format_args!("\n"));
    }};
}

/// Lê as entradas dos consoles e executa o que for digitado. Nunca retorna.
///
/// É uma tarefa do executor cooperativo, ao lado do canal do agente. Entre
/// uma entrada e outra ela devolve `Pending`, e o núcleo dorme: uma pessoa
/// digitando é a coisa mais lenta que este kernel espera, e girar à toa por
/// causa dela seria gastar todo o núcleo com o que não chega.
#[cfg(not(feature = "modo-teste"))]
pub async fn atender() {
    crate::serial_println!();
    abrir_console(Console::Fisico);

    loop {
        match (Proximo { relogio: None }).await {
            Evento::Entrada(crate::teclado::Entrada::Console(Console::Fisico, c)) => {
                consumir_do_teclado(c)
            }
            Evento::Entrada(crate::teclado::Entrada::Console(console, c)) => tratar(console, c),
            Evento::Entrada(crate::teclado::Entrada::Janela(c)) => tratar_tecla_de_janela(c),
            Evento::Retomar => {
                retomar_suspensos();
            }
            Evento::Pareamento => crate::pareamento::no_console(),
        }
    }
}

/// O que acorda o interpretador.
#[cfg(not(feature = "modo-teste"))]
enum Evento {
    /// Uma entrada de um console que não espera comando, ou de uma janela.
    Entrada(crate::teclado::Entrada),
    /// A espera de um comando suspenso acabou.
    Retomar,
    /// A cerimônia de pareamento deve um passo que só se dá na vez do
    /// console: gravar, ou desfazer — ver [`crate::pareamento::no_console`].
    Pareamento,
}

/// O próximo [`Evento`]: a entrada de um console livre ou de uma janela; o
/// evento da conexão por que um comando suspenso espera — a pilha acorda a
/// tarefa —; ou o prazo mais próximo, pelo relógio.
#[cfg(not(feature = "modo-teste"))]
struct Proximo {
    relogio: Option<crate::tarefas::relogio::Dormir>,
}

#[cfg(not(feature = "modo-teste"))]
impl core::future::Future for Proximo {
    type Output = Evento;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context,
    ) -> core::task::Poll<Evento> {
        use core::task::Poll;
        let este = self.get_mut();
        if crate::pareamento::deve_ao_console() {
            return Poll::Ready(Evento::Pareamento);
        }
        // Cada conferência deixa o waker desta tarefa no socket da conexão.
        let (acabou, prazo, ocupados) = crate::arch::sem_interrupcoes(|| {
            let tabela = SUSPENSOS.lock();
            let acabou = tabela
                .iter()
                .flatten()
                .any(|s| s.espera.conferir(Some(cx.waker())).is_some());
            let prazo = tabela.iter().flatten().map(|s| s.espera.prazo()).min();
            let ocupados = tabela
                .iter()
                .enumerate()
                .filter(|(_, s)| s.is_some())
                .fold(0u32, |m, (i, _)| m | (1 << i));
            (acabou, prazo, ocupados)
        });
        if acabou {
            return Poll::Ready(Evento::Retomar);
        }
        let entrada = core::pin::Pin::new(&mut crate::teclado::proxima_entrada(ocupados)).poll(cx);
        if let Poll::Ready(e) = entrada {
            return Poll::Ready(Evento::Entrada(e));
        }
        let Some(prazo) = prazo else {
            este.relogio = None;
            return Poll::Pending;
        };
        if este.relogio.as_ref().is_none_or(|r| r.alvo() != prazo) {
            este.relogio = Some(crate::tarefas::relogio::ate_o_tique(prazo));
        }
        match este
            .relogio
            .as_mut()
            .map(|r| core::pin::Pin::new(r).poll(cx))
        {
            Some(Poll::Ready(())) => Poll::Ready(Evento::Retomar),
            _ => Poll::Pending,
        }
    }
}

/// Executa de novo os comandos suspensos cuja espera acabou — conferida sem
/// registrar waker nenhum —, cada um no console dele, e devolve quantos.
///
/// Pelo mesmo caminho da primeira vez: a mesma linha, o mesmo gate — a
/// pessoa, pela sessão de quem está no console agora; um agente, só se ele
/// ainda está na conexão de onde confirmou, como a reexecução do canal
/// (`agent::reexecutar`): a sessão dele é a vaga do transporte, e quem
/// estiver nela depois não é ele. Um console que reabriu ou fechou durante
/// a espera não recebe nada.
pub fn retomar_suspensos() -> usize {
    let prontos: alloc::vec::Vec<(Console, Suspenso, crate::rede::espera::Desfecho)> =
        crate::arch::sem_interrupcoes(|| {
            let mut tabela = SUSPENSOS.lock();
            let mut prontos = alloc::vec::Vec::new();
            for (i, vaga) in tabela.iter_mut().enumerate() {
                if let Some(d) = vaga.as_ref().and_then(|s| s.espera.conferir(None))
                    && let Some(s) = vaga.take()
                {
                    prontos.push((console_na(i), s, d));
                }
            }
            prontos
        });
    let mut retomados = 0;
    for (console, suspenso, desfecho) in prontos {
        let Suspenso {
            abertura,
            linha,
            origem,
            amarrada,
            espera,
        } = suspenso;
        drop(espera);
        if com_estado(console, |e| e.abertura) != Some(abertura) {
            crate::log_info!(
                "console",
                "{}: o console mudou durante a espera ({:?}); nada a mostrar",
                console.texto(),
                desfecho
            );
            continue;
        }
        if let Origem::Agente(sessao) = origem
            && !amarrada.is_some_and(|a| a.vale())
        {
            crate::log_info!(
                "console",
                "{}: o agente {} que confirmou a linha saiu da conexao durante a espera ({:?}); nada a executar",
                console.texto(),
                sessao,
                desfecho
            );
            mostrar_prompt(console);
            continue;
        }
        let texto = core::str::from_utf8(linha.como_bytes()).unwrap_or("");
        // A espera acabou: a reexecução responde, e não suspende de novo.
        let (_, espera) = executar(console, texto, origem, false);
        drop(espera);
        mostrar_prompt(console);
        retomados += 1;
    }
    retomados
}

/// Abre um console: sem ninguém entrado, a linha vazia, e o convite para
/// entrar. O físico abre quando o interpretador começa; um Terminal, quando
/// o pseudo-terminal dele abre.
///
/// Uma sessão que tivesse ficado no console é **encerrada**, e não só
/// esquecida: esquecê-la a deixaria viva no registro de pessoas, sem console
/// nenhum que a feche. O pseudo-terminal fecha o console antes de reabri-lo,
/// e então não sobra sessão; isto é a segunda linha, para a ordem que não
/// devia acontecer — e que aconteceu, com vários núcleos, antes de a vaga do
/// pseudo-terminal ganhar o estado em troca.
pub fn abrir_console(console: Console) {
    let sobra = com_estado(console, |e| {
        let sobra = e.sessao.take();
        e.zerar();
        e.largar_troca();
        e.aberto = true;
        e.abertura += 1;
        e.modo = Modo::Comando;
        e.cerimonia = None;
        e.passo_da_cerimonia = 0;
        e.nome_tam = 0;
        e.enter_pedido = [None; ENTER_PEDIDOS];
        e.engolindo = false;
        e.enter_na_janela = false;
        e.press_pela_arvore = None;
        e.largar_edicoes();
        saidaln!(
            console,
            "Duke, {}. Ninguem entrou: `login` para entrar, `ajuda` para saber mais.",
            console.texto()
        );
        prompt_em(console, e);
        sobra
    })
    .flatten();
    largar_suspenso(console);
    // A cerimônia de pareamento deste console, se havia uma, acaba: quem a
    // abriu não está mais nele.
    crate::pareamento::console_mudou(console);
    // A linha volta a pedir um comando: o teclado volta a gravar o
    // histórico, se ela pedia uma senha.
    if let Some(i) = indice(console) {
        crate::teclado::pedindo_senha(i, false);
    }
    if let Some(id) = sobra {
        crate::pessoas::encerrar_pelo_console(id, "o console reabriu");
    }
    if console == Console::Fisico {
        crate::ui::mudou();
    }
}

/// O que [`press_pela_arvore`] devolve, para [`desfazer_press_pela_arvore`]:
/// o console, o número da anotação que ela pôs, e a que havia antes.
#[derive(Clone, Copy, Debug)]
pub struct Anotacao {
    console: Console,
    posta: u64,
    anterior: Option<PressAnotado>,
}

/// O número da próxima anotação de [`press_pela_arvore`]: um por anotação,
/// desde o boot.
static ANOTACOES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// A árvore entrega ao Terminal deste console o `press` de `origem` na
/// caixa de fechar da janela dele: anota, para o registro do `logout` dizer
/// quem fechou — ver [`quem_fechou`] —, e devolve a [`Anotacao`], para
/// [`desfazer_press_pela_arvore`]. Chamada por `crate::ui` **antes** de
/// publicar o evento: noutro núcleo, o Terminal pode fechar e o console
/// acabar antes de a publicação voltar.
///
/// Só diz quem foi; não decide nada, e não recusa nada. A decisão do
/// `press` é a do `ui.act`, gravada antes, com o nome de quem pediu.
pub fn press_pela_arvore(console: Console, origem: Origem) -> Anotacao {
    let numero = ANOTACOES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let posta = PressAnotado { origem, numero };
    let anterior = com_estado(console, |e| e.press_pela_arvore.replace(posta)).flatten();
    Anotacao {
        console,
        posta: numero,
        anterior,
    }
}

/// Desfaz um [`press_pela_arvore`]: o evento não chegou ao Terminal.
///
/// Compara antes de restaurar: só desfaz se a anotação do console ainda é
/// a que ela pôs. Outra anotação depois dela — um `press` que chegou —, ou
/// o console que fechou ou reabriu no meio, que apaga as anotações, ficam
/// como estão. Restaurar às cegas poria a anotação de antes no lugar da de
/// um `press` que chegou ao Terminal, ou no console reaberto, e o registro
/// do `logout` seguinte culparia quem não fechou.
pub fn desfazer_press_pela_arvore(anotacao: Anotacao) {
    com_estado(anotacao.console, |e| {
        if e.press_pela_arvore
            .is_some_and(|p| p.numero == anotacao.posta)
        {
            e.press_pela_arvore = anotacao.anterior;
        }
    });
}

/// Quem fechou o Terminal deste console, para o registro do `logout`.
///
/// - Com o `press` da árvore anotado ([`press_pela_arvore`]): `o terminal
///   fechou pelo press de agente N na arvore` — ou `de pessoa`, a pessoa
///   que pediu pela árvore. A sessão `N` é a vaga do transporte, que outra
///   conexão ocupa depois; o `ui.act` gravado diz o nome.
/// - Sem: `o terminal fechou pelo clique da pessoa` — uma dedução: o dono
///   do pseudo-terminal o fechou sem um `press` da árvore anotado. O
///   Terminal só fecha o pseudo-terminal por um gesto de fechar, e o que
///   não veio da árvore veio do ponteiro, que é o mouse da máquina; quem
///   pode ser "o Terminal" — o dono do pseudo-terminal — é a decisão
///   pendente do nome `terminal`.
///
/// A queda, o término e a saída sem fechar não passam por aqui: o coletor
/// os acha, e diz `o terminal morreu`. Com a pessoa clicando e um agente
/// apertando ao mesmo tempo, diz o agente — o `press` dele foi entregue
/// antes do fechamento —, ainda que o clique tenha fechado: o clique numa
/// janela não é gravado.
pub fn quem_fechou(console: Console) -> alloc::string::String {
    match com_estado(console, |e| e.press_pela_arvore).flatten() {
        Some(p) => alloc::format!("o terminal fechou pelo press de {} na arvore", p.origem),
        None => alloc::string::String::from("o terminal fechou pelo clique da pessoa"),
    }
}

/// Larga o comando suspenso do console, se há um: o console reabriu ou
/// fechou, e quem confirmou a linha não está mais nele. A espera desarma, e
/// a entrada do console volta a ser lida. Fora das duas travas.
fn largar_suspenso(console: Console) {
    let Some(i) = indice(console) else {
        return;
    };
    let suspenso = crate::arch::sem_interrupcoes(|| SUSPENSOS.lock()[i].take());
    if suspenso.is_some() {
        crate::log_info!(
            "console",
            "{}: o comando que esperava foi largado; o console mudou",
            console.texto()
        );
    }
    drop(suspenso);
}

/// Fecha um console: a sessão de quem estava nele acaba, e o que ele
/// guardava se apaga. Chamada pelo pseudo-terminal quando o Terminal fecha,
/// ou o processo dele morre. O `motivo` vai ao registro do `logout`: quem
/// fechou — ver [`quem_fechou`] —, ou a queda.
pub fn fechar_console(console: Console, motivo: &str) {
    let Some((sessao, i)) = com_estado(console, |e| {
        let sessao = e.sessao.take();
        e.zerar();
        e.largar_troca();
        e.aberto = false;
        e.abertura += 1;
        e.inicio = None;
        e.modo = Modo::Comando;
        e.cerimonia = None;
        e.passo_da_cerimonia = 0;
        e.nome = [0; NOME_MAX];
        e.nome_tam = 0;
        e.enter_pedido = [None; ENTER_PEDIDOS];
        e.engolindo = false;
        e.enter_na_janela = false;
        e.press_pela_arvore = None;
        e.largar_edicoes();
        sessao
    })
    .zip(indice(console)) else {
        return;
    };
    largar_suspenso(console);
    crate::pareamento::console_mudou(console);
    crate::teclado::pedindo_senha(i, false);
    if let Some(id) = sessao {
        crate::pessoas::encerrar_pelo_console(id, motivo);
    }
}

/// O que uma tecla faz, quando chega a quem está na frente da máquina.
///
/// Separado do laço para a suíte alcançá-lo: em modo de teste não há
/// executor, e sem isto o caminho da pessoa só seria exercitado pela fumaça.
/// É o mesmo consumo da produção — ver [`consumir_do_teclado`].
#[cfg(feature = "modo-teste")]
pub fn tratar_tecla(c: char) {
    consumir_do_teclado(c);
}

/// O console físico consome uma tecla da fila do teclado da máquina: ela
/// entra no histórico do teclado — se é texto, e se nenhum console pede uma
/// senha **agora**, com a linha como está — e então é tratada. Ver
/// [`crate::teclado::consumida`].
///
/// O histórico antes de tratar, e não depois: vale o modo em que a tecla é
/// consumida. O Enter que leva à senha entra; a primeira letra dela, com a
/// linha já pedindo-a, não. A tecla de uma janela que cai no físico — sem
/// quem a escute — não passa por aqui: ela entrou no histórico quando
/// chegou.
///
/// Um caminho só para a produção e para a suíte, como o de [`separar`].
fn consumir_do_teclado(c: char) {
    crate::teclado::consumida(c);
    tratar(Console::Fisico, c);
}

/// O que um caractere faz num console.
pub fn tratar(console: Console, c: char) {
    use protocolo::usuario::terminal::{APAGAR_A_LINHA, agente_que_confirmou, veio_da_arvore};
    // Um clique e as teclas de função são do console físico — os
    // pseudo-terminais não os deixam passar — e acionam a barra pelo mesmo
    // caminho do `press` do agente ([`crate::ui::agir`]), depois da decisão
    // com a sessão de quem está no console: sem ninguém entrado, nada. Não
    // dependem da linha estar atendendo: a barra é da tela, e não da linha.
    match c {
        crate::teclado::CLIQUE => {
            let (x, y) = crate::ponteiro::ultimo_clique();
            if let Some(id) = crate::ui::acionavel_em(x, y)
                && pessoa_pode_agir(console, id)
            {
                crate::ponteiro::tratar_clique(x, y);
            }
            return;
        }
        crate::teclado::F1 | crate::teclado::F2 | crate::teclado::F3 => {
            let id = match c {
                crate::teclado::F1 => crate::ui::ID_DO_BOTAO_LIMPAR,
                crate::teclado::F2 => crate::ui::ID_DO_BOTAO_SOBRE,
                _ => crate::ui::ID_DO_BOTAO_TERMINAL,
            };
            if pessoa_pode_agir(console, id) {
                let _ = crate::ui::agir(id, crate::ui::Acao::Pressionar, None, Origem::Pessoa);
            }
            return;
        }
        _ => {}
    }
    if !com_estado(console, |e| e.aberto).unwrap_or(false) {
        return;
    }
    // O que o Terminal digitou pela árvore vem marcado: a regra da linha da
    // pessoa é conferida aqui, contra a linha de agora — ver [`pela_arvore`].
    if let Some(original) = veio_da_arvore(c) {
        pela_arvore(console, original);
        return;
    }
    // O que vem sem marca é a tecla da Pessoa — ou o que quem escreve no
    // pseudo-terminal digitou sem marcar, que chega como ela —, e acaba a
    // edição da árvore que o console consumia.
    com_estado(console, |e| e.na_arvore = None);
    // O resto de uma senha cuja cerimônia acabou no meio: descartado até o
    // Enter, antes da coordenação — o que se engole não arrenda a linha,
    // não aumenta a versão dela e não é recusado como `CONFLICT`.
    if engolir(console, c) {
        return;
    }
    #[cfg(feature = "modo-teste")]
    no_meio(NoMeio::DaTecla);
    if console == Console::Fisico && !tecla_coordenada(c) {
        return;
    }
    // O apagar e o texto conferem o engolir de novo, na mesma seção que
    // editam a linha: [`engolir`] solta a trava, e o fim da cerimônia,
    // noutro núcleo, pode pô-la a engolir antes desta tecla chegar à linha —
    // e então ela é o resto da senha: sem eco, e fora da linha. O Enter
    // confere em [`confirmar_em`]; o resto não edita a linha.
    match c {
        '\n' => {
            confirmar_em(console, Origem::Pessoa);
        }
        '\u{8}' => {
            com_estado(console, |e| {
                if !e.engolindo {
                    apagar_em(console, e);
                }
            });
        }
        // A linha inteira, sem marca: como o Ctrl-U da pessoa — nenhum
        // teclado o produz, e o Terminal digita o da árvore marcado (ver
        // [`pela_arvore`]); sem marca, é o que quem escreve no
        // pseudo-terminal digitou por conta própria, e chega como a tecla da
        // pessoa. Ver `protocolo::usuario::terminal`.
        APAGAR_A_LINHA => {
            let _ = definir_em(console, "");
        }
        // O Enter de um agente vale só como a árvore o pediu: o `confirm`
        // daquela sessão, entregue ao Terminal deste console. Escrito por
        // conta própria por quem tem o pseudo-terminal, não confirma nada —
        // o número dentro do caractere não é autoridade.
        c if agente_que_confirmou(c).is_some() => {
            if let Some(sessao) = agente_que_confirmou(c) {
                match tomar_enter_pedido(console, sessao) {
                    Tomado::Valido => {
                        confirmar_em(console, Origem::Agente(sessao));
                    }
                    Tomado::DeOutraConexao => crate::log_warn!(
                        "console",
                        "{}: o Enter do agente {} nao e mais da conexao que o pediu; descartado",
                        console.texto(),
                        sessao
                    ),
                    Tomado::Nenhum => crate::log_warn!(
                        "console",
                        "{}: o Enter do agente {} nao foi pedido pela arvore; descartado",
                        console.texto(),
                        sessao
                    ),
                }
            }
        }
        // Só o que é texto entra na linha. Teclas sem caractere já não
        // chegam aqui, mas o controle que sobra — um tab, por exemplo —
        // desalinharia a conta entre o que está no buffer e o que está
        // desenhado.
        c if aceito(c) => {
            let coube = com_estado(console, |e| {
                if e.engolindo {
                    return true;
                }
                digitar_em(console, e, c)
            })
            .unwrap_or(true);
            if !coube {
                com_estado(console, |e| {
                    saidaln!(console);
                    saidaln!(console, "linha longa demais; ate {} caracteres", LINHA_MAX);
                    e.zerar();
                    prompt_em(console, e);
                });
            }
        }
        _ => {}
    }
    if console == Console::Fisico {
        crate::ui::mudou();
    }
}

/// Uma tecla para a janela com o foco: decidida, e então entregue.
///
/// - Quem digita: numa janela de Terminal, a pessoa entrada no console
///   dele; em qualquer outra, a pessoa entrada no console físico — o
///   teclado é o da máquina. Numa janela que não é de Terminal, sem ninguém
///   entrado no físico, nada: `DENY_NOT_AUTHENTICATED`, gravado. No
///   Terminal a tecla passa — o login é dele, e o console dele decide.
/// - O campo que a janela declara na linha `foco` é um recurso arrendável:
///   a tecla que o edita passa pela coordenação como a do console físico —
///   arrenda o campo livre, e é recusada (`CONFLICT`, gravado) no campo de
///   outro. O Enter de um campo com algo pede o arrendamento.
/// - Menos o resto de uma senha que o console do Terminal engole — ver
///   [`engolir`] e [`engolida_na_janela`]: como no físico, o que se engole
///   não arrenda o campo, não aumenta a versão dele e não é `CONFLICT`. A
///   tecla vai ao Terminal, que a escreve no pseudo-terminal, e o console a
///   descarta.
/// - Sem quem escute na janela — o dono morreu e o foco ainda não voltou
///   —, a tecla vai para o console físico, em vez de sumir. A que o console
///   do Terminal engolia, não: é o resto de uma senha, e some.
pub fn tratar_tecla_de_janela(c: char) {
    let Some(janela) = crate::superficies::janela_com_foco() else {
        tratar(Console::Fisico, c);
        return;
    };
    let terminal = crate::pseudoterminal::console_do_dono(janela.dono);
    let console = terminal.unwrap_or(Console::Fisico);
    let titular = crate::coordenacao::titular(Origem::Pessoa, console);
    if terminal.is_none() && titular.is_none() {
        crate::autorizacao::recusar_sem_login(Console::Fisico, "keyboard", &[]);
        return;
    }
    let engolida = terminal.is_some_and(|console| engolida_na_janela(console, c));
    if !engolida
        && let Some((indice, valor)) = &janela.campo
        && let Some(id) = crate::ui::id_do_elemento(janela.camada, *indice)
    {
        let recurso = crate::coordenacao::recurso(id);
        // O valor vem da última descrição da janela, que pode não ter
        // chegado ainda à tecla de antes: o Enter logo depois de digitar
        // veria o campo vazio. Por isso o Enter só passa sem confirmar no
        // campo vazio **e** livre — com arrendamento, confirma: o de quem
        // digitou é solto, e o de outro é `CONFLICT`.
        let livre = || crate::coordenacao::estado(&recurso).arrendamento.is_none();
        let r = match c {
            '\n' if valor.is_empty() && livre() => Ok(0),
            '\n' => crate::coordenacao::confirmar(&recurso, titular, None, "keyboard"),
            '\u{8}' => crate::coordenacao::editar(&recurso, titular, None, "keyboard"),
            c if aceito(c) => crate::coordenacao::editar(&recurso, titular, None, "keyboard"),
            _ => Ok(0),
        };
        if let Err(codigo) = r {
            crate::log_info!("console", "tecla na janela recusada: {}", codigo.nome());
            return;
        }
    }
    let evento = protocolo::usuario::evento::Evento {
        tipo: protocolo::usuario::evento::tipo::TECLA,
        a: c as i64,
        b: 0,
        c: 0,
    };
    if !crate::superficies::entregar(janela.destino, evento) && !engolida {
        tratar(Console::Fisico, c);
    }
}

/// A tecla `c`, que vai à janela do Terminal do console `console`, é o
/// resto de uma senha que ele engole — ver [`engolir`]?
///
/// O console engole quando trata a tecla, e a janela a recebe antes: entre
/// as duas, o Terminal e a fila do pseudo-terminal. Então a janela conta o
/// Enter que passa por ela: até ele — inclusive —, as teclas são o resto
/// da senha, que o console vai engolir; as de depois, ele não engole, e
/// voltam a passar pela coordenação mesmo que o console ainda não tenha
/// tratado o Enter. O console que para de engolir, ou que abre e fecha,
/// zera a conta.
///
/// Fica de fora só a borda: a tecla que passou pela janela antes de o fim
/// da cerimônia chegar já passou pela coordenação — como a do físico que
/// passa por [`engolir`] antes dele —; e a que vem depois de um Enter
/// digitado antes do fim, ainda a caminho, não passa até o console tratar
/// esse Enter.
fn engolida_na_janela(console: Console, c: char) -> bool {
    com_estado(console, |e| {
        let engolida = e.engolindo && !e.enter_na_janela;
        if engolida && c == '\n' {
            e.enter_na_janela = true;
        }
        engolida
    })
    .unwrap_or(false)
}

/// A tecla da pessoa na linha do console físico, pela coordenação — ver
/// [`crate::coordenacao`]: a linha é um recurso compartilhado com os
/// agentes, pela árvore.
///
/// Uma edição — um caractere, o apagar — arrenda a linha livre para a
/// pessoa entrada no console, e renova o arrendamento dela; o Enter de uma
/// linha com algo pede o arrendamento, e o solta depois. Na linha arrendada
/// por outro, a tecla é recusada — `CONFLICT`, gravado —, e não substitui
/// em silêncio quem estava ali. Falso se a tecla não deve ter efeito.
///
/// Sem ninguém entrado — a pessoa digitando o `login` —, a tecla só passa
/// na linha livre, e não a arrenda.
fn tecla_coordenada(c: char) -> bool {
    let recurso = crate::coordenacao::recurso(crate::ui::ID_DA_LINHA_DE_COMANDO);
    let titular = || crate::coordenacao::titular(Origem::Pessoa, Console::Fisico);
    let r = match c {
        '\n' => {
            let (modo, vazia) = com_fisico(|e| (e.modo, e.tam == 0));
            if modo != Modo::Comando || vazia {
                return true;
            }
            crate::coordenacao::confirmar(&recurso, titular(), None, "keyboard")
        }
        '\u{8}' => crate::coordenacao::editar(&recurso, titular(), None, "keyboard"),
        c if aceito(c) => crate::coordenacao::editar(&recurso, titular(), None, "keyboard"),
        _ => return true,
    };
    if let Err(codigo) = r {
        crate::log_info!(
            "console",
            "tecla na linha de comando recusada: {}",
            codigo.nome()
        );
        return false;
    }
    true
}

/// A pessoa no console pode acionar o elemento `id`? Decide `ui.act` com a
/// sessão dela, e grava; sem ninguém entrado, recusa e grava também.
fn pessoa_pode_agir(console: Console, id: u32) -> bool {
    let sessao = sessao_valida(console);
    let codigo = autorizacao::autorizar_acao_da_pessoa(console, sessao, id);
    if !codigo.permite() {
        crate::log_info!(
            "console",
            "{}: acao no elemento {} negada: {}",
            console.texto(),
            id,
            codigo.nome()
        );
    }
    codigo.permite()
}

/// Um caractere que uma pessoa consegue pôr na linha.
fn aceito(c: char) -> bool {
    c.is_ascii_graphic() || c == ' '
}

/// O prompt do modo, e onde o campo começa. Com o estado na mão.
fn prompt_em(console: Console, e: &mut Estado) {
    let prompt = e.modo.prompt();
    saida!(console, "{prompt}");
    if console == Console::Fisico {
        e.inicio = Some(crate::tela::console::cursor_em_celulas());
        e.rolagens = crate::tela::console::rolagens();
    }
}

/// Acrescenta um caractere à linha e o desenha — menos na senha, que não
/// ecoa. Falso se ele não coube.
fn digitar_em(console: Console, e: &mut Estado, c: char) -> bool {
    if e.tam >= LINHA_MAX {
        return false;
    }
    e.bytes[e.tam] = c as u8;
    e.tam += 1;
    if !e.modo.secreto() {
        saida!(console, "{c}");
    }
    true
}

/// Apaga o último caractere da linha, e da tela.
///
/// O apagar precisa apagar na tela também, e não só no buffer. Uma tela que
/// mostra o que foi apagado é pior que nenhuma: ela afirma algo falso sobre o
/// que será executado.
///
/// `\u{8} \u{8}`, e não só `\u{8}`: o console da tela apaga a célula com o
/// primeiro, mas um terminal do outro lado da COM1 só volta o cursor, e o
/// espaço é o que cobre a letra nele.
fn apagar_em(console: Console, e: &mut Estado) {
    if e.tam > 0 {
        e.tam -= 1;
        e.bytes[e.tam] = 0;
        if !e.modo.secreto() {
            saida!(console, "\u{8} \u{8}");
        }
    }
}

/// Limpa o console físico e recomeça do topo, com a linha que estava sendo
/// digitada redesenhada no prompt.
///
/// É o que o botão da barra superior faz. O que estava digitado não se
/// perde: limpar a tela não é desistir do comando, e uma pessoa que apertou
/// o botão no meio de uma linha espera encontrá-la ali.
///
/// Tudo na seção crítica, pelo motivo escrito junto de [`ESTADOS`]: um
/// registro que chegasse entre a limpeza e o prompt seria desenhado por
/// [`por_cima`] contando com um prompt que ainda não existe.
pub fn limpar() {
    com_fisico(|e| {
        crate::tela::banner();
        if e.inicio.is_some() {
            prompt_em(Console::Fisico, e);
            redesenhar(e);
        }
    });
    crate::ui::mudou();
}

/// Desenha de novo o que está digitado no físico — nada, se é a senha.
fn redesenhar(e: &Estado) {
    if !e.modo.secreto() {
        crate::serial_print!("{}", e.texto());
    }
}

/// Onde o campo da linha de comando do físico começa na tela, em células,
/// se o interpretador estiver atendendo.
pub fn inicio_do_campo() -> Option<(u32, u32)> {
    com_fisico(|e| {
        let (coluna, linha) = e.inicio?;
        // Cada rolagem desde o prompt subiu o campo uma linha. Um campo que
        // subiu além do topo começa, para quem pergunta, na primeira linha:
        // o que saiu da tela não tem moldura.
        let subiu = crate::tela::console::rolagens().wrapping_sub(e.rolagens);
        Some((coluna, linha.saturating_sub(subiu)))
    })
}

/// O que está digitado agora no físico. Para a árvore semântica — que não
/// vê a senha: no lugar dela, nada.
pub fn com_valor<R>(f: impl FnOnce(&str) -> R) -> R {
    com_fisico(|e| {
        if e.modo.secreto() {
            f("")
        } else {
            f(e.texto())
        }
    })
}

/// O que a linha do físico está pedindo.
#[cfg(feature = "modo-teste")]
pub fn modo() -> Modo {
    com_fisico(|e| e.modo)
}

/// A sessão de quem está num console, se ainda vale. Uma sessão que acabou
/// por fora — revogada, a pessoa revogada — sai do console aqui, com o
/// aviso: o console volta a pedir o login.
pub fn sessao_valida(console: Console) -> Option<IdSessao> {
    let id = com_estado(console, |e| e.sessao).flatten()?;
    match crate::pessoas::sessao(id) {
        EstadoDaSessao::Ativa { .. } => Some(id),
        outro => {
            com_estado(console, |e| {
                if e.sessao == Some(id) {
                    e.sessao = None;
                }
            });
            let motivo = match outro {
                EstadoDaSessao::Encerrada(m) => match m {
                    crate::pessoas::Encerramento::Revogada => "a sessao foi revogada",
                    crate::pessoas::Encerramento::PessoaRevogada => "a pessoa foi revogada",
                    _ => "a sessao acabou",
                },
                _ => "a sessao acabou",
            };
            saidaln!(console, "{}; `login` para entrar de novo", motivo);
            None
        }
    }
}

/// A sessão de quem está num console agora, sem conferir se ainda vale.
/// Para a suíte.
#[cfg(feature = "modo-teste")]
pub fn sessao_do_console(console: Console) -> Option<IdSessao> {
    com_estado(console, |e| e.sessao).flatten()
}

/// Troca o que está na linha do físico, apagando o que havia e digitando o
/// novo.
///
/// É o `set_value` da árvore semântica. Passa pelo apagar e pelo digitar de
/// quem está na frente da máquina, caractere por caractere, para que a tela
/// termine igual ao que uma pessoa veria se tivesse digitado — inclusive onde
/// a linha quebra.
///
/// Recusa antes de mexer em qualquer coisa: um valor longo demais, ou com
/// algo que uma pessoa não conseguiria digitar, não apaga a linha que estava
/// lá. E a linha que pede o nome ou a senha não se edita por aqui: o login é
/// de quem está no teclado.
pub fn definir(valor: &str) -> Result<(), &'static str> {
    definir_pela_arvore_em(Console::Fisico, valor)
}

/// [`definir_em`], pela árvore: a regra da linha da pessoa conferida de
/// novo na seção que edita — nem escrever, nem esvaziar, nem a linha que
/// engole. Quem chama a conferiu antes ([`pode_definir`]) e contou a edição
/// na coordenação; entre as duas, a linha poderia ter mudado — fechado por
/// construção: o `ui.act` do físico roda no executor que consome as teclas,
/// e a corrida não se alcança.
fn definir_pela_arvore_em(console: Console, valor: &str) -> Result<(), &'static str> {
    let (aberto, inicio) =
        com_estado(console, |e| (e.aberto, e.inicio)).ok_or("console desconhecido")?;
    if !aberto || (console == Console::Fisico && inicio.is_none()) {
        return Err("a linha de comando nao esta atendendo");
    }
    if valor.len() > LINHA_MAX {
        return Err("o valor nao cabe na linha de comando");
    }
    if !valor.chars().all(aceito) {
        return Err(CARACTERE_QUE_NAO_SE_DIGITA);
    }
    com_estado(console, |e| {
        if pede_a_pessoa_em(e) {
            return Err(LINHA_DA_PESSOA);
        }
        while e.tam > 0 {
            apagar_em(console, e);
        }
        for c in valor.chars() {
            digitar_em(console, e, c);
        }
        Ok(())
    })
    .ok_or("console desconhecido")??;
    if console == Console::Fisico {
        crate::ui::mudou();
    }
    Ok(())
}

/// A recusa de quem edita, pela árvore, a linha que pede o nome ou uma
/// senha: o login e a troca da própria senha são de quem está no teclado.
pub const LINHA_DA_PESSOA: &str =
    "a linha esta pedindo o nome, uma senha ou um codigo de uma pessoa; so se digita pelo teclado";

/// E a de um agente que a confirma pela árvore.
pub const CONFIRMAR_A_LINHA_DA_PESSOA: &str = "a linha esta pedindo o nome, uma senha ou um codigo de uma pessoa; so se confirma pelo teclado";

/// A recusa de um valor com algo que uma pessoa não digita na linha — um
/// Enter, o Enter de um agente, um controle.
pub const CARACTERE_QUE_NAO_SE_DIGITA: &str =
    "o valor tem caracteres que nao se digitam na linha de comando";

fn definir_em(console: Console, valor: &str) -> Result<(), &'static str> {
    let (aberto, modo, inicio) =
        com_estado(console, |e| (e.aberto, e.modo, e.inicio)).ok_or("console desconhecido")?;
    if !aberto || (console == Console::Fisico && inicio.is_none()) {
        return Err("a linha de comando nao esta atendendo");
    }
    if valor.len() > LINHA_MAX {
        return Err("o valor nao cabe na linha de comando");
    }
    if !valor.chars().all(aceito) {
        return Err(CARACTERE_QUE_NAO_SE_DIGITA);
    }
    // Esvaziar a linha do login é o `APAGAR_A_LINHA` sem marca — o Ctrl-U de
    // quem digita —, e vale aqui; escrever nela, não. O que vem da árvore
    // passa por uma regra mais estrita — nem esvaziar —: na entrada, ver
    // [`pode_editar_pela_arvore`]; e, num Terminal, de novo quando o console
    // consome o que o programa digitou, marcado — ver [`pela_arvore`].
    if modo != Modo::Comando && !valor.is_empty() {
        return Err(LINHA_DA_PESSOA);
    }
    com_estado(console, |e| {
        while e.tam > 0 {
            apagar_em(console, e);
        }
        for c in valor.chars() {
            digitar_em(console, e, c);
        }
    });
    if console == Console::Fisico {
        crate::ui::mudou();
    }
    Ok(())
}

/// A linha do físico aceitaria este valor pela árvore — o `set_value`, e o
/// `cancel` com o valor vazio? A conferência de [`definir`], sem mudar
/// nada, e a regra da linha da pessoa — [`pode_editar_pela_arvore`]: quem
/// pede confere antes de pedir o arrendamento — ver [`crate::coordenacao`]
/// —, para uma recusa não arrendar a linha nem fazer a versão crescer.
pub fn pode_definir(valor: &str) -> Result<(), &'static str> {
    let (aberto, inicio) =
        com_estado(Console::Fisico, |e| (e.aberto, e.inicio)).unwrap_or((false, None));
    if !aberto || inicio.is_none() {
        return Err("a linha de comando nao esta atendendo");
    }
    pode_definir_em(Console::Fisico, valor)
}

/// A conferência do valor de um `set_value` na linha de `console` — a do
/// físico, ou a de um Terminal, que a árvore mostra como o campo da janela
/// dele: o valor cabe na linha, só tem o que uma pessoa digitaria nela, e a
/// linha não pede o que só a pessoa digita ([`pode_editar_pela_arvore`]).
///
/// No Terminal, o valor vai ao programa, que o digita no pseudo-terminal
/// caractere por caractere, pelo mesmo caminho das teclas: um `\n` dentro
/// dele seria o Enter da pessoa, e um caractere de
/// [`protocolo::usuario::terminal::confirmar_pelo_agente`], o Enter de outra
/// sessão — a da serial também. O `set_value` executaria a linha em nome de
/// outro. Por isso a regra do físico vale lá inteira: só passa o que se
/// digita.
pub fn pode_definir_em(console: Console, valor: &str) -> Result<(), &'static str> {
    if valor.len() > LINHA_MAX {
        return Err("o valor nao cabe na linha de comando");
    }
    if !valor.chars().all(aceito) {
        return Err(CARACTERE_QUE_NAO_SE_DIGITA);
    }
    pode_editar_pela_arvore(console)
}

/// A linha do físico aceitaria o `confirm` de `origem`? Um agente não
/// confirma a linha do login — [`pode_confirmar_pela_arvore`] —, e ninguém
/// confirma outra linha enquanto um comando espera.
pub fn pode_confirmar(origem: Origem) -> Result<(), &'static str> {
    pode_confirmar_pela_arvore(Console::Fisico, origem)?;
    if ocupado(Console::Fisico) {
        return Err(CONSOLE_OCUPADO);
    }
    Ok(())
}

/// A recusa de um `confirm` com o console esperando um comando.
pub const CONSOLE_OCUPADO: &str = "o console espera um comando que ainda nao respondeu";

/// A linha de `console` pede o que só a pessoa no teclado digita — o nome,
/// uma senha, um passo da cerimônia de pareamento —, e não um comando? Ou
/// ainda engole o resto de uma senha (ver [`engolir`]): a linha não deixou
/// de ser a da senha até o Enter da Pessoa, e a árvore não a edita nem a
/// confirma por um agente nesse meio-tempo.
fn pede_a_pessoa(console: Console) -> bool {
    com_estado(console, |e| pede_a_pessoa_em(e)).unwrap_or(false)
}

/// [`pede_a_pessoa`], com o estado na mão: a mesma regra, para quem a
/// confere na seção que edita a linha — ver [`pela_arvore`].
fn pede_a_pessoa_em(e: &Estado) -> bool {
    e.modo != Modo::Comando || e.engolindo
}

/// A regra da linha da pessoa, para quem a **edita** pela árvore semântica
/// — o `set_value` e o `cancel` de [`crate::ui`]: a linha que pede o nome,
/// uma senha ou um passo da cerimônia de pareamento só se edita pelo
/// teclado. Nem para esvaziar: apagar o que a pessoa digitou é editar, e a
/// edição arrendaria a linha a quem a pediu — as teclas dela, em seguida,
/// seriam `CONFLICT`.
///
/// Uma regra só, para as duas linhas que a árvore alcança: a do físico, por
/// [`pode_definir`], e a de cada Terminal, que a árvore mostra como o campo
/// da janela dele e que o programa digita no pseudo-terminal. Ela vale
/// quando a ação entra, em `crate::ui` — com quem pediu conhecido, e antes
/// do arrendamento do campo —; e, num Terminal, de novo quando o console
/// consome o que o programa digitou, marcado, contra a linha de agora: ver
/// [`pela_arvore`].
pub fn pode_editar_pela_arvore(console: Console) -> Result<(), &'static str> {
    if pede_a_pessoa(console) {
        return Err(LINHA_DA_PESSOA);
    }
    Ok(())
}

/// E para quem a **confirma**: um agente não confirma a linha que pede o
/// nome, uma senha ou um passo da cerimônia — entraria por alguém. A
/// pessoa, pela árvore, confirma como no Enter. A mesma para o físico, por
/// [`pode_confirmar`], e para cada Terminal — ver [`pode_editar_pela_arvore`].
pub fn pode_confirmar_pela_arvore(console: Console, origem: Origem) -> Result<(), &'static str> {
    if let Origem::Agente(_) = origem
        && pede_a_pessoa(console)
    {
        return Err(CONFIRMAR_A_LINHA_DA_PESSOA);
    }
    Ok(())
}

/// Quantos Enter de agente pedidos pela árvore um console guarda à espera
/// do pseudo-terminal. Com todos ocupados, o `confirm` seguinte é recusado:
/// despejar o mais velho perderia o Enter de quem já ouviu que o pedido foi
/// aceito.
const ENTER_PEDIDOS: usize = 4;

/// A recusa do Enter de um agente com os pedidos do console cheios.
pub const ENTER_DEMAIS: &str = "o console ja espera o Enter de agentes demais";

/// A recusa do Enter de um agente que não está mais na sessão de onde
/// pediu — a conexão acabou, ou a sessão é de outra.
pub const AGENTE_FORA_DA_SESSAO: &str = "o agente nao esta mais na sessao de onde pediu";

/// A recusa, no consumo, da edição de uma pessoa que não está mais na
/// sessão de onde pediu — ela saiu, a sessão foi revogada, ou a pessoa.
pub const PESSOA_FORA_DA_SESSAO: &str = "a pessoa nao esta mais na sessao de onde pediu";

/// A recusa da reserva de uma edição de pessoa sem a sessão dela: o
/// consumo não teria o que conferir.
pub const PESSOA_SEM_SESSAO: &str = "a edicao de uma pessoa vai com a sessao dela";

/// Reserva no console o Enter que o `confirm` da sessão `sessao` no campo
/// do Terminal dele vai digitar: quando o pseudo-terminal o trouxer, ele
/// vale — uma vez —, se quem o pediu ainda estiver na mesma conexão.
/// `chave` é a que o gate decidiu para o pedido: a sessão tem de ser ainda
/// a dela. Quem chama reserva antes da conta da coordenação, e desiste com
/// [`desistir_do_enter_do_agente`] se o `confirm` não chega ao programa.
///
/// O Enter de um agente chega ao interpretador como um caractere que diz a
/// sessão (ver [`protocolo::usuario::terminal::confirmar_pelo_agente`]), pelo
/// pseudo-terminal que o Terminal escreve. Sem o pedido, o número dentro do
/// caractere seria a autoridade: quem escreve no pseudo-terminal confirmaria
/// a linha em nome de qualquer sessão. E o pedido não guarda só o número: o
/// número é a vaga do transporte, que outra conexão ocupa quando esta acaba
/// — a mesma chave, outra, ou um aperto do TCP repetido por quem o capturou
/// ([`Amarrada`]). O Enter que chega para uma conexão que já não é a de
/// quem pediu não confirma nada.
///
/// Recusa, como no físico, com o console esperando um comando — o Enter
/// ficaria na fila até a espera acabar, e quem estivesse na sessão então
/// não é quem pediu —, com a sessão que não é mais de quem pediu, e com os
/// pedidos cheios.
pub fn pedir_enter_do_agente(
    console: Console,
    sessao: u8,
    chave: Option<[u8; 32]>,
) -> Result<Amarrada, &'static str> {
    if ocupado(console) {
        return Err(CONSOLE_OCUPADO);
    }
    let amarrada = Amarrada::agora(sessao)
        .filter(|a| a.chave() == chave)
        .ok_or(AGENTE_FORA_DA_SESSAO)?;
    // Os pedidos de conexões que acabaram não ocupam lugar: conferidos fora
    // da trava do estado, que não toma a das sessões.
    esquecer_enter_de_outras_conexoes(console);
    com_estado(console, |e| {
        let vaga = e
            .enter_pedido
            .iter_mut()
            .find(|v| v.is_none())
            .ok_or(ENTER_DEMAIS)?;
        *vaga = Some(amarrada);
        Ok(amarrada)
    })
    .unwrap_or(Err("console desconhecido"))
}

/// Desfaz um [`pedir_enter_do_agente`]: o `confirm` não chegou ao programa.
pub fn desistir_do_enter_do_agente(console: Console, amarrada: Amarrada) {
    com_estado(console, |e| {
        if let Some(v) = e
            .enter_pedido
            .iter_mut()
            .rev()
            .find(|v| **v == Some(amarrada))
        {
            *v = None;
        }
    });
}

/// O número da próxima reserva de [`reservar_edicao_da_arvore`]: uma por
/// edição, desde o boot.
static EDICOES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Reserva no console a edição que a interface vai entregar ao Terminal
/// dele — o `set_value` ou o `cancel` de `origem` no `campo` da janela —, e
/// devolve o número dela.
///
/// O programa digita a edição no pseudo-terminal marcada (ver
/// `protocolo::usuario::terminal::da_arvore`), e o console a consome depois
/// — com o Enter da Pessoa que já ia a caminho, talvez, na frente. Ali, em
/// [`pela_arvore`], ela é conferida de novo pela regra da linha da pessoa,
/// e a reserva diz o que a edição fez no arrendamento do campo: na recusa,
/// o que ela mesma tomou sai.
///
/// Quem chama reserva antes da conta da coordenação — as reservas cheias
/// recusam a ação sem arrendar o campo —, anota o que a conta fez com
/// [`anotar_a_edicao_da_arvore`], e desiste com
/// [`desistir_da_edicao_da_arvore`] se a edição não chega ao programa.
///
/// As reservas são a ordem em que o console espera as edições: o apagar
/// marcado que começa cada uma toma a mais velha. Escrita por conta
/// própria, a marca de quem tem o pseudo-terminal toma, no máximo, a
/// reserva de uma edição que a interface entregou a ele — a que ele mesmo
/// digitaria. Sem reserva, a marca não solta nada.
///
/// A edição de um agente é amarrada à conexão de onde ele pediu e à chave
/// que o gate decidiu — a do `titular` —, como o Enter dele: quem já não
/// está nela é recusado aqui, antes da conta, e a edição de quem saiu
/// depois é descartada quando o console a consome (o achado 7 do adversário
/// do passo 1). A da pessoa guarda a sessão e a pessoa do `titular`, e a
/// de uma pessoa sem ele é recusada aqui: no consumo, a sessão tem de
/// estar ainda aberta e ser dela, e a edição da pessoa que saiu, da sessão
/// revogada ou da pessoa revogada é descartada, como a do agente que saiu
/// (o achado 1 do adversário do passo 1c). No consumo, a contenção é
/// perguntada também: a edição de quem foi contido com ela a caminho — o
/// agente suspenso, a credencial dele ou a da pessoa — é descartada, como o
/// pedido em curso que a contenção recusa no ponto de commit (o achado 2 do
/// adversário do passo 1b).
pub fn reservar_edicao_da_arvore(
    console: Console,
    campo: u32,
    origem: Origem,
    acao: crate::ui::Acao,
    titular: Option<politica::arrendamento::Titular>,
) -> Result<u64, &'static str> {
    use politica::arrendamento::Titular;
    // Fora da trava do estado, que não toma a das sessões.
    let quem = match origem {
        Origem::Agente(sessao) => {
            let chave = match titular {
                Some(Titular::Agente { chave, .. }) => chave,
                _ => None,
            };
            QuemPediu::Agente(
                Amarrada::agora(sessao)
                    .filter(|a| a.chave() == chave)
                    .ok_or(AGENTE_FORA_DA_SESSAO)?,
            )
        }
        Origem::Pessoa => match titular {
            Some(Titular::Pessoa { sessao, pessoa }) => {
                QuemPediu::Pessoa(IdSessao(sessao), sigilo::pessoas::IdPessoa(pessoa))
            }
            _ => return Err(PESSOA_SEM_SESSAO),
        },
    };
    let numero = EDICOES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    com_estado(console, |e| {
        let vaga = e
            .edicoes
            .iter_mut()
            .find(|v| v.is_none())
            .ok_or(EDICOES_DEMAIS)?;
        *vaga = Some(EdicaoPedida {
            numero,
            campo,
            origem,
            acao,
            quem,
            rastro: None,
            recusada: false,
        });
        Ok(numero)
    })
    .unwrap_or(Err("console desconhecido"))
}

/// Anota na reserva `numero` o que a conta da coordenação fez no campo —
/// ver [`crate::coordenacao::Rastro`]. Uma reserva que o console já tomou,
/// ou que se foi com ele, fica como está. A que a linha recusou com ela a
/// caminho, antes de a conta ser anotada — a virada noutro núcleo, entre a
/// conferência da entrada e a conta —, solta aqui o que tomou, pela regra
/// de [`recusar_as_edicoes_a_caminho`].
pub fn anotar_a_edicao_da_arvore(
    console: Console,
    numero: u64,
    rastro: crate::coordenacao::Rastro,
) {
    let soltar = com_estado(console, |e| {
        let p = e
            .edicoes
            .iter_mut()
            .flatten()
            .find(|p| p.numero == numero)?;
        p.rastro = Some(rastro);
        if !p.recusada {
            return None;
        }
        let campo = p.campo;
        let continua = rastro.tomou() || e.recusadas == Some(rastro.antes());
        e.recusadas = continua.then(|| rastro.depois());
        continua.then_some((campo, rastro))
    })
    .flatten();
    if let Some((campo, rastro)) = soltar {
        soltar_o_que_ela_deixou(
            console,
            campo,
            &rastro,
            crate::coordenacao::PorQueSolta::LinhaDaPessoa,
        );
    }
}

/// Desfaz um [`reservar_edicao_da_arvore`] antes da conta: a coordenação
/// recusou a edição, e ela não mudou nada no campo.
pub fn desistir_da_edicao_da_arvore(console: Console, numero: u64) {
    com_estado(console, |e| {
        for v in e.edicoes.iter_mut() {
            if v.is_some_and(|p| p.numero == numero) {
                *v = None;
            }
        }
    });
}

/// A edição `numero`, contada pela coordenação, não chegou ao programa — o
/// aviso não foi entregue —: a reserva sai, e o arrendamento que ela tomou
/// não fica com quem a pediu (o achado 1 do adversário do passo 1). A
/// versão que a conta fez crescer fica.
///
/// - Se ela tomou o arrendamento, ele sai já, se o campo ainda está
///   exatamente como ela o deixou (`PorQueSolta::NaoChegou`).
/// - Se só o renovou — o campo já era de quem pediu, por uma edição antes
///   dela —, a sequência das recusadas não pode se quebrar nela: o console
///   nunca vai consumi-la, e a edição seguinte não começaria onde a
///   anterior deixou o campo. Então a renovação vai para a edição que ela
///   continuou — a reserva a caminho que deixou o campo onde ela começou
///   ([`crate::coordenacao::Rastro::seguida_de`]) —, e, recusada essa, o
///   arrendamento que a sequência tomou sai com o estado que esta deixou;
///   aceita no consumo, numa linha de comando, a renovação fica com ela.
/// - Ou para a sequência das já recusadas, se é dela que ela começou: aí
///   nada sai agora, e o arrendamento fica até vencer, ou até a recusa de
///   uma edição seguinte da sequência. Esse ramo não se alcança: a anterior
///   teria de ser recusada entre a conta desta e a entrega dela, e a
///   reserva, a conta e a entrega rodam num passo só do executor; a recusa
///   no consumo e no Enter, no mesmo executor; e a do aviso da cerimônia, de
///   outro fio, nunca leva uma linha de comando a pedir a pessoa.
///
/// Se a janela do Terminal fechou no meio — ele morreu —, o console fechou
/// com ela, as reservas saíram, e não há o que achar aqui: o arrendamento
/// fica até vencer, num elemento que não volta.
pub fn edicao_nao_entregue(console: Console, numero: u64) {
    let soltar = com_estado(console, |e| {
        let i = e
            .edicoes
            .iter()
            .position(|v| v.is_some_and(|p| p.numero == numero))?;
        let p = e.edicoes[i].take()?;
        let rastro = p.rastro?;
        if rastro.tomou() {
            return Some((p.campo, rastro));
        }
        let anterior = e
            .edicoes
            .iter_mut()
            .flatten()
            .filter(|q| {
                !q.recusada
                    && q.numero < numero
                    && q.rastro.is_some_and(|r| r.depois() == rastro.antes())
            })
            .max_by_key(|q| q.numero);
        match anterior {
            Some(q) => q.rastro = q.rastro.and_then(|r| r.seguida_de(rastro)),
            None if e.recusadas == Some(rastro.antes()) => e.recusadas = Some(rastro.depois()),
            None => {}
        }
        None
    })
    .flatten();
    if let Some((campo, rastro)) = soltar {
        soltar_o_que_ela_deixou(
            console,
            campo,
            &rastro,
            crate::coordenacao::PorQueSolta::NaoChegou,
        );
    }
}

/// Solta o arrendamento que a edição do `rastro` deixou no `campo`, se ele
/// ainda é exatamente o dela — ver
/// [`crate::coordenacao::soltar_o_da_edicao_recusada`] —; solto, a sequência
/// das recusadas do console acaba: não há o que a seguinte continue.
fn soltar_o_que_ela_deixou(
    console: Console,
    campo: u32,
    rastro: &crate::coordenacao::Rastro,
    motivo: crate::coordenacao::PorQueSolta,
) -> bool {
    let solto = crate::coordenacao::soltar_o_da_edicao_recusada(
        &crate::coordenacao::recurso(campo),
        rastro,
        motivo,
    );
    if solto {
        com_estado(console, |e| e.recusadas = None);
    }
    solto
}

/// A linha de `console` passou a pedir a pessoa — o Enter do `login`, da
/// `senha`, do `aceitar` ou do `parear`; o aviso da cerimônia confere o
/// mesmo, mas hoje nunca leva uma linha que pede um comando a pedir a
/// pessoa: a cerimônia começa pelo Enter, e o engolir só começa de uma
/// linha que já pedia a senha. As edições da árvore a caminho — reservadas
/// e ainda não consumidas — seriam recusadas quando chegassem, pela regra
/// da linha da pessoa, e o arrendamento delas só sairia ali: a tecla da
/// Pessoa, nesse meio-tempo, seria `CONFLICT`. São recusadas aqui, todas,
/// na ordem (o achado 2 do adversário do passo 1): o arrendamento que a
/// sequência delas tomou sai já, pela regra de sempre — o estado exato, e
/// cada uma começando onde a anterior deixou o campo —, e o que chegar
/// marcado delas depois é descartado, mesmo que a linha volte a pedir um
/// comando. Uma linha no log por edição, como a recusa no consumo.
///
/// O que fica: a tecla da Pessoa entre a entrada da edição e o consumo do
/// Enter, com a linha ainda pedindo um comando, coordenada na janela contra
/// o arrendamento de quem editou — a coordenação no consumo, como a do
/// físico, é uma mudança de desenho da família da DT-1 (a decisão sobre o
/// Terminal e o teclado da Pessoa, no README), pendente.
fn recusar_as_edicoes_a_caminho(console: Console) {
    let Some((recusadas, soltar)) = com_estado(console, |e| {
        let mut ordem: alloc::vec::Vec<usize> = (0..EDICOES_PEDIDAS)
            .filter(|&i| e.edicoes[i].is_some_and(|p| !p.recusada))
            .collect();
        ordem.sort_by_key(|&i| e.edicoes[i].map_or(u64::MAX, |p| p.numero));
        let mut quem = alloc::vec::Vec::new();
        let mut soltar = None;
        for i in ordem {
            let Some(p) = e.edicoes[i].as_mut() else {
                continue;
            };
            p.recusada = true;
            quem.push((p.origem, p.acao, p.campo));
            // A sem a conta anotada solta quando a anotação chegar.
            let Some(r) = p.rastro else {
                continue;
            };
            let continua = r.tomou() || e.recusadas == Some(r.antes());
            e.recusadas = continua.then(|| r.depois());
            soltar = continua.then_some((p.campo, r));
        }
        (quem, soltar)
    }) else {
        return;
    };
    if let Some((campo, rastro)) = soltar {
        soltar_o_que_ela_deixou(
            console,
            campo,
            &rastro,
            crate::coordenacao::PorQueSolta::LinhaDaPessoa,
        );
    }
    for (origem, acao, campo) in recusadas {
        crate::log_info!(
            "ui",
            "{}: {} no elemento {} recusado no console: {}",
            origem,
            acao.nome(),
            campo,
            LINHA_DA_PESSOA
        );
    }
}

/// Se quem pediu uma edição já não vale, quando o console a consome: o
/// agente que não está mais na conexão de onde pediu, com a chave que o
/// gate decidiu ([`AGENTE_FORA_DA_SESSAO`]); a pessoa cuja sessão acabou ou
/// é de outra — ela saiu, a sessão foi revogada, a pessoa foi revogada
/// ([`PESSOA_FORA_DA_SESSAO`]); ou o agente, a credencial dele ou a da
/// pessoa, contidos — a mesma pergunta que a contenção faz ao pedido em
/// curso no ponto de commit ([`crate::contencao::recusa_de`]), com o motivo
/// dela. A sessão vem antes da contenção: a contenção da pessoa é procurada
/// pela sessão, e a revogação esquece a suspensão (o achado 1 do adversário
/// do passo 1c). Toma as travas das sessões, das pessoas e da contenção:
/// chamada fora da do estado.
fn quem_ja_nao_vale(quem: QuemPediu) -> Option<(crate::coordenacao::PorQueSolta, &'static str)> {
    use crate::autorizacao::Autoridade;
    use crate::coordenacao::PorQueSolta;
    let autoridade = match quem {
        QuemPediu::Agente(a) => {
            if !a.vale() {
                return Some((PorQueSolta::ForaDaSessao, AGENTE_FORA_DA_SESSAO));
            }
            Autoridade::Sessao {
                sessao: a.sessao(),
                chave: a.chave(),
            }
        }
        QuemPediu::Pessoa(sessao, pessoa) => {
            let ainda_dela = match crate::pessoas::sessao(sessao) {
                EstadoDaSessao::Ativa { pessoa: dona, .. } => dona == pessoa,
                _ => false,
            };
            if !ainda_dela {
                return Some((PorQueSolta::ForaDaSessao, PESSOA_FORA_DA_SESSAO));
            }
            Autoridade::Pessoa { sessao }
        }
    };
    crate::contencao::recusa_de(None, autoridade).map(|(_, motivo)| (PorQueSolta::Contido, motivo))
}

/// Tira das reservas do console a mais velha — a da edição que o apagar
/// marcado começa.
fn tirar_a_reserva(e: &mut Estado) -> Option<EdicaoPedida> {
    let vaga = e
        .edicoes
        .iter_mut()
        .filter(|v| v.is_some())
        .min_by_key(|v| v.as_ref().map_or(u64::MAX, |p| p.numero))?;
    vaga.take()
}

/// O que um caractere marcado da árvore fez no console — ver
/// [`pela_arvore`].
enum DaArvore {
    /// Entrou na linha, como entraria sem marca numa linha de comando.
    Editado,
    /// Não coube: a linha passaria do teto.
    NaoCoube,
    /// Descartado: a edição já tinha sido recusada.
    Descartado,
    /// Recusado agora — a primeira recusa da edição —, pela regra da linha
    /// da pessoa ou porque quem a pediu saiu da sessão: quem a pediu, o quê
    /// e em que campo, se ela tinha reserva; o rastro do arrendamento que
    /// sai, se é o de edições recusadas; e o porquê.
    Recusado {
        quem: Option<(Origem, crate::ui::Acao, u32)>,
        soltar: Option<crate::coordenacao::Rastro>,
        motivo: crate::coordenacao::PorQueSolta,
        texto: &'static str,
    },
}

/// Um caractere que o Terminal digitou pela árvore — o apagar da linha que
/// começa um `set_value` ou um `cancel`, ou uma letra do texto —, já sem a
/// marca (ver `protocolo::usuario::terminal::da_arvore`).
///
/// # A regra, onde o caractere é consumido
///
/// A interface confere a regra da linha da pessoa quando a ação entra
/// ([`pode_editar_pela_arvore`]) e recusa cedo, com o motivo, sem arrendar o
/// campo. Mas entre a entrada e o console há o programa e a fila do
/// pseudo-terminal, e o Enter da Pessoa que já ia a caminho pode, nesse
/// meio-tempo, fazer a linha pedir o nome, uma senha ou um passo do
/// pareamento. Aqui a mesma regra ([`pede_a_pessoa`]) é conferida contra a
/// linha de agora, na mesma seção que a edita: na linha da pessoa, o que
/// veio da árvore é descartado — sem eco, fora da linha, da árvore e do
/// histórico, e sem passar pela coordenação. E a edição inteira: recusada
/// uma letra, as seguintes também, mesmo que a linha volte a pedir um
/// comando no meio — o resto dela não vai à frente do que a Pessoa digitar.
/// A recusa vai ao log, uma linha por edição e sem o texto: a linha pode
/// ser a de uma senha.
///
/// # O arrendamento que ela tomou
///
/// Uma ação recusada não arrenda o campo. Na primeira recusa, o console
/// solta o arrendamento que a própria edição tomou quando entrou — e só ele:
/// se depois dela o campo mudou por qualquer outro caminho — outro titular o
/// arrendou, um `ui.claim` o renovou, uma tecla o editou —, nada se solta
/// ([`crate::coordenacao::soltar_o_da_edicao_recusada`]). Uma sequência de
/// edições da árvore em voo, todas recusadas, conta como uma: o
/// arrendamento que a primeira tomou e as seguintes só renovaram sai na
/// recusa da última — cada uma começou exatamente onde a anterior deixou o
/// campo, conferido pelo estado inteiro dele, e nada mais o mexeu.
///
/// # A marca não é autoridade
///
/// Ela só aponta a edição que a interface reservou, a mais velha do console
/// ([`reservar_edicao_da_arvore`]): o apagar marcado começa uma edição e toma
/// a reserva; as letras marcadas seguintes são dela, até o que vier sem
/// marca. O que vem marcado sem reserva passa pela mesma regra e não solta
/// nada; o que vem sem marca chega como a tecla da Pessoa, como sempre —
/// quem pode ser "o Terminal" é a decisão pendente do nome `terminal`. No
/// console físico não há o que marcar: a árvore edita a linha dele direto,
/// em [`definir`], e o que chegasse marcado é descartado.
fn pela_arvore(console: Console, c: char) {
    use crate::coordenacao::PorQueSolta;
    use protocolo::usuario::terminal::APAGAR_A_LINHA;
    if console == Console::Fisico {
        return;
    }
    // O apagar marcado começa uma edição: a de quem já não vale — o agente
    // que não está na conexão de onde pediu, com a chave que o gate decidiu;
    // a pessoa fora da sessão de onde pediu; o agente ou a pessoa contidos —
    // é descartada. Conferido aqui, fora da
    // trava do estado, que não toma a das sessões nem a da contenção, como o
    // Enter do agente. A reserva que ele vai tomar é a mais velha, e só o
    // executor as tira e põe.
    let ja_nao_vale = if c == APAGAR_A_LINHA {
        com_estado(console, |e| {
            e.edicoes
                .iter()
                .flatten()
                .min_by_key(|p| p.numero)
                .filter(|p| !p.recusada)
                .map(|p| (p.numero, p.quem))
        })
        .flatten()
        .and_then(|(numero, quem)| quem_ja_nao_vale(quem).map(|motivo| (numero, motivo)))
    } else {
        None
    };
    let Some(feito) = com_estado(console, |e| {
        if c == APAGAR_A_LINHA || e.na_arvore.is_none() {
            let pedida = if c == APAGAR_A_LINHA {
                tirar_a_reserva(e)
            } else {
                None
            };
            // A recusada com ela a caminho: descartada, sem outra linha no
            // log — a recusa já foi dita, e o arrendamento já saiu.
            let ja_recusada = pedida.is_some_and(|p| p.recusada);
            e.na_arvore = Some(EmCurso {
                pedida,
                recusada: ja_recusada,
            });
        }
        let recusadas = e.recusadas;
        let pede = pede_a_pessoa_em(e);
        let Some(em_curso) = e.na_arvore.as_mut() else {
            return DaArvore::Descartado;
        };
        if em_curso.recusada {
            return DaArvore::Descartado;
        }
        let saiu = ja_nao_vale
            .filter(|(numero, _)| em_curso.pedida.is_some_and(|p| p.numero == *numero))
            .map(|(_, motivo)| motivo);
        if pede || saiu.is_some() {
            em_curso.recusada = true;
            let pedida = em_curso.pedida;
            // O arrendamento que sai: o que esta edição tomou, ou o de uma
            // sequência de recusadas que ela continua — começou onde a
            // anterior deixou o campo.
            let soltar = pedida
                .and_then(|p| p.rastro)
                .filter(|r| r.tomou() || recusadas == Some(r.antes()));
            // O que veio sem reserva não é edição de ninguém: não começa nem
            // corta a sequência.
            if pedida.is_some() {
                e.recusadas = soltar.map(|r| r.depois());
            }
            let (motivo, texto) = match saiu {
                Some(quem) if !pede => quem,
                _ => (PorQueSolta::LinhaDaPessoa, LINHA_DA_PESSOA),
            };
            return DaArvore::Recusado {
                quem: pedida.map(|p| (p.origem, p.acao, p.campo)),
                soltar,
                motivo,
                texto,
            };
        }
        if c == APAGAR_A_LINHA {
            while e.tam > 0 {
                apagar_em(console, e);
            }
            DaArvore::Editado
        } else if digitar_em(console, e, c) {
            DaArvore::Editado
        } else {
            DaArvore::NaoCoube
        }
    }) else {
        return;
    };
    match feito {
        DaArvore::Recusado {
            quem,
            soltar,
            motivo,
            texto,
        } => {
            if let (Some((_, _, campo)), Some(rastro)) = (quem, soltar) {
                soltar_o_que_ela_deixou(console, campo, &rastro, motivo);
            }
            match quem {
                // A recusa da linha, no formato da recusa na entrada (ver
                // `crate::ui::agir_com_versao`), e sem o texto: a linha pode
                // ser a de uma senha. O arrendamento solto vai à auditoria,
                // como o implícito foi quando a edição o tomou.
                Some((origem, acao, campo)) => crate::log_info!(
                    "ui",
                    "{}: {} no elemento {} recusado no console: {}",
                    origem,
                    acao.nome(),
                    campo,
                    texto
                ),
                None => crate::log_warn!(
                    "console",
                    "{}: o que veio marcado da arvore sem reserva chegou a linha da pessoa; descartado",
                    console.texto()
                ),
            }
        }
        DaArvore::NaoCoube => {
            com_estado(console, |e| {
                saidaln!(console);
                saidaln!(console, "linha longa demais; ate {} caracteres", LINHA_MAX);
                e.zerar();
                prompt_em(console, e);
            });
        }
        DaArvore::Editado | DaArvore::Descartado => {}
    }
}

/// Tira dos pedidos do console os de conexões que acabaram.
fn esquecer_enter_de_outras_conexoes(console: Console) {
    let pedidos = com_estado(console, |e| e.enter_pedido).unwrap_or([None; ENTER_PEDIDOS]);
    for velho in pedidos.into_iter().flatten().filter(|a| !a.vale()) {
        com_estado(console, |e| {
            for v in e.enter_pedido.iter_mut().filter(|v| **v == Some(velho)) {
                *v = None;
            }
        });
    }
}

/// O que o Enter de um agente achou nos pedidos do console.
enum Tomado {
    /// Um pedido da sessão, da conexão de quem o pediu: vale.
    Valido,
    /// Só pedidos da sessão de conexões que acabaram: tirados, e nada vale.
    DeOutraConexao,
    /// Nenhum pedido da sessão.
    Nenhum,
}

/// Tira um Enter pedido da sessão `sessao` que ainda valha, e os dela que
/// são de conexões que acabaram.
fn tomar_enter_pedido(console: Console, sessao: u8) -> Tomado {
    let pedidos = com_estado(console, |e| e.enter_pedido).unwrap_or([None; ENTER_PEDIDOS]);
    let da_sessao = || {
        pedidos
            .into_iter()
            .flatten()
            .filter(move |a| a.sessao() == sessao)
    };
    if da_sessao().next().is_none() {
        return Tomado::Nenhum;
    }
    let valido = da_sessao().find(|a| a.vale());
    com_estado(console, |e| {
        for v in e.enter_pedido.iter_mut() {
            if v.is_some_and(|a| a.sessao() == sessao && Some(a) != valido) {
                *v = None;
            }
        }
        match valido.and_then(|a| e.enter_pedido.iter_mut().find(|v| **v == Some(a))) {
            Some(v) => {
                *v = None;
                Tomado::Valido
            }
            None => Tomado::DeOutraConexao,
        }
    })
    .unwrap_or(Tomado::Nenhum)
}

/// Executa a linha do físico, como o Enter. É o `confirm` da árvore.
///
/// Devolve o nome do comando que foi executado, vazio se a linha estava
/// vazia. Um agente não confirma a linha do login.
pub fn confirmar(origem: Origem) -> alloc::string::String {
    confirmar_em(Console::Fisico, origem)
}

/// Confirma a linha de `console`, como o Enter de `origem` — e, se ela
/// passou a pedir a pessoa com isso (o `login`, a `senha`, o `aceitar`, o
/// `parear`), recusa as edições da árvore a caminho: ver
/// [`recusar_as_edicoes_a_caminho`].
fn confirmar_em(console: Console, origem: Origem) -> alloc::string::String {
    let antes = pede_a_pessoa(console);
    let nome = confirmar_a_linha(console, origem);
    if !antes && pede_a_pessoa(console) {
        recusar_as_edicoes_a_caminho(console);
    }
    nome
}

fn confirmar_a_linha(console: Console, origem: Origem) -> alloc::string::String {
    let Some((modo, engolindo)) = com_estado(console, |e| (e.modo, e.engolindo)) else {
        return alloc::string::String::new();
    };
    // Com o console engolindo o resto de uma senha, confirmar é o Enter que
    // acaba o engolir, e nada se executa — ver [`engolir`]. A pessoa que
    // confirma a linha do físico pela árvore confirma como no Enter; um
    // agente, não: a árvore o recusa nessa linha ([`pede_a_pessoa`]), e se
    // chegar aqui numa corrida, nada acontece.
    if engolindo {
        if origem == Origem::Pessoa {
            engolir(console, '\n');
        }
        return alloc::string::String::new();
    }
    // Um comando de cada vez: o seguinte só depois que o suspenso responder.
    if ocupado(console) {
        crate::log_warn!(
            "console",
            "{}: a linha nao foi confirmada; um comando ainda espera",
            console.texto()
        );
        return alloc::string::String::new();
    }
    if modo != Modo::Comando {
        if let Origem::Agente(_) = origem {
            return alloc::string::String::new();
        }
        if modo.da_troca() {
            trocar_passo(console);
            return alloc::string::String::from("senha");
        }
        if modo.do_pareamento() {
            parear_passo(console, modo);
            return alloc::string::String::from("pareamento");
        }
        entrar_passo(console);
        return alloc::string::String::from("login");
    }
    let mut copia = [0u8; LINHA_MAX];
    // O campo deixa de existir enquanto o comando roda, e volta com o prompt
    // seguinte. É o que diz a [`por_cima`] que a linha na tela já não está em
    // edição — a saída do comando vem depois dela, e não por cima.
    let Some(tam) = com_estado(console, |e| {
        let tam = e.tam;
        copia[..tam].copy_from_slice(&e.bytes[..tam]);
        e.zerar();
        e.inicio = None;
        e.executando = true;
        saidaln!(console);
        tam
    }) else {
        return alloc::string::String::new();
    };
    let linha = core::str::from_utf8(&copia[..tam]).unwrap_or("");
    let r = match executar(console, linha, origem, true) {
        // O comando suspendeu: o console espera por ele, sem prompt, e o
        // interpretador o executa de novo quando a espera acabar.
        (nome, Some(espera)) => {
            if !suspender(console, linha, origem, espera) {
                mostrar_prompt(console);
            }
            nome
        }
        (nome, None) => {
            com_estado(console, |e| e.executando = false);
            mostrar_prompt(console);
            nome
        }
    };
    com_estado(console, |e| e.executando = false);
    r
}

/// Guarda o comando que suspendeu no console, e acorda o interpretador:
/// quem confirmou pode ter sido outra tarefa — um agente, pela árvore —, e
/// é a tarefa do interpretador que espera pela conexão. O de um agente vai
/// amarrado à conexão dele; se ele já saiu dela, não há o que guardar, e
/// devolve falso — a espera é largada.
fn suspender(
    console: Console,
    linha: &str,
    origem: Origem,
    espera: crate::rede::espera::Espera,
) -> bool {
    let (Some(i), Some(abertura)) = (indice(console), com_estado(console, |e| e.abertura)) else {
        return false;
    };
    let amarrada = match origem {
        Origem::Agente(sessao) => match Amarrada::agora(sessao) {
            Some(a) => Some(a),
            None => return false,
        },
        Origem::Pessoa => None,
    };
    let mut texto = politica::sigiloso::Texto::novo();
    texto.acrescentar(linha.as_bytes());
    let anterior = crate::arch::sem_interrupcoes(|| {
        SUSPENSOS.lock()[i].replace(Suspenso {
            abertura,
            linha: texto,
            origem,
            amarrada,
            espera,
        })
    });
    // Não há: um console ocupado não confirma outra linha. Se houvesse, a
    // espera dele é desarmada aqui, fora da trava.
    drop(anterior);
    crate::teclado::despertar_o_interpretador();
    true
}

/// Só para a suíte: põe `linha` na linha do console e a confirma, como a
/// pessoa no Enter; devolve o nome do comando executado — vazio se nada
/// foi —, e deixa a linha vazia.
#[cfg(feature = "modo-teste")]
pub fn confirmar_de_teste(console: Console, linha: &str) -> alloc::string::String {
    let _ = definir_em(console, linha);
    let nome = confirmar_em(console, Origem::Pessoa);
    let _ = definir_em(console, "");
    nome
}

/// Desenha o prompt do modo de agora.
fn mostrar_prompt(console: Console) {
    com_estado(console, |e| {
        if e.aberto {
            prompt_em(console, e);
        }
    });
    if console == Console::Fisico {
        crate::ui::mudou();
    }
}

/// O Enter no meio do login: o nome vira a pergunta da senha; a senha vira
/// a conferência.
fn entrar_passo(console: Console) {
    let Some(i) = indice(console) else {
        return;
    };
    let modo = com_estado(console, |e| e.modo).unwrap_or(Modo::Comando);
    match modo {
        Modo::Nome => {
            com_estado(console, |e| {
                saidaln!(console);
                let mut nome = [0u8; NOME_MAX];
                let digitado = e.texto().trim();
                let tam = digitado.len();
                if tam == 0 || tam > NOME_MAX {
                    e.modo = Modo::Comando;
                } else {
                    nome[..tam].copy_from_slice(digitado.as_bytes());
                    e.nome = nome;
                    e.nome_tam = tam;
                    e.modo = Modo::Senha;
                    crate::teclado::pedindo_senha(i, true);
                }
                e.zerar();
                prompt_em(console, e);
            });
        }
        Modo::Senha => {
            // A senha e o nome saem da tabela para a conferência — que é
            // longa, e não acontece com as interrupções desligadas — e são
            // apagados dos dois lugares.
            let mut senha = [0u8; LINHA_MAX];
            let mut nome = [0u8; NOME_MAX];
            let (tam, nome_tam, abertura) = com_estado(console, |e| {
                let tam = e.tam;
                senha[..tam].copy_from_slice(&e.bytes[..tam]);
                nome.copy_from_slice(&e.nome);
                let nome_tam = e.nome_tam;
                e.zerar();
                e.nome = [0; NOME_MAX];
                e.nome_tam = 0;
                e.modo = Modo::Comando;
                e.inicio = None;
                saidaln!(console);
                (tam, nome_tam, e.abertura)
            })
            .unwrap_or((0, 0, 0));
            crate::teclado::pedindo_senha(i, false);
            let nome_texto = core::str::from_utf8(&nome[..nome_tam]).unwrap_or("");
            let desfecho = crate::pessoas::autenticar(console, nome_texto, &senha[..tam]);
            sigilo::zeroize::Zeroize::zeroize(&mut senha);
            match desfecho {
                Ok(id) => {
                    // A conferência da senha é longa e roda fora da tranca, e
                    // no meio dela o console pode ter fechado — o Terminal
                    // morreu — e até reaberto para **outro** Terminal, na
                    // mesma vaga. Entrar mesmo assim poria a sessão desta
                    // pessoa no console de outro processo, ou num console
                    // fechado, viva e sem ninguém que a feche. Só entra o
                    // console que ainda é o da senha; senão, a sessão que
                    // acabou de nascer acaba.
                    let Some(anterior) = com_estado(console, |e| {
                        (e.aberto && e.abertura == abertura).then(|| e.sessao.replace(id))
                    })
                    .flatten() else {
                        crate::pessoas::encerrar_pelo_console(
                            id,
                            "o console fechou durante o login",
                        );
                        return;
                    };
                    if let Some(velha) = anterior {
                        crate::pessoas::sair(velha);
                    }
                    let papel = match crate::pessoas::sessao(id) {
                        EstadoDaSessao::Ativa { papel, .. } => papel,
                        _ => alloc::string::String::new(),
                    };
                    saidaln!(
                        console,
                        "ola, {} ({}). `logout` para sair.",
                        nome_texto,
                        papel
                    );
                }
                Err(recusa) => saidaln!(console, "{}", recusa.resposta()),
            }
            mostrar_prompt(console);
        }
        Modo::Comando
        | Modo::SenhaAtual
        | Modo::SenhaNova
        | Modo::SenhaDeNovo
        | Modo::Pareando
        | Modo::CodigoDoPar
        | Modo::SenhaDoPareamento => {}
    }
}

/// Escreve algo no console físico sem partir a linha que está sendo
/// digitada.
///
/// # O defeito
///
/// Todo registro de log é ecoado no console, e o console é a mesma tela em
/// que a pessoa digita. Uma linha de log que chegasse no meio da edição era
/// desenhada depois do que já estava digitado, e o que a pessoa digitasse em
/// seguida continuava na linha de baixo: `duke> sys` numa linha, o registro,
/// e `tem.info` embaixo. A linha que seria executada não era nenhuma das que
/// estavam na tela.
///
/// # O conserto
///
/// O que um terminal faz: com uma linha em edição, apagá-la, escrever o que
/// chegou, e redesenhar o prompt com o que já estava digitado. A pessoa vê o
/// registro aparecer acima da linha dela, e a linha continua inteira.
///
/// Sem linha em edição — antes de o interpretador atender, ou enquanto um
/// comando roda — escreve direto.
///
/// Tudo dentro da seção crítica, pelo motivo escrito junto de [`ESTADOS`].
/// `escrever` roda com a linha na mão, então não pode registrar nada no log
/// — e não registra: quem chama é o eco do próprio log.
pub fn por_cima(escrever_o_registro: impl FnOnce()) {
    com_fisico(|e| {
        if e.inicio.is_none() {
            escrever_o_registro();
            return;
        }
        let prompt = e.modo.prompt().len();
        let digitado = if e.modo.secreto() { 0 } else { e.tam };
        for _ in 0..prompt + digitado {
            crate::serial_print!("\u{8} \u{8}");
        }
        escrever_o_registro();
        prompt_em(Console::Fisico, e);
        redesenhar(e);
    });
    crate::ui::mudou();
}

/// Destrava os consoles à força, para uso exclusivo do caminho de falha
/// fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { ESTADOS.force_unlock() };
}

/// Abre o console físico sem a tarefa do interpretador, com uma pessoa de
/// teste já entrada nele. Para a suíte, que roda no lugar do laço em que a
/// tarefa viveria — e que não paga um Argon2id em cada caso: o caminho da
/// credencial tem os casos próprios.
#[cfg(feature = "modo-teste")]
pub fn ativar_para_teste() {
    abrir_console(Console::Fisico);
    entrar_para_teste(Console::Fisico, PESSOA_DE_TESTE, PAPEL_DA_PESSOA_DE_TESTE);
}

/// O console está aberto? Só para a suíte, que confere que o coletor de um
/// pseudo-terminal não fecha o console do dono seguinte.
#[cfg(feature = "modo-teste")]
pub fn console_aberto(console: Console) -> bool {
    com_estado(console, |e| e.aberto).unwrap_or(false)
}

/// O console está pedindo a senha? Só para a suíte, que precisa saber
/// quando a senha já saiu da linha e a conferência começou.
#[cfg(feature = "modo-teste")]
pub fn pedindo_senha(console: Console) -> bool {
    com_estado(console, |e| e.modo.secreto()).unwrap_or(false)
}

/// O que a linha de um console pede, e quantos caracteres ela tem — sem o
/// que eles são. Só para a suíte, que confere que a árvore não mexeu na
/// linha da senha de um Terminal: o console não ecoa a senha, e a grade
/// não a mostra.
#[cfg(feature = "modo-teste")]
pub fn linha_de_teste(console: Console) -> Option<(Modo, usize)> {
    com_estado(console, |e| (e.modo, e.tam))
}

/// A pessoa que a suíte põe no console, e o papel dela.
#[cfg(feature = "modo-teste")]
pub const PESSOA_DE_TESTE: &str = "pessoa-de-teste";
#[cfg(feature = "modo-teste")]
pub const PAPEL_DA_PESSOA_DE_TESTE: &str = "operador";

/// Só para a suíte: a abertura de agora do console — a que a cerimônia de
/// pareamento guarda ao abrir.
#[cfg(feature = "modo-teste")]
pub fn abertura_de_teste(console: Console) -> u64 {
    com_estado(console, |e| e.abertura).unwrap_or(0)
}

/// Põe uma pessoa num console, direto — ver [`ativar_para_teste`].
#[cfg(feature = "modo-teste")]
pub fn entrar_para_teste(console: Console, nome: &str, papel: &str) -> IdSessao {
    let id = crate::pessoas::sessao_de_teste(console, nome, papel);
    com_estado(console, |e| e.sessao = Some(id));
    id
}

/// Fecha a linha do console físico de novo, para que os casos seguintes
/// vejam a máquina como a suíte a encontra: sem linha atendendo, e com a
/// pessoa de teste entrada — ver [`pessoa_padrao_para_teste`].
#[cfg(feature = "modo-teste")]
pub fn desativar_para_teste() {
    fechar_console(Console::Fisico, "fim do caso");
    crate::serial_println!();
    pessoa_padrao_para_teste();
    crate::ui::mudou();
}

/// O estado em que a suíte deixa o console físico entre os casos: alguém
/// entrado — a pessoa de teste —, como numa máquina em uso, sem a linha de
/// comando atendendo. Os casos que apertam a barra como a pessoa contam com
/// isto; os que conferem o console sem ninguém partem do zero, com
/// [`abrir_console`], e devolvem este estado ao terminar.
#[cfg(feature = "modo-teste")]
pub fn pessoa_padrao_para_teste() {
    if sessao_do_console(Console::Fisico)
        .is_some_and(|id| matches!(crate::pessoas::sessao(id), EstadoDaSessao::Ativa { .. }))
    {
        return;
    }
    let id =
        crate::pessoas::sessao_de_teste(Console::Fisico, PESSOA_DE_TESTE, PAPEL_DA_PESSOA_DE_TESTE);
    com_estado(Console::Fisico, |e| e.sessao = Some(id));
}

/// Separa o nome do comando dos parâmetros.
///
/// O nome vai até o primeiro espaço; o resto são os parâmetros, em JSON. É a
/// mesma separação que o `cargo xtask agent` faz, para que quem aprendeu um
/// saiba o outro.
///
/// Fica numa função sua, e não no meio de `executar`, porque é a única
/// lógica deste módulo que não depende de hardware — e portanto a única que a
/// suíte alcança. Ter a de verdade aqui é o que impede o caso de teste de
/// exercitar uma cópia enquanto o interpretador usa outra.
///
/// Parâmetros ausentes viram `{}`, e não string vazia: um `Json` sobre bytes
/// vazios não é um objeto, e todo handler que consulta um campo opcional veria
/// ausência onde deveria ver um objeto sem campos.
pub fn separar(linha: &str) -> (&str, &str) {
    let linha = linha.trim();
    match linha.find(' ') {
        Some(i) => {
            let resto = linha[i + 1..].trim();
            (&linha[..i], if resto.is_empty() { "{}" } else { resto })
        }
        None => (linha, "{}"),
    }
}

/// Executa uma linha, e devolve o nome do comando que ela pedia — e a
/// espera, se ele suspendeu: só com `permitir`. Ver [`suspender`].
fn executar(
    console: Console,
    linha: &str,
    origem: Origem,
    permitir: bool,
) -> (alloc::string::String, Option<crate::rede::espera::Espera>) {
    let linha = linha.trim();
    if linha.is_empty() {
        return (alloc::string::String::new(), None);
    }

    let (nome, params) = separar(linha);

    let espera = match (nome, origem) {
        ("ajuda", _) => {
            ajuda(console, origem);
            None
        }
        // O login, a saída e a troca da própria senha são da pessoa no
        // console. Um agente que os confirmasse estaria entrando por alguém,
        // tirando alguém dali, ou trocando a senha de alguém.
        ("login" | "logout" | "senha" | "aceitar" | "parear", Origem::Agente(_)) => {
            saidaln!(console, "`{}` e da pessoa no console, pelo teclado", nome);
            None
        }
        ("aceitar", Origem::Pessoa) => {
            comecar_pareamento(console, true, params);
            None
        }
        ("parear", Origem::Pessoa) => {
            comecar_pareamento(console, false, params);
            None
        }
        ("login", Origem::Pessoa) => {
            comecar_login(console, params);
            None
        }
        ("logout", Origem::Pessoa) => {
            sair(console);
            None
        }
        ("senha", Origem::Pessoa) => {
            comecar_troca(console, params);
            None
        }
        _ => despachar(console, nome, params, origem, permitir),
    };
    (alloc::string::String::from(nome), espera)
}

/// `login`: pede o nome, ou — com o nome junto, `login maria` — a senha.
fn comecar_login(console: Console, params: &str) {
    let Some(i) = indice(console) else {
        return;
    };
    let nome = if params == "{}" { "" } else { params };
    com_estado(console, |e| {
        if nome.is_empty() || nome.len() > NOME_MAX {
            e.modo = Modo::Nome;
        } else {
            e.nome = [0; NOME_MAX];
            e.nome[..nome.len()].copy_from_slice(nome.as_bytes());
            e.nome_tam = nome.len();
            e.modo = Modo::Senha;
            crate::teclado::pedindo_senha(i, true);
        }
    });
}

/// `logout`: a sessão acaba, e o console volta a pedir o login.
fn sair(console: Console) {
    match com_estado(console, |e| e.sessao.take()).flatten() {
        Some(id) => {
            crate::pareamento::console_mudou(console);
            crate::pessoas::sair(id);
            saidaln!(console, "ate logo.");
        }
        None => saidaln!(console, "ninguem entrou neste console"),
    }
}

/// `senha`: a pessoa do console troca a **própria** senha — a da sessão
/// dela, e nenhuma outra: não há parâmetro que diga de quem.
///
/// Antes de pedir qualquer senha, o que não depende dela: alguém entrado,
/// a decisão do gate com o papel de agora, a persistência de pé e a
/// máquina sem reinício a caminho — ver
/// [`crate::pessoas::pode_trocar_a_propria_senha`]. Recusado ali, nada é
/// pedido. Depois, três linhas sem eco: a atual, a nova e a nova de novo;
/// a troca é feita no Enter da última — ver [`trocar_passo`].
///
/// Nada se digita junto da palavra: uma senha na linha de comando já teria
/// ecoado. `senha <algo>` é recusado, e o que veio junto não é usado.
fn comecar_troca(console: Console, params: &str) {
    let Some(i) = indice(console) else {
        return;
    };
    if params != "{}" {
        saidaln!(
            console,
            "`senha` nao recebe nada na linha: as senhas se digitam depois, sem eco"
        );
        return;
    }
    let Some(sessao) = sessao_valida(console) else {
        autorizacao::recusar_sem_login(console, autorizacao::TROCA_DA_PROPRIA_SENHA, &[]);
        saidaln!(
            console,
            "negado: DENY_NOT_AUTHENTICATED; `login` para entrar"
        );
        return;
    };
    if let Err((codigo, motivo)) = crate::pessoas::pode_trocar_a_propria_senha(console, sessao) {
        saidaln!(console, "negado: {}; {}", codigo.nome(), motivo);
        return;
    }
    com_estado(console, |e| {
        e.largar_troca();
        e.troca = Some(sessao);
        e.modo = Modo::SenhaAtual;
    });
    crate::teclado::pedindo_senha(i, true);
}

/// O Enter no meio da troca da própria senha: a atual leva à nova, a nova
/// à confirmação, e a confirmação à troca — feita fora da tranca, que o
/// Argon2id é longo, com as senhas copiadas para fora e apagadas dos dois
/// lugares. Uma linha vazia, em qualquer passo, desiste sem conferir nada.
fn trocar_passo(console: Console) {
    let Some(i) = indice(console) else {
        return;
    };
    let modo = com_estado(console, |e| e.modo).unwrap_or(Modo::Comando);
    match modo {
        Modo::SenhaAtual | Modo::SenhaNova => {
            let seguiu = com_estado(console, |e| {
                saidaln!(console);
                let seguiu = e.tam > 0;
                if !seguiu {
                    e.largar_troca();
                    e.modo = Modo::Comando;
                } else if e.modo == Modo::SenhaAtual {
                    e.atual = e.bytes;
                    e.atual_tam = e.tam;
                    e.modo = Modo::SenhaNova;
                } else {
                    e.nova = e.bytes;
                    e.nova_tam = e.tam;
                    e.modo = Modo::SenhaDeNovo;
                }
                e.zerar();
                if seguiu {
                    prompt_em(console, e);
                }
                seguiu
            })
            .unwrap_or(false);
            if !seguiu {
                crate::teclado::pedindo_senha(i, false);
                saidaln!(console, "troca de senha desistida: nada mudou");
                mostrar_prompt(console);
            }
        }
        Modo::SenhaDeNovo => {
            let mut atual = [0u8; LINHA_MAX];
            let mut nova = [0u8; LINHA_MAX];
            let mut de_novo = [0u8; LINHA_MAX];
            // A sessão que pediu a troca: se ela acabou no meio, a troca a
            // encontra acabada, e recusa — gravando.
            let (sessao, tamanhos) = com_estado(console, |e| {
                let sessao = e.troca;
                let tamanhos = (e.atual_tam, e.nova_tam, e.tam);
                atual = e.atual;
                nova = e.nova;
                de_novo = e.bytes;
                e.zerar();
                e.largar_troca();
                e.modo = Modo::Comando;
                e.inicio = None;
                saidaln!(console);
                (sessao, tamanhos)
            })
            .unwrap_or((None, (0, 0, 0)));
            crate::teclado::pedindo_senha(i, false);
            let (ta, tn, td) = tamanhos;
            let desfecho = match sessao {
                Some(s) if td > 0 => Some(crate::pessoas::trocar_a_propria_senha(
                    console,
                    s,
                    &atual[..ta],
                    &nova[..tn],
                    &de_novo[..td],
                )),
                _ => None,
            };
            sigilo::zeroize::Zeroize::zeroize(&mut atual);
            sigilo::zeroize::Zeroize::zeroize(&mut nova);
            sigilo::zeroize::Zeroize::zeroize(&mut de_novo);
            match desfecho {
                None => saidaln!(console, "troca de senha desistida: nada mudou"),
                Some(Ok(())) => saidaln!(
                    console,
                    "senha trocada: a antiga nao entra mais, e as sessoes abertas continuam"
                ),
                Some(Err((codigo, motivo))) => {
                    saidaln!(console, "senha nao trocada: {} ({})", motivo, codigo.nome())
                }
            }
            // A sessão pode ter acabado no meio: o console fica sabendo.
            let _ = sessao_valida(console);
            mostrar_prompt(console);
        }
        Modo::Comando
        | Modo::Nome
        | Modo::Senha
        | Modo::Pareando
        | Modo::CodigoDoPar
        | Modo::SenhaDoPareamento => {}
    }
}

/// `aceitar <nome> <papel> [<endereço>]` e `parear <nome> <endereço>
/// <papel>`: a pessoa do console abre uma cerimônia de pareamento — ver
/// [`crate::pareamento`]. Sem ninguém entrado, nada: recusado e gravado.
/// Aberta, a linha passa a pedir o que a cerimônia pede.
fn comecar_pareamento(console: Console, aceitar: bool, params: &str) {
    let Some(i) = indice(console) else {
        return;
    };
    let Some(sessao) = sessao_valida(console) else {
        autorizacao::recusar_sem_login(console, autorizacao::PAREAMENTO, &[]);
        saidaln!(
            console,
            "negado: DENY_NOT_AUTHENTICATED; `login` para entrar"
        );
        return;
    };
    let abertura = com_estado(console, |e| e.abertura).unwrap_or(0);
    let texto = if aceitar {
        crate::pareamento::aceitar(console, abertura, sessao, params)
    } else {
        crate::pareamento::parear(console, abertura, sessao, params)
    };
    saidaln!(console, "{}", texto);
    // O que a cerimônia pede e o número dela, numa tomada só da trava dela,
    // fora da do console; escritos na linha só se nada mais novo chegou a
    // ela nesse meio-tempo — ver [`seguir_a_cerimonia`].
    let lida = crate::pareamento::linha_e_numero_do_console(console);
    #[cfg(feature = "modo-teste")]
    no_meio(NoMeio::DoPassoLido);
    let modo = com_estado(console, |e| {
        seguir_a_cerimonia(e, lida, true);
        e.modo
    })
    .unwrap_or(Modo::Comando);
    crate::teclado::pedindo_senha(i, modo.secreto());
}

/// A linha de um console segue a cerimônia dele, com o que o `aceitar`, o
/// `parear` (`comeco`) ou o Enter numa linha dela leram da cerimônia —
/// [`crate::pareamento::linha_e_numero_do_console`], numa tomada só da
/// trava dela, fora da do console, que a lê depois sem inverter a ordem das
/// travas.
///
/// Entre a leitura e esta escrita, um aviso da cerimônia, de outro fio,
/// pode ter mudado a linha — os códigos à mostra, o fim (ver
/// [`aviso_do_pareamento`]). A leitura de antes não o desfaz: a cerimônia
/// só anda para a frente, e a linha só vai a um passo dela que não seja de
/// antes do que já mostra; a do fim vai a um comando. Escrevia-se o que se
/// leu, e o Enter com texto na linha da espera voltava a linha dos códigos à
/// da espera, e o código digitado em seguida ouvia "ja respondido"; e o
/// Enter que leu a cerimônia viva antes do fim a punha de volta na linha (o
/// achado 3 do adversário do passo 1b).
///
/// - Lida viva, `(n, passo)`: a linha vai ao que ela pede se a cerimônia do
///   console é `n` e o passo não é de antes do que a linha mostra — ou, no
///   começo, se o console não tem cerimônia e `n` não acabou para ele.
/// - Lida acabada — ou nenhuma —: a linha volta a pedir um comando, e a
///   cerimônia que ela tinha conta como acabada.
fn seguir_a_cerimonia(
    e: &mut Estado,
    (linha, viva): (crate::pareamento::Linha, Option<(u64, u8)>),
    comeco: bool,
) {
    match viva {
        Some((numero, passo)) => {
            let segue = match e.cerimonia {
                Some(atual) => atual == numero && passo >= e.passo_da_cerimonia,
                None => comeco && numero > e.cerimonia_encerrada,
            };
            if segue {
                e.modo = Modo::da_cerimonia(linha);
                e.cerimonia = Some(numero);
                e.passo_da_cerimonia = passo;
            }
        }
        None => {
            if let Some(numero) = e.cerimonia.take() {
                e.cerimonia_encerrada = e.cerimonia_encerrada.max(numero);
            }
            e.modo = Modo::Comando;
            e.passo_da_cerimonia = 0;
        }
    }
}

/// O Enter numa linha da cerimônia de pareamento: o que se digitou sai da
/// linha — e é apagado dos dois lugares, se era a senha —, vai à
/// cerimônia, e a linha passa a pedir o que ela pede agora.
///
/// O Enter leu o modo da linha em [`confirmar_em`], numa tomada da trava, e
/// a toma aqui, noutra. Se o fim da cerimônia chegou entre as duas — de
/// outro núcleo, com a linha ainda parada, porque o Enter ainda não a tinha
/// tomado —, ele já zerou a senha e pôs o console a engolir. Então este
/// Enter é o que acaba o engolir, como em [`engolir`]: nada vai à
/// cerimônia, e a linha seguinte da Pessoa não é engolida.
fn parear_passo(console: Console, modo: Modo) {
    let (Some(i), Some(linha)) = (indice(console), modo.linha_da_cerimonia()) else {
        return;
    };
    #[cfg(feature = "modo-teste")]
    no_meio(NoMeio::DoEnter);
    let mut copia = [0u8; LINHA_MAX];
    let tomada = com_estado(console, |e| {
        if e.engolindo {
            e.parar_de_engolir();
            return None;
        }
        let tam = e.tam;
        copia[..tam].copy_from_slice(&e.bytes[..tam]);
        e.zerar();
        e.inicio = None;
        e.executando = true;
        saidaln!(console);
        Some((tam, e.abertura))
    })
    .flatten();
    let Some((tam, abertura)) = tomada else {
        fim_do_engolir(console);
        return;
    };
    crate::teclado::pedindo_senha(i, false);
    let sessao = sessao_valida(console);
    let digitado = if modo.secreto() {
        &copia[..tam]
    } else {
        copia[..tam].trim_ascii()
    };
    let texto = crate::pareamento::linha_digitada(console, abertura, sessao, linha, digitado);
    sigilo::zeroize::Zeroize::zeroize(&mut copia);
    if !texto.is_empty() {
        saidaln!(console, "{}", texto);
    }
    let lida = crate::pareamento::linha_e_numero_do_console(console);
    #[cfg(feature = "modo-teste")]
    no_meio(NoMeio::DoPassoLido);
    let modo = com_estado(console, |e| {
        seguir_a_cerimonia(e, lida, false);
        e.executando = false;
        e.modo
    })
    .unwrap_or(Modo::Comando);
    crate::teclado::pedindo_senha(i, modo.secreto());
    mostrar_prompt(console);
}

/// O que o console diz, depois do desfecho, quando passa a engolir o resto
/// de uma senha — ver [`aviso_do_pareamento`].
pub const AVISO_DO_ENGOLIR: &str = "(o que se digitar ate o Enter e descartado)";

/// A cerimônia de pareamento escreve no console dela — os códigos, o
/// desfecho — de fora da vez dele: a rede, o coletor, a revogação. Como um
/// registro do log por cima da linha: a linha em edição sai, o texto entra,
/// e o prompt volta com o que a cerimônia pede agora. Com uma linha sendo
/// executada, só o texto: o prompt é do fim dela. Um console que reabriu ou
/// fechado desde a abertura não recebe nada.
///
/// # A cerimônia que acaba no meio da senha
///
/// O fim chega de fora — o outro desistiu, a conexão caiu, o prazo venceu,
/// a sessão acabou —, e pode chegar com a linha da senha parada no meio do
/// que a Pessoa digita. A linha volta a pedir um comando, mas ela não sabe
/// disso, e continua digitando: o resto da senha ecoaria, iria à árvore e
/// ao histórico do teclado, e no Enter viraria `comando desconhecido`.
/// Então o console **engole** o que se digitar até o Enter seguinte — ver
/// [`engolir`] —, e diz isso ([`AVISO_DO_ENGOLIR`]), sem prompt: o prompt
/// é do Enter. O bit do histórico fica ligado enquanto ele engole. Com a
/// linha sendo executada, não: o Enter dela já levou a senha.
///
/// O fim roda noutro fio, e pode correr com a tecla e com o Enter da
/// Pessoa, que leem a linha numa tomada da trava e a editam ou tomam
/// noutra. A tecla que passou por [`engolir`] antes do fim confere o
/// engolir de novo na seção que edita a linha ([`tratar`]); o Enter que
/// leu a linha da senha antes do fim, e a toma depois, é o que acaba o
/// engolir ([`parear_passo`]). Num Terminal, a janela, que recebe a tecla
/// antes do console, conta o Enter — ver [`engolida_na_janela`].
///
/// # A linha que não é da cerimônia
///
/// O aviso só muda o modo — e só começa a engolir — de uma linha que é da
/// cerimônia, um passo dela, ou que pede um comando. A do login e as da
/// troca da própria senha não são: o aviso que sai do outro fio pode chegar
/// atrasado, depois de a Pessoa ter desistido da cerimônia, saído e
/// começado o `login` — e a linha do nome viraria uma linha de comando, com
/// o nome e a senha que ela digitasse adiantado ecoando, indo à árvore e ao
/// histórico; a da senha, engolida. Nessas linhas, o aviso só escreve o
/// texto, por cima, e a linha continua a que ela era.
///
/// E só a da cerimônia do console: o aviso leva o número dela
/// (`cerimonia`), o console guarda o da dele — pelo `aceitar`, pelo
/// `parear` e por cada passo —, e o aviso de outra, lido antes de ela
/// acabar e entregue depois, só escreve o texto (o achado 6 do adversário
/// do passo 1). E só para a frente: o aviso que leu um passo de antes do
/// que a linha já mostra — o Enter a levou adiante — também só escreve o
/// texto (o achado 3 do adversário do passo 1b; ver
/// [`seguir_a_cerimonia`]).
pub fn aviso_do_pareamento(console: Console, abertura: u64, cerimonia: u64, texto: &str) {
    #[cfg(feature = "modo-teste")]
    no_meio(NoMeio::DoAviso);
    // O que a cerimônia pede, lido fora da trava do console — relido
    // dentro, inverteria a ordem das travas —, numa tomada só da trava dela:
    // a linha, o número e o passo. Ela pode acabar, ou andar, entre a
    // leitura e a trava: o número diz, dentro da trava, se o aviso ainda é
    // da cerimônia do console, e o passo, se ninguém mostrou na linha um
    // passo mais novo — ver [`seguir_a_cerimonia`].
    let (linha, viva) = crate::pareamento::linha_e_numero_do_console(console);
    let (modo, passo) = match viva {
        Some((numero, passo)) if numero == cerimonia => (Modo::da_cerimonia(linha), passo),
        // A cerimônia do aviso acabou: a linha volta a pedir um comando.
        _ => (Modo::Comando, crate::pareamento::PASSO_DO_FIM),
    };
    #[cfg(feature = "modo-teste")]
    no_meio(NoMeio::DoAvisoLido);
    let Some(i) = indice(console) else {
        return;
    };
    let feito = com_estado(console, |e| {
        if !e.aberto || e.abertura != abertura {
            return None;
        }
        let pedia_a_pessoa = pede_a_pessoa_em(e);
        let parado = !e.executando;
        if parado {
            match console {
                Console::Fisico if e.inicio.is_some() => {
                    let prompt = e.modo.prompt().len();
                    let digitado = if e.modo.secreto() { 0 } else { e.tam };
                    for _ in 0..prompt + digitado {
                        saida!(console, "\u{8} \u{8}");
                    }
                }
                // Engolindo, a saída já está numa linha nova: a do aviso.
                _ if e.engolindo => {}
                _ => saidaln!(console),
            }
        }
        saidaln!(console, "{}", texto);
        // A cerimônia só mexe na linha que é dela ou que pede um comando —
        // ver acima: a do login e as da troca da senha ficam como estão —, e
        // só a cerimônia do console: o aviso atrasado de uma que acabou — o
        // prazo venceu com ele a caminho, e o aviso do fim passou na frente
        // — não põe a linha numa cerimônia morta (o achado 6 do adversário
        // do passo 1).
        let da_cerimonia = (e.modo == Modo::Comando || e.modo.do_pareamento())
            && e.cerimonia == Some(cerimonia)
            && passo >= e.passo_da_cerimonia;
        if modo == Modo::Comando {
            e.cerimonia_encerrada = e.cerimonia_encerrada.max(cerimonia);
        }
        // A linha pedia a senha da cerimônia, parada — a Pessoa no meio dela
        // —, e a cerimônia a tirou do modo secreto: o resto, até o Enter, é
        // engolido.
        let comecou = da_cerimonia && parado && e.modo.secreto() && !modo.secreto();
        if comecou {
            e.engolindo = true;
            e.enter_na_janela = false;
        }
        if da_cerimonia && e.modo != modo {
            e.zerar();
            e.modo = modo;
        }
        // A linha que a cerimônia devolveu a um comando não é mais dela; a
        // que segue nela mostra o passo do aviso.
        if da_cerimonia {
            if modo == Modo::Comando {
                e.cerimonia = None;
                e.passo_da_cerimonia = 0;
            } else {
                e.passo_da_cerimonia = passo;
            }
        }
        if parado {
            if e.engolindo {
                // Sem prompt e sem campo: o prompt é do Enter que acaba o
                // engolir, e a árvore não mostra a linha do físico.
                if comecou {
                    saidaln!(console, "{}", AVISO_DO_ENGOLIR);
                }
                e.inicio = None;
            } else {
                prompt_em(console, e);
                redesenhar_em(console, e);
            }
        }
        let virou = !pedia_a_pessoa && pede_a_pessoa_em(e);
        Some((comecou, e.engolindo, e.modo, virou))
    })
    .flatten();
    let Some((comecou, engolindo, modo, virou)) = feito else {
        return;
    };
    // A linha passou a pedir a pessoa: as edições da árvore a caminho são
    // recusadas agora. Hoje não acontece — a cerimônia começa pelo Enter,
    // que já é a virada, e o engolir só começa de uma linha que já pedia a
    // senha —, e a conferência fica, pela mesma regra.
    if virou {
        recusar_as_edicoes_a_caminho(console);
    }
    // Conforme o modo em que a linha ficou — a da senha do login continua
    // pedindo a senha —, e ligado enquanto o console engole: as teclas que
    // chegam nesse meio-tempo são o resto de uma senha — também as da
    // janela de um Terminal, que entram no histórico quando chegam.
    crate::teclado::pedindo_senha(i, modo.secreto() || engolindo);
    if comecou {
        // Uma linha, e nenhuma por tecla: a conta delas seria o tamanho do
        // resto da senha.
        crate::log_info!(
            "console",
            "{}: engole ate o Enter; a cerimonia acabou no meio da senha",
            console.texto()
        );
    }
    if console == Console::Fisico {
        crate::ui::mudou();
    }
}

/// Se o console engole o resto de uma senha — ver [`aviso_do_pareamento`]
/// —, descarta `c` e devolve verdadeiro: sem eco, fora da linha, da árvore
/// e do histórico, e sem passar pela coordenação — no físico; num Terminal,
/// a tecla já passou pela janela, que não a pôs na coordenação: ver
/// [`engolida_na_janela`].
///
/// O Enter acaba o engolir: o console volta a pedir o que a linha pede —
/// um comando —, com o prompt, o bit do histórico conforme ela, a linha
/// vazia ([`Estado::parar_de_engolir`]), e nada se executa. O Enter de um
/// agente que chegue nesse meio-tempo — só numa corrida: a árvore não
/// reserva Enter na linha que engole — sai dos pedidos, para não ficar
/// órfão, e é descartado.
///
/// Solta a trava antes de devolver: a tecla que passou daqui sem ser
/// engolida confere o engolir de novo na seção que edita a linha — ver
/// [`tratar`].
fn engolir(console: Console, c: char) -> bool {
    use protocolo::usuario::terminal::agente_que_confirmou;
    let Some(acabou) = com_estado(console, |e| {
        e.engolindo.then(|| {
            if c == '\n' {
                e.parar_de_engolir();
            }
            !e.engolindo
        })
    })
    .flatten() else {
        return false;
    };
    if acabou {
        fim_do_engolir(console);
    } else if let Some(sessao) = agente_que_confirmou(c) {
        let _ = tomar_enter_pedido(console, sessao);
        crate::log_warn!(
            "console",
            "{}: o Enter do agente {} chegou com o console engolindo o resto de uma senha; descartado",
            console.texto(),
            sessao
        );
    }
    true
}

/// O console parou de engolir, no Enter da Pessoa: volta a pedir o que a
/// linha pede — um comando —, com o bit do histórico conforme ela, e o
/// prompt. Fora da trava.
fn fim_do_engolir(console: Console) {
    let modo = com_estado(console, |e| e.modo).unwrap_or(Modo::Comando);
    if let Some(i) = indice(console) {
        crate::teclado::pedindo_senha(i, modo.secreto());
    }
    mostrar_prompt(console);
}

/// O console engole o resto de uma senha? Só para a suíte.
#[cfg(feature = "modo-teste")]
pub fn engolindo_de_teste(console: Console) -> bool {
    com_estado(console, |e| e.engolindo).unwrap_or(false)
}

/// Só para a suíte: põe `texto` direto na linha do console, sem conferir
/// nada — o que entrasse nela por um caminho que não confere o engolir.
/// Para o caso conferir a defesa de [`Estado::parar_de_engolir`].
#[cfg(feature = "modo-teste")]
pub fn por_na_linha_de_teste(console: Console, texto: &str) {
    com_estado(console, |e| {
        for c in texto.chars() {
            digitar_em(console, e, c);
        }
    });
}

/// Só para a suíte: os pontos em que um caso põe algo "no meio" — o fim de
/// uma cerimônia entre duas tomadas da trava dos consoles, ou as teclas da
/// Pessoa entre o fim e o aviso dele —, como o fio de outro núcleo o poria.
#[cfg(feature = "modo-teste")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoMeio {
    /// Em [`tratar`]: a tecla passou por [`engolir`] — o console não
    /// engolia — e ainda não chegou à linha.
    DaTecla,
    /// Em [`parear_passo`]: o Enter da Pessoa leu o modo da linha, em
    /// [`confirmar_em`], e ainda não a tomou.
    DoEnter,
    /// Em [`aviso_do_pareamento`]: o aviso saiu da cerimônia — o fim dela
    /// já foi contado — e ainda não chegou à linha; o fio que o leva pode
    /// demorar, e a Pessoa, digitar.
    DoAviso,
    /// Em [`aviso_do_pareamento`]: o aviso já leu o que a cerimônia pede da
    /// linha, e ainda não tomou a trava do console — a cerimônia pode
    /// acabar nesse meio-tempo.
    DoAvisoLido,
    /// No Enter numa linha da cerimônia ([`parear_passo`]) e no `aceitar` ou
    /// `parear` ([`comecar_pareamento`]): o que a cerimônia pede já foi
    /// lido, e a linha ainda não o mostra — um aviso pode chegar nesse
    /// meio-tempo.
    DoPassoLido,
}

/// Só para a suíte: o ponto, e o que roda nele.
#[cfg(feature = "modo-teste")]
pub type Gancho = (NoMeio, fn());

/// Só para a suíte: o que roda, uma vez, no ponto [`NoMeio`] que o caso
/// escolheu.
#[cfg(feature = "modo-teste")]
static NO_MEIO: Mutex<Option<Gancho>> = Mutex::new(None);

/// Só para a suíte: põe (ou tira) o que roda no ponto [`NoMeio`].
#[cfg(feature = "modo-teste")]
pub fn no_meio_de_teste(gancho: Option<Gancho>) {
    crate::arch::sem_interrupcoes(|| *NO_MEIO.lock() = gancho);
}

/// Só para a suíte: roda o gancho de `ponto`, se é o que o caso pôs — e o
/// tira: uma vez só. Fora da trava dos consoles.
#[cfg(feature = "modo-teste")]
fn no_meio(ponto: NoMeio) {
    let gancho = crate::arch::sem_interrupcoes(|| {
        let mut g = NO_MEIO.lock();
        match *g {
            Some((p, f)) if p == ponto => {
                *g = None;
                Some(f)
            }
            _ => None,
        }
    });
    if let Some(f) = gancho {
        f();
    }
}

/// Desenha de novo o que está digitado num console — nada, se é uma senha.
fn redesenhar_em(console: Console, e: &Estado) {
    if !e.modo.secreto() && e.tam > 0 {
        saida!(console, "{}", e.texto());
    }
}

/// Manda o comando ao registro do agente e desenha a resposta — ou, se ele
/// suspendeu, não desenha nada e devolve a espera.
fn despachar(
    console: Console,
    nome: &str,
    params: &str,
    origem: Origem,
    permitir: bool,
) -> Option<crate::rede::espera::Espera> {
    // Quem pede: o agente que confirmou, como a sessão dele; ou a pessoa do
    // console, pela sessão dela. Sem ninguém entrado, nada: o pedido é
    // recusado sem dizer se o comando existe — a resposta é a mesma —, e
    // gravado: o nome e o resumo dos parâmetros só do comando que existe. O
    // que não é comando vai com o marcador, sem resumo: pode ser uma senha
    // digitada no lugar errado — ver `autorizacao::recusar_sem_login`.
    let chamador = match origem {
        Origem::Agente(sessao) => Chamador::Sessao(sessao),
        Origem::Pessoa => match sessao_valida(console) {
            Some(id) => Chamador::Pessoa(id),
            None => {
                match registry::encontrar(nome) {
                    Some(comando) => {
                        autorizacao::recusar_sem_login(console, comando.nome, params.as_bytes())
                    }
                    None => autorizacao::recusar_sem_login(
                        console,
                        autorizacao::COMANDO_DESCONHECIDO,
                        &[],
                    ),
                }
                saidaln!(
                    console,
                    "negado: DENY_NOT_AUTHENTICATED; `login` para entrar"
                );
                return None;
            }
        },
    };

    let Some(comando) = registry::encontrar(nome) else {
        saidaln!(console, "comando desconhecido: {}", nome);
        saidaln!(
            console,
            "`ajuda` lista os {} que existem",
            registry::todos().len()
        );
        return None;
    };

    // No log, e não só na tela, porque é o que torna o interpretador
    // observável de fora: o canal do agente lê `log.tail` e vê o que foi
    // executado na máquina — por quem, e em qual console.
    crate::log_info!(
        "console",
        "executado: {} ({}) em {}",
        nome,
        origem,
        console.texto()
    );

    // A linha passa pelo mesmo crivo do canal: os parâmetros que o comando
    // declara, e a decisão. A pessoa decide pelo papel dela; um agente que
    // confirmou a linha no Terminal é a sessão dele, com o papel dele — o
    // Terminal não é um atalho para o que o canal recusaria.
    let params = Json(params.as_bytes());
    if let Err(campo) = registry::validar(comando, params) {
        autorizacao::auditar_invalido(chamador, comando.nome, params.0, campo);
        saidaln!(console, "parametro invalido: {}", campo);
        return None;
    }
    let licenca = match autorizacao::autorizar(chamador, comando, params, permitir) {
        Ok(autorizacao::Decisao::Licenca(l)) => l,
        // Adiado pelo caminho da auditoria: o console espera como espera um
        // comando que suspendeu, e o interpretador o executa de novo, pelo
        // gate, quando a espera acabar — ver `crate::oleoduto`.
        Ok(autorizacao::Decisao::Adiada(espera)) => return Some(espera),
        Err(recusa) => {
            // A frase para a pessoa — o que ela pediu, o papel dela, o que
            // fazer —, e o código e o registro, para quem investiga
            // (`security.explain` lê o registro).
            saidaln!(console, "negado: {}", recusa.frase());
            match recusa.decisao {
                0 => saidaln!(console, "({})", recusa.codigo.nome()),
                d => saidaln!(console, "({}; registro {})", recusa.codigo.nome(), d),
            }
            // A sessão pode ter acabado entre o começo e a decisão: o
            // console fica sabendo, e volta a pedir o login.
            if let Chamador::Pessoa(_) = chamador {
                let _ = sessao_valida(console);
            }
            return None;
        }
    };

    let mut saida = SaidaHumana::nova(console);
    let mut escritor = JsonWriter::new(&mut saida);
    let (escreveu, espera) =
        licenca.executar_suspensivel(params, alloc::vec::Vec::new(), permitir, &mut escritor);
    // Suspenso: o handler não escreveu nada, e não há o que descarregar.
    if espera.is_some() {
        return espera;
    }
    saida.descarregar();
    if escreveu.is_err() {
        saidaln!(console, "a resposta nao coube");
    }
    saidaln!(console);
    None
}

/// Lista o que se pode fazer neste console.
///
/// Sai do mesmo registro que `agent.describe` publica. Uma lista escrita à
/// mão aqui seria a segunda superfície que este módulo existe para não ter.
/// Sem ninguém entrado, a ajuda diz só como entrar: ela não é privilegiada,
/// e a lista do que o sistema faz é para quem entrou.
fn ajuda(console: Console, origem: Origem) {
    crate::log_info!(
        "console",
        "executado: ajuda ({}) em {}",
        origem,
        console.texto()
    );
    let entrou = sessao_valida(console).is_some() || matches!(origem, Origem::Agente(_));
    if entrou {
        for comando in registry::todos() {
            saidaln!(console, "  {:<18} {}", comando.nome, comando.resumo);
        }
    }
    saidaln!(
        console,
        "  {:<18} {}",
        "login",
        "Entra: pede o nome e a senha (`login nome` pede so a senha)."
    );
    saidaln!(console, "  {:<18} {}", "logout", "Sai.");
    saidaln!(
        console,
        "  {:<18} {}",
        "senha",
        "Troca a propria senha: pede a atual e a nova, sem eco."
    );
    saidaln!(
        console,
        "  {:<18} {}",
        "aceitar",
        "Abre, por 120 s, a janela para parear este Duke a outro seu: `aceitar <nome> <papel> [<endereco>]`."
    );
    saidaln!(
        console,
        "  {:<18} {}",
        "parear",
        "Pareia este Duke ao outro seu que aceitou: `parear <nome> <endereco> <papel>`; pede o codigo do outro e a senha."
    );
    saidaln!(console, "  {:<18} {}", "ajuda", "Esta lista.");
}

/// O maior pedaço da resposta que [`SaidaHumana`] junta antes de escrever.
const PEDACO_DA_RESPOSTA: usize = 2048;

/// Desenha JSON de um jeito que uma pessoa consiga ler, na saída de um
/// console.
///
/// # Por que reformatar, e não interpretar
///
/// Porque interpretar exigiria um segundo leitor de JSON — e um leitor que
/// discordasse do escritor produziria uma tela que não corresponde ao que o
/// agente recebe. Isto aqui não entende nada: conta chaves, respeita strings,
/// e quebra linha onde a leitura pede. O conteúdo é byte a byte o que sai no
/// canal.
///
/// # Por que em pedaços, e não caractere a caractere
///
/// Porque cada escrita no console físico é uma descarga da tela, com as
/// interrupções desligadas. Com o console cheio, cada linha nova rola a
/// camada inteira, e a descarga seguinte recompõe a tela toda: escrita
/// caractere a caractere, uma resposta de trinta linhas eram trinta
/// recomposições de tela inteira seguidas. Medido no build de depuração, a
/// máquina ficava segundos sem atender o canal do agente — a fumaça via a
/// porta sem resposta. Juntando a resposta em pedaços de
/// [`PEDACO_DA_RESPOSTA`] bytes, cada pedaço é uma descarga só, por mais
/// linhas que role.
struct SaidaHumana {
    console: Console,
    profundidade: u32,
    dentro_de_string: bool,
    escapado: bool,
    /// O que já foi formatado e ainda não foi escrito.
    pendente: alloc::string::String,
}

impl SaidaHumana {
    fn nova(console: Console) -> SaidaHumana {
        SaidaHumana {
            console,
            profundidade: 0,
            dentro_de_string: false,
            escapado: false,
            pendente: alloc::string::String::new(),
        }
    }

    /// Escreve no console o que estiver pendente, numa escrita só.
    fn descarregar(&mut self) {
        if !self.pendente.is_empty() {
            saida!(self.console, "{}", self.pendente);
            self.pendente.clear();
        }
    }

    fn pôr(&mut self, texto: &str) {
        self.pendente.push_str(texto);
        if self.pendente.len() >= PEDACO_DA_RESPOSTA {
            self.descarregar();
        }
    }

    fn pôr_char(&mut self, c: char) {
        let mut b = [0u8; 4];
        self.pôr(c.encode_utf8(&mut b));
    }

    fn quebrar(&mut self) {
        self.pôr("\n");
        for _ in 0..self.profundidade {
            self.pôr("  ");
        }
    }

    fn caractere(&mut self, c: char) {
        // Dentro de uma string, nada é pontuação: uma chave entre aspas não
        // abre nível nenhum. Sem esta distinção, um valor que contivesse `{`
        // desalinharia a indentação de tudo que viesse depois.
        if self.dentro_de_string {
            self.pôr_char(c);
            if self.escapado {
                self.escapado = false;
            } else if c == '\\' {
                self.escapado = true;
            } else if c == '"' {
                self.dentro_de_string = false;
            }
            return;
        }

        match c {
            '"' => {
                self.dentro_de_string = true;
                self.pôr_char(c);
            }
            '{' | '[' => {
                self.pôr_char(c);
                self.profundidade += 1;
                self.quebrar();
            }
            '}' | ']' => {
                self.profundidade = self.profundidade.saturating_sub(1);
                self.quebrar();
                self.pôr_char(c);
            }
            ',' => {
                self.pôr_char(c);
                self.quebrar();
            }
            ':' => {
                self.pôr_char(c);
                self.pôr(" ");
            }
            _ => self.pôr_char(c),
        }
    }
}

impl fmt::Write for SaidaHumana {
    fn write_str(&mut self, pedaco: &str) -> fmt::Result {
        for c in pedaco.chars() {
            self.caractere(c);
        }
        Ok(())
    }
}
