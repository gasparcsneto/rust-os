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
//! são as três palavras do próprio console — `login`, `logout` e `ajuda` —,
//! que não são operações do sistema: dizem quem está no console.
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
//! `DENY_NOT_AUTHENTICATED` e vai para a auditoria. Depois do login, cada
//! comando passa pela decisão com o papel que o registro dá à pessoa
//! **agora**: uma revogação vale no comando seguinte, e o console volta a
//! pedir o login.
//!
//! A senha não ecoa, não aparece na árvore semântica, não entra no
//! histórico do teclado, e o buffer dela é apagado depois da conferência.
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

// Em `modo-teste` o laço do agente é trocado pelo executor da suíte, e o
// interpretador — que é uma tarefa desse laço — não é lançado. O resto do
// módulo existe nas duas compilações: a suíte abre os consoles à mão e age
// sobre eles pelo mesmo caminho que o agente e a pessoa usam em produção.
use core::fmt;

use spin::Mutex;

use crate::agent::json::{Json, JsonWriter};
use crate::agent::registry;
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

/// O que a linha de um console está pedindo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modo {
    /// Um comando.
    Comando,
    /// O nome de quem vai entrar.
    Nome,
    /// A senha. O que se digita não ecoa.
    Senha,
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
    };

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
        let (console, c) = crate::teclado::proxima_entrada().await;
        tratar(console, c);
    }
}

/// Abre um console: sem ninguém entrado, a linha vazia, e o convite para
/// entrar. O físico abre quando o interpretador começa; um Terminal, quando
/// o pseudo-terminal dele abre.
pub fn abrir_console(console: Console) {
    com_estado(console, |e| {
        e.zerar();
        e.aberto = true;
        e.modo = Modo::Comando;
        e.nome_tam = 0;
        e.sessao = None;
        saidaln!(
            console,
            "Duke, {}. Ninguem entrou: `login` para entrar, `ajuda` para saber mais.",
            console.texto()
        );
        prompt_em(console, e);
    });
    if console == Console::Fisico {
        crate::ui::mudou();
    }
}

/// Fecha um console: a sessão de quem estava nele acaba, e o que ele
/// guardava se apaga. Chamada pelo pseudo-terminal quando o Terminal fecha,
/// ou o processo dele morre.
pub fn fechar_console(console: Console, motivo: &str) {
    let Some((sessao, i)) = com_estado(console, |e| {
        let sessao = e.sessao.take();
        e.zerar();
        e.aberto = false;
        e.inicio = None;
        e.modo = Modo::Comando;
        e.nome = [0; NOME_MAX];
        e.nome_tam = 0;
        sessao
    })
    .zip(indice(console)) else {
        return;
    };
    crate::teclado::pedindo_senha(i, false);
    if let Some(id) = sessao {
        crate::pessoas::encerrar_pelo_console(id, motivo);
    }
}

/// O que uma tecla faz, quando chega a quem está na frente da máquina.
///
/// Separado do laço para a suíte alcançá-lo: em modo de teste não há
/// executor, e sem isto o caminho da pessoa só seria exercitado pela fumaça.
#[cfg(feature = "modo-teste")]
pub fn tratar_tecla(c: char) {
    tratar(Console::Fisico, c);
}

/// O que um caractere faz num console.
pub fn tratar(console: Console, c: char) {
    use protocolo::usuario::terminal::{APAGAR_A_LINHA, agente_que_confirmou};
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
    match c {
        '\n' => {
            confirmar_em(console, Origem::Pessoa);
        }
        '\u{8}' => {
            com_estado(console, |e| apagar_em(console, e));
        }
        // A linha inteira, e o Enter de um agente: o que o Terminal escreve
        // pelo pseudo-terminal quando a ação vem da árvore — o `cancel` e o
        // `confirm` da linha de comando dele. Ver `protocolo::usuario::terminal`.
        APAGAR_A_LINHA => {
            let _ = definir_em(console, "");
        }
        c if agente_que_confirmou(c).is_some() => {
            if let Some(sessao) = agente_que_confirmou(c) {
                confirmar_em(console, Origem::Agente(sessao));
            }
        }
        // Só o que é texto entra na linha. Teclas sem caractere já não
        // chegam aqui, mas o controle que sobra — um tab, por exemplo —
        // desalinharia a conta entre o que está no buffer e o que está
        // desenhado.
        c if aceito(c) => {
            let coube = com_estado(console, |e| digitar_em(console, e, c)).unwrap_or(true);
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
    let prompt = match e.modo {
        Modo::Comando => PROMPT,
        Modo::Nome => PROMPT_DO_NOME,
        Modo::Senha => PROMPT_DA_SENHA,
    };
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
    if e.modo != Modo::Senha {
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
        if e.modo != Modo::Senha {
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
    if e.modo != Modo::Senha {
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
        if e.modo == Modo::Senha {
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
    definir_em(Console::Fisico, valor)
}

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
        return Err("o valor tem caracteres que nao se digitam na linha de comando");
    }
    // Esvaziar a linha do login é o `APAGAR_A_LINHA` do Terminal, e vale;
    // escrever nela, não.
    if modo != Modo::Comando && !valor.is_empty() {
        return Err("a linha esta pedindo o login de uma pessoa; so se digita pelo teclado");
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

/// Executa a linha do físico, como o Enter. É o `confirm` da árvore.
///
/// Devolve o nome do comando que foi executado, vazio se a linha estava
/// vazia. Um agente não confirma a linha do login.
pub fn confirmar(origem: Origem) -> alloc::string::String {
    confirmar_em(Console::Fisico, origem)
}

fn confirmar_em(console: Console, origem: Origem) -> alloc::string::String {
    let Some(modo) = com_estado(console, |e| e.modo) else {
        return alloc::string::String::new();
    };
    if modo != Modo::Comando {
        if let Origem::Agente(_) = origem {
            return alloc::string::String::new();
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
        saidaln!(console);
        tam
    }) else {
        return alloc::string::String::new();
    };
    let linha = core::str::from_utf8(&copia[..tam]).unwrap_or("");
    let nome = executar(console, linha, origem);
    mostrar_prompt(console);
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
            let (tam, nome_tam) = com_estado(console, |e| {
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
                (tam, nome_tam)
            })
            .unwrap_or((0, 0));
            crate::teclado::pedindo_senha(i, false);
            let nome_texto = core::str::from_utf8(&nome[..nome_tam]).unwrap_or("");
            let desfecho = crate::pessoas::autenticar(console, nome_texto, &senha[..tam]);
            sigilo::zeroize::Zeroize::zeroize(&mut senha);
            match desfecho {
                Ok(id) => {
                    let anterior = com_estado(console, |e| e.sessao.replace(id)).flatten();
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
        Modo::Comando => {}
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
        let prompt = match e.modo {
            Modo::Comando => PROMPT.len(),
            Modo::Nome => PROMPT_DO_NOME.len(),
            Modo::Senha => PROMPT_DA_SENHA.len(),
        };
        let digitado = if e.modo == Modo::Senha { 0 } else { e.tam };
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

/// A pessoa que a suíte põe no console, e o papel dela.
#[cfg(feature = "modo-teste")]
pub const PESSOA_DE_TESTE: &str = "pessoa-de-teste";
#[cfg(feature = "modo-teste")]
pub const PAPEL_DA_PESSOA_DE_TESTE: &str = "operador";

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

/// Executa uma linha, e devolve o nome do comando que ela pedia.
fn executar(console: Console, linha: &str, origem: Origem) -> alloc::string::String {
    let linha = linha.trim();
    if linha.is_empty() {
        return alloc::string::String::new();
    }

    let (nome, params) = separar(linha);

    match (nome, origem) {
        ("ajuda", _) => ajuda(console, origem),
        // O login e a saída são da pessoa no console. Um agente que os
        // confirmasse estaria entrando por alguém, ou tirando alguém dali.
        ("login" | "logout", Origem::Agente(_)) => {
            saidaln!(console, "`{}` e da pessoa no console, pelo teclado", nome);
        }
        ("login", Origem::Pessoa) => comecar_login(console, params),
        ("logout", Origem::Pessoa) => sair(console),
        _ => despachar(console, nome, params, origem),
    }
    alloc::string::String::from(nome)
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
            crate::pessoas::sair(id);
            saidaln!(console, "ate logo.");
        }
        None => saidaln!(console, "ninguem entrou neste console"),
    }
}

/// Manda o comando ao registro do agente e desenha a resposta.
fn despachar(console: Console, nome: &str, params: &str, origem: Origem) {
    // Quem pede: o agente que confirmou, como a sessão dele; ou a pessoa do
    // console, pela sessão dela. Sem ninguém entrado, nada: o pedido é
    // recusado antes de se saber se o comando existe, e gravado.
    let chamador = match origem {
        Origem::Agente(sessao) => Chamador::Sessao(sessao),
        Origem::Pessoa => match sessao_valida(console) {
            Some(id) => Chamador::Pessoa(id),
            None => {
                autorizacao::recusar_sem_login(console, nome, params.as_bytes());
                saidaln!(
                    console,
                    "negado: DENY_NOT_AUTHENTICATED; `login` para entrar"
                );
                return;
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
        return;
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
        return;
    }
    let licenca = match autorizacao::autorizar(chamador, comando, params) {
        Ok(l) => l,
        Err(codigo) => {
            saidaln!(console, "negado: {}", codigo.nome());
            // A sessão pode ter acabado entre o começo e a decisão: o
            // console fica sabendo, e volta a pedir o login.
            if let Chamador::Pessoa(_) = chamador {
                let _ = sessao_valida(console);
            }
            return;
        }
    };

    let mut saida = SaidaHumana::nova(console);
    let mut escritor = JsonWriter::new(&mut saida);
    let escreveu = licenca.executar(params, &mut escritor);
    saida.descarregar();
    if escreveu.is_err() {
        saidaln!(console, "a resposta nao coube");
    }
    saidaln!(console);
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
