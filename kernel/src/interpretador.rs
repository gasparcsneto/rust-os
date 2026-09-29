//! O interpretador: operar o Duke digitando.
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
//! compacto, e uma pessoa lê o mesmo JSON quebrado em linhas. É a mesma ideia
//! que o log estruturado defende desde o começo — o texto legível é uma
//! renderização, e não a fonte da verdade.
//!
//! # Onde a saída aparece
//!
//! No console humano, que é a tela nas duas arquiteturas e também a COM1 no
//! x86. Não no canal do agente: as duas conversas são independentes, e
//! misturá-las quebraria o enquadramento de quem está do outro lado.
//!
//! # A linha de comando tem dois donos, e um caminho
//!
//! Quem está na frente da máquina edita a linha pelo teclado; um agente, pela
//! árvore semântica ([`crate::ui`]), com `set_value` e `confirm`. Os dois
//! passam pelas **mesmas** funções deste módulo — [`definir`], [`confirmar`]
//! —, que editam o mesmo buffer, desenham na mesma tela e registram no mesmo
//! log, com a origem dizendo quem foi. Um caminho à parte para o agente seria
//! uma segunda forma de executar um comando, e a pessoa não veria o que ele
//! fez.

// Em `modo-teste` o laço do agente é trocado pelo executor da suíte, e o
// interpretador — que é uma tarefa desse laço — não é lançado. O resto do
// módulo existe nas duas compilações: a suíte ativa a linha de comando à mão
// e age sobre ela pelo mesmo caminho que o agente usa em produção.
use core::fmt;

use spin::Mutex;

use crate::agent::json::{Json, JsonWriter};
use crate::agent::registry;
use crate::ui::Origem;

/// O maior comando que se pode digitar.
///
/// Não há heap no caminho de uma tecla, então a linha é um buffer fixo. Cento
/// e vinte caracteres cobrem o maior comando com parâmetros que este kernel
/// tem; o que passar disso é recusado com aviso, e não truncado em silêncio.
pub const LINHA_MAX: usize = 120;

/// O que aparece antes do que se digita.
const PROMPT: &str = "duke> ";

/// A linha de comando: o que foi digitado e ainda não confirmado.
struct Linha {
    bytes: [u8; LINHA_MAX],
    tam: usize,
    /// Onde o campo começa na tela, em células — logo depois do prompt.
    ///
    /// `None` enquanto o interpretador não está atendendo: não há campo, e a
    /// árvore não o publica.
    inicio: Option<(u32, u32)>,
    /// Quantas vezes o console tinha rolado quando o campo começou. O campo
    /// sobe uma linha a cada rolagem desde então — ver
    /// [`crate::tela::console::rolagens`].
    rolagens: u32,
}

// A tomada desta tranca passa por `sem_interrupcoes`, pelo motivo de toda
// tranca deste kernel, e nunca atravessa a execução de um comando: um comando
// pode ser `ui.tree`, que lê esta mesma linha.
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
static LINHA: Mutex<Linha> = Mutex::new(Linha {
    bytes: [0; LINHA_MAX],
    tam: 0,
    inicio: None,
    rolagens: 0,
});

fn com_linha<R>(f: impl FnOnce(&mut Linha) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut LINHA.lock()))
}

/// Lê o teclado e executa o que for digitado. Nunca retorna.
///
/// É uma tarefa do executor cooperativo, ao lado do canal do agente. Entre uma
/// tecla e outra ela devolve `Pending`, e o núcleo dorme: uma pessoa digitando
/// é a coisa mais lenta que este kernel espera, e girar à toa por causa dela
/// seria gastar todo o núcleo com o que não chega.
#[cfg(not(feature = "modo-teste"))]
pub async fn atender() {
    crate::serial_println!();
    mostrar_prompt();

    loop {
        tratar_tecla(crate::teclado::proxima_tecla().await);
    }
}

/// O que uma tecla faz, quando chega a quem está na frente da máquina.
///
/// Separado do laço para a suíte alcançá-lo: em modo de teste não há
/// executor, e sem isto o caminho da pessoa só seria exercitado pela fumaça.
pub fn tratar_tecla(c: char) {
    match c {
        '\n' => {
            confirmar(Origem::Pessoa);
        }
        '\u{8}' => apagar(),
        // F1 é o botão da barra superior. Pelo mesmo caminho do `press` do
        // agente — [`crate::ui::agir`] —, com a outra origem: é o que faz o
        // log dizer quem apertou, e o que impede os dois de divergirem.
        // Um clique: o que estiver debaixo do ponteiro, se aceitar `press`,
        // é acionado pelo mesmo caminho — ver [`crate::ponteiro`].
        crate::teclado::CLIQUE => {
            let (x, y) = crate::ponteiro::ultimo_clique();
            crate::ponteiro::tratar_clique(x, y);
        }
        crate::teclado::F1 => {
            let _ = crate::ui::agir(
                crate::ui::ID_DO_BOTAO_LIMPAR,
                crate::ui::Acao::Pressionar,
                None,
                Origem::Pessoa,
            );
        }
        // F2, o botão "Sobre", pelo mesmo caminho.
        crate::teclado::F2 => {
            let _ = crate::ui::agir(
                crate::ui::ID_DO_BOTAO_SOBRE,
                crate::ui::Acao::Pressionar,
                None,
                Origem::Pessoa,
            );
        }
        // Só o que é texto entra na linha. Teclas sem caractere já não
        // chegam aqui, mas o controle que sobra — um tab, por exemplo —
        // desalinharia a conta entre o que está no buffer e o que está
        // desenhado.
        c if aceito(c) => {
            let coube = digitar(c);
            if !coube {
                crate::serial_println!();
                crate::serial_println!("linha longa demais; ate {} caracteres", LINHA_MAX);
                com_linha(|l| l.tam = 0);
                mostrar_prompt();
            }
        }
        _ => {}
    }
}

/// Um caractere que uma pessoa consegue pôr na linha.
fn aceito(c: char) -> bool {
    c.is_ascii_graphic() || c == ' '
}

/// Desenha o prompt e marca ali o começo do campo.
fn mostrar_prompt() {
    com_linha(prompt_em);
    crate::ui::mudou();
}

/// O mesmo, com a linha já na mão.
fn prompt_em(l: &mut Linha) {
    crate::serial_print!("{PROMPT}");
    l.inicio = Some(crate::tela::console::cursor_em_celulas());
    l.rolagens = crate::tela::console::rolagens();
}

/// Acrescenta um caractere à linha e o desenha. Falso se ele não coube.
fn digitar(c: char) -> bool {
    com_linha(|l| digitar_em(l, c))
}

fn digitar_em(l: &mut Linha, c: char) -> bool {
    if l.tam >= LINHA_MAX {
        return false;
    }
    l.bytes[l.tam] = c as u8;
    l.tam += 1;
    crate::serial_print!("{c}");
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
fn apagar() {
    com_linha(apagar_em);
}

fn apagar_em(l: &mut Linha) {
    if l.tam > 0 {
        l.tam -= 1;
        crate::serial_print!("\u{8} \u{8}");
    }
}

/// Limpa o console e recomeça do topo, com a linha que estava sendo
/// digitada redesenhada no prompt.
///
/// É o que o botão da barra superior faz. O que estava digitado não se
/// perde: limpar a tela não é desistir do comando, e uma pessoa que apertou
/// o botão no meio de uma linha espera encontrá-la ali.
///
/// Tudo na seção crítica da linha, pelo motivo escrito junto de [`LINHA`]:
/// um registro que chegasse entre a limpeza e o prompt seria desenhado por
/// [`por_cima`] contando com um prompt que ainda não existe.
pub fn limpar() {
    com_linha(|l| {
        crate::tela::banner();
        if l.inicio.is_some() {
            prompt_em(l);
            crate::serial_print!("{}", core::str::from_utf8(&l.bytes[..l.tam]).unwrap_or(""));
        }
    });
    crate::ui::mudou();
}

/// Onde o campo da linha de comando começa na tela, em células, se o
/// interpretador estiver atendendo.
pub fn inicio_do_campo() -> Option<(u32, u32)> {
    com_linha(|l| {
        let (coluna, linha) = l.inicio?;
        // Cada rolagem desde o prompt subiu o campo uma linha. Um campo que
        // subiu além do topo começa, para quem pergunta, na primeira linha:
        // o que saiu da tela não tem moldura.
        let subiu = crate::tela::console::rolagens().wrapping_sub(l.rolagens);
        Some((coluna, linha.saturating_sub(subiu)))
    })
}

/// O que está digitado agora. Para a árvore semântica.
pub fn com_valor<R>(f: impl FnOnce(&str) -> R) -> R {
    com_linha(|l| f(core::str::from_utf8(&l.bytes[..l.tam]).unwrap_or("")))
}

/// Troca o que está na linha, apagando o que havia e digitando o novo.
///
/// É o `set_value` da árvore semântica. Passa pelo apagar e pelo digitar de
/// quem está na frente da máquina, caractere por caractere, para que a tela
/// termine igual ao que uma pessoa veria se tivesse digitado — inclusive onde
/// a linha quebra.
///
/// Recusa antes de mexer em qualquer coisa: um valor longo demais, ou com
/// algo que uma pessoa não conseguiria digitar, não apaga a linha que estava
/// lá.
pub fn definir(valor: &str) -> Result<(), &'static str> {
    if com_linha(|l| l.inicio.is_none()) {
        return Err("a linha de comando nao esta atendendo");
    }
    if valor.len() > LINHA_MAX {
        return Err("o valor nao cabe na linha de comando");
    }
    if !valor.chars().all(aceito) {
        return Err("o valor tem caracteres que nao se digitam na linha de comando");
    }
    com_linha(|l| {
        while l.tam > 0 {
            apagar_em(l);
        }
        for c in valor.chars() {
            digitar_em(l, c);
        }
    });
    crate::ui::mudou();
    Ok(())
}

/// Executa a linha, como o Enter.
///
/// Devolve o nome do comando que foi executado, vazio se a linha estava
/// vazia. A trava da linha é solta **antes** de executar: o comando pode ser
/// `ui.tree`, que lê a linha, ou `ui.act`, que a edita.
pub fn confirmar(origem: Origem) -> alloc::string::String {
    let mut copia = [0u8; LINHA_MAX];
    // O campo deixa de existir enquanto o comando roda, e volta com o prompt
    // seguinte. É o que diz a [`por_cima`] que a linha na tela já não está em
    // edição — a saída do comando vem depois dela, e não por cima.
    let tam = com_linha(|l| {
        let tam = l.tam;
        copia[..tam].copy_from_slice(&l.bytes[..tam]);
        l.tam = 0;
        l.inicio = None;
        crate::serial_println!();
        tam
    });
    // `from_utf8` não falha: só entram na linha caracteres ASCII, filtrados
    // em [`digitar`] e em [`definir`]. O `unwrap_or` existe para que um dia
    // em que isso mude vire uma linha vazia, e não um pânico.
    let linha = core::str::from_utf8(&copia[..tam]).unwrap_or("");
    let nome = executar(linha, origem);
    mostrar_prompt();
    nome
}

/// Escreve algo no console sem partir a linha que está sendo digitada.
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
/// A árvore semântica tornou isso visível — a própria ação do agente registra
/// uma linha antes de agir —, mas o defeito é anterior a ela e vale para
/// qualquer registro, inclusive os do timer e dos drivers.
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
/// Tudo dentro da seção crítica da linha, pelo motivo escrito junto de
/// [`LINHA`]. `escrever` roda com a linha na mão, então não pode registrar
/// nada no log — e não registra: quem chama é o eco do próprio log.
pub fn por_cima(escrever: impl FnOnce()) {
    com_linha(|l| {
        if l.inicio.is_none() {
            escrever();
            return;
        }
        for _ in 0..PROMPT.len() + l.tam {
            crate::serial_print!("\u{8} \u{8}");
        }
        escrever();
        prompt_em(l);
        crate::serial_print!("{}", core::str::from_utf8(&l.bytes[..l.tam]).unwrap_or(""));
    });
    crate::ui::mudou();
}

/// Destrava a linha de comando à força, para uso exclusivo do caminho de
/// falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { LINHA.force_unlock() };
}

/// Liga a linha de comando sem a tarefa do interpretador. Para a suíte, que
/// roda no lugar do laço em que a tarefa viveria.
#[cfg(feature = "modo-teste")]
pub fn ativar_para_teste() {
    com_linha(|l| l.tam = 0);
    mostrar_prompt();
}

/// Desliga a linha de comando de novo, para que os casos seguintes vejam a
/// máquina como a suíte a encontra.
#[cfg(feature = "modo-teste")]
pub fn desativar_para_teste() {
    com_linha(|l| {
        l.tam = 0;
        l.inicio = None;
    });
    crate::serial_println!();
    crate::ui::mudou();
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
fn executar(linha: &str, origem: Origem) -> alloc::string::String {
    let linha = linha.trim();
    if linha.is_empty() {
        return alloc::string::String::new();
    }

    let (nome, params) = separar(linha);

    match nome {
        "ajuda" => ajuda(origem),
        _ => despachar(nome, params, origem),
    }
    alloc::string::String::from(nome)
}

/// Manda o comando ao registro do agente e desenha a resposta.
fn despachar(nome: &str, params: &str, origem: Origem) {
    let Some(comando) = registry::encontrar(nome) else {
        crate::serial_println!("comando desconhecido: {}", nome);
        crate::serial_println!("`ajuda` lista os {} que existem", registry::todos().len());
        return;
    };

    // No log, e não só na tela, porque é o que torna o interpretador
    // observável de fora: o canal do agente lê `log.tail` e vê o que foi
    // executado na máquina — e por quem. A origem é o começo da auditoria que
    // a fase 12 do roteiro pede: se um agente pode fazer tudo que uma pessoa
    // faz, o registro precisa dizer qual dos dois fez.
    crate::log_info!("console", "executado: {} ({})", nome, origem.nome());

    let mut saida = SaidaHumana::nova();
    let mut escritor = JsonWriter::new(&mut saida);
    if (comando.handler)(Json(params.as_bytes()), &mut escritor).is_err() {
        crate::serial_println!("a resposta nao coube");
    }
    crate::serial_println!();
}

/// Lista os comandos que existem.
///
/// Sai do mesmo registro que `agent.describe` publica. Uma lista escrita à
/// mão aqui seria a segunda superfície que este módulo existe para não ter.
fn ajuda(origem: Origem) {
    crate::log_info!("console", "executado: ajuda ({})", origem.nome());
    for comando in registry::todos() {
        crate::serial_println!("  {:<18} {}", comando.nome, comando.resumo);
    }
    crate::serial_println!("  {:<18} {}", "ajuda", "Esta lista.");
}

/// Desenha JSON de um jeito que uma pessoa consiga ler.
///
/// # Por que reformatar, e não interpretar
///
/// Porque interpretar exigiria um segundo leitor de JSON — e um leitor que
/// discordasse do escritor produziria uma tela que não corresponde ao que o
/// agente recebe. Isto aqui não entende nada: conta chaves, respeita strings,
/// e quebra linha onde a leitura pede. O conteúdo é byte a byte o que sai no
/// canal.
struct SaidaHumana {
    profundidade: u32,
    dentro_de_string: bool,
    escapado: bool,
}

impl SaidaHumana {
    fn nova() -> SaidaHumana {
        SaidaHumana {
            profundidade: 0,
            dentro_de_string: false,
            escapado: false,
        }
    }

    fn quebrar(&self) {
        crate::serial_println!();
        for _ in 0..self.profundidade {
            crate::serial_print!("  ");
        }
    }

    fn caractere(&mut self, c: char) {
        // Dentro de uma string, nada é pontuação: uma chave entre aspas não
        // abre nível nenhum. Sem esta distinção, um valor que contivesse `{`
        // desalinharia a indentação de tudo que viesse depois.
        if self.dentro_de_string {
            crate::serial_print!("{c}");
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
                crate::serial_print!("{c}");
            }
            '{' | '[' => {
                crate::serial_print!("{c}");
                self.profundidade += 1;
                self.quebrar();
            }
            '}' | ']' => {
                self.profundidade = self.profundidade.saturating_sub(1);
                self.quebrar();
                crate::serial_print!("{c}");
            }
            ',' => {
                crate::serial_print!("{c}");
                self.quebrar();
            }
            ':' => crate::serial_print!("{c} "),
            _ => crate::serial_print!("{c}"),
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
