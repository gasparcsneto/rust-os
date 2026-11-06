//! A pessoa no teclado da máquina, pelo monitor do emulador: o ritmo da
//! digitação, que se adapta à perda de teclas, e a linha conferida antes do
//! Enter.
//!
//! As bancadas digitam como a pessoa — o `sendkey` do monitor, uma tecla de
//! cada vez — no Terminal que tem o foco desde o boot, no console físico
//! depois de um clique fora das janelas, ou no campo de uma janela. Todas as
//! que digitam passam por aqui: as de duas máquinas (`enlace`,
//! `pareamento`, `fluxo` e `sdk`, pela [`super::enlace::DePe`]), a da senha
//! e a da atualização (por [`super::senha`]). A fumaça e a imagem de
//! produção da persistência digitam no ritmo base, sem conferir — ver
//! [`super::digitar_pelo_monitor`].
//!
//! # Por que tecla se perde
//!
//! O convidado tira a tecla da fila do dispositivo quando atende — no ARM,
//! a cada tique do relógio, de trinta e dois buffers do `virtio-input`, oito
//! teclas (`kernel/src/virtio/teclado.rs`); no x86, na interrupção do PS/2
//! —, e a que chega com a fila cheia se perde. Com o hospedeiro ocupado —
//! duas máquinas emuladas nele, num runner da CI —, ele atende tarde, e as
//! teclas se perdem em rajada: na CI 434, no par aarch64>aarch64,
//! `/programas/aarch64/carteiro` chegou como `/programas/aarch64ro` e como
//! `/programas/aaarteiro`, e as tentativas, digitadas no mesmo ritmo,
//! perderam do mesmo jeito. Mais devagar, cabe mais atraso.
//!
//! # O ritmo que se adapta
//!
//! Cada máquina guarda um fator de respiro ([`Ritmo`]): começa em 1×, dobra a
//! cada perda que a bancada vê — a linha que a tela mostra estragada, a
//! senha que a conta das teclas do kernel não fecha, o Enter que ela não
//! viu, o comando que o gate não decidiu, o login recusado ou não decidido
//! — até o [`TETO`], 8×, e não volta. Vale até o fim da rodada — o par, nas
//! bancadas de duas máquinas; a bancada inteira, na da senha; o cenário, na
//! da atualização —, e atravessa os cortes de energia: o fator é da
//! [`super::enlace::Maquina`] — ou da bancada —, e o teclado de cada boot o
//! divide ([`RitmoDaMaquina`]). Cada perda sai na saída da bancada, com o
//! número dela e o fator novo; no fim de cada par, o que ficou nas duas
//! máquinas.
//!
//! # A linha conferida antes do Enter
//!
//! - a linha de comando, a do nome no login e a do código do pareamento: a
//!   bancada digita sem o Enter, lê a tela pela árvore semântica (`ui.tree`:
//!   a grade do Terminal, ou a do console físico) e só dá o Enter com a linha
//!   inteira; a estragada se apaga — um apagar por caractere, e dois a mais —
//!   e se digita de novo, no ritmo novo;
//! - o campo de uma janela — a `conversa` do SDK —: o mesmo, pelo valor do
//!   campo na árvore;
//! - a senha, que não ecoa: pela conta das teclas do kernel — o `pressed` e o
//!   `dropped` de `keyboard.read` —, que tem de subir exatamente o tamanho
//!   dela, sem descarte; a que chega com tecla a menos se apaga pela mesma
//!   conta, sem nada na tela nem no log. A conta não vê um shift perdido, e
//!   as senhas das bancadas não têm tecla com shift. A serial das bancadas
//!   lê o teclado — é `sistema`, também na imagem de produção que elas
//!   montam —; numa política em que ela não leia, a senha e o Enter só se
//!   confeririam pelo resultado;
//! - o Enter: contado do mesmo jeito. O que não chega ao kernel vai de novo:
//!   a linha ainda espera por ele, e nada roda duas vezes.
//!
//! Quantas vezes: [`VEZES_DE_DIGITAR`], cinco — cada linha, e cada comando
//! ou login que não chegou a um desfecho —: as três de antes, em 1×, 2× e 4×
//! numa máquina que ainda não perdeu tecla, e mais duas no teto, 8×; na que
//! já perdeu, todas mais devagar.

use std::cell::Cell;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::time::{Duration, Instant};

use super::persistencia::Ligada;

/// O teto do fator de respiro: oito vezes o ritmo base.
pub(crate) const TETO: u32 = 8;

/// Quantas vezes digitar uma linha, ou repetir o que ela pede: as três de
/// antes — em 1×, 2× e 4×, se cada uma perder — e mais duas no teto.
pub(crate) const VEZES_DE_DIGITAR: usize = 5;

/// O prompt de cada linha, como `kernel/src/interpretador.rs` os escreve.
pub(crate) const PROMPT: &str = protocolo::usuario::terminal::PROMPT;
pub(crate) const PROMPT_DO_NOME: &str = "nome: ";
pub(crate) const PROMPT_DA_SENHA: &str = "senha: ";
pub(crate) const PROMPT_DA_ATUAL: &str = "senha atual: ";
pub(crate) const PROMPT_DA_NOVA: &str = "senha nova: ";
pub(crate) const PROMPT_DE_NOVO: &str = "a nova de novo: ";

/// Quanto esperar a linha pedir o que se vai digitar: o prompt vazio — o
/// Terminal recém-ligado, o comando de antes respondendo, a conferência de
/// uma senha.
const ESPERA_PELA_LINHA: Duration = Duration::from_secs(60);

/// Quanto esperar a tela mostrar a linha que se digitou: o eco que ainda vem
/// depois da última tecla. Conta desde a última mudança da linha — a que
/// ainda chega espera mais, até [`ESPERA_MAXIMA_PELO_ECO`] —; a que já se
/// desviou da certa, parada, não espera.
const ESPERA_PELO_ECO: Duration = Duration::from_secs(5);
const ESPERA_MAXIMA_PELO_ECO: Duration = Duration::from_secs(30);

/// Quanto esperar a conta das teclas do kernel fechar, no ritmo base: a
/// última tecla saiu do emulador, falta a interrupção. Estica com o fator.
const ESPERA_PELA_CONTA: Duration = Duration::from_secs(3);

/// O intervalo entre duas leituras da tela ou da conta.
const ENTRE_LEITURAS: Duration = Duration::from_millis(250);

/// Quantas vezes apagar o que sobrou numa linha antes de digitá-la, e o
/// intervalo entre uma vez e outra: o apagar que vai enquanto o comando de
/// antes ainda responde só chega depois, à linha vazia, e não faz nada.
const VEZES_DE_APAGAR: usize = 3;
const ENTRE_APAGARES: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// O ritmo
// ---------------------------------------------------------------------------

/// O ritmo da digitação de uma máquina: o fator que estica o respiro base
/// depois de cada tecla, e as perdas que o fizeram crescer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ritmo {
    fator: u32,
    perdas: u32,
}

impl Default for Ritmo {
    fn default() -> Ritmo {
        Ritmo {
            fator: 1,
            perdas: 0,
        }
    }
}

impl Ritmo {
    pub(crate) fn fator(self) -> u32 {
        self.fator
    }

    pub(crate) fn perdas(self) -> u32 {
        self.perdas
    }

    /// O ritmo depois de mais uma perda: o fator dobra, até o [`TETO`].
    pub(crate) fn com_perda(self) -> Ritmo {
        Ritmo {
            fator: (self.fator * 2).min(TETO),
            perdas: self.perdas + 1,
        }
    }

    /// O respiro depois de `c`, neste ritmo.
    pub(crate) fn respiro(self, c: char) -> Duration {
        respiro_base(c) * self.fator
    }

    /// Como a bancada o diz: as perdas e o fator.
    pub(crate) fn texto(self) -> String {
        match self.perdas {
            0 => format!("nenhuma perda, {}x", self.fator),
            1 => format!("1 perda, o respiro em {}x", self.fator),
            n => format!("{n} perdas, o respiro em {}x", self.fator),
        }
    }
}

/// O ritmo de uma máquina, dividido entre os boots dela: a
/// [`super::enlace::Maquina`] o guarda, e o teclado de cada boot o usa.
pub(crate) type RitmoDaMaquina = Rc<Cell<Ritmo>>;

/// Um ritmo novo: 1×, nenhuma perda.
pub(crate) fn ritmo_novo() -> RitmoDaMaquina {
    Rc::new(Cell::new(Ritmo::default()))
}

/// O respiro base depois de `c`: o tempo de o emulador entregar a tecla.
///
/// O emulador entrega uma tecla por vez, e mandá-las sem respiro faz
/// algumas se perderem entre o monitor e o dispositivo. Uma tecla com shift
/// são quatro eventos na fila do emulador, e não dois: o dobro do respiro.
///
/// E depois do Enter, mais: no console da máquina, cheio, cada linha nova
/// rola a tela e a recompõe inteira, com as interrupções desligadas — no
/// build de depuração, perto de um quarto de segundo. As teclas que chegam
/// nesse meio esperam na fila do PS/2 do emulador, que é curta: medido, a
/// vinte milissegundos por tecla o Enter depois do nome se perdia, e a
/// senha entrava ecoada no nome.
pub(crate) fn respiro_base(c: char) -> Duration {
    Duration::from_millis(match c {
        '\n' => 600,
        _ if com_shift(c) => 40,
        _ => 20,
    })
}

/// A tecla de `c` vai com o shift.
pub(crate) fn com_shift(c: char) -> bool {
    super::tecla_do_monitor(c).is_some_and(|nome| nome.starts_with("shift-"))
}

/// Manda `texto` ao monitor, uma tecla por vez, no `ritmo`.
pub(crate) fn mandar(
    mon: &mut UnixStream,
    texto: &str,
    quem: &str,
    ritmo: Ritmo,
) -> Result<(), String> {
    for c in texto.chars() {
        let nome = super::tecla_do_monitor(c)
            .ok_or_else(|| format!("{quem}: a bancada nao sabe digitar {c:?}"))?;
        mon.write_all(format!("sendkey {nome}\n").as_bytes())
            .and_then(|()| mon.flush())
            .map_err(|e| format!("{quem}: falha ao mandar `{nome}`: {e}"))?;
        std::thread::sleep(ritmo.respiro(c));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// O teclado
// ---------------------------------------------------------------------------

/// O teclado de uma máquina: o monitor do emulador, que atende uma conexão
/// de cada vez, e o ritmo dela.
pub(crate) struct Teclado {
    monitor: UnixStream,
    ritmo: RitmoDaMaquina,
    /// Como a bancada chama a máquina nas mensagens.
    quem: &'static str,
    /// A serial desta máquina não lê o teclado — o `keyboard.read` foi
    /// recusado uma vez —, e a conta não se pede mais: uma recusa atrás da
    /// outra só encheria a auditoria e o perfil da serial.
    sem_conta: bool,
}

impl Teclado {
    pub(crate) fn novo(monitor: UnixStream, ritmo: RitmoDaMaquina, quem: &'static str) -> Teclado {
        Teclado {
            monitor,
            ritmo,
            quem,
            sem_conta: false,
        }
    }

    pub(crate) fn ritmo(&self) -> Ritmo {
        self.ritmo.get()
    }

    pub(crate) fn quem(&self) -> &'static str {
        self.quem
    }

    /// Manda `texto`, uma tecla por vez, no ritmo de agora.
    pub(crate) fn mandar(&mut self, texto: &str) -> Result<(), String> {
        mandar(&mut self.monitor, texto, self.quem, self.ritmo.get())
    }

    /// Uma perda de tecla, vista: o fator dobra, e a bancada diz qual foi, com
    /// o número dela e o fator novo. `o_que` nunca leva uma senha.
    pub(crate) fn perda(&self, o_que: &str) {
        let r = self.ritmo.get().com_perda();
        self.ritmo.set(r);
        println!(
            "  [teclado] {}: perda {} ({o_que}); o respiro agora em {}x",
            self.quem,
            r.perdas(),
            r.fator()
        );
    }
}

// ---------------------------------------------------------------------------
// A tela
// ---------------------------------------------------------------------------

/// Onde aparece a linha que o teclado edita: a do Terminal, que tem o foco
/// desde o boot, ou a do console físico, depois que um clique fora das
/// janelas devolve o teclado ao kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tela {
    Terminal,
    Fisico,
}

impl Tela {
    /// O rótulo da grade dela na árvore semântica.
    fn rotulo(self) -> &'static str {
        match self {
            Tela::Terminal => "terminal",
            Tela::Fisico => "console",
        }
    }

    fn nome(self) -> &'static str {
        match self {
            Tela::Terminal => "o Terminal",
            Tela::Fisico => "o console fisico",
        }
    }
}

/// O valor do primeiro elemento da árvore com o `papel` e o `rotulo`, sem os
/// escapes: o texto de uma grade, ou o de um campo. Só o dele: o valor vem
/// antes dos filhos, e o que vem depois deles é de outro elemento.
pub(crate) fn valor_do_elemento(arvore: &str, papel: &str, rotulo: &str) -> Option<String> {
    let resto = super::apos(arvore, &format!(r#""role":"{papel}","label":"{rotulo}""#))?;
    let ate = resto.find(r#""children":"#).unwrap_or(resto.len());
    texto_json(super::apos(&resto[..ate], r#""value":""#)?)
}

/// O texto da `tela` na árvore semântica: as linhas da grade dela.
pub(crate) fn texto_da_tela(arvore: &str, tela: Tela) -> Option<String> {
    valor_do_elemento(arvore, "text_area", tela.rotulo())
}

/// O valor do campo `rotulo` de uma janela: vazio, se a árvore o mostra sem
/// valor; nada, se não o mostra.
pub(crate) fn valor_do_campo(arvore: &str, rotulo: &str) -> Option<String> {
    arvore
        .contains(&format!(r#""role":"text_field","label":"{rotulo}""#))
        .then(|| valor_do_elemento(arvore, "text_field", rotulo).unwrap_or_default())
}

/// Um texto JSON, do começo até a aspa que o fecha, sem os escapes.
pub(crate) fn texto_json(s: &str) -> Option<String> {
    let mut texto = String::new();
    let mut c = s.chars();
    while let Some(x) = c.next() {
        match x {
            '"' => return Some(texto),
            '\\' => match c.next()? {
                'n' => texto.push('\n'),
                't' => texto.push('\t'),
                'r' => texto.push('\r'),
                'b' => texto.push('\u{8}'),
                'f' => texto.push('\u{c}'),
                'u' => {
                    let hex: String = c.by_ref().take(4).collect();
                    texto.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                outro => texto.push(outro),
            },
            outro => texto.push(outro),
        }
    }
    None
}

/// A última linha da tela — a do cursor —, sem os espaços do fim.
pub(crate) fn ultima_linha(tela: &str) -> &str {
    tela.rsplit('\n').next().unwrap_or("").trim_end()
}

/// As últimas linhas da tela, para a mensagem de uma falha.
pub(crate) fn fim_da_tela(tela: &str) -> String {
    let linhas: Vec<&str> = tela.lines().collect();
    linhas[linhas.len().saturating_sub(8)..]
        .iter()
        .map(|l| format!("    | {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// O que a linha mostra, diante do que se digitou nela.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Conferencia {
    /// A linha certa, inteira: o Enter pode ir.
    Inteira,
    /// Um começo dela: o eco do resto ainda a caminho.
    AChegar,
    /// Outra coisa: uma tecla perdida, trocada ou a mais.
    Estragada,
}

/// Confere a `linha` que a tela mostra contra a `certa`, as duas sem os
/// espaços do fim: a linha certa; um começo dela, do tamanho da `vazia` — o
/// prompt — para cima; ou outra coisa.
pub(crate) fn conferir(linha: &str, vazia: &str, certa: &str) -> Conferencia {
    let (linha, vazia, certa) = (linha.trim_end(), vazia.trim_end(), certa.trim_end());
    if linha == certa {
        Conferencia::Inteira
    } else if linha.starts_with(vazia) && certa.starts_with(linha) {
        Conferencia::AChegar
    } else {
        Conferencia::Estragada
    }
}

/// Onde a bancada digita uma linha: a tela, com o prompt dela, ou o campo de
/// uma janela, pelo rótulo.
#[derive(Clone, Copy, Debug)]
enum Onde<'a> {
    Tela(Tela, &'a str),
    Campo(&'a str),
}

impl Onde<'_> {
    /// A linha vazia, como ela se lê: o prompt, ou nada.
    fn vazia(&self) -> String {
        match self {
            Onde::Tela(_, prompt) => prompt.trim_end().to_string(),
            Onde::Campo(_) => String::new(),
        }
    }

    /// A linha certa com `texto` digitado.
    fn certa(&self, texto: &str) -> String {
        match self {
            Onde::Tela(_, prompt) => format!("{prompt}{texto}").trim_end().to_string(),
            Onde::Campo(_) => texto.to_string(),
        }
    }

    /// A linha de agora: a última da tela, ou o valor do campo. Nada, se a
    /// árvore ainda não a mostra.
    fn ler(&self, m: &mut Ligada) -> Result<Option<String>, String> {
        let arvore = m.pedir("ui.tree", "{}")?;
        Ok(match self {
            Onde::Tela(tela, _) => {
                texto_da_tela(&arvore, *tela).map(|t| ultima_linha(&t).to_string())
            }
            Onde::Campo(rotulo) => {
                valor_do_campo(&arvore, rotulo).map(|v| v.trim_end().to_string())
            }
        })
    }

    fn nome(&self) -> String {
        match self {
            Onde::Tela(tela, _) => tela.nome().to_string(),
            Onde::Campo(rotulo) => format!("o campo `{rotulo}`"),
        }
    }
}

// ---------------------------------------------------------------------------
// A conta das teclas do kernel
// ---------------------------------------------------------------------------

/// A conta das teclas do kernel: as que viraram caractere desde o boot, e as
/// que as filas dele descartaram — o `pressed` e o `dropped` de
/// `keyboard.read`. Nada, se a serial não pode ler o teclado: depois da
/// primeira recusa, nem se pede. O texto do histórico que vem junto não se
/// olha nem se mostra: com `max` 1, uma tecla só, e nunca uma da senha — o
/// kernel não grava no histórico com um console pedindo senha, e a bancada
/// só a digita com o prompt dela à mostra.
fn conta(m: &mut Ligada, t: &mut Teclado) -> Result<Option<(u64, u64)>, String> {
    if t.sem_conta {
        return Ok(None);
    }
    let r = m.pedir("keyboard.read", r#"{"max":1}"#)?;
    let numero = |chave: &str| super::valor_de(&r, chave).and_then(|v| v.parse::<u64>().ok());
    let conta = numero(r#""pressed":"#).zip(numero(r#""dropped":"#));
    t.sem_conta = conta.is_none();
    Ok(conta)
}

/// Espera a conta subir `n` desde `antes`, no prazo do `ritmo`: a conta de
/// agora. Para antes, se ela passar de `n`, ou se alguma fila descartar.
fn esperar_conta(
    m: &mut Ligada,
    t: &mut Teclado,
    antes: (u64, u64),
    n: u64,
) -> Result<(u64, u64), String> {
    let limite = Instant::now() + ESPERA_PELA_CONTA * t.ritmo().fator();
    loop {
        let agora = conta(m, t)?.unwrap_or(antes);
        let chegaram = agora.0.saturating_sub(antes.0);
        if chegaram >= n || agora.1 != antes.1 || Instant::now() >= limite {
            return Ok(agora);
        }
        std::thread::sleep(ENTRE_LEITURAS);
    }
}

// ---------------------------------------------------------------------------
// A linha conferida
// ---------------------------------------------------------------------------

/// Espera a linha de `onde` vazia — o prompt, ou o campo sem nada —, e
/// apaga o que tiver ficado nela: uma linha estragada, ou pela metade — um
/// apagar por caractere, e dois a mais. Só apaga o que a tela mostra igual
/// em duas leituras seguidas — o que ainda chega não se apaga pela metade —,
/// e só depois do prompt: uma linha que não começa com ele é de outro passo
/// — a resposta do comando de antes, a conferência de uma senha —, e se
/// espera. O comando de antes que ainda responde também se mostra igual: o
/// apagar que vai a ele só chega depois, à linha vazia, e não faz nada; por
/// isso, no máximo [`VEZES_DE_APAGAR`] vezes, espaçadas.
fn linha_vazia(m: &mut Ligada, t: &mut Teclado, onde: Onde) -> Result<(), String> {
    let vazia = onde.vazia();
    let limite = Instant::now() + ESPERA_PELA_LINHA;
    let mut anterior: Option<String> = None;
    let (mut apagou, mut apagado) = (0, None::<Instant>);
    loop {
        let linha = onde.ler(m)?;
        match &linha {
            Some(l) if *l == vazia => return Ok(()),
            Some(l)
                if l.starts_with(&vazia)
                    && anterior.as_ref() == Some(l)
                    && apagou < VEZES_DE_APAGAR
                    && apagado.is_none_or(|a| a.elapsed() >= ENTRE_APAGARES) =>
            {
                let sobra = l.chars().count() - vazia.chars().count();
                t.mandar(&"\u{8}".repeat(sobra + 2))?;
                apagou += 1;
                apagado = Some(Instant::now());
            }
            _ => {}
        }
        if Instant::now() >= limite {
            return Err(format!(
                "{}: {} nao mostrou a linha `{vazia}` vazia em {} s (mostra `{}`)",
                t.quem(),
                onde.nome(),
                ESPERA_PELA_LINHA.as_secs(),
                linha.unwrap_or_default()
            ));
        }
        anterior = linha;
        std::thread::sleep(ENTRE_LEITURAS);
    }
}

/// Espera a tela de `onde` mostrar a linha `certa` inteira, depois de a
/// bancada digitá-la: o que se conferiu, e a linha que a tela mostrou. A
/// estragada só conta parada — lida igual duas vezes seguidas: uma leitura
/// no meio de um redesenho não a condena, e o que ainda chega dela chega
/// antes de ela se apagar —; a que fica pela metade, parada por
/// [`ESPERA_PELO_ECO`], também é estragada: o fim dela se perdeu.
fn eco(m: &mut Ligada, onde: Onde, certa: &str) -> Result<(Conferencia, String), String> {
    let vazia = onde.vazia();
    let comeco = Instant::now();
    let mut mudou = comeco;
    let mut anterior: Option<String> = None;
    loop {
        let linha = onde.ler(m)?.unwrap_or_default();
        let conferido = conferir(&linha, &vazia, certa);
        if conferido == Conferencia::Inteira {
            return Ok((Conferencia::Inteira, linha));
        }
        let parada = anterior.as_ref() == Some(&linha);
        if !parada {
            mudou = Instant::now();
        }
        if (conferido == Conferencia::Estragada && parada)
            || mudou.elapsed() >= ESPERA_PELO_ECO
            || comeco.elapsed() >= ESPERA_MAXIMA_PELO_ECO
        {
            return Ok((Conferencia::Estragada, linha));
        }
        anterior = Some(linha);
        std::thread::sleep(ENTRE_LEITURAS);
    }
}

/// Digita `texto` em `onde`, confere que ele entrou inteiro, e só então dá o
/// Enter — contado. A linha estragada se apaga e se digita de novo, no ritmo
/// novo, até [`VEZES_DE_DIGITAR`] vezes. A linha em que nada aparece, com as
/// teclas todas na conta do kernel, não se digita de novo: elas foram a
/// outra janela, e quem chama decide — clicar de novo, por exemplo.
fn digitar_conferido(
    m: &mut Ligada,
    t: &mut Teclado,
    onde: Onde,
    texto: &str,
) -> Result<(), String> {
    let (vazia, certa) = (onde.vazia(), onde.certa(texto));
    let mut ultima = String::new();
    for _ in 0..VEZES_DE_DIGITAR {
        linha_vazia(m, t, onde)?;
        let antes = conta(m, t)?;
        t.mandar(texto)?;
        let (conferido, linha) = eco(m, onde, &certa)?;
        if conferido == Conferencia::Inteira {
            return enter(m, t);
        }
        if linha == vazia
            && let Some(antes) = antes
            && let Some(agora) = conta(m, t)?
            && agora.0.saturating_sub(antes.0) >= texto.chars().count() as u64
            && agora.1 == antes.1
        {
            return Err(format!(
                "{}: as teclas de `{certa}` chegaram ao kernel, e nao a {}: o teclado esta com outra janela",
                t.quem(),
                onde.nome()
            ));
        }
        t.perda(&format!("a linha `{certa}` entrou como `{linha}`"));
        ultima = linha;
    }
    Err(format!(
        "{}: a linha `{certa}` nao entrou inteira em {VEZES_DE_DIGITAR} vezes (a ultima: `{ultima}`)",
        t.quem()
    ))
}

/// Digita `texto` na linha de `tela` que pede `prompt` — vazia —, confere
/// na tela que ele entrou inteiro, e só então dá o Enter, contado.
pub(crate) fn linha(
    m: &mut Ligada,
    t: &mut Teclado,
    tela: Tela,
    prompt: &str,
    texto: &str,
) -> Result<(), String> {
    digitar_conferido(m, t, Onde::Tela(tela, prompt), texto)
}

/// Espera a linha de `tela` pedir `prompt`, vazia, apagando o que tiver
/// ficado nela.
pub(crate) fn esperar_a_linha(
    m: &mut Ligada,
    t: &mut Teclado,
    tela: Tela,
    prompt: &str,
) -> Result<(), String> {
    linha_vazia(m, t, Onde::Tela(tela, prompt))
}

/// Digita `texto` no campo `rotulo` da janela que tem o foco, confere na
/// árvore que ele entrou inteiro, e só então dá o Enter, contado.
pub(crate) fn no_campo(
    m: &mut Ligada,
    t: &mut Teclado,
    rotulo: &str,
    texto: &str,
) -> Result<(), String> {
    digitar_conferido(m, t, Onde::Campo(rotulo), texto)
}

/// O Enter, contado: a conta das teclas do kernel tem de subir um, sem
/// descarte. O que não sobe se perdeu antes do kernel — a linha ainda
/// espera por ele, e nada rodou —, e vai outro, no ritmo novo. Sem a conta,
/// só manda.
pub(crate) fn enter(m: &mut Ligada, t: &mut Teclado) -> Result<(), String> {
    let Some(mut antes) = conta(m, t)? else {
        return t.mandar("\n");
    };
    for _ in 0..VEZES_DE_DIGITAR {
        t.mandar("\n")?;
        let agora = esperar_conta(m, t, antes, 1)?;
        if agora.0 > antes.0 && agora.1 == antes.1 {
            return Ok(());
        }
        t.perda(if agora.1 != antes.1 {
            "o Enter caiu numa fila cheia do kernel"
        } else {
            "o Enter nao chegou ao kernel"
        });
        antes = agora;
    }
    Err(format!(
        "{}: o Enter nao chegou ao kernel em {VEZES_DE_DIGITAR} vezes",
        t.quem()
    ))
}

/// Como termina a linha de uma senha.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fim {
    /// O Enter contado, como o de toda linha.
    Contado,
    /// O Enter só mandado: o da última linha de uma troca que a máquina não
    /// sobrevive — o ponto de queda, o botão logo depois —, onde não há a
    /// quem perguntar a conta.
    Solto,
}

/// A senha, na linha de `tela` que pede `prompt`: não ecoa, e se confere
/// pela conta das teclas do kernel — tem de subir exatamente o tamanho dela,
/// sem descarte —, antes do Enter. A que chega com tecla a menos se apaga
/// pela mesma conta — o apagar a mais numa linha vazia não faz nada — e se
/// digita de novo, no ritmo novo. Nada dela sai na mensagem: só quantas
/// teclas chegaram.
pub(crate) fn senha(
    m: &mut Ligada,
    t: &mut Teclado,
    tela: Tela,
    prompt: &str,
    senha: &str,
    fim: Fim,
) -> Result<(), String> {
    let n = senha.chars().count() as u64;
    for _ in 0..VEZES_DE_DIGITAR {
        linha_vazia(m, t, Onde::Tela(tela, prompt))?;
        let Some(antes) = conta(m, t)? else {
            // Sem a conta, só pelo resultado.
            t.mandar(senha)?;
            return t.mandar("\n");
        };
        t.mandar(senha)?;
        let agora = esperar_conta(m, t, antes, n)?;
        let chegaram = agora.0.saturating_sub(antes.0);
        if chegaram == n && agora.1 == antes.1 {
            return match fim {
                Fim::Contado => enter(m, t),
                Fim::Solto => t.mandar("\n"),
            };
        }
        t.perda(&format!(
            "a senha chegou ao kernel com {chegaram} de {n} teclas{}",
            if agora.1 != antes.1 {
                ", e uma fila dele descartou"
            } else {
                ""
            }
        ));
        // O resto dela que ainda vinha chega antes do apagar: a conta parada.
        let parada = conta_parada(m, t, agora)?;
        apagar_contado(m, t, parada.0.saturating_sub(antes.0) + 2)?;
    }
    Err(format!(
        "{}: a senha nao chegou inteira ao kernel em {VEZES_DE_DIGITAR} vezes",
        t.quem()
    ))
}

/// A conta das teclas do kernel, parada: igual em duas leituras com meio
/// segundo entre elas, até [`ESPERA_PELO_ECO`].
fn conta_parada(
    m: &mut Ligada,
    t: &mut Teclado,
    mut agora: (u64, u64),
) -> Result<(u64, u64), String> {
    let limite = Instant::now() + ESPERA_PELO_ECO;
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let depois = conta(m, t)?.unwrap_or(agora);
        if depois == agora || Instant::now() >= limite {
            return Ok(depois);
        }
        agora = depois;
    }
}

/// Manda `n` apagares e espera a conta deles: o que tiver ficado de uma
/// senha sai antes da próxima, e a conta dela começa limpa. O apagar que não
/// chega vai de novo.
fn apagar_contado(m: &mut Ligada, t: &mut Teclado, n: u64) -> Result<(), String> {
    for _ in 0..VEZES_DE_DIGITAR {
        let Some(antes) = conta(m, t)? else {
            return t.mandar(&"\u{8}".repeat(n as usize));
        };
        t.mandar(&"\u{8}".repeat(n as usize))?;
        let agora = esperar_conta(m, t, antes, n)?;
        if agora.0.saturating_sub(antes.0) >= n && agora.1 == antes.1 {
            return Ok(());
        }
    }
    Err(format!(
        "{}: os apagares da senha nao chegaram ao kernel em {VEZES_DE_DIGITAR} vezes",
        t.quem()
    ))
}

/// O `login` em `tela`: o comando e o nome conferidos na tela, a senha pela
/// conta das teclas, cada Enter contado. O desfecho, quem chama confere na
/// auditoria.
pub(crate) fn login(
    m: &mut Ligada,
    t: &mut Teclado,
    tela: Tela,
    nome: &str,
    senha_: &str,
) -> Result<(), String> {
    linha(m, t, tela, PROMPT, "login")?;
    linha(m, t, tela, PROMPT_DO_NOME, nome)?;
    senha(m, t, tela, PROMPT_DA_SENHA, senha_, Fim::Contado)
}

/// Leva a linha de `tela` de volta ao comando: a que ficou pedindo o nome
/// ou a senha de um login pela metade recebe um Enter — o nome vazio volta
/// ao comando; a senha vazia é recusada, e volta também —, até o prompt do
/// comando aparecer.
pub(crate) fn voltar_ao_comando(m: &mut Ligada, t: &mut Teclado, tela: Tela) -> Result<(), String> {
    let comando = Onde::Tela(tela, PROMPT);
    for _ in 0..VEZES_DE_DIGITAR {
        let linha = comando.ler(m)?.unwrap_or_default();
        if linha.starts_with(PROMPT.trim_end()) {
            return Ok(());
        }
        if [PROMPT_DO_NOME, PROMPT_DA_SENHA]
            .iter()
            .any(|p| linha.starts_with(p.trim_end()))
        {
            t.mandar("\n")?;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    linha_vazia(m, t, comando)
}
