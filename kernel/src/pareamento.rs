//! A cerimônia de pareamento no kernel — o autosserviço da Pessoa (D8): uma
//! Pessoa, com sessão nos dois Dukes dela, relaciona um ao outro sem o
//! administrador.
//!
//! # Quem faz o quê
//!
//! - **A Pessoa**, no console, pelo teclado: `aceitar <nome> <papel>
//!   [<endereço>]` no Duke que entra; `parear <nome> <endereço> <papel>` no
//!   que conhece o endereço do outro. Depois, em cada um, o código que o
//!   **outro** mostra, e a senha dela. São palavras do console, como `senha`:
//!   um agente que as confirme pela árvore semântica é recusado, e as linhas
//!   do código e da senha só o teclado edita (ver `crate::interpretador`).
//! - **O gate** decide, como a Pessoa, ao abrir — `device.pair` e
//!   `device.forget dispositivo:<nome>`, ver
//!   [`crate::autorizacao::decidir_pareamento`] — e **de novo no commit**,
//!   com a ordem das gravações na mão ([`crate::persistencia::em_ordem`]).
//! - **A conta** — os estados, os prazos, o compromisso, os códigos e o
//!   identificador da relação — é a de [`politica::pareamento`]; aqui ela
//!   ganha a trava, a rede, o console e o journal.
//! - **O Duke que aceita** responde na porta do enlace (a 7071), pelo
//!   respondedor de [`crate::enlace`]: o primeiro quadro diz se a sessão é
//!   de enlace ou de cerimônia, e uma nunca vira a outra.
//! - **O Duke que inicia** conduz o protocolo num fio próprio, lançado por
//!   [`crate::enlace::lancar_o_pareamento`] com a autoridade do serviço de
//!   enlace: `net.connect`, `net.send` e `net.recv` pelo gate, e nada mais.
//!   O fio não decide, não grava e não fala como a Pessoa.
//! - **O console** é onde a Pessoa age, e só nele a cerimônia grava: o
//!   commit roda na vez do console — no Enter da senha, ou, quando o
//!   `conferido` do outro chega depois dela, na vez que o interpretador
//!   ganha ao ser acordado ([`no_console`]).
//!
//! # O que a cerimônia não é
//!
//! Não é autoridade: a sessão da cerimônia não tem chamador, não chega ao
//! `autorizar`, e só conhece as mensagens dela. Parear não autoriza nada: a
//! relação gravada só permite pedir — o que chega por ela é decidido pelo
//! gate com o papel da Pessoa, o da relação e o teto `remoto`, a cada vez.
//!
//! # Uma por Duke, e o que é volátil
//!
//! Uma cerimônia por Duke, sob a trava [`CERIMONIA`]; a segunda Pessoa
//! recebe `CONFLICT`. A janela, o resumo do aperto, o nonce, os códigos e o
//! estado da conferência são voláteis: um boot os perde, e nada da
//! cerimônia vai ao disco — só a relação, no commit, com a decisão no mesmo
//! registro do journal.
//!
//! # A ordem das mensagens
//!
//! O que sai pelo transporte cifrado sai na ordem em que se cifra: cada
//! mensagem é cifrada e posta na saída **sob a trava** — na vaga do Duke que
//! aceita ([`crate::rede::canal::enfileirar_na_conexao`]), ou na fila que o
//! fio do iniciante esvazia. Venha de onde vier — o console, a rede, o
//! coletor, uma revogação —, o contador do transporte do outro lado vê as
//! mensagens na ordem dele.
//!
//! # A meia relação
//!
//! Cada lado grava quando tem as três coisas: o código certo, a senha e o
//! `conferido` do outro. Uma queda — de energia, da conexão — depois de um
//! lado gravar e antes de o outro pode deixar a relação de um lado só: sem
//! autoridade a mais (a chave que a Pessoa conferiu), inerte do lado que não
//! gravou (o enlace recusa a chave sem relação), visível no
//! `device.registry` e desfeita com `device.forget`. Não há transação
//! distribuída que a elimine, e não se finge que há. Um lado que gravou não
//! manda `desistiu` — o outro desfaria a relação dele —, e o que recebe
//! `desistiu` depois de gravar desfaz a sua.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use politica::Codigo;
use politica::pareamento::{self as conta, Cerimonia, Desfecho, Estado, Lado, Motivo, Recusa};
use protocolo::json::Json;
use sigilo::quadro::{self, Leitor, Tipo};
use sigilo::{Iniciador, Respondedor, Transporte};

use crate::enlace::Via;
use crate::pessoas::{Console, EstadoDaSessao, IdSessao};
use crate::trava::Mutex;

/// De quanto em quanto o fio do iniciante olha a cerimônia, depois do
/// aperto, em ms: o que a Pessoa confirma sai em até isso.
const PASSO_MS: u64 = 500;

/// Quanto o iniciante espera cada quadro do aperto, em ms: o prazo da
/// conversa do enlace.
const PRAZO_DO_QUADRO_MS: u64 = 8_000;

/// A maior mensagem da cerimônia, em claro. As quatro cabem com folga.
const MAIOR_MENSAGEM: usize = 160;

/// O maior texto que o outro manda ao desistir.
const MAIOR_MOTIVO_DO_OUTRO: usize = 48;

/// O que a linha de um console pede, por causa da cerimônia dele.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Linha {
    /// Nada da cerimônia: um comando.
    Comando,
    /// A cerimônia espera o outro — o aperto, o `conferido`, o `gravado`. Uma
    /// linha vazia desiste.
    Esperando,
    /// O código que o **outro** dispositivo mostra.
    Codigo,
    /// A senha da Pessoa, de novo. Não ecoa.
    Senha,
}

/// O que o console deve à cerimônia: o que só se faz na vez dele.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Devido {
    /// As duas confirmações estão aí: gravar.
    Gravar,
    /// Este lado gravou e o outro desistiu: desfazer.
    Desfazer,
}

/// Uma cerimônia viva, com o que o kernel sabe em volta da conta.
struct Viva {
    /// O número desta cerimônia, que não se repete no boot: um passo que
    /// soltou a trava confere, ao voltar, que ainda é a mesma.
    numero: u64,
    c: Cerimonia,
    /// A sessão da Pessoa que abriu, e a pessoa dela.
    sessao: IdSessao,
    pessoa: [u8; 8],
    /// O console dela, e a abertura dele quando ela abriu: reaberto ou
    /// fechado, a cerimônia acaba.
    console: Console,
    abertura: u64,
    /// O nome local do outro, o papel da relação e o endereço.
    nome: String,
    papel: String,
    endereco: Option<String>,
    /// O transporte cifrado, depois do aperto.
    transporte: Option<Transporte>,
    /// O resumo do aperto, `h`. Apagado no fim.
    resumo: Option<[u8; 32]>,
    /// No que aceita: a conexão que ocupou a janela.
    vaga: Option<(u8, u64)>,
    /// No que inicia: os quadros que o fio manda, na ordem.
    saida: VecDeque<Vec<u8>>,
    devido: Option<Devido>,
    /// O fim já foi contado — à auditoria e ao console —, uma vez.
    avisada: bool,
    /// No que inicia: o fio ainda corre.
    fio: bool,
    /// A decisão gravada com a relação: a resposta guardada de um commit
    /// pedido de novo.
    decisao: Option<u64>,
    /// O que o outro disse ao desistir.
    do_outro: Option<String>,
    /// O código e o motivo de uma recusa — da decisão, do registro, da
    /// senha —, para a auditoria do fim.
    recusa: Option<(Codigo, String)>,
}

impl Drop for Viva {
    fn drop(&mut self) {
        if let Some(mut h) = self.resumo.take() {
            politica::sigiloso::zerar(&mut h);
        }
    }
}

/// O fim de uma cerimônia, para contar fora da trava.
struct Fim {
    desfecho: Desfecho,
    sessao: IdSessao,
    console: Console,
    abertura: u64,
    nome: String,
    recurso: String,
    par: Option<[u8; 32]>,
    relacao: Option<[u8; 16]>,
    lado: Lado,
    vaga: Option<(u8, u64)>,
    do_outro: Option<String>,
    recusa: Option<(Codigo, String)>,
}

/// A cerimônia do Duke — uma, ou nenhuma. Nunca tomada com outra trava na
/// mão, a não ser a de uma vaga do canal, por dentro: cifrar e enfileirar
/// é um passo só.
static CERIMONIA: Mutex<Option<Viva>> = Mutex::new(None);

/// Há uma cerimônia — viva, ou por liberar: quem pergunta a cada tique, sem
/// trava.
static HA: AtomicBool = AtomicBool::new(false);

/// O Duke que aceita está numa cerimônia: a porta do enlace escuta — ver
/// `crate::rede::pilha`, que pergunta a cada volta, com a trava dela na mão.
static ESCUTA: AtomicBool = AtomicBool::new(false);

/// O número da próxima cerimônia.
static NUMERO: AtomicU64 = AtomicU64::new(0);

fn com<R>(f: impl FnOnce(&mut Option<Viva>) -> R) -> R {
    crate::arch::sem_interrupcoes(|| {
        let mut g = CERIMONIA.lock();
        let r = f(&mut g);
        HA.store(g.is_some(), Ordering::Release);
        ESCUTA.store(
            g.as_ref()
                .is_some_and(|x| x.c.lado() == Lado::Aceita && !x.c.acabou()),
            Ordering::Release,
        );
        r
    })
}

/// A cerimônia de número `numero`, se ainda é ela.
fn viva(g: &mut Option<Viva>, numero: u64) -> Option<&mut Viva> {
    g.as_mut().filter(|x| x.numero == numero)
}

/// O relógio da cerimônia: o tempo de máquina — adiantado, na suíte, para
/// vencer os prazos sem esperá-los.
fn agora() -> u64 {
    let t = crate::tempo::uptime_ms();
    #[cfg(feature = "modo-teste")]
    let t = t.saturating_add(ADIANTE.load(Ordering::Relaxed));
    t
}

#[cfg(feature = "modo-teste")]
static ADIANTE: AtomicU64 = AtomicU64::new(0);

/// O que a cerimônia acabada já deixou de precisar: sai na próxima vez.
fn liberavel(x: &Viva) -> bool {
    x.c.acabou() && x.devido.is_none() && !x.fio
}

/// A porta do enlace escuta por causa de uma janela aberta.
pub fn escutando() -> bool {
    ESCUTA.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------
// As mensagens da cerimônia, depois do aperto.
// ---------------------------------------------------------------------

const CONFERIDO: &[u8] = br#"{"estado":"conferido"}"#;

fn mensagem_do_nonce(n: &[u8; 32]) -> String {
    format!(r#"{{"nonce":"{}"}}"#, sigilo::hex_de(n))
}

fn mensagem_gravado(r: &[u8; 16]) -> String {
    format!(
        r#"{{"estado":"gravado","relation":"{}"}}"#,
        politica::dispositivos::id_texto(r)
    )
}

fn mensagem_desistiu(motivo: &str) -> String {
    format!(r#"{{"estado":"desistiu","motivo":"{motivo}"}}"#)
}

/// Uma mensagem que chegou pelo transporte.
enum Recebida {
    Nonce([u8; 32]),
    Conferido,
    Gravado([u8; 16]),
    Desistiu(String),
}

/// Lê uma mensagem da cerimônia: só as quatro, cada uma na forma exata em
/// que se escreve — o que não é uma delas, ou não está na forma, é `None`,
/// e encerra.
fn ler_mensagem(b: &[u8]) -> Option<Recebida> {
    if b == CONFERIDO {
        return Some(Recebida::Conferido);
    }
    let j = Json(b);
    if let Some(n) = j
        .member("nonce")
        .and_then(|v| v.as_str())
        .and_then(sigilo::de_hex_fixo::<32>)
    {
        return (b == mensagem_do_nonce(&n).as_bytes()).then_some(Recebida::Nonce(n));
    }
    match j.member("estado").and_then(|v| v.as_str()) {
        Some("gravado") => {
            let r = j
                .member("relation")
                .and_then(|v| v.as_str())
                .and_then(politica::dispositivos::ler_id)?;
            (b == mensagem_gravado(&r).as_bytes()).then_some(Recebida::Gravado(r))
        }
        Some("desistiu") => {
            let m = j.member("motivo").and_then(|v| v.as_str())?;
            let curto = m.len() <= MAIOR_MOTIVO_DO_OUTRO
                && m.bytes().all(|c| c.is_ascii_graphic() || c == b' ')
                && !m.contains('"')
                && !m.contains('\\');
            (curto && b == mensagem_desistiu(m).as_bytes())
                .then(|| Recebida::Desistiu(m.to_string()))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------
// A saída: pela vaga, no que aceita; pela fila do fio, no que inicia.
// ---------------------------------------------------------------------

/// Na suíte, o que iria às vagas fica aqui, para o caso ler — ver
/// [`saida_de_teste`].
#[cfg(feature = "modo-teste")]
static VAGAS_DE_TESTE: Mutex<Option<Vec<NaVaga>>> = Mutex::new(None);

/// O que a cerimônia fez numa vaga, na suíte.
#[cfg(feature = "modo-teste")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NaVaga {
    Quadro(u8, u64, Vec<u8>),
    Identificada(u8, u64, [u8; 32]),
    Encerrada(u8, u64),
}

#[cfg(feature = "modo-teste")]
fn na_vaga_de_teste(e: NaVaga) -> bool {
    crate::arch::sem_interrupcoes(|| match VAGAS_DE_TESTE.lock().as_mut() {
        Some(v) => {
            v.push(e);
            true
        }
        None => false,
    })
}

/// Põe um quadro na saída da vaga `v`, na conexão `g`. Sob a trava da
/// cerimônia, ou fora dela: só enfileira; quem chama faz a pilha andar.
fn por_na_vaga(v: u8, g: u64, q: &[u8]) -> bool {
    #[cfg(feature = "modo-teste")]
    if na_vaga_de_teste(NaVaga::Quadro(v, g, q.to_vec())) {
        return true;
    }
    crate::rede::canal::enfileirar_na_conexao(v, g, q)
}

fn identificar_na_vaga(v: u8, g: u64, chave: [u8; 32]) {
    #[cfg(feature = "modo-teste")]
    if na_vaga_de_teste(NaVaga::Identificada(v, g, chave)) {
        return;
    }
    crate::rede::canal::identificar(v, g, chave);
}

fn encerrar_vaga(v: u8, g: u64) {
    #[cfg(feature = "modo-teste")]
    if na_vaga_de_teste(NaVaga::Encerrada(v, g)) {
        return;
    }
    crate::rede::canal::encerrar(v, g);
}

/// A pilha anda: o que se enfileirou sai.
fn andar() {
    #[cfg(feature = "modo-teste")]
    if crate::arch::sem_interrupcoes(|| VAGAS_DE_TESTE.lock().is_some()) {
        return;
    }
    crate::rede::pilha::sondar();
}

/// Põe um quadro na saída da cerimônia, sob a trava dela.
fn por(x: &mut Viva, q: Vec<u8>) -> bool {
    match x.vaga {
        Some((v, g)) => por_na_vaga(v, g, &q),
        None if x.c.lado() == Lado::Inicia => {
            x.saida.push_back(q);
            true
        }
        None => false,
    }
}

/// Cifra e põe na saída uma mensagem da cerimônia, sob a trava dela: a ordem
/// em que se cifra é a ordem em que sai.
fn mandar(x: &mut Viva, mensagem: &[u8]) -> bool {
    let Some(t) = x.transporte.as_mut() else {
        return false;
    };
    let mut cifrado = vec![0u8; mensagem.len() + 16];
    let Ok(n) = t.cifrar(mensagem, &mut cifrado) else {
        return false;
    };
    match quadro::montar(Tipo::Dados, &cifrado[..n]) {
        Ok(q) => por(x, q),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------
// O fim.
// ---------------------------------------------------------------------

/// Se a cerimônia acabou e o fim ainda não foi contado: o fim, para contar
/// fora da trava. O que é do aperto sai já: o transporte e o resumo.
fn fim_de(x: &mut Viva) -> Option<Fim> {
    let Estado::Fim(desfecho) = x.c.estado() else {
        return None;
    };
    if x.avisada {
        return None;
    }
    x.avisada = true;
    x.transporte = None;
    if let Some(mut h) = x.resumo.take() {
        politica::sigiloso::zerar(&mut h);
    }
    if desfecho == Desfecho::DesfazerAqui && x.devido.is_none() {
        x.devido = Some(Devido::Desfazer);
    }
    let vaga = x.vaga.take();
    Some(Fim {
        desfecho,
        sessao: x.sessao,
        console: x.console,
        abertura: x.abertura,
        nome: x.nome.clone(),
        recurso: recurso(&x.nome),
        par: x.c.par(),
        relacao: x.c.relacao(),
        lado: x.c.lado(),
        vaga,
        do_outro: x.do_outro.clone(),
        recusa: x.recusa.clone(),
    })
}

/// A cerimônia acaba por `motivo` — se ainda não acabou —, e o fim, se é a
/// primeira vez. Com `avisar_o_par`, o `desistiu` sai antes, cifrado — mas só
/// se nada foi gravado aqui: o lado que gravou não pede ao outro que desfaça
/// o dele.
///
/// Com a gravação em curso, a cerimônia não acaba aqui: a desistência
/// espera a gravação, e o fim sai dela — ver [`gravar`].
fn acabar(x: &mut Viva, motivo: Motivo, avisar_o_par: bool) -> Option<Fim> {
    if x.avisada {
        return None;
    }
    if let Some(Desfecho::Desfeita(m)) = x.c.desistir(motivo)
        && avisar_o_par
    {
        mandar(x, mensagem_desistiu(m.texto()).as_bytes());
    }
    fim_de(x)
}

/// O código da auditoria de um fim sem gravar.
fn codigo_do_motivo(m: Motivo) -> Codigo {
    match m {
        Motivo::CodigoErrado
        | Motivo::SenhaErrada
        | Motivo::CompromissoErrado
        | Motivo::ParRevogado
        | Motivo::FimDaSessao
        | Motivo::ParNaoProvou => Codigo::DenyNotAuthenticated,
        Motivo::ParSuspenso => Codigo::DenyCredential,
        Motivo::Recusada => Codigo::DenyPolicy,
        Motivo::Desligamento => Codigo::Conflict,
        Motivo::ForaDoProtocolo => Codigo::InvalidArgument,
        Motivo::Prazo
        | Motivo::Cancelada
        | Motivo::OutroDesistiu
        | Motivo::Conexao
        | Motivo::RelacaoDiferente => Codigo::Error,
    }
}

fn recurso(nome: &str) -> String {
    format!("{}{nome}", politica::arquivo::PREFIXO_DE_DISPOSITIVO)
}

fn impressao_de(par: Option<[u8; 32]>) -> String {
    par.map_or_else(|| String::from("-"), |k| crate::identidade::impressao(&k))
}

fn id8(r: &[u8; 16]) -> String {
    let mut t = politica::dispositivos::id_texto(r);
    t.truncate(8);
    t
}

/// Conta o fim: à auditoria — o que acabou sem gravar; o que gravou já foi
/// gravado com a decisão —, à conexão, que fecha, e ao log. Devolve o texto
/// para o console; com `ao_console`, o põe lá também, por cima da linha.
fn contar_o_fim(f: Fim, ao_console: bool) -> String {
    let par = impressao_de(f.par);
    let relacao = f.relacao.as_ref().map(id8).unwrap_or_default();
    let texto = match f.desfecho {
        Desfecho::Desfeita(m) => {
            let (codigo, porque) = match &f.recusa {
                Some((c, motivo)) => (*c, motivo.as_str()),
                None => (codigo_do_motivo(m), m.texto()),
            };
            let mut detalhe = format!("desfeita: {porque}; par {par}");
            detalhe.truncate(politica::auditoria::MAIOR_DETALHE);
            crate::autorizacao::auditar_pareamento(f.sessao, &f.recurso, codigo, &detalhe);
            match &f.do_outro {
                Some(o) => format!("pareamento desfeito: {porque} ({o}); nada foi gravado"),
                None => format!("pareamento desfeito: {porque}; nada foi gravado"),
            }
        }
        Desfecho::Concluida => {
            format!(
                "pareado: {} ({par}), relacao {relacao}; o outro gravou",
                f.nome
            )
        }
        Desfecho::GravadaSemAviso => format!(
            "pareado aqui: {} ({par}), relacao {relacao}; o outro nao confirmou que gravou: confira nele (device.registry)",
            f.nome
        ),
        Desfecho::DesfazerAqui => format!(
            "o outro desistiu depois de este Duke gravar a relacao {relacao}: ela sera desfeita aqui"
        ),
    };
    if let Some((v, g)) = f.vaga {
        encerrar_vaga(v, g);
        andar();
    }
    crate::log_info!(
        "pareamento",
        "{}: {:?}, par {}",
        match f.lado {
            Lado::Aceita => "aceitante",
            Lado::Inicia => "iniciante",
        },
        f.desfecho,
        par
    );
    if ao_console {
        avisar(f.console, f.abertura, &texto);
    }
    texto
}

/// Escreve no console da cerimônia, por cima da linha, e a linha passa ao
/// que a cerimônia pede agora.
fn avisar(console: Console, abertura: u64, texto: &str) {
    crate::interpretador::aviso_do_pareamento(console, abertura, texto);
}

// ---------------------------------------------------------------------
// A abertura: `aceitar` e `parear`, no console.
// ---------------------------------------------------------------------

/// As palavras depois de `aceitar` ou `parear`.
fn palavras(args: &str) -> Vec<&str> {
    if args == "{}" {
        Vec::new()
    } else {
        args.split_whitespace().collect()
    }
}

/// Grava a recusa de uma abertura e devolve o texto dela.
fn recusar(sessao: IdSessao, recurso: &str, codigo: Codigo, motivo: &str) -> String {
    crate::autorizacao::auditar_pareamento(sessao, recurso, codigo, motivo);
    format!("pareamento recusado: {motivo} ({})", codigo.nome())
}

/// O papel `papel` pode ser o de uma relação desta Pessoa: existe, não é um
/// teto, e cabe no dela — a mesma regra do administrador ao registrar.
fn papel_da_relacao(sessao: IdSessao, papel: &str) -> Result<(), (Codigo, String)> {
    if crate::autorizacao::e_papel_de_teto(papel) {
        return Err((
            Codigo::DenyPolicy,
            format!("`{papel}` e o teto de um administrador: delega, nao se da"),
        ));
    }
    let da_pessoa = match crate::pessoas::sessao(sessao) {
        EstadoDaSessao::Ativa { papel, .. } => papel,
        _ => {
            return Err((
                Codigo::DenyNotAuthenticated,
                String::from("a sessao acabou"),
            ));
        }
    };
    crate::autorizacao::com_politica(|p| p.cabe_em(papel, &da_pessoa))
        .map_err(|r| (r.codigo(), r.motivo()))
}

/// A chave `chave` pode ser a do dispositivo de nome `nome` para a pessoa
/// `pessoa`: ela não tem relação com ele; e nome e chave são o mesmo par do
/// registro — o nome é do dispositivo, e o segundo a parear usa o que o
/// primeiro deu.
fn nome_e_chave(nome: &str, pessoa: &[u8; 8], chave: &[u8; 32]) -> Result<(), &'static str> {
    if let Some(d) = crate::dispositivos::dispositivo(chave) {
        if d.relacao_da_pessoa(pessoa).is_some() {
            return Err("a pessoa ja tem uma relacao com este dispositivo");
        }
        if d.nome != nome {
            return Err("o dispositivo ja esta no registro com outro nome: use o que ele ja tem");
        }
    }
    if crate::dispositivos::por_nome(nome).is_some_and(|d| d.chave != *chave) {
        return Err("o nome ja e de outro dispositivo");
    }
    Ok(())
}

/// A chave do outro pode ser par: a espécie, a lápide, a suspensão. A
/// recusa como o motivo da cerimônia, o código e o texto.
fn par_aceitavel(chave: &[u8; 32]) -> Result<(), (Motivo, Codigo, &'static str)> {
    if let Err(r) = crate::dispositivos::pode_ser_par(chave) {
        let motivo = match r {
            crate::dispositivos::Recusa::Registro(politica::dispositivos::Recusa::Revogada) => {
                Motivo::ParRevogado
            }
            _ => Motivo::Recusada,
        };
        return Err((motivo, r.codigo(), r.motivo()));
    }
    if crate::contencao::dispositivo_suspenso(chave) {
        return Err((
            Motivo::ParSuspenso,
            Codigo::DenyCredential,
            "dispositivo suspenso",
        ));
    }
    Ok(())
}

/// A máquina pode gravar uma relação agora? A persistência de pé, e nenhum
/// desligamento a caminho.
fn pronta_para_gravar() -> Result<(), (Codigo, &'static str)> {
    if crate::persistencia::exigir().is_err() {
        return Err((
            Codigo::Error,
            "persistencia indisponivel: nada se pareia sem gravar",
        ));
    }
    if crate::energia::pedida().is_some() {
        return Err((Codigo::Conflict, "a maquina esta desligando"));
    }
    Ok(())
}

/// Abre uma cerimônia: as conferências, na ordem, e a vaga dela. Devolve o
/// número; a recusa já gravada, como o texto para o console.
#[allow(clippy::too_many_arguments)]
fn abrir(
    console: Console,
    abertura: u64,
    sessao: IdSessao,
    lado: Lado,
    nome: &str,
    papel: &str,
    endereco: Option<&str>,
) -> Result<u64, String> {
    let recurso = recurso(nome);
    if !politica::arquivo::nome_valido(nome) {
        return Err(recusar(
            sessao,
            &recurso,
            Codigo::InvalidArgument,
            "nome de dispositivo fora da regra",
        ));
    }
    if !politica::arquivo::nome_valido(papel) {
        return Err(recusar(
            sessao,
            &recurso,
            Codigo::InvalidArgument,
            "papel fora da regra",
        ));
    }
    let endereco = match endereco {
        None => None,
        Some(e) => match politica::endereco::normalizar(e)
            .filter(|n| n.as_str() == e && n.starts_with("tcp:"))
        {
            Some(n) => Some(n),
            None => {
                return Err(recusar(
                    sessao,
                    &recurso,
                    Codigo::InvalidArgument,
                    "endereco invalido: so `tcp:<ipv4>:<porta>`, na forma normal",
                ));
            }
        },
    };
    // O gate, como a Pessoa, pelo papel de agora.
    let (codigo, motivo) = crate::autorizacao::decidir_pareamento(sessao, nome);
    if !codigo.permite() {
        return Err(recusar(sessao, &recurso, codigo, motivo));
    }
    if let Err((codigo, motivo)) = papel_da_relacao(sessao, papel) {
        return Err(recusar(sessao, &recurso, codigo, &motivo));
    }
    let Some(pessoa) = crate::pessoas::dona_da_sessao(sessao) else {
        return Err(recusar(
            sessao,
            &recurso,
            Codigo::DenyNotAuthenticated,
            "a sessao acabou",
        ));
    };
    if crate::dispositivos::da_pessoa(nome, &pessoa.0).is_some() {
        return Err(recusar(
            sessao,
            &recurso,
            Codigo::InvalidArgument,
            "a pessoa ja tem uma relacao com este nome: device.forget antes",
        ));
    }
    if let Err((codigo, motivo)) = pronta_para_gravar() {
        return Err(recusar(sessao, &recurso, codigo, motivo));
    }
    if crate::identidade::publica_do_duke().is_none() {
        return Err(recusar(
            sessao,
            &recurso,
            Codigo::Error,
            "o Duke nao tem chave",
        ));
    }
    let mut sorteio = [0u8; conta::TAM_NONCE];
    if crate::aleatorio::preencher(&mut sorteio).is_err() {
        return Err(recusar(
            sessao,
            &recurso,
            Codigo::Error,
            "sem entropia para a cerimonia",
        ));
    }
    let numero = NUMERO.fetch_add(1, Ordering::Relaxed) + 1;
    let papel_dela = papel.to_string();
    let ocupada = com(|g| {
        if g.as_ref().is_some_and(|x| !liberavel(x)) {
            return true;
        }
        let c = match lado {
            Lado::Aceita => {
                let mut w = [0u8; conta::TAM_DESAFIO];
                w.copy_from_slice(&sorteio[..conta::TAM_DESAFIO]);
                Cerimonia::aceitar(agora(), w)
            }
            Lado::Inicia => Cerimonia::parear(agora(), sorteio),
        };
        *g = Some(Viva {
            numero,
            c,
            sessao,
            pessoa: pessoa.0,
            console,
            abertura,
            nome: nome.to_string(),
            papel: papel_dela,
            endereco: endereco.clone(),
            transporte: None,
            resumo: None,
            vaga: None,
            saida: VecDeque::new(),
            devido: None,
            avisada: false,
            fio: false,
            decisao: None,
            do_outro: None,
            recusa: None,
        });
        false
    });
    politica::sigiloso::zerar(&mut sorteio);
    if ocupada {
        return Err(recusar(
            sessao,
            &recurso,
            Codigo::Conflict,
            "outra cerimonia de pareamento em curso neste Duke; tente depois",
        ));
    }
    let detalhe = match (lado, &endereco) {
        (Lado::Inicia, Some(e)) => format!("para {e}; papel {papel}; {}", console.texto()),
        _ => format!("janela aberta; papel {papel}; {}", console.texto()),
    };
    crate::autorizacao::auditar_pareamento(sessao, &recurso, Codigo::Allow, &detalhe);
    Ok(numero)
}

/// `aceitar <nome> <papel> [<endereço>]`: o Duke que entra abre a janela —
/// 120 s para o aperto chegar — e a porta do enlace passa a escutar.
pub fn aceitar(console: Console, abertura: u64, sessao: IdSessao, args: &str) -> String {
    let p = palavras(args);
    let (nome, papel, endereco) = match p[..] {
        [n, r] => (n, r, None),
        [n, r, e] => (n, r, Some(e)),
        _ => return String::from("uso: aceitar <nome> <papel> [<endereco>]"),
    };
    if let Err(texto) = abrir(
        console,
        abertura,
        sessao,
        Lado::Aceita,
        nome,
        papel,
        endereco,
    ) {
        return texto;
    }
    let eu = impressao_de(crate::identidade::publica_do_duke());
    let onde = crate::rede::pilha::resumo()
        .and_then(|r| r.endereco)
        .map(|([a, b, c, d], _)| {
            format!(
                "tcp:{a}.{b}.{c}.{d}:{}",
                crate::rede::canal::PORTA_DO_ENLACE
            )
        })
        .unwrap_or_else(|| format!("a porta {}", crate::rede::canal::PORTA_DO_ENLACE));
    andar();
    format!(
        "aceitando um pareamento por {} s. Este Duke: {eu}, em {onde}.\nNo outro dispositivo: parear <nome> {onde} <papel>. Uma linha vazia desiste.",
        conta::JANELA_MS / 1000
    )
}

/// `parear <nome> <endereço> <papel>`: o Duke que conhece o endereço do
/// outro inicia; o fio da cerimônia conecta pelo gate.
pub fn parear(console: Console, abertura: u64, sessao: IdSessao, args: &str) -> String {
    let p = palavras(args);
    let [nome, endereco, papel] = p[..] else {
        return String::from("uso: parear <nome> <endereco> <papel>");
    };
    let numero = match abrir(
        console,
        abertura,
        sessao,
        Lado::Inicia,
        nome,
        papel,
        Some(endereco),
    ) {
        Ok(n) => n,
        Err(texto) => return texto,
    };
    if let Err(texto) = lancar_o_fio(numero) {
        return texto;
    }
    format!("pareando com {endereco}: esperando o outro Duke. Uma linha vazia desiste.")
}

/// Lança o fio que conduz a cerimônia do iniciante. Na suíte não há fio: o
/// caso conduz com a via de teste dele (`conduzir_de_teste`).
fn lancar_o_fio(numero: u64) -> Result<(), String> {
    #[cfg(feature = "modo-teste")]
    {
        let _ = numero;
        Ok(())
    }
    #[cfg(not(feature = "modo-teste"))]
    {
        com(|g| {
            if let Some(x) = viva(g, numero) {
                x.fio = true;
            }
        });
        if let Err(motivo) = crate::enlace::lancar_o_pareamento() {
            fio_saiu();
            let f = com(|g| {
                viva(g, numero).and_then(|x| {
                    x.recusa = Some((Codigo::Error, String::from(motivo)));
                    acabar(x, Motivo::Conexao, false)
                })
            });
            return Err(f.map(|f| contar_o_fim(f, false)).unwrap_or_default());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// O console: a linha que a cerimônia pede, e o que a Pessoa digita.
// ---------------------------------------------------------------------

fn linha_de(x: &Viva) -> Linha {
    match x.c.estado() {
        Estado::Fim(_) => Linha::Comando,
        Estado::Apertada => Linha::Codigo,
        Estado::CodigoCerto => Linha::Senha,
        _ => Linha::Esperando,
    }
}

/// O que a linha do console `console` pede por causa da cerimônia: nada,
/// se ela não é dele ou acabou.
pub fn linha_do_console(console: Console) -> Linha {
    if !HA.load(Ordering::Acquire) {
        return Linha::Comando;
    }
    com(|g| match g.as_ref() {
        Some(x) if x.console == console => linha_de(x),
        _ => Linha::Comando,
    })
}

/// O Enter numa linha da cerimônia: `linha` é o que o console pedia, e
/// `texto` o que a Pessoa digitou — a senha, na linha da senha; quem chama
/// a apaga. Uma linha vazia desiste. Devolve o texto para o console.
pub fn linha_digitada(
    console: Console,
    abertura: u64,
    sessao: Option<IdSessao>,
    linha: Linha,
    texto: &[u8],
) -> String {
    let atual = com(|g| {
        g.as_ref()
            .filter(|x| x.console == console && x.abertura == abertura && !x.c.acabou())
            .map(|x| (x.numero, x.sessao, linha_de(x)))
    });
    let Some((numero, dona, pedida)) = atual else {
        return String::from("nenhuma cerimonia de pareamento neste console");
    };
    if sessao != Some(dona) {
        let f = com(|g| viva(g, numero).and_then(|x| acabar(x, Motivo::FimDaSessao, true)));
        andar();
        return f.map(|f| contar_o_fim(f, false)).unwrap_or_default();
    }
    if pedida != linha {
        return ja_respondida();
    }
    if texto.is_empty() {
        let f = com(|g| viva(g, numero).and_then(|x| acabar(x, Motivo::Cancelada, true)));
        andar();
        return f.map(|f| contar_o_fim(f, false)).unwrap_or_default();
    }
    match linha {
        Linha::Codigo => digitar_codigo(numero, texto),
        Linha::Senha => conferir_a_senha(console, numero, dona, texto),
        Linha::Esperando | Linha::Comando => {
            String::from("esperando o outro dispositivo; uma linha vazia desiste")
        }
    }
}

/// O código do outro, digitado. Uma vez: errado — ou fora da forma —, a
/// cerimônia acaba nos dois lados.
fn digitar_codigo(numero: u64, texto: &[u8]) -> String {
    // Fora da forma é errado: u32::MAX nunca é um código de 8 dígitos.
    let k = core::str::from_utf8(texto)
        .ok()
        .and_then(conta::ler_codigo)
        .unwrap_or(u32::MAX);
    let r = com(|g| {
        let x = viva(g, numero)?;
        Some(match x.c.digitado(agora(), k) {
            Ok(()) => Ok(()),
            Err(Recusa::CodigoErrado) => Err(acabar(x, Motivo::CodigoErrado, true)),
            Err(Recusa::Vencida | Recusa::Acabou) => Err(acabar(x, Motivo::Prazo, true)),
            Err(_) => Err(None),
        })
    });
    andar();
    match r {
        Some(Ok(())) => String::from("codigo conferido. Agora a senha desta pessoa, neste Duke."),
        Some(Err(Some(f))) => contar_o_fim(f, false),
        _ => ja_respondida(),
    }
}

/// A segunda entrada no mesmo passo: a primeira já o consumiu.
fn ja_respondida() -> String {
    format!(
        "ja respondido: a cerimonia pede outra coisa agora ({})",
        Codigo::Conflict.nome()
    )
}

/// A senha da Pessoa, de novo. Certa, o `conferido` sai; e, se o do outro já
/// chegou, a relação se grava — aqui, na vez do console.
fn conferir_a_senha(console: Console, numero: u64, sessao: IdSessao, senha: &[u8]) -> String {
    if let Err((codigo, motivo)) =
        crate::pessoas::conferir_para_o_pareamento(console, sessao, senha)
    {
        let f = com(|g| {
            viva(g, numero).and_then(|x| {
                x.recusa = Some((codigo, motivo.to_string()));
                acabar(x, Motivo::SenhaErrada, true)
            })
        });
        andar();
        return f.map(|f| contar_o_fim(f, false)).unwrap_or_default();
    }
    let r = com(|g| {
        let x = viva(g, numero)?;
        Some(match x.c.senha_conferida(agora()) {
            Ok(la) => {
                mandar(x, CONFERIDO);
                Ok(la)
            }
            Err(_) => Err(acabar(x, Motivo::Prazo, true)),
        })
    });
    andar();
    match r {
        Some(Ok(true)) => gravar(numero),
        Some(Ok(false)) => String::from(
            "conferido. Esperando o outro dispositivo conferir; uma linha vazia desiste.",
        ),
        Some(Err(Some(f))) => contar_o_fim(f, false),
        _ => String::new(),
    }
}

/// O console mudou — reabriu, fechou, a pessoa saiu —: a cerimônia dele
/// acaba, sem gravar.
pub fn console_mudou(console: Console) {
    if !HA.load(Ordering::Acquire) {
        return;
    }
    let f = com(|g| {
        let x = g.as_mut()?;
        if x.console != console {
            return None;
        }
        acabar(x, Motivo::FimDaSessao, true)
    });
    andar();
    if let Some(f) = f {
        contar_o_fim(f, false);
    }
}

/// O console deve à cerimônia um passo que só ele dá — gravar, desfazer?
pub fn deve_ao_console() -> bool {
    HA.load(Ordering::Acquire) && com(|g| g.as_ref().is_some_and(|x| x.devido.is_some()))
}

/// Dá, na vez do console, o passo que ele deve: a gravação que o `conferido`
/// do outro liberou, ou o desfazimento que o `desistiu` dele pediu. O texto
/// vai ao console da cerimônia, por cima da linha.
pub fn no_console() {
    let devido = com(|g| {
        let x = g.as_mut()?;
        let d = x.devido.take()?;
        Some((x.numero, d, x.console, x.abertura))
    });
    let Some((numero, d, console, abertura)) = devido else {
        return;
    };
    let texto = match d {
        Devido::Gravar => gravar(numero),
        Devido::Desfazer => desfazer(numero),
    };
    if !texto.is_empty() {
        avisar(console, abertura, &texto);
    }
}

// ---------------------------------------------------------------------
// O commit.
// ---------------------------------------------------------------------

/// O que o commit precisa da cerimônia, copiado para fora da trava.
struct ParaGravar {
    sessao: IdSessao,
    pessoa: [u8; 8],
    console: Console,
    nome: String,
    papel: String,
    endereco: Option<String>,
    par: [u8; 32],
    relacao: [u8; 16],
}

/// Grava a relação: as duas confirmações estão aí. Uma vez — um segundo
/// pedido devolve a resposta guardada.
///
/// Com a ordem das gravações na mão: a cerimônia ainda gravando e no prazo;
/// a máquina sem desligamento e a persistência de pé; **a decisão de novo**
/// — `device.pair` e `device.forget dispositivo:<nome>`, o papel que cabe —,
/// a sessão da mesma pessoa; a chave do par sem lápide, de outra espécie e
/// sem suspensão; o registro; a decisão gravada; e o journal, com a decisão
/// no mesmo registro. O que a revogação, a suspensão, a política nova ou o
/// fim da sessão mudarem gravam com esta mesma ordem: ou o commit os vê, ou
/// eles vêm depois dele inteiro.
fn gravar(numero: u64) -> String {
    enum Antes {
        Gravar(ParaGravar),
        Guardada(String),
        Fim(Option<Fim>),
    }
    let antes = com(|g| {
        let x = viva(g, numero)?;
        if let Some(d) = x.decisao {
            let r = x.c.relacao().as_ref().map(id8).unwrap_or_default();
            return Some(Antes::Guardada(format!(
                "ja gravada: relacao {r}, decisao {d}"
            )));
        }
        Some(match x.c.gravar(agora()) {
            Ok(()) => match (x.c.par(), x.c.relacao()) {
                (Some(par), Some(relacao)) => Antes::Gravar(ParaGravar {
                    sessao: x.sessao,
                    pessoa: x.pessoa,
                    console: x.console,
                    nome: x.nome.clone(),
                    papel: x.papel.clone(),
                    endereco: x.endereco.clone(),
                    par,
                    relacao,
                }),
                _ => Antes::Fim(acabar(x, Motivo::ForaDoProtocolo, true)),
            },
            Err(Recusa::Vencida | Recusa::Acabou) => Antes::Fim(acabar(x, Motivo::Prazo, true)),
            Err(_) => Antes::Fim(None),
        })
    });
    let d = match antes {
        None => return String::new(),
        Some(Antes::Guardada(t)) => return t,
        Some(Antes::Fim(f)) => {
            andar();
            return f.map(|f| contar_o_fim(f, false)).unwrap_or_default();
        }
        Some(Antes::Gravar(d)) => d,
    };
    let recurso = recurso(&d.nome);
    let feito = crate::persistencia::em_ordem(|| -> Result<u64, (Codigo, String)> {
        #[cfg(feature = "modo-teste")]
        crate::autorizacao::gancho_da_reconfirmacao();
        // A cerimônia ainda gravando, no prazo, e sem desistência que tenha
        // chegado antes — o outro que desistiu, a conexão que caiu, a chave
        // revogada: aí nada se grava. A que chegar daqui até o fim da
        // gravação espera por ela.
        let ainda = com(|g| {
            viva(g, numero).map(|x| {
                (
                    x.c.estado() == Estado::Gravando && x.c.ainda_no_prazo(agora()),
                    x.c.pendente(),
                )
            })
        });
        match ainda {
            Some((true, None)) => {}
            Some((true, Some(m))) => return Err((codigo_do_motivo(m), String::from(m.texto()))),
            _ => {
                return Err((
                    Codigo::Error,
                    String::from("a cerimonia acabou ou venceu antes da gravacao"),
                ));
            }
        }
        pronta_para_gravar().map_err(|(c, m)| (c, String::from(m)))?;
        let (codigo, motivo) = crate::autorizacao::decidir_pareamento(d.sessao, &d.nome);
        if !codigo.permite() {
            return Err((codigo, String::from(motivo)));
        }
        papel_da_relacao(d.sessao, &d.papel)?;
        if crate::pessoas::dona_da_sessao(d.sessao).map(|p| p.0) != Some(d.pessoa) {
            return Err((
                Codigo::DenyNotAuthenticated,
                String::from("a sessao acabou"),
            ));
        }
        par_aceitavel(&d.par).map_err(|(_, c, m)| (c, String::from(m)))?;
        let foto = crate::persistencia::Foto::tirar();
        let relacao = crate::dispositivos::Relacao {
            id: d.relacao,
            pessoa: d.pessoa,
            papel: d.papel.clone(),
            endereco: d.endereco.clone(),
        };
        crate::dispositivos::registrar(d.par, &d.nome, relacao)
            .map_err(|r| (r.codigo(), String::from(r.motivo())))?;
        let detalhe = format!(
            "pareado: relacao {}, par {}; {}",
            id8(&d.relacao),
            crate::identidade::impressao(&d.par),
            d.console.texto()
        );
        let decisao =
            crate::autorizacao::auditar_pareamento(d.sessao, &recurso, Codigo::Allow, &detalhe);
        crate::persistencia::concluir(
            &foto,
            crate::autorizacao::PAREAMENTO,
            &recurso,
            true,
            decisao,
        )
        .map_err(|m| {
            (
                Codigo::Error,
                format!("a gravacao falhou ({m}): nada mudou"),
            )
        })?;
        Ok(decisao)
    });
    match feito {
        Ok(decisao) => {
            let f = com(|g| {
                let x = viva(g, numero)?;
                x.decisao = Some(decisao);
                let _ = x.c.gravada();
                // O `gravado` sai a quem espera por ele — e não a quem já
                // desistiu: aí este lado desfaz o que gravou.
                if matches!(
                    x.c.estado(),
                    Estado::Gravada | Estado::Fim(Desfecho::Concluida)
                ) {
                    mandar(x, mensagem_gravado(&d.relacao).as_bytes());
                }
                if x.devido.is_none() && x.c.estado() == Estado::Fim(Desfecho::DesfazerAqui) {
                    x.devido = Some(Devido::Desfazer);
                }
                Some(fim_de(x))
            });
            andar();
            crate::log_info!(
                "pareamento",
                "relacao {} com {} gravada (decisao {})",
                id8(&d.relacao),
                crate::identidade::impressao(&d.par),
                decisao
            );
            let mut texto = match f {
                Some(Some(f)) => contar_o_fim(f, false),
                _ => format!(
                    "pareado aqui: {} ({}), relacao {}; esperando o outro gravar",
                    d.nome,
                    crate::identidade::impressao(&d.par),
                    id8(&d.relacao)
                ),
            };
            // O outro desistiu durante a gravação: já na vez do console,
            // desfaz-se aqui mesmo.
            let desfazer_ja = com(|g| {
                viva(g, numero).is_some_and(|x| {
                    let sim = x.devido == Some(Devido::Desfazer);
                    if sim {
                        x.devido = None;
                    }
                    sim
                })
            });
            if desfazer_ja {
                texto.push('\n');
                texto.push_str(&desfazer(numero));
            }
            texto
        }
        Err((codigo, motivo)) => {
            let f = com(|g| {
                viva(g, numero).and_then(|x| {
                    x.recusa = Some((codigo, motivo));
                    // O motivo que o outro ouve: o prazo que venceu no ponto
                    // do commit; a desistência que esperava a gravação — a
                    // revogação, a sessão que acabou —; ou a decisão, que
                    // recusou.
                    let m = if x.c.ainda_no_prazo(agora()) {
                        x.c.pendente().unwrap_or(Motivo::Recusada)
                    } else {
                        Motivo::Prazo
                    };
                    if let Ok(Desfecho::Desfeita(m)) = x.c.nao_gravada(m) {
                        mandar(x, mensagem_desistiu(m.texto()).as_bytes());
                    }
                    fim_de(x)
                })
            });
            andar();
            f.map(|f| contar_o_fim(f, false)).unwrap_or_default()
        }
    }
}

/// Este lado gravou, e o outro desistiu — a reconfirmação ou o journal dele
/// recusou —: a relação gravada aqui sai, gravada também (o registro 44, com
/// o desfazimento na auditoria). Tirar é a direção segura: não depende de a
/// sessão ainda valer.
fn desfazer(numero: u64) -> String {
    let dados = com(|g| {
        let x = viva(g, numero)?;
        Some((x.sessao, x.nome.clone(), x.c.par()?, x.c.relacao()?))
    });
    let Some((sessao, nome, par, relacao)) = dados else {
        return String::new();
    };
    let recurso = recurso(&nome);
    let feito = crate::persistencia::em_ordem(|| -> Result<bool, &'static str> {
        let foto = crate::persistencia::Foto::tirar();
        let (_, ultima) = crate::dispositivos::esquecer(&par, &relacao).map_err(|r| r.motivo())?;
        let decisao = crate::autorizacao::auditar_esquecimento(
            sessao,
            &recurso,
            Codigo::Allow,
            &format!("relacao {} desfeita: o outro desistiu", id8(&relacao)),
        );
        crate::persistencia::concluir(
            &foto,
            crate::autorizacao::ESQUECIMENTO,
            &recurso,
            false,
            decisao,
        )
        .map(|()| ultima)
        .map_err(|_| "a desfeita nao ficou gravada: vale ate o boot")
    });
    match feito {
        Ok(ultima) => {
            crate::enlace::relacao_saiu(&par, &relacao, ultima);
            format!(
                "relacao {} desfeita aqui: o outro desistiu depois de este Duke gravar",
                id8(&relacao)
            )
        }
        Err(m) => format!(
            "a relacao {} nao se desfez aqui ({m}): desfaca com device.forget",
            id8(&relacao)
        ),
    }
}

// ---------------------------------------------------------------------
// O que aceita: a vaga do enlace.
// ---------------------------------------------------------------------

/// Recusa uma conexão de cerimônia: grava (como `pair.open`), manda a
/// recusa em claro e fecha. A janela não muda.
fn recusar_na_vaga(v: u8, g: u64, chave: Option<[u8; 32]>, codigo: Codigo, motivo: &str) -> bool {
    let par = crate::rede::canal::remoto_da_conexao(v, g)
        .map_or_else(|| String::from("tcp"), crate::rede::canal::texto_do_par);
    let mut detalhe = format!("{motivo} ({par})");
    detalhe.truncate(politica::auditoria::MAIOR_DETALHE);
    crate::autorizacao::auditar_aperto_do_pareamento(chave, codigo, &detalhe);
    if let Ok(q) = quadro::montar(Tipo::Recusa, motivo.as_bytes()) {
        por_na_vaga(v, g, &q);
    }
    encerrar_vaga(v, g);
    false
}

/// Um quadro numa vaga do enlace cuja sessão é — ou vira — de cerimônia. É
/// o respondedor de [`crate::enlace`] quem chama, no primeiro quadro da
/// conexão (o pedido da chave, ou a primeira mensagem) e em todos os
/// seguintes. Falso se a sessão acabou: a recusa e o fecho já saíram.
pub fn quadro_na_vaga(v: u8, g: u64, tipo: Tipo, corpo: &[u8]) -> bool {
    let continua = match tipo {
        Tipo::PedidoDaChave => anunciar(v, g),
        Tipo::InicioPareamento => primeira_mensagem(v, g, corpo),
        Tipo::Dados => dados_na_vaga(v, g, corpo),
        _ => fora_do_protocolo_na_vaga(v, g),
    };
    andar();
    continua
}

/// O pedido da chave: com a janela livre, o anúncio — a chave deste Duke e o
/// desafio da janela, em claro. Nada se ocupa por ele.
fn anunciar(v: u8, g: u64) -> bool {
    if !crate::autorizacao::permitir_aperto_do_enlace(v) {
        if let Ok(q) = quadro::montar(Tipo::Recusa, b"apertos demais; espere a janela") {
            por_na_vaga(v, g, &q);
        }
        encerrar_vaga(v, g);
        return false;
    }
    let desafio = com(|x| {
        x.as_ref()
            .filter(|x| x.c.lado() == Lado::Aceita && x.c.janela_livre(agora()))
            .and_then(|x| x.c.desafio())
    });
    let Some(w) = desafio else {
        return recusar_na_vaga(
            v,
            g,
            None,
            Codigo::DenyNotAuthenticated,
            "sem janela de pareamento aberta",
        );
    };
    let Some(pk) = crate::identidade::publica_do_duke() else {
        return recusar_na_vaga(v, g, None, Codigo::Error, "o Duke nao tem chave");
    };
    let mut anuncio = [0u8; 32 + conta::TAM_DESAFIO];
    anuncio[..32].copy_from_slice(&pk);
    anuncio[32..].copy_from_slice(&w);
    match quadro::montar(Tipo::ChaveDoDuke, &anuncio) {
        Ok(q) if por_na_vaga(v, g, &q) => true,
        _ => recusar_na_vaga(v, g, None, Codigo::Error, "o anuncio nao saiu"),
    }
}

/// A primeira mensagem do aperto da cerimônia. Abre com a chave deste
/// Duke; traz o compromisso do iniciante e o desafio; a chave dele passa
/// nas conferências; e a janela a aceita — uma por janela, só a do desafio
/// dela. Então a segunda, e a janela está ocupada.
fn primeira_mensagem(v: u8, g: u64, corpo: &[u8]) -> bool {
    if !crate::autorizacao::permitir_aperto_do_enlace(v) {
        if let Ok(q) = quadro::montar(Tipo::Recusa, b"apertos demais; espere a janela") {
            por_na_vaga(v, g, &q);
        }
        encerrar_vaga(v, g);
        return false;
    }
    let mut carga = vec![0u8; corpo.len()];
    let lido = crate::identidade::com_chave_do_duke(|k| {
        Respondedor::novo(sigilo::PROLOGO_DO_PAREAMENTO, k).ler(corpo, &mut carga)
    });
    let (n, recebido) = match lido {
        None => return recusar_na_vaga(v, g, None, Codigo::Error, "o Duke nao tem chave"),
        Some(Err(e)) => {
            return recusar_na_vaga(v, g, None, Codigo::DenyNotAuthenticated, e.motivo());
        }
        Some(Ok(r)) => r,
    };
    let chave = recebido.remota();
    let j = Json(&carga[..n]);
    let compromisso = j
        .member("commit")
        .and_then(|x| x.as_str())
        .and_then(sigilo::de_hex_fixo::<32>);
    let desafio = j
        .member("janela")
        .and_then(|x| x.as_str())
        .and_then(sigilo::de_hex_fixo::<{ conta::TAM_DESAFIO }>);
    let (Some(compromisso), Some(desafio)) = (compromisso, desafio) else {
        return recusar_na_vaga(
            v,
            g,
            Some(chave),
            Codigo::InvalidArgument,
            "a primeira mensagem nao traz o compromisso e o desafio",
        );
    };
    if crate::energia::pedida().is_some() {
        return recusar_na_vaga(
            v,
            g,
            Some(chave),
            Codigo::Conflict,
            "a maquina esta desligando",
        );
    }
    if let Err((_, codigo, motivo)) = par_aceitavel(&chave) {
        return recusar_na_vaga(v, g, Some(chave), codigo, motivo);
    }
    let quem = com(|x| {
        x.as_ref()
            .filter(|x| x.c.lado() == Lado::Aceita && !x.c.acabou())
            .map(|x| (x.numero, x.pessoa, x.nome.clone()))
    });
    let Some((numero, pessoa, nome)) = quem else {
        return recusar_na_vaga(
            v,
            g,
            Some(chave),
            Codigo::DenyNotAuthenticated,
            "sem janela de pareamento aberta",
        );
    };
    if let Err(motivo) = nome_e_chave(&nome, &pessoa, &chave) {
        return recusar_na_vaga(v, g, Some(chave), Codigo::InvalidArgument, motivo);
    }
    let reservada = com(|x| {
        let Some(x) = viva(x, numero) else {
            return Err(Recusa::Acabou);
        };
        x.c.primeira_mensagem(agora(), &desafio, chave, compromisso)?;
        x.vaga = Some((v, g));
        Ok(())
    });
    if let Err(r) = reservada {
        let (codigo, motivo) = match r {
            Recusa::DesafioErrado => (
                Codigo::DenyNotAuthenticated,
                "o desafio nao e o desta janela",
            ),
            Recusa::Ocupada => (
                Codigo::Conflict,
                "ocupado: a janela ja respondeu a outro dispositivo",
            ),
            Recusa::Vencida => (Codigo::DenyNotAuthenticated, "a janela venceu"),
            _ => (
                Codigo::DenyNotAuthenticated,
                "sem janela de pareamento aberta",
            ),
        };
        return recusar_na_vaga(v, g, Some(chave), codigo, motivo);
    }
    // A segunda mensagem, fora da trava: a janela já está ocupada por esta
    // conexão, e o iniciante não manda nada até recebê-la.
    let resposta = crate::aleatorio::chave().ok().and_then(|efemera| {
        let mut saida = vec![0u8; 128];
        let (m, t) = recebido.escrever(efemera, b"{}", &mut saida).ok()?;
        let q = quadro::montar(Tipo::Resposta, &saida[..m]).ok()?;
        Some((q, t))
    });
    let posta = com(|x| {
        let x = viva(x, numero)?;
        if x.vaga != Some((v, g)) || x.c.estado() != Estado::Ocupada {
            return Some(Err(None));
        }
        let Some((q, t)) = resposta else {
            x.recusa = Some((
                Codigo::Error,
                String::from("a segunda mensagem nao se escreveu"),
            ));
            return Some(Err(acabar(x, Motivo::Conexao, false)));
        };
        x.resumo = Some(t.resumo_do_aperto());
        x.transporte = Some(t);
        Some(if por(x, q) {
            Ok(())
        } else {
            x.recusa = Some((Codigo::Error, String::from("a segunda mensagem nao saiu")));
            Err(acabar(x, Motivo::Conexao, false))
        })
    });
    match posta {
        Some(Ok(())) => {
            let par = crate::rede::canal::remoto_da_conexao(v, g)
                .map_or_else(|| String::from("tcp"), crate::rede::canal::texto_do_par);
            crate::autorizacao::auditar_aperto_do_pareamento(
                Some(chave),
                Codigo::Allow,
                &format!(
                    "aperto da cerimonia ({}, {par})",
                    crate::identidade::impressao(&chave)
                ),
            );
            true
        }
        Some(Err(Some(f))) => {
            contar_o_fim(f, true);
            false
        }
        _ => {
            encerrar_vaga(v, g);
            false
        }
    }
}

/// O que um passo da cerimônia deixou a fazer fora da trava.
#[derive(Default)]
struct Depois {
    fim: Option<Fim>,
    /// O aperto fechou: os códigos à mostra, no console da cerimônia.
    codigos: Option<(Console, u64, String)>,
    /// A chave do iniciante se provou: o prazo do aperto da vaga para.
    identificar: Option<(u8, u64, [u8; 32])>,
    acordar_o_console: bool,
}

impl Depois {
    fn fazer(self) {
        if let Some((v, g, k)) = self.identificar {
            identificar_na_vaga(v, g, k);
        }
        andar();
        if let Some((console, abertura, texto)) = self.codigos {
            avisar(console, abertura, &texto);
        }
        if self.acordar_o_console {
            crate::teclado::despertar_o_interpretador();
        }
        if let Some(f) = self.fim {
            contar_o_fim(f, true);
        }
    }
}

/// O texto dos códigos, para a Pessoa: o que ela digita no **outro**, e as
/// impressões das duas chaves.
fn texto_dos_codigos(x: &Viva, eu: &str) -> String {
    let k =
        x.c.codigo_a_mostrar()
            .map(conta::texto_do_codigo)
            .unwrap_or_default();
    format!(
        "pareando com {}; este Duke e {eu}.\nNo outro dispositivo, digite: {k}\nAqui, digite so o codigo que aparece no seu outro dispositivo; ninguem mais precisa dele.",
        impressao_de(x.c.par())
    )
}

/// Uma mensagem cifrada da cerimônia, sob a trava: abre, lê e dá o passo.
/// Falso se a cerimônia acabou por ela.
fn receber_dados(x: &mut Viva, corpo: &[u8], eu: &str, depois: &mut Depois) -> bool {
    let aberta = match x.transporte.as_mut() {
        Some(t) if corpo.len() <= MAIOR_MENSAGEM + 16 => {
            let mut claro = vec![0u8; corpo.len()];
            let lida = t
                .decifrar(corpo, &mut claro)
                .ok()
                .and_then(|n| ler_mensagem(&claro[..n]));
            politica::sigiloso::zerar(&mut claro);
            lida
        }
        _ => None,
    };
    let Some(m) = aberta else {
        // Adulterada, repetida, fora de ordem, ou nenhuma das quatro: a
        // sessão não é mais de confiança, e a cerimônia acaba.
        depois.fim = acabar(x, Motivo::ForaDoProtocolo, true);
        return false;
    };
    match m {
        Recebida::Nonce(n) if x.c.lado() == Lado::Aceita => {
            let h = x.resumo.unwrap_or([0; 32]);
            match x.c.nonce_aberto(agora(), &h, n) {
                Ok(()) => {
                    if let (Some((v, g)), Some(k)) = (x.vaga, x.c.par()) {
                        depois.identificar = Some((v, g, k));
                    }
                    depois.codigos = Some((x.console, x.abertura, texto_dos_codigos(x, eu)));
                    true
                }
                Err(Recusa::CompromissoErrado) => {
                    depois.fim = acabar(x, Motivo::CompromissoErrado, true);
                    false
                }
                Err(Recusa::Vencida | Recusa::Acabou) => {
                    depois.fim = acabar(x, Motivo::Prazo, true);
                    false
                }
                Err(_) => {
                    depois.fim = acabar(x, Motivo::ForaDoProtocolo, true);
                    false
                }
            }
        }
        Recebida::Conferido => match x.c.conferido_do_outro(agora()) {
            Ok(true) => {
                x.devido = Some(Devido::Gravar);
                depois.acordar_o_console = true;
                true
            }
            Ok(false) => true,
            Err(Recusa::Vencida | Recusa::Acabou) => {
                depois.fim = acabar(x, Motivo::Prazo, true);
                false
            }
            Err(_) => {
                depois.fim = acabar(x, Motivo::ForaDoProtocolo, true);
                false
            }
        },
        Recebida::Gravado(r) => match x.c.gravado_do_outro(&r) {
            Ok(()) => {
                depois.fim = fim_de(x);
                depois.fim.is_none()
            }
            Err(Recusa::RelacaoDiferente) => {
                depois.fim = acabar(x, Motivo::RelacaoDiferente, true);
                depois.acordar_o_console = x.devido.is_some();
                false
            }
            Err(_) => {
                depois.fim = acabar(x, Motivo::ForaDoProtocolo, true);
                false
            }
        },
        Recebida::Desistiu(texto) => {
            x.do_outro = Some(texto);
            depois.fim = acabar(x, Motivo::OutroDesistiu, false);
            depois.acordar_o_console = x.devido.is_some();
            false
        }
        Recebida::Nonce(_) => {
            depois.fim = acabar(x, Motivo::ForaDoProtocolo, true);
            false
        }
    }
}

/// Um quadro de dados numa vaga: só o da conexão que ocupou a janela.
fn dados_na_vaga(v: u8, g: u64, corpo: &[u8]) -> bool {
    let eu = impressao_de(crate::identidade::publica_do_duke());
    let mut depois = Depois::default();
    let continua = com(|x| {
        let x = x.as_mut().filter(|x| x.vaga == Some((v, g)))?;
        Some(receber_dados(x, corpo, &eu, &mut depois))
    });
    depois.fazer();
    match continua {
        Some(c) => c,
        None => fora_do_protocolo_na_vaga(v, g),
    }
}

/// Um quadro que a sessão de cerimônia não conhece — o de um enlace, o de
/// um agente —: se a conexão é a da cerimônia, ela acaba; e a conexão fecha.
fn fora_do_protocolo_na_vaga(v: u8, g: u64) -> bool {
    let f = com(|x| {
        let x = x.as_mut().filter(|x| x.vaga == Some((v, g)))?;
        acabar(x, Motivo::ForaDoProtocolo, true)
    });
    match f {
        Some(f) => {
            contar_o_fim(f, true);
            false
        }
        None => recusar_na_vaga(
            v,
            g,
            None,
            Codigo::InvalidArgument,
            "quadro fora do protocolo da cerimonia",
        ),
    }
}

/// A conexão `g` da vaga `v` acabou: se era a da cerimônia, ela acaba.
pub fn vaga_acabou(v: u8, g: u64) {
    if !HA.load(Ordering::Acquire) {
        return;
    }
    let f = com(|x| {
        let x = x.as_mut().filter(|x| x.vaga == Some((v, g)))?;
        x.vaga = None;
        acabar(x, Motivo::Conexao, false)
    });
    if let Some(f) = f {
        contar_o_fim(f, true);
    }
}

// ---------------------------------------------------------------------
// O que inicia: o fio da cerimônia.
// ---------------------------------------------------------------------

/// O endereço da cerimônia que o fio conduz.
pub fn endereco_do_iniciante() -> Option<String> {
    com(|g| {
        g.as_ref()
            .filter(|x| x.c.lado() == Lado::Inicia && !x.c.acabou())
            .and_then(|x| x.endereco.clone())
    })
}

/// O fio da cerimônia acabou.
pub fn fio_saiu() {
    com(|g| {
        if let Some(x) = g.as_mut() {
            x.fio = false;
        }
    });
}

/// O fio não conectou ao outro: a cerimônia acaba.
pub fn nao_conectou(codigo: Codigo, motivo: &'static str) {
    let f = com(|g| {
        let x = g.as_mut().filter(|x| x.c.lado() == Lado::Inicia)?;
        x.recusa = Some((codigo, String::from(motivo)));
        acabar(x, Motivo::Conexao, false)
    });
    if let Some(f) = f {
        contar_o_fim(f, true);
    }
}

/// Acaba a cerimônia do fio, e conta.
fn acabar_no_fio(
    numero: u64,
    motivo: Motivo,
    avisar_o_par: bool,
    recusa: Option<(Codigo, String)>,
) {
    let f = com(|g| {
        let x = viva(g, numero)?;
        if x.recusa.is_none() {
            x.recusa = recusa;
        }
        acabar(x, motivo, avisar_o_par)
    });
    if let Some(f) = f {
        contar_o_fim(f, true);
    }
}

/// Conduz a cerimônia do iniciante pela via `via` — a conexão TCP pelo
/// gate, no fio da cerimônia; a via de teste, na suíte: o aperto, e então a
/// conversa, até o fim.
pub fn conduzir(via: &mut impl Via) {
    let Some(numero) = com(|g| {
        g.as_ref()
            .filter(|x| x.c.lado() == Lado::Inicia && !x.c.acabou())
            .map(|x| x.numero)
    }) else {
        return;
    };
    let mut leitor = Leitor::novo();
    let mut guardado = Vec::new();
    if let Err((motivo, avisar_o_par, recusa)) =
        apertar_como_iniciante(via, numero, &mut leitor, &mut guardado)
    {
        acabar_no_fio(numero, motivo, avisar_o_par, recusa);
        esvaziar(via, numero);
        return;
    }
    conversar(via, numero, &mut leitor, &mut guardado);
}

/// Manda o que está na fila — o `desistiu` do fim, o `gravado` —, sem
/// esperar nada.
fn esvaziar(via: &mut impl Via, numero: u64) {
    let quadros: Vec<Vec<u8>> = com(|g| {
        viva(g, numero)
            .map(|x| x.saida.drain(..).collect())
            .unwrap_or_default()
    });
    for q in quadros {
        if via.mandar(&q).is_err() {
            return;
        }
    }
}

type FalhaDoAperto = (Motivo, bool, Option<(Codigo, String)>);

/// O aperto do iniciante: o pedido da chave, o anúncio conferido, a
/// primeira mensagem com o compromisso e o desafio, a segunda, e o nonce.
fn apertar_como_iniciante(
    via: &mut impl Via,
    numero: u64,
    leitor: &mut Leitor,
    guardado: &mut Vec<u8>,
) -> Result<(), FalhaDoAperto> {
    let conexao = |m: &'static str| {
        (
            Motivo::Conexao,
            false,
            Some((Codigo::Error, String::from(m))),
        )
    };
    let pedido =
        quadro::montar(Tipo::PedidoDaChave, &[]).map_err(|_| conexao("o pedido nao se montou"))?;
    via.mandar(&pedido).map_err(|(_, m)| conexao(m))?;
    let limite = crate::tempo::uptime_ms().saturating_add(PRAZO_DO_QUADRO_MS);
    let (tipo, corpo) = crate::enlace::proximo_quadro(via, leitor, guardado, limite)
        .map_err(|(_, m)| conexao(m))?;
    let (pk, w) = match tipo {
        Tipo::ChaveDoDuke if corpo.len() == 32 + conta::TAM_DESAFIO => {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&corpo[..32]);
            let mut w = [0u8; conta::TAM_DESAFIO];
            w.copy_from_slice(&corpo[32..]);
            (pk, w)
        }
        Tipo::Recusa => return Err(recusa_do_outro(&corpo)),
        _ => return Err((Motivo::ForaDoProtocolo, false, None)),
    };
    // A chave anunciada: a espécie, a lápide, a suspensão, o nome. O aperto
    // que vem depois a prova — ou não fecha.
    if let Err((motivo, codigo, m)) = par_aceitavel(&pk) {
        return Err((motivo, false, Some((codigo, String::from(m)))));
    }
    let quem = com(|g| viva(g, numero).map(|x| (x.pessoa, x.nome.clone())));
    let Some((pessoa, nome)) = quem else {
        return Err((Motivo::Cancelada, false, None));
    };
    if let Err(m) = nome_e_chave(&nome, &pessoa, &pk) {
        return Err((
            Motivo::Recusada,
            false,
            Some((Codigo::InvalidArgument, String::from(m))),
        ));
    }
    let compromisso = com(|g| {
        let x = viva(g, numero)?;
        x.c.anuncio(agora(), pk, w).ok()?;
        x.c.compromisso_a_mandar()
    })
    .ok_or((Motivo::Prazo, false, None))?;
    // A primeira mensagem: o compromisso e o desafio, cifrados.
    let carga = format!(
        r#"{{"commit":"{}","janela":"{}"}}"#,
        sigilo::hex_de(&compromisso),
        sigilo::hex_de(&w)
    );
    let efemera = crate::aleatorio::chave().map_err(|_| conexao("sem entropia para o aperto"))?;
    let mut primeira = vec![0u8; 512];
    let escrito = crate::identidade::com_chave_do_duke(|k| {
        Iniciador::novo(sigilo::PROLOGO_DO_PAREAMENTO, k, &pk).escrever(
            efemera,
            carga.as_bytes(),
            &mut primeira,
        )
    });
    let (n, aguardando) = match escrito {
        None => return Err(conexao("o Duke nao tem chave")),
        Some(Err(e)) => {
            return Err((
                Motivo::Recusada,
                false,
                Some((Codigo::DenyNotAuthenticated, String::from(e.motivo()))),
            ));
        }
        Some(Ok(r)) => r,
    };
    let q = quadro::montar(Tipo::InicioPareamento, &primeira[..n])
        .map_err(|_| conexao("a primeira mensagem nao cabe num quadro"))?;
    via.mandar(&q).map_err(|(_, m)| conexao(m))?;
    com(|g| viva(g, numero).map(|x| x.c.primeira_mandada(agora()).is_ok()))
        .filter(|ok| *ok)
        .ok_or((Motivo::Prazo, false, None))?;
    // A segunda: o aperto fecha só com a chave anunciada.
    let limite = crate::tempo::uptime_ms().saturating_add(PRAZO_DO_QUADRO_MS);
    let (tipo, corpo) = crate::enlace::proximo_quadro(via, leitor, guardado, limite)
        .map_err(|(_, m)| conexao(m))?;
    let transporte = match tipo {
        Tipo::Resposta => {
            let mut lixo = vec![0u8; corpo.len()];
            aguardando
                .ler(&corpo, &mut lixo)
                .map_err(|_| (Motivo::ParNaoProvou, false, None))?
                .1
        }
        Tipo::Recusa => return Err(recusa_do_outro(&corpo)),
        _ => return Err((Motivo::ForaDoProtocolo, false, None)),
    };
    let h = transporte.resumo_do_aperto();
    // O nonce sai, e os códigos aparecem.
    let eu = impressao_de(crate::identidade::publica_do_duke());
    let mut depois = Depois::default();
    let ok = com(|g| {
        let x = viva(g, numero)?;
        match x.c.segunda_mensagem(agora(), &h) {
            Ok(mut nonce) => {
                x.transporte = Some(transporte);
                x.resumo = Some(h);
                mandar(x, mensagem_do_nonce(&nonce).as_bytes());
                politica::sigiloso::zerar(&mut nonce);
                depois.codigos = Some((x.console, x.abertura, texto_dos_codigos(x, &eu)));
                Some(())
            }
            Err(_) => None,
        }
    });
    depois.fazer();
    ok.ok_or((Motivo::Prazo, false, None))
}

/// O que o outro disse ao recusar, em claro: curto e ASCII.
fn recusa_do_outro(corpo: &[u8]) -> FalhaDoAperto {
    let mut texto: String = corpo
        .iter()
        .take(MAIOR_MOTIVO_DO_OUTRO)
        .map(|&c| {
            if c.is_ascii_graphic() || c == b' ' {
                c as char
            } else {
                '?'
            }
        })
        .collect();
    if texto.is_empty() {
        texto = String::from("recusado");
    }
    (
        Motivo::OutroDesistiu,
        false,
        Some((
            Codigo::DenyNotAuthenticated,
            format!("o outro recusou: {texto}"),
        )),
    )
}

/// A conversa do iniciante, depois do aperto: manda o que a cerimônia pôs
/// na fila, lê o que o outro manda, até o fim — e o que o fim deixou na
/// fila sai também.
fn conversar(via: &mut impl Via, numero: u64, leitor: &mut Leitor, guardado: &mut Vec<u8>) {
    let eu = impressao_de(crate::identidade::publica_do_duke());
    loop {
        let (quadros, acabou) = com(|g| match viva(g, numero) {
            Some(x) => (x.saida.drain(..).collect::<Vec<_>>(), x.c.acabou()),
            None => (Vec::new(), true),
        });
        for q in quadros {
            if via.mandar(&q).is_err() {
                acabar_no_fio(numero, Motivo::Conexao, false, None);
                return;
            }
        }
        if acabou {
            return;
        }
        let chegou = match via.receber(PASSO_MS) {
            Ok(b) => b,
            Err(_) => {
                // A conexão caiu: a cerimônia acaba — ou, com a gravação em
                // curso, a desistência espera por ela —, e o fio sai.
                acabar_no_fio(numero, Motivo::Conexao, false, None);
                return;
            }
        };
        guardado.extend_from_slice(&chegou);
        while !guardado.is_empty() {
            let b = guardado.remove(0);
            let quadro = match leitor.empurrar(b) {
                Ok(Some((tipo, corpo))) => (tipo, corpo.to_vec()),
                Ok(None) => continue,
                Err(_) => {
                    acabar_no_fio(numero, Motivo::ForaDoProtocolo, true, None);
                    break;
                }
            };
            let mut depois = Depois::default();
            com(|g| {
                let Some(x) = viva(g, numero) else {
                    return;
                };
                match quadro.0 {
                    Tipo::Dados => {
                        receber_dados(x, &quadro.1, &eu, &mut depois);
                    }
                    Tipo::Recusa => {
                        let (_, _, recusa) = recusa_do_outro(&quadro.1);
                        if x.recusa.is_none() {
                            x.recusa = recusa;
                        }
                        depois.fim = acabar(x, Motivo::OutroDesistiu, false);
                        depois.acordar_o_console = x.devido.is_some();
                    }
                    _ => depois.fim = acabar(x, Motivo::ForaDoProtocolo, true),
                }
            });
            depois.fazer();
        }
    }
}

// ---------------------------------------------------------------------
// Os prazos, a revogação, o fim da sessão, o desligamento.
// ---------------------------------------------------------------------

/// O coletor, a cada tique: [`vencer`]. Na suíte, quem vence é o caso: ele
/// conduz a cerimônia passo a passo, os dois lados, e o coletor de outro
/// núcleo não a acaba — nem a libera — no meio de um passo dele.
pub fn passada_do_coletor() {
    #[cfg(not(feature = "modo-teste"))]
    vencer();
}

/// O prazo da janela e o da cerimônia; a sessão da Pessoa que acabou; o
/// desligamento pedido. E a cerimônia acabada que ninguém precisa mais
/// sai.
pub fn vencer() {
    if !HA.load(Ordering::Acquire) {
        return;
    }
    let Some((numero, sessao)) = com(|g| g.as_ref().map(|x| (x.numero, x.sessao))) else {
        return;
    };
    let sessao_vale = matches!(crate::pessoas::sessao(sessao), EstadoDaSessao::Ativa { .. });
    let desligando = crate::energia::pedida().is_some();
    let f = com(|g| {
        let x = g.as_mut().filter(|x| x.numero == numero)?;
        if x.c.acabou() {
            if liberavel(x) {
                *g = None;
            }
            return None;
        }
        if x.c.vencer(agora()).is_some() {
            return acabar(x, Motivo::Prazo, true);
        }
        if !sessao_vale {
            return acabar(x, Motivo::FimDaSessao, true);
        }
        if desligando {
            return acabar(x, Motivo::Desligamento, true);
        }
        None
    });
    if let Some(f) = f {
        andar();
        contar_o_fim(f, true);
    }
}

/// A chave do outro foi revogada ou suspensa aqui — ver
/// [`crate::enlace::dispositivo_saiu`]: a cerimônia com ela acaba.
pub fn par_saiu(chave: &[u8; 32], codigo: Codigo) {
    if !HA.load(Ordering::Acquire) {
        return;
    }
    let f = com(|g| {
        let x = g.as_mut()?;
        if x.c.par() != Some(*chave) {
            return None;
        }
        let motivo = if codigo == Codigo::DenyCredential {
            Motivo::ParSuspenso
        } else {
            Motivo::ParRevogado
        };
        acabar(x, motivo, true)
    });
    if let Some(f) = f {
        andar();
        contar_o_fim(f, true);
    }
}

// ---------------------------------------------------------------------
// `device.forget`: a Pessoa desfaz a relação dela.
// ---------------------------------------------------------------------

/// O que `device.forget` desfez.
pub struct Esquecida {
    pub chave: [u8; 32],
    pub relacao: [u8; 16],
    /// Era a última relação do dispositivo: ele saiu do registro, sem
    /// lápide.
    pub dispositivo_saiu: bool,
    /// As entregas vivas pela relação, anuladas.
    pub anuladas: usize,
}

/// `device.forget dispositivo:<nome>`: a relação **da Pessoa de quem pede**
/// com o dispositivo de nome `<nome>` sai — e só ela. O nome se resolve no
/// espaço dela: a de outra Pessoa responde o mesmo que a que não existe.
/// Com a ordem das gravações na mão: a decisão de novo, o registro, e o
/// journal (o registro 44, com a decisão). Depois, o que andava por ela —
/// as entregas, os pedidos, os enlaces, se era a última.
pub fn esquecer_pelo_comando(alvo: &str) -> Result<Esquecida, (Codigo, &'static str)> {
    let nome = politica::arquivo::nome_de_dispositivo(alvo).ok_or((
        Codigo::InvalidArgument,
        "`device` nao e `dispositivo:<nome>`",
    ))?;
    let pessoa = match crate::autorizacao::autoridade_atual() {
        crate::autorizacao::Autoridade::Pessoa { sessao } => crate::pessoas::dona_da_sessao(sessao),
        _ => None,
    }
    .ok_or((
        Codigo::DenyResource,
        "o dispositivo nao existe para quem pede",
    ))?;
    let (chave, relacao, saiu, gravada) = crate::persistencia::em_ordem(|| {
        #[cfg(feature = "modo-teste")]
        crate::autorizacao::gancho_da_reconfirmacao();
        crate::autorizacao::reconfirmar()?;
        let (chave, rel) = crate::dispositivos::da_pessoa(nome, &pessoa.0).ok_or((
            Codigo::DenyResource,
            "o dispositivo nao existe para quem pede",
        ))?;
        let foto = crate::persistencia::Foto::tirar();
        let (_, saiu) =
            crate::dispositivos::esquecer(&chave, &rel.id).map_err(|r| (r.codigo(), r.motivo()))?;
        let gravada = crate::persistencia::concluir(
            &foto,
            crate::autorizacao::ESQUECIMENTO,
            alvo,
            false,
            crate::autorizacao::decisao_atual().unwrap_or(0),
        )
        .is_ok();
        Ok::<_, (Codigo, &'static str)>((chave, rel.id, saiu, gravada))
    })?;
    let anuladas = crate::enlace::relacao_saiu(&chave, &relacao, saiu);
    if !gravada {
        return Err((
            Codigo::Error,
            "a desfeita nao ficou gravada no journal: vale ate o boot",
        ));
    }
    crate::log_info!(
        "pareamento",
        "relacao {} com {} desfeita{}",
        id8(&relacao),
        crate::identidade::impressao(&chave),
        if saiu { "; o dispositivo saiu" } else { "" }
    );
    Ok(Esquecida {
        chave,
        relacao,
        dispositivo_saiu: saiu,
        anuladas,
    })
}

// ---------------------------------------------------------------------
// O relatório e a suíte.
// ---------------------------------------------------------------------

/// A cerimônia em curso, como o `device.registry` a mostra: o lado, o passo,
/// o nome, a impressão do par e o tempo que falta. Nunca o código, o nonce,
/// o desafio ou o resumo do aperto.
pub struct Resumo {
    pub lado: &'static str,
    pub passo: &'static str,
    pub nome: String,
    pub par: Option<String>,
    pub restante_ms: u64,
    pub console: String,
}

/// O resumo da cerimônia em curso, se há uma.
pub fn resumo() -> Option<Resumo> {
    if !HA.load(Ordering::Acquire) {
        return None;
    }
    com(|g| {
        let x = g.as_ref().filter(|x| !x.c.acabou())?;
        Some(Resumo {
            lado: match x.c.lado() {
                Lado::Aceita => "accept",
                Lado::Inicia => "initiate",
            },
            passo: match x.c.estado() {
                Estado::Aberta => "open",
                Estado::Ocupada => "handshake",
                Estado::Apertada => "code",
                Estado::CodigoCerto => "password",
                Estado::ConferidaAqui => "confirmed",
                Estado::Gravando => "recording",
                Estado::Gravada => "recorded",
                Estado::Fim(_) => "ended",
            },
            nome: x.nome.clone(),
            par: x.c.par().map(|k| crate::identidade::impressao(&k)),
            restante_ms: x.c.restante_ms(agora()),
            console: x.console.texto(),
        })
    })
}

/// Para o invariante da suíte: a cerimônia nunca quebra as regras dela, e a
/// porta só escuta por uma janela viva.
#[cfg(feature = "modo-teste")]
pub fn coerente() -> bool {
    com(|g| {
        let escuta = g
            .as_ref()
            .is_some_and(|x| x.c.lado() == Lado::Aceita && !x.c.acabou());
        g.as_ref().is_none_or(|x| {
            x.c.coerente()
                && (x.c.acabou() || !x.avisada)
                && (!x.c.acabou() || x.transporte.is_none())
        }) && escuta == escutando()
    })
}

/// Só para a suíte: conduz a cerimônia do iniciante pela via de teste — a
/// mesma conversa do fio.
#[cfg(feature = "modo-teste")]
pub fn conduzir_de_teste(via: &mut impl Via) {
    conduzir(via);
}

/// Só para a suíte: o que iria às vagas fica guardado para o caso ler
/// ([`tirar_das_vagas_de_teste`]); com `false`, volta a ir às vagas.
#[cfg(feature = "modo-teste")]
pub fn saida_de_teste(guardar: bool) {
    crate::arch::sem_interrupcoes(|| {
        *VAGAS_DE_TESTE.lock() = guardar.then(Vec::new);
    });
}

/// Só para a suíte: o que a cerimônia fez nas vagas desde a última vez.
#[cfg(feature = "modo-teste")]
pub fn tirar_das_vagas_de_teste() -> Vec<NaVaga> {
    crate::arch::sem_interrupcoes(|| {
        VAGAS_DE_TESTE
            .lock()
            .as_mut()
            .map(core::mem::take)
            .unwrap_or_default()
    })
}

/// Só para a suíte: o relógio da cerimônia adiantado de `ms`.
#[cfg(feature = "modo-teste")]
pub fn adiantar_de_teste(ms: u64) {
    ADIANTE.fetch_add(ms, Ordering::Relaxed);
}

/// Só para a suíte: o estado da cerimônia, se há uma.
#[cfg(feature = "modo-teste")]
pub fn estado_de_teste() -> Option<(Lado, Estado)> {
    com(|g| g.as_ref().map(|x| (x.c.lado(), x.c.estado())))
}

/// Só para a suíte: o commit pedido de novo na cerimônia de agora — o que
/// um passo repetido do console pediria —, para conferir a resposta
/// guardada: uma relação, um registro.
#[cfg(feature = "modo-teste")]
pub fn gravar_de_novo_de_teste() -> String {
    match com(|g| g.as_ref().map(|x| x.numero)) {
        Some(numero) => gravar(numero),
        None => String::new(),
    }
}

/// Só para a suíte: o desafio da janela aberta — o que o anúncio leva.
#[cfg(feature = "modo-teste")]
pub fn desafio_de_teste() -> Option<[u8; conta::TAM_DESAFIO]> {
    com(|g| g.as_ref().and_then(|x| x.c.desafio()))
}

/// Só para a suíte: nenhuma cerimônia, nada guardado, o relógio de volta.
#[cfg(feature = "modo-teste")]
pub fn esquecer_de_teste() {
    com(|g| *g = None);
    ADIANTE.store(0, Ordering::Relaxed);
    saida_de_teste(false);
}

/// Destrava a cerimônia, para o caminho de falha fatal.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        CERIMONIA.force_unlock();
        #[cfg(feature = "modo-teste")]
        VAGAS_DE_TESTE.force_unlock();
    }
}
