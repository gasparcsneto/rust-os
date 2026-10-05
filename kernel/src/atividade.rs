//! Quem está agindo na máquina: os agentes conectados, e quem agiu por
//! último.
//!
//! # O que a pessoa precisa saber
//!
//! Que não está sozinha. Com agentes conectados, o que muda na tela pode
//! não ter sido ela — e a barra diz, o tempo todo, quantos agentes estão nas
//! portas e quem foi o último a agir: `agentes: 2 · último: teste-1
//! (operador)`. Os agentes leem o mesmo texto na árvore, e a lista inteira
//! — cada um, o papel, o último comando e há quanto tempo — no
//! `agent.list`. Ninguém precisa de outro canal para saber quem está aqui.
//!
//! # Onde a conta é feita
//!
//! No ponto de decisão, e só nele — [`crate::autorizacao`] chama
//! [`registrar`] depois de um `ALLOW`, e mais ninguém chama. Não há como
//! agir sem passar por lá, então não há como agir sem aparecer aqui: um
//! indicador alimentado por quem age, e não pela decisão, mostraria só quem
//! quisesse ser mostrado. Uma recusa não conta — quem foi recusado não
//! agiu.
//!
//! # O que conta como agir
//!
//! Exercer uma permissão que muda o estado — ver
//! [`politica::Permissao::muda_estado`]. Ler a árvore, o log ou a caixa de
//! mensagens não é agir: um agente que só observa não toma o "último" de
//! quem mexeu na tela. O **último comando** de cada sessão conta qualquer
//! um que passou, leitura ou não: é o que ela está fazendo, e não o que ela
//! mudou.
//!
//! A pessoa entra pelo mesmo critério: um comando no interpretador, uma
//! tecla de função ou um clique num botão da barra passam pela decisão e
//! aparecem como `pessoa:<nome>`. A tecla digitada numa linha, não: quem
//! digita está diante da tela, e a linha arrendada já diz de quem ela é. O
//! administrador pela prova aparece como `admin:<nome>`, e o processo do
//! sistema não aparece — ele age por quem o lançou, que já apareceu ao
//! lançá-lo.
//!
//! # Os nomes não se confundem
//!
//! O nome de um agente não tem `:` — a regra do registro —, então nenhum
//! agente se chama `pessoa:ana` nem `admin:raiz`, e o rótulo diz de que
//! tipo é quem agiu sem precisar de mais nada.

use alloc::string::String;

use crate::trava::Mutex;

use crate::sessoes::PORTAS;

/// Quem agiu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ator {
    /// Uma sessão de agente numa porta, com a chave que provou o aperto.
    Agente {
        sessao: u8,
        chave: [u8; 32],
        nome: String,
    },
    /// A serial: o canal de controle.
    Serial,
    /// Uma pessoa do registro, pela sessão dela.
    Pessoa { nome: String },
    /// Um administrador, pela prova.
    Administrador { nome: String },
}

impl Ator {
    /// Como a barra o escreve.
    pub fn rotulo(&self) -> String {
        match self {
            Ator::Agente { nome, .. } => nome.clone(),
            Ator::Serial => String::from("serial"),
            Ator::Pessoa { nome } => alloc::format!("pessoa:{nome}"),
            Ator::Administrador { nome } => alloc::format!("admin:{nome}"),
        }
    }
}

/// A última ação: quem, com que papel, qual comando, e quando.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acao {
    pub rotulo: String,
    pub papel: String,
    pub metodo: &'static str,
    pub quando_ms: u64,
}

/// O que uma sessão de agente fez: o último comando que passou e a última
/// ação — cada um com o momento.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uso {
    /// A chave de quem está na sessão: uma sessão nova na mesma porta, de
    /// outro agente, não herda o que o anterior fez.
    chave: [u8; 32],
    pub comando: Option<(&'static str, u64)>,
    pub acao: Option<(&'static str, u64)>,
}

// Tomadas sempre por `sem_interrupcoes`, como toda tranca deste kernel, e
// soltas no caminho fatal.
static ULTIMA: Mutex<Option<Acao>> = Mutex::new(None);
static USOS: Mutex<[Option<Uso>; PORTAS]> = Mutex::new([None; PORTAS]);

/// Registra que `ator`, com `papel`, passou pela decisão com `metodo`; com
/// `muda`, a permissão que exerceu muda o estado — e ele passa a ser o
/// "último" da barra.
///
/// Só a decisão chama — ver o cabeçalho.
pub(crate) fn registrar(ator: Ator, papel: &str, metodo: &'static str, muda: bool) {
    let agora = crate::tempo::uptime_ms();
    crate::arch::sem_interrupcoes(|| {
        if let Ator::Agente { sessao, chave, .. } = &ator
            && let Some(i) = indice(*sessao)
        {
            let mut usos = USOS.lock();
            let uso = usos[i].get_or_insert(Uso {
                chave: *chave,
                comando: None,
                acao: None,
            });
            if uso.chave != *chave {
                *uso = Uso {
                    chave: *chave,
                    comando: None,
                    acao: None,
                };
            }
            uso.comando = Some((metodo, agora));
            if muda {
                uso.acao = Some((metodo, agora));
            }
        }
        if muda {
            *ULTIMA.lock() = Some(Acao {
                rotulo: ator.rotulo(),
                papel: String::from(papel),
                metodo,
                quando_ms: agora,
            });
        }
    });
    if muda {
        crate::barra::atualizar_indicador();
    }
}

fn indice(p: u8) -> Option<usize> {
    (1..=PORTAS as u8).contains(&p).then(|| usize::from(p) - 1)
}

/// A última ação, de quem quer que seja.
pub fn ultima() -> Option<Acao> {
    crate::arch::sem_interrupcoes(|| ULTIMA.lock().clone())
}

/// O que a sessão `p` fez, se é de quem tem a `chave`.
pub fn uso(p: u8, chave: &[u8; 32]) -> Option<Uso> {
    let i = indice(p)?;
    crate::arch::sem_interrupcoes(|| USOS.lock()[i].filter(|u| u.chave == *chave))
}

/// A sessão da porta `p` acabou: o que ela fez sai com ela. O "último" da
/// barra fica — ele diz quem agiu, e isso não deixa de ter acontecido.
pub fn sessao_acabou(p: u8) {
    if let Some(i) = indice(p) {
        crate::arch::sem_interrupcoes(|| USOS.lock()[i] = None);
    }
    crate::barra::atualizar_indicador();
}

/// As portas com um agente conectado agora: a sessão estabelecida, e a
/// chave ainda no registro. Uma chave revogada sai da conta na hora, antes
/// de a porta cair — ela já não age.
pub fn conectados() -> impl Iterator<Item = (u8, crate::sessoes::Identificada)> {
    (1..=PORTAS as u8).filter_map(|p| {
        crate::sessoes::identidade(p)
            .filter(|id| crate::identidade::agente(&id.chave).is_some())
            .map(|id| (p, id))
    })
}

/// O texto do indicador, inteiro — a barra o corta, se não couber.
pub fn texto_do_indicador() -> String {
    let n = conectados().count();
    match ultima() {
        Some(a) => alloc::format!("agentes: {n} · último: {} ({})", a.rotulo, a.papel),
        None => alloc::format!("agentes: {n} · último: ninguém"),
    }
}

/// Esquece tudo, para a suíte: cada caso começa sem "último".
#[cfg(feature = "modo-teste")]
pub fn esquecer() {
    crate::arch::sem_interrupcoes(|| {
        *ULTIMA.lock() = None;
        *USOS.lock() = [None; PORTAS];
    });
    crate::barra::atualizar_indicador();
}

/// Destrava as trancas à força, para uso exclusivo do caminho de falha
/// fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        ULTIMA.force_unlock();
        USOS.force_unlock();
    }
}
