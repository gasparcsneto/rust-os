//! O pseudo-terminal: o interpretador do kernel, visto de um processo.
//!
//! # O que ele é
//!
//! O arranjo do Unix, reduzido ao que o Terminal precisa. Dois sentidos, e
//! nenhum deles novo para o kernel:
//!
//! - **o que o processo escreve é digitado.** Cada caractere entra na fila
//!   do teclado que o interpretador lê, como se uma pessoa o tivesse
//!   digitado na máquina. O interpretador não sabe de onde veio;
//! - **o que o kernel imprime é lido.** Tudo o que passa por
//!   [`crate::serial::_print`] — as respostas do interpretador, o eco do que
//!   se digita, o log — vai também para um anel de bytes daqui, e o processo
//!   o lê.
//!
//! O console do kernel continua desenhando o mesmo texto na camada de baixo:
//! ele é o fundo, e a reserva — o que se vê no boot, sem servidor, e o
//! caminho da tela de falha. O Terminal é outra janela sobre o mesmo
//! interpretador, e não um segundo interpretador.
//!
//! # Por que a leitura não bloqueia
//!
//! Porque o Terminal espera duas coisas: a saída do kernel e o teclado. Um
//! processo deste kernel tem um fio só, e um fio que dormisse na leitura do
//! pseudo-terminal não veria a tecla que chegasse no canal dele. Então a
//! espera é uma só, no canal de eventos: o kernel avisa ali, com um evento
//! [`SAIDA`](protocolo::usuario::evento::tipo::SAIDA), que há o que ler, e o
//! processo lê até a leitura devolver zero.
//!
//! # Por que o aviso é adiado
//!
//! Porque quem escreve no anel é o `_print`, e o `_print` roda em qualquer
//! lugar — inclusive dentro da tranca do escalonador, quando o próprio
//! escalonador registra algo no log. Avisar é publicar no canal, e publicar
//! acorda o ouvinte, que toma a tranca do escalonador: por dentro dela, o
//! kernel giraria para sempre. O `_print` só marca que há saída nova, e quem
//! avisa é o coletor de fios, a cada volta — um tique de atraso, de um lugar
//! sem tranca nenhuma na mão.
//!
//! # O anel
//!
//! Guarda os últimos [`ANEL`] bytes impressos, desde o boot, tenha ou não um
//! Terminal aberto: é o que faz o Terminal começar mostrando o que aconteceu
//! antes dele. O que não cabe empurra o mais antigo para fora, e é contado —
//! o kernel não espera um leitor lento para imprimir.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use spin::Mutex;

/// Quantos bytes da saída o anel guarda.
pub const ANEL: usize = 16 * 1024;

struct Anel {
    bytes: [u8; ANEL],
    /// Onde está o byte mais antigo, e quantos há.
    inicio: usize,
    quantos: usize,
}

impl Anel {
    fn pôr(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.quantos == ANEL {
                // Cheio: o mais antigo sai.
                self.inicio = (self.inicio + 1) % ANEL;
                self.quantos -= 1;
                PERDIDOS.fetch_add(1, Ordering::Relaxed);
            }
            self.bytes[(self.inicio + self.quantos) % ANEL] = b;
            self.quantos += 1;
        }
    }

    fn tirar(&mut self, destino: &mut [u8]) -> usize {
        let n = destino.len().min(self.quantos);
        for (i, d) in destino.iter_mut().take(n).enumerate() {
            *d = self.bytes[(self.inicio + i) % ANEL];
        }
        self.inicio = (self.inicio + n) % ANEL;
        self.quantos -= n;
        n
    }
}

// Tomada por `try_lock` do `_print` — que já roda com as interrupções
// mascaradas — e por `sem_interrupcoes` do resto. Solta no caminho fatal.
static SAIDA: Mutex<Anel> = Mutex::new(Anel {
    bytes: [0; ANEL],
    inicio: 0,
    quantos: 0,
});

/// Quem tem o pseudo-terminal aberto.
#[derive(Clone, Copy)]
struct Dono {
    fio: u64,
    geracao: u64,
    /// O canal onde o kernel avisa que há saída.
    canal: crate::eventos::Chave,
}

static DONO: Mutex<Option<Dono>> = Mutex::new(None);

/// Houve saída desde o último aviso.
static PENDENTE: AtomicBool = AtomicBool::new(false);
static PROXIMA_GERACAO: AtomicU64 = AtomicU64::new(1);
/// Bytes que saíram do anel sem ninguém lê-los; avisos entregues; teclas
/// digitadas pelo pseudo-terminal.
static PERDIDOS: AtomicU64 = AtomicU64::new(0);
static AVISOS: AtomicU64 = AtomicU64::new(0);
static DIGITADOS: AtomicU64 = AtomicU64::new(0);

/// O que um descritor do pseudo-terminal guarda: qual abertura ele é.
///
/// Uma geração, pelo motivo dos canais e das superfícies: o descritor de
/// quem fechou não alcança a abertura seguinte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chave {
    pub geracao: u64,
}

/// Guarda `texto` no anel. Chamada pelo `_print`, de qualquer lugar.
///
/// Uma tranca tomada perde o texto, em vez de esperar: quem imprime não pode
/// esperar ninguém. Com as interrupções mascaradas em toda tomada, só uma
/// exceção no meio de uma leitura do anel a encontra tomada — e esperar ali
/// seria esperar para sempre.
pub fn registrar(texto: &str) {
    if let Some(mut anel) = SAIDA.try_lock() {
        anel.pôr(texto.as_bytes());
        PENDENTE.store(true, Ordering::Relaxed);
    }
}

/// O `_print` escreve pelo `core::fmt`, e isto é o destino dele.
pub struct Registro;

impl core::fmt::Write for Registro {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        registrar(s);
        Ok(())
    }
}

/// Por que o pseudo-terminal não abriu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// Há outro dono vivo.
    Ocupado,
}

/// Abre o pseudo-terminal para `fio`, com os avisos no `canal`.
///
/// Um dono morto não o segura: quem abre confere, e toma o lugar.
pub fn abrir(fio: u64, canal: crate::eventos::Chave) -> Result<Chave, Recusa> {
    let chave = crate::arch::sem_interrupcoes(|| {
        let mut dono = DONO.lock();
        if dono.is_some_and(|d| crate::fios::vivo(d.fio)) {
            return Err(Recusa::Ocupado);
        }
        let geracao = PROXIMA_GERACAO.fetch_add(1, Ordering::Relaxed);
        *dono = Some(Dono {
            fio,
            geracao,
            canal,
        });
        Ok(Chave { geracao })
    })?;
    // O que já está no anel é saída que o dono novo ainda não leu.
    PENDENTE.store(true, Ordering::Relaxed);
    Ok(chave)
}

/// A `chave` é a abertura viva, e de `fio`?
fn confere(chave: Chave, fio: u64) -> bool {
    crate::arch::sem_interrupcoes(|| {
        DONO.lock()
            .is_some_and(|d| d.geracao == chave.geracao && d.fio == fio)
    })
}

/// Lê para `destino` o que o kernel imprimiu. Zero quando não há nada — não
/// bloqueia. `None` se a chave não é de `fio`.
pub fn ler(chave: Chave, fio: u64, destino: &mut [u8]) -> Option<usize> {
    if !confere(chave, fio) {
        return None;
    }
    Some(crate::arch::sem_interrupcoes(|| {
        SAIDA.lock().tirar(destino)
    }))
}

/// Digita `texto` no interpretador, caractere por caractere, até a fila do
/// teclado encher. Devolve quantos bytes foram aceitos — uma escrita
/// parcial, como a de um `write` num pipe cheio. `None` se a chave não é de
/// `fio`.
///
/// # O que não é texto é consumido e descartado
///
/// A fila do teclado carrega também as teclas de função e o clique — é por
/// ela que F1 limpa a tela. Um processo que escrevesse esses caracteres
/// apertaria botões do kernel por um canal que só deveria digitar. Então só
/// passa o que mexe na linha do interpretador: texto, a quebra de linha, o
/// apagar, o apagar da linha inteira e o Enter de um agente — ver
/// `protocolo::usuario::terminal`. O resto conta como aceito, porque recusá-lo
/// deixaria quem escreve repetindo para sempre o mesmo caractere.
pub fn escrever(chave: Chave, fio: u64, texto: &str) -> Option<usize> {
    if !confere(chave, fio) {
        return None;
    }
    let mut aceitos = 0;
    for c in texto.chars() {
        if e_digitavel(c) {
            if !crate::teclado::injetar(c) {
                break;
            }
            DIGITADOS.fetch_add(1, Ordering::Relaxed);
        }
        aceitos += c.len_utf8();
    }
    Some(aceitos)
}

/// Um caractere que o pseudo-terminal deixa chegar ao interpretador.
fn e_digitavel(c: char) -> bool {
    use protocolo::usuario::terminal::{APAGAR_A_LINHA, agente_que_confirmou};
    c.is_ascii_graphic()
        || matches!(c, ' ' | '\n' | '\u{8}' | APAGAR_A_LINHA)
        || agente_que_confirmou(c).is_some()
}

/// Fecha o pseudo-terminal, se a `chave` for a abertura de `fio`.
pub fn fechar(chave: Chave, fio: u64) {
    crate::arch::sem_interrupcoes(|| {
        let mut dono = DONO.lock();
        if dono.is_some_and(|d| d.geracao == chave.geracao && d.fio == fio) {
            *dono = None;
        }
    });
}

/// Avisa o dono, no canal dele, que há saída nova. Chamada pelo coletor de
/// fios a cada volta — ver o cabeçalho sobre por que o aviso é adiado.
///
/// Um aviso por volta, e não um por impressão: o dono lê tudo o que houver
/// quando acordar. A fila cheia do canal não perde nada que importe — o
/// próximo aviso vem na volta seguinte, se ainda houver o que ler.
pub fn avisar_se_preciso() {
    if !PENDENTE.load(Ordering::Relaxed) {
        return;
    }
    let Some(dono) = crate::arch::sem_interrupcoes(|| *DONO.lock()) else {
        return;
    };
    PENDENTE.store(false, Ordering::Relaxed);
    let aviso = protocolo::usuario::evento::Evento {
        tipo: protocolo::usuario::evento::tipo::SAIDA,
        ..Default::default()
    };
    if crate::eventos::publicar_em(dono.canal, aviso).is_ok() {
        AVISOS.fetch_add(1, Ordering::Relaxed);
    }
}

/// `(bytes perdidos, avisos entregues, teclas digitadas)`.
pub fn estatisticas() -> (u64, u64, u64) {
    (
        PERDIDOS.load(Ordering::Relaxed),
        AVISOS.load(Ordering::Relaxed),
        DIGITADOS.load(Ordering::Relaxed),
    )
}

/// O fio que tem o pseudo-terminal aberto, se algum.
pub fn dono() -> Option<u64> {
    crate::arch::sem_interrupcoes(|| DONO.lock().map(|d| d.fio))
}

/// Destrava o anel e o dono à força, para o caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        SAIDA.force_unlock();
        DONO.force_unlock();
    }
}
