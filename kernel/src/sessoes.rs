//! O estado das sessões cifradas das portas de agente: quem está em cada
//! porta, e as chaves do transporte.
//!
//! Só o armazenamento. Quem faz o aperto de mão, decifra e cifra é o canal
//! do agente, em [`crate::agent::seguro`]; ele mora lá porque é código que
//! lê o que vem de fora, e o canal não tem `unsafe`. Este módulo tem as
//! travas estáticas — e, com elas, o `destravar` do caminho fatal, que é
//! `unsafe`.

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use sigilo::{TAM_CHAVE, Transporte};
use spin::Mutex;

/// Quantas portas de agente há.
pub const PORTAS: usize = crate::virtio::console::PORTAS as usize;

/// Quem está numa porta.
#[derive(Clone)]
pub struct Identificada {
    /// O nome do agente, do registro.
    pub nome: String,
    /// A chave pública que ele provou ter.
    pub chave: [u8; TAM_CHAVE],
    /// Quando a sessão foi estabelecida, em milissegundos desde o boot.
    pub desde_ms: u64,
}

/// O transporte de cada porta estabelecida.
///
/// Separado da identidade porque é usado de outro jeito: quem cifra uma
/// resposta **tira** o transporte daqui, cifra fora da trava — uma resposta
/// grande leva milissegundos para cifrar, e não precisa das interrupções
/// desligadas — e o devolve.
static TRANSPORTES: Mutex<[Option<Transporte>; PORTAS]> = Mutex::new([const { None }; PORTAS]);

/// Quem está em cada porta, para o relatório e para o log.
static IDENTIDADES: Mutex<[Option<Identificada>; PORTAS]> = Mutex::new([const { None }; PORTAS]);

/// Apertos recusados: chave fora do registro, quadro inválido, sem entropia.
static RECUSADOS: AtomicU64 = AtomicU64::new(0);
/// Sessões estabelecidas que acabaram por um quadro que não abriu, ou por
/// uma resposta que não saiu.
static ENCERRADAS: AtomicU64 = AtomicU64::new(0);

fn indice(p: u8) -> Option<usize> {
    (1..=PORTAS as u8).contains(&p).then(|| usize::from(p) - 1)
}

/// Guarda uma sessão recém-estabelecida.
pub fn estabelecer(p: u8, transporte: Transporte, identificada: Identificada) {
    let Some(i) = indice(p) else {
        return;
    };
    crate::arch::sem_interrupcoes(|| {
        TRANSPORTES.lock()[i] = Some(transporte);
        IDENTIDADES.lock()[i] = Some(identificada);
    });
}

/// Tira o transporte da porta `p`, para cifrar ou decifrar fora da trava.
/// Quem tira devolve com [`devolver`], ou encerra com [`esquecer`].
pub fn tirar(p: u8) -> Option<Transporte> {
    let i = indice(p)?;
    crate::arch::sem_interrupcoes(|| TRANSPORTES.lock()[i].take())
}

/// Devolve o transporte depois de usado.
pub fn devolver(p: u8, transporte: Transporte) {
    let Some(i) = indice(p) else {
        return;
    };
    crate::arch::sem_interrupcoes(|| TRANSPORTES.lock()[i] = Some(transporte));
}

/// Esquece a sessão da porta `p`: a identidade e as chaves. Devolve quem
/// estava nela.
pub fn esquecer(p: u8) -> Option<Identificada> {
    let i = indice(p)?;
    // O transporte sai da trava e é destruído fora dela; o `Drop` da cifra
    // apaga as chaves.
    let (identidade, transporte) = crate::arch::sem_interrupcoes(|| {
        (IDENTIDADES.lock()[i].take(), TRANSPORTES.lock()[i].take())
    });
    drop(transporte);
    identidade
}

/// Quem está na porta `p`, se a sessão está estabelecida.
pub fn identidade(p: u8) -> Option<Identificada> {
    let i = indice(p)?;
    crate::arch::sem_interrupcoes(|| IDENTIDADES.lock()[i].clone())
}

/// Conta um aperto recusado.
pub fn contar_recusa() {
    RECUSADOS.fetch_add(1, Ordering::Relaxed);
}

/// Conta uma sessão encerrada.
pub fn contar_encerrada() {
    ENCERRADAS.fetch_add(1, Ordering::Relaxed);
}

/// Os contadores: apertos recusados e sessões encerradas.
pub fn contadores() -> (u64, u64) {
    (
        RECUSADOS.load(Ordering::Relaxed),
        ENCERRADAS.load(Ordering::Relaxed),
    )
}

/// Destrava as sessões à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        TRANSPORTES.force_unlock();
        IDENTIDADES.force_unlock();
    }
}
