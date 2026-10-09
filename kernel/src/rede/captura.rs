//! A captura: o conteúdo dos datagramas trocados com um destino
//! observado.
//!
//! # O que se guarda
//!
//! Só o que vai e vem por uma associação UDP cujo destino algum papel da
//! política em vigor tem no alcance de `net.observe` — hoje, o DNS da
//! bancada (ver `politica::Politica::observavel`). Nada de TCP, nada de
//! destino que ninguém observa. Um anel de [`CAPACIDADE`] datagramas: o
//! mais velho sai.
//!
//! # Quem lê
//!
//! Só quem pede `net.observe {to}` e passa pelo gate — a permissão
//! `net.observe`, com `to` no alcance, gravado na auditoria. O conteúdo
//! nunca vai para a auditoria, que guarda resumos e não corpos. O tecido de
//! segurança lê por aqui, como qualquer um; o número do último datagrama
//! ([`ultimo`]) é o despertador dele, sem conteúdo.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use politica::endereco::{Destino, Protocolo};

use super::conexoes::Dono;
use crate::trava::Mutex;

/// Quantos datagramas o anel guarda.
pub const CAPACIDADE: usize = 32;

/// Um datagrama guardado.
#[derive(Clone, Debug)]
pub struct Datagrama {
    pub seq: u64,
    pub ts_ms: u64,
    /// O último registro da auditoria quando o datagrama foi guardado: a
    /// ordem dele entre as decisões do gate, que o relógio de um segundo
    /// não dá. Um número, sem conteúdo.
    pub registro: u64,
    pub conexao: u64,
    /// O dono da associação — ver [`Dono::texto`].
    pub dono: String,
    pub destino: Destino,
    /// O dono mandou, e não recebeu.
    pub saida: bool,
    pub dados: Vec<u8>,
}

struct Anel {
    itens: VecDeque<Datagrama>,
    proximo: u64,
}

static ANEL: Mutex<Anel> = Mutex::new(Anel {
    itens: VecDeque::new(),
    proximo: 1,
});

/// O número do último datagrama guardado.
static ULTIMO: AtomicU64 = AtomicU64::new(0);

/// O número do último datagrama guardado — um despertador, sem conteúdo.
pub fn ultimo() -> u64 {
    ULTIMO.load(Ordering::Acquire)
}

/// Guarda o datagrama que `dono` trocou com `destino` pela associação
/// `conexao`, se o destino é observado.
pub fn guardar(conexao: u64, dono: &Dono, destino: &Destino, saida: bool, dados: &[u8]) {
    if destino.protocolo != Protocolo::Udp {
        return;
    }
    let texto = destino.texto();
    if !crate::autorizacao::com_politica(|p| p.observavel(&texto)) {
        return;
    }
    let mut d = Datagrama {
        seq: 0,
        ts_ms: crate::persistencia::agora_ms(),
        registro: crate::autorizacao::ultimo_registro(),
        conexao,
        dono: dono.texto(),
        destino: *destino,
        saida,
        dados: Vec::from(dados),
    };
    // O que sai do anel é largado fora da trava: devolver memória.
    let saiu = crate::arch::sem_interrupcoes(|| {
        let mut a = ANEL.lock();
        d.seq = a.proximo;
        a.proximo += 1;
        let saiu = (a.itens.len() == CAPACIDADE)
            .then(|| a.itens.pop_front())
            .flatten();
        ULTIMO.store(d.seq, Ordering::Release);
        a.itens.push_back(d);
        saiu
    });
    drop(saiu);
}

/// Os datagramas de `destino` depois de `depois`, até `max`, do mais velho
/// ao mais novo. O handler de `net.observe` chama, depois do gate.
pub fn depois_de(destino: &Destino, depois: u64, max: usize) -> Vec<Datagrama> {
    crate::arch::sem_interrupcoes(|| {
        ANEL.lock()
            .itens
            .iter()
            .filter(|d| d.seq > depois && d.destino == *destino)
            .take(max)
            .cloned()
            .collect()
    })
}

/// Destrava o anel, para o caminho de falha fatal.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        ANEL.force_unlock();
    }
}
