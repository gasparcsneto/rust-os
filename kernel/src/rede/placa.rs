//! A placa da pilha: a virtio de uma máquina virtual, ou a Intel 82574L de
//! uma física — ver [`crate::e1000`].
//!
//! # Uma placa, dois drivers
//!
//! A pilha e o ARP do diagnóstico pedem a uma placa sempre o mesmo:
//! transmitir um quadro, colher os que chegaram, dizer o endereço e se ainda
//! responde. É [`PlacaDeRede`], e cada driver a cumpre do seu jeito — a
//! virtio por duas filas do virtio, a Intel por dois anéis de descritores.
//! Nada acima daqui sabe qual das duas está embaixo, a não ser pelo nome que
//! o `net.info` mostra.
//!
//! # Duas placas na mesma máquina
//!
//! As duas ligam — cada driver pega a sua —, e a pilha usa uma: a virtio,
//! se houver, e a Intel na falta dela. A outra fica ligada e sem pilha: os
//! anéis dela são do kernel, e o que chega nela se perde no anel cheio, sem
//! escrever em memória de ninguém. É o que a suíte usa para exercitar o
//! driver da Intel numa máquina cuja rede é a virtio.

use core::sync::atomic::{AtomicU8, Ordering};

/// O maior quadro que a pilha manda e recebe: o Ethernet clássico, 14 de
/// cabeçalho e 1500 de carga, sem jumbo e sem VLAN. As duas placas o
/// transportam inteiro.
pub const MAIOR_QUADRO: usize = 1514;

/// Quanto mede o endereço de uma placa Ethernet.
pub const TAMANHO_DO_MAC: usize = 6;

/// A rajada que a placa recebe sem perder quadro: o menor número de buffers
/// de recepção que os dois drivers penduram — ver
/// `virtio::net::BUFFERS_DE_RECEPCAO` e `e1000::NA_RECEPCAO`. A pilha
/// limita a janela anunciada a ela.
pub const BUFFERS_DE_RECEPCAO: usize = 16;

const _: () = assert!(
    crate::virtio::net::MAIOR_QUADRO == MAIOR_QUADRO
        && crate::e1000::MAIOR_QUADRO == MAIOR_QUADRO
        && crate::virtio::net::TAMANHO_DO_MAC == TAMANHO_DO_MAC
        && crate::virtio::net::BUFFERS_DE_RECEPCAO >= BUFFERS_DE_RECEPCAO
        && crate::e1000::NA_RECEPCAO > BUFFERS_DE_RECEPCAO,
    "uma placa nao cumpre o que a pilha supoe dela"
);

/// A recusa de um quadro sem enlace: a placa está bem, o cabo não. A pilha
/// não a repete no log a cada quadro — o driver diz quando o enlace cai e
/// volta, e o `net.info` conta.
pub const SEM_ENLACE: &str = "a placa esta sem enlace: o quadro nao saiu";

/// O que se conta dos quadros que não passaram, numa placa que conta.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Perdas {
    /// Os que a placa recebeu com erro — soma, símbolo, sequência — ou
    /// partidos, e que o driver jogou fora.
    pub descartados: u64,
    /// Os que não saíram porque a placa estava sem enlace: o cabo, ou o
    /// outro lado.
    pub sem_enlace: u64,
    /// Quantas vezes o driver reiniciou a placa porque uma transmissão não
    /// se confirmou no prazo.
    pub reinicios: u64,
}

/// O que a pilha pede de uma placa: o transporte de quadros.
pub trait PlacaDeRede {
    /// O nome do driver, para o relatório: `virtio-net`, `e1000e`.
    fn driver(&self) -> &'static str;

    /// O endereço da placa, se ela tem um.
    fn mac(&self) -> Option<[u8; TAMANHO_DO_MAC]>;

    /// Quantos quadros saíram e quantos entraram.
    fn contadores(&self) -> (u64, u64);

    /// A maior espera por uma confirmação de transmissão, em voltas.
    fn maior_espera(&self) -> u32;

    /// Se há enlace: `None` numa placa que não sabe — a virtio do emulador,
    /// sem cabo.
    fn enlace(&self) -> Option<bool>;

    /// O que se perdeu, numa placa que conta.
    fn perdas(&self) -> Option<Perdas>;

    /// Transmite um quadro Ethernet inteiro, a partir do endereço de
    /// destino.
    fn transmitir(&mut self, quadro: &[u8]) -> Result<(), &'static str>;

    /// Colhe um quadro recebido, se houver, e devolve quantos bytes dele
    /// foram copiados para `destino`.
    fn receber(&mut self, destino: &mut [u8]) -> Option<usize>;

    /// Se a placa ainda está no ar.
    fn vivo(&self) -> bool;
}

/// Qual placa a pilha usa.
static ESCOLHIDA: AtomicU8 = AtomicU8::new(NENHUMA);
const NENHUMA: u8 = 0;
const VIRTIO: u8 = 1;
const INTEL: u8 = 2;

/// Liga as placas que os drivers acharem e escolhe a da pilha.
pub fn init() {
    crate::virtio::net::init();
    crate::e1000::init();
    let virtio = crate::virtio::net::com_a_placa(|_| ()).is_some();
    let intel = crate::e1000::com_a_placa(|_| ()).is_some();
    let escolhida = match (virtio, intel) {
        (true, _) => VIRTIO,
        (false, true) => INTEL,
        (false, false) => NENHUMA,
    };
    if virtio && intel {
        crate::log_info!(
            "rede",
            "duas placas: a pilha usa a virtio, e a Intel fica ligada sem pilha"
        );
    }
    ESCOLHIDA.store(escolhida, Ordering::Release);
}

/// Chama `f` com a placa da pilha, se houver uma — com a trava do driver
/// dela, como o `com_a_placa` de cada um.
pub fn com_a_placa<R>(f: impl FnOnce(&mut dyn PlacaDeRede) -> R) -> Option<R> {
    match ESCOLHIDA.load(Ordering::Acquire) {
        VIRTIO => crate::virtio::net::com_a_placa(|p| f(p)),
        INTEL => crate::e1000::com_a_placa(|p| f(p)),
        _ => None,
    }
}
