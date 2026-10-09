//! Só na suíte: o servidor de DNS da bancada, de dentro da máquina.
//!
//! O DNS do emulador (`10.0.2.3`) repassa a pergunta ao resolvedor do
//! hospedeiro, e a resposta depende da rede de quem roda a suíte. Este é
//! determinístico: um endereço que o emulador não tem, [`SERVIDOR`], e uma
//! tabela que o caso escreve. O quadro que a pilha manda passa por
//! [`observar_saida`] depois do firewall — um quadro que o firewall barrou
//! nunca chega aqui —; um ARP perguntando pelo servidor ganha a resposta, e
//! uma pergunta de DNS para `10.0.2.53:53` ganha a da tabela — as duas
//! postas na fila do que a placa recebeu, colhidas na mesma volta da
//! pilha, e passando pelo firewall de entrada como qualquer quadro. O que
//! é para a bancada fica nela: não sai pela placa para a rede do emulador.
//!
//! O modo deixa o caso mentir de propósito: responder de outra origem, com
//! bytes que não são DNS, ou não responder.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
    EthernetRepr, IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr,
};

use crate::trava::Mutex;

/// O servidor de DNS da bancada.
pub const SERVIDOR: [u8; 4] = [10, 0, 2, 53];

/// O endereço de quem forja: a resposta "do servidor" vinda daqui não é do
/// destino da associação.
pub const FORJADOR: [u8; 4] = [10, 0, 2, 54];

/// O endereço de placa inventado do servidor.
const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x00, 0x53];

/// Como o servidor responde.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Modo {
    /// A resposta da tabela, do servidor.
    Normal = 0,
    /// A resposta da tabela, mas de [`FORJADOR`].
    Forjada = 1,
    /// Bytes que não são DNS.
    Malformada = 2,
    /// Nenhuma resposta.
    Muda = 3,
}

static MODO: AtomicU8 = AtomicU8::new(Modo::Normal as u8);
static TABELA: Mutex<Vec<(String, Vec<[u8; 4]>)>> = Mutex::new(Vec::new());
static PERGUNTAS: AtomicU64 = AtomicU64::new(0);

/// Põe a tabela e o modo. Um nome fora da tabela tem resposta de nome
/// inexistente.
pub fn por_de_teste(nomes: &[(&str, &[[u8; 4]])], modo: Modo) {
    let tabela: Vec<(String, Vec<[u8; 4]>)> = nomes
        .iter()
        .map(|(n, ips)| (n.to_string(), ips.to_vec()))
        .collect();
    let velha = crate::arch::sem_interrupcoes(|| core::mem::replace(&mut *TABELA.lock(), tabela));
    drop(velha);
    MODO.store(modo as u8, Ordering::Release);
}

/// Quantas perguntas o servidor viu.
pub fn perguntas_de_teste() -> u64 {
    PERGUNTAS.load(Ordering::Acquire)
}

fn modo() -> Modo {
    match MODO.load(Ordering::Acquire) {
        1 => Modo::Forjada,
        2 => Modo::Malformada,
        3 => Modo::Muda,
        _ => Modo::Normal,
    }
}

/// Olha um quadro que a pilha mandou — e já passou pelo firewall. Com
/// [`super::pilha`] tomada: a resposta só entra na fila. Verdadeiro se o
/// quadro era para a bancada, e não deve sair pela placa.
pub(super) fn observar_saida(quadro: &[u8]) -> bool {
    let Ok(eth) = EthernetFrame::new_checked(quadro) else {
        return false;
    };
    let nosso_mac = eth.src_addr();
    match eth.ethertype() {
        EthernetProtocol::Arp => responder_arp(&eth, nosso_mac),
        EthernetProtocol::Ipv4 => responder_dns(eth.payload(), nosso_mac),
        _ => false,
    }
}

/// Quem pergunta pelo servidor ouve o endereço inventado.
fn responder_arp(eth: &EthernetFrame<&[u8]>, nosso_mac: EthernetAddress) -> bool {
    let Ok(pacote) = ArpPacket::new_checked(eth.payload()) else {
        return false;
    };
    let Ok(ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr,
        source_protocol_addr,
        target_protocol_addr,
        ..
    }) = ArpRepr::parse(&pacote)
    else {
        return false;
    };
    if target_protocol_addr.octets() != SERVIDOR && target_protocol_addr.octets() != FORJADOR {
        return false;
    }
    let arp = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Reply,
        source_hardware_addr: EthernetAddress(MAC),
        source_protocol_addr: target_protocol_addr,
        target_hardware_addr: source_hardware_addr,
        target_protocol_addr: source_protocol_addr,
    };
    let eth = EthernetRepr {
        src_addr: EthernetAddress(MAC),
        dst_addr: nosso_mac,
        ethertype: EthernetProtocol::Arp,
    };
    let mut q = alloc::vec![0u8; eth.buffer_len() + arp.buffer_len()];
    let mut frame = EthernetFrame::new_unchecked(&mut q[..]);
    eth.emit(&mut frame);
    arp.emit(&mut ArpPacket::new_unchecked(frame.payload_mut()));
    super::pilha::enfileirar_de_teste(&q);
    true
}

/// A pergunta para o servidor ganha a resposta da tabela, no modo posto.
/// Verdadeiro para todo quadro ao servidor: nenhum vai à placa.
fn responder_dns(ip: &[u8], nosso_mac: EthernetAddress) -> bool {
    let Ok(pacote) = Ipv4Packet::new_checked(ip) else {
        return false;
    };
    if pacote.dst_addr().octets() != SERVIDOR {
        return false;
    }
    if pacote.next_header() != IpProtocol::Udp {
        return true;
    }
    let Ok(udp) = UdpPacket::new_checked(pacote.payload()) else {
        return true;
    };
    if udp.dst_port() != protocolo::dns::PORTA {
        return true;
    }
    PERGUNTAS.fetch_add(1, Ordering::AcqRel);
    let Ok(pergunta) = protocolo::dns::ler(udp.payload()) else {
        return true;
    };
    let Some(nome) = pergunta.nome() else {
        return true;
    };
    let modo = modo();
    if modo == Modo::Muda {
        return true;
    }
    let enderecos = crate::arch::sem_interrupcoes(|| {
        TABELA
            .lock()
            .iter()
            .find(|(n, _)| n == nome.texto())
            .map(|(_, ips)| ips.clone())
    });
    let mut b = [0u8; protocolo::dns::MAIOR_MENSAGEM];
    let resposta: Vec<u8> = if modo == Modo::Malformada {
        alloc::vec![0xFF; 7]
    } else {
        let (ips, codigo) = match &enderecos {
            Some(ips) => (&ips[..], protocolo::dns::SEM_ERRO),
            None => (&[][..], protocolo::dns::NOME_INEXISTENTE),
        };
        match protocolo::dns::resposta(pergunta.id, nome, ips, 60, codigo, &mut b) {
            Ok(n) => b[..n].to_vec(),
            Err(_) => return true,
        }
    };
    let origem = if modo == Modo::Forjada {
        FORJADOR
    } else {
        SERVIDOR
    };
    let udp = UdpRepr {
        src_port: protocolo::dns::PORTA,
        dst_port: udp.src_port(),
    };
    let ip = Ipv4Repr {
        src_addr: Ipv4Address::from(origem),
        dst_addr: pacote.src_addr(),
        next_header: IpProtocol::Udp,
        payload_len: udp.header_len() + resposta.len(),
        hop_limit: 64,
    };
    let eth = EthernetRepr {
        src_addr: EthernetAddress(MAC),
        dst_addr: nosso_mac,
        ethertype: EthernetProtocol::Ipv4,
    };
    let mut q = alloc::vec![0u8; eth.buffer_len() + ip.buffer_len() + ip.payload_len];
    let mut frame = EthernetFrame::new_unchecked(&mut q[..]);
    eth.emit(&mut frame);
    let mut ip_saida = Ipv4Packet::new_unchecked(frame.payload_mut());
    ip.emit(&mut ip_saida, &ChecksumCapabilities::default());
    let mut segmento = UdpPacket::new_unchecked(ip_saida.payload_mut());
    udp.emit(
        &mut segmento,
        &IpAddress::Ipv4(ip.src_addr),
        &IpAddress::Ipv4(ip.dst_addr),
        resposta.len(),
        |d| d.copy_from_slice(&resposta),
        &ChecksumCapabilities::default(),
    );
    super::pilha::enfileirar_de_teste(&q);
    true
}

/// Destrava a tabela, para o caminho de falha fatal.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        TABELA.force_unlock();
    }
}
