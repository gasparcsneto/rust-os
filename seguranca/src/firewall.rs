//! As contas do firewall nativo: as regras, quem elas alcançam, e o que
//! cada quadro é.
//!
//! # O lugar dele
//!
//! ```text
//! gate → operação de rede → firewall → rede
//! ```
//!
//! O firewall controla tráfego; não é uma segunda política. Não há regra
//! que permita: um quadro só sai se o gate decidiu a conexão dele **e**
//! nenhuma regra o barra. O que o gate recusa não chega a ter tráfego para o
//! firewall olhar, e o que o firewall barra não passa por mais que o gate o
//! tenha permitido — nenhum conflito entre os dois abre passagem.
//!
//! # As duas camadas
//!
//! - **Estrutural**: cada quadro que sai pertence a um fluxo da tabela da
//!   pilha — uma conexão que o gate decidiu — ou ao DHCP da própria placa;
//!   cada quadro que chega vai à porta local de um fluxo do mesmo protocolo
//!   (no TCP, com a quádrupla inteira) ou ao DHCP. O ARP passa. O resto não
//!   passa: nem ICMP, nem IPv6, nem fragmento — a pilha não fragmenta, e um
//!   eco ou um RST que ninguém decidiu é tráfego sem decisão.
//! - **Regras**: `net.block` barra um destino, para todos ou só para um dono
//!   — ver [`Escopo`]. O fluxo barrado tem o número da regra; os quadros
//!   dele não passam, nos dois sentidos.
//!
//! # A escuta do canal do agente
//!
//! Um transporte de entrada — o canal do agente por TCP, ver
//! `kernel/src/rede/canal.rs` — não tem fluxo antes de o outro lado
//! chamar: o primeiro quadro dele é um SYN de quem o kernel ainda não
//! conhece. Uma [`Fluxo::escuta`] é a porta local desse transporte, e
//! deixa passar só o começo de uma conexão: o SYN que chega a ela — e mais
//! nada —, e o SYN-ACK ou o RST que saem dela, a resposta da pilha a esse
//! SYN na mesma volta, antes de a conexão aceita entrar na fotografia. O
//! resto da conversa é o de um fluxo como os outros, com a quádrupla
//! inteira, que as regras alcançam: a conexão aceita é um fluxo da tabela.
//! A escuta não autoriza nada — quem chega ainda tem de provar a chave
//! dele no aperto do canal, e cada pedido passa pelo gate.

use alloc::string::String;
use alloc::vec::Vec;

use politica::endereco::{Destino, Protocolo};

use crate::util;

/// Quantas regras a tabela tem, no máximo.
pub const MAIS_REGRAS: usize = 16;

/// A porta do servidor de DHCP, e a do cliente.
const DHCP_SERVIDOR: u16 = 67;
const DHCP_CLIENTE: u16 = 68;

/// A quem uma regra se aplica.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Escopo {
    /// A todos os fluxos para o destino.
    Todos,
    /// Aos fluxos de um agente: os da sessão dele e os dos processos que
    /// agem com a autoridade dele, pela chave.
    Agente([u8; 32]),
    /// Aos fluxos de uma sessão de pessoa, e dos processos dela.
    Pessoa([u8; 8]),
    /// Aos fluxos de um processo só, pelo fio.
    Processo(u64),
    /// Aos fluxos da serial.
    Serial,
}

impl Escopo {
    /// Lê o escopo como `net.block` o recebe: `agent:<64 hex>`,
    /// `person:<16 hex>`, `process:<fio>`, `serial` — ou nada, todos.
    pub fn ler(texto: Option<&str>) -> Option<Escopo> {
        let Some(t) = texto else {
            return Some(Escopo::Todos);
        };
        if t == "serial" {
            return Some(Escopo::Serial);
        }
        if let Some(h) = t.strip_prefix("agent:") {
            return util::de_hex::<32>(h).map(Escopo::Agente);
        }
        if let Some(h) = t.strip_prefix("person:") {
            return util::de_hex::<8>(h).map(Escopo::Pessoa);
        }
        if let Some(n) = t.strip_prefix("process:") {
            // Só a forma normal: sem zero à esquerda, sem sinal.
            if n.is_empty() || (n.len() > 1 && n.starts_with('0')) {
                return None;
            }
            return n.parse().ok().map(Escopo::Processo);
        }
        None
    }

    /// O texto que [`Escopo::ler`] lê de volta igual; vazio para todos.
    pub fn texto(&self) -> String {
        match self {
            Escopo::Todos => String::new(),
            Escopo::Agente(k) => alloc::format!("agent:{}", util::hex(k)),
            Escopo::Pessoa(s) => alloc::format!("person:{}", util::hex(s)),
            Escopo::Processo(f) => alloc::format!("process:{f}"),
            Escopo::Serial => String::from("serial"),
        }
    }

    /// O escopo alcança o dono de um fluxo.
    pub fn alcanca(&self, d: &DonoDoFluxo) -> bool {
        match self {
            Escopo::Todos => true,
            Escopo::Agente(k) => d.agente == Some(*k),
            Escopo::Pessoa(s) => d.pessoa == Some(*s),
            Escopo::Processo(f) => d.processo == Some(*f),
            Escopo::Serial => d.serial,
        }
    }
}

/// De quem é um fluxo, para as regras: o processo que o abriu, se foi um,
/// e por quem ele age — o agente pela chave, a pessoa pela sessão, ou a
/// serial. Fixado quando a conexão abre: é a autoridade que o gate
/// decidiu.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DonoDoFluxo {
    pub processo: Option<u64>,
    pub agente: Option<[u8; 32]>,
    pub pessoa: Option<[u8; 8]>,
    pub serial: bool,
}

/// Uma regra.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Regra {
    pub id: u64,
    pub destino: Destino,
    pub escopo: Escopo,
    /// A decisão do gate que a pôs — o `net.block` na auditoria.
    pub decisao: u64,
    /// Quem a pôs, como a auditoria o nomeia.
    pub autor: String,
}

/// A regra que barra `destino` para `dono`, se alguma barra.
pub fn barrado(regras: &[Regra], destino: &Destino, dono: &DonoDoFluxo) -> Option<u64> {
    regras
        .iter()
        .find(|r| r.destino == *destino && r.escopo.alcanca(dono))
        .map(|r| r.id)
}

/// Um fluxo da tabela da pilha, como o firewall o vê.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fluxo {
    pub protocolo: Protocolo,
    pub porta_local: u16,
    pub remoto: [u8; 4],
    pub porta_remota: u16,
    /// A regra que barra este fluxo, se alguma.
    pub barrado: Option<u64>,
    /// Uma escuta, e não uma conversa: a porta local de um transporte de
    /// entrada — ver o cabeçalho. `remoto` e `porta_remota` não valem, e a
    /// escuta nunca casa como fluxo de quádrupla.
    pub escuta: bool,
}

impl Fluxo {
    /// A escuta TCP na porta local `porta` — ver o cabeçalho.
    pub const fn escuta(porta: u16) -> Fluxo {
        Fluxo {
            protocolo: Protocolo::Tcp,
            porta_local: porta,
            remoto: [0; 4],
            porta_remota: 0,
            barrado: None,
            escuta: true,
        }
    }

    /// Este fluxo é a conversa da quádrupla dada — uma escuta nunca é.
    fn casa(
        &self,
        protocolo: Protocolo,
        porta_local: u16,
        remoto: [u8; 4],
        porta_remota: u16,
    ) -> bool {
        !self.escuta
            && self.protocolo == protocolo
            && self.porta_local == porta_local
            && self.remoto == remoto
            && self.porta_remota == porta_remota
    }
}

/// Os bits do TCP que a escuta olha.
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// Por que um quadro não passou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Motivo {
    /// Não pertence a fluxo nenhum.
    SemFluxo,
    /// Uma regra barra o fluxo dele.
    Regra(u64),
    /// Não é ARP, nem IPv4 com TCP ou UDP inteiro.
    Protocolo,
}

/// O que fazer com um quadro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Veredito {
    Passa,
    Descarta(Motivo),
}

/// O que um quadro é, lido do cabeçalho.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Quadro {
    Arp,
    Ip {
        protocolo: Protocolo,
        origem: [u8; 4],
        destino: [u8; 4],
        porta_de_origem: u16,
        porta_de_destino: u16,
        /// Os bits do cabeçalho TCP; zero no UDP.
        bits: u8,
    },
    Outro,
}

/// Lê o cabeçalho: Ethernet II, IPv4 sem fragmento, e as portas de TCP ou
/// UDP — tudo dentro do quadro, ou é [`Quadro::Outro`].
fn ler(q: &[u8]) -> Quadro {
    let Some(tipo) = q.get(12..14) else {
        return Quadro::Outro;
    };
    match [tipo[0], tipo[1]] {
        [0x08, 0x06] => return Quadro::Arp,
        [0x08, 0x00] => {}
        _ => return Quadro::Outro,
    }
    let ip = &q[14..];
    let Some(&vi) = ip.first() else {
        return Quadro::Outro;
    };
    let ihl = usize::from(vi & 0x0F) * 4;
    if vi >> 4 != 4 || ihl < 20 || ip.len() < ihl {
        return Quadro::Outro;
    }
    // Um fragmento — o bit "mais fragmentos", ou um deslocamento — não é um
    // datagrama inteiro.
    let frag = u16::from_be_bytes([ip[6], ip[7]]);
    if frag & 0x3FFF != 0 {
        return Quadro::Outro;
    }
    let protocolo = match ip[9] {
        6 => Protocolo::Tcp,
        17 => Protocolo::Udp,
        _ => return Quadro::Outro,
    };
    let l4 = &ip[ihl..];
    if l4.len() < 4 {
        return Quadro::Outro;
    }
    // No TCP, os bits — o byte 13 do cabeçalho: um segmento que não os
    // tem não é TCP inteiro.
    let bits = match protocolo {
        Protocolo::Tcp => match l4.get(13) {
            Some(&b) => b,
            None => return Quadro::Outro,
        },
        Protocolo::Udp => 0,
    };
    Quadro::Ip {
        protocolo,
        origem: [ip[12], ip[13], ip[14], ip[15]],
        destino: [ip[16], ip[17], ip[18], ip[19]],
        porta_de_origem: u16::from_be_bytes([l4[0], l4[1]]),
        porta_de_destino: u16::from_be_bytes([l4[2], l4[3]]),
        bits,
    }
}

/// Uma escuta na porta local `porta`, entre os fluxos.
fn escutando(fluxos: &[Fluxo], protocolo: Protocolo, porta: u16) -> bool {
    fluxos
        .iter()
        .any(|f| f.escuta && f.protocolo == protocolo && f.porta_local == porta)
}

/// Um quadro que a pilha quer mandar.
pub fn saida(quadro: &[u8], fluxos: &[Fluxo]) -> Veredito {
    match ler(quadro) {
        Quadro::Arp => Veredito::Passa,
        Quadro::Outro => Veredito::Descarta(Motivo::Protocolo),
        Quadro::Ip {
            protocolo,
            destino,
            porta_de_origem,
            porta_de_destino,
            bits,
            ..
        } => {
            if protocolo == Protocolo::Udp
                && porta_de_origem == DHCP_CLIENTE
                && porta_de_destino == DHCP_SERVIDOR
            {
                return Veredito::Passa;
            }
            match fluxos
                .iter()
                .find(|f| f.casa(protocolo, porta_de_origem, destino, porta_de_destino))
            {
                Some(Fluxo {
                    barrado: Some(r), ..
                }) => Veredito::Descarta(Motivo::Regra(*r)),
                Some(_) => Veredito::Passa,
                // Da escuta, só a resposta a um SYN: o SYN-ACK que aceita,
                // ou o RST que recusa. Ela nunca começa uma conversa.
                None if escutando(fluxos, protocolo, porta_de_origem)
                    && (bits & RST != 0 || bits & (SYN | ACK | FIN) == SYN | ACK) =>
                {
                    Veredito::Passa
                }
                None => Veredito::Descarta(Motivo::SemFluxo),
            }
        }
    }
}

/// Um quadro que a placa recebeu, antes de a pilha o ver.
///
/// No UDP, o fluxo é achado pela porta local: um datagrama de outra origem
/// na porta de uma associação passa, e a associação o descarta — é a regra
/// dela, que o 9.3 fixou, e é ela que o conta. O que vem do destino de um
/// fluxo barrado não passa.
pub fn entrada(quadro: &[u8], fluxos: &[Fluxo]) -> Veredito {
    match ler(quadro) {
        Quadro::Arp => Veredito::Passa,
        Quadro::Outro => Veredito::Descarta(Motivo::Protocolo),
        Quadro::Ip {
            protocolo,
            origem,
            porta_de_origem,
            porta_de_destino,
            bits,
            ..
        } => {
            if protocolo == Protocolo::Udp
                && porta_de_origem == DHCP_SERVIDOR
                && porta_de_destino == DHCP_CLIENTE
            {
                return Veredito::Passa;
            }
            if let Some(f) = fluxos
                .iter()
                .find(|f| f.casa(protocolo, porta_de_destino, origem, porta_de_origem))
            {
                return match f.barrado {
                    Some(r) => Veredito::Descarta(Motivo::Regra(r)),
                    None => Veredito::Passa,
                };
            }
            // Na escuta, só o começo de uma conexão: o SYN sozinho. O que
            // mais chegar a ela sem fluxo — um ACK, dados, um FIN, um RST —
            // é de uma conversa que o kernel não tem.
            if escutando(fluxos, protocolo, porta_de_destino)
                && bits & (SYN | ACK | FIN | RST) == SYN
            {
                return Veredito::Passa;
            }
            let da_porta = fluxos.iter().any(|f| {
                !f.escuta && f.protocolo == protocolo && f.porta_local == porta_de_destino
            });
            if protocolo == Protocolo::Udp && da_porta {
                Veredito::Passa
            } else {
                Veredito::Descarta(Motivo::SemFluxo)
            }
        }
    }
}

/// Os fluxos a partir das conexões: cada uma com o destino, a porta local
/// e o dono, e a regra que a barra, se alguma.
pub fn fluxos<'a>(
    conexoes: impl Iterator<Item = (Destino, u16, DonoDoFluxo)> + 'a,
    regras: &'a [Regra],
) -> impl Iterator<Item = Fluxo> + 'a {
    conexoes.map(move |(destino, porta_local, dono)| Fluxo {
        protocolo: destino.protocolo,
        porta_local,
        remoto: destino.ip,
        porta_remota: destino.porta,
        barrado: barrado(regras, &destino, &dono),
        escuta: false,
    })
}

/// A tabela de regras: o que `net.block` põe e `net.unblock` tira. A
/// decisão de pôr é do gate; isto só guarda.
#[derive(Clone, Debug, Default)]
pub struct Regras {
    regras: Vec<Regra>,
    proxima: u64,
}

impl Regras {
    pub fn nova() -> Regras {
        Regras {
            regras: Vec::new(),
            proxima: 1,
        }
    }

    /// Põe uma regra; devolve o número dela. A mesma (destino, escopo) não
    /// se repete: devolve a que já está. `Err` com a tabela cheia.
    pub fn por(
        &mut self,
        destino: Destino,
        escopo: Escopo,
        decisao: u64,
        autor: &str,
    ) -> Result<(u64, bool), &'static str> {
        if let Some(r) = self
            .regras
            .iter()
            .find(|r| r.destino == destino && r.escopo == escopo)
        {
            return Ok((r.id, false));
        }
        if self.regras.len() >= MAIS_REGRAS {
            return Err("a tabela de regras do firewall esta cheia");
        }
        let id = self.proxima.max(1);
        self.proxima = id + 1;
        self.regras.push(Regra {
            id,
            destino,
            escopo,
            decisao,
            autor: String::from(autor),
        });
        Ok((id, true))
    }

    /// Tira a regra (destino, escopo); devolve o número dela.
    pub fn tirar(&mut self, destino: &Destino, escopo: &Escopo) -> Option<u64> {
        let i = self
            .regras
            .iter()
            .position(|r| r.destino == *destino && r.escopo == *escopo)?;
        Some(self.regras.remove(i).id)
    }

    /// As regras, na ordem em que entraram.
    pub fn todas(&self) -> &[Regra] {
        &self.regras
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    const GUEST: [u8; 4] = [10, 0, 2, 15];
    const ECO: [u8; 4] = [10, 0, 2, 100];

    /// Um quadro Ethernet + IPv4 + o começo de TCP ou UDP.
    fn quadro(proto: u8, origem: [u8; 4], destino: [u8; 4], po: u16, pd: u16) -> Vec<u8> {
        let mut q = alloc::vec![0u8; 14];
        q[12] = 0x08;
        q[13] = 0x00;
        let mut ip = alloc::vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, proto, 0, 0];
        ip.extend(origem);
        ip.extend(destino);
        q.extend(ip);
        q.extend(po.to_be_bytes());
        q.extend(pd.to_be_bytes());
        q.extend([0u8; 16]);
        q
    }

    fn eco(barrado: Option<u64>) -> Fluxo {
        Fluxo {
            protocolo: Protocolo::Tcp,
            porta_local: 50000,
            remoto: ECO,
            porta_remota: 7,
            barrado,
            escuta: false,
        }
    }

    fn tftp() -> Fluxo {
        Fluxo {
            protocolo: Protocolo::Udp,
            porta_local: 50001,
            remoto: [10, 0, 2, 2],
            porta_remota: 69,
            barrado: None,
            escuta: false,
        }
    }

    /// Um segmento TCP com os bits dados.
    fn segmento(origem: [u8; 4], destino: [u8; 4], po: u16, pd: u16, bits: u8) -> Vec<u8> {
        let mut q = quadro(6, origem, destino, po, pd);
        q[14 + 20 + 13] = bits;
        q
    }

    const CANAL: u16 = 7070;
    const HOSPEDEIRO: [u8; 4] = [10, 0, 2, 2];

    /// A conexão do canal que a pilha já aceitou: um fluxo como os outros.
    fn aceita(barrado: Option<u64>) -> Fluxo {
        Fluxo {
            protocolo: Protocolo::Tcp,
            porta_local: CANAL,
            remoto: HOSPEDEIRO,
            porta_remota: 40000,
            barrado,
            escuta: false,
        }
    }

    #[test]
    fn so_sai_o_que_tem_fluxo() {
        let fluxos = [eco(None), tftp()];
        assert_eq!(
            saida(&quadro(6, GUEST, ECO, 50000, 7), &fluxos),
            Veredito::Passa
        );
        // Outra porta local, outro destino, outro protocolo: sem fluxo.
        for q in [
            quadro(6, GUEST, ECO, 50002, 7),
            quadro(6, GUEST, ECO, 50000, 8),
            quadro(6, GUEST, [10, 0, 2, 101], 50000, 7),
            quadro(17, GUEST, ECO, 50000, 7),
        ] {
            assert_eq!(saida(&q, &fluxos), Veredito::Descarta(Motivo::SemFluxo));
        }
        // O DHCP da placa, e o ARP, passam sem fluxo.
        assert_eq!(
            saida(&quadro(17, [0; 4], [255; 4], 68, 67), &[]),
            Veredito::Passa
        );
        let mut arp = alloc::vec![0u8; 42];
        arp[12] = 0x08;
        arp[13] = 0x06;
        assert_eq!(saida(&arp, &[]), Veredito::Passa);
        // ICMP, IPv6, um fragmento, um quadro cortado: não.
        for q in [
            quadro(1, GUEST, ECO, 0, 0),
            {
                let mut q = quadro(6, GUEST, ECO, 50000, 7);
                q[12] = 0x86;
                q[13] = 0xDD;
                q
            },
            {
                let mut q = quadro(6, GUEST, ECO, 50000, 7);
                q[14 + 6] = 0x20;
                q
            },
            quadro(6, GUEST, ECO, 50000, 7)[..14 + 21].to_vec(),
            alloc::vec![0u8; 5],
        ] {
            assert_eq!(saida(&q, &fluxos), Veredito::Descarta(Motivo::Protocolo));
        }
    }

    #[test]
    fn so_entra_o_que_vai_a_um_fluxo() {
        let fluxos = [eco(None), tftp()];
        assert_eq!(
            entrada(&quadro(6, ECO, GUEST, 7, 50000), &fluxos),
            Veredito::Passa
        );
        // TCP de outra origem na porta de um fluxo: sem fluxo — sem RST.
        assert_eq!(
            entrada(&quadro(6, [10, 0, 2, 2], GUEST, 7, 50000), &fluxos),
            Veredito::Descarta(Motivo::SemFluxo)
        );
        // UDP de outra origem na porta de uma associação: passa, e a
        // associação o descarta.
        assert_eq!(
            entrada(&quadro(17, [10, 0, 2, 99], GUEST, 9, 50001), &fluxos),
            Veredito::Passa
        );
        // Para uma porta sem fluxo: não.
        assert_eq!(
            entrada(&quadro(17, [10, 0, 2, 2], GUEST, 69, 50009), &fluxos),
            Veredito::Descarta(Motivo::SemFluxo)
        );
        assert_eq!(
            entrada(&quadro(17, [10, 0, 2, 2], [255; 4], 67, 68), &[]),
            Veredito::Passa
        );
        assert_eq!(
            entrada(&quadro(1, ECO, GUEST, 0, 0), &fluxos),
            Veredito::Descarta(Motivo::Protocolo)
        );
    }

    /// Na escuta do canal só entra o SYN — de quem for: quem chega ainda
    /// tem de provar a chave no aperto do canal. Um ACK, dados, um FIN ou
    /// um RST sem a conexão aceita não entram; outra porta não tem escuta,
    /// e a escuta é do TCP.
    #[test]
    fn a_escuta_so_recebe_o_syn() {
        let fluxos = [Fluxo::escuta(CANAL), eco(None)];
        for origem in [HOSPEDEIRO, [192, 168, 7, 9]] {
            for bits in [SYN, SYN | 0xC0] {
                assert_eq!(
                    entrada(&segmento(origem, GUEST, 40000, CANAL, bits), &fluxos),
                    Veredito::Passa,
                    "bits {bits:#04x}"
                );
            }
        }
        for bits in [
            ACK,
            SYN | ACK,
            ACK | 0x08,
            FIN | ACK,
            RST,
            SYN | FIN,
            SYN | RST,
            0,
        ] {
            assert_eq!(
                entrada(&segmento(HOSPEDEIRO, GUEST, 40000, CANAL, bits), &fluxos),
                Veredito::Descarta(Motivo::SemFluxo),
                "bits {bits:#04x}"
            );
        }
        assert_eq!(
            entrada(&segmento(HOSPEDEIRO, GUEST, 40000, CANAL + 1, SYN), &fluxos),
            Veredito::Descarta(Motivo::SemFluxo)
        );
        assert_eq!(
            entrada(&quadro(17, HOSPEDEIRO, GUEST, 40000, CANAL), &fluxos),
            Veredito::Descarta(Motivo::SemFluxo)
        );
        // Um TCP sem os bits — cortado antes do byte 13 — não é TCP inteiro.
        let curto = quadro(6, HOSPEDEIRO, GUEST, 40000, CANAL)[..14 + 20 + 10].to_vec();
        assert_eq!(
            entrada(&curto, &fluxos),
            Veredito::Descarta(Motivo::Protocolo)
        );
    }

    /// Da escuta só sai a resposta a um SYN — o SYN-ACK que aceita, ou o
    /// RST que recusa —, e nunca um SYN, dados ou um FIN: ela não começa
    /// conversa.
    #[test]
    fn a_escuta_so_responde() {
        let fluxos = [Fluxo::escuta(CANAL)];
        for bits in [SYN | ACK, RST, RST | ACK] {
            assert_eq!(
                saida(&segmento(GUEST, HOSPEDEIRO, CANAL, 40000, bits), &fluxos),
                Veredito::Passa,
                "bits {bits:#04x}"
            );
        }
        for bits in [SYN, ACK, ACK | 0x08, FIN | ACK, SYN | ACK | FIN, 0] {
            assert_eq!(
                saida(&segmento(GUEST, HOSPEDEIRO, CANAL, 40000, bits), &fluxos),
                Veredito::Descarta(Motivo::SemFluxo),
                "bits {bits:#04x}"
            );
        }
        assert_eq!(
            saida(
                &segmento(GUEST, HOSPEDEIRO, CANAL + 1, 40000, SYN | ACK),
                &fluxos
            ),
            Veredito::Descarta(Motivo::SemFluxo)
        );
    }

    /// A escuta não é a conversa de ninguém: um segmento forjado com a
    /// "quádrupla" dela — origem zero, porta zero — não casa com ela.
    #[test]
    fn a_escuta_nao_casa_como_quadrupla() {
        let fluxos = [Fluxo::escuta(CANAL)];
        assert_eq!(
            entrada(&segmento([0; 4], GUEST, 0, CANAL, ACK), &fluxos),
            Veredito::Descarta(Motivo::SemFluxo)
        );
        assert_eq!(
            saida(&segmento(GUEST, [0; 4], CANAL, 0, ACK), &fluxos),
            Veredito::Descarta(Motivo::SemFluxo)
        );
    }

    /// A conexão aceita é um fluxo da tabela: conversa nos dois sentidos, e
    /// a regra que a alcança a barra — a escuta não a protege, nem o RST
    /// dela passa por uma conversa barrada.
    #[test]
    fn a_conexao_aceita_e_um_fluxo() {
        let fluxos = [Fluxo::escuta(CANAL), aceita(None)];
        assert_eq!(
            entrada(
                &segmento(HOSPEDEIRO, GUEST, 40000, CANAL, ACK | 0x08),
                &fluxos
            ),
            Veredito::Passa
        );
        assert_eq!(
            saida(
                &segmento(GUEST, HOSPEDEIRO, CANAL, 40000, ACK | 0x08),
                &fluxos
            ),
            Veredito::Passa
        );
        let barrada = [Fluxo::escuta(CANAL), aceita(Some(3))];
        assert_eq!(
            entrada(&segmento(HOSPEDEIRO, GUEST, 40000, CANAL, ACK), &barrada),
            Veredito::Descarta(Motivo::Regra(3))
        );
        for bits in [ACK, RST] {
            assert_eq!(
                saida(&segmento(GUEST, HOSPEDEIRO, CANAL, 40000, bits), &barrada),
                Veredito::Descarta(Motivo::Regra(3))
            );
        }
    }

    #[test]
    fn a_regra_barra_nos_dois_sentidos() {
        let fluxos = [eco(Some(4))];
        assert_eq!(
            saida(&quadro(6, GUEST, ECO, 50000, 7), &fluxos),
            Veredito::Descarta(Motivo::Regra(4))
        );
        assert_eq!(
            entrada(&quadro(6, ECO, GUEST, 7, 50000), &fluxos),
            Veredito::Descarta(Motivo::Regra(4))
        );
    }

    #[test]
    fn o_escopo() {
        let k = [0xAA; 32];
        let do_agente = DonoDoFluxo {
            agente: Some(k),
            ..Default::default()
        };
        let do_processo_dele = DonoDoFluxo {
            processo: Some(9),
            agente: Some(k),
            ..Default::default()
        };
        let de_outro = DonoDoFluxo {
            agente: Some([0xBB; 32]),
            ..Default::default()
        };
        let da_serial = DonoDoFluxo {
            serial: true,
            ..Default::default()
        };
        assert!(Escopo::Agente(k).alcanca(&do_agente));
        assert!(Escopo::Agente(k).alcanca(&do_processo_dele));
        assert!(!Escopo::Agente(k).alcanca(&de_outro));
        assert!(Escopo::Processo(9).alcanca(&do_processo_dele));
        assert!(!Escopo::Processo(9).alcanca(&do_agente));
        assert!(Escopo::Serial.alcanca(&da_serial) && !Escopo::Serial.alcanca(&do_agente));
        assert!(Escopo::Todos.alcanca(&de_outro));
        for e in [
            Escopo::Todos,
            Escopo::Agente(k),
            Escopo::Pessoa([1; 8]),
            Escopo::Processo(12),
            Escopo::Serial,
        ] {
            let t = e.texto();
            assert_eq!(Escopo::ler((!t.is_empty()).then_some(t.as_str())), Some(e));
        }
        for ruim in [
            "agent:aa",
            "person:",
            "process:",
            "process:012",
            "process:-1",
            "proc:1",
            "*",
        ] {
            assert_eq!(Escopo::ler(Some(ruim)), None, "{ruim}");
        }
    }

    #[test]
    fn a_tabela() {
        let d = politica::endereco::ler("tcp:10.0.2.100:7").unwrap();
        let mut t = Regras::nova();
        assert_eq!(t.por(d, Escopo::Todos, 5, "nsf"), Ok((1, true)));
        assert_eq!(t.por(d, Escopo::Todos, 6, "serial"), Ok((1, false)));
        assert_eq!(t.por(d, Escopo::Processo(3), 7, "nsf"), Ok((2, true)));
        let dono = DonoDoFluxo {
            processo: Some(3),
            ..Default::default()
        };
        assert_eq!(barrado(t.todas(), &d, &dono), Some(1));
        assert_eq!(t.tirar(&d, &Escopo::Todos), Some(1));
        assert_eq!(barrado(t.todas(), &d, &dono), Some(2));
        assert_eq!(barrado(t.todas(), &d, &DonoDoFluxo::default()), None);
        assert_eq!(t.tirar(&d, &Escopo::Todos), None);
        for i in 0..MAIS_REGRAS as u64 {
            let _ = t.por(d, Escopo::Processo(100 + i), i, "nsf");
        }
        assert!(t.por(d, Escopo::Serial, 1, "x").is_err());
        let fluxos: Vec<Fluxo> = fluxos([(d, 50000, dono)].into_iter(), t.todas()).collect();
        assert_eq!(fluxos[0].barrado, Some(2));
    }
}
