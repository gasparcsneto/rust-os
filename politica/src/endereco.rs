//! Destinos de rede: a forma normal de `tcp:<ipv4>:<porta>` e de
//! `udp:<ipv4>:<porta>`.
//!
//! # Por que enumerado, e por que aqui
//!
//! O alcance de `net.connect` é uma lista de destinos escritos por inteiro —
//! protocolo, endereço e porta —, como o de `message.send` é uma lista de
//! papéis: sem curinga, sem faixa, sem "qualquer porta". Um papel alcança o
//! que a linha dele escreve, e nada que se pareça com isso.
//!
//! A forma normal mora na política pela razão de [`crate::caminho`]: a
//! conferência só vale se o destino conferido for **o mesmo** que o kernel
//! vai discar. Duas leituras de `tcp:010.0.2.1:07` — uma que vê o octeto 10
//! e outra que vê um octal — seriam duas respostas para "que destino é
//! este". Aqui há uma só, e ela recusa o que é ambíguo em vez de adivinhar:
//! zero à esquerda, octeto acima de 255, porta zero ou acima de 65535,
//! espaço, maiúscula, nome de máquina.
//!
//! # O protocolo é parte do destino
//!
//! `tcp:10.0.2.2:69` e `udp:10.0.2.2:69` são dois destinos, e uma
//! linha que alcança um não alcança o outro: o prefixo diz o que o kernel
//! abre — uma conexão TCP, com aperto de mão e fluxo de bytes, ou uma
//! associação UDP, que manda e recebe datagramas inteiros. Só IPv4, por
//! enquanto. Um protocolo novo entra aqui, com o prefixo dele, e cada linha
//! da política continua dizendo qual.

use alloc::format;
use alloc::string::String;

/// O prefixo de um destino TCP.
pub const PREFIXO_TCP: &str = "tcp:";

/// O prefixo de um destino UDP.
pub const PREFIXO_UDP: &str = "udp:";

/// O protocolo de um destino.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocolo {
    /// Uma conexão TCP: aperto de mão, fluxo de bytes, fecho.
    Tcp,
    /// Uma associação UDP: datagramas inteiros, de e para um destino só.
    Udp,
}

impl Protocolo {
    /// O prefixo que o protocolo escreve na forma normal.
    pub const fn prefixo(self) -> &'static str {
        match self {
            Protocolo::Tcp => PREFIXO_TCP,
            Protocolo::Udp => PREFIXO_UDP,
        }
    }
}

/// Um destino de rede, lido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Destino {
    pub protocolo: Protocolo,
    pub ip: [u8; 4],
    pub porta: u16,
}

impl Destino {
    /// A forma normal, a que a política guarda e a decisão compara.
    pub fn texto(&self) -> String {
        let [a, b, c, d] = self.ip;
        format!("{}{a}.{b}.{c}.{d}:{}", self.protocolo.prefixo(), self.porta)
    }
}

/// Um número decimal sem sinal, sem zero à esquerda (o próprio `0` vale),
/// até `teto`.
fn decimal(texto: &str, teto: u32) -> Option<u32> {
    if texto.is_empty() || texto.len() > 5 || !texto.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if texto.len() > 1 && texto.starts_with('0') {
        return None;
    }
    let n: u32 = texto.parse().ok()?;
    (n <= teto).then_some(n)
}

/// Lê `tcp:<a>.<b>.<c>.<d>:<porta>` ou `udp:<a>.<b>.<c>.<d>:<porta>`.
/// `None` para qualquer outra coisa.
pub fn ler(texto: &str) -> Option<Destino> {
    let (protocolo, resto) = if let Some(resto) = texto.strip_prefix(PREFIXO_TCP) {
        (Protocolo::Tcp, resto)
    } else {
        (Protocolo::Udp, texto.strip_prefix(PREFIXO_UDP)?)
    };
    let (ip, porta) = resto.split_once(':')?;
    let porta = decimal(porta, u32::from(u16::MAX))?;
    if porta == 0 {
        return None;
    }
    let mut octetos = [0u8; 4];
    let mut partes = ip.split('.');
    for o in &mut octetos {
        *o = decimal(partes.next()?, 255)? as u8;
    }
    if partes.next().is_some() {
        return None;
    }
    Some(Destino {
        protocolo,
        ip: octetos,
        porta: porta as u16,
    })
}

/// A forma normal de um destino, ou `None` se ele não se lê. Como só a
/// forma normal se lê, ela é a própria entrada — mas quem compara passa
/// por aqui, e não pela igualdade de textos crus.
pub fn normalizar(texto: &str) -> Option<String> {
    ler(texto).map(|d| d.texto())
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn a_forma_normal() {
        assert_eq!(
            ler("tcp:10.0.2.100:7"),
            Some(Destino {
                protocolo: Protocolo::Tcp,
                ip: [10, 0, 2, 100],
                porta: 7
            })
        );
        assert_eq!(
            ler("udp:10.0.2.2:9007"),
            Some(Destino {
                protocolo: Protocolo::Udp,
                ip: [10, 0, 2, 2],
                porta: 9007
            })
        );
        assert_eq!(
            normalizar("udp:0.0.0.0:65535").as_deref(),
            Some("udp:0.0.0.0:65535")
        );
        assert_eq!(
            normalizar("tcp:0.0.0.0:65535").as_deref(),
            Some("tcp:0.0.0.0:65535")
        );
        assert_eq!(
            normalizar("tcp:255.255.255.255:1").as_deref(),
            Some("tcp:255.255.255.255:1")
        );
    }

    #[test]
    fn o_ambiguo_e_recusado() {
        for errado in [
            "",
            "tcp:",
            "tcp:10.0.2.100",
            "tcp:10.0.2.100:",
            "tcp:10.0.2.100:0",
            "tcp:10.0.2.100:65536",
            "tcp:10.0.2.100:07",
            "tcp:010.0.2.100:7",
            "tcp:10.0.2.256:7",
            "tcp:10.0.2:7",
            "tcp:10.0.2.100.1:7",
            "tcp:10.0.2.-1:7",
            "tcp:10.0.2.+1:7",
            "tcp: 10.0.2.100:7",
            "tcp:10.0.2.100:7 ",
            "TCP:10.0.2.100:7",
            "UDP:10.0.2.2:9007",
            "Udp:10.0.2.2:9007",
            "udp:",
            "udp:10.0.2.2",
            "udp:10.0.2.2:0",
            "udp:10.0.2.2:09007",
            "udp:010.0.2.2:9007",
            "udp:maquina:53",
            "udp:10.0.2.2:*",
            "udptcp:10.0.2.2:9007",
            "tcpudp:10.0.2.2:9007",
            "sctp:10.0.2.100:7",
            "tcp:maquina:7",
            "tcp:10.0.2.100:*",
            "tcp:*:7",
            "tcp:10.0.2.100:7:8",
            "tcp:10.0.2.100:123456",
            "10.0.2.100:7",
        ] {
            assert_eq!(ler(errado), None, "{errado:?}");
        }
    }

    /// O protocolo é parte do destino: os mesmos endereço e porta, em
    /// protocolos diferentes, são dois destinos, com duas formas normais.
    #[test]
    fn o_protocolo_separa_os_destinos() {
        let tcp = ler("tcp:10.0.2.2:9007").unwrap();
        let udp = ler("udp:10.0.2.2:9007").unwrap();
        assert_ne!(tcp, udp);
        assert_eq!((tcp.ip, tcp.porta), (udp.ip, udp.porta));
        assert_eq!(tcp.texto(), "tcp:10.0.2.2:9007");
        assert_eq!(udp.texto(), "udp:10.0.2.2:9007");
        assert_ne!(
            normalizar("tcp:10.0.2.2:9007"),
            normalizar("udp:10.0.2.2:9007")
        );
    }
}
