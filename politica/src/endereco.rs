//! Destinos de rede: a forma normal de `tcp:<ipv4>:<porta>`.
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
//! Só TCP e só IPv4, por enquanto. Um protocolo novo entra aqui, com o
//! prefixo dele, e cada linha da política continua dizendo qual.

use alloc::format;
use alloc::string::String;

/// O prefixo de um destino TCP.
pub const PREFIXO_TCP: &str = "tcp:";

/// Um destino TCP, lido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Destino {
    pub ip: [u8; 4],
    pub porta: u16,
}

impl Destino {
    /// A forma normal, a que a política guarda e a decisão compara.
    pub fn texto(&self) -> String {
        let [a, b, c, d] = self.ip;
        format!("{PREFIXO_TCP}{a}.{b}.{c}.{d}:{}", self.porta)
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

/// Lê `tcp:<a>.<b>.<c>.<d>:<porta>`. `None` para qualquer outra coisa.
pub fn ler(texto: &str) -> Option<Destino> {
    let resto = texto.strip_prefix(PREFIXO_TCP)?;
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
                ip: [10, 0, 2, 100],
                porta: 7
            })
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
            "udp:10.0.2.100:7",
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
}
