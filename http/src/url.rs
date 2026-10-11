//! A URL de um pedido: o esquema, o host, a porta e o alvo.
//!
//! # O que se aceita
//!
//! `http://` e `https://`, e nada mais. O host é um nome DNS ou um IPv4 na
//! forma normal — quatro números de 0 a 255, sem zero à esquerda, a mesma
//! regra dos destinos da política, para que `10.0.2.010` não seja lido de
//! dois jeitos —; a porta, quando há, de 1 a 65535, também sem zero à
//! esquerda. O alvo é o caminho com a consulta; o fragmento sai, porque não
//! vai ao servidor.
//!
//! E o que se recusa, de propósito:
//!
//! - credenciais na URL (`http://quem@host/`): o `@` é o jeito clássico de
//!   fazer uma URL parecer de um host e ser de outro;
//! - IPv6 (`[::1]`): a pilha do Duke não tem;
//! - qualquer byte fora do ASCII visível — espaço, controle, acento: o
//!   alvo vai para a linha do pedido como está, e um espaço ou um CR ali
//!   seria outro pedido. Quem precisa de um desses bytes o escreve com `%`.
//!
//! # O que a URL **não** é
//!
//! Um recurso da política. O host é um nome — o DNS o transforma num
//! endereço, e é o endereço, com a porta, que o gate decide em
//! `net.connect` —, e o nome vai para o TLS conferir o certificado e para o
//! cabeçalho `Host`. Nada daqui autoriza nada.

use alloc::string::{String, ToString};

/// A maior URL que se lê.
pub const MAIOR_URL: usize = 2048;

/// O maior nome DNS (RFC 1035): 253 caracteres sem o ponto final.
const MAIOR_NOME: usize = 253;

/// O maior rótulo de um nome.
const MAIOR_ROTULO: usize = 63;

/// `http` ou `https`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Esquema {
    Http,
    Https,
}

impl Esquema {
    /// A porta de quando a URL não diz uma.
    pub const fn porta_padrao(self) -> u16 {
        match self {
            Esquema::Http => 80,
            Esquema::Https => 443,
        }
    }

    pub const fn nome(self) -> &'static str {
        match self {
            Esquema::Http => "http",
            Esquema::Https => "https",
        }
    }
}

/// O host de uma URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {
    /// Um nome DNS, em minúsculas.
    Nome(String),
    /// Um endereço IPv4.
    Ipv4([u8; 4]),
}

/// Por que um texto não é uma URL que o cliente aceita.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErroDeUrl {
    /// Nem `http://` nem `https://`.
    Esquema,
    /// Um `@` antes do host: credenciais na URL.
    Credenciais,
    /// Um host vazio, ou que não é nem nome nem IPv4 na forma normal.
    Host,
    /// Um endereço IPv6.
    Ipv6,
    /// Uma porta vazia, zero, grande demais ou com zero à esquerda.
    Porta,
    /// Um byte fora do ASCII visível.
    Caractere,
    /// Mais que [`MAIOR_URL`] bytes.
    Grande,
}

/// Uma URL que o cliente aceita — ver o cabeçalho do módulo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub esquema: Esquema,
    pub host: Host,
    pub porta: u16,
    /// O caminho e a consulta, começando por `/`.
    pub alvo: String,
}

impl Url {
    /// Lê `texto` como URL.
    pub fn ler(texto: &str) -> Result<Url, ErroDeUrl> {
        if texto.len() > MAIOR_URL {
            return Err(ErroDeUrl::Grande);
        }
        if !texto.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ErroDeUrl::Caractere);
        }
        let (esquema, resto) = if let Some(r) = sem_prefixo(texto, "http://") {
            (Esquema::Http, r)
        } else if let Some(r) = sem_prefixo(texto, "https://") {
            (Esquema::Https, r)
        } else {
            return Err(ErroDeUrl::Esquema);
        };
        let fim = resto.find(['/', '?', '#']).unwrap_or(resto.len());
        let (autoridade, alvo) = resto.split_at(fim);
        if autoridade.contains('@') {
            return Err(ErroDeUrl::Credenciais);
        }
        if autoridade.starts_with('[') {
            return Err(ErroDeUrl::Ipv6);
        }
        let (host, porta) = match autoridade.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (autoridade, None),
        };
        let host = ler_host(host)?;
        let porta = match porta {
            Some(p) => ler_porta(p)?,
            None => esquema.porta_padrao(),
        };
        // O fragmento é de quem lê a página, e não vai ao servidor.
        let alvo = alvo.split('#').next().unwrap_or("");
        let alvo = if alvo.starts_with('/') {
            alvo.to_string()
        } else {
            // Só a consulta, ou nada: o caminho é a raiz.
            alloc::format!("/{alvo}")
        };
        Ok(Url {
            esquema,
            host,
            porta,
            alvo,
        })
    }

    /// O host como texto: o nome, ou o endereço com pontos. É o que o TLS
    /// confere no certificado.
    pub fn nome(&self) -> String {
        match &self.host {
            Host::Nome(n) => n.clone(),
            Host::Ipv4([a, b, c, d]) => alloc::format!("{a}.{b}.{c}.{d}"),
        }
    }

    /// O valor do cabeçalho `Host`: o host, e a porta quando não é a do
    /// esquema.
    pub fn autoridade(&self) -> String {
        if self.porta == self.esquema.porta_padrao() {
            self.nome()
        } else {
            alloc::format!("{}:{}", self.nome(), self.porta)
        }
    }
}

/// `texto` sem `prefixo`, comparado sem diferença de maiúsculas.
fn sem_prefixo<'a>(texto: &'a str, prefixo: &str) -> Option<&'a str> {
    let cabeca = texto.get(..prefixo.len())?;
    cabeca
        .eq_ignore_ascii_case(prefixo)
        .then(|| &texto[prefixo.len()..])
}

/// Um número decimal na forma normal: dígitos, sem zero à esquerda.
fn decimal(texto: &str) -> Option<u32> {
    if texto.is_empty()
        || texto.len() > 5
        || !texto.bytes().all(|b| b.is_ascii_digit())
        || (texto.len() > 1 && texto.starts_with('0'))
    {
        return None;
    }
    texto.parse().ok()
}

fn ler_porta(texto: &str) -> Result<u16, ErroDeUrl> {
    match decimal(texto) {
        Some(p) if (1..=u32::from(u16::MAX)).contains(&p) => Ok(p as u16),
        _ => Err(ErroDeUrl::Porta),
    }
}

fn ler_host(texto: &str) -> Result<Host, ErroDeUrl> {
    if texto.is_empty() {
        return Err(ErroDeUrl::Host);
    }
    // Só dígitos e pontos: é um endereço, e tem de ser um na forma normal —
    // não um nome que pareça endereço.
    if texto.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        let mut partes = texto.split('.');
        let mut ip = [0u8; 4];
        for octeto in &mut ip {
            let n = partes.next().and_then(decimal).ok_or(ErroDeUrl::Host)?;
            *octeto = u8::try_from(n).map_err(|_| ErroDeUrl::Host)?;
        }
        if partes.next().is_some() {
            return Err(ErroDeUrl::Host);
        }
        return Ok(Host::Ipv4(ip));
    }
    if texto.len() > MAIOR_NOME {
        return Err(ErroDeUrl::Host);
    }
    for rotulo in texto.split('.') {
        let b = rotulo.as_bytes();
        let valido = !b.is_empty()
            && b.len() <= MAIOR_ROTULO
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
            && b[0] != b'-'
            && b[b.len() - 1] != b'-';
        if !valido {
            return Err(ErroDeUrl::Host);
        }
    }
    Ok(Host::Nome(texto.to_ascii_lowercase()))
}

#[cfg(test)]
mod testes {
    use super::*;

    fn url(texto: &str) -> Url {
        Url::ler(texto).unwrap_or_else(|e| panic!("{texto}: {e:?}"))
    }

    #[test]
    fn o_esquema_da_a_porta_e_o_host_o_nome() {
        let u = url("http://bancada.duke/ola");
        assert_eq!(u.esquema, Esquema::Http);
        assert_eq!(u.host, Host::Nome("bancada.duke".into()));
        assert_eq!(u.porta, 80);
        assert_eq!(u.alvo, "/ola");
        assert_eq!(u.autoridade(), "bancada.duke");
        let u = url("HTTPS://Bancada.Duke:8443/a/b?c=d&e=f#fim");
        assert_eq!(u.esquema, Esquema::Https);
        assert_eq!(u.host, Host::Nome("bancada.duke".into()));
        assert_eq!(u.porta, 8443);
        assert_eq!(u.alvo, "/a/b?c=d&e=f");
        assert_eq!(u.autoridade(), "bancada.duke:8443");
        assert_eq!(u.nome(), "bancada.duke");
    }

    #[test]
    fn sem_caminho_o_alvo_e_a_raiz() {
        assert_eq!(url("http://10.0.2.100").alvo, "/");
        assert_eq!(url("http://10.0.2.100?x=1").alvo, "/?x=1");
        assert_eq!(url("http://10.0.2.100#frag").alvo, "/");
        assert_eq!(url("https://bancada.duke").porta, 443);
    }

    #[test]
    fn o_endereco_so_na_forma_normal() {
        let u = url("http://10.0.2.100:80/");
        assert_eq!(u.host, Host::Ipv4([10, 0, 2, 100]));
        assert_eq!(u.autoridade(), "10.0.2.100");
        for errado in [
            "http://10.0.2.010/",
            "http://10.0.2/",
            "http://10.0.2.100.1/",
            "http://10.0.2.256/",
            "http://10..2.100/",
            "http://1234567890/",
        ] {
            assert_eq!(Url::ler(errado), Err(ErroDeUrl::Host), "{errado}");
        }
    }

    #[test]
    fn a_porta_e_conferida() {
        for errado in [
            "http://h:/",
            "http://h:0/",
            "http://h:65536/",
            "http://h:080/",
            "http://h:8a/",
            "http://h:1:2/",
        ] {
            assert_eq!(Url::ler(errado), Err(ErroDeUrl::Porta), "{errado}");
        }
        assert_eq!(url("http://h:65535/").porta, 65535);
    }

    #[test]
    fn o_que_se_recusa_de_proposito() {
        assert_eq!(Url::ler("ftp://h/"), Err(ErroDeUrl::Esquema));
        assert_eq!(Url::ler("http:/h/"), Err(ErroDeUrl::Esquema));
        assert_eq!(Url::ler("//h/"), Err(ErroDeUrl::Esquema));
        assert_eq!(
            Url::ler("http://bancada.duke@10.0.2.99/"),
            Err(ErroDeUrl::Credenciais)
        );
        assert_eq!(Url::ler("http://[::1]/"), Err(ErroDeUrl::Ipv6));
        assert_eq!(Url::ler("http://h/a b"), Err(ErroDeUrl::Caractere));
        assert_eq!(Url::ler("http://h/a\r\nX: y"), Err(ErroDeUrl::Caractere));
        assert_eq!(Url::ler("http://h/ç"), Err(ErroDeUrl::Caractere));
        assert_eq!(Url::ler("http:///"), Err(ErroDeUrl::Host));
        let longa = alloc::format!("http://h/{}", "a".repeat(MAIOR_URL));
        assert_eq!(Url::ler(&longa), Err(ErroDeUrl::Grande));
    }

    #[test]
    fn o_nome_e_conferido_rotulo_a_rotulo() {
        for errado in [
            "http://-a.duke/",
            "http://a-.duke/",
            "http://a..duke/",
            "http://a_b.duke/",
            "http://.duke/",
            "http://duke./",
        ] {
            assert_eq!(Url::ler(errado), Err(ErroDeUrl::Host), "{errado}");
        }
        let rotulo = "a".repeat(64);
        assert_eq!(
            Url::ler(&alloc::format!("http://{rotulo}.duke/")),
            Err(ErroDeUrl::Host)
        );
        let comprido = alloc::vec!["a".repeat(63); 4].join(".");
        assert_eq!(
            Url::ler(&alloc::format!("http://{comprido}/")),
            Err(ErroDeUrl::Host)
        );
        assert!(Url::ler("http://a-b.c9.duke/").is_ok());
    }
}
