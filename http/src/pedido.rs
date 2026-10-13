//! O pedido: a linha, os cabeçalhos e o corpo, escritos como o HTTP/1.1
//! manda (RFC 9112).
//!
//! # Quem escreve o quê
//!
//! A linha do pedido, o `Host`, o `Content-Length` e o `Connection` são
//! escritos aqui, e só aqui: são eles que dizem onde a mensagem acaba, e
//! um cabeçalho desses vindo de quem chama — um segundo `Content-Length`,
//! um `Transfer-Encoding` — faria o servidor ler o pedido de um jeito e o
//! cliente o escrever de outro, que é como se contrabandeia um pedido
//! dentro de outro. O `Accept-Encoding` também: ele diz o que o cliente
//! decodifica ([`Pedido::aceitas`]), e um escrito por quem chama pediria o
//! que o cliente não decodifica. Quem chama acrescenta os outros, e cada um
//! é conferido: o nome é um *token*, e o valor não tem CR, LF nem NUL — sem
//! isso, um valor com `\r\n` seria uma linha nova.

use alloc::string::String;
use alloc::vec::Vec;

use crate::codificacao::Aceitas;
use crate::url::Url;

/// Os métodos que o cliente pede.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Metodo {
    Get,
    Head,
    Post,
    Put,
    Delete,
}

impl Metodo {
    pub const fn nome(self) -> &'static str {
        match self {
            Metodo::Get => "GET",
            Metodo::Head => "HEAD",
            Metodo::Post => "POST",
            Metodo::Put => "PUT",
            Metodo::Delete => "DELETE",
        }
    }

    /// O método leva corpo: o `Content-Length` vai sempre, mesmo zero —
    /// um servidor que espera um corpo e não sabe o tamanho esperaria o
    /// fecho.
    const fn leva_corpo(self) -> bool {
        matches!(self, Metodo::Post | Metodo::Put)
    }
}

/// Por que um cabeçalho não entrou no pedido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErroDePedido {
    /// O nome não é um *token*.
    Nome,
    /// O valor tem CR, LF, NUL ou outro controle.
    Valor,
    /// O cabeçalho é dos que este pacote escreve — ver o cabeçalho do
    /// módulo.
    Reservado,
    /// Cabeçalhos demais, ou grandes demais.
    Grande,
}

/// Os cabeçalhos que só este pacote escreve.
const RESERVADOS: [&str; 11] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "accept-encoding",
];

/// Quantos cabeçalhos quem chama pode pôr.
const MAIS_CABECALHOS: usize = 32;

/// Quantos bytes, nome e valor juntos, cada um pode ter.
const MAIOR_CABECALHO: usize = 4096;

/// Um `tchar` da RFC 9110, 5.6.2: o que pode estar num nome de cabeçalho.
pub(crate) fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Um pedido.
#[derive(Clone, Debug)]
pub struct Pedido {
    pub metodo: Metodo,
    pub url: Url,
    cabecalhos: Vec<(String, String)>,
    pub corpo: Vec<u8>,
    /// Pede ao servidor que feche a conexão depois da resposta
    /// (`Connection: close`): a conexão não leva outro pedido.
    pub fechar: bool,
    /// As codificações de conteúdo que o pedido aceita
    /// (`Accept-Encoding`), e que o cliente decodifica — todas, a menos que
    /// quem chama diga outra coisa. Ver [`crate::codificacao`].
    pub aceitas: Aceitas,
}

impl Pedido {
    /// Um pedido sem cabeçalhos de quem chama e sem corpo.
    pub fn novo(metodo: Metodo, url: Url) -> Pedido {
        Pedido {
            metodo,
            url,
            cabecalhos: Vec::new(),
            corpo: Vec::new(),
            fechar: false,
            aceitas: Aceitas::TODAS,
        }
    }

    /// Acrescenta o cabeçalho `nome: valor`, conferido — ver o cabeçalho
    /// do módulo.
    pub fn cabecalho(&mut self, nome: &str, valor: &str) -> Result<(), ErroDePedido> {
        if nome.is_empty() || !nome.bytes().all(tchar) {
            return Err(ErroDePedido::Nome);
        }
        if RESERVADOS.iter().any(|r| r.eq_ignore_ascii_case(nome)) {
            return Err(ErroDePedido::Reservado);
        }
        // O valor: texto visível, espaço e tabulação; nada de controle.
        if !valor
            .bytes()
            .all(|b| b == b' ' || b == b'\t' || b.is_ascii_graphic() || b >= 0x80)
        {
            return Err(ErroDePedido::Valor);
        }
        if self.cabecalhos.len() >= MAIS_CABECALHOS || nome.len() + valor.len() > MAIOR_CABECALHO {
            return Err(ErroDePedido::Grande);
        }
        self.cabecalhos
            .push((String::from(nome), String::from(valor.trim())));
        Ok(())
    }

    /// Os cabeçalhos que quem chama pôs.
    pub fn cabecalhos(&self) -> &[(String, String)] {
        &self.cabecalhos
    }

    /// O pedido como vai para a conexão.
    pub fn escrever(&self) -> Vec<u8> {
        let mut s = String::new();
        s.push_str(self.metodo.nome());
        s.push(' ');
        s.push_str(&self.url.alvo);
        s.push_str(" HTTP/1.1\r\nHost: ");
        s.push_str(&self.url.autoridade());
        s.push_str("\r\nAccept-Encoding: ");
        s.push_str(self.aceitas.cabecalho());
        s.push_str("\r\n");
        for (nome, valor) in &self.cabecalhos {
            s.push_str(nome);
            s.push_str(": ");
            s.push_str(valor);
            s.push_str("\r\n");
        }
        if self.metodo.leva_corpo() || !self.corpo.is_empty() {
            s.push_str(&alloc::format!("Content-Length: {}\r\n", self.corpo.len()));
        }
        if self.fechar {
            s.push_str("Connection: close\r\n");
        }
        s.push_str("\r\n");
        let mut bytes = s.into_bytes();
        bytes.extend_from_slice(&self.corpo);
        bytes
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    fn pedido(metodo: Metodo, url: &str) -> Pedido {
        Pedido::novo(metodo, Url::ler(url).unwrap())
    }

    fn texto(p: &Pedido) -> String {
        String::from_utf8(p.escrever()).unwrap()
    }

    #[test]
    fn o_get_tem_a_linha_e_o_host() {
        let p = pedido(Metodo::Get, "http://bancada.duke/ola?x=1#f");
        assert_eq!(
            texto(&p),
            "GET /ola?x=1 HTTP/1.1\r\nHost: bancada.duke\r\nAccept-Encoding: gzip, deflate\r\n\r\n"
        );
        let p = pedido(Metodo::Head, "https://bancada.duke:8443/");
        assert_eq!(
            texto(&p),
            "HEAD / HTTP/1.1\r\nHost: bancada.duke:8443\r\nAccept-Encoding: gzip, deflate\r\n\r\n"
        );
    }

    #[test]
    fn o_post_diz_o_tamanho_do_corpo() {
        let mut p = pedido(Metodo::Post, "http://10.0.2.100/eco");
        p.corpo = b"abc".to_vec();
        p.cabecalho("Content-Type", "text/plain").unwrap();
        p.fechar = true;
        assert_eq!(
            texto(&p),
            "POST /eco HTTP/1.1\r\nHost: 10.0.2.100\r\nAccept-Encoding: gzip, deflate\r\n\
             Content-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc"
        );
        // Sem corpo, o POST diz zero.
        let p = pedido(Metodo::Post, "http://10.0.2.100/eco");
        assert!(texto(&p).contains("Content-Length: 0\r\n"));
        let p = pedido(Metodo::Get, "http://10.0.2.100/");
        assert!(!texto(&p).contains("Content-Length"));
    }

    #[test]
    fn os_cabecalhos_de_quem_chama_sao_conferidos() {
        let mut p = pedido(Metodo::Get, "http://h/");
        assert_eq!(p.cabecalho("X Y", "1"), Err(ErroDePedido::Nome));
        assert_eq!(p.cabecalho("", "1"), Err(ErroDePedido::Nome));
        assert_eq!(p.cabecalho("X:Y", "1"), Err(ErroDePedido::Nome));
        assert_eq!(
            p.cabecalho("X-Duke", "1\r\nContent-Length: 0"),
            Err(ErroDePedido::Valor)
        );
        assert_eq!(p.cabecalho("X-Duke", "a\nb"), Err(ErroDePedido::Valor));
        assert_eq!(p.cabecalho("X-Duke", "a\0b"), Err(ErroDePedido::Valor));
        for reservado in [
            "Host",
            "content-length",
            "Transfer-Encoding",
            "CONNECTION",
            "Upgrade",
            "Expect",
            "Accept-Encoding",
        ] {
            assert_eq!(
                p.cabecalho(reservado, "x"),
                Err(ErroDePedido::Reservado),
                "{reservado}"
            );
        }
        assert!(p.cabecalho("X-Duke-Token", "  a b\tc  ").is_ok());
        assert!(texto(&p).contains("X-Duke-Token: a b\tc\r\n"));
        for i in 1..MAIS_CABECALHOS {
            p.cabecalho(&alloc::format!("X-{i}"), "v").unwrap();
        }
        assert_eq!(p.cabecalho("X-Demais", "v"), Err(ErroDePedido::Grande));
    }

    #[test]
    fn o_accept_encoding_diz_o_que_o_cliente_decodifica() {
        for (aceitas, valor) in [
            (Aceitas::TODAS, "gzip, deflate"),
            (
                Aceitas {
                    gzip: true,
                    deflate: false,
                },
                "gzip",
            ),
            (
                Aceitas {
                    gzip: false,
                    deflate: true,
                },
                "deflate",
            ),
            // Sem o cabeçalho, o servidor poderia mandar qualquer uma.
            (Aceitas::NENHUMA, "identity"),
        ] {
            let mut p = pedido(Metodo::Get, "http://h/");
            p.aceitas = aceitas;
            let t = texto(&p);
            assert!(
                t.contains(&alloc::format!("\r\nAccept-Encoding: {valor}\r\n")),
                "{t:?}"
            );
            assert_eq!(t.matches("Accept-Encoding").count(), 1, "{t:?}");
        }
        // O padrão aceita as duas.
        assert_eq!(pedido(Metodo::Get, "http://h/").aceitas, Aceitas::TODAS);
    }
}
