//! O HTTP do Duke: o cliente HTTP/1.1 com que um programa conversa com um
//! servidor.
//!
//! # O que é, e o que não é
//!
//! Um programa, como o DNS e o TLS (`docs/SEGURANCA.md`, 9.4 e 9.5): o HTTP
//! roda dentro do processo, sobre a conexão que o gate decidiu —
//! `net.connect` com o destino inteiro, e cada `net.send` e `net.recv`
//! decidido de novo —, direto no TCP ou com o TLS do pacote `tls` no meio.
//! O kernel não sabe de método, de URL, de cabeçalho nem de status: vê
//! bytes indo para um destino que a política enumera — e, com TLS, nem os
//! bytes.
//!
//! Por isso nada do HTTP é autorização. O método, a URL, o `Host`, os
//! cabeçalhos, o status, o corpo, o redirecionamento e o *keep-alive* são
//! do protocolo e de quem o fala: não viram permissão, recurso nem regra.
//! O que o programa pode é o que o gate decide para os pedidos de rede
//! dele, com a autoridade de quem o lançou — e o HTTP não muda isso, nem
//! para mais, nem para menos.
//!
//! # O que este pacote faz
//!
//! - [`Url`]: só `http` e `https`, host por nome ou IPv4 na forma normal;
//! - [`Pedido`]: a linha, o `Host`, os cabeçalhos de quem chama conferidos,
//!   e o corpo com `Content-Length`;
//! - [`Cliente`]: manda o pedido e lê a resposta pelo [`Fluxo`] de quem
//!   chama — com `Content-Length`, em pedaços (`chunked`) ou até o fecho —,
//!   e reaproveita a conexão quando a resposta deixa;
//! - [`Codificacao`]: o corpo comprimido — `gzip` e `deflate` —, negociado
//!   pelo pedido ([`Aceitas`]) e decodificado aqui, com um teto fixado
//!   antes de descomprimir ([`codificacao`]). A
//!   compressão é do protocolo: o gate não a vê, e nada nela autoriza ou
//!   recusa;
//! - [`Limites`]: a maior linha, a maior cabeça, quantos cabeçalhos, o
//!   maior corpo e o maior corpo decodificado — a memória não cresce na
//!   vontade do servidor;
//! - [`Erro`]: a falha de baixo como veio, a conexão que acabou cedo, o
//!   protocolo, os limites e o conteúdo que não se decodifica, sem se
//!   confundirem;
//! - [`categoria`]: de que família é o código de uma falha — a recusa do
//!   gate, a contenção, o firewall, o DNS, o transporte, o prazo, o TLS, a
//!   conversa que acabou cedo, o protocolo, os limites —, para quem se
//!   recupera não misturar uma com a outra. Nomear não é decidir: o código
//!   é de quem o deu.
//!
//! # O que fica de fora, de propósito
//!
//! HTTP/2 e HTTP/3, pedidos em fila, cookies, autenticação, *proxy*, a
//! compressão do pedido, o `Transfer-Encoding` que não é `chunked`, o
//! Brotli e seguir redirecionamento sozinho: uma resposta `3xx` volta a
//! quem chama com o `Location`, e ir até lá é outro pedido — outro nome no
//! DNS, outro destino no gate.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod categoria;
mod cliente;
pub mod codificacao;
mod erro;
mod inflar;
mod pedido;
mod resposta;
mod url;

#[cfg(test)]
mod testes;
#[cfg(test)]
mod testes_da_codificacao;

pub use categoria::{Categoria, categoria};
pub use cliente::{Cliente, Fluxo};
pub use codificacao::{Aceitas, Codificacao};
pub use erro::{Defeito, Erro, Limite, Motivo};
pub use pedido::{ErroDePedido, Metodo, Pedido};
pub use resposta::{Enquadramento, Limites, Resposta, Versao};
pub use url::{ErroDeUrl, Esquema, Host, MAIOR_URL, Url};
