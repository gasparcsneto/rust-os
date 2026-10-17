//! A hora do Duke: as contas do Roughtime e do relógio civil.
//!
//! Aqui moram só as contas. Nada de relógio, de rede ou de trava: quem chama
//! dá os bytes que chegaram e os instantes do contador, e recebe de volta
//! vereditos, intervalos e decisões. O fio do serviço, o gate e a auditoria
//! são do kernel.
//!
//! - [`moldura`]: o pacote — `ROUGHTIM`, o comprimento e a mensagem;
//! - [`mensagem`]: o cabeçalho, as etiquetas e os valores, como fatias dos
//!   bytes recebidos;
//! - [`pedido`]: o pedido da versão 1, de 1024 bytes, e a folha dele;
//! - [`merkle`]: a folha, o nó e a subida pelo caminho;
//! - [`resposta`]: a conferência de uma resposta contra o pedido;
//! - [`pedidos`]: os pedidos em aberto — o id ligado ao principal, à fonte,
//!   à chave fixada e à folha;
//! - [`encadeamento`]: o nonce encadeado;
//! - [`intervalo`]: a amostra como intervalo no instante da chegada;
//! - [`quorum`]: o acordo de pelo menos duas chaves sobre os intervalos;
//! - [`disciplina`]: o relógio civil — o ajuste gradual, o salto, o salto
//!   pendente e os estados;
//! - [`registro`]: as fontes em que se confia — `/etc/duke/tempo` —, o
//!   quórum e os tetos, e a coerência deles com a política.
//!
//! # O protocolo, e de onde vem o que se sabe dele
//!
//! O alvo é a RFC 10049 (Roughtime), **versão 1, e só ela**: o pedido
//! oferece só a versão 1, e uma resposta de outra versão é recusada — nem a
//! `0x8000000c` dos servidores feitos para os rascunhos, nem o protocolo
//! legado do Google, que não tem moldura e usa outro nonce.
//!
//! **O texto oficial da RFC não foi lido**: os endereços do IETF e do RFC
//! Editor estão bloqueados no ambiente em que isto foi escrito. Cada regra
//! diz de onde vem:
//!
//! - **reproduzido**: recalculado byte a byte sobre o par de vetores da RFC
//!   10049 da implementação de referência (`roughenough` 2.2.0) e sobre uma
//!   captura de um servidor da época dos rascunhos. Os dois pares estão em
//!   `testdata/`, e os casos de [`resposta`] os conferem;
//! - **referência**: lido no código da implementação de referência,
//!   incluindo os trechos da RFC que ela cita — uma implementação só, e
//!   citação de segunda mão;
//! - **pendente**: não confirmado; a escolha feita aqui é a do lado que
//!   recusa.
//!
//! Nada aqui declara conformidade com a RFC nem interoperabilidade: os
//! pontos pendentes esperam o texto oficial. Um erro de leitura num ponto
//! pendente faz este lado recusar uma resposta válida, e nunca aceitar uma
//! inválida.
//!
//! # O que nada aqui faz
//!
//! Escolher a hora com uma resposta. Uma resposta válida prova só que o
//! servidor assinou um carimbo depois de receber o nosso pedido, e não que o
//! carimbo está certo. A hora só se move por acordo de pelo menos duas
//! chaves ([`quorum`]), e só dentro das regras da [`disciplina`].

#![no_std]

#[cfg(test)]
extern crate std;

#[cfg(any(test, feature = "servidor"))]
extern crate alloc;

pub mod disciplina;
pub mod encadeamento;
pub mod intervalo;
pub mod mensagem;
pub mod merkle;
pub mod moldura;
pub mod pedido;
pub mod pedidos;
pub mod quorum;
pub mod registro;
pub mod resposta;

#[cfg(any(test, feature = "servidor"))]
pub mod servidor_de_teste;
