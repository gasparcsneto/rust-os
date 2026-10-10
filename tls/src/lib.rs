//! O TLS do Duke: o cliente TLS 1.3 com que um programa conversa com um
//! servidor que nunca viu.
//!
//! # O que é, e o que não é
//!
//! Um programa, como o DNS (`docs/SEGURANCA.md`, 9.4): o TLS roda dentro do
//! processo, sobre a conexão TCP que o gate decidiu — `net.connect` com o
//! destino inteiro, e cada `net.send` e `net.recv` decidido de novo. O
//! kernel não vê o texto claro, nem as chaves, nem o nome do servidor: vê
//! bytes cifrados indo para um destino que a política enumera.
//!
//! O certificado autentica o servidor **para o programa**: prova que do
//! outro lado está quem o nome diz. Ele não autoriza nada. O nome não é
//! recurso da política, e um certificado válido para um nome não abre
//! destino nenhum: o gate decidiu o destino antes do primeiro byte do TLS,
//! e continua decidindo cada uso da conexão depois do aperto. Uma política
//! que tira o destino do alcance no meio da sessão derruba a sessão com o
//! código do gate, e não com um do TLS.
//!
//! # De onde vem o que o TLS precisa
//!
//! - o **aleatório** — o `random` do `ClientHello` e a chave efêmera — vem
//!   de quem chama, numa semente de 32 bytes por conexão: num programa do
//!   Duke, do `random.read`, pelo gate. A semente é parâmetro de
//!   [`Sessao::conectar`], e não um estado que se configura uma vez: um
//!   processo que se bifurcou não repete no filho a chave efêmera do pai,
//!   porque cada conexão mistura entropia nova. Sem semente o gerador não
//!   inventa nada ([`Falha::SemAcaso`]);
//! - o **relógio** — para a validade dos certificados — vem de quem chama,
//!   em segundos desde 1970: num programa do Duke, o tempo lógico, o RTC
//!   com o piso do journal, que nunca volta. Sem relógio não há conexão: um
//!   certificado vencido não se distinguiria de um válido
//!   ([`Falha::SemRelogio`]);
//! - as **âncoras** — as raízes em que o programa confia — vêm de quem
//!   chama, em PEM ([`Ancoras`]): num programa do Duke, de um arquivo lido
//!   pelo gate. Não há âncora embutida: um programa confia no que lhe
//!   deram, e em nada mais;
//! - o **transporte** — mandar e receber bytes — é de quem chama: o
//!   [`Transporte`] de um programa do Duke é a conexão do `net.connect`.
//!
//! # O perfil
//!
//! TLS 1.3, e só. Suítes: AES-128-GCM, AES-256-GCM e ChaCha20-Poly1305.
//! Troca de chaves: X25519 e P-256. Assinaturas — do servidor e da cadeia
//! —: ECDSA P-256 com SHA-256, e Ed25519. Sem RSA, sem P-384, sem
//! retomada de sessão, sem dados antecipados, sem certificado de cliente.
//! Um servidor fora do perfil é recusado no aperto, com o motivo — nunca
//! aceito com menos verificação. E não há, neste pacote, caminho que pule a
//! verificação: a configuração é montada aqui, com o verificador do
//! `rustls` sobre as âncoras dadas, e quem usa o pacote não a recebe para
//! trocar.
//!
//! # As primitivas
//!
//! As do RustCrypto e do dalek — as mesmas do `sigilo` —, em software. O
//! que este pacote escreve é a composição: cada peça do provedor do
//! `rustls` sobre a primitiva correspondente ([`provedor`]). Os testes
//! conversam com o servidor do `rustls` usando o provedor do *ring* — outra
//! implementação de cada primitiva —, e a bancada do Duke, com o OpenSSL.

#![no_std]

extern crate alloc;

mod acaso;
mod assinatura;
mod cifra;
mod falha;
pub mod provedor;
mod resumo;
mod sessao;
mod troca;

pub use falha::{Codigo, Falha};
pub use sessao::{Ancoras, CLARO_POR_REGISTRO, Sessao, Transporte};

/// Os bytes que um registro TLS 1.3 cifrado tem a mais que o texto: o
/// cabeçalho (5), o tipo verdadeiro (1) e a etiqueta (16).
pub const SOBRA_DO_REGISTRO: usize = 5 + 1 + 16;
