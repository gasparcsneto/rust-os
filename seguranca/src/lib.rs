//! O tecido nativo de segurança do Duke (NSF): as contas.
//!
//! O NSF observa, correlaciona e interpreta o que acontece no sistema, e
//! **pede** respostas. Não decide nada sobre acesso: a cadeia continua
//!
//! ```text
//! identidade → autoridade → política → gate → recurso
//! ```
//!
//! e o NSF entra nela como qualquer principal — o serviço `nsf`, com o papel
//! que a política lhe dá —, lendo pelo gate e pedindo ao gate. O desenho e
//! os contratos estão em `docs/SEGURANCA.md`.
//!
//! # O que mora aqui
//!
//! Tudo o que é conta, sem relógio e sem trava — o kernel põe o fio, as
//! leituras e os pedidos:
//!
//! - [`evento`]: o registro da auditoria lido, refeito elo a elo, e o
//!   evento de segurança que ele vira;
//! - [`grafo`]: a cadeia causal — quem lançou quem, quem pediu o quê, que
//!   nome levou a que endereço — e a proveniência até a raiz;
//! - [`ueba`]: o perfil de comportamento de cada identidade;
//! - [`risco`]: a pontuação explicável;
//! - [`regras`]: as detecções;
//! - [`invariantes`]: o monitor da segunda camada;
//! - [`incidente`]: o incidente;
//! - [`evidencia`]: o cofre, com cadeia de resumos própria;
//! - [`resposta`]: o que o NSF pede, e o que recomenda;
//! - [`dns`]: o que o NSF vê do DNS, pela captura;
//! - [`firewall`]: as regras e a classificação de quadros;
//! - [`motor`]: o caminho inteiro;
//! - [`relatorio`]: o JSON das consultas.
//!
//! # O que nada aqui faz
//!
//! Decidir. O gate não lê nada deste pacote: um risco alto não fecha nada,
//! uma detecção não abre nada, e o que o motor planeja é um pedido que o
//! gate decide como decidiria o de qualquer um.

#![no_std]

extern crate alloc;

pub mod dns;
pub mod evento;
pub mod evidencia;
pub mod firewall;
pub mod grafo;
pub mod incidente;
pub mod invariantes;
pub mod motor;
pub mod regras;
pub mod relatorio;
pub mod resposta;
pub mod risco;
pub mod ueba;
pub mod util;

pub use motor::{Motor, Pedido};
