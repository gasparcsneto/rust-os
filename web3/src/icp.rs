//! O Internet Computer, do lado de quem consulta e chama: as contas da
//! consulta verificada e da chamada de atualização verificada — do
//! anônimo, ou assinadas por quem tem chave.
//!
//! - [`principal`]: o Principal — bytes, texto, classes;
//! - [`cbor`]: o subconjunto estrito do CBOR que o IC usa;
//! - [`resumo`]: o hash independente de representação (`hash_of_map`);
//! - [`pedido`]: os envelopes da consulta, da chamada e da leitura de
//!   estado — do anônimo, ou assinados —, e o id do pedido;
//! - [`arvore`]: a árvore de hash — reconstrução e procura;
//! - [`certificado`]: o certificado — BLS, delegação, faixas e tempo;
//! - [`assinatura`]: a assinatura Ed25519 de um nó (ZIP215);
//! - [`consulta`]: a resposta da consulta e as assinaturas dos nós;
//! - [`candid`]: o Candid — a tabela de tipos inteira, os valores de um
//!   subconjunto, e a escrita com o tipo dado;
//! - [`icrc1`]: o ICRC-1 de um ledger — a conta, a transferência, o
//!   resultado dela e o saldo;
//! - [`cmc`]: o CMC — a cunhagem de cycles com ICP;
//! - [`situacao`]: a situação de uma chamada — o corpo da chamada
//!   síncrona e o `request_status` de um certificado;
//! - [`agente`]: o agente síncrono da consulta — do anônimo, ou assinada
//!   por quem tem chave —, sobre um transporte de quem chama;
//! - [`atualizacao`]: a chamada de atualização verificada — do anônimo,
//!   ou assinada por quem tem chave —, e o acompanhamento dela;
//! - [`registro`]: as redes em que se confia — `/dados/icp/redes`.
//!
//! # De onde vem o que se sabe do protocolo
//!
//! Cada regra diz de onde vem:
//!
//! - **especificação**: a *Internet Computer Interface Specification*
//!   (`dfinity/portal`, `docs/references/ic-interface-spec.md`, commit
//!   `ed742236de3b54ed56161f188913536259941a12`) e a especificação do
//!   Candid (`dfinity/candid`, `spec/Candid.md`, commit
//!   `10423fae0c84f6a3f13abf1042f28f2ae40ac3af`), lidas;
//! - **referência**: o código das implementações oficiais — `ic-agent` e
//!   `ic-transport-types` 0.49.2, `ic-certification` e
//!   `ic-certificate-verification` 4.0.0, `ic_principal` 0.1.5, `candid`
//!   0.10.38, `ic-ed25519` 0.6.0 —, onde a especificação deixa a escolha ao
//!   cliente; e, do ICRC-1, o `icrc-ledger-types` 0.2.0;
//! - **oráculo**: os testes do hospedeiro conferem cada peça contra a
//!   oficial, nos dois sentidos, e os vetores de exemplo da especificação
//!   (a árvore de hash e o id do pedido) estão nos casos.
//!
//! Onde a especificação deixa a escolha ao cliente, a escolha daqui é a do
//! lado que recusa: um erro de leitura faz este lado recusar uma resposta
//! válida, e nunca aceitar uma inválida.
//!
//! # Três coisas que não se confundem
//!
//! | | O que prova | O que não é |
//! |---|---|---|
//! | o TLS (pacote `tls`) | que o endpoint tem o nome pedido, pelas âncoras do programa | não é a resposta do IC, nem autorização |
//! | a verificação daqui | que os nós da sub-rede do canister responderam isto a este pedido | não é `ALLOW` do Duke |
//! | o gate do Duke | que esta identidade pode falar com este destino, agora | não diz nada sobre o canister |

pub mod agente;
pub mod arvore;
pub mod assinatura;
pub mod atualizacao;
pub mod candid;
pub mod cbor;
pub mod certificado;
pub mod cmc;
pub mod consulta;
pub mod icrc1;
pub mod pedido;
pub mod principal;
pub mod registro;
pub mod resumo;
pub mod situacao;

#[cfg(test)]
mod bancada;

/// Um minuto, em nanossegundos — a unidade de tempo do IC.
pub const MINUTO_NS: u64 = 60 * 1_000_000_000;

/// Quanto o tempo de um certificado e o carimbo de uma assinatura de nó
/// podem distar da hora de quem verifica, para mais ou para menos: cinco
/// minutos. **Especificação** (nota da *Query call*: "a reasonable expiry
/// time … is 5 minutes"); **referência**: o `ic-agent` usa a própria
/// validade do pedido, cinco minutos por padrão.
pub const TOLERANCIA_NS: u64 = 5 * MINUTO_NS;

/// Quanto um pedido vale depois de montado: quatro minutos — dentro dos
/// cinco que o IC aceita no futuro (**referência**: o `ic-agent` usa até
/// cinco, menos uma folga).
pub const VALIDADE_DO_PEDIDO_NS: u64 = 4 * MINUTO_NS;
