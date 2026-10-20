//! Os protocolos Web3 de um programa do Duke.
//!
//! O primeiro, e por enquanto o único, é o Internet Computer ([`icp`]): a
//! consulta (*query*) anônima a um canister, verificada como o agente
//! oficial da DFINITY verifica. Outros protocolos entram como módulos
//! irmãos, quando entrarem — nada aqui os antecipa.
//!
//! # O que nada aqui faz
//!
//! Rede, relógio, aleatório ou decisão. O pacote só conta: quem chama dá o
//! transporte (no Duke, o HTTP do programa sobre a conexão que o gate
//! decidiu — `programas::icp`), a hora (a do `system.info`, pela regra dos
//! consumidores) e os bytes do nonce, e recebe de volta uma resposta
//! verificada ou o motivo exato da recusa.
//!
//! Uma resposta verificada prova que os nós da sub-rede que hospeda o
//! canister responderam aquilo àquele pedido. Não prova nada ao Duke: não
//! é permissão, recurso nem regra, e o Principal do IC não é identidade de
//! ninguém aqui. Quem pode falar com o IC é quem o gate deixa conectar ao
//! destino, a cada pedido.

#![no_std]

#[cfg(test)]
extern crate std;

extern crate alloc;

pub mod icp;
