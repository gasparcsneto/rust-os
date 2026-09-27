//! O que muda de uma arquitetura para a outra.
//!
//! # O mesmo programa, dois alvos e dois firmwares
//!
//! A UEFI é a mesma especificação nas duas máquinas: as mesmas tabelas, os
//! mesmos GUIDs, a mesma convenção de chamada — `efiapi`, que o compilador
//! traduz para o que cada processador usa. Abrir a ESP, ler o kernel,
//! conferir o ELF e pedir o mapa de memória é **o mesmo código**, e é por
//! isso que ele não está aqui dentro.
//!
//! O que sobra para este módulo é o que a especificação não cobre porque não
//! é dela: qual UART existe nesta placa, que número o ELF usa para esta
//! arquitetura, e — a partir do momento em que o firmware sai de cena — como
//! se monta uma tabela de tradução e como se salta para o kernel.
//!
//! É a mesma divisão que o kernel faz em [`crate::alvo`]: a fachada expõe as
//! perguntas, e cada backend responde do jeito da máquina dele.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64 as atual;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64 as atual;

pub use atual::{MAQUINA, Partida, RELOCACAO_RELATIVA, Serial, dormir, init_serial, nome, partir};

/// Onde este iniciador fala, quando o endereço é uma escolha da placa.
///
/// Só existe no ARM: no x86 a serial é alcançada por porta de I/O, não por
/// endereço, e não há device tree que possa discordar.
#[cfg(target_arch = "aarch64")]
pub use atual::UART;
