//! Dispositivos virtio.
//!
//! # O que virtio resolve
//!
//! Um driver de disco SATA existe para falar com um controlador SATA, que é
//! uma peça de silício com décadas de compatibilidade retroativa dentro. Numa
//! máquina virtual, do outro lado desse controlador não há silício nenhum —
//! há um programa emulando uma peça de silício para que o driver reconheça o
//! que espera. É trabalho dobrado: o hóspede finge que há hardware, o
//! hospedeiro finge que é hardware.
//!
//! O virtio corta os dois fingimentos. É uma interface desenhada para o caso
//! em que os dois lados são software e sabem disso: em vez de registradores
//! que imitam um chip, um anel de descritores em memória compartilhada, e uma
//! escrita num endereço para avisar que há trabalho.
//!
//! # Moderno, e não legado
//!
//! Um dispositivo virtio do QEMU costuma ser *transicional*: responde tanto à
//! interface legada quanto à moderna (a de virtio 1.0). As duas funcionam, e a
//! escolha aqui não é sobre elegância.
//!
//! A interface legada vive numa região de **I/O**. No x86 isso é o par de
//! instruções `in`/`out`, que a arquitetura tem. No ARM não existe I/O como
//! espaço separado: a janela de I/O do barramento PCI é uma faixa de memória
//! que a ponte traduz, e alcançá-la significaria um segundo mecanismo de
//! acesso, só para o ARM, para chegar aos mesmos registradores.
//!
//! A interface moderna vive em memória mapeada, que funciona igual nas duas.
//! Um caminho só, testado nas duas arquiteturas pelo mesmo código — que é
//! exatamente o critério que este kernel usa em todo lugar.
//!
//! # O que está aqui
//!
//! - [`transporte`]: como achar os registradores do dispositivo e como fazer o
//!   aperto de mão que o liga.
//! - [`fila`]: a virtqueue, que é o canal por onde os pedidos passam.
//! - [`blk`]: o disco.
//! - [`net`]: a placa de rede.

pub mod blk;
pub mod fila;
pub mod net;
pub mod transporte;
