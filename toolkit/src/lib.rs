//! O toolkit do Duke: widgets que se desenham e se descrevem do mesmo estado.
//!
//! # A regra
//!
//! Cada widget sabe três coisas: o tamanho que pede, como se desenha na
//! área que recebe, e o que é para a árvore semântica. As três saem do mesmo
//! estado, e o desenho e a descrição percorrem a mesma árvore com as mesmas
//! áreas — ver [`arvore`]. Um programa não escreve descrição à mão: ele
//! monta widgets, e a descrição é gerada deles.
//!
//! É o que o roteiro pede desde a fase 10. A árvore semântica é como um
//! agente opera o Duke; se ela fosse escrita ao lado da interface, seria a
//! segunda superfície que este projeto existe para não ter — e divergiria
//! da primeira na primeira mudança que só uma das duas recebesse.
//!
//! # O que existe
//!
//! - [`Rotulo`]: texto que se lê, com um nome para a árvore;
//! - [`Botao`]: algo que se aciona;
//! - [`Coluna`] e [`Linha`]: os filhos um depois do outro.
//!
//! A cor, a medida e o estilo de texto de cada um vêm da [`aparencia`]: o
//! botão de uma janela é o botão da barra do kernel.
//!
//! # Testado no hospedeiro
//!
//! O layout, o desenho e a descrição são contas, e os testes deste pacote as
//! conferem com `cargo test`: a descrição gerada é lida de volta pelo
//! **mesmo** leitor que o kernel usa, do `protocolo`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod arvore;
mod tela;
mod widgets;

pub use arvore::{Indice, Semantica, Widget};
pub use protocolo::usuario::descricao::{Escritor, Retangulo, Tipo};
pub use tela::Tela;
pub use widgets::{Botao, Coluna, Linha, Pilha, Rotulo};

#[cfg(test)]
mod testes;
