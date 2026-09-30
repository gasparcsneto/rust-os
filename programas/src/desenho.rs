//! Desenhar numa memória de pixels: retângulos e texto.
//!
//! A memória é a do toolkit — [`Tela`] —, e o texto é o da `tipografia`: a
//! mesma fonte, os mesmos estilos e a mesma mistura que o kernel usa no
//! console e na barra. Uma letra numa janela e no console saem com os
//! mesmos pixels.

pub use tipografia::Estilo;
pub use toolkit::Tela;
