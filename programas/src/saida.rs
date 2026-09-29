//! A saída de um programa: uma linha formatada por chamada de sistema.
//!
//! # Por que uma linha inteira de cada vez
//!
//! Porque cada `escrever` vira um registro no log do kernel. Um `write!`
//! comum chama a escrita a cada pedaço do formato — o texto, depois o
//! número, depois o resto —, e cada pedaço sairia como um registro próprio.
//! Aqui a linha é montada num buffer e vai de uma vez.
//!
//! O buffer tem o tamanho de um registro, 160 bytes. O que passar disso é
//! cortado, e o corte é marcado com `…`: uma linha truncada que parecesse
//! inteira mentiria para quem lê o log.

use core::fmt::{self, Write};

/// Quantos bytes cabem numa linha — o que o kernel guarda num registro.
pub const LINHA: usize = 160;

/// Uma linha em montagem.
struct Linha {
    bytes: [u8; LINHA],
    tamanho: usize,
    cortada: bool,
}

impl Write for Linha {
    fn write_str(&mut self, texto: &str) -> fmt::Result {
        for c in texto.chars() {
            let mut utf8 = [0u8; 4];
            let codificado = c.encode_utf8(&mut utf8).as_bytes();
            // Um caractere que não cabe inteiro não entra pela metade: o
            // kernel recusaria a linha toda como UTF-8 inválido.
            if self.tamanho + codificado.len() > LINHA {
                self.cortada = true;
                return Ok(());
            }
            self.bytes[self.tamanho..self.tamanho + codificado.len()].copy_from_slice(codificado);
            self.tamanho += codificado.len();
        }
        Ok(())
    }
}

/// Monta a linha e a escreve em `descritor`. Devolve o que o kernel disse.
pub fn escrever_linha(descritor: u64, argumentos: fmt::Arguments<'_>) -> i64 {
    let mut linha = Linha {
        bytes: [0; LINHA],
        tamanho: 0,
        cortada: false,
    };
    let _ = linha.write_fmt(argumentos);
    if linha.cortada {
        // Três bytes para a reticência, tirados do fim sem partir um
        // caractere ao meio.
        let mut fim = linha.tamanho.min(LINHA - 3);
        while fim > 0 && (linha.bytes[fim] & 0xC0) == 0x80 {
            fim -= 1;
        }
        linha.bytes[fim..fim + 3].copy_from_slice("…".as_bytes());
        linha.tamanho = fim + 3;
    }
    crate::sistema::escrever(descritor, &linha.bytes[..linha.tamanho])
}

/// Escreve uma linha formatada na saída comum — o log do kernel, em `info`.
#[macro_export]
macro_rules! escreverln {
    ($($argumento:tt)*) => {
        $crate::saida::escrever_linha(
            $crate::sistema::SAIDA,
            ::core::format_args!($($argumento)*),
        )
    };
}
