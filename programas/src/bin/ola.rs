//! O primeiro programa do Duke escrito em Rust e compilado à parte.
//!
//! Diz olá, e usa as três coisas que um programa compilado usa sem pensar e
//! que os programas montados à mão nunca precisaram: o monte (`Vec` e
//! `String`), a formatação, e uma pilha de dezenas de KiB.
//!
//! Sai com [`CODIGO`] quando tudo confere, e com um código menor que diz o
//! quê, quando não.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use programas::escreverln;

/// O código de saída quando tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 61;

#[unsafe(no_mangle)]
fn principal() -> i64 {
    escreverln!("ola do Rust, no anel sem privilegio");

    // O monte: dez mil quadrados num `Vec`, que cresce por realocação — cada
    // uma devolve o bloco anterior à lista.
    let quadrados: Vec<u64> = (0..10_000u64).map(|i| i * i).collect();
    // A soma dos quadrados de 0 a n-1 é (n-1)n(2n-1)/6.
    let n = 10_000u64;
    if quadrados.iter().sum::<u64>() != (n - 1) * n * (2 * n - 1) / 6 {
        return 1;
    }

    // A formatação, numa `String`.
    let mut texto = String::new();
    let _ = write!(
        texto,
        "{} quadrados, o ultimo {}",
        quadrados.len(),
        quadrados[9_999]
    );
    if texto != "10000 quadrados, o ultimo 99980001" {
        return 2;
    }
    escreverln!("{}", texto);

    // A pilha: 40 KiB de uma vez, mais do que a pilha de uma página dos
    // programas montados à mão. `black_box` impede o compilador de ver que
    // o vetor é só somado e de tirá-lo da pilha.
    if fundo_da_pilha(core::hint::black_box(7)) != 7 * 40 * 1024 {
        return 3;
    }

    // Uma linha maior que um registro do kernel: sai cortada, e marcada com
    // a reticência. A suíte confere o corte.
    escreverln!("{}", "longa ".repeat(40));

    CODIGO
}

#[inline(never)]
fn fundo_da_pilha(valor: u8) -> u64 {
    let bloco = core::hint::black_box([valor; 40 * 1024]);
    bloco.iter().map(|&b| u64::from(b)).sum()
}
