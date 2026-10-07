//! Cede a vez muitas vezes seguidas, e confere que voltou inteiro.
//!
//! É o outro lado do caso da suíte que lança várias cópias dele ao mesmo
//! tempo, em todos os núcleos. Cada volta faz a chamada `ceder` com um
//! estado vivo nos registradores e na pilha — um acumulador que depende de
//! todas as voltas anteriores — e confere, ao voltar, que o fio ainda é o
//! mesmo e que a conta chega ao número que só a sequência inteira dá.
//!
//! No ARM a chamada de sistema roda na pilha de exceção do **núcleo**, e não
//! numa do fio. Ceder de dentro dela, como a chamada fazia, salvava o fio no
//! meio do handler, com os quadros dele naquela pilha; retomado noutro
//! núcleo, ou depois de outro fio ter feito o mesmo, ele voltava pelos
//! quadros de outro. Este programa é a pressão que tornava isso visível.

#![no_std]
#![no_main]

programas::manifesto!("cedente");

use programas::escreverln;
use programas::sistema;

/// O código de saída quando tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 78;

/// Quantas vezes cada cópia cede.
const VOLTAS: u64 = 2_000;

/// O acumulador depois de `voltas` voltas — a mesma conta, sem ceder.
fn esperado(voltas: u64) -> u64 {
    (0..voltas).fold(0x9E37_79B9_7F4A_7C15, passo)
}

fn passo(s: u64, i: u64) -> u64 {
    s.rotate_left(7) ^ i.wrapping_mul(0xBF58_476D_1CE4_E5B9)
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let eu = sistema::id();
    let mut soma = 0x9E37_79B9_7F4A_7C15u64;
    for i in 0..VOLTAS {
        soma = passo(soma, i);
        sistema::ceder();
        if sistema::id() != eu {
            return 1;
        }
    }
    if soma != esperado(VOLTAS) {
        return 2;
    }
    escreverln!("cedente: {} voltas conferidas", VOLTAS);
    CODIGO
}
