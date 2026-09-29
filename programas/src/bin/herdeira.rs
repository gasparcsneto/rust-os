//! O programa que um `exec` põe no lugar de outro que tinha uma superfície
//! aberta — no mesmo endereço em que este põe a sua.
//!
//! Quem o executa é o filho zumbi do programa `superficie`: ele cria uma
//! superfície no começo da faixa das superfícies e troca de imagem. O
//! descritor dela sobrevive ao `exec`, e a memória não; e este programa,
//! com a tabela de faixas zerada, põe a própria superfície **no mesmo
//! endereço**.
//!
//! Então fecha tudo o que herdou. Fechar a superfície herdada desfaz o
//! espelho dela no espaço do processo — e, se o kernel desfizesse pelo
//! endereço, sem conferir de quem é o frame, arrancaria a memória da
//! superfície nova. A escrita seguinte mataria o processo.
//!
//! Sai com zero quando tudo confere, e **sem** fechar a própria superfície:
//! ela é a que o coletor tira da tela enquanto este processo é um zumbi.

#![no_std]
#![no_main]

use programas::monte::FIM_DO_MONTE;
use programas::sistema;
use programas::superficie::Superficie;

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let mut minha = match Superficie::nova(8, 8) {
        Ok(s) => s,
        Err(_) => return 1,
    };
    if minha.endereco() != FIM_DO_MONTE {
        return 2;
    }
    // Tudo o que veio da imagem anterior, menos a saída e a própria.
    for descritor in 3..16 {
        if descritor != minha.descritor() {
            sistema::fechar(descritor);
        }
    }
    // A memória continua aqui, e a camada continua sendo desta superfície.
    minha.pixels().fill(0xFF12_3456);
    if minha.pixels()[63] != 0xFF12_3456 || minha.danificar_tudo().is_err() {
        return 3;
    }
    core::mem::forget(minha);
    0
}
