//! Pede ao kernel que escreva onde o processo não pode: no próprio código.
//!
//! Duas chamadas escrevem num buffer que o processo dá — `ler` e `esperar` —,
//! e o kernel conferia só se a faixa era do processo e estava mapeada, e não
//! se era gravável. Uma página de código é das duas coisas e não da
//! terceira: o kernel escrevia nela pelo anel zero, a proteção de escrita do
//! processador recusava, e a falha era do **kernel** — fatal. Qualquer
//! processo derrubava a máquina com um `ler` para o endereço de uma função.
//!
//! Aqui as duas são pedidas assim, e o programa confere que o kernel recusa
//! com `ENDERECO_INVALIDO` — e que continua de pé para responder.
//!
//! Sai com [`CODIGO`] quando tudo confere, e com um código menor que diz o
//! quê, quando não.

#![no_std]
#![no_main]

use programas::escreverln;
use programas::sistema::{self, erro};

/// O código de saída quando tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 64;

/// O código com que o filho sai, para o pai conferir que o colheu.
///
/// Distinto de todo código que outro programa usa para dizer algo: era 7, e
/// 7 é o que o exemplo montado à mão usa para ".bss suja" — o caso dele, que
/// procura esse código no log, reprovou por causa deste filho.
const DO_FILHO: i64 = 65;

#[unsafe(no_mangle)]
fn principal() -> i64 {
    // Um endereço de código deste processo: mapeado, dele, e só de leitura.
    let codigo = principal as fn() -> i64 as usize as u64;

    // `ler` para dentro do código.
    let arquivo = sistema::abrir("/saudacao.txt");
    if arquivo < 0 {
        return 1;
    }
    // SAFETY: o ponto é o kernel recusar; se ele aceitasse, escreveria no
    // código, e o programa não chegaria à conferência seguinte.
    let lido = unsafe { sistema::ler_cru(arquivo as u64, codigo, 8) };
    if lido != erro::ENDERECO_INVALIDO {
        escreverln!("ler no codigo devolveu {}", lido);
        return 2;
    }

    // `esperar` para dentro do código. Ele só escreve quando colhe, então
    // há de haver um filho que já saiu.
    match sistema::bifurcar() {
        0 => sistema::sair(DO_FILHO),
        filho if filho < 0 => return 3,
        _ => {}
    }
    // SAFETY: como acima.
    let colhido = unsafe { sistema::esperar_cru(0, codigo) };
    if colhido != erro::ENDERECO_INVALIDO {
        escreverln!("esperar no codigo devolveu {}", colhido);
        return 4;
    }
    // E a recusa não consumiu o filho: a espera legítima o colhe, com o
    // código dele.
    match sistema::esperar(0) {
        Ok((_, Some(DO_FILHO))) => {}
        outro => {
            escreverln!("a espera legitima deu {:?}", outro);
            return 5;
        }
    }

    escreverln!("ponteiros conferidos: o kernel recusou escrever no codigo");
    CODIGO
}
