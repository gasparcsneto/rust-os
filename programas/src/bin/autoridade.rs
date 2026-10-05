//! Confere, de dentro de um processo, com que autoridade ele roda.
//!
//! A suíte o lança como um agente de papel `operador`: ele abre arquivos de
//! `/dados`, `/bin` e `/programas`, executa programas de `/bin` e
//! `/programas`, e nada mais. Aqui cada recusa é pedida pelas chamadas de
//! sistema de verdade:
//!
//! - abrir `/saudacao.txt`, fora do alcance: [`erro::NEGADO`];
//! - o filho de um `fork` herda a autoridade — e não a do sistema: a mesma
//!   abertura, recusada também;
//! - executar um programa fora do alcance: recusado, e o processo continua
//!   o mesmo, de pé para dizer.
//!
//! Sai com [`CODIGO`] quando tudo confere, e com um código menor que diz o
//! quê, quando não. Lançado pelo sistema, a primeira abertura passa, e ele
//! sai com 1: o caso confere que a recusa é do papel, e não do arquivo.

#![no_std]
#![no_main]

programas::manifesto!("autoridade", "fs.read", "process.run");

use programas::escreverln;
use programas::sistema::{self, erro};

/// O código de saída quando tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 72;

/// O código com que o filho sai quando as recusas dele conferem.
const DO_FILHO: i64 = 73;

/// Um arquivo que existe, fora do alcance do operador.
const FORA_DO_ALCANCE: &str = "/saudacao.txt";

/// Um programa fora do alcance do operador: não precisa existir — a
/// decisão vem antes de procurar.
const PROGRAMA_FORA: &str = "/dados/programa";

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let aberto = sistema::abrir(FORA_DO_ALCANCE);
    if aberto != erro::NEGADO {
        escreverln!("autoridade: abrir devolveu {}", aberto);
        return 1;
    }
    match sistema::bifurcar() {
        0 => {
            if sistema::abrir(FORA_DO_ALCANCE) != erro::NEGADO {
                sistema::sair(2);
            }
            if sistema::executar(PROGRAMA_FORA) != erro::NEGADO {
                sistema::sair(3);
            }
            sistema::sair(DO_FILHO)
        }
        filho if filho < 0 => return 4,
        _ => {}
    }
    match sistema::esperar(0) {
        Ok((_, Some(DO_FILHO))) => {}
        outro => {
            escreverln!("autoridade: o filho deu {:?}", outro);
            return 5;
        }
    }
    escreverln!("autoridade conferida: o processo age como quem o lancou");
    CODIGO
}
