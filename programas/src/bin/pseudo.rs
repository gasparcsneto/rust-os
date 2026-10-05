//! Digita um comando no interpretador pelo pseudo-terminal, e lê a resposta.
//!
//! O caminho inteiro que o Terminal vai usar, sem a janela: abrir o
//! pseudo-terminal com os avisos num canal, esvaziar o que o kernel já tinha
//! impresso, escrever uma linha, dormir no canal até o aviso de saída, e
//! achar a resposta do interpretador no que se lê.
//!
//! O console do pseudo-terminal é um console novo, sem ninguém entrado: a
//! resposta a qualquer comando é a recusa de quem não fez o login —
//! `DENY_NOT_AUTHENTICATED` —, do próprio interpretador, sempre a mesma. É
//! também a prova, de dentro de um processo, de que um Terminal não herda a
//! sessão de ninguém.
//!
//! No caminho, as recusas: o segundo `terminal` do mesmo dono, um canal que
//! não é canal, e o filho de um `fork`, que herda os descritores e não a
//! abertura.
//!
//! Sai com [`CODIGO`] quando tudo confere, e com um código menor que diz o
//! quê, quando não.

#![no_std]
#![no_main]

programas::manifesto!("pseudo", "terminal.attach");

use programas::escreverln;
use programas::sistema::{self, erro};
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída quando tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 68;

/// O código com que o filho sai quando as recusas dele conferem.
const DO_FILHO: i64 = 69;

/// A linha digitada. Começa com uma tecla de função, que o pseudo-terminal
/// tem de engolir sem entregar ao interpretador — a suíte conta as teclas.
const LINHA: &str = "\u{F704}duke-pty\n";

/// O que o interpretador responde a ela, num console sem ninguém entrado.
const RESPOSTA: &[u8] = b"negado: DENY_NOT_AUTHENTICATED";

/// Quantos avisos esperar pela resposta antes de desistir.
const AVISOS: usize = 200;

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let canal = sistema::escutar("pseudo");
    if canal < 0 {
        return 1;
    }
    let canal = canal as u64;

    // Um descritor que não é de canal não serve de canal.
    if sistema::terminal(sistema::SAIDA) != erro::DESCRITOR_INVALIDO {
        return 2;
    }
    let pty = sistema::terminal(canal);
    if pty < 0 {
        escreverln!("terminal devolveu {}", pty);
        return 3;
    }
    let pty = pty as u64;
    // Um dono de cada vez — nem o próprio abre duas vezes.
    if sistema::terminal(canal) != erro::OCUPADO {
        return 4;
    }

    // O anel guarda o que o kernel imprimiu desde o boot: há o que ler já na
    // primeira leitura. Esvaziá-lo, até a leitura devolver zero — sem
    // bloquear.
    let mut bytes = [0u8; 256];
    let primeira = sistema::ler(pty, &mut bytes);
    if primeira <= 0 {
        escreverln!("a primeira leitura devolveu {}", primeira);
        return 5;
    }
    let mut voltas = 0;
    while sistema::ler(pty, &mut bytes) > 0 {
        voltas += 1;
        if voltas > 10_000 {
            return 6;
        }
    }

    // O filho herda os descritores, e nenhum deles é dele.
    match sistema::bifurcar() {
        0 => {
            let recusas = [
                sistema::ler(pty, &mut bytes),
                sistema::escrever(pty, b"x"),
                sistema::terminal(canal),
            ];
            let codigo = if recusas == [erro::DESCRITOR_INVALIDO; 3] {
                DO_FILHO
            } else {
                1
            };
            sistema::sair(codigo)
        }
        filho if filho < 0 => return 7,
        _ => {}
    }
    match sistema::esperar(0) {
        Ok((_, Some(DO_FILHO))) => {}
        outro => {
            escreverln!("o filho deu {:?}", outro);
            return 8;
        }
    }

    // Digitar. A tecla de função conta como aceita — recusá-la deixaria quem
    // escreve repetindo o mesmo caractere para sempre.
    let aceitos = sistema::escrever(pty, LINHA.as_bytes());
    if aceitos != LINHA.len() as i64 {
        escreverln!("escrever no terminal devolveu {}", aceitos);
        return 9;
    }

    // E esperar a resposta, dormindo no canal. Uma janela deslizante, porque
    // a resposta pode vir partida entre duas leituras.
    let mut janela = [0u8; 512];
    let mut tem = 0;
    let mut eventos = [Evento::default(); 16];
    for _ in 0..AVISOS {
        let n = match sistema::ler_eventos(canal, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("ler eventos devolveu {}", e);
                return 10;
            }
        };
        if !eventos[..n].iter().any(|e| e.tipo == tipo::SAIDA) {
            return 11;
        }
        loop {
            if tem > janela.len() - bytes.len() {
                let manter = janela.len() / 2;
                janela.copy_within(tem - manter..tem, 0);
                tem = manter;
            }
            let lidos = sistema::ler(pty, &mut janela[tem..tem + bytes.len()]);
            if lidos < 0 {
                return 12;
            }
            if lidos == 0 {
                break;
            }
            tem += lidos as usize;
        }
        if janela[..tem].windows(RESPOSTA.len()).any(|w| w == RESPOSTA) {
            // Fechar solta a abertura, e ela pode ser tomada de novo.
            if sistema::fechar(pty) != 0 {
                return 13;
            }
            let de_novo = sistema::terminal(canal);
            if de_novo < 0 {
                escreverln!("reabrir devolveu {}", de_novo);
                return 14;
            }
            // Sai com o terminal aberto: a suíte confere que a abertura de
            // um morto não segura o pseudo-terminal.
            escreverln!("pseudo-terminal conferido: o interpretador respondeu");
            return CODIGO;
        }
    }
    escreverln!("a resposta nao chegou em {} avisos", AVISOS);
    15
}
