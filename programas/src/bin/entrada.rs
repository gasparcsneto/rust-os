//! Uma janela que não é do servidor de janelas: a superfície com o canal de
//! entrada dela.
//!
//! É o outro lado do caso da suíte que confere que cada superfície recebe a
//! sua entrada. O programa escuta o canal [`CANAL`], cria uma superfície,
//! aponta a entrada dela para o canal, e diz no log cada evento que chega —
//! `entrada: ponteiro x y botoes`, `entrada: tecla c`, `entrada: foco
//! perdido`, `entrada: acao elemento acao`. A suíte aperta, digita e
//! aciona, e confere que chegou aqui, e não ao servidor.
//!
//! As recusas de [`ENTRADA`](protocolo::usuario::superficie::operacao::ENTRADA)
//! — um descritor que não é de canal — o programa confere do lado dele, e
//! diz qual falhou pelo código de saída. Sai com [`CODIGO`] quando a suíte
//! pede o fim.

#![no_std]
#![no_main]

use programas::escreverln;
use programas::sistema::{self, erro};
use programas::superficie::Superficie;
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída quando tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 70;

/// O canal da entrada, e o que a suíte publica para pedir o fim.
const CANAL: &str = "teste-entrada";

/// Onde a janela fica, e o tamanho — os mesmos que a suíte usa.
const X: i32 = 20;
const Y: i32 = 60;
const LARGURA: u32 = 120;
const ALTURA: u32 = 80;

/// A descrição: um botão, no canto de cima.
const DESCRICAO: &str = "janela\tEntrada\nbotao\t5\t10\t10\t40\t20\tOk";

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let canal = sistema::escutar(CANAL);
    if canal < 0 {
        escreverln!("entrada: escutar devolveu {}", canal);
        return 1;
    }
    let canal = canal as u64;
    let mut janela = match Superficie::nova(LARGURA, ALTURA) {
        Ok(s) => s,
        Err(e) => {
            escreverln!("entrada: sem superficie: {}", e);
            return 2;
        }
    };

    // Só um canal que este processo escuta serve de entrada: nem a saída,
    // nem a própria superfície.
    if janela.entrada(sistema::SAIDA) != Err(erro::ARGUMENTO_INVALIDO) {
        return 3;
    }
    if janela.entrada(janela.descritor()) != Err(erro::ARGUMENTO_INVALIDO) {
        return 4;
    }
    if janela.entrada(canal).is_err() {
        return 5;
    }

    janela.pixels().fill(0xFF20_C040);
    if janela.danificar_tudo().is_err()
        || janela.mover(X, Y).is_err()
        || janela.mostrar().is_err()
        || sistema::descrever(janela.descritor(), DESCRICAO) != 0
    {
        return 6;
    }
    escreverln!("entrada: pronta");

    let mut eventos = [Evento::default(); 16];
    loop {
        let n = match sistema::ler_eventos(canal, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("entrada: a leitura falhou: {}", e);
                return 7;
            }
        };
        for e in &eventos[..n] {
            let _ = match e.tipo {
                tipo::PONTEIRO => escreverln!("entrada: ponteiro {} {} {}", e.a, e.b, e.c),
                tipo::TECLA => escreverln!("entrada: tecla {}", e.a),
                tipo::FOCO_PERDIDO => escreverln!("entrada: foco perdido"),
                tipo::ACAO => escreverln!("entrada: acao {} {}", e.a, e.b),
                tipo::ENCERRAR => {
                    escreverln!("entrada: encerrada");
                    return CODIGO;
                }
                outro => escreverln!("entrada: evento {}", outro),
            };
        }
    }
}
