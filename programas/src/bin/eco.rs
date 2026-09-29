//! Escuta o canal `teste-eco` e diz cada evento que chega.
//!
//! É o outro lado do caso da suíte que confere os canais de eventos: o
//! kernel publica, este programa lê. Entre uma publicação e outra ele fica
//! **parado** numa leitura — é isso que o caso confere, contando as chamadas
//! de sistema enquanto o canal está vazio.
//!
//! Cada evento de teste com um número diferente de zero vira uma linha
//! `eco <numero>` no log; o zero pede o fim, e o programa diz quantos
//! recebeu e a soma deles antes de sair com [`CODIGO`].

#![no_std]
#![no_main]

use programas::escreverln;
use programas::sistema::{self, erro};
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída quando tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 63;

/// O canal que a suíte publica.
const CANAL: &str = "teste-eco";

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let canal = sistema::escutar(CANAL);
    if canal < 0 {
        escreverln!("escutar devolveu {}", canal);
        return 1;
    }
    let canal = canal as u64;

    // Um canal tem um ouvinte só: pedir de novo, mesmo do mesmo processo, é
    // recusado.
    if sistema::escutar(CANAL) != erro::OCUPADO {
        return 2;
    }
    // Um buffer menor que um evento é recusado, em vez de receber metade.
    let mut pequeno = [0u8; 16];
    if sistema::ler(canal, &mut pequeno) != erro::TAMANHO_INVALIDO {
        return 3;
    }

    // Um filho de `fork` herda o descritor, e não o canal: o canal tem um
    // ouvinte só, este processo, e o filho que lê é recusado — em vez de
    // dormir numa fila que não é dele, ou de roubar os eventos do pai.
    match sistema::bifurcar() {
        0 => {
            let mut um = [0u8; 32];
            let lido = sistema::ler(canal, &mut um);
            sistema::sair(if lido == erro::DESCRITOR_INVALIDO {
                0
            } else {
                1
            });
        }
        filho if filho < 0 => return 7,
        _ => {}
    }
    if !matches!(sistema::esperar(0), Ok((_, Some(0)))) {
        return 8;
    }

    // Só agora o canal está pronto para a suíte: ela espera esta linha antes
    // de publicar.
    escreverln!("eco: escutando");

    let (mut recebidos, mut soma) = (0i64, 0i64);
    let mut eventos = [Evento::default(); 8];
    loop {
        let quantos = match sistema::ler_eventos(canal, &mut eventos) {
            Ok(0) => return 4,
            Ok(quantos) => quantos,
            Err(e) => {
                escreverln!("ler devolveu {}", e);
                return 5;
            }
        };
        for evento in &eventos[..quantos] {
            if evento.tipo != tipo::TESTE {
                return 6;
            }
            if evento.a == 0 {
                // Fechar devolve o nome na hora: escutar de novo dá certo.
                sistema::fechar(canal);
                let de_novo = sistema::escutar(CANAL);
                if de_novo < 0 {
                    escreverln!("escutar depois de fechar devolveu {}", de_novo);
                    return 9;
                }
                escreverln!("eco: fim, {} eventos, soma {}", recebidos, soma);
                return CODIGO;
            }
            recebidos += 1;
            soma += evento.a;
            escreverln!("eco {}", evento.a);
        }
    }
}
