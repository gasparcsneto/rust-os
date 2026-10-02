//! Um programa que tenta cobrir a barra do kernel.
//!
//! É o outro lado do caso da suíte que confere que a barra não pode ser
//! coberta. A barra diz quantos agentes estão conectados e quem agiu por
//! último; uma janela por cima dela poderia dizer outra coisa, e receber o
//! clique de quem acreditasse. Este programa faz o que um programa hostil
//! faria:
//!
//! - uma superfície que se mostra e vem para a frente **sem mover** — se o
//!   kernel a deixasse nascer na origem, ela estaria na faixa da barra;
//! - outra que pede para subir **acima** da barra, pela chamada crua, sem o
//!   runtime de janelas, que faria a conta do lado de cá.
//!
//! As duas pintadas de [`COR`], a cor de uma barra falsa. O kernel aceita
//! os dois pedidos — mover para cima da barra não é erro, é parar nela —, e
//! a suíte confere onde elas ficaram e o que se vê na faixa.
//!
//! Sai com zero quando tudo foi aceito, e com um código que diz o quê,
//! quando não.

#![no_std]
#![no_main]

use programas::escreverln;
use programas::sistema;
use programas::superficie::Superficie;
use protocolo::usuario::evento::Evento;

/// O canal por onde a suíte diz que já olhou a tela.
const CANAL: &str = "teste-cobrir";

// A geometria e a cor que a suíte confere — ver o caso dela.
const LARGURA: u32 = 96;
const ALTURA: u32 = 48;
const ALTA_X: i32 = 300;
const ALTA_Y: i32 = -40;
const COR: u32 = 0xFFE0_1010;

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let mut parada = match Superficie::nova(LARGURA, ALTURA) {
        Ok(s) => s,
        Err(_) => return 1,
    };
    parada.pixels().fill(COR);
    if parada.mostrar().is_err()
        || parada.trazer_para_frente().is_err()
        || parada.danificar_tudo().is_err()
    {
        return 2;
    }

    let mut alta = match Superficie::nova(LARGURA, ALTURA) {
        Ok(s) => s,
        Err(_) => return 3,
    };
    alta.pixels().fill(COR);
    if alta.mover(ALTA_X, ALTA_Y).is_err() {
        return 4;
    }
    if alta.mostrar().is_err()
        || alta.trazer_para_frente().is_err()
        || alta.danificar_tudo().is_err()
    {
        return 5;
    }

    let canal = sistema::escutar(CANAL);
    if canal < 0 {
        return 6;
    }
    escreverln!("cobrir: pronto");
    let mut evento = [Evento::default(); 1];
    if sistema::ler_eventos(canal as u64, &mut evento) != Ok(1) {
        return 7;
    }
    drop(alta);
    drop(parada);
    escreverln!("cobrir: fim");
    0
}
