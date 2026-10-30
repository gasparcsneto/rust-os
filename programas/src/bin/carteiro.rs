//! Quem manda a outro dispositivo: o "aplicativo A" do enlace, na bancada
//! de duas máquinas (`cargo xtask enlace`).
//!
//! Lançado pela pessoa, sem argumentos, ele procura quem oferece
//! [`INTENCAO`] em [`PAR`] — outro Duke, relacionado a ela pelo registro de
//! dispositivos desta máquina —, manda um corpo ao primeiro candidato,
//! manda de novo com o mesmo nonce — o reenvio, que devolve o mesmo id — e
//! pergunta o estado até a confirmação de lá. Cada passo ele diz no log:
//!
//! - `carteiro: achei <n>`, e uma linha
//!   `carteiro: candidato <programa> <resumo> <endpoint>` por candidato;
//! - `carteiro: mandando <corpo>` e `carteiro: mandei <id>`;
//! - `carteiro: reenvio igual`, ou `carteiro: reenvio outro <id>`;
//! - `carteiro: estado <estado> <resposta>`;
//! - numa recusa, daqui ou de lá, `carteiro: <passo> <código> <motivo>`;
//! - e, por último, sempre, `carteiro: fim <código de saída>`.
//!
//! O corpo leva o número do processo: cada lançamento manda um diferente, e
//! quem lê o log de lá sabe qual chegou. Sai com [`CODIGO`] depois da
//! confirmação, e com [`RECUSADO`] na primeira recusa: quem perdeu a
//! autoridade não fica tentando.
//!
//! Poucos pedidos por lançamento: cada um é um enlace novo — um aperto do
//! Noise IK —, e o Duke de lá conta os apertos de cada vaga na janela da
//! política.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!("carteiro", "fabric.send", "fabric.remote");

use alloc::format;
use programas::escreverln;
use programas::malha::{Falha, Par};
use programas::sistema;

/// O outro dispositivo, como o registro desta máquina o chama.
const PAR: Par<'static> = Par("dispositivo:par");

/// A intenção que o carteiro procura lá.
const INTENCAO: &str = "imagem.compartilhar";

/// O código de saída depois da confirmação de lá. A bancada o procura.
const CODIGO: i64 = 44;

/// O código de saída depois de uma recusa.
const RECUSADO: i64 = 45;

/// Quantas vezes perguntar o estado antes de desistir de esperar a
/// confirmação.
const PERGUNTAS: u32 = 3;

/// Diz a recusa de um passo e devolve o código de saída dela.
fn recusado(passo: &str, f: &Falha) -> i64 {
    match f {
        Falha::Recusa { codigo, motivo } => {
            escreverln!("carteiro: {} {} {}", passo, codigo, motivo);
        }
        outra => {
            escreverln!("carteiro: {} {}", passo, outra.codigo());
        }
    }
    RECUSADO
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let codigo = correr();
    escreverln!("carteiro: fim {}", codigo);
    codigo
}

fn correr() -> i64 {
    let candidatos = match PAR.descobrir(INTENCAO) {
        Ok(v) => v,
        Err(f) => return recusado("procurar", &f),
    };
    escreverln!("carteiro: achei {}", candidatos.len());
    for c in &candidatos {
        escreverln!(
            "carteiro: candidato {} {} {}",
            c.programa,
            c.resumo.get(..8).unwrap_or(&c.resumo),
            c.endpoint
        );
    }
    let Some(destino) = candidatos.first() else {
        return RECUSADO;
    };
    let corpo = format!("foto-{}.png", sistema::id());
    escreverln!("carteiro: mandando {}", corpo);
    let id = match PAR.enviar(&destino.endpoint, INTENCAO, &corpo, 1) {
        Ok(id) => id,
        Err(f) => return recusado("mandar", &f),
    };
    escreverln!("carteiro: mandei {}", id);
    match PAR.enviar(&destino.endpoint, INTENCAO, &corpo, 1) {
        Ok(de_novo) if de_novo == id => {
            escreverln!("carteiro: reenvio igual");
        }
        Ok(de_novo) => {
            escreverln!("carteiro: reenvio outro {}", de_novo);
        }
        Err(f) => return recusado("reenviar", &f),
    }
    for _ in 0..PERGUNTAS {
        match PAR.estado(&id) {
            Ok((estado, resposta)) => {
                escreverln!(
                    "carteiro: estado {} {}",
                    estado,
                    resposta.as_deref().unwrap_or("-")
                );
                if estado == "acked" {
                    return CODIGO;
                }
            }
            Err(f) => return recusado("estado", &f),
        }
    }
    RECUSADO
}
