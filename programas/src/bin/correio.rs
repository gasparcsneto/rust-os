//! Quem atende: a ponta que recebe nos casos `malha:` da suíte — o
//! "aplicativo B" do primeiro marco da malha.
//!
//! O programa oferece a intenção [`INTENCAO`], diz `correio: endpoint <id>`
//! e espera o que chega, com `fabric.recv` e `wait` — o pedido dorme no
//! kernel, sem gastar a taxa a cada volta. Cada entrega nova ele diz
//! `correio: recebi <corpo> de <programa> <resumo>` — o programa e o resumo
//! que o kernel conferiu, `titular` se veio da sessão, sem programa, ou o
//! dispositivo, se veio de outro pelo enlace — e a confirma com a resposta
//! `guardada:<corpo>`.
//!
//! O corpo [`FIM`] encerra o programa com [`CODIGO`]. Uma recusa do gate ou
//! da malha — o endpoint que fechou, a pessoa que saiu, a chave revogada, a
//! política que tirou a intenção — ele diz `correio: receber <código>` e
//! sai com [`RECUSADO`]: quem perdeu a autoridade não fica tentando.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!("correio", "fabric.offer");

use alloc::format;
use alloc::string::String;
use programas::escreverln;
use programas::malha;

/// A intenção que o correio oferece.
const INTENCAO: &str = "imagem.compartilhar";

/// O corpo que encerra o programa.
const FIM: &str = "fim";

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 41;

/// O código de saída depois de uma recusa.
const RECUSADO: i64 = 42;

/// Quanto cada leitura espera, no máximo: o teto do `wait`.
const ESPERA_MS: u64 = 10_000;

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let endpoint = match malha::oferecer(INTENCAO) {
        Ok(e) => e,
        Err(f) => {
            escreverln!("correio: oferecer {}", f.codigo());
            return RECUSADO;
        }
    };
    escreverln!("correio: endpoint {}", endpoint);
    let mut ultima: Option<String> = None;
    loop {
        let entregas = match malha::receber(&endpoint, ultima.as_deref(), ESPERA_MS) {
            Ok(v) => v,
            Err(f) => {
                escreverln!("correio: receber {}", f.codigo());
                return RECUSADO;
            }
        };
        for e in entregas {
            match (&e.de, &e.dispositivo) {
                (_, Some(dispositivo)) => {
                    escreverln!("correio: recebi {} de {}", e.corpo, dispositivo);
                }
                (Some((programa, resumo)), None) => {
                    escreverln!(
                        "correio: recebi {} de {} {}",
                        e.corpo,
                        programa,
                        resumo.get(..8).unwrap_or(resumo)
                    );
                }
                (None, None) => {
                    escreverln!("correio: recebi {} de titular", e.corpo);
                }
            }
            let resposta = format!("guardada:{}", e.corpo);
            if let Err(f) = malha::confirmar(&e.id, Some(&resposta)) {
                escreverln!("correio: confirmar {}", f.codigo());
            }
            ultima = Some(e.id.clone());
            if e.corpo == FIM {
                escreverln!("correio: encerrado");
                return CODIGO;
            }
        }
    }
}
