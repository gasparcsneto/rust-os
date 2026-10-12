//! O programa que chega pela rede.
//!
//! Não está na imagem: o `xtask` o publica, selado pelo editor `bancada`,
//! no servidor HTTP da bancada — ver `xtask/src/codigo.rs` —, e quem o
//! quiser rodar o baixa, grava no armazém e o executa. O Duke só o deixa
//! rodar com o selo de um editor em que o papel de quem o lança confia, e
//! cada pedido dele pergunta isso de novo.
//!
//! Diz que rodou e pede uma coisa pelo gate — `system.info`, que o
//! manifesto declara. Sai com [`CODIGO`] quando o pedido passa, e com
//! [`RECUSADO`] quando o gate o recusa: o que a suíte confere quando a
//! confiança no editor sai antes do primeiro pedido.

#![no_std]
#![no_main]

programas::manifesto!("vindo", "system.read");

use programas::escreverln;
use programas::nativo::{self, Recusa};

/// O pedido passou. A suíte e a fumaça o procuram.
const CODIGO: i64 = 92;
/// O gate recusou o pedido.
const RECUSADO: i64 = 93;

#[unsafe(no_mangle)]
fn principal() -> i64 {
    escreverln!("vindo: rodando, de fora da imagem");
    match nativo::pedir("system.info", |_| Ok(())) {
        Ok(r) => match r.resultado() {
            Ok(_) => {
                escreverln!("vindo: o gate deixou");
                CODIGO
            }
            Err(Recusa { motivo, .. }) => {
                escreverln!("vindo: recusado {}", motivo.unwrap_or("?"));
                RECUSADO
            }
        },
        Err(e) => {
            escreverln!("vindo: o pedido falhou: {}", e);
            1
        }
    }
}
