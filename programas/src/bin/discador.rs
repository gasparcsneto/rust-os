//! Um programa que conversa pela rede do Duke, e confere de dentro o que a
//! rede promete a um processo:
//!
//! - a conexão é pedida ao registro — `net.connect`, com o destino inteiro
//!   —, pelo mesmo `pedir` de todo comando; o manifesto declara
//!   `net.connect`, e sem isso o gate recusaria, qualquer que fosse o papel
//!   de quem o lançou;
//! - o destino é o recurso que a política decide: o eco da bancada,
//!   `tcp:10.0.2.100:7`, está no alcance; a porta ao lado não está, e a
//!   recusa é `DENY_RESOURCE`;
//! - os bytes vão e voltam inteiros: os 256 valores de um byte, pelo anexo
//!   do pedido, e de volta em texto quando são texto e em base64 quando
//!   não são;
//! - fechada, a conexão deixa de existir para o programa também:
//!   `DENY_RESOURCE`, a mesma resposta de um número que nunca existiu.
//!
//! Lançado por alguém sem `net.connect` no papel, sai com [`SEM_REDE`]
//! depois de ouvir `DENY_PERMISSION`. Sai com [`CODIGO`] quando tudo
//! confere, e com um código menor que diz o quê, quando não.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!("discador", "net.connect");

use alloc::vec::Vec;
use programas::escreverln;
use programas::nativo::{self, Recusa};
use programas::sistema;

/// O código de saída quando tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 79;

/// O código de quem foi lançado sem `net.connect` no papel.
const SEM_REDE: i64 = 71;

/// O eco da bancada — ver a política de desenvolvimento.
const ECO: &str = "tcp:10.0.2.100:7";

/// Quantas voltas esperar o eco, cedendo entre uma e outra.
const VOLTAS: usize = 20_000;

fn codigo_de(r: &nativo::Resposta) -> Option<&str> {
    match r.resultado() {
        Err(Recusa { motivo, .. }) => motivo,
        Ok(_) => None,
    }
}

fn numero(r: &nativo::Resposta, campo: &str) -> Option<u64> {
    r.resultado().ok()?.member(campo)?.as_u64()
}

fn texto<'r>(r: &'r nativo::Resposta, campo: &str) -> Option<&'r str> {
    r.resultado().ok()?.member(campo)?.as_str()
}

/// O valor de um caractere base64, ou `None` para o que não é.
fn valor(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// Base64 com preenchimento, de volta a bytes.
fn de_base64(texto: &str, saida: &mut Vec<u8>) -> Option<()> {
    let b = texto.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    for quarteto in b.chunks(4) {
        let iguais = quarteto.iter().rev().take_while(|&&c| c == b'=').count();
        let mut n = 0u32;
        for &c in &quarteto[..4 - iguais] {
            n = (n << 6) | valor(c)?;
        }
        n <<= 6 * iguais as u32;
        let tres = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        saida.extend_from_slice(&tres[..3 - iguais]);
    }
    Some(())
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    // A porta ao lado do eco: fora do alcance de qualquer papel desta
    // imagem.
    let Ok(r) = nativo::pedir("net.connect", |w| w.field_str("to", "tcp:10.0.2.100:8")) else {
        return 1;
    };
    match codigo_de(&r) {
        Some("DENY_PERMISSION") => {
            escreverln!("discador: sem net.connect no papel de quem me lancou");
            return SEM_REDE;
        }
        Some("DENY_RESOURCE") => {}
        outro => {
            escreverln!("discador: a porta ao lado deu {:?}", outro);
            return 2;
        }
    }

    let Ok(r) = nativo::pedir("net.connect", |w| w.field_str("to", ECO)) else {
        return 3;
    };
    let Some(conexao) = numero(&r, "connection") else {
        escreverln!(
            "discador: o eco nao abriu: {:?} {:?}",
            codigo_de(&r),
            texto(&r, "error")
        );
        return 3;
    };

    // Os 256 valores de um byte, pelo anexo: metade não é texto.
    let enviado: Vec<u8> = (0..=255u8).collect();
    let mut mandados = 0usize;
    let mut voltou = Vec::new();
    for _ in 0..VOLTAS {
        if mandados < enviado.len() {
            let resto = &enviado[mandados..];
            let Ok(r) =
                nativo::pedir_com_anexo("net.send", |w| w.field_u64("connection", conexao), resto)
            else {
                return 4;
            };
            match numero(&r, "sent") {
                Some(n) => mandados += n as usize,
                None => {
                    escreverln!(
                        "discador: net.send deu {:?} {:?}",
                        codigo_de(&r),
                        texto(&r, "error")
                    );
                    return 4;
                }
            }
        }
        let Ok(r) = nativo::pedir("net.recv", |w| w.field_u64("connection", conexao)) else {
            return 5;
        };
        let (Some(codificacao), Some(conteudo)) = (texto(&r, "encoding"), texto(&r, "content"))
        else {
            escreverln!(
                "discador: net.recv deu {:?} {:?}",
                codigo_de(&r),
                texto(&r, "error")
            );
            return 5;
        };
        match codificacao {
            // O texto vem escapado no JSON — os bytes de controle como
            // `\u0001` —, e volta ao que era pelo leitor do protocolo.
            "utf-8" => {
                let mut claro = alloc::vec![0u8; conteudo.len()];
                let Some(t) = r
                    .resultado()
                    .ok()
                    .and_then(|v| v.member("content"))
                    .and_then(|c| c.desescapar_em(&mut claro))
                else {
                    return 6;
                };
                voltou.extend_from_slice(t.as_bytes());
            }
            "base64" => {
                if de_base64(conteudo, &mut voltou).is_none() {
                    return 6;
                }
            }
            _ => return 6,
        }
        if voltou.len() >= enviado.len() {
            break;
        }
        if texto(&r, "state") == Some("closed") {
            escreverln!(
                "discador: o eco fechou com {} de {} bytes",
                voltou.len(),
                enviado.len()
            );
            return 7;
        }
        sistema::ceder();
    }
    if voltou != enviado {
        escreverln!(
            "discador: voltaram {} bytes, e nao os mandados",
            voltou.len()
        );
        return 8;
    }

    let Ok(r) = nativo::pedir("net.close", |w| w.field_u64("connection", conexao)) else {
        return 9;
    };
    if codigo_de(&r).is_some() {
        return 9;
    }
    // Fechada, o número não vale mais — nem para quem a abriu.
    let Ok(r) = nativo::pedir("net.recv", |w| w.field_u64("connection", conexao)) else {
        return 10;
    };
    if codigo_de(&r) != Some("DENY_RESOURCE") {
        escreverln!("discador: a conexao fechada respondeu {:?}", codigo_de(&r));
        return 10;
    }

    escreverln!("discador: 256 bytes foram e voltaram pelo eco");
    CODIGO
}
