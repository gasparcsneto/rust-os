//! Uma ponta de fluxo para a suíte: os casos `fluxo:` lançam dois deste,
//! cada um com a autoridade de uma pessoa ou de um agente, e ditam os
//! passos pelo canal `teste-fluxos-<id>` — o id do processo.
//!
//! O programa oferece a intenção [`INTENCAO`] e diz `fluxos: pronto
//! <endpoint>`. Os passos:
//!
//! - [`MANDAR`] `b` KiB: procura quem oferece a intenção — o outro, que não
//!   é ele; procurar é o `fabric.discover`, decidido sobre `fabric.send` —,
//!   abre um fluxo, escreve `b` KiB determinísticos, termina o
//!   sentido dele e lê o que volta até o fim. Diz `fluxos: mandei <n>
//!   voltou <m> <resumo>`.
//! - [`RECEBER`] com `b`: aceita um fluxo, lê tudo e diz `fluxos: recebi
//!   <n> <resumo> de <programa> <resumo da imagem>`; grava o que leu pelo
//!   `fs.write` **dele** — no armazém compartilhado com `b` zero, fora dele
//!   com `b` um — e diz `fluxos: gravar <código>`: ler um fluxo não dá
//!   escrita nenhuma. Depois devolve os mesmos bytes, termina e diz
//!   `fluxos: devolvi <n>`.
//! - [`TROCAR`]: troca de imagem (`executar`, decidido sobre
//!   `process.run`) para o `ola` do disco — [`OLA`] —, que sai com o mesmo
//!   [`CODIGO`]: os fluxos dele acabam. Com `b` 1, para um programa grande
//!   do disco — [`GRANDE`], uns 850 KiB —, que a suíte encerra: a medida da
//!   troca sob escritas sem parar.
//! - [`BIFURCAR`]: duplica o processo; o pai diz `fluxos: filho <id>`, e o
//!   filho escuta o canal dele.
//! - [`COLHER`] o filho `b`: espera ele (`esperar`) e diz `fluxos: colhi
//!   <id> <codigo>` — ou `fluxos: colher <erro>`. Até a suíte mandar, o
//!   filho que saiu é um zumbi.
//!
//! O resumo é o FNV-1a de 64 bits: a suíte o confere contra o dos bytes que
//! o padrão determinístico dá. Cada falha diz o código e o passo, e o
//! programa segue escutando.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "fluxos",
    "fabric.offer",
    "fabric.send",
    "fabric.stream",
    "fabric.remote",
    "fs.write",
    "process.run"
);

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use programas::escreverln;
use programas::fluxo;
use programas::malha;
use programas::nativo;
use programas::sistema;
use protocolo::usuario::evento::{Evento, tipo};

/// A intenção que os dois oferecem.
const INTENCAO: &str = "imagem.compartilhar";

/// Os passos.
const MANDAR: i64 = 1;
const RECEBER: i64 = 2;
const TROCAR: i64 = 3;
const BIFURCAR: i64 = 4;
const COLHER: i64 = 5;

/// O código de saída no fim pedido. A suíte do kernel o procura — e é o
/// mesmo do `ola`, a imagem da troca.
const CODIGO: i64 = 61;

/// A imagem da troca: o `ola`, do disco dos programas — em `/bin` só estão
/// os embutidos no kernel.
#[cfg(target_arch = "x86_64")]
const OLA: &str = "/programas/x86_64/ola";
#[cfg(target_arch = "aarch64")]
const OLA: &str = "/programas/aarch64/ola";

/// O programa grande da troca medida: o `livro`, do disco dos programas.
#[cfg(target_arch = "x86_64")]
const GRANDE: &str = "/programas/x86_64/livro";
#[cfg(target_arch = "aarch64")]
const GRANDE: &str = "/programas/aarch64/livro";

/// Quanto cada pedido espera, no máximo: o teto do `wait`.
const ESPERA_MS: u64 = 10_000;

/// O maior fluxo que se lê: 4 MiB.
const TETO: usize = 4 * 1024 * 1024;

/// O byte `i` do padrão determinístico.
pub fn padrao(i: usize) -> u8 {
    ((i * 7 + 3) % 251) as u8
}

/// O FNV-1a de 64 bits.
fn resumo(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// O endpoint de outro programa que oferece a intenção — não o deste.
fn o_outro(meu: &str) -> Option<String> {
    malha::descobrir(INTENCAO)
        .ok()?
        .into_iter()
        .map(|c| c.endpoint)
        .find(|e| e != meu)
}

fn mandar(meu: &str, kib: i64) {
    let Some(endpoint) = o_outro(meu) else {
        escreverln!("fluxos: mandar sem o outro");
        return;
    };
    let f = match fluxo::abrir(&endpoint, INTENCAO) {
        Ok(f) => f,
        Err(e) => {
            escreverln!("fluxos: abrir {} {}", e.codigo(), e.motivo());
            return;
        }
    };
    let n = (kib.max(0) as usize) * 1024;
    let dados: Vec<u8> = (0..n).map(padrao).collect();
    if let Err(e) = f.escrever_tudo(&dados, ESPERA_MS, 3) {
        escreverln!("fluxos: escrever {} {}", e.codigo(), e.motivo());
        return;
    }
    if let Err(e) = f.terminar() {
        escreverln!("fluxos: terminar {}", e.codigo());
        return;
    }
    let mut volta = Vec::new();
    match f.ler_tudo(&mut volta, TETO, ESPERA_MS, 3) {
        Ok(()) => {
            escreverln!(
                "fluxos: mandei {} voltou {} {:016x}",
                n,
                volta.len(),
                resumo(&volta)
            );
        }
        Err(e) => {
            escreverln!("fluxos: ler {} {}", e.codigo(), e.motivo());
        }
    }
}

fn receber(meu: &str, fora: i64) {
    let (f, de) = match fluxo::aceitar(meu, ESPERA_MS) {
        Ok(Some(x)) => x,
        Ok(None) => {
            escreverln!("fluxos: aceitar nada");
            return;
        }
        Err(e) => {
            escreverln!("fluxos: aceitar {} {}", e.codigo(), e.motivo());
            return;
        }
    };
    let mut dados = Vec::new();
    if let Err(e) = f.ler_tudo(&mut dados, TETO, ESPERA_MS, 3) {
        escreverln!("fluxos: ler {} {}", e.codigo(), e.motivo());
        return;
    }
    let quem = match (&de.programa, &de.dispositivo) {
        (Some((p, r)), _) => format!("{} {}", p, r.get(..8).unwrap_or(r)),
        (None, Some(d)) => d.clone(),
        (None, None) => String::from("?"),
    };
    escreverln!(
        "fluxos: recebi {} {:016x} de {}",
        dados.len(),
        resumo(&dados),
        quem
    );
    // Gravar é decisão de quem lê, pelo papel dele: o fluxo não deu nada.
    let caminho = if fora == 0 {
        format!("/armazem/compartilhado/fluxo-{}", sistema::id())
    } else {
        format!("/dados/fluxo-{}", sistema::id())
    };
    let pedaco = &dados[..dados.len().min(4096)];
    let codigo = match nativo::pedir_com_anexo(
        "fs.write",
        |w| {
            w.field_str("path", &caminho)?;
            w.field_u64("expect_version", 0)
        },
        pedaco,
    ) {
        Ok(r) => match r.resultado() {
            Ok(j) if j.member("ok").and_then(|v| v.as_bool()) != Some(false) => {
                String::from("ALLOW")
            }
            Ok(j) => j
                .member("code")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| String::from("ERROR")),
            Err(recusa) => String::from(recusa.motivo.unwrap_or("ERROR")),
        },
        Err(e) => format!("CHAMADA {e}"),
    };
    escreverln!("fluxos: gravar {}", codigo);
    if let Err(e) = f.escrever_tudo(&dados, ESPERA_MS, 3) {
        escreverln!("fluxos: devolver {} {}", e.codigo(), e.motivo());
        return;
    }
    match f.terminar() {
        Ok(()) => {
            escreverln!("fluxos: devolvi {}", dados.len());
        }
        Err(e) => {
            escreverln!("fluxos: terminar {}", e.codigo());
        }
    }
}

/// Escuta o canal deste processo e atende os passos até o fim.
fn escutar(meu: &str) -> i64 {
    let nome = format!("teste-fluxos-{}", sistema::id());
    let canal = sistema::escutar(&nome);
    if canal < 0 {
        escreverln!("fluxos: escutar devolveu {}", canal);
        return 1;
    }
    escreverln!("fluxos: pronto {}", meu);
    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("fluxos: a leitura falhou: {}", e);
                return 2;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                escreverln!("fluxos: encerrado");
                return CODIGO;
            }
            if e.tipo != tipo::ACAO {
                continue;
            }
            match e.a {
                MANDAR => mandar(meu, e.b),
                RECEBER => receber(meu, e.b),
                TROCAR => {
                    escreverln!("fluxos: trocando");
                    let r = sistema::executar(if e.b == 1 { GRANDE } else { OLA });
                    escreverln!("fluxos: trocar devolveu {}", r);
                }
                BIFURCAR => match sistema::bifurcar() {
                    0 => {
                        escreverln!("fluxos: sou o filho {}", sistema::id());
                        return escutar(meu);
                    }
                    filho if filho > 0 => {
                        escreverln!("fluxos: filho {}", filho);
                    }
                    erro => {
                        escreverln!("fluxos: bifurcar devolveu {}", erro);
                    }
                },
                COLHER => match sistema::esperar(e.b.max(0) as u64) {
                    Ok((id, Some(codigo))) => {
                        escreverln!("fluxos: colhi {} {}", id, codigo);
                    }
                    Ok((id, None)) => {
                        escreverln!("fluxos: colhi {} falha", id);
                    }
                    Err(erro) => {
                        escreverln!("fluxos: colher {}", erro);
                    }
                },
                outro => {
                    escreverln!("fluxos: passo desconhecido {}", outro);
                }
            }
        }
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let meu = match malha::oferecer(INTENCAO) {
        Ok(e) => e,
        Err(f) => {
            escreverln!("fluxos: oferecer {}", f.codigo());
            return 3;
        }
    };
    escutar(&meu)
}
