//! Resolve nomes pelo DNS da bancada, e confere de dentro o que uma
//! resposta de DNS **não** faz: dar acesso.
//!
//! - o DNS é este programa, sobre a associação UDP com o servidor —
//!   `udp:10.0.2.53:53`, o da bancada da suíte —, que o gate decide; o
//!   kernel não resolve nada;
//! - `permitido.duke` resolve para o eco da bancada, e a conexão com ele
//!   passa: o gate decidiu o destino, que está no alcance — não o nome;
//! - `proibido.duke` resolve para um endereço fora do alcance, e a conexão
//!   é `DENY_RESOURCE`, a mesma recusa de quem digitasse o número: a
//!   resposta não abriu nada;
//! - `inexistente.duke` não existe, e o programa ouve isso.
//!
//! Sai com [`CODIGO`] quando tudo confere, e com um código que diz o quê,
//! quando não — a suíte o procura, também com a bancada mentindo.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!("resolvedor", "net.connect");

use programas::dns::{self, Falha};
use programas::escreverln;
use programas::nativo;

/// Tudo conferiu.
const CODIGO: i64 = 83;
/// O gate recusou a associação com o servidor.
const SEM_SERVIDOR: i64 = 71;
/// O servidor não respondeu — ou respondeu de outra origem, que a
/// associação descartou.
const SEM_RESPOSTA: i64 = 72;
/// A resposta não se leu.
const MALFORMADA: i64 = 73;
/// O nome permitido resolveu, e a conexão com o endereço não passou.
const PERMITIDO_RECUSADO: i64 = 74;
/// O nome proibido resolveu, e a conexão com o endereço **passou** — a
/// resposta do DNS teria dado acesso. Não pode acontecer.
const PROIBIDO_PASSOU: i64 = 75;
/// Um nome resolveu para outro endereço.
const OUTRO_ENDERECO: i64 = 76;
/// O nome inexistente não ouviu que não existe.
const INEXISTENTE: i64 = 77;
/// Outra falha da resolução.
const OUTRA: i64 = 78;

/// O servidor de DNS da bancada.
const SERVIDOR: &str = "udp:10.0.2.53:53";

/// A porta do eco: o destino permitido é o eco, e o proibido é um endereço
/// que ninguém tem no alcance, na mesma porta.
const PORTA: u16 = 7;

fn falha(f: Falha) -> i64 {
    escreverln!("resolvedor: {:?}", f);
    match f {
        Falha::Recusada => SEM_SERVIDOR,
        Falha::SemResposta => SEM_RESPOSTA,
        Falha::Malformada(_) => MALFORMADA,
        _ => OUTRA,
    }
}

/// Pede `net.connect` ao endereço, pelo gate, e fecha. `Ok` se o gate
/// deixou; `Err` com o código da recusa.
fn conectar(ip: [u8; 4]) -> Result<(), alloc::string::String> {
    let [a, b, c, d] = ip;
    let destino = alloc::format!("tcp:{a}.{b}.{c}.{d}:{PORTA}");
    let r = nativo::pedir("net.connect", |w| w.field_str("to", &destino))
        .map_err(|e| alloc::format!("chamada {e}"))?;
    match r.resultado() {
        Ok(j) => {
            if let Some(n) = j.member("connection").and_then(|v| v.as_u64()) {
                let _ = nativo::pedir("net.close", |w| w.field_u64("connection", n));
                Ok(())
            } else {
                Err(alloc::string::String::from("sem conexao"))
            }
        }
        Err(recusa) => Err(alloc::string::String::from(recusa.motivo.unwrap_or("?"))),
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    // O permitido: resolve, e o gate deixa conectar no endereço.
    let ips = match dns::resolver(SERVIDOR, "permitido.duke", 0x5101) {
        Ok(ips) => ips,
        Err(f) => return falha(f),
    };
    if ips != [[10, 0, 2, 100]] {
        escreverln!("resolvedor: permitido.duke deu {:?}", ips);
        return OUTRO_ENDERECO;
    }
    if let Err(motivo) = conectar(ips[0]) {
        escreverln!("resolvedor: o endereco permitido foi recusado: {}", motivo);
        return PERMITIDO_RECUSADO;
    }
    escreverln!("resolvedor: permitido.duke -> 10.0.2.100, e o gate deixou conectar");

    // O proibido: resolve, e o gate recusa o endereço — como recusaria o
    // número digitado.
    let ips = match dns::resolver(SERVIDOR, "proibido.duke", 0x5102) {
        Ok(ips) => ips,
        Err(f) => return falha(f),
    };
    if ips != [[10, 0, 2, 99]] {
        escreverln!("resolvedor: proibido.duke deu {:?}", ips);
        return OUTRO_ENDERECO;
    }
    match conectar(ips[0]) {
        Err(motivo) if motivo == "DENY_RESOURCE" => {}
        outro => {
            escreverln!("resolvedor: o endereco proibido deu {:?}", outro);
            return PROIBIDO_PASSOU;
        }
    }
    escreverln!("resolvedor: proibido.duke -> 10.0.2.99, e o gate recusou: DENY_RESOURCE");

    // O inexistente.
    match dns::resolver(SERVIDOR, "inexistente.duke", 0x5103) {
        Err(Falha::Codigo(protocolo::dns::NOME_INEXISTENTE)) => {}
        outro => {
            escreverln!("resolvedor: inexistente.duke deu {:?}", outro);
            return INEXISTENTE;
        }
    }
    escreverln!("resolvedor: inexistente.duke nao existe");
    CODIGO
}
