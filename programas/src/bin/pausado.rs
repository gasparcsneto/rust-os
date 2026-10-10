//! Uma sessão TLS que a suíte interrompe no meio: o outro lado dos casos
//! `tls: a politica que tira o destino derruba a sessao`, `tls: o firewall
//! barra a conexao nova com o codigo dele` e `tls: o processo isolado perde
//! a sessao`.
//!
//! O programa conecta ao eco TLS da bancada como `bancada.duke`, manda e lê
//! de volta uma linha, diz `pausado: no meio` e espera um evento no canal
//! [`CANAL`]. A cada evento [`tipo::ACAO`]:
//!
//! - com `a` igual a [`RECONECTAR`], larga a sessão de antes e conecta de
//!   novo, do zero — a semente, o relógio e o destino pelo gate —, manda e
//!   lê uma linha, e diz `pausado: de novo: ALLOW`, ou o código da falha;
//! - com qualquer outro, manda pela sessão que tem e diz `pausado: depois:
//!   ALLOW` se o eco voltou, ou `pausado: depois: <código>`.
//!
//! A sessão cifrada não muda nada no que o gate decide: a recusa dele —
//! `DENY_RESOURCE` depois de a política tirar o destino, `DENY_CONTAINED`
//! com o processo isolado — e a do firewall depois dele —
//! `FIREWALL_BLOCKED` — passam pelo TLS com o código de quem recusou, e não
//! viram um código do TLS.
//!
//! Sai com [`CODIGO`] quando a suíte pede o fim.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "pausado",
    "net.connect",
    "random.read",
    "system.read",
    "fs.read"
);

use alloc::vec::Vec;
use programas::escreverln;
use programas::sistema;
use programas::tls::{self, Ancoras, Falha};
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 87;

/// O canal por onde a suíte dita o passo.
const CANAL: &str = "teste-pausado";

/// O `a` do passo que conecta de novo, em vez de mandar pela sessão que
/// há. A suíte tem a mesma constante.
const RECONECTAR: i64 = 2;

/// A raiz da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// O eco TLS da bancada.
const ECO_TLS: &str = "tcp:10.0.2.100:443";

/// Manda `texto` pela sessão e lê o eco inteiro.
fn eco(sessao: &mut tls::Sessao<tls::Conexao>, texto: &[u8]) -> Result<(), Falha> {
    sessao.mandar(texto)?;
    let mut voltou = Vec::new();
    let mut buf = [0u8; 256];
    while voltou.len() < texto.len() {
        let n = sessao.receber(&mut buf)?;
        if n == 0 {
            return Err(Falha::Interrompida);
        }
        voltou.extend_from_slice(&buf[..n]);
    }
    if voltou != texto {
        return Err(Falha::Interna);
    }
    Ok(())
}

/// Uma sessão nova com o eco TLS, que já mandou e leu `texto`.
fn conectar(ancoras: &Ancoras, texto: &[u8]) -> Result<tls::Sessao<tls::Conexao>, Falha> {
    let mut sessao = tls::conectar(ECO_TLS, "bancada.duke", ancoras)?;
    eco(&mut sessao, texto)?;
    Ok(sessao)
}

/// Diz o desfecho de um passo: `ALLOW`, ou o código de quem recusou.
fn dizer(passo: &str, desfecho: Result<(), Falha>) {
    match desfecho {
        Ok(()) => {
            escreverln!("pausado: {}: ALLOW", passo);
        }
        Err(f) => {
            escreverln!("pausado: {}: {}", passo, f.codigo());
        }
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let canal = sistema::escutar(CANAL);
    if canal < 0 {
        escreverln!("pausado: escutar devolveu {}", canal);
        return 1;
    }
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("pausado: as ancoras nao se leram: {}", f.codigo());
            return 2;
        }
    };
    let mut sessao = match conectar(&ancoras, b"antes da pausa") {
        Ok(s) => Some(s),
        Err(f) => {
            escreverln!("pausado: o aperto antes da pausa falhou: {}", f.codigo());
            return 3;
        }
    };
    escreverln!("pausado: no meio");
    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("pausado: a leitura do canal falhou: {}", e);
                return 4;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                escreverln!("pausado: encerrado");
                return CODIGO;
            }
            if e.tipo != tipo::ACAO {
                continue;
            }
            if e.a == RECONECTAR {
                // A sessão de antes sai primeiro — e a conexão dela fecha,
                // se ainda há —, e a nova não herda nada dela.
                drop(sessao.take());
                match conectar(&ancoras, b"de novo") {
                    Ok(s) => {
                        sessao = Some(s);
                        dizer("de novo", Ok(()));
                    }
                    Err(f) => dizer("de novo", Err(f)),
                }
                continue;
            }
            let desfecho = match sessao.as_mut() {
                Some(s) => eco(s, b"depois da pausa"),
                None => Err(Falha::Interrompida),
            };
            dizer("depois", desfecho);
        }
    }
}
