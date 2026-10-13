//! Um processo que passa dados pela conexão aberta, e insiste: o outro lado
//! dos casos da suíte que contêm, revogam e barram no meio de uma
//! transferência, e conferem que o processo contido não tem o benefício do
//! plano de dados.
//!
//! O programa escuta o canal [`CANAL`], e cada evento é um passo que a
//! suíte dita — sem corrida com o relógio:
//!
//! - [`PASSAR`]: abre uma conexão com o eco, se não tem uma, e passa por
//!   ela `b` idas e voltas de 256 bytes, cada envio e cada leitura com
//!   `wait`; diz `insistente: passou <b>`, ou a falha;
//! - [`INSISTIR`]: `b` envios de um byte, sem `wait`, um atrás do outro, e
//!   diz quantos saíram e quantos ouviram cada recusa;
//! - [`UM`]: um envio só, com `wait` — o que a suíte segura no caminho da
//!   auditoria —, e diz o que ouviu: `ENVIADO`, ou o código;
//! - [`FECHAR`]: fecha a conexão, e diz o que ouviu.
//!
//! Sai com [`CODIGO`] quando a suíte pede o fim.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!("insistente", "net.connect");

use alloc::vec::Vec;
use programas::conexao::{Codigo, Falha};
use programas::escreverln;
use programas::nativo;
use programas::sistema;
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 97;

/// O canal por onde a suíte dita o passo.
const CANAL: &str = "teste-insistente";

/// Os passos — o `a` do evento; o `b` é o quanto.
const PASSAR: i64 = 1;
const INSISTIR: i64 = 2;
const UM: i64 = 3;
const FECHAR: i64 = 4;

/// O eco da bancada.
const ECO: &str = "tcp:10.0.2.100:7";

/// O que um pedido sobre a conexão ouviu: `ENVIADO`, o código da recusa do
/// gate, o código de depois do gate — o firewall —, ou `ALLOW`.
fn desfecho(r: Result<nativo::Resposta, i64>) -> Codigo {
    let Ok(r) = r else {
        return Codigo::de("SEM_RESPOSTA");
    };
    match r.resultado() {
        Err(recusa) => Codigo::de(recusa.motivo.unwrap_or("?")),
        Ok(res) => match res.member("code").and_then(|c| c.as_str()) {
            Some(c) => Codigo::de(c),
            None if res
                .member("sent")
                .and_then(|v| v.as_u64())
                .is_some_and(|n| n > 0) =>
            {
                Codigo::de("ENVIADO")
            }
            None => Codigo::de("ALLOW"),
        },
    }
}

/// Um envio de `dados` pela conexão, com `wait` em milissegundos, ou sem.
fn mandar(conexao: u64, dados: &[u8], wait: Option<u64>) -> Result<nativo::Resposta, i64> {
    nativo::pedir_com_anexo(
        "net.send",
        |w| {
            w.field_u64("connection", conexao)?;
            match wait {
                Some(ms) => w.field_u64("wait", ms),
                None => Ok(()),
            }
        },
        dados,
    )
}

/// `n` idas e voltas de 256 bytes pela conexão.
fn passar(conexao: &mut programas::conexao::Conexao, n: i64) -> Result<(), Falha> {
    let mut buf = [0u8; 256];
    for k in 0..n.max(0) as usize {
        let dados: Vec<u8> = (0..256).map(|i| b'a' + ((i + k) % 26) as u8).collect();
        conexao.mandar(&dados)?;
        let mut lidos = 0;
        while lidos < dados.len() {
            match conexao.receber(&mut buf[..dados.len() - lidos])? {
                0 => return Err(Falha::Caiu),
                m => {
                    if buf[..m] != dados[lidos..lidos + m] {
                        return Err(Falha::Interna);
                    }
                    lidos += m;
                }
            }
        }
    }
    Ok(())
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let canal = sistema::escutar(CANAL);
    if canal < 0 {
        escreverln!("insistente: escutar devolveu {}", canal);
        return 1;
    }
    escreverln!("insistente: pronto");
    let mut conexao: Option<programas::conexao::Conexao> = None;
    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("insistente: a leitura falhou: {}", e);
                return 2;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                // Largada, a conexão fecha.
                drop(conexao.take());
                escreverln!("insistente: encerrado");
                return CODIGO;
            }
            match e.a {
                PASSAR => {
                    if conexao.is_none() {
                        match programas::conexao::abrir(ECO, programas::conexao::Prazo::PADRAO) {
                            Ok(c) => conexao = Some(c),
                            Err(f) => {
                                escreverln!("insistente: passou: {}", f.codigo());
                                continue;
                            }
                        }
                    }
                    let Some(c) = conexao.as_mut() else {
                        continue;
                    };
                    match passar(c, e.b) {
                        Ok(()) => {
                            escreverln!("insistente: passou {}", e.b);
                        }
                        Err(f) => {
                            escreverln!("insistente: passou: {}", f.codigo());
                        }
                    }
                }
                INSISTIR => {
                    let numero = conexao.as_ref().map_or(0, |c| c.numero());
                    let (mut enviados, mut contidos, mut taxa, mut outros) = (0, 0, 0, 0);
                    for _ in 0..e.b.max(0) {
                        match desfecho(mandar(numero, b"x", None)).como_str() {
                            "ENVIADO" => enviados += 1,
                            "DENY_CONTAINED" => contidos += 1,
                            "RATE_LIMIT" => taxa += 1,
                            _ => outros += 1,
                        }
                    }
                    escreverln!(
                        "insistente: insistiu {} enviados, {} contidos, {} taxa, {} outros",
                        enviados,
                        contidos,
                        taxa,
                        outros
                    );
                }
                UM => {
                    let numero = conexao.as_ref().map_or(0, |c| c.numero());
                    let d = desfecho(mandar(numero, b"y", Some(10_000)));
                    escreverln!("insistente: um {}", d.como_str());
                }
                FECHAR => {
                    let numero = conexao.as_ref().map_or(0, |c| c.numero());
                    let r = nativo::pedir("net.close", |w| w.field_u64("connection", numero));
                    // A conexão não volta a ser pedida: o número é esquecido
                    // sem o fecho do `Drop`.
                    if let Some(c) = conexao.take() {
                        core::mem::forget(c);
                    }
                    escreverln!("insistente: fechou {}", desfecho(r).como_str());
                }
                _ => {
                    escreverln!("insistente: passo desconhecido {}", e.a);
                }
            }
        }
    }
}
