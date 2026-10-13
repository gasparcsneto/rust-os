//! Várias conexões ao mesmo tempo, de um programa só, pelo plano de dados.
//!
//! O programa abre [`CONEXOES`] conexões com o eco da bancada — cada uma um
//! `net.connect`, exercício de autoridade, decidido pelo gate e pago com a
//! ficha da taxa do papel de quem o lançou — e passa por elas,
//! intercalados, [`POR_CONEXAO`] bytes de ida e volta em cada uma: um
//! pedaço em cada, depois o pedaço de volta de cada. Cada `net.send` e cada
//! `net.recv` é uma decisão do gate, gravada na auditoria; nenhum gasta a
//! ficha: são o plano de dados sobre uma conexão já aberta do próprio
//! processo. São centenas de decisões — mais que a rajada inteira do papel.
//!
//! Os bytes de cada conexão são dela: um padrão que muda com a conexão, e o
//! que volta de uma não pode ser o de outra.
//!
//! A suíte roda várias cópias ao mesmo tempo, de pessoas e de agentes: a
//! concorrência entre principais no plano de dados. Sai com [`CODIGO`]
//! quando tudo confere, e com um código menor que diz o quê, quando não.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!("carga", "net.connect", "system.read");

use alloc::vec::Vec;
use programas::conexao::{self, Conexao, Prazo};
use programas::escreverln;
use programas::nativo;

/// Tudo conferiu. A suíte o procura.
const CODIGO: i64 = 96;
/// Uma conexão não abriu.
const ABRIU: i64 = 56;
/// Um envio não saiu.
const MANDOU: i64 = 57;
/// Uma leitura falhou, ou a conexão caiu antes de o eco voltar inteiro.
const LEU: i64 = 58;
/// Voltou por uma conexão o que não era dela.
const TROCOU: i64 = 59;

/// O eco da bancada — ver a política de desenvolvimento.
const ECO: &str = "tcp:10.0.2.100:7";

/// Quantas conexões ao mesmo tempo.
const CONEXOES: usize = 4;

/// O pedaço de cada vez em cada conexão: metade do buffer dela. O eco
/// devolve tudo o que recebe, e o que ele devolve tem de caber no buffer
/// de recepção antes de o programa o ler — senão os dois lados esperariam
/// um pelo outro.
const PEDACO: usize = 8 * 1024;

/// Quantos bytes vão e voltam por conexão.
const POR_CONEXAO: usize = 256 * 1024;

/// O byte `i` da conexão `c`: o padrão de cada uma é só dela.
fn byte(c: usize, i: usize) -> u8 {
    ((i + c * 97) % 251) as u8
}

/// O tempo desde o boot, em milissegundos. Zero, se o relógio não
/// respondeu.
fn agora_ms() -> u64 {
    nativo::pedir("system.uptime", |_| Ok(()))
        .ok()
        .and_then(|r| r.resultado().ok()?.member("uptime_ms")?.as_u64())
        .unwrap_or(0)
}

/// Lê de `conexao` exatamente `n` bytes, que têm de ser os de `c` a partir
/// de `desde`.
fn ler_de_volta(conexao: &mut Conexao, c: usize, desde: usize, n: usize) -> Result<(), i64> {
    let mut buf = alloc::vec![0u8; n];
    let mut lidos = 0;
    while lidos < n {
        let k = conexao.receber(&mut buf[..n - lidos]).map_err(|f| {
            escreverln!("carga: a leitura da conexao {} falhou: {}", c, f.codigo());
            LEU
        })?;
        if k == 0 {
            escreverln!("carga: a conexao {} fechou no meio do eco", c);
            return Err(LEU);
        }
        if (0..k).any(|j| buf[j] != byte(c, desde + lidos + j)) {
            escreverln!("carga: voltou pela conexao {} o que nao era dela", c);
            return Err(TROCOU);
        }
        lidos += k;
    }
    Ok(())
}

fn tudo() -> Result<(), i64> {
    let comeco = agora_ms();
    let mut conexoes = Vec::new();
    for c in 0..CONEXOES {
        conexoes.push(conexao::abrir(ECO, Prazo::PADRAO).map_err(|f| {
            escreverln!("carga: a conexao {} nao abriu: {}", c, f.codigo());
            ABRIU
        })?);
    }
    let mut feito = 0;
    while feito < POR_CONEXAO {
        let n = PEDACO.min(POR_CONEXAO - feito);
        for (c, conexao) in conexoes.iter_mut().enumerate() {
            let pedaco: Vec<u8> = (feito..feito + n).map(|i| byte(c, i)).collect();
            conexao.mandar(&pedaco).map_err(|f| {
                escreverln!("carga: o envio da conexao {} falhou: {}", c, f.codigo());
                MANDOU
            })?;
        }
        for (c, conexao) in conexoes.iter_mut().enumerate() {
            ler_de_volta(conexao, c, feito, n)?;
        }
        feito += n;
    }
    // Largadas, elas fecham: o fecho de cada conexão aberta.
    drop(conexoes);
    escreverln!(
        "carga: {} conexoes, {} KiB de ida e volta em cada, em {} ms",
        CONEXOES,
        POR_CONEXAO / 1024,
        agora_ms().saturating_sub(comeco)
    );
    Ok(())
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    match tudo() {
        Ok(()) => CODIGO,
        Err(codigo) => codigo,
    }
}
