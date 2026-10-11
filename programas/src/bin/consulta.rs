//! Uma visita curta ao servidor HTTP da bancada, para a suíte rodar várias
//! ao mesmo tempo — de pessoas e de agentes — e conferir que cada uma
//! conversa com a autoridade de quem a lançou, e só com ela.
//!
//! - `GET http://bancada.duke/ola`;
//! - três `GET /conta` numa conexão só, que contam 1, 2 e 3;
//! - 16 KiB num `POST /eco`, ida e volta.
//!
//! O nome vai direto a `10.0.2.100`, sem DNS: o que se confere aqui é a
//! concorrência e a autoridade, e não a resolução — que é do `buscador`.
//! Sai com [`CODIGO`] quando tudo confere, e com um código menor que diz o
//! quê, quando não.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!("consulta", "net.connect");

use alloc::vec::Vec;
use programas::conexao::Prazo;
use programas::escreverln;
use programas::http::{self, Limites, Metodo, Opcoes, Pedido, Resolucao, Url};

/// Tudo conferiu. A suíte o procura.
const CODIGO: i64 = 91;
/// A página não veio.
const PAGINA: i64 = 50;
/// A conexão mantida não contou 1, 2 e 3.
const MANTIDA: i64 = 51;
/// O eco não voltou igual.
const ECO: i64 = 52;

fn tudo() -> Result<(), i64> {
    let opcoes = Opcoes {
        resolucao: Resolucao::Fixa([10, 0, 2, 100]),
        ancoras: None,
        prazo: Prazo::PADRAO,
    };
    let limites = Limites::default();
    match http::obter("http://bancada.duke/ola", &opcoes, &limites) {
        Ok(r) if r.status == 200 && r.corpo == b"ola, duke\n" => {}
        outro => {
            escreverln!(
                "consulta: /ola deu {:?}",
                outro.map(|r| r.status).map_err(|f| f.categoria().nome())
            );
            return Err(PAGINA);
        }
    }
    let url = Url::ler("http://bancada.duke/conta").map_err(|_| MANTIDA)?;
    let mut conexao = http::conectar(&url, &opcoes).map_err(|f| {
        escreverln!("consulta: a conexao falhou: {}", f.codigo());
        MANTIDA
    })?;
    let mut contas = Vec::new();
    for _ in 0..3 {
        match conexao.trocar(&Pedido::novo(Metodo::Get, url.clone()), &limites) {
            Ok(r) if r.status == 200 => contas.push(http::texto(&r)),
            outro => {
                escreverln!(
                    "consulta: /conta deu {:?}",
                    outro.map(|r| r.status).map_err(|f| f.categoria().nome())
                );
                return Err(MANTIDA);
            }
        }
    }
    conexao.fechar();
    if contas != ["1", "2", "3"] {
        escreverln!("consulta: a conexao mantida contou {:?}", contas);
        return Err(MANTIDA);
    }
    let mut pedido = Pedido::novo(
        Metodo::Post,
        Url::ler("http://bancada.duke/eco").map_err(|_| ECO)?,
    );
    pedido.corpo = http::padrao(16 * 1024);
    match http::buscar(pedido.clone(), &opcoes, &limites) {
        Ok(r) if r.status == 200 && r.corpo == pedido.corpo => Ok(()),
        outro => {
            escreverln!(
                "consulta: o eco deu {:?}",
                outro
                    .map(|r| r.corpo.len())
                    .map_err(|f| f.categoria().nome())
            );
            Err(ECO)
        }
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    match tudo() {
        Ok(()) => CODIGO,
        Err(codigo) => codigo,
    }
}
