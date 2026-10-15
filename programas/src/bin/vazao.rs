//! Uma transferência grande, pelo plano de dados, com a política de todo
//! dia: [`CLARAS`] corpos de 1 MiB do servidor HTTP da bancada, e
//! [`CIFRADAS`] atrás do TLS.
//!
//! Cada corpo é uma conexão: o `net.connect` é exercício de autoridade, e
//! gasta uma ficha da taxa do papel de quem lançou o programa — como a
//! semente e o relógio de cada aperto TLS, e a leitura da âncora. O corpo
//! vem em dezenas de decisões do gate por MiB, uma por `net.recv`, cada
//! uma gravada na auditoria; nenhuma delas gasta a ficha: são o plano de
//! dados sobre a conexão já aberta do próprio processo. Antes da separação
//! do plano de dados, a pessoa operadora ouvia `RATE_LIMIT` no meio do
//! segundo MiB — e a transferência autorizada caía.
//!
//! O nome vai direto a `10.0.2.100`, sem DNS. Sai com [`CODIGO`] quando
//! todos os corpos chegaram inteiros e certos, e diz no log quanto cada um
//! levou e a vazão de tudo — a medida que o benchmark compara.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "vazao",
    "net.connect",
    "random.read",
    "system.read",
    "fs.read"
);

use programas::conexao::Prazo;
use programas::escreverln;
use programas::http::{self, Limites, Opcoes, Protocolo, Resolucao};
use programas::nativo;
use programas::tls;

/// Tudo conferiu. A suíte e a fumaça o procuram.
const CODIGO: i64 = 95;
/// As âncoras não se leram.
const SEM_ANCORAS: i64 = 53;
/// Um corpo não chegou: a falha, com o código e a família dela.
const FALHOU: i64 = 54;
/// Um corpo chegou diferente do que a bancada manda.
const ERRADO: i64 = 55;

/// Quantos corpos claros, e quantos cifrados: 5 MiB, quatro vezes o que a
/// taxa do operador deixava passar quando os dados gastavam a ficha.
const CLARAS: usize = 4;
const CIFRADAS: usize = 1;

/// O tamanho de cada corpo: o maior que o HTTP do programa aceita.
const TAMANHO: usize = 1024 * 1024;

/// A raiz da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// O tempo desde o boot, em milissegundos. Zero, se o relógio não
/// respondeu.
fn agora_ms() -> u64 {
    nativo::pedir("system.uptime", |_| Ok(()))
        .ok()
        .and_then(|r| r.resultado().ok()?.member("uptime_ms")?.as_u64())
        .unwrap_or(0)
}

/// `vezes` corpos de `url`, um depois do outro, cada um conferido byte a
/// byte contra o padrão da bancada. Devolve os bytes.
fn serie(opcoes: &Opcoes<'_>, rotulo: &str, url: &str, vezes: usize) -> Result<u64, i64> {
    let limites = Limites::default();
    let comeco = agora_ms();
    let mut bytes = 0u64;
    for i in 0..vezes {
        let antes = agora_ms();
        let r = http::obter(url, opcoes, &limites).map_err(|f| {
            escreverln!(
                "vazao: {} #{} falhou: {} {}",
                rotulo,
                i,
                f.categoria().nome(),
                f.codigo()
            );
            FALHOU
        })?;
        let certo = r.status == 200
            && r.corpo.len() == TAMANHO
            && r.corpo
                .iter()
                .enumerate()
                .all(|(j, b)| *b == b'0' + (j % 10) as u8);
        if !certo {
            escreverln!(
                "vazao: {} #{} deu {} com {} bytes",
                rotulo,
                i,
                r.status,
                r.corpo.len()
            );
            return Err(ERRADO);
        }
        bytes += r.corpo.len() as u64;
        escreverln!(
            "vazao: {} #{}: {} bytes em {} ms",
            rotulo,
            i,
            r.corpo.len(),
            agora_ms().saturating_sub(antes)
        );
    }
    let ms = agora_ms().saturating_sub(comeco).max(1);
    escreverln!(
        "vazao: {}: {} KiB em {} ms ({} KiB/s)",
        rotulo,
        bytes / 1024,
        ms,
        bytes * 1000 / 1024 / ms
    );
    Ok(bytes)
}

fn tudo(ancoras: &tls::Ancoras) -> Result<(), i64> {
    let opcoes = Opcoes {
        resolucao: Resolucao::Fixa([10, 0, 2, 100]),
        ancoras: Some(ancoras),
        prazo: Prazo::PADRAO,
        protocolo: Protocolo::Http1,
    };
    let comeco = agora_ms();
    let claros = serie(
        &opcoes,
        "claro",
        "http://bancada.duke/grande/1048576",
        CLARAS,
    )?;
    let cifrados = serie(
        &opcoes,
        "cifrado",
        "https://bancada.duke:8443/grande/1048576",
        CIFRADAS,
    )?;
    let ms = agora_ms().saturating_sub(comeco).max(1);
    let total = claros + cifrados;
    escreverln!(
        "vazao: tudo: {} KiB em {} ms ({} KiB/s)",
        total / 1024,
        ms,
        total * 1000 / 1024 / ms
    );
    Ok(())
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("vazao: as ancoras nao se leram: {}", f.codigo());
            return SEM_ANCORAS;
        }
    };
    match tudo(&ancoras) {
        Ok(()) => {
            escreverln!("vazao: tudo conferiu");
            CODIGO
        }
        Err(codigo) => codigo,
    }
}
