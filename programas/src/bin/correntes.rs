//! O HTTP/2 de ponta a ponta, contra o servidor da bancada — claro, com
//! conhecimento prévio (h2c), e atrás do TLS, pelo ALPN —, e o que ele
//! **não** é: autoridade.
//!
//! O nome `bancada.duke` vai direto a `10.0.2.100`, sem DNS, como no
//! `compressao` e no `cookies`. Cada passo diz no log o que conferiu:
//!
//! - a conexão fala o HTTP/2 que se pediu, e a resposta diz que veio nele;
//! - várias correntes ao mesmo tempo numa conexão só — de um byte a 100
//!   KiB, uma lenta no meio —, recebidas de trás para a frente;
//! - o corpo de um pedido de 200 KiB, que vai e volta dentro das janelas
//!   do servidor;
//! - o corpo comprimido e os cookies, pelas correntes como pelo HTTP/1.1;
//! - o corpo além do limite falha só a corrente dele, e a conexão segue;
//! - o servidor que reinicia ou recusa uma corrente falha só ela; o que
//!   quebra o protocolo — o *push* que o cliente desligou, o bloco de
//!   cabeça que não se decodifica, a enxurrada de `PING`, o `GOAWAY` com
//!   erro — acaba com a conexão inteira, e cada corrente que esperava ouve o
//!   mesmo código;
//! - pelo TLS, o ALPN: o HTTP/2 só, o HTTP/2 se o servidor quiser, e o
//!   HTTP/1.1 sem oferecer nada; e o servidor que não fala HTTP/2 — o
//!   `antigo.duke`, o mesmo destino —: o HTTP/1.1 de reserva, e a recusa de
//!   quem exige o HTTP/2;
//! - a medida: os mesmos pedidos pelo HTTP/1.1 numa conexão mantida, pelo
//!   HTTP/2 um de cada vez, e pelo HTTP/2 todos ao mesmo tempo;
//! - fora do alcance, a recusa é do gate, `DENY_RESOURCE`, antes do
//!   primeiro byte — o HTTP/2 não entra nisso.
//!
//! Sai com [`CODIGO`] quando tudo confere, e com um código menor que diz o
//! quê, quando não.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "correntes",
    "net.connect",
    "random.read",
    "system.read",
    "fs.read"
);

use alloc::collections::VecDeque;
use alloc::format;
use alloc::vec::Vec;
use programas::conexao::Prazo;
use programas::escreverln;
use programas::http::{
    self, Categoria, Codificacao, ConexaoHttp, Falha, Limites, Metodo, Opcoes, Pedido, Pote,
    Protocolo, Resolucao, Resposta, Url, Versao,
};
use programas::tls;

/// Tudo conferiu. A suíte e a fumaça o procuram.
const CODIGO: i64 = 99;
/// As âncoras não se leram.
const SEM_ANCORAS: i64 = 40;
/// A conexão não falou o HTTP que se pediu.
const VERSAO: i64 = 41;
/// As correntes ao mesmo tempo não vieram certas.
const CORRENTES: i64 = 42;
/// O corpo do pedido não voltou inteiro.
const ECO: i64 = 43;
/// O corpo comprimido ou os cookies não vieram certos.
const CONTEUDO: i64 = 44;
/// O limite do corpo não ficou na corrente.
const LIMITES: i64 = 45;
/// O servidor que quebra o protocolo não foi recusado como devia.
const HOSTIS: i64 = 46;
/// O ALPN não deu o HTTP que se pediu.
const ALPN: i64 = 47;
/// O destino fora do alcance não foi recusado pelo gate.
const FORA: i64 = 48;
/// A medida não se fez.
const MEDIDA: i64 = 49;

/// A raiz da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// O servidor HTTP da bancada, sem DNS.
const BANCADA: [u8; 4] = [10, 0, 2, 100];

const CLARA: &str = "http://bancada.duke";
const CIFRADA: &str = "https://bancada.duke:8443";
/// O mesmo servidor e o mesmo destino, por um nome em que o ALPN só oferece
/// o HTTP/1.1.
const ANTIGA: &str = "https://antigo.duke:8443";

/// As opções de sempre, com o `protocolo`.
fn opcoes<'a>(ancoras: &'a tls::Ancoras, protocolo: Protocolo) -> Opcoes<'a> {
    Opcoes {
        resolucao: Resolucao::Fixa(BANCADA),
        ancoras: Some(ancoras),
        prazo: Prazo {
            espera_ms: 5_000,
            esperas: 4,
        },
        protocolo,
    }
}

fn url(origem: &str, caminho: &str) -> Url {
    // As URLs daqui são escritas à mão, e todas se leem.
    Url::ler(&format!("{origem}{caminho}")).unwrap_or_else(|_| unreachable!())
}

fn get(origem: &str, caminho: &str) -> Pedido {
    Pedido::novo(Metodo::Get, url(origem, caminho))
}

/// Conecta à `origem`, e diz por que não, se não.
fn conectar(origem: &str, opcoes: &Opcoes<'_>, codigo: i64) -> Result<ConexaoHttp, i64> {
    http::conectar(&url(origem, "/"), opcoes).map_err(|f| {
        escreverln!("correntes: {} nao conectou: {}", origem, f.codigo());
        codigo
    })
}

/// O que chegou, para dizer quando não confere.
fn dizer(onde: &str, r: &Result<Resposta, Falha>) {
    match r {
        Ok(r) => {
            escreverln!(
                "correntes: {} deu {} {:?} com {} bytes",
                onde,
                r.status,
                r.versao,
                r.corpo.len()
            );
        }
        Err(f) => {
            escreverln!(
                "correntes: {} falhou: {} {}",
                onde,
                f.categoria().nome(),
                f.codigo()
            );
        }
    }
}

/// O tempo desde o boot, em milissegundos. Zero, se o relógio não
/// respondeu.
fn agora_ms() -> u64 {
    programas::nativo::pedir("system.uptime", |_| Ok(()))
        .ok()
        .and_then(|r| r.resultado().ok()?.member("uptime_ms")?.as_u64())
        .unwrap_or(0)
}

/// A conexão clara fala HTTP/2, e a resposta diz que veio nele.
fn versao(opcoes: &Opcoes<'_>) -> Result<ConexaoHttp, i64> {
    let mut c = conectar(CLARA, opcoes, VERSAO)?;
    let r = c.trocar(&get(CLARA, "/ola"), &Limites::default());
    match &r {
        Ok(r)
            if c.versao() == Versao::Http2
                && r.versao == Versao::Http2
                && r.status == 200
                && r.corpo == b"ola, duke\n" => {}
        _ => {
            dizer("/ola", &r);
            return Err(VERSAO);
        }
    }
    escreverln!("correntes: h2c com conhecimento previo: 200 Http2");
    Ok(c)
}

/// Os tamanhos das correntes ao mesmo tempo: as duas últimas passam da
/// janela inicial de cada corrente.
const TAMANHOS: [usize; 8] = [1, 10, 100, 1_000, 10_000, 30_000, 70_000, 100_000];

/// Várias correntes ao mesmo tempo, com uma lenta no meio, recebidas de
/// trás para a frente.
fn correntes(c: &mut ConexaoHttp) -> Result<(), i64> {
    let comeco = agora_ms();
    let lenta = c
        .enviar(&get(CLARA, "/lento/300"), &Limites::default())
        .map_err(|f| {
            escreverln!("correntes: a lenta nao saiu: {}", f.codigo());
            CORRENTES
        })?;
    let mut abertas = Vec::new();
    for n in TAMANHOS {
        let corrente = c
            .enviar(&get(CLARA, &format!("/grande/{n}")), &Limites::default())
            .map_err(|f| {
                escreverln!("correntes: /grande/{} nao saiu: {}", n, f.codigo());
                CORRENTES
            })?;
        abertas.push((n, corrente));
    }
    if c.abertas() != TAMANHOS.len() + 1 {
        escreverln!("correntes: {} abertas", c.abertas());
        return Err(CORRENTES);
    }
    for (n, corrente) in abertas.into_iter().rev() {
        let r = c.receber(corrente);
        match &r {
            Ok(r) if r.status == 200 && r.corpo == http::padrao(n) => {}
            _ => {
                dizer(&format!("/grande/{n}"), &r);
                return Err(CORRENTES);
            }
        }
    }
    let rapidas = agora_ms().saturating_sub(comeco);
    let r = c.receber(lenta);
    match &r {
        Ok(r) if r.status == 200 && r.corpo == b"lento\n" => {}
        _ => {
            dizer("/lento/300", &r);
            return Err(CORRENTES);
        }
    }
    escreverln!(
        "correntes: {} ao mesmo tempo de 1 byte a 100 KiB em {} ms, e a lenta em {} ms",
        TAMANHOS.len(),
        rapidas,
        agora_ms().saturating_sub(comeco)
    );
    Ok(())
}

/// O corpo de um pedido de 200 KiB vai e volta, dentro das janelas do
/// servidor.
fn eco(c: &mut ConexaoHttp) -> Result<(), i64> {
    let mut p = Pedido::novo(Metodo::Post, url(CLARA, "/eco"));
    p.corpo = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
    let r = c.trocar(&p, &Limites::default());
    match &r {
        Ok(r) if r.status == 200 && r.corpo == p.corpo => {
            escreverln!("correntes: o eco de 200 KiB voltou inteiro");
            Ok(())
        }
        _ => {
            dizer("/eco", &r);
            Err(ECO)
        }
    }
}

/// O corpo comprimido e os cookies, pelas correntes.
fn conteudo(c: &mut ConexaoHttp) -> Result<(), i64> {
    let r = c.trocar(&get(CLARA, "/negocia/65536"), &Limites::default());
    match &r {
        Ok(r)
            if r.codificacao == Some(Codificacao::Gzip)
                && r.corpo == http::texto_da_bancada(65536) => {}
        _ => {
            dizer("/negocia/65536", &r);
            return Err(CONTEUDO);
        }
    }
    let mut pote = Pote::novo();
    let entrou = c.trocar_com_pote(
        &get(CLARA, "/cookies/entrar"),
        &Limites::default(),
        &mut pote,
    );
    if !matches!(&entrou, Ok(r) if r.cookies.novos == 1) {
        dizer("/cookies/entrar", &entrou);
        return Err(CONTEUDO);
    }
    let privado = c.trocar_com_pote(
        &get(CLARA, "/cookies/privado"),
        &Limites::default(),
        &mut pote,
    );
    match &privado {
        Ok(r) if r.status == 200 && r.corpo.starts_with(b"privado ") => {}
        _ => {
            dizer("/cookies/privado", &privado);
            return Err(CONTEUDO);
        }
    }
    escreverln!("correntes: gzip decodificado, e a sessao da bancada pelo pote");
    Ok(())
}

/// O corpo além do limite falha só a corrente dele.
fn limites(c: &mut ConexaoHttp) -> Result<(), i64> {
    let r = c.trocar(&get(CLARA, "/grande/2000000"), &Limites::default());
    if !matches!(&r, Err(f) if f.codigo() == "HTTP_TOO_LARGE") {
        dizer("/grande/2000000", &r);
        return Err(LIMITES);
    }
    let r = c.trocar(&get(CLARA, "/ola"), &Limites::default());
    if !matches!(&r, Ok(r) if r.corpo == b"ola, duke\n") || !c.pronta() {
        dizer("/ola depois do limite", &r);
        return Err(LIMITES);
    }
    escreverln!(
        "correntes: 2 MB passam do limite: HTTP_TOO_LARGE so na corrente, e a conexao segue"
    );
    Ok(())
}

/// O servidor que reinicia ou recusa uma corrente: só ela falha.
fn hostis_da_corrente(c: &mut ConexaoHttp) -> Result<(), i64> {
    for (rota, codigo) in [
        ("/h2/reinicia", "HTTP_STREAM_RESET"),
        ("/h2/recusa", "HTTP_STREAM_REFUSED"),
    ] {
        let r = c.trocar(&get(CLARA, rota), &Limites::default());
        if !matches!(&r, Err(f) if f.codigo() == codigo && f.categoria() == Categoria::Fechada) {
            dizer(rota, &r);
            return Err(HOSTIS);
        }
    }
    let r = c.trocar(&get(CLARA, "/ola"), &Limites::default());
    if !matches!(&r, Ok(r) if r.corpo == b"ola, duke\n") {
        dizer("/ola depois dos reinicios", &r);
        return Err(HOSTIS);
    }
    escreverln!(
        "correntes: reiniciada e recusada so na corrente: HTTP_STREAM_RESET HTTP_STREAM_REFUSED"
    );
    Ok(())
}

/// O servidor que quebra o protocolo: a conexão inteira acaba, e a outra
/// corrente que esperava ouve o mesmo código.
fn hostis_da_conexao(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let mut vistos = Vec::new();
    for (rota, codigo) in [
        ("/h2/empurra", "HTTP_MALFORMED"),
        ("/h2/hpack", "HTTP_MALFORMED"),
        ("/h2/enxurrada", "HTTP_TOO_MANY_FRAMES"),
        ("/h2/adeus", "HTTP_CONNECTION_ENDED"),
    ] {
        let mut c = conectar(CLARA, opcoes, HOSTIS)?;
        let outra = c
            .enviar(&get(CLARA, "/lento/2000"), &Limites::default())
            .map_err(|f| {
                escreverln!("correntes: a outra corrente nao saiu: {}", f.codigo());
                HOSTIS
            })?;
        let r = c.trocar(&get(CLARA, rota), &Limites::default());
        let da_outra = c.receber(outra);
        let seguinte = c.enviar(&get(CLARA, "/ola"), &Limites::default());
        let mesmo = |r: &Result<Resposta, Falha>| matches!(r, Err(f) if f.codigo() == codigo);
        if !mesmo(&r)
            || !mesmo(&da_outra)
            || !matches!(&seguinte, Err(f) if f.codigo() == "HTTP_CONNECTION_SPENT")
        {
            dizer(rota, &r);
            dizer("a outra corrente", &da_outra);
            return Err(HOSTIS);
        }
        c.fechar();
        vistos.push(codigo);
    }
    escreverln!(
        "correntes: a conexao acaba inteira, a outra corrente junto: {}",
        vistos.join(" ")
    );
    Ok(())
}

/// Pelo TLS, o ALPN: o HTTP/2 só, o HTTP/2 se o servidor quiser, e o
/// HTTP/1.1 sem oferecer nada. Pelo servidor que não fala HTTP/2, o HTTP/1.1
/// de reserva, e a recusa de quem exige o HTTP/2 — depois do aperto, pelo
/// programa: o destino é o mesmo, e o gate o deixou. E no claro, sem
/// conhecimento prévio, o HTTP/1.1.
fn alpn(ancoras: &tls::Ancoras) -> Result<(), i64> {
    // O que se viu em cada origem — numa linha que cabe num registro do log.
    let (mut cifrada, mut antiga, mut clara) = (Vec::new(), Vec::new(), Vec::new());
    for (origem, protocolo, esperada) in [
        (CIFRADA, Protocolo::Http2, Versao::Http2),
        (CIFRADA, Protocolo::Preferir2, Versao::Http2),
        (CIFRADA, Protocolo::Http1, Versao::Http11),
        (ANTIGA, Protocolo::Preferir2, Versao::Http11),
        (CLARA, Protocolo::Preferir2, Versao::Http11),
    ] {
        let mut c = conectar(origem, &opcoes(ancoras, protocolo), ALPN)?;
        let r = c.trocar(&get(origem, "/ola"), &Limites::default());
        match &r {
            Ok(r)
                if c.versao() == esperada && r.versao == esperada && r.corpo == b"ola, duke\n" => {}
            _ => {
                dizer(&format!("{origem}/ola com {protocolo:?}"), &r);
                return Err(ALPN);
            }
        }
        c.fechar();
        let visto = format!("{protocolo:?} {esperada:?}");
        if origem == CIFRADA {
            cifrada.push(visto);
        } else if origem == ANTIGA {
            antiga.push(visto);
        } else {
            clara.push(visto);
        }
    }
    match http::conectar(&url(ANTIGA, "/"), &opcoes(ancoras, Protocolo::Http2)) {
        Err(f) if f.codigo() == "HTTP_MALFORMED" && f.categoria() == Categoria::Protocolo => {
            antiga.push(format!("Http2 {}", f.codigo()));
        }
        Err(f) => {
            escreverln!("correntes: {} com Http2 falhou com {}", ANTIGA, f.codigo());
            return Err(ALPN);
        }
        Ok(c) => {
            escreverln!("correntes: {} com Http2 falou {:?}", ANTIGA, c.versao());
            return Err(ALPN);
        }
    }
    escreverln!(
        "correntes: o ALPN: {}; antigo: {}; claro: {}",
        cifrada.join(", "),
        antiga.join(", "),
        clara.join(", ")
    );
    Ok(())
}

/// Os pedidos de cada série da [`medida`].
const PEDIDOS: usize = 40;

/// Quanto o HTTP/2 muda: [`PEDIDOS`] pedidos de 1 KiB pelo HTTP/1.1 numa
/// conexão mantida, pelo HTTP/2 um de cada vez, e pelo HTTP/2 todos ao
/// mesmo tempo — tantos quantos a conexão guarda: quando ela diz
/// `HTTP_TOO_MANY_STREAMS`, o programa recebe a mais antiga antes de abrir
/// outra. É o teto da memória de uma conexão, e a contrapressão dela.
fn medida(ancoras: &tls::Ancoras) -> Result<(), i64> {
    let pedido = get(CLARA, "/grande/1024");
    let confere = |r: &Result<Resposta, Falha>| matches!(r, Ok(r) if r.corpo.len() == 1024);
    let mut tempos = Vec::new();
    for (rotulo, protocolo, juntos) in [
        ("http/1.1", Protocolo::Http1, false),
        ("h2 um a um", Protocolo::Http2, false),
        ("h2 juntos", Protocolo::Http2, true),
    ] {
        let mut c = conectar(CLARA, &opcoes(ancoras, protocolo), MEDIDA)?;
        let comeco = agora_ms();
        if juntos {
            let mut abertas = VecDeque::new();
            let mut mais = 0;
            let receber_a_mais_antiga = |c: &mut ConexaoHttp, abertas: &mut VecDeque<_>| {
                let r = abertas.pop_front().map(|corrente| c.receber(corrente));
                match r {
                    Some(r) if confere(&r) => Ok(()),
                    Some(r) => {
                        dizer(rotulo, &r);
                        Err(MEDIDA)
                    }
                    None => Err(MEDIDA),
                }
            };
            for _ in 0..PEDIDOS {
                loop {
                    match c.enviar(&pedido, &Limites::default()) {
                        Ok(corrente) => {
                            abertas.push_back(corrente);
                            break;
                        }
                        Err(f) if f.codigo() == "HTTP_TOO_MANY_STREAMS" && !abertas.is_empty() => {
                            mais = mais.max(abertas.len());
                            receber_a_mais_antiga(&mut c, &mut abertas)?;
                        }
                        Err(f) => {
                            escreverln!("correntes: {} nao saiu: {}", rotulo, f.codigo());
                            return Err(MEDIDA);
                        }
                    }
                }
            }
            while !abertas.is_empty() {
                receber_a_mais_antiga(&mut c, &mut abertas)?;
            }
            if mais == 0 {
                escreverln!(
                    "correntes: {} correntes abertas sem o teto da conexao",
                    PEDIDOS
                );
                return Err(MEDIDA);
            }
            escreverln!(
                "correntes: {} pedidos, no maximo {} guardados: HTTP_TOO_MANY_STREAMS, e a mais antiga recebida antes da seguinte",
                PEDIDOS,
                mais
            );
        } else {
            for _ in 0..PEDIDOS {
                let r = c.trocar(&pedido, &Limites::default());
                if !confere(&r) {
                    dizer(rotulo, &r);
                    return Err(MEDIDA);
                }
            }
        }
        tempos.push(format!("{rotulo} {}", agora_ms().saturating_sub(comeco)));
        c.fechar();
    }
    escreverln!(
        "correntes: medida {} pedidos de 1 KiB, em ms: {}",
        PEDIDOS,
        tempos.join(", ")
    );
    Ok(())
}

fn tudo(ancoras: &tls::Ancoras) -> Result<(), i64> {
    let h2 = opcoes(ancoras, Protocolo::Http2);
    let mut c = versao(&h2)?;
    correntes(&mut c)?;
    eco(&mut c)?;
    conteudo(&mut c)?;
    limites(&mut c)?;
    hostis_da_corrente(&mut c)?;
    let trocas = c.trocas();
    c.fechar();
    escreverln!("correntes: {} trocas numa conexao so", trocas);
    hostis_da_conexao(&h2)?;
    alpn(ancoras)?;
    medida(ancoras)?;

    // Fora do alcance: o gate recusa antes do primeiro byte, seja qual for o
    // HTTP. Por último, para a suíte achar o registro dela.
    let fora = "http://bancada.duke:81";
    match http::conectar(&url(fora, "/"), &h2) {
        Err(f) if f.codigo() == "DENY_RESOURCE" && f.categoria() == Categoria::Negado => {
            escreverln!("correntes: {} pelo HTTP/2 -> denied DENY_RESOURCE", fora);
            Ok(())
        }
        Err(f) => {
            escreverln!("correntes: {} falhou com {}", fora, f.codigo());
            Err(FORA)
        }
        Ok(_) => {
            escreverln!("correntes: {} conectou", fora);
            Err(FORA)
        }
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("correntes: as ancoras nao se leram: {}", f.codigo());
            return SEM_ANCORAS;
        }
    };
    match tudo(&ancoras) {
        Ok(()) => {
            escreverln!("correntes: tudo conferiu");
            CODIGO
        }
        Err(codigo) => codigo,
    }
}
