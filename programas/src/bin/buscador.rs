//! Uma conversa HTTP que a suíte interrompe no meio: o outro lado dos casos
//! `http:` que revogam, contêm, barram e encerram enquanto o programa tem
//! uma conexão aberta, ou um pedido esperando a resposta.
//!
//! O programa começa pela cadeia inteira: o nome `bancada.duke` pelo DNS
//! da bancada da suíte — a associação com `udp:10.0.2.53:53`, que o gate
//! decide —, a conexão com o endereço que ele deu, `tcp:10.0.2.100:80`,
//! que o gate decide como se o número tivesse sido digitado, e um `GET`.
//! Diz `buscador: no meio` e espera um evento no canal [`CANAL`] — ou, se
//! outro buscador já o escuta, diz `buscador: no meio pelo segundo canal`
//! e espera no [`SEGUNDO_CANAL`]: dois processos ao mesmo tempo, cada um
//! ditado pelo seu. A cada evento [`tipo::ACAO`], o `a` diz o passo:
//!
//! - [`TROCA`]: um `GET /conta` pela conexão que tem;
//! - [`NOVA`]: larga a conexão, resolve o nome de novo e conecta do zero —
//!   o DNS, o destino e o pedido, cada um pelo gate;
//! - [`LENTA`]: um `GET /lento/<b>` pela conexão que tem: o servidor só
//!   responde depois de `b` milissegundos, e o programa espera a resposta
//!   dormindo no kernel — é ali que a suíte revoga, contém, barra ou
//!   encerra a sessão;
//! - [`CIFRADA`]: uma conexão nova com `https://bancada.duke:8443`, pelo
//!   DNS, e um `GET /ola` — a cadeia DNS → TCP → TLS → HTTP;
//! - [`CIFRADA_LENTA`]: um `GET /lento/<b>` pela conexão cifrada;
//! - [`MUDO`]: um `GET /mudo` numa conexão nova, com um prazo curto;
//! - [`COMPRIMIDA_LENTA`]: um `GET /comprimido-lento/<b>` pela conexão que
//!   tem: 64 KiB de texto em gzip, e o servidor manda a metade, espera `b`
//!   milissegundos, e manda o resto — é no meio do corpo comprimido que a
//!   suíte revoga, contém ou barra;
//! - [`CIFRADA_COMPRIMIDA_LENTA`]: o mesmo pela conexão cifrada;
//! - [`NEGOCIADA`]: uma conexão nova, e um `GET /negocia/65536` que aceita
//!   o que `b` diz — o bit 1, `gzip`; o 2, `deflate` —: a suíte compara o
//!   que o gate decidiu com e sem compressão;
//! - [`COOKIE_ENTRAR`]: um `GET /cookies/entrar` pela conexão que tem,
//!   com o pote do programa: a bancada dá uma sessão (`HttpOnly`), e ela
//!   vai para o pote;
//! - [`COOKIE_PRIVADO`]: um `GET /cookies/privado` pela conexão que tem,
//!   com o pote: a bancada diz o id da sessão que reconheceu, ou 401 — é
//!   aqui que a suíte revoga, contém ou barra, com a sessão no pote;
//! - [`COOKIE_ECO`]: um `GET /cookies/eco` com o pote: os nomes dos
//!   cookies que a bancada recebeu — os valores não vão para o log;
//! - [`H2`]: uma conexão HTTP/2 nova — `b` 0, clara, com conhecimento
//!   prévio; 1, pelo TLS, com o ALPN —, pelo DNS, e um `GET /ola`;
//! - [`H2_LENTA`]: três correntes ao mesmo tempo pela conexão HTTP/2 que
//!   tem — `/ola`, `/h2/lento-meio/<b>` e `/lento/<b>` —: a primeira é
//!   recebida, o programa diz `buscador: h2 lenta: a primeira <status>`, e
//!   espera a segunda, cujo corpo pára na metade por `b` milissegundos — é
//!   ali que a suíte revoga, contém ou barra —, e depois a terceira;
//! - [`SAIR_SEM_FECHAR`]: sai sem fechar nada — o kernel recolhe as
//!   conexões de quem acabou.
//!
//! Depois de cada passo, diz `buscador: <passo>: <status> <corpo>` — ou,
//! nos comprimidos, `buscador: <passo>: <status> <codificação> <bytes>
//! <no fio> <confere>` —, ou `buscador: <passo>: <família> <código>` — o
//! código de quem falhou: a
//! recusa do gate, a contenção, o firewall, o DNS, o transporte, o prazo,
//! o TLS, o HTTP. Sai com [`CODIGO`] quando a suíte pede o fim.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "buscador",
    "net.connect",
    "random.read",
    "system.read",
    "fs.read"
);

use alloc::format;
use alloc::string::String;
use programas::conexao::Prazo;
use programas::escreverln;
use programas::http::{
    self, Aceitas, ConexaoHttp, Falha, Limites, Metodo, Opcoes, Pedido, Pote, Protocolo, Resolucao,
    Url,
};
use programas::sistema;
use programas::tls;
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 89;

/// O código de saída de [`SAIR_SEM_FECHAR`].
const SEM_FECHAR: i64 = 90;

/// O canal por onde a suíte dita o passo.
const CANAL: &str = "teste-buscador";

/// O canal de um segundo buscador, com o primeiro vivo.
const SEGUNDO_CANAL: &str = "teste-buscador-2";

/// Os passos — a suíte tem as mesmas constantes.
const TROCA: i64 = 1;
const NOVA: i64 = 2;
const LENTA: i64 = 3;
const CIFRADA: i64 = 4;
const CIFRADA_LENTA: i64 = 5;
const MUDO: i64 = 6;
const COMPRIMIDA_LENTA: i64 = 7;
const NEGOCIADA: i64 = 8;
const SAIR_SEM_FECHAR: i64 = 9;
const CIFRADA_COMPRIMIDA_LENTA: i64 = 10;
const COOKIE_ENTRAR: i64 = 11;
const COOKIE_PRIVADO: i64 = 12;
const COOKIE_ECO: i64 = 13;
const H2: i64 = 14;
const H2_LENTA: i64 = 15;

/// O DNS da bancada da suíte.
const DNS: &str = "udp:10.0.2.53:53";

/// A raiz da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// Diz o desfecho de um passo.
fn dizer(passo: &str, desfecho: Result<http::Resposta, Falha>) {
    match desfecho {
        Ok(r) => {
            escreverln!("buscador: {}: {} {}", passo, r.status, http::texto(&r));
        }
        Err(f) => {
            escreverln!(
                "buscador: {}: {} {}",
                passo,
                f.categoria().nome(),
                f.codigo()
            );
        }
    }
}

/// Diz o desfecho de um passo comprimido: a codificação, os bytes, os do
/// fio, e se o conteúdo é o texto de `n` bytes da bancada.
fn dizer_comprimida(passo: &str, n: usize, desfecho: Result<http::Resposta, Falha>) {
    match desfecho {
        Ok(r) => {
            let confere = r.corpo == http::texto_da_bancada(n);
            escreverln!(
                "buscador: {}: {} {} {} {} {}",
                passo,
                r.status,
                r.codificacao.map_or("identity", http::Codificacao::nome),
                r.corpo.len(),
                r.no_fio,
                if confere { "confere" } else { "diferente" }
            );
        }
        Err(f) => dizer(passo, Err(f)),
    }
}

/// Um `GET` de `caminho` pela conexão `conexao`, se há uma.
fn obter(
    conexao: &mut Option<ConexaoHttp>,
    base: &str,
    caminho: &str,
) -> Result<http::Resposta, Falha> {
    let url = Url::ler(&format!("{base}{caminho}")).map_err(Falha::Url)?;
    let Some(c) = conexao.as_mut() else {
        return Err(Falha::Http(http::Erro::Esgotada));
    };
    c.trocar(&Pedido::novo(Metodo::Get, url), &Limites::default())
}

/// Um `GET` de `caminho` pela conexão `conexao`, com `pote`.
fn obter_com_pote(
    conexao: &mut Option<ConexaoHttp>,
    base: &str,
    caminho: &str,
    pote: &mut Pote,
) -> Result<http::Resposta, Falha> {
    let url = Url::ler(&format!("{base}{caminho}")).map_err(Falha::Url)?;
    let Some(c) = conexao.as_mut() else {
        return Err(Falha::Http(http::Erro::Esgotada));
    };
    c.trocar_com_pote(&Pedido::novo(Metodo::Get, url), &Limites::default(), pote)
}

/// O corpo de `r` como texto, sem o fim de linha com que a bancada acaba
/// as respostas dela.
fn linha(r: &http::Resposta) -> String {
    let mut texto = http::texto(r);
    if r.corpo.ends_with(b"\n") {
        texto.pop();
    }
    texto
}

/// Diz o desfecho de um `/cookies/privado`: a sessão que a bancada
/// reconheceu, ou o 401.
fn dizer_privado(desfecho: Result<http::Resposta, Falha>) {
    match desfecho {
        Ok(r) => {
            escreverln!("buscador: cookie privado: {} {}", r.status, linha(&r));
        }
        Err(f) => dizer("cookie privado", Err(f)),
    }
}

/// Diz o desfecho de um `/cookies/eco`: só os nomes do que a bancada
/// recebeu.
fn dizer_eco(desfecho: Result<http::Resposta, Falha>) {
    match desfecho {
        Ok(r) => {
            let corpo = linha(&r);
            let nomes: alloc::vec::Vec<&str> = if corpo == "-" {
                alloc::vec::Vec::new()
            } else {
                corpo
                    .split("; ")
                    .map(|par| par.split('=').next().unwrap_or(""))
                    .collect()
            };
            let nomes = if nomes.is_empty() {
                String::from("nenhum")
            } else {
                nomes.join(",")
            };
            escreverln!("buscador: cookie eco: {} {}", r.status, nomes);
        }
        Err(f) => dizer("cookie eco", Err(f)),
    }
}

/// O desfecho curto de uma corrente: o status, ou a família e o código.
fn curto(desfecho: &Result<http::Resposta, Falha>) -> String {
    match desfecho {
        Ok(r) => format!("{}", r.status),
        Err(f) => format!("{} {}", f.categoria().nome(), f.codigo()),
    }
}

/// As três correntes de [`H2_LENTA`] pela conexão `h2`.
fn h2_lenta(h2: &mut Option<ConexaoHttp>, base: &str, ms: i64) {
    let Some(c) = h2.as_mut() else {
        dizer("h2 lenta", Err(Falha::Http(http::Erro::Esgotada)));
        return;
    };
    let pedido = |caminho: &str| -> Result<Pedido, Falha> {
        let url = Url::ler(&format!("{base}{caminho}")).map_err(Falha::Url)?;
        Ok(Pedido::novo(Metodo::Get, url))
    };
    let correntes = (|| -> Result<_, Falha> {
        let primeira = c.enviar(&pedido("/ola")?, &Limites::default())?;
        let no_meio = c.enviar(
            &pedido(&format!("/h2/lento-meio/{ms}"))?,
            &Limites::default(),
        )?;
        let lenta = c.enviar(&pedido(&format!("/lento/{ms}"))?, &Limites::default())?;
        Ok((primeira, no_meio, lenta))
    })();
    let (primeira, no_meio, lenta) = match correntes {
        Ok(c) => c,
        Err(f) => {
            dizer("h2 lenta", Err(f));
            return;
        }
    };
    let r = c.receber(primeira);
    escreverln!("buscador: h2 lenta: a primeira {}", curto(&r));
    let r = c.receber(no_meio);
    let no_meio = match &r {
        Ok(r) if r.corpo != http::texto_da_bancada(64 * 1024) => String::from("diferente"),
        _ => curto(&r),
    };
    let lenta = curto(&c.receber(lenta));
    escreverln!("buscador: h2 lenta: {} / {}", no_meio, lenta);
}

/// Uma conexão nova com `base`, pelo DNS.
fn conectar(base: &str, opcoes: &Opcoes<'_>) -> Result<ConexaoHttp, Falha> {
    let url = Url::ler(base).map_err(Falha::Url)?;
    http::conectar(&url, opcoes)
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let mut segundo = false;
    let mut canal = sistema::escutar(CANAL);
    if canal < 0 {
        segundo = true;
        canal = sistema::escutar(SEGUNDO_CANAL);
    }
    if canal < 0 {
        escreverln!("buscador: escutar devolveu {}", canal);
        return 1;
    }
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("buscador: as ancoras nao se leram: {}", f.codigo());
            return 2;
        }
    };
    let opcoes = Opcoes {
        resolucao: Resolucao::Dns(DNS),
        ancoras: Some(&ancoras),
        prazo: Prazo {
            espera_ms: 2_000,
            esperas: 3,
        },
        protocolo: Protocolo::Http1,
    };
    const CLARA: &str = "http://bancada.duke";
    const CIFRADA_URL: &str = "https://bancada.duke:8443";

    let mut clara = match conectar(CLARA, &opcoes) {
        Ok(c) => Some(c),
        Err(f) => {
            escreverln!(
                "buscador: o comeco falhou: {} {}",
                f.categoria().nome(),
                f.codigo()
            );
            return 3;
        }
    };
    match obter(&mut clara, CLARA, "/ola") {
        Ok(r) if r.status == 200 => {}
        outro => {
            dizer("comeco", outro);
            return 4;
        }
    }
    let mut cifrada: Option<ConexaoHttp> = None;
    // A conexão HTTP/2, clara ou cifrada: as correntes dela são deste
    // processo.
    let mut h2: Option<ConexaoHttp> = None;
    let mut h2_base = CLARA;
    // Os cookies deste processo: na memória dele, e de mais ninguém.
    let mut pote = Pote::novo();
    if segundo {
        escreverln!("buscador: no meio pelo segundo canal");
    } else {
        escreverln!("buscador: no meio");
    }

    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("buscador: a leitura do canal falhou: {}", e);
                return 5;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                escreverln!("buscador: encerrado");
                return CODIGO;
            }
            if e.tipo != tipo::ACAO {
                continue;
            }
            match e.a {
                TROCA => dizer("troca", obter(&mut clara, CLARA, "/conta")),
                NOVA => {
                    // A conexão de antes sai primeiro, e a nova não herda
                    // nada dela: o nome, o destino e o pedido, de novo.
                    drop(clara.take());
                    let desfecho = conectar(CLARA, &opcoes).and_then(|c| {
                        clara = Some(c);
                        obter(&mut clara, CLARA, "/conta")
                    });
                    dizer("nova", desfecho);
                }
                LENTA => {
                    let caminho: String = format!("/lento/{}", e.b);
                    dizer("lenta", obter(&mut clara, CLARA, &caminho));
                }
                CIFRADA => {
                    drop(cifrada.take());
                    let desfecho = conectar(CIFRADA_URL, &opcoes).and_then(|c| {
                        cifrada = Some(c);
                        obter(&mut cifrada, CIFRADA_URL, "/ola")
                    });
                    dizer("cifrada", desfecho);
                }
                CIFRADA_LENTA => {
                    let caminho: String = format!("/lento/{}", e.b);
                    dizer("cifrada lenta", obter(&mut cifrada, CIFRADA_URL, &caminho));
                }
                MUDO => {
                    let curto = Opcoes {
                        prazo: Prazo {
                            espera_ms: 500,
                            esperas: 2,
                        },
                        ..opcoes
                    };
                    let desfecho = conectar(CLARA, &curto).and_then(|c| {
                        let mut mudo = Some(c);
                        obter(&mut mudo, CLARA, "/mudo")
                    });
                    dizer("mudo", desfecho);
                }
                COMPRIMIDA_LENTA => {
                    let caminho: String = format!("/comprimido-lento/{}", e.b);
                    let desfecho = obter(&mut clara, CLARA, &caminho);
                    dizer_comprimida("comprimida lenta", 64 * 1024, desfecho);
                }
                CIFRADA_COMPRIMIDA_LENTA => {
                    let caminho: String = format!("/comprimido-lento/{}", e.b);
                    let desfecho = obter(&mut cifrada, CIFRADA_URL, &caminho);
                    dizer_comprimida("cifrada comprimida lenta", 64 * 1024, desfecho);
                }
                NEGOCIADA => {
                    let aceitas = Aceitas {
                        gzip: e.b & 1 != 0,
                        deflate: e.b & 2 != 0,
                    };
                    let desfecho = conectar(CLARA, &opcoes).and_then(|mut c| {
                        let url =
                            Url::ler(&format!("{CLARA}/negocia/65536")).map_err(Falha::Url)?;
                        let mut pedido = Pedido::novo(Metodo::Get, url);
                        pedido.aceitas = aceitas;
                        let r = c.trocar(&pedido, &Limites::default());
                        c.fechar();
                        r
                    });
                    dizer_comprimida("negociada", 65536, desfecho);
                }
                COOKIE_ENTRAR => {
                    match obter_com_pote(&mut clara, CLARA, "/cookies/entrar", &mut pote) {
                        Ok(r) => {
                            escreverln!(
                                "buscador: cookie entrar: {} {} novo(s), {} no pote",
                                r.status,
                                r.cookies.novos,
                                pote.quantos()
                            );
                        }
                        Err(f) => dizer("cookie entrar", Err(f)),
                    }
                }
                COOKIE_PRIVADO => dizer_privado(obter_com_pote(
                    &mut clara,
                    CLARA,
                    "/cookies/privado",
                    &mut pote,
                )),
                COOKIE_ECO => {
                    dizer_eco(obter_com_pote(&mut clara, CLARA, "/cookies/eco", &mut pote))
                }
                H2 => {
                    if let Some(c) = h2.take() {
                        c.fechar();
                    }
                    h2_base = if e.b == 1 { CIFRADA_URL } else { CLARA };
                    let so_h2 = Opcoes {
                        protocolo: Protocolo::Http2,
                        ..opcoes
                    };
                    let desfecho = conectar(h2_base, &so_h2).and_then(|c| {
                        h2 = Some(c);
                        obter(&mut h2, h2_base, "/ola")
                    });
                    match desfecho {
                        Ok(r) => {
                            escreverln!("buscador: h2: {} {:?} {}", r.status, r.versao, linha(&r));
                        }
                        Err(f) => dizer("h2", Err(f)),
                    }
                }
                H2_LENTA => h2_lenta(&mut h2, h2_base, e.b),
                SAIR_SEM_FECHAR => {
                    escreverln!("buscador: saindo sem fechar");
                    sistema::sair(SEM_FECHAR);
                }
                outro => {
                    escreverln!("buscador: passo desconhecido {}", outro);
                }
            }
        }
    }
}
