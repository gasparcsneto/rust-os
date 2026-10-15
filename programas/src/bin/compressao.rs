//! A compressão do HTTP de ponta a ponta, contra o servidor da bancada —
//! claro e atrás do TLS —, e o que ela **não** muda: o que o gate decide.
//!
//! O nome `bancada.duke` vai direto a `10.0.2.100`, sem DNS, como no
//! `pagina`. O corpo de cada página é o texto da bancada
//! ([`http::texto_da_bancada`]), que o servidor comprime e o programa gera
//! igual para conferir. Cada passo diz no log o que conferiu:
//!
//! - a bomba, primeiro, com o monte do processo ainda vazio: meio GiB de
//!   zeros em uns 500 KiB, parado no teto do corpo decodificado —
//!   `HTTP_TOO_LARGE` —, e quanto monte o processo mapeou; e o comprimido
//!   maior que o limite do corpo, recusado antes de ser lido;
//! - o texto em `gzip`, `x-gzip` e `deflate`, decodificado inteiro e igual,
//!   com o corpo no fio menor que ele: pelo tamanho, em pedaços, até o
//!   fecho, e cifrado;
//! - a negociação: o pedido diz o que aceita, o servidor escolhe — e diz
//!   qual em `X-Codificacao` —, e o cliente decodifica o que ele escolheu;
//! - três respostas comprimidas numa conexão só (*keep-alive*);
//! - a codificação que o pedido não aceitou, uma desconhecida, duas
//!   empilhadas: `HTTP_UNACCEPTED_ENCODING`;
//! - o comprimido estragado — a soma, o tamanho, os dados, a cabeça, o
//!   DEFLATE cru como `deflate`, bytes a mais, cortado pelo tamanho e pelo
//!   fecho: `HTTP_CORRUPT_CONTENT`. O corpo vazio é o conteúdo vazio;
//! - o teto é de quem pede: 4,5 MiB de texto não passam no padrão, e
//!   passam com um teto maior;
//! - a medida: 1 MiB de texto como é e em gzip, claro e cifrado — os bytes
//!   no fio e o tempo;
//! - fora do alcance, a recusa é do gate, `DENY_RESOURCE`, antes do
//!   primeiro byte — a compressão não entra nisso.
//!
//! Cada falha sai com o código de quem falhou e a família dele. Sai com
//! [`CODIGO`] quando tudo confere, e com um código menor que diz o quê,
//! quando não.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "compressao",
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
    self, Aceitas, Categoria, Codificacao, Falha, Limites, Metodo, Opcoes, Pedido, Protocolo,
    Resolucao, Resposta, Url,
};
use programas::monte;
use programas::nativo;
use programas::tls;

/// Tudo conferiu. A suíte e a fumaça o procuram.
const CODIGO: i64 = 98;
/// As âncoras não se leram.
const SEM_ANCORAS: i64 = 30;
/// A bomba não parou no teto, ou custou monte demais.
const BOMBA: i64 = 31;
/// Uma página comprimida não chegou, ou chegou diferente.
const COMPRIMIDA: i64 = 32;
/// O servidor não escolheu o que o pedido aceitou, ou o cliente não
/// decodificou o que ele escolheu.
const NEGOCIACAO: i64 = 33;
/// As três respostas comprimidas não vieram numa conexão só.
const MANTIDA: i64 = 34;
/// Um corpo que não se decodifica não deu a falha certa.
const FALHA: i64 = 35;
/// O teto de quem pede não valeu.
const TETO: i64 = 36;
/// O destino fora do alcance não foi recusado pelo gate.
const FORA: i64 = 37;
/// A medida não se fez.
const MEDIDA: i64 = 38;

/// A raiz da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// O servidor HTTP da bancada, sem DNS.
const BANCADA: [u8; 4] = [10, 0, 2, 100];

const CLARA: &str = "http://bancada.duke";
const CIFRADA: &str = "https://bancada.duke:8443";

/// O monte que a bomba pode custar: a saída dobra até o teto de 4 MiB, e
/// os pedaços que ficam para trás não voltam ao kernel — o monte de um
/// programa não devolve páginas —, mais o corpo de meio MiB e as tabelas.
const MONTE_DA_BOMBA: u64 = 12 * 1024 * 1024;

/// O tempo desde o boot, em milissegundos. Zero, se o relógio não
/// respondeu.
fn agora_ms() -> u64 {
    nativo::pedir("system.uptime", |_| Ok(()))
        .ok()
        .and_then(|r| r.resultado().ok()?.member("uptime_ms")?.as_u64())
        .unwrap_or(0)
}

/// Um `GET` de `url` que aceita `aceitas`, numa conexão só.
fn obter(
    url: &str,
    aceitas: Aceitas,
    opcoes: &Opcoes<'_>,
    limites: &Limites,
) -> Result<Resposta, Falha> {
    let url = Url::ler(url).map_err(Falha::Url)?;
    let mut pedido = Pedido::novo(Metodo::Get, url);
    pedido.aceitas = aceitas;
    http::buscar(pedido, opcoes, limites)
}

/// O nome de uma codificação, ou `identity`.
fn nome(c: Option<Codificacao>) -> &'static str {
    c.map_or("identity", Codificacao::nome)
}

/// O que chegou de `url`, para dizer quando não confere.
fn dizer(url: &str, r: &Resultado) {
    match r {
        Ok(r) => {
            escreverln!(
                "compressao: {} deu {} em {} com {} bytes ({} no fio)",
                url,
                r.status,
                nome(r.codificacao),
                r.corpo.len(),
                r.no_fio
            );
        }
        Err(f) => {
            escreverln!(
                "compressao: {} falhou: {} {}",
                url,
                f.categoria().nome(),
                f.codigo()
            );
        }
    }
}

type Resultado = Result<Resposta, Falha>;

/// `caminho` de `base` chega em `codificacao`, menor no fio, e decodificado
/// igual aos `n` bytes do texto da bancada.
fn comprimida(
    base: &str,
    caminho: &str,
    n: usize,
    codificacao: Codificacao,
    opcoes: &Opcoes<'_>,
) -> Result<(), i64> {
    let url = format!("{base}{caminho}");
    let r = obter(&url, Aceitas::TODAS, opcoes, &Limites::default());
    match &r {
        Ok(r)
            if r.status == 200
                && r.codificacao == Some(codificacao)
                && r.no_fio < n
                && r.corpo == http::texto_da_bancada(n) =>
        {
            escreverln!(
                "compressao: {} -> {}: {} bytes de {} no fio",
                url,
                codificacao.nome(),
                r.corpo.len(),
                r.no_fio
            );
            Ok(())
        }
        _ => {
            dizer(&url, &r);
            Err(COMPRIMIDA)
        }
    }
}

/// `/negocia` com `aceitas`: o servidor escolhe `esperada`, diz qual, e o
/// cliente a decodifica.
fn negociada(
    base: &str,
    aceitas: Aceitas,
    esperada: Option<Codificacao>,
    opcoes: &Opcoes<'_>,
) -> Result<(), i64> {
    const N: usize = 65536;
    let url = format!("{base}/negocia/{N}");
    let r = obter(&url, aceitas, opcoes, &Limites::default());
    match &r {
        Ok(r)
            if r.status == 200
                && r.cabecalho("x-codificacao") == Some(nome(esperada))
                && r.codificacao == esperada
                && r.corpo == http::texto_da_bancada(N) =>
        {
            escreverln!(
                "compressao: {} aceitando gzip={} deflate={} -> {} ({} bytes no fio)",
                url,
                aceitas.gzip,
                aceitas.deflate,
                nome(esperada),
                r.no_fio
            );
            Ok(())
        }
        _ => {
            dizer(&url, &r);
            Err(NEGOCIACAO)
        }
    }
}

/// `url` falha com `codigo`, da família `categoria`: diz o porquê, e
/// confere que a família é a do código — nenhuma vira outra.
fn falha(
    url: &str,
    aceitas: Aceitas,
    opcoes: &Opcoes<'_>,
    limites: &Limites,
    categoria: Categoria,
    codigo: &str,
    erro: i64,
) -> Result<(), i64> {
    let r = obter(url, aceitas, opcoes, limites);
    match &r {
        Err(f) if f.codigo() == codigo && f.categoria() == categoria => {
            escreverln!("compressao: {} -> {} {}", url, categoria.nome(), codigo);
            Ok(())
        }
        _ => {
            dizer(url, &r);
            Err(erro)
        }
    }
}

/// A bomba, com o monte do processo ainda no começo.
fn bomba(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let antes = monte::mapeados();
    falha(
        &format!("{CLARA}/bomba/gzip/512"),
        Aceitas::TODAS,
        opcoes,
        &Limites::default(),
        Categoria::Limite,
        "HTTP_TOO_LARGE",
        BOMBA,
    )?;
    let depois = monte::mapeados();
    escreverln!(
        "compressao: a bomba de 512 MiB parou no teto de 4 MiB; o monte foi de {} a {} KiB",
        antes / 1024,
        depois / 1024
    );
    if depois > MONTE_DA_BOMBA {
        return Err(BOMBA);
    }
    // Maior que o limite do corpo — o texto de 6 MiB em gzip passa de 1 MiB
    // no fio —: recusado pelo tamanho anunciado, antes de ler.
    falha(
        &format!("{CLARA}/comprimido/gzip/6291456"),
        Aceitas::TODAS,
        opcoes,
        &Limites::default(),
        Categoria::Limite,
        "HTTP_TOO_LARGE",
        BOMBA,
    )
}

/// Três respostas comprimidas numa conexão só.
fn mantida(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let url = Url::ler(CLARA).map_err(|_| MANTIDA)?;
    let mut conexao = http::conectar(&url, opcoes).map_err(|f| {
        escreverln!("compressao: a conexao mantida nao abriu: {}", f.codigo());
        MANTIDA
    })?;
    for (caminho, n) in [
        ("/comprimido/gzip/4096", 4096),
        ("/comprimido/deflate/8192", 8192),
        ("/negocia/16384", 16384),
    ] {
        let url = Url::ler(&format!("{CLARA}{caminho}")).map_err(|_| MANTIDA)?;
        let r = conexao.trocar(&Pedido::novo(Metodo::Get, url), &Limites::default());
        match &r {
            Ok(r) if r.codificacao.is_some() && r.corpo == http::texto_da_bancada(n) => {}
            _ => {
                dizer(caminho, &r);
                return Err(MANTIDA);
            }
        }
    }
    let trocas = conexao.trocas();
    let pronta = conexao.pronta();
    conexao.fechar();
    if trocas != 3 || !pronta {
        escreverln!("compressao: a conexao mantida fez {} trocas", trocas);
        return Err(MANTIDA);
    }
    escreverln!("compressao: tres respostas comprimidas numa conexao so");
    Ok(())
}

/// O teto do corpo decodificado é de quem pede.
fn teto(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    const N: usize = 4608 * 1024;
    let url = format!("{CLARA}/comprimido/gzip/{N}");
    falha(
        &url,
        Aceitas::TODAS,
        opcoes,
        &Limites::default(),
        Categoria::Limite,
        "HTTP_TOO_LARGE",
        TETO,
    )?;
    let maior = Limites {
        descomprimido: 8 * 1024 * 1024,
        ..Limites::default()
    };
    let r = obter(&url, Aceitas::TODAS, opcoes, &maior);
    match &r {
        Ok(r) if r.corpo == http::texto_da_bancada(N) => {
            escreverln!(
                "compressao: {} com um teto de 8 MiB: {} bytes de {} no fio",
                url,
                r.corpo.len(),
                r.no_fio
            );
            Ok(())
        }
        _ => {
            dizer(&url, &r);
            Err(TETO)
        }
    }
}

/// 1 MiB de texto como é e em gzip: os bytes no fio e o tempo.
fn medida(base: &str, opcoes: &Opcoes<'_>) -> Result<(), i64> {
    const N: usize = 1024 * 1024;
    let url = format!("{base}/negocia/{N}");
    let texto = http::texto_da_bancada(N);
    for (rotulo, aceitas) in [("como e", Aceitas::NENHUMA), ("gzip", Aceitas::TODAS)] {
        let mut tempos = String::new();
        let mut no_fio = 0;
        for _ in 0..3 {
            let comeco = agora_ms();
            let r = obter(&url, aceitas, opcoes, &Limites::default());
            let ms = agora_ms().saturating_sub(comeco);
            match &r {
                Ok(r) if r.corpo == texto => no_fio = r.no_fio,
                _ => {
                    dizer(&url, &r);
                    return Err(MEDIDA);
                }
            }
            tempos.push_str(&format!(" {ms}"));
        }
        escreverln!(
            "compressao: medida {} {}: {} bytes no fio por MiB, em ms:{}",
            base,
            rotulo,
            no_fio,
            tempos
        );
    }
    Ok(())
}

fn tudo(ancoras: &tls::Ancoras) -> Result<(), i64> {
    let opcoes = Opcoes {
        resolucao: Resolucao::Fixa(BANCADA),
        ancoras: Some(ancoras),
        prazo: Prazo {
            espera_ms: 5_000,
            esperas: 4,
        },
        protocolo: Protocolo::Http1,
    };
    let padrao = Limites::default();
    bomba(&opcoes)?;

    // As páginas comprimidas: pelo tamanho, em pedaços, até o fecho, e
    // cifradas.
    for (caminho, n, c) in [
        ("/comprimido/gzip/65536", 65536, Codificacao::Gzip),
        ("/comprimido/x-gzip/65536", 65536, Codificacao::Gzip),
        ("/comprimido/deflate/65536", 65536, Codificacao::Deflate),
        ("/comprimido-pedacos/gzip/65536", 65536, Codificacao::Gzip),
        (
            "/comprimido-pedacos/deflate/32768",
            32768,
            Codificacao::Deflate,
        ),
        (
            "/comprimido-ate-fechar/gzip/65536",
            65536,
            Codificacao::Gzip,
        ),
        ("/comprimido/gzip/1048576", 1_048_576, Codificacao::Gzip),
    ] {
        comprimida(CLARA, caminho, n, c, &opcoes)?;
    }
    comprimida(
        CIFRADA,
        "/comprimido/gzip/65536",
        65536,
        Codificacao::Gzip,
        &opcoes,
    )?;
    comprimida(
        CIFRADA,
        "/comprimido-pedacos/deflate/65536",
        65536,
        Codificacao::Deflate,
        &opcoes,
    )?;

    // A negociação.
    let so_gzip = Aceitas {
        gzip: true,
        deflate: false,
    };
    let so_deflate = Aceitas {
        gzip: false,
        deflate: true,
    };
    for (base, aceitas, esperada) in [
        (CLARA, Aceitas::TODAS, Some(Codificacao::Gzip)),
        (CLARA, so_gzip, Some(Codificacao::Gzip)),
        (CLARA, so_deflate, Some(Codificacao::Deflate)),
        (CLARA, Aceitas::NENHUMA, None),
        (CIFRADA, so_deflate, Some(Codificacao::Deflate)),
        (CIFRADA, Aceitas::NENHUMA, None),
    ] {
        negociada(base, aceitas, esperada, &opcoes)?;
    }
    mantida(&opcoes)?;

    // A codificação que o pedido não aceitou, a desconhecida e as
    // empilhadas.
    for (caminho, aceitas) in [
        ("/comprimido/gzip/1000", Aceitas::NENHUMA),
        ("/comprimido/deflate/1000", so_gzip),
        ("/estragado/desconhecida", Aceitas::TODAS),
        ("/estragado/empilhada", Aceitas::TODAS),
    ] {
        falha(
            &format!("{CLARA}{caminho}"),
            aceitas,
            &opcoes,
            &padrao,
            Categoria::Protocolo,
            "HTTP_UNACCEPTED_ENCODING",
            FALHA,
        )?;
    }
    // O comprimido estragado: claro, e um cifrado.
    for tipo in [
        "crc",
        "isize",
        "adler",
        "dados",
        "cabeca",
        "cru",
        "sobra",
        "cortado",
        "cortado-fecho",
    ] {
        falha(
            &format!("{CLARA}/estragado/{tipo}"),
            Aceitas::TODAS,
            &opcoes,
            &padrao,
            Categoria::Protocolo,
            "HTTP_CORRUPT_CONTENT",
            FALHA,
        )?;
    }
    falha(
        &format!("{CIFRADA}/estragado/crc"),
        Aceitas::TODAS,
        &opcoes,
        &padrao,
        Categoria::Protocolo,
        "HTTP_CORRUPT_CONTENT",
        FALHA,
    )?;
    // O corpo vazio é o conteúdo vazio.
    let url = format!("{CLARA}/estragado/vazio");
    let r = obter(&url, Aceitas::TODAS, &opcoes, &padrao);
    match &r {
        Ok(r) if r.corpo.is_empty() && r.codificacao == Some(Codificacao::Gzip) => {
            escreverln!("compressao: {} -> o conteudo vazio", url);
        }
        _ => {
            dizer(&url, &r);
            return Err(FALHA);
        }
    }
    teto(&opcoes)?;
    medida(CLARA, &opcoes)?;
    medida(CIFRADA, &opcoes)?;

    // Fora do alcance: o gate recusa antes do primeiro byte, comprima o
    // servidor ou não. Por último, para a suíte achar o registro dela.
    falha(
        "http://bancada.duke:81/comprimido/gzip/1000",
        Aceitas::TODAS,
        &opcoes,
        &padrao,
        Categoria::Negado,
        "DENY_RESOURCE",
        FORA,
    )?;
    escreverln!(
        "compressao: o monte mapeado no fim: {} KiB",
        monte::mapeados() / 1024
    );
    Ok(())
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("compressao: as ancoras nao se leram: {}", f.codigo());
            return SEM_ANCORAS;
        }
    };
    match tudo(&ancoras) {
        Ok(()) => {
            escreverln!("compressao: tudo conferiu");
            CODIGO
        }
        Err(codigo) => codigo,
    }
}
