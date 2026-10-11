//! Busca páginas no servidor HTTP da bancada — claro e atrás do TLS — e
//! confere de dentro o que o HTTP do Duke promete, e o que ele **não** faz:
//! dar acesso.
//!
//! O nome `bancada.duke` vai direto a `10.0.2.100`, sem DNS: a fumaça roda
//! sem o DNS da bancada da suíte, e o DNS do emulador repassa a pergunta à
//! rede de quem roda. A cadeia inteira, com o DNS no começo, é a do
//! `buscador`, na suíte.
//!
//! - `http://bancada.duke/ola`: o gate decide `tcp:10.0.2.100:80`, e a
//!   resposta chega inteira, pelo tamanho;
//! - três pedidos numa conexão só (*keep-alive*): um `net.connect`, e cada
//!   envio e cada leitura decididos de novo;
//! - o corpo em pedaços (`chunked`), com extensão e *trailer*;
//! - 64 KiB num `POST`, ida e volta: mais que o buffer da conexão, e o
//!   `net.send` espera espaço em vez de girar;
//! - um `404` é uma resposta, e não uma falha; um `302` volta com o
//!   `Location`, e o programa não o segue sozinho;
//! - o corpo até o fecho, que não deixa a conexão para outro pedido;
//! - `https://bancada.duke:8443/ola`: o TLS prova o nome pela âncora da
//!   imagem, e o HTTP vai cifrado;
//! - no **mesmo** destino, `outro.duke`: o gate deixou a conexão — o
//!   destino está no alcance —, e o TLS recusa o nome, `TLS_NAME_MISMATCH`.
//!   O nome não é recurso da política, e o certificado não autoriza nada;
//! - `http://bancada.duke:81/`: fora do alcance, a recusa é do gate,
//!   `DENY_RESOURCE`, antes do primeiro byte;
//! - as respostas malformadas — LF sozinho, cabeçalho dobrado, tamanhos
//!   ambíguos, linha de status, pedaço, versão — são `HTTP_MALFORMED`; o
//!   corpo grande demais é `HTTP_TOO_LARGE`, sem ler o resto; a resposta
//!   cortada é `HTTP_CLOSED`; o servidor mudo é `NETWORK_TIMEOUT`.
//!
//! Cada falha sai com o código de quem falhou e a família dele, e nenhuma
//! se confunde com outra. Sai com [`CODIGO`] quando tudo confere, e com um
//! código menor que diz o quê, quando não.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "pagina",
    "net.connect",
    "random.read",
    "system.read",
    "fs.read"
);

use alloc::string::String;
use alloc::vec::Vec;
use programas::conexao::{self, Prazo};
use programas::escreverln;
use programas::http::{
    self, Categoria, Falha, Limites, Metodo, Opcoes, Pedido, Resolucao, Resposta, Url,
};
use programas::nativo;
use programas::tls;

/// Tudo conferiu. A suíte e a fumaça o procuram.
const CODIGO: i64 = 88;
/// As âncoras não se leram.
const SEM_ANCORAS: i64 = 40;
/// Uma página que devia chegar não chegou, ou chegou diferente.
const PAGINA: i64 = 41;
/// O *keep-alive* não levou os três pedidos numa conexão só.
const MANTIDA: i64 = 42;
/// O `POST` grande não voltou igual.
const ECO: i64 = 43;
/// Um status que não é 2xx virou falha, ou o 3xx foi seguido.
const STATUS: i64 = 44;
/// O TLS não fechou com `bancada.duke`.
const CIFRADA: i64 = 45;
/// Um nome que o servidor não prova foi aceito, ou recusado pelo motivo
/// errado.
const NOME: i64 = 46;
/// O destino fora do alcance não foi recusado pelo gate.
const FORA: i64 = 47;
/// Uma resposta malformada, grande, cortada ou muda não deu a falha
/// certa.
const FALHA: i64 = 48;

/// A raiz da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// O servidor HTTP da bancada, sem DNS.
const BANCADA: [u8; 4] = [10, 0, 2, 100];

/// O tempo desde o boot, em milissegundos. Zero, se o relógio não
/// respondeu.
fn agora_ms() -> u64 {
    nativo::pedir("system.uptime", |_| Ok(()))
        .ok()
        .and_then(|r| r.resultado().ok()?.member("uptime_ms")?.as_u64())
        .unwrap_or(0)
}

/// Um `GET` de `url`, numa conexão só.
fn obter(url: &str, opcoes: &Opcoes<'_>, limites: &Limites) -> Result<Resposta, Falha> {
    http::obter(url, opcoes, limites)
}

/// `url` responde `status` com `corpo`.
fn pagina(url: &str, opcoes: &Opcoes<'_>, status: u16, corpo: &[u8]) -> Result<(), i64> {
    let comeco = agora_ms();
    match obter(url, opcoes, &Limites::default()) {
        Ok(r) if r.status == status && r.corpo == corpo => {
            escreverln!(
                "pagina: {} -> {} ({} bytes) em {} ms",
                url,
                r.status,
                r.corpo.len(),
                agora_ms().saturating_sub(comeco)
            );
            Ok(())
        }
        Ok(r) => {
            escreverln!("pagina: {} deu {} com {:?}", url, r.status, http::texto(&r));
            Err(PAGINA)
        }
        Err(f) => {
            escreverln!(
                "pagina: {} falhou: {} {}",
                url,
                f.categoria().nome(),
                f.codigo()
            );
            Err(PAGINA)
        }
    }
}

/// `url` falha com `codigo`, da família `categoria`: diz o porquê, e
/// confere que a família é a do código — nenhuma vira outra.
fn falha(
    url: &str,
    opcoes: &Opcoes<'_>,
    limites: &Limites,
    categoria: Categoria,
    codigo: &str,
    erro: i64,
) -> Result<(), i64> {
    let comeco = agora_ms();
    match obter(url, opcoes, limites) {
        Err(f) if f.codigo() == codigo && f.categoria() == categoria => {
            escreverln!(
                "pagina: {} -> {} {} em {} ms",
                url,
                categoria.nome(),
                codigo,
                agora_ms().saturating_sub(comeco)
            );
            Ok(())
        }
        Err(f) => {
            escreverln!(
                "pagina: {} deu {} {}, e nao {} {}",
                url,
                f.categoria().nome(),
                f.codigo(),
                categoria.nome(),
                codigo
            );
            Err(erro)
        }
        Ok(r) => {
            escreverln!("pagina: {} deu {}, e nao {}", url, r.status, codigo);
            Err(erro)
        }
    }
}

/// Três pedidos numa conexão só, cada um com o número dele na conexão.
fn mantida(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let url = Url::ler("http://bancada.duke/conta").map_err(|_| MANTIDA)?;
    let mut conexao = http::conectar(&url, opcoes).map_err(|f| {
        escreverln!("pagina: a conexao mantida falhou: {}", f.codigo());
        MANTIDA
    })?;
    let numero = conexao.numero();
    let mut corpos = Vec::new();
    for i in 0..3 {
        let mut pedido = Pedido::novo(Metodo::Get, url.clone());
        pedido.fechar = i == 2;
        match conexao.trocar(&pedido, &Limites::default()) {
            Ok(r) if r.status == 200 => corpos.push(http::texto(&r)),
            Ok(r) => {
                escreverln!("pagina: o pedido {} da conexao deu {}", i + 1, r.status);
                return Err(MANTIDA);
            }
            Err(f) => {
                escreverln!(
                    "pagina: o pedido {} da conexao falhou: {}",
                    i + 1,
                    f.codigo()
                );
                return Err(MANTIDA);
            }
        }
    }
    // A última pediu para fechar: a conexão não leva mais nada.
    let depois = conexao.trocar(&Pedido::novo(Metodo::Get, url), &Limites::default());
    if corpos != ["1", "2", "3"]
        || conexao.trocas() != 3
        || conexao.numero() != numero
        || conexao.pronta()
        || depois.map_err(|f| f.codigo() == "HTTP_CONNECTION_SPENT") != Err(true)
    {
        escreverln!("pagina: a conexao mantida deu {:?}", corpos);
        return Err(MANTIDA);
    }
    conexao.fechar();
    escreverln!(
        "pagina: tres pedidos numa conexao so (keep-alive), {} {} {}, e a quarta recusada depois do close",
        corpos[0],
        corpos[1],
        corpos[2]
    );
    Ok(())
}

/// 64 KiB num `POST`, ida e volta.
fn eco(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let url = Url::ler("http://bancada.duke/eco").map_err(|_| ECO)?;
    let mut pedido = Pedido::novo(Metodo::Post, url);
    pedido.corpo = http::padrao(64 * 1024);
    let comeco = agora_ms();
    match http::buscar(pedido.clone(), opcoes, &Limites::default()) {
        Ok(r) if r.status == 200 && r.corpo == pedido.corpo => {
            escreverln!(
                "pagina: {} bytes foram e voltaram (POST) em {} ms",
                r.corpo.len(),
                agora_ms().saturating_sub(comeco)
            );
            Ok(())
        }
        Ok(r) => {
            escreverln!(
                "pagina: o eco voltou {} com {} bytes",
                r.status,
                r.corpo.len()
            );
            Err(ECO)
        }
        Err(f) => {
            escreverln!("pagina: o eco falhou: {}", f.codigo());
            Err(ECO)
        }
    }
}

/// Um status que não é 2xx é resposta; o 3xx não é seguido.
fn status(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    match obter(
        "http://bancada.duke/status/404",
        opcoes,
        &Limites::default(),
    ) {
        Ok(r) if r.status == 404 => {}
        outro => {
            escreverln!("pagina: o 404 deu {:?}", outro.map(|r| r.status));
            return Err(STATUS);
        }
    }
    match obter(
        "http://bancada.duke/redireciona",
        opcoes,
        &Limites::default(),
    ) {
        Ok(r) if r.status == 302 && r.cabecalho("location") == Some("http://bancada.duke/ola") => {}
        outro => {
            escreverln!("pagina: o 302 deu {:?}", outro.map(|r| r.status));
            return Err(STATUS);
        }
    }
    escreverln!("pagina: 404 e uma resposta, e 302 volta com o Location, sem ser seguido");
    Ok(())
}

/// O corpo até o fecho: chega inteiro, e não deixa a conexão.
fn ate_fechar(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    match obter(
        "http://bancada.duke/ate-fechar",
        opcoes,
        &Limites::default(),
    ) {
        Ok(r) if r.status == 200 && r.corpo == b"ate o fecho\n" && !r.reutilizavel => {
            escreverln!("pagina: o corpo ate o fecho chegou inteiro, e a conexao nao ficou");
            Ok(())
        }
        outro => {
            escreverln!(
                "pagina: o corpo ate o fecho deu {:?}",
                outro.map(|r| r.status)
            );
            Err(PAGINA)
        }
    }
}

/// `https://bancada.duke:8443/ola`, com a medida do aperto e do pedido.
fn cifrada(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let url = Url::ler("https://bancada.duke:8443/ola").map_err(|_| CIFRADA)?;
    let comeco = agora_ms();
    let mut conexao = http::conectar(&url, opcoes).map_err(|f| {
        escreverln!(
            "pagina: o https falhou: {} {}",
            f.categoria().nome(),
            f.codigo()
        );
        CIFRADA
    })?;
    let aperto = agora_ms().saturating_sub(comeco);
    let suite = conexao.suite().unwrap_or("?");
    let mut pedido = Pedido::novo(Metodo::Get, url);
    pedido.fechar = true;
    let r = conexao.trocar(&pedido, &Limites::default());
    conexao.fechar();
    match r {
        Ok(r) if r.status == 200 && r.corpo == b"ola, duke\n" => {
            escreverln!(
                "pagina: https://bancada.duke:8443/ola -> 200 ({}) em {} ms, o aperto em {} ms",
                suite,
                agora_ms().saturating_sub(comeco),
                aperto
            );
            Ok(())
        }
        Ok(r) => {
            escreverln!("pagina: o https deu {}", r.status);
            Err(CIFRADA)
        }
        Err(f) => {
            escreverln!("pagina: o pedido cifrado falhou: {}", f.codigo());
            Err(CIFRADA)
        }
    }
}

/// O que a bancada mede: o corpo grande, claro e cifrado.
fn vazao(opcoes: &Opcoes<'_>, url: &str) -> Result<(), i64> {
    let comeco = agora_ms();
    match obter(url, opcoes, &Limites::default()) {
        Ok(r) if r.status == 200 && r.corpo == http::padrao(r.corpo.len()) => {
            let ms = agora_ms().saturating_sub(comeco).max(1);
            escreverln!(
                "pagina: {} -> {} bytes em {} ms ({} KiB/s)",
                url,
                r.corpo.len(),
                ms,
                r.corpo.len() as u64 * 1000 / 1024 / ms
            );
            Ok(())
        }
        outro => {
            escreverln!("pagina: {} deu {:?}", url, outro.map(|r| r.status));
            Err(PAGINA)
        }
    }
}

/// A linha de base do custo do HTTP: os mesmos 64 KiB do `POST`, de ida e
/// volta pelo eco TCP da bancada, sem HTTP nenhum — a mesma conexão do
/// gate, o mesmo transporte.
fn eco_cru() -> Result<(), i64> {
    let dados = http::padrao(64 * 1024);
    let comeco = agora_ms();
    let mut conexao = conexao::abrir("tcp:10.0.2.100:7", Prazo::PADRAO).map_err(|f| {
        escreverln!("pagina: o eco TCP falhou: {}", f.codigo());
        ECO
    })?;
    conexao.mandar(&dados).map_err(|f| {
        escreverln!("pagina: o eco TCP nao mandou: {}", f.codigo());
        ECO
    })?;
    let mut voltou = Vec::with_capacity(dados.len());
    let mut buf = alloc::vec![0u8; 4096];
    while voltou.len() < dados.len() {
        match conexao.receber(&mut buf) {
            Ok(0) | Err(_) => {
                escreverln!("pagina: o eco TCP voltou {} bytes", voltou.len());
                return Err(ECO);
            }
            Ok(n) => voltou.extend_from_slice(&buf[..n]),
        }
    }
    if voltou != dados {
        return Err(ECO);
    }
    escreverln!(
        "pagina: eco TCP cru: {} bytes foram e voltaram em {} ms",
        dados.len(),
        agora_ms().saturating_sub(comeco)
    );
    Ok(())
}

fn tudo(ancoras: &tls::Ancoras) -> Result<(), i64> {
    let opcoes = Opcoes {
        resolucao: Resolucao::Fixa(BANCADA),
        ancoras: Some(ancoras),
        prazo: Prazo::PADRAO,
    };
    let padrao = Limites::default();

    pagina("http://bancada.duke/ola", &opcoes, 200, b"ola, duke\n")?;
    mantida(&opcoes)?;
    pagina(
        "http://bancada.duke/pedacos",
        &opcoes,
        200,
        b"em pedacos, de verdade",
    )?;
    eco(&opcoes)?;
    status(&opcoes)?;
    ate_fechar(&opcoes)?;
    cifrada(&opcoes)?;

    // O mesmo destino, com um nome que o servidor não prova: o gate
    // deixou, e o TLS recusa.
    falha(
        "https://outro.duke:8443/ola",
        &opcoes,
        &padrao,
        Categoria::Tls,
        "TLS_NAME_MISMATCH",
        NOME,
    )?;
    // Fora do alcance: a recusa é do gate.
    falha(
        "http://bancada.duke:81/ola",
        &opcoes,
        &padrao,
        Categoria::Negado,
        "DENY_RESOURCE",
        FORA,
    )?;
    for torta in [
        "lf", "dobra", "ambiguo", "status", "pedaco", "versao", "tamanhos",
    ] {
        let mut url = String::from("http://bancada.duke/torto/");
        url.push_str(torta);
        falha(
            &url,
            &opcoes,
            &padrao,
            Categoria::Protocolo,
            "HTTP_MALFORMED",
            FALHA,
        )?;
    }
    falha(
        "http://bancada.duke/grande/2000000",
        &opcoes,
        &padrao,
        Categoria::Limite,
        "HTTP_TOO_LARGE",
        FALHA,
    )?;
    falha(
        "http://bancada.duke/corta",
        &opcoes,
        &padrao,
        Categoria::Fechada,
        "HTTP_CLOSED",
        FALHA,
    )?;
    // O mudo, com um prazo curto: um segundo de silêncio, duas vezes.
    let curto = Opcoes {
        prazo: Prazo {
            espera_ms: 1_000,
            esperas: 2,
        },
        ..opcoes
    };
    falha(
        "http://bancada.duke/mudo",
        &curto,
        &padrao,
        Categoria::Prazo,
        "NETWORK_TIMEOUT",
        FALHA,
    )?;

    // As medidas: o eco cru é a base do POST; o mesmo corpo, claro e
    // cifrado, dá o custo do TLS; o corpo grande, a vazão.
    eco_cru()?;
    vazao(&opcoes, "http://bancada.duke/grande/65536")?;
    vazao(&opcoes, "https://bancada.duke:8443/grande/65536")?;
    vazao(&opcoes, "http://bancada.duke/grande/262144")?;
    Ok(())
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("pagina: as ancoras nao se leram: {}", f.codigo());
            return SEM_ANCORAS;
        }
    };
    match tudo(&ancoras) {
        Ok(()) => {
            escreverln!("pagina: tudo conferiu");
            CODIGO
        }
        Err(codigo) => codigo,
    }
}
