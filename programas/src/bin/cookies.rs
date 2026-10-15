//! Os cookies de ponta a ponta, contra o servidor da bancada — claro e
//! atrás do TLS —, e o que eles **não** são: credencial do Duke.
//!
//! O nome `bancada.duke` vai direto a `10.0.2.100`, sem DNS, como no
//! `compressao` — e `estranho.duke` também, para o cookie de um host não ir
//! ao outro. A sessão é a da bancada: `/cookies/entrar` dá um cookie
//! `sessao`, `HttpOnly`, assinado por ela, e `/cookies/privado` só responde
//! a quem o traz. Cada passo diz no log o que conferiu:
//!
//! - a sessão, clara e cifrada: entrar, o privado com ela, sair, e o
//!   privado sem ela — com o `HttpOnly` fora do alcance do programa;
//! - o isolamento: o cookie de um pote não vai por outro pote, nem num
//!   pedido sem pote, nem a outro host;
//! - o `Secure`: só vai e só vem por `https`, e uma origem clara não o
//!   sobrescreve;
//! - o domínio, o caminho, os prefixos, o `SameSite` pelo contexto do
//!   pedido, e o `HttpOnly` pela API do programa;
//! - a validade, no relógio do sistema: o `Max-Age` vence, o `Expires`
//!   passado apaga, o futuro fica;
//! - os limites: o pote fica no teto de cookies por domínio, e o cookie
//!   grande demais não entra;
//! - quatro trocas numa conexão só, com o pote mudando entre elas;
//! - a medida: o tempo de trocas numa conexão mantida sem pote, com uma
//!   sessão sem validade e com um cookie de `Max-Age`, que lê o relógio;
//! - fora do alcance, a recusa é do gate, `DENY_RESOURCE`, antes do
//!   primeiro byte — o cookie não entra nisso.
//!
//! O valor da sessão nunca vai para o log: só o identificador que a
//! bancada devolve no privado, que sem a assinatura não vale nada. Sai com
//! [`CODIGO`] quando tudo confere, e com um código menor que diz o quê,
//! quando não.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "cookies",
    "net.connect",
    "random.read",
    "system.read",
    "fs.read"
);

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use programas::conexao::Prazo;
use programas::escreverln;
use programas::http::{
    self, Agora, Categoria, Contexto, Falha, Guardados, Limites, Metodo, Opcoes, Pedido, Pote,
    Protocolo, RecusaDeCookie, Resolucao, Resposta, Url,
};
use programas::tls;

/// Tudo conferiu. A suíte e a fumaça o procuram.
const CODIGO: i64 = 99;
/// As âncoras não se leram.
const SEM_ANCORAS: i64 = 40;
/// Entrar, o privado ou sair não foram como deviam.
const SESSAO: i64 = 41;
/// Um cookie foi aonde não devia: outro pote, sem pote, outro host.
const ISOLAMENTO: i64 = 42;
/// O `Secure` não valeu.
const SEGURO: i64 = 43;
/// O domínio, o caminho, um prefixo, o `SameSite` ou o `HttpOnly` não
/// valeram.
const ATRIBUTOS: i64 = 44;
/// A validade não valeu.
const VALIDADE: i64 = 45;
/// Os limites do pote não valeram.
const LIMITES: i64 = 46;
/// As quatro trocas não vieram numa conexão só.
const MANTIDA: i64 = 47;
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
const OUTRO_HOST: &str = "http://estranho.duke";

type Resultado = Result<Resposta, Falha>;

/// Um `GET` de `url` com `pote`, numa conexão só, de `contexto`.
fn pedir(pote: &mut Pote, url: &str, contexto: Contexto, opcoes: &Opcoes<'_>) -> Resultado {
    let url = Url::ler(url).map_err(Falha::Url)?;
    let mut pedido = Pedido::novo(Metodo::Get, url);
    pedido.contexto = contexto;
    http::buscar_com_pote(pedido, opcoes, &Limites::default(), pote)
}

/// O que chegou de `url`, para dizer quando não confere.
fn dizer(url: &str, r: &Resultado) {
    match r {
        Ok(r) => {
            escreverln!(
                "cookies: {} deu {} ({} novos, {} substituidos, {} apagados, {} recusados, {} retidos)",
                url,
                r.status,
                r.cookies.novos,
                r.cookies.substituidos,
                r.cookies.apagados,
                r.cookies.recusados,
                r.cookies.retidos
            );
        }
        Err(f) => {
            escreverln!(
                "cookies: {} falhou: {} {}",
                url,
                f.categoria().nome(),
                f.codigo()
            );
        }
    }
}

/// O corpo de `r` como texto, sem o fim de linha com que a bancada acaba
/// as respostas dela.
fn linha(r: &Resposta) -> String {
    let mut texto = http::texto(r);
    if r.corpo.ends_with(b"\n") {
        texto.pop();
    }
    texto
}

/// Os nomes dos cookies que o servidor recebeu num `/eco` de `url` — os
/// valores ficam de fora: o da sessão não vai para o log.
fn eco(
    pote: &mut Pote,
    url: &str,
    contexto: Contexto,
    opcoes: &Opcoes<'_>,
    erro: i64,
) -> Result<Vec<String>, i64> {
    let r = pedir(pote, url, contexto, opcoes);
    match &r {
        Ok(r) if r.status == 200 => {
            let corpo = linha(r);
            if corpo == "-" {
                return Ok(Vec::new());
            }
            Ok(corpo
                .split("; ")
                .map(|par| String::from(par.split('=').next().unwrap_or("")))
                .collect())
        }
        _ => {
            dizer(url, &r);
            Err(erro)
        }
    }
}

/// Os nomes, juntos, para dizer.
fn nomes(v: &[String]) -> String {
    if v.is_empty() {
        return String::from("nenhum");
    }
    v.join(",")
}

/// `texto` como vai numa consulta: o que não é letra, dígito ou `-._~`
/// vira `%XX`.
fn por_cento(texto: &str) -> String {
    let mut s = String::new();
    for b in texto.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    s
}

/// A bancada manda um `Set-Cookie` para cada um de `cookies`, na resposta
/// a um pedido de `base`: o que o pote fez com eles.
fn definir(
    pote: &mut Pote,
    base: &str,
    cookies: &[&str],
    opcoes: &Opcoes<'_>,
    erro: i64,
) -> Result<Guardados, i64> {
    let consulta: Vec<String> = cookies
        .iter()
        .map(|c| format!("c={}", por_cento(c)))
        .collect();
    let url = format!("{base}/cookies/definir?{}", consulta.join("&"));
    let r = pedir(pote, &url, Contexto::DoProprioSite, opcoes);
    match &r {
        Ok(r) if r.status == 200 => Ok(r.cookies),
        _ => {
            dizer(&url, &r);
            Err(erro)
        }
    }
}

/// O id da sessão que o privado de `base` reconhece, ou `None` com 401.
fn privado(pote: &mut Pote, base: &str, opcoes: &Opcoes<'_>) -> Result<Option<String>, i64> {
    let url = format!("{base}/cookies/privado");
    let r = pedir(pote, &url, Contexto::DoProprioSite, opcoes);
    match &r {
        Ok(r) if r.status == 200 => Ok(linha(r).strip_prefix("privado ").map(String::from)),
        Ok(r) if r.status == 401 => Ok(None),
        _ => {
            dizer(&url, &r);
            Err(SESSAO)
        }
    }
}

/// Os cookies que o programa vê para `url`, pela API dele.
fn visiveis(pote: &mut Pote, url: &Url) -> Vec<String> {
    let mut relogio = http::relogio_dos_cookies;
    pote.visiveis(url, &mut Agora::de(&mut relogio))
        .into_iter()
        .map(|(nome, _)| nome)
        .collect()
}

/// O programa põe `set_cookie` no pote, pela API dele.
fn definir_pelo_programa(
    pote: &mut Pote,
    url: &Url,
    set_cookie: &str,
) -> Result<http::Guardado, RecusaDeCookie> {
    let mut relogio = http::relogio_dos_cookies;
    pote.definir(url, set_cookie, &mut Agora::de(&mut relogio))
}

/// Entrar, o privado com a sessão, sair, e o privado sem ela — em `base`.
fn sessao(base: &str, opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let mut pote = Pote::novo();
    let url = format!("{base}/cookies/entrar");
    let r = pedir(&mut pote, &url, Contexto::DoProprioSite, opcoes);
    match &r {
        // O `Set-Cookie` foi para o pote, e saiu da resposta.
        Ok(r) if r.status == 200 && r.cookies.novos == 1 && r.cabecalho("set-cookie").is_none() => {
        }
        _ => {
            dizer(&url, &r);
            return Err(SESSAO);
        }
    }
    // O `HttpOnly` não sai do pote para o programa.
    let u = Url::ler(base).map_err(|_| SESSAO)?;
    if !visiveis(&mut pote, &u).is_empty() {
        escreverln!("cookies: o programa viu um cookie HttpOnly");
        return Err(SESSAO);
    }
    let Some(id) = privado(&mut pote, base, opcoes)? else {
        escreverln!("cookies: {}/cookies/privado nao reconheceu a sessao", base);
        return Err(SESSAO);
    };
    let url = format!("{base}/cookies/sair");
    let r = pedir(&mut pote, &url, Contexto::DoProprioSite, opcoes);
    match &r {
        Ok(r) if r.status == 200 && r.cookies.apagados == 1 && pote.quantos() == 0 => {}
        _ => {
            dizer(&url, &r);
            return Err(SESSAO);
        }
    }
    if privado(&mut pote, base, opcoes)?.is_some() {
        escreverln!("cookies: {} reconheceu a sessao depois de sair", base);
        return Err(SESSAO);
    }
    escreverln!(
        "cookies: {} entrou (sessao {}), o privado a reconheceu, e depois de sair nao",
        base,
        id
    );
    Ok(())
}

/// O cookie de um pote não vai por outro pote, num pedido sem pote, nem a
/// outro host.
fn isolamento(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let mut um = Pote::novo();
    let r = pedir(
        &mut um,
        &format!("{CLARA}/cookies/entrar"),
        Contexto::DoProprioSite,
        opcoes,
    );
    if !matches!(&r, Ok(r) if r.cookies.novos == 1) {
        dizer("entrar", &r);
        return Err(ISOLAMENTO);
    }
    let id = privado(&mut um, CLARA, opcoes)?;
    let mut outro = Pote::novo();
    let do_outro = privado(&mut outro, CLARA, opcoes)?;
    let eco_do_outro = eco(
        &mut outro,
        &format!("{CLARA}/cookies/eco"),
        Contexto::DoProprioSite,
        opcoes,
        ISOLAMENTO,
    )?;
    // Sem pote, nada de cookie: o pote não é estado do processo inteiro.
    let sem_pote = http::obter(
        &format!("{CLARA}/cookies/privado"),
        opcoes,
        &Limites::default(),
    );
    let sem_pote_401 = matches!(&sem_pote, Ok(r) if r.status == 401);
    // Outro host — o mesmo endereço, o mesmo destino no gate —, nada.
    let eco_de_outro_host = eco(
        &mut um,
        &format!("{OUTRO_HOST}/cookies/eco"),
        Contexto::DoProprioSite,
        opcoes,
        ISOLAMENTO,
    )?;
    if id.is_none()
        || do_outro.is_some()
        || !eco_do_outro.is_empty()
        || !sem_pote_401
        || !eco_de_outro_host.is_empty()
    {
        escreverln!(
            "cookies: a sessao vazou: pote {:?}, outro pote {:?} e {}, sem pote {}, outro host {}",
            id,
            do_outro,
            nomes(&eco_do_outro),
            sem_pote_401,
            nomes(&eco_de_outro_host)
        );
        return Err(ISOLAMENTO);
    }
    escreverln!(
        "cookies: a sessao de um pote nao foi por outro pote, por um pedido sem pote, nem a {}",
        OUTRO_HOST
    );
    Ok(())
}

/// O `Secure` só vai e só vem por `https`, e uma origem clara não o
/// sobrescreve.
fn seguro(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let mut pote = Pote::novo();
    let r = pedir(
        &mut pote,
        &format!("{CIFRADA}/cookies/entrar"),
        Contexto::DoProprioSite,
        opcoes,
    );
    if !matches!(&r, Ok(r) if r.cookies.novos == 1) {
        dizer("entrar cifrado", &r);
        return Err(SEGURO);
    }
    let claro = eco(
        &mut pote,
        &format!("{CLARA}/cookies/eco"),
        Contexto::DoProprioSite,
        opcoes,
        SEGURO,
    )?;
    let cifrado = eco(
        &mut pote,
        &format!("{CIFRADA}/cookies/eco"),
        Contexto::DoProprioSite,
        opcoes,
        SEGURO,
    )?;
    // A origem clara não sobrescreve o seguro, nem escreve um.
    let forjado = definir(
        &mut pote,
        CLARA,
        &["sessao=forjada; Path=/", "x=1; Secure"],
        opcoes,
        SEGURO,
    )?;
    let ainda = privado(&mut pote, CIFRADA, opcoes)?;
    if !claro.is_empty() || cifrado != ["sessao"] || forjado.recusados != 2 || ainda.is_none() {
        escreverln!(
            "cookies: o Secure nao valeu: claro {}, cifrado {}, {} recusados, sessao {:?}",
            nomes(&claro),
            nomes(&cifrado),
            forjado.recusados,
            ainda
        );
        return Err(SEGURO);
    }
    escreverln!("cookies: o Secure so foi por https, e a origem clara nao o sobrescreveu");
    Ok(())
}

/// O domínio, o caminho, os prefixos, o `SameSite` e o `HttpOnly`.
fn atributos(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let mut pote = Pote::novo();
    let dominio = definir(
        &mut pote,
        CLARA,
        &[
            "d1=1; Domain=duke",
            "d2=1; Domain=bancada.duke",
            "d3=1; Domain=estranho.duke",
            "p=1; Path=/cookies/so-aqui",
        ],
        opcoes,
        ATRIBUTOS,
    )?;
    let raiz = eco(
        &mut pote,
        &format!("{CLARA}/cookies/eco"),
        Contexto::DoProprioSite,
        opcoes,
        ATRIBUTOS,
    )?;
    let dentro = eco(
        &mut pote,
        &format!("{CLARA}/cookies/so-aqui/eco"),
        Contexto::DoProprioSite,
        opcoes,
        ATRIBUTOS,
    )?;
    if dominio.recusados != 2 || raiz != ["d2"] || dentro != ["p", "d2"] {
        escreverln!(
            "cookies: o dominio ou o caminho nao valeram: {} recusados, {} na raiz, {} dentro",
            dominio.recusados,
            nomes(&raiz),
            nomes(&dentro)
        );
        return Err(ATRIBUTOS);
    }
    escreverln!(
        "cookies: Domain=duke e Domain=estranho.duke recusados; o Path so vale dentro dele"
    );

    let mut cifrado = Pote::novo();
    let prefixos = definir(
        &mut cifrado,
        CIFRADA,
        &[
            "__Host-a=1; Secure; Path=/",
            "__Host-b=1; Secure; Path=/; Domain=bancada.duke",
            "__Secure-c=1",
            "s1=1; SameSite=Strict; Secure",
            "s2=1; SameSite=Lax; Secure",
            "s3=1; SameSite=None; Secure",
            "s4=1; SameSite=None",
        ],
        opcoes,
        ATRIBUTOS,
    )?;
    let eco_cifrado = format!("{CIFRADA}/cookies/eco");
    let proprio = eco(
        &mut cifrado,
        &eco_cifrado,
        Contexto::DoProprioSite,
        opcoes,
        ATRIBUTOS,
    )?;
    let navegando = eco(
        &mut cifrado,
        &eco_cifrado,
        Contexto::DeOutroSite { navegacao: true },
        opcoes,
        ATRIBUTOS,
    )?;
    let buscando = eco(
        &mut cifrado,
        &eco_cifrado,
        Contexto::DeOutroSite { navegacao: false },
        opcoes,
        ATRIBUTOS,
    )?;
    // Os `s` têm o caminho padrão, `/cookies`, mais longo que o `/` do
    // `__Host-a`: vão antes dele.
    if prefixos.recusados != 3
        || proprio != ["s1", "s2", "s3", "__Host-a"]
        || navegando != ["s2", "s3", "__Host-a"]
        || buscando != ["s3"]
    {
        escreverln!(
            "cookies: os prefixos ou o SameSite nao valeram: {} recusados; {} | {} | {}",
            prefixos.recusados,
            nomes(&proprio),
            nomes(&navegando),
            nomes(&buscando)
        );
        return Err(ATRIBUTOS);
    }
    escreverln!(
        "cookies: os prefixos valeram; do proprio site {}, navegando de outro {}, buscando para outro {}",
        nomes(&proprio),
        nomes(&navegando),
        nomes(&buscando)
    );

    // O `HttpOnly` pela API do programa: não cria, não sobrescreve, não lê.
    let r = pedir(
        &mut pote,
        &format!("{CLARA}/cookies/entrar"),
        Contexto::DoProprioSite,
        opcoes,
    );
    if !matches!(&r, Ok(r) if r.cookies.novos == 1) {
        dizer("entrar", &r);
        return Err(ATRIBUTOS);
    }
    let u = Url::ler(&format!("{CLARA}/cookies/eco")).map_err(|_| ATRIBUTOS)?;
    let criar = definir_pelo_programa(&mut pote, &u, "h=1; HttpOnly");
    let sobrescrever = definir_pelo_programa(&mut pote, &u, "sessao=forjada; Path=/");
    let vistos = visiveis(&mut pote, &u);
    let ainda = privado(&mut pote, CLARA, opcoes)?;
    if criar != Err(RecusaDeCookie::SoHttp)
        || sobrescrever != Err(RecusaDeCookie::SoHttp)
        || vistos != ["d2"]
        || ainda.is_none()
    {
        escreverln!(
            "cookies: o HttpOnly nao valeu: {:?} {:?} {} {:?}",
            criar,
            sobrescrever,
            nomes(&vistos),
            ainda
        );
        return Err(ATRIBUTOS);
    }
    escreverln!("cookies: o programa nao criou, nao sobrescreveu e nao viu o HttpOnly");
    Ok(())
}

/// A validade, no relógio do sistema — que anda de segundo em segundo: o
/// `Max-Age=5` vence entre 4 e 5 segundos depois de chegar, e o eco
/// seguinte, logo depois, ainda o leva; depois de 5,1 s, não.
fn validade(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let mut pote = Pote::novo();
    let g = definir(
        &mut pote,
        CLARA,
        &[
            "vence=1; Max-Age=5",
            "passado=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
            "futuro=1; Expires=Fri, 31 Dec 2100 23:59:59 GMT",
        ],
        opcoes,
        VALIDADE,
    )?;
    let antes = eco(
        &mut pote,
        &format!("{CLARA}/cookies/eco"),
        Contexto::DoProprioSite,
        opcoes,
        VALIDADE,
    )?;
    // A bancada espera do lado dela: o programa não tem como dormir.
    let r = pedir(
        &mut pote,
        &format!("{CLARA}/lento/5100"),
        Contexto::DoProprioSite,
        opcoes,
    );
    if !matches!(&r, Ok(r) if r.status == 200) {
        dizer("lento", &r);
        return Err(VALIDADE);
    }
    let depois = eco(
        &mut pote,
        &format!("{CLARA}/cookies/eco"),
        Contexto::DoProprioSite,
        opcoes,
        VALIDADE,
    )?;
    if g.novos != 2 || g.apagados != 1 || antes != ["vence", "futuro"] || depois != ["futuro"] {
        escreverln!(
            "cookies: a validade nao valeu: {} novos, {} apagados; antes {}, depois {}",
            g.novos,
            g.apagados,
            nomes(&antes),
            nomes(&depois)
        );
        return Err(VALIDADE);
    }
    escreverln!(
        "cookies: o Max-Age=5 venceu no relogio do sistema; o Expires passado apagou, o futuro ficou"
    );
    Ok(())
}

/// Os limites do pote.
fn limites(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let mut pote = Pote::novo();
    let r = pedir(
        &mut pote,
        &format!("{CLARA}/cookies/muitos/60/16"),
        Contexto::DoProprioSite,
        opcoes,
    );
    let muitos =
        matches!(&r, Ok(r) if r.status == 200 && r.cookies.novos == 60) && pote.quantos() == 50;
    if !muitos {
        dizer("muitos", &r);
    }
    let r = pedir(
        &mut pote,
        &format!("{CLARA}/cookies/muitos/1/4100"),
        Contexto::DoProprioSite,
        opcoes,
    );
    let grande = matches!(&r, Ok(r) if r.cookies.recusados == 1) && pote.quantos() == 50;
    if !grande {
        dizer("grande", &r);
    }
    if !muitos || !grande {
        return Err(LIMITES);
    }
    escreverln!("cookies: 60 cookies num dominio ficaram 50 no pote; o de 4100 bytes nao entrou");
    Ok(())
}

/// Entrar, o privado e sair numa conexão só, com o pote mudando entre as
/// trocas.
fn mantida(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let url = Url::ler(CLARA).map_err(|_| MANTIDA)?;
    let mut conexao = http::conectar(&url, opcoes).map_err(|f| {
        escreverln!("cookies: a conexao mantida nao abriu: {}", f.codigo());
        MANTIDA
    })?;
    let mut pote = Pote::novo();
    let mut status = Vec::new();
    for caminho in [
        "/cookies/entrar",
        "/cookies/privado",
        "/cookies/sair",
        "/cookies/privado",
    ] {
        let url = Url::ler(&format!("{CLARA}{caminho}")).map_err(|_| MANTIDA)?;
        let r = conexao.trocar_com_pote(
            &Pedido::novo(Metodo::Get, url),
            &Limites::default(),
            &mut pote,
        );
        match &r {
            Ok(r) => status.push(r.status),
            Err(_) => {
                dizer(caminho, &r);
                return Err(MANTIDA);
            }
        }
    }
    let trocas = conexao.trocas();
    conexao.fechar();
    if trocas != 4 || status != [200, 200, 200, 401] {
        escreverln!(
            "cookies: a conexao mantida fez {} trocas: {:?}",
            trocas,
            status
        );
        return Err(MANTIDA);
    }
    escreverln!("cookies: entrar, privado, sair e privado numa conexao so: 200 200 200 401");
    Ok(())
}

/// O tempo desde o boot, em milissegundos. Zero, se o relógio não
/// respondeu.
fn agora_ms() -> u64 {
    programas::nativo::pedir("system.uptime", |_| Ok(()))
        .ok()
        .and_then(|r| r.resultado().ok()?.member("uptime_ms")?.as_u64())
        .unwrap_or(0)
}

/// As trocas de cada série da [`medida`].
const TROCAS: usize = 40;

/// Quanto o pote custa numa conexão mantida: [`TROCAS`] pedidos ao
/// `/cookies/eco` sem pote, com o pote de uma sessão sem validade, e com o
/// de um cookie com `Max-Age` — que lê o relógio, pelo gate, a cada troca.
/// A bancada devolve o que chegou: nada, ou o cookie.
fn medida(opcoes: &Opcoes<'_>) -> Result<(), i64> {
    let mut tempos = Vec::new();
    for (rotulo, cookie) in [
        ("sem pote", None),
        ("sessao", Some("m=1")),
        ("max-age", Some("m=1; Max-Age=3600")),
    ] {
        let mut pote = Pote::novo();
        if let Some(c) = cookie {
            definir(&mut pote, CLARA, &[c], opcoes, MEDIDA)?;
        }
        let url = Url::ler(&format!("{CLARA}/cookies/eco")).map_err(|_| MEDIDA)?;
        let mut conexao = http::conectar(&url, opcoes).map_err(|f| {
            escreverln!("cookies: a conexao da medida nao abriu: {}", f.codigo());
            MEDIDA
        })?;
        let pedido = Pedido::novo(Metodo::Get, url);
        let esperado = if cookie.is_some() { "m=1" } else { "-" };
        let comeco = agora_ms();
        for _ in 0..TROCAS {
            let r = match cookie {
                None => conexao.trocar(&pedido, &Limites::default()),
                Some(_) => conexao.trocar_com_pote(&pedido, &Limites::default(), &mut pote),
            };
            match &r {
                Ok(r) if r.status == 200 && linha(r) == esperado => {}
                _ => {
                    dizer(rotulo, &r);
                    return Err(MEDIDA);
                }
            }
        }
        let ms = agora_ms().saturating_sub(comeco);
        conexao.fechar();
        tempos.push(format!("{rotulo} {ms}"));
    }
    escreverln!(
        "cookies: medida {} trocas numa conexao mantida, em ms: {}",
        TROCAS,
        tempos.join(", ")
    );
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
    sessao(CLARA, &opcoes)?;
    sessao(CIFRADA, &opcoes)?;
    isolamento(&opcoes)?;
    seguro(&opcoes)?;
    atributos(&opcoes)?;
    validade(&opcoes)?;
    limites(&opcoes)?;
    mantida(&opcoes)?;
    medida(&opcoes)?;

    // Fora do alcance: o gate recusa antes do primeiro byte, leve o pedido
    // cookie ou não. Por último, para a suíte achar o registro dela.
    let mut pote = Pote::novo();
    let r = pedir(
        &mut pote,
        &format!("{CLARA}/cookies/entrar"),
        Contexto::DoProprioSite,
        &opcoes,
    );
    if !matches!(&r, Ok(r) if r.cookies.novos == 1) {
        dizer("entrar", &r);
        return Err(FORA);
    }
    let url = "http://bancada.duke:81/cookies/privado";
    let r = pedir(&mut pote, url, Contexto::DoProprioSite, &opcoes);
    match &r {
        Err(f) if f.codigo() == "DENY_RESOURCE" && f.categoria() == Categoria::Negado => {
            escreverln!(
                "cookies: {} com a sessao no pote -> denied DENY_RESOURCE",
                url
            );
            Ok(())
        }
        _ => {
            dizer(url, &r);
            Err(FORA)
        }
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("cookies: as ancoras nao se leram: {}", f.codigo());
            return SEM_ANCORAS;
        }
    };
    match tudo(&ancoras) {
        Ok(()) => {
            escreverln!("cookies: tudo conferiu");
            CODIGO
        }
        Err(codigo) => codigo,
    }
}
