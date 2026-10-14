//! Os testes dos cookies: a leitura do `Set-Cookie` e das datas, o modelo
//! de armazenamento, a escolha do que vai em cada pedido, os limites, a
//! troca com o pote pelo cliente — e o que um programa não consegue: ler um
//! `HttpOnly`, escrever um `HttpOnly`, ou ver um cookie de outro pote.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::cookies::{
    Agora, Contexto, Guardado, Guardados, LimitesDoPote, MAIOR_VALIDADE, Pote, Recusa, data,
};
use crate::testes::{FalhaDeTeste, Roteiro};
use crate::testes_da_codificacao::pico_de;
use crate::{Cliente, Erro, Limite, Limites, Metodo, Pedido, Url};

fn url(t: &str) -> Url {
    Url::ler(t).unwrap()
}

/// O `Set-Cookie` `sc`, vindo pela rede na resposta a um pedido de `u` em
/// `contexto`, com o relógio em `t`.
fn da_rede_em(
    p: &mut Pote,
    u: &str,
    contexto: Contexto,
    sc: &str,
    t: Option<u64>,
) -> Result<Guardado, Recusa> {
    let mut ler = move || t;
    p.guardar_um(&url(u), contexto, sc, &mut Agora::de(&mut ler))
}

fn da_rede(p: &mut Pote, u: &str, sc: &str, t: Option<u64>) -> Result<Guardado, Recusa> {
    da_rede_em(p, u, Contexto::DoProprioSite, sc, t)
}

/// O `Cookie` de um pedido `metodo` a `u` em `contexto`, com o relógio em
/// `t`.
fn cookie_em(
    p: &mut Pote,
    u: &str,
    metodo: Metodo,
    contexto: Contexto,
    t: Option<u64>,
) -> Option<String> {
    let mut ler = move || t;
    p.cabecalho(&url(u), metodo, contexto, &mut Agora::de(&mut ler))
        .0
}

fn cookie(p: &mut Pote, u: &str, t: Option<u64>) -> Option<String> {
    cookie_em(p, u, Metodo::Get, Contexto::DoProprioSite, t)
}

fn definir(p: &mut Pote, u: &str, sc: &str, t: Option<u64>) -> Result<Guardado, Recusa> {
    let mut ler = move || t;
    p.definir(&url(u), sc, &mut Agora::de(&mut ler))
}

fn visiveis(p: &mut Pote, u: &str, t: Option<u64>) -> Vec<(String, String)> {
    let mut ler = move || t;
    p.visiveis(&url(u), &mut Agora::de(&mut ler))
}

/// Um tempo qualquer de 2026, para as validades.
const T: u64 = 1_790_000_000;

const BANCADA: &str = "http://bancada.duke/";
const CIFRADA: &str = "https://bancada.duke/";

#[test]
fn o_set_cookie_se_le() {
    let mut p = Pote::novo();
    // O espaço em volta sai; o resto do valor fica como veio.
    assert_eq!(
        da_rede(&mut p, BANCADA, "  a  =  b c  ", None),
        Ok(Guardado::Novo)
    );
    assert_eq!(cookie(&mut p, BANCADA, None).as_deref(), Some("a=b c"));
    // O valor pode ser vazio, e ter `=`.
    da_rede(&mut p, BANCADA, "vazio=", None).unwrap();
    da_rede(&mut p, BANCADA, "igual=x=y", None).unwrap();
    assert_eq!(
        cookie(&mut p, BANCADA, None).as_deref(),
        Some("a=b c; vazio=; igual=x=y")
    );
    // Os atributos: sem caixa, desconhecidos ignorados, o último vale.
    let mut p = Pote::novo();
    da_rede(
        &mut p,
        "http://bancada.duke/x/y",
        "c=1; PATH=/um; pAtH=/dois; Coisa=nada; flag",
        None,
    )
    .unwrap();
    assert_eq!(
        cookie(&mut p, "http://bancada.duke/dois", None).as_deref(),
        Some("c=1")
    );
    assert_eq!(cookie(&mut p, "http://bancada.duke/um", None), None);
    // Um `Path` que não começa por `/` vale o padrão: o diretório do pedido.
    let mut p = Pote::novo();
    da_rede(
        &mut p,
        "http://bancada.duke/x/y",
        "d=1; Path=relativo",
        None,
    )
    .unwrap();
    assert_eq!(
        cookie(&mut p, "http://bancada.duke/x/z", None).as_deref(),
        Some("d=1")
    );
    assert_eq!(cookie(&mut p, "http://bancada.duke/w", None), None);
    // Um atributo de mais de 1024 bytes é ignorado — o cookie fica.
    let mut p = Pote::novo();
    let longo = format!("e=1; Path=/{}", "p".repeat(1024));
    da_rede(&mut p, "http://bancada.duke/a/b", &longo, None).unwrap();
    assert_eq!(
        cookie(&mut p, "http://bancada.duke/a/c", None).as_deref(),
        Some("e=1")
    );
    // O `Domain` com o ponto da frente e em maiúsculas é o mesmo domínio.
    let mut p = Pote::novo();
    da_rede(&mut p, BANCADA, "f=1; Domain=.BANCADA.Duke", None).unwrap();
    assert_eq!(
        cookie(&mut p, "http://www.bancada.duke/", None).as_deref(),
        Some("f=1")
    );
    // Vazio, o `Domain` não diz nada: o cookie é só do host.
    let mut p = Pote::novo();
    da_rede(&mut p, BANCADA, "g=1; Domain=", None).unwrap();
    assert_eq!(cookie(&mut p, "http://www.bancada.duke/", None), None);
    assert_eq!(cookie(&mut p, BANCADA, None).as_deref(), Some("g=1"));
}

#[test]
fn o_que_nao_e_cookie_e_recusado() {
    let mut p = Pote::novo();
    for (sc, recusa) in [
        ("semigual", Recusa::Formato),
        ("=valor", Recusa::Formato),
        ("   =valor", Recusa::Formato),
        ("", Recusa::Formato),
        ("; Path=/", Recusa::Formato),
        ("a\u{1}b=1", Recusa::Formato),
        ("a=b\u{0}c", Recusa::Formato),
        ("a=b\u{7f}", Recusa::Formato),
        ("a=b\rc", Recusa::Formato),
        ("a=b\nCookie: x", Recusa::Formato),
    ] {
        assert_eq!(da_rede(&mut p, BANCADA, sc, None), Err(recusa), "{sc:?}");
    }
    // A tabulação passa, e o que não é ASCII também.
    da_rede(&mut p, BANCADA, "t=a\tb", None).unwrap();
    da_rede(&mut p, BANCADA, "u=ação", None).unwrap();
    assert_eq!(p.quantos(), 2);
    // O nome e o valor juntos: 4096 bytes entram, 4097 não.
    let mut p = Pote::novo();
    let cabe = format!("n={}", "v".repeat(4095));
    assert_eq!(da_rede(&mut p, BANCADA, &cabe, None), Ok(Guardado::Novo));
    let nao_cabe = format!("n={}", "v".repeat(4096));
    assert_eq!(
        da_rede(&mut p, BANCADA, &nao_cabe, None),
        Err(Recusa::Grande)
    );
    let nome_grande = format!("{}=v", "n".repeat(4096));
    assert_eq!(
        da_rede(&mut p, BANCADA, &nome_grande, None),
        Err(Recusa::Grande)
    );
    assert_eq!(p.quantos(), 1);
}

#[test]
fn as_datas_de_cookie() {
    for (texto, segundos) in [
        ("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_777),
        ("Sunday, 06-Nov-94 08:49:37 GMT", 784_111_777),
        ("Sun Nov  6 08:49:37 1994", 784_111_777),
        ("06 Nov 1994 08:49:37", 784_111_777),
        ("Nov 06 1994 08:49:37", 784_111_777),
        ("1994 Nov 06 08:49:37", 784_111_777),
        ("08:49:37 06 Nov 1994", 784_111_777),
        ("sun, 06 NOVEMBER 1994 08:49:37GMT", 784_111_777),
        ("Thu, 10 Apr 1980 16:33:12 GMT", 324_232_392),
        ("Thu, 01 Jan 1970 00:00:00 GMT", 0),
        ("Thu, 01-Jan-1970 00:00:01 GMT", 1),
        ("Tue, 29 Feb 2000 00:00:00 GMT", 951_782_400),
        ("Thu, 29 Feb 2024 12:0:0 GMT", 1_709_208_000),
        ("Fri, 31 Dec 9999 23:59:59 GMT", 253_402_300_799),
        // O ano de dois dígitos: 70 a 99 são do século XX, 0 a 69 do XXI.
        ("01 Jan 69 00:00:00", 3_124_224_000),
        ("01 Jan 70 00:00:01", 1),
        // Antes de 1970 vale zero — o vencido.
        ("Mon, 01 Jan 1601 00:00:00 GMT", 0),
    ] {
        assert_eq!(data(texto), Some(segundos), "{texto:?}");
    }
    for texto in [
        "",
        "agora",
        "06 Nov 1994",
        "Nov 1994 08:49:37",
        "06 1994 08:49:37",
        "06 Nov 08:49:37",
        "Sun, 31 Feb 2000 00:00:00 GMT",
        "Thu, 29 Feb 1900 00:00:00 GMT",
        "Thu, 29 Feb 2023 00:00:00 GMT",
        "Sun, 31 Apr 1994 00:00:00 GMT",
        "Sun, 06 Nov 1994 24:00:00 GMT",
        "Sun, 06 Nov 1994 23:60:00 GMT",
        "Sun, 06 Nov 1994 23:59:60 GMT",
        "Sun, 00 Nov 1994 08:49:37 GMT",
        "Sun, 32 Nov 1994 08:49:37 GMT",
        "Sun, 06 Nov 1600 08:49:37 GMT",
        "Sun, 06 Nov 1994 08:49:370 GMT",
        "Sun, 06 Nov 1994 123:49:37 GMT",
        "Sun, 06 Nov 19945 08:49:37 GMT",
        "Sun, 06 No 1994 08:49:37 GMT",
    ] {
        assert_eq!(data(texto), None, "{texto:?}");
    }
}

#[test]
fn a_validade() {
    let mut p = Pote::novo();
    // `Max-Age`: vale até agora mais tantos segundos — vencido no instante
    // em que chega lá.
    da_rede(&mut p, BANCADA, "m=1; Max-Age=10", Some(T)).unwrap();
    assert_eq!(cookie(&mut p, BANCADA, Some(T + 9)).as_deref(), Some("m=1"));
    assert_eq!(cookie(&mut p, BANCADA, Some(T + 10)), None);
    // E o vencido sai do pote quando o relógio é lido.
    assert_eq!(p.quantos(), 0);
    // `Expires`, a data.
    let mut p = Pote::novo();
    da_rede(
        &mut p,
        BANCADA,
        "e=1; Expires=Fri, 31 Dec 2100 23:59:59 GMT",
        Some(4_133_980_000),
    )
    .unwrap();
    assert_eq!(
        cookie(&mut p, BANCADA, Some(4_133_980_798)).as_deref(),
        Some("e=1")
    );
    assert_eq!(cookie(&mut p, BANCADA, Some(4_133_980_799)), None);
    // O `Max-Age` vence o `Expires`, venha antes ou depois.
    for sc in [
        "x=1; Max-Age=5; Expires=Fri, 31 Dec 2100 23:59:59 GMT",
        "x=1; Expires=Fri, 31 Dec 2100 23:59:59 GMT; Max-Age=5",
    ] {
        let mut p = Pote::novo();
        da_rede(&mut p, BANCADA, sc, Some(T)).unwrap();
        assert_eq!(cookie(&mut p, BANCADA, Some(T + 4)).as_deref(), Some("x=1"));
        assert_eq!(cookie(&mut p, BANCADA, Some(T + 5)), None, "{sc}");
    }
    // Um `Max-Age` que não é inteiro é ignorado: o cookie fica de sessão.
    for sc in [
        "s=1; Max-Age=1a",
        "s=1; Max-Age=+5",
        "s=1; Max-Age=-",
        "s=1; Max-Age=",
    ] {
        let mut p = Pote::novo();
        da_rede(&mut p, BANCADA, sc, Some(T)).unwrap();
        assert_eq!(
            cookie(&mut p, BANCADA, Some(u64::MAX)).as_deref(),
            Some("s=1"),
            "{sc}"
        );
    }
    // Nenhuma validade passa de 400 dias.
    for sc in [
        "l=1; Max-Age=999999999999999999999999",
        "l=1; Expires=Fri, 31 Dec 9999 23:59:59 GMT",
    ] {
        let mut p = Pote::novo();
        da_rede(&mut p, BANCADA, sc, Some(T)).unwrap();
        assert_eq!(
            cookie(&mut p, BANCADA, Some(T + MAIOR_VALIDADE - 1)).as_deref(),
            Some("l=1"),
            "{sc}"
        );
        assert_eq!(
            cookie(&mut p, BANCADA, Some(T + MAIOR_VALIDADE)),
            None,
            "{sc}"
        );
    }
}

#[test]
fn o_que_ja_venceu_apaga() {
    for apaga in [
        "k=; Max-Age=0",
        "k=; Max-Age=-1",
        "k=; Max-Age=-99999999999999999999999",
        "k=; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        "k=; Expires=Sun, 06 Nov 1994 08:49:37 GMT",
    ] {
        let mut p = Pote::novo();
        da_rede(&mut p, BANCADA, "k=1", None).unwrap();
        da_rede(&mut p, BANCADA, "outro=1", None).unwrap();
        assert_eq!(
            da_rede(&mut p, BANCADA, apaga, Some(T)),
            Ok(Guardado::Apagado),
            "{apaga}"
        );
        assert_eq!(
            cookie(&mut p, BANCADA, Some(T)).as_deref(),
            Some("outro=1"),
            "{apaga}"
        );
    }
    // Só o de mesmo nome, domínio e caminho sai.
    let mut p = Pote::novo();
    da_rede(&mut p, BANCADA, "k=1; Path=/a", None).unwrap();
    da_rede(&mut p, BANCADA, "k=; Max-Age=0; Path=/b", None).unwrap();
    assert_eq!(
        cookie(&mut p, "http://bancada.duke/a", None).as_deref(),
        Some("k=1")
    );
    // Apagar o que não existe não põe nada.
    let mut p = Pote::novo();
    assert_eq!(
        da_rede(&mut p, BANCADA, "z=1; Max-Age=0", None),
        Ok(Guardado::Apagado)
    );
    assert_eq!(p.quantos(), 0);
}

#[test]
fn sem_relogio_a_validade_nao_se_confere() {
    // O cookie novo com validade fica de sessão: o valor novo substitui o
    // velho — o do `Expires` passado também —, e o `Max-Age=0` apaga.
    let mut p = Pote::novo();
    da_rede(&mut p, BANCADA, "s=1", None).unwrap();
    assert_eq!(
        da_rede(&mut p, BANCADA, "s=2; Max-Age=60", None),
        Ok(Guardado::Substituido)
    );
    assert_eq!(cookie(&mut p, BANCADA, None).as_deref(), Some("s=2"));
    assert_eq!(
        da_rede(
            &mut p,
            BANCADA,
            "s=; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
            None
        ),
        Ok(Guardado::Substituido)
    );
    assert_eq!(cookie(&mut p, BANCADA, None).as_deref(), Some("s="));
    assert_eq!(
        da_rede(&mut p, BANCADA, "s=; Max-Age=0", None),
        Ok(Guardado::Apagado)
    );
    assert_eq!(p.quantos(), 0);
    // O guardado com validade não vai sem relógio: não há como saber se
    // venceu.
    let mut p = Pote::novo();
    da_rede(&mut p, BANCADA, "v=1; Max-Age=60", Some(T)).unwrap();
    da_rede(&mut p, BANCADA, "w=1", None).unwrap();
    assert_eq!(cookie(&mut p, BANCADA, None).as_deref(), Some("w=1"));
    assert_eq!(
        cookie(&mut p, BANCADA, Some(T)).as_deref(),
        Some("v=1; w=1")
    );
}

#[test]
fn o_relogio_so_e_lido_quando_um_cookie_tem_validade() {
    let leituras = core::cell::Cell::new(0);
    let mut relogio = || {
        leituras.set(leituras.get() + 1);
        Some(T)
    };
    let mut p = Pote::novo();
    let u = url(BANCADA);
    {
        let mut agora = Agora::de(&mut relogio);
        // Os de sessão não leem o relógio.
        p.guardar_um(&u, Contexto::DoProprioSite, "a=1", &mut agora)
            .unwrap();
        assert!(
            p.cabecalho(&u, Metodo::Get, Contexto::DoProprioSite, &mut agora)
                .0
                .is_some()
        );
    }
    assert_eq!(leituras.get(), 0);
    {
        // O primeiro com validade lê — uma vez, por mais cookies que haja
        // na mesma troca.
        let mut agora = Agora::de(&mut relogio);
        p.guardar_um(&u, Contexto::DoProprioSite, "b=1; Max-Age=60", &mut agora)
            .unwrap();
        p.guardar_um(&u, Contexto::DoProprioSite, "c=1; Max-Age=60", &mut agora)
            .unwrap();
        p.cabecalho(&u, Metodo::Get, Contexto::DoProprioSite, &mut agora);
    }
    assert_eq!(leituras.get(), 1);
    {
        // Um pedido a que nenhum cookie com validade iria não lê.
        let mut agora = Agora::de(&mut relogio);
        p.cabecalho(
            &url("http://outro.duke/"),
            Metodo::Get,
            Contexto::DoProprioSite,
            &mut agora,
        );
    }
    assert_eq!(leituras.get(), 1);
}

#[test]
fn o_dominio() {
    let mut p = Pote::novo();
    // Sem `Domain`: só o host.
    da_rede(&mut p, "http://www.bancada.duke/", "so=1", None).unwrap();
    // Com ele: o domínio e os de baixo.
    da_rede(
        &mut p,
        "http://www.bancada.duke/",
        "todos=1; Domain=bancada.duke",
        None,
    )
    .unwrap();
    // O próprio host como `Domain` também vale para os de baixo.
    da_rede(
        &mut p,
        "http://www.bancada.duke/",
        "host=1; Domain=www.bancada.duke",
        None,
    )
    .unwrap();
    assert_eq!(
        cookie(&mut p, "http://www.bancada.duke/", None).as_deref(),
        Some("so=1; todos=1; host=1")
    );
    assert_eq!(
        cookie(&mut p, "http://bancada.duke/", None).as_deref(),
        Some("todos=1")
    );
    assert_eq!(
        cookie(&mut p, "http://a.www.bancada.duke/", None).as_deref(),
        Some("todos=1; host=1")
    );
    // Um nome que só termina igual não está no domínio.
    assert_eq!(cookie(&mut p, "http://xbancada.duke/", None), None);
    assert_eq!(cookie(&mut p, "http://outro.duke/", None), None);
    // O host não escreve para um irmão, para um de baixo, nem para outro.
    for d in [
        "outro.bancada.duke",
        "a.www.bancada.duke",
        "outro.duke",
        "ancada.duke",
    ] {
        assert_eq!(
            da_rede(
                &mut p,
                "http://www.bancada.duke/",
                &format!("x=1; Domain={d}"),
                None
            ),
            Err(Recusa::Dominio),
            "{d}"
        );
    }
    // Um rótulo só é de todo mundo — a menos que seja o próprio host.
    for d in ["duke", ".duke"] {
        assert_eq!(
            da_rede(
                &mut p,
                "http://bancada.duke/",
                &format!("y=1; Domain={d}"),
                None
            ),
            Err(Recusa::Dominio),
            "{d}"
        );
    }
    let mut local = Pote::novo();
    da_rede(
        &mut local,
        "http://localhost/",
        "l=1; Domain=localhost",
        None,
    )
    .unwrap();
    assert_eq!(
        cookie(&mut local, "http://localhost/", None).as_deref(),
        Some("l=1")
    );
    assert_eq!(cookie(&mut local, "http://a.localhost/", None), None);
}

#[test]
fn o_host_por_endereco_so_tem_cookie_dele() {
    let mut p = Pote::novo();
    da_rede(&mut p, "http://10.0.2.100/", "a=1", None).unwrap();
    da_rede(&mut p, "http://10.0.2.100/", "b=1; Domain=10.0.2.100", None).unwrap();
    for d in ["0.2.100", "2.100", "10.0.2.1", "bancada.duke"] {
        assert_eq!(
            da_rede(
                &mut p,
                "http://10.0.2.100/",
                &format!("c=1; Domain={d}"),
                None
            ),
            Err(Recusa::Dominio),
            "{d}"
        );
    }
    assert_eq!(
        cookie(&mut p, "http://10.0.2.100/", None).as_deref(),
        Some("a=1; b=1")
    );
    assert_eq!(cookie(&mut p, "http://110.0.2.100/", None), None);
    assert_eq!(cookie(&mut p, "http://10.0.2.10/", None), None);
    // Um nome que acaba como um endereço pode ter o cookie do domínio dele
    // — mas o endereço não é um nome abaixo desse domínio: não vai.
    let mut p = Pote::novo();
    assert_eq!(
        da_rede(&mut p, "http://x.0.2.100/", "n=1; Domain=0.2.100", None),
        Ok(Guardado::Novo)
    );
    assert_eq!(
        cookie(&mut p, "http://y.0.2.100/", None).as_deref(),
        Some("n=1")
    );
    assert_eq!(cookie(&mut p, "http://10.0.2.100/", None), None);
}

#[test]
fn o_caminho() {
    // O padrão é o diretório do pedido.
    for (pedido, vai, nao_vai) in [
        ("http://h.duke/a/b/c", "/a/b/x", "/a/x"),
        ("http://h.duke/a/b/", "/a/b/x", "/a/x"),
        ("http://h.duke/a", "/qualquer", ""),
        ("http://h.duke/", "/qualquer", ""),
        ("http://h.duke/a/b?x=/c/d", "/a/x", "/b"),
    ] {
        let mut p = Pote::novo();
        da_rede(&mut p, pedido, "c=1", None).unwrap();
        assert_eq!(
            cookie(&mut p, &format!("http://h.duke{vai}"), None).as_deref(),
            Some("c=1"),
            "{pedido} {vai}"
        );
        if !nao_vai.is_empty() {
            assert_eq!(
                cookie(&mut p, &format!("http://h.duke{nao_vai}"), None),
                None,
                "{pedido} {nao_vai}"
            );
        }
    }
    // O caminho do cookie casa com ele mesmo e com o que está abaixo.
    let mut p = Pote::novo();
    da_rede(&mut p, "http://h.duke/", "f=1; Path=/foo", None).unwrap();
    for (caminho, vai) in [
        ("/foo", true),
        ("/foo/", true),
        ("/foo/bar", true),
        ("/foo?x", true),
        ("/foobar", false),
        ("/fo", false),
        ("/", false),
        ("/bar/foo", false),
    ] {
        assert_eq!(
            cookie(&mut p, &format!("http://h.duke{caminho}"), None).is_some(),
            vai,
            "{caminho}"
        );
    }
    let mut p = Pote::novo();
    da_rede(&mut p, "http://h.duke/", "g=1; Path=/foo/", None).unwrap();
    assert!(cookie(&mut p, "http://h.duke/foo/bar", None).is_some());
    assert!(cookie(&mut p, "http://h.duke/foo", None).is_none());
}

#[test]
fn a_ordem_do_cabecalho() {
    // O caminho mais longo primeiro; entre caminhos iguais, o mais antigo.
    let mut p = Pote::novo();
    da_rede(&mut p, "http://h.duke/", "raiz1=1; Path=/", None).unwrap();
    da_rede(&mut p, "http://h.duke/", "fundo=1; Path=/a/b", None).unwrap();
    da_rede(&mut p, "http://h.duke/", "meio=1; Path=/a", None).unwrap();
    da_rede(&mut p, "http://h.duke/", "raiz2=1; Path=/", None).unwrap();
    assert_eq!(
        cookie(&mut p, "http://h.duke/a/b/c", None).as_deref(),
        Some("fundo=1; meio=1; raiz1=1; raiz2=1")
    );
    // Substituir guarda a criação: o `raiz1` novo continua antes do
    // `raiz2`.
    assert_eq!(
        da_rede(&mut p, "http://h.duke/", "raiz1=2; Path=/", None),
        Ok(Guardado::Substituido)
    );
    assert_eq!(
        cookie(&mut p, "http://h.duke/", None).as_deref(),
        Some("raiz1=2; raiz2=1")
    );
    // O mesmo nome com outro caminho é outro cookie — e o caminho igual
    // ao do `meio`, mais novo, vem depois dele.
    da_rede(&mut p, "http://h.duke/", "raiz1=3; Path=/a", None).unwrap();
    assert_eq!(
        cookie(&mut p, "http://h.duke/a", None).as_deref(),
        Some("meio=1; raiz1=3; raiz1=2; raiz2=1")
    );
}

#[test]
fn o_secure() {
    let mut p = Pote::novo();
    // Só uma origem cifrada escreve um `Secure`.
    assert_eq!(
        da_rede(&mut p, BANCADA, "s=1; Secure", None),
        Err(Recusa::Seguro)
    );
    assert_eq!(
        da_rede(&mut p, CIFRADA, "s=1; Secure", None),
        Ok(Guardado::Novo)
    );
    da_rede(&mut p, BANCADA, "claro=1", None).unwrap();
    // E ele só vai por `https`. O claro vai pelos dois: o cookie não é da
    // porta nem do esquema.
    assert_eq!(cookie(&mut p, BANCADA, None).as_deref(), Some("claro=1"));
    assert_eq!(
        cookie(&mut p, CIFRADA, None).as_deref(),
        Some("s=1; claro=1")
    );
    assert_eq!(
        cookie(&mut p, "https://bancada.duke:8443/", None).as_deref(),
        Some("s=1; claro=1")
    );
    // Uma origem clara não sobrescreve o seguro de mesmo nome — nem pelo
    // domínio de cima, nem por um caminho dentro do dele.
    for sc in [
        "s=forjado",
        "s=forjado; Path=/a",
        "s=forjado; Domain=bancada.duke",
    ] {
        assert_eq!(
            da_rede(&mut p, BANCADA, sc, None),
            Err(Recusa::Seguro),
            "{sc}"
        );
    }
    assert_eq!(
        da_rede(
            &mut p,
            "http://www.bancada.duke/",
            "s=forjado; Domain=bancada.duke",
            None
        ),
        Err(Recusa::Seguro)
    );
    // Outro nome, ou um caminho que não está no dele, passa.
    let mut p2 = Pote::novo();
    da_rede(
        &mut p2,
        "https://bancada.duke/a/x",
        "s=1; Secure; Path=/a",
        None,
    )
    .unwrap();
    assert_eq!(
        da_rede(&mut p2, BANCADA, "s=claro; Path=/b", None),
        Ok(Guardado::Novo)
    );
    assert_eq!(
        da_rede(&mut p2, BANCADA, "t=claro; Path=/a", None),
        Ok(Guardado::Novo)
    );
    // A origem cifrada sobrescreve.
    assert_eq!(
        da_rede(&mut p, CIFRADA, "s=2; Secure", None),
        Ok(Guardado::Substituido)
    );
    assert_eq!(
        cookie(&mut p, CIFRADA, None).as_deref(),
        Some("s=2; claro=1")
    );
}

#[test]
fn os_prefixos() {
    let mut p = Pote::novo();
    for (u, sc, desfecho) in [
        (CIFRADA, "__Secure-a=1; Secure", Ok(Guardado::Novo)),
        (CIFRADA, "__Secure-b=1", Err(Recusa::Prefixo)),
        (CIFRADA, "__SECURE-c=1", Err(Recusa::Prefixo)),
        (BANCADA, "__Secure-d=1; Secure", Err(Recusa::Seguro)),
        (CIFRADA, "__Host-e=1; Secure; Path=/", Ok(Guardado::Novo)),
        (CIFRADA, "__Host-f=1; Secure", Err(Recusa::Prefixo)),
        (CIFRADA, "__Host-g=1; Path=/", Err(Recusa::Prefixo)),
        (CIFRADA, "__Host-h=1; Secure; Path=/a", Err(Recusa::Prefixo)),
        (
            CIFRADA,
            "__Host-i=1; Secure; Path=/; Domain=bancada.duke",
            Err(Recusa::Prefixo),
        ),
        (CIFRADA, "__host-j=1; Secure", Err(Recusa::Prefixo)),
        // Um nome que só parece o prefixo não é.
        (CIFRADA, "_Host-k=1", Ok(Guardado::Novo)),
    ] {
        assert_eq!(da_rede(&mut p, u, sc, None), desfecho, "{sc}");
    }
}

#[test]
fn o_samesite() {
    let mut p = Pote::novo();
    // `None` só com `Secure`.
    assert_eq!(
        da_rede(&mut p, CIFRADA, "n=1; SameSite=None", None),
        Err(Recusa::MesmoSite)
    );
    da_rede(&mut p, CIFRADA, "estrito=1; SameSite=Strict", None).unwrap();
    da_rede(&mut p, CIFRADA, "frouxo=1; SameSite=Lax", None).unwrap();
    da_rede(&mut p, CIFRADA, "padrao=1", None).unwrap();
    da_rede(&mut p, CIFRADA, "outro=1; SameSite=Talvez", None).unwrap();
    da_rede(&mut p, CIFRADA, "livre=1; SameSite=None; Secure", None).unwrap();
    // Do próprio site, todos.
    assert_eq!(
        cookie(&mut p, CIFRADA, None).as_deref(),
        Some("estrito=1; frouxo=1; padrao=1; outro=1; livre=1")
    );
    let navega = Contexto::DeOutroSite { navegacao: true };
    let busca = Contexto::DeOutroSite { navegacao: false };
    // Navegando de outro site, por método seguro: os frouxos — e o sem
    // atributo, que vale frouxo — e os livres.
    for metodo in [Metodo::Get, Metodo::Head] {
        assert_eq!(
            cookie_em(&mut p, CIFRADA, metodo, navega, None).as_deref(),
            Some("frouxo=1; padrao=1; outro=1; livre=1")
        );
    }
    // Por um método que muda o servidor, ou buscando um pedaço para outro
    // site: só os livres.
    for metodo in [Metodo::Post, Metodo::Put, Metodo::Delete] {
        assert_eq!(
            cookie_em(&mut p, CIFRADA, metodo, navega, None).as_deref(),
            Some("livre=1")
        );
    }
    assert_eq!(
        cookie_em(&mut p, CIFRADA, Metodo::Get, busca, None).as_deref(),
        Some("livre=1")
    );
    // A resposta a um pedido de outro site que não é navegação não grava
    // os estritos nem os frouxos; a de uma navegação grava.
    let mut q = Pote::novo();
    for sc in ["a=1; SameSite=Strict", "b=1; SameSite=Lax", "c=1"] {
        assert_eq!(
            da_rede_em(&mut q, CIFRADA, busca, sc, None),
            Err(Recusa::MesmoSite)
        );
        assert_eq!(
            da_rede_em(&mut q, CIFRADA, navega, sc, None),
            Ok(Guardado::Novo)
        );
    }
    assert_eq!(
        da_rede_em(&mut q, CIFRADA, busca, "d=1; SameSite=None; Secure", None),
        Ok(Guardado::Novo)
    );
}

#[test]
fn o_httponly_nao_sai_do_pote_para_o_programa() {
    let mut p = Pote::novo();
    da_rede(&mut p, BANCADA, "sessao=segredo; HttpOnly", None).unwrap();
    da_rede(&mut p, BANCADA, "tema=escuro", None).unwrap();
    // Vai ao servidor...
    assert_eq!(
        cookie(&mut p, BANCADA, None).as_deref(),
        Some("sessao=segredo; tema=escuro")
    );
    // ... e o programa não o vê.
    assert_eq!(
        visiveis(&mut p, BANCADA, None),
        vec![(String::from("tema"), String::from("escuro"))]
    );
    // A API do programa não cria um `HttpOnly`, nem sobrescreve um.
    assert_eq!(
        definir(&mut p, BANCADA, "outro=1; HttpOnly", None),
        Err(Recusa::SoHttp)
    );
    assert_eq!(
        definir(&mut p, BANCADA, "sessao=forjada", None),
        Err(Recusa::SoHttp)
    );
    assert_eq!(
        definir(&mut p, BANCADA, "sessao=; Max-Age=0", None),
        Err(Recusa::SoHttp)
    );
    assert_eq!(
        cookie(&mut p, BANCADA, None).as_deref(),
        Some("sessao=segredo; tema=escuro")
    );
    // E escreve o que não é `HttpOnly`, com as mesmas regras.
    assert_eq!(
        definir(&mut p, BANCADA, "tema=claro", None),
        Ok(Guardado::Substituido)
    );
    assert_eq!(
        definir(&mut p, BANCADA, "x=1; Secure", None),
        Err(Recusa::Seguro)
    );
    assert_eq!(
        definir(&mut p, BANCADA, "x\r\n=1", None),
        Err(Recusa::Formato)
    );
    assert_eq!(
        cookie(&mut p, BANCADA, None).as_deref(),
        Some("sessao=segredo; tema=claro")
    );
    // A rede sobrescreve o `HttpOnly`.
    assert_eq!(
        da_rede(&mut p, BANCADA, "sessao=nova; HttpOnly", None),
        Ok(Guardado::Substituido)
    );
}

#[test]
fn cada_pote_e_um_estado() {
    let mut um = Pote::novo();
    let mut outro = Pote::novo();
    da_rede(&mut um, BANCADA, "sessao=1; HttpOnly", None).unwrap();
    assert_eq!(cookie(&mut outro, BANCADA, None), None);
    assert!(visiveis(&mut outro, BANCADA, None).is_empty());
    // O clone é uma cópia: nada do que um faz chega ao outro.
    let mut copia = um.clone();
    da_rede(&mut copia, BANCADA, "sessao=2; HttpOnly", None).unwrap();
    assert_eq!(cookie(&mut um, BANCADA, None).as_deref(), Some("sessao=1"));
    um.limpar();
    assert_eq!(cookie(&mut um, BANCADA, None), None);
    assert_eq!(
        cookie(&mut copia, BANCADA, None).as_deref(),
        Some("sessao=2")
    );
}

#[test]
fn os_limites_e_o_despejo() {
    // Por domínio: o 51º tira o usado há mais tempo do mesmo domínio — e
    // o uso conta, não só a criação.
    let mut p = Pote::novo();
    da_rede(&mut p, BANCADA, "c0=1; Path=/a", None).unwrap();
    for i in 1..50 {
        da_rede(&mut p, BANCADA, &format!("c{i}=1; Path=/b"), None).unwrap();
    }
    da_rede(&mut p, "http://outro.duke/", "fora=1", None).unwrap();
    // O `c0`, o mais velho, foi usado agora: o usado há mais tempo passa a
    // ser o `c1`.
    assert_eq!(
        cookie(&mut p, "http://bancada.duke/a", None).as_deref(),
        Some("c0=1")
    );
    da_rede(&mut p, BANCADA, "c50=1; Path=/b", None).unwrap();
    assert_eq!(p.quantos(), 51);
    let b = cookie(&mut p, "http://bancada.duke/b", None).unwrap();
    assert_eq!(b.split("; ").count(), 49);
    assert!(!b.contains("c1="), "{b}");
    assert!(b.contains("c50=1"), "{b}");
    assert_eq!(
        cookie(&mut p, "http://bancada.duke/a", None).as_deref(),
        Some("c0=1")
    );
    // O outro domínio não perdeu nada.
    assert_eq!(
        cookie(&mut p, "http://outro.duke/", None).as_deref(),
        Some("fora=1")
    );

    // O total, entre domínios.
    let limites = LimitesDoPote {
        total: 10,
        ..LimitesDoPote::default()
    };
    let mut p = Pote::com_limites(limites);
    for i in 0..12 {
        da_rede(&mut p, &format!("http://h{i}.duke/"), "x=1", None).unwrap();
    }
    assert_eq!(p.quantos(), 10);
    assert_eq!(cookie(&mut p, "http://h0.duke/", None), None);
    assert_eq!(cookie(&mut p, "http://h1.duke/", None), None);
    assert!(cookie(&mut p, "http://h2.duke/", None).is_some());

    // Os bytes.
    let limites = LimitesDoPote {
        bytes: 2000,
        ..LimitesDoPote::default()
    };
    let mut p = Pote::com_limites(limites);
    for i in 0..5 {
        da_rede(&mut p, BANCADA, &format!("g{i}={}", "v".repeat(500)), None).unwrap();
    }
    assert!(p.bytes() <= 2000, "{}", p.bytes());
    assert_eq!(p.quantos(), 3);

    // Os vencidos saem primeiro, antes de qualquer um que vale.
    let limites = LimitesDoPote {
        total: 3,
        ..LimitesDoPote::default()
    };
    let mut p = Pote::com_limites(limites);
    da_rede(&mut p, BANCADA, "vale1=1", Some(T)).unwrap();
    da_rede(&mut p, BANCADA, "vence=1; Max-Age=5", Some(T)).unwrap();
    da_rede(&mut p, BANCADA, "vale2=1", Some(T)).unwrap();
    da_rede(&mut p, BANCADA, "vale3=1; Max-Age=60", Some(T + 10)).unwrap();
    assert_eq!(
        cookie(&mut p, BANCADA, Some(T + 10)).as_deref(),
        Some("vale1=1; vale2=1; vale3=1")
    );
}

#[test]
fn o_monte_do_pote_tem_teto() {
    // Um servidor mandando o maior cookie de novo e de novo, com nomes
    // novos: o pote fica nos limites, e a memória com ele.
    let ((), pico) = pico_de(|| {
        let mut p = Pote::novo();
        for i in 0..2000 {
            let sc = format!("n{i}={}", "v".repeat(4000));
            let host = format!("http://h{}.duke/", i % 40);
            let _ = da_rede(&mut p, &host, &sc, None);
        }
        assert!(p.bytes() <= 128 * 1024, "{}", p.bytes());
        assert!(p.quantos() <= 300);
    });
    assert!(pico < 1024 * 1024, "{pico}");
}

#[test]
fn nada_do_que_o_servidor_manda_quebra_o_pote() {
    // Uma bateria de `Set-Cookie` arbitrários, de um gerador fixo: nenhum
    // derruba o pote, e o que entra respeita o que o pote promete.
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    let mut proximo = || {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (x >> 33) as usize
    };
    const PEDACOS: [&str; 24] = [
        "a",
        "=",
        ";",
        " ",
        "Domain=",
        "bancada.duke",
        ".duke",
        "Path=",
        "/",
        "/a",
        "Secure",
        "HttpOnly",
        "SameSite=",
        "None",
        "Lax",
        "Strict",
        "Max-Age=",
        "-1",
        "60",
        "Expires=",
        "Thu, 01 Jan 1970 00:00:00 GMT",
        "__Host-",
        "__Secure-",
        "\t",
    ];
    let urls = [
        "http://bancada.duke/a/b",
        "https://bancada.duke/",
        "http://www.bancada.duke/",
        "http://10.0.2.100/",
    ];
    let mut p = Pote::com_limites(LimitesDoPote {
        total: 20,
        por_dominio: 8,
        ..LimitesDoPote::default()
    });
    for i in 0..20_000 {
        let n = proximo() % 12;
        let sc: String = (0..n).map(|_| PEDACOS[proximo() % PEDACOS.len()]).collect();
        let u = urls[proximo() % urls.len()];
        let t = if i % 3 == 0 { None } else { Some(T + i) };
        let _ = da_rede(&mut p, u, &sc, t);
        let _ = definir(&mut p, u, &sc, t);
        assert!(p.quantos() <= 20);
        for u in urls {
            if let Some(c) = cookie(&mut p, u, t) {
                assert!(!c.bytes().any(|b| b == b'\r' || b == b'\n'), "{c:?}");
                // Por `http`, nada seguro — e um prefixo só existe seguro.
                if u.starts_with("http:") {
                    for par in c.split("; ") {
                        let nome = par.split('=').next().unwrap().to_ascii_lowercase();
                        assert!(
                            !nome.starts_with("__host-") && !nome.starts_with("__secure-"),
                            "{c:?}"
                        );
                    }
                }
            }
        }
    }
}

// A troca com o pote, pelo cliente.

/// As respostas de um servidor de mentira, uma por pedido.
fn servidor(respostas: &[&str]) -> Cliente<Roteiro> {
    let mut chegada = Vec::new();
    let mut rodadas = Vec::new();
    for r in respostas {
        chegada.extend_from_slice(r.as_bytes());
        rodadas.push(chegada.len());
    }
    let mut roteiro = Roteiro::novo(&chegada, 7);
    roteiro.rodadas = rodadas;
    Cliente::novo(roteiro)
}

fn pedidos_mandados(c: &mut Cliente<Roteiro>) -> String {
    String::from_utf8(c.fluxo().mandado.clone()).unwrap()
}

#[test]
fn a_troca_com_o_pote() {
    let mut c = servidor(&[
        "HTTP/1.1 200 OK\r\nSet-Cookie: sessao=abc; HttpOnly; Path=/\r\n\
         Set-Cookie: tema=claro\r\nSet-Cookie: =ruim\r\nX-Outro: sim\r\n\
         Content-Length: 2\r\n\r\nok",
        "HTTP/1.1 200 OK\r\nSet-Cookie: tema=; Max-Age=0\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 302 Found\r\nSet-Cookie: depois=1\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    ]);
    let mut pote = Pote::novo();
    let mut relogio = || Some(T);
    let limites = Limites::default();
    let get =
        |caminho: &str| Pedido::novo(Metodo::Get, url(&format!("http://bancada.duke{caminho}")));

    let r = c
        .trocar_com_pote(&get("/entrar"), &limites, &mut pote, &mut relogio)
        .unwrap();
    // Os `Set-Cookie` foram para o pote, e saíram do que o programa vê.
    assert!(
        r.cabecalhos.iter().all(|(n, _)| n != "set-cookie"),
        "{:?}",
        r.cabecalhos
    );
    assert!(
        r.cabecalhos
            .iter()
            .any(|(n, v)| n == "x-outro" && v == "sim")
    );
    assert_eq!(
        r.cookies,
        Guardados {
            novos: 2,
            substituidos: 0,
            apagados: 0,
            recusados: 1,
            retidos: 0
        }
    );
    let r = c
        .trocar_com_pote(&get("/sair"), &limites, &mut pote, &mut relogio)
        .unwrap();
    assert_eq!(r.cookies.apagados, 1);
    // A resposta 3xx também grava: quem segue o `Location` é o programa.
    let r = c
        .trocar_com_pote(&get("/vai"), &limites, &mut pote, &mut relogio)
        .unwrap();
    assert_eq!(r.status, 302);
    assert_eq!(r.cookies.novos, 1);
    c.trocar_com_pote(&get("/fim"), &limites, &mut pote, &mut relogio)
        .unwrap();
    // Cada pedido levou o que o pote tinha antes dele — um `Cookie` só.
    let mandados = pedidos_mandados(&mut c);
    let pedidos: Vec<&str> = mandados.split("GET ").skip(1).collect();
    assert_eq!(pedidos.len(), 4);
    assert!(!pedidos[0].contains("Cookie"), "{}", pedidos[0]);
    assert!(
        pedidos[1].contains("\r\nCookie: sessao=abc; tema=claro\r\n"),
        "{}",
        pedidos[1]
    );
    assert!(
        pedidos[2].contains("\r\nCookie: sessao=abc\r\n"),
        "{}",
        pedidos[2]
    );
    assert!(
        pedidos[3].contains("\r\nCookie: sessao=abc; depois=1\r\n"),
        "{}",
        pedidos[3]
    );
    for p in &pedidos {
        assert!(p.matches("Cookie").count() <= 1, "{p}");
    }
}

#[test]
fn sem_pote_nada_de_cookie() {
    // A troca sem pote não manda cookie, e devolve os `Set-Cookie` como
    // vieram — o programa que não quer pote fica com eles.
    let mut c = servidor(&["HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nContent-Length: 0\r\n\r\n"]);
    let r = c
        .trocar(
            &Pedido::novo(Metodo::Get, url(BANCADA)),
            &Limites::default(),
        )
        .unwrap();
    assert!(
        r.cabecalhos
            .iter()
            .any(|(n, v)| n == "set-cookie" && v == "a=1")
    );
    assert_eq!(r.cookies, Guardados::default());
    assert!(!pedidos_mandados(&mut c).contains("Cookie"));
    // E o `Cookie` é do pacote: quem chama não o escreve.
    let mut p = Pedido::novo(Metodo::Get, url(BANCADA));
    assert_eq!(
        p.cabecalho("cookie", "sessao=forjada"),
        Err(crate::ErroDePedido::Reservado)
    );
}

#[test]
fn a_troca_que_falha_nao_grava_cookie() {
    // A resposta grande demais: o `Set-Cookie` dela não entra.
    let mut c =
        servidor(&["HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nContent-Length: 10\r\n\r\n0123456789"]);
    let mut pote = Pote::novo();
    let limites = Limites {
        corpo: 5,
        ..Limites::default()
    };
    let r = c.trocar_com_pote(
        &Pedido::novo(Metodo::Get, url(BANCADA)),
        &limites,
        &mut pote,
        &mut || Some(T),
    );
    assert_eq!(r.unwrap_err(), Erro::Limite(Limite::Corpo));
    assert_eq!(pote.quantos(), 0);
    // E o transporte que falha também não.
    let mut roteiro = Roteiro::novo(b"HTTP/1.1 200 OK\r\nSet-Cookie: b=1\r\n", 64);
    roteiro.rodadas = vec![34];
    let mut c = Cliente::novo(roteiro);
    let r = c.trocar_com_pote(
        &Pedido::novo(Metodo::Get, url(BANCADA)),
        &Limites::default(),
        &mut pote,
        &mut || Some(T),
    );
    assert!(r.is_err());
    assert_eq!(pote.quantos(), 0);
    let _ = FalhaDeTeste("nada");
}

#[test]
fn o_contexto_do_pedido_vai_ao_pote() {
    let mut c = servidor(&[
        "HTTP/1.1 200 OK\r\nSet-Cookie: e=1; SameSite=Strict\r\n\
         Set-Cookie: l=1; SameSite=None; Secure\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    ]);
    let mut pote = Pote::novo();
    let mut relogio = || None;
    let limites = Limites::default();
    c.trocar_com_pote(
        &Pedido::novo(Metodo::Get, url(CIFRADA)),
        &limites,
        &mut pote,
        &mut relogio,
    )
    .unwrap();
    let mut de_outro = Pedido::novo(Metodo::Post, url(CIFRADA));
    de_outro.contexto = Contexto::DeOutroSite { navegacao: true };
    c.trocar_com_pote(&de_outro, &limites, &mut pote, &mut relogio)
        .unwrap();
    let mandados = pedidos_mandados(&mut c);
    assert!(mandados.contains("\r\nCookie: l=1\r\n"), "{mandados}");
    assert!(!mandados.contains("e=1"), "{mandados}");
}

#[test]
fn o_contexto_do_pedido_vale_para_a_resposta() {
    // A resposta a um pedido de outro site, que não é navegação, não põe
    // `Strict` nem `Lax` — só o `None`.
    let mut c = servidor(&["HTTP/1.1 200 OK\r\nSet-Cookie: x=1; SameSite=Lax\r\n\
         Set-Cookie: y=1; SameSite=None; Secure\r\nContent-Length: 0\r\n\r\n"]);
    let mut pote = Pote::novo();
    let mut relogio = || None;
    let mut de_outro = Pedido::novo(Metodo::Get, url(CIFRADA));
    de_outro.contexto = Contexto::DeOutroSite { navegacao: false };
    let r = c
        .trocar_com_pote(&de_outro, &Limites::default(), &mut pote, &mut relogio)
        .unwrap();
    assert_eq!((r.cookies.novos, r.cookies.recusados), (1, 1));
    assert_eq!(cookie(&mut pote, CIFRADA, None).as_deref(), Some("y=1"));
}

#[test]
fn a_troca_le_o_relogio_uma_vez() {
    let mut c = servidor(&[
        "HTTP/1.1 200 OK\r\nSet-Cookie: v=1; Max-Age=60\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nSet-Cookie: w=1; Max-Age=60\r\nContent-Length: 0\r\n\r\n",
    ]);
    let leituras = core::cell::Cell::new(0);
    let mut relogio = || {
        leituras.set(leituras.get() + 1);
        Some(T)
    };
    let mut pote = Pote::novo();
    let limites = Limites::default();
    let get = Pedido::novo(Metodo::Get, url(BANCADA));
    // O pote vazio não lê; o `Set-Cookie` com validade lê.
    c.trocar_com_pote(&get, &limites, &mut pote, &mut relogio)
        .unwrap();
    assert_eq!(leituras.get(), 1);
    // O pedido leva o `v`, que tem validade, e a resposta traz o `w`: uma
    // leitura para os dois.
    c.trocar_com_pote(&get, &limites, &mut pote, &mut relogio)
        .unwrap();
    assert_eq!(leituras.get(), 2);
}

#[test]
fn sem_relogio_a_troca_diz_quantos_ficaram() {
    let mut c = servidor(&[
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    ]);
    let mut pote = Pote::novo();
    for sc in ["v=1; Max-Age=60", "w=1; Max-Age=60", "s=1"] {
        da_rede(&mut pote, BANCADA, sc, Some(T)).unwrap();
    }
    let limites = Limites::default();
    let get = Pedido::novo(Metodo::Get, url(BANCADA));
    // Sem relógio — o gate recusou, ou o sistema não tem —, os dois com
    // validade ficam, e a resposta diz quantos.
    let mut sem = || None;
    let r = c
        .trocar_com_pote(&get, &limites, &mut pote, &mut sem)
        .unwrap();
    assert_eq!(r.cookies.retidos, 2);
    let mut com = || Some(T + 1);
    let r = c
        .trocar_com_pote(&get, &limites, &mut pote, &mut com)
        .unwrap();
    assert_eq!(r.cookies.retidos, 0);
    let mandados = pedidos_mandados(&mut c);
    let pedidos: Vec<&str> = mandados.split("GET ").skip(1).collect();
    assert!(pedidos[0].contains("\r\nCookie: s=1\r\n"), "{}", pedidos[0]);
    assert!(
        pedidos[1].contains("\r\nCookie: v=1; w=1; s=1\r\n"),
        "{}",
        pedidos[1]
    );
}
