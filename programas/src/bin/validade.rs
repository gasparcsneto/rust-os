//! Diz com que hora o sistema confere validades — a dos certificados do TLS
//! e a dos cookies —, e o que ela deu, para a bancada de tempo conferir em
//! cada estado do relógio.
//!
//! - **a hora**: a do objeto `time` do `system.info`, pelo gate, e pela
//!   regra de `protocolo::usuario::hora` — o civil quando a hora é
//!   autenticada, o tempo lógico quando não é. O programa diz o estado, se
//!   a hora era autenticada, e os segundos de cada relógio;
//! - **o TLS**: `bancada.duke` (válido de 2025 a 2040), `vencido.duke` (de
//!   2020 a 2021) e `futuro.duke` (de 2042 a 2044, ainda não válido), no
//!   eco TLS da bancada: aceito, ou o código da recusa;
//! - **os cookies**: um `Expires` de 2023, um de 2100 e um `Max-Age=10`,
//!   pelo servidor HTTP da bancada: os que o pote levou logo depois de
//!   guardar, e os que ele leva 12 s depois — a bancada espera do lado
//!   dela. Dez segundos, e não três: o relógio dos cookies é em segundos, e
//!   a janela antes do primeiro pedido é a do `Max-Age` menos a fração do
//!   segundo em que se guardou e o trabalho de uma conexão nova — com três
//!   processos, rodadas e o NSF ao mesmo tempo, mais de dois segundos. E
//!   doze, e não 10,1: o relógio dos cookies é o civil, e num ajuste
//!   gradual ele anda até 5% mais devagar que o contador (ver
//!   `hora::disciplina`) — dez segundos dele podem ser 10,5 do hospedeiro,
//!   fora a deriva do contador. Com 10,1, a bancada de tempo do ARM viu o
//!   `vence` ir depois, logo que as fontes voltaram.
//!
//! O programa não julga: diz o que viu, e a bancada sabe o que cada estado
//! deve dar. Sai com [`CODIGO`] quando disse tudo, e com um código menor
//! quando algo nem se pôde perguntar.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "validade",
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
    self, Contexto, Falha, Limites, Metodo, Opcoes, Pedido, Pote, Protocolo, Resolucao, Resposta,
    Url,
};
use programas::tls;

/// Disse tudo. A bancada de tempo o procura.
const CODIGO: i64 = 77;
/// A hora não se leu.
const SEM_HORA: i64 = 71;
/// As âncoras não se leram.
const SEM_ANCORAS: i64 = 72;
/// A bancada HTTP não respondeu como devia.
const BANCADA_HTTP: i64 = 73;

/// A raiz da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// O eco TLS da bancada.
const ECO_TLS: &str = "tcp:10.0.2.100:443";

/// O servidor HTTP da bancada, sem DNS.
const BANCADA: [u8; 4] = [10, 0, 2, 100];

const CLARA: &str = "http://bancada.duke";

/// Os cookies com validade: um que venceu antes do piso de qualquer boot
/// desta bancada e depois do RTC atrasado dela, um que não vence, e um que
/// vence em 10 s.
const COOKIES: [&str; 3] = [
    "antigo=1; Expires=Sun, 01 Jan 2023 00:00:00 GMT",
    "futuro=1; Expires=Fri, 31 Dec 2100 23:59:59 GMT",
    "vence=1; Max-Age=10",
];

/// Um `GET` de `url` com `pote`, numa conexão só.
fn pedir(pote: &mut Pote, url: &str, opcoes: &Opcoes<'_>) -> Result<Resposta, Falha> {
    let url = Url::ler(url).map_err(Falha::Url)?;
    let mut pedido = Pedido::novo(Metodo::Get, url);
    pedido.contexto = Contexto::DoProprioSite;
    http::buscar_com_pote(pedido, opcoes, &Limites::default(), pote)
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

/// Os nomes dos cookies que o servidor recebeu num `/cookies/eco` — os
/// valores ficam de fora.
fn eco(pote: &mut Pote, opcoes: &Opcoes<'_>) -> Result<String, i64> {
    let url = format!("{CLARA}/cookies/eco");
    match pedir(pote, &url, opcoes) {
        Ok(r) if r.status == 200 => {
            let mut corpo = http::texto(&r);
            if corpo.ends_with('\n') {
                corpo.pop();
            }
            if corpo == "-" {
                return Ok(String::from("nenhum"));
            }
            let nomes: Vec<&str> = corpo
                .split("; ")
                .map(|par| par.split('=').next().unwrap_or(""))
                .collect();
            Ok(nomes.join(","))
        }
        Ok(r) => {
            escreverln!("validade: {} deu {}", url, r.status);
            Err(BANCADA_HTTP)
        }
        Err(f) => {
            escreverln!("validade: {} falhou: {}", url, f.codigo());
            Err(BANCADA_HTTP)
        }
    }
}

/// O TLS: o que cada nome deu, pela hora do sistema.
fn tls_de(ancoras: &tls::Ancoras) {
    for nome in ["bancada.duke", "vencido.duke", "futuro.duke"] {
        match tls::conectar(ECO_TLS, nome, ancoras) {
            Ok(sessao) => {
                let _ = sessao.fechar();
                escreverln!("validade: tls {} -> aceito", nome);
            }
            Err(f) => {
                escreverln!("validade: tls {} -> {}", nome, f.codigo());
            }
        }
    }
}

/// Os cookies: os que o pote levou logo depois de guardar, e 12 s depois.
fn cookies(ancoras: &tls::Ancoras) -> Result<(), i64> {
    let opcoes = Opcoes {
        resolucao: Resolucao::Fixa(BANCADA),
        ancoras: Some(ancoras),
        prazo: Prazo {
            espera_ms: 5_000,
            esperas: 4,
        },
        protocolo: Protocolo::Http1,
    };
    let mut pote = Pote::novo();
    let consulta: Vec<String> = COOKIES
        .iter()
        .map(|c| format!("c={}", por_cento(c)))
        .collect();
    let url = format!("{CLARA}/cookies/definir?{}", consulta.join("&"));
    match pedir(&mut pote, &url, &opcoes) {
        Ok(r) if r.status == 200 => {}
        Ok(r) => {
            escreverln!("validade: definir deu {}", r.status);
            return Err(BANCADA_HTTP);
        }
        Err(f) => {
            escreverln!("validade: definir falhou: {}", f.codigo());
            return Err(BANCADA_HTTP);
        }
    }
    let antes = eco(&mut pote, &opcoes)?;
    escreverln!("validade: cookies antes {}", antes);
    // A bancada espera do lado dela: o programa não tem como dormir.
    match pedir(&mut pote, &format!("{CLARA}/lento/12000"), &opcoes) {
        Ok(r) if r.status == 200 => {}
        _ => {
            escreverln!("validade: a espera da bancada falhou");
            return Err(BANCADA_HTTP);
        }
    }
    let depois = eco(&mut pote, &opcoes)?;
    escreverln!("validade: cookies depois {}", depois);
    Ok(())
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let hora = match tls::hora() {
        Ok(h) => h,
        Err(f) => {
            escreverln!("validade: sem hora: {}", f.codigo());
            return SEM_HORA;
        }
    };
    escreverln!("validade: a hora {}", hora);
    escreverln!(
        "validade: segundos {} civil {} logico {}",
        hora.validade_s(),
        hora.civil_ms / 1000,
        hora.logico_s
    );
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("validade: as ancoras nao se leram: {}", f.codigo());
            return SEM_ANCORAS;
        }
    };
    tls_de(&ancoras);
    if let Err(codigo) = cookies(&ancoras) {
        return codigo;
    }
    CODIGO
}
