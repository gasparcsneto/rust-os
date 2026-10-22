//! A rede principal do IC, de verdade: pergunta ao livro-razão do ICP — o
//! canister [`LIVRO_RAZAO`], na sub-rede do NNS — o símbolo dele
//! (`icrc1_symbol`), pela rede `mainnet` de `/dados/icp/redes`, e espera
//! `ICP`, verificado. Só a fumaça real o lança (`cargo xtask mainnet`): a
//! CI não depende da rede principal.
//!
//! O caminho é o de qualquer consulta, medido
//! ([`programas::icp::consultar_medindo`]):
//!
//! 1. `icp-api.io` pelo DNS do emulador, [`DNS`] — que repassa a pergunta
//!    ao resolvedor do hospedeiro —, numa associação que o gate decide. O
//!    DNS só dá um endereço: um DNS que mente leva, no máximo, a uma
//!    conexão que o gate, o TLS ou a verificação recusam;
//! 2. o destino, `tcp:<ipv4>:443`, pelo gate, como se o número tivesse
//!    sido digitado: o nome não autoriza nada, e o endereço fora da
//!    política é `DENY_RESOURCE` antes de qualquer byte;
//! 3. o TLS 1.3 pelas âncoras públicas da imagem, [`PUBLICAS`] — nada que o
//!    servidor mande vira âncora —, provando o nome `icp-api.io`;
//! 4. o `read_state` da sub-rede do canister e o `query`, cada `net.send`
//!    e cada `net.recv` decididos de novo pelo gate;
//! 5. a verificação: o certificado da sub-rede até a raiz do arquivo de
//!    redes — nunca a que a rede anuncia —, e a resposta contra os nós
//!    dele, com a hora da regra de `protocolo::usuario::hora`. Nada é
//!    entregue antes dela.
//!
//! Diz cada parte numa linha `livro: …` — a rede, o destino, o TLS, a
//! medida de cada parte, a prova e o símbolo —, declara a consulta por
//! `audit.declare`, ancorada na conexão em que foi, e sai com [`CODIGO`]
//! quando o símbolo verificado é `ICP`; com um código menor, que diz o
//! quê, quando não.
//!
//! # O que o programa não é
//!
//! O canister, o método, o Principal e o certificado não dão nada a este
//! processo: o que ele pode é o que o gate decide para os pedidos dele,
//! com a autoridade de quem o lançou. Uma resposta verificada prova o que
//! os nós da rede principal responderam a este pedido, e não é `ALLOW` de
//! nada.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "livro",
    "net.connect",
    "random.read",
    "system.read",
    "fs.read",
    "audit.declare"
);

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use programas::escreverln;
use programas::icp::{self, Desfecho, Principal, Valor};
use programas::tls;

/// O código de saída quando o símbolo verificado é `ICP`. A fumaça real o
/// procura.
const CODIGO: i64 = 85;

/// Os códigos de cada falha.
const SEM_ANCORAS: i64 = 30;
const SEM_REDES: i64 = 31;
const SEM_A_REDE: i64 = 32;
const SEM_O_CANISTER: i64 = 33;
const NAO_VERIFICOU: i64 = 34;
const OUTRO_SIMBOLO: i64 = 35;

/// A rede principal, em `/dados/icp/redes`.
const REDE: &str = "mainnet";

/// O livro-razão do ICP, na sub-rede do NNS da rede principal.
const LIVRO_RAZAO: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";

/// O método, e o símbolo que ele tem de responder.
const METODO: &str = "icrc1_symbol";
const SIMBOLO: &str = "ICP";

/// As raízes públicas da imagem: as da autoridade do endpoint da rede
/// principal.
const PUBLICAS: &str = "/dados/tls/publicas.pem";

/// O DNS do emulador, que repassa ao resolvedor do hospedeiro: o que
/// conhece `icp-api.io`.
const DNS: &str = "udp:10.0.2.3:53";

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let ancoras = match tls::ancoras(PUBLICAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("livro: as ancoras publicas nao se leram: {}", f.codigo());
            return SEM_ANCORAS;
        }
    };
    let redes = match icp::redes() {
        Ok(r) => r,
        Err(f) => {
            escreverln!("livro: as redes nao se leram: {}", f);
            return SEM_REDES;
        }
    };
    let Some(rede) = redes.iter().find(|r| r.nome == REDE) else {
        escreverln!("livro: a rede {} nao esta no arquivo", REDE);
        return SEM_A_REDE;
    };
    let Ok(livro) = Principal::de_texto(LIVRO_RAZAO) else {
        escreverln!("livro: o canister nao se le");
        return SEM_O_CANISTER;
    };
    escreverln!(
        "livro: rede {} https://{}:{} {}; raiz da sub-rede {}; {} ancoras",
        rede.nome,
        rede.host,
        rede.porta,
        match rede.endereco {
            Some([a, b, c, d]) => format!("endereco {a}.{b}.{c}.{d}"),
            None => String::from("dns"),
        },
        rede.raiz.sub_rede().texto(),
        ancoras.quantas()
    );

    let sem_argumentos = Vec::from(*b"DIDL\x00\x00");
    let c = icp::consultar_medindo(rede, &ancoras, DNS, &livro, METODO, &sem_argumentos);
    let m = &c.medida;
    escreverln!(
        "livro: destino {}",
        m.conexao.destino.as_deref().unwrap_or("nenhum")
    );
    escreverln!("livro: tls {}", c.suite.unwrap_or("nenhum"));
    escreverln!(
        "livro: medida preparo {} dns {} tcp {} tls {} http {} verificacao {} total {}",
        m.preparo_ms + m.conexao.preparo_ms,
        m.conexao.dns_ms,
        m.conexao.tcp_ms,
        m.conexao.tls_ms,
        m.http_ms,
        m.verificacao_ms,
        m.total_ms
    );
    let declarada = match &c.declarada {
        Ok(n) => format!("{n}"),
        Err(codigo) => format!("recusada {codigo}"),
    };
    let hora = c.hora.map_or("nenhuma", |h| h.estado.nome());
    let v = match &c.r {
        Ok(v) => v,
        Err(f) => {
            escreverln!(
                "livro: {}: {}; declarada {}; hora {}; {}",
                METODO,
                icp::desfecho(&c.r),
                declarada,
                hora,
                f
            );
            return NAO_VERIFICOU;
        }
    };
    escreverln!(
        "livro: prova sub-rede {} {}; certificado {} s; assinaturas {}/{}; pedido {}",
        v.sub_rede.texto(),
        if v.delegada { "delegada" } else { "da raiz" },
        v.tempo_do_certificado_ns / 1_000_000_000,
        v.assinaturas,
        v.nos,
        hex(&v.id_do_pedido)
    );
    let resposta = match &v.desfecho {
        Desfecho::Respondida(bytes) => match icp::candid::decodificar(bytes) {
            Ok(valores) => match valores.as_slice() {
                [Valor::Texto(t)] => format!("texto {t}"),
                outros => format!("{} valores", outros.len()),
            },
            Err(e) => format!("recusado: {e}"),
        },
        Desfecho::Recusada { codigo, erro, .. } => {
            format!("recusa {codigo} {}", erro.as_deref().unwrap_or("-"))
        }
    };
    escreverln!(
        "livro: {}: {}; declarada {}; hora {}; {}",
        METODO,
        icp::desfecho(&c.r),
        declarada,
        hora,
        resposta
    );
    if resposta != format!("texto {SIMBOLO}") {
        return OUTRO_SIMBOLO;
    }
    escreverln!("livro: o simbolo verificado e {}", SIMBOLO);
    CODIGO
}

/// Bytes em hexadecimal minúsculo.
fn hex(bytes: &[u8]) -> String {
    const DIGITOS: &[u8; 16] = b"0123456789abcdef";
    let mut t = String::with_capacity(2 * bytes.len());
    for b in bytes {
        t.push(char::from(DIGITOS[usize::from(b >> 4)]));
        t.push(char::from(DIGITOS[usize::from(b & 0xf)]));
    }
    t
}
