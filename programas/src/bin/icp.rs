//! Consulta o canister da bancada do Internet Computer, e confere de dentro
//! o que a consulta verificada promete — e o que ela **não** faz: dar
//! acesso.
//!
//! O programa lê as âncoras do TLS da bancada e as redes em que confia
//! (`/dados/icp/redes`), diz `icp: pronto` e espera um evento no canal
//! [`CANAL`] — ou, se outro `icp` já o escuta, diz `icp: pronto pelo
//! segundo canal` e espera no [`SEGUNDO_CANAL`]: dois processos ao mesmo
//! tempo, cada um ditado pelo seu. A cada evento [`tipo::ACAO`], o `a` diz o
//! passo, e o `b`, a rede — o índice em [`REDES`]. Cada passo é uma
//! conexão nova com o endpoint da rede, pelo caminho inteiro: o DNS, o
//! destino no gate, o TLS, os dois `POST` da consulta e a verificação.
//!
//! - [`OLA`]: o método `ola`, sem argumentos — a resposta é o texto `ola`;
//! - [`ECO`]: o método `eco`, com o texto `duke` — a resposta tem de ser
//!   ele;
//! - [`RECUSA`]: o método `recusa`, que o canister recusa: a recusa
//!   assinada pelos nós também é uma resposta verificada;
//! - [`CANDID`]: o método `candid_<c>` — `truncado`, `sobra`, `magica` —,
//!   que responde Candid fora da forma: verificado, e recusado na leitura;
//! - [`PRINCIPAL_INVALIDO`]: dois canisters que não são Principal — um
//!   texto fora da base32, e o da bancada com um caractere trocado, que se
//!   lê e tem o tamanho certo, mas a soma não confere: nada sai, e nada se
//!   declara;
//! - [`SAIR_SEM_FECHAR`]: sai sem fechar nada — o kernel recolhe as
//!   conexões de quem acabou.
//!
//! Antes de cada pedido, diz `icp: <passo> pede <etapa>` — `read_state` ou
//! `query`: a suíte sabe assim que o programa espera a resposta daquele
//! pedido, e age no meio da consulta. Depois de cada passo, diz
//! `icp: <passo>: <desfecho>; declarada
//! <registro>; hora <estado>; <detalhe>` — o desfecho numa palavra
//! (`programas::icp::desfecho`), o registro da declaração na auditoria —
//! ou o código de quem a recusou —, o estado do relógio com que conferiu,
//! e o que a verificação provou ou por que não provou. O detalhe vai por
//! último: uma linha passa de [`programas::saida::LINHA`] com o nome de um
//! nó, e o corte só come o fim. A declaração vai antes do fecho da
//! conexão: ancorada nela, o kernel escreve o destino real. Sai com
//! [`CODIGO`] quando a suíte pede o fim.
//!
//! # O que o programa não é
//!
//! O canister, o método, o Principal e o certificado não dão nada a este
//! processo: o que ele pode é o que o gate decide para os pedidos dele —
//! `fs.read`, `random.read`, `system.info`, `net.connect` e
//! `audit.declare`, com a autoridade de quem o lançou. Uma resposta
//! verificada prova o que os nós responderam, e não é `ALLOW` de nada.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "icp",
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
use programas::icp::{self, Desfecho, Falha, Principal, Rede, Valor, Verificada};
use programas::sistema;
use programas::tls::{self, Ancoras};
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 93;

/// O código de saída de [`SAIR_SEM_FECHAR`].
const SEM_FECHAR: i64 = 94;

/// O canal por onde a suíte dita o passo.
const CANAL: &str = "teste-icp";

/// O canal de um segundo `icp`, com o primeiro vivo.
const SEGUNDO_CANAL: &str = "teste-icp-2";

/// Os passos — a suíte tem as mesmas constantes.
const OLA: i64 = 1;
const ECO: i64 = 2;
const RECUSA: i64 = 3;
const CANDID: i64 = 4;
const PRINCIPAL_INVALIDO: i64 = 5;
const SAIR_SEM_FECHAR: i64 = 6;

/// As redes, pelo índice que o `b` de um evento diz — os nomes de
/// `/dados/icp/redes` da bancada. Cada uma é o mesmo canister por um
/// endpoint que o proxy da bancada trata de um jeito: o honesto, o lento,
/// e os que adulteram a resposta, cada um de uma maneira; a de chave
/// errada, honesta e com outra raiz; e a honesta sem DNS.
const REDES: [&str; 12] = [
    "bancada",
    "lenta",
    "raiz-errada",
    "bls-invalida",
    "sem-assinatura",
    "no-de-fora",
    "assinatura-errada",
    "pedido-trocado",
    "aninhada",
    "faixa-errada",
    "velho",
    "direta",
];

/// Os métodos que respondem Candid fora da forma, pelo `c` de um evento
/// [`CANDID`].
const FORA_DA_FORMA: [&str; 3] = ["candid_truncado", "candid_sobra", "candid_magica"];

/// O canister da bancada: o primeiro da primeira sub-rede de aplicação da
/// PocketIC — a bancada confere que é este (`xtask/src/icp.rs`).
const BANCADA: &str = "pi33i-pt777-77776-aaaaa-cai";

/// Os canisters que não são Principal, do passo [`PRINCIPAL_INVALIDO`]: um
/// fora da base32, e o da bancada com o vigésimo caractere trocado — um bit
/// dos bytes, e não do CRC nem da sobra da base32: a soma não confere, e é
/// só ela que o recusa.
const NAO_PRINCIPAIS: [&str; 2] = ["aaaaa-aa-nao-e-principal", "pi33i-pt777-77776-aaaab-cai"];

/// O DNS da bancada da suíte.
const DNS: &str = "udp:10.0.2.53:53";

/// A raiz do TLS da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// Os argumentos de `ola`: nenhum.
fn sem_argumentos() -> Vec<u8> {
    Vec::from(*b"DIDL\x00\x00")
}

/// O que a verificação provou, curto — `prova <sub-rede> <delegada|da raiz>
/// <assinaturas>/<nós>: <resposta>`: a sub-rede pelo primeiro grupo do
/// texto dela, se assinou por delegação da raiz, as assinaturas de nó que
/// conferiram sobre os nós do certificado, e a resposta — ou por que o
/// Candid dela não se lê.
fn provado(v: &Verificada) -> String {
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
    let texto = v.sub_rede.texto();
    format!(
        "prova {} {} {}/{}: {}",
        texto.split('-').next().unwrap_or(""),
        if v.delegada { "delegada" } else { "da raiz" },
        v.assinaturas,
        v.nos,
        resposta
    )
}

/// O [`icp::Gateway`] de um passo, que diz cada pedido antes de mandá-lo.
struct Narrado<'a> {
    gateway: &'a mut icp::Gateway,
    passo: &'a str,
}

impl icp::agente::Transporte for Narrado<'_> {
    type Erro = icp::Transporte;

    fn post(&mut self, caminho: &str, corpo: &[u8]) -> Result<(u16, Vec<u8>), icp::Transporte> {
        let etapa = caminho.rsplit('/').next().unwrap_or(caminho);
        escreverln!("icp: {} pede {}", self.passo, etapa);
        self.gateway.post(caminho, corpo)
    }
}

/// O desfecho, com o Candid lido: uma resposta verificada que não se lê é
/// `verified_malformed` — a prova fechou, e o conteúdo não.
fn desfecho(r: &Result<Verificada, Falha>) -> &'static str {
    if let Ok(v) = r
        && let Desfecho::Respondida(bytes) = &v.desfecho
        && icp::candid::decodificar(bytes).is_err()
    {
        return "verified_malformed";
    }
    icp::desfecho(r)
}

/// Uma consulta pelo caminho inteiro, declarada antes do fecho: diz o
/// desfecho, a prova ou a falha, a hora e a declaração.
fn consultar(
    passo: &str,
    rede: &Rede,
    ancoras: &Ancoras,
    canister: &Principal,
    metodo: &str,
    arg: &[u8],
) {
    let assunto = icp::assunto(canister, metodo);
    let hora = match icp::hora() {
        Ok(h) => h,
        Err(f) => {
            let r = Err(f);
            let declarada = icp::declarar(&assunto, icp::desfecho(&r), None);
            dizer(passo, &r, None, &declarada);
            return;
        }
    };
    let nonce = icp::nonce();
    let mut gateway = None;
    let r = nonce.and_then(|nonce| {
        let gateway = gateway.insert(icp::conectar(rede, ancoras, DNS)?);
        let mut narrado = Narrado { gateway, passo };
        icp::consultar(&mut narrado, rede, canister, metodo, arg, &hora, &nonce)
    });
    let declarada = icp::declarar(
        &assunto,
        desfecho(&r),
        gateway.as_ref().map(icp::Gateway::conexao),
    );
    dizer(passo, &r, Some(hora.estado.nome()), &declarada);
    if let Some(g) = gateway {
        g.fechar();
    }
}

/// Diz o desfecho de um passo.
fn dizer(
    passo: &str,
    r: &Result<Verificada, Falha>,
    hora: Option<&str>,
    declarada: &icp::Declarada,
) {
    let detalhe = match r {
        Ok(v) => provado(v),
        Err(f) => format!("{f}"),
    };
    let declarada = match declarada {
        Ok(n) => format!("{n}"),
        Err(codigo) => format!("recusada {codigo}"),
    };
    escreverln!(
        "icp: {}: {}; declarada {}; hora {}; {}",
        passo,
        desfecho(r),
        declarada,
        hora.unwrap_or("nenhuma"),
        detalhe
    );
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
        escreverln!("icp: escutar devolveu {}", canal);
        return 1;
    }
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("icp: as ancoras nao se leram: {}", f.codigo());
            return 2;
        }
    };
    let redes = match icp::redes() {
        Ok(r) => r,
        Err(f) => {
            escreverln!("icp: as redes nao se leram: {}", f);
            return 3;
        }
    };
    let Ok(bancada) = Principal::de_texto(BANCADA) else {
        escreverln!("icp: o canister da bancada nao se le");
        return 4;
    };
    if segundo {
        escreverln!("icp: pronto pelo segundo canal ({} redes)", redes.len());
    } else {
        escreverln!("icp: pronto ({} redes)", redes.len());
    }

    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("icp: a leitura do canal falhou: {}", e);
                return 5;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                escreverln!("icp: encerrado");
                return CODIGO;
            }
            if e.tipo != tipo::ACAO {
                continue;
            }
            let nome = usize::try_from(e.b)
                .ok()
                .and_then(|i| REDES.get(i))
                .copied()
                .unwrap_or("?");
            let rede = redes.iter().find(|r| r.nome == nome);
            match (e.a, rede) {
                (SAIR_SEM_FECHAR, _) => {
                    escreverln!("icp: saindo sem fechar");
                    return SEM_FECHAR;
                }
                (PRINCIPAL_INVALIDO, _) => {
                    // Nada sai, e nada se declara: o Principal não se lê.
                    let ditos: Vec<String> = NAO_PRINCIPAIS
                        .iter()
                        .map(|texto| match Principal::de_texto(texto) {
                            Ok(_) => String::from("aceito"),
                            Err(e) => format!("recusado: {e}"),
                        })
                        .collect();
                    escreverln!("icp: principal invalido: {}", ditos.join("; "));
                }
                (_, None) => {
                    escreverln!("icp: rede {} nao esta no arquivo", nome);
                }
                (OLA, Some(rede)) => {
                    let passo = format!("ola {nome}");
                    consultar(&passo, rede, &ancoras, &bancada, "ola", &sem_argumentos());
                }
                (ECO, Some(rede)) => {
                    let passo = format!("eco {nome}");
                    let arg = icp::candid::codificar(&[Valor::Texto(String::from("duke"))])
                        .unwrap_or_default();
                    consultar(&passo, rede, &ancoras, &bancada, "eco", &arg);
                }
                (RECUSA, Some(rede)) => {
                    let passo = format!("recusa {nome}");
                    consultar(
                        &passo,
                        rede,
                        &ancoras,
                        &bancada,
                        "recusa",
                        &sem_argumentos(),
                    );
                }
                (CANDID, Some(rede)) => {
                    let metodo = usize::try_from(e.c)
                        .ok()
                        .and_then(|i| FORA_DA_FORMA.get(i))
                        .copied()
                        .unwrap_or("candid_truncado");
                    let passo = format!("{metodo} {nome}");
                    consultar(&passo, rede, &ancoras, &bancada, metodo, &sem_argumentos());
                }
                (outro, _) => {
                    escreverln!("icp: passo {} desconhecido", outro);
                }
            }
        }
    }
}
