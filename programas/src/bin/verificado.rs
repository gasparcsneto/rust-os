//! O IC na imagem de produção: consulta o canister da bancada pela rede
//! `direta` — o endereço fixo da bancada, porque a imagem de produção não
//! tem o DNS da suíte —, confere a prova de dentro, recusa a prova
//! adulterada, mede e sai. A fumaça (`cargo xtask fumaca`) confere o que o
//! kernel viu.
//!
//! - `ola` e `eco`, verificados: a sub-rede delegada pela raiz do arquivo
//!   de redes, a assinatura do nó, e a resposta — o texto `ola` e o eco
//!   de `duke`;
//! - `ola` pela `bls-invalida`: `unverified_certificate`, e nada entregue;
//! - a medida: [`MEDIDAS`] consultas `ola` seguidas, cada uma uma conexão
//!   nova, com o tempo de cada parte — a conexão (o aperto do TLS), os dois
//!   pedidos e o resto, que é a verificação.
//!
//! Cada consulta é declarada por `audit.declare`, ancorada na conexão
//! dela, antes do fecho. Sai com [`CODIGO`] quando tudo confere, e com um
//! código menor que diz o quê, quando não.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "verificado",
    "net.connect",
    "random.read",
    "system.read",
    "fs.read",
    "audit.declare"
);

use alloc::string::String;
use alloc::vec::Vec;
use programas::escreverln;
use programas::icp::{self, Desfecho, Falha, Principal, Rede, Valor, Verificada};
use programas::nativo;
use programas::tls::{self, Ancoras};

/// O código de saída quando tudo conferiu. A fumaça o procura.
const CODIGO: i64 = 97;

/// Os códigos de cada falha.
const SEM_ANCORAS: i64 = 40;
const SEM_REDES: i64 = 41;
const SEM_A_REDE: i64 = 42;
const SEM_O_CANISTER: i64 = 43;
const OLA: i64 = 44;
const ECO: i64 = 45;
const ADULTERADA: i64 = 46;
const MEDIDA: i64 = 47;

/// Quantas consultas a medida faz.
const MEDIDAS: usize = 5;

/// O canister da bancada — ver `xtask/src/icp.rs`.
const BANCADA: &str = "pi33i-pt777-77776-aaaaa-cai";

/// A raiz do TLS da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// O DNS do emulador: as duas redes daqui têm o endereço fixo, e ele não é
/// perguntado.
const DNS: &str = "udp:10.0.2.3:53";

/// O tempo desde o boot, em milissegundos. Zero, se o relógio não
/// respondeu.
fn agora_ms() -> u64 {
    nativo::pedir("system.uptime", |_| Ok(()))
        .ok()
        .and_then(|r| r.resultado().ok()?.member("uptime_ms")?.as_u64())
        .unwrap_or(0)
}

/// O [`icp::Gateway`] de uma consulta, que soma o tempo dos pedidos.
struct Cronometrado<'a> {
    gateway: &'a mut icp::Gateway,
    ms: u64,
}

impl icp::agente::Transporte for Cronometrado<'_> {
    type Erro = icp::Transporte;

    fn post(&mut self, caminho: &str, corpo: &[u8]) -> Result<(u16, Vec<u8>), icp::Transporte> {
        let inicio = agora_ms();
        let r = self.gateway.post(caminho, corpo);
        self.ms += agora_ms().saturating_sub(inicio);
        r
    }
}

/// Uma consulta, como saiu: o desfecho, a declaração e o tempo das partes.
struct Consulta {
    r: Result<Verificada, Falha>,
    declarada: icp::Declarada,
    conexao_ms: u64,
    pedidos_ms: u64,
    total_ms: u64,
}

impl Consulta {
    /// O resto do tempo: a verificação — e a hora e o nonce, pelo gate.
    fn resto_ms(&self) -> u64 {
        self.total_ms
            .saturating_sub(self.conexao_ms)
            .saturating_sub(self.pedidos_ms)
    }
}

/// Uma consulta pelo caminho inteiro, declarada antes do fecho.
fn consultar(
    rede: &Rede,
    ancoras: &Ancoras,
    canister: &Principal,
    metodo: &str,
    arg: &[u8],
) -> Consulta {
    let inicio = agora_ms();
    let (mut conexao_ms, mut pedidos_ms) = (0, 0);
    let mut gateway = None;
    let r = icp::hora().and_then(|hora| {
        let nonce = icp::nonce()?;
        let antes = agora_ms();
        let gateway = gateway.insert(icp::conectar(rede, ancoras, DNS)?);
        conexao_ms = agora_ms().saturating_sub(antes);
        let mut cronometrado = Cronometrado { gateway, ms: 0 };
        let r = icp::consultar(
            &mut cronometrado,
            rede,
            canister,
            metodo,
            arg,
            &hora,
            &nonce,
        );
        pedidos_ms = cronometrado.ms;
        r
    });
    let total_ms = agora_ms().saturating_sub(inicio);
    let declarada = icp::declarar(
        &icp::assunto(canister, metodo),
        icp::desfecho(&r),
        gateway.as_ref().map(icp::Gateway::conexao),
    );
    if let Some(g) = gateway {
        g.fechar();
    }
    Consulta {
        r,
        declarada,
        conexao_ms,
        pedidos_ms,
        total_ms,
    }
}

/// O texto que uma consulta verificada respondeu, se foi um texto só.
fn texto(c: &Consulta) -> Option<String> {
    let v = c.r.as_ref().ok()?;
    let Desfecho::Respondida(bytes) = &v.desfecho else {
        return None;
    };
    match icp::candid::decodificar(bytes).ok()?.as_slice() {
        [Valor::Texto(t)] if v.delegada && v.assinaturas >= 1 => Some(t.clone()),
        _ => None,
    }
}

/// Diz uma consulta: o desfecho, a declaração, a prova ou a falha.
fn dizer(passo: &str, c: &Consulta) {
    let declarada = match &c.declarada {
        Ok(n) => alloc::format!("{n}"),
        Err(codigo) => alloc::format!("recusada {codigo}"),
    };
    let detalhe = match &c.r {
        Ok(v) => alloc::format!(
            "{} assinatura(s) de {} nos, {}",
            v.assinaturas,
            v.nos,
            texto(c).unwrap_or_default()
        ),
        Err(f) => alloc::format!("{f}"),
    };
    escreverln!(
        "verificado: {}: {}; declarada {}; em {} ms; {}",
        passo,
        icp::desfecho(&c.r),
        declarada,
        c.total_ms,
        detalhe
    );
}

/// A mediana de `v`, que não é vazio.
fn mediana(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[v.len() / 2]
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("verificado: as ancoras nao se leram: {}", f.codigo());
            return SEM_ANCORAS;
        }
    };
    let redes = match icp::redes() {
        Ok(r) => r,
        Err(f) => {
            escreverln!("verificado: as redes nao se leram: {}", f);
            return SEM_REDES;
        }
    };
    let rede = |nome: &str| redes.iter().find(|r| r.nome == nome);
    let (Some(direta), Some(adulterada)) = (rede("direta"), rede("bls-invalida")) else {
        escreverln!("verificado: as redes da fumaca nao estao no arquivo");
        return SEM_A_REDE;
    };
    let Ok(canister) = Principal::de_texto(BANCADA) else {
        escreverln!("verificado: o canister da bancada nao se le");
        return SEM_O_CANISTER;
    };
    let sem_argumentos = Vec::from(*b"DIDL\x00\x00");

    let ola = consultar(direta, &ancoras, &canister, "ola", &sem_argumentos);
    dizer("ola", &ola);
    if texto(&ola).as_deref() != Some("ola") || ola.declarada.is_err() {
        return OLA;
    }
    let duke = icp::candid::codificar(&[Valor::Texto(String::from("duke"))]).unwrap_or_default();
    let eco = consultar(direta, &ancoras, &canister, "eco", &duke);
    dizer("eco", &eco);
    if texto(&eco).as_deref() != Some("duke") || eco.declarada.is_err() {
        return ECO;
    }
    let falsa = consultar(adulterada, &ancoras, &canister, "ola", &sem_argumentos);
    dizer("adulterada", &falsa);
    if icp::desfecho(&falsa.r) != "unverified_certificate" || falsa.declarada.is_err() {
        return ADULTERADA;
    }

    let mut medidas = Vec::new();
    for _ in 0..MEDIDAS {
        let c = consultar(direta, &ancoras, &canister, "ola", &sem_argumentos);
        if texto(&c).as_deref() != Some("ola") || c.declarada.is_err() {
            dizer("medida", &c);
            return MEDIDA;
        }
        medidas.push(c);
    }
    let parte = |f: fn(&Consulta) -> u64| mediana(medidas.iter().map(f).collect());
    let totais: Vec<u64> = medidas.iter().map(|c| c.total_ms).collect();
    escreverln!(
        "verificado: medida {} consultas, medianas em ms: conexao {}, pedidos {}, verificacao {}, total {} (de {} a {})",
        MEDIDAS,
        parte(|c| c.conexao_ms),
        parte(|c| c.pedidos_ms),
        parte(Consulta::resto_ms),
        parte(|c| c.total_ms),
        totais.iter().min().copied().unwrap_or(0),
        totais.iter().max().copied().unwrap_or(0)
    );
    escreverln!("verificado: tudo conferiu");
    CODIGO
}
