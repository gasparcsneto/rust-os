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
//!   pedidos e o resto, que é a verificação;
//! - a chamada de atualização `quem`, assinada pela chave [`CHAVE`] de
//!   quem lançou o programa — o canister responde o Principal da chave —,
//!   e do anônimo — o Principal anônimo;
//! - a medida da chamada: [`MEDIDAS`] chamadas `contar` assinadas e
//!   [`MEDIDAS`] do anônimo, cada uma uma conexão nova, e [`MEDIDAS`]
//!   assinaturas sozinhas, pelo `key.sign`.
//!
//! Cada consulta é declarada por `audit.declare`, ancorada na conexão
//! dela, antes do fecho; cada chamada, na decisão da assinatura dela — ou
//! na conexão, do anônimo. Sai com [`CODIGO`] quando tudo confere, e com um
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
    "audit.declare",
    "key.read",
    "key.sign"
);

use alloc::string::String;
use alloc::vec::Vec;
use programas::escreverln;
use programas::icp::{
    self, Andamento, ChaveDoKernel, Desfecho, Falha, Final, Principal, Rede, Valor, Verificada,
};
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
const SEM_CHAVE: i64 = 48;
const QUEM_ASSINADA: i64 = 49;
const QUEM_ANONIMA: i64 = 50;
const MEDIDA_DA_CHAMADA: i64 = 51;
const MEDIDA_DA_ASSINATURA: i64 = 52;

/// Quantas consultas a medida faz.
const MEDIDAS: usize = 5;

/// A chave de quem lançou o programa, que a fumaça cria antes.
const CHAVE: &str = "chave:bancada";

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

/// Uma chamada de atualização, como saiu: o desfecho, a declaração, as
/// assinaturas que o kernel fez para ela e o tempo.
struct Chamada {
    r: Result<(icp::Atualizacao, Andamento), Falha>,
    declarada: icp::Declarada,
    assinaturas: usize,
    total_ms: u64,
}

impl Chamada {
    /// O desfecho, numa palavra.
    fn desfecho(&self) -> &'static str {
        icp::desfecho_da_chamada(self.r.as_ref().map(|(_, andamento)| andamento))
    }

    /// O Principal que o canister respondeu, se a chamada foi verificada e
    /// a resposta é um Principal só.
    fn principal(&self) -> Option<Principal> {
        let (
            _,
            Andamento::Certificado {
                desfecho: Final::Respondida(bytes),
                ..
            },
        ) = self.r.as_ref().ok()?
        else {
            return None;
        };
        match icp::candid::decodificar(bytes).ok()?.as_slice() {
            [Valor::Principal(p)] => Some(*p),
            _ => None,
        }
    }
}

/// Uma chamada de atualização sem argumentos pelo caminho inteiro —
/// assinada pela chave `chave` de quem lançou o programa, ou do anônimo —,
/// acompanhada enquanto pendente, e declarada antes do fecho: ancorada na
/// decisão da assinatura da chamada, ou, do anônimo, na conexão.
fn chamar(
    rede: &Rede,
    ancoras: &Ancoras,
    canister: &Principal,
    metodo: &str,
    chave: Option<&str>,
) -> Chamada {
    let inicio = agora_ms();
    let mut kernel = None;
    let mut gateway = None;
    let r = (|| {
        if let Some(nome) = chave {
            kernel = Some(ChaveDoKernel::ler(nome)?);
        }
        let hora = icp::hora()?;
        let nonce = icp::nonce()?;
        let gateway = gateway.insert(icp::conectar(rede, ancoras, DNS)?);
        let a = icp::chamar(
            gateway,
            rede,
            kernel.as_mut(),
            canister,
            metodo,
            b"DIDL\x00\x00",
            &hora,
            &nonce,
        )?;
        let mut andamento = a.andamento.clone();
        let mut leituras = 0;
        while let Andamento::Pendente(_) = andamento
            && leituras < icp::MAIS_LEITURAS
        {
            gateway.esperar(icp::ESPERA_ENTRE_LEITURAS_MS)?;
            let hora = icp::hora()?;
            leituras += 1;
            andamento = icp::acompanhar(gateway, rede, kernel.as_mut(), &a, &hora)?;
        }
        Ok((a, andamento))
    })();
    let total_ms = agora_ms().saturating_sub(inicio);
    let desfecho = icp::desfecho_da_chamada(r.as_ref().map(|(_, andamento)| andamento));
    let ancora = match (
        kernel
            .as_ref()
            .and_then(|k: &ChaveDoKernel| k.decisoes().first().copied()),
        gateway.as_ref(),
    ) {
        (Some(d), _) => icp::Ancora::Decisao(d),
        (None, Some(g)) => icp::Ancora::Conexao(g.conexao()),
        (None, None) => icp::Ancora::Nenhuma,
    };
    let declarada = icp::declarar_chamada(&icp::assunto(canister, metodo), desfecho, ancora);
    let assinaturas = kernel.as_ref().map_or(0, |k| k.decisoes().len());
    if let Some(g) = gateway {
        g.fechar();
    }
    Chamada {
        r,
        declarada,
        assinaturas,
        total_ms,
    }
}

/// Diz uma chamada: o desfecho, a declaração, as assinaturas, o tempo, e
/// quem o canister disse que chamou — ou a falha.
fn dizer_chamada(passo: &str, c: &Chamada) {
    let declarada = match &c.declarada {
        Ok(n) => alloc::format!("{n}"),
        Err(codigo) => alloc::format!("recusada {codigo}"),
    };
    let detalhe = match (&c.r, c.principal()) {
        (Ok(_), Some(p)) => alloc::format!("principal {}", p.texto()),
        (Ok(_), None) => String::from("sem principal"),
        (Err(f), _) => alloc::format!("{f}"),
    };
    escreverln!(
        "verificado: {}: {}; declarada {}; assinaturas {}; em {} ms; {}",
        passo,
        c.desfecho(),
        declarada,
        c.assinaturas,
        c.total_ms,
        detalhe
    );
}

/// Uma assinatura sozinha, pelo `key.sign`, do resumo `resumo` com a
/// [`CHAVE`] no domínio do pedido do IC: o tempo, se assinou.
fn assinar_so(resumo: &[u8; 32]) -> Option<u64> {
    let mut digitos = String::with_capacity(64);
    for b in resumo {
        digitos.push_str(&alloc::format!("{b:02x}"));
    }
    let inicio = agora_ms();
    let r = nativo::pedir("key.sign", |w| {
        w.field_str("key", CHAVE)?;
        w.field_str("domain", icp::DOMINIO_DO_PEDIDO)?;
        w.field_str("digest", &digitos)
    })
    .ok()?;
    let ms = agora_ms().saturating_sub(inicio);
    r.resultado()
        .ok()?
        .member("signed")?
        .as_bool()?
        .then_some(ms)
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

    // A chamada de atualização: o `quem` assinado pela chave de quem lançou
    // o programa responde o Principal dela; o do anônimo, o anônimo.
    let chave = match ChaveDoKernel::ler(CHAVE) {
        Ok(k) => k,
        Err(f) => {
            escreverln!("verificado: a chave nao se leu: {}", f);
            return SEM_CHAVE;
        }
    };
    let assinada = chamar(direta, &ancoras, &canister, "quem", Some(CHAVE));
    dizer_chamada("quem assinada", &assinada);
    if assinada.desfecho() != "verified"
        || assinada.principal() != Some(chave.principal())
        || assinada.assinaturas != 1
        || assinada.declarada.is_err()
    {
        return QUEM_ASSINADA;
    }
    let anonima = chamar(direta, &ancoras, &canister, "quem", None);
    dizer_chamada("quem anonima", &anonima);
    if anonima.desfecho() != "verified"
        || anonima.principal() != Some(Principal::ANONIMO)
        || anonima.assinaturas != 0
        || anonima.declarada.is_err()
    {
        return QUEM_ANONIMA;
    }

    // A medida da chamada: o `contar` assinado e do anônimo, e a
    // assinatura sozinha.
    let mut assinadas = Vec::new();
    let mut anonimas = Vec::new();
    for _ in 0..MEDIDAS {
        for (chave, medidas) in [(Some(CHAVE), &mut assinadas), (None, &mut anonimas)] {
            let c = chamar(direta, &ancoras, &canister, "contar", chave);
            if c.desfecho() != "verified" || c.declarada.is_err() {
                dizer_chamada("medida da chamada", &c);
                return MEDIDA_DA_CHAMADA;
            }
            medidas.push(c.total_ms);
        }
    }
    let mut so_assinatura = Vec::new();
    for i in 0..MEDIDAS {
        match assinar_so(&[0xd0 + i as u8; 32]) {
            Some(ms) => so_assinatura.push(ms),
            None => {
                escreverln!("verificado: a assinatura sozinha nao saiu");
                return MEDIDA_DA_ASSINATURA;
            }
        }
    }
    escreverln!(
        "verificado: medida da chamada {} contar, medianas em ms: assinada {}, anonima {}; key.sign sozinho {} (de {} a {})",
        MEDIDAS,
        mediana(assinadas),
        mediana(anonimas),
        mediana(so_assinatura.clone()),
        so_assinatura.iter().min().copied().unwrap_or(0),
        so_assinatura.iter().max().copied().unwrap_or(0)
    );
    escreverln!("verificado: tudo conferiu");
    CODIGO
}
