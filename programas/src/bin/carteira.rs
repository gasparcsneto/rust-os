//! A carteira da bancada do Internet Computer (ICP-4d): uma identidade do
//! Duke move valor com a própria chave — o saldo, a transferência do
//! ICRC-1, a repetição que não executa duas vezes, e ICP convertido em
//! cycles pelo CMC —, cada resposta verificada antes de chegar aqui.
//!
//! Como o `icp`: lê as âncoras do TLS da bancada e as redes em que confia,
//! diz `carteira: pronto` e espera um evento no canal [`CANAL`] — ou, com
//! outra carteira escutando, diz `carteira: pronto pelo segundo canal` e
//! espera no [`SEGUNDO_CANAL`]. A cada evento [`tipo::ACAO`], o `a` diz o
//! passo, o `b` a rede — o índice em [`REDES`] — e o `c` a conta: zero é o
//! anônimo, e 1 e 2, as chaves de [`CHAVES`], que o kernel guarda para quem
//! lançou o processo. Cada pedido vai por uma conexão nova, pelo caminho
//! inteiro: o DNS, o destino no gate, o TLS, os `POST` e a verificação.
//!
//! - [`SALDO`] e [`SALDO_DE_CICLOS`]: o saldo da conta `c` no ledger de ICP
//!   ([`LEDGER`]) e no de cycles ([`LEDGER_DE_CICLOS`]) — a consulta do
//!   anônimo, verificada pelas assinaturas dos nós: o saldo é público. O
//!   Principal de uma chave vem do `key.read`;
//! - [`FUNDOS`]: o anônimo transfere [`FUNDOS_QUANTIA`] para a chave `c`.
//!   Só na bancada: o anônimo da PocketIC começa com um bilhão de ICP, e o
//!   da rede de verdade não tem nada;
//! - [`TRANSFERIR`]: a chave `c` transfere [`QUANTIA`] para a outra chave,
//!   assinado, com o `created_at_time` da hora do Duke e um `memo` de bytes
//!   do gerador do kernel — o que faz desta transferência uma só —, e a
//!   guarda;
//! - [`REPETIR`]: a última transferência de novo, pela rede `b`: os mesmos
//!   argumentos — o mesmo `created_at_time` e o mesmo `memo` —, assinados
//!   de novo. O ledger responde `Duplicate` com o bloco da primeira, e não
//!   executa;
//! - [`FIXAR_HORA`] e [`TRANSFERIR_EM`]: a hora que o `b` diz, em segundos,
//!   fica para as transferências seguintes; e a chave `c` transfere
//!   [`QUANTIA`] para a outra chave, pela rede `b`, com o `created_at_time`
//!   dessa hora e o [`MEMO_FIXO`]: duas carteiras com a mesma hora fazem a
//!   mesma transferência, e uma hora velha ou no futuro o ledger recusa;
//! - [`CICLOS`]: a chave `c` cunha cycles com [`QUANTIA`] — a transferência
//!   para a conta de depósito dela no CMC ([`CMC`]), com o memo `MINT`, e o
//!   `notify_mint_cycles` com o bloco dela, as duas chamadas assinadas — e
//!   guarda a notificação;
//! - [`NOTIFICAR`]: a última notificação de novo, assinada pela chave `c`:
//!   pela mesma chave, o CMC devolve o mesmo resultado; pela outra, recusa.
//!
//! Antes de cada pedido, diz `carteira: <passo> pede <etapa>` — `read_state`,
//! `query` ou `call`: a suíte sabe assim que o programa espera a resposta
//! daquele pedido, e age no meio. Numa chamada que chegou ao fim, diz quem
//! chamou — `carteira: <passo> remetente <principal>` — e o que voltou —
//! `carteira: <passo> resposta <resposta>`: `bloco <n>`, `erro <nome do
//! padrão>`, `cunhados <n> saldo <n> bloco <n>`, ou `recusa <código>`.
//! Depois, a linha do desfecho, como a do `icp`: `carteira: <passo>:
//! <desfecho>; declarada <registro>; hora <estado>; assinaturas <n>;
//! <detalhe>` — numa consulta, sem as assinaturas, e com o saldo no
//! detalhe. A cunhagem são dois passos, `ciclos <rede> <chave>
//! transferencia` e `... notificacao`. Sai com [`CODIGO`] quando a suíte
//! pede o fim.
//!
//! # O que o programa não é
//!
//! O ledger, o CMC, a quantia e o destino não dão nada a este processo, nem
//! são recurso do Duke: o kernel não sabe o que assina. O que o programa
//! pode é o que o gate decide para os pedidos dele — `fs.read`,
//! `random.read`, `system.info`, `net.connect`, `audit.declare`, `key.read`
//! e `key.sign` —, com a autoridade de quem o lançou: as chaves que o papel
//! alcança, uma decisão por assinatura. Os passos de valor só andam nas
//! redes da bancada: a rede principal não está em [`REDES`].

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "carteira",
    "net.connect",
    "random.read",
    "system.read",
    "fs.read",
    "audit.declare",
    "key.read",
    "key.sign"
);

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use programas::escreverln;
use programas::icp::{
    self, Ancora, Andamento, ChaveDoKernel, Desfecho, Falha, Final, Principal, Rede, Verificada,
};
use programas::sistema;
use programas::tls::{self, Ancoras, Hora};
use protocolo::usuario::evento::{Evento, tipo};
use web3::icp::cmc::{self, Notificacao};
use web3::icp::icrc1::{self, Conta, Transferencia};

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 81;

/// O canal por onde a suíte dita o passo.
const CANAL: &str = "teste-carteira";

/// O canal de uma segunda carteira, com a primeira viva.
const SEGUNDO_CANAL: &str = "teste-carteira-2";

/// Os passos — a suíte tem as mesmas constantes.
const SALDO: i64 = 1;
const SALDO_DE_CICLOS: i64 = 2;
const FUNDOS: i64 = 3;
const TRANSFERIR: i64 = 4;
const REPETIR: i64 = 5;
const TRANSFERIR_EM: i64 = 6;
const CICLOS: i64 = 7;
const NOTIFICAR: i64 = 8;
const FIXAR_HORA: i64 = 9;

/// As chaves, pelo `c` de um evento — `c` zero é o anônimo. Os nomes que a
/// política padrão dá ao operador.
const CHAVES: [&str; 2] = ["chave:bancada", "chave:bancada-2"];

/// As redes da bancada, pelo índice que o `b` de um evento diz — os nomes
/// de `/dados/icp/redes`, na ordem do `icp`: a honesta, a lenta, as que
/// adulteram a prova, a de raiz errada, a sem DNS e a que responde 202. A
/// rede principal não está aqui.
const REDES: [&str; 13] = [
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
    "assincrona",
];

/// O ledger de ICP, o CMC e o ledger de cycles: os ids da rede principal,
/// em que a PocketIC da bancada os sobe — a bancada confere
/// (`xtask/src/icp.rs`).
const LEDGER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
const CMC: &str = "rkp4c-7iaaa-aaaaa-aaaca-cai";
const LEDGER_DE_CICLOS: &str = "um5iw-rqaaa-aaaaq-qaaba-cai";

/// O DNS da bancada da suíte.
const DNS: &str = "udp:10.0.2.53:53";

/// A raiz do TLS da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// A quantia de uma transferência e de uma cunhagem: 1 ICP, em e8s.
const QUANTIA: u128 = 100_000_000;

/// O que o anônimo põe numa chave: 10 ICP.
const FUNDOS_QUANTIA: u128 = 1_000_000_000;

/// O `memo` dos fundos.
const MEMO_DE_FUNDOS: &[u8] = b"duke 4d fundos";

/// O `memo` de [`TRANSFERIR_EM`]: o mesmo em toda carteira.
const MEMO_FIXO: &[u8] = b"duke 4d";

/// Quantos bytes do gerador vão no `memo` de [`TRANSFERIR`].
const BYTES_DO_MEMO: usize = 16;

/// O [`icp::Gateway`] de um passo, que diz cada pedido antes de mandá-lo.
struct Narrado<'a> {
    gateway: &'a mut icp::Gateway,
    passo: &'a str,
}

impl icp::agente::Transporte for Narrado<'_> {
    type Erro = icp::Transporte;

    fn post(&mut self, caminho: &str, corpo: &[u8]) -> Result<(u16, Vec<u8>), icp::Transporte> {
        let etapa = caminho.rsplit('/').next().unwrap_or(caminho);
        escreverln!("carteira: {} pede {}", self.passo, etapa);
        self.gateway.post(caminho, corpo)
    }
}

/// O registro de uma declaração, ou o código de quem a recusou.
fn declarada(d: &icp::Declarada) -> String {
    match d {
        Ok(n) => format!("{n}"),
        Err(codigo) => format!("recusada {codigo}"),
    }
}

/// O primeiro grupo do texto de uma sub-rede, e se ela assinou por
/// delegação.
fn sub_rede(p: &Principal, delegada: bool) -> String {
    let texto = p.texto();
    format!(
        "{} {}",
        texto.split('-').next().unwrap_or(""),
        if delegada { "delegada" } else { "da raiz" }
    )
}

/// O Principal da chave `nome`, pelo `key.read`.
fn principal_da_chave(nome: &str) -> Result<Principal, Falha> {
    ChaveDoKernel::ler(nome).map(|k| k.principal())
}

/// A conta `c` de um evento: o anônimo, ou a de uma chave.
fn conta(c: Option<&str>) -> Result<Conta, Falha> {
    let dono = match c {
        Some(nome) => principal_da_chave(nome)?,
        None => Principal::ANONIMO,
    };
    Ok(Conta {
        dono,
        subconta: None,
    })
}

/// O `created_at_time` da hora do Duke: a mesma com que se conferem os
/// certificados.
fn criada_em_ns(hora: &Hora) -> u64 {
    hora.validade_s().saturating_mul(1_000_000_000)
}

/// O argumento de uma transferência daqui: o `memo` é sempre curto.
fn argumento(t: &Transferencia) -> Vec<u8> {
    icrc1::argumento_da_transferencia(t).expect("o memo daqui cabe")
}

/// O saldo da `conta` no `ledger`, pela consulta do anônimo, verificada e
/// declarada antes do fecho, ancorada na conexão.
fn saldo(passo: &str, rede: &Rede, ancoras: &Ancoras, ledger: &Principal, chave: Option<&str>) {
    const METODO: &str = "icrc1_balance_of";
    let assunto = icp::assunto(ledger, METODO);
    let mut gateway = None;
    let mut hora_dita = None;
    let r: Result<Verificada, Falha> = (|| {
        let arg = icrc1::argumento_do_saldo(&conta(chave)?);
        let hora = icp::hora()?;
        hora_dita = Some(hora.estado.nome());
        let nonce = icp::nonce()?;
        let gateway = gateway.insert(icp::conectar(rede, ancoras, DNS)?);
        let mut narrado = Narrado { gateway, passo };
        icp::consultar(&mut narrado, rede, ledger, METODO, &arg, &hora, &nonce)
    })();
    let lido = match &r {
        Ok(v) => match &v.desfecho {
            Desfecho::Respondida(bytes) => Some(icrc1::ler_saldo(bytes)),
            Desfecho::Recusada { .. } => None,
        },
        Err(_) => None,
    };
    let desfecho = match &lido {
        Some(Err(_)) => "verified_malformed",
        _ => icp::desfecho_da_consulta_assinada(&r),
    };
    let d = icp::declarar(
        &assunto,
        desfecho,
        gateway.as_ref().map(icp::Gateway::conexao),
    );
    let detalhe = match (&r, &lido) {
        (Ok(v), lido) => {
            let prova = format!(
                "prova {} {}/{}",
                sub_rede(&v.sub_rede, v.delegada),
                v.assinaturas,
                v.nos
            );
            match (lido, &v.desfecho) {
                (Some(Ok(n)), _) => format!("saldo {n}; {prova}"),
                (Some(Err(e)), _) => format!("{prova}: recusado: {e}"),
                (None, Desfecho::Recusada { codigo, erro, .. }) => {
                    format!(
                        "{prova}: recusa {codigo} {}",
                        erro.as_deref().unwrap_or("-")
                    )
                }
                (None, Desfecho::Respondida(_)) => prova,
            }
        }
        (Err(f), _) => format!("{f}"),
    };
    escreverln!(
        "carteira: {}: {}; declarada {}; hora {}; {}",
        passo,
        desfecho,
        declarada(&d),
        hora_dita.unwrap_or("nenhuma"),
        detalhe
    );
    if let Some(g) = gateway {
        g.fechar();
    }
}

/// O que monta o argumento de uma chamada, para quem chama e com a hora.
type Preparo<'a> = dyn FnMut(&Principal, &Hora) -> Result<Vec<u8>, Falha> + 'a;

/// Uma chamada de `metodo` de `canister` pelo caminho inteiro — a chave
/// lida, a hora, o argumento que `preparar` monta para quem chama, a
/// conexão, a chamada assinada e as leituras da situação enquanto
/// pendente —, declarada antes do fecho, ancorada na decisão da assinatura
/// da chamada; do anônimo, na conexão. Diz quem chamou e o que voltou —
/// lido por `ler`; o que não se lê é `verified_malformed` —, e devolve a
/// resposta verificada.
#[allow(clippy::too_many_arguments)]
fn chamar(
    passo: &str,
    rede: &Rede,
    ancoras: &Ancoras,
    chave: Option<&str>,
    canister: &Principal,
    metodo: &str,
    preparar: &mut Preparo<'_>,
    ler: &dyn Fn(&[u8]) -> Result<String, String>,
) -> Option<Vec<u8>> {
    let assunto = icp::assunto(canister, metodo);
    let mut kernel = None;
    let mut gateway = None;
    let mut hora_dita = None;
    let mut leituras = 0u32;
    let r: Result<(icp::Atualizacao, Andamento), Falha> = (|| {
        if let Some(nome) = chave {
            kernel = Some(ChaveDoKernel::ler(nome)?);
        }
        let remetente = kernel
            .as_ref()
            .map_or(Principal::ANONIMO, ChaveDoKernel::principal);
        let hora = icp::hora()?;
        hora_dita = Some(hora.estado.nome());
        let arg = preparar(&remetente, &hora)?;
        let nonce = icp::nonce()?;
        let gateway = gateway.insert(icp::conectar(rede, ancoras, DNS)?);
        let mut narrado = Narrado { gateway, passo };
        let mut a = icp::chamar(
            &mut narrado,
            rede,
            kernel.as_mut(),
            canister,
            metodo,
            &arg,
            &hora,
            &nonce,
        )?;
        let mut andamento = a.andamento.clone();
        while let Andamento::Pendente(situacao) = andamento
            && leituras < icp::MAIS_LEITURAS
        {
            escreverln!("carteira: {} pendente {}", passo, situacao);
            narrado.gateway.esperar(icp::ESPERA_ENTRE_LEITURAS_MS)?;
            let hora = icp::hora()?;
            leituras += 1;
            andamento = icp::acompanhar(&mut narrado, rede, kernel.as_mut(), &mut a, &hora)?;
        }
        Ok((a, andamento))
    })();
    let resposta = match &r {
        Ok((
            _,
            Andamento::Certificado {
                desfecho: Final::Respondida(bytes),
                ..
            },
        )) => Some((bytes.clone(), ler(bytes))),
        _ => None,
    };
    let desfecho = match &resposta {
        Some((_, Err(_))) => "verified_malformed",
        _ => icp::desfecho_da_chamada(r.as_ref().map(|(_, andamento)| andamento)),
    };
    let decisao = kernel.as_ref().and_then(|k| k.decisoes().first().copied());
    let ancora = match (decisao, gateway.as_ref()) {
        (Some(d), _) => Ancora::Decisao(d),
        (None, Some(g)) => Ancora::Conexao(g.conexao()),
        (None, None) => Ancora::Nenhuma,
    };
    let d = icp::declarar_chamada(&assunto, desfecho, ancora);
    let detalhe = match &r {
        Ok((a, andamento)) => {
            escreverln!("carteira: {} remetente {}", passo, a.remetente.texto());
            let dito = match (&resposta, andamento) {
                (Some((_, Ok(t))), _) => t.clone(),
                (Some((_, Err(e))), _) => format!("recusado: {e}"),
                (None, Andamento::Certificado { desfecho, .. }) => match desfecho {
                    Final::Recusada { codigo, erro, .. } => {
                        format!("recusa {codigo} {}", erro.as_deref().unwrap_or("-"))
                    }
                    Final::Concluida => String::from("concluida"),
                    Final::Respondida(_) => String::new(),
                },
                (None, Andamento::RecusaNaoReplicada { codigo, erro, .. }) => format!(
                    "recusa sem prova {codigo} {}",
                    erro.as_deref().unwrap_or("-")
                ),
                (None, Andamento::Pendente(s)) => format!("pendente {s}"),
            };
            escreverln!("carteira: {} resposta {}", passo, dito);
            format!(
                "prova {} leituras {}",
                sub_rede(&a.faixas.sub_rede, a.faixas.delegada),
                leituras
            )
        }
        Err(f) => format!("{f}"),
    };
    let assinaturas = kernel.as_ref().map_or(0, |k| k.decisoes().len());
    escreverln!(
        "carteira: {}: {}; declarada {}; hora {}; assinaturas {}; {}",
        passo,
        desfecho,
        declarada(&d),
        hora_dita.unwrap_or("nenhuma"),
        assinaturas,
        detalhe
    );
    if let Some(g) = gateway {
        g.fechar();
    }
    match (desfecho, resposta) {
        ("verified", Some((bytes, _))) => Some(bytes),
        _ => None,
    }
}

/// O que uma transferência respondeu, dito: o bloco, ou o erro do ledger
/// pelo nome do padrão.
fn ler_transferencia(bytes: &[u8]) -> Result<String, String> {
    match icrc1::ler_transferencia(bytes) {
        Ok(Ok(bloco)) => Ok(format!("bloco {bloco}")),
        Ok(Err(recusa)) => Ok(format!("erro {recusa}")),
        Err(e) => Err(format!("{e}")),
    }
}

/// O que uma cunhagem respondeu, dito: os cycles cunhados, o saldo e o
/// bloco no ledger de cycles, ou o erro do CMC pelo nome da interface.
fn ler_cunhagem(bytes: &[u8]) -> Result<String, String> {
    match cmc::ler_cunhagem(bytes) {
        Ok(Ok(c)) => Ok(format!(
            "cunhados {} saldo {} bloco {}",
            c.cunhados, c.saldo, c.bloco
        )),
        Ok(Err(recusa)) => Ok(format!("erro {recusa}")),
        Err(e) => Err(format!("{e}")),
    }
}

/// Uma transferência do ICRC-1 pela `chave` — ou do anônimo —, com o
/// argumento que `montar` faz da hora; devolve o bloco, se o ledger
/// executou e a prova fechou.
fn transferir(
    passo: &str,
    rede: &Rede,
    ancoras: &Ancoras,
    chave: Option<&str>,
    ledger: &Principal,
    montar: &mut dyn FnMut(&Principal, &Hora) -> Result<Transferencia, Falha>,
) -> Option<u128> {
    let mut preparar =
        |remetente: &Principal, hora: &Hora| montar(remetente, hora).map(|t| argumento(&t));
    let bytes = chamar(
        passo,
        rede,
        ancoras,
        chave,
        ledger,
        "icrc1_transfer",
        &mut preparar,
        &ler_transferencia,
    )?;
    match icrc1::ler_transferencia(&bytes) {
        Ok(Ok(bloco)) => Some(bloco),
        _ => None,
    }
}

/// A notificação `n` ao CMC, assinada pela `chave`.
fn notificar(
    passo: &str,
    rede: &Rede,
    ancoras: &Ancoras,
    chave: Option<&str>,
    cmc: &Principal,
    n: &Notificacao,
) {
    let mut preparar = |_: &Principal, _: &Hora| {
        Ok(cmc::argumento_da_cunhagem(n).expect("a notificacao daqui nao tem memo"))
    };
    chamar(
        passo,
        rede,
        ancoras,
        chave,
        cmc,
        "notify_mint_cycles",
        &mut preparar,
        &ler_cunhagem,
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
        escreverln!("carteira: escutar devolveu {}", canal);
        return 1;
    }
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("carteira: as ancoras nao se leram: {}", f.codigo());
            return 2;
        }
    };
    let redes = match icp::redes() {
        Ok(r) => r,
        Err(f) => {
            escreverln!("carteira: as redes nao se leram: {}", f);
            return 3;
        }
    };
    let (Ok(ledger), Ok(cmc), Ok(ledger_de_ciclos)) = (
        Principal::de_texto(LEDGER),
        Principal::de_texto(CMC),
        Principal::de_texto(LEDGER_DE_CICLOS),
    ) else {
        escreverln!("carteira: os ledgers nao se leem");
        return 4;
    };
    if segundo {
        escreverln!(
            "carteira: pronto pelo segundo canal ({} redes)",
            redes.len()
        );
    } else {
        escreverln!("carteira: pronto ({} redes)", redes.len());
    }

    // A última transferência — quem assinou e os argumentos — e a última
    // notificação: o que [`REPETIR`] e [`NOTIFICAR`] mandam de novo.
    let mut ultima: Option<(Option<&'static str>, Transferencia)> = None;
    let mut ultima_notificacao: Option<Notificacao> = None;
    // A hora de [`TRANSFERIR_EM`], em segundos.
    let mut hora_fixada: Option<u64> = None;
    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("carteira: a leitura do canal falhou: {}", e);
                return 5;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                escreverln!("carteira: encerrado");
                return CODIGO;
            }
            if e.tipo != tipo::ACAO {
                continue;
            }
            if e.a == FIXAR_HORA {
                hora_fixada = u64::try_from(e.b).ok();
                escreverln!("carteira: hora fixada {}", e.b);
                continue;
            }
            let nome = usize::try_from(e.b)
                .ok()
                .and_then(|i| REDES.get(i))
                .copied()
                .unwrap_or("?");
            let Some(rede) = redes.iter().find(|r| r.nome == nome) else {
                escreverln!("carteira: rede {} fora da bancada", nome);
                continue;
            };
            // A chave do `c`, a outra, e o nome da conta.
            let chave = usize::try_from(e.c)
                .ok()
                .and_then(|i| i.checked_sub(1))
                .and_then(|i| CHAVES.get(i))
                .copied();
            let outra = match e.c {
                1 => Some(CHAVES[1]),
                2 => Some(CHAVES[0]),
                _ => None,
            };
            let quem = chave.unwrap_or("anonimo");
            match e.a {
                SALDO => {
                    let passo = format!("saldo {nome} {quem}");
                    saldo(&passo, rede, &ancoras, &ledger, chave);
                }
                SALDO_DE_CICLOS => {
                    let passo = format!("saldo_de_ciclos {nome} {quem}");
                    saldo(&passo, rede, &ancoras, &ledger_de_ciclos, chave);
                }
                FUNDOS if chave.is_some() => {
                    let passo = format!("fundos {nome} {quem}");
                    transferir(&passo, rede, &ancoras, None, &ledger, &mut |_, hora| {
                        Ok(Transferencia {
                            de_subconta: None,
                            para: conta(chave)?,
                            quantia: FUNDOS_QUANTIA,
                            taxa: None,
                            memo: Some(Vec::from(MEMO_DE_FUNDOS)),
                            criada_em_ns: Some(criada_em_ns(hora)),
                        })
                    });
                }
                TRANSFERIR if chave.is_some() => {
                    let passo = format!("transferir {nome} {quem}");
                    let mut feita = None;
                    transferir(&passo, rede, &ancoras, chave, &ledger, &mut |_, hora| {
                        let memo = Vec::from(&icp::nonce()?[..BYTES_DO_MEMO]);
                        let t = Transferencia {
                            de_subconta: None,
                            para: conta(outra)?,
                            quantia: QUANTIA,
                            taxa: None,
                            memo: Some(memo),
                            criada_em_ns: Some(criada_em_ns(hora)),
                        };
                        feita = Some(t.clone());
                        Ok(t)
                    });
                    // Guardada mesmo sem desfecho: é a resposta perdida que
                    // a repetição esclarece.
                    if let Some(t) = feita {
                        ultima = Some((chave, t));
                    }
                }
                REPETIR => match &ultima {
                    Some((de, t)) => {
                        let passo = format!("repetir {nome} {}", de.unwrap_or("anonimo"));
                        let t = t.clone();
                        transferir(&passo, rede, &ancoras, *de, &ledger, &mut |_, _| {
                            Ok(t.clone())
                        });
                    }
                    None => {
                        escreverln!("carteira: nada a repetir");
                    }
                },
                TRANSFERIR_EM if chave.is_some() => {
                    let Some(segundos) = hora_fixada else {
                        escreverln!("carteira: hora nao fixada");
                        continue;
                    };
                    let passo = format!("transferir_em {nome} {quem}");
                    transferir(&passo, rede, &ancoras, chave, &ledger, &mut |_, _| {
                        Ok(Transferencia {
                            de_subconta: None,
                            para: conta(outra)?,
                            quantia: QUANTIA,
                            taxa: None,
                            memo: Some(Vec::from(MEMO_FIXO)),
                            criada_em_ns: Some(segundos.saturating_mul(1_000_000_000)),
                        })
                    });
                }
                CICLOS if chave.is_some() => {
                    let passo = format!("ciclos {nome} {quem} transferencia");
                    let bloco = transferir(
                        &passo,
                        rede,
                        &ancoras,
                        chave,
                        &ledger,
                        &mut |remetente, hora| {
                            Ok(Transferencia {
                                de_subconta: None,
                                para: cmc::conta_de_deposito(&cmc, remetente),
                                quantia: QUANTIA,
                                taxa: None,
                                memo: Some(Vec::from(cmc::MEMO_DE_CUNHAGEM)),
                                criada_em_ns: Some(criada_em_ns(hora)),
                            })
                        },
                    );
                    let Some(bloco) = bloco.and_then(|b| u64::try_from(b).ok()) else {
                        continue;
                    };
                    let n = Notificacao {
                        bloco,
                        para_subconta: None,
                        memo_do_deposito: None,
                    };
                    let passo = format!("ciclos {nome} {quem} notificacao");
                    notificar(&passo, rede, &ancoras, chave, &cmc, &n);
                    ultima_notificacao = Some(n);
                }
                NOTIFICAR if chave.is_some() => match &ultima_notificacao {
                    Some(n) => {
                        let passo = format!("notificar {nome} {quem}");
                        notificar(&passo, rede, &ancoras, chave, &cmc, n);
                    }
                    None => {
                        escreverln!("carteira: nada a notificar");
                    }
                },
                outro => {
                    escreverln!(
                        "carteira: passo {} desconhecido com a conta {}",
                        outro,
                        quem
                    );
                }
            }
        }
    }
}
