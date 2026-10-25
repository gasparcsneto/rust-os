//! O gestor de canisters: uma pessoa ou um agente opera os canisters de
//! uma chave dela — cria, instala, lê o estado, para, inicia, troca os
//! controladores, desinstala, apaga, carrega cycles —, por um pedido no
//! armazém, e cada resposta é verificada antes de chegar aqui.
//!
//! O programa não tem argumentos — `user.run` não os passa. O pedido é um
//! arquivo, e a resposta outro, cada passo pelo gate:
//!
//! 1. quem opera grava o pedido em [`PEDIDO`] (`fs.write`): a ação, a
//!    rede, a chave e o que a ação pede — o formato e as regras estão em
//!    [`web3::icp::gestor`];
//! 2. lança o programa (`user.run`), com a autoridade dele;
//! 3. lê a resposta em [`RESPOSTA`] (`fs.read`), e o registro dos canisters
//!    da chave em [`REGISTROS`]`/<rede>/<principal da chave>`.
//!
//! # O caminho
//!
//! - **o arrendamento**: o programa arrenda o pedido (`fs.claim`) enquanto
//!   trabalha — ninguém mais o muda até ele acabar —, e o solta no fim;
//! - **quem pediu**: o pedido tem de ter sido gravado pela identidade que
//!   lançou o programa — o dono que o armazém diz dele é o da resposta que
//!   o programa grava ao começar. O armazém compartilhado deixa outra
//!   pessoa gravar ali, e ela não escolhe o que a chave de quem lançou
//!   assina;
//! - **o pedido**: a versão dele pelo `fs.stat`, o texto por um `abrir` só,
//!   conferido pela versão depois de lido, o SHA-256 do texto, e as regras:
//!   o que falta, sobra ou não confirma recusa o pedido antes de qualquer
//!   outra coisa;
//! - **a chave**: `key.read` — o Principal dela confere a regra dos
//!   controladores, e nomeia o registro;
//! - **o registro**: lido inteiro, ou nada — o que não se entende, o de
//!   outro dono e o que muda durante a leitura param o programa, sem
//!   sobrescrever; e o plano: o pedido que acabou não repete, o mesmo texto
//!   em andamento retoma com a mesma hora, e outro em andamento bloqueia —
//!   a resposta diz o texto dele, para quem for repeti-lo. Antes de mandar
//!   o que muda alguma coisa, o pedido vai para o registro como em
//!   andamento, com o texto, pela versão que se leu: dois programas não
//!   executam o mesmo pedido;
//! - **as chamadas**: cada uma pelo caminho inteiro — o DNS, o destino no
//!   gate, o TLS, os `POST`, a assinatura (`key.sign`, uma decisão por
//!   assinatura) e a verificação —, declarada ancorada na decisão da
//!   assinatura dela (`icp.update`; a consulta assinada, `icp.query`);
//! - **o fim**: o registro com o pedido feito, se o desfecho foi provado;
//!   em andamento, se não foi e alguma chamada que muda alguma coisa foi
//!   assinada — ela pode ter chegado ao IC —; e de volta ao que era, se
//!   nenhuma foi: nada saiu, e o pedido se repete como novo. O estado só
//!   lê, e os pedaços só enchem o depósito do canister: não contam. Depois,
//!   os canisters, e a resposta.
//!
//! # Os módulos
//!
//! Do disco da imagem ou do armazém, pelo `abrir`: uma decisão do gate, e o
//! `ler` do descritor sem outra. Até [`gestor::MAIOR_MODULO`]: o que cabe
//! num pedaço vai inteiro (`install_code`); o maior vai em pedaços de
//! 1 MiB, lidos um de cada vez — `upload_chunk` por pedaço, com o hash que
//! volta conferido contra o dos bytes lidos, e `install_chunked_code` com
//! os hashes e o do módulo inteiro, somado aos poucos —, e o depósito de
//! pedaços do canister é esvaziado no fim. O módulo que muda no meio da
//! leitura para tudo antes da instalação.
//!
//! Só se instalam os bytes que têm o `sha256` do pedido: o inteiro confere
//! antes do `install_code`, e o em pedaços, antes do
//! `install_chunked_code` — o que não confere esvazia o depósito e não
//! instala nada. O arquivo pode estar onde outra pessoa grava; o que a
//! chave instala é o que o pedido diz.
//!
//! # O que o programa não é
//!
//! O canister, o módulo, os cycles, os controladores e o registro não dão
//! nada a este processo, nem são recurso do Duke: o kernel não sabe o que
//! assina, quem controla um canister é um fato do IC, e o registro é dado
//! de quem opera. O que o programa pode é o que o gate decide para os
//! pedidos dele — `fs.read`, `fs.write`, `random.read`, `system.read`,
//! `net.connect`, `audit.declare`, `key.read` e `key.sign` —, com a
//! autoridade de quem o lançou. A rede principal é a do arquivo de redes, e
//! o destino dela, o que a política deixa — por padrão, nenhum.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "gestor",
    "net.connect",
    "random.read",
    "system.read",
    "fs.read",
    "fs.write",
    "audit.declare",
    "key.read",
    "key.sign"
);

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use programas::escreverln;
use programas::icp::{
    self, Ancora, Andamento, ChaveDoKernel, Desfecho, Falha, Final, Principal, Rede,
};
use programas::nativo;
use programas::sistema;
use programas::tls::{self, Ancoras, Hora};
use web3::icp::gerenciamento::{self, Ajustes, MAIOR_PEDACO, Modo, Situacao as DoIc};
use web3::icp::gestor::{self, Acao, Canister, Fase, Pedido, Plano, Registro, Situacao, Ultimo};
use web3::icp::resumo::{self, Hash, Sha256EmPedacos};
use web3::icp::{ciclos, cmc, icrc1};

/// O pedido, no diretório do gestor — que quem opera cria uma vez.
const PEDIDO: &str = "/armazem/compartilhado/gestor/pedido";
/// A resposta.
const RESPOSTA: &str = "/armazem/compartilhado/gestor/resposta";
/// Os registros: `<rede>/<principal da chave>`.
const REGISTROS: &str = "/armazem/compartilhado/gestor/registro";

/// As âncoras do TLS e o resolvedor, sem `ancoras` e `dns` no pedido: os
/// de uma máquina de verdade — as raízes públicas da imagem e o DNS do
/// emulador, que repassa ao do hospedeiro.
const ANCORAS_PADRAO: &str = "/dados/tls/publicas.pem";
const DNS_PADRAO: &str = "udp:10.0.2.3:53";

/// O ledger de ICP, o de cycles e o CMC: os ids da rede principal, em que
/// a PocketIC da bancada também os sobe.
const LEDGER_DE_ICP: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
const LEDGER_DE_CICLOS: &str = "um5iw-rqaaa-aaaaq-qaaba-cai";
const CMC: &str = "rkp4c-7iaaa-aaaaa-aaaca-cai";

/// O maior `ler` que o kernel aceita de uma vez: o resto é
/// `TAMANHO_INVALIDO`.
const MAIOR_LEITURA: usize = 4096;

/// Quanto o arrendamento do pedido dura: o teto, renovado pela atividade.
const PRAZO_DO_ARRENDAMENTO_MS: u64 = 300_000;

/// Os códigos de saída.
const FEITO: i64 = 90;
const REPETIDO: i64 = 91;
const RECUSADO: i64 = 92;
const BLOQUEADO: i64 = 93;
const EM_USO: i64 = 94;
const FALHOU: i64 = 95;
const SEM_REGISTRO: i64 = 96;

/// O fim do programa: o código de saída e as linhas da resposta.
struct Fim {
    codigo: i64,
    desfecho: &'static str,
    linhas: Vec<String>,
}

impl Fim {
    fn novo(codigo: i64, desfecho: &'static str, linha: impl Into<String>) -> Fim {
        Fim {
            codigo,
            desfecho,
            linhas: alloc::vec![linha.into()],
        }
    }
}

/// Bytes em hexadecimal minúsculo.
fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// O código de uma recusa no resultado de um comando do armazém: o
/// `code`, ou o do envelope.
fn codigo_de(r: &nativo::Resposta) -> Option<String> {
    match r.resultado() {
        Err(recusa) => Some(String::from(recusa.motivo.unwrap_or("TECHNICAL_ERROR"))),
        Ok(resultado) => {
            if resultado.member("ok").and_then(|v| v.as_bool()) == Some(false) {
                Some(String::from(
                    resultado
                        .member("code")
                        .and_then(|c| c.as_str())
                        .unwrap_or("ERROR"),
                ))
            } else {
                resultado
                    .member("code")
                    .and_then(|c| c.as_str())
                    .map(String::from)
            }
        }
    }
}

/// O que o armazém diz de um caminho: se é arquivo, a versão e o dono —
/// a identidade de quem o gravou por último.
struct Estatistica {
    arquivo: bool,
    versao: u64,
    dono: Option<String>,
}

fn estatistica(caminho: &str) -> Result<Estatistica, String> {
    let r = nativo::pedir("fs.stat", |w| w.field_str("path", caminho))
        .map_err(|e| format!("ERRO {e}"))?;
    if let Some(codigo) = codigo_de(&r) {
        return Err(codigo);
    }
    let resultado = r.resultado().map_err(|_| String::from("TECHNICAL_ERROR"))?;
    Ok(Estatistica {
        arquivo: resultado.member("type").and_then(|t| t.as_str()) == Some("file"),
        versao: resultado
            .member("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        dono: resultado
            .member("owner")
            .and_then(|v| v.as_str())
            .map(String::from),
    })
}

/// O conteúdo inteiro de `caminho`, por um `abrir` e quantos `ler` forem
/// precisos — uma decisão do gate —, até `teto` bytes.
fn ler_arquivo(caminho: &str, teto: usize) -> Result<Vec<u8>, String> {
    let fd = sistema::abrir(caminho);
    if fd < 0 {
        return Err(format!("abrir {fd}"));
    }
    let fd = fd as u64;
    let mut bytes = Vec::new();
    let mut buffer = alloc::vec![0u8; MAIOR_LEITURA];
    let r = loop {
        let n = sistema::ler(fd, &mut buffer);
        if n < 0 {
            break Err(format!("ler {n}"));
        }
        if n == 0 {
            break Ok(());
        }
        bytes.extend_from_slice(&buffer[..n as usize]);
        if bytes.len() > teto {
            break Err(String::from("grande demais"));
        }
    };
    sistema::fechar(fd);
    r.map(|()| bytes)
}

/// Grava `texto` em `caminho` pela versão `esperada` — zero para criar.
/// Devolve a versão nova, ou o código da recusa.
fn gravar(caminho: &str, texto: &str, esperada: u64) -> Result<u64, String> {
    let r = nativo::pedir("fs.write", |w| {
        w.field_str("path", caminho)?;
        w.field_str("content", texto)?;
        w.field_u64("expect_version", esperada)
    })
    .map_err(|e| format!("ERRO {e}"))?;
    if let Some(codigo) = codigo_de(&r) {
        return Err(codigo);
    }
    r.resultado()
        .ok()
        .and_then(|v| v.member("version").and_then(|v| v.as_u64()))
        .ok_or_else(|| String::from("TECHNICAL_ERROR"))
}

/// Cria o diretório, se não existe. O que falhar aparece na gravação
/// seguinte, que é quem precisa dele.
fn diretorio(caminho: &str) {
    let _ = nativo::pedir("fs.mkdir", |w| w.field_str("path", caminho));
}

/// Arrenda o pedido para a sessão de quem lançou o programa.
fn arrendar() -> Result<(), String> {
    let r = nativo::pedir("fs.claim", |w| {
        w.field_str("path", PEDIDO)?;
        w.field_u64("ttl_ms", PRAZO_DO_ARRENDAMENTO_MS)
    })
    .map_err(|e| format!("ERRO {e}"))?;
    match codigo_de(&r) {
        Some(codigo) => Err(codigo),
        None => Ok(()),
    }
}

fn soltar() {
    let _ = nativo::pedir("fs.release", |w| w.field_str("path", PEDIDO));
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
        escreverln!("gestor: {} pede {}", self.passo, etapa);
        self.gateway.post(caminho, corpo)
    }
}

/// O que se precisa para falar com a rede do pedido.
struct Contexto {
    rede: Rede,
    ancoras: Ancoras,
    dns: String,
    chave: String,
    /// Quantas chamadas que mudam alguma coisa foram assinadas: sem
    /// nenhuma, nada que mude alguma coisa saiu daqui.
    saidas: core::cell::Cell<u32>,
}

/// Para onde vai uma chamada.
#[derive(Clone, Copy)]
enum Destino {
    /// Um canister: um ledger, o CMC.
    Canister(Principal),
    /// O canister de gerenciamento, pelo canister efetivo — o que o método
    /// gerencia.
    Gerenciamento(Principal),
}

impl Destino {
    /// O assunto da declaração — no gerenciamento,
    /// `aaaaa-aa/<método>@<canister>`.
    fn assunto(&self, metodo: &str) -> String {
        match self {
            Destino::Canister(c) => icp::assunto(c, metodo),
            Destino::Gerenciamento(alvo) => icp::assunto(
                &Principal::GERENCIAMENTO,
                &format!("{metodo}@{}", alvo.texto()),
            ),
        }
    }
}

/// Uma chamada que acabou: o desfecho numa palavra, e a resposta, quando
/// foi provada.
struct Chamada {
    desfecho: &'static str,
    resposta: Option<Vec<u8>>,
    detalhe: String,
}

impl Chamada {
    /// O desfecho foi provado — a resposta, ou a recusa, pelo certificado.
    fn provada(&self) -> bool {
        matches!(
            self.desfecho,
            "verified" | "verified_reject" | "verified_done"
        )
    }
}

/// Uma chamada de `metodo` ao `destino` pelo caminho inteiro — a chave
/// lida, a hora, a conexão, a chamada assinada e as leituras da situação
/// enquanto pendente —, declarada ancorada na decisão da assinatura dela.
fn chamar(contexto: &Contexto, passo: &str, destino: Destino, metodo: &str, arg: &[u8]) -> Chamada {
    let assunto = destino.assunto(metodo);
    let mut kernel = None;
    let mut gateway = None;
    let mut leituras = 0u32;
    let r: Result<(icp::Atualizacao, Andamento), Falha> = (|| {
        let kernel = kernel.insert(ChaveDoKernel::ler(&contexto.chave)?);
        let hora = icp::hora()?;
        let nonce = icp::nonce()?;
        let gateway = gateway.insert(icp::conectar(
            &contexto.rede,
            &contexto.ancoras,
            &contexto.dns,
        )?);
        let mut narrado = Narrado { gateway, passo };
        let mut a = match destino {
            Destino::Canister(canister) => icp::chamar(
                &mut narrado,
                &contexto.rede,
                Some(&mut *kernel),
                &canister,
                metodo,
                arg,
                &hora,
                &nonce,
            )?,
            Destino::Gerenciamento(efetivo) => icp::chamar_ao_gerenciamento(
                &mut narrado,
                &contexto.rede,
                Some(&mut *kernel),
                &efetivo,
                metodo,
                arg,
                &hora,
                &nonce,
            )?,
        };
        let mut andamento = a.andamento.clone();
        while let Andamento::Pendente(_) = andamento
            && leituras < icp::MAIS_LEITURAS
        {
            narrado.gateway.esperar(icp::ESPERA_ENTRE_LEITURAS_MS)?;
            let hora = icp::hora()?;
            leituras += 1;
            andamento = icp::acompanhar(
                &mut narrado,
                &contexto.rede,
                Some(&mut *kernel),
                &mut a,
                &hora,
            )?;
        }
        Ok((a, andamento))
    })();
    let desfecho = icp::desfecho_da_chamada(r.as_ref().map(|(_, andamento)| andamento));
    // A chamada assinada pode ter saído — e, se muda alguma coisa, o pedido
    // não volta atrás sozinho. O estado só lê, e os pedaços só enchem o
    // depósito do canister, sem mexer no módulo nem nos dados dele.
    if !matches!(
        metodo,
        "canister_status" | "upload_chunk" | "clear_chunk_store"
    ) && kernel.as_ref().is_some_and(|k| k.assinaturas() > 0)
    {
        contexto.saidas.set(contexto.saidas.get() + 1);
    }
    let decisao = kernel
        .as_ref()
        .and_then(|k: &ChaveDoKernel| k.decisoes().first().copied());
    let ancora = match (decisao, gateway.as_ref()) {
        (Some(d), _) => Ancora::Decisao(d),
        (None, Some(g)) => Ancora::Conexao(g.conexao()),
        (None, None) => Ancora::Nenhuma,
    };
    let declarada = icp::declarar_chamada(&assunto, desfecho, ancora);
    let (resposta, detalhe) = match &r {
        Ok((_, Andamento::Certificado { desfecho, .. })) => match desfecho {
            Final::Respondida(bytes) => (Some(bytes.clone()), String::from("respondida")),
            Final::Recusada { codigo, erro, .. } => (
                None,
                format!("recusa {codigo} {}", erro.as_deref().unwrap_or("-")),
            ),
            Final::Concluida => (None, String::from("concluida")),
        },
        Ok((_, Andamento::RecusaNaoReplicada { codigo, erro, .. })) => (
            None,
            format!(
                "recusa sem prova {codigo} {}",
                erro.as_deref().unwrap_or("-")
            ),
        ),
        Ok((_, Andamento::Pendente(s))) => (None, format!("pendente {s}")),
        Err(f) => (None, format!("{f}")),
    };
    escreverln!(
        "gestor: {}: {}; declarada {}; leituras {}; {}",
        passo,
        desfecho,
        match &declarada {
            Ok(n) => format!("{n}"),
            Err(c) => format!("recusada {c}"),
        },
        leituras,
        detalhe
    );
    if let Some(g) = gateway {
        g.fechar();
    }
    Chamada {
        desfecho,
        resposta,
        detalhe,
    }
}

/// Uma consulta assinada de `metodo` a `canister`, declarada ancorada na
/// decisão da assinatura. Devolve a resposta verificada, ou o desfecho.
fn consultar(
    contexto: &Contexto,
    canister: &Principal,
    metodo: &str,
    arg: &[u8],
) -> Result<Vec<u8>, String> {
    let mut kernel = None;
    let mut gateway = None;
    let r = (|| {
        let kernel = kernel.insert(ChaveDoKernel::ler(&contexto.chave)?);
        let hora = icp::hora()?;
        let nonce = icp::nonce()?;
        let gateway = gateway.insert(icp::conectar(
            &contexto.rede,
            &contexto.ancoras,
            &contexto.dns,
        )?);
        let mut narrado = Narrado {
            gateway,
            passo: metodo,
        };
        icp::consultar_assinada(
            &mut narrado,
            &contexto.rede,
            kernel,
            canister,
            metodo,
            arg,
            &hora,
            &nonce,
        )
    })();
    let desfecho = icp::desfecho_da_consulta_assinada(&r);
    let decisao = kernel
        .as_ref()
        .and_then(|k: &ChaveDoKernel| k.decisoes().first().copied());
    let ancora = match (decisao, gateway.as_ref()) {
        (Some(d), _) => Ancora::Decisao(d),
        (None, Some(g)) => Ancora::Conexao(g.conexao()),
        (None, None) => Ancora::Nenhuma,
    };
    let _ = icp::declarar_consulta(&icp::assunto(canister, metodo), desfecho, ancora);
    if let Some(g) = gateway {
        g.fechar();
    }
    match r {
        Ok(v) => match v.desfecho {
            Desfecho::Respondida(bytes) => Ok(bytes),
            Desfecho::Recusada { codigo, .. } => Err(format!("{desfecho} {codigo}")),
        },
        Err(f) => Err(format!("{desfecho} {f}")),
    }
}

/// O que uma ação deu: o código, o desfecho, as linhas — e se o desfecho
/// foi provado, o que fecha o pedido no registro.
struct Feito {
    fim: Fim,
    provado: bool,
}

fn feito(chamada: &Chamada, linha: String) -> Feito {
    let provado = chamada.provada();
    Feito {
        fim: Fim {
            codigo: if chamada.desfecho == "verified" {
                FEITO
            } else {
                FALHOU
            },
            desfecho: chamada.desfecho,
            linhas: alloc::vec![linha],
        },
        provado,
    }
}

fn falhou(desfecho: &'static str, linha: String) -> Feito {
    Feito {
        fim: Fim::novo(FALHOU, desfecho, linha),
        provado: false,
    }
}

/// O hash de 32 bytes em hexadecimal.
fn dito(h: &Hash) -> String {
    hex(h)
}

/// Anota o canister no registro com a situação e o módulo dados.
fn anotar(
    registro: &mut Registro,
    canister: Principal,
    situacao: Situacao,
    modulo: Option<Option<Hash>>,
    ns: u64,
) {
    let antes = registro.canister(&canister).and_then(|c| c.modulo);
    let _ = registro.anotar(Canister {
        id: canister,
        situacao,
        modulo: modulo.unwrap_or(antes),
        ns,
    });
}

/// O saldo da chave no ledger de ICP e no de cycles.
fn saldo(contexto: &Contexto, principal: &Principal) -> Feito {
    let conta = icrc1::Conta {
        dono: *principal,
        subconta: None,
    };
    let arg = icrc1::argumento_do_saldo(&conta);
    let mut linhas = Vec::new();
    for (nome, ledger) in [("icp", LEDGER_DE_ICP), ("ciclos", LEDGER_DE_CICLOS)] {
        let ledger = Principal::de_texto(ledger).expect("o id e valido");
        match consultar(contexto, &ledger, "icrc1_balance_of", &arg) {
            Ok(bytes) => match icrc1::ler_saldo(&bytes) {
                Ok(s) => linhas.push(format!("saldo {nome} {s}")),
                Err(e) => return falhou("verified_malformed", format!("saldo {nome}: {e}")),
            },
            Err(e) => return falhou("failed_query", format!("saldo {nome}: {e}")),
        }
    }
    Feito {
        fim: Fim {
            codigo: FEITO,
            desfecho: "verified",
            linhas,
        },
        provado: true,
    }
}

/// O tamanho de um arquivo da árvore — do disco da imagem ou do armazém —,
/// pelo `fs.read` de um byte: o `size` que ele diz. A recusa é o código.
fn tamanho_de(caminho: &str) -> Result<u64, String> {
    let r = nativo::pedir("fs.read", |w| {
        w.field_str("path", caminho)?;
        w.field_u64("max", 1)
    })
    .map_err(|e| format!("ERRO {e}"))?;
    if let Some(codigo) = codigo_de(&r) {
        return Err(codigo);
    }
    r.resultado()
        .ok()
        .and_then(|v| v.member("size").and_then(|s| s.as_u64()))
        .ok_or_else(|| String::from("nao se le"))
}

/// Instala o módulo do pedido no canister — inteiro, ou em pedaços.
fn instalar(contexto: &Contexto, pedido: &Pedido, registro: &mut Registro, ns: u64) -> Feito {
    let canister = pedido.canister.expect("a instalacao tem canister");
    let caminho = pedido.modulo.as_deref().expect("a instalacao tem modulo");
    let modo = pedido.modo.expect("a instalacao tem modo");
    let sha256 = pedido.sha256.expect("a instalacao tem sha256");
    // O tamanho antes de qualquer pedaço subir: o módulo acima do teto não
    // manda nada.
    let tamanho = match tamanho_de(caminho) {
        Ok(t) => t,
        Err(c) => return falhou("failed_module", format!("modulo {caminho}: {c}")),
    };
    if tamanho > gestor::MAIOR_MODULO {
        return falhou(
            "failed_module",
            format!("modulo {caminho}: {tamanho} bytes, acima do teto"),
        );
    }
    let fd = sistema::abrir(caminho);
    if fd < 0 {
        return falhou("failed_module", format!("modulo {caminho}: abrir {fd}"));
    }
    let fd = fd as u64;
    let r = instalar_do_descritor(contexto, &canister, modo, &pedido.argumento, &sha256, fd);
    sistema::fechar(fd);
    match r {
        Ok((chamada, hash, n, pedacos)) => {
            if chamada.desfecho == "verified" {
                anotar(registro, canister, Situacao::Ativo, Some(Some(hash)), ns);
            }
            let mut f = feito(
                &chamada,
                format!(
                    "modulo {} {} bytes {} pedacos; {}",
                    dito(&hash),
                    n,
                    pedacos,
                    chamada.detalhe
                ),
            );
            if chamada.desfecho == "verified" && pedacos > 1 {
                // O depósito de pedaços do canister: esvaziado depois da
                // instalação, que já não precisa dele.
                let limpeza = chamar(
                    contexto,
                    "limpeza",
                    Destino::Gerenciamento(canister),
                    "clear_chunk_store",
                    &gerenciamento::argumento_do_canister(&canister),
                );
                f.fim
                    .linhas
                    .push(format!("deposito de pedacos: {}", limpeza.desfecho));
            }
            f
        }
        Err(f) => f,
    }
}

/// O módulo que não é o do pedido: nada se instala.
fn outro_modulo(hash: &Hash) -> Feito {
    falhou(
        "failed_module",
        format!("o modulo lido tem sha256 {}, e nao o do pedido", dito(hash)),
    )
}

/// O resto da instalação, com o módulo aberto em `fd`: só os bytes que
/// têm o `sha256` do pedido se instalam.
fn instalar_do_descritor(
    contexto: &Contexto,
    canister: &Principal,
    modo: Modo,
    argumento: &[u8],
    sha256: &Hash,
    fd: u64,
) -> Result<(Chamada, Hash, u64, usize), Feito> {
    let mut pedaco = alloc::vec![0u8; MAIOR_PEDACO];
    let mut soma = Sha256EmPedacos::novo();
    let mut total = 0u64;
    let mut hashes: Vec<Hash> = Vec::new();
    let mut cheio = encher(fd, &mut pedaco)?;
    if cheio == 0 {
        return Err(falhou("failed_module", String::from("modulo vazio")));
    }
    // Cada volta tem um pedaço cheio — ou o último, que pode não ser.
    loop {
        let atual = &pedaco[..cheio];
        total += atual.len() as u64;
        if total > gestor::MAIOR_MODULO {
            return Err(falhou(
                "failed_module",
                String::from("modulo acima do teto"),
            ));
        }
        soma.juntar(atual);
        // Mais um byte diz se o arquivo continua: ele é o primeiro do
        // pedaço seguinte.
        let mut um = [0u8; 1];
        let n = sistema::ler(fd, &mut um);
        if n < 0 {
            return Err(ler_falhou(n));
        }
        let continua = n == 1;
        if !continua && hashes.is_empty() {
            // Cabe num pedaço: vai inteiro.
            let hash = soma.fim();
            escreverln!("gestor: modulo {} {} bytes inteiro", dito(&hash), total);
            if hash != *sha256 {
                return Err(outro_modulo(&hash));
            }
            let arg = gerenciamento::argumento_da_instalacao(modo, canister, atual, argumento)
                .map_err(|e| falhou("failed_module", format!("{e}")))?;
            let c = chamar(
                contexto,
                "instalacao",
                Destino::Gerenciamento(*canister),
                "install_code",
                &arg,
            );
            return Ok((c, hash, total, 1));
        }
        // Em pedaços: este sobe agora.
        let esperado = resumo::sha256(atual);
        let passo = format!("pedaco {}", hashes.len() + 1);
        let arg = gerenciamento::argumento_do_pedaco(canister, atual)
            .map_err(|e| falhou("failed_module", format!("{e}")))?;
        let c = chamar(
            contexto,
            &passo,
            Destino::Gerenciamento(*canister),
            "upload_chunk",
            &arg,
        );
        let Some(resposta) = c.resposta.as_deref().filter(|_| c.desfecho == "verified") else {
            return Err(feito(&c, format!("{passo}: {}", c.detalhe)));
        };
        match gerenciamento::ler_pedaco(resposta) {
            Ok(h) if h == esperado => hashes.push(h),
            Ok(_) => {
                return Err(falhou(
                    "verified_mismatch",
                    format!("{passo}: o hash que voltou nao e o dos bytes lidos"),
                ));
            }
            Err(e) => return Err(falhou("verified_malformed", format!("{passo}: {e}"))),
        }
        if !continua {
            break;
        }
        pedaco[0] = um[0];
        cheio = 1 + encher(fd, &mut pedaco[1..])?;
    }
    let hash = soma.fim();
    escreverln!(
        "gestor: modulo {} {} bytes em {} pedacos",
        dito(&hash),
        total,
        hashes.len()
    );
    if hash != *sha256 {
        // Os pedaços que subiram não instalam nada: o depósito se esvazia.
        let limpeza = chamar(
            contexto,
            "limpeza",
            Destino::Gerenciamento(*canister),
            "clear_chunk_store",
            &gerenciamento::argumento_do_canister(canister),
        );
        let mut f = outro_modulo(&hash);
        f.fim
            .linhas
            .push(format!("deposito de pedacos: {}", limpeza.desfecho));
        return Err(f);
    }
    let arg = gerenciamento::argumento_da_instalacao_em_pedacos(
        modo, canister, &hashes, &hash, argumento,
    )
    .map_err(|e| falhou("failed_module", format!("{e}")))?;
    let c = chamar(
        contexto,
        "instalacao",
        Destino::Gerenciamento(*canister),
        "install_chunked_code",
        &arg,
    );
    Ok((c, hash, total, hashes.len()))
}

/// A falha de um `ler`: o módulo que mudou no meio, ou outra.
fn ler_falhou(n: i64) -> Feito {
    if n == programas::sistema::erro::MUDOU {
        falhou(
            "failed_module",
            String::from("o modulo mudou durante a leitura"),
        )
    } else {
        falhou("failed_module", format!("ler {n}"))
    }
}

/// Enche `destino` do descritor, até o fim dele ou do arquivo, de
/// [`MAIOR_LEITURA`] em [`MAIOR_LEITURA`]. Devolve quantos bytes vieram.
fn encher(fd: u64, destino: &mut [u8]) -> Result<usize, Feito> {
    let mut cheio = 0;
    while cheio < destino.len() {
        let ate = destino.len().min(cheio + MAIOR_LEITURA);
        let n = sistema::ler(fd, &mut destino[cheio..ate]);
        if n < 0 {
            return Err(ler_falhou(n));
        }
        if n == 0 {
            break;
        }
        cheio += n as usize;
    }
    Ok(cheio)
}

/// O estado do canister, dito numa linha por coisa.
fn estado(contexto: &Contexto, canister: &Principal) -> Result<gerenciamento::Estado, Feito> {
    let c = chamar(
        contexto,
        "estado",
        Destino::Gerenciamento(*canister),
        "canister_status",
        &gerenciamento::argumento_do_canister(canister),
    );
    match (c.desfecho, c.resposta.as_deref()) {
        ("verified", Some(bytes)) => gerenciamento::ler_estado(bytes)
            .map_err(|e| falhou("verified_malformed", format!("estado: {e}"))),
        _ => Err(feito(&c, format!("estado: {}", c.detalhe))),
    }
}

fn linhas_do_estado(e: &gerenciamento::Estado) -> Vec<String> {
    let mut l = alloc::vec![
        format!("situacao {}", e.situacao.nome()),
        format!(
            "modulo {}",
            e.modulo.as_ref().map_or(String::from("nenhum"), dito)
        ),
        format!("cycles {}", e.cycles),
        format!("memoria {}", e.memoria),
    ];
    if let Some(s) = e.congelamento {
        l.push(format!("congelamento {s}"));
    }
    for c in &e.controladores {
        l.push(format!("controlador {}", c.texto()));
    }
    l
}

/// Uma chamada ao gerenciamento que não devolve nada, sobre o canister.
fn vazia(
    contexto: &Contexto,
    passo: &str,
    canister: &Principal,
    metodo: &str,
    arg: &[u8],
) -> Chamada {
    let mut c = chamar(
        contexto,
        passo,
        Destino::Gerenciamento(*canister),
        metodo,
        arg,
    );
    if c.desfecho == "verified"
        && let Some(bytes) = c.resposta.as_deref()
        && let Err(e) = gerenciamento::ler_vazio(bytes)
    {
        c.desfecho = "verified_malformed";
        c.detalhe = format!("{e}");
    }
    c
}

/// Executa o pedido.
fn executar(
    contexto: &Contexto,
    pedido: &Pedido,
    principal: &Principal,
    registro: &mut Registro,
    criado_em_ns: u64,
    ns: u64,
) -> Feito {
    let canister = pedido.canister;
    match pedido.acao {
        Acao::Saldo => saldo(contexto, principal),
        Acao::Criar => {
            let ciclos = pedido.ciclos.expect("a criacao tem ciclos");
            let criacao = ciclos::Criacao {
                quantia: ciclos,
                criada_em_ns: Some(criado_em_ns),
                controladores: None,
            };
            let arg = match ciclos::argumento_da_criacao(&criacao) {
                Ok(a) => a,
                Err(e) => return falhou("failed_request", format!("{e}")),
            };
            let ledger = Principal::de_texto(LEDGER_DE_CICLOS).expect("o id e valido");
            let c = chamar(
                contexto,
                "criar",
                Destino::Canister(ledger),
                "create_canister",
                &arg,
            );
            let Some(bytes) = c.resposta.as_deref().filter(|_| c.desfecho == "verified") else {
                return feito(&c, format!("criar: {}", c.detalhe));
            };
            match ciclos::ler_criacao(bytes) {
                Ok(Ok(criado)) => {
                    anotar(registro, criado.canister, Situacao::Ativo, Some(None), ns);
                    feito(
                        &c,
                        format!(
                            "canister {} bloco {}",
                            criado.canister.texto(),
                            criado.bloco
                        ),
                    )
                }
                Ok(Err(ciclos::RecusaDaCriacao::Duplicada {
                    bloco,
                    canister: Some(c2),
                })) => {
                    anotar(registro, c2, Situacao::Ativo, None, ns);
                    feito(
                        &c,
                        format!("canister {} bloco {} duplicada", c2.texto(), bloco),
                    )
                }
                Ok(Err(recusa)) => Feito {
                    fim: Fim::novo(FALHOU, "verified_ledger_error", format!("erro {recusa}")),
                    provado: true,
                },
                Err(e) => falhou("verified_malformed", format!("criar: {e}")),
            }
        }
        Acao::Instalar => instalar(contexto, pedido, registro, ns),
        Acao::Estado => {
            let canister = canister.expect("tem canister");
            match estado(contexto, &canister) {
                Ok(e) => {
                    let situacao = match e.situacao {
                        DoIc::Parado => Situacao::Parado,
                        _ => Situacao::Ativo,
                    };
                    anotar(registro, canister, situacao, Some(e.modulo), ns);
                    Feito {
                        fim: Fim {
                            codigo: FEITO,
                            desfecho: "verified",
                            linhas: linhas_do_estado(&e),
                        },
                        provado: true,
                    }
                }
                Err(f) => f,
            }
        }
        Acao::Parar | Acao::Iniciar => {
            let canister = canister.expect("tem canister");
            let (metodo, situacao) = if pedido.acao == Acao::Parar {
                ("stop_canister", Situacao::Parado)
            } else {
                ("start_canister", Situacao::Ativo)
            };
            let c = vazia(
                contexto,
                pedido.acao.nome(),
                &canister,
                metodo,
                &gerenciamento::argumento_do_canister(&canister),
            );
            if c.desfecho == "verified" {
                anotar(registro, canister, situacao, None, ns);
            }
            feito(&c, format!("{}: {}", pedido.acao.nome(), c.detalhe))
        }
        Acao::Controladores | Acao::Congelamento => {
            let canister = canister.expect("tem canister");
            let ajustes = if pedido.acao == Acao::Controladores {
                Ajustes {
                    controladores: Some(pedido.controladores.clone()),
                    congelamento: None,
                }
            } else {
                Ajustes {
                    controladores: None,
                    congelamento: pedido.congelamento,
                }
            };
            let arg = match gerenciamento::argumento_dos_ajustes(&canister, &ajustes) {
                Ok(a) => a,
                Err(e) => return falhou("failed_request", format!("{e}")),
            };
            let c = vazia(
                contexto,
                pedido.acao.nome(),
                &canister,
                "update_settings",
                &arg,
            );
            feito(&c, format!("{}: {}", pedido.acao.nome(), c.detalhe))
        }
        Acao::Desinstalar => {
            let canister = canister.expect("tem canister");
            let c = vazia(
                contexto,
                "desinstalar",
                &canister,
                "uninstall_code",
                &gerenciamento::argumento_da_desinstalacao(&canister),
            );
            if c.desfecho == "verified" {
                let situacao = registro
                    .canister(&canister)
                    .map_or(Situacao::Ativo, |r| r.situacao);
                anotar(registro, canister, situacao, Some(None), ns);
            }
            feito(&c, format!("desinstalar: {}", c.detalhe))
        }
        Acao::Apagar => {
            let canister = canister.expect("tem canister");
            // Só o parado se apaga: o estado primeiro, pelo IC.
            let e = match estado(contexto, &canister) {
                Ok(e) => e,
                Err(f) => return f,
            };
            if e.situacao != DoIc::Parado {
                return Feito {
                    fim: Fim::novo(
                        RECUSADO,
                        "refused_running",
                        format!(
                            "o canister esta {}: pare antes de apagar",
                            e.situacao.nome()
                        ),
                    ),
                    provado: true,
                };
            }
            let c = vazia(
                contexto,
                "apagar",
                &canister,
                "delete_canister",
                &gerenciamento::argumento_do_canister(&canister),
            );
            if c.desfecho == "verified" {
                anotar(registro, canister, Situacao::Apagado, Some(None), ns);
            }
            feito(
                &c,
                format!("apagar: {}; cycles perdidos {}", c.detalhe, e.cycles),
            )
        }
        Acao::Carregar => {
            let canister = canister.expect("tem canister");
            let carga = ciclos::Carga {
                para: canister,
                quantia: pedido.ciclos.expect("a carga tem ciclos"),
                criada_em_ns: Some(criado_em_ns),
            };
            let ledger = Principal::de_texto(LEDGER_DE_CICLOS).expect("o id e valido");
            let c = chamar(
                contexto,
                "carregar",
                Destino::Canister(ledger),
                "withdraw",
                &ciclos::argumento_da_carga(&carga),
            );
            let Some(bytes) = c.resposta.as_deref().filter(|_| c.desfecho == "verified") else {
                return feito(&c, format!("carregar: {}", c.detalhe));
            };
            match ciclos::ler_carga(bytes) {
                Ok(Ok(bloco)) => feito(&c, format!("carregado bloco {bloco}")),
                Ok(Err(ciclos::RecusaDaCarga::Duplicada { bloco })) => {
                    feito(&c, format!("carregado bloco {bloco} duplicada"))
                }
                Ok(Err(recusa)) => Feito {
                    fim: Fim::novo(FALHOU, "verified_ledger_error", format!("erro {recusa}")),
                    provado: true,
                },
                Err(e) => falhou("verified_malformed", format!("carregar: {e}")),
            }
        }
        Acao::Recarregar => recarregar(contexto, pedido, criado_em_ns),
    }
}

/// ICP da chave em cycles do canister: a transferência para a conta de
/// recarga dele no CMC e o `notify_top_up` com o bloco.
fn recarregar(contexto: &Contexto, pedido: &Pedido, criado_em_ns: u64) -> Feito {
    let canister = pedido.canister.expect("tem canister");
    let cmc_id = Principal::de_texto(CMC).expect("o id e valido");
    let ledger = Principal::de_texto(LEDGER_DE_ICP).expect("o id e valido");
    let t = icrc1::Transferencia {
        de_subconta: None,
        para: cmc::conta_de_recarga(&cmc_id, &canister),
        quantia: u128::from(pedido.icp.expect("a recarga tem icp")),
        taxa: None,
        memo: Some(Vec::from(cmc::MEMO_DE_RECARGA)),
        criada_em_ns: Some(criado_em_ns),
    };
    let arg = match icrc1::argumento_da_transferencia(&t) {
        Ok(a) => a,
        Err(e) => return falhou("failed_request", format!("{e}")),
    };
    let c = chamar(
        contexto,
        "transferencia",
        Destino::Canister(ledger),
        "icrc1_transfer",
        &arg,
    );
    let Some(bytes) = c.resposta.as_deref().filter(|_| c.desfecho == "verified") else {
        return feito(&c, format!("transferencia: {}", c.detalhe));
    };
    let bloco = match icrc1::ler_transferencia(bytes) {
        Ok(Ok(b)) => b,
        Ok(Err(icrc1::Recusa::Duplicada { bloco })) => bloco,
        Ok(Err(recusa)) => {
            return Feito {
                fim: Fim::novo(FALHOU, "verified_ledger_error", format!("erro {recusa}")),
                provado: true,
            };
        }
        Err(e) => return falhou("verified_malformed", format!("transferencia: {e}")),
    };
    let Ok(bloco64) = u64::try_from(bloco) else {
        return falhou("verified_malformed", String::from("bloco acima de 64 bits"));
    };
    let n = chamar(
        contexto,
        "notificacao",
        Destino::Canister(cmc_id),
        "notify_top_up",
        &cmc::argumento_da_recarga(bloco64, &canister),
    );
    let Some(bytes) = n.resposta.as_deref().filter(|_| n.desfecho == "verified") else {
        return feito(&n, format!("bloco {bloco}; notificacao: {}", n.detalhe));
    };
    match cmc::ler_recarga(bytes) {
        Ok(Ok(cycles)) => feito(&n, format!("recarregado bloco {bloco} cycles {cycles}")),
        // Outra notificação do mesmo bloco em curso: o pedido continua em
        // andamento, e repetir conclui.
        Ok(Err(cmc::Recusa::Processando)) => falhou(
            "pending_notify",
            format!("bloco {bloco}; notificacao em curso"),
        ),
        Ok(Err(recusa)) => Feito {
            fim: Fim::novo(
                FALHOU,
                "verified_cmc_error",
                format!("bloco {bloco}; erro {recusa}"),
            ),
            provado: true,
        },
        Err(e) => falhou("verified_malformed", format!("notificacao: {e}")),
    }
}

/// A resposta, pela versão que se leu ou gravou: cada gravação é pela
/// anterior, e a de outro no meio recusa a seguinte.
struct Resposta {
    versao: u64,
}

impl Resposta {
    fn nova() -> Resposta {
        Resposta {
            versao: estatistica(RESPOSTA).map_or(0, |e| e.versao),
        }
    }

    fn gravar(&mut self, texto: &str) -> Result<u64, String> {
        let v = gravar(RESPOSTA, texto, self.versao)?;
        self.versao = v;
        Ok(v)
    }

    /// Diz que o pedido `versao` está sendo trabalhado, e devolve quem o
    /// trabalha: o dono que o armazém deu à resposta que acabou de se
    /// gravar — a identidade de quem lançou o programa. A versão confere:
    /// outro que gravasse no meio seria o dono lido.
    fn trabalhando(&mut self, versao: u64) -> Result<String, String> {
        let v = self.gravar(&format!("pedido {versao}\ndesfecho working\n"))?;
        let e = estatistica(RESPOSTA)?;
        if e.versao != v {
            return Err(String::from("a resposta mudou no meio"));
        }
        e.dono.ok_or_else(|| String::from("a resposta sem dono"))
    }

    /// Grava o fim: o pedido, a ação, o desfecho e as linhas.
    fn fim(&mut self, versao: Option<u64>, acao: Option<Acao>, fim: &Fim) {
        let mut texto = String::new();
        if let Some(v) = versao {
            texto.push_str(&format!("pedido {v}\n"));
        }
        if let Some(a) = acao {
            texto.push_str(&format!("acao {}\n", a.nome()));
        }
        texto.push_str(&format!("desfecho {}\n", fim.desfecho));
        for l in &fim.linhas {
            texto.push_str(l);
            texto.push('\n');
            escreverln!("gestor: {}", l);
        }
        let gravada = self.gravar(&texto);
        escreverln!(
            "gestor: desfecho {}; resposta {}",
            fim.desfecho,
            match gravada {
                Ok(v) => format!("versao {v}"),
                Err(c) => format!("recusada {c}"),
            }
        );
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    // Sem o arrendamento, nada — nem a resposta, que é de quem o tem.
    if let Err(codigo) = arrendar() {
        escreverln!("gestor: o pedido nao se arrendou: {}", codigo);
        return if codigo == "CONFLICT" {
            EM_USO
        } else {
            RECUSADO
        };
    }
    let mut resposta = Resposta::nova();
    let (versao, acao, fim) = trabalhar(&mut resposta);
    resposta.fim(versao, acao, &fim);
    soltar();
    fim.codigo
}

/// Lê o registro em `caminho`, gravado por `eu`: inteiro, ou nada. Devolve
/// o registro e a versão dele — zero, sem registro.
fn ler_registro(caminho: &str, eu: &str) -> Result<(Registro, u64), String> {
    let e = estatistica(caminho)?;
    if !e.arquivo {
        return Ok((Registro::default(), 0));
    }
    // De outro, não: quem pode gravar no armazém compartilhado não muda o
    // plano de quem lançou o programa.
    if e.dono.as_deref() != Some(eu) {
        return Err(format!(
            "gravado por {}, e nao por quem lancou o gestor",
            e.dono.as_deref().unwrap_or("ninguem")
        ));
    }
    let bytes = ler_arquivo(caminho, gestor::MAIOR_REGISTRO)?;
    // O que se leu é o da versão vista: o que mudou no meio não vale.
    if estatistica(caminho)?.versao != e.versao {
        return Err(String::from("o registro mudou durante a leitura"));
    }
    let texto = core::str::from_utf8(&bytes).map_err(|_| String::from("nao e utf-8"))?;
    let registro = gestor::ler_registro(texto).map_err(|e| e.to_string())?;
    Ok((registro, e.versao))
}

/// O programa inteiro, até a resposta.
fn trabalhar(resposta: &mut Resposta) -> (Option<u64>, Option<Acao>, Fim) {
    // O pedido: a versão, quem o gravou, o texto e as regras.
    let est = match estatistica(PEDIDO) {
        Ok(e) if e.arquivo => e,
        Ok(_) => {
            return (
                None,
                None,
                Fim::novo(RECUSADO, "failed_request", "sem pedido"),
            );
        }
        Err(c) => {
            return (
                None,
                None,
                Fim::novo(RECUSADO, "failed_request", format!("pedido: {c}")),
            );
        }
    };
    let versao = Some(est.versao);
    // Quem lançou o programa, e quem gravou o pedido: a mesma identidade.
    // O armazém compartilhado deixa outra pessoa gravar o pedido — e ela
    // não escolhe o que a chave de quem lançou assina.
    let eu = match resposta.trabalhando(est.versao) {
        Ok(d) => d,
        Err(c) => {
            return (
                versao,
                None,
                Fim::novo(FALHOU, "failed_response", format!("resposta: {c}")),
            );
        }
    };
    if est.dono.as_deref() != Some(eu.as_str()) {
        return (
            versao,
            None,
            Fim::novo(
                RECUSADO,
                "refused_owner",
                format!(
                    "o pedido foi gravado por {}, e nao por quem lancou o gestor",
                    est.dono.as_deref().unwrap_or("ninguem")
                ),
            ),
        );
    }
    let bytes = match ler_arquivo(PEDIDO, gestor::MAIOR_PEDIDO) {
        Ok(b) => b,
        Err(e) => {
            return (
                versao,
                None,
                Fim::novo(RECUSADO, "failed_request", format!("pedido: {e}")),
            );
        }
    };
    // O texto lido é o da versão vista — e do dono visto.
    match estatistica(PEDIDO) {
        Ok(e) if e.versao == est.versao => {}
        _ => {
            return (
                versao,
                None,
                Fim::novo(
                    RECUSADO,
                    "failed_request",
                    "o pedido mudou durante a leitura",
                ),
            );
        }
    }
    let Ok(texto) = core::str::from_utf8(&bytes) else {
        return (
            versao,
            None,
            Fim::novo(RECUSADO, "failed_request", "pedido que nao e utf-8"),
        );
    };
    let resumo_do_pedido = resumo::sha256(&bytes);
    let pedido = match gestor::ler_pedido(texto) {
        Ok(p) => p,
        Err(e) => {
            return (
                versao,
                None,
                Fim::novo(RECUSADO, "failed_request", format!("pedido: {e}")),
            );
        }
    };
    let acao = Some(pedido.acao);
    escreverln!(
        "gestor: pedido {} {} na rede {} pela {}",
        est.versao,
        pedido.acao.nome(),
        pedido.rede,
        pedido.chave
    );

    // A rede, as âncoras e a chave.
    let rede = match icp::rede(&pedido.rede) {
        Ok(r) => r,
        Err(f) => {
            return (
                versao,
                acao,
                Fim::novo(RECUSADO, "failed_network", format!("rede: {f}")),
            );
        }
    };
    let ancoras = match tls::ancoras(pedido.ancoras.as_deref().unwrap_or(ANCORAS_PADRAO)) {
        Ok(a) => a,
        Err(f) => {
            return (
                versao,
                acao,
                Fim::novo(
                    RECUSADO,
                    "failed_anchors",
                    format!("ancoras: {}", f.codigo()),
                ),
            );
        }
    };
    let chave = match ChaveDoKernel::ler(&pedido.chave) {
        Ok(c) => c,
        Err(f) => {
            return (
                versao,
                acao,
                Fim::novo(FALHOU, "failed_key", format!("{f}")),
            );
        }
    };
    let principal = chave.principal();
    if let Err(motivo) = gestor::conferir_controladores(&pedido, &principal) {
        return (versao, acao, Fim::novo(RECUSADO, "failed_request", motivo));
    }
    let contexto = Contexto {
        rede,
        ancoras,
        dns: pedido
            .dns
            .clone()
            .unwrap_or_else(|| String::from(DNS_PADRAO)),
        chave: pedido.chave.clone(),
        saidas: core::cell::Cell::new(0),
    };

    // O registro da chave na rede: inteiro, ou nada.
    diretorio(REGISTROS);
    let pasta = format!("{REGISTROS}/{}", pedido.rede);
    diretorio(&pasta);
    let caminho = format!("{pasta}/{}", principal.texto());
    let (mut registro, mut versao_do_registro) = match ler_registro(&caminho, &eu) {
        Ok(r) => r,
        Err(m) => {
            return (
                versao,
                acao,
                Fim::novo(SEM_REGISTRO, "failed_registry", format!("{caminho}: {m}")),
            );
        }
    };
    // O que estava, para não regravar o registro que não mudou.
    let mut texto_do_registro = if versao_do_registro == 0 {
        String::new()
    } else {
        registro.texto()
    };

    // O plano.
    let hora: Hora = match icp::hora() {
        Ok(h) => h,
        Err(f) => {
            return (
                versao,
                acao,
                Fim::novo(FALHOU, "failed_clock", format!("{f}")),
            );
        }
    };
    let agora_ns = hora.validade_s().saturating_mul(1_000_000_000);
    let plano = gestor::planejar(
        est.versao,
        pedido.acao,
        &resumo_do_pedido,
        &registro,
        agora_ns,
    );
    let criado_em_ns = match plano {
        Plano::JaFeito => {
            return (
                versao,
                acao,
                Fim::novo(REPETIDO, "repeated", "o pedido ja foi feito"),
            );
        }
        Plano::Bloqueado {
            pendente,
            versao: v,
        } => {
            let mut fim = Fim::novo(
                BLOQUEADO,
                "blocked",
                format!(
                    "o pedido {v} ({}) ficou em andamento: repita-o",
                    pendente.nome()
                ),
            );
            // O texto dele, para quem for repeti-lo: cada linha depois de
            // `pendente `.
            if let Some(t) = registro.ultimo.as_ref().and_then(|u| u.pendente()) {
                fim.linhas
                    .extend(t.lines().map(|l| format!("pendente {l}")));
            }
            return (versao, acao, fim);
        }
        Plano::Retomar { criado_em_ns } => {
            escreverln!("gestor: retoma o pedido em andamento, com a hora dele");
            criado_em_ns
        }
        Plano::Executar { criado_em_ns } => criado_em_ns,
    };

    // O pedido em andamento, antes de mandar o que muda alguma coisa.
    let anterior = registro.ultimo.clone();
    if !pedido.acao.so_le() {
        registro.ultimo = Some(Ultimo {
            pedido: est.versao,
            acao: pedido.acao,
            fase: Fase::Andamento(String::from(texto)),
            criado_em_ns,
            resumo: resumo_do_pedido,
        });
        match gravar(&caminho, &registro.texto(), versao_do_registro) {
            Ok(v) => {
                versao_do_registro = v;
                texto_do_registro = registro.texto();
            }
            Err(c) => {
                return (
                    versao,
                    acao,
                    Fim::novo(EM_USO, "busy", format!("o registro mudou: {c}")),
                );
            }
        }
    }

    let feito = executar(
        &contexto,
        &pedido,
        &principal,
        &mut registro,
        criado_em_ns,
        agora_ns,
    );
    let mut fim = feito.fim;

    // O registro de volta: o pedido feito, se provado; de volta ao de
    // antes, se nada que muda alguma coisa foi assinado — nada saiu, e o
    // pedido pode ser repetido como novo —; e os canisters.
    if !pedido.acao.so_le() {
        if feito.provado {
            if let Some(u) = registro.ultimo.as_mut() {
                u.fase = Fase::Feito;
            }
        } else if contexto.saidas.get() == 0 {
            registro.ultimo = anterior;
            fim.linhas.push(String::from(
                "nada que muda o canister foi assinado: o pedido nao ficou em andamento",
            ));
        }
    }
    let mudou = registro.texto() != texto_do_registro;
    if mudou && let Err(c) = gravar(&caminho, &registro.texto(), versao_do_registro) {
        fim.linhas.push(format!("o registro nao se gravou: {c}"));
        return (versao, acao, fim);
    }
    fim.linhas.push(format!("registro {caminho}"));
    (versao, acao, fim)
}
