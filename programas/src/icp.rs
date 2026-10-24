//! O Internet Computer de um programa: a consulta verificada e a chamada
//! de atualização verificada do pacote `web3` ([`web3::icp`]), sobre o
//! HTTPS do Duke ([`crate::http`]) — do anônimo, ou assinadas pela chave
//! que o kernel guarda para quem lançou o processo ([`ChaveDoKernel`]).
//!
//! # O caminho de uma consulta
//!
//! 1. **as redes**: as de `/dados/icp/redes`, lidas por `fs.read`, pelo
//!    gate — o nome, o endpoint e a chave da raiz ([`registro`]). A chave
//!    nunca se aprende da rede;
//! 2. **a conexão**: o host do endpoint pelo DNS do programa, ou o
//!    endereço fixo do arquivo → `net.connect` → TLS 1.3 com as âncoras do
//!    programa → HTTP/1.1. É a conexão de [`crate::http::conectar`], e o
//!    gate a decide como qualquer outra: o destino inteiro, o alcance do
//!    papel, o manifesto, o firewall;
//! 3. **os pedidos**: um `POST` `application/cbor` por passo do agente
//!    ([`agente::consultar`]), com cada `net.send` e cada `net.recv`
//!    decididos de novo — a revogação, a contenção e o firewall valem no
//!    meio de uma consulta;
//! 4. **a verificação**, aqui no processo: o certificado da sub-rede até a
//!    raiz do arquivo, e a resposta contra os nós dele, com a hora da regra
//!    de `protocolo::usuario::hora` ([`hora`]) e um nonce do `random.read`
//!    ([`nonce`]). Nada é entregue antes dela;
//! 5. **a declaração**: o que o programa concluiu, por `audit.declare`,
//!    ancorada na conexão em que a consulta foi ([`declarar`]): o kernel
//!    escreve o destino real dela, e o programa não o diz.
//!
//! # O desfecho, numa palavra
//!
//! O que se declara é o que o programa concluiu ([`desfecho`]):
//! `verified` — os nós responderam isto a este pedido —, `verified_reject`
//! — os nós provaram que o canister recusou —, `unverified_<etapa>` — a
//! prova não fechou: o certificado, a leitura de estado ou a resposta —, e
//! `failed_<etapa>` quando não houve o que verificar: o transporte, o HTTP,
//! o pedido. A convenção `unverified` é a que o NSF observa (ver
//! `seguranca::regras`); o kernel não lê nenhuma delas.
//!
//! # A chamada de atualização
//!
//! Do anônimo, ou assinada pela chave `chave:<nome>` de quem lançou o
//! processo — a pessoa, o agente: a identidade durável do Duke, nunca o
//! processo nem a sessão. O programa lê a pública por `key.read` e pede
//! cada assinatura por `key.sign`, no domínio `ic-request`, com o id do
//! pedido como resumo: uma decisão do gate por assinatura — a da chamada
//! e a de cada leitura da situação dela —, e a privada nunca chega aqui
//! ([`ChaveDoKernel`]). O Principal do IC é o da pública; o kernel não o
//! conhece. A chamada que fica pendente (a resposta 202, ou um
//! certificado com `received` ou `processing`) é acompanhada por leituras
//! assinadas de novo, com uma espera decidida pelo gate entre elas
//! ([`Gateway::esperar`]). A declaração da chamada vai ancorada na
//! decisão da assinatura dela ([`declarar_chamada`]): o kernel confere
//! que a decisão é deste processo, e grava o método dela.
//!
//! # A consulta assinada
//!
//! A consulta também vai assinada pela mesma chave ([`consultar_assinada`]),
//! e pelo mesmo caminho: a pública por `key.read`, a assinatura por
//! `key.sign` — uma decisão do gate, uma só, a da consulta: as faixas vão
//! do anônimo. O remetente é o Principal da chave, e as assinaturas dos
//! nós prendem a resposta ao id do pedido, que o leva. A chave que não se
//! lê não conecta (`failed_key`); a assinatura recusada não manda a
//! consulta, nem do anônimo no lugar (`failed_signature`) — ver
//! [`desfecho_da_consulta_assinada`]. A declaração é a da consulta,
//! [`EVENTO`], ancorada na decisão da assinatura dela
//! ([`declarar_consulta`]).
//!
//! A **consulta replicada** é o método de consulta pelo caminho da chamada
//! ([`chamar`]): a resposta passa pelo consenso e vem certificada, como a
//! de uma chamada — e é declarada como uma, [`EVENTO_DA_CHAMADA`].
//!
//! # O que não há aqui
//!
//! Nenhuma decisão do Duke. O canister, o método, o Principal, o
//! certificado e o resultado não viram permissão, recurso nem regra: o
//! TLS prova o nome do endpoint, a verificação prova o que os nós
//! responderam a este pedido, e o gate decide se esta identidade fala com
//! este destino e assina com esta chave — nenhuma das três é as outras.
//! Nenhum Principal do IC — o anônimo, ou o de uma chave — é identidade de
//! ninguém no Duke: quem pede ao gate é o processo, com a autoridade de
//! quem o lançou.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub use web3::icp::agente::{self, Desfecho, Etapa, Verificada};
pub use web3::icp::atualizacao::{self, Andamento, Atualizacao, Final};
pub use web3::icp::candid::{self, Valor};
pub use web3::icp::pedido::DOMINIO_DO_PEDIDO;
pub use web3::icp::principal::Principal;
pub use web3::icp::registro::{self, Rede};

use crate::conexao::{self, Prazo};
use crate::http::{self, Aceitas, ConexaoHttp, Limites, Metodo, Opcoes, Pedido, Protocolo, Url};
use crate::nativo::{self, conteudo};
use crate::tls::{self, Ancoras, Hora};

/// O tipo dos corpos do IC — **especificação**, *HTTPS interface*.
pub const TIPO: &str = "application/cbor";

/// O maior corpo de resposta que se lê: um certificado de sub-rede com a
/// delegação e as chaves dos nós, ou a resposta de uma consulta, cabem com
/// folga; um corpo maior não se lê.
pub const MAIOR_CORPO: usize = 512 * 1024;

/// O evento de uma consulta, como o programa a declara. O espaço `icp`
/// não é de nenhum comando do Duke — o kernel recusaria.
pub const EVENTO: &str = "icp.query";

/// O evento de uma chamada de atualização.
pub const EVENTO_DA_CHAMADA: &str = "icp.update";

/// Quantas leituras da situação de uma chamada pendente, no máximo.
pub const MAIS_LEITURAS: u32 = 20;

/// Quanto se espera entre duas leituras da situação, em ms.
pub const ESPERA_ENTRE_LEITURAS_MS: u64 = 500;

/// O maior assunto que o kernel aceita numa declaração.
const MAIOR_ASSUNTO: usize = 64;

/// Por que não houve consulta, ou por que ela não deu uma resposta
/// verificada — a falha de quem falhou, como veio.
#[derive(Debug)]
pub enum Falha {
    /// O arquivo das redes não se leu pelo gate: o código da recusa, ou
    /// `None` se a chamada falhou ou o arquivo passou do teto.
    Arquivo(Option<String>),
    /// O arquivo das redes não vale.
    Registro(registro::Erro),
    /// Nenhuma rede com o nome pedido.
    SemRede,
    /// O endpoint não vira URL — não acontece com um arquivo que valeu.
    Url,
    /// A hora de conferir, pelo gate — ver [`hora`].
    Hora(tls::Falha),
    /// O nonce, pelo gate — ver [`nonce`].
    Acaso(tls::Falha),
    /// A conexão com o endpoint: o DNS, o gate, o firewall, o TLS.
    Conexao(http::Falha),
    /// A consulta: o transporte, o HTTP, a verificação.
    Consulta(agente::Erro<Transporte>),
    /// A chave do kernel não se leu: o código de quem recusou — o gate,
    /// ou o kernel depois dele —, ou a chave fora do domínio do pedido.
    Chave(String),
    /// A chamada: o transporte, o HTTP, a assinatura, a verificação.
    Chamada(atualizacao::Erro<Transporte, Recusada>),
    /// A consulta assinada que a chave do kernel não assinou: ela não
    /// saiu.
    Assinatura(Recusada),
}

/// Por que a chave do kernel não assinou: o código de quem recusou — o
/// gate, ou o kernel depois dele —, ou `BAD_SIGNATURE` se o que voltou
/// não confere com a pública lida.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recusada(pub String);

impl fmt::Display for Recusada {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A falha do transporte de uma consulta: a da conexão HTTPS, como veio —
/// a recusa do gate, a contenção, o firewall, o TLS, o HTTP —, dita pela
/// família e pelo código dela.
#[derive(Debug)]
pub struct Transporte(pub http::Falha);

impl fmt::Display for Transporte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0.categoria().nome(), self.0.codigo())
    }
}

impl fmt::Display for Falha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Falha::Arquivo(Some(codigo)) => write!(f, "{}: {codigo}", registro::CAMINHO),
            Falha::Arquivo(None) => write!(f, "{}: nao se le", registro::CAMINHO),
            Falha::Registro(e) => write!(f, "{e}"),
            Falha::SemRede => f.write_str("nenhuma rede com esse nome"),
            Falha::Url => f.write_str("o endpoint nao vira url"),
            Falha::Hora(e) => write!(f, "hora: {}", e.codigo()),
            Falha::Acaso(e) => write!(f, "nonce: {}", e.codigo()),
            Falha::Conexao(e) => write!(f, "{} {}", e.categoria().nome(), e.codigo()),
            Falha::Consulta(e) => write!(f, "{e}"),
            Falha::Chave(codigo) => write!(f, "chave: {codigo}"),
            Falha::Chamada(e) => write!(f, "{e}"),
            Falha::Assinatura(r) => write!(f, "{}: assinatura: {r}", Etapa::Consulta),
        }
    }
}

/// O desfecho de uma consulta, numa palavra — ver o cabeçalho do módulo.
pub fn desfecho(r: &Result<Verificada, Falha>) -> &'static str {
    match r {
        Ok(v) => match v.desfecho {
            Desfecho::Respondida(_) => "verified",
            Desfecho::Recusada { .. } => "verified_reject",
        },
        Err(Falha::Consulta(e)) => match e {
            agente::Erro::Certificado(_) => "unverified_certificate",
            agente::Erro::LeituraDeEstado => "unverified_read_state",
            agente::Erro::Consulta(_) => "unverified_response",
            agente::Erro::Http(..) => "failed_http",
            agente::Erro::Transporte(..) => "failed_transport",
            agente::Erro::Pedido(_) => "failed_request",
        },
        Err(Falha::Conexao(_)) => "failed_connect",
        Err(Falha::Hora(_)) => "failed_clock",
        Err(Falha::Acaso(_)) => "failed_entropy",
        Err(_) => "failed_setup",
    }
}

/// O desfecho de uma consulta assinada, numa palavra: o da consulta
/// ([`desfecho`]), e `failed_key` — a chave não se leu — e
/// `failed_signature` — ela não assinou, e a consulta não saiu.
pub fn desfecho_da_consulta_assinada(r: &Result<Verificada, Falha>) -> &'static str {
    match r {
        Err(Falha::Chave(_)) => "failed_key",
        Err(Falha::Assinatura(_)) => "failed_signature",
        outro => desfecho(outro),
    }
}

/// O desfecho de uma chamada de atualização, numa palavra: `verified`,
/// `verified_reject` e `verified_done` — o certificado provou a resposta,
/// a recusa, ou que acabou e a resposta saiu do estado —;
/// `uncertified_reject`, a recusa que não passou pelo consenso, sem prova
/// nenhuma — dita à parte, e não como verificação que falhou —;
/// `pending`, sem desfecho depois das leituras; `unverified_<etapa>`
/// quando a prova não fechou; e `failed_<etapa>` quando não houve o que
/// verificar — `failed_signature` se a chave não assinou.
pub fn desfecho_da_chamada(r: Result<&Andamento, &Falha>) -> &'static str {
    use atualizacao::Erro;
    match r {
        Ok(Andamento::Certificado { desfecho, .. }) => match desfecho {
            Final::Respondida(_) => "verified",
            Final::Recusada { .. } => "verified_reject",
            Final::Concluida => "verified_done",
        },
        Ok(Andamento::RecusaNaoReplicada { .. }) => "uncertified_reject",
        Ok(Andamento::Pendente(_)) => "pending",
        Err(Falha::Chamada(e)) => match e {
            Erro::Certificado(..) => "unverified_certificate",
            Erro::Situacao(..) => "unverified_request_status",
            Erro::LeituraDeEstado(_) => "unverified_read_state",
            Erro::Corpo(_) => "unverified_response",
            Erro::Http(..) => "failed_http",
            Erro::Transporte(..) => "failed_transport",
            Erro::Pedido(_) => "failed_request",
            Erro::Assinatura(..) => "failed_signature",
        },
        Err(Falha::Chave(_)) => "failed_key",
        Err(Falha::Conexao(_)) => "failed_connect",
        Err(Falha::Hora(_)) => "failed_clock",
        Err(Falha::Acaso(_)) => "failed_entropy",
        Err(_) => "failed_setup",
    }
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

/// `N` bytes de exatamente `2N` dígitos hexadecimais minúsculos.
fn de_hex<const N: usize>(texto: &str) -> Option<[u8; N]> {
    let t = texto.as_bytes();
    if t.len() != 2 * N {
        return None;
    }
    let digito = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut saida = [0u8; N];
    for (i, b) in saida.iter_mut().enumerate() {
        *b = (digito(t[2 * i])? << 4) | digito(t[2 * i + 1])?;
    }
    Some(saida)
}

/// O código de quem recusou um pedido: o do gate, ou o do kernel depois
/// dele — `code` no resultado.
fn recusa_de(r: &nativo::Resposta) -> Option<String> {
    match r.resultado() {
        Err(recusa) => Some(String::from(recusa.motivo.unwrap_or("TECHNICAL_ERROR"))),
        Ok(resultado) => resultado
            .member("code")
            .and_then(|c| c.as_str())
            .map(String::from),
    }
}

/// A chave de assinatura `chave:<nome>` de quem lançou o processo — a
/// pessoa, o agente —, que o kernel guarda. O programa tem a pública, lida
/// por `key.read`, e pede cada assinatura por `key.sign`, pelo gate: uma
/// decisão por assinatura. A privada nunca chega aqui.
pub struct ChaveDoKernel {
    nome: String,
    publica: [u8; 32],
    der: [u8; 44],
    decisoes: Vec<u64>,
}

impl ChaveDoKernel {
    /// Lê a chave `chave` — `chave:<nome>`, no espaço de quem lançou o
    /// processo —, por `key.read`: viva, Ed25519, no domínio do pedido do
    /// IC. O nome de outro dono responde como o que ninguém tem.
    pub fn ler(chave: &str) -> Result<ChaveDoKernel, Falha> {
        let r = nativo::pedir("key.read", |w| w.field_str("key", chave))
            .map_err(|e| Falha::Chave(format!("ERRO {e}")))?;
        if let Some(codigo) = recusa_de(&r) {
            return Err(Falha::Chave(codigo));
        }
        let resultado = r
            .resultado()
            .map_err(|_| Falha::Chave(String::from("TECHNICAL_ERROR")))?;
        let campo = |nome: &str| resultado.member(nome).and_then(|v| v.as_str());
        if campo("state") != Some("active") {
            return Err(Falha::Chave(String::from(campo("state").unwrap_or("?"))));
        }
        if campo("algorithm") != Some("ed25519") || campo("domain") != Some(DOMINIO_DO_PEDIDO) {
            return Err(Falha::Chave(String::from("WRONG_DOMAIN")));
        }
        let publica = campo("public")
            .and_then(de_hex::<32>)
            .ok_or_else(|| Falha::Chave(String::from("TECHNICAL_ERROR")))?;
        Ok(ChaveDoKernel {
            nome: String::from(chave),
            publica,
            der: web3::icp::pedido::der_ed25519(&publica),
            decisoes: Vec::new(),
        })
    }

    /// O Principal do IC desta chave: o auto-autenticado da pública.
    pub fn principal(&self) -> Principal {
        Principal::auto_autenticado(&self.der)
    }

    /// As decisões do gate de cada assinatura feita, na ordem.
    pub fn decisoes(&self) -> &[u64] {
        &self.decisoes
    }
}

impl atualizacao::Assinador for ChaveDoKernel {
    type Erro = Recusada;

    fn chave_der(&self) -> &[u8] {
        &self.der
    }

    fn assinar(&mut self, id: &[u8; 32]) -> Result<Vec<u8>, Recusada> {
        let resumo = hex(id);
        let r = nativo::pedir("key.sign", |w| {
            w.field_str("key", &self.nome)?;
            w.field_str("domain", DOMINIO_DO_PEDIDO)?;
            w.field_str("digest", &resumo)
        })
        .map_err(|e| Recusada(format!("ERRO {e}")))?;
        if let Some(codigo) = recusa_de(&r) {
            return Err(Recusada(codigo));
        }
        let resultado = r
            .resultado()
            .map_err(|_| Recusada(String::from("TECHNICAL_ERROR")))?;
        let assinatura = resultado
            .member("signature")
            .and_then(|s| s.as_str())
            .and_then(de_hex::<64>)
            .ok_or_else(|| Recusada(String::from("TECHNICAL_ERROR")))?;
        // O que voltou tem de ser a assinatura deste id pela pública lida:
        // nada que não confira sai daqui.
        let mensagem = web3::icp::pedido::assinavel(id);
        if !web3::icp::assinatura::verificar(&self.publica, &mensagem, &assinatura) {
            return Err(Recusada(String::from("BAD_SIGNATURE")));
        }
        if let Some(d) = resultado.member("decision").and_then(|v| v.as_u64()) {
            self.decisoes.push(d);
        }
        Ok(assinatura.to_vec())
    }
}

/// O conteúdo do arquivo `caminho`, lido por `fs.read`, pelo gate, até
/// `teto` bytes.
fn ler_arquivo(caminho: &str, teto: usize) -> Result<Vec<u8>, Falha> {
    let mut bytes = Vec::new();
    loop {
        let r = nativo::pedir("fs.read", |w| {
            w.field_str("path", caminho)?;
            w.field_u64("offset", bytes.len() as u64)?;
            w.field_u64("max", 4096)
        })
        .map_err(|_| Falha::Arquivo(None))?;
        let resultado = r
            .resultado()
            .map_err(|recusa| Falha::Arquivo(recusa.motivo.map(String::from)))?;
        if let Some(codigo) = resultado.member("code").and_then(|c| c.as_str()) {
            return Err(Falha::Arquivo(Some(String::from(codigo))));
        }
        if resultado.member("error").is_some() {
            return Err(Falha::Arquivo(None));
        }
        let tamanho = resultado
            .member("size")
            .and_then(|v| v.as_u64())
            .ok_or(Falha::Arquivo(None))?;
        if tamanho > teto as u64 {
            return Err(Falha::Arquivo(None));
        }
        let pedaco = conteudo(&r).ok_or(Falha::Arquivo(None))?;
        if pedaco.is_empty() {
            break;
        }
        bytes.extend_from_slice(&pedaco);
        if bytes.len() as u64 >= tamanho {
            break;
        }
    }
    Ok(bytes)
}

/// As redes em que o programa confia: `/dados/icp/redes`, pelo gate.
/// Qualquer erro recusa o arquivo inteiro — ver [`registro::ler`].
pub fn redes() -> Result<Vec<Rede>, Falha> {
    let bytes = ler_arquivo(registro::CAMINHO, registro::MAIOR_ARQUIVO)?;
    let texto = core::str::from_utf8(&bytes).map_err(|_| {
        Falha::Registro(registro::Erro {
            linha: 0,
            motivo: "arquivo que nao e utf-8",
        })
    })?;
    registro::ler(texto).map_err(Falha::Registro)
}

/// A rede `nome`, das [`redes`].
pub fn rede(nome: &str) -> Result<Rede, Falha> {
    redes()?
        .into_iter()
        .find(|r| r.nome == nome)
        .ok_or(Falha::SemRede)
}

/// A hora de conferir certificados e assinaturas, pela regra de
/// `protocolo::usuario::hora`: o civil quando autenticado, o lógico quando
/// não — o mesmo relógio da validade dos certificados do TLS. O estado vai
/// junto, para quem consulta dizer com que hora conferiu.
pub fn hora() -> Result<Hora, Falha> {
    tls::hora().map_err(Falha::Hora)
}

/// Um nonce de 32 bytes do `random.read`, pelo gate: cada consulta é
/// outro pedido, com outro id.
pub fn nonce() -> Result<[u8; 32], Falha> {
    tls::semente().map_err(Falha::Acaso)
}

/// O endpoint de uma rede, pela conexão HTTPS que o gate decidiu: o
/// transporte do agente. Largado, a conexão fecha.
pub struct Gateway {
    conexao: ConexaoHttp,
    origem: String,
    limites: Limites,
}

impl Gateway {
    /// O número da conexão no kernel: a âncora de uma declaração.
    pub fn conexao(&self) -> u64 {
        self.conexao.numero()
    }

    /// O destino que o gate decidiu: `tcp:<ipv4>:<porta>`.
    pub fn destino(&self) -> &str {
        self.conexao.destino()
    }

    /// Fecha a conexão.
    pub fn fechar(self) {
        self.conexao.fechar();
    }

    /// Espera até `ms` milissegundos pela própria conexão — um `net.recv`
    /// que não lê nada (`max` zero), decidido pelo gate como qualquer
    /// outro: entre duas leituras da situação de uma chamada, nada chega,
    /// e a espera vence o prazo. Volta antes se a conexão mudou.
    ///
    /// A espera é parte da leitura da situação: a recusa dela — a do gate,
    /// a contenção, o firewall, a conexão que caiu — é a falha do
    /// transporte da leitura, com o código de quem recusou.
    pub fn esperar(&self, ms: u64) -> Result<(), Falha> {
        let r = conexao::do_pedido(nativo::pedir("net.recv", |w| {
            w.field_u64("connection", self.conexao.numero())?;
            w.field_u64("max", 0)?;
            w.field_u64("wait", ms)
        }));
        let falha = match r {
            Err(f) => f,
            Ok(r) => match conexao::depois_do_gate(&r) {
                Some(f) => f,
                None => return Ok(()),
            },
        };
        Err(Falha::Chamada(atualizacao::Erro::Transporte(
            atualizacao::Etapa::Situacao,
            Transporte(http::Falha::Conexao(falha)),
        )))
    }
}

impl agente::Transporte for Gateway {
    type Erro = Transporte;

    fn post(&mut self, caminho: &str, corpo: &[u8]) -> Result<(u16, Vec<u8>), Transporte> {
        let url = Url::ler(&format!("{}{caminho}", self.origem))
            .map_err(|e| Transporte(http::Falha::Url(e)))?;
        let mut pedido = Pedido::novo(Metodo::Post, url);
        pedido
            .cabecalho("Content-Type", TIPO)
            .map_err(|e| Transporte(http::Falha::Pedido(Some(e))))?;
        pedido.corpo = Vec::from(corpo);
        // O IC responde em CBOR: nada a descomprimir.
        pedido.aceitas = Aceitas::NENHUMA;
        let r = self
            .conexao
            .trocar(&pedido, &self.limites)
            .map_err(Transporte)?;
        Ok((r.status, r.corpo))
    }
}

/// Conecta ao endpoint de `rede`: o host pelo DNS `dns` — ou pelo endereço
/// fixo do arquivo —, o destino pelo gate, e o TLS pelas `ancoras`.
pub fn conectar(rede: &Rede, ancoras: &Ancoras, dns: &str) -> Result<Gateway, Falha> {
    let (origem, url, opcoes) = endpoint(rede, ancoras, dns)?;
    let conexao = http::conectar(&url, &opcoes).map_err(Falha::Conexao)?;
    Ok(Gateway::de(conexao, origem))
}

/// [`conectar`], com o tempo de cada parte da conexão — ver
/// [`http::conectar_medindo`].
pub fn conectar_medindo(
    rede: &Rede,
    ancoras: &Ancoras,
    dns: &str,
) -> (Result<Gateway, Falha>, http::Medida) {
    let (origem, url, opcoes) = match endpoint(rede, ancoras, dns) {
        Ok(e) => e,
        Err(f) => return (Err(f), http::Medida::default()),
    };
    let (r, medida) = http::conectar_medindo(&url, &opcoes);
    (
        r.map(|c| Gateway::de(c, origem)).map_err(Falha::Conexao),
        medida,
    )
}

/// A origem, a URL e as opções da conexão com o endpoint de `rede`.
fn endpoint<'a>(
    rede: &Rede,
    ancoras: &'a Ancoras,
    dns: &'a str,
) -> Result<(String, Url, Opcoes<'a>), Falha> {
    let origem = format!("https://{}:{}", rede.host, rede.porta);
    let url = Url::ler(&origem).map_err(|_| Falha::Url)?;
    let opcoes = Opcoes {
        resolucao: match rede.endereco {
            Some(ip) => http::Resolucao::Fixa(ip),
            None => http::Resolucao::Dns(dns),
        },
        ancoras: Some(ancoras),
        prazo: Prazo::PADRAO,
        protocolo: Protocolo::Http1,
    };
    Ok((origem, url, opcoes))
}

impl Gateway {
    fn de(conexao: ConexaoHttp, origem: String) -> Gateway {
        let limites = Limites {
            corpo: MAIOR_CORPO,
            descomprimido: MAIOR_CORPO,
            ..Limites::default()
        };
        Gateway {
            conexao,
            origem,
            limites,
        }
    }

    /// A suíte do TLS da conexão.
    pub fn suite(&self) -> Option<&'static str> {
        self.conexao.suite()
    }
}

/// O tempo de cada parte de uma consulta, em ms do `system.uptime` — a
/// régua de 10 ms. Ver [`consultar_medindo`].
#[derive(Clone, Debug, Default)]
pub struct Medida {
    /// A hora de conferir e o nonce da consulta, pelo gate.
    pub preparo_ms: u64,
    /// A conexão: o preparo do TLS, o DNS, o TCP e o aperto, e o destino.
    pub conexao: http::Medida,
    /// Os pedidos HTTP — o `read_state` e o `query` —, de ida e volta.
    pub http_ms: u64,
    /// A verificação, com os pedidos montados e as respostas lidas: o
    /// certificado até a raiz, a resposta contra os nós, o Candid. Tudo o
    /// que a consulta fez fora do HTTP.
    pub verificacao_ms: u64,
    /// Do começo da consulta ao fim da verificação, antes da declaração.
    pub total_ms: u64,
}

/// Uma consulta pelo caminho inteiro, como saiu — ver
/// [`consultar_medindo`].
pub struct ConsultaMedida {
    /// O que a consulta deu.
    pub r: Result<Verificada, Falha>,
    /// A hora com que conferiu, se o gate a deu.
    pub hora: Option<Hora>,
    /// A suíte do TLS, se o aperto fechou.
    pub suite: Option<&'static str>,
    /// A declaração à auditoria.
    pub declarada: Declarada,
    /// O tempo de cada parte.
    pub medida: Medida,
}

/// O [`Gateway`] de uma consulta medida, que soma o tempo dos pedidos.
struct Cronometrado<'g> {
    gateway: &'g mut Gateway,
    ms: u64,
}

impl agente::Transporte for Cronometrado<'_> {
    type Erro = Transporte;

    fn post(&mut self, caminho: &str, corpo: &[u8]) -> Result<(u16, Vec<u8>), Transporte> {
        let inicio = nativo::uptime_ms();
        let r = self.gateway.post(caminho, corpo);
        self.ms += nativo::uptime_ms().saturating_sub(inicio);
        r
    }
}

/// Consulta `metodo` de `canister` com `arg` pela rede `rede`, pelo
/// caminho inteiro — a hora e o nonce, o DNS `dns`, o destino pelo gate, o
/// TLS pelas `ancoras`, os dois `POST` e a verificação —, medindo cada
/// parte. Declara o desfecho antes do fecho, ancorado na conexão — ou sem
/// âncora, se não houve conexão. Nada é entregue antes da verificação.
pub fn consultar_medindo(
    rede: &Rede,
    ancoras: &Ancoras,
    dns: &str,
    canister: &Principal,
    metodo: &str,
    arg: &[u8],
) -> ConsultaMedida {
    let mut medida = Medida::default();
    let inicio = nativo::uptime_ms();
    let preparo = hora().and_then(|h| Ok((h, nonce()?)));
    medida.preparo_ms = nativo::uptime_ms().saturating_sub(inicio);
    let hora = preparo.as_ref().ok().map(|(h, _)| *h);
    let mut gateway = None;
    let mut suite = None;
    let r = preparo.and_then(|(hora, nonce)| {
        let (g, conexao) = conectar_medindo(rede, ancoras, dns);
        medida.conexao = conexao;
        let g = gateway.insert(g?);
        suite = g.suite();
        let mut cronometrado = Cronometrado { gateway: g, ms: 0 };
        let antes = nativo::uptime_ms();
        let r = consultar(
            &mut cronometrado,
            rede,
            canister,
            metodo,
            arg,
            &hora,
            &nonce,
        );
        medida.http_ms = cronometrado.ms;
        medida.verificacao_ms = nativo::uptime_ms()
            .saturating_sub(antes)
            .saturating_sub(cronometrado.ms);
        r
    });
    medida.total_ms = nativo::uptime_ms().saturating_sub(inicio);
    let declarada = declarar(
        &assunto(canister, metodo),
        desfecho(&r),
        gateway.as_ref().map(Gateway::conexao),
    );
    if let Some(g) = gateway {
        g.fechar();
    }
    ConsultaMedida {
        r,
        hora,
        suite,
        declarada,
        medida,
    }
}

/// Consulta `metodo` de `canister` com `arg` (Candid), como o anônimo,
/// pelo `transporte` — o [`Gateway`], ou um que o embrulhe —, e confere
/// tudo contra a raiz de `rede` com a hora `agora` — ver
/// [`agente::consultar`]. Nada é entregue antes da verificação.
pub fn consultar<T: agente::Transporte<Erro = Transporte>>(
    transporte: &mut T,
    rede: &Rede,
    canister: &Principal,
    metodo: &str,
    arg: &[u8],
    agora: &Hora,
    nonce: &[u8; 32],
) -> Result<Verificada, Falha> {
    let agora_ns = agora.validade_s().saturating_mul(1_000_000_000);
    agente::consultar(
        transporte, &rede.raiz, canister, metodo, arg, agora_ns, nonce,
    )
    .map_err(Falha::Consulta)
}

/// Consulta `metodo` de `canister` com `arg` (Candid) pelo `transporte`,
/// assinada pela `chave` do kernel — o remetente é o Principal dela —, e
/// confere tudo contra a raiz de `rede` com a hora `agora` — ver
/// [`agente::consultar_assinada`]. Uma assinatura, uma decisão do gate;
/// recusada, a consulta não sai. Nada é entregue antes da verificação.
#[allow(clippy::too_many_arguments)]
pub fn consultar_assinada<T: agente::Transporte<Erro = Transporte>>(
    transporte: &mut T,
    rede: &Rede,
    chave: &mut ChaveDoKernel,
    canister: &Principal,
    metodo: &str,
    arg: &[u8],
    agora: &Hora,
    nonce: &[u8; 32],
) -> Result<Verificada, Falha> {
    let agora_ns = agora.validade_s().saturating_mul(1_000_000_000);
    agente::consultar_assinada(
        transporte, chave, &rede.raiz, canister, metodo, arg, agora_ns, nonce,
    )
    .map_err(|e| match e {
        agente::ErroDaAssinada::Consulta(e) => Falha::Consulta(e),
        agente::ErroDaAssinada::Assinatura(r) => Falha::Assinatura(r),
    })
}

/// Chama `metodo` de `canister` com `arg` (Candid) pelo `transporte`,
/// assinado pela `chave` do kernel — ou do anônimo, sem ela —, e confere
/// tudo contra a raiz de `rede` com a hora `agora` — ver
/// [`atualizacao::chamar`]. A chamada que fica pendente segue por
/// [`acompanhar`].
#[allow(clippy::too_many_arguments)]
pub fn chamar<T: agente::Transporte<Erro = Transporte>>(
    transporte: &mut T,
    rede: &Rede,
    chave: Option<&mut ChaveDoKernel>,
    canister: &Principal,
    metodo: &str,
    arg: &[u8],
    agora: &Hora,
    nonce: &[u8; 32],
) -> Result<Atualizacao, Falha> {
    let agora_ns = agora.validade_s().saturating_mul(1_000_000_000);
    atualizacao::chamar(
        transporte, chave, &rede.raiz, canister, metodo, arg, agora_ns, nonce,
    )
    .map_err(Falha::Chamada)
}

/// Lê a situação de uma chamada pendente, uma vez: outro pedido, assinado
/// de novo pela mesma `chave` — ou do anônimo —, com a hora `agora` — ver
/// [`atualizacao::acompanhar`].
pub fn acompanhar<T: agente::Transporte<Erro = Transporte>>(
    transporte: &mut T,
    rede: &Rede,
    chave: Option<&mut ChaveDoKernel>,
    chamada: &mut Atualizacao,
    agora: &Hora,
) -> Result<Andamento, Falha> {
    let agora_ns = agora.validade_s().saturating_mul(1_000_000_000);
    atualizacao::acompanhar(transporte, chave, &rede.raiz, chamada, agora_ns)
        .map_err(Falha::Chamada)
}

/// O assunto de uma consulta, como o kernel o aceita numa declaração: o
/// canister e o método — ou só o canister, se o método não cabe na forma
/// (ASCII visível sem aspas, barra invertida nem `;`, até 64 com o resto).
pub fn assunto(canister: &Principal, metodo: &str) -> String {
    let mut a = canister.texto();
    let cabe = !metodo.is_empty()
        && a.len() + 1 + metodo.len() <= MAIOR_ASSUNTO
        && metodo
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\' | b';'));
    if cabe {
        a.push('/');
        a.push_str(metodo);
    }
    a
}

/// O que uma declaração deu: o número do registro, ou o código de quem a
/// recusou — o gate, ou o kernel depois dele.
pub type Declarada = Result<u64, String>;

/// A que fato do kernel uma declaração se ancora — uma âncora só.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ancora {
    /// Nenhum.
    Nenhuma,
    /// A conexão em que se falou com o IC.
    Conexao(u64),
    /// A decisão do gate que o processo exerceu — a da assinatura de uma
    /// chamada, ou de uma consulta assinada.
    Decisao(u64),
}

fn declarar_uma(evento: &str, assunto: &str, desfecho: &str, ancora: Ancora) -> Declarada {
    let r = nativo::pedir("audit.declare", |w| {
        w.field_str("event", evento)?;
        w.field_str("subject", assunto)?;
        w.field_str("outcome", desfecho)?;
        match ancora {
            Ancora::Conexao(n) => w.field_u64("connection", n),
            Ancora::Decisao(d) => w.field_u64("decision", d),
            Ancora::Nenhuma => Ok(()),
        }
    })
    .map_err(|e| format!("ERRO {e}"))?;
    let resultado = r
        .resultado()
        .map_err(|recusa| String::from(recusa.motivo.unwrap_or("TECHNICAL_ERROR")))?;
    if let Some(n) = resultado.member("record").and_then(|v| v.as_u64()) {
        return Ok(n);
    }
    Err(String::from(
        resultado
            .member("code")
            .and_then(|c| c.as_str())
            .unwrap_or("TECHNICAL_ERROR"),
    ))
}

/// Declara a consulta à auditoria, por `audit.declare`: o evento
/// [`EVENTO`], o `assunto` e o `desfecho`, ancorada na conexão `conexao` —
/// o kernel escreve o destino real dela. Se a conexão já não é deste
/// processo — o firewall a cortou, o par a fechou —, a declaração vai sem
/// âncora: a alegação fica, e o kernel diz que não havia conexão.
pub fn declarar(assunto: &str, desfecho: &str, conexao: Option<u64>) -> Declarada {
    let ancora = conexao.map_or(Ancora::Nenhuma, Ancora::Conexao);
    match declarar_uma(EVENTO, assunto, desfecho, ancora) {
        Err(codigo) if conexao.is_some() && codigo == "INVALID_ARGUMENT" => {
            declarar_uma(EVENTO, assunto, desfecho, Ancora::Nenhuma)
        }
        outro => outro,
    }
}

/// Declara a consulta à auditoria, como [`declarar`], com a `ancora` que
/// a prende — a decisão da assinatura dela, quando foi assinada
/// ([`consultar_assinada`]); a conexão, quando não chegou a ser assinada,
/// ou é do anônimo. Uma âncora que o kernel recusa cai para nenhuma: a
/// alegação fica, sem o fato.
pub fn declarar_consulta(assunto: &str, desfecho: &str, ancora: Ancora) -> Declarada {
    match declarar_uma(EVENTO, assunto, desfecho, ancora) {
        Err(codigo) if ancora != Ancora::Nenhuma && codigo == "INVALID_ARGUMENT" => {
            declarar_uma(EVENTO, assunto, desfecho, Ancora::Nenhuma)
        }
        outro => outro,
    }
}

/// Declara a chamada à auditoria, por `audit.declare`: o evento
/// [`EVENTO_DA_CHAMADA`], o `assunto` e o `desfecho`, ancorada no fato do
/// kernel que a prende — a decisão da assinatura da chamada, quando ela
/// foi assinada; a conexão, quando foi do anônimo. Uma âncora que o kernel
/// recusa — a conexão que já não é deste processo — cai para nenhuma: a
/// alegação fica, sem o fato.
pub fn declarar_chamada(assunto: &str, desfecho: &str, ancora: Ancora) -> Declarada {
    match declarar_uma(EVENTO_DA_CHAMADA, assunto, desfecho, ancora) {
        Err(codigo) if ancora != Ancora::Nenhuma && codigo == "INVALID_ARGUMENT" => {
            declarar_uma(EVENTO_DA_CHAMADA, assunto, desfecho, Ancora::Nenhuma)
        }
        outro => outro,
    }
}

/// Chama `metodo` do canister de gerenciamento (`aaaaa-aa`) com `arg`
/// (Candid) pelo `transporte`, assinado pela `chave` do kernel — ou do
/// anônimo, sem ela —, pelo canister `efetivo` — o que o método gerencia —,
/// e confere tudo contra a raiz de `rede` com a hora `agora` — ver
/// [`atualizacao::chamar_ao_gerenciamento`]. A chamada que fica pendente
/// segue por [`acompanhar`], que lê a situação pelo efetivo.
#[allow(clippy::too_many_arguments)]
pub fn chamar_ao_gerenciamento<T: agente::Transporte<Erro = Transporte>>(
    transporte: &mut T,
    rede: &Rede,
    chave: Option<&mut ChaveDoKernel>,
    efetivo: &Principal,
    metodo: &str,
    arg: &[u8],
    agora: &Hora,
    nonce: &[u8; 32],
) -> Result<Atualizacao, Falha> {
    let agora_ns = agora.validade_s().saturating_mul(1_000_000_000);
    atualizacao::chamar_ao_gerenciamento(
        transporte, chave, &rede.raiz, efetivo, metodo, arg, agora_ns, nonce,
    )
    .map_err(Falha::Chamada)
}

/// O conteúdo do arquivo `caminho`, lido por `fs.read`, pelo gate — em
/// pedaços de 4 KiB, uma decisão cada —, até `teto` bytes: o arquivo maior
/// não se lê. A recusa é a [`Falha::Arquivo`], com o código de quem
/// recusou.
pub fn ler(caminho: &str, teto: usize) -> Result<Vec<u8>, Falha> {
    ler_arquivo(caminho, teto)
}
