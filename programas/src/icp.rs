//! O Internet Computer de um programa: a consulta anônima verificada do
//! pacote `web3` ([`web3::icp`]) sobre o HTTPS do Duke ([`crate::http`]).
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
//! # O que não há aqui
//!
//! Nenhuma decisão do Duke. O canister, o método, o Principal, o
//! certificado e o resultado não viram permissão, recurso nem regra: o
//! TLS prova o nome do endpoint, a verificação prova o que os nós
//! responderam a este pedido, e o gate decide se esta identidade fala com
//! este destino — nenhuma das três é as outras. A consulta é anônima: o
//! Principal anônimo não é identidade de ninguém no Duke, e quem pede ao
//! gate é o processo, com a autoridade de quem o lançou.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub use web3::icp::agente::{self, Desfecho, Etapa, Verificada};
pub use web3::icp::candid::{self, Valor};
pub use web3::icp::principal::Principal;
pub use web3::icp::registro::{self, Rede};

use crate::conexao::Prazo;
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
    let conexao = http::conectar(&url, &opcoes).map_err(Falha::Conexao)?;
    let limites = Limites {
        corpo: MAIOR_CORPO,
        descomprimido: MAIOR_CORPO,
        ..Limites::default()
    };
    Ok(Gateway {
        conexao,
        origem,
        limites,
    })
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

fn declarar_uma(assunto: &str, desfecho: &str, conexao: Option<u64>) -> Declarada {
    let r = nativo::pedir("audit.declare", |w| {
        w.field_str("event", EVENTO)?;
        w.field_str("subject", assunto)?;
        w.field_str("outcome", desfecho)?;
        match conexao {
            Some(n) => w.field_u64("connection", n),
            None => Ok(()),
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
    match declarar_uma(assunto, desfecho, conexao) {
        Err(codigo) if conexao.is_some() && codigo == "INVALID_ARGUMENT" => {
            declarar_uma(assunto, desfecho, None)
        }
        outro => outro,
    }
}
