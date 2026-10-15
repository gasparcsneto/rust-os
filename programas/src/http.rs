//! O HTTP de um programa: o pacote `http` sobre a conexão do gate — direto
//! no TCP, ou com o TLS do pacote `tls` no meio —, com o nome resolvido pelo
//! DNS do próprio programa.
//!
//! # A ordem de uma conexão
//!
//! 1. a URL: só `http` e `https`, o host por nome ou IPv4 — ver
//!    `http::Url`;
//! 2. com `https`, a semente e o relógio, pelo gate, antes de qualquer
//!    conexão — sem eles, nada sai (ver [`crate::tls`]);
//! 3. o nome vira endereço, pelo DNS do programa ([`crate::dns`]): a
//!    associação UDP com o servidor, que o gate decide. Ou o endereço que
//!    quem chama já tem ([`Resolucao::Fixa`]). O endereço não vale nada
//!    para a política;
//! 4. `net.connect` com o destino inteiro, `tcp:<ipv4>:<porta>`: o gate o
//!    decide como se o número tivesse sido digitado — e o firewall, depois
//!    dele;
//! 5. com `https`, o TLS prova o nome da URL pelas âncoras de quem chama. O
//!    certificado autentica o servidor para o programa, e não dá nada a
//!    ninguém;
//! 6. cada pedido e cada resposta, com cada `net.send` e cada `net.recv`
//!    decidido de novo pelo gate, com a autoridade de agora;
//! 7. o corpo comprimido — `gzip` ou `deflate`, o que o pedido aceitou —
//!    decodificado aqui, no processo, com o teto de quem pediu
//!    (`http::codificacao`). O gate viu os bytes que passaram, e não sabe
//!    que eram comprimidos;
//! 8. com um pote ([`Pote`], e as trocas `_com_pote`), os cookies: o pedido
//!    leva os que o pote dá para ele, e os da resposta vão para o pote —
//!    que é do processo, na memória dele, e acaba com ele
//!    (`http::cookies`). O relógio da validade é o `system.info` do TLS,
//!    pelo gate, lido só quando um cookie com validade está em jogo.
//!
//! # O que não há aqui
//!
//! Nenhuma decisão. O método, a URL, o `Host`, os cabeçalhos, o status, o
//! corpo, a compressão, os cookies, o redirecionamento e o *keep-alive* não
//! viram permissão, recurso nem regra: um cookie prova alguma coisa ao
//! servidor, e nada ao Duke. O que este programa pode é o que o gate
//! decide para os pedidos de rede dele, e uma conexão aberta não leva
//! autorização para o pedido seguinte — a revogação, a contenção, a
//! política nova e o firewall valem no próximo `net.send` ou `net.recv`,
//! no meio de uma resposta. Um `3xx` volta a quem chama com o `Location`: seguir é outro
//! pedido, outro nome no DNS, outro destino no gate.
//!
//! # As falhas
//!
//! [`Falha`] guarda a de quem falhou — a URL, o DNS, a conexão, o TLS, o
//! HTTP —, com o código dele ([`Falha::codigo`]) e a família
//! ([`Falha::categoria`], de `http::categoria`): a recusa do gate, a
//! contenção, o firewall, o DNS, o transporte, o prazo, o TLS, a conversa
//! que acabou cedo, o protocolo e os limites nunca se confundem.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;

pub use http::{
    Aceitas, Agora, Categoria, Codificacao, Contexto, Defeito, Enquadramento, Erro, ErroDePedido,
    ErroDeUrl, Esquema, Guardado, Guardados, Host, Limite, Limites, LimitesDoPote, MesmoSite,
    Metodo, Pedido, Pote, RecusaDeCookie, Resposta, Url, Versao,
};

use crate::conexao::{self, Conexao, Prazo};
use crate::dns;
use crate::tls::{self, Ancoras, Sessao};

/// Como o nome da URL vira endereço.
#[derive(Clone, Copy, Debug)]
pub enum Resolucao<'a> {
    /// Pelo servidor de DNS `servidor` (`udp:<ipv4>:53`), numa associação
    /// que o gate decide.
    Dns(&'a str),
    /// O endereço que quem chama já tem, sem DNS — o host da URL ainda é o
    /// nome que o TLS prova e que vai no `Host`.
    Fixa([u8; 4]),
}

/// O que uma conexão precisa de quem a pede.
#[derive(Clone, Copy)]
pub struct Opcoes<'a> {
    pub resolucao: Resolucao<'a>,
    /// As raízes em que o programa confia, para `https`. Sem elas, uma URL
    /// `https` não conecta: não há âncora embutida.
    pub ancoras: Option<&'a Ancoras>,
    /// Quanto o transporte espera o outro lado.
    pub prazo: Prazo,
}

/// Por que uma conexão ou uma troca não deu uma resposta — a falha de quem
/// falhou, como veio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falha {
    /// A URL não se lê.
    Url(ErroDeUrl),
    /// O pedido não se escreve: um cabeçalho, ou a URL de outra origem que
    /// não a da conexão.
    Pedido(Option<ErroDePedido>),
    /// Uma URL `https` sem âncoras.
    SemAncoras,
    /// O nome não virou endereço — ou a recusa veio no meio do DNS.
    Dns(dns::Falha),
    /// A conexão TCP: a recusa do gate, o firewall, a rede, o outro lado, o
    /// prazo.
    Conexao(conexao::Falha),
    /// O TLS — ou a falha de baixo dele, que passa com o código de quem
    /// falhou.
    Tls(tls::Falha),
    /// O HTTP: a conversa que acabou cedo, o protocolo, os limites, a
    /// conexão que não leva mais pedidos, o corpo comprimido que não se
    /// decodifica.
    Http(http::Erro<Infallible>),
}

impl Falha {
    /// O código da falha: o de quem falhou.
    pub fn codigo(&self) -> &str {
        match self {
            Falha::Url(_) | Falha::Pedido(_) => "INVALID_REQUEST",
            Falha::SemAncoras => "TLS_ANCHORS_INVALID",
            Falha::Dns(f) => f.codigo(),
            Falha::Conexao(f) => f.codigo(),
            Falha::Tls(f) => f.codigo(),
            Falha::Http(e) => e.codigo().unwrap_or("TECHNICAL_ERROR"),
        }
    }

    /// A família da falha — ver `http::categoria`.
    pub fn categoria(&self) -> Categoria {
        http::categoria(self.codigo())
    }
}

/// O erro do HTTP, com a falha de baixo dita por `baixo`.
fn do_http<F>(e: http::Erro<F>, baixo: impl FnOnce(F) -> Falha) -> Falha {
    match e {
        http::Erro::Baixo(f) => baixo(f),
        http::Erro::Fechada => Falha::Http(http::Erro::Fechada),
        http::Erro::Protocolo(m) => Falha::Http(http::Erro::Protocolo(m)),
        http::Erro::Limite(l) => Falha::Http(http::Erro::Limite(l)),
        http::Erro::Esgotada => Falha::Http(http::Erro::Esgotada),
        http::Erro::Conteudo(d) => Falha::Http(http::Erro::Conteudo(d)),
        http::Erro::Reiniciada(c) => Falha::Http(http::Erro::Reiniciada(c)),
        http::Erro::Recusada => Falha::Http(http::Erro::Recusada),
        http::Erro::Encerrada(c) => Falha::Http(http::Erro::Encerrada(c)),
    }
}

/// A sessão TLS como fluxo do HTTP.
struct Cifrada(Sessao<Conexao>);

impl http::Fluxo for Cifrada {
    type Falha = tls::Falha;

    fn mandar(&mut self, dados: &[u8]) -> Result<(), tls::Falha> {
        self.0.mandar(dados)
    }

    fn receber(&mut self, destino: &mut [u8]) -> Result<usize, tls::Falha> {
        self.0.receber(destino)
    }
}

/// Por onde os bytes vão. A sessão TLS é grande — o estado do `rustls` —,
/// e mora no monte.
enum Via {
    Clara(http::Cliente<Conexao>),
    Cifrada(Box<http::Cliente<Cifrada>>),
}

/// Uma conexão HTTP com uma origem: o esquema, o host e a porta de uma
/// URL. Largada, a conexão TCP fecha.
pub struct ConexaoHttp {
    via: Via,
    esquema: Esquema,
    host: Host,
    porta: u16,
    destino: String,
    numero: u64,
    suite: Option<&'static str>,
}

/// O endereço do nome da URL, pela `resolucao`.
fn endereco(url: &Url, resolucao: Resolucao<'_>, id: u16) -> Result<[u8; 4], Falha> {
    match (&url.host, resolucao) {
        // Um endereço na URL já é o endereço: o DNS não tem o que dizer.
        (Host::Ipv4(ip), _) => Ok(*ip),
        (Host::Nome(_), Resolucao::Fixa(ip)) => Ok(ip),
        (Host::Nome(nome), Resolucao::Dns(servidor)) => {
            let ips = dns::resolver(servidor, nome, id).map_err(Falha::Dns)?;
            // Um nome sem endereço IPv4 não leva a lugar nenhum.
            ips.first().copied().ok_or(Falha::Dns(dns::Falha::Codigo(
                protocolo::dns::NOME_INEXISTENTE,
            )))
        }
    }
}

/// Um número para a pergunta do DNS, do id do processo e de uma conta:
/// cada pergunta de um processo tem o seu.
fn id_da_pergunta() -> u16 {
    use core::sync::atomic::{AtomicU16, Ordering};
    static CONTA: AtomicU16 = AtomicU16::new(0);
    let processo = crate::sistema::id() as u16;
    processo
        .wrapping_mul(0x9e37)
        .wrapping_add(CONTA.fetch_add(1, Ordering::Relaxed))
}

/// Conecta à origem de `url` — ver o cabeçalho do módulo para a ordem.
pub fn conectar(url: &Url, opcoes: &Opcoes<'_>) -> Result<ConexaoHttp, Falha> {
    // Com `https`, antes de qualquer pergunta e de qualquer conexão: as
    // âncoras, a semente e o relógio. Sem eles, nada sai.
    let cifra = match url.esquema {
        Esquema::Http => None,
        Esquema::Https => {
            let ancoras = opcoes.ancoras.ok_or(Falha::SemAncoras)?;
            let semente = tls::semente().map_err(Falha::Tls)?;
            let agora = tls::relogio().map_err(Falha::Tls)?;
            Some((ancoras, semente, agora))
        }
    };
    let [a, b, c, d] = endereco(url, opcoes.resolucao, id_da_pergunta())?;
    let destino = format!("tcp:{a}.{b}.{c}.{d}:{}", url.porta);
    let conexao = conexao::abrir(&destino, opcoes.prazo).map_err(Falha::Conexao)?;
    let numero = conexao.numero();
    let (via, suite) = match cifra {
        None => (Via::Clara(http::Cliente::novo(conexao)), None),
        Some((ancoras, semente, agora)) => {
            let sessao = Sessao::conectar(conexao, &url.nome(), ancoras, agora, semente)
                .map_err(Falha::Tls)?;
            let suite = sessao.suite();
            (
                Via::Cifrada(Box::new(http::Cliente::novo(Cifrada(sessao)))),
                suite,
            )
        }
    };
    Ok(ConexaoHttp {
        via,
        esquema: url.esquema,
        host: url.host.clone(),
        porta: url.porta,
        destino,
        numero,
        suite,
    })
}

impl ConexaoHttp {
    /// O destino que o gate decidiu: `tcp:<ipv4>:<porta>`.
    pub fn destino(&self) -> &str {
        &self.destino
    }

    /// O número da conexão TCP, no kernel.
    pub fn numero(&self) -> u64 {
        self.numero
    }

    /// A conexão leva o pedido seguinte.
    pub fn pronta(&self) -> bool {
        match &self.via {
            Via::Clara(c) => c.pronto(),
            Via::Cifrada(c) => c.pronto(),
        }
    }

    /// Quantas trocas terminaram com uma resposta nesta conexão.
    pub fn trocas(&self) -> u64 {
        match &self.via {
            Via::Clara(c) => c.trocas(),
            Via::Cifrada(c) => c.trocas(),
        }
    }

    /// A suíte do TLS, numa conexão `https`.
    pub fn suite(&self) -> Option<&'static str> {
        self.suite
    }

    /// Manda `pedido` e lê a resposta, com `limites`. O pedido é para a
    /// origem desta conexão: outra origem é outra conexão — outro nome,
    /// outro destino no gate. Sem pote: nenhum cookie vai, e os
    /// `Set-Cookie` voltam como vieram.
    pub fn trocar(&mut self, pedido: &Pedido, limites: &Limites) -> Result<Resposta, Falha> {
        self.da_origem(pedido)?;
        match &mut self.via {
            Via::Clara(c) => c
                .trocar(pedido, limites)
                .map_err(|e| do_http(e, Falha::Conexao)),
            Via::Cifrada(c) => c
                .trocar(pedido, limites)
                .map_err(|e| do_http(e, Falha::Tls)),
        }
    }

    /// [`ConexaoHttp::trocar`] com os cookies de `pote`: o pedido leva os
    /// que vão para ele, e os da resposta vão para o pote — e saem dos
    /// cabeçalhos dela. Os com validade que ficaram sem o relógio, a
    /// resposta conta (`cookies.retidos`).
    pub fn trocar_com_pote(
        &mut self,
        pedido: &Pedido,
        limites: &Limites,
        pote: &mut Pote,
    ) -> Result<Resposta, Falha> {
        self.da_origem(pedido)?;
        let mut relogio = relogio_dos_cookies;
        match &mut self.via {
            Via::Clara(c) => c
                .trocar_com_pote(pedido, limites, pote, &mut relogio)
                .map_err(|e| do_http(e, Falha::Conexao)),
            Via::Cifrada(c) => c
                .trocar_com_pote(pedido, limites, pote, &mut relogio)
                .map_err(|e| do_http(e, Falha::Tls)),
        }
    }

    /// O pedido é para a origem desta conexão.
    fn da_origem(&self, pedido: &Pedido) -> Result<(), Falha> {
        let u = &pedido.url;
        if u.esquema != self.esquema || u.host != self.host || u.porta != self.porta {
            return Err(Falha::Pedido(None));
        }
        Ok(())
    }

    /// Fecha a conexão: no `https`, avisa o outro lado (`close_notify`)
    /// antes de a conexão TCP fechar.
    pub fn fechar(self) {
        if let Via::Cifrada(c) = self.via {
            let _ = c.devolver().0.fechar();
        }
    }
}

/// Um pedido só, numa conexão só: conecta, manda `pedido` com
/// `Connection: close`, lê a resposta e fecha.
pub fn buscar(pedido: Pedido, opcoes: &Opcoes<'_>, limites: &Limites) -> Result<Resposta, Falha> {
    let mut conexao = conectar(&pedido.url, opcoes)?;
    let mut pedido = pedido;
    pedido.fechar = true;
    let r = conexao.trocar(&pedido, limites);
    conexao.fechar();
    r
}

/// Um `GET` de `url`, numa conexão só.
pub fn obter(url: &str, opcoes: &Opcoes<'_>, limites: &Limites) -> Result<Resposta, Falha> {
    let url = Url::ler(url).map_err(Falha::Url)?;
    buscar(Pedido::novo(Metodo::Get, url), opcoes, limites)
}

/// [`buscar`] com os cookies de `pote`.
pub fn buscar_com_pote(
    pedido: Pedido,
    opcoes: &Opcoes<'_>,
    limites: &Limites,
    pote: &mut Pote,
) -> Result<Resposta, Falha> {
    let mut conexao = conectar(&pedido.url, opcoes)?;
    let mut pedido = pedido;
    pedido.fechar = true;
    let r = conexao.trocar_com_pote(&pedido, limites, pote);
    conexao.fechar();
    r
}

/// [`obter`] com os cookies de `pote`.
pub fn obter_com_pote(
    url: &str,
    opcoes: &Opcoes<'_>,
    limites: &Limites,
    pote: &mut Pote,
) -> Result<Resposta, Falha> {
    let url = Url::ler(url).map_err(Falha::Url)?;
    buscar_com_pote(Pedido::novo(Metodo::Get, url), opcoes, limites, pote)
}

/// O relógio da validade dos cookies: o tempo lógico do `system.info`,
/// pelo gate, o mesmo do TLS. `None` sem relógio — sem RTC, sem a permissão
/// de lê-lo, ou com a leitura recusada —: aí a validade não se confere, e
/// os cookies que a têm não vão (ver `http::cookies`).
pub fn relogio_dos_cookies() -> Option<u64> {
    tls::relogio().ok()
}

/// O corpo de `r` como texto, para dizer — o que não é texto vira `?`.
pub fn texto(r: &Resposta) -> String {
    r.corpo
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '?'
            }
        })
        .collect()
}

/// Os bytes de `n` posições do padrão da bancada: `0123456789` repetido.
pub fn padrao(n: usize) -> Vec<u8> {
    (0..n).map(|i| b'0' + (i % 10) as u8).collect()
}

/// As palavras do texto da bancada — as mesmas do servidor HTTP dela.
const PALAVRAS: [&[u8]; 28] = [
    b"duke",
    b"gate",
    b"politica",
    b"auditoria",
    b"conexao",
    b"pedido",
    b"resposta",
    b"corpo",
    b"limite",
    b"agente",
    b"pessoa",
    b"processo",
    b"destino",
    b"firewall",
    b"revogacao",
    b"contencao",
    b"o",
    b"a",
    b"de",
    b"que",
    b"e",
    b"um",
    b"uma",
    b"nao",
    b"com",
    b"por",
    b"para",
    b"sem",
];

/// Os `n` bytes do texto da bancada: palavras escolhidas por um gerador
/// congruente, que o servidor dela gera igual. Comprime como texto — umas
/// cinco vezes —, e não como o padrão, que se repete a cada dez bytes.
pub fn texto_da_bancada(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    let mut saida = Vec::with_capacity(n + 16);
    let mut k = 0;
    while saida.len() < n {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        saida.extend_from_slice(PALAVRAS[((x >> 33) % PALAVRAS.len() as u64) as usize]);
        k += 1;
        saida.push(if k % 12 == 0 { b'\n' } else { b' ' });
    }
    saida.truncate(n);
    saida
}
