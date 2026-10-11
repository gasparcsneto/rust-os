//! A conexão TCP de um programa: o `net.connect` com o destino inteiro, e
//! cada `net.send` e cada `net.recv` sobre ela — todos pelo gate, cada um
//! decidido de novo, com a autoridade de quem lançou o programa.
//!
//! É o transporte de baixo do TLS ([`crate::tls`]) e do HTTP
//! ([`crate::http`]). Os dois esperam pelo evento da pilha (`wait`) em vez
//! de girar: quem não tem o que ler, ou onde pôr o que manda, dorme no
//! kernel até a pilha ter o que dizer, ou até o prazo.
//!
//! # As falhas não se misturam
//!
//! [`Falha`] separa o que o gate recusou — com o código dele —, o que o
//! gate deixou e a execução não — o firewall, a rede, o teto, com o código
//! de depois do gate —, o outro lado que recusou a conexão, a conexão que o
//! outro lado derrubou, e o par que não respondeu no prazo. Nenhuma vira
//! outra: um `DENY_*` não é "a conexão caiu", e o firewall não é a
//! política.
//!
//! O fecho do outro lado não é falha: [`Conexao::receber`] devolve `Ok(0)`
//! quando ele fechou o sentido dele em ordem (o `FIN`) e nada mais há para
//! ler — o que o TLS e o HTTP leem como fim. A conexão derrubada (o `RST`)
//! é [`Falha::Caiu`]: o que chegou até ali pode estar cortado.

use crate::nativo::{self, Resposta, conteudo};

pub use tls::Codigo;

/// O maior pedaço de um `net.send`: o buffer de uma conexão.
const MAIOR_ENVIO: usize = 4096;

/// Quanto o transporte espera o outro lado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prazo {
    /// Quanto cada `net.recv` e cada `net.send` espera pelo evento da
    /// pilha, em milissegundos — no máximo o teto do kernel, dez segundos.
    pub espera_ms: u64,
    /// Quantas esperas vencidas seguidas, sem nada chegar nem sair, o
    /// transporte aceita antes de dizer que o par não responde. É um prazo
    /// de silêncio, e não da conversa inteira: um par que manda um pouco de
    /// cada vez o renova — e os limites de tamanho de quem lê, e a taxa do
    /// papel no gate, é que acabam com ele.
    pub esperas: usize,
}

impl Prazo {
    /// Cinco segundos, três vezes: quinze segundos de silêncio.
    pub const PADRAO: Prazo = Prazo {
        espera_ms: 5_000,
        esperas: 3,
    };
}

/// Por que a conexão não abriu, não levou ou não trouxe os bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falha {
    /// O gate recusou o pedido — o `net.connect`, um `net.send`, um
    /// `net.recv` —, com o código dele: a autoridade de quem pediu, a
    /// contenção, a política de agora.
    Recusada(Codigo),
    /// O gate deixou, e a execução não: o firewall barrou
    /// (`FIREWALL_BLOCKED`), a rede não está (`NETWORK_UNAVAILABLE`), a
    /// tabela ou o teto do titular estão cheios (`RESOURCE_LIMIT`) — o
    /// `code` do resultado.
    Rede(Codigo),
    /// O outro lado recusou a conexão.
    Recusou,
    /// O outro lado derrubou a conexão.
    Caiu,
    /// O par não respondeu — nem aceitou o que se mandou — no [`Prazo`].
    Prazo,
    /// A chamada não voltou, ou a resposta do kernel não se entende.
    Interna,
}

impl Falha {
    /// O código da falha: o de quem recusou, ou o do transporte.
    pub fn codigo(&self) -> &str {
        match self {
            Falha::Recusada(c) | Falha::Rede(c) => c.como_str(),
            Falha::Recusou => "CONNECTION_REFUSED",
            Falha::Caiu => "CONNECTION_RESET",
            Falha::Prazo => "NETWORK_TIMEOUT",
            Falha::Interna => "TECHNICAL_ERROR",
        }
    }

    /// A mesma falha, para o TLS: passa como veio, com o código — o TLS
    /// não a traduz num código dele.
    pub fn para_o_tls(self) -> tls::Falha {
        match self {
            Falha::Interna => tls::Falha::Interna,
            outra => tls::Falha::Transporte(Codigo::de(outra.codigo())),
        }
    }
}

/// A recusa do gate, com o código dele, ou a chamada que não voltou.
pub(crate) fn do_pedido(r: Result<Resposta, i64>) -> Result<Resposta, Falha> {
    let r = r.map_err(|_| Falha::Interna)?;
    if let Err(recusa) = r.resultado() {
        return Err(Falha::Recusada(Codigo::de(
            recusa.motivo.unwrap_or("TECHNICAL_ERROR"),
        )));
    }
    Ok(r)
}

/// O `code` de uma falha depois do gate — o firewall, a rede, o teto —, ou
/// o `error` sem código, que é técnico.
pub(crate) fn depois_do_gate(r: &Resposta) -> Option<Falha> {
    let resultado = r.resultado().ok()?;
    if let Some(codigo) = resultado.member("code").and_then(|c| c.as_str()) {
        return Some(Falha::Rede(Codigo::de(codigo)));
    }
    resultado.member("error").map(|_| Falha::Interna)
}

/// O estado que a resposta diz.
fn estado(r: &Resposta) -> Option<&str> {
    r.resultado().ok()?.member("state")?.as_str()
}

/// Uma conexão do `net.connect`. Largada, é fechada.
pub struct Conexao {
    numero: u64,
    prazo: Prazo,
}

/// Conecta ao `destino` — `tcp:<ipv4>:<porta>`, decidido pelo gate, e
/// depois dele pelo firewall — e espera o aperto do TCP terminar.
pub fn abrir(destino: &str, prazo: Prazo) -> Result<Conexao, Falha> {
    let r = do_pedido(nativo::pedir("net.connect", |w| w.field_str("to", destino)))?;
    if let Some(f) = depois_do_gate(&r) {
        return Err(f);
    }
    let numero = r
        .resultado()
        .ok()
        .and_then(|j| j.member("connection")?.as_u64())
        .ok_or(Falha::Interna)?;
    // Daqui em diante, largada, ela fecha — também se o aperto falha.
    let mut conexao = Conexao { numero, prazo };
    conexao.esperar_aberta()?;
    Ok(conexao)
}

impl Conexao {
    /// O número que o `net.connect` devolveu.
    pub fn numero(&self) -> u64 {
        self.numero
    }

    /// Espera o aperto do TCP terminar: uma leitura de nada, que espera o
    /// estado sair de `connecting`.
    fn esperar_aberta(&mut self) -> Result<(), Falha> {
        for _ in 0..self.prazo.esperas {
            let r = do_pedido(nativo::pedir("net.recv", |w| {
                w.field_u64("connection", self.numero)?;
                w.field_u64("max", 0)?;
                w.field_u64("wait", self.prazo.espera_ms)
            }))?;
            if let Some(f) = depois_do_gate(&r) {
                return Err(f);
            }
            match estado(&r) {
                // Aberta — e talvez já fechando do lado de lá, o que a
                // leitura seguinte vê.
                Some("established") | Some("closing") => return Ok(()),
                Some("connecting") => {}
                // Recusada pelo outro lado: o `RST` ao `SYN`.
                Some("closed") => return Err(Falha::Recusou),
                _ => return Err(Falha::Interna),
            }
        }
        Err(Falha::Prazo)
    }

    /// Manda `dados` inteiros, em pedaços do tamanho do buffer da conexão,
    /// esperando espaço quando a fila de saída está cheia.
    pub fn mandar(&mut self, dados: &[u8]) -> Result<(), Falha> {
        let mut mandados = 0;
        let mut vencidas = 0;
        while mandados < dados.len() {
            let fim = (mandados + MAIOR_ENVIO).min(dados.len());
            let r = do_pedido(nativo::pedir_com_anexo(
                "net.send",
                |w| {
                    w.field_u64("connection", self.numero)?;
                    w.field_u64("wait", self.prazo.espera_ms)
                },
                &dados[mandados..fim],
            ))?;
            if let Some(f) = depois_do_gate(&r) {
                return Err(f);
            }
            let n = r
                .resultado()
                .ok()
                .and_then(|j| j.member("sent")?.as_u64())
                .ok_or(Falha::Interna)? as usize;
            if n == 0 {
                match estado(&r) {
                    // A espera venceu sem espaço.
                    Some("established") | Some("connecting") | Some("closing") => {
                        vencidas += 1;
                        if vencidas >= self.prazo.esperas {
                            return Err(Falha::Prazo);
                        }
                    }
                    // O outro lado a derrubou: nada mais sai.
                    Some("closed") => return Err(Falha::Caiu),
                    _ => return Err(Falha::Interna),
                }
            } else {
                vencidas = 0;
            }
            mandados += n.min(fim - mandados);
        }
        Ok(())
    }

    /// Recebe o que chegar, até `destino.len()` bytes, esperando por algo.
    /// `Ok(0)` quando o outro lado fechou em ordem e nada mais há para ler.
    pub fn receber(&mut self, destino: &mut [u8]) -> Result<usize, Falha> {
        for _ in 0..self.prazo.esperas {
            let maximo = destino.len().min(MAIOR_ENVIO) as u64;
            let r = do_pedido(nativo::pedir("net.recv", |w| {
                w.field_u64("connection", self.numero)?;
                w.field_u64("max", maximo)?;
                w.field_u64("wait", self.prazo.espera_ms)
            }))?;
            if let Some(f) = depois_do_gate(&r) {
                return Err(f);
            }
            let bytes = conteudo(&r).ok_or(Falha::Interna)?;
            if !bytes.is_empty() {
                let n = bytes.len().min(destino.len());
                destino[..n].copy_from_slice(&bytes[..n]);
                return Ok(n);
            }
            match estado(&r) {
                // A espera venceu no silêncio: espera de novo.
                Some("established") | Some("connecting") => {}
                // O outro lado fechou o sentido dele, e tudo já foi lido.
                Some("closing") => return Ok(0),
                // Derrubada: o que vinha pode ter ficado no caminho.
                Some("closed") => return Err(Falha::Caiu),
                _ => return Err(Falha::Interna),
            }
        }
        Err(Falha::Prazo)
    }
}

impl Drop for Conexao {
    fn drop(&mut self) {
        // Sem garantia: a conexão pode já ter acabado, ou o gate recusar —
        // um processo isolado não fecha nada, e a dele cai sozinha.
        let _ = nativo::pedir("net.close", |w| w.field_u64("connection", self.numero));
    }
}

impl tls::Transporte for Conexao {
    fn mandar(&mut self, dados: &[u8]) -> Result<(), tls::Falha> {
        Conexao::mandar(self, dados).map_err(Falha::para_o_tls)
    }

    fn receber(&mut self, destino: &mut [u8]) -> Result<usize, tls::Falha> {
        Conexao::receber(self, destino).map_err(Falha::para_o_tls)
    }
}

impl http::Fluxo for Conexao {
    type Falha = Falha;

    fn mandar(&mut self, dados: &[u8]) -> Result<(), Falha> {
        Conexao::mandar(self, dados)
    }

    fn receber(&mut self, destino: &mut [u8]) -> Result<usize, Falha> {
        Conexao::receber(self, destino)
    }
}
