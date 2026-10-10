//! O TLS de um programa: o pacote `tls` sobre a interface nativa.
//!
//! O que o pacote pede a quem o usa, aqui vem do registro, cada coisa pelo
//! gate, como qualquer pedido do programa:
//!
//! - a **semente** de cada conexão: 32 bytes do `random.read`;
//! - o **relógio**: o tempo lógico do `system.info` — o RTC com o piso do
//!   journal, que nunca volta: um RTC atrasado de propósito não ressuscita
//!   um certificado vencido;
//! - as **âncoras**: um arquivo PEM lido por `fs.read`;
//! - o **transporte**: a conexão do `net.connect` — o destino inteiro, que
//!   a política enumera —, com cada `net.send` e cada `net.recv` decididos
//!   de novo, e os dois esperando pelo evento da pilha (`wait`), sem girar.
//!
//! A ordem de [`conectar`] é a de quem falha fechado: a semente e o relógio
//! antes de qualquer conexão — sem eles, nada sai —, e o destino decidido
//! pelo gate antes do primeiro byte do TLS. Um destino fora do alcance é a
//! recusa do gate, com o código dele, e o `ClientHello` nem é montado.

use alloc::vec::Vec;

pub use tls::{Ancoras, CLARO_POR_REGISTRO, Codigo, Falha, Sessao};

use crate::nativo::{self, Resposta, conteudo};

/// Quanto cada `net.recv` e cada `net.send` espera pelo evento da pilha, em
/// milissegundos.
const ESPERA_MS: u64 = 5_000;

/// Quantas esperas vencidas seguidas o transporte aceita antes de dizer
/// que o par não responde.
const ESPERAS: usize = 3;

/// O maior pedaço de um `net.send`: o buffer de uma conexão.
const MAIOR_ENVIO: usize = 4096;

/// O maior arquivo de âncoras que se lê.
const MAIOR_ANCORAS: u64 = 16 * 1024;

/// A recusa do gate, com o código dele, ou a falha da chamada.
fn do_pedido(r: Result<Resposta, i64>) -> Result<Resposta, Falha> {
    let r = r.map_err(|_| Falha::Transporte(Codigo::de("TECHNICAL_ERROR")))?;
    if let Err(recusa) = r.resultado() {
        return Err(Falha::Transporte(Codigo::de(
            recusa.motivo.unwrap_or("TECHNICAL_ERROR"),
        )));
    }
    Ok(r)
}

/// O `code` de uma falha depois do gate — o firewall, a rede —, ou o
/// `error` sem código, que é técnico.
fn falha_depois_do_gate(r: &Resposta) -> Option<Falha> {
    let resultado = r.resultado().ok()?;
    if let Some(codigo) = resultado.member("code").and_then(|c| c.as_str()) {
        return Some(Falha::Transporte(Codigo::de(codigo)));
    }
    resultado
        .member("error")
        .map(|_| Falha::Transporte(Codigo::de("TECHNICAL_ERROR")))
}

/// A semente de uma conexão: 32 bytes do `random.read`, pelo gate. Sem
/// ela, não há conexão.
pub fn semente() -> Result<[u8; 32], Falha> {
    let r = do_pedido(nativo::pedir("random.read", |w| w.field_u64("bytes", 32)))?;
    if let Some(f) = falha_depois_do_gate(&r) {
        // Sem entropia no kernel: o TLS não começa.
        return Err(match f {
            Falha::Transporte(c) if c.como_str() == "ENTROPY_UNAVAILABLE" => Falha::SemAcaso,
            outra => outra,
        });
    }
    let resultado = r.resultado().map_err(|_| Falha::SemAcaso)?;
    let hex = resultado
        .member("content")
        .and_then(|c| c.as_str())
        .filter(|h| h.len() == 64)
        .ok_or(Falha::SemAcaso)?;
    let mut semente = [0u8; 32];
    for (i, par) in hex.as_bytes().chunks(2).enumerate() {
        let alto = (par[0] as char).to_digit(16).ok_or(Falha::SemAcaso)?;
        let baixo = (par[1] as char).to_digit(16).ok_or(Falha::SemAcaso)?;
        semente[i] = (alto * 16 + baixo) as u8;
    }
    Ok(semente)
}

/// O relógio: o tempo lógico, em segundos desde 1970, do `system.info`.
/// Zero — sem RTC e sem piso — é falta de relógio.
pub fn relogio() -> Result<u64, Falha> {
    let r = do_pedido(nativo::pedir("system.info", |_| Ok(())))?;
    r.resultado()
        .ok()
        .and_then(|i| i.member("persistence")?.member("clock")?.as_u64())
        .filter(|&s| s > 0)
        .ok_or(Falha::SemRelogio)
}

/// As âncoras do arquivo PEM `caminho`, lido por `fs.read`, pelo gate.
pub fn ancoras(caminho: &str) -> Result<Ancoras, Falha> {
    let mut pem = Vec::new();
    loop {
        let r = do_pedido(nativo::pedir("fs.read", |w| {
            w.field_str("path", caminho)?;
            w.field_u64("offset", pem.len() as u64)?;
            w.field_u64("max", 4096)
        }))?;
        let resultado = r.resultado().map_err(|_| Falha::Ancoras)?;
        if resultado.member("error").is_some() {
            return Err(Falha::Ancoras);
        }
        let tamanho = resultado
            .member("size")
            .and_then(|v| v.as_u64())
            .ok_or(Falha::Ancoras)?;
        if tamanho > MAIOR_ANCORAS {
            return Err(Falha::Ancoras);
        }
        let pedaco = conteudo(&r).ok_or(Falha::Ancoras)?;
        if pedaco.is_empty() {
            break;
        }
        pem.extend_from_slice(&pedaco);
        if pem.len() as u64 >= tamanho {
            break;
        }
    }
    Ancoras::de_pem(&pem)
}

/// A conexão do `net.connect`, como transporte do TLS. Largada, é fechada.
pub struct Conexao {
    numero: u64,
}

impl Conexao {
    /// O número que o `net.connect` devolveu.
    pub fn numero(&self) -> u64 {
        self.numero
    }

    /// Espera o aperto do TCP terminar: uma leitura de nada, que espera o
    /// estado sair de `connecting`.
    fn esperar_aberta(&mut self) -> Result<(), Falha> {
        for _ in 0..ESPERAS {
            let r = do_pedido(nativo::pedir("net.recv", |w| {
                w.field_u64("connection", self.numero)?;
                w.field_u64("max", 0)?;
                w.field_u64("wait", ESPERA_MS)
            }))?;
            if let Some(f) = falha_depois_do_gate(&r) {
                return Err(f);
            }
            match r.resultado().ok().and_then(|j| j.member("state")?.as_str()) {
                Some("established") => return Ok(()),
                Some("connecting") => {}
                // Recusada pelo outro lado, ou caiu.
                _ => return Err(Falha::SemResposta),
            }
        }
        Err(Falha::SemResposta)
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
    fn mandar(&mut self, dados: &[u8]) -> Result<(), Falha> {
        let mut mandados = 0;
        let mut vencidas = 0;
        while mandados < dados.len() {
            let fim = (mandados + MAIOR_ENVIO).min(dados.len());
            let r = do_pedido(nativo::pedir_com_anexo(
                "net.send",
                |w| {
                    w.field_u64("connection", self.numero)?;
                    w.field_u64("wait", ESPERA_MS)
                },
                &dados[mandados..fim],
            ))?;
            if let Some(f) = falha_depois_do_gate(&r) {
                return Err(f);
            }
            let resultado = r.resultado().map_err(|_| Falha::Interna)?;
            let n = resultado
                .member("sent")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            if n == 0 {
                // A espera venceu sem espaço, ou a conexão não manda mais.
                match resultado.member("state").and_then(|e| e.as_str()) {
                    Some("established") | Some("connecting") => {
                        vencidas += 1;
                        if vencidas >= ESPERAS {
                            return Err(Falha::SemResposta);
                        }
                    }
                    _ => return Err(Falha::Interrompida),
                }
            } else {
                vencidas = 0;
            }
            mandados += n;
        }
        Ok(())
    }

    fn receber(&mut self, destino: &mut [u8]) -> Result<usize, Falha> {
        for _ in 0..ESPERAS {
            let maximo = destino.len().min(MAIOR_ENVIO) as u64;
            let r = do_pedido(nativo::pedir("net.recv", |w| {
                w.field_u64("connection", self.numero)?;
                w.field_u64("max", maximo)?;
                w.field_u64("wait", ESPERA_MS)
            }))?;
            if let Some(f) = falha_depois_do_gate(&r) {
                return Err(f);
            }
            let bytes = conteudo(&r).ok_or(Falha::Interna)?;
            if !bytes.is_empty() {
                let n = bytes.len().min(destino.len());
                destino[..n].copy_from_slice(&bytes[..n]);
                return Ok(n);
            }
            match r.resultado().ok().and_then(|j| j.member("state")?.as_str()) {
                // A espera venceu no silêncio: espera de novo.
                Some("established") | Some("connecting") => {}
                // O outro lado fechou, e nada mais vem.
                _ => return Ok(0),
            }
        }
        Err(Falha::SemResposta)
    }
}

/// Conecta ao `destino` — `tcp:<ipv4>:<porta>`, decidido pelo gate —, e
/// conversa TLS com quem prova ser `nome`, pelas `ancoras`.
pub fn conectar(destino: &str, nome: &str, ancoras: &Ancoras) -> Result<Sessao<Conexao>, Falha> {
    // Antes de qualquer conexão: sem semente ou sem relógio, nada sai.
    let semente = semente()?;
    let agora = relogio()?;
    // O destino, pelo gate: a recusa vem com o código dele, e o TLS nem
    // começa.
    let r = do_pedido(nativo::pedir("net.connect", |w| w.field_str("to", destino)))?;
    if let Some(f) = falha_depois_do_gate(&r) {
        return Err(f);
    }
    let numero = r
        .resultado()
        .ok()
        .and_then(|j| j.member("connection")?.as_u64())
        .ok_or(Falha::Interna)?;
    let mut conexao = Conexao { numero };
    conexao.esperar_aberta()?;
    Sessao::conectar(conexao, nome, ancoras, agora, semente)
}
