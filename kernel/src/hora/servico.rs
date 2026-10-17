//! O fio `hora`: o serviço de hora, que fala só pelo gate.
//!
//! Como o NSF (`crate::seguranca`): um fio do kernel com
//! `Autoridade::Servico(Servico::Hora)` e o papel que a linha `servico hora`
//! da política lhe dá, e nenhum passo a menos que um processo — cada
//! operação é um pedido JSON-RPC ao gate, decidido e gravado. Ele não toca
//! o relógio: só entrega ao kernel o que as fontes responderam, e quem
//! decide é o tratador de `time.sync`.
//!
//! # Uma rodada
//!
//! Para cada fonte do registro, na ordem dele (o nonce encadeado exige a
//! ordem — ver `super::rodada`):
//!
//! 1. `time.request {source}`: o pedido v1, de 1024 bytes, e o id;
//! 2. `net.connect {to}`: a associação UDP com o destino da fonte — o gate
//!    decide pelo alcance do papel `tempo`, e o firewall pode cortá-la;
//! 3. `net.send` com o pedido no anexo, byte a byte;
//! 4. `net.recv` com espera até o prazo do pedido: cada datagrama que
//!    chega vai inteiro, como chegou, a `time.sync` — uma recusa não
//!    consome o id, e a fonte tem até quatro entregas;
//! 5. `net.close`;
//! 6. sem resposta aceita nem recusada de vez, `time.sync {id}` sem anexo:
//!    o aviso de que ela não veio. A entrega da última fonte fecha a rodada.
//!
//! Uma recusa do gate — sem `time.sync`, sem a linha `servico`, a taxa —
//! encerra a rodada: nada aqui tenta outro caminho, e a recusa fica
//! gravada.
//!
//! # O intervalo
//!
//! O do desenho (§7.6): 2 s entre rodadas até sincronizar, crescendo até
//! 64 s com as fontes caladas; sincronizado, 64 s dobrando até 1024 s; uma
//! falha depois disso volta a 64 s; um candidato a salto pede a rodada
//! seguinte depois da separação mínima. Medido no relógio do kernel — é
//! uma duração.
//!
//! # Como o fio espera
//!
//! Bloqueado, e não descansando: entre as rodadas, até o tique da próxima;
//! no `net.recv`, até o datagrama ou o prazo — ver `fios::bloquear_em`. Um
//! fio que descansa a cada interrupção continua pronto, e o da hora era o
//! quinto da máquina de quatro núcleos da bancada: nenhum núcleo dormia
//! mais, e o canal do agente respondia duas vezes e meia mais devagar.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use politica::sigiloso::Texto;
use protocolo::json::{Json, JsonWriter};

use crate::autorizacao::{Autoridade, Chamador, Programa, Servico};

/// O intervalo entre rodadas antes da primeira sincronização.
pub const ANTES_DE_SINCRONIZAR_MS: u64 = 2_000;

/// O maior intervalo sem hora autenticada, com as fontes caladas.
pub const MAIOR_SEM_HORA_MS: u64 = 64_000;

/// O intervalo depois de sincronizar, e o de depois de uma falha.
pub const SINCRONIZADO_MS: u64 = 64_000;

/// O maior intervalo, sincronizado.
pub const MAIOR_INTERVALO_MS: u64 = 1_024_000;

/// A margem antes do prazo de um pedido: a espera por uma resposta acaba
/// antes de o id vencer, para a entrega ainda achar o id.
const MARGEM_MS: u64 = 100;

/// Antes de quando a próxima rodada não acontece, no relógio do kernel.
static PROXIMA_MS: AtomicU64 = AtomicU64::new(0);

/// O intervalo depois da última rodada.
static INTERVALO_MS: AtomicU64 = AtomicU64::new(ANTES_DE_SINCRONIZAR_MS);

/// O que uma rodada deu, para o intervalo até a próxima.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Desfecho {
    /// A última fonte fechou a rodada: o efeito e o estado depois.
    Fechada { efeito: String, estado: String },
    /// O gate recusou um pedido no meio, ou a resposta não se leu: o
    /// motivo.
    Encerrada(&'static str),
}

/// Liga o serviço de hora: o fio, com a autoridade do serviço. Sem
/// registro de fontes, o serviço não sobe, e o civil fica no RTC.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
pub fn iniciar() {
    if crate::identidade::fontes_de_hora().is_none() {
        crate::log_info!(
            "hora",
            "sem registro de fontes de hora: o servico nao sobe, e o civil fica no RTC"
        );
        return;
    }
    match crate::fios::criar_como("hora", laco, 0, Autoridade::Servico(Servico::Hora)) {
        Ok(id) => crate::log_info!("hora", "servico de hora no fio {}", id.numero()),
        Err(motivo) => crate::log_error!("hora", "o fio do servico de hora nao subiu: {}", motivo),
    }
}

/// O fio do serviço: uma rodada quando chega a hora dela, e até a próxima
/// fora do rodízio — o tique do relógio dos dormentes o devolve. Descansar
/// a cada interrupção, como o NSF, o deixaria pronto o tempo todo, e com ele
/// os fios que descansam passavam o número de núcleos da bancada: ver
/// `fios::bloquear_em`.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
extern "C" fn laco(_argumento: u64) -> ! {
    loop {
        let agora = crate::tempo::uptime_ms();
        let proxima = PROXIMA_MS.load(Ordering::Acquire);
        if agora < proxima {
            crate::fios::bloquear_em(crate::tarefas::relogio::por_ms(proxima - agora));
            continue;
        }
        let d = rodada();
        let intervalo = proximo_intervalo(INTERVALO_MS.load(Ordering::Acquire), &d);
        INTERVALO_MS.store(intervalo, Ordering::Release);
        PROXIMA_MS.store(
            crate::tempo::uptime_ms().saturating_add(intervalo),
            Ordering::Release,
        );
    }
}

/// O intervalo até a próxima rodada, depois de uma com este desfecho —
/// ver o topo do módulo.
pub fn proximo_intervalo(anterior: u64, d: &Desfecho) -> u64 {
    let ja_sincronizou = super::civil::ler().is_some_and(|l| l.incerteza_ms.is_some());
    match d {
        Desfecho::Fechada { efeito, .. } if efeito == "candidato" => super::civil::parametros()
            .map_or(4_000, |p| p.separacao_minima_ms)
            .max(ANTES_DE_SINCRONIZAR_MS),
        Desfecho::Fechada { estado, efeito }
            if estado == "sincronizado" && efeito != "pendente" =>
        {
            if anterior < SINCRONIZADO_MS {
                SINCRONIZADO_MS
            } else {
                anterior.saturating_mul(2).min(MAIOR_INTERVALO_MS)
            }
        }
        _ if ja_sincronizou => SINCRONIZADO_MS,
        _ => anterior
            .saturating_mul(2)
            .clamp(ANTES_DE_SINCRONIZAR_MS, MAIOR_SEM_HORA_MS),
    }
}

/// O serviço de hora, como o gate o vê: um pedido pelo fio que pede, com a
/// autoridade do serviço — e só ela —, e nenhuma imagem a atenuar.
fn chamador() -> Chamador {
    Chamador::Processo {
        fio: crate::fios::id_atual(),
        autoridade: Autoridade::Servico(Servico::Hora),
        programa: Programa::Kernel,
    }
}

/// Pede um comando ao gate, como `quem`, com o anexo se vier um. `Ok` com
/// o resultado; `Err` com o envelope inteiro da recusa.
fn pedir(
    quem: Chamador,
    metodo: &str,
    params: &str,
    anexo: Option<&[u8]>,
) -> Result<Vec<u8>, Texto> {
    let mut linha = String::new();
    {
        let mut w = JsonWriter::new(&mut linha);
        let _ = w.begin_object();
        let _ = w.field_str("jsonrpc", "2.0");
        let _ = w.field_u64("id", 1);
        let _ = w.field_str("method", metodo);
        let _ = w.key("params");
        let _ = w.raw_value(params);
        let _ = w.end_object();
    }
    let mut pedido = linha.into_bytes();
    if let Some(a) = anexo {
        pedido.push(crate::nativo::SEPARADOR);
        pedido.extend_from_slice(a);
    }
    let envelope = crate::nativo::responder_pelo_kernel_esperando(quem, &pedido);
    match Json(envelope.como_bytes()).member("result") {
        Some(r) => Ok(r.0.to_vec()),
        None => Err(envelope),
    }
}

/// Um resultado sem `error`: o comando fez o que pediu.
fn sem_erro(r: &[u8]) -> bool {
    Json(r).member("error").is_none()
}

/// O datagrama de um `net.recv`, como chegou: em base64, ou em texto — o
/// gate manda texto quando o datagrama inteiro é UTF-8. `None` sem
/// datagrama.
fn datagrama(r: &[u8]) -> Option<Vec<u8>> {
    let r = Json(r);
    if r.member("datagram").and_then(|d| d.as_u64()).unwrap_or(0) == 0 {
        return None;
    }
    let conteudo = r.member("content")?;
    match r.member("encoding").and_then(|e| e.as_str()) {
        Some("base64") => de_base64(conteudo.as_str()?),
        Some("utf-8") => {
            let mut destino = alloc::vec![0u8; conteudo.0.len()];
            let texto = conteudo.desescapar_em(&mut destino)?;
            Some(texto.as_bytes().to_vec())
        }
        _ => None,
    }
}

/// O base64 do gate — o pedido de `time.request`, o datagrama de
/// `net.recv` —, de volta aos bytes. Estrito: múltiplo de quatro, o
/// preenchimento só no fim. Cada cliente da interface tem o seu, como os
/// programas; o do NSF é dele.
fn de_base64(texto: &str) -> Option<Vec<u8>> {
    let t = texto.as_bytes();
    if !t.len().is_multiple_of(4) {
        return None;
    }
    let valor = |c: u8| -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let (quadras, _) = t.as_chunks::<4>();
    let blocos = quadras.len();
    let mut saida = Vec::with_capacity(blocos * 3);
    for (i, bloco) in quadras.iter().enumerate() {
        let preenchidos = bloco.iter().rev().take_while(|&&c| c == b'=').count();
        if preenchidos > 2 || (preenchidos > 0 && i + 1 != blocos) {
            return None;
        }
        let mut n = 0u32;
        for &c in &bloco[..4 - preenchidos] {
            n = (n << 6) | valor(c)?;
        }
        n <<= 6 * preenchidos as u32;
        saida.extend_from_slice(&n.to_be_bytes()[1..4 - preenchidos]);
    }
    Some(saida)
}

/// Uma rodada do serviço, fonte por fonte — ver o topo do módulo. Só o fio
/// do serviço e a suíte chamam: o `xtask` confere.
pub fn rodada() -> Desfecho {
    rodada_como(chamador())
}

/// Só para a suíte: uma rodada pedida por outro principal — o sistema, um
/// agente —, pelas mesmas operações e pelo mesmo gate.
#[cfg(feature = "modo-teste")]
pub fn rodada_de_teste(quem: Chamador) -> Desfecho {
    rodada_como(quem)
}

fn rodada_como(quem: Chamador) -> Desfecho {
    let Some(registro) = crate::identidade::fontes_de_hora() else {
        return Desfecho::Encerrada("sem registro de fontes");
    };
    let n = registro.fontes().len();
    for (i, fonte) in registro.fontes().iter().enumerate() {
        match consultar(quem, fonte) {
            Ok(Some(fechada)) => return fechada,
            Ok(None) if i + 1 < n => {}
            Ok(None) => return Desfecho::Encerrada("a ultima fonte nao fechou a rodada"),
            Err(motivo) => return Desfecho::Encerrada(motivo),
        }
    }
    Desfecho::Encerrada("o registro nao tem fontes")
}

/// Uma fonte: o pedido, a ida, a volta, a entrega. `Ok(Some)` quando esta
/// entrega fechou a rodada; `Err` quando o gate recusou um pedido do
/// serviço.
///
/// Em passos pequenos, cada um fora dos outros: a entrega de uma resposta
/// confere duas assinaturas no fundo do despacho do gate, e o que fica na
/// pilha por baixo dela é só o quadro de quem orquestra — ver a pilha em
/// [`super::rodada`].
fn consultar(
    quem: Chamador,
    fonte: &hora::registro::Fonte,
) -> Result<Option<Desfecho>, &'static str> {
    let (id, bytes) = pedir_a_fonte(quem, fonte)?;
    let prazo = crate::tempo::uptime_ms() + super::PRAZO_MS.saturating_sub(MARGEM_MS);
    let fechou = match conectar(quem, fonte) {
        Some(c) => {
            let fechou = ida_e_volta(quem, c, id, &bytes, prazo);
            fechar(quem, c);
            fechou?
        }
        None => None,
    };
    let entrega = match fechou {
        Some(e) => e,
        None => sincronizar(quem, id, None)?,
    };
    Ok(rodada_fechada(&entrega))
}

/// `time.request` da fonte: o id do pedido e os bytes a mandar.
#[inline(never)]
fn pedir_a_fonte(
    quem: Chamador,
    fonte: &hora::registro::Fonte,
) -> Result<(u64, Vec<u8>), &'static str> {
    let params = alloc::format!(r#"{{"source":"{}"}}"#, fonte.nome());
    let pedido = pedir(quem, "time.request", &params, None).map_err(|_| "time.request recusado")?;
    if !sem_erro(&pedido) {
        return Err("time.request sem pedido");
    }
    let lido = Json(&pedido);
    let id = lido
        .member("id")
        .and_then(|v| v.as_u64())
        .ok_or("time.request sem id")?;
    let bytes = lido
        .member("request")
        .and_then(|v| v.as_str())
        .and_then(de_base64)
        .ok_or("time.request sem o pedido")?;
    Ok((id, bytes))
}

/// `net.connect` ao destino da fonte: a conexão, se o gate deixou.
#[inline(never)]
fn conectar(quem: Chamador, fonte: &hora::registro::Fonte) -> Option<u64> {
    let destino = alloc::format!(r#"{{"to":"{}"}}"#, fonte.destino());
    pedir(quem, "net.connect", &destino, None)
        .ok()
        .filter(|r| sem_erro(r))
        .and_then(|r| Json(&r).member("connection").and_then(|c| c.as_u64()))
}

/// `net.close` da conexão.
#[inline(never)]
fn fechar(quem: Chamador, c: u64) {
    let fecho = alloc::format!(r#"{{"connection":{c}}}"#);
    let _ = pedir(quem, "net.close", &fecho, None);
}

/// A ida e a volta: manda o pedido e entrega, até o prazo, cada datagrama
/// que voltar — até a fonte fechar. `Ok(Some)` com a entrega que a fechou.
#[inline(never)]
fn ida_e_volta(
    quem: Chamador,
    c: u64,
    id: u64,
    bytes: &[u8],
    prazo: u64,
) -> Result<Option<Vec<u8>>, &'static str> {
    if !mandar(quem, c, bytes) {
        return Ok(None);
    }
    for _ in 0..hora::pedidos::MAIS_TENTATIVAS {
        let falta = prazo.saturating_sub(crate::tempo::uptime_ms());
        if falta == 0 {
            break;
        }
        let Some(chegou) = receber(quem, c, falta) else {
            break;
        };
        let entrega = sincronizar(quem, id, Some(&chegou))?;
        if Json(&entrega)
            .member("closed")
            .and_then(|v| v.as_bool())
            .unwrap_or(true)
        {
            return Ok(Some(entrega));
        }
    }
    Ok(None)
}

/// `net.send` do pedido pela conexão: se foi inteiro.
#[inline(never)]
fn mandar(quem: Chamador, c: u64, bytes: &[u8]) -> bool {
    let envio = alloc::format!(r#"{{"connection":{c},"attachment":{}}}"#, bytes.len());
    pedir(quem, "net.send", &envio, Some(bytes))
        .ok()
        .is_some_and(|r| {
            Json(&r).member("sent").and_then(|s| s.as_u64()) == Some(bytes.len() as u64)
        })
}

/// `net.recv` da conexão, esperando até `falta` ms: o datagrama, se veio.
#[inline(never)]
fn receber(quem: Chamador, c: u64, falta: u64) -> Option<Vec<u8>> {
    let leitura = alloc::format!(
        r#"{{"connection":{c},"max":{},"wait":{falta}}}"#,
        crate::rede::pilha::BUFFER_DA_CONEXAO
    );
    pedir(quem, "net.recv", &leitura, None)
        .ok()
        .and_then(|r| datagrama(&r))
}

/// `time.sync` do id, com a resposta como chegou — ou sem ela.
#[inline(never)]
fn sincronizar(quem: Chamador, id: u64, resposta: Option<&[u8]>) -> Result<Vec<u8>, &'static str> {
    let params = match resposta {
        Some(r) => alloc::format!(r#"{{"id":{id},"attachment":{}}}"#, r.len()),
        None => alloc::format!(r#"{{"id":{id}}}"#),
    };
    pedir(quem, "time.sync", &params, resposta).map_err(|_| "time.sync recusado")
}

/// O desfecho da rodada, se esta entrega a fechou.
fn rodada_fechada(entrega: &[u8]) -> Option<Desfecho> {
    let rodada = Json(entrega).member("round")?;
    if rodada.member("closed").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    let texto = |chave: &str| {
        rodada
            .member(chave)
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_default()
    };
    Some(Desfecho::Fechada {
        efeito: texto("effect"),
        estado: texto("state_after"),
    })
}
