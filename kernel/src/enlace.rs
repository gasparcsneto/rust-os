//! O enlace entre dois Dukes relacionados: o pedido da malha que vai de um
//! dispositivo a outro, e volta — sem um segundo gate, nem uma segunda
//! política, nem uma segunda auditoria.
//!
//! ```text
//! A: processo da pessoa ─ gate (fabric.send + fabric.remote) ─ tabela ─ serviço enlace
//!      ─ net.* pelo gate ─ Noise IK (chave do Duke A, prólogo do enlace) ─▶
//! B: vaga 7071 ─ aperto (registro de dispositivos) ─ gate (pessoa ∩ relação ∩ remoto)
//!      ─ malha de B, titular a pessoa da relação ─ resposta ─▶ A ─ o processo lê
//! ```
//!
//! # A origem
//!
//! O processo de uma pessoa pede `fabric.send`, `fabric.discover`,
//! `fabric.status` ou `fabric.cancel` com `device: "dispositivo:<nome>"`.
//! O gate decide as duas permissões — a da malha sobre a intenção, e
//! `fabric.remote` sobre o dispositivo, resolvido no espaço da pessoa —, e
//! o handler põe o pedido na tabela ([`politica::enlace`]) com a ordem das
//! gravações na mão, depois de decidir de novo. O comando **suspende**:
//! quem despachou executa o pedido de novo, inteiro, pelo gate, quando a
//! resposta chega ou o prazo vence — e só então a lê. A decisão de antes
//! da espera não vale depois dela.
//!
//! O **serviço de enlace** — um fio do kernel com `Autoridade::Servico`,
//! como o de hora — leva cada pedido ao par: `net.connect` ao endereço da
//! relação, pelo gate, com o papel da linha `servico enlace`; o aperto IK
//! com a chave do Duke ([`crate::identidade::com_chave_do_duke`]) e a do
//! par fixada pela relação; o pedido cifrado; a resposta. Ele não decide
//! entrega nenhuma: carrega as que o gate já decidiu, e só para relações
//! ativas e dispositivos que não estão suspensos.
//!
//! # O destino
//!
//! As vagas de cima do canal TCP escutam a porta do enlace — ver
//! [`crate::rede::canal`]. Cada uma tem um [`Lado`]: o aperto IK com o
//! prólogo do enlace, a chave procurada no **registro de dispositivos** —
//! nunca no de agentes —, a contenção, e a confirmação pelo primeiro
//! quadro de dados que abre, como no canal do agente. Cada pedido que
//! chega diz a relação e o programa que a origem atesta, e vai ao gate
//! como `Chamador::Remoto`: o papel da pessoa da relação, o da relação e o
//! teto `remoto`, todos ao mesmo tempo, procurados a cada decisão e
//! reconfirmados no ponto de commit. Só o conjunto fechado da malha passa —
//! ver [`politica::enlace::METODOS`] —, e o programa atestado não é
//! critério de nada: vai à auditoria.
//!
//! # A revogação e a suspensão
//!
//! [`dispositivo_saiu`]: as sessões de enlace daquela chave caem na hora,
//! com a recusa em claro; as entregas vivas que ela mandou à malha daqui
//! são anuladas; os pedidos daqui a ela falham, e quem esperava acorda. A
//! revogação, além disso, esquece a contagem de nonces da chave, que não
//! volta.
//!
//! # Volátil
//!
//! A tabela, as sessões e as entregas remotas vivem na memória: um boot as
//! perde. Só a relação, o registro e a lápide são gravados — ver
//! [`crate::dispositivos`].

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::task::Waker;

use politica::Codigo;
use politica::enlace::{Andamento, Enlace, Tomado};
use politica::mensagens::Canal;
use protocolo::json::{Json, JsonWriter};
use sigilo::quadro::{self, Leitor, Tipo};
use sigilo::{Iniciador, Respondedor, Transporte};

use crate::autorizacao::{Autoridade, Chamador, Programa, Servico};
use crate::rede::espera::Desfecho;
use crate::trava::Mutex;

/// O maior pedido, ou a maior resposta, que atravessa o enlace, em bytes:
/// uma linha. O corpo de uma entrega tem 512; o resto é o envelope.
pub const MAIOR_LINHA: usize = 8 * 1024;

/// Quanto o serviço espera o par em cada passo de rede.
const PASSO_MS: u64 = 5_000;

/// Quantos passos de rede o serviço dá até a resposta: o aperto do TCP, a
/// resposta do aperto, a do pedido — com folga para as voltas da pilha.
const MAIS_PASSOS: usize = 8;

// ---------------------------------------------------------------------
// A origem: a tabela, a espera e o serviço.
// ---------------------------------------------------------------------

struct Origem {
    tabela: Enlace,
    /// Sorteada no primeiro uso: o par abre uma janela nova a cada boot
    /// daqui.
    epoca: [u8; 8],
    /// As esperas armadas, por pedido: o waker de quem espera.
    esperas: BTreeMap<u64, Option<Waker>>,
    /// O fio do serviço, esperando um pedido na fila.
    servico: Option<Waker>,
}

static ORIGEM: Mutex<Option<Origem>> = Mutex::new(None);

fn com_origem<R>(f: impl FnOnce(&mut Origem) -> R) -> R {
    // A época sai do gerador antes da trava, como a da malha.
    let precisa = crate::arch::sem_interrupcoes(|| ORIGEM.lock().is_none());
    let nova = precisa.then(|| {
        let mut epoca = [0u8; 8];
        if crate::aleatorio::preencher(&mut epoca).is_err() {
            epoca = crate::tempo::uptime_ms().to_le_bytes();
        }
        Origem {
            tabela: Enlace::nova(),
            epoca,
            esperas: BTreeMap::new(),
            servico: None,
        }
    });
    crate::arch::sem_interrupcoes(|| {
        let mut o = ORIGEM.lock();
        if o.is_none() {
            *o = nova;
        }
        f(o.as_mut().expect("a tabela do enlace acabou de ser criada"))
    })
}

/// Como [`com_origem`], sem criar a tabela: para quem só limpa.
fn se_ha_origem<R>(f: impl FnOnce(&mut Origem) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| ORIGEM.lock().as_mut().map(f))
}

/// A época deste boot, que vai no aperto.
pub fn epoca() -> [u8; 8] {
    com_origem(|o| o.epoca)
}

fn acordar(wakers: Vec<Waker>) {
    for w in wakers {
        w.wake();
    }
}

/// Os wakers de quem espera pelos pedidos `ids`. Com a tabela na mão.
fn de_quem_espera(o: &mut Origem, ids: &[u64]) -> Vec<Waker> {
    ids.iter()
        .filter_map(|id| o.esperas.get_mut(id).and_then(Option::take))
        .collect()
}

/// O resumo de um pedido: o método e os parâmetros, como vieram — a mesma
/// pergunta executada de novo tem o mesmo.
fn resumo_do_pedido(metodo: &str, params: &[u8]) -> [u8; 32] {
    sigilo::resumo::resumir(&[
        &(metodo.len() as u64).to_le_bytes(),
        metodo.as_bytes(),
        params,
    ])
}

/// A linha que vai ao par: o mesmo método e os mesmos parâmetros, sem o
/// `device` — o par não o conhece — e sem a espera, com o nonce do enlace
/// no lugar do nonce do processo.
fn linha_para_o_par(metodo: &str, params: Json, nonce: Option<u64>) -> String {
    let mut linha = String::new();
    let mut w = JsonWriter::new(&mut linha);
    let _ = (|| -> fmt::Result {
        w.begin_object()?;
        w.field_str("jsonrpc", "2.0")?;
        w.field_u64("id", 1)?;
        w.field_str("method", metodo)?;
        w.key("params")?;
        w.begin_object()?;
        let mut r = Ok(());
        params.para_cada_chave(|chave| {
            if r.is_err() || matches!(chave, politica::enlace::PARAMETRO | "wait" | "nonce") {
                return;
            }
            if let Some(bruto) = params.member(chave).and_then(|v| v.raw_str()) {
                r = w.key(chave).and_then(|_| w.raw_value(bruto));
            }
        });
        r?;
        if let Some(n) = nonce {
            w.field_u64("nonce", n)?;
        }
        w.end_object()?;
        w.end_object()
    })();
    linha
}

/// O canal e a pessoa de quem pede o comando em execução, e o resumo da
/// imagem do programa dele — o que a origem atesta ao par. Só quem age
/// por uma pessoa fala com outro dispositivo: o gate já o garantiu.
fn quem_pede() -> Option<(Canal, [u8; 32])> {
    let ator = crate::malha::Ator::do_comando()?;
    let programa = match crate::autorizacao::programa_decidido() {
        Some(Programa::Imagem { resumo, .. }) => resumo,
        _ => [0; 32],
    };
    Some((ator.canal(), programa))
}

/// Escreve o desfecho de um pedido que terminou: a resposta do par,
/// aninhada em `remote` — o que o par diz não se mistura com o que este
/// Duke diz —, ou a falha.
fn escrever_desfecho(
    w: &mut JsonWriter,
    recurso: &str,
    desfecho: Result<String, (Codigo, &'static str)>,
) -> Result<Option<String>, fmt::Error> {
    let texto = match desfecho {
        Ok(t) => t,
        Err((codigo, motivo)) => {
            w.field_bool("ok", false)?;
            w.field_str("device", recurso)?;
            w.field_str("code", codigo.nome())?;
            w.field_str("error", motivo)?;
            w.end_object()?;
            return Ok(None);
        }
    };
    let envelope = Json(texto.as_bytes());
    match (envelope.member("result"), envelope.member("error")) {
        (Some(r), _) if r.0.first() == Some(&b'{') => {
            let ok = r.member("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            w.field_bool("ok", ok)?;
            w.field_str("device", recurso)?;
            w.key("remote")?;
            w.raw_value(r.raw_str().unwrap_or("{}"))?;
            w.end_object()?;
            Ok(Some(texto))
        }
        // O gate do par recusou: o código dele, e não o daqui.
        (_, Some(e)) => {
            let codigo = e
                .member("data")
                .and_then(|v| v.as_str())
                .and_then(Codigo::de_nome)
                .unwrap_or(Codigo::Error);
            w.field_bool("ok", false)?;
            w.field_str("device", recurso)?;
            w.field_str("code", codigo.nome())?;
            w.field_str("error", "o par recusou o pedido")?;
            w.end_object()?;
            Ok(None)
        }
        _ => {
            w.field_bool("ok", false)?;
            w.field_str("device", recurso)?;
            w.field_str("code", Codigo::Error.nome())?;
            w.field_str("error", "a resposta do par nao se le")?;
            w.end_object()?;
            Ok(None)
        }
    }
}

/// O pedido da malha a outro dispositivo, pelo handler do comando — ver o
/// topo do módulo. `metodo` é o do comando em execução; o dispositivo é o
/// que o gate decidiu.
///
/// Suspende — sem escrever nada — se o pedido entrou ou já esperava, e o
/// despachante sabe esperar; responde, se terminou.
pub fn pelo_enlace(metodo: &'static str, params: Json, w: &mut JsonWriter) -> fmt::Result {
    let Some(alvo) = crate::autorizacao::dispositivo_decidido() else {
        w.begin_object()?;
        w.field_bool("ok", false)?;
        w.field_str("code", Codigo::DenyResource.nome())?;
        w.field_str("error", "o dispositivo nao e o que o gate decidiu")?;
        return w.end_object();
    };
    let recurso = alvo.recurso.clone();
    let Some((canal, programa)) = quem_pede() else {
        w.begin_object()?;
        w.field_bool("ok", false)?;
        w.field_str("code", Codigo::DenyNotAuthenticated.nome())?;
        w.field_str("error", "quem pede nao age por uma pessoa")?;
        return w.end_object();
    };
    let nonce = (metodo == "fabric.send")
        .then(|| params.member("nonce").and_then(|v| v.as_u64()))
        .flatten();
    let resumo = resumo_do_pedido(metodo, params.0);
    let r = crate::persistencia::em_ordem(|| {
        #[cfg(feature = "modo-teste")]
        crate::autorizacao::gancho_da_reconfirmacao();
        crate::autorizacao::reconfirmar()?;
        if crate::energia::pedida().is_some() {
            return Err((Codigo::Conflict, "a maquina esta reiniciando ou desligando"));
        }
        let agora = crate::tempo::uptime_ms();
        com_origem(|o| {
            o.tabela.pedir(
                canal,
                resumo,
                alvo.chave,
                alvo.relacao,
                nonce,
                programa,
                |n| linha_para_o_par(metodo, params, n),
                agora,
            )
        })
        .map_err(|r| (r.codigo(), r.motivo()))
    });
    let (id, novo) = match r {
        Err((codigo, motivo)) => {
            crate::autorizacao::auditar_execucao(&recurso, codigo, motivo);
            w.begin_object()?;
            w.field_bool("ok", false)?;
            w.field_str("device", &recurso)?;
            w.field_str("code", codigo.nome())?;
            w.field_str("error", motivo)?;
            return w.end_object();
        }
        Ok(Andamento::Pronto(desfecho)) => {
            let codigo = match &desfecho {
                Ok(_) => Codigo::Allow,
                Err((c, _)) => *c,
            };
            let detalhe = match &desfecho {
                Ok(_) => "respondido pelo par",
                Err((_, m)) => m,
            };
            crate::autorizacao::auditar_execucao(&recurso, codigo, detalhe);
            w.begin_object()?;
            let respondido = escrever_desfecho(w, &recurso, desfecho)?;
            // A entrega que o par aceitou: só este canal pergunta por ela.
            if let (Some(texto), "fabric.send") = (respondido, metodo) {
                let resultado = Json(texto.as_bytes()).member("result");
                let id = resultado
                    .and_then(|r| r.member("id"))
                    .and_then(|v| v.as_str());
                let intencao = params.member("intent").and_then(|v| v.as_str());
                if let (Some(id), Some(intencao)) = (id, intencao) {
                    com_origem(|o| o.tabela.lembrar(canal, alvo.chave, id, intencao));
                }
            }
            return Ok(());
        }
        Ok(Andamento::Novo(id)) => (id, true),
        Ok(Andamento::Esperando(id)) => (id, false),
    };
    if novo {
        crate::autorizacao::auditar_execucao(
            &recurso,
            Codigo::Allow,
            &alloc::format!("na fila do enlace: pedido {id}"),
        );
        acordar_o_servico();
    }
    if crate::autorizacao::pode_suspender()
        && let Some(e) = crate::rede::espera::Espera::pelo_enlace(id, PRAZO_DA_ESPERA_MS)
    {
        match crate::autorizacao::suspender(e) {
            Ok(()) => return Ok(()),
            Err(e) => drop(e),
        }
    }
    // Quem não espera pergunta de novo: o pedido segue a caminho.
    w.begin_object()?;
    w.field_bool("ok", false)?;
    w.field_str("device", &recurso)?;
    w.field_str("code", Codigo::Conflict.nome())?;
    w.field_str("error", "a caminho do par: peca de novo para a resposta")?;
    w.field_u64("request", id)?;
    w.end_object()
}

/// O recurso que o gate decide para um pedido da malha a outro
/// dispositivo: a intenção do pedido (`intent`), ou a da entrega que o
/// canal de quem pede mandou àquele dispositivo (`id`) — a que ele não
/// mandou, a de outro canal, ou a que nunca existiu, não resolve, e quem
/// tem a permissão ouve `DENY_RESOURCE` sem saber qual.
pub fn recurso_do_pedido(
    chamador: Chamador,
    comando: &crate::agent::registry::Command,
    params: Json,
) -> Result<String, &'static str> {
    let prefixo = politica::arquivo::PREFIXO_DE_INTENCAO;
    let texto = |nome: &str| params.member(nome).and_then(|v| v.as_str()).unwrap_or("");
    match comando.recurso {
        Some(crate::malha::PARAMETRO_DA_INTENCAO) => {
            return Ok(alloc::format!(
                "{prefixo}{}",
                texto(crate::malha::PARAMETRO_DA_INTENCAO)
            ));
        }
        Some("id") => {}
        _ => return Ok(String::new()),
    }
    let (canal, sessao) = match chamador {
        Chamador::Processo {
            fio,
            autoridade: Autoridade::Pessoa { sessao },
            ..
        } => (Canal::Processo(fio), sessao),
        Chamador::Pessoa(id) => (Canal::Pessoa(id.0), id),
        _ => return Err("so quem age por uma pessoa fala com outro dispositivo"),
    };
    let pessoa = crate::pessoas::dona_da_sessao(sessao).ok_or("sessao de pessoa que acabou")?;
    let nome = politica::arquivo::nome_de_dispositivo(texto(politica::enlace::PARAMETRO))
        .ok_or("`device` nao e `dispositivo:<nome>`")?;
    let (chave, _) = crate::dispositivos::da_pessoa(nome, &pessoa.0)
        .ok_or("o dispositivo nao existe para quem pede")?;
    se_ha_origem(|o| {
        o.tabela
            .intencao_lembrada(canal, &chave, texto("id"))
            .map(|i| alloc::format!("{prefixo}{i}"))
    })
    .flatten()
    .ok_or("a entrega remota nao existe para quem pede")
}

/// Quanto quem pede espera a resposta antes de ser executado de novo: o
/// teto das esperas.
const PRAZO_DA_ESPERA_MS: u64 = crate::rede::espera::PRAZO_MAXIMO_MS;

/// Acorda o fio do serviço, se ele espera um pedido.
fn acordar_o_servico() {
    if let Some(w) = se_ha_origem(|o| o.servico.take()).flatten() {
        w.wake();
    }
}

/// Arma a espera de quem pediu o pedido `id`. Falso se não há o que
/// esperar — ele terminou, ou saiu.
pub fn armar_espera(id: u64) -> bool {
    com_origem(|o| match o.tabela.pedido(id) {
        Some(p) if !p.estado.terminado() => {
            o.esperas.entry(id).or_insert(None);
            true
        }
        _ => false,
    })
}

/// A espera pelo pedido `id` acabou? `Chegou` se ele terminou, `Sumiu` se
/// saiu da tabela; senão `None`, e o waker fica para quando ele terminar.
pub fn conferir_espera(id: u64, waker: Option<&Waker>) -> Option<Desfecho> {
    se_ha_origem(|o| match o.tabela.pedido(id) {
        None => Some(Desfecho::Sumiu),
        Some(p) if p.estado.terminado() => Some(Desfecho::Chegou),
        Some(_) => {
            if let (Some(w), Some(slot)) = (waker, o.esperas.get_mut(&id)) {
                *slot = Some(w.clone());
            }
            None
        }
    })
    .unwrap_or(Some(Desfecho::Sumiu))
}

/// Desarma a espera pelo pedido `id`.
pub fn desarmar_espera(id: u64) {
    se_ha_origem(|o| o.esperas.remove(&id));
}

/// O canal acabou — o processo, a sessão da pessoa —: os pedidos dele saem
/// da tabela. O que já estava a caminho chega ao par, e a resposta não
/// tem quem leia.
pub fn canal_acabou(canal: Canal) {
    let wakers = se_ha_origem(|o| {
        let saem = o.tabela.canal_acabou(canal);
        de_quem_espera(o, &saem)
    })
    .unwrap_or_default();
    acordar(wakers);
}

/// O prazo: o que esperava o par e venceu falha, e quem esperava acorda.
/// Chamada pelo coletor de fios, uma vez por segundo.
pub fn vencer_todos() {
    use core::sync::atomic::{AtomicU64, Ordering};
    static ULTIMA: AtomicU64 = AtomicU64::new(0);
    let agora = crate::tempo::uptime_ms();
    if agora.saturating_sub(ULTIMA.load(Ordering::Relaxed)) < 1_000 {
        return;
    }
    ULTIMA.store(agora, Ordering::Relaxed);
    let wakers = se_ha_origem(|o| {
        let falharam = o.tabela.vencer(agora);
        de_quem_espera(o, &falharam)
    })
    .unwrap_or_default();
    acordar(wakers);
}

/// O próximo pedido da fila, para o serviço levar ao par.
pub fn tomar() -> Option<Tomado> {
    se_ha_origem(|o| o.tabela.tomar()).flatten()
}

/// O desfecho do pedido que o serviço levou: a resposta do par, ou a
/// falha. Quem esperava acorda.
fn concluir(id: u64, r: Result<String, (Codigo, &'static str)>) {
    let wakers = se_ha_origem(|o| {
        match r {
            Ok(texto) => o.tabela.responder(id, texto),
            Err((c, m)) => o.tabela.falhar(id, c, m),
        };
        de_quem_espera(o, &[id])
    })
    .unwrap_or_default();
    acordar(wakers);
}

/// Se o pedido `id` ainda está a caminho — a revogação, a suspensão, o
/// prazo e o fim de quem pediu o tiram.
fn a_caminho(id: u64) -> bool {
    se_ha_origem(|o| o.tabela.a_caminho(id)).unwrap_or(false)
}

/// Por onde o serviço fala com o par: a conexão TCP pelo gate, ou — na
/// suíte — o par de teste.
pub trait Via {
    /// Manda os bytes, inteiros.
    fn mandar(&mut self, bytes: &[u8]) -> Result<(), (Codigo, &'static str)>;
    /// O que chegou, esperando até `prazo_ms`. Vazio se nada chegou.
    fn receber(&mut self, prazo_ms: u64) -> Result<Vec<u8>, (Codigo, &'static str)>;
}

/// O par de um quadro: lê da via até um quadro inteiro.
fn proximo_quadro(
    via: &mut impl Via,
    leitor: &mut Leitor,
    guardado: &mut Vec<u8>,
) -> Result<(Tipo, Vec<u8>), (Codigo, &'static str)> {
    for _ in 0..MAIS_PASSOS {
        while !guardado.is_empty() {
            let b = guardado.remove(0);
            match leitor.empurrar(b) {
                Ok(Some((tipo, corpo))) => return Ok((tipo, corpo.to_vec())),
                Ok(None) => {}
                Err(_) => return Err((Codigo::Error, "o par mandou um quadro que nao se le")),
            }
        }
        let chegou = via.receber(PASSO_MS)?;
        if chegou.is_empty() {
            continue;
        }
        guardado.extend_from_slice(&chegou);
    }
    Err((Codigo::Error, "o par nao respondeu no prazo"))
}

/// A conversa com o par, numa via aberta: o aperto, o pedido, a resposta.
///
/// `estatica` roda o que precisa da chave privada desta ponta — a do Duke,
/// em [`crate::identidade::com_chave_do_duke`]; a cópia que o aperto guarda
/// para a resposta é apagada com ele.
pub fn conversar(
    via: &mut impl Via,
    t: &Tomado,
    epoca: [u8; 8],
    estatica: impl FnOnce(&mut dyn FnMut(&[u8; 32])) -> bool,
) -> Result<String, (Codigo, &'static str)> {
    // O que a revogação, a suspensão, o prazo ou o fim de quem pediu tirou
    // do caminho não chega ao par — nem o aperto.
    if !a_caminho(t.id) {
        return Err((Codigo::Error, "o pedido saiu do caminho"));
    }
    let efemera =
        crate::aleatorio::chave().map_err(|_| (Codigo::Error, "sem entropia para o aperto"))?;
    let carga = alloc::format!(r#"{{"epoch":"{}"}}"#, sigilo::hex_de(&epoca));
    let mut primeira = vec![0u8; sigilo::MAIOR_MENSAGEM];
    let mut escrito = None;
    let tem_chave = estatica(&mut |chave| {
        escrito = Some(
            Iniciador::novo(sigilo::PROLOGO_DO_ENLACE, chave, &t.dispositivo).escrever(
                efemera,
                carga.as_bytes(),
                &mut primeira,
            ),
        );
    });
    if !tem_chave {
        return Err((Codigo::Error, "o Duke nao tem chave"));
    }
    let (n, aguardando) = escrito
        .ok_or((Codigo::Error, "o aperto nao se escreveu"))?
        .map_err(|_| (Codigo::Error, "o aperto nao se escreveu"))?;
    let q = quadro::montar(Tipo::InicioEnlace, &primeira[..n])
        .map_err(|_| (Codigo::Error, "o aperto nao cabe num quadro"))?;
    via.mandar(&q)?;
    let mut leitor = Leitor::novo();
    let mut guardado = Vec::new();
    let (tipo, corpo) = proximo_quadro(via, &mut leitor, &mut guardado)?;
    let mut transporte = match tipo {
        Tipo::Resposta => {
            let mut lixo = vec![0u8; corpo.len()];
            aguardando
                .ler(&corpo, &mut lixo)
                .map_err(|_| {
                    (
                        Codigo::DenyNotAuthenticated,
                        "o par nao provou a chave da relacao",
                    )
                })?
                .1
        }
        Tipo::Recusa => return Err((Codigo::DenyNotAuthenticated, "o par recusou o aperto")),
        _ => return Err((Codigo::Error, "o par respondeu fora do aperto")),
    };
    // O pedido: a relação, o programa que esta ponta atesta, e a linha.
    let mut mensagem = String::new();
    {
        let mut w = JsonWriter::new(&mut mensagem);
        let _ = (|| -> fmt::Result {
            w.begin_object()?;
            w.field_str("relation", &politica::dispositivos::id_texto(&t.relacao))?;
            w.field_str("program", &sigilo::hex(&t.programa))?;
            w.key("rpc")?;
            w.raw_value(&t.linha)?;
            w.end_object()
        })();
    }
    mensagem.push('\n');
    if mensagem.len() > MAIOR_LINHA {
        return Err((Codigo::InvalidArgument, "o pedido passa do teto do enlace"));
    }
    if !a_caminho(t.id) {
        return Err((Codigo::Error, "o pedido saiu do caminho"));
    }
    mandar_cifrado(via, &mut transporte, mensagem.as_bytes())?;
    // A resposta: quadros de dados até a quebra de linha.
    let mut texto = Vec::new();
    loop {
        let (tipo, corpo) = proximo_quadro(via, &mut leitor, &mut guardado)?;
        match tipo {
            Tipo::Dados => {
                let mut claro = vec![0u8; corpo.len()];
                let n = transporte
                    .decifrar(&corpo, &mut claro)
                    .map_err(|_| (Codigo::Error, "a resposta do par nao abriu"))?;
                texto.extend_from_slice(&claro[..n]);
                politica::sigiloso::zerar(&mut claro);
                if texto.len() > MAIOR_LINHA {
                    return Err((Codigo::Error, "a resposta do par passa do teto"));
                }
                if texto.last() == Some(&b'\n') {
                    texto.pop();
                    return String::from_utf8(texto)
                        .map_err(|_| (Codigo::Error, "a resposta do par nao e texto"));
                }
            }
            Tipo::Recusa => return Err((Codigo::DenyNotAuthenticated, "o par encerrou o enlace")),
            _ => return Err((Codigo::Error, "o par mandou um quadro fora de ordem")),
        }
    }
}

/// Cifra e manda `texto` em quadros de dados.
fn mandar_cifrado(
    via: &mut impl Via,
    transporte: &mut Transporte,
    texto: &[u8],
) -> Result<(), (Codigo, &'static str)> {
    let mut cifrado = vec![0u8; sigilo::MAIOR_MENSAGEM];
    for pedaco in texto.chunks(Transporte::MAIOR_CLARO) {
        let n = transporte
            .cifrar(pedaco, &mut cifrado)
            .map_err(|_| (Codigo::Error, "o pedido nao se cifrou"))?;
        let q = quadro::montar(Tipo::Dados, &cifrado[..n])
            .map_err(|_| (Codigo::Error, "o pedido nao cabe num quadro"))?;
        via.mandar(&q)?;
    }
    Ok(())
}

/// Leva o pedido `t` ao par e conclui: a relação ainda ativa, o
/// dispositivo não suspenso, o endereço da relação, a conexão pelo gate, a
/// conversa, o fecho.
pub fn levar(t: &Tomado, quem: Chamador) {
    let r = levar_pela_rede(t, quem);
    concluir(t.id, r);
}

fn levar_pela_rede(t: &Tomado, quem: Chamador) -> Result<String, (Codigo, &'static str)> {
    let (_, relacao) = crate::dispositivos::relacao(&t.dispositivo, &t.relacao).ok_or((
        Codigo::DenyNotAuthenticated,
        "a relacao nao esta mais ativa",
    ))?;
    if crate::contencao::dispositivo_suspenso(&t.dispositivo) {
        return Err((Codigo::DenyCredential, "dispositivo suspenso"));
    }
    let endereco = relacao
        .endereco
        .ok_or((Codigo::Error, "a relacao nao tem endereco"))?;
    let mut via = ViaTcp::conectar(quem, &endereco)?;
    let epoca = epoca();
    let r = conversar(&mut via, t, epoca, |f| {
        crate::identidade::com_chave_do_duke(|k| f(k)).is_some()
    });
    via.fechar();
    r
}

/// Pede um comando ao gate, como `quem`, com o anexo se vier um. `Ok` com
/// o resultado; `Err` com o envelope inteiro da recusa.
fn pedir_ao_gate(
    quem: Chamador,
    metodo: &str,
    params: &str,
    anexo: Option<&[u8]>,
) -> Result<Vec<u8>, ()> {
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
        Some(r) if r.member("error").is_none() => Ok(r.0.to_vec()),
        _ => Err(()),
    }
}

/// A conexão TCP com o par, pelo gate: cada passo é um pedido do serviço,
/// decidido e gravado.
struct ViaTcp {
    quem: Chamador,
    conexao: u64,
}

impl ViaTcp {
    fn conectar(quem: Chamador, endereco: &str) -> Result<ViaTcp, (Codigo, &'static str)> {
        let params = alloc::format!(r#"{{"to":"{endereco}"}}"#);
        let r = pedir_ao_gate(quem, "net.connect", &params, None).map_err(|_| {
            (
                Codigo::DenyPermission,
                "o gate nao deixou o servico conectar ao par",
            )
        })?;
        let conexao = Json(&r)
            .member("connection")
            .and_then(|c| c.as_u64())
            .ok_or((Codigo::Error, "a conexao com o par nao abriu"))?;
        Ok(ViaTcp { quem, conexao })
    }

    fn fechar(&mut self) {
        let params = alloc::format!(r#"{{"connection":{}}}"#, self.conexao);
        let _ = pedir_ao_gate(self.quem, "net.close", &params, None);
    }
}

impl Via for ViaTcp {
    fn mandar(&mut self, bytes: &[u8]) -> Result<(), (Codigo, &'static str)> {
        let mut falta = bytes;
        for _ in 0..MAIS_PASSOS {
            if falta.is_empty() {
                return Ok(());
            }
            let params = alloc::format!(
                r#"{{"connection":{},"attachment":{},"wait":{PASSO_MS}}}"#,
                self.conexao,
                falta.len()
            );
            let r = pedir_ao_gate(self.quem, "net.send", &params, Some(falta))
                .map_err(|_| (Codigo::Error, "o gate recusou o envio ao par"))?;
            let r = Json(&r);
            if let Some(m) = r.member("error").and_then(|e| e.as_str()) {
                let _ = m;
                return Err((Codigo::Error, "a conexao com o par recusou o envio"));
            }
            let saiu = r.member("sent").and_then(|s| s.as_u64()).unwrap_or(0) as usize;
            falta = &falta[saiu.min(falta.len())..];
        }
        if falta.is_empty() {
            Ok(())
        } else {
            Err((Codigo::Error, "o par nao leu o que se mandou"))
        }
    }

    fn receber(&mut self, prazo_ms: u64) -> Result<Vec<u8>, (Codigo, &'static str)> {
        let params = alloc::format!(
            r#"{{"connection":{},"max":{},"wait":{prazo_ms}}}"#,
            self.conexao,
            crate::rede::pilha::BUFFER_DA_CONEXAO
        );
        let r = pedir_ao_gate(self.quem, "net.recv", &params, None)
            .map_err(|_| (Codigo::Error, "o gate recusou a leitura do par"))?;
        let r = Json(&r);
        let estado = r.member("state").and_then(|s| s.as_str()).unwrap_or("");
        let conteudo = r.member("content");
        let bytes = match (r.member("encoding").and_then(|e| e.as_str()), conteudo) {
            (Some("base64"), Some(c)) => c
                .as_str()
                .and_then(crate::hora::servico::de_base64)
                .ok_or((Codigo::Error, "a leitura do par nao se le"))?,
            (Some("utf-8"), Some(c)) => {
                let mut destino = vec![0u8; c.0.len()];
                c.desescapar_em(&mut destino)
                    .map(|t| t.as_bytes().to_vec())
                    .ok_or((Codigo::Error, "a leitura do par nao se le"))?
            }
            _ => Vec::new(),
        };
        if bytes.is_empty() && matches!(estado, "closed" | "closing") {
            return Err((Codigo::Error, "o par fechou a conexao"));
        }
        Ok(bytes)
    }
}

/// O serviço de enlace, como o gate o vê: um pedido pelo fio que pede,
/// com a autoridade do serviço — e só ela —, e nenhuma imagem a atenuar.
fn chamador() -> Chamador {
    Chamador::Processo {
        fio: crate::fios::id_atual(),
        autoridade: Autoridade::Servico(Servico::Enlace),
        programa: Programa::Kernel,
    }
}

/// Liga o serviço de enlace: o fio, com a autoridade do serviço.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
pub fn iniciar() {
    match crate::fios::criar_como("enlace", laco, 0, Autoridade::Servico(Servico::Enlace)) {
        Ok(id) => crate::log_info!("enlace", "servico de enlace no fio {}", id.numero()),
        Err(motivo) => {
            crate::log_error!("enlace", "o fio do servico de enlace nao subiu: {}", motivo)
        }
    }
}

/// O fio do serviço: um pedido de cada vez, e bloqueado até o próximo.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
extern "C" fn laco(_argumento: u64) -> ! {
    loop {
        match tomar() {
            Some(t) => levar(&t, chamador()),
            None => crate::fios::bloquear_em(Fila),
        }
    }
}

/// A espera do serviço por um pedido na fila. A conferência e o registro
/// do waker sob a mesma trava com que o pedido entra.
struct Fila;

impl core::future::Future for Fila {
    type Output = ();

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> core::task::Poll<()> {
        let pronto = com_origem(|o| {
            if o.tabela
                .pedidos()
                .iter()
                .any(|p| p.estado == politica::enlace::Estado::NaFila)
            {
                return true;
            }
            o.servico = Some(cx.waker().clone());
            false
        });
        if pronto {
            core::task::Poll::Ready(())
        } else {
            core::task::Poll::Pending
        }
    }
}

// ---------------------------------------------------------------------
// O destino: o respondedor das vagas do enlace.
// ---------------------------------------------------------------------

/// Uma sessão de enlace aberta numa vaga, para a revogação a achar.
#[derive(Clone, Copy, Debug, Default)]
struct Aberta {
    geracao: u64,
    dispositivo: Option<[u8; 32]>,
    confirmada: bool,
    /// A revogação ou a suspensão a encerrou por fora: a recusa já foi.
    avisada: bool,
}

static SESSOES: Mutex<[Aberta; crate::rede::canal::VAGAS_DO_ENLACE as usize]> = Mutex::new(
    [Aberta {
        geracao: 0,
        dispositivo: None,
        confirmada: false,
        avisada: false,
    }; crate::rede::canal::VAGAS_DO_ENLACE as usize],
);

fn com_sessao<R>(v: u8, f: impl FnOnce(&mut Aberta) -> R) -> Option<R> {
    let i = usize::from(v.checked_sub(crate::rede::canal::VAGAS + 1)?);
    crate::arch::sem_interrupcoes(|| SESSOES.lock().get_mut(i).map(f))
}

/// O que o respondedor precisa da vaga: mandar, confirmar a chave,
/// encerrar e dizer o par.
pub trait Ponta {
    /// Manda um quadro inteiro. Falso se não saiu.
    fn mandar(&mut self, quadro: &[u8]) -> bool;
    /// A chave do aperto se confirmou: o prazo do aperto para de correr.
    fn confirmar(&mut self, chave: [u8; 32]);
    /// A sessão acabou por dentro: a conexão fecha depois da saída.
    fn encerrar(&mut self);
    /// O par, como a auditoria o escreve.
    fn par(&self) -> String;
}

/// A conexão `geracao` da vaga `v`.
pub struct PontaDaVaga {
    pub v: u8,
    pub geracao: u64,
}

impl Ponta for PontaDaVaga {
    fn mandar(&mut self, q: &[u8]) -> bool {
        crate::rede::canal::enviar_na_conexao(self.v, self.geracao, q)
    }

    fn confirmar(&mut self, chave: [u8; 32]) {
        crate::rede::canal::identificar(self.v, self.geracao, chave);
    }

    fn encerrar(&mut self) {
        crate::rede::canal::encerrar(self.v, self.geracao);
    }

    fn par(&self) -> String {
        crate::rede::canal::remoto_da_conexao(self.v, self.geracao)
            .map_or_else(|| String::from("tcp"), crate::rede::canal::texto_do_par)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EstadoDoLado {
    Aguardando,
    Estabelecida,
    Encerrada,
}

/// O lado de dentro de uma vaga do enlace: remonta os quadros, faz o aperto
/// com o registro de dispositivos, decifra e leva cada pedido ao gate.
pub struct Lado {
    v: u8,
    geracao: u64,
    leitor: Leitor,
    estado: EstadoDoLado,
    transporte: Option<Transporte>,
    dispositivo: [u8; 32],
    nome: String,
    epoca: [u8; 8],
    confirmada: bool,
    texto: Vec<u8>,
}

impl Lado {
    /// O lado da vaga `v`, na conexão `geracao`.
    pub fn nova(v: u8, geracao: u64) -> Lado {
        Lado {
            v,
            geracao,
            leitor: Leitor::novo(),
            estado: EstadoDoLado::Aguardando,
            transporte: None,
            dispositivo: [0; 32],
            nome: String::new(),
            epoca: [0; 8],
            confirmada: false,
            texto: Vec::new(),
        }
    }

    /// A conexão de agora na vaga. Uma nova recomeça o lado: o que havia
    /// era de quem saiu.
    pub fn conexao(&mut self, geracao: u64) {
        if geracao == self.geracao {
            return;
        }
        *self = Lado::nova(self.v, geracao);
        // A sessão da conexão que acabou, se o coletor ainda não a tirou: um
        // aperto respondido e nunca confirmado vai à auditoria — por quem a
        // tirar primeiro, uma vez.
        let saiu = com_sessao(self.v, |s| {
            core::mem::replace(
                s,
                Aberta {
                    geracao,
                    ..Aberta::default()
                },
            )
        });
        if let Some(Aberta {
            dispositivo: Some(k),
            confirmada: false,
            avisada: false,
            ..
        }) = saiu
        {
            auditar_aperto(
                Some(k),
                "",
                Codigo::DenyNotAuthenticated,
                "a chave do aperto nao foi confirmada: a conexao acabou",
                "tcp",
            );
        }
    }

    /// Se a sessão terminou: o lado não faz mais nada até a conexão mudar.
    #[cfg(feature = "modo-teste")]
    pub fn encerrada(&self) -> bool {
        self.estado == EstadoDoLado::Encerrada
    }

    /// Recebe um byte cru da vaga.
    pub fn receber(&mut self, byte: u8, ponta: &mut impl Ponta) {
        if self.estado == EstadoDoLado::Encerrada {
            return;
        }
        // Encerrada por fora — a revogação, a suspensão: a recusa já saiu.
        if com_sessao(self.v, |s| s.geracao == self.geracao && s.avisada).unwrap_or(false) {
            self.estado = EstadoDoLado::Encerrada;
            return;
        }
        let (tipo, corpo) = match self.leitor.empurrar(byte) {
            Ok(Some((tipo, corpo))) => (tipo, corpo.to_vec()),
            Ok(None) => return,
            Err(e) => return self.encerrar(ponta, e.motivo()),
        };
        match (self.estado, tipo) {
            (EstadoDoLado::Aguardando, Tipo::InicioEnlace) => self.apertar(&corpo, ponta),
            (EstadoDoLado::Estabelecida, Tipo::Dados) => self.decifrar(&corpo, ponta),
            _ => self.encerrar(ponta, "quadro fora de ordem"),
        }
    }

    /// Encerra a sessão: a recusa em claro, a conexão fecha. Um aperto que
    /// não terminou — nunca veio, ou não confirmou — vai à auditoria como
    /// recusa.
    fn encerrar(&mut self, ponta: &mut impl Ponta, motivo: &str) {
        if self.estado == EstadoDoLado::Encerrada {
            return;
        }
        if !self.confirmada {
            let chave = (self.estado == EstadoDoLado::Estabelecida).then_some(self.dispositivo);
            auditar_aperto(
                chave,
                &self.nome,
                Codigo::DenyNotAuthenticated,
                motivo,
                &ponta.par(),
            );
        }
        crate::log_warn!("enlace", "vaga {}: {}; enlace encerrado", self.v, motivo);
        self.terminar(ponta, motivo);
    }

    /// O fim, sem auditoria.
    fn terminar(&mut self, ponta: &mut impl Ponta, motivo: &str) {
        self.estado = EstadoDoLado::Encerrada;
        self.transporte = None;
        if let Ok(q) = quadro::montar(Tipo::Recusa, motivo.as_bytes()) {
            ponta.mandar(&q);
        }
        ponta.encerrar();
        com_sessao(self.v, |s| {
            if s.geracao == self.geracao {
                s.dispositivo = None;
            }
        });
    }

    /// Recusa o aperto: grava, e encerra.
    fn recusar(
        &mut self,
        ponta: &mut impl Ponta,
        chave: Option<[u8; 32]>,
        codigo: Codigo,
        motivo: &str,
    ) {
        auditar_aperto(chave, "", codigo, motivo, &ponta.par());
        self.terminar(ponta, motivo);
    }

    /// O aperto: a primeira mensagem do IK com o prólogo do enlace, a chave
    /// no registro de dispositivos, a contenção, a época, a resposta.
    fn apertar(&mut self, mensagem: &[u8], ponta: &mut impl Ponta) {
        if !crate::autorizacao::permitir_aperto_do_enlace(self.v) {
            return self.terminar(ponta, "apertos demais; espere a janela");
        }
        if crate::energia::pedida().is_some() {
            return self.recusar(ponta, None, Codigo::Conflict, "a maquina esta desligando");
        }
        let mut carga = vec![0u8; sigilo::MAIOR_MENSAGEM];
        let lido = crate::identidade::com_chave_do_duke(|chave| {
            Respondedor::novo(sigilo::PROLOGO_DO_ENLACE, chave).ler(mensagem, &mut carga)
        });
        let (n, recebido) = match lido {
            None => return self.recusar(ponta, None, Codigo::Error, "o Duke nao tem chave"),
            Some(Err(e)) => {
                return self.recusar(ponta, None, Codigo::DenyNotAuthenticated, e.motivo());
            }
            Some(Ok(r)) => r,
        };
        // Autenticado não é relacionado: a chave provou ser de quem diz, e o
        // registro de dispositivos diz se ela tem relação aqui.
        let chave = recebido.remota();
        let Some(d) = crate::dispositivos::dispositivo(&chave) else {
            return self.recusar(
                ponta,
                Some(chave),
                Codigo::DenyNotAuthenticated,
                "chave fora do registro de dispositivos",
            );
        };
        if crate::contencao::dispositivo_suspenso(&chave) {
            return self.recusar(
                ponta,
                Some(chave),
                Codigo::DenyCredential,
                "dispositivo suspenso",
            );
        }
        let epoca = Json(&carga[..n])
            .member("epoch")
            .and_then(|v| v.as_str())
            .and_then(sigilo::de_hex_fixo::<8>);
        let Some(epoca) = epoca else {
            return self.recusar(
                ponta,
                Some(chave),
                Codigo::InvalidArgument,
                "o aperto nao diz a epoca da origem",
            );
        };
        let Ok(efemera) = crate::aleatorio::chave() else {
            return self.recusar(
                ponta,
                Some(chave),
                Codigo::Error,
                "sem entropia para o aperto",
            );
        };
        let mut resposta = vec![0u8; sigilo::MAIOR_MENSAGEM];
        let (n, transporte) = match recebido.escrever(efemera, b"{}", &mut resposta) {
            Ok(r) => r,
            Err(e) => return self.recusar(ponta, Some(chave), Codigo::Error, e.motivo()),
        };
        let saiu = quadro::montar(Tipo::Resposta, &resposta[..n]).is_ok_and(|q| ponta.mandar(&q));
        if !saiu {
            return self.recusar(
                ponta,
                Some(chave),
                Codigo::Error,
                "a resposta do aperto nao saiu",
            );
        }
        self.transporte = Some(transporte);
        self.dispositivo = chave;
        self.nome = d.nome;
        self.epoca = epoca;
        self.estado = EstadoDoLado::Estabelecida;
        com_sessao(self.v, |s| {
            *s = Aberta {
                geracao: self.geracao,
                dispositivo: Some(chave),
                confirmada: false,
                avisada: false,
            }
        });
    }

    /// Um quadro de dados: o primeiro que abre confirma a chave; cada linha
    /// que se completa é um pedido.
    fn decifrar(&mut self, mensagem: &[u8], ponta: &mut impl Ponta) {
        let Some(transporte) = self.transporte.as_mut() else {
            return self.encerrar(ponta, "sessao sem transporte");
        };
        let mut claro = vec![0u8; mensagem.len()];
        let n = match transporte.decifrar(mensagem, &mut claro) {
            Ok(n) => n,
            Err(e) => return self.encerrar(ponta, e.motivo()),
        };
        if !self.confirmada {
            self.confirmada = true;
            ponta.confirmar(self.dispositivo);
            com_sessao(self.v, |s| {
                if s.geracao == self.geracao {
                    s.confirmada = true;
                }
            });
            auditar_aperto(
                Some(self.dispositivo),
                &self.nome,
                Codigo::Allow,
                "aperto completo",
                &ponta.par(),
            );
            crate::log_info!(
                "enlace",
                "vaga {}: {} entrou ({})",
                self.v,
                self.nome,
                crate::identidade::impressao(&self.dispositivo)
            );
        }
        self.texto.extend_from_slice(&claro[..n]);
        politica::sigiloso::zerar(&mut claro);
        if self.texto.len() > MAIOR_LINHA {
            return self.encerrar(ponta, "pedido grande demais");
        }
        while let Some(fim) = self.texto.iter().position(|&b| b == b'\n') {
            let linha: Vec<u8> = self.texto.drain(..=fim).collect();
            self.atender(&linha[..fim], ponta);
            if self.estado != EstadoDoLado::Estabelecida {
                return;
            }
        }
    }

    /// Um pedido: a relação, o programa atestado e a linha, que vai ao gate
    /// como o dispositivo, por ela.
    fn atender(&mut self, linha: &[u8], ponta: &mut impl Ponta) {
        let m = Json(linha);
        let relacao = m
            .member("relation")
            .and_then(|v| v.as_str())
            .and_then(politica::dispositivos::ler_id);
        let programa = m
            .member("program")
            .and_then(|v| v.as_str())
            .and_then(sigilo::de_hex);
        let rpc = m.member("rpc").filter(|r| r.0.first() == Some(&b'{'));
        let (Some(relacao), Some(programa), Some(rpc)) = (relacao, programa, rpc) else {
            return self.encerrar(ponta, "pedido fora do protocolo do enlace");
        };
        let chamador = Chamador::Remoto {
            dispositivo: self.dispositivo,
            relacao,
            epoca: self.epoca,
            programa,
        };
        let resposta = crate::nativo::responder_pelo_kernel(chamador, rpc.0);
        let mut texto = resposta.como_bytes().to_vec();
        texto.push(b'\n');
        let Some(transporte) = self.transporte.as_mut() else {
            return self.encerrar(ponta, "sessao sem transporte");
        };
        let mut cifrado = vec![0u8; sigilo::MAIOR_MENSAGEM];
        for pedaco in texto.chunks(Transporte::MAIOR_CLARO) {
            let saiu = match transporte.cifrar(pedaco, &mut cifrado) {
                Ok(n) => quadro::montar(Tipo::Dados, &cifrado[..n]).is_ok_and(|q| ponta.mandar(&q)),
                Err(_) => false,
            };
            if !saiu {
                return self.encerrar(ponta, "a resposta nao saiu inteira");
            }
        }
    }
}

/// Grava um aperto de enlace: o que entrou, com o nome do dispositivo, e o
/// recusado, com a chave alegada — e o par.
fn auditar_aperto(chave: Option<[u8; 32]>, nome: &str, codigo: Codigo, motivo: &str, par: &str) {
    let detalhe = alloc::format!("{motivo} ({par})");
    crate::autorizacao::auditar_aperto_do_enlace(chave, nome, codigo, &detalhe);
}

/// A tarefa de uma vaga do enlace: os bytes da conexão, para o lado dela.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
pub async fn atender(v: u8) {
    let mut lado = Lado::nova(v, crate::rede::canal::geracao(v));
    loop {
        let (byte, geracao) = crate::rede::canal::proximo_byte(v).await;
        lado.conexao(geracao);
        lado.receber(byte, &mut PontaDaVaga { v, geracao });
    }
}

/// O desfecho de uma conexão numa vaga do enlace — ver
/// [`crate::rede::canal`]: quem chama é o coletor, fora das travas.
pub fn desfecho_da_vaga(v: u8, d: crate::rede::canal::Desfecho) {
    use crate::rede::canal::{Desfecho as D, texto_do_par};
    match d {
        D::Aceita { remoto, geracao } => {
            crate::log_info!(
                "enlace",
                "vaga {}: conexao {} de {}",
                v,
                geracao,
                texto_do_par(remoto)
            );
        }
        D::Acabou { geracao } => {
            let saiu =
                com_sessao(v, |s| (s.geracao == geracao).then(|| core::mem::take(s))).flatten();
            // Um aperto respondido e nunca confirmado: recusado.
            if let Some(Aberta {
                dispositivo: Some(k),
                confirmada: false,
                avisada: false,
                ..
            }) = saiu
            {
                auditar_aperto(
                    Some(k),
                    "",
                    Codigo::DenyNotAuthenticated,
                    "a chave do aperto nao foi confirmada: a conexao acabou",
                    "tcp",
                );
            }
        }
        D::Expirou { remoto, geracao } => {
            let saiu =
                com_sessao(v, |s| (s.geracao == geracao).then(|| core::mem::take(s))).flatten();
            let par = texto_do_par(remoto);
            match saiu {
                Some(Aberta {
                    dispositivo: Some(k),
                    confirmada: false,
                    ..
                }) => auditar_aperto(
                    Some(k),
                    "",
                    Codigo::DenyNotAuthenticated,
                    "a chave do aperto nao foi confirmada no prazo",
                    &par,
                ),
                Some(Aberta {
                    confirmada: true, ..
                }) => {}
                _ => {
                    if crate::autorizacao::permitir_aperto_do_enlace(v) {
                        auditar_aperto(
                            None,
                            "",
                            Codigo::DenyNotAuthenticated,
                            "o aperto do enlace nao veio no prazo",
                            &par,
                        );
                    }
                }
            }
        }
    }
}

/// O dispositivo saiu — revogado, ou suspenso —: as sessões de enlace dele
/// caem na hora, com a recusa em claro; as entregas vivas que ele mandou à
/// malha daqui são anuladas; os pedidos daqui a ele falham, e quem
/// esperava acorda.
pub fn dispositivo_saiu(chave: &[u8; 32], codigo: Codigo, motivo: &'static str) {
    let mut derrubar = Vec::new();
    for v in (crate::rede::canal::VAGAS + 1)..=crate::rede::canal::TODAS {
        let alvo = com_sessao(v, |s| {
            if s.dispositivo == Some(*chave) && !s.avisada {
                s.avisada = true;
                s.dispositivo = None;
                Some(s.geracao)
            } else {
                None
            }
        })
        .flatten();
        if let Some(g) = alvo {
            derrubar.push((v, g));
        }
    }
    for (v, g) in derrubar {
        if let Ok(q) = quadro::montar(Tipo::Recusa, motivo.as_bytes()) {
            crate::rede::canal::enviar_na_conexao(v, g, &q);
        }
        crate::rede::canal::encerrar(v, g);
        crate::log_warn!("enlace", "vaga {}: {}; enlace encerrado", v, motivo);
    }
    crate::malha::anular_dispositivo(chave, motivo);
    let wakers = se_ha_origem(|o| {
        let falharam = o.tabela.anular_dispositivo(chave, codigo, motivo);
        de_quem_espera(o, &falharam)
    })
    .unwrap_or_default();
    acordar(wakers);
}

/// O dispositivo foi revogado: além do que [`dispositivo_saiu`] faz, a
/// contagem de nonces dele sai — a chave não volta.
pub fn dispositivo_revogado(chave: &[u8; 32]) {
    dispositivo_saiu(chave, Codigo::DenyNotAuthenticated, "dispositivo revogado");
    se_ha_origem(|o| o.tabela.esquecer_dispositivo(chave));
}

/// Quantas sessões de enlace estão confirmadas, e de quem — para o
/// relatório.
pub fn sessoes() -> Vec<(u8, [u8; 32], bool)> {
    let mut v = Vec::new();
    for vaga in (crate::rede::canal::VAGAS + 1)..=crate::rede::canal::TODAS {
        if let Some((Some(k), c)) = com_sessao(vaga, |s| (s.dispositivo, s.confirmada)) {
            v.push((vaga, k, c));
        }
    }
    v
}

/// Quantos pedidos esperam o par — para o relatório.
pub fn pedidos() -> usize {
    se_ha_origem(|o| o.tabela.quantos()).unwrap_or(0)
}

/// Só para a suíte: leva o pedido `t` ao par pela via de teste — a mesma
/// conversa do serviço, com a chave do Duke —, e conclui.
#[cfg(feature = "modo-teste")]
pub fn levar_pela_via_de_teste(t: &Tomado, via: &mut impl Via) {
    let r = conversar(via, t, epoca(), |f| {
        crate::identidade::com_chave_do_duke(|k| f(k)).is_some()
    });
    concluir(t.id, r);
}

/// Para o invariante da suíte: a tabela nunca quebra as regras dela.
#[cfg(feature = "modo-teste")]
pub fn coerente() -> bool {
    se_ha_origem(|o| o.tabela.coerente()).unwrap_or(true)
}

/// Só para a suíte: a tabela vazia e as sessões esquecidas — cada caso
/// começa do zero. A época continua.
#[cfg(feature = "modo-teste")]
pub fn esvaziar_de_teste() {
    let wakers = se_ha_origem(|o| {
        let epoca = o.epoca;
        let w: Vec<Waker> = o.esperas.values_mut().filter_map(Option::take).collect();
        *o = Origem {
            tabela: Enlace::nova(),
            epoca,
            esperas: BTreeMap::new(),
            servico: None,
        };
        w
    })
    .unwrap_or_default();
    acordar(wakers);
    crate::arch::sem_interrupcoes(|| {
        *SESSOES.lock() = [Aberta::default(); crate::rede::canal::VAGAS_DO_ENLACE as usize]
    });
}

/// Destrava a tabela e as sessões, para o caminho de falha fatal.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        ORIGEM.force_unlock();
        SESSOES.force_unlock();
    }
}
