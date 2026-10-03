//! As mensagens entre titulares, no kernel: um recurso do sistema, e não um
//! canal privilegiado.
//!
//! A conta — caixas, estados, cotas, nonces — é a de
//! [`politica::mensagens`]. Aqui ela ganha o relógio, a identidade de quem
//! pede, o destinatário resolvido e a auditoria. Nenhum caminho daqui
//! contorna a decisão:
//!
//! - **Mandar** é `message.send`, que passa por
//!   [`crate::autorizacao::autorizar`]: o destinatário é resolvido **lá**, e
//!   o papel dele é o recurso da decisão — `papel:<nome>`, contra o alcance
//!   enumerado do papel de quem pede. O handler recebe pela licença o
//!   destinatário que foi decidido, e não o resolve de novo.
//! - **Quem manda** é derivado da sessão autenticada — a chave do aperto, a
//!   sessão de pessoa, a serial —, por [`Remetente::da_sessao`]. Nunca vem
//!   dos parâmetros: o comando não declara `from`, e a validação recusa o
//!   campo.
//! - **Ler, confirmar, consultar e cancelar** são sempre sobre a caixa e as
//!   mensagens do titular da sessão. A caixa não é parâmetro.
//! - **O administrador** não abre sessão: manda, lê e confirma só por
//!   operação administrativa, com prova — [`Remetente::do_administrador`],
//!   chamado só por [`crate::agent::administracao`].
//! - **A revogação** de uma chave ou de uma pessoa anula, na hora, as
//!   mensagens vivas que ela mandou e as que ia receber.
//! - **O corpo não é interpretado.** Vai para a caixa e volta para quem lê;
//!   a auditoria grava o resumo dos parâmetros do pedido, nunca o texto.
//!
//! # O journal
//!
//! Cada mudança — a mensagem aceita, a entregue, a confirmada, a vencida,
//! a anulada — vai para o journal **antes** da resposta: a operação muda a
//! tabela e grava o registro do que mudou com a ordem das gravações na mão
//! ([`crate::persistencia::em_ordem`]), e só então responde. A resposta diz
//! `durable: true` quando o registro está escrito, descarregado e ancorado;
//! uma operação respondida assim não volta atrás num reboot. Sem a
//! persistência — sem TPM, journal recusado, uma gravação que falhou —, a
//! mensagem continua, só em memória, e a resposta diz `durable: false` e
//! por quê.
//!
//! O que fica no journal são resultados: a mensagem criada, com o corpo
//! (cifrado com o registro), e cada transição, com a versão. O boot os
//! repõe na ordem ([`restaurar`] e [`aplicar`]). Os prazos são do tempo
//! lógico ([`crate::persistencia::agora_ms`]), que não volta num reboot, e
//! a época dos ids é a da instalação: um id continua sendo o mesmo depois
//! de um boot.
//!
//! As janelas de nonces não vão: são de um canal — uma sessão, ou os
//! desafios de um administrador —, e nenhum deles atravessa um boot. Um
//! quadro de uma sessão não se repete em outra, que tem outras chaves; uma
//! operação administrativa precisa de um desafio deste boot.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use politica::Codigo;
use politica::mensagens::{Caixas, Canal, Dono, Enviada, Estado, Lida, Recusa, Transicao};
use spin::Mutex;

use crate::autorizacao::{AtorDeMensagem, Autoridade};

struct Tabela {
    caixas: Caixas,
    /// A da instalação, com a persistência disponível: os ids continuam de
    /// um boot para o outro. Sem ela, sorteada no primeiro uso: um id de
    /// outro boot não é confundido com um deste.
    epoca: [u8; 8],
}

/// Se o que uma operação mudou está no journal: `Ok` — escrito,
/// descarregado e ancorado, ou nada mudou —, ou o motivo de valer só em
/// memória.
pub type Duravel = Result<(), &'static str>;

/// O que uma leitura devolve: a época e as mensagens, com o id de cada uma.
pub type Leitura = (String, Vec<(String, Lida)>);

/// Uma viva campo a campo, para a suíte.
#[cfg(feature = "modo-teste")]
pub type Retrato = (u64, Dono, Dono, String, u64, u64, Estado, u64);

/// Grava o que a operação anotou. Chamada com a ordem na mão.
fn gravar_o_que_mudou() -> Duravel {
    crate::persistencia::gravar_mensagens()
}

/// Anota as transições para o próximo registro.
fn anotar(ts: &[Transicao]) {
    crate::persistencia::anotar_transicoes(ts);
}

static TABELA: Mutex<Option<Tabela>> = Mutex::new(None);

fn com_tabela<R>(f: impl FnOnce(&mut Tabela) -> R) -> R {
    // A época sai do gerador antes da trava: sortear dentro dela seria
    // pedir outra trava com esta na mão.
    let precisa = crate::arch::sem_interrupcoes(|| TABELA.lock().is_none());
    let nova = precisa.then(|| {
        let mut epoca = [0u8; 8];
        if crate::aleatorio::preencher(&mut epoca).is_err() {
            // Sem entropia, o relógio: a época só distingue boots, e não
            // protege nada que precise ser imprevisível.
            epoca = crate::tempo::uptime_ms().to_le_bytes();
        }
        Tabela {
            caixas: Caixas::nova(),
            epoca,
        }
    });
    crate::arch::sem_interrupcoes(|| {
        let mut t = TABELA.lock();
        if t.is_none() {
            *t = nova;
        }
        f(t.as_mut().expect("a tabela acabou de ser criada"))
    })
}

/// Repõe uma mensagem criada, do journal, no boot.
pub fn restaurar(g: politica::mensagens::Gravada) -> Result<(), &'static str> {
    com_tabela(|t| t.caixas.restaurar(g))
}

/// Repõe uma transição, do journal, no boot.
pub fn aplicar(id: u64, estado: Estado, versao: u64) -> Result<(), &'static str> {
    com_tabela(|t| t.caixas.aplicar(id, estado, versao))
}

/// O journal foi confirmado: a tabela reposta vale, na época da instalação.
pub fn adotar(epoca: [u8; 8]) {
    com_tabela(|t| t.epoca = epoca);
}

/// O journal não vale — recusado, ou sem âncora: o que se repôs dele sai, e
/// a tabela recomeça vazia, numa época sorteada.
pub fn descartar() {
    crate::arch::sem_interrupcoes(|| *TABELA.lock() = None);
}

/// O id de uma mensagem como o relatório o escreve: a época e o número.
fn id_texto(epoca: &[u8; 8], n: u64) -> String {
    format!("{}:{n}", sigilo::hex_de(epoca))
}

/// O número de um id deste boot. Um id de outra época, ou malformado, não é
/// de mensagem nenhuma.
fn ler_id(epoca: &[u8; 8], texto: &str) -> Option<u64> {
    let (e, n) = texto.split_once(':')?;
    (e == sigilo::hex_de(epoca)).then_some(())?;
    n.parse().ok()
}

/// O recurso de uma mensagem na auditoria.
fn recurso(epoca: &[u8; 8], n: u64) -> String {
    format!("msg:{}", id_texto(epoca, n))
}

/// Um destinatário resolvido: o titular, o papel dele agora — o recurso da
/// decisão —, e o texto como veio no pedido.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Destino {
    pub dono: Dono,
    pub papel: String,
    pub texto: String,
}

/// Resolve o destinatário de um envio. O `Err` é o motivo exato, para a
/// auditoria — a resposta a quem pede é a mesma para todos: o inexistente,
/// o revogado e o sem papel são `DENY_RESOURCE`, sem dizer qual.
///
/// O titular é o de [`titular`]; aqui ele precisa, além de existir, ter um
/// papel — o recurso da decisão.
pub fn resolver(texto: &str) -> Result<Destino, &'static str> {
    let (dono, papel) = titular(texto)?;
    let papel = papel.ok_or("destinatario sem papel")?;
    Ok(Destino {
        dono,
        papel,
        texto: texto.to_string(),
    })
}

/// O titular de uma caixa, pelo endereço — o mesmo de um envio —, com o
/// papel dele agora, se tem. O `Err` é o motivo exato.
///
/// - `serial`: a serial;
/// - `pessoa:<16 hex>`: uma pessoa do registro, ativa;
/// - `admin:<nome>`: a chave de um administrador, com o papel dela — que a
///   política da imagem deixa só o sistema e o próprio administrador
///   alcançarem; a chave lê a caixa só pela prova;
/// - qualquer outro: o nome de um agente do registro.
///
/// Um titular revogado não tem caixa: a revogação já anulou o que ele ia
/// receber.
pub fn titular(texto: &str) -> Result<(Dono, Option<String>), &'static str> {
    if texto == "serial" {
        let papel = crate::autorizacao::com_politica(|p| p.serial().to_string());
        return Ok((Dono::Serial, Some(papel)));
    }
    if let Some(nome) = texto.strip_prefix("admin:") {
        let (chave, papel) =
            crate::identidade::administrador_por_nome(nome).ok_or("destinatario inexistente")?;
        return Ok((Dono::Administrador(chave), papel));
    }
    if texto.starts_with("pessoa:") {
        let id = sigilo::pessoas::IdPessoa::ler(texto).ok_or("destinatario inexistente")?;
        return match crate::pessoas::pessoa(id) {
            Some(p) if p.estado == sigilo::pessoas::Estado::Ativa => {
                Ok((Dono::Pessoa(id.0), Some(p.papel)))
            }
            Some(_) => Err("destinatario revogado"),
            None => Err("destinatario inexistente"),
        };
    }
    let chave = crate::identidade::chave_do_agente(texto).ok_or("destinatario inexistente")?;
    Ok((
        Dono::Agente(chave),
        crate::identidade::papel_do_agente(&chave),
    ))
}

/// Quem age sobre as mensagens: o titular, o canal dos nonces dele, e como
/// a auditoria o grava. Só se cria de dois jeitos — pela sessão autenticada
/// do pedido, ou pela prova de um administrador —, e nunca de um parâmetro.
pub struct Remetente {
    dono: Dono,
    canal: Canal,
    ator: AtorDeMensagem,
}

impl Remetente {
    /// O titular da sessão que pediu o comando que está rodando. `None` sem
    /// titular de mensagens: a autoridade local — um processo do sistema —
    /// não tem caixa, e uma sessão de pessoa que acabou também não.
    pub fn da_sessao() -> Option<Remetente> {
        let autoridade = crate::autorizacao::autoridade_atual();
        let (dono, canal) = match autoridade {
            Autoridade::Sistema => return None,
            Autoridade::Sessao {
                sessao: crate::agent::sessao::SERIAL,
                chave: None,
            } => (Dono::Serial, Canal::Sessao(crate::agent::sessao::SERIAL)),
            Autoridade::Sessao {
                sessao,
                chave: Some(k),
            } => (Dono::Agente(k), Canal::Sessao(sessao)),
            Autoridade::Sessao { chave: None, .. } => return None,
            Autoridade::Pessoa { sessao } => match crate::pessoas::sessao(sessao) {
                crate::pessoas::EstadoDaSessao::Ativa { pessoa, .. } => {
                    (Dono::Pessoa(pessoa.0), Canal::Pessoa(sessao.0))
                }
                _ => return None,
            },
        };
        Some(Remetente {
            dono,
            canal,
            ator: AtorDeMensagem::Autoridade(autoridade),
        })
    }

    /// O administrador de uma operação administrativa, com a prova já
    /// conferida. Só [`crate::agent::administracao`] chama — o `xtask
    /// invariantes` confere.
    pub fn do_administrador(chave: [u8; 32]) -> Remetente {
        let dono = Dono::Administrador(chave);
        Remetente {
            dono,
            canal: Canal::Administrador(chave),
            ator: AtorDeMensagem::Dono(dono),
        }
    }
}

/// Grava cada transição que não foi pedida por quem está agindo: a entrega
/// a quem lê, o vencimento, a anulação.
fn gravar_transicoes(epoca: &[u8; 8], ator: AtorDeMensagem, ts: &[Transicao]) {
    for t in ts {
        let (metodo, ator, detalhe) = match t.estado {
            Estado::Entregue => ("message.deliver", ator, "lida pela primeira vez"),
            Estado::Expirada => ("message.expire", AtorDeMensagem::Kernel, "o prazo venceu"),
            Estado::Confirmada => ("message.ack", ator, "confirmada por quem recebeu"),
            Estado::Cancelada => ("message.cancel", ator, "cancelada por quem mandou"),
            Estado::Anulada => ("message.void", ator, "anulada"),
            Estado::Purgada => ("message.purge", ator, "tirada por um administrador"),
            Estado::Pendente => continue,
        };
        crate::autorizacao::auditar_mensagem(
            ator,
            metodo,
            &recurso(epoca, t.id),
            Codigo::Allow,
            &format!("{detalhe}; versao {}", t.versao),
        );
    }
}

/// Manda. O destinatário é o que a decisão resolveu; o remetente, o da
/// sessão. Devolve o id e o desfecho; a recusa vai para a auditoria.
pub fn enviar(
    r: &Remetente,
    destino: &Destino,
    corpo: &str,
    nonce: u64,
    prazo_ms: Option<u64>,
) -> (Result<(String, Enviada), Recusa>, Duravel) {
    crate::persistencia::em_ordem(|| {
        let r = enviar_em_ordem(r, destino, corpo, nonce, prazo_ms);
        (r, gravar_o_que_mudou())
    })
}

fn enviar_em_ordem(
    r: &Remetente,
    destino: &Destino,
    corpo: &str,
    nonce: u64,
    prazo_ms: Option<u64>,
) -> Result<(String, Enviada), Recusa> {
    let agora = crate::persistencia::agora_ms();
    // As cotas são da política, e saem antes da trava da tabela: pedir a da
    // política com esta na mão seria uma trava dentro da outra.
    let cotas = crate::autorizacao::cotas_de_mensagens(r.ator, &destino.papel);
    let (epoca, resultado, vencidas, criada) = com_tabela(|t| {
        let (res, venc) = t.caixas.enviar(
            r.canal,
            r.dono,
            destino.dono,
            corpo,
            nonce,
            prazo_ms,
            agora,
            cotas,
        );
        // A entrada se monta aqui, com a mensagem na mão: o corpo não sai
        // da tabela para outro lugar antes de ir para o journal.
        let criada = match &res {
            Ok(e) if !e.duplicata => t
                .caixas
                .mensagem(e.id)
                .map(|m| crate::persistencia::entrada_criada(m.gravada())),
            _ => None,
        };
        (t.epoca, res, venc, criada)
    });
    anotar(&vencidas);
    if let Some(e) = criada {
        crate::persistencia::anotar(e);
    }
    gravar_transicoes(&epoca, r.ator, &vencidas);
    match resultado {
        Ok(e) => {
            let detalhe = if e.duplicata {
                "reenvio do mesmo pedido: o mesmo id, nada criado"
            } else {
                "aceita, pendente"
            };
            crate::autorizacao::auditar_mensagem(
                r.ator,
                "message.send",
                &recurso(&epoca, e.id),
                Codigo::Allow,
                detalhe,
            );
            Ok((id_texto(&epoca, e.id), e))
        }
        Err(recusa) => {
            crate::autorizacao::auditar_mensagem(
                r.ator,
                "message.send",
                &destino.texto,
                recusa.codigo(),
                recusa.motivo(),
            );
            Err(recusa)
        }
    }
}

/// Lê a própria caixa, a partir do id `apos`. Não consome; a primeira
/// leitura de cada uma vai para a auditoria. O `Err` é um `apos` que não é
/// id deste boot.
pub fn ler(r: &Remetente, apos: Option<&str>, max: usize) -> (Result<Leitura, Recusa>, Duravel) {
    crate::persistencia::em_ordem(|| {
        let r = ler_em_ordem(r, apos, max);
        (r, gravar_o_que_mudou())
    })
}

fn ler_em_ordem(r: &Remetente, apos: Option<&str>, max: usize) -> Result<Leitura, Recusa> {
    let agora = crate::persistencia::agora_ms();
    let (epoca, res) = com_tabela(|t| {
        let apos = match apos {
            None => Some(0),
            Some(texto) => ler_id(&t.epoca, texto),
        };
        let res = apos.map(|apos| t.caixas.ler(r.dono, apos, max, agora));
        (t.epoca, res)
    });
    let Some((lidas, transicoes)) = res else {
        return Err(Recusa::Desconhecida);
    };
    // A entrega também vai para o journal antes da resposta: uma mensagem
    // que alguém já leu não volta a pendente — e cancelável — num boot.
    anotar(&transicoes);
    gravar_transicoes(&epoca, r.ator, &transicoes);
    let lidas = lidas
        .into_iter()
        .map(|l| (id_texto(&epoca, l.id), l))
        .collect();
    Ok((sigilo::hex_de(&epoca), lidas))
}

/// Uma operação sobre uma mensagem pelo id: confirmar ou cancelar.
fn sobre_uma(
    r: &Remetente,
    id: &str,
    metodo: &str,
    f: impl FnOnce(&mut Caixas, u64, u64) -> (Result<Transicao, Recusa>, Vec<Transicao>),
) -> (Result<Transicao, Recusa>, Duravel) {
    crate::persistencia::em_ordem(|| {
        let r = sobre_uma_em_ordem(r, id, metodo, f);
        (r, gravar_o_que_mudou())
    })
}

fn sobre_uma_em_ordem(
    r: &Remetente,
    id: &str,
    metodo: &str,
    f: impl FnOnce(&mut Caixas, u64, u64) -> (Result<Transicao, Recusa>, Vec<Transicao>),
) -> Result<Transicao, Recusa> {
    let agora = crate::persistencia::agora_ms();
    let (epoca, res) = com_tabela(|t| {
        let res = match ler_id(&t.epoca, id) {
            Some(n) => f(&mut t.caixas, n, agora),
            None => (Err(Recusa::Desconhecida), Vec::new()),
        };
        (t.epoca, res)
    });
    let (resultado, vencidas) = res;
    anotar(&vencidas);
    gravar_transicoes(&epoca, r.ator, &vencidas);
    match resultado {
        Ok(t) => {
            anotar(&[t]);
            gravar_transicoes(&epoca, r.ator, &[t]);
            Ok(t)
        }
        Err(recusa) => {
            // O id como veio: a recusa de um id alheio e a de um que não
            // existe são gravadas iguais para quem pediu — e o motivo exato
            // é o da tabela.
            crate::autorizacao::auditar_mensagem(
                r.ator,
                metodo,
                &format!("msg:{id}"),
                recusa.codigo(),
                recusa.motivo(),
            );
            Err(recusa)
        }
    }
}

/// O `ack` de quem recebeu: a mensagem entregue sai da caixa.
pub fn confirmar(
    r: &Remetente,
    id: &str,
    esperada: Option<u64>,
) -> (Result<Transicao, Recusa>, Duravel) {
    sobre_uma(r, id, "message.ack", |c, n, agora| {
        c.confirmar(r.dono, n, esperada, agora)
    })
}

/// O cancelamento de quem mandou, antes da primeira leitura.
pub fn cancelar(
    r: &Remetente,
    id: &str,
    esperada: Option<u64>,
) -> (Result<Transicao, Recusa>, Duravel) {
    sobre_uma(r, id, "message.cancel", |c, n, agora| {
        c.cancelar(r.dono, n, esperada, agora)
    })
}

/// O estado de uma mensagem, para quem tem parte nela.
pub fn estado(r: &Remetente, id: &str) -> (Result<(Estado, u64), Recusa>, Duravel) {
    // Vence antes de responder: uma mensagem cujo prazo passou é `expired`
    // agora, e não quando o coletor passar. As que vencem aqui vão para a
    // auditoria como as do coletor — e para o journal antes da resposta:
    // um `expired` dito não volta a `pending` num boot.
    crate::persistencia::em_ordem(|| {
        let agora = crate::persistencia::agora_ms();
        let (epoca, estado, vencidas) = com_tabela(|t| {
            let (estado, vencidas) = match ler_id(&t.epoca, id) {
                Some(n) => t.caixas.consultar(r.dono, n, agora),
                None => (None, t.caixas.vencer(agora)),
            };
            (t.epoca, estado, vencidas)
        });
        anotar(&vencidas);
        gravar_transicoes(&epoca, AtorDeMensagem::Kernel, &vencidas);
        (estado.ok_or(Recusa::Desconhecida), gravar_o_que_mudou())
    })
}

/// O titular foi revogado: as mensagens vivas que ele mandou e as que ia
/// receber são anuladas, e cada anulação vai para a auditoria em nome
/// dele. Chamada por [`crate::identidade::revogar`] e
/// [`crate::pessoas::revogar_pessoa`].
///
/// As anulações são anotadas, e não gravadas aqui: quem revoga é uma
/// operação de autoridade, e o registro dela leva a revogação e as
/// anulações juntas — ver [`crate::persistencia::concluir`].
pub fn anular_titular(dono: Dono, motivo: &str) {
    let (epoca, anuladas) = crate::persistencia::em_ordem(|| {
        let (epoca, anuladas) = com_tabela(|t| (t.epoca, t.caixas.anular(dono)));
        anotar(&anuladas);
        (epoca, anuladas)
    });
    for a in anuladas {
        let papel = if a.de == dono {
            "remetente"
        } else {
            "destinatario"
        };
        crate::autorizacao::auditar_mensagem(
            AtorDeMensagem::Dono(dono),
            "message.void",
            &recurso(&epoca, a.id),
            Codigo::Allow,
            &format!("anulada: {papel} {motivo}; versao {}", a.versao),
        );
    }
}

/// `message.purge`: uma mensagem, de quem for. Só a operação
/// administrativa, com prova, chama — e ela grava o desfecho dela.
pub fn purgar(r: &Remetente, id: &str) -> (Result<Transicao, Recusa>, Duravel) {
    crate::persistencia::em_ordem(|| {
        let (epoca, t) = com_tabela(|t| {
            let saiu = ler_id(&t.epoca, id).and_then(|n| t.caixas.purgar(n));
            (t.epoca, saiu)
        });
        let Some(t) = t else {
            return (Err(Recusa::Desconhecida), gravar_o_que_mudou());
        };
        anotar(&[t]);
        gravar_transicoes(&epoca, r.ator, &[t]);
        (Ok(t), gravar_o_que_mudou())
    })
}

/// `message.purge_mailbox`: esvazia a caixa de `dono`, endereçada como
/// `alvo`. Só a operação administrativa, com prova e com a permissão
/// própria, chama — e ela grava o desfecho dela, ligado a estas pelo
/// `desafio`.
///
/// Cada mensagem tirada vai para a auditoria uma a uma, com o id: é o que
/// diz **quais** saíram, e não só quantas. As que venceram antes saem como
/// vencidas, em nome do kernel. Devolve os ids tirados, na ordem.
pub fn purgar_caixa(r: &Remetente, dono: Dono, alvo: &str, desafio: u64) -> (Vec<String>, Duravel) {
    crate::persistencia::em_ordem(|| {
        let ids = purgar_caixa_em_ordem(r, dono, alvo, desafio);
        (ids, gravar_o_que_mudou())
    })
}

fn purgar_caixa_em_ordem(r: &Remetente, dono: Dono, alvo: &str, desafio: u64) -> Vec<String> {
    let agora = crate::persistencia::agora_ms();
    let (epoca, (tiradas, vencidas)) =
        com_tabela(|t| (t.epoca, t.caixas.purgar_caixa(dono, agora)));
    anotar(&vencidas);
    anotar(&tiradas);
    gravar_transicoes(&epoca, AtorDeMensagem::Kernel, &vencidas);
    for t in &tiradas {
        crate::autorizacao::auditar_mensagem(
            r.ator,
            "message.purge",
            &recurso(&epoca, t.id),
            Codigo::Allow,
            &format!(
                "tirada com a caixa inteira de {alvo}, pelo desafio {desafio}; versao {}",
                t.versao
            ),
        );
    }
    tiradas.iter().map(|t| id_texto(&epoca, t.id)).collect()
}

/// A sessão do canal acabou: os nonces dela também.
pub fn canal_acabou(canal: Canal) {
    com_tabela(|t| t.caixas.esquecer_canal(canal));
}

/// As que venceram saem, e vão para a auditoria. Chamada pelo coletor de
/// fios — uma vez por segundo basta.
pub fn vencer_todos() {
    use core::sync::atomic::{AtomicU64, Ordering};
    static ULTIMA: AtomicU64 = AtomicU64::new(0);
    // O intervalo é de quantas vezes olhar, e não um prazo: o tempo desde o
    // boot serve para isso. Os prazos são do tempo lógico.
    let desde_o_boot = crate::tempo::uptime_ms();
    if desde_o_boot.saturating_sub(ULTIMA.load(Ordering::Relaxed)) < 1_000 {
        return;
    }
    ULTIMA.store(desde_o_boot, Ordering::Relaxed);
    // Sem tabela, nada a vencer — e nenhuma razão para sortear a época.
    if crate::arch::sem_interrupcoes(|| TABELA.lock().is_none()) {
        return;
    }
    let vencidas = crate::persistencia::em_ordem(|| {
        let agora = crate::persistencia::agora_ms();
        let (epoca, vencidas) = com_tabela(|t| (t.epoca, t.caixas.vencer(agora)));
        if vencidas.is_empty() {
            return None;
        }
        anotar(&vencidas);
        // Uma vencida dita a alguém — pela auditoria — está no journal: não
        // volta a pendente num boot com o RTC atrasado.
        let _ = gravar_o_que_mudou();
        Some((epoca, vencidas))
    });
    let Some((epoca, vencidas)) = vencidas else {
        return;
    };
    gravar_transicoes(&epoca, AtorDeMensagem::Kernel, &vencidas);
}

/// O remetente de uma mensagem, para o relatório: o tipo e quem.
pub fn descrever(dono: Dono) -> (&'static str, Option<(&'static str, String)>) {
    match dono {
        Dono::Serial => ("serial", None),
        Dono::Agente(k) => (
            "agent",
            Some((
                "name",
                crate::identidade::agente(&k).unwrap_or_else(|| sigilo::hex(&k)),
            )),
        ),
        Dono::Pessoa(p) => (
            "person",
            Some(("person", sigilo::pessoas::IdPessoa(p).texto())),
        ),
        Dono::Administrador(k) => (
            "admin",
            Some((
                "name",
                crate::identidade::administrador(&k).unwrap_or_else(|| sigilo::hex(&k)),
            )),
        ),
    }
}

/// Esvazia a tabela, para a suíte: cada caso começa sem mensagens — e sem
/// transições anotadas e ainda não gravadas, que iriam no registro de outro
/// caso.
#[cfg(feature = "modo-teste")]
pub fn esquecer() {
    crate::arch::sem_interrupcoes(|| *TABELA.lock() = None);
    crate::persistencia::esquecer_pendentes_de_teste();
}

/// As vivas, campo a campo, para a suíte comparar duas tabelas.
#[cfg(feature = "modo-teste")]
pub fn retrato_de_teste() -> Vec<Retrato> {
    com_tabela(|t| {
        t.caixas
            .todas()
            .map(|m| {
                (
                    m.id,
                    m.de,
                    m.para,
                    String::from(m.corpo()),
                    m.criada_ms,
                    m.expira_ms,
                    m.estado,
                    m.versao,
                )
            })
            .collect()
    })
}

/// Para o invariante da suíte: ids em ordem, nenhum repetido, nenhuma viva
/// num estado final.
#[cfg(feature = "modo-teste")]
pub fn coerente() -> bool {
    com_tabela(|t| t.caixas.coerente())
}

/// Quantas vivas há para `dono` — para a suíte conferir uma caixa sem lê-la
/// como ele.
#[cfg(feature = "modo-teste")]
pub fn na_caixa(dono: Dono) -> usize {
    com_tabela(|t| t.caixas.na_caixa(dono))
}

/// Destrava a tabela à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        TABELA.force_unlock();
    }
}
