//! A coordenação: versões e arrendamentos dos recursos compartilhados, no
//! kernel.
//!
//! A conta é a de [`politica::arrendamento`]; aqui ela ganha o relógio, o
//! titular de cada pedido e a auditoria. Tudo o que muda a tabela passa por
//! este módulo — o `xtask invariantes` confere —, e cada evento vai para a
//! auditoria: tomar, soltar, a recusa de tomar, o conflito de versão, o
//! arrendamento vencido, o invalidado por revogação, a ação sem o
//! arrendamento que ela pede, e a mudança feita — a confirmação, com a
//! versão nova, e sem o texto.
//!
//! # Os recursos
//!
//! Cada elemento editável da árvore semântica é um recurso, pelo número
//! dele: `ui:3` é a linha de comando do console físico; `ui:<n>` um campo
//! de janela, como a linha de comando de um Terminal. O nome é o mesmo que
//! o agente vê em `ui.tree`.
//!
//! # A regra das edições
//!
//! - **Editar** — digitar, `set_value`, `cancel` — num recurso livre o
//!   arrenda, implicitamente, para quem editou: a primeira tecla de uma
//!   pessoa, o primeiro `set_value` de um agente. O arrendamento implícito
//!   vai para a auditoria uma vez; as teclas seguintes o renovam, sem
//!   registro cada uma.
//! - Num recurso arrendado por outro: `CONFLICT`, e nada muda — a tecla não
//!   substitui em silêncio quem estava ali.
//! - **Confirmar** pede o arrendamento: quem confirma é quem editou, ou quem
//!   tomou com `ui.claim`. Confirmado, o arrendamento é solto: a linha volta
//!   vazia e livre.
//!
//! Pessoa e agente seguem a mesma regra, sem prioridade entre eles; e o
//! `sistema` não tem passe: quebrar o arrendamento de outro é
//! `lease.revoke`, uma operação administrativa com prova.

use alloc::format;
use alloc::string::String;

use crate::trava::Mutex;
use politica::Codigo;
use politica::arrendamento::{Arrendamento, Estado, Recusa, Tabela, Titular, Vencido};

use crate::pessoas::{Console, IdSessao};
use crate::ui::Origem;

/// O prazo do arrendamento implícito de uma edição. Renovado a cada tecla.
pub const PRAZO_IMPLICITO_MS: u64 = 60_000;

/// O prazo de um `ui.claim` que não diz o seu.
pub const PRAZO_PADRAO_MS: u64 = 30_000;

static TABELA: Mutex<Tabela> = Mutex::new(Tabela::nova());

fn com_tabela<R>(f: impl FnOnce(&mut Tabela) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut TABELA.lock()))
}

/// O nome do recurso de um elemento da árvore.
pub fn recurso(elemento: u32) -> String {
    format!("ui:{elemento}")
}

/// O nome do recurso de um arquivo do armazém, pelo caminho inteiro na
/// forma normal: `fs:/armazem/compartilhado/notas.txt`. Ver
/// [`crate::armazem`].
pub fn recurso_do_caminho(caminho: &str) -> String {
    format!("fs:{caminho}")
}

/// O titular de uma sessão do canal: a chave que provou o aperto, ou a
/// serial, sem chave. `None` para uma porta sem aperto.
pub fn titular_do_agente(sessao: u8) -> Option<Titular> {
    if sessao == crate::agent::sessao::SERIAL {
        return Some(Titular::Agente {
            sessao,
            chave: None,
        });
    }
    crate::sessoes::identidade(sessao).map(|id| Titular::Agente {
        sessao,
        chave: Some(id.chave),
    })
}

/// O titular de quem um comando age por: a autoridade que o gate decidiu,
/// e não o canal por onde o pedido chegou.
///
/// - um agente, pela chave que ele provou — a mesma chave, e não quem
///   estiver hoje na porta: o processo de um agente que desconectou não
///   arrenda como o agente que entrou depois na mesma porta;
/// - a serial;
/// - uma pessoa, pela sessão dela, se ainda vale;
/// - o sistema não tem titular: a autoridade local não arrenda.
///
/// # Por que não pelo canal
///
/// Era pelo canal — `titular_do_agente(sessao::atual())` —, e a sessão do
/// canal é a do despachante: uma pessoa que pedia `ui.claim` no
/// interpretador, onde ninguém a punha, arrendava o campo como a serial.
pub fn titular_da_autoridade(autoridade: crate::autorizacao::Autoridade) -> Option<Titular> {
    use crate::autorizacao::Autoridade;
    match autoridade {
        Autoridade::Sistema => None,
        Autoridade::Sessao {
            sessao: crate::agent::sessao::SERIAL,
            chave: None,
        } => Some(Titular::Agente {
            sessao: crate::agent::sessao::SERIAL,
            chave: None,
        }),
        Autoridade::Sessao { chave: None, .. } => None,
        Autoridade::Sessao {
            sessao,
            chave: Some(k),
        } => Some(Titular::Agente {
            sessao,
            chave: Some(k),
        }),
        Autoridade::Pessoa { sessao } => titular_da_pessoa(sessao),
        // Um serviço não arrenda nada: não é quem edita.
        Autoridade::Servico(_) => None,
    }
}

/// O titular de uma sessão de pessoa, se ela ainda vale.
pub fn titular_da_pessoa(sessao: IdSessao) -> Option<Titular> {
    match crate::pessoas::sessao(sessao) {
        crate::pessoas::EstadoDaSessao::Ativa { pessoa, .. } => Some(Titular::Pessoa {
            sessao: sessao.0,
            pessoa: pessoa.0,
        }),
        _ => None,
    }
}

/// Quem age: o agente da sessão, ou a pessoa entrada no console.
pub fn titular(origem: Origem, console: Console) -> Option<Titular> {
    match origem {
        Origem::Agente(sessao) => titular_do_agente(sessao),
        Origem::Pessoa => crate::interpretador::sessao_valida(console).and_then(titular_da_pessoa),
    }
}

/// Quantos arrendamentos válidos a sessão `sessao` do canal tem agora,
/// com a chave `chave` — para o `agent.list`.
pub fn quantos_do_agente(sessao: u8, chave: [u8; 32]) -> usize {
    let agora = crate::tempo::uptime_ms();
    let dele = Titular::Agente {
        sessao,
        chave: Some(chave),
    };
    com_tabela(|t| {
        t.arrendados(agora)
            .filter(|(_, e)| e.arrendamento.is_some_and(|a| a.titular == dele))
            .count()
    })
}

/// O texto de um titular, para o relatório: o tipo e o identificador.
pub fn descrever(t: &Titular) -> (&'static str, String) {
    match t {
        Titular::Pessoa { pessoa, .. } => ("person", sigilo::pessoas::IdPessoa(*pessoa).texto()),
        Titular::Agente {
            sessao,
            chave: None,
        } => ("agent", format!("serial:{sessao}")),
        Titular::Agente { chave: Some(k), .. } => (
            "agent",
            crate::identidade::agente(k).unwrap_or_else(|| sigilo::hex(k)),
        ),
    }
}

/// Grava um evento de arrendamento, em nome de `titular` — ou de ninguém,
/// para uma pessoa sem login.
fn gravar(titular: Option<&Titular>, metodo: &str, recurso: &str, codigo: Codigo, detalhe: &str) {
    crate::autorizacao::auditar_arrendamento(titular, metodo, recurso, codigo, detalhe);
}

fn gravar_vencido(recurso: &str, vencido: Option<Vencido>) {
    if let Some(Vencido(a)) = vencido {
        gravar(
            Some(&a.titular),
            "lease.expire",
            recurso,
            Codigo::Allow,
            "o prazo venceu",
        );
    }
}

/// O estado de um recurso agora.
pub fn estado(recurso: &str) -> Estado {
    let agora = crate::tempo::uptime_ms();
    com_tabela(|t| t.estado(recurso, agora))
}

/// `ui.claim`: toma o arrendamento por `prazo_ms`. Do mesmo titular,
/// renova. Grava o desfecho.
pub fn tomar(recurso: &str, titular: Titular, prazo_ms: u64) -> Result<Arrendamento, Codigo> {
    tomar_por(recurso, titular, prazo_ms, "ui.claim")
}

/// [`tomar`], gravado com o método que pediu — `ui.claim`, `fs.claim`.
pub fn tomar_por(
    recurso: &str,
    titular: Titular,
    prazo_ms: u64,
    metodo: &str,
) -> Result<Arrendamento, Codigo> {
    let agora = crate::tempo::uptime_ms();
    let (r, vencido) = com_tabela(|t| t.tomar(recurso, titular, agora, prazo_ms));
    gravar_vencido(recurso, vencido);
    match r {
        Ok(a) => {
            gravar(
                Some(&titular),
                metodo,
                recurso,
                Codigo::Allow,
                "arrendamento tomado",
            );
            Ok(a)
        }
        Err(recusa) => {
            gravar(
                Some(&titular),
                metodo,
                recurso,
                recusa.codigo(),
                recusa.motivo(),
            );
            Err(recusa.codigo())
        }
    }
}

/// `ui.release`: solta o arrendamento, se for de `titular`. Grava.
pub fn soltar(recurso: &str, titular: Titular) -> Result<(), Codigo> {
    soltar_por(recurso, titular, "ui.release")
}

/// [`soltar`], gravado com o método que pediu — `ui.release`, `fs.release`.
pub fn soltar_por(recurso: &str, titular: Titular, metodo: &str) -> Result<(), Codigo> {
    let agora = crate::tempo::uptime_ms();
    let (r, vencido) = com_tabela(|t| t.soltar(recurso, titular, agora));
    gravar_vencido(recurso, vencido);
    match r {
        Ok(_) => {
            gravar(
                Some(&titular),
                metodo,
                recurso,
                Codigo::Allow,
                "arrendamento solto",
            );
            Ok(())
        }
        Err(recusa) => {
            gravar(
                Some(&titular),
                metodo,
                recurso,
                recusa.codigo(),
                recusa.motivo(),
            );
            Err(recusa.codigo())
        }
    }
}

/// Os recursos arrendados agora cujo caminho está abaixo de `caminho` — na
/// forma normal. Um rename leva tudo abaixo da origem, e o que está abaixo
/// do destino passa a existir: o arrendamento de cada um conta.
pub fn arrendados_abaixo(caminho: &str) -> alloc::vec::Vec<String> {
    let agora = crate::tempo::uptime_ms();
    let prefixo = recurso_do_caminho(caminho);
    com_tabela(|t| {
        t.arrendados(agora)
            .filter(|(r, _)| {
                r.len() > prefixo.len()
                    && r.starts_with(prefixo.as_str())
                    && r.as_bytes()[prefixo.len()] == b'/'
            })
            .map(|(r, _)| String::from(r))
            .collect()
    })
}

/// Confere só o arrendamento de `recurso` para uma mudança em nome de
/// `titular` — ou de uma autoridade que não arrenda, `None` —, sem tocar
/// na versão desta tabela: o recurso tem a versão dele em outro lugar (o
/// armazém). O arrendamento do titular é renovado pela atividade; o de
/// outro recusa, com o titular dele.
///
/// Só grava o arrendamento que venceu no caminho: a recusa é gravada por
/// quem chama, como o resultado do comando que ela recusou.
pub fn conferir(recurso: &str, titular: Option<Titular>) -> Result<(), Recusa> {
    let agora = crate::tempo::uptime_ms();
    let (r, vencido) = com_tabela(|t| t.conferir(recurso, titular, agora));
    gravar_vencido(recurso, vencido);
    r
}

/// Uma edição — uma tecla, um `set_value`, um `cancel` — em nome de
/// `titular`: arrenda o recurso livre implicitamente, e confere a versão.
/// Devolve a versão nova.
///
/// Sem titular — uma pessoa num console sem login, digitando o `login` — a
/// edição só passa num recurso livre, e não o arrenda: o arrendamento é de
/// uma sessão autenticada.
pub fn editar(
    recurso: &str,
    titular: Option<Titular>,
    esperada: Option<u64>,
    metodo: &str,
) -> Result<u64, Codigo> {
    let agora = crate::tempo::uptime_ms();
    let Some(titular) = titular else {
        let livre = estado(recurso).arrendamento.is_none();
        if !livre {
            gravar(
                None,
                metodo,
                recurso,
                Codigo::Conflict,
                "outro titular tem o arrendamento",
            );
            return Err(Codigo::Conflict);
        }
        return Ok(estado(recurso).versao);
    };
    let (implicito, vencido, r) = com_tabela(|t| {
        let mut vencidos = None;
        let antes = t.estado(recurso, agora).arrendamento;
        let implicito = antes.is_none();
        if implicito {
            let (r, v) = t.tomar(recurso, titular, agora, PRAZO_IMPLICITO_MS);
            vencidos = v;
            if let Err(recusa) = r {
                return (false, vencidos, Err(recusa));
            }
        }
        let (r, v) = t.mudar(recurso, titular, esperada, true, agora);
        if implicito && r.is_err() {
            // A edição recusada não deixa o arrendamento que acabou de
            // tomar: a recusa não muda nada.
            let _ = t.soltar(recurso, titular, agora);
        }
        (implicito && r.is_ok(), vencidos.or(v), r)
    });
    gravar_vencido(recurso, vencido);
    match r {
        Ok(versao) => {
            if implicito {
                gravar(
                    Some(&titular),
                    "ui.claim",
                    recurso,
                    Codigo::Allow,
                    "arrendamento implicito pela edicao",
                );
            }
            Ok(versao)
        }
        Err(recusa) => {
            gravar(
                Some(&titular),
                metodo,
                recurso,
                recusa.codigo(),
                recusa.motivo(),
            );
            Err(recusa.codigo())
        }
    }
}

/// Uma confirmação em nome de `titular`: pede o arrendamento, e confere a
/// versão. Passando, a versão cresce e o arrendamento é solto — a linha
/// confirmada volta vazia e livre.
///
/// Sem titular, como em [`editar`]: só num recurso livre.
pub fn confirmar(
    recurso: &str,
    titular: Option<Titular>,
    esperada: Option<u64>,
    metodo: &str,
) -> Result<u64, Codigo> {
    let agora = crate::tempo::uptime_ms();
    let Some(titular) = titular else {
        if estado(recurso).arrendamento.is_some() {
            gravar(
                None,
                metodo,
                recurso,
                Codigo::Conflict,
                "outro titular tem o arrendamento",
            );
            return Err(Codigo::Conflict);
        }
        return Ok(estado(recurso).versao);
    };
    let (r, vencido) = com_tabela(|t| {
        let (r, v) = t.mudar(recurso, titular, esperada, true, agora);
        if r.is_ok() {
            let _ = t.soltar(recurso, titular, agora);
        }
        (r, v)
    });
    gravar_vencido(recurso, vencido);
    match r {
        Ok(versao) => {
            // A mudança feita: o que a confirmação levou não vai — a
            // auditoria guarda quem, onde e a versão, e não o texto.
            gravar(
                Some(&titular),
                metodo,
                recurso,
                Codigo::Allow,
                &format!("confirmado na versao {versao}"),
            );
            Ok(versao)
        }
        Err(recusa) => {
            let detalhe = match recusa {
                Recusa::SemArrendamento => "confirmar sem o arrendamento",
                outra => outra.motivo(),
            };
            gravar(Some(&titular), metodo, recurso, recusa.codigo(), detalhe);
            Err(recusa.codigo())
        }
    }
}

/// Tira os arrendamentos de uma sessão de pessoa que acabou. Grava cada um.
pub fn invalidar_pessoa(sessao: IdSessao, motivo: &str) {
    invalidar(
        |t| matches!(t, Titular::Pessoa { sessao: s, .. } if *s == sessao.0),
        motivo,
    );
}

/// Tira os arrendamentos de todas as pessoas: o registro foi recarregado, e
/// nenhuma sessão de pessoa sobrou. Grava.
pub fn invalidar_pessoas(motivo: &str) {
    invalidar(Titular::e_pessoa, motivo);
}

/// Tira os arrendamentos de uma chave revogada, em qualquer sessão. Grava.
pub fn invalidar_chave(chave: &[u8; 32], motivo: &str) {
    invalidar(
        |t| matches!(t, Titular::Agente { chave: Some(k), .. } if k == chave),
        motivo,
    );
}

/// Tira os arrendamentos de uma sessão do canal que acabou — a porta
/// desconectou. Grava.
pub fn invalidar_sessao_do_canal(sessao: u8, motivo: &str) {
    invalidar(
        |t| matches!(t, Titular::Agente { sessao: s, .. } if *s == sessao),
        motivo,
    );
}

fn invalidar(acabou: impl Fn(&Titular) -> bool, motivo: &str) {
    let saidos = com_tabela(|t| t.invalidar(acabou));
    for (recurso, a) in saidos {
        gravar(
            Some(&a.titular),
            "lease.invalidate",
            &recurso,
            Codigo::Allow,
            motivo,
        );
    }
}

/// Tira os arrendamentos vencidos, e grava cada um. Chamada pelo coletor de
/// fios — uma vez por segundo basta.
pub fn vencer_todos() {
    use core::sync::atomic::{AtomicU64, Ordering};
    static ULTIMA: AtomicU64 = AtomicU64::new(0);
    let agora = crate::tempo::uptime_ms();
    if agora.saturating_sub(ULTIMA.load(Ordering::Relaxed)) < 1_000 {
        return;
    }
    ULTIMA.store(agora, Ordering::Relaxed);
    let saidos = com_tabela(|t| t.vencer_todos(agora));
    for (recurso, a) in saidos {
        gravar(
            Some(&a.titular),
            "lease.expire",
            &recurso,
            Codigo::Allow,
            "o prazo venceu",
        );
    }
}

/// Revoga o arrendamento de um recurso, de quem for: `lease.revoke`. Só a
/// operação administrativa chama, com a prova conferida — e ela grava o
/// desfecho; aqui se grava o arrendamento que saiu, em nome de quem o tinha.
pub fn revogar(recurso: &str) -> Option<Arrendamento> {
    let saiu = com_tabela(|t| t.revogar(recurso));
    if let Some(a) = saiu {
        gravar(
            Some(&a.titular),
            "lease.invalidate",
            recurso,
            Codigo::Allow,
            "revogado por um administrador",
        );
    }
    saiu
}

/// Para o invariante da suíte: nenhum recurso com dois arrendamentos.
#[cfg(feature = "modo-teste")]
pub fn um_por_recurso() -> bool {
    com_tabela(|t| t.um_por_recurso())
}

/// Esvazia a tabela, para a suíte: cada caso começa sem arrendamento.
#[cfg(feature = "modo-teste")]
pub fn esquecer() {
    com_tabela(|t| *t = Tabela::nova());
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
