//! As contenções reversíveis: o processo isolado, o agente suspenso, a
//! credencial suspensa.
//!
//! # O que é
//!
//! Estado do gate, como a revogação: quem está contido pede, e o gate
//! recusa — `DENY_CONTAINED` para o processo isolado e o agente suspenso,
//! `DENY_CREDENTIAL` para a credencial suspensa —, e grava. Não é uma
//! segunda autorização: ninguém ganha nada por aqui, só perde, e o que se
//! perde foi decidido pelo gate, pela política, para quem tem a permissão
//! — `process.isolate`, `agent.suspend`, `credential.suspend` — sobre o
//! papel do alvo. Ver `docs/USABILIDADE.md`.
//!
//! # O que cada uma faz
//!
//! - `process.isolate`: o processo continua existindo, mas todo pedido dele
//!   é recusado, e as conexões dele caem.
//! - `agent.suspend`: o agente continua registrado e conectado, mas todo
//!   pedido dele — e dos processos dele — é recusado; as conexões caem, e
//!   os arrendamentos são soltos.
//! - `credential.suspend`: a credencial — de uma pessoa, ou a chave de um
//!   agente — não autentica: o login e o aperto são recusados, e as sessões
//!   abertas com ela também não agem; as conexões caem, e os arrendamentos
//!   são soltos.
//!
//! Cada uma tem o seu inverso, pela mesma permissão: `process.release`,
//! `agent.resume`, `credential.resume`.
//!
//! # Idempotente
//!
//! Conter o que já está contido não muda nada, e diz isso — `changed:
//! false`, `already_contained` —; soltar o que não está contido, também.
//! Ninguém fica "duas vezes isolado".
//!
//! # Volátil
//!
//! Como as regras do firewall: uma contenção é medida de incidente, e não
//! sobrevive a um boot. O que é definitivo é a revogação — administrativa,
//! com prova, gravada no journal. Suspender não é revogar, e uma nunca vira
//! a outra.
//!
//! # Quem pode mudar
//!
//! Só os handlers dos comandos — depois do gate — e as operações
//! administrativas — depois da prova; o `xtask` confere.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use politica::Codigo;
use protocolo::json::Json;
use sigilo::pessoas::IdPessoa;

use crate::autorizacao::{Autoridade, Chamador};
use crate::trava::Mutex;

/// Quantos contidos de cada espécie, no máximo: passou disso, a contenção
/// seguinte é recusada — e um processo que acabou sai antes de contar.
pub const MAIS_CONTIDOS: usize = 64;

/// Quem uma contenção alcança.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alvo {
    /// Um processo, pelo fio: `process.isolate`.
    Processo(u64),
    /// Um agente, pela chave: `agent.suspend`.
    Agente([u8; 32]),
    /// A credencial de um agente, pela chave: `credential.suspend {key}`.
    ChaveDeAgente([u8; 32]),
    /// A credencial de uma pessoa: `credential.suspend {person}`.
    Pessoa(IdPessoa),
}

/// A chave de um agente, em hexadecimal, de um parâmetro.
fn chave(v: Option<Json>) -> Option<[u8; 32]> {
    v.and_then(|v| v.as_str()).and_then(sigilo::de_hex_fixo)
}

impl Alvo {
    /// Como a auditoria grava o alvo — o recurso da decisão —, e como o
    /// tecido de segurança e o escopo de uma regra do firewall o escrevem:
    /// `process:<fio>`, `agent:<chave>`, `pessoa:<16 hex>`.
    pub fn texto(&self) -> String {
        match self {
            Alvo::Processo(fio) => alloc::format!("process:{fio}"),
            Alvo::Agente(k) | Alvo::ChaveDeAgente(k) => alloc::format!("agent:{}", sigilo::hex(k)),
            Alvo::Pessoa(id) => id.texto(),
        }
    }

    /// O alvo de um pedido de contenção, ou do inverso dela: o método diz a
    /// espécie, e os parâmetros, quem.
    pub fn do_pedido(metodo: &str, params: Json) -> Result<Alvo, &'static str> {
        match metodo {
            "process.isolate" | "process.release" => params
                .member("process")
                .and_then(|v| v.as_u64())
                .map(Alvo::Processo)
                .ok_or("falta o processo"),
            "agent.suspend" | "agent.resume" => chave(params.member("key"))
                .map(Alvo::Agente)
                .ok_or("chave de agente invalida"),
            "credential.suspend" | "credential.resume" => {
                match (params.member("person"), params.member("key")) {
                    (Some(p), None) => p
                        .as_str()
                        .and_then(IdPessoa::ler)
                        .map(Alvo::Pessoa)
                        .ok_or("pessoa invalida"),
                    (None, Some(k)) => chave(Some(k))
                        .map(Alvo::ChaveDeAgente)
                        .ok_or("chave de agente invalida"),
                    _ => Err("diga `person` ou `key`"),
                }
            }
            _ => Err("nao e uma contencao"),
        }
    }

    /// O alvo, lido de volta do texto que o gate decidiu.
    pub fn do_texto(metodo: &str, texto: &str) -> Option<Alvo> {
        if let Some(fio) = texto.strip_prefix("process:") {
            return metodo
                .starts_with("process.")
                .then(|| fio.parse().ok().map(Alvo::Processo))
                .flatten();
        }
        if let Some(k) = texto.strip_prefix("agent:") {
            let k = sigilo::de_hex_fixo(k)?;
            return match metodo {
                "agent.suspend" | "agent.resume" => Some(Alvo::Agente(k)),
                "credential.suspend" | "credential.resume" => Some(Alvo::ChaveDeAgente(k)),
                _ => None,
            };
        }
        metodo
            .starts_with("credential.")
            .then(|| IdPessoa::ler(texto).map(Alvo::Pessoa))
            .flatten()
    }

    /// O papel de quem o alvo alcança — o recurso que a política decide é
    /// `papel:<este>`. Um alvo que não existe não tem papel, e a recusa diz
    /// por quê.
    pub fn papel(&self) -> Result<String, &'static str> {
        match self {
            Alvo::Processo(fio) => {
                let autoridade =
                    crate::fios::autoridade_do_processo(*fio).ok_or("processo inexistente")?;
                crate::autorizacao::papel_da_autoridade(autoridade).ok_or("processo sem papel")
            }
            Alvo::Agente(k) | Alvo::ChaveDeAgente(k) => {
                crate::identidade::papel_do_agente(k).ok_or("agente inexistente")
            }
            Alvo::Pessoa(id) => match crate::pessoas::pessoa(*id) {
                Some(p) if p.estado == sigilo::pessoas::Estado::Ativa => Ok(p.papel),
                _ => Err("pessoa inexistente"),
            },
        }
    }
}

/// O estado.
struct Contidos {
    /// Os processos isolados, pelo fio — que nunca se repete.
    isolados: BTreeSet<u64>,
    /// Os agentes suspensos, pela chave.
    suspensos: BTreeSet<[u8; 32]>,
    /// As chaves de agente com a credencial suspensa.
    chaves: BTreeSet<[u8; 32]>,
    /// As pessoas com a credencial suspensa.
    pessoas: BTreeSet<[u8; 8]>,
}

static CONTIDOS: Mutex<Contidos> = Mutex::new(Contidos {
    isolados: BTreeSet::new(),
    suspensos: BTreeSet::new(),
    chaves: BTreeSet::new(),
    pessoas: BTreeSet::new(),
});

fn com_contidos<R>(f: impl FnOnce(&mut Contidos) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut CONTIDOS.lock()))
}

/// Se quem pede está contido: o código da recusa e o motivo. O gate
/// pergunta, para todo pedido que não seja de prova administrativa — a
/// prova é a autoridade, e a sessão por onde ela veio é só o transporte:
/// o administrador recupera o sistema mesmo pela porta de quem foi contido.
pub fn recusa(chamador: Chamador, autoridade: Autoridade) -> Option<(Codigo, &'static str)> {
    // A pessoa da sessão, procurada fora da trava: a do registro de
    // pessoas não entra debaixo desta.
    let pessoa = match autoridade {
        Autoridade::Pessoa { sessao } if com_contidos(|c| !c.pessoas.is_empty()) => {
            crate::pessoas::dona_da_sessao(sessao)
        }
        _ => None,
    };
    com_contidos(|c| {
        if let Chamador::Processo { fio, .. } = chamador
            && c.isolados.contains(&fio)
        {
            return Some((Codigo::DenyContained, "processo isolado"));
        }
        match autoridade {
            Autoridade::Sessao { chave: Some(k), .. } => {
                if c.chaves.contains(&k) {
                    Some((Codigo::DenyCredential, "credencial suspensa"))
                } else if c.suspensos.contains(&k) {
                    Some((Codigo::DenyContained, "agente suspenso"))
                } else {
                    None
                }
            }
            Autoridade::Pessoa { .. } => pessoa
                .filter(|p| c.pessoas.contains(&p.0))
                .map(|_| (Codigo::DenyCredential, "credencial suspensa")),
            _ => None,
        }
    })
}

/// A credencial deste agente está suspensa: o aperto é recusado.
pub fn chave_suspensa(chave: &[u8; 32]) -> bool {
    com_contidos(|c| c.chaves.contains(chave))
}

/// A credencial desta pessoa está suspensa: o login é recusado.
pub fn pessoa_suspensa(id: IdPessoa) -> bool {
    com_contidos(|c| c.pessoas.contains(&id.0))
}

/// O que uma contenção mudou.
#[derive(Debug, Default)]
pub struct Feito {
    /// Se o estado mudou: conter o contido, ou soltar o solto, não muda.
    pub mudou: bool,
    /// As conexões que caíram: o número e o destino.
    pub derrubadas: Vec<(u64, politica::endereco::Destino)>,
}

/// Tira os processos que acabaram: o fio nunca se repete, e um morto não
/// ocupa vaga. A vida de cada um é procurada fora da trava — a do
/// escalonador não entra debaixo desta.
fn podar() {
    let isolados: Vec<u64> = com_contidos(|c| c.isolados.iter().copied().collect());
    let mortos: Vec<u64> = isolados
        .into_iter()
        .filter(|f| !crate::fios::vivo(*f))
        .collect();
    if !mortos.is_empty() {
        com_contidos(|c| {
            for f in &mortos {
                c.isolados.remove(f);
            }
        });
    }
}

/// Contém `alvo`: o estado, e o efeito — as conexões de quem foi contido
/// caem, e os arrendamentos são soltos (cada um gravado pela coordenação).
/// Só os handlers dos comandos e as operações administrativas chamam.
pub fn conter(alvo: &Alvo) -> Result<Feito, &'static str> {
    podar();
    let mudou = com_contidos(|c| {
        let (conjunto_cheio, novo) = match alvo {
            Alvo::Processo(fio) => (c.isolados.len() >= MAIS_CONTIDOS, !c.isolados.contains(fio)),
            Alvo::Agente(k) => (c.suspensos.len() >= MAIS_CONTIDOS, !c.suspensos.contains(k)),
            Alvo::ChaveDeAgente(k) => (c.chaves.len() >= MAIS_CONTIDOS, !c.chaves.contains(k)),
            Alvo::Pessoa(id) => (c.pessoas.len() >= MAIS_CONTIDOS, !c.pessoas.contains(&id.0)),
        };
        if novo && conjunto_cheio {
            return Err("teto de contencoes desta especie");
        }
        Ok(match alvo {
            Alvo::Processo(fio) => c.isolados.insert(*fio),
            Alvo::Agente(k) => c.suspensos.insert(*k),
            Alvo::ChaveDeAgente(k) => c.chaves.insert(*k),
            Alvo::Pessoa(id) => c.pessoas.insert(id.0),
        })
    })?;
    let mut feito = Feito {
        mudou,
        derrubadas: Vec::new(),
    };
    if mudou {
        feito.derrubadas = derrubar(alvo);
        let motivo = match alvo {
            Alvo::Processo(_) => None,
            Alvo::Agente(_) => Some("agente suspenso"),
            Alvo::ChaveDeAgente(_) | Alvo::Pessoa(_) => Some("credencial suspensa"),
        };
        if let Some(motivo) = motivo {
            match alvo {
                Alvo::Agente(k) | Alvo::ChaveDeAgente(k) => {
                    crate::coordenacao::invalidar_chave(k, motivo)
                }
                Alvo::Pessoa(id) => crate::coordenacao::invalidar_da_pessoa(id.0, motivo),
                Alvo::Processo(_) => {}
            }
        }
    }
    Ok(feito)
}

/// Desfaz a contenção de `alvo`. Nada mais muda: as conexões que caíram não
/// voltam, e quem foi solto pede de novo, pelo gate, como antes.
pub fn soltar(alvo: &Alvo) -> Feito {
    let mudou = com_contidos(|c| match alvo {
        Alvo::Processo(fio) => c.isolados.remove(fio),
        Alvo::Agente(k) => c.suspensos.remove(k),
        Alvo::ChaveDeAgente(k) => c.chaves.remove(k),
        Alvo::Pessoa(id) => c.pessoas.remove(&id.0),
    });
    Feito {
        mudou,
        derrubadas: Vec::new(),
    }
}

/// O desfecho em uma palavra, para a resposta e a auditoria: `isolated`,
/// `already_isolated`, `released`, `not_isolated` — e os de suspensão.
pub fn desfecho(alvo: &Alvo, conter: bool, mudou: bool) -> &'static str {
    let (feito, ja) = match alvo {
        Alvo::Processo(_) if conter => ("isolated", "already_isolated"),
        Alvo::Processo(_) => ("released", "not_isolated"),
        _ if conter => ("suspended", "already_suspended"),
        _ => ("resumed", "not_suspended"),
    };
    if mudou { feito } else { ja }
}

/// Se `alvo` está contido agora.
pub fn contido(alvo: &Alvo) -> bool {
    com_contidos(|c| match alvo {
        Alvo::Processo(fio) => c.isolados.contains(fio),
        Alvo::Agente(k) => c.suspensos.contains(k),
        Alvo::ChaveDeAgente(k) => c.chaves.contains(k),
        Alvo::Pessoa(id) => c.pessoas.contains(&id.0),
    })
}

/// Derruba as conexões de quem `alvo` alcança: o processo; o agente, pelo
/// canal dele e pelos processos que ele lançou; a pessoa, pelas sessões e
/// pelos processos dela. A vida e a autoridade de cada dono são procuradas
/// fora da trava da pilha.
fn derrubar(alvo: &Alvo) -> Vec<(u64, politica::endereco::Destino)> {
    use crate::rede::conexoes::Dono;
    let alcanca = |dono: &Dono| -> bool {
        match (alvo, dono) {
            (Alvo::Processo(f), Dono::Processo(d)) => f == d,
            (Alvo::Agente(k) | Alvo::ChaveDeAgente(k), Dono::Canal { chave: Some(c), .. }) => {
                k == c
            }
            (Alvo::Agente(k) | Alvo::ChaveDeAgente(k), Dono::Processo(d)) => matches!(
                crate::fios::autoridade_do_processo(*d),
                Some(Autoridade::Sessao { chave: Some(c), .. }) if c == *k
            ),
            (Alvo::Pessoa(id), Dono::Pessoa(s)) => {
                crate::pessoas::dona_da_sessao(*s).is_some_and(|p| p == *id)
            }
            (Alvo::Pessoa(id), Dono::Processo(d)) => {
                match crate::fios::autoridade_do_processo(*d) {
                    Some(Autoridade::Pessoa { sessao }) => {
                        crate::pessoas::dona_da_sessao(sessao).is_some_and(|p| p == *id)
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    };
    let alcancadas: Vec<(u64, politica::endereco::Destino)> = crate::rede::pilha::donos()
        .into_iter()
        .filter(|(_, dono, _)| alcanca(dono))
        .map(|(id, _, destino)| (id, destino))
        .collect();
    if alcancadas.is_empty() {
        return alcancadas;
    }
    let ids: Vec<u64> = alcancadas.iter().map(|(id, _)| *id).collect();
    crate::rede::pilha::derrubar(&ids);
    alcancadas
}

/// O estado, para quem investiga: cada contido, pelo texto do alvo.
pub fn lista() -> Vec<(&'static str, String)> {
    podar();
    let (isolados, suspensos, chaves, pessoas) = com_contidos(|c| {
        (
            c.isolados.iter().copied().collect::<Vec<_>>(),
            c.suspensos.iter().copied().collect::<Vec<_>>(),
            c.chaves.iter().copied().collect::<Vec<_>>(),
            c.pessoas.iter().copied().collect::<Vec<_>>(),
        )
    });
    let mut v = Vec::new();
    for f in isolados {
        v.push(("process.isolate", Alvo::Processo(f).texto()));
    }
    for k in suspensos {
        v.push(("agent.suspend", Alvo::Agente(k).texto()));
    }
    for k in chaves {
        v.push(("credential.suspend", Alvo::ChaveDeAgente(k).texto()));
    }
    for p in pessoas {
        v.push(("credential.suspend", Alvo::Pessoa(IdPessoa(p)).texto()));
    }
    v
}

/// Esquece as contenções de uma chave revogada: a revogação é o definitivo,
/// e uma chave registrada de novo não herda a suspensão de antes.
pub fn esquecer_chave(chave: &[u8; 32]) {
    com_contidos(|c| {
        c.suspensos.remove(chave);
        c.chaves.remove(chave);
    });
}

/// Esquece a contenção de uma pessoa revogada.
pub fn esquecer_pessoa(id: IdPessoa) {
    com_contidos(|c| {
        c.pessoas.remove(&id.0);
    });
}

/// Só para a suíte: ninguém contido — cada caso começa do zero.
#[cfg(feature = "modo-teste")]
pub fn esquecer_de_teste() {
    com_contidos(|c| {
        c.isolados.clear();
        c.suspensos.clear();
        c.chaves.clear();
        c.pessoas.clear();
    });
}

/// Destrava o estado, para o caminho de falha fatal.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        CONTIDOS.force_unlock();
    }
}
