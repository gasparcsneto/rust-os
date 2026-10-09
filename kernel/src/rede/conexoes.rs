//! A conexão de saída como capacidade do registro.
//!
//! # A regra
//!
//! Um programa não abre um socket: pede uma conexão ao registro —
//! `net.connect`, com o destino `tcp:<ipv4>:<porta>` ou
//! `udp:<ipv4>:<porta>` —, pelo mesmo gate, e o destino é o recurso que a
//! política decide. O alcance de cada papel é uma lista enumerada de
//! destinos (ver `politica::endereco`); nada de curinga, nem para o
//! sistema. Uma associação UDP é uma conexão como as outras para tudo o que
//! este módulo diz — dono, decisão a cada uso, derrubada quando o dono
//! acaba —; o que muda é a unidade, o datagrama (ver `super::pilha`).
//!
//! Usar a conexão — `net.send`, `net.recv`, `net.close` — **também** passa
//! pelo gate, com a mesma permissão e o mesmo destino como recurso: o gate
//! resolve o número da conexão no destino dela, para quem pede, antes de
//! decidir. Uma revogação, uma troca de papel ou uma política nova valem no
//! pedido seguinte, para a conexão já aberta — como valem para o processo
//! já lançado. Cada pedido vai para a auditoria com o destino.
//!
//! # De quem é uma conexão
//!
//! De quem a abriu, pelo caminho por onde o pedido veio — o [`Dono`]:
//!
//! - uma sessão do canal: a porta, a chave que provou o aperto, e a geração
//!   da porta. Um agente que desconecta perde as conexões dele; o seguinte
//!   na mesma porta — mesmo com a mesma chave — não as herda;
//! - uma pessoa, pela sessão dela no console;
//! - um processo, pelo fio dele — e não pela autoridade de quem o lançou:
//!   o agente que lançou um programa não lê a conexão do programa, nem o
//!   programa a do agente.
//!
//! Um número de outro titular e um que não existe têm a mesma resposta,
//! `DENY_RESOURCE`: quem pergunta não descobre o que é dos outros.
//!
//! # Quando o dono acaba
//!
//! O coletor de fios, a cada passada, derruba as conexões cujo dono acabou
//! — o processo morreu, a porta reabriu, a sessão da pessoa terminou — e
//! grava cada uma na auditoria. É a mesma regra das camadas de um processo
//! morto (`superficies::recolher_orfas`).

use alloc::vec::Vec;

use crate::autorizacao::{Autoridade, Chamador, Pedinte};
use politica::endereco::Destino;

/// O parâmetro que nomeia a conexão nos comandos que a usam. O gate o
/// reconhece por este nome e resolve o recurso — o destino — em vez de
/// decidir o número.
pub const PARAMETRO: &str = "connection";

/// De quem é uma conexão — ver o cabeçalho do módulo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dono {
    /// Uma sessão do canal: a serial (`sessao` 0, sem chave) ou uma porta.
    Canal {
        sessao: u8,
        chave: Option<[u8; 32]>,
        geracao: u64,
    },
    /// Uma pessoa, pela sessão dela.
    Pessoa(crate::pessoas::IdSessao),
    /// Um processo, pelo fio.
    Processo(u64),
}

/// A geração atual de uma sessão do canal.
fn geracao(sessao: u8) -> u64 {
    if sessao == crate::agent::sessao::SERIAL {
        crate::agent::sessao::Canal::Serial.geracao()
    } else {
        crate::agent::sessao::Canal::Porta(sessao).geracao()
    }
}

impl Dono {
    /// O dono para quem o gate decide: o chamador, e a chave que a sessão
    /// provou — a mesma que vai na autoridade do comando.
    pub fn do_chamador(chamador: Chamador, chave: Option<[u8; 32]>) -> Dono {
        match chamador {
            Chamador::Sessao(sessao) => Dono::Canal {
                sessao,
                chave,
                geracao: geracao(sessao),
            },
            Chamador::Pessoa(id) => Dono::Pessoa(id),
            Chamador::Processo { fio, .. } => Dono::Processo(fio),
        }
    }

    /// O dono do comando em execução neste fio, pelo caminho por onde ele
    /// veio e pela autoridade com que roda. `None` fora de um comando, ou
    /// para o kernel chamando um handler direto: não é ninguém.
    pub fn do_comando() -> Option<Dono> {
        match (
            crate::autorizacao::pedinte()?,
            crate::autorizacao::autoridade_atual(),
        ) {
            (Pedinte::Canal(s), Autoridade::Sessao { sessao, chave }) if s == sessao => {
                Some(Dono::Canal {
                    sessao,
                    chave,
                    geracao: geracao(sessao),
                })
            }
            (Pedinte::Pessoa, Autoridade::Pessoa { sessao }) => Some(Dono::Pessoa(sessao)),
            (Pedinte::Processo(fio), _) => Some(Dono::Processo(fio)),
            _ => None,
        }
    }

    /// De quem é o fluxo, para as regras do firewall: o processo, se o dono
    /// é um, e por quem ele age — a autoridade que o gate decidiu para o
    /// comando em execução. Ver `seguranca::firewall::DonoDoFluxo`.
    pub fn fluxo_do_comando(&self) -> seguranca::firewall::DonoDoFluxo {
        use crate::autorizacao::Autoridade;
        let mut f = seguranca::firewall::DonoDoFluxo::default();
        if let Dono::Processo(fio) = self {
            f.processo = Some(*fio);
        }
        match crate::autorizacao::autoridade_atual() {
            Autoridade::Sessao { chave: Some(k), .. } => f.agente = Some(k),
            Autoridade::Sessao {
                sessao: crate::agent::sessao::SERIAL,
                chave: None,
            } => f.serial = true,
            Autoridade::Pessoa { sessao } => f.pessoa = Some(sessao.0),
            Autoridade::Sistema | Autoridade::Sessao { .. } | Autoridade::Servico(_) => {}
        }
        f
    }

    /// Como a captura, o tecido de segurança e o escopo de uma regra do
    /// firewall o escrevem: o processo pelo fio, o agente pela chave, a
    /// pessoa pela sessão, a serial — ver `seguranca::firewall::Escopo`.
    pub fn texto(&self) -> alloc::string::String {
        match self {
            Dono::Processo(fio) => alloc::format!("process:{fio}"),
            Dono::Canal { chave: Some(k), .. } => alloc::format!("agent:{}", sigilo::hex(k)),
            Dono::Canal {
                sessao: crate::agent::sessao::SERIAL,
                chave: None,
                ..
            } => alloc::string::String::from("serial"),
            Dono::Canal { sessao, .. } => alloc::format!("channel:{sessao}"),
            Dono::Pessoa(id) => alloc::format!("person:{}", sigilo::hex_de(&id.0)),
        }
    }

    /// O dono ainda existe? Um processo vivo, a mesma sessão na mesma porta
    /// com a mesma chave, uma sessão de pessoa ativa.
    fn vivo(&self) -> bool {
        match *self {
            Dono::Processo(fio) => crate::fios::vivo(fio),
            Dono::Canal {
                sessao,
                chave,
                geracao: g,
            } => {
                g == geracao(sessao)
                    && (sessao == crate::agent::sessao::SERIAL
                        || crate::sessoes::identidade(sessao).map(|i| i.chave) == chave)
            }
            Dono::Pessoa(id) => matches!(
                crate::pessoas::sessao(id),
                crate::pessoas::EstadoDaSessao::Ativa { .. }
            ),
        }
    }
}

/// O destino de uma conexão para o gate: o número que o pedido traz,
/// resolvido para `dono`. `Err` com o motivo, que vai para a auditoria —
/// e a recusa é `DENY_RESOURCE`, a mesma de um destino fora do alcance.
pub fn destino_para(numero: Option<u64>, dono: &Dono) -> Result<Destino, &'static str> {
    let Some(numero) = numero else {
        return Err("falta o numero da conexao");
    };
    super::pilha::destino_de(numero, dono)
}

/// Derruba as conexões de donos que acabaram, e grava cada uma na
/// auditoria. Devolve quantas. Chamada pelo coletor de fios.
///
/// A vida de cada dono é conferida **fora** da trava da pilha: ela olha o
/// escalonador, as sessões e as pessoas, e nenhuma dessas travas entra
/// debaixo da da pilha.
pub fn recolher_orfas() -> usize {
    let donos = super::pilha::donos();
    if donos.is_empty() {
        return 0;
    }
    let mortas: Vec<(u64, Destino)> = donos
        .iter()
        .filter(|(_, dono, _)| !dono.vivo())
        .map(|(id, _, destino)| (*id, *destino))
        .collect();
    if mortas.is_empty() {
        return 0;
    }
    let ids: Vec<u64> = mortas.iter().map(|(id, _)| *id).collect();
    let n = super::pilha::derrubar(&ids);
    for (id, destino) in &mortas {
        crate::autorizacao::auditar_do_kernel(
            "net.close",
            &destino.texto(),
            politica::Codigo::Allow,
            &alloc::format!("conexao {id} derrubada: o dono acabou"),
        );
    }
    n
}
