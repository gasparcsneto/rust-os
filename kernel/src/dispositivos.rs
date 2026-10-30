//! Os dispositivos relacionados no kernel: o registro, o que ele não sabe
//! conferir sozinho, e o que a revogação de um desfaz.
//!
//! A conta — quem é cada dispositivo, a que pessoa desta máquina cada um se
//! relaciona, com que papel, e quem tem lápide — é a de
//! [`politica::dispositivos`]. Aqui ela ganha a trava, a persistência e as
//! conferências que dependem do resto do kernel:
//!
//! - **Uma chave, uma espécie de principal.** A chave de um dispositivo não
//!   é a de um agente nem a de um administrador — nem a de um administrador
//!   revogado —, e a deste Duke nunca é par dele mesmo. O registro de
//!   agentes recusa, do outro lado, a chave de um dispositivo e a que tem
//!   lápide de dispositivo — ver [`conhecida`].
//! - **Só por quem pode.** Registrar e revogar são operações
//!   administrativas, com prova — `device.register` e `device.revoke`, em
//!   `agent::administracao` —, e a reposição do journal no boot. Nada mais
//!   muda o registro; o `xtask` confere.
//! - **Gravado antes de responder.** A operação muda a memória e a
//!   persistência grava o resultado — a linha da relação, ou a lápide — no
//!   journal, na mesma ordem das gravações; o que foi concedido e não ficou
//!   gravado volta ([`restaurar`]).
//! - **A revogação é o dispositivo inteiro**, e permanente: as relações
//!   saem, a chave ganha a lápide, a suspensão de antes some — ela não volta
//!   a valer para uma chave que não volta —, e o que a revogação desfaz no
//!   enlace e na malha é feito por quem chama, com a lápide já no registro.
//!
//! O registro não decide nada: o gate decide, pela política, com o papel da
//! pessoa local, o da relação e o teto `remoto`.

use alloc::string::String;
use alloc::vec::Vec;

use politica::Codigo;
pub use politica::dispositivos::{Dispositivo, Relacao, TAM_ID};
use politica::dispositivos::{Recusa as RecusaDoRegistro, Registro};

use crate::trava::Mutex;

static REGISTRO: Mutex<Registro> = Mutex::new(Registro::novo());

fn com_registro<R>(f: impl FnOnce(&mut Registro) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut REGISTRO.lock()))
}

/// Por que um registro de dispositivo foi recusado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// A conta do registro recusou.
    Registro(RecusaDoRegistro),
    /// A chave é a deste Duke: ninguém é par de si mesmo.
    ProprioDuke,
    /// A chave é de um agente.
    DeAgente,
    /// A chave é — ou foi — de um administrador.
    DeAdministrador,
}

impl Recusa {
    pub const fn motivo(self) -> &'static str {
        match self {
            Recusa::Registro(r) => r.motivo(),
            Recusa::ProprioDuke => "a chave e a deste Duke: ninguem e par de si mesmo",
            Recusa::DeAgente => "a chave e de um agente: um dispositivo nao e um agente",
            Recusa::DeAdministrador => {
                "a chave e de um administrador: um dispositivo nao e um administrador"
            }
        }
    }

    /// O código da resposta e da auditoria.
    pub const fn codigo(self) -> Codigo {
        match self {
            Recusa::Registro(RecusaDoRegistro::Cheio) => Codigo::Error,
            Recusa::Registro(RecusaDoRegistro::Revogada) => Codigo::DenyPolicy,
            Recusa::Registro(_) => Codigo::InvalidArgument,
            Recusa::ProprioDuke | Recusa::DeAgente | Recusa::DeAdministrador => Codigo::DenyPolicy,
        }
    }
}

impl From<RecusaDoRegistro> for Recusa {
    fn from(r: RecusaDoRegistro) -> Recusa {
        Recusa::Registro(r)
    }
}

/// As conferências que a conta não sabe fazer: a chave não é a deste Duke,
/// nem a de um agente, nem a de um administrador, de agora ou revogado. Cada
/// uma com a trava dela, e nenhuma com a do registro na mão.
fn chave_de_outro_principal(chave: &[u8; 32]) -> Result<(), Recusa> {
    if crate::identidade::publica_do_duke() == Some(*chave) {
        return Err(Recusa::ProprioDuke);
    }
    if crate::identidade::agente(chave).is_some() {
        return Err(Recusa::DeAgente);
    }
    if crate::identidade::administrador(chave).is_some()
        || crate::identidade::administradores_revogados().contains(chave)
    {
        return Err(Recusa::DeAdministrador);
    }
    Ok(())
}

/// Registra a relação `relacao` do dispositivo `chave`, de nome `nome`. Só
/// a operação administrativa chama, depois da prova e da decisão — e com a
/// ordem das gravações na mão, como toda operação que concede: um registro
/// de agente da mesma chave não passa entre a conferência e a inserção.
pub fn registrar(chave: [u8; 32], nome: &str, relacao: Relacao) -> Result<(), Recusa> {
    chave_de_outro_principal(&chave)?;
    com_registro(|r| r.registrar(chave, nome, relacao)).map_err(Recusa::from)
}

/// Revoga o dispositivo `chave`: as relações saem, a chave ganha a lápide,
/// e a suspensão de antes some. Devolve o que saiu. Quem chama desfaz o
/// resto — os enlaces, as entregas — e grava.
pub fn revogar(chave: &[u8; 32]) -> Result<Dispositivo, Recusa> {
    let saiu = com_registro(|r| r.revogar(chave)).map_err(Recusa::from)?;
    crate::contencao::esquecer_dispositivo(chave);
    Ok(saiu)
}

/// Repõe uma relação gravada, no boot: a linha volta igual. Uma relação
/// que a conta recusa — a chave que a lápide, mais adiante no journal, já
/// tinha tirado e um registro mais antigo traz — não é erro do journal: a
/// lápide vence.
pub fn restaurar_linha(linha: &str) -> Result<(), &'static str> {
    let (chave, nome, relacao) =
        politica::dispositivos::ler_linha(linha).map_err(|r| r.motivo())?;
    let _ = com_registro(|r| r.registrar(chave, &nome, relacao));
    Ok(())
}

/// Aplica a lápide de `chave`, no boot: o dispositivo sai, se estava, e a
/// chave não volta.
pub fn aplicar_lapide(chave: &[u8; 32]) {
    com_registro(|r| r.aplicar_lapide(chave));
    crate::contencao::esquecer_dispositivo(chave);
}

/// As relações, achatadas — a chave, o nome e a relação —, para a foto da
/// persistência e para o relatório.
pub fn relacoes() -> Vec<([u8; 32], String, Relacao)> {
    com_registro(|r| {
        r.dispositivos()
            .iter()
            .flat_map(|d| {
                d.relacoes
                    .iter()
                    .map(|rel| (d.chave, d.nome.clone(), rel.clone()))
            })
            .collect()
    })
}

/// As lápides, em ordem.
pub fn lapides() -> Vec<[u8; 32]> {
    com_registro(|r| r.lapides().to_vec())
}

/// Volta o registro às relações de `antes`, mantendo as lápides: o que uma
/// operação que concede pôs e não ficou gravado sai. Uma relação que não
/// está em `antes` sai; uma que está e sumiu não volta — tirar não se
/// desfaz.
pub fn restaurar(antes: &[([u8; 32], String, Relacao)]) {
    com_registro(|r| {
        let lapides = r.lapides().to_vec();
        let mut novo = Registro::novo();
        for (chave, nome, rel) in antes {
            let ainda = r
                .dispositivo(chave)
                .is_some_and(|d| d.relacao(&rel.id).is_some());
            if ainda {
                let _ = novo.registrar(*chave, nome, rel.clone());
            }
        }
        for k in &lapides {
            novo.aplicar_lapide(k);
        }
        *r = novo;
    });
}

/// Se a chave é de um dispositivo, ou tem lápide de um: o registro de
/// agentes a recusa — uma chave, uma espécie de principal.
pub fn conhecida(chave: &[u8; 32]) -> bool {
    com_registro(|r| r.dispositivo(chave).is_some() || r.revogada(chave))
}

/// O dispositivo de chave `chave`.
pub fn dispositivo(chave: &[u8; 32]) -> Option<Dispositivo> {
    com_registro(|r| r.dispositivo(chave).cloned())
}

/// O dispositivo de nome `nome`.
pub fn por_nome(nome: &str) -> Option<Dispositivo> {
    com_registro(|r| r.por_nome(nome).cloned())
}

/// Para o invariante da suíte: o registro nunca quebra as regras dele, e
/// nenhuma chave dele é de outra espécie de principal.
#[cfg(feature = "modo-teste")]
pub fn coerente() -> bool {
    let (coerente, chaves) = com_registro(|r| {
        (
            r.coerente(),
            r.dispositivos().iter().map(|d| d.chave).collect::<Vec<_>>(),
        )
    });
    coerente && chaves.iter().all(|k| chave_de_outro_principal(k).is_ok())
}

/// Só para a suíte: o registro vazio, sem lápides — cada caso começa do
/// zero.
#[cfg(feature = "modo-teste")]
pub fn esquecer_de_teste() {
    com_registro(|r| *r = Registro::novo());
}

/// Destrava o registro, para o caminho de falha fatal.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        REGISTRO.force_unlock();
    }
}
