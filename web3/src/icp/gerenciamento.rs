//! O canister de gerenciamento (`aaaaa-aa`) — **especificação**: a
//! *IC management canister interface*; **referência**:
//! `ic-management-canister-types` 0.11.0 —: o argumento e o resultado dos
//! métodos que instalam e leem um canister, em Candid.
//!
//! - [`argumento_da_instalacao`] escreve o de `install_code`: o modo, o
//!   canister, o módulo inteiro e o argumento de quem o recebe;
//! - [`argumento_do_pedaco`] e [`ler_pedaco`], o de `upload_chunk` e o hash
//!   que ele devolve — um pedaço de até [`MAIOR_PEDACO`] bytes, guardado
//!   no canister;
//! - [`argumento_da_instalacao_em_pedacos`], o de `install_chunked_code`:
//!   os hashes dos pedaços, em ordem, e o do módulo inteiro;
//! - [`argumento_do_estado`] e [`ler_estado`], o de `canister_status` e o
//!   estado: a situação, o hash do módulo, os controladores, o limiar de
//!   congelamento, os cycles e a memória — os campos pelo nome; os que esta
//!   leitura não usa, e os que a interface ganhar, não atrapalham;
//! - [`argumento_do_canister`], o dos métodos que só levam o canister:
//!   `start_canister`, `stop_canister`, `delete_canister` e
//!   `clear_chunk_store` — e o próprio `canister_status`;
//! - [`argumento_da_desinstalacao`], o de `uninstall_code`;
//! - [`argumento_dos_ajustes`], o de `update_settings`, com os
//!   [`Ajustes`] que se mudam: os controladores, até
//!   [`MAIS_CONTROLADORES`], e o limiar de congelamento. O que não se
//!   muda não vai: na interface, cada ajuste é opcional, e o ausente fica
//!   como estava.
//!
//! O que não tem a forma da interface é recusado. A chamada vai pela
//! [`super::atualizacao::chamar_ao_gerenciamento`], com o canister efetivo
//! — o canister que o método gerencia. Nada aqui assina, conecta ou
//! verifica.
//!
//! # Os modos
//!
//! [`Modo::Instalar`] só serve a um canister vazio: num canister com
//! módulo, o IC recusa. [`Modo::Atualizar`] troca o módulo e guarda a
//! memória estável do canister. [`Modo::Reinstalar`] troca o módulo e
//! **apaga** o estado — a memória estável inclusive.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use super::candid::{self, ErroDaEscrita, Primitivo, Tipo, Valor};
use super::principal::Principal;
use super::resumo::Hash;

/// O maior pedaço que o IC guarda: 1 MiB.
pub const MAIOR_PEDACO: usize = 1024 * 1024;

/// Quantos controladores um canister tem, no máximo — **especificação**:
/// "a list of at most 10 principals".
pub const MAIS_CONTROLADORES: usize = 10;

/// O modo de uma instalação — `canister_install_mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modo {
    /// `install`: o canister vazio recebe o módulo.
    Instalar,
    /// `reinstall`: troca o módulo e apaga o estado.
    Reinstalar,
    /// `upgrade`, sem as opções: troca o módulo e guarda a memória
    /// estável.
    Atualizar,
}

/// A situação de um canister — `canister_status_type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Situacao {
    /// `running`.
    Rodando,
    /// `stopping`.
    Parando,
    /// `stopped`.
    Parado,
}

impl Situacao {
    /// O nome da interface.
    pub fn nome(self) -> &'static str {
        match self {
            Situacao::Rodando => "running",
            Situacao::Parando => "stopping",
            Situacao::Parado => "stopped",
        }
    }
}

/// O estado de um canister — o que esta leitura usa do
/// `canister_status_result`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Estado {
    /// A situação.
    pub situacao: Situacao,
    /// O SHA-256 do módulo instalado; nenhum, no canister vazio.
    pub modulo: Option<Hash>,
    /// Os controladores.
    pub controladores: Vec<Principal>,
    /// O limiar de congelamento, em segundos; nenhum, numa interface que
    /// não o diz.
    pub congelamento: Option<u128>,
    /// Os cycles do canister.
    pub cycles: u128,
    /// A memória que o canister ocupa, em bytes.
    pub memoria: u128,
}

/// Por que um argumento não se escreve, ou uma resposta não se lê.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// Um pedaço de mais de [`MAIOR_PEDACO`] bytes: o IC o recusaria.
    PedacoGrande,
    /// Mais de [`MAIS_CONTROLADORES`] controladores: o IC os recusaria.
    MuitosControladores,
    /// O argumento passa dos tetos da escrita.
    Escrita(ErroDaEscrita),
    /// A resposta não é Candid.
    Candid(candid::Erro),
    /// A resposta é Candid, mas não tem a forma da interface.
    Forma,
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Erro::PedacoGrande => f.write_str("pedaco maior que 1 MiB"),
            Erro::MuitosControladores => f.write_str("mais de 10 controladores"),
            Erro::Escrita(e) => write!(f, "{e}"),
            Erro::Candid(e) => write!(f, "{e}"),
            Erro::Forma => f.write_str("resposta fora da forma do gerenciamento"),
        }
    }
}

/// `canister_install_mode`: `variant { install; reinstall; upgrade : opt
/// record { skip_pre_upgrade : opt bool; wasm_memory_persistence : opt
/// variant { keep; replace } } }`.
fn tipo_do_modo() -> Tipo {
    let persistencia = Tipo::variant([
        ("keep", Primitivo::Null.into()),
        ("replace", Primitivo::Null.into()),
    ]);
    let opcoes = Tipo::record([
        ("skip_pre_upgrade", Tipo::opt(Primitivo::Bool)),
        ("wasm_memory_persistence", Tipo::opt(persistencia)),
    ]);
    Tipo::variant([
        ("install", Primitivo::Null.into()),
        ("reinstall", Primitivo::Null.into()),
        ("upgrade", Tipo::opt(opcoes)),
    ])
}

fn valor_do_modo(modo: Modo) -> Valor {
    let (nome, dentro) = match modo {
        Modo::Instalar => ("install", Valor::Null),
        Modo::Reinstalar => ("reinstall", Valor::Null),
        Modo::Atualizar => ("upgrade", Valor::Opt(None)),
    };
    Valor::Variant(candid::id_do_campo(nome), Box::new(dentro))
}

/// Um campo pelo nome.
fn campo(nome: &str, v: Valor) -> (u32, Valor) {
    (candid::id_do_campo(nome), v)
}

/// Um argumento dos tipos daqui.
fn escrever(tipo: Tipo, valor: Valor) -> Result<Vec<u8>, Erro> {
    candid::codificar_com_tipos(&[tipo], &[valor]).map_err(Erro::Escrita)
}

/// Escreve o argumento de `install_code`: `(install_code_args)`.
pub fn argumento_da_instalacao(
    modo: Modo,
    canister: &Principal,
    modulo: &[u8],
    arg: &[u8],
) -> Result<Vec<u8>, Erro> {
    let tipo = Tipo::record([
        ("mode", tipo_do_modo()),
        ("canister_id", Primitivo::Principal.into()),
        ("wasm_module", Tipo::blob()),
        ("arg", Tipo::blob()),
        ("sender_canister_version", Tipo::opt(Primitivo::Nat64)),
    ]);
    let valor = Valor::Record(alloc::vec![
        campo("mode", valor_do_modo(modo)),
        campo("canister_id", Valor::Principal(*canister)),
        campo("wasm_module", Valor::Blob(Vec::from(modulo))),
        campo("arg", Valor::Blob(Vec::from(arg))),
        campo("sender_canister_version", Valor::Opt(None)),
    ]);
    escrever(tipo, valor)
}

/// Escreve o argumento de `upload_chunk`: `(upload_chunk_args)`.
pub fn argumento_do_pedaco(canister: &Principal, pedaco: &[u8]) -> Result<Vec<u8>, Erro> {
    if pedaco.len() > MAIOR_PEDACO {
        return Err(Erro::PedacoGrande);
    }
    let tipo = Tipo::record([
        ("canister_id", Primitivo::Principal.into()),
        ("chunk", Tipo::blob()),
    ]);
    let valor = Valor::Record(alloc::vec![
        campo("canister_id", Valor::Principal(*canister)),
        campo("chunk", Valor::Blob(Vec::from(pedaco))),
    ]);
    escrever(tipo, valor)
}

/// `chunk_hash`: `record { hash : blob }`.
fn tipo_do_hash() -> Tipo {
    Tipo::record([("hash", Tipo::blob())])
}

fn valor_do_hash(h: &Hash) -> Valor {
    Valor::Record(alloc::vec![campo("hash", Valor::Blob(Vec::from(h)))])
}

/// Escreve o argumento de `install_chunked_code`:
/// `(install_chunked_code_args)` — os pedaços guardados no próprio
/// `alvo`, os hashes deles na ordem do módulo, e o hash do módulo inteiro.
pub fn argumento_da_instalacao_em_pedacos(
    modo: Modo,
    alvo: &Principal,
    hashes: &[Hash],
    modulo: &Hash,
    arg: &[u8],
) -> Result<Vec<u8>, Erro> {
    let tipo = Tipo::record([
        ("mode", tipo_do_modo()),
        ("target_canister", Primitivo::Principal.into()),
        ("store_canister", Tipo::opt(Primitivo::Principal)),
        ("chunk_hashes_list", Tipo::vec(tipo_do_hash())),
        ("wasm_module_hash", Tipo::blob()),
        ("arg", Tipo::blob()),
        ("sender_canister_version", Tipo::opt(Primitivo::Nat64)),
    ]);
    let valor = Valor::Record(alloc::vec![
        campo("mode", valor_do_modo(modo)),
        campo("target_canister", Valor::Principal(*alvo)),
        campo("store_canister", Valor::Opt(None)),
        campo(
            "chunk_hashes_list",
            Valor::Vec(hashes.iter().map(valor_do_hash).collect()),
        ),
        campo("wasm_module_hash", Valor::Blob(Vec::from(modulo))),
        campo("arg", Valor::Blob(Vec::from(arg))),
        campo("sender_canister_version", Valor::Opt(None)),
    ]);
    escrever(tipo, valor)
}

/// Escreve o argumento de `canister_status`: `(record { canister_id :
/// principal })` — o de [`argumento_do_canister`].
pub fn argumento_do_estado(canister: &Principal) -> Vec<u8> {
    argumento_do_canister(canister)
}

/// Escreve o argumento dos métodos que só levam o canister —
/// `canister_status`, `start_canister`, `stop_canister`, `delete_canister`
/// e `clear_chunk_store`: `(record { canister_id : principal })`.
pub fn argumento_do_canister(canister: &Principal) -> Vec<u8> {
    let tipo = Tipo::record([("canister_id", Primitivo::Principal.into())]);
    let valor = Valor::Record(alloc::vec![campo(
        "canister_id",
        Valor::Principal(*canister)
    )]);
    escrever(tipo, valor).expect("o valor e do tipo daqui")
}

/// Escreve o argumento de `uninstall_code`: `(record { canister_id :
/// principal; sender_canister_version : opt nat64 })`. O canister fica
/// sem módulo e sem estado — a memória estável inclusive.
pub fn argumento_da_desinstalacao(canister: &Principal) -> Vec<u8> {
    let tipo = Tipo::record([
        ("canister_id", Primitivo::Principal.into()),
        ("sender_canister_version", Tipo::opt(Primitivo::Nat64)),
    ]);
    let valor = Valor::Record(alloc::vec![
        campo("canister_id", Valor::Principal(*canister)),
        campo("sender_canister_version", Valor::Opt(None)),
    ]);
    escrever(tipo, valor).expect("o valor e do tipo daqui")
}

/// Os ajustes que um `update_settings` muda — a parte de
/// `canister_settings` que se usa aqui. `None` é "não muda".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ajustes {
    /// Os controladores, que **substituem** os de agora: até
    /// [`MAIS_CONTROLADORES`]. Quem não estiver na lista deixa de
    /// controlar o canister.
    pub controladores: Option<Vec<Principal>>,
    /// O limiar de congelamento, em segundos: o canister que não teria
    /// cycles para tanto tempo para de executar, em vez de se esgotar.
    pub congelamento: Option<u64>,
}

/// Escreve o argumento de `update_settings`: `(record { canister_id :
/// principal; settings : canister_settings; sender_canister_version : opt
/// nat64 })`, com só os ajustes dados em `canister_settings`. Na
/// interface, cada ajuste é `opt`, e o campo que falta se lê como `null`
/// — "não muda".
pub fn argumento_dos_ajustes(canister: &Principal, ajustes: &Ajustes) -> Result<Vec<u8>, Erro> {
    if ajustes
        .controladores
        .as_ref()
        .is_some_and(|c| c.len() > MAIS_CONTROLADORES)
    {
        return Err(Erro::MuitosControladores);
    }
    let mut tipos = Vec::new();
    let mut valores = Vec::new();
    if let Some(cs) = &ajustes.controladores {
        tipos.push(("controllers", Tipo::opt(Tipo::vec(Primitivo::Principal))));
        valores.push(campo(
            "controllers",
            Valor::Opt(Some(Box::new(Valor::Vec(
                cs.iter().map(|c| Valor::Principal(*c)).collect(),
            )))),
        ));
    }
    if let Some(segundos) = ajustes.congelamento {
        tipos.push(("freezing_threshold", Tipo::opt(Primitivo::Nat)));
        valores.push(campo(
            "freezing_threshold",
            Valor::Opt(Some(Box::new(Valor::Nat(u128::from(segundos))))),
        ));
    }
    let tipo = Tipo::record([
        ("canister_id", Primitivo::Principal.into()),
        ("settings", Tipo::record(tipos)),
        ("sender_canister_version", Tipo::opt(Primitivo::Nat64)),
    ]);
    let valor = Valor::Record(alloc::vec![
        campo("canister_id", Valor::Principal(*canister)),
        campo("settings", Valor::Record(valores)),
        campo("sender_canister_version", Valor::Opt(None)),
    ]);
    escrever(tipo, valor)
}

/// Os pedaços de um módulo, de até `tamanho` bytes cada — de 1 até
/// [`MAIOR_PEDACO`] —, na ordem dele.
pub fn pedacos(modulo: &[u8], tamanho: usize) -> core::slice::Chunks<'_, u8> {
    modulo.chunks(tamanho.clamp(1, MAIOR_PEDACO))
}

/// O único valor de uma resposta.
fn unico(resposta: &[u8]) -> Result<Valor, Erro> {
    let mut valores = candid::decodificar(resposta).map_err(Erro::Candid)?;
    match valores.len() {
        1 => Ok(valores.remove(0)),
        _ => Err(Erro::Forma),
    }
}

/// Um hash de 32 bytes.
fn hash(v: Option<&Valor>) -> Result<Hash, Erro> {
    match v {
        Some(Valor::Blob(b)) => b.as_slice().try_into().map_err(|_| Erro::Forma),
        _ => Err(Erro::Forma),
    }
}

/// Um `nat`.
fn nat(v: Option<&Valor>) -> Result<u128, Erro> {
    match v {
        Some(Valor::Nat(n)) => Ok(*n),
        _ => Err(Erro::Forma),
    }
}

/// Lê a resposta de `install_code`, de `install_chunked_code` e dos
/// métodos que não devolvem nada — `start_canister`, `stop_canister`,
/// `delete_canister`, `uninstall_code`, `update_settings` e
/// `clear_chunk_store`: `()`.
pub fn ler_vazio(resposta: &[u8]) -> Result<(), Erro> {
    let valores = candid::decodificar(resposta).map_err(Erro::Candid)?;
    if valores.is_empty() {
        Ok(())
    } else {
        Err(Erro::Forma)
    }
}

/// Lê a resposta de `upload_chunk`: `(record { hash : blob })` — o
/// SHA-256 do pedaço guardado.
pub fn ler_pedaco(resposta: &[u8]) -> Result<Hash, Erro> {
    hash(unico(resposta)?.campo("hash"))
}

/// Lê a resposta de `canister_status`: `(canister_status_result)`.
pub fn ler_estado(resposta: &[u8]) -> Result<Estado, Erro> {
    let v = unico(resposta)?;
    let s = v.campo("status").ok_or(Erro::Forma)?;
    let situacao = if s.caso("running").is_some() {
        Situacao::Rodando
    } else if s.caso("stopping").is_some() {
        Situacao::Parando
    } else if s.caso("stopped").is_some() {
        Situacao::Parado
    } else {
        return Err(Erro::Forma);
    };
    let modulo = match v.campo("module_hash") {
        Some(Valor::Opt(None)) => None,
        Some(Valor::Opt(Some(h))) => Some(hash(Some(h))?),
        _ => return Err(Erro::Forma),
    };
    let controladores = match v.campo("settings").and_then(|s| s.campo("controllers")) {
        Some(Valor::Vec(cs)) => cs
            .iter()
            .map(|c| match c {
                Valor::Principal(p) => Ok(*p),
                _ => Err(Erro::Forma),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(Erro::Forma),
    };
    let congelamento = match v
        .campo("settings")
        .and_then(|s| s.campo("freezing_threshold"))
    {
        None => None,
        Some(Valor::Nat(n)) => Some(*n),
        Some(_) => return Err(Erro::Forma),
    };
    Ok(Estado {
        situacao,
        modulo,
        controladores,
        congelamento,
        cycles: nat(v.campo("cycles"))?,
        memoria: nat(v.campo("memory_size"))?,
    })
}

#[cfg(test)]
mod testes;
