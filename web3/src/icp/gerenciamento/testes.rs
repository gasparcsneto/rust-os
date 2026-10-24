//! O canister de gerenciamento contra o `ic-management-canister-types`,
//! nos dois sentidos.

use std::borrow::ToOwned;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use ::candid::{CandidType, Decode, Deserialize, Encode, Nat};
use ic_management_canister_types::{
    CanisterIdRecord, CanisterInstallMode, CanisterStatusResult, CanisterStatusType, ChunkHash,
    DefiniteCanisterSettings, InstallChunkedCodeArgs, InstallCodeArgs, MemoryMetrics, QueryStats,
    UploadChunkArgs,
};

use super::*;
use crate::icp::bancada::Sorteio;
use crate::icp::resumo::sha256;

fn oficial(p: &Principal) -> ::candid::Principal {
    ::candid::Principal::from_slice(p.bytes())
}

fn principal_sorteado(s: &mut Sorteio) -> Principal {
    Principal::de_bytes(&s.bytes_ate(29)).unwrap()
}

fn modo_sorteado(s: &mut Sorteio) -> Modo {
    [Modo::Instalar, Modo::Reinstalar, Modo::Atualizar][s.ate(3) as usize]
}

fn modo_oficial(m: Modo) -> CanisterInstallMode {
    match m {
        Modo::Instalar => CanisterInstallMode::Install,
        Modo::Reinstalar => CanisterInstallMode::Reinstall,
        Modo::Atualizar => CanisterInstallMode::Upgrade(None),
    }
}

/// Os valores de uma mensagem, comparáveis: os campos pelo id, e o `blob`
/// como `vec nat8`.
fn lidos(bytes: &[u8]) -> Vec<Valor> {
    fn canonico(v: &Valor) -> Valor {
        match v {
            Valor::Blob(b) => Valor::Vec(b.iter().map(|x| Valor::Nat8(*x)).collect()),
            Valor::Vec(itens) => Valor::Vec(itens.iter().map(canonico).collect()),
            Valor::Opt(Some(v)) => Valor::Opt(Some(std::boxed::Box::new(canonico(v)))),
            Valor::Record(c) => {
                let mut c: Vec<(u32, Valor)> = c.iter().map(|(i, v)| (*i, canonico(v))).collect();
                c.sort_by_key(|(i, _)| *i);
                Valor::Record(c)
            }
            Valor::Variant(i, v) => Valor::Variant(*i, std::boxed::Box::new(canonico(v))),
            outro => outro.clone(),
        }
    }
    candid::decodificar(bytes)
        .unwrap()
        .iter()
        .map(canonico)
        .collect()
}

#[test]
fn a_instalacao_e_a_do_oficial() {
    let mut s = Sorteio::novo(41);
    for _ in 0..300 {
        let modo = modo_sorteado(&mut s);
        let canister = principal_sorteado(&mut s);
        let modulo = s.bytes_ate(2048);
        let arg = s.bytes_ate(64);
        let bytes = argumento_da_instalacao(modo, &canister, &modulo, &arg).unwrap();
        let dele = Decode!(&bytes, InstallCodeArgs).unwrap();
        assert_eq!(dele.mode, modo_oficial(modo));
        assert_eq!(dele.canister_id, oficial(&canister));
        assert_eq!(dele.wasm_module, modulo);
        assert_eq!(dele.arg, arg);
        assert_eq!(dele.sender_canister_version, None);
        assert_eq!(lidos(&Encode!(&dele).unwrap()), lidos(&bytes));
    }
}

#[test]
fn o_pedaco_e_o_do_oficial() {
    let mut s = Sorteio::novo(42);
    for _ in 0..200 {
        let canister = principal_sorteado(&mut s);
        let pedaco = s.bytes_ate(4096);
        let bytes = argumento_do_pedaco(&canister, &pedaco).unwrap();
        let dele = Decode!(&bytes, UploadChunkArgs).unwrap();
        assert_eq!(dele.canister_id, oficial(&canister));
        assert_eq!(dele.chunk, pedaco);
        assert_eq!(lidos(&Encode!(&dele).unwrap()), lidos(&bytes));
        // A resposta: o hash do pedaço, escrito pelo oficial.
        let h = sha256(&pedaco);
        let resposta = Encode!(&ChunkHash { hash: h.to_vec() }).unwrap();
        assert_eq!(ler_pedaco(&resposta), Ok(h));
    }
    // O pedaço de 1 MiB passa; um byte a mais, não se escreve.
    let canister = Principal::de_texto("qpsvj-4l777-77775-qaaaa-cai").unwrap();
    assert!(argumento_do_pedaco(&canister, &vec![0; MAIOR_PEDACO]).is_ok());
    assert_eq!(
        argumento_do_pedaco(&canister, &vec![0; MAIOR_PEDACO + 1]),
        Err(Erro::PedacoGrande)
    );
    // Um hash que não tem 32 bytes não é hash.
    for n in [0usize, 31, 33] {
        let resposta = Encode!(&ChunkHash { hash: vec![1; n] }).unwrap();
        assert_eq!(ler_pedaco(&resposta), Err(Erro::Forma));
    }
}

#[test]
fn a_instalacao_em_pedacos_e_a_do_oficial() {
    let mut s = Sorteio::novo(43);
    for _ in 0..200 {
        let modo = modo_sorteado(&mut s);
        let alvo = principal_sorteado(&mut s);
        let hashes: Vec<Hash> = (0..s.ate(12)).map(|_| sha256(&s.bytes_ate(64))).collect();
        let modulo = sha256(&s.bytes_ate(64));
        let arg = s.bytes_ate(32);
        let bytes =
            argumento_da_instalacao_em_pedacos(modo, &alvo, &hashes, &modulo, &arg).unwrap();
        let dele = Decode!(&bytes, InstallChunkedCodeArgs).unwrap();
        assert_eq!(dele.mode, modo_oficial(modo));
        assert_eq!(dele.target_canister, oficial(&alvo));
        assert_eq!(dele.store_canister, None);
        let dele_hashes: Vec<Vec<u8>> = dele
            .chunk_hashes_list
            .iter()
            .map(|c| c.hash.clone())
            .collect();
        let nossos: Vec<Vec<u8>> = hashes.iter().map(|h| h.to_vec()).collect();
        assert_eq!(dele_hashes, nossos);
        assert_eq!(dele.wasm_module_hash, modulo.to_vec());
        assert_eq!(dele.arg, arg);
        assert_eq!(dele.sender_canister_version, None);
        assert_eq!(lidos(&Encode!(&dele).unwrap()), lidos(&bytes));
    }
}

#[test]
fn o_argumento_do_estado_e_o_do_oficial() {
    let mut s = Sorteio::novo(44);
    for _ in 0..100 {
        let canister = principal_sorteado(&mut s);
        let bytes = argumento_do_estado(&canister);
        let dele = Decode!(&bytes, CanisterIdRecord).unwrap();
        assert_eq!(dele.canister_id, oficial(&canister));
        assert_eq!(lidos(&Encode!(&dele).unwrap()), lidos(&bytes));
    }
}

fn zero() -> Nat {
    Nat::from(0u8)
}

fn estado_oficial(
    status: CanisterStatusType,
    module_hash: Option<Vec<u8>>,
    controllers: Vec<::candid::Principal>,
    cycles: u128,
    memory_size: u128,
) -> CanisterStatusResult {
    CanisterStatusResult {
        status,
        ready_for_migration: false,
        version: 7,
        settings: DefiniteCanisterSettings {
            controllers,
            ..DefiniteCanisterSettings::default()
        },
        module_hash,
        memory_size: Nat::from(memory_size),
        memory_metrics: MemoryMetrics {
            wasm_memory_size: zero(),
            stable_memory_size: zero(),
            global_memory_size: zero(),
            wasm_binary_size: zero(),
            custom_sections_size: zero(),
            canister_history_size: zero(),
            wasm_chunk_store_size: zero(),
            snapshots_size: zero(),
            log_memory_store_size: zero(),
        },
        cycles: Nat::from(cycles),
        reserved_cycles: zero(),
        idle_cycles_burned_per_day: zero(),
        query_stats: QueryStats {
            num_calls_total: zero(),
            num_instructions_total: zero(),
            request_payload_bytes_total: zero(),
            response_payload_bytes_total: zero(),
        },
    }
}

#[test]
fn o_estado_escrito_pelo_oficial() {
    let mut s = Sorteio::novo(45);
    let situacoes = [
        (CanisterStatusType::Running, Situacao::Rodando),
        (CanisterStatusType::Stopping, Situacao::Parando),
        (CanisterStatusType::Stopped, Situacao::Parado),
    ];
    for _ in 0..200 {
        let (oficial_status, situacao) = situacoes[s.ate(3) as usize];
        let modulo = (s.ate(2) == 1).then(|| sha256(&s.bytes_ate(16)));
        let controladores: Vec<Principal> =
            (0..s.ate(11)).map(|_| principal_sorteado(&mut s)).collect();
        let cycles = u128::MAX >> s.ate(128);
        let memoria = u128::from(s.proximo());
        let dele = estado_oficial(
            oficial_status,
            modulo.map(|h| h.to_vec()),
            controladores.iter().map(oficial).collect(),
            cycles,
            memoria,
        );
        let estado = ler_estado(&Encode!(&dele).unwrap()).unwrap();
        assert_eq!(
            estado,
            Estado {
                situacao,
                modulo,
                controladores,
                cycles,
                memoria,
            }
        );
    }
}

/// O estado de uma interface que tem campos a mais ou a menos que a do
/// oficial — a da PocketIC da bancada tem outros —: os campos que esta
/// leitura usa, pelo nome; os outros não atrapalham. Um campo que falta, ou
/// fora do tipo, é recusado.
#[test]
fn o_estado_de_outra_versao_da_interface() {
    #[derive(CandidType, Deserialize)]
    struct Ajustes {
        controllers: Vec<::candid::Principal>,
        novo: Option<String>,
    }
    #[derive(CandidType, Deserialize)]
    enum Status {
        #[serde(rename = "running")]
        Running,
    }
    #[derive(CandidType, Deserialize)]
    struct Enxuto {
        status: Status,
        settings: Ajustes,
        module_hash: Option<serde_bytes::ByteBuf>,
        memory_size: Nat,
        cycles: Nat,
        balance: Vec<(serde_bytes::ByteBuf, Nat)>,
    }
    let dono = ::candid::Principal::from_slice(&[1, 2, 3]);
    let enxuto = Enxuto {
        status: Status::Running,
        settings: Ajustes {
            controllers: vec![dono],
            novo: Some("x".to_owned()),
        },
        module_hash: None,
        memory_size: Nat::from(12_510u32),
        cycles: Nat::from(2_499_998_434_000u64),
        balance: vec![(serde_bytes::ByteBuf::from(vec![0]), Nat::from(1u8))],
    };
    let estado = ler_estado(&Encode!(&enxuto).unwrap()).unwrap();
    assert_eq!(estado.situacao, Situacao::Rodando);
    assert_eq!(estado.modulo, None);
    assert_eq!(
        estado.controladores,
        vec![Principal::de_bytes(&[1, 2, 3]).unwrap()]
    );
    assert_eq!(estado.cycles, 2_499_998_434_000);
    assert_eq!(estado.memoria, 12_510);

    // Sem o hash do módulo: fora da forma.
    #[derive(CandidType, Deserialize)]
    struct SemModulo {
        status: Status,
        settings: Ajustes,
        memory_size: Nat,
        cycles: Nat,
    }
    let sem = SemModulo {
        status: Status::Running,
        settings: Ajustes {
            controllers: vec![],
            novo: None,
        },
        memory_size: zero(),
        cycles: zero(),
    };
    assert_eq!(ler_estado(&Encode!(&sem).unwrap()), Err(Erro::Forma));

    // Uma situação que a interface não tem.
    #[derive(CandidType, Deserialize)]
    enum Outra {
        #[serde(rename = "migrating")]
        Migrating,
    }
    #[derive(CandidType, Deserialize)]
    struct ComOutra {
        status: Outra,
        settings: Ajustes,
        module_hash: Option<serde_bytes::ByteBuf>,
        memory_size: Nat,
        cycles: Nat,
    }
    let outra = ComOutra {
        status: Outra::Migrating,
        settings: Ajustes {
            controllers: vec![],
            novo: None,
        },
        module_hash: None,
        memory_size: zero(),
        cycles: zero(),
    };
    assert_eq!(ler_estado(&Encode!(&outra).unwrap()), Err(Erro::Forma));

    // O hash do módulo que não tem 32 bytes; os cycles que não são `nat`.
    let curto = estado_oficial(CanisterStatusType::Running, Some(vec![1; 31]), vec![], 1, 1);
    assert_eq!(ler_estado(&Encode!(&curto).unwrap()), Err(Erro::Forma));
    #[derive(CandidType, Deserialize)]
    struct CyclesTexto {
        status: Status,
        settings: Ajustes,
        module_hash: Option<serde_bytes::ByteBuf>,
        memory_size: Nat,
        cycles: String,
    }
    let texto = CyclesTexto {
        status: Status::Running,
        settings: Ajustes {
            controllers: vec![],
            novo: None,
        },
        module_hash: None,
        memory_size: zero(),
        cycles: "muitos".to_owned(),
    };
    assert_eq!(ler_estado(&Encode!(&texto).unwrap()), Err(Erro::Forma));
}

/// A resposta de `install_code`: `()`; com um valor, fora da forma.
#[test]
fn a_resposta_vazia() {
    assert_eq!(ler_vazio(&Encode!().unwrap()), Ok(()));
    assert_eq!(ler_vazio(&Encode!(&1u8).unwrap()), Err(Erro::Forma));
    assert!(matches!(ler_vazio(b"DIDX\x00\x00"), Err(Erro::Candid(_))));
}

/// Os pedaços de um módulo: na ordem, do tamanho pedido, e juntos são o
/// módulo; o tamanho fica entre 1 e o maior pedaço.
#[test]
fn os_pedacos_de_um_modulo() {
    let mut s = Sorteio::novo(46);
    for _ in 0..100 {
        let modulo = s.bytes_ate(3000);
        let tamanho = 1 + s.ate(400) as usize;
        let partes: Vec<&[u8]> = pedacos(&modulo, tamanho).collect();
        assert_eq!(partes.concat(), modulo);
        assert!(partes.iter().all(|p| !p.is_empty() && p.len() <= tamanho));
        assert_eq!(partes.len(), modulo.len().div_ceil(tamanho));
    }
    assert_eq!(pedacos(b"abc", 0).count(), 3);
    assert_eq!(pedacos(&vec![0; MAIOR_PEDACO + 1], usize::MAX).count(), 2);
}

#[test]
fn as_mensagens_sao_ascii() {
    for e in [
        Erro::PedacoGrande,
        Erro::Escrita(ErroDaEscrita::Grande),
        Erro::Candid(candid::Erro::Truncado),
        Erro::Forma,
    ] {
        assert!(e.to_string().is_ascii());
    }
    for s in [Situacao::Rodando, Situacao::Parando, Situacao::Parado] {
        assert!(s.nome().is_ascii());
    }
}
