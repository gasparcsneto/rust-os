//! O ledger de cycles contra a interface dele (`cycles-ledger.did`),
//! declarada aqui com o `candid`: não há crate oficial publicado com os
//! tipos. A bancada confere o mesmo contra o ledger de verdade, o da
//! PocketIC.

use std::borrow::ToOwned;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use ::candid::{CandidType, Decode, Deserialize, Encode, Nat};
use serde_bytes::ByteBuf;

use super::*;
use crate::icp::bancada::Sorteio;

#[derive(CandidType, Deserialize, Debug)]
enum LogVisibility {
    #[serde(rename = "controllers")]
    Controllers,
    #[serde(rename = "public")]
    Public,
}

#[derive(CandidType, Deserialize, Debug)]
struct CanisterSettings {
    controllers: Option<Vec<::candid::Principal>>,
    compute_allocation: Option<Nat>,
    memory_allocation: Option<Nat>,
    freezing_threshold: Option<Nat>,
    reserved_cycles_limit: Option<Nat>,
    log_visibility: Option<LogVisibility>,
    wasm_memory_limit: Option<Nat>,
    wasm_memory_threshold: Option<Nat>,
}

#[derive(CandidType, Deserialize, Debug)]
struct SubnetFilter {
    subnet_type: Option<String>,
}

#[derive(CandidType, Deserialize, Debug)]
enum SubnetSelection {
    Subnet { subnet: ::candid::Principal },
    Filter(SubnetFilter),
}

#[derive(CandidType, Deserialize, Debug)]
struct CmcCreateCanisterArgs {
    settings: Option<CanisterSettings>,
    subnet_selection: Option<SubnetSelection>,
}

#[derive(CandidType, Deserialize, Debug)]
struct CreateCanisterArgs {
    from_subaccount: Option<ByteBuf>,
    created_at_time: Option<u64>,
    amount: Nat,
    creation_args: Option<CmcCreateCanisterArgs>,
}

#[derive(CandidType, Deserialize)]
struct CreateCanisterSuccess {
    block_id: Nat,
    canister_id: ::candid::Principal,
}

#[derive(CandidType, Deserialize)]
enum CreateCanisterError {
    InsufficientFunds {
        balance: Nat,
    },
    TooOld,
    CreatedInFuture {
        ledger_time: u64,
    },
    TemporarilyUnavailable,
    Duplicate {
        duplicate_of: Nat,
        canister_id: Option<::candid::Principal>,
    },
    FailedToCreate {
        fee_block: Option<Nat>,
        refund_block: Option<Nat>,
        error: String,
    },
    GenericError {
        message: String,
        error_code: Nat,
    },
}

#[derive(CandidType, Deserialize, Debug)]
struct WithdrawArgs {
    from_subaccount: Option<ByteBuf>,
    to: ::candid::Principal,
    created_at_time: Option<u64>,
    amount: Nat,
}

#[derive(CandidType, Deserialize)]
enum RejectionCode {
    NoError,
    CanisterError,
    SysTransient,
    DestinationInvalid,
    Unknown,
    SysFatal,
    CanisterReject,
}

#[derive(CandidType, Deserialize)]
enum WithdrawError {
    BadFee {
        expected_fee: Nat,
    },
    InsufficientFunds {
        balance: Nat,
    },
    TooOld,
    CreatedInFuture {
        ledger_time: u64,
    },
    TemporarilyUnavailable,
    Duplicate {
        duplicate_of: Nat,
    },
    FailedToWithdraw {
        fee_block: Option<Nat>,
        rejection_code: RejectionCode,
        rejection_reason: String,
    },
    GenericError {
        error_code: Nat,
        message: String,
    },
    InvalidReceiver {
        receiver: ::candid::Principal,
    },
}

fn oficial(p: &Principal) -> ::candid::Principal {
    ::candid::Principal::from_slice(p.bytes())
}

fn principal_sorteado(s: &mut Sorteio) -> Principal {
    Principal::de_bytes(&s.bytes_ate(29)).unwrap()
}

#[test]
fn a_criacao_e_a_da_interface() {
    let mut s = Sorteio::novo(51);
    for _ in 0..300 {
        let c = Criacao {
            quantia: u128::MAX >> s.ate(128),
            criada_em_ns: (s.ate(2) == 1).then(|| s.proximo()),
            controladores: (s.ate(2) == 1).then(|| {
                (0..s.ate(MAIS_CONTROLADORES as u64 + 1))
                    .map(|_| principal_sorteado(&mut s))
                    .collect()
            }),
        };
        let bytes = argumento_da_criacao(&c).unwrap();
        // A interface lê o que se escreveu aqui: os campos dos ajustes que
        // ficaram de fora, e a escolha da sub-rede, ausentes.
        let dele = Decode!(&bytes, CreateCanisterArgs).unwrap();
        assert!(dele.from_subaccount.is_none());
        assert_eq!(dele.created_at_time, c.criada_em_ns);
        assert_eq!(dele.amount, Nat::from(c.quantia));
        match (&c.controladores, dele.creation_args) {
            (None, None) => {}
            (Some(cs), Some(a)) => {
                assert!(a.subnet_selection.is_none());
                let ajustes = a.settings.unwrap();
                let deles = ajustes.controllers.unwrap();
                assert_eq!(deles, cs.iter().map(oficial).collect::<Vec<_>>());
                assert!(ajustes.compute_allocation.is_none());
                assert!(ajustes.freezing_threshold.is_none());
                assert!(ajustes.log_visibility.is_none());
                assert!(ajustes.wasm_memory_limit.is_none());
            }
            outro => panic!("{outro:?}"),
        }
    }
    // Onze controladores não se escrevem.
    let onze = Criacao {
        quantia: 1,
        criada_em_ns: None,
        controladores: Some(vec![Principal::ANONIMO; MAIS_CONTROLADORES + 1]),
    };
    assert_eq!(argumento_da_criacao(&onze), Err(Erro::Controladores));
}

type ResultadoDaCriacao = Result<CreateCanisterSuccess, CreateCanisterError>;

#[test]
fn a_resposta_da_criacao_escrita_pela_interface() {
    let canister = ::candid::Principal::from_text("qpsvj-4l777-77775-qaaaa-cai").unwrap();
    let nosso = Principal::de_texto("qpsvj-4l777-77775-qaaaa-cai").unwrap();
    let ok: ResultadoDaCriacao = Ok(CreateCanisterSuccess {
        block_id: Nat::from(2u8),
        canister_id: canister,
    });
    assert_eq!(
        ler_criacao(&Encode!(&ok).unwrap()),
        Ok(Ok(Criado {
            bloco: 2,
            canister: nosso,
        }))
    );
    let casos: Vec<(CreateCanisterError, RecusaDaCriacao)> = vec![
        (
            CreateCanisterError::InsufficientFunds {
                balance: Nat::from(5u8),
            },
            RecusaDaCriacao::SemFundos { saldo: 5 },
        ),
        (CreateCanisterError::TooOld, RecusaDaCriacao::Velha),
        (
            CreateCanisterError::CreatedInFuture { ledger_time: 9 },
            RecusaDaCriacao::NoFuturo {
                hora_do_ledger_ns: 9,
            },
        ),
        (
            CreateCanisterError::TemporarilyUnavailable,
            RecusaDaCriacao::Indisponivel,
        ),
        (
            CreateCanisterError::Duplicate {
                duplicate_of: Nat::from(2u8),
                canister_id: Some(canister),
            },
            RecusaDaCriacao::Duplicada {
                bloco: 2,
                canister: Some(nosso),
            },
        ),
        (
            CreateCanisterError::Duplicate {
                duplicate_of: Nat::from(3u8),
                canister_id: None,
            },
            RecusaDaCriacao::Duplicada {
                bloco: 3,
                canister: None,
            },
        ),
        (
            CreateCanisterError::FailedToCreate {
                fee_block: Some(Nat::from(4u8)),
                refund_block: None,
                error: "sem sub-rede".to_owned(),
            },
            RecusaDaCriacao::NaoCriou {
                bloco_da_taxa: Some(4),
                bloco_da_devolucao: None,
                motivo: "sem sub-rede".to_owned(),
            },
        ),
        (
            CreateCanisterError::GenericError {
                message: "nao".to_owned(),
                error_code: Nat::from(7u8),
            },
            RecusaDaCriacao::Generica {
                codigo: 7,
                mensagem: "nao".to_owned(),
            },
        ),
    ];
    for (dela, nossa) in casos {
        let r: ResultadoDaCriacao = Err(dela);
        assert_eq!(ler_criacao(&Encode!(&r).unwrap()), Ok(Err(nossa)));
    }
}

#[test]
fn a_carga_e_a_da_interface() {
    let mut s = Sorteio::novo(52);
    for _ in 0..200 {
        let c = Carga {
            para: principal_sorteado(&mut s),
            quantia: u128::MAX >> s.ate(128),
            criada_em_ns: (s.ate(2) == 1).then(|| s.proximo()),
        };
        let dele = Decode!(&argumento_da_carga(&c), WithdrawArgs).unwrap();
        assert!(dele.from_subaccount.is_none());
        assert_eq!(dele.to, oficial(&c.para));
        assert_eq!(dele.created_at_time, c.criada_em_ns);
        assert_eq!(dele.amount, Nat::from(c.quantia));
    }
}

type ResultadoDaCarga = Result<Nat, WithdrawError>;

#[test]
fn a_resposta_da_carga_escrita_pela_interface() {
    let ok: ResultadoDaCarga = Ok(Nat::from(3u8));
    assert_eq!(ler_carga(&Encode!(&ok).unwrap()), Ok(Ok(3)));
    let quem = ::candid::Principal::from_slice(&[9; 29]);
    let casos: Vec<(WithdrawError, RecusaDaCarga)> = vec![
        (
            WithdrawError::BadFee {
                expected_fee: Nat::from(100_000_000u32),
            },
            RecusaDaCarga::TaxaErrada {
                esperada: 100_000_000,
            },
        ),
        (
            WithdrawError::InsufficientFunds {
                balance: Nat::from(1u8),
            },
            RecusaDaCarga::SemFundos { saldo: 1 },
        ),
        (WithdrawError::TooOld, RecusaDaCarga::Velha),
        (
            WithdrawError::CreatedInFuture { ledger_time: 5 },
            RecusaDaCarga::NoFuturo {
                hora_do_ledger_ns: 5,
            },
        ),
        (
            WithdrawError::TemporarilyUnavailable,
            RecusaDaCarga::Indisponivel,
        ),
        (
            WithdrawError::Duplicate {
                duplicate_of: Nat::from(3u8),
            },
            RecusaDaCarga::Duplicada { bloco: 3 },
        ),
        (
            WithdrawError::FailedToWithdraw {
                fee_block: None,
                rejection_code: RejectionCode::DestinationInvalid,
                rejection_reason: "nao achou".to_owned(),
            },
            RecusaDaCarga::NaoCarregou {
                bloco_da_taxa: None,
                motivo: "nao achou".to_owned(),
            },
        ),
        (
            WithdrawError::GenericError {
                error_code: Nat::from(1u8),
                message: "x".to_owned(),
            },
            RecusaDaCarga::Generica {
                codigo: 1,
                mensagem: "x".to_owned(),
            },
        ),
        (
            WithdrawError::InvalidReceiver { receiver: quem },
            RecusaDaCarga::DestinoInvalido {
                destino: Principal::de_bytes(&[9; 29]).unwrap(),
            },
        ),
    ];
    for (dela, nossa) in casos {
        let r: ResultadoDaCarga = Err(dela);
        assert_eq!(ler_carga(&Encode!(&r).unwrap()), Ok(Err(nossa)));
    }
    // Os códigos de recusa que não se usam aqui também se leem.
    for codigo in [
        RejectionCode::NoError,
        RejectionCode::CanisterError,
        RejectionCode::SysTransient,
        RejectionCode::Unknown,
        RejectionCode::SysFatal,
        RejectionCode::CanisterReject,
    ] {
        let r: ResultadoDaCarga = Err(WithdrawError::FailedToWithdraw {
            fee_block: Some(Nat::from(2u8)),
            rejection_code: codigo,
            rejection_reason: String::new(),
        });
        assert!(matches!(
            ler_carga(&Encode!(&r).unwrap()),
            Ok(Err(RecusaDaCarga::NaoCarregou {
                bloco_da_taxa: Some(2),
                ..
            }))
        ));
    }
}

/// O que não tem a forma da interface nunca vira canister nem bloco.
#[test]
fn o_que_nao_e_da_interface_nao_vira_canister() {
    #[derive(CandidType, Deserialize)]
    enum Novo {
        Novo { x: Nat },
    }
    let r: Result<CreateCanisterSuccess, Novo> = Err(Novo::Novo { x: Nat::from(1u8) });
    assert_eq!(ler_criacao(&Encode!(&r).unwrap()), Err(Erro::Forma));
    // O canister que não é `principal`; o bloco que não é `nat`.
    #[derive(CandidType, Deserialize)]
    struct Torto {
        block_id: Nat,
        canister_id: String,
    }
    let r: Result<Torto, ()> = Ok(Torto {
        block_id: Nat::from(1u8),
        canister_id: "qpsvj".to_owned(),
    });
    assert_eq!(ler_criacao(&Encode!(&r).unwrap()), Err(Erro::Forma));
    let r: Result<u64, ()> = Ok(3);
    assert_eq!(ler_carga(&Encode!(&r).unwrap()), Err(Erro::Forma));
    // Nem `Ok` nem `Err`; dois valores; nenhum.
    #[derive(CandidType, Deserialize)]
    enum Talvez {
        Sim(Nat),
    }
    assert_eq!(
        ler_carga(&Encode!(&Talvez::Sim(Nat::from(1u8))).unwrap()),
        Err(Erro::Forma)
    );
    assert_eq!(ler_criacao(&Encode!(&1u8, &2u8).unwrap()), Err(Erro::Forma));
    assert_eq!(ler_carga(&Encode!().unwrap()), Err(Erro::Forma));
    assert!(matches!(ler_carga(b"DIDL"), Err(Erro::Candid(_))));
}

#[test]
fn as_mensagens_sao_ascii() {
    for e in [
        Erro::Controladores,
        Erro::Candid(candid::Erro::Truncado),
        Erro::Forma,
    ] {
        assert!(e.to_string().is_ascii());
    }
    let canister = Principal::de_texto("qpsvj-4l777-77775-qaaaa-cai").unwrap();
    let r = RecusaDaCriacao::Duplicada {
        bloco: 2,
        canister: Some(canister),
    };
    assert_eq!(
        r.to_string(),
        "Duplicate duplicate_of 2 canister_id qpsvj-4l777-77775-qaaaa-cai"
    );
    let r = RecusaDaCriacao::NaoCriou {
        bloco_da_taxa: None,
        bloco_da_devolucao: None,
        motivo: "n\u{e3}o \u{1b}[31m".to_owned(),
    };
    assert!(r.to_string().is_ascii());
    let r = RecusaDaCarga::DestinoInvalido { destino: canister };
    assert_eq!(
        r.to_string(),
        "InvalidReceiver receiver qpsvj-4l777-77775-qaaaa-cai"
    );
    assert!(
        RecusaDaCarga::Generica {
            codigo: 1,
            mensagem: "\u{7}".to_owned()
        }
        .to_string()
        .is_ascii()
    );
}
