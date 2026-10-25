//! O CMC contra a interface dele (`cmc.did`), declarada aqui com o
//! `candid`: não há crate oficial com os tipos. A bancada confere o mesmo
//! contra o CMC de verdade, o da PocketIC.

use std::borrow::ToOwned;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use ::candid::{CandidType, Decode, Deserialize, Encode, Nat};
use serde_bytes::ByteBuf;

use super::*;
use crate::icp::bancada::Sorteio;

#[derive(CandidType, Deserialize, Debug)]
struct NotifyMintCyclesArg {
    block_index: u64,
    to_subaccount: Option<ByteBuf>,
    deposit_memo: Option<ByteBuf>,
}

#[derive(CandidType, Deserialize)]
struct NotifyMintCyclesSuccess {
    block_index: Nat,
    minted: Nat,
    balance: Nat,
}

#[derive(CandidType, Deserialize)]
enum NotifyError {
    Refunded {
        reason: String,
        block_index: Option<u64>,
    },
    Processing,
    TransactionTooOld(u64),
    InvalidTransaction(String),
    Other {
        error_code: u64,
        error_message: String,
    },
}

type Resultado = Result<NotifyMintCyclesSuccess, NotifyError>;

#[test]
fn a_subconta_de_um_principal() {
    // O anônimo: um byte, 0x04.
    let anonimo = Principal::de_texto("2vxsx-fae").unwrap();
    let mut esperada = [0u8; SUBCONTA];
    esperada[0] = 1;
    esperada[1] = 4;
    assert_eq!(subconta_de(&anonimo), esperada);
    // Cada tamanho, de 0 a 29: o tamanho, os bytes e zeros.
    let mut s = Sorteio::novo(3);
    for n in 0..=29 {
        let bytes = s.bytes(n);
        let sub = subconta_de(&Principal::de_bytes(&bytes).unwrap());
        assert_eq!(usize::from(sub[0]), n);
        assert_eq!(&sub[1..1 + n], &bytes[..]);
        assert!(sub[1 + n..].iter().all(|b| *b == 0));
    }
    // A conta de depósito: o CMC, com a subconta de quem cunha.
    let cmc = Principal::de_texto("rkp4c-7iaaa-aaaaa-aaaca-cai").unwrap();
    assert_eq!(
        conta_de_deposito(&cmc, &anonimo),
        Conta {
            dono: cmc,
            subconta: Some(esperada)
        }
    );
}

#[test]
fn o_memo_da_cunhagem() {
    assert_eq!(&MEMO_DE_CUNHAGEM, b"MINT\0\0\0\0");
    assert_eq!(u64::from_le_bytes(MEMO_DE_CUNHAGEM), 0x544e_494d);
}

#[test]
fn a_notificacao_e_a_da_interface() {
    let mut s = Sorteio::novo(5);
    for _ in 0..300 {
        let n = Notificacao {
            bloco: s.proximo(),
            para_subconta: (s.ate(2) == 1).then(|| {
                let mut b = [0u8; SUBCONTA];
                b.copy_from_slice(&s.bytes(SUBCONTA));
                b
            }),
            memo_do_deposito: (s.ate(2) == 1).then(|| s.bytes_ate(32)),
        };
        let dele = Decode!(&argumento_da_cunhagem(&n).unwrap(), NotifyMintCyclesArg).unwrap();
        assert_eq!(dele.block_index, n.bloco);
        assert_eq!(
            dele.to_subaccount.map(|b| b.into_vec()),
            n.para_subconta.map(Vec::from)
        );
        assert_eq!(dele.deposit_memo.map(|b| b.into_vec()), n.memo_do_deposito);
    }
    let grande = Notificacao {
        bloco: 1,
        para_subconta: None,
        memo_do_deposito: Some(vec![0; 33]),
    };
    assert_eq!(argumento_da_cunhagem(&grande), Err(Erro::MemoGrande));
}

#[test]
fn o_resultado_escrito_pela_interface() {
    // O que a bancada respondeu: 1 ICP, 3,52 T cycles, e o saldo do
    // anônimo, acima de 2^127.
    let saldo = (1u128 << 127) + 3_519_900_000_000;
    let ok: Resultado = Ok(NotifyMintCyclesSuccess {
        block_index: Nat::from(1u8),
        minted: Nat::from(3_520_000_000_000u64),
        balance: Nat::from(saldo),
    });
    assert_eq!(
        ler_cunhagem(&Encode!(&ok).unwrap()),
        Ok(Ok(Cunhagem {
            cunhados: 3_520_000_000_000,
            saldo,
            bloco: 1,
        }))
    );
    let casos = [
        (
            NotifyError::Refunded {
                reason: "não".into(),
                block_index: Some(9),
            },
            Recusa::Devolvida {
                motivo: "não".into(),
                bloco: Some(9),
            },
            "Refunded reason \"n\\u{e3}o\" block_index 9",
        ),
        (
            NotifyError::Refunded {
                reason: "x".into(),
                block_index: None,
            },
            Recusa::Devolvida {
                motivo: "x".into(),
                bloco: None,
            },
            "Refunded reason \"x\"",
        ),
        (NotifyError::Processing, Recusa::Processando, "Processing"),
        (
            NotifyError::TransactionTooOld(5),
            Recusa::BlocoVelho { menor: 5 },
            "TransactionTooOld 5",
        ),
        (
            NotifyError::InvalidTransaction("Destination account in the block".into()),
            Recusa::Invalida {
                motivo: "Destination account in the block".into(),
            },
            "InvalidTransaction \"Destination account in the block\"",
        ),
        (
            NotifyError::Other {
                error_code: 3,
                error_message: "y".into(),
            },
            Recusa::Outra {
                codigo: 3,
                mensagem: "y".into(),
            },
            "Other error_code 3 error_message \"y\"",
        ),
    ];
    for (dela, daqui, texto) in casos {
        let r: Resultado = Err(dela);
        assert_eq!(ler_cunhagem(&Encode!(&r).unwrap()), Ok(Err(daqui.clone())));
        assert_eq!(daqui.to_string(), texto);
    }
}

#[test]
fn o_que_nao_e_do_cmc_nao_vira_cunhagem() {
    // Os cycles que não são `nat`.
    #[derive(CandidType, Deserialize)]
    struct Torto {
        block_index: Nat,
        minted: u64,
        balance: Nat,
    }
    let r: Result<Torto, NotifyError> = Ok(Torto {
        block_index: Nat::from(1u8),
        minted: 2,
        balance: Nat::from(3u8),
    });
    assert_eq!(ler_cunhagem(&Encode!(&r).unwrap()), Err(Erro::Forma));
    // Um campo que falta.
    #[derive(CandidType, Deserialize)]
    struct Curto {
        minted: Nat,
        balance: Nat,
    }
    let r: Result<Curto, NotifyError> = Ok(Curto {
        minted: Nat::from(2u8),
        balance: Nat::from(3u8),
    });
    assert_eq!(ler_cunhagem(&Encode!(&r).unwrap()), Err(Erro::Forma));
    // Um caso que a interface não tem.
    #[derive(CandidType, Deserialize)]
    enum Novo {
        Novo,
    }
    let r: Result<NotifyMintCyclesSuccess, Novo> = Err(Novo::Novo);
    assert_eq!(ler_cunhagem(&Encode!(&r).unwrap()), Err(Erro::Forma));
    // O bloco de uma devolução que não é `opt nat64`.
    #[derive(CandidType, Deserialize)]
    enum Devolucao {
        Refunded { reason: String, block_index: u64 },
    }
    let r: Result<NotifyMintCyclesSuccess, Devolucao> = Err(Devolucao::Refunded {
        reason: "x".into(),
        block_index: 1,
    });
    assert_eq!(ler_cunhagem(&Encode!(&r).unwrap()), Err(Erro::Forma));
    // Nem `variant`, nem Candid.
    assert_eq!(ler_cunhagem(&Encode!(&"Ok").unwrap()), Err(Erro::Forma));
    assert!(matches!(ler_cunhagem(b"DIDL\x00"), Err(Erro::Candid(_))));
}

#[test]
fn as_mensagens_sao_ascii() {
    for e in [
        Erro::MemoGrande,
        Erro::Candid(candid::Erro::Truncado),
        Erro::Forma,
    ] {
        assert!(e.to_string().is_ascii());
    }
    let r = Recusa::Invalida {
        motivo: "\u{1b}]0;€".to_string(),
    };
    assert!(r.to_string().is_ascii(), "{r}");
}

#[derive(CandidType, Deserialize, Debug)]
struct NotifyTopUpArg {
    block_index: u64,
    canister_id: ::candid::Principal,
}

#[test]
fn o_memo_e_a_conta_da_recarga() {
    assert_eq!(&MEMO_DE_RECARGA, b"TPUP\0\0\0\0");
    assert_eq!(u64::from_le_bytes(MEMO_DE_RECARGA), 0x5055_5054);
    // A conta é a do CMC, com a subconta **do canister** — a mesma forma
    // da de depósito, de outro Principal.
    let cmc = Principal::de_texto("rkp4c-7iaaa-aaaaa-aaaca-cai").unwrap();
    let canister = Principal::de_texto("qpsvj-4l777-77775-qaaaa-cai").unwrap();
    assert_eq!(
        conta_de_recarga(&cmc, &canister),
        Conta {
            dono: cmc,
            subconta: Some(subconta_de(&canister)),
        }
    );
    assert_eq!(
        conta_de_recarga(&cmc, &canister),
        conta_de_deposito(&cmc, &canister)
    );
}

#[test]
fn a_recarga_e_a_da_interface() {
    let mut s = Sorteio::novo(6);
    for _ in 0..300 {
        let bloco = s.proximo();
        let bytes = s.bytes_ate(29);
        let canister = Principal::de_bytes(&bytes).unwrap();
        let dele = Decode!(&argumento_da_recarga(bloco, &canister), NotifyTopUpArg).unwrap();
        assert_eq!(dele.block_index, bloco);
        assert_eq!(dele.canister_id.as_slice(), canister.bytes());
    }
}

#[test]
fn o_resultado_da_recarga_escrito_pela_interface() {
    type DaRecarga = Result<Nat, NotifyError>;
    let ok: DaRecarga = Ok(Nat::from(3_520_000_000_000u64));
    assert_eq!(
        ler_recarga(&Encode!(&ok).unwrap()),
        Ok(Ok(3_520_000_000_000))
    );
    // As recusas são as da cunhagem, pelo mesmo leitor.
    let r: DaRecarga = Err(NotifyError::Processing);
    assert_eq!(
        ler_recarga(&Encode!(&r).unwrap()),
        Ok(Err(Recusa::Processando))
    );
    let r: DaRecarga = Err(NotifyError::Refunded {
        reason: "x".into(),
        block_index: Some(4),
    });
    assert_eq!(
        ler_recarga(&Encode!(&r).unwrap()),
        Ok(Err(Recusa::Devolvida {
            motivo: "x".into(),
            bloco: Some(4),
        }))
    );
    // Os cycles que não são `nat`, e a resposta de dois valores: fora da
    // forma.
    let torto: Result<u64, NotifyError> = Ok(5);
    assert_eq!(ler_recarga(&Encode!(&torto).unwrap()), Err(Erro::Forma));
    assert_eq!(ler_recarga(&Encode!(&ok, &ok).unwrap()), Err(Erro::Forma));
    // A resposta de uma cunhagem não é a de uma recarga.
    let cunhagem: Resultado = Ok(NotifyMintCyclesSuccess {
        block_index: Nat::from(1u8),
        minted: Nat::from(2u8),
        balance: Nat::from(3u8),
    });
    assert_eq!(ler_recarga(&Encode!(&cunhagem).unwrap()), Err(Erro::Forma));
}
