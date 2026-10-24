//! O ICRC-1 contra o `icrc-ledger-types`, nos dois sentidos.

use std::borrow::ToOwned;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use ::candid::{CandidType, Decode, Deserialize, Encode, Nat};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{TransferArg, TransferError};

use super::*;
use crate::icp::bancada::Sorteio;

fn oficial(p: &Principal) -> ::candid::Principal {
    ::candid::Principal::from_slice(p.bytes())
}

fn principal_sorteado(s: &mut Sorteio) -> Principal {
    Principal::de_bytes(&s.bytes_ate(29)).unwrap()
}

/// Sem subconta, a de zeros escrita, ou outra: as duas primeiras são a
/// mesma conta para o ledger, e não o mesmo argumento.
fn subconta_sorteada(s: &mut Sorteio) -> Option<[u8; SUBCONTA]> {
    match s.ate(3) {
        0 => None,
        1 => Some([0; SUBCONTA]),
        _ => {
            let mut b = [0u8; SUBCONTA];
            b.copy_from_slice(&s.bytes(SUBCONTA));
            Some(b)
        }
    }
}

fn transferencia_sorteada(s: &mut Sorteio) -> Transferencia {
    Transferencia {
        de_subconta: subconta_sorteada(s),
        para: Conta {
            dono: principal_sorteado(s),
            subconta: subconta_sorteada(s),
        },
        quantia: match s.ate(3) {
            0 => 0,
            1 => u128::from(s.proximo()),
            _ => u128::MAX >> s.ate(64),
        },
        taxa: (s.ate(2) == 1).then(|| u128::from(s.proximo())),
        memo: (s.ate(2) == 1).then(|| s.bytes_ate(MAIOR_MEMO)),
        criada_em_ns: (s.ate(2) == 1).then(|| s.proximo()),
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
fn a_transferencia_e_a_do_oficial() {
    let mut s = Sorteio::novo(11);
    for _ in 0..500 {
        let t = transferencia_sorteada(&mut s);
        let bytes = argumento_da_transferencia(&t).unwrap();
        // O oficial lê o que se escreveu aqui. Campo a campo: o `PartialEq`
        // da conta oficial iguala a subconta ausente à de zeros, e aqui as
        // duas são argumentos diferentes.
        let dele = Decode!(&bytes, TransferArg).unwrap();
        assert_eq!(dele.from_subaccount, t.de_subconta);
        assert_eq!(dele.to.owner, oficial(&t.para.dono));
        assert_eq!(dele.to.subaccount, t.para.subconta);
        assert_eq!(dele.amount, Nat::from(t.quantia));
        assert_eq!(dele.fee, t.taxa.map(Nat::from));
        assert_eq!(dele.memo.as_ref().map(|m| m.0.to_vec()), t.memo);
        assert_eq!(dele.created_at_time, t.criada_em_ns);
        // E o que o oficial escreve do mesmo argumento diz o mesmo valor.
        assert_eq!(lidos(&Encode!(&dele).unwrap()), lidos(&bytes));
    }
}

#[test]
fn o_saldo_e_o_do_oficial() {
    let mut s = Sorteio::novo(12);
    for _ in 0..200 {
        let c = Conta {
            dono: principal_sorteado(&mut s),
            subconta: subconta_sorteada(&mut s),
        };
        let bytes = argumento_do_saldo(&c);
        let dele = Decode!(&bytes, Account).unwrap();
        assert_eq!(dele.owner, oficial(&c.dono));
        assert_eq!(dele.subaccount, c.subconta);
        assert_eq!(lidos(&Encode!(&dele).unwrap()), lidos(&bytes));
    }
    // A resposta, um `nat` de até 128 bits: o anônimo da bancada tem
    // 2^127 - 1 cycles.
    for n in [0u128, 1, 10_000, u64::MAX.into(), 1 << 127, u128::MAX] {
        assert_eq!(ler_saldo(&Encode!(&Nat::from(n)).unwrap()), Ok(n));
    }
    // Fora da forma: outro tipo, dois valores, nenhum.
    assert_eq!(ler_saldo(&Encode!(&10_000u64).unwrap()), Err(Erro::Forma));
    assert_eq!(
        ler_saldo(&Encode!(&Nat::from(1u8), &Nat::from(2u8)).unwrap()),
        Err(Erro::Forma)
    );
    assert_eq!(ler_saldo(&Encode!().unwrap()), Err(Erro::Forma));
    // Além de 128 bits, o Candid daqui recusa — nunca um saldo cortado.
    let grande = Nat::from(u128::MAX) + Nat::from(1u8);
    assert_eq!(
        ler_saldo(&Encode!(&grande).unwrap()),
        Err(Erro::Candid(candid::Erro::Transborda))
    );
}

#[test]
fn o_resultado_escrito_pelo_oficial() {
    type Resultado = Result<Nat, TransferError>;
    for bloco in [0u128, 4, u64::MAX.into(), u128::MAX] {
        let ok: Resultado = Ok(Nat::from(bloco));
        assert_eq!(ler_transferencia(&Encode!(&ok).unwrap()), Ok(Ok(bloco)));
    }
    let agora = 1_792_793_518_971_579_136u64;
    let casos = [
        (
            TransferError::BadFee {
                expected_fee: Nat::from(10_000u32),
            },
            Recusa::TaxaErrada { esperada: 10_000 },
            "BadFee expected_fee 10000",
        ),
        (
            TransferError::BadBurn {
                min_burn_amount: Nat::from(5u8),
            },
            Recusa::QueimaPequena { minima: 5 },
            "BadBurn min_burn_amount 5",
        ),
        (
            TransferError::InsufficientFunds {
                balance: Nat::from(400_000_000u64),
            },
            Recusa::SemFundos { saldo: 400_000_000 },
            "InsufficientFunds balance 400000000",
        ),
        (TransferError::TooOld, Recusa::Velha, "TooOld"),
        (
            TransferError::CreatedInFuture { ledger_time: agora },
            Recusa::NoFuturo {
                hora_do_ledger_ns: agora,
            },
            "CreatedInFuture ledger_time 1792793518971579136",
        ),
        (
            TransferError::TemporarilyUnavailable,
            Recusa::Indisponivel,
            "TemporarilyUnavailable",
        ),
        (
            TransferError::Duplicate {
                duplicate_of: Nat::from(4u8),
            },
            Recusa::Duplicada { bloco: 4 },
            "Duplicate duplicate_of 4",
        ),
        (
            TransferError::GenericError {
                error_code: Nat::from(7u8),
                message: "não\n".into(),
            },
            Recusa::Generica {
                codigo: 7,
                mensagem: "não\n".into(),
            },
            "GenericError error_code 7 message \"n\\u{e3}o\\u{a}\"",
        ),
    ];
    for (dele, daqui, texto) in casos {
        let r: Resultado = Err(dele);
        assert_eq!(
            ler_transferencia(&Encode!(&r).unwrap()),
            Ok(Err(daqui.clone()))
        );
        assert_eq!(daqui.to_string(), texto);
    }
}

#[test]
fn o_que_nao_e_do_icrc1_nao_vira_bloco() {
    // Um caso que o padrão não tem.
    #[derive(CandidType, Deserialize)]
    enum Novo {
        Novo { x: Nat },
    }
    let r: Result<Nat, Novo> = Err(Novo::Novo { x: Nat::from(1u8) });
    assert_eq!(ler_transferencia(&Encode!(&r).unwrap()), Err(Erro::Forma));
    // O bloco que não é `nat`.
    let r: Result<u64, TransferError> = Ok(4);
    assert_eq!(ler_transferencia(&Encode!(&r).unwrap()), Err(Erro::Forma));
    // Nem `Ok` nem `Err`.
    #[derive(CandidType, Deserialize)]
    enum Talvez {
        Sim(Nat),
    }
    assert_eq!(
        ler_transferencia(&Encode!(&Talvez::Sim(Nat::from(4u8))).unwrap()),
        Err(Erro::Forma)
    );
    // Um campo de recusa de outro tipo, ou que falta.
    #[derive(CandidType, Deserialize)]
    enum Torta {
        InsufficientFunds { balance: String },
        Duplicate { outro: Nat },
        CreatedInFuture { ledger_time: Nat },
    }
    for torta in [
        Torta::InsufficientFunds {
            balance: "muito".into(),
        },
        Torta::Duplicate {
            outro: Nat::from(1u8),
        },
        Torta::CreatedInFuture {
            ledger_time: Nat::from(1u8),
        },
    ] {
        let r: Result<Nat, Torta> = Err(torta);
        assert_eq!(ler_transferencia(&Encode!(&r).unwrap()), Err(Erro::Forma));
    }
    // O texto, e não o `variant`; dois valores; nenhum.
    assert_eq!(
        ler_transferencia(&Encode!(&"Ok").unwrap()),
        Err(Erro::Forma)
    );
    let ok: Result<Nat, TransferError> = Ok(Nat::from(1u8));
    assert_eq!(
        ler_transferencia(&Encode!(&ok, &ok).unwrap()),
        Err(Erro::Forma)
    );
    assert_eq!(ler_transferencia(&Encode!().unwrap()), Err(Erro::Forma));
    // E o que não é Candid.
    assert!(matches!(ler_transferencia(b"DIDX"), Err(Erro::Candid(_))));
}

#[test]
fn os_campos_a_mais_de_um_ledger_novo_nao_atrapalham() {
    // Um padrão que crescesse — um campo a mais numa recusa — se lê pelo
    // nome do que se conhece.
    #[derive(CandidType, Deserialize)]
    enum Novo {
        Duplicate { duplicate_of: Nat, quando: u64 },
    }
    let r: Result<Nat, Novo> = Err(Novo::Duplicate {
        duplicate_of: Nat::from(9u8),
        quando: 1,
    });
    assert_eq!(
        ler_transferencia(&Encode!(&r).unwrap()),
        Ok(Err(Recusa::Duplicada { bloco: 9 }))
    );
}

#[test]
fn o_memo_maior_que_32_nao_se_escreve() {
    let mut s = Sorteio::novo(13);
    let mut t = transferencia_sorteada(&mut s);
    t.memo = Some(vec![7; MAIOR_MEMO + 1]);
    assert_eq!(argumento_da_transferencia(&t), Err(Erro::MemoGrande));
    t.memo = Some(vec![7; MAIOR_MEMO]);
    let dele = Decode!(&argumento_da_transferencia(&t).unwrap(), TransferArg).unwrap();
    assert_eq!(dele.memo.map(|m| m.0.into_vec()), Some(vec![7; MAIOR_MEMO]));
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
    let r = Recusa::Generica {
        codigo: 1,
        mensagem: String::from("\u{1b}[2J€"),
    };
    assert!(r.to_string().is_ascii(), "{r}");
}
