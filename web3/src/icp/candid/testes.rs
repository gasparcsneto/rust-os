//! O Candid contra a especificação e contra o crate `candid`.

use std::borrow::ToOwned;
use std::boxed::Box;
use std::format;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use ::candid::types::Label;
use ::candid::types::value::{IDLArgs, IDLField, IDLValue, VariantValue};

use super::*;
use crate::icp::bancada::Sorteio;

/// O valor daqui de um valor do oráculo; `None` para o que este lado não
/// representa (ponto flutuante, `func`, `service`, número sem tipo).
fn de_idl(v: &IDLValue) -> Option<Valor> {
    Some(match v {
        IDLValue::Null => Valor::Null,
        IDLValue::Bool(b) => Valor::Bool(*b),
        IDLValue::Nat(n) => Valor::Nat(u128::try_from(n.0.clone()).ok()?),
        IDLValue::Int(i) => Valor::Int(i128::try_from(i.0.clone()).ok()?),
        IDLValue::Nat8(n) => Valor::Nat8(*n),
        IDLValue::Nat16(n) => Valor::Nat16(*n),
        IDLValue::Nat32(n) => Valor::Nat32(*n),
        IDLValue::Nat64(n) => Valor::Nat64(*n),
        IDLValue::Int8(n) => Valor::Int8(*n),
        IDLValue::Int16(n) => Valor::Int16(*n),
        IDLValue::Int32(n) => Valor::Int32(*n),
        IDLValue::Int64(n) => Valor::Int64(*n),
        IDLValue::Text(t) => Valor::Texto(t.clone()),
        IDLValue::Reserved => Valor::Reservado,
        IDLValue::Principal(p) => Valor::Principal(Principal::de_bytes(p.as_slice()).ok()?),
        IDLValue::None => Valor::Opt(None),
        IDLValue::Opt(v) => Valor::Opt(Some(Box::new(de_idl(v)?))),
        IDLValue::Blob(b) => Valor::Blob(b.clone()),
        IDLValue::Vec(itens) => Valor::Vec(itens.iter().map(de_idl).collect::<Option<_>>()?),
        IDLValue::Record(campos) => Valor::Record(
            campos
                .iter()
                .map(|f| Some((f.id.get_id(), de_idl(&f.val)?)))
                .collect::<Option<_>>()?,
        ),
        IDLValue::Variant(VariantValue(f, _)) => {
            Valor::Variant(f.id.get_id(), Box::new(de_idl(&f.val)?))
        }
        IDLValue::Float32(_)
        | IDLValue::Float64(_)
        | IDLValue::Number(_)
        | IDLValue::Service(_)
        | IDLValue::Func(..) => return None,
    })
}

/// O valor com `blob` escrito como `vec nat8`, para comparar: o oráculo
/// usa um ou outro, conforme o caminho.
fn normal(v: &Valor) -> Valor {
    match v {
        Valor::Blob(b) => Valor::Vec(b.iter().map(|x| Valor::Nat8(*x)).collect()),
        Valor::Vec(itens) => Valor::Vec(itens.iter().map(normal).collect()),
        Valor::Opt(Some(v)) => Valor::Opt(Some(Box::new(normal(v)))),
        Valor::Record(c) => Valor::Record(c.iter().map(|(i, v)| (*i, normal(v))).collect()),
        Valor::Variant(i, v) => Valor::Variant(*i, Box::new(normal(v))),
        outro => outro.clone(),
    }
}

fn normais(v: &[Valor]) -> Vec<Valor> {
    v.iter().map(normal).collect()
}

/// O oráculo, com uma cota para que uma mensagem hostil não o pendure.
fn oraculo(bytes: &[u8]) -> Option<Vec<Valor>> {
    let mut config = ::candid::de::DecoderConfig::new();
    config.set_decoding_quota(10_000_000);
    config.set_skipping_quota(10_000_000);
    let args = IDLArgs::from_bytes_with_config(bytes, &config).ok()?;
    args.args.iter().map(de_idl).collect()
}

fn hex(texto: &str) -> Vec<u8> {
    let texto: String = texto.chars().filter(|c| !c.is_whitespace()).collect();
    (0..texto.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&texto[i..i + 2], 16).unwrap())
        .collect()
}

fn didl(resto: &str) -> Vec<u8> {
    let mut b = Vec::from(*MAGICA);
    b.extend(hex(resto));
    b
}

#[test]
fn mensagens_simples() {
    assert_eq!(decodificar(&didl("00 00")), Ok(vec![]));
    assert_eq!(
        decodificar(&didl("00 01 71 03 6f6c61")),
        Ok(vec![Valor::Texto("ola".into())])
    );
    // **Especificação** (o LEB128 do hash independente usa os mesmos
    // exemplos): 624485 e -123456.
    assert_eq!(
        decodificar(&didl("00 01 7d e58e26")),
        Ok(vec![Valor::Nat(624_485)])
    );
    assert_eq!(
        decodificar(&didl("00 01 7c c0bb78")),
        Ok(vec![Valor::Int(-123_456)])
    );
    assert_eq!(decodificar(b"DIDX\x00\x00"), Err(Erro::Magica));
    assert_eq!(decodificar(b"DID"), Err(Erro::Magica));
    assert_eq!(decodificar(&didl("00 00 00")), Err(Erro::Sobra));
}

#[test]
fn a_codificacao_e_a_do_oraculo() {
    use ::candid::{Encode, Int, Nat};
    let p = Principal::de_texto("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap();
    let oficial_p = ::candid::Principal::from_slice(p.bytes());
    let casos: Vec<(Vec<Valor>, Vec<u8>)> = vec![
        (vec![], Encode!().unwrap()),
        (vec![Valor::Texto("ola".into())], Encode!(&"ola").unwrap()),
        (vec![Valor::Texto("çã€".into())], Encode!(&"çã€").unwrap()),
        (vec![Valor::Nat(0)], Encode!(&Nat::from(0u8)).unwrap()),
        (
            vec![Valor::Nat(u128::MAX)],
            Encode!(&Nat::from(u128::MAX)).unwrap(),
        ),
        (
            vec![
                Valor::Int(i128::MIN),
                Valor::Int(-1),
                Valor::Int(63),
                Valor::Int(64),
            ],
            Encode!(
                &Int::from(i128::MIN),
                &Int::from(-1),
                &Int::from(63),
                &Int::from(64)
            )
            .unwrap(),
        ),
        (
            vec![
                Valor::Nat8(1),
                Valor::Nat16(2),
                Valor::Nat32(3),
                Valor::Nat64(u64::MAX),
                Valor::Int8(-1),
                Valor::Int16(-2),
                Valor::Int32(-3),
                Valor::Int64(i64::MIN),
            ],
            Encode!(
                &1u8,
                &2u16,
                &3u32,
                &u64::MAX,
                &-1i8,
                &-2i16,
                &-3i32,
                &i64::MIN
            )
            .unwrap(),
        ),
        (
            vec![Valor::Bool(true), Valor::Null, Valor::Reservado],
            Encode!(&true, &(), &::candid::Reserved).unwrap(),
        ),
        (vec![Valor::Principal(p)], Encode!(&oficial_p).unwrap()),
        (
            vec![
                Valor::Blob(vec![0xde, 0xad]),
                Valor::Texto("x".into()),
                Valor::Blob(vec![]),
            ],
            Encode!(
                &serde_bytes::ByteBuf::from(vec![0xde, 0xad]),
                &"x",
                &serde_bytes::ByteBuf::from(vec![])
            )
            .unwrap(),
        ),
    ];
    for (valores, esperado) in casos {
        let nossos = codificar(&valores).unwrap();
        assert_eq!(nossos, esperado, "{valores:?}");
        assert_eq!(decodificar(&nossos), Ok(valores.clone()));
        assert_eq!(
            oraculo(&nossos).map(|v| normais(&v)),
            Some(normais(&valores))
        );
    }
    // O que precisa de tipo de fora não se codifica aqui.
    for v in [
        Valor::Opt(None),
        Valor::Vec(vec![]),
        Valor::Record(vec![]),
        Valor::Variant(0, Box::new(Valor::Null)),
    ] {
        assert_eq!(codificar(&[v]), Err(Erro::NaoCodificavel));
    }
}

#[test]
fn tipos_compostos_contra_o_oraculo() {
    use ::candid::{CandidType, Deserialize, Encode};
    #[derive(CandidType, Deserialize)]
    enum Cor {
        Vermelho,
        Verde(u8),
        Azul { brilho: String },
    }
    #[derive(CandidType, Deserialize)]
    struct Coisa {
        nome: String,
        idade: Option<u16>,
        cores: Vec<Cor>,
        dono: Option<::candid::Principal>,
        dados: serde_bytes::ByteBuf,
        par: (i32, bool),
        vazio: Vec<Option<String>>,
    }
    #[derive(CandidType, Deserialize)]
    struct Lista {
        cabeca: u8,
        cauda: Option<Box<Lista>>,
    }
    let coisa = Coisa {
        nome: "ola".into(),
        idade: Some(7),
        cores: vec![
            Cor::Vermelho,
            Cor::Verde(3),
            Cor::Azul { brilho: "x".into() },
        ],
        dono: Some(::candid::Principal::anonymous()),
        dados: serde_bytes::ByteBuf::from(vec![1, 2, 3]),
        par: (-5, true),
        vazio: vec![None, Some("a".into())],
    };
    let lista = Lista {
        cabeca: 1,
        cauda: Some(Box::new(Lista {
            cabeca: 2,
            cauda: None,
        })),
    };
    for bytes in [
        Encode!(&coisa).unwrap(),
        Encode!(&lista).unwrap(),
        Encode!(&coisa, &lista, &"fim").unwrap(),
        Encode!(&Vec::<Lista>::new()).unwrap(),
        Encode!(&Some(Some(Some(1u8)))).unwrap(),
    ] {
        let nossos = decodificar(&bytes).unwrap();
        assert_eq!(Some(normais(&nossos)), oraculo(&bytes).map(|v| normais(&v)));
    }
    // A forma textual sai em ASCII, com os campos pelo id.
    let texto = decodificar(&Encode!(&coisa).unwrap()).unwrap()[0].to_string();
    assert!(texto.is_ascii(), "{texto}");
    assert!(texto.starts_with("record {"), "{texto}");
}

#[test]
fn os_valores_fora_do_subconjunto_sao_recusados_pelo_nome() {
    use ::candid::Encode;
    for (bytes, nome) in [
        (Encode!(&1.5f32).unwrap(), "float32"),
        (Encode!(&2.5f64).unwrap(), "float64"),
        // `func () -> ()` com o valor `pub(service 2vxsx-fae, "m")`.
        (didl("01 6a 00 00 00 01 00 01 01 01 04 01 6d"), "func"),
        // `service {}` com o valor `service 2vxsx-fae`.
        (didl("01 69 00 01 00 01 01 04"), "service"),
    ] {
        assert_eq!(decodificar(&bytes), Err(Erro::Recusado(nome)), "{nome}");
        assert!(IDLArgs::from_bytes(&bytes).is_ok());
    }
    // O principal por referência opaca.
    assert_eq!(
        decodificar(&didl("00 01 68 00")),
        Err(Erro::Recusado("principal por referencia opaca"))
    );
    // Um tipo futuro na tabela não incomoda; o valor dele, sim.
    let futuro = didl("01 67 02 aabb 00");
    assert_eq!(decodificar(&futuro), Ok(vec![]));
    let com_valor = didl("01 67 02 aabb 01 00 01 00 00");
    assert_eq!(decodificar(&com_valor), Err(Erro::Recusado("tipo futuro")));
    // `empty` não tem valor.
    assert_eq!(decodificar(&didl("00 01 6f")), Err(Erro::Empty));
    assert!(Erro::Recusado("func").to_string().contains("func"));
}

#[test]
fn a_tabela_de_tipos() {
    for (resto, erro) in [
        // Um primitivo como entrada da tabela.
        ("01 7f 00", Erro::Tipo),
        ("01 71 00", Erro::Tipo),
        // Um composto como referência.
        ("01 6e 6e 00", Erro::Tipo),
        ("00 01 6c", Erro::Tipo),
        // Um opcode positivo como entrada.
        ("01 05 00", Erro::Tipo),
        // Referência fora da tabela, na tabela e nos argumentos.
        ("01 6e 01 00", Erro::Referencia),
        ("01 6e 7f 01 01", Erro::Referencia),
        // Campos fora de ordem, repetidos, ou com id maior que 32 bits.
        ("01 6c 02 01 7f 00 7f 00", Erro::Campo),
        ("01 6c 02 01 7f 01 7f 00", Erro::Campo),
        ("01 6b 02 05 7f 05 7f 00", Erro::Campo),
        ("01 6c 01 8080808010 7f 00", Erro::Campo),
        // Uma anotação de `func` desconhecida.
        ("01 6a 00 00 01 04 00", Erro::Anotacao),
        // Um método de serviço que não é `func`, fora de ordem, repetido.
        ("01 69 01 01 61 7f 00", Erro::Referencia),
        ("02 69 02 01 62 01 01 61 01 6a 00 00 00 00", Erro::Metodo),
        ("02 69 02 01 61 01 01 61 01 6a 00 00 00 00", Erro::Metodo),
        ("01 69 01 01 ff 00 00", Erro::Metodo),
    ] {
        let bytes = didl(resto);
        assert_eq!(decodificar(&bytes), Err(erro), "{resto}");
        assert!(
            IDLArgs::from_bytes(&bytes).is_err(),
            "o oraculo aceitou {resto}"
        );
    }
    // Uma tabela com referência para frente e recursão vale.
    let recursiva = didl("02 6e 01 6c 02 00 7b 01 00 01 00 01 05 01 06 00");
    assert!(decodificar(&recursiva).is_ok());
    assert!(oraculo(&recursiva).is_some());
}

#[test]
fn valores_fora_da_forma() {
    for (resto, erro) in [
        ("00 01 7e 02", Erro::Bool),
        ("01 6e 7f 01 00 02", Erro::Opt),
        ("01 6b 01 00 7f 01 00 01", Erro::Variante),
        ("00 01 71 02 c328", Erro::Utf8),
        ("00 01 68 01 1e", Erro::PrincipalForma),
        ("00 01 68 02", Erro::PrincipalForma),
        ("00 01 71 05 6f6c61", Erro::Truncado),
        ("00 01 78 0102", Erro::Truncado),
    ] {
        let bytes = didl(resto);
        assert_eq!(decodificar(&bytes), Err(erro), "{resto}");
        assert!(oraculo(&bytes).is_none(), "o oraculo aceitou {resto}");
    }
}

#[test]
fn o_leb128_que_transborda() {
    // O maior `nat` de 128 bits, em 19 bytes; um a mais, não.
    let mut maior = String::from("00 01 7d");
    for _ in 0..18 {
        maior.push_str(" ff");
    }
    maior.push_str(" 03");
    assert_eq!(decodificar(&didl(&maior)), Ok(vec![Valor::Nat(u128::MAX)]));
    let mut alem = String::from("00 01 7d");
    for _ in 0..18 {
        alem.push_str(" ff");
    }
    alem.push_str(" 04");
    assert_eq!(decodificar(&didl(&alem)), Err(Erro::Transborda));
    // O oráculo aceita (o `nat` dele não tem teto): este lado recusa pelo
    // nome, em vez de truncar.
    assert!(IDLArgs::from_bytes(&didl(&alem)).is_ok());
    // O `int` nas duas pontas, e um passo além.
    for n in [i128::MIN, i128::MAX, -1, 0, 1 << 125, -(1 << 125)] {
        let bytes = codificar(&[Valor::Int(n)]).unwrap();
        assert_eq!(decodificar(&bytes), Ok(vec![Valor::Int(n)]), "{n}");
        assert_eq!(oraculo(&bytes), Some(vec![Valor::Int(n)]));
    }
    // No 19º byte cabem dois bits e o sinal: `01` é o i128::MAX, `7e` o
    // i128::MIN com 126 zeros; `02` (o bit 127 sem sinal), `40` (o sinal
    // sem o bit 127) ou a continuação, não.
    let dezenove = |ultimo: &str, resto: &str| {
        let mut t = String::from("00 01 7c");
        for _ in 0..18 {
            t.push(' ');
            t.push_str(resto);
        }
        t.push(' ');
        t.push_str(ultimo);
        didl(&t)
    };
    assert_eq!(
        decodificar(&dezenove("01", "ff")),
        Ok(vec![Valor::Int(i128::MAX)])
    );
    assert_eq!(
        decodificar(&dezenove("7e", "80")),
        Ok(vec![Valor::Int(i128::MIN)])
    );
    for ultimo in ["02", "03", "40", "7d", "81", "ff"] {
        assert_eq!(
            decodificar(&dezenove(ultimo, "ff")),
            Err(Erro::Transborda),
            "{ultimo}"
        );
    }
    // Um tamanho que não cabe em 64 bits.
    let mut tamanho = String::from("00 01 71");
    for _ in 0..10 {
        tamanho.push_str(" ff");
    }
    tamanho.push_str(" 01");
    assert_eq!(decodificar(&didl(&tamanho)), Err(Erro::Transborda));
}

#[test]
fn os_tetos() {
    // Um `vec null` de 2^40 itens em poucos bytes: recusado antes de
    // gastar memória ou tempo.
    let bytes = didl("01 6d 7f 01 00 8080808080 20");
    assert_eq!(decodificar(&bytes), Err(Erro::Grande));
    // O teto de valores, exato.
    let n = TETOS.valores - 1;
    let mut bytes = didl("01 6d 7f 01 00");
    let mut x = n;
    loop {
        let b = (x & 0x7f) as u8;
        x >>= 7;
        if x == 0 {
            bytes.push(b);
            break;
        }
        bytes.push(b | 0x80);
    }
    assert!(decodificar(&bytes).is_ok());
    let tetos = Tetos {
        valores: n,
        ..TETOS
    };
    assert_eq!(decodificar_com(&bytes, tetos), Err(Erro::Grande));
    // A profundidade: `opt opt … null`.
    let fundo = |n: usize| {
        let mut resto = format!("{n:02x} ");
        for i in 0..n {
            if i + 1 < n {
                resto.push_str(&format!("6e {:02x} ", i + 1));
            } else {
                resto.push_str("6e 7f ");
            }
        }
        resto.push_str("01 00 ");
        for _ in 0..n {
            resto.push_str("01 ");
        }
        didl(&resto)
    };
    assert!(decodificar(&fundo(TETOS.profundidade)).is_ok());
    assert_eq!(
        decodificar(&fundo(TETOS.profundidade + 1)),
        Err(Erro::Profundo)
    );
    // Um tipo que só tem valor infinito (`record { 0: t }` de si mesmo):
    // a recursão para no teto.
    assert_eq!(
        decodificar(&didl("01 6c 01 00 00 01 00")),
        Err(Erro::Profundo)
    );
    // A tabela e os argumentos.
    let mut grande = didl("");
    grande.extend_from_slice(&[0x81, 0x02]);
    assert_eq!(decodificar(&grande), Err(Erro::Grande));
    let mut args = didl("00 41");
    args.extend(std::iter::repeat_n(0x7f, 65));
    assert_eq!(decodificar(&args), Err(Erro::Grande));
}

#[test]
fn todo_prefixo_concorda_com_o_oraculo() {
    use ::candid::Encode;
    let bytes = Encode!(
        &"ola",
        &Some(vec![1u16, 2, 3]),
        &(::candid::Principal::anonymous(), -7i64),
        &::candid::Nat::from(1u128 << 100)
    )
    .unwrap();
    for n in 0..=bytes.len() {
        let prefixo = &bytes[..n];
        let nosso = decodificar(prefixo).ok().map(|v| normais(&v));
        let oficial = oraculo(prefixo).map(|v| normais(&v));
        assert_eq!(nosso, oficial, "{n}");
    }
}

fn gerar_valor(s: &mut Sorteio, nivel: usize) -> IDLValue {
    use ::candid::{Int, Nat};
    let folha = nivel > 3;
    match if folha { s.ate(12) } else { s.ate(17) } {
        0 => IDLValue::Null,
        1 => IDLValue::Bool(s.ate(2) == 1),
        2 => IDLValue::Nat(Nat::from(u128::from(s.proximo()) << s.ate(64))),
        3 => IDLValue::Int(Int::from(i128::from(s.proximo() as i64) << s.ate(60))),
        4 => IDLValue::Nat8(s.proximo() as u8),
        5 => IDLValue::Nat64(s.proximo()),
        6 => IDLValue::Int16(s.proximo() as i16),
        7 => IDLValue::Int32(s.proximo() as i32),
        8 => IDLValue::Text(
            (0..s.ate(6))
                .map(|_| ['a', 'é', '€', '"'][s.ate(4) as usize])
                .collect(),
        ),
        9 => IDLValue::Reserved,
        10 => IDLValue::Principal(::candid::Principal::from_slice(&s.bytes_ate(29))),
        11 => IDLValue::Blob(s.bytes_ate(10)),
        12 => IDLValue::None,
        13 => IDLValue::Opt(Box::new(gerar_valor(s, nivel + 1))),
        14 => {
            // Itens do mesmo tipo: o mesmo gerador, a mesma escolha.
            let semente = s.proximo();
            IDLValue::Vec(
                (0..s.ate(4))
                    .map(|_| gerar_valor(&mut Sorteio::novo(semente), nivel + 1))
                    .collect(),
            )
        }
        15 => IDLValue::Record(
            (0..s.ate(4))
                .map(|i| IDLField {
                    id: Label::Id(i as u32 * 3),
                    val: gerar_valor(s, nivel + 1),
                })
                .collect(),
        ),
        _ => IDLValue::Variant(VariantValue(
            Box::new(IDLField {
                id: Label::Id(s.ate(5) as u32),
                val: gerar_valor(s, nivel + 1),
            }),
            0,
        )),
    }
}

#[test]
fn mensagens_geradas_e_estragadas_contra_o_oraculo() {
    let mut s = Sorteio::novo(51);
    let (mut aceitas, mut recusadas) = (0, 0);
    for _ in 0..3000 {
        let valores: Vec<IDLValue> = (0..s.ate(4)).map(|_| gerar_valor(&mut s, 0)).collect();
        let Ok(bytes) = IDLArgs::new(&valores).to_bytes() else {
            continue;
        };
        // A mensagem inteira: os dois leem o mesmo.
        let nossa = decodificar(&bytes).unwrap_or_else(|e| panic!("{bytes:02x?}: {e}"));
        assert_eq!(Some(normais(&nossa)), oraculo(&bytes).map(|v| normais(&v)));
        // Estragada: se este lado aceita, o oráculo aceita igual; se o
        // oráculo recusa, este lado recusa.
        for _ in 0..8 {
            let mut ruim = bytes.clone();
            for _ in 0..1 + s.ate(2) {
                let i = 4 + s.ate((ruim.len() - 4).max(1) as u64) as usize;
                match s.ate(3) {
                    0 if i < ruim.len() => ruim[i] = s.proximo() as u8,
                    1 if i < ruim.len() => {
                        ruim.remove(i);
                    }
                    _ => ruim.insert(i.min(ruim.len()), s.proximo() as u8),
                }
            }
            let nosso = decodificar(&ruim);
            let oficial = oraculo(&ruim);
            match (&nosso, &oficial) {
                (Ok(n), Some(o)) => {
                    aceitas += 1;
                    assert_eq!(normais(n), normais(o), "{ruim:02x?}");
                }
                (Ok(n), None) => panic!("{ruim:02x?}: daqui {n:?}, o oraculo recusou"),
                (Err(_), None) => recusadas += 1,
                (Err(e), Some(_)) => {
                    // Só pelas recusas que o subconjunto declara.
                    assert!(
                        matches!(
                            e,
                            Erro::Transborda | Erro::Recusado(_) | Erro::Grande | Erro::Profundo
                        ),
                        "{ruim:02x?}: daqui {e:?}, o oraculo aceitou"
                    );
                }
            }
        }
    }
    assert!(aceitas > 500 && recusadas > 500, "{aceitas} {recusadas}");
}

#[test]
fn a_forma_textual() {
    let p = Principal::de_texto("aaaaa-aa").unwrap();
    let casos = [
        (
            Valor::Texto("ola \"x\" \\ é".into()),
            "\"ola \\\"x\\\" \\\\ \\u{e9}\"",
        ),
        (Valor::Nat(5), "5 : nat"),
        (Valor::Int(-5), "-5 : int"),
        (Valor::Nat8(1), "1 : nat8"),
        (Valor::Principal(p), "principal \"aaaaa-aa\""),
        (Valor::Blob(vec![0xde, 0xad]), "blob \"\\de\\ad\""),
        (Valor::Opt(None), "null"),
        (Valor::Opt(Some(Box::new(Valor::Bool(true)))), "opt true"),
        (
            Valor::Vec(vec![Valor::Null, Valor::Reservado]),
            "vec { null; reserved; }",
        ),
        (
            Valor::Record(vec![(0, Valor::Nat16(2)), (7, Valor::Texto("a".into()))]),
            "record { 0 = 2 : nat16; 7 = \"a\"; }",
        ),
        (
            Valor::Variant(3, Box::new(Valor::Null)),
            "variant { 3 = null }",
        ),
        (Valor::Texto("\u{1b}[2J".into()), "\"\\u{1b}[2J\""),
    ];
    for (v, texto) in casos {
        assert_eq!(v.to_string(), texto);
        assert!(v.to_string().is_ascii());
    }
}

#[test]
fn as_mensagens_sao_ascii() {
    for e in [
        Erro::Magica,
        Erro::Truncado,
        Erro::Sobra,
        Erro::Transborda,
        Erro::Tipo,
        Erro::Referencia,
        Erro::Campo,
        Erro::Anotacao,
        Erro::Metodo,
        Erro::Bool,
        Erro::Opt,
        Erro::Variante,
        Erro::Utf8,
        Erro::PrincipalForma,
        Erro::Empty,
        Erro::Recusado("func"),
        Erro::Profundo,
        Erro::Grande,
        Erro::NaoCodificavel,
    ] {
        assert!(e.to_string().is_ascii());
    }
}
