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

// ---------------------------------------------------------------------------
// A escrita com o tipo dado (ICP-4d)
// ---------------------------------------------------------------------------

/// O valor na forma que se compara: o `blob` como `vec nat8`, como em
/// [`normal`], e os campos de um `record` pelo id, em ordem — a escrita
/// aceita em qualquer ordem, e a leitura devolve na do tipo.
fn canonico(v: &Valor) -> Valor {
    match normal(v) {
        Valor::Vec(itens) => Valor::Vec(itens.iter().map(canonico).collect()),
        Valor::Opt(Some(v)) => Valor::Opt(Some(Box::new(canonico(&v)))),
        Valor::Record(c) => {
            let mut c: Vec<(u32, Valor)> = c.iter().map(|(i, v)| (*i, canonico(v))).collect();
            c.sort_by_key(|(i, _)| *i);
            Valor::Record(c)
        }
        Valor::Variant(i, v) => Valor::Variant(i, Box::new(canonico(&v))),
        outro => outro,
    }
}

fn canonicos(v: &[Valor]) -> Vec<Valor> {
    v.iter().map(canonico).collect()
}

/// O tipo do oráculo de um tipo daqui.
fn tipo_do_oraculo(t: &Tipo) -> ::candid::types::Type {
    use ::candid::types::{Field, TypeInner};
    let campos = |c: &[(u32, Tipo)]| {
        let mut c: Vec<Field> = c
            .iter()
            .map(|(id, t)| Field {
                id: std::rc::Rc::new(Label::Id(*id)),
                ty: tipo_do_oraculo(t),
            })
            .collect();
        c.sort_by_key(|f| f.id.get_id());
        c
    };
    match t {
        Tipo::Primitivo(p) => match p {
            Primitivo::Null => TypeInner::Null,
            Primitivo::Bool => TypeInner::Bool,
            Primitivo::Nat => TypeInner::Nat,
            Primitivo::Int => TypeInner::Int,
            Primitivo::Nat8 => TypeInner::Nat8,
            Primitivo::Nat16 => TypeInner::Nat16,
            Primitivo::Nat32 => TypeInner::Nat32,
            Primitivo::Nat64 => TypeInner::Nat64,
            Primitivo::Int8 => TypeInner::Int8,
            Primitivo::Int16 => TypeInner::Int16,
            Primitivo::Int32 => TypeInner::Int32,
            Primitivo::Int64 => TypeInner::Int64,
            Primitivo::Float32 => TypeInner::Float32,
            Primitivo::Float64 => TypeInner::Float64,
            Primitivo::Text => TypeInner::Text,
            Primitivo::Reserved => TypeInner::Reserved,
            Primitivo::Empty => TypeInner::Empty,
            Primitivo::Principal => TypeInner::Principal,
        }
        .into(),
        Tipo::Opt(d) => TypeInner::Opt(tipo_do_oraculo(d)).into(),
        Tipo::Vec(d) => TypeInner::Vec(tipo_do_oraculo(d)).into(),
        Tipo::Record(c) => TypeInner::Record(campos(c)).into(),
        Tipo::Variant(c) => TypeInner::Variant(campos(c)).into(),
    }
}

/// O valor do oráculo de um valor daqui.
fn idl_de(v: &Valor) -> IDLValue {
    use ::candid::{Int, Nat};
    match v {
        Valor::Null => IDLValue::Null,
        Valor::Bool(b) => IDLValue::Bool(*b),
        Valor::Nat(n) => IDLValue::Nat(Nat::from(*n)),
        Valor::Int(n) => IDLValue::Int(Int::from(*n)),
        Valor::Nat8(n) => IDLValue::Nat8(*n),
        Valor::Nat16(n) => IDLValue::Nat16(*n),
        Valor::Nat32(n) => IDLValue::Nat32(*n),
        Valor::Nat64(n) => IDLValue::Nat64(*n),
        Valor::Int8(n) => IDLValue::Int8(*n),
        Valor::Int16(n) => IDLValue::Int16(*n),
        Valor::Int32(n) => IDLValue::Int32(*n),
        Valor::Int64(n) => IDLValue::Int64(*n),
        Valor::Texto(t) => IDLValue::Text(t.clone()),
        Valor::Reservado => IDLValue::Reserved,
        Valor::Principal(p) => IDLValue::Principal(::candid::Principal::from_slice(p.bytes())),
        Valor::Opt(None) => IDLValue::None,
        Valor::Opt(Some(x)) => IDLValue::Opt(Box::new(idl_de(x))),
        Valor::Blob(b) => IDLValue::Blob(b.clone()),
        Valor::Vec(itens) => IDLValue::Vec(itens.iter().map(idl_de).collect()),
        Valor::Record(c) => IDLValue::Record(
            c.iter()
                .map(|(id, v)| IDLField {
                    id: Label::Id(*id),
                    val: idl_de(v),
                })
                .collect(),
        ),
        Valor::Variant(id, x) => IDLValue::Variant(VariantValue(
            Box::new(IDLField {
                id: Label::Id(*id),
                val: idl_de(x),
            }),
            0,
        )),
    }
}

/// Um tipo sorteado: os primitivos com valor, e os compostos até o quarto
/// nível. Os ids dos campos vêm de faixas separadas — nunca repetem — e em
/// qualquer ordem.
fn gerar_tipo(s: &mut Sorteio, nivel: usize) -> Tipo {
    const PRIMITIVOS: [Primitivo; 15] = [
        Primitivo::Null,
        Primitivo::Bool,
        Primitivo::Nat,
        Primitivo::Int,
        Primitivo::Nat8,
        Primitivo::Nat16,
        Primitivo::Nat32,
        Primitivo::Nat64,
        Primitivo::Int8,
        Primitivo::Int16,
        Primitivo::Int32,
        Primitivo::Int64,
        Primitivo::Text,
        Primitivo::Reserved,
        Primitivo::Principal,
    ];
    if nivel > 3 || s.ate(3) == 0 {
        return PRIMITIVOS[s.ate(PRIMITIVOS.len() as u64) as usize].into();
    }
    let campos = |s: &mut Sorteio, minimo: u64| {
        let mut c: Vec<(u32, Tipo)> = (0..minimo + s.ate(4))
            .map(|i| {
                (
                    i as u32 * 1000 + s.ate(1000) as u32,
                    gerar_tipo(s, nivel + 1),
                )
            })
            .collect();
        if s.ate(2) == 0 {
            c.reverse();
        }
        c
    };
    match s.ate(5) {
        0 => Tipo::opt(gerar_tipo(s, nivel + 1)),
        1 => Tipo::vec(gerar_tipo(s, nivel + 1)),
        2 => Tipo::blob(),
        3 => Tipo::Record(campos(s, 0)),
        // Um caso ao menos: um `variant` sem casos não tem valor.
        _ => Tipo::Variant(campos(s, 1)),
    }
}

/// Um valor sorteado do tipo `t`.
fn gerar_valor_do_tipo(s: &mut Sorteio, t: &Tipo) -> Valor {
    match t {
        Tipo::Primitivo(p) => match p {
            Primitivo::Null => Valor::Null,
            Primitivo::Bool => Valor::Bool(s.ate(2) == 1),
            Primitivo::Nat => Valor::Nat(u128::from(s.proximo()) << s.ate(64)),
            Primitivo::Int => Valor::Int(i128::from(s.proximo() as i64) << s.ate(60)),
            Primitivo::Nat8 => Valor::Nat8(s.proximo() as u8),
            Primitivo::Nat16 => Valor::Nat16(s.proximo() as u16),
            Primitivo::Nat32 => Valor::Nat32(s.proximo() as u32),
            Primitivo::Nat64 => Valor::Nat64(s.proximo()),
            Primitivo::Int8 => Valor::Int8(s.proximo() as i8),
            Primitivo::Int16 => Valor::Int16(s.proximo() as i16),
            Primitivo::Int32 => Valor::Int32(s.proximo() as i32),
            Primitivo::Int64 => Valor::Int64(s.proximo() as i64),
            Primitivo::Text => Valor::Texto(
                (0..s.ate(6))
                    .map(|_| ['a', 'é', '€', '"'][s.ate(4) as usize])
                    .collect(),
            ),
            Primitivo::Reserved => Valor::Reservado,
            Primitivo::Principal => {
                Valor::Principal(Principal::de_bytes(&s.bytes_ate(29)).unwrap())
            }
            outro => unreachable!("sem valor: {outro:?}"),
        },
        Tipo::Opt(d) => Valor::Opt(if s.ate(2) == 0 {
            None
        } else {
            Some(Box::new(gerar_valor_do_tipo(s, d)))
        }),
        Tipo::Vec(d) if **d == Tipo::Primitivo(Primitivo::Nat8) && s.ate(2) == 0 => {
            Valor::Blob(s.bytes_ate(10))
        }
        Tipo::Vec(d) => Valor::Vec((0..s.ate(4)).map(|_| gerar_valor_do_tipo(s, d)).collect()),
        Tipo::Record(c) => {
            let mut v: Vec<(u32, Valor)> = c
                .iter()
                .map(|(id, t)| (*id, gerar_valor_do_tipo(s, t)))
                .collect();
            if s.ate(2) == 0 {
                v.reverse();
            }
            Valor::Record(v)
        }
        Tipo::Variant(c) => {
            let (id, t) = &c[s.ate(c.len() as u64) as usize];
            Valor::Variant(*id, Box::new(gerar_valor_do_tipo(s, t)))
        }
    }
}

#[test]
fn o_id_do_campo_e_o_do_oraculo() {
    let mut s = Sorteio::novo(77);
    let mut nomes: Vec<String> = [
        "",
        "a",
        "owner",
        "subaccount",
        "created_at_time",
        "Ok",
        "Err",
        "Duplicate",
        "duplicate_of",
        "block_index",
        "çã€",
    ]
    .iter()
    .map(|n| n.to_string())
    .collect();
    for _ in 0..300 {
        nomes.push(
            (0..s.ate(40))
                .map(|_| ['a', 'z', '_', '0', 'é', '€'][s.ate(6) as usize])
                .collect(),
        );
    }
    for n in &nomes {
        assert_eq!(id_do_campo(n), ::candid::idl_hash(n), "{n}");
    }
}

#[test]
fn a_escrita_com_tipos_e_a_leitura_do_oraculo() {
    use ::candid::{CandidType, Decode, Deserialize, Encode, Nat};
    use serde_bytes::ByteBuf;
    #[derive(CandidType, Deserialize, Debug, PartialEq, Clone)]
    struct Conta {
        owner: ::candid::Principal,
        subaccount: Option<ByteBuf>,
    }
    #[derive(CandidType, Deserialize, Debug, PartialEq, Clone)]
    enum Falha {
        Sem,
        Com { saldo: Nat },
        Texto(String),
    }
    #[derive(CandidType, Deserialize, Debug, PartialEq, Clone)]
    enum Resultado {
        Ok(Nat),
        Err(Falha),
    }
    #[derive(CandidType, Deserialize, Debug, PartialEq, Clone)]
    struct Pedido {
        de: Option<ByteBuf>,
        para: Conta,
        quanto: Nat,
        quando: Option<u64>,
        lista: Vec<Conta>,
        vazia: Vec<Option<i32>>,
        resultado: Resultado,
    }

    let conta = Tipo::record([
        ("owner", Primitivo::Principal.into()),
        ("subaccount", Tipo::opt(Tipo::blob())),
    ]);
    let falha = Tipo::variant([
        ("Sem", Primitivo::Null.into()),
        ("Com", Tipo::record([("saldo", Primitivo::Nat.into())])),
        ("Texto", Primitivo::Text.into()),
    ]);
    // Os campos fora da ordem do hash: a escrita ordena.
    let pedido = Tipo::record([
        (
            "resultado",
            Tipo::variant([("Ok", Primitivo::Nat.into()), ("Err", falha)]),
        ),
        ("vazia", Tipo::vec(Tipo::opt(Primitivo::Int32))),
        ("lista", Tipo::vec(conta.clone())),
        ("quando", Tipo::opt(Primitivo::Nat64)),
        ("quanto", Primitivo::Nat.into()),
        ("para", conta),
        ("de", Tipo::opt(Tipo::blob())),
    ]);

    let r = |campos: Vec<(&str, Valor)>| {
        Valor::Record(
            campos
                .into_iter()
                .map(|(n, v)| (id_do_campo(n), v))
                .collect(),
        )
    };
    let caso = |nome: &str, v: Valor| Valor::Variant(id_do_campo(nome), Box::new(v));
    let algum = |v: Valor| Valor::Opt(Some(Box::new(v)));
    let p = Principal::de_bytes(&[1, 2, 3]).unwrap();
    let oficial_p = ::candid::Principal::from_slice(&[1, 2, 3]);
    let conta_daqui = |sub: Option<Vec<u8>>| {
        r(vec![
            ("owner", Valor::Principal(p)),
            (
                "subaccount",
                Valor::Opt(sub.map(|s| Box::new(Valor::Blob(s)))),
            ),
        ])
    };
    let conta_oficial = |sub: Option<Vec<u8>>| Conta {
        owner: oficial_p,
        subaccount: sub.map(ByteBuf::from),
    };

    let casos = [
        (
            r(vec![
                ("de", Valor::Opt(None)),
                ("para", conta_daqui(None)),
                ("quanto", Valor::Nat(u128::MAX)),
                ("quando", Valor::Opt(None)),
                ("lista", Valor::Vec(vec![])),
                ("vazia", Valor::Vec(vec![])),
                ("resultado", caso("Ok", Valor::Nat(0))),
            ]),
            Pedido {
                de: None,
                para: conta_oficial(None),
                quanto: Nat::from(u128::MAX),
                quando: None,
                lista: vec![],
                vazia: vec![],
                resultado: Resultado::Ok(Nat::from(0u8)),
            },
        ),
        (
            r(vec![
                (
                    "resultado",
                    caso("Err", caso("Com", r(vec![("saldo", Valor::Nat(7))]))),
                ),
                ("de", algum(Valor::Blob(vec![0; 32]))),
                ("para", conta_daqui(Some(vec![9, 9]))),
                ("quanto", Valor::Nat(1)),
                ("quando", algum(Valor::Nat64(1_792_793_518_971_579_136))),
                (
                    "lista",
                    Valor::Vec(vec![conta_daqui(None), conta_daqui(Some(vec![]))]),
                ),
                (
                    "vazia",
                    Valor::Vec(vec![Valor::Opt(None), algum(Valor::Int32(-5))]),
                ),
            ]),
            Pedido {
                de: Some(ByteBuf::from(vec![0; 32])),
                para: conta_oficial(Some(vec![9, 9])),
                quanto: Nat::from(1u8),
                quando: Some(1_792_793_518_971_579_136),
                lista: vec![conta_oficial(None), conta_oficial(Some(vec![]))],
                vazia: vec![None, Some(-5)],
                resultado: Resultado::Err(Falha::Com {
                    saldo: Nat::from(7u8),
                }),
            },
        ),
        (
            r(vec![
                ("resultado", caso("Err", caso("Sem", Valor::Null))),
                ("de", Valor::Opt(None)),
                ("para", conta_daqui(None)),
                ("quanto", Valor::Nat(1 << 64)),
                ("quando", Valor::Opt(None)),
                ("lista", Valor::Vec(vec![])),
                ("vazia", Valor::Vec(vec![])),
            ]),
            Pedido {
                de: None,
                para: conta_oficial(None),
                quanto: Nat::from(1u128 << 64),
                quando: None,
                lista: vec![],
                vazia: vec![],
                resultado: Resultado::Err(Falha::Sem),
            },
        ),
        (
            r(vec![
                (
                    "resultado",
                    caso("Err", caso("Texto", Valor::Texto("não".into()))),
                ),
                ("de", Valor::Opt(None)),
                ("para", conta_daqui(None)),
                ("quanto", Valor::Nat(0)),
                ("quando", Valor::Opt(None)),
                ("lista", Valor::Vec(vec![])),
                ("vazia", Valor::Vec(vec![Valor::Opt(None)])),
            ]),
            Pedido {
                de: None,
                para: conta_oficial(None),
                quanto: Nat::from(0u8),
                quando: None,
                lista: vec![],
                vazia: vec![None],
                resultado: Resultado::Err(Falha::Texto("não".into())),
            },
        ),
    ];
    for (daqui, oficial) in casos {
        // O que se escreve aqui, o oráculo lê como o valor dele.
        let bytes = codificar_com_tipos(
            core::slice::from_ref(&pedido),
            core::slice::from_ref(&daqui),
        )
        .unwrap();
        assert_eq!(Decode!(&bytes, Pedido).unwrap(), oficial);
        // E com o texto do tipo: dois argumentos, um deles sem composto.
        let dois = codificar_com_tipos(
            &[Primitivo::Text.into(), pedido.clone()],
            &[Valor::Texto("x".into()), daqui.clone()],
        )
        .unwrap();
        assert_eq!(
            Decode!(&dois, String, Pedido).unwrap(),
            ("x".into(), oficial.clone())
        );
        // O que o oráculo escreve, este lado lê como o valor daqui.
        let dele = Encode!(&oficial).unwrap();
        assert_eq!(
            canonicos(&decodificar(&dele).unwrap()),
            canonicos(core::slice::from_ref(&daqui))
        );
        // E lê o que escreveu.
        assert_eq!(
            canonicos(&decodificar(&bytes).unwrap()),
            canonicos(&[daqui])
        );
    }
}

#[test]
fn cada_composto_uma_vez_na_tabela() {
    let conta = Tipo::record([
        ("owner", Primitivo::Principal.into()),
        ("subaccount", Tipo::opt(Tipo::blob())),
    ]);
    let par = Tipo::record([("a", conta.clone()), ("b", conta.clone())]);
    let p = Principal::de_bytes(&[]).unwrap();
    let c = Valor::Record(vec![
        (id_do_campo("owner"), Valor::Principal(p)),
        (id_do_campo("subaccount"), Valor::Opt(None)),
    ]);
    let v = Valor::Record(vec![(id_do_campo("a"), c.clone()), (id_do_campo("b"), c)]);
    let bytes = codificar_com_tipos(&[par.clone(), par], &[v.clone(), v]).unwrap();
    // A tabela: o par, a conta, o `opt blob` e o `blob` — quatro entradas,
    // por mais vezes que apareçam.
    assert_eq!(&bytes[..5], b"DIDL\x04");
    assert!(oraculo(&bytes).is_some());
}

#[test]
fn tipos_e_valores_sorteados_nos_dois_sentidos() {
    let mut s = Sorteio::novo(4);
    let vazio = ::candid::types::TypeEnv::new();
    for _ in 0..3000 {
        let tipos: Vec<Tipo> = (0..s.ate(4)).map(|_| gerar_tipo(&mut s, 0)).collect();
        let valores: Vec<Valor> = tipos
            .iter()
            .map(|t| gerar_valor_do_tipo(&mut s, t))
            .collect();
        let bytes = codificar_com_tipos(&tipos, &valores)
            .unwrap_or_else(|e| panic!("{tipos:?} {valores:?}: {e}"));
        // Este lado lê o que escreveu, e o oráculo lê o mesmo.
        assert_eq!(
            canonicos(&decodificar(&bytes).unwrap()),
            canonicos(&valores)
        );
        assert_eq!(
            oraculo(&bytes).map(|v| canonicos(&v)),
            Some(canonicos(&valores)),
            "{bytes:02x?}"
        );
        // E o que o oráculo escreve nesses tipos, este lado lê.
        let do_oraculo: Vec<_> = tipos.iter().map(tipo_do_oraculo).collect();
        let args = IDLArgs::new(&valores.iter().map(idl_de).collect::<Vec<_>>());
        let dele = args.to_bytes_with_types(&vazio, &do_oraculo).unwrap();
        assert_eq!(canonicos(&decodificar(&dele).unwrap()), canonicos(&valores));
    }
}

#[test]
fn o_que_nao_e_do_tipo_nao_se_escreve() {
    let nat: Tipo = Primitivo::Nat.into();
    let conta = Tipo::record([
        ("owner", Primitivo::Principal.into()),
        ("subaccount", Tipo::opt(Tipo::blob())),
    ]);
    let p = Principal::de_texto("aaaaa-aa").unwrap();
    let owner = (id_do_campo("owner"), Valor::Principal(p));
    let sub = (id_do_campo("subaccount"), Valor::Opt(None));
    let boa = Valor::Record(vec![owner.clone(), sub.clone()]);
    assert!(codificar_com_tipos(core::slice::from_ref(&conta), &[boa]).is_ok());

    let um = |t: Tipo, v: Valor| (vec![t], vec![v]);
    let casos = [
        // Outro primitivo.
        um(nat.clone(), Valor::Texto("1".into())),
        um(nat.clone(), Valor::Nat64(1)),
        // Tipos e valores em números diferentes.
        (vec![nat.clone()], vec![]),
        (vec![], vec![Valor::Nat(1)]),
        // O `opt` sem o valor de `opt`, e o de dentro de outro tipo.
        um(Tipo::opt(nat.clone()), Valor::Nat(1)),
        um(
            Tipo::opt(Primitivo::Nat8),
            Valor::Opt(Some(Box::new(Valor::Nat(1)))),
        ),
        // O `blob` num `vec` que não é de `nat8`.
        um(Tipo::vec(Primitivo::Nat16), Valor::Blob(vec![1])),
        // Um campo que falta, um que sobra, e um trocado.
        um(conta.clone(), Valor::Record(vec![owner.clone()])),
        um(
            conta.clone(),
            Valor::Record(vec![owner.clone(), sub.clone(), (7, Valor::Null)]),
        ),
        um(
            conta.clone(),
            Valor::Record(vec![
                owner.clone(),
                (id_do_campo("subconta"), Valor::Opt(None)),
            ]),
        ),
        um(
            conta.clone(),
            Valor::Record(vec![owner.clone(), owner.clone()]),
        ),
        // Um caso que o `variant` não tem.
        um(
            Tipo::variant([("Ok", nat.clone())]),
            Valor::Variant(id_do_campo("Err"), Box::new(Valor::Nat(1))),
        ),
        // Tipos sem valor.
        um(Primitivo::Empty.into(), Valor::Null),
        um(Primitivo::Float64.into(), Valor::Nat(1)),
        um(Tipo::variant([]), Valor::Variant(0, Box::new(Valor::Null))),
    ];
    for (t, v) in casos {
        assert_eq!(
            codificar_com_tipos(&t, &v),
            Err(ErroDaEscrita::ForaDoTipo),
            "{t:?} {v:?}"
        );
    }

    // Um id repetido no tipo.
    let repetido = Tipo::Record(vec![(1, nat.clone()), (1, nat.clone())]);
    assert_eq!(
        codificar_com_tipos(
            &[repetido],
            &[Valor::Record(vec![(1, Valor::Nat(1)), (1, Valor::Nat(2))])]
        ),
        Err(ErroDaEscrita::CampoRepetido)
    );
}

#[test]
fn a_escrita_nao_passa_dos_tetos_da_leitura() {
    let nat: Tipo = Primitivo::Nat.into();
    // Trinta e dois compostos, um dentro do outro, se escrevem e se leem;
    // trinta e três, não.
    let mut fundo = nat.clone();
    let mut valor = Valor::Nat(7);
    for _ in 0..TETOS.profundidade {
        fundo = Tipo::opt(fundo);
        valor = Valor::Opt(Some(Box::new(valor)));
    }
    let bytes =
        codificar_com_tipos(core::slice::from_ref(&fundo), core::slice::from_ref(&valor)).unwrap();
    assert_eq!(decodificar(&bytes), Ok(vec![valor.clone()]));
    let mais = Tipo::opt(fundo.clone());
    assert_eq!(
        codificar_com_tipos(core::slice::from_ref(&mais), &[Valor::Opt(None)]),
        Err(ErroDaEscrita::Profundo)
    );
    // Também quando o tipo fundo já está na tabela, por outro argumento.
    assert_eq!(
        codificar_com_tipos(&[fundo, mais], &[valor, Valor::Opt(None)]),
        Err(ErroDaEscrita::Profundo)
    );

    // Os argumentos.
    let muitos = vec![nat.clone(); TETOS.argumentos + 1];
    let uns = vec![Valor::Nat(1); TETOS.argumentos + 1];
    assert_eq!(
        codificar_com_tipos(&muitos, &uns),
        Err(ErroDaEscrita::Grande)
    );
    assert!(codificar_com_tipos(&muitos[1..], &uns[1..]).is_ok());

    // Os campos de um `record`.
    let largo = |n: u32| Tipo::Record((0..n).map(|i| (i, Primitivo::Null.into())).collect());
    let nulos = |n: u32| Valor::Record((0..n).map(|i| (i, Valor::Null)).collect());
    let n = TETOS.campos as u32;
    assert!(codificar_com_tipos(&[largo(n)], &[nulos(n)]).is_ok());
    assert_eq!(
        codificar_com_tipos(&[largo(n + 1)], &[nulos(n + 1)]),
        Err(ErroDaEscrita::Grande)
    );

    // As entradas da tabela: cada `vec` de um `record` diferente.
    let tipos: Vec<Tipo> = (0..TETOS.argumentos as u32)
        .map(|a| {
            Tipo::Record(
                (0..5)
                    .map(|i| (i, Tipo::vec(Tipo::Record(vec![(a * 5 + i, nat.clone())]))))
                    .collect(),
            )
        })
        .collect();
    let valores: Vec<Valor> = (0..TETOS.argumentos as u32)
        .map(|_| Valor::Record((0..5).map(|i| (i, Valor::Vec(vec![]))).collect()))
        .collect();
    // 64 argumentos, cada um com cinco `vec` e cinco `record` seus: 704
    // entradas.
    assert_eq!(
        codificar_com_tipos(&tipos, &valores),
        Err(ErroDaEscrita::Grande)
    );

    // Os valores: um `vec` de mais itens que o orçamento inteiro.
    let v = Tipo::vec(Primitivo::Null);
    assert_eq!(
        codificar_com_tipos(
            core::slice::from_ref(&v),
            &[Valor::Vec(vec![Valor::Null; TETOS.valores])]
        ),
        Err(ErroDaEscrita::Grande)
    );
    let cabe =
        codificar_com_tipos(&[v], &[Valor::Vec(vec![Valor::Null; TETOS.valores - 1])]).unwrap();
    assert!(decodificar(&cabe).is_ok());
    // Um `blob` é um valor só, de qualquer tamanho.
    assert!(codificar_com_tipos(&[Tipo::blob()], &[Valor::Blob(vec![0; 100_000])]).is_ok());
}

#[test]
fn os_campos_e_os_casos_pelo_nome() {
    let r = Valor::Record(vec![
        (id_do_campo("owner"), Valor::Nat(1)),
        (id_do_campo("subaccount"), Valor::Opt(None)),
    ]);
    assert_eq!(r.campo("owner"), Some(&Valor::Nat(1)));
    assert_eq!(r.campo("subaccount"), Some(&Valor::Opt(None)));
    assert_eq!(r.campo("Owner"), None);
    assert_eq!(Valor::Nat(1).campo("owner"), None);
    let v = Valor::Variant(id_do_campo("Err"), Box::new(Valor::Nat(2)));
    assert_eq!(v.caso("Err"), Some(&Valor::Nat(2)));
    assert_eq!(v.caso("Ok"), None);
    assert_eq!(r.caso("owner"), None);
}

#[test]
fn as_mensagens_da_escrita_sao_ascii() {
    for e in [
        ErroDaEscrita::ForaDoTipo,
        ErroDaEscrita::CampoRepetido,
        ErroDaEscrita::Profundo,
        ErroDaEscrita::Grande,
    ] {
        assert!(e.to_string().is_ascii());
    }
}
