//! As partes de uma rodada, do lado do hospedeiro: a variável `DUKE_PARTE`,
//! lida pelas bancadas que se dividem entre máquinas da CI — a de
//! persistência, a de tempo e a da atualização — e pela suíte do kernel — o
//! `cargo xtask test`, também com `--video virtio`, e o `cargo xtask
//! iniciador` do ARM, que roda a suíte pelo firmware —; e o anúncio da parte
//! que a suíte faz no começo da saída, conferido no fim.
//!
//! A regra da divisão — `k/n`, o item `i` na parte `k` sse `i % n == k - 1`
//! — é a de [`protocolo::partes`], a mesma conta que o kernel faz.
//!
//! # A parte chega ao kernel pela compilação
//!
//! O kernel não lê linha de comando, e não deve ler `DUKE_PARTE`: um valor
//! esquecido no shell filtraria a suíte em silêncio. A parte vai em
//! [`DA_SUITE`], que o `xtask` põe só no build da suíte — a partir do
//! `DUKE_PARTE` dele, já conferido — e tira do ambiente de todo outro build
//! (ver `ambiente_do_kernel`, no `main.rs`). O ELF muda com ela, e a
//! proveniência a registra.
//!
//! # E volta pela saída
//!
//! O kernel anuncia, na primeira linha da suíte, a parte que roda — ou que
//! roda a suíte inteira —, e o placar do fim conta os casos que rodaram. O
//! `xtask` confere os dois contra o que pediu ([`conferir_a_suite`]): um ELF
//! de outra compilação, que rodasse outra parte ou a suíte inteira, não passa
//! por esta.

use protocolo::partes::{ErroDaParte, Parte};

/// A variável da parte, nas bancadas e na suíte: `k/n`.
pub(crate) const VARIAVEL: &str = "DUKE_PARTE";

/// A variável da compilação da suíte que leva a parte ao kernel — o
/// `option_env!` de `kernel/src/testes.rs`.
pub(crate) const DA_SUITE: &str = "DUKE_PARTE_DA_SUITE";

/// A parte desta rodada, de [`VARIAVEL`] — ou nenhuma, sem a variável.
pub(crate) fn pedida() -> Result<Option<Parte>, String> {
    pedida_de(std::env::var_os(VARIAVEL).as_deref())
}

/// [`pedida`], do valor da variável: um valor que não é texto também não
/// se lê, e não vira a rodada inteira.
fn pedida_de(valor: Option<&std::ffi::OsStr>) -> Result<Option<Parte>, String> {
    match valor {
        None => Ok(None),
        Some(valor) => match valor.to_str() {
            Some(texto) => parte_da_rodada(Some(texto)),
            None => Err(format!(
                "{VARIAVEL}={}: não é texto",
                valor.to_string_lossy()
            )),
        },
    }
}

/// A parte da rodada pedida em `DUKE_PARTE`: `k/n`, com `1 <= k <= n` — ou
/// nenhuma, sem a variável. A CI divide as bancadas longas e a suíte entre
/// máquinas por ela (`.github/workflows/ci.yml`). Um valor que não se lê é
/// um erro: uma parte mal escrita não pode virar "nenhum cenário" nem
/// "todos" em silêncio.
pub(crate) fn parte_da_rodada(valor: Option<&str>) -> Result<Option<Parte>, String> {
    let Some(valor) = valor else {
        return Ok(None);
    };
    Parte::ler(valor).map(Some).map_err(|erro| {
        // O motivo do `protocolo` é ASCII — o kernel o escreve na serial —,
        // e o daqui, o do `xtask`, com os acentos dele.
        let motivo = match erro {
            ErroDaParte::Forma => "esperava a parte e o total, como 1/2",
            ErroDaParte::Faixa => "a parte vai de 1 ao total, e o total não é zero",
        };
        format!("{VARIAVEL}={valor}: {motivo}")
    })
}

/// O item de índice `i` — a posição dele na tabela inteira da bancada — é
/// da `parte`: `i % n == k - 1`; sem parte, todos. Todo item cai em
/// exatamente uma parte, e um item novo entra numa delas sem mexer na CI.
pub(crate) fn na_parte(i: usize, parte: Option<Parte>) -> bool {
    protocolo::partes::na_parte(i, parte)
}

/// Os cenários de uma bancada que rodam nesta rodada, na ordem da tabela: os
/// de `normais` e os de `de_queda` — que rodam sobre outra compilação do
/// kernel, e por isso vêm em lista à parte. O índice de um cenário é a
/// posição dele em todos, os de queda depois dos normais; rodam os da
/// `parte` que o `filtro` de `DUKE_CENARIOS` escolhe — pedaços do nome
/// separados por `|`, e vale o cenário que tiver qualquer um deles. Uma
/// lista vazia é uma compilação que não precisa acontecer.
pub(crate) fn da_rodada<'a, C>(
    normais: &'a [C],
    de_queda: &'a [C],
    nome: impl Fn(&C) -> &str,
    parte: Option<Parte>,
    filtro: Option<&str>,
) -> (Vec<&'a C>, Vec<&'a C>) {
    let escolhido = |c: &C| filtro.is_none_or(|f| f.split('|').any(|p| nome(c).contains(p)));
    let de = |cenarios: &'a [C], primeiro: usize| -> Vec<&'a C> {
        cenarios
            .iter()
            .enumerate()
            .filter(|&(i, c)| escolhido(c) && na_parte(primeiro + i, parte))
            .map(|(_, c)| c)
            .collect()
    };
    (de(normais, 0), de(de_queda, normais.len()))
}

/// O cabeçalho de uma bancada com `total` cenários na `parte`: quantos
/// rodam, e de quantos.
pub(crate) fn descrever(parte: Option<Parte>, total: usize) -> String {
    match parte {
        None => format!("{total} cenarios"),
        Some(p) => format!(
            "a parte {} de {} — {} dos {total} cenarios",
            p.k(),
            p.n(),
            p.quantos(total)
        ),
    }
}

/// O que a suíte anunciou na primeira linha dela: a parte, quantos casos
/// roda e quantos tem a suíte inteira.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Anuncio {
    pub(crate) parte: Option<Parte>,
    pub(crate) rodados: usize,
    pub(crate) total: usize,
}

/// O anúncio de uma linha da saída da suíte, se ela é o anúncio:
/// `  suite de testes :: <arquitetura> :: <total> casos`, a suíte inteira,
/// ou `  suite de testes :: <arquitetura> :: parte <k> de <n>: <rodados> de
/// <total> casos` — como `testes::executar_todos` a escreve.
pub(crate) fn ler_o_anuncio(linha: &str) -> Option<Anuncio> {
    let (_, resto) = linha.trim_end().split_once("suite de testes :: ")?;
    let (_arquitetura, resto) = resto.split_once(" :: ")?;
    let numero = |texto: &str| texto.parse::<usize>().ok();
    match resto.strip_prefix("parte ") {
        None => {
            let total = numero(resto.strip_suffix(" casos")?)?;
            Some(Anuncio {
                parte: None,
                rodados: total,
                total,
            })
        }
        Some(resto) => {
            let (k, resto) = resto.split_once(" de ")?;
            let (n, resto) = resto.split_once(": ")?;
            let (rodados, resto) = resto.split_once(" de ")?;
            let total = numero(resto.strip_suffix(" casos")?)?;
            Some(Anuncio {
                parte: Some(Parte::nova(numero(k)?, numero(n)?)?),
                rodados: numero(rodados)?,
                total,
            })
        }
    }
}

/// O placar do fim da suíte, `  <passaram> de <rodados> passaram`, se a
/// linha é ele — reconhecido campo a campo, como `conferir_a_suite` do
/// iniciador o reconhece.
pub(crate) fn ler_o_placar(linha: &str) -> Option<(usize, usize)> {
    let mut campos = linha.split_whitespace();
    let passaram = campos.next()?.parse().ok()?;
    (campos.next()? == "de").then_some(())?;
    let rodados = campos.next()?.parse().ok()?;
    (campos.next()? == "passaram" && campos.next().is_none()).then_some((passaram, rodados))
}

/// Confere, nas linhas da saída de uma suíte que passou, que ela rodou a
/// parte `pedida` — ou a suíte inteira, sem parte: o anúncio diz a parte
/// pedida, e o placar conta exatamente os casos anunciados, todos passando.
///
/// Sem anúncio, ou com outro, o ELF que rodou não é o desta compilação — ou
/// a saída se perdeu —, e o verde não diz nada sobre a parte pedida.
pub(crate) fn conferir_a_suite<'a>(
    pedida: Option<Parte>,
    linhas: impl IntoIterator<Item = &'a str>,
) -> Result<Anuncio, String> {
    let mut anuncios = Vec::new();
    let mut placares = Vec::new();
    for linha in linhas {
        if let Some(a) = ler_o_anuncio(linha) {
            anuncios.push(a);
        } else if let Some(p) = ler_o_placar(linha) {
            placares.push(p);
        }
    }
    let pedido = pedida.map_or_else(
        || String::from("a suíte inteira"),
        |p| format!("a parte {p}"),
    );
    let anunciada = |a: &Anuncio| {
        a.parte.map_or_else(
            || String::from("a suíte inteira"),
            |p| format!("a parte {p}"),
        )
    };
    let [anuncio] = anuncios.as_slice() else {
        return Err(if anuncios.is_empty() {
            format!(
                "pediu {pedido}, e a suíte não se anunciou: a saída não tem a linha `suite de testes :: ...`"
            )
        } else {
            format!(
                "pediu {pedido}, e a suíte se anunciou {} vezes — a máquina subiu de novo no meio?",
                anuncios.len()
            )
        });
    };
    if anuncio.parte != pedida {
        return Err(format!(
            "pediu {pedido}, e o kernel anunciou {}: o ELF que rodou não é o desta compilação",
            anunciada(anuncio)
        ));
    }
    let esperado = anuncio
        .parte
        .map_or(anuncio.total, |p| p.quantos(anuncio.total));
    if anuncio.parte.is_some() && anuncio.rodados < esperado {
        // A conta exata é do kernel, que sabe o tamanho da cauda: a fatia
        // da tabela do meio mais a cauda inteira. Ela nunca é menor que a
        // regra aplicada ao total — a cauda tem ao menos tantos quantos a
        // regra tiraria dela —, e um anúncio menor é outra regra.
        return Err(format!(
            "o kernel anunciou {} casos para {}, menos que os {esperado} da regra sobre {}",
            anuncio.rodados,
            anunciada(anuncio),
            anuncio.total
        ));
    }
    match placares.as_slice() {
        [(passaram, rodados)] if *passaram == anuncio.rodados && *rodados == anuncio.rodados => {
            Ok(*anuncio)
        }
        [(passaram, rodados)] => Err(format!(
            "o kernel anunciou {} casos, e o placar diz {passaram} de {rodados}",
            anuncio.rodados
        )),
        [] => Err("a suíte não chegou ao placar".into()),
        _ => Err(format!(
            "a saída tem {} placares — a suíte rodou mais de uma vez?",
            placares.len()
        )),
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    fn parte(k: usize, n: usize) -> Option<Parte> {
        Some(Parte::nova(k, n).unwrap())
    }

    #[test]
    fn a_parte_mal_escrita_e_recusada() {
        assert_eq!(parte_da_rodada(None), Ok(None));
        assert_eq!(parte_da_rodada(Some("1/2")), Ok(parte(1, 2)));
        assert_eq!(parte_da_rodada(Some("2/2")), Ok(parte(2, 2)));
        assert_eq!(parte_da_rodada(Some(" 1 / 1 ")), Ok(parte(1, 1)));
        for ruim in ["", "1", "a/b", "1/2/3", "-1/2"] {
            let erro = parte_da_rodada(Some(ruim)).unwrap_err();
            assert_eq!(
                erro,
                format!("DUKE_PARTE={ruim}: esperava a parte e o total, como 1/2")
            );
        }
        for fora in ["0/2", "3/2", "1/0"] {
            let erro = parte_da_rodada(Some(fora)).unwrap_err();
            assert_eq!(
                erro,
                format!("DUKE_PARTE={fora}: a parte vai de 1 ao total, e o total não é zero")
            );
        }
    }

    #[test]
    fn a_variavel_que_nao_e_texto_e_recusada() {
        use std::ffi::OsStr;
        assert_eq!(pedida_de(None), Ok(None));
        assert_eq!(pedida_de(Some(OsStr::new("2/3"))), Ok(parte(2, 3)));
        assert!(pedida_de(Some(OsStr::new("2 de 3"))).is_err());
        assert!(
            pedida_de(Some(OsStr::new(""))).is_err(),
            "a variável vazia não é a rodada inteira"
        );
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let erro = pedida_de(Some(OsStr::from_bytes(b"1/\xff"))).unwrap_err();
            assert!(erro.contains("não é texto"), "{erro}");
        }
    }

    const NORMAIS: [&str; 6] = ["a1", "b2", "c3", "d4", "e5", "f6"];
    const DE_QUEDA: [&str; 4] = ["q7", "r8", "s9", "t10"];

    fn rodada(
        parte: Option<Parte>,
        filtro: Option<&str>,
    ) -> (Vec<&'static str>, Vec<&'static str>) {
        let (n, q) = da_rodada(&NORMAIS, &DE_QUEDA, |c| c, parte, filtro);
        (
            n.into_iter().copied().collect(),
            q.into_iter().copied().collect(),
        )
    }

    #[test]
    fn a_rodada_de_cada_parte_e_a_fatia_da_tabela_inteira() {
        // Sem parte nem filtro, todos, na ordem.
        assert_eq!(rodada(None, None), (NORMAIS.to_vec(), DE_QUEDA.to_vec()));
        for n in 1..=12 {
            let mut normais = Vec::new();
            let mut de_queda = Vec::new();
            for k in 1..=n {
                let (a, b) = rodada(parte(k, n), None);
                normais.extend(a);
                de_queda.extend(b);
            }
            // Cada um em exatamente uma parte: a união, sem repetição, é a
            // tabela inteira.
            normais.sort_unstable();
            de_queda.sort_unstable();
            let (mut todos_n, mut todos_q) = (NORMAIS.to_vec(), DE_QUEDA.to_vec());
            todos_n.sort_unstable();
            todos_q.sort_unstable();
            assert_eq!((normais, de_queda), (todos_n, todos_q), "{n} partes");
        }
        // O índice dos de queda continua o dos normais: na parte 1 de 3, os
        // de índice 0, 3, 6 e 9 — dois normais e dois de queda.
        assert_eq!(
            rodada(parte(1, 3), None),
            (vec!["a1", "d4"], vec!["q7", "t10"])
        );
        assert_eq!(rodada(parte(3, 3), None), (vec!["c3", "f6"], vec!["s9"]));
        // Uma parte sem nenhum de queda não pede a compilação deles.
        assert_eq!(rodada(parte(6, 10), None), (vec!["f6"], vec![]));
        assert_eq!(rodada(parte(7, 10), None), (vec![], vec!["q7"]));
    }

    #[test]
    fn o_filtro_pelo_nome_vale_dentro_da_parte() {
        assert_eq!(rodada(None, Some("b2|r8")), (vec!["b2"], vec!["r8"]));
        // "b2" é da parte 2 de 2 (índice 1), "r8" também (índice 7).
        assert_eq!(rodada(parte(1, 2), Some("b2|r8")), (vec![], vec![]));
        assert_eq!(rodada(parte(2, 2), Some("b2|r8")), (vec!["b2"], vec!["r8"]));
        assert_eq!(rodada(None, Some("nenhum")), (vec![], vec![]));
    }

    #[test]
    fn o_cabecalho_da_bancada_diz_quantos_da_parte() {
        assert_eq!(descrever(None, 60), "60 cenarios");
        assert_eq!(
            descrever(parte(1, 3), 60),
            "a parte 1 de 3 — 20 dos 60 cenarios"
        );
        assert_eq!(
            descrever(parte(2, 3), 20),
            "a parte 2 de 3 — 7 dos 20 cenarios"
        );
        assert_eq!(
            descrever(parte(3, 3), 20),
            "a parte 3 de 3 — 6 dos 20 cenarios"
        );
    }

    #[test]
    fn o_anuncio_da_suite_se_le() {
        assert_eq!(
            ler_o_anuncio("  suite de testes :: x86_64 :: 989 casos"),
            Some(Anuncio {
                parte: None,
                rodados: 989,
                total: 989
            })
        );
        assert_eq!(
            ler_o_anuncio("  suite de testes :: aarch64 :: parte 2 de 40: 31 de 987 casos\r"),
            Some(Anuncio {
                parte: parte(2, 40),
                rodados: 31,
                total: 987
            })
        );
        for nao in [
            "",
            "  suite de testes :: x86_64",
            "  suite de testes :: x86_64 :: casos",
            "  suite de testes :: x86_64 :: parte 0 de 2: 1 de 3 casos",
            "  suite de testes :: x86_64 :: parte 3 de 2: 1 de 3 casos",
            "  suite de testes :: x86_64 :: parte 1 de 2 1 de 3 casos",
            "  suite de testes :: x86_64 :: parte um de 2: 1 de 3 casos",
            "  memoria: clonar compartilha sem copiar     ok",
        ] {
            assert_eq!(ler_o_anuncio(nao), None, "{nao}");
        }
    }

    #[test]
    fn o_placar_se_le_campo_a_campo() {
        assert_eq!(ler_o_placar("  31 de 31 passaram"), Some((31, 31)));
        assert_eq!(ler_o_placar("  30 de 31 passaram\r"), Some((30, 31)));
        assert_eq!(ler_o_placar("janela de MMIO em 0x1000"), None);
        assert_eq!(ler_o_placar("  31 de 31 passaram, quase"), None);
        // Nada depois do placar: a linha é ele inteira.
        assert_eq!(ler_o_placar("  31 de 31 passaram agora"), None);
        assert_eq!(ler_o_placar("  31 de 31"), None);
    }

    fn saida(linhas: &[&'static str]) -> Vec<&'static str> {
        linhas.to_vec()
    }

    #[test]
    fn a_suite_que_rodou_a_parte_pedida_passa() {
        let s = saida(&[
            "=====",
            "  suite de testes :: x86_64 :: parte 1 de 40: 32 de 989 casos",
            "  json: desescapa os substitutos    ok",
            "-----",
            "  32 de 32 passaram",
            "  pilha: estouro e detectado        ok",
        ]);
        assert_eq!(
            conferir_a_suite(parte(1, 40), s.iter().copied()),
            Ok(Anuncio {
                parte: parte(1, 40),
                rodados: 32,
                total: 989
            })
        );
        let inteira = saida(&[
            "  suite de testes :: aarch64 :: 987 casos",
            "  987 de 987 passaram",
        ]);
        assert!(conferir_a_suite(None, inteira.iter().copied()).is_ok());
    }

    #[test]
    fn a_suite_de_outra_parte_ou_sem_anuncio_reprova() {
        let da_parte = saida(&[
            "  suite de testes :: x86_64 :: parte 2 de 40: 31 de 989 casos",
            "  31 de 31 passaram",
        ]);
        // Outra parte, e a inteira, contra um ELF da parte 2 de 40.
        let erro = conferir_a_suite(parte(1, 40), da_parte.iter().copied()).unwrap_err();
        assert!(
            erro.contains("a parte 1/40") && erro.contains("a parte 2/40"),
            "{erro}"
        );
        let erro = conferir_a_suite(None, da_parte.iter().copied()).unwrap_err();
        assert!(erro.contains("a suíte inteira"), "{erro}");
        // A inteira contra quem pediu uma parte.
        let inteira = saida(&[
            "  suite de testes :: x86_64 :: 989 casos",
            "  989 de 989 passaram",
        ]);
        assert!(conferir_a_suite(parte(1, 2), inteira.iter().copied()).is_err());
        // Sem anúncio.
        let muda = saida(&["  989 de 989 passaram"]);
        assert!(conferir_a_suite(None, muda.iter().copied()).is_err());
        // Dois anúncios: a máquina subiu duas vezes.
        let duas = saida(&[
            "  suite de testes :: x86_64 :: 989 casos",
            "  suite de testes :: x86_64 :: 989 casos",
            "  989 de 989 passaram",
        ]);
        assert!(conferir_a_suite(None, duas.iter().copied()).is_err());
    }

    #[test]
    fn o_placar_tem_de_contar_os_anunciados() {
        let a = "  suite de testes :: x86_64 :: parte 1 de 2: 500 de 989 casos";
        // O placar de outra contagem, nenhum, ou dois.
        for placar in [
            vec!["  499 de 500 passaram"],
            vec!["  989 de 989 passaram"],
            vec![],
            vec!["  500 de 500 passaram", "  500 de 500 passaram"],
        ] {
            let mut s = vec![a];
            s.extend(placar.iter().copied());
            assert!(
                conferir_a_suite(parte(1, 2), s.iter().copied()).is_err(),
                "{s:?}"
            );
        }
        let mut s = vec![a];
        s.push("  500 de 500 passaram");
        assert!(conferir_a_suite(parte(1, 2), s.iter().copied()).is_ok());
    }

    #[test]
    fn o_anuncio_menor_que_a_fatia_da_regra_reprova() {
        // A parte 1 de 2 de 989 tem 495 pela regra; 400 é outra conta.
        let s = saida(&[
            "  suite de testes :: x86_64 :: parte 1 de 2: 400 de 989 casos",
            "  400 de 400 passaram",
        ]);
        let erro = conferir_a_suite(parte(1, 2), s.iter().copied()).unwrap_err();
        assert!(erro.contains("menos que os 495"), "{erro}");
    }

    /// A parte vai para a compilação da suíte, e só para ela: sem parte, a
    /// variável sai do ambiente do cargo — um valor herdado de um shell não
    /// chega ao kernel —; com ela, vai com o texto `k/n`. E uma parte numa
    /// compilação sem `modo-teste` é recusada antes do cargo.
    #[test]
    fn a_parte_so_vai_para_a_compilacao_da_suite() {
        use std::ffi::{OsStr, OsString};
        let ambiente = |p: Option<Parte>| -> Vec<(OsString, Option<OsString>)> {
            let mut cargo = std::process::Command::new("cargo");
            super::super::ambiente_do_kernel(&mut cargo, p);
            cargo
                .get_envs()
                .map(|(k, v)| (k.to_owned(), v.map(OsStr::to_owned)))
                .collect()
        };
        let sem = ambiente(None);
        assert!(sem.contains(&(OsString::from(DA_SUITE), None)), "{sem:?}");
        let com = ambiente(parte(2, 3));
        assert!(
            com.contains(&(OsString::from(DA_SUITE), Some(OsString::from("2/3")))),
            "{com:?}"
        );
        // E o que o cargo exporta para o `xtask` sai nos dois.
        for var in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR"] {
            assert!(sem.contains(&(OsString::from(var), None)), "{var}");
            assert!(com.contains(&(OsString::from(var), None)), "{var}");
        }
        let fora = super::super::compilar_o_kernel_com(
            super::super::Arquitetura::X86_64,
            false,
            &[],
            None,
            parte(1, 2),
        );
        assert!(fora.is_err_and(|e| e.contains("modo-teste")));
    }

    /// O nome da variável da compilação é o mesmo dos dois lados: o
    /// `option_env!` do kernel e a constante daqui. Divergindo, o kernel não
    /// receberia a parte, rodaria a suíte inteira — e o anúncio reprovaria,
    /// mas só depois de uma suíte inteira de máquina.
    #[test]
    fn o_kernel_le_a_parte_da_variavel_que_o_xtask_poe() {
        let testes =
            std::fs::read_to_string(super::super::raiz_do_projeto().join("kernel/src/testes.rs"))
                .expect("kernel/src/testes.rs");
        assert!(
            testes.contains(&format!("option_env!(\"{DA_SUITE}\")")),
            "o kernel não lê {DA_SUITE}"
        );
        assert!(
            !testes.contains("option_env!(\"DUKE_PARTE\")")
                && !testes.contains("env!(\"DUKE_PARTE\")"),
            "o kernel lê DUKE_PARTE direto"
        );
    }
}
