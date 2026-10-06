//! Os testes do armazém, no hospedeiro.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::bloco::{self, CARGA, TAM_BLOCO};
use crate::mapa::Mapa;
use crate::registro::{self, Entrada, Volume};
use crate::*;

const ATOR: &str = "agente:aa";
const OUTRO: &str = "agente:bb";
const LIVRE: Cota = Cota {
    bytes: u64::MAX / 4,
    objetos: u64::MAX / 4,
};
const TETO: usize = usize::MAX / 4;

fn s(t: &str) -> String {
    String::from(t)
}

/// Um conteúdo de `tamanho` bytes, em blocos a partir de `bloco`, numa
/// extensão só.
fn conteudo(tamanho: u64, bloco: u64, id: u8) -> Conteudo {
    let n = tamanho.div_ceil(CARGA as u64);
    Conteudo {
        tamanho,
        extensoes: if n == 0 {
            vec![]
        } else {
            vec![Extensao {
                bloco,
                quantos: n as u32,
                id: [id; 16],
                indice: 0,
            }]
        },
    }
}

fn gravar(c: &str, esperada: u64, conteudo: Conteudo) -> Op {
    Op::Gravar {
        caminho: s(c),
        esperada,
        conteudo,
    }
}

fn mkdir(c: &str) -> Op {
    Op::CriarDiretorio { caminho: s(c) }
}

fn mv(de: &str, para: &str, esperada: u64) -> Op {
    Op::Renomear {
        de: s(de),
        para: s(para),
        esperada,
    }
}

/// Prepara e aplica, como o kernel faz depois de gravar.
fn fazer(a: &mut Armazem, ator: &str, ops: &[Op]) -> Result<Faixas, (usize, Recusa)> {
    let lote = a.preparar(ops, ator, LIVRE, 0, TETO)?;
    let saidas = a.aplicar(&lote).expect("o lote preparado se aplica");
    assert!(a.coerente(), "{a:?}");
    Ok(saidas)
}

/// O mesmo armazém refeito do zero pelo journal: cada lote codificado,
/// lido de volta e aplicado num armazém vazio.
fn reposto(lotes: &[Lote]) -> Armazem {
    let mut b = Armazem::novo();
    for l in lotes {
        let bytes = registro::lote(&l.mudancas).expect("codifica");
        let mudancas = registro::entradas(&bytes)
            .expect("decodifica")
            .into_iter()
            .map(|e| match e {
                Entrada::Mudanca(m) => m,
                outra => panic!("{outra:?}"),
            })
            .collect();
        b.aplicar(&Lote {
            mudancas,
            proxima: 0,
        })
        .expect("o journal se reaplica");
    }
    b
}

#[test]
fn caminhos() {
    assert!(caminho_valido("a"));
    assert!(caminho_valido("a/b-c/d.txt"));
    for ruim in ["", "/a", "a/", "a//b", ".", "..", "a/../b", "a b", "a/./b"] {
        assert!(!caminho_valido(ruim), "{ruim}");
    }
    let fundo = ["x"; MAIS_NIVEIS].join("/");
    assert!(caminho_valido(&fundo));
    assert!(!caminho_valido(&alloc::format!("{fundo}/y")));
    assert!(!componente_valido(&"a".repeat(MAIOR_COMPONENTE + 1)));
    assert_eq!(pai("a/b/c"), "a/b");
    assert_eq!(pai("a"), "");
    assert!(abaixo_de("a/b", "a"));
    assert!(!abaixo_de("ab", "a"));
    assert!(!abaixo_de("a", "a"));
    assert!(abaixo_de("a", ""));
}

#[test]
fn nada_nasce_sem_o_pai() {
    let mut a = Armazem::novo();
    assert_eq!(
        fazer(&mut a, ATOR, &[gravar("d/x", 0, Conteudo::vazio())]),
        Err((0, Recusa::PaiNaoExiste))
    );
    assert_eq!(
        fazer(&mut a, ATOR, &[mkdir("d/e")]),
        Err((0, Recusa::PaiNaoExiste))
    );
    fazer(&mut a, ATOR, &[mkdir("d")]).unwrap();
    fazer(&mut a, ATOR, &[gravar("d/x", 0, Conteudo::vazio())]).unwrap();
    assert_eq!(a.tipo("d"), Some(Tipo::Diretorio));
    // Um arquivo não é pai.
    assert_eq!(
        fazer(&mut a, ATOR, &[gravar("d/x/y", 0, Conteudo::vazio())]),
        Err((0, Recusa::NaoEhDiretorio))
    );
    assert_eq!(
        fazer(&mut a, ATOR, &[gravar("d", 0, Conteudo::vazio())]),
        Err((0, Recusa::EhDiretorio))
    );
}

#[test]
fn versoes_nunca_voltam() {
    let mut a = Armazem::novo();
    fazer(&mut a, ATOR, &[gravar("x", 0, conteudo(10, 0, 1))]).unwrap();
    let v1 = a.versao("x");
    assert_eq!(
        fazer(&mut a, ATOR, &[gravar("x", 0, conteudo(10, 1, 2))]),
        Err((0, Recusa::Versao { atual: v1 }))
    );
    fazer(&mut a, ATOR, &[gravar("x", v1, conteudo(20, 1, 2))]).unwrap();
    let v2 = a.versao("x");
    assert!(v2 > v1);
    assert!(a.por_versao(v1).is_none());
    assert_eq!(a.por_versao(v2).map(|(c, _)| c), Some("x"));
    fazer(
        &mut a,
        ATOR,
        &[Op::Apagar {
            caminho: s("x"),
            esperada: v2,
        }],
    )
    .unwrap();
    assert_eq!(a.versao("x"), 0);
    fazer(&mut a, ATOR, &[gravar("x", 0, Conteudo::vazio())]).unwrap();
    assert!(a.versao("x") > v2 + 1, "a remocao gastou uma versao");
    assert_eq!(
        fazer(
            &mut a,
            ATOR,
            &[Op::Apagar {
                caminho: s("y"),
                esperada: 0
            }]
        ),
        Err((0, Recusa::NaoExiste))
    );
}

#[test]
fn diretorios_explicitos() {
    let mut a = Armazem::novo();
    fazer(&mut a, ATOR, &[mkdir("d"), mkdir("d/e")]).unwrap();
    assert_eq!(fazer(&mut a, ATOR, &[mkdir("d")]), Err((0, Recusa::Existe)));
    let vd = a.versao("d");
    let rmdir = |c: &str, esperada| Op::RemoverDiretorio {
        caminho: s(c),
        esperada,
    };
    assert_eq!(
        fazer(&mut a, ATOR, &[rmdir("d", vd)]),
        Err((0, Recusa::NaoVazio))
    );
    let ve = a.versao("d/e");
    assert_eq!(
        fazer(&mut a, ATOR, &[rmdir("d/e", ve + 1)]),
        Err((0, Recusa::Versao { atual: ve }))
    );
    // Vazio, existe e se lista; depois sai.
    assert_eq!(a.filhos("d"), vec![(s("e"), Tipo::Diretorio)]);
    fazer(&mut a, ATOR, &[rmdir("d/e", ve), rmdir("d", vd)]).unwrap();
    assert_eq!(a.quantos(), 0);
    assert_eq!(
        fazer(&mut a, ATOR, &[rmdir("z", 0)]),
        Err((0, Recusa::NaoExiste))
    );
    fazer(&mut a, ATOR, &[gravar("f", 0, Conteudo::vazio())]).unwrap();
    let vf = a.versao("f");
    assert_eq!(
        fazer(&mut a, ATOR, &[rmdir("f", vf)]),
        Err((0, Recusa::NaoEhDiretorio))
    );
}

#[test]
fn filhos_em_ordem_de_nome() {
    let mut a = Armazem::novo();
    fazer(
        &mut a,
        ATOR,
        &[
            mkdir("b"),
            mkdir("b/x"),
            gravar("b-c", 0, Conteudo::vazio()),
            gravar("b.d", 0, Conteudo::vazio()),
            gravar("b/x/y", 0, Conteudo::vazio()),
            gravar("a", 0, Conteudo::vazio()),
        ],
    )
    .unwrap();
    let nomes: Vec<String> = a.filhos("").into_iter().map(|(n, _)| n).collect();
    assert_eq!(nomes, vec![s("a"), s("b"), s("b-c"), s("b.d")]);
    assert_eq!(a.filhos("b"), vec![(s("x"), Tipo::Diretorio)]);
    assert!(a.filhos("a").is_empty());
}

#[test]
fn renomear_um_arquivo() {
    let mut a = Armazem::novo();
    fazer(
        &mut a,
        ATOR,
        &[mkdir("d"), gravar("x", 0, conteudo(5, 0, 1))],
    )
    .unwrap();
    let v = a.versao("x");
    let antes = a.no("x").cloned().unwrap();
    fazer(&mut a, ATOR, &[mv("x", "d/y", v)]).unwrap();
    assert!(a.no("x").is_none());
    let depois = a.no("d/y").unwrap();
    assert_eq!(depois.conteudo(), antes.conteudo());
    assert!(depois.versao() > v);
    assert!(
        a.por_versao(v).is_none(),
        "a versao velha nao acha o movido"
    );
}

#[test]
fn renomear_recusa_o_que_escaparia() {
    let mut a = Armazem::novo();
    fazer(
        &mut a,
        ATOR,
        &[mkdir("a"), mkdir("a/b"), gravar("c", 0, Conteudo::vazio())],
    )
    .unwrap();
    let va = a.versao("a");
    assert_eq!(
        fazer(&mut a, ATOR, &[mv("a", "a/b/z", va)]),
        Err((0, Recusa::DentroDeSi))
    );
    assert_eq!(
        fazer(&mut a, ATOR, &[mv("a", "a", va)]),
        Err((0, Recusa::DentroDeSi))
    );
    assert_eq!(
        fazer(&mut a, ATOR, &[mv("a", "c", va)]),
        Err((0, Recusa::Existe))
    );
    assert_eq!(
        fazer(&mut a, ATOR, &[mv("a", "q/z", va)]),
        Err((0, Recusa::PaiNaoExiste))
    );
    assert_eq!(
        fazer(&mut a, ATOR, &[mv("a", "c/z", va)]),
        Err((0, Recusa::NaoEhDiretorio))
    );
    assert_eq!(
        fazer(&mut a, ATOR, &[mv("a", "../z", va)]),
        Err((0, Recusa::CaminhoInvalido))
    );
    assert_eq!(
        fazer(&mut a, ATOR, &[mv("a", "z", va + 99)]),
        Err((0, Recusa::Versao { atual: va }))
    );
    assert_eq!(
        fazer(&mut a, ATOR, &[mv("nada", "z", 0)]),
        Err((0, Recusa::NaoExiste))
    );
    // Fundo demais depois do movimento: recusado antes de mover.
    let mut ops = Vec::new();
    let mut c = String::from("f");
    ops.push(mkdir("f"));
    for _ in 1..MAIS_NIVEIS {
        c.push_str("/f");
        ops.push(mkdir(&c));
    }
    fazer(&mut a, ATOR, &ops).unwrap();
    let vf = a.versao("f");
    assert_eq!(
        fazer(&mut a, ATOR, &[mv("f", "a/b/f", vf)]),
        Err((0, Recusa::CaminhoInvalido))
    );
    assert!(a.no(&c).is_some());
}

#[test]
fn renomear_um_diretorio_leva_tudo_com_versoes_novas() {
    let mut a = Armazem::novo();
    fazer(
        &mut a,
        ATOR,
        &[
            mkdir("a"),
            mkdir("a/b"),
            gravar("a/b/x", 0, conteudo(5000, 0, 1)),
            gravar("a/y", 0, conteudo(1, 2, 2)),
            gravar("ab", 0, Conteudo::vazio()),
            mkdir("z"),
        ],
    )
    .unwrap();
    let antigas: Vec<u64> = ["a", "a/b", "a/b/x", "a/y"]
        .iter()
        .map(|c| a.versao(c))
        .collect();
    let proxima = a.proxima();
    let l = a
        .preparar(&[mv("a", "z/n", antigas[0])], ATOR, LIVRE, 0, TETO)
        .unwrap();
    assert_eq!(
        l.mudancas,
        vec![Mudanca::Movido {
            de: s("a"),
            para: s("z/n"),
            versao: proxima
        }]
    );
    let saidas = a.aplicar(&l).unwrap();
    assert!(saidas.is_empty(), "mover nao solta bloco nenhum");
    // A irmã de nome parecido fica.
    assert!(a.no("ab").is_some());
    for (i, c) in ["z/n", "z/n/b", "z/n/b/x", "z/n/y"].iter().enumerate() {
        assert_eq!(a.versao(c), proxima + i as u64, "{c}");
    }
    for v in antigas {
        assert!(a.por_versao(v).is_none());
    }
    assert!(a.coerente());
    assert_eq!(a.proxima(), proxima + 4);
}

#[test]
fn o_lote_e_inteiro_ou_nada() {
    let mut a = Armazem::novo();
    fazer(
        &mut a,
        ATOR,
        &[mkdir("d"), gravar("d/x", 0, conteudo(1, 0, 1))],
    )
    .unwrap();
    let antes = a.clone();
    // A terceira recusa: nada das duas primeiras vale.
    let r = fazer(
        &mut a,
        ATOR,
        &[
            mkdir("e"),
            gravar("e/y", 0, conteudo(1, 1, 2)),
            Op::Apagar {
                caminho: s("d/x"),
                esperada: 999,
            },
        ],
    );
    assert_eq!(
        r,
        Err((
            2,
            Recusa::Versao {
                atual: antes.versao("d/x")
            }
        ))
    );
    assert_eq!(a, antes);
    // Cada operação vê as anteriores: criar e já escrever dentro; trocar
    // dois nomes por um terceiro, num lote só.
    fazer(
        &mut a,
        ATOR,
        &[mkdir("p"), gravar("p/um", 0, conteudo(1, 3, 3)), mkdir("q")],
    )
    .unwrap();
    let (vp, vq) = (a.versao("p"), a.versao("q"));
    fazer(&mut a, ATOR, &[mv("p", "t", vp), mv("q", "p", vq)]).unwrap();
    let vt = a.versao("t");
    fazer(&mut a, ATOR, &[mv("t", "q", vt)]).unwrap();
    assert!(a.no("q/um").is_some());
    assert_eq!(a.tipo("p"), Some(Tipo::Diretorio));
    assert!(a.filhos("p").is_empty());
}

#[test]
fn a_cota_e_do_lote_e_de_quem_pede() {
    let mut a = Armazem::novo();
    let cota = Cota {
        bytes: 10_000,
        objetos: 3,
    };
    let preparar =
        |a: &Armazem, ops: &[Op], reservado| a.preparar(ops, ATOR, cota, reservado, TETO);
    let l = preparar(&a, &[mkdir("d"), gravar("d/x", 0, conteudo(6000, 0, 1))], 0).unwrap();
    a.aplicar(&l).unwrap();
    assert_eq!(
        a.uso(ATOR),
        Uso {
            bytes: 6000,
            objetos: 2
        }
    );
    // Passaria dos bytes com o que ele tem reservado fora.
    assert_eq!(
        preparar(&a, &[gravar("d/y", 0, conteudo(3000, 2, 2))], 2000),
        Err((0, Recusa::Cota))
    );
    // Passaria dos objetos.
    let l = preparar(&a, &[gravar("d/y", 0, conteudo(10, 2, 2))], 0).unwrap();
    a.aplicar(&l).unwrap();
    assert_eq!(preparar(&a, &[mkdir("e")], 0), Err((0, Recusa::Cota)));
    // Trocar um pelo outro no mesmo lote passa: a conta é do lote.
    let v = a.versao("d/y");
    assert!(
        preparar(
            &a,
            &[
                Op::Apagar {
                    caminho: s("d/y"),
                    esperada: v
                },
                mkdir("e")
            ],
            0
        )
        .is_ok()
    );
    // A cota baixou abaixo do uso: o que diminui passa, o que aumenta não.
    let baixa = Cota {
        bytes: 100,
        objetos: 1,
    };
    let vx = a.versao("d/x");
    assert!(
        a.preparar(
            &[gravar("d/x", vx, conteudo(50, 3, 3))],
            ATOR,
            baixa,
            0,
            TETO
        )
        .is_ok()
    );
    assert_eq!(
        a.preparar(
            &[gravar("d/x", vx, conteudo(7000, 3, 3))],
            ATOR,
            baixa,
            0,
            TETO
        ),
        Err((0, Recusa::Cota))
    );
    // Outro dono que sobrescreve paga o que gravou; o de antes deixa de
    // pagar.
    let l = a
        .preparar(
            &[gravar("d/x", vx, conteudo(100, 5, 4))],
            OUTRO,
            LIVRE,
            0,
            TETO,
        )
        .unwrap();
    a.aplicar(&l).unwrap();
    assert_eq!(
        a.uso(OUTRO),
        Uso {
            bytes: 100,
            objetos: 1
        }
    );
    assert_eq!(
        a.uso(ATOR),
        Uso {
            bytes: 10,
            objetos: 2
        }
    );
    // Sem linha, sem cota.
    assert_eq!(
        a.preparar(&[mkdir("w")], "pessoa:x", Cota::NENHUMA, 0, TETO),
        Err((0, Recusa::Cota))
    );
}

#[test]
fn duas_vezes_seguidas_nao_passam_da_cota() {
    // O kernel prepara e aplica um lote de cada vez: o segundo vê o
    // primeiro, e os dois juntos não passam.
    let mut a = Armazem::novo();
    fazer(&mut a, ATOR, &[mkdir("d")]).unwrap();
    let cota = Cota {
        bytes: 100,
        objetos: 100,
    };
    let um = a
        .preparar(
            &[gravar("d/a", 0, conteudo(60, 0, 1))],
            OUTRO,
            cota,
            0,
            TETO,
        )
        .unwrap();
    a.aplicar(&um).unwrap();
    assert_eq!(
        a.preparar(
            &[gravar("d/b", 0, conteudo(60, 1, 2))],
            OUTRO,
            cota,
            0,
            TETO
        ),
        Err((0, Recusa::Cota))
    );
}

#[test]
fn o_teto_dos_metadados() {
    let a = Armazem::novo();
    let teto = CUSTO_DE_NO + 1 + ATOR.len();
    assert!(a.preparar(&[mkdir("d")], ATOR, LIVRE, 0, teto).is_ok());
    assert_eq!(
        a.preparar(&[mkdir("d"), mkdir("e")], ATOR, LIVRE, 0, teto),
        Err((1, Recusa::Cheio))
    );
}

#[test]
fn os_blocos_que_saem() {
    let carga = CARGA as u64;
    let mut a = Armazem::novo();
    fazer(&mut a, ATOR, &[gravar("x", 0, conteudo(3 * carga, 10, 1))]).unwrap();
    // Substituir solta o conteúdo velho inteiro.
    let v = a.versao("x");
    let saidas = fazer(&mut a, ATOR, &[gravar("x", v, conteudo(10, 20, 2))]).unwrap();
    assert_eq!(saidas, vec![(10, 13)]);
    // Um conteúdo de dois blocos e meio, e o acréscimo que o completa: os
    // blocos cheios ficam, o último é reescrito noutro lugar.
    let v = a.versao("x");
    let base = conteudo(2 * carga + 7, 30, 3);
    let saidas = fazer(&mut a, ATOR, &[gravar("x", v, base.clone())]).unwrap();
    assert_eq!(saidas, vec![(20, 21)]);
    let mut acrescido = base.clone();
    acrescido.tamanho = 3 * carga;
    acrescido.extensoes[0].quantos = 2;
    acrescido.extensoes.push(Extensao {
        bloco: 40,
        quantos: 1,
        id: [4; 16],
        indice: 2,
    });
    let v = a.versao("x");
    let saidas = fazer(&mut a, ATOR, &[gravar("x", v, acrescido)]).unwrap();
    assert_eq!(saidas, vec![(32, 33)]);
    // Escrito duas vezes no mesmo lote: o primeiro conteúdo sai também.
    let v = a.versao("x");
    let saidas = fazer(
        &mut a,
        ATOR,
        &[
            gravar("x", v, conteudo(1, 50, 5)),
            gravar("x", v + 1, conteudo(1, 51, 6)),
        ],
    )
    .unwrap();
    assert_eq!(saidas, vec![(30, 32), (40, 41), (50, 51)]);
    // Apagar solta tudo.
    let v = a.versao("x");
    let saidas = fazer(
        &mut a,
        ATOR,
        &[Op::Apagar {
            caminho: s("x"),
            esperada: v,
        }],
    )
    .unwrap();
    assert_eq!(saidas, vec![(51, 52)]);
    assert!(a.blocos_em_uso().is_empty());
}

#[test]
fn conteudo_incoerente_e_recusado() {
    let carga = CARGA as u64;
    let a = Armazem::novo();
    let mut c = conteudo(2 * carga, 0, 1);
    c.tamanho += 1;
    assert_eq!(
        a.preparar(&[gravar("x", 0, c)], ATOR, LIVRE, 0, TETO),
        Err((0, Recusa::ConteudoIncoerente))
    );
    let mut c = conteudo(2 * carga, 0, 1);
    c.extensoes[0].indice = 1;
    assert!(!c.valido());
    let buraco = Conteudo {
        tamanho: 3 * carga,
        extensoes: vec![
            Extensao {
                bloco: 0,
                quantos: 1,
                id: [1; 16],
                indice: 0,
            },
            Extensao {
                bloco: 5,
                quantos: 1,
                id: [1; 16],
                indice: 2,
            },
        ],
    };
    assert!(!buraco.valido());
    let certo = Conteudo {
        tamanho: 3 * carga,
        extensoes: vec![
            Extensao {
                bloco: 9,
                quantos: 2,
                id: [1; 16],
                indice: 0,
            },
            Extensao {
                bloco: 4,
                quantos: 1,
                id: [2; 16],
                indice: 2,
            },
        ],
    };
    assert!(certo.valido());
    assert_eq!(certo.onde(0), Some((9, [1; 16])));
    assert_eq!(certo.onde(1), Some((10, [1; 16])));
    assert_eq!(certo.onde(2), Some((4, [2; 16])));
    assert_eq!(certo.onde(3), None);
}

#[test]
fn o_journal_repoe_e_a_base_tambem() {
    let mut a = Armazem::novo();
    let mut lotes = Vec::new();
    let mut lote = |a: &mut Armazem, ator: &str, ops: &[Op]| {
        let l = a.preparar(ops, ator, LIVRE, 0, TETO).unwrap();
        a.aplicar(&l).unwrap();
        lotes.push(l);
    };
    lote(
        &mut a,
        ATOR,
        &[mkdir("d"), gravar("d/x", 0, conteudo(9000, 0, 1))],
    );
    lote(
        &mut a,
        OUTRO,
        &[mkdir("d/e"), gravar("0", 0, Conteudo::vazio())],
    );
    let vx = a.versao("d/x");
    lote(&mut a, ATOR, &[mv("d/x", "d/e/x", vx)]);
    let v0 = a.versao("0");
    lote(
        &mut a,
        OUTRO,
        &[Op::Apagar {
            caminho: s("0"),
            esperada: v0,
        }],
    );
    assert_eq!(reposto(&lotes), a);
    assert!(reposto(&lotes).coerente());
    // A base: os nós em ordem de caminho, e a próxima.
    let mut b = Armazem::novo();
    for (c, n) in a.todos() {
        let no = match registro::decodificar(&registro::codificar_no(c, n).unwrap()).unwrap() {
            Entrada::Mudanca(Mudanca::Arquivo {
                versao,
                conteudo,
                dono,
                ..
            }) => No::Arquivo {
                versao,
                conteudo,
                dono,
            },
            Entrada::Mudanca(Mudanca::Diretorio { versao, dono, .. }) => {
                No::Diretorio { versao, dono }
            }
            outra => panic!("{outra:?}"),
        };
        b.restaurar(c, no).unwrap();
    }
    b.fixar_proxima(a.proxima()).unwrap();
    assert_eq!(b, a);
    assert!(b.coerente());
    assert_eq!(b.uso(ATOR), a.uso(ATOR));
    // A próxima da base não volta nem fica abaixo de uma versão reposta.
    assert!(b.fixar_proxima(1).is_err());
    // Um nó repetido, ou sem pai, não se repõe.
    assert_eq!(
        b.restaurar(
            "d",
            No::Diretorio {
                versao: 999,
                dono: s(ATOR)
            }
        ),
        Err(Recusa::Existe)
    );
    assert_eq!(
        b.restaurar(
            "q/r",
            No::Diretorio {
                versao: 998,
                dono: s(ATOR)
            }
        ),
        Err(Recusa::PaiNaoExiste)
    );
}

#[test]
fn o_journal_fora_de_ordem_nao_se_aplica() {
    let mut a = Armazem::novo();
    let l = a.preparar(&[mkdir("d")], ATOR, LIVRE, 0, TETO).unwrap();
    a.aplicar(&l).unwrap();
    // O mesmo lote outra vez: a versão já foi vista.
    assert_eq!(a.aplicar(&l), Err(Recusa::ForaDeOrdem));
    let mut b = Armazem::novo();
    assert_eq!(
        b.aplicar(&Lote {
            mudancas: vec![Mudanca::Removido {
                caminho: s("x"),
                versao: 5
            }],
            proxima: 0
        }),
        Err(Recusa::NaoExiste)
    );
}

#[test]
fn o_registro_se_le_e_recusa_o_que_nao_se_le() {
    let ms = vec![
        Mudanca::Arquivo {
            caminho: s("a/b"),
            versao: 7,
            conteudo: Conteudo {
                tamanho: 2 * CARGA as u64,
                extensoes: vec![Extensao {
                    bloco: 3,
                    quantos: 2,
                    id: [9; 16],
                    indice: 0,
                }],
            },
            dono: s(ATOR),
        },
        Mudanca::Diretorio {
            caminho: s("a"),
            versao: 8,
            dono: s(OUTRO),
        },
        Mudanca::Removido {
            caminho: s("z"),
            versao: 9,
        },
        Mudanca::Movido {
            de: s("p"),
            para: s("q/r"),
            versao: 10,
        },
    ];
    let bytes = registro::lote(&ms).unwrap();
    let lidas: Vec<Mudanca> = registro::entradas(&bytes)
        .unwrap()
        .into_iter()
        .map(|e| match e {
            Entrada::Mudanca(m) => m,
            _ => panic!(),
        })
        .collect();
    assert_eq!(lidas, ms);
    let v = Volume {
        id: [3; 16],
        setores: 1 << 20,
        setores_do_diario: 4096,
    };
    assert_eq!(
        registro::decodificar(&registro::volume(&v).unwrap()),
        Ok(Entrada::Volume(v))
    );
    assert_eq!(
        registro::decodificar(&registro::proxima(42).unwrap()),
        Ok(Entrada::Proxima(42))
    );
    // Cortada em qualquer ponto, não se lê.
    let uma = registro::codificar(&ms[0]).unwrap();
    for n in 0..uma.len() {
        assert!(registro::decodificar(&uma[..n]).is_err(), "{n}");
    }
    // Um tipo desconhecido, ou os campos de outro tipo.
    let estranha = diario::estado::campos(&[&99u16.to_le_bytes(), b"x"]).unwrap();
    assert!(registro::decodificar(&estranha).is_err());
    let trocada = diario::estado::campos(&[&registro::tipo::REMOVIDO.to_le_bytes(), b"x"]).unwrap();
    assert!(registro::decodificar(&trocada).is_err());
}

#[test]
fn o_mapa_dos_blocos() {
    let mut m = Mapa::novo(100);
    assert_eq!(m.reservar(10, 4).unwrap(), vec![(0, 10)]);
    assert_eq!(m.reservar(20, 4).unwrap(), vec![(10, 30)]);
    assert_eq!(m.livres(), 70);
    m.soltar(0, 10).unwrap();
    // Contígua, do cursor em volta.
    assert_eq!(m.reservar(70, 4).unwrap(), vec![(30, 100)]);
    // Em pedaços, quando não há uma faixa inteira — e no máximo `mais`.
    m.soltar(40, 45).unwrap();
    assert_eq!(m.reservar(15, 1), None);
    assert_eq!(m.reservar(15, 2).unwrap(), vec![(0, 10), (40, 45)]);
    assert_eq!(m.livres(), 0);
    assert_eq!(m.reservar(1, 4), None);
    // Marcar o que está em uso, soltar o que está livre: erro, e nada muda.
    assert!(m.marcar(5, 6).is_err());
    m.soltar(0, 10).unwrap();
    assert!(m.soltar(0, 1).is_err());
    assert!(m.marcar(95, 101).is_err());
    assert_eq!(m.livres(), 10);
    assert_eq!(m.contar_usados(), 90);
    assert_eq!(m.reservar(0, 0), Some(vec![]));
}

#[test]
fn os_blocos_cifrados() {
    let chave = [7u8; 32];
    let volume = [1u8; 16];
    let id = [2u8; 16];
    let mut b = [0u8; TAM_BLOCO];
    bloco::selar(&chave, &volume, &id, 5, b"conteudo secreto", &mut b).unwrap();
    assert!(
        !b.windows(8).any(|w| w == b"conteudo"),
        "o claro foi para o disco"
    );
    let mut c = b;
    assert_eq!(
        &bloco::abrir(&chave, &volume, &id, 5, &mut c).unwrap()[..16],
        b"conteudo secreto"
    );
    // Outro índice, outra escrita, outro volume, outra chave: não abre.
    for (k, v, i, n) in [
        ([7u8; 32], [1u8; 16], [2u8; 16], 6u64),
        ([7u8; 32], [1u8; 16], [3u8; 16], 5),
        ([7u8; 32], [9u8; 16], [2u8; 16], 5),
        ([8u8; 32], [1u8; 16], [2u8; 16], 5),
    ] {
        let mut c = b;
        assert!(bloco::abrir(&k, &v, &i, n, &mut c).is_err());
    }
    // Um bit trocado em qualquer lugar: não abre.
    for pos in [0, 100, CARGA - 1, CARGA, TAM_BLOCO - 1] {
        let mut c = b;
        c[pos] ^= 1;
        assert!(
            bloco::abrir(&chave, &volume, &id, 5, &mut c).is_err(),
            "{pos}"
        );
    }
    assert!(bloco::selar(&chave, &volume, &id, 0, &[0; CARGA + 1], &mut b).is_err());
}

#[test]
fn faixas() {
    assert_eq!(
        normalizar(vec![(5, 7), (0, 2), (1, 3), (7, 9), (4, 4)]),
        vec![(0, 3), (5, 9)]
    );
    assert_eq!(
        subtrair(&[(0, 10)], &[(2, 3), (5, 7)]),
        vec![(0, 2), (3, 5), (7, 10)]
    );
    assert_eq!(subtrair(&[(0, 10), (20, 30)], &[(0, 30)]), vec![]);
    assert_eq!(subtrair(&[(0, 10)], &[]), vec![(0, 10)]);
    assert_eq!(subtrair(&[(5, 10)], &[(0, 6), (9, 12)]), vec![(6, 9)]);
}

/// Uma sequência longa de lotes sorteados — com recusas no meio —, e depois
/// de cada um: a conta coerente, o lote recusado sem efeito, e o journal
/// repondo exatamente o mesmo armazém. O mapa de blocos acompanha como o
/// kernel o acompanha: nenhum bloco de dois arquivos, nenhum que se perde.
#[test]
fn sequencias_sorteadas() {
    let mut semente = 0x9E37_79B9_7F4A_7C15u64;
    let mut sorteio = move |n: u64| {
        semente ^= semente << 13;
        semente ^= semente >> 7;
        semente ^= semente << 17;
        semente % n
    };
    let nomes = ["a", "b", "a/c", "a/d", "b/e", "a/c/f", "g"];
    let mut a = Armazem::novo();
    let mut mapa = Mapa::novo(4096);
    let mut lotes = Vec::new();
    let mut id = 0u8;
    let mut aceitos = 0;
    for _ in 0..3000 {
        let mut ops = Vec::new();
        let mut reservadas: Faixas = Vec::new();
        for _ in 0..1 + sorteio(3) {
            let c = s(nomes[sorteio(nomes.len() as u64) as usize]);
            let atual = a.versao(&c);
            let esperada = if sorteio(5) == 0 { atual + 1 } else { atual };
            ops.push(match sorteio(6) {
                0 => mkdir(&c),
                1 => Op::RemoverDiretorio {
                    caminho: c,
                    esperada,
                },
                2 => Op::Apagar {
                    caminho: c,
                    esperada,
                },
                3 => mv(&c, nomes[sorteio(nomes.len() as u64) as usize], esperada),
                _ => {
                    let tamanho = sorteio(3 * CARGA as u64);
                    let n = tamanho.div_ceil(CARGA as u64);
                    let faixas = mapa.reservar(n, 4).expect("cabe");
                    reservadas.extend(faixas.iter().copied());
                    id = id.wrapping_add(1);
                    let mut indice = 0;
                    let extensoes = faixas
                        .iter()
                        .map(|&(de, ate)| {
                            let e = Extensao {
                                bloco: de,
                                quantos: (ate - de) as u32,
                                id: [id; 16],
                                indice,
                            };
                            indice += ate - de;
                            e
                        })
                        .collect();
                    gravar(&c, esperada, Conteudo { tamanho, extensoes })
                }
            });
        }
        let antes = a.clone();
        match a.preparar(&ops, ATOR, LIVRE, 0, TETO) {
            Ok(l) => {
                let saidas = a.aplicar(&l).unwrap();
                mapa.soltar_faixas(&saidas).unwrap();
                // O que foi reservado e nenhum arquivo levou sai também.
                let sobra = subtrair(&normalizar(reservadas), &a.blocos_em_uso());
                mapa.soltar_faixas(&sobra).unwrap();
                lotes.push(l);
                aceitos += 1;
            }
            Err(_) => {
                assert_eq!(a, antes);
                mapa.soltar_faixas(&normalizar(reservadas)).unwrap();
            }
        }
        assert!(a.coerente());
        let usados: u64 = a.blocos_em_uso().iter().map(|(x, y)| y - x).sum();
        assert_eq!(
            mapa.contar_usados(),
            usados,
            "o mapa e os metadados divergiram"
        );
    }
    assert!(aceitos > 150, "{aceitos} lotes aceitos");
    assert_eq!(reposto(&lotes), a);
}
