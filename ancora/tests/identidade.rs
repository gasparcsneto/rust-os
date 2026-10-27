//! A área do selo da identidade e a decisão do boot, sem TPM: o formato
//! byte a byte, o setor estragado de cada jeito, e a tabela inteira.
//!
//! O selo de verdade — selar, abrir, o barramento, outro TPM — mora em
//! `tests/swtpm.rs`, contra um TPM de verdade.

use ancora::cofre::SeladoDaIdentidade;
use ancora::identidade::{self, Area, Decisao, Leitura, Recusa, TAM_AREA};

/// Uma área com bytes diferentes uns dos outros, e um bloco privado de
/// `tam` bytes.
fn area(semeadura: u8, tam: usize) -> Area {
    let b = |i: usize| {
        semeadura
            .wrapping_mul(29)
            .wrapping_add((i as u8).wrapping_mul(13).wrapping_add(1))
    };
    let unico: [u8; 32] = core::array::from_fn(|i| b(i + 100));
    let privado: Vec<u8> = (0..tam).map(|i| b(i + 200)).collect();
    Area {
        ek: core::array::from_fn(b),
        publica: core::array::from_fn(|i| b(i + 64)),
        selado: SeladoDaIdentidade::de_partes(&unico, &privado).unwrap(),
    }
}

/// Os bytes de `a` com `mexer` aplicado e o resumo refeito: o que passa do
/// resumo e tem de ser pego pelo resto da conferência.
fn com_resumo_refeito(a: &Area, mexer: impl Fn(&mut [u8; TAM_AREA])) -> [u8; TAM_AREA] {
    use sha2::Digest;
    let mut b = a.em_bytes();
    mexer(&mut b);
    let r = sha2::Sha256::digest(&b[..480]);
    b[480..].copy_from_slice(&r);
    b
}

#[test]
fn a_area_vai_e_volta() {
    for tam in [1, 2, 157, 158, 255, 256] {
        let a = area(tam as u8, tam);
        assert_eq!(identidade::ler(&a.em_bytes()), Leitura::Valida(a), "{tam}");
    }
}

/// O formato do cabeçalho do módulo, conferido byte a byte — escrito aqui
/// pelo desenho, e não pelas constantes do pacote.
#[test]
fn a_area_tem_o_formato_do_desenho() {
    use sha2::Digest;
    let a = area(7, 158);
    let b = a.em_bytes();
    assert_eq!(&b[..8], b"DUKEIDT1");
    assert_eq!(&b[8..10], &[1, 0]);
    assert_eq!(&b[10..12], &158u16.to_le_bytes());
    assert_eq!(&b[12..16], &[0; 4]);
    assert_eq!(&b[16..80], &a.ek);
    assert_eq!(&b[80..112], &a.publica);
    assert_eq!(&b[112..144], a.selado.unico());
    assert_eq!(&b[144..302], a.selado.privado());
    assert!(b[302..480].iter().all(|&x| x == 0));
    assert_eq!(&b[480..], &sha2::Sha256::digest(&b[..480])[..]);
}

#[test]
fn o_setor_zerado_e_vazio() {
    assert_eq!(identidade::ler(&[0; TAM_AREA]), Leitura::Vazia);
}

/// Qualquer bit de qualquer byte trocado: estragada — e nunca outra área
/// válida.
#[test]
fn um_bit_trocado_em_qualquer_lugar_estraga() {
    let a = area(3, 158);
    let b = a.em_bytes();
    for i in 0..TAM_AREA {
        for bit in [0x01, 0x10, 0x80] {
            let mut m = b;
            m[i] ^= bit;
            assert_eq!(identidade::ler(&m), Leitura::Estragada, "byte {i}");
        }
    }
}

/// Uma escrita cortada: o começo do setor novo e o resto do que havia —
/// zeros, ou a área de antes. Nunca uma terceira área: ou estragada, ou uma
/// das duas inteira — a de antes, se o corte só levou o que as duas têm de
/// igual no começo.
#[test]
fn a_escrita_cortada_estraga() {
    let nova = area(4, 158).em_bytes();
    let velha = area(5, 158).em_bytes();
    let igual_no_comeco = nova.iter().zip(&velha).take_while(|(a, b)| a == b).count();
    assert_eq!(
        igual_no_comeco, 16,
        "a magia, a versao, o tamanho e o reservado"
    );
    for corte in 1..TAM_AREA {
        let mut m = [0u8; TAM_AREA];
        m[..corte].copy_from_slice(&nova[..corte]);
        assert_eq!(
            identidade::ler(&m),
            Leitura::Estragada,
            "zeros depois de {corte}"
        );
        let mut m = velha;
        m[..corte].copy_from_slice(&nova[..corte]);
        let esperada = if corte <= igual_no_comeco {
            identidade::ler(&velha)
        } else {
            Leitura::Estragada
        };
        assert_eq!(identidade::ler(&m), esperada, "a velha depois de {corte}");
    }
}

/// Um jeito de mexer numa cópia, e o nome dele.
type Mexida = (&'static str, fn(&mut [u8; TAM_AREA]));

/// Com o resumo refeito, o resto da conferência ainda pega o que não é do
/// formato.
#[test]
fn o_resumo_refeito_nao_salva_o_formato_errado() {
    let a = area(6, 158);
    let casos: [Mexida; 7] = [
        ("a magia", |b| b[0] ^= 1),
        ("a versao", |b| b[8] = 2),
        ("o reservado", |b| b[13] = 1),
        ("o tamanho zero", |b| {
            b[10..12].copy_from_slice(&0u16.to_le_bytes())
        }),
        ("o tamanho grande demais", |b| {
            b[10..12].copy_from_slice(&257u16.to_le_bytes())
        }),
        ("um byte depois do bloco privado", |b| b[302] = 1),
        ("o ultimo byte antes do resumo", |b| b[479] = 1),
    ];
    for (qual, mexer) in casos {
        assert_eq!(
            identidade::ler(&com_resumo_refeito(&a, mexer)),
            Leitura::Estragada,
            "{qual}"
        );
    }
    // O controle: refeito sem mexer, é a mesma.
    assert_eq!(
        identidade::ler(&com_resumo_refeito(&a, |_| {})),
        Leitura::Valida(a.clone())
    );
    // O tamanho menor com o último byte do bloco zerado e o resumo refeito
    // é outra área válida — o bloco privado cortado. O resumo não é contra
    // quem escreve no disco: quem pega esta é o TPM, no `TPM2_Load`.
    let cortada = com_resumo_refeito(&a, |b| {
        b[10..12].copy_from_slice(&157u16.to_le_bytes());
        b[301] = 0;
    });
    match identidade::ler(&cortada) {
        Leitura::Valida(c) => assert_eq!(c.selado.privado(), &a.selado.privado()[..157]),
        outra => panic!("{outra:?}"),
    }
}

/// O bloco privado do tamanho que o selado aceita, e não mais.
#[test]
fn o_bloco_privado_tem_teto() {
    assert!(SeladoDaIdentidade::de_partes(&[1; 32], &[2; 256]).is_ok());
    assert!(SeladoDaIdentidade::de_partes(&[1; 32], &[2; 257]).is_err());
    assert!(SeladoDaIdentidade::de_partes(&[1; 32], &[]).is_err());
    assert!(SeladoDaIdentidade::de_partes(&[1; 31], &[2; 10]).is_err());
}

// ---------------------------------------------------------------------------
// A decisão
// ---------------------------------------------------------------------------

fn v(semeadura: u8) -> Leitura {
    Leitura::Valida(area(semeadura, 158))
}

/// Todas as leituras de uma cópia, menos a válida.
fn nao_validas() -> [Leitura; 3] {
    [Leitura::Vazia, Leitura::Estragada, Leitura::Ilegivel]
}

/// O TPM ausente, presente sem estado do Duke, e com ele.
const TPMS: [Option<bool>; 3] = [None, Some(false), Some(true)];

#[test]
fn duas_copias_iguais_abrem_sem_reparo() {
    for journal in [false, true] {
        for tpm in [Some(false), Some(true)] {
            assert_eq!(
                identidade::decidir(&[v(1), v(1)], journal, tpm),
                Decisao::Abrir {
                    copia: 0,
                    reparar: false
                }
            );
        }
    }
}

#[test]
fn uma_copia_inteira_abre_e_repara_a_outra() {
    for outra in nao_validas() {
        for journal in [false, true] {
            for tpm in [Some(false), Some(true)] {
                assert_eq!(
                    identidade::decidir(&[v(1), outra.clone()], journal, tpm),
                    Decisao::Abrir {
                        copia: 0,
                        reparar: true
                    },
                    "{outra:?}"
                );
                assert_eq!(
                    identidade::decidir(&[outra.clone(), v(1)], journal, tpm),
                    Decisao::Abrir {
                        copia: 1,
                        reparar: true
                    },
                    "{outra:?}"
                );
            }
        }
    }
}

#[test]
fn duas_copias_diferentes_recusam() {
    for journal in [false, true] {
        for tpm in TPMS {
            assert_eq!(
                identidade::decidir(&[v(1), v(2)], journal, tpm),
                Decisao::Recusar(Recusa::CopiasDivergem)
            );
        }
    }
}

#[test]
fn sem_tpm_nada_abre_nem_nasce() {
    for copias in [
        [v(1), v(1)],
        [v(1), Leitura::Vazia],
        [Leitura::Estragada, v(1)],
        [Leitura::Vazia, Leitura::Vazia],
        [Leitura::Estragada, Leitura::Vazia],
    ] {
        assert_eq!(
            identidade::decidir(&copias, false, None),
            Decisao::Recusar(Recusa::SemTpm),
            "{copias:?}"
        );
    }
}

#[test]
fn sem_copia_inteira_e_com_uma_ilegivel_recusa() {
    for outra in nao_validas() {
        for journal in [false, true] {
            for tpm in TPMS {
                for copias in [
                    [Leitura::Ilegivel, outra.clone()],
                    [outra.clone(), Leitura::Ilegivel],
                ] {
                    assert_eq!(
                        identidade::decidir(&copias, journal, tpm),
                        Decisao::Recusar(Recusa::AreaIlegivel),
                        "{copias:?}"
                    );
                }
            }
        }
    }
}

/// Sem selo e com journal: o estado de uma identidade que se perdeu —
/// nunca uma nova por cima dele, com TPM ou sem.
#[test]
fn o_journal_sem_selo_recusa() {
    for a in [Leitura::Vazia, Leitura::Estragada] {
        for b in [Leitura::Vazia, Leitura::Estragada] {
            for tpm in TPMS {
                assert_eq!(
                    identidade::decidir(&[a.clone(), b.clone()], true, tpm),
                    Decisao::Recusar(Recusa::SemSelo)
                );
            }
        }
    }
}

#[test]
fn o_tpm_com_estado_de_outra_instalacao_recusa() {
    for a in [Leitura::Vazia, Leitura::Estragada] {
        for b in [Leitura::Vazia, Leitura::Estragada] {
            assert_eq!(
                identidade::decidir(&[a.clone(), b.clone()], false, Some(true)),
                Decisao::Recusar(Recusa::TpmDeOutraInstalacao)
            );
        }
    }
}

/// A instalação nova: e também a que caiu no meio da escrita do selo, com
/// uma cópia — ou as duas — estragadas e nada ao redor.
#[test]
fn a_instalacao_nova_nasce() {
    for a in [Leitura::Vazia, Leitura::Estragada] {
        for b in [Leitura::Vazia, Leitura::Estragada] {
            assert_eq!(
                identidade::decidir(&[a.clone(), b.clone()], false, Some(false)),
                Decisao::Nascer
            );
        }
    }
}

/// A tabela inteira, de outro jeito: nascer só em instalação nova, abrir
/// só com uma cópia inteira e TPM, e cada recusa só no caso dela.
#[test]
fn a_tabela_inteira() {
    let leituras = [
        v(1),
        v(2),
        Leitura::Vazia,
        Leitura::Estragada,
        Leitura::Ilegivel,
    ];
    let mut vistas = std::collections::BTreeSet::new();
    for a in &leituras {
        for b in &leituras {
            for journal in [false, true] {
                for tpm in TPMS {
                    let copias = [a.clone(), b.clone()];
                    let d = identidade::decidir(&copias, journal, tpm);
                    let valida = |l: &Leitura| matches!(l, Leitura::Valida(_));
                    let alguma = copias.iter().any(valida);
                    match d {
                        Decisao::Nascer => {
                            assert!(!alguma && !journal && tpm == Some(false));
                            assert!(!copias.contains(&Leitura::Ilegivel));
                        }
                        Decisao::Abrir { copia, reparar } => {
                            assert!(valida(&copias[copia]) && tpm.is_some());
                            assert_eq!(reparar, copias[0] != copias[1]);
                        }
                        Decisao::Recusar(r) => {
                            assert!(!r.motivo().is_empty() && r.motivo().is_ascii());
                            // Inteiro no detalhe da auditoria, que o kernel
                            // grava na recusa: o teto é o
                            // `politica::auditoria::MAIOR_DETALHE`.
                            assert!(r.motivo().len() <= 96, "{}", r.motivo());
                        }
                    }
                    vistas.insert(format!("{d:?}"));
                }
            }
        }
    }
    // Toda saída da tabela aparece.
    assert_eq!(vistas.len(), 9, "{vistas:?}");
}
