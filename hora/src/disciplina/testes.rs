//! Os casos da disciplina: os cinco cenários do incremento — o relógio
//! atrasado, o adiantado, o salto das fontes, a perda delas e a volta —, as
//! regras uma a uma, e a monotonicidade por sorteio.

use std::vec::Vec;

use super::*;
use crate::intervalo::Amostra;
use crate::quorum::{self, Desfecho};

const P: Parametros = Parametros::PADRAO;

/// A hora verdadeira no instante 0 do contador.
const VERDADE_0: u64 = 1_791_158_400_000;

/// A hora verdadeira num instante do contador, com o contador exato.
fn verdade(local_ms: u64) -> u64 {
    VERDADE_0 + local_ms
}

/// Uma rodada de três fontes honestas que dizem `hora_ms`, com raio `raio_ms`.
fn rodada_de(hora_ms: u64, raio_ms: u64, local_ms: u64) -> Desfecho {
    let amostras: Vec<Amostra> = (1..=3u8)
        .map(|k| Amostra {
            chave: [k; 32],
            cedo_ms: hora_ms - raio_ms,
            tarde_ms: hora_ms + raio_ms,
            instante_ms: local_ms,
        })
        .collect();
    quorum::acordo(&amostras, 2)
}

fn honestas(hora_ms: u64, local_ms: u64) -> Desfecho {
    rodada_de(hora_ms, 5_000, local_ms)
}

/// Um relógio já sincronizado no instante `t`.
fn sincronizado(t: u64) -> Relogio {
    let mut r = Relogio::do_rtc(P, Some(VERDADE_0 / 1000), 0);
    assert_eq!(r.rodada(&honestas(verdade(t), t), t, None), Efeito::Nada);
    r
}

fn desvio(efeito: Efeito) -> i64 {
    match efeito {
        Efeito::Gradual { desvio_ms }
        | Efeito::Candidato { desvio_ms }
        | Efeito::Salto { desvio_ms, .. }
        | Efeito::Pendente { desvio_ms } => desvio_ms,
        outro => panic!("sem desvio: {outro:?}"),
    }
}

// --- Antes do primeiro acordo ---------------------------------------------------

#[test]
fn antes_do_primeiro_acordo_e_o_rtc() {
    let mut r = Relogio::do_rtc(P, Some(1_000), 0);
    let l = r.ler(0);
    assert_eq!(
        (l.meio_ms, l.incerteza_ms, l.estado),
        (1_000_000, None, Estado::Rtc)
    );
    assert_eq!(r.ler(5_000).meio_ms, 1_005_000, "anda com o contador");
    assert!(r.reler_rtc(Some(2_000), 6_000));
    assert_eq!(r.ler(6_000).meio_ms, 2_000_000);
    assert_eq!(
        Relogio::do_rtc(P, None, 0).ler(10).meio_ms,
        10,
        "sem RTC, do zero"
    );
}

#[test]
fn depois_do_acordo_o_rtc_nao_move_mais() {
    let mut r = sincronizado(1_000);
    let antes = r.ler(2_000);
    assert!(!r.reler_rtc(Some(5), 2_000));
    assert_eq!(r.ler(2_000), antes);
}

#[test]
fn o_primeiro_acordo_perto_do_rtc_so_ancora() {
    let mut r = Relogio::do_rtc(P, Some(VERDADE_0 / 1000 + 3), 0);
    let efeito = r.rodada(&honestas(verdade(1_000), 1_000), 1_000, None);
    assert_eq!(efeito, Efeito::Nada, "3 s, dentro dos 5 s do acordo");
    let l = r.ler(1_000);
    assert_eq!(l.estado, Estado::Sincronizado);
    assert_eq!(l.incerteza_ms, Some(8_000), "o raio mais o desvio");
}

// --- Relógio atrasado -------------------------------------------------------------

#[test]
fn relogio_atrasado_salta_para_a_frente_em_duas_rodadas() {
    let rtc = VERDADE_0 / 1000 - 3_600;
    let mut r = Relogio::do_rtc(P, Some(rtc), 0);
    let primeira = r.rodada(&honestas(verdade(10_000), 10_000), 10_000, Some(rtc * 1000));
    assert_eq!(
        primeira,
        Efeito::Candidato {
            desvio_ms: 3_600_000
        }
    );
    assert_eq!(
        r.ler(10_000).estado,
        Estado::Rtc,
        "um candidato não move nada"
    );
    assert_eq!(r.ler(10_000).meio_ms, rtc * 1000 + 10_000);
    let segunda = r.rodada(&honestas(verdade(15_000), 15_000), 15_000, Some(rtc * 1000));
    assert_eq!(
        segunda,
        Efeito::Salto {
            desvio_ms: 3_600_000,
            alem_do_envelope: false
        },
        "a primeira sincronização não tem envelope"
    );
    let l = r.ler(15_000);
    assert_eq!(l.meio_ms, verdade(15_000));
    assert_eq!(l.incerteza_ms, Some(5_000));
    assert_eq!(l.estado, Estado::Sincronizado);
}

#[test]
fn o_contador_lento_e_corrigido_devagar() {
    // O contador perde tiques: a hora verdadeira anda 0,4% mais que ele.
    let mut r = sincronizado(0);
    let mut t = 0;
    let mut gradual = 0;
    for _ in 0..10 {
        t += 1_024_000;
        let hora = verdade(t) + t / 250;
        match r.rodada(&honestas(hora, t), t, None) {
            Efeito::Gradual { desvio_ms } => {
                assert!(desvio_ms > 0);
                gradual += 1;
            }
            Efeito::Nada => {}
            outro => panic!("{outro:?}"),
        }
        let l = r.ler(t);
        assert!(
            l.meio_ms.abs_diff(hora) <= 10_000,
            "o civil acompanha: {}",
            l.meio_ms.abs_diff(hora)
        );
    }
    assert!(gradual > 0, "algum ajuste aconteceu");
}

// --- Relógio adiantado -------------------------------------------------------------

#[test]
fn relogio_adiantado_volta_na_primeira_sincronizacao() {
    let rtc = VERDADE_0 / 1000 + 120;
    let mut r = Relogio::do_rtc(P, Some(rtc), 0);
    assert_eq!(
        r.rodada(&honestas(verdade(10_000), 10_000), 10_000, Some(rtc * 1000)),
        Efeito::Candidato {
            desvio_ms: -120_000
        }
    );
    let antes = r.ler(15_000).meio_ms;
    let salto = r.rodada(&honestas(verdade(15_000), 15_000), 15_000, Some(rtc * 1000));
    assert_eq!(
        salto,
        Efeito::Salto {
            desvio_ms: -120_000,
            alem_do_envelope: false
        }
    );
    assert_eq!(
        r.ler(15_000).meio_ms,
        antes - 120_000,
        "o civil volta; o lógico é do kernel"
    );
}

#[test]
fn depois_de_sincronizado_voltar_fora_do_envelope_espera_uma_pessoa() {
    let mut r = sincronizado(0);
    let t = 1_024_000;
    let antes = r.ler(t);
    let efeito = r.rodada(&honestas(verdade(t) - 600_000, t), t, None);
    assert_eq!(
        efeito,
        Efeito::Pendente {
            desvio_ms: -600_000
        }
    );
    let depois = r.ler(t);
    assert_eq!(depois.meio_ms, antes.meio_ms, "pendente não move");
    assert_eq!(depois.pendente_ms, Some(-600_000));
    // De novo, a mesma coisa: continua pendente, atualizado.
    let t2 = t + 64_000;
    assert_eq!(
        r.rodada(&honestas(verdade(t2) - 600_000, t2), t2, None),
        Efeito::Pendente {
            desvio_ms: -600_000
        }
    );
    // Uma pessoa confirma.
    let t3 = t2 + 10_000;
    assert_eq!(
        r.confirmar(t3),
        Some(Efeito::Salto {
            desvio_ms: -600_000,
            alem_do_envelope: true
        })
    );
    let l = r.ler(t3);
    assert_eq!(l.meio_ms, verdade(t3) - 600_000);
    assert_eq!(
        l.incerteza_ms,
        Some(5_000 + 5),
        "a do acordo, mais a deriva dos 10 s desde ele"
    );
    assert_eq!(l.pendente_ms, None);
    assert!(l.alem_do_envelope);
    assert_eq!(r.confirmar(t3), None, "nada mais pendente");
}

#[test]
fn voltar_dentro_do_envelope_salta_em_duas_rodadas() {
    // Muito tempo sem acordo: a incerteza cresceu, e o acordo cabe nela.
    let mut r = sincronizado(0);
    let t = 50_000_000; // 25 s de deriva máxima
    let i = r.ler(t).incerteza_ms.unwrap();
    assert!(i >= 30_000, "{i}");
    let hora = verdade(t) - 20_000;
    assert_eq!(
        r.rodada(&honestas(hora, t), t, None),
        Efeito::Candidato { desvio_ms: -20_000 }
    );
    let t2 = t + 5_000;
    assert_eq!(
        r.rodada(&honestas(hora + 5_000, t2), t2, None),
        Efeito::Salto {
            desvio_ms: -20_000,
            alem_do_envelope: false
        }
    );
}

#[test]
fn o_adiantamento_pequeno_e_absorvido_sem_voltar() {
    let mut r = sincronizado(0);
    let t = 1_024_000;
    let l = r.ler(t);
    assert_eq!(
        r.rodada(&honestas(verdade(t) - 8_000, t), t, None),
        Efeito::Gradual { desvio_ms: -8_000 }
    );
    // 5% de 100 s são 5 s: o civil andou 95 s em 100 s.
    assert_eq!(r.ler(t + 100_000).meio_ms, l.meio_ms + 100_000 - 5_000);
    assert_eq!(
        r.ler(t + 160_000).meio_ms,
        l.meio_ms + 160_000 - 8_000,
        "absorvido inteiro"
    );
    let mut anterior = 0;
    for passo in (0..200_000).step_by(7) {
        let m = r.ler(t + passo).meio_ms;
        assert!(m >= anterior, "nunca volta no ajuste");
        anterior = m;
    }
}

// --- Salto das fontes ------------------------------------------------------------

#[test]
fn o_salto_das_fontes_para_a_frente_e_marcado() {
    let mut r = sincronizado(0);
    let t = 1_024_000;
    assert_eq!(
        r.rodada(&honestas(verdade(t) + 600_000, t), t, None),
        Efeito::Candidato { desvio_ms: 600_000 }
    );
    let t2 = t + 5_000;
    assert_eq!(
        r.rodada(&honestas(verdade(t2) + 600_000, t2), t2, None),
        Efeito::Salto {
            desvio_ms: 600_000,
            alem_do_envelope: true
        }
    );
    assert!(r.ler(t2).alem_do_envelope);
}

#[test]
fn alem_do_teto_fica_pendente() {
    let mut r = sincronizado(0);
    let t = 1_024_000;
    let dois_dias = 2 * 86_400_000;
    let antes = r.ler(t).meio_ms;
    assert_eq!(
        r.rodada(&honestas(verdade(t) + dois_dias, t), t, None),
        Efeito::Pendente {
            desvio_ms: dois_dias as i64
        }
    );
    assert_eq!(r.ler(t).meio_ms, antes);
    assert!(matches!(r.confirmar(t + 1_000), Some(Efeito::Salto { .. })));
    assert_eq!(r.ler(t + 1_000).meio_ms, verdade(t + 1_000) + dois_dias);
}

#[test]
fn o_teto_conta_da_referencia_na_primeira_sincronizacao() {
    // RTC morto (sem RTC): sem referência, décadas de salto esperam uma
    // pessoa.
    let mut r = Relogio::do_rtc(P, None, 0);
    assert!(matches!(
        r.rodada(&honestas(verdade(10_000), 10_000), 10_000, None),
        Efeito::Pendente { .. }
    ));
    // Com o piso de duas horas atrás como referência, o salto a partir dele
    // cabe no teto: duas rodadas e salta.
    let mut r = Relogio::do_rtc(P, None, 0);
    let piso = verdade(0) - 7_200_000;
    assert!(matches!(
        r.rodada(&honestas(verdade(10_000), 10_000), 10_000, Some(piso)),
        Efeito::Candidato { .. }
    ));
    assert!(matches!(
        r.rodada(&honestas(verdade(15_000), 15_000), 15_000, Some(piso)),
        Efeito::Salto { .. }
    ));
}

#[test]
fn um_salto_do_tamanho_do_teto_ainda_e_automatico() {
    // O teto é o maior salto sem uma pessoa: do tamanho dele, contado da
    // referência, salta em duas rodadas; um milissegundo a mais, espera.
    let teto = P.salto_maximo_ms;
    let mut r = Relogio::do_rtc(P, None, 0);
    for (t, salta) in [(10_000, false), (15_000, true)] {
        let efeito = r.rodada(&honestas(verdade(t), t), t, Some(verdade(t) - teto));
        assert_eq!(matches!(efeito, Efeito::Salto { .. }), salta, "{efeito:?}");
        assert!(!matches!(efeito, Efeito::Pendente { .. }));
    }
    let mut r = Relogio::do_rtc(P, None, 0);
    assert!(matches!(
        r.rodada(
            &honestas(verdade(10_000), 10_000),
            10_000,
            Some(verdade(10_000) - teto - 1)
        ),
        Efeito::Pendente { .. }
    ));
}

#[test]
fn o_salto_pede_duas_rodadas_seguidas_e_separadas() {
    let mut r = sincronizado(0);
    let mais = 600_000;
    let t = 1_024_000;
    assert!(matches!(
        r.rodada(&honestas(verdade(t) + mais, t), t, None),
        Efeito::Candidato { .. }
    ));
    // Cedo demais: continua candidato.
    let cedo = t + 1_000;
    assert!(matches!(
        r.rodada(&honestas(verdade(cedo) + mais, cedo), cedo, None),
        Efeito::Candidato { .. }
    ));
    // Separado do primeiro: salta.
    let t2 = t + 4_000;
    assert!(matches!(
        r.rodada(&honestas(verdade(t2) + mais, t2), t2, None),
        Efeito::Salto { .. }
    ));

    // Uma rodada normal no meio desfaz o candidato.
    let mut r = sincronizado(0);
    assert!(matches!(
        r.rodada(&honestas(verdade(t) + mais, t), t, None),
        Efeito::Candidato { .. }
    ));
    let meio = t + 5_000;
    assert_eq!(
        r.rodada(&honestas(verdade(meio), meio), meio, None),
        Efeito::Nada
    );
    let t3 = t + 10_000;
    assert!(matches!(
        r.rodada(&honestas(verdade(t3) + mais, t3), t3, None),
        Efeito::Candidato { .. }
    ));

    // Uma rodada sem acordo no meio também.
    let mut r = sincronizado(0);
    assert!(matches!(
        r.rodada(&honestas(verdade(t) + mais, t), t, None),
        Efeito::Candidato { .. }
    ));
    let sem = quorum::acordo(&[], 2);
    assert_eq!(r.rodada(&sem, t + 5_000, None), Efeito::SemAcordo);
    assert!(matches!(
        r.rodada(&honestas(verdade(t3) + mais, t3), t3, None),
        Efeito::Candidato { .. }
    ));

    // Um empate, ou uma rodada inválida, no meio também.
    for no_meio in [Desfecho::Empate { cobertura: 2 }, Desfecho::Invalido] {
        let mut r = sincronizado(0);
        assert!(matches!(
            r.rodada(&honestas(verdade(t) + mais, t), t, None),
            Efeito::Candidato { .. }
        ));
        assert_eq!(r.rodada(&no_meio, t + 5_000, None), Efeito::SemAcordo);
        assert!(
            matches!(
                r.rodada(&honestas(verdade(t3) + mais, t3), t3, None),
                Efeito::Candidato { .. }
            ),
            "{no_meio:?}"
        );
    }

    // E um salto pendente no meio: as duas rodadas têm de ser seguidas.
    let mut r = sincronizado(0);
    assert!(matches!(
        r.rodada(&honestas(verdade(t) + mais, t), t, None),
        Efeito::Candidato { .. }
    ));
    let dois_dias = 2 * 86_400_000;
    let no_meio = t + 5_000;
    assert!(matches!(
        r.rodada(
            &honestas(verdade(no_meio) + dois_dias, no_meio),
            no_meio,
            None
        ),
        Efeito::Pendente { .. }
    ));
    assert!(matches!(
        r.rodada(&honestas(verdade(t3) + mais, t3), t3, None),
        Efeito::Candidato { .. }
    ));

    // Dois desvios grandes que não concordam: o segundo vira o candidato.
    let mut r = sincronizado(0);
    assert!(matches!(
        r.rodada(&honestas(verdade(t) + mais, t), t, None),
        Efeito::Candidato { .. }
    ));
    let t4 = t + 5_000;
    assert_eq!(
        r.rodada(&honestas(verdade(t4) + 2 * mais, t4), t4, None),
        Efeito::Candidato {
            desvio_ms: 1_200_000
        }
    );
    let t5 = t4 + 5_000;
    assert_eq!(
        desvio(r.rodada(&honestas(verdade(t5) + 2 * mais, t5), t5, None)),
        1_200_000
    );
    assert_eq!(r.ler(t5).meio_ms, verdade(t5) + 2 * mais);
}

#[test]
fn o_limiar_cresce_com_a_incerteza_do_acordo() {
    // Raio de 9 s: o limiar é 18 s, e 15 s é ajuste gradual.
    let mut r = sincronizado(0);
    let t = 1_024_000;
    assert_eq!(
        r.rodada(&rodada_de(verdade(t) + 15_000, 9_000, t), t, None),
        Efeito::Gradual { desvio_ms: 15_000 }
    );
    // Raio de 5 s: o limiar é 10 s, e 15 s é candidato a salto.
    let mut r = sincronizado(0);
    assert_eq!(
        r.rodada(&rodada_de(verdade(t) + 15_000, 5_000, t), t, None),
        Efeito::Candidato { desvio_ms: 15_000 }
    );
    // Raio de 1 s: o limiar fica no mínimo, 10 s, e 8 s ainda é gradual.
    let mut r = sincronizado(0);
    assert_eq!(
        r.rodada(&rodada_de(verdade(t) + 8_000, 1_000, t), t, None),
        Efeito::Gradual { desvio_ms: 8_000 }
    );
}

#[test]
fn as_pontas_da_incerteza_e_do_limiar() {
    // Um desvio do tamanho da incerteza do acordo ainda cabe nele; um do
    // tamanho do limiar ainda é gradual.
    let t = 1_024_000;
    for (desvio_ms, esperado) in [
        (5_000u64, Efeito::Nada),
        (5_001, Efeito::Gradual { desvio_ms: 5_001 }),
        (10_000, Efeito::Gradual { desvio_ms: 10_000 }),
        (10_001, Efeito::Candidato { desvio_ms: 10_001 }),
    ] {
        let mut r = sincronizado(0);
        assert_eq!(
            r.rodada(&honestas(verdade(t) + desvio_ms, t), t, None),
            esperado
        );
    }
}

#[test]
fn o_salto_descarta_o_ajuste_gradual_em_curso() {
    // Um ajuste gradual em curso, e então as fontes saltam: depois do salto,
    // o civil fica no acordo, sem o resto do ajuste velho.
    let mut r = sincronizado(0);
    let t = 1_024_000;
    assert_eq!(
        r.rodada(&honestas(verdade(t) + 8_000, t), t, None),
        Efeito::Gradual { desvio_ms: 8_000 }
    );
    let mais = 600_000;
    let t2 = t + 1_000;
    assert!(matches!(
        r.rodada(&honestas(verdade(t2) + mais, t2), t2, None),
        Efeito::Candidato { .. }
    ));
    let t3 = t2 + 5_000;
    assert!(matches!(
        r.rodada(&honestas(verdade(t3) + mais, t3), t3, None),
        Efeito::Salto { .. }
    ));
    for depois in [0, 100_000, 1_000_000] {
        assert_eq!(r.ler(t3 + depois).meio_ms, verdade(t3 + depois) + mais);
    }
}

#[test]
fn as_fontes_que_desmentem_o_pendente_o_apagam() {
    // Um salto pendente que as fontes desmentem não espera mais ninguém: a
    // pessoa não confirma o que elas já não dizem.
    let t = 1_024_000;
    let t2 = t + 64_000;
    for (hora, esperado) in [
        (verdade(t2), Efeito::Nada),
        (verdade(t2) + 8_000, Efeito::Gradual { desvio_ms: 8_000 }),
    ] {
        let mut r = sincronizado(0);
        assert!(matches!(
            r.rodada(&honestas(verdade(t) - 600_000, t), t, None),
            Efeito::Pendente { .. }
        ));
        assert_eq!(r.rodada(&honestas(hora, t2), t2, None), esperado);
        assert_eq!(r.ler(t2).pendente_ms, None, "{esperado:?}");
        assert_eq!(r.confirmar(t2), None);
    }
}

#[test]
fn o_ajuste_gradual_para_a_frente_tem_teto_de_taxa() {
    let mut r = sincronizado(0);
    let t = 1_024_000;
    let l = r.ler(t);
    assert_eq!(
        r.rodada(&honestas(verdade(t) + 8_000, t), t, None),
        Efeito::Gradual { desvio_ms: 8_000 }
    );
    assert_eq!(r.ler(t + 100_000).meio_ms, l.meio_ms + 100_000 + 5_000);
    assert_eq!(r.ler(t + 1_000_000).meio_ms, l.meio_ms + 1_000_000 + 8_000);
    // A incerteza conta o que falta absorver.
    let i = r.ler(t).incerteza_ms.unwrap();
    assert_eq!(i, 5_000 + 8_000);
}

// --- Perda das fontes e volta ----------------------------------------------------

#[test]
fn sem_fontes_a_incerteza_cresce_e_o_estado_muda() {
    let mut r = sincronizado(0);
    let sem = quorum::acordo(&[], 2);
    assert_eq!(r.rodada(&sem, 1_000_000, None), Efeito::SemAcordo);
    let l = r.ler(1_000_000);
    assert_eq!(l.estado, Estado::Sincronizado);
    let l = r.ler(3_000_000);
    assert_eq!(l.estado, Estado::Holdover);
    assert_eq!(l.incerteza_ms, Some(5_000 + 1_500), "500 ppm de 3000 s");
    assert_eq!(
        l.meio_ms,
        verdade(3_000_000),
        "o contador continua contando"
    );
    let l = r.ler(120_000_000);
    assert_eq!(l.incerteza_ms, Some(5_000 + 60_000));
    assert_eq!(l.estado, Estado::Vencido);
    // A janela do sincronizado conta com a ponta.
    let janela = P.janela_sincronizado_ms;
    assert_eq!(r.ler(janela).estado, Estado::Sincronizado);
    assert_eq!(r.ler(janela + 1).estado, Estado::Holdover);
    // No teto, ainda holdover; um milissegundo depois, vencido.
    let no_teto = 110_000_000;
    let l = r.ler(no_teto);
    assert_eq!(
        l.incerteza_ms,
        Some(60_000),
        "5 s mais 500 ppm de 110 000 s"
    );
    assert_eq!(l.estado, Estado::Holdover);
    assert_eq!(r.ler(no_teto + 1).estado, Estado::Vencido);
}

#[test]
fn a_volta_das_fontes() {
    // O contador derivou 400 ppm durante a perda.
    let mut r = sincronizado(0);
    let t = 120_000_000;
    assert_eq!(r.ler(t).estado, Estado::Vencido);
    let hora = verdade(t) + t * 400 / 1_000_000;
    assert!(matches!(
        r.rodada(&honestas(hora, t), t, None),
        Efeito::Candidato { .. }
    ));
    let t2 = t + 5_000;
    assert_eq!(
        r.rodada(&honestas(hora + 5_000, t2), t2, None),
        Efeito::Salto {
            desvio_ms: 48_000,
            alem_do_envelope: false
        },
        "dentro do envelope: o contador explica"
    );
    let l = r.ler(t2);
    assert_eq!(l.estado, Estado::Sincronizado);
    assert_eq!(l.incerteza_ms, Some(5_000));
}

#[test]
fn a_volta_com_desvio_pequeno_so_reancora() {
    let mut r = sincronizado(0);
    let t = 120_000_000;
    let hora = verdade(t) + 2_000;
    assert_eq!(r.rodada(&honestas(hora, t), t, None), Efeito::Nada);
    let l = r.ler(t);
    assert_eq!(l.estado, Estado::Sincronizado);
    assert_eq!(l.incerteza_ms, Some(7_000));
}

// --- Divergência --------------------------------------------------------------------

#[test]
fn empate_e_divergencia_nao_movem_e_ficam_marcados() {
    let mut r = sincronizado(0);
    let t = 1_024_000;
    let antes = r.ler(t).meio_ms;
    let empate = quorum::acordo(
        &[
            Amostra {
                chave: [1; 32],
                cedo_ms: 0,
                tarde_ms: 10,
                instante_ms: t,
            },
            Amostra {
                chave: [2; 32],
                cedo_ms: 5,
                tarde_ms: 15,
                instante_ms: t,
            },
            Amostra {
                chave: [3; 32],
                cedo_ms: 12,
                tarde_ms: 20,
                instante_ms: t,
            },
        ],
        2,
    );
    assert!(matches!(empate, Desfecho::Empate { .. }));
    assert_eq!(r.rodada(&empate, t, None), Efeito::SemAcordo);
    assert_eq!(r.ler(t).meio_ms, antes);
    assert!(r.ler(t).divergente);
    // Duas fontes que não se tocam, k = 2: sem quórum, divergentes.
    let dois = quorum::acordo(
        &[
            Amostra {
                chave: [1; 32],
                cedo_ms: 0,
                tarde_ms: 10,
                instante_ms: t,
            },
            Amostra {
                chave: [2; 32],
                cedo_ms: 50,
                tarde_ms: 60,
                instante_ms: t,
            },
        ],
        2,
    );
    let mut r = sincronizado(0);
    assert_eq!(r.rodada(&dois, t, None), Efeito::SemAcordo);
    assert!(r.ler(t).divergente);
    // Uma fonte só: sem quórum, e não é divergência.
    let uma = quorum::acordo(
        &[Amostra {
            chave: [1; 32],
            cedo_ms: 0,
            tarde_ms: 10,
            instante_ms: t,
        }],
        2,
    );
    let mut r = sincronizado(0);
    assert_eq!(r.rodada(&uma, t, None), Efeito::SemAcordo);
    assert!(!r.ler(t).divergente);
    // Um acordo com uma divergente: move, e marca.
    let mut amostras: Vec<Amostra> = (1..=3u8)
        .map(|k| Amostra {
            chave: [k; 32],
            cedo_ms: verdade(t) - 5_000,
            tarde_ms: verdade(t) + 5_000,
            instante_ms: t,
        })
        .collect();
    amostras[2].cedo_ms += 1_000_000;
    amostras[2].tarde_ms += 1_000_000;
    let mut r = sincronizado(0);
    assert_eq!(
        r.rodada(&quorum::acordo(&amostras, 2), t, None),
        Efeito::Nada
    );
    assert!(r.ler(t).divergente);
}

#[test]
fn uma_fonte_so_nunca_move_o_relogio() {
    // Uma fonte que diz uma hora absurda, muitas vezes: nada se move.
    let mut r = sincronizado(0);
    let antes = r.ler(10_000_000).meio_ms;
    for i in 1..=20u64 {
        let t = i * 100_000;
        let sozinha = quorum::acordo(
            &[Amostra {
                chave: [9; 32],
                cedo_ms: verdade(t) + 3_600_000,
                tarde_ms: verdade(t) + 3_610_000,
                instante_ms: t,
            }],
            2,
        );
        assert_eq!(r.rodada(&sozinha, t, None), Efeito::SemAcordo);
    }
    assert_eq!(r.ler(10_000_000).meio_ms, antes);
}

// --- Monotonicidade -----------------------------------------------------------------

/// Um gerador determinístico, para o sorteio sempre igual.
struct Xorshift(u64);

impl Xorshift {
    fn proximo(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn o_civil_so_volta_num_salto_para_tras() {
    // Quantas vezes cada efeito apareceu: o sorteio tem de passar por todos,
    // ou a propriedade não diz nada.
    let mut vistos = [0usize; 7];
    for semente in 1..=20u64 {
        let mut sorte = Xorshift(semente.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut r = Relogio::do_rtc(P, Some(VERDADE_0 / 1000 + sorte.proximo() % 200), 0);
        let mut t = 0u64;
        let mut anterior = r.ler(0).meio_ms;
        let mut desvio_das_fontes: i64 = 0;
        for _ in 0..400 {
            t += 1 + sorte.proximo() % 90_000;
            let mut pode_voltar = false;
            match sorte.proximo() % 10 {
                0 => desvio_das_fontes += (sorte.proximo() % 1_200_000) as i64 - 600_000,
                1 => desvio_das_fontes = 0,
                _ => {}
            }
            let efeito = match sorte.proximo() % 5 {
                0 => r.rodada(&quorum::acordo(&[], 2), t, None),
                1 => r.confirmar(t).unwrap_or(Efeito::SemAcordo),
                _ => {
                    let hora = (verdade(t) as i64 + desvio_das_fontes) as u64;
                    let ruido = sorte.proximo() % 3_000;
                    r.rodada(&honestas(hora + ruido, t), t, Some(VERDADE_0))
                }
            };
            let indice = match efeito {
                Efeito::Nada => 0,
                Efeito::Gradual { .. } => 1,
                Efeito::Candidato { .. } => 2,
                Efeito::Salto { desvio_ms, .. } if desvio_ms < 0 => 3,
                Efeito::Salto { .. } => 4,
                Efeito::Pendente { .. } => 5,
                Efeito::SemAcordo => 6,
            };
            vistos[indice] += 1;
            if let Efeito::Salto { desvio_ms, .. } = efeito {
                pode_voltar = desvio_ms < 0;
            }
            let agora = r.ler(t).meio_ms;
            assert!(
                agora >= anterior || pode_voltar,
                "semente {semente}: voltou de {anterior} para {agora} com {efeito:?}"
            );
            anterior = agora;
        }
    }
    assert!(
        vistos.iter().all(|&v| v > 0),
        "o sorteio não passou por todos os efeitos: {vistos:?}"
    );
}

// --- O resto --------------------------------------------------------------------------

#[test]
fn os_parametros() {
    assert!(P.validos());
    assert!(
        !Parametros {
            taxa_gradual_por_mil: 0,
            ..P
        }
        .validos()
    );
    assert!(
        !Parametros {
            taxa_gradual_por_mil: 1000,
            ..P
        }
        .validos()
    );
    assert!(
        !Parametros {
            limiar_minimo_ms: 0,
            ..P
        }
        .validos()
    );
    assert!(
        !Parametros {
            separacao_minima_ms: 0,
            ..P
        }
        .validos()
    );
    assert!(
        !Parametros {
            salto_maximo_ms: 0,
            ..P
        }
        .validos()
    );
}

#[test]
fn os_nomes_dos_estados() {
    assert_eq!(Estado::Rtc.nome(), "rtc");
    assert_eq!(Estado::Sincronizado.nome(), "sincronizado");
    assert_eq!(Estado::Holdover.nome(), "holdover");
    assert_eq!(Estado::Vencido.nome(), "vencido");
}

#[test]
fn ler_antes_da_ancora_le_a_ancora() {
    let r = sincronizado(10_000);
    assert_eq!(r.ler(5_000).meio_ms, r.ler(10_000).meio_ms);
}
