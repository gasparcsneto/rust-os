//! O controle de boot: o que o iniciador lê antes de o kernel existir.
//!
//! # Onde
//!
//! Numa partição própria. Cada cópia do registro mora num bloco de 4 KiB
//! próprio — ver [`crate::disco::COPIA_EM`] —: num disco de setor de 4 KiB,
//! as duas nunca dividem um setor físico, e um rasgo na escrita de uma não
//! leva a outra.
//!
//! # O registro
//!
//! ```text
//!    0  "DUKECTL1"            a magia
//!    8  versão     u16 LE     deste formato — hoje 1
//!   10  reservado  u16        zero
//!   12  reservado  u32        zero
//!   16  sequência  u64 LE     sobe a cada gravação
//!   24  bom        u8         o slot que boota: 1 = A, 2 = B
//!   25  tentativa  u8         o slot em tentativa: 0 = nenhum
//!   26  restantes  u8         as tentativas que sobram
//!   27  falha      u8         por que a tentativa acabou — ver [`Falha`]
//!   28  sintetizado u8        1: o iniciador o escreveu sem controle
//!                             íntegro — ver [`sintetizar`]; 0: o kernel
//!   29  reservado  3 bytes    zero
//!   32  manifesto de A        o resumo do manifesto que o slot A pode
//!                             bootar; zero: nenhum
//!   64  manifesto de B        idem, o slot B
//!   96  reservado             zeros até 480
//!  480  BLAKE2s-256 dos bytes 0..480
//! ```
//!
//! # As duas cópias
//!
//! Vale a cópia íntegra de maior sequência. Quem grava escreve a sequência
//! seguinte na **outra** cópia — a que não vale — e descarrega: uma queda
//! no meio estraga só a cópia que se escrevia, e a anterior continua
//! valendo, inteira. Nenhuma gravação toca a cópia que vale.
//!
//! # O controle não decide
//!
//! Quem decide é o journal (ver [`crate::estado`]). O controle é o que o
//! iniciador precisa para bootar sem ler o journal: qual slot, com que
//! manifesto, e se há uma tentativa. O kernel o confere contra o journal a
//! cada boot, e o regrava quando discordam.

use crate::{Resumidor, Slot, TAM_RESUMO, TAM_SETOR};

/// A magia.
pub const MAGIA: [u8; 8] = *b"DUKECTL1";

/// A versão do formato.
pub const VERSAO: u16 = 1;

/// Quantas vezes uma versão nova tenta bootar antes de o iniciador voltar
/// para a velha. Cada boot da tentativa gasta uma, antes de o kernel novo
/// receber o controle: uma queda de energia no meio também gasta.
pub const TENTATIVAS: u8 = 3;

/// Onde mora o resumo.
const EM_RESUMO: usize = TAM_SETOR - TAM_RESUMO;

/// Por que a tentativa acabou antes de as tentativas acabarem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falha {
    Nenhuma,
    /// O iniciador não carregou a versão nova: o cabeçalho, o manifesto ou
    /// o kernel não conferiram, ou o disco falhou.
    CargaRecusada,
    /// O kernel novo bootou e recusou a si mesmo: assinatura, pacote,
    /// arquitetura, formato do estado, persistência ou journal.
    ValidacaoRecusada,
}

impl Falha {
    pub const fn byte(self) -> u8 {
        match self {
            Falha::Nenhuma => 0,
            Falha::CargaRecusada => 1,
            Falha::ValidacaoRecusada => 2,
        }
    }

    pub const fn do_byte(b: u8) -> Option<Falha> {
        match b {
            0 => Some(Falha::Nenhuma),
            1 => Some(Falha::CargaRecusada),
            2 => Some(Falha::ValidacaoRecusada),
            _ => None,
        }
    }

    /// O motivo, para o journal e a auditoria.
    pub const fn motivo(self) -> &'static str {
        match self {
            Falha::Nenhuma => "as tentativas da versao nova acabaram",
            Falha::CargaRecusada => "o iniciador recusou a carga da versao nova",
            Falha::ValidacaoRecusada => "a versao nova recusou a si mesma no boot",
        }
    }
}

/// Um controle lido, ou a gravar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Controle {
    pub sequencia: u64,
    pub bom: Slot,
    pub tentativa: Option<Slot>,
    pub restantes: u8,
    pub falha: Falha,
    /// Por slot, o resumo do manifesto que ele pode bootar; zero, nenhum.
    pub manifestos: [[u8; TAM_RESUMO]; 2],
    /// Escrito pelo iniciador, sem controle íntegro, e não pelo kernel a
    /// partir do journal.
    pub sintetizado: bool,
}

impl Controle {
    /// O manifesto que `slot` pode bootar, se há.
    pub fn manifesto(&self, slot: Slot) -> Option<[u8; TAM_RESUMO]> {
        let m = self.manifestos[slot.indice()];
        (m != [0; TAM_RESUMO]).then_some(m)
    }

    /// Se dizem a mesma coisa — tudo menos a sequência.
    pub fn mesmo_que(&self, outro: &Controle) -> bool {
        Controle {
            sequencia: outro.sequencia,
            ..*self
        } == *outro
    }

    /// Este controle, com a tentativa encerrada por `falha`: nenhuma
    /// tentativa restante, e o motivo. O slot em tentativa e o manifesto
    /// dele ficam — é o kernel da versão boa que os limpa, depois de
    /// registrar no journal que a tentativa acabou.
    pub fn tentativa_encerrada(&self, falha: Falha) -> Controle {
        Controle {
            restantes: 0,
            falha,
            ..*self
        }
    }
}

/// Lê uma cópia. `None` se ela não é um controle íntegro — magia, versão,
/// reservados, valores e resumo, todos conferidos.
pub fn ler(setor: &[u8]) -> Option<Controle> {
    let b = setor.get(..TAM_SETOR)?;
    if b[..8] != MAGIA
        || u16::from_le_bytes([b[8], b[9]]) != VERSAO
        || b[10..16].iter().any(|&x| x != 0)
        || b[28] > 1
        || b[29..32].iter().any(|&x| x != 0)
        || b[96..EM_RESUMO].iter().any(|&x| x != 0)
    {
        return None;
    }
    let mut r = Resumidor::novo();
    r.somar(&b[..EM_RESUMO]);
    if r.terminar()[..] != b[EM_RESUMO..] {
        return None;
    }
    let bom = Slot::do_byte(b[24])?;
    let tentativa = match b[25] {
        0 => None,
        t => Some(Slot::do_byte(t)?),
    };
    // A tentativa é sempre do outro slot: o bom não tenta a si mesmo.
    if tentativa == Some(bom) {
        return None;
    }
    let mut manifestos = [[0u8; TAM_RESUMO]; 2];
    manifestos[0].copy_from_slice(&b[32..64]);
    manifestos[1].copy_from_slice(&b[64..96]);
    Some(Controle {
        sequencia: u64::from_le_bytes(b[16..24].try_into().ok()?),
        bom,
        tentativa,
        restantes: b[26],
        falha: Falha::do_byte(b[27])?,
        manifestos,
        sintetizado: b[28] == 1,
    })
}

/// Escreve uma cópia.
pub fn escrever(c: &Controle) -> [u8; TAM_SETOR] {
    let mut b = [0u8; TAM_SETOR];
    b[..8].copy_from_slice(&MAGIA);
    b[8..10].copy_from_slice(&VERSAO.to_le_bytes());
    b[16..24].copy_from_slice(&c.sequencia.to_le_bytes());
    b[24] = c.bom.byte();
    b[25] = c.tentativa.map_or(0, Slot::byte);
    b[26] = c.restantes;
    b[27] = c.falha.byte();
    b[28] = u8::from(c.sintetizado);
    b[32..64].copy_from_slice(&c.manifestos[0]);
    b[64..96].copy_from_slice(&c.manifestos[1]);
    let mut r = Resumidor::novo();
    r.somar(&b[..EM_RESUMO]);
    b[EM_RESUMO..].copy_from_slice(&r.terminar());
    b
}

/// A cópia que vale, entre as duas lidas: a íntegra de maior sequência;
/// num empate, a primeira. Devolve o índice da cópia (0 ou 1) e o
/// controle.
pub fn escolher(copias: [Option<Controle>; 2]) -> Option<(usize, Controle)> {
    match copias {
        [Some(a), Some(b)] if b.sequencia > a.sequencia => Some((1, b)),
        [Some(a), _] => Some((0, a)),
        [None, Some(b)] => Some((1, b)),
        [None, None] => None,
    }
}

/// Onde e com que sequência gravar `novo`, sabendo qual cópia vale agora:
/// na outra cópia, com a sequência seguinte. Sem cópia que valha, na
/// primeira, com a sequência 1.
pub fn proxima(vale: Option<(usize, &Controle)>, novo: &Controle) -> (usize, Controle) {
    match vale {
        Some((i, atual)) => (
            1 - i,
            Controle {
                sequencia: atual.sequencia.wrapping_add(1),
                ..*novo
            },
        ),
        None => (
            0,
            Controle {
                sequencia: 1,
                ..*novo
            },
        ),
    }
}

/// Como o kernel recebeu o controle — o que o iniciador conta a ele na
/// entrega.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modo {
    /// O slot bom, sem tentativa armada.
    Normal,
    /// A versão nova, numa tentativa.
    Tentativa,
    /// O slot bom, com uma tentativa armada que acabou: as tentativas se
    /// esgotaram, ou a carga da versão nova falhou.
    Desfeita,
    /// Nada do controle carregou: o iniciador escolheu o slot pelo que
    /// achou nos slots — e o kernel regrava o controle pelo journal.
    SemControle,
}

impl Modo {
    pub const fn byte(self) -> u8 {
        match self {
            Modo::Normal => 1,
            Modo::Tentativa => 2,
            Modo::Desfeita => 3,
            Modo::SemControle => 4,
        }
    }

    pub const fn do_byte(b: u8) -> Option<Modo> {
        match b {
            1 => Some(Modo::Normal),
            2 => Some(Modo::Tentativa),
            3 => Some(Modo::Desfeita),
            4 => Some(Modo::SemControle),
            _ => None,
        }
    }

    pub const fn nome(self) -> &'static str {
        match self {
            Modo::Normal => "normal",
            Modo::Tentativa => "tentativa",
            Modo::Desfeita => "desfeita",
            Modo::SemControle => "sem-controle",
        }
    }
}

/// Um boot a tentar: o slot, o manifesto que ele tem de ter — `None` só
/// sem controle, quando o iniciador confere apenas que o kernel bate com o
/// manifesto do próprio slot —, e o modo que vai na entrega.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Boot {
    pub slot: Slot,
    pub manifesto: Option<[u8; TAM_RESUMO]>,
    pub modo: Modo,
}

/// O que o iniciador faz com o controle que leu — ou com o que sintetizou
/// ([`sintetizar`]), quando nenhuma cópia era íntegra.
///
/// Se nada do plano carrega — o slot bom estragado, um controle que aponta
/// para um slot vazio —, o iniciador ainda procura pelos slots, na ordem de
/// [`ordem_sem_controle`], sem gravar nada, e boota no modo
/// [`Modo::SemControle`]: enquanto um slot tiver um kernel que bate com o
/// próprio manifesto, a máquina boota, e o kernel decide pelo journal se
/// aquela imagem tem autoridade. Sem gravar porque o controle íntegro que
/// estava lá é o que o kernel escreveu pelo journal: trocá-lo faria o
/// kernel regravá-lo, e os dois em laço.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plano {
    /// Gravar `gravar` — o controle com uma tentativa a menos — e, gravado e
    /// descarregado, bootar `tentativa`. Se a gravação falha, ou se a carga
    /// da tentativa falha, bootar `bom`; na falha da carga, gravar antes
    /// [`carga_recusada`].
    Tentar {
        gravar: Controle,
        tentativa: Boot,
        bom: Boot,
    },
    /// Bootar o slot bom.
    Bootar(Boot),
}

/// O plano do iniciador para o controle `c`.
///
/// A tentativa gasta uma vez **antes** de bootar: se o kernel novo travar,
/// entrar em pânico ou a energia cair, a conta já desceu, e o próximo boot
/// tenta de novo ou desiste. Nenhum caminho boota a versão nova sem descer
/// a conta.
pub fn planejar(c: &Controle) -> Plano {
    let bom = |modo| Boot {
        slot: c.bom,
        manifesto: Some(c.manifestos[c.bom.indice()]),
        modo,
    };
    match c.tentativa {
        Some(t) => match (c.manifesto(t), c.manifesto(c.bom)) {
            (Some(m), _) if c.restantes > 0 => Plano::Tentar {
                gravar: Controle {
                    restantes: c.restantes - 1,
                    ..*c
                },
                tentativa: Boot {
                    slot: t,
                    manifesto: Some(m),
                    modo: Modo::Tentativa,
                },
                bom: bom(Modo::Desfeita),
            },
            // Sintetizado, com a tentativa gasta: a vez do outro, também
            // com uma tentativa só — os dois se alternam até um kernel
            // regravar o controle pelo journal. Sem isso, o bom
            // sintetizado bootaria sem conta, e um pânico nele pararia a
            // máquina com a ativa boa no outro slot.
            (Some(m), Some(b)) if c.sintetizado => Plano::Tentar {
                gravar: Controle {
                    bom: t,
                    tentativa: Some(c.bom),
                    restantes: 0,
                    falha: Falha::Nenhuma,
                    ..*c
                },
                tentativa: Boot {
                    slot: c.bom,
                    manifesto: Some(b),
                    modo: Modo::Tentativa,
                },
                bom: Boot {
                    slot: t,
                    manifesto: Some(m),
                    modo: Modo::Desfeita,
                },
            },
            _ => Plano::Bootar(bom(Modo::Desfeita)),
        },
        None => Plano::Bootar(bom(Modo::Normal)),
    }
}

/// O controle a gravar quando a carga da tentativa falhou: a tentativa
/// encerrada, para que o kernel bom registre o desfazimento.
pub fn carga_recusada(gravado: &Controle) -> Controle {
    gravado.tentativa_encerrada(Falha::CargaRecusada)
}

/// O controle que o iniciador escreve quando nenhuma das duas cópias é
/// íntegra, a partir dos cabeçalhos dos slots: `cabecalhos[i]` é o resumo
/// e a geração do manifesto do slot `i`, se o cabeçalho dele é legível.
///
/// Com dois slots, o primeiro de [`ordem_sem_controle`] vai em tentativa,
/// com **uma** tentativa só, e o outro é o bom: o iniciador desce a conta e
/// tenta o primeiro; se ele entrar em pânico, travar, não carregar ou a
/// energia cair, o boot seguinte tenta o outro, também uma vez — e os dois
/// se alternam ([`planejar`]). Sem a conta, um kernel em pânico no primeiro
/// slot pararia a máquina a cada boot, com uma versão boa no outro. Com um
/// slot só, ele é o bom. Nenhum dos dois é o que decide: o kernel que subir
/// confere contra o journal e regrava o controle — e reinicia, se não é ele
/// o slot que o journal quer. Os dois em pânico se alternam até alguém
/// regravar um slot: não há versão boa para voltar.
///
/// Uma tentativa sintetizada da versão nova armada no journal pode se
/// confirmar, como uma tentativa de verdade: a armação é do journal, e a
/// conta de tentativas vale do mesmo jeito.
pub fn sintetizar(cabecalhos: [Option<([u8; TAM_RESUMO], u64)>; 2]) -> Option<Controle> {
    let geracoes = cabecalhos.map(|c| c.map(|(_, g)| g));
    let mut manifestos = [[0u8; TAM_RESUMO]; 2];
    for (i, c) in cabecalhos.iter().enumerate() {
        if let Some((m, _)) = c {
            manifestos[i] = *m;
        }
    }
    let base = |bom, tentativa, restantes| Controle {
        sequencia: 0,
        bom,
        tentativa,
        restantes,
        falha: Falha::Nenhuma,
        manifestos,
        sintetizado: true,
    };
    match ordem_sem_controle(geracoes) {
        [Some(primeiro), Some(segundo)] => Some(base(segundo, Some(primeiro), 1)),
        [Some(so), None] => Some(base(so, None, 0)),
        _ => None,
    }
}

/// A ordem dos slots sem controle: o de **menor** geração primeiro, e A
/// num empate. `geracoes[i]` é a geração do manifesto que o slot `i` tem,
/// se ele tem um manifesto legível. O kernel que subir regrava o controle
/// pelo journal — e reinicia, se não é ele o slot que o journal quer.
///
/// A menor primeiro porque ela já bootou: a de geração maior que a ativa é
/// uma versão nova, que talvez nunca tenha subido. A menor é a ativa, ou
/// uma velha abaixo do piso, que já foi a ativa: o kernel dela recusa a
/// autoridade, regrava o controle e reinicia — um boot a mais, e não um
/// laço.
pub fn ordem_sem_controle(geracoes: [Option<u64>; 2]) -> [Option<Slot>; 2] {
    let slot = |i: usize| if i == 0 { Slot::A } else { Slot::B };
    let mut ordem = [None, None];
    let mut n = 0;
    let primeiro = match geracoes {
        [Some(a), Some(b)] if b < a => 1,
        _ => 0,
    };
    for i in [primeiro, 1 - primeiro] {
        if geracoes[i].is_some() {
            ordem[n] = Some(slot(i));
            n += 1;
        }
    }
    ordem
}

#[cfg(test)]
mod testes {
    use super::*;

    fn exemplo() -> Controle {
        Controle {
            sequencia: 41,
            bom: Slot::A,
            tentativa: Some(Slot::B),
            restantes: 2,
            falha: Falha::Nenhuma,
            manifestos: [[1; 32], [2; 32]],
            sintetizado: false,
        }
    }

    #[test]
    fn ida_e_volta() {
        let c = exemplo();
        assert_eq!(ler(&escrever(&c)), Some(c));
        let sem = Controle {
            tentativa: None,
            restantes: 0,
            manifestos: [[1; 32], [0; 32]],
            ..c
        };
        assert_eq!(ler(&escrever(&sem)), Some(sem));
        assert_eq!(sem.manifesto(Slot::B), None);
        assert_eq!(sem.manifesto(Slot::A), Some([1; 32]));
    }

    #[test]
    fn um_bit_trocado_e_um_controle_que_nao_vale() {
        let b = escrever(&exemplo());
        for byte in 0..TAM_SETOR {
            for bit in 0..8 {
                let mut ruim = b;
                ruim[byte] ^= 1 << bit;
                assert_eq!(ler(&ruim), None, "byte {byte}, bit {bit}");
            }
        }
        assert_eq!(ler(&b[..100]), None);
        assert_eq!(ler(&[0u8; TAM_SETOR]), None);
    }

    #[test]
    fn recusa_valores_fora_do_dominio_mesmo_com_o_resumo_certo() {
        let refaz = |mexe: &dyn Fn(&mut [u8; TAM_SETOR])| {
            let mut b = escrever(&exemplo());
            mexe(&mut b);
            let mut r = Resumidor::novo();
            r.somar(&b[..EM_RESUMO]);
            b[EM_RESUMO..].copy_from_slice(&r.terminar());
            ler(&b)
        };
        assert!(refaz(&|_| {}).is_some());
        assert!(refaz(&|b| b[24] = 0).is_none());
        assert!(refaz(&|b| b[24] = 3).is_none());
        assert!(refaz(&|b| b[25] = 3).is_none());
        // A tentativa no próprio slot bom.
        assert!(refaz(&|b| b[25] = 1).is_none());
        assert!(refaz(&|b| b[27] = 3).is_none());
        assert!(refaz(&|b| b[11] = 1).is_none());
        assert!(refaz(&|b| b[28] = 2).is_none());
        assert!(refaz(&|b| b[30] = 1).is_none());
        assert!(refaz(&|b| b[28] = 1).is_some_and(|c| c.sintetizado));
        assert!(refaz(&|b| b[200] = 1).is_none());
        assert!(refaz(&|b| b[8] = 2).is_none());
    }

    #[test]
    fn vale_a_maior_sequencia_integra_e_grava_se_na_outra() {
        let a = exemplo();
        let b = Controle { sequencia: 42, ..a };
        assert_eq!(escolher([Some(a), Some(b)]), Some((1, b)));
        assert_eq!(escolher([Some(b), Some(a)]), Some((0, b)));
        assert_eq!(escolher([None, Some(a)]), Some((1, a)));
        assert_eq!(escolher([Some(a), None]), Some((0, a)));
        assert_eq!(escolher([None, None]), None);
        // Empate: a primeira.
        assert_eq!(escolher([Some(a), Some(a)]), Some((0, a)));

        let novo = Controle { restantes: 1, ..a };
        let (onde, gravar) = proxima(Some((1, &b)), &novo);
        assert_eq!((onde, gravar.sequencia, gravar.restantes), (0, 43, 1));
        let (onde, gravar) = proxima(None, &novo);
        assert_eq!((onde, gravar.sequencia), (0, 1));
    }

    #[test]
    fn a_gravacao_rasgada_deixa_a_anterior_valendo() {
        let a = exemplo();
        let mut copias = [Some(a), None];
        let (vale, atual) = escolher(copias).unwrap();
        let (onde, novo) = proxima(
            Some((vale, &atual)),
            &Controle {
                restantes: 1,
                ..atual
            },
        );
        assert_ne!(onde, vale);
        // Rasgada: a cópia que se escrevia vira lixo, e a anterior vale.
        let mut rasgada = escrever(&novo);
        rasgada[100] ^= 0x40;
        copias[onde] = ler(&rasgada);
        assert_eq!(escolher(copias), Some((vale, a)));
        // Inteira: a nova vale.
        copias[onde] = ler(&escrever(&novo));
        assert_eq!(escolher(copias), Some((onde, novo)));
    }

    #[test]
    fn o_plano_desce_a_conta_antes_de_tentar() {
        let c = exemplo();
        match planejar(&c) {
            Plano::Tentar {
                gravar,
                tentativa,
                bom,
            } => {
                assert_eq!(gravar.restantes, 1);
                assert_eq!(gravar.sequencia, c.sequencia, "a sequencia e de quem grava");
                assert_eq!(
                    tentativa,
                    Boot {
                        slot: Slot::B,
                        manifesto: Some([2; 32]),
                        modo: Modo::Tentativa
                    }
                );
                assert_eq!(bom.modo, Modo::Desfeita);
                assert_eq!(bom.slot, Slot::A);
                let recusada = carga_recusada(&gravar);
                assert_eq!(
                    (recusada.restantes, recusada.falha),
                    (0, Falha::CargaRecusada)
                );
                assert_eq!(recusada.tentativa, Some(Slot::B));
            }
            outro => panic!("{outro:?}"),
        }
        // Sem tentativas restantes: o bom, desfeita.
        let esgotada = Controle { restantes: 0, ..c };
        assert_eq!(
            planejar(&esgotada),
            Plano::Bootar(Boot {
                slot: Slot::A,
                manifesto: Some([1; 32]),
                modo: Modo::Desfeita
            })
        );
        // A tentativa sem manifesto não boota.
        let sem_manifesto = Controle {
            manifestos: [[1; 32], [0; 32]],
            ..c
        };
        assert!(matches!(
            planejar(&sem_manifesto),
            Plano::Bootar(Boot {
                modo: Modo::Desfeita,
                ..
            })
        ));
        // Sem tentativa: normal.
        let normal = Controle {
            tentativa: None,
            ..c
        };
        assert!(matches!(
            planejar(&normal),
            Plano::Bootar(Boot {
                slot: Slot::A,
                modo: Modo::Normal,
                ..
            })
        ));
    }

    #[test]
    fn sem_controle_a_menor_geracao_primeiro() {
        assert_eq!(
            ordem_sem_controle([Some(3), Some(4)]),
            [Some(Slot::A), Some(Slot::B)]
        );
        assert_eq!(
            ordem_sem_controle([Some(5), Some(4)]),
            [Some(Slot::B), Some(Slot::A)]
        );
        assert_eq!(
            ordem_sem_controle([Some(4), Some(4)]),
            [Some(Slot::A), Some(Slot::B)]
        );
        assert_eq!(ordem_sem_controle([None, Some(4)]), [Some(Slot::B), None]);
        assert_eq!(ordem_sem_controle([None, None]), [None, None]);
    }

    #[test]
    fn o_controle_sintetizado_tenta_o_primeiro_uma_vez_so() {
        let a = ([1u8; 32], 3);
        let b = ([2u8; 32], 4);
        let c = sintetizar([Some(a), Some(b)]).unwrap();
        assert_eq!(
            (c.bom, c.tentativa, c.restantes),
            (Slot::B, Some(Slot::A), 1)
        );
        assert_eq!(c.manifestos, [[1; 32], [2; 32]]);
        assert_eq!(c.falha, Falha::Nenhuma);
        assert!(c.sintetizado);
        assert_eq!(ler(&escrever(&c)), Some(c), "o sintetizado e um controle");
        // O plano dele: tenta A, uma vez; depois B, uma vez; depois A...
        let Plano::Tentar {
            gravar,
            tentativa,
            bom,
        } = planejar(&c)
        else {
            panic!()
        };
        assert_eq!(
            (gravar.restantes, tentativa.slot, bom.slot),
            (0, Slot::A, Slot::B)
        );
        let Plano::Tentar {
            gravar: depois,
            tentativa,
            bom,
        } = planejar(&gravar)
        else {
            panic!()
        };
        assert_eq!((tentativa.slot, tentativa.modo), (Slot::B, Modo::Tentativa));
        assert_eq!((bom.slot, bom.modo), (Slot::A, Modo::Desfeita));
        assert_eq!(
            (depois.bom, depois.tentativa, depois.restantes),
            (Slot::A, Some(Slot::B), 0)
        );
        let Plano::Tentar { tentativa, .. } = planejar(&depois) else {
            panic!()
        };
        assert_eq!(tentativa.slot, Slot::A);
        // O do kernel, com a tentativa gasta, não alterna: volta ao bom.
        let do_kernel = Controle {
            sintetizado: false,
            ..gravar
        };
        assert!(matches!(
            planejar(&do_kernel),
            Plano::Bootar(Boot {
                slot: Slot::B,
                modo: Modo::Desfeita,
                ..
            })
        ));
        let so = sintetizar([None, Some(b)]).unwrap();
        assert_eq!((so.bom, so.tentativa), (Slot::B, None));
        assert_eq!(so.manifesto(Slot::A), None);
        assert_eq!(sintetizar([None, None]), None);
    }

    #[test]
    fn os_modos_e_as_falhas_vao_e_voltam_pelo_byte() {
        for m in [
            Modo::Normal,
            Modo::Tentativa,
            Modo::Desfeita,
            Modo::SemControle,
        ] {
            assert_eq!(Modo::do_byte(m.byte()), Some(m));
        }
        assert_eq!(Modo::do_byte(0), None);
        for f in [
            Falha::Nenhuma,
            Falha::CargaRecusada,
            Falha::ValidacaoRecusada,
        ] {
            assert_eq!(Falha::do_byte(f.byte()), Some(f));
        }
    }
}
