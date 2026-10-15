//! O acordo k-de-n sobre os intervalos das fontes.
//!
//! Uma resposta válida não diz que a hora está certa; diz que a fonte a
//! assinou. O relógio só se move pelo que **pelo menos k chaves**
//! concordam, e k é pelo menos 2, quantas fontes houver: com uma fonte só,
//! as respostas são conferidas e registradas, e nada se move.
//!
//! # A conta
//!
//! Cada amostra é um intervalo fechado, já levado ao mesmo instante do
//! contador ([`Amostra::em`]). A cobertura de um ponto é quantas **chaves
//! diferentes** têm intervalo que o contém. O acordo é o trecho de maior
//! cobertura — o algoritmo de Marzullo —, desde que:
//!
//! - a maior cobertura seja pelo menos k;
//! - **um só trecho** tenha essa cobertura: dois trechos disjuntos
//!   empatados são duas histórias com o mesmo apoio, e escolher uma seria
//!   escolher no escuro. O acordo é recusado (D0-10).
//!
//! # Uma chave conta uma vez
//!
//! Duas amostras da mesma chave valem uma: o intervalo dela é a interseção
//! das duas. Se as duas não se tocam, a chave se contradisse, e fica de fora
//! da conta, marcada.
//!
//! # O que uma fonte mentirosa consegue
//!
//! Com no máximo k − 1 fontes mentindo, todo trecho com cobertura k contém
//! o intervalo de ao menos uma fonte honesta, e a hora verdadeira está no
//! intervalo de toda fonte honesta. Uma mentirosa que se sobrepõe em parte
//! pode puxar o acordo **para dentro** do intervalo de uma honesta; nunca
//! para fora dele. Uma que não se sobrepõe fica marcada como divergente.

use crate::intervalo::Amostra;

/// O maior número de amostras numa rodada.
pub const MAIS_AMOSTRAS: usize = 8;

// As marcas de divergência são bits de um `u8`.
const _: () = assert!(MAIS_AMOSTRAS <= 8);

/// O que uma rodada deu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Desfecho {
    /// Pelo menos k chaves concordam neste trecho.
    Acordo(Acordo),
    /// Menos de k chaves no trecho mais coberto (ou menos de k chaves).
    SemQuorum {
        /// Quantas chaves diferentes deram amostra que conta.
        chaves: usize,
        /// A maior cobertura.
        maior_cobertura: usize,
    },
    /// Dois ou mais trechos disjuntos com a mesma maior cobertura.
    Empate { cobertura: usize },
    /// k menor que 2, ou amostras demais: nunca há acordo.
    Invalido,
}

/// O trecho em que as chaves concordam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acordo {
    pub cedo_ms: u64,
    pub tarde_ms: u64,
    /// Quantas chaves cobrem o trecho.
    pub cobertura: usize,
    /// As amostras (bits, na ordem dada) cujo intervalo não toca o trecho.
    pub divergentes: u8,
    /// As amostras (bits) de chaves que se contradisseram.
    pub contraditorias: u8,
}

impl Acordo {
    /// O meio do trecho.
    pub fn meio_ms(&self) -> u64 {
        self.cedo_ms + (self.tarde_ms - self.cedo_ms) / 2
    }

    /// A meia largura: a incerteza do acordo.
    pub fn incerteza_ms(&self) -> u64 {
        (self.tarde_ms - self.cedo_ms).div_ceil(2)
    }
}

/// O acordo de pelo menos `k` chaves sobre estas amostras, já levadas ao
/// mesmo instante.
pub fn acordo(amostras: &[Amostra], k: usize) -> Desfecho {
    if k < 2 || amostras.len() > MAIS_AMOSTRAS {
        return Desfecho::Invalido;
    }

    // Uma chave, um intervalo: a interseção das amostras dela.
    let mut chaves = [[0u8; 32]; MAIS_AMOSTRAS];
    let mut intervalos = [(0u64, 0u64); MAIS_AMOSTRAS];
    let mut contraditoria = [false; MAIS_AMOSTRAS];
    let mut n = 0;
    let mut de_quem = [0usize; MAIS_AMOSTRAS];
    for (i, a) in amostras.iter().enumerate() {
        match chaves[..n].iter().position(|c| *c == a.chave) {
            Some(j) => {
                let (cedo, tarde) = intervalos[j];
                intervalos[j] = (cedo.max(a.cedo_ms), tarde.min(a.tarde_ms));
                de_quem[i] = j;
            }
            None => {
                chaves[n] = a.chave;
                intervalos[n] = (a.cedo_ms, a.tarde_ms);
                de_quem[i] = n;
                n += 1;
            }
        }
    }
    let mut contraditorias = 0u8;
    for j in 0..n {
        if intervalos[j].0 > intervalos[j].1 {
            contraditoria[j] = true;
        }
    }
    for (i, &j) in de_quem.iter().enumerate().take(amostras.len()) {
        if contraditoria[j] {
            contraditorias |= 1 << i;
        }
    }
    let validas: usize = (0..n).filter(|&j| !contraditoria[j]).count();

    // A maior cobertura é atingida no começo de algum intervalo.
    let cobertura = |x: u64| -> usize {
        (0..n)
            .filter(|&j| !contraditoria[j] && intervalos[j].0 <= x && x <= intervalos[j].1)
            .count()
    };
    let mut maior = 0;
    for j in 0..n {
        if !contraditoria[j] {
            maior = maior.max(cobertura(intervalos[j].0));
        }
    }
    if maior < k {
        return Desfecho::SemQuorum {
            chaves: validas,
            maior_cobertura: maior,
        };
    }

    // Os trechos de maior cobertura. Cada um começa no começo de um
    // intervalo e acaba no fim de outro: cobertura máxima num ponto quer
    // dizer que todos os intervalos que o contêm se cruzam ali, e o trecho
    // é a interseção deles.
    let mut trechos = [(0u64, 0u64); MAIS_AMOSTRAS];
    let mut quantos = 0;
    for j in 0..n {
        if contraditoria[j] || cobertura(intervalos[j].0) != maior {
            continue;
        }
        let x = intervalos[j].0;
        let mut cedo = 0;
        let mut tarde = u64::MAX;
        for m in 0..n {
            if !contraditoria[m] && intervalos[m].0 <= x && x <= intervalos[m].1 {
                cedo = cedo.max(intervalos[m].0);
                tarde = tarde.min(intervalos[m].1);
            }
        }
        if !trechos[..quantos].contains(&(cedo, tarde)) {
            trechos[quantos] = (cedo, tarde);
            quantos += 1;
        }
    }
    if quantos != 1 {
        return Desfecho::Empate { cobertura: maior };
    }
    let (cedo, tarde) = trechos[0];
    let mut divergentes = 0u8;
    for (i, &j) in de_quem.iter().enumerate().take(amostras.len()) {
        if !contraditoria[j] && (intervalos[j].1 < cedo || intervalos[j].0 > tarde) {
            divergentes |= 1 << i;
        }
    }
    Desfecho::Acordo(Acordo {
        cedo_ms: cedo,
        tarde_ms: tarde,
        cobertura: maior,
        divergentes,
        contraditorias,
    })
}

#[cfg(test)]
mod testes {
    use super::*;
    use std::vec::Vec;

    fn a(chave: u8, cedo: u64, tarde: u64) -> Amostra {
        Amostra {
            chave: [chave; 32],
            cedo_ms: cedo,
            tarde_ms: tarde,
            instante_ms: 0,
        }
    }

    fn acordo_de(amostras: &[Amostra], k: usize) -> Acordo {
        match acordo(amostras, k) {
            Desfecho::Acordo(x) => x,
            outro => panic!("sem acordo: {outro:?}"),
        }
    }

    #[test]
    fn k_menor_que_dois_nunca_da_acordo() {
        let amostras = [a(1, 0, 10), a(2, 0, 10), a(3, 0, 10)];
        assert_eq!(acordo(&amostras, 1), Desfecho::Invalido);
        assert_eq!(acordo(&amostras, 0), Desfecho::Invalido);
        assert!(matches!(acordo(&amostras, 2), Desfecho::Acordo(_)));
    }

    #[test]
    fn uma_fonte_so_nao_move_nada() {
        assert_eq!(
            acordo(&[a(1, 0, 10)], 2),
            Desfecho::SemQuorum {
                chaves: 1,
                maior_cobertura: 1
            }
        );
        assert_eq!(
            acordo(&[], 2),
            Desfecho::SemQuorum {
                chaves: 0,
                maior_cobertura: 0
            }
        );
    }

    #[test]
    fn tres_honestas_concordam_na_intersecao() {
        let x = acordo_de(&[a(1, 0, 10), a(2, 4, 12), a(3, 2, 8)], 2);
        assert_eq!((x.cedo_ms, x.tarde_ms, x.cobertura), (4, 8, 3));
        assert_eq!(x.divergentes, 0);
        assert_eq!(x.meio_ms(), 6);
        assert_eq!(x.incerteza_ms(), 2);
    }

    #[test]
    fn a_divergente_fica_de_fora_e_marcada() {
        let x = acordo_de(&[a(1, 0, 10), a(2, 30, 40), a(3, 2, 12)], 2);
        assert_eq!((x.cedo_ms, x.tarde_ms, x.cobertura), (2, 10, 2));
        assert_eq!(x.divergentes, 0b010);
    }

    #[test]
    fn duas_regioes_empatadas_sao_recusadas() {
        // Honestas A e B; a mentirosa C cruza só com B.
        let amostras = [a(1, 0, 10), a(2, 5, 15), a(3, 12, 20)];
        assert_eq!(acordo(&amostras, 2), Desfecho::Empate { cobertura: 2 });
        // Duas contra duas.
        let amostras = [a(1, 0, 10), a(2, 2, 12), a(3, 50, 60), a(4, 52, 62)];
        assert_eq!(acordo(&amostras, 2), Desfecho::Empate { cobertura: 2 });
    }

    #[test]
    fn a_maior_cobertura_ganha_do_trecho_menor() {
        // Três concordam em [5, 8]; duas em [20, 25]: ganha a de três.
        let amostras = [
            a(1, 0, 10),
            a(2, 5, 12),
            a(3, 3, 8),
            a(4, 20, 30),
            a(5, 15, 25),
        ];
        let x = acordo_de(&amostras, 2);
        assert_eq!((x.cedo_ms, x.tarde_ms, x.cobertura), (5, 8, 3));
        assert_eq!(x.divergentes, 0b11000);
    }

    #[test]
    fn a_mesma_chave_conta_uma_vez() {
        // A chave 1 repetida não faz quórum sozinha.
        let amostras = [a(1, 0, 10), a(1, 2, 12), a(1, 3, 9)];
        assert_eq!(
            acordo(&amostras, 2),
            Desfecho::SemQuorum {
                chaves: 1,
                maior_cobertura: 1
            }
        );
        // E não infla a cobertura: duas chaves, cobertura 2, e k = 3 falha.
        let amostras = [a(1, 0, 10), a(1, 0, 10), a(2, 0, 10)];
        assert!(matches!(
            acordo(&amostras, 3),
            Desfecho::SemQuorum {
                chaves: 2,
                maior_cobertura: 2
            }
        ));
        let x = acordo_de(&amostras, 2);
        assert_eq!(x.cobertura, 2);
    }

    #[test]
    fn a_chave_que_se_contradiz_fica_de_fora() {
        let amostras = [a(1, 0, 10), a(1, 50, 60), a(2, 2, 12), a(3, 3, 11)];
        let x = acordo_de(&amostras, 2);
        assert_eq!(x.cobertura, 2);
        assert_eq!(x.contraditorias, 0b0011);
        assert_eq!((x.cedo_ms, x.tarde_ms), (3, 11));
    }

    #[test]
    fn a_mentirosa_que_cruza_puxa_so_para_dentro_de_uma_honesta() {
        let honestas = [a(1, 0, 10), a(2, 2, 12)];
        let mentirosa = a(3, 9, 30);
        let x = acordo_de(&[honestas[0], honestas[1], mentirosa], 2);
        assert_eq!((x.cedo_ms, x.tarde_ms), (9, 10));
        for h in honestas {
            assert!(h.cedo_ms <= x.cedo_ms && x.tarde_ms <= h.tarde_ms);
        }
    }

    #[test]
    fn as_pontas_que_se_tocam_contam() {
        let x = acordo_de(&[a(1, 0, 10), a(2, 10, 20)], 2);
        assert_eq!((x.cedo_ms, x.tarde_ms), (10, 10));
        assert!(matches!(
            acordo(&[a(1, 0, 10), a(2, 11, 20)], 2),
            Desfecho::SemQuorum { .. }
        ));
    }

    #[test]
    fn amostras_demais() {
        let muitas: Vec<Amostra> = (0..=MAIS_AMOSTRAS as u8).map(|i| a(i, 0, 10)).collect();
        assert_eq!(acordo(&muitas, 2), Desfecho::Invalido);
        assert!(matches!(
            acordo(&muitas[..MAIS_AMOSTRAS], 2),
            Desfecho::Acordo(_)
        ));
    }

    #[test]
    fn o_resultado_nao_depende_da_ordem() {
        let amostras = [a(1, 0, 10), a(2, 30, 40), a(3, 2, 12), a(4, 5, 9)];
        let base = acordo_de(&amostras, 2);
        let mut outra = amostras;
        outra.reverse();
        let invertido = acordo_de(&outra, 2);
        assert_eq!(
            (base.cedo_ms, base.tarde_ms, base.cobertura),
            (invertido.cedo_ms, invertido.tarde_ms, invertido.cobertura)
        );
    }
}
