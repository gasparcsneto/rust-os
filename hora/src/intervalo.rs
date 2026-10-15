//! A amostra: o intervalo em que a hora estava quando a resposta chegou.
//!
//! **Referência:** uma resposta válida prova que a fonte assinou, enquanto
//! processava o pedido, um carimbo `MIDP` com a hora a menos de `RADI`
//! segundos dele.
//!
//! O processamento aconteceu entre a saída do pedido e a chegada da
//! resposta, e esse tempo (o RTT) é medido por quem chama, pelo contador
//! local. No instante da chegada, então, a hora estava em
//!
//! ```text
//! [MIDP − RADI, MIDP + RADI + RTT]
//! ```
//!
//! O transporte só consegue atrasar, e atraso alarga o intervalo; não o
//! desloca. Os intervalos são fechados, e em milissegundos.

/// Uma amostra: o intervalo da hora num instante do contador local, e a
/// chave longa da fonte que a assinou.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Amostra {
    /// A chave longa da fonte.
    pub chave: [u8; 32],
    /// O começo do intervalo, em milissegundos desde a época Unix.
    pub cedo_ms: u64,
    /// O fim do intervalo.
    pub tarde_ms: u64,
    /// O instante do contador local a que o intervalo se refere.
    pub instante_ms: u64,
}

impl Amostra {
    /// A amostra de um carimbo e um raio, em segundos, com o RTT medido.
    pub fn de(chave: [u8; 32], midp: u64, radi: u32, rtt_ms: u64, instante_ms: u64) -> Amostra {
        let radi = u64::from(radi);
        Amostra {
            chave,
            cedo_ms: midp.saturating_sub(radi).saturating_mul(1000),
            tarde_ms: midp
                .saturating_add(radi)
                .saturating_mul(1000)
                .saturating_add(rtt_ms),
            instante_ms,
        }
    }

    /// A mesma amostra levada a um instante posterior do contador: o
    /// intervalo anda o tempo que passou, e se alarga pela deriva máxima do
    /// contador nesse tempo. Um instante anterior não é aceito — devolve a
    /// amostra como está.
    pub fn em(&self, instante_ms: u64, deriva_ppm: u64) -> Amostra {
        let decorrido = instante_ms.saturating_sub(self.instante_ms);
        let folga = deriva_em(decorrido, deriva_ppm);
        Amostra {
            chave: self.chave,
            cedo_ms: self.cedo_ms.saturating_add(decorrido).saturating_sub(folga),
            tarde_ms: self
                .tarde_ms
                .saturating_add(decorrido)
                .saturating_add(folga),
            instante_ms: self.instante_ms.max(instante_ms),
        }
    }
}

/// O quanto um contador com esta deriva máxima pode ter errado em
/// `decorrido` milissegundos — arredondado para cima.
pub fn deriva_em(decorrido_ms: u64, deriva_ppm: u64) -> u64 {
    let produto = u128::from(decorrido_ms) * u128::from(deriva_ppm);
    u64::try_from(produto.div_ceil(1_000_000)).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn o_intervalo_tem_o_raio_dos_dois_lados_e_o_rtt_no_fim() {
        let a = Amostra::de([1; 32], 1000, 5, 120, 77);
        assert_eq!(a.cedo_ms, 995_000);
        assert_eq!(a.tarde_ms, 1_005_120);
        assert_eq!(a.instante_ms, 77);
        let sem_rtt = Amostra::de([1; 32], 1000, 5, 0, 77);
        assert_eq!(sem_rtt.tarde_ms, 1_005_000);
    }

    #[test]
    fn nas_pontas_satura() {
        let a = Amostra::de([1; 32], 2, 5, 0, 0);
        assert_eq!(a.cedo_ms, 0);
        let b = Amostra::de([1; 32], u64::MAX, 5, 9, 0);
        assert_eq!(b.tarde_ms, u64::MAX);
    }

    #[test]
    fn levar_adiante_anda_e_alarga() {
        let a = Amostra::de([1; 32], 1000, 5, 0, 10_000);
        let b = a.em(10_000 + 1_000_000, 500);
        assert_eq!(b.instante_ms, 1_010_000);
        assert_eq!(b.cedo_ms, 995_000 + 1_000_000 - 500);
        assert_eq!(b.tarde_ms, 1_005_000 + 1_000_000 + 500);
        assert_eq!(a.em(10_000, 500), a, "nada passou, nada muda");
        assert_eq!(a.em(5_000, 500), a, "para trás, não");
    }

    #[test]
    fn a_deriva_arredonda_para_cima() {
        assert_eq!(deriva_em(0, 500), 0);
        assert_eq!(deriva_em(1, 500), 1);
        assert_eq!(deriva_em(2_000, 500), 1);
        assert_eq!(deriva_em(2_001, 500), 2);
        assert_eq!(deriva_em(1_000_000, 500), 500);
        assert_eq!(deriva_em(u64::MAX, u64::MAX), u64::MAX);
    }
}
