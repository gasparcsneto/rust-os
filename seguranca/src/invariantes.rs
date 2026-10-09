//! O monitor de invariantes: a segunda camada, sobre o que as regras não
//! olham — a própria auditoria que o NSF lê, e o próprio NSF.
//!
//! - Cada registro refaz o elo dele (`politica::auditoria::elo`), e o
//!   anterior dele é o elo do registro de antes: uma cadeia que não se
//!   refaz não foi escrita pelo gate como está.
//! - A sequência não pula: um buraco é o que saiu do anel antes de o NSF o
//!   ler — às vezes por excesso, às vezes por uma enxurrada feita para
//!   empurrar alguma coisa para fora.
//! - O tempo não volta.
//! - Toda ação do NSF que a auditoria mostra corresponde a um pedido que o
//!   motor planejou — essa conta mora no motor, que tem os planos; ver
//!   [`crate::motor`].

use alloc::vec::Vec;

use crate::evento::Registro;

/// O que não confere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violacao {
    /// O elo do registro não refaz a conta.
    Adulterado { seq: u64 },
    /// O anterior do registro não é o elo do registro de antes.
    Desencadeado { seq: u64 },
    /// Registros que sumiram antes da leitura: do primeiro ao último.
    Lacuna { de: u64, ate: u64 },
    /// O tempo do registro é menor que o do anterior.
    TempoVolta { seq: u64 },
}

/// O monitor.
#[derive(Clone, Debug, Default)]
pub struct Monitor {
    ultimo: Option<(u64, [u8; 32], u64)>,
}

impl Monitor {
    pub fn novo() -> Monitor {
        Monitor::default()
    }

    /// Começa a conferência depois de `seq`: a leitura começa ali, e o que
    /// veio antes não é buraco.
    pub fn comecar_em(&mut self, seq: u64, elo: [u8; 32], ts: u64) {
        self.ultimo = Some((seq, elo, ts));
    }

    /// Confere um registro novo — de sequência maior que a do último.
    pub fn conferir(&mut self, r: &Registro) -> Vec<Violacao> {
        let mut v = Vec::new();
        if !r.elo_confere() {
            v.push(Violacao::Adulterado { seq: r.seq });
        }
        if let Some((seq, elo, ts)) = self.ultimo {
            if r.seq == seq + 1 && r.anterior != elo {
                v.push(Violacao::Desencadeado { seq: r.seq });
            }
            if r.seq > seq + 1 {
                v.push(Violacao::Lacuna {
                    de: seq + 1,
                    ate: r.seq - 1,
                });
            }
            if r.ts_ms < ts {
                v.push(Violacao::TempoVolta { seq: r.seq });
            }
        }
        self.ultimo = Some((r.seq, r.elo, r.ts_ms));
        v
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::evento::testes::registro;

    fn corrente(n: u64) -> Vec<Registro> {
        let mut v: Vec<Registro> = Vec::new();
        for seq in 1..=n {
            let anterior = v.last().map_or([0; 32], |r| r.elo);
            v.push(registro(seq, anterior, |_| {}));
        }
        v
    }

    #[test]
    fn a_cadeia_inteira_confere() {
        let mut m = Monitor::novo();
        for r in corrente(5) {
            assert!(m.conferir(&r).is_empty(), "{}", r.seq);
        }
    }

    #[test]
    fn adulterado_e_desencadeado() {
        let mut c = corrente(4);
        c[1].recurso = "/adulterado".into();
        c[2].anterior = [9; 32];
        let mut m = Monitor::novo();
        let v: Vec<Vec<Violacao>> = c.iter().map(|r| m.conferir(r)).collect();
        assert_eq!(v[1], [Violacao::Adulterado { seq: 2 }]);
        // O terceiro: o anterior foi trocado, e o elo não refaz mais.
        assert!(v[2].contains(&Violacao::Desencadeado { seq: 3 }));
        assert!(v[2].contains(&Violacao::Adulterado { seq: 3 }));
        assert!(v[3].is_empty());
    }

    #[test]
    fn a_lacuna_e_o_tempo() {
        let c = corrente(6);
        let mut m = Monitor::novo();
        assert!(m.conferir(&c[0]).is_empty());
        assert_eq!(m.conferir(&c[4]), [Violacao::Lacuna { de: 2, ate: 4 }]);
        let mut volta = c[5].clone();
        volta.ts_ms = 0;
        volta.elo = politica::auditoria::elo(&volta.anterior, volta.seq, &volta.evento_da_cadeia());
        assert_eq!(m.conferir(&volta), [Violacao::TempoVolta { seq: 6 }]);
        // Começar em um ponto: o que veio antes não é buraco.
        let mut m = Monitor::novo();
        m.comecar_em(4, c[3].elo, c[3].ts_ms);
        assert!(m.conferir(&c[4]).is_empty());
    }
}
