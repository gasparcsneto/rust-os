//! O balde de fichas: quantos pedidos por segundo, com rajada.
//!
//! Cada pedido gasta uma ficha. O balde enche à razão de `por_segundo` e
//! guarda no máximo `rajada`. Um agente que pede devagar sempre acha ficha;
//! um que despeja pedidos gasta a rajada e passa a ser atendido na razão do
//! balde — o resto ouve `RATE_LIMIT`.
//!
//! O tempo vem de quem chama, em milissegundos: o balde não sabe de relógio,
//! e por isso os testes o conferem sem esperar.

use crate::arquivo::Taxa;

/// Um balde. As fichas são contadas em milésimos, para encher sem fração.
#[derive(Clone, Copy, Debug)]
pub struct Balde {
    taxa: Taxa,
    milifichas: u64,
    ultimo_ms: u64,
}

impl Balde {
    /// Um balde cheio.
    pub fn novo(taxa: Taxa, agora_ms: u64) -> Balde {
        Balde {
            taxa,
            milifichas: u64::from(taxa.rajada) * 1000,
            ultimo_ms: agora_ms,
        }
    }

    /// A taxa deste balde. Quem muda o papel de alguém troca o balde.
    pub fn taxa(&self) -> Taxa {
        self.taxa
    }

    /// Tenta gastar uma ficha. Verdadeiro se havia.
    pub fn tentar(&mut self, agora_ms: u64) -> bool {
        // Um relógio que anda para trás não devolve fichas.
        let passou = agora_ms.saturating_sub(self.ultimo_ms);
        self.ultimo_ms = self.ultimo_ms.max(agora_ms);
        let teto = u64::from(self.taxa.rajada) * 1000;
        self.milifichas = self
            .milifichas
            .saturating_add(passou.saturating_mul(u64::from(self.taxa.por_segundo)))
            .min(teto);
        if self.milifichas >= 1000 {
            self.milifichas -= 1000;
            true
        } else {
            false
        }
    }
}

/// Uma janela de apertos de mão: no máximo `quantos` a cada `janela_ms`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Janela {
    inicio_ms: u64,
    contados: u32,
}

impl Janela {
    /// Uma janela vazia, para iniciar uma tabela estática.
    pub const NOVA: Janela = Janela {
        inicio_ms: 0,
        contados: 0,
    };

    /// Conta um aperto. Verdadeiro se ele cabe na janela.
    pub fn contar(&mut self, limite: crate::arquivo::Apertos, agora_ms: u64) -> bool {
        if agora_ms.saturating_sub(self.inicio_ms) >= limite.janela_ms {
            self.inicio_ms = agora_ms;
            self.contados = 0;
        }
        if self.contados >= limite.quantos {
            return false;
        }
        self.contados += 1;
        true
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::arquivo::Apertos;

    #[test]
    fn rajada_e_depois_a_razao() {
        let taxa = Taxa {
            por_segundo: 10,
            rajada: 5,
        };
        let mut b = Balde::novo(taxa, 0);
        for _ in 0..5 {
            assert!(b.tentar(0));
        }
        assert!(!b.tentar(0), "a rajada acabou");
        // Cem milissegundos a dez por segundo: uma ficha.
        assert!(b.tentar(100));
        assert!(!b.tentar(100));
        // Um segundo parado enche, mas não passa da rajada.
        for _ in 0..5 {
            assert!(b.tentar(10_000));
        }
        assert!(!b.tentar(10_000));
    }

    #[test]
    fn relogio_para_tras_nao_enche() {
        let mut b = Balde::novo(
            Taxa {
                por_segundo: 1000,
                rajada: 1,
            },
            1000,
        );
        assert!(b.tentar(1000));
        assert!(!b.tentar(0));
    }

    #[test]
    fn janela_de_apertos() {
        let limite = Apertos {
            quantos: 2,
            janela_ms: 1000,
        };
        let mut j = Janela::default();
        assert!(j.contar(limite, 0));
        assert!(j.contar(limite, 10));
        assert!(!j.contar(limite, 20));
        assert!(j.contar(limite, 1000));
    }
}
