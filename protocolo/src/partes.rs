//! As partes de uma rodada: a suíte do kernel e as bancadas longas do
//! `xtask`, divididas entre máquinas da CI.
//!
//! # A regra
//!
//! Uma parte se escreve `k/n` — a `k`-ésima de `n`, com `1 <= k <= n`. O
//! item de índice `i`, a posição dele na tabela inteira, na ordem em que ela
//! roda, é da parte `k` de `n` exatamente quando `i % n == k - 1`. Daí o que
//! a CI precisa:
//!
//! - todo item cai em **exatamente uma** das `n` partes: a união delas é a
//!   tabela inteira, e nada roda duas vezes;
//! - dentro de uma parte, a ordem é a da tabela: o que tem de vir antes de
//!   outro continua antes quando os dois caem juntos, e o primeiro de cada
//!   parte é o de menor índice dela;
//! - um item novo entra numa das partes sem mexer na CI, e a intercalação
//!   deixa as partes equilibradas — o que é longo não se junta numa só.
//!
//! O que tem de rodar em toda parte — o que confere a rodada inteira até ali
//! — não entra na conta: fica numa tabela à parte, a cauda da suíte (ver
//! `kernel/src/testes.rs`).
//!
//! # Por que mora aqui
//!
//! Porque são dois os que leem uma parte e escolhem por ela: o `xtask`, que
//! a lê de `DUKE_PARTE` — para as bancadas e para a compilação da suíte — e
//! confere o que a suíte anunciou, e o kernel da suíte, que a recebe da
//! compilação e roda a fatia dela. Uma regra, uma declaração: duas contas
//! iguais em dois lugares são duas que podem divergir, e uma parte que o
//! kernel escolhesse por outra conta deixaria casos fora de todas sem que
//! nada reprovasse.
//!
//! # Um valor que não se lê
//!
//! É recusado, e não vira "nenhum" nem "todos": uma parte mal escrita que
//! rodasse a tabela inteira gastaria uma máquina à toa; uma que não rodasse
//! nada passaria verde sem testar coisa alguma.

use core::fmt;

/// Uma parte: a `k`-ésima de `n`, com `1 <= k <= n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parte {
    k: usize,
    n: usize,
}

/// Por que um texto não é uma parte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErroDaParte {
    /// Não é `k/n`: falta a barra, ou um dos lados não é um número.
    Forma,
    /// `k` fora de `1..=n`, ou `n` zero.
    Faixa,
}

impl ErroDaParte {
    /// O motivo, numa frase.
    pub const fn motivo(self) -> &'static str {
        match self {
            ErroDaParte::Forma => "esperava a parte e o total, como 1/2",
            ErroDaParte::Faixa => "a parte vai de 1 ao total, e o total nao e zero",
        }
    }
}

impl fmt::Display for ErroDaParte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.motivo())
    }
}

impl Parte {
    /// A parte `k` de `n`, se `1 <= k <= n`.
    pub const fn nova(k: usize, n: usize) -> Option<Parte> {
        if k >= 1 && k <= n {
            Some(Parte { k, n })
        } else {
            None
        }
    }

    /// Lê `k/n`: dois números, separados por uma barra, com espaços em
    /// volta de cada um admitidos.
    pub fn ler(texto: &str) -> Result<Parte, ErroDaParte> {
        let (k, n) = texto
            .split_once('/')
            .and_then(|(k, n)| Some((k.trim().parse().ok()?, n.trim().parse().ok()?)))
            .ok_or(ErroDaParte::Forma)?;
        Parte::nova(k, n).ok_or(ErroDaParte::Faixa)
    }

    /// Qual das partes: de 1 a [`Parte::n`].
    pub const fn k(self) -> usize {
        self.k
    }

    /// Em quantas partes a rodada se divide.
    pub const fn n(self) -> usize {
        self.n
    }

    /// Se o item de índice `i` é desta parte: `i % n == k - 1`.
    pub const fn tem(self, i: usize) -> bool {
        i % self.n == self.k - 1
    }

    /// Quantos dos índices `0..total` são desta parte: os da forma
    /// `k - 1 + j * n`.
    pub const fn quantos(self, total: usize) -> usize {
        if total < self.k {
            0
        } else {
            (total - self.k) / self.n + 1
        }
    }
}

impl fmt::Display for Parte {
    /// `k/n` — o mesmo texto que [`Parte::ler`] lê.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.k, self.n)
    }
}

/// Se o item de índice `i` roda numa rodada da `parte` — sem parte, todos.
pub fn na_parte(i: usize, parte: Option<Parte>) -> bool {
    parte.is_none_or(|p| p.tem(i))
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn cada_indice_cai_em_exatamente_uma_parte() {
        for n in 1..=12 {
            for i in 0..500 {
                let partes = (1..=n)
                    .filter(|&k| Parte::nova(k, n).unwrap().tem(i))
                    .count();
                assert_eq!(partes, 1, "o indice {i} em {n} partes");
            }
        }
        // Sem a parte, todos.
        assert!((0..500).all(|i| na_parte(i, None)));
    }

    #[test]
    fn a_uniao_das_partes_e_a_tabela_inteira_na_ordem_dela() {
        for total in [0, 1, 2, 7, 40, 41, 989, 1000] {
            for n in [1, 2, 3, 4, 7, 40, 1001] {
                let mut vistos = Vec::new();
                for k in 1..=n {
                    let p = Parte::nova(k, n).unwrap();
                    let fatia: Vec<usize> = (0..total).filter(|&i| na_parte(i, Some(p))).collect();
                    // A ordem dentro da parte é a da tabela.
                    assert!(fatia.windows(2).all(|w| w[0] < w[1]));
                    // O primeiro da parte é o índice k - 1, quando existe.
                    assert_eq!(fatia.first().copied(), (k - 1 < total).then_some(k - 1));
                    assert_eq!(fatia.len(), p.quantos(total), "{k}/{n} de {total}");
                    vistos.extend(fatia);
                }
                vistos.sort_unstable();
                assert_eq!(
                    vistos,
                    (0..total).collect::<Vec<_>>(),
                    "{n} partes de {total}"
                );
            }
        }
    }

    #[test]
    fn as_partes_saem_equilibradas() {
        for total in [989, 990, 60, 18, 20] {
            for n in 1..=8 {
                let tamanhos: Vec<usize> = (1..=n)
                    .map(|k| Parte::nova(k, n).unwrap().quantos(total))
                    .collect();
                let (menor, maior) = (
                    *tamanhos.iter().min().unwrap(),
                    *tamanhos.iter().max().unwrap(),
                );
                assert!(maior - menor <= 1, "{n} partes de {total}: {tamanhos:?}");
            }
        }
    }

    #[test]
    fn a_parte_se_le_e_se_escreve_igual() {
        assert_eq!(Parte::ler("1/2"), Ok(Parte::nova(1, 2).unwrap()));
        assert_eq!(Parte::ler("2/2"), Ok(Parte::nova(2, 2).unwrap()));
        assert_eq!(Parte::ler(" 1 / 1 "), Ok(Parte::nova(1, 1).unwrap()));
        assert_eq!(Parte::ler("40/40"), Ok(Parte::nova(40, 40).unwrap()));
        for k in 1..=9 {
            for n in k..=9 {
                let p = Parte::nova(k, n).unwrap();
                assert_eq!((p.k(), p.n()), (k, n));
                assert_eq!(Parte::ler(&p.to_string()), Ok(p));
            }
        }
    }

    #[test]
    fn a_parte_mal_escrita_e_recusada() {
        for ruim in [
            "", "1", "1/", "/2", "a/b", "1/2/3", "-1/2", "1 2", "1\\2", "1/2x",
        ] {
            assert_eq!(Parte::ler(ruim), Err(ErroDaParte::Forma), "{ruim}");
        }
        for fora in ["0/2", "3/2", "1/0", "0/0", "5/4"] {
            assert_eq!(Parte::ler(fora), Err(ErroDaParte::Faixa), "{fora}");
        }
        assert_eq!(Parte::nova(0, 1), None);
        assert_eq!(Parte::nova(2, 1), None);
        assert_eq!(Parte::nova(1, 0), None);
    }

    #[test]
    fn quantos_conta_os_da_parte() {
        let p = Parte::nova(3, 4).unwrap();
        // 2, 6, 10: os índices de 0..11 com i % 4 == 2.
        assert_eq!(p.quantos(11), 3);
        assert_eq!(p.quantos(10), 2);
        assert_eq!(p.quantos(3), 1);
        assert_eq!(p.quantos(2), 0);
        assert_eq!(p.quantos(0), 0);
        assert_eq!(Parte::nova(1, 1).unwrap().quantos(989), 989);
    }
}
