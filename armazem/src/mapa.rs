//! O mapa dos blocos da área de dados: quais estão em uso.
//!
//! Não vai para o disco: o boot o refaz dos metadados — um bloco está em
//! uso se algum arquivo o tem ([`crate::Armazem::blocos_em_uso`]). Em
//! memória, o kernel ainda **reserva** blocos para o que está escrevendo e
//! ainda não gravou — um rascunho, o conteúdo de um lote —, e os solta
//! quando o lote grava (e os blocos passam a ser de um arquivo) ou não
//! grava.
//!
//! # Por que um bloco reservado nunca é de outro
//!
//! O conteúdo novo vai sempre para blocos livres, nunca por cima do que um
//! arquivo tem: um lote que cai no meio deixa no disco o conteúdo velho
//! intacto, e o que ele escreveu fica em blocos que, no boot seguinte,
//! nenhum metadado aponta — livres de novo.

use alloc::vec::Vec;

use crate::Faixas;

/// O mapa: um bit por bloco, ligado quando o bloco está em uso.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapa {
    palavras: Vec<u64>,
    total: u64,
    livres: u64,
    /// Onde a próxima procura começa: os blocos são dados em volta, e não
    /// sempre do começo.
    cursor: u64,
}

impl Mapa {
    /// Um mapa de `total` blocos, todos livres.
    pub fn novo(total: u64) -> Mapa {
        Mapa {
            palavras: alloc::vec![0; total.div_ceil(64) as usize],
            total,
            livres: total,
            cursor: 0,
        }
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn livres(&self) -> u64 {
        self.livres
    }

    fn usado(&self, b: u64) -> bool {
        self.palavras[(b / 64) as usize] & (1 << (b % 64)) != 0
    }

    fn por(&mut self, b: u64, usado: bool) {
        let p = &mut self.palavras[(b / 64) as usize];
        if usado {
            *p |= 1 << (b % 64);
        } else {
            *p &= !(1 << (b % 64));
        }
    }

    /// Marca `[de, ate)` como em uso. Recusa — sem marcar nada — uma faixa
    /// fora do mapa, ou com um bloco já em uso: dois arquivos no mesmo
    /// bloco é um volume que não se explica.
    pub fn marcar(&mut self, de: u64, ate: u64) -> Result<(), &'static str> {
        if de > ate || ate > self.total {
            return Err("faixa de blocos fora do volume");
        }
        if (de..ate).any(|b| self.usado(b)) {
            return Err("bloco em uso por dois");
        }
        for b in de..ate {
            self.por(b, true);
        }
        self.livres -= ate - de;
        Ok(())
    }

    /// Solta `[de, ate)`. Um bloco que já estava livre é erro de quem
    /// chama, e nada muda.
    pub fn soltar(&mut self, de: u64, ate: u64) -> Result<(), &'static str> {
        if de > ate || ate > self.total {
            return Err("faixa de blocos fora do volume");
        }
        if (de..ate).any(|b| !self.usado(b)) {
            return Err("bloco solto que nao estava em uso");
        }
        for b in de..ate {
            self.por(b, false);
        }
        self.livres += ate - de;
        Ok(())
    }

    /// Solta as faixas — as que um lote deixou de usar.
    pub fn soltar_faixas(&mut self, faixas: &Faixas) -> Result<(), &'static str> {
        for &(de, ate) in faixas {
            self.soltar(de, ate)?;
        }
        Ok(())
    }

    /// Reserva `n` blocos, em até `mais` faixas, e os devolve como faixas.
    /// A primeira escolha é uma faixa só; depois, as maiores que houver a
    /// partir do cursor. `None` — e nada reservado — se não cabem.
    pub fn reservar(&mut self, n: u64, mais: usize) -> Option<Faixas> {
        if n == 0 {
            return Some(Vec::new());
        }
        if n > self.livres || mais == 0 {
            return None;
        }
        // Uma faixa só, do cursor em volta.
        if let Some(inicio) = self.procurar_contigua(n) {
            self.marcar(inicio, inicio + n).ok()?;
            self.cursor = (inicio + n) % self.total.max(1);
            return Some(alloc::vec![(inicio, inicio + n)]);
        }
        // Em pedaços: as faixas livres na ordem em que aparecem.
        let mut faixas: Faixas = Vec::new();
        let mut falta = n;
        let mut b = 0u64;
        while b < self.total && falta > 0 {
            if self.usado(b) {
                b += 1;
                continue;
            }
            let inicio = b;
            while b < self.total && !self.usado(b) && b - inicio < falta {
                b += 1;
            }
            faixas.push((inicio, b));
            falta -= b - inicio;
        }
        if falta > 0 || faixas.len() > mais {
            return None;
        }
        for &(de, ate) in &faixas {
            self.marcar(de, ate).ok()?;
        }
        Some(faixas)
    }

    fn procurar_contigua(&self, n: u64) -> Option<u64> {
        let total = self.total;
        let mut corrida = 0u64;
        let mut inicio = 0u64;
        // Do cursor ao fim, e do começo ao cursor: uma volta.
        for passo in 0..total {
            let b = (self.cursor + passo) % total;
            if b == 0 {
                corrida = 0;
            }
            if self.usado(b) {
                corrida = 0;
                continue;
            }
            if corrida == 0 {
                inicio = b;
            }
            corrida += 1;
            if corrida == n {
                return Some(inicio);
            }
        }
        None
    }

    /// Os blocos em uso, contados de novo — para conferir a conta.
    pub fn contar_usados(&self) -> u64 {
        self.palavras
            .iter()
            .map(|p| u64::from(p.count_ones()))
            .sum()
    }
}
