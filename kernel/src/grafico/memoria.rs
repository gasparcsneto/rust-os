//! A memória de uma superfície: páginas próprias, fora do heap.
//!
//! # Por que não o heap
//!
//! Porque ele tem 1 MiB e uma tela inteira tem 4. O Redox não tem esse
//! problema — os drivers dele vivem em espaço de usuário e pedem memória com
//! `mmap` —, e este é o ponto em que o porte não pode ser literal: aqui a
//! superfície sai direto do alocador de frames, mapeada numa faixa virtual
//! reservada para isso em cada arquitetura
//! ([`crate::arch::BASE_DAS_SUPERFICIES`]).
//!
//! # Por que a reserva nunca anda para trás
//!
//! O mesmo arranjo de [`crate::mmio`]: um incremento, sem reaproveitar
//! endereço virtual. Serve enquanto superfícies nascerem poucas vezes — hoje,
//! a da tela e as da suíte. **Não** serve para um compositor que cria uma
//! superfície por janela: no ARM a faixa é uma entrada de topo, 1 GiB, e
//! telas de 4 MiB a esgotam depois de umas duzentas e cinquenta. O que acaba
//! é o espaço virtual, e não a memória — os frames voltam ao alocador no
//! `Drop`. Antes do compositor, a reserva precisa passar a devolver faixa.
//!
//! Esgotar não corrompe nada: a reserva recusa, e a criação da superfície
//! falha com um erro que diz o quê.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{BASE_DAS_SUPERFICIES, COBERTURA_DA_ENTRADA_DE_TOPO, Permissoes, TAMANHO_PAGINA};

/// O próximo endereço livre da faixa.
static PROXIMO: AtomicU64 = AtomicU64::new(BASE_DAS_SUPERFICIES);

/// Quantas superfícies estão vivas, e quantos bytes elas seguram.
///
/// Para o relatório do agente: é o número que diz se alguém está criando
/// superfícies e esquecendo de largá-las, antes de a memória acabar.
static VIVAS: AtomicU64 = AtomicU64::new(0);
static BYTES_VIVOS: AtomicU64 = AtomicU64::new(0);

/// Uma faixa de páginas mapeadas, que devolve os frames quando some.
pub struct Memoria {
    inicio: u64,
    paginas: u64,
}

impl Memoria {
    /// Reserva, mapeia e zera páginas que cubram `bytes`.
    ///
    /// Tudo ou nada: se o alocador de frames falhar no meio, as páginas já
    /// mapeadas são devolvidas antes de o erro subir. Uma superfície pela
    /// metade seria memória presa sem dono — o mesmo raciocínio do desfazer
    /// de [`crate::mmio::mapear`], e com um caso que o prova do mesmo jeito.
    pub fn nova(bytes: u64) -> Result<Memoria, &'static str> {
        let paginas = bytes.div_ceil(TAMANHO_PAGINA);
        if paginas == 0 {
            return Err("superficie de tamanho zero");
        }
        let inicio = reservar(paginas * TAMANHO_PAGINA)?;

        for indice in 0..paginas {
            let pagina = inicio + indice * TAMANHO_PAGINA;
            if let Err(motivo) = crate::paginacao::mapear_novo(pagina, Permissoes::DADOS) {
                for desfazer in 0..indice {
                    let pagina = inicio + desfazer * TAMANHO_PAGINA;
                    if let Err(porque) = crate::paginacao::desmapear_e_liberar(pagina) {
                        crate::log_error!(
                            "grafico",
                            "a pagina {:#x} ficou presa depois de uma superficie que falhou: {}",
                            pagina,
                            porque
                        );
                    }
                }
                return Err(motivo);
            }
        }

        VIVAS.fetch_add(1, Ordering::Relaxed);
        BYTES_VIVOS.fetch_add(paginas * TAMANHO_PAGINA, Ordering::Relaxed);
        Ok(Memoria { inicio, paginas })
    }

    /// O endereço virtual da primeira página.
    ///
    /// Hoje só a suíte pergunta, para montar uma tela sintética por cima.
    #[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
    pub fn inicio(&self) -> u64 {
        self.inicio
    }

    /// Quantos bytes estão mapeados — o pedido, arredondado para página.
    pub fn bytes(&self) -> u64 {
        self.paginas * TAMANHO_PAGINA
    }

    /// A memória como pixels de 32 bits.
    pub fn pixels(&self) -> &[u32] {
        // SAFETY: as páginas foram mapeadas por `nova`, são desta estrutura
        // enquanto ela viver, e o início é alinhado a página — logo a 32
        // bits. O comprimento cabe no que foi mapeado.
        unsafe { core::slice::from_raw_parts(self.inicio as *const u32, self.quantos_u32()) }
    }

    /// A memória como pixels de 32 bits, para escrever.
    pub fn pixels_mut(&mut self) -> &mut [u32] {
        // SAFETY: as de `pixels`, e o `&mut self` garante que não há outra
        // referência viva para a mesma faixa.
        unsafe { core::slice::from_raw_parts_mut(self.inicio as *mut u32, self.quantos_u32()) }
    }

    fn quantos_u32(&self) -> usize {
        (self.bytes() / 4) as usize
    }
}

impl Drop for Memoria {
    fn drop(&mut self) {
        for indice in 0..self.paginas {
            let pagina = self.inicio + indice * TAMANHO_PAGINA;
            if let Err(porque) = crate::paginacao::desmapear_e_liberar(pagina) {
                crate::log_error!(
                    "grafico",
                    "a pagina {:#x} de uma superficie nao voltou ao alocador: {}",
                    pagina,
                    porque
                );
            }
        }
        VIVAS.fetch_sub(1, Ordering::Relaxed);
        BYTES_VIVOS.fetch_sub(self.bytes(), Ordering::Relaxed);
    }
}

/// Onde a próxima superfície vai cair.
///
/// Só para a suíte: é o que permite a um caso saber que páginas conferir
/// depois de uma criação que falhou — o endereço reservado se perde junto
/// com o erro, e o incremento não anda para trás.
#[cfg(feature = "modo-teste")]
pub fn proximo() -> u64 {
    PROXIMO.load(Ordering::Acquire)
}

/// Quantas superfícies estão vivas, e quantos bytes elas seguram.
pub fn vivas() -> (u64, u64) {
    (
        VIVAS.load(Ordering::Relaxed),
        BYTES_VIVOS.load(Ordering::Relaxed),
    )
}

/// Reserva espaço virtual na faixa das superfícies.
///
/// O mesmo `try_update` de [`crate::mmio`], pelo mesmo motivo: a reserva
/// precisa ser atômica, e a alternativa seria uma tranca para proteger um
/// `u64`.
fn reservar(bytes: u64) -> Result<u64, &'static str> {
    let fim_da_faixa = BASE_DAS_SUPERFICIES + COBERTURA_DA_ENTRADA_DE_TOPO;
    PROXIMO
        .try_update(Ordering::AcqRel, Ordering::Acquire, |atual| {
            let fim = atual.checked_add(bytes)?;
            (fim <= fim_da_faixa).then_some(fim)
        })
        .map_err(|_| "a faixa das superficies se esgotou")
}
