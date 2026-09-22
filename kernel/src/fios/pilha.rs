//! Pilhas de fio de execução, com guard page.
//!
//! # Por que não alocar no heap
//!
//! Um `Box<[u8]>` seria uma linha de código. E seria a decisão errada.
//!
//! Multitarefa preemptiva significa que um fio pode ser interrompido em
//! qualquer instrução, inclusive no meio de uma recursão funda. Se a pilha
//! dele for um bloco do heap, estourá-la não produz falha nenhuma: produz uma
//! escrita silenciosa no bloco vizinho, que pertence a outra estrutura. O
//! sintoma aparece longe da causa, em outro subsistema, e não há como
//! rastrear.
//!
//! Mapeando a pilha em páginas próprias, com uma página **não mapeada** logo
//! abaixo, o estouro vira uma falha de página no instante em que acontece —
//! com o endereço exato no relatório. É a mesma proteção que o kernel já tem
//! para a própria pilha nas duas arquiteturas; aqui ela passa a valer por fio.
//!
//! # O mapa
//!
//! ```text
//!   BASE + n*TAMANHO_DA_VAGA  ┌──────────────┐
//!                             │  guard page  │  não mapeada
//!                             ├──────────────┤
//!                             │              │
//!                             │    pilha     │  cresce para baixo
//!                             │              │
//!                             └──────────────┘ ← topo
//! ```

use crate::arch::{Permissoes, TAMANHO_PAGINA};

/// Onde começa a área reservada às pilhas de fio.
///
/// Vem da arquitetura pelo mesmo motivo de [`crate::heap::HEAP_INICIO`]: cada
/// região do kernel precisa de uma entrada de topo só dela, para que montar
/// uma tabela de tradução por processo seja copiar entradas de topo. Ver o
/// mapa em `arch::x86_64` e `arch::aarch64`.
pub(crate) const BASE: u64 = crate::arch::BASE_DAS_PILHAS;

/// Espaço virtual reservado por fio, guard page incluída.
const TAMANHO_DA_VAGA: u64 = 64 * 1024;

/// Quanto desse espaço é pilha de verdade.
pub const TAMANHO_DA_PILHA: u64 = TAMANHO_DA_VAGA - TAMANHO_PAGINA;

/// Uma pilha mapeada, identificada pela vaga que ocupa.
pub struct Pilha {
    vaga: usize,
    topo: u64,
}

impl Pilha {
    /// O endereço inicial do ponteiro de pilha, já alinhado.
    ///
    /// As duas arquiteturas exigem alinhamento de 16 bytes no ponto de
    /// chamada; o ARM chega a gerar exceção de alinhamento de SP se ele
    /// estiver torto.
    pub fn topo(&self) -> u64 {
        self.topo
    }
}

/// Mapeia uma pilha nova na vaga indicada.
///
/// A guard page não é "desmapeada": ela simplesmente nunca é mapeada, que é
/// mais forte — não há janela entre criar e proteger.
pub fn reservar(vaga: usize) -> Result<Pilha, &'static str> {
    let inicio_da_vaga = BASE + vaga as u64 * TAMANHO_DA_VAGA;
    let primeira_pagina = inicio_da_vaga + TAMANHO_PAGINA;
    let topo = inicio_da_vaga + TAMANHO_DA_VAGA;

    let mut mapeadas = 0u64;
    let mut endereco = primeira_pagina;
    while endereco < topo {
        if let Err(motivo) = crate::paginacao::mapear_novo(endereco, Permissoes::DADOS) {
            // Desfazemos o que já foi mapeado antes de desistir. Sem isto, uma
            // falha no meio deixaria páginas órfãs: mapeadas, contabilizadas
            // como usadas, e sem ninguém que soubesse liberá-las.
            liberar_paginas(primeira_pagina, mapeadas);
            return Err(motivo);
        }
        mapeadas += 1;
        endereco += TAMANHO_PAGINA;
    }

    Ok(Pilha { vaga, topo })
}

impl Drop for Pilha {
    fn drop(&mut self) {
        let primeira_pagina = BASE + self.vaga as u64 * TAMANHO_DA_VAGA + TAMANHO_PAGINA;
        liberar_paginas(primeira_pagina, TAMANHO_DA_PILHA / TAMANHO_PAGINA);
    }
}

fn liberar_paginas(primeira: u64, quantas: u64) {
    for i in 0..quantas {
        let endereco = primeira + i * TAMANHO_PAGINA;
        if let Err(motivo) = crate::paginacao::desmapear_e_liberar(endereco) {
            // Não há a quem propagar: estamos num `Drop`. Registrar é o que
            // impede que um vazamento de página vire um mistério silencioso.
            crate::log_error!("fios", "pilha em {:#x} nao voltou: {}", endereco, motivo);
        }
    }
}
