//! O monte do processo: páginas pedidas ao kernel e repartidas aqui.
//!
//! # O desenho: o mesmo do kernel
//!
//! Uma lista de blocos livres que mora **dentro da própria memória livre** —
//! cada bloco guarda, nos primeiros bytes, o próprio tamanho e o próximo —,
//! ordenada por endereço, com fusão dos vizinhos ao liberar. É o desenho do
//! heap do kernel (`kernel/src/heap.rs`), e pela mesma razão: sem a fusão, um
//! monte sob uso normal se estilhaça em pedaços pequenos demais para qualquer
//! pedido, com memória livre de sobra.
//!
//! # De onde as páginas vêm
//!
//! De `mapear`, a partir do começo de [`protocolo::usuario::MAPEAVEL`] e
//! sempre para cima, de [`CRESCIMENTO`] em [`CRESCIMENTO`]. Quem guarda onde
//! o monte termina é este módulo, numa variável do processo: um `fork` a
//! copia junto com o resto da memória, e o filho continua do mesmo ponto; um
//! `exec` a joga fora junto com a imagem. O kernel não precisa saber.
//!
//! As páginas nunca voltam ao kernel. Um bloco liberado volta para a lista e
//! é reaproveitado; o monte só cresce quando nenhum bloco livre serve.
//!
//! # Tudo em múltiplos de 16
//!
//! Tamanhos e endereços de bloco são múltiplos de [`GRAO`], que é também o
//! tamanho do cabeçalho de um bloco livre. É o que garante que toda sobra —
//! o que fica antes de um bloco alinhado, ou depois do pedido — tenha pelo
//! menos um grão e caiba um cabeçalho: nenhuma sobra fica órfã.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;

use protocolo::usuario::MAPEAVEL;

/// A unidade de tamanho e de alinhamento dos blocos.
pub const GRAO: usize = 16;

/// Quanto o monte cresce de cada vez: 64 KiB, ou o pedido arredondado se
/// ele for maior. Crescer de página em página pagaria uma chamada de sistema
/// por página.
pub const CRESCIMENTO: u64 = 64 * 1024;

/// Até onde o monte vai: a primeira metade de `MAPEAVEL`. A segunda fica
/// para o que o processo mapear por conta própria — as superfícies do
/// compositor, na etapa em que elas chegarem.
pub const FIM_DO_MONTE: u64 = MAPEAVEL.0 + (MAPEAVEL.1 - MAPEAVEL.0) / 2;

/// Um bloco livre, no começo da própria memória.
#[repr(C)]
struct Livre {
    tamanho: usize,
    proximo: *mut Livre,
}

const _: () = assert!(core::mem::size_of::<Livre>() == GRAO);

struct Estado {
    /// O primeiro bloco livre, o de menor endereço.
    primeiro: *mut Livre,
    /// Onde o monte termina hoje: o próximo `mapear` começa aqui.
    fim: u64,
    /// Quantos bytes já foram pedidos ao kernel.
    mapeados: u64,
}

/// O monte, que o `alloc` do Rust usa por `#[global_allocator]`.
pub struct Monte(UnsafeCell<Estado>);

// SAFETY: um processo é um fluxo só — ver o cabeçalho do pacote. Ninguém
// mais entra no monte enquanto uma chamada está em curso.
unsafe impl Sync for Monte {}

#[global_allocator]
static MONTE: Monte = Monte(UnsafeCell::new(Estado {
    primeiro: ptr::null_mut(),
    fim: MAPEAVEL.0,
    mapeados: 0,
}));

/// Quantos bytes o monte já pediu ao kernel.
pub fn mapeados() -> u64 {
    // SAFETY: leitura de um campo, no único fluxo do processo.
    unsafe { (*MONTE.0.get()).mapeados }
}

const fn arredondar(valor: usize, multiplo: usize) -> usize {
    valor.div_ceil(multiplo) * multiplo
}

impl Estado {
    /// Devolve `[inicio, inicio + tamanho)` à lista, fundindo com os
    /// vizinhos.
    ///
    /// # Safety
    ///
    /// A faixa precisa ser do monte, alinhada a [`GRAO`], com tamanho
    /// múltiplo dele, e não estar na lista nem em uso.
    unsafe fn devolver(&mut self, inicio: usize, tamanho: usize) {
        // O vizinho de baixo e o de cima, na ordem dos endereços.
        let mut anterior: *mut Livre = ptr::null_mut();
        let mut seguinte = self.primeiro;
        while !seguinte.is_null() && (seguinte as usize) < inicio {
            anterior = seguinte;
            // SAFETY: todo bloco da lista é um `Livre` válido.
            seguinte = unsafe { (*seguinte).proximo };
        }

        let novo = inicio as *mut Livre;
        // SAFETY: a faixa é do monte, livre, e cabe um cabeçalho.
        unsafe {
            novo.write(Livre {
                tamanho,
                proximo: seguinte,
            });
        }

        // Funde com o de cima, se ele começa onde este termina.
        if !seguinte.is_null() && inicio + tamanho == seguinte as usize {
            // SAFETY: os dois são blocos da lista.
            unsafe {
                (*novo).tamanho += (*seguinte).tamanho;
                (*novo).proximo = (*seguinte).proximo;
            }
        }

        // E com o de baixo, se este começa onde ele termina.
        if anterior.is_null() {
            self.primeiro = novo;
        } else {
            // SAFETY: `anterior` é bloco da lista, e `novo` acabou de ser
            // escrito.
            unsafe {
                if anterior as usize + (*anterior).tamanho == inicio {
                    (*anterior).tamanho += (*novo).tamanho;
                    (*anterior).proximo = (*novo).proximo;
                } else {
                    (*anterior).proximo = novo;
                }
            }
        }
    }

    /// Tira da lista um pedaço de `tamanho` bytes alinhado a `alinhamento`.
    unsafe fn tirar(&mut self, tamanho: usize, alinhamento: usize) -> *mut u8 {
        let mut anterior: *mut Livre = ptr::null_mut();
        let mut atual = self.primeiro;
        while !atual.is_null() {
            let inicio = atual as usize;
            // SAFETY: `atual` é bloco da lista.
            let (disponivel, proximo) = unsafe { ((*atual).tamanho, (*atual).proximo) };
            let alinhado = arredondar(inicio, alinhamento);
            let antes = alinhado - inicio;
            if antes + tamanho <= disponivel {
                // Tira o bloco inteiro da lista e devolve as sobras dos dois
                // lados. As duas são múltiplos de `GRAO` — ver o cabeçalho —,
                // então cabem.
                if anterior.is_null() {
                    self.primeiro = proximo;
                } else {
                    // SAFETY: `anterior` é bloco da lista.
                    unsafe { (*anterior).proximo = proximo };
                }
                let depois = disponivel - antes - tamanho;
                // SAFETY: as sobras são pedaços do bloco que acabou de sair.
                unsafe {
                    if antes > 0 {
                        self.devolver(inicio, antes);
                    }
                    if depois > 0 {
                        self.devolver(alinhado + tamanho, depois);
                    }
                }
                return alinhado as *mut u8;
            }
            anterior = atual;
            atual = proximo;
        }
        ptr::null_mut()
    }

    /// Pede ao kernel páginas para um pedido de `tamanho` alinhado a
    /// `alinhamento`, e as põe na lista. Falso se o kernel recusou ou se o
    /// monte chegou ao fim.
    unsafe fn crescer(&mut self, tamanho: usize, alinhamento: usize) -> bool {
        let pedido = (tamanho + alinhamento) as u64;
        let bytes = pedido.div_ceil(CRESCIMENTO) * CRESCIMENTO;
        if self.fim + bytes > FIM_DO_MONTE {
            return false;
        }
        if crate::sistema::mapear(self.fim, bytes) != 0 {
            return false;
        }
        let inicio = self.fim as usize;
        self.fim += bytes;
        self.mapeados += bytes;
        // SAFETY: as páginas acabaram de ser mapeadas, são do monte e não
        // estão na lista.
        unsafe { self.devolver(inicio, bytes as usize) };
        true
    }
}

// SAFETY: os blocos entregues são alinhados como o `Layout` pede, têm pelo
// menos o tamanho pedido e não se sobrepõem — a lista só guarda o que não
// está entregue.
unsafe impl GlobalAlloc for Monte {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let tamanho = arredondar(layout.size().max(1), GRAO);
        let alinhamento = layout.align().max(GRAO);
        // SAFETY: um fluxo só — ver o `Sync` acima.
        let estado = unsafe { &mut *self.0.get() };
        // SAFETY: tamanho e alinhamento são múltiplos de `GRAO`.
        unsafe {
            let bloco = estado.tirar(tamanho, alinhamento);
            if !bloco.is_null() {
                return bloco;
            }
            if !estado.crescer(tamanho, alinhamento) {
                return ptr::null_mut();
            }
            estado.tirar(tamanho, alinhamento)
        }
    }

    unsafe fn dealloc(&self, bloco: *mut u8, layout: Layout) {
        let tamanho = arredondar(layout.size().max(1), GRAO);
        // SAFETY: um fluxo só; o bloco saiu de `alloc` com este `Layout`, e
        // é o mesmo arredondamento de lá.
        unsafe { (*self.0.get()).devolver(bloco as usize, tamanho) };
    }
}
