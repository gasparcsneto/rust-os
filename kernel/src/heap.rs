//! O heap do kernel: alocador de memória dinâmica.
//!
//! # O que isto destrava
//!
//! Até aqui o kernel inteiro foi escrito sem alocação dinâmica — buffers de
//! tamanho fixo, listas estáticas, serialização em streaming. Isso foi uma
//! necessidade, não uma escolha estética: sem heap não existem `Box`, `Vec`
//! nem `String`.
//!
//! Com este módulo, a `alloc` passa a funcionar, e com ela boa parte do
//! vocabulário normal do Rust.
//!
//! # O desenho: lista livre ordenada, com fusão
//!
//! Os blocos livres formam uma lista encadeada que mora **dentro da própria
//! memória livre** — cada região disponível guarda, nos seus primeiros bytes,
//! o próprio tamanho e o ponteiro para a próxima. Custo de metadados: zero
//! bytes fora do heap.
//!
//! A decisão que importa é manter a lista **ordenada por endereço**. Inserir
//! na frente seria mais rápido, mas impediria o passo que realmente conta:
//! ao liberar um bloco, verificar se os vizinhos imediatos também estão
//! livres e fundir os três num só.
//!
//! Sem essa fusão, um heap sob uso normal se estilhaça. Um ciclo de alocar e
//! liberar blocos de tamanhos variados vai quebrando as regiões em pedaços
//! cada vez menores, e chega um ponto em que há memória livre de sobra mas
//! nenhum pedaço contíguo grande o bastante — o alocador falha com o heap
//! quase vazio. Liberar fica mais lento por causa da busca ordenada; é o
//! preço, e vale.
//!
//! # A regra que evita vazamento silencioso
//!
//! Quando um bloco é maior que o pedido, a sobra volta para a lista. Mas uma
//! sobra menor que um nó da lista **não tem como ser registrada** — não
//! caberia o próprio descritor. Nesses casos a região inteira é recusada e a
//! busca continua. Aceitar e "esquecer" os bytes excedentes seria um
//! vazamento silencioso que cresce com o tempo.

use core::alloc::{GlobalAlloc, Layout};
use core::mem;
use core::ptr;

use spin::Mutex;

use crate::arch::{Permissoes, TAMANHO_PAGINA};

/// Onde o heap vive no espaço virtual.
///
/// O endereço vem da arquitetura porque as duas resolvem o mesmo problema de
/// jeitos diferentes: no x86 o heap precisa estar na metade alta, para não
/// dividir uma entrada de topo de 512 GiB com o espaço do usuário; no ARM as
/// entradas de topo cobrem 1 GiB cada, e 64 GiB já é uma entrada só dele. Ver
/// o mapa em `arch::x86_64` e `arch::aarch64`.
pub const HEAP_INICIO: usize = crate::arch::BASE_DO_HEAP as usize;

/// Tamanho do heap. 1 MiB é folgado para o que o kernel faz hoje e barato
/// diante dos 128 MiB da máquina.
pub const HEAP_TAMANHO: usize = 1024 * 1024;

/// Um bloco livre.
///
/// Mora dentro da memória que descreve, então `tamanho` conta os bytes da
/// região inteira — inclusive os ocupados por este próprio cabeçalho.
#[repr(C)]
struct No {
    tamanho: usize,
    proximo: *mut No,
}

const TAMANHO_NO: usize = mem::size_of::<No>();
const ALINHAMENTO_NO: usize = mem::align_of::<No>();

struct Estado {
    /// Primeiro bloco livre, ou nulo. A lista é ordenada por endereço.
    primeiro: *mut No,
    total: usize,
    alocado: usize,
    alocacoes: u64,
    liberacoes: u64,
    /// Pedidos que não puderam ser atendidos.
    falhas: u64,
}

// SAFETY: o ponteiro cru aponta para dentro do heap do kernel e só é tocado
// com o `Mutex` travado e interrupções mascaradas.
unsafe impl Send for Estado {}

impl Estado {
    const VAZIO: Self = Self {
        primeiro: ptr::null_mut(),
        total: 0,
        alocado: 0,
        alocacoes: 0,
        liberacoes: 0,
        falhas: 0,
    };

    /// Devolve uma região à lista, fundindo com vizinhos adjacentes.
    ///
    /// # Safety
    ///
    /// A região `[endereco, endereco + tamanho)` precisa estar dentro do heap,
    /// não pertencer a mais ninguém, caber um [`No`] e estar alinhada para
    /// um.
    unsafe fn inserir(&mut self, endereco: usize, tamanho: usize) {
        debug_assert!(tamanho >= TAMANHO_NO);
        debug_assert_eq!(endereco % ALINHAMENTO_NO, 0);

        // SAFETY: percorremos a lista, cujos nós são todos válidos.
        unsafe {
            // Procura a posição que mantém a ordem por endereço.
            let mut anterior: *mut No = ptr::null_mut();
            let mut seguinte: *mut No = self.primeiro;
            while !seguinte.is_null() && (seguinte as usize) < endereco {
                anterior = seguinte;
                seguinte = (*seguinte).proximo;
            }

            // Escreve o descritor dentro da própria região liberada.
            let no = endereco as *mut No;
            no.write(No {
                tamanho,
                proximo: seguinte,
            });

            if anterior.is_null() {
                self.primeiro = no;
            } else {
                (*anterior).proximo = no;
            }

            // Fusão com o vizinho da direita, se forem encostados.
            if !seguinte.is_null() && endereco + tamanho == seguinte as usize {
                (*no).tamanho += (*seguinte).tamanho;
                (*no).proximo = (*seguinte).proximo;
            }

            // Fusão com o vizinho da esquerda. Feita depois da direita de
            // propósito: assim três blocos adjacentes viram um só numa
            // passada.
            if !anterior.is_null() && anterior as usize + (*anterior).tamanho == endereco {
                (*anterior).tamanho += (*no).tamanho;
                (*anterior).proximo = (*no).proximo;
            }
        }
    }

    /// Retira da lista uma região que comporte o pedido, devolvendo o endereço
    /// já alinhado.
    ///
    /// Primeiro ajuste (*first fit*): devolve a primeira região que serve. É
    /// mais rápido que procurar a que sobra menos, e com a fusão ativa a
    /// diferença em fragmentação é pequena.
    ///
    /// # Safety
    ///
    /// A lista precisa estar consistente.
    unsafe fn retirar(&mut self, tamanho: usize, alinhamento: usize) -> Option<usize> {
        // SAFETY: percorremos a lista, cujos nós são todos válidos.
        unsafe {
            let mut anterior: *mut No = ptr::null_mut();
            let mut atual: *mut No = self.primeiro;

            while !atual.is_null() {
                let inicio = atual as usize;
                let fim = inicio + (*atual).tamanho;
                let inicio_alinhado = alinhar_acima(inicio, alinhamento);

                // O alinhamento pode empurrar o início para além do fim da
                // região; `checked_add` também cobre o estouro.
                if let Some(fim_alocacao) = inicio_alinhado.checked_add(tamanho)
                    && fim_alocacao <= fim
                {
                    let antes = inicio_alinhado - inicio;
                    let depois = fim - fim_alocacao;

                    // Uma sobra menor que um nó não caberia o próprio
                    // descritor e se perderia. Recusamos a região inteira em
                    // vez de vazar os bytes.
                    let sobras_registraveis = (antes == 0 || antes >= TAMANHO_NO)
                        && (depois == 0 || depois >= TAMANHO_NO);

                    if sobras_registraveis {
                        // Retira o nó da lista antes de mexer na memória dele.
                        let proximo = (*atual).proximo;
                        if anterior.is_null() {
                            self.primeiro = proximo;
                        } else {
                            (*anterior).proximo = proximo;
                        }

                        if antes > 0 {
                            self.inserir(inicio, antes);
                        }
                        if depois > 0 {
                            self.inserir(fim_alocacao, depois);
                        }

                        return Some(inicio_alinhado);
                    }
                }

                anterior = atual;
                atual = (*atual).proximo;
            }

            None
        }
    }
}

/// Arredonda para cima até o próximo múltiplo do alinhamento.
///
/// `alinhamento` precisa ser potência de dois, o que [`Layout`] garante.
const fn alinhar_acima(valor: usize, alinhamento: usize) -> usize {
    (valor + alinhamento - 1) & !(alinhamento - 1)
}

/// Ajusta um [`Layout`] para que o bloco alocado também sirva de nó da lista.
///
/// Isto não é detalhe: o bloco vai ser liberado um dia, e nessa hora
/// precisamos escrever um [`No`] dentro dele. Se fosse menor que um nó, ou
/// desalinhado para um, a escrita invadiria memória vizinha.
fn ajustar(layout: Layout) -> Option<(usize, usize)> {
    let layout = layout.align_to(ALINHAMENTO_NO).ok()?.pad_to_align();
    Some((layout.size().max(TAMANHO_NO), layout.align()))
}

/// O alocador global do kernel.
pub struct Alocador {
    estado: Mutex<Estado>,
}

// SAFETY: as duas operações mantêm a invariante central do trait — uma região
// entregue por `alloc` sai da lista livre e só volta por `dealloc`, então o
// mesmo bloco nunca é entregue duas vezes. A exclusão mútua é garantida pelo
// `Mutex` com interrupções mascaradas.
unsafe impl GlobalAlloc for Alocador {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some((tamanho, alinhamento)) = ajustar(layout) else {
            return ptr::null_mut();
        };

        // Mascarar interrupções é obrigatório: um handler que alocasse
        // enquanto o código interrompido segura este `Mutex` giraria para
        // sempre — spinlocks não são reentrantes.
        crate::arch::sem_interrupcoes(|| {
            let mut estado = self.estado.lock();

            // SAFETY: a trava garante acesso exclusivo à lista.
            match unsafe { estado.retirar(tamanho, alinhamento) } {
                Some(endereco) => {
                    estado.alocado += tamanho;
                    estado.alocacoes += 1;
                    endereco as *mut u8
                }
                None => {
                    // O contrato do trait manda sinalizar falha com ponteiro
                    // nulo, nunca com pânico: quem chama é o compilador, e um
                    // pânico aqui seria terminal.
                    estado.falhas += 1;
                    ptr::null_mut()
                }
            }
        })
    }

    unsafe fn dealloc(&self, ponteiro: *mut u8, layout: Layout) {
        let Some((tamanho, _)) = ajustar(layout) else {
            return;
        };

        crate::arch::sem_interrupcoes(|| {
            let mut estado = self.estado.lock();

            // SAFETY: o contrato de `dealloc` garante que o ponteiro veio de
            // `alloc` com este mesmo layout, então a região tem o tamanho e o
            // alinhamento que `inserir` exige.
            unsafe { estado.inserir(ponteiro as usize, tamanho) };

            estado.alocado = estado.alocado.saturating_sub(tamanho);
            estado.liberacoes += 1;
        })
    }
}

#[global_allocator]
static ALOCADOR: Alocador = Alocador {
    estado: Mutex::new(Estado::VAZIO),
};

/// Chama o alocador diretamente, sem passar pelas funções de [`alloc`].
///
/// Existe para os testes, e por uma razão concreta: as funções de
/// `alloc::alloc` carregam atributos que marcam-nas como alocador, e o LLVM
/// tem permissão para **eliminar** um par alocar/liberar cujo resultado só é
/// comparado com nulo — assumindo, ao eliminá-lo, que a alocação teve
/// sucesso. Em modo release isso fazia um teste do caminho de falha passar a
/// medir o otimizador em vez do alocador.
///
/// [`alloc`]: alloc
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn tentar_alocar(layout: Layout) -> *mut u8 {
    // SAFETY: repassamos o layout tal como veio; o contrato de tamanho
    // não-zero é do chamador, como em `GlobalAlloc::alloc`.
    unsafe { ALOCADOR.alloc(layout) }
}

/// Contraparte de [`tentar_alocar`].
///
/// # Safety
///
/// `ponteiro` precisa ter vindo de [`tentar_alocar`] com este mesmo `layout`.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub unsafe fn devolver(ponteiro: *mut u8, layout: Layout) {
    // SAFETY: delegada ao chamador pelo contrato acima.
    unsafe { ALOCADOR.dealloc(ponteiro, layout) }
}

/// Mapeia a faixa do heap e a entrega ao alocador.
///
/// Precisa rodar depois da paginação e antes de qualquer alocação.
pub fn init() -> Result<(), &'static str> {
    let paginas = HEAP_TAMANHO / TAMANHO_PAGINA as usize;

    for indice in 0..paginas {
        let virtual_ = HEAP_INICIO + indice * TAMANHO_PAGINA as usize;
        // `mapear_novo` tira o frame do alocador e o zera, então o heap nasce
        // com memória que não pertence a mais ninguém.
        crate::paginacao::mapear_novo(virtual_ as u64, Permissoes::DADOS)?;
    }

    crate::arch::sem_interrupcoes(|| {
        let mut estado = ALOCADOR.estado.lock();
        estado.total = HEAP_TAMANHO;
        // SAFETY: a faixa acabou de ser mapeada, pertence só a nós, e o início
        // do heap é alinhado em página — portanto também para um `No`.
        unsafe { estado.inserir(HEAP_INICIO, HEAP_TAMANHO) };
    });

    crate::log_info!(
        "heap",
        "{} KiB em {:#x}, {} paginas mapeadas",
        HEAP_TAMANHO / 1024,
        HEAP_INICIO,
        paginas
    );

    Ok(())
}

/// Retrato do heap num instante.
#[derive(Clone, Copy, Debug)]
pub struct Estatisticas {
    pub total: usize,
    pub alocado: usize,
    pub livre: usize,
    pub blocos_livres: usize,
    /// O maior bloco contíguo disponível.
    ///
    /// É a medida honesta de fragmentação: quando ele fica muito menor que
    /// `livre`, há memória de sobra mas nenhuma peça grande o bastante.
    pub maior_bloco: usize,
    pub alocacoes: u64,
    pub liberacoes: u64,
    pub falhas: u64,
}

pub fn estatisticas() -> Estatisticas {
    crate::arch::sem_interrupcoes(|| {
        let estado = ALOCADOR.estado.lock();

        let mut livre = 0usize;
        let mut blocos = 0usize;
        let mut maior = 0usize;

        // SAFETY: a trava garante que a lista não muda durante a travessia.
        unsafe {
            let mut atual = estado.primeiro;
            while !atual.is_null() {
                livre += (*atual).tamanho;
                maior = maior.max((*atual).tamanho);
                blocos += 1;
                atual = (*atual).proximo;
            }
        }

        Estatisticas {
            total: estado.total,
            alocado: estado.alocado,
            livre,
            blocos_livres: blocos,
            maior_bloco: maior,
            alocacoes: estado.alocacoes,
            liberacoes: estado.liberacoes,
            falhas: estado.falhas,
        }
    })
}

/// Destrava o alocador à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { ALOCADOR.estado.force_unlock() };
}
