//! Alocador de frames de memória física.
//!
//! # O que é um frame
//!
//! A unidade de memória física que o hardware de paginação manipula: 4 KiB
//! alinhados. Enquanto a paginação decide *onde* a memória aparece no espaço
//! de endereçamento virtual, este módulo decide *qual* pedaço de RAM física
//! está livre para ser usado.
//!
//! É a camada mais baixa da gerência de memória. Tudo que vier depois —
//! tabelas de página, heap, pilhas de processo — pede frames daqui.
//!
//! # Por que um bitmap
//!
//! Um bit por frame: ligado significa livre. As alternativas seriam uma lista
//! encadeada de frames livres (que precisa de espaço *dentro* dos frames, e
//! portanto exige que eles estejam mapeados para serem manipulados) ou um
//! alocador que nunca libera (simples, mas inútil assim que houver processos).
//!
//! O bitmap custa 1 bit por 4 KiB, ou seja, 32 KiB para cobrir 1 GiB. É
//! estático e de tamanho fixo, o que significa que nunca falha por falta de
//! espaço para se gerenciar — propriedade que vale muito na camada mais baixa
//! do sistema.
//!
//! # O que fica de fora
//!
//! Três coisas nunca podem ser entregues:
//!
//! 1. Memória que o firmware marcou como reservada.
//! 2. A própria imagem do kernel, incluindo sua pilha.
//! 3. O frame do endereço zero, para que desreferenciar um ponteiro nulo
//!    continue falhando em vez de corromper dados de verdade.
//!
//! Quem sabe sobre (2) é cada arquitetura, e por motivos diferentes — ver
//! [`crate::arch::reservar_faixas`].

use spin::Mutex;

// Toda tomada de `ALOCADOR` abaixo passa por `sem_interrupcoes`, e a partir da
// fase 1 isso deixou de ser zelo e virou requisito. Com o escalonador
// preemptivo, o timer pode trocar de fio de execução em qualquer instrução: um
// fio preemptado segurando esta trava faria o próximo que pedisse um frame
// girar para sempre, porque um spinlock não é reentrante e só o dono o solta.
// Mascarar interrupções desliga a preempção junto, que é o que torna a seção
// crítica de fato crítica.

/// Tamanho de um frame. 4 KiB é o granulado nativo das duas arquiteturas.
pub const TAMANHO_FRAME: u64 = 4096;

/// Quantos frames o bitmap rastreia: 1 GiB de cobertura.
///
/// Memória além disso é ignorada com um aviso. Preferimos um limite explícito
/// e um bitmap estático a uma estrutura dinâmica que precisaria de um alocador
/// para existir — o que seria circular, já que somos nós o alocador de base.
const MAX_FRAMES: usize = 1 << 18;

const PALAVRAS: usize = MAX_FRAMES / 64;

struct Alocador {
    /// Bit ligado = frame livre. Índice relativo a [`Alocador::base`].
    bitmap: [u64; PALAVRAS],
    /// Endereço físico correspondente ao bit 0.
    base: u64,
    /// Quantos frames estão de fato sob gerência.
    rastreados: usize,
    livres: usize,
    /// Por onde começar a próxima busca.
    ///
    /// Sem esta dica, alocar N frames seria O(N²): cada busca recomeçaria do
    /// zero e percorreria tudo que já foi entregue.
    dica: usize,
    inicializado: bool,
}

static ALOCADOR: Mutex<Alocador> = Mutex::new(Alocador {
    bitmap: [0; PALAVRAS],
    base: 0,
    rastreados: 0,
    livres: 0,
    dica: 0,
    inicializado: false,
});

/// Executa `f` com acesso exclusivo ao alocador.
///
/// Concentrar a tomada da trava num lugar só é o que torna a invariante
/// estrutural em vez de uma regra que cada chamador precisa lembrar: não há
/// como acessar o alocador sem passar por aqui, e aqui a preempção está
/// desligada.
fn com_alocador<R>(f: impl FnOnce(&mut Alocador) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut ALOCADOR.lock()))
}

impl Alocador {
    /// Marca um frame como livre, se estiver dentro da janela rastreada.
    fn liberar_indice(&mut self, indice: usize) {
        if indice >= self.rastreados {
            return;
        }
        let palavra = indice / 64;
        let bit = 1u64 << (indice % 64);
        if self.bitmap[palavra] & bit == 0 {
            self.bitmap[palavra] |= bit;
            self.livres += 1;
        }
    }

    /// Marca um frame como ocupado.
    fn ocupar_indice(&mut self, indice: usize) {
        if indice >= self.rastreados {
            return;
        }
        let palavra = indice / 64;
        let bit = 1u64 << (indice % 64);
        if self.bitmap[palavra] & bit != 0 {
            self.bitmap[palavra] &= !bit;
            self.livres -= 1;
        }
    }

    /// Converte um endereço físico no índice do frame que o contém.
    fn indice_de(&self, endereco: u64) -> Option<usize> {
        if endereco < self.base {
            return None;
        }
        let indice = ((endereco - self.base) / TAMANHO_FRAME) as usize;
        (indice < self.rastreados).then_some(indice)
    }
}

/// Descobre a memória disponível e monta o bitmap.
///
/// Chame uma vez, depois que [`crate::machine`] estiver preenchido.
pub fn init() {
    let mut menor = u64::MAX;
    let mut maior = 0u64;

    crate::machine::com_regioes(|regiao| {
        if regiao.tipo == crate::machine::TipoRegiao::Utilizavel {
            menor = menor.min(regiao.inicio);
            maior = maior.max(regiao.fim);
        }
    });

    if menor == u64::MAX {
        crate::log_error!("frames", "nenhuma regiao utilizavel; alocador inerte");
        return;
    }

    let base = menor & !(TAMANHO_FRAME - 1);
    let necessarios = ((maior - base) / TAMANHO_FRAME) as usize;
    let rastreados = necessarios.min(MAX_FRAMES);

    com_alocador(|a| {
        a.base = base;
        a.rastreados = rastreados;
        a.livres = 0;
        a.dica = 0;
        // O bitmap começa todo zerado, ou seja, tudo ocupado. Liberamos
        // explicitamente só o que o firmware garantiu ser utilizável — é a
        // política segura: esquecer de liberar desperdiça memória, esquecer de
        // reservar corrompe o sistema.
        a.bitmap = [0; PALAVRAS];
        a.inicializado = true;
    });

    crate::machine::com_regioes(|regiao| {
        if regiao.tipo != crate::machine::TipoRegiao::Utilizavel {
            return;
        }
        // Arredondamos para dentro: um frame só é considerado livre se estiver
        // *inteiramente* dentro da região. Um frame parcialmente reservado
        // entregue como livre seria corrupção garantida.
        let primeiro = regiao.inicio.div_ceil(TAMANHO_FRAME);
        let ultimo = regiao.fim / TAMANHO_FRAME;

        com_alocador(|a| {
            for frame in primeiro..ultimo {
                let endereco = frame * TAMANHO_FRAME;
                if let Some(indice) = a.indice_de(endereco) {
                    a.liberar_indice(indice);
                }
            }
        });
    });

    // Cada arquitetura sabe de coisas diferentes que não podem ser entregues.
    crate::arch::reservar_faixas(reservar);

    // O frame do endereço zero nunca é entregue, para que desreferenciar um
    // ponteiro nulo continue produzindo uma falha diagnosticável em vez de
    // corromper dados legítimos.
    reservar(0, TAMANHO_FRAME);

    let (livres, total) = estatisticas();
    crate::log_info!(
        "frames",
        "{} de {} frames livres ({} MiB), base {:#x}",
        livres,
        total,
        livres as u64 * TAMANHO_FRAME / 1024 / 1024,
        base
    );

    if necessarios > MAX_FRAMES {
        crate::log_warn!(
            "frames",
            "memoria alem de {} MiB ignorada pelo bitmap",
            MAX_FRAMES as u64 * TAMANHO_FRAME / 1024 / 1024
        );
    }
}

/// Retira da circulação todos os frames que tocam a faixa `[inicio, fim)`.
///
/// Arredonda para fora de propósito: se qualquer byte de um frame estiver
/// dentro da faixa, o frame inteiro é reservado. O oposto — entregar um frame
/// parcialmente reservado — corromperia o que estivesse ali.
pub fn reservar(inicio: u64, fim: u64) {
    if fim <= inicio {
        return;
    }
    let primeiro = inicio / TAMANHO_FRAME;
    let ultimo = fim.div_ceil(TAMANHO_FRAME);

    com_alocador(|a| {
        for frame in primeiro..ultimo {
            let endereco = frame * TAMANHO_FRAME;
            if let Some(indice) = a.indice_de(endereco) {
                a.ocupar_indice(indice);
            }
        }
    });
}

/// Entrega um frame livre, ou `None` se a memória acabou.
///
/// O endereço devolvido é físico e alinhado em [`TAMANHO_FRAME`]. O conteúdo
/// é indefinido: quem pedir um frame para uma tabela de página precisa zerá-lo
/// antes de usar, porque lixo interpretado como descritor é caos.
// Hoje o único consumidor fora dos testes ainda não existe: quem vai pedir
// frames de verdade é a paginação, que precisa deles para as tabelas de
// tradução. Até lá a anotação mantém o build limpo sem esconder código morto
// de verdade — quando a paginação chegar, ela some.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn alocar() -> Option<u64> {
    com_alocador(|a| {
        if !a.inicializado || a.livres == 0 {
            return None;
        }

        let palavras = a.rastreados.div_ceil(64);

        // Duas passadas: da dica até o fim, depois do início até a dica. Assim a
        // busca é amortizada mesmo quando a memória livre está fragmentada no
        // começo do bitmap.
        for tentativa in 0..2 {
            let (de, ate) = if tentativa == 0 {
                (a.dica, palavras)
            } else {
                (0, a.dica.min(palavras))
            };

            for palavra in de..ate {
                if a.bitmap[palavra] == 0 {
                    continue;
                }
                let bit = a.bitmap[palavra].trailing_zeros() as usize;
                let indice = palavra * 64 + bit;
                if indice >= a.rastreados {
                    continue;
                }

                a.ocupar_indice(indice);
                a.dica = palavra;
                return Some(a.base + indice as u64 * TAMANHO_FRAME);
            }
        }

        None
    })
}

/// Devolve um frame ao alocador.
///
/// Liberar um frame que não estava alocado é tratado como no-op em vez de
/// pânico: num kernel, um erro de contabilidade não deve derrubar o sistema
/// se houver como seguir com segurança.
// Hoje o único consumidor fora dos testes ainda não existe: quem vai pedir
// frames de verdade é a paginação, que precisa deles para as tabelas de
// tradução. Até lá a anotação mantém o build limpo sem esconder código morto
// de verdade — quando a paginação chegar, ela some.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn liberar(endereco: u64) {
    com_alocador(|a| {
        if let Some(indice) = a.indice_de(endereco) {
            a.liberar_indice(indice);
            // Buscar a partir daqui aproveita a localidade: quem libera
            // costuma voltar a alocar logo em seguida.
            a.dica = indice / 64;
        }
    });
}

/// `(frames livres, frames rastreados)`.
pub fn estatisticas() -> (usize, usize) {
    com_alocador(|a| (a.livres, a.rastreados))
}

/// Endereço físico coberto pelo primeiro frame rastreado.
pub fn base() -> u64 {
    com_alocador(|a| a.base)
}

/// O frame que contém este endereço está livre?
///
/// Existe para os testes: permite verificar que faixas reservadas — a imagem
/// do kernel, o frame nulo — realmente não estão na circulação.
// Hoje o único consumidor fora dos testes ainda não existe: quem vai pedir
// frames de verdade é a paginação, que precisa deles para as tabelas de
// tradução. Até lá a anotação mantém o build limpo sem esconder código morto
// de verdade — quando a paginação chegar, ela some.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn esta_livre(endereco: u64) -> bool {
    com_alocador(|a| match a.indice_de(endereco) {
        Some(indice) => a.bitmap[indice / 64] & (1u64 << (indice % 64)) != 0,
        None => false,
    })
}
