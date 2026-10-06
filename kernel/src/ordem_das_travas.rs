//! A ordem das travas, conferida enquanto a suíte roda.
//!
//! # O que isto confere
//!
//! Que nenhum par de travas do kernel é tomado nas duas ordens: se em algum
//! lugar se toma `A` e, com ela na mão, `B`, em nenhum outro lugar se toma
//! `B` e, com ela na mão, `A` — nem por um caminho mais longo, `B` → `C` →
//! `A`. Duas ordens são um impasse esperando dois núcleos chegarem ao mesmo
//! tempo, e a suíte, que roda num emulador com poucos núcleos, quase nunca
//! os faz chegar; a ordem, ela mostra na primeira vez que cada caminho
//! roda, com um núcleo só que seja.
//!
//! # Como
//!
//! Cada trava é uma **classe**, pelo endereço — as do kernel são estáticas,
//! e o endereço é o nome. Cada núcleo guarda a pilha das que tem na mão:
//! uma trava do kernel é tomada com as interrupções mascaradas e solta antes
//! de o fio ceder o núcleo, então o que um núcleo tem na mão é o que o código
//! que roda nele tem. Ao pedir `B` com `A` na mão, a aresta `A → B` entra no
//! grafo; se `B` já alcança `A` pelo grafo, a aresta fecharia um ciclo, e a
//! inversão é registrada — com onde cada uma das duas foi tomada pela
//! primeira vez e onde o ciclo se fechou.
//!
//! A ordem das gravações do journal ([`crate::persistencia::em_ordem`]) é
//! uma trava também, de outra espécie: é do fio, e não do núcleo — quem a
//! tem cede a CPU e volta, até em outro núcleo. Ela entra no grafo como a
//! classe [`ORDEM`]: o fio que a tem e pede uma trava acrescenta
//! `ORDEM → trava`; quem a pede com uma trava na mão acrescenta
//! `trava → ORDEM`, e as duas juntas são o ciclo.
//!
//! O `try_lock` não acrescenta aresta: ele não espera, e não há impasse sem
//! espera. Mas a trava que ele toma vai para a pilha, e o que se pedir com
//! ela na mão acrescenta as arestas dela.
//!
//! # O que não confere
//!
//! Travas de duas instâncias do mesmo tipo são classes diferentes: tomar
//! duas portas na ordem `1, 2` num lugar e `2, 1` noutro é um ciclo que o
//! grafo vê; dois objetos do heap que nascem no mesmo endereço, um depois
//! do outro, seriam a mesma classe — o kernel não tem travas assim no heap
//! que se tomem juntas.
//!
//! Só na compilação da suíte (`modo-teste`): o custo é uma busca por trava
//! tomada, e o kernel de verdade não paga por uma conferência cujo
//! resultado só a suíte lê. O caso `travas: nenhuma inversao de ordem`,
//! o último, falha a suíte com a primeira inversão que aparecer — em
//! qualquer caso, em qualquer arquitetura e número de núcleos.

use core::panic::Location;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU16, AtomicU64, AtomicUsize, Ordering};

use crate::nucleos::MAX_NUCLEOS;

/// Quantas classes cabem. O kernel tem perto de cem travas.
const CLASSES: usize = 512;
const PALAVRAS: usize = CLASSES / 64;
/// Quantas travas um núcleo tem na mão ao mesmo tempo, no máximo conferido.
const PROFUNDIDADE: usize = 24;
/// Uma vaga vazia na pilha.
const NENHUMA: u16 = u16::MAX;

/// O endereço de cada classe; zero é vaga livre.
static ENDERECOS: [AtomicUsize; CLASSES] = [const { AtomicUsize::new(0) }; CLASSES];
/// Onde cada classe foi pedida pela primeira vez.
static ONDE: [AtomicPtr<Location<'static>>; CLASSES] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; CLASSES];
/// `ARESTAS[a]` tem o bit `b`: `a` já esteve na mão quando `b` foi pedida.
static ARESTAS: [[AtomicU64; PALAVRAS]; CLASSES] =
    [const { [const { AtomicU64::new(0) }; PALAVRAS] }; CLASSES];

/// O que cada núcleo tem na mão.
static NA_MAO: [[AtomicU16; PROFUNDIDADE]; MAX_NUCLEOS] =
    [const { [const { AtomicU16::new(NENHUMA) }; PROFUNDIDADE] }; MAX_NUCLEOS];
static ALTURA: [AtomicUsize; MAX_NUCLEOS] = [const { AtomicUsize::new(0) }; MAX_NUCLEOS];

/// O grafo muda com esta na mão. Não é uma [`crate::trava::Mutex`] — ela
/// seria conferida por aqui —, e é tomada só com as interrupções
/// mascaradas.
static OCUPADO: AtomicBool = AtomicBool::new(false);

/// Quantas inversões apareceram, e a primeira.
static INVERSOES: AtomicU64 = AtomicU64::new(0);
static PRIMEIRA_DE: AtomicUsize = AtomicUsize::new(usize::MAX);
static PRIMEIRA_PARA: AtomicUsize = AtomicUsize::new(usize::MAX);
static PRIMEIRA_ONDE: AtomicPtr<Location<'static>> = AtomicPtr::new(core::ptr::null_mut());

/// O que a conferência não pôde ver: classes além da tabela, pilhas além
/// da altura, travas soltas num núcleo que não as tinha.
static FORA_DA_TABELA: AtomicU64 = AtomicU64::new(0);
static FORA_DA_PILHA: AtomicU64 = AtomicU64::new(0);
static SOLTAS_DE_FORA: AtomicU64 = AtomicU64::new(0);

/// Depois do caminho fatal, que destrava tudo à força, a conferência não
/// sabe mais quem tem o quê.
static DESLIGADA: AtomicBool = AtomicBool::new(false);

/// A classe da ordem das gravações do journal: o endereço é o desta
/// estática, que nenhuma trava tem.
pub static ORDEM: u8 = 0;

fn endereco_da_ordem() -> usize {
    &ORDEM as *const u8 as usize
}

/// A vaga da classe de `endereco`, criando-a se `onde` é dado.
fn classe(endereco: usize, onde: Option<&'static Location<'static>>) -> Option<usize> {
    let mut i = (endereco >> 3).wrapping_mul(0x9E37_79B9_7F4A_7C15) % CLASSES;
    for _ in 0..CLASSES {
        let atual = ENDERECOS[i].load(Ordering::Acquire);
        if atual == endereco {
            return Some(i);
        }
        if atual == 0 {
            let onde = onde?;
            match ENDERECOS[i].compare_exchange(0, endereco, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    ONDE[i].store(onde as *const _ as *mut _, Ordering::Release);
                    return Some(i);
                }
                Err(outro) if outro == endereco => return Some(i),
                Err(_) => {}
            }
        }
        i = (i + 1) % CLASSES;
    }
    FORA_DA_TABELA.fetch_add(1, Ordering::Relaxed);
    None
}

fn tem_aresta(de: usize, para: usize) -> bool {
    ARESTAS[de][para / 64].load(Ordering::Acquire) & (1 << (para % 64)) != 0
}

/// `de` alcança `para` pelo grafo? Com [`OCUPADO`] na mão.
fn alcanca(de: usize, para: usize) -> bool {
    let mut visto = [0u64; PALAVRAS];
    let mut pilha = [0u16; CLASSES];
    let mut topo = 0usize;
    pilha[0] = de as u16;
    topo += 1;
    visto[de / 64] |= 1 << (de % 64);
    while topo > 0 {
        topo -= 1;
        let v = pilha[topo] as usize;
        if v == para {
            return true;
        }
        for p in 0..PALAVRAS {
            let mut novos = ARESTAS[v][p].load(Ordering::Acquire) & !visto[p];
            visto[p] |= novos;
            while novos != 0 {
                let b = novos.trailing_zeros() as usize;
                novos &= novos - 1;
                pilha[topo] = (p * 64 + b) as u16;
                topo += 1;
            }
        }
    }
    false
}

/// Acrescenta `de → para`, se ainda não está. Uma aresta que fecharia um
/// ciclo é a inversão: registrada, e não acrescentada — o grafo continua
/// sem ciclo, e a próxima inversão diferente também aparece.
fn acrescentar(de: usize, para: usize, onde: &'static Location<'static>) {
    if tem_aresta(de, para) {
        return;
    }
    while OCUPADO
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    if !tem_aresta(de, para) {
        if de == para || alcanca(para, de) {
            if INVERSOES.fetch_add(1, Ordering::AcqRel) == 0 {
                PRIMEIRA_DE.store(de, Ordering::Release);
                PRIMEIRA_PARA.store(para, Ordering::Release);
                PRIMEIRA_ONDE.store(onde as *const _ as *mut _, Ordering::Release);
            }
        } else {
            ARESTAS[de][para / 64].fetch_or(1 << (para % 64), Ordering::AcqRel);
        }
    }
    OCUPADO.store(false, Ordering::Release);
}

/// A classe de uma trava, guardada na própria trava depois da primeira vez:
/// a busca pelo endereço é feita uma vez por trava, e não a cada `lock`.
fn classe_em(
    endereco: usize,
    guardada: &AtomicU16,
    onde: &'static Location<'static>,
) -> Option<usize> {
    let c = guardada.load(Ordering::Relaxed);
    if c != NENHUMA {
        return Some(c as usize);
    }
    let c = classe(endereco, Some(onde))?;
    guardada.store(c as u16, Ordering::Relaxed);
    Some(c)
}

/// A classe da ordem das gravações, guardada como a das travas.
static CLASSE_DA_ORDEM: AtomicU16 = AtomicU16::new(NENHUMA);

/// Roda `f` com as interrupções mascaradas — e não as mascara de novo se já
/// estão: quase toda trava é tomada assim, e salvar e restaurar o estado a
/// cada gancho custaria, no emulador, o que um caso de tempo mede.
fn mascarado<R>(f: impl FnOnce() -> R) -> R {
    if crate::arch::interrupcoes_habilitadas() {
        crate::arch::sem_interrupcoes(f)
    } else {
        f()
    }
}

/// As classes na mão deste núcleo, e a da ordem se o fio a tem.
fn com_o_que_esta_na_mao(mut f: impl FnMut(usize)) {
    let n = crate::nucleos::atual();
    let altura = ALTURA[n].load(Ordering::Relaxed).min(PROFUNDIDADE);
    for vaga in &NA_MAO[n][..altura] {
        let c = vaga.load(Ordering::Relaxed);
        if c != NENHUMA {
            f(c as usize);
        }
    }
    if crate::persistencia::ordem_na_mao_sem_trava()
        && let Some(c) = classe_em(endereco_da_ordem(), &CLASSE_DA_ORDEM, Location::caller())
    {
        f(c);
    }
}

/// Uma trava em `endereco` vai ser pedida, com espera. `guardada` é onde
/// a trava guarda a classe dela.
#[track_caller]
pub fn ao_pedir(endereco: usize, guardada: &AtomicU16) {
    if DESLIGADA.load(Ordering::Relaxed) {
        return;
    }
    let onde = Location::caller();
    mascarado(|| {
        let Some(c) = classe_em(endereco, guardada, onde) else {
            return;
        };
        com_o_que_esta_na_mao(|h| acrescentar(h, c, onde));
    });
}

/// Uma trava em `endereco` foi tomada: vai para a pilha deste núcleo.
#[track_caller]
pub fn ao_tomar(endereco: usize, guardada: &AtomicU16) {
    if DESLIGADA.load(Ordering::Relaxed) {
        return;
    }
    let onde = Location::caller();
    mascarado(|| {
        let Some(c) = classe_em(endereco, guardada, onde) else {
            return;
        };
        let n = crate::nucleos::atual();
        let altura = ALTURA[n].load(Ordering::Relaxed);
        if altura < PROFUNDIDADE {
            NA_MAO[n][altura].store(c as u16, Ordering::Relaxed);
        } else {
            FORA_DA_PILHA.fetch_add(1, Ordering::Relaxed);
        }
        ALTURA[n].store(altura + 1, Ordering::Relaxed);
    });
}

/// A trava foi solta: sai da pilha deste núcleo.
pub fn ao_soltar(guardada: &AtomicU16) {
    if DESLIGADA.load(Ordering::Relaxed) {
        return;
    }
    mascarado(|| {
        let n = crate::nucleos::atual();
        let altura = ALTURA[n].load(Ordering::Relaxed);
        if altura == 0 {
            SOLTAS_DE_FORA.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if altura > PROFUNDIDADE {
            // A que sai pode ser uma das que não couberam; a conta basta.
            ALTURA[n].store(altura - 1, Ordering::Relaxed);
            return;
        }
        let c = guardada.load(Ordering::Relaxed);
        if c == NENHUMA {
            ALTURA[n].store(altura - 1, Ordering::Relaxed);
            return;
        }
        let c = c as usize;
        // De cima para baixo: quase sempre a última tomada é a que sai.
        let pilha = &NA_MAO[n][..altura];
        let Some(i) = pilha
            .iter()
            .rposition(|v| v.load(Ordering::Relaxed) == c as u16)
        else {
            SOLTAS_DE_FORA.fetch_add(1, Ordering::Relaxed);
            return;
        };
        for j in i..altura - 1 {
            NA_MAO[n][j].store(NA_MAO[n][j + 1].load(Ordering::Relaxed), Ordering::Relaxed);
        }
        NA_MAO[n][altura - 1].store(NENHUMA, Ordering::Relaxed);
        ALTURA[n].store(altura - 1, Ordering::Relaxed);
    });
}

/// A ordem das gravações vai ser pedida por quem não a tem.
#[track_caller]
pub fn ao_pedir_a_ordem() {
    ao_pedir(endereco_da_ordem(), &CLASSE_DA_ORDEM);
}

/// O caminho fatal destravou tudo à força: daqui em diante a conferência
/// não sabe quem tem o quê, e para.
pub fn desligar() {
    DESLIGADA.store(true, Ordering::Release);
}

/// Uma inversão: as duas classes, onde cada uma foi pedida pela primeira
/// vez, e onde o ciclo se fechou.
pub struct Inversao {
    pub de: &'static Location<'static>,
    pub para: &'static Location<'static>,
    pub onde: &'static Location<'static>,
}

fn onde_de(c: usize) -> &'static Location<'static> {
    let p = ONDE
        .get(c)
        .map_or(core::ptr::null_mut(), |o| o.load(Ordering::Acquire));
    if p.is_null() {
        Location::caller()
    } else {
        // SAFETY: só se guardam aqui referências `'static` de
        // `Location::caller`.
        unsafe { &*p }
    }
}

/// Quantas inversões apareceram, e a primeira.
pub fn inversoes() -> (u64, Option<Inversao>) {
    let n = INVERSOES.load(Ordering::Acquire);
    if n == 0 {
        return (0, None);
    }
    let onde = PRIMEIRA_ONDE.load(Ordering::Acquire);
    let onde = if onde.is_null() {
        Location::caller()
    } else {
        // SAFETY: idem.
        unsafe { &*onde }
    };
    (
        n,
        Some(Inversao {
            de: onde_de(PRIMEIRA_DE.load(Ordering::Acquire)),
            para: onde_de(PRIMEIRA_PARA.load(Ordering::Acquire)),
            onde,
        }),
    )
}

/// O que a conferência não viu: classes fora da tabela, travas além da
/// altura da pilha, e solturas de uma trava que o núcleo não tinha — a
/// última é uma guarda que mudou de núcleo, uma trava levada através de
/// uma troca de fio.
pub fn pontos_cegos() -> (u64, u64, u64) {
    (
        FORA_DA_TABELA.load(Ordering::Relaxed),
        FORA_DA_PILHA.load(Ordering::Relaxed),
        SOLTAS_DE_FORA.load(Ordering::Relaxed),
    )
}

/// Quantas classes a conferência conhece, e quantas arestas.
pub fn tamanho() -> (usize, u32) {
    let classes = ENDERECOS
        .iter()
        .filter(|e| e.load(Ordering::Relaxed) != 0)
        .count();
    let arestas = ARESTAS
        .iter()
        .flat_map(|l| l.iter())
        .map(|p| p.load(Ordering::Relaxed).count_ones())
        .sum();
    (classes, arestas)
}

/// Roda `f`, que inverte de propósito, e devolve quantas inversões ela
/// fez — sem que contem para o caso final. Só a suíte, para provar que a
/// conferência vê.
pub fn com_inversoes_esperadas(f: impl FnOnce()) -> u64 {
    let antes = INVERSOES.swap(0, Ordering::AcqRel);
    let (de, para, onde) = (
        PRIMEIRA_DE.load(Ordering::Acquire),
        PRIMEIRA_PARA.load(Ordering::Acquire),
        PRIMEIRA_ONDE.load(Ordering::Acquire),
    );
    f();
    let feitas = INVERSOES.swap(antes, Ordering::AcqRel);
    PRIMEIRA_DE.store(de, Ordering::Release);
    PRIMEIRA_PARA.store(para, Ordering::Release);
    PRIMEIRA_ONDE.store(onde, Ordering::Release);
    feitas
}
