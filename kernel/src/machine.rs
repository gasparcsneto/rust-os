//! Descrição da máquina, independente de arquitetura.
//!
//! # O problema que este módulo resolve
//!
//! No x86_64 o mapa de memória chega pronto, numa struct `BootInfo` que o
//! bootloader monta. No aarch64 não existe bootloader equivalente: o QEMU nos
//! entrega um ponteiro para um *device tree* e cabe a nós interpretá-lo.
//!
//! Se o resto do kernel conhecesse essas diferenças, cada subsistema teria
//! dois caminhos e o custo de adicionar uma terceira arquitetura seria
//! proporcional ao tamanho do kernel. Em vez disso, cada backend de
//! arquitetura traduz o que recebeu para as estruturas *deste* módulo durante
//! o boot, e a partir daí o kernel inteiro fala uma língua só.
//!
//! # Por que copiamos para um array fixo
//!
//! No x86 poderíamos apenas emprestar a fatia do `BootInfo`, que é `'static`.
//! No ARM os dados saem de um parser e não sobrevivem por si. Copiar para um
//! array estático unifica os dois casos e, de quebra, torna o mapa imune a
//! qualquer reaproveitamento futuro da memória onde o bootloader o colocou.
//!
//! # O que **não** está aqui
//!
//! O framebuffer. Ele foi descrito neste módulo por um tempo, e mudou para
//! [`crate::tela`] por uma razão concreta: a descrição da máquina vive atrás
//! de um `Mutex`, e a tela precisa ser alcançável de dentro de um handler de
//! exceção fatal — que é justamente onde alguém pode estar segurando aquela
//! trava. A geometria acompanhou os pixels para não haver duas cópias dela.

use spin::Mutex;

/// Quantas regiões de memória o kernel consegue registrar.
///
/// O QEMU x86 reporta ~10 e o `virt` do ARM reporta 1. Firmware UEFI real
/// costuma ficar abaixo de 40. 64 dá folga confortável.
const MAX_REGIOES: usize = 64;

/// Para que serve uma faixa de memória física.
//
// `Bootloader` e `Reservada` só são construídas pelo backend x86, porque é o
// único que hoje recebe um mapa com essa distinção — no ARM o device tree
// descreve a RAM instalada sem dizer o que já está ocupado. As variantes
// pertencem à abstração, não a uma arquitetura, então ficam aqui; a anotação
// evita que o build de ARM as acuse de mortas.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TipoRegiao {
    /// Livre para o kernel alocar.
    Utilizavel,
    /// Em uso pelo bootloader ou pelas suas estruturas.
    Bootloader,
    /// Reservada por firmware/hardware (MMIO, ACPI, ROM).
    Reservada,
    Desconhecida,
}

impl TipoRegiao {
    /// Nome exposto no protocolo do agente.
    pub const fn nome(self) -> &'static str {
        match self {
            TipoRegiao::Utilizavel => "usable",
            TipoRegiao::Bootloader => "bootloader",
            TipoRegiao::Reservada => "reserved",
            TipoRegiao::Desconhecida => "unknown",
        }
    }
}

/// Uma faixa contígua de memória física.
#[derive(Clone, Copy, Debug)]
pub struct Regiao {
    pub inicio: u64,
    /// Exclusivo: a região vai de `inicio` até `fim - 1`.
    pub fim: u64,
    pub tipo: TipoRegiao,
}

impl Regiao {
    const VAZIA: Self = Self {
        inicio: 0,
        fim: 0,
        tipo: TipoRegiao::Desconhecida,
    };

    pub const fn tamanho(&self) -> u64 {
        self.fim - self.inicio
    }
}

struct Maquina {
    regioes: [Regiao; MAX_REGIOES],
    n: usize,
    /// Regiões que não couberam em [`MAX_REGIOES`].
    descartadas: usize,
}

/// Executa `f` com acesso exclusivo à descrição da máquina.
///
/// Como em [`crate::frames`], a trava é tomada com a preempção desligada. Com
/// o escalonador preemptivo, um fio de execução interrompido segurando este
/// `Mutex` faria o próximo que consultasse o mapa girar para sempre.
fn com_maquina<R>(f: impl FnOnce(&mut Maquina) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut MAQUINA.lock()))
}

static MAQUINA: Mutex<Maquina> = Mutex::new(Maquina {
    regioes: [Regiao::VAZIA; MAX_REGIOES],
    n: 0,
    descartadas: 0,
});

/// Registra uma região. Chamado pelo backend de arquitetura durante o boot.
///
/// Regiões degeneradas — as de tamanho zero, e as em que a soma
/// `inicio + tamanho` transbordou na origem — são descartadas aqui, e não
/// mais adiante. O motivo é que elas envenenam todo consumidor a jusante:
/// o alocador de frames calcularia uma janela sem sentido, e a montagem do
/// mapa de identidade no ARM faz `fim - 1` para achar o último bloco, o que
/// numa região com `fim == 0` entra em *underflow* — pânico em debug e, em
/// release, um índice gigante que mapearia meio espaço de endereços como RAM.
///
/// Filtrar na entrada é o único ponto em que a checagem vale por todos: é por
/// aqui que passam as regiões das duas arquiteturas.
pub fn adicionar_regiao(regiao: Regiao) {
    com_maquina(|m| {
        if regiao.fim <= regiao.inicio || m.n >= MAX_REGIOES {
            // Contamos em vez de ignorar em silêncio: um mapa truncado faria
            // `memory.stats` mentir, e um agente não tem como desconfiar de um
            // número que parece plausível.
            m.descartadas += 1;
            return;
        }
        let n = m.n;
        m.regioes[n] = regiao;
        m.n = n + 1;
    });
}

/// Executa `f` para cada região registrada.
pub fn com_regioes<F: FnMut(&Regiao)>(mut f: F) {
    com_maquina(|m| {
        for regiao in &m.regioes[..m.n] {
            f(regiao);
        }
    });
}

/// Totais agregados: (bytes utilizáveis, bytes totais, número de regiões).
pub fn estatisticas() -> (u64, u64, usize) {
    com_maquina(|m| {
        let mut utilizavel = 0;
        let mut total = 0;
        for regiao in &m.regioes[..m.n] {
            total += regiao.tamanho();
            if regiao.tipo == TipoRegiao::Utilizavel {
                utilizavel += regiao.tamanho();
            }
        }
        (utilizavel, total, m.n)
    })
}

/// Quantas regiões foram descartadas por falta de espaço.
pub fn regioes_descartadas() -> usize {
    com_maquina(|m| m.descartadas)
}
