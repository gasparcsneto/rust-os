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

use spin::Mutex;

/// Quantas regiões de memória o kernel consegue registrar.
///
/// O QEMU x86 reporta ~10 e o `virt` do ARM reporta 1. Firmware UEFI real
/// costuma ficar abaixo de 40. 64 dá folga confortável.
const MAX_REGIOES: usize = 64;

/// Para que serve uma faixa de memória física.
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

/// Um framebuffer linear já configurado pelo firmware.
#[derive(Clone, Copy, Debug)]
pub struct Video {
    pub largura: u64,
    pub altura: u64,
    /// Pixels por linha, que pode exceder a largura visível por alinhamento.
    pub stride: u64,
    pub bytes_por_pixel: u64,
    pub formato: &'static str,
}

struct Maquina {
    regioes: [Regiao; MAX_REGIOES],
    n: usize,
    /// Regiões que não couberam em [`MAX_REGIOES`].
    descartadas: usize,
    video: Option<Video>,
}

static MAQUINA: Mutex<Maquina> = Mutex::new(Maquina {
    regioes: [Regiao::VAZIA; MAX_REGIOES],
    n: 0,
    descartadas: 0,
    video: None,
});

/// Registra uma região. Chamado pelo backend de arquitetura durante o boot.
pub fn adicionar_regiao(regiao: Regiao) {
    let mut m = MAQUINA.lock();
    if m.n < MAX_REGIOES {
        let n = m.n;
        m.regioes[n] = regiao;
        m.n = n + 1;
    } else {
        // Contamos em vez de ignorar em silêncio: um mapa truncado faria
        // `memory.stats` mentir, e um agente não tem como desconfiar de um
        // número que parece plausível.
        m.descartadas += 1;
    }
}

/// Registra o framebuffer, se a plataforma tiver um.
pub fn definir_video(video: Video) {
    MAQUINA.lock().video = Some(video);
}

/// Executa `f` para cada região registrada.
pub fn com_regioes<F: FnMut(&Regiao)>(mut f: F) {
    let m = MAQUINA.lock();
    for regiao in &m.regioes[..m.n] {
        f(regiao);
    }
}

/// Totais agregados: (bytes utilizáveis, bytes totais, número de regiões).
pub fn estatisticas() -> (u64, u64, usize) {
    let m = MAQUINA.lock();
    let mut utilizavel = 0;
    let mut total = 0;
    for regiao in &m.regioes[..m.n] {
        total += regiao.tamanho();
        if regiao.tipo == TipoRegiao::Utilizavel {
            utilizavel += regiao.tamanho();
        }
    }
    (utilizavel, total, m.n)
}

/// Quantas regiões foram descartadas por falta de espaço.
pub fn regioes_descartadas() -> usize {
    MAQUINA.lock().descartadas
}

pub fn video() -> Option<Video> {
    MAQUINA.lock().video
}
