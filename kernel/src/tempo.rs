//! Contagem de tempo desde o boot.
//!
//! # Por que isto importa tanto
//!
//! Até agora o kernel não tinha qualquer noção de tempo. Os registros de log
//! traziam um número de sequência, que diz *ordem* mas não diz *quando* nem
//! *quanto tempo* separou dois eventos. Para um agente tentando entender se o
//! sistema travou ou apenas está lento, é a diferença entre diagnosticar e
//! adivinhar.
//!
//! Com um timer periódico gerando interrupções, passamos a ter um relógio:
//! cada interrupção incrementa o contador, e a frequência configurada permite
//! convertê-lo em milissegundos.
//!
//! # Por que atômicos e não `Mutex`
//!
//! O incremento acontece dentro do handler de interrupção do timer, que pode
//! preemptar qualquer código em qualquer ponto — inclusive código que já
//! segure um spinlock. Um `Mutex` aqui seria um deadlock esperando acontecer.
//! Operações atômicas não travam nada e são exatamente o que este caso pede.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static TICKS: AtomicU64 = AtomicU64::new(0);
static FREQUENCIA_HZ: AtomicU32 = AtomicU32::new(0);

/// Informa a frequência com que o timer foi programado.
///
/// Chamado pelo backend de arquitetura ao configurar o timer. Sem isto, os
/// ticks são apenas um contador sem unidade.
pub fn registrar_frequencia(hz: u32) {
    FREQUENCIA_HZ.store(hz, Ordering::Relaxed);
}

/// Incrementa o contador. Chamado pelo handler do timer.
///
/// `Relaxed` basta: não estamos sincronizando acesso a nenhum outro dado,
/// apenas contando. Uma ordenação mais forte custaria barreiras sem nos dar
/// garantia nenhuma que importe.
pub fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);

    // Acorda quem pediu para ser avisado quando o tempo passasse. Fica aqui,
    // e não nos handlers de cada arquitetura, porque a contagem do tempo já é
    // o ponto neutro por onde as duas passam.
    crate::tarefas::relogio::tique();

    // E puxa o que estiver parado na serial do agente, uma vez a cada tique.
    //
    // # Por que um kernel que tem interrupção de recepção precisa disto
    //
    // Porque a interrupção pode se perder, e no ARM ela se perde de um jeito
    // que não volta sozinho. `coletar` drena no máximo um teto de bytes por
    // interrupção; num despejo grande o hospedeiro realimenta a FIFO enquanto
    // drenamos, o teto é atingido com ela ainda cheia, e a causa de recepção
    // **já foi reconhecida** na entrada. A PL011 só a levanta de novo quando a
    // FIFO cruza o nível de gatilho, o que exige esvaziá-la antes. Ninguém
    // esvazia, e o canal morre em silêncio.
    //
    // Medido, despejando vinte mil bytes pelo canal do agente no ARM: depois
    // de algumas rodadas o canal parava de responder e não voltava, com o
    // kernel **ocioso** — zero tiques de CPU em cinco segundos, e as
    // interrupções de relógio entrando e voltando ao mesmo `wfi`. O x86 não
    // sofria: o 16550 do QEMU recalcula a causa por nível.
    //
    // Dá para apertar o teto do `coletar`, e vale; mas a raiz é depender de um
    // único caminho para uma coisa que não pode falhar. Uma puxada por tique
    // custa dois testes de registrador a cem hertz e transforma "o canal
    // morreu" em "o canal teve dez milissegundos de latência".
    crate::tarefas::entrada::coletar();
}

/// Quantas interrupções de timer ocorreram desde o boot.
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// A frequência configurada do timer, ou zero se ainda não há timer.
pub fn frequencia_hz() -> u32 {
    FREQUENCIA_HZ.load(Ordering::Relaxed)
}

/// Tempo desde o boot em milissegundos.
///
/// Devolve zero enquanto não houver timer configurado — o que é honesto: é
/// melhor que o agente veja um zero evidente do que um número inventado.
pub fn uptime_ms() -> u64 {
    let hz = frequencia_hz() as u64;
    if hz == 0 {
        return 0;
    }
    // Multiplicamos antes de dividir para não perder precisão: com hz=100,
    // dividir primeiro descartaria toda a parte fracionária.
    ticks().saturating_mul(1000) / hz
}
