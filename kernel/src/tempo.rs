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

use crate::nucleos::MAX_NUCLEOS;

static TICKS: AtomicU64 = AtomicU64::new(0);

/// O relógio que cada núcleo viu no próprio tique anterior.
static VISTO: [AtomicU64; MAX_NUCLEOS] = [const { AtomicU64::new(u64::MAX) }; MAX_NUCLEOS];
static FREQUENCIA_HZ: AtomicU32 = AtomicU32::new(0);

/// Informa a frequência com que o timer foi programado.
///
/// Chamado pelo backend de arquitetura ao configurar o timer. Sem isto, os
/// ticks são apenas um contador sem unidade.
pub fn registrar_frequencia(hz: u32) {
    FREQUENCIA_HZ.store(hz, Ordering::Relaxed);
}

/// Um tique do timer deste núcleo. Chamado pelo handler do timer de
/// **todo** núcleo.
///
/// O relógio anda aqui, e o trabalho dos dispositivos se faz aqui — mas só
/// no núcleo dos dispositivos ([`crate::nucleos::NUCLEO_DOS_DISPOSITIVOS`]).
pub fn tick() {
    avancar();
    if crate::nucleos::e_o_dos_dispositivos() {
        trabalho_dos_dispositivos();
    }
}

/// Oferece o tique deste núcleo ao relógio.
///
/// # Uma vez por período, por qualquer núcleo vivo
///
/// O relógio é um só, e cada núcleo tem timer, todos na mesma frequência.
/// Se todos o andassem, ele correria tantas vezes mais rápido quantos
/// fossem os núcleos; se só um o andasse, ele pararia com esse núcleo — e
/// com ele todo prazo do kernel: arrendamentos, mensagens, o piso do
/// relógio da persistência. A regra: um núcleo anda o relógio se ninguém o
/// andou desde o tique anterior **dele**. Em regime, um núcleo anda e os
/// outros, no tique seguinte deles, veem que andou; se o que anda para —
/// interrupções mascaradas, um laço preso —, o próximo a tiquear não vê
/// nada mudar e passa a andar no lugar, um período depois.
///
/// Dois núcleos nunca andam o mesmo período: o que anda o faz por troca
/// atômica do valor que viu, e quem viu o mesmo valor e perdeu a troca vê,
/// no próximo tique, que andou. A frequência é a do timer de quem anda —
/// todos programados na mesma.
fn avancar() {
    let n = crate::nucleos::atual().min(MAX_NUCLEOS - 1);
    let agora = TICKS.load(Ordering::Acquire);
    let antes = VISTO[n].load(Ordering::Relaxed);
    // O primeiro tique de um núcleo só olha: `u64::MAX` nunca é o relógio.
    let visto = if agora == antes
        && TICKS
            .compare_exchange(agora, agora + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        agora + 1
    } else {
        TICKS.load(Ordering::Acquire)
    };
    VISTO[n].store(visto, Ordering::Relaxed);
}

/// O que o tique faz no núcleo dos dispositivos, além de andar o relógio.
fn trabalho_dos_dispositivos() {
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

    // E o teclado, onde ele for virtio.
    //
    // Por que aqui, e não pela interrupção do dispositivo: o despacho de
    // interrupção do virtio neste kernel reconhece o aviso e conta, mas não
    // chama de volta o driver — os dois drivers que existiam antes deste
    // esperam em laço e leem o anel de usados, e nenhum precisava de
    // retorno. Um teclado precisa, e a escolha é entre dar um caminho de
    // volta ao despacho ou recolher no pulso que já existe.
    //
    // O pulso custa dez milissegundos de latência no pior caso, que é
    // metade do que uma pessoa percebe como instantâneo, e não acrescenta
    // um caminho novo entre um handler de interrupção e um driver com
    // trava. O caminho de volta fica para quando houver um segundo
    // dispositivo que precise dele.
    crate::virtio::teclado::colher();
    crate::virtio::console::colher();
    crate::usb::xhci::colher();

    // E o retângulo do console que ficou sujo porque a trava do compositor
    // estava na mão de outro: ele esperava a escrita seguinte no console, que
    // pode não vir — a última linha de um log ficava fora da tela. Com um
    // núcleo só a trava quase nunca estava tomada; com vários, outro núcleo
    // compondo é o caso comum. Vazio, isto é uma leitura de atômico.
    crate::tela::descarregar();

    // E o que outros núcleos compuseram e deixaram para o núcleo dos dispositivos levar à
    // tela — ver `grafico::apresentar_pendente`. Normalmente o cutucão de
    // quem compôs chega antes; aqui é a rede, para o cutucão que se perder.
    crate::grafico::apresentar_pendente();
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
