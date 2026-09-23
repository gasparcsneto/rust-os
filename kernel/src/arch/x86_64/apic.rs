//! O APIC local: o timer por núcleo do x86 moderno.
//!
//! # Por que trocar um timer que funciona
//!
//! O PIT funciona, e continua sendo o primeiro timer deste kernel — ver
//! [`super::pic`]. O problema dele não é a precisão: é que existe **um só**.
//!
//! O PIT é uma peça da placa, ligada a uma linha do controlador de
//! interrupções. Numa máquina com vários núcleos, um deles recebe as
//! interrupções e os outros não têm relógio nenhum: não há como preemptar um
//! fio que esteja rodando no núcleo 3, porque nada naquele núcleo interrompe.
//!
//! O APIC local resolve isso por construção — cada núcleo tem o seu, com
//! contador próprio, e a interrupção nasce e morre dentro do núcleo sem
//! passar por controlador nenhum. É a mesma propriedade que o timer genérico
//! do ARM já tinha, e é por isso que este arquivo não tem par do outro lado.
//!
//! # A frequência que ninguém declara
//!
//! O timer do APIC conta na frequência do barramento, que **não é
//! auto-descritiva**: não há registrador que a informe, e ela varia entre
//! máquinas. Isso é o oposto do ARM, onde `CNTFRQ_EL0` diz a própria.
//!
//! A saída é medi-la contra um relógio que já se conhece — e o kernel tem
//! um: o PIT, rodando desde o boot a uma frequência conhecida. Contamos
//! quantos tiques do APIC cabem num intervalo medido em tiques do PIT.
//!
//! É por isso que o PIT não é desperdício nem dívida: ele é o que torna a
//! calibração possível. Um kernel que começasse pelo APIC teria de medi-lo
//! contra alguma outra coisa.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::register_structs;
use tock_registers::registers::{ReadOnly, ReadWrite, WriteOnly};
use x86_64::registers::model_specific::Msr;

register_structs! {
    /// O bloco de registradores do APIC local.
    ///
    /// Os registradores são espaçados de dezesseis em dezesseis bytes, e só
    /// os quatro primeiros de cada grupo existem. Declarar o bloco em vez de
    /// somar deslocamentos soltos transforma um endereço errado em erro de
    /// compilação — a mesma razão pela qual o GIC do ARM é declarado assim.
    Lapic {
        (0x000 => _reservado0),
        /// Qual núcleo é este. Lido só para o relatório.
        (0x020 => id: ReadOnly<u32>),
        (0x024 => _reservado1),
        (0x030 => versao: ReadOnly<u32>),
        (0x034 => _reservado2),
        /// Prioridade a partir da qual este núcleo aceita interrupções.
        (0x080 => tpr: ReadWrite<u32>),
        (0x084 => _reservado3),
        /// Fim de interrupção. Substitui o do PIC para tudo que vem do APIC.
        (0x0B0 => eoi: WriteOnly<u32>),
        (0x0B4 => _reservado4),
        /// Vetor espúrio e o bit que liga o APIC por software.
        (0x0F0 => svr: ReadWrite<u32>),
        (0x0F4 => _reservado5),
        /// Como o timer interrompe: vetor, máscara e modo.
        (0x320 => lvt_timer: ReadWrite<u32>),
        (0x324 => _reservado6),
        /// De quanto o contador começa. Escrever aqui dispara a contagem.
        (0x380 => contagem_inicial: ReadWrite<u32>),
        (0x384 => _reservado7),
        /// Quanto falta. Conta para baixo.
        (0x390 => contagem_atual: ReadOnly<u32>),
        (0x394 => _reservado8),
        /// Divisor aplicado à frequência do barramento.
        (0x3E0 => divisor: ReadWrite<u32>),
        (0x3E4 => _reservado9),
        (0x400 => @END),
    }
}

/// O MSR que diz onde o APIC está e se ele está ligado.
const IA32_APIC_BASE: u32 = 0x1B;
/// Bit do MSR que liga o APIC globalmente.
const MSR_HABILITADO: u64 = 1 << 11;
/// Máscara dos bits de endereço no MSR.
const MSR_ENDERECO: u64 = 0x0000_000F_FFFF_F000;

/// Vetor da interrupção do timer do APIC.
///
/// Acima dos dezesseis do PIC, que ocupam 32 a 47. Escolher um vetor livre em
/// vez de reaproveitar o do PIT é o que permite os dois coexistirem durante a
/// calibração — e é durante a calibração que os dois precisam coexistir.
pub const VETOR_TIMER: u8 = 48;

/// Vetor das interrupções espúrias.
///
/// O APIC exige que este campo seja preenchido, e entrega neste vetor as
/// interrupções que ele próprio não conseguiu atribuir a ninguém. Elas
/// acontecem em condições de corrida legítimas — uma linha que baixa entre o
/// reconhecimento e a leitura — e a resposta certa é não fazer nada, nem
/// sequer sinalizar fim de interrupção.
pub const VETOR_ESPURIO: u8 = 255;

/// Bit que liga o APIC por software, no registrador de vetor espúrio.
const SVR_HABILITADO: u32 = 1 << 8;

/// Modo periódico, nos bits 17-18 do registrador do timer.
const TIMER_PERIODICO: u32 = 0b01 << 17;
/// Bit de máscara do registrador do timer.
const TIMER_MASCARADO: u32 = 1 << 16;

/// De quanto o divisor divide.
///
/// Dezesseis dá folga: mesmo num barramento de gigahertz, o contador de 32
/// bits leva mais de um minuto para dar a volta.
const DIVISOR: u64 = 16;

/// O divisor acima, na codificação do registrador.
///
/// Os bits são 0, 1 e 3 — o bit 2 não existe, o que torna a codificação
/// exatamente o tipo de coisa que se escreve errado lendo o manual rápido.
const DIVISOR_CODIFICADO: u32 = 0b0011;

/// Onde o APIC deste núcleo está mapeado, ou zero se não há um.
static BASE: AtomicU64 = AtomicU64::new(0);
/// Quantas vezes por segundo o **contador** decrementa.
///
/// Do contador, e não do barramento. A distinção não é preciosismo: o
/// registrador de contagem inicial é medido nesta unidade, e uma versão
/// anterior guardou aqui a frequência do barramento — dezesseis vezes maior.
/// O resultado foi um timer disparando dezesseis vezes mais devagar do que o
/// pedido, e um log dizendo "100 Hz" com toda a convicção, porque a conta
/// `frequencia / contagem` é autoconsistente sobre a premissa errada.
static FREQUENCIA_DO_CONTADOR: AtomicU32 = AtomicU32::new(0);

/// Os registradores, se o APIC já foi mapeado.
fn lapic() -> Option<&'static Lapic> {
    let base = BASE.load(Ordering::Acquire);
    // SAFETY: `base` só é diferente de zero depois de `mmio::mapear` ter
    // mapeado a página do APIC como memória de dispositivo, e nada neste
    // kernel desmapeia MMIO.
    (base != 0).then(|| unsafe { &*(base as *const Lapic) })
}

/// Se este processador tem um APIC local.
fn existe() -> bool {
    // A folha 1 é válida em todo x86_64, e a instrução não tem efeito
    // colateral — daí ela não ser `unsafe`.
    let info = core::arch::x86_64::__cpuid(1);
    info.edx & (1 << 9) != 0
}

/// Onde o APIC está, segundo o próprio processador.
///
/// O endereço vem de um registrador de modelo, e não de uma tabela da ACPI.
/// É uma diferença que vale: descobrir o APIC pela ACPI exigiria um parser de
/// tabelas inteiro, e o MSR responde a mesma pergunta com uma instrução.
///
/// A ACPI continua sendo necessária para o **outro** APIC — o de entrada e
/// saída, que roteia as linhas dos dispositivos —, e por isso este kernel
/// continua entregando as interrupções de PCI pelo PIC.
fn endereco() -> Option<u64> {
    if !existe() {
        return None;
    }

    // SAFETY: o MSR existe sempre que o `cpuid` acima diz que há APIC.
    let valor = unsafe { Msr::new(IA32_APIC_BASE).read() };
    (valor & MSR_HABILITADO != 0).then_some(valor & MSR_ENDERECO)
}

/// Espera a linha do PIT avançar `quantos` disparos a partir de `de`.
///
/// Devolve quantos disparos aconteceram, ou `None` se o teto de voltas se
/// esgotou antes.
///
/// # Por que um teto, e não um laço até acontecer
///
/// Porque a versão sem teto era um travamento em silêncio esperando um
/// firmware ruim. Toda espera por dispositivo neste kernel tem teto — o disco
/// e a rede contam voltas por escrito —, e a espera pelo PIT não tinha,
/// embora dependa de um dispositivo tanto quanto as outras: se a IRQ 0 não
/// chega, porque o PIT está morto ou porque a linha foi roteada para outro
/// lugar, o contador nunca muda e o laço gira para sempre.
///
/// E gira no pior lugar possível: durante o boot, antes de o canal do agente
/// ter respondido a primeira pergunta. A máquina não travaria com um
/// diagnóstico ruim; travaria sem diagnóstico nenhum.
///
/// O teto é folgado de propósito. Ele não mede tempo, só distingue "o PIT
/// está lento" de "o PIT não está disparando" — e errar para o lado folgado
/// custa um boot demorado, enquanto errar para o lado apertado custa um APIC
/// recusado numa máquina em que ele funcionava.
fn esperar_disparos(linha: usize, de: u64, quantos: u64) -> Option<u64> {
    /// Voltas de espera toleradas por disparo do PIT.
    ///
    /// A dez milissegundos por disparo, cem milhões de voltas são ordens de
    /// grandeza mais do que qualquer máquina precisa — inclusive um emulador
    /// interpretando instrução por instrução.
    const VOLTAS_POR_DISPARO: u64 = 100_000_000;

    for _ in 0..VOLTAS_POR_DISPARO.saturating_mul(quantos) {
        let agora = crate::irq::contagem_da_linha(linha).wrapping_sub(de);
        if agora >= quantos {
            return Some(agora);
        }
        core::hint::spin_loop();
    }

    crate::log_error!(
        "irq",
        "o PIT nao disparou {} vezes; a linha {} esta parada em {}",
        quantos,
        linha,
        crate::irq::contagem_da_linha(linha)
    );
    None
}

/// Mede a frequência do contador do timer contra o PIT.
///
/// Devolve quantas vezes por segundo o contador decrementa — que é a unidade
/// em que o registrador de contagem inicial é medido, e portanto a única que
/// serve para programá-lo.
///
/// # Como a medida é feita
///
/// O contador do APIC é carregado com o maior valor possível e conta para
/// baixo livremente. Esperamos um número conhecido de interrupções do PIT — o
/// relógio que já está calibrado — e lemos quanto o contador andou. A conta é
/// uma regra de três.
///
/// A espera começa na **borda** de um tique do PIT, e não no instante em que
/// a função é chamada. Sem isso, o primeiro intervalo seria uma fração
/// arbitrária de dez milissegundos, e o erro entraria direto na frequência
/// calculada.
fn calibrar(lapic: &Lapic) -> Option<u32> {
    /// Quantos tiques do PIT esperar. Cinco, a 100 Hz, são cinquenta
    /// milissegundos: tempo suficiente para o erro de meio tique ficar abaixo
    /// de um por cento, e pouco o bastante para não ser notado no boot.
    const TIQUES_DO_PIT: u64 = 5;

    let hz_do_pit = crate::tempo::frequencia_hz() as u64;
    if hz_do_pit == 0 {
        // Sem relógio de referência não há como medir. Acontece se esta
        // função for chamada antes de o PIT ser programado, o que seria um
        // erro de ordem no boot — e um erro que é melhor reportar do que
        // esconder atrás de uma frequência inventada.
        return None;
    }

    lapic.divisor.set(DIVISOR_CODIFICADO);
    // Mascarado durante a medida: queremos o contador andando, não
    // interrupções chegando num vetor que ainda não tem handler.
    lapic.lvt_timer.set(TIMER_MASCARADO);

    // Os disparos do PIT, e não os tiques do relógio do kernel. Aqui os dois
    // ainda coincidem — o timer do APIC está mascarado —, e usar a linha
    // mesmo assim é o que mantém a medida correta se um dia deixarem.
    let linha = super::pic::IRQ_TIMER as usize;

    let borda = crate::irq::contagem_da_linha(linha);
    esperar_disparos(linha, borda, 1)?;

    let comeco = crate::irq::contagem_da_linha(linha);
    lapic.contagem_inicial.set(u32::MAX);

    let Some(tiques) = esperar_disparos(linha, comeco, TIQUES_DO_PIT) else {
        // Desarma o contador antes de desistir. Ele foi carregado logo acima e
        // continuaria correndo; deixá-lo assim entregaria ao próximo leitor um
        // APIC em meio estado, que é pior que um APIC recusado.
        lapic.contagem_inicial.set(0);
        return None;
    };

    let restante = lapic.contagem_atual.get();
    lapic.contagem_inicial.set(0);

    let andou = u32::MAX.checked_sub(restante)? as u64;
    if andou == 0 {
        // O contador não se mexeu. Num emulador sem APIC de verdade isso é o
        // que se vê, e prosseguir daria uma divisão por zero mais adiante.
        return None;
    }

    // `andou` decrementos em `tiques / hz_do_pit` segundos. O divisor
    // **não** entra nesta conta: ele já está embutido no que medimos, porque
    // o que contamos foram decrementos do contador, não ciclos do barramento.
    //
    // O divisor da regra de três são os tiques **observados**, e não os
    // pedidos: a espera pode devolver mais de um disparo por volta se o PIT
    // vier atrasado, e dividir pelo número pedido atribuiria a um intervalo
    // curto um contador que andou um intervalo longo.
    let por_segundo = andou.checked_mul(hz_do_pit)?.checked_div(tiques)?;

    u32::try_from(por_segundo).ok()
}

/// Confere, contra o PIT, que o timer está mesmo disparando na taxa pedida.
///
/// # Por que isto existe
///
/// Porque a aritmética da calibração é autoconsistente mesmo quando está
/// errada. Uma versão anterior deste arquivo confundiu a frequência do
/// barramento com a do contador: o timer passou a disparar dezesseis vezes
/// mais devagar, e o log anunciou "100 Hz" com toda a convicção, porque
/// `frequencia / contagem` dá o número pedido de volta seja qual for a
/// unidade de `frequencia`.
///
/// Nenhum teste da suíte pegava isso, e não por descuido: depois que o PIT é
/// mascarado, o relógio do kernel **é** o timer do APIC, e não existe mais
/// nada com que compará-lo. Perguntar ao relógio se ele está certo é
/// perguntar a ele sobre ele mesmo.
///
/// Este é o único instante em que a máquina tem dois relógios independentes.
///
/// # Por que contar linhas, e não tiques do relógio
///
/// Porque quando esta função roda o timer do APIC **já está armado**, e os
/// dois timers estão alimentando `tempo::ticks`. Medir um intervalo por ele
/// daria metade do tempo real, e a primeira versão desta conferência fez
/// exatamente isso: acusou 50% de desvio num timer que estava certo.
///
/// Foi o mesmo erro que ela existe para pegar, cometido dentro dela. Os
/// contadores por linha não têm esse problema: cada um é alimentado por
/// exatamente uma fonte.
///
/// Devolve `true` se a taxa observada bate com a pedida dentro da tolerância.
fn conferir_contra_o_pit(hz_pedido: u32) -> bool {
    /// Quantos disparos do PIT observar. Vinte, a 100 Hz, são duzentos
    /// milissegundos — tempo para o APIC disparar vinte vezes e o erro de
    /// arredondamento de uma delas não dominar a conta.
    const DISPAROS_DO_PIT: u64 = 20;

    /// Quanto a taxa observada pode se afastar da pedida, em porcento.
    ///
    /// Vinte e cinco é frouxo de propósito. O que precisa ser pego é um erro
    /// de unidade — um fator de dezesseis, ou de mil —, não um desvio de
    /// alguns por cento entre dois osciladores emulados. Uma tolerância
    /// apertada aqui trocaria um defeito real por um boot instável.
    const TOLERANCIA: u64 = 25;

    let hz_do_pit = crate::tempo::frequencia_hz() as u64;
    if hz_do_pit == 0 || hz_pedido == 0 {
        return false;
    }

    let linha_do_pit = super::pic::IRQ_TIMER as usize;
    let linha_do_apic = VETOR_TIMER as usize;

    let pit_antes = crate::irq::contagem_da_linha(linha_do_pit);
    let apic_antes = crate::irq::contagem_da_linha(linha_do_apic);

    let Some(do_pit) = esperar_disparos(linha_do_pit, pit_antes, DISPAROS_DO_PIT) else {
        return false;
    };
    let do_apic = crate::irq::contagem_da_linha(linha_do_apic) - apic_antes;

    // Quantos disparos do APIC caberiam nos do PIT que acabamos de observar,
    // se as duas taxas fossem as pedidas.
    let esperados = hz_pedido as u64 * do_pit / hz_do_pit;
    if esperados == 0 {
        return false;
    }

    let desvio = do_apic.abs_diff(esperados) * 100 / esperados;
    if desvio > TOLERANCIA {
        crate::log_warn!(
            "irq",
            "o APIC disparou {} vezes onde {} eram esperadas ({}% de desvio)",
            do_apic,
            esperados,
            desvio
        );
        return false;
    }

    true
}

/// Liga o APIC local e programa o timer dele na frequência pedida.
///
/// Devolve a frequência efetiva, ou `None` se esta máquina não tem APIC, se a
/// calibração não deu um número utilizável, ou se o timer não disparou na
/// taxa pedida. Nos três casos o PIT continua sendo o relógio, que é por que
/// o erro não é fatal.
///
/// # Safety
///
/// Exige a paginação no ar (o APIC precisa ser mapeado), o PIT já rodando
/// (para calibrar e para conferir) e as interrupções habilitadas (as duas
/// coisas esperam por tiques do PIT).
pub unsafe fn init(hz: u32) -> Option<u32> {
    let fisico = endereco()?;

    // O APIC é memória de dispositivo. O mapa da memória física do bootloader
    // cobre este endereço, mas como memória normal — e servir a leitura de um
    // registrador pelo cache devolveria um valor velho, sem aviso.
    let virtual_ = crate::mmio::mapear(fisico, 4096).ok()?;
    BASE.store(virtual_, Ordering::Release);

    let lapic = lapic()?;

    // Ligar por software, com o vetor de espúrias preenchido. Sem este passo
    // o APIC está presente e simplesmente não entrega nada.
    lapic.svr.set(SVR_HABILITADO | VETOR_ESPURIO as u32);
    // Aceitar interrupções de qualquer prioridade. O valor de reset já é
    // zero, e escrevê-lo é dizer que a escolha foi feita.
    lapic.tpr.set(0);

    let frequencia = calibrar(lapic)?;
    FREQUENCIA_DO_CONTADOR.store(frequencia, Ordering::Release);

    let contagem = (frequencia / hz.max(1)).max(1);
    lapic.divisor.set(DIVISOR_CODIFICADO);
    lapic.lvt_timer.set(TIMER_PERIODICO | VETOR_TIMER as u32);
    lapic.contagem_inicial.set(contagem);

    let efetiva = frequencia / contagem;

    if !conferir_contra_o_pit(efetiva) {
        // Desarmar antes de desistir: um timer disparando na taxa errada num
        // vetor que ninguém mais espera é pior que timer nenhum.
        lapic.lvt_timer.set(TIMER_MASCARADO);
        lapic.contagem_inicial.set(0);
        return None;
    }

    Some(efetiva)
}

/// Sinaliza o fim de uma interrupção entregue pelo APIC.
///
/// Não substitui o do PIC: as interrupções de dispositivo continuam vindo por
/// lá e continuam sendo finalizadas lá. Confundir os dois é o erro que faz o
/// timer disparar exatamente uma vez.
pub fn fim_de_interrupcao() {
    if let Some(lapic) = lapic() {
        lapic.eoi.set(0);
    }
}

/// Quantas vezes por segundo o contador do timer decrementa.
pub fn frequencia_do_contador() -> u32 {
    FREQUENCIA_DO_CONTADOR.load(Ordering::Acquire)
}

/// A frequência do barramento que alimenta o timer, em Hz.
///
/// É a do contador multiplicada de volta pelo divisor. Só serve para o
/// relatório — nada é programado nesta unidade, e foi confundi-la com a do
/// contador que produziu o defeito documentado em [`FREQUENCIA_DO_CONTADOR`].
pub fn frequencia_do_barramento() -> u64 {
    frequencia_do_contador() as u64 * DIVISOR
}

/// O identificador deste núcleo, se houver APIC.
pub fn id_do_nucleo() -> Option<u32> {
    lapic().map(|lapic| lapic.id.get() >> 24)
}
