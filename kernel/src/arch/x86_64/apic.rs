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
//!
//! # O tique pela grade comum do TSC
//!
//! O timer não é periódico: dispara uma vez, e o handler escreve a distância
//! até o ponto seguinte de uma grade só, contada no TSC — ver [`PRAZO`].

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::nucleos::MAX_NUCLEOS;

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
        /// Comando de interrupção, metade baixa: o que mandar e como.
        /// Escrever aqui **envia** — por isso a metade alta vem antes.
        (0x300 => icr_baixo: ReadWrite<u32>),
        (0x304 => _reservado_icr0),
        /// Comando de interrupção, metade alta: para qual APIC, no byte de
        /// cima.
        (0x310 => icr_alto: ReadWrite<u32>),
        (0x314 => _reservado_icr1),
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

/// Vetor do cutucão: a interrupção que um núcleo manda a outro só para
/// acordá-lo — ver [`crate::nucleos::cutucar`]. Não carrega pedido nenhum: o
/// núcleo acordado volta do `hlt`, e é o código dele que confere o que mudou.
pub const VETOR_CUTUCAO: u8 = 240;

/// Bit que liga o APIC por software, no registrador de vetor espúrio.
const SVR_HABILITADO: u32 = 1 << 8;

/// O registrador do timer em disparo único — os bits 17-18 do modo em
/// zero —, sem máscara, no vetor do timer: o contador desce a contagem
/// inicial uma vez e para, e o handler escreve a seguinte (ver [`PRAZO`]).
const LVT_DO_TIMER: u32 = VETOR_TIMER as u32;
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

/// A contagem de um período no contador do APIC, no primeiro núcleo. Não
/// programa nada — o timer é armado pela grade ([`PRAZO`]) —: diferente de
/// zero, diz que o timer foi programado e conferido ([`pronto`]).
///
/// Sai com `Release`, depois da grade ([`ORIGEM`], [`INTERVALO`],
/// [`CICLOS_POR_DECREMENTO`]); cada núcleo secundário a lê com `Acquire`
/// antes de armar, e lê a grade inteira. Eles não calibram de novo: a
/// calibração mede o contador contra o PIT, e o PIT é **um** só — calibrar
/// em dois núcleos ao mesmo tempo seria disputar o mesmo relógio de
/// referência, e calibrar depois que ele foi mascarado seria medir contra
/// nada. Os contadores de todos os núcleos andam na frequência do mesmo
/// barramento.
static CONTAGEM: AtomicU32 = AtomicU32::new(0);

/// O próximo disparo de cada núcleo, em ciclos do TSC: um ponto da grade
/// comum, `ORIGEM + k · INTERVALO`.
///
/// # Uma grade só, no TSC
///
/// O timer era periódico: cada núcleo carregava a contagem ao ligar o timer,
/// e cada um disparava na sua grade, na sua fase. O relógio do sistema anda
/// pelo núcleo que não viu ninguém andar desde o próprio tique anterior
/// (`tempo::avancar`), e com uma grade por núcleo isso contava o mesmo
/// período duas vezes: um tique atrasado que tinha visto o avanço de outro
/// núcleo era seguido do próximo da grade dele a menos de um período, antes
/// do próximo do outro, e ninguém tinha andado no meio. Agora o APIC dispara
/// uma vez, e o handler escreve a distância até o ponto seguinte de uma
/// grade só, contada no TSC — que a grade supõe igual em todos os núcleos:
/// no emulador ele é um só, e no hardware é o TSC invariante e
/// sincronizado. O boot avisa quando o `CPUID` não anuncia o invariante, e
/// a sincronia não se confere. É o que o ARM faz com o `CNTP_CVAL_EL0`. O
/// TSC é lido sempre em ordem (`ciclos_em_ordem`): o rearme o lê depois de
/// ver, no relógio, o avanço de outro núcleo.
/// O modo do x86 que compara direto com o TSC (o TSC-deadline) não existe no
/// emulador sem aceleração: o `qemu64` não o anuncia, e o QEMU o tira dos
/// recursos do TCG. A CI não o exercitaria.
///
/// # O período é o do TSC, e não o do APIC
///
/// A grade é contada no TSC, com a frequência medida contra o canal 2 do PIT
/// (`pic::frequencia_do_tsc`) — a mesma medida da régua do civil, com erro
/// de até 200 ppm. O APIC só mede a distância até o ponto. O período deixou
/// de depender da calibração do APIC, que mede o contador dele contra os
/// disparos do PIT vistos por um laço: o laço vê cada disparo depois do
/// handler inteiro dele, e um handler mais longo na borda do começo que na
/// do fim encurtava a medida, e o período. Entre as CIs 512 e 520 a bancada
/// de tempo mediu o relógio do kernel do x86 de -808 a +10 082 ppm do
/// contador — quatro rodadas acima de +6 000, a ordem de grandeza de uma
/// calibração 0,6 a 1% curta —, e nos boots da suíte o barramento medido vai
/// de 855 a 1 131 MHz, contra o 1 GHz do emulador.
///
/// # Um disparo antes do prazo
///
/// A contagem é a distância no TSC convertida pela razão entre os dois
/// contadores medida na calibração ([`CICLOS_POR_DECREMENTO`]), arredondada
/// para cima e com 1/1024 a mais. Se ainda assim o APIC disparar antes
/// do prazo, o disparo não é tique: o handler só rearma para o mesmo prazo
/// ([`rearmar`]). É a primeira das três propriedades de `tempo::avancar`.
///
/// Cada núcleo só lê e escreve o seu, com as interrupções mascaradas, e por
/// isso `Relaxed` basta.
static PRAZO: [AtomicU64; MAX_NUCLEOS] = [const { AtomicU64::new(0) }; MAX_NUCLEOS];

/// A origem da grade: o TSC quando o primeiro núcleo ligou o timer — ver
/// [`PRAZO`]. Sai antes da [`CONTAGEM`].
static ORIGEM: AtomicU64 = AtomicU64::new(0);

/// O período da grade, em ciclos do TSC. Sai antes da [`CONTAGEM`].
static INTERVALO: AtomicU64 = AtomicU64::new(0);

/// Quantos ciclos do TSC cabem num decremento do contador do APIC, em ponto
/// fixo de 16 bits de fração, medidos na mesma janela da calibração — ver
/// [`calibrar`]. Converte a distância até o prazo em contagem. Sai antes da
/// [`CONTAGEM`].
static CICLOS_POR_DECREMENTO: AtomicU64 = AtomicU64::new(0);

/// Quantos disparos do timer, em todos os núcleos, chegaram no prazo ou
/// depois: os tiques. A conferência contra o PIT ([`conferir_contra_o_pit`])
/// conta estes, e não as interrupções da linha, que incluem os disparos
/// antes do prazo.
static TIQUES: AtomicU64 = AtomicU64::new(0);

/// Quantos disparos do timer, em todos os núcleos, acharam o prazo do
/// núcleo ainda no futuro, e só rearmaram ([`chegou_o_prazo`]). A
/// conferência contra o PIT os conta também: uma conversão do TSC para o
/// APIC curta demais — a razão alta — não muda os tiques, e só aparece
/// aqui.
static ANTECIPADOS: AtomicU64 = AtomicU64::new(0);

/// Só para a suíte: o TSC que o [`armar_o_primeiro`] de cada núcleo leu, e o
/// primeiro prazo que ele calculou — ver [`primeiro_prazo_de_teste`]. Um bit
/// por núcleo em [`PRIMEIROS_DE_TESTE`] diz quais anotaram.
#[cfg(feature = "modo-teste")]
static PRIMEIRO_AGORA_DE_TESTE: [AtomicU64; MAX_NUCLEOS] =
    [const { AtomicU64::new(0) }; MAX_NUCLEOS];
#[cfg(feature = "modo-teste")]
static PRIMEIRO_PRAZO_DE_TESTE: [AtomicU64; MAX_NUCLEOS] =
    [const { AtomicU64::new(0) }; MAX_NUCLEOS];
#[cfg(feature = "modo-teste")]
static PRIMEIROS_DE_TESTE: AtomicU64 = AtomicU64::new(0);

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
///
/// # E a razão para o TSC
///
/// Devolve também quantos ciclos do TSC cabem num decremento do contador,
/// em ponto fixo de 16 bits de fração ([`CICLOS_POR_DECREMENTO`]): o TSC
/// lido logo depois de carregar o contador e logo depois de ler o que
/// restou, a mesma janela dos dois lados. Essa razão não depende das bordas
/// do PIT — o laço que as vê depois do handler inteiro de cada disparo, o
/// erro da frequência acima —, e é ela que converte a distância até o prazo
/// em contagem.
fn calibrar(lapic: &Lapic) -> Option<(u32, u64)> {
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
    let tsc_no_comeco = super::ciclos_em_ordem();

    let Some(tiques) = esperar_disparos(linha, comeco, TIQUES_DO_PIT) else {
        // Desarma o contador antes de desistir. Ele foi carregado logo acima e
        // continuaria correndo; deixá-lo assim entregaria ao próximo leitor um
        // APIC em meio estado, que é pior que um APIC recusado.
        lapic.contagem_inicial.set(0);
        return None;
    };

    let restante = lapic.contagem_atual.get();
    let tsc_no_fim = super::ciclos_em_ordem();
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

    let ciclos = tsc_no_fim.checked_sub(tsc_no_comeco)?;
    let razao = (u128::from(ciclos) << 16) / u128::from(andou);
    let razao = u64::try_from(razao).ok().filter(|&r| r > 0)?;

    Some((u32::try_from(por_segundo).ok()?, razao))
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
/// # Por que contar os disparos de cada um, e não tiques do relógio
///
/// Porque quando esta função roda o timer do APIC **já está armado**, e os
/// dois timers alimentavam `tempo::ticks`. Medir um intervalo por ele dava
/// metade do tempo real, e a primeira versão desta conferência fez
/// exatamente isso: acusou 50% de desvio num timer que estava certo.
///
/// Foi o mesmo erro que ela existe para pegar, cometido dentro dela. Do PIT
/// conta a linha, que só ele alimenta; do APIC, os tiques dele ([`TIQUES`]),
/// e não a linha: um disparo antes do prazo também é uma interrupção da
/// linha, e não é tique.
///
/// Desde o #455-C o relógio, aqui, é só do PIT: o APIC só o anda depois de
/// assumi-lo, com o PIT já mascarado ([`assumir_o_relogio`]). O que ele
/// andou na janela vai junto nos números ([`Conferencia::relogio`]).
///
/// # O que ela confere agora
///
/// O período é o da grade no TSC ([`PRAZO`]): os tiques pegam um erro de
/// unidade na frequência do TSC, ou na conversão para o APIC para o lado
/// longo — as contagens grandes demais perdem tiques —, como pegavam na do
/// APIC. O lado curto da conversão — a razão alta, as contagens pequenas
/// demais — não muda os tiques: cada disparo antes do prazo só rearma
/// ([`chegou_o_prazo`]). Ele aparece nos disparos antes do prazo
/// ([`ANTECIPADOS`]), e a conferência recusa a tentativa com mais de quatro
/// por tique, o teto do caso da suíte: com a razão dezesseis vezes alta, uns
/// 24 por tique, e o boot passava com eles. A tentativa seguinte calibra de
/// novo; a razão alta sem defeito, de uma parada do hospedeiro no fim da
/// janela da calibração, não se repete.
///
/// O veredito sai dos números da tentativa ([`julgar_a_conferencia`]), que
/// vão para o log do boot quando ela aprova.
///
/// Devolve `true` se a taxa observada bate com a pedida dentro da tolerância,
/// e os disparos antes do prazo não passam do teto.
fn conferir_contra_o_pit(hz_pedido: u32) -> bool {
    /// Quantos disparos do PIT observar. Vinte, a 100 Hz, são duzentos
    /// milissegundos — tempo para o APIC disparar vinte vezes e o erro de
    /// arredondamento de uma delas não dominar a conta.
    const DISPAROS_DO_PIT: u64 = 20;

    let hz_do_pit = crate::tempo::frequencia_hz() as u64;
    if hz_do_pit == 0 || hz_pedido == 0 {
        return false;
    }

    let linha_do_pit = super::pic::IRQ_TIMER as usize;

    let pit_antes = crate::irq::contagem_da_linha(linha_do_pit);
    let apic_antes = TIQUES.load(Ordering::Relaxed);
    let antecipados_antes = ANTECIPADOS.load(Ordering::Relaxed);
    let relogio_antes = crate::tempo::ticks();

    let Some(pit) = esperar_disparos(linha_do_pit, pit_antes, DISPAROS_DO_PIT) else {
        return false;
    };
    let conferencia = Conferencia {
        pit,
        tiques: TIQUES.load(Ordering::Relaxed) - apic_antes,
        antecipados: ANTECIPADOS.load(Ordering::Relaxed) - antecipados_antes,
        relogio: crate::tempo::ticks() - relogio_antes,
    };
    #[cfg(feature = "modo-teste")]
    for (lugar, valor) in CONFERENCIA_DE_TESTE.iter().zip([
        conferencia.pit,
        conferencia.tiques,
        conferencia.antecipados,
        conferencia.relogio,
    ]) {
        lugar.store(valor, Ordering::SeqCst);
    }

    match julgar_a_conferencia(conferencia, hz_pedido, hz_do_pit) {
        Ok(()) => {
            crate::log_info!(
                "irq",
                "conferencia contra o PIT: {} tique(s) do APIC e {} disparo(s) antes do prazo em {} disparo(s) do PIT, e o relogio andou {}",
                conferencia.tiques,
                conferencia.antecipados,
                conferencia.pit,
                conferencia.relogio
            );
            true
        }
        Err(Recusa::SemMedida) => false,
        Err(Recusa::Taxa { esperados, desvio }) => {
            crate::log_warn!(
                "irq",
                "o APIC disparou {} vezes onde {} eram esperadas ({}% de desvio)",
                conferencia.tiques,
                esperados,
                desvio
            );
            false
        }
        Err(Recusa::Antecipados) => {
            crate::log_warn!(
                "irq",
                "o APIC disparou {} vezes antes do prazo em {} tiques: a conversao do TSC para o APIC esta curta",
                conferencia.antecipados,
                conferencia.tiques
            );
            false
        }
    }
}

/// O que uma conferência contra o PIT viu ([`conferir_contra_o_pit`]): os
/// disparos do PIT e, no mesmo intervalo, os tiques do APIC e os disparos
/// dele antes do prazo, em todos os núcleos — no boot, só no primeiro.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Conferencia {
    /// Os disparos do PIT, pela contagem da linha dele.
    pub pit: u64,
    /// Os tiques do APIC: os disparos no prazo ou depois ([`TIQUES`]).
    pub tiques: u64,
    /// Os disparos do APIC antes do prazo ([`ANTECIPADOS`]).
    pub antecipados: u64,
    /// O que o relógio do kernel andou: só o PIT o anda na conferência
    /// ([`assumir_o_relogio`]), e ele fica nos disparos do PIT, um a mais ou
    /// a menos pelas pontas da janela. Fora do veredito: é o kernel, e não o
    /// timer, que ele confere.
    pub relogio: u64,
}

/// Por que uma conferência reprovou — ver [`julgar_a_conferencia`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// Nenhum tique do APIC caberia nos disparos do PIT observados: não há
    /// taxa a comparar.
    SemMedida,
    /// Os tiques do APIC longe da taxa pedida: quantos eram `esperados`, e o
    /// `desvio`, em porcento, acima da tolerância.
    Taxa { esperados: u64, desvio: u64 },
    /// Disparos antes do prazo demais por tique: a conversão do TSC para o
    /// APIC curta.
    Antecipados,
}

/// Quanto a taxa observada pode se afastar da pedida, em porcento.
///
/// Vinte e cinco é frouxo de propósito. O que precisa ser pego é um erro de
/// unidade — um fator de dezesseis, ou de mil —, não um desvio de alguns por
/// cento entre dois osciladores emulados. Uma tolerância apertada aqui
/// trocaria um defeito real por um boot instável.
const TOLERANCIA_DA_TAXA: u64 = 25;

/// Quantos disparos antes do prazo, por tique, a conferência tolera — o teto
/// do caso `smp: o tique do x86 vem pela grade comum do TSC`. O código certo
/// dá zero.
pub const ANTECIPADOS_POR_TIQUE: u64 = 4;

/// O veredito de uma conferência contra o PIT, pelos números dela: os tiques
/// do APIC na taxa pedida (`hz_pedido`), contra os disparos do PIT na dele
/// (`hz_do_pit`), dentro da tolerância; e os disparos antes do prazo até o
/// teto por tique. Pura: a suíte a confere sem o PIT, que depois do boot
/// está mascarado.
pub fn julgar_a_conferencia(c: Conferencia, hz_pedido: u32, hz_do_pit: u64) -> Result<(), Recusa> {
    // Quantos tiques do APIC caberiam nos disparos do PIT observados, se as
    // duas taxas fossem as pedidas.
    let esperados = u64::from(hz_pedido)
        .saturating_mul(c.pit)
        .checked_div(hz_do_pit)
        .unwrap_or(0);
    if esperados == 0 {
        return Err(Recusa::SemMedida);
    }
    let desvio = c.tiques.abs_diff(esperados).saturating_mul(100) / esperados;
    if desvio > TOLERANCIA_DA_TAXA {
        return Err(Recusa::Taxa { esperados, desvio });
    }
    // A conversão curta: os tiques certos, e disparos antes do prazo demais
    // entre eles — ver [`conferir_contra_o_pit`].
    if c.antecipados > c.tiques.saturating_mul(ANTECIPADOS_POR_TIQUE) {
        return Err(Recusa::Antecipados);
    }
    Ok(())
}

/// Só para a suíte: os números da última conferência contra o PIT — os
/// campos de [`Conferencia`], na ordem —, escritos no primeiro núcleo, no
/// boot, antes de os outros acordarem. Ver [`conferencia_de_teste`].
#[cfg(feature = "modo-teste")]
static CONFERENCIA_DE_TESTE: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// Só para a suíte: os números da última conferência contra o PIT — a que
/// aprovou o APIC, quando ele é o timer —, ou zeros se nenhuma chegou a
/// contar.
#[cfg(feature = "modo-teste")]
pub fn conferencia_de_teste() -> Conferencia {
    let [pit, tiques, antecipados, relogio] =
        core::array::from_fn(|i| CONFERENCIA_DE_TESTE[i].load(Ordering::SeqCst));
    Conferencia {
        pit,
        tiques,
        antecipados,
        relogio,
    }
}

/// Se o timer do APIC anda o relógio do kernel — ver [`assumir_o_relogio`].
static ANDA_O_RELOGIO: AtomicBool = AtomicBool::new(false);

/// O timer do APIC passa a andar o relógio do kernel. Chamada uma vez, no
/// boot, por `init_timer_definitivo`, depois de a conferência aprovar o APIC
/// e de o PIT ser mascarado.
///
/// # Um timer de cada vez no relógio
///
/// Na conferência contra o PIT ([`conferir_contra_o_pit`]) os dois timers
/// disparam no primeiro núcleo, e os dois chamavam `tempo::tick`: o tique de
/// cada um achava o `VISTO` que o outro tinha gravado, e o relógio andava ao
/// dobro — uns vinte tiques a mais em cada tentativa, fora da grade, contra
/// o "nunca à frente" de `tempo::avancar` (o achado 4 do adversário do
/// #455-B). Até aqui, só o PIT anda o relógio; o handler do APIC conta os
/// tiques dele ([`TIQUES`]), que é o que a conferência compara, e o pulso do
/// núcleo. Daqui em diante, só o APIC: o PIT já saiu. Entre o mascarar do
/// PIT e esta chamada nenhum dos dois o anda — uns microssegundos, e no
/// máximo um tique a menos.
pub fn assumir_o_relogio() {
    ANDA_O_RELOGIO.store(true, Ordering::Release);
}

/// O timer do APIC anda o relógio do kernel? Falso até
/// [`assumir_o_relogio`].
pub fn anda_o_relogio() -> bool {
    ANDA_O_RELOGIO.load(Ordering::Acquire)
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

    // O APIC é memória de dispositivo. O mapa da memória física do iniciador
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

    // A frequência do TSC, medida contra o canal 2 do PIT, uma vez só — a
    // mesma que a régua do civil lê depois. É a régua da grade dos tiques
    // (ver `PRAZO`). Sem ela, a que a razão medida na calibração dá pela
    // frequência do contador do APIC: a medida de antes, com o erro dela.
    let do_tsc = super::pic::frequencia_do_tsc().map(|(hz_do_tsc, _)| hz_do_tsc);

    // Mais de uma tentativa, porque calibrar e conferir são medidas, e uma
    // medida pode ser estragada por quem executa a máquina: medido, no QEMU
    // sem aceleração com o hospedeiro ocupado, "o APIC disparou 14 vezes onde
    // 20 eram esperadas". Com um núcleo só, isso custava o timer do APIC e o
    // PIT seguia. Com vários custa os outros núcleos inteiros — sem APIC não
    // há como acordá-los —, então um boot ruim por acaso virava uma máquina
    // de um núcleo. O erro que a conferência existe para pegar é de unidade,
    // um fator de dezesseis ou de mil, e esse se repete em toda tentativa.
    const TENTATIVAS: u32 = 3;
    for _ in 0..TENTATIVAS {
        let (frequencia, razao) = calibrar(lapic)?;
        FREQUENCIA_DO_CONTADOR.store(frequencia, Ordering::Release);
        CICLOS_POR_DECREMENTO.store(razao, Ordering::Relaxed);

        let hz_do_tsc = do_tsc.unwrap_or_else(|| {
            u64::try_from((u128::from(frequencia) * u128::from(razao)) >> 16).unwrap_or(0)
        });
        let intervalo = hz_do_tsc / u64::from(hz.max(1));
        if intervalo < 1_000 {
            // Um TSC abaixo de cem mil ciclos por segundo não é um TSC: a
            // grade de um ciclo armaria o disparo já, sem parar, e a
            // conferência contra o PIT não sairia da tempestade. O PIT segue.
            return None;
        }
        INTERVALO.store(intervalo, Ordering::Relaxed);
        ORIGEM.store(super::ciclos_em_ordem(), Ordering::Relaxed);
        lapic.divisor.set(DIVISOR_CODIFICADO);
        lapic.lvt_timer.set(LVT_DO_TIMER);
        armar_o_primeiro();

        let efetiva = u32::try_from(hz_do_tsc / intervalo).unwrap_or(u32::MAX);

        if conferir_contra_o_pit(efetiva) {
            // Só depois da conferência, e depois da grade: um núcleo
            // secundário a lê por esta, e ela precisa ser uma que se provou
            // certa.
            CONTAGEM.store((frequencia / hz.max(1)).max(1), Ordering::Release);
            return Some(efetiva);
        }

        // Desarmar antes de medir de novo, ou de desistir: um timer
        // disparando na taxa errada num vetor que ninguém mais espera é pior
        // que timer nenhum.
        lapic.lvt_timer.set(TIMER_MASCARADO);
        lapic.contagem_inicial.set(0);
    }
    None
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

/// O id de APIC deste núcleo, segundo o `cpuid`.
///
/// É o mesmo número que o registrador de id do APIC traz, mas não depende de
/// o APIC já estar mapeado — serve ao primeiro núcleo no começo do boot,
/// antes da paginação.
pub fn id_inicial() -> u32 {
    core::arch::x86_64::__cpuid(1).ebx >> 24
}

/// O APIC local está mapeado e o timer dele foi programado?
///
/// Sem ele não há como mandar sinal a outro núcleo, nem timer por núcleo —
/// e então não há vários núcleos.
pub fn pronto() -> bool {
    lapic().is_some() && CONTAGEM.load(Ordering::Acquire) != 0
}

/// Modos de entrega do comando de interrupção, nos bits 8 a 10.
const ENTREGA_NMI: u32 = 0b100 << 8;
const ENTREGA_INIT: u32 = 0b101 << 8;
const ENTREGA_PARTIDA: u32 = 0b110 << 8;
/// O comando ainda está sendo entregue (somente leitura).
const ENTREGA_PENDENTE: u32 = 1 << 12;
/// Nível afirmado, e disparo por nível — o que o INIT pede.
const NIVEL_AFIRMADO: u32 = 1 << 14;
const DISPARO_POR_NIVEL: u32 = 1 << 15;

/// Manda um comando de interrupção ao APIC de id `destino`, e espera o APIC
/// local dizer que entregou.
///
/// # Por que esperar
///
/// Porque o registrador é um só, e escrever o próximo comando com o anterior
/// ainda pendente o descarta sem aviso. A espera tem teto pelo mesmo motivo
/// de toda espera por hardware neste kernel: um APIC que não entrega não pode
/// travar quem pediu.
///
/// # Por que mascarado
///
/// Porque o comando é escrito em duas metades — o destino primeiro, o resto
/// depois —, e as duas são registradores **deste** núcleo. Uma interrupção
/// entre as duas escritas cujo handler também mandasse um comando (um
/// despertar vindo do timer, por exemplo) escreveria o destino dela por cima
/// do nosso, e a nossa segunda metade sairia para o núcleo errado. Com um
/// núcleo só nada mandava comandos; agora tudo manda.
fn comandar(destino: u32, comando: u32) -> Result<(), &'static str> {
    const VOLTAS: u32 = 1_000_000;
    let lapic = lapic().ok_or("sem APIC local")?;
    crate::arch::sem_interrupcoes(|| {
        lapic.icr_alto.set(destino << 24);
        lapic.icr_baixo.set(comando);
        for _ in 0..VOLTAS {
            if lapic.icr_baixo.get() & ENTREGA_PENDENTE == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("o APIC local nao entregou o comando")
    })
}

/// Manda o cutucão ao núcleo de APIC `destino` — ver [`VETOR_CUTUCAO`].
pub fn cutucar(destino: u32) -> Result<(), &'static str> {
    comandar(destino, VETOR_CUTUCAO as u32)
}

/// Manda uma NMI ao núcleo de APIC `destino`.
///
/// A NMI chega mesmo a um núcleo com as interrupções desligadas — é o único
/// sinal que chega. É por isso que ela serve para avisar de uma tradução que
/// morreu e para parar todos no caminho de falha: o núcleo que precisa ouvir
/// pode estar girando numa trava, mascarado.
pub fn enviar_nmi(destino: u32) -> Result<(), &'static str> {
    comandar(destino, ENTREGA_NMI)
}

/// Acorda o núcleo de APIC `destino` na página `pagina` abaixo de 1 MiB.
///
/// A sequência é a que a Intel especifica para acordar um processador de
/// aplicação: um INIT, que o põe em espera, e dois SIPI — o sinal de partida,
/// que carrega o número da página onde ele vai começar a executar, em modo
/// real. O segundo SIPI existe porque o primeiro pode se perder num
/// processador antigo; num que já acordou, ele é ignorado.
///
/// # Safety
///
/// `pagina` precisa ser uma página abaixo de 1 MiB com o código de partida
/// já escrito, e o núcleo precisa ser um que ainda não acordou: um INIT
/// manda o núcleo de volta ao começo, com o que estiver rodando nele.
pub unsafe fn acordar(destino: u32, pagina: u64) -> Result<(), &'static str> {
    if pagina >= 0x10_0000 || !pagina.is_multiple_of(4096) {
        return Err("a pagina de partida precisa estar abaixo de 1 MiB e alinhada");
    }
    let vetor = (pagina >> 12) as u32;

    comandar(destino, ENTREGA_INIT | NIVEL_AFIRMADO | DISPARO_POR_NIVEL)?;
    esperar_tiques(1);
    // A metade "desafirmar" do INIT. Processadores modernos a ignoram; os
    // antigos, de APIC externo, precisam dela para soltar o núcleo.
    comandar(destino, ENTREGA_INIT | DISPARO_POR_NIVEL)?;
    esperar_tiques(1);

    for _ in 0..2 {
        comandar(destino, ENTREGA_PARTIDA | vetor)?;
        esperar_tiques(1);
    }
    Ok(())
}

/// Espera o relógio andar `quantos` tiques, com as interrupções ligadas.
///
/// A especificação pede dez milissegundos depois do INIT e duzentos
/// microssegundos entre os SIPI. O relógio deste kernel anda de dez em dez
/// milissegundos, e esperar a mais aqui não custa nada que se perceba — é o
/// boot, uma vez por núcleo.
fn esperar_tiques(quantos: u64) {
    let comeco = crate::tempo::ticks();
    // O teto é em voltas, e não em tempo: se o relógio parou, a espera
    // precisa terminar mesmo assim.
    for _ in 0..100_000_000u64 {
        if crate::tempo::ticks().wrapping_sub(comeco) > quantos {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Liga o APIC local **deste** núcleo, com o timer na grade do primeiro.
///
/// # Safety
///
/// Precisa rodar no núcleo que acabou de acordar, com as interrupções
/// mascaradas e a IDT dele carregada: o timer começa a contar aqui.
pub unsafe fn ligar_neste_nucleo() -> Result<(), &'static str> {
    let lapic = lapic().ok_or("sem APIC local")?;
    // Com `Acquire`: diferente de zero, a grade inteira está escrita.
    if CONTAGEM.load(Ordering::Acquire) == 0 {
        return Err("o timer do primeiro nucleo nao foi programado");
    }
    lapic.svr.set(SVR_HABILITADO | VETOR_ESPURIO as u32);
    lapic.tpr.set(0);
    lapic.divisor.set(DIVISOR_CODIFICADO);
    lapic.lvt_timer.set(LVT_DO_TIMER);
    armar_o_primeiro();
    Ok(())
}

/// Arma o primeiro disparo deste núcleo: o primeiro ponto da grade comum
/// depois do TSC de agora — à frente dele, e a no máximo um período. Ver
/// [`PRAZO`].
fn armar_o_primeiro() {
    let n = super::gdt::nucleo_atual();
    let agora = super::ciclos_em_ordem();
    let prazo = crate::tempo::proximo_prazo(
        ORIGEM.load(Ordering::Relaxed),
        agora,
        INTERVALO.load(Ordering::Relaxed),
    );
    PRAZO[n].store(prazo, Ordering::Relaxed);
    armar_para(prazo, agora);
    #[cfg(feature = "modo-teste")]
    {
        PRIMEIRO_AGORA_DE_TESTE[n].store(agora, Ordering::SeqCst);
        PRIMEIRO_PRAZO_DE_TESTE[n].store(prazo, Ordering::SeqCst);
        PRIMEIROS_DE_TESTE.fetch_or(crate::nucleos::bit(n), Ordering::SeqCst);
    }
}

/// Programa o disparo único deste núcleo para o prazo `prazo` do TSC, a
/// partir do TSC `agora`: a distância convertida em contagem pela razão da
/// calibração ([`CICLOS_POR_DECREMENTO`]), arredondada para cima e com
/// 1/1024 a mais — a razão medida erra pouco, e o disparo antes do prazo
/// custa uma interrupção a mais. Um prazo que já passou dispara já (a
/// contagem um): a contagem zero pararia o timer.
fn armar_para(prazo: u64, agora: u64) {
    let Some(lapic) = lapic() else {
        return;
    };
    let falta = prazo.wrapping_sub(agora) as i64;
    let contagem = if falta <= 0 {
        1
    } else {
        let razao = u128::from(CICLOS_POR_DECREMENTO.load(Ordering::Relaxed).max(1));
        let exata = (u128::from(falta.unsigned_abs()) << 16).div_ceil(razao);
        u32::try_from(exata + exata / 1024)
            .unwrap_or(u32::MAX)
            .max(1)
    };
    lapic.contagem_inicial.set(contagem);
}

/// O disparo deste núcleo chegou no prazo, ou depois? Chamada no começo do
/// handler do timer, com o TSC de agora: `false` é um disparo antes do
/// prazo, que não é tique — ver [`PRAZO`].
pub fn chegou_o_prazo() -> bool {
    let n = super::gdt::nucleo_atual();
    let prazo = PRAZO[n].load(Ordering::Relaxed);
    let chegou = (super::ciclos_em_ordem().wrapping_sub(prazo) as i64) >= 0;
    if chegou {
        TIQUES.fetch_add(1, Ordering::Relaxed);
    } else {
        ANTECIPADOS.fetch_add(1, Ordering::Relaxed);
    }
    chegou
}

/// Rearma este núcleo, no fim do handler do timer. Depois de um tique
/// (`contou`), para o ponto seguinte da grade depois do TSC de agora: os
/// que passaram durante o trabalho do tique, ou mascarados, são pulados
/// ([`crate::tempo::proximo_prazo`]), e o núcleo dos dispositivos não emenda
/// um tique no outro. Depois de um disparo antes do prazo, para o mesmo
/// prazo: ele não foi contado, e não pode ser pulado — se passou durante o
/// handler, dispara já.
pub fn rearmar(contou: bool) {
    let n = super::gdt::nucleo_atual();
    let vencido = PRAZO[n].load(Ordering::Relaxed);
    let agora = super::ciclos_em_ordem();
    let proximo = if contou {
        crate::tempo::proximo_prazo(vencido, agora, INTERVALO.load(Ordering::Relaxed))
    } else {
        vencido
    };
    PRAZO[n].store(proximo, Ordering::Relaxed);
    armar_para(proximo, agora);
}

/// Só para a suíte: o TSC que o [`armar_o_primeiro`] do núcleo `i` leu e o
/// primeiro prazo que ele calculou, ou `None` se o núcleo não armou.
#[cfg(feature = "modo-teste")]
pub fn primeiro_prazo_de_teste(i: usize) -> Option<(u64, u64)> {
    if i >= MAX_NUCLEOS || PRIMEIROS_DE_TESTE.load(Ordering::SeqCst) & crate::nucleos::bit(i) == 0 {
        return None;
    }
    Some((
        PRIMEIRO_AGORA_DE_TESTE[i].load(Ordering::SeqCst),
        PRIMEIRO_PRAZO_DE_TESTE[i].load(Ordering::SeqCst),
    ))
}

/// Só para a suíte: a origem e o período da grade, em ciclos do TSC.
#[cfg(feature = "modo-teste")]
pub fn grade_de_teste() -> (u64, u64) {
    (
        ORIGEM.load(Ordering::SeqCst),
        INTERVALO.load(Ordering::SeqCst),
    )
}

/// Só para a suíte: o prazo armado deste núcleo, em ciclos do TSC.
#[cfg(feature = "modo-teste")]
pub fn prazo_de_teste() -> u64 {
    PRAZO[super::gdt::nucleo_atual()].load(Ordering::SeqCst)
}

/// Só para a suíte: quantos disparos do timer, desde o boot, chegaram antes
/// do prazo do núcleo e só rearmaram.
#[cfg(feature = "modo-teste")]
pub fn antecipados_de_teste() -> u64 {
    ANTECIPADOS.load(Ordering::SeqCst)
}

/// Só para a suíte: quantos disparos do timer, em todos os núcleos e desde o
/// boot, chegaram no prazo ou depois — os tiques ([`TIQUES`]).
#[cfg(feature = "modo-teste")]
pub fn tiques_de_teste() -> u64 {
    TIQUES.load(Ordering::SeqCst)
}

/// Só para a suíte: faz o APIC deste núcleo disparar já, com o prazo dele no
/// futuro — um disparo antes do prazo, de propósito. Mascarado: o disparo
/// fica pendente até a suíte desmascarar.
#[cfg(feature = "modo-teste")]
pub fn antecipar_de_teste() {
    if let Some(lapic) = lapic() {
        lapic.contagem_inicial.set(1);
    }
}
