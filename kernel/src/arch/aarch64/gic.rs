//! Controlador de interrupções (GIC v2) e timer genérico do ARM.
//!
//! # O contraste com o x86
//!
//! No x86 herdamos um controlador dos anos 1980 em portas de I/O fixas, e um
//! timer separado que precisa ser programado com um divisor derivado de um
//! cristal de 1,19 MHz.
//!
//! No ARM os dois são bem mais modernos e bem mais integrados:
//!
//! - O **GIC** é mapeado em memória e dividido em duas metades: o
//!   *distribuidor*, que decide quais interrupções existem e para onde vão, e
//!   a *interface de CPU*, por onde cada núcleo reconhece e finaliza as que
//!   recebe.
//! - O **timer genérico** faz parte do próprio processador, acessado por
//!   registradores de sistema em vez de portas. Ele informa a própria
//!   frequência em `CNTFRQ_EL0`, então não precisamos de nenhuma constante
//!   mágica de hardware. Ele não é periódico: dispara quando o contador
//!   passa de um prazo, e o tique de cada núcleo é o prazo seguinte, escrito
//!   a cada disparo — ver [`PRAZO`].

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use aarch64_cpu::asm::barrier;
use aarch64_cpu::registers::{CNTFRQ_EL0, CNTP_CTL_EL0, CNTP_CVAL_EL0, CNTPCT_EL0};
use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::register_structs;
use tock_registers::registers::{ReadOnly, ReadWrite, WriteOnly};

use crate::nucleos::MAX_NUCLEOS;

/// Distribuidor do GIC na máquina `virt`.
const GICD_BASE: usize = 0x0800_0000;
/// Interface de CPU do GIC na máquina `virt`.
const GICC_BASE: usize = 0x0801_0000;

register_structs! {
    /// O *distribuidor*: decide quais interrupções existem e para onde vão.
    ///
    /// Declarar o bloco em vez de somar deslocamentos soltos tem duas
    /// vantagens concretas aqui. A macro exige que **todo** intervalo entre
    /// dois registradores seja declarado e confere o total em tempo de
    /// compilação, então um deslocamento errado vira erro de build. E os
    /// registradores que são vetores — um bit por INTID em `ISENABLER`, um
    /// byte por INTID em `ITARGETSR` — viram arrays indexáveis, no lugar da
    /// aritmética `base + offset + (intid / 32) * 4` feita à mão.
    Distribuidor {
        (0x000 => ctlr: ReadWrite<u32>),
        (0x004 => _reservado0),
        /// Um bit por INTID: escrever 1 habilita aquela linha.
        (0x100 => isenabler: [ReadWrite<u32>; 32]),
        /// Um bit por INTID: escrever 1 desabilita aquela linha.
        (0x180 => icenabler: [ReadWrite<u32>; 32]),
        (0x200 => _reservado1),
        /// Um byte por INTID, e cada bit desse byte é um núcleo destino.
        ///
        /// Só vale para interrupções compartilhadas (SPIs, INTID >= 32): as
        /// privadas de cada núcleo são entregues ao seu por construção.
        (0x800 => itargetsr: [ReadWrite<u8>; 1020]),
        (0xBFC => _reservado2),
        /// Gera uma interrupção de software (SGI): os bits 23-16 são os
        /// núcleos destino, e os quatro de baixo o número dela.
        (0xF00 => sgir: WriteOnly<u32>),
        (0xF04 => _reservado3),
        (0x1000 => @END),
    }
}

register_structs! {
    /// A *interface de CPU*: por onde este núcleo reconhece e finaliza as
    /// interrupções que recebe.
    InterfaceDeCpu {
        (0x000 => ctlr: ReadWrite<u32>),
        /// Máscara de prioridade: o GIC só entrega interrupções de prioridade
        /// numericamente *menor* que este valor.
        (0x004 => pmr: ReadWrite<u32>),
        (0x008 => _reservado0),
        /// Reconhecimento. A leitura tem efeito colateral: marca a
        /// interrupção como em atendimento.
        (0x00C => iar: ReadOnly<u32>),
        /// Fim de interrupção.
        (0x010 => eoir: WriteOnly<u32>),
        (0x014 => _reservado1),
        (0x1000 => @END),
    }
}

/// Os registradores do distribuidor.
///
/// É seguro: o endereço é fixo e o bloco está sempre acessível. Antes de a
/// MMU ligar porque não há tradução, e depois dela porque o mapa é de
/// identidade — nos dois casos, o mesmo endereço.
fn distribuidor() -> &'static Distribuidor {
    // SAFETY: endereço fixo do GIC da máquina `virt`, confirmado no device
    // tree. O bloco é de dispositivo e existe durante toda a vida do kernel.
    unsafe { &*(GICD_BASE as *const Distribuidor) }
}

/// Os registradores da interface de CPU deste núcleo.
fn interface_de_cpu() -> &'static InterfaceDeCpu {
    // SAFETY: mesma justificativa de `distribuidor`.
    unsafe { &*(GICC_BASE as *const InterfaceDeCpu) }
}

/// INTID do timer físico de EL1.
///
/// As interrupções privadas de cada núcleo (PPIs) ocupam os INTIDs 16 a 31; o
/// timer físico não-seguro de EL1 é o PPI 14, ou seja, INTID 30.
pub const INTID_TIMER: u32 = 30;

/// INTID da PL011 na máquina `virt`.
///
/// As interrupções de periférico (SPIs) começam no INTID 32, e o device tree
/// do QEMU declara a UART como SPI 1 — daí 33. Confirmado no mesmo dump de
/// device tree que deu o endereço da porta.
pub const INTID_UART: u32 = 33;

/// A interrupção de software que manda um núcleo parar — ver
/// [`super::smp::parar_os_outros`].
///
/// As dezesseis primeiras INTIDs são as SGIs: nascem de uma escrita de outro
/// núcleo no distribuidor, e não de um dispositivo.
pub const SGI_PARAR: u32 = 1;

/// A interrupção de software que só acorda um núcleo — ver
/// [`crate::nucleos::cutucar`].
pub const SGI_CUTUCAO: u32 = 0;

/// O número de interface de CPU de cada núcleo, como máscara de um bit.
///
/// É o que o GIC entende por "destino". Não se supõe que seja `1 << índice`:
/// cada núcleo lê a própria no distribuidor, onde o primeiro registrador de
/// destino é banqueado e devolve, a quem lê, o bit dele.
static INTERFACES: [AtomicU8; MAIS_INTERFACES] = [const { AtomicU8::new(0) }; MAIS_INTERFACES];

/// Quantas interfaces de CPU o GICv2 endereça: a lista de destino de uma
/// SGI e o `ITARGETSR` de uma linha têm um bit por interface, oito.
pub const MAIS_INTERFACES: usize = 8;

/// INTID devolvido pelo GIC quando não há interrupção pendente de verdade.
///
/// Reconhecer uma interrupção espúria é normal (pode acontecer quando outra
/// coisa mascara a interrupção entre o disparo e o reconhecimento) e ela
/// **não** deve ser finalizada — sinalizar fim de uma interrupção que nunca
/// começou desregula a contabilidade interna do controlador.
const INTID_ESPURIO: u32 = 1023;

/// Intervalo, em ciclos do timer, entre duas interrupções.
///
/// Guardado porque o timer genérico dispara uma vez por prazo: depois de
/// disparar, o handler escreve o seguinte — o que venceu mais este
/// intervalo, ver [`PRAZO`]. Sai com `Release`, depois da [`ORIGEM`].
static INTERVALO: AtomicU32 = AtomicU32::new(0);

/// O próximo disparo de cada núcleo, em ciclos do contador físico
/// (`CNTPCT_EL0`): o valor que está no `CNTP_CVAL_EL0` dele.
///
/// # Pelo prazo, e não pela distância
///
/// O timer compara o contador com um prazo e dispara uma vez; quem o quer
/// periódico escreve o prazo seguinte a cada disparo. Ele era rearmado pelo
/// `CNTP_TVAL_EL0` — a distância *a partir de agora* — no fim do handler:
/// cada período durava o intervalo mais o atraso da interrupção e o handler
/// inteiro. Todo núcleo perdia o atraso de cada interrupção, e com eles o
/// relógio: a bancada de tempo media o relógio do kernel do ARM a -12 681
/// ppm do contador, contra -25 no x86 na mesma rodada — no x86 a taxa
/// mudava de uma CI para outra, pelo período do APIC (ver `apic::PRAZO`). E
/// o núcleo dos dispositivos, que recolhe os dispositivos e apresenta a
/// tela no tique e no cutucão, perdia do pulso também tudo o que fazia ali
/// — na CI 508, "relogio andou 51, o primeiro nucleo contou 40". Essa parte
/// o relógio só sentia com um núcleo só — com vários, outro o anda no lugar
/// (ver `tempo::tick`) —, e então todo prazo que mede nele também.
///
/// Agora os núcleos têm uma grade só, a do primeiro ([`ORIGEM`]): o
/// primeiro prazo de cada um é o primeiro ponto dela depois do contador de
/// agora ([`armar`], no boot e ao acordar), e cada um dos seguintes é o que
/// venceu mais um intervalo ([`rearmar`]). Um atraso menor que um período
/// não custa tique: o disparo chega atrasado, e o seguinte vem na hora da
/// grade.
///
/// # Uma grade só, e não uma por núcleo
///
/// O relógio do sistema anda pelo núcleo que não viu ninguém andar desde o
/// próprio tique anterior (`tempo::avancar`), e a regra supõe que um núcleo
/// não tiqueia de novo num ponto cujo avanço já viu. O #455 armava o
/// primeiro prazo de cada núcleo a partir do contador dele — uma grade por
/// núcleo, cada uma na sua fase —, e um tique atrasado era seguido do
/// próximo a menos de um período: se o atrasado tinha visto o avanço de
/// outro núcleo, e o seguinte chegava antes do próximo desse outro, ele
/// andava o relógio de novo. O mesmo período contava duas vezes, e o
/// relógio passava à frente do contador sob carga: com os quatro núcleos
/// mascarados em trechos de 3 a 9 ms por três segundos — o caso do
/// adversário do #455 —, ele andou 307, 332 e 322 contra 300 períodos, em
/// depuração. Na mesma grade, o seguinte chega junto com o do outro, e um
/// só dos dois anda. As três propriedades que a regra pede estão em
/// `tempo::avancar`.
///
/// # Um atraso maior que um período
///
/// Não vira rajada. O timer guarda o nível, e não a conta: ao desmascarar
/// chega **um** disparo, e não um por prazo perdido. Os perdidos são
/// pulados, e o próximo é o primeiro da grade ainda no futuro
/// ([`crate::tempo::proximo_prazo`]). Pular, e não compensar, é o que o
/// timer do x86 faz também, e o relógio do sistema não depende de um
/// núcleo só. Compensar seria a rajada, e pior que um tique a
/// menos: com outro núcleo andando o relógio durante o atraso, cada disparo
/// dela — sem ninguém tiqueando no meio — andaria o relógio de novo
/// (`tempo::avancar`), e o tempo mascarado contaria duas vezes.
///
/// # A volta do contador, e um salto de mais de 2^63
///
/// Inalcançáveis, e ditos aqui para quem um dia os alcançar. O contador tem
/// pelo menos 56 bits, e a arquitetura promete ao menos 40 anos até a
/// volta; a 62,5 MHz do `cortex-a72` do emulador, 64 bits são uns 9 mil
/// anos, e a 1 GHz, 584. O comparador do timer não tem sinal: um prazo que
/// passou de 2^64 antes do contador parece vencido, e o timer dispara
/// seguido até o contador voltar também — até um período inteiro de
/// disparos, cada um com o atraso lido negativo, o prazo conservado, um
/// tique contado e, se este núcleo anda o relógio, um avanço: uns segundos
/// de relógio de uma vez, uma vez a cada volta. O `CNTP_TVAL_EL0` de antes
/// tinha a mesma volta. E um contador que saltasse mais de 2^63 à frente
/// do prazo — só um deslocamento posto perto de 2^64 por um hipervisor ou
/// um firmware — teria o atraso lido negativo, e o timer dispararia seguido
/// até a volta seguinte. Nenhum dos dois vira pânico nem trava a conta.
///
/// Cada núcleo só lê e escreve o seu, com as interrupções mascaradas — no
/// handler, ou ao ligar o timer —, e por isso `Relaxed` basta.
static PRAZO: [AtomicU64; MAX_NUCLEOS] = [const { AtomicU64::new(0) }; MAX_NUCLEOS];

/// A origem da grade de todos os núcleos: o contador quando o primeiro ligou
/// o timer ([`init_timer`]) — ver [`PRAZO`].
///
/// Escrita uma vez, no primeiro núcleo, antes do [`INTERVALO`], que sai com
/// `Release`: quem lê o intervalo diferente de zero com `Acquire` lê esta
/// também. E os outros núcleos só a leem depois de acordar, pelo caminho do
/// intervalo: o `init_timer` roda em `init_interrupcoes`, muito antes de
/// `nucleos::ligar_os_demais`, e o `smp::partir` de cada núcleo faz um `dsb
/// sy` (em `limpar_ate_a_ram`) antes do `CPU_ON` que o acorda.
static ORIGEM: AtomicU64 = AtomicU64::new(0);

/// Só para a suíte: quantos disparos do timer acharam o prazo do núcleo
/// ainda no futuro, no começo do handler — ver [`conferir_o_prazo_de_teste`]
/// e [`antecipados_de_teste`].
#[cfg(feature = "modo-teste")]
static ANTECIPADOS_DE_TESTE: AtomicU64 = AtomicU64::new(0);

/// Só para a suíte: quantos rearmes acharam o [`PRAZO`] do núcleo diferente
/// do `CNTP_CVAL_EL0` dele — ver [`divergencias_de_teste`].
#[cfg(feature = "modo-teste")]
static DIVERGENCIAS_DE_TESTE: AtomicU64 = AtomicU64::new(0);

/// Só para a suíte: o contador que o [`armar`] de cada núcleo leu, e o
/// primeiro prazo que ele calculou — ver [`primeiro_prazo_de_teste`]. Um
/// bit por núcleo em [`PRIMEIROS_DE_TESTE`] diz quais anotaram.
#[cfg(feature = "modo-teste")]
static PRIMEIRO_AGORA_DE_TESTE: [AtomicU64; MAX_NUCLEOS] =
    [const { AtomicU64::new(0) }; MAX_NUCLEOS];
#[cfg(feature = "modo-teste")]
static PRIMEIRO_PRAZO_DE_TESTE: [AtomicU64; MAX_NUCLEOS] =
    [const { AtomicU64::new(0) }; MAX_NUCLEOS];
#[cfg(feature = "modo-teste")]
static PRIMEIROS_DE_TESTE: AtomicU64 = AtomicU64::new(0);

/// Inicializa o GIC e habilita a linha do timer.
///
/// # Safety
///
/// Precisa ser chamada com as interrupções mascaradas e a tabela de vetores
/// já instalada.
pub unsafe fn init() {
    let gicd = distribuidor();
    let gicc = interface_de_cpu();

    // Distribuidor: liga o encaminhamento de interrupções.
    gicd.ctlr.set(1);

    // Máscara de prioridade da interface de CPU. Um valor alto deixa passar
    // tudo: o GIC só entrega interrupções de prioridade *numericamente menor*
    // que a máscara, e 0xFF é o maior valor possível.
    gicc.pmr.set(0xFF);

    // Liga a interface de CPU.
    gicc.ctlr.set(1);

    // O timer desligado antes de a linha dele valer — ver
    // `desligar_o_timer`.
    desligar_o_timer();
    habilitar_linha(INTID_TIMER);
    habilitar_linha(SGI_PARAR);
    habilitar_linha(SGI_CUTUCAO);
    registrar_interface();
}

/// A máscara de interface do primeiro núcleo, para onde vão as linhas
/// compartilhadas — ver [`habilitar_spi`].
///
/// Lida do GIC, e não escrita como `0b1`: a interface 0 é o núcleo de boot no
/// QEMU, mas a especificação não promete isso, e numa placa em que o boot
/// fosse por outra interface, todas as interrupções de dispositivo iriam a
/// um núcleo que não as trata — ou a nenhum, se ele estivesse desligado.
/// Antes de o primeiro núcleo se registrar, a interface 0, que era o valor
/// de sempre.
fn interface_do_primeiro() -> u8 {
    match INTERFACES[0].load(Ordering::Acquire) {
        0 => 0b0000_0001,
        m => m,
    }
}

/// Anota a máscara de interface de CPU deste núcleo.
fn registrar_interface() {
    let indice = super::nucleo_atual();
    if indice >= MAIS_INTERFACES {
        // Não acontece: a descoberta não liga um núcleo que o GIC não
        // alcança — ver `nucleo_enderecavel`.
        return;
    }
    // O primeiro registrador de destino cobre as INTIDs privadas, e é
    // banqueado: cada núcleo lê nele o próprio bit.
    INTERFACES[indice].store(distribuidor().itargetsr[0].get(), Ordering::Release);
}

/// Liga a interface de CPU **deste** núcleo e o timer dele.
///
/// O distribuidor é um só e já está ligado; a interface de CPU é uma por
/// núcleo, banqueada no mesmo endereço, e cada núcleo liga a sua. As linhas
/// privadas — o timer e as SGIs — também são banqueadas: habilitá-las no
/// primeiro núcleo não as habilita aqui.
///
/// # Safety
///
/// Precisa rodar no núcleo que acabou de acordar, com as interrupções
/// mascaradas e a tabela de vetores dele instalada.
pub unsafe fn ligar_neste_nucleo() {
    let gicc = interface_de_cpu();
    gicc.pmr.set(0xFF);
    gicc.ctlr.set(1);
    // O timer deste núcleo desligado antes de a linha dele valer — ver
    // `desligar_o_timer`. Sem intervalo, fica desligado.
    desligar_o_timer();
    habilitar_linha(INTID_TIMER);
    habilitar_linha(SGI_PARAR);
    habilitar_linha(SGI_CUTUCAO);
    registrar_interface();

    // O primeiro prazo deste núcleo é o primeiro ponto da grade do primeiro
    // depois do contador de agora: uma grade só — ver `PRAZO`. O intervalo
    // com `Acquire`: diferente de zero, a origem já está escrita.
    let intervalo = INTERVALO.load(Ordering::Acquire);
    if intervalo != 0 {
        armar(intervalo);
        CNTP_CTL_EL0.write(CNTP_CTL_EL0::ENABLE::SET + CNTP_CTL_EL0::IMASK::CLEAR);
    }
}

/// Desliga o timer físico deste núcleo — sem `ENABLE`, e com o `IMASK` —,
/// e espera a escrita valer (`isb`). Chamada antes de a linha do timer ser
/// habilitada no distribuidor, no primeiro núcleo e em cada um que acorda.
///
/// # Por que antes da linha
///
/// O timer pode vir ligado de quem rodou antes — um firmware, um kernel
/// anterior —, com o prazo vencido e a linha levantada. O GICv2 do QEMU,
/// ao habilitar uma linha de nível levantada, a marca pendente (a escrita
/// do `GICD_ISENABLER` em `hw/intc/arm_gic.c`), e a marca sobrevive à
/// linha descer: armar o prazo para a frente não a apagaria, e o primeiro
/// disparo chegaria com o prazo no futuro. Desligado antes, a linha está
/// baixa quando é habilitada.
///
/// Cobre também o `CNTFRQ_EL0` em zero: sem frequência, [`init_timer`] não
/// arma, e o timer fica desligado — e não ligado pelo firmware, disparando
/// sem ninguém rearmar.
///
/// # A pendência velha não se limpa
///
/// Uma pendência marcada antes do kernel — pela linha habilitada levantada,
/// ou escrita no `GICD_ISPENDR` — sobraria. Nenhum caminho de boot daqui a
/// deixa: o reset do emulador zera o distribuidor, a linha do timer de cada
/// núcleo só é habilitada aqui, e o firmware do iniciador não a deixa — o
/// caso que conta os disparos antecipados passa pelos dois caminhos. E
/// limpá-la não seria de graça: no GIC do QEMU, o `GICD_ICPENDR` de uma
/// linha privada limpa a pendência dela em **todos** os núcleos (o próprio
/// fonte diz que não sabe se é o certo), e um núcleo acordando mexeria no
/// timer dos que já rodam.
fn desligar_o_timer() {
    CNTP_CTL_EL0.write(CNTP_CTL_EL0::ENABLE::CLEAR + CNTP_CTL_EL0::IMASK::SET);
    barrier::isb(barrier::SY);
}

/// Manda a SGI `intid` aos núcleos da máscara `nucleos` (bit `i` = núcleo
/// `i` do kernel).
pub fn enviar_sgi(nucleos: crate::nucleos::Mascara, intid: u32) {
    let mut destino = 0u32;
    for (i, interface) in INTERFACES.iter().enumerate() {
        if nucleos & (1 << i) != 0 {
            destino |= interface.load(Ordering::Acquire) as u32;
        }
    }
    if destino == 0 {
        return;
    }
    // A barreira garante que o que o núcleo escreveu antes do aviso já está
    // visível a quem o recebe.
    aarch64_cpu::asm::barrier::dsb(aarch64_cpu::asm::barrier::ISH);
    distribuidor().sgir.set((destino << 16) | (intid & 0xF));
}

/// Habilita uma linha de interrupção no distribuidor.
///
/// Cada registrador de `ISENABLER` cobre 32 linhas, uma por bit.
fn habilitar_linha(intid: u32) {
    let indice = (intid / 32) as usize;
    distribuidor().isenabler[indice].set(1 << (intid % 32));
}

/// Habilita a linha da UART e a roteia para este núcleo.
///
/// # Por que uma SPI dá mais trabalho que o timer
///
/// O timer é uma PPI: uma interrupção *privada*, que existe separadamente em
/// cada núcleo e por construção só pode ser entregue ao seu. Uma SPI é
/// compartilhada por todo o sistema, então o distribuidor precisa ser
/// informado de para quem entregá-la — e o valor de reset desse registrador é
/// zero, ou seja, "para ninguém". Sem esta escrita a interrupção é habilitada
/// e simplesmente nunca chega.
///
/// # Safety
///
/// Exige tabela de vetores instalada e [`init`] já executado.
pub unsafe fn habilitar_uart() {
    // Entrega ao núcleo 0. Um byte por INTID, um bit por interface dentro
    // dele.
    distribuidor().itargetsr[INTID_UART as usize].set(interface_do_primeiro());
    habilitar_linha(INTID_UART);
}

/// Traduz um especificador do device tree em INTID.
///
/// O device tree não nomeia interrupções por INTID: ele diz a classe e o
/// número **dentro** da classe. As PPIs, privadas de cada núcleo, ocupam os
/// INTIDs 16 a 31; as SPIs, compartilhadas, começam em 32. Somar o
/// deslocamento certo é a tradução inteira.
///
/// Devolve `None` para uma classe que este kernel não trata — as interrupções
/// de software (SGIs) são geradas por núcleos, não por dispositivos, e não há
/// o que um driver de PCI faça com uma.
pub fn intid_de(tipo: u32, numero: u32) -> Option<u32> {
    const TIPO_SPI: u32 = 0;
    const TIPO_PPI: u32 = 1;
    const PRIMEIRA_PPI: u32 = 16;
    const PRIMEIRA_SPI: u32 = 32;

    let intid = match tipo {
        TIPO_SPI => PRIMEIRA_SPI.checked_add(numero)?,
        TIPO_PPI => PRIMEIRA_PPI.checked_add(numero)?,
        _ => return None,
    };

    // O teto do GIC é 1020; acima disso os números são reservados, e 1023 é o
    // "nenhuma interrupção" que a leitura de reconhecimento devolve.
    (intid < 1020).then_some(intid)
}

/// Habilita uma linha compartilhada e a roteia para o primeiro núcleo, que é
/// o dos dispositivos — ver [`crate::nucleos`].
///
/// Mesma armadilha que [`habilitar_uart`] documenta: o valor de reset do
/// registrador de destino é zero, ou seja, "para ninguém". Sem a escrita a
/// linha fica habilitada e a interrupção simplesmente nunca chega.
///
/// # Safety
///
/// Exige tabela de vetores instalada, [`init`] já executado, e que exista
/// quem trate a linha.
pub unsafe fn habilitar_spi(intid: u32) {
    let indice = intid as usize;
    if indice >= 1020 {
        return;
    }
    distribuidor().itargetsr[indice].set(interface_do_primeiro());
    habilitar_linha(intid);
}

/// Desabilita uma linha compartilhada no distribuidor: ela deixa de chegar
/// a qualquer núcleo. É o que o botão de energia faz com a linha dele numa
/// tempestade — ver `super::botao`.
///
/// # Safety
///
/// Desabilitar uma linha que alguém ainda espera deixa o sistema sem aquele
/// evento, sem aviso nenhum.
pub unsafe fn desabilitar_spi(intid: u32) {
    if !(32..1020).contains(&intid) {
        return;
    }
    distribuidor().icenabler[(intid / 32) as usize].set(1 << (intid % 32));
}

/// Reconhece a interrupção pendente e devolve o valor **inteiro** do
/// registrador de reconhecimento.
///
/// A leitura tem efeito colateral — marca a interrupção como em atendimento
/// —, e `ReadOnly` garante que seja volátil.
///
/// # Por que inteiro, e não só o INTID
///
/// Porque numa SGI os bits 12-10 dizem qual núcleo a mandou, e o fim de
/// interrupção precisa deles de volta: o GIC v2 trata a mesma SGI vinda de
/// núcleos diferentes como interrupções diferentes. Finalizar só com o
/// INTID deixaria a de outro núcleo ativa para sempre. Com um núcleo só não
/// havia SGI, e cortar os bits não custava nada.
fn reconhecer() -> u32 {
    interface_de_cpu().iar.get()
}

/// Sinaliza o fim do atendimento, com o valor que [`reconhecer`] leu.
///
/// Sem isto o GIC considera a interrupção ainda ativa e não entrega outra da
/// mesma linha. O sintoma é o timer disparar uma única vez.
fn finalizar(reconhecido: u32) {
    interface_de_cpu().eoir.set(reconhecido);
}

/// Frequência do timer genérico, em Hz, informada pelo próprio processador.
fn frequencia_do_contador() -> u32 {
    CNTFRQ_EL0.get() as u32
}

/// O contador físico, lido depois de tudo o que veio antes (`isb`): sem a
/// barreira, a leitura do `CNTPCT_EL0` pode vir adiantada, de antes das
/// instruções anteriores — e de antes de outra leitura dele.
fn contador() -> u64 {
    barrier::isb(barrier::SY);
    CNTPCT_EL0.get()
}

/// Arma o primeiro disparo deste núcleo: o primeiro ponto da grade comum
/// ([`ORIGEM`], de `ciclos` em `ciclos`) depois do contador de agora — à
/// frente dele, e a no máximo `ciclos`. Ver [`PRAZO`].
///
/// O contador é lido depois da barreira ([`contador`]): no primeiro núcleo,
/// esta leitura vem logo depois da que deu a origem, e adiantada poderia
/// dar menos que ela — o primeiro prazo seria a própria origem, já
/// passada. O prazo vai para o `CNTP_CVAL_EL0` antes de quem chama ligar o
/// timer, e o `isb` depois dele faz a escrita valer antes disso: o valor de
/// antes, de reset ou do firmware, não chega a disparar.
fn armar(ciclos: u32) {
    let origem = ORIGEM.load(Ordering::Relaxed);
    let agora = contador();
    let prazo = crate::tempo::proximo_prazo(origem, agora, u64::from(ciclos));
    let n = super::nucleo_atual();
    PRAZO[n].store(prazo, Ordering::Relaxed);
    CNTP_CVAL_EL0.set(prazo);
    barrier::isb(barrier::SY);
    #[cfg(feature = "modo-teste")]
    {
        PRIMEIRO_AGORA_DE_TESTE[n].store(agora, Ordering::SeqCst);
        PRIMEIRO_PRAZO_DE_TESTE[n].store(prazo, Ordering::SeqCst);
        PRIMEIROS_DE_TESTE.fetch_or(crate::nucleos::bit(n), Ordering::SeqCst);
    }
}

/// Rearma este núcleo, de dentro do handler, para o prazo seguinte ao que
/// venceu, na grade comum — ver [`PRAZO`] e [`crate::tempo::proximo_prazo`].
///
/// O contador é lido aqui, no fim do handler: o prazo que passou durante o
/// trabalho do tique é pulado, e o núcleo dos dispositivos não emenda um
/// tique no outro.
///
/// # O que o rearme supõe do timer
///
/// - **O prazo ainda no futuro**, o atraso negativo, não acontece num
///   disparo de verdade: o timer só levanta a linha com o contador já no
///   prazo, e só este núcleo escreve o dele. Se acontecer, o prazo fica, e
///   o disparo vem na hora dele; a suíte conta quantas vezes, com o
///   contador lido no começo do handler, e não aqui (`antecipados_de_teste`,
///   em [`tratar`]), e confere aqui que o `PRAZO` é o que o `CNTP_CVAL_EL0`
///   tem (`divergencias_de_teste`) — sem isso, um `PRAZO` que deixasse de
///   ser escrito desligaria a conta dos antecipados.
/// - **O prazo escrito no passado.** Entre a leitura do contador e a
///   escrita do `CNTP_CVAL_EL0` o núcleo pode parar — o hospedeiro do
///   emulador o tira da CPU — e o prazo calculado já ter passado quando é
///   escrito. O comparador do timer é `CNTPCT >= CVAL`: a linha continua
///   levantada, e o disparo vem logo depois do fim desta interrupção. É o
///   daquele prazo, que de fato passou, e chega atrasado como chegaria
///   mascarado; o handler seguinte pula o que mais tiver passado. Um disparo
///   a mais por atraso, e nunca uma rajada.
/// - **O `isb` depois do `CNTP_CVAL_EL0`**: a escrita do registrador de
///   sistema vale antes do fim da interrupção ([`finalizar`]). Sem ele, num
///   núcleo com o timer físico de verdade, o fim chegaria ao GIC com a linha
///   ainda levantada pelo prazo velho, e a interrupção voltaria com o prazo
///   novo no futuro. No emulador a escrita recalcula a linha na hora, e a
///   barreira não muda nada que se veja.
/// - **O `ISTATUS` não é lido.** O handler não confere, no `CNTP_CTL_EL0`,
///   se a condição do timer ainda vale antes de contar o tique: com o `isb`,
///   o fim da interrupção já vê a linha do prazo novo, e um disparo com o
///   prazo no futuro só viria do timer deixado ligado por quem rodou antes:
///   a pendência que a linha habilitada levantada marcaria, e que o
///   [`desligar_o_timer`] evita — uma marcada antes do kernel sobraria, e
///   nenhum caminho de boot daqui a deixa. A suíte conta os que chegarem
///   (`antecipados_de_teste`); no x86 a recusa é necessária, e está lá
///   (`apic::chegou_o_prazo`).
fn rearmar(ciclos: u32) {
    let n = super::nucleo_atual();
    let vencido = PRAZO[n].load(Ordering::Relaxed);
    let agora = contador();
    #[cfg(feature = "modo-teste")]
    if CNTP_CVAL_EL0.get() != vencido {
        DIVERGENCIAS_DE_TESTE.fetch_add(1, Ordering::SeqCst);
    }
    let proximo = crate::tempo::proximo_prazo(vencido, agora, u64::from(ciclos));
    PRAZO[n].store(proximo, Ordering::Relaxed);
    CNTP_CVAL_EL0.set(proximo);
    barrier::isb(barrier::SY);
}

/// Só para a suíte: o disparo do timer deste núcleo chegou com o prazo dele
/// ainda no futuro? Conta em [`ANTECIPADOS_DE_TESTE`].
///
/// Chamada no começo do ramo do timer, em [`tratar`], antes do trabalho do
/// tique. Com o contador lido no fim do handler — no [`rearmar`], onde a
/// conta morava —, um disparo antecipado a menos de um handler do prazo já o
/// teria passado, e contava como tique sem ser visto (o achado 5 do
/// adversário do #455-B). É a leitura do x86, no começo do handler
/// (`apic::chegou_o_prazo`): lá, para recusar o tique; aqui, só para contar.
#[cfg(feature = "modo-teste")]
fn conferir_o_prazo_de_teste() {
    let n = super::nucleo_atual();
    let prazo = PRAZO[n].load(Ordering::Relaxed);
    if (contador().wrapping_sub(prazo) as i64) < 0 {
        ANTECIPADOS_DE_TESTE.fetch_add(1, Ordering::SeqCst);
    }
}

/// Só para a suíte: o contador que o [`armar`] do núcleo `i` leu e o
/// primeiro prazo que ele calculou, ou `None` se o núcleo não armou. Os dois
/// valores que a conta usou: a distância entre eles não depende de quando a
/// suíte olha, nem de uma parada do hospedeiro no meio.
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

/// Só para a suíte: a origem da grade comum — ver [`ORIGEM`].
#[cfg(feature = "modo-teste")]
pub fn origem_de_teste() -> u64 {
    ORIGEM.load(Ordering::SeqCst)
}

/// Só para a suíte: quantos rearmes, desde o boot, acharam o [`PRAZO`] do
/// núcleo diferente do `CNTP_CVAL_EL0` dele. Zero: o `PRAZO` é o espelho do
/// registrador.
#[cfg(feature = "modo-teste")]
pub fn divergencias_de_teste() -> u64 {
    DIVERGENCIAS_DE_TESTE.load(Ordering::SeqCst)
}

/// Só para a suíte: quantos disparos do timer, desde o boot, acharam o
/// prazo do núcleo ainda no futuro no começo do handler. Zero com um prazo
/// por núcleo — ver [`rearmar`] e [`conferir_o_prazo_de_teste`].
#[cfg(feature = "modo-teste")]
pub fn antecipados_de_teste() -> u64 {
    ANTECIPADOS_DE_TESTE.load(Ordering::SeqCst)
}

/// Só para a suíte: o intervalo do timer, em ciclos do contador.
#[cfg(feature = "modo-teste")]
pub fn intervalo_de_teste() -> u64 {
    u64::from(INTERVALO.load(Ordering::Relaxed))
}

/// Configura o timer para disparar periodicamente na frequência pedida.
///
/// Devolve a frequência efetiva, que pode diferir da pedida porque o
/// intervalo em ciclos é inteiro.
///
/// # Safety
/// Precisa ser chamada com as interrupções mascaradas.
pub unsafe fn init_timer(hz_desejado: u32) -> u32 {
    let frequencia = frequencia_do_contador();

    // `CNTFRQ_EL0` não é medido: é um registrador que o firmware preenche
    // para dizer ao software a que taxa o contador anda. Um firmware que não
    // o preenche deixa zero ali — e o contador continua andando do mesmo
    // jeito, porque este registrador só descreve, não controla.
    //
    // É por isso que o zero é perigoso e não inofensivo. `0 / hz` é zero, e o
    // `.max(1)` logo abaixo — que existe justamente para impedir um intervalo
    // de zero ciclos — o transformaria num intervalo de **um** ciclo do
    // contador real. A tempestade de interrupções que aquele mínimo evita
    // chegaria pela outra ponta: dezenas de milhões de disparos por segundo,
    // cada um rearmando o próximo, e nenhum ciclo sobrando para o resto.
    //
    // Sem frequência declarada não há como programar o timer, e é melhor
    // ficar sem relógio do que travar a máquina com um. O resto do kernel já
    // sabe viver assim: `tempo` reporta uptime zero em vez de inventar um
    // número, e `tarefas::relogio::por_ms` degrada para polling com aviso.
    //
    // O timer fica desligado: [`init`] o desligou antes de habilitar a linha
    // dele (`desligar_o_timer`), e sem intervalo nenhum núcleo o arma.
    if frequencia == 0 || hz_desejado == 0 {
        crate::log_error!(
            "irq",
            "CNTFRQ_EL0 diz {} Hz; sem timer, o kernel segue sem relogio",
            frequencia
        );
        return 0;
    }

    // Mínimo de 1 para não armar um timer de zero ciclos, que dispararia
    // continuamente e travaria o sistema numa tempestade de interrupções.
    let intervalo = (frequencia / hz_desejado).max(1);

    // A grade de todos os núcleos parte do contador de agora, e a origem sai
    // antes do intervalo — ver `ORIGEM`. O primeiro prazo deste núcleo é o
    // ponto seguinte dela; os dos outros, o primeiro dela depois de acordarem.
    ORIGEM.store(contador(), Ordering::Relaxed);
    INTERVALO.store(intervalo, Ordering::Release);
    armar(intervalo);
    CNTP_CTL_EL0.write(CNTP_CTL_EL0::ENABLE::SET + CNTP_CTL_EL0::IMASK::CLEAR);

    frequencia / intervalo
}

/// Atende a interrupção de hardware pendente. Chamado pelo handler de IRQ.
///
/// Devolve `true` quando o escalonador pediu uma troca de fio. Quem troca é o
/// handler, e não esta função, porque a troca precisa acontecer depois do fim
/// de interrupção e com o quadro de exceção em mãos.
pub fn tratar() -> bool {
    let reconhecido = reconhecer();
    let intid = reconhecido & 0x3FF;

    // Espúria: nada a atender e, principalmente, nada a finalizar.
    if intid == INTID_ESPURIO {
        return false;
    }

    let mut preemptar = false;

    if intid == SGI_PARAR {
        // O sistema parou em outro núcleo. Finalizar antes de parar não é
        // cortesia: sem o fim, a interface deste núcleo fica com a SGI
        // ativa, e o relatório de falha que lê o GIC veria um estado falso.
        finalizar(reconhecido);
        super::smp::atender_parada();
        return false;
    }

    if intid == SGI_CUTUCAO {
        // Só acordar: quem cutucou já mudou o que tinha de mudar, e este
        // núcleo confere ao voltar do `wfi`.
        crate::irq::contabilizar(intid as usize);
        finalizar(reconhecido);
        crate::nucleos::ao_ser_cutucado();
        return false;
    }

    if intid == INTID_TIMER {
        // Na suíte, o disparo conferido contra o prazo antes do trabalho do
        // tique — ver `conferir_o_prazo_de_teste`.
        #[cfg(feature = "modo-teste")]
        conferir_o_prazo_de_teste();
        // Cada núcleo conta o próprio pulso e o oferece ao relógio, que anda
        // uma vez por período por qualquer núcleo vivo — ver `tempo::tick`.
        crate::nucleos::tique_local();
        crate::tempo::tick();
        preemptar = crate::fios::tique();

        // O timer genérico dispara uma vez por prazo: sem o seguinte, esta
        // seria a última interrupção que receberíamos. Pelo prazo que venceu,
        // e não a partir de agora — ver `PRAZO`.
        rearmar(INTERVALO.load(Ordering::Relaxed));
    }

    if intid == INTID_UART {
        // Mínimo indispensável: tirar os bytes do hardware e acordar quem os
        // espera. O trabalho de verdade acontece na tarefa, fora do handler.
        crate::tarefas::entrada::coletar();
    }

    // As linhas que não são deste backend são dos dispositivos que o kernel
    // dirige. Perguntar a eles é o que evita uma tabela de handlers aqui —
    // e, com dois dispositivos, uma tabela seria generalidade sem cliente.
    // E a do controlador da tecla de energia: ver `super::botao`.
    if intid != INTID_TIMER && intid != INTID_UART {
        let dispositivos = crate::virtio::atender_interrupcao(intid);
        super::botao::atender(intid, dispositivos);
    }

    crate::irq::contabilizar(intid as usize);
    finalizar(reconhecido);

    preemptar
}
