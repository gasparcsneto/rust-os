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
//!   mágica de hardware.

use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use aarch64_cpu::registers::{CNTFRQ_EL0, CNTP_CTL_EL0, CNTP_TVAL_EL0};
use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::register_structs;
use tock_registers::registers::{ReadOnly, ReadWrite, WriteOnly};

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
        (0x180 => _reservado1),
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
static INTERFACES: [AtomicU8; crate::nucleos::MAX_NUCLEOS] =
    [const { AtomicU8::new(0) }; crate::nucleos::MAX_NUCLEOS];

/// INTID devolvido pelo GIC quando não há interrupção pendente de verdade.
///
/// Reconhecer uma interrupção espúria é normal (pode acontecer quando outra
/// coisa mascara a interrupção entre o disparo e o reconhecimento) e ela
/// **não** deve ser finalizada — sinalizar fim de uma interrupção que nunca
/// começou desregula a contabilidade interna do controlador.
const INTID_ESPURIO: u32 = 1023;

/// Intervalo, em ciclos do timer, entre duas interrupções.
///
/// Guardado porque o timer genérico é *one-shot*: depois de disparar, ele
/// precisa ser rearmado com a mesma contagem, de dentro do handler.
static INTERVALO: AtomicU32 = AtomicU32::new(0);

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
    let indice = super::nucleo_atual().min(crate::nucleos::MAX_NUCLEOS - 1);
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
    habilitar_linha(INTID_TIMER);
    habilitar_linha(SGI_PARAR);
    habilitar_linha(SGI_CUTUCAO);
    registrar_interface();

    let intervalo = INTERVALO.load(Ordering::Relaxed);
    if intervalo != 0 {
        armar(intervalo);
        CNTP_CTL_EL0.write(CNTP_CTL_EL0::ENABLE::SET + CNTP_CTL_EL0::IMASK::CLEAR);
    }
}

/// Manda a SGI `intid` aos núcleos da máscara `nucleos` (bit `i` = núcleo
/// `i` do kernel).
pub fn enviar_sgi(nucleos: u8, intid: u32) {
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

/// Arma o timer para disparar daqui a `ciclos`.
///
/// # Safety
/// Altera o estado do timer do processador.
fn armar(ciclos: u32) {
    CNTP_TVAL_EL0.set(ciclos as u64);
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
    INTERVALO.store(intervalo, Ordering::Relaxed);

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
        // Cada núcleo conta o próprio pulso; o relógio do sistema, só o
        // primeiro anda — ver `crate::nucleos`.
        crate::nucleos::tique_local();
        if crate::nucleos::e_o_primeiro() {
            crate::tempo::tick();
        }
        preemptar = crate::fios::tique();

        // O timer genérico é one-shot: sem rearmar aqui, esta seria a última
        // interrupção que receberíamos.
        armar(INTERVALO.load(Ordering::Relaxed));
    }

    if intid == INTID_UART {
        // Mínimo indispensável: tirar os bytes do hardware e acordar quem os
        // espera. O trabalho de verdade acontece na tarefa, fora do handler.
        crate::tarefas::entrada::coletar();
    }

    // As linhas que não são deste backend são dos dispositivos que o kernel
    // dirige. Perguntar a eles é o que evita uma tabela de handlers aqui —
    // e, com dois dispositivos, uma tabela seria generalidade sem cliente.
    if intid != INTID_TIMER && intid != INTID_UART {
        crate::virtio::atender_interrupcao(intid);
    }

    crate::irq::contabilizar(intid as usize);
    finalizar(reconhecido);

    preemptar
}
