//! Backend de arquitetura para x86_64.
//!
//! No x86 o trabalho pesado de boot já foi feito quando chegamos aqui: o
//! crate `bootloader` cuidou do modo real, da transição para long mode e da
//! montagem das tabelas de página iniciais, e nos entrega um [`BootInfo`]
//! pronto. Este módulo basicamente traduz esse `BootInfo` para as estruturas
//! neutras de [`crate::machine`] e segue para o fluxo comum.

pub mod contexto;
pub mod gdt;
pub mod idt;
pub mod paginacao;
pub mod pci;
pub mod pic;
pub mod uart;
pub mod usuario;

pub use contexto::{
    Contexto, ceder_cpu, preparar_contexto, preparar_contexto_de_fork, redirecionar_para,
};
pub use usuario::{definir_pilha_de_kernel, entrar as entrar_em_usuario, init as init_usuario};

use core::sync::atomic::{AtomicU64, Ordering};

use bootloader_api::BootInfo;
use bootloader_api::info::{MemoryRegionKind, PixelFormat};

use crate::machine::{Regiao, TipoRegiao, Video};

pub use uart::Uart;

/// Nome da arquitetura, exposto no protocolo do agente.
pub const fn nome() -> &'static str {
    "x86_64"
}

/// Onde o bootloader mapeou a memória física completa.
///
/// A sentinela `u64::MAX` distingue "não fornecido" de um deslocamento zero.
static DESLOCAMENTO_FISICO: AtomicU64 = AtomicU64::new(u64::MAX);

/// Configuração pedida ao bootloader.
///
/// O pedido que importa é `physical_memory`: sem ele, o bootloader não mapeia
/// a RAM física no espaço virtual, e ficaríamos sem qualquer forma de
/// *alcançar* as tabelas de página — cujos descritores contêm endereços
/// físicos, enquanto todo acesso nosso é virtual. É o que torna a paginação
/// editável.
const CONFIG: bootloader_api::BootloaderConfig = {
    use bootloader_api::config::Mapping;

    let mut config = bootloader_api::BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::FixedAddress(BASE_DA_MEMORIA_FISICA));
    config.mappings.kernel_base = Mapping::FixedAddress(BASE_DO_KERNEL);

    // Tudo o que o bootloader ainda escolhe sozinho — a pilha inicial, a
    // `BootInfo`, o framebuffer — precisa cair na metade alta. Sem este piso
    // ele procura um buraco livre a partir do zero, e foi o que aconteceu: o
    // mapa da memória física apareceu em 2 TiB, dentro da metade que agora
    // pertence ao usuário.
    config.mappings.dynamic_range_start = Some(BASE_DO_RESTO);
    config
};

// ---------------------------------------------------------------------------
// O mapa do espaço virtual
// ---------------------------------------------------------------------------
//
// A regra é uma só: **a metade baixa é do usuário, a alta é do kernel**.
//
// Não é estética. Uma tabela de tradução por processo se monta copiando as
// entradas de topo do kernel para a tabela nova; as que sobram são do
// processo. Isso só funciona se nenhuma entrada de topo for compartilhada
// entre os dois — e uma entrada de topo no x86 cobre 512 GiB.
//
// Antes disto o heap (64 GiB) e as pilhas de fio (128 GiB) moravam na mesma
// entrada de topo que o espaço do usuário (4 GiB). Copiar "as entradas do
// kernel" teria levado junto o mapa do processo anterior, ou deixado o kernel
// sem heap — conforme o lado que se escolhesse.
//
// Cada região ganha uma entrada de topo só dela, com folga de sobra entre
// elas. Desperdiçar espaço virtual num endereçamento de 48 bits não custa
// nada: o que custa é descobrir tarde que duas regiões se encostaram.

/// Onde o mapa da memória física inteira começa.
///
/// Fixo pelo mesmo motivo de [`BASE_DO_KERNEL`]: o bootloader escolheria um
/// endereço estável entre execuções mas desconhecido em tempo de compilação, e
/// este é o deslocamento por onde o kernel enxerga *qualquer* byte de RAM —
/// inclusive as tabelas de página. Saber o valor de cor vale numa sessão de
/// depuração.
pub const BASE_DA_MEMORIA_FISICA: u64 = 0xFFFF_8800_0000_0000;

/// Onde o heap do kernel começa.
pub const BASE_DO_HEAP: u64 = 0xFFFF_9000_0000_0000;

/// Onde a área das pilhas de fio começa.
pub const BASE_DAS_PILHAS: u64 = 0xFFFF_9800_0000_0000;

/// Piso para o que o bootloader ainda posiciona por conta própria.
const BASE_DO_RESTO: u64 = 0xFFFF_A000_0000_0000;

/// Quanto espaço virtual uma entrada da tabela de topo cobre.
///
/// A raiz do x86_64 é a PML4, e cada uma das 512 entradas dela cobre 512 GiB.
/// É a granularidade com que uma tabela por processo pode separar kernel de
/// usuário — daí as regiões do kernel precisarem estar longe umas das outras.
pub const COBERTURA_DA_ENTRADA_DE_TOPO: u64 = 512 * 1024 * 1024 * 1024;

/// Endereço virtual onde o kernel é carregado.
///
/// # Por que fixo, e não dinâmico
///
/// Por padrão o bootloader escolhe o endereço na hora. O endereço é estável
/// entre execuções (o ASLR vem desligado), mas **não é conhecido em tempo de
/// compilação** — e isso custa caro na hora de depurar.
///
/// O binário do kernel é um executável independente de posição, ligado a
/// partir do zero. Com base dinâmica, todo endereço que o kernel reporta em
/// tempo de execução — o `pc` de uma exceção em `traps.stats`, um quadro de
/// pilha no depurador — está deslocado por uma constante desconhecida em
/// relação ao binário. Traduzir endereço para arquivo e linha exige descobrir
/// esse deslocamento antes, e um depurador conectado *antes* do boot não tem
/// como perguntá-lo a ninguém.
///
/// Fixando a base, o deslocamento passa a ser esta constante. `cargo xtask
/// simbolo` e `cargo xtask debug` a usam diretamente.
///
/// # Por que este endereço
///
/// `0xFFFF_8000_0000_0000` é o primeiro endereço canônico da metade alta do
/// espaço virtual de 48 bits. É a convenção de quase todo kernel de 64 bits, e
/// a razão é a fase 1: quando houver processos, a metade baixa inteira fica
/// para o userspace e a alta para o kernel, sem que o mapa de um precise
/// negociar espaço com o do outro.
///
/// Também aproxima as duas arquiteturas: no ARM a imagem já tem endereço fixo
/// (`0x4008_0000`, imposto pelo protocolo de boot do arm64 e escrito no script
/// do linker).
pub const BASE_DO_KERNEL: u64 = 0xFFFF_8000_0000_0000;

// Declara `inicio` como o ponto de entrada do kernel.
//
// A macro gera um símbolo `_start` com a ABI que o bootloader espera e, o
// mais importante, faz uma verificação de tipo da assinatura em tempo de
// compilação. Sem isso, uma divergência entre o que o bootloader passa e o
// que o kernel espera viraria corrupção de memória silenciosa no boot.
bootloader_api::entry_point!(inicio, config = &CONFIG);

/// Primeira função Rust a executar depois do bootloader.
///
/// O `boot_info` é a única fonte de verdade sobre a máquina neste ponto. Ele
/// é um `&'static mut` porque o bootloader entrega a posse exclusiva da
/// estrutura ao kernel — não existe mais ninguém rodando.
fn inicio(boot_info: &'static mut BootInfo) -> ! {
    // A serial vem antes de qualquer outra coisa. Sem ela, qualquer falha a
    // partir daqui seria uma tela preta sem diagnóstico.
    let canal = crate::serial::init();

    for regiao in boot_info.memory_regions.iter() {
        crate::machine::adicionar_regiao(Regiao {
            inicio: regiao.start,
            fim: regiao.end,
            tipo: match regiao.kind {
                MemoryRegionKind::Usable => TipoRegiao::Utilizavel,
                MemoryRegionKind::Bootloader => TipoRegiao::Bootloader,
                // As variantes `UnknownUefi`/`UnknownBios` carregam o código
                // cru do firmware. Do ponto de vista do kernel todas
                // significam a mesma coisa: não é nossa para usar.
                _ => TipoRegiao::Reservada,
            },
        });
    }

    if let Some(deslocamento) = boot_info.physical_memory_offset.into_option() {
        DESLOCAMENTO_FISICO.store(deslocamento, Ordering::Relaxed);
    }

    if let Some(fb) = boot_info.framebuffer.as_ref() {
        let info = fb.info();
        crate::machine::definir_video(Video {
            largura: info.width as u64,
            altura: info.height as u64,
            stride: info.stride as u64,
            bytes_por_pixel: info.bytes_per_pixel as u64,
            formato: nome_formato_pixel(info.pixel_format),
        });
    }

    crate::inicio_comum(canal)
}

fn nome_formato_pixel(formato: PixelFormat) -> &'static str {
    match formato {
        PixelFormat::Rgb => "rgb",
        PixelFormat::Bgr => "bgr",
        PixelFormat::U8 => "grayscale8",
        // `PixelFormat` é `non_exhaustive`: versões futuras do bootloader
        // podem adicionar variantes, e o kernel precisa continuar compilando.
        _ => "desconhecido",
    }
}

/// Abre as portas seriais: (console humano, canal do agente).
///
/// O x86 tem o luxo de duas UARTs legadas sempre presentes, então damos uma
/// para cada papel. Separá-las garante que o canal do agente seja um stream
/// NDJSON limpo, sem ruído de log exigindo parsing heurístico.
pub fn init_seriais() -> (Option<Uart>, Option<Uart>) {
    // SAFETY: rodamos antes de qualquer outro código tocar nessas portas, em
    // núcleo único, então o acesso é de fato exclusivo.
    let console = unsafe { Uart::abrir(uart::COM1_BASE) };
    let agente = unsafe { Uart::abrir(uart::COM2_BASE) };
    (console, agente)
}

/// Assume o controle das tabelas de página que o bootloader deixou ativas.
pub fn init_paginacao() {
    let deslocamento = DESLOCAMENTO_FISICO.load(Ordering::Relaxed);
    if deslocamento == u64::MAX {
        // Sem o mapeamento da memória física não há como editar tabelas. É
        // fatal para a paginação, mas não para o kernel: reportamos e seguimos
        // com o que o bootloader montou, que já basta para executar.
        crate::log_error!("mmu", "bootloader nao mapeou a memoria fisica");
        return;
    }

    // SAFETY: o deslocamento veio do próprio bootloader, que o estabeleceu ao
    // montar as tabelas.
    unsafe { paginacao::init(deslocamento) };
}

/// Só para a suíte: o par de conversões de permissão deste backend.
#[cfg(feature = "modo-teste")]
pub use paginacao::permissoes_ida_e_volta;

pub use paginacao::{
    acesso_fisico, criar_espaco, desmapear, destruir_espaco, espaco_atual, espaco_do_kernel,
    mapear_frame, percorrer_paginas_do_usuario, traduzir, trocar_espaco,
};

/// O nome da falha que um estouro de pilha produz nesta arquitetura.
///
/// A pilha bate na guard page do bootloader e gera uma falha de página. Mas o
/// processador precisa empilhar o quadro da exceção — na mesma pilha
/// estourada — e falha de novo, o que escala para *double fault*. É por isso
/// que a pilha dedicada da IST não é opcional: sem ela, a terceira tentativa
/// vira triple fault e a máquina reinicia sem diagnóstico.
pub const fn falha_de_estouro_de_pilha() -> &'static str {
    "double_fault"
}

/// Informa faixas de memória física que o alocador de frames não pode
/// entregar.
///
/// No x86 não há nenhuma: o crate `bootloader` já marca no mapa de memória
/// tudo que ocupou — a imagem do kernel, as tabelas de página iniciais, o
/// próprio `BootInfo` — com o tipo `Bootloader`, e nunca como utilizável. A
/// tradução em [`inicio`] preserva essa distinção, então o alocador já nasce
/// sabendo o que evitar.
pub fn reservar_faixas(_f: impl FnMut(u64, u64)) {}

/// Instala GDT, TSS e IDT.
///
/// Depois desta chamada o processador tem para onde ir quando uma exceção
/// acontece. Antes dela, qualquer falha vira triple fault — reboot sem
/// diagnóstico.
pub fn init_excecoes() {
    // A ordem importa: a IDT referencia a IST, que vive no TSS, que é
    // apontado pela GDT.
    gdt::init();
    idt::init();
}

/// Remapeia o PIC, programa o timer e habilita as interrupções.
///
/// Exige que [`init_excecoes`] já tenha rodado: habilitar interrupções sem
/// IDT instalada entrega o controle a um vetor indefinido.
pub fn init_interrupcoes() {
    /// 100 Hz dá resolução de 10 ms — suficiente para medir uptime e para o
    /// scheduler da fase 1, sem custo perceptível de handler.
    const HZ: u32 = 100;

    // SAFETY: as interrupções ainda estão desabilitadas neste ponto (só as
    // habilitamos no fim) e a IDT já está instalada.
    let efetiva = unsafe {
        pic::init();
        pic::programar_timer(HZ)
    };

    crate::tempo::registrar_frequencia(efetiva);
    crate::irq::nomear(0, "timer-pit");
    crate::irq::nomear(1, "teclado-ps2");

    x86_64::instructions::interrupts::enable();

    crate::log_info!("irq", "PIC remapeado, timer a {} Hz", efetiva);
}

/// Faz a serial do agente interromper quando chegar um byte.
///
/// Fica separada de [`init_interrupcoes`] porque a ordem importa: só faz
/// sentido liberar a linha depois que existe quem consuma os bytes. Entre
/// ligar a interrupção e a tarefa começar a rodar, os bytes já vão para a
/// fila — que é justamente o que queremos.
/// Não há nada a descobrir: as portas de configuração são da arquitetura.
///
/// Existe para que o caminho de boot seja o mesmo nas duas plataformas — no
/// ARM esta função lê o device tree para achar o ECAM.
pub fn init_pci() {}

pub fn init_interrupcao_serial() {
    // Antes de ligar a recepção: o FIFO pode ter um pedaço de requisição de
    // quem conectou enquanto o kernel ainda bootava. Ver
    // `tarefas::entrada::descartar_pendentes` — deixá-lo ali contamina a
    // requisição seguinte.
    let descartados = crate::tarefas::entrada::descartar_pendentes();
    if descartados > 0 {
        crate::log_warn!(
            "agent",
            "{} bytes descartados: chegaram antes do canal subir",
            descartados
        );
    }

    crate::arch::sem_interrupcoes(|| {
        let mut guarda = crate::serial::AGENT_LINK.lock();
        let Some(porta) = guarda.as_mut() else {
            return;
        };
        porta.habilitar_interrupcao_recepcao();
    });

    crate::irq::nomear(pic::IRQ_SERIAL_AGENTE as usize, "serial-agente");

    // SAFETY: o handler do vetor correspondente foi instalado por
    // `init_excecoes`, e a porta acabou de ser configurada.
    unsafe { pic::desmascarar(pic::IRQ_SERIAL_AGENTE) };

    crate::log_info!(
        "irq",
        "COM2 interrompendo na IRQ {}",
        pic::IRQ_SERIAL_AGENTE
    );
}

/// Espera pela próxima interrupção, em baixo consumo.
///
/// Devolve o controle imediatamente se as interrupções estiverem
/// desabilitadas: `hlt` sem interrupções pendentes pararia o núcleo para
/// sempre — o sistema morreria no primeiro instante ocioso.
/// As interrupções estão habilitadas?
///
/// Existe para que código portátil possa **conferir** que está numa seção
/// crítica, em vez de confiar que quem o chamou lembrou de criar uma.
pub fn interrupcoes_habilitadas() -> bool {
    x86_64::instructions::interrupts::are_enabled()
}

pub fn esperar_interrupcao() {
    if x86_64::instructions::interrupts::are_enabled() {
        x86_64::instructions::hlt();
    } else {
        core::hint::spin_loop();
    }
}

/// Dorme até a próxima interrupção, mas só se `ocioso` confirmar que não há
/// trabalho — e sem deixar fresta entre as duas coisas.
///
/// # A corrida que esta função existe para fechar
///
/// O ingênuo seria `if ocioso() { hlt() }`. Uma interrupção caindo *entre* a
/// checagem e o `hlt` deixaria trabalho enfileirado e a CPU dormindo: o
/// sistema só acordaria no próximo evento, que pode demorar — ou não vir.
///
/// A saída é desligar as interrupções antes de checar e reabilitá-las
/// *junto* com o `hlt`. O x86 garante que uma interrupção pendente após um
/// `sti` só é entregue depois da instrução seguinte, e é exatamente por isso
/// que o par `sti; hlt` nessa ordem é atômico para este fim. Qualquer
/// interrupção que tenha chegado durante a checagem fica retida e é entregue
/// já com a CPU dormindo, que a acorda na hora.
pub fn dormir_se_ocioso(ocioso: impl FnOnce() -> bool) {
    use x86_64::instructions::interrupts;

    // Um chamador pode nos invocar de dentro de uma seção crítica. Restaurar
    // o estado anterior, em vez de ligar incondicionalmente, é o que impede
    // que a seção dele termine mais cedo do que ele pediu.
    let estavam_ligadas = interrupts::are_enabled();
    interrupts::disable();

    if !ocioso() {
        if estavam_ligadas {
            interrupts::enable();
        }
        return;
    }

    if estavam_ligadas {
        interrupts::enable_and_hlt();
    } else {
        // Dormir com as interrupções mascaradas pararia o núcleo para sempre:
        // nada poderia acordá-lo. Girar é desperdício, mas é recuperável.
        core::hint::spin_loop();
    }
}

/// Dispara um breakpoint (`int3`), que é tratado e retorna normalmente.
///
/// Existe para que o agente possa verificar, em tempo de execução, que o
/// caminho de exceções está de fato funcionando — ver o comando
/// `debug.trigger`.
pub fn disparar_breakpoint() {
    x86_64::instructions::interrupts::int3();
}

/// Endereço garantidamente não mapeado, para provocar uma falha de propósito.
///
/// É canônico (bit 47 zerado, metade baixa) e está muito abaixo de tudo que o
/// bootloader mapeia: o kernel vive em [`BASE_DO_KERNEL`], a memória física
/// num deslocamento alto, e o heap em 64 GiB. Nada do kernel encosta aqui.
const ENDERECO_INVALIDO: u64 = 0xDEAD_0000;

/// Provoca uma falha irrecuperável de propósito. Nunca retorna.
///
/// Serve ao comando `debug.trigger` com `kind: "fatal"`, que existe para
/// exercitar o modo post-mortem sem precisar plantar um defeito no código e
/// recompilar.
pub fn disparar_falha_fatal() -> ! {
    // SAFETY: nenhuma. É deliberadamente inválida — escrever aqui é o ponto.
    // O handler de page fault reconhece a falha, registra o endereço e entra
    // em modo post-mortem.
    unsafe { core::ptr::write_volatile(ENDERECO_INVALIDO as *mut u64, 0) };

    // Inalcançável se a paginação estiver funcionando. Se chegarmos aqui, o
    // fato de *não* ter falhado é em si o diagnóstico.
    crate::log_error!(
        "debug",
        "escrita em {:#x} nao falhou; a paginacao nao esta protegendo nada",
        ENDERECO_INVALIDO
    );
    halt_forever()
}

/// Executa `f` com as interrupções mascaradas, restaurando o estado ao sair.
pub fn sem_interrupcoes<R>(f: impl FnOnce() -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(f)
}

/// Para a CPU até a próxima interrupção, para sempre.
///
/// Prefira isto a `loop {}`. Um loop vazio mantém o núcleo em 100% de uso
/// girando à toa; `hlt` coloca a CPU em estado de baixo consumo e ela só
/// acorda quando há trabalho de verdade.
pub fn halt_forever() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

/// Lê a string de fabricante da CPU via `CPUID` folha 0.
///
/// Os 12 caracteres vêm espalhados em três registradores, e a ordem
/// EBX-EDX-ECX não é um engano: é literalmente como a Intel especificou.
pub fn identificar_cpu() -> super::IdCpu {
    // `__cpuid` é seguro: `CPUID` faz parte da linha de base do x86_64, então
    // o compilador sabe que a instrução sempre existe no alvo e não há
    // pré-condição para o chamador garantir.
    let r = core::arch::x86_64::__cpuid(0);

    let mut bytes = [0u8; 12];
    bytes[0..4].copy_from_slice(&r.ebx.to_le_bytes());
    bytes[4..8].copy_from_slice(&r.edx.to_le_bytes());
    bytes[8..12].copy_from_slice(&r.ecx.to_le_bytes());

    super::IdCpu::de_bytes(&bytes)
}

/// Encerra o QEMU pelo dispositivo `isa-debug-exit`.
///
/// Ao escrever um valor na porta configurada, o QEMU termina imediatamente
/// com o código de saída `(valor << 1) | 1`. Os valores evitam 0 e 1 de
/// propósito: assim um código nosso nunca colide com uma saída "natural" do
/// emulador, como um crash do próprio QEMU.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn encerrar_emulador(resultado: crate::qemu::Resultado) -> ! {
    use crate::qemu::Resultado;

    // Precisa casar com o `-device isa-debug-exit,iobase=...` que o xtask
    // passa ao QEMU. `0xf4` é convencional por estar numa faixa que hardware
    // real não usa.
    const PORTA_SAIDA: u16 = 0xf4;

    let codigo: u32 = match resultado {
        Resultado::Sucesso => 0x10, // vira 33 no host
        Resultado::Falha => 0x11,   // vira 35 no host
    };

    // SAFETY: escrever numa porta de I/O é sempre `unsafe` porque o efeito
    // depende do dispositivo. Aqui o efeito é conhecido e desejado. Em
    // hardware real `0xf4` não está mapeada e a escrita é inofensiva.
    unsafe {
        x86_64::instructions::port::Port::new(PORTA_SAIDA).write(codigo);
    }

    // Inalcançável sob o QEMU, mas o kernel também roda em hardware real.
    halt_forever()
}
