//! Backend de arquitetura para x86_64.
//!
//! Quando chegamos aqui o processador já está em long mode, com paginação
//! ligada no mapa que o [`iniciador`](../../../iniciador/index.html) montou e
//! uma pilha própria — e quem fez isso é deste projeto. Este módulo traduz a
//! [`protocolo::Entrega`] que ele deixou para as estruturas neutras de
//! [`crate::machine`] e segue para o fluxo comum.

pub mod acpi;
pub mod apic;
pub mod contexto;
pub mod gdt;
pub mod idt;
pub mod mouse;
pub mod paginacao;
pub mod pci;
pub mod pic;
pub mod smp;
pub mod uart;
pub mod usuario;

pub use contexto::{
    Contexto, ceder_cpu, preparar_contexto, preparar_contexto_de_fork, redirecionar_para,
};
pub use usuario::{definir_pilha_de_kernel, entrar as entrar_em_usuario, init as init_usuario};

use core::sync::atomic::{AtomicU64, Ordering};

use crate::machine::{Regiao, TipoRegiao};

pub use uart::Uart;

/// Nome da arquitetura, exposto no protocolo do agente.
/// Liga o mouse PS/2 da máquina, se houver um. Devolve se ligou.
pub fn iniciar_mouse() -> bool {
    mouse::init()
}

pub const fn nome() -> &'static str {
    "x86_64"
}

/// Onde o iniciador mapeou a memória física completa.
///
/// A sentinela `u64::MAX` distingue "não fornecido" de um deslocamento zero.
static DESLOCAMENTO_FISICO: AtomicU64 = AtomicU64::new(u64::MAX);

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

/// As bases do espaço virtual, e por que elas não moram mais aqui.
///
/// Elas eram declaradas neste arquivo, e o iniciador tinha uma cópia. Um
/// teste do `xtask` lia as duas fontes e exigia que batessem — funcionava, e
/// era o remédio para um problema que deixou de existir: agora há um pacote
/// que os dois incluem, e a divergência não pode acontecer.
///
/// O preço de divergir era alto e mudo: um kernel mapeado num endereço e
/// ligado para outro não dá erro nem mensagem, dá uma máquina que reinicia no
/// primeiro salto.
pub use protocolo::mapa::{BASE_DAS_PILHAS, BASE_DAS_SUPERFICIES, BASE_DE_MMIO, BASE_DO_HEAP};

// A base do kernel e a da memória física não são reexportadas. A primeira é
// do iniciador e do `xtask`; a segunda o kernel lê da **entrega**, e não da
// constante — perguntar à constante seria acreditar numa das duas pontas sem
// ouvir a outra. Quem precisa delas pelo nome (a suíte) as importa do
// `protocolo`, que é onde elas moram.

/// Quanto espaço virtual uma entrada da tabela de topo cobre.
///
/// A raiz do x86_64 é a PML4, e cada uma das 512 entradas dela cobre 512 GiB.
/// É a granularidade com que uma tabela por processo pode separar kernel de
/// usuário — daí as regiões do kernel precisarem estar longe umas das outras.
pub const COBERTURA_DA_ENTRADA_DE_TOPO: u64 = 512 * 1024 * 1024 * 1024;

/// A primeira instrução do Duke, e o símbolo que o `e_entry` do ELF aponta.
///
/// # O que já está pronto quando ela roda
///
/// O iniciador deixou a máquina assim: long mode, interrupções desligadas,
/// paginação no mapa que ele montou — a imagem do kernel na metade alta, a
/// memória física em [`protocolo::mapa::BASE_DA_MEMORIA_FISICA`], uma pilha com página de
/// guarda — e os serviços de boot da UEFI já encerrados. O `RDI` traz o
/// endereço virtual da entrega.
///
/// # Safety
///
/// Nada chama esta função: o processador salta para ela. `entrega` precisa
/// ser o ponteiro que o iniciador pôs no `RDI`, e o contrato inteiro de
/// [`protocolo`] precisa estar valendo.
#[unsafe(no_mangle)]
pub unsafe extern "sysv64" fn _start(entrega: *const protocolo::Entrega) -> ! {
    // A serial vem antes de qualquer outra coisa. Sem ela, qualquer falha a
    // partir daqui seria uma tela preta sem diagnóstico — e aqui isso é
    // literal: o iniciador acabou de se despedir pela mesma porta.
    let canal = crate::serial::init();

    // SAFETY: o ponteiro é o que o iniciador entregou. A conferência abaixo é
    // o que separa "um ponteiro" de "a entrega": sem ela, um iniciador de
    // outra versão daria campos deslocados, e um mapa de memória lido com
    // deslocamento errado não dá erro — dá um alocador que entrega páginas do
    // firmware.
    let entrega = unsafe { conferir_a_entrega(entrega) };

    DESLOCAMENTO_FISICO.store(entrega.deslocamento_fisico, Ordering::Relaxed);
    acpi::registrar_rsdp(entrega.acpi);

    for i in 0..entrega.quantas_regioes {
        // SAFETY: o ponteiro e a contagem vêm da entrega conferida, e as
        // regiões estão mapeadas no espaço que já está ativo.
        let r = unsafe { *(entrega.regioes as *const protocolo::Regiao).add(i as usize) };
        crate::machine::adicionar_regiao(Regiao {
            inicio: r.inicio,
            fim: r.fim,
            tipo: match r.tipo {
                protocolo::tipo::UTILIZAVEL => TipoRegiao::Utilizavel,
                protocolo::tipo::DO_INICIADOR => TipoRegiao::Bootloader,
                // Do firmware ou de hardware. Do ponto de vista do kernel as
                // duas significam a mesma coisa: não é nossa para usar.
                _ => TipoRegiao::Reservada,
            },
        });
    }

    // O endereço já está mapeado e gravável — é o que torna a tela utilizável
    // desde o primeiro instante, antes mesmo de a paginação ser nossa. Num
    // kernel que quer poder desenhar uma tela de falha, esse "desde o
    // primeiro instante" é a propriedade que importa.
    //
    // SAFETY: a faixa é a que o iniciador mapeou, com exatamente o tamanho
    // que a geometria descreve, e ninguém mais a tem.
    unsafe { crate::tela::adotar(&entrega.video) };

    crate::inicio_comum(canal)
}

/// Confere que o ponteiro do `RDI` aponta mesmo para uma entrega desta versão.
///
/// # Por que parar em vez de seguir
///
/// Porque não há como seguir. Se a entrega não for a que este kernel espera,
/// o mapa de memória, o deslocamento físico e a geometria do vídeo estão
/// todos deslocados — e cada um deles vira um defeito que aparece em outro
/// lugar, páginas depois, sem nada que aponte para aqui.
///
/// A serial já está de pé quando esta função roda, e é por isso que ela pode
/// dizer o que aconteceu antes de parar.
///
/// # Safety
/// `entrega` precisa ser o ponteiro que o iniciador pôs no `RDI`.
unsafe fn conferir_a_entrega(entrega: *const protocolo::Entrega) -> protocolo::Entrega {
    let parar = |motivo: &str| -> ! {
        crate::log_error!("boot", "a entrega do iniciador nao serve: {}", motivo);
        halt_forever()
    };

    if entrega.is_null() || !(entrega as usize).is_multiple_of(align_of::<protocolo::Entrega>()) {
        parar("o ponteiro e nulo ou esta desalinhado");
    }

    // SAFETY: delegada a quem chama; o alinhamento acabou de ser conferido, e
    // um ponteiro que não aponte para memória mapeada faria uma falha de
    // página — que é um desfecho melhor que ler campos deslocados.
    let entrega = unsafe { core::ptr::read(entrega) };

    if entrega.magica != protocolo::MAGICA {
        crate::log_error!(
            "boot",
            "magica {:#018x}, esperava {:#018x}",
            entrega.magica,
            protocolo::MAGICA
        );
        parar("a magica nao confere");
    }
    if entrega.versao != protocolo::VERSAO {
        crate::log_error!(
            "boot",
            "versao {}, este kernel fala a {}",
            entrega.versao,
            protocolo::VERSAO
        );
        parar("o iniciador e de outra versao do protocolo");
    }
    // Menor que o esperado significa campos que este kernel leria e que não
    // foram escritos. Maior é um iniciador mais novo, e os campos que este
    // kernel conhece continuam onde estavam — por isso só o menor é recusado.
    if (entrega.tamanho as usize) < size_of::<protocolo::Entrega>() {
        crate::log_error!(
            "boot",
            "a entrega tem {} bytes, e este kernel le {}",
            entrega.tamanho,
            size_of::<protocolo::Entrega>()
        );
        parar("a entrega e menor do que este kernel le");
    }
    if entrega.regioes == 0 || entrega.quantas_regioes == 0 {
        parar("a entrega nao traz mapa de memoria");
    }

    // O ponteiro das regiões é **virtual**, no espaço que o iniciador montou,
    // e portanto alcançável pelo mapa da memória física. Um ponteiro abaixo
    // desse deslocamento é físico, e ler por ele funciona **por acidente**:
    // no instante em que este código roda a identidade que o iniciador
    // deixou ainda está de pé, e ela faz um endereço físico baixo parecer
    // válido. Ela sai alguns passos adiante, em `init_paginacao`.
    //
    // Medido por mutação: com as regiões entregues em endereço físico, o
    // kernel bootava e passava em tudo. O defeito só apareceria numa máquina
    // onde elas caíssem acima da identidade — ou no dia em que ela fosse
    // largada mais cedo.
    if entrega.regioes < entrega.deslocamento_fisico {
        crate::log_error!(
            "boot",
            "as regioes estao em {:#x}, abaixo do deslocamento {:#x}",
            entrega.regioes,
            entrega.deslocamento_fisico
        );
        parar("o ponteiro das regioes nao e do espaco do kernel");
    }

    entrega
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

/// Assume o controle das tabelas de página que o iniciador deixou ativas.
pub fn init_paginacao() {
    let deslocamento = DESLOCAMENTO_FISICO.load(Ordering::Relaxed);
    if deslocamento == u64::MAX {
        // Sem o mapeamento da memória física não há como editar tabelas. É
        // fatal para a paginação, mas não para o kernel: reportamos e seguimos
        // com o que o iniciador montou, que já basta para executar.
        crate::log_error!("mmu", "o iniciador nao mapeou a memoria fisica");
        return;
    }

    // SAFETY: o deslocamento veio da entrega do iniciador, que o estabeleceu
    // ao montar as tabelas.
    unsafe { paginacao::init(deslocamento) };

    paginacao::largar_a_identidade();
    exigir_protecao_de_escrita();
    exigir_que_o_kernel_nao_execute_pagina_de_usuario();
}

/// Faz o bit de escrita valer também para o anel zero.
///
/// # O bit que não vinha de lugar nenhum
///
/// Por padrão o `WRITE_PROTECT` do `CR0` está **desligado**, e com ele
/// desligado o processador ignora o bit de escrita das páginas quando quem
/// escreve é o kernel. Isso é herança do 386: o supervisor podia tudo, e o
/// bit foi acrescentado depois justamente porque "podia tudo" impede
/// implementar cópia na escrita.
///
/// Sem ele, a marca que o `fork` põe nas páginas protege o processo e não
/// protege o kernel. A chamada `ler` entrega os bytes lidos escrevendo no
/// buffer do usuário, do anel zero: numa página recém-bifurcada essa escrita
/// atravessaria a proteção sem falha nenhuma e apareceria na memória do
/// **outro** processo. Nenhum log, nenhum sintoma, e a corrupção a um `fork`
/// de distância.
///
/// # Nenhum caso protege esta linha, e o que foi medido
///
/// Apagando-a, a suíte inteira passa — medido nas 143 de então e remedido nas
/// 162 de hoje. O motivo está no próprio log que a função emite — **o
/// firmware já a deixara ligada**. O EDK II liga o bit para as próprias
/// proteções de página, e depois do `ExitBootServices` ninguém mais o toca:
/// nem o iniciador, nem o kernel. A linha não muda nada nesta máquina.
///
/// O que **é** falsificável é o bit, e vale ter medido: trocando `insert`
/// por `remove`, quatro casos caem de uma vez — os mesmos quatro das 143 às
/// 162 — `clonar copia o conteudo`,
/// `clonar compartilha sem copiar`, `copia na escrita nao copia sem socio` e
/// `fork do fork mantem a escrita`. Todos pelo mesmo motivo, e nenhum deles
/// com uma mensagem que aponte para o `CR0`: eles relatam que escrever de um
/// lado alterou o outro.
///
/// Ou seja: o que esta linha garante é indispensável e está provado; o que
/// não dá para provar aqui é que **precisamos ligá-lo nós**. Ela fica porque
/// herdar o bit é depender de um firmware específico, e a primeira máquina
/// que arrancar de outro perderia a cópia na escrita sem um único sintoma
/// que levasse até aqui.
///
/// O ARM não precisa do equivalente: lá `AP[2]` vale para EL1 do mesmo jeito
/// que para EL0, e não existe bit que deixe o supervisor passar por cima.
/// Impede o anel zero de executar uma página marcada como de usuário.
///
/// # A proteção que existia numa arquitetura só
///
/// O backend do ARM põe `PXN` em **toda** página de usuário, e o comentário
/// de lá diz, desde que foi escrito: "é a mesma proteção que o x86 chama de
/// SMEP". Não era. O x86 deste kernel nunca tocou no `CR4` — nem aqui, nem
/// no iniciador —, e portanto nunca ligou o SMEP.
///
/// A diferença é concreta. No ARM, um desvio acidental do kernel para um
/// endereço de userspace é uma falha de permissão na hora. No x86, era o
/// processador executando o código do processo com privilégio total, sem
/// nada no caminho. Um ponteiro de função corrompido, um salto calculado
/// sobre dado do usuário, e o anel deixa de significar coisa alguma.
///
/// Era o defeito característico deste projeto na sua forma mais cara: uma
/// regra escrita de um lado, afirmada nos dois, e conferida em nenhum.
///
/// # Por que só o SMEP, e não o SMAP também
///
/// Porque o SMAP proíbe o kernel de **ler e escrever** página de usuário, e
/// este kernel faz as duas coisas o tempo todo: copiar o buffer de
/// `escrever`, ler o caminho de `abrir`, depositar o desfecho de `esperar`.
/// Ligá-lo exigiria `stac`/`clac` em cada um desses pontos, que é outro
/// trabalho.
///
/// E ele não quebraria simetria nenhuma: o equivalente do ARM é o `PAN`, do
/// ARMv8.1, que este kernel também não liga. SMAP e PAN estão ausentes dos
/// dois lados — que é uma lacuna, e não uma divergência.
fn exigir_que_o_kernel_nao_execute_pagina_de_usuario() {
    use x86_64::registers::control::{Cr4, Cr4Flags};

    // O bit 7 do `EBX` da folha 7, sub-folha 0: é assim que o processador
    // diz se tem SMEP. Perguntar antes de ligar não é cerimônia — escrever
    // um bit reservado do `CR4` é `#GP`, e o kernel morreria no boot numa
    // máquina mais velha em vez de seguir sem a proteção.
    let tem_smep = core::arch::x86_64::__cpuid_count(7, 0).ebx & (1 << 7) != 0;

    if !tem_smep {
        crate::log_warn!(
            "mmu",
            "esta cpu nao oferece SMEP; o anel zero pode executar pagina de usuario"
        );
        return;
    }

    // SAFETY: o processador declarou o bit, e ligá-lo só torna as
    // verificações **mais** estritas. O kernel nunca executa código de
    // userspace com privilégio — quando entra em ring 3, o processador já
    // mudou de nível antes da primeira instrução do processo.
    unsafe { Cr4::update(|flags| flags.insert(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION)) };

    crate::log_info!(
        "mmu",
        "SMEP ligado: o anel zero nao executa pagina de usuario"
    );
}

/// O SMEP está ligado, ou esta CPU não o oferece?
///
/// Existe para a suíte: é a pergunta que distingue "a proteção está de pé"
/// de "alguém apagou a linha que a liga".
#[cfg(feature = "modo-teste")]
pub fn protecao_de_execucao() -> (bool, bool) {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    let tem = core::arch::x86_64::__cpuid_count(7, 0).ebx & (1 << 7) != 0;
    let ligado = Cr4::read().contains(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION);
    (tem, ligado)
}

fn exigir_protecao_de_escrita() {
    use x86_64::registers::control::{Cr0, Cr0Flags};

    let ja_estava = Cr0::read().contains(Cr0Flags::WRITE_PROTECT);

    // SAFETY: ligar `WRITE_PROTECT` só torna o processador **mais** estrito,
    // e nenhuma escrita do kernel depende de atravessar uma página somente
    // leitura — a suíte confirma, porque o caso que a violaria seria uma
    // falha fatal e não um resultado errado.
    unsafe { Cr0::update(|flags| flags.insert(Cr0Flags::WRITE_PROTECT)) };

    // O log diz qual dos dois casos aconteceu de propósito: é a única
    // evidência, em campo, de que a herança do firmware não é garantida. O
    // dia em que esta linha aparecer com "nao a tinha" é o dia em que a
    // função deixou de ser redundante.
    crate::log_info!(
        "mmu",
        "protecao de escrita no anel zero ligada (o firmware {})",
        if ja_estava {
            "ja a deixara"
        } else {
            "nao a tinha"
        }
    );
}

/// Só para a suíte: tira a marca de compartilhada de uma página.
#[cfg(feature = "modo-teste")]
pub use paginacao::desmarcar_compartilhada_de_teste;
/// Só para a suíte: o par de conversões de permissão deste backend.
#[cfg(feature = "modo-teste")]
pub use paginacao::permissoes_ida_e_volta;

pub use paginacao::{
    acesso_fisico, copia_na_escrita_em, criar_espaco, desmapear, destravar_paginacao,
    destruir_espaco, espaco_atual, espaco_do_kernel, gravavel_pelo_usuario, mapear_frame,
    marcar_compartilhada, marcar_copia_na_escrita, percorrer_paginas_do_usuario, traduzir,
    trocar_espaco,
};

/// O nome da falha que um estouro de pilha produz nesta arquitetura.
///
/// A pilha bate na página de guarda e gera uma falha de página. Mas o
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
/// Do que o iniciador ocupou, nenhuma: ele marca no mapa de memória tudo que
/// usou — a imagem do kernel, as tabelas de página, a pilha inicial, a
/// própria entrega — como [`protocolo::tipo::DO_INICIADOR`], e nunca como
/// utilizável. A tradução em [`_start`] preserva essa distinção, então o
/// alocador já nasce sabendo o que evitar.
///
/// O que sai daqui é do próprio kernel: duas páginas abaixo de 1 MiB, onde os
/// outros núcleos acordam — ver [`smp`]. Elas precisam ser escolhidas antes
/// de o alocador entregar qualquer frame, porque depois disso as páginas
/// baixas podem já ter dono.
pub fn reservar_faixas(f: impl FnMut(u64, u64)) {
    smp::reservar_paginas_baixas(f);
}

// ---------------------------------------------------------------------------
// Vários núcleos
// ---------------------------------------------------------------------------

/// Em que núcleo este código está rodando — ver [`gdt::nucleo_atual`].
pub use gdt::nucleo_atual;

/// O id de APIC deste núcleo, que é como o hardware o chama.
pub fn hardware_deste_nucleo() -> u64 {
    apic::id_inicial() as u64
}

/// Chama `f` com o id de APIC de cada núcleo que a ACPI descreve como
/// habilitado — o primeiro incluído.
pub fn descobrir_nucleos(mut f: impl FnMut(u64)) {
    if let Err(motivo) = acpi::processadores(|id| f(id as u64)) {
        crate::log_warn!(
            "smp",
            "a ACPI nao listou os nucleos ({}): segue com um so",
            motivo
        );
    }
}

/// O APIC alcança o núcleo de identificador `hardware`? O xAPIC endereça
/// identificadores de 8 bits, e o 255 é o de difusão: acima de 254 só o
/// x2APIC, que este kernel não programa. O limite é deste controlador, e
/// mora aqui — o resto do kernel conta até [`crate::nucleos::MAX_NUCLEOS`].
pub fn nucleo_enderecavel(_indice: usize, hardware: u64) -> Result<(), &'static str> {
    if hardware > 254 {
        return Err("o xAPIC nao endereca identificadores acima de 254 (x2APIC nao suportado)");
    }
    Ok(())
}

/// Nada a preparar no primeiro núcleo: a chamada de sistema roda na pilha de
/// kernel do fio, com guarda, e as pilhas de emergência do TSS são as de
/// cada núcleo do mesmo jeito.
pub fn preparar_o_primeiro_nucleo() -> Result<(), &'static str> {
    Ok(())
}

/// Acorda o núcleo de APIC `hardware` como o núcleo `indice`, na pilha `topo`.
pub fn partir_nucleo(indice: usize, hardware: u64, topo: u64) -> Result<(), &'static str> {
    smp::partir(indice, hardware, topo)
}

pub use smp::{parar_este_nucleo, parar_os_outros};

/// Acorda os núcleos da máscara, se estiverem dormindo — ver
/// [`crate::nucleos::cutucar`].
pub fn cutucar(mascara: crate::nucleos::Mascara) {
    for i in 0..crate::nucleos::MAX_NUCLEOS {
        if mascara & (1 << i) != 0
            && let Some(h) = crate::nucleos::hardware(i).and_then(|h| u32::try_from(h).ok())
        {
            let _ = apic::cutucar(h);
        }
    }
}

/// Quantas vezes este kernel pediu aos outros núcleos que largassem uma
/// tradução — ver [`smp::descartar_nos_outros`].
pub fn invalidacoes_remotas() -> u64 {
    smp::descartes()
}

/// Quantos avisos de descarte foram reenviados a um núcleo que demorava —
/// ver [`smp::descartar_nos_outros`].
pub fn reavisos_remotos() -> u64 {
    smp::reavisos()
}

/// Liga as interrupções deste núcleo.
pub fn ligar_interrupcoes() {
    x86_64::instructions::interrupts::enable();
}

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

/// Troca o PIT pelo timer do APIC local, se esta máquina tiver um.
///
/// # Por que não em [`init_interrupcoes`]
///
/// Porque o APIC é memória mapeada e precisa da paginação no ar — e a
/// paginação, por sua vez, precisa do alocador de frames, que precisa do mapa
/// de memória. O timer vem antes de tudo isso no boot por um bom motivo: sem
/// ele os registros de log não têm carimbo de tempo, e é entre o boot e a
/// paginação que as coisas mais difíceis de depurar acontecem.
///
/// A saída é a que os kernels costumam tomar: o PIT sobe cedo e serve de
/// relógio provisório, e o APIC o substitui assim que pode. Não é dívida —
/// o PIT é o que torna a calibração do APIC possível.
///
/// Se não houver APIC, ou se a calibração não der um número utilizável, o PIT
/// continua. Um timer pior é melhor que nenhum.
pub fn init_timer_definitivo() {
    /// A mesma frequência do PIT: 100 Hz dão resolução de 10 ms, que é o que
    /// o escalonador desta fase precisa. O ganho do APIC aqui não é
    /// resolução, é ter um timer por núcleo.
    const HZ: u32 = 100;

    // SAFETY: a paginação está no ar, o PIT está rodando desde
    // `init_interrupcoes` e as interrupções estão habilitadas — as três
    // pré-condições da calibração.
    let Some(efetiva) = (unsafe { apic::init(HZ) }) else {
        crate::log_info!("irq", "sem APIC local utilizavel; o PIT continua");
        return;
    };

    // Só agora o PIT pode ser desligado. Entre a programação do APIC e esta
    // linha os dois disparam, e os dois chamam `tempo::tick` — o relógio anda
    // rápido demais por alguns milissegundos, o que é infinitamente melhor
    // que a alternativa: desligar o PIT primeiro e descobrir que o APIC não
    // estava contando.
    //
    // SAFETY: o timer do APIC já está entregando no lugar dele.
    unsafe { pic::mascarar(0) };

    crate::tempo::registrar_frequencia(efetiva);
    crate::irq::nomear(apic::VETOR_TIMER as usize, "timer-apic");
    crate::irq::nomear(apic::VETOR_ESPURIO as usize, "apic-espuria");

    crate::log_info!(
        "irq",
        "timer do APIC a {} Hz no nucleo {} (barramento medido em {} kHz), PIT desligado",
        efetiva,
        apic::id_do_nucleo().unwrap_or(0),
        apic::frequencia_do_barramento() / 1000
    );
}

/// Não há nada a descobrir: as portas de configuração são da arquitetura.
///
/// Existe para que o caminho de boot seja o mesmo nas duas plataformas — no
/// ARM esta função lê o device tree para achar o ECAM.
pub fn init_pci() {}

/// Faz a serial do agente interromper quando chegar um byte.
///
/// Fica separada de [`init_interrupcoes`] porque a ordem importa: só faz
/// sentido liberar a linha depois que existe quem consuma os bytes. Entre
/// ligar a interrupção e a tarefa começar a rodar, os bytes já vão para a
/// fila — que é justamente o que queremos.
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
        #[cfg(feature = "modo-teste")]
        GIROS_MASCARADOS.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

/// Quantas vezes [`esperar_interrupcao`] girou em vez de dormir.
///
/// # Por que contar, em vez de deixar escrito que é zero
///
/// Porque já estava escrito, e uma frase não se remede sozinha. O ramo
/// mascarado desta função é um giro que só termina se **outro** fio religar
/// as interrupções; para quem chamou sem ter para onde voltar, ele é o fim.
/// A medida de que ele nunca é tomado era o que autorizava os dois chamadores
/// de hoje — o laço do agente e o descanso do coletor — a usarem esta função
/// em vez de [`dormir_parado`].
///
/// Escrita num comentário, essa medida vale até o próximo chamador. Contada,
/// vale a cada rodada da suíte.
#[cfg(feature = "modo-teste")]
pub fn giros_mascarados() -> u64 {
    GIROS_MASCARADOS.load(Ordering::Relaxed)
}

#[cfg(feature = "modo-teste")]
static GIROS_MASCARADOS: AtomicU64 = AtomicU64::new(0);

/// Dorme até a próxima interrupção, ligando-as se for preciso.
///
/// # Quem pode chamar, e por que a pergunta importa
///
/// Só quem **não pode prosseguir** e **não tem trava na mão**: um fio que
/// terminou, ou um que espera um filho. Para esses dois, ligar as
/// interrupções não encurta seção crítica nenhuma — não há seção — e é a
/// única coisa que pode mudar a situação deles.
///
/// # Por que [`esperar_interrupcao`] não serve
///
/// Porque ela se recusa a dormir com as interrupções mascaradas, e está
/// certa: um `hlt` com `IF=0` para o núcleo até um NMI, ou seja, para
/// sempre. O problema é que ela então **gira**, e girar com `IF=0` também é
/// para sempre — o timer não chega nos dois casos. O comentário dela chama
/// o giro de "recuperável", e ele só é recuperável se outro fio puder rodar
/// e religar as interrupções; para quem está parado, não há outro momento.
///
/// E é justamente de dentro de uma chamada de sistema que isso acontece no
/// x86: o `syscall` limpa `IF` por causa do `SFMask`, então todo o despacho
/// roda mascarado.
///
/// Que o ramo mascarado de [`esperar_interrupcao`] seja tomado **zero** vezes
/// deixou de ser uma medida escrita aqui e virou um caso, contando os giros
/// sob `modo-teste` em vez de confiar na frase. O travamento era latente, e
/// esperava a primeira máquina em que o coletor não estivesse pronto para
/// rodar.
///
/// No ARM esta função é um `wfi` e pronto: lá a instrução já acorda com a
/// interrupção mascarada, e não há o que ligar.
pub fn dormir_parado() {
    use x86_64::instructions::interrupts;

    // Restaurar o estado anterior, e não ligar de vez: quem chamou com as
    // interrupções ligadas continua com elas ligadas, e quem chamou de
    // dentro de uma chamada de sistema volta mascarado, como o resto do
    // despacho espera.
    let estavam_ligadas = interrupts::are_enabled();
    interrupts::enable_and_hlt();
    if !estavam_ligadas {
        interrupts::disable();
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
/// iniciador mapeia: o kernel vive em [`protocolo::mapa::BASE_DO_KERNEL`], a
/// memória física
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

/// Estoura de propósito a pilha em que um handler de exceção roda. Nunca
/// retorna.
///
/// Serve ao `debug.trigger` com `kind: "stack_overflow"`, o mesmo das duas
/// arquiteturas: o `int3` cai em [`idt`], que vê o pedido e afunda dali. No
/// x86 o handler roda na pilha de kernel do fio; a recursão chega à guarda,
/// a falha de página não tem onde empilhar o quadro, e quem relata é a falha
/// dupla, na pilha da IST.
pub fn disparar_estouro_em_excecao() -> ! {
    idt::AFUNDAR_NO_PONTO_DE_PARADA.store(true, core::sync::atomic::Ordering::SeqCst);
    x86_64::instructions::interrupts::int3();
    // Inalcançável: o handler não volta quando o pedido está de pé.
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

/// O contador de tempo do processador, o TSC: anda numa frequência que o
/// kernel não conhece de antemão, e é a régua das medidas de custo — ver
/// [`crate::metricas`] —, que a convertem pelo próprio relógio do kernel.
pub fn ciclos() -> u64 {
    // SAFETY: `rdtsc` só lê o contador do processador, sem tocar a memória;
    // existe em todo x86_64, e no anel 0 nada o impede — o `CR4.TSD` só
    // vale para o anel 3.
    unsafe { core::arch::x86_64::_rdtsc() }
}
