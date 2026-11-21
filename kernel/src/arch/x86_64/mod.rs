//! Backend de arquitetura para x86_64.
//!
//! Quando chegamos aqui o processador já está em long mode, com paginação
//! ligada no mapa que o [`iniciador`](../../../iniciador/index.html) montou e
//! uma pilha própria — e quem fez isso é deste projeto. Este módulo traduz a
//! [`protocolo::Entrega`] que ele deixou para as estruturas neutras de
//! [`crate::machine`] e segue para o fluxo comum.

pub mod acpi;
pub mod apic;
pub mod botao;
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
pub use usuario::{entrar as entrar_em_usuario, init as init_usuario};

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

    // O regime que o firmware deixou, antes de o kernel escrever um
    // registrador de controle — só para o log do boot.
    REGIME_DO_FIRMWARE.call_once(ler_o_regime_deste_nucleo);

    // SAFETY: o ponteiro é o que o iniciador entregou. A conferência abaixo é
    // o que separa "um ponteiro" de "a entrega": sem ela, um iniciador de
    // outra versão daria campos deslocados, e um mapa de memória lido com
    // deslocamento errado não dá erro — dá um alocador que entrega páginas do
    // firmware.
    let entrega = unsafe { conferir_a_entrega(entrega) };

    DESLOCAMENTO_FISICO.store(entrega.deslocamento_fisico, Ordering::Relaxed);
    acpi::registrar_rsdp(entrega.acpi);
    crate::slots::registrar(entrega.arranque);

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
    // página — que é um desfecho melhor que ler campos deslocados. A
    // entrega mora no começo de uma página do iniciador, e a struct inteira
    // cabe nela mesmo quando o iniciador é de antes do último campo.
    let mut entrega = unsafe { core::ptr::read(entrega) };

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
    // A exceção é o arranque, o único campo que pode faltar: um iniciador
    // de antes dele é um kernel que não veio de slot nenhum — ver
    // `protocolo::Entrega::arranque`.
    if (entrega.tamanho as usize) < protocolo::TAMANHO_SEM_ARRANQUE {
        crate::log_error!(
            "boot",
            "a entrega tem {} bytes, e este kernel le {}",
            entrega.tamanho,
            size_of::<protocolo::Entrega>()
        );
        parar("a entrega e menor do que este kernel le");
    }
    if (entrega.tamanho as usize) < size_of::<protocolo::Entrega>() {
        entrega.arranque = protocolo::Arranque::default();
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

/// Tira o contador de ciclos do anel 3, **neste** núcleo: o `CR4.TSD`
/// ligado torna o `rdtsc` e o `rdtscp` privilegiados, e o `CR4.PCE`
/// desligado — o valor de reset, escrito assim de propósito —, o `rdpmc`.
/// Chamada por [`usuario::ligar_neste_nucleo`], no primeiro núcleo e em cada
/// um que acorda: o `CR4` é do núcleo, e o dos outros copia o do primeiro
/// (`smp::fotografar`), mas a escrita não depende da cópia.
///
/// # O relógio que não passava pelo gate
///
/// O relógio de um programa é o `system.uptime`: uma decisão do gate, com
/// a taxa do papel, que anda de 10 em 10 ms. Com o `CR4` só com o SMEP, o
/// `rdtsc` rodava no anel 3: o contador de ciclos, sem decisão nem
/// registro, numa resolução que o programa calibra contra o
/// `system.uptime` — a régua de um ataque de tempo, fora do modelo escrito
/// (o #451). Nenhum dos programas o usava, e nenhuma conferência o
/// proibia. Agora um processo que o lê morre pela falha de proteção (`#GP`),
/// como um que executa uma instrução privilegiada, e o log diz qual.
///
/// O kernel continua lendo o contador no anel zero — a régua das medidas
/// de custo ([`ciclos`]), o relógio da hora — e o bit não o alcança: ele só
/// vale com CPL > 0. O `rdpid` não é um contador — lê o `IA32_TSC_AUX`, que
/// o regime do núcleo zera ([`escrever_o_regime_deste_nucleo`]) —, e o bit
/// não o toca.
pub(super) fn fechar_os_contadores_ao_usuario() {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    // SAFETY: os dois bits existem em todo x86_64, e o kernel nunca executa
    // `rdtsc`, `rdtscp` nem `rdpmc` fora do anel zero: ligar um e desligar o
    // outro só tira do anel 3 o que ele não deve ter.
    unsafe {
        Cr4::update(|flags| {
            flags.insert(Cr4Flags::TIMESTAMP_DISABLE);
            flags.remove(Cr4Flags::PERFORMANCE_MONITOR_COUNTER);
        })
    };
    #[cfg(feature = "modo-teste")]
    FECHAMENTOS[gdt::nucleo_atual()].fetch_add(1, core::sync::atomic::Ordering::SeqCst);
}

/// Só para a suíte: quantas vezes cada núcleo tirou os contadores do anel 3
/// ([`fechar_os_contadores_ao_usuario`]) — o primeiro no boot, cada
/// secundário ao acordar.
#[cfg(feature = "modo-teste")]
static FECHAMENTOS: [core::sync::atomic::AtomicU64; crate::nucleos::MAX_NUCLEOS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; crate::nucleos::MAX_NUCLEOS];

/// Só para a suíte: quantas vezes o núcleo `cpu` tirou os contadores do
/// anel 3.
#[cfg(feature = "modo-teste")]
pub fn fechamentos_dos_contadores_de_teste(cpu: usize) -> u64 {
    FECHAMENTOS
        .get(cpu)
        .map_or(0, |f| f.load(core::sync::atomic::Ordering::SeqCst))
}

/// Só para a suíte: suja os controles deste núcleo como um firmware que os
/// deixasse abertos — o `CR4.TSD` desligado e o `CR4.PCE` ligado —, e os
/// fecha de novo por [`fechar_os_contadores_ao_usuario`]; devolve os dois
/// bits sujos e os dois de depois. Tudo mascarado: nenhum processo roda
/// neste núcleo no meio.
#[cfg(feature = "modo-teste")]
pub fn sujar_e_fechar_os_contadores_de_teste() -> ((bool, bool), (bool, bool)) {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    sem_interrupcoes(|| {
        // SAFETY: os dois bits existem em todo x86_64; abertos só até a
        // linha seguinte, com as interrupções mascaradas — nenhum processo
        // roda aqui no meio.
        unsafe {
            Cr4::update(|flags| {
                flags.remove(Cr4Flags::TIMESTAMP_DISABLE);
                flags.insert(Cr4Flags::PERFORMANCE_MONITOR_COUNTER);
            })
        };
        let sujos = contadores_do_usuario();
        fechar_os_contadores_ao_usuario();
        (sujos, contadores_do_usuario())
    })
}

/// Só para a suíte: o próprio kernel liga o `TF` no anel 0, com as
/// interrupções mascaradas — `pushfq`, o `TF` no topo, `popfq` —, e roda
/// dois `nop`: o `#DB` do passo chega depois do primeiro, no anel 0, com o
/// `BS` no `DR6`, como o do passo que o `mov ss` de um processo adia até
/// depois da `syscall`. O tratador apaga o `TF` do quadro e volta — ver
/// `idt::depuracao`. Devolve o `RFLAGS` lido depois do segundo `nop`: sem o
/// `TF`, se o tratador o apagou. Sem o conserto, o `#DB` do anel 0 é fatal,
/// e a suíte acaba aqui.
#[cfg(feature = "modo-teste")]
pub fn passo_no_anel_0_de_teste() -> u64 {
    sem_interrupcoes(|| {
        let flags: u64;
        // SAFETY: só as flags mudam: o `TF` ligado pelo `popfq`, que o
        // tratador do `#DB` apaga do quadro depois do primeiro `nop`, e o
        // `RFLAGS` lido de volta. A pilha é a deste fio, e o que se empilha
        // aqui se desempilha aqui; as interrupções seguem mascaradas.
        unsafe {
            core::arch::asm!(
                "pushfq",
                "or qword ptr [rsp], 0x100",
                "popfq",
                "nop",
                "nop",
                "pushfq",
                "pop {flags}",
                flags = out(reg) flags,
            );
        }
        flags
    })
}

/// Só para a suíte: o `CR4.TSD` e o `CR4.PCE` deste núcleo — ver
/// [`fechar_os_contadores_ao_usuario`].
#[cfg(feature = "modo-teste")]
pub fn contadores_do_usuario() -> (bool, bool) {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    let cr4 = Cr4::read();
    (
        cr4.contains(Cr4Flags::TIMESTAMP_DISABLE),
        cr4.contains(Cr4Flags::PERFORMANCE_MONITOR_COUNTER),
    )
}

// ---------------------------------------------------------------------------
// O regime de cada núcleo: o que o firmware deixa, e o que o kernel escreve
// ---------------------------------------------------------------------------

/// O estado de controle de um núcleo que vale para todo processo que roda
/// nele, e que o kernel escreve em vez de herdar — ver
/// [`escrever_o_regime_deste_nucleo`]: o `CR0`, o `CR4`, o `XCR0`, os pontos
/// de parada (`DR0` a `DR3` e o `DR7`), os três registradores do
/// `sysenter`, as bases do `FS` e do `GS` e o `IA32_TSC_AUX`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Regime {
    pub cr0: u64,
    pub cr4: u64,
    /// O `XCR0`, com o `CR4.OSXSAVE` ligado; zero sem ele — o `xgetbv`
    /// seria `#UD`.
    pub xcr0: u64,
    /// Os endereços dos quatro pontos de parada, o `DR0` a o `DR3`.
    pub dr: [u64; 4],
    pub dr7: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    /// As bases ativas do `FS` e do `GS` — o `IA32_FS_BASE` e o
    /// `IA32_GS_BASE` —, e não o `IA32_KERNEL_GS_BASE` do `swapgs`.
    pub fs_base: u64,
    pub gs_base: u64,
    /// O `IA32_TSC_AUX`, o que o `rdtscp` e o `rdpid` entregam; zero sem
    /// eles ([`tem_tsc_aux`]).
    pub tsc_aux: u64,
}

/// Os registradores de modelo do `sysenter`: o seletor de código do anel 0
/// por onde ele entra, a pilha e o endereço.
const IA32_SYSENTER_CS: u32 = 0x174;
const IA32_SYSENTER_ESP: u32 = 0x175;
const IA32_SYSENTER_EIP: u32 = 0x176;

/// O processador tem o `sysenter` — o `SEP`, o bit 11 do `EDX` da folha 1
/// —, e com ele os três registradores de modelo dele? A leitura
/// ([`ler_o_regime_deste_nucleo`]), a escrita
/// ([`escrever_o_regime_deste_nucleo`]) e o regime sujo da suíte perguntam
/// aqui, os três, antes de tocá-los: sem o `SEP`, a arquitetura não promete
/// que eles existam, e o `rdmsr` ou o `wrmsr` de um registrador de modelo
/// que não existe é `#GP` no anel 0 (o item 9 do lote B4 do #448, do
/// revisor do lote B3 — a leitura dizia que eles existem em todo x86_64).
///
/// Perguntar, e não escrever os três sempre — como o Linux, que os escreve
/// pelo `wrmsrl_safe` —: o kernel não tem como se recuperar de um `#GP` no
/// anel 0, e o `wrmsr` num hipervisor que escondesse o `SEP` sem ter os
/// registradores pararia o boot. O que a pergunta deixa de fora é o
/// contrário: um hipervisor que esconda o `SEP` e ainda honre o `sysenter`
/// — o VT-x o honra, pelo VMCS — com valores que o firmware tenha escrito
/// neles, sem o `SEP` que os anuncia; o reset e o OVMF os deixam em repouso
/// (o log do boot), e com o seletor zero o `sysenter` é `#GP(0)`. E esta
/// função não se confere por ela mesma: o caso do regime lê o `SEP` pelo
/// CPUID dele (`regime_sujo_inteiro`, só da suíte), e uma resposta errada
/// daqui o reprova (o achado 2 do adversário do lote B4).
fn tem_sysenter() -> bool {
    core::arch::x86_64::__cpuid(1).edx & (1 << 11) != 0
}

/// O `IA32_TSC_AUX`: o valor que o `rdtscp` e o `rdpid` entregam ao anel 3
/// — ver [`escrever_o_regime_deste_nucleo`].
const IA32_TSC_AUX: u32 = 0xC000_0103;

/// O processador tem o `IA32_TSC_AUX` — o `RDTSCP`, o bit 27 do `EDX` da
/// folha 0x8000_0001, ou o `RDPID`, o bit 22 do `ECX` da folha 7? A
/// leitura, a escrita e o regime sujo da suíte perguntam aqui antes de
/// tocá-lo, como no `sysenter` ([`tem_sysenter`]): sem nenhum dos dois, a
/// arquitetura não promete que ele exista, e o `rdmsr` ou o `wrmsr` seria
/// `#GP` no anel 0. O caso do regime não pergunta aqui: lê o CPUID dele
/// (`regime_sujo_inteiro`, só da suíte).
fn tem_tsc_aux() -> bool {
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    let rdtscp =
        __cpuid(0x8000_0000).eax >= 0x8000_0001 && __cpuid(0x8000_0001).edx & (1 << 27) != 0;
    let rdpid = __cpuid(0).eax >= 7 && __cpuid_count(7, 0).ecx & (1 << 22) != 0;
    rdtscp || rdpid
}

/// O regime deste núcleo, como está agora. Sem o `sysenter`
/// ([`tem_sysenter`]), os três registradores dele saem em zero; sem o
/// `RDTSCP` e o `RDPID` ([`tem_tsc_aux`]), o `IA32_TSC_AUX` também.
pub fn ler_o_regime_deste_nucleo() -> Regime {
    use x86_64::registers::control::{Cr0, Cr4};
    use x86_64::registers::model_specific::Msr;
    use x86_64::registers::model_specific::{FsBase, GsBase};
    let (dr0, dr1, dr2, dr3, dr7): (u64, u64, u64, u64, u64);
    // SAFETY: estamos no anel 0; ler os registradores de depuração e as
    // bases do `FS` e do `GS`, que existem em todo x86_64, os três do
    // `sysenter`, só com o `SEP`, e o `IA32_TSC_AUX`, só com o `RDTSCP` ou
    // o `RDPID`, não muda nada.
    let ((cs, esp, eip), (fs_base, gs_base), tsc_aux) = unsafe {
        core::arch::asm!(
            "mov {}, dr0",
            "mov {}, dr1",
            "mov {}, dr2",
            "mov {}, dr3",
            "mov {}, dr7",
            out(reg) dr0,
            out(reg) dr1,
            out(reg) dr2,
            out(reg) dr3,
            out(reg) dr7,
            options(nomem, nostack, preserves_flags)
        );
        let sysenter = if tem_sysenter() {
            (
                Msr::new(IA32_SYSENTER_CS).read(),
                Msr::new(IA32_SYSENTER_ESP).read(),
                Msr::new(IA32_SYSENTER_EIP).read(),
            )
        } else {
            (0, 0, 0)
        };
        let tsc_aux = if tem_tsc_aux() {
            Msr::new(IA32_TSC_AUX).read()
        } else {
            0
        };
        (sysenter, (FsBase::MSR.read(), GsBase::MSR.read()), tsc_aux)
    };
    Regime {
        cr0: Cr0::read_raw(),
        cr4: Cr4::read_raw(),
        xcr0: ler_o_xcr0(),
        dr: [dr0, dr1, dr2, dr3],
        dr7,
        sysenter_cs: cs,
        sysenter_esp: esp,
        sysenter_eip: eip,
        fs_base,
        gs_base,
        tsc_aux,
    }
}

/// O `XCR0` deste núcleo, com o `CR4.OSXSAVE` ligado; zero sem ele — o
/// `xgetbv` seria `#UD`.
fn ler_o_xcr0() -> u64 {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    if !Cr4::read().contains(Cr4Flags::OSXSAVE) {
        return 0;
    }
    let (baixo, alto): (u32, u32);
    // SAFETY: o `OSXSAVE` está ligado, e o `xgetbv` do `XCR0` só lê.
    unsafe {
        core::arch::asm!(
            "xgetbv",
            in("ecx") 0u32,
            out("eax") baixo,
            out("edx") alto,
            options(nomem, nostack, preserves_flags)
        );
    }
    (u64::from(alto) << 32) | u64::from(baixo)
}

/// O regime que o primeiro núcleo trouxe do firmware — e do iniciador, que
/// não toca nele —, lido na primeira instrução Rust ([`_start`]), antes de o
/// kernel escrever qualquer registrador de controle. Só para o log do boot
/// ([`usuario::init`]): o que o OVMF deixa, numa máquina, é o que esta linha
/// diz.
static REGIME_DO_FIRMWARE: spin::Once<Regime> = spin::Once::new();

/// O regime que o primeiro núcleo trouxe do firmware — ver
/// [`REGIME_DO_FIRMWARE`].
pub fn regime_do_firmware() -> Option<Regime> {
    REGIME_DO_FIRMWARE.get().copied()
}

/// O `DR7` em repouso: nenhum ponto de parada armado, e o bit 10, reservado,
/// ligado.
const DR7_EM_REPOUSO: u64 = 0x400;

/// O `DR6` em repouso — ver `idt::depuracao`.
const DR6_EM_REPOUSO: u64 = 0xFFFF_0FF0;

/// O `CR4` que o kernel quer, bit por bit, e não o que o firmware deixou: o
/// primeiro núcleo o escreve inteiro ([`escrever_o_regime_deste_nucleo`]),
/// e cada um que acorda também (`smp::entrada_secundaria`), em vez de
/// copiar o do primeiro.
///
/// - **`PAE`**: o modo longo o exige.
/// - **`LA57`**: o que já está — ele não muda no modo longo, e o iniciador
///   monta tabelas de quatro níveis.
/// - **`TSD`** ligado e **`PCE`** desligado: o contador de ciclos e os de
///   desempenho fora do anel 3 (o #451; ver
///   [`fechar_os_contadores_ao_usuario`]).
/// - **`OSFXSR`**: para que o SSE de um processo seja o `#NM` do `CR0.TS`,
///   como o x87 — sem ele, seria `#UD` antes —; o kernel é *soft-float* e
///   não o usa. O **`OSXMMEXCPT`**, como o OVMF o deixa: ele só escolhe
///   entre o `#XM` e o `#UD` de uma exceção de SIMD desmascarada,
///   inalcançável com o `TS`. E o **`OSXSAVE`**, se o processador tem o
///   `xsave`: com ele, o regime escreve o `XCR0` do kernel
///   ([`xcr0_do_kernel`]), e o AVX de um processo é o `#NM` do `TS`, como
///   o SSE.
/// - **`DE`**, se o processador o tem: o `DR4` e o `DR5` deixam de ser
///   apelidos do `DR6` e do `DR7` — mais estrito, e o OVMF já o liga.
/// - **`MCE`**, se o processador o tem: sem ele, uma verificação da máquina
///   desliga o processador, em vez de chegar ao tratador do `#MC`.
/// - **`SMEP`**, se o processador o tem: o anel 0 não executa página de
///   usuário (ver [`exigir_que_o_kernel_nao_execute_pagina_de_usuario`]).
/// - **`UMIP`**, se o processador o tem: o `str`, o `sldt`, o `smsw`, o
///   `sgdt` e o `sidt` do anel 3 são `#GP(0)`, e o processo morre dele. Sem
///   ele, diziam ao processo o seletor do TSS do núcleo, o do LDT, o `CR0`
///   baixo e onde estão a GDT e a IDT do kernel (o item 6 do adversário do
///   lote B3 do #448). O `str` do anel 0 — [`gdt::nucleo_atual`] — ele não
///   toca. A suíte roda com o `+umip` no `-cpu` (`xtask`), que o TCG emula.
///
/// E nada mais, desligado de propósito. Entre os que um firmware poderia ter
/// deixado: o **`FSGSBASE`**, que daria ao anel 3 o `wrfsbase` e o
/// `wrgsbase` — a base do `FS` e do `GS`, que o kernel não guarda por
/// processo, seria outro registrador passado de um processo ao seguinte no
/// mesmo núcleo —, o **`PKE`**, pelo mesmo motivo com o `PKRU`, o **`SMAP`**
/// e o **`CET`**, que o kernel não sabe atender, o **`PCIDE`**, o **`PGE`**
/// — nenhuma página do kernel é global —, o **`VME`** e o **`PVI`**. O OVMF
/// deixa `DE`, `PAE`, `MCE`, `OSFXSR` e `OSXMMEXCPT` (0x668, no log do
/// boot).
pub(super) fn cr4_do_kernel() -> u64 {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    let um = core::arch::x86_64::__cpuid(1);
    let (sete_ebx, sete_ecx) = if core::arch::x86_64::__cpuid(0).eax >= 7 {
        let sete = core::arch::x86_64::__cpuid_count(7, 0);
        (sete.ebx, sete.ecx)
    } else {
        (0, 0)
    };
    let mut cr4 = Cr4Flags::PHYSICAL_ADDRESS_EXTENSION
        | Cr4Flags::TIMESTAMP_DISABLE
        | Cr4Flags::OSFXSR
        | Cr4Flags::OSXMMEXCPT_ENABLE;
    // O `LA57` não muda no modo longo: o que está.
    cr4 |= Cr4::read() & Cr4Flags::L5_PAGING;
    for (tem, bit) in [
        (um.edx & (1 << 2) != 0, Cr4Flags::DEBUGGING_EXTENSIONS),
        (um.edx & (1 << 7) != 0, Cr4Flags::MACHINE_CHECK_EXCEPTION),
        (um.ecx & (1 << 26) != 0, Cr4Flags::OSXSAVE),
        (
            sete_ebx & (1 << 7) != 0,
            Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION,
        ),
        (
            sete_ecx & (1 << 2) != 0,
            Cr4Flags::USER_MODE_INSTRUCTION_PREVENTION,
        ),
    ] {
        if tem {
            cr4 |= bit;
        }
    }
    cr4.bits()
}

/// O `XCR0` que o kernel escreve em todo núcleo com o `OSXSAVE` — ver
/// [`escrever_o_regime_deste_nucleo`]: o x87, que a arquitetura exige; o SSE
/// e o AVX, se o processador os declara (`CPUID.(0xD,0).EAX`) — o AVX só
/// com o SSE, que ela também exige —; e nada mais. Os outros componentes do
/// `xsave` ficam desligados: as instruções do AMX são `#UD`, e as do MPX,
/// no espaço dos `nop`, não tocam os limites. Nenhum dos dois confere o
/// `CR0.TS` — o `#NM` dos ladrilhos é o do `XFD`, e os registradores de
/// limites não são estado de ponto flutuante —, e com eles ligados os
/// ladrilhos e os limites de um processo passariam ao seguinte no mesmo
/// núcleo.
pub(super) fn xcr0_do_kernel() -> u64 {
    const X87: u64 = 1;
    const SSE: u64 = 1 << 1;
    const AVX: u64 = 1 << 2;
    let declarados = if core::arch::x86_64::__cpuid(0).eax >= 0xD {
        u64::from(core::arch::x86_64::__cpuid_count(0xD, 0).eax)
    } else {
        X87
    };
    let sse = declarados & SSE;
    let avx = if sse != 0 { declarados & AVX } else { 0 };
    X87 | sse | avx
}

/// Escreve o regime deste núcleo: o que vale para todo processo que roda
/// nele, e que o kernel não herda do firmware. Chamada por
/// [`usuario::ligar_neste_nucleo`], no primeiro núcleo e em cada um que
/// acorda, antes do primeiro processo dele. Devolve o regime escrito.
///
/// - **O `CR0.TS` e o `CR0.MP` ligados, e nunca desligados** — nenhum `clts`
///   no kernel —, e o `CR0.EM` desligado: toda instrução de um processo que
///   toca o estado do x87, do MMX, do SSE ou do AVX é `#NM` — o AVX sem o
///   `OSXSAVE` é `#UD` antes —, e o processo morre dela
///   (`idt::dispositivo_indisponivel`); o `MP` põe o `wait` junto. O kernel
///   não salvava nem zerava o estado de ponto flutuante de um processo para
///   o outro, e o `xmm0` que um deixava chegava ao seguinte no mesmo núcleo
///   — um canal entre titulares, por fora do gate, da auditoria e do NSF (o
///   achado 2 do adversário do lote B2 do #448). Os alvos dos programas e do
///   kernel são *soft-float* (o DS-2), e nenhum programa do contrato usa
///   ponto flutuante: o código de fora dele passa de uma corrupção calada a
///   uma falha dita. Salvar e restaurar o estado, e liberá-lo aos programas,
///   é a R12-SIMD (`docs/DECISOES.md`), que continua aberta.
/// - **O `CR4`**: o de [`cr4_do_kernel`], inteiro.
/// - **O `XCR0`**: o de [`xcr0_do_kernel`], se o `CR4` tem o `OSXSAVE`.
///   Antes, era o que o firmware deixou no primeiro núcleo, e os
///   secundários copiavam o dele (`smp`): um firmware que deixasse o AMX
///   ligado (`XCR0[18:17]`), num processador que o tem, deixava os
///   ladrilhos passarem de um processo ao seguinte no mesmo núcleo — eles
///   não conferem o `CR0.TS` (o item 4 do adversário do lote B3 do #448). O
///   `qemu64` da suíte não tem o `xsave`: ali não há o que escrever. Uma
///   rodada à parte, fora da CI, com o `+xsave` e o `+xsaveopt` no `-cpu`,
///   exercitou a escrita e o caso do regime; e outra, com o `+pku` junto, o
///   filtro: o PKRU que essa CPU declara fica de fora. Com o `+xsave`
///   sozinho, o
///   QEMU 8.2 para a máquina na escrita do `CR4`: ele marca o `OSXSAVE`
///   como reservado quando o `CPUID.(0xD,1).EAX` é zero, e a escrita de um
///   bit reservado do `CR4` vira, no TCG, um falso VMEXIT, e não o `#GP(0)`
///   da arquitetura (ver o README).
/// - **O `DR7` e o `DR6` em repouso** (0x400 e 0xFFFF_0FF0: nenhum ponto
///   armado, nenhuma causa), e os quatro pontos zerados: um ponto de parada
///   que o firmware deixasse armado daria um `#DB` no anel 0, que é fatal.
/// - **Os três registradores do `sysenter` em zero**, se o processador tem
///   o `sysenter`: num Intel, ele existe no modo de 64 bits, e entraria no
///   anel 0 pelo `IA32_SYSENTER_CS` e pelo `IA32_SYSENTER_EIP` que o
///   firmware deixasse; com o seletor zero, é `#GP(0)`, e o processo morre
///   dele. Num AMD, ele é `#UD` no modo longo de qualquer jeito.
/// - **As bases do `FS` e do `GS` em zero** — o `IA32_FS_BASE` e o
///   `IA32_GS_BASE`. O seletor nulo que `gdt::carregar` põe nos dois já as
///   zera num Intel e no TCG, mas não num AMD sem o
///   `NullSelectorClearsBase` (o `X86_BUG_NULL_SEG` do Linux): ali, a base
///   que o firmware deixasse chegava aos processos do núcleo, pelo
///   endereçamento relativo ao `FS` e ao `GS`, até um deles carregar um
///   seletor não nulo, de base zero (um informativo do adversário do lote
///   B4 do #448). O `IA32_KERNEL_GS_BASE`, o do `swapgs`, não: ele é a
///   estrutura deste núcleo, que [`usuario::ligar_neste_nucleo`] escreve
///   logo depois daqui. O kernel não usa o `FS`, e o `GS` só na janela do
///   `swapgs` da entrada da `syscall`, que corre com o `IF` limpo: nada
///   daqui cai nela.
/// - **O `IA32_TSC_AUX` em zero**, se o processador tem o `RDTSCP` ou o
///   `RDPID` ([`tem_tsc_aux`]). O `CR4.TSD` prende o `rdtscp` no anel 3, mas
///   não o `rdpid`, que o entrega a qualquer processo; o kernel não o usa,
///   e o valor que o firmware — ou o sistema de antes, num reboot quente —
///   deixasse ali chegaria aos processos do núcleo, como as bases do `FS` e
///   do `GS`: de mão única, um por núcleo e por boot, e não um canal entre
///   processos, que nenhum o escreve (um informativo do adversário do delta
///   do lote B4 do #448).
pub(super) fn escrever_o_regime_deste_nucleo() -> Regime {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4};
    use x86_64::registers::model_specific::{FsBase, GsBase, Msr};
    let tem_sysenter = tem_sysenter();
    let tem_tsc_aux = tem_tsc_aux();
    // SAFETY: estamos no anel 0, e cada escrita só torna o processador mais
    // estrito para o anel 3 ou devolve a ele o estado de repouso: o kernel
    // não executa instrução de ponto flutuante nem de SIMD (o alvo é
    // *soft-float*, e `xtask::conferir_sem_simd` confere o binário — o
    // `fninit` do núcleo que acorda vem antes daqui), os bits do `CR4` e os
    // do `XCR0` são os que o processador declara — o `xsetbv` só com o
    // `OSXSAVE` que o `CR4` acabou de ligar —, os pontos de parada não são do
    // kernel, o `sysenter` não é a entrada de chamadas dele, ele não usa a
    // base do `FS` nem a do `GS` fora da janela do `swapgs`, e não lê o
    // `IA32_TSC_AUX` — o `wrmsr` dele, só com o `RDTSCP` ou o `RDPID`.
    unsafe {
        Cr0::update(|flags| {
            flags.insert(Cr0Flags::TASK_SWITCHED | Cr0Flags::MONITOR_COPROCESSOR);
            flags.remove(Cr0Flags::EMULATE_COPROCESSOR);
        });
        Cr4::write_raw(cr4_do_kernel());
        if Cr4::read().contains(x86_64::registers::control::Cr4Flags::OSXSAVE) {
            let xcr0 = xcr0_do_kernel();
            core::arch::asm!(
                "xsetbv",
                in("ecx") 0u32,
                in("eax") xcr0 as u32,
                in("edx") (xcr0 >> 32) as u32,
                options(nomem, nostack, preserves_flags)
            );
        }
        core::arch::asm!(
            "mov dr7, {repouso}",
            "mov dr0, {zero}",
            "mov dr1, {zero}",
            "mov dr2, {zero}",
            "mov dr3, {zero}",
            "mov dr6, {dr6}",
            repouso = in(reg) DR7_EM_REPOUSO,
            zero = in(reg) 0u64,
            dr6 = in(reg) DR6_EM_REPOUSO,
            options(nomem, nostack, preserves_flags)
        );
        if tem_sysenter {
            Msr::new(IA32_SYSENTER_CS).write(0);
            Msr::new(IA32_SYSENTER_ESP).write(0);
            Msr::new(IA32_SYSENTER_EIP).write(0);
        }
        if tem_tsc_aux {
            Msr::new(IA32_TSC_AUX).write(0);
        }
    }
    FsBase::write(x86_64::VirtAddr::zero());
    GsBase::write(x86_64::VirtAddr::zero());
    #[cfg(feature = "modo-teste")]
    REGIMES[gdt::nucleo_atual()].fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    ler_o_regime_deste_nucleo()
}

/// Só para a suíte: quantas vezes cada núcleo escreveu o regime
/// ([`escrever_o_regime_deste_nucleo`]) — o primeiro no boot, cada
/// secundário ao acordar.
#[cfg(feature = "modo-teste")]
static REGIMES: [core::sync::atomic::AtomicU64; crate::nucleos::MAX_NUCLEOS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; crate::nucleos::MAX_NUCLEOS];

/// Só para a suíte: quantas vezes o núcleo `cpu` escreveu o regime.
#[cfg(feature = "modo-teste")]
pub fn regimes_escritos_de_teste(cpu: usize) -> u64 {
    REGIMES
        .get(cpu)
        .map_or(0, |r| r.load(core::sync::atomic::Ordering::SeqCst))
}

/// Só para a suíte: o regime que o kernel escreve, como o caso o confere,
/// bit a bit contra o CPUID lido aqui — e não contra [`cr4_do_kernel`], que
/// é quem escreve: comparar o `CR4` com ela era tautológico, e tirar dela o
/// `MCE` ou o `DE` passava (o item 7 do lote B4 do #448). O `CR0` com o
/// `TS` e o `MP` e sem o `EM`; no `CR4`, o `PAE`, o `TSD`, o `OSFXSR` e o
/// `OSXMMEXCPT` ligados, o `DE`, o `MCE`, o `OSXSAVE`, o `SMEP` e o `UMIP`
/// conforme o processador os declara, o `LA57` como está, e nenhum outro —
/// o `PCE`, o `PGE`, o `FSGSBASE`, o `PKE`, o `VME`, o `PVI`, o `SMAP`, o
/// `PCIDE` e o `CET` desligados, pelo nome —; o `XCR0` com o x87, o SSE e o
/// AVX que o processador declara, e nada mais, se há o `OSXSAVE`; nenhum
/// ponto de parada armado no `DR7`, e os quatro endereços em zero; os três
/// do `sysenter` em zero; as bases do `FS` e do `GS` em zero; e o
/// `IA32_TSC_AUX` em zero. Devolve o primeiro que diverge.
#[cfg(feature = "modo-teste")]
pub fn regime_como_o_kernel_escreve(r: &Regime) -> Result<(), &'static str> {
    use x86_64::registers::control::{Cr0Flags, Cr4Flags as F};
    let maximo = core::arch::x86_64::__cpuid(0).eax;
    let um = core::arch::x86_64::__cpuid(1);
    let (sete_ebx, sete_ecx) = if maximo >= 7 {
        let sete = core::arch::x86_64::__cpuid_count(7, 0);
        (sete.ebx, sete.ecx)
    } else {
        (0, 0)
    };
    let cr0 = Cr0Flags::from_bits_truncate(r.cr0);
    if !cr0.contains(Cr0Flags::TASK_SWITCHED) {
        return Err("o CR0 sem o TS");
    }
    if !cr0.contains(Cr0Flags::MONITOR_COPROCESSOR) {
        return Err("o CR0 sem o MP");
    }
    if cr0.contains(Cr0Flags::EMULATE_COPROCESSOR) {
        return Err("o CR0 com o EM");
    }
    let osxsave = um.ecx & (1 << 26) != 0;
    let bits = [
        ("PAE", F::PHYSICAL_ADDRESS_EXTENSION, true),
        ("TSD", F::TIMESTAMP_DISABLE, true),
        ("OSFXSR", F::OSFXSR, true),
        ("OSXMMEXCPT", F::OSXMMEXCPT_ENABLE, true),
        ("DE", F::DEBUGGING_EXTENSIONS, um.edx & (1 << 2) != 0),
        ("MCE", F::MACHINE_CHECK_EXCEPTION, um.edx & (1 << 7) != 0),
        ("OSXSAVE", F::OSXSAVE, osxsave),
        (
            "SMEP",
            F::SUPERVISOR_MODE_EXECUTION_PROTECTION,
            sete_ebx & (1 << 7) != 0,
        ),
        (
            "UMIP",
            F::USER_MODE_INSTRUCTION_PREVENTION,
            sete_ecx & (1 << 2) != 0,
        ),
        ("PCE", F::PERFORMANCE_MONITOR_COUNTER, false),
        ("PGE", F::PAGE_GLOBAL, false),
        ("FSGSBASE", F::FSGSBASE, false),
        ("PKE", F::PROTECTION_KEY_USER, false),
        ("VME", F::VIRTUAL_8086_MODE_EXTENSIONS, false),
        ("PVI", F::PROTECTED_MODE_VIRTUAL_INTERRUPTS, false),
        ("SMAP", F::SUPERVISOR_MODE_ACCESS_PREVENTION, false),
        ("PCIDE", F::PCID, false),
        ("CET", F::CONTROL_FLOW_ENFORCEMENT, false),
    ];
    let cr4 = F::from_bits_retain(r.cr4);
    // O `LA57` não muda no modo longo: o que está.
    let mut conhecidos = F::L5_PAGING;
    for (nome, bit, ligado) in bits {
        if cr4.contains(bit) != ligado {
            return Err(nome);
        }
        conhecidos |= bit;
    }
    if r.cr4 & !conhecidos.bits() != 0 {
        return Err("um bit do CR4 que o kernel nao liga");
    }
    // O x87 sempre; o SSE e o AVX se o processador os declara, e o AVX só
    // com o SSE.
    let xcr0 = if osxsave {
        let declarados = if maximo >= 0xD {
            u64::from(core::arch::x86_64::__cpuid_count(0xD, 0).eax)
        } else {
            0
        };
        let sse = declarados & 0b10;
        let avx = if sse != 0 { declarados & 0b100 } else { 0 };
        1 | sse | avx
    } else {
        0
    };
    if r.xcr0 != xcr0 {
        return Err("o XCR0");
    }
    if r.dr7 & 0xFF != 0 {
        return Err("um ponto de parada armado no DR7");
    }
    if r.dr != [0; 4] {
        return Err("um dos DR0 a DR3 fora de zero");
    }
    if r.sysenter_cs != 0 || r.sysenter_esp != 0 || r.sysenter_eip != 0 {
        return Err("um registrador do sysenter fora de zero");
    }
    if r.fs_base != 0 || r.gs_base != 0 {
        return Err("a base do FS ou a do GS fora de zero");
    }
    if r.tsc_aux != 0 {
        return Err("o TSC_AUX fora de zero");
    }
    Ok(())
}

/// Só para a suíte: o regime sujo de [`sujar_e_reescrever_o_regime_de_teste`]
/// aparece inteiro na leitura — cada item que ela suja, sujo —, para que o
/// "depois" do caso prove a reescrita de cada um, e não só a do primeiro que
/// diverge (o achado 2 do adversário do lote B4 do #448). O `SEP`, o
/// `xsave`, o `RDTSCP` e o `RDPID` saem do CPUID lido aqui, e não de
/// [`tem_sysenter`], de [`tem_tsc_aux`] nem do `CR4` sujo: a leitura, a
/// sujeira e a escrita do `sysenter` passam as três por
/// [`tem_sysenter`], e com ela errada nada se sujava, a leitura dava zero
/// por construção, nada se escrevia, e o caso passava sem ter conferido os
/// três. Devolve o primeiro item que não apareceu sujo.
#[cfg(feature = "modo-teste")]
pub fn regime_sujo_inteiro(r: &Regime) -> Result<(), &'static str> {
    use x86_64::registers::control::{Cr0Flags, Cr4Flags as F};
    let um = core::arch::x86_64::__cpuid(1);
    let cr0 = Cr0Flags::from_bits_truncate(r.cr0);
    if cr0.intersects(Cr0Flags::TASK_SWITCHED | Cr0Flags::MONITOR_COPROCESSOR) {
        return Err("o CR0 sujo ainda com o TS ou o MP");
    }
    if !F::from_bits_retain(r.cr4).contains(CR4_SUJO) {
        return Err("o CR4 sujo sem o PGE, o PCE, o VME ou o PVI");
    }
    // O `xsave` do processador, o bit 26 do `ECX` da folha 1: com ele, o
    // regime do kernel liga o `OSXSAVE`, e o sujo escreve o `XCR0` só com o
    // x87.
    if um.ecx & (1 << 26) != 0 && r.xcr0 != 1 {
        return Err("o XCR0 sujo nao e so o x87");
    }
    if r.dr != DR_SUJOS || r.dr7 & DR7_SUJO != DR7_SUJO {
        return Err("os pontos de parada sujos nao foram escritos ou nao foram lidos");
    }
    // O `SEP`, o bit 11 do `EDX` da folha 1: lido aqui, e não por
    // [`tem_sysenter`], que é o que se confere.
    let codigo_kernel = u64::from(gdt::seletores().codigo_kernel.0);
    if um.edx & (1 << 11) != 0
        && (r.sysenter_cs != codigo_kernel
            || r.sysenter_esp != ENDERECO_INVALIDO
            || r.sysenter_eip != ENDERECO_INVALIDO)
    {
        return Err("o sysenter sujo nao foi escrito ou lido, e o processador declara o SEP");
    }
    if r.fs_base != FS_BASE_SUJA || r.gs_base != GS_BASE_SUJA {
        return Err("as bases do FS e do GS sujas nao foram escritas ou nao foram lidas");
    }
    // O `RDTSCP` (o bit 27 do `EDX` da folha 0x8000_0001) e o `RDPID` (o bit
    // 22 do `ECX` da folha 7): lidos aqui, e não por [`tem_tsc_aux`].
    let rdtscp = core::arch::x86_64::__cpuid(0x8000_0000).eax >= 0x8000_0001
        && core::arch::x86_64::__cpuid(0x8000_0001).edx & (1 << 27) != 0;
    let rdpid = core::arch::x86_64::__cpuid(0).eax >= 7
        && core::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 22) != 0;
    if (rdtscp || rdpid) && r.tsc_aux != TSC_AUX_SUJO {
        return Err("o TSC_AUX sujo nao foi escrito ou lido, e o processador o declara");
    }
    Ok(())
}

/// Só para a suíte: o processador declara o UMIP (o bit 2 do `ECX` da folha
/// 7), e o `CR4` deste núcleo o tem ligado?
#[cfg(feature = "modo-teste")]
pub fn umip_de_teste() -> (bool, bool) {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    let tem = core::arch::x86_64::__cpuid(0).eax >= 7
        && core::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 2) != 0;
    let ligado = Cr4::read().contains(Cr4Flags::USER_MODE_INSTRUCTION_PREVENTION);
    (tem, ligado)
}

/// Só para a suíte: os bits do `CR4` que o regime sujo liga, e que o kernel
/// não liga — ver [`sujar_e_reescrever_o_regime_de_teste`].
#[cfg(feature = "modo-teste")]
const CR4_SUJO: x86_64::registers::control::Cr4Flags = {
    use x86_64::registers::control::Cr4Flags as F;
    F::PAGE_GLOBAL
        .union(F::PERFORMANCE_MONITOR_COUNTER)
        .union(F::VIRTUAL_8086_MODE_EXTENSIONS)
        .union(F::PROTECTED_MODE_VIRTUAL_INTERRUPTS)
};

/// Só para a suíte: os quatro endereços dos pontos de parada sujos, perto de
/// [`ENDERECO_INVALIDO`].
#[cfg(feature = "modo-teste")]
const DR_SUJOS: [u64; 4] = [
    ENDERECO_INVALIDO,
    ENDERECO_INVALIDO + 8,
    ENDERECO_INVALIDO + 16,
    ENDERECO_INVALIDO + 24,
];

/// Só para a suíte: o `DR7` sujo — o `L0`, de leitura e escrita, de quatro
/// bytes (o `LEN0` em 11; oito seria o 10); os outros três pontos só com o
/// endereço, desarmados.
#[cfg(feature = "modo-teste")]
const DR7_SUJO: u64 = 1 | (0b11 << 16) | (0b11 << 18);

/// Só para a suíte: as bases do `FS` e do `GS` sujas, perto de
/// [`ENDERECO_INVALIDO`].
#[cfg(feature = "modo-teste")]
const FS_BASE_SUJA: u64 = ENDERECO_INVALIDO + 0x40;
#[cfg(feature = "modo-teste")]
const GS_BASE_SUJA: u64 = ENDERECO_INVALIDO + 0x48;

/// Só para a suíte: a marca do `IA32_TSC_AUX` sujo — 32 bits: os de cima
/// são reservados, e o `wrmsr` com eles seria `#GP`.
#[cfg(feature = "modo-teste")]
const TSC_AUX_SUJO: u64 = 0x7E57_0A11;

/// Só para a suíte: suja o regime deste núcleo como um firmware que o
/// deixasse aberto — o `CR0` sem o `TS` e o `MP`; o `CR4` com o `PGE`, o
/// `PCE`, o `VME` e o `PVI`, que o kernel não liga; o `XCR0` só com o x87,
/// se há o `OSXSAVE`; um ponto de parada armado no `DR7` e os quatro
/// endereços dos pontos fora de zero, perto de [`ENDERECO_INVALIDO`], uma
/// página que nada toca no meio; o `sysenter` apontado para o anel 0, se o
/// processador o tem ([`tem_sysenter`]); as bases do `FS` e do `GS` perto do
/// mesmo endereço; e uma marca no `IA32_TSC_AUX`, se o processador o tem
/// ([`tem_tsc_aux`]) —, e o escreve de novo por
/// [`escrever_o_regime_deste_nucleo`]; devolve o regime sujo e o de depois.
/// Tudo mascarado: nenhum processo roda neste núcleo no meio, e o kernel não
/// executa ponto flutuante, não toca o endereço armado, não usa a base do
/// `FS` e só usa a do `GS` na janela do `swapgs`, que não corre aqui. O caso
/// confere que o sujo apareceu inteiro na leitura ([`regime_sujo_inteiro`]),
/// e não só que ele diverge do do kernel.
#[cfg(feature = "modo-teste")]
pub fn sujar_e_reescrever_o_regime_de_teste() -> (Regime, Regime) {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
    use x86_64::registers::model_specific::{FsBase, GsBase, Msr};
    sem_interrupcoes(|| {
        // SAFETY: tudo só até a linha seguinte, com as interrupções
        // mascaradas — ver acima. O `PGE` e o `PCE` existem em todo x86_64,
        // e nenhuma entrada de página do kernel é global: ligá-lo não muda
        // tradução nenhuma. O `VME` e o `PVI` também — e o QEMU do TCG os
        // aceita mesmo com o `qemu64`, que não declara o `VME` —, e só valem
        // no modo virtual 8086 e no anel 3, que não rodam no meio. O `XCR0`
        // só com o x87 é sempre válido, e o kernel não usa o `xsave`.
        unsafe {
            Cr0::update(|flags| {
                flags.remove(Cr0Flags::TASK_SWITCHED | Cr0Flags::MONITOR_COPROCESSOR)
            });
            Cr4::update(|flags| flags.insert(CR4_SUJO));
            if Cr4::read().contains(Cr4Flags::OSXSAVE) {
                core::arch::asm!(
                    "xsetbv",
                    in("ecx") 0u32,
                    in("eax") 1u32,
                    in("edx") 0u32,
                    options(nomem, nostack, preserves_flags)
                );
            }
            core::arch::asm!(
                "mov dr0, {alvo}",
                "mov dr1, {um}",
                "mov dr2, {dois}",
                "mov dr3, {tres}",
                "mov dr7, {armado}",
                alvo = in(reg) DR_SUJOS[0],
                um = in(reg) DR_SUJOS[1],
                dois = in(reg) DR_SUJOS[2],
                tres = in(reg) DR_SUJOS[3],
                armado = in(reg) DR7_EM_REPOUSO | DR7_SUJO,
                options(nomem, nostack, preserves_flags)
            );
            if tem_sysenter() {
                let sel = gdt::seletores();
                Msr::new(IA32_SYSENTER_CS).write(u64::from(sel.codigo_kernel.0));
                Msr::new(IA32_SYSENTER_ESP).write(ENDERECO_INVALIDO);
                Msr::new(IA32_SYSENTER_EIP).write(ENDERECO_INVALIDO);
            }
            if tem_tsc_aux() {
                Msr::new(IA32_TSC_AUX).write(TSC_AUX_SUJO);
            }
        }
        FsBase::write(x86_64::VirtAddr::new(FS_BASE_SUJA));
        GsBase::write(x86_64::VirtAddr::new(GS_BASE_SUJA));
        let sujo = ler_o_regime_deste_nucleo();
        (sujo, escrever_o_regime_deste_nucleo())
    })
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
    marcar_compartilhada, marcar_copia_na_escrita, percorrer_paginas_do_usuario,
    sincronizar_instrucoes, traduzir, trocar_espaco,
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

    if !tsc_invariante() {
        crate::log_warn!(
            "irq",
            "o CPUID nao anuncia o TSC invariante (0x80000007, EDX bit 8): a grade dos tiques e a regua do civil supoem o TSC numa taxa so, e igual em todos os nucleos"
        );
    }

    // SAFETY: a paginação está no ar, o PIT está rodando desde
    // `init_interrupcoes` e as interrupções estão habilitadas — as três
    // pré-condições da calibração.
    let Some(efetiva) = (unsafe { apic::init(HZ) }) else {
        crate::log_info!("irq", "sem APIC local utilizavel; o PIT continua");
        return;
    };

    // Só agora o PIT pode ser desligado. Entre a programação do APIC e esta
    // linha os dois disparam, e só o PIT anda o relógio: o APIC conta os
    // tiques dele, para a conferência, e assume o relógio logo abaixo, com o
    // PIT já mascarado (`apic::assumir_o_relogio`). Até o #455-C os dois o
    // andavam, ao dobro, duzentos milissegundos por tentativa da
    // conferência. A ordem é a que não arrisca: desligar o PIT primeiro
    // seria descobrir tarde que o APIC não estava contando.
    //
    // SAFETY: o timer do APIC já está entregando no lugar dele.
    unsafe { pic::mascarar(0) };
    apic::assumir_o_relogio();

    crate::tempo::registrar_frequencia(efetiva);
    crate::irq::nomear(apic::VETOR_TIMER as usize, "timer-apic");
    crate::irq::nomear(apic::VETOR_ESPURIO as usize, "apic-espuria");

    crate::log_info!(
        "irq",
        "timer do APIC a {} Hz no nucleo {}, pela grade do TSC (barramento medido em {} kHz), PIT desligado",
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

/// Quantas vezes [`esperar_interrupcao`] — ou [`dormir_se_ocioso`] — girou
/// em vez de dormir.
///
/// # Por que contar, em vez de deixar escrito que é zero
///
/// Porque já estava escrito, e uma frase não se remede sozinha. O ramo
/// mascarado destas funções é um giro que só termina se **outro** fio
/// religar as interrupções; para quem chamou sem ter para onde voltar, ele
/// é o fim. A medida de que ele nunca é tomado era o que autorizava os
/// chamadores de hoje — o laço do agente, e o descanso do coletor, que
/// desde o lote B3 do #448 pergunta pelo chamado dentro da janela de
/// [`dormir_se_ocioso`] — a usarem estas funções em vez de
/// [`dormir_parado`].
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
        // nada poderia acordá-lo. Girar é desperdício, mas é recuperável — e
        // contado, como o de `esperar_interrupcao` (ver `giros_mascarados`).
        #[cfg(feature = "modo-teste")]
        GIROS_MASCARADOS.fetch_add(1, Ordering::Relaxed);
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

/// Mascara as interrupções deste núcleo, sem devolver o estado de antes:
/// para quem não volta mais — o handler de pânico, que roda assim até
/// reiniciar ou parar, como o caminho da falha fatal, que entra por um
/// portão de exceção, já mascarado.
pub fn mascarar_as_interrupcoes() {
    x86_64::instructions::interrupts::disable();
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

/// Como esta máquina reinicia e desliga, pelo que a ACPI descreve: o
/// reinício pelo registrador da FADT (`acpi`) ou pela porta `0xCF9`
/// (`cf9`, que todo PC tem); o desligamento pelo S5 (`acpi-s5`), pelo
/// controle de sono do hardware reduzido (`acpi-reduzido`), ou nenhum.
pub fn meios_da_energia() -> (&'static str, &'static str) {
    let Ok(e) = acpi::energia() else {
        return ("cf9", "nenhum");
    };
    let reinicio = if e.reinicio.is_some() { "acpi" } else { "cf9" };
    let desligamento = match (e.pm1a, e.s5, e.controle_de_sono) {
        (Some(_), Some(_), _) => "acpi-s5",
        (_, Some(_), Some(_)) => "acpi-reduzido",
        _ => "nenhum",
    };
    (reinicio, desligamento)
}

/// Escreve `valor` no registrador genérico da ACPI `r`: numa porta, ou na
/// memória do dispositivo, mapeada para isso. `largura` é 8 ou 16.
// Na suíte a energia só anota a ação — ver `crate::energia`.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
fn escrever_registrador(r: acpi::Registrador, valor: u16, largura: u8) {
    match r.espaco {
        acpi::ESPACO_PORTA => {
            let porta = r.endereco as u16;
            // SAFETY: a porta é a que a FADT descreve para este registrador,
            // e o efeito — reiniciar, desligar — é o pedido.
            unsafe {
                if largura == 8 {
                    x86_64::instructions::port::Port::<u8>::new(porta).write(valor as u8);
                } else {
                    x86_64::instructions::port::Port::<u16>::new(porta).write(valor);
                }
            }
        }
        acpi::ESPACO_MEMORIA => {
            if let Ok(virtual_) = crate::mmio::mapear(r.endereco, 4096) {
                // SAFETY: o endereço é o do registrador que a FADT descreve,
                // acabado de mapear como memória de dispositivo.
                unsafe {
                    if largura == 8 {
                        core::ptr::write_volatile(virtual_ as *mut u8, valor as u8);
                    } else {
                        core::ptr::write_volatile(virtual_ as *mut u16, valor);
                    }
                }
            }
        }
        _ => {}
    }
}

/// Lê dezesseis bits do registrador genérico `r`, se ele é uma porta.
fn ler_registrador(r: acpi::Registrador) -> Option<u16> {
    // SAFETY: leitura da porta que a FADT descreve como o controle do PM1.
    (r.espaco == acpi::ESPACO_PORTA)
        .then(|| unsafe { x86_64::instructions::port::Port::<u16>::new(r.endereco as u16).read() })
}

/// `SCI_EN`, no controle do PM1: a máquina está no modo ACPI.
const MODO_ACPI: u16 = 1;

/// Põe a máquina no modo ACPI se o firmware a deixou fora — o `SCI_EN`
/// desligado no controle `pm1a` —, pelo valor `ACPI_ENABLE` na porta
/// `SMI_CMD`, e espera o chipset ligar o bit. Devolve se ela está no modo.
///
/// O desligamento pelo S5 pede o modo antes de dormir; o botão de energia,
/// antes de esperar o SCI — fora dele, o botão é do firmware. Um controle
/// fora das portas, este kernel não lê: não há como saber, e nada se
/// escreve.
fn entrar_no_modo_acpi(pm1a: acpi::Registrador, smi_cmd: u32, acpi_enable: u8) -> bool {
    match ler_registrador(pm1a) {
        None => return false,
        Some(v) if v & MODO_ACPI != 0 => return true,
        Some(_) => {}
    }
    if smi_cmd == 0 || acpi_enable == 0 {
        return false;
    }
    // SAFETY: a porta e o valor que a FADT dá para ligar o modo ACPI.
    unsafe { x86_64::instructions::port::Port::<u8>::new(smi_cmd as u16).write(acpi_enable) };
    for _ in 0..1_000_000 {
        if ler_registrador(pm1a).is_some_and(|v| v & MODO_ACPI != 0) {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Gira um pouco, para o chipset ter tempo de agir antes do próximo modo.
// Na suíte a energia só anota a ação — ver `crate::energia`.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
fn esperar_o_chipset() {
    for _ in 0..10_000_000u32 {
        core::hint::spin_loop();
    }
}

/// Reinicia a máquina — ver [`crate::energia`]. Nunca volta.
///
/// Quatro modos, do que a máquina descreve ao que ela não pode recusar, e
/// cada um só se o anterior não reiniciou:
///
/// 1. o registrador de reinício da FADT, com o valor dela;
/// 2. a porta `0xCF9`, o controle de reinício dos chipsets de PC: `0x02`
///    prepara, `0x06` reinicia de verdade;
/// 3. o controlador de teclado 8042: o comando `0xFE` pulsa a linha de
///    reinício;
/// 4. a falha tripla: uma tabela de interrupções vazia e uma interrupção —
///    o processador não tem para onde ir, e reinicia.
// Na suíte a energia só anota a ação — ver `crate::energia`.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
pub fn reiniciar_a_maquina() -> ! {
    use x86_64::instructions::port::Port;
    x86_64::instructions::interrupts::disable();
    if let Ok(energia) = acpi::energia()
        && let Some((registrador, valor)) = energia.reinicio
    {
        escrever_registrador(registrador, u16::from(valor), 8);
        esperar_o_chipset();
    }
    // SAFETY: `0xCF9` e o 8042 são as portas de reinício do PC; escrever
    // nelas é o efeito pedido. Numa máquina sem elas, a escrita se perde.
    unsafe {
        let mut cf9 = Port::<u8>::new(0xCF9);
        cf9.write(0x02);
        esperar_o_chipset();
        cf9.write(0x06);
        esperar_o_chipset();
        let mut estado = Port::<u8>::new(0x64);
        for _ in 0..100_000 {
            if estado.read() & 0x02 == 0 {
                break;
            }
        }
        estado.write(0xFE);
    }
    esperar_o_chipset();
    #[repr(C, packed)]
    struct Vazia {
        limite: u16,
        base: u64,
    }
    let vazia = Vazia { limite: 0, base: 0 };
    // SAFETY: carregar uma tabela de interrupções vazia e interromper é a
    // falha tripla de propósito — o último modo de reiniciar, que não volta.
    unsafe {
        core::arch::asm!("lidt [{}]", "int3", in(reg) &vazia, options(noreturn));
    }
}

/// Desliga a máquina pela ACPI — ver [`crate::energia`]. Nunca volta.
///
/// O estado S5: o `SLP_TYP` do `\_S5` da DSDT e o bit `SLP_EN` no
/// controle do PM1a — e no do PM1b, quando há —, preservando os outros
/// bits. Antes, se o firmware deixou a máquina fora do modo ACPI (`SCI_EN`
/// desligado), o modo é ligado pela porta `SMI_CMD`. Numa máquina de
/// hardware reduzido, o `SLEEP_CONTROL_REG`. Sem nada disso, o núcleo para
/// aqui, de interrupções desligadas: a máquina fica parada, mas ligada.
// Na suíte a energia só anota a ação — ver `crate::energia`.
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
pub fn desligar_a_maquina() -> ! {
    /// `SLP_EN`, no controle do PM1.
    const DORMIR: u16 = 1 << 13;
    x86_64::instructions::interrupts::disable();
    match acpi::energia() {
        Ok(e) => match (e.pm1a, e.s5, e.controle_de_sono) {
            (Some(pm1a), Some((a, b)), _) => {
                let _ = entrar_no_modo_acpi(pm1a, e.smi_cmd, e.acpi_enable);
                let atual = ler_registrador(pm1a).unwrap_or(0) & !(7 << 10);
                escrever_registrador(pm1a, atual | u16::from(a) << 10 | DORMIR, 16);
                if let Some(pm1b) = e.pm1b {
                    let atual = ler_registrador(pm1b).unwrap_or(0) & !(7 << 10);
                    escrever_registrador(pm1b, atual | u16::from(b) << 10 | DORMIR, 16);
                }
            }
            (_, Some((a, _)), Some(controle)) => {
                escrever_registrador(controle, u16::from(a & 7) << 2 | 1 << 5, 8);
            }
            _ => crate::log_error!("energia", "a ACPI nao descreve como desligar"),
        },
        Err(motivo) => crate::log_error!("energia", "sem FADT para desligar: {}", motivo),
    }
    esperar_o_chipset();
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

/// O TSC lido em ordem: o `lfence` antes do `rdtsc` faz a leitura esperar
/// tudo o que veio antes dela terminar, as leituras da memória incluídas.
/// Sem ele o processador pode executar o `rdtsc` adiantado, antes de uma
/// leitura que o programa faz primeiro.
///
/// É a leitura da grade dos tiques (`apic::PRAZO`): o rearme lê o TSC depois
/// de ver, no relógio, o avanço de outro núcleo (`tempo::avancar`), e o pulo
/// dos perdidos supõe essa ordem — o achado 3 do adversário do #455-B. No
/// emulador sem aceleração as instruções correm em ordem, e a barreira não
/// muda nada que se veja; no hardware, a janela é de nanossegundos.
/// [`ciclos`] fica sem ela: as medidas de custo, a régua do civil e as
/// esperas não dependem dessa ordem, e ela custaria em cada uma.
fn ciclos_em_ordem() -> u64 {
    let (baixo, alto): (u32, u32);
    // SAFETY: `lfence` só ordena, e `rdtsc` só lê o contador do processador;
    // os dois existem em todo x86_64, e no anel 0 nada os impede. Sem
    // `nomem`: o compilador também não passa por ela um acesso à memória.
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            out("eax") baixo,
            out("edx") alto,
            options(nostack, preserves_flags),
        );
    }
    (u64::from(alto) << 32) | u64::from(baixo)
}

/// O processador anuncia o TSC invariante — o bit 8 do EDX da folha
/// `0x8000_0007` do `CPUID`: o TSC numa taxa só, em todo estado de energia e
/// de frequência. A grade dos tiques (`apic::PRAZO`) e a régua do civil
/// supõem isso, e a grade supõe ainda o TSC igual em todos os núcleos, que
/// o kernel não confere. Sem o bit, o boot só avisa: o emulador sem
/// aceleração não o anuncia, e o TSC dele é um só, para todos.
fn tsc_invariante() -> bool {
    // A folha existe se o maior número das estendidas chega a ela; nenhuma
    // das duas leituras tem efeito colateral.
    core::arch::x86_64::__cpuid(0x8000_0000).eax >= 0x8000_0007
        && core::arch::x86_64::__cpuid(0x8000_0007).edx & (1 << 8) != 0
}

/// A frequência de [`ciclos`] e o erro máximo dela, em ppm: o x86 não a
/// declara, e ela é medida contra o PIT — ver [`pic::calibrar_ciclos`] —,
/// uma vez só, e a mesma serve à grade dos tiques ([`pic::frequencia_do_tsc`]).
/// `None` se a medida não valeu.
pub fn frequencia_dos_ciclos() -> Option<(u64, u64)> {
    pic::frequencia_do_tsc()
}
