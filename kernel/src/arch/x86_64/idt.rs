//! Tabela de descritores de interrupção (IDT) e handlers de exceção.
//!
//! A IDT associa cada vetor de exceção a uma função. Sem ela instalada, o
//! processador não tem para onde ir quando algo dá errado — e o resultado é
//! triple fault, ou seja, reboot sem diagnóstico.
//!
//! # A ABI `x86-interrupt`
//!
//! Handlers de interrupção não podem usar a convenção de chamada normal: o
//! processador empilha um quadro com formato próprio, e o retorno precisa ser
//! `iretq` em vez de `ret`. Além disso, um handler pode interromper qualquer
//! código em qualquer ponto, então precisa preservar *todos* os registradores,
//! não só os salvos pelo chamado.
//!
//! Escrever isso à mão seria assembly delicado. A ABI `x86-interrupt` faz o
//! compilador gerar o prólogo e o epílogo corretos — é por isso que o kernel
//! exige Rust nightly.
//!
//! # As exceções, todas, e de quem é a culpa
//!
//! Toda exceção da arquitetura que o crate `x86_64` oferece tem tratador, e
//! a regra é uma só, a do `#GP` e da falha de página — e a do ARM
//! (`aarch64::vetores`): vinda do **anel 3**, a culpa é do processo, e o
//! processo morre — a linha `processo morto por ...` no log e a falha contada
//! (`traps::registrar`) —; vinda do **anel 0**, é do kernel, e é fatal. O
//! `#MC` é sempre fatal: é o hardware. O `#BP` do anel 0 é o único que volta
//! — o `debug.trigger` —, fora a falha de página da cópia na escrita, que o
//! kernel resolve; e o `#DF`, sempre fatal, tem a pilha dele.
//!
//! Antes, a IDT só tinha o `#BP`, o `#UD`, o `#GP`, a falha de página, o
//! `#DF`, a NMI e as interrupções, e o `#UD` era fatal sem olhar o anel: um
//! `ud2` de qualquer processo parava a máquina para todos os titulares, e
//! uma divisão por zero, um `int1`, o `TF` ligado pelo `popfq` ou um `push`
//! com o `rsp` não canônico iam pela entrada ausente ao `#NP`, ausente, e
//! dali ao `#DF` — fatal também. O que estava no anel da auditoria e ainda
//! não tinha ido ao journal ficava só no cadáver: um processo agia e apagava
//! o fim da própria trilha parando a máquina (o achado do adversário do lote
//! B do #448, corrigido no lote B2).

use spin::once::Once;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

static IDT: Once<InterruptDescriptorTable> = Once::new();

/// Monta e carrega a IDT. Exige que a GDT já esteja instalada.
pub fn init() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();

        // As exceções da arquitetura, todas as que o crate oferece — ver o
        // cabeçalho. Os vetores reservados e o 9, que nenhum processador de
        // 64 bits gera, o crate não deixa instalar.
        idt.divide_error.set_handler_fn(erro_de_divisao);
        idt.breakpoint.set_handler_fn(ponto_de_parada);
        idt.overflow.set_handler_fn(estouro);
        idt.bound_range_exceeded.set_handler_fn(limite_excedido);
        idt.invalid_opcode.set_handler_fn(opcode_invalido);
        idt.device_not_available
            .set_handler_fn(dispositivo_indisponivel);
        idt.invalid_tss.set_handler_fn(tss_invalido);
        idt.segment_not_present.set_handler_fn(segmento_ausente);
        idt.stack_segment_fault
            .set_handler_fn(falha_de_segmento_de_pilha);
        idt.general_protection_fault.set_handler_fn(protecao_geral);
        idt.page_fault.set_handler_fn(falha_de_pagina);
        idt.x87_floating_point.set_handler_fn(ponto_flutuante_x87);
        idt.alignment_check.set_handler_fn(alinhamento);
        idt.simd_floating_point.set_handler_fn(ponto_flutuante_simd);
        idt.virtualization.set_handler_fn(virtualizacao);
        idt.cp_protection_exception
            .set_handler_fn(protecao_do_fluxo_de_controle);
        idt.hv_injection_exception
            .set_handler_fn(injecao_do_hipervisor);
        idt.vmm_communication_exception
            .set_handler_fn(comunicacao_com_o_vmm);
        idt.security_exception.set_handler_fn(excecao_de_seguranca);

        // O `#DB`, com pilha própria: ele pode chegar ao anel 0 numa das
        // instruções da entrada de `syscall` em que o `RSP` ainda é a pilha
        // do processo — o `TF` que a entrada não apagasse, um aviso de
        // depuração adiado por um `mov ss` —, e o processador empilharia o
        // quadro onde o processo mandou, numa memória que outro fio dele
        // escreve. O `SFMask` apaga o `TF` na entrada (ver
        // `usuario::ligar_neste_nucleo`); a pilha é a segunda linha. Ver
        // `gdt::IST_DEPURACAO`.
        //
        // SAFETY: `IST_DEPURACAO` é um índice válido da IST, preparado em
        // `gdt::init` para todos os núcleos.
        unsafe {
            idt.debug
                .set_handler_fn(depuracao)
                .set_stack_index(super::gdt::IST_DEPURACAO);
        }

        // O `#MC`, sempre fatal, na pilha do `#DF`: ele chega em qualquer
        // instrução, também nas da entrada de `syscall` com o `RSP` do
        // processo, e o relatório não volta — como o do `#DF`. Antes ele
        // chegava lá pelo caminho mais longo: a entrada ausente, o `#NP`
        // ausente, o `#DF`.
        //
        // SAFETY: `IST_DOUBLE_FAULT` é um índice válido da IST, preparado em
        // `gdt::init`; quem roda nela não volta.
        unsafe {
            idt.machine_check
                .set_handler_fn(verificacao_da_maquina)
                .set_stack_index(super::gdt::IST_DOUBLE_FAULT);
        }

        // Interrupções de hardware, já remapeadas pelo PIC para fora da
        // faixa das exceções.
        //
        // Todas as dezesseis, e não só as que hoje têm uso. O vetor precisa
        // existir na IDT **antes** de a linha ser desmascarada, e quem
        // desmascara é o driver do dispositivo, muito depois daqui. Instalar
        // sob demanda exigiria mexer na IDT com o sistema rodando; instalar
        // todas de uma vez custa dezesseis entradas numa tabela de 256.
        //
        // Uma linha sem dono não é perigosa: o handler contabiliza, pergunta
        // aos drivers e sinaliza o fim. O que seria perigoso é o contrário —
        // uma linha desmascarada sem vetor derruba o processador.
        for (linha, tratador) in TRATADORES.iter().enumerate() {
            idt[super::pic::OFFSET_MESTRE + linha as u8].set_handler_fn(*tratador);
        }

        // O timer do APIC local não passa pelo PIC: ele nasce dentro do
        // núcleo e é entregue direto num vetor próprio. Os dois ficam
        // instalados ao mesmo tempo de propósito — a calibração do APIC
        // depende do PIT estar rodando.
        idt[super::apic::VETOR_TIMER].set_handler_fn(timer_do_apic);
        idt[super::apic::VETOR_ESPURIO].set_handler_fn(espuria);
        idt[super::apic::VETOR_CUTUCAO].set_handler_fn(cutucao);

        // SAFETY: `IST_DOUBLE_FAULT` é um índice válido da IST, e a pilha
        // correspondente foi preparada em `gdt::init`, que roda antes desta
        // função. Ver a explicação do triple fault em `gdt`.
        unsafe {
            idt.double_fault
                .set_handler_fn(falha_dupla)
                .set_stack_index(super::gdt::IST_DOUBLE_FAULT);
        }

        // A NMI, com pilha própria: ela chega em qualquer instrução,
        // inclusive nas três da entrada de `syscall` em que `RSP` ainda é a
        // pilha do usuário. Ver `gdt::IST_NMI`.
        //
        // SAFETY: `IST_NMI` é um índice válido da IST, preparado em
        // `gdt::init` para todos os núcleos.
        unsafe {
            idt.non_maskable_interrupt
                .set_handler_fn(nmi)
                .set_stack_index(super::gdt::IST_NMI);
        }

        idt
    });

    idt.load();
}

/// Carrega neste núcleo a IDT que o primeiro montou.
///
/// A IDT é uma só para todos: ela não guarda nada de um núcleo — as pilhas
/// da IST que ela cita são índices, e cada núcleo os resolve no próprio TSS.
pub fn carregar() {
    if let Some(idt) = IDT.get() {
        idt.load();
    }
}

/// Interrupção não mascarável: o aviso de outro núcleo — ver `smp`.
extern "x86-interrupt" fn nmi(_quadro: InterruptStackFrame) {
    super::smp::atender_nmi();
}

/// Gera um handler por linha do PIC.
///
/// # Por que uma macro
///
/// Porque a ABI `x86-interrupt` não passa o número do vetor ao handler: o
/// processador salta para o endereço que a IDT guarda e pronto. Saber qual
/// linha disparou só é possível tendo uma função **por linha**, e a única
/// diferença entre as dezesseis é o número que elas repassam.
///
/// Escrevê-las à mão seria dezesseis corpos idênticos, e a primeira correção
/// que só quinze recebessem viraria um bug que aparece numa linha só.
macro_rules! tratadores {
    ($($nome:ident = $linha:expr),* $(,)?) => {
        $(
            extern "x86-interrupt" fn $nome(quadro: InterruptStackFrame) {
                let preemptar = atender($linha);
                terminar_se_veio_do_usuario(&quadro);
                if preemptar {
                    // Trocar de fio aqui dentro é seguro porque no x86 o
                    // quadro de interrupção foi empilhado na pilha do fio
                    // interrompido: a troca leva o quadro junto, e o `iretq`
                    // do fim deste handler acontece na pilha do outro fio,
                    // retomando o ponto em que *ele* parou.
                    super::contexto::ceder_cpu();
                }
            }
        )*

        /// Os handlers, indexados pela linha do PIC.
        static TRATADORES: [extern "x86-interrupt" fn(InterruptStackFrame); 16] =
            [$($nome),*];
    };
}

tratadores! {
    linha0 = 0, linha1 = 1, linha2 = 2, linha3 = 3,
    linha4 = 4, linha5 = 5, linha6 = 6, linha7 = 7,
    linha8 = 8, linha9 = 9, linha10 = 10, linha11 = 11,
    linha12 = 12, linha13 = 13, linha14 = 14, linha15 = 15,
}

/// Interrupção periódica do timer do APIC local.
///
/// É a gêmea de `atender(0)`, e faz o mesmo trabalho: marcar o tempo e
/// perguntar ao escalonador. O que muda é quem precisa ser avisado no fim —
/// o APIC, não o PIC.
extern "x86-interrupt" fn timer_do_apic(quadro: InterruptStackFrame) {
    // Cada núcleo tem o seu timer, e cada um conta o próprio pulso e o
    // oferece ao relógio, que anda uma vez por período por qualquer núcleo
    // vivo — ver `tempo::tick`. Os dispositivos, só no núcleo deles.
    crate::nucleos::tique_local();
    crate::tempo::tick();
    let preemptar = crate::fios::tique();

    crate::irq::contabilizar(super::apic::VETOR_TIMER as usize);

    // Antes da troca de fio, pela mesma razão do PIC: se trocássemos
    // primeiro, este handler só voltaria a executar quando o fio atual fosse
    // escalonado de novo, e até lá o APIC não entregaria outra.
    super::apic::fim_de_interrupcao();

    terminar_se_veio_do_usuario(&quadro);
    if preemptar {
        super::contexto::ceder_cpu();
    }
}

/// O término pedido por `process.terminate`, quando a interrupção pegou o
/// processo no anel do usuário — ver `crate::fios::terminar_se_pedido`. É
/// o ponto seguro de quem só gira, sem chamada de sistema: ali ele não
/// segura nada do kernel. Vinda do anel zero, a interrupção pode ter
/// cortado uma chamada no meio, com uma trava na mão, e o processo morre
/// na volta dela.
///
/// Depois do fim da interrupção, que já foi sinalizado: marcado, o fio sai
/// de circulação como o morto de uma falha de página — `descansar` não
/// volta, e o quadro desta interrupção fica para trás com a pilha dele.
fn terminar_se_veio_do_usuario(quadro: &InterruptStackFrame) {
    if quadro.code_segment.rpl() as u8 == x86_64::PrivilegeLevel::Ring3 as u8
        && crate::fios::terminar_se_pedido()
    {
        crate::fios::descansar();
    }
}

/// O cutucão de outro núcleo: só acorda este. Quem cutucou já mudou o que
/// tinha de mudar — uma tarefa na fila, um fio pronto —, e este núcleo, ao
/// voltar do `hlt`, confere por conta própria.
extern "x86-interrupt" fn cutucao(_quadro: InterruptStackFrame) {
    crate::irq::contabilizar(super::apic::VETOR_CUTUCAO as usize);
    super::apic::fim_de_interrupcao();
    crate::nucleos::ao_ser_cutucado();
}

/// Interrupção espúria do APIC.
///
/// Acontece numa corrida legítima: uma linha que baixa entre o processador
/// aceitar a interrupção e o APIC decidir de quem ela é. A especificação é
/// explícita em que **não** se deve sinalizar fim de interrupção aqui — o
/// APIC não considera esta entrega em atendimento, e finalizá-la encerraria a
/// interrupção anterior, que ainda está.
extern "x86-interrupt" fn espuria(_quadro: InterruptStackFrame) {
    crate::irq::contabilizar(super::apic::VETOR_ESPURIO as usize);
}

/// Atende a interrupção da linha indicada. Devolve se o escalonador pediu
/// troca de fio.
///
/// É o gêmeo de `aarch64::gic::tratar` no outro backend — sem link porque o
/// outro backend não existe nesta compilação —, e a
/// simetria é deliberada: as duas arquiteturas fazem a mesma sequência — o
/// mínimo indispensável, contabilizar, sinalizar o fim — e quem lê uma
/// reconhece a outra.
fn atender(linha: u8) -> bool {
    let mut preemptar = false;

    match linha {
        // O coração do kernel: dá a noção de tempo e é o ponto em que o
        // escalonador preemptivo decide trocar de fio.
        0 => {
            crate::tempo::tick();
            preemptar = crate::fios::tique();
        }

        // Ler o scancode não é opcional: o controlador de teclado só arma a
        // próxima interrupção depois que o byte anterior for consumido. Sem
        // esta leitura, a primeira tecla travaria o teclado para sempre.
        //
        // SAFETY: 0x60 é a porta de dados do controlador 8042, e a leitura é
        // o protocolo documentado de consumo do scancode.
        1 => {
            let scancode: u8 = unsafe { x86_64::instructions::port::Port::new(0x60).read() };
            teclado_ps2(scancode);
        }

        // Chegou byte para o agente. O handler faz o mínimo: move os bytes do
        // FIFO do hardware para a fila do kernel e acorda a tarefa que os
        // espera. Decodificar o JSON, executar o comando e serializar a
        // resposta acontece fora daqui.
        3 => crate::tarefas::entrada::coletar(),

        // O mouse PS/2. Ler o byte é obrigatório pelo mesmo motivo do
        // teclado: o 8042 só arma a próxima interrupção depois dele — mas só
        // quando há um byte, ver `mouse::atender`.
        super::mouse::IRQ_MOUSE => super::mouse::atender(),

        // As demais são dos dispositivos que o kernel dirige. Perguntar a
        // eles é o que evita uma tabela de handlers — e, com dois
        // dispositivos, uma tabela seria generalidade sem cliente. E do SCI
        // da ACPI, que traz o botão de energia e pode dividir a linha com
        // um deles: os dois são perguntados — ver `super::botao`.
        _ => {
            let dispositivos = crate::virtio::atender_interrupcao(linha as u32);
            super::botao::atender(linha, dispositivos);
        }
    }

    crate::irq::contabilizar(linha as usize);

    // O EOI vem **antes** da troca de fio, e a ordem importa. Se trocássemos
    // primeiro, este handler só voltaria a executar quando o fio atual fosse
    // escalonado de novo — e até lá o PIC consideraria a interrupção em
    // atendimento e não entregaria outra. O timer pararia, e com ele o
    // escalonador: um sistema que troca de fio exatamente uma vez.
    //
    // SAFETY: estamos no handler desta exata interrupção.
    unsafe { super::pic::fim_de_interrupcao(super::pic::OFFSET_MESTRE + linha) };

    preemptar
}

/// O processo do fio atual morre da exceção `nome` — a do anel 3 —, com o
/// `motivo` no log, e o fio sai de circulação. Não volta.
///
/// Sem código de saída: quem morre de falha não chegou a `sair`, e um pai
/// que estivesse esperando por ele precisa saber a diferença entre "saiu
/// com zero" e "foi morto".
///
/// Cedemos de vez, em vez de retornar: o `iretq` do fim do tratador
/// devolveria o controle a um processo que já não existe — e o abandono do
/// quadro da exceção é inofensivo: ele está na pilha de kernel do fio, que
/// volta quando o coletor recolher o fio. Por isso os tratadores com pilha
/// própria, da IST, não chamam esta função: ver [`depuracao`].
fn morre_o_processo(nome: &'static str, motivo: &str, pc: u64, codigo: u64) -> ! {
    anotar_a_morte(nome, motivo, pc, codigo);
    crate::fios::descansar()
}

/// A falha contada e a linha do log de um processo morto por `nome`, e o fio
/// marcado — o que [`morre_o_processo`] faz antes de sair de circulação.
fn anotar_a_morte(nome: &'static str, motivo: &str, pc: u64, codigo: u64) {
    let seq = crate::traps::registrar(nome, pc, None, codigo);
    crate::log_error!(
        "usuario",
        "processo morto por {} #{} em pc={:#x}",
        motivo,
        seq,
        pc
    );
    crate::fios::marcar_terminado(None);
}

/// A exceção veio do anel sem privilégio? O `CS` salvo diz de onde veio —
/// os dois bits baixos são o nível de privilégio de quem foi interrompido.
fn do_anel_3(quadro: &InterruptStackFrame) -> bool {
    quadro.code_segment.rpl() as u8 == x86_64::PrivilegeLevel::Ring3 as u8
}

/// A regra de toda exceção — ver o cabeçalho: do anel 3, o processo morre;
/// do anel 0, é fatal.
fn excecao(quadro: &InterruptStackFrame, nome: &'static str, motivo: &str, codigo: u64) -> ! {
    let pc = quadro.instruction_pointer.as_u64();
    if do_anel_3(quadro) {
        morre_o_processo(nome, motivo, pc, codigo);
    }
    crate::traps::fatal(nome, pc, None, codigo)
}

/// Gera um tratador por exceção sem código de erro, todos pela regra de
/// [`excecao`]: o nome canônico, o da contabilidade, e o motivo do log.
///
/// O atributo que a macro repassa é só o `doc` — o comentário `///` de cada
/// linha —, escrito por extenso: um atributo inteiro montado pela macro
/// (`#[$…]`) poderia ser o `path`, e trazer o código de outro arquivo para
/// fora da conferência das invariantes (`cargo xtask invariantes`).
macro_rules! sem_codigo {
    ($($(#[doc = $doc:literal])* $tratador:ident => $nome:literal, $motivo:literal;)*) => {
        $(
            $(#[doc = $doc])*
            extern "x86-interrupt" fn $tratador(quadro: InterruptStackFrame) {
                excecao(&quadro, $nome, $motivo, 0)
            }
        )*
    };
}

/// O mesmo, para as exceções com código de erro: o código vai cru para a
/// contabilidade.
macro_rules! com_codigo {
    ($($(#[doc = $doc:literal])* $tratador:ident => $nome:literal, $motivo:literal;)*) => {
        $(
            $(#[doc = $doc])*
            extern "x86-interrupt" fn $tratador(quadro: InterruptStackFrame, codigo: u64) {
                excecao(&quadro, $nome, $motivo, codigo)
            }
        )*
    };
}

sem_codigo! {
    /// `#DE`: a divisão por zero, ou o quociente que não cabe.
    erro_de_divisao => "divide_error", "erro de divisao";
    /// `#OF`: o `into` não existe em 64 bits, e o `int 4` do anel 3 é `#GP`
    /// — o portão tem DPL 0 —, mas a regra é a mesma.
    estouro => "overflow", "estouro";
    /// `#BR`: o `bound` não existe em 64 bits; sobra o MPX, que o kernel
    /// não liga.
    limite_excedido => "bound_range_exceeded", "limite excedido";
    /// `#UD`: a instrução inválida — `ud2`, o `abort` de um programa
    /// (`programas::_start`), um código que não existe neste processador.
    /// No QEMU do TCG, também o `int1` (ver `testes::excecoes`).
    opcode_invalido => "invalid_opcode", "instrucao invalida";
    /// `#NM`: a unidade de ponto flutuante indisponível — o `CR0.TS`, que o
    /// kernel não liga.
    dispositivo_indisponivel => "device_not_available", "dispositivo indisponivel";
    /// `#MF`: o erro do x87 que o processo desmascarou.
    ponto_flutuante_x87 => "x87_floating_point", "erro de ponto flutuante x87";
    /// `#XM`: o erro de SIMD que o processo desmascarou no `MXCSR`.
    ponto_flutuante_simd => "simd_floating_point", "erro de ponto flutuante simd";
    /// `#VE`: a exceção de virtualização, de um hóspede de VMX.
    virtualizacao => "virtualization", "excecao de virtualizacao";
    /// `#HV`: a injeção do hipervisor, num hóspede SEV-SNP.
    injecao_do_hipervisor => "hv_injection_exception", "injecao do hipervisor";
}

com_codigo! {
    /// `#TS`: o TSS inválido — não há troca de tarefa em 64 bits.
    tss_invalido => "invalid_tss", "tss invalido";
    /// `#NP`: o segmento ou o portão ausente.
    segmento_ausente => "segment_not_present", "segmento ausente";
    /// `#SS`: a referência à pilha num endereço não canônico, ou o `SS`
    /// ausente.
    falha_de_segmento_de_pilha => "stack_segment_fault", "falha de segmento de pilha";
    /// `#AC`: o acesso desalinhado com o `AC` ligado — e o `CR0.AM`.
    alinhamento => "alignment_check", "falha de alinhamento";
    /// `#CP`: a proteção do fluxo de controle, que o kernel não liga.
    protecao_do_fluxo_de_controle => "cp_protection_exception", "protecao do fluxo de controle";
    /// `#VC`: a comunicação com o VMM, num hóspede SEV-ES.
    comunicacao_com_o_vmm => "vmm_communication_exception", "comunicacao com o vmm";
    /// `#SX`: a exceção de segurança da AMD.
    excecao_de_seguranca => "security_exception", "excecao de seguranca";
}

/// O próximo `int3` **do anel 0** afunda a pilha em vez de voltar — ver
/// [`super::disparar_estouro_em_excecao`].
pub(super) static AFUNDAR_NO_PONTO_DE_PARADA: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// `int3` — o ponto de parada dos depuradores.
///
/// Do anel 0 é a única exceção aqui que **retorna** sem ter resolvido nada —
/// a outra é a falha de página da cópia na escrita —: o processador já avançou
/// o RIP para depois da instrução, então basta voltar. Serve de prova viva de
/// que os handlers funcionam, e é o que o comando `debug.trigger` usa.
///
/// Do anel 3, o processo morre, como de qualquer outra exceção — registrar e
/// seguir deixaria um processo encher o log e a contabilidade das falhas sem
/// limite. Hoje o `int3` do processo nem chega aqui: o portão tem DPL 0, e o
/// `int3` de um anel acima dele é um `#GP` com o vetor no código de erro —
/// `0x1A` —, que mata o processo pelo [`protecao_geral`]. A regra fica aqui
/// também, para o dia em que o portão mudar.
///
/// O estouro de propósito só vale do anel 0: o `int3` de um processo, no
/// meio, não consome o pedido.
extern "x86-interrupt" fn ponto_de_parada(quadro: InterruptStackFrame) {
    let pc = quadro.instruction_pointer.as_u64();
    if do_anel_3(&quadro) {
        morre_o_processo("breakpoint", "ponto de parada", pc, 0);
    }
    // O estouro de propósito — ver `disparar_estouro_em_excecao`.
    if AFUNDAR_NO_PONTO_DE_PARADA.swap(false, core::sync::atomic::Ordering::SeqCst) {
        crate::traps::afundar_de_proposito();
    }
    let seq = crate::traps::registrar("breakpoint", pc, None, 0);
    crate::log_info!("traps", "breakpoint #{} em pc={:#x}", seq, pc);
}

/// `#DB` — a armadilha do passo (`TF`), o `int1` e os pontos de parada do
/// hardware, que o kernel não arma. Roda na pilha da IST
/// ([`super::gdt::IST_DEPURACAO`]).
///
/// O código é o `DR6`: o que o processador diz da causa — o `BS`, o bit 14, é
/// o passo. Lido e devolvido ao valor de repouso, que o processador nunca
/// limpa sozinho: o `#DB` seguinte diz só a causa dele.
///
/// Do anel 3, o processo morre, como de qualquer exceção; mas não nesta
/// pilha. Ela é do núcleo, e não do fio: sair de circulação aqui deixaria o
/// fio morto parado nela, com as interrupções ligadas pelo sono do ocioso, e
/// o tratador de cada uma empilhado em cima, numa pilha sem guarda. A morte
/// continua na pilha de kernel do fio — a que o `#GP` e a falha de página
/// usariam, o `RSP0` deste núcleo —, que está vazia: o fio estava no anel 3.
///
/// Do anel 0, é fatal: o kernel não usa o passo nem arma os pontos do
/// hardware, e o `SFMask` apaga o `TF` do processo na entrada de `syscall`.
///
/// Fica um caminho, só no processador: o `mov ss` do processo, com o `TF`
/// ligado, adia o `#DB` do passo até depois da instrução seguinte, e, se
/// ela é a `syscall` ou vira exceção, ele chega aqui do anel 0 — na pilha
/// da IST, e não na do processo — e para a máquina. O conserto conhecido (o
/// do Linux, `exc_debug_kernel`, para o cenário do CVE-2018-8897) é ter o
/// `#DB` do anel 0 com o `BS` por esse passo adiado: apagar o `TF` do quadro
/// e voltar, e o processo morre pelo caminho de sempre. Não entrou no lote
/// B2, por não ter caso que o exercite na suíte — o QEMU do TCG não adia o
/// passo —, e fica para o lote B3, com um caso que liga o `TF` no anel 0 —
/// ver *O que fica*, em "Userspace", no README.
extern "x86-interrupt" fn depuracao(quadro: InterruptStackFrame) {
    let pc = quadro.instruction_pointer.as_u64();
    let dr6 = ler_e_repor_o_dr6();
    if do_anel_3(&quadro) {
        anotar_a_morte("debug", "depuracao", pc, dr6);
        let topo = super::gdt::pilha_de_kernel_deste_nucleo();
        if topo != 0 {
            // SAFETY: `topo` é o `RSP0` deste núcleo, o topo da pilha de
            // kernel do fio atual — a troca de contexto o mantém —, e ela
            // está vazia: a exceção veio do anel 3. Nada desta pilha da IST
            // é usado depois do salto, e as interrupções seguem mascaradas
            // pelo portão até `descansar` decidir.
            unsafe { descansar_na_pilha_do_fio(topo) }
        }
        crate::fios::descansar()
    }
    crate::traps::fatal("debug", pc, None, dr6)
}

/// O valor do `DR6` em repouso: os bits reservados ligados, e nenhuma causa.
const DR6_EM_REPOUSO: u64 = 0xFFFF_0FF0;

/// Lê o `DR6` e o devolve ao repouso.
fn ler_e_repor_o_dr6() -> u64 {
    let dr6: u64;
    // SAFETY: estamos no anel 0, no tratador do `#DB`; ler e escrever o
    // `DR6` não toca memória nem muda nada além dele.
    unsafe {
        core::arch::asm!("mov {}, dr6", out(reg) dr6, options(nomem, nostack, preserves_flags));
        core::arch::asm!(
            "mov dr6, {}",
            in(reg) DR6_EM_REPOUSO,
            options(nomem, nostack, preserves_flags)
        );
    }
    dr6
}

/// Troca a pilha da IST pela de kernel do fio, `topo`, e sai de circulação
/// dali. Não volta.
///
/// # Safety
///
/// `topo` precisa ser o topo, alinhado em 16, da pilha de kernel do fio
/// atual, e nada vivo pode estar nela.
unsafe fn descansar_na_pilha_do_fio(topo: u64) -> ! {
    // SAFETY: delegada ao chamador. O `call` empilha o retorno e deixa a
    // pilha como a convenção espera na entrada de uma função.
    unsafe {
        core::arch::asm!(
            "mov rsp, {topo}",
            "call {descansar}",
            "ud2",
            topo = in(reg) topo,
            descansar = sym descansar_sem_volta,
            options(noreturn),
        )
    }
}

/// A ponte de [`descansar_na_pilha_do_fio`] para [`crate::fios::descansar`].
extern "C" fn descansar_sem_volta() -> ! {
    crate::fios::descansar()
}

/// `#MC`: o hardware acusou um erro da máquina. Sempre fatal, de qualquer
/// anel — o processo não tem culpa, e o núcleo não tem como seguir. Roda na
/// pilha do `#DF`.
extern "x86-interrupt" fn verificacao_da_maquina(quadro: InterruptStackFrame) -> ! {
    crate::traps::fatal(
        "machine_check",
        quadro.instruction_pointer.as_u64(),
        None,
        0,
    )
}

/// Violação de proteção: acesso a um segmento ou registrador não permitido.
///
/// Mesma regra de toda exceção: instrução privilegiada tentada pelo
/// processo — ou o `int3`, o `int n` e o contador de ciclos (`CR4.TSD`) —
/// mata o processo, não o kernel.
extern "x86-interrupt" fn protecao_geral(quadro: InterruptStackFrame, codigo: u64) {
    excecao(
        &quadro,
        "general_protection_fault",
        "falha de protecao",
        codigo,
    )
}

/// Falha de página: o endereço acessado não está mapeado, ou o acesso é
/// proibido pelas permissões da página.
///
/// O endereço acusado vive no registrador CR2 — é a única forma de descobrir
/// *qual* endereço causou a falha, já que o quadro só informa a instrução.
extern "x86-interrupt" fn falha_de_pagina(quadro: InterruptStackFrame, codigo: PageFaultErrorCode) {
    let endereco = x86_64::registers::control::Cr2::read()
        .ok()
        .map(|addr| addr.as_u64());
    let pc = quadro.instruction_pointer.as_u64();

    // Antes de decidir de quem é a culpa, a pergunta que pode dissolver a
    // falha: era uma escrita numa página de cópia na escrita?
    //
    // # Por que a checagem do anel não entra aqui
    //
    // Porque o kernel também escreve em memória do usuário — é o que `ler`
    // faz ao entregar os bytes lidos ao buffer do processo. Essa escrita vem
    // do anel zero e, numa página compartilhada por um `fork`, falharia
    // exatamente como a do processo. Tratar só o caso do usuário deixaria o
    // kernel morrer de uma falha que ele sabe resolver, e pior: a máquina
    // inteira cairia por causa de um programa que apenas bifurcou e leu um
    // arquivo.
    //
    // O que **não** se afrouxa é o resto. `copia_na_escrita_em` só reconhece
    // uma página presente e marcada, e a marca só existe onde um `fork` a
    // pôs. Uma escrita do kernel num endereço qualquer segue sendo fatal.
    //
    // Os dois bits são exigidos juntos de propósito: `PROTECTION_VIOLATION`
    // separa "a página existe e o acesso é proibido" de "não há página", e
    // `CAUSED_BY_WRITE` separa a escrita da leitura. Sem o primeiro,
    // tentaríamos resolver uma falha de página ausente; sem o segundo, uma
    // leitura numa página marcada seria "resolvida" tirando uma cópia que
    // ninguém pediu.
    let escrita_protegida = codigo
        .contains(PageFaultErrorCode::CAUSED_BY_WRITE | PageFaultErrorCode::PROTECTION_VIOLATION);
    if escrita_protegida
        && let Some(endereco) = endereco
        && crate::paginacao::resolver_copia_na_escrita(endereco)
    {
        // Retornar reexecuta a instrução que falhou, agora sobre uma página
        // gravável. O processo não vê nada além do tempo que isto levou.
        return;
    }

    // Uma falha vinda do anel sem privilégio é culpa do processo, não do
    // kernel. Matar o sistema por causa dela entregaria a todo processo um
    // jeito trivial de derrubar a máquina — e desperdiçaria exatamente a
    // proteção que o ring 3 existe para dar.
    //
    // O bit que o processador usa para dizer isso é `USER_MODE` no código de
    // erro: ele descreve o privilégio de **quem causou** a falha, não o do
    // handler.
    if codigo.contains(PageFaultErrorCode::USER_MODE) {
        let seq = crate::traps::registrar("page_fault", pc, endereco, codigo.bits());
        crate::log_error!(
            "usuario",
            "processo morto por falha de pagina #{} em pc={:#x}, endereco {:#x}",
            seq,
            pc,
            endereco.unwrap_or(0)
        );
        // Sem código de saída, pelo mesmo motivo da falha de proteção acima.
        crate::fios::marcar_terminado(None);

        // Cedemos de vez, em vez de retornar. O `iretq` do fim deste handler
        // devolveria o controle a um processo que já não existe — e o
        // abandono deste quadro de interrupção é inofensivo: a pilha de
        // kernel dele volta quando o coletor recolher o fio.
        crate::fios::descansar();
    }

    crate::traps::fatal("page_fault", pc, endereco, codigo.bits())
}

/// Double fault: uma exceção ocorreu *enquanto* o processador tratava outra.
///
/// Este handler é a última linha de defesa contra o triple fault. Ele roda
/// numa pilha própria (ver `gdt::IST_DOUBLE_FAULT`), o que garante que
/// consegue funcionar mesmo quando a pilha do kernel estourou.
///
/// O tipo de retorno é `!` porque a arquitetura não define um estado ao qual
/// retornar: um double fault é sempre terminal.
extern "x86-interrupt" fn falha_dupla(quadro: InterruptStackFrame, codigo: u64) -> ! {
    crate::traps::fatal(
        "double_fault",
        quadro.instruction_pointer.as_u64(),
        None,
        codigo,
    )
}

/// O byte que anuncia um scancode estendido.
///
/// As teclas que o teclado original do PC não tinha — setas, `ctrl` da
/// direita, as de navegação — são anunciadas por um prefixo `0xE0` seguido do
/// código. Nenhuma delas produz texto, e o que este kernel precisa fazer com
/// elas é justamente **não** as confundir com as que produzem: sem o prefixo,
/// o código que vem depois é o de outra tecla, e a seta para a esquerda
/// digitaria um `k`.
const PREFIXO_ESTENDIDO: u8 = 0xE0;

/// O bit que distingue soltar de pressionar no conjunto 1 de scancodes.
const SOLTOU: u8 = 0x80;

/// O próximo byte é a segunda metade de um código estendido?
static ESTENDIDO: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Traduz um scancode do 8042 e o entrega ao teclado.
///
/// # Por que o estado mora aqui e não em [`crate::teclado`]
///
/// Porque o prefixo é do PS/2, e só dele. O `virtio-input` do ARM entrega o
/// par código-valor já separado, e o USB entrega outro formato ainda. Pôr o
/// prefixo na camada comum obrigaria os outros a conhecerem uma peculiaridade
/// que não os afeta.
///
/// # Uma guarda que este ambiente não falsifica
///
/// Desligar o tratamento do prefixo não muda nada observável hoje, e a razão
/// é a tabela de [`crate::teclado`]: ela cobre 58 códigos, e quase todo código
/// estendido cai acima disso — a seta para a esquerda é `0xE0 0x4B`, e 0x4B é
/// 75. Os poucos que caem dentro aliam para a tecla de mesmo significado: o
/// `enter` do teclado numérico é `0xE0 0x1C`, e 0x1C é o `enter` comum.
///
/// Então a mutação passa, e isso está escrito aqui em vez de ficar parecendo
/// que a sonda cobre o caso. A guarda vale no dia em que a tabela crescer
/// para as teclas de navegação — que é exatamente quando o alias deixa de ser
/// inofensivo — e o custo dela até lá são quatro linhas.
fn teclado_ps2(scancode: u8) {
    use core::sync::atomic::Ordering;

    if scancode == PREFIXO_ESTENDIDO {
        ESTENDIDO.store(true, Ordering::Relaxed);
        return;
    }

    // Uma tecla estendida consome o byte seguinte e não produz nada.
    if ESTENDIDO.swap(false, Ordering::Relaxed) {
        return;
    }

    crate::teclado::evento(scancode & !SOLTOU, scancode & SOLTOU == 0);
}
