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

use spin::once::Once;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

static IDT: Once<InterruptDescriptorTable> = Once::new();

/// Monta e carrega a IDT. Exige que a GDT já esteja instalada.
pub fn init() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();

        idt.breakpoint.set_handler_fn(ponto_de_parada);
        idt.invalid_opcode.set_handler_fn(opcode_invalido);
        idt.general_protection_fault.set_handler_fn(protecao_geral);
        idt.page_fault.set_handler_fn(falha_de_pagina);

        // Interrupções de hardware, já remapeadas pelo PIC para fora da
        // faixa das exceções.
        idt[super::pic::VETOR_TIMER].set_handler_fn(timer);
        idt[super::pic::VETOR_TECLADO].set_handler_fn(teclado);
        idt[super::pic::VETOR_SERIAL_AGENTE].set_handler_fn(serial_agente);

        // SAFETY: `IST_DOUBLE_FAULT` é um índice válido da IST, e a pilha
        // correspondente foi preparada em `gdt::init`, que roda antes desta
        // função. Ver a explicação do triple fault em `gdt`.
        unsafe {
            idt.double_fault
                .set_handler_fn(falha_dupla)
                .set_stack_index(super::gdt::IST_DOUBLE_FAULT);
        }

        idt
    });

    idt.load();
}

/// Interrupção periódica do timer (IRQ 0).
///
/// É o coração do kernel: dá noção de tempo hoje e, na fase 1, será o ponto
/// em que o scheduler preemptivo decide trocar de tarefa.
extern "x86-interrupt" fn timer(_quadro: InterruptStackFrame) {
    crate::tempo::tick();
    crate::irq::contabilizar(0);

    // SAFETY: estamos no handler desta exata interrupção. Omitir o EOI faria
    // o PIC considerar a interrupção eternamente em atendimento e nunca mais
    // entregar outra — o timer dispararia uma única vez.
    unsafe { super::pic::fim_de_interrupcao(super::pic::VETOR_TIMER) };
}

/// Interrupção de recepção da COM2 (IRQ 3): chegou byte para o agente.
///
/// O handler faz o mínimo: move os bytes do FIFO do hardware para a fila do
/// kernel e acorda a tarefa que os espera. Decodificar o JSON, executar o
/// comando e serializar a resposta acontece fora daqui — um handler roda com
/// interrupções mascaradas e suspende qualquer coisa que estivesse rodando,
/// então tudo que puder sair dele, sai.
extern "x86-interrupt" fn serial_agente(_quadro: InterruptStackFrame) {
    crate::tarefas::entrada::coletar();

    crate::irq::contabilizar(3);
    // SAFETY: estamos no fim do handler da própria interrupção.
    unsafe { super::pic::fim_de_interrupcao(super::pic::VETOR_SERIAL_AGENTE) };
}

/// Interrupção do teclado PS/2 (IRQ 1).
extern "x86-interrupt" fn teclado(_quadro: InterruptStackFrame) {
    // Ler o scancode não é opcional: o controlador de teclado só arma a
    // próxima interrupção depois que o byte anterior for consumido. Sem esta
    // leitura, a primeira tecla travaria o teclado para sempre.
    //
    // SAFETY: 0x60 é a porta de dados do controlador 8042, e a leitura é o
    // protocolo documentado de consumo do scancode.
    let _scancode: u8 = unsafe { x86_64::instructions::port::Port::new(0x60).read() };

    crate::irq::contabilizar(1);

    // SAFETY: estamos no handler desta exata interrupção.
    unsafe { super::pic::fim_de_interrupcao(super::pic::VETOR_TECLADO) };
}

/// `int3` — o ponto de parada dos depuradores.
///
/// É a única exceção aqui que **retorna**: o processador já avançou o RIP para
/// depois da instrução, então basta voltar. Serve de prova viva de que os
/// handlers funcionam, e é o que o comando `debug.trigger` usa.
extern "x86-interrupt" fn ponto_de_parada(quadro: InterruptStackFrame) {
    let pc = quadro.instruction_pointer.as_u64();
    let seq = crate::traps::registrar("breakpoint", pc, None, 0);
    crate::log_info!("traps", "breakpoint #{} em pc={:#x}", seq, pc);
}

/// Instrução inválida: o fluxo de execução saiu dos trilhos.
extern "x86-interrupt" fn opcode_invalido(quadro: InterruptStackFrame) {
    crate::traps::fatal(
        "invalid_opcode",
        quadro.instruction_pointer.as_u64(),
        None,
        0,
    )
}

/// Violação de proteção: acesso a um segmento ou registrador não permitido.
extern "x86-interrupt" fn protecao_geral(quadro: InterruptStackFrame, codigo: u64) {
    crate::traps::fatal(
        "general_protection_fault",
        quadro.instruction_pointer.as_u64(),
        None,
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

    crate::traps::fatal(
        "page_fault",
        quadro.instruction_pointer.as_u64(),
        endereco,
        codigo.bits(),
    )
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
