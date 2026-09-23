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
            extern "x86-interrupt" fn $nome(_quadro: InterruptStackFrame) {
                if atender($linha) {
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

/// Atende a interrupção da linha indicada. Devolve se o escalonador pediu
/// troca de fio.
///
/// É o gêmeo de [`super::super::aarch64::gic::tratar`] no outro backend, e a
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
            let _scancode: u8 = unsafe { x86_64::instructions::port::Port::new(0x60).read() };
        }

        // Chegou byte para o agente. O handler faz o mínimo: move os bytes do
        // FIFO do hardware para a fila do kernel e acorda a tarefa que os
        // espera. Decodificar o JSON, executar o comando e serializar a
        // resposta acontece fora daqui.
        3 => crate::tarefas::entrada::coletar(),

        // As demais são dos dispositivos que o kernel dirige. Perguntar a
        // eles é o que evita uma tabela de handlers — e, com dois
        // dispositivos, uma tabela seria generalidade sem cliente.
        _ => crate::virtio::atender_interrupcao(linha as u32),
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
    let pc = quadro.instruction_pointer.as_u64();

    // Mesma regra da falha de página: instrução privilegiada tentada pelo
    // processo mata o processo, não o kernel. O `CS` salvo diz de onde veio —
    // os dois bits baixos são o nível de privilégio.
    if quadro.code_segment.rpl() as u8 == x86_64::PrivilegeLevel::Ring3 as u8 {
        let seq = crate::traps::registrar("general_protection_fault", pc, None, codigo);
        crate::log_error!(
            "usuario",
            "processo morto por falha de protecao #{} em pc={:#x}",
            seq,
            pc
        );
        crate::fios::marcar_terminado();
        crate::fios::descansar();
    }

    crate::traps::fatal("general_protection_fault", pc, None, codigo)
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
        crate::fios::marcar_terminado();

        // Cedemos de vez, em vez de retornar. O `iretq` do fim deste handler
        // devolveria o controle a um processo que já não existe — e o
        // abandono deste quadro de interrupção é inofensivo: a pilha de
        // kernel dele volta quando a vaga do fio for reaproveitada.
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
