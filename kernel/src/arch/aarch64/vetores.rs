//! Tabela de vetores de exceção do aarch64.
//!
//! # O contraste com a IDT do x86
//!
//! No x86 a IDT é um array de descritores, cada um contendo o *endereço* de
//! uma função — o processador salta direto para o seu handler e já empilhou o
//! contexto por você.
//!
//! No ARM é diferente em dois aspectos que mudam tudo:
//!
//! 1. A tabela contém **código**, não ponteiros. São 16 entradas de 128 bytes
//!    cada, e o processador simplesmente salta para o início da entrada certa.
//!    Cabe ali um desvio, e é isso que cada entrada faz.
//!
//! 2. O processador **não salva registrador nenhum**. Ele guarda apenas o
//!    endereço de retorno em `ELR_EL1` e o estado em `SPSR_EL1`. Todo o resto
//!    — os 31 registradores de uso geral — é responsabilidade nossa, em
//!    assembly, antes de qualquer código Rust poder rodar.
//!
//! # As 16 entradas
//!
//! São quatro grupos de quatro. Os grupos dizem *de onde* a exceção veio; as
//! quatro entradas de cada grupo dizem *que tipo* ela é (síncrona, IRQ, FIQ,
//! SError).
//!
//! O kernel roda em EL1 usando `SP_EL1`, então o grupo que nos importa hoje é
//! o segundo. O quarto grupo (vindo de EL mais baixo) é o que passará a
//! importar na fase 1, quando houver userspace em EL0 fazendo syscalls.

use aarch64_cpu::asm::barrier;
use aarch64_cpu::registers::{CurrentEL, ESR_EL1, FAR_EL1, VBAR_EL1};
use tock_registers::interfaces::{Readable, Writeable};

/// O contexto salvo pela macro de assembly `SALVAR` quando uma exceção
/// acontece.
///
/// O layout precisa casar **exatamente** com os deslocamentos usados no
/// assembly abaixo: `x0..x30` contíguos a partir do início, depois `elr` e
/// `spsr`. Qualquer divergência aqui vira corrupção silenciosa de registrador,
/// que é das coisas mais difíceis de depurar num kernel.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Quadro {
    /// Registradores de uso geral `x0` a `x30`.
    pub x: [u64; 31],
    /// Endereço de retorno (`ELR_EL1`): a instrução a executar ao sair.
    ///
    /// Alterá-lo é o que permite retomar a execução *depois* de uma instrução
    /// que falhou — é assim que tratamos `brk` sem entrar em laço infinito.
    pub elr: u64,
    /// Estado do processador salvo (`SPSR_EL1`).
    pub spsr: u64,
}

// A tabela de vetores e o código de entrada/saída das exceções.
//
// As macros SALVAR/RESTAURAR existem porque os quatro tipos de exceção
// precisam do mesmo preâmbulo; escrevê-lo quatro vezes convidaria a uma
// divergência sutil entre eles.
core::arch::global_asm!(
    r#"
.section .text.vetores

// Empilha os 31 registradores de uso geral mais ELR e SPSR.
//
// 272 bytes em vez dos 264 necessários: a ABI do aarch64 exige que SP fique
// sempre alinhado em 16 bytes, e 264 não é múltiplo de 16.
.macro SALVAR
    sub     sp, sp, #272
    stp     x0,  x1,  [sp, #16 * 0]
    stp     x2,  x3,  [sp, #16 * 1]
    stp     x4,  x5,  [sp, #16 * 2]
    stp     x6,  x7,  [sp, #16 * 3]
    stp     x8,  x9,  [sp, #16 * 4]
    stp     x10, x11, [sp, #16 * 5]
    stp     x12, x13, [sp, #16 * 6]
    stp     x14, x15, [sp, #16 * 7]
    stp     x16, x17, [sp, #16 * 8]
    stp     x18, x19, [sp, #16 * 9]
    stp     x20, x21, [sp, #16 * 10]
    stp     x22, x23, [sp, #16 * 11]
    stp     x24, x25, [sp, #16 * 12]
    stp     x26, x27, [sp, #16 * 13]
    stp     x28, x29, [sp, #16 * 14]
    // x0 e x1 já estão salvos, então servem de rascunho a partir daqui.
    mrs     x0, elr_el1
    mrs     x1, spsr_el1
    stp     x30, x0,  [sp, #16 * 15]
    str     x1,       [sp, #16 * 16]
.endm

// Desfaz SALVAR. A ordem é deliberada: ELR e SPSR são restaurados primeiro,
// usando x0/x1 como rascunho, e só depois os valores reais de x0/x1 voltam.
.macro RESTAURAR
    ldr     x1,       [sp, #16 * 16]
    ldp     x30, x0,  [sp, #16 * 15]
    msr     spsr_el1, x1
    msr     elr_el1,  x0
    ldp     x0,  x1,  [sp, #16 * 0]
    ldp     x2,  x3,  [sp, #16 * 1]
    ldp     x4,  x5,  [sp, #16 * 2]
    ldp     x6,  x7,  [sp, #16 * 3]
    ldp     x8,  x9,  [sp, #16 * 4]
    ldp     x10, x11, [sp, #16 * 5]
    ldp     x12, x13, [sp, #16 * 6]
    ldp     x14, x15, [sp, #16 * 7]
    ldp     x16, x17, [sp, #16 * 8]
    ldp     x18, x19, [sp, #16 * 9]
    ldp     x20, x21, [sp, #16 * 10]
    ldp     x22, x23, [sp, #16 * 11]
    ldp     x24, x25, [sp, #16 * 12]
    ldp     x26, x27, [sp, #16 * 13]
    ldp     x28, x29, [sp, #16 * 14]
    add     sp, sp, #272
.endm

// Confere, antes de empilhar o quadro, que ele cabe na pilha de exceção.
//
// Toda pilha de exceção é uma vaga de 64 KiB alinhada em 64 KiB cuja
// primeira página é a guarda (ver `fios::pilha`; a do boot é montada igual
// no linker script). Um endereço da vaga está na guarda exatamente quando
// os bits 12 a 15 dele são zero. O quadro vai para [sp - 272, sp), e não
// cabe quando o primeiro byte dele, `sp - 272`, está na guarda — ou quando
// o último, `sp - 1`, está: uma função com quadro de quase 4 KiB pode
// deixar `sp` nos 272 bytes de baixo da guarda, e aí `sp - 272` já é o topo
// da vaga de baixo, onde os bits dizem "não é guarda". O último byte, e não
// `sp`: no repouso `sp` é o topo da vaga, que é o começo da seguinte, e os
// bits dele são zero.
//
// Sem esta conferência, um estouro de verdade não parava na guarda: o
// `stp` do `SALVAR` falhava nela, a falha entrava de novo aqui, descia mais
// 272 bytes e falhava de novo — umas quinze vezes, até `sp` sair por baixo
// da guarda e o quadro ser escrito no topo da vaga vizinha, que é a pilha
// de exceção de outro núcleo, viva. O relatório vinha depois disso, e
// apontava para o próprio `stp`.
//
// Nenhum registrador está livre aqui, então a conferência troca `sp` e `x0`
// por aritmética, sem tocar a memória, e desfaz a troca antes de desviar:
// `add`/`sub` sem `s` não mexem nas flags que o `tst` deixou.
.macro CONFERIR_A_PILHA
    sub     sp, sp, #272
    add     sp, sp, x0          // sp = S + x0, com S = sp - 272
    sub     x0, sp, x0          // x0 = S
    tst     x0, #0xF000         // S na guarda?
    b.eq    9f
    add     x0, x0, #271
    tst     x0, #0xF000         // ou o último byte dele, sp - 1?
    sub     x0, x0, #271
9:
    sub     x0, sp, x0          // x0 = x0 de volta
    sub     sp, sp, x0          // sp = S
    add     sp, sp, #272
    b.eq    .Lestouro
.endm

// Cada entrada da tabela tem exatamente 128 bytes (.align 7). Só cabe um
// desvio, então o trabalho real fica nos rótulos comuns mais abaixo.
.macro ENTRADA rotulo
    .align 7
    b       \rotulo
.endm

// A tabela inteira precisa de alinhamento de 2 KiB (.align 11): VBAR_EL1
// ignora os 11 bits baixos do endereço que recebe.
.align 11
.global tabela_vetores_el1
tabela_vetores_el1:
    // --- EL atual usando SP0 ---------------------------------------------
    // Não usamos SP0, mas as entradas precisam existir: se uma exceção caísse
    // aqui e encontrasse lixo, o desfecho seria imprevisível.
    ENTRADA .Ltrap_sync
    ENTRADA .Ltrap_irq
    ENTRADA .Ltrap_fiq
    ENTRADA .Ltrap_serror

    // --- EL atual usando SPx --- é aqui que o kernel vive ----------------
    ENTRADA .Ltrap_sync
    ENTRADA .Ltrap_irq
    ENTRADA .Ltrap_fiq
    ENTRADA .Ltrap_serror

    // --- EL mais baixo, AArch64 --- userspace, a partir da fase 1 --------
    ENTRADA .Ltrap_sync
    ENTRADA .Ltrap_irq
    ENTRADA .Ltrap_fiq
    ENTRADA .Ltrap_serror

    // --- EL mais baixo, AArch32 --- não suportamos código de 32 bits -----
    ENTRADA .Ltrap_sync
    ENTRADA .Ltrap_irq
    ENTRADA .Ltrap_fiq
    ENTRADA .Ltrap_serror

.Ltrap_sync:
    CONFERIR_A_PILHA
    SALVAR
    mov     x0, sp
    bl      {sync}
    RESTAURAR
    eret

.Ltrap_irq:
    CONFERIR_A_PILHA
    SALVAR
    mov     x0, sp
    bl      {irq}
    RESTAURAR
    eret

.Ltrap_fiq:
    CONFERIR_A_PILHA
    SALVAR
    mov     x0, sp
    bl      {fiq}
    RESTAURAR
    eret

.Ltrap_serror:
    CONFERIR_A_PILHA
    SALVAR
    mov     x0, sp
    bl      {serror}
    RESTAURAR
    eret

// A pilha de exceção estourou: o que está nela é a cadeia que estourou, e
// não há volta para ela. O handler recomeça no topo da **própria** vaga —
// `sp` com os 16 bits baixos ligados, mais um —, e nada fora dela é
// tocado. `SP_EL0` serve de rascunho para `x0`: o fio interrompido não
// continua, e o relatório não precisa dele.
.Lestouro:
    msr     sp_el0, x0
    mov     x0, sp
    orr     x0, x0, #0xFFFF
    add     x0, x0, #1
    mov     sp, x0
    mrs     x0, sp_el0
    SALVAR
    mov     x0, sp
    bl      {estouro}
.Lestouro_sem_volta:
    b       .Lestouro_sem_volta
"#,
    sync = sym tratar_sync,
    irq = sym tratar_irq,
    fiq = sym tratar_fiq,
    serror = sym tratar_serror,
    estouro = sym tratar_estouro,
);

/// O registrador de síndrome da exceção (`ESR_EL1`), cru.
///
/// É onde o processador descreve *o que* aconteceu. Guardamos o valor inteiro
/// em [`crate::traps`] sem interpretar: qualquer decodificação que fizéssemos
/// perderia bits do campo ISS que podem importar, e o agente tem como
/// consultar o manual.
fn ler_esr() -> u64 {
    ESR_EL1.get()
}

/// A classe da exceção — o campo `EC` do `ESR_EL1`.
///
/// Antes isto era `(esr >> 26) & 0x3F` espalhado pelos handlers. O
/// deslocamento e a máscara estavam corretos, mas eram duas oportunidades de
/// errar em silêncio a cada uso.
fn classe_da_excecao() -> u64 {
    ESR_EL1.read(ESR_EL1::EC)
}

/// Lê o registrador de endereço da falha (`FAR_EL1`).
///
/// Contém o endereço acusado numa falha de acesso a memória — o equivalente
/// ao CR2 do x86. Só é significativo para abortos de dado ou de instrução.
fn ler_far() -> u64 {
    FAR_EL1.get()
}

/// Traduz a classe de exceção (campo EC do ESR) para um nome estável.
///
/// Os códigos vêm do manual de arquitetura ARM (seção sobre ESR_ELx).
const fn nome_da_classe(ec: u64) -> &'static str {
    match ec {
        0x00 => "unknown",
        0x0E => "illegal_execution_state",
        0x15 => "svc",
        0x18 => "msr_mrs_trap",
        0x20 => "instruction_abort_lower_el",
        0x21 => "instruction_abort",
        0x22 => "pc_alignment_fault",
        0x24 => "data_abort_lower_el",
        0x25 => "data_abort",
        0x26 => "sp_alignment_fault",
        0x3C => "breakpoint",
        _ => "sync_desconhecida",
    }
}

/// Handler de exceções síncronas: causadas pela instrução que estava
/// executando (acesso inválido a memória, instrução ilegal, `brk`, `svc`).
#[unsafe(no_mangle)]
extern "C" fn tratar_sync(quadro: &mut Quadro) {
    let esr = ler_esr();
    let ec = classe_da_excecao();
    let nome = nome_da_classe(ec);

    // `SVC` é a chamada de sistema. Hoje tem um único uso: um fio de execução
    // pedindo para ceder a vez. Passa por aqui de propósito — assim a cessão
    // voluntária e a preempção usam exatamente o mesmo caminho de troca, sobre
    // o mesmo quadro montado do mesmo jeito.
    //
    // O `eret` volta para a instrução *seguinte* ao `svc` sem que precisemos
    // ajustar nada: diferente do `brk`, o processador já deixa `ELR_EL1`
    // apontando para depois dela.
    if ec == 0x15 {
        if super::usuario::veio_de_usuario(quadro) {
            // Chamada de sistema de um processo.
            super::usuario::atender_chamada(quadro);

            // Uma chamada pode deixar o fio sem poder continuar de duas
            // formas: ele saiu, ou está esperando um filho. Quem troca de
            // contexto nos dois casos é este handler, sobre o quadro que ele
            // já tem. Ver `fios::marcar_terminado` para o porquê de não ser a
            // própria chamada a ceder.
            //
            // E pelo mesmo motivo a chamada `ceder` só pede a vez: dada
            // aqui, sobre o quadro de fora, o fio volta em EL0 pelo quadro
            // dele, em qualquer núcleo. Ver `fios::pedir_cessao`.
            let ceder = crate::fios::tirar_cessao();
            if crate::fios::atual_parado() {
                parar_o_fio_atual(quadro);
            } else if ceder {
                // SAFETY: estamos dentro de um handler de exceção, com as
                // interrupções mascaradas pela própria entrada da exceção, e
                // o quadro é o de fora — o do usuário.
                unsafe { super::contexto::trocar_no_quadro(quadro) };
            }
            return;
        }

        // `svc` de EL1: um fio do kernel cedendo a vez.
        //
        // SAFETY: estamos dentro de um handler de exceção, com as interrupções
        // mascaradas pela própria entrada da exceção.
        unsafe { super::contexto::trocar_no_quadro(quadro) };
        return;
    }

    // O `brk` do estouro de propósito — ver
    // [`super::disparar_estouro_em_excecao`]. Afunda daqui, na pilha de
    // exceção, até a guarda.
    if ec == 0x3C && esr & 0xFFFF == IMEDIATO_DO_ESTOURO as u64 {
        crate::traps::afundar_de_proposito();
    }
    // E o da borda: `sp` a 16 bytes da base da guarda, onde o quadro do
    // próximo aninhamento começaria na vaga de baixo — ver
    // [`super::disparar_estouro_na_borda`].
    if ec == 0x3C && esr & 0xFFFF == IMEDIATO_DO_ESTOURO_NA_BORDA as u64 {
        pisar_no_fundo_da_guarda();
    }

    // `BRK` é a única outra classe que sabemos retomar hoje.
    if ec == 0x3C {
        let seq = crate::traps::registrar(nome, quadro.elr, None, esr);
        crate::log_info!("traps", "breakpoint #{} em pc={:#x}", seq, quadro.elr);

        // Sem este avanço o `eret` voltaria para a *mesma* instrução `brk` e
        // o kernel entraria num laço infinito de exceções. Toda instrução
        // aarch64 tem 4 bytes, então o próximo endereço é sempre elr + 4.
        quadro.elr += 4;
        return;
    }

    // Um endereço acusado só faz sentido para falhas de acesso a memória; nas
    // demais classes o FAR contém lixo de uma falha anterior.
    let endereco = matches!(ec, 0x20 | 0x21 | 0x24 | 0x25).then(ler_far);

    // Antes de decidir de quem é a culpa, a pergunta que pode dissolver a
    // falha: era uma escrita numa página de cópia na escrita?
    //
    // # Por que a checagem do nível de exceção não entra aqui
    //
    // Porque o kernel também escreve em memória do usuário — é o que `ler`
    // faz ao entregar os bytes lidos ao buffer do processo. Essa escrita vem
    // de EL1 e, numa página compartilhada por um `fork`, falharia exatamente
    // como a do processo. Por isso as duas classes de aborto de dado entram:
    // `0x24`, vindo de EL0, e `0x25`, vindo daqui mesmo.
    //
    // O que **não** se afrouxa é o resto. `copia_na_escrita_em` só reconhece
    // uma página presente e marcada, e a marca só existe onde um `fork` a
    // pôs. Uma escrita do kernel num endereço qualquer segue sendo fatal.
    if matches!(ec, 0x24 | 0x25)
        && e_escrita_proibida(esr)
        && let Some(endereco) = endereco
        && crate::paginacao::resolver_copia_na_escrita(endereco)
    {
        // O `eret` reexecuta a instrução que falhou, agora sobre uma página
        // gravável: diferente do `brk`, aqui o `ELR_EL1` aponta para a
        // própria instrução, que é exatamente o que queremos.
        return;
    }

    // Uma falha vinda de EL0 é culpa do processo, não do kernel. Matar o
    // sistema por causa dela seria entregar a todo processo um jeito trivial
    // de derrubar a máquina — e desperdiçaria exatamente a proteção que ring 3
    // existe para dar.
    if super::usuario::veio_de_usuario(quadro) {
        let seq = crate::traps::registrar(nome, quadro.elr, endereco, esr);
        crate::log_error!(
            "usuario",
            "processo morto por {} #{} em pc={:#x}",
            nome,
            seq,
            quadro.elr
        );
        // Sem código de saída: este processo não chegou a `sair`.
        crate::fios::marcar_terminado(None);
        parar_o_fio_atual(quadro);
        return;
    }

    crate::traps::fatal(nome, quadro.elr, endereco, esr)
}

/// O imediato do `brk` que pede um estouro da pilha de exceção, de
/// propósito: `debug.trigger` com `kind: "stack_overflow"`.
pub(super) const IMEDIATO_DO_ESTOURO: u16 = 0xE5;

/// O do estouro na borda: `kind: "stack_overflow_edge"`.
pub(super) const IMEDIATO_DO_ESTOURO_NA_BORDA: u16 = 0xE6;

/// Põe `sp` a 16 bytes da base da guarda da vaga em uso e escreve ali.
///
/// A escrita falha na guarda, e a exceção entra com `sp - 272` já na vaga
/// de baixo — onde os bits de `sp - 272` dizem "não é guarda". É a borda
/// que só a segunda metade da conferência da entrada pega (o último byte do
/// quadro, `sp - 1`); sem ela, o quadro seria escrito no topo da vaga
/// vizinha. A recursão de [`crate::traps::afundar_de_proposito`] chega à
/// guarda pelo alto, e não a alcança.
///
/// Fora de linha: o relatório do estouro nomeia esta função pelo `pc`.
#[inline(never)]
fn pisar_no_fundo_da_guarda() -> ! {
    // SAFETY: nenhuma; é o ponto. Não há volta: a escrita falha, e a
    // falha é um estouro relatado.
    unsafe {
        core::arch::asm!(
            "mov x9, sp",
            "and x9, x9, #0xFFFFFFFFFFFF0000",
            "add x9, x9, #16",
            "mov sp, x9",
            "str xzr, [sp]",
            "2: b 2b",
            options(noreturn)
        )
    }
}

/// A pilha de exceção estourou — a conferência da entrada dos vetores viu o
/// quadro cair na guarda. Roda no topo da própria vaga, recomeçada.
///
/// O `pc` é o da instrução que tocou a guarda: a função que estourou, que
/// `cargo xtask simbolo` traduz. O endereço acusado, quando a exceção é um
/// aborto, é o da guarda.
extern "C" fn tratar_estouro(quadro: &mut Quadro) -> ! {
    let ec = classe_da_excecao();
    let endereco = matches!(ec, 0x20 | 0x21 | 0x24 | 0x25).then(ler_far);
    crate::traps::fatal(
        "estouro_da_pilha_de_excecao",
        quadro.elr,
        endereco,
        ler_esr(),
    )
}

/// O aborto de dado descrito por `esr` foi uma **escrita** barrada pelas
/// permissões da página?
///
/// São as duas perguntas que separam a falha que a cópia na escrita resolve
/// de todas as outras, e as duas moram no campo ISS do `ESR_EL1`:
///
/// - `WnR`, o bit 6, diz se o acesso era escrita. Sem ele, uma **leitura**
///   numa página marcada seria "resolvida" tirando uma cópia que ninguém
///   pediu — e a leitura teria funcionado sozinha, porque a marca não tira a
///   leitura.
/// - `DFSC`, os seis bits baixos, diz *por que* o acesso falhou. A família
///   `0b0011LL` é a falha de permissão, em qualquer um dos quatro níveis de
///   tabela; as outras famílias são tradução ausente, erro de barramento,
///   desalinhamento. Sem esta conferência, tentaríamos resolver como cópia na
///   escrita um endereço que sequer tem página.
///
/// A comparação usa a família inteira, e não o nível 3 sozinho, porque o
/// nível em que o hardware reporta a falha é o do descritor que a barrou —
/// e um bloco grande a reportaria mais acima. Aceitar a família e deixar
/// `copia_na_escrita_em` recusar o que não for folha de 4 KiB põe a decisão
/// em quem sabe olhar a tabela.
const fn e_escrita_proibida(esr: u64) -> bool {
    const WNR: u64 = 1 << 6;
    const FAMILIA_DFSC: u64 = 0b11_1100;
    const FALHA_DE_PERMISSAO: u64 = 0b00_1100;

    esr & WNR != 0 && esr & FAMILIA_DFSC == FALHA_DE_PERMISSAO
}

/// Tira de circulação o fio que não pode continuar, sobre o quadro da
/// exceção corrente.
///
/// São dois casos, e a diferença entre eles não aparece aqui: um fio
/// encerrado nunca mais é escolhido, e um que espera um filho volta quando o
/// filho sai. Os dois precisam da mesma coisa agora — sair da frente.
///
/// Se não houver outro fio pronto, esperamos aqui dentro em vez de retornar:
/// um `eret` neste ponto devolveria o controle a um processo que já não
/// existe, ou retomaria um que ainda não pode andar.
///
/// A condição de parada é sobre o fio **atual depois da troca**, que já é
/// outro: sair do laço quer dizer "conseguimos passar a bola para alguém que
/// pode correr".
fn parar_o_fio_atual(quadro: &mut Quadro) {
    loop {
        // SAFETY: estamos dentro de um handler de exceção, com as interrupções
        // mascaradas pela própria entrada da exceção.
        unsafe { super::contexto::trocar_no_quadro(quadro) };

        if !crate::fios::atual_parado() {
            return;
        }

        // `wfi` acorda com uma IRQ pendente mesmo mascarada — e aqui elas
        // estão, pela própria entrada da exceção —, então a próxima
        // interrupção do timer nos traz de volta, possivelmente com alguém
        // pronto para rodar.
        //
        // `dormir_parado` porque é ela que promete isso nas duas
        // arquiteturas. Este comentário já descreveu um `wfi` que não
        // acontecia: `esperar_interrupcao` copiava a guarda do x86 e girava
        // quando mascarada, que é sempre, aqui dentro.
        crate::arch::dormir_parado();
    }
}

/// Handler de IRQ: interrupção de hardware.
///
/// Delega ao GIC, que identifica a fonte, atende e finaliza. O quadro salvo
/// não é consultado hoje, mas existe e está correto — é dele que o scheduler
/// preemptivo vai precisar na fase 1, quando uma interrupção de timer puder
/// resultar em troca de contexto.
#[unsafe(no_mangle)]
extern "C" fn tratar_irq(quadro: &mut Quadro) {
    let preemptar = super::gic::tratar();

    if preemptar {
        // A troca acontece **depois** de o GIC ter sido avisado do fim do
        // atendimento, lá dentro de `tratar`. Se trocássemos antes, a linha do
        // timer ficaria eternamente em atendimento e o próximo tique nunca
        // chegaria — o sistema trocaria de fio uma única vez.
        //
        // SAFETY: estamos dentro de um handler de exceção, com as interrupções
        // mascaradas pela própria entrada da exceção.
        unsafe { super::contexto::trocar_no_quadro(quadro) };
    }
}

/// Handler de FIQ: interrupção rápida, de prioridade mais alta.
#[unsafe(no_mangle)]
extern "C" fn tratar_fiq(quadro: &mut Quadro) {
    let seq = crate::traps::registrar("fiq", quadro.elr, None, 0);
    crate::log_warn!("traps", "FIQ inesperada #{} em pc={:#x}", seq, quadro.elr);
}

/// Handler de SError: erro assíncrono do sistema.
///
/// Tipicamente sinaliza um problema de barramento ou de memória detectado
/// depois do fato. Como é assíncrono, o `pc` salvo não aponta necessariamente
/// para a instrução culpada — por isso é fatal: não há a que retornar com
/// confiança.
#[unsafe(no_mangle)]
extern "C" fn tratar_serror(quadro: &mut Quadro) {
    crate::traps::fatal("serror", quadro.elr, None, ler_esr())
}

/// Instala a tabela de vetores em `VBAR_EL1`.
pub fn init() {
    // SAFETY: o símbolo é definido pelo assembly acima e tem o alinhamento de
    // 2 KiB que VBAR_EL1 exige.
    unsafe extern "C" {
        static tabela_vetores_el1: u8;
    }

    VBAR_EL1.set(&raw const tabela_vetores_el1 as u64);

    // Obrigatório: sem ele o processador pode continuar usando o VBAR antigo
    // por algumas instruções, e uma exceção nesse intervalo saltaria para o
    // lugar errado.
    barrier::isb(barrier::SY);
}

/// O nível de exceção em que o kernel está rodando.
///
/// Útil no diagnóstico: `VBAR_EL1` só governa exceções tomadas *em* EL1, então
/// se tivéssemos bootado em EL2 a tabela não teria efeito — e isso explicaria
/// um silêncio difícil de entender.
pub fn nivel_de_excecao() -> u8 {
    CurrentEL.read(CurrentEL::EL) as u8
}
