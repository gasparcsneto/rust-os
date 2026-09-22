//! Entrada em ring 3 e chamadas de sistema no x86_64.
//!
//! # Os dois sentidos da travessia
//!
//! **Descer para o usuário** não tem instrução própria. Usamos `iretq`, a
//! mesma que encerra um handler de interrupção: ela restaura `CS:RIP`,
//! `RFLAGS` e `SS:RSP` de uma vez a partir da pilha, e o nível de privilégio
//! sai do `CS` que empilhamos. Fabricar um quadro de retorno que nunca
//! existiu é o truque clássico para entrar em ring 3 pela primeira vez.
//!
//! **Subir de volta** tem: `syscall`. Ela é rápida porque faz quase nada — e
//! é justamente o "quase nada" que dá trabalho, como se vê abaixo.
//!
//! # O que `syscall` não faz por você
//!
//! Uma interrupção vinda de ring 3 faz o processador trocar de pilha sozinho,
//! usando o `RSP0` do TSS. A instrução `syscall` **não troca a pilha**: ela
//! carrega `CS` e `SS` de `STAR`, põe o endereço de retorno em `RCX` e as
//! flags em `R11`, salta para `LSTAR` — e deixa `RSP` apontando para a pilha
//! do usuário.
//!
//! Ou seja: o kernel começa a executar com um ponteiro de pilha que o processo
//! controla. Se o handler empilhasse qualquer coisa antes de trocar, estaria
//! escrevendo onde o usuário mandou. A primeira coisa que o ponto de entrada
//! faz, portanto, é trocar de pilha — e para isso precisa guardar a do usuário
//! em algum lugar que não seja a própria pilha.
//!
//! A solução canônica é `swapgs` com dados por núcleo. Com um núcleo só, duas
//! variáveis globais alcançadas por endereçamento relativo ao `RIP` dão o
//! mesmo resultado com muito menos maquinaria. Quando houver SMP, estas duas
//! viram campos de uma estrutura por núcleo e o `swapgs` entra.

use core::arch::global_asm;

use x86_64::VirtAddr;
use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;

use super::gdt;

/// Onde o ponto de entrada guarda a pilha do usuário durante a chamada.
///
/// Um núcleo, um fio dentro do kernel por vez: enquanto esta chamada não
/// retornar, nenhum outro código pode entrar por aqui. Com SMP isto vira um
/// campo por núcleo.
#[unsafe(no_mangle)]
static mut PILHA_DE_USUARIO_SALVA: u64 = 0;

/// A pilha de kernel que o ponto de entrada adota.
///
/// Atualizada junto com o `RSP0` do TSS a cada troca de contexto — os dois
/// precisam apontar para a pilha do mesmo fio.
#[unsafe(no_mangle)]
static mut PILHA_DE_KERNEL_ATUAL: u64 = 0;

/// Informa a pilha de kernel do fio que vai rodar.
///
/// Chamado pela troca de contexto. Atualiza os dois caminhos de entrada no
/// kernel a partir do usuário: o `RSP0` do TSS, que a *interrupção* usa, e a
/// global que a *chamada de sistema* usa.
pub fn definir_pilha_de_kernel(topo: u64) {
    if topo == 0 {
        return;
    }
    gdt::definir_pilha_de_kernel(topo);
    // SAFETY: escrita de uma palavra alinhada, com as interrupções mascaradas
    // pelo chamador. Só o ponto de entrada de `syscall` a lê, e ele não pode
    // estar executando agora — estamos em ring 0, e não há outro núcleo.
    unsafe { PILHA_DE_KERNEL_ATUAL = topo };
}

/// Liga o mecanismo de chamadas de sistema.
///
/// # Safety
///
/// Exige a GDT já carregada: os seletores que vão para `STAR` vêm dela.
pub unsafe fn init() {
    let sel = gdt::seletores();

    // SAFETY: os quatro registradores abaixo são os que definem o mecanismo;
    // escrevê-los antes de habilitar `SCE` garante que nenhuma `syscall` possa
    // ser atendida com metade da configuração no lugar.
    unsafe {
        // Quem entra e quem sai. `Star::write` confere a ordem dos descritores
        // e recusa uma GDT montada errado — a mesma ordem que `gdt::init`
        // explica em detalhe.
        Star::write(
            sel.codigo_usuario,
            sel.dados_usuario,
            sel.codigo_kernel,
            sel.dados_kernel,
        )
        .expect("a ordem dos seletores na GDT nao satisfaz o sysret");

        // Para onde saltar.
        LStar::write(VirtAddr::new(ponto_de_entrada as *const () as u64));

        // Quais flags apagar na entrada. `INTERRUPT_FLAG` é a que importa: sem
        // ela, uma interrupção poderia chegar entre o `syscall` e a troca de
        // pilha, quando o kernel ainda está rodando sobre a pilha do usuário.
        // `DIRECTION_FLAG` entra porque as rotinas de memória do compilador
        // assumem contagem crescente, e o usuário pode tê-la invertido.
        SFMask::write(RFlags::INTERRUPT_FLAG | RFlags::DIRECTION_FLAG);

        // Só agora a instrução passa a existir para o processador.
        Efer::update(|flags| flags.insert(EferFlags::SYSTEM_CALL_EXTENSIONS));
    }

    crate::log_info!("usuario", "syscall/sysret habilitados");
}

unsafe extern "C" {
    fn ponto_de_entrada();
}

/// O estado do usuário no instante da chamada de sistema.
///
/// # Por que o quadro existe agora, e não antes
///
/// Antes do `fork`, o caminho de chamada de sistema só precisava preservar o
/// que o usuário esperava de volta — e os registradores que a convenção de
/// chamada já preserva ficavam por conta do compilador, nos próprios
/// registradores. `fork` muda isso: para dar ao filho o estado do pai é
/// preciso **ler** esse estado, e o que mora só num registrador não tem
/// endereço.
///
/// Empilhar tudo também aproxima as duas arquiteturas. No ARM a entrada de
/// exceção já materializa um quadro completo; aqui ele passa a existir pelo
/// mesmo motivo e com o mesmo papel.
///
/// # A ordem dos campos não é estética
///
/// Ela espelha, do endereço mais baixo para o mais alto, a ordem inversa dos
/// `push` em [`ponto_de_entrada`]. Trocar um campo de lugar sem trocar o
/// `push` correspondente faria o usuário voltar com registradores embaralhados
/// — e nada nisso falha de imediato.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct QuadroDeUsuario {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    /// `RFLAGS` no instante do `syscall`: a instrução as deposita aqui.
    pub r11: u64,
    /// Endereço de retorno ao usuário: a instrução `syscall` o deposita aqui.
    pub rcx: u64,
    /// Número da chamada na entrada, valor de retorno na saída.
    pub rax: u64,
    /// O `RSP` do usuário, guardado antes da troca para a pilha de kernel.
    pub rsp: u64,
}

global_asm!(
    r#"
.section .text
.global ponto_de_entrada
ponto_de_entrada:
    // Entramos em ring 0 com RSP ainda apontando para a pilha do *usuário*.
    // Trocar é a primeira coisa, antes de empilhar qualquer byte.
    mov [rip + PILHA_DE_USUARIO_SALVA], rsp
    mov rsp, [rip + PILHA_DE_KERNEL_ATUAL]

    // A partir daqui montamos o `QuadroDeUsuario` na pilha de kernel. A ordem
    // é o contrato: cada `push` corresponde a um campo da struct, do endereço
    // mais alto para o mais baixo.
    push qword ptr [rip + PILHA_DE_USUARIO_SALVA]
    push rax

    // RCX e R11 não são escolha nossa: a instrução `syscall` os sobrescreve
    // com o endereço de retorno e as flags. Guardá-los é o que permite ao
    // `sysretq` devolver o usuário exatamente onde ele estava.
    push rcx
    push r11

    // Os registradores que a convenção de chamada não preserva e que o usuário
    // espera de volta intactos.
    push rdi
    push rsi
    push rdx
    push r8
    push r9
    push r10

    // E os que ela preserva. Antes do `fork` bastava deixá-los com o
    // compilador; agora o filho precisa recebê-los, e para isso eles precisam
    // de um endereço.
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    // Dezesseis `push` a partir de um topo alinhado em 16 deixam o RSP
    // alinhado, que é o que a convenção de chamada exige no ponto do `call`.
    mov rdi, rsp
    call {despachar}

    // O retorno vai para o campo `rax` do quadro, e não para o registrador:
    // ele ainda vai ser restaurado pelos `pop` abaixo.
    mov [rsp + 14*8], rax

// Onde um filho de `fork` entra em cena. Ele nunca passou pela metade de cima
// desta funcao: o contexto dele foi montado para que a primeira troca de fio
// caia exatamente aqui, com um `QuadroDeUsuario` pronto logo acima do RSP.
.global retorno_ao_usuario
retorno_ao_usuario:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

    pop r10
    pop r9
    pop r8
    pop rdx
    pop rsi
    pop rdi

    pop r11
    pop rcx
    pop rax

    // `pop rsp` devolve a pilha do usuário direto do quadro — inclusive quando
    // o quadro é o de um filho de `fork`, que nunca passou por aqui na ida.
    pop rsp

    // `sysretq`, com q: sem o sufixo o retorno seria para modo compatível de
    // 32 bits, e o processo voltaria a executar seu próprio código
    // interpretado como instruções de 32 bits.
    sysretq
"#,
    despachar = sym despachar_chamada,
);

/// Ponte do assembly para o despacho neutro de arquitetura.
///
/// # Safety
///
/// `quadro` precisa apontar para o [`QuadroDeUsuario`] que o
/// [`ponto_de_entrada`] acabou de montar na pilha de kernel deste fio.
extern "C" fn despachar_chamada(quadro: *mut QuadroDeUsuario) -> i64 {
    // SAFETY: o ponteiro vem do assembly logo acima, e aponta para o quadro
    // recém-montado na nossa própria pilha de kernel.
    let q = unsafe { &mut *quadro };
    let (numero, a0, a1, a2) = (q.rax, q.rdi, q.rsi, q.rdx);

    // SAFETY: o quadro é o desta chamada; `bifurcar` e `executar` o leem e o
    // reescrevem, e é por isso que ele desce até o despacho.
    let resultado =
        unsafe { crate::usuario::despachar(numero, a0, a1, a2, quadro as *mut core::ffi::c_void) };

    // `sair` apenas marca; quem troca de contexto é quem tem como não voltar.
    // Aqui estamos numa cadeia de chamadas comum sobre a pilha de kernel do
    // fio, então ceder de vez basta — e o `sysretq` lá embaixo nunca chega a
    // executar, que é exatamente o desejado para um processo encerrado.
    if crate::fios::atual_terminou() {
        crate::fios::descansar();
    }

    resultado
}

/// Desce para ring 3 e começa a executar em `entrada`. Nunca retorna.
///
/// # Safety
///
/// `entrada` e `pilha` precisam estar mapeados com permissão de usuário, e a
/// pilha de kernel do fio atual precisa já ter sido informada por
/// [`definir_pilha_de_kernel`] — sem isso, a primeira interrupção que chegar
/// com o usuário rodando não terá para onde empilhar.
pub unsafe fn entrar(entrada: u64, pilha: u64) -> ! {
    let sel = gdt::seletores();

    // O `iretq` espera, do topo para baixo: SS, RSP, RFLAGS, CS, RIP. Os
    // seletores levam RPL 3 — é o RPL, e não o DPL do descritor, que define o
    // privilégio com que o código passa a executar.
    let ss = sel.dados_usuario.0 as u64;
    let cs = sel.codigo_usuario.0 as u64;

    // `0x202`: bit 1 sempre ligado (reservado, exigido pelo processador) e
    // `IF` ligado. Entrar com as interrupções desligadas deixaria o processo
    // impreemptável, e o primeiro laço infinito dele travaria a máquina.
    const RFLAGS: u64 = 0x202;

    // SAFETY: o quadro abaixo descreve um retorno para ring 3 que nunca
    // aconteceu, que é exatamente como se entra em userspace pela primeira
    // vez. O chamador garantiu os mapeamentos.
    unsafe {
        core::arch::asm!(
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = in(reg) ss,
            rsp = in(reg) pilha,
            rflags = in(reg) RFLAGS,
            cs = in(reg) cs,
            rip = in(reg) entrada,
            options(noreturn),
        )
    }
}
