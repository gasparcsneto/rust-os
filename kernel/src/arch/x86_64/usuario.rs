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
//! A solução canônica é `swapgs` com dados por núcleo, e é a que este kernel
//! usa desde que tem vários núcleos. Com um só, duas variáveis globais
//! alcançadas por endereçamento relativo ao `RIP` bastavam; com dois, os dois
//! núcleos guardariam a pilha do usuário **no mesmo lugar**, e o segundo
//! `syscall` sobrescreveria a do primeiro antes de ele empilhá-la.
//!
//! # O `swapgs`, e por que ele dura três instruções
//!
//! `swapgs` troca a base do `GS` pelo valor guardado em `IA32_KERNEL_GS_BASE`
//! — que aqui aponta para a [`PorNucleo`] deste núcleo. O ponto de entrada
//! troca, guarda a pilha do usuário, adota a de kernel, empilha a do usuário
//! e **troca de volta**. Fora dessas instruções o kernel nunca olha o `GS`.
//!
//! Isso é deliberado. Os kernels costumam deixar o `GS` trocado por todo o
//! tempo em que estão no anel zero, e então precisam decidir, em cada
//! interrupção, se ela veio do usuário (e precisa trocar) ou do kernel (e não
//! pode). Errar essa decisão uma vez é dar a um handler o `GS` do processo.
//! Aqui não há decisão: o `syscall` limpa `IF` (ver o `SFMask` em [`init`]),
//! então nenhuma interrupção cai na janela, e a NMI — que cai — tem pilha
//! própria e não usa `GS` — ver [`super::gdt::IST_NMI`]. Quem precisa saber
//! em que núcleo está pergunta ao `TR`, que o processo não alcança — ver
//! [`super::gdt::nucleo_atual`].

use core::arch::global_asm;
use core::cell::UnsafeCell;

use x86_64::VirtAddr;
use x86_64::registers::model_specific::{Efer, EferFlags, KernelGsBase, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;

use super::gdt;
use crate::nucleos::MAX_NUCLEOS;

/// O que o ponto de entrada de `syscall` precisa, por núcleo.
///
/// A ordem dos campos é contrato com o assembly: ele os alcança como
/// `gs:[0]` e `gs:[8]`.
#[repr(C, align(64))]
pub struct PorNucleo {
    /// A pilha de kernel que o ponto de entrada adota — a do fio que este
    /// núcleo está rodando. Atualizada junto com o `RSP0` do TSS a cada
    /// troca de contexto: os dois precisam apontar para a pilha do mesmo
    /// fio.
    pilha_de_kernel: UnsafeCell<u64>,
    /// Onde o ponto de entrada guarda a pilha do usuário durante as poucas
    /// instruções em que ainda não há onde empilhá-la.
    pilha_de_usuario: UnsafeCell<u64>,
}

/// Uma por núcleo, alinhadas a 64 bytes para que duas nunca dividam uma linha
/// de cache — duas palavras escritas por núcleos diferentes na mesma linha a
/// fariam ir e voltar entre eles a cada chamada de sistema.
struct TabelaPorNucleo([PorNucleo; MAX_NUCLEOS]);

// SAFETY: cada `PorNucleo` só é escrito pelo seu núcleo — pela troca de
// contexto, com as interrupções mascaradas, e pelo ponto de entrada, com
// `IF` limpo pelo `SFMask`. Nenhum núcleo alcança a de outro: o `GS` de cada
// um aponta para a sua.
unsafe impl Sync for TabelaPorNucleo {}

static POR_NUCLEO: TabelaPorNucleo = TabelaPorNucleo(
    [const {
        PorNucleo {
            pilha_de_kernel: UnsafeCell::new(0),
            pilha_de_usuario: UnsafeCell::new(0),
        }
    }; MAX_NUCLEOS],
);

/// Informa a pilha de kernel do fio que vai rodar.
///
/// Chamado pela troca de contexto, e só por ela (`contexto::ceder_cpu`), com
/// as interrupções mascaradas. Atualiza os dois caminhos de entrada no
/// kernel a partir do usuário: o `RSP0` do TSS, que a *interrupção* usa, e a
/// [`PorNucleo`] que a *chamada de sistema* usa — os dois **deste** núcleo,
/// lido uma vez só.
///
/// # Por que só mascarado
///
/// Porque "deste núcleo" só vale enquanto o fio não pode sair dele. A
/// entrada de um processo novo (`usuario::programa::entrar`) também a
/// chamava, com as interrupções ligadas — o fio roda assim desde o `sti` do
/// trampolim —: entre a leitura do núcleo e a escrita, o tique podia
/// preemptar o fio e levá-lo a outro núcleo, e a escrita punha a pilha dele
/// no `RSP0` e na [`PorNucleo`] do núcleo de antes. Até a troca seguinte
/// ali, o fio que rodava naquele núcleo empilhava as interrupções do anel 3
/// e entrava nas chamadas de sistema sobre a pilha deste, que rodava noutro
/// (o item 4 do adversário do lote B2 do #448). A chamada era redundante —
/// a troca que pôs o fio no núcleo já informou a pilha dele, e cada troca
/// seguinte a informa de novo —, e saiu. O `debug_assert!` faz um chamador
/// solto reprovar a suíte de depuração na primeira entrada.
pub fn definir_pilha_de_kernel(topo: u64) {
    debug_assert!(
        !x86_64::instructions::interrupts::are_enabled(),
        "a pilha de kernel informada com as interrupcoes ligadas"
    );
    if topo == 0 {
        return;
    }
    let nucleo = gdt::nucleo_atual();
    gdt::definir_pilha_de_kernel(nucleo, topo);
    // SAFETY: escrita de uma palavra alinhada na estrutura deste núcleo, com
    // as interrupções mascaradas pelo chamador — o núcleo lido acima não
    // muda até aqui. Só o ponto de entrada de `syscall` **deste** núcleo a
    // lê, e ele não pode estar executando agora — estamos em ring 0, no meio
    // de uma troca de contexto.
    unsafe { *POR_NUCLEO.0[nucleo].pilha_de_kernel.get() = topo };
}

/// Liga o mecanismo de chamadas de sistema no primeiro núcleo.
///
/// # Safety
///
/// Exige a GDT já carregada: os seletores que vão para `STAR` vêm dela.
pub unsafe fn init() {
    // SAFETY: delegada ao chamador.
    unsafe { ligar_neste_nucleo() };
    crate::log_info!("usuario", "syscall/sysret habilitados");
    crate::log_info!(
        "usuario",
        "o contador de ciclos fora do anel 3: CR4.TSD ligado, CR4.PCE desligado"
    );
    crate::log_info!(
        "usuario",
        "o ponto flutuante e o SIMD fora do anel 3: CR0.TS e CR0.MP ligados, e nunca desligados"
    );
    if let Some(r) = super::regime_do_firmware() {
        crate::log_info!(
            "usuario",
            "o regime que o firmware deixou: CR0 {:#x}, CR4 {:#x}, XCR0 {:#x}, DR7 {:#x}, \
             SYSENTER_CS {:#x}, SYSENTER_ESP {:#x}, SYSENTER_EIP {:#x}, FS_BASE {:#x}, \
             GS_BASE {:#x}, TSC_AUX {:#x}",
            r.cr0,
            r.cr4,
            r.xcr0,
            r.dr7,
            r.sysenter_cs,
            r.sysenter_esp,
            r.sysenter_eip,
            r.fs_base,
            r.gs_base,
            r.tsc_aux
        );
    }
    let r = super::ler_o_regime_deste_nucleo();
    crate::log_info!(
        "usuario",
        "o regime do kernel: CR0 {:#x}, CR4 {:#x}, XCR0 {:#x}, DR7 {:#x}, SYSENTER_CS {:#x}, \
         SYSENTER_ESP {:#x}, SYSENTER_EIP {:#x}, FS_BASE {:#x}, GS_BASE {:#x}, TSC_AUX {:#x}",
        r.cr0,
        r.cr4,
        r.xcr0,
        r.dr7,
        r.sysenter_cs,
        r.sysenter_esp,
        r.sysenter_eip,
        r.fs_base,
        r.gs_base,
        r.tsc_aux
    );
}

/// Liga o mecanismo de chamadas de sistema **neste** núcleo, escreve o
/// regime dele (ver [`super::escrever_o_regime_deste_nucleo`]) e tira dele
/// o contador de ciclos do anel 3 (ver
/// [`super::fechar_os_contadores_ao_usuario`]).
///
/// Os registradores de modelo abaixo são do núcleo, não do sistema: cada
/// núcleo que acorda precisa escrevê-los, ou o primeiro `syscall` que um
/// processo fizer ali é `#UD`. O `CR4` também é do núcleo.
///
/// # Safety
///
/// Exige a GDT já carregada neste núcleo, com o TSS dele em `TR`.
pub unsafe fn ligar_neste_nucleo() {
    // Antes do primeiro processo que este núcleo rodar: o regime dele — o
    // ponto flutuante preso, o `CR4` do kernel, nenhum ponto de parada, o
    // `sysenter` sem entrada, as bases do `FS` e do `GS` e o `IA32_TSC_AUX`
    // em zero (ver `escrever_o_regime_deste_nucleo`) —, e o anel 3 nunca vê
    // o contador.
    // O `IA32_KERNEL_GS_BASE` vem depois, abaixo, e a `syscall` só existe
    // no fim: nenhuma janela do `swapgs` corre antes.
    super::escrever_o_regime_deste_nucleo();
    super::fechar_os_contadores_ao_usuario();
    let sel = gdt::seletores();
    let por_nucleo = &POR_NUCLEO.0[gdt::nucleo_atual()] as *const PorNucleo as u64;

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

        // Quais flags apagar na entrada — ver [`FLAGS_APAGADAS_NA_ENTRADA`].
        SFMask::write(FLAGS_APAGADAS_NA_ENTRADA);

        // Para onde o `swapgs` da entrada leva o `GS`: a estrutura deste
        // núcleo. A base do `GS` em si fica zero, que é o que o processo vê.
        KernelGsBase::write(VirtAddr::new(por_nucleo));

        // Só agora a instrução passa a existir para o processador.
        Efer::update(|flags| flags.insert(EferFlags::SYSTEM_CALL_EXTENSIONS));
    }
}

/// As flags que a entrada de `syscall` apaga: o `SFMask`. O processador
/// guarda as do processo em `R11`, apaga estas, e o `sysretq` devolve as do
/// processo — ele não vê nada.
///
/// # A máscara do Linux, inteira
///
/// É a de `syscall_init` no Linux: toda flag que o processo alcança, e o
/// kernel começa cada chamada com as flags em zero. Uma por uma:
///
/// - **`IF`**: sem ela, uma interrupção poderia chegar entre o `syscall` e a
///   troca de pilha, com o kernel ainda sobre a pilha do processo.
/// - **`DF`**: as rotinas de memória do compilador contam para cima, e o
///   processo pode ter invertido a direção.
/// - **`TF`**: com o passo ligado pelo processo, o `#DB` do passo chegaria ao
///   anel 0 depois da `syscall`, antes da troca de pilha, com o `RSP` dele —
///   o quadro da exceção iria para uma memória que outro fio do processo
///   escreve. O processador confere o `TF` depois da `syscall`, já
///   mascarado: o passo volta com o `sysretq`, e o `#DB` chega no anel 3,
///   na volta — como se a `syscall` tivesse acabado de rodar ali.
///   (O `#DB` tem também uma pilha própria — ver
///   [`super::gdt::IST_DEPURACAO`].)
/// - **`NT`**: no modo longo ele só faz uma coisa — o `iretq` com ele ligado
///   é `#GP`. Ligado na chamada, ele passava pela troca voluntária de fio
///   (`ceder_cpu`, que não guarda as flags) ao fio que entrava, e o `iretq`
///   da volta dele — a de um tratador que o tique preemptou, ou a descida de
///   um processo novo — dava `#GP` no anel 0: a máquina parava. A suíte o
///   viu (`excecoes: o NT ligado ...`).
/// - **`AC`**: no anel 0 ele só desliga o SMAP, que o kernel hoje não liga;
///   ligado, ele valeria a chamada inteira. Fora antes que o SMAP entre.
/// - **as aritméticas** (`CF`, `PF`, `AF`, `ZF`, `SF`, `OF`), o **`IOPL`**, o
///   **`RF`** e o **`ID`**: nenhuma muda o que o kernel faz — o compilador
///   não lê flag que não escreveu, o processo não muda o `IOPL` no anel 3, e
///   o kernel não arma pontos de parada que o `RF` suprimiria —, mas o
///   kernel começa cada chamada no mesmo estado, qualquer que seja o
///   processo, e nenhuma flag dele vaza pela troca voluntária para outro fio.
///
/// O `VM`, o `VIF` e o `VIP` ficam de fora, como no Linux: o `VM` não existe
/// no modo longo, e o `VIF` e o `VIP` só valem com o `CR4.VME` ou o
/// `CR4.PVI`, que o kernel não liga — e o processo não liga nenhum dos três:
/// o `popfq` do anel 3 não os muda.
const FLAGS_APAGADAS_NA_ENTRADA: RFlags = RFlags::CARRY_FLAG
    .union(RFlags::PARITY_FLAG)
    .union(RFlags::AUXILIARY_CARRY_FLAG)
    .union(RFlags::ZERO_FLAG)
    .union(RFlags::SIGN_FLAG)
    .union(RFlags::TRAP_FLAG)
    .union(RFlags::INTERRUPT_FLAG)
    .union(RFlags::DIRECTION_FLAG)
    .union(RFlags::OVERFLOW_FLAG)
    .union(RFlags::IOPL_LOW)
    .union(RFlags::IOPL_HIGH)
    .union(RFlags::NESTED_TASK)
    .union(RFlags::RESUME_FLAG)
    .union(RFlags::ALIGNMENT_CHECK)
    .union(RFlags::ID);

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
    // Trocar é a primeira coisa, antes de empilhar qualquer byte — e para
    // trocar é preciso saber de que núcleo é a pilha de kernel, que é o que o
    // `swapgs` responde: depois dele, `gs:` é a `PorNucleo` deste núcleo.
    swapgs
    mov gs:[8], rsp
    mov rsp, gs:[0]

    // A partir daqui montamos o `QuadroDeUsuario` na pilha de kernel. A ordem
    // é o contrato: cada `push` corresponde a um campo da struct, do endereço
    // mais alto para o mais baixo.
    push qword ptr gs:[8]

    // E o `GS` volta a ser o do processo. A pilha do usuário já está no
    // quadro, e nada mais precisa da estrutura por núcleo até a próxima
    // entrada — ver o cabeçalho deste módulo sobre por que a janela é curta.
    swapgs
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

    // Os argumentos saem do quadro **uma vez**, para locais, e é o que torna
    // a reexecução abaixo possível: `esperar` precisa ser chamada de novo com
    // o que o usuário pediu, e o quadro é reescrito no caminho.
    //
    // # O mesmo contrato, dois mecanismos
    //
    // `esperar` pode dizer "ainda não" e pedir para ser chamada de novo (ver
    // `crate::usuario::esperar`). Aqui isso é um laço, e pode ser: esta
    // função roda sobre uma cadeia de chamadas comum na pilha de kernel do
    // fio, então `estacionar` o guarda sem abandoná-la, e ele volta na
    // instrução seguinte — dentro do kernel.
    //
    // No ARM não pode. Lá a chamada roda dentro de um handler de exceção, e
    // estacionar o fio salva como contexto dele o **quadro da exceção**: ele
    // voltaria em EL0, não aqui. O backend de lá recua o `ELR_EL1` para que
    // o `svc` se repita, o que dá no mesmo de fora e não tem como dar no
    // mesmo por dentro. Ver `arch::aarch64::usuario::atender_chamada`.
    loop {
        // O término pedido por `process.terminate` — ver
        // `crate::fios::terminar_se_pedido`. Aqui, antes de a chamada rodar:
        // é por onde passa o processo que esperava e foi acordado pelo
        // pedido, e ele não repete a chamada para morrer depois dela.
        // Marcado, `estacionar` não volta.
        if crate::fios::terminar_se_pedido() {
            estacionar();
        }

        // SAFETY: o quadro é o desta chamada; `bifurcar` e `executar` o leem e
        // o reescrevem, e é por isso que ele desce até o despacho.
        let resultado = unsafe {
            crate::usuario::despachar(numero, a0, a1, a2, quadro as *mut core::ffi::c_void)
        };

        // A chamada pediu para ser reexecutada? A pergunta é à chamada, e não
        // ao estado do fio: com vários núcleos, o filho pode ter acordado o
        // pai entre a chamada estacionar e esta linha, e o pai pronto parecia
        // uma chamada que acabou — o zero dela chegava ao processo como
        // resposta. Ver `crate::fios::tirar_reexecucao`.
        #[cfg(feature = "modo-teste")]
        crate::fios::pausa_de_teste::talvez_pausar();
        let reexecutar = crate::fios::tirar_reexecucao();
        let ceder = crate::fios::tirar_cessao();
        // E na volta: um término pedido durante a chamada vale antes de o
        // processo ver o resultado dela. Marcado, ele está parado, e cai no
        // `estacionar` abaixo, que não volta.
        crate::fios::terminar_se_pedido();

        // O fio continua de pé, e a chamada não pediu outra volta? Então ela
        // acabou e o valor é dela — depois de dar a vez, se ela pediu. Aqui
        // ceder é seguro, na pilha de kernel do fio; o pedido passa por
        // `fios::pedir_cessao` porque no ARM não é, e a chamada é uma só.
        if !reexecutar && !crate::fios::atual_parado() {
            if ceder {
                crate::arch::ceder_cpu();
            }
            return resultado;
        }

        // Não continua. Ou ele terminou — e aí `estacionar` nunca volta, que
        // é exatamente o desejado: o `sysretq` lá embaixo devolveria o
        // controle a um processo que já não existe — ou está esperando, e
        // volta quando o acordarem (ou na hora, se já o acordaram). Nesse
        // caso o `resultado` acima é descartado e a chamada roda de novo,
        // agora com o que colher. Ou, de pé, a chamada só pediu a vez e a
        // repetição, sem ter mudado nada — ver `fios::ceder_e_reexecutar`:
        // `estacionar` cede uma vez, abre uma janela para as interrupções e
        // volta, e ela roda de novo.
        estacionar();
    }
}

/// Tira o fio atual de circulação até ele poder continuar.
///
/// Só volta quando ele pode. Para um fio encerrado isso nunca acontece, e é
/// por isso que esta função serve aos dois casos: ela é o `descansar` de
/// sempre, com uma saída para quem acorda.
///
/// Aqui estamos numa cadeia de chamadas comum sobre a pilha de kernel do fio
/// — e não dentro de um handler, como no ARM —, então ceder de dentro dela é
/// seguro: o contexto salvo aponta para o meio desta função, e é aqui que o
/// fio volta.
fn estacionar() {
    loop {
        crate::arch::ceder_cpu();
        if !crate::fios::atual_parado() {
            janela_de_interrupcoes();
            return;
        }
        // Se voltamos aqui é porque não havia outro fio pronto. Só uma
        // interrupção pode mudar isso, e aqui elas estão mascaradas: o
        // `syscall` as desliga por causa do `SFMask`. `dormir_parado` liga,
        // dorme e devolve a máscara — ver o cabeçalho dela para por que
        // `esperar_interrupcao` não serve neste ponto.
        crate::arch::dormir_parado();
    }
}

/// Uma janela para as interrupções deste núcleo, antes de a chamada rodar de
/// novo.
///
/// O despacho roda mascarado — o `SFMask` —, e quem volta de [`estacionar`]
/// de pé repete a chamada sem passar pelo anel do usuário. A chamada que só
/// pediu a vez e a repetição (`fios::ceder_e_reexecutar`: a ordem das
/// gravações com outro fio, na troca de imagem de quem é ponta de fluxo)
/// pode repetir muitas vezes, e, sem outro fio pronto a quem ceder, giraria
/// aqui com as interrupções mascaradas: o timer, os dispositivos e os
/// cutucões deste núcleo parados enquanto ela espera — a espera mascarada que
/// [`crate::persistencia::em_ordem`] recusa. Com a janela, cada volta deixa
/// entrar o que estava pendente, como entra para quem espera a ordem num fio
/// do kernel; e a preempção que vier nela troca de fio como em
/// `dormir_parado`, que já liga as interrupções neste mesmo ponto.
///
/// No ARM a repetição volta ao `svc` pelo `eret`, com as IRQs ligadas em
/// EL0, e a janela já existe.
fn janela_de_interrupcoes() {
    // Já ligadas, a janela já está aberta — e o `cli` abaixo as fecharia
    // para quem não as fechou.
    if x86_64::instructions::interrupts::are_enabled() {
        return;
    }
    // SAFETY: ligar as interrupções aqui é o que `dormir_parado` já faz no
    // mesmo ponto do despacho: a pilha é a do fio, o `GS` é o do processo e
    // nenhum handler o olha, e nenhuma trava está na mão. Uma interrupção
    // pendente é entregue depois da instrução seguinte ao `sti` — o `nop` —,
    // e o `cli` devolve a máscara que o despacho espera. Sem `nomem`: o que
    // o handler mudar na memória não fica num registrador de antes.
    unsafe { core::arch::asm!("sti", "nop", "cli", options(nostack)) };
}

/// O `RFLAGS` com que um processo começa, pela primeira entrada ([`entrar`])
/// e pela troca de imagem (`contexto::redirecionar_para`): 0x202 — o bit 1,
/// reservado e sempre ligado, e o `IF`: sem ele o processo seria
/// impreemptável, e o primeiro laço infinito dele travaria a máquina. Nada
/// mais: nem o `DF`, nem o `TF`, nem o `AC`, nem o `NT`, nem as aritméticas
/// de quem rodou antes (o achado 1 do adversário do lote B4 do #448). Como o
/// `start_thread` do Linux.
pub(super) const RFLAGS_DE_UM_PROCESSO_NOVO: u64 = 0x202;

/// Desce para ring 3 e começa a executar em `entrada`. Nunca retorna.
///
/// # Safety
///
/// `entrada` e `pilha` precisam estar mapeados com permissão de usuário, e o
/// fio atual precisa ter pilha de kernel própria — a que a troca de
/// contexto que o pôs neste núcleo informou por [`definir_pilha_de_kernel`]
/// (o fio inicial, que veio do boot, não tem) —: sem ela, a primeira
/// interrupção que chegar com o usuário rodando não terá para onde empilhar.
pub unsafe fn entrar(entrada: u64, pilha: u64) -> ! {
    let sel = gdt::seletores();

    // O `iretq` espera, do topo para baixo: SS, RSP, RFLAGS, CS, RIP. Os
    // seletores levam RPL 3 — é o RPL, e não o DPL do descritor, que define o
    // privilégio com que o código passa a executar.
    let ss = sel.dados_usuario.0 as u64;
    let cs = sel.codigo_usuario.0 as u64;

    // As flags de um processo novo — ver [`RFLAGS_DE_UM_PROCESSO_NOVO`].
    const RFLAGS: u64 = RFLAGS_DE_UM_PROCESSO_NOVO;

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
            // O processo novo não recebe o que o kernel deixou nos
            // registradores — endereços do kernel, temporários do caminho do
            // fio —, como na troca de imagem (`contexto::redirecionar_para`):
            // os quatro seletores de dados nulos e os gerais em zero (o item
            // 5 do adversário do lote B3 do #448). Nenhum programa recebe
            // argumento em registrador na entrada. O quadro do `iretq` já
            // está na pilha, os operandos já foram consumidos, e as flags vêm
            // do quadro. Uma troca no meio leva os seletores nulos com o fio.
            "xor eax, eax",
            "mov ds, eax",
            "mov es, eax",
            "mov fs, eax",
            "mov gs, eax",
            "xor ebx, ebx",
            "xor ecx, ecx",
            "xor edx, edx",
            "xor esi, esi",
            "xor edi, edi",
            "xor ebp, ebp",
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
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
