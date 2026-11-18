//! Troca de contexto no x86_64.
//!
//! # O mecanismo
//!
//! No x86, quando uma interrupção chega a código de mesmo privilégio, o
//! processador empilha o quadro de retorno na **pilha que já estava em uso** —
//! a do fio interrompido. Isso tem uma consequência que simplifica tudo:
//! trocar de fio é trocar de pilha, e mais nada.
//!
//! [`trocar_contexto`] empilha os registradores que a convenção de chamada
//! System V manda preservar, guarda o `rsp` resultante no fio que sai, carrega
//! o `rsp` do fio que entra, desempilha os mesmos registradores e retorna.
//!
//! O `ret` é a parte bonita. Ele consome o endereço de retorno da pilha
//! *nova*, então quem volta não é quem chamou: é o fio que entrou, no ponto
//! exato em que ele havia chamado esta mesma função. A troca inteira cabe em
//! trinta e uma instruções — quinze para os registradores preservados e a
//! pilha, dezesseis para os quatro seletores de dados — porque o hardware já
//! fez o resto.
//!
//! # Por que só os registradores preservados
//!
//! Porque `trocar_contexto` é uma chamada de função comum, e a convenção de
//! chamada já diz que os registradores voláteis podem ser destruídos por
//! qualquer chamada. Quem chamou já os salvou, se precisava deles. Salvar os
//! dezesseis seria pagar por uma garantia que o compilador já deu.
//!
//! # E os quatro seletores de dados
//!
//! O `DS`, o `ES`, o `FS` e o `GS` são outra coisa: não são da convenção, e
//! sim do **processo** — o anel 3 os carrega com `mov`, e nada mais os troca:
//! a entrada da `syscall` e a de uma interrupção não os tocam, o `sysretq`
//! também não, e o `iretq` só anula os de privilégio maior que o do anel
//! para onde volta. Sem guardá-los por fio, o seletor que um processo
//! deixava chegava ao processo seguinte no mesmo núcleo — uns 16 bits por
//! troca, entre titulares, por fora do gate (o item 2 do adversário do lote
//! B3 do #448). Então [`trocar_contexto`] os empilha junto com os seis, e o
//! fio que entra recebe os dele: nulos num fio novo, os do pai num filho de
//! `fork`, nulos de novo na troca de imagem. Como o `__switch_to` do Linux.
//! Zerá-los a cada troca também fecharia o canal, mas o processo perderia
//! os próprios numa preempção.
//!
//! Recarregá-los no anel 0 não falha: um seletor que o anel 3 conseguiu
//! carregar aponta para um descritor de DPL 3 — ou é nulo —, que o anel 0
//! também carrega, e a GDT não muda depois do boot (menos na suíte, nos
//! casos do `#NP` e do `#SS`, que marcam ausente o descritor 3, que nenhum
//! processo da suíte carrega). O seletor que o firmware deixava no `FS` e
//! no `GS` do fio do boot era outro caso — ver `gdt::carregar`, que os
//! anula. E carregar o `GS` muda a base **ativa** dele — a de um descritor
//! de DPL 3, zero; o nulo a zera num Intel e no TCG, e num AMD antigo a
//! deixa como estava, que é zero desde o regime do núcleo
//! (`escrever_o_regime_deste_nucleo` zera as duas bases antes do primeiro
//! processo); o `FSGSBASE` está desligado —, e não o `IA32_KERNEL_GS_BASE`,
//! que o `swapgs` da entrada da `syscall` usa: nada no anel 0 olha o `GS`
//! fora daquela janela, que corre com o `IF` limpo e não troca de fio (ver
//! [`super::usuario`]).

use core::arch::global_asm;

use x86_64::instructions::segmentation::{DS, ES, FS, GS, Segment};
use x86_64::structures::gdt::SegmentSelector;

/// O estado salvo de um fio que não está executando.
///
/// Um ponteiro de pilha, e nada mais: todo o resto está *na* pilha, empilhado
/// por [`trocar_contexto`] — os seis registradores preservados e os quatro
/// seletores de dados.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Contexto {
    pub sp: u64,
    /// O topo da pilha de kernel deste fio.
    ///
    /// Diferente de `sp`, que acompanha a execução, este valor é fixo. Ele
    /// existe porque o processador precisa saber para onde empilhar quando uma
    /// interrupção chega com o **usuário** rodando: nesse momento `sp` aponta
    /// para a pilha do processo, e o kernel precisa de uma sua.
    ///
    /// Zero no fio inicial: a pilha dele veio do boot e ele não roda código de
    /// usuário.
    pub pilha_de_kernel: u64,
}

impl Contexto {
    pub const fn vazio() -> Self {
        Self {
            sp: 0,
            pilha_de_kernel: 0,
        }
    }

    pub fn pilha_de_kernel(&self) -> u64 {
        self.pilha_de_kernel
    }
}

unsafe extern "C" {
    /// Troca a pilha corrente pela de outro fio.
    ///
    /// # Safety
    ///
    /// `de` precisa apontar para um [`Contexto`] gravável, e `para` para um
    /// contexto preparado por [`preparar_contexto`] ou salvo por uma chamada
    /// anterior desta função. As interrupções precisam estar mascaradas: uma
    /// troca pela metade — com `rsp` já apontando para a outra pilha mas os
    /// registradores ainda não restaurados — não é um estado do qual um
    /// handler possa voltar.
    pub fn trocar_contexto(de: *mut Contexto, para: *const Contexto);
}

global_asm!(
    r#"
.section .text
.global trocar_contexto
trocar_contexto:
    // System V: rdi = de, rsi = para.
    //
    // Os seis registradores abaixo são os que a convenção manda preservar
    // entre chamadas. A ordem de empilhar tem de ser a inversa da de
    // desempilhar, e tem de casar com a que `preparar_contexto` e
    // `preparar_contexto_de_fork` montam para um fio novo — as três estão
    // amarradas.
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15

    // E os quatro seletores de dados, que são do processo do fio — ver o
    // cabeçalho do módulo. O `rax` é livre: a convenção o deixa a quem chama.
    mov eax, ds
    push rax
    mov eax, es
    push rax
    mov eax, fs
    push rax
    mov eax, gs
    push rax

    mov [rdi], rsp      // guarda o ponteiro de pilha do fio que sai
    mov rsp, [rsi]      // adota o do fio que entra

    // Os do fio que entra, na ordem inversa. Carregar o `GS` muda a base
    // ativa dele, e não o `IA32_KERNEL_GS_BASE` — ver o cabeçalho.
    pop rax
    mov gs, eax
    pop rax
    mov fs, eax
    pop rax
    mov es, eax
    pop rax
    mov ds, eax

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp

    // Consome o endereço de retorno da pilha *nova*. Daqui em diante estamos
    // no outro fio.
    ret
"#
);

global_asm!(
    r#"
.section .text
.global trampolim_de_fio
trampolim_de_fio:
    // Chegamos aqui pelo `ret` de `trocar_contexto`, na primeira vez que um
    // fio novo é escalonado. Os registradores preservados foram carregados do
    // quadro inicial que `preparar_contexto` montou: r12 tem a função de
    // entrada e r13 o argumento.
    //
    // Primeiro, ainda mascarado: avisar que a troca terminou. Quem chamou a
    // troca faria isso ao voltar de `trocar_contexto` — mas não voltamos a
    // ele, voltamos para cá. Sem este aviso, o fio que este núcleo largou
    // ficaria preso a ele, e nenhum outro núcleo o escolheria. A pilha está
    // alinhada em 16 aqui, que é o que o `call` pede.
    call fios_troca_concluida

    // As interrupções foram mascaradas por quem chamou a troca, e ele as
    // religaria ao voltar — só que não voltamos a ele, voltamos para cá. Então
    // quem religa somos nós, e é aqui que este fio passa a ser preemptável.
    sti

    mov rdi, r13
    call r12

    // A função de entrada é declarada como divergente, então chegar aqui é bug
    // de quem a escreveu. Encerrar o fio é o desfecho seguro.
    call fios_terminar
    ud2
"#
);

/// Monta na pilha o quadro inicial que [`trocar_contexto`] vai desempilhar.
///
/// # Safety
///
/// `topo` precisa ser o endereço logo acima de uma pilha mapeada e exclusiva
/// deste fio, com pelo menos algumas centenas de bytes livres.
pub unsafe fn preparar_contexto(
    contexto: &mut Contexto,
    topo: u64,
    entrada: extern "C" fn(u64) -> !,
    argumento: u64,
) {
    unsafe extern "C" {
        fn trampolim_de_fio();
    }

    // A ABI exige que `rsp + 8` seja múltiplo de 16 na entrada de uma função,
    // que é o estado logo após um `call`. Montamos a pilha para reproduzir
    // exatamente isso quando o `ret` de `trocar_contexto` saltar para o
    // trampolim.
    let mut sp = topo & !0xF;

    // SAFETY: a pilha é nossa e tem espaço de sobra para onze palavras.
    unsafe {
        let mut empilhar = |valor: u64| {
            sp -= 8;
            (sp as *mut u64).write(valor);
        };

        // Endereço de retorno: para onde o `ret` de `trocar_contexto` salta.
        //
        // O caminho por ponteiro de função, em vez do `as usize` direto, é o
        // que o compilador pede: um *item* de função não tem endereço até ser
        // coagido a ponteiro, e converter o item direto em inteiro esconde
        // essa coação.
        let trampolim: unsafe extern "C" fn() = trampolim_de_fio;
        empilhar(trampolim as *const () as u64);

        // Os seis preservados, na ordem em que `trocar_contexto` os empilha —
        // ele os desempilha na inversa.
        empilhar(0); // rbp
        empilhar(0); // rbx
        empilhar(entrada as *const () as u64); // r12
        empilhar(argumento); // r13
        empilhar(0); // r14
        empilhar(0); // r15

        // E os quatro seletores de dados nulos — o `DS`, o `ES`, o `FS` e o
        // `GS`: um fio novo não herda os de ninguém.
        for _ in 0..4 {
            empilhar(0);
        }
    }

    contexto.sp = sp;
    contexto.pilha_de_kernel = topo & !0xF;
}

/// Ponte para [`crate::fios::terminar`] com nome estável para o assembly.
#[unsafe(no_mangle)]
extern "C" fn fios_terminar() -> ! {
    crate::fios::terminar()
}

/// Ponte para [`crate::fios::troca_concluida`] com nome estável para o
/// assembly: os dois trampolins — o do fio novo e o do filho de `fork` — a
/// chamam antes de qualquer outra coisa.
#[unsafe(no_mangle)]
extern "C" fn fios_troca_concluida() {
    crate::fios::troca_concluida()
}

/// Cede a CPU ao próximo fio pronto.
///
/// Serve tanto para a cessão voluntária quanto para a preempção: no x86 as
/// duas são a mesma coisa, porque o quadro de interrupção mora na pilha do
/// próprio fio e a troca de pilha o leva junto.
pub fn ceder_cpu() {
    // Mascaramos à mão em vez de usar `sem_interrupcoes` porque a restauração
    // precisa acontecer do outro lado da troca. Quem sai daqui não é quem
    // entrou: o `ret` lá dentro devolve o controle ao *outro* fio, e é o
    // estado dele que vale.
    let estavam_ligadas = x86_64::instructions::interrupts::are_enabled();
    x86_64::instructions::interrupts::disable();

    // SAFETY: as interrupções estão mascaradas, e os ponteiros vêm da tabela
    // do escalonador, que só é modificada com elas mascaradas.
    unsafe {
        if let Some(troca) = crate::fios::selecionar() {
            // O espaço de endereços do fio que entra, antes de qualquer outra
            // coisa. Trocar aqui é seguro em qualquer ordem porque as duas
            // raízes carregam as mesmas entradas de topo do kernel: a pilha
            // que estamos usando agora e a que vamos usar depois seguem
            // mapeadas dos dois lados.
            //
            // Comparar antes de escrever não é microotimização: escrever CR3
            // descarta a TLB inteira, e fazer isso a cada troca entre fios do
            // kernel — que compartilham o espaço — custaria caro à toa.
            if troca.espaco != super::paginacao::espaco_atual() {
                super::paginacao::trocar_espaco(troca.espaco);
            }

            // O processador precisa saber onde empilhar se uma interrupção
            // chegar com o usuário rodando, e esse lugar muda com o fio.
            // Informar **antes** da troca é obrigatório: depois dela já
            // estamos executando o outro fio.
            super::usuario::definir_pilha_de_kernel((*troca.para).pilha_de_kernel);
            trocar_contexto(troca.de, troca.para);

            // Estamos do outro lado: este já é o fio que entrou, voltando do
            // `trocar_contexto` que ele mesmo chamou quando saiu. O contexto
            // do que saiu está escrito, e outro núcleo já pode retomá-lo.
            crate::fios::troca_concluida();
        }
    }

    if estavam_ligadas {
        x86_64::instructions::interrupts::enable();
    }
}

unsafe extern "C" {
    /// A porta de entrada de um filho de `fork`.
    ///
    /// O contexto dele é montado para que a primeira troca de fio salte
    /// direto para este rótulo, com o quadro de usuário pronto logo acima do
    /// ponteiro de pilha. O rótulo avisa que a troca terminou e cai no
    /// caminho que restaura o usuário.
    fn retorno_de_fork();
}

global_asm!(
    r#"
.section .text
.global retorno_de_fork
retorno_de_fork:
    // Como no trampolim de um fio novo: quem chamou a troca não vai voltar
    // para avisar que ela terminou, então avisamos nós. O `rsp` aponta para
    // o quadro de usuário, alinhado em 16 — o `call` não o desalinha, e os
    // registradores que ele pode destruir são todos restaurados do quadro
    // logo em seguida.
    call fios_troca_concluida
    jmp retorno_ao_usuario
"#
);

/// Monta o contexto de um filho de `fork`.
///
/// O filho acorda como se tivesse acabado de fazer a mesma chamada de sistema
/// que o pai, e recebe `0` onde o pai recebe o identificador dele.
///
/// # Como a pilha do filho é montada
///
/// De cima para baixo: uma cópia do quadro do pai, depois o quadro de troca de
/// contexto que [`trocar_contexto`] espera. O endereço de retorno desse quadro
/// aponta para o caminho que restaura o usuário — então a primeira vez que o
/// escalonador escolher este fio, ele cai direto na sequência de `pop` seguida
/// de `sysretq`, com o quadro do pai logo acima do `rsp`.
///
/// É o mesmo mecanismo do fio comum, com outro destino: lá o `ret` salta para
/// o trampolim que chama uma função Rust; aqui salta para o retorno ao anel
/// sem privilégio.
///
/// # Safety
///
/// `quadro` precisa apontar para o [`super::usuario::QuadroDeUsuario`] da
/// chamada de sistema em curso, e `topo` para o topo de uma pilha de kernel
/// recém-criada e ainda não usada.
pub unsafe fn preparar_contexto_de_fork(
    contexto: &mut Contexto,
    topo: u64,
    quadro: *const core::ffi::c_void,
) {
    let quadro = quadro as *const super::usuario::QuadroDeUsuario;
    let mut sp = topo & !0xF;

    // Os seletores de dados do pai, que roda agora a chamada no anel 0 com
    // os dele no processador — a entrada da `syscall` não os toca, e uma
    // troca no meio da chamada os devolve com ele: o filho é uma cópia dele.
    let seletores = seletores_de_dados();

    // SAFETY: `quadro` é o quadro da chamada em curso, e a pilha é nova e tem
    // espaço de sobra para as vinte e sete palavras que empilhamos.
    unsafe {
        let mut empilhar = |valor: u64| {
            sp -= 8;
            (sp as *mut u64).write(valor);
        };

        let q = *quadro;

        // A ordem é a dos `push` do ponto de entrada, para que os `pop` do
        // retorno encontrem cada campo onde esperam.
        empilhar(q.rsp);
        empilhar(0); // rax: o que `fork` devolve ao filho
        empilhar(q.rcx);
        empilhar(q.r11);
        empilhar(q.rdi);
        empilhar(q.rsi);
        empilhar(q.rdx);
        empilhar(q.r8);
        empilhar(q.r9);
        empilhar(q.r10);
        empilhar(q.rbx);
        empilhar(q.rbp);
        empilhar(q.r12);
        empilhar(q.r13);
        empilhar(q.r14);
        empilhar(q.r15);

        // E o quadro que `trocar_contexto` desempilha, com o retorno apontando
        // para a restauração do usuário.
        let retorno: unsafe extern "C" fn() = retorno_de_fork;
        empilhar(retorno as *const () as u64);
        empilhar(0); // rbp
        empilhar(0); // rbx
        empilhar(0); // r12
        empilhar(0); // r13
        empilhar(0); // r14
        empilhar(0); // r15
        for seletor in seletores {
            empilhar(seletor);
        }
    }

    contexto.sp = sp;
    contexto.pilha_de_kernel = topo & !0xF;
}

/// Reescreve o quadro para que o retorno da chamada caia noutro programa.
///
/// É o que `exec` precisa: o processo não volta para onde chamou, volta para o
/// começo da imagem nova. Os demais registradores são zerados, os seletores
/// de dados anulados e as flags as de um processo novo — o programa que entra
/// não tem direito ao estado do que saiu.
///
/// # Safety
///
/// `quadro` precisa apontar para o [`super::usuario::QuadroDeUsuario`] da
/// chamada de sistema em curso.
pub unsafe fn redirecionar_para(quadro: *mut core::ffi::c_void, entrada: u64, pilha: u64) {
    let quadro = quadro as *mut super::usuario::QuadroDeUsuario;

    // SAFETY: delegada ao chamador.
    unsafe {
        let q = &mut *quadro;
        *q = super::usuario::QuadroDeUsuario::default();
        q.rcx = entrada; // `sysretq` retoma a execucao aqui
        q.rsp = pilha;
        // As flags de um processo novo, as do `entrar`, e não as da imagem
        // que saiu: o `R11` é o `RFLAGS` que a `syscall` do `executar`
        // guardou — o `DF`, o `TF`, o `AC`, o `NT`, o `ID` e as aritméticas
        // dela —, e o `sysretq` o devolveria ao começo da imagem nova. Com o
        // `DF` herdado, o `memset` e o `memcpy` dela andariam para trás (o
        // achado 1 do adversário do lote B4 do #448).
        q.r11 = super::usuario::RFLAGS_DE_UM_PROCESSO_NOVO;
    }
    // E os seletores de dados nulos. No processador, e não no quadro: eles
    // não fazem parte dele, e o fio os leva na troca seguinte.
    anular_os_seletores_de_dados();
}

/// Os quatro seletores de dados deste núcleo — o `DS`, o `ES`, o `FS` e o
/// `GS` —, na ordem em que [`trocar_contexto`] os empilha.
fn seletores_de_dados() -> [u64; 4] {
    [
        u64::from(DS::get_reg().0),
        u64::from(ES::get_reg().0),
        u64::from(FS::get_reg().0),
        u64::from(GS::get_reg().0),
    ]
}

/// Carrega o seletor nulo nos quatro seletores de dados deste núcleo — os
/// do fio que roda, que os leva na troca seguinte.
fn anular_os_seletores_de_dados() {
    let nulo = SegmentSelector(0);
    // SAFETY: estamos no anel 0, e o seletor nulo se carrega em qualquer um
    // dos quatro no modo de 64 bits; muda a base ativa do `GS`, e não o
    // `IA32_KERNEL_GS_BASE` — ver o cabeçalho do módulo.
    unsafe {
        DS::set_reg(nulo);
        ES::set_reg(nulo);
        FS::set_reg(nulo);
        GS::set_reg(nulo);
    }
}
