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
//! quinze instruções porque o hardware já fez o resto.
//!
//! # Por que só os registradores preservados
//!
//! Porque `trocar_contexto` é uma chamada de função comum, e a convenção de
//! chamada já diz que os registradores voláteis podem ser destruídos por
//! qualquer chamada. Quem chamou já os salvou, se precisava deles. Salvar os
//! dezesseis seria pagar por uma garantia que o compilador já deu.

use core::arch::global_asm;

/// O estado salvo de um fio que não está executando.
///
/// Um ponteiro de pilha, e nada mais: todo o resto está *na* pilha, empilhado
/// por [`trocar_contexto`].
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
    // desempilhar, e tem de casar com a que `preparar_contexto` monta para um
    // fio novo — as três estão amarradas.
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov [rdi], rsp      // guarda o ponteiro de pilha do fio que sai
    mov rsp, [rsi]      // adota o do fio que entra

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

    // SAFETY: a pilha é nossa e tem espaço de sobra para sete palavras.
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

        // Os seis preservados, na ordem em que `trocar_contexto` os desempilha
        // — ou seja, o inverso da ordem em que ele os empilha.
        empilhar(0); // rbp
        empilhar(0); // rbx
        empilhar(entrada as *const () as u64); // r12
        empilhar(argumento); // r13
        empilhar(0); // r14
        empilhar(0); // r15
    }

    contexto.sp = sp;
    contexto.pilha_de_kernel = topo & !0xF;
}

/// Ponte para [`crate::fios::terminar`] com nome estável para o assembly.
#[unsafe(no_mangle)]
extern "C" fn fios_terminar() -> ! {
    crate::fios::terminar()
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
        }
    }

    if estavam_ligadas {
        x86_64::instructions::interrupts::enable();
    }
}
