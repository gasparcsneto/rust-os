//! Um programa de usuário mínimo, em assembly.
//!
//! # Por que em assembly, e dentro do próprio binário
//!
//! Porque o que se quer provar aqui é a travessia de privilégio, e nada mais.
//! Um programa compilado à parte exigiria um segundo alvo de build, um
//! carregador de ELF e uma biblioteca mínima — três coisas que podem falhar e
//! que não têm relação com ring 3.
//!
//! Estes poucos bytes fazem exatamente três coisas: uma chamada de sistema que
//! escreve, uma que encerra, e um laço de segurança caso alguma delas volte
//! quando não deveria.
//!
//! # A restrição que o código precisa respeitar
//!
//! Ele é **copiado** para o endereço do processo, então todo acesso precisa ser
//! relativo ao ponteiro de instrução. Um endereço absoluto apontaria de volta
//! para dentro do kernel — onde o processo não tem permissão de tocar, e onde
//! não deveria mesmo.

/// Código de saída que o invasor usaria se a proteção falhasse.
///
/// Se este valor aparecer em `ultima_saida`, o processo conseguiu ler a
/// memória do kernel e seguiu em frente — que é exatamente o que ring 3
/// existe para impedir.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub const CODIGO_DO_INVASOR: i64 = 99;

/// Código de saída que o programa de exemplo devolve.
///
/// Um valor arbitrário e improvável: se ele aparecer do outro lado, veio daqui
/// e de nenhum outro lugar.
pub const CODIGO_DE_SAIDA: i64 = 42;

unsafe extern "C" {
    #[link_name = "programa_exemplo_inicio"]
    static INICIO: u8;
    #[link_name = "programa_exemplo_fim"]
    static FIM: u8;
    #[link_name = "programa_invasor_inicio"]
    static INVASOR_INICIO: u8;
    #[link_name = "programa_invasor_fim"]
    static INVASOR_FIM: u8;
}

/// Os bytes do programa bem-comportado.
pub fn bytes() -> &'static [u8] {
    // SAFETY: ver `entre`.
    unsafe { entre(&raw const INICIO, &raw const FIM) }
}

/// Os bytes de um programa que tenta ler a memória do kernel.
///
/// Existe para provar que a proteção é real. Um ring 3 que se entra mas não
/// protege nada é só uma troca de contexto cara — o que precisa ser
/// demonstrado é que o processo **não alcança** o que não é dele, e que a
/// tentativa mata o processo e não o sistema.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn bytes_invasores() -> &'static [u8] {
    // SAFETY: ver `entre`.
    unsafe { entre(&raw const INVASOR_INICIO, &raw const INVASOR_FIM) }
}

/// # Safety
/// Os dois símbolos precisam delimitar uma região contígua da seção de código,
/// na ordem em que o bloco de assembly os emite.
unsafe fn entre(inicio: *const u8, fim: *const u8) -> &'static [u8] {
    // SAFETY: delegada ao chamador; o linker preserva a ordem dos rótulos.
    unsafe {
        let tamanho = fim.offset_from(inicio) as usize;
        core::slice::from_raw_parts(inicio, tamanho)
    }
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
.section .text.programa_exemplo
.global programa_exemplo_inicio
programa_exemplo_inicio:
    // escrever(mensagem, tamanho)
    //
    // `lea` com deslocamento relativo ao RIP: o endereço da mensagem é
    // calculado a partir de onde o código *está executando*, que é o espaço do
    // usuário — e não de onde ele foi montado, que é dentro do kernel.
    lea     rdi, [rip + .Lmensagem]
    // `offset` é obrigatório: na sintaxe Intel, um símbolo sem ele é um
    // *endereço de memória*, e `mov esi, TAMANHO` carregaria de 13 em vez de
    // carregar 13. Foi exatamente esse o primeiro erro deste programa — falha
    // de página no endereço 0xd, que é o tamanho da mensagem.
    mov     esi, offset TAMANHO_DA_MENSAGEM
    mov     eax, 1
    syscall

    // sair(42)
    mov     eax, 0
    mov     edi, 42
    syscall

    // Inalcançável: `sair` não volta. Se voltar, girar aqui é melhor que
    // executar o que houver na memória seguinte.
.Lprender:
    jmp     .Lprender

.Lmensagem:
    .ascii  "ola do anel 3"
.Lfim_da_mensagem:
.set TAMANHO_DA_MENSAGEM, .Lfim_da_mensagem - .Lmensagem

.global programa_exemplo_fim
programa_exemplo_fim:

// --- o invasor -------------------------------------------------------------
.global programa_invasor_inicio
programa_invasor_inicio:
    // Lê o primeiro endereço do kernel, que vive na metade alta. Um endereço
    // de 64 bits não cabe num imediato comum, daí o `movabs`.
    movabs  rax, 0xffff800000000000
    mov     rax, [rax]

    // Inalcançável: a leitura acima é uma falha de proteção. Se chegarmos
    // aqui, o processo saiu com um código que o teste reconhece como
    // "a protecao nao funcionou".
    mov     eax, 0
    mov     edi, 99
    syscall
.Lprender_invasor:
    jmp     .Lprender_invasor

.global programa_invasor_fim
programa_invasor_fim:
"#
);

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    r#"
.section .text.programa_exemplo
.global programa_exemplo_inicio
programa_exemplo_inicio:
    // escrever(mensagem, tamanho)
    //
    // `adr` calcula o endereço relativo ao PC, pelo mesmo motivo do `lea`
    // relativo ao RIP no x86: o código executa noutro endereço do que foi
    // montado.
    adr     x0, .Lmensagem
    mov     x1, #TAMANHO_DA_MENSAGEM
    mov     x8, #1
    svc     #0

    // sair(42)
    mov     x8, #0
    mov     x0, #42
    svc     #0

    // Inalcançável: `sair` não volta.
.Lprender:
    b       .Lprender

.Lmensagem:
    .ascii  "ola do EL0"
.Lfim_da_mensagem:
.set TAMANHO_DA_MENSAGEM, .Lfim_da_mensagem - .Lmensagem
    .balign 4

.global programa_exemplo_fim
programa_exemplo_fim:

// --- o invasor -------------------------------------------------------------
.global programa_invasor_inicio
programa_invasor_inicio:
    // Lê o começo da imagem do kernel, em 0x4008_0000. `movz` com
    // deslocamento monta a metade alta do endereço num registrador.
    movz    x0, #0x4008, lsl #16
    ldr     x0, [x0]

    // Inalcançável: a leitura acima é uma falha de proteção.
    mov     x8, #0
    mov     x0, #99
    svc     #0
.Lprender_invasor:
    b       .Lprender_invasor

.global programa_invasor_fim
programa_invasor_fim:
"#
);
