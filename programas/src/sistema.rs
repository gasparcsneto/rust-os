//! As chamadas de sistema, uma função por chamada.
//!
//! # A convenção
//!
//! A mesma que o kernel documenta em [`protocolo::usuario::numero`]: no x86,
//! `syscall` com o número em `rax` e os argumentos em `rdi`, `rsi` e `rdx`;
//! no ARM, `svc #0` com o número em `x8` e os argumentos em `x0` a `x2`. O
//! retorno volta em `rax` ou `x0`, negativo quando é erro.
//!
//! No x86, `syscall` escreve o endereço de retorno em `rcx` e os flags em
//! `r11` — é o próprio processador, e não o kernel —, e os dois são
//! declarados como perdidos. O resto o kernel devolve como encontrou.
//!
//! # Por que as funções devolvem `i64`, e não `Result`
//!
//! Porque o número é o que o kernel disse, e os erros são os de
//! [`protocolo::usuario::erro`]: quem chama compara com eles. Um `Result`
//! aqui seria uma segunda tradução da mesma tabela, e uma a mais para
//! divergir.

use protocolo::usuario::numero;

pub use protocolo::usuario::erro;
pub use protocolo::usuario::padrao::{ERRO as DIAGNOSTICO, SAIDA};

/// Faz a chamada `numero` com três argumentos.
///
/// # Safety
///
/// Os argumentos precisam ser os que a chamada espera: um ponteiro que o
/// kernel vá ler ou escrever precisa apontar para memória deste processo, do
/// tamanho dito. O kernel confere e recusa o que não for — mas uma escrita
/// que ele aceite num endereço errado deste processo é deste processo.
#[inline(always)]
unsafe fn chamar(numero: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let retorno: i64;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: a convenção do cabeçalho; o contrato é de quem chama.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") numero as i64 => retorno,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: a convenção do cabeçalho; o contrato é de quem chama.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") numero,
            inlateout("x0") a0 as i64 => retorno,
            in("x1") a1,
            in("x2") a2,
            options(nostack),
        );
    }
    retorno
}

/// Encerra o processo com `codigo`.
pub fn sair(codigo: i64) -> ! {
    // SAFETY: `sair` não recebe ponteiro.
    unsafe { chamar(numero::SAIR, codigo as u64, 0, 0) };
    // O kernel não volta de `sair`. Se voltasse, girar aqui é melhor que
    // executar o que viesse depois de uma função que não retorna.
    loop {
        core::hint::spin_loop();
    }
}

/// Escreve `bytes` em `descritor`. Devolve quantos foram aceitos, ou um
/// erro.
pub fn escrever(descritor: u64, bytes: &[u8]) -> i64 {
    // SAFETY: a fatia é deste processo e tem o tamanho dito.
    unsafe {
        chamar(
            numero::ESCREVER,
            descritor,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
        )
    }
}

/// O identificador do fio que executa este processo.
pub fn id() -> i64 {
    // SAFETY: `id` não recebe ponteiro.
    unsafe { chamar(numero::ID, 0, 0, 0) }
}

/// Devolve a CPU ao escalonador.
pub fn ceder() {
    // SAFETY: `ceder` não recebe ponteiro.
    unsafe { chamar(numero::CEDER, 0, 0, 0) };
}

/// Pede ao kernel memória nova, zerada, gravável e não executável, em
/// `[endereco, endereco + tamanho)`. Zero, ou um erro — e, no erro, nada
/// foi mapeado.
pub fn mapear(endereco: u64, tamanho: u64) -> i64 {
    // SAFETY: o kernel não escreve na faixa por este pedido — ele a cria. Uma
    // faixa já em uso é recusada com `JA_MAPEADO`.
    unsafe { chamar(numero::MAPEAR, endereco, tamanho, 0) }
}

/// Abre o arquivo do `caminho`. Um descritor, ou um erro.
pub fn abrir(caminho: &str) -> i64 {
    // SAFETY: a fatia é deste processo e tem o tamanho dito.
    unsafe {
        chamar(
            numero::ABRIR,
            caminho.as_ptr() as u64,
            caminho.len() as u64,
            0,
        )
    }
}

/// Lê de `descritor` para `destino`. Quantos bytes vieram, ou um erro.
pub fn ler(descritor: u64, destino: &mut [u8]) -> i64 {
    // SAFETY: a fatia é deste processo, gravável, e tem o tamanho dito.
    unsafe {
        chamar(
            numero::LER,
            descritor,
            destino.as_mut_ptr() as u64,
            destino.len() as u64,
        )
    }
}

/// Fecha `descritor`.
pub fn fechar(descritor: u64) -> i64 {
    // SAFETY: `fechar` não recebe ponteiro.
    unsafe { chamar(numero::FECHAR, descritor, 0, 0) }
}

/// `ler` com o ponteiro cru, sem uma fatia no meio.
///
/// # Safety
///
/// Nenhuma do lado do Rust — o kernel confere a faixa e recusa o que não
/// for do processo, ou não for gravável. Existe para os programas que
/// conferem essa recusa, e marcada `unsafe` porque uma faixa que o kernel
/// aceite é escrita, e o compilador não sabe.
pub unsafe fn ler_cru(descritor: u64, ponteiro: u64, tamanho: u64) -> i64 {
    // SAFETY: o contrato é de quem chama.
    unsafe { chamar(numero::LER, descritor, ponteiro, tamanho) }
}

/// Duplica o processo. Zero no filho; o identificador do filho no pai; ou
/// um erro.
pub fn bifurcar() -> i64 {
    // SAFETY: `bifurcar` não recebe ponteiro.
    unsafe { chamar(numero::BIFURCAR, 0, 0, 0) }
}

/// Espera o filho `id` — ou qualquer um, com zero — e devolve o
/// identificador do colhido e o código de saída dele, quando ele saiu; o
/// código vem `None` quando ele morreu por uma falha.
pub fn esperar(id: u64) -> Result<(i64, Option<i64>), i64> {
    let mut desfecho = [0i64; 2];
    // SAFETY: os dezesseis bytes são deste processo e graváveis.
    let colhido = unsafe { esperar_cru(id, desfecho.as_mut_ptr() as u64) };
    if colhido < 0 {
        return Err(colhido);
    }
    // A segunda palavra diz se o código vale — ver
    // `protocolo::usuario::numero::ESPERAR`.
    Ok((colhido, (desfecho[1] != 0).then_some(desfecho[0])))
}

/// `esperar` com o ponteiro cru.
///
/// # Safety
///
/// Como [`ler_cru`]: uma faixa que o kernel aceite é escrita.
pub unsafe fn esperar_cru(id: u64, ponteiro: u64) -> i64 {
    // SAFETY: o contrato é de quem chama.
    unsafe { chamar(numero::ESPERAR, id, ponteiro, 0) }
}
