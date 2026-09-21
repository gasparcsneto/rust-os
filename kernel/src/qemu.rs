//! Encerramento do emulador a partir de dentro do kernel.
//!
//! Um kernel normalmente nunca "retorna" — ele roda até a máquina desligar.
//! Isso é um problema para testes automatizados: precisamos que a suíte
//! consiga terminar o emulador e comunicar sucesso ou falha ao CI.
//!
//! O mecanismo é completamente diferente em cada arquitetura (porta de I/O no
//! x86, semihosting no ARM), então a implementação vive em [`crate::arch`] e
//! este módulo é só o vocabulário comum.

/// Como a execução terminou.
//
// Só tem consumidor quando a feature `modo-teste` está ligada; num build
// normal o kernel nunca termina de propósito. Marcamos em vez de apagar
// porque o mecanismo é parte do contrato com o CI.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resultado {
    Sucesso,
    Falha,
}

/// Encerra o emulador. Não retorna.
///
/// Em hardware real não há emulador para encerrar; nesse caso a implementação
/// de cada arquitetura simplesmente para a CPU.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn encerrar(resultado: Resultado) -> ! {
    crate::arch::encerrar_emulador(resultado)
}
