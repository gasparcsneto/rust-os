//! Encerramento do QEMU a partir de dentro do kernel.
//!
//! Um kernel normalmente nunca "retorna" — ele roda até a máquina desligar.
//! Isso é um problema para testes automatizados: precisamos que a suíte de
//! testes consiga terminar o processo do QEMU e comunicar sucesso ou falha.
//!
//! O QEMU oferece para isso o dispositivo `isa-debug-exit`. Ao escrever um
//! valor numa porta de I/O configurada, o QEMU encerra imediatamente com o
//! código de saída `(valor << 1) | 1`. É o que torna possível rodar os testes
//! do kernel em CI.

use x86_64::instructions::port::Port;

/// Porta de I/O onde o dispositivo `isa-debug-exit` escuta.
///
/// O valor é arbitrário — nós o escolhemos e passamos ao QEMU via
/// `-device isa-debug-exit,iobase=0xf4,iosize=0x04`. `0xf4` é convencional por
/// estar numa faixa não usada por hardware real.
const EXIT_PORT: u16 = 0xf4;

/// Resultado de uma execução do kernel sob teste.
///
/// Os valores evitam `0` e `1` de propósito: como o QEMU aplica
/// `(valor << 1) | 1`, um código nosso nunca colide com uma saída "natural"
/// do QEMU (por exemplo, um crash do próprio emulador).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ExitCode {
    /// Todos os testes passaram. Vira código de saída 33 no host.
    Success = 0x10,
    /// Algum teste falhou, ou o kernel entrou em pânico. Vira 35 no host.
    Failed = 0x11,
}

/// Encerra o QEMU com o código informado.
pub fn exit(code: ExitCode) -> ! {
    // SAFETY: escrever numa porta de I/O é sempre `unsafe` porque o efeito
    // depende do dispositivo. Aqui o efeito é conhecido e desejado: o QEMU
    // termina o processo. Em hardware real, `0xf4` não está mapeada e a
    // escrita é inofensiva (vira no-op).
    unsafe {
        Port::new(EXIT_PORT).write(code as u32);
    }

    // Inalcançável sob o QEMU com `isa-debug-exit`. Mas o kernel também roda
    // em hardware real, onde a escrita acima não faz nada — então precisamos
    // de um destino válido para o `-> !`. `hlt` em loop é o jeito correto:
    // para a CPU até a próxima interrupção, em vez de queimar energia num
    // busy-loop.
    crate::hlt_loop()
}
