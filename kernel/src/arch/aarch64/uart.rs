//! Porta serial do ARM: PL011, mapeada em memória.
//!
//! # A diferença fundamental para o x86
//!
//! O x86 tem um espaço de endereçamento separado para I/O, acessado pelas
//! instruções `in`/`out`. O ARM não tem nada disso: todo periférico é
//! *mapeado em memória*, e conversar com a UART é ler e escrever em endereços
//! comuns.
//!
//! Isso impõe uma disciplina que o compilador não conhece: acessos a
//! registradores de hardware **não podem ser otimizados**. Escrever duas vezes
//! no mesmo endereço não é redundância — pode ser enviar dois bytes. Ler o
//! mesmo endereço duas vezes pode dar valores diferentes. Por isso todo acesso
//! aqui usa [`read_volatile`]/[`write_volatile`], que proíbem o compilador de
//! reordenar, fundir ou eliminar a operação.
//!
//! [`read_volatile`]: core::ptr::read_volatile
//! [`write_volatile`]: core::ptr::write_volatile

use core::fmt;

/// Endereço da PL011 na máquina `virt` do QEMU.
///
/// Confirmado lendo o device tree que o próprio QEMU gera
/// (`-machine virt,dumpdtb=...`), e não por suposição: o nó aparece como
/// `pl011@9000000`.
pub const PL011_BASE: usize = 0x0900_0000;

// Deslocamentos dos registradores, conforme o manual do ARM PrimeCell PL011.
const DR: usize = 0x00; // Data Register
const FR: usize = 0x18; // Flag Register
const IBRD: usize = 0x24; // Integer Baud Rate Divisor
const FBRD: usize = 0x28; // Fractional Baud Rate Divisor
const LCRH: usize = 0x2C; // Line Control Register
const CR: usize = 0x30; // Control Register
const IMSC: usize = 0x38; // Interrupt Mask Set/Clear
const ICR: usize = 0x44; // Interrupt Clear Register

const IMSC_RXIM: u32 = 1 << 4; // interrupção de recepção
const IMSC_RTIM: u32 = 1 << 6; // interrupção de recepção parada (timeout)

const ICR_RXIC: u32 = 1 << 4;
const ICR_RTIC: u32 = 1 << 6;

const FR_RXFE: u32 = 1 << 4; // FIFO de recepção vazia
const FR_TXFF: u32 = 1 << 5; // FIFO de transmissão cheia

const CR_UARTEN: u32 = 1 << 0;
const CR_TXE: u32 = 1 << 8;
const CR_RXE: u32 = 1 << 9;

const LCRH_FEN: u32 = 1 << 4; // habilita FIFOs
const LCRH_WLEN_8: u32 = 0b11 << 5; // palavra de 8 bits

/// Uma PL011 inicializada.
pub struct Uart {
    base: *mut u8,
}

// SAFETY: a struct é só um endereço de MMIO. O acesso concorrente é impedido
// pelo `spin::Mutex` que a envolve em `crate::serial`, não por esta impl —
// que existe apenas para permitir guardá-la num `static`.
unsafe impl Send for Uart {}

impl Uart {
    /// Inicializa a PL011 no endereço informado.
    ///
    /// # Safety
    ///
    /// `base` precisa apontar para os registradores de uma PL011 de verdade,
    /// e o chamador precisa garantir acesso exclusivo a ela.
    pub unsafe fn abrir(base: usize) -> Option<Self> {
        let uart = Self {
            base: base as *mut u8,
        };

        // SAFETY: o chamador garantiu que `base` é uma PL011 válida.
        unsafe {
            // Desligar antes de reconfigurar. Mexer em LCRH com a UART ativa
            // tem comportamento indefinido pelo manual.
            uart.escrever(CR, 0);

            // Limpa todas as interrupções pendentes (11 bits de causas).
            uart.escrever(ICR, 0x7FF);

            // 115200 baud com o clock de 24 MHz que o QEMU usa:
            //   divisor = 24e6 / (16 * 115200) = 13.0208…
            //   parte inteira = 13; fracionária = 0.0208 * 64 ≈ 1
            // O QEMU ignora o baud rate, mas hardware real não — e o objetivo
            // é que este driver funcione numa placa de verdade.
            uart.escrever(IBRD, 13);
            uart.escrever(FBRD, 1);

            // 8 bits, sem paridade, 1 stop bit, FIFOs ligadas.
            uart.escrever(LCRH, LCRH_WLEN_8 | LCRH_FEN);

            // Nenhuma interrupção por enquanto: quando esta porta é aberta,
            // o kernel ainda não tem tabela de vetores nem GIC, e uma
            // interrupção entregue aqui não teria para onde ir. Elas são
            // ligadas depois, por `habilitar_interrupcao_recepcao`.
            uart.escrever(IMSC, 0);

            uart.escrever(CR, CR_UARTEN | CR_TXE | CR_RXE);
        }

        let mut porta = uart;
        porta.drenar_recepcao();
        Some(porta)
    }

    /// # Safety
    /// O deslocamento precisa ser de um registrador válido da PL011.
    unsafe fn escrever(&self, offset: usize, valor: u32) {
        unsafe { core::ptr::write_volatile(self.base.add(offset) as *mut u32, valor) }
    }

    /// # Safety
    /// O deslocamento precisa ser de um registrador válido da PL011.
    unsafe fn ler(&self, offset: usize) -> u32 {
        unsafe { core::ptr::read_volatile(self.base.add(offset) as *const u32) }
    }

    /// Passa a interromper o processador quando chegar um byte.
    ///
    /// Só pode ser chamada depois que a tabela de vetores e o GIC estiverem
    /// de pé.
    ///
    /// Habilitamos **duas** causas, e as duas são necessárias. `RXIM` dispara
    /// quando a FIFO de recepção atinge o nível de gatilho — que por padrão é
    /// a metade dela. Sozinha, ela deixaria uma requisição curta do agente
    /// parada na FIFO indefinidamente, esperando bytes que não vêm. `RTIM` é
    /// o complemento: dispara quando há dados parados na FIFO e a linha fica
    /// ociosa, garantindo que a cauda de qualquer mensagem seja entregue.
    ///
    /// (No modelo de dispositivo do QEMU o nível de gatilho é sempre um
    /// caractere, então `RXIM` já bastaria. Mas o driver é escrito para o
    /// hardware descrito no manual, não para o emulador.)
    pub fn habilitar_interrupcao_recepcao(&mut self) {
        // SAFETY: registradores válidos de uma PL011 já inicializada.
        unsafe {
            self.escrever(ICR, ICR_RXIC | ICR_RTIC);
            self.escrever(IMSC, IMSC_RXIM | IMSC_RTIM);
        }
    }

    /// Reconhece a interrupção de recepção no próprio dispositivo.
    ///
    /// Chamado depois de drenar a FIFO. A de recepção some sozinha quando a
    /// FIFO esvazia, mas a de *timeout* fica pendente até ser limpa
    /// explicitamente — sem esta escrita, o GIC reentregaria a mesma
    /// interrupção para sempre.
    pub fn fim_de_recepcao(&mut self) {
        // SAFETY: registrador válido de uma PL011 já inicializada.
        unsafe { self.escrever(ICR, ICR_RXIC | ICR_RTIC) }
    }

    /// Descarta o que já estiver na FIFO de recepção.
    ///
    /// Bytes residuais sobreviveriam até a primeira requisição do agente e a
    /// invalidariam, grudados na frente do JSON. O limite impede que uma UART
    /// defeituosa, reportando dados para sempre, trave o boot.
    fn drenar_recepcao(&mut self) {
        for _ in 0..64 {
            if self.read_byte().is_none() {
                break;
            }
        }
    }

    /// Envia todos os bytes, aguardando espaço na FIFO conforme necessário.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            // SAFETY: registradores válidos de uma PL011 inicializada.
            unsafe {
                // Espera ativa enquanto a FIFO de transmissão estiver cheia.
                // Sem esta checagem, bytes seriam descartados silenciosamente
                // sob carga — e "o log some de vez em quando" é uma das
                // falhas mais caras de diagnosticar num kernel.
                while self.ler(FR) & FR_TXFF != 0 {
                    core::hint::spin_loop();
                }
                self.escrever(DR, byte as u32);
            }
        }
    }

    /// Lê um byte se houver algum disponível, sem bloquear.
    pub fn read_byte(&mut self) -> Option<u8> {
        // SAFETY: registradores válidos de uma PL011 inicializada.
        unsafe {
            if self.ler(FR) & FR_RXFE != 0 {
                None
            } else {
                Some(self.ler(DR) as u8)
            }
        }
    }
}

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}
