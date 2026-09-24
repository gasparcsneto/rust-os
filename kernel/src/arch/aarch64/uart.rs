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

use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::registers::{ReadOnly, ReadWrite, WriteOnly};
use tock_registers::{register_bitfields, register_structs};

/// Endereço da PL011 na máquina `virt` do QEMU.
///
/// Confirmado lendo o device tree que o próprio QEMU gera
/// (`-machine virt,dumpdtb=...`), e não por suposição: o nó aparece como
/// `pl011@9000000`.
pub const PL011_BASE: usize = 0x0900_0000;

register_bitfields! {u32,
    /// Flag Register: o estado das FIFOs e das linhas de controle.
    FR [
        /// FIFO de recepção vazia.
        RXFE OFFSET(4) NUMBITS(1) [],
        /// FIFO de transmissão cheia.
        TXFF OFFSET(5) NUMBITS(1) [],
    ],

    /// Line Control Register: formato do quadro serial.
    LCRH [
        /// Habilita as FIFOs de 16 bytes. Com elas desligadas, cada registro
        /// guarda um byte só.
        FEN  OFFSET(4) NUMBITS(1) [],
        /// Bits por palavra.
        WLEN OFFSET(5) NUMBITS(2) [
            Bits5 = 0b00,
            Bits6 = 0b01,
            Bits7 = 0b10,
            Bits8 = 0b11,
        ],
    ],

    /// Control Register.
    CR [
        /// Liga a UART.
        UARTEN OFFSET(0) NUMBITS(1) [],
        /// Habilita a transmissão.
        TXE    OFFSET(8) NUMBITS(1) [],
        /// Habilita a recepção.
        RXE    OFFSET(9) NUMBITS(1) [],
    ],

    /// Interrupt Mask Set/Clear: quais causas chegam a interromper.
    IMSC [
        /// Recepção: dispara quando a FIFO atinge o nível de gatilho.
        RXIM OFFSET(4) NUMBITS(1) [],
        /// Recepção parada: dispara quando há dados na FIFO e a linha fica
        /// ociosa. É o que entrega a cauda de uma mensagem curta.
        RTIM OFFSET(6) NUMBITS(1) [],
    ],

    /// Interrupt Clear Register: escrever 1 reconhece a causa.
    ICR [
        RXIC OFFSET(4) NUMBITS(1) [],
        RTIC OFFSET(6) NUMBITS(1) [],
        /// Todas as onze causas de uma vez.
        TODAS OFFSET(0) NUMBITS(11) [],
    ],
}

register_structs! {
    /// O bloco de registradores da PL011, conforme o manual do ARM PrimeCell.
    ///
    /// Antes isto era uma lista de constantes de deslocamento e um par de
    /// funções `ler`/`escrever` que recebiam `usize`. Funcionava, mas nada
    /// impedia passar o deslocamento de um registrador e a máscara de outro —
    /// e o compilador não tinha como perceber. A macro confere o layout
    /// inteiro em tempo de compilação: os intervalos precisam fechar, e cada
    /// campo só aceita as máscaras do seu próprio registrador.
    Registradores {
        /// Data Register: ler consome um byte da FIFO, escrever enfileira um.
        (0x00 => dr: ReadWrite<u32>),
        (0x04 => _reservado0),
        (0x18 => fr: ReadOnly<u32, FR::Register>),
        (0x1C => _reservado1),
        /// Divisor de baud rate, parte inteira.
        (0x24 => ibrd: WriteOnly<u32>),
        /// Divisor de baud rate, parte fracionária.
        (0x28 => fbrd: WriteOnly<u32>),
        (0x2C => lcrh: WriteOnly<u32, LCRH::Register>),
        (0x30 => cr: WriteOnly<u32, CR::Register>),
        (0x34 => _reservado2),
        (0x38 => imsc: WriteOnly<u32, IMSC::Register>),
        (0x3C => _reservado3),
        (0x44 => icr: WriteOnly<u32, ICR::Register>),
        (0x48 => @END),
    }
}

/// Uma PL011 inicializada.
pub struct Uart {
    registradores: *const Registradores,
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
            registradores: base as *const Registradores,
        };
        let r = uart.regs();

        // Desligar antes de reconfigurar. Mexer em LCRH com a UART ativa tem
        // comportamento indefinido pelo manual.
        r.cr.set(0);

        // Limpa todas as causas de interrupção pendentes.
        r.icr.write(ICR::TODAS.val(0x7FF));

        // 115200 baud com o clock de 24 MHz que o QEMU usa:
        //   divisor = 24e6 / (16 * 115200) = 13.0208…
        //   parte inteira = 13; fracionária = 0.0208 * 64 ≈ 1
        // O QEMU ignora o baud rate, mas hardware real não — e o objetivo é
        // que este driver funcione numa placa de verdade.
        r.ibrd.set(13);
        r.fbrd.set(1);

        // 8 bits, sem paridade, 1 stop bit, FIFOs ligadas.
        r.lcrh.write(LCRH::WLEN::Bits8 + LCRH::FEN::SET);

        // Nenhuma interrupção por enquanto: quando esta porta é aberta, o
        // kernel ainda não tem tabela de vetores nem GIC, e uma interrupção
        // entregue aqui não teria para onde ir. Elas são ligadas depois, por
        // `habilitar_interrupcao_recepcao`.
        r.imsc.set(0);

        r.cr.write(CR::UARTEN::SET + CR::TXE::SET + CR::RXE::SET);

        let mut porta = uart;
        porta.drenar_recepcao();
        Some(porta)
    }

    /// O bloco de registradores desta porta.
    ///
    /// Seguro porque o ponteiro veio de [`Self::abrir`], cujo contrato exige
    /// que `base` aponte para uma PL011 de verdade, e o bloco de dispositivos
    /// vive enquanto a máquina viver.
    fn regs(&self) -> &Registradores {
        // SAFETY: garantido pelo contrato de `abrir`.
        unsafe { &*self.registradores }
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
        let r = self.regs();
        r.icr.write(ICR::RXIC::SET + ICR::RTIC::SET);
        r.imsc.write(IMSC::RXIM::SET + IMSC::RTIM::SET);
    }

    /// Reconhece a interrupção de recepção no próprio dispositivo.
    ///
    /// Chamado depois de drenar a FIFO. A de recepção some sozinha quando a
    /// FIFO esvazia, mas a de *timeout* fica pendente até ser limpa
    /// explicitamente — sem esta escrita, o GIC reentregaria a mesma
    /// interrupção para sempre.
    pub fn reconhecer_recepcao(&mut self) {
        self.regs().icr.write(ICR::RXIC::SET + ICR::RTIC::SET);
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

    /// Envia os bytes, aguardando espaço na FIFO dentro de um orçamento.
    ///
    /// Espera ativa enquanto a FIFO de transmissão estiver cheia: sem isso,
    /// bytes seriam descartados sob carga, e "o log some de vez em quando" é
    /// uma das falhas mais caras de diagnosticar num kernel.
    ///
    /// Mas a espera tem teto, e é preciso que tenha. Sem ele, um cliente que
    /// conecta no socket e para de ler enche o buffer do hospedeiro, a FIFO
    /// deixa de drenar, e o kernel gira aqui para sempre — com as interrupções
    /// mascaradas, porque `serial::_print` as mascara. O que restava do log
    /// nunca sairia, e nada diria por quê.
    ///
    /// Esgotado o orçamento, o resto é descartado e **contado**. Ver
    /// [`crate::serial::perder_saida`]: um log incompleto que se declara
    /// incompleto é outra coisa que um log que some.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        let r = self.regs();
        let mut orcamento = crate::serial::orcamento_de_saida();

        for (enviados, &byte) in bytes.iter().enumerate() {
            while r.fr.is_set(FR::TXFF) {
                if orcamento == 0 {
                    crate::serial::perder_saida((bytes.len() - enviados) as u64);
                    return;
                }
                orcamento -= 1;
                core::hint::spin_loop();
            }
            r.dr.set(byte as u32);
            crate::serial::saida_fluiu();
        }
    }

    /// Lê um byte se houver algum disponível, sem bloquear.
    pub fn read_byte(&mut self) -> Option<u8> {
        let r = self.regs();
        if r.fr.is_set(FR::RXFE) {
            None
        } else {
            Some(r.dr.get() as u8)
        }
    }
}

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}
