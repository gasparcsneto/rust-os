//! Porta serial do x86: UART 16550 acessada por portas de I/O.
//!
//! O x86 é a única arquitetura corrente com um espaço de endereçamento
//! separado para I/O, acessado pelas instruções `in`/`out` em vez de por
//! endereços de memória. A UART aqui vive nesse espaço — daí o "PIO"
//! (*programmed I/O*) no nome do backend. No ARM, a mesma função é cumprida
//! por registradores mapeados em memória (ver o driver PL011).

use core::fmt;

use uart_16550::spec::registers::{FifoTriggerLevel, IER};
use uart_16550::{Config, Uart16550, backend::PioBackend};

/// Endereço base da COM1. Fixo no barramento ISA desde o IBM PC original.
pub const COM1_BASE: u16 = 0x3F8;

/// Endereço base da COM2.
pub const COM2_BASE: u16 = 0x2F8;

/// Uma porta serial inicializada.
pub struct Uart(Uart16550<PioBackend>);

impl Uart {
    /// Abre e configura a UART no endereço informado.
    ///
    /// Retorna `None` se não houver dispositivo ali. Isso não é um erro: em
    /// muitas máquinas a COM2 simplesmente não existe, e o kernel precisa
    /// continuar bootando normalmente sem o canal do agente.
    ///
    /// # Safety
    ///
    /// `base` precisa ser o endereço de uma UART 16550 de verdade, e o
    /// chamador precisa garantir acesso exclusivo a ela.
    pub unsafe fn abrir(base: u16) -> Option<Self> {
        // SAFETY: delegada ao chamador pelo contrato acima.
        let mut uart = unsafe { Uart16550::new_port(base) }.ok()?;

        // `Config::DEFAULT` é 8-N-1 com FIFO ativado. O FIFO não é opcional
        // na prática: com ele desligado o modelo de dispositivo do QEMU nunca
        // drena os bytes, e o primeiro envio trava para sempre.
        uart.init(Config::DEFAULT).ok()?;

        let mut porta = Self(uart);
        porta.drenar_recepcao();
        Some(porta)
    }

    /// Passa a interromper o processador quando chegar um byte.
    ///
    /// Só pode ser chamada depois que a IDT e o PIC estiverem de pé: uma
    /// interrupção entregue antes disso seria um triplo fault.
    ///
    /// Reduzimos o gatilho do FIFO para um único caractere. O padrão do 16550
    /// é interromper a cada catorze, o que é ótimo para throughput e péssimo
    /// para latência — uma requisição do agente com menos de catorze bytes
    /// ficaria parada no FIFO até o temporizador de caractere do hardware
    /// desistir. O canal do agente é de baixa vazão e sensível a latência;
    /// uma interrupção por byte é exatamente o negócio certo aqui.
    pub fn habilitar_interrupcao_recepcao(&mut self) {
        let config = Config {
            interrupts: IER::DATA_READY,
            fifo_trigger_level: Some(FifoTriggerLevel::One),
            ..Config::DEFAULT
        };
        // Reaplicar a configuração inteira é o caminho que o driver oferece
        // para mexer no IER. É seguro: a sequência é a mesma da abertura, e a
        // porta está ociosa neste ponto do boot.
        let _ = self.0.init(config);
    }

    /// Reconhece a interrupção de recepção no próprio dispositivo.
    ///
    /// No 16550 não há nada a fazer: a condição de interrupção desaparece
    /// sozinha quando o FIFO de recepção é esvaziado. Existe para que
    /// [`crate::tarefas::entrada`] possa ser neutra de arquitetura — na
    /// PL011 do ARM a mesma chamada escreve num registrador de verdade.
    pub fn fim_de_recepcao(&mut self) {}

    /// Descarta o que já estiver na FIFO de recepção.
    ///
    /// Uma UART recém-inicializada pode ter bytes residuais esperando: lixo de
    /// linha, sobras de um estágio anterior de boot, ou ruído do modelo de
    /// dispositivo do emulador. Se eles sobrevivessem, apareceriam grudados na
    /// frente da primeira requisição do agente e a invalidariam — foi
    /// exatamente esse o sintoma observado: o primeiro pedido após o boot
    /// voltava com erro de JSON malformado, e o segundo funcionava.
    ///
    /// O limite existe porque uma UART com defeito pode reportar dados
    /// disponíveis indefinidamente, e um laço sem saída aqui travaria o boot.
    fn drenar_recepcao(&mut self) {
        for _ in 0..64 {
            if self.read_byte().is_none() {
                break;
            }
        }
    }

    /// Envia os bytes, aguardando espaço no FIFO dentro de um orçamento.
    ///
    /// `send_bytes_exact` faria isto em uma linha, e é o que estava aqui — mas
    /// ele espera sem teto, e um teto é o que separa "o log atrasa" de "o
    /// kernel trava". Basta um cliente conectar no socket e parar de ler: o
    /// buffer do hospedeiro enche, o FIFO deixa de drenar, e a espera não
    /// termina. `send_bytes` devolve quantos couberam, que é o que permite
    /// desistir.
    ///
    /// O que não coube é contado, não sumido — ver
    /// [`crate::serial::perder_saida`]. A mesma correção do PL011, porque o
    /// defeito era o mesmo nas duas arquiteturas.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        let mut restante = bytes;
        let mut orcamento = crate::serial::orcamento_de_saida();

        while !restante.is_empty() {
            let enviados = self.0.send_bytes(restante);
            if enviados > 0 {
                restante = &restante[enviados..];
                crate::serial::saida_fluiu();
                continue;
            }
            if orcamento == 0 {
                crate::serial::perder_saida(restante.len() as u64);
                return;
            }
            orcamento -= 1;
            core::hint::spin_loop();
        }
    }

    /// Lê um byte se houver algum disponível, sem bloquear.
    ///
    /// Não-bloqueante de propósito: o laço do agente precisa poder consultar a
    /// porta e seguir em frente quando não há nada, em vez de congelar o
    /// kernel esperando um cliente que talvez nunca conecte.
    pub fn read_byte(&mut self) -> Option<u8> {
        self.0.try_receive_byte().ok()
    }
}

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}
