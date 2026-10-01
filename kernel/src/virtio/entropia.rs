//! A fonte de entropia: o `virtio-rng`.
//!
//! # Por que o kernel precisa de uma
//!
//! O canal cifrado das portas de agente sorteia uma chave efêmera a cada
//! aperto de mão, e um desafio administrativo sorteia um nonce e outra
//! chave. Uma efêmera previsível é uma sessão que qualquer um decifra
//! depois — e até aqui o kernel não tinha de onde tirar um número que
//! ninguém soubesse: o relógio, o contador de tiques e os endereços são
//! todos adivinháveis por quem conhece a máquina.
//!
//! # Por que virtio, e não uma instrução do processador
//!
//! O x86 tem `RDRAND` e o ARMv8.5 tem `RNDR`, mas nenhum dos dois é
//! garantido: o processador padrão do QEMU para x86 não anuncia o `RDRAND`, e
//! o Cortex-A72 da máquina ARM é anterior ao `RNDR`. O `virtio-rng` existe nas
//! duas, pelo mesmo barramento e pelo mesmo transporte dos outros
//! dispositivos virtio — e do lado de fora ele lê o `/dev/urandom` do
//! hospedeiro, que é exatamente a fonte que se quer.
//!
//! # O protocolo
//!
//! O mais simples do padrão: uma fila só, e o driver entrega a ela buffers
//! que o dispositivo **escreve** com bytes aleatórios. O tamanho usado vem no
//! anel de usados, e pode ser menor que o buffer.
//!
//! Este driver não guarda bytes: cada pedido vai ao dispositivo e espera a
//! resposta. Quem consome muita aleatoriedade é o gerador de
//! [`crate::aleatorio`], que pede 32 bytes daqui de tempos em tempos e
//! produz o resto.

use spin::Mutex;

use super::fila::Fila;
use super::transporte::{FABRICANTE, Transporte, VERSAO_1};
use crate::pci::Dispositivo;

/// O identificador PCI do `virtio-rng` na forma transicional.
const MODELO_TRANSICIONAL: u16 = 0x1005;
/// E na moderna (`0x1040` mais o tipo 4).
const MODELO_MODERNO: u16 = 0x1044;

/// A única fila do dispositivo.
const FILA_DE_PEDIDOS: u16 = 0;

/// O maior pedido de uma vez. O gerador pede 32 bytes; o teto é folga.
pub const MAIOR_PEDIDO: usize = 64;

/// Quantas voltas esperar pela resposta antes de desistir.
///
/// O dispositivo do QEMU responde na hora — a leitura do `/dev/urandom` é
/// síncrona do lado de lá —, e a espera é por consulta ao anel, como o disco
/// faz. O teto existe para um dispositivo que não responde não travar o
/// kernel: sem entropia, quem pediu recusa o que ia fazer, e o resto segue.
const VOLTAS_ESPERANDO: u64 = 50_000_000;

static ENTROPIA: Mutex<Option<Entropia>> = Mutex::new(None);

struct Entropia {
    transporte: Transporte,
    fila: Fila,
    /// O frame onde o dispositivo escreve.
    frame: u64,
    base: *mut u8,
    /// Quantos bytes o dispositivo já entregou. Para o relatório.
    entregues: u64,
}

// SAFETY: o ponteiro é para um frame que este driver aloca e nunca devolve, e
// todo acesso a ele passa pelo `Mutex` que guarda o dono — a mesma razão do
// teclado e da rede.
unsafe impl Send for Entropia {}

impl Entropia {
    fn novo(d: &Dispositivo) -> Result<Entropia, &'static str> {
        let transporte = Transporte::descobrir(d)?;
        transporte.iniciar(VERSAO_1)?;
        // A fila do `virtio-rng` do QEMU tem oito descritores: ver
        // [`Fila::pequena`].
        let fila = Fila::pequena(&transporte, FILA_DE_PEDIDOS)?;
        let Some(frame) = crate::frames::alocar() else {
            transporte.abortar();
            return Err("sem frame para o buffer de entropia");
        };
        crate::pci::habilitar_mestre(d);
        // O dono se registra antes do `DRIVER_OK` — ver
        // [`super::ligar_interrupcao`].
        super::ligar_interrupcao(d, &transporte, super::NOME_ENTROPIA);
        transporte.liberar();
        Ok(Entropia {
            transporte,
            fila,
            frame,
            base: crate::arch::acesso_fisico(frame),
            entregues: 0,
        })
    }

    /// Pede bytes ao dispositivo e espera por eles. Devolve quantos vieram.
    fn ler(&mut self, destino: &mut [u8]) -> usize {
        let pedido = destino.len().min(MAIOR_PEDIDO);
        if pedido == 0
            || self
                .fila
                .submeter(&[(self.frame, pedido as u32, true)])
                .is_err()
        {
            return 0;
        }
        self.fila.notificar(&self.transporte);

        for _ in 0..VOLTAS_ESPERANDO {
            if let Some((_, escritos)) = self.fila.colher() {
                // O dispositivo diz quantos escreveu; nunca mais que o buffer
                // que recebeu, e se disser, não se acredita.
                let n = (escritos as usize).min(pedido);
                // SAFETY: o frame é deste driver, tem quatro mil bytes, e `n`
                // não passa de `MAIOR_PEDIDO`. O dispositivo já terminou de
                // escrever: o descritor voltou pelo anel de usados.
                let origem = unsafe { core::slice::from_raw_parts(self.base, n) };
                destino[..n].copy_from_slice(origem);
                // E o frame não guarda o que foi entregue.
                // SAFETY: a mesma região, agora para zerar.
                unsafe { core::ptr::write_bytes(self.base, 0, n) };
                self.entregues += n as u64;
                return n;
            }
            core::hint::spin_loop();
        }
        // O descritor fica com o dispositivo. Um próximo pedido não o
        // reaproveita enquanto ele não voltar, e se nunca voltar a fila
        // acaba — e a entropia com ela, que é o desfecho certo para um
        // dispositivo que parou.
        0
    }
}

/// Procura o `virtio-rng` no barramento e o põe de pé.
pub fn init() {
    let mut alvo = None;
    crate::pci::com_dispositivos(|d| {
        if alvo.is_none()
            && d.fabricante == FABRICANTE
            && (d.modelo == MODELO_TRANSICIONAL || d.modelo == MODELO_MODERNO)
        {
            alvo = Some(*d);
        }
    });
    let Some(alvo) = alvo else {
        crate::log_warn!(
            "virtio",
            "nenhuma fonte de entropia: as portas de agente vao recusar o aperto"
        );
        return;
    };
    match Entropia::novo(&alvo) {
        Ok(e) => {
            crate::log_info!(
                "virtio",
                "entropia em {:02x}.{} pronta",
                alvo.dispositivo,
                alvo.funcao
            );
            crate::arch::sem_interrupcoes(|| *ENTROPIA.lock() = Some(e));
        }
        Err(motivo) => crate::log_warn!("virtio", "entropia nao inicializada: {}", motivo),
    }
}

/// Enche `destino` com bytes do dispositivo. Verdadeiro se encheu tudo.
///
/// Pede quantas vezes for preciso: o dispositivo pode entregar menos que o
/// pedido. Uma resposta vazia é o fim — o dispositivo parou, ou não há
/// dispositivo —, e o que já veio não é devolvido como se bastasse.
pub fn ler(destino: &mut [u8]) -> bool {
    crate::arch::sem_interrupcoes(|| {
        let mut guarda = ENTROPIA.lock();
        let Some(e) = guarda.as_mut() else {
            return false;
        };
        let mut feito = 0;
        while feito < destino.len() {
            let n = e.ler(&mut destino[feito..]);
            if n == 0 {
                return false;
            }
            feito += n;
        }
        true
    })
}

/// Se há fonte de entropia.
pub fn presente() -> bool {
    crate::arch::sem_interrupcoes(|| ENTROPIA.lock().is_some())
}

/// Quantos bytes o dispositivo entregou desde o boot.
pub fn entregues() -> Option<u64> {
    crate::arch::sem_interrupcoes(|| ENTROPIA.lock().as_ref().map(|e| e.entregues))
}

/// Destrava a fonte à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        ENTROPIA.force_unlock();
    }
}
