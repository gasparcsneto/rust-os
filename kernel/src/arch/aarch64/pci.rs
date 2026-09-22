//! Acesso ao espaço de configuração PCI no aarch64.
//!
//! # ECAM, e por que o endereço vem do device tree
//!
//! No ARM não existe o par de portas do x86: a configuração PCI é memória
//! mapeada, no arranjo que a especificação chama de ECAM. O endereço de um
//! registrador é uma conta simples sobre barramento, dispositivo, função e
//! deslocamento — mas a **base** é escolha da placa.
//!
//! Fixá-la no código seria contradizer a razão de este kernel ler o device
//! tree desde o boot. Ver [`super::fdt::encontrar_barramento_pci`].

use core::sync::atomic::{AtomicU64, Ordering};

use pci_types::{ConfigRegionAccess, PciAddress};

use crate::pci::JanelaMmio;

/// Base do ECAM, ou zero enquanto não foi descoberta.
static BASE: AtomicU64 = AtomicU64::new(0);
/// Quanto o ECAM ocupa, para conferir que um acesso cabe nele.
static TAMANHO: AtomicU64 = AtomicU64::new(0);

/// A janela de MMIO que o barramento encaminha, como o barramento a vê, como
/// a CPU a vê, e quanto ela ocupa. Tamanho zero enquanto não foi descoberta.
static JANELA_NO_BARRAMENTO: AtomicU64 = AtomicU64::new(0);
static JANELA_NA_CPU: AtomicU64 = AtomicU64::new(0);
static JANELA_TAMANHO: AtomicU64 = AtomicU64::new(0);

/// Guarda onde o device tree disse que a configuração PCI está.
pub fn registrar(base: u64, tamanho: u64) {
    BASE.store(base, Ordering::Release);
    TAMANHO.store(tamanho, Ordering::Release);
}

/// Guarda a janela de MMIO que o kernel pode distribuir entre os BARs.
///
/// Separada de [`registrar`] porque as duas coisas podem faltar
/// independentemente: uma placa pode descrever o ECAM e não encaminhar
/// memória de 32 bits, e nesse caso a enumeração ainda funciona — só não há
/// onde pôr os BARs.
pub fn registrar_janela(no_barramento: u64, na_cpu: u64, tamanho: u64) {
    JANELA_NO_BARRAMENTO.store(no_barramento, Ordering::Release);
    JANELA_NA_CPU.store(na_cpu, Ordering::Release);
    JANELA_TAMANHO.store(tamanho, Ordering::Release);
}

/// A janela de MMIO desta placa, se houver uma.
///
/// # Por que o ARM precisa disto e o x86 não
///
/// No x86 o BIOS roda antes do kernel e já distribuiu os BARs. Aqui o QEMU
/// carrega o ELF e salta para ele: não houve firmware nenhum, e todo
/// dispositivo do barramento está com os BARs zerados. Distribuí-los é
/// trabalho do kernel, e a janela é a faixa de endereços em que ele pode
/// fazê-lo sem colidir com a RAM ou com os periféricos da placa.
pub fn janela_mmio() -> Option<JanelaMmio> {
    let tamanho = JANELA_TAMANHO.load(Ordering::Acquire);
    (tamanho > 0).then(|| JanelaMmio {
        barramento: JANELA_NO_BARRAMENTO.load(Ordering::Acquire),
        cpu: JANELA_NA_CPU.load(Ordering::Acquire),
        tamanho,
    })
}

/// O ECAM desta máquina.
#[derive(Clone, Copy)]
pub struct Acesso {
    base: u64,
    tamanho: u64,
}

/// Deslocamento de um registrador dentro do ECAM.
///
/// O formato é fixo: doze bits de deslocamento dentro da função, três de
/// função, cinco de dispositivo e oito de barramento. É o mesmo cálculo em
/// qualquer implementação de ECAM — é isso que o "generic" do `compatible`
/// quer dizer.
fn deslocamento_no_ecam(endereco: PciAddress, deslocamento: u16) -> u64 {
    ((endereco.bus() as u64) << 20)
        | ((endereco.device() as u64) << 15)
        | ((endereco.function() as u64) << 12)
        | (deslocamento as u64 & 0xFFF)
}

impl ConfigRegionAccess for Acesso {
    unsafe fn read(&self, endereco: PciAddress, deslocamento: u16) -> u32 {
        let dentro = deslocamento_no_ecam(endereco, deslocamento);
        if dentro + 4 > self.tamanho {
            // Fora da janela que a placa declarou. Devolver "sem dispositivo"
            // é o mesmo que o hardware devolve para um endereço vazio, e é
            // melhor que ler memória que não é nossa.
            return u32::MAX;
        }

        // SAFETY: a base veio do device tree, a janela foi conferida acima, e
        // a região está mapeada como memória de dispositivo — leitura de 32
        // bits alinhada é exatamente o que o ECAM aceita.
        unsafe { core::ptr::read_volatile((self.base + dentro) as *const u32) }
    }

    unsafe fn write(&self, endereco: PciAddress, deslocamento: u16, valor: u32) {
        let dentro = deslocamento_no_ecam(endereco, deslocamento);
        if dentro + 4 > self.tamanho {
            return;
        }
        // SAFETY: mesma justificativa da leitura.
        unsafe { core::ptr::write_volatile((self.base + dentro) as *mut u32, valor) };
    }
}

/// O acesso à configuração PCI desta máquina, se o device tree a descreveu.
pub fn acesso() -> Option<Acesso> {
    let base = BASE.load(Ordering::Acquire);
    let tamanho = TAMANHO.load(Ordering::Acquire);
    (base != 0 && tamanho >= 4).then_some(Acesso { base, tamanho })
}

/// Como o barramento é alcançado, para o relatório do agente.
pub const MECANISMO: &str = "ecam";
