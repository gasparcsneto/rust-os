//! Acesso ao espaço de configuração PCI no x86_64.
//!
//! # Por que duas portas, e não memória
//!
//! O x86 tem dois jeitos de alcançar a configuração PCI. O antigo é um par de
//! portas de I/O: escreve-se o endereço numa e lê-se o dado na outra. O
//! moderno é o ECAM, memória mapeada, mas descobrir onde ele está exige ler a
//! tabela `MCFG` da ACPI — que é outro parser, outro formato, e mais uma coisa
//! que pode faltar.
//!
//! O par de portas existe em toda máquina x86 desde 1993, não precisa ser
//! descoberto e alcança o barramento 0 inteiro, que é onde o QEMU põe tudo que
//! nos interessa. Quando a ACPI entrar no kernel por outro motivo, trocar isto
//! por ECAM é uma implementação nova do mesmo trait.

use pci_types::{ConfigRegionAccess, PciAddress};
use x86_64::instructions::port::Port;

/// Onde se escreve qual registrador se quer.
const PORTA_DE_ENDERECO: u16 = 0xCF8;
/// Onde se lê ou escreve o registrador selecionado.
const PORTA_DE_DADOS: u16 = 0xCFC;

/// O par de portas, empacotado para o `pci_types`.
#[derive(Clone, Copy)]
pub struct Acesso;

/// Monta a palavra de seleção.
///
/// O bit 31 é o que diz "isto é um acesso de configuração"; sem ele o par de
/// portas se comporta como I/O comum. Os dois bits baixos do deslocamento são
/// descartados porque a porta de dados é de 32 bits e sempre devolve a palavra
/// alinhada — quem quer um campo menor recorta depois.
fn selecionar(endereco: PciAddress, deslocamento: u16) -> u32 {
    const HABILITADO: u32 = 1 << 31;

    HABILITADO
        | ((endereco.bus() as u32) << 16)
        | ((endereco.device() as u32) << 11)
        | ((endereco.function() as u32) << 8)
        | ((deslocamento as u32) & 0xFC)
}

impl ConfigRegionAccess for Acesso {
    unsafe fn read(&self, endereco: PciAddress, deslocamento: u16) -> u32 {
        // O par de portas é **estado compartilhado do chipset**: entre escrever
        // o endereço e ler o dado, qualquer outro acesso de configuração
        // sobrescreve a seleção e devolvemos o registrador errado. Um handler
        // que tocasse PCI no meio disto seria suficiente.
        crate::arch::sem_interrupcoes(|| {
            // SAFETY: as duas portas são as de configuração PCI, fixas na
            // arquitetura, e a seleção acabou de ser montada para elas.
            unsafe {
                Port::<u32>::new(PORTA_DE_ENDERECO).write(selecionar(endereco, deslocamento));
                Port::<u32>::new(PORTA_DE_DADOS).read()
            }
        })
    }

    unsafe fn write(&self, endereco: PciAddress, deslocamento: u16, valor: u32) {
        crate::arch::sem_interrupcoes(|| {
            // SAFETY: mesma justificativa da leitura.
            unsafe {
                Port::<u32>::new(PORTA_DE_ENDERECO).write(selecionar(endereco, deslocamento));
                Port::<u32>::new(PORTA_DE_DADOS).write(valor);
            }
        })
    }
}

/// O acesso à configuração PCI desta máquina.
///
/// Nunca falha no x86: as portas são parte da arquitetura.
pub fn acesso() -> Option<Acesso> {
    Some(Acesso)
}

/// A janela de MMIO que o kernel pode distribuir entre os BARs: nenhuma.
///
/// Não porque a máquina não tenha uma, mas porque o BIOS já distribuiu os
/// BARs antes de o kernel existir. Repetir o trabalho exigiria descobrir
/// quais faixas continuam livres — informação que está na ACPI, que este
/// kernel ainda não lê — e o ganho seria zero: o resultado seria outro
/// endereço para o mesmo dispositivo.
///
/// A assimetria com o ARM não é um buraco; é a diferença entre uma plataforma
/// com firmware e uma sem.
pub fn janela_mmio() -> Option<crate::pci::JanelaMmio> {
    None
}

/// Como o barramento é alcançado, para o relatório do agente.
pub const MECANISMO: &str = "port-io-cf8";
