//! Enumeração do barramento PCI.
//!
//! # O que muda a partir daqui
//!
//! Até a fase 1 todo dispositivo que o kernel tocava tinha endereço conhecido
//! de antemão: a UART, o timer, o controlador de interrupções. São peças da
//! placa, e a placa é sempre a mesma.
//!
//! Disco e rede não funcionam assim. Eles aparecem num barramento que precisa
//! ser **descoberto** — quantos há, de que tipo, e onde cada um respondeu. É o
//! primeiro momento em que o kernel pergunta ao hardware o que existe em vez
//! de já saber.
//!
//! # Como a descoberta funciona
//!
//! Cada função possível tem um endereço `(barramento, dispositivo, função)`.
//! Lê-se o identificador do fabricante nesse endereço: `0xFFFF` quer dizer
//! "ninguém aqui" — é o que o barramento devolve quando ninguém responde, e
//! por isso serve de sinal de ausência sem precisar de uma lista prévia.
//!
//! Um dispositivo pode ter até oito funções, mas só vale procurá-las se a
//! função zero disser que existem. Ignorar isso faria o kernel ler oito vezes
//! mais endereços vazios em toda máquina.
//!
//! # Por que `pci_types`
//!
//! O critério deste projeto está escrito no `Cargo.toml`: montar palavras de
//! configuração a partir de deslocamentos lidos de um manual vai para
//! biblioteca. Os deslocamentos do cabeçalho PCI são exatamente isso — e errar
//! um não gera erro, gera um dispositivo descrito errado.
//!
//! O que fica aqui é o que é **decisão nossa**: como varrer, o que guardar, e
//! como reportar.

use core::sync::atomic::{AtomicUsize, Ordering};

use pci_types::{ConfigRegionAccess, PciAddress, PciHeader};
use spin::Mutex;

/// Quantos dispositivos cabem no inventário.
///
/// A máquina `virt` do QEMU expõe menos de uma dezena; o teto existe para que
/// a varredura tenha custo previsível e nunca dependa do heap — ela roda no
/// boot, e um boot que falha por falta de memória é o pior lugar para falhar.
pub const MAX_DISPOSITIVOS: usize = 32;

/// Barramentos varridos.
///
/// Um só, por ora. A máquina `virt` e o QEMU no x86 põem tudo no barramento 0,
/// e varrer os 256 possíveis custaria 32 mil leituras de configuração num boot
/// para encontrar nada. Pontes PCI-PCI, que é o que torna os outros
/// alcançáveis, são assunto de quando houver uma.
const BARRAMENTOS: u8 = 1;

/// Um dispositivo encontrado no barramento.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dispositivo {
    pub barramento: u8,
    pub dispositivo: u8,
    pub funcao: u8,
    pub fabricante: u16,
    pub modelo: u16,
    /// Classe, subclasse e interface: o que o dispositivo **faz**, num
    /// vocabulário padronizado, independente de quem o fabricou.
    pub classe: u8,
    pub subclasse: u8,
    pub interface: u8,
    pub revisao: u8,
}

impl Dispositivo {
    /// Uma descrição legível da classe, para o relatório do agente.
    ///
    /// Só os casos que este kernel vai encontrar ou usar. O resto vira
    /// `"outro"` de propósito: uma tabela com as centenas de classes do padrão
    /// seria decoração que envelhece.
    pub fn o_que_faz(&self) -> &'static str {
        match (self.classe, self.subclasse) {
            (0x01, 0x00) => "disco-scsi",
            (0x01, 0x01) => "disco-ide",
            (0x01, 0x06) => "disco-sata",
            (0x01, 0x08) => "disco-nvme",
            (0x02, _) => "rede",
            (0x03, _) => "video",
            (0x06, 0x00) => "ponte-hospedeira",
            (0x06, 0x04) => "ponte-pci",
            (0x0C, 0x03) => "usb",
            _ => "outro",
        }
    }
}

/// O inventário, preenchido uma vez no boot.
///
/// Guardado em vez de revarrido a cada pergunta porque uma varredura é dezenas
/// de acessos ao chipset, e o canal do agente pode perguntar quantas vezes
/// quiser. O barramento não muda sozinho: não há hot-plug nesta fase.
static INVENTARIO: Mutex<[Option<Dispositivo>; MAX_DISPOSITIVOS]> =
    Mutex::new([None; MAX_DISPOSITIVOS]);

/// Quantos dispositivos a varredura encontrou, incluindo os que não couberam.
static ENCONTRADOS: AtomicUsize = AtomicUsize::new(0);

/// Lê um dispositivo, ou `None` se não há ninguém naquele endereço.
fn ler(acesso: &impl ConfigRegionAccess, endereco: PciAddress) -> Option<Dispositivo> {
    let cabecalho = PciHeader::new(endereco);
    let (fabricante, modelo) = cabecalho.id(acesso);

    // `0xFFFF` é o que o barramento devolve quando ninguém responde: as linhas
    // ficam em nível alto e a leitura vira todos os bits em um.
    if fabricante == 0xFFFF {
        return None;
    }

    let (revisao, classe, subclasse, interface) = cabecalho.revision_and_class(acesso);
    Some(Dispositivo {
        barramento: endereco.bus(),
        dispositivo: endereco.device(),
        funcao: endereco.function(),
        fabricante,
        modelo,
        classe,
        subclasse,
        interface,
        revisao,
    })
}

/// Varre o barramento e guarda o que encontrar.
pub fn init() {
    let Some(acesso) = crate::arch::pci::acesso() else {
        crate::log_warn!("pci", "sem acesso a configuracao: barramento nao enumerado");
        return;
    };

    let mut encontrados = 0usize;
    let mut guardados = 0usize;

    crate::arch::sem_interrupcoes(|| {
        let mut inventario = INVENTARIO.lock();

        for barramento in 0..BARRAMENTOS {
            for dispositivo in 0..32u8 {
                let zero = PciAddress::new(0, barramento, dispositivo, 0);
                let Some(primeira) = ler(&acesso, zero) else {
                    continue;
                };

                // Só procuramos as outras sete funções se a função zero disser
                // que elas existem. Sem essa checagem, a varredura custaria
                // oito vezes mais para encontrar exatamente o mesmo.
                let multiplas = PciHeader::new(zero).has_multiple_functions(acesso);
                let ultima = if multiplas { 8 } else { 1 };

                for funcao in 0..ultima {
                    let achado = if funcao == 0 {
                        Some(primeira)
                    } else {
                        ler(&acesso, PciAddress::new(0, barramento, dispositivo, funcao))
                    };

                    let Some(achado) = achado else { continue };
                    encontrados += 1;
                    if guardados < MAX_DISPOSITIVOS {
                        inventario[guardados] = Some(achado);
                        guardados += 1;
                    }
                }
            }
        }
    });

    ENCONTRADOS.store(encontrados, Ordering::Release);

    if encontrados > guardados {
        crate::log_warn!(
            "pci",
            "{} dispositivos encontrados, {} guardados: inventario cheio",
            encontrados,
            guardados
        );
    } else {
        crate::log_info!(
            "pci",
            "{} dispositivos no barramento ({})",
            encontrados,
            crate::arch::pci::MECANISMO
        );
    }
}

/// Quantos dispositivos a varredura encontrou.
pub fn total() -> usize {
    ENCONTRADOS.load(Ordering::Acquire)
}

/// Chama `f` para cada dispositivo guardado.
pub fn com_dispositivos<F: FnMut(&Dispositivo)>(mut f: F) {
    crate::arch::sem_interrupcoes(|| {
        for achado in INVENTARIO.lock().iter().flatten() {
            f(achado);
        }
    });
}
