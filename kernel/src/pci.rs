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

use pci_types::{Bar, CommandRegister, ConfigRegionAccess, EndpointHeader, PciAddress, PciHeader};
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

/// Uma faixa de endereços em que o kernel pode pôr os BARs dos dispositivos.
///
/// Os dois endereços não são redundância. O que se escreve num BAR é o
/// endereço **do lado do barramento**; o que a CPU desreferencia é o endereço
/// do lado dela. Numa placa em que a ponte traduz, os dois diferem, e confundi
/// -los produz um driver que escreve o BAR certo e lê o endereço errado.
#[derive(Clone, Copy, Debug)]
pub struct JanelaMmio {
    /// Primeiro endereço da janela, como o barramento o enxerga.
    pub barramento: u64,
    /// O mesmo endereço, como a CPU o enxerga.
    pub cpu: u64,
    /// Quanto a janela ocupa.
    pub tamanho: u64,
}

impl JanelaMmio {
    /// Traduz um endereço do lado do barramento para o lado da CPU, se ele
    /// cair dentro desta janela.
    ///
    /// `None` para um endereço de fora não é um caso de erro: é o que
    /// acontece com um BAR que outra janela encaminha — a de 64 bits, por
    /// exemplo. Quem pergunta decide o que fazer com isso.
    pub fn na_cpu(&self, no_barramento: u64) -> Option<u64> {
        let dentro = no_barramento.checked_sub(self.barramento)?;
        (dentro < self.tamanho).then_some(self.cpu + dentro)
    }
}

/// Distribui uma [`JanelaMmio`] entre os BARs, um dispositivo por vez.
///
/// # Por que um alocador de incremento
///
/// Porque a lista de clientes é conhecida e fechada: tudo é atribuído numa
/// passada no boot, e nada nunca é devolvido — um dispositivo PCI não some do
/// barramento nesta fase. Um alocador com liberação seria código sem chamador,
/// e código sem chamador é código sem teste.
struct Distribuidor {
    janela: JanelaMmio,
    /// Primeiro endereço ainda livre, do lado do barramento.
    proximo: u64,
}

impl Distribuidor {
    fn novo(janela: JanelaMmio) -> Self {
        Self {
            janela,
            proximo: janela.barramento,
        }
    }

    /// Reserva `tamanho` bytes, ou `None` se a janela acabou.
    fn reservar(&mut self, tamanho: u64) -> Option<u64> {
        // Um BAR não guarda um endereço qualquer: os bits baixos dele são
        // fixos em zero, tantos quantos o tamanho da região exige. Escrever um
        // endereço desalinhado não dá erro — grava outro endereço, e o
        // dispositivo passa a responder num lugar que ninguém procura.
        if tamanho == 0 || !tamanho.is_power_of_two() {
            return None;
        }

        let inicio = self.proximo.checked_next_multiple_of(tamanho)?;
        let fim = inicio.checked_add(tamanho)?;
        if fim > self.janela.barramento.checked_add(self.janela.tamanho)? {
            return None;
        }

        self.proximo = fim;
        Some(inicio)
    }
}

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
    /// Onde a primeira região de memória do dispositivo está, **do ponto de
    /// vista da CPU**, e quanto ela ocupa.
    ///
    /// Do ponto de vista da CPU porque é isso que um driver desreferencia. O
    /// BAR guarda o endereço do lado do barramento, e os dois só coincidem
    /// quando a ponte não traduz nada — ver [`JanelaMmio::na_cpu`].
    ///
    /// `None` quando o dispositivo não tem região nenhuma, ou quando ninguém
    /// lhe atribuiu endereço. O segundo caso não é defeito do dispositivo:
    /// alguém precisa **distribuir** as janelas do barramento, e esse alguém é
    /// o firmware ou o kernel.
    pub memoria: Option<(u64, u64)>,
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

/// Lê a identidade de um dispositivo, ou `None` se não há ninguém ali.
///
/// Só a identidade: onde as regiões dele estão é assunto de [`preparar`], que
/// roda depois e pode **mudar** a resposta.
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
        memoria: None,
    })
}

/// Dá endereço às regiões de memória do dispositivo e liga o decodificador.
///
/// # O que "preparar" quer dizer
///
/// Um dispositivo recém-visto no barramento não responde a nada. Ele declara,
/// em cada BAR, quanto espaço quer; alguém precisa dizer **onde**, e então
/// permitir que ele decodifique esse espaço. Num PC o BIOS já fez as duas
/// coisas antes de o kernel existir. No ARM, onde carregamos sem firmware
/// nenhum, não há quem tenha feito — e é por isso que `distribuidor` é
/// opcional em vez de obrigatório.
///
/// Preencher `memoria` é a última coisa, e de propósito: o valor só é
/// verdadeiro depois da atribuição.
fn preparar(
    acesso: &impl ConfigRegionAccess,
    achado: &mut Dispositivo,
    distribuidor: &mut Option<Distribuidor>,
) {
    let endereco = PciAddress::new(0, achado.barramento, achado.dispositivo, achado.funcao);

    // Só dispositivos comuns têm BARs no lugar que nos interessa; pontes usam
    // o mesmo espaço para descrever a faixa de barramentos que encaminham.
    let Some(mut ponta) = EndpointHeader::from_header(PciHeader::new(endereco), acesso) else {
        return;
    };

    if let Some(distribuidor) = distribuidor.as_mut() {
        atribuir_bars(acesso, &mut ponta, distribuidor);
    }

    // Onde a primeira região de memória ficou. Lida depois da atribuição, e
    // percorrendo os seis slots porque um BAR de 64 bits ocupa dois: parar no
    // primeiro slot vazio daria `None` num dispositivo que tem região.
    let mut slot = 0u8;
    while slot < 6 {
        let regiao = match ponta.bar(slot, acesso) {
            Some(Bar::Memory32 { address, size, .. }) if address != 0 => {
                Some((address as u64, size as u64))
            }
            Some(Bar::Memory64 { address, size, .. }) if address != 0 => Some((address, size)),
            Some(Bar::Memory64 { .. }) => {
                slot += 2;
                continue;
            }
            _ => {
                slot += 1;
                continue;
            }
        };

        if let Some((no_barramento, tamanho)) = regiao {
            // Onde houve firmware não há janela declarada, e não há tradução a
            // aplicar: num PC o endereço do barramento é o da CPU. Onde há
            // janela, é ela que sabe a diferença.
            let na_cpu = match distribuidor.as_ref() {
                Some(d) => d.janela.na_cpu(no_barramento),
                None => Some(no_barramento),
            };

            match na_cpu {
                Some(na_cpu) => achado.memoria = Some((na_cpu, tamanho)),
                None => crate::log_warn!(
                    "pci",
                    "BAR {} em {:#x} fica fora da janela conhecida",
                    slot,
                    no_barramento
                ),
            }
            break;
        }
    }

    // Com endereço atribuído, o decodificador pode ser ligado. Fazemos isso
    // mesmo no x86, onde o BIOS já ligou: é uma escrita idempotente, e em
    // troca a invariante fica igual nas duas arquiteturas — se `memoria` é
    // `Some`, aquela faixa responde.
    //
    // `BUS_MASTER` fica de fora. Ele autoriza o dispositivo a escrever na
    // memória por conta própria, e isso é poder que só faz sentido dar a quem
    // o kernel decidiu usar — ver [`habilitar_mestre`].
    if achado.memoria.is_some() {
        ponta.update_command(acesso, |atual| atual | CommandRegister::MEMORY_ENABLE);
    }
}

/// Percorre os BARs vazios e dá um endereço a cada um.
fn atribuir_bars(
    acesso: &impl ConfigRegionAccess,
    ponta: &mut EndpointHeader,
    distribuidor: &mut Distribuidor,
) {
    // Medir um BAR é destrutivo: escreve-se todos os uns nele e lê-se de volta
    // a máscara de bits fixos, que diz o tamanho. Entre a escrita e a
    // restauração o BAR contém lixo, e um dispositivo que estivesse
    // decodificando responderia, por um instante, por uma faixa enorme —
    // possivelmente por cima de outro. Desligar o decodificador antes é o que
    // torna a medição segura, e religá-lo é trabalho de quem chamou.
    ponta.update_command(acesso, |atual| {
        atual & !(CommandRegister::MEMORY_ENABLE | CommandRegister::IO_ENABLE)
    });

    let mut slot = 0u8;
    while slot < 6 {
        let (tamanho, largura_em_slots) = match ponta.bar(slot, acesso) {
            Some(Bar::Memory32 {
                address: 0, size, ..
            }) => (size as u64, 1),
            Some(Bar::Memory64 {
                address: 0, size, ..
            }) => (size, 2),

            // Já tem endereço: não é nosso para mexer. Só precisamos saber
            // quantos slots ele ocupa para não ler a metade alta como se
            // fosse um BAR próprio.
            Some(Bar::Memory64 { .. }) => {
                slot += 2;
                continue;
            }

            // Um BAR de I/O fica sem endereço de propósito. Este kernel fala
            // com os dispositivos virtio pelo caminho moderno, que é memória
            // mapeada; a janela de I/O do ARM existe, mas usá-la significaria
            // um segundo mecanismo de acesso para não ganhar nada.
            _ => {
                slot += 1;
                continue;
            }
        };

        match distribuidor.reservar(tamanho) {
            Some(no_barramento) => {
                // SAFETY: o endereço saiu da janela que o device tree declarou
                // para este barramento, está alinhado ao tamanho do BAR, e o
                // slot é o primeiro do par quando o BAR é de 64 bits.
                let r = unsafe { ponta.write_bar(slot, acesso, no_barramento as usize) };
                if let Err(motivo) = r {
                    crate::log_warn!("pci", "BAR {} nao aceitou endereco: {:?}", slot, motivo);
                }
            }
            None => crate::log_warn!(
                "pci",
                "sem espaco na janela para {} KiB do BAR {}",
                tamanho / 1024,
                slot
            ),
        }

        slot += largura_em_slots;
    }
}

/// Varre o barramento e guarda o que encontrar.
pub fn init() {
    let Some(acesso) = crate::arch::pci::acesso() else {
        crate::log_warn!("pci", "sem acesso a configuracao: barramento nao enumerado");
        return;
    };

    let mut encontrados = 0usize;
    let mut guardados = 0usize;

    // Um distribuidor só existe onde não houve firmware para distribuir. Ele
    // é criado uma vez para toda a varredura, e não por dispositivo, porque é
    // exatamente o que impede dois dispositivos de receberem a mesma faixa.
    let mut distribuidor = crate::arch::pci::janela_mmio().map(Distribuidor::novo);

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

                    let Some(mut achado) = achado else { continue };
                    preparar(&acesso, &mut achado, &mut distribuidor);
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
