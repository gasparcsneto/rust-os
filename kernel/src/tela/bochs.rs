//! O adaptador de vídeo do QEMU, programado do zero.
//!
//! # Por que um driver só serve as duas arquiteturas
//!
//! Porque é o mesmo dispositivo. A VGA padrão do QEMU no x86 e o
//! `bochs-display` da máquina `virt` do ARM respondem pelos mesmos
//! identificadores de PCI — `1234:1111`, classe 3 — e programam o modo pela
//! mesma interface, a VBE DISPI. Não é coincidência: as duas são a mesma
//! implementação do emulador, exposta em barramentos diferentes.
//!
//! Isso importa mais do que parece. A alternativa para o ARM seria um driver
//! de virtio-gpu — filas, recursos 2D, `set_scanout` —, e o resultado seria
//! vídeo por um caminho de um lado e por outro do outro. Um kernel que já
//! pagou caro por regras escritas em uma arquitetura só não precisa de mais
//! uma.
//!
//! # Por que o x86 não passa por aqui hoje
//!
//! Porque lá o framebuffer chega pronto: o `bootloader` configura o modo por
//! UEFI ou VBE antes de o kernel existir e entrega a geometria em `BootInfo`.
//! Este driver entra quando **ninguém** entregou nada, que é o caso do ARM —
//! onde o boot é o protocolo arm64 cru e não há firmware que configure vídeo.
//!
//! Ele funciona no x86 também, e um dia pode ser o único caminho nas duas. Não
//! é hoje: trocar um framebuffer que funciona por um que ainda não foi usado
//! em lugar nenhum é a ordem errada de fazer as coisas.

use crate::tela::Formato;

/// Quem procuramos no barramento.
///
/// Conferir fabricante e modelo, e não só a classe 3, porque o que vem depois
/// é escrita em registrador: um adaptador de vídeo qualquer responderia pela
/// classe e interpretaria estes deslocamentos como outra coisa.
const FABRICANTE: u16 = 0x1234;
const MODELO: u16 = 0x1111;

/// O BAR onde mora o framebuffer, e o BAR onde moram os registradores.
///
/// Medidos no dispositivo, e não deduzidos: no ARM a enumeração reportou
/// `bar 0 base 0x11000000 tamanho 0x1000000` e `bar 2 base 0x12000000
/// tamanho 0x1000`. Sedimentar os números seria amarrar o driver ao endereço
/// que a máquina escolheu desta vez; sedimentar os **índices** é o contrato do
/// dispositivo.
const BAR_DO_FRAMEBUFFER: u8 = 0;
const BAR_DOS_REGISTRADORES: u8 = 2;

/// Onde os registradores da VBE DISPI começam dentro do BAR 2.
///
/// O BAR inteiro tem 4 KiB e hospeda mais de uma coisa — as portas da VGA
/// legada ficam em outro deslocamento. Só esta faixa interessa.
const DISPI_EM: u64 = 0x500;

/// Os registradores, por índice. Cada um ocupa 16 bits.
mod reg {
    pub const ID: u64 = 0;
    pub const XRES: u64 = 1;
    pub const YRES: u64 = 2;
    pub const BPP: u64 = 3;
    pub const LIGADO: u64 = 4;
    pub const LARGURA_VIRTUAL: u64 = 6;
}

/// O valor que o registrador `ID` devolve, com a versão nos quatro bits baixos.
///
/// É a confirmação de que o que responde ali é mesmo a interface DISPI, e não
/// memória solta ou um BAR que ninguém endereçou. Comparamos só a parte alta:
/// a versão muda entre releases do emulador e não é contrato nosso.
const ID_DISPI: u16 = 0xB0C0;
const MASCARA_DO_ID: u16 = 0xFFF0;

/// Desligar o modo antes de trocá-lo.
const DESLIGADO: u16 = 0x00;
/// Ligar, com o framebuffer linear em vez do banco de 64 KiB da VGA antiga.
const LIGADO_LINEAR: u16 = 0x01 | 0x40;

/// A resolução que pedimos.
///
/// A mesma que o `bootloader` entrega no x86, para que uma pessoa veja a mesma
/// tela nas duas arquiteturas — que é o ponto de ter vídeo no ARM.
///
/// Cabe com folga: 1280 × 720 × 4 bytes são 3,5 MiB dos 16 MiB do BAR.
const LARGURA: u16 = 1280;
const ALTURA: u16 = 720;
/// Trinta e dois bits, e não vinte e quatro, porque um pixel alinhado em
/// quatro bytes é um acesso alinhado. Os oito bits que sobram não são usados.
const BITS_POR_PIXEL: u16 = 32;

/// Procura o adaptador, programa o modo e registra a tela.
///
/// Não devolve erro: não há nada que o chamador possa fazer com um. O que há
/// é o registro — cada saída possível deixa uma linha de log dizendo por onde
/// saiu, porque "a tela não apareceu" sem mais nada é a pior forma de falhar.
pub fn init() {
    let mut achado = None;
    crate::pci::com_dispositivos(|d| {
        if d.fabricante == FABRICANTE && d.modelo == MODELO {
            achado = Some(*d);
        }
    });

    let Some(dispositivo) = achado else {
        crate::log_info!(
            "tela",
            "nenhum adaptador {:04x}:{:04x} no barramento",
            FABRICANTE,
            MODELO
        );
        return;
    };

    let (Some(quadro), Some(registradores)) = (
        dispositivo.regiao(BAR_DO_FRAMEBUFFER),
        dispositivo.regiao(BAR_DOS_REGISTRADORES),
    ) else {
        crate::log_warn!(
            "tela",
            "adaptador em {:02x}.{} sem os BARs {} e {}",
            dispositivo.dispositivo,
            dispositivo.funcao,
            BAR_DO_FRAMEBUFFER,
            BAR_DOS_REGISTRADORES
        );
        return;
    };

    // Os registradores primeiro. Se o modo não for aceito, não há por que
    // gastar um mapeamento de 16 MiB no framebuffer.
    let base_dos_registradores =
        match crate::mmio::mapear(registradores.base, registradores.tamanho) {
            Ok(v) => v + DISPI_EM,
            Err(motivo) => {
                crate::log_warn!("tela", "registradores nao mapeados: {}", motivo);
                return;
            }
        };

    // SAFETY: `mapear` devolveu uma faixa de MMIO deste tamanho, e
    // `DISPI_EM` mais o maior índice usado cabem nos 4 KiB do BAR.
    let identificacao = unsafe { ler(base_dos_registradores, reg::ID) };
    if identificacao & MASCARA_DO_ID != ID_DISPI {
        crate::log_warn!(
            "tela",
            "o que responde no BAR {} nao e a interface DISPI (id {:#06x})",
            BAR_DOS_REGISTRADORES,
            identificacao
        );
        return;
    }

    // A ordem é protocolo, não estilo: a resolução só pode ser trocada com o
    // modo desligado. Programar por cima de um modo ligado é o caminho para
    // uma tela que mostra metade de cada coisa.
    //
    // SAFETY: mesma faixa conferida acima.
    unsafe {
        escrever(base_dos_registradores, reg::LIGADO, DESLIGADO);
        escrever(base_dos_registradores, reg::XRES, LARGURA);
        escrever(base_dos_registradores, reg::YRES, ALTURA);
        escrever(base_dos_registradores, reg::BPP, BITS_POR_PIXEL);
        escrever(base_dos_registradores, reg::LIGADO, LIGADO_LINEAR);
    }

    // E conferir o que o dispositivo **aceitou**, em vez do que pedimos. Ele
    // pode arredondar uma resolução para a que consegue, e desenhar sobre a
    // geometria pedida em vez da concedida escreve fora da tela — sem sintoma
    // local, que é o pior tipo de erro que este kernel tem.
    //
    // SAFETY: mesma faixa conferida acima.
    let (largura, altura, bpp, largura_virtual) = unsafe {
        (
            ler(base_dos_registradores, reg::XRES),
            ler(base_dos_registradores, reg::YRES),
            ler(base_dos_registradores, reg::BPP),
            ler(base_dos_registradores, reg::LARGURA_VIRTUAL),
        )
    };

    if bpp != BITS_POR_PIXEL {
        crate::log_warn!(
            "tela",
            "o adaptador aceitou {} bits por pixel, e nao {}",
            bpp,
            BITS_POR_PIXEL
        );
        return;
    }

    let bytes_por_pixel = u32::from(bpp) / 8;

    // O stride vem do dispositivo, e não da largura. A largura virtual é o
    // que separa uma linha da seguinte na memória, e ela pode ser maior que a
    // visível — é assim que se rola a tela sem copiar nada.
    let stride = u32::from(largura_virtual).max(u32::from(largura));

    // O framebuffer precisa caber no BAR. A conta é do kernel porque o
    // dispositivo não recusa: ele aceitaria uma geometria que transborda e
    // deixaria a escrita do último pixel cair fora da região mapeada.
    let bytes_da_tela = u64::from(stride) * u64::from(altura) * u64::from(bytes_por_pixel);
    if bytes_da_tela > quadro.tamanho {
        crate::log_warn!(
            "tela",
            "a geometria aceita ({}x{}, stride {}) nao cabe nos {} KiB do BAR",
            largura,
            altura,
            stride,
            quadro.tamanho / 1024
        );
        return;
    }

    let base = match crate::mmio::mapear(quadro.base, bytes_da_tela) {
        Ok(v) => v,
        Err(motivo) => {
            crate::log_warn!("tela", "framebuffer nao mapeado: {}", motivo);
            return;
        }
    };

    // SAFETY: a região mapeada tem `bytes_da_tela` bytes, que é exatamente o
    // que esta geometria alcança — a conferência acima é o que garante isso.
    unsafe {
        crate::tela::registrar(
            base,
            u32::from(largura),
            u32::from(altura),
            stride,
            bytes_por_pixel,
            // Trinta e dois bits nesta interface são `0x00RRGGBB` numa
            // palavra little-endian, o que na memória são os bytes azul,
            // verde, vermelho — e um que ninguém usa.
            Formato::Bgr,
        );
    }

    crate::log_info!(
        "tela",
        "adaptador {:04x}:{:04x} programado: {}x{}, stride {}, {} bytes por pixel",
        FABRICANTE,
        MODELO,
        largura,
        altura,
        stride,
        bytes_por_pixel
    );
}

/// Lê um registrador de 16 bits da faixa DISPI.
///
/// # Safety
///
/// `base` precisa apontar para o começo da faixa DISPI de um BAR mapeado como
/// memória de dispositivo, e `indice` precisa ser um dos registradores dela.
unsafe fn ler(base: u64, indice: u64) -> u16 {
    let ponteiro = (base + indice * 2) as *const u16;
    // `read_volatile` porque ler um registrador é um efeito, e não uma
    // consulta que o compilador possa remover ou reaproveitar.
    u16::from_le(unsafe { core::ptr::read_volatile(ponteiro) })
}

/// Escreve um registrador de 16 bits da faixa DISPI.
///
/// # Safety
///
/// As mesmas de [`ler`], e o valor precisa ser válido para o registrador: uma
/// resolução que o adaptador não suporta é recusada por ele, mas um índice
/// errado escreve em outro registrador sem que nada reclame.
unsafe fn escrever(base: u64, indice: u64, valor: u16) {
    let ponteiro = (base + indice * 2) as *mut u16;
    unsafe { core::ptr::write_volatile(ponteiro, valor.to_le()) };
}
