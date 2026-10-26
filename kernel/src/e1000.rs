//! A placa de rede Intel 82574L: a da máquina física de referência.
//!
//! # Por que esta placa, e só ela
//!
//! A virtio só existe dentro de uma máquina virtual. Uma máquina física
//! precisa de uma placa de verdade, e uma basta: a 82574L é uma placa PCIe
//! de um gigabit que se compra avulsa e se põe em qualquer PC, a Intel
//! publica o manual dela inteiro, e o QEMU a emula (`-device e1000e`) — a
//! suíte e a bancada exercitam o mesmo driver que roda no metal. As placas
//! da mesma família que o chipset traz na placa-mãe (I217, I219) falam com
//! o PHY por outro caminho, e não estão aqui: ver "A máquina de referência"
//! em `docs/OPERACAO.md`.
//!
//! # Dois anéis
//!
//! Como a virtio, uma fila para cada sentido, mas na forma da Intel: um anel
//! de descritores na memória do kernel, com uma cabeça que a placa avança e
//! uma cauda que o driver escreve. Na recepção, o driver entrega à placa os
//! descritores até a cauda, cada um apontando para um buffer vazio; ela
//! enche um, marca nele que acabou (`DD`) e passa ao seguinte. Na
//! transmissão, o driver escreve o descritor do quadro e avança a cauda; a
//! placa lê o quadro e marca o descritor.
//!
//! O driver confia só no que está na memória dele — o `DD` e o tamanho do
//! descritor —, e nunca na cabeça que a placa publica: um tamanho maior que
//! o buffer é cortado no buffer, e um quadro com erro ou partido não sobe.
//!
//! # Por consulta, como o NVMe
//!
//! Sem interrupção: as da placa ficam mascaradas, e a do PCI, desligada. O
//! fio da rede acorda a cada tique do timer e colhe o que houver. É menos
//! vazão que a virtio, que acorda pela interrupção, e é um caminho a menos
//! para uma placa de verdade, com vetores e linhas de outro jeito, dar
//! errado.
//!
//! # O cabo
//!
//! A diferença que a virtio não tem: uma placa física tem enlace, e ele cai
//! — o cabo sai, o switch reinicia. Sem enlace a placa não transmite, e um
//! quadro entregue a ela ficaria no anel até o enlace voltar: o driver nem
//! o entrega, e diz por quê (`sem_enlace`, no `net.info`). A pilha
//! retransmite o que importa quando o cabo volta.
//!
//! Uma transmissão que não se confirma no prazo não desliga a placa de vez,
//! como desliga a virtio: o reinício para o DMA dela — o buffer de
//! transmissão volta a ser do driver — e reprograma os anéis. Ela é
//! desligada quando um reinício não volta, ou quando a transmissão falha de
//! novo depois de três reinícios seguidos sem um quadro confirmado no meio.
//!
//! # O que este driver não faz
//!
//! Interrupção, MSI-X, soma de verificação na placa, segmentação, VLAN,
//! quadros jumbo, várias filas, Wake-on-LAN, a gerência de energia do PHY e
//! a EEPROM: o endereço vem do registro que a placa carrega dela no
//! reinício.

use core::sync::atomic::{Ordering, fence};

use crate::bloco::Prazo;
use crate::rede::placa::{Perdas, PlacaDeRede, TAMANHO_DO_MAC};
use crate::trava::Mutex;

/// O fabricante e o modelo da 82574L.
const INTEL: u16 = 0x8086;
const MODELO_82574L: u16 = 0x10D3;

/// O nome do driver, para o relatório.
const DRIVER: &str = "e1000e";

/// O maior quadro que este driver transporta: o Ethernet clássico, sem o
/// CRC, que a placa acrescenta na saída e tira na entrada.
pub const MAIOR_QUADRO: usize = 1514;

/// Quantos descritores tem o anel de recepção. A placa usa no máximo um a
/// menos — a cauda igual à cabeça é o anel vazio —, e trinta e um cobrem a
/// rajada que a pilha anuncia (`rede::placa::BUFFERS_DE_RECEPCAO`).
pub const NA_RECEPCAO: usize = 32;

/// Quantos descritores tem o anel de transmissão: oito, o menor anel que a
/// placa aceita (128 bytes). O driver usa um de cada vez — o buffer de
/// transmissão é um só, como na virtio.
const NA_TRANSMISSAO: usize = 8;

/// Quanto mede um descritor, nos dois anéis.
const DESCRITOR: usize = 16;

/// Onde o anel de transmissão começa, no frame dos anéis: depois do de
/// recepção, alinhado.
const ANEL_DE_TRANSMISSAO: usize = 2048;

/// Quanto mede cada buffer de recepção: o tamanho que `RCTL.BSIZE` zero
/// pede. Dois por frame.
const BUFFER: usize = 2048;

const PAGINA: usize = crate::arch::TAMANHO_PAGINA as usize;
const BUFFERS_POR_FRAME: usize = PAGINA / BUFFER;
const FRAMES_DE_RECEPCAO: usize = NA_RECEPCAO / BUFFERS_POR_FRAME;

/// Os frames do driver: o dos anéis, os de recepção e o de transmissão.
const FRAMES: usize = 1 + FRAMES_DE_RECEPCAO + 1;

const _: () = assert!(
    NA_RECEPCAO * DESCRITOR <= ANEL_DE_TRANSMISSAO
        && ANEL_DE_TRANSMISSAO + NA_TRANSMISSAO * DESCRITOR <= PAGINA
        && (NA_RECEPCAO * DESCRITOR).is_multiple_of(128)
        && (NA_TRANSMISSAO * DESCRITOR).is_multiple_of(128)
        && NA_RECEPCAO.is_multiple_of(BUFFERS_POR_FRAME)
        && MAIOR_QUADRO <= BUFFER,
    "os aneis ou os buffers da placa Intel nao cabem onde o driver os poe"
);

/// Os registradores — os deslocamentos são os do manual da 82574L.
mod registro {
    pub const CTRL: usize = 0x0000;
    pub const STATUS: usize = 0x0008;
    pub const EECD: usize = 0x0010;
    pub const ICR: usize = 0x00C0;
    pub const IMC: usize = 0x00D8;
    pub const RCTL: usize = 0x0100;
    pub const TCTL: usize = 0x0400;
    pub const TIPG: usize = 0x0410;
    pub const RDBAL: usize = 0x2800;
    pub const RDBAH: usize = 0x2804;
    pub const RDLEN: usize = 0x2808;
    pub const RDH: usize = 0x2810;
    pub const RDT: usize = 0x2818;
    pub const RDTR: usize = 0x2820;
    pub const TDBAL: usize = 0x3800;
    pub const TDBAH: usize = 0x3804;
    pub const TDLEN: usize = 0x3808;
    pub const TDH: usize = 0x3810;
    pub const TDT: usize = 0x3818;
    pub const TXDCTL: usize = 0x3828;
    pub const MTA: usize = 0x5200;
    pub const RAL0: usize = 0x5400;
    pub const RAH0: usize = 0x5404;
    /// Até onde o driver lê e escreve: o fim do `RAH0`.
    pub const FIM: usize = RAH0 + 4;
}

/// Os bits que o driver usa.
const CTRL_DESLIGAR_MESTRE: u32 = 1 << 2;
const CTRL_VELOCIDADE_AUTOMATICA: u32 = 1 << 5;
const CTRL_ENLACE: u32 = 1 << 6;
const CTRL_FORCAR_VELOCIDADE: u32 = 1 << 11;
const CTRL_FORCAR_DUPLEX: u32 = 1 << 12;
const CTRL_REINICIO: u32 = 1 << 26;
const CTRL_VLAN: u32 = 1 << 30;
const CTRL_REINICIO_DO_PHY: u32 = 1 << 31;
const STATUS_ENLACE: u32 = 1 << 1;
const STATUS_MESTRE_LIGADO: u32 = 1 << 19;
/// A carga do que a placa lê da EEPROM no reinício — o endereço entre as
/// coisas — terminou.
const EECD_LEITURA_FEITA: u32 = 1 << 9;
/// Recebe, aceita os quadros de difusão — o ARP e o DHCP chegam assim — e
/// tira o CRC. O buffer de 2048 é o `BSIZE` zero.
const RCTL_LIGADA: u32 = (1 << 1) | (1 << 15) | (1 << 26);
/// Transmite, completa os quadros curtos até o mínimo do Ethernet, e o
/// limiar de colisões e a distância de colisão do manual para full duplex.
const TCTL_LIGADA: u32 = (1 << 1) | (1 << 3) | (0x0F << 4) | (0x3F << 12);
/// O intervalo entre quadros do manual, para cobre.
const TIPG_PADRAO: u32 = 8 | (8 << 10) | (6 << 20);
/// A escrita de volta de cada descritor transmitido, assim que ele acaba, e
/// a contagem dos descritores pendentes: o que o manual pede para a 82574L.
const TXDCTL_LIMIAR: u32 = 0x3F << 16;
const TXDCTL_UM_POR_VEZ: u32 = (1 << 16) | (1 << 24) | (1 << 22);
const RAH_VALIDO: u32 = 1 << 31;

/// Nos descritores.
const DD: u8 = 1 << 0;
const RX_FIM_DO_QUADRO: u8 = 1 << 1;
/// Os erros de quadro de um descritor de recepção: CRC, símbolo, sequência,
/// extensão de portadora e o de recepção. Os outros dois bits do campo são
/// de soma de verificação, que o driver não pede.
const RX_ERROS_DE_QUADRO: u8 = 0x97;
const TX_FIM_DO_QUADRO: u8 = 1 << 0;
const TX_CRC: u8 = 1 << 1;
const TX_RELATAR: u8 = 1 << 3;

/// Quanto o driver espera por uma transmissão: o quadro maior, a dez
/// megabits, leva pouco mais de um milissegundo; um switch que pede pausa
/// pode segurar a placa por mais. Dois segundos separam o ocupado do parado.
const ESPERA_DA_TRANSMISSAO_MS: u64 = 2_000;
/// Quanto o reinício leva: a placa recarrega a EEPROM — o manual dá dez
/// milissegundos.
const ESPERA_DO_REINICIO_MS: u64 = 100;
/// Quanto o DMA leva para parar antes do reinício.
const ESPERA_DO_MESTRE_MS: u64 = 80;
/// As voltas no lugar dos prazos, cedo no boot — antes da régua do civil,
/// que é quando a placa liga.
const VOLTAS_DE_TRANSMISSAO: u64 = 400_000_000;
const VOLTAS_DE_REGISTRADOR: u64 = 1_000_000;
/// Quantos reinícios seguidos, sem uma transmissão confirmada no meio,
/// antes de desligar a placa.
const REINICIOS_SEGUIDOS: u32 = 3;

/// A placa da máquina, se houver uma.
static PLACA: Mutex<Option<Placa>> = Mutex::new(None);

/// Uma 82574L pronta para uso.
pub struct Placa {
    /// Onde os registradores estão, no espaço virtual.
    registradores: u64,
    /// O frame dos anéis, e por onde o kernel o enxerga.
    aneis: u64,
    base_dos_aneis: *mut u8,
    /// Os frames dos buffers de recepção, dois buffers por frame.
    frames_de_recepcao: [u64; FRAMES_DE_RECEPCAO],
    bases_de_recepcao: [*mut u8; FRAMES_DE_RECEPCAO],
    /// O frame do buffer de transmissão.
    frame_de_transmissao: u64,
    base_de_transmissao: *mut u8,
    /// O próximo descritor que o driver colhe, e o próximo que ele usa para
    /// transmitir.
    proxima_recepcao: usize,
    proxima_transmissao: usize,
    mac: [u8; TAMANHO_DO_MAC],
    transmitidos: u64,
    recebidos: u64,
    perdas: Perdas,
    /// A maior espera por uma confirmação de transmissão, em voltas.
    maior_espera: u32,
    /// Os reinícios desde a última transmissão confirmada.
    reinicios_seguidos: u32,
    /// O enlace da última transmissão, para dizer no log quando ele muda.
    enlace_visto: bool,
    /// Se a placa ainda pode ser usada: falso depois de um reinício que não
    /// voltou, ou de reinícios demais.
    vivo: bool,
}

// SAFETY: os ponteiros são para frames de propriedade exclusiva desta placa,
// alocados na construção e nunca compartilhados, e para os registradores
// dela.
unsafe impl Send for Placa {}

/// Os frames do driver, zerados, ou nenhum.
fn alocar_frames() -> Option<[u64; FRAMES]> {
    let mut frames = [0u64; FRAMES];
    let mut quantos = 0;
    while quantos < FRAMES {
        let Some(frame) = crate::frames::alocar() else {
            for frame in &frames[..quantos] {
                crate::frames::liberar(*frame);
            }
            return None;
        };
        // SAFETY: o frame acabou de vir do alocador, é deste driver, e
        // `acesso_fisico` o alcança inteiro.
        unsafe { core::ptr::write_bytes(crate::arch::acesso_fisico(frame), 0, PAGINA) };
        frames[quantos] = frame;
        quantos += 1;
    }
    Some(frames)
}

/// Espera `ms` milissegundos sem tocar a placa.
fn esperar(ms: u64, voltas: u64) {
    let prazo = Prazo::em(ms, voltas);
    let mut volta = 0;
    while !prazo.vencido(volta) {
        volta += 1;
        core::hint::spin_loop();
    }
}

impl Placa {
    /// Uma placa sobre `registradores` e os frames, ainda sem programar.
    fn com(registradores: u64, frames: [u64; FRAMES]) -> Placa {
        let mut frames_de_recepcao = [0u64; FRAMES_DE_RECEPCAO];
        frames_de_recepcao.copy_from_slice(&frames[1..1 + FRAMES_DE_RECEPCAO]);
        let mut bases_de_recepcao = [core::ptr::null_mut(); FRAMES_DE_RECEPCAO];
        for (base, frame) in bases_de_recepcao.iter_mut().zip(&frames_de_recepcao) {
            *base = crate::arch::acesso_fisico(*frame);
        }
        let frame_de_transmissao = frames[FRAMES - 1];
        Placa {
            registradores,
            aneis: frames[0],
            base_dos_aneis: crate::arch::acesso_fisico(frames[0]),
            frames_de_recepcao,
            bases_de_recepcao,
            frame_de_transmissao,
            base_de_transmissao: crate::arch::acesso_fisico(frame_de_transmissao),
            proxima_recepcao: 0,
            proxima_transmissao: 0,
            mac: [0; TAMANHO_DO_MAC],
            transmitidos: 0,
            recebidos: 0,
            perdas: Perdas::default(),
            maior_espera: 0,
            reinicios_seguidos: 0,
            enlace_visto: false,
            vivo: true,
        }
    }

    fn ler(&self, r: usize) -> u32 {
        // SAFETY: `r` é um dos deslocamentos de [`registro`], todos abaixo
        // de `registro::FIM`, que cabe no BAR conferido em `ligar` — ou na
        // memória da placa de mentira.
        unsafe { core::ptr::read_volatile((self.registradores + r as u64) as *const u32) }
    }

    fn escrever(&self, r: usize, valor: u32) {
        // SAFETY: como em `ler`.
        unsafe { core::ptr::write_volatile((self.registradores + r as u64) as *mut u32, valor) }
    }

    /// O descritor `i` do anel que começa em `anel`.
    fn descritor(&self, anel: usize, i: usize) -> *mut u8 {
        // SAFETY: os dois anéis cabem no frame dos anéis pela asserção de
        // compilação, e `i` é sempre menor que o tamanho do anel — os dois
        // índices andam módulo ele.
        unsafe { self.base_dos_aneis.add(anel + i * DESCRITOR) }
    }

    /// Onde o buffer de recepção `i` está: no barramento e para o kernel.
    fn buffer_de_recepcao(&self, i: usize) -> (u64, *mut u8) {
        let frame = i / BUFFERS_POR_FRAME;
        let dentro = (i % BUFFERS_POR_FRAME) * BUFFER;
        // SAFETY: `dentro + BUFFER` cabe no frame.
        let base = unsafe { self.bases_de_recepcao[frame].add(dentro) };
        (self.frames_de_recepcao[frame] + dentro as u64, base)
    }

    /// Liga a placa encontrada no barramento.
    fn ligar(d: &crate::pci::Dispositivo) -> Result<Placa, &'static str> {
        let regiao = d.regiao(0).ok_or("o BAR 0 da placa nao tem endereco")?;
        if regiao.tamanho < registro::FIM as u64 {
            return Err("o BAR 0 da placa e pequeno demais para os registradores");
        }
        let registradores = crate::mmio::mapear(regiao.base, regiao.tamanho)?;
        let frames = alocar_frames().ok_or("sem frames para os aneis e os buffers")?;
        let mut placa = Placa::com(registradores, frames);
        // Parada e reiniciada antes da mestria de barramento: o firmware
        // pode tê-la deixado lendo anéis dele, numa memória que agora é do
        // kernel.
        placa.parar()?;
        placa.mac = placa.ler_mac()?;
        crate::pci::habilitar_mestre_por_consulta(d);
        placa.programar();
        placa.enlace_visto = placa.ler(registro::STATUS) & STATUS_ENLACE != 0;
        Ok(placa)
    }

    /// Para o DMA e reinicia a placa: depois disto ela não lê nem escreve
    /// memória nenhuma até [`Placa::programar`].
    fn parar(&mut self) -> Result<(), &'static str> {
        self.escrever(registro::IMC, u32::MAX);
        // O DMA primeiro: um reinício no meio de uma transação do PCIe pode
        // prender o barramento. Uma placa que não para no prazo é
        // reiniciada assim mesmo — é o que o reinício existe para resolver.
        self.escrever(
            registro::CTRL,
            self.ler(registro::CTRL) | CTRL_DESLIGAR_MESTRE,
        );
        let prazo = Prazo::em(ESPERA_DO_MESTRE_MS, VOLTAS_DE_REGISTRADOR);
        let mut volta = 0;
        while self.ler(registro::STATUS) & STATUS_MESTRE_LIGADO != 0 {
            if prazo.vencido(volta) {
                crate::log_warn!(
                    "e1000",
                    "a placa nao parou o DMA em {}; reiniciada assim mesmo",
                    prazo
                );
                break;
            }
            volta += 1;
            core::hint::spin_loop();
        }

        self.escrever(registro::CTRL, self.ler(registro::CTRL) | CTRL_REINICIO);
        // Um milissegundo antes de ler de novo: a placa está recarregando
        // tudo, e o manual não promete o que uma leitura devolve no meio.
        esperar(1, 2_000_000);
        let prazo = Prazo::em(ESPERA_DO_REINICIO_MS, VOLTAS_DE_REGISTRADOR);
        let mut volta = 0;
        loop {
            let ctrl = self.ler(registro::CTRL);
            let eecd = self.ler(registro::EECD);
            if ctrl & CTRL_REINICIO == 0 && eecd & EECD_LEITURA_FEITA != 0 {
                break;
            }
            if prazo.vencido(volta) {
                return Err("a placa nao voltou do reinicio no prazo");
            }
            volta += 1;
            core::hint::spin_loop();
        }
        self.escrever(registro::IMC, u32::MAX);
        let _ = self.ler(registro::ICR);
        Ok(())
    }

    /// O endereço que a placa carregou da EEPROM no registro 0.
    fn ler_mac(&self) -> Result<[u8; TAMANHO_DO_MAC], &'static str> {
        let baixo = self.ler(registro::RAL0);
        let alto = self.ler(registro::RAH0);
        if alto & RAH_VALIDO == 0 {
            return Err("a placa nao carregou endereco nenhum");
        }
        let [a, b, c, d] = baixo.to_le_bytes();
        let [e, f, _, _] = alto.to_le_bytes();
        let mac = [a, b, c, d, e, f];
        // Um endereço de grupo ou zerado não é de uma placa só: a pilha
        // recusaria, e o DHCP daria o mesmo endereço a duas máquinas.
        if mac == [0; TAMANHO_DO_MAC] || mac[0] & 1 != 0 {
            return Err("a placa carregou um endereco que nao e de uma placa so");
        }
        Ok(mac)
    }

    /// Monta os dois anéis e liga a recepção, a transmissão e o enlace.
    fn programar(&mut self) {
        for i in 0..NA_RECEPCAO {
            let (fisico, _) = self.buffer_de_recepcao(i);
            let d = self.descritor(0, i);
            // SAFETY: o descritor é deste driver — ver [`Placa::descritor`] —,
            // e a placa está parada: ninguém mais o lê agora.
            unsafe {
                core::ptr::write_bytes(d, 0, DESCRITOR);
                core::ptr::write_volatile(d as *mut u64, fisico.to_le());
            }
        }
        for i in 0..NA_TRANSMISSAO {
            // SAFETY: como acima.
            unsafe { core::ptr::write_bytes(self.descritor(ANEL_DE_TRANSMISSAO, i), 0, DESCRITOR) };
        }
        // Nenhum endereço de grupo: a tabela inteira zerada.
        for i in 0..128 {
            self.escrever(registro::MTA + 4 * i, 0);
        }
        // Os anéis na memória antes de a placa saber deles.
        fence(Ordering::SeqCst);

        self.escrever(registro::RDBAL, self.aneis as u32);
        self.escrever(registro::RDBAH, (self.aneis >> 32) as u32);
        self.escrever(registro::RDLEN, (NA_RECEPCAO * DESCRITOR) as u32);
        self.escrever(registro::RDH, 0);
        self.escrever(registro::RDT, (NA_RECEPCAO - 1) as u32);
        // Sem atraso na escrita de volta: o driver consulta, e um descritor
        // segurado pela placa seria um quadro que chega atrasado.
        self.escrever(registro::RDTR, 0);

        let transmissao = self.aneis + ANEL_DE_TRANSMISSAO as u64;
        self.escrever(registro::TDBAL, transmissao as u32);
        self.escrever(registro::TDBAH, (transmissao >> 32) as u32);
        self.escrever(registro::TDLEN, (NA_TRANSMISSAO * DESCRITOR) as u32);
        self.escrever(registro::TDH, 0);
        self.escrever(registro::TDT, 0);
        self.escrever(
            registro::TXDCTL,
            (self.ler(registro::TXDCTL) & !TXDCTL_LIMIAR) | TXDCTL_UM_POR_VEZ,
        );
        self.escrever(registro::TIPG, TIPG_PADRAO);
        self.proxima_recepcao = 0;
        self.proxima_transmissao = 0;

        self.escrever(registro::RCTL, RCTL_LIGADA);
        self.escrever(registro::TCTL, TCTL_LIGADA);
        // O enlace: o MAC segue o que o PHY negociar, sem velocidade forçada.
        let ctrl = self.ler(registro::CTRL);
        self.escrever(
            registro::CTRL,
            (ctrl | CTRL_ENLACE | CTRL_VELOCIDADE_AUTOMATICA)
                & !(CTRL_FORCAR_VELOCIDADE
                    | CTRL_FORCAR_DUPLEX
                    | CTRL_REINICIO_DO_PHY
                    | CTRL_VLAN
                    | CTRL_DESLIGAR_MESTRE),
        );
    }

    /// Reinicia a placa depois de uma transmissão que não se confirmou, e
    /// devolve o erro dela. O reinício para o DMA: o buffer de transmissão,
    /// e os de recepção, voltam a ser do driver.
    fn recuperar(&mut self, motivo: &'static str) -> Result<(), &'static str> {
        self.perdas.reinicios += 1;
        self.reinicios_seguidos += 1;
        if self.reinicios_seguidos > REINICIOS_SEGUIDOS {
            self.vivo = false;
            crate::log_error!(
                "e1000",
                "{} reinicios seguidos sem uma transmissao confirmada; placa desligada",
                REINICIOS_SEGUIDOS
            );
            return Err("a placa nao confirma transmissoes e foi desligada");
        }
        match self.parar() {
            Ok(()) => {
                self.programar();
                crate::log_warn!("e1000", "{}; placa reiniciada", motivo);
                Err(motivo)
            }
            Err(falha) => {
                self.vivo = false;
                crate::log_error!("e1000", "{}, e {}; placa desligada", motivo, falha);
                Err(falha)
            }
        }
    }

    /// Diz no log quando o enlace muda.
    fn notar_enlace(&mut self, agora: bool) {
        if agora != self.enlace_visto {
            self.enlace_visto = agora;
            if agora {
                crate::log_info!("e1000", "enlace de pe");
            } else {
                crate::log_warn!("e1000", "o enlace caiu: o cabo, ou o outro lado");
            }
        }
    }

    /// Só na suíte: reinicia e reprograma a placa, como depois de uma
    /// transmissão perdida — o caminho de [`Placa::recuperar`] numa placa
    /// de verdade.
    #[cfg(feature = "modo-teste")]
    pub fn reiniciar_de_teste(&mut self) -> Result<(), &'static str> {
        self.parar()?;
        self.programar();
        Ok(())
    }

    /// Só na suíte: escreve num registrador da placa — numa de
    /// [`de_mentira`], é o caso fazendo o papel da placa.
    #[cfg(feature = "modo-teste")]
    pub fn tocar_registrador(&mut self, r: usize, valor: u32) {
        assert!(r < registro::FIM && r.is_multiple_of(4));
        self.escrever(r, valor);
    }

    /// Só na suíte: lê um registrador da placa.
    #[cfg(feature = "modo-teste")]
    pub fn registrador(&self, r: usize) -> u32 {
        assert!(r < registro::FIM && r.is_multiple_of(4));
        self.ler(r)
    }

    /// Só na suíte: faz o papel da placa no descritor de recepção `i` —
    /// enche o buffer com `byte`, e escreve no descritor o tamanho, o
    /// estado e os erros.
    #[cfg(feature = "modo-teste")]
    pub fn depositar(&mut self, i: usize, byte: u8, tamanho: u16, estado: u8, erros: u8) {
        let (_, base) = self.buffer_de_recepcao(i % NA_RECEPCAO);
        let d = self.descritor(0, i % NA_RECEPCAO);
        // SAFETY: o buffer e o descritor são deste driver; numa placa de
        // mentira ninguém mais os escreve.
        unsafe {
            core::ptr::write_bytes(base, byte, BUFFER);
            core::ptr::write_volatile(d.add(8) as *mut u16, tamanho.to_le());
            core::ptr::write_volatile(d.add(13), erros);
            fence(Ordering::SeqCst);
            core::ptr::write_volatile(d.add(12), estado);
        }
    }
}

impl PlacaDeRede for Placa {
    fn driver(&self) -> &'static str {
        DRIVER
    }

    fn mac(&self) -> Option<[u8; TAMANHO_DO_MAC]> {
        Some(self.mac)
    }

    fn contadores(&self) -> (u64, u64) {
        (self.transmitidos, self.recebidos)
    }

    fn maior_espera(&self) -> u32 {
        self.maior_espera
    }

    fn enlace(&self) -> Option<bool> {
        Some(self.ler(registro::STATUS) & STATUS_ENLACE != 0)
    }

    fn perdas(&self) -> Option<Perdas> {
        Some(self.perdas)
    }

    fn transmitir(&mut self, quadro: &[u8]) -> Result<(), &'static str> {
        if !self.vivo {
            return Err("a placa parou de responder e foi desligada");
        }
        if quadro.is_empty() {
            return Err("quadro vazio");
        }
        if quadro.len() > MAIOR_QUADRO {
            return Err("quadro maior que o maximo deste driver");
        }
        let enlace = self.ler(registro::STATUS) & STATUS_ENLACE != 0;
        self.notar_enlace(enlace);
        if !enlace {
            self.perdas.sem_enlace += 1;
            return Err(crate::rede::placa::SEM_ENLACE);
        }

        // SAFETY: o frame é deste driver, o quadro cabe nele pela conferência
        // acima, e o descritor anterior foi confirmado — a placa não lê o
        // buffer agora.
        unsafe {
            core::ptr::copy_nonoverlapping(quadro.as_ptr(), self.base_de_transmissao, quadro.len());
        }
        let i = self.proxima_transmissao;
        let d = self.descritor(ANEL_DE_TRANSMISSAO, i);
        // SAFETY: o descritor é deste driver, e a placa já confirmou o que
        // ele levava da última volta do anel.
        unsafe {
            core::ptr::write_volatile(d as *mut u64, self.frame_de_transmissao.to_le());
            core::ptr::write_volatile(d.add(8) as *mut u16, (quadro.len() as u16).to_le());
            core::ptr::write_volatile(d.add(10), 0);
            core::ptr::write_volatile(d.add(11), TX_FIM_DO_QUADRO | TX_CRC | TX_RELATAR);
            core::ptr::write_volatile(d.add(12), 0);
        }
        // O descritor e o quadro na memória antes de a cauda dizer que eles
        // existem — ver a nota de domínio em `virtio::fila`.
        fence(Ordering::SeqCst);
        self.proxima_transmissao = (i + 1) % NA_TRANSMISSAO;
        self.escrever(registro::TDT, self.proxima_transmissao as u32);

        let prazo = Prazo::em(ESPERA_DA_TRANSMISSAO_MS, VOLTAS_DE_TRANSMISSAO);
        let mut volta = 0u64;
        loop {
            // SAFETY: como acima.
            let estado = unsafe { core::ptr::read_volatile(d.add(12)) };
            if estado & DD != 0 {
                fence(Ordering::SeqCst);
                self.maior_espera = self
                    .maior_espera
                    .max(u32::try_from(volta).unwrap_or(u32::MAX));
                self.transmitidos += 1;
                self.reinicios_seguidos = 0;
                return Ok(());
            }
            if prazo.vencido(volta) {
                break;
            }
            volta += 1;
            core::hint::spin_loop();
        }
        // O quadro continua com a placa, e o buffer com ele: só o reinício o
        // devolve.
        self.recuperar("a placa nao confirmou uma transmissao no prazo")
    }

    fn receber(&mut self, destino: &mut [u8]) -> Option<usize> {
        if !self.vivo {
            return None;
        }
        // No máximo uma volta do anel: um descritor com erro é devolvido e
        // o seguinte é olhado, mas a colheita termina.
        for _ in 0..NA_RECEPCAO {
            let i = self.proxima_recepcao;
            let d = self.descritor(0, i);
            // SAFETY: o descritor é deste driver.
            let estado = unsafe { core::ptr::read_volatile(d.add(12)) };
            if estado & DD == 0 {
                return None;
            }
            // O `DD` é o que anuncia o resto do descritor: lê-lo antes seria
            // ler o que a placa ainda não escreveu.
            fence(Ordering::SeqCst);
            // SAFETY: como acima.
            let (tamanho, erros) = unsafe {
                (
                    u16::from_le(core::ptr::read_volatile(d.add(8) as *const u16)),
                    core::ptr::read_volatile(d.add(13)),
                )
            };
            // Um quadro inteiro e sem erro sobe; o tamanho é o que a placa
            // disse, cortado no buffer — nunca um byte além dele.
            let bom = estado & RX_FIM_DO_QUADRO != 0 && erros & RX_ERROS_DE_QUADRO == 0;
            let copiados = if bom {
                let n = usize::from(tamanho)
                    .min(BUFFER)
                    .min(MAIOR_QUADRO)
                    .min(destino.len());
                let (_, base) = self.buffer_de_recepcao(i);
                // SAFETY: `n` é no máximo um buffer, que é deste driver, e a
                // placa terminou de escrevê-lo — o `DD` disse.
                unsafe { core::ptr::copy_nonoverlapping(base, destino.as_mut_ptr(), n) };
                n
            } else {
                0
            };
            // O descritor volta para a placa: o estado zerado, e a cauda
            // passa a ser ele — a placa usa até o anterior.
            // SAFETY: como acima.
            unsafe { core::ptr::write_volatile(d.add(12), 0) };
            fence(Ordering::SeqCst);
            self.escrever(registro::RDT, i as u32);
            self.proxima_recepcao = (i + 1) % NA_RECEPCAO;
            if bom && copiados > 0 {
                self.recebidos += 1;
                return Some(copiados);
            }
            self.perdas.descartados += 1;
        }
        None
    }

    fn vivo(&self) -> bool {
        self.vivo
    }
}

/// Procura uma 82574L no barramento e a liga.
pub fn init() {
    let mut alvo = None;
    crate::pci::com_dispositivos(|d| {
        if alvo.is_none() && d.fabricante == INTEL && d.modelo == MODELO_82574L {
            alvo = Some(*d);
        }
    });
    let Some(alvo) = alvo else {
        return;
    };
    match Placa::ligar(&alvo) {
        Ok(placa) => {
            let m = placa.mac;
            crate::log_info!(
                "e1000",
                "82574L em {:02x}:{:02x}.{}: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, enlace {}",
                alvo.barramento,
                alvo.dispositivo,
                alvo.funcao,
                m[0],
                m[1],
                m[2],
                m[3],
                m[4],
                m[5],
                if placa.enlace_visto { "de pe" } else { "caido" }
            );
            crate::arch::sem_interrupcoes(|| *PLACA.lock() = Some(placa));
        }
        Err(motivo) => crate::log_error!("e1000", "a 82574L nao pode ser ligada: {}", motivo),
    }
}

/// Chama `f` com a placa da máquina, se houver uma — o mesmo acesso da
/// virtio, e pelo mesmo motivo: o buffer de transmissão é um só.
pub fn com_a_placa<R>(f: impl FnOnce(&mut Placa) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| PLACA.lock().as_mut().map(f))
}

/// Destrava a tranca da placa à força, para uso exclusivo do caminho de
/// falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { PLACA.force_unlock() };
}

/// Só na suíte: uma placa de mentira — os anéis e os buffers de verdade,
/// e os registradores em memória comum do heap, onde ninguém faz DMA. O
/// caso faz o papel da placa: escreve nos descritores
/// ([`Placa::depositar`]) e nos registradores ([`Placa::tocar_registrador`]),
/// e a placa que ninguém reinicia é a que nunca volta do reinício. Começa
/// programada e com enlace. Os frames e a memória não voltam: os casos
/// criam poucas.
#[cfg(feature = "modo-teste")]
pub fn de_mentira() -> Option<Placa> {
    let frames = alocar_frames()?;
    let registradores = alloc::vec![0u32; registro::FIM / 4].leak();
    let mut placa = Placa::com(registradores.as_mut_ptr() as u64, frames);
    placa.mac = [0x02, 0, 0, 0, 0x82, 0x74];
    placa.programar();
    placa.escrever(registro::STATUS, STATUS_ENLACE);
    placa.enlace_visto = true;
    Some(placa)
}

/// Só na suíte: os deslocamentos que os casos tocam.
#[cfg(feature = "modo-teste")]
pub mod registros_de_teste {
    pub use super::registro::{RDT, STATUS, TDT};
    pub const DD: u8 = super::DD;
    pub const FIM_DO_QUADRO: u8 = super::RX_FIM_DO_QUADRO;
}
