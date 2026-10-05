//! O TPM da máquina, pela interface TIS ou pela CRB.
//!
//! # O que é o TIS
//!
//! A *TPM Interface Specification* do perfil de PC: um bloco de
//! registradores mapeado em memória, por onde um comando entra byte a byte
//! numa fila (a FIFO) e a resposta sai do mesmo jeito. É a interface que os
//! TPMs discretos implementam — o chip de verdade na placa-mãe —, e é a que
//! o QEMU oferece com o `tpm-tis` (no endereço fixo do PC, `0xFED4_0000`) e
//! com o `tpm-tis-device` (na máquina `virt` do ARM, onde o device tree diz
//! o endereço).
//!
//! # O que este módulo faz
//!
//! Só o transporte: entrega bytes de comando e devolve bytes de resposta —
//! o [`ancora::Tpm`]. O que os bytes dizem é do pacote `ancora`, que é onde
//! a lógica mora e onde ela é testada contra o `swtpm`.
//!
//! # As duas interfaces
//!
//! - **TIS** (a FIFO): a dos TPMs discretos, o chip na placa. O comando
//!   entra byte a byte, respeitando o `burstCount`.
//! - **CRB** (*Command Response Buffer*): a dos TPMs de firmware — o PTT
//!   da Intel, o fTPM da AMD — e a do `tpm-crb` do QEMU. O comando inteiro
//!   vai num buffer de memória, e um registrador manda executar.
//!
//! As duas moram no mesmo endereço do PC, e o registrador de identificação
//! da interface (`INTERFACE_ID`, no deslocamento `0x30` das duas) diz qual
//! é. No ARM, o device tree descreve só o TIS.
//!
//! Um fTPM cujo método de início é o ACPI (`_DSM`) — e não a escrita no
//! registrador de início — não é atendido: executar AML não é coisa deste
//! kernel. Ele aparece como TPM ausente.
//!
//! # Localidade
//!
//! O TIS tem cinco "localidades", janelas de registradores de 4 KiB, cada
//! uma com um nível de confiança diferente: a 0 é a do sistema operacional.
//! Este driver usa só ela, e a pede a cada comando: um firmware ou um
//! carregador que a deixou ativa não é algo de que se possa depender.
//!
//! # Por que espera em laço
//!
//! Pela mesma razão do disco: os chamadores são síncronos, e o tempo de um
//! comando do TPM — milissegundos, no pior caso — é uma vez por gravação
//! do journal. O laço tem teto em voltas, e não em milissegundos, porque o
//! relógio do kernel conta interrupções, e quem fala com o TPM o faz com
//! elas mascaradas.

use crate::trava::Mutex;

use ancora::{Erro, MAIOR_QUADRO, Tpm};

/// Onde os TPMs de PC moram, pela especificação do perfil de cliente.
#[cfg(target_arch = "x86_64")]
const BASE_FISICA_DO_PC: u64 = 0xFED4_0000;

/// O tamanho do bloco: cinco localidades de 4 KiB.
const TAMANHO_DO_BLOCO: u64 = 0x5000;

/// Os registradores da localidade 0 que este driver usa.
mod reg {
    /// `TPM_ACCESS`: pedir e devolver a localidade.
    pub const ACESSO: usize = 0x00;
    /// `TPM_STS`: o estado, os comandos de controle e o `burstCount`.
    pub const ESTADO: usize = 0x18;
    /// `TPM_DATA_FIFO`: a fila por onde os bytes passam.
    pub const FIFO: usize = 0x24;
    /// `TPM_DID_VID`: fabricante e modelo.
    pub const FABRICANTE: usize = 0xF00;
}

/// Os bits de `TPM_ACCESS`.
mod acesso {
    pub const PEDIR: u8 = 1 << 1;
    pub const ATIVA: u8 = 1 << 5;
    pub const VALIDO: u8 = 1 << 7;
}

/// Os bits de `TPM_STS`.
mod estado {
    /// O TPM ainda espera bytes do comando.
    pub const ESPERA_MAIS: u32 = 1 << 3;
    /// Há bytes de resposta para ler.
    pub const DADOS: u32 = 1 << 4;
    /// Executar o comando que está na fila.
    pub const EXECUTAR: u32 = 1 << 5;
    /// Pronto para receber um comando; escrever 1 aqui o põe nesse estado.
    pub const PRONTO: u32 = 1 << 6;
    /// Os bits de `ESPERA_MAIS` e `DADOS` valem.
    pub const VALIDO: u32 = 1 << 7;
    /// A família, nos bits 27–26: `01` é TPM 2.0.
    pub const FAMILIA: u32 = 0b11 << 26;
    pub const FAMILIA_2_0: u32 = 0b01 << 26;
}

/// `INTERFACE_ID`: o tipo de interface, nos bits 3–0. CRB é 1; a FIFO do
/// TIS é 0, ou 0xF nos TPMs de antes do perfil PTP.
const INTERFACE_ID: usize = 0x30;
const INTERFACE_CRB: u32 = 0x1;

/// Os registradores da CRB, na localidade 0.
mod crb {
    /// `LOC_CTRL`: pedir a localidade (bit 0).
    pub const LOC_CTRL: usize = 0x08;
    /// `LOC_STS`: a localidade concedida (bit 0).
    pub const LOC_STS: usize = 0x0C;
    /// `CTRL_REQ`: `cmdReady` (bit 0) e `goIdle` (bit 1).
    pub const CTRL_REQ: usize = 0x40;
    /// `CTRL_STS`: erro fatal (bit 0) e ocioso (bit 1).
    pub const CTRL_STS: usize = 0x44;
    /// `CTRL_START`: 1 executa; o TPM volta a 0 quando acaba.
    pub const CTRL_START: usize = 0x4C;
    /// O tamanho e o endereço físico dos buffers de comando e de resposta.
    pub const CMD_SIZE: usize = 0x58;
    pub const CMD_LADDR: usize = 0x5C;
    pub const CMD_HADDR: usize = 0x60;
    pub const RSP_SIZE: usize = 0x64;
    pub const RSP_ADDR: usize = 0x68;
    pub const PRONTO: u32 = 1 << 0;
    pub const OCIOSO: u32 = 1 << 1;
    pub const ERRO: u32 = 1 << 0;
    pub const CONCEDIDA: u32 = 1 << 0;
}

/// Quantas voltas esperar por uma mudança de estado do TPM.
///
/// Cada volta é uma leitura de registrador, que no emulador custa uma saída
/// para o hospedeiro — da ordem de um microssegundo. Cinco milhões são uns
/// segundos, o que separa "lento" de "morto" com folga.
const VOLTAS_DE_ESPERA: u32 = 5_000_000;

/// Um TPM falando TIS.
pub struct Tis {
    /// O endereço virtual da localidade 0.
    base: u64,
}

// SAFETY: `base` é um mapeamento de dispositivo exclusivo deste driver, e o
// acesso é serializado pela tranca de [`TPM`].
unsafe impl Send for Tis {}

impl Tis {
    fn ler8(&self, deslocamento: usize) -> u8 {
        // SAFETY: `base` foi mapeado como dispositivo com
        // [`TAMANHO_DO_BLOCO`] bytes, e todos os deslocamentos de `reg`
        // estão dentro da localidade 0.
        unsafe { core::ptr::read_volatile((self.base as usize + deslocamento) as *const u8) }
    }

    fn escrever8(&self, deslocamento: usize, valor: u8) {
        // SAFETY: a mesma de [`Tis::ler8`].
        unsafe { core::ptr::write_volatile((self.base as usize + deslocamento) as *mut u8, valor) }
    }

    fn ler32(&self, deslocamento: usize) -> u32 {
        // SAFETY: a mesma de [`Tis::ler8`]; os registradores de 32 bits do
        // TIS são alinhados a 4.
        unsafe { core::ptr::read_volatile((self.base as usize + deslocamento) as *const u32) }
    }

    fn escrever32(&self, deslocamento: usize, valor: u32) {
        // SAFETY: a mesma de [`Tis::ler32`].
        unsafe { core::ptr::write_volatile((self.base as usize + deslocamento) as *mut u32, valor) }
    }

    /// Quantos bytes a FIFO aceita ou entrega de uma vez, agora.
    fn rajada(&self) -> usize {
        ((self.ler32(reg::ESTADO) >> 8) & 0xFFFF) as usize
    }

    /// Espera até `condicao` valer sobre o estado.
    fn esperar(&self, condicao: impl Fn(u32) -> bool, o_que: &'static str) -> Result<u32, Erro> {
        for _ in 0..VOLTAS_DE_ESPERA {
            let e = self.ler32(reg::ESTADO);
            if condicao(e) {
                return Ok(e);
            }
            core::hint::spin_loop();
        }
        Err(Erro::Transporte(o_que))
    }

    /// Pede a localidade 0, e espera recebê-la.
    fn pedir_a_localidade(&self) -> Result<(), Erro> {
        if self.ler8(reg::ACESSO) & (acesso::ATIVA | acesso::VALIDO)
            == acesso::ATIVA | acesso::VALIDO
        {
            return Ok(());
        }
        self.escrever8(reg::ACESSO, acesso::PEDIR);
        for _ in 0..VOLTAS_DE_ESPERA {
            let a = self.ler8(reg::ACESSO);
            if a & (acesso::ATIVA | acesso::VALIDO) == acesso::ATIVA | acesso::VALIDO {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Erro::Transporte("o TPM nao concedeu a localidade 0"))
    }

    /// Põe o TPM no estado de pronto, que descarta o que estiver pela
    /// metade.
    fn aprontar(&self) -> Result<(), Erro> {
        self.escrever32(reg::ESTADO, estado::PRONTO);
        self.esperar(|e| e & estado::PRONTO != 0, "o TPM nao ficou pronto")?;
        Ok(())
    }
}

impl Tpm for Tis {
    fn trocar(&mut self, comando: &[u8], resposta: &mut [u8; MAIOR_QUADRO]) -> Result<usize, Erro> {
        self.pedir_a_localidade()?;
        self.aprontar()?;

        // O comando entra respeitando a rajada: o TPM diz quantos bytes
        // aceita agora, e escrever mais do que isso é perder os do fim.
        let mut enviados = 0;
        while enviados < comando.len() {
            let rajada = self.rajada();
            if rajada == 0 {
                core::hint::spin_loop();
                continue;
            }
            let ate = (enviados + rajada).min(comando.len());
            for &b in &comando[enviados..ate] {
                self.escrever8(reg::FIFO, b);
            }
            enviados = ate;
        }
        // Inteiro: o TPM não espera mais nada. Se esperasse, o tamanho no
        // cabeçalho diria mais do que mandamos — e executar assim seria
        // executar outro comando.
        let e = self.esperar(|e| e & estado::VALIDO != 0, "o TPM nao validou o comando")?;
        if e & estado::ESPERA_MAIS != 0 {
            let _ = self.aprontar();
            return Err(Erro::Transporte("o TPM esperava mais bytes do comando"));
        }

        self.escrever32(reg::ESTADO, estado::EXECUTAR);
        self.esperar(
            |e| e & (estado::VALIDO | estado::DADOS) == estado::VALIDO | estado::DADOS,
            "o TPM nao respondeu",
        )?;

        // O cabeçalho primeiro: é ele que diz quanto mais há para ler.
        let mut lidos = 0;
        let mut total = 10;
        while lidos < total {
            let rajada = self.rajada();
            if rajada == 0 {
                core::hint::spin_loop();
                continue;
            }
            let ate = (lidos + rajada).min(total);
            for b in &mut resposta[lidos..ate] {
                *b = self.ler8(reg::FIFO);
            }
            lidos = ate;
            if lidos == 10 && total == 10 {
                total = u32::from_be_bytes([resposta[2], resposta[3], resposta[4], resposta[5]])
                    as usize;
                if !(10..=MAIOR_QUADRO).contains(&total) {
                    let _ = self.aprontar();
                    return Err(Erro::Transporte(
                        "o TPM anunciou uma resposta de tamanho impossivel",
                    ));
                }
            }
        }
        // E nada sobrou na fila: uma resposta mais longa do que o próprio
        // cabeçalho diz é uma resposta que não se entendeu.
        let e = self.esperar(|e| e & estado::VALIDO != 0, "o TPM nao validou a resposta")?;
        let sobrou = e & estado::DADOS != 0;
        self.aprontar()?;
        if sobrou {
            return Err(Erro::Transporte("sobraram bytes na resposta do TPM"));
        }
        Ok(total)
    }
}

/// Um TPM falando CRB.
pub struct Crb {
    /// O endereço virtual da localidade 0.
    base: u64,
    /// Os endereços virtuais dos buffers de comando e de resposta, e os
    /// tamanhos.
    comando: u64,
    tam_comando: usize,
    resposta: u64,
    tam_resposta: usize,
}

// SAFETY: os endereços são mapeamentos de dispositivo exclusivos deste
// driver, e o acesso é serializado pela tranca de [`TPM`].
unsafe impl Send for Crb {}

impl Crb {
    fn ler32(&self, deslocamento: usize) -> u32 {
        // SAFETY: `base` foi mapeado como dispositivo com
        // [`TAMANHO_DO_BLOCO`] bytes, e os registradores de `crb` estão na
        // localidade 0, alinhados a 4.
        unsafe { core::ptr::read_volatile((self.base as usize + deslocamento) as *const u32) }
    }

    fn escrever32(&self, deslocamento: usize, valor: u32) {
        // SAFETY: a mesma de [`Crb::ler32`].
        unsafe { core::ptr::write_volatile((self.base as usize + deslocamento) as *mut u32, valor) }
    }

    /// Espera até `condicao` valer sobre o registrador `reg`.
    fn esperar(
        &self,
        reg: usize,
        condicao: impl Fn(u32) -> bool,
        o_que: &'static str,
    ) -> Result<u32, Erro> {
        for _ in 0..VOLTAS_DE_ESPERA {
            let v = self.ler32(reg);
            if condicao(v) {
                return Ok(v);
            }
            core::hint::spin_loop();
        }
        Err(Erro::Transporte(o_que))
    }

    /// Liga a CRB em `base`: pede a localidade e acha os buffers.
    fn ligar(base: u64) -> Result<Crb, &'static str> {
        let mut c = Crb {
            base,
            comando: 0,
            tam_comando: 0,
            resposta: 0,
            tam_resposta: 0,
        };
        c.escrever32(crb::LOC_CTRL, 1);
        c.esperar(
            crb::LOC_STS,
            |v| v & crb::CONCEDIDA != 0,
            "a CRB nao concedeu a localidade 0",
        )
        .map_err(|e| e.motivo())?;
        let fisico_comando =
            (u64::from(c.ler32(crb::CMD_HADDR)) << 32) | u64::from(c.ler32(crb::CMD_LADDR));
        let fisico_resposta =
            (u64::from(c.ler32(crb::RSP_ADDR + 4)) << 32) | u64::from(c.ler32(crb::RSP_ADDR));
        c.tam_comando = c.ler32(crb::CMD_SIZE) as usize;
        c.tam_resposta = c.ler32(crb::RSP_SIZE) as usize;
        if c.tam_comando < 64 || c.tam_resposta < 64 {
            return Err("a CRB anunciou buffers pequenos demais");
        }
        c.comando = crate::mmio::mapear(fisico_comando, c.tam_comando as u64)?;
        c.resposta = if fisico_resposta == fisico_comando {
            c.comando
        } else {
            crate::mmio::mapear(fisico_resposta, c.tam_resposta as u64)?
        };
        Ok(c)
    }
}

impl Tpm for Crb {
    fn trocar(&mut self, comando: &[u8], resposta: &mut [u8; MAIOR_QUADRO]) -> Result<usize, Erro> {
        if comando.len() > self.tam_comando {
            return Err(Erro::Transporte("comando maior que o buffer da CRB"));
        }
        // Pronto para receber: o TPM sai do ócio e limpa o pedido.
        self.escrever32(crb::CTRL_REQ, crb::PRONTO);
        self.esperar(
            crb::CTRL_REQ,
            |v| v & crb::PRONTO == 0,
            "a CRB nao ficou pronta",
        )?;
        self.esperar(
            crb::CTRL_STS,
            |v| v & crb::OCIOSO == 0,
            "a CRB continuou ociosa",
        )?;
        for (i, &b) in comando.iter().enumerate() {
            // SAFETY: `comando` foi mapeado com `tam_comando` bytes, e
            // `i < comando.len() <= tam_comando`.
            unsafe { core::ptr::write_volatile((self.comando as usize + i) as *mut u8, b) };
        }
        self.escrever32(crb::CTRL_START, 1);
        self.esperar(crb::CTRL_START, |v| v & 1 == 0, "a CRB nao respondeu")?;
        let resultado = (|| {
            if self.ler32(crb::CTRL_STS) & crb::ERRO != 0 {
                return Err(Erro::Transporte("a CRB acusou erro fatal"));
            }
            let ler = |i: usize| {
                // SAFETY: `resposta` foi mapeado com `tam_resposta` bytes, e
                // quem chama confere `i` contra ele.
                unsafe { core::ptr::read_volatile((self.resposta as usize + i) as *const u8) }
            };
            for (i, b) in resposta[..10].iter_mut().enumerate() {
                *b = ler(i);
            }
            let total =
                u32::from_be_bytes([resposta[2], resposta[3], resposta[4], resposta[5]]) as usize;
            if !(10..=MAIOR_QUADRO.min(self.tam_resposta)).contains(&total) {
                return Err(Erro::Transporte(
                    "o TPM anunciou uma resposta de tamanho impossivel",
                ));
            }
            for (i, b) in resposta[10..total].iter_mut().enumerate() {
                *b = ler(10 + i);
            }
            Ok(total)
        })();
        // De volta ao ócio, deu certo ou não.
        self.escrever32(crb::CTRL_REQ, crb::OCIOSO);
        resultado
    }
}

/// O TPM, pela interface que ele tem.
pub enum Interface {
    Tis(Tis),
    Crb(Crb),
}

impl Interface {
    fn nome(&self) -> &'static str {
        match self {
            Interface::Tis(_) => "TIS",
            Interface::Crb(_) => "CRB",
        }
    }
}

impl Tpm for Interface {
    fn trocar(&mut self, comando: &[u8], resposta: &mut [u8; MAIOR_QUADRO]) -> Result<usize, Erro> {
        #[cfg(feature = "modo-teste")]
        return falhas::trocar(self, comando, resposta);
        #[cfg(not(feature = "modo-teste"))]
        self.trocar_de_fato(comando, resposta)
    }
}

impl Interface {
    fn trocar_de_fato(
        &mut self,
        comando: &[u8],
        resposta: &mut [u8; MAIOR_QUADRO],
    ) -> Result<usize, Erro> {
        match self {
            Interface::Tis(t) => t.trocar(comando, resposta),
            Interface::Crb(c) => c.trocar(comando, resposta),
        }
    }
}

/// Só na suíte: falhas no barramento, uma de cada vez, no próximo comando
/// de um código — o que um interposto entre a CPU e o chip faria, ou um
/// barramento ruim.
#[cfg(feature = "modo-teste")]
pub mod falhas {
    use super::*;

    /// O que fazer com o próximo comando de um código.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Falha {
        /// Estraga o HMAC do comando: para o TPM, uma credencial inválida.
        ComandoAdulterado,
        /// O TPM executa, e um byte do valor da resposta muda no caminho.
        RespostaAdulterada,
        /// O TPM executa, e no lugar da resposta volta a anterior do mesmo
        /// comando.
        RespostaRepetida,
        /// O TPM executa, e a resposta se perde.
        RespostaPerdida,
    }

    /// A falha armada: o código do comando, o que fazer, e quantas vezes.
    static PLANO: Mutex<Option<(u32, Falha, u32)>> = Mutex::new(None);
    /// A última resposta de cada código de comando, para repetir.
    static ANTERIORES: Mutex<[(u32, [u8; MAIOR_QUADRO], usize); 4]> =
        Mutex::new([(0, [0; MAIOR_QUADRO], 0); 4]);

    /// Arma a falha para os próximos `vezes` comandos de código `codigo`.
    pub fn armar(codigo: u32, falha: Falha, vezes: u32) {
        crate::arch::sem_interrupcoes(|| *PLANO.lock() = Some((codigo, falha, vezes)));
    }

    /// Se a falha armada ainda não aconteceu todas as vezes.
    pub fn pendente() -> bool {
        crate::arch::sem_interrupcoes(|| PLANO.lock().is_some())
    }

    pub fn desarmar() {
        crate::arch::sem_interrupcoes(|| *PLANO.lock() = None);
    }

    /// O segredo que a escuta procura em todo comando e resposta, e se já
    /// o viu passar.
    static ESCUTA: Mutex<Option<[u8; 32]>> = Mutex::new(None);
    static VISTO: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    /// Passa a procurar `segredo` no barramento — ou para, com `None`.
    pub fn escutar(segredo: Option<[u8; 32]>) {
        VISTO.store(false, core::sync::atomic::Ordering::Release);
        crate::arch::sem_interrupcoes(|| *ESCUTA.lock() = segredo);
    }

    /// Se o segredo da escuta passou pelo barramento.
    pub fn visto() -> bool {
        VISTO.load(core::sync::atomic::Ordering::Acquire)
    }

    fn procurar(bytes: &[u8]) {
        if let Some(s) = *ESCUTA.lock()
            && bytes.windows(8).any(|w| s.windows(8).any(|p| p == w))
        {
            VISTO.store(true, core::sync::atomic::Ordering::Release);
        }
    }

    pub(super) fn trocar(
        i: &mut Interface,
        comando: &[u8],
        resposta: &mut [u8; MAIOR_QUADRO],
    ) -> Result<usize, Erro> {
        let codigo = u32::from_be_bytes([comando[6], comando[7], comando[8], comando[9]]);
        let falha = {
            let mut plano = PLANO.lock();
            match *plano {
                Some((c, f, n)) if c == codigo => {
                    *plano = if n > 1 { Some((c, f, n - 1)) } else { None };
                    Some(f)
                }
                _ => None,
            }
        };
        let mut copia = [0u8; MAIOR_QUADRO];
        copia[..comando.len()].copy_from_slice(comando);
        if falha == Some(Falha::ComandoAdulterado) {
            // O último byte do HMAC da sessão, que vem logo antes dos
            // parâmetros: em todo comando com sessão, o fim da área de
            // autorização.
            let area = 10 + 4 * handles(codigo);
            let tam_area =
                u32::from_be_bytes(copia[area..area + 4].try_into().expect("4 bytes")) as usize;
            copia[area + 4 + tam_area - 1] ^= 0x5A;
        }
        procurar(&copia[..comando.len()]);
        let n = i.trocar_de_fato(&copia[..comando.len()], resposta)?;
        procurar(&resposta[..n]);
        let anterior = {
            let mut anteriores = ANTERIORES.lock();
            let vaga = anteriores
                .iter()
                .position(|a| a.0 == codigo)
                .or_else(|| anteriores.iter().position(|a| a.0 == 0))
                .unwrap_or(0);
            let antes = anteriores[vaga];
            anteriores[vaga] = (codigo, *resposta, n);
            antes
        };
        match falha {
            Some(Falha::RespostaAdulterada) if n > 16 => {
                resposta[16] ^= 0x01;
                Ok(n)
            }
            Some(Falha::RespostaRepetida) if anterior.0 == codigo => {
                *resposta = anterior.1;
                Ok(anterior.2)
            }
            Some(Falha::RespostaPerdida) => Err(Erro::Transporte("a resposta do TPM se perdeu")),
            _ => Ok(n),
        }
    }

    /// Quantos handles os comandos que a âncora manda levam antes da área
    /// de autorização.
    fn handles(codigo: u32) -> usize {
        match codigo {
            // NV_DefineSpace e NV_UndefineSpace: a hierarquia (e o índice).
            0x12A => 1,
            0x122 => 2,
            // CreatePrimary: a hierarquia.
            0x131 => 1,
            // NV_Read, NV_Write, NV_Increment: o índice duas vezes.
            _ => 2,
        }
    }
}

/// O TPM da máquina, se houver um.
static TPM: Mutex<Option<Interface>> = Mutex::new(None);

/// Procura o TPM e o deixa pronto para uso.
pub fn init() {
    let Some(fisico) = endereco() else {
        crate::log_info!("tpm", "nenhum TPM descrito nesta maquina");
        return;
    };
    let base = match crate::mmio::mapear(fisico, TAMANHO_DO_BLOCO) {
        Ok(b) => b,
        Err(motivo) => {
            crate::log_error!("tpm", "o bloco do TPM nao foi mapeado: {}", motivo);
            return;
        }
    };
    let tis = Tis { base };
    // Um endereço sem dispositivo atrás lê tudo em um. É o que distingue
    // "não há TPM" de "há, e está ocupado".
    let id = tis.ler32(INTERFACE_ID);
    if id != 0xFFFF_FFFF && id & 0xF == INTERFACE_CRB {
        match Crb::ligar(base) {
            Ok(c) => {
                crate::log_info!("tpm", "TPM 2.0 em {:#x}, pela CRB", fisico);
                *TPM.lock() = Some(Interface::Crb(c));
            }
            Err(motivo) => crate::log_error!("tpm", "a CRB em {:#x}: {}", fisico, motivo),
        }
        return;
    }
    let fabricante = tis.ler32(reg::FABRICANTE);
    if fabricante == 0xFFFF_FFFF || fabricante == 0 || tis.ler8(reg::ACESSO) & acesso::VALIDO == 0 {
        crate::log_info!("tpm", "nenhum TPM responde em {:#x}", fisico);
        return;
    }
    if let Err(e) = tis.pedir_a_localidade() {
        crate::log_error!("tpm", "{}", e.motivo());
        return;
    }
    if tis.ler32(reg::ESTADO) & estado::FAMILIA != estado::FAMILIA_2_0 {
        crate::log_error!("tpm", "o TPM em {:#x} nao e 2.0", fisico);
        return;
    }
    crate::log_info!(
        "tpm",
        "TPM 2.0 em {:#x}, pelo TIS, fabricante {:04x} modelo {:04x}",
        fisico,
        fabricante & 0xFFFF,
        fabricante >> 16
    );
    *TPM.lock() = Some(Interface::Tis(tis));
}

/// A interface do TPM da máquina, se houver um: `"TIS"` ou `"CRB"`.
pub fn interface() -> Option<&'static str> {
    crate::arch::sem_interrupcoes(|| TPM.lock().as_ref().map(Interface::nome))
}
/// Onde o TPM está, se a máquina diz.
#[cfg(target_arch = "x86_64")]
fn endereco() -> Option<u64> {
    // O PC não descreve o TPM num lugar que este kernel leia — a tabela
    // ACPI `TPM2` —, mas o perfil de PC fixa o endereço, o mesmo para o
    // TIS e para a CRB, e [`init`] distingue as duas — e um buraco.
    Some(BASE_FISICA_DO_PC)
}

#[cfg(target_arch = "aarch64")]
fn endereco() -> Option<u64> {
    // SAFETY: o ponteiro do device tree é o que o boot validou.
    unsafe {
        crate::arch::aarch64::fdt::encontrar_mmio(crate::arch::aarch64::dtb(), b"tcg,tpm-tis-mmio")
    }
    .map(|(inicio, _)| inicio)
}

/// Se há um TPM.
pub fn presente() -> bool {
    crate::arch::sem_interrupcoes(|| TPM.lock().is_some())
}

/// Chama `f` com o TPM da máquina, se houver um. Um comando do TPM não é
/// reentrante — a FIFO é uma só —, e a tranca é o que torna isso
/// impossível em vez de improvável.
pub fn com_o_tpm<R>(f: impl FnOnce(&mut Interface) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| TPM.lock().as_mut().map(f))
}

/// Destrava a tranca do TPM à força, para uso exclusivo do caminho de falha
/// fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { TPM.force_unlock() };
}
