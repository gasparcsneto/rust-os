//! O TPM da máquina, pela interface TIS.
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
//! a lógica mora e onde ela é testada contra o `swtpm`. Um TPM com outra
//! interface (o CRB dos TPMs de firmware) é outro transporte atrás do mesmo
//! trait, e nada acima dele muda.
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

use spin::Mutex;

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

/// O TPM da máquina, se houver um.
static TPM: Mutex<Option<Tis>> = Mutex::new(None);

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
    // Um endereço sem dispositivo atrás lê tudo em um: o bit de validade
    // aceso e um fabricante `FFFF`. É o que distingue "não há TPM" de "há,
    // e está ocupado".
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
        "TPM 2.0 em {:#x}, fabricante {:04x} modelo {:04x}",
        fisico,
        fabricante & 0xFFFF,
        fabricante >> 16
    );
    *TPM.lock() = Some(tis);
}

/// Onde o TPM está, se a máquina diz.
#[cfg(target_arch = "x86_64")]
fn endereco() -> Option<u64> {
    // O PC não descreve o TPM num lugar que este kernel leia — a tabela
    // ACPI `TPM2` —, mas o perfil de PC fixa o endereço do TIS, e a
    // conferência do fabricante em [`init`] distingue um TPM de um buraco.
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
pub fn com_o_tpm<R>(f: impl FnOnce(&mut Tis) -> R) -> Option<R> {
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
