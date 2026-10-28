//! O botão de energia no ARM: a tecla do device tree, num PL061.
//!
//! # O caminho
//!
//! ```text
//!   aperto ──► o pino da tecla sobe no PL061 ──(borda, GPIOIE)──► a SPI do PL061
//!          ──► `gic::tratar` ──► [`atender`]: lê o estado mascarado e limpa a borda
//!          ──► `crate::botao::apertado`
//! ```
//!
//! A máquina `virt` do QEMU, sem ACPI, descreve o botão como uma tecla de
//! `gpio-keys` — o código `KEY_POWER` — num pino de um controlador de GPIO
//! PL061; o aperto é uma borda no pino, e o PL061 avisa pela interrupção
//! dele. Ver [`super::fdt::encontrar_tecla_de_energia`]. A ACPI do ARM não
//! é lida por este kernel, e uma placa que descreva o botão de outro jeito
//! fica sem ele: [`ligar`] diz por quê.
//!
//! Este arquivo só diz que o botão foi apertado: não decide nada, não pede
//! nada, e não chama a energia. Quem decide é o sistema, pelo gate — ver
//! [`crate::botao`].
//!
//! # Ligar
//!
//! O controlador tem de se identificar como um PL061 — os números de
//! periférico e de PrimeCell no fim da janela dele —: um device tree que
//! aponte a tecla para outra coisa não faz o kernel escrever nela. O pino
//! vira entrada, sensível à borda que a tecla faz ao ser apertada — a de
//! subida, ou a de descida se ela é ativa em baixo —; a borda velha é
//! limpa, e só então a interrupção do pino e a linha do controlador abrem.
//!
//! # A tempestade
//!
//! A linha do PL061 é de nível: fica afirmada enquanto houver uma borda
//! habilitada não limpa. Uma borda que não se limpa, ou uma interrupção sem
//! borda nenhuma, seguidas [`TETO_SEM_DONO`] vezes, desligam o botão — a
//! interrupção do pino fechada e a linha desabilitada no distribuidor —, e
//! o fio do botão registra por quê. É o mesmo de `x86_64::botao`.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::{fdt, gic};

/// Os registradores do PL061 que este kernel usa, pelo deslocamento: cada
/// um tem oito bits, um por pino, numa palavra de trinta e dois.
const DIRECAO: u64 = 0x400;
const SENSIBILIDADE: u64 = 0x404;
const AS_DUAS_BORDAS: u64 = 0x408;
const EVENTO: u64 = 0x40C;
const HABILITACAO: u64 = 0x410;
const ESTADO_MASCARADO: u64 = 0x418;
const LIMPEZA: u64 = 0x41C;
const FUNCAO_ALTERNATIVA: u64 = 0x420;

/// A janela de um PL061: quatro KiB, com a identificação no fim.
const JANELA: u64 = 0x1000;

/// Os números de identificação no fim da janela: os quatro bytes de
/// periférico (`GPIOPeriphID0`-`3`, a partir de `0xFE0`) — dos quais o
/// número da peça, `0x061`, e o projetista, a ARM — e os quatro de
/// PrimeCell (`0xFF0`).
const PERIFERICO: u64 = 0xFE0;
const PRIMECELL: u64 = 0xFF0;
const ID_PRIMECELL: [u32; 4] = [0x0D, 0xF0, 0x05, 0xB1];

/// Quantas interrupções seguidas sem dono desligam o botão — ver o topo.
pub const TETO_SEM_DONO: u32 = 64;

/// O controlador mapeado, o bit do pino e a linha, quando o botão está
/// ligado; a linha é [`SEM_LINHA`] quando não. A da tecla fica guardada
/// também em [`LINHA_DA_TECLA`], que a tempestade não apaga.
static BASE: AtomicU64 = AtomicU64::new(0);
static BIT: AtomicU32 = AtomicU32::new(0);
static LINHA: AtomicU32 = AtomicU32::new(SEM_LINHA);
static LINHA_DA_TECLA: AtomicU32 = AtomicU32::new(SEM_LINHA);
const SEM_LINHA: u32 = u32::MAX;

/// As interrupções sem dono seguidas.
static SEM_DONO: AtomicU32 = AtomicU32::new(0);

fn ler(base: u64, deslocamento: u64) -> u32 {
    // SAFETY: `base` é a janela do PL061, mapeada como memória de
    // dispositivo por `ligar`, e o deslocamento é de um registrador dela.
    unsafe { core::ptr::read_volatile((base + deslocamento) as *const u32) }
}

fn escrever(base: u64, deslocamento: u64, valor: u32) {
    // SAFETY: a mesma de `ler`; escrever nos registradores de configuração
    // e de limpeza do pino é o que se quer deles.
    unsafe { core::ptr::write_volatile((base + deslocamento) as *mut u32, valor) }
}

/// Se a janela em `base` se identifica como um PL061.
fn e_um_pl061(base: u64) -> bool {
    let byte = |i: u64| ler(base, PERIFERICO + 4 * i) & 0xFF;
    // A peça `0x061`, o projetista ARM (`0x41`, dividido entre os dois
    // bytes seguintes) — e a revisão, que varia, fica de fora.
    byte(0) == 0x61
        && byte(1) == 0x10
        && byte(2) & 0x0F == 0x04
        && (0..4).all(|i| ler(base, PRIMECELL + 4 * i) & 0xFF == ID_PRIMECELL[i as usize])
}

/// Liga a tecla de energia do device tree — ver o topo deste arquivo.
/// Devolve como a máquina diz o aperto (`gpio-keys`), ou por que ela não
/// diz.
pub fn ligar() -> Result<&'static str, &'static str> {
    // SAFETY: o ponteiro veio do firmware em `x0` e foi guardado no boot; o
    // leitor confere a assinatura e trata o ponteiro nulo.
    let tecla = unsafe { fdt::encontrar_tecla_de_energia(super::dtb()) }?;
    let linha = gic::intid_de(tecla.interrupcao.tipo, tecla.interrupcao.numero)
        .filter(|&l| l >= 32 && l != gic::INTID_UART)
        .ok_or("o PL061 da tecla nao avisa por uma linha compartilhada livre")?;
    if tecla.pino >= 8 {
        return Err("o pino da tecla alem dos oito do PL061");
    }
    if tecla.tamanho < JANELA {
        return Err("a janela do PL061 da tecla menor que a de um PL061");
    }
    let base = crate::mmio::mapear(tecla.base, JANELA)?;
    if !e_um_pl061(base) {
        return Err("o controlador da tecla nao se identifica como um PL061");
    }
    let bit = 1u32 << tecla.pino;
    let mudar = |deslocamento: u64, ligado: bool| {
        let atual = ler(base, deslocamento);
        escrever(
            base,
            deslocamento,
            if ligado { atual | bit } else { atual & !bit },
        );
    };
    // Fechado enquanto se configura; entrada, sem função alternativa;
    // sensível à borda, a de uma só; a de subida, ou a de descida para a
    // tecla ativa em baixo.
    mudar(HABILITACAO, false);
    mudar(DIRECAO, false);
    mudar(FUNCAO_ALTERNATIVA, false);
    mudar(SENSIBILIDADE, false);
    mudar(AS_DUAS_BORDAS, false);
    mudar(EVENTO, !tecla.ativa_em_baixo);
    // A borda velha não é um aperto de agora.
    escrever(base, LIMPEZA, bit);
    BASE.store(base, Ordering::Release);
    BIT.store(bit, Ordering::Release);
    LINHA_DA_TECLA.store(linha, Ordering::Release);
    LINHA.store(linha, Ordering::Release);
    mudar(HABILITACAO, true);
    // SAFETY: a tabela de vetores e o GIC estão de pé desde o boot, e
    // `gic::tratar` pergunta a [`atender`] por esta linha.
    unsafe { gic::habilitar_spi(linha) };
    Ok("gpio-keys")
}

/// Atende uma interrupção na `linha`, se ela é a do PL061 da tecla: lê o
/// estado mascarado, limpa a borda do pino e a confere limpa, e só então
/// diz o aperto. `dispositivos` é se um dispositivo da mesma linha a
/// reclamou.
///
/// Roda no tratador da interrupção: não toma trava, não registra, não
/// decide — conta e acorda, ver [`crate::botao::apertado`].
pub fn atender(linha: u32, dispositivos: bool) {
    if linha != LINHA.load(Ordering::Acquire) {
        return;
    }
    let base = BASE.load(Ordering::Acquire);
    let bit = BIT.load(Ordering::Acquire);
    let estado = ler(base, ESTADO_MASCARADO);
    let mut preso = false;
    if estado & bit != 0 {
        escrever(base, LIMPEZA, bit);
        if ler(base, ESTADO_MASCARADO) & bit == 0 {
            SEM_DONO.store(0, Ordering::Relaxed);
            crate::botao::apertado();
            return;
        }
        preso = true;
    } else if estado != 0 {
        // A borda de um pino que este kernel não habilitou: limpa, e não é
        // o botão.
        escrever(base, LIMPEZA, estado);
    }
    if dispositivos && !preso {
        SEM_DONO.store(0, Ordering::Relaxed);
        return;
    }
    crate::botao::sem_o_botao();
    if SEM_DONO.fetch_add(1, Ordering::Relaxed) + 1 >= TETO_SEM_DONO {
        escrever(base, HABILITACAO, ler(base, HABILITACAO) & !bit);
        LINHA.store(SEM_LINHA, Ordering::Release);
        if !crate::virtio::linha_com_dono(linha) {
            // SAFETY: a linha é a do PL061 da tecla, e ninguém mais a usa.
            unsafe { gic::desabilitar_spi(linha) };
        }
        crate::botao::desligado_pelo_hardware(if preso {
            crate::botao::Desligamento::NaoLimpa
        } else {
            crate::botao::Desligamento::SemDono
        });
    }
}

/// Só para a suíte: se a janela em `fisico` se identifica como um PL061 —
/// a do controlador da tecla sim; a de outro PrimeCell, como a PL031, não.
#[cfg(feature = "modo-teste")]
pub fn identifica_um_pl061_de_teste(fisico: u64) -> bool {
    crate::mmio::mapear(fisico, JANELA).is_ok_and(e_um_pl061)
}

/// Só para a suíte: a linha do PL061 da tecla, se o botão está ligado.
#[cfg(feature = "modo-teste")]
pub fn linha_de_teste() -> Option<u32> {
    let l = LINHA.load(Ordering::Acquire);
    (l != SEM_LINHA).then_some(l)
}

/// Só para a suíte: o que o PL061 diz agora — o bit do pino, e a
/// habilitação, o evento, a sensibilidade e a direção.
#[cfg(feature = "modo-teste")]
pub fn registradores_de_teste() -> Option<(u32, u32, u32, u32, u32)> {
    let base = BASE.load(Ordering::Acquire);
    (base != 0).then(|| {
        (
            BIT.load(Ordering::Acquire),
            ler(base, HABILITACAO),
            ler(base, EVENTO),
            ler(base, SENSIBILIDADE),
            ler(base, DIRECAO),
        )
    })
}

/// Só para a suíte: o botão ligado de novo depois de um caso o desligar
/// numa tempestade de mentira — a borda limpa, a interrupção do pino, a
/// conta e a linha.
#[cfg(feature = "modo-teste")]
pub fn religar_de_teste() {
    let base = BASE.load(Ordering::Acquire);
    let linha = LINHA_DA_TECLA.load(Ordering::Acquire);
    if base == 0 || linha == SEM_LINHA {
        return;
    }
    let bit = BIT.load(Ordering::Acquire);
    escrever(base, LIMPEZA, bit);
    escrever(base, HABILITACAO, ler(base, HABILITACAO) | bit);
    SEM_DONO.store(0, Ordering::Relaxed);
    LINHA.store(linha, Ordering::Release);
    // SAFETY: a mesma de `ligar`.
    unsafe { gic::habilitar_spi(linha) };
}
