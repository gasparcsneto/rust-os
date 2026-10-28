//! O botão de energia no x86: o evento fixo da ACPI, pelo SCI.
//!
//! # O caminho
//!
//! ```text
//!   aperto ──► PWRBTN_STS no estado do PM1 ──(PWRBTN_EN)──► SCI, na linha do 8259
//!          ──► `idt::atender` ──► [`atender`]: lê o estado e limpa o bit
//!          ──► `crate::botao::apertado`
//! ```
//!
//! Este arquivo só diz que o botão foi apertado: não decide nada, não pede
//! nada, e não chama a energia. Quem decide é o sistema, pelo gate — ver
//! [`crate::botao`].
//!
//! # Ligar
//!
//! [`ligar`] faz o que um sistema faz ao tomar conta dos eventos fixos da
//! ACPI: entra no modo ACPI, se o firmware não entrou — fora dele, o botão
//! é do firmware —; desliga os GPEs, porque este kernel não interpreta a
//! AML que os atenderia, e um GPE ligado faria o SCI disparar sem dono;
//! limpa o estado velho do botão — o aperto que ligou a máquina fica no
//! `PWRBTN_STS` de muita placa, e não é um pedido de desligar —; habilita
//! o botão, e só ele; e abre a linha do SCI no 8259.
//!
//! O que a FADT não descreve como recurso fixo — o botão de método de
//! controle, o do hardware reduzido —, ou um SCI fora das linhas do 8259,
//! fica sem botão: [`ligar`] diz por quê, e a máquina segue sem ele.
//!
//! # A tempestade
//!
//! O SCI é de nível: enquanto um bit de estado habilitado estiver ligado, a
//! linha fica afirmada. Um bit que não se limpa — um chipset com defeito,
//! ou hostil —, ou um SCI que dispara sem o botão e sem um dispositivo que
//! divida a linha e o reclame, viraria uma tempestade de interrupções no
//! núcleo 0. Depois de [`TETO_SEM_DONO`] seguidas assim, o botão é
//! desligado — a habilitação zerada e, se nenhum dispositivo divide a
//! linha, a linha fechada —, e o fio do botão registra por quê. A máquina
//! segue; o botão, não.

use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use spin::once::Once;
use x86_64::instructions::port::Port;

use super::acpi::{self, BotaoFixo, Registrador};

/// `PWRBTN_STS` no estado do PM1, e `PWRBTN_EN` na habilitação: o mesmo
/// bit nos dois.
const BOTAO: u16 = 1 << 8;

/// Quantos SCIs seguidos sem dono — sem o botão, e sem dispositivo que os
/// reclame — desligam o botão. Um aperto não dá dois; a corrida legítima
/// de uma linha que baixa entre o pedido e o atendimento dá um. Sessenta e
/// quatro é uma tempestade, e no núcleo 0 custa microssegundos.
pub const TETO_SEM_DONO: u32 = 64;

/// A linha do SCI, quando o botão está ligado; [`SEM_LINHA`] quando não.
static LINHA: AtomicU8 = AtomicU8::new(SEM_LINHA);
const SEM_LINHA: u8 = u8::MAX;

/// O que a FADT disse, guardado quando o botão foi ligado.
static FIXO: Once<BotaoFixo> = Once::new();

/// Os SCIs sem dono seguidos — ver [`TETO_SEM_DONO`].
static SEM_DONO: AtomicU32 = AtomicU32::new(0);

/// Lê dezesseis bits em `deslocamento` dentro do bloco de portas `r`.
fn ler16(r: Registrador, deslocamento: u8) -> u16 {
    // SAFETY: a porta é do bloco de eventos do PM1 que a FADT descreve, e
    // ler o estado ou a habilitação não tem efeito.
    unsafe { Port::<u16>::new((r.endereco as u16).wrapping_add(u16::from(deslocamento))).read() }
}

/// Escreve dezesseis bits em `deslocamento` dentro do bloco de portas `r`.
fn escrever16(r: Registrador, deslocamento: u8, valor: u16) {
    // SAFETY: a porta é do bloco de eventos do PM1 que a FADT descreve; no
    // estado, escrever 1 limpa o bit, e 0 não muda nada; na habilitação, é
    // o que se quer habilitado.
    unsafe {
        Port::<u16>::new((r.endereco as u16).wrapping_add(u16::from(deslocamento))).write(valor)
    }
}

/// Os blocos de eventos do PM1: o `a` sempre, o `b` quando há.
fn blocos(b: &BotaoFixo) -> impl Iterator<Item = Registrador> {
    [Some(b.eventos_a), b.eventos_b].into_iter().flatten()
}

/// Desliga os GPEs de um bloco: a habilitação zerada, e o estado limpo —
/// cada registrador é um byte, a metade de baixo do bloco é o estado e a
/// de cima a habilitação. Um bloco fora das portas fica como está.
fn desligar_os_gpes(bloco: Option<(Registrador, u8)>) {
    let Some((r, bytes)) = bloco.filter(|(r, _)| r.espaco == acpi::ESPACO_PORTA) else {
        return;
    };
    let metade = u16::from(bytes / 2);
    let base = r.endereco as u16;
    for i in 0..metade {
        // SAFETY: as portas do bloco de GPE que a FADT descreve; zerar a
        // habilitação e limpar o estado só cala o que ninguém atende.
        unsafe {
            Port::<u8>::new(base.wrapping_add(metade + i)).write(0);
            Port::<u8>::new(base.wrapping_add(i)).write(0xFF);
        }
    }
}

/// Liga o botão de energia fixo da ACPI — ver o topo deste arquivo.
/// Devolve como a máquina diz o aperto (`acpi`), ou por que ela não diz.
pub fn ligar() -> Result<&'static str, &'static str> {
    let b = acpi::botao_fixo()?;
    if blocos(&b).any(|r| r.espaco != acpi::ESPACO_PORTA) {
        return Err("o bloco de eventos do PM1 fora das portas de E/S");
    }
    // A linha: do 8259, e nenhuma das que o kernel já usa por conta própria.
    let linha = u8::try_from(b.sci)
        .ok()
        .filter(|&l| l < 16)
        .ok_or("o SCI fora das linhas do 8259")?;
    if matches!(linha, 0..=2)
        || linha == super::pic::IRQ_SERIAL_AGENTE
        || linha == super::mouse::IRQ_MOUSE
    {
        return Err("o SCI numa linha que o kernel ja usa");
    }
    let Some(controle) = b.controle else {
        return Err("a FADT nao tem o controle do PM1");
    };
    if !super::entrar_no_modo_acpi(controle, b.smi_cmd, b.acpi_enable) {
        return Err("a maquina nao entrou no modo ACPI: o botao segue com o firmware");
    }
    desligar_os_gpes(b.gpe0);
    desligar_os_gpes(b.gpe1);
    for r in blocos(&b) {
        // O aperto de antes — o que ligou a máquina — não é um pedido; e só
        // o botão habilitado: os outros eventos fixos não têm quem os
        // atenda.
        escrever16(r, 0, BOTAO);
        escrever16(r, b.meio_do_bloco, BOTAO);
    }
    FIXO.call_once(|| b);
    LINHA.store(linha, Ordering::Release);
    // SAFETY: a IDT tem vetor para as dezesseis linhas desde `idt::init`, e
    // `idt::atender` pergunta a [`atender`] por esta.
    unsafe { super::pic::desmascarar(linha) };
    Ok("acpi")
}

/// Atende uma interrupção na `linha`, se ela é a do SCI: lê o estado do
/// PM1, limpa o bit do botão e o confere limpo, e só então diz o aperto.
/// `dispositivos` é se algum dispositivo que divide a linha reclamou a
/// interrupção — e então ela não é sem dono.
///
/// Roda no tratador da interrupção: não toma trava, não registra, não
/// decide — conta e acorda, ver [`crate::botao::apertado`].
pub fn atender(linha: u8, dispositivos: bool) {
    if linha != LINHA.load(Ordering::Acquire) {
        return;
    }
    let Some(b) = FIXO.get() else {
        return;
    };
    let mut apertado = false;
    let mut preso = false;
    for r in blocos(b) {
        if ler16(r, 0) & BOTAO == 0 {
            continue;
        }
        escrever16(r, 0, BOTAO);
        if ler16(r, 0) & BOTAO != 0 {
            preso = true;
        } else {
            apertado = true;
        }
    }
    if apertado && !preso {
        SEM_DONO.store(0, Ordering::Relaxed);
        crate::botao::apertado();
        return;
    }
    if dispositivos && !preso {
        SEM_DONO.store(0, Ordering::Relaxed);
        return;
    }
    crate::botao::sem_o_botao();
    if SEM_DONO.fetch_add(1, Ordering::Relaxed) + 1 >= TETO_SEM_DONO {
        desligar(b, linha, preso);
    }
}

/// Desliga o botão numa tempestade: a habilitação zerada nos dois blocos,
/// a linha fechada se nenhum dispositivo a divide, e o motivo para o fio
/// do botão registrar.
fn desligar(b: &BotaoFixo, linha: u8, preso: bool) {
    for r in blocos(b) {
        escrever16(r, b.meio_do_bloco, 0);
    }
    LINHA.store(SEM_LINHA, Ordering::Release);
    if !crate::virtio::linha_com_dono(u32::from(linha)) {
        // SAFETY: a linha é a do SCI, e ninguém mais a usa.
        unsafe { super::pic::mascarar(linha) };
    }
    crate::botao::desligado_pelo_hardware(if preso {
        crate::botao::Desligamento::NaoLimpa
    } else {
        crate::botao::Desligamento::SemDono
    });
}

/// Só para a suíte: a linha do SCI, se o botão está ligado.
#[cfg(feature = "modo-teste")]
pub fn linha_de_teste() -> Option<u8> {
    let l = LINHA.load(Ordering::Acquire);
    (l != SEM_LINHA).then_some(l)
}

/// Só para a suíte: o que o hardware diz agora — a habilitação do PM1a,
/// se a máquina está no modo ACPI, e se a linha do SCI está aberta no
/// 8259.
#[cfg(feature = "modo-teste")]
pub fn registradores_de_teste() -> Option<(u16, bool, bool)> {
    let b = FIXO.get()?;
    let modo = b
        .controle
        .is_some_and(|c| super::ler_registrador(c).is_some_and(|v| v & super::MODO_ACPI != 0));
    let aberta = u8::try_from(b.sci).is_ok_and(|l| !super::pic::mascarada_de_teste(l));
    Some((ler16(b.eventos_a, b.meio_do_bloco), modo, aberta))
}

/// Só para a suíte: o botão ligado de novo depois de um caso o desligar
/// numa tempestade de mentira — a habilitação, a conta e a linha.
#[cfg(feature = "modo-teste")]
pub fn religar_de_teste() {
    let Some(b) = FIXO.get() else {
        return;
    };
    let Ok(linha) = u8::try_from(b.sci) else {
        return;
    };
    for r in blocos(b) {
        escrever16(r, 0, BOTAO);
        escrever16(r, b.meio_do_bloco, BOTAO);
    }
    SEM_DONO.store(0, Ordering::Relaxed);
    LINHA.store(linha, Ordering::Release);
    // SAFETY: a mesma de `ligar`.
    unsafe { super::pic::desmascarar(linha) };
}
