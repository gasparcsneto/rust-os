//! O mouse PS/2: a porta auxiliar do controlador 8042.
//!
//! # Por que ele
//!
//! Porque é o mouse que a máquina `pc` tem de fábrica, como o 8042 é o
//! teclado dela. Diz quanto andou — não onde está —, em pacotes de três
//! bytes: botões e sinais, deslocamento em x, deslocamento em y. O ARM não
//! tem 8042; lá o ponteiro chega por um tablet virtio.
//!
//! # A conversa com o controlador
//!
//! O 8042 atende os dois dispositivos pela mesma porta de dados (0x60). Para
//! falar com o mouse, cada byte é precedido do comando 0xD4 na porta de
//! comando (0x64); o mouse responde 0xFA a cada comando que aceita. E a
//! configuração do controlador precisa de dois bits: um liga a interrupção
//! da porta auxiliar (a IRQ 12), o outro desliga o bloqueio do relógio dela.
//!
//! Tudo com as interrupções mascaradas: o handler do teclado também lê a
//! porta 0x60, e um byte de resposta do mouse lido por ele iria parar na
//! fila do teclado.
//!
//! # Esperas com teto
//!
//! O controlador avisa por bits de estado quando pode receber e quando tem
//! byte para entregar. Um controlador que não avisa nunca — uma máquina sem
//! porta auxiliar — não pode prender o boot: cada espera tem teto, e o mouse
//! fica desligado.

use core::sync::atomic::{AtomicU32, Ordering};

use x86_64::instructions::port::Port;

const DADOS: u16 = 0x60;
const COMANDO: u16 = 0x64;

/// O controlador tem byte para entregar.
const SAIDA_CHEIA: u8 = 1 << 0;
/// O controlador ainda não consumiu o último byte recebido.
const ENTRADA_CHEIA: u8 = 1 << 1;
/// O byte à espera veio da porta auxiliar — do mouse, e não do teclado.
const SAIDA_DO_AUXILIAR: u8 = 1 << 5;

/// Na configuração do 8042: interrupção da porta auxiliar, e o bloqueio do
/// relógio dela.
const CONFIG_IRQ_AUXILIAR: u8 = 1 << 1;
const CONFIG_RELOGIO_AUXILIAR_DESLIGADO: u8 = 1 << 5;

const LIGAR_AUXILIAR: u8 = 0xA8;
const LER_CONFIG: u8 = 0x20;
const ESCREVER_CONFIG: u8 = 0x60;
const PARA_O_MOUSE: u8 = 0xD4;

const PADROES: u8 = 0xF6;
const LIGAR_RELATOS: u8 = 0xF4;
const ACEITO: u8 = 0xFA;

/// A linha do mouse no PIC.
pub const IRQ_MOUSE: u8 = 12;

/// Quantas voltas esperar por um bit de estado.
const VOLTAS: u32 = 100_000;

/// No primeiro byte de um pacote: o botão esquerdo, os sinais de x e y, e o
/// bit que é sempre um — o que permite achar o começo de um pacote.
const BOTAO_ESQUERDO: u8 = 1 << 0;
const SEMPRE_UM: u8 = 1 << 3;
const X_NEGATIVO: u8 = 1 << 4;
const Y_NEGATIVO: u8 = 1 << 5;
const TRANSBORDOU: u8 = 0b1100_0000;

/// O pacote em montagem: os bytes que chegaram, e quantos. Só o handler da
/// IRQ 12 mexe aqui, com as interrupções mascaradas.
static PACOTE: AtomicU32 = AtomicU32::new(0);
static RECEBIDOS: AtomicU32 = AtomicU32::new(0);

fn estado() -> u8 {
    // SAFETY: 0x64 é a porta de estado do 8042; ler não tem efeito colateral.
    unsafe { Port::<u8>::new(COMANDO).read() }
}

fn esperar_para_escrever() -> bool {
    (0..VOLTAS).any(|_| estado() & ENTRADA_CHEIA == 0)
}

fn esperar_para_ler() -> bool {
    (0..VOLTAS).any(|_| estado() & SAIDA_CHEIA != 0)
}

fn comando(c: u8) -> bool {
    if !esperar_para_escrever() {
        return false;
    }
    // SAFETY: a porta de comando do 8042, com ele pronto para receber.
    unsafe { Port::<u8>::new(COMANDO).write(c) };
    true
}

fn escrever_dado(d: u8) -> bool {
    if !esperar_para_escrever() {
        return false;
    }
    // SAFETY: a porta de dados do 8042, com ele pronto para receber.
    unsafe { Port::<u8>::new(DADOS).write(d) };
    true
}

fn ler_dado() -> Option<u8> {
    if !esperar_para_ler() {
        return None;
    }
    // SAFETY: a porta de dados do 8042, com um byte à espera.
    Some(unsafe { Port::<u8>::new(DADOS).read() })
}

/// Manda um comando ao mouse e espera o aceite.
fn ao_mouse(c: u8) -> bool {
    comando(PARA_O_MOUSE) && escrever_dado(c) && ler_dado() == Some(ACEITO)
}

/// Liga a porta auxiliar e o mouse, e desmascara a IRQ 12.
///
/// Devolve se o mouse respondeu. Sem ele, nada é desmascarado.
pub fn init() -> bool {
    crate::arch::sem_interrupcoes(|| {
        if !comando(LIGAR_AUXILIAR) || !comando(LER_CONFIG) {
            return false;
        }
        let Some(config) = ler_dado() else {
            return false;
        };
        let config = (config | CONFIG_IRQ_AUXILIAR) & !CONFIG_RELOGIO_AUXILIAR_DESLIGADO;
        if !comando(ESCREVER_CONFIG) || !escrever_dado(config) {
            return false;
        }
        if !ao_mouse(PADROES) || !ao_mouse(LIGAR_RELATOS) {
            return false;
        }
        PACOTE.store(0, Ordering::Relaxed);
        RECEBIDOS.store(0, Ordering::Relaxed);
        // SAFETY: a IRQ 12 tem handler — ver `idt::atender` — e o mouse está
        // pronto para relatar.
        unsafe { super::pic::desmascarar(IRQ_MOUSE) };
        true
    })
}

/// A IRQ 12: lê o byte do mouse, se houver um.
///
/// # Por que perguntar antes de ler
///
/// Porque a IRQ 12 chega sem byte, uma vez: a de cada aceite da
/// inicialização. A configuração liga a interrupção da porta auxiliar antes
/// dos comandos ao mouse, e o PIC guarda o pedido enquanto a linha está
/// mascarada; quando ela é desmascarada, ele entrega esse pedido velho. Ler
/// a porta ali devolvia o último byte de novo — o 0xFA do aceite —, que tem o
/// bit 3 ligado e passava por começo de pacote. Medido: a suíte achou um
/// byte pendurado antes do primeiro pacote, e o pacote dela saiu fora de
/// fase.
pub fn atender() {
    let estado = estado();
    if estado & SAIDA_CHEIA == 0 || estado & SAIDA_DO_AUXILIAR == 0 {
        return;
    }
    // SAFETY: a porta de dados do 8042, com um byte da porta auxiliar à
    // espera — conferido acima.
    let b = unsafe { Port::<u8>::new(DADOS).read() };
    byte(b);
}

/// Um byte que o mouse mandou.
pub fn byte(b: u8) {
    let n = RECEBIDOS.load(Ordering::Relaxed);
    // O primeiro byte de um pacote tem o bit 3 ligado. Um byte que deveria
    // ser o primeiro e não tem é o meio de um pacote que se perdeu: descarta
    // até achar o começo de novo, em vez de ler o resto fora de fase.
    if n == 0 && b & SEMPRE_UM == 0 {
        return;
    }
    let pacote = PACOTE.load(Ordering::Relaxed) | (b as u32) << (8 * n);
    if n < 2 {
        PACOTE.store(pacote, Ordering::Relaxed);
        RECEBIDOS.store(n + 1, Ordering::Relaxed);
        return;
    }
    PACOTE.store(0, Ordering::Relaxed);
    RECEBIDOS.store(0, Ordering::Relaxed);
    let [estado, dx, dy, _] = pacote.to_le_bytes();
    tratar_pacote(estado, dx, dy);
}

/// Esquece o pacote pela metade, e devolve quantos bytes dele havia. Para a
/// suíte, que monta pacotes à mão e precisa começar do começo de um.
#[cfg(feature = "modo-teste")]
pub fn esquecer() -> u32 {
    PACOTE.store(0, Ordering::Relaxed);
    RECEBIDOS.swap(0, Ordering::Relaxed)
}

/// Um pacote inteiro: movimento, botão, e o fim do lote.
fn tratar_pacote(estado: u8, dx: u8, dy: u8) {
    // Deslocamentos de nove bits: o byte, e o sinal no primeiro byte.
    let com_sinal = |v: u8, negativo: bool| v as i32 - if negativo { 256 } else { 0 };
    if estado & TRANSBORDOU == 0 {
        let dx = com_sinal(dx, estado & X_NEGATIVO != 0);
        let dy = com_sinal(dy, estado & Y_NEGATIVO != 0);
        // No PS/2, y positivo é para cima; na tela, para baixo.
        crate::ponteiro::relativo(dx, -dy);
    }
    crate::ponteiro::botao(estado & BOTAO_ESQUERDO != 0);
    crate::ponteiro::sincronizar();
}
