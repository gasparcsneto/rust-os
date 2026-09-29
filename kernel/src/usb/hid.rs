//! Os relatórios de um teclado e de um mouse USB, traduzidos.
//!
//! # O terceiro espaço de códigos
//!
//! O PS/2 e o `virtio-input` compartilham a numeração do conjunto 1 do AT, o
//! que permitiu uma tabela só para os dois. O USB não: o HID tem numeração
//! própria, os *usage IDs*, em que `a` é 0x04 e as letras seguem a ordem do
//! alfabeto — enquanto no AT elas seguem a ordem das teclas no teclado.
//!
//! Então aqui há uma tabela de tradução, e ela desemboca no mesmo
//! [`crate::teclado::evento`] que os outros dois. O que muda é a porta de
//! entrada; o que uma pessoa digita é o mesmo.
//!
//! # Por que o protocolo de boot
//!
//! Porque ele fixa o formato do relatório em oito bytes com significado
//! conhecido, sem precisar interpretar o descritor de relatório do HID — que
//! é uma linguagem inteira, com coleções, usos e tamanhos declarados campo a
//! campo. O protocolo de boot existe justamente para que uma BIOS consiga ler
//! um teclado sem implementar aquilo, e a razão dela é a nossa.
//!
//! O mouse tem o seu protocolo de boot pela mesma razão, e com o mesmo
//! ganho: três bytes fixos — botões, x, y — e o resto do dispositivo.

use core::sync::atomic::{AtomicU64, Ordering};

/// O relatório do teclado no protocolo de boot: oito bytes.
///
/// O primeiro são os modificadores, o segundo é reservado, e os seis últimos
/// são as teclas pressionadas **agora** — não as que mudaram. Um teclado USB
/// não manda eventos: manda o estado, e quem quiser eventos que os deduza.
pub const TAMANHO_DO_RELATORIO: usize = 8;

/// Quantas teclas simultâneas o protocolo de boot carrega.
const TECLAS: usize = 6;

/// Os bits de shift no byte de modificadores.
const SHIFT_ESQUERDO: u8 = 1 << 1;
const SHIFT_DIREITO: u8 = 1 << 5;

/// O botão esquerdo, no primeiro byte do relatório de um mouse.
const BOTAO_ESQUERDO: u8 = 1 << 0;

/// O código do AT correspondente a cada *usage* do HID.
///
/// Zero é "não traduzimos", e é o que sobra para tudo que não produz texto.
/// A tabela vai até as teclas de função, 0x45; o que vem depois é navegação
/// e o teclado numérico.
const DE_HID: [u8; 0x46] = [
    // 0x00 a 0x03: nenhuma tecla, e os três códigos de erro que o teclado usa
    // para dizer que não consegue reportar (excesso de teclas simultâneas).
    0, 0, 0, 0, //
    // 0x04 a 0x1D: as letras, em ordem alfabética no HID e na ordem do teclado
    // no AT. É esta discrepância que obriga a tabela a existir.
    30, 48, 46, 32, 18, 33, 34, 35, // a b c d e f g h
    23, 36, 37, 38, 50, 49, 24, 25, // i j k l m n o p
    16, 19, 31, 20, 22, 47, 17, 45, // q r s t u v w x
    21, 44, // y z
    // 0x1E a 0x27: os dígitos, que no HID começam em 1 e terminam em 0.
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, //
    // 0x28 a 0x2C: enter, esc, backspace, tab, espaço.
    28, 1, 14, 15, 57, //
    // 0x2D a 0x31: - = [ ] \
    12, 13, 26, 27, 43, //
    // 0x32: a tecla que só existe em teclados não americanos.
    0, //
    // 0x33 a 0x38: ; ' ` , . /
    39, 40, 41, 51, 52, 53, //
    // 0x39: caps lock, que o teclado deste kernel ainda não trata.
    0, //
    // 0x3A a 0x45: F1 a F12. No AT, F1 a F10 são seguidas e F11 e F12 vieram
    // depois, num buraco mais adiante.
    59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 87, 88,
];

// A tabela é escrita à mão, e um elemento a mais ou a menos em qualquer linha
// desloca todo o resto — com o sintoma de uma tecla digitando a letra da
// vizinha. O compilador confere os pontos onde isso apareceria.
const _: () = assert!(DE_HID[0x04] == 30); // a
const _: () = assert!(DE_HID[0x1D] == 44); // z
const _: () = assert!(DE_HID[0x1E] == 2); // 1
const _: () = assert!(DE_HID[0x27] == 11); // 0
const _: () = assert!(DE_HID[0x28] == 28); // enter
const _: () = assert!(DE_HID[0x2C] == 57); // espaço
const _: () = assert!(DE_HID[0x38] == 53); // barra
const _: () = assert!(DE_HID[0x3A] == 59); // F1
const _: () = assert!(DE_HID[0x43] == 68); // F10
const _: () = assert!(DE_HID[0x45] == 88); // F12

/// Quantos relatórios de teclado já foram processados.
///
/// Existe para separar "o teclado USB não entregou nada" de "entregou e nada
/// virou tecla". Com dois teclados na mesma máquina, é também o que diz por
/// onde o que foi digitado chegou — sem ele, a sonda passaria sem saber qual
/// dos dois caminhos exercitou.
static RELATORIOS: AtomicU64 = AtomicU64::new(0);

/// Quantos relatórios de mouse, pela mesma razão: numa máquina com o mouse
/// PS/2 e o USB, é o que diz qual dos dois moveu o ponteiro.
static RELATORIOS_DO_MOUSE: AtomicU64 = AtomicU64::new(0);

/// Quantos relatórios o teclado USB entregou.
pub fn relatorios() -> u64 {
    RELATORIOS.load(Ordering::Relaxed)
}

/// Quantos relatórios o mouse USB entregou.
pub fn relatorios_do_mouse() -> u64 {
    RELATORIOS_DO_MOUSE.load(Ordering::Relaxed)
}

/// Traduz um relatório de teclado em eventos de tecla.
///
/// `anterior` é o relatório anterior **deste** teclado, que a função
/// atualiza. Um teclado USB manda o estado completo a cada mudança, então
/// quem quer eventos precisa comparar. Sem esta memória, segurar uma tecla
/// mandaria a letra a cada relatório — e soltar não mandaria nada.
///
/// A memória é de quem chama, e não um estático daqui: cada teclado tem a
/// sua, e dois teclados não confundem o que um soltou com o que o outro
/// segura.
pub fn processar(anterior: &mut [u8; TAMANHO_DO_RELATORIO], relatorio: [u8; TAMANHO_DO_RELATORIO]) {
    RELATORIOS.fetch_add(1, Ordering::Relaxed);

    // Os modificadores primeiro, e é obrigatório que seja antes: o shift
    // precisa estar valendo quando a letra do mesmo relatório for traduzida.
    let shift_antes = anterior[0] & (SHIFT_ESQUERDO | SHIFT_DIREITO) != 0;
    let shift_agora = relatorio[0] & (SHIFT_ESQUERDO | SHIFT_DIREITO) != 0;
    if shift_antes != shift_agora {
        // O código 42 é o shift esquerdo no AT. Qual dos dois foi não importa
        // para [`crate::teclado`], que guarda um estado só.
        crate::teclado::evento(42, shift_agora);
    }

    let teclas_de = |r: &[u8; TAMANHO_DO_RELATORIO]| -> [u8; TECLAS] {
        let mut t = [0u8; TECLAS];
        t.copy_from_slice(&r[2..2 + TECLAS]);
        t
    };
    let antes = teclas_de(anterior);
    let agora = teclas_de(&relatorio);

    // Pressionadas: as que estão no relatório novo e não estavam no anterior.
    // Soltas não geram nada por enquanto — [`crate::teclado`] só transforma o
    // pressionar em caractere —, mas a comparação existe do mesmo jeito
    // porque é ela que impede a repetição.
    for tecla in agora {
        if tecla == 0 || antes.contains(&tecla) {
            continue;
        }
        if let Some(codigo) = traduzir(tecla) {
            crate::teclado::evento(codigo, true);
        }
    }

    *anterior = relatorio;
}

/// O relatório de um mouse no protocolo de boot: botões, x e y.
///
/// # O formato
///
/// Os três primeiros bytes são fixos: os botões — o esquerdo no bit 0 —, e
/// quanto o mouse andou em x e em y, com sinal, em complemento de dois. O
/// que vem depois — a roda, quase sempre — é do dispositivo, e o protocolo
/// de boot diz para ignorar. Ao contrário do PS/2, y positivo é para baixo,
/// como na tela.
///
/// Um mouse não precisa da memória que o teclado precisa: o relatório diz
/// quanto andou, e não onde está, e o botão já é comparado com o anterior
/// em [`crate::ponteiro::botao`].
pub fn processar_mouse(relatorio: &[u8]) {
    let [botoes, dx, dy, ..] = *relatorio else {
        return;
    };
    RELATORIOS_DO_MOUSE.fetch_add(1, Ordering::Relaxed);
    crate::ponteiro::relativo(i32::from(dx as i8), i32::from(dy as i8));
    crate::ponteiro::botao(botoes & BOTAO_ESQUERDO != 0);
    crate::ponteiro::sincronizar();
}

/// O código do AT para um *usage* do HID, se houver um.
pub fn traduzir(usage: u8) -> Option<u8> {
    let codigo = *DE_HID.get(usage as usize)?;
    (codigo != 0).then_some(codigo)
}
