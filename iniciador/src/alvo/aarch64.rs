//! O que o Duke precisa saber sobre o aarch64 para ser iniciado.
//!
//! # A porta serial, escrita direto no hardware
//!
//! Pelo mesmo motivo do x86, e com uma diferença de grau: o console do
//! firmware é um serviço de boot, e o trabalho deste programa termina
//! **depois** de `ExitBootServices`, exatamente onde esse console deixa de
//! existir. Um relatório que emudece no passo mais delicado do boot é um
//! relatório que falta quando é mais necessário.
//!
//! A diferença de grau é que no ARM não há tela nenhuma por baixo: o x86
//! ainda teria a VGA, e aqui a serial é tudo.
//!
//! # A UART não é a mesma, e o endereço dela não vem de lugar nenhum
//!
//! No x86 a COM1 está em `0x3F8` desde 1981, e é o processador que entrega
//! as portas de I/O. No ARM não há portas: a UART é memória mapeada, e
//! **onde** ela está é escolha da placa. A máquina `virt` do QEMU põe uma
//! PL011 em `0x0900_0000`, e é isso que este iniciador escreve.
//!
//! Escrever o endereço à mão é o que há de menos satisfatório neste arquivo,
//! e vale dizer por que ele está aqui em vez de vir do device tree. Para ler
//! o device tree é preciso antes achá-lo na tabela de configuração da UEFI,
//! e para relatar que não o achou é preciso já ter uma serial. A dependência
//! é circular, e alguém tem de chutar primeiro.
//!
//! O que **não** é chute é o resto: o iniciador acha o device tree logo em
//! seguida e relata o endereço que ele declara para a UART. Numa placa em
//! que os dois números discordem, a discordância aparece na primeira linha
//! do relatório — em vez de aparecer como silêncio.

use core::fmt;
use core::ptr::{read_volatile, write_volatile};

/// A PL011 da máquina `virt` do QEMU. Ver o cabeçalho deste módulo.
pub const UART: u64 = 0x0900_0000;

// Os registradores, contados em bytes a partir da base.
/// Dados: escrever aqui transmite um byte.
const DADOS: u64 = 0x00;
/// Bandeiras. O bit 5 diz que a fila de transmissão está cheia.
const BANDEIRAS: u64 = 0x18;

/// `TXFF`: não cabe mais nada na fila de transmissão.
const FILA_CHEIA: u32 = 1 << 5;

/// O número que o ELF usa para esta arquitetura.
pub const MAQUINA: u16 = 0xB7;

/// O tipo de relocação que soma a base de carga a um valor.
///
/// `R_AARCH64_RELATIVE`. É a única que uma imagem autocontida e independente
/// de posição produz, e recusar qualquer outra é o que impede este
/// iniciador de aplicar em silêncio uma relocação cujo significado ele não
/// conhece.
///
/// O número é **outro** que o do x86 — 1027 contra 8 —, e isso não é
/// detalhe: cada arquitetura numera as próprias relocações a partir de um,
/// então o `8` do x86 existe aqui também e quer dizer outra coisa
/// (`R_AARCH64_ABS16`). Aplicar a tabela do x86 num ELF de ARM não daria
/// erro; daria um punhado de escritas plausíveis nos lugares errados.
pub const RELOCACAO_RELATIVA: u32 = 1027;

/// O nome desta arquitetura, para o relatório.
pub const fn nome() -> &'static str {
    "aarch64"
}

/// Prepara a UART para o relatório.
///
/// # Por que ela não é reprogramada
///
/// No x86 o iniciador reprograma a COM1 — divisor, formato, FIFO —, porque
/// a configuração herdada é do firmware e um iniciador que dependesse dela
/// emudeceria noutro. Aqui a decisão é a inversa, e por um motivo concreto:
/// a taxa de transmissão de uma PL011 depende do relógio que a placa
/// entrega a ela, e esse número **não está na UART**. Ele está no device
/// tree, que ainda não foi lido.
///
/// Calcular os divisores a partir de um relógio chutado é o jeito mais
/// direto de produzir lixo na linha. O firmware já falou por esta porta
/// para imprimir o próprio banner, então ela está programada e funciona; o
/// que este iniciador faz é continuar usando o que já está de pé.
pub fn init_serial() {}

fn escrever_byte(byte: u8) {
    // SAFETY: a base é a da PL011 desta placa, e somos o único núcleo
    // escrevendo nela. As duas leituras são de registradores de dispositivo,
    // então precisam ser voláteis: um compilador que juntasse as voltas do
    // laço leria a bandeira uma vez só e giraria para sempre.
    unsafe {
        while read_volatile((UART + BANDEIRAS) as *const u32) & FILA_CHEIA != 0 {
            core::hint::spin_loop();
        }
        write_volatile((UART + DADOS) as *mut u32, u32::from(byte));
    }
}

/// O destino de tudo que este programa tem a dizer.
pub struct Serial;

impl fmt::Write for Serial {
    fn write_str(&mut self, texto: &str) -> fmt::Result {
        for byte in texto.bytes() {
            // A UART não conhece `\n` sozinho: um terminal que receba só o
            // avanço de linha continua na coluna em que estava.
            if byte == b'\n' {
                escrever_byte(b'\r');
            }
            escrever_byte(byte);
        }
        Ok(())
    }
}

/// Escreve uma linha do relatório, sempre com o prefixo que a identifica.
///
/// O prefixo não é enfeite: a saída do firmware e a nossa dividem a mesma
/// porta, e é por ele que uma pessoa — ou o `xtask` — separa as duas.
#[macro_export]
macro_rules! relatar {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = writeln!($crate::alvo::Serial, "iniciador: {}", format_args!($($arg)*));
    }};
}

/// Pára o núcleo até a próxima interrupção.
///
/// O equivalente do `hlt` do x86. `wfi` — *wait for interrupt* — suspende o
/// núcleo e acorda com a próxima interrupção pendente, mesmo mascarada.
pub fn dormir() {
    // SAFETY: `wfi` não toca em memória e só suspende o núcleo.
    unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
}

/// O que o último instante precisa saber, no ARM.
///
/// Bem menos que no x86, e o motivo é a UEFI: a especificação exige que uma
/// máquina AArch64 entregue o programa de boot com a MMU **ligada e mapeada
/// por identidade**, e esse estado sobrevive ao `ExitBootServices`. Não há
/// tabela de tradução a montar aqui — há uma a desmontar.
pub struct Partida {
    /// Para onde saltar. Físico e virtual coincidem: o mapa é de identidade.
    pub entrada: u64,
    /// O endereço da entrega, que vai em `x0`.
    pub entrega: u64,
}

/// Desliga a MMU e salta para o kernel. Não retorna.
///
/// # O que o kernel do ARM espera encontrar
///
/// O protocolo de boot do arm64 é explícito, e o que ele descreve é um
/// estado, não um formato: MMU desligada, cache de dados desligado, e a
/// imagem do kernel já visível na memória de verdade. O kernel deste projeto
/// foi escrito contra esse protocolo desde o primeiro dia — o `_start` dele
/// monta as próprias pilhas, zera o `.bss` e liga a MMU com tabelas suas.
///
/// Então o trabalho aqui é **desfazer** o que o firmware deixou, até chegar
/// exatamente no estado que o kernel já sabia esperar. É o oposto do x86,
/// onde o iniciador precisa construir o mapa que o kernel vai adotar.
///
/// # Por que o cache precisa ser limpo antes, e por set/way
///
/// Porque desligar o cache de dados não o esvazia: as linhas sujas continuam
/// lá, e uma delas pode ser expulsa **depois**, escrevendo um valor velho
/// por cima de memória que o kernel já usou para outra coisa. É o defeito
/// mais difícil de diagnosticar que existe nesta transição — ele acontece
/// muito depois do salto, num endereço que nada tem a ver com o iniciador.
///
/// Limpar por endereço cobriria só o que sabemos ter escrito. O que precisa
/// sair são também as linhas do **firmware**, que rodou durante segundos
/// antes de nós. A varredura por conjunto e via é a única forma de alcançar
/// todas: ela percorre a geometria do cache que o próprio processador
/// declara, nível por nível.
///
/// # Safety
///
/// Só pode ser chamada depois do `ExitBootServices`, com um núcleo só, e com
/// a imagem do kernel já copiada para o endereço em que ela vai executar.
pub unsafe fn partir(p: Partida) -> ! {
    // SAFETY: delegada a quem chama. A sequência abaixo é a do protocolo de
    // boot do arm64, e cada passo depende do anterior ter completado — que é
    // o que as barreiras garantem.
    unsafe {
        limpar_o_cache_de_dados();

        core::arch::asm!(
            // Interrupções fora. A tabela de vetores ainda instalada é a do
            // firmware, e o código dela some junto com o mapa.
            "msr daifset, #0xf",

            // A MMU e o cache de dados saem juntos. Do instante seguinte em
            // diante, virtual e físico são a mesma coisa de verdade — e é o
            // mapa de identidade da UEFI que garante que esta própria
            // instrução continue sendo buscada do mesmo lugar.
            "mrs x9, sctlr_el1",
            // Bit 0 é M (tradução), bit 2 é C (cache de dados).
            "bic x9, x9, #(1 << 0)",
            "bic x9, x9, #(1 << 2)",
            "msr sctlr_el1, x9",
            "isb",

            // O cache de instruções pode continuar ligado pelo protocolo,
            // mas o que está dentro dele foi buscado sob outro regime de
            // atributos de memória. Invalidá-lo é o que impede o kernel de
            // executar instruções que já não estão na RAM.
            "ic iallu",
            "dsb nsh",
            "isb",

            // E o salto, com a entrega em `x0` — o mesmo registrador em que
            // o protocolo de imagem crua entrega o device tree. É o kernel
            // que distingue os dois, pela magia.
            "br {entrada}",
            entrada = in(reg) p.entrada,
            // `x0` é o primeiro argumento por contrato, e é onde o protocolo
            // de boot do arm64 entrega o ponteiro. Nomeá-lo aqui, em vez de
            // um `mov` dentro do bloco, é o que impede o compilador de
            // escolher `x0` para outra coisa.
            in("x0") p.entrega,
            options(noreturn)
        );
    }
}

/// Limpa e invalida todo o cache de dados, por conjunto e via.
///
/// # De onde vem a geometria
///
/// Do próprio processador. O `CLIDR_EL1` diz quantos níveis existem e até
/// qual deles a coerência precisa chegar; para cada nível, o `CCSIDR_EL1`
/// diz quantos conjuntos e quantas vias ele tem, e de que tamanho é a linha.
/// Percorrer isso é o único jeito de alcançar **todas** as linhas: não há
/// instrução que diga "limpe tudo".
///
/// A aritmética dos deslocamentos é a parte que erra em silêncio. O operando
/// de `dc cisw` empacota o número da via nos bits altos e o do conjunto logo
/// acima do deslocamento da linha, e quantos bits cada um ocupa depende da
/// geometria lida. Errar por um deslocamento não dá erro: dá linhas que
/// continuam sujas, e o defeito aparece depois do salto.
///
/// # Safety
///
/// Precisa rodar em EL1, com um núcleo só. Ela não tem efeito observável
/// além de sincronizar cache e memória.
unsafe fn limpar_o_cache_de_dados() {
    // SAFETY: delegada a quem chama. Todos os registradores tocados são
    // declarados como sujos, e nenhuma das instruções acessa memória.
    unsafe {
        core::arch::asm!(
            // O nível até onde a coerência precisa chegar, em CLIDR[26:24].
            "mrs x0, clidr_el1",
            "ubfx x3, x0, #24, #3",
            "cbz x3, 5f",
            "mov x10, #0",          // x10 = nível * 2, o formato do CSSELR

            "1:",
            // O tipo do cache deste nível vem de CLIDR[3*n +: 3]. Menos que 2
            // significa "não tem cache de dados aqui" — só de instruções, ou
            // nenhum —, e não há o que limpar.
            "add x2, x10, x10, lsr #1",
            "lsr x12, x0, x2",
            "and x12, x12, #7",
            "cmp x12, #2",
            "b.lt 4f",

            // Seleciona o nível e lê a geometria dele.
            "msr csselr_el1, x10",
            "isb",
            "mrs x1, ccsidr_el1",
            // Tamanho da linha: CCSIDR[2:0] + 4 é log2 dos bytes.
            "and x2, x1, #7",
            "add x2, x2, #4",
            // Vias e conjuntos, ambos guardados como "menos um".
            "ubfx x4, x1, #3, #10",   // x4 = vias - 1
            "ubfx x7, x1, #13, #15",  // x7 = conjuntos - 1
            // O deslocamento do campo de via é 32 menos o log2 do número de
            // vias. `clz` sobre `vias - 1` num registrador de 32 bits dá
            // exatamente isso.
            "clz w5, w4",

            "mov x9, x4",             // x9 conta as vias, de cima para baixo
            "2:",
            "mov x11, x7",            // x11 conta os conjuntos
            "3:",
            "lsl x6, x9, x5",
            "orr x8, x10, x6",        // nível e via
            "lsl x6, x11, x2",
            "orr x8, x8, x6",         // e conjunto
            "dc cisw, x8",
            "subs x11, x11, #1",
            "b.ge 3b",
            "subs x9, x9, #1",
            "b.ge 2b",

            "4:",
            "add x10, x10, #2",
            "cmp x3, x10, lsr #1",
            "b.gt 1b",

            "5:",
            // A limpeza precisa ter chegado ao ponto de coerência antes de
            // qualquer coisa depender dela.
            "dsb sy",
            "isb",
            out("x0") _, out("x1") _, out("x2") _, out("x3") _,
            out("x4") _, out("x5") _, out("x6") _, out("x7") _,
            out("x8") _, out("x9") _, out("x10") _, out("x11") _,
            out("x12") _,
            options(nostack)
        );
    }
}
