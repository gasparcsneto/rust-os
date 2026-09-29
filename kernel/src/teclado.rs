//! O teclado: o que uma pessoa digita chega ao kernel.
//!
//! # Uma tabela para dois barramentos
//!
//! O teclado PS/2 do x86 e o `virtio-input` do ARM entregam números
//! diferentes de jeitos diferentes — e os **mesmos** números. Os códigos de
//! tecla do Linux, que o virtio-input usa, foram derivados do conjunto 1 de
//! scancodes do AT: `ESC` é 1 nos dois, `A` é 30 nos dois, `ENTER` é 28 nos
//! dois. Não é coincidência que valha para as teclas que importam aqui; é
//! herança direta.
//!
//! Então a tradução de código para caractere é uma só, e o que cada driver
//! faz é extrair o par `(código, pressionada)` do formato dele: o PS/2
//! carrega o "soltou" no bit alto do byte, o virtio-input num campo separado.
//!
//! Isso importa além da economia. Duas tabelas seriam duas oportunidades de
//! divergir, e divergiriam na arquitetura que alguém testasse menos — que é
//! exatamente o defeito que este kernel já pagou caro três vezes.
//!
//! # O que este módulo não é
//!
//! Não é um mapa de teclado configurável. O layout é o americano, que é o que
//! o emulador entrega por padrão, e está numa tabela só para poder ser
//! trocado quando houver quem escolha. Um teclado ABNT2 difere nos símbolos,
//! não nas letras nem nos dígitos.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::tarefas::fila::Fila;

/// Quantos caracteres cabem esperando serem lidos.
///
/// Uma pessoa digitando não chega perto disto. O tamanho existe para o caso
/// contrário — ninguém lendo — e o que ele garante é que o excesso vira um
/// contador em vez de crescer sem limite.
const CAPACIDADE: usize = 64;

static TECLADO: Fila<char, CAPACIDADE> = Fila::nova();

/// O que foi digitado, para quem pergunta de fora.
///
/// # Por que uma segunda fila, e não uma leitura da primeira
///
/// Porque a fila do teclado tem **dono**: o interpretador, que atende quem
/// está na frente da máquina. Um segundo consumidor tirando dela não observa
/// o que foi digitado — ele rouba. Medido: com o canal do agente e o
/// interpretador lendo a mesma fila, a sonda de fumaça recebeu `a` das três
/// teclas que mandou, e as outras duas foram para o interpretador.
///
/// Esta aqui é escrita junto com a outra e lida só pelo canal. Quem a
/// consome não tira nada de ninguém — e se ninguém a consumir, ela transborda
/// e conta os descartes, que é o comportamento certo para um diagnóstico.
static HISTORICO: Fila<char, CAPACIDADE> = Fila::nova();

/// Alguma das duas teclas de shift está pressionada?
///
/// Uma só para as duas: o hardware distingue a esquerda da direita, e nada
/// que este kernel faça com elas distingue. Guardar as duas separadas seria
/// estado que ninguém consulta.
static SHIFT: AtomicBool = AtomicBool::new(false);

/// Quantas teclas chegaram, ao todo.
///
/// Conta **eventos de pressionar** que viraram caractere, e não bytes do
/// hardware: é o número que responde "o teclado está chegando?" para quem
/// olha de fora, e o que a suíte e o canal do agente consultam.
static PRESSIONADAS: AtomicU64 = AtomicU64::new(0);

/// Os códigos que este kernel entende, na numeração comum ao PS/2 e ao evdev.
mod codigo {
    pub const ESC: u8 = 1;
    pub const BACKSPACE: u8 = 14;
    pub const TAB: u8 = 15;
    pub const ENTER: u8 = 28;
    pub const SHIFT_ESQ: u8 = 42;
    pub const SHIFT_DIR: u8 = 54;
    pub const ESPACO: u8 = 57;
    pub const F1: u8 = 59;
    pub const F10: u8 = 68;
    pub const F11: u8 = 87;
    pub const F12: u8 = 88;
}

/// O caractere que uma tecla de função produz na fila do interpretador.
///
/// # Por que um caractere, e não outra fila
///
/// Porque a fila do teclado já tem dono — o interpretador — e já é o caminho
/// de quem está na frente da máquina. Uma tecla de função precisa chegar a
/// ele na ordem em que foi apertada em relação às letras, e fora do handler
/// de interrupção: o que ela aciona pode ser limpar a tela inteira, e isso
/// não é trabalho para dentro de uma interrupção.
///
/// Os valores são os que a Apple usa para as teclas de função
/// (`NSF1FunctionKey` é U+F704): área de uso privado do Unicode, que nenhum
/// texto de verdade contém. Não entram no histórico que `keyboard.read`
/// devolve, que é o que foi **digitado**.
pub const fn tecla_de_funcao(n: u8) -> char {
    // De U+F704 a U+F70F é sempre um escalar válido, e o `None` não
    // acontece; mas `char::from_u32` é o que existe num `const fn`.
    match char::from_u32(0xF704 + n as u32 - 1) {
        Some(c) => c,
        None => '\u{F704}',
    }
}

/// F1: a tecla do botão da barra superior.
pub const F1: char = tecla_de_funcao(1);

/// Um clique do ponteiro, na fila do interpretador.
///
/// Pelo mesmo motivo das teclas de função: o interpretador é quem atende a
/// pessoa, e o clique precisa chegar a ele na ordem, fora da interrupção.
/// Onde foi o clique fica em [`crate::ponteiro::ultimo_clique`].
pub const CLIQUE: char = '\u{F8FE}';

/// Enfileira um clique para o interpretador. Chamado pelo ponteiro.
pub fn clique() {
    let _ = TECLADO.enfileirar(CLIQUE);
    #[cfg(not(feature = "modo-teste"))]
    despertar();
}

/// Qual tecla de função um código é, de 1 a 12.
fn funcao(codigo_da_tecla: u8) -> Option<u8> {
    match codigo_da_tecla {
        codigo::F1..=codigo::F10 => Some(codigo_da_tecla - codigo::F1 + 1),
        codigo::F11 => Some(11),
        codigo::F12 => Some(12),
        _ => None,
    }
}

/// O que cada código produz sem shift, na ordem em que os códigos crescem.
///
/// Um `\0` marca um código sem caractere — modificadores, teclas de função,
/// tudo que não é texto. Uma tabela densa indexada pelo código, e não um
/// `match` com dezenas de braços: a densidade é o que torna óbvio, olhando,
/// que nenhum código foi esquecido no meio.
const SEM_SHIFT: [u8; 58] = *b"\0\0\
1234567890-=\x08\
\tqwertyuiop[]\n\
\0asdfghjkl;'`\
\0\\zxcvbnm,./\0\
*\0 ";

/// O mesmo, com shift. Difere só onde o layout americano difere.
const COM_SHIFT: [u8; 58] = *b"\0\0\
!@#$%^&*()_+\x08\
\tQWERTYUIOP{}\n\
\0ASDFGHJKL:\"~\
\0|ZXCVBNM<>?\0\
*\0 ";

// As duas tabelas descrevem o mesmo teclado, então uma linha a mais numa e
// não na outra é um desalinhamento silencioso: a partir dali, shift passaria
// a devolver o caractere de outra tecla.
const _: () = assert!(SEM_SHIFT.len() == COM_SHIFT.len());
const _: () = assert!(SEM_SHIFT.len() > codigo::ESPACO as usize);

// E os índices, conferidos onde eles importam. As tabelas são escritas à mão,
// contando caracteres; um a mais ou a menos em qualquer trecho desloca tudo
// que vem depois, e o sintoma seria uma tecla produzindo a letra da vizinha —
// nada que quebre, nada que apareça num teste que não digite.
//
// O compilador conta melhor que eu.
const _: () = assert!(SEM_SHIFT[2] == b'1');
const _: () = assert!(SEM_SHIFT[codigo::BACKSPACE as usize] == 0x08);
const _: () = assert!(SEM_SHIFT[codigo::TAB as usize] == b'\t');
const _: () = assert!(SEM_SHIFT[16] == b'q');
const _: () = assert!(SEM_SHIFT[codigo::ENTER as usize] == b'\n');
const _: () = assert!(SEM_SHIFT[30] == b'a');
const _: () = assert!(SEM_SHIFT[44] == b'z');
const _: () = assert!(SEM_SHIFT[codigo::ESPACO as usize] == b' ');
const _: () = assert!(SEM_SHIFT[codigo::SHIFT_ESQ as usize] == 0);
const _: () = assert!(SEM_SHIFT[codigo::SHIFT_DIR as usize] == 0);

const _: () = assert!(COM_SHIFT[2] == b'!');
const _: () = assert!(COM_SHIFT[16] == b'Q');
const _: () = assert!(COM_SHIFT[30] == b'A');
const _: () = assert!(COM_SHIFT[44] == b'Z');
const _: () = assert!(COM_SHIFT[codigo::ENTER as usize] == b'\n');
const _: () = assert!(COM_SHIFT[codigo::ESPACO as usize] == b' ');

/// Um evento de tecla, já traduzido do formato do barramento.
///
/// `pressionada` falsa é o soltar, e ele importa: sem ele o shift ficaria
/// preso para sempre no primeiro uso.
pub fn evento(codigo_da_tecla: u8, pressionada: bool) {
    match codigo_da_tecla {
        codigo::SHIFT_ESQ | codigo::SHIFT_DIR => {
            SHIFT.store(pressionada, Ordering::Relaxed);
            return;
        }
        // Soltar qualquer outra tecla não produz nada. É o pressionar que
        // gera texto, e tratar os dois geraria cada letra em dobro.
        _ if !pressionada => return,
        _ => {}
    }

    if let Some(n) = funcao(codigo_da_tecla) {
        PRESSIONADAS.fetch_add(1, Ordering::Relaxed);
        let _ = TECLADO.enfileirar(tecla_de_funcao(n));
        #[cfg(not(feature = "modo-teste"))]
        despertar();
        return;
    }

    let Some(c) = caractere(codigo_da_tecla) else {
        return;
    };

    PRESSIONADAS.fetch_add(1, Ordering::Relaxed);

    // Com o foco numa janela, o caractere é do servidor de janelas. Se não
    // houver quem escute — o servidor morreu —, o foco volta ao kernel e o
    // caractere segue para o console, em vez de sumir.
    if crate::superficies::foco_ativo() {
        let evento = protocolo::usuario::evento::Evento {
            tipo: protocolo::usuario::evento::tipo::TECLA,
            a: c as i64,
            b: 0,
            c: 0,
        };
        match crate::eventos::publicar(protocolo::usuario::evento::CANAL_DAS_JANELAS, evento) {
            Err(crate::eventos::NaoPublicado::SemOuvinte) => {
                crate::superficies::devolver_foco();
            }
            _ => {
                let _ = HISTORICO.enfileirar(c);
                return;
            }
        }
    }

    // Fila cheia é fila cheia: o contador de descartados da própria fila
    // guarda quantos se perderam, e não há para quem reclamar aqui dentro —
    // isto roda num handler de interrupção.
    let _ = TECLADO.enfileirar(c);
    let _ = HISTORICO.enfileirar(c);

    // E avisar quem espera. Depois de enfileirar, nunca antes: um waker
    // acordado para uma fila ainda vazia faz a tarefa consultar, não achar
    // nada e voltar a dormir — e ninguém a acorda de novo.
    #[cfg(not(feature = "modo-teste"))]
    despertar();
}

/// O caractere que um código produz, com o shift que estiver valendo.
pub fn caractere(codigo_da_tecla: u8) -> Option<char> {
    let bruto = match codigo_da_tecla {
        codigo::ESC => return None,
        c if (c as usize) < SEM_SHIFT.len() => {
            if SHIFT.load(Ordering::Relaxed) {
                COM_SHIFT[c as usize]
            } else {
                SEM_SHIFT[c as usize]
            }
        }
        _ => return None,
    };

    (bruto != 0).then_some(bruto as char)
}

/// Tira o próximo caractere digitado, se houver algum.
///
/// É por aqui que o interpretador lê, e ele é o único que deveria: ver a nota
/// de [`HISTORICO`] sobre por que um segundo leitor rouba em vez de observar.
pub fn ler() -> Option<char> {
    TECLADO.desenfileirar()
}

/// Tira o próximo caractere do histórico de diagnóstico.
pub fn observar() -> Option<char> {
    HISTORICO.desenfileirar()
}

/// Quantas teclas viraram caractere desde o boot.
pub fn pressionadas() -> u64 {
    PRESSIONADAS.load(Ordering::Relaxed)
}

/// Quantos caracteres se perderam por ninguém ler.
///
/// Soma as duas filas: perder no histórico é perder um diagnóstico, perder na
/// do interpretador é perder o que alguém digitou. As duas contam, e quem
/// investiga quer saber que houve perda antes de saber onde.
pub fn descartados() -> u64 {
    TECLADO.descartados() + HISTORICO.descartados()
}

/// Quantos caracteres estão esperando no histórico.
pub fn esperando() -> usize {
    HISTORICO.ocupacao()
}

/// Devolve o teclado ao estado de quem não digitou nada. Para a suíte.
#[cfg(feature = "modo-teste")]
pub fn esvaziar() {
    while TECLADO.desenfileirar().is_some() {}
    while HISTORICO.desenfileirar().is_some() {}
    SHIFT.store(false, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Esperar por uma tecla sem girar
// ---------------------------------------------------------------------------

/// Quem acordar quando uma tecla chegar.
///
/// Mesma estrutura de [`crate::tarefas::entrada`], e pela mesma razão: uma
/// tarefa que espera entrada não deve ser repolada até haver entrada. A
/// diferença é o que acorda — lá um byte do agente, aqui uma tecla de uma
/// pessoa — e as duas convivem no mesmo executor.
#[cfg(not(feature = "modo-teste"))]
static DESPERTADOR: spin::Mutex<Option<core::task::Waker>> = spin::Mutex::new(None);

#[cfg(not(feature = "modo-teste"))]
fn despertar() {
    crate::arch::sem_interrupcoes(|| {
        if let Some(waker) = DESPERTADOR.lock().as_ref() {
            waker.wake_by_ref();
        }
    });
}

/// A próxima tecla digitada, quando houver uma.
#[cfg(not(feature = "modo-teste"))]
pub fn proxima_tecla() -> ProximaTecla {
    ProximaTecla
}

/// O futuro devolvido por [`proxima_tecla`].
///
/// Sem estado: tudo de que precisa está nos `static` do módulo.
#[cfg(not(feature = "modo-teste"))]
pub struct ProximaTecla;

#[cfg(not(feature = "modo-teste"))]
impl core::future::Future for ProximaTecla {
    type Output = char;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        contexto: &mut core::task::Context,
    ) -> core::task::Poll<char> {
        // Caminho rápido: com teclas na fila, nem tocamos no waker.
        if let Some(c) = ler() {
            return core::task::Poll::Ready(c);
        }

        crate::arch::sem_interrupcoes(|| {
            let mut guarda = DESPERTADOR.lock();
            // `will_wake` evita clonar um waker idêntico ao guardado, que é o
            // caso em toda repolagem da mesma tarefa.
            if guarda
                .as_ref()
                .is_some_and(|atual| atual.will_wake(contexto.waker()))
            {
                return;
            }
            *guarda = Some(contexto.waker().clone());
        });

        // Segunda consulta, agora com o waker no lugar. Sem ela, uma tecla que
        // chegasse entre a primeira consulta e o registro acordaria um waker
        // que ainda não existia, e o aviso se perderia — a tarefa dormiria
        // para sempre com a tecla na fila.
        match ler() {
            Some(c) => core::task::Poll::Ready(c),
            None => core::task::Poll::Pending,
        }
    }
}

/// Destrava as filas do teclado e quem espera por elas à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        TECLADO.destravar();
        HISTORICO.destravar();
        #[cfg(not(feature = "modo-teste"))]
        DESPERTADOR.force_unlock();
    }
}
