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

/// Quantas teclas o histórico guarda.
pub const HISTORIA: usize = 256;

/// O que foi digitado, para quem pergunta de fora — `keyboard.read`.
///
/// # Por que não a fila do teclado
///
/// Porque a fila do teclado tem **dono**: o interpretador, que atende quem
/// está na frente da máquina. Um segundo consumidor tirando dela não observa
/// o que foi digitado — ele rouba. Medido: com o canal do agente e o
/// interpretador lendo a mesma fila, a sonda de fumaça recebeu `a` das três
/// teclas que mandou, e as outras duas foram para o interpretador.
///
/// # Por que um anel com cursores, e não uma fila
///
/// Porque uma fila tem o mesmo defeito entre os leitores de fora: dois
/// agentes lendo, um rouba do outro. O histórico é um anel das últimas
/// [`HISTORIA`] teclas, numeradas desde o boot, e cada leitor tem o seu
/// cursor — ver [`ler_para`]: cada um lê tudo o que foi digitado desde a
/// última leitura dele, e não tira nada de ninguém. O que sai do anel antes
/// de um leitor ler é contado como perdido para ele.
struct Historia {
    teclas: [char; HISTORIA],
    /// Quantas teclas entraram desde o boot: a de número `n` está em
    /// `teclas[n % HISTORIA]`, enquanto `n` for maior que `total - HISTORIA`.
    total: u64,
}

// Tomada pelo tratador da interrupção — que já roda com as interrupções
// mascaradas — e por `sem_interrupcoes` do resto. Solta no caminho fatal.
static HISTORICO: spin::Mutex<Historia> = spin::Mutex::new(Historia {
    teclas: ['\0'; HISTORIA],
    total: 0,
});

/// O cursor de cada leitor: a autoridade de quem lê — a sessão do agente, a
/// sessão da pessoa, o sistema — e o número da próxima tecla que ele não
/// leu. Com teto: um leitor esquecido sai, e começa de novo do mais antigo
/// que o anel guarda.
static CURSORES: spin::Mutex<alloc::vec::Vec<(crate::autorizacao::Autoridade, u64)>> =
    spin::Mutex::new(alloc::vec::Vec::new());

/// Quantos leitores têm cursor ao mesmo tempo.
const MAIS_LEITORES: usize = 32;

/// As teclas para a janela com o foco, esperando a tarefa do
/// interpretador.
///
/// # Por que não entregar já, na interrupção
///
/// Porque antes de entregar há o que decidir: a tecla edita o campo que a
/// janela declara, e esse campo é um recurso arrendável — ver
/// [`crate::coordenacao`]. Decidir e gravar na auditoria não é trabalho de
/// um tratador de interrupção, então a tecla espera aqui e quem decide é a
/// tarefa, como para o console.
static PARA_JANELAS: Fila<char, CAPACIDADE> = Fila::nova();

/// Os consoles que estão pedindo uma senha agora, um bit cada.
///
/// Enquanto houver algum, nada entra no [`HISTORICO`]: o histórico é o que
/// `keyboard.read` devolve, e uma senha digitada — no console físico ou na
/// janela de um Terminal, que recebe as teclas pelo canal dela — não é
/// diagnóstico de ninguém. O kernel não sabe para qual janela uma tecla vai
/// virar senha, então não grava tecla nenhuma até o último console sair do
/// pedido de senha.
static PEDINDO_SENHA: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Marca se o console `indice` está pedindo uma senha. Chamada pelo
/// interpretador.
pub fn pedindo_senha(indice: usize, pedindo: bool) {
    let bit = 1u32 << (indice % 32);
    if pedindo {
        PEDINDO_SENHA.fetch_or(bit, Ordering::Relaxed);
    } else {
        PEDINDO_SENHA.fetch_and(!bit, Ordering::Relaxed);
    }
}

/// Guarda no histórico, se nenhum console estiver pedindo senha.
fn registrar_no_historico(c: char) {
    if PEDINDO_SENHA.load(Ordering::Relaxed) == 0 {
        crate::arch::sem_interrupcoes(|| {
            let mut h = HISTORICO.lock();
            let i = (h.total % HISTORIA as u64) as usize;
            h.teclas[i] = c;
            h.total += 1;
        });
    }
}

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

/// F2: a tecla do botão "Sobre" da barra superior.
pub const F2: char = tecla_de_funcao(2);

/// F3: a tecla do botão "Terminal".
pub const F3: char = tecla_de_funcao(3);

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

    // Com o foco numa janela, o caractere é do dono dela — mas quem o
    // entrega é a tarefa do interpretador, depois de decidir: ver
    // [`PARA_JANELAS`]. Se, na hora de entregar, não houver quem escute — o
    // dono morreu e o coletor ainda não passou para devolver o foco —, ele
    // segue para o console, em vez de sumir.
    if crate::superficies::foco_ativo() {
        let _ = PARA_JANELAS.enfileirar(c);
        registrar_no_historico(c);
        #[cfg(not(feature = "modo-teste"))]
        despertar();
        return;
    }

    // Fila cheia é fila cheia: o contador de descartados da própria fila
    // guarda quantos se perderam, e não há para quem reclamar aqui dentro —
    // isto roda num handler de interrupção.
    let _ = TECLADO.enfileirar(c);
    registrar_no_historico(c);

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

/// O que um leitor leu do histórico.
pub struct Leitura {
    /// As teclas que saíram do anel antes de o leitor lê-las.
    pub perdidas: u64,
    /// As que ainda esperam por ele, depois desta leitura.
    pub esperando: u64,
}

/// Lê do histórico, para `leitor`, até `max` teclas, a partir do cursor
/// dele — chamando `f` com cada uma —, e avança o cursor. Não tira nada de
/// nenhum outro leitor.
pub fn ler_para(
    leitor: crate::autorizacao::Autoridade,
    max: usize,
    mut f: impl FnMut(char),
) -> Leitura {
    // A cópia sai da trava antes de `f` rodar: `f` escreve no canal.
    let (teclas, perdidas, esperando) = crate::arch::sem_interrupcoes(|| {
        let h = HISTORICO.lock();
        let mut cursores = CURSORES.lock();
        let mais_antiga = h.total.saturating_sub(HISTORIA as u64);
        let i = match cursores.iter().position(|(l, _)| *l == leitor) {
            Some(i) => i,
            None => {
                if cursores.len() >= MAIS_LEITORES {
                    cursores.remove(0);
                }
                cursores.push((leitor, mais_antiga));
                cursores.len() - 1
            }
        };
        let cursor = cursores[i].1;
        let perdidas = mais_antiga.saturating_sub(cursor);
        let desde = cursor.max(mais_antiga);
        let ate = h.total.min(desde + max as u64);
        let mut teclas = alloc::vec::Vec::with_capacity((ate - desde) as usize);
        for n in desde..ate {
            teclas.push(h.teclas[(n % HISTORIA as u64) as usize]);
        }
        cursores[i].1 = ate;
        (teclas, perdidas, h.total - ate)
    });
    for c in teclas {
        f(c);
    }
    Leitura {
        perdidas,
        esperando,
    }
}

/// Tira a próxima tecla do histórico para o leitor do sistema. Para a suíte,
/// que observa o histórico como um leitor.
#[cfg(feature = "modo-teste")]
pub fn observar() -> Option<char> {
    let mut lida = None;
    ler_para(crate::autorizacao::Autoridade::Sistema, 1, |c| {
        lida = Some(c)
    });
    lida
}

/// Quantas teclas viraram caractere desde o boot.
pub fn pressionadas() -> u64 {
    PRESSIONADAS.load(Ordering::Relaxed)
}

/// Quantos caracteres se perderam por ninguém ler a tempo: na fila do
/// console e na das janelas — perder ali é perder o que alguém digitou. O
/// que um leitor do histórico perdeu é dele, e vai na leitura dele.
pub fn descartados() -> u64 {
    TECLADO.descartados() + PARA_JANELAS.descartados()
}

/// Devolve o teclado ao estado de quem não digitou nada. Para a suíte.
#[cfg(feature = "modo-teste")]
pub fn esvaziar() {
    while TECLADO.desenfileirar().is_some() {}
    while PARA_JANELAS.desenfileirar().is_some() {}
    crate::arch::sem_interrupcoes(|| {
        HISTORICO.lock().total = 0;
        CURSORES.lock().clear();
    });
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

/// Acorda o interpretador: há o que ler numa fila de entrada de um
/// pseudo-terminal. Na suíte não há tarefa para acordar.
pub fn despertar_o_interpretador() {
    #[cfg(not(feature = "modo-teste"))]
    despertar();
}

/// Tira a próxima tecla para a janela com o foco, se houver.
pub fn ler_para_janela() -> Option<char> {
    PARA_JANELAS.desenfileirar()
}

/// O que chega à tarefa do interpretador.
#[cfg(not(feature = "modo-teste"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entrada {
    /// Um caractere para um console: do teclado da máquina para o físico,
    /// ou de um pseudo-terminal para o console dele.
    Console(crate::pessoas::Console, char),
    /// Uma tecla para a janela com o foco.
    Janela(char),
}

/// A próxima entrada: uma tecla para uma janela, uma do teclado da máquina
/// para o console físico, ou um caractere digitado num pseudo-terminal.
#[cfg(not(feature = "modo-teste"))]
fn proxima() -> Option<Entrada> {
    ler_para_janela()
        .map(Entrada::Janela)
        .or_else(|| ler().map(|c| Entrada::Console(crate::pessoas::Console::Fisico, c)))
        .or_else(|| crate::pseudoterminal::proxima_entrada().map(|(c, ch)| Entrada::Console(c, ch)))
}

/// A próxima entrada de algum console, quando houver uma.
#[cfg(not(feature = "modo-teste"))]
pub fn proxima_entrada() -> ProximaEntrada {
    ProximaEntrada
}

/// O futuro devolvido por [`proxima_entrada`].
///
/// Sem estado: tudo de que precisa está nos `static` do módulo e das filas
/// dos pseudo-terminais.
#[cfg(not(feature = "modo-teste"))]
pub struct ProximaEntrada;

#[cfg(not(feature = "modo-teste"))]
impl core::future::Future for ProximaEntrada {
    type Output = Entrada;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        contexto: &mut core::task::Context,
    ) -> core::task::Poll<Self::Output> {
        // Caminho rápido: com entrada na fila, nem tocamos no waker.
        if let Some(e) = proxima() {
            return core::task::Poll::Ready(e);
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
        match proxima() {
            Some(e) => core::task::Poll::Ready(e),
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
        HISTORICO.force_unlock();
        CURSORES.force_unlock();
        PARA_JANELAS.destravar();
        #[cfg(not(feature = "modo-teste"))]
        DESPERTADOR.force_unlock();
    }
}
