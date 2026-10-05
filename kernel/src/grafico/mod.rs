//! A pilha gráfica: o que fica entre quem desenha e a tela.
//!
//! # De onde vem o desenho
//!
//! Do Redox, e não por falta de ideia própria: por ser a resposta certa a uma
//! pergunta que este projeto tinha respondido errado.
//!
//! A pergunta era virtio-gpu ou framebuffer linear. O `xtask` registrava a
//! resposta — `bochs-display`, porque virtio-gpu seria "um segundo caminho
//! para a mesma coisa". O Redox mostra que a escolha é falsa. Os dois drivers
//! dele, `vesad` e `virtio-gpud`, implementam o **mesmo** trait, e o
//! compositor acima dele desenha num buffer, entrega o retângulo que mudou e
//! não sabe qual dos dois está embaixo. Há um caminho só — acima do trait. É
//! o mesmo arranjo que o Duke já usa em [`crate::virtio::transporte`], com
//! disco, rede e teclado pendurados na mesma porta.
//!
//! O trait é porte de `GraphicsAdapter`, de `redox-os/drivers`
//! (`graphics/driver-graphics/src/lib.rs`). MIT, Copyright (c) 2017 Redox OS;
//! ver `THIRD_PARTY.md`.
//!
//! # O que mudou no porte
//!
//! - **Criar uma superfície pode falhar.** No Redox, `create_dumb_framebuffer`
//!   devolve a superfície sem erro e entra em pânico por dentro se não houver
//!   memória — derruba um daemon. Aqui derrubaria o kernel.
//! - **Pixels são uma fatia, e não um ponteiro.** O original tem
//!   `map_dumb_framebuffer(...) -> *mut u8`; aqui a superfície entrega
//!   `&mut [u32]`, e quem desenha não escreve `unsafe`.
//! - **Atualizar devolve o que foi atualizado**, depois do recorte. O
//!   original não devolve nada. É a resposta que o agente quer: não "o que
//!   pediram para redesenhar", mas "o que de fato mudou na tela".
//! - **A superfície da tela.** Um método que o original não tem,
//!   [`AdaptadorGrafico::superficie_da_tela`]: onde a tela já é um buffer
//!   que o monitor só vê quando mandado, o compositor monta a tela nela em
//!   vez de pedir outra do mesmo tamanho.
//! - **Sem cursor.** O trait original tem cinco métodos de cursor de
//!   hardware; este kernel ainda não tem mouse, e cinco métodos sem chamador
//!   seriam cinco métodos que ninguém confere.
//!
//! # Por que ao lado de [`crate::tela`], e não por cima dela
//!
//! Porque a `tela` é alcançável de dentro de um handler de falha fatal, sem
//! tranca nenhuma — o estado dela é atômico por isso. Esta pilha segura uma
//! tranca e aloca memória, duas coisas que um handler de falha não pode
//! fazer. Então as duas convivem: o caminho post-mortem continua desenhando
//! direto no hardware, **por baixo** de tudo isto, e é por isso que ele
//! continua funcionando quando é exatamente esta pilha que quebrou.
//!
//! # O que há aqui
//!
//! Os dois adaptadores, o linear e o [`virtio`]; o [`compositor`], com o
//! console como a camada de baixo; a memória das superfícies, com a faixa
//! que volta quando elas saem ([`memoria`]); e o que o agente precisa para
//! saber qual adaptador está ativo, que camadas estão na tela e o que chegou
//! a ela. A árvore semântica mora em [`crate::ui`], porque descreve a
//! interface, e não o adaptador.
//!
//! Quem cria camadas: a barra superior e o cursor, no kernel; e os
//! processos, por [`crate::superficies`] — o servidor de janelas, uma por
//! janela. A entrada chega às janelas por [`crate::ponteiro`] e
//! [`crate::teclado`], que perguntam a [`camada_em`] o que está debaixo do
//! ponteiro.

pub mod compositor;
pub mod dano;
pub mod linear;
pub(crate) mod memoria;
pub mod virtio;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::trava::Mutex;

use compositor::Compositor;
pub use dano::Dano;

/// Um buffer de pixels onde se desenha antes de a tela ver.
///
/// Os pixels estão no formato de [`crate::tela::Cor::para_u32`].
pub trait Superficie {
    fn largura(&self) -> u32;
    fn altura(&self) -> u32;
    fn pixels(&self) -> &[u32];
    fn pixels_mut(&mut self) -> &mut [u32];
    /// Quanta memória a superfície segura.
    ///
    /// Hoje só a suíte pergunta, para conferir que criar e soltar mexem na
    /// conta de [`memoria::vivas`] — que é o que o relatório do agente lê.
    #[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
    fn bytes(&self) -> u64;
}

/// O que um adaptador de vídeo precisa saber fazer.
///
/// Porte de `GraphicsAdapter` do Redox — ver o cabeçalho do módulo para o
/// que mudou e por quê.
pub trait AdaptadorGrafico {
    /// A superfície deste adaptador: memória onde se desenha, mais o que o
    /// adaptador precisar associar a ela. No linear, nada; no virtio-gpu,
    /// um recurso do dispositivo.
    type Superficie: Superficie;

    /// O nome que o relatório do agente usa.
    fn nome(&self) -> &'static str;

    /// Quantas telas o adaptador pode ter. Constante enquanto ele viver.
    fn telas(&self) -> usize;

    fn tamanho_da_tela(&self, tela: usize) -> Option<(u32, u32)>;

    fn criar_superficie(
        &mut self,
        largura: u32,
        altura: u32,
    ) -> Result<Self::Superficie, &'static str>;

    /// A superfície que a tela já mostra, quando ela serve de quadro ao
    /// compositor.
    ///
    /// # Por que um adaptador tem e o outro não
    ///
    /// O quadro é onde o compositor monta a tela antes de ela aparecer, e
    /// precisa ser invisível enquanto está pela metade — senão o console
    /// apareceria por um instante debaixo de cada janela. No `virtio-gpu` a
    /// memória da tela já é assim: o monitor só vê o que se transfere, e
    /// compor nela não mostra nada até o fim. Usá-la economiza uma tela
    /// inteira de memória, e deixa a tela física sendo o que o monitor
    /// mostra — que é onde o caminho de falha pinta.
    ///
    /// Num framebuffer linear, o que se escreve aparece: compor nele
    /// mostraria cada camada sendo pintada. Ali não há superfície da tela, e
    /// o compositor cria um quadro com [`AdaptadorGrafico::criar_superficie`]
    /// — o buffer de fundo do `vesad`.
    ///
    /// É extensão do porte: o `GraphicsAdapter` do Redox não tem isto.
    fn superficie_da_tela(&mut self, _tela: usize) -> Option<Self::Superficie> {
        None
    }

    /// Leva à tela o retângulo `dano` da superfície.
    ///
    /// Devolve o retângulo que de fato foi levado, depois do recorte — que
    /// pode ser menor que o pedido, ou vazio.
    fn atualizar(
        &mut self,
        tela: usize,
        superficie: &Self::Superficie,
        dano: Dano,
    ) -> Result<Dano, &'static str>;
}

/// O compositor da tela, com o adaptador embaixo dele.
// A tomada desta tranca passa por `sem_interrupcoes`, pelo motivo de toda
// tranca deste kernel: um handler que a pedisse enquanto ela estivesse na mão
// do código interrompido giraria para sempre.
static ATIVO: Mutex<Option<Compositor>> = Mutex::new(None);

/// Roda `f` com o compositor, se houver um. Espera pela trava.
///
/// Para quem mexe nas camadas — nunca de dentro de uma escrita no console,
/// que usa [`compor`].
fn com_compositor<R>(f: impl FnOnce(&mut Compositor) -> R) -> Option<R> {
    if DESLIGADO.load(Ordering::Acquire) {
        return None;
    }
    crate::arch::sem_interrupcoes(|| ATIVO.lock().as_mut().map(f))
}

/// O compositor foi desligado pela falha fatal — ver [`desligar`].
static DESLIGADO: AtomicBool = AtomicBool::new(false);

/// Desliga o compositor, para sempre: nada mais passa por ele até a tela.
///
/// # Por que a falha desliga, e não só passa por baixo
///
/// O caminho fatal pinta a tela física sem o compositor, porque não pode
/// confiar nele. Passar por baixo não bastava: o compositor continuava
/// vivo, e o que ainda chegasse a ele compunha por cima da tela de falha.
/// Medido: um `ui.act` do agente no post-mortem redesenhava a barra e
/// apagava a tela de falha inteira — de 99,8% da tela na cor de falha para
/// zero.
///
/// E desligado, ele deixa de levar à tela o que a falha pintasse por
/// engano na camada do console, em vez da tela física: esse desvio, que
/// antes passava pela fumaça, agora não chega ao monitor.
///
/// Sozinho, desligar não se vê hoje: a interface também recusa agir no
/// post-mortem, e ela era o único caminho de produção que ainda chegava ao
/// compositor ali — o relógio da barra para com o executor, e o mouse com
/// as interrupções, mascaradas desde a entrada da exceção. A mutação que o
/// tira passa pela fumaça. Ele é a segunda trava, para o próximo caminho
/// que chegar ao compositor sem passar pela interface.
pub fn desligar() {
    DESLIGADO.store(true, Ordering::Release);
}

/// Recompõe `dano` na tela. Chamado por [`crate::tela::descarregar`], com o
/// que o console sujou.
///
/// Devolve falso se não pôde agora — a trava estava tomada —, e quem chama
/// guarda o retângulo para a próxima vez.
///
/// # Por que `try_lock`
///
/// Porque quem chama é a escrita no console, e ela acontece em qualquer
/// lugar — inclusive de dentro do próprio compositor, quando algo que ele
/// chama registra no log. Esperar pela trava ali seria esperar por si mesmo.
pub fn compor(dano: Dano) -> bool {
    if DESLIGADO.load(Ordering::Acquire) {
        return false;
    }
    crate::arch::sem_interrupcoes(|| {
        let Some(mut guarda) = ATIVO.try_lock() else {
            return false;
        };
        let Some(compositor) = guarda.as_mut() else {
            return false;
        };
        // Uma apresentação recusada não devolve falso: o compositor guardou o
        // dano como pendente, e o retângulo do console já foi composto.
        let _ = compositor.compor(dano);
        true
    })
}

/// Apresenta o que outros núcleos compuseram e deixaram pendente — ver
/// [`Compositor::apresentar_pendente`]. Só faz alguma coisa no primeiro
/// núcleo.
///
/// Por `try_lock`, pelo mesmo motivo de [`compor`]: quem chama é o tique do
/// relógio e o cutucão, de dentro de uma interrupção, e o código
/// interrompido pode estar com o compositor na mão. Se estiver, o pendente
/// vai no próximo.
pub fn apresentar_pendente() {
    if DESLIGADO.load(Ordering::Acquire) || !crate::nucleos::e_o_primeiro() {
        return;
    }
    crate::arch::sem_interrupcoes(|| {
        if let Some(mut guarda) = ATIVO.try_lock()
            && let Some(compositor) = guarda.as_mut()
        {
            compositor.apresentar_pendente();
        }
    });
}

/// As camadas da tela, de baixo para cima, começando pelo console. Nenhuma
/// sem compositor.
///
/// # `f` roda sem a trava do compositor
///
/// As camadas são copiadas sob a trava, e `f` é chamada depois, com ela
/// solta. Antes, `f` rodava dentro dela — e o `ui.tree`, para cada janela,
/// pedia a descrição dela às superfícies, tomando a trava delas: a ordem
/// compositor → superfícies. Uma superfície que se pinta ou se move faz o
/// contrário, superfícies → compositor. Com um núcleo só as duas nunca se
/// cruzavam, porque as duas rodam com as interrupções mascaradas; com
/// vários, o executor no primeiro núcleo pedindo a árvore e o Terminal em
/// outro redesenhando a linha que o agente acabou de digitar seguravam uma
/// cada um e esperavam a outra para sempre — com as interrupções do
/// primeiro núcleo desligadas, e com elas o canal. Visto na fumaça do x86 em
/// release, na bancada de integração contínua.
pub fn camadas(mut f: impl FnMut(compositor::InfoCamada)) {
    let mut copia: alloc::vec::Vec<compositor::InfoCamada> = alloc::vec::Vec::with_capacity(64);
    com_compositor(|c| c.camadas(|info| copia.push(info)));
    for info in copia {
        f(info);
    }
}

/// Só para a suíte: a trava do compositor está livre para quem a pedir
/// agora? Tenta algumas vezes — outro núcleo pode estar compondo.
#[cfg(feature = "modo-teste")]
pub fn compositor_alcancavel_de_teste() -> bool {
    (0..10_000).any(|_| crate::arch::sem_interrupcoes(|| ATIVO.try_lock().is_some()))
}

/// A camada de cima em `(x, y)`, sem o cursor nem as invisíveis — ver
/// [`Compositor::camada_em`]. `None` sobre o console, ou sem compositor.
pub fn camada_em(x: u32, y: u32) -> Option<compositor::InfoCamada> {
    com_compositor(|c| c.camada_em(x, y)).flatten()
}

/// Quantas atualizações chegaram à tela, e a última delas.
///
/// Atômicos, e não parte do estado sob a tranca, para o relatório do agente
/// não disputar a tranca com quem está desenhando.
static ATUALIZACOES: AtomicU64 = AtomicU64::new(0);
static ULTIMO_DANO: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// Liga a pilha gráfica sobre a tela que o boot publicou, se houver uma, e
/// põe o console na camada de baixo do compositor.
///
/// Sem tela, não há o que ligar, e isso não é erro: a máquina pode
/// legitimamente não ter uma, e a pilha fica desligada. Sem memória para o
/// compositor, também não: o console continua desenhando direto na tela,
/// como desenhava antes de haver um.
pub fn iniciar() {
    let Some(fisica) = crate::tela::tela_fisica() else {
        crate::log_info!("grafico", "sem tela, pilha grafica desligada");
        return;
    };
    // O adaptador é o de quem mostra a tela: sobre um `virtio-gpu`, o dele;
    // sobre um framebuffer, o linear. Ver `Compositor::novo`.
    let mut compositor = match Compositor::novo(fisica) {
        Ok(c) => c,
        Err(motivo) => {
            crate::log_error!(
                "grafico",
                "compositor nao montado: {}; o console segue direto na tela",
                motivo
            );
            return;
        }
    };
    let nome = compositor.nome();

    // Adotar o que está na tela e desviar o console, sem ninguém escrever no
    // meio: uma linha escrita entre as duas coisas iria para a tela física e
    // faltaria na camada, e a próxima composição daquela região a apagaria.
    crate::arch::sem_interrupcoes(|| {
        compositor.adotar(&fisica);
        let base = compositor.base_do_console();
        *ATIVO.lock() = Some(compositor);
        // SAFETY: a camada do console é do compositor, que acabou de ir para
        // `ATIVO` e vive até o fim do kernel; ela tem a geometria da tela
        // física em quatro bytes por pixel — ver `Compositor::novo`.
        unsafe { crate::tela::desviar_console(base) };
    });
    crate::log_info!(
        "grafico",
        "compositor sobre o adaptador {}, {}x{}; o console e a camada de baixo",
        nome,
        fisica.largura,
        fisica.altura
    );
}

/// Registra, para o relatório, uma atualização que chegou à tela.
///
/// Quem chama é quem atualiza — o compositor, e a suíte. O adaptador não
/// registra sozinho porque ele não sabe se a tela em que escreve é a da
/// máquina ou uma sintética de teste.
pub fn registrar_atualizacao(dano: Dano) {
    ATUALIZACOES.fetch_add(1, Ordering::Relaxed);
    ULTIMO_DANO[0].store((dano.x as u64) << 32 | dano.y as u64, Ordering::Relaxed);
    ULTIMO_DANO[1].store(
        (dano.largura as u64) << 32 | dano.altura as u64,
        Ordering::Relaxed,
    );
}

/// O que o agente enxerga da pilha gráfica.
pub struct Relatorio {
    pub adaptador: &'static str,
    pub telas: usize,
    pub tamanho: Option<(u32, u32)>,
    pub superficies: u64,
    pub bytes_em_superficies: u64,
    pub atualizacoes: u64,
    pub ultimo_dano: Option<Dano>,
    /// Num adaptador que só mostra o que se manda: comandos mandados,
    /// descargas feitas e recusas do dispositivo. `None` num linear, onde não
    /// há o que mandar.
    pub dispositivo: Option<(u64, u64, u64)>,
}

/// O relatório, se a pilha estiver ligada.
pub fn relatorio() -> Option<Relatorio> {
    let (adaptador, telas, tamanho) =
        com_compositor(|c| (c.nome(), c.telas(), c.tamanho_da_tela()))?;

    let (superficies, bytes_em_superficies) = memoria::vivas();
    let atualizacoes = ATUALIZACOES.load(Ordering::Relaxed);
    let ultimo_dano = (atualizacoes > 0).then(|| {
        let origem = ULTIMO_DANO[0].load(Ordering::Relaxed);
        let medida = ULTIMO_DANO[1].load(Ordering::Relaxed);
        Dano::novo(
            (origem >> 32) as u32,
            origem as u32,
            (medida >> 32) as u32,
            medida as u32,
        )
    });

    Some(Relatorio {
        adaptador,
        telas,
        tamanho,
        superficies,
        bytes_em_superficies,
        atualizacoes,
        ultimo_dano,
        dispositivo: crate::tela::precisa_descarregar().then(crate::virtio::gpu::contadores),
    })
}

/// Destrava o adaptador gráfico ativo à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        ATIVO.force_unlock();
    }
}
