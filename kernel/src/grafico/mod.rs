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
//! # O que ainda não existe aqui
//!
//! O compositor — ver o roteiro, fase 10. Há os dois adaptadores, o linear
//! e o [`virtio`], a memória das superfícies com a faixa que volta quando
//! elas saem ([`memoria`]), e o que o agente precisa para saber qual
//! adaptador está ativo e o que ele fez. A árvore semântica mora em
//! [`crate::ui`], porque descreve a interface, e não o adaptador.

pub mod dano;
pub mod linear;
pub(crate) mod memoria;
pub mod virtio;

use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;

pub use dano::Dano;

// Hoje só a suíte desenha por aqui: quem vai criar superfícies e atualizar a
// tela em produção é o compositor, que é o próximo passo da fase 10. Até lá a
// anotação mantém o build de produção limpo sem esconder código morto de
// verdade — na compilação de teste, onde há consumidor, ela não vale, e o que
// sobrar sem uso lá aparece. Quando o compositor chegar, ela some.
/// Um buffer de pixels onde se desenha antes de a tela ver.
///
/// Os pixels estão no formato de [`crate::tela::Cor::para_u32`].
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub trait Superficie {
    fn largura(&self) -> u32;
    fn altura(&self) -> u32;
    fn pixels(&self) -> &[u32];
    fn pixels_mut(&mut self) -> &mut [u32];
    /// Quanta memória a superfície segura — o que o relatório do agente mede.
    fn bytes(&self) -> u64;
}

/// O que um adaptador de vídeo precisa saber fazer.
///
/// Porte de `GraphicsAdapter` do Redox — ver o cabeçalho do módulo para o
/// que mudou e por quê.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
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

/// O adaptador que esta máquina usa.
///
/// Uma enumeração, e não um objeto de trait, porque o trait tem tipo
/// associado — e a lista de adaptadores é pequena e conhecida.
pub enum Adaptador {
    Linear(linear::AdaptadorLinear),
    Virtio(virtio::AdaptadorVirtio),
}

impl Adaptador {
    pub fn nome(&self) -> &'static str {
        match self {
            Adaptador::Linear(a) => a.nome(),
            Adaptador::Virtio(a) => a.nome(),
        }
    }

    pub fn tamanho_da_tela(&self, tela: usize) -> Option<(u32, u32)> {
        match self {
            Adaptador::Linear(a) => a.tamanho_da_tela(tela),
            Adaptador::Virtio(a) => a.tamanho_da_tela(tela),
        }
    }

    pub fn telas(&self) -> usize {
        match self {
            Adaptador::Linear(a) => a.telas(),
            Adaptador::Virtio(a) => a.telas(),
        }
    }
}

// A tomada desta tranca passa por `sem_interrupcoes`, pelo motivo de toda
// tranca deste kernel: um handler que a pedisse enquanto ela estivesse na mão
// do código interrompido giraria para sempre.
static ATIVO: Mutex<Option<Adaptador>> = Mutex::new(None);

/// Quantas atualizações chegaram à tela, e a última delas.
///
/// Atômicos, e não parte do estado sob a tranca, para o relatório do agente
/// não disputar a tranca com quem está desenhando.
static ATUALIZACOES: AtomicU64 = AtomicU64::new(0);
static ULTIMO_DANO: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// Liga a pilha gráfica sobre a tela que o boot publicou, se houver uma.
///
/// Sem tela, não há o que ligar, e isso não é erro: a máquina pode
/// legitimamente não ter uma, e a pilha fica desligada.
pub fn iniciar() {
    let Some(tela) = crate::tela::tela() else {
        crate::log_info!("grafico", "sem tela, pilha grafica desligada");
        return;
    };
    // O adaptador é o de quem mostra a tela. Se ela mora sobre um
    // `virtio-gpu`, copiar superfícies para dentro dela como o linear faz
    // escreveria numa memória que ninguém descarrega — nada apareceria.
    let adaptador = if crate::virtio::gpu::tem_a_tela() {
        Adaptador::Virtio(virtio::AdaptadorVirtio)
    } else {
        Adaptador::Linear(linear::AdaptadorLinear::novo(tela))
    };
    crate::log_info!(
        "grafico",
        "adaptador {} sobre {}x{}",
        adaptador.nome(),
        tela.largura,
        tela.altura
    );
    crate::arch::sem_interrupcoes(|| *ATIVO.lock() = Some(adaptador));
}

/// Registra, para o relatório, uma atualização que chegou à tela.
///
/// Quem chama é quem atualiza — o compositor, quando existir, e hoje a
/// suíte. O adaptador não registra sozinho porque ele não sabe se a tela em
/// que escreve é a da máquina ou uma sintética de teste.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
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
    let (adaptador, telas, tamanho) = crate::arch::sem_interrupcoes(|| {
        ATIVO
            .lock()
            .as_ref()
            .map(|a| (a.nome(), a.telas(), a.tamanho_da_tela(0)))
    })?;

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
