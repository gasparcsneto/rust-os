//! O framebuffer: desenhar na tela.
//!
//! # Para que serve numa máquina operada por agente
//!
//! Um agente não olha para uma tela. A pergunta legítima, então, é por que um
//! kernel agent-native desenha alguma coisa.
//!
//! A resposta é o momento em que o canal do agente **não** responde. Um
//! kernel que morre antes de a serial subir, ou que morre de um jeito que
//! leva a serial junto, não tem como contar o que houve — e é exatamente aí
//! que a tela é o último canal que sobra. É o mesmo raciocínio do modo
//! post-mortem, aplicado a uma falha anterior.
//!
//! O segundo motivo é simétrico: a tela precisa ser **legível pelo agente**.
//! Desenhar sem poder conferir o que foi desenhado seria acrescentar uma
//! superfície que ninguém consegue testar. Daí [`Tela::ler_pixel`] existir ao
//! lado de [`Tela::retangulo`], e o comando `video.sample` devolver uma amostra em
//! grade — a forma de um agente enxergar a tela sem ter olhos.
//!
//! # Por que aqui e não em `machine`
//!
//! [`crate::machine`] descreve a máquina, e a descrição vive atrás de um
//! `Mutex`. Isso é certo para um mapa de memória consultado pelo canal do
//! agente, e errado para o que a tela precisa ser: alcançável de dentro de um
//! handler de exceção fatal, que é justamente onde alguém pode estar
//! segurando aquela trava.
//!
//! Por isso o estado aqui é atômico, e por isso a geometria mora aqui e não
//! lá. Duas cópias da mesma geometria seriam duas coisas que podem divergir.

pub mod bochs;
pub mod console;

/// Altura do traço de acento que o banner desenha sob o topo da tela.
///
/// Com compositor, a barra superior fica por cima dele, e o indicador de
/// kernel vivo passa a ser a linha de acento da barra.
///
/// Mora aqui, e não dentro de [`banner`], porque o console de texto precisa
/// saber onde ele acaba: a faixa é do banner, e limpar a tela inteira para
/// recomeçar uma página de texto apagaria o indicador de que há um kernel
/// vivo. Foi o que aconteceu — o caso `tela: o banner esta na tela de
/// verdade` reprovou assim que o console passou a escrever.
pub(crate) const ALTURA_DO_ACENTO: u32 = 3;

/// Altura da barra superior, que o compositor põe por cima do topo da tela.
///
/// Mora aqui pelo mesmo motivo da faixa de acento: o console precisa saber
/// onde ela acaba, para começar abaixo dela e para não limpar por baixo
/// dela à toa. Sem compositor não há barra, e a faixa fica vazia — o
/// console não muda de lugar conforme ela existe ou não, e o texto de uma
/// máquina e da outra cai nas mesmas linhas.
pub(crate) const ALTURA_DA_BARRA: u32 = 24;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Como os bytes de um pixel são ordenados na memória.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Formato {
    /// Vermelho, verde, azul, nessa ordem.
    Rgb,
    /// Azul, verde, vermelho — a ordem mais comum em firmware de PC.
    Bgr,
    /// Um byte só, de luminância.
    Cinza,
}

impl Formato {
    /// O código com que o formato é guardado num atômico.
    const fn codigo(self) -> u32 {
        match self {
            Formato::Rgb => 1,
            Formato::Bgr => 2,
            Formato::Cinza => 3,
        }
    }

    fn de_codigo(codigo: u32) -> Option<Formato> {
        match codigo {
            1 => Some(Formato::Rgb),
            2 => Some(Formato::Bgr),
            3 => Some(Formato::Cinza),
            _ => None,
        }
    }

    /// Quantos bytes de cada pixel este formato lê e escreve.
    ///
    /// Não é o mesmo que `bytes_por_pixel`: uma tela de 32 bits guarda quatro
    /// bytes por pixel e este formato só toca três, deixando o quarto —
    /// tipicamente o alfa — como estava. O que **não** pode acontecer é o
    /// contrário: um formato que toque mais bytes do que o pixel tem faz a
    /// leitura do último pixel da tela cair para fora dela.
    const fn bytes_tocados(self) -> u32 {
        match self {
            Formato::Rgb | Formato::Bgr => 3,
            Formato::Cinza => 1,
        }
    }

    /// O nome que o relatório do agente usa.
    pub fn como_str(self) -> &'static str {
        match self {
            Formato::Rgb => "rgb",
            Formato::Bgr => "bgr",
            Formato::Cinza => "grayscale8",
        }
    }
}

/// Uma cor, independente de como a placa a guarda.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Cor {
    pub const fn nova(r: u8, g: u8, b: u8) -> Cor {
        Cor { r, g, b }
    }

    /// A cor como um pixel de superfície: `0x00RRGGBB`.
    ///
    /// # Por que este formato
    ///
    /// É o do Redox e do `orbclient`, de onde vem a pilha gráfica — e não por
    /// deferência: num little-endian, `0x00RRGGBB` fica na memória como
    /// `BB GG RR 00`, que é exatamente um pixel BGR de quatro bytes. O formato
    /// mais comum em firmware de PC, e o das duas máquinas desta suíte, é
    /// então uma cópia sem conversão nenhuma.
    pub const fn para_u32(self) -> u32 {
        (self.r as u32) << 16 | (self.g as u32) << 8 | self.b as u32
    }

    /// O inverso de [`Cor::para_u32`]. O byte alto é ignorado.
    pub const fn de_u32(pixel: u32) -> Cor {
        Cor::nova((pixel >> 16) as u8, (pixel >> 8) as u8, pixel as u8)
    }

    /// A luminância aproximada, para telas de um byte por pixel.
    ///
    /// Os pesos são os da percepção humana — o verde domina, o azul quase não
    /// conta. Uma média simples faria o azul puro e o verde puro virarem o
    /// mesmo cinza, que é visivelmente errado.
    const fn luminancia(self) -> u8 {
        ((self.r as u32 * 30 + self.g as u32 * 59 + self.b as u32 * 11) / 100) as u8
    }

    /// As duas cores extremas, usadas pela suíte para conferir a ida e volta
    /// de cada formato. Nenhum desenho do kernel as usa: um preto puro e um
    /// branco puro na tela não comunicam nada.
    #[cfg(feature = "modo-teste")]
    pub const PRETO: Cor = Cor::nova(0, 0, 0);
    #[cfg(feature = "modo-teste")]
    pub const BRANCO: Cor = Cor::nova(0xFF, 0xFF, 0xFF);
    /// O fundo do banner de boot: um azul escuro que não cansa numa tela
    /// ligada o tempo todo.
    pub const FUNDO: Cor = Cor::nova(0x10, 0x18, 0x28);
    /// A faixa de acento do banner.
    pub const ACENTO: Cor = Cor::nova(0x3A, 0x8F, 0xD0);
    /// O fundo da tela de falha fatal.
    pub const FALHA: Cor = Cor::nova(0x60, 0x10, 0x10);
}

// O estado é atômico, e não um `Mutex`, porque a tela precisa ser alcançável
// de dentro de um handler de exceção fatal. Ver a nota no topo do módulo.
static BASE: AtomicU64 = AtomicU64::new(0);
static LARGURA: AtomicU32 = AtomicU32::new(0);
static ALTURA: AtomicU32 = AtomicU32::new(0);
static STRIDE: AtomicU32 = AtomicU32::new(0);
static BYTES_POR_PIXEL: AtomicU32 = AtomicU32::new(0);
static FORMATO: AtomicU32 = AtomicU32::new(0);

/// Quem precisa ser avisado para a tela física mostrar o que se escreveu
/// nela.
///
/// Nenhum, num framebuffer linear: o dispositivo varre a memória sozinho, e o
/// que se escreve aparece. Um adaptador como o `virtio-gpu` não varre nada —
/// só mostra o que lhe mandam —, e então a tela anota o retângulo que sujou e
/// o entrega a ele em [`descarregar`].
///
/// Um atômico, e não uma trava, porque a tela é alcançável do caminho de
/// falha fatal. Zero é "ninguém".
static DESCARREGADOR: AtomicU32 = AtomicU32::new(0);
const DESCARREGADOR_VIRTIO: u32 = 1;

/// Onde o console desenha quando há compositor: a camada de baixo, em
/// memória comum. Zero enquanto ele desenha direto na tela física.
///
/// # Por que duas telas
///
/// Porque o console deixou de ser a tela e passou a ser uma camada dela. Com
/// janelas por cima, desenhar direto no framebuffer escreveria **sobre** elas
/// — e redesenhá-las depois de cada letra faria o texto piscar por baixo. O
/// console escreve na camada dele, e o compositor põe na tela física o que
/// cada camada deixa ver.
///
/// A tela física continua registrada e continua sendo a do caminho de falha
/// fatal: [`falha`] zera este desvio e pinta direto nela, sem compositor, sem
/// trava e sem heap — que é o que se pode ter ali.
///
/// A geometria da camada é a da tela física, com o formato das superfícies
/// ([`Cor::para_u32`], quatro bytes por pixel, uma linha de `largura`
/// pixels). Só a base muda.
static BASE_DO_CONSOLE: AtomicU64 = AtomicU64::new(0);

/// O retângulo sujo desde a última descarga: `[x0, x1) × [y0, y1)`.
///
/// Vazio quando `x0 >= x1`. Quatro atômicos que crescem por mínimo e máximo:
/// quem escreve só alarga, e quem descarrega troca pelo vazio. Entre as duas
/// coisas não há corrida de verdade — as escritas na tela acontecem com as
/// interrupções mascaradas, num núcleo só —, e se um dia houver, o pior
/// desfecho é descarregar um pouco a mais.
static SUJO_X0: AtomicU32 = AtomicU32::new(u32::MAX);
static SUJO_Y0: AtomicU32 = AtomicU32::new(u32::MAX);
static SUJO_X1: AtomicU32 = AtomicU32::new(0);
static SUJO_Y1: AtomicU32 = AtomicU32::new(0);

/// Um framebuffer linear pronto para desenhar.
#[derive(Clone, Copy, Debug)]
pub struct Tela {
    base: u64,
    pub largura: u32,
    pub altura: u32,
    /// Pixels de uma linha à seguinte, que pode exceder a largura visível.
    ///
    /// A distinção importa: escrever `largura` pixels e pular para a linha
    /// seguinte sem contar o excedente produz uma imagem inclinada, que é o
    /// sintoma clássico de confundir os dois.
    pub stride: u32,
    pub bytes_por_pixel: u32,
    pub formato: Formato,
}

/// Registra o framebuffer que esta máquina oferece.
///
/// Uma geometria que não se sustenta é recusada: a tela não é publicada, o
/// kernel segue sem ela, e o motivo vai para o log. Ver [`geometria_coerente`].
///
/// # Safety
///
/// `base` precisa ser um endereço virtual válido, já mapeado e gravável, de
/// uma região com pelo menos `stride * altura * bytes_por_pixel` bytes.
pub unsafe fn registrar(
    base: u64,
    largura: u32,
    altura: u32,
    stride: u32,
    bytes_por_pixel: u32,
    formato: Formato,
) {
    if !geometria_coerente(largura, altura, stride, bytes_por_pixel, formato) {
        crate::log_error!(
            "tela",
            "geometria recusada: {}x{}, stride {}, {} bytes por pixel, formato {}",
            largura,
            altura,
            stride,
            bytes_por_pixel,
            formato.como_str()
        );
        return;
    }

    LARGURA.store(largura, Ordering::Relaxed);
    ALTURA.store(altura, Ordering::Relaxed);
    STRIDE.store(stride, Ordering::Relaxed);
    BYTES_POR_PIXEL.store(bytes_por_pixel, Ordering::Relaxed);
    FORMATO.store(formato.codigo(), Ordering::Relaxed);

    // A base vai por último, e com `Release`: ela é o que [`tela`] usa para
    // decidir que há um framebuffer, então publicá-la antes da geometria
    // abriria uma janela em que alguém desenharia com largura zero.
    BASE.store(base, Ordering::Release);
}

/// A partir de agora, o que se escreve na tela precisa ser levado ao
/// dispositivo por `quem`. Ver [`DESCARREGADOR`].
pub fn descarregar_por(quem: crate::virtio::gpu::Descarregador) {
    match quem {
        crate::virtio::gpu::Descarregador::Virtio => {
            DESCARREGADOR.store(DESCARREGADOR_VIRTIO, Ordering::Release)
        }
    }
}

/// A tela física precisa ser descarregada para aparecer?
pub fn precisa_descarregar() -> bool {
    DESCARREGADOR.load(Ordering::Acquire) != 0
}

/// Desvia o console para uma camada do compositor.
///
/// Daqui em diante [`tela`] devolve a camada, e o que se escreve nela é
/// levado à tela física pelo compositor, em [`descarregar`].
///
/// # Safety
///
/// `base` precisa ter `largura * altura * 4` bytes mapeados e graváveis,
/// com a geometria da tela física, e viver enquanto o desvio durar.
pub unsafe fn desviar_console(base: u64) {
    BASE_DO_CONSOLE.store(base, Ordering::Release);
}

/// O console está numa camada do compositor?
pub fn console_desviado() -> bool {
    BASE_DO_CONSOLE.load(Ordering::Acquire) != 0
}

/// A base da tela cujas escritas são anotadas no retângulo sujo, ou zero.
///
/// A camada do console, se ele estiver desviado — o compositor leva o que
/// ela sujou. Senão a tela física, se ela precisar ser descarregada. Senão
/// ninguém: um framebuffer linear sem compositor mostra o que se escreve.
fn base_rastreada() -> u64 {
    let console = BASE_DO_CONSOLE.load(Ordering::Relaxed);
    if console != 0 {
        console
    } else if DESCARREGADOR.load(Ordering::Relaxed) != 0 {
        BASE.load(Ordering::Relaxed)
    } else {
        0
    }
}

/// Leva à tela física o que o console sujou desde a última vez.
///
/// Chamada depois de cada escrita no console, do banner e da tela de falha.
/// Com o console numa camada, quem leva é o compositor; sem, e num
/// `virtio-gpu`, o dispositivo; num framebuffer linear sem compositor, não
/// há o que fazer. Se quem leva não pôde agora, o retângulo volta a ser
/// sujo e vai junto com a próxima escrita — nada se perde, só atrasa.
pub fn descarregar() {
    let desviado = console_desviado();
    if !desviado && DESCARREGADOR.load(Ordering::Acquire) != DESCARREGADOR_VIRTIO {
        return;
    }
    let x0 = SUJO_X0.swap(u32::MAX, Ordering::Relaxed);
    let y0 = SUJO_Y0.swap(u32::MAX, Ordering::Relaxed);
    let x1 = SUJO_X1.swap(0, Ordering::Relaxed);
    let y1 = SUJO_Y1.swap(0, Ordering::Relaxed);
    if x0 >= x1 || y0 >= y1 {
        return;
    }
    let levou = if desviado {
        crate::grafico::compor(crate::grafico::Dano::novo(x0, y0, x1 - x0, y1 - y0))
    } else {
        crate::virtio::gpu::descarregar_tela(crate::virtio::gpu::Retangulo {
            x: x0,
            y: y0,
            largura: x1 - x0,
            altura: y1 - y0,
        })
    };
    if !levou {
        sujar(x0, y0, x1, y1);
    }
}

/// Alarga o retângulo sujo para cobrir `[x0, x1) × [y0, y1)`.
fn sujar(x0: u32, y0: u32, x1: u32, y1: u32) {
    SUJO_X0.fetch_min(x0, Ordering::Relaxed);
    SUJO_Y0.fetch_min(y0, Ordering::Relaxed);
    SUJO_X1.fetch_max(x1, Ordering::Relaxed);
    SUJO_Y1.fetch_max(y1, Ordering::Relaxed);
}

/// O retângulo sujo agora, sem tocá-lo. Para a suíte.
#[cfg(feature = "modo-teste")]
pub fn sujo() -> Option<(u32, u32, u32, u32)> {
    let (x0, y0) = (
        SUJO_X0.load(Ordering::Relaxed),
        SUJO_Y0.load(Ordering::Relaxed),
    );
    let (x1, y1) = (
        SUJO_X1.load(Ordering::Relaxed),
        SUJO_Y1.load(Ordering::Relaxed),
    );
    (x0 < x1 && y0 < y1).then_some((x0, y0, x1, y1))
}

/// Adota a tela que o iniciador entregou, se ele entregou uma.
///
/// Devolve se o kernel ficou com um framebuffer publicado — o que é menos
/// que "a entrega trazia um": uma geometria incoerente é recusada por
/// [`registrar`], e quem chama precisa saber a diferença para não anunciar
/// uma tela que não existe.
///
/// # Por que a tradução mora aqui e não em cada arquitetura
///
/// Porque ela morava em cada arquitetura, e as duas cópias já tinham
/// divergido do pior jeito possível: o x86 adotava a tela desde o primeiro
/// dia, e o ARM lia a mesma entrega, **descartava** o vídeo dela e ia
/// procurar um adaptador no PCI. O resultado era uma máquina com duas telas
/// — a que o firmware configurou e ninguém usava, e a que o kernel
/// programava depois — e ninguém percebia, porque as duas desenhavam.
///
/// Com um lugar só, adotar a entrega é a mesma decisão nas duas pontas, e a
/// tradução de `formato` não tem como ficar para trás de um lado.
///
/// # Safety
///
/// `video.em` precisa ser um endereço já mapeado e gravável no espaço que
/// está ativo, com pelo menos `pixels_por_linha * altura * bytes_por_pixel`
/// bytes — as mesmas condições de [`registrar`], que é quem publica.
pub unsafe fn adotar(video: &protocolo::Video) -> bool {
    if video.presente == 0 {
        return false;
    }

    // SAFETY: delegada a quem chama.
    unsafe {
        registrar(
            video.em,
            video.largura,
            video.altura,
            video.pixels_por_linha,
            video.bytes_por_pixel,
            match video.formato {
                protocolo::formato::RGB => Formato::Rgb,
                protocolo::formato::BGR => Formato::Bgr,
                // Um formato que este kernel não sabe desenhar vira cinza: é
                // uma escolha visível, e melhor que escrever bytes na ordem
                // errada e produzir cores trocadas sem ninguém saber por quê.
                _ => Formato::Cinza,
            },
        );
    }

    tela_fisica().is_some()
}

/// A geometria descreve uma tela em que a aritmética de pixel se sustenta?
///
/// # O que cada condição protege
///
/// A segurança de [`Tela::endereco`] não vem só do tamanho da região: ela vem
/// de o endereço de todo pixel **dentro da tela** cair dentro dela. Duas
/// relações sustentam isso, e nenhuma das duas estava escrita em lugar nenhum.
///
/// A primeira é `stride >= largura`. O limite que a função confere é a
/// largura, mas o endereço que ela calcula usa o stride: com um stride menor,
/// o pixel mais à direita da última linha cai depois do fim da região — e a
/// condição de segurança de [`registrar`], que fala em
/// `stride * altura * bytes_por_pixel` bytes, não o impede.
///
/// A segunda é `bytes_por_pixel >= bytes_tocados`. O leitor de um pixel RGB
/// lê três bytes a partir do começo dele; num framebuffer que declarasse um
/// byte por pixel, os dois últimos viriam de fora da tela na última posição.
///
/// Nenhuma das duas acontece com um bootloader que funciona. As duas são
/// baratas de conferir uma vez no boot, e o que elas evitam — uma escrita
/// fora da região — não tem sintoma local: aparece como memória alheia
/// corrompida, longe daqui.
fn geometria_coerente(
    largura: u32,
    altura: u32,
    stride: u32,
    bytes_por_pixel: u32,
    formato: Formato,
) -> bool {
    largura > 0 && altura > 0 && stride >= largura && bytes_por_pixel >= formato.bytes_tocados()
}

/// Uma tela sobre memória que quem chama possui, sem publicá-la.
///
/// Existe para a suíte exercitar formatos que nenhuma das duas máquinas de
/// teste tem. As duas são BGR de quatro bytes por pixel, então um desenho que
/// errasse RGB ou três bytes por pixel passaria em todas as rodadas — e só
/// apareceria na primeira máquina de verdade com outra placa.
///
/// A geometria passa pela mesma conferência de [`registrar`].
///
/// # Safety
///
/// As mesmas de [`registrar`]: `base` mapeado, gravável, com pelo menos
/// `stride * altura * bytes_por_pixel` bytes, e vivo enquanto a tela durar.
#[cfg(feature = "modo-teste")]
pub unsafe fn sintetica(
    base: u64,
    largura: u32,
    altura: u32,
    stride: u32,
    bytes_por_pixel: u32,
    formato: Formato,
) -> Option<Tela> {
    if base == 0 || !geometria_coerente(largura, altura, stride, bytes_por_pixel, formato) {
        return None;
    }
    Some(Tela {
        base,
        largura,
        altura,
        stride,
        bytes_por_pixel,
        formato,
    })
}

/// A tela onde o console desenha, se houver uma.
///
/// A camada do console, quando há compositor; a tela física, antes dele e
/// depois de uma falha fatal. Quem desenha texto quer esta. Quem quer saber o
/// que o monitor mostra quer [`tela_fisica`].
pub fn tela() -> Option<Tela> {
    let fisica = tela_fisica()?;
    let console = BASE_DO_CONSOLE.load(Ordering::Acquire);
    if console == 0 {
        return Some(fisica);
    }
    Some(Tela {
        base: console,
        largura: fisica.largura,
        altura: fisica.altura,
        stride: fisica.largura,
        bytes_por_pixel: 4,
        formato: Formato::Bgr,
    })
}

/// A tela que o monitor mostra: o framebuffer, ou a memória do recurso do
/// `virtio-gpu` que está na varredura.
pub fn tela_fisica() -> Option<Tela> {
    let base = BASE.load(Ordering::Acquire);
    if base == 0 {
        return None;
    }

    let formato = Formato::de_codigo(FORMATO.load(Ordering::Relaxed))?;
    let largura = LARGURA.load(Ordering::Relaxed);
    let altura = ALTURA.load(Ordering::Relaxed);

    (largura > 0 && altura > 0).then_some(Tela {
        base,
        largura,
        altura,
        stride: STRIDE.load(Ordering::Relaxed),
        bytes_por_pixel: BYTES_POR_PIXEL.load(Ordering::Relaxed),
        formato,
    })
}

impl Tela {
    /// Uma tela sobre uma região qualquer de memória.
    ///
    /// Existe para a suíte: ela monta uma tela minúscula sobre um buffer na
    /// pilha e exercita a aritmética de pixel — a ordem dos bytes de cada
    /// formato, o recorte na borda, e a diferença entre largura e stride.
    ///
    /// Sem isto, essa aritmética só seria testada onde há framebuffer de
    /// verdade, ou seja, só no x86. Ela não tem nada de específico de
    /// arquitetura, e testá-la em uma só seria testar metade.
    ///
    /// # Safety
    ///
    /// `base` precisa apontar para pelo menos
    /// `stride * altura * bytes_por_pixel` bytes graváveis, e a geometria
    /// precisa satisfazer [`geometria_coerente`] — este construtor não passa
    /// por [`registrar`], então é o chamador quem garante as duas relações de
    /// que a aritmética de pixel depende.
    #[cfg(feature = "modo-teste")]
    pub const unsafe fn sobre(
        base: u64,
        largura: u32,
        altura: u32,
        stride: u32,
        bytes_por_pixel: u32,
        formato: Formato,
    ) -> Tela {
        Tela {
            base,
            largura,
            altura,
            stride,
            bytes_por_pixel,
            formato,
        }
    }

    /// Onde a tela mora e quantos bytes ela ocupa.
    ///
    /// Existe para quem precisa tratá-la como **região de memória** em vez de
    /// como grade de pixels: o mapa de identidade do ARM, que tem de garantir
    /// que o framebuffer continue endereçável depois de a MMU ligar, e a
    /// linha de log que o anuncia. Deduzir a extensão fora daqui seria
    /// repetir a multiplicação que [`geometria_coerente`] valida, num lugar
    /// onde ninguém a valida.
    pub fn faixa(&self) -> (u64, u64) {
        // Saturante, e não a multiplicação direta: os três fatores vêm da
        // entrega do iniciador, que é dado de fora, e
        // [`geometria_coerente`] confere as relações entre eles sem limitar
        // a magnitude de nenhum. Três `u32` no teto estouram um `u64`, o que
        // numa compilação de depuração é pânico — e chegar aqui já significa
        // que algo antes falhou, então o desfecho certo é um número grande
        // demais para ser aceito adiante, e não a morte do kernel.
        let bytes = (self.stride as u64)
            .saturating_mul(self.altura as u64)
            .saturating_mul(self.bytes_por_pixel as u64);
        (self.base, bytes)
    }

    /// Anota que `[x0, x1) × [y0, y1)` mudou, se esta for a tela da máquina e
    /// ela precisar ser descarregada.
    ///
    /// A comparação da base é o que deixa de fora as telas sintéticas da
    /// suíte — elas desenham em memória de quem as criou, e sujá-las não diz
    /// nada sobre o que o monitor mostra — e a tela física quando o console
    /// está numa camada: aí quem escreve nela é o compositor, que já sabe o
    /// que escreveu.
    fn sujar(&self, x0: u32, y0: u32, x1: u32, y1: u32) {
        let rastreada = base_rastreada();
        if rastreada != 0 && self.base == rastreada {
            sujar(x0, y0, x1, y1);
        }
    }

    /// Onde os bytes de um pixel começam, se ele estiver dentro da tela.
    fn endereco(&self, x: u32, y: u32) -> Option<*mut u8> {
        if x >= self.largura || y >= self.altura {
            return None;
        }
        let dentro = (y as u64 * self.stride as u64 + x as u64) * self.bytes_por_pixel as u64;
        Some((self.base + dentro) as *mut u8)
    }

    /// Lê a cor de um pixel.
    ///
    /// Existe para que a tela seja **verificável**. Uma superfície de
    /// desenho sem leitura é uma superfície que só um humano olhando confirma
    /// — o que não serve nem para o teste automatizado nem para o agente.
    ///
    /// Num framebuffer de um byte por pixel a volta não é exata: a cor foi
    /// reduzida a luminância na escrita, e o que volta é um cinza. É o
    /// formato que perde a informação, não a leitura.
    pub fn ler_pixel(&self, x: u32, y: u32) -> Option<Cor> {
        let ponteiro = self.endereco(x, y)?;

        // SAFETY: mesma justificativa da escrita.
        unsafe {
            Some(match self.formato {
                Formato::Rgb => Cor::nova(
                    core::ptr::read_volatile(ponteiro),
                    core::ptr::read_volatile(ponteiro.add(1)),
                    core::ptr::read_volatile(ponteiro.add(2)),
                ),
                Formato::Bgr => Cor::nova(
                    core::ptr::read_volatile(ponteiro.add(2)),
                    core::ptr::read_volatile(ponteiro.add(1)),
                    core::ptr::read_volatile(ponteiro),
                ),
                Formato::Cinza => {
                    let luz = core::ptr::read_volatile(ponteiro);
                    Cor::nova(luz, luz, luz)
                }
            })
        }
    }

    /// Os bytes de um pixel desta cor, na ordem que este formato usa.
    ///
    /// Devolve quantos bytes valem. Separar isto do desenho é o que permite a
    /// um preenchimento converter a cor **uma vez** em vez de uma vez por
    /// pixel.
    ///
    /// # Por que é o único lugar que conhece a ordem
    ///
    /// Porque houve dois. O desenho de um pixel só — que existiu antes de
    /// [`Tela::retangulo`] e foi absorvido por ele — tinha a sua própria
    /// conversão, e este preenchimento tinha outra: as duas certas, até que
    /// uma mudasse.
    /// Trocar a ordem aqui e deixar a de lá intacta produzia uma tela com as
    /// cores invertidas que o teste de ida e volta de formato **não** pegava,
    /// porque ele só exercitava o outro caminho.
    ///
    /// Uma ordem de bytes escrita em dois lugares é uma ordem de bytes que vai
    /// divergir. Hoje só [`Tela::retangulo`] escreve, e um pixel solto é um
    /// retângulo de um por um — não há segundo caminho para divergir.
    fn bytes_da_cor(&self, cor: Cor) -> ([u8; 4], usize) {
        match self.formato {
            Formato::Rgb => ([cor.r, cor.g, cor.b, 0], 3),
            Formato::Bgr => ([cor.b, cor.g, cor.r, 0], 3),
            Formato::Cinza => ([cor.luminancia(), 0, 0, 0], 1),
        }
    }

    /// Pinta um retângulo, recortado na borda da tela.
    ///
    /// # Por que não é um laço sobre um desenho de pixel
    ///
    /// Porque era, e custava caro. Cada chamada recalculava o endereço — uma
    /// multiplicação e duas comparações de limite — para um pixel que já se
    /// sabia estar dentro, e reconvertia a cor para bytes. Limpar uma tela de
    /// 1280x720 assim levava quase meio segundo num emulador sem aceleração.
    ///
    /// Aqui o recorte acontece uma vez, a cor é convertida uma vez, e cada
    /// linha avança por soma em vez de multiplicação. As escritas continuam
    /// voláteis pelo mesmo motivo de sempre: quem lê este buffer não é este
    /// programa.
    ///
    /// Medido no mesmo emulador, limpando a mesma tela: 450 ms antes, 250 ms
    /// depois. Uma versão intermediária, que percorria os bytes da cor com um
    /// iterador, chegou a 800 ms — o laço mais interno roda uma vez por
    /// pixel, e ali um iterador custa mais que os acessos que ele economiza.
    ///
    /// **Esses três números são de `debug`, e não diziam.** A omissão é o
    /// defeito: por anos eles foram lidos como o custo de desenhar, e o custo
    /// de desenhar no binário que se entrega é outro. Remedido, com os quatro
    /// perfis nomeados:
    ///
    /// | | x86_64 | aarch64 |
    /// |---|---|---|
    /// | release | 7,3 ms | 8,0 ms |
    /// | debug | 637 ms | 603 ms |
    ///
    /// Oitenta e cinco vezes entre um e outro. Em release são 4,1 MiB em 7 ms,
    /// ou uns 550 MiB/s — cento e trinta telas cheias por segundo, com folga
    /// para um compositor a 60 Hz.
    ///
    /// O número não mora mais aqui: quem o mede é
    /// `tela_desenhar_nao_regrediu_em_ordem_de_grandeza`, a cada rodada da
    /// suíte, com um teto por perfil. Uma medida escrita num comentário vale
    /// até a próxima mudança; esta vale sempre.
    pub fn retangulo(&self, x: u32, y: u32, largura: u32, altura: u32, cor: Cor) {
        let fim_x = x.saturating_add(largura).min(self.largura);
        let fim_y = y.saturating_add(altura).min(self.altura);
        if x >= fim_x || y >= fim_y {
            return;
        }
        self.sujar(x, y, fim_x, fim_y);

        let (bytes, quantos) = self.bytes_da_cor(cor);
        let passo = self.bytes_por_pixel as u64;
        let linha_a_linha = self.stride as u64 * passo;
        let mut inicio_da_linha = self.base + y as u64 * linha_a_linha + x as u64 * passo;

        for _ in y..fim_y {
            let mut ponteiro = inicio_da_linha as *mut u8;
            for _ in x..fim_x {
                // SAFETY: o recorte acima confinou o retângulo à tela, e o
                // registro garantiu que a tela inteira está mapeada e é
                // gravável. O ponteiro avança dentro dessa faixa.
                // Escritas explícitas, e não um laço sobre os bytes: o laço
                // interno roda uma vez por pixel, e um iterador ali dentro
                // custa mais que os três acessos que ele economiza — medido,
                // quase o dobro do tempo num build de depuração.
                unsafe {
                    core::ptr::write_volatile(ponteiro, bytes[0]);
                    if quantos == 3 {
                        core::ptr::write_volatile(ponteiro.add(1), bytes[1]);
                        core::ptr::write_volatile(ponteiro.add(2), bytes[2]);
                    }
                    ponteiro = ponteiro.add(passo as usize);
                }
            }
            inicio_da_linha += linha_a_linha;
        }
    }

    /// Escreve uma sequência de pixels de superfície a partir de `(x, y)`.
    ///
    /// Os pixels vêm no formato de [`Cor::para_u32`] e saem no formato do
    /// hardware. É o que um adaptador gráfico chama para cada linha de um
    /// retângulo de dano — e mora aqui, e não no adaptador, porque saber como
    /// esta placa guarda um pixel é assunto desta estrutura e de mais
    /// nenhuma. Dois lugares com essa resposta divergiriam no primeiro
    /// formato novo.
    ///
    /// O que passar da borda direita, ou uma linha fora da tela, é descartado
    /// em silêncio: o recorte é trabalho de quem chama, e aqui ele só impede
    /// que um erro de quem chama vire escrita fora do framebuffer.
    ///
    /// # O caminho rápido
    ///
    /// BGR de quatro bytes por pixel — as duas máquinas da suíte — é uma
    /// escrita de 32 bits por pixel, sem conversão. Os outros formatos
    /// convertem pixel a pixel. As escritas continuam voláteis pelo motivo
    /// de sempre: quem lê este buffer não é este programa.
    pub fn copiar_linha(&self, x: u32, y: u32, pixels: &[u32]) {
        if y >= self.altura || x >= self.largura {
            return;
        }
        let cabem = (self.largura - x) as usize;
        let pixels = &pixels[..pixels.len().min(cabem)];
        self.sujar(x, y, x + pixels.len() as u32, y + 1);

        let Some(inicio) = self.endereco(x, y) else {
            return;
        };

        if self.formato == Formato::Bgr && self.bytes_por_pixel == 4 {
            let destino = inicio as *mut u32;
            for (i, &pixel) in pixels.iter().enumerate() {
                // SAFETY: `x + i` está abaixo da largura pelo corte acima, e
                // `y` abaixo da altura; o registro garantiu a região mapeada e
                // gravável. Quatro bytes por pixel e base alinhada a página
                // deixam cada endereço alinhado a 32 bits.
                unsafe { core::ptr::write_volatile(destino.add(i), pixel) };
            }
            return;
        }

        let passo = self.bytes_por_pixel as usize;
        for (i, &pixel) in pixels.iter().enumerate() {
            let (bytes, quantos) = self.bytes_da_cor(Cor::de_u32(pixel));
            // SAFETY: mesma faixa do caminho rápido; aqui o passo é o do
            // pixel, e `geometria_coerente` garantiu que ele cobre os bytes
            // que o formato toca.
            unsafe {
                let ponteiro = inicio.add(i * passo);
                core::ptr::write_volatile(ponteiro, bytes[0]);
                if quantos == 3 {
                    core::ptr::write_volatile(ponteiro.add(1), bytes[1]);
                    core::ptr::write_volatile(ponteiro.add(2), bytes[2]);
                }
            }
        }
    }

    /// Lê uma sequência de pixels a partir de `(x, y)`, no formato de
    /// [`Cor::para_u32`]. O inverso de [`Tela::copiar_linha`].
    ///
    /// Existe para o compositor adotar o que já está na tela quando ele
    /// assume — o banner e as linhas do boot —, em vez de começar de uma tela
    /// em branco. Devolve quantos pixels leu: o que passar da borda direita,
    /// ou uma linha fora da tela, não é lido.
    pub fn ler_linha(&self, x: u32, y: u32, pixels: &mut [u32]) -> usize {
        if y >= self.altura || x >= self.largura {
            return 0;
        }
        let quantos = pixels.len().min((self.largura - x) as usize);
        let Some(inicio) = self.endereco(x, y) else {
            return 0;
        };

        if self.formato == Formato::Bgr && self.bytes_por_pixel == 4 {
            let origem = inicio as *const u32;
            for (i, pixel) in pixels[..quantos].iter_mut().enumerate() {
                // SAFETY: as mesmas do caminho rápido de `copiar_linha`: `x +
                // i` abaixo da largura, `y` abaixo da altura, região mapeada
                // e alinhada a 32 bits. O byte alto — o alfa que ninguém usa
                // — é zerado para o pixel sair no formato das superfícies.
                *pixel = unsafe { core::ptr::read_volatile(origem.add(i)) } & 0x00FF_FFFF;
            }
            return quantos;
        }

        for (i, pixel) in pixels[..quantos].iter_mut().enumerate() {
            *pixel = self
                .ler_pixel(x + i as u32, y)
                .map(Cor::para_u32)
                .unwrap_or(0);
        }
        quantos
    }

    /// Pinta a tela inteira.
    pub fn preencher(&self, cor: Cor) {
        self.retangulo(0, 0, self.largura, self.altura, cor);
    }
}

/// Limpa a tela e desenha o indicador de que o kernel assumiu.
///
/// # Por que limpar, e não só desenhar por cima
///
/// Porque o que está na tela quando o kernel começa não é dele: é o que o
/// firmware e o iniciador deixaram, linha após linha de texto que já cumpriu
/// o papel. Desenhar uma
/// faixa em cima disso deixa a tela com duas coisas ao mesmo tempo, e nenhuma
/// delas dizendo com clareza quem está no comando.
///
/// Limpar também é o que torna a amostra do agente interpretável: depois
/// dela, tudo o que aparece na tela foi este kernel que pôs ali.
pub fn banner() {
    let Some(tela) = tela() else {
        return;
    };

    tela.preencher(Cor::FUNDO);
    tela.retangulo(0, 0, tela.largura, ALTURA_DO_ACENTO, Cor::ACENTO);
    // A tela ficou em branco; o cursor do console precisa saber disso, ou a
    // primeira linha de texto sai onde ele parou da última vez.
    console::recomecar();
    descarregar();
}

/// Pinta a tela de falha.
///
/// Chamada do caminho de exceção fatal, onde não se pode contar com mais
/// nada: nem com o heap, nem com o canal do agente, nem com as travas que o
/// resto do kernel usa. É por isso que este módulo não tem nenhuma.
///
/// A tela inteira aqui, e não uma faixa: o custo deixou de importar, e o que
/// importa passou a ser não haver dúvida sobre o que aconteceu.
pub fn falha() {
    // O console volta à tela física antes de tudo: daqui em diante não há
    // compositor em quem confiar, e o que se escrever depois da tela de falha
    // — o relatório do post-mortem — tem de sair por cima dela, e não numa
    // camada que ninguém mais compõe.
    BASE_DO_CONSOLE.store(0, Ordering::Release);
    if let Some(tela) = tela_fisica() {
        tela.preencher(Cor::FALHA);
    }
    // Num adaptador que só mostra o que se manda, a tela de falha precisa ser
    // mandada. O caminho fatal destravou o dispositivo antes de chegar aqui;
    // se a falha foi dentro de um comando dele, a fila pode estar pela metade
    // e a descarga não chegar — e a tela fica como estava, sem pior desfecho.
    descarregar();
}
