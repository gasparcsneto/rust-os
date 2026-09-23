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
//! lado de [`Tela::pixel`], e o comando `video.sample` devolver uma amostra em
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
    ///
    /// Sem chamador no ARM, porque lá nada chama [`registrar`]: a máquina
    /// `virt` não expõe framebuffer nenhum. É a lacuna que um driver de
    /// virtio-gpu fecharia, e o `allow` condicionado à arquitetura é o que
    /// mantém a lacuna visível em vez de escondida.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
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
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
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
    largura > 0
        && altura > 0
        && stride >= largura
        && bytes_por_pixel >= formato.bytes_tocados()
}

/// A tela desta máquina, se houver uma.
pub fn tela() -> Option<Tela> {
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
    /// `stride * altura * bytes_por_pixel` bytes graváveis.
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
    /// Porque houve dois. [`Tela::pixel`] tinha a sua própria conversão, e
    /// este preenchimento tinha outra — as duas certas, até que uma mudasse.
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
    /// # Por que não é um laço sobre [`Tela::pixel`]
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
    pub fn retangulo(&self, x: u32, y: u32, largura: u32, altura: u32, cor: Cor) {
        let fim_x = x.saturating_add(largura).min(self.largura);
        let fim_y = y.saturating_add(altura).min(self.altura);
        if x >= fim_x || y >= fim_y {
            return;
        }

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

    /// Pinta a tela inteira.
    pub fn preencher(&self, cor: Cor) {
        self.retangulo(0, 0, self.largura, self.altura, cor);
    }
}

/// Limpa a tela e desenha o indicador de que o kernel assumiu.
///
/// # Por que limpar, e não só desenhar por cima
///
/// Porque o que está na tela quando o kernel começa não é dele: é o log do
/// bootloader, linha após linha de texto que já cumpriu o papel. Desenhar uma
/// faixa em cima disso deixa a tela com duas coisas ao mesmo tempo, e nenhuma
/// delas dizendo com clareza quem está no comando.
///
/// Limpar também é o que torna a amostra do agente interpretável: depois
/// dela, tudo o que aparece na tela foi este kernel que pôs ali.
pub fn banner() {
    let Some(tela) = tela() else {
        return;
    };

    /// Altura do traço de acento sob o topo.
    const ACENTO: u32 = 3;

    tela.preencher(Cor::FUNDO);
    tela.retangulo(0, 0, tela.largura, ACENTO, Cor::ACENTO);
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
    if let Some(tela) = tela() {
        tela.preencher(Cor::FALHA);
    }
}
