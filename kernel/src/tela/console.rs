//! O console de texto: o que uma pessoa lê na tela.
//!
//! # Por que isto existe
//!
//! Porque até aqui o Duke não podia ser operado por uma pessoa em nenhuma das
//! duas arquiteturas. No x86 havia uma segunda serial levando o log para o
//! terminal do hospedeiro; no ARM não havia nem isso — a `virt` tem uma porta
//! só, e ela é do canal do agente. Quem estivesse sentado na frente da
//! máquina via um retângulo azul e nada mais.
//!
//! Este módulo transforma o framebuffer no que ele deveria sempre ter sido:
//! uma superfície onde o texto do kernel aparece. Ele não inventa conteúdo
//! nenhum — desenha exatamente o que já ia para o console humano, pelo mesmo
//! funil ([`crate::serial::_print`]). É a mesma ideia que o log estruturado
//! já defende: o texto é uma **renderização**, e não a fonte da verdade.
//!
//! # Por que ele não rola, e o que mudou nessa conta
//!
//! A razão escrita aqui era de custo: [`Tela::retangulo`] levaria 250 ms para
//! escrever 1280x720, uma rolagem seria isso mais a leitura, e meio segundo
//! por linha tornaria o console mais lento que o que ele mostra.
//!
//! Remedido, e a conta não é essa. Aqueles 250 ms eram de `debug` e o
//! comentário não dizia. Em release um preenchimento leva 7 ms e uma leitura
//! de tela cheia — pelo caminho mais lento que existe, pixel a pixel por
//! `ler_pixel` — leva 15 ms. Uma rolagem custaria uns 22 ms por linha, e bem
//! menos com um `memmove` no lugar da leitura pixel a pixel.
//!
//! Ou seja: em release rolar é perfeitamente pagável, e em debug não é (lá o
//! preenchimento sozinho passa de 600 ms). A razão de custo vale para um
//! perfil só.
//!
//! O console segue sem rolar: quando o texto chega ao pé da tela, ela
//! recomeça do topo. A razão que este cabeçalho dava — "perder o que saiu da
//! tela não custa informação, `log.tail` devolve tudo" — é verdade para o
//! agente e não para a pessoa. Quem está na frente da máquina lendo a
//! resposta de um comando perde o começo dela quando a página vira, e o
//! `log.tail` que a recuperaria é JSON. Com o interpretador, o console
//! deixou de ser só um relatório de boot: rolar passou a ser dívida do lado
//! humano, e fica registrado como tal.
//!
//! O caminho barato existe: o adaptador tem registradores de altura virtual
//! e deslocamento vertical, feitos para rolar sem copiar nada. Ele exige
//! reprogramar o modo, inclusive onde o kernel não o programou — nos dois
//! boots por UEFI quem deixou o modo de pé foi o firmware —, e por isso a
//! saída mais provável é redesenhar a partir do texto guardado, que em
//! release custa os 22 ms por linha medidos acima.

use core::sync::atomic::{AtomicU32, Ordering};

use noto_sans_mono_bitmap::{FontWeight, RasterHeight, get_raster, get_raster_width};

use crate::tela::{Cor, Tela};

/// O peso e a altura dos glifos.
///
/// Uma altura só, e a menor que a fonte oferece. Uma tela de 720 linhas dá 42
/// linhas de texto com esta, abaixo da barra superior, o que é um relatório de boot inteiro sem
/// recomeçar; alturas maiores existiriam para serem escolhidas por alguém, e
/// não há ninguém para escolher.
const PESO: FontWeight = FontWeight::Regular;
const ALTURA: RasterHeight = RasterHeight::Size16;

/// A margem entre o texto e a borda da tela.
///
/// No topo, abaixo da barra superior, que fica por cima dele: a primeira
/// linha começa oito pixels depois de onde a barra acaba. Embaixo e dos
/// lados, oito pixels da borda.
const MARGEM_X: u32 = 8;
const MARGEM_Y: u32 = crate::tela::ALTURA_DA_BARRA + 8;
const MARGEM_DE_BAIXO: u32 = 8;

/// O que o glifo desenha, e sobre o quê.
const TINTA: Cor = Cor::nova(0xD8, 0xDE, 0xE8);
const PAPEL: Cor = Cor::FUNDO;

/// Onde a próxima letra vai, em pixels.
///
/// Atômicos, e não um `Mutex`, pela razão que vale para todo o resto deste
/// módulo: a tela precisa ser alcançável de dentro de um handler de exceção
/// fatal, e uma trava é justamente o que pode estar tomada ali.
///
/// A exclusão mútua de verdade vem de fora: quem chama é
/// [`crate::serial::_print`], que já roda com as interrupções desligadas.
/// Numa máquina de um núcleo isso é suficiente, e quando deixar de ser — o
/// dia em que houver um segundo núcleo — o que muda é aqui.
static CURSOR_X: AtomicU32 = AtomicU32::new(MARGEM_X);
static CURSOR_Y: AtomicU32 = AtomicU32::new(MARGEM_Y);

/// O maior console que a grade de texto acompanha, em caracteres.
///
/// Folgado para as telas que existem aqui — 1280x800 dá 180 colunas por 47
/// linhas com esta fonte — e para uma de 1920x1080. O que passar disto é
/// desenhado e não guardado; [`texto_completo`] diz quando isso aconteceu.
const MAX_COLUNAS: usize = 256;
const MAX_LINHAS: usize = 72;

/// O texto que está na tela, caractere por caractere.
///
/// # Por que guardar o que já foi desenhado
///
/// Porque a árvore semântica ([`crate::ui`]) descreve o que está na tela, e a
/// tela é pixels. Ler os pixels de volta e reconhecer letras seria adivinhar;
/// guardar o texto no instante em que ele é desenhado faz a árvore dizer
/// exatamente o que foi posto ali. É a inversão que o projeto repete desde o
/// log estruturado: o texto é a fonte, e os pixels a renderização dele.
///
/// Atômica pela mesma razão do cursor: este módulo é alcançável do caminho de
/// falha fatal, onde uma trava pode estar tomada. Zero é célula vazia.
static GRADE: [AtomicU32; MAX_COLUNAS * MAX_LINHAS] =
    [const { AtomicU32::new(0) }; MAX_COLUNAS * MAX_LINHAS];

/// Alguma célula ficou fora da grade desde a última limpeza?
static TRANSBORDOU: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// A célula da grade na posição de pixel `(x, y)`, se ela couber.
fn celula(x: u32, y: u32) -> Option<&'static AtomicU32> {
    let (largura, altura) = tamanho_do_caractere();
    let coluna = (x.checked_sub(MARGEM_X)? / largura) as usize;
    let linha = (y.checked_sub(MARGEM_Y)? / altura) as usize;
    if coluna >= MAX_COLUNAS || linha >= MAX_LINHAS {
        TRANSBORDOU.store(true, Ordering::Relaxed);
        return None;
    }
    GRADE.get(linha * MAX_COLUNAS + coluna)
}

fn limpar_grade() {
    for c in &GRADE {
        c.store(0, Ordering::Relaxed);
    }
    TRANSBORDOU.store(false, Ordering::Relaxed);
}

fn tamanho_do_caractere() -> (u32, u32) {
    (get_raster_width(PESO, ALTURA) as u32, ALTURA.val() as u32)
}

/// Escreve um texto na tela, se houver uma.
///
/// Devolve se escreveu. Quem chama usa isso para saber se o texto chegou a
/// alguém: numa máquina sem tela e sem console serial, ele não chegou.
pub fn escrever(texto: &str) -> bool {
    let Some(tela) = crate::tela::tela() else {
        return false;
    };

    let (largura_do_glifo, altura_do_glifo) = tamanho_do_caractere();

    let mut x = CURSOR_X.load(Ordering::Relaxed);
    let mut y = CURSOR_Y.load(Ordering::Relaxed);

    for c in texto.chars() {
        match c {
            '\n' => {
                x = MARGEM_X;
                y += altura_do_glifo;
            }
            // Um retorno de carro sem avanço de linha volta ao começo da
            // linha atual. Ninguém no kernel manda um hoje; tratá-lo custa
            // uma linha e evita que um dia ele vire um glifo de lixo.
            '\r' => x = MARGEM_X,
            // Apagar o caractere anterior: voltar uma célula e pintá-la de
            // fundo.
            //
            // Não era tratado, e o interpretador o manda a cada tecla de
            // apagar: a fonte não tem glifo para ele, o desenho caía no de
            // substituição, e uma pessoa que apagasse via um `?` aparecer e o
            // cursor **avançar**. A linha no buffer estava certa e a tela
            // afirmava outra coisa — que é o que um console não pode fazer.
            //
            // Voltar do começo de uma linha sobe para a última coluna da de
            // cima: é onde a quebra por largura deixou o caractere anterior.
            // No topo da tela não há para onde voltar, e o apagar se perde —
            // o texto de antes da última limpeza já não está lá.
            '\u{8}' => {
                if x >= MARGEM_X + largura_do_glifo {
                    x -= largura_do_glifo;
                } else if y >= MARGEM_Y + altura_do_glifo {
                    y -= altura_do_glifo;
                    let colunas = colunas_da_tela(&tela, largura_do_glifo);
                    x = MARGEM_X + colunas.saturating_sub(1) * largura_do_glifo;
                } else {
                    continue;
                }
                tela.retangulo(x, y, largura_do_glifo, altura_do_glifo, PAPEL);
                if let Some(celula) = celula(x, y) {
                    celula.store(0, Ordering::Relaxed);
                }
                continue;
            }
            _ => {
                // Uma letra que não cabe na linha desce para a seguinte, em
                // vez de ser cortada pela borda. O recorte de
                // [`Tela::retangulo`] a deixaria pela metade, o que é pior
                // que quebrar a linha: some sem dizer que sumiu.
                if x + largura_do_glifo > tela.largura.saturating_sub(MARGEM_X) {
                    x = MARGEM_X;
                    y += altura_do_glifo;
                }

                y = recomecar_se_encheu(&tela, y, altura_do_glifo);
                desenhar(&tela, c, x, y);
                if let Some(celula) = celula(x, y) {
                    celula.store(c as u32, Ordering::Relaxed);
                }
                x += largura_do_glifo;
                continue;
            }
        }

        y = recomecar_se_encheu(&tela, y, altura_do_glifo);
    }

    CURSOR_X.store(x, Ordering::Relaxed);
    CURSOR_Y.store(y, Ordering::Relaxed);
    crate::ui::mudou();
    true
}

/// Quantas colunas de texto cabem numa linha desta tela.
///
/// A conta é a da quebra de linha em [`escrever`]: uma letra cabe enquanto o
/// fim dela não passar da margem direita.
fn colunas_da_tela(tela: &Tela, largura_do_glifo: u32) -> u32 {
    tela.largura.saturating_sub(2 * MARGEM_X) / largura_do_glifo
}

/// Volta ao topo quando não cabe mais uma linha, limpando a tela.
///
/// Ver a nota do módulo sobre por que não se rola. Limpar é o que separa
/// texto novo de texto velho: sem isso, as linhas de cima ficariam sendo as
/// da volta anterior, e uma pessoa leria as duas como se fossem a mesma
/// sequência.
fn recomecar_se_encheu(tela: &Tela, y: u32, altura_do_glifo: u32) -> u32 {
    if y + altura_do_glifo <= tela.altura.saturating_sub(MARGEM_DE_BAIXO) {
        return y;
    }
    // Só a região do console, e não a tela inteira: a faixa da barra
    // superior fica de fora. Com a barra por cima ela não aparece, e limpá-la
    // seria recompor a barra à toa; sem a barra, é onde o banner desenhou o
    // acento que diz que há um kernel vivo.
    let topo = crate::tela::ALTURA_DA_BARRA;
    tela.retangulo(0, topo, tela.largura, tela.altura - topo, PAPEL);
    limpar_grade();
    MARGEM_Y
}

/// Desenha um glifo com o canto superior esquerdo em `(x, y)`.
///
/// # Por que a cobertura é misturada, e não limiarizada
///
/// Porque a fonte entrega um byte de cobertura por pixel, e não um bit. Usar
/// só "tem tinta ou não" jogaria fora justamente o que torna texto de 16
/// pixels de altura legível — as bordas deixam de ser serrilhadas porque os
/// pixels da borda são parciais.
fn desenhar(tela: &Tela, c: char, x: u32, y: u32) {
    // Um caractere fora do bloco básico do latim não tem glifo nesta fonte.
    // Desenhar nada deixaria um buraco que ninguém consegue distinguir de um
    // espaço; um losango diz que havia algo ali que não soubemos mostrar.
    let glifo = get_raster(c, PESO, ALTURA).or_else(|| get_raster('?', PESO, ALTURA));
    let Some(glifo) = glifo else {
        return;
    };

    for (linha, pixels) in glifo.raster().iter().enumerate() {
        for (coluna, &cobertura) in pixels.iter().enumerate() {
            // Pular o transparente não é otimização de gosto: a maior parte
            // de um glifo é fundo, e cada pixel escrito é um acesso a memória
            // de dispositivo, sem cache.
            if cobertura == 0 {
                continue;
            }
            // Um pixel é um retângulo de um por um, que é o único caminho de
            // escrita da tela — ver a nota em [`Tela::retangulo`] sobre por
            // que não existe um segundo.
            tela.retangulo(
                x + coluna as u32,
                y + linha as u32,
                1,
                1,
                misturar(PAPEL, TINTA, cobertura),
            );
        }
    }
}

/// Desenha `texto` numa memória de pixels, no formato das superfícies.
///
/// Para quem desenha fora do console — a barra superior, numa camada do
/// compositor — com a mesma fonte e a mesma mistura. Uma segunda cópia da
/// fonte seria uma segunda resposta para "como uma letra fica na tela".
///
/// Ao contrário do console, pinta também os pixels sem tinta, com `papel`:
/// uma camada não tem o fundo já pintado embaixo, e redesenhar um texto
/// sobre o anterior — o relógio da barra — precisa apagar o que havia.
/// Recorta no que couber em `largura` e no fim da memória. Devolve onde o
/// texto acabou.
pub fn desenhar_texto_em(
    pixels: &mut [u32],
    largura: u32,
    x: u32,
    y: u32,
    texto: &str,
    tinta: Cor,
    papel: Cor,
) -> u32 {
    let (largura_do_glifo, _) = tamanho_do_caractere();
    let mut x = x;
    for c in texto.chars() {
        let glifo = get_raster(c, PESO, ALTURA).or_else(|| get_raster('?', PESO, ALTURA));
        if let Some(glifo) = glifo {
            for (linha, cobertura) in glifo.raster().iter().enumerate() {
                for (coluna, &c) in cobertura.iter().enumerate() {
                    let (px, py) = (x + coluna as u32, y + linha as u32);
                    if px >= largura {
                        continue;
                    }
                    let i = py as usize * largura as usize + px as usize;
                    if let Some(pixel) = pixels.get_mut(i) {
                        *pixel = misturar(papel, tinta, c).para_u32();
                    }
                }
            }
        }
        x += largura_do_glifo;
    }
    x
}

/// A altura de uma linha de texto com esta fonte, em pixels.
pub fn altura_do_texto() -> u32 {
    tamanho_do_caractere().1
}

/// Quantos pixels `texto` ocupa na horizontal com esta fonte.
pub fn largura_do_texto(texto: &str) -> u32 {
    texto.chars().count() as u32 * tamanho_do_caractere().0
}

/// A cor de um pixel com cobertura parcial de tinta.
///
/// Aritmética inteira de ponta a ponta: o alvo ARM deste kernel é
/// `softfloat`, onde uma multiplicação em ponto flutuante não é só lenta —
/// ela não existe sem a biblioteca que a emula.
fn misturar(fundo: Cor, frente: Cor, cobertura: u8) -> Cor {
    let c = u16::from(cobertura);
    let componente = |f: u8, t: u8| -> u8 {
        let mistura = u16::from(f) * (255 - c) + u16::from(t) * c;
        // Divisão por 255, e não deslocamento de 8: com o deslocamento, uma
        // cobertura cheia devolveria a cor levemente escurecida, e texto
        // branco nunca sairia branco.
        (mistura / 255) as u8
    };
    Cor::nova(
        componente(fundo.r, frente.r),
        componente(fundo.g, frente.g),
        componente(fundo.b, frente.b),
    )
}

/// Devolve o cursor ao começo, sem tocar na tela.
///
/// Existe para quem limpa a tela por fora — [`crate::tela::banner`] —, porque
/// um cursor que continua onde estava depois de uma limpeza escreve a
/// primeira linha no meio do nada.
pub fn recomecar() {
    CURSOR_X.store(MARGEM_X, Ordering::Relaxed);
    CURSOR_Y.store(MARGEM_Y, Ordering::Relaxed);
    // Quem chama limpou a tela, e o texto que a grade guardava não está mais
    // lá. Uma árvore que continuasse a descrevê-lo descreveria o passado.
    limpar_grade();
    crate::ui::mudou();
}

/// A geometria do console, em caracteres e em pixels.
pub struct Geometria {
    /// Quantas colunas e linhas a tela comporta — limitadas ao que a grade
    /// guarda.
    pub colunas: u32,
    pub linhas: u32,
    /// O tamanho de uma célula, em pixels.
    pub largura_da_celula: u32,
    pub altura_da_celula: u32,
    /// Onde a primeira célula começa.
    pub margem_x: u32,
    pub margem_y: u32,
}

/// A geometria do console desta tela, se houver uma.
pub fn geometria() -> Option<Geometria> {
    let tela = crate::tela::tela()?;
    let (largura, altura) = tamanho_do_caractere();
    let colunas = colunas_da_tela(&tela, largura).min(MAX_COLUNAS as u32);
    let linhas =
        (tela.altura.saturating_sub(MARGEM_Y + MARGEM_DE_BAIXO) / altura).min(MAX_LINHAS as u32);
    Some(Geometria {
        colunas,
        linhas,
        largura_da_celula: largura,
        altura_da_celula: altura,
        margem_x: MARGEM_X,
        margem_y: MARGEM_Y,
    })
}

/// O caractere guardado na célula `(coluna, linha)`, ou `None` se ela está
/// vazia ou fora da grade.
pub fn caractere(coluna: u32, linha: u32) -> Option<char> {
    let (coluna, linha) = (coluna as usize, linha as usize);
    if coluna >= MAX_COLUNAS || linha >= MAX_LINHAS {
        return None;
    }
    char::from_u32(GRADE[linha * MAX_COLUNAS + coluna].load(Ordering::Relaxed))
        .filter(|&c| c != '\0')
}

/// A grade guardou tudo o que foi desenhado desde a última limpeza?
///
/// Falso numa tela maior que a grade. É o que a árvore publica para que um
/// texto cortado não se passe por inteiro.
pub fn texto_completo() -> bool {
    !TRANSBORDOU.load(Ordering::Relaxed)
}

/// Onde o cursor está, em células.
pub fn cursor_em_celulas() -> (u32, u32) {
    let (largura, altura) = tamanho_do_caractere();
    (
        CURSOR_X.load(Ordering::Relaxed).saturating_sub(MARGEM_X) / largura,
        CURSOR_Y.load(Ordering::Relaxed).saturating_sub(MARGEM_Y) / altura,
    )
}

/// Onde o cursor está, em pixels. Para a suíte.
#[cfg(feature = "modo-teste")]
pub fn cursor() -> (u32, u32) {
    (
        CURSOR_X.load(Ordering::Relaxed),
        CURSOR_Y.load(Ordering::Relaxed),
    )
}

/// O tamanho de um glifo, em pixels. Para a suíte.
#[cfg(feature = "modo-teste")]
pub fn tamanho_do_glifo() -> (u32, u32) {
    (get_raster_width(PESO, ALTURA) as u32, ALTURA.val() as u32)
}

/// O console como destino de `core::fmt`.
///
/// Existe para que [`crate::serial::_print`] escreva na tela pelo mesmo
/// `write_fmt` com que escreve na serial — sem um buffer intermediário, que
/// num kernel sem heap no momento do primeiro log seria um array de tamanho
/// arbitrário e um truncamento silencioso.
pub struct Saida;

impl core::fmt::Write for Saida {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        escrever(s);
        Ok(())
    }
}

/// Confere que o glifo de `c` está desenhado com o canto em `(x, y)`.
///
/// # Por que a conferência mora aqui
///
/// Porque ela precisa da mesma fonte e da mesma mistura que o desenho usou, e
/// duplicá-las na suíte seria escrever a resposta duas vezes — o teste
/// passaria com as duas erradas do mesmo jeito. Aqui ele compara o que está
/// **na memória do framebuffer** com o que a fonte diz que deveria estar.
///
/// Confere pixel a pixel, e não uma amostra: o que pode dar errado entre a
/// fonte e a tela é deslocamento, ordem de bytes e stride, e os três produzem
/// uma imagem que uma amostra esparsa aceita.
#[cfg(feature = "modo-teste")]
pub fn conferir_glifo(c: char, x: u32, y: u32) -> Result<(), &'static str> {
    let Some(tela) = crate::tela::tela() else {
        return Err("nao ha tela para conferir");
    };
    conferir_glifo_em(&tela, c, x, y)
}

/// [`conferir_glifo`] numa tela dada — a física, para conferir que o
/// compositor levou até ela o que o console desenhou na camada dele.
#[cfg(feature = "modo-teste")]
pub fn conferir_glifo_em(
    tela: &crate::tela::Tela,
    c: char,
    x: u32,
    y: u32,
) -> Result<(), &'static str> {
    let Some(glifo) = get_raster(c, PESO, ALTURA) else {
        return Err("a fonte nao tem este glifo");
    };

    for (linha, pixels) in glifo.raster().iter().enumerate() {
        for (coluna, &cobertura) in pixels.iter().enumerate() {
            let esperado = misturar(PAPEL, TINTA, cobertura);
            let Some(lido) = tela.ler_pixel(x + coluna as u32, y + linha as u32) else {
                return Err("o glifo caiu fora da tela");
            };
            if lido != esperado {
                crate::log_error!(
                    "teste",
                    "pixel {},{} do glifo: {:02x}{:02x}{:02x}, esperado {:02x}{:02x}{:02x}",
                    coluna,
                    linha,
                    lido.r,
                    lido.g,
                    lido.b,
                    esperado.r,
                    esperado.g,
                    esperado.b
                );
                return Err("o glifo na tela nao e o da fonte");
            }
        }
    }

    Ok(())
}

/// Confere que a célula com o canto em `(x, y)` está vazia: só fundo.
///
/// O par de [`conferir_glifo`] para o apagar. Mora aqui pelo mesmo motivo:
/// "vazio" é a cor de fundo que este módulo usa, e a suíte não deveria ter
/// uma segunda cópia dela.
#[cfg(feature = "modo-teste")]
pub fn conferir_celula_vazia(x: u32, y: u32) -> Result<(), &'static str> {
    let Some(tela) = crate::tela::tela() else {
        return Err("nao ha tela para conferir");
    };
    let (largura, altura) = tamanho_do_caractere();
    for linha in 0..altura {
        for coluna in 0..largura {
            match tela.ler_pixel(x + coluna, y + linha) {
                Some(cor) if cor == PAPEL => {}
                Some(_) => return Err("a celula apagada ainda tem tinta"),
                None => return Err("a celula caiu fora da tela"),
            }
        }
    }
    Ok(())
}
