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
//! # Ele rola
//!
//! Quando o texto chega ao pé da tela, ele sobe uma linha, e a nova entra
//! embaixo. Por muito tempo não foi assim: a tela recomeçava do topo,
//! limpando, e quem estava lendo a resposta de um comando perdia o começo
//! dela quando a página virava. A razão escrita aqui era de custo — um
//! preenchimento de tela em debug passa de 600 ms, e uma rolagem seria isso
//! mais a leitura.
//!
//! A conta mudou com o compositor. O console desenha numa camada em memória
//! comum, e rolar é mover um bloco de memória — as linhas de pixel são
//! contíguas — e pintar só a última linha: [`Tela::rolar`]. O compositor
//! leva à tela o que mudou. A grade de caracteres sobe junto, para a árvore
//! semântica continuar descrevendo o que está na tela, e um contador
//! ([`rolagens`]) diz a quem guardou uma posição em linhas — a linha de
//! comando — quanto ela subiu.
//!
//! A página que virava tinha um defeito além do incômodo: a última linha
//! escrita sumia junto com ela. Um registro de log que caísse no pé da tela
//! desaparecia antes de alguém lê-lo, e um caso da árvore semântica passou a
//! reprovar por isso quando a barra superior tirou duas linhas da página.

use core::sync::atomic::{AtomicU32, Ordering};

use tipografia::Estilo;

use crate::tela::{Cor, Tela};

/// O estilo do console: o texto de todo dia, regular e de 16 pixels.
///
/// Uma altura só, e a menor que a fonte oferece. Uma tela de 720 linhas dá 42
/// linhas de texto com esta, abaixo da barra superior, o que é um relatório de
/// boot inteiro sem recomeçar. A fonte e os outros estilos moram no pacote
/// `tipografia`, com os programas de usuário.
const ESTILO: Estilo = Estilo::TEXTO;

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

/// Sobe a grade uma linha, junto com a tela, e esvazia a de baixo.
fn rolar_grade() {
    for linha in 0..MAX_LINHAS - 1 {
        for coluna in 0..MAX_COLUNAS {
            let abaixo = GRADE[(linha + 1) * MAX_COLUNAS + coluna].load(Ordering::Relaxed);
            GRADE[linha * MAX_COLUNAS + coluna].store(abaixo, Ordering::Relaxed);
        }
    }
    for c in &GRADE[(MAX_LINHAS - 1) * MAX_COLUNAS..] {
        c.store(0, Ordering::Relaxed);
    }
}

/// Quantas vezes o console rolou desde o boot.
///
/// Para quem guarda uma posição em linhas de texto — o começo da linha de
/// comando — saber quanto ela subiu desde que foi guardada. Um contador, e
/// não um aviso a quem guarda: quem escreve aqui é o console, sem trava, e
/// quem guarda a posição é o interpretador, que escreve no console com a
/// trava dele na mão.
static ROLAGENS: AtomicU32 = AtomicU32::new(0);

pub fn rolagens() -> u32 {
    ROLAGENS.load(Ordering::Relaxed)
}

fn tamanho_do_caractere() -> (u32, u32) {
    (ESTILO.largura(), ESTILO.altura())
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

/// Rola uma linha quando não cabe mais uma, e devolve onde a próxima vai.
///
/// O texto sobe, a linha de cima sai, e a nova entra embaixo — o que um
/// terminal faz, e o que uma pessoa lendo a resposta de um comando espera. A
/// grade de caracteres sobe junto, para a árvore semântica continuar
/// descrevendo a tela.
///
/// Numa tela pequena demais para rolar — menos de duas linhas de texto —
/// recomeça do topo, limpando: é o que o console fazia sempre, antes de
/// rolar.
fn recomecar_se_encheu(tela: &Tela, y: u32, altura_do_glifo: u32) -> u32 {
    if y + altura_do_glifo <= tela.altura.saturating_sub(MARGEM_DE_BAIXO) {
        return y;
    }
    if tela.rolar(MARGEM_Y, y - MARGEM_Y, altura_do_glifo, PAPEL) {
        rolar_grade();
        ROLAGENS.fetch_add(1, Ordering::Relaxed);
        return y - altura_do_glifo;
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
///
/// Uma letra que a fonte não tem sai como o substituto da `tipografia`, e
/// não como nada: um buraco não se distingue de um espaço.
fn desenhar(tela: &Tela, c: char, x: u32, y: u32) {
    tipografia::percorrer(c, ESTILO, |coluna, linha, cobertura| {
        // Pular o transparente não é otimização de gosto: a maior parte de
        // um glifo é fundo, e cada pixel escrito é um acesso a memória de
        // dispositivo, sem cache.
        if cobertura == 0 {
            return;
        }
        // Um pixel é um retângulo de um por um, que é o único caminho de
        // escrita da tela — ver a nota em [`Tela::retangulo`] sobre por que
        // não existe um segundo.
        tela.retangulo(
            x + coluna,
            y + linha,
            1,
            1,
            misturar(PAPEL, TINTA, cobertura),
        );
    });
}

/// Desenha `texto` no `estilo` numa memória de pixels, no formato das
/// superfícies.
///
/// Para quem desenha fora do console — a barra superior, numa camada do
/// compositor. É o desenho da `tipografia`, o mesmo que o servidor de janelas
/// usa, com as cores do kernel.
///
/// Ao contrário do console, pinta também os pixels sem tinta, com `papel`:
/// uma camada não tem o fundo já pintado embaixo, e redesenhar um texto
/// sobre o anterior — o relógio da barra — precisa apagar o que havia.
/// Recorta no que couber em `largura` e no fim da memória. Devolve onde o
/// texto acabou.
pub fn desenhar_texto_em(
    pixels: &mut [u32],
    largura: u32,
    (x, y): (u32, u32),
    texto: &str,
    estilo: Estilo,
    (tinta, papel): (Cor, Cor),
) -> u32 {
    tipografia::escrever(
        pixels,
        largura,
        (x, y),
        texto,
        estilo,
        tinta.para_u32(),
        papel.para_u32(),
    )
}

/// A cor de um pixel com cobertura parcial de tinta — a mistura da
/// `tipografia`, a mesma dos programas de usuário, sobre as cores do kernel.
fn misturar(fundo: Cor, frente: Cor, cobertura: u8) -> Cor {
    Cor::de_u32(tipografia::misturar(
        fundo.para_u32(),
        frente.para_u32(),
        cobertura,
    ))
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
    tamanho_do_caractere()
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
    if !tipografia::tem_glifo(c, ESTILO) {
        return Err("a fonte nao tem este glifo");
    }

    let mut resultado = Ok(());
    tipografia::percorrer(c, ESTILO, |coluna, linha, cobertura| {
        if resultado.is_err() {
            return;
        }
        let esperado = misturar(PAPEL, TINTA, cobertura);
        let Some(lido) = tela.ler_pixel(x + coluna, y + linha) else {
            resultado = Err("o glifo caiu fora da tela");
            return;
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
            resultado = Err("o glifo na tela nao e o da fonte");
        }
    });
    resultado
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
