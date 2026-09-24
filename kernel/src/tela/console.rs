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
//! # Por que ele não rola
//!
//! Porque rolar custaria a tela inteira por linha. [`Tela::retangulo`] leva
//! 250 ms para escrever 1280x720 num emulador sem aceleração, e uma rolagem é
//! isso mais a leitura — meio segundo por linha de log, o que tornaria o
//! console mais lento que o que ele mostra.
//!
//! Quando o texto chega ao pé da tela, ela recomeça do topo. Perder o que
//! saiu não custa informação: os registros estão no anel de [`crate::log`], e
//! `log.tail` os devolve inteiros. A tela é a renderização.
//!
//! A saída certa para isso existe e fica para quando o console for
//! interativo: o adaptador tem registradores de altura virtual e
//! deslocamento vertical, feitos exatamente para rolar sem copiar nada. Ela
//! exige reprogramar o modo, inclusive no x86, onde hoje quem o programou foi
//! o `bootloader` — e não é trabalho para o commit que faz o texto aparecer.

use core::sync::atomic::{AtomicU32, Ordering};

use noto_sans_mono_bitmap::{FontWeight, RasterHeight, get_raster, get_raster_width};

use crate::tela::{Cor, Tela};

/// O peso e a altura dos glifos.
///
/// Uma altura só, e a menor que a fonte oferece. Uma tela de 720 linhas dá 44
/// linhas de texto com esta, o que é um relatório de boot inteiro sem
/// recomeçar; alturas maiores existiriam para serem escolhidas por alguém, e
/// não há ninguém para escolher.
const PESO: FontWeight = FontWeight::Regular;
const ALTURA: RasterHeight = RasterHeight::Size16;

/// A margem entre o texto e a borda da tela.
///
/// Vertical maior que a faixa de acento do banner (3 px), para que a primeira
/// linha não encoste nela.
const MARGEM_X: u32 = 8;
const MARGEM_Y: u32 = 8;

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

/// Escreve um texto na tela, se houver uma.
///
/// Devolve se escreveu. Quem chama usa isso para saber se o texto chegou a
/// alguém: numa máquina sem tela e sem console serial, ele não chegou.
pub fn escrever(texto: &str) -> bool {
    let Some(tela) = crate::tela::tela() else {
        return false;
    };

    let largura_do_glifo = get_raster_width(PESO, ALTURA) as u32;
    let altura_do_glifo = ALTURA.val() as u32;

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
                x += largura_do_glifo;
                continue;
            }
        }

        y = recomecar_se_encheu(&tela, y, altura_do_glifo);
    }

    CURSOR_X.store(x, Ordering::Relaxed);
    CURSOR_Y.store(y, Ordering::Relaxed);
    true
}

/// Volta ao topo quando não cabe mais uma linha, limpando a tela.
///
/// Ver a nota do módulo sobre por que não se rola. Limpar é o que separa
/// texto novo de texto velho: sem isso, as linhas de cima ficariam sendo as
/// da volta anterior, e uma pessoa leria as duas como se fossem a mesma
/// sequência.
fn recomecar_se_encheu(tela: &Tela, y: u32, altura_do_glifo: u32) -> u32 {
    if y + altura_do_glifo <= tela.altura.saturating_sub(MARGEM_Y) {
        return y;
    }
    // Só a região do console, e não a tela inteira. A faixa de acento sob o
    // topo é do banner, e apagá-la tira da tela o indicador de que há um
    // kernel vivo — que é justamente o que uma pessoa olha primeiro.
    let topo = crate::tela::ALTURA_DO_ACENTO;
    tela.retangulo(0, topo, tela.largura, tela.altura - topo, PAPEL);
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
