//! O compositor: as camadas, e a tela que elas deixam ver.
//!
//! # O que ele faz
//!
//! Guarda uma pilha de camadas — cada uma uma superfície com posição — e,
//! quando algo muda num retângulo, recompõe só esse retângulo, de baixo para
//! cima, num quadro, e entrega o quadro ao adaptador. As camadas são opacas:
//! a de cima esconde a de baixo inteira onde as duas se cruzam, e compor é
//! copiar linhas, sem ler o fundo. A transparência, quando vier, é outra
//! conta e outro custo.
//!
//! A camada de baixo é o console. Ele escreve nela como sempre escreveu na
//! tela — sem trava, de qualquer lugar —, e o retângulo que ele suja chega
//! aqui por [`crate::tela::descarregar`]. É o mesmo retângulo sujo que o
//! `virtio-gpu` já usava: o compositor passou a ser quem leva a tela.
//!
//! # O quadro
//!
//! Onde a tela é montada antes de aparecer. Num `virtio-gpu`, é a própria
//! memória da tela, que o monitor só vê quando se transfere; num framebuffer
//! linear, um buffer de fundo que o adaptador copia para o framebuffer só no
//! retângulo que mudou. Ver [`AdaptadorGrafico::superficie_da_tela`].
//!
//! # O que fica de fora dele
//!
//! O caminho de falha fatal. [`crate::tela::falha`] devolve o console à
//! tela física e pinta direto nela: o compositor segura uma trava e mora no
//! heap, duas coisas em que um handler de falha não pode confiar. Depois
//! disso ele não compõe mais — ver [`Compositor::compor`].
//!
//! # De onde vem o desenho
//!
//! Do Orbital, o compositor do Redox, no que importa aqui: um retângulo de
//! dano por vez, as janelas de baixo para cima, e o quadro entregue ao
//! adaptador pelo mesmo trait que o `vesad` e o `virtio-gpud` implementam.
//! Código do Orbital não há: o dele vive em espaço de usuário, com
//! transparência e decorações, e nada disso existe aqui ainda.

use alloc::vec::Vec;

use super::linear::{AdaptadorLinear, SuperficieLinear};
use super::memoria::Memoria;
use super::virtio::{AdaptadorVirtio, SuperficieVirtio};
use super::{AdaptadorGrafico, Dano, Superficie};
use crate::tela::Tela;

/// O identificador da camada do console, sempre a de baixo.
pub const CAMADA_DO_CONSOLE: u32 = 0;

/// Onde o compositor entrega a tela: o adaptador, e o quadro que ele mostra.
///
/// Uma enumeração, e não um objeto de trait, pelo motivo de
/// [`super::AdaptadorGrafico`] ter tipo associado.
enum Saida {
    Linear(AdaptadorLinear, SuperficieLinear),
    Virtio(AdaptadorVirtio, SuperficieVirtio),
}

impl Saida {
    fn nome(&self) -> &'static str {
        match self {
            Saida::Linear(a, _) => a.nome(),
            Saida::Virtio(a, _) => a.nome(),
        }
    }

    fn telas(&self) -> usize {
        match self {
            Saida::Linear(a, _) => a.telas(),
            Saida::Virtio(a, _) => a.telas(),
        }
    }

    fn tamanho_da_tela(&self) -> Option<(u32, u32)> {
        match self {
            Saida::Linear(a, _) => a.tamanho_da_tela(0),
            Saida::Virtio(a, _) => a.tamanho_da_tela(0),
        }
    }

    fn quadro(&mut self) -> &mut [u32] {
        match self {
            Saida::Linear(_, q) => q.pixels_mut(),
            Saida::Virtio(_, q) => q.pixels_mut(),
        }
    }

    fn apresentar(&mut self, dano: Dano) -> Result<Dano, &'static str> {
        match self {
            Saida::Linear(a, q) => a.atualizar(0, q, dano),
            Saida::Virtio(a, q) => a.atualizar(0, q, dano),
        }
    }
}

/// Uma camada acima do console.
struct Entrada {
    id: u32,
    nome: &'static str,
    /// A posição do canto superior esquerdo. Pode ser negativa, ou passar da
    /// tela: uma janela arrastada para a borda continua sendo uma janela, e
    /// só o que cai dentro da tela é composto.
    x: i32,
    y: i32,
    largura: u32,
    altura: u32,
    memoria: Memoria,
}

impl Entrada {
    /// Onde a camada cai na tela, recortada a ela.
    fn na_tela(&self, largura: u32, altura: u32) -> Dano {
        recortar_posicionado(self.x, self.y, self.largura, self.altura, largura, altura)
    }
}

/// O que o agente vê de uma camada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InfoCamada {
    pub id: u32,
    pub nome: &'static str,
    pub x: i32,
    pub y: i32,
    pub largura: u32,
    pub altura: u32,
}

impl InfoCamada {
    /// A parte da camada que cai numa tela de `largura` por `altura`.
    pub fn na_tela(&self, largura: u32, altura: u32) -> Dano {
        recortar_posicionado(self.x, self.y, self.largura, self.altura, largura, altura)
    }
}

/// O compositor da tela 0.
pub struct Compositor {
    saida: Saida,
    largura: u32,
    altura: u32,
    /// A camada de baixo: onde o console desenha.
    console: Memoria,
    /// As outras camadas, de baixo para cima.
    camadas: Vec<Entrada>,
    proximo_id: u32,
    /// O que não pôde ser apresentado da última vez. Vai junto com o próximo
    /// dano, para não se perder.
    pendente: Dano,
}

impl Compositor {
    /// Monta o compositor sobre a tela física, sem ainda tomá-la.
    ///
    /// Quem chama adota o que está na tela ([`Compositor::adotar`]) e só
    /// então desvia o console — nessa ordem, e sem ninguém escrevendo no
    /// meio.
    pub fn novo(fisica: Tela) -> Result<Compositor, &'static str> {
        let (largura, altura) = (fisica.largura, fisica.altura);
        let saida = if crate::virtio::gpu::tem_a_tela() {
            let mut adaptador = AdaptadorVirtio;
            let quadro = adaptador
                .superficie_da_tela(0)
                .ok_or("o video virtio nao entregou a superficie da tela")?;
            Saida::Virtio(adaptador, quadro)
        } else {
            let mut adaptador = AdaptadorLinear::novo(fisica);
            let quadro = adaptador.criar_superficie(largura, altura)?;
            Saida::Linear(adaptador, quadro)
        };
        let console = Memoria::nova(largura as u64 * altura as u64 * 4)?;
        Ok(Compositor {
            saida,
            largura,
            altura,
            console,
            camadas: Vec::new(),
            proximo_id: CAMADA_DO_CONSOLE + 1,
            pendente: Dano::novo(0, 0, 0, 0),
        })
    }

    /// Copia para a camada do console o que a tela física mostra agora — o
    /// banner e as linhas do boot —, e para o quadro também.
    ///
    /// Sem isto a primeira escrita depois do desvio levaria à tela uma
    /// camada em branco em volta do caractere, e o boot sumiria em pedaços.
    pub fn adotar(&mut self, fisica: &Tela) {
        let (largura, altura) = (self.largura as usize, self.altura);
        let Compositor { saida, console, .. } = &mut *self;
        let console = console.pixels_mut();
        let quadro = saida.quadro();
        for y in 0..altura {
            let inicio = y as usize * largura;
            let linha = &mut console[inicio..inicio + largura];
            fisica.ler_linha(0, y, linha);
            quadro[inicio..inicio + largura].copy_from_slice(linha);
        }
    }

    /// Onde a camada do console mora, para desviar o console para ela.
    pub fn base_do_console(&self) -> u64 {
        self.console.inicio()
    }

    pub fn nome(&self) -> &'static str {
        self.saida.nome()
    }

    pub fn telas(&self) -> usize {
        self.saida.telas()
    }

    pub fn tamanho_da_tela(&self) -> Option<(u32, u32)> {
        self.saida.tamanho_da_tela()
    }

    /// Recompõe `dano` e o entrega ao adaptador.
    ///
    /// De baixo para cima: o console, que cobre a tela inteira, e depois
    /// cada camada, só onde ela cruza o dano. Opacas, então cada pixel é
    /// escrito uma vez por camada que o cobre, sem ler o que havia.
    ///
    /// Se o adaptador não pôde apresentar — no `virtio-gpu`, a tela coberta
    /// por outra superfície, ou o dispositivo ocupado —, o dano fica
    /// pendente e vai junto com o próximo. Devolve o que foi apresentado.
    ///
    /// Depois de uma falha fatal o console não está mais desviado, e aqui
    /// não se compõe nada: a tela de falha é do caminho fatal.
    pub fn compor(&mut self, dano: Dano) -> Result<Dano, &'static str> {
        if !crate::tela::console_desviado() {
            return Ok(Dano::novo(0, 0, 0, 0));
        }
        let (largura, altura) = (self.largura, self.altura);
        let dano = dano.unir(self.pendente).recortar(largura, altura);
        self.pendente = Dano::novo(0, 0, 0, 0);
        if dano.vazio() {
            return Ok(dano);
        }

        let resultado = {
            let Compositor {
                saida,
                console,
                camadas,
                ..
            } = &mut *self;
            compor_em(saida, console, camadas, largura, altura, dano);
            saida.apresentar(dano)
        };
        match resultado {
            Ok(apresentado) => {
                super::registrar_atualizacao(apresentado);
                Ok(apresentado)
            }
            Err(motivo) => {
                self.pendente = dano;
                Err(motivo)
            }
        }
    }

    /// Põe uma camada nova no topo e a compõe. Os pixels começam pretos.
    #[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
    fn criar(
        &mut self,
        nome: &'static str,
        x: i32,
        y: i32,
        largura: u32,
        altura: u32,
    ) -> Result<u32, &'static str> {
        if largura == 0 || altura == 0 {
            return Err("camada sem area");
        }
        let bytes = (largura as u64)
            .checked_mul(altura as u64)
            .and_then(|p| p.checked_mul(4))
            .ok_or("camada grande demais")?;
        let memoria = Memoria::nova(bytes)?;
        let id = self.proximo_id;
        self.proximo_id = self
            .proximo_id
            .checked_add(1)
            .ok_or("identificadores esgotados")?;
        self.camadas.push(Entrada {
            id,
            nome,
            x,
            y,
            largura,
            altura,
            memoria,
        });
        crate::ui::mudou();
        let _ = self.compor_camada(id);
        Ok(id)
    }

    #[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
    fn indice(&self, id: u32) -> Option<usize> {
        self.camadas.iter().position(|c| c.id == id)
    }

    /// Recompõe o retângulo que uma camada ocupa na tela.
    #[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
    fn compor_camada(&mut self, id: u32) -> Result<Dano, &'static str> {
        let i = self.indice(id).ok_or("camada inexistente")?;
        let onde = self.camadas[i].na_tela(self.largura, self.altura);
        self.compor(onde)
    }

    #[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
    fn remover(&mut self, id: u32) {
        let Some(i) = self.indice(id) else {
            return;
        };
        let onde = self.camadas[i].na_tela(self.largura, self.altura);
        // A memória sai daqui, depois de a camada deixar a pilha: compor com
        // ela ainda na lista mostraria o que está sendo solto.
        let saiu = self.camadas.remove(i);
        crate::ui::mudou();
        let _ = self.compor(onde);
        drop(saiu);
    }

    /// As camadas, de baixo para cima, começando pelo console.
    pub fn camadas(&self, mut f: impl FnMut(InfoCamada)) {
        f(InfoCamada {
            id: CAMADA_DO_CONSOLE,
            nome: "console",
            x: 0,
            y: 0,
            largura: self.largura,
            altura: self.altura,
        });
        for c in &self.camadas {
            f(InfoCamada {
                id: c.id,
                nome: c.nome,
                x: c.x,
                y: c.y,
                largura: c.largura,
                altura: c.altura,
            });
        }
    }
}

/// Uma camada acima do console, enquanto este valor viver.
///
/// Soltá-lo tira a camada da tela e devolve a memória dela — o mesmo
/// arranjo de [`Memoria`], pelo mesmo motivo: quem esquece de desfazer é o
/// compilador, e ele não esquece.
// Hoje só a suíte cria camadas: o primeiro cliente de produção é a barra
// superior, ou o servidor de janelas, e nenhum dos dois existe ainda. A
// anotação mantém o build de produção limpo sem esconder código morto de
// verdade — na compilação de teste, onde há consumidor, ela não vale.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub struct Camada {
    id: u32,
}

#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
impl Camada {
    /// Cria uma camada no topo, em `(x, y)`, e a mostra. Os pixels começam
    /// pretos; quem a criou pinta com [`Camada::pintar`].
    pub fn nova(
        nome: &'static str,
        x: i32,
        y: i32,
        largura: u32,
        altura: u32,
    ) -> Result<Camada, &'static str> {
        let id = super::com_compositor(|c| c.criar(nome, x, y, largura, altura))
            .ok_or("nao ha compositor")??;
        Ok(Camada { id })
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    /// Pinta a camada e recompõe o que ela ocupa na tela.
    ///
    /// `f` recebe os pixels, linha a linha, no formato de
    /// [`crate::tela::Cor::para_u32`], e a largura e a altura da camada. Ele
    /// roda com o compositor travado: não pode criar nem mexer em camadas.
    pub fn pintar(&self, f: impl FnOnce(&mut [u32], u32, u32)) -> Result<Dano, &'static str> {
        super::com_compositor(|c| {
            let i = c.indice(self.id).ok_or("camada inexistente")?;
            let entrada = &mut c.camadas[i];
            let quantos = entrada.largura as usize * entrada.altura as usize;
            f(
                &mut entrada.memoria.pixels_mut()[..quantos],
                entrada.largura,
                entrada.altura,
            );
            c.compor_camada(self.id)
        })
        .ok_or("nao ha compositor")?
    }

    /// Move a camada, e recompõe onde ela estava e onde ela está.
    ///
    /// Os dois retângulos, e não só o novo: sem o antigo, o que a camada
    /// cobria continuaria na tela, como um rastro.
    pub fn mover(&self, x: i32, y: i32) -> Result<Dano, &'static str> {
        super::com_compositor(|c| {
            let i = c.indice(self.id).ok_or("camada inexistente")?;
            let antes = c.camadas[i].na_tela(c.largura, c.altura);
            c.camadas[i].x = x;
            c.camadas[i].y = y;
            crate::ui::mudou();
            let depois = c.camadas[i].na_tela(c.largura, c.altura);
            c.compor(antes.unir(depois))
        })
        .ok_or("nao ha compositor")?
    }

    /// Põe a camada no topo da pilha.
    pub fn trazer_para_frente(&self) -> Result<Dano, &'static str> {
        super::com_compositor(|c| {
            let i = c.indice(self.id).ok_or("camada inexistente")?;
            let entrada = c.camadas.remove(i);
            c.camadas.push(entrada);
            crate::ui::mudou();
            c.compor_camada(self.id)
        })
        .ok_or("nao ha compositor")?
    }
}

impl Drop for Camada {
    fn drop(&mut self) {
        super::com_compositor(|c| c.remover(self.id));
    }
}

/// Recorta um retângulo posicionado — que pode começar antes da origem — a
/// uma área de `largura` por `altura`.
fn recortar_posicionado(
    x: i32,
    y: i32,
    largura: u32,
    altura: u32,
    largura_da_area: u32,
    altura_da_area: u32,
) -> Dano {
    let eixo = |inicio: i32, tamanho: u32, limite: u32| -> (u32, u32) {
        let comeco = (inicio as i64).clamp(0, limite as i64);
        let fim = (inicio as i64 + tamanho as i64).clamp(0, limite as i64);
        (comeco as u32, (fim - comeco).max(0) as u32)
    };
    let (x, largura) = eixo(x, largura, largura_da_area);
    let (y, altura) = eixo(y, altura, altura_da_area);
    Dano::novo(x, y, largura, altura)
}

/// Onde dois retângulos se cruzam, ou um vazio.
fn interseccao(a: Dano, b: Dano) -> Dano {
    let x0 = a.x.max(b.x);
    let y0 = a.y.max(b.y);
    let x1 =
        a.x.saturating_add(a.largura)
            .min(b.x.saturating_add(b.largura));
    let y1 =
        a.y.saturating_add(a.altura)
            .min(b.y.saturating_add(b.altura));
    if x0 >= x1 || y0 >= y1 {
        return Dano::novo(0, 0, 0, 0);
    }
    Dano::novo(x0, y0, x1 - x0, y1 - y0)
}

/// Monta `dano` no quadro: o console, e por cima cada camada onde ela cruza.
fn compor_em(
    saida: &mut Saida,
    console: &Memoria,
    camadas: &[Entrada],
    largura: u32,
    altura: u32,
    dano: Dano,
) {
    let quadro = saida.quadro();
    let linha = largura as usize;

    let console = console.pixels();
    for y in dano.y..dano.y + dano.altura {
        let inicio = y as usize * linha + dano.x as usize;
        let fim = inicio + dano.largura as usize;
        quadro[inicio..fim].copy_from_slice(&console[inicio..fim]);
    }

    for camada in camadas.iter() {
        let cruza = interseccao(dano, camada.na_tela(largura, altura));
        if cruza.vazio() {
            continue;
        }
        let pixels = camada.memoria.pixels();
        // Da tela para a camada: a posição pode ser negativa, e o
        // recorte garantiu que `cruza` está dentro das duas.
        let dx = (cruza.x as i64 - camada.x as i64) as usize;
        let dy = (cruza.y as i64 - camada.y as i64) as usize;
        for i in 0..cruza.altura as usize {
            let de = (dy + i) * camada.largura as usize + dx;
            let para = (cruza.y as usize + i) * linha + cruza.x as usize;
            let n = cruza.largura as usize;
            quadro[para..para + n].copy_from_slice(&pixels[de..de + n]);
        }
    }
}
