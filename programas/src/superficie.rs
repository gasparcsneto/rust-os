//! Uma superfície do compositor, do lado do processo.
//!
//! # O que ela é
//!
//! Uma camada da tela cujos pixels moram na memória deste processo:
//! [`Superficie::pixels`] é uma fatia comum, e escrever nela é desenhar. O
//! compositor lê dos mesmos frames — nada é copiado —, e só recompõe o que
//! o processo acusa com [`Superficie::danificar`].
//!
//! Ela nasce invisível: desenhe, posicione, e então [`Superficie::mostrar`].
//! E some quando o valor sai de escopo — a camada sai da tela, e a memória
//! sai do processo.
//!
//! # De onde vem o endereço
//!
//! Da segunda metade de [`MAPEAVEL`], acima de onde o [monte](crate::monte)
//! pode chegar. Quem escolhe é este módulo, numa tabela de faixas ocupadas
//! do processo: a primeira faixa livre que caiba. Uma superfície fechada
//! devolve a faixa, e a próxima pode cair no mesmo lugar — é o que deixa uma
//! janela abrir e fechar sem fim.

use core::cell::UnsafeCell;

use protocolo::usuario::superficie::{self as abi, operacao};
use protocolo::usuario::{MAPEAVEL, PAGINA};

use crate::monte::FIM_DO_MONTE;
use crate::sistema;

/// Quantas superfícies um processo tem ao mesmo tempo, no máximo — o mesmo
/// que o kernel admite somando todos.
const FAIXAS: usize = 16;

/// As faixas ocupadas, `(início, fim)`, sem ordem. Zero é vaga.
struct Faixas(UnsafeCell<[(u64, u64); FAIXAS]>);

// SAFETY: um processo é um fluxo só — ver o cabeçalho do pacote.
unsafe impl Sync for Faixas {}

static OCUPADAS: Faixas = Faixas(UnsafeCell::new([(0, 0); FAIXAS]));

/// A primeira faixa de `bytes` livre, reservada; `None` se nenhuma cabe.
fn reservar(bytes: u64) -> Option<u64> {
    // SAFETY: um fluxo só; ninguém mais segura esta referência.
    let ocupadas = unsafe { &mut *OCUPADAS.0.get() };
    let vaga = ocupadas.iter().position(|&(inicio, _)| inicio == 0)?;
    // Os candidatos são o começo da região e o fim de cada faixa ocupada:
    // se há lugar, ele começa num desses pontos.
    let candidatos =
        core::iter::once(FIM_DO_MONTE).chain(ocupadas.iter().filter(|f| f.0 != 0).map(|f| f.1));
    let mut escolhido = None;
    for inicio in candidatos {
        let fim = inicio + bytes;
        let livre = fim <= MAPEAVEL.1
            && ocupadas
                .iter()
                .filter(|f| f.0 != 0)
                .all(|&(a, b)| fim <= a || inicio >= b);
        if livre && escolhido.is_none_or(|e| inicio < e) {
            escolhido = Some(inicio);
        }
    }
    let inicio = escolhido?;
    ocupadas[vaga] = (inicio, inicio + bytes);
    Some(inicio)
}

fn devolver(inicio: u64) {
    // SAFETY: como em `reservar`.
    let ocupadas = unsafe { &mut *OCUPADAS.0.get() };
    if let Some(f) = ocupadas.iter_mut().find(|f| f.0 == inicio) {
        *f = (0, 0);
    }
}

/// Uma camada do compositor com os pixels neste processo.
pub struct Superficie {
    descritor: u64,
    inicio: u64,
    largura: u32,
    altura: u32,
}

impl Superficie {
    /// Cria uma superfície de `largura` por `altura`, invisível, na origem.
    /// O erro é o do kernel — ou [`sistema::erro::SEM_MEMORIA`] quando o
    /// processo não tem mais onde pô-la.
    pub fn nova(largura: u32, altura: u32) -> Result<Superficie, i64> {
        // Os limites antes da conta: dois lados de 32 bits multiplicados por
        // quatro passam de 64 bits, e a faixa reservada com um tamanho
        // transbordado seria qualquer uma.
        if largura == 0 || altura == 0 || largura > abi::MAIOR_LADO || altura > abi::MAIOR_LADO {
            return Err(sistema::erro::TAMANHO_INVALIDO);
        }
        let bytes = (largura as u64 * altura as u64 * 4).div_ceil(PAGINA) * PAGINA;
        let inicio = reservar(bytes).ok_or(sistema::erro::SEM_MEMORIA)?;
        let descritor = sistema::superficie(largura, altura, inicio);
        if descritor < 0 {
            devolver(inicio);
            return Err(descritor);
        }
        Ok(Superficie {
            descritor: descritor as u64,
            inicio,
            largura,
            altura,
        })
    }

    pub fn largura(&self) -> u32 {
        self.largura
    }

    pub fn altura(&self) -> u32 {
        self.altura
    }

    /// O descritor, para quem quiser falar com o kernel direto.
    pub fn descritor(&self) -> u64 {
        self.descritor
    }

    /// Onde os pixels estão neste processo.
    pub fn endereco(&self) -> u64 {
        self.inicio
    }

    /// Os pixels, linha a linha, `0xAARRGGBB`.
    pub fn pixels(&mut self) -> &mut [u32] {
        // SAFETY: o kernel mapeou `largura * altura * 4` bytes graváveis em
        // `inicio`, alinhados a página; eles são desta superfície enquanto
        // ela viver, e o `&mut self` garante uma referência só.
        unsafe {
            core::slice::from_raw_parts_mut(
                self.inicio as *mut u32,
                self.largura as usize * self.altura as usize,
            )
        }
    }

    fn controlar(&self, op: u64, argumento: u64) -> Result<(), i64> {
        match sistema::controlar(self.descritor, op, argumento) {
            0 => Ok(()),
            e => Err(e),
        }
    }

    /// Leva o canto superior esquerdo a `(x, y)` na tela.
    pub fn mover(&self, x: i32, y: i32) -> Result<(), i64> {
        self.controlar(operacao::MOVER, abi::posicao(x, y))
    }

    /// Diz ao compositor que o retângulo mudou.
    pub fn danificar(&self, x: u16, y: u16, largura: u16, altura: u16) -> Result<(), i64> {
        self.controlar(operacao::DANO, abi::retangulo(x, y, largura, altura))
    }

    /// Diz ao compositor que a superfície inteira mudou.
    pub fn danificar_tudo(&self) -> Result<(), i64> {
        self.danificar(0, 0, self.largura as u16, self.altura as u16)
    }

    /// A opacidade da camada inteira: 0 a esconde, 255 a mostra inteira.
    pub fn opacidade(&self, opacidade: u8) -> Result<(), i64> {
        self.controlar(operacao::OPACIDADE, opacidade as u64)
    }

    /// Mostra a camada — opacidade inteira.
    pub fn mostrar(&self) -> Result<(), i64> {
        self.opacidade(u8::MAX)
    }

    /// Põe a camada na frente das outras — abaixo do cursor.
    pub fn trazer_para_frente(&self) -> Result<(), i64> {
        self.controlar(operacao::FRENTE, 0)
    }

    /// Usa o byte alto de cada pixel como a opacidade dele, ou o ignora.
    pub fn transparente(&self, sim: bool) -> Result<(), i64> {
        let mistura = if sim { operacao::ALFA } else { operacao::OPACA };
        self.controlar(operacao::MISTURA, mistura)
    }

    /// Manda a entrada desta superfície — o ponteiro sobre ela, as teclas
    /// com o foco nela — para o canal de eventos `canal`, um descritor que
    /// este processo escuta. Sem isso, ela vai para o canal das janelas.
    pub fn entrada(&self, canal: u64) -> Result<(), i64> {
        self.controlar(operacao::ENTRADA, canal)
    }

    /// Pede o foco do teclado para esta superfície.
    pub fn focar(&self) -> Result<(), i64> {
        self.controlar(operacao::FOCO, 1)
    }
}

impl Drop for Superficie {
    fn drop(&mut self) {
        // Fechar tira a camada da tela e a memória do processo; só depois a
        // faixa volta a ser escolhível.
        sistema::fechar(self.descritor);
        devolver(self.inicio);
    }
}
