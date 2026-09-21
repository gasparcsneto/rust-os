//! Camada de abstração de arquitetura.
//!
//! # Como funciona
//!
//! Cada arquitetura suportada tem um submódulo que exporta o mesmo conjunto
//! de itens. O `pub use ... as atual` abaixo escolhe um deles em tempo de
//! compilação, e o resto do kernel importa sempre de `crate::arch`, sem
//! nenhum `cfg` espalhado pelo código.
//!
//! # Por que tipos concretos e não `dyn Trait`
//!
//! O caminho natural em Rust seria um `trait SerialPort` com objetos de trait.
//! Não dá: objetos de trait exigem ponteiro gordo e, para armazená-los num
//! `static`, alocação — que o kernel ainda não tem. Um alias de tipo
//! ([`Uart`]) resolvido por `cfg` dá o mesmo desacoplamento com despacho
//! estático e custo zero.
//!
//! # O que cada backend precisa fornecer
//!
//! - `Uart`: o tipo concreto da porta serial da plataforma.
//! - `init_seriais()`: abre as portas e devolve (console humano, canal do
//!   agente). Qualquer uma pode ser `None`.
//! - `halt_forever()`: para a CPU definitivamente.
//! - `sem_interrupcoes()`: executa uma closure com interrupções mascaradas.
//! - `identificar_cpu()`: string de identificação do processador.
//! - `init_excecoes()`: instala o mecanismo de tratamento de exceções.
//! - `init_interrupcoes()`: liga o controlador de interrupções e o timer.
//! - `reservar_faixas()`: faixas físicas que o alocador de frames deve evitar.
//! - `init_paginacao()`, `mapear()`, `desmapear()`, `traduzir()`: a MMU.
//! - `acesso_fisico()`: endereço virtual por onde se enxerga um físico.
//! - `esperar_interrupcao()`: dorme até a próxima interrupção.
//! - `disparar_breakpoint()`: gera uma exceção recuperável, para autoteste.
//! - `encerrar_emulador()`: termina o QEMU comunicando sucesso ou falha.
//! - `nome()`: o nome da arquitetura, para o protocolo do agente.
//! - O ponto de entrada de boot, que preenche [`crate::machine`] e chama
//!   [`crate::inicio_comum`].

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64 as atual;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64 as atual;

// A paginação ainda só tem consumidor nos testes: quem vai mapear páginas de
// verdade é o heap, próximo da fila. Anotar mantém o build limpo sem esconder
// código morto de verdade.
#[cfg_attr(not(feature = "modo-teste"), allow(unused_imports))]
pub use atual::{
    Uart, acesso_fisico, desmapear, disparar_breakpoint, encerrar_emulador, esperar_interrupcao,
    halt_forever, identificar_cpu, init_excecoes, init_interrupcoes, init_paginacao, init_seriais,
    mapear, nome, reservar_faixas, sem_interrupcoes, traduzir,
};

/// Como uma página pode ser acessada.
///
/// Os dois hardwares codificam isto de formas completamente diferentes — bits
/// de flag no x86, índices para uma tabela de atributos no ARM —, mas as
/// perguntas que o kernel precisa responder são as mesmas.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissoes {
    pub escrita: bool,
    pub executavel: bool,
    /// Memória de dispositivo: sem cache, sem junção de escritas, sem
    /// reordenação. Registradores de hardware exigem isto; RAM, não.
    pub dispositivo: bool,
}

#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
impl Permissoes {
    /// Dados do kernel: leitura e escrita, jamais executáveis.
    pub const DADOS: Self = Self {
        escrita: true,
        executavel: false,
        dispositivo: false,
    };
}

/// Identificação do processador, num buffer de tamanho fixo.
///
/// Devolvemos isto em vez de `&'static str` porque a string é *lida do
/// hardware* em tempo de execução (CPUID no x86, MIDR_EL1 no ARM) e precisa
/// de um lugar para morar sem heap.
pub struct IdCpu {
    bytes: [u8; 24],
    tam: usize,
}

impl IdCpu {
    pub const fn vazio() -> Self {
        Self {
            bytes: [0; 24],
            tam: 0,
        }
    }

    /// Constrói a partir de bytes lidos do hardware, truncando se preciso.
    pub fn de_bytes(origem: &[u8]) -> Self {
        let mut id = Self::vazio();
        let n = origem.len().min(id.bytes.len());
        id.bytes[..n].copy_from_slice(&origem[..n]);
        id.tam = n;
        id
    }

    pub fn como_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.tam]).unwrap_or("desconhecido")
    }
}
