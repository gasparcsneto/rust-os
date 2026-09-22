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
//! - `init_interrupcao_serial()`: faz a serial do agente avisar por
//!   interrupção em vez de ser consultada em laço.
//! - `reservar_faixas()`: faixas físicas que o alocador de frames deve evitar.
//! - `init_paginacao()`, `mapear_frame()`, `desmapear()`, `traduzir()`: a MMU.
//! - `acesso_fisico()`: endereço virtual por onde se enxerga um físico.
//! - `esperar_interrupcao()`: dorme até a próxima interrupção.
//! - `dormir_se_ocioso()`: dorme só se não houver trabalho, sem corrida.
//! - `disparar_breakpoint()`: gera uma exceção recuperável, para autoteste.
//! - `disparar_falha_fatal()`: gera uma exceção irrecuperável, de propósito.
//! - `init_usuario()`, `entrar_em_usuario()`, `definir_pilha_de_kernel()`: a
//!   travessia para o anel sem privilégio — ver [`crate::usuario`].
//! - `Contexto`, `preparar_contexto()`, `ceder_cpu()`: a troca de contexto
//!   entre fios de execução. O mecanismo difere entre as duas arquiteturas —
//!   ver [`crate::fios`].
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

// A fachada reexporta a superfície completa que os backends oferecem. Quais
// itens têm consumidor depende da configuração de build — `halt_forever` não
// é usado em modo de teste, onde o pânico encerra o emulador; e há itens que
// só os testes exercitam. Anotar aqui é mais honesto que espalhar `allow`
// pelos backends, que esconderia código morto de verdade dentro deles.
#[allow(unused_imports)]
pub use atual::{
    BASE_DAS_PILHAS, BASE_DO_HEAP, COBERTURA_DA_ENTRADA_DE_TOPO, Contexto, Uart, acesso_fisico,
    ceder_cpu, criar_espaco, definir_pilha_de_kernel, desmapear, destruir_espaco,
    disparar_breakpoint, disparar_falha_fatal, dormir_se_ocioso, encerrar_emulador,
    entrar_em_usuario, espaco_atual, espaco_do_kernel, esperar_interrupcao,
    falha_de_estouro_de_pilha, halt_forever, identificar_cpu, init_excecoes,
    init_interrupcao_serial, init_interrupcoes, init_paginacao, init_seriais, init_usuario,
    mapear_frame, nome, percorrer_paginas_do_usuario, preparar_contexto, preparar_contexto_de_fork,
    redirecionar_para, reservar_faixas, sem_interrupcoes, traduzir, trocar_espaco,
};

/// Só para a suíte: o par de conversões de permissão de cada backend.
#[cfg(feature = "modo-teste")]
pub use atual::permissoes_ida_e_volta;

/// Tamanho de uma página nas duas arquiteturas.
pub const TAMANHO_PAGINA: u64 = 4096;

/// Qual entrada da tabela de topo cobre este endereço.
///
/// É a pergunta que decide se duas regiões podem ser separadas por uma tabela
/// de tradução por processo: entradas diferentes, sim; a mesma entrada, não —
/// copiar a do kernel levaria junto a do usuário.
pub const fn entrada_de_topo(endereco: u64) -> u64 {
    endereco / COBERTURA_DA_ENTRADA_DE_TOPO
}

/// A entrada de topo que cada espaço de endereços tem só para si.
///
/// Todas as outras são **cópias** das do kernel: os espaços compartilham as
/// tabelas de nível inferior por referência, e é isso que faz um mapeamento do
/// kernel valer em todos ao mesmo tempo.
pub const ENTRADA_PRIVADA: u64 = entrada_de_topo(crate::usuario::BASE);

/// Este endereço mora na parte do espaço que pertence só a ele?
///
/// A pergunta decide quem pode **liberar uma tabela**. Numa entrada privada,
/// esvaziar uma tabela e devolvê-la ao alocador é correto: ninguém mais a
/// alcança. Numa entrada compartilhada, é uma referência pendurada — quem
/// desmapeia enxerga só a raiz ativa, e zerar a entrada de topo ali não
/// alcança as cópias que os outros espaços guardam. Elas continuariam
/// apontando para um frame que já voltou ao alocador.
pub const fn e_privado(endereco: u64) -> bool {
    entrada_de_topo(endereco) == ENTRADA_PRIVADA
}

/// Recusa endereços que não servem para um mapeamento de página.
///
/// O ponto aqui não é ser pedante: as duas APIs de hardware **arredondam para
/// baixo em silêncio** um endereço desalinhado. Quem pede para mapear
/// `frame + 8` recebe um mapeamento para `frame`, sem qualquer aviso, e passa
/// a escrever 8 bytes antes do que pretendia. Falhar alto é a única forma de
/// esse erro ser encontrado no dia em que é cometido, e não semanas depois
/// como corrupção inexplicável.
#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
pub fn validar_alinhamento(virtual_: u64, fisico: u64) -> Result<(), &'static str> {
    if !virtual_.is_multiple_of(TAMANHO_PAGINA) {
        return Err("endereco virtual desalinhado");
    }
    if !fisico.is_multiple_of(TAMANHO_PAGINA) {
        return Err("endereco fisico desalinhado");
    }
    Ok(())
}

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
    /// Alcançável a partir do anel sem privilégio.
    ///
    /// É o bit que separa o kernel do userspace, e o padrão é `false` de
    /// propósito: uma página que deveria ser do usuário e não é gera uma falha
    /// alta e imediata; uma página do kernel que vaza para o usuário não gera
    /// falha nenhuma — gera uma brecha.
    pub usuario: bool,
}

#[cfg_attr(not(feature = "modo-teste"), allow(dead_code))]
impl Permissoes {
    /// Dados do kernel: leitura e escrita, jamais executáveis.
    pub const DADOS: Self = Self {
        escrita: true,
        executavel: false,
        dispositivo: false,
        usuario: false,
    };

    /// Dados de userspace: leitura e escrita pelo anel sem privilégio.
    pub const DADOS_USUARIO: Self = Self {
        escrita: true,
        executavel: false,
        dispositivo: false,
        usuario: true,
    };

    // Não existe uma constante para código de userspace: as permissões de cada
    // segmento vêm do ELF que pediu por elas, montadas em
    // `usuario::programa::carregar`. Uma constante aqui seria um segundo lugar
    // com a mesma resposta, e o dia em que os dois discordassem o carregador
    // silenciosamente ignoraria o que o programa pediu.
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
