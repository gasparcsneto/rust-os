//! As sessões do canal do agente: vários agentes ao mesmo tempo.
//!
//! # O que é uma sessão
//!
//! Um agente conectado por um canal. Cada canal tem o seu quadro sendo
//! montado, a sua tarefa que o atende e a sua saída — o pedido de um não
//! cola no do outro, e a resposta de um não sai pelo canal do outro. O
//! número da sessão é atribuído pelo kernel, pelo canal por onde o pedido
//! chegou, e não dito pelo agente: é o que vai para o log como quem fez.
//!
//! - a **sessão 0** é a serial: o canal de sempre, e o de emergência — o
//!   único que responde no modo post-mortem;
//! - as **sessões 1 a 4** são as portas do `virtio-console`, uma por
//!   agente — ver [`crate::virtio::console`].
//!
//! # Acima do transporte
//!
//! O resto do canal — o enquadramento, o JSON-RPC, os comandos — não sabe
//! por onde os bytes vieram: pergunta ao [`Canal`]. Um transporte novo — o
//! TCP, quando houver rede — é mais um caso aqui, e nada muda em cima.

/// O número de uma sessão.
pub type Sessao = u8;

/// A serial: a sessão de sempre, e a de emergência.
pub const SERIAL: Sessao = 0;

/// Por onde uma sessão fala.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Canal {
    /// A serial do agente: a COM2 no x86, a PL011 no ARM.
    Serial,
    /// Uma porta do `virtio-console`, da 1 à 4.
    Porta(u8),
}

impl Canal {
    /// A sessão deste canal.
    pub const fn sessao(self) -> Sessao {
        match self {
            Canal::Serial => SERIAL,
            Canal::Porta(p) => p,
        }
    }

    /// O nome do transporte, para o relatório.
    pub const fn transporte(self) -> &'static str {
        match self {
            Canal::Serial => "serial",
            Canal::Porta(_) => "virtio-console",
        }
    }

    /// Quantos bytes este canal já perdeu na entrada.
    pub fn perdidos(self) -> u64 {
        match self {
            Canal::Serial => crate::tarefas::entrada::perdidos(),
            Canal::Porta(p) => crate::virtio::console::perdidos(p),
        }
    }

    /// Quantos bytes **de texto** este canal já perdeu: o que o montador
    /// confere para saber se um quadro chegou inteiro.
    ///
    /// Na serial, é o mesmo que [`Canal::perdidos`]. Numa porta é sempre
    /// zero, e não por otimismo: os bytes passam pela sessão cifrada antes de
    /// virar texto, e um byte perdido no caminho faz a etiqueta do quadro não
    /// conferir — a sessão acaba ali, em [`crate::agent::seguro`], e nenhum
    /// texto danificado chega ao montador.
    pub fn perdidos_no_texto(self) -> u64 {
        match self {
            Canal::Serial => crate::tarefas::entrada::perdidos(),
            Canal::Porta(_) => 0,
        }
    }

    /// Descarta a entrada até a próxima quebra de linha. Verdadeiro se a
    /// achou.
    ///
    /// Só a serial: numa porta o texto não perde bytes — ver
    /// [`Canal::perdidos_no_texto`] —, e a entrada crua é cifrada, onde uma
    /// "quebra de linha" é só um byte qualquer.
    pub fn descartar_ate_nova_linha(self) -> bool {
        match self {
            Canal::Serial => crate::tarefas::entrada::descartar_ate_nova_linha(),
            Canal::Porta(_) => false,
        }
    }

    /// Quantas vezes o outro lado deste canal abriu. A serial não sabe —
    /// não há linha de modem entre ela e o socket —, e diz sempre zero.
    pub fn geracao(self) -> u64 {
        match self {
            Canal::Serial => 0,
            Canal::Porta(p) => crate::virtio::console::geracao(p),
        }
    }

    /// O próximo byte, quando houver.
    /// O próximo byte, e se ele chegou depois de um silêncio — o que só a
    /// serial sabe dizer; numa porta, o fim de um cliente é a geração dela.
    pub async fn proximo_byte(self) -> (u8, bool) {
        match self {
            Canal::Serial => crate::tarefas::entrada::proximo_byte().await,
            Canal::Porta(p) => (crate::virtio::console::proximo_byte(p).await, false),
        }
    }
}
