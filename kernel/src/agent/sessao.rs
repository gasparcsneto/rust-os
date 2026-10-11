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
//!   agente — ver [`crate::virtio::console`];
//! - as **sessões 5 a 8** são as vagas do canal por TCP, uma por conexão
//!   aceita na porta do canal — ver [`crate::rede::canal`].
//!
//! # Acima do transporte
//!
//! O resto do canal — o enquadramento, o JSON-RPC, os comandos — não sabe
//! por onde os bytes vieram: pergunta ao [`Canal`]. O TCP é mais um caso
//! aqui, e nada mudou em cima: a mesma sessão cifrada, o mesmo aperto, a
//! mesma chave no registro, o mesmo gate. A conexão não traz autoridade
//! nenhuma — nem o endereço do par, nem a porta: quem age é a chave que
//! provou o aperto, e o que ela pode é o papel que o registro lhe dá.

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
    /// Uma vaga do canal por TCP, da 1 à [`crate::rede::canal::VAGAS`].
    Tcp(u8),
}

/// Um byte que chegou por um canal: o valor, se veio depois de um silêncio
/// — o que só a serial sabe dizer —, e a conexão de onde veio — a geração
/// do transporte; zero na serial.
#[derive(Clone, Copy, Debug)]
pub struct Chegada {
    pub byte: u8,
    pub depois_de_silencio: bool,
    pub geracao: u64,
}

impl Canal {
    /// A sessão deste canal.
    pub const fn sessao(self) -> Sessao {
        match self {
            Canal::Serial => SERIAL,
            Canal::Porta(p) => p,
            Canal::Tcp(v) => crate::rede::canal::sessao(v),
        }
    }

    /// O canal da sessão `s`, se ela é de um: a serial, uma porta, uma vaga
    /// do canal TCP.
    pub fn da_sessao(s: Sessao) -> Option<Canal> {
        if s == SERIAL {
            Some(Canal::Serial)
        } else if (1..=crate::virtio::console::PORTAS).contains(&s) {
            Some(Canal::Porta(s))
        } else {
            crate::rede::canal::vaga_da_sessao(s).map(Canal::Tcp)
        }
    }

    /// O nome do transporte, para o relatório.
    pub const fn transporte(self) -> &'static str {
        match self {
            Canal::Serial => "serial",
            Canal::Porta(_) => "virtio-console",
            Canal::Tcp(_) => "tcp",
        }
    }

    /// Quantos bytes este canal já perdeu na entrada. No TCP, nenhum: o
    /// que não cabe na entrada da vaga espera no socket, com a janela
    /// fechada — ver [`crate::rede::canal`].
    pub fn perdidos(self) -> u64 {
        match self {
            Canal::Serial => crate::tarefas::entrada::perdidos(),
            Canal::Porta(p) => crate::virtio::console::perdidos(p),
            Canal::Tcp(_) => 0,
        }
    }

    /// Quantos bytes **de texto** este canal já perdeu: o que o montador
    /// confere para saber se um quadro chegou inteiro.
    ///
    /// Na serial, é o mesmo que [`Canal::perdidos`]. Numa porta e no TCP é
    /// sempre zero, e não por otimismo: os bytes passam pela sessão cifrada
    /// antes de virar texto, e um byte perdido no caminho faz a etiqueta do
    /// quadro não conferir — a sessão acaba ali, em [`crate::agent::seguro`],
    /// e nenhum texto danificado chega ao montador.
    pub fn perdidos_no_texto(self) -> u64 {
        match self {
            Canal::Serial => crate::tarefas::entrada::perdidos(),
            Canal::Porta(_) | Canal::Tcp(_) => 0,
        }
    }

    /// Descarta a entrada até a próxima quebra de linha. Verdadeiro se a
    /// achou.
    ///
    /// Só a serial: numa porta e no TCP o texto não perde bytes — ver
    /// [`Canal::perdidos_no_texto`] —, e a entrada crua é cifrada, onde uma
    /// "quebra de linha" é só um byte qualquer.
    pub fn descartar_ate_nova_linha(self) -> bool {
        match self {
            Canal::Serial => crate::tarefas::entrada::descartar_ate_nova_linha(),
            Canal::Porta(_) | Canal::Tcp(_) => false,
        }
    }

    /// Quantas vezes o outro lado deste canal abriu: a geração da porta, ou
    /// quantas conexões a vaga do canal TCP aceitou. A serial não sabe —
    /// não há linha de modem entre ela e o socket —, e diz sempre zero.
    pub fn geracao(self) -> u64 {
        match self {
            Canal::Serial => 0,
            Canal::Porta(p) => crate::virtio::console::geracao(p),
            Canal::Tcp(v) => crate::rede::canal::geracao(v),
        }
    }

    /// O cliente da conexão `geracao` ainda está do outro lado? Na serial,
    /// sempre; numa porta, enquanto ela não reabrir; no TCP, enquanto a
    /// conexão estiver aberta — o fim dela o kernel vê.
    pub fn na_conexao(self, geracao: u64) -> bool {
        match self {
            Canal::Serial => true,
            Canal::Porta(p) => crate::virtio::console::geracao(p) == geracao,
            Canal::Tcp(v) => crate::rede::canal::na_conexao(v, geracao),
        }
    }

    /// O próximo byte, quando houver: com a marca de silêncio — que só a
    /// serial sabe dizer; numa porta e no TCP, o fim de um cliente é a
    /// geração —, e a conexão de onde ele veio.
    pub async fn proximo_byte(self) -> Chegada {
        match self {
            Canal::Serial => {
                let (byte, depois_de_silencio) = crate::tarefas::entrada::proximo_byte().await;
                Chegada {
                    byte,
                    depois_de_silencio,
                    geracao: 0,
                }
            }
            Canal::Porta(p) => {
                let byte = crate::virtio::console::proximo_byte(p).await;
                Chegada {
                    byte,
                    depois_de_silencio: false,
                    geracao: crate::virtio::console::geracao(p),
                }
            }
            Canal::Tcp(v) => {
                let (byte, geracao) = crate::rede::canal::proximo_byte(v).await;
                Chegada {
                    byte,
                    depois_de_silencio: false,
                    geracao,
                }
            }
        }
    }
}
