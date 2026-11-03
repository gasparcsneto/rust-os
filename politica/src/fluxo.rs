//! O fluxo da malha como conta pura: um canal ordenado de bytes, nos dois
//! sentidos, entre dois processos do mesmo titular — os estados, os
//! sentidos, o buffer de cada um, o crédito entre dois Dukes, as cotas e as
//! lápides.
//!
//! # O que é
//!
//! A entrega da malha ([`crate::malha`]) leva um texto curto, de uma vez. O
//! fluxo leva bytes, quantos forem, na ordem, com contrapressão: um processo
//! **abre** um pedido contra um endpoint que oferece uma intenção, o dono do
//! endpoint **aceita**, e os dois escrevem e leem, cada um no seu sentido —
//! a **ida**, de quem abriu para quem aceitou, e a **volta** —, até
//! terminar.
//!
//! - **Terminar um sentido** (`finish`): quem escreve não escreve mais; quem
//!   lê lê o resto e depois o **fim**. O outro sentido continua.
//! - **Fechar** (`close`): a ponta sai. O que ela já escreveu continua
//!   legível pela outra, até o fim do sentido — como o FIN do TCP —, e o que
//!   estava para ela ler sai zerado.
//! - **Abortar**: o que o kernel faz na revogação, na morte, no `exec`, no
//!   desligamento, no prazo, no erro de protocolo: os dois sentidos acabam
//!   na hora, com os buffers zerados, e cada ponta ouve o motivo.
//!
//! Um leitor nunca confunde o fim limpo com o aborto: o fim é `fim: true`,
//! depois do último byte; o abortado responde o motivo.
//!
//! # O que ele não é
//!
//! - **Uma autoridade.** Cada passo — abrir, aceitar, escrever, ler — é uma
//!   decisão do gate de quem o dá, com a permissão `fabric.stream` e a
//!   intenção como recurso enumerado ([`crate::permissao`]). Esta conta
//!   confere só a forma: de quem é cada ponta, o que cabe, em que estado.
//! - **Uma transferência de autoridade.** Os bytes são entrada não confiável
//!   para quem os lê; o que ele faz com eles é decidido pelo papel dele.
//! - **Um caminho entre titulares.** As duas pontas são do mesmo titular.
//! - **Persistente.** O fluxo vive na memória: um boot o perde, e um id de
//!   outro boot não é de nada.
//!
//! # As pontas
//!
//! Uma ponta é um **processo** — o fio, com o programa que o kernel
//! conferiu ([`Programa`]) —, ou, na modalidade entre dois Dukes, o **par**:
//! a chave do outro Duke, a relação e o programa que ele atesta, que não é
//! critério de nada ([`Ponta::Remota`]). Um fluxo tem no máximo uma ponta
//! remota. Um id só se resolve para as duas pontas ([`Fluxos::intencao_para`]);
//! para qualquer outro, ele não existe.
//!
//! # O crédito
//!
//! Entre dois Dukes, cada lado diz ao outro quanto pode mandar. Quem lê
//! devolve o que liberou, de [`LIMIAR_DO_CREDITO`] em diante; quem manda
//! nunca passa do que tem — passar é erro de protocolo, e o fluxo acaba. A
//! memória de cada lado fica limitada pelo que ele mesmo concedeu, faça o
//! outro o que fizer: `concedido + no buffer + a devolver` é sempre
//! [`BUFFER_DO_SENTIDO`].

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;

use crate::codigo::Codigo;
pub use crate::malha::{Programa, Titular};
use crate::sigiloso::{zerar, zerar_bloco};

/// O buffer de cada sentido, em bytes: o mesmo de uma conexão.
pub const BUFFER_DO_SENTIDO: usize = 16 * 1024;
/// O maior pedaço de uma escrita: uma decisão do gate por até um buffer.
pub const MAIOR_ESCRITA: usize = BUFFER_DO_SENTIDO;
/// O maior pedaço de uma leitura.
pub const MAIOR_LEITURA: usize = BUFFER_DO_SENTIDO;
/// Quantos fluxos um processo tem — os que abriu, e os que aceitou.
pub const FLUXOS_POR_PROCESSO: usize = 4;
/// Quantos fluxos um titular tem, somando os processos dele.
pub const FLUXOS_POR_TITULAR: usize = 8;
/// Quantos fluxos a máquina guarda: 16 × 2 × 16 KiB, 512 KiB no pior caso.
pub const FLUXOS: usize = 16;
/// Quantos pedidos esperam o aceite num endpoint.
pub const PEDIDOS_POR_ENDPOINT: usize = 4;
/// Quantos pedidos esperam o aceite na máquina.
pub const PEDIDOS: usize = 16;
/// Quantos fluxos daqui vão a outros Dukes ao mesmo tempo.
pub const REMOTOS_QUE_SAEM: usize = 2;
/// Quantos fluxos chegam de outro Duke por uma relação.
pub const REMOTOS_POR_RELACAO: usize = 1;
/// Quantas sessões de fluxo, vindas de outros Dukes, ocupam as vagas do
/// enlace ao mesmo tempo: as outras duas ficam para o enlace e a cerimônia.
pub const SESSOES_QUE_CHEGAM: usize = 2;
/// Quantas lápides a tabela lembra.
pub const LAPIDES: usize = 32;
/// O prazo de um pedido sem aceite.
pub const PRAZO_DO_ACEITE_MS: u64 = 30_000;
/// O prazo de um pedido a outro Duke: o do aceite de lá, mais a conexão, o
/// aperto e o pedido.
pub const PRAZO_DO_ACEITE_REMOTO_MS: u64 = 50_000;
/// Quanto um fluxo aberto fica sem mover um byte antes de acabar.
pub const OCIOSO_MS: u64 = 120_000;
/// A partir de quanto espaço liberado o leitor devolve crédito ao par.
pub const LIMIAR_DO_CREDITO: usize = 4 * 1024;
/// O maior motivo que se guarda, em bytes: cabe no detalhe da auditoria com
/// as contagens.
pub const MAIOR_MOTIVO: usize = 40;

/// Os métodos que o domínio do fluxo leva de outro Duke ao gate daqui: o
/// pedido de abertura e cada pedaço de dados. O fim e o fecho que chegam
/// não pedem autoridade: o kernel os aplica.
pub const METODOS_REMOTOS: [&str; 2] = ["stream.open", "stream.write"];

/// Se `nome` é um dos [`METODOS_REMOTOS`].
pub fn metodo_remoto(nome: &str) -> bool {
    METODOS_REMOTOS.contains(&nome)
}

/// Os motivos de encerramento: textos curtos e fixos, que vão à auditoria e
/// à ponta.
pub mod motivo {
    /// Os dois sentidos terminaram e foram lidos.
    pub const CONCLUIDO: &str = "concluido";
    /// Uma ponta fechou.
    pub const FECHADO: &str = "fechado pela ponta";
    /// Ninguém aceitou no prazo.
    pub const PRAZO_DO_ACEITE: &str = "prazo do aceite";
    /// O endpoint acabou antes do aceite.
    pub const ENDPOINT: &str = "o endpoint fechou";
    /// A reconfirmação no aceite recusou quem abriu.
    pub const ABRIDOR: &str = "quem abriu nao pode mais";
    /// Muito tempo sem dados.
    pub const OCIOSO: &str = "ocioso";
    /// Uma ponta morreu.
    pub const PROCESSO: &str = "o processo acabou";
    /// Uma ponta trocou de imagem.
    pub const PROGRAMA: &str = "o programa mudou";
    /// A chave ou a Pessoa do titular foi revogada.
    pub const REVOGADO: &str = "revogado";
    /// O dispositivo do par foi revogado.
    pub const DISPOSITIVO_REVOGADO: &str = "o dispositivo foi revogado";
    /// O dispositivo do par foi suspenso.
    pub const DISPOSITIVO_SUSPENSO: &str = "o dispositivo foi suspenso";
    /// A relação do par foi desfeita.
    pub const RELACAO: &str = "a relacao foi desfeita";
    /// A máquina está reiniciando ou desligando.
    pub const DESLIGANDO: &str = "desligando";
    /// O transporte do par caiu.
    pub const CONEXAO: &str = "a conexao caiu";
    /// O par mandou o que o protocolo não aceita.
    pub const PROTOCOLO: &str = "protocolo";
    /// O aperto com o par não fechou: a chave, a resposta, a entropia.
    pub const APERTO: &str = "o aperto com o par falhou";
    /// O par não respondeu no prazo do aperto.
    pub const PAR_MUDO: &str = "o par nao respondeu";
    /// Não houve fio para levar a sessão com o par.
    pub const SEM_FIO: &str = "sem fio para a sessao";
}

/// O motivo que o par deu — numa recusa ou num `fechar` —, guardado como
/// os daqui: curto, só ASCII imprimível, e marcado como do par.
pub fn motivo_do_par(texto: &str) -> String {
    motivo_guardado(&alloc::format!("par: {texto}"))
}

/// Bytes que saem da memória zerados: o que uma leitura devolve.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Pedaco(Vec<u8>);

impl Pedaco {
    /// Uma cópia de `bytes`.
    pub fn de(bytes: &[u8]) -> Pedaco {
        Pedaco(Vec::from(bytes))
    }
}

impl Deref for Pedaco {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Pedaco {
    // O conteúdo não vai a log nenhum: só o tamanho.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Pedaco({} bytes)", self.0.len())
    }
}

impl Drop for Pedaco {
    fn drop(&mut self) {
        zerar_bloco(&mut self.0);
    }
}

/// O buffer de um sentido: um anel de [`BUFFER_DO_SENTIDO`] bytes, alocado
/// na primeira escrita e devolvido zerado quando esvazia. O que se lê sai
/// zerado do anel na hora.
struct Anel {
    bloco: Vec<u8>,
    inicio: usize,
    tamanho: usize,
}

impl Anel {
    const fn novo() -> Anel {
        Anel {
            bloco: Vec::new(),
            inicio: 0,
            tamanho: 0,
        }
    }

    fn tamanho(&self) -> usize {
        self.tamanho
    }

    fn livre(&self) -> usize {
        BUFFER_DO_SENTIDO - self.tamanho
    }

    /// Põe o que couber de `dados`; devolve quantos entraram.
    fn por(&mut self, dados: &[u8]) -> usize {
        let n = dados.len().min(self.livre());
        if n == 0 {
            return 0;
        }
        if self.bloco.is_empty() {
            self.bloco = alloc::vec![0; BUFFER_DO_SENTIDO];
            self.inicio = 0;
        }
        let fim = (self.inicio + self.tamanho) % BUFFER_DO_SENTIDO;
        let primeira = n.min(BUFFER_DO_SENTIDO - fim);
        self.bloco[fim..fim + primeira].copy_from_slice(&dados[..primeira]);
        self.bloco[..n - primeira].copy_from_slice(&dados[primeira..n]);
        self.tamanho += n;
        n
    }

    /// Tira até `max` bytes, na ordem; o lugar deles fica zerado.
    fn tirar(&mut self, max: usize) -> Pedaco {
        let n = max.min(self.tamanho);
        if n == 0 {
            return Pedaco::default();
        }
        let mut v = Vec::with_capacity(n);
        let primeira = n.min(BUFFER_DO_SENTIDO - self.inicio);
        let (a, b) = (self.inicio, self.inicio + primeira);
        v.extend_from_slice(&self.bloco[a..b]);
        zerar(&mut self.bloco[a..b]);
        v.extend_from_slice(&self.bloco[..n - primeira]);
        zerar(&mut self.bloco[..n - primeira]);
        self.inicio = (self.inicio + n) % BUFFER_DO_SENTIDO;
        self.tamanho -= n;
        if self.tamanho == 0 {
            self.soltar();
        }
        Pedaco(v)
    }

    /// Descarta tudo; devolve quantos bytes saíram.
    fn descartar(&mut self) -> usize {
        let n = self.tamanho;
        self.soltar();
        n
    }

    fn soltar(&mut self) {
        zerar_bloco(&mut self.bloco);
        self.bloco = Vec::new();
        self.inicio = 0;
        self.tamanho = 0;
    }
}

impl Drop for Anel {
    fn drop(&mut self) {
        zerar_bloco(&mut self.bloco);
    }
}

/// Como um sentido está.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EstadoDoSentido {
    /// Quem escreve ainda escreve.
    Aberto,
    /// Quem escreve terminou: quem lê lê o resto, e depois o fim.
    Fim,
    /// Acabou sem fim limpo: o que havia saiu zerado.
    Abortado,
}

impl EstadoDoSentido {
    /// O nome, como a resposta o escreve.
    pub const fn nome(self) -> &'static str {
        match self {
            EstadoDoSentido::Aberto => "open",
            EstadoDoSentido::Fim => "finished",
            EstadoDoSentido::Abortado => "aborted",
        }
    }
}

/// Um sentido: o buffer, o estado e as contas.
struct Sentido {
    anel: Anel,
    estado: EstadoDoSentido,
    /// Quem lê já viu o fim: a leitura que o devolveu, ou — no sentido que
    /// vai ao par — o `fim` que saiu.
    fim_visto: bool,
    escritos: u64,
    lidos: u64,
    descartados: u64,
}

impl Sentido {
    const fn novo() -> Sentido {
        Sentido {
            anel: Anel::novo(),
            estado: EstadoDoSentido::Aberto,
            fim_visto: false,
            escritos: 0,
            lidos: 0,
            descartados: 0,
        }
    }

    /// Quem lê já viu tudo: o fim, depois do último byte, ou o aborto.
    fn terminado(&self) -> bool {
        match self.estado {
            EstadoDoSentido::Aberto => false,
            EstadoDoSentido::Fim => self.anel.tamanho() == 0 && self.fim_visto,
            EstadoDoSentido::Abortado => true,
        }
    }

    /// Acaba sem fim limpo: o que havia sai zerado, e entra na conta.
    fn abortar(&mut self) {
        let n = self.anel.descartar();
        self.descartados += n as u64;
        self.estado = EstadoDoSentido::Abortado;
    }
}

/// Uma ponta de um fluxo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ponta {
    /// Um processo deste Duke, com o programa que o kernel conferiu.
    Processo { fio: u64, programa: Programa },
    /// Outro Duke, pela relação: a chave dele, a relação e o resumo do
    /// programa que ele atesta — atestado, e não conferido; não é critério
    /// de nada.
    Remota {
        dispositivo: [u8; 32],
        relacao: [u8; 16],
        programa: [u8; 32],
    },
}

impl Ponta {
    /// Quem é, para resolver um pedido.
    pub fn quem(&self) -> Quem {
        match self {
            Ponta::Processo { fio, .. } => Quem::Processo(*fio),
            Ponta::Remota {
                dispositivo,
                relacao,
                ..
            } => Quem::Remoto {
                dispositivo: *dispositivo,
                relacao: *relacao,
            },
        }
    }

    fn remota(&self) -> bool {
        matches!(self, Ponta::Remota { .. })
    }
}

/// Quem pede uma operação sobre um fluxo: um processo, ou o par pela
/// relação.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quem {
    Processo(u64),
    Remoto {
        dispositivo: [u8; 32],
        relacao: [u8; 16],
    },
}

/// Qual das pontas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lado {
    /// Quem abriu: escreve na ida, lê a volta.
    Abridor,
    /// Quem aceitou: lê a ida, escreve na volta.
    Aceitante,
}

impl Lado {
    const fn indice(self) -> usize {
        match self {
            Lado::Abridor => 0,
            Lado::Aceitante => 1,
        }
    }

    const fn outro(self) -> Lado {
        match self {
            Lado::Abridor => Lado::Aceitante,
            Lado::Aceitante => Lado::Abridor,
        }
    }
}

/// O endpoint contra o qual o fluxo abriu: um daqui, pelo número, ou um do
/// par, como o par o escreve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Daqui(u64),
    DoPar(String),
}

/// O estado de um fluxo vivo. O encerrado sai da tabela e deixa a lápide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Estado {
    /// Pedido de abertura, esperando o aceite.
    Pedido,
    /// Os dois sentidos podem ter dados.
    Aberto,
}

/// As contas do crédito de um fluxo com uma ponta remota.
#[derive(Clone, Copy, Debug)]
struct Credito {
    /// Quanto o par ainda pode mandar para o sentido que chega dele.
    concedido: u64,
    /// O que o leitor daqui liberou e ainda não se devolveu ao par.
    a_devolver: u64,
    /// Quanto daqui ainda se pode mandar ao par.
    para_mandar: u64,
}

impl Credito {
    const fn inicial() -> Credito {
        Credito {
            concedido: BUFFER_DO_SENTIDO as u64,
            a_devolver: 0,
            para_mandar: BUFFER_DO_SENTIDO as u64,
        }
    }
}

/// Um fluxo vivo.
struct Fluxo {
    id: u64,
    titular: Titular,
    intencao: String,
    endpoint: Endpoint,
    abridor: Ponta,
    aceitante: Ponta,
    estado: Estado,
    /// De quem abriu para quem aceitou.
    ida: Sentido,
    /// De quem aceitou para quem abriu.
    volta: Sentido,
    /// Cada ponta que fechou e saiu: `[abridor, aceitante]`.
    saiu: [bool; 2],
    criado_ms: u64,
    /// O prazo do aceite, enquanto é pedido.
    vence_ms: u64,
    /// O último byte que andou — o relógio da inatividade.
    ultimo_ms: u64,
    versao: u64,
    /// Só com uma ponta remota.
    credito: Option<Credito>,
}

impl Fluxo {
    fn ponta(&self, lado: Lado) -> &Ponta {
        match lado {
            Lado::Abridor => &self.abridor,
            Lado::Aceitante => &self.aceitante,
        }
    }

    /// A ponta que `q` é. O aceitante só é ponta depois do aceite: antes, o
    /// pedido não é dele.
    fn lado_de(&self, q: Quem) -> Option<Lado> {
        if self.abridor.quem() == q {
            Some(Lado::Abridor)
        } else if self.aceitante.quem() == q && self.estado == Estado::Aberto {
            Some(Lado::Aceitante)
        } else {
            None
        }
    }

    /// O sentido em que `lado` escreve.
    fn escrita(&mut self, lado: Lado) -> &mut Sentido {
        match lado {
            Lado::Abridor => &mut self.ida,
            Lado::Aceitante => &mut self.volta,
        }
    }

    /// O sentido que `lado` lê.
    fn leitura(&mut self, lado: Lado) -> &mut Sentido {
        match lado {
            Lado::Abridor => &mut self.volta,
            Lado::Aceitante => &mut self.ida,
        }
    }

    fn escrita_de(&self, lado: Lado) -> &Sentido {
        match lado {
            Lado::Abridor => &self.ida,
            Lado::Aceitante => &self.volta,
        }
    }

    fn leitura_de(&self, lado: Lado) -> &Sentido {
        match lado {
            Lado::Abridor => &self.volta,
            Lado::Aceitante => &self.ida,
        }
    }

    /// A ponta remota, se há.
    fn lado_remoto(&self) -> Option<Lado> {
        if self.abridor.remota() {
            Some(Lado::Abridor)
        } else if self.aceitante.remota() {
            Some(Lado::Aceitante)
        } else {
            None
        }
    }

    /// Se `q` é do processo `fio`: as pontas dele contam na cota dele — a
    /// que abriu sempre, a que aceitou depois do aceite.
    fn conta_para(&self, fio: u64) -> bool {
        self.abridor.quem() == Quem::Processo(fio)
            || (self.estado == Estado::Aberto && self.aceitante.quem() == Quem::Processo(fio))
    }

    /// Os dois sentidos terminaram: o fluxo acabou.
    fn concluido(&self) -> bool {
        self.estado == Estado::Aberto && self.ida.terminado() && self.volta.terminado()
    }

    fn mudou(&mut self, agora_ms: u64) {
        self.versao += 1;
        self.ultimo_ms = self.ultimo_ms.max(agora_ms);
    }
}

/// O que sobra de um fluxo que acabou: quem, o motivo e as contas — para
/// cada ponta saber, uma vez.
#[derive(Debug)]
struct Lapide {
    id: u64,
    titular: Titular,
    intencao: String,
    abridor: Quem,
    aceitante: Quem,
    motivo: String,
    ida: (u64, u64),
    volta: (u64, u64),
    versao: u64,
    /// Cada ponta que já soube: `[abridor, aceitante]`.
    sabem: [bool; 2],
}

/// O que o aviso da malha diz de uma ponta — ver [`Fluxos::prontidao`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prontidao {
    /// Vivo, com estes bits de prontidão.
    Vivo(u8),
    /// Acabou; `ja_sabe` se a ponta já ouviu o motivo — e então não há o
    /// que avisar.
    Acabou { ja_sabe: bool },
}

/// Um fluxo que acabou, para a auditoria e para acordar quem espera.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encerramento {
    pub id: u64,
    pub titular: Titular,
    pub endpoint: Endpoint,
    pub abridor: Quem,
    pub aceitante: Quem,
    pub motivo: String,
    /// Os bytes escritos em cada sentido.
    pub ida: u64,
    pub volta: u64,
    /// Os que saíram sem ser lidos — o fecho, o aborto.
    pub descartados: u64,
    pub versao: u64,
    /// Se o fluxo chegou a ser aceito: só então ele contava na cota de quem
    /// aceitou. O pedido que acaba sem aceite só contava na de quem abriu.
    pub aceito: bool,
}

/// O que uma leitura devolve: os bytes, na ordem, e se o sentido terminou
/// limpo depois deles.
#[derive(Debug, PartialEq, Eq)]
pub struct Lida {
    pub dados: Pedaco,
    pub fim: bool,
}

/// O aceite: o fluxo e quem o abriu, para o aceitante ver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aceito {
    pub id: u64,
    pub intencao: String,
    pub abridor: Ponta,
    pub versao: u64,
}

/// O que a sessão com o par lê de um fluxo vivo: quem é, o que pede e em
/// que pé está — para escrever o `abrir`, saber do aceite e reconfirmar
/// quem abriu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retrato {
    pub titular: Titular,
    pub intencao: String,
    pub endpoint: Endpoint,
    pub abridor: Ponta,
    pub aceitante: Ponta,
    pub estado: Estado,
    pub versao: u64,
}

/// O que uma ponta vê de um fluxo — vivo ou lembrado.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vista {
    /// `pending`, `open` ou `closed`.
    pub estado: &'static str,
    /// O motivo, se acabou.
    pub motivo: Option<String>,
    pub intencao: String,
    /// A outra ponta, enquanto o fluxo vive.
    pub outra: Option<Ponta>,
    /// O sentido em que quem pergunta escreve, e o que ele lê.
    pub escrita: Option<EstadoDoSentido>,
    pub leitura: Option<EstadoDoSentido>,
    /// Bytes que quem pergunta escreveu, e que leu.
    pub escritos: u64,
    pub lidos: u64,
    pub versao: u64,
}

/// Por que uma operação foi recusada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// Não há, **para quem pede**, o fluxo, o pedido ou o endpoint: o de
    /// outro titular, de outro processo, um que acabou, um que nunca
    /// existiu — todos respondem igual.
    NaoExiste,
    /// A intenção não tem a forma.
    Intencao,
    /// Um processo não abre fluxo com ele mesmo.
    MesmoProcesso,
    /// Uma cota cheia: o motivo diz qual.
    Cota(&'static str),
    /// O fluxo não está num estado que aceite a operação.
    Estado(&'static str),
    /// O fluxo acabou, com este motivo.
    Encerrado(String),
    /// A escrita passa de [`MAIOR_ESCRITA`].
    Grande,
    /// O par quebrou o protocolo: o fluxo acaba.
    Protocolo(&'static str),
}

impl Recusa {
    /// O código da auditoria e da resposta.
    pub fn codigo(&self) -> Codigo {
        match self {
            Recusa::NaoExiste => Codigo::DenyResource,
            Recusa::Intencao | Recusa::MesmoProcesso | Recusa::Grande => Codigo::InvalidArgument,
            Recusa::Cota(_) => Codigo::DenyPolicy,
            Recusa::Estado(_) | Recusa::Encerrado(_) => Codigo::Conflict,
            Recusa::Protocolo(_) => Codigo::Error,
        }
    }

    /// O motivo, para quem pediu e para a auditoria.
    pub fn motivo(&self) -> &str {
        match self {
            Recusa::NaoExiste => "nao existe para quem pede",
            Recusa::Intencao => "a intencao nao tem a forma",
            Recusa::MesmoProcesso => "um processo nao abre fluxo com ele mesmo",
            Recusa::Cota(m) | Recusa::Estado(m) | Recusa::Protocolo(m) => m,
            Recusa::Encerrado(m) => m,
            Recusa::Grande => "a escrita passa de 16 KiB",
        }
    }
}

/// Um motivo como a tabela o guarda: até [`MAIOR_MOTIVO`] bytes, ASCII
/// imprimível — o que vem do par é texto de fora.
pub fn motivo_guardado(texto: &str) -> String {
    let mut m: String = texto
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(MAIOR_MOTIVO)
        .collect();
    if m.is_empty() {
        m.push_str(motivo::PROTOCOLO);
    }
    m
}

/// A tabela de fluxos: os vivos, em ordem de id, e as lápides.
pub struct Fluxos {
    vivos: Vec<Fluxo>,
    proximo: u64,
    lapides: VecDeque<Lapide>,
    /// O maior que um buffer de sentido chegou a ter, em bytes — ver
    /// [`Fluxos::pico_do_buffer`].
    pico: usize,
}

impl Default for Fluxos {
    fn default() -> Fluxos {
        Fluxos::nova()
    }
}

impl Fluxos {
    pub fn nova() -> Fluxos {
        Fluxos {
            vivos: Vec::new(),
            proximo: 1,
            lapides: VecDeque::new(),
            pico: 0,
        }
    }

    fn i(&self, id: u64) -> Option<usize> {
        self.vivos.iter().position(|f| f.id == id)
    }

    /// A posição do fluxo `id` de `titular` e a ponta que `quem` é nele.
    fn resolver(&self, titular: Titular, quem: Quem, id: u64) -> Option<(usize, Lado)> {
        let i = self.i(id)?;
        let f = &self.vivos[i];
        if f.titular != titular {
            return None;
        }
        Some((i, f.lado_de(quem)?))
    }

    /// A lápide do fluxo `id` para `quem`, que fica sabendo do fim.
    fn lembrar(&mut self, titular: Titular, quem: Quem, id: u64) -> Option<Recusa> {
        let l = self
            .lapides
            .iter_mut()
            .find(|l| l.id == id && l.titular == titular)?;
        let lado = if l.abridor == quem {
            Lado::Abridor
        } else if l.aceitante == quem {
            Lado::Aceitante
        } else {
            return None;
        };
        l.sabem[lado.indice()] = true;
        let r = Recusa::Encerrado(l.motivo.clone());
        self.lapides.retain(|l| !(l.sabem[0] && l.sabem[1]));
        Some(r)
    }

    /// O fluxo `id` de `titular`, para `quem`: a posição e a ponta, ou a
    /// recusa — o motivo do fim para uma ponta de um que acabou; o mesmo
    /// `NaoExiste` para qualquer outro.
    fn alvo(&mut self, titular: Titular, quem: Quem, id: u64) -> Result<(usize, Lado), Recusa> {
        if let Some(r) = self.resolver(titular, quem, id) {
            let f = &self.vivos[r.0];
            if f.saiu[r.1.indice()] {
                return Err(Recusa::Encerrado(String::from(motivo::FECHADO)));
            }
            return Ok(r);
        }
        Err(self.lembrar(titular, quem, id).unwrap_or(Recusa::NaoExiste))
    }

    /// Confere as cotas de um pedido novo.
    fn cabe(
        &self,
        titular: Titular,
        abridor: &Ponta,
        endpoint: Option<u64>,
        para_o_par: bool,
    ) -> Result<(), Recusa> {
        if self.vivos.len() >= FLUXOS {
            return Err(Recusa::Cota("ja ha 16 fluxos na maquina"));
        }
        if self.vivos.iter().filter(|f| f.titular == titular).count() >= FLUXOS_POR_TITULAR {
            return Err(Recusa::Cota("o titular ja tem 8 fluxos"));
        }
        match abridor {
            Ponta::Processo { fio, .. } => {
                if self.vivos.iter().filter(|f| f.conta_para(*fio)).count() >= FLUXOS_POR_PROCESSO {
                    return Err(Recusa::Cota("o processo ja tem 4 fluxos"));
                }
            }
            Ponta::Remota {
                dispositivo,
                relacao,
                ..
            } => {
                let q = Quem::Remoto {
                    dispositivo: *dispositivo,
                    relacao: *relacao,
                };
                if self.vivos.iter().filter(|f| f.abridor.quem() == q).count()
                    >= REMOTOS_POR_RELACAO
                {
                    return Err(Recusa::Cota("a relacao ja tem um fluxo aberto aqui"));
                }
            }
        }
        if let Some(e) = endpoint {
            let pedidos = |f: &&Fluxo| f.estado == Estado::Pedido;
            if self
                .vivos
                .iter()
                .filter(pedidos)
                .filter(|f| f.endpoint == Endpoint::Daqui(e))
                .count()
                >= PEDIDOS_POR_ENDPOINT
            {
                return Err(Recusa::Cota("o endpoint ja tem 4 pedidos na fila"));
            }
            if self.vivos.iter().filter(pedidos).count() >= PEDIDOS {
                return Err(Recusa::Cota("ja ha 16 pedidos na maquina"));
            }
        }
        if para_o_par
            && self.vivos.iter().filter(|f| f.aceitante.remota()).count() >= REMOTOS_QUE_SAEM
        {
            return Err(Recusa::Cota("ja ha 2 fluxos daqui a outros dispositivos"));
        }
        Ok(())
    }

    fn novo_id(&mut self) -> u64 {
        let id = self.proximo;
        self.proximo += 1;
        id
    }

    /// Abre um pedido de `abridor` contra o endpoint daqui `endpoint`, cujo
    /// dono é `dono` e que oferece `intencao`. O kernel já conferiu que o
    /// endpoint é do titular e que o dono receberia.
    #[allow(clippy::too_many_arguments)]
    pub fn abrir(
        &mut self,
        titular: Titular,
        abridor: Ponta,
        endpoint: u64,
        dono: Ponta,
        intencao: &str,
        agora_ms: u64,
    ) -> Result<u64, Recusa> {
        if !crate::malha::intencao_valida(intencao) {
            return Err(Recusa::Intencao);
        }
        if abridor.quem() == dono.quem() {
            return Err(Recusa::MesmoProcesso);
        }
        if dono.remota() {
            return Err(Recusa::NaoExiste);
        }
        self.cabe(titular, &abridor, Some(endpoint), false)?;
        let id = self.novo_id();
        self.vivos.push(Fluxo {
            id,
            titular,
            intencao: String::from(intencao),
            endpoint: Endpoint::Daqui(endpoint),
            abridor,
            aceitante: dono,
            estado: Estado::Pedido,
            ida: Sentido::novo(),
            volta: Sentido::novo(),
            saiu: [false; 2],
            criado_ms: agora_ms,
            vence_ms: agora_ms.saturating_add(PRAZO_DO_ACEITE_MS),
            ultimo_ms: agora_ms,
            versao: 1,
            credito: None,
        });
        Ok(id)
    }

    /// Abre, daqui, um pedido ao endpoint `endpoint` de outro Duke: o
    /// aceitante é o `par`, e o pedido espera o aceite de lá.
    pub fn abrir_no_par(
        &mut self,
        titular: Titular,
        abridor: Ponta,
        par: Ponta,
        endpoint: &str,
        intencao: &str,
        agora_ms: u64,
    ) -> Result<u64, Recusa> {
        if !crate::malha::intencao_valida(intencao) {
            return Err(Recusa::Intencao);
        }
        if abridor.remota() || !par.remota() {
            return Err(Recusa::NaoExiste);
        }
        self.cabe(titular, &abridor, None, true)?;
        let id = self.novo_id();
        self.vivos.push(Fluxo {
            id,
            titular,
            intencao: String::from(intencao),
            endpoint: Endpoint::DoPar(String::from(endpoint)),
            abridor,
            aceitante: par,
            estado: Estado::Pedido,
            ida: Sentido::novo(),
            volta: Sentido::novo(),
            saiu: [false; 2],
            criado_ms: agora_ms,
            vence_ms: agora_ms.saturating_add(PRAZO_DO_ACEITE_REMOTO_MS),
            ultimo_ms: agora_ms,
            versao: 1,
            credito: None,
        });
        Ok(id)
    }

    /// O pedido mais antigo no endpoint `endpoint` do processo `fio`, de
    /// `titular` — o que o aceite pega.
    pub fn primeiro_pedido(&self, titular: Titular, fio: u64, endpoint: u64) -> Option<u64> {
        self.vivos
            .iter()
            .filter(|f| {
                f.titular == titular
                    && f.estado == Estado::Pedido
                    && f.endpoint == Endpoint::Daqui(endpoint)
                    && f.aceitante.quem() == Quem::Processo(fio)
            })
            .map(|f| f.id)
            .min()
    }

    /// Se há pedido esperando no endpoint `endpoint`.
    pub fn tem_pedido(&self, endpoint: u64) -> bool {
        self.vivos
            .iter()
            .any(|f| f.estado == Estado::Pedido && f.endpoint == Endpoint::Daqui(endpoint))
    }

    /// Quem abriu o pedido `id` e o que ele pede: para a reconfirmação.
    pub fn pedido(&self, id: u64) -> Option<(&Ponta, &str)> {
        let f = &self.vivos[self.i(id)?];
        (f.estado == Estado::Pedido).then_some((&f.abridor, f.intencao.as_str()))
    }

    /// Abre o pedido `id` para o processo `fio`, o dono do endpoint. O
    /// kernel já reconfirmou as duas decisões, dentro da ordem.
    pub fn aceitar(
        &mut self,
        titular: Titular,
        fio: u64,
        id: u64,
        agora_ms: u64,
    ) -> Result<Aceito, Recusa> {
        let i = self.i(id).ok_or(Recusa::NaoExiste)?;
        {
            let f = &self.vivos[i];
            if f.titular != titular
                || f.estado != Estado::Pedido
                || f.aceitante.quem() != Quem::Processo(fio)
            {
                return Err(Recusa::NaoExiste);
            }
        }
        if self.vivos.iter().filter(|f| f.conta_para(fio)).count() >= FLUXOS_POR_PROCESSO {
            return Err(Recusa::Cota("o processo ja tem 4 fluxos"));
        }
        let f = &mut self.vivos[i];
        f.estado = Estado::Aberto;
        if f.lado_remoto().is_some() {
            f.credito = Some(Credito::inicial());
        }
        f.mudou(agora_ms);
        Ok(Aceito {
            id,
            intencao: f.intencao.clone(),
            abridor: f.abridor.clone(),
            versao: f.versao,
        })
    }

    /// O par aceitou o pedido `id` que saiu daqui: aberto, com o crédito
    /// inicial. O kernel já reconfirmou quem abriu.
    pub fn aceito_pelo_par(&mut self, id: u64, agora_ms: u64) -> Result<u64, Recusa> {
        let i = self.i(id).ok_or(Recusa::NaoExiste)?;
        let f = &mut self.vivos[i];
        if f.estado != Estado::Pedido || f.lado_remoto() != Some(Lado::Aceitante) {
            return Err(Recusa::Protocolo("aceito fora de hora"));
        }
        f.estado = Estado::Aberto;
        f.credito = Some(Credito::inicial());
        f.mudou(agora_ms);
        Ok(f.versao)
    }

    /// Encerra o pedido `id`, que não abre: a reconfirmação recusou quem
    /// abriu, ou o par recusou.
    pub fn recusar(&mut self, id: u64, motivo: &str) -> Option<Encerramento> {
        let i = self.i(id)?;
        if self.vivos[i].estado != Estado::Pedido {
            return None;
        }
        Some(self.encerrar(i, motivo))
    }

    /// Tira o fluxo da posição `i` e deixa a lápide.
    fn encerrar(&mut self, i: usize, motivo: &str) -> Encerramento {
        let mut f = self.vivos.remove(i);
        let descartados = f.ida.descartados + f.volta.descartados;
        let descartar = |s: &mut Sentido| s.anel.descartar() as u64;
        let restos = descartar(&mut f.ida) + descartar(&mut f.volta);
        let motivo = motivo_guardado(motivo);
        let e = Encerramento {
            id: f.id,
            titular: f.titular,
            endpoint: f.endpoint.clone(),
            abridor: f.abridor.quem(),
            aceitante: f.aceitante.quem(),
            motivo: motivo.clone(),
            ida: f.ida.escritos,
            volta: f.volta.escritos,
            descartados: descartados + restos,
            versao: f.versao + 1,
            aceito: f.estado == Estado::Aberto,
        };
        // A ponta remota sabe pelo protocolo; a que saiu, por ter saído.
        let sabe = |l: Lado| f.ponta(l).remota() || f.saiu[l.indice()];
        let mut sabem = [sabe(Lado::Abridor), sabe(Lado::Aceitante)];
        // O aceitante de um pedido nunca soube dele.
        if f.estado == Estado::Pedido {
            sabem[1] = true;
        }
        if !(sabem[0] && sabem[1]) {
            if self.lapides.len() >= LAPIDES {
                self.lapides.pop_front();
            }
            self.lapides.push_back(Lapide {
                id: f.id,
                titular: f.titular,
                intencao: f.intencao.clone(),
                abridor: e.abridor,
                aceitante: e.aceitante,
                motivo,
                ida: (f.ida.escritos, f.ida.lidos),
                volta: (f.volta.escritos, f.volta.lidos),
                versao: e.versao,
                sabem,
            });
        }
        e
    }

    /// Se o fluxo da posição `i` acabou — os dois sentidos terminados —, o
    /// encerra: `concluido`, ou `fechado pela ponta` se uma saiu.
    fn talvez_concluir(&mut self, i: usize) -> Option<Encerramento> {
        let f = &self.vivos[i];
        if !f.concluido() {
            return None;
        }
        let motivo = if f.saiu[0] || f.saiu[1] {
            motivo::FECHADO
        } else {
            motivo::CONCLUIDO
        };
        Some(self.encerrar(i, motivo))
    }

    /// Escreve `dados` no sentido de `quem`: o que couber no buffer. Devolve
    /// quantos entraram — zero com o buffer cheio. A ponta remota tem de
    /// caber inteira no crédito que lhe foi concedido.
    pub fn escrever(
        &mut self,
        titular: Titular,
        quem: Quem,
        id: u64,
        dados: &[u8],
        agora_ms: u64,
    ) -> Result<usize, Recusa> {
        if dados.len() > MAIOR_ESCRITA {
            return Err(Recusa::Grande);
        }
        let (i, lado) = self.alvo(titular, quem, id)?;
        let f = &mut self.vivos[i];
        if f.estado == Estado::Pedido {
            return Err(Recusa::Estado("o fluxo ainda nao abriu"));
        }
        let remoto = f.lado_remoto() == Some(lado);
        match f.escrita(lado).estado {
            EstadoDoSentido::Aberto => {}
            EstadoDoSentido::Fim => return Err(Recusa::Estado("o sentido ja acabou")),
            EstadoDoSentido::Abortado => {
                return Err(Recusa::Encerrado(String::from(motivo::FECHADO)));
            }
        }
        if remoto {
            let concedido = f.credito.map_or(0, |c| c.concedido);
            if dados.len() as u64 > concedido || dados.len() > f.escrita(lado).anel.livre() {
                return Err(Recusa::Protocolo("o par passou do credito"));
            }
        }
        let s = f.escrita(lado);
        let n = s.anel.por(dados);
        s.escritos += n as u64;
        let ocupado = s.anel.tamanho();
        if remoto && let Some(c) = f.credito.as_mut() {
            c.concedido -= n as u64;
        }
        if n > 0 {
            f.mudou(agora_ms);
        }
        self.pico = self.pico.max(ocupado);
        Ok(n)
    }

    /// Lê até `max` bytes do sentido de `quem`, na ordem. `fim` quando o
    /// sentido terminou limpo e nada mais vem. O que sai do buffer volta,
    /// no remoto, como crédito a devolver.
    pub fn ler(
        &mut self,
        titular: Titular,
        quem: Quem,
        id: u64,
        max: usize,
        agora_ms: u64,
    ) -> Result<(Lida, Option<Encerramento>), Recusa> {
        let (i, lado) = self.alvo(titular, quem, id)?;
        let f = &mut self.vivos[i];
        if f.estado == Estado::Pedido {
            return Err(Recusa::Estado("o fluxo ainda nao abriu"));
        }
        if f.leitura(lado).estado == EstadoDoSentido::Abortado {
            return Err(Recusa::Encerrado(String::from(motivo::FECHADO)));
        }
        let chega_do_par = f.lado_remoto() == Some(lado.outro());
        let s = f.leitura(lado);
        let dados = s.anel.tirar(max.min(MAIOR_LEITURA));
        s.lidos += dados.len() as u64;
        let fim = s.estado == EstadoDoSentido::Fim && s.anel.tamanho() == 0;
        s.fim_visto |= fim;
        if chega_do_par && let Some(c) = f.credito.as_mut() {
            c.a_devolver += dados.len() as u64;
        }
        if !dados.is_empty() {
            f.mudou(agora_ms);
        }
        let e = self.talvez_concluir(i);
        Ok((Lida { dados, fim }, e))
    }

    /// Termina o sentido em que `quem` escreve: quem lê lê o resto, e
    /// depois o fim.
    pub fn terminar(
        &mut self,
        titular: Titular,
        quem: Quem,
        id: u64,
        agora_ms: u64,
    ) -> Result<Option<Encerramento>, Recusa> {
        let (i, lado) = self.alvo(titular, quem, id)?;
        let f = &mut self.vivos[i];
        if f.estado == Estado::Pedido {
            return Err(Recusa::Estado("o fluxo ainda nao abriu"));
        }
        let s = f.escrita(lado);
        match s.estado {
            EstadoDoSentido::Aberto => s.estado = EstadoDoSentido::Fim,
            EstadoDoSentido::Fim => return Err(Recusa::Estado("o sentido ja acabou")),
            EstadoDoSentido::Abortado => {
                return Err(Recusa::Encerrado(String::from(motivo::FECHADO)));
            }
        }
        f.mudou(agora_ms);
        Ok(self.talvez_concluir(i))
    }

    /// `quem` fecha e sai: o que ele já escreveu continua legível pela
    /// outra ponta, até o fim do sentido; o que estava para ele ler sai
    /// zerado. O pedido que ainda não abriu acaba.
    pub fn fechar(
        &mut self,
        titular: Titular,
        quem: Quem,
        id: u64,
        agora_ms: u64,
    ) -> Result<Option<Encerramento>, Recusa> {
        let (i, lado) = self.alvo(titular, quem, id)?;
        if self.vivos[i].estado == Estado::Pedido {
            // Quem fecha sabe: a lápide não espera por ele.
            self.vivos[i].saiu[lado.indice()] = true;
            return Ok(Some(self.encerrar(i, motivo::FECHADO)));
        }
        let f = &mut self.vivos[i];
        f.saiu[lado.indice()] = true;
        let s = f.escrita(lado);
        if s.estado == EstadoDoSentido::Aberto {
            s.estado = EstadoDoSentido::Fim;
        }
        let r = f.leitura(lado);
        if r.estado != EstadoDoSentido::Abortado {
            r.abortar();
        }
        f.mudou(agora_ms);
        // A outra ponta também já saiu: nada mais a ler para ninguém.
        if f.saiu[lado.outro().indice()] {
            return Ok(Some(self.encerrar(i, motivo::FECHADO)));
        }
        Ok(self.talvez_concluir(i))
    }

    /// O kernel aborta o fluxo `id`: os dois sentidos acabam na hora.
    pub fn abortar(&mut self, id: u64, motivo: &str) -> Option<Encerramento> {
        let i = self.i(id)?;
        let f = &mut self.vivos[i];
        f.ida.abortar();
        f.volta.abortar();
        Some(self.encerrar(i, motivo))
    }

    /// O que uma ponta vê do fluxo `id`: vivo, ou a lápide — e então ela
    /// fica sabendo do fim.
    pub fn estado(&mut self, titular: Titular, quem: Quem, id: u64) -> Result<Vista, Recusa> {
        if let Some((i, lado)) = self.resolver(titular, quem, id) {
            let f = &self.vivos[i];
            let estado = if f.saiu[lado.indice()] {
                "closed"
            } else {
                match f.estado {
                    Estado::Pedido => "pending",
                    Estado::Aberto => "open",
                }
            };
            return Ok(Vista {
                estado,
                motivo: f.saiu[lado.indice()].then(|| String::from(motivo::FECHADO)),
                intencao: f.intencao.clone(),
                outra: Some(f.ponta(lado.outro()).clone()),
                escrita: Some(f.escrita_de(lado).estado),
                leitura: Some(f.leitura_de(lado).estado),
                escritos: f.escrita_de(lado).escritos,
                lidos: f.leitura_de(lado).lidos,
                versao: f.versao,
            });
        }
        let l = self
            .lapides
            .iter()
            .find(|l| {
                l.id == id && l.titular == titular && (l.abridor == quem || l.aceitante == quem)
            })
            .ok_or(Recusa::NaoExiste)?;
        let abridor = l.abridor == quem;
        let (escritos, lidos) = if abridor {
            (l.ida.0, l.volta.1)
        } else {
            (l.volta.0, l.ida.1)
        };
        let vista = Vista {
            estado: "closed",
            motivo: Some(l.motivo.clone()),
            intencao: l.intencao.clone(),
            outra: None,
            escrita: None,
            leitura: None,
            escritos,
            lidos,
            versao: l.versao,
        };
        self.lembrar(titular, quem, id);
        Ok(vista)
    }

    // -----------------------------------------------------------------
    // O par: o que a sessão entre dois Dukes leva e traz.
    // -----------------------------------------------------------------

    /// Tira, do sentido que vai ao par, até `max` bytes — no máximo o
    /// crédito que ele concedeu. Vazio quando não há o que mandar.
    pub fn tirar_para_o_par(&mut self, id: u64, max: usize, agora_ms: u64) -> Pedaco {
        let Some(i) = self.i(id) else {
            return Pedaco::default();
        };
        let f = &mut self.vivos[i];
        let Some(remoto) = f.lado_remoto() else {
            return Pedaco::default();
        };
        if f.estado != Estado::Aberto {
            return Pedaco::default();
        }
        let credito = f.credito.map_or(0, |c| c.para_mandar);
        let n = (max as u64).min(credito) as usize;
        let s = f.leitura(remoto);
        let dados = s.anel.tirar(n);
        s.lidos += dados.len() as u64;
        if let Some(c) = f.credito.as_mut() {
            c.para_mandar -= dados.len() as u64;
        }
        if !dados.is_empty() {
            f.mudou(agora_ms);
        }
        dados
    }

    /// Se `n` bytes do par cabem agora no fluxo `id`: aberto, o sentido em
    /// que ele escreve ainda aberto, e dentro do crédito concedido e do
    /// buffer. A sessão confere antes de pedir ao gate: passar do crédito,
    /// mandar antes do aceite ou depois do fim é protocolo — e não decisão
    /// de autoridade nenhuma. `Encerrado` quando a ponta daqui já fechou: o
    /// que chega é descartado, e o fecho vai ao par.
    pub fn cabe_do_par(&self, id: u64, n: usize) -> Result<(), Recusa> {
        let i = self.i(id).ok_or(Recusa::NaoExiste)?;
        let f = &self.vivos[i];
        let remoto = f
            .lado_remoto()
            .ok_or(Recusa::Protocolo("dados fora de hora"))?;
        if f.estado != Estado::Aberto {
            return Err(Recusa::Protocolo("dados antes do aceite"));
        }
        let s = f.escrita_de(remoto);
        match s.estado {
            EstadoDoSentido::Aberto => {}
            EstadoDoSentido::Fim => return Err(Recusa::Protocolo("dados depois do fim")),
            EstadoDoSentido::Abortado => {
                return Err(Recusa::Encerrado(String::from(motivo::FECHADO)));
            }
        }
        let concedido = f.credito.map_or(0, |c| c.concedido);
        if n as u64 > concedido || n > s.anel.livre() {
            return Err(Recusa::Protocolo("o par passou do credito"));
        }
        Ok(())
    }

    /// O par concedeu `n` bytes a mais. Passar do buffer dele é erro de
    /// protocolo: ninguém concede o que não tem.
    pub fn credito_do_par(&mut self, id: u64, n: u64) -> Result<(), Recusa> {
        let i = self.i(id).ok_or(Recusa::NaoExiste)?;
        let f = &mut self.vivos[i];
        let c = f
            .credito
            .as_mut()
            .ok_or(Recusa::Protocolo("credito fora de hora"))?;
        let novo = c.para_mandar.saturating_add(n);
        if n == 0 || novo > BUFFER_DO_SENTIDO as u64 {
            return Err(Recusa::Protocolo("o par concedeu mais que o buffer dele"));
        }
        c.para_mandar = novo;
        Ok(())
    }

    /// O crédito a devolver ao par, se já passou do limiar — ou se o
    /// sentido esvaziou: sai da conta, e vira concedido.
    pub fn credito_a_devolver(&mut self, id: u64) -> Option<u64> {
        let i = self.i(id)?;
        let f = &mut self.vivos[i];
        let remoto = f.lado_remoto()?;
        if f.escrita(remoto).estado != EstadoDoSentido::Aberto {
            return None;
        }
        let c = f.credito.as_mut()?;
        if c.a_devolver < LIMIAR_DO_CREDITO as u64 {
            return None;
        }
        let n = c.a_devolver;
        c.a_devolver = 0;
        c.concedido += n;
        Some(n)
    }

    /// O sentido que vai ao par terminou e já saiu inteiro: o fim, a ser
    /// dito uma vez.
    pub fn fim_para_o_par(&mut self, id: u64) -> bool {
        let Some(i) = self.i(id) else {
            return false;
        };
        let f = &mut self.vivos[i];
        let Some(remoto) = f.lado_remoto() else {
            return false;
        };
        if f.estado != Estado::Aberto {
            return false;
        }
        let s = f.leitura(remoto);
        if s.estado == EstadoDoSentido::Fim && s.anel.tamanho() == 0 && !s.fim_visto {
            s.fim_visto = true;
            return true;
        }
        false
    }

    /// Se o fluxo `id` acabou — os dois sentidos terminados —, o encerra. A
    /// sessão com o par pergunta depois de dizer o fim ou o fecho.
    pub fn talvez_encerrar(&mut self, id: u64) -> Option<Encerramento> {
        let i = self.i(id)?;
        self.talvez_concluir(i)
    }

    /// A ponta daqui saiu do fluxo `id`, e o que ela escreveu já foi
    /// inteiro ao par: a sessão diz `fechar` e acaba.
    pub fn saiu_e_foi(&self, id: u64) -> bool {
        let Some(i) = self.i(id) else {
            return false;
        };
        let f = &self.vivos[i];
        let Some(remoto) = f.lado_remoto() else {
            return false;
        };
        f.saiu[remoto.outro().indice()] && f.leitura_de(remoto).fim_visto
    }

    /// O par terminou o sentido dele.
    pub fn fim_do_par(&mut self, id: u64, agora_ms: u64) -> Result<Option<Encerramento>, Recusa> {
        let i = self.i(id).ok_or(Recusa::NaoExiste)?;
        let f = &mut self.vivos[i];
        let remoto = f
            .lado_remoto()
            .ok_or(Recusa::Protocolo("fim fora de hora"))?;
        if f.estado != Estado::Aberto {
            return Err(Recusa::Protocolo("fim fora de hora"));
        }
        let s = f.escrita(remoto);
        match s.estado {
            EstadoDoSentido::Aberto => s.estado = EstadoDoSentido::Fim,
            EstadoDoSentido::Fim => return Err(Recusa::Protocolo("fim repetido")),
            // A ponta daqui fechou, e o que o par manda já não é lido.
            EstadoDoSentido::Abortado => {}
        }
        f.mudou(agora_ms);
        Ok(self.talvez_concluir(i))
    }

    /// O par fechou o fluxo `id`. Se ele terminou o sentido dele antes — o
    /// fecho em ordem —, o que mandou continua legível aqui, até o fim; o
    /// que vai a ele sai. Sem o fim antes, é um aborto, com o motivo dele.
    pub fn fechar_do_par(&mut self, id: u64, motivo_do_par: &str) -> Option<Encerramento> {
        let i = self.i(id)?;
        let f = &mut self.vivos[i];
        let remoto = f.lado_remoto()?;
        if f.estado != Estado::Aberto || f.escrita(remoto).estado != EstadoDoSentido::Fim {
            return self.abortar(id, motivo_do_par);
        }
        f.saiu[remoto.indice()] = true;
        let s = f.leitura(remoto);
        if s.estado != EstadoDoSentido::Abortado {
            s.abortar();
        }
        if f.saiu[remoto.outro().indice()] {
            return Some(self.encerrar(i, motivo::FECHADO));
        }
        self.talvez_concluir(i)
    }

    // -----------------------------------------------------------------
    // As perguntas: o gate, o plano de dados, as esperas.
    // -----------------------------------------------------------------

    /// A intenção do fluxo `id` para `quem`, de `titular` — vivo, ou a
    /// lápide de uma ponta dele. Para qualquer outro, nada.
    pub fn intencao_para(&self, titular: Titular, quem: Quem, id: u64) -> Option<&str> {
        if let Some((i, _)) = self.resolver(titular, quem, id) {
            return Some(self.vivos[i].intencao.as_str());
        }
        self.lapides
            .iter()
            .find(|l| {
                l.id == id && l.titular == titular && (l.abridor == quem || l.aceitante == quem)
            })
            .map(|l| l.intencao.as_str())
    }

    /// O fluxo `id` está aberto e vivo para `quem`, que não saiu dele: o
    /// recurso aberto do plano de dados.
    pub fn aberto_para(&self, titular: Titular, quem: Quem, id: u64) -> bool {
        self.resolver(titular, quem, id).is_some_and(|(i, lado)| {
            let f = &self.vivos[i];
            f.estado == Estado::Aberto && !f.saiu[lado.indice()]
        })
    }

    /// O fluxo vivo `id`, como a sessão com o par o lê. `None` se ele
    /// acabou — ou nunca foi.
    pub fn retrato(&self, id: u64) -> Option<Retrato> {
        let f = &self.vivos[self.i(id)?];
        Some(Retrato {
            titular: f.titular,
            intencao: f.intencao.clone(),
            endpoint: f.endpoint.clone(),
            abridor: f.abridor.clone(),
            aceitante: f.aceitante.clone(),
            estado: f.estado,
            versao: f.versao,
        })
    }

    /// A ponta que o par é no fluxo `id`, se há uma.
    pub fn par_de(&self, id: u64) -> Option<&Ponta> {
        let f = &self.vivos[self.i(id)?];
        f.lado_remoto().map(|l| f.ponta(l))
    }

    /// Se `quem` pode ler o fluxo `id` agora — ou se não há mais o que
    /// esperar nele: acabou, abortou, o fim chegou.
    pub fn pode_ler(&self, quem: Quem, id: u64) -> bool {
        let Some(i) = self.i(id) else {
            return true;
        };
        let f = &self.vivos[i];
        let Some(lado) = f.lado_de(quem) else {
            return true;
        };
        if f.estado == Estado::Pedido {
            return false;
        }
        let s = f.leitura_de(lado);
        f.saiu[lado.indice()] || s.estado != EstadoDoSentido::Aberto || s.anel.tamanho() > 0
    }

    /// O que o aviso da malha (DS-1) diz da ponta `quem` do fluxo `id`: o
    /// que uma operação dela acharia agora — os bits de
    /// [`crate::aviso::bits`] — ou que o fluxo acabou, e se ela já ouviu o
    /// motivo. Uma ponta que fechou e saiu já sabe.
    pub fn prontidao(&self, quem: Quem, id: u64) -> Prontidao {
        use crate::aviso::bits;
        if let Some(i) = self.i(id) {
            let f = &self.vivos[i];
            let Some(lado) = f.lado_de(quem) else {
                return Prontidao::Vivo(0);
            };
            if f.saiu[lado.indice()] {
                return Prontidao::Acabou { ja_sabe: true };
            }
            if f.estado == Estado::Pedido {
                return Prontidao::Vivo(0);
            }
            let le = f.leitura_de(lado);
            let es = f.escrita_de(lado);
            let mut b = 0;
            if le.anel.tamanho() > 0 || (le.estado == EstadoDoSentido::Fim && !le.fim_visto) {
                b |= bits::LEGIVEL;
            }
            if (es.estado == EstadoDoSentido::Aberto && es.anel.livre() > 0)
                || es.estado == EstadoDoSentido::Abortado
            {
                b |= bits::GRAVAVEL;
            }
            return Prontidao::Vivo(b);
        }
        match self.lapides.iter().find(|l| l.id == id) {
            Some(l) if l.abridor == quem => Prontidao::Acabou {
                ja_sabe: l.sabem[0],
            },
            Some(l) if l.aceitante == quem => Prontidao::Acabou {
                ja_sabe: l.sabem[1],
            },
            _ => Prontidao::Acabou { ja_sabe: true },
        }
    }

    /// Se `quem` pode escrever no fluxo `id` agora — ou se não há mais o
    /// que esperar nele.
    pub fn pode_escrever(&self, quem: Quem, id: u64) -> bool {
        let Some(i) = self.i(id) else {
            return true;
        };
        let f = &self.vivos[i];
        let Some(lado) = f.lado_de(quem) else {
            return true;
        };
        if f.estado == Estado::Pedido {
            return false;
        }
        let s = f.escrita_de(lado);
        f.saiu[lado.indice()] || s.estado != EstadoDoSentido::Aberto || s.anel.livre() > 0
    }

    /// Se a sessão com o par do fluxo `id` tem o que fazer: dados e crédito
    /// para mandar, crédito a devolver, o fim a dizer, o fecho — ou se o
    /// fluxo acabou.
    pub fn par_tem_o_que_fazer(&self, id: u64) -> bool {
        let Some(i) = self.i(id) else {
            return true;
        };
        let f = &self.vivos[i];
        let Some(remoto) = f.lado_remoto() else {
            return true;
        };
        if f.estado == Estado::Pedido {
            return false;
        }
        let Some(c) = f.credito else {
            return true;
        };
        let sai = f.leitura_de(remoto);
        (sai.anel.tamanho() > 0 && c.para_mandar > 0)
            || (sai.estado == EstadoDoSentido::Fim && sai.anel.tamanho() == 0 && !sai.fim_visto)
            || (c.a_devolver >= LIMIAR_DO_CREDITO as u64
                && f.escrita_de(remoto).estado == EstadoDoSentido::Aberto)
            // A ponta daqui saiu e tudo o que ela escreveu já foi: o fecho.
            // Antes disso — dados esperando crédito —, não há o que fazer
            // até o par conceder.
            || (f.saiu[remoto.outro().indice()] && sai.fim_visto)
    }

    /// Se o fluxo `id` ainda precisa da sessão com o par: o pedido, um
    /// sentido em que o par ainda pode mandar, ou um que ainda não foi
    /// inteiro a ele. Sem isso — os dois fins ditos, ou o fecho em ordem do
    /// par —, o que sobra é só leitura daqui, e o fluxo vive sem a sessão
    /// até quem lê acabar.
    pub fn precisa_do_par(&self, id: u64) -> bool {
        let Some(i) = self.i(id) else {
            return false;
        };
        let f = &self.vivos[i];
        let Some(remoto) = f.lado_remoto() else {
            return false;
        };
        if f.estado == Estado::Pedido {
            return true;
        }
        let chega = f.escrita_de(remoto);
        let sai = f.leitura_de(remoto);
        chega.estado == EstadoDoSentido::Aberto
            || (sai.estado != EstadoDoSentido::Abortado && !sai.fim_visto)
    }

    /// Os ids vivos, em ordem.
    pub fn ids(&self) -> Vec<u64> {
        self.vivos.iter().map(|f| f.id).collect()
    }

    /// O maior que um buffer de sentido chegou a ter, em bytes, desde que
    /// a tabela nasceu: a memória de um sentido nunca passa do
    /// [`BUFFER_DO_SENTIDO`], venha a escrita de um processo daqui ou do
    /// par, dentro do crédito. Para `security.metrics`.
    pub fn pico_do_buffer(&self) -> usize {
        self.pico
    }

    /// Quantos vivos têm uma ponta noutro Duke.
    pub fn remotos_vivos(&self) -> usize {
        self.vivos
            .iter()
            .filter(|f| f.lado_remoto().is_some())
            .count()
    }

    /// Quantos vivos — e, deles, quantos pedidos.
    pub fn contagem(&self) -> (usize, usize) {
        (
            self.vivos.len(),
            self.vivos
                .iter()
                .filter(|f| f.estado == Estado::Pedido)
                .count(),
        )
    }

    /// Quantas lápides.
    pub fn lapides(&self) -> usize {
        self.lapides.len()
    }

    /// Esquece as lápides — para a suíte começar cada caso limpa. Os ids
    /// continuam de onde estavam.
    pub fn esquecer_lapides(&mut self) {
        self.lapides.clear();
    }

    // -----------------------------------------------------------------
    // Os ganchos: o kernel encerra por fora.
    // -----------------------------------------------------------------

    /// Aborta, com `motivo`, os fluxos para os quais `cond` diz sim.
    fn abortar_onde(&mut self, motivo: &str, cond: impl Fn(&Fluxo) -> bool) -> Vec<Encerramento> {
        let ids: Vec<u64> = self
            .vivos
            .iter()
            .filter(|f| cond(f))
            .map(|f| f.id)
            .collect();
        ids.into_iter()
            .filter_map(|id| self.abortar(id, motivo))
            .collect()
    }

    /// O titular foi revogado: todos os fluxos dele acabam.
    pub fn anular_titular(&mut self, titular: Titular, motivo: &str) -> Vec<Encerramento> {
        self.abortar_onde(motivo, |f| f.titular == titular)
    }

    /// O processo `fio` acabou — ou trocou de programa: os fluxos de que ele
    /// é ponta acabam, e os pedidos que ele abriu também. O pedido que
    /// esperava um endpoint dele acaba pelo endpoint. A ponta de que ele já
    /// saiu — fechou — não é mais dele: o que ele escreveu segue legível
    /// pela outra, até o fim do sentido, como no fecho.
    pub fn processo_acabou(&mut self, fio: u64, motivo: &str) -> Vec<Encerramento> {
        let q = Quem::Processo(fio);
        self.abortar_onde(motivo, |f| {
            let ainda = |l: Lado| !f.saiu[l.indice()];
            (f.abridor.quem() == q && ainda(Lado::Abridor))
                || (f.estado == Estado::Aberto && f.aceitante.quem() == q && ainda(Lado::Aceitante))
        })
    }

    /// O endpoint daqui `endpoint` acabou: os pedidos que esperavam nele
    /// acabam. Os abertos continuam — são dos processos.
    pub fn endpoint_acabou(&mut self, endpoint: u64) -> Vec<Encerramento> {
        self.abortar_onde(motivo::ENDPOINT, |f| {
            f.estado == Estado::Pedido && f.endpoint == Endpoint::Daqui(endpoint)
        })
    }

    /// Os fluxos com o par cujo dispositivo e relação `cond` diz acabam.
    pub fn anular_remotos(
        &mut self,
        motivo: &str,
        cond: impl Fn(&[u8; 32], &[u8; 16]) -> bool,
    ) -> Vec<Encerramento> {
        self.abortar_onde(motivo, |f| match f.lado_remoto().map(|l| f.ponta(l)) {
            Some(Ponta::Remota {
                dispositivo,
                relacao,
                ..
            }) => cond(dispositivo, relacao),
            _ => false,
        })
    }

    /// Todos acabam: o desligamento.
    pub fn abortar_todos(&mut self, motivo: &str) -> Vec<Encerramento> {
        self.abortar_onde(motivo, |_| true)
    }

    /// Os pedidos que passaram do prazo do aceite e os abertos ociosos
    /// acabam.
    pub fn vencer(&mut self, agora_ms: u64) -> Vec<Encerramento> {
        let mut fim = self.abortar_onde(motivo::PRAZO_DO_ACEITE, |f| {
            f.estado == Estado::Pedido && agora_ms >= f.vence_ms
        });
        fim.extend(self.abortar_onde(motivo::OCIOSO, |f| {
            f.estado == Estado::Aberto && agora_ms >= f.ultimo_ms.saturating_add(OCIOSO_MS)
        }));
        fim
    }

    /// As regras da tabela, conferidas — para os testes e a suíte.
    pub fn coerente(&self) -> bool {
        let mut ids: Vec<u64> = self.vivos.iter().map(|f| f.id).collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != self.vivos.len() || ids.last().is_some_and(|&u| u >= self.proximo) {
            return false;
        }
        if self.vivos.len() > FLUXOS || self.lapides.len() > LAPIDES {
            return false;
        }
        if self
            .lapides
            .iter()
            .any(|l| ids.binary_search(&l.id).is_ok() || (l.sabem[0] && l.sabem[1]))
        {
            return false;
        }
        let pedidos = self
            .vivos
            .iter()
            .filter(|f| f.estado == Estado::Pedido)
            .count();
        if pedidos > PEDIDOS
            || self.vivos.iter().filter(|f| f.aceitante.remota()).count() > REMOTOS_QUE_SAEM
        {
            return false;
        }
        for f in &self.vivos {
            if f.abridor.quem() == f.aceitante.quem()
                || (f.abridor.remota() && f.aceitante.remota())
                || f.versao == 0
                || f.ultimo_ms < f.criado_ms
            {
                return false;
            }
            for s in [&f.ida, &f.volta] {
                if s.anel.tamanho() > BUFFER_DO_SENTIDO
                    || s.escritos != s.lidos + s.descartados + s.anel.tamanho() as u64
                    || (s.estado == EstadoDoSentido::Abortado && s.anel.tamanho() != 0)
                {
                    return false;
                }
            }
            if f.estado == Estado::Pedido
                && (f.ida.escritos != 0 || f.volta.escritos != 0 || f.saiu != [false; 2])
            {
                return false;
            }
            if f.lado_remoto().is_none() && f.concluido() {
                // O concluído sai na hora: não fica vivo. O remoto espera a
                // sessão dizer o fim ou o fecho — `talvez_encerrar`.
                return false;
            }
            match (f.lado_remoto(), f.credito) {
                (None, Some(_)) => return false,
                (Some(_), None) if f.estado == Estado::Aberto => return false,
                (Some(r), Some(c)) => {
                    let chega = f.escrita_de(r);
                    if chega.estado == EstadoDoSentido::Aberto
                        && c.concedido + chega.anel.tamanho() as u64 + c.a_devolver
                            != BUFFER_DO_SENTIDO as u64
                    {
                        return false;
                    }
                    if c.para_mandar > BUFFER_DO_SENTIDO as u64 {
                        return false;
                    }
                }
                _ => {}
            }
            if f.vivos_do_titular_passam(self) {
                return false;
            }
        }
        // As cotas, para cada processo, endpoint e relação que aparecem.
        for f in &self.vivos {
            for p in [&f.abridor, &f.aceitante] {
                if let Ponta::Processo { fio, .. } = p
                    && self.vivos.iter().filter(|g| g.conta_para(*fio)).count()
                        > FLUXOS_POR_PROCESSO
                {
                    return false;
                }
            }
            if let Endpoint::Daqui(e) = f.endpoint
                && self
                    .vivos
                    .iter()
                    .filter(|g| g.estado == Estado::Pedido && g.endpoint == Endpoint::Daqui(e))
                    .count()
                    > PEDIDOS_POR_ENDPOINT
            {
                return false;
            }
            if f.abridor.remota()
                && self
                    .vivos
                    .iter()
                    .filter(|g| g.abridor.quem() == f.abridor.quem())
                    .count()
                    > REMOTOS_POR_RELACAO
            {
                return false;
            }
        }
        true
    }
}

impl Fluxo {
    /// O titular deste fluxo tem mais fluxos que a cota.
    fn vivos_do_titular_passam(&self, t: &Fluxos) -> bool {
        t.vivos.iter().filter(|g| g.titular == self.titular).count() > FLUXOS_POR_TITULAR
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    const P1: Titular = Titular::Pessoa([1; 8]);
    const P2: Titular = Titular::Pessoa([2; 8]);

    fn programa(nome: &str, n: u8) -> Programa {
        Programa {
            nome: String::from(nome),
            resumo: [n; 32],
            editor: None,
        }
    }

    fn processo(fio: u64) -> Ponta {
        Ponta::Processo {
            fio,
            programa: programa("p", fio as u8),
        }
    }

    fn par(n: u8) -> Ponta {
        Ponta::Remota {
            dispositivo: [n; 32],
            relacao: [n; 16],
            programa: [0xab; 32],
        }
    }

    fn q(fio: u64) -> Quem {
        Quem::Processo(fio)
    }

    fn qpar(n: u8) -> Quem {
        par(n).quem()
    }

    /// Abre e aceita um fluxo local de 10 para o endpoint 7 de 20.
    fn aberto(t: &mut Fluxos) -> u64 {
        let id = t
            .abrir(P1, processo(10), 7, processo(20), "a.b", 0)
            .unwrap();
        assert_eq!(t.primeiro_pedido(P1, 20, 7), Some(id));
        t.aceitar(P1, 20, id, 0).unwrap();
        id
    }

    fn ler_tudo(t: &mut Fluxos, quem: Quem, id: u64) -> (Vec<u8>, bool) {
        let mut v = Vec::new();
        loop {
            let (l, _) = t.ler(P1, quem, id, MAIOR_LEITURA, 1).unwrap();
            v.extend_from_slice(&l.dados);
            if l.dados.is_empty() || l.fim {
                return (v, l.fim);
            }
        }
    }

    /// FH01: a tabela estado × evento — o que cada estado aceita e recusa.
    #[test]
    fn estados_e_transicoes() {
        let mut t = Fluxos::nova();
        let id = t
            .abrir(P1, processo(10), 7, processo(20), "a.b", 0)
            .unwrap();
        // Pedido: ninguém escreve nem lê; o aceitante ainda não é ponta.
        assert_eq!(
            t.escrever(P1, q(10), id, b"x", 0),
            Err(Recusa::Estado("o fluxo ainda nao abriu"))
        );
        assert!(t.ler(P1, q(10), id, 1, 0).is_err());
        assert_eq!(t.escrever(P1, q(20), id, b"x", 0), Err(Recusa::NaoExiste));
        assert_eq!(t.estado(P1, q(10), id).unwrap().estado, "pending");
        assert_eq!(t.estado(P1, q(20), id), Err(Recusa::NaoExiste));
        // Só o dono do endpoint aceita, uma vez.
        assert_eq!(t.aceitar(P1, 30, id, 0), Err(Recusa::NaoExiste));
        assert_eq!(t.aceitar(P2, 20, id, 0), Err(Recusa::NaoExiste));
        let a = t.aceitar(P1, 20, id, 0).unwrap();
        assert_eq!(a.abridor, processo(10));
        assert_eq!(t.aceitar(P1, 20, id, 0), Err(Recusa::NaoExiste));
        assert_eq!(t.estado(P1, q(20), id).unwrap().estado, "open");
        assert_eq!(t.estado(P1, q(20), id).unwrap().outra, Some(processo(10)));
        // Aberto: os dois escrevem e leem.
        assert_eq!(t.escrever(P1, q(10), id, b"ola", 1), Ok(3));
        assert_eq!(t.escrever(P1, q(20), id, b"oi", 1), Ok(2));
        let (l, _) = t.ler(P1, q(20), id, 10, 2).unwrap();
        assert_eq!(&*l.dados, b"ola");
        assert!(!l.fim);
        // Os dois terminam: concluído, e a lápide diz a cada um, uma vez.
        assert_eq!(t.terminar(P1, q(10), id, 3), Ok(None));
        assert_eq!(t.terminar(P1, q(20), id, 3), Ok(None));
        let (l, e) = t.ler(P1, q(20), id, 10, 4).unwrap();
        assert!(l.dados.is_empty() && l.fim && e.is_none());
        let (l, e) = t.ler(P1, q(10), id, 10, 4).unwrap();
        assert_eq!((&*l.dados, l.fim), (&b"oi"[..], true));
        let e = e.expect("concluido");
        assert_eq!(e.motivo, motivo::CONCLUIDO);
        assert_eq!((e.ida, e.volta, e.descartados), (3, 2, 0));
        assert!(t.coerente());
        assert_eq!(
            t.escrever(P1, q(10), id, b"x", 5),
            Err(Recusa::Encerrado(String::from("concluido")))
        );
        assert_eq!(t.estado(P1, q(20), id).unwrap().estado, "closed");
        // Os dois já souberam: a lápide saiu, e o id não é mais de nada.
        assert_eq!(t.lapides(), 0);
        assert_eq!(t.estado(P1, q(10), id), Err(Recusa::NaoExiste));
        // Fechar o pedido: acaba, e quem abriu sabe na hora.
        let id = t
            .abrir(P1, processo(10), 7, processo(20), "a.b", 0)
            .unwrap();
        let e = t.fechar(P1, q(10), id, 1).unwrap().unwrap();
        assert_eq!(e.motivo, motivo::FECHADO);
        assert_eq!(t.lapides(), 0);
        assert_eq!(t.primeiro_pedido(P1, 20, 7), None);
        // A reconfirmação recusa quem abriu: o pedido acaba com o motivo.
        let id = t
            .abrir(P1, processo(10), 7, processo(20), "a.b", 0)
            .unwrap();
        assert_eq!(
            t.recusar(id, motivo::ABRIDOR).unwrap().motivo,
            motivo::ABRIDOR
        );
        assert_eq!(
            t.escrever(P1, q(10), id, b"x", 1),
            Err(Recusa::Encerrado(String::from(motivo::ABRIDOR)))
        );
        // Ninguém abre fluxo consigo; a intenção tem a forma.
        assert_eq!(
            t.abrir(P1, processo(10), 7, processo(10), "a.b", 0),
            Err(Recusa::MesmoProcesso)
        );
        assert!(t.abrir(P1, processo(10), 7, processo(20), "a*", 0).is_err());
        assert!(t.coerente());
    }

    /// FH02: os sentidos terminam sozinhos; o fim depois do último byte.
    #[test]
    fn os_sentidos() {
        let mut t = Fluxos::nova();
        let id = aberto(&mut t);
        assert_eq!(t.escrever(P1, q(10), id, b"abc", 1), Ok(3));
        assert_eq!(t.terminar(P1, q(10), id, 1), Ok(None));
        assert_eq!(
            t.terminar(P1, q(10), id, 1),
            Err(Recusa::Estado("o sentido ja acabou"))
        );
        assert_eq!(
            t.escrever(P1, q(10), id, b"d", 1),
            Err(Recusa::Estado("o sentido ja acabou"))
        );
        // O outro sentido continua.
        assert_eq!(t.escrever(P1, q(20), id, b"xyz", 1), Ok(3));
        let (l, _) = t.ler(P1, q(20), id, 2, 2).unwrap();
        assert_eq!((&*l.dados, l.fim), (&b"ab"[..], false));
        let (l, _) = t.ler(P1, q(20), id, 2, 2).unwrap();
        assert_eq!((&*l.dados, l.fim), (&b"c"[..], true));
        let (l, _) = t.ler(P1, q(20), id, 2, 2).unwrap();
        assert!(l.dados.is_empty() && l.fim);
        let v = t.estado(P1, q(20), id).unwrap();
        assert_eq!(v.leitura, Some(EstadoDoSentido::Fim));
        assert_eq!(v.escrita, Some(EstadoDoSentido::Aberto));
        assert!(t.coerente());
    }

    /// O encerramento zera e conta o que sobrou num sentido que ninguém
    /// abortou. Hoje todo caminho aborta os sentidos, ou os lê até o fim,
    /// antes de encerrar — é a defesa de um caminho novo que esqueça.
    #[test]
    fn o_encerramento_conta_os_restos() {
        let mut t = Fluxos::nova();
        let id = aberto(&mut t);
        t.escrever(P1, q(10), id, b"sobra", 1).unwrap();
        t.escrever(P1, q(20), id, b"e mais", 1).unwrap();
        let i = t.i(id).unwrap();
        let e = t.encerrar(i, motivo::REVOGADO);
        assert_eq!((e.ida, e.volta, e.descartados), (5, 6, 11));
        assert!(t.coerente());
    }

    /// FH03: o fecho deixa legível o que a ponta escreveu e tira o que ela
    /// não leu; o aborto tira tudo — com as contas.
    #[test]
    fn fechar_e_abortar() {
        let mut t = Fluxos::nova();
        let id = aberto(&mut t);
        t.escrever(P1, q(10), id, b"para o 20", 1).unwrap();
        t.escrever(P1, q(20), id, b"para o 10, nunca lido", 1)
            .unwrap();
        // 10 fecha: o que escreveu continua para 20; o que era dele, sai.
        assert_eq!(t.fechar(P1, q(10), id, 2), Ok(None));
        // Sai na hora do fecho — o anel solto e zerado, os bytes contados —,
        // e não só no fim do fluxo, que pode demorar o quanto 20 quiser.
        let f = &t.vivos[t.i(id).unwrap()];
        assert_eq!((f.volta.anel.tamanho(), f.volta.descartados), (0, 21));
        assert_eq!(
            t.escrever(P1, q(10), id, b"x", 2),
            Err(Recusa::Encerrado(String::from(motivo::FECHADO)))
        );
        assert_eq!(
            t.escrever(P1, q(20), id, b"x", 2),
            Err(Recusa::Encerrado(String::from(motivo::FECHADO)))
        );
        let (l, e) = t.ler(P1, q(20), id, 100, 3).unwrap();
        assert_eq!((&*l.dados, l.fim), (&b"para o 20"[..], true));
        let e = e.expect("o fluxo acaba quando 20 le o fim");
        assert_eq!(e.motivo, motivo::FECHADO);
        assert_eq!(e.descartados, 21);
        assert!(t.coerente());
        // O aborto: os dois sentidos saem, e a próxima operação diz o motivo.
        let id = aberto(&mut t);
        t.escrever(P1, q(10), id, b"12345", 1).unwrap();
        t.escrever(P1, q(20), id, b"678", 1).unwrap();
        let e = t.abortar(id, motivo::REVOGADO).unwrap();
        assert_eq!((e.ida, e.volta, e.descartados), (5, 3, 8));
        assert_eq!(
            t.ler(P1, q(20), id, 10, 2).map(|(l, _)| l.fim),
            Err(Recusa::Encerrado(String::from(motivo::REVOGADO)))
        );
        assert_eq!(
            t.estado(P1, q(10), id).unwrap().motivo.as_deref(),
            Some(motivo::REVOGADO)
        );
        // Fechar os dois lados: o segundo acaba o fluxo.
        let id = aberto(&mut t);
        assert_eq!(t.fechar(P1, q(20), id, 1), Ok(None));
        let e = t.fechar(P1, q(10), id, 1).unwrap().unwrap();
        assert_eq!(e.motivo, motivo::FECHADO);
        assert!(t.coerente());
        // A morte de quem só terminou o sentido dele aborta: ele ainda é
        // ponta — ainda lê.
        let id = aberto(&mut t);
        t.escrever(P1, q(20), id, b"volta", 1).unwrap();
        t.terminar(P1, q(20), id, 1).unwrap();
        let e = t.processo_acabou(20, motivo::PROCESSO);
        assert_eq!(e.len(), 1);
        assert_eq!(
            (e[0].motivo.as_str(), e[0].descartados),
            (motivo::PROCESSO, 5)
        );
        // A de quem já fechou, não: a ponta não era mais dele, e o que ele
        // escreveu segue legível pela outra, até o fim — como no fecho.
        let id = aberto(&mut t);
        t.escrever(P1, q(20), id, b"volta", 1).unwrap();
        assert_eq!(t.fechar(P1, q(20), id, 1), Ok(None));
        assert!(t.processo_acabou(20, motivo::PROCESSO).is_empty());
        assert!(t.processo_acabou(20, motivo::PROGRAMA).is_empty());
        let (l, e) = t.ler(P1, q(10), id, 100, 2).unwrap();
        assert_eq!((&*l.dados, l.fim), (&b"volta"[..], true));
        assert_eq!(e.expect("o fluxo acaba no fim").motivo, motivo::FECHADO);
        // E a de quem fica, depois, também não acha nada: acabou.
        assert!(t.processo_acabou(10, motivo::PROCESSO).is_empty());
        assert!(t.coerente());
    }

    /// FH04: os prazos — o do aceite, o da inatividade, e a atividade que
    /// renova o relógio.
    #[test]
    fn os_prazos() {
        let mut t = Fluxos::nova();
        let id = t
            .abrir(P1, processo(10), 7, processo(20), "a.b", 1000)
            .unwrap();
        assert!(t.vencer(1000 + PRAZO_DO_ACEITE_MS - 1).is_empty());
        let v = t.vencer(1000 + PRAZO_DO_ACEITE_MS);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].motivo, motivo::PRAZO_DO_ACEITE);
        assert_eq!(
            t.escrever(P1, q(10), id, b"x", 0),
            Err(Recusa::Encerrado(String::from(motivo::PRAZO_DO_ACEITE)))
        );
        let id = aberto(&mut t);
        assert!(t.vencer(OCIOSO_MS - 1).is_empty());
        // Um byte renova o relógio.
        t.escrever(P1, q(10), id, b"x", 100_000).unwrap();
        assert!(t.vencer(OCIOSO_MS + 1).is_empty());
        let v = t.vencer(100_000 + OCIOSO_MS);
        assert_eq!(v[0].motivo, motivo::OCIOSO);
        assert_eq!(v[0].descartados, 1);
        // Um pedido ao par tem o prazo dele.
        let id = t
            .abrir_no_par(P1, processo(10), par(9), "e:1", "a.b", 0)
            .unwrap();
        assert!(t.vencer(PRAZO_DO_ACEITE_MS).is_empty());
        assert_eq!(t.vencer(PRAZO_DO_ACEITE_REMOTO_MS)[0].id, id);
        assert!(t.coerente());
    }

    /// FH05: as cotas — do processo, do titular, da máquina, do endpoint e
    /// do par. Um vivo nunca é cortado por cota.
    #[test]
    fn as_cotas() {
        let mut t = Fluxos::nova();
        // Quatro de um processo; o quinto não.
        for e in 0..4 {
            t.abrir(P1, processo(10), 100 + e, processo(20 + e), "a.b", 0)
                .unwrap();
        }
        assert_eq!(
            t.abrir(P1, processo(10), 200, processo(30), "a.b", 0),
            Err(Recusa::Cota("o processo ja tem 4 fluxos"))
        );
        // O aceitante conta depois do aceite.
        let id = t.primeiro_pedido(P1, 20, 100).unwrap();
        t.aceitar(P1, 20, id, 0).unwrap();
        // Oito do titular; o nono não.
        for f in 0..4 {
            t.abrir(P1, processo(11 + f), 300 + f, processo(40 + f), "a.b", 0)
                .unwrap();
        }
        assert_eq!(
            t.abrir(P1, processo(15), 400, processo(50), "a.b", 0),
            Err(Recusa::Cota("o titular ja tem 8 fluxos"))
        );
        // Dezesseis na máquina; o décimo sétimo não.
        for f in 0..8 {
            t.abrir(P2, processo(60 + f), 500 + f, processo(70 + f), "a.b", 0)
                .unwrap();
        }
        assert_eq!(
            t.abrir(Titular::Sistema, processo(90), 600, processo(91), "a.b", 0),
            Err(Recusa::Cota("ja ha 16 fluxos na maquina"))
        );
        assert!(t.coerente());
        // A fila de um endpoint: quatro; o quinto não.
        let mut t = Fluxos::nova();
        for f in 0..4 {
            t.abrir(P1, processo(10 + f), 7, processo(1), "a.b", 0)
                .unwrap();
        }
        assert_eq!(
            t.abrir(P1, processo(20), 7, processo(1), "a.b", 0),
            Err(Recusa::Cota("o endpoint ja tem 4 pedidos na fila"))
        );
        // O aceitante cheio não aceita, e o pedido fica.
        let mut t = Fluxos::nova();
        for f in 0..5 {
            t.abrir(P1, processo(10 + f), 7, processo(1), "a.b", 0)
                .unwrap_or(0);
        }
        for _ in 0..4 {
            let id = t.primeiro_pedido(P1, 1, 7).unwrap();
            t.aceitar(P1, 1, id, 0).unwrap();
        }
        let id = t.abrir(P1, processo(30), 7, processo(1), "a.b", 0).unwrap();
        assert_eq!(
            t.aceitar(P1, 1, id, 0),
            Err(Recusa::Cota("o processo ja tem 4 fluxos"))
        );
        assert_eq!(t.primeiro_pedido(P1, 1, 7), Some(id));
        // O par: dois que saem; um por relação que chega.
        let mut t = Fluxos::nova();
        t.abrir_no_par(P1, processo(10), par(1), "e:1", "a.b", 0)
            .unwrap();
        t.abrir_no_par(P1, processo(11), par(1), "e:1", "a.b", 0)
            .unwrap();
        assert_eq!(
            t.abrir_no_par(P1, processo(12), par(2), "e:1", "a.b", 0),
            Err(Recusa::Cota("ja ha 2 fluxos daqui a outros dispositivos"))
        );
        let mut t = Fluxos::nova();
        t.abrir(P1, par(3), 7, processo(1), "a.b", 0).unwrap();
        assert_eq!(
            t.abrir(P1, par(3), 8, processo(2), "a.b", 0),
            Err(Recusa::Cota("a relacao ja tem um fluxo aberto aqui"))
        );
        t.abrir(P1, par(4), 8, processo(2), "a.b", 0).unwrap();
        assert!(t.coerente());
    }

    /// Um fluxo de 10 (daqui) com o par: aberto, com o crédito inicial.
    fn com_o_par(t: &mut Fluxos) -> u64 {
        let id = t
            .abrir_no_par(P1, processo(10), par(9), "e:1", "a.b", 0)
            .unwrap();
        t.aceito_pelo_par(id, 0).unwrap();
        id
    }

    /// A ponta daqui que fecha com dados à espera de crédito não deixa a
    /// sessão sem o que esperar: só o fecho, depois de tudo ir, é o que
    /// fazer; e o fluxo precisa da sessão até os dois fins andarem.
    #[test]
    fn o_fecho_daqui_espera_o_credito() {
        let mut t = Fluxos::nova();
        let id = com_o_par(&mut t);
        assert!(t.precisa_do_par(id));
        // O crédito do par inteiro vai; o que se escreve depois espera.
        let grande = alloc::vec![1u8; BUFFER_DO_SENTIDO];
        assert_eq!(t.escrever(P1, q(10), id, &grande, 1), Ok(BUFFER_DO_SENTIDO));
        assert_eq!(
            t.tirar_para_o_par(id, usize::MAX, 1).len(),
            BUFFER_DO_SENTIDO
        );
        assert_eq!(t.escrever(P1, q(10), id, &grande[..100], 1), Ok(100));
        assert!(t.tirar_para_o_par(id, usize::MAX, 1).is_empty());
        t.fechar(P1, q(10), id, 2).unwrap();
        // Dados à espera, sem crédito: nada a fazer, e não o fecho.
        assert!(!t.saiu_e_foi(id));
        assert!(!t.par_tem_o_que_fazer(id));
        assert!(t.precisa_do_par(id));
        // O crédito chega: os dados, o fim e então o fecho.
        t.credito_do_par(id, 100).unwrap();
        assert!(t.par_tem_o_que_fazer(id));
        assert_eq!(t.tirar_para_o_par(id, usize::MAX, 3).len(), 100);
        assert!(t.par_tem_o_que_fazer(id));
        assert!(t.fim_para_o_par(id));
        assert!(t.saiu_e_foi(id));
        assert!(t.par_tem_o_que_fazer(id));
        assert!(t.coerente());
    }

    /// O que o par manda passa pela conta antes de qualquer decisão: dentro
    /// do crédito cabe; além dele, antes do aceite e depois do fim é
    /// protocolo; depois do fecho daqui é descartado.
    #[test]
    fn o_que_cabe_do_par() {
        let mut t = Fluxos::nova();
        let id = t
            .abrir_no_par(P1, processo(10), par(9), "e:1", "a.b", 0)
            .unwrap();
        assert_eq!(
            t.cabe_do_par(id, 1),
            Err(Recusa::Protocolo("dados antes do aceite"))
        );
        t.aceito_pelo_par(id, 0).unwrap();
        assert_eq!(t.cabe_do_par(id, BUFFER_DO_SENTIDO), Ok(()));
        assert_eq!(
            t.cabe_do_par(id, BUFFER_DO_SENTIDO + 1),
            Err(Recusa::Protocolo("o par passou do credito"))
        );
        assert_eq!(t.escrever(P1, qpar(9), id, &[1; 100], 1), Ok(100));
        assert_eq!(
            t.cabe_do_par(id, BUFFER_DO_SENTIDO - 99),
            Err(Recusa::Protocolo("o par passou do credito"))
        );
        assert_eq!(t.cabe_do_par(id, BUFFER_DO_SENTIDO - 100), Ok(()));
        assert_eq!(t.fim_do_par(id, 2), Ok(None));
        assert_eq!(
            t.cabe_do_par(id, 1),
            Err(Recusa::Protocolo("dados depois do fim"))
        );
        assert_eq!(t.cabe_do_par(id + 1, 1), Err(Recusa::NaoExiste));
        let outro = t
            .abrir_no_par(P1, processo(11), par(8), "e:2", "a.b", 0)
            .unwrap();
        t.aceito_pelo_par(outro, 0).unwrap();
        t.fechar(P1, q(11), outro, 3).unwrap();
        assert_eq!(
            t.cabe_do_par(outro, 1),
            Err(Recusa::Encerrado(String::from(motivo::FECHADO)))
        );
        assert!(t.coerente());
    }

    /// Os dois fins ditos: o fluxo não precisa mais da sessão, e quem lê
    /// daqui lê o resto sem ela.
    #[test]
    fn depois_dos_dois_fins_o_fluxo_nao_precisa_do_par() {
        let mut t = Fluxos::nova();
        let id = com_o_par(&mut t);
        assert_eq!(t.escrever(P1, qpar(9), id, b"resto", 1), Ok(5));
        assert_eq!(t.fim_do_par(id, 1), Ok(None));
        assert!(t.precisa_do_par(id));
        t.terminar(P1, q(10), id, 2).unwrap();
        assert!(t.fim_para_o_par(id));
        assert!(!t.precisa_do_par(id));
        let (l, e) = t.ler(P1, q(10), id, 100, 3).unwrap();
        assert_eq!(&l.dados[..], b"resto");
        assert!(l.fim);
        assert_eq!(e.map(|e| e.motivo), Some(String::from(motivo::CONCLUIDO)));
        assert!(!t.precisa_do_par(id));
    }

    /// O pico dos buffers: o maior que um sentido chegou a ter, de um
    /// processo daqui ou do par, nunca passa do buffer do sentido — e não
    /// desce quando o buffer esvazia. E os vivos com uma ponta noutro Duke.
    #[test]
    fn o_pico_dos_buffers() {
        let mut t = Fluxos::nova();
        assert_eq!(t.pico_do_buffer(), 0);
        let id = com_o_par(&mut t);
        assert_eq!(t.remotos_vivos(), 1);
        assert_eq!(t.escrever(P1, q(10), id, &[1; 1000], 1), Ok(1000));
        assert_eq!(t.pico_do_buffer(), 1000);
        let cheio = alloc::vec![7u8; BUFFER_DO_SENTIDO];
        assert_eq!(
            t.escrever(P1, qpar(9), id, &cheio, 1),
            Ok(BUFFER_DO_SENTIDO)
        );
        assert_eq!(t.pico_do_buffer(), BUFFER_DO_SENTIDO);
        // O par além do crédito é protocolo, e o pico não passa do buffer.
        assert!(t.escrever(P1, qpar(9), id, b"x", 1).is_err());
        assert_eq!(t.pico_do_buffer(), BUFFER_DO_SENTIDO);
        // Daqui, o buffer cheio não aceita mais nada.
        let mais = alloc::vec![2u8; BUFFER_DO_SENTIDO];
        assert_eq!(
            t.escrever(P1, q(10), id, &mais, 1),
            Ok(BUFFER_DO_SENTIDO - 1000)
        );
        assert_eq!(t.escrever(P1, q(10), id, b"y", 1), Ok(0));
        assert_eq!(t.pico_do_buffer(), BUFFER_DO_SENTIDO);
        t.ler(P1, q(10), id, BUFFER_DO_SENTIDO, 2).unwrap();
        assert_eq!(t.pico_do_buffer(), BUFFER_DO_SENTIDO);
        let local = t
            .abrir(P1, processo(20), 7, processo(21), "a.b", 3)
            .unwrap();
        assert_eq!(t.remotos_vivos(), 1);
        t.abortar(id, motivo::CONEXAO).unwrap();
        assert_eq!(t.remotos_vivos(), 0);
        assert!(t.retrato(local).is_some());
        assert!(t.coerente());
    }

    /// O retrato que a sessão com o par lê: o pedido, o aberto, e nada do
    /// que acabou.
    #[test]
    fn o_retrato_do_fluxo() {
        let mut t = Fluxos::nova();
        let id = t
            .abrir_no_par(P1, processo(10), par(9), "e:1", "a.b", 0)
            .unwrap();
        let r = t.retrato(id).unwrap();
        assert_eq!(r.estado, Estado::Pedido);
        assert_eq!(r.titular, P1);
        assert_eq!(r.intencao, "a.b");
        assert_eq!(r.endpoint, Endpoint::DoPar(String::from("e:1")));
        assert_eq!(r.abridor, processo(10));
        assert_eq!(r.aceitante, par(9));
        t.aceito_pelo_par(id, 1).unwrap();
        assert_eq!(t.retrato(id).unwrap().estado, Estado::Aberto);
        t.abortar(id, motivo::CONEXAO).unwrap();
        assert_eq!(t.retrato(id), None);
        assert_eq!(t.retrato(id + 1), None);
    }

    /// FH06: o crédito — concedido, consumido, devolvido; passar dele é
    /// protocolo; a memória nunca passa do que se concedeu.
    #[test]
    fn o_credito() {
        let mut t = Fluxos::nova();
        let id = com_o_par(&mut t);
        // O par manda até o crédito; um byte a mais é protocolo.
        let cheio = alloc::vec![7u8; BUFFER_DO_SENTIDO];
        assert_eq!(
            t.escrever(P1, qpar(9), id, &cheio, 1),
            Ok(BUFFER_DO_SENTIDO)
        );
        assert_eq!(
            t.escrever(P1, qpar(9), id, b"x", 1),
            Err(Recusa::Protocolo("o par passou do credito"))
        );
        assert!(t.coerente());
        // Ler devolve crédito a partir do limiar, agrupado.
        t.ler(P1, q(10), id, LIMIAR_DO_CREDITO - 1, 2).unwrap();
        assert_eq!(t.credito_a_devolver(id), None);
        t.ler(P1, q(10), id, 1, 2).unwrap();
        assert_eq!(t.credito_a_devolver(id), Some(LIMIAR_DO_CREDITO as u64));
        assert_eq!(t.credito_a_devolver(id), None);
        assert_eq!(
            t.escrever(P1, qpar(9), id, &cheio[..LIMIAR_DO_CREDITO], 3),
            Ok(LIMIAR_DO_CREDITO)
        );
        assert!(t.coerente());
        // Daqui ao par: o que ele concedeu, e nada além.
        let grande = alloc::vec![1u8; BUFFER_DO_SENTIDO];
        assert_eq!(t.escrever(P1, q(10), id, &grande, 3), Ok(BUFFER_DO_SENTIDO));
        assert_eq!(
            t.tirar_para_o_par(id, usize::MAX, 4).len(),
            BUFFER_DO_SENTIDO
        );
        assert!(t.tirar_para_o_par(id, usize::MAX, 4).is_empty());
        assert_eq!(t.escrever(P1, q(10), id, &grande[..100], 4), Ok(100));
        assert!(t.tirar_para_o_par(id, usize::MAX, 4).is_empty());
        assert!(!t.par_tem_o_que_fazer(id));
        t.credito_do_par(id, 60).unwrap();
        assert!(t.par_tem_o_que_fazer(id));
        assert_eq!(t.tirar_para_o_par(id, usize::MAX, 5).len(), 60);
        // Conceder mais que o buffer dele é protocolo.
        t.credito_do_par(id, 100).unwrap();
        assert!(t.credito_do_par(id, BUFFER_DO_SENTIDO as u64).is_err());
        assert!(t.credito_do_par(id, 0).is_err());
        // O fim, uma vez, depois do último byte que saiu.
        t.terminar(P1, q(10), id, 6).unwrap();
        assert!(!t.fim_para_o_par(id));
        assert_eq!(t.tirar_para_o_par(id, usize::MAX, 6).len(), 40);
        assert!(t.fim_para_o_par(id));
        assert!(!t.fim_para_o_par(id));
        assert!(t.coerente());
        // O par fecha em ordem: o fim dele, depois o fecho; o que ele mandou
        // continua legível aqui.
        let id = com_o_par(&mut t);
        t.escrever(P1, qpar(9), id, b"ultimo", 1).unwrap();
        assert_eq!(t.fim_do_par(id, 1), Ok(None));
        assert_eq!(t.fechar_do_par(id, motivo::FECHADO), None);
        let (l, e) = t.ler(P1, q(10), id, 100, 2).unwrap();
        assert_eq!((&*l.dados, l.fim), (&b"ultimo"[..], true));
        assert_eq!(e.unwrap().motivo, motivo::FECHADO);
        // Sem o fim antes, o fecho do par é aborto, com o motivo dele.
        let id = com_o_par(&mut t);
        t.escrever(P1, qpar(9), id, b"cortado", 1).unwrap();
        let e = t.fechar_do_par(id, "revogado\nlá").unwrap();
        assert_eq!(e.motivo, "revogadol");
        assert_eq!(e.descartados, 7);
        // A ponta daqui fecha: o que escreveu vai, depois o fim; e a sessão
        // diz `fechar`.
        let id = com_o_par(&mut t);
        t.escrever(P1, q(10), id, b"vai", 1).unwrap();
        assert_eq!(t.fechar(P1, q(10), id, 1), Ok(None));
        assert!(!t.saiu_e_foi(id));
        assert_eq!(&*t.tirar_para_o_par(id, 100, 2), b"vai");
        assert!(t.fim_para_o_par(id));
        assert!(t.saiu_e_foi(id));
        assert_eq!(t.talvez_encerrar(id).unwrap().motivo, motivo::FECHADO);
        assert!(t.coerente());
    }

    /// FH07: os bytes saem na ordem, sem buraco nem repetição, sob escritas
    /// e leituras de tamanhos sorteados.
    #[test]
    fn a_ordem_por_sorteio() {
        let mut t = Fluxos::nova();
        let id = aberto(&mut t);
        let mut semente = 0x2545_F491_4F6C_DD1Du64;
        let mut proximo = move || {
            semente ^= semente << 13;
            semente ^= semente >> 7;
            semente ^= semente << 17;
            semente
        };
        let mut escrito: u64 = 0;
        let mut lido: Vec<u8> = Vec::new();
        for _ in 0..3000 {
            let n = (proximo() % 5000) as usize;
            let dados: Vec<u8> = (0..n).map(|i| ((escrito + i as u64) % 251) as u8).collect();
            let k = t.escrever(P1, q(10), id, &dados, 1).unwrap();
            escrito += k as u64;
            let m = (proximo() % 6000) as usize;
            let (l, _) = t.ler(P1, q(20), id, m, 1).unwrap();
            lido.extend_from_slice(&l.dados);
            assert!(t.coerente());
        }
        t.terminar(P1, q(10), id, 2).unwrap();
        let (resto, fim) = ler_tudo(&mut t, q(20), id);
        lido.extend_from_slice(&resto);
        assert!(fim);
        assert_eq!(lido.len() as u64, escrito);
        assert!(
            lido.iter()
                .enumerate()
                .all(|(i, &b)| b == (i as u64 % 251) as u8)
        );
    }

    /// FH08: sorteio — abrir, aceitar, escrever, ler, terminar, fechar,
    /// abortar, vencer, matar, revogar, o par — e a tabela coerente depois
    /// de cada passo.
    #[test]
    fn coerente_por_sorteio() {
        let mut t = Fluxos::nova();
        let mut semente = 0x9E37_79B9_7F4A_7C15u64;
        let mut proximo = move || {
            semente ^= semente << 13;
            semente ^= semente >> 7;
            semente ^= semente << 17;
            semente
        };
        let titulares = [P1, P2];
        for passo in 0..4000u64 {
            let ti = titulares[(proximo() % 2) as usize];
            let fio = 1 + proximo() % 8;
            let outro = 1 + proximo() % 8;
            let id = 1 + proximo() % 40;
            let n = (proximo() % 3000) as usize;
            let dados = alloc::vec![(passo % 256) as u8; n];
            match proximo() % 14 {
                0 | 1 => {
                    let _ = t.abrir(ti, processo(fio), outro, processo(outro), "a.b", passo);
                }
                2 => {
                    if let Some(id) = t.primeiro_pedido(ti, outro, outro) {
                        let _ = t.aceitar(ti, outro, id, passo);
                    }
                }
                3 | 4 => {
                    let _ = t.escrever(ti, q(fio), id, &dados, passo);
                }
                5 | 6 => {
                    let _ = t.ler(ti, q(fio), id, n, passo);
                }
                7 => {
                    let _ = t.terminar(ti, q(fio), id, passo);
                }
                8 => {
                    let _ = t.fechar(ti, q(fio), id, passo);
                }
                9 => {
                    if proximo() % 10 == 0 {
                        t.anular_titular(ti, motivo::REVOGADO);
                    } else {
                        t.processo_acabou(fio, motivo::PROCESSO);
                    }
                }
                10 => {
                    let _ = t.vencer(passo * 50);
                    let _ = t.endpoint_acabou(outro);
                }
                11 => {
                    // O par: abre para cá, e daqui para lá.
                    if proximo() % 2 == 0 {
                        let _ = t.abrir(
                            ti,
                            par((fio % 3) as u8),
                            outro,
                            processo(outro),
                            "a.b",
                            passo,
                        );
                    } else if let Ok(id) = t.abrir_no_par(
                        ti,
                        processo(fio),
                        par((outro % 3) as u8),
                        "e:1",
                        "a.b",
                        passo,
                    ) {
                        let _ = t.aceito_pelo_par(id, passo);
                    }
                }
                12 => {
                    let r = (fio % 3) as u8;
                    let _ = t.escrever(ti, qpar(r), id, &dados, passo);
                    let _ = t.tirar_para_o_par(id, n, passo);
                    let _ = t.credito_do_par(id, (n % 5000) as u64);
                    let _ = t.credito_a_devolver(id);
                    let _ = t.fim_para_o_par(id);
                    let _ = t.talvez_encerrar(id);
                }
                _ => match proximo() % 4 {
                    0 => {
                        let _ = t.fim_do_par(id, passo);
                    }
                    1 => {
                        let _ = t.fechar_do_par(id, "do par");
                    }
                    2 => {
                        let _ = t.anular_remotos(motivo::RELACAO, |d, _| d[0] == (fio % 3) as u8);
                    }
                    _ => {
                        let _ = t.estado(ti, q(fio), id);
                    }
                },
            }
            assert!(t.coerente(), "passo {passo}");
        }
    }

    /// FH09: um id só se resolve para as duas pontas; o de outro, de outro
    /// titular, ou o que não existe, não resolve — e o vivo é aberto só
    /// para quem ainda está nele.
    #[test]
    fn o_id_so_para_as_pontas() {
        let mut t = Fluxos::nova();
        let pedido = t
            .abrir(P1, processo(10), 7, processo(20), "a.b", 0)
            .unwrap();
        assert_eq!(t.intencao_para(P1, q(10), pedido), Some("a.b"));
        // O aceitante ainda não é ponta de um pedido.
        assert_eq!(t.intencao_para(P1, q(20), pedido), None);
        assert!(!t.aberto_para(P1, q(10), pedido));
        t.aceitar(P1, 20, pedido, 0).unwrap();
        for quem in [q(10), q(20)] {
            assert_eq!(t.intencao_para(P1, quem, pedido), Some("a.b"));
            assert!(t.aberto_para(P1, quem, pedido));
        }
        assert_eq!(t.intencao_para(P1, q(30), pedido), None);
        assert_eq!(t.intencao_para(P2, q(10), pedido), None);
        assert_eq!(t.intencao_para(P1, q(10), pedido + 100), None);
        assert_eq!(t.intencao_para(P1, qpar(1), pedido), None);
        assert_eq!(t.ler(P1, q(30), pedido, 1, 0), Err(Recusa::NaoExiste));
        // Quem fechou não tem mais o recurso aberto; a lápide resolve para
        // as pontas, só elas.
        t.fechar(P1, q(10), pedido, 1).unwrap();
        assert!(!t.aberto_para(P1, q(10), pedido));
        assert!(t.aberto_para(P1, q(20), pedido));
        t.abortar(pedido, motivo::REVOGADO).unwrap();
        assert_eq!(t.intencao_para(P1, q(20), pedido), Some("a.b"));
        assert_eq!(t.intencao_para(P1, q(30), pedido), None);
        assert!(!t.aberto_para(P1, q(20), pedido));
        assert!(t.coerente());
    }

    /// O motivo de fora é texto curto e imprimível.
    #[test]
    fn o_motivo_guardado() {
        assert_eq!(motivo_guardado("ok"), "ok");
        assert_eq!(motivo_guardado("\u{7}\n"), motivo::PROTOCOLO);
        assert_eq!(motivo_guardado(&"x".repeat(100)).len(), MAIOR_MOTIVO);
        assert!(metodo_remoto("stream.write") && !metodo_remoto("stream.read"));
    }
    /// NH12: a prontidão de uma ponta, para o aviso da malha — o dado e o
    /// fim não lido para quem lê, o espaço e o sentido abortado para quem
    /// escreve, nada no pedido, e o fim com quem já sabe e quem não sabe.
    #[test]
    fn nh12_a_prontidao_da_ponta() {
        use crate::aviso::bits::{FIM, GRAVAVEL, LEGIVEL};
        let mut t = Fluxos::nova();
        let id = t
            .abrir(P1, processo(10), 7, processo(20), "a.b", 0)
            .unwrap();
        // O pedido: nada, nem para quem abriu.
        assert_eq!(t.prontidao(q(10), id), Prontidao::Vivo(0));
        // Quem ainda não é ponta não vê nada.
        assert_eq!(t.prontidao(q(20), id), Prontidao::Vivo(0));
        t.aceitar(P1, 20, id, 0).unwrap();
        // Aberto: os dois podem escrever, ninguém tem o que ler.
        assert_eq!(t.prontidao(q(10), id), Prontidao::Vivo(GRAVAVEL));
        assert_eq!(t.prontidao(q(20), id), Prontidao::Vivo(GRAVAVEL));
        // O dado chega a quem lê; o buffer cheio tira o espaço de quem
        // escreve.
        let cheio = alloc::vec![7u8; BUFFER_DO_SENTIDO];
        assert_eq!(t.escrever(P1, q(10), id, &cheio, 1), Ok(BUFFER_DO_SENTIDO));
        assert_eq!(t.prontidao(q(10), id), Prontidao::Vivo(0));
        assert_eq!(t.prontidao(q(20), id), Prontidao::Vivo(LEGIVEL | GRAVAVEL));
        // A leitura abre espaço.
        t.ler(P1, q(20), id, 10, 2).unwrap();
        assert_eq!(t.prontidao(q(10), id), Prontidao::Vivo(GRAVAVEL));
        let _ = ler_tudo(&mut t, q(20), id);
        assert_eq!(t.prontidao(q(20), id), Prontidao::Vivo(GRAVAVEL));
        // O fim do sentido é legível até ser lido.
        t.terminar(P1, q(10), id, 3).unwrap();
        assert_eq!(t.prontidao(q(20), id), Prontidao::Vivo(LEGIVEL | GRAVAVEL));
        let (_, fim) = ler_tudo(&mut t, q(20), id);
        assert!(fim);
        assert_eq!(t.prontidao(q(20), id), Prontidao::Vivo(GRAVAVEL));
        // Quem fecha sai: já sabe. O outro lado tem o fim do que ele
        // escreveu para ler, e escreve num sentido abortado — o espaço
        // avisa, e a escrita dirá o motivo.
        let id2 = aberto(&mut t);
        t.fechar(P1, q(20), id2, 4).unwrap();
        assert_eq!(t.prontidao(q(20), id2), Prontidao::Acabou { ja_sabe: true });
        assert_eq!(t.prontidao(q(10), id2), Prontidao::Vivo(LEGIVEL | GRAVAVEL));
        // O aborto: os dois lados ficam sem saber até a operação.
        let id3 = aberto(&mut t);
        t.abortar(id3, motivo::REVOGADO);
        assert_eq!(
            t.prontidao(q(10), id3),
            Prontidao::Acabou { ja_sabe: false }
        );
        assert_eq!(
            t.prontidao(q(20), id3),
            Prontidao::Acabou { ja_sabe: false }
        );
        assert!(t.escrever(P1, q(10), id3, b"x", 5).is_err());
        assert_eq!(t.prontidao(q(10), id3), Prontidao::Acabou { ja_sabe: true });
        assert_eq!(
            t.prontidao(q(20), id3),
            Prontidao::Acabou { ja_sabe: false }
        );
        // Um id que nunca existiu: nada a dizer.
        assert_eq!(t.prontidao(q(10), 999), Prontidao::Acabou { ja_sabe: true });
        // O bit FIM não é da conta daqui: é o aviso que o diz.
        let _ = FIM;
    }
}
