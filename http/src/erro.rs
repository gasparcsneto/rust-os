//! Por que uma troca HTTP não terminou com uma resposta.
//!
//! Quatro famílias que não se confundem:
//!
//! - **a de baixo** ([`Erro::Baixo`]): o transporte falhou — o gate recusou
//!   um `net.recv`, o firewall barrou, o TLS não conferiu, o par não
//!   respondeu no prazo. A falha passa como veio, com o código de quem a
//!   deu: o HTTP não a traduz, e não a esconde atrás de um código dele;
//! - **a conexão que acabou cedo** ([`Erro::Fechada`]): o servidor fechou
//!   antes de a resposta estar inteira — sem resposta nenhuma, no meio dos
//!   cabeçalhos, ou antes do fim que o corpo prometia. O que chegou não é
//!   entregue: uma resposta cortada não é uma resposta;
//! - **o protocolo** ([`Erro::Protocolo`]): o que chegou não é HTTP/1.1, ou
//!   é ambíguo de um jeito que deixaria cliente e servidor lerem coisas
//!   diferentes;
//! - **os limites** ([`Erro::Limite`]): uma linha, os cabeçalhos ou o
//!   corpo passaram do que quem chama aceita. O cliente para de ler ali, e
//!   a memória não cresce na vontade do servidor.
//!
//! Nenhuma delas vira resposta. Um status de erro do servidor — um 404, um
//! 500 — não está aqui: é uma resposta, o protocolo funcionou.

/// Por que o que chegou não é uma resposta HTTP/1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Motivo {
    /// Uma linha que não acaba em CRLF: um LF sozinho, ou um CR no meio.
    FimDeLinha,
    /// A versão não é `HTTP/1.0` nem `HTTP/1.1`.
    Versao,
    /// A linha de status não tem a forma da RFC 9112.
    LinhaDeStatus,
    /// O status não está entre 100 e 599.
    Status,
    /// `101 Switching Protocols`: o cliente não troca de protocolo.
    Troca,
    /// Respostas informativas (1xx) demais antes da final.
    Informativas,
    /// Um cabeçalho sem nome, sem dois-pontos, com espaço antes deles, com
    /// um byte de controle no valor.
    Cabecalho,
    /// Um cabeçalho dobrado em várias linhas (`obs-fold`): a RFC 9112
    /// manda recusar.
    Dobra,
    /// `Content-Length` que não é um número, ou dois que não concordam.
    Tamanho,
    /// Um `Transfer-Encoding` que não é só `chunked`.
    Codificacao,
    /// `Transfer-Encoding` e `Content-Length` juntos: cada lado poderia
    /// delimitar o corpo por um.
    Ambiguo,
    /// Um pedaço (`chunked`) malformado: o tamanho não é hexadecimal, ou o
    /// dado não acaba em CRLF.
    Pedaco,
}

impl Motivo {
    pub const fn nome(self) -> &'static str {
        match self {
            Motivo::FimDeLinha => "line-ending",
            Motivo::Versao => "version",
            Motivo::LinhaDeStatus => "status-line",
            Motivo::Status => "status-code",
            Motivo::Troca => "protocol-switch",
            Motivo::Informativas => "too-many-informational",
            Motivo::Cabecalho => "header",
            Motivo::Dobra => "folded-header",
            Motivo::Tamanho => "content-length",
            Motivo::Codificacao => "transfer-encoding",
            Motivo::Ambiguo => "ambiguous-framing",
            Motivo::Pedaco => "chunk",
        }
    }
}

/// Que limite a resposta passou — ver [`crate::Limites`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limite {
    /// Uma linha: a de status, um cabeçalho, o tamanho de um pedaço.
    Linha,
    /// A cabeça inteira: status e cabeçalhos — ou os *trailers*.
    Cabeca,
    /// Cabeçalhos demais.
    Cabecalhos,
    /// O corpo.
    Corpo,
}

impl Limite {
    pub const fn nome(self) -> &'static str {
        match self {
            Limite::Linha => "line",
            Limite::Cabeca => "head",
            Limite::Cabecalhos => "headers",
            Limite::Corpo => "body",
        }
    }
}

/// Por que uma troca HTTP não terminou com uma resposta — ver o cabeçalho
/// do módulo. `F` é a falha do transporte de quem chama.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro<F> {
    /// O transporte falhou, com a falha dele.
    Baixo(F),
    /// O servidor fechou antes de a resposta estar inteira.
    Fechada,
    /// O que chegou não é uma resposta HTTP/1.1.
    Protocolo(Motivo),
    /// A resposta passou de um limite.
    Limite(Limite),
    /// A conexão não leva mais pedidos: a resposta anterior a fechou, não
    /// tinha fim certo, ou a troca falhou no meio.
    Esgotada,
}

impl<F> Erro<F> {
    /// O código, para quem conta as falhas do HTTP. A de baixo não tem:
    /// é de quem implementa o transporte dizer.
    pub const fn codigo(&self) -> Option<&'static str> {
        match self {
            Erro::Baixo(_) => None,
            Erro::Fechada => Some("HTTP_CLOSED"),
            Erro::Protocolo(_) => Some("HTTP_MALFORMED"),
            Erro::Limite(_) => Some("HTTP_TOO_LARGE"),
            Erro::Esgotada => Some("HTTP_CONNECTION_SPENT"),
        }
    }
}
