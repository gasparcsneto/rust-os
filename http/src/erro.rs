//! Por que uma troca HTTP não terminou com uma resposta.
//!
//! Seis famílias que não se confundem:
//!
//! - **a de baixo** ([`Erro::Baixo`]): o transporte falhou — o gate recusou
//!   um `net.recv`, o firewall barrou, o TLS não conferiu, o par não
//!   respondeu no prazo. A falha passa como veio, com o código de quem a
//!   deu: o HTTP não a traduz, e não a esconde atrás de um código dele;
//! - **a conexão que acabou cedo** ([`Erro::Fechada`]): o servidor fechou
//!   antes de a resposta estar inteira — sem resposta nenhuma, no meio dos
//!   cabeçalhos, ou antes do fim que o corpo prometia. O que chegou não é
//!   entregue: uma resposta cortada não é uma resposta;
//! - **a corrente que o servidor largou**, no HTTP/2 ([`Erro::Reiniciada`],
//!   [`Erro::Recusada`], [`Erro::Encerrada`]): o servidor reiniciou a
//!   corrente, não chegou a processá-la, ou encerrou a conexão com um erro
//!   antes da resposta. Como a conexão que acabou cedo, o que chegou não é
//!   entregue — e a recusada pode ir noutra conexão, porque o servidor diz
//!   que não fez nada com ela;
//! - **o protocolo** ([`Erro::Protocolo`]): o que chegou não é HTTP/1.1 nem
//!   HTTP/2, ou é ambíguo de um jeito que deixaria cliente e servidor lerem
//!   coisas diferentes;
//! - **os limites** ([`Erro::Limite`]): uma linha, os cabeçalhos, o
//!   corpo ou o corpo decodificado passaram do que quem chama aceita. O
//!   cliente para de ler — ou de decodificar — ali, e a memória não cresce
//!   na vontade do servidor;
//! - **o conteúdo** ([`Erro::Conteudo`]): a mensagem chegou inteira, e o
//!   corpo veio numa codificação que o pedido não aceitou, ou comprimido de
//!   um jeito que não se decodifica — cortado, corrompido, com a soma
//!   errada. O que saiu do decodificador não é entregue.
//!
//! Nenhuma delas vira resposta. Um status de erro do servidor — um 404, um
//! 500 — não está aqui: é uma resposta, o protocolo funcionou.

use crate::quadro::CodigoH2;

/// Por que o que chegou não é uma resposta HTTP/1.1 ou HTTP/2.
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
    /// HTTP/2: o servidor não começou com o prefácio dele — um `SETTINGS`.
    /// Um servidor que só fala HTTP/1.1 cai aqui.
    Prefacio,
    /// HTTP/2: um quadro que a RFC 9113 recusa — o tamanho, a corrente
    /// zero onde não pode, o preenchimento, um ajuste fora da faixa, um
    /// quadro no meio de um bloco de cabeça, uma corrente que o servidor não
    /// pode abrir.
    Quadro,
    /// HTTP/2: o bloco de cabeça não se decodifica (HPACK). A tabela
    /// dinâmica fica sem saber o que é, e a conexão inteira acaba.
    Compressao,
    /// HTTP/2: o controle de fluxo — o servidor mandou além da janela, ou
    /// passou do maior tamanho de uma.
    Janela,
    /// HTTP/2: um quadro numa corrente que já acabou.
    Corrente,
    /// HTTP/2: a mensagem malformada (RFC 9113, 8.1.1) — sem `:status`, um
    /// pseudo-cabeçalho onde não pode, um cabeçalho da conexão
    /// (`Connection`, `Transfer-Encoding`...), dados antes da cabeça, uma
    /// informativa que acaba a corrente, *trailers* que não a acabam.
    Mensagem,
    /// HTTP/2: um `PUSH_PROMISE`, que este cliente desliga no prefácio.
    Empurrado,
}

/// Por que o corpo codificado não se decodifica — ver
/// [`crate::Codificacao`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Defeito {
    /// Uma codificação que o pedido não aceitou, uma que o cliente não
    /// conhece, ou mais de uma empilhada.
    Codificacao,
    /// O invólucro não confere: a assinatura do gzip, o método, um bit
    /// reservado, o `FCHECK` do zlib, o dicionário preestabelecido.
    Cabecalho,
    /// O DEFLATE não se decodifica: um bloco, um código, uma distância.
    Dados,
    /// O corpo acabou antes do fim do fluxo comprimido.
    Cortado,
    /// Uma soma não confere — o CRC-32 do gzip, o da cabeça dele, o
    /// Adler-32 do zlib —, ou o tamanho que o gzip guarda.
    Soma,
    /// Bytes depois do fim do fluxo.
    Sobra,
}

impl Defeito {
    pub const fn nome(self) -> &'static str {
        match self {
            Defeito::Codificacao => "unaccepted-coding",
            Defeito::Cabecalho => "coding-header",
            Defeito::Dados => "corrupt-data",
            Defeito::Cortado => "truncated",
            Defeito::Soma => "checksum",
            Defeito::Sobra => "trailing-data",
        }
    }
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
            Motivo::Prefacio => "preface",
            Motivo::Quadro => "frame",
            Motivo::Compressao => "hpack",
            Motivo::Janela => "flow-control",
            Motivo::Corrente => "stream-state",
            Motivo::Mensagem => "message",
            Motivo::Empurrado => "push",
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
    /// O corpo, como veio.
    Corpo,
    /// O corpo decodificado: o que sai do decodificador.
    Descomprimido,
    /// HTTP/2: correntes abertas demais na conexão — as deste lado, ou as
    /// que o servidor aceita.
    Correntes,
    /// HTTP/2: quadros demais sem levar a resposta adiante — `PING`,
    /// `SETTINGS`, quadros vazios ou desconhecidos, `CONTINUATION` sem fim.
    Quadros,
}

impl Limite {
    pub const fn nome(self) -> &'static str {
        match self {
            Limite::Linha => "line",
            Limite::Cabeca => "head",
            Limite::Cabecalhos => "headers",
            Limite::Corpo => "body",
            Limite::Descomprimido => "decoded-body",
            Limite::Correntes => "streams",
            Limite::Quadros => "frames",
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
    /// O corpo não se decodifica.
    Conteudo(Defeito),
    /// HTTP/2: o servidor reiniciou a corrente (`RST_STREAM`) antes de a
    /// resposta estar inteira, com este código.
    Reiniciada(CodigoH2),
    /// HTTP/2: o servidor não processou o pedido — `REFUSED_STREAM`, ou uma
    /// corrente acima da última que o `GOAWAY` dele diz ter processado. O
    /// pedido pode ir noutra conexão.
    Recusada,
    /// HTTP/2: o servidor encerrou a conexão (`GOAWAY`) com este erro antes
    /// de a resposta estar inteira.
    Encerrada(CodigoH2),
}

impl<F> Erro<F> {
    /// O código, para quem conta as falhas do HTTP. A de baixo não tem:
    /// é de quem implementa o transporte dizer.
    pub const fn codigo(&self) -> Option<&'static str> {
        match self {
            Erro::Baixo(_) => None,
            Erro::Fechada => Some("HTTP_CLOSED"),
            Erro::Protocolo(_) => Some("HTTP_MALFORMED"),
            Erro::Limite(Limite::Correntes) => Some("HTTP_TOO_MANY_STREAMS"),
            Erro::Limite(Limite::Quadros) => Some("HTTP_TOO_MANY_FRAMES"),
            Erro::Limite(_) => Some("HTTP_TOO_LARGE"),
            Erro::Esgotada => Some("HTTP_CONNECTION_SPENT"),
            Erro::Conteudo(Defeito::Codificacao) => Some("HTTP_UNACCEPTED_ENCODING"),
            Erro::Conteudo(_) => Some("HTTP_CORRUPT_CONTENT"),
            Erro::Reiniciada(_) => Some("HTTP_STREAM_RESET"),
            Erro::Recusada => Some("HTTP_STREAM_REFUSED"),
            Erro::Encerrada(_) => Some("HTTP_CONNECTION_ENDED"),
        }
    }
}
