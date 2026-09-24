//! Envelope JSON-RPC 2.0 do canal do agente.
//!
//! # Por que JSON-RPC 2.0 e não um protocolo próprio
//!
//! Poderíamos inventar um formato binário mais compacto. Não é o objetivo:
//! o ponto deste canal é que um agente consiga operar o OS *sem precisar de
//! um cliente especial*. JSON-RPC 2.0 é uma especificação pública, estável e
//! amplamente implementada — qualquer ferramenta, e qualquer modelo de
//! linguagem, já sabe falá-la sem instrução adicional.
//!
//! # Enquadramento
//!
//! Uma requisição por linha, uma resposta por linha (NDJSON). Um `\n` delimita
//! cada quadro, o que permite ao cliente ler respostas sem precisar contar
//! chaves para achar onde o objeto termina.
//!
//! # Idioma
//!
//! Comentários e identificadores deste projeto são em português, mas as
//! **chaves do protocolo são em inglês** (`method`, `params`, `result`). Elas
//! fazem parte de um contrato externo padronizado; traduzi-las quebraria a
//! compatibilidade com qualquer cliente JSON-RPC existente.

use core::fmt;

use super::json::{Json, JsonWriter};

/// Versão do protocolo, obrigatória em todo envelope.
pub const VERSAO: &str = "2.0";

/// Um erro a ser reportado ao cliente.
#[derive(Clone, Copy, Debug)]
pub struct RpcError {
    pub codigo: i32,
    pub mensagem: &'static str,
}

impl RpcError {
    // Os códigos de -32768 a -32000 são reservados pela especificação
    // JSON-RPC 2.0. Usamos os valores padrão para os erros previstos por ela,
    // e a faixa -32000+ para erros específicos deste kernel.

    pub const PARSE: Self = Self {
        codigo: -32700,
        mensagem: "JSON malformado",
    };
    pub const REQUISICAO_INVALIDA: Self = Self {
        codigo: -32600,
        mensagem: "requisicao JSON-RPC invalida",
    };
    pub const METODO_NAO_ENCONTRADO: Self = Self {
        codigo: -32601,
        mensagem: "metodo nao encontrado",
    };
    pub const PARAMS_INVALIDOS: Self = Self {
        codigo: -32602,
        mensagem: "parametros invalidos",
    };
    pub const LINHA_MUITO_LONGA: Self = Self {
        codigo: -32000,
        mensagem: "requisicao excede o buffer de linha do kernel",
    };
    /// Bytes desta requisição não couberam na fila de entrada.
    ///
    /// # O que o agente precisa fazer com isto
    ///
    /// Reenviar **esta** requisição, e só ela. As que vierem depois não são
    /// afetadas.
    ///
    /// Essa garantia não é de graça, e por um tempo não existiu. A perda
    /// acontece quando o handler lê a serial mais rápido do que a tarefa
    /// consome, e o byte que sobra é descartado. O delimitador é o **último**
    /// byte de cada requisição, ou seja, exatamente o que chega quando a fila
    /// está mais cheia — então era ele que se perdia, o quadro danificado
    /// colava no seguinte, e a requisição seguinte era consumida na
    /// ressincronização. Medido no ARM: dois de cada três despejos.
    ///
    /// O conserto está em [`crate::tarefas::entrada::coletar`], e a chave é
    /// que a perda acontece **dentro** do kernel: o handler enxerga todo byte
    /// que chega, só não consegue guardar todos. Enxergando, ele sabe onde a
    /// requisição atropelada terminou e repõe o `\n` numa vaga que os bytes
    /// comuns nunca tomam.
    ///
    pub const ENTRADA_PERDIDA: Self = Self {
        codigo: -32001,
        mensagem: "bytes perdidos no caminho; a requisicao foi descartada",
    };
}

/// Uma requisição já decomposta, com todos os campos emprestando da linha
/// original — nenhuma cópia, nenhuma alocação.
pub struct Requisicao<'a> {
    /// O `id` bruto, preservado para ser ecoado de volta com o mesmo tipo.
    pub id: Option<Json<'a>>,
    pub metodo: &'a str,
    pub params: Json<'a>,
}

impl<'a> Requisicao<'a> {
    /// Decompõe uma linha.
    ///
    /// Em caso de erro devolve também o `id`, quando ele foi legível: a
    /// especificação exige que a resposta de erro ecoe o `id` do pedido, e um
    /// cliente que enviou várias requisições precisa dele para saber qual
    /// delas falhou.
    pub fn parse(linha: &'a [u8]) -> Result<Self, (Option<Json<'a>>, RpcError)> {
        let raiz = Json(linha);

        // Se nem o objeto externo é válido, não há id a recuperar.
        if raiz.member("jsonrpc").is_none() && raiz.member("method").is_none() {
            return Err((None, RpcError::PARSE));
        }

        // O `id` é ecoado **cru** na resposta, byte a byte, porque o
        // JSON-RPC exige que ele volte idêntico — com o mesmo tipo e a mesma
        // grafia. Isso faz da conferência aqui a única coisa entre o que o
        // cliente escreveu e o que sai pela porta: sem ela, um `id` que a
        // varredura aceitou mas que não é JSON (`abc`, `1e`, um byte de
        // controle dentro das aspas) ia inteiro para dentro de uma resposta
        // nossa, e a resposta deixava de ser legível.
        //
        // O estrago era pior do que parece. O comando **executava**: o
        // trabalho era feito e a resposta entregue num formato que o cliente
        // não consegue ler nem atribuir ao pedido que a causou. Recusar o
        // pedido inteiro é o que a especificação manda (§4: o `id` só pode
        // ser String, Number ou Null) e é também o que informa o agente.
        let id = raiz.member("id").filter(|j| !j.is_null());
        // Sem id utilizável não há o que ecoar: a resposta de erro leva
        // `null`, como a especificação manda para um pedido inválido.
        if id.is_some_and(|id| !id.e_string_ecoavel() && !id.e_numero()) {
            return Err((None, RpcError::REQUISICAO_INVALIDA));
        }

        let Some(metodo) = raiz.member("method").and_then(|m| m.as_str()) else {
            return Err((id, RpcError::REQUISICAO_INVALIDA));
        };

        // `params` é opcional na especificação. Um objeto vazio como padrão
        // deixa os handlers uniformes: todos consultam `params.member(...)`
        // sem precisar tratar o caso ausente.
        let params = raiz.member("params").unwrap_or(Json(b"{}"));

        Ok(Self { id, metodo, params })
    }
}

/// Escreve `{"jsonrpc":"2.0","id":…,"result":<corpo>}`.
///
/// O corpo é produzido por uma closure porque a escrita é em streaming: o
/// valor de `result` precisa ser emitido exatamente no ponto certo da
/// sequência, entre a chave `"result"` e o fechamento do envelope.
pub fn envelope_ok(
    w: &mut JsonWriter,
    id: Option<Json>,
    corpo: impl FnOnce(&mut JsonWriter) -> fmt::Result,
) -> fmt::Result {
    w.begin_object()?;
    w.field_str("jsonrpc", VERSAO)?;
    w.key("id")?;
    escrever_id(w, id)?;
    w.key("result")?;
    corpo(w)?;
    w.end_object()
}

/// Escreve `{"jsonrpc":"2.0","id":…,"error":{…}}`.
pub fn envelope_erro(
    w: &mut JsonWriter,
    id: Option<Json>,
    erro: RpcError,
    detalhe: Option<&str>,
) -> fmt::Result {
    w.begin_object()?;
    w.field_str("jsonrpc", VERSAO)?;
    w.key("id")?;
    escrever_id(w, id)?;
    w.key("error")?;
    w.begin_object()?;
    w.key("code")?;
    w.i64_value(erro.codigo as i64)?;
    w.field_str("message", erro.mensagem)?;
    if let Some(detalhe) = detalhe {
        w.field_str("data", detalhe)?;
    }
    w.end_object()?;
    w.end_object()
}

/// Ecoa o `id` exatamente como veio, ou `null` se não havia um.
fn escrever_id(w: &mut JsonWriter, id: Option<Json>) -> fmt::Result {
    match id.and_then(|j| j.raw_str()) {
        Some(bruto) => w.raw_value(bruto),
        None => w.null_value(),
    }
}
