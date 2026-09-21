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

        let id = raiz.member("id").filter(|j| !j.is_null());

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
