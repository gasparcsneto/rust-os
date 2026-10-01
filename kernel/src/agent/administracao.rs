//! As operações administrativas, e a prova que cada uma exige.
//!
//! # A regra
//!
//! Uma operação administrativa — hoje, registrar um agente — não é um
//! comando como os outros. Ela não está em [`super::commands::COMANDOS`] e
//! não se chama pelo nome: chega embrulhada em `admin.execute`, com a prova
//! de um administrador para **aquele** pedido, naquela sessão, com aquele
//! desafio. Ver [`sigilo::administracao`] para o protocolo e para o que a
//! prova amarra.
//!
//! Vale em qualquer sessão, e é por isso que existe: a serial é aberta — é o
//! canal de emergência —, e o que se faz por ela sem prova não pode incluir
//! dar a uma chave o direito de entrar.
//!
//! # O caminho de um pedido
//!
//! 1. `admin.challenge` devolve um desafio: número, nonce, efêmera pública.
//! 2. O administrador calcula a prova sobre o comando e os parâmetros —
//!    **o texto exato** dos parâmetros, que vai como string e só é
//!    interpretado depois de a prova conferir.
//! 3. `admin.execute` tira o desafio (uma tentativa só), confere que a chave
//!    é de um administrador e que a prova confere, e executa.
//!
//! Qualquer falha é registrada no log com o motivo, e a resposta diz qual
//! foi: quem administra precisa saber se errou a prova ou o desafio venceu.

use core::fmt;

use super::json::{Json, JsonWriter};
use sigilo::administracao::{Contexto, conferir};

/// Uma operação administrativa: o nome e o que ela faz com os parâmetros.
struct Operacao {
    nome: &'static str,
    resumo: &'static str,
    executar: fn(Json, &mut JsonWriter) -> Result<(), &'static str>,
}

/// As operações que `admin.execute` aceita.
static OPERACOES: &[Operacao] = &[Operacao {
    nome: "agent.register",
    resumo: "Registra um agente: {\"key\": chave publica em hex, \"name\": nome}. Vale ate \
             o proximo boot.",
    executar: registrar_agente,
}];

/// Os nomes das operações, para o `agent.describe` e para o resumo.
pub fn operacoes() -> impl Iterator<Item = (&'static str, &'static str)> {
    OPERACOES.iter().map(|o| (o.nome, o.resumo))
}

/// Emite um desafio para a sessão do pedido: `admin.challenge`.
pub(crate) fn desafiar(w: &mut JsonWriter) -> fmt::Result {
    let sessao = super::sessao::atual();
    w.begin_object()?;
    match crate::identidade::desafiar(sessao) {
        Ok(d) => {
            w.field_u64("challenge", d.id)?;
            w.field_str("nonce", &sigilo::hex(&d.nonce))?;
            w.field_str("ephemeral", &sigilo::hex(&d.efemera))?;
            w.field_u64("session", u64::from(sessao))?;
            w.field_u64("valid_ms", crate::identidade::VALIDADE_DO_DESAFIO_MS)?;
        }
        Err(_) => w.field_str("error", "sem entropia: nenhum desafio pode ser emitido")?,
    }
    w.end_object()
}

/// O maior texto de parâmetros de uma operação.
pub const MAIORES_PARAMETROS: usize = 512;

/// Um pedido de `admin.execute`, com os campos já tirados do JSON — pelo
/// handler em [`super::commands`], que é onde os parâmetros de um comando
/// são lidos.
pub struct Pedido<'a> {
    pub desafio: Option<u64>,
    pub comando: Option<&'a str>,
    /// O texto dos parâmetros já desescapado: exatamente os bytes que a
    /// prova cobre.
    pub parametros: Option<&'a str>,
    pub administrador: Option<[u8; sigilo::TAM_CHAVE]>,
    pub prova: Option<[u8; 32]>,
}

/// Executa uma operação administrativa: `admin.execute`.
pub(crate) fn executar(pedido: Pedido, w: &mut JsonWriter) -> fmt::Result {
    let sessao = super::sessao::atual();
    w.begin_object()?;
    if let Err(motivo) = conferir_e_executar(sessao, pedido, w) {
        crate::log_warn!(
            "admin",
            "sessao {}: operacao administrativa recusada: {}",
            sessao,
            motivo
        );
        w.field_bool("executed", false)?;
        w.field_str("error", motivo)?;
    }
    w.end_object()
}

/// Confere tudo e executa. Um `Err` é o motivo da recusa.
fn conferir_e_executar(sessao: u8, pedido: Pedido, w: &mut JsonWriter) -> Result<(), &'static str> {
    let id = pedido.desafio.ok_or("falta o desafio")?;
    let comando = pedido.comando.ok_or("falta o comando")?;
    let parametros = pedido
        .parametros
        .ok_or("parametros ausentes, invalidos ou grandes demais")?;
    let administrador = pedido
        .administrador
        .ok_or("chave de administrador ausente ou invalida")?;
    let prova = pedido.prova.ok_or("prova ausente ou invalida")?;

    // O desafio sai primeiro, e sai de qualquer jeito: daqui para baixo,
    // errar qualquer coisa gasta a tentativa.
    let desafio = crate::identidade::consumir(sessao, id).map_err(|e| e.motivo())?;

    let Some(nome) = crate::identidade::administrador(&administrador) else {
        return Err("chave fora do registro de administradores");
    };

    let efemera = sigilo::publica_de(&desafio.efemera);
    let contexto = Contexto {
        nonce: &desafio.nonce,
        sessao,
        administrador: &administrador,
        efemera: &efemera,
        comando,
        parametros,
    };
    if !conferir(&desafio.efemera, &contexto, &prova) {
        return Err("a prova nao confere");
    }

    // Só agora o comando é procurado, e só agora os parâmetros são lidos:
    // até aqui eles eram bytes cobertos pela prova, e nada mais.
    let operacao = OPERACOES
        .iter()
        .find(|o| o.nome == comando)
        .ok_or("operacao administrativa desconhecida")?;
    // A operação escreve os campos dela só se der certo; os de cima vêm
    // depois, para uma recusa da operação não deixar um `executed` dizendo
    // o contrário na mesma resposta.
    (operacao.executar)(Json(parametros.as_bytes()), w)?;
    let _ = w.field_bool("executed", true);
    let _ = w.field_str("command", operacao.nome);
    let _ = w.field_str("by", &nome);
    crate::log_info!(
        "admin",
        "sessao {}: {} executou {}",
        sessao,
        nome,
        operacao.nome
    );
    Ok(())
}

fn registrar_agente(params: Json, w: &mut JsonWriter) -> Result<(), &'static str> {
    let chave = params
        .member("key")
        .and_then(|v| v.as_str())
        .and_then(sigilo::de_hex)
        .ok_or("falta a chave do agente, em hex")?;
    let nome = params
        .member("name")
        .and_then(|v| v.as_str())
        .ok_or("falta o nome do agente")?;
    crate::identidade::registrar(chave, nome).map_err(|r| r.motivo())?;
    crate::log_info!(
        "admin",
        "agente {} registrado ({})",
        nome,
        crate::identidade::impressao(&chave)
    );
    let _ = w.field_str("agent", nome);
    let _ = w.field_str("key", &sigilo::hex(&chave));
    Ok(())
}
