//! As operações administrativas, e a prova que cada uma exige.
//!
//! # A regra
//!
//! Uma operação administrativa — registrar e revogar um agente, atribuir um
//! papel, mudar a política, registrar e revogar uma pessoa, trocar a
//! credencial dela, encerrar uma sessão de pessoa, revogar um arrendamento
//! — não é um comando como os outros. Ela não está
//! em [`super::commands::COMANDOS`] e não se chama pelo nome: chega
//! embrulhada em `admin.execute`, com a prova de um administrador para
//! **aquele** pedido, naquela sessão, com aquele desafio. Ver
//! [`sigilo::administracao`] para o protocolo e para o que a prova amarra.
//!
//! Vale em qualquer sessão, e é por isso que existe: a serial é aberta — é o
//! canal de emergência —, e o que se faz por ela sem prova não pode incluir
//! dar a uma chave o direito de entrar.
//!
//! # Prova e papel, os dois
//!
//! A prova diz **quem** pede; o papel do administrador, na política, diz se
//! ele pode **isto**. Uma permissão administrativa num papel nunca substitui
//! a prova: não há outro caminho até [`OPERACOES`] além deste arquivo, e
//! aqui a prova vem primeiro. E a prova não substitui o papel: um
//! administrador cujo papel não tem `policy.write` não muda a política.
//!
//! # Ninguém se dá mais do que tem
//!
//! O papel do administrador é o **teto** do que ele concede:
//!
//! - registra e atribui só papéis que cabem no dele, e só mexe em agentes
//!   cujo papel de agora também cabe — não rebaixa nem revoga quem pode mais
//!   que ele;
//! - não muda o papel da sessão de onde pede, nem revoga a chave dela;
//! - não registra como agente uma chave de administrador;
//! - não edita o próprio papel, nem os dos outros administradores, nem o da
//!   sessão de onde pede — ver [`politica::Politica::com_linha`].
//!
//! # O caminho de um pedido
//!
//! 1. `admin.challenge` devolve um desafio: número, nonce, efêmera pública.
//! 2. O administrador calcula a prova sobre o comando e os parâmetros —
//!    **o texto exato** dos parâmetros, que vai como string e só é
//!    interpretado depois de a prova conferir.
//! 3. `admin.execute` tira o desafio (uma tentativa só), confere que a chave
//!    é de um administrador e que a prova confere, decide pelo papel dele, e
//!    executa.
//!
//! Cada desfecho vai para a auditoria, com o código — e a resposta diz qual
//! foi: quem administra precisa saber se errou a prova, se o papel não deixa,
//! ou se a política recusou a mudança.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use politica::{Codigo, Permissao, Recusa};

use super::json::{Json, JsonWriter};
use crate::autorizacao;
use sigilo::administracao::{Contexto, conferir};

/// Quem pede uma operação, já com a prova conferida.
struct Pedinte<'a> {
    sessao: u8,
    nome: &'a str,
    /// O papel do administrador: o teto do que ele concede.
    papel: &'a str,
    /// A chave do agente na sessão de onde o pedido veio — nenhuma na
    /// serial. É o "si mesmo" das regras de não-autoprivilegiamento.
    chave_da_sessao: Option<[u8; sigilo::TAM_CHAVE]>,
    /// A chave do administrador que provou: o titular das mensagens dele,
    /// que nunca abre sessão.
    administrador: [u8; sigilo::TAM_CHAVE],
    /// O destinatário de um `message.send`, como a decisão o resolveu — com
    /// o papel do administrador.
    destino: Option<crate::mensagens::Destino>,
}

/// Por que uma operação não foi feita: o código da auditoria e o motivo.
type Falha = (Codigo, String);

fn falha(codigo: Codigo, motivo: impl Into<String>) -> Falha {
    (codigo, motivo.into())
}

/// Uma operação administrativa: o nome, a permissão que o papel do
/// administrador precisa ter, e o que ela faz com os parâmetros. Devolve o
/// recurso, para a auditoria.
struct Operacao {
    nome: &'static str,
    resumo: &'static str,
    permissao: Permissao,
    executar: fn(&Pedinte, Json, &mut JsonWriter) -> Result<String, Falha>,
}

/// As operações que `admin.execute` aceita.
static OPERACOES: &[Operacao] = &[
    Operacao {
        nome: "agent.register",
        resumo: "Registra um agente: {\"key\": chave publica em hex, \"name\": nome, \"role\": \
                 papel}. O papel cabe no do administrador. Vale ate o proximo boot.",
        permissao: Permissao::AgentRegister,
        executar: registrar_agente,
    },
    Operacao {
        nome: "agent.revoke",
        resumo: "Revoga um agente: {\"key\": chave publica em hex}. As sessoes abertas com a \
                 chave sao encerradas na hora. Nao vale para a chave da propria sessao.",
        permissao: Permissao::AgentRevoke,
        executar: revogar_agente,
    },
    Operacao {
        nome: "policy.assign",
        resumo: "Atribui um papel: {\"agent\": nome, ou \"serial\", \"role\": papel}. O papel \
                 novo e o de agora cabem no do administrador; nao vale para a propria sessao.",
        permissao: Permissao::PolicyAssign,
        executar: atribuir_papel,
    },
    Operacao {
        nome: "policy.write",
        resumo: "Muda uma linha da politica em memoria: {\"line\": \"papel ...\", \"recurso ...\" \
                 ou \"taxa ...\"}. Validada como o arquivo; vale na decisao seguinte; o disco \
                 nao muda.",
        permissao: Permissao::PolicyWrite,
        executar: escrever_politica,
    },
    Operacao {
        nome: "person.register",
        resumo: "Registra uma pessoa: {\"name\": nome, \"role\": papel, \"credential\": \
                 \"argon2id:m=..,t=..,p=1:<sal>:<verificador>\"}. O verificador e calculado \
                 fora: a senha nunca vem. O papel cabe no do administrador. Devolve o \
                 identificador. Vale ate o proximo boot.",
        permissao: Permissao::PersonRegister,
        executar: registrar_pessoa,
    },
    Operacao {
        nome: "person.revoke",
        resumo: "Revoga uma pessoa: {\"person\": \"pessoa:<16 hex>\"}. Ela nao entra mais, e \
                 as sessoes dela acabam na hora; o registro fica, com o estado revogada.",
        permissao: Permissao::PersonRevoke,
        executar: revogar_pessoa,
    },
    Operacao {
        nome: "credential.rotate",
        resumo: "Troca a credencial de uma pessoa: {\"person\": identificador, \"credential\": \
                 verificador como no registro}. A pessoa e a mesma; as sessoes continuam.",
        permissao: Permissao::CredentialRotate,
        executar: rotacionar_credencial,
    },
    Operacao {
        nome: "session.revoke",
        resumo: "Encerra uma sessao de pessoa: {\"session\": 16 hex}. A pessoa continua \
                 registrada e pode entrar de novo.",
        permissao: Permissao::SessionRevoke,
        executar: revogar_sessao,
    },
    Operacao {
        nome: "lease.revoke",
        resumo: "Revoga o arrendamento de um campo, de quem for: {\"id\": o id do campo em \
                 ui.tree}. A unica forma de quebrar o arrendamento de outro.",
        permissao: Permissao::LeaseRevoke,
        executar: revogar_arrendamento,
    },
    Operacao {
        nome: "message.send",
        resumo: "Manda uma mensagem como o administrador: {\"to\", \"body\", \"nonce\", \
                 \"ttl_ms\"?}, como `message.send`. O alcance e o do papel do administrador; \
                 a chave dele nunca abre sessao.",
        permissao: Permissao::MessageSend,
        executar: mandar_mensagem,
    },
    Operacao {
        nome: "message.read",
        resumo: "Le a caixa do administrador: {\"after\"?, \"max\"?}, como `message.read`.",
        permissao: Permissao::MessageRead,
        executar: ler_mensagens,
    },
    Operacao {
        nome: "message.ack",
        resumo: "Confirma uma mensagem da caixa do administrador: {\"id\", \
                 \"expect_version\"?}.",
        permissao: Permissao::MessageRead,
        executar: confirmar_mensagem,
    },
    Operacao {
        nome: "message.purge",
        resumo: "Tira uma mensagem viva, de quem for: {\"id\"}. Fica a lapide, e a \
                 auditoria.",
        permissao: Permissao::MessagePurge,
        executar: purgar_mensagem,
    },
];

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
    if let Err((codigo, motivo)) = conferir_e_executar(sessao, pedido, w) {
        crate::log_warn!(
            "admin",
            "sessao {}: operacao administrativa recusada: {} ({})",
            sessao,
            motivo,
            codigo.nome()
        );
        w.field_bool("executed", false)?;
        w.field_str("code", codigo.nome())?;
        w.field_str("error", &motivo)?;
    }
    w.end_object()
}

/// Confere tudo, decide e executa. Um `Err` é a recusa, já auditada.
fn conferir_e_executar(sessao: u8, pedido: Pedido, w: &mut JsonWriter) -> Result<(), Falha> {
    let bytes = pedido.parametros.unwrap_or("").as_bytes();
    let metodo = pedido.comando.unwrap_or("admin.execute");
    // Uma recusa antes de se saber quem é o administrador: a auditoria grava
    // a chave que veio, se veio, e o nome vazio.
    let recusar_anonimo = |codigo: Codigo, motivo: &str| -> Falha {
        let chave = pedido.administrador.unwrap_or([0; 32]);
        let administrador = pedido.administrador.map(|_| ("", &chave));
        autorizacao::auditar_administracao(
            sessao,
            administrador,
            None,
            metodo,
            "",
            codigo,
            bytes,
            motivo,
        );
        falha(codigo, motivo)
    };

    let Some(id) = pedido.desafio else {
        return Err(recusar_anonimo(Codigo::InvalidArgument, "falta o desafio"));
    };
    let Some(comando) = pedido.comando else {
        return Err(recusar_anonimo(Codigo::InvalidArgument, "falta o comando"));
    };
    let Some(parametros) = pedido.parametros else {
        return Err(recusar_anonimo(
            Codigo::InvalidArgument,
            "parametros ausentes, invalidos ou grandes demais",
        ));
    };
    let Some(administrador) = pedido.administrador else {
        return Err(recusar_anonimo(
            Codigo::InvalidArgument,
            "chave de administrador ausente ou invalida",
        ));
    };
    let Some(prova) = pedido.prova else {
        return Err(recusar_anonimo(
            Codigo::InvalidArgument,
            "prova ausente ou invalida",
        ));
    };

    // O desafio sai primeiro, e sai de qualquer jeito: daqui para baixo,
    // errar qualquer coisa gasta a tentativa.
    let desafio = match crate::identidade::consumir(sessao, id) {
        Ok(d) => d,
        Err(e) => return Err(recusar_anonimo(Codigo::DenyNotAuthenticated, e.motivo())),
    };

    let Some((nome, papel)) = crate::identidade::papel_do_administrador(&administrador) else {
        return Err(recusar_anonimo(
            Codigo::DenyNotAuthenticated,
            "chave fora do registro de administradores",
        ));
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
    // A partir daqui a auditoria grava o administrador pelo nome.
    let gravar = |codigo: Codigo, recurso: &str, motivo: &str| {
        autorizacao::auditar_administracao(
            sessao,
            Some((&nome, &administrador)),
            papel.as_deref(),
            comando,
            recurso,
            codigo,
            bytes,
            motivo,
        );
    };
    if !conferir(&desafio.efemera, &contexto, &prova) {
        gravar(Codigo::DenyNotAuthenticated, "", "a prova nao confere");
        return Err(falha(Codigo::DenyNotAuthenticated, "a prova nao confere"));
    }

    // Só agora o comando é procurado, e só agora os parâmetros são lidos:
    // até aqui eles eram bytes cobertos pela prova, e nada mais.
    let Some(operacao) = OPERACOES.iter().find(|o| o.nome == comando) else {
        gravar(
            Codigo::InvalidArgument,
            "",
            "operacao administrativa desconhecida",
        );
        return Err(falha(
            Codigo::InvalidArgument,
            "operacao administrativa desconhecida",
        ));
    };

    // A prova disse quem; a política diz se o papel dele pode isto. A
    // permissão de destino tem o recurso nos parâmetros: o papel primeiro,
    // e o destinatário logo abaixo.
    let decisao = if operacao.permissao.recurso_e_destino() {
        autorizacao::papel_tem(papel.as_deref(), operacao.permissao)
    } else {
        autorizacao::decidir_administracao(papel.as_deref(), operacao.permissao)
    };
    let papel = match (decisao, papel.as_deref()) {
        (Codigo::Allow, Some(papel)) => papel,
        (Codigo::DenyRole, _) | (_, None) => {
            let motivo = "administrador sem papel, ou papel que a politica nao tem";
            gravar(Codigo::DenyRole, "", motivo);
            return Err(falha(Codigo::DenyRole, motivo));
        }
        (codigo, Some(_)) => {
            let motivo = "o papel do administrador nao tem a permissao";
            gravar(codigo, "", motivo);
            return Err(falha(codigo, motivo));
        }
    };

    // O destinatário, pelo mesmo `decidir_destino` da sessão, com o papel do
    // administrador: o alcance dele, enumerado como o de todos.
    let mut destino = None;
    if operacao.permissao.recurso_e_destino() {
        let alvo = Json(parametros.as_bytes())
            .member("to")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let (codigo, motivo, resolvido) =
            autorizacao::decidir_destino(Some(papel), operacao.permissao, alvo);
        if !codigo.permite() {
            gravar(codigo, alvo, motivo);
            return Err(falha(codigo, motivo));
        }
        destino = resolvido;
    }

    let pedinte = Pedinte {
        sessao,
        nome: &nome,
        papel,
        chave_da_sessao: crate::sessoes::identidade(sessao).map(|id| id.chave),
        administrador,
        destino,
    };

    // A operação escreve os campos dela só se der certo; os de cima vêm
    // depois, para uma recusa da operação não deixar um `executed` dizendo
    // o contrário na mesma resposta.
    match (operacao.executar)(&pedinte, Json(parametros.as_bytes()), w) {
        Ok(recurso) => {
            gravar(Codigo::Allow, &recurso, "prova conferida; executada");
            autorizacao::contar_administracao(&nome, papel, operacao.nome, operacao.permissao);
            let _ = w.field_bool("executed", true);
            let _ = w.field_str("command", operacao.nome);
            let _ = w.field_str("by", &nome);
            crate::log_info!(
                "admin",
                "sessao {}: {} executou {} ({})",
                sessao,
                nome,
                operacao.nome,
                recurso
            );
            Ok(())
        }
        Err((codigo, motivo)) => {
            gravar(codigo, "", &motivo);
            Err((codigo, motivo))
        }
    }
}

/// Um parâmetro de texto obrigatório.
fn texto<'a>(params: Json<'a>, nome: &str) -> Result<&'a str, Falha> {
    params
        .member(nome)
        .and_then(|v| v.as_str())
        .ok_or_else(|| falha(Codigo::InvalidArgument, format!("falta `{nome}`")))
}

/// Uma chave pública em hex, obrigatória.
fn chave(params: Json, nome: &str) -> Result<[u8; sigilo::TAM_CHAVE], Falha> {
    sigilo::de_hex(texto(params, nome)?).ok_or_else(|| {
        falha(
            Codigo::InvalidArgument,
            format!("`{nome}` nao e uma chave em hex"),
        )
    })
}

/// O papel `papel` cabe no do administrador. A recusa é da política.
fn cabe(pedinte: &Pedinte, papel: &str) -> Result<(), Falha> {
    autorizacao::com_politica(|p| p.cabe_em(papel, pedinte.papel))
        .map_err(|r| falha(r.codigo(), r.motivo()))
}

fn recusa_do_registro(r: crate::identidade::Recusa) -> Falha {
    use crate::identidade::Recusa as R;
    let codigo = match r {
        R::Cheio => Codigo::Error,
        R::Nome | R::ChaveRepetida | R::NomeRepetido | R::Desconhecido => Codigo::InvalidArgument,
    };
    falha(codigo, r.motivo())
}

fn registrar_agente(pedinte: &Pedinte, params: Json, w: &mut JsonWriter) -> Result<String, Falha> {
    let chave = chave(params, "key")?;
    let nome = texto(params, "name")?;
    let papel = texto(params, "role")?;
    // Uma chave de administrador como agente seria o administrador
    // exercendo, por uma sessão, as permissões que no papel dele só dizem o
    // que ele concede.
    if crate::identidade::administrador(&chave).is_some() {
        return Err(falha(
            Codigo::DenyPolicy,
            "uma chave de administrador nao se registra como agente",
        ));
    }
    cabe(pedinte, papel)?;
    crate::identidade::registrar(chave, nome, papel).map_err(recusa_do_registro)?;
    crate::log_info!(
        "admin",
        "agente {} registrado como {} ({})",
        nome,
        papel,
        crate::identidade::impressao(&chave)
    );
    let _ = w.field_str("agent", nome);
    let _ = w.field_str("key", &sigilo::hex(&chave));
    let _ = w.field_str("role", papel);
    Ok(nome.to_string())
}

/// O agente com esta chave existe, e o papel de agora dele cabe no do
/// administrador: quem pode mais que ele não é rebaixado nem revogado por
/// ele. Sem papel, o agente não pode nada, e mexer nele não alcança mais.
fn alcancavel(pedinte: &Pedinte, chave: &[u8; sigilo::TAM_CHAVE]) -> Result<(), Falha> {
    if crate::identidade::agente(chave).is_none() {
        return Err(falha(Codigo::InvalidArgument, "agente desconhecido"));
    }
    if let Some(atual) = crate::identidade::papel_do_agente(chave) {
        cabe(pedinte, &atual)?;
    }
    Ok(())
}

fn revogar_agente(pedinte: &Pedinte, params: Json, w: &mut JsonWriter) -> Result<String, Falha> {
    let chave = chave(params, "key")?;
    if pedinte.chave_da_sessao == Some(chave) {
        return Err(falha(
            Codigo::DenyPolicy,
            "uma sessao nao revoga a propria chave",
        ));
    }
    alcancavel(pedinte, &chave)?;
    let nome = crate::identidade::revogar(&chave).map_err(recusa_do_registro)?;
    // As sessões vivas da chave caem agora, e não no próximo aperto.
    let encerradas = super::seguro::revogar(&chave);
    crate::log_info!(
        "admin",
        "agente {} revogado; {} sessoes encerradas",
        nome,
        encerradas.len()
    );
    let _ = w.field_str("agent", &nome);
    let _ = w.key("sessions_closed");
    let _ = w.begin_array();
    for p in &encerradas {
        let _ = w.u64_value(u64::from(*p));
    }
    let _ = w.end_array();
    Ok(nome)
}

/// O nome que a atribuição usa para a serial.
const ALVO_SERIAL: &str = "serial";

fn atribuir_papel(pedinte: &Pedinte, params: Json, w: &mut JsonWriter) -> Result<String, Falha> {
    let alvo = texto(params, "agent")?;
    let papel = texto(params, "role")?;
    cabe(pedinte, papel)?;

    if alvo == ALVO_SERIAL {
        if pedinte.sessao == super::sessao::SERIAL {
            return Err(falha(
                Codigo::DenyPolicy,
                "uma sessao nao muda o proprio papel",
            ));
        }
        // O papel de agora da serial também precisa caber: um administrador
        // não rebaixa o canal de emergência abaixo do que ele mesmo é.
        let atual = autorizacao::com_politica(|p| p.serial().to_string());
        cabe(pedinte, &atual)?;
        autorizacao::mudar_politica(|p| p.com_serial(papel))
            .map_err(|r: Recusa| falha(r.codigo(), r.motivo()))?;
    } else {
        let chave = crate::identidade::chave_do_agente(alvo)
            .ok_or_else(|| falha(Codigo::InvalidArgument, "agente desconhecido"))?;
        if pedinte.chave_da_sessao == Some(chave) {
            return Err(falha(
                Codigo::DenyPolicy,
                "uma sessao nao muda o proprio papel",
            ));
        }
        alcancavel(pedinte, &chave)?;
        crate::identidade::atribuir(alvo, papel).map_err(recusa_do_registro)?;
    }
    let _ = w.field_str("agent", alvo);
    let _ = w.field_str("role", papel);
    Ok(format!("{alvo} -> {papel}"))
}

fn escrever_politica(pedinte: &Pedinte, params: Json, w: &mut JsonWriter) -> Result<String, Falha> {
    let linha = texto(params, "line")?;
    // Protegidos: o papel de cada administrador — e o de quem pede é um
    // deles —, o da sessão de onde o pedido vem, e os da serial e da
    // autoridade local: a autoridade de sistema não encolhe por uma linha
    // escrita em tempo de execução. Nenhum muda por aqui.
    let mut protegidos = crate::identidade::papeis_dos_administradores();
    protegidos.extend(autorizacao::com_politica(|p| {
        [p.serial().to_string(), p.local().to_string()]
    }));
    let da_sessao = match pedinte.chave_da_sessao {
        Some(k) => crate::identidade::papel_do_agente(&k),
        None if pedinte.sessao == super::sessao::SERIAL => {
            Some(autorizacao::com_politica(|p| p.serial().to_string()))
        }
        None => None,
    };
    protegidos.extend(da_sessao);
    let protegidos: Vec<&str> = protegidos.iter().map(String::as_str).collect();
    autorizacao::mudar_politica(|p| p.com_linha(linha, pedinte.papel, &protegidos))
        .map_err(|r: Recusa| falha(r.codigo(), r.motivo()))?;
    let _ = w.field_str("line", linha);
    let _ = w.field_str("by", pedinte.nome);
    // O recurso da auditoria: as duas primeiras palavras, que dizem o que a
    // linha muda — `papel operador`, `taxa observador`. O resto está no
    // resumo dos parâmetros.
    let mut palavras = linha.split_whitespace();
    let recurso = match (palavras.next(), palavras.next()) {
        (Some(a), Some(b)) => format!("{a} {b}"),
        (Some(a), None) => a.to_string(),
        _ => String::new(),
    };
    Ok(recurso)
}

// ---------------------------------------------------------------------------
// Pessoas
// ---------------------------------------------------------------------------

fn recusa_de_pessoas(r: crate::pessoas::Recusa) -> Falha {
    use crate::pessoas::Recusa as R;
    let codigo = match r {
        R::Cheio | R::SemEntropia => Codigo::Error,
        R::Nome | R::Papel | R::NomeRepetido | R::Desconhecida | R::JaRevogada => {
            Codigo::InvalidArgument
        }
    };
    falha(codigo, r.motivo())
}

/// Uma credencial, na forma do registro. Só o verificador: uma senha não
/// tem esta forma, e não é aceita.
fn credencial(params: Json) -> Result<sigilo::credencial::Credencial, Falha> {
    sigilo::credencial::Credencial::ler(texto(params, "credential")?)
        .map_err(|e| falha(Codigo::InvalidArgument, e.motivo()))
}

/// A pessoa com este identificador existe, e o papel dela cabe no do
/// administrador: como com os agentes, quem pode mais que ele não é
/// revogado nem tem a credencial trocada por ele.
fn pessoa_alcancavel(pedinte: &Pedinte, params: Json) -> Result<sigilo::pessoas::Pessoa, Falha> {
    let id = sigilo::pessoas::IdPessoa::ler(texto(params, "person")?).ok_or_else(|| {
        falha(
            Codigo::InvalidArgument,
            "`person` nao e um identificador pessoa:<16 hex>",
        )
    })?;
    let pessoa = crate::pessoas::pessoa(id)
        .ok_or_else(|| recusa_de_pessoas(crate::pessoas::Recusa::Desconhecida))?;
    cabe(pedinte, &pessoa.papel)?;
    Ok(pessoa)
}

fn registrar_pessoa(pedinte: &Pedinte, params: Json, w: &mut JsonWriter) -> Result<String, Falha> {
    let nome = texto(params, "name")?;
    let papel = texto(params, "role")?;
    let credencial = credencial(params)?;
    cabe(pedinte, papel)?;
    let id = crate::pessoas::registrar(nome, papel, credencial).map_err(recusa_de_pessoas)?;
    crate::log_info!(
        "admin",
        "pessoa {} registrada como {} ({})",
        nome,
        papel,
        id.texto()
    );
    let _ = w.field_str("person", &id.texto());
    let _ = w.field_str("name", nome);
    let _ = w.field_str("role", papel);
    Ok(id.texto())
}

fn revogar_pessoa(pedinte: &Pedinte, params: Json, w: &mut JsonWriter) -> Result<String, Falha> {
    let pessoa = pessoa_alcancavel(pedinte, params)?;
    let encerradas = crate::pessoas::revogar_pessoa(pessoa.id).map_err(recusa_de_pessoas)?;
    crate::log_info!(
        "admin",
        "pessoa {} revogada; {} sessoes encerradas",
        pessoa.nome,
        encerradas.len()
    );
    let _ = w.field_str("person", &pessoa.id.texto());
    let _ = w.key("sessions_closed");
    let _ = w.begin_array();
    for s in &encerradas {
        let _ = w.str_value(&s.texto());
    }
    let _ = w.end_array();
    Ok(pessoa.id.texto())
}

fn rotacionar_credencial(
    pedinte: &Pedinte,
    params: Json,
    w: &mut JsonWriter,
) -> Result<String, Falha> {
    let pessoa = pessoa_alcancavel(pedinte, params)?;
    let credencial = credencial(params)?;
    crate::pessoas::rotacionar(pessoa.id, credencial).map_err(recusa_de_pessoas)?;
    crate::log_info!("admin", "credencial de {} trocada", pessoa.nome);
    let _ = w.field_str("person", &pessoa.id.texto());
    Ok(pessoa.id.texto())
}

fn revogar_sessao(pedinte: &Pedinte, params: Json, w: &mut JsonWriter) -> Result<String, Falha> {
    let id = crate::pessoas::IdSessao::ler(texto(params, "session")?)
        .ok_or_else(|| falha(Codigo::InvalidArgument, "`session` nao e 16 hex"))?;
    // A sessão é de uma pessoa, e a pessoa precisa estar ao alcance: o
    // papel dela cabe no do administrador.
    let dona = crate::pessoas::dona_da_sessao(id)
        .and_then(crate::pessoas::pessoa)
        .ok_or_else(|| recusa_de_pessoas(crate::pessoas::Recusa::Desconhecida))?;
    cabe(pedinte, &dona.papel)?;
    crate::pessoas::revogar_sessao(id).map_err(recusa_de_pessoas)?;
    crate::log_info!("admin", "sessao {} de {} revogada", id.texto(), dona.nome);
    let _ = w.field_str("session", &id.texto());
    let _ = w.field_str("person", &dona.id.texto());
    Ok(id.texto())
}

// ---------------------------------------------------------------------------
// Arrendamentos
// ---------------------------------------------------------------------------

/// `lease.revoke`: tira o arrendamento de um campo, de quem for.
///
/// Sem preempção, esta é a única forma de quebrar o arrendamento de outro:
/// com a prova, com a permissão no papel do administrador, e gravada — o
/// arrendamento que saiu vai para a auditoria em nome de quem o tinha, e a
/// operação em nome do administrador. O `sistema` não tem um atalho para
/// isto.
fn revogar_arrendamento(
    _pedinte: &Pedinte,
    params: Json,
    w: &mut JsonWriter,
) -> Result<String, Falha> {
    let id = params
        .member("id")
        .and_then(|v| v.as_u64())
        .and_then(|id| u32::try_from(id).ok())
        .ok_or_else(|| falha(Codigo::InvalidArgument, "falta `id`"))?;
    let recurso = crate::coordenacao::recurso(id);
    let saiu = crate::coordenacao::revogar(&recurso)
        .ok_or_else(|| falha(Codigo::InvalidArgument, "o campo nao esta arrendado"))?;
    let (tipo, quem) = crate::coordenacao::descrever(&saiu.titular);
    let _ = w.field_str("resource", &recurso);
    let _ = w.field_str("holder", tipo);
    let _ = w.field_str("by", &quem);
    Ok(recurso)
}

/// A falha de uma operação de mensagem.
fn falha_de_mensagem(r: politica::mensagens::Recusa) -> Falha {
    falha(r.codigo(), r.motivo())
}

fn mandar_mensagem(pedinte: &Pedinte, params: Json, w: &mut JsonWriter) -> Result<String, Falha> {
    let destino = pedinte
        .destino
        .as_ref()
        .ok_or_else(|| falha(Codigo::DenyResource, "sem destinatario decidido"))?;
    let nonce = params.member("nonce").and_then(|v| v.as_u64()).unwrap_or(0);
    let prazo = params.member("ttl_ms").and_then(|v| v.as_u64());
    let bruto = params
        .member("body")
        .ok_or_else(|| falha(Codigo::InvalidArgument, "falta `body`"))?;
    let mut buffer = alloc::vec![0u8; bruto.0.len()];
    let corpo = bruto
        .desescapar_em(&mut buffer)
        .ok_or_else(|| falha(Codigo::InvalidArgument, "o corpo nao e texto"))?;
    let remetente = crate::mensagens::Remetente::do_administrador(pedinte.administrador);
    let (id, e) = crate::mensagens::enviar(&remetente, destino, corpo, nonce, prazo)
        .map_err(falha_de_mensagem)?;
    let _ = w.field_str("id", &id);
    let _ = w.field_bool("duplicate", e.duplicata);
    Ok(format!("msg:{id}"))
}

fn ler_mensagens(pedinte: &Pedinte, params: Json, w: &mut JsonWriter) -> Result<String, Falha> {
    let remetente = crate::mensagens::Remetente::do_administrador(pedinte.administrador);
    let apos = params.member("after").and_then(|v| v.as_str());
    let max = params.member("max").and_then(|v| v.as_u64());
    super::commands::escrever_caixa(w, &remetente, apos, max)
        .map_err(|(codigo, motivo)| falha(codigo, motivo))?;
    Ok(String::from("caixa"))
}

fn confirmar_mensagem(
    pedinte: &Pedinte,
    params: Json,
    w: &mut JsonWriter,
) -> Result<String, Falha> {
    let id = texto(params, "id")?;
    let esperada = params.member("expect_version").and_then(|v| v.as_u64());
    let remetente = crate::mensagens::Remetente::do_administrador(pedinte.administrador);
    let t = crate::mensagens::confirmar(&remetente, id, esperada).map_err(falha_de_mensagem)?;
    let _ = w.field_str("state", t.estado.nome());
    Ok(format!("msg:{id}"))
}

fn purgar_mensagem(pedinte: &Pedinte, params: Json, w: &mut JsonWriter) -> Result<String, Falha> {
    let id = texto(params, "id")?;
    let remetente = crate::mensagens::Remetente::do_administrador(pedinte.administrador);
    let t = crate::mensagens::purgar(&remetente, id).map_err(falha_de_mensagem)?;
    let _ = w.field_str("state", t.estado.nome());
    Ok(format!("msg:{id}"))
}
