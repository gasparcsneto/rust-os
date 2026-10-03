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
    /// O número do desafio que a prova consumiu: identifica a operação na
    /// auditoria, e liga a ela o que a operação grava por conta própria.
    desafio: u64,
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
    /// O que ela faz com o estado de autoridade — e com isso se precisa da
    /// persistência para acontecer. Ver [`Efeito`].
    efeito: Efeito,
    executar: fn(&Pedinte, Json, &mut JsonWriter) -> Result<String, Falha>,
}

/// O que uma operação faz com o estado de autoridade.
///
/// Toda operação que muda autoridade passa pela persistência: sem ela
/// disponível, é recusada — não há exceção para o `sistema` nem para a
/// serial —, e com ela, o que mudou é gravado no journal antes da
/// resposta. A diferença entre conceder e tirar é o que acontece quando a
/// gravação falha: o que foi concedido é desfeito; o que foi tirado fica.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Efeito {
    /// Não muda autoridade: arrendamentos e mensagens.
    Nenhum,
    /// Dá a alguém o que ele não tinha: um registro, um papel, uma
    /// política, uma credencial.
    Concede,
    /// Tira de alguém o que ele tinha: uma revogação.
    Tira,
}

/// As operações que `admin.execute` aceita.
static OPERACOES: &[Operacao] = &[
    Operacao {
        nome: "agent.register",
        resumo: "Registra um agente: {\"key\": chave publica em hex, \"name\": nome, \"role\": \
                 papel}. O papel cabe no do administrador. Fica gravado no journal.",
        permissao: Permissao::AgentRegister,
        efeito: Efeito::Concede,
        executar: registrar_agente,
    },
    Operacao {
        nome: "agent.revoke",
        resumo: "Revoga um agente: {\"key\": chave publica em hex}. As sessoes abertas com a \
                 chave sao encerradas na hora. Nao vale para a chave da propria sessao.",
        permissao: Permissao::AgentRevoke,
        efeito: Efeito::Tira,
        executar: revogar_agente,
    },
    Operacao {
        nome: "policy.assign",
        resumo: "Atribui um papel: {\"agent\": nome, ou \"serial\", \"role\": papel}. O papel \
                 novo e o de agora cabem no do administrador; nao vale para a propria sessao.",
        permissao: Permissao::PolicyAssign,
        efeito: Efeito::Concede,
        executar: atribuir_papel,
    },
    Operacao {
        nome: "policy.write",
        resumo: "Muda uma linha da politica em memoria: {\"line\": \"papel ...\", \"recurso ...\" \
                 ou \"taxa ...\"}. Validada como o arquivo; vale na decisao seguinte; o disco \
                 nao muda.",
        permissao: Permissao::PolicyWrite,
        efeito: Efeito::Concede,
        executar: escrever_politica,
    },
    Operacao {
        nome: "person.register",
        resumo: "Registra uma pessoa: {\"name\": nome, \"role\": papel, \"credential\": \
                 \"argon2id:m=..,t=..,p=1:<sal>:<verificador>\"}. O verificador e calculado \
                 fora: a senha nunca vem. O papel cabe no do administrador. Devolve o \
                 identificador. Fica gravado no journal.",
        permissao: Permissao::PersonRegister,
        efeito: Efeito::Concede,
        executar: registrar_pessoa,
    },
    Operacao {
        nome: "person.revoke",
        resumo: "Revoga uma pessoa: {\"person\": \"pessoa:<16 hex>\"}. Ela nao entra mais, e \
                 as sessoes dela acabam na hora; o registro fica, com o estado revogada.",
        permissao: Permissao::PersonRevoke,
        efeito: Efeito::Tira,
        executar: revogar_pessoa,
    },
    Operacao {
        nome: "credential.rotate",
        resumo: "Troca a credencial de uma pessoa: {\"person\": identificador, \"credential\": \
                 verificador como no registro}. A pessoa e a mesma; as sessoes continuam.",
        permissao: Permissao::CredentialRotate,
        efeito: Efeito::Concede,
        executar: rotacionar_credencial,
    },
    Operacao {
        nome: "session.revoke",
        resumo: "Encerra uma sessao de pessoa: {\"session\": 16 hex}. A pessoa continua \
                 registrada e pode entrar de novo.",
        permissao: Permissao::SessionRevoke,
        efeito: Efeito::Tira,
        executar: revogar_sessao,
    },
    Operacao {
        nome: "lease.revoke",
        resumo: "Revoga o arrendamento de um campo, de quem for: {\"id\": o id do campo em \
                 ui.tree}. A unica forma de quebrar o arrendamento de outro.",
        permissao: Permissao::LeaseRevoke,
        efeito: Efeito::Nenhum,
        executar: revogar_arrendamento,
    },
    Operacao {
        nome: "message.send",
        resumo: "Manda uma mensagem como o administrador: {\"to\", \"body\", \"nonce\", \
                 \"ttl_ms\"?}, como `message.send`. O alcance e o do papel do administrador; \
                 a chave dele nunca abre sessao.",
        permissao: Permissao::MessageSend,
        efeito: Efeito::Nenhum,
        executar: mandar_mensagem,
    },
    Operacao {
        nome: "message.read",
        resumo: "Le a caixa do administrador: {\"after\"?, \"max\"?}, como `message.read`.",
        permissao: Permissao::MessageRead,
        efeito: Efeito::Nenhum,
        executar: ler_mensagens,
    },
    Operacao {
        nome: "message.ack",
        resumo: "Confirma uma mensagem da caixa do administrador: {\"id\", \
                 \"expect_version\"?}.",
        permissao: Permissao::MessageRead,
        efeito: Efeito::Nenhum,
        executar: confirmar_mensagem,
    },
    Operacao {
        nome: "message.purge",
        resumo: "Tira uma mensagem viva, de quem for: {\"id\"}. Fica a lapide, e a \
                 auditoria.",
        permissao: Permissao::MessagePurge,
        efeito: Efeito::Nenhum,
        executar: purgar_mensagem,
    },
    Operacao {
        nome: "message.purge_mailbox",
        resumo: "Esvazia a caixa inteira de um titular: {\"mailbox\": endereco, como o \
                 `to` do message.send}. Permissao propria: a de tirar uma mensagem nao \
                 basta. Cada mensagem tirada vai para a auditoria com o id.",
        permissao: Permissao::MessagePurgeMailbox,
        efeito: Efeito::Nenhum,
        executar: esvaziar_caixa,
    },
];

/// Os nomes das operações, para o `agent.describe` e para o resumo.
pub fn operacoes() -> impl Iterator<Item = (&'static str, &'static str)> {
    OPERACOES.iter().map(|o| (o.nome, o.resumo))
}

/// Emite um desafio para a sessão do pedido: `admin.challenge`. Com `para`,
/// um desafio de quórum para aquela operação — e a resposta diz o que as
/// credenciais vão provar além dele: a versão da política, M e N.
pub(crate) fn desafiar(para: Option<&str>, w: &mut JsonWriter) -> fmt::Result {
    let sessao = super::sessao::atual();
    w.begin_object()?;
    let quorum = match para {
        None => None,
        Some(nome) => match politica::arquivo::OPERACOES_DE_QUORUM
            .iter()
            .find(|o| **o == nome)
        {
            Some(o) => Some(*o),
            None => {
                w.field_str("error", "nao e uma operacao de quorum")?;
                return w.end_object();
            }
        },
    };
    match crate::identidade::desafiar(sessao, quorum) {
        Ok(d) => {
            w.field_u64("challenge", d.id)?;
            w.field_str("nonce", &sigilo::hex(&d.nonce))?;
            w.field_str("ephemeral", &sigilo::hex(&d.efemera))?;
            w.field_u64("session", u64::from(sessao))?;
            w.field_u64("valid_ms", d.valido_ms)?;
            if let Some(operacao) = quorum {
                w.field_str("operation", operacao)?;
                w.field_u64("policy_version", d.versao_da_politica)?;
                w.field_u64("generation", d.geracao)?;
                if let Some(q) = autorizacao::com_politica(|p| p.quorum(operacao)) {
                    w.field_u64("m", u64::from(q.m))?;
                    w.field_u64("n", u64::from(q.n))?;
                }
            }
        }
        Err(_) => w.field_str("error", "sem entropia: nenhum desafio pode ser emitido")?,
    }
    w.end_object()
}

/// O maior texto de parâmetros de uma operação: 1 KiB, os bytes que a
/// prova cobre, já desescapados.
///
/// # Por que 1 KiB
///
/// Porque o pedido administrativo maior que existe precisa caber inteiro:
/// o `message.send` do administrador com o maior corpo, 512 bytes, mais o
/// destinatário, o nonce e o prazo. Com 512, o corpo do administrador era
/// menor que o de qualquer agente — o envelope comia o resto. Tudo continua
/// sob a prova: o texto inteiro dos parâmetros entra no HMAC e na derivação
/// da chave, byte a byte, e nada sai dele para caber.
///
/// O que limita por cima é a linha do pedido: os parâmetros vão como texto
/// dentro do JSON de `admin.execute`, escapados mais uma vez — ver
/// [`super::LINHA_MAX`], que é dimensionada a partir deste número.
pub const MAIORES_PARAMETROS: usize = 1024;

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
    /// As assinaturas de um quórum, como vieram: `chave:prova,chave:prova`,
    /// em hex. No lugar de `administrador` e `prova`, nunca junto.
    pub assinaturas: Option<&'a str>,
}

/// Executa uma operação administrativa: `admin.execute`. Com assinaturas,
/// uma operação de quórum — ver [`conferir_quorum_e_executar`].
pub(crate) fn executar(pedido: Pedido, w: &mut JsonWriter) -> fmt::Result {
    let sessao = super::sessao::atual();
    w.begin_object()?;
    let resultado = if pedido.assinaturas.is_some() {
        conferir_quorum_e_executar(sessao, pedido, w)
    } else {
        conferir_e_executar(sessao, pedido, w)
    };
    if let Err((codigo, motivo)) = resultado {
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
    // Um desafio de quórum não serve a uma credencial só: ele vale mais
    // tempo, e foi pedido para outra coisa.
    if desafio.quorum.is_some() {
        return Err(recusar_anonimo(
            Codigo::DenyNotAuthenticated,
            "um desafio de quorum nao serve a uma credencial so",
        ));
    }

    let Some((nome, papel)) = crate::identidade::papel_do_administrador(&administrador) else {
        let motivo = if crate::identidade::administrador_revogado(&administrador) {
            "credencial de administrador revogada"
        } else {
            "chave fora do registro de administradores"
        };
        return Err(recusar_anonimo(Codigo::DenyNotAuthenticated, motivo));
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

    // A persistência, antes de qualquer coisa: sem ela confiável, nenhuma
    // credencial administrativa é aceita — nem para o que não muda
    // autoridade. Sem o journal confirmado pela âncora, o kernel não sabe
    // quais credenciais foram revogadas: um disco restaurado, ou o registro
    // da lápide estragado, deixaria uma credencial revogada lendo e
    // mandando mensagens como administradora. O `sistema` e a serial
    // passam por aqui como qualquer um.
    if let Err(motivo) = crate::persistencia::exigir() {
        let motivo = format!("persistencia indisponivel: {motivo}");
        gravar(Codigo::Error, "", &motivo);
        return Err(falha(Codigo::Error, motivo));
    }
    let pedinte = Pedinte {
        sessao,
        nome: &nome,
        papel,
        chave_da_sessao: crate::sessoes::identidade(sessao).map(|id| id.chave),
        administrador,
        destino,
        desafio: id,
    };

    // A operação escreve os campos dela só se der certo; os de cima vêm
    // depois, para uma recusa da operação não deixar um `executed` dizendo
    // o contrário na mesma resposta.
    //
    // A foto, a operação e a gravação, com a ordem das gravações na mão:
    // nada que outro fio mude no meio — uma mensagem que vence — entra na
    // diferença desta operação, nem é gravado antes dela.
    let (feito, gravado) = crate::persistencia::em_ordem(|| {
        let foto = (operacao.efeito != Efeito::Nenhum).then(crate::persistencia::Foto::tirar);
        let feito = (operacao.executar)(&pedinte, Json(parametros.as_bytes()), w);
        let gravado = match (&feito, &foto) {
            (Ok(recurso), Some(foto)) => crate::persistencia::concluir(
                foto,
                operacao.nome,
                recurso,
                operacao.efeito == Efeito::Concede,
            ),
            _ => Ok(()),
        };
        (feito, gravado)
    });
    match feito {
        Ok(recurso) => {
            // Gravada antes de responder. Sem a gravação, o que foi
            // concedido volta, e a resposta diz que não foi feita.
            if let Err(m) = gravado {
                let motivo = format!("a operacao nao ficou gravada no journal: {m}");
                gravar(Codigo::Error, &recurso, &motivo);
                return Err(falha(Codigo::Error, motivo));
            }
            // A autorização que valeu, e a operação: a permissão que o papel
            // tinha e o desafio que a prova consumiu.
            let detalhe = format!(
                "prova conferida; executada; permissao {}; desafio {}",
                operacao.permissao.nome(),
                id
            );
            gravar(Codigo::Allow, &recurso, &detalhe);
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

/// As operações de quórum: M credenciais distintas provam o mesmo pedido.
/// O M e o N são os da linha `quorum` da política; sem a linha, a operação
/// não existe.
struct OperacaoDeQuorum {
    nome: &'static str,
    /// A permissão que o papel de **cada** credencial que assina precisa ter.
    permissao: Permissao,
}

static OPERACOES_DE_QUORUM: &[OperacaoDeQuorum] = &[OperacaoDeQuorum {
    nome: "admin.revoke",
    permissao: Permissao::AdminRevoke,
}];

/// Quantas assinaturas um pedido de quórum pode trazer: o maior grupo.
const MAIS_ASSINATURAS: usize = politica::arquivo::MAIOR_GRUPO as usize;

/// As assinaturas como vieram, `credencial:assinatura,...`, em hex: a chave
/// da credencial — a que a identifica no registro — e a assinatura Ed25519,
/// 64 bytes. A chave que confere a assinatura **não** vem do pedido: vem do
/// registro, pela credencial. `None` para qualquer coisa fora do formato —
/// uma vazia, uma sem os dois lados, hex do tamanho errado, ou mais que o
/// maior grupo.
fn ler_assinaturas(texto: &str) -> Option<Vec<([u8; 32], [u8; sigilo::quorum::TAM_ASSINATURA])>> {
    let mut lidas = Vec::new();
    for parte in texto.split(',') {
        let (chave, assinatura) = parte.split_once(':')?;
        lidas.push((sigilo::de_hex(chave)?, sigilo::de_hex_fixo(assinatura)?));
        if lidas.len() > MAIS_ASSINATURAS {
            return None;
        }
    }
    Some(lidas)
}

/// Confere um pedido de quórum, decide e executa. Um `Err` é a recusa, já
/// auditada.
///
/// # O caminho
///
/// O mesmo de uma operação de uma credencial só, com M credenciais no lugar
/// de uma: as credenciais bem formadas; o desafio, que sai de qualquer
/// jeito — e tem de ser de quórum, para esta operação, sob a política de
/// agora —; cada assinatura Ed25519 conferida sobre o **mesmo** conteúdo
/// canônico ([`sigilo::quorum::Conteudo`]), com a chave pública de
/// assinatura que o registro tem para a credencial — o Duke não tem, nem
/// precisa de, chave privada nenhuma para isso —; cada credencial no
/// registro, ativa, uma vez só; o quórum, M delas; a política, que o papel de **cada** uma tenha
/// a permissão — pela mesma [`autorizacao::decidir_administracao`] de toda
/// operação administrativa —; as restrições da operação; e só então ela.
/// Toda recusa vai para a auditoria com o motivo.
///
/// Uma assinatura que não confere derruba o pedido inteiro, mesmo que as
/// outras bastassem: um pedido com uma assinatura forjada é um pedido de
/// quem tentou forjá-la. Nenhum papel — nem o `sistema`, nem a sessão de
/// onde o pedido vem — substitui uma assinatura.
fn conferir_quorum_e_executar(sessao: u8, pedido: Pedido, w: &mut JsonWriter) -> Result<(), Falha> {
    let bytes = pedido.parametros.unwrap_or("").as_bytes();
    let metodo = pedido.comando.unwrap_or("admin.execute");
    // Os nomes de quem já assinou e foi conferido: a auditoria grava em
    // nome deles. Antes disso, ninguém.
    let gravar = |assinantes: &[&str], papel: Option<&str>, codigo, recurso: &str, motivo: &str| {
        autorizacao::auditar_quorum(
            sessao, assinantes, papel, metodo, recurso, codigo, bytes, motivo,
        );
    };
    let recusar = |assinantes: &[&str], codigo: Codigo, recurso: &str, motivo: &str| -> Falha {
        gravar(assinantes, None, codigo, recurso, motivo);
        falha(codigo, motivo)
    };

    // As credenciais, bem formadas, antes de gastar o desafio.
    let Some(id) = pedido.desafio else {
        return Err(recusar(&[], Codigo::InvalidArgument, "", "falta o desafio"));
    };
    let Some(comando) = pedido.comando else {
        return Err(recusar(&[], Codigo::InvalidArgument, "", "falta o comando"));
    };
    let Some(parametros) = pedido.parametros else {
        return Err(recusar(
            &[],
            Codigo::InvalidArgument,
            "",
            "parametros ausentes, invalidos ou grandes demais",
        ));
    };
    if pedido.administrador.is_some() || pedido.prova.is_some() {
        return Err(recusar(
            &[],
            Codigo::InvalidArgument,
            "",
            "assinaturas de quorum e prova de uma credencial no mesmo pedido",
        ));
    }
    let Some(assinaturas) = pedido.assinaturas.and_then(ler_assinaturas) else {
        return Err(recusar(
            &[],
            Codigo::InvalidArgument,
            "",
            "assinaturas fora do formato `chave:prova,...`",
        ));
    };

    // O desafio sai primeiro, e sai de qualquer jeito.
    let desafio = match crate::identidade::consumir(sessao, id) {
        Ok(d) => d,
        Err(e) => return Err(recusar(&[], Codigo::DenyNotAuthenticated, "", e.motivo())),
    };
    let Some(operacao) = OPERACOES_DE_QUORUM.iter().find(|o| o.nome == comando) else {
        return Err(recusar(
            &[],
            Codigo::InvalidArgument,
            "",
            "nao e uma operacao de quorum",
        ));
    };
    if desafio.quorum != Some(operacao.nome) {
        return Err(recusar(
            &[],
            Codigo::DenyNotAuthenticated,
            "",
            "o desafio nao e de quorum para esta operacao",
        ));
    }
    // A política de agora é a do desafio: as assinaturas provaram aquela
    // versão, e com ela o M e o N.
    let versao = autorizacao::versao_da_politica();
    if desafio.versao_da_politica != versao {
        return Err(recusar(
            &[],
            Codigo::DenyNotAuthenticated,
            "",
            "a politica mudou desde o desafio",
        ));
    }
    // E o estado de autoridade: as assinaturas provaram aquela geração. Uma
    // mudança de autoridade no meio — um agente registrado, uma pessoa
    // revogada — faz delas assinaturas sobre um estado que já não existe.
    let geracao = crate::persistencia::geracao();
    if desafio.geracao != geracao {
        return Err(recusar(
            &[],
            Codigo::DenyNotAuthenticated,
            "",
            "o estado de autoridade mudou desde o desafio",
        ));
    }
    let Some(quorum) = autorizacao::com_politica(|p| p.quorum(operacao.nome)) else {
        return Err(recusar(
            &[],
            Codigo::DenyPolicy,
            "",
            "a politica nao define o quorum desta operacao",
        ));
    };
    // O N é o grupo inteiro do registro, as revogadas também: o quórum é
    // M de N, e um registro com outro N não é o grupo que a política diz.
    let grupo = crate::identidade::grupo_de_administradores();
    if grupo.len() != usize::from(quorum.n) {
        return Err(recusar(
            &[],
            Codigo::DenyPolicy,
            "",
            "o grupo de administradores nao tem o N que a politica diz",
        ));
    }

    // O alvo, dos parâmetros: entra no conteúdo, e uma assinatura feita
    // para outro alvo não confere.
    let alvo = Json(parametros.as_bytes())
        .member("key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let efemera = sigilo::publica_de(&desafio.efemera);
    let conteudo = sigilo::quorum::Conteudo {
        operacao: id,
        nonce: &desafio.nonce,
        sessao,
        efemera: &efemera,
        versao_da_politica: versao,
        geracao,
        m: quorum.m,
        n: quorum.n,
        comando,
        alvo,
        parametros,
    };

    // Cada assinatura: uma vez cada credencial, do grupo, ativa, com chave
    // de assinatura no registro, e a assinatura conferida sobre o conteúdo
    // com essa chave pública.
    let mut assinantes: Vec<(String, [u8; 32], Option<String>)> = Vec::new();
    for (chave, prova) in &assinaturas {
        let nomes: Vec<&str> = assinantes.iter().map(|a| a.0.as_str()).collect();
        if assinantes.iter().any(|a| a.1 == *chave) {
            return Err(recusar(
                &nomes,
                Codigo::DenyPolicy,
                "",
                "a mesma credencial assinou duas vezes",
            ));
        }
        let Some(membro) = grupo.iter().find(|a| a.chave == *chave) else {
            return Err(recusar(
                &nomes,
                Codigo::DenyNotAuthenticated,
                "",
                "uma assinatura de credencial fora do registro de administradores",
            ));
        };
        if membro.revogado {
            return Err(recusar(
                &nomes,
                Codigo::DenyNotAuthenticated,
                "",
                "uma assinatura de credencial revogada",
            ));
        }
        let Some(publica) = membro.assinatura else {
            return Err(recusar(
                &nomes,
                Codigo::DenyNotAuthenticated,
                "",
                "uma credencial sem chave de assinatura no registro",
            ));
        };
        if !sigilo::quorum::conferir(&publica, &conteudo, prova) {
            return Err(recusar(
                &nomes,
                Codigo::DenyNotAuthenticated,
                "",
                "uma assinatura nao confere com o conteudo",
            ));
        }
        assinantes.push((membro.nome.clone(), *chave, membro.papel.clone()));
    }
    let nomes: Vec<&str> = assinantes.iter().map(|a| a.0.as_str()).collect();

    // O quórum.
    if assinantes.len() < usize::from(quorum.m) {
        let motivo = format!(
            "quorum incompleto: {} de {} assinaturas",
            assinantes.len(),
            quorum.m
        );
        return Err(recusar(&nomes, Codigo::DenyPolicy, "", &motivo));
    }

    // A política: o papel de cada uma tem a permissão, pela decisão central.
    for (nome, _, papel) in &assinantes {
        let codigo = autorizacao::decidir_administracao(papel.as_deref(), operacao.permissao);
        if !codigo.permite() {
            let motivo = format!("o papel de `{nome}` nao tem a permissao");
            return Err(recusar(&nomes, codigo, "", &motivo));
        }
    }
    // Cada assinatura conferida vai para a auditoria com a chave inteira de
    // quem assinou — o registro do desfecho tem lugar para os nomes, e não
    // para as chaves.
    for (nome, chave, papel) in &assinantes {
        autorizacao::auditar_administracao(
            sessao,
            Some((nome, chave)),
            papel.as_deref(),
            metodo,
            alvo,
            Codigo::Allow,
            bytes,
            &format!(
                "assinatura ed25519 conferida; permissao {}; desafio {id}",
                operacao.permissao.nome()
            ),
        );
    }

    // A persistência, como para toda operação de autoridade: sem ela, a
    // revogação não acontece — uma lápide que não fica gravada seria uma
    // credencial que volta no próximo boot.
    if let Err(motivo) = crate::persistencia::exigir() {
        let motivo = format!("persistencia indisponivel: {motivo}");
        return Err(recusar(&nomes, Codigo::Error, "", &motivo));
    }
    // As restrições e a execução da operação, e a gravação, com a ordem
    // das gravações na mão — como as de uma credencial.
    let (feito, gravado) = crate::persistencia::em_ordem(|| {
        let foto = crate::persistencia::Foto::tirar();
        let feito = match operacao.nome {
            "admin.revoke" => revogar_administrador(&assinantes, alvo, quorum.m, parametros),
            _ => Err(falha(Codigo::Error, "operacao de quorum sem execucao")),
        };
        let gravado = match &feito {
            Ok(f) => crate::persistencia::concluir(&foto, operacao.nome, &f.recurso, false),
            Err(_) => Ok(()),
        };
        (feito, gravado)
    });
    let papeis: Vec<&str> = assinantes.iter().filter_map(|a| a.2.as_deref()).collect();
    let papel = papeis.first().copied();
    match feito {
        Ok(Feito {
            recurso,
            detalhe,
            descartados,
        }) => {
            // Gravada antes de responder: a lápide no journal, a âncora
            // avançada. Se falhar, a revogação continua valendo em memória —
            // o que se tira não volta — e a resposta diz que não ficou
            // gravada; a persistência indisponível bloqueia o resto.
            if let Err(m) = gravado {
                let motivo = format!("a revogacao vale, mas nao ficou gravada no journal: {m}");
                gravar(&nomes, papel, Codigo::Error, &recurso, &motivo);
                return Err((Codigo::Error, motivo));
            }
            // O detalhe tem teto: o que identifica a operação primeiro, o
            // motivo por último — é ele que se corta.
            let detalhe = format!(
                "quorum {} de {}; desafio {}; politica v{}; descartados {}; {}",
                assinantes.len(),
                quorum.n,
                id,
                versao,
                descartados,
                detalhe
            );
            gravar(&nomes, papel, Codigo::Allow, &recurso, &detalhe);
            for (nome, _, papel) in &assinantes {
                autorizacao::contar_administracao(
                    nome,
                    papel.as_deref().unwrap_or(""),
                    operacao.nome,
                    operacao.permissao,
                );
            }
            let _ = w.field_bool("executed", true);
            let _ = w.field_str("command", operacao.nome);
            let _ = w.field_str("target", &recurso);
            let _ = w.field_u64("challenges_discarded", descartados as u64);
            let _ = w.key("signed_by");
            let _ = w.begin_array();
            for nome in &nomes {
                let _ = w.str_value(nome);
            }
            let _ = w.end_array();
            crate::log_info!(
                "admin",
                "sessao {}: {} por quorum ({}): {}",
                sessao,
                operacao.nome,
                nomes.join("+"),
                recurso
            );
            Ok(())
        }
        Err((codigo, motivo)) => {
            gravar(&nomes, papel, codigo, "", &motivo);
            Err((codigo, motivo))
        }
    }
}

/// O que uma operação de quórum fez: o recurso e o que ela acrescenta ao
/// detalhe da auditoria.
struct Feito {
    recurso: String,
    detalhe: String,
    /// Quantos desafios pendentes a operação descartou.
    descartados: usize,
}

/// `admin.revoke`: `{"key": chave pública em hex, "reason": texto}`.
///
/// - o alvo existe no grupo, e não está revogado;
/// - o alvo não assina a própria revogação: o quórum vem das credenciais
///   que vão continuar;
/// - restam pelo menos M ativas depois — conferido e marcado numa seção
///   só, em [`crate::identidade::revogar_administrador`];
/// - a revogação vale na hora: os desafios pendentes de todas as sessões
///   saem, as mensagens vivas da credencial são anuladas, e nada que ela
///   provar depois confere. O que ela já fez fica na auditoria.
fn revogar_administrador(
    assinantes: &[(String, [u8; 32], Option<String>)],
    alvo: &str,
    m: u8,
    parametros: &str,
) -> Result<Feito, Falha> {
    let chave = sigilo::de_hex(alvo)
        .ok_or_else(|| falha(Codigo::InvalidArgument, "`key` nao e uma chave em hex"))?;
    let motivo = Json(parametros.as_bytes())
        .member("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if motivo.is_empty() {
        return Err(falha(Codigo::InvalidArgument, "falta `reason`"));
    }
    if assinantes.iter().any(|a| a.1 == chave) {
        return Err(falha(
            Codigo::DenyPolicy,
            "a credencial alvo nao assina a propria revogacao",
        ));
    }
    use crate::identidade::RecusaDaRevogacao as R;
    let nome = crate::identidade::revogar_administrador(&chave, m).map_err(|r| {
        let codigo = match r {
            R::Desconhecido => Codigo::InvalidArgument,
            R::JaRevogado => Codigo::Conflict,
            R::AbaixoDoQuorum => Codigo::DenyPolicy,
        };
        falha(codigo, r.motivo())
    })?;
    let descartados = crate::identidade::descartar_desafios();
    // O motivo é de quem administra, e vai cortado: a auditoria não é lugar
    // de texto longo.
    let mut motivo = String::from(motivo);
    if motivo.len() > 32 {
        let mut fim = 32;
        while !motivo.is_char_boundary(fim) {
            fim -= 1;
        }
        motivo.truncate(fim);
    }
    Ok(Feito {
        recurso: format!("admin:{nome} ({})", crate::identidade::impressao(&chave)),
        detalhe: format!("motivo: {motivo}"),
        descartados,
    })
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
    let (resultado, duravel) = crate::mensagens::enviar(&remetente, destino, corpo, nonce, prazo);
    let (id, e) = resultado.map_err(falha_de_mensagem)?;
    let _ = w.field_str("id", &id);
    let _ = w.field_bool("duplicate", e.duplicata);
    let _ = super::commands::escrever_duravel(w, duravel);
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
    let (t, duravel) = crate::mensagens::confirmar(&remetente, id, esperada);
    let t = t.map_err(falha_de_mensagem)?;
    let _ = w.field_str("state", t.estado.nome());
    let _ = super::commands::escrever_duravel(w, duravel);
    Ok(format!("msg:{id}"))
}

fn purgar_mensagem(pedinte: &Pedinte, params: Json, w: &mut JsonWriter) -> Result<String, Falha> {
    let id = texto(params, "id")?;
    let remetente = crate::mensagens::Remetente::do_administrador(pedinte.administrador);
    let (t, duravel) = crate::mensagens::purgar(&remetente, id);
    let t = t.map_err(falha_de_mensagem)?;
    let _ = w.field_str("state", t.estado.nome());
    let _ = super::commands::escrever_duravel(w, duravel);
    Ok(format!("msg:{id}"))
}

/// A caixa inteira de um titular. A decisão — a prova, e a permissão
/// própria no papel do administrador — já foi; aqui só se resolve o alvo e
/// se esvazia. O recurso da auditoria diz a caixa e quantas saíram; cada
/// uma foi gravada com o id por [`crate::mensagens::purgar_caixa`].
fn esvaziar_caixa(pedinte: &Pedinte, params: Json, w: &mut JsonWriter) -> Result<String, Falha> {
    let alvo = texto(params, "mailbox")?;
    let (dono, _) =
        crate::mensagens::titular(alvo).map_err(|m| falha(Codigo::InvalidArgument, m))?;
    let remetente = crate::mensagens::Remetente::do_administrador(pedinte.administrador);
    let (tiradas, duravel) =
        crate::mensagens::purgar_caixa(&remetente, dono, alvo, pedinte.desafio);
    let _ = w.field_str("mailbox", alvo);
    let _ = super::commands::escrever_duravel(w, duravel);
    let _ = w.field_u64("removed", tiradas.len() as u64);
    let _ = w.key("ids");
    let _ = w.begin_array();
    for id in &tiradas {
        let _ = w.str_value(id);
    }
    let _ = w.end_array();
    Ok(format!("caixa:{alvo}; {} tiradas", tiradas.len()))
}
