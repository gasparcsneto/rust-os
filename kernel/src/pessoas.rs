//! Pessoas: o registro, a autenticação e as sessões.
//!
//! # Registro, autenticação e autorização são três coisas
//!
//! ```text
//! pessoa registrada → autenticação → sessão → papel → permissões
//! ```
//!
//! - **Registrada**: está em `/etc/duke/privado/pessoas`, com um
//!   identificador `pessoa:<16 hex>`, um nome, um papel, um estado e uma
//!   credencial — ver [`sigilo::pessoas`]. Estar registrada não abre nada.
//! - **Autenticada**: provou, num console, que é ela — hoje, com a senha que
//!   confere com o verificador Argon2id. Autenticar não dá permissão
//!   nenhuma: cria uma **sessão de pessoa**, e só.
//! - **Autorizada**: cada pedido da sessão passa pelo ponto único de decisão
//!   com o papel que o registro dá à pessoa **agora** — ver
//!   [`crate::autorizacao`]. Uma revogação ou uma troca de papel vale na
//!   decisão seguinte.
//!
//! # O console não é a identidade
//!
//! Uma sessão diz qual pessoa e em qual console. Duas pessoas no mesmo
//! console, uma depois da outra, são duas sessões; a mesma pessoa em dois
//! consoles também — com a mesma identidade e estado independente. A serial
//! não está aqui: é o canal de controle e emergência, sem pessoa.
//!
//! # Pessoa não é agente
//!
//! Um agente é a chave dele, e prova o aperto de mão a cada conexão. Uma
//! pessoa é um identificador do registro, com uma credencial que prova que é
//! ela. Os dois não se confundem em texto — o identificador da pessoa tem
//! um `:` que nenhum nome de agente tem — nem na auditoria, que grava o tipo
//! de titular ([`politica::auditoria::Titular`]) e a sessão de pessoa no
//! elo.
//!
//! # Revogar
//!
//! - **A sessão**: acaba na hora; a pessoa continua registrada e pode entrar
//!   de novo.
//! - **A pessoa**: não entra mais, e as sessões dela acabam na hora. O
//!   registro dela fica, com o estado `revogada`, para a auditoria de ontem
//!   continuar apontando para alguém.
//! - **A credencial** não se revoga sozinha: troca-se
//!   ([`rotacionar`]), e a pessoa continua a mesma. As sessões abertas
//!   continuam — encerrá-las é a outra operação, de propósito separada.
//!
//! As três são operações administrativas, com prova — ver
//! [`crate::agent::administracao`]. O que elas mudam vai para o journal, e
//! o boot o reaplica por cima do registro da imagem — ver
//! [`crate::persistencia`].
//!
//! # A senha
//!
//! Nunca é guardada: o registro tem o verificador. O kernel a recebe só para
//! conferir, e a apaga em seguida. O cálculo usa memória de trabalho fora do
//! heap — [`crate::grafico::memoria::Memoria`], que vem do alocador de
//! frames —, zerada antes de voltar. O tempo de uma recusa não diz se o nome
//! existe: um nome desconhecido paga o mesmo Argon2id, contra uma credencial
//! que não confere com nada.
//!
//! # Tentativas
//!
//! Cada console tem uma janela de [`TENTATIVAS`]: passou dela, a tentativa é
//! recusada antes do cálculo — `RATE_LIMIT`, na auditoria uma vez por
//! sequência.

use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::trava::Mutex;
use politica::Codigo;
use politica::taxa::Janela;
use sigilo::credencial::{self, Credencial, Custo, TAM_SAL, TAM_VERIFICADOR};
use sigilo::pessoas::{Estado, IdPessoa, Pessoa};
use sigilo::registro::nome_valido;

/// Onde mora o registro de pessoas. No diretório reservado: o verificador
/// não é a senha, mas quem o tem pode testar palpites fora da máquina.
pub const CAMINHO_DAS_PESSOAS: &str = "/etc/duke/privado/pessoas";

/// Quantas pessoas o registro guarda. Revogadas contam: elas ficam.
pub const MAIOR_REGISTRO: usize = 64;

/// Quantas sessões de pessoa podem estar abertas ao mesmo tempo.
pub const MAIOR_NUMERO_DE_SESSOES: usize = 32;

/// Quantas sessões encerradas a tabela lembra, e por quê: o bastante para
/// a suíte e o relatório distinguirem "encerrada" de "nunca existiu".
const ENCERRADAS_LEMBRADAS: usize = 32;

/// O limite de tentativas de login por console.
pub const TENTATIVAS: politica::Apertos = politica::Apertos {
    quantos: 5,
    janela_ms: 60_000,
};

/// A maior senha aceita, em bytes. O Argon2id aceita mais; um teto impede
/// que uma senha de megabytes vire trabalho do kernel.
pub const MAIOR_SENHA: usize = 128;

/// Um console onde uma pessoa entra: o físico, ou um Terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Console {
    /// O teclado e a tela da máquina.
    Fisico,
    /// Uma janela do Terminal, pelo número dela.
    Terminal(u16),
}

impl Console {
    /// Como a auditoria e o relatório o escrevem.
    pub fn texto(self) -> String {
        match self {
            Console::Fisico => "console".to_string(),
            Console::Terminal(n) => alloc::format!("terminal:{n}"),
        }
    }
}

/// O identificador de uma sessão de pessoa: 8 bytes sorteados no login.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdSessao(pub [u8; 8]);

impl IdSessao {
    pub fn texto(&self) -> String {
        sigilo::hex_de(&self.0)
    }

    pub fn ler(texto: &str) -> Option<IdSessao> {
        sigilo::de_hex_fixo(texto).map(IdSessao)
    }
}

/// Uma sessão aberta.
#[derive(Clone, Copy, Debug)]
struct Sessao {
    id: IdSessao,
    pessoa: IdPessoa,
    console: Console,
    desde_ms: u64,
}

/// Por que uma sessão acabou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encerramento {
    /// A pessoa saiu.
    Saida,
    /// Um administrador revogou a sessão.
    Revogada,
    /// Um administrador revogou a pessoa.
    PessoaRevogada,
    /// O console fechou: a janela do Terminal, ou o processo dela morreu.
    ConsoleFechado,
}

/// O que se sabe de uma sessão agora.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EstadoDaSessao {
    /// Aberta, de uma pessoa ativa, com o papel que o registro dá agora.
    Ativa {
        pessoa: IdPessoa,
        nome: String,
        papel: String,
        console: Console,
    },
    /// Acabou, e por quê.
    Encerrada(Encerramento),
    /// Não há sessão com este número — ou acabou há tanto tempo que a
    /// tabela não lembra.
    Desconhecida,
}

struct Tabela {
    pessoas: Vec<Pessoa>,
    sessoes: Vec<Sessao>,
    encerradas: VecDeque<(IdSessao, Encerramento)>,
    /// A janela de tentativas de cada console, e quantas foram recusadas
    /// desde a última que passou.
    tentativas: Vec<(Console, Janela, u64)>,
}

static TABELA: Mutex<Tabela> = Mutex::new(Tabela {
    pessoas: Vec::new(),
    sessoes: Vec::new(),
    encerradas: VecDeque::new(),
    tentativas: Vec::new(),
});

fn com_tabela<R>(f: impl FnOnce(&mut Tabela) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut TABELA.lock()))
}

/// Lê o registro do disco. No boot, depois do registro de agentes.
///
/// Uma linha errada é pulada com um aviso, e as outras entram — como no
/// registro de agentes. Um arquivo ausente é um registro vazio: ninguém
/// entra pelo console, e a serial continua sendo o caminho de controle.
pub fn carregar() {
    let pessoas = match crate::vfs::ler_segredo(CAMINHO_DAS_PESSOAS) {
        Ok(mut bytes) => {
            let pessoas = ler_registro(&bytes);
            sigilo::zeroize::Zeroize::zeroize(&mut bytes);
            pessoas
        }
        Err(e) => {
            crate::log_info!(
                "pessoas",
                "{} ({}): nenhuma pessoa registrada",
                CAMINHO_DAS_PESSOAS,
                e.motivo()
            );
            Vec::new()
        }
    };
    crate::log_info!("pessoas", "{} pessoas no registro", pessoas.len());
    com_tabela(|t| {
        t.pessoas = pessoas;
        t.sessoes.clear();
        t.encerradas.clear();
        t.tentativas.clear();
    });
    // Nenhuma sessão de pessoa sobrou: nenhum arrendamento de pessoa
    // também.
    crate::coordenacao::invalidar_pessoas("o registro de pessoas foi recarregado");
}

fn ler_registro(bytes: &[u8]) -> Vec<Pessoa> {
    let Ok(texto) = core::str::from_utf8(bytes) else {
        crate::log_error!("pessoas", "{} nao e texto", CAMINHO_DAS_PESSOAS);
        return Vec::new();
    };
    let mut pessoas: Vec<Pessoa> = Vec::new();
    for (i, linha) in texto.lines().enumerate() {
        match sigilo::pessoas::ler_linha(linha) {
            Ok(Some(p)) => {
                if pessoas.len() >= MAIOR_REGISTRO {
                    crate::log_warn!("pessoas", "mais de {} pessoas", MAIOR_REGISTRO);
                    break;
                }
                if pessoas.iter().any(|q| q.id == p.id || q.nome == p.nome) {
                    crate::log_warn!(
                        "pessoas",
                        "{}:{}: identificador ou nome repetido, ignorada",
                        CAMINHO_DAS_PESSOAS,
                        i + 1
                    );
                    continue;
                }
                pessoas.push(p);
            }
            Ok(None) => {}
            Err(e) => crate::log_warn!(
                "pessoas",
                "{}:{}: {}, ignorada",
                CAMINHO_DAS_PESSOAS,
                i + 1,
                e.motivo()
            ),
        }
    }
    pessoas
}

// ---------------------------------------------------------------------------
// Autenticação
// ---------------------------------------------------------------------------

/// Por que um login foi recusado. O que a pessoa no console vê é menos que
/// isto: nome desconhecido, pessoa revogada e senha errada são a mesma
/// resposta — ver [`RecusaDeLogin::resposta`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecusaDeLogin {
    /// Tentativas demais neste console.
    Tentativas,
    /// Nome desconhecido, pessoa revogada, ou senha que não confere.
    NaoConfere,
    /// Sem memória de trabalho para o cálculo.
    Memoria,
    /// Sem entropia para sortear a sessão.
    SemEntropia,
    /// Sessões abertas demais.
    Cheio,
    /// A senha conferiu, e a credencial está suspensa — uma contenção
    /// reversível, que um administrador desfaz. Só quem tem a senha ouve
    /// isto: a recusa vem depois da conferência.
    Suspensa,
}

impl RecusaDeLogin {
    /// O que se diz a quem tentou.
    pub const fn resposta(self) -> &'static str {
        match self {
            RecusaDeLogin::Tentativas => "tentativas demais; espere um minuto",
            RecusaDeLogin::NaoConfere => "nome ou senha nao conferem",
            RecusaDeLogin::Memoria => "sem memoria para conferir a senha",
            RecusaDeLogin::SemEntropia => "sem entropia para abrir a sessao",
            RecusaDeLogin::Cheio => "sessoes demais abertas",
            RecusaDeLogin::Suspensa => "credencial suspensa; um administrador pode retoma-la",
        }
    }

    pub const fn codigo(self) -> Codigo {
        match self {
            RecusaDeLogin::Tentativas => Codigo::RateLimit,
            RecusaDeLogin::NaoConfere => Codigo::DenyNotAuthenticated,
            RecusaDeLogin::Memoria | RecusaDeLogin::SemEntropia | RecusaDeLogin::Cheio => {
                Codigo::Error
            }
            RecusaDeLogin::Suspensa => Codigo::DenyCredential,
        }
    }
}

/// A credencial contra a qual um nome desconhecido é conferido: o mesmo
/// custo das credenciais novas, um verificador que nenhuma senha dá — a
/// chance de um Argon2id de 32 bytes sair todo zero é a de acertar uma
/// chave. Existe só para o tempo da recusa não dizer se o nome existe.
const NINGUEM: Credencial = Credencial::Senha {
    custo: Custo::PADRAO,
    sal: [0; TAM_SAL],
    verificador: [0; TAM_VERIFICADOR],
};

/// Confere uma credencial com memória de trabalho de frames, zerada antes
/// de voltar. `None` se não houve memória.
fn conferir(credencial: &Credencial, senha: &[u8]) -> Option<bool> {
    let bytes = (credencial.blocos() * 1024) as u64;
    let mut memoria = crate::grafico::memoria::Memoria::nova(bytes).ok()?;
    let blocos = memoria.blocos_mut();
    let igual = credencial.conferir_com_memoria(senha, &mut blocos[..credencial.blocos()]);
    credencial::apagar(blocos);
    Some(igual)
}

/// Conta uma tentativa no console. Falso se passou do limite — e, se é a
/// primeira recusada da sequência, grava.
fn contar_tentativa(console: Console) -> bool {
    let agora = crate::tempo::uptime_ms();
    let (passou, suprimidas, primeira) = com_tabela(|t| {
        let i = match t.tentativas.iter().position(|(c, _, _)| *c == console) {
            Some(i) => i,
            None => {
                t.tentativas.push((console, Janela::NOVA, 0));
                t.tentativas.len() - 1
            }
        };
        let (_, janela, recusadas) = &mut t.tentativas[i];
        if janela.contar(TENTATIVAS, agora) {
            (true, core::mem::take(recusadas), false)
        } else {
            *recusadas += 1;
            (false, 0, *recusadas == 1)
        }
    });
    if passou && suprimidas > 1 {
        crate::autorizacao::auditar_pessoa(
            None,
            None,
            "person.login",
            &console.texto(),
            Codigo::RateLimit,
            &alloc::format!("{suprimidas} tentativas recusadas por limite"),
        );
    }
    if !passou && primeira {
        crate::autorizacao::auditar_pessoa(
            None,
            None,
            "person.login",
            &console.texto(),
            Codigo::RateLimit,
            "tentativas demais neste console",
        );
    }
    passou
}

/// Autentica uma pessoa num console. `Ok` com a sessão nova.
///
/// Grava na auditoria o desfecho, uma vez: a sessão aberta, com a pessoa e
/// o número da sessão; ou a recusa, com o motivo de verdade — a resposta a
/// quem tentou não distingue nome de senha, a auditoria distingue. Um nome
/// que não é de ninguém não vai para a auditoria: pode ser uma senha
/// digitada no lugar errado.
pub fn autenticar(console: Console, nome: &str, senha: &[u8]) -> Result<IdSessao, RecusaDeLogin> {
    if !contar_tentativa(console) {
        return Err(RecusaDeLogin::Tentativas);
    }
    let recurso = console.texto();
    // A pessoa com este nome, copiada para fora da trava: o cálculo é
    // longo, e não acontece com as interrupções desligadas.
    let candidata = com_tabela(|t| t.pessoas.iter().find(|p| p.nome == nome).cloned());
    let credencial = candidata.as_ref().map_or(&NINGUEM, |p| &p.credencial);
    let senha_valida = senha.len() <= MAIOR_SENHA;
    let senha = if senha_valida { senha } else { &[] };
    let Some(confere) = conferir(credencial, senha) else {
        crate::autorizacao::auditar_pessoa(
            None,
            None,
            "person.login",
            &recurso,
            Codigo::Error,
            "sem memoria para o argon2id",
        );
        return Err(RecusaDeLogin::Memoria);
    };
    let recusar = |id: Option<&IdPessoa>, detalhe: &str| {
        let texto = id.map(IdPessoa::texto);
        crate::autorizacao::auditar_pessoa_recusada(
            texto.as_deref(),
            "person.login",
            &recurso,
            detalhe,
        );
        Err(RecusaDeLogin::NaoConfere)
    };
    let Some(pessoa) = candidata else {
        return recusar(None, "nome desconhecido");
    };
    if pessoa.estado == Estado::Revogada {
        return recusar(Some(&pessoa.id), "pessoa revogada");
    }
    if !confere || !senha_valida {
        return recusar(Some(&pessoa.id), "senha nao confere");
    }
    // A credencial suspensa confere e não entra — ver `crate::contencao`.
    if crate::contencao::pessoa_suspensa(pessoa.id) {
        crate::autorizacao::auditar_pessoa_recusada_com(
            Codigo::DenyCredential,
            Some(&pessoa.id.texto()),
            "person.login",
            &recurso,
            "credencial suspensa",
        );
        return Err(RecusaDeLogin::Suspensa);
    }

    let mut bytes = [0u8; 8];
    if crate::aleatorio::preencher(&mut bytes).is_err() {
        return Err(RecusaDeLogin::SemEntropia);
    }
    let id = IdSessao(bytes);
    let agora = crate::tempo::uptime_ms();
    // O registro pode ter mudado durante o cálculo: a pessoa revogada, a
    // credencial trocada. A sessão só abre se a pessoa de agora ainda é a
    // que conferiu.
    let aberta = com_tabela(|t| {
        let ainda = t
            .pessoas
            .iter()
            .find(|p| p.id == pessoa.id)
            .is_some_and(|p| p.estado == Estado::Ativa && p.credencial == pessoa.credencial);
        if !ainda {
            return Err(RecusaDeLogin::NaoConfere);
        }
        if t.sessoes.len() >= MAIOR_NUMERO_DE_SESSOES {
            return Err(RecusaDeLogin::Cheio);
        }
        if t.sessoes.iter().any(|s| s.id == id) || t.encerradas.iter().any(|(e, _)| *e == id) {
            // Oito bytes sorteados repetindo: improvável a ponto de ser um
            // gerador quebrado, e um gerador quebrado não abre sessão.
            return Err(RecusaDeLogin::SemEntropia);
        }
        t.sessoes.push(Sessao {
            id,
            pessoa: pessoa.id,
            console,
            desde_ms: agora,
        });
        Ok(())
    });
    match aberta {
        Ok(()) => {
            crate::autorizacao::auditar_pessoa(
                Some((&pessoa.id.texto(), id.0)),
                Some(&pessoa.papel),
                "person.login",
                &recurso,
                Codigo::Allow,
                "sessao aberta",
            );
            crate::log_info!(
                "pessoas",
                "{} ({}) entrou em {}",
                pessoa.nome,
                pessoa.id.texto(),
                recurso
            );
            Ok(id)
        }
        Err(RecusaDeLogin::NaoConfere) => {
            recusar(Some(&pessoa.id), "o registro mudou durante a conferencia")
        }
        Err(e) => {
            crate::autorizacao::auditar_pessoa(
                None,
                None,
                "person.login",
                &recurso,
                e.codigo(),
                e.resposta(),
            );
            Err(e)
        }
    }
}

/// Tira uma sessão da tabela, lembrando por quê. Devolve a sessão.
fn tirar(t: &mut Tabela, id: IdSessao, motivo: Encerramento) -> Option<Sessao> {
    let i = t.sessoes.iter().position(|s| s.id == id)?;
    let sessao = t.sessoes.swap_remove(i);
    if t.encerradas.len() >= ENCERRADAS_LEMBRADAS {
        t.encerradas.pop_front();
    }
    t.encerradas.push_back((id, motivo));
    Some(sessao)
}

/// A pessoa sai. Falso se a sessão não estava aberta.
pub fn sair(id: IdSessao) -> bool {
    let Some(sessao) = com_tabela(|t| tirar(t, id, Encerramento::Saida)) else {
        return false;
    };
    crate::coordenacao::invalidar_pessoa(id, "a pessoa saiu");
    crate::mensagens::canal_acabou(politica::mensagens::Canal::Pessoa(id.0));
    crate::autorizacao::auditar_pessoa(
        Some((&sessao.pessoa.texto(), id.0)),
        None,
        "person.logout",
        &sessao.console.texto(),
        Codigo::Allow,
        "sessao encerrada pela pessoa",
    );
    true
}

/// O console onde a sessão estava fechou: a sessão acaba com ele.
pub fn encerrar_pelo_console(id: IdSessao, detalhe: &str) {
    let Some(sessao) = com_tabela(|t| tirar(t, id, Encerramento::ConsoleFechado)) else {
        return;
    };
    crate::coordenacao::invalidar_pessoa(id, detalhe);
    crate::mensagens::canal_acabou(politica::mensagens::Canal::Pessoa(id.0));
    crate::autorizacao::auditar_pessoa(
        Some((&sessao.pessoa.texto(), id.0)),
        None,
        "person.logout",
        &sessao.console.texto(),
        Codigo::Allow,
        detalhe,
    );
}

/// O que se sabe de uma sessão agora: a pessoa e o papel dela **de agora**.
pub fn sessao(id: IdSessao) -> EstadoDaSessao {
    com_tabela(|t| {
        if let Some(s) = t.sessoes.iter().find(|s| s.id == id) {
            // Uma sessão aberta de uma pessoa que não está ativa não
            // deveria existir — revogar a pessoa encerra as sessões. Se
            // existir, não vale.
            return match t.pessoas.iter().find(|p| p.id == s.pessoa) {
                Some(p) if p.estado == Estado::Ativa => EstadoDaSessao::Ativa {
                    pessoa: p.id,
                    nome: p.nome.clone(),
                    papel: p.papel.clone(),
                    console: s.console,
                },
                _ => EstadoDaSessao::Encerrada(Encerramento::PessoaRevogada),
            };
        }
        match t.encerradas.iter().find(|(e, _)| *e == id) {
            Some((_, motivo)) => EstadoDaSessao::Encerrada(*motivo),
            None => EstadoDaSessao::Desconhecida,
        }
    })
}

// ---------------------------------------------------------------------------
// As operações administrativas
// ---------------------------------------------------------------------------

/// Por que uma operação no registro foi recusada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    Nome,
    Papel,
    NomeRepetido,
    Cheio,
    Desconhecida,
    JaRevogada,
    SemEntropia,
}

impl Recusa {
    pub const fn motivo(self) -> &'static str {
        match self {
            Recusa::Nome => "nome fora da regra",
            Recusa::Papel => "papel fora da regra",
            Recusa::NomeRepetido => "nome ja usado por outra pessoa",
            Recusa::Cheio => "registro de pessoas cheio",
            Recusa::Desconhecida => "pessoa ou sessao desconhecida",
            Recusa::JaRevogada => "pessoa revogada",
            Recusa::SemEntropia => "sem entropia para sortear o identificador",
        }
    }
}

/// Registra uma pessoa. Só [`crate::agent::administracao`] chama, depois de
/// a prova conferir e de o papel caber no do administrador.
///
/// O nome de uma pessoa revogada continua dela: o registro guarda a
/// revogada, e dois registros com o mesmo nome seriam a mesma pessoa para
/// quem lê o log.
pub fn registrar(nome: &str, papel: &str, credencial: Credencial) -> Result<IdPessoa, Recusa> {
    if !nome_valido(nome) {
        return Err(Recusa::Nome);
    }
    if !nome_valido(papel) {
        return Err(Recusa::Papel);
    }
    let mut bytes = [0u8; 8];
    crate::aleatorio::preencher(&mut bytes).map_err(|_| Recusa::SemEntropia)?;
    let id = IdPessoa(bytes);
    com_tabela(|t| {
        if t.pessoas.iter().any(|p| p.nome == nome) {
            return Err(Recusa::NomeRepetido);
        }
        if t.pessoas.iter().any(|p| p.id == id) {
            return Err(Recusa::SemEntropia);
        }
        if t.pessoas.len() >= MAIOR_REGISTRO {
            return Err(Recusa::Cheio);
        }
        t.pessoas.push(Pessoa {
            id,
            nome: nome.to_string(),
            papel: papel.to_string(),
            estado: Estado::Ativa,
            credencial,
        });
        Ok(id)
    })
}

/// Revoga uma pessoa: o estado vira `revogada`, e as sessões dela acabam
/// agora. Devolve as sessões encerradas.
pub fn revogar_pessoa(id: IdPessoa) -> Result<Vec<IdSessao>, Recusa> {
    let encerradas = com_tabela(|t| {
        let p = t
            .pessoas
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(Recusa::Desconhecida)?;
        if p.estado == Estado::Revogada {
            return Err(Recusa::JaRevogada);
        }
        p.estado = Estado::Revogada;
        let ids: Vec<IdSessao> = t
            .sessoes
            .iter()
            .filter(|s| s.pessoa == id)
            .map(|s| s.id)
            .collect();
        for s in &ids {
            tirar(t, *s, Encerramento::PessoaRevogada);
        }
        Ok(ids)
    })?;
    for s in &encerradas {
        crate::coordenacao::invalidar_pessoa(*s, "a pessoa foi revogada");
        crate::mensagens::canal_acabou(politica::mensagens::Canal::Pessoa(s.0));
    }
    // As mensagens dela, as que mandou e as que ia receber: anuladas.
    crate::mensagens::anular_titular(
        politica::mensagens::Dono::Pessoa(id.0),
        "com a pessoa revogada",
    );
    // A revogação é o definitivo: a suspensão de antes some.
    crate::contencao::esquecer_pessoa(id);
    Ok(encerradas)
}

/// Troca a credencial de uma pessoa ativa. A pessoa é a mesma — o mesmo
/// identificador, o mesmo papel —, e as sessões abertas continuam.
pub fn rotacionar(id: IdPessoa, credencial: Credencial) -> Result<(), Recusa> {
    com_tabela(|t| {
        let p = t
            .pessoas
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(Recusa::Desconhecida)?;
        if p.estado == Estado::Revogada {
            return Err(Recusa::JaRevogada);
        }
        p.credencial = credencial;
        Ok(())
    })
}

/// Encerra uma sessão, sem tocar na pessoa. Devolve de quem era.
pub fn revogar_sessao(id: IdSessao) -> Result<IdPessoa, Recusa> {
    let dona = com_tabela(|t| tirar(t, id, Encerramento::Revogada))
        .map(|s| s.pessoa)
        .ok_or(Recusa::Desconhecida)?;
    crate::coordenacao::invalidar_pessoa(id, "a sessao foi revogada");
    crate::mensagens::canal_acabou(politica::mensagens::Canal::Pessoa(id.0));
    Ok(dona)
}

/// O registro de pessoas inteiro: o que a persistência compara antes e
/// depois de uma operação.
pub fn todas() -> Vec<Pessoa> {
    com_tabela(|t| t.pessoas.clone())
}

/// Troca o registro de pessoas inteiro: o que a persistência faz para
/// desfazer uma operação cuja gravação falhou. As sessões ficam.
pub fn restaurar(pessoas: &[Pessoa]) {
    com_tabela(|t| t.pessoas = pessoas.to_vec());
}

/// Põe de volta uma pessoa que o journal registrou, ou a credencial nova
/// dela: substitui qualquer entrada com o mesmo identificador ou o mesmo
/// nome.
pub fn restaurar_pessoa(p: Pessoa) {
    com_tabela(|t| {
        t.pessoas.retain(|q| q.id != p.id && q.nome != p.nome);
        t.pessoas.push(p);
    });
}

/// A pessoa com este identificador.
pub fn pessoa(id: IdPessoa) -> Option<Pessoa> {
    com_tabela(|t| t.pessoas.iter().find(|p| p.id == id).cloned())
}

/// De quem é uma sessão aberta.
pub fn dona_da_sessao(id: IdSessao) -> Option<IdPessoa> {
    com_tabela(|t| t.sessoes.iter().find(|s| s.id == id).map(|s| s.pessoa))
}

/// Uma pessoa, para o relatório: sem a credencial.
pub struct Resumo {
    pub id: IdPessoa,
    pub nome: String,
    pub papel: String,
    pub estado: Estado,
    /// As sessões abertas: o número, o console e desde quando.
    pub sessoes: Vec<(IdSessao, Console, u64)>,
}

/// O registro, para o relatório.
pub fn resumos() -> Vec<Resumo> {
    com_tabela(|t| {
        t.pessoas
            .iter()
            .map(|p| Resumo {
                id: p.id,
                nome: p.nome.clone(),
                papel: p.papel.clone(),
                estado: p.estado,
                sessoes: t
                    .sessoes
                    .iter()
                    .filter(|s| s.pessoa == p.id)
                    .map(|s| (s.id, s.console, s.desde_ms))
                    .collect(),
            })
            .collect()
    })
}

/// Registra uma pessoa direto, sem prova, para a suíte montar os casos
/// dela. O caminho com prova tem os casos próprios.
#[cfg(feature = "modo-teste")]
pub fn registrar_de_teste(nome: &str, papel: &str, senha: &[u8]) -> IdPessoa {
    registrar(nome, papel, credencial_de_teste(senha)).expect("a suite registra nomes novos")
}

/// A credencial de uma senha, calculada aqui — para a suíte, que precisa
/// de credenciais e não tem o hospedeiro para calculá-las. Com o custo
/// mínimo: a suíte confere muitas senhas, e o custo não é o que ela testa.
/// A memória de trabalho é de frames, como a do login: o mínimo é 1 MiB, o
/// heap inteiro.
#[cfg(feature = "modo-teste")]
pub fn credencial_de_teste(senha: &[u8]) -> Credencial {
    let custo = Custo::MINIMO;
    let sal = [9; TAM_SAL];
    let mut memoria = crate::grafico::memoria::Memoria::nova((custo.blocos() * 1024) as u64)
        .expect("a suite tem memoria para o argon2id");
    let blocos = memoria.blocos_mut();
    let verificador = credencial::verificador_com_memoria(senha, &sal, custo, blocos)
        .expect("o custo minimo e aceitavel");
    credencial::apagar(blocos);
    Credencial::Senha {
        custo,
        sal,
        verificador,
    }
}

/// Abre uma sessão direto, sem credencial nem limite de tentativas, para a
/// suíte pôr uma pessoa num console sem pagar um Argon2id em cada caso. A
/// pessoa é registrada se ainda não existe. O caminho da credencial tem os
/// casos próprios.
#[cfg(feature = "modo-teste")]
pub fn sessao_de_teste(console: Console, nome: &str, papel: &str) -> IdSessao {
    let id = match com_tabela(|t| t.pessoas.iter().find(|p| p.nome == nome).map(|p| p.id)) {
        Some(id) => id,
        None => registrar_de_teste(nome, papel, b"senha de teste"),
    };
    let mut bytes = [0u8; 8];
    crate::aleatorio::preencher(&mut bytes).expect("a suite tem entropia");
    let sessao = IdSessao(bytes);
    com_tabela(|t| {
        t.sessoes.push(Sessao {
            id: sessao,
            pessoa: id,
            console,
            desde_ms: crate::tempo::uptime_ms(),
        })
    });
    crate::autorizacao::auditar_pessoa(
        Some((&id.texto(), sessao.0)),
        Some(papel),
        "person.login",
        &console.texto(),
        Codigo::Allow,
        "sessao de teste",
    );
    sessao
}

/// Devolve o registro ao que a imagem diz, fecha todas as sessões, e põe de
/// volta a pessoa que a suíte deixa no console físico entre os casos — ver
/// [`crate::interpretador::pessoa_padrao_para_teste`].
#[cfg(feature = "modo-teste")]
pub fn esquecer_registradas() {
    carregar();
    crate::interpretador::pessoa_padrao_para_teste();
}

/// Destrava a tabela à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        TABELA.force_unlock();
    }
}
