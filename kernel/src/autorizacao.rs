//! O ponto único de decisão.
//!
//! # A cadeia
//!
//! ```text
//! identidade → sessão → papel → permissão → operação
//! ```
//!
//! Cada pedido que chega a uma operação protegida passa por aqui, e só por
//! aqui:
//!
//! - os comandos do canal do agente, pela serial e pelas portas
//!   ([`crate::agent`]), e os do interpretador, digitados pela pessoa ou
//!   confirmados por um agente no Terminal ([`crate::interpretador`]): os
//!   dois pedem [`autorizar`], e só o [`Autorizado`] que ela devolve chama o
//!   handler. Não há outro caminho até um handler — o `xtask` confere que a
//!   chamada `(…handler)(` só existe neste arquivo;
//! - as chamadas de sistema de um processo lançado por um agente — abrir um
//!   arquivo, executar um programa —, por [`autorizar_processo`], com a
//!   autoridade de quem o lançou;
//! - o aperto de mão das portas, pelo limite de [`permitir_aperto`];
//! - as operações administrativas, que conferem a prova e então pedem
//!   [`decidir_administracao`] com o papel do administrador.
//!
//! # Tudo vai para a auditoria
//!
//! Permitido ou não. Cada decisão vira um registro na cadeia: quem (sessão,
//! agente, chave, papel), o quê (método e recurso), o código, o BLAKE2s dos
//! parâmetros e um detalhe. Ver [`politica::auditoria`].
//!
//! # O sistema decide como os outros
//!
//! A autoridade local — os processos do sistema: o servidor de janelas, o
//! Terminal — é a máxima, e passa pela mesma conta: o papel dela é o da linha `local` da
//! política, o `sistema`, que enumera cada permissão e o alcance de cada uma.
//! Não há `ALLOW` por ser sistema. A única exceção é o boot do próprio
//! kernel, que carrega a chave, o registro e a política antes de haver o que
//! decidir — ver [`crate::identidade::carregar`] e [`carregar`] —, e esse
//! caminho não é alcançável por processo, agente, console, serial ou
//! pseudo-terminal: o `xtask` confere quem chama cada um.
//!
//! # Sem política no disco
//!
//! Se falta, ou não se lê, vale a de emergência, embutida
//! ([`politica::Politica::emergencia`]): o mesmo `sistema`, com as mesmas
//! permissões enumeradas, para a serial e a autoridade local, e o mesmo
//! `administrador`. Os outros papéis não estão nela: um agente de papel
//! `operador` ou `observador` é recusado; um de papel `sistema` continua o
//! que era — ninguém ganha nem perde papel na emergência.

use alloc::string::{String, ToString};
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use politica::auditoria::{Cadeia, Evento, Titular, resumo_dos_parametros};
use politica::taxa::{Balde, Janela};
use politica::{Codigo, Permissao, Politica};
use spin::Mutex;

use crate::agent::json::{Json, JsonWriter};
use crate::agent::registry::{Acesso, Command};

/// Onde a política mora no disco.
pub const CAMINHO_DA_POLITICA: &str = "/etc/duke/politica";

/// Quantos registros a auditoria guarda na memória. Os que saem pela ponta
/// deixam o elo como âncora — ver [`politica::auditoria`].
pub const CAPACIDADE_DA_AUDITORIA: usize = 1024;

/// As sessões com balde: a serial e as quatro portas.
const SESSOES: usize = 1 + crate::sessoes::PORTAS;

/// A sessão que a auditoria atribui à autoridade local — a pessoa na frente
/// da máquina e os processos do sistema: ela não é uma sessão do canal.
pub const SESSAO_DA_PESSOA: u8 = u8::MAX;

static POLITICA: Mutex<Option<Politica>> = Mutex::new(None);
/// Se a política em vigor veio do disco, ou é a de emergência.
static DO_DISCO: AtomicBool = AtomicBool::new(false);
static AUDITORIA: Mutex<Option<Cadeia>> = Mutex::new(None);

struct Taxas {
    /// O balde de cada sessão, e de que chave ele é: uma chave nova na
    /// mesma porta começa com um balde novo, e a mesma chave que reconecta
    /// continua com o que tinha — reconectar não enche o balde.
    baldes: [Option<(Option<[u8; 32]>, Balde)>; SESSOES],
    /// Pedidos recusados por taxa desde o último registro de taxa: a
    /// auditoria grava o primeiro e soma os seguintes, para uma enxurrada
    /// não empurrar para fora do anel o que importa.
    suprimidos: [u64; SESSOES],
    janelas: [Janela; crate::sessoes::PORTAS],
    apertos_suprimidos: [u64; crate::sessoes::PORTAS],
}

static TAXAS: Mutex<Taxas> = Mutex::new(Taxas {
    baldes: [None; SESSOES],
    suprimidos: [0; SESSOES],
    janelas: [Janela::NOVA; crate::sessoes::PORTAS],
    apertos_suprimidos: [0; crate::sessoes::PORTAS],
});

/// Com que autoridade algo roda.
///
/// `Copy`, sem nada no heap: ela vai dentro de cada fio, e é copiada com a
/// trava do escalonador na mão — ver `crate::fios`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Autoridade {
    /// A autoridade local: um processo lançado pelo sistema — o servidor de
    /// janelas, o Terminal. É a máxima, e **não** é um passe livre: decide
    /// pela política como as outras, com o papel da linha `local` — o
    /// `sistema`, que enumera o que pode —, e vai para a auditoria.
    Sistema,
    /// Uma sessão do canal, e o que ela lançou: a serial (`chave` vazia) ou
    /// uma porta, com a chave de quem provou o aperto. O papel não é
    /// guardado, nem o nome: são procurados a cada decisão, para que uma
    /// revogação ou uma troca de papel valham na hora — também para o
    /// processo já lançado.
    Sessao { sessao: u8, chave: Option<[u8; 32]> },
    /// Uma pessoa, pela sessão que ela abriu num console, e o que ela
    /// lançou. Como a de um agente, o papel é procurado a cada decisão: a
    /// sessão que acaba — a pessoa sai, é revogada, o console fecha — leva
    /// junto a autoridade dos processos que ela lançou.
    Pessoa { sessao: crate::pessoas::IdSessao },
}

impl Autoridade {
    /// A menor que há: uma porta sem chave, que papel nenhum tem. Para um
    /// fio cuja origem não se lê — o que não deveria acontecer, e se
    /// acontecer, recusa tudo.
    pub const NENHUMA: Autoridade = Autoridade::Sessao {
        sessao: u8::MAX,
        chave: None,
    };
}

/// A autoridade de quem está executando um comando agora — ver
/// [`Autorizado::executar`]. É o que `user.run` grava no processo que lança.
static AUTORIDADE_ATUAL: Mutex<Autoridade> = Mutex::new(Autoridade::Sistema);

/// A autoridade do comando em execução.
pub fn autoridade_atual() -> Autoridade {
    crate::arch::sem_interrupcoes(|| *AUTORIDADE_ATUAL.lock())
}

/// Quem está numa decisão, como a auditoria o grava.
struct Quem {
    titular: Titular,
    sessao: u8,
    sessao_de_pessoa: Option<[u8; 8]>,
    agente: String,
    chave: Option<[u8; 32]>,
    papel: Option<String>,
}

/// Roda `f` com a política em vigor.
pub fn com_politica<R>(f: impl FnOnce(&Politica) -> R) -> R {
    crate::arch::sem_interrupcoes(|| match POLITICA.lock().as_ref() {
        Some(p) => f(p),
        None => f(&Politica::emergencia()),
    })
}

/// Troca a política em vigor por outra, já validada. A troca é inteira: a
/// decisão seguinte vê a nova, e a que estava em curso já tinha decidido.
pub fn trocar_politica(nova: Politica) {
    let velha = crate::arch::sem_interrupcoes(|| POLITICA.lock().replace(nova));
    drop(velha);
}

/// Se a política em vigor veio do disco.
pub fn politica_do_disco() -> bool {
    DO_DISCO.load(Ordering::Relaxed)
}

/// Lê a política do disco. No boot, depois do registro de identidades.
pub fn carregar() {
    crate::arch::sem_interrupcoes(|| {
        let mut a = AUDITORIA.lock();
        if a.is_none() {
            *a = Some(Cadeia::nova(CAPACIDADE_DA_AUDITORIA));
        }
    });
    let sistema = Quem {
        titular: Titular::Kernel,
        sessao: SESSAO_DA_PESSOA,
        sessao_de_pessoa: None,
        agente: "kernel".to_string(),
        chave: None,
        papel: None,
    };
    let (politica, codigo, detalhe, resumo) = match crate::vfs::ler_tudo(CAMINHO_DA_POLITICA) {
        Ok(bytes) => {
            let resumo = bytes.clone();
            match core::str::from_utf8(&bytes)
                .map_err(|_| "a politica nao e texto".to_string())
                .and_then(|t| Politica::ler(t).map_err(|e| e.motivo()))
            {
                Ok(p) => (p, Codigo::Allow, String::new(), resumo),
                Err(motivo) => (Politica::emergencia(), Codigo::DenyPolicy, motivo, resumo),
            }
        }
        Err(e) => (
            Politica::emergencia(),
            Codigo::DenyPolicy,
            e.motivo().to_string(),
            alloc::vec::Vec::new(),
        ),
    };
    let do_disco = codigo.permite();
    if do_disco {
        crate::log_info!(
            "politica",
            "{} papeis, serial como `{}`",
            politica.papeis().len(),
            politica.serial()
        );
    } else {
        crate::log_error!(
            "politica",
            "{}: {}; vale a de emergencia",
            CAMINHO_DA_POLITICA,
            detalhe
        );
    }
    DO_DISCO.store(do_disco, Ordering::Relaxed);
    trocar_politica(politica);
    auditar(
        &sistema,
        "policy.load",
        CAMINHO_DA_POLITICA,
        codigo,
        &resumo,
        &detalhe,
    );
}

/// O maior recurso que a auditoria grava, em bytes. O recurso vem do pedido
/// — um caminho, um número —, e um pedido hostil poderia mandar um caminho
/// de quinhentos bytes para encher o anel com menos registros.
const MAIOR_RECURSO: usize = 128;

/// Corta um texto em `teto` bytes, numa fronteira de caractere.
fn cortado(texto: &str, teto: usize) -> &str {
    if texto.len() <= teto {
        return texto;
    }
    let mut fim = teto;
    while !texto.is_char_boundary(fim) {
        fim -= 1;
    }
    &texto[..fim]
}

/// Grava uma decisão na cadeia.
fn auditar(
    quem: &Quem,
    metodo: &str,
    recurso: &str,
    codigo: Codigo,
    parametros: &[u8],
    detalhe: &str,
) {
    let recurso = cortado(recurso, MAIOR_RECURSO);
    let metodo = cortado(metodo, MAIOR_RECURSO);
    let evento = Evento {
        ts_ms: crate::tempo::uptime_ms(),
        titular: quem.titular,
        sessao: quem.sessao,
        sessao_de_pessoa: quem.sessao_de_pessoa,
        agente: quem.agente.clone(),
        chave: quem.chave,
        papel: quem.papel.clone().unwrap_or_default(),
        metodo: metodo.to_string(),
        recurso: recurso.to_string(),
        codigo,
        parametros: resumo_dos_parametros(parametros),
        detalhe: detalhe.to_string(),
    };
    crate::arch::sem_interrupcoes(|| {
        if let Some(c) = AUDITORIA.lock().as_mut() {
            c.anexar(evento);
        }
    });
}

/// Roda `f` com a cadeia da auditoria.
pub fn com_auditoria<R>(f: impl FnOnce(&Cadeia) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| AUDITORIA.lock().as_ref().map(f))
}

/// Quem está na sessão `sessao`. `Err` com o que se sabe, se a sessão não é
/// autenticada — uma porta sem aperto completo.
fn quem_da_sessao(sessao: u8) -> Result<Quem, Quem> {
    if sessao == crate::agent::sessao::SERIAL {
        return Ok(Quem {
            titular: Titular::Serial,
            sessao,
            sessao_de_pessoa: None,
            agente: "serial".to_string(),
            chave: None,
            papel: Some(com_politica(|p| p.serial().to_string())),
        });
    }
    match crate::sessoes::identidade(sessao) {
        // A chave saiu do registro depois do aperto: a revogação vale na
        // hora, mesmo que a sessão ainda não tenha sido derrubada.
        Some(id) if crate::identidade::agente(&id.chave).is_none() => Err(Quem {
            titular: Titular::Agente,
            sessao,
            sessao_de_pessoa: None,
            agente: id.nome,
            chave: Some(id.chave),
            papel: None,
        }),
        Some(id) => Ok(Quem {
            titular: Titular::Agente,
            sessao,
            sessao_de_pessoa: None,
            papel: crate::identidade::papel_do_agente(&id.chave),
            agente: id.nome,
            chave: Some(id.chave),
        }),
        None => Err(Quem {
            titular: Titular::Anonimo,
            sessao,
            sessao_de_pessoa: None,
            agente: String::new(),
            chave: None,
            papel: None,
        }),
    }
}

/// Quem é uma sessão de pessoa, procurada agora. `Err` com o que se sabe,
/// se a sessão não vale mais.
fn quem_da_pessoa(id: crate::pessoas::IdSessao) -> Result<Quem, Quem> {
    match crate::pessoas::sessao(id) {
        crate::pessoas::EstadoDaSessao::Ativa { pessoa, papel, .. } => Ok(Quem {
            titular: Titular::Pessoa,
            sessao: SESSAO_DA_PESSOA,
            sessao_de_pessoa: Some(id.0),
            agente: pessoa.texto(),
            chave: None,
            papel: Some(papel),
        }),
        _ => Err(Quem {
            titular: Titular::Anonimo,
            sessao: SESSAO_DA_PESSOA,
            sessao_de_pessoa: Some(id.0),
            agente: crate::pessoas::dona_da_sessao(id)
                .map(|p| p.texto())
                .unwrap_or_default(),
            chave: None,
            papel: None,
        }),
    }
}

/// Ninguém num console: o titular de um pedido feito antes do login.
fn quem_sem_login() -> Quem {
    Quem {
        titular: Titular::Anonimo,
        sessao: SESSAO_DA_PESSOA,
        sessao_de_pessoa: None,
        agente: String::new(),
        chave: None,
        papel: None,
    }
}

/// A autoridade local, com o papel que a política dá a ela agora: o dos
/// processos do sistema.
fn quem_local(agente: &str) -> Quem {
    Quem {
        titular: Titular::Sistema,
        sessao: SESSAO_DA_PESSOA,
        sessao_de_pessoa: None,
        agente: agente.to_string(),
        chave: None,
        papel: Some(com_politica(|p| p.local().to_string())),
    }
}

/// Quem é uma autoridade de sessão, procurado agora: o nome e o papel do
/// registro de hoje. Uma chave revogada não tem nenhum dos dois, e o papel
/// vazio recusa.
fn quem_da_autoridade(sessao: u8, chave: Option<[u8; 32]>) -> Quem {
    match (sessao, chave) {
        (crate::agent::sessao::SERIAL, None) => Quem {
            titular: Titular::Serial,
            sessao,
            sessao_de_pessoa: None,
            agente: "serial".to_string(),
            chave: None,
            papel: Some(com_politica(|p| p.serial().to_string())),
        },
        (_, Some(k)) => Quem {
            titular: Titular::Agente,
            sessao,
            sessao_de_pessoa: None,
            agente: crate::identidade::agente(&k).unwrap_or_else(|| "(revogado)".to_string()),
            chave: Some(k),
            papel: crate::identidade::papel_do_agente(&k),
        },
        (_, None) => Quem {
            titular: Titular::Anonimo,
            sessao,
            sessao_de_pessoa: None,
            agente: String::new(),
            chave: None,
            papel: None,
        },
    }
}

/// Gasta uma ficha do balde da sessão. `Err` se não havia. Na volta de uma
/// sequência recusada, grava quantas foram — ver [`Taxas::suprimidos`].
fn passar_pela_taxa(quem: &Quem, metodo: &str, parametros: &[u8]) -> Result<(), Codigo> {
    let Some(papel) = quem.papel.as_deref() else {
        // Sem papel não há taxa a aplicar: a decisão vai recusar.
        return Ok(());
    };
    let taxa = com_politica(|p| p.papel(papel).map(|r| r.taxa));
    let Some(taxa) = taxa else {
        return Ok(());
    };
    let i = usize::from(quem.sessao);
    if i >= SESSOES {
        return Ok(());
    }
    let agora = crate::tempo::uptime_ms();
    let (passou, suprimidos_antes, primeiro_recusado) = crate::arch::sem_interrupcoes(|| {
        let mut t = TAXAS.lock();
        let (dono, balde) =
            t.baldes[i].get_or_insert_with(|| (quem.chave, Balde::novo(taxa, agora)));
        // Outra chave na porta, ou o papel mudou de taxa: um balde novo,
        // cheio, com a taxa de agora.
        if *dono != quem.chave || balde.taxa() != taxa {
            *dono = quem.chave;
            *balde = Balde::novo(taxa, agora);
        }
        if balde.tentar(agora) {
            let s = core::mem::take(&mut t.suprimidos[i]);
            (true, s, false)
        } else {
            t.suprimidos[i] += 1;
            (false, 0, t.suprimidos[i] == 1)
        }
    });
    if passou {
        if suprimidos_antes > 1 {
            auditar(
                quem,
                metodo,
                "",
                Codigo::RateLimit,
                &[],
                &alloc::format!("{} pedidos recusados por taxa", suprimidos_antes),
            );
        }
        return Ok(());
    }
    if primeiro_recusado {
        auditar(
            quem,
            metodo,
            "",
            Codigo::RateLimit,
            parametros,
            "taxa do papel esgotada",
        );
    }
    Err(Codigo::RateLimit)
}

/// O recurso de um pedido, como texto: o valor do parâmetro que o comando
/// declarou — **cru**, exatamente como o handler o lê (`as_str`), e não
/// desescapado. A decisão tem de ser sobre o mesmo valor que a operação
/// usa: um caminho com `\u002e` decidido na forma desescapada e aberto na
/// crua seria a diferença por onde um prefixo escaparia. Um valor que não é
/// texto — um número — vai como foi escrito.
fn recurso_do_pedido(comando: &Command, params: Json) -> String {
    let Some(nome) = comando.recurso else {
        return String::new();
    };
    let Some(valor) = params.member(nome) else {
        return String::new();
    };
    match valor.as_str() {
        Some(texto) => texto.to_string(),
        None => core::str::from_utf8(valor.0)
            .unwrap_or("")
            .trim()
            .to_string(),
    }
}

/// A decisão sobre uma permissão e um recurso, com a regra que vale para
/// todo papel: o diretório reservado do kernel não é recurso de ninguém.
fn decidir(papel: Option<&str>, permissao: Permissao, recurso: &str) -> (Codigo, &'static str) {
    if permissao.recurso_e_caminho()
        && politica::caminho::normalizar(recurso).is_some_and(|c| crate::vfs::reservado(&c))
    {
        return (Codigo::DenyResource, "reservado ao kernel");
    }
    let codigo = com_politica(|p| p.decidir(papel, permissao, Some(recurso)));
    let detalhe = match codigo {
        Codigo::DenyRole => "sem papel, ou papel que a politica nao tem",
        Codigo::DenyPermission => "o papel nao tem a permissao",
        Codigo::DenyResource => "recurso fora do alcance do papel",
        _ => "",
    };
    (codigo, detalhe)
}

/// Quem pede um comando.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chamador {
    /// Uma sessão do canal: a serial, uma porta, ou um agente confirmando
    /// no Terminal — que age como a sessão dele.
    Sessao(u8),
    /// Uma pessoa, pela sessão que ela abriu num console.
    Pessoa(crate::pessoas::IdSessao),
}

/// A licença para executar um comando: só [`autorizar`] a cria, e só ela
/// chama o handler.
pub struct Autorizado {
    comando: &'static Command,
    autoridade: Autoridade,
}

impl Autorizado {
    /// Executa o comando com a autoridade de quem pediu — que `user.run`,
    /// por exemplo, grava no processo que lança.
    pub fn executar(self, params: Json, w: &mut JsonWriter) -> fmt::Result {
        let anterior = crate::arch::sem_interrupcoes(|| {
            core::mem::replace(&mut *AUTORIDADE_ATUAL.lock(), self.autoridade)
        });
        let r = (self.comando.handler)(params, w);
        crate::arch::sem_interrupcoes(|| *AUTORIDADE_ATUAL.lock() = anterior);
        r
    }
}

/// Decide um comando. `Ok` com a licença para executá-lo; `Err` com o código
/// da recusa. A decisão vai para a auditoria nos dois casos.
pub fn autorizar(
    chamador: Chamador,
    comando: &'static Command,
    params: Json,
) -> Result<Autorizado, Codigo> {
    let parametros = params.0;
    // Quem pede, e com que autoridade o comando roda se passar. A pessoa
    // decide pelo papel dela no registro, procurado agora pela sessão — a
    // mesma conta dos agentes, e a mesma auditoria.
    let (quem, autoridade) = match chamador {
        Chamador::Pessoa(id) => match quem_da_pessoa(id) {
            Ok(q) => (q, Autoridade::Pessoa { sessao: id }),
            Err(q) => {
                auditar(
                    &q,
                    comando.nome,
                    "",
                    Codigo::DenyNotAuthenticated,
                    parametros,
                    "sessao de pessoa que acabou",
                );
                return Err(Codigo::DenyNotAuthenticated);
            }
        },
        Chamador::Sessao(sessao) => match quem_da_sessao(sessao) {
            Ok(q) => {
                let chave = q.chave;
                (q, Autoridade::Sessao { sessao, chave })
            }
            Err(q) => {
                let detalhe = if q.chave.is_some() {
                    "chave revogada"
                } else {
                    "sessao sem aperto"
                };
                auditar(
                    &q,
                    comando.nome,
                    "",
                    Codigo::DenyNotAuthenticated,
                    parametros,
                    detalhe,
                );
                return Err(Codigo::DenyNotAuthenticated);
            }
        },
    };
    passar_pela_taxa(&quem, comando.nome, parametros)?;

    let recurso = recurso_do_pedido(comando, params);
    let (codigo, detalhe) = match comando.acesso {
        // A prova é conferida dentro da operação, e a decisão dela é
        // gravada lá, com o papel do administrador.
        Acesso::PorProva => (Codigo::Allow, "a autorizacao e a prova"),
        Acesso::Exige(permissao) => decidir(quem.papel.as_deref(), permissao, &recurso),
    };
    auditar(&quem, comando.nome, &recurso, codigo, parametros, detalhe);
    if !codigo.permite() {
        return Err(codigo);
    }
    Ok(Autorizado {
        comando,
        autoridade,
    })
}

/// Grava um pedido que não chegou a ser um comando: JSON quebrado, método
/// desconhecido, parâmetros recusados. `INVALID_ARGUMENT`.
pub fn auditar_invalido(chamador: Chamador, metodo: &str, parametros: &[u8], detalhe: &str) {
    let quem = match chamador {
        Chamador::Pessoa(id) => match quem_da_pessoa(id) {
            Ok(q) | Err(q) => q,
        },
        Chamador::Sessao(s) => match quem_da_sessao(s) {
            Ok(q) | Err(q) => q,
        },
    };
    auditar(
        &quem,
        metodo,
        "",
        Codigo::InvalidArgument,
        parametros,
        detalhe,
    );
}

/// Decide uma chamada de sistema de um processo: abrir um arquivo, executar
/// um programa, prender-se ao pseudo-terminal. Com a autoridade do processo,
/// que é a de quem o lançou.
///
/// Um processo do sistema — o servidor de janelas, o Terminal, o que a
/// pessoa lançou — decide pelo papel da autoridade local, e vai para a
/// auditoria como os outros: a autoridade dele é a máxima que a política
/// enumera, e não um passe livre. O de um agente decide pelo papel do
/// agente, procurado agora.
pub fn autorizar_processo(permissao: Permissao, recurso: &str, metodo: &str) -> Codigo {
    let quem = match crate::fios::autoridade_atual() {
        Autoridade::Sistema => quem_local("sistema"),
        Autoridade::Sessao { sessao, chave } => quem_da_autoridade(sessao, chave),
        // Uma sessão que acabou não tem papel, e o papel vazio recusa.
        Autoridade::Pessoa { sessao } => match quem_da_pessoa(sessao) {
            Ok(q) | Err(q) => q,
        },
    };
    let (codigo, detalhe) = decidir(quem.papel.as_deref(), permissao, recurso);
    auditar(&quem, metodo, recurso, codigo, &[], detalhe);
    codigo
}

/// Recusa um pedido feito num console sem ninguém entrado: só `login` e
/// `ajuda` passam antes do login, e o resto — um comando, conhecido ou não —
/// é `DENY_NOT_AUTHENTICATED`, gravado com o console.
pub fn recusar_sem_login(console: crate::pessoas::Console, metodo: &str, parametros: &[u8]) {
    auditar(
        &quem_sem_login(),
        metodo,
        &console.texto(),
        Codigo::DenyNotAuthenticated,
        parametros,
        "ninguem entrou no console",
    );
}

/// Decide uma ação da pessoa de um console na interface — uma tecla de
/// função, um clique num botão da barra —: `ui.act` sobre o elemento, com a
/// sessão de quem está no console. Sem ninguém entrado, ou com uma sessão
/// que acabou, `DENY_NOT_AUTHENTICATED`. Grava nos dois casos.
pub fn autorizar_acao_da_pessoa(
    console: crate::pessoas::Console,
    sessao: Option<crate::pessoas::IdSessao>,
    elemento: u32,
) -> Codigo {
    let recurso = alloc::format!("{} elemento {}", console.texto(), elemento);
    let quem = match sessao.map(quem_da_pessoa) {
        Some(Ok(q)) => q,
        Some(Err(q)) => {
            auditar(
                &q,
                "ui.act",
                &recurso,
                Codigo::DenyNotAuthenticated,
                &[],
                "sessao de pessoa que acabou",
            );
            return Codigo::DenyNotAuthenticated;
        }
        None => {
            auditar(
                &quem_sem_login(),
                "ui.act",
                &recurso,
                Codigo::DenyNotAuthenticated,
                &[],
                "ninguem entrou no console",
            );
            return Codigo::DenyNotAuthenticated;
        }
    };
    let (codigo, detalhe) = decidir(quem.papel.as_deref(), Permissao::UiAct, "");
    auditar(&quem, "ui.act", &recurso, codigo, &[], detalhe);
    codigo
}

/// Conta um aperto de mão na janela da porta `p`. Falso se passou do
/// limite da política — e grava o primeiro da sequência.
pub fn permitir_aperto(p: u8) -> bool {
    let Some(i) = (1..=crate::sessoes::PORTAS as u8)
        .contains(&p)
        .then(|| usize::from(p) - 1)
    else {
        return false;
    };
    let limite = com_politica(|pol| pol.apertos());
    let agora = crate::tempo::uptime_ms();
    let (passou, primeiro) = crate::arch::sem_interrupcoes(|| {
        let mut t = TAXAS.lock();
        if t.janelas[i].contar(limite, agora) {
            t.apertos_suprimidos[i] = 0;
            (true, false)
        } else {
            t.apertos_suprimidos[i] += 1;
            (false, t.apertos_suprimidos[i] == 1)
        }
    });
    if !passou && primeiro {
        let quem = Quem {
            titular: Titular::Anonimo,
            sessao: p,
            sessao_de_pessoa: None,
            agente: String::new(),
            chave: None,
            papel: None,
        };
        auditar(
            &quem,
            "session.open",
            "",
            Codigo::RateLimit,
            &[],
            "apertos demais na janela",
        );
    }
    passou
}

/// Grava um aperto de mão: o que entrou, ou o que foi recusado e por quê.
pub fn auditar_aperto(p: u8, chave: Option<[u8; 32]>, nome: &str, codigo: Codigo, detalhe: &str) {
    let papel = match (&chave, codigo) {
        (Some(k), Codigo::Allow) => crate::identidade::papel_do_agente(k),
        _ => None,
    };
    // Um aperto que entrou é de um agente; um recusado, de ninguém ainda —
    // o nome e a chave dizem o que ele alegou.
    let titular = if codigo.permite() {
        Titular::Agente
    } else {
        Titular::Anonimo
    };
    let quem = Quem {
        titular,
        sessao: p,
        sessao_de_pessoa: None,
        agente: nome.to_string(),
        chave,
        papel,
    };
    auditar(&quem, "session.open", "", codigo, &[], detalhe);
}

/// Decide uma operação administrativa, já com a prova conferida: o papel do
/// administrador tem a permissão? Não grava: quem grava é a operação, uma
/// vez, com o desfecho inteiro — ver [`auditar_administracao`].
pub fn decidir_administracao(papel: Option<&str>, permissao: Permissao) -> Codigo {
    com_politica(|p| p.decidir(papel, permissao, None))
}

/// Grava um desfecho de operação administrativa. `administrador` vazio
/// quando a recusa veio antes de se saber quem era.
#[allow(clippy::too_many_arguments)]
pub fn auditar_administracao(
    sessao: u8,
    administrador: Option<(&str, &[u8; 32])>,
    papel: Option<&str>,
    metodo: &str,
    recurso: &str,
    codigo: Codigo,
    parametros: &[u8],
    detalhe: &str,
) {
    // Sem administrador conhecido — a prova não conferiu —, ninguém ainda.
    let titular = if administrador.is_some() {
        Titular::Administrador
    } else {
        Titular::Anonimo
    };
    let quem = Quem {
        titular,
        sessao,
        sessao_de_pessoa: None,
        agente: administrador.map(|a| a.0.to_string()).unwrap_or_default(),
        chave: administrador.map(|a| *a.1),
        papel: papel.map(ToString::to_string),
    };
    auditar(&quem, metodo, recurso, codigo, parametros, detalhe);
}

/// Grava um desfecho de sessão de pessoa: o login, a saída, uma tentativa
/// recusada por limite. Com a pessoa e a sessão, o titular é a pessoa; sem,
/// é ninguém ainda — um console sem login.
pub fn auditar_pessoa(
    pessoa: Option<(&str, [u8; 8])>,
    papel: Option<&str>,
    metodo: &str,
    recurso: &str,
    codigo: Codigo,
    detalhe: &str,
) {
    let quem = Quem {
        titular: if pessoa.is_some() {
            Titular::Pessoa
        } else {
            Titular::Anonimo
        },
        sessao: SESSAO_DA_PESSOA,
        sessao_de_pessoa: pessoa.map(|p| p.1),
        agente: pessoa.map(|p| p.0.to_string()).unwrap_or_default(),
        chave: None,
        papel: papel.map(ToString::to_string),
    };
    auditar(&quem, metodo, recurso, codigo, &[], detalhe);
}

/// Grava um login recusado. O titular é ninguém — não houve autenticação —,
/// e o identificador é o da pessoa que se tentou ser, se o nome era de
/// alguém: é o que mostra uma pessoa sendo atacada. Um nome que não é de
/// ninguém não é gravado.
pub fn auditar_pessoa_recusada(alvo: Option<&str>, metodo: &str, recurso: &str, detalhe: &str) {
    let quem = Quem {
        titular: Titular::Anonimo,
        sessao: SESSAO_DA_PESSOA,
        sessao_de_pessoa: None,
        agente: alvo.unwrap_or_default().to_string(),
        chave: None,
        papel: None,
    };
    auditar(
        &quem,
        metodo,
        recurso,
        Codigo::DenyNotAuthenticated,
        &[],
        detalhe,
    );
}

/// Muda a política em vigor por uma conta sobre ela, numa seção só: ler a
/// de agora, validar a nova e trocar acontecem sem outra mudança no meio.
/// Uma recusa deixa a de agora como estava.
pub fn mudar_politica<E>(f: impl FnOnce(&Politica) -> Result<Politica, E>) -> Result<(), E> {
    let velha = crate::arch::sem_interrupcoes(|| {
        let mut guarda = POLITICA.lock();
        let nova = match guarda.as_ref() {
            Some(p) => f(p),
            None => f(&Politica::emergencia()),
        }?;
        Ok(guarda.replace(nova))
    })?;
    // A velha sai fora da seção: largar uma política é devolver memória.
    drop(velha);
    Ok(())
}

/// Destrava a política, a auditoria e as taxas à força, para uso exclusivo
/// do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        POLITICA.force_unlock();
        AUDITORIA.force_unlock();
        TAXAS.force_unlock();
        AUTORIDADE_ATUAL.force_unlock();
    }
}
