//! A coordenação: versões e arrendamentos dos recursos compartilhados, no
//! kernel.
//!
//! A conta é a de [`politica::arrendamento`]; aqui ela ganha o relógio, o
//! titular de cada pedido e a auditoria. Tudo o que muda a tabela passa por
//! este módulo — o `xtask invariantes` confere —, e cada evento vai para a
//! auditoria: tomar, soltar, a recusa de tomar, o conflito de versão, o
//! arrendamento vencido, o invalidado por revogação, a ação sem o
//! arrendamento que ela pede, e a mudança feita — a confirmação, com a
//! versão nova, e sem o texto.
//!
//! # Os recursos
//!
//! Cada elemento editável da árvore semântica é um recurso, pelo número
//! dele: `ui:3` é a linha de comando do console físico; `ui:<n>` um campo
//! de janela, como a linha de comando de um Terminal. O nome é o mesmo que
//! o agente vê em `ui.tree`.
//!
//! # A regra das edições
//!
//! - **Editar** — digitar, `set_value`, `cancel` — num recurso livre o
//!   arrenda, implicitamente, para quem editou: a primeira tecla de uma
//!   pessoa, o primeiro `set_value` de um agente. O arrendamento implícito
//!   vai para a auditoria uma vez; as teclas seguintes o renovam, sem
//!   registro cada uma.
//! - Num recurso arrendado por outro: `CONFLICT`, e nada muda — a tecla não
//!   substitui em silêncio quem estava ali.
//! - **Confirmar** pede o arrendamento: quem confirma é quem editou, ou quem
//!   tomou com `ui.claim`. Confirmado, o arrendamento é solto: a linha volta
//!   vazia e livre.
//! - Uma edição recusada não arrenda o campo. A que o console de um Terminal
//!   recusa depois de ela entrar — a regra da linha da pessoa, conferida de
//!   novo quando o que o Terminal digitou chega a ele — solta o arrendamento
//!   que ela mesma tomou, e só ele: ver [`soltar_o_da_edicao_recusada`].
//!
//! Pessoa e agente seguem a mesma regra, sem prioridade entre eles; e o
//! `sistema` não tem passe: quebrar o arrendamento de outro é
//! `lease.revoke`, uma operação administrativa com prova.

use alloc::format;
use alloc::string::String;

use crate::trava::Mutex;
use politica::Codigo;
use politica::arrendamento::{Arrendamento, Estado, Recusa, Tabela, Titular, Vencido};

use crate::pessoas::{Console, IdSessao};
use crate::ui::Origem;

/// O prazo do arrendamento implícito de uma edição. Renovado a cada tecla.
pub const PRAZO_IMPLICITO_MS: u64 = 60_000;

/// O prazo de um `ui.claim` que não diz o seu.
pub const PRAZO_PADRAO_MS: u64 = 30_000;

static TABELA: Mutex<Tabela> = Mutex::new(Tabela::nova());

fn com_tabela<R>(f: impl FnOnce(&mut Tabela) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut TABELA.lock()))
}

/// O nome do recurso de um elemento da árvore.
pub fn recurso(elemento: u32) -> String {
    format!("ui:{elemento}")
}

/// O nome do recurso de um arquivo do armazém, pelo caminho inteiro na
/// forma normal: `fs:/armazem/compartilhado/notas.txt`. Ver
/// [`crate::armazem`].
pub fn recurso_do_caminho(caminho: &str) -> String {
    format!("fs:{caminho}")
}

/// O titular de uma sessão do canal: a chave que provou o aperto, ou a
/// serial, sem chave. `None` para uma porta sem aperto.
pub fn titular_do_agente(sessao: u8) -> Option<Titular> {
    if sessao == crate::agent::sessao::SERIAL {
        return Some(Titular::Agente {
            sessao,
            chave: None,
        });
    }
    crate::sessoes::identidade(sessao).map(|id| Titular::Agente {
        sessao,
        chave: Some(id.chave),
    })
}

/// O titular de quem um comando age por: a autoridade que o gate decidiu,
/// e não o canal por onde o pedido chegou.
///
/// - um agente, pela chave que ele provou — a mesma chave, e não quem
///   estiver hoje na porta: o processo de um agente que desconectou não
///   arrenda como o agente que entrou depois na mesma porta;
/// - a serial;
/// - uma pessoa, pela sessão dela, se ainda vale;
/// - o sistema não tem titular: a autoridade local não arrenda.
///
/// # Por que não pelo canal
///
/// Era pelo canal — `titular_do_agente(sessao::atual())` —, e a sessão do
/// canal é a do despachante: uma pessoa que pedia `ui.claim` no
/// interpretador, onde ninguém a punha, arrendava o campo como a serial.
pub fn titular_da_autoridade(autoridade: crate::autorizacao::Autoridade) -> Option<Titular> {
    use crate::autorizacao::Autoridade;
    match autoridade {
        Autoridade::Sistema => None,
        Autoridade::Sessao {
            sessao: crate::agent::sessao::SERIAL,
            chave: None,
        } => Some(Titular::Agente {
            sessao: crate::agent::sessao::SERIAL,
            chave: None,
        }),
        Autoridade::Sessao { chave: None, .. } => None,
        Autoridade::Sessao {
            sessao,
            chave: Some(k),
        } => Some(Titular::Agente {
            sessao,
            chave: Some(k),
        }),
        Autoridade::Pessoa { sessao } => titular_da_pessoa(sessao),
        // Um serviço não arrenda nada: não é quem edita. Nem outro
        // dispositivo: só a malha lhe responde.
        Autoridade::Servico(_) | Autoridade::Remoto { .. } => None,
    }
}

/// O titular de uma sessão de pessoa, se ela ainda vale.
pub fn titular_da_pessoa(sessao: IdSessao) -> Option<Titular> {
    match crate::pessoas::sessao(sessao) {
        crate::pessoas::EstadoDaSessao::Ativa { pessoa, .. } => Some(Titular::Pessoa {
            sessao: sessao.0,
            pessoa: pessoa.0,
        }),
        _ => None,
    }
}

/// Quem age: o agente da sessão, ou a pessoa entrada no console.
pub fn titular(origem: Origem, console: Console) -> Option<Titular> {
    match origem {
        Origem::Agente(sessao) => titular_do_agente(sessao),
        Origem::Pessoa => crate::interpretador::sessao_valida(console).and_then(titular_da_pessoa),
    }
}

/// Quantos arrendamentos válidos a sessão `sessao` do canal tem agora,
/// com a chave `chave` — para o `agent.list`.
pub fn quantos_do_agente(sessao: u8, chave: [u8; 32]) -> usize {
    let agora = crate::tempo::uptime_ms();
    let dele = Titular::Agente {
        sessao,
        chave: Some(chave),
    };
    com_tabela(|t| {
        t.arrendados(agora)
            .filter(|(_, e)| e.arrendamento.is_some_and(|a| a.titular == dele))
            .count()
    })
}

/// O texto de um titular, para o relatório: o tipo e o identificador.
pub fn descrever(t: &Titular) -> (&'static str, String) {
    match t {
        Titular::Pessoa { pessoa, .. } => ("person", sigilo::pessoas::IdPessoa(*pessoa).texto()),
        Titular::Agente {
            sessao,
            chave: None,
        } => ("agent", format!("serial:{sessao}")),
        Titular::Agente { chave: Some(k), .. } => (
            "agent",
            crate::identidade::agente(k).unwrap_or_else(|| sigilo::hex(k)),
        ),
    }
}

/// Grava um evento de arrendamento, em nome de `titular` — ou de ninguém,
/// para uma pessoa sem login.
fn gravar(titular: Option<&Titular>, metodo: &str, recurso: &str, codigo: Codigo, detalhe: &str) {
    crate::autorizacao::auditar_arrendamento(titular, metodo, recurso, codigo, detalhe);
}

fn gravar_vencido(recurso: &str, vencido: Option<Vencido>) {
    if let Some(Vencido(a)) = vencido {
        gravar(
            Some(&a.titular),
            "lease.expire",
            recurso,
            Codigo::Allow,
            "o prazo venceu",
        );
    }
}

/// O estado de um recurso agora.
pub fn estado(recurso: &str) -> Estado {
    let agora = crate::tempo::uptime_ms();
    com_tabela(|t| t.estado(recurso, agora))
}

/// `ui.claim`: toma o arrendamento por `prazo_ms`. Do mesmo titular,
/// renova. Grava o desfecho.
pub fn tomar(recurso: &str, titular: Titular, prazo_ms: u64) -> Result<Arrendamento, Codigo> {
    tomar_por(recurso, titular, prazo_ms, "ui.claim")
}

/// [`tomar`], gravado com o método que pediu — `ui.claim`, `fs.claim`.
pub fn tomar_por(
    recurso: &str,
    titular: Titular,
    prazo_ms: u64,
    metodo: &str,
) -> Result<Arrendamento, Codigo> {
    let agora = crate::tempo::uptime_ms();
    let (r, vencido) = com_tabela(|t| t.tomar(recurso, titular, agora, prazo_ms));
    gravar_vencido(recurso, vencido);
    match r {
        Ok(a) => {
            gravar(
                Some(&titular),
                metodo,
                recurso,
                Codigo::Allow,
                "arrendamento tomado",
            );
            Ok(a)
        }
        Err(recusa) => {
            gravar(
                Some(&titular),
                metodo,
                recurso,
                recusa.codigo(),
                recusa.motivo(),
            );
            Err(recusa.codigo())
        }
    }
}

/// `ui.release`: solta o arrendamento, se for de `titular`. Grava.
pub fn soltar(recurso: &str, titular: Titular) -> Result<(), Codigo> {
    soltar_por(recurso, titular, "ui.release")
}

/// [`soltar`], gravado com o método que pediu — `ui.release`, `fs.release`.
pub fn soltar_por(recurso: &str, titular: Titular, metodo: &str) -> Result<(), Codigo> {
    let agora = crate::tempo::uptime_ms();
    let (r, vencido) = com_tabela(|t| t.soltar(recurso, titular, agora));
    gravar_vencido(recurso, vencido);
    match r {
        Ok(_) => {
            gravar(
                Some(&titular),
                metodo,
                recurso,
                Codigo::Allow,
                "arrendamento solto",
            );
            Ok(())
        }
        Err(recusa) => {
            gravar(
                Some(&titular),
                metodo,
                recurso,
                recusa.codigo(),
                recusa.motivo(),
            );
            Err(recusa.codigo())
        }
    }
}

/// Os recursos arrendados agora cujo caminho está abaixo de `caminho` — na
/// forma normal. Um rename leva tudo abaixo da origem, e o que está abaixo
/// do destino passa a existir: o arrendamento de cada um conta.
pub fn arrendados_abaixo(caminho: &str) -> alloc::vec::Vec<String> {
    let agora = crate::tempo::uptime_ms();
    let prefixo = recurso_do_caminho(caminho);
    com_tabela(|t| {
        t.arrendados(agora)
            .filter(|(r, _)| {
                r.len() > prefixo.len()
                    && r.starts_with(prefixo.as_str())
                    && r.as_bytes()[prefixo.len()] == b'/'
            })
            .map(|(r, _)| String::from(r))
            .collect()
    })
}

/// Confere só o arrendamento de `recurso` para uma mudança em nome de
/// `titular` — ou de uma autoridade que não arrenda, `None` —, sem tocar
/// na versão desta tabela: o recurso tem a versão dele em outro lugar (o
/// armazém). O arrendamento do titular é renovado pela atividade; o de
/// outro recusa, com o titular dele.
///
/// Só grava o arrendamento que venceu no caminho: a recusa é gravada por
/// quem chama, como o resultado do comando que ela recusou.
pub fn conferir(recurso: &str, titular: Option<Titular>) -> Result<(), Recusa> {
    let agora = crate::tempo::uptime_ms();
    let (r, vencido) = com_tabela(|t| t.conferir(recurso, titular, agora));
    gravar_vencido(recurso, vencido);
    r
}

/// Uma edição — uma tecla, um `set_value`, um `cancel` — em nome de
/// `titular`: arrenda o recurso livre implicitamente, e confere a versão.
/// Devolve a versão nova.
///
/// Sem titular — uma pessoa num console sem login, digitando o `login` — a
/// edição só passa num recurso livre, e não o arrenda: o arrendamento é de
/// uma sessão autenticada.
pub fn editar(
    recurso: &str,
    titular: Option<Titular>,
    esperada: Option<u64>,
    metodo: &str,
) -> Result<u64, Codigo> {
    editar_com_rastro(recurso, titular, esperada, metodo).map(|r| r.depois.versao)
}

/// O que uma edição fez num recurso: o estado dele logo antes e logo depois
/// dela, lidos na mesma seção da tabela que a fez — a versão e o
/// arrendamento inteiro, com o desde, o vencimento e o prazo —, e de que
/// recurso. É o que identifica o arrendamento que **ela** deixou: ver
/// [`soltar_o_da_edicao_recusada`].
///
/// Os campos são privados, e só [`editar_com_rastro`] o constrói — e
/// [`Rastro::seguida_de`], de dois que ela construiu: quem solta um
/// arrendamento pela recusa de uma edição não escolhe o estado a soltar, e
/// o estado de agora, lido por fora, não solta nada (o achado 8 do
/// adversário do passo 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rastro {
    /// O resumo do nome do recurso — o rastro de um não solta o de outro.
    recurso: u64,
    antes: Estado,
    depois: Estado,
}

/// O FNV-1a de 64 bits do nome de um recurso, para o [`Rastro`] dizer de
/// qual ele é sem guardar o nome.
fn resumo_do_recurso(recurso: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in recurso.as_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

impl Rastro {
    /// A edição tomou o arrendamento: o recurso estava livre, e ficou com o
    /// de quem editou — o implícito.
    pub fn tomou(&self) -> bool {
        self.antes.arrendamento.is_none() && self.depois.arrendamento.is_some()
    }

    /// O estado do recurso logo antes da edição.
    pub fn antes(&self) -> Estado {
        self.antes
    }

    /// O estado do recurso logo depois da edição — o que ela deixou.
    pub fn depois(&self) -> Estado {
        self.depois
    }

    /// As duas edições juntas: `self`, e `depois`, que começou exatamente
    /// onde `self` deixou o recurso — o antes de uma e o depois da outra.
    /// `None` se `depois` não começou ali, ou é de outro recurso. É a edição
    /// que só renovou o arrendamento e não chegou ao programa, somada à que
    /// ela continuou: a sequência das recusadas atravessa a que o console
    /// nunca vai consumir — ver `interpretador::edicao_nao_entregue`.
    pub fn seguida_de(self, depois: Rastro) -> Option<Rastro> {
        (self.recurso == depois.recurso && self.depois == depois.antes).then_some(Rastro {
            recurso: self.recurso,
            antes: self.antes,
            depois: depois.depois,
        })
    }
}

/// [`editar`], devolvendo o [`Rastro`] da edição em vez da versão nova —
/// para quem precisa saber, depois, se o arrendamento do recurso ainda é o
/// que ela deixou: a interface, que entrega a edição ao Terminal de um
/// console, e o console, que a confere de novo quando a consome.
pub fn editar_com_rastro(
    recurso: &str,
    titular: Option<Titular>,
    esperada: Option<u64>,
    metodo: &str,
) -> Result<Rastro, Codigo> {
    let agora = crate::tempo::uptime_ms();
    let Some(titular) = titular else {
        let estado = estado(recurso);
        if estado.arrendamento.is_some() {
            gravar(
                None,
                metodo,
                recurso,
                Codigo::Conflict,
                "outro titular tem o arrendamento",
            );
            return Err(Codigo::Conflict);
        }
        return Ok(Rastro {
            recurso: resumo_do_recurso(recurso),
            antes: estado,
            depois: estado,
        });
    };
    let (implicito, vencido, r) = com_tabela(|t| {
        let mut vencidos = None;
        let antes = t.estado(recurso, agora);
        let implicito = antes.arrendamento.is_none();
        if implicito {
            let (r, v) = t.tomar(recurso, titular, agora, PRAZO_IMPLICITO_MS);
            vencidos = v;
            if let Err(recusa) = r {
                return (false, vencidos, Err(recusa));
            }
        }
        let (r, v) = t.mudar(recurso, titular, esperada, true, agora);
        if implicito && r.is_err() {
            // A edição recusada não deixa o arrendamento que acabou de
            // tomar: a recusa não muda nada.
            let _ = t.soltar(recurso, titular, agora);
        }
        let r = r.map(|_| Rastro {
            recurso: resumo_do_recurso(recurso),
            antes,
            depois: t.estado(recurso, agora),
        });
        (implicito && r.is_ok(), vencidos.or(v), r)
    });
    gravar_vencido(recurso, vencido);
    match r {
        Ok(rastro) => {
            if implicito {
                gravar(
                    Some(&titular),
                    "ui.claim",
                    recurso,
                    Codigo::Allow,
                    "arrendamento implicito pela edicao",
                );
            }
            Ok(rastro)
        }
        Err(recusa) => {
            gravar(
                Some(&titular),
                metodo,
                recurso,
                recusa.codigo(),
                recusa.motivo(),
            );
            Err(recusa.codigo())
        }
    }
}

/// O detalhe do arrendamento que [`soltar_o_da_edicao_recusada`] solta, na
/// auditoria, quando o console recusou a edição pela regra da linha da
/// pessoa.
pub const SOLTO_PELA_RECUSA: &str =
    "arrendamento implicito solto: a edicao pela arvore foi recusada na linha da pessoa";

/// O detalhe, quando a edição contada não chegou à linha — o programa não a
/// recebeu, ou a linha do físico deixou de atender entre a conferência e a
/// edição; a que passou a pedir a pessoa solta com [`SOLTO_PELA_RECUSA`].
pub const SOLTO_SEM_ENTREGA: &str =
    "arrendamento implicito solto: a edicao pela arvore nao chegou a linha";

/// O detalhe, quando quem pediu a edição já não estava na sessão de onde
/// pediu quando o console a consumiu.
pub const SOLTO_FORA_DA_SESSAO: &str =
    "arrendamento implicito solto: quem pediu a edicao pela arvore saiu da sessao";

/// O detalhe, quando quem pediu a edição estava contido quando o console a
/// consumiu — o agente suspenso, a credencial dele ou a da pessoa
/// suspensa.
pub const SOLTO_PELA_CONTENCAO: &str =
    "arrendamento implicito solto: quem pediu a edicao pela arvore foi contido";

/// Por que a edição que tomou o arrendamento não ficou — o detalhe da
/// soltura, na auditoria.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PorQueSolta {
    /// O console a recusou pela regra da linha da pessoa:
    /// [`SOLTO_PELA_RECUSA`].
    LinhaDaPessoa,
    /// Contada, ela não chegou à linha: [`SOLTO_SEM_ENTREGA`].
    NaoChegou,
    /// Quem a pediu saiu da sessão antes de o console a consumir:
    /// [`SOLTO_FORA_DA_SESSAO`].
    ForaDaSessao,
    /// Quem a pediu foi contido antes de o console a consumir:
    /// [`SOLTO_PELA_CONTENCAO`].
    Contido,
}

impl PorQueSolta {
    pub const fn detalhe(self) -> &'static str {
        match self {
            PorQueSolta::LinhaDaPessoa => SOLTO_PELA_RECUSA,
            PorQueSolta::NaoChegou => SOLTO_SEM_ENTREGA,
            PorQueSolta::ForaDaSessao => SOLTO_FORA_DA_SESSAO,
            PorQueSolta::Contido => SOLTO_PELA_CONTENCAO,
        }
    }
}

/// Solta o arrendamento que uma edição recusada deixou — a do campo de um
/// Terminal que o console dele recusou, pela regra da linha da pessoa,
/// quando a consumiu, ou quando a linha passou a pedir a pessoa com ela a
/// caminho; a de quem saiu da sessão; a que não chegou ao programa ou à
/// linha: ver `crate::interpretador` e `crate::ui` —, se o recurso ainda
/// está **exatamente** como ela o deixou: o depois do `rastro`, lido na
/// seção da tabela que a fez — o mesmo titular, desde o mesmo instante, com
/// o mesmo vencimento e o mesmo prazo, e na mesma versão.
///
/// Qualquer coisa depois dela muda um desses: outra edição, a versão; um
/// `ui.claim` do mesmo titular, o vencimento e o prazo; o arrendamento
/// solto e tomado de novo, o desde; o de outro titular, o titular. E aí
/// nada se solta: o arrendamento que outra ação renovou não é mais só o
/// dela, e soltar o de outro é preempção — que não há. Também não se solta
/// o que venceu: o coletor o grava, como sempre. O rastro é o que
/// [`editar_com_rastro`] devolveu, e de `recurso`: o estado não se escolhe.
///
/// Grava como o kernel grava o arrendamento que sai sem pedido do titular —
/// `lease.invalidate`, como a sessão que acabou e a revogação, em nome de
/// quem o tinha —, com o motivo no detalhe ([`PorQueSolta::detalhe`]): não
/// é o `ui.release` que o titular não pediu (o achado 5 do adversário do
/// passo 1). Devolve se soltou.
pub fn soltar_o_da_edicao_recusada(recurso: &str, rastro: &Rastro, motivo: PorQueSolta) -> bool {
    if rastro.recurso != resumo_do_recurso(recurso) {
        return false;
    }
    let depois = rastro.depois;
    let Some(deixado) = depois.arrendamento else {
        return false;
    };
    let agora = crate::tempo::uptime_ms();
    let (saiu, vencido) = com_tabela(|t| {
        if t.estado(recurso, agora) != depois {
            return (None, None);
        }
        let (r, v) = t.soltar(recurso, deixado.titular, agora);
        (r.ok(), v)
    });
    gravar_vencido(recurso, vencido);
    let Some(a) = saiu else {
        return false;
    };
    gravar(
        Some(&a.titular),
        "lease.invalidate",
        recurso,
        Codigo::Allow,
        motivo.detalhe(),
    );
    true
}

/// Uma confirmação em nome de `titular`: pede o arrendamento, e confere a
/// versão. Passando, a versão cresce e o arrendamento é solto — a linha
/// confirmada volta vazia e livre.
///
/// Sem titular, como em [`editar`]: só num recurso livre.
pub fn confirmar(
    recurso: &str,
    titular: Option<Titular>,
    esperada: Option<u64>,
    metodo: &str,
) -> Result<u64, Codigo> {
    let agora = crate::tempo::uptime_ms();
    let Some(titular) = titular else {
        if estado(recurso).arrendamento.is_some() {
            gravar(
                None,
                metodo,
                recurso,
                Codigo::Conflict,
                "outro titular tem o arrendamento",
            );
            return Err(Codigo::Conflict);
        }
        return Ok(estado(recurso).versao);
    };
    let (r, vencido) = com_tabela(|t| {
        let (r, v) = t.mudar(recurso, titular, esperada, true, agora);
        if r.is_ok() {
            let _ = t.soltar(recurso, titular, agora);
        }
        (r, v)
    });
    gravar_vencido(recurso, vencido);
    match r {
        Ok(versao) => {
            // A mudança feita: o que a confirmação levou não vai — a
            // auditoria guarda quem, onde e a versão, e não o texto.
            gravar(
                Some(&titular),
                metodo,
                recurso,
                Codigo::Allow,
                &format!("confirmado na versao {versao}"),
            );
            Ok(versao)
        }
        Err(recusa) => {
            let detalhe = match recusa {
                Recusa::SemArrendamento => "confirmar sem o arrendamento",
                outra => outra.motivo(),
            };
            gravar(Some(&titular), metodo, recurso, recusa.codigo(), detalhe);
            Err(recusa.codigo())
        }
    }
}

/// Tira os arrendamentos de uma sessão de pessoa que acabou. Grava cada um.
pub fn invalidar_pessoa(sessao: IdSessao, motivo: &str) {
    invalidar(
        |t| matches!(t, Titular::Pessoa { sessao: s, .. } if *s == sessao.0),
        motivo,
    );
}

/// Tira os arrendamentos de todas as pessoas: o registro foi recarregado, e
/// nenhuma sessão de pessoa sobrou. Grava.
pub fn invalidar_pessoas(motivo: &str) {
    invalidar(Titular::e_pessoa, motivo);
}

/// Tira os arrendamentos de uma pessoa — de todas as sessões dela —: a
/// credencial foi suspensa. Grava.
pub fn invalidar_da_pessoa(pessoa: [u8; 8], motivo: &str) {
    invalidar(
        |t| matches!(t, Titular::Pessoa { pessoa: p, .. } if *p == pessoa),
        motivo,
    );
}

/// Tira os arrendamentos de uma chave revogada, em qualquer sessão. Grava.
pub fn invalidar_chave(chave: &[u8; 32], motivo: &str) {
    invalidar(
        |t| matches!(t, Titular::Agente { chave: Some(k), .. } if k == chave),
        motivo,
    );
}

/// Tira os arrendamentos de uma sessão do canal que acabou — a porta
/// desconectou. Grava.
pub fn invalidar_sessao_do_canal(sessao: u8, motivo: &str) {
    invalidar(
        |t| matches!(t, Titular::Agente { sessao: s, .. } if *s == sessao),
        motivo,
    );
}

fn invalidar(acabou: impl Fn(&Titular) -> bool, motivo: &str) {
    let saidos = com_tabela(|t| t.invalidar(acabou));
    crate::metricas::arrendamentos_soltos(crate::metricas::Saida::do_motivo(motivo), saidos.len());
    for (recurso, a) in saidos {
        gravar(
            Some(&a.titular),
            "lease.invalidate",
            &recurso,
            Codigo::Allow,
            motivo,
        );
    }
}

/// Tira os arrendamentos vencidos, e grava cada um. Chamada pelo coletor de
/// fios — uma vez por segundo basta.
pub fn vencer_todos() {
    use core::sync::atomic::{AtomicU64, Ordering};
    static ULTIMA: AtomicU64 = AtomicU64::new(0);
    let agora = crate::tempo::uptime_ms();
    if agora.saturating_sub(ULTIMA.load(Ordering::Relaxed)) < 1_000 {
        return;
    }
    ULTIMA.store(agora, Ordering::Relaxed);
    let saidos = com_tabela(|t| t.vencer_todos(agora));
    crate::metricas::arrendamentos_soltos(crate::metricas::Saida::Vencimento, saidos.len());
    for (recurso, a) in saidos {
        // Quanto depois do prazo o arrendamento saiu: o coletor passa uma
        // vez por segundo, e nada prende o recurso além disso.
        crate::metricas::VENCIMENTO_MS.somar(agora.saturating_sub(a.expira_ms));
        gravar(
            Some(&a.titular),
            "lease.expire",
            &recurso,
            Codigo::Allow,
            "o prazo venceu",
        );
    }
}

/// Revoga o arrendamento de um recurso, de quem for: `lease.revoke`. Só a
/// operação administrativa chama, com a prova conferida — e ela grava o
/// desfecho; aqui se grava o arrendamento que saiu, em nome de quem o tinha.
pub fn revogar(recurso: &str) -> Option<Arrendamento> {
    let saiu = com_tabela(|t| t.revogar(recurso));
    if let Some(a) = saiu {
        crate::metricas::arrendamentos_soltos(crate::metricas::Saida::Administrador, 1);
        gravar(
            Some(&a.titular),
            "lease.invalidate",
            recurso,
            Codigo::Allow,
            "revogado por um administrador",
        );
    }
    saiu
}

/// Para o invariante da suíte: nenhum recurso com dois arrendamentos.
#[cfg(feature = "modo-teste")]
pub fn um_por_recurso() -> bool {
    com_tabela(|t| t.um_por_recurso())
}

/// Esvazia a tabela, para a suíte: cada caso começa sem arrendamento.
#[cfg(feature = "modo-teste")]
pub fn esquecer() {
    com_tabela(|t| *t = Tabela::nova());
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
