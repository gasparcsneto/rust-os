//! Quem é quem: a chave do Duke, os agentes autorizados e os administradores.
//!
//! # De onde vem
//!
//! Do disco, no boot — provisionado pelo `xtask` na imagem, como as chaves de
//! um servidor e o `authorized_keys` dos usuários dele:
//!
//! - `/etc/duke/privado/chave`: a chave privada do Duke, que só o kernel lê
//!   — ver [`crate::vfs::DIRETORIO_RESERVADO`];
//! - `/etc/duke/agentes`: as chaves públicas dos agentes que podem abrir uma
//!   porta, com o nome de cada um;
//! - `/etc/duke/administradores`: as dos administradores, que podem provar
//!   uma operação administrativa — ver [`crate::agent::administracao`].
//!
//! # Por que fora do canal do agente
//!
//! O canal do agente não tem `unsafe` — é o código que lê o que vem de fora
//! —, e uma trava estática precisa de um `destravar` para o caminho fatal,
//! que é `unsafe`. O registro é um serviço do sistema que o canal consulta,
//! e mora aqui. A política, quando vier, consulta o mesmo.
//!
//! E, em tempo de execução, de `agent.register`: um agente registrado por um
//! administrador. O disco é só de leitura, então esse registro vale até o
//! próximo boot. Um armazenamento persistente de chaves é um passo seguinte,
//! e entra por baixo desta mesma interface.
//!
//! # O que o registro decide, e o que não
//!
//! Ele decide **quem pode entrar**: uma chave fora do registro não completa
//! o aperto de mão. O que cada agente pode fazer depois de entrar — a
//! política — é da etapa seguinte; hoje todo agente registrado pode o que a
//! serial pode.

use alloc::string::String;
use alloc::vec::Vec;

use sigilo::TAM_CHAVE;
use sigilo::registro::{self, ErroDeLinha};
use spin::Mutex;

/// Onde está a chave privada do Duke.
pub const CAMINHO_DA_CHAVE: &str = "/etc/duke/privado/chave";
/// Onde estão os agentes autorizados.
pub const CAMINHO_DOS_AGENTES: &str = "/etc/duke/agentes";
/// Onde estão os administradores.
pub const CAMINHO_DOS_ADMINISTRADORES: &str = "/etc/duke/administradores";

/// Quantos agentes o registro guarda. Um teto para que `agent.register` não
/// seja um jeito de esgotar a memória do kernel.
pub const MAIOR_REGISTRO: usize = 64;

/// De onde veio uma entrada do registro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origem {
    /// Do arquivo na imagem, lido no boot.
    Imagem,
    /// De um `agent.register` provado por um administrador.
    Administracao,
}

impl Origem {
    /// O nome que vai para o relatório.
    pub const fn como_str(self) -> &'static str {
        match self {
            Origem::Imagem => "image",
            Origem::Administracao => "admin",
        }
    }
}

/// Um agente que pode entrar.
#[derive(Clone)]
pub struct Agente {
    pub chave: [u8; TAM_CHAVE],
    pub nome: String,
    pub origem: Origem,
    /// O papel, que a política define. Sem papel, o agente entra e não pode
    /// nada: `DENY_ROLE`.
    pub papel: Option<String>,
}

/// Um administrador.
#[derive(Clone)]
pub struct Administrador {
    pub chave: [u8; TAM_CHAVE],
    pub nome: String,
    /// O papel dele: o teto do que ele delega, e as operações
    /// administrativas que pode. Só a imagem o define — não muda em tempo
    /// de execução.
    pub papel: Option<String>,
    /// Revogada por `admin.revoke`, com quórum. A credencial fica no
    /// registro — continua membro do grupo de N, e o nome dela continua
    /// nomeando o que ela fez na auditoria —, mas não prova mais nada, não
    /// assina quórum e não recebe mensagem. Vale até o próximo boot: o disco
    /// é só de leitura.
    pub revogado: bool,
    /// A chave **pública** Ed25519 com que a credencial assina um quórum —
    /// ver [`sigilo::quorum`]. A privada fica com quem assina; o Duke só
    /// confere. Sem ela, a credencial prova operações de uma credencial só e
    /// não assina quórum.
    pub assinatura: Option<[u8; TAM_CHAVE]>,
}

struct Identidade {
    /// A chave privada do Duke. Nunca sai deste módulo: quem precisa dela
    /// pede uma operação em [`com_chave_do_duke`].
    chave: Option<[u8; TAM_CHAVE]>,
    agentes: Vec<Agente>,
    administradores: Vec<Administrador>,
}

static IDENTIDADE: Mutex<Identidade> = Mutex::new(Identidade {
    chave: None,
    agentes: Vec::new(),
    administradores: Vec::new(),
});

/// Lê as chaves do disco. No boot, depois de a raiz estar montada.
pub fn carregar() {
    let chave = match crate::vfs::ler_segredo(CAMINHO_DA_CHAVE) {
        Ok(bytes) => {
            let texto = core::str::from_utf8(&bytes).unwrap_or("");
            let chave = sigilo::de_hex(texto);
            // O texto lido tinha a chave; ele não fica por aí.
            let mut bytes = bytes;
            sigilo::zeroize::Zeroize::zeroize(&mut bytes);
            if chave.is_none() {
                crate::log_error!("agent", "{} nao tem uma chave valida", CAMINHO_DA_CHAVE);
            }
            chave
        }
        Err(motivo) => {
            crate::log_warn!(
                "agent",
                "sem chave do Duke ({}): as portas de agente vao recusar o aperto",
                motivo.motivo()
            );
            None
        }
    };

    let agentes: Vec<Agente> = ler_arquivo(CAMINHO_DOS_AGENTES, false)
        .into_iter()
        .map(|(chave, nome, papel, _)| Agente {
            chave,
            nome,
            origem: Origem::Imagem,
            papel,
        })
        .collect();
    let administradores: Vec<Administrador> = ler_arquivo(CAMINHO_DOS_ADMINISTRADORES, true)
        .into_iter()
        .map(|(chave, nome, papel, assinatura)| Administrador {
            chave,
            nome,
            papel,
            revogado: false,
            assinatura,
        })
        .collect();

    if let Some(c) = &chave {
        crate::log_info!(
            "agent",
            "chave do Duke {}, {} agentes, {} administradores",
            impressao(&sigilo::publica_de(c)),
            agentes.len(),
            administradores.len()
        );
    }
    crate::arch::sem_interrupcoes(|| {
        let mut id = IDENTIDADE.lock();
        id.chave = chave;
        id.agentes = agentes;
        id.administradores = administradores;
    });
}

/// Uma entrada de um arquivo de chaves: a chave, o nome, o papel e — só no
/// dos administradores — a chave pública de assinatura.
type Entrada = (
    [u8; TAM_CHAVE],
    String,
    Option<String>,
    Option<[u8; TAM_CHAVE]>,
);

/// As entradas de um arquivo de chaves; com `administradores`, no formato
/// do arquivo dos administradores, com a chave de assinatura.
///
/// Uma linha errada é pulada com um aviso dizendo qual e por quê, e as
/// outras entram. Recusar o arquivo inteiro por uma linha deixaria todo
/// agente de fora por um erro de digitação em outro — e um arquivo ausente é
/// um registro vazio, e não um erro: é o estado de uma máquina sem agentes.
fn ler_arquivo(caminho: &str, administradores: bool) -> Vec<Entrada> {
    let Ok(bytes) = crate::vfs::ler_tudo(caminho) else {
        crate::log_info!("agent", "{} nao existe: nenhuma chave dali", caminho);
        return Vec::new();
    };
    let Ok(texto) = core::str::from_utf8(&bytes) else {
        crate::log_error!("agent", "{} nao e texto", caminho);
        return Vec::new();
    };
    let mut entradas: Vec<Entrada> = Vec::new();
    for (i, linha) in texto.lines().enumerate() {
        let lida = if administradores {
            registro::ler_linha_de_administrador(linha)
        } else {
            registro::ler_linha(linha).map(|e| e.map(|(c, n, p)| (c, n, p, None)))
        };
        match lida {
            Ok(Some((chave, nome, papel, assinatura))) => {
                if entradas.len() >= MAIOR_REGISTRO {
                    crate::log_warn!("agent", "{}: mais de {} chaves", caminho, MAIOR_REGISTRO);
                    break;
                }
                if entradas.iter().any(|e| e.0 == chave) {
                    crate::log_warn!("agent", "{}:{}: chave repetida, ignorada", caminho, i + 1);
                    continue;
                }
                entradas.push((
                    chave,
                    String::from(nome),
                    papel.map(String::from),
                    assinatura,
                ));
            }
            Ok(None) => {}
            Err(e) => avisar_linha(caminho, i + 1, e),
        }
    }
    entradas
}

fn avisar_linha(caminho: &str, linha: usize, e: ErroDeLinha) {
    crate::log_warn!("agent", "{}:{}: {}, ignorada", caminho, linha, e.motivo());
}

/// Os oito primeiros dígitos de uma chave pública: o bastante para
/// reconhecer, curto o bastante para o log.
pub fn impressao(chave: &[u8; TAM_CHAVE]) -> String {
    let mut s = sigilo::hex(chave);
    s.truncate(8);
    s
}

/// Roda `f` com a chave privada do Duke, se houver.
///
/// A chave sai da trava como cópia, e a cópia é apagada depois: `f` faz um
/// aperto de mão inteiro, que não precisa acontecer com as interrupções
/// desligadas.
pub fn com_chave_do_duke<R>(f: impl FnOnce(&[u8; TAM_CHAVE]) -> R) -> Option<R> {
    let mut chave = crate::arch::sem_interrupcoes(|| IDENTIDADE.lock().chave)?;
    let r = f(&chave);
    sigilo::zeroize::Zeroize::zeroize(&mut chave);
    Some(r)
}

/// A chave pública do Duke: o que um agente precisa ter para o aperto.
pub fn publica_do_duke() -> Option<[u8; TAM_CHAVE]> {
    crate::arch::sem_interrupcoes(|| IDENTIDADE.lock().chave.map(|c| sigilo::publica_de(&c)))
}

/// O nome do agente com esta chave, se ele estiver no registro.
pub fn agente(chave: &[u8; TAM_CHAVE]) -> Option<String> {
    crate::arch::sem_interrupcoes(|| {
        IDENTIDADE
            .lock()
            .agentes
            .iter()
            .find(|a| a.chave == *chave)
            .map(|a| a.nome.clone())
    })
}

/// A chave e o papel do administrador com este nome — o destinatário
/// `admin:<nome>` de uma mensagem.
pub fn administrador_por_nome(nome: &str) -> Option<([u8; TAM_CHAVE], Option<String>)> {
    crate::arch::sem_interrupcoes(|| {
        IDENTIDADE
            .lock()
            .administradores
            .iter()
            .find(|a| a.nome == nome && !a.revogado)
            .map(|a| (a.chave, a.papel.clone()))
    })
}

/// Se esta chave é de um administrador: o nome dele.
pub fn administrador(chave: &[u8; TAM_CHAVE]) -> Option<String> {
    crate::arch::sem_interrupcoes(|| {
        IDENTIDADE
            .lock()
            .administradores
            .iter()
            .find(|a| a.chave == *chave)
            .map(|a| a.nome.clone())
    })
}

/// O papel do agente com esta chave. `None` se a chave não está no
/// registro — foi revogada — ou não tem papel.
pub fn papel_do_agente(chave: &[u8; TAM_CHAVE]) -> Option<String> {
    crate::arch::sem_interrupcoes(|| {
        IDENTIDADE
            .lock()
            .agentes
            .iter()
            .find(|a| a.chave == *chave)
            .and_then(|a| a.papel.clone())
    })
}

/// O nome e o papel do administrador com esta chave. `None` também para a
/// credencial revogada: ela não prova mais nada — ver
/// [`administrador_revogado`] para dizer por quê.
pub fn papel_do_administrador(chave: &[u8; TAM_CHAVE]) -> Option<(String, Option<String>)> {
    crate::arch::sem_interrupcoes(|| {
        IDENTIDADE
            .lock()
            .administradores
            .iter()
            .find(|a| a.chave == *chave && !a.revogado)
            .map(|a| (a.nome.clone(), a.papel.clone()))
    })
}

/// Se esta chave é de um administrador revogado.
pub fn administrador_revogado(chave: &[u8; TAM_CHAVE]) -> bool {
    crate::arch::sem_interrupcoes(|| {
        IDENTIDADE
            .lock()
            .administradores
            .iter()
            .any(|a| a.chave == *chave && a.revogado)
    })
}

/// O grupo de administradores: todas as credenciais do registro, as
/// revogadas também — o N de um quórum é o grupo da imagem, e uma
/// revogação não o encolhe.
pub fn grupo_de_administradores() -> Vec<Administrador> {
    crate::arch::sem_interrupcoes(|| IDENTIDADE.lock().administradores.clone())
}

/// Por que uma credencial de administrador não pôde ser revogada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecusaDaRevogacao {
    /// Não há administrador com esta chave.
    Desconhecido,
    /// Já foi revogada.
    JaRevogado,
    /// Restariam menos credenciais ativas que o quórum: ninguém mais
    /// conseguiria revogar, nem a próxima credencial perdida.
    AbaixoDoQuorum,
}

impl RecusaDaRevogacao {
    pub const fn motivo(self) -> &'static str {
        match self {
            RecusaDaRevogacao::Desconhecido => "administrador desconhecido",
            RecusaDaRevogacao::JaRevogado => "a credencial ja foi revogada",
            RecusaDaRevogacao::AbaixoDoQuorum => {
                "restariam menos credenciais ativas que o quorum exige"
            }
        }
    }
}

/// Revoga a credencial de administrador `chave`, se depois dela restarem
/// pelo menos `m` ativas. Conferir e marcar acontecem na mesma seção, com
/// o registro travado: duas revogações ao mesmo tempo não passam as duas
/// pela conta do que resta. As mensagens vivas da credencial são anuladas,
/// como as de um agente revogado. Devolve o nome.
pub fn revogar_administrador(chave: &[u8; TAM_CHAVE], m: u8) -> Result<String, RecusaDaRevogacao> {
    let nome = marcar_revogado(chave, m)?;
    crate::mensagens::anular_titular(
        politica::mensagens::Dono::Administrador(*chave),
        "com a credencial revogada",
    );
    Ok(nome)
}

fn marcar_revogado(chave: &[u8; TAM_CHAVE], m: u8) -> Result<String, RecusaDaRevogacao> {
    crate::arch::sem_interrupcoes(|| {
        let mut id = IDENTIDADE.lock();
        let ativas = id.administradores.iter().filter(|a| !a.revogado).count();
        let alvo = id
            .administradores
            .iter_mut()
            .find(|a| a.chave == *chave)
            .ok_or(RecusaDaRevogacao::Desconhecido)?;
        if alvo.revogado {
            return Err(RecusaDaRevogacao::JaRevogado);
        }
        if ativas.saturating_sub(1) < usize::from(m) {
            return Err(RecusaDaRevogacao::AbaixoDoQuorum);
        }
        alvo.revogado = true;
        Ok(alvo.nome.clone())
    })
}

/// Os papéis dos administradores: os que nenhuma mudança em tempo de
/// execução pode tocar.
pub fn papeis_dos_administradores() -> Vec<String> {
    crate::arch::sem_interrupcoes(|| {
        let mut papeis: Vec<String> = IDENTIDADE
            .lock()
            .administradores
            .iter()
            .filter_map(|a| a.papel.clone())
            .collect();
        papeis.sort();
        papeis.dedup();
        papeis
    })
}

/// A chave do agente com este nome.
pub fn chave_do_agente(nome: &str) -> Option<[u8; TAM_CHAVE]> {
    crate::arch::sem_interrupcoes(|| {
        IDENTIDADE
            .lock()
            .agentes
            .iter()
            .find(|a| a.nome == nome)
            .map(|a| a.chave)
    })
}

/// Por que um registro foi recusado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// O nome não segue a regra de [`sigilo::registro::nome_valido`].
    Nome,
    /// A chave já está registrada.
    ChaveRepetida,
    /// O nome já é de outra chave: dois agentes com o mesmo nome seriam o
    /// mesmo para quem lê o log.
    NomeRepetido,
    /// O registro está no teto.
    Cheio,
    /// Não há agente com esta chave, ou com este nome.
    Desconhecido,
}

impl Recusa {
    pub const fn motivo(self) -> &'static str {
        match self {
            Recusa::Nome => "nome fora da regra",
            Recusa::ChaveRepetida => "chave ja registrada",
            Recusa::NomeRepetido => "nome ja usado por outra chave",
            Recusa::Cheio => "registro cheio",
            Recusa::Desconhecido => "agente desconhecido",
        }
    }
}

/// Registra um agente. Só [`crate::agent::administracao`] chama, depois de a
/// prova conferir.
pub fn registrar(chave: [u8; TAM_CHAVE], nome: &str, papel: &str) -> Result<(), Recusa> {
    if !registro::nome_valido(nome) {
        return Err(Recusa::Nome);
    }
    crate::arch::sem_interrupcoes(|| {
        let mut id = IDENTIDADE.lock();
        if id.agentes.iter().any(|a| a.chave == chave) {
            return Err(Recusa::ChaveRepetida);
        }
        if id.agentes.iter().any(|a| a.nome == nome) {
            return Err(Recusa::NomeRepetido);
        }
        if id.agentes.len() >= MAIOR_REGISTRO {
            return Err(Recusa::Cheio);
        }
        id.agentes.push(Agente {
            chave,
            nome: String::from(nome),
            origem: Origem::Administracao,
            papel: Some(String::from(papel)),
        });
        Ok(())
    })
}

/// Tira um agente do registro. Devolve o nome dele. As sessões vivas da
/// chave quem encerra é quem chama — ver [`crate::agent::administracao`].
pub fn revogar(chave: &[u8; TAM_CHAVE]) -> Result<String, Recusa> {
    let nome = crate::arch::sem_interrupcoes(|| {
        let mut id = IDENTIDADE.lock();
        let i = id
            .agentes
            .iter()
            .position(|a| a.chave == *chave)
            .ok_or(Recusa::Desconhecido)?;
        Ok(id.agentes.remove(i).nome)
    })?;
    // Os arrendamentos da chave acabam com ela, na hora — em qualquer sessão.
    crate::coordenacao::invalidar_chave(chave, "a chave foi revogada");
    // E as mensagens dela: as que mandou e as que ia receber. Nenhuma é
    // entregue depois — nem se a mesma chave voltar ao registro.
    crate::mensagens::anular_titular(
        politica::mensagens::Dono::Agente(*chave),
        "com a chave revogada",
    );
    // A chave revogada não conta mais como agente conectado, mesmo antes de
    // a porta cair: a barra diz isso na hora.
    crate::barra::atualizar_indicador();
    Ok(nome)
}

/// Troca o papel de um agente, pelo nome.
pub fn atribuir(nome: &str, papel: &str) -> Result<(), Recusa> {
    crate::arch::sem_interrupcoes(|| {
        let mut id = IDENTIDADE.lock();
        let agente = id
            .agentes
            .iter_mut()
            .find(|a| a.nome == nome)
            .ok_or(Recusa::Desconhecido)?;
        agente.papel = Some(String::from(papel));
        Ok(())
    })
}

/// Quantos administradores há. Só o número: as chaves deles não vão para
/// relatório nenhum.
pub fn quantos_administradores() -> usize {
    crate::arch::sem_interrupcoes(|| IDENTIDADE.lock().administradores.len())
}

/// Uma cópia do registro de agentes, para o relatório.
pub fn agentes() -> Vec<Agente> {
    crate::arch::sem_interrupcoes(|| IDENTIDADE.lock().agentes.clone())
}

/// O nome com que a suíte registra os administradores dela.
#[cfg(feature = "modo-teste")]
pub const ADMINISTRADOR_DE_TESTE: &str = "administrador-de-teste";

/// Registra um administrador, para a suíte: ela não tem a chave privada do
/// administrador da imagem — e não deveria ter —, e precisa de uma para
/// provar operações.
#[cfg(feature = "modo-teste")]
pub fn registrar_administrador_de_teste(chave: [u8; TAM_CHAVE], papel: &str) {
    crate::arch::sem_interrupcoes(|| {
        let mut id = IDENTIDADE.lock();
        if !id.administradores.iter().any(|a| a.chave == chave) {
            id.administradores.push(Administrador {
                chave,
                nome: String::from(ADMINISTRADOR_DE_TESTE),
                papel: Some(String::from(papel)),
                revogado: false,
                assinatura: None,
            });
        }
    });
}

/// Um membro do grupo de teste: a credencial, o nome, o papel e a chave
/// pública de assinatura.
#[cfg(feature = "modo-teste")]
pub type MembroDeTeste<'a> = ([u8; TAM_CHAVE], &'a str, &'a str, Option<[u8; TAM_CHAVE]>);

/// Troca o grupo de administradores inteiro, para a suíte: o quórum é
/// sobre o grupo, e a suíte precisa de um cujas chaves privadas ela tem —
/// do lado de quem assina; o registro guarda só as públicas, como o da
/// imagem. [`esquecer_registrados`] volta ao da imagem.
#[cfg(feature = "modo-teste")]
pub fn substituir_administradores_de_teste(grupo: &[MembroDeTeste]) {
    let grupo: Vec<Administrador> = grupo
        .iter()
        .map(|(chave, nome, papel, assinatura)| Administrador {
            chave: *chave,
            nome: String::from(*nome),
            papel: Some(String::from(*papel)),
            revogado: false,
            assinatura: *assinatura,
        })
        .collect();
    crate::arch::sem_interrupcoes(|| IDENTIDADE.lock().administradores = grupo);
}

/// Registra um agente direto, sem prova, para a suíte montar as sessões
/// dela. O caminho com prova tem os casos próprios.
#[cfg(feature = "modo-teste")]
pub fn registrar_agente_de_teste(chave: [u8; TAM_CHAVE], nome: &str, papel: &str) {
    let _ = registrar(chave, nome, papel);
}

/// Devolve o registro ao que a imagem diz: relê os arquivos. O que a suíte
/// registrou, revogou ou mudou de papel volta ao que era. O caso seguinte
/// encontra o registro da imagem.
#[cfg(feature = "modo-teste")]
pub fn esquecer_registrados() {
    carregar();
}

// ---------------------------------------------------------------------------
// Os desafios das operações administrativas
// ---------------------------------------------------------------------------

/// Quanto tempo um desafio vale, em milissegundos.
///
/// O bastante para um cliente calcular a prova e mandá-la — milissegundos —
/// com folga para uma pessoa que esteja fazendo isso à mão pela serial. Um
/// desafio que vale para sempre é um desafio que espera, guardado, alguém
/// conseguir a chave.
pub const VALIDADE_DO_DESAFIO_MS: u64 = 30_000;

/// Quanto tempo vale um desafio de quórum: mais que o de uma credencial só,
/// porque as provas de M credenciais precisam ser juntadas — cada uma
/// calculada por quem a tem — antes de o pedido sair. Ainda curto: o
/// desafio é de uma operação, e não uma autorização guardada.
pub const VALIDADE_DO_DESAFIO_DE_QUORUM_MS: u64 = 120_000;

/// Um desafio pendente. Um por sessão: pedir outro descarta o anterior.
struct Desafio {
    id: u64,
    sessao: u8,
    efemera: [u8; TAM_CHAVE],
    nonce: [u8; 32],
    criado_ms: u64,
    /// A operação de quórum para que foi pedido; `None`, o de uma
    /// credencial só. Um não serve para o outro.
    quorum: Option<&'static str>,
    /// A versão da política quando foi emitido.
    versao_da_politica: u64,
}

impl Drop for Desafio {
    fn drop(&mut self) {
        sigilo::zeroize::Zeroize::zeroize(&mut self.efemera);
    }
}

static DESAFIOS: Mutex<Vec<Desafio>> = Mutex::new(Vec::new());

/// O número do próximo desafio. Só identifica; quem dá a segurança é o nonce.
static PROXIMO_DESAFIO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// O que um desafio mostra a quem o pediu.
pub struct DesafioPublico {
    pub id: u64,
    pub nonce: [u8; 32],
    /// A parte pública da efêmera.
    pub efemera: [u8; TAM_CHAVE],
    pub versao_da_politica: u64,
    pub valido_ms: u64,
}

/// O que sobra de um desafio para conferir a prova: a efêmera privada e o
/// nonce. Apagado ao sair de uso.
pub struct DesafioConsumido {
    pub efemera: [u8; TAM_CHAVE],
    pub nonce: [u8; 32],
    pub quorum: Option<&'static str>,
    pub versao_da_politica: u64,
}

impl Drop for DesafioConsumido {
    fn drop(&mut self) {
        sigilo::zeroize::Zeroize::zeroize(&mut self.efemera);
    }
}

/// Um desafio novo para a sessão `sessao`, no lugar de qualquer anterior
/// dela — de uma credencial só, ou, com `quorum`, para aquela operação de
/// quórum.
pub fn desafiar(
    sessao: u8,
    quorum: Option<&'static str>,
) -> Result<DesafioPublico, crate::aleatorio::SemEntropia> {
    let efemera = crate::aleatorio::chave()?;
    let nonce = crate::aleatorio::chave()?;
    let id = PROXIMO_DESAFIO.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let versao_da_politica = crate::autorizacao::versao_da_politica();
    let publico = DesafioPublico {
        id,
        nonce,
        efemera: sigilo::publica_de(&efemera),
        versao_da_politica,
        valido_ms: validade(quorum),
    };
    let desafio = Desafio {
        id,
        sessao,
        efemera,
        nonce,
        criado_ms: agora_dos_desafios(),
        quorum,
        versao_da_politica,
    };
    let anterior = crate::arch::sem_interrupcoes(|| {
        let mut desafios = DESAFIOS.lock();
        let anterior = desafios
            .iter()
            .position(|d| d.sessao == sessao)
            .map(|i| desafios.swap_remove(i));
        desafios.push(desafio);
        anterior
    });
    drop(anterior);
    Ok(publico)
}

/// Por que um desafio não pôde ser usado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesafioRecusado {
    /// Não há desafio com este número **nesta sessão**: nunca houve, já foi
    /// usado, ou é de outra sessão.
    Desconhecido,
    /// Venceu.
    Vencido,
}

impl DesafioRecusado {
    pub const fn motivo(self) -> &'static str {
        match self {
            DesafioRecusado::Desconhecido => "desafio desconhecido nesta sessao",
            DesafioRecusado::Vencido => "desafio vencido",
        }
    }
}

/// Tira o desafio `id` da sessão `sessao`, para conferir uma prova.
///
/// Sai da lista acerte a prova ou erre: um desafio vale **uma** tentativa.
/// Sem isso, quem tivesse o desafio poderia testar provas até acertar.
///
/// Um desafio de outra sessão não é tocado: responder "desconhecido" sem
/// tirá-lo impede que uma sessão queime, pelo número, os desafios de outra.
pub fn consumir(sessao: u8, id: u64) -> Result<DesafioConsumido, DesafioRecusado> {
    let desafio = crate::arch::sem_interrupcoes(|| {
        let mut desafios = DESAFIOS.lock();
        desafios
            .iter()
            .position(|d| d.id == id && d.sessao == sessao)
            .map(|i| desafios.swap_remove(i))
    })
    .ok_or(DesafioRecusado::Desconhecido)?;
    if agora_dos_desafios().saturating_sub(desafio.criado_ms) > validade(desafio.quorum) {
        return Err(DesafioRecusado::Vencido);
    }
    Ok(DesafioConsumido {
        efemera: desafio.efemera,
        nonce: desafio.nonce,
        quorum: desafio.quorum,
        versao_da_politica: desafio.versao_da_politica,
    })
}

fn validade(quorum: Option<&'static str>) -> u64 {
    if quorum.is_some() {
        VALIDADE_DO_DESAFIO_DE_QUORUM_MS
    } else {
        VALIDADE_DO_DESAFIO_MS
    }
}

/// O relógio dos desafios: o do sistema — e, na suíte, adiantado pelo que
/// `envelhecer_desafios_de_teste` pediu.
fn agora_dos_desafios() -> u64 {
    let agora = crate::tempo::uptime_ms();
    #[cfg(feature = "modo-teste")]
    let agora = agora + ADIANTO_DE_TESTE.load(core::sync::atomic::Ordering::SeqCst);
    agora
}

/// Quanto a suíte adiantou o relógio dos desafios. Só cresce.
#[cfg(feature = "modo-teste")]
static ADIANTO_DE_TESTE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Adianta o relógio dos desafios em `ms`: os pendentes envelhecem, para a
/// suíte conferir o vencimento sem esperar dois minutos. Subtrair da hora
/// de criação não serviria: no começo da suíte o relógio tem segundos, e a
/// conta pararia no zero.
#[cfg(feature = "modo-teste")]
pub fn envelhecer_desafios_de_teste(ms: u64) {
    ADIANTO_DE_TESTE.fetch_add(ms, core::sync::atomic::Ordering::SeqCst);
}

/// Descarta todos os desafios pendentes, de todas as sessões. Uma
/// revogação de administrador chama: os desafios não são de uma chave —
/// qualquer um pendente podia estar com a credencial revogada, ou com uma
/// operação de quórum calculada sobre o grupo de antes. Quem estava no
/// meio pede outro, e calcula sobre o estado novo. Devolve quantos eram.
pub fn descartar_desafios() -> usize {
    let descartados = crate::arch::sem_interrupcoes(|| core::mem::take(&mut *DESAFIOS.lock()));
    descartados.len()
}

/// Destrava o registro à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        IDENTIDADE.force_unlock();
        DESAFIOS.force_unlock();
    }
}
