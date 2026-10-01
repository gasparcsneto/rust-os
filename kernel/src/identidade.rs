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
}

/// Um administrador.
#[derive(Clone)]
pub struct Administrador {
    pub chave: [u8; TAM_CHAVE],
    pub nome: String,
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

    let agentes: Vec<Agente> = ler_arquivo(CAMINHO_DOS_AGENTES)
        .into_iter()
        .map(|(chave, nome)| Agente {
            chave,
            nome,
            origem: Origem::Imagem,
        })
        .collect();
    let administradores: Vec<Administrador> = ler_arquivo(CAMINHO_DOS_ADMINISTRADORES)
        .into_iter()
        .map(|(chave, nome)| Administrador { chave, nome })
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

/// As entradas de um arquivo de chaves.
///
/// Uma linha errada é pulada com um aviso dizendo qual e por quê, e as
/// outras entram. Recusar o arquivo inteiro por uma linha deixaria todo
/// agente de fora por um erro de digitação em outro — e um arquivo ausente é
/// um registro vazio, e não um erro: é o estado de uma máquina sem agentes.
fn ler_arquivo(caminho: &str) -> Vec<([u8; TAM_CHAVE], String)> {
    let Ok(bytes) = crate::vfs::ler_tudo(caminho) else {
        crate::log_info!("agent", "{} nao existe: nenhuma chave dali", caminho);
        return Vec::new();
    };
    let Ok(texto) = core::str::from_utf8(&bytes) else {
        crate::log_error!("agent", "{} nao e texto", caminho);
        return Vec::new();
    };
    let mut entradas = Vec::new();
    for (i, linha) in texto.lines().enumerate() {
        match registro::ler_linha(linha) {
            Ok(Some((chave, nome))) => {
                if entradas.len() >= MAIOR_REGISTRO {
                    crate::log_warn!("agent", "{}: mais de {} chaves", caminho, MAIOR_REGISTRO);
                    break;
                }
                if entradas.iter().any(|(c, _)| *c == chave) {
                    crate::log_warn!("agent", "{}:{}: chave repetida, ignorada", caminho, i + 1);
                    continue;
                }
                entradas.push((chave, String::from(nome)));
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

/// Se esta chave é de um administrador.
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
}

impl Recusa {
    pub const fn motivo(self) -> &'static str {
        match self {
            Recusa::Nome => "nome fora da regra",
            Recusa::ChaveRepetida => "chave ja registrada",
            Recusa::NomeRepetido => "nome ja usado por outra chave",
            Recusa::Cheio => "registro cheio",
        }
    }
}

/// Registra um agente. Só [`crate::agent::administracao`] chama, depois de a
/// prova conferir.
pub fn registrar(chave: [u8; TAM_CHAVE], nome: &str) -> Result<(), Recusa> {
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
        });
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
const ADMINISTRADOR_DE_TESTE: &str = "administrador-de-teste";

/// Registra um administrador, para a suíte: ela não tem a chave privada do
/// administrador da imagem — e não deveria ter —, e precisa de uma para
/// provar operações.
#[cfg(feature = "modo-teste")]
pub fn registrar_administrador_de_teste(chave: [u8; TAM_CHAVE]) {
    crate::arch::sem_interrupcoes(|| {
        let mut id = IDENTIDADE.lock();
        if !id.administradores.iter().any(|a| a.chave == chave) {
            id.administradores.push(Administrador {
                chave,
                nome: String::from(ADMINISTRADOR_DE_TESTE),
            });
        }
    });
}

/// Registra um agente direto, sem prova, para a suíte montar as sessões
/// dela. O caminho com prova tem os casos próprios.
#[cfg(feature = "modo-teste")]
pub fn registrar_agente_de_teste(chave: [u8; TAM_CHAVE], nome: &str) {
    let _ = registrar(chave, nome);
}

/// Esquece o que a suíte registrou em tempo de execução: os agentes e os
/// administradores dela. O caso seguinte encontra o registro da imagem.
#[cfg(feature = "modo-teste")]
pub fn esquecer_registrados() {
    crate::arch::sem_interrupcoes(|| {
        let mut id = IDENTIDADE.lock();
        id.agentes.retain(|a| a.origem == Origem::Imagem);
        id.administradores
            .retain(|a| a.nome != ADMINISTRADOR_DE_TESTE);
    });
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

/// Um desafio pendente. Um por sessão: pedir outro descarta o anterior.
struct Desafio {
    id: u64,
    sessao: u8,
    efemera: [u8; TAM_CHAVE],
    nonce: [u8; 32],
    criado_ms: u64,
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
}

/// O que sobra de um desafio para conferir a prova: a efêmera privada e o
/// nonce. Apagado ao sair de uso.
pub struct DesafioConsumido {
    pub efemera: [u8; TAM_CHAVE],
    pub nonce: [u8; 32],
}

impl Drop for DesafioConsumido {
    fn drop(&mut self) {
        sigilo::zeroize::Zeroize::zeroize(&mut self.efemera);
    }
}

/// Um desafio novo para a sessão `sessao`, no lugar de qualquer anterior
/// dela.
pub fn desafiar(sessao: u8) -> Result<DesafioPublico, crate::aleatorio::SemEntropia> {
    let efemera = crate::aleatorio::chave()?;
    let nonce = crate::aleatorio::chave()?;
    let id = PROXIMO_DESAFIO.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let publico = DesafioPublico {
        id,
        nonce,
        efemera: sigilo::publica_de(&efemera),
    };
    let desafio = Desafio {
        id,
        sessao,
        efemera,
        nonce,
        criado_ms: crate::tempo::uptime_ms(),
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
    if crate::tempo::uptime_ms().saturating_sub(desafio.criado_ms) > VALIDADE_DO_DESAFIO_MS {
        return Err(DesafioRecusado::Vencido);
    }
    Ok(DesafioConsumido {
        efemera: desafio.efemera,
        nonce: desafio.nonce,
    })
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
