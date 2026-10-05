//! Canais de eventos: por onde o kernel fala com um processo que escuta.
//!
//! # Para que servem
//!
//! Para o servidor de janelas, que mora no espaço do usuário e precisa saber
//! do que acontece do lado de cá: o ponteiro andou, uma tecla chegou, alguém
//! pediu uma ação pela árvore semântica. O servidor não pergunta — ele
//! **espera**: lê o canal, e a leitura bloqueia até haver o que entregar.
//!
//! # Um canal
//!
//! Tem um nome, um ouvinte e uma fila. O ouvinte é o processo que chamou
//! `escutar` com o nome; a fila guarda até [`CAPACIDADE`] eventos que ele
//! ainda não leu. Quem publica é o kernel, pelo nome: quem publica não
//! precisa saber qual processo escuta, nem se algum escuta.
//!
//! # O que não cabe
//!
//! É recusado, e contado. A alternativa — jogar fora o mais antigo para
//! caber o novo — também perderia um evento, e perderia o do começo: quem
//! lesse veria uma sequência que começa no meio. Recusar deixa o que o
//! ouvinte recebe sendo um prefixo do que foi publicado, e quem publica
//! sabe que não coube.
//!
//! # Quando o ouvinte some
//!
//! Um processo que morre não fecha os descritores — a tabela dele vai
//! embora junto com o fio, sem passar por aqui. O canal guarda o
//! identificador do ouvinte, e quem o procura confere se ele ainda vive: um
//! canal de ouvinte morto é devolvido ali mesmo, e o nome fica livre para o
//! próximo. É a mesma escolha da tabela de descritores morar no fio — nada
//! aqui depende de alguém lembrar de limpar no caminho da morte.

// Quem publica em produção ainda não existe: é o roteamento de entrada do
// servidor de janelas, na etapa seguinte. Até lá só a suíte publica, e o que
// só ela usa fica marcado — em vez de um publicador inventado para o build
// ficar limpo.
#![cfg_attr(not(feature = "modo-teste"), allow(dead_code))]

use core::sync::atomic::{AtomicU64, Ordering};

use crate::trava::Mutex;
use protocolo::usuario::evento::Evento;

/// Quantos canais podem existir ao mesmo tempo.
pub const CANAIS: usize = 8;

/// Quantos eventos não lidos um canal guarda.
pub const CAPACIDADE: usize = 64;

/// O maior nome de canal, em bytes.
pub const NOME_MAX: usize = 32;

/// O que um descritor guarda para achar o seu canal: a vaga, e qual dos
/// canais que já passaram por ela.
///
/// A vaga sozinha não bastava. O filho de um `fork` herda o descritor do
/// pai; o pai fecha o canal, e a vaga fica livre; o filho escuta um canal e
/// ele cai na mesma vaga. O descritor herdado passava a alcançar o canal
/// novo — agora o ouvinte confere, porque é o filho —, e fechá-lo largava
/// o canal que o filho acabara de abrir. A geração é um número que nenhum
/// outro canal recebe, e o descritor velho é recusado porque ela não
/// confere. É a mesma chave das superfícies — ver
/// [`crate::superficies::Chave`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chave {
    pub vaga: usize,
    pub geracao: u64,
}

struct Canal {
    geracao: u64,
    nome: [u8; NOME_MAX],
    tamanho_do_nome: usize,
    /// O fio do processo que escuta.
    ouvinte: u64,
    fila: [Evento; CAPACIDADE],
    /// Onde está o evento mais antigo, e quantos há.
    inicio: usize,
    quantos: usize,
    /// O ouvinte está estacionado numa leitura deste canal.
    esperando: bool,
    publicados: u64,
    entregues: u64,
    recusados: u64,
}

impl Canal {
    fn nome(&self) -> &[u8] {
        &self.nome[..self.tamanho_do_nome]
    }
}

// A tomada desta tranca passa por `sem_interrupcoes`, como toda tranca deste
// kernel: quem publica pode ser um handler de interrupção. E é solta no
// caminho fatal.
static CANAIS_ABERTOS: Mutex<[Option<Canal>; CANAIS]> = Mutex::new([const { None }; CANAIS]);

/// Quantos canais de ouvinte morto já foram devolvidos.
static RECUPERADOS: AtomicU64 = AtomicU64::new(0);

/// A geração do próximo canal — ver [`Chave`]. Só anda sob a tranca dos
/// canais, mas é atômica para não precisar de outra.
static PROXIMA_GERACAO: AtomicU64 = AtomicU64::new(1);

fn com_canais<R>(f: impl FnOnce(&mut [Option<Canal>; CANAIS]) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut CANAIS_ABERTOS.lock()))
}

/// Devolve a vaga de um canal cujo ouvinte já morreu.
///
/// Chamada por toda operação que procura um canal pelo nome ou pela vaga,
/// com a tranca na mão. Toma a do escalonador dentro dela — a ordem é
/// sempre essa, canais e depois escalonador, e nunca o contrário.
fn recuperar_se_orfao(vaga: &mut Option<Canal>) {
    if let Some(canal) = vaga
        && !crate::fios::vivo(canal.ouvinte)
    {
        *vaga = None;
        RECUPERADOS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Por que um canal não pôde ser aberto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recusa {
    /// O nome é vazio, grande demais, ou não é texto.
    NomeInvalido,
    /// Há um ouvinte vivo com este nome, ou não há vaga.
    Ocupado,
}

/// Torna `ouvinte` o ouvinte do canal `nome`, e devolve a chave do canal.
pub fn escutar(nome: &[u8], ouvinte: u64) -> Result<Chave, Recusa> {
    if nome.is_empty() || nome.len() > NOME_MAX || core::str::from_utf8(nome).is_err() {
        return Err(Recusa::NomeInvalido);
    }
    com_canais(|canais| {
        canais.iter_mut().for_each(recuperar_se_orfao);
        if canais.iter().flatten().any(|c| c.nome() == nome) {
            return Err(Recusa::Ocupado);
        }
        let vaga = canais
            .iter()
            .position(Option::is_none)
            .ok_or(Recusa::Ocupado)?;
        let mut guardado = [0u8; NOME_MAX];
        guardado[..nome.len()].copy_from_slice(nome);
        let geracao = PROXIMA_GERACAO.fetch_add(1, Ordering::Relaxed);
        canais[vaga] = Some(Canal {
            geracao,
            nome: guardado,
            tamanho_do_nome: nome.len(),
            ouvinte,
            fila: [Evento::default(); CAPACIDADE],
            inicio: 0,
            quantos: 0,
            esperando: false,
            publicados: 0,
            entregues: 0,
            recusados: 0,
        });
        Ok(Chave { vaga, geracao })
    })
}

/// Por que um evento não foi publicado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NaoPublicado {
    /// Ninguém escuta este canal — nunca escutou, ou o ouvinte morreu.
    SemOuvinte,
    /// A fila está cheia. O evento foi recusado e contado.
    Cheio,
}

/// Publica `evento` no canal `nome`, e acorda o ouvinte se ele estiver
/// esperando.
pub fn publicar(nome: &str, evento: Evento) -> Result<(), NaoPublicado> {
    com_canais(|canais| {
        let vaga = canais
            .iter_mut()
            .find(|v| v.as_ref().is_some_and(|c| c.nome() == nome.as_bytes()))
            .ok_or(NaoPublicado::SemOuvinte)?;
        recuperar_se_orfao(vaga);
        let canal = vaga.as_mut().ok_or(NaoPublicado::SemOuvinte)?;
        entregar(canal, evento)
    })
}

/// Publica `evento` no canal da `chave` — pelo canal que um processo deu ao
/// kernel, e não pelo nome. Mesmas regras de [`publicar`].
pub fn publicar_em(chave: Chave, evento: Evento) -> Result<(), NaoPublicado> {
    com_canais(|canais| {
        let vaga = canais.get_mut(chave.vaga).ok_or(NaoPublicado::SemOuvinte)?;
        if vaga.as_ref().is_none_or(|c| c.geracao != chave.geracao) {
            return Err(NaoPublicado::SemOuvinte);
        }
        recuperar_se_orfao(vaga);
        let canal = vaga.as_mut().ok_or(NaoPublicado::SemOuvinte)?;
        entregar(canal, evento)
    })
}

/// Põe o evento na fila do canal e acorda o ouvinte, ou recusa e conta.
fn entregar(canal: &mut Canal, evento: Evento) -> Result<(), NaoPublicado> {
    if canal.quantos == CAPACIDADE {
        canal.recusados += 1;
        return Err(NaoPublicado::Cheio);
    }
    let posicao = (canal.inicio + canal.quantos) % CAPACIDADE;
    canal.fila[posicao] = evento;
    canal.quantos += 1;
    canal.publicados += 1;
    if canal.esperando {
        canal.esperando = false;
        crate::fios::acordar(canal.ouvinte);
    }
    Ok(())
}

/// O que uma leitura do canal deu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Colheita {
    /// Tantos eventos foram copiados para o destino.
    Entregues(usize),
    /// A fila estava vazia, e o fio que leu foi estacionado. A chamada de
    /// sistema vai ser reexecutada quando ele acordar.
    Estacionado,
    /// A vaga não é mais um canal deste ouvinte.
    NaoEhSeu,
}

/// Tira até `destino.len()` eventos do canal da `chave`, para o `ouvinte`.
///
/// # Estacionar sem efeito
///
/// Com a fila vazia, nada é tirado nem mudado além de o canal lembrar que o
/// ouvinte espera — e o fio sai de circulação. É o que torna a reexecução
/// segura: a chamada que volta encontra o canal como estava, agora com o
/// que chegou. Estacionar com a tranca do canal na mão é o que fecha a
/// janela em que um evento chegasse entre "está vazio" e "vou dormir": quem
/// publica toma a mesma tranca, e só vê o ouvinte depois de ele estar
/// marcado como esperando.
pub fn colher(chave: Chave, ouvinte: u64, destino: &mut [Evento]) -> Colheita {
    com_canais(|canais| {
        let Some(canal) = canais.get_mut(chave.vaga).and_then(Option::as_mut) else {
            return Colheita::NaoEhSeu;
        };
        if canal.geracao != chave.geracao || canal.ouvinte != ouvinte {
            return Colheita::NaoEhSeu;
        }
        if canal.quantos == 0 {
            canal.esperando = true;
            crate::fios::estacionar_atual();
            return Colheita::Estacionado;
        }
        let n = destino.len().min(canal.quantos);
        for (i, alvo) in destino.iter_mut().take(n).enumerate() {
            *alvo = canal.fila[(canal.inicio + i) % CAPACIDADE];
        }
        canal.inicio = (canal.inicio + n) % CAPACIDADE;
        canal.quantos -= n;
        canal.entregues += n as u64;
        Colheita::Entregues(n)
    })
}

/// A `chave` é de um canal aberto que o `ouvinte` escuta?
pub fn e_ouvinte(chave: Chave, ouvinte: u64) -> bool {
    com_canais(|canais| {
        canais
            .get(chave.vaga)
            .and_then(Option::as_ref)
            .is_some_and(|c| c.geracao == chave.geracao && c.ouvinte == ouvinte)
    })
}

/// Fecha o canal da `chave`, se ele for do `ouvinte`.
pub fn largar(chave: Chave, ouvinte: u64) {
    com_canais(|canais| {
        if let Some(v) = canais.get_mut(chave.vaga)
            && v.as_ref()
                .is_some_and(|c| c.geracao == chave.geracao && c.ouvinte == ouvinte)
        {
            *v = None;
        }
    });
}

/// O que se sabe de um canal, para o agente e para a suíte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Estado {
    pub ouvinte: u64,
    pub na_fila: usize,
    pub esperando: bool,
    pub publicados: u64,
    pub entregues: u64,
    pub recusados: u64,
}

/// O estado do canal `nome`, se há quem o escute.
pub fn estado(nome: &str) -> Option<Estado> {
    com_canais(|canais| {
        let vaga = canais
            .iter_mut()
            .find(|v| v.as_ref().is_some_and(|c| c.nome() == nome.as_bytes()))?;
        recuperar_se_orfao(vaga);
        let c = vaga.as_ref()?;
        Some(Estado {
            ouvinte: c.ouvinte,
            na_fila: c.quantos,
            esperando: c.esperando,
            publicados: c.publicados,
            entregues: c.entregues,
            recusados: c.recusados,
        })
    })
}

/// Quantos canais de ouvinte morto já foram devolvidos.
pub fn recuperados() -> u64 {
    RECUPERADOS.load(Ordering::Relaxed)
}

/// Destrava os canais à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { CANAIS_ABERTOS.force_unlock() };
}
