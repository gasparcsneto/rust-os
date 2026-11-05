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
//! # A tabela
//!
//! Fixa, e do tamanho do pior caso dos processos: dois canais por fio que o
//! escalonador comporta — ver [`CANAIS`]. Nenhum conjunto de processos a
//! enche, e o laço de um processo não ouve `OCUPADO` porque outros
//! escutaram antes. Ela não usa o heap: quem publica pode ser um handler de
//! interrupção, onde não se pede nem se devolve memória, e `escutar`, que
//! não passa pelo gate, não pode fazer da falta de memória um pânico do
//! kernel. A vaga livre é toda em zero ([`Canal::LIVRE`]), e a tabela
//! inteira vai para o `.bss`: pesa na memória, uns 400 KiB fixos, e não na
//! imagem.
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
//! canal de ouvinte morto é devolvido ali mesmo — a vaga volta a ser toda em
//! zero —, e o nome fica livre para o próximo. É a mesma escolha da tabela
//! de descritores morar no fio — nada aqui depende de alguém lembrar de
//! limpar no caminho da morte.
//!
//! `escutar` confere a tabela inteira, antes de qualquer recusa, contra uma
//! fotografia dos fios vivos tirada uma vez, com a tranca dos canais na mão:
//! uma tomada da tranca do escalonador por varredura, e não uma por canal.
//! Quem publica confere só o canal que achou.

// Quem publica em produção ainda não existe: é o roteamento de entrada do
// servidor de janelas, na etapa seguinte. Até lá só a suíte publica, e o que
// só ela usa fica marcado — em vez de um publicador inventado para o build
// ficar limpo.
#![cfg_attr(not(feature = "modo-teste"), allow(dead_code))]

use core::sync::atomic::{AtomicU64, Ordering};

use crate::trava::Mutex;
use protocolo::usuario::evento::Evento;

/// Quantos canais podem existir ao mesmo tempo: dois por fio que o
/// escalonador comporta — o pior caso dos processos.
///
/// Em produção só um processo escuta, e só pela chamada `escutar`: como ele
/// mesmo — o ouvinte é o fio que chama —, e no máximo
/// [`CANAIS_POR_PROCESSO`], conferido em [`escutar`] na mesma seção crítica
/// que insere. Um processo é um fio só, todo fio vivo ocupa uma das
/// [`crate::fios::MAX_FIOS`] vagas do escalonador, e o canal de quem morreu
/// volta na varredura de cada `escutar`, antes de qualquer recusa. Então
/// nenhum conjunto de processos — de um principal ou de vários — enche esta
/// tabela: o pior caso cabe por construção, sem cota por principal.
///
/// A conta é com todas as vagas do escalonador, e não com as de trabalho
/// ([`crate::fios::VAGAS_DE_TRABALHO`]): estas são o mínimo garantido ao
/// trabalho com todos os núcleos ligados, e com menos núcleos a vaga do
/// ocioso que não existe também recebe processo. Os fios do kernel que
/// escutam fora da chamada, sem o teto, são só os da suíte, e não entram na
/// conta.
///
/// Eram 8 — o servidor de janelas, o Terminal e os programas da suíte —, e
/// 32 com o aviso da malha (DS-1). Cada canal custa a fila dele,
/// [`CAPACIDADE`] eventos, numa tabela fixa — ver [`Canal::LIVRE`].
pub const CANAIS: usize = CANAIS_POR_PROCESSO * crate::fios::MAX_FIOS;

/// Quantos canais um processo escuta ao mesmo tempo: um para o laço dele e
/// um de folga.
///
/// O teto é conferido em [`escutar`] — a função da chamada —, na mesma
/// seção crítica que insere o canal: entre contar e inserir não há janela,
/// nem para um processo com dois fios, se um dia houver. Só a suíte escuta
/// sem ele, dos fios do kernel (`escutar_sem_teto`, que só existe com
/// `modo-teste`).
pub const CANAIS_POR_PROCESSO: usize = 2;

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

/// Uma vaga da tabela: um canal, ou nenhum — a geração zero, ver
/// [`Canal::LIVRE`].
struct Canal {
    /// A geração do canal — ver [`Chave`]. Zero é a vaga livre: nenhum canal
    /// recebe zero, porque [`PROXIMA_GERACAO`] começa em 1.
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

/// O evento todo em zero, que enche a fila de uma vaga livre. Escrito à
/// mão, e não `Evento::default()`, porque precisa existir em tempo de
/// compilação.
const EVENTO_ZERADO: Evento = Evento {
    tipo: 0,
    a: 0,
    b: 0,
    c: 0,
};

impl Canal {
    /// A vaga livre: tudo em zero. É o que a tabela tem no boot, e o que a
    /// vaga volta a ter quando o canal é largado ou o ouvinte morre — sem
    /// nada a devolver a ninguém, também quando quem a devolve é quem
    /// publica, num handler de interrupção.
    ///
    /// Toda em zero, a tabela inteira vai para o `.bss`. Era um
    /// `Option<Canal>`, e o `None` usava o nicho do `esperando`: um byte
    /// diferente de zero em cada vaga, e a tabela ia para o `.data`, dentro
    /// da imagem.
    const LIVRE: Canal = Canal {
        geracao: 0,
        nome: [0; NOME_MAX],
        tamanho_do_nome: 0,
        ouvinte: 0,
        fila: [EVENTO_ZERADO; CAPACIDADE],
        inicio: 0,
        quantos: 0,
        esperando: false,
        publicados: 0,
        entregues: 0,
        recusados: 0,
    };

    /// A vaga tem um canal?
    fn aberto(&self) -> bool {
        self.geracao != 0
    }

    /// A vaga tem o canal da `chave`? Numa vaga livre, nunca: uma chave é de
    /// um canal que existiu, e a geração dele não é zero.
    fn e_da(&self, chave: Chave) -> bool {
        self.aberto() && self.geracao == chave.geracao
    }

    /// A vaga tem um canal com este nome?
    fn chama(&self, nome: &[u8]) -> bool {
        self.aberto() && self.nome() == nome
    }

    fn nome(&self) -> &[u8] {
        &self.nome[..self.tamanho_do_nome]
    }
}

// A tomada desta tranca passa por `sem_interrupcoes`, como toda tranca deste
// kernel: quem publica pode ser um handler de interrupção. E é solta no
// caminho fatal.
static CANAIS_ABERTOS: Mutex<[Canal; CANAIS]> = Mutex::new([const { Canal::LIVRE }; CANAIS]);

/// Quantos canais de ouvinte morto já foram devolvidos.
static RECUPERADOS: AtomicU64 = AtomicU64::new(0);

/// A geração do próximo canal — ver [`Chave`]. Começa em 1: a zero é a da
/// vaga livre. Só anda sob a tranca dos canais, mas é atômica para não
/// precisar de outra.
static PROXIMA_GERACAO: AtomicU64 = AtomicU64::new(1);

/// Só para a suíte: quantas vezes a varredura em curso perguntou ao
/// escalonador quem vive — a fotografia conta uma; cada pergunta por um
/// ouvinte, uma. Só quem tem a tranca dos canais mexe nele.
#[cfg(feature = "modo-teste")]
static CONSULTAS_NA_VARREDURA: AtomicU64 = AtomicU64::new(0);

/// Só para a suíte: a maior conta de [`CONSULTAS_NA_VARREDURA`] numa
/// varredura, desde a última pergunta — ver [`mais_consultas_de_teste`].
#[cfg(feature = "modo-teste")]
static MAIS_CONSULTAS: AtomicU64 = AtomicU64::new(0);

fn com_canais<R>(f: impl FnOnce(&mut [Canal; CANAIS]) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut CANAIS_ABERTOS.lock()))
}

/// Devolve a vaga de um canal cujo ouvinte já morreu: ela volta a ser toda
/// em zero.
///
/// Chamada por toda operação que procura um canal pelo nome ou pela vaga,
/// com a tranca na mão. `vive` pergunta ao escalonador — ou à fotografia
/// que uma varredura tirou dele —, e a tranca dele é tomada dentro da dos
/// canais: a ordem é sempre essa, canais e depois escalonador, e nunca o
/// contrário.
fn recuperar_se_orfao(canal: &mut Canal, vive: impl FnOnce(u64) -> bool) {
    if canal.aberto() && !vive(canal.ouvinte) {
        *canal = Canal::LIVRE;
        RECUPERADOS.fetch_add(1, Ordering::Relaxed);
    }
}

/// A pergunta ao escalonador por um ouvinte só: uma tomada da tranca dele.
/// É a de quem procura um canal — quem publica, quem pede o estado.
fn ainda_vive(id: u64) -> bool {
    #[cfg(feature = "modo-teste")]
    CONSULTAS_NA_VARREDURA.fetch_add(1, Ordering::Relaxed);
    crate::fios::vivo(id)
}

/// Os ids dos fios vivos, ordenados: uma tomada da tranca do escalonador
/// para a tabela inteira.
fn fotografar(ids: &mut [u64; crate::fios::MAX_FIOS]) -> &[u64] {
    #[cfg(feature = "modo-teste")]
    CONSULTAS_NA_VARREDURA.fetch_add(1, Ordering::Relaxed);
    let quantos = crate::fios::ids_vivos(ids);
    let vivos = &mut ids[..quantos];
    vivos.sort_unstable();
    vivos
}

/// A varredura: devolve todo canal de ouvinte morto, conferindo os ouvintes
/// contra uma fotografia dos fios vivos — uma tomada da tranca do
/// escalonador, e não uma por canal.
///
/// A fotografia é tirada com a tranca dos canais na mão, e é isso que a
/// torna certa. Todo canal da tabela foi aberto antes dela, por um ouvinte
/// que já existia, e um id não é reusado: o ouvinte que não está nela
/// morreu. Tirada antes da tranca, ela não teria o fio que nasceu depois —
/// e daria por órfão o canal que ele abrisse, em outro núcleo, antes de a
/// varredura começar.
fn recuperar_orfaos(canais: &mut [Canal; CANAIS]) {
    #[cfg(feature = "modo-teste")]
    CONSULTAS_NA_VARREDURA.store(0, Ordering::Relaxed);
    let mut ids = [0u64; crate::fios::MAX_FIOS];
    let vivos = fotografar(&mut ids);
    for canal in canais.iter_mut() {
        recuperar_se_orfao(canal, |id| vivos.binary_search(&id).is_ok());
    }
    #[cfg(feature = "modo-teste")]
    MAIS_CONSULTAS.fetch_max(
        CONSULTAS_NA_VARREDURA.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
}

/// Por que um canal não pôde ser aberto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recusa {
    /// O nome é vazio, grande demais, ou não é texto.
    NomeInvalido,
    /// Há um ouvinte vivo com este nome, ou não há vaga.
    Ocupado,
    /// O ouvinte já escuta [`CANAIS_POR_PROCESSO`] canais: o teto da
    /// chamada. Quem a atende responde o mesmo `OCUPADO` das outras.
    TetoDoOuvinte,
}

/// Torna `ouvinte` o ouvinte do canal `nome`, e devolve a chave do canal: o
/// que a chamada `escutar` faz, com o teto de [`CANAIS_POR_PROCESSO`] canais
/// por ouvinte, contado na mesma seção crítica que insere.
pub fn escutar(nome: &[u8], ouvinte: u64) -> Result<Chave, Recusa> {
    abrir(nome, ouvinte, Some(CANAIS_POR_PROCESSO))
}

/// Só para a suíte: [`escutar`] sem o teto — os fios do kernel que tomam mais
/// nomes do que um processo pode, para encher a tabela ou os nomes de um
/// laço.
#[cfg(feature = "modo-teste")]
pub fn escutar_sem_teto(nome: &[u8], ouvinte: u64) -> Result<Chave, Recusa> {
    abrir(nome, ouvinte, None)
}

/// Abre o canal `nome` para o `ouvinte`, com o `teto` de canais dele, se há.
///
/// Uma seção crítica, e uma varredura só, antes de qualquer recusa: os
/// canais de ouvinte morto não são limitados pelos fios vivos, e contá-los
/// recusaria por um teto, um nome ou uma vaga que já não são de ninguém.
/// Depois, na ordem de sempre: o teto, o nome, a vaga.
fn abrir(nome: &[u8], ouvinte: u64, teto: Option<usize>) -> Result<Chave, Recusa> {
    if nome.is_empty() || nome.len() > NOME_MAX || core::str::from_utf8(nome).is_err() {
        return Err(Recusa::NomeInvalido);
    }
    let mut guardado = [0u8; NOME_MAX];
    guardado[..nome.len()].copy_from_slice(nome);
    com_canais(|canais| {
        recuperar_orfaos(canais);
        if let Some(teto) = teto {
            let dele = canais
                .iter()
                .filter(|c| c.aberto() && c.ouvinte == ouvinte)
                .count();
            if dele >= teto {
                return Err(Recusa::TetoDoOuvinte);
            }
        }
        if canais.iter().any(|c| c.chama(nome)) {
            return Err(Recusa::Ocupado);
        }
        let vaga = canais
            .iter()
            .position(|c| !c.aberto())
            .ok_or(Recusa::Ocupado)?;
        let geracao = PROXIMA_GERACAO.fetch_add(1, Ordering::Relaxed);
        canais[vaga] = Canal {
            geracao,
            nome: guardado,
            tamanho_do_nome: nome.len(),
            ouvinte,
            ..Canal::LIVRE
        };
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
        let canal = canais
            .iter_mut()
            .find(|c| c.chama(nome.as_bytes()))
            .ok_or(NaoPublicado::SemOuvinte)?;
        recuperar_se_orfao(canal, ainda_vive);
        if !canal.aberto() {
            return Err(NaoPublicado::SemOuvinte);
        }
        entregar(canal, evento)
    })
}

/// Publica `evento` no canal da `chave` — pelo canal que um processo deu ao
/// kernel, e não pelo nome. Mesmas regras de [`publicar`].
pub fn publicar_em(chave: Chave, evento: Evento) -> Result<(), NaoPublicado> {
    com_canais(|canais| {
        let canal = canais
            .get_mut(chave.vaga)
            .filter(|c| c.e_da(chave))
            .ok_or(NaoPublicado::SemOuvinte)?;
        recuperar_se_orfao(canal, ainda_vive);
        if !canal.aberto() {
            return Err(NaoPublicado::SemOuvinte);
        }
        entregar(canal, evento)
    })
}

/// Se um evento publicado agora no canal `nome` entraria: há quem escute, e
/// a fila tem lugar. Não publica nem conta nada — para quem precisa recusar
/// antes de mudar alguma coisa, como a interface antes da conta da
/// coordenação. A resposta vale para o instante.
pub fn caberia(nome: &str) -> Result<(), NaoPublicado> {
    com_canais(|canais| {
        let canal = canais
            .iter_mut()
            .find(|c| c.chama(nome.as_bytes()))
            .ok_or(NaoPublicado::SemOuvinte)?;
        recuperar_se_orfao(canal, ainda_vive);
        caberia_no(canal)
    })
}

/// [`caberia`], pelo canal da `chave`.
pub fn caberia_em(chave: Chave) -> Result<(), NaoPublicado> {
    com_canais(|canais| {
        let canal = canais
            .get_mut(chave.vaga)
            .filter(|c| c.e_da(chave))
            .ok_or(NaoPublicado::SemOuvinte)?;
        recuperar_se_orfao(canal, ainda_vive);
        caberia_no(canal)
    })
}

/// A conferência de [`entregar`], sem entregar.
fn caberia_no(canal: &Canal) -> Result<(), NaoPublicado> {
    if !canal.aberto() {
        return Err(NaoPublicado::SemOuvinte);
    }
    if canal.quantos == CAPACIDADE {
        return Err(NaoPublicado::Cheio);
    }
    Ok(())
}

/// Como foi publicado um evento por [`publicar_em_juntando`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Publicado {
    /// Entrou na fila, como outro qualquer.
    Novo,
    /// Juntou-se a um evento que ainda esperava na fila: a fila não cresceu.
    Junto,
}

/// Como [`publicar_em`], mas um evento que ainda espera na fila e que
/// `juntar` aceita recebe o novo, em vez de outro entrar: `juntar(na_fila,
/// novo)` diz se juntou. Junto, a fila não cresce — também cheia —, e o
/// ouvinte já tem o que ler: não há quem acordar.
pub fn publicar_em_juntando(
    chave: Chave,
    evento: Evento,
    juntar: impl Fn(&mut Evento, &Evento) -> bool,
) -> Result<Publicado, NaoPublicado> {
    com_canais(|canais| {
        let canal = canais
            .get_mut(chave.vaga)
            .filter(|c| c.e_da(chave))
            .ok_or(NaoPublicado::SemOuvinte)?;
        recuperar_se_orfao(canal, ainda_vive);
        if !canal.aberto() {
            return Err(NaoPublicado::SemOuvinte);
        }
        for i in 0..canal.quantos {
            let posicao = (canal.inicio + i) % CAPACIDADE;
            if juntar(&mut canal.fila[posicao], &evento) {
                return Ok(Publicado::Junto);
            }
        }
        entregar(canal, evento).map(|()| Publicado::Novo)
    })
}

/// Junta `evento` a um que ainda espera na fila do canal da `chave` e que
/// `juntar` aceita — e só isso: sem um assim, nada entra na fila, e o
/// ouvinte não é acordado. Devolve se juntou.
pub fn juntar_na_fila(
    chave: Chave,
    evento: &Evento,
    juntar: impl Fn(&mut Evento, &Evento) -> bool,
) -> bool {
    com_canais(|canais| {
        let Some(canal) = canais.get_mut(chave.vaga).filter(|c| c.e_da(chave)) else {
            return false;
        };
        for i in 0..canal.quantos {
            let posicao = (canal.inicio + i) % CAPACIDADE;
            if juntar(&mut canal.fila[posicao], evento) {
                return true;
            }
        }
        false
    })
}

/// Quantos eventos [`descartar`] já tirou das filas.
static DESCARTADOS: AtomicU64 = AtomicU64::new(0);

/// Tira das filas dos canais que o `ouvinte` escuta os eventos do tipo
/// `tipo`, na ordem em que os outros ficam: na troca de imagem, os avisos
/// da malha que a imagem anterior não leu — a imagem nova não ouve os
/// avisos da anterior. Devolve quantos saíram.
///
/// As posições que a fila deixa de usar ficam em zero: compactar copia os
/// que ficam para a frente, e o que estava atrás deles — uma tecla, que
/// pode ser de uma senha — ficaria no anel em dobro, até ser sobrescrito.
pub fn descartar(ouvinte: u64, tipo: u32) -> usize {
    let tirados = com_canais(|canais| {
        let mut tirados = 0;
        for canal in canais
            .iter_mut()
            .filter(|c| c.aberto() && c.ouvinte == ouvinte)
        {
            let mut ficam = 0;
            for i in 0..canal.quantos {
                let e = canal.fila[(canal.inicio + i) % CAPACIDADE];
                if e.tipo == tipo {
                    tirados += 1;
                } else {
                    canal.fila[(canal.inicio + ficam) % CAPACIDADE] = e;
                    ficam += 1;
                }
            }
            for i in ficam..canal.quantos {
                canal.fila[(canal.inicio + i) % CAPACIDADE] = EVENTO_ZERADO;
            }
            canal.quantos = ficam;
        }
        tirados
    });
    DESCARTADOS.fetch_add(tirados as u64, Ordering::Relaxed);
    tirados
}

/// Só para a suíte: quantos eventos as trocas de imagem já tiraram das
/// filas.
#[cfg(feature = "modo-teste")]
pub fn descartados_de_teste() -> u64 {
    DESCARTADOS.load(Ordering::Relaxed)
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
///
/// # O que é entregue sai do anel
///
/// A posição de cada evento entregue volta a zero. Copiar e só mexer no
/// começo deixaria o evento no anel até outro cair na mesma posição — e o
/// evento pode ser uma tecla da janela de um Terminal, que pode ser de uma
/// senha. Quem leu tem a cópia dele, e é ele quem a guarda ou zera.
pub fn colher(chave: Chave, ouvinte: u64, destino: &mut [Evento]) -> Colheita {
    com_canais(|canais| {
        let Some(canal) = canais.get_mut(chave.vaga).filter(|c| c.e_da(chave)) else {
            return Colheita::NaoEhSeu;
        };
        if canal.ouvinte != ouvinte {
            return Colheita::NaoEhSeu;
        }
        if canal.quantos == 0 {
            canal.esperando = true;
            crate::fios::estacionar_atual();
            return Colheita::Estacionado;
        }
        let n = destino.len().min(canal.quantos);
        for (i, alvo) in destino.iter_mut().take(n).enumerate() {
            let posicao = (canal.inicio + i) % CAPACIDADE;
            *alvo = canal.fila[posicao];
            canal.fila[posicao] = EVENTO_ZERADO;
        }
        canal.inicio = (canal.inicio + n) % CAPACIDADE;
        canal.quantos -= n;
        canal.entregues += n as u64;
        Colheita::Entregues(n)
    })
}

/// O nome do canal da `chave`, se ele está aberto.
///
/// Os bytes saem da tranca numa cópia, e o texto nasce fora dela: nada aloca
/// com os canais travados.
pub fn nome_de(chave: Chave) -> Option<alloc::string::String> {
    let (nome, tamanho) = com_canais(|canais| {
        let c = canais.get(chave.vaga).filter(|c| c.e_da(chave))?;
        Some((c.nome, c.tamanho_do_nome))
    })?;
    Some(alloc::string::String::from_utf8_lossy(&nome[..tamanho]).into_owned())
}

/// A `chave` é de um canal aberto que o `ouvinte` escuta?
pub fn e_ouvinte(chave: Chave, ouvinte: u64) -> bool {
    com_canais(|canais| {
        canais
            .get(chave.vaga)
            .is_some_and(|c| c.e_da(chave) && c.ouvinte == ouvinte)
    })
}

/// Fecha o canal da `chave`, se ele for do `ouvinte`: a vaga volta a ser
/// toda em zero.
pub fn largar(chave: Chave, ouvinte: u64) {
    com_canais(|canais| {
        if let Some(canal) = canais.get_mut(chave.vaga)
            && canal.e_da(chave)
            && canal.ouvinte == ouvinte
        {
            *canal = Canal::LIVRE;
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
        let c = canais.iter_mut().find(|c| c.chama(nome.as_bytes()))?;
        recuperar_se_orfao(c, ainda_vive);
        if !c.aberto() {
            return None;
        }
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

/// Só para a suíte: alguma posição do anel do canal da `chave` — a fila e o
/// que ficou fora dela — satisfaz `f`? É o que diz se um evento entregue ou
/// descartado ficou para trás.
#[cfg(feature = "modo-teste")]
pub fn guarda_de_teste(chave: Chave, f: impl Fn(&Evento) -> bool) -> bool {
    com_canais(|canais| {
        canais
            .get(chave.vaga)
            .filter(|c| c.e_da(chave))
            .is_some_and(|c| c.fila.iter().any(&f))
    })
}

/// Só para a suíte: a vaga do canal `nome`, se ele está aberto.
#[cfg(feature = "modo-teste")]
pub fn vaga_de_teste(nome: &str) -> Option<usize> {
    com_canais(|canais| canais.iter().position(|c| c.chama(nome.as_bytes())))
}

/// Só para a suíte: quantos canais o `ouvinte` escuta agora — depois da
/// varredura que devolve os de ouvinte morto.
#[cfg(feature = "modo-teste")]
pub fn canais_de_teste(ouvinte: u64) -> usize {
    com_canais(|canais| {
        recuperar_orfaos(canais);
        canais
            .iter()
            .filter(|c| c.aberto() && c.ouvinte == ouvinte)
            .count()
    })
}

/// Só para a suíte: quantos canais estão abertos — depois da varredura que
/// devolve os de ouvinte morto.
#[cfg(feature = "modo-teste")]
pub fn abertos_de_teste() -> usize {
    com_canais(|canais| {
        recuperar_orfaos(canais);
        canais.iter().filter(|c| c.aberto()).count()
    })
}

/// Só para a suíte: a maior conta de perguntas ao escalonador numa
/// varredura, desde a última vez que se perguntou — e a zera. Com a
/// fotografia, uma por varredura, por cheia que esteja a tabela.
#[cfg(feature = "modo-teste")]
pub fn mais_consultas_de_teste() -> u64 {
    MAIS_CONSULTAS.swap(0, Ordering::Relaxed)
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
