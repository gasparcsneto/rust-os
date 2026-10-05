//! Os pseudo-terminais: um console do interpretador para cada Terminal.
//!
//! # O que eles são
//!
//! O arranjo do Unix, reduzido ao que o Terminal precisa. Cada Terminal que
//! abre recebe um pseudo-terminal **seu**, e com ele um console seu do
//! interpretador — ver [`crate::interpretador`]: a linha de comando, a
//! pessoa que entrou nele e a sessão dela. Dois sentidos, por instância:
//!
//! - **o que o processo escreve é digitado** no console dele: cada caractere
//!   entra na fila de entrada desta instância, que o interpretador lê;
//! - **o que o console imprime é lido**: o eco, o prompt e as respostas do
//!   console desta instância vão para um anel de bytes daqui, e o processo
//!   o lê.
//!
//! # Por que um console por Terminal, e não um espelho do físico
//!
//! Antes, o Terminal era outra janela sobre o mesmo interpretador: o que se
//! digitava nele caía na fila do teclado da máquina, e o anel guardava tudo
//! o que o kernel imprimia. Com pessoas, isso não serve: quem entra num
//! Terminal é uma sessão, e a pessoa no console físico é outra — mesmo que
//! seja a mesma pessoa. Cada uma tem a sua linha, o seu login e o que ela
//! pode; o que uma digita não aparece na outra, e o log do kernel continua
//! no console físico, que é o fundo e a reserva.
//!
//! # Por que a leitura não bloqueia
//!
//! Porque o Terminal espera duas coisas: a saída do console e o teclado. Um
//! processo deste kernel tem um fio só, e um fio que dormisse na leitura do
//! pseudo-terminal não veria a tecla que chegasse no canal dele. Então a
//! espera é uma só, no canal de eventos: o kernel avisa ali, com um evento
//! [`SAIDA`](protocolo::usuario::evento::tipo::SAIDA), que há o que ler, e o
//! processo lê até a leitura devolver zero.
//!
//! # Por que o aviso é adiado
//!
//! Porque quem escreve no anel pode rodar com a tranca do escalonador na
//! mão. Avisar é publicar no canal, e publicar acorda o ouvinte, que toma a
//! tranca do escalonador. Quem escreve só marca que há saída nova, e quem
//! avisa é o coletor de fios, a cada volta — um tique de atraso, de um lugar
//! sem tranca nenhuma na mão.
//!
//! # O anel
//!
//! Guarda os últimos [`ANEL`] bytes que o console imprimiu. O que não cabe
//! empurra o mais antigo para fora, e é contado — o kernel não espera um
//! leitor lento para imprimir.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::trava::Mutex;

use crate::pessoas::Console;
use crate::tarefas::fila::Fila;

/// Quantos Terminais podem ter um pseudo-terminal aberto ao mesmo tempo.
pub const TERMINAIS: usize = 4;

/// Quantos bytes da saída o anel de cada um guarda.
pub const ANEL: usize = 16 * 1024;

/// Quantos caracteres digitados cabem esperando o interpretador.
pub const ENTRADA: usize = 256;

struct Anel {
    bytes: [u8; ANEL],
    /// Onde está o byte mais antigo, e quantos há.
    inicio: usize,
    quantos: usize,
}

impl Anel {
    const VAZIO: Anel = Anel {
        bytes: [0; ANEL],
        inicio: 0,
        quantos: 0,
    };

    fn pôr(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if self.quantos == ANEL {
                // Cheio: o mais antigo sai.
                self.inicio = (self.inicio + 1) % ANEL;
                self.quantos -= 1;
                PERDIDOS.fetch_add(1, Ordering::Relaxed);
            }
            self.bytes[(self.inicio + self.quantos) % ANEL] = b;
            self.quantos += 1;
        }
    }

    fn tirar(&mut self, destino: &mut [u8]) -> usize {
        let n = destino.len().min(self.quantos);
        for (i, d) in destino.iter_mut().take(n).enumerate() {
            *d = self.bytes[(self.inicio + i) % ANEL];
        }
        self.inicio = (self.inicio + n) % ANEL;
        self.quantos -= n;
        n
    }

    fn esvaziar(&mut self) {
        self.inicio = 0;
        self.quantos = 0;
    }
}

/// Quem tem um pseudo-terminal aberto.
#[derive(Clone, Copy)]
struct Dono {
    fio: u64,
    geracao: u64,
    /// O canal onde o kernel avisa que há saída.
    canal: crate::eventos::Chave,
}

/// O que uma instância é agora.
///
/// # Por que há um estado entre aberta e livre
///
/// Fechar e abrir o console mexem no interpretador — e fechar encerra a
/// sessão de quem estava nele, o que passa pelo registro de pessoas e pela
/// auditoria. Isso não cabe sob [`DONOS`], que é uma folha tomada com as
/// interrupções mascaradas; é feito fora dela.
///
/// Com um núcleo só, fazer fora bastava. Com vários, o coletor de fios
/// (que fecha o console de um dono morto) e um `abrir` em outro núcleo
/// correm juntos, e a ordem antiga — largar a vaga sob a tranca, fechar o
/// console depois — deixava uma janela: o `abrir` via a vaga livre, abria o
/// console para o novo dono, e o fechamento atrasado do coletor fechava o
/// console **do novo dono**, ou o `abrir` zerava o console antes do
/// fechamento e a sessão de quem estava no Terminal morto ficava viva no
/// registro, sem console. Os dois foram vistos na suíte, com quatro núcleos.
///
/// Então quem vai mexer no console marca a vaga [`Vaga::EmTroca`] sob a
/// tranca, mexe fora dela, e só então a solta — livre, ou aberta para o
/// novo dono. Uma vaga em troca não é de ninguém: não é tomada por outro
/// `abrir`, não é colhida pelo coletor, e nenhuma chave a alcança. Só quem a
/// marcou a desmarca, e quem a marcou é sempre o próprio fio, dentro do
/// kernel, que não morre no meio — um fio só termina a si mesmo.
#[derive(Clone, Copy)]
enum Vaga {
    Livre,
    EmTroca,
    Aberta(Dono),
}

impl Vaga {
    fn dono(self) -> Option<Dono> {
        match self {
            Vaga::Aberta(d) => Some(d),
            _ => None,
        }
    }
}

// Tomadas sempre por `sem_interrupcoes`, e cada seção sob elas é uma folha:
// copia bytes, e não toma outra tranca — ver `saida`. Soltas no caminho
// fatal.
static SAIDAS: [Mutex<Anel>; TERMINAIS] = [const { Mutex::new(Anel::VAZIO) }; TERMINAIS];
static DONOS: Mutex<[Vaga; TERMINAIS]> = Mutex::new([Vaga::Livre; TERMINAIS]);
static ENTRADAS: [Fila<char, ENTRADA>; TERMINAIS] = [const { Fila::nova() }; TERMINAIS];

/// Houve saída desde o último aviso, por instância.
static PENDENTES: [AtomicBool; TERMINAIS] = [const { AtomicBool::new(false) }; TERMINAIS];
static PROXIMA_GERACAO: AtomicU64 = AtomicU64::new(1);
/// Bytes que saíram de um anel sem ninguém lê-los; avisos entregues; teclas
/// digitadas pelos pseudo-terminais.
static PERDIDOS: AtomicU64 = AtomicU64::new(0);
static AVISOS: AtomicU64 = AtomicU64::new(0);
static DIGITADOS: AtomicU64 = AtomicU64::new(0);

/// O que um descritor de pseudo-terminal guarda: qual instância, e qual
/// abertura dela.
///
/// Uma geração, pelo motivo dos canais e das superfícies: o descritor de
/// quem fechou não alcança a abertura seguinte da mesma instância.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chave {
    pub indice: u8,
    pub geracao: u64,
}

impl Chave {
    /// O console desta instância.
    pub fn console(self) -> Console {
        Console::Terminal(u16::from(self.indice))
    }
}

/// O que o console da instância `indice` imprimiu. Chamada pelo
/// interpretador.
///
/// # Esperar a tranca, e não perder o texto
///
/// A versão anterior tomava a tranca do anel por `try_lock` e, se ela
/// estivesse tomada, **jogava o texto fora**: quem imprime não podia esperar
/// ninguém. Com um núcleo só, ela nunca estava tomada nesse instante — toda
/// outra mão nela mascarava as interrupções, e então nada rodava no meio.
/// Com vários, o processo do Terminal lendo o anel num núcleo, ou quem
/// abre a instância, segura a tranca enquanto o interpretador imprime em
/// outro, e o prompt, o eco ou a resposta somem sem deixar rastro — nem na
/// conta de perdidos, que é a do anel cheio.
///
/// Esperar é seguro porque toda seção sob esta tranca é uma **folha**: copia
/// bytes para dentro ou para fora do anel, e não toma outra tranca nem
/// imprime nada. Quem a segura sempre a solta, sem depender de ninguém. O
/// que a espera precisa é ser mascarada, como a de todo o resto: sem isso,
/// uma interrupção que imprimisse no mesmo console, neste núcleo, esperaria
/// pela tranca que o código interrompido segura.
pub fn saida(indice: u8, texto: &str) {
    let Some(anel) = SAIDAS.get(usize::from(indice)) else {
        return;
    };
    crate::arch::sem_interrupcoes(|| {
        anel.lock().pôr(texto.as_bytes());
    });
    PENDENTES[usize::from(indice)].store(true, Ordering::Relaxed);
}

/// O `core::fmt` do console de uma instância.
pub struct Saida(pub u8);

impl core::fmt::Write for Saida {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        saida(self.0, s);
        Ok(())
    }
}

/// Por que um pseudo-terminal não abriu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recusa {
    /// Todas as instâncias têm dono vivo, ou quem pede já tem uma: um
    /// processo, um console.
    Ocupado,
}

/// Abre um pseudo-terminal para `fio`, com os avisos no `canal`: a primeira
/// instância livre. Um dono morto não segura a dele: quem abre confere, e
/// toma o lugar.
///
/// O console da instância começa do zero — sem ninguém entrado, a linha
/// vazia, o anel e a entrada vazios —, e o que ficou de uma abertura
/// anterior é encerrado antes: a sessão de quem estava nele acaba.
///
/// A vaga fica [em troca](Vaga::EmTroca) enquanto o console é fechado e
/// reaberto, e só vira do novo dono depois: ninguém a usa pela metade.
pub fn abrir(fio: u64, canal: crate::eventos::Chave) -> Result<Chave, Recusa> {
    let (chave, anterior) = crate::arch::sem_interrupcoes(|| {
        let mut donos = DONOS.lock();
        if donos.iter().any(|d| {
            d.dono()
                .is_some_and(|d| d.fio == fio && crate::fios::vivo(d.fio))
        }) {
            return Err(Recusa::Ocupado);
        }
        let indice = donos
            .iter()
            .position(|d| match d {
                Vaga::Livre => true,
                Vaga::EmTroca => false,
                Vaga::Aberta(d) => !crate::fios::vivo(d.fio),
            })
            .ok_or(Recusa::Ocupado)?;
        let anterior = matches!(donos[indice], Vaga::Aberta(_));
        let geracao = PROXIMA_GERACAO.fetch_add(1, Ordering::Relaxed);
        donos[indice] = Vaga::EmTroca;
        SAIDAS[indice].lock().esvaziar();
        while ENTRADAS[indice].desenfileirar().is_some() {}
        Ok((
            Chave {
                indice: indice as u8,
                geracao,
            },
            anterior,
        ))
    })?;
    if anterior {
        crate::interpretador::fechar_console(chave.console(), "o terminal anterior morreu");
    }
    crate::interpretador::abrir_console(chave.console());
    crate::arch::sem_interrupcoes(|| {
        DONOS.lock()[usize::from(chave.indice)] = Vaga::Aberta(Dono {
            fio,
            geracao: chave.geracao,
            canal,
        });
    });
    PENDENTES[usize::from(chave.indice)].store(true, Ordering::Relaxed);
    Ok(chave)
}

/// A `chave` é a abertura viva da instância, e de `fio`?
fn confere(chave: Chave, fio: u64) -> bool {
    crate::arch::sem_interrupcoes(|| {
        DONOS
            .lock()
            .get(usize::from(chave.indice))
            .is_some_and(|d| {
                d.dono()
                    .is_some_and(|d| d.geracao == chave.geracao && d.fio == fio)
            })
    })
}

/// Lê para `destino` o que o console imprimiu. Zero quando não há nada —
/// não bloqueia. `None` se a chave não é de `fio`.
pub fn ler(chave: Chave, fio: u64, destino: &mut [u8]) -> Option<usize> {
    if !confere(chave, fio) {
        return None;
    }
    Some(crate::arch::sem_interrupcoes(|| {
        SAIDAS[usize::from(chave.indice)].lock().tirar(destino)
    }))
}

/// Digita `texto` no console da instância, caractere por caractere, até a
/// fila de entrada encher. Devolve quantos bytes foram aceitos — uma escrita
/// parcial, como a de um `write` num pipe cheio. `None` se a chave não é de
/// `fio`.
///
/// # O que não é texto é consumido e descartado
///
/// Só passa o que mexe na linha do interpretador: texto, a quebra de linha,
/// o apagar, o apagar da linha inteira e o Enter de um agente — ver
/// `protocolo::usuario::terminal`. As teclas de função e o clique são do
/// console físico; um processo que os escrevesse apertaria botões da barra
/// por um canal que só deveria digitar. O resto conta como aceito, porque
/// recusá-lo deixaria quem escreve repetindo para sempre o mesmo caractere.
pub fn escrever(chave: Chave, fio: u64, texto: &str) -> Option<usize> {
    if !confere(chave, fio) {
        return None;
    }
    let fila = &ENTRADAS[usize::from(chave.indice)];
    let mut aceitos = 0;
    for c in texto.chars() {
        if e_digitavel(c) {
            if fila.enfileirar(c).is_err() {
                break;
            }
            DIGITADOS.fetch_add(1, Ordering::Relaxed);
        }
        aceitos += c.len_utf8();
    }
    if aceitos > 0 {
        crate::teclado::despertar_o_interpretador();
    }
    Some(aceitos)
}

/// Um caractere que o pseudo-terminal deixa chegar ao interpretador.
fn e_digitavel(c: char) -> bool {
    use protocolo::usuario::terminal::{APAGAR_A_LINHA, agente_que_confirmou};
    c.is_ascii_graphic()
        || matches!(c, ' ' | '\n' | '\u{8}' | APAGAR_A_LINHA)
        || agente_que_confirmou(c).is_some()
}

/// O próximo caractere digitado em algum pseudo-terminal, com o console de
/// onde veio. Uma volta pelas instâncias, a partir da seguinte à da última
/// vez: um Terminal que digita muito não deixa os outros esperando.
pub fn proxima_entrada() -> Option<(Console, char)> {
    static VEZ: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    let comeco = VEZ.load(Ordering::Relaxed);
    for passo in 0..TERMINAIS {
        let i = (comeco + passo) % TERMINAIS;
        if let Some(c) = ENTRADAS[i].desenfileirar() {
            VEZ.store(i + 1, Ordering::Relaxed);
            return Some((Console::Terminal(i as u16), c));
        }
    }
    None
}

/// Fecha o pseudo-terminal, se a `chave` for a abertura de `fio`. O console
/// dele fecha junto: a sessão de quem estava nele acaba.
pub fn fechar(chave: Chave, fio: u64) {
    let fechou = crate::arch::sem_interrupcoes(|| {
        let mut donos = DONOS.lock();
        match donos.get_mut(usize::from(chave.indice)) {
            Some(d)
                if d.dono()
                    .is_some_and(|d| d.geracao == chave.geracao && d.fio == fio) =>
            {
                *d = Vaga::EmTroca;
                true
            }
            _ => false,
        }
    });
    if fechou {
        encerrar_e_soltar(usize::from(chave.indice), "o terminal fechou");
    }
}

/// Fecha o console da instância `i`, que quem chama marcou
/// [em troca](Vaga::EmTroca), e só então a solta.
fn encerrar_e_soltar(i: usize, motivo: &str) {
    crate::interpretador::fechar_console(Console::Terminal(i as u16), motivo);
    crate::arch::sem_interrupcoes(|| DONOS.lock()[i] = Vaga::Livre);
}

/// Avisa cada dono, no canal dele, que há saída nova; e fecha o console de
/// um dono que morreu sem fechar. Chamada pelo coletor de fios a cada volta
/// — ver o cabeçalho sobre por que o aviso é adiado.
///
/// Um aviso por volta, e não um por impressão: o dono lê tudo o que houver
/// quando acordar.
pub fn avisar_se_preciso() {
    for (i, pendente) in PENDENTES.iter().enumerate() {
        let dono = crate::arch::sem_interrupcoes(|| DONOS.lock()[i].dono());
        let Some(dono) = dono else {
            continue;
        };
        if !crate::fios::vivo(dono.fio) {
            let largou = crate::arch::sem_interrupcoes(|| {
                let mut donos = DONOS.lock();
                let mesmo = donos[i].dono().is_some_and(|d| d.geracao == dono.geracao);
                if mesmo {
                    donos[i] = Vaga::EmTroca;
                }
                mesmo
            });
            if largou {
                encerrar_e_soltar(i, "o terminal morreu");
            }
            continue;
        }
        if !pendente.swap(false, Ordering::Relaxed) {
            continue;
        }
        let aviso = protocolo::usuario::evento::Evento {
            tipo: protocolo::usuario::evento::tipo::SAIDA,
            ..Default::default()
        };
        if crate::eventos::publicar_em(dono.canal, aviso).is_ok() {
            AVISOS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A passada do coletor de fios: [`avisar_se_preciso`], a menos que a
/// suíte a tenha pausado.
pub fn passada_do_coletor() {
    #[cfg(feature = "modo-teste")]
    {
        // A ordem é a de Dekker, com `SeqCst` nos dois lados: ou o coletor
        // vê a pausa e não passa, ou a suíte o vê passando e espera.
        PASSANDO.store(true, Ordering::SeqCst);
        if COLETOR_PAUSADO.load(Ordering::SeqCst) {
            PASSANDO.store(false, Ordering::SeqCst);
            return;
        }
    }
    avisar_se_preciso();
    #[cfg(feature = "modo-teste")]
    PASSANDO.store(false, Ordering::SeqCst);
}

/// Só na suíte: o coletor de fios deixa os pseudo-terminais em paz.
///
/// Os casos que fecham o console de um dono morto conduzem a passada eles
/// mesmos, chamando [`avisar_se_preciso`]. Com um núcleo só, as interrupções
/// mascaradas do caso bastavam para o coletor não rodar no meio; com vários,
/// ele roda em outro núcleo, e podia fechar o console do dono morto antes de
/// o caso pôr uma pessoa nele — a sessão dela nascia num console fechado,
/// que ninguém mais fecharia.
#[cfg(feature = "modo-teste")]
static COLETOR_PAUSADO: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "modo-teste")]
static PASSANDO: AtomicBool = AtomicBool::new(false);

/// Pausa ou solta a passada do coletor. Pausar espera a passada em curso
/// terminar: quando volta, nenhuma está no meio.
#[cfg(feature = "modo-teste")]
pub fn pausar_o_coletor_de_teste(pausado: bool) {
    COLETOR_PAUSADO.store(pausado, Ordering::SeqCst);
    if pausado {
        while PASSANDO.load(Ordering::SeqCst) {
            crate::fios::ceder();
        }
    }
}

/// `(bytes perdidos, avisos entregues, teclas digitadas)`.
pub fn estatisticas() -> (u64, u64, u64) {
    (
        PERDIDOS.load(Ordering::Relaxed),
        AVISOS.load(Ordering::Relaxed),
        DIGITADOS.load(Ordering::Relaxed),
    )
}

/// Os fios que têm um pseudo-terminal aberto, por instância.
pub fn donos() -> [Option<u64>; TERMINAIS] {
    crate::arch::sem_interrupcoes(|| DONOS.lock().map(|d| d.dono().map(|d| d.fio)))
}

/// Destrava os anéis e os donos à força, para o caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        for anel in &SAIDAS {
            anel.force_unlock();
        }
        DONOS.force_unlock();
        for fila in &ENTRADAS {
            fila.destravar();
        }
    }
}
