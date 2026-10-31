//! O canal do agente por TCP: mais um transporte de sessão — e, nas vagas
//! de cima, o transporte do enlace entre dispositivos.
//!
//! # O que é
//!
//! As mesmas sessões cifradas das portas do `virtio-console` — o aperto IK
//! do Noise, a chave no registro, o gate a cada pedido, a auditoria —, sobre
//! uma conexão TCP que o kernel aceita na porta [`PORTA`]. São as sessões
//! de [`PRIMEIRA_SESSAO`] em diante, uma por vaga: [`VAGAS`] conexões ao
//! mesmo tempo. O canal do agente não sabe por onde os bytes vieram — ver
//! [`crate::agent::sessao`] —, e nada acima daqui mudou para o TCP existir.
//!
//! # O que este módulo é, e o que não é
//!
//! O transporte, e só: o que chegou e o que vai sair de cada vaga, a
//! geração — quantas conexões a vaga já aceitou —, e o par de cada uma. O
//! mesmo contrato do [`crate::virtio::console`] para as portas. Nada aqui
//! decide: aceitar uma conexão não é autenticar — quem chega ainda prova a
//! chave dele no aperto, em [`crate::agent::seguro`] —, e autenticar não é
//! autorizar — cada pedido passa pelo gate, com o papel que o registro dá à
//! chave. Não há política do TCP: a mesma decisão que abre uma sessão numa
//! porta abre aqui.
//!
//! # A vida de uma vaga
//!
//! 1. **Escutando**: um socket do `smoltcp` em `listen` na [`PORTA`] — ver
//!    `super::pilha`, que guarda os sockets e faz a pilha andar. O firewall
//!    deixa entrar só o SYN — a escuta do firewall, ver `super::pilha`.
//! 2. **Aceita**: o socket estabeleceu com um par. A vaga abre, a geração
//!    anda, o par fica guardado — o que chegou e ia sair de uma conexão
//!    nunca passa para a seguinte. Daqui a conexão é um fluxo da tabela do
//!    firewall, e as regras de `net.block` a alcançam.
//! 3. **O aperto tem prazo**: [`PRAZO_DO_APERTO_MS`]. Quem conecta e não
//!    prova a chave não segura a vaga: a conexão cai, e a recusa vai à
//!    auditoria, com o par. No TCP o aperto só termina com a chave
//!    confirmada — o primeiro quadro de dados que abre —, e não com a
//!    resposta: a primeira mensagem do IK pode ser repetida por quem a
//!    capturou, e quem repete não confirma. Ver `agent::seguro`.
//! 4. **Conversa**: o que chega vai à entrada da vaga, de onde a tarefa da
//!    sessão lê; o que a sessão manda vai à saída, que a pilha escoa no
//!    socket.
//! 5. **Fim**: o par fecha ou cai, uma regra do firewall a derruba, ou a
//!    sessão acaba por dentro — uma revogação, um quadro que não abre, um
//!    aperto recusado: a recusa em claro sai, e então o FIN. O fecho tem
//!    prazo também ([`PRAZO_DO_FECHO_MS`]); passado ele, um RST. A sessão é
//!    esquecida, e a vaga volta a escutar.
//!
//! # As vagas do enlace
//!
//! As vagas de [`VAGAS`] + 1 a [`TODAS`] escutam outra porta,
//! [`PORTA_DO_ENLACE`]: a de outro Duke relacionado, que faz o aperto do
//! enlace — ver [`crate::enlace`]. A mesma vida, os mesmos prazos e o mesmo
//! fecho; outras vagas, para o enlace não esgotar as do agente, que são a
//! porta do administrador. Não são sessões do agente: o que chega nelas vai
//! ao respondedor do enlace, e o desfecho de cada conexão também. O firewall
//! só deixa entrar o SYN nela enquanto há uma relação — ver `super::pilha`.
//!
//! # O que fica para fora das travas
//!
//! A pilha anda no fio da rede, que não pode esperar um disco: o fim de uma
//! conexão e o aperto que venceu o prazo deixam um [`Desfecho`] — a sessão
//! a esquecer, a recusa a gravar —, e quem o trata é o coletor, a cada
//! tique, como trata as conexões de quem acabou. O fim de uma conexão leva
//! só a sessão **dela** — pela geração —, e nunca a da conexão seguinte na
//! mesma vaga, que já pode ter feito o aperto.
//!
//! # Contrapressão
//!
//! - **Entrada**: a pilha só tira do socket o que cabe na entrada da vaga
//!   ([`MAIOR_ENTRADA`]). O resto fica no socket, a janela do TCP fecha, e
//!   o agente que manda mais depressa do que a sessão atende espera — nada
//!   se perde. É a diferença para uma porta, cujo dispositivo não espera:
//!   lá o que não cabe é contado como perdido e encerra a sessão.
//! - **Saída**: com mais de [`LIMIAR_DA_SAIDA`] esperando para sair, a
//!   sessão não lê o pedido seguinte até o par ler o que já tem — ver
//!   `agent::atender`. Passando de [`MAIOR_SAIDA`] — um par que não lê —,
//!   a resposta não sai e a sessão acaba, como numa porta.
//!
//! # As travas
//!
//! Uma por vaga. A pilha a toma com a dela na mão — para escoar, ao
//! aceitar, ao fechar —; aqui ela nunca é tomada com a de uma vaga na mão:
//! quem manda ou lê solta a vaga antes de pedir à pilha que ande. A das
//! pendências é tomada sozinha, ou dentro da da pilha.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Waker;

use smoltcp::socket::tcp;

use crate::trava::Mutex;

/// A porta TCP em que o canal do agente escuta.
pub const PORTA: u16 = 7070;

/// Quantas conexões o canal aceita ao mesmo tempo: uma por vaga.
pub const VAGAS: u8 = 4;

/// A porta TCP do enlace entre dispositivos: outra porta, porque o
/// `smoltcp` não escolhe o conjunto de vagas pelo primeiro quadro.
pub const PORTA_DO_ENLACE: u16 = 7071;

/// Quantos enlaces chegam ao mesmo tempo: as vagas depois das do agente.
pub const VAGAS_DO_ENLACE: u8 = 4;

/// Todas as vagas: as do agente, de 1 a [`VAGAS`], e as do enlace, depois.
pub const TODAS: u8 = VAGAS + VAGAS_DO_ENLACE;

/// Se a vaga `v` é do enlace.
pub const fn do_enlace(v: u8) -> bool {
    v > VAGAS && v <= TODAS
}

/// A porta que a vaga `v` escuta.
pub const fn porta(v: u8) -> u16 {
    if do_enlace(v) { PORTA_DO_ENLACE } else { PORTA }
}

/// A sessão da primeira vaga: depois da serial (0) e das portas do
/// `virtio-console` (1 a 4).
pub const PRIMEIRA_SESSAO: u8 = crate::virtio::console::PORTAS + 1;

/// Quanto tempo quem conectou tem para provar a chave. Um aperto completo
/// leva milissegundos — centenas, no kernel de depuração emulado —; quem
/// passa disso está segurando a vaga sem dizer quem é.
pub const PRAZO_DO_APERTO_MS: u64 = 10_000;

/// O que cabe na entrada de uma vaga. Não é o teto de nada que o agente
/// mande: o que não cabe fica no socket, com a janela do TCP fechada, até
/// a sessão ler — ver o cabeçalho.
pub const MAIOR_ENTRADA: usize = 16 * 1024;

/// O que cabe na saída de uma vaga: o mesmo da porta. Passando disso, a
/// resposta não sai, e a sessão acaba — o par não está lendo.
pub const MAIOR_SAIDA: usize = 256 * 1024;

/// Com mais que isto na saída, a sessão não lê o pedido seguinte: a
/// resposta dele ainda cabe, e o agente que não lê espera, em vez de
/// perder a sessão. Um quarto do teto: a saída de quem não lê fica perto
/// disto, e não do teto — o heap do kernel é de todos.
pub const LIMIAR_DA_SAIDA: usize = MAIOR_SAIDA / 4;

/// Quanto o fecho de uma conexão pode levar: a recusa que ainda sai, o
/// FIN e a confirmação dele. Um par que não lê, ou que sumiu, não segura a
/// vaga: passado isto, a conexão cai com um RST, e a vaga volta a escutar.
pub const PRAZO_DO_FECHO_MS: u64 = 5_000;

/// O silêncio que o socket de uma vaga tolera, e de quanto em quanto ele
/// pergunta ao par se ainda está lá — o `keep-alive` do TCP. Um agente
/// conectado e calado continua; um que sumiu sem fechar libera a vaga.
pub const SILENCIO_MAXIMO_MS: u64 = 90_000;
pub const PERGUNTA_AO_SILENCIO_MS: u64 = 30_000;

/// O buffer de cada sentido do socket de uma vaga, no `smoltcp`.
pub const BUFFER_DO_SOCKET: usize = 16 * 1024;

/// Uma vaga do canal.
struct Vaga {
    /// Há uma conexão aceita.
    aberta: bool,
    /// Quantas conexões a vaga já aceitou.
    geracao: u64,
    entrada: VecDeque<u8>,
    saida: VecDeque<u8>,
    /// Bytes de resposta descartados: a conexão tinha acabado, ou o par
    /// não lia.
    perdidos_na_saida: u64,
    /// Ficou dado no socket porque a entrada estava cheia: quem ler da
    /// entrada pede à pilha que ande de novo.
    retido: bool,
    /// A tarefa que espera um byte.
    despertador: Option<Waker>,
    /// A tarefa que espera a saída esvaziar abaixo do limiar.
    despertador_da_saida: Option<Waker>,
    /// O par da conexão aceita: o endereço e a porta de quem chamou.
    remoto: Option<([u8; 4], u16)>,
    /// Quando a conexão foi aceita, para o prazo do aperto.
    aceita_ms: u64,
    /// A chave que provou o aperto nesta conexão — para o firewall saber de
    /// quem é o fluxo. `None` até o aperto completar.
    chave: Option<[u8; 32]>,
    /// A sessão pediu o fecho: a pilha fecha o socket assim que a saída
    /// esvaziar — a recusa em claro sai antes do FIN.
    fechar: bool,
    /// Quando a sessão pediu o fecho: ver [`PRAZO_DO_FECHO_MS`].
    fechar_desde_ms: u64,
    /// Quando a última conexão deixou a vaga: o fecho dela com o par tem o
    /// mesmo prazo.
    fechada_ms: u64,
}

impl Vaga {
    const fn nova() -> Vaga {
        Vaga {
            aberta: false,
            geracao: 0,
            entrada: VecDeque::new(),
            saida: VecDeque::new(),
            perdidos_na_saida: 0,
            retido: false,
            despertador: None,
            despertador_da_saida: None,
            remoto: None,
            aceita_ms: 0,
            chave: None,
            fechar: false,
            fechar_desde_ms: 0,
            fechada_ms: 0,
        }
    }
}

static VAGAS_DO_CANAL: [Mutex<Vaga>; TODAS as usize] =
    [const { Mutex::new(Vaga::nova()) }; TODAS as usize];

/// Quantas conexões o canal aceitou, e quantos apertos venceram o prazo,
/// desde o boot.
static ACEITAS: AtomicU64 = AtomicU64::new(0);
static EXPIRADOS: AtomicU64 = AtomicU64::new(0);

fn com_vaga<R>(v: u8, f: impl FnOnce(&mut Vaga) -> R) -> Option<R> {
    let i = usize::from(v.checked_sub(1)?);
    let vaga = VAGAS_DO_CANAL.get(i)?;
    Some(crate::arch::sem_interrupcoes(|| f(&mut vaga.lock())))
}

/// A sessão da vaga `v`.
pub const fn sessao(v: u8) -> u8 {
    PRIMEIRA_SESSAO + v - 1
}

/// A vaga da sessão `s`, se `s` é uma sessão do canal TCP.
pub fn vaga_da_sessao(s: u8) -> Option<u8> {
    let v = s.checked_sub(PRIMEIRA_SESSAO)? + 1;
    (v <= VAGAS).then_some(v)
}

/// Há uma conexão aceita na vaga `v`?
pub fn aberta(v: u8) -> bool {
    com_vaga(v, |f| f.aberta).unwrap_or(false)
}

/// Quantas conexões a vaga `v` já aceitou.
pub fn geracao(v: u8) -> u64 {
    com_vaga(v, |f| f.geracao).unwrap_or(0)
}

/// A conexão `geracao` ainda é a da vaga `v`, e está aberta?
pub fn na_conexao(v: u8, geracao: u64) -> bool {
    com_vaga(v, |f| f.aberta && f.geracao == geracao).unwrap_or(false)
}

/// O par da conexão da vaga `v`: o endereço e a porta de quem chamou.
pub fn remoto(v: u8) -> Option<([u8; 4], u16)> {
    com_vaga(v, |f| f.remoto.filter(|_| f.aberta)).flatten()
}

/// O par da conexão `geracao` da vaga `v`, se ainda é ela a da vaga — o
/// que a auditoria de um aperto grava: o par de **quem fez** o aperto.
pub fn remoto_da_conexao(v: u8, geracao: u64) -> Option<([u8; 4], u16)> {
    com_vaga(v, |f| f.remoto.filter(|_| f.geracao == geracao)).flatten()
}

/// Bytes de resposta da vaga `v` descartados.
pub fn perdidos_na_saida(v: u8) -> u64 {
    com_vaga(v, |f| f.perdidos_na_saida).unwrap_or(0)
}

/// Quantos bytes esperam na saída da vaga `v` — o que o par ainda não leu
/// e não coube no socket.
pub fn na_saida(v: u8) -> usize {
    com_vaga(v, |f| f.saida.len()).unwrap_or(0)
}

/// Quantas conexões o canal aceitou, e quantos apertos venceram o prazo.
pub fn contadores() -> (u64, u64) {
    (
        ACEITAS.load(Ordering::Relaxed),
        EXPIRADOS.load(Ordering::Relaxed),
    )
}

/// O par escrito como a auditoria e o log o escrevem: `tcp a.b.c.d:porta`.
pub fn texto_do_par(([a, b, c, d], porta): ([u8; 4], u16)) -> alloc::string::String {
    alloc::format!("tcp {a}.{b}.{c}.{d}:{porta}")
}

/// A chave que provou o aperto na conexão `geracao` da vaga `v` — se ela
/// ainda é a da vaga: o firewall a usa para saber de quem é o fluxo, e o
/// prazo do aperto deixa de correr. Quem chama é a sessão cifrada, quando
/// o agente confirma a chave — o primeiro quadro de dados que abre.
pub fn identificar(v: u8, geracao: u64, chave: [u8; 32]) {
    com_vaga(v, |f| {
        if f.aberta && f.geracao == geracao {
            f.chave = Some(chave);
        }
    });
}

/// O próximo byte da vaga `v`, quando houver, com a geração da conexão de
/// onde ele veio — conferida na mesma trava que o tira da entrada: um byte
/// da conexão que acabou nunca passa por um da seguinte.
pub fn proximo_byte(v: u8) -> ProximoByte {
    ProximoByte(v)
}

/// O futuro de [`proximo_byte`].
pub struct ProximoByte(u8);

impl core::future::Future for ProximoByte {
    type Output = (u8, u64);

    fn poll(
        self: core::pin::Pin<&mut Self>,
        contexto: &mut core::task::Context,
    ) -> core::task::Poll<(u8, u64)> {
        let v = self.0;
        // O byte e o registro do despertador sob a mesma trava: um byte que
        // chegasse entre os dois não acordaria ninguém.
        let (byte, andar) = com_vaga(v, |f| match f.entrada.pop_front() {
            Some(b) => (Some((b, f.geracao)), tirar_retido(f)),
            None => {
                if !f
                    .despertador
                    .as_ref()
                    .is_some_and(|w| w.will_wake(contexto.waker()))
                {
                    f.despertador = Some(contexto.waker().clone());
                }
                (None, tirar_retido(f))
            }
        })
        .unwrap_or((None, false));
        // Fora da trava da vaga: a pilha a toma com a dela na mão.
        if andar {
            super::pilha::sondar();
        }
        match byte {
            Some(b) => core::task::Poll::Ready(b),
            None => core::task::Poll::Pending,
        }
    }
}

/// Se ficou dado no socket e a entrada já tem espaço para ele: quem leu
/// pede à pilha que ande. Sem isto, o dado retido só sairia do socket na
/// próxima volta do fio da rede — e com a janela fechada, o par só manda
/// a sonda dela, segundos depois.
fn tirar_retido(f: &mut Vaga) -> bool {
    if f.retido && f.entrada.len() <= MAIOR_ENTRADA / 2 {
        f.retido = false;
        true
    } else {
        false
    }
}

/// Espera a saída da vaga `v` ter espaço — no máximo [`LIMIAR_DA_SAIDA`] —,
/// ou a conexão acabar.
pub fn espaco_na_saida(v: u8) -> EspacoNaSaida {
    EspacoNaSaida(v)
}

/// O futuro de [`espaco_na_saida`].
pub struct EspacoNaSaida(u8);

impl core::future::Future for EspacoNaSaida {
    type Output = ();

    fn poll(
        self: core::pin::Pin<&mut Self>,
        contexto: &mut core::task::Context,
    ) -> core::task::Poll<()> {
        let pronto = com_vaga(self.0, |f| {
            if !f.aberta || f.saida.len() <= LIMIAR_DA_SAIDA {
                return true;
            }
            f.despertador_da_saida = Some(contexto.waker().clone());
            false
        })
        .unwrap_or(true);
        if pronto {
            core::task::Poll::Ready(())
        } else {
            core::task::Poll::Pending
        }
    }
}

/// Manda `bytes` pela vaga `v`. Sem conexão, ou sem espaço na saída, são
/// descartados e contados — tudo ou nada, nunca metade: o canal cifrado
/// depende disso, como numa porta. Devolve se foram aceitos.
pub fn enviar(v: u8, bytes: &[u8]) -> bool {
    enviar_se(v, None, bytes)
}

/// Manda `bytes` pela vaga `v` só se ela ainda está na conexão `geracao`:
/// para o que foi feito para uma conexão, e não serve a outra — a resposta
/// a um aperto, a recusa dele. A conferência é na mesma trava que põe os
/// bytes na saída.
pub fn enviar_na_conexao(v: u8, geracao: u64, bytes: &[u8]) -> bool {
    enviar_se(v, Some(geracao), bytes)
}

/// Põe `bytes` na saída da conexão `geracao` da vaga `v`, sem fazer a pilha
/// andar — quem chama a faz andar depois, com [`super::pilha::sondar`],
/// fora das travas dele. É o que a cerimônia de pareamento usa para cifrar
/// e enfileirar uma mensagem na mesma trava: a ordem em que elas se
/// cifram é a ordem em que saem, venha de onde vier cada uma — ver
/// [`crate::pareamento`].
pub fn enfileirar_na_conexao(v: u8, geracao: u64, bytes: &[u8]) -> bool {
    com_vaga(v, |f| {
        if geracao != f.geracao || !f.aberta || f.fechar {
            return false;
        }
        if f.saida.len() + bytes.len() > MAIOR_SAIDA {
            f.perdidos_na_saida += bytes.len() as u64;
            return false;
        }
        f.saida.extend(bytes.iter().copied());
        true
    })
    .unwrap_or(false)
}

fn enviar_se(v: u8, geracao: Option<u64>, bytes: &[u8]) -> bool {
    let aceito = com_vaga(v, |f| {
        if geracao.is_some_and(|g| g != f.geracao) {
            // Não havia, na conexão de agora, quem esperasse isto: não é
            // perda.
            return false;
        }
        if !f.aberta || f.fechar || f.saida.len() + bytes.len() > MAIOR_SAIDA {
            f.perdidos_na_saida += bytes.len() as u64;
            return false;
        }
        f.saida.extend(bytes.iter().copied());
        true
    })
    .unwrap_or(false);
    // A pilha escoa já, e não no próximo tique: uma resposta pequena sai
    // na hora.
    if aceito {
        super::pilha::sondar();
    }
    aceito
}

/// A sessão da vaga `v` acabou por dentro — uma recusa, uma revogação, um
/// quadro que não abriu: a conexão `geracao` fecha depois de a saída
/// esvaziar, para a recusa em claro chegar ao agente antes do FIN, e nada
/// mais entra na saída dela. Uma conexão que já não é a de agora não é
/// tocada.
pub fn encerrar(v: u8, geracao: u64) {
    let agora = crate::tempo::uptime_ms();
    let pediu = com_vaga(v, |f| {
        if f.aberta && f.geracao == geracao && !f.fechar {
            f.fechar = true;
            f.fechar_desde_ms = agora;
            true
        } else {
            false
        }
    })
    .unwrap_or(false);
    if pediu {
        super::pilha::sondar();
    }
}

/// O que uma volta da pilha fez com uma vaga e precisa ser tratado fora
/// das travas — ver o cabeçalho.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Desfecho {
    /// A vaga aceitou a conexão `geracao`, de `remoto`.
    Aceita {
        remoto: ([u8; 4], u16),
        geracao: u64,
    },
    /// A conexão `geracao` acabou: a sessão **dela**, se fez o aperto, tem
    /// de ser esquecida.
    Acabou { geracao: u64 },
    /// O aperto da conexão `geracao` não veio no prazo: ela caiu, e a
    /// recusa é gravada.
    Expirou {
        remoto: ([u8; 4], u16),
        geracao: u64,
    },
}

/// Uma volta da vaga `v` sobre o socket dela: aceita, escoa nos dois
/// sentidos, confere os prazos, fecha o que acabou e volta a escutar. Quem
/// chama é a pilha, com a trava dela na mão — ver o cabeçalho.
pub(super) fn bombear(v: u8, s: &mut tcp::Socket, agora_ms: u64) -> Option<Desfecho> {
    use tcp::State;
    let mut acordar = None;
    let mut acordar_saida = None;
    let desfecho = com_vaga(v, |f| {
        let estado = s.state();
        let mut desfecho = None;
        if !f.aberta {
            match estado {
                // Uma conexão nova: aceita, com o par dela. O que estava na
                // vaga era da conexão de antes.
                State::Established | State::CloseWait => {
                    let remoto = s.remote_endpoint().map(|e| {
                        let smoltcp::wire::IpAddress::Ipv4(ip) = e.addr;
                        (ip.octets(), e.port)
                    });
                    f.aberta = true;
                    f.geracao += 1;
                    f.entrada.clear();
                    f.saida.clear();
                    f.retido = false;
                    f.fechar = false;
                    f.chave = None;
                    f.remoto = remoto;
                    f.aceita_ms = agora_ms;
                    ACEITAS.fetch_add(1, Ordering::Relaxed);
                    desfecho = remoto.map(|remoto| Desfecho::Aceita {
                        remoto,
                        geracao: f.geracao,
                    });
                }
                // O fecho da conexão de antes, que o par não termina — não
                // confirma o FIN, ou não lê o que falta: um RST.
                State::FinWait1 | State::FinWait2 | State::Closing | State::LastAck => {
                    if agora_ms.saturating_sub(f.fechada_ms) > PRAZO_DO_FECHO_MS {
                        s.abort();
                    }
                    return None;
                }
                // O fecho terminou: a vaga volta a escutar. O `TIME_WAIT`
                // não é esperado — ver `Pilha::fechando`, sobre as
                // conexões de saída: o par de uma conexão nova escolhe
                // outra porta dele. Fechada depois de um RST, só quando ele
                // já saiu: até sair, o socket ainda tem o par.
                State::TimeWait => {
                    let _ = s.listen(porta(v));
                    return None;
                }
                State::Closed if s.remote_endpoint().is_none() => {
                    let _ = s.listen(porta(v));
                    return None;
                }
                _ => return None,
            }
        }
        // O que chegou, até onde cabe; o resto espera no socket.
        let mut chegou = false;
        while f.entrada.len() < MAIOR_ENTRADA && s.can_recv() {
            let livre = MAIOR_ENTRADA - f.entrada.len();
            let tirados = s
                .recv(|buf| {
                    let n = buf.len().min(livre);
                    f.entrada.extend(buf[..n].iter().copied());
                    (n, n)
                })
                .unwrap_or(0);
            if tirados == 0 {
                break;
            }
            chegou = true;
        }
        f.retido = s.can_recv();
        if chegou {
            acordar = f.despertador.take();
        }
        // O que vai sair, até onde o socket aceita.
        while !f.saida.is_empty() && s.can_send() {
            let (frente, _) = f.saida.as_slices();
            let postos = s.send_slice(frente).unwrap_or(0);
            if postos == 0 {
                break;
            }
            f.saida.drain(..postos);
        }
        if f.saida.len() <= LIMIAR_DA_SAIDA {
            acordar_saida = f.despertador_da_saida.take();
        }
        let geracao = f.geracao;
        // O fecho que a sessão pediu, com a saída já no socket: o FIN sai
        // depois do que estava nele. Um par que não lê não o segura: no
        // prazo, um RST. Uma conexão que já caiu não tem por que esperar.
        if f.fechar {
            let viva = matches!(estado, State::Established | State::CloseWait);
            if viva && f.saida.is_empty() {
                s.close();
            } else if !viva || agora_ms.saturating_sub(f.fechar_desde_ms) > PRAZO_DO_FECHO_MS {
                s.abort();
            } else {
                return desfecho;
            }
            fechar_vaga(f, agora_ms, &mut acordar, &mut acordar_saida);
            return Some(Desfecho::Acabou { geracao });
        }
        // O aperto que não veio no prazo: quem conectou não disse quem é.
        if f.chave.is_none() && agora_ms.saturating_sub(f.aceita_ms) > PRAZO_DO_APERTO_MS {
            s.abort();
            EXPIRADOS.fetch_add(1, Ordering::Relaxed);
            let remoto = f.remoto.unwrap_or(([0; 4], 0));
            fechar_vaga(f, agora_ms, &mut acordar, &mut acordar_saida);
            return Some(Desfecho::Expirou { remoto, geracao });
        }
        // O par fechou o sentido dele, ou a conexão caiu: a sessão acaba, e
        // o lado de cá fecha também — o que ainda ia sair não tem quem leia.
        if estado != State::Established {
            if estado == State::CloseWait {
                s.close();
            }
            fechar_vaga(f, agora_ms, &mut acordar, &mut acordar_saida);
            return Some(Desfecho::Acabou { geracao });
        }
        desfecho
    })
    .flatten();
    // Os despertadores fora da trava da vaga.
    if let Some(w) = acordar {
        w.wake();
    }
    if let Some(w) = acordar_saida {
        w.wake();
    }
    desfecho
}

/// A vaga deixa de ter conexão: o que chegou e não foi lido era de quem
/// saiu, o que ia sair não tem quem leia, e quem espera é acordado para ver
/// que acabou.
fn fechar_vaga(
    f: &mut Vaga,
    agora_ms: u64,
    acordar: &mut Option<Waker>,
    acordar_saida: &mut Option<Waker>,
) {
    f.aberta = false;
    f.fechar = false;
    f.chave = None;
    f.fechada_ms = agora_ms;
    f.entrada.clear();
    f.perdidos_na_saida += f.saida.len() as u64;
    f.saida.clear();
    f.retido = false;
    if let Some(w) = f.despertador.take() {
        *acordar = Some(w);
    }
    if let Some(w) = f.despertador_da_saida.take() {
        *acordar_saida = Some(w);
    }
}

/// A conexão da vaga `v` foi derrubada por fora — uma regra do firewall
/// que a alcança: a sessão acaba como se o par tivesse caído. Devolve a
/// geração da conexão que caiu, se havia uma.
pub(super) fn derrubada(v: u8) -> Option<u64> {
    let agora = crate::tempo::uptime_ms();
    let mut acordar = None;
    let mut acordar_saida = None;
    let caiu = com_vaga(v, |f| {
        if !f.aberta {
            return None;
        }
        let g = f.geracao;
        fechar_vaga(f, agora, &mut acordar, &mut acordar_saida);
        Some(g)
    })
    .flatten();
    if let Some(w) = acordar {
        w.wake();
    }
    if let Some(w) = acordar_saida {
        w.wake();
    }
    caiu
}

/// De quem é o fluxo da vaga `v`, para as regras do firewall: o agente que
/// provou a chave nesta conexão, ou ninguém ainda.
pub(super) fn chave_da_vaga(v: u8) -> Option<[u8; 32]> {
    com_vaga(v, |f| f.chave.filter(|_| f.aberta)).flatten()
}

/// O que as voltas da pilha deixaram para ser feito fora das travas — ver
/// o cabeçalho.
static PENDENCIAS: Mutex<Vec<(u8, Desfecho)>> = Mutex::new(Vec::new());

/// Guarda o desfecho de uma vaga, para depois — ver [`PENDENCIAS`].
pub(super) fn deixar(v: u8, d: Desfecho) {
    crate::arch::sem_interrupcoes(|| PENDENCIAS.lock().push((v, d)));
}

/// Trata o que as voltas da pilha deixaram, fora de qualquer trava: quem
/// chama é o coletor, a cada tique — ver o cabeçalho.
pub fn atender_pendencias() {
    loop {
        // A pendência só sai da lista depois de tratada: quem espera a lista
        // vazia — a vaga livre de novo — espera a sessão esquecida e a
        // recusa gravada, e não só a pendência tirada. Só o coletor tira, e
        // quem deixa põe no fim: a primeira continua sendo esta.
        let proxima = crate::arch::sem_interrupcoes(|| PENDENCIAS.lock().first().copied());
        let Some((v, d)) = proxima else {
            return;
        };
        tratar(v, d);
        crate::arch::sem_interrupcoes(|| {
            let mut p = PENDENCIAS.lock();
            if p.first() == Some(&(v, d)) {
                p.remove(0);
            }
        });
    }
}

/// Trata um desfecho da vaga `v` — ver [`atender_pendencias`]. O de uma
/// vaga do enlace é do enlace.
fn tratar(v: u8, d: Desfecho) {
    if do_enlace(v) {
        return crate::enlace::desfecho_da_vaga(v, d);
    }
    let s = sessao(v);
    match d {
        Desfecho::Aceita { remoto, geracao } => {
            crate::log_info!(
                "agent",
                "sessao {}: conexao {} de {}",
                s,
                geracao,
                texto_do_par(remoto)
            );
        }
        Desfecho::Acabou { geracao } => match crate::sessoes::esquecer_da_conexao(s, geracao) {
            Some(saiu) if saiu.confirmada => {
                crate::log_info!("agent", "sessao {}: {} saiu (tcp)", s, saiu.nome);
            }
            // A conexão acabou com o aperto respondido e a chave por
            // confirmar: um aperto que não terminou.
            Some(saiu) => {
                crate::agent::seguro::gravar_sem_confirmacao(s, &saiu, "a conexao acabou")
            }
            None => {}
        },
        // O aperto que respondeu e não foi confirmado — ver `agent::seguro`,
        // a confirmação — deixou uma sessão: ela é esquecida, e a recusa diz
        // o que faltou. Sem sessão, o aperto nem veio.
        Desfecho::Expirou { remoto, geracao } => {
            match crate::sessoes::esquecer_da_conexao(s, geracao) {
                // A confirmação chegou junto com o prazo, que a derrubou.
                Some(saiu) if saiu.confirmada => {
                    crate::log_info!("agent", "sessao {}: {} saiu (tcp)", s, saiu.nome);
                }
                Some(saiu) => {
                    let motivo =
                        alloc::format!("o prazo de {} s venceu", PRAZO_DO_APERTO_MS / 1000);
                    crate::agent::seguro::gravar_sem_confirmacao(s, &saiu, &motivo);
                }
                None => {
                    crate::sessoes::contar_recusa();
                    let detalhe = alloc::format!(
                        "o aperto nao veio em {} s ({}, conexao {})",
                        PRAZO_DO_APERTO_MS / 1000,
                        texto_do_par(remoto),
                        geracao
                    );
                    crate::log_warn!("agent", "sessao {}: {}", s, detalhe);
                    recusar_conexao(s, &detalhe);
                }
            }
        }
    }
}

/// Grava a recusa de uma conexão do canal que não fez o aperto — o prazo
/// venceu, ou o que ela mandou não era um aperto. A mesma janela dos
/// apertos da sessão conta a tentativa: uma enxurrada de conexões grava a
/// primeira recusa a mais, e não uma por conexão — ver
/// [`crate::autorizacao::permitir_aperto`].
pub fn recusar_conexao(s: u8, detalhe: &str) {
    if crate::autorizacao::permitir_aperto(s) {
        crate::autorizacao::auditar_aperto(
            s,
            None,
            "",
            politica::Codigo::DenyNotAuthenticated,
            detalhe,
        );
    }
}

/// Só para a suíte: de quem é a conexão da vaga `v` para o firewall — ver
/// [`identificar`].
#[cfg(feature = "modo-teste")]
pub fn chave_de_teste(v: u8) -> Option<[u8; 32]> {
    chave_da_vaga(v)
}

/// Só para a suíte: quantos bytes esperam na saída e na entrada da vaga
/// `v`.
#[cfg(feature = "modo-teste")]
pub fn filas_de_teste(v: u8) -> (usize, usize) {
    com_vaga(v, |f| (f.saida.len(), f.entrada.len())).unwrap_or((0, 0))
}

/// Só para a suíte: quantos desfechos o coletor ainda não terminou de
/// tratar — ver [`atender_pendencias`].
#[cfg(feature = "modo-teste")]
pub fn pendencias_de_teste() -> usize {
    crate::arch::sem_interrupcoes(|| PENDENCIAS.lock().len())
}

/// Destrava as vagas, para o caminho de falha fatal.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        for v in &VAGAS_DO_CANAL {
            v.force_unlock();
        }
        PENDENCIAS.force_unlock();
    }
}
