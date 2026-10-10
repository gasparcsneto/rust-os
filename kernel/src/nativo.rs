//! A interface nativa: o registro de comandos como API dos programas.
//!
//! # O que isto é
//!
//! Um programa do Duke pede ao sistema o que um agente pede pelo canal e uma
//! pessoa pelo interpretador: um comando do registro, com os mesmos
//! parâmetros, decidido pelo mesmo gate — `autorizacao::autorizar`, com
//! [`Chamador::Processo`] —, com a autoridade do processo, que é a de quem o
//! lançou, e gravado na mesma auditoria. A resposta é o mesmo envelope
//! JSON-RPC, com o mesmo código de recusa. O desenho está em
//! `docs/INTERFACE.md`.
//!
//! # Por que o comando não roda na chamada de sistema
//!
//! Porque uma chamada de sistema roda com as interrupções mascaradas — e, no
//! ARM, na pilha de exceção do núcleo, onde o fio não pode nem estacionar no
//! meio. Um handler do registro pode ir ao disco, esperar a ordem das
//! gravações do journal, falar com o TPM: esperar mascarado, com a vez de
//! outro fio do mesmo núcleo, é a receita de um núcleo parado.
//!
//! Então `pedir` faz o que `esperar` faz: deixa o pedido no próprio fio,
//! põe o fio a esperar e volta. O comando roda no executor — onde os
//! comandos dos agentes e das pessoas sempre rodaram, um de cada vez, com as
//! interrupções ligadas —, e a resposta volta ao fio, que acorda e reexecuta
//! `pedir`: desta vez ela encontra a resposta pronta e devolve o tamanho.
//! Os handlers continuam rodando no lugar para o qual foram escritos; nada
//! deles precisou saber que um processo existe.
//!
//! # A resposta pendente
//!
//! O comando já teve efeito quando a resposta fica pronta — um
//! `message.send` mandou, um `message.read` entregou —, e ela pode não caber
//! no buffer do programa. Descartá-la seria perder de vista o efeito. Ela
//! fica no fio até `resposta` a buscar; o pedido seguinte descarta a que não
//! foi buscada.
//!
//! # O pedido suspenso
//!
//! Um comando que espera — o `net.recv` com `wait` — não prende o executor:
//! suspende, e o pedido fica aqui, em [`SUSPENSOS`], com a espera que ele
//! armou, enquanto a tarefa atende os outros processos. O fio segue
//! esperando a resposta, como em qualquer pedido. A pilha acorda a tarefa
//! no evento da conexão, o relógio no prazo, e o pedido é executado de
//! novo, inteiro, pelo gate — com a autoridade e o programa do fio de
//! agora —, e a resposta vai ao fio. Ver [`crate::rede::espera`].

use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Waker;

use politica::sigiloso::Texto;

use crate::agent::json::JsonWriter;
use crate::agent::protocol::{self, Requisicao, RpcError};
use crate::agent::registry;
use crate::autorizacao::{self, Chamador};
use crate::tarefas::fila::Fila;
use crate::trava::Mutex;
use protocolo::usuario::erro;
use protocolo::usuario::nativo::MAIOR_PEDIDO;

// O teto do pedido é o da linha do canal: o vocabulário é um só.
const _: () = assert!(MAIOR_PEDIDO == crate::agent::LINHA_MAX);

/// Os fios com pedido esperando o executor, na ordem em que pediram. Cabe
/// um por fio — um fio tem um pedido de cada vez —, com folga para os que
/// morreram com o pedido na fila.
static FILA: Fila<u64, { 2 * crate::fios::MAX_FIOS }> = Fila::nova();

/// Quem acordar quando um pedido chega: a tarefa do executor.
static DESPERTADOR: Mutex<Option<Waker>> = Mutex::new(None);

/// Um pedido de processo que suspendeu: o fio que espera a resposta, o
/// texto do pedido — executado de novo quando a espera acabar — e a espera.
struct Suspenso {
    fio: u64,
    pedido: Texto,
    espera: crate::rede::espera::Espera,
}

/// Os pedidos suspensos dos processos. No máximo um por fio — um fio tem um
/// pedido de cada vez —, e um por conexão: a espera armada é única nela.
static SUSPENSOS: Mutex<alloc::vec::Vec<Suspenso>> = Mutex::new(alloc::vec::Vec::new());

/// Quantos pedidos de processo foram atendidos, e quantos recusados antes de
/// chegar a um comando — JSON quebrado, método desconhecido, parâmetro errado.
static ATENDIDOS: AtomicU64 = AtomicU64::new(0);
static INVALIDOS: AtomicU64 = AtomicU64::new(0);

/// O separador entre o pedido e o anexo, no texto que espera na fila: um
/// byte que uma linha JSON nunca tem — um controle cru não é JSON.
const SEPARADOR_DO_ANEXO: u8 = 0;

// O teto do anexo é o do gate: o vocabulário é um só.
const _: () = assert!(protocolo::usuario::nativo::MAIOR_ANEXO == crate::autorizacao::MAIOR_ANEXO);

/// `pedir(ptr, tamanho)` — ver `protocolo::usuario::numero::PEDIR`.
pub fn pedir(ponteiro: u64, tamanho: u64) -> i64 {
    pedir_com(ponteiro, tamanho, None)
}

/// `pedir_com_anexo(ptr, tamanho, anexo)` — ver
/// `protocolo::usuario::numero::PEDIR_COM_ANEXO`.
pub fn pedir_com_anexo(ponteiro: u64, tamanho: u64, descritor: u64) -> i64 {
    pedir_com(ponteiro, tamanho, Some(descritor))
}

fn pedir_com(ponteiro: u64, tamanho: u64, anexo: Option<u64>) -> i64 {
    use crate::fios::Retomada;
    match crate::fios::retomar_pedido() {
        Retomada::Pronto(n) => return n as i64,
        // Acordado sem resposta — um evento de outro canal, por exemplo —:
        // volta a esperar, e o valor não chega ao processo.
        Retomada::Esperando => return 0,
        Retomada::Novo => {}
    }
    if tamanho == 0 || tamanho as usize > MAIOR_PEDIDO {
        return erro::TAMANHO_INVALIDO;
    }
    if let Err(e) = crate::usuario::validar_faixa(ponteiro, tamanho) {
        return e;
    }
    let mut texto = Texto::novo();
    // SAFETY: `validar_faixa` confirmou que a faixa está no espaço do usuário
    // e mapeada, e ainda estamos no espaço de endereços em que ela vale.
    let linha = unsafe { core::slice::from_raw_parts(ponteiro as *const u8, tamanho as usize) };
    if linha.contains(&SEPARADOR_DO_ANEXO) {
        return erro::TAMANHO_INVALIDO;
    }
    texto.acrescentar(linha);
    // O anexo: o descritor dele — endereço e tamanho —, e os bytes, copiados
    // agora, no espaço do processo: o comando roda no executor, que não o
    // vê.
    if let Some(descritor) = anexo {
        if let Err(e) = crate::usuario::validar_faixa(descritor, 16) {
            return e;
        }
        // SAFETY: os 16 bytes estão no espaço do usuário, mapeados; lidos
        // sem alinhamento suposto.
        let (onde, quantos) = unsafe {
            let p = descritor as *const [u8; 8];
            (
                u64::from_le_bytes(core::ptr::read_unaligned(p)),
                u64::from_le_bytes(core::ptr::read_unaligned(p.add(1))),
            )
        };
        let teto = protocolo::usuario::nativo::MAIOR_ANEXO as u64;
        if quantos > teto {
            return erro::TAMANHO_INVALIDO;
        }
        if quantos > 0 {
            // O teto do anexo, e não o de uma transferência comum: o anexo
            // vai até `MAIOR_ANEXO`, como a interface promete.
            if let Err(e) = crate::usuario::validar_faixa_ate(onde, quantos, teto) {
                return e;
            }
            texto.acrescentar(&[SEPARADOR_DO_ANEXO]);
            // SAFETY: idem, para a faixa do anexo.
            texto.acrescentar(unsafe {
                core::slice::from_raw_parts(onde as *const u8, quantos as usize)
            });
        }
    }
    let id = crate::fios::id_atual();
    // O estado vai para o fio antes de o fio ir para a fila: o executor pode
    // tomar o pedido no instante seguinte, em outro núcleo.
    let anterior = crate::fios::enfileirar_pedido(texto);
    drop(anterior);
    if FILA.enfileirar(id).is_err() {
        // Não acontece — há uma vaga por fio, e folga. Se acontecesse, o
        // fio não pode ficar esperando um pedido que ninguém vai ver.
        drop(crate::fios::desfazer_pedido());
        return erro::OCUPADO;
    }
    acordar_o_executor();
    0
}

/// `resposta(ptr, capacidade)` — ver `protocolo::usuario::numero::RESPOSTA`.
pub fn resposta(ponteiro: u64, capacidade: u64) -> i64 {
    let Some(texto) = crate::fios::tirar_resposta() else {
        return erro::NAO_ENCONTRADO;
    };
    let n = texto.len();
    if (capacidade as usize) < n {
        crate::fios::devolver_resposta(texto);
        return n as i64;
    }
    // O teto é o tamanho da própria resposta: quem a montou foi o kernel, e
    // não o processo. Com o de uma transferência comum, 4 KiB, nenhuma
    // resposta maior chegava ao programa — ver `usuario::validar_faixa_ate`.
    if let Err(e) = crate::usuario::validar_escrita_ate(ponteiro, n as u64, n as u64) {
        crate::fios::devolver_resposta(texto);
        return e;
    }
    // SAFETY: `validar_escrita_ate` confirmou os `n` bytes no espaço do
    // usuário, mapeados e graváveis. Fora de qualquer trava: escrever na
    // memória do processo pode passar pelo tratador de uma página de cópia
    // na escrita.
    unsafe {
        core::ptr::copy_nonoverlapping(texto.como_bytes().as_ptr(), ponteiro as *mut u8, n);
    }
    n as i64
}

fn acordar_o_executor() {
    let waker = crate::arch::sem_interrupcoes(|| DESPERTADOR.lock().take());
    if let Some(w) = waker {
        w.wake();
    }
}

/// Atende os pedidos que estão na fila, um de cada vez, e devolve quantos.
///
/// O executor chama quando é acordado; a suíte, que roda no lugar do
/// executor, chama enquanto espera um processo.
pub fn atender_pendentes() -> usize {
    let mut atendidos = 0;
    while let Some(id) = FILA.desenfileirar() {
        // O fio morreu com o pedido na fila, ou já foi atendido: nada a fazer.
        let Some((pedido, autoridade, programa)) = crate::fios::tomar_pedido(id) else {
            continue;
        };
        let chamador = Chamador::Processo {
            fio: id,
            autoridade,
            programa,
        };
        match responder_como(chamador, pedido.como_bytes(), true) {
            Ok(resposta) => {
                drop(pedido);
                entregar(id, resposta);
            }
            // Suspenso: o fio segue esperando, e o pedido fica para depois.
            Err(espera) => crate::arch::sem_interrupcoes(|| {
                SUSPENSOS.lock().push(Suspenso {
                    fio: id,
                    pedido,
                    espera,
                })
            }),
        }
        atendidos += 1;
    }
    atendidos + retomar_suspensos()
}

/// A resposta de um pedido vai ao fio `id`.
fn entregar(id: u64, resposta: Texto) {
    // O fio morreu enquanto o comando executava: a resposta se apaga, e
    // a janela de nonces que o comando possa ter aberto também — o
    // coletor pode tê-la esquecido antes de o comando terminar.
    if let Some(sobra) = crate::fios::responder_pedido(id, resposta) {
        drop(sobra);
        crate::mensagens::canal_acabou(politica::mensagens::Canal::Processo(id));
    }
    ATENDIDOS.fetch_add(1, Ordering::Relaxed);
}

/// Executa de novo os pedidos suspensos cuja espera acabou, e entrega cada
/// resposta ao fio que espera por ela. Devolve quantos.
///
/// A conferência não registra waker nenhum: quem espera é a tarefa, em
/// [`ProximoPedido`], e um waker daqui apagaria o dela no socket.
fn retomar_suspensos() -> usize {
    let prontos: alloc::vec::Vec<(Suspenso, crate::rede::espera::Desfecho)> =
        crate::arch::sem_interrupcoes(|| {
            let mut lista = SUSPENSOS.lock();
            let mut prontos = alloc::vec::Vec::new();
            let mut i = 0;
            while i < lista.len() {
                match lista[i].espera.conferir(None) {
                    Some(d) => prontos.push((lista.remove(i), d)),
                    None => i += 1,
                }
            }
            prontos
        });
    let mut retomados = 0;
    for (suspenso, desfecho) in prontos {
        let Suspenso {
            fio,
            pedido,
            espera,
        } = suspenso;
        // Desarmada antes da reexecução, fora da trava da lista.
        drop(espera);
        // O fio ainda espera por este pedido? Com a autoridade e o programa
        // que ele tem agora. Morto, não há a quem responder, e o pedido
        // não é executado em nome de ninguém.
        let Some((autoridade, programa)) = crate::fios::pedido_em_curso(fio) else {
            crate::log_debug!(
                "nativo",
                "o fio {} acabou com o pedido suspenso ({:?})",
                fio,
                desfecho
            );
            continue;
        };
        let chamador = Chamador::Processo {
            fio,
            autoridade,
            programa,
        };
        // A espera acabou: a reexecução responde com o que houver, e não
        // suspende de novo.
        if let Ok(resposta) = responder_como(chamador, pedido.como_bytes(), false) {
            drop(pedido);
            entregar(fio, resposta);
            retomados += 1;
        }
    }
    retomados
}

/// Decodifica um pedido, decide e executa o comando como `chamador`, e
/// monta a resposta — os mesmos passos do canal, na mesma ordem. `Err` com
/// a espera, se o comando suspendeu — só com `permitir`: então o envelope
/// começado se apaga, e o pedido é executado de novo quando ela acabar.
fn responder_como(
    chamador: Chamador,
    pedido: &[u8],
    permitir: bool,
) -> Result<Texto, crate::rede::espera::Espera> {
    // O pedido e o anexo, se veio um.
    let (linha, anexo) = match pedido.iter().position(|&b| b == SEPARADOR_DO_ANEXO) {
        Some(i) => (&pedido[..i], pedido[i + 1..].to_vec()),
        None => (pedido, alloc::vec::Vec::new()),
    };
    let linha = crate::agent::limpar_quadro(linha);
    let mut texto = Texto::novo();
    let mut espera = None;
    {
        let mut w = JsonWriter::new(&mut texto);
        let _ = responder(chamador, linha, anexo, permitir, &mut espera, &mut w);
    }
    match espera {
        Some(e) => Err(e),
        None => Ok(texto),
    }
}

fn responder(
    chamador: Chamador,
    linha: &[u8],
    mut anexo: alloc::vec::Vec<u8>,
    permitir: bool,
    espera: &mut Option<crate::rede::espera::Espera>,
    w: &mut JsonWriter,
) -> core::fmt::Result {
    let requisicao = match Requisicao::parse(linha) {
        Ok(r) => r,
        Err((id, erro)) => {
            INVALIDOS.fetch_add(1, Ordering::Relaxed);
            autorizacao::auditar_invalido(chamador, "", linha, erro.mensagem);
            return protocol::envelope_erro(w, id, erro, None);
        }
    };
    let Some(comando) = registry::encontrar(requisicao.metodo) else {
        INVALIDOS.fetch_add(1, Ordering::Relaxed);
        autorizacao::auditar_invalido(
            chamador,
            requisicao.metodo,
            requisicao.params.0,
            "metodo nao encontrado",
        );
        return protocol::envelope_erro(w, requisicao.id, RpcError::METODO_NAO_ENCONTRADO, None);
    };
    if let Err(campo) = registry::validar(comando, requisicao.params) {
        INVALIDOS.fetch_add(1, Ordering::Relaxed);
        autorizacao::auditar_invalido(chamador, comando.nome, requisicao.params.0, campo);
        return protocol::envelope_erro(w, requisicao.id, RpcError::PARAMS_INVALIDOS, Some(campo));
    }
    let licenca = match autorizacao::autorizar(chamador, comando, requisicao.params) {
        Ok(l) => l,
        Err(recusa) => return protocol::envelope_recusa(w, requisicao.id, &recusa),
    };
    let r = protocol::envelope_ok(w, requisicao.id, |w| {
        let (r, e) = licenca.executar_suspensivel(
            requisicao.params,
            core::mem::take(&mut anexo),
            permitir,
            w,
        );
        *espera = e;
        r
    });
    // Um anexo que o pedido não chegou a usar — recusado antes — sai zerado.
    politica::sigiloso::zerar_bloco(&mut anexo);
    r
}

/// A tarefa do executor que atende os pedidos dos processos. Na suíte não
/// há executor: quem espera um processo atende — ver [`atender_pendentes`].
#[cfg(not(feature = "modo-teste"))]
pub async fn servir() {
    loop {
        ProximoPedido { relogio: None }.await;
        atender_pendentes();
    }
}

/// Fica pronto quando há pedido na fila, ou quando a espera de um pedido
/// suspenso acabou: a pilha acorda a tarefa no evento da conexão, e o
/// relógio no prazo mais próximo. Na suíte, que não tem a tarefa, um caso
/// o consulta com o waker dele — ver `consultar_de_teste`, que só existe
/// no `modo-teste`.
struct ProximoPedido {
    relogio: Option<crate::tarefas::relogio::Dormir>,
}

impl core::future::Future for ProximoPedido {
    type Output = ();

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> core::task::Poll<()> {
        use core::task::Poll;
        let este = self.get_mut();
        if !FILA.vazia() {
            return Poll::Ready(());
        }
        let waker = cx.waker().clone();
        crate::arch::sem_interrupcoes(|| *DESPERTADOR.lock() = Some(waker));
        // De novo, com o despertador no lugar: um pedido que chegou entre a
        // primeira olhada e o registro não pode ficar esperando o próximo.
        if !FILA.vazia() {
            return Poll::Ready(());
        }
        // Os suspensos: cada conferência deixa o waker desta tarefa no
        // socket da conexão, e o prazo mais próximo fica com o relógio.
        let (acabou, prazo) = crate::arch::sem_interrupcoes(|| {
            let lista = SUSPENSOS.lock();
            let acabou = lista
                .iter()
                .any(|s| s.espera.conferir(Some(cx.waker())).is_some());
            (acabou, lista.iter().map(|s| s.espera.prazo()).min())
        });
        if acabou {
            return Poll::Ready(());
        }
        match prazo {
            Some(prazo) => {
                let relogio = este
                    .relogio
                    .get_or_insert_with(|| crate::tarefas::relogio::ate_o_tique(prazo));
                if relogio.alvo() != prazo {
                    *relogio = crate::tarefas::relogio::ate_o_tique(prazo);
                }
                match core::pin::Pin::new(relogio).poll(cx) {
                    Poll::Ready(()) => Poll::Ready(()),
                    Poll::Pending => Poll::Pending,
                }
            }
            None => {
                este.relogio = None;
                Poll::Pending
            }
        }
    }
}

/// Atende `linha` como `chamador`, pelos mesmos passos de um pedido de
/// processo — a validação, o gate, o envelope, a auditoria —, sem
/// suspensão, e devolve o envelope.
///
/// É por aqui que o tecido de segurança pede: como um processo, com a
/// autoridade dele, e sem nenhum passo a menos — ver `crate::seguranca`. O
/// `xtask` confere que ninguém mais chama.
pub fn responder_pelo_kernel(chamador: Chamador, linha: &[u8]) -> Texto {
    // Sem suspensão, o comando responde: não há espera a largar.
    responder_como(chamador, linha, false).unwrap_or_default()
}

/// `(atendidos, inválidos)` — para `system.info`.
pub fn estatisticas() -> (u64, u64) {
    (
        ATENDIDOS.load(Ordering::Relaxed),
        INVALIDOS.load(Ordering::Relaxed),
    )
}

/// Destrava a fila e o despertador, para o caminho de falha fatal.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        FILA.destravar();
        DESPERTADOR.force_unlock();
        SUSPENSOS.force_unlock();
    }
}

/// Atende `linha` como `chamador`, pelos mesmos passos de um pedido de
/// processo, e devolve o envelope: para a suíte comparar a decisão de um
/// processo com a de quem o lançou, pela mesma função.
#[cfg(feature = "modo-teste")]
pub fn responder_de_teste(chamador: Chamador, linha: &str) -> alloc::string::String {
    // Sem suspensão: um `wait` responde na hora, como no modo post-mortem.
    let texto = responder_como(chamador, linha.as_bytes(), false).unwrap_or_default();
    alloc::string::String::from_utf8_lossy(texto.como_bytes()).into_owned()
}

/// Só para a suíte: [`responder_de_teste`], com o comando podendo
/// suspender, como na primeira execução de um pedido. `Err` com a espera:
/// a suíte confere o desfecho e executa de novo pelo
/// [`responder_de_teste`], como a tarefa faria.
#[cfg(feature = "modo-teste")]
pub fn responder_suspensivel_de_teste(
    chamador: Chamador,
    linha: &str,
) -> Result<alloc::string::String, crate::rede::espera::Espera> {
    let texto = responder_como(chamador, linha.as_bytes(), true)?;
    Ok(alloc::string::String::from_utf8_lossy(texto.como_bytes()).into_owned())
}

/// Só para a suíte: [`responder_suspensivel_de_teste`] com um anexo, como
/// o de `PEDIR_COM_ANEXO`. `Err` com a espera, se suspendeu: a reexecução,
/// pelo [`responder_com_anexo_de_teste`], leva o mesmo anexo — como a
/// tarefa, que o guarda no texto do pedido suspenso.
#[cfg(feature = "modo-teste")]
pub fn responder_suspensivel_com_anexo_de_teste(
    chamador: Chamador,
    linha: &str,
    anexo: &[u8],
) -> Result<alloc::string::String, crate::rede::espera::Espera> {
    let mut pedido = alloc::vec::Vec::from(linha.as_bytes());
    if !anexo.is_empty() {
        pedido.push(SEPARADOR_DO_ANEXO);
        pedido.extend_from_slice(anexo);
    }
    let texto = responder_como(chamador, &pedido, true)?;
    Ok(alloc::string::String::from_utf8_lossy(texto.como_bytes()).into_owned())
}

/// Só para a suíte: guarda como suspenso o pedido `linha` do fio `fio`,
/// com a espera dele — o que [`atender_pendentes`] faz quando um comando
/// suspende.
#[cfg(feature = "modo-teste")]
pub fn suspender_de_teste(fio: u64, linha: &str, espera: crate::rede::espera::Espera) {
    let mut pedido = Texto::novo();
    pedido.acrescentar(linha.as_bytes());
    crate::arch::sem_interrupcoes(|| {
        SUSPENSOS.lock().push(Suspenso {
            fio,
            pedido,
            espera,
        })
    });
}

/// Só para a suíte: consulta uma vez o futuro da tarefa `programas` com
/// `waker`, como o executor faria — e com isso o deixa nos sockets das
/// esperas suspensas. Verdadeiro se ele estava pronto.
#[cfg(feature = "modo-teste")]
pub fn consultar_de_teste(waker: &Waker) -> bool {
    use core::future::Future;
    let mut proximo = ProximoPedido { relogio: None };
    let mut cx = core::task::Context::from_waker(waker);
    core::pin::Pin::new(&mut proximo).poll(&mut cx).is_ready()
}

/// Só para a suíte: quantos pedidos de processo estão suspensos.
#[cfg(feature = "modo-teste")]
pub fn suspensos_de_teste() -> usize {
    crate::arch::sem_interrupcoes(|| SUSPENSOS.lock().len())
}

/// Só para a suíte: [`responder_de_teste`], com um anexo — como chega pela
/// chamada de sistema.
#[cfg(feature = "modo-teste")]
pub fn responder_com_anexo_de_teste(
    chamador: Chamador,
    linha: &str,
    anexo: &[u8],
) -> alloc::string::String {
    let mut pedido = alloc::vec::Vec::from(linha.as_bytes());
    if !anexo.is_empty() {
        pedido.push(SEPARADOR_DO_ANEXO);
        pedido.extend_from_slice(anexo);
    }
    let texto = responder_como(chamador, &pedido, false).unwrap_or_default();
    alloc::string::String::from_utf8_lossy(texto.como_bytes()).into_owned()
}

/// Põe na fila o fio `id` como se ele tivesse pedido — para a suíte
/// conferir que a fila larga o fio que não está mais lá.
#[cfg(feature = "modo-teste")]
pub fn enfileirar_de_teste(id: u64) -> bool {
    FILA.enfileirar(id).is_ok()
}

/// Quantos fios estão na fila — para a suíte conferir que um pedido não
/// entra duas vezes.
#[cfg(feature = "modo-teste")]
pub fn pendentes_de_teste() -> usize {
    FILA.ocupacao()
}

/// Toma o próximo pedido da fila como o executor tomaria, sem atendê-lo: o
/// fio, o texto e o chamador. O pedido fica em curso até
/// [`responder_tomado_de_teste`].
#[cfg(feature = "modo-teste")]
pub fn tomar_de_teste() -> Option<(u64, Texto, Chamador)> {
    let id = FILA.desenfileirar()?;
    let (texto, autoridade, programa) = crate::fios::tomar_pedido(id)?;
    let chamador = Chamador::Processo {
        fio: id,
        autoridade,
        programa,
    };
    Some((id, texto, chamador))
}

/// Atende o pedido tomado por [`tomar_de_teste`] e entrega a resposta.
/// Falso se o fio não a recebeu — não estava mais esperando por ela.
#[cfg(feature = "modo-teste")]
pub fn responder_tomado_de_teste(id: u64, texto: &Texto, chamador: Chamador) -> bool {
    let resposta = responder_como(chamador, texto.como_bytes(), false).unwrap_or_default();
    crate::fios::responder_pedido(id, resposta).is_none()
}
