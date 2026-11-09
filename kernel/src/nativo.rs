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
//!
//! # A vez da tarefa, e o orçamento dela
//!
//! O executor é cooperativo: a tarefa `programas` o divide com o canal do
//! agente, o enlace, o pulso, o console e a barra, e nenhuma delas roda
//! enquanto ela não devolve o controle. Cada vez dela — cada vez que o
//! executor a avança — atende no máximo um [`OrcamentoDaVez`] (os
//! [`PEDIDOS_POR_VEZ`] primeiros da fila, ou os que couberem em
//! [`TEMPO_POR_VEZ_US`] microssegundos, o que acabar antes) e cede
//! ([`crate::tarefas::ceder`]): ela vai para o fim da fila de prontas, e as
//! tarefas acordadas enquanto ela atendia rodam antes da vez seguinte dela,
//! mesmo com a fila dos pedidos sempre cheia. O pedido que não coube fica
//! na fila, no lugar dele: nada se perde, nada se repete, e a ordem é a da
//! chegada. Os suspensos cuja espera acabou são executados de novo a cada
//! vez, com a fila cheia ou vazia, fora do orçamento.
//!
//! Antes do orçamento, a tarefa atendia a fila até esvaziá-la, e só cedia
//! quando a encontrava vazia: medido em produção, dois processos de um
//! titular pedindo sem parar faziam-na atender cadeias de até 1 366 pedidos
//! numa vez só, segurando o executor até 338 ms, e o canal do agente dos
//! outros titulares ia de um p99 de 9–56 ms sem carga a 164–280 ms (a
//! investigação de 8/11/2026; ver o README, *Decisões pendentes*). O canal do
//! agente já cedia depois de cada pedido; a tarefa `programas` passou a
//! ceder depois de cada vez. Nada muda no que um pedido decide — o mesmo
//! gate, a mesma taxa, a mesma auditoria —, só quando ele é atendido.

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

/// Quanto uma vez da tarefa `programas` atende antes de ceder o executor —
/// ver "A vez da tarefa, e o orçamento dela", no começo do módulo.
///
/// Conta cada id tirado da fila: o pedido atendido, o que suspendeu, o
/// recusado — pela taxa, pelo gate, pelo JSON — e o largado, de um fio que
/// morreu com o pedido na fila. Todo id passa pela tabela de fios, e todo
/// pedido que chega a um comando, pelo gate inteiro: a recusa pela taxa
/// custa quase o mesmo que um pedido atendido, e não protege o executor —
/// ela é servida no mesmo orçamento que os outros.
///
/// Os suspensos cuja espera acabou não contam: são executados de novo a
/// cada vez, todos — no máximo um por fio, e cada um uma vez só, sem
/// suspender de novo (ver [`retomar_suspensos`]) —, e por isso não passam
/// fome atrás de uma fila que não esvazia.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrcamentoDaVez {
    /// Quantos ids, no máximo, uma vez tira da fila. Zero vale um: toda vez
    /// anda.
    pub pedidos: usize,
    /// Por quanto tempo, em nanossegundos pela régua de [`crate::metricas`],
    /// uma vez segue tirando pedidos. Conferido antes de tirar o próximo, e
    /// nunca antes do primeiro: toda vez atende ao menos um, e o pedido
    /// tirado é tratado nesta vez. `u64::MAX`: sem tempo.
    pub tempo_ns: u64,
}

impl OrcamentoDaVez {
    /// O tempo da vez que começou em `inicio` — o contador de
    /// [`crate::arch::ciclos`] — acabou. A régua só se calibra depois do
    /// primeiro tique: antes dele, o tempo não acaba, e quem limita a vez é
    /// a conta dos pedidos.
    fn venceu(self, inicio: u64) -> bool {
        self.tempo_ns != u64::MAX
            && crate::metricas::nanos(crate::metricas::desde(inicio)) >= self.tempo_ns
    }

    /// Só para a suíte: [`Self::venceu`], para um caso conferir a unidade
    /// do tempo contra a régua de [`crate::metricas`].
    #[cfg(feature = "modo-teste")]
    pub fn venceu_de_teste(self, inicio: u64) -> bool {
        self.venceu(inicio)
    }
}

/// Quantos pedidos uma vez da tarefa `programas` tira da fila, no máximo.
///
/// Escolhido pela bancada (`cargo xtask disponibilidade`, 9/11/2026), com
/// [`TEMPO_POR_VEZ_US`]: na varredura do x86_64 em `release` com 3 vCPUs —
/// 1, 4, 16 e 64 pedidos sem tempo, e 0,5, 2 e 8 ms sem conta —, de 1 a 16
/// pedidos o canal do agente sob carga voltou abaixo do controle sem fila,
/// sem a vazão cair; com 64, a vez foi a 25–33 ms no p99. Dezesseis é a
/// maior conta com a vez perto de 10 ms no p99, e a de maior vazão com dois
/// processos e com dois titulares; o tempo limita a vez quando os pedidos
/// custam mais. Os números estão em `docs/INTERFACE.md`, em *A fila e a
/// vez da tarefa `programas`*.
pub const PEDIDOS_POR_VEZ: usize = 16;

/// Por quanto tempo, em microssegundos, uma vez da tarefa `programas` segue
/// tirando pedidos.
///
/// Dois milissegundos, pela mesma varredura de [`PEDIDOS_POR_VEZ`]: a conta
/// sozinha não vê o pedido caro — a depuração, a espera pela trava da
/// auditoria, o disco —, e com dezesseis pedidos a vez chegou a 12 ms no
/// p99 em `release`; com o tempo, ela fica em 4 ms no p99 em `release`, nas
/// duas arquiteturas, sem a vazão cair em relação ao código de antes. Em
/// depuração, com o pedido de uns 2 ms, a vez fica em 12–66 ms no p99. O
/// tempo corta a vez depois do pedido que passou dele — um pedido nunca é
/// cortado no meio. `u64::MAX` seria sem tempo, só a conta — o `cargo
/// xtask invariantes` não o aceita aqui.
pub const TEMPO_POR_VEZ_US: u64 = 2_000;

/// O orçamento da tarefa `programas`: [`PEDIDOS_POR_VEZ`] e
/// [`TEMPO_POR_VEZ_US`].
pub const ORCAMENTO_DA_VEZ: OrcamentoDaVez = OrcamentoDaVez {
    pedidos: PEDIDOS_POR_VEZ,
    tempo_ns: TEMPO_POR_VEZ_US.saturating_mul(1_000),
};

// Toda vez anda: com zero, a tarefa cederia sem atender, e os processos
// esperariam para sempre.
const _: () = assert!(PEDIDOS_POR_VEZ >= 1);

/// Uma vez do `orcamento`: atende os pedidos da fila na ordem em que
/// chegaram, um de cada vez, até o orçamento acabar ou a fila esvaziar; e
/// executa de novo os suspensos cuja espera acabou. Devolve quantos pedidos
/// chegaram a um comando — atendidos ou suspensos — mais os suspensos
/// atendidos; o id largado (o fio que morreu com o pedido na fila) conta no
/// orçamento, e não aqui.
///
/// O orçamento é conferido **antes** de tirar o id seguinte: o que não
/// coube fica na fila, no lugar dele, para a próxima vez — nenhum id sai da
/// fila sem ser tratado nesta vez. E [`crate::fios::tomar_pedido`] toma o
/// pedido de um fio uma vez só: um id repetido na fila, ou o de um fio que
/// já não espera aquele pedido, é largado sem chegar ao gate.
pub fn atender_com(orcamento: OrcamentoDaVez) -> usize {
    let teto = orcamento.pedidos.max(1);
    let inicio = crate::arch::ciclos();
    let mut tirados = 0;
    let mut atendidos = 0;
    while tirados < teto {
        // O tempo, antes de tirar o próximo — e nunca antes do primeiro.
        if tirados > 0 && orcamento.venceu(inicio) {
            break;
        }
        let Some(id) = FILA.desenfileirar() else {
            break;
        };
        tirados += 1;
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

/// Só para a suíte: uma vez do [`ORCAMENTO_DA_VEZ`] — a mesma da tarefa
/// `programas`.
///
/// Na suíte não há a tarefa: quem espera um processo chama, e volta a
/// conferir a espera dele depois de cada vez — a chamada acaba, mesmo com
/// processos pedindo sem parar noutro núcleo. Fora da suíte ela não
/// existe: a fila só é atendida pela tarefa, no executor (e o `xtask`
/// confere que os nomes que a atendem não aparecem fora deste arquivo e da
/// suíte).
#[cfg(feature = "modo-teste")]
pub fn atender_pendentes() -> usize {
    atender_com(ORCAMENTO_DA_VEZ)
}

/// A resposta de um pedido vai ao fio `id`.
fn entregar(id: u64, resposta: Texto) {
    // O fio morreu enquanto o comando executava: a resposta se apaga, e
    // a janela de nonces que o comando possa ter aberto também — o
    // coletor pode tê-la esquecido antes de o comando terminar.
    if let Some(sobra) = crate::fios::responder_pedido(id, resposta) {
        drop(sobra);
        crate::mensagens::canal_acabou(politica::mensagens::Canal::Processo(id));
        // E o endpoint que o comando possa ter aberto na malha.
        crate::malha::canal_acabou(politica::mensagens::Canal::Processo(id));
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
    let licenca = match autorizacao::autorizar(chamador, comando, requisicao.params, permitir) {
        Ok(autorizacao::Decisao::Licenca(l)) => l,
        // Adiado pelo caminho da auditoria: como um comando que suspendeu,
        // o pedido fica, e é executado de novo, pelo gate, quando a espera
        // acabar — ver `crate::oleoduto`.
        Ok(autorizacao::Decisao::Adiada(e)) => {
            *espera = Some(e);
            politica::sigiloso::zerar_bloco(&mut anexo);
            return Ok(());
        }
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

/// A tarefa do executor que atende os pedidos dos processos: o laço de
/// [`servir_com`], com o [`ORCAMENTO_DA_VEZ`]. Na suíte não há executor:
/// quem espera um processo atende — ver `atender_pendentes`, que só existe
/// nela —, e um caso roda o mesmo laço num executor de teste.
#[cfg(not(feature = "modo-teste"))]
pub async fn servir() {
    servir_com(ORCAMENTO_DA_VEZ, || true).await
}

/// O laço da tarefa `programas`, o mesmo na produção e num executor da
/// suíte: espera um pedido na fila, ou o fim da espera de um suspenso
/// ([`ProximoPedido`]); atende uma vez do `orcamento` ([`atender_com`]); e
/// cede ([`crate::tarefas::ceder`]).
///
/// Cede **sempre**, e não só quando o orçamento acaba: a vez que esvaziou a
/// fila e cedesse só então emendaria noutra no pedido que chegasse logo
/// depois — o `ProximoPedido` o encontraria pronto —, e a cadeia de vezes
/// voltaria a não ter fim. Cedendo, a tarefa vai para o fim da fila de
/// prontas do executor: o canal do agente, o enlace, o pulso, o console e a
/// barra que foram acordados enquanto ela atendia rodam antes da vez
/// seguinte dela.
///
/// Sai quando `seguir`, conferido no começo de cada volta — e por isso logo
/// depois de cada cessão —, diz que não: na produção, nunca.
pub async fn servir_com(orcamento: OrcamentoDaVez, seguir: fn() -> bool) {
    while seguir() {
        ProximoPedido { relogio: None }.await;
        atender_com(orcamento);
        crate::tarefas::ceder().await;
    }
}

/// Fica pronto quando há pedido na fila, ou quando a espera de um pedido
/// suspenso acabou: a pilha acorda a tarefa no evento da conexão, e o
/// relógio no prazo mais próximo. Na suíte, que não tem a tarefa, um caso
/// o consulta com o waker dele — ver `consultar_de_teste`, que só existe
/// no `modo-teste` —, ou roda o laço de [`servir_com`] num executor de
/// teste.
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
/// autoridade dele, e sem nenhum passo a menos — ver `crate::seguranca`. E
/// o fio do botão de energia, que pede o desligamento como o sistema — ver
/// `crate::botao`. O `xtask` confere que ninguém mais chama.
pub fn responder_pelo_kernel(chamador: Chamador, linha: &[u8]) -> Texto {
    // Sem suspensão, o comando responde: não há espera a largar.
    responder_como(chamador, linha, false).unwrap_or_default()
}

/// [`responder_pelo_kernel`], podendo esperar: um comando que suspende — o
/// `net.recv` com `wait` do serviço de hora, ou um pedido de dados que o
/// caminho da auditoria adiou — espera aqui, no fio de quem pede, e é
/// executado de novo, inteiro, pelo gate, quando a espera acaba: o mesmo
/// que um pedido de processo suspenso (ver [`retomar_suspensos`]). Quem
/// espera sai do rodízio até o evento da conexão ou o tique do prazo, como
/// a tarefa de uma sessão do canal — ver `fios::bloquear_em`. O waker fica
/// no socket da conexão de quem pede, que ninguém mais espera.
///
/// `pedido` é a linha, e o anexo depois do separador, se houver — como na
/// fila dos processos. O `xtask` confere que só o serviço de hora chama.
pub fn responder_pelo_kernel_esperando(chamador: Chamador, pedido: &[u8]) -> Texto {
    let espera = match responder_como(chamador, pedido, true) {
        Ok(texto) => return texto,
        Err(espera) => espera,
    };
    crate::fios::bloquear_em(crate::rede::espera::Aguardar::nova(&espera));
    // Desarmada antes da reexecução, que responde com o que houver e não
    // suspende de novo.
    drop(espera);
    responder_como(chamador, pedido, false).unwrap_or_default()
}

/// O separador entre a linha e o anexo, para quem monta um pedido com
/// anexo para [`responder_pelo_kernel_esperando`].
pub const SEPARADOR: u8 = SEPARADOR_DO_ANEXO;

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
/// com a espera dele — o que [`atender_com`] faz quando um comando
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

/// Só para a suíte: põe na fila o fio `id`, como `pedir` põe, e acorda
/// quem a espera — para dar à tarefa uma fila que não esvazia sem um
/// processo de verdade. O id de um fio que não existe é largado sem chegar
/// ao gate, e conta no orçamento da vez como qualquer outro. Falso se a
/// fila estava cheia.
#[cfg(feature = "modo-teste")]
pub fn enfileirar_e_acordar_de_teste(id: u64) -> bool {
    let entrou = FILA.enfileirar(id).is_ok();
    acordar_o_executor();
    entrou
}

/// Só para a suíte: vezes do [`ORCAMENTO_DA_VEZ`] até a fila esvaziar — ao
/// menos uma, com os suspensos dela —, para o caso que precisa da fila
/// vazia. Devolve quantos foram atendidos. Com teto: um processo que pede
/// sem parar noutro núcleo não a deixaria esvaziar.
#[cfg(feature = "modo-teste")]
pub fn esvaziar_de_teste() -> usize {
    let mut atendidos = 0;
    for _ in 0..FILA.capacidade() {
        atendidos += atender_pendentes();
        if FILA.vazia() {
            break;
        }
    }
    atendidos
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
