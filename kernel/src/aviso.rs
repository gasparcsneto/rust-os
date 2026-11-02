//! O aviso da malha (DS-1): o kernel avisa um processo, no canal de eventos
//! dele, que um objeto da malha dele ficou pronto — e só isso.
//!
//! # O que é
//!
//! Um processo do Duke tem um fio só, e um pedido que espera espera **um**
//! objeto. O pseudo-terminal e as janelas já resolveram isso: a espera é
//! uma só, no canal de eventos do processo, e o kernel avisa ali. O aviso
//! da malha põe ali também os endpoints e as pontas de fluxo:
//!
//! - **a designação** vem no mesmo pedido que cria ou aceita o objeto —
//!   `fabric.offer`, `stream.open`, `stream.accept`, com `notify`, o
//!   descritor de um canal de eventos que o processo escuta. O gate decide
//!   o comando como sempre, com a permissão e o recurso de sempre: a
//!   designação anda dentro dessa decisão, sem permissão nova e sem decisão
//!   a mais. O canal tem de ser do processo que pede ([`canal_do_pedido`]);
//! - **o aviso** é um evento [`MALHA`](protocolo::usuario::evento::tipo::MALHA)
//!   que só diz o tipo do objeto, o número do id dele e os bits de
//!   prontidão. Nenhum byte, nenhum motivo, nenhuma identidade, nenhuma
//!   autoridade. Quem recebe pede ao gate o que fazer;
//! - **a conta** de quando avisar é a de [`politica::aviso`]: no máximo um
//!   aviso não consumido por objeto, rearmado pela operação do dono; o
//!   espaço para escrever só para quem esbarrou no cheio; o fim uma vez; o
//!   canal cheio deixa o aviso devido, e o coletor tenta de novo. E um
//!   aviso de cada objeto no canal: o que ainda espera na fila recebe os
//!   bits do seguinte do mesmo objeto
//!   ([`publicar_em_juntando`](crate::eventos::publicar_em_juntando)).
//!
//! # Onde ele nasce
//!
//! Nos mesmos pontos em que a espera de hoje acorda: quem muda um fluxo ou
//! a malha, com a tabela deles na mão, marca o objeto ([`tocar_fluxo`],
//! [`tocar_endpoint`], [`tocar_endpoints`]); quem
//! acorda as esperas, fora da tabela, processa as marcas ([`processar`]) —
//! pergunta o nível do objeto agora, faz a conta e publica. A operação do
//! dono consome o aviso e rearma ([`operou`]). O coletor de fios tenta de
//! novo o que ficou devido ([`passada_do_coletor`]).
//!
//! A ordem das travas: a das marcas é folha — quem a toma não toma mais
//! nada. A das designações nunca fica na mão enquanto se pergunta o nível
//! (as tabelas do fluxo e da malha); e fica na mão enquanto se publica — a
//! dos canais vem depois dela, e a do escalonador depois desta, quando o
//! canal acorda o ouvinte. É o que garante que nada é publicado depois de
//! a operação do dono ouvir o fim: a operação larga a designação pela
//! mesma trava, e ou o aviso já está no canal, ou não sai mais.
//!
//! # O que ele não é
//!
//! Não é registro da auditoria — como os eventos de entrada e o aviso de
//! saída do pseudo-terminal, ele não decide nada: a designação vai no
//! registro da decisão que a criou, cada operação que segue é decidida e
//! gravada, e os avisos contam nas medidas ([`medidas`]). Não atravessa o
//! enlace: cada Duke avisa os processos dele. Não persiste.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::agent::json::Json;
use crate::trava::Mutex;
use politica::aviso::{Aviso, Designacao, Situacao, bits};
use protocolo::usuario::evento::{self, Evento};

// Os bits e os tipos do contrato são os da conta.
const _: () = {
    assert!(evento::malha::LEGIVEL == bits::LEGIVEL as i64);
    assert!(evento::malha::GRAVAVEL == bits::GRAVAVEL as i64);
    assert!(evento::malha::FIM == bits::FIM as i64);
    assert!(evento::malha::PEDIDO == bits::PEDIDO as i64);
    assert!(evento::malha::ENTREGA == bits::ENTREGA as i64);
    assert!(evento::malha::ENDPOINT == politica::aviso::ENDPOINT);
    assert!(evento::malha::PONTA == politica::aviso::PONTA);
};

/// O motivo da recusa de um `notify` que não é um canal de eventos que o
/// processo que pede escuta — curto, para caber inteiro no detalhe da
/// auditoria com o processo na frente e a decisão citada no fim. Não diz
/// de quem é o canal.
pub const RECUSA: &str = "notify nao e canal deste processo";

/// Um objeto da malha que pode ser designado.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Objeto {
    /// Um endpoint, pelo número do id.
    Endpoint(u64),
    /// A ponta do processo `fio` no fluxo `fluxo`.
    Ponta { fluxo: u64, fio: u64 },
}

impl Objeto {
    fn tipo(self) -> i64 {
        match self {
            Objeto::Endpoint(_) => politica::aviso::ENDPOINT,
            Objeto::Ponta { .. } => politica::aviso::PONTA,
        }
    }

    fn numero(self) -> u64 {
        match self {
            Objeto::Endpoint(n) => n,
            Objeto::Ponta { fluxo, .. } => fluxo,
        }
    }

    fn dono(self, canal: Canal) -> u64 {
        match self {
            Objeto::Endpoint(_) => canal.dono,
            Objeto::Ponta { fio, .. } => fio,
        }
    }
}

/// O canal de eventos que um processo designou: a chave dele, e o processo
/// que o escuta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Canal {
    chave: crate::eventos::Chave,
    dono: u64,
}

/// O que mudou, como quem muda o vê: um fluxo inteiro (as duas pontas), um
/// endpoint, ou os endpoints todos — a malha mudou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tocado {
    Fluxo(u64),
    Endpoint(u64),
    Endpoints,
}

struct Entrada {
    canal: Canal,
    d: Designacao,
    /// Os ciclos em que o último aviso foi publicado, até a operação do dono
    /// que o consome: a latência do aviso ([`crate::metricas::AVISO`]). Zero
    /// sem aviso esperando.
    avisado_em: u64,
}

/// As designações vivas.
static DESIGNACOES: Mutex<BTreeMap<Objeto, Entrada>> = Mutex::new(BTreeMap::new());

/// Quantas há: o atalho de quem toca sem designação nenhuma.
static QUANTAS: AtomicUsize = AtomicUsize::new(0);

/// As marcas, esperando quem as processe. A trava é folha.
static TOCADOS: Mutex<Vec<Tocado>> = Mutex::new(Vec::new());

/// Quantas marcas cabem; passou disso, avalia-se tudo.
const MARCAS: usize = 64;

/// As marcas não couberam: a próxima passada avalia todas as designações.
static TRANSBORDOU: AtomicBool = AtomicBool::new(false);

static PUBLICADOS: AtomicU64 = AtomicU64::new(0);
static COALESCIDOS: AtomicU64 = AtomicU64::new(0);
static DEVIDOS: AtomicU64 = AtomicU64::new(0);
static ENTREGUES_DEPOIS: AtomicU64 = AtomicU64::new(0);
static JUNTADOS: AtomicU64 = AtomicU64::new(0);
static LARGADOS: AtomicU64 = AtomicU64::new(0);
static RECUSADAS: AtomicU64 = AtomicU64::new(0);

fn com_designacoes<R>(f: impl FnOnce(&mut BTreeMap<Objeto, Entrada>) -> R) -> R {
    crate::arch::sem_interrupcoes(|| {
        let mut d = DESIGNACOES.lock();
        let r = f(&mut d);
        QUANTAS.store(d.len(), Ordering::Release);
        r
    })
}

/// O canal do `notify` do pedido em execução — o valor que o handler leu
/// do parâmetro —, resolvido para quem pede: `Ok(None)` sem o parâmetro, ou
/// para quem não é processo — o comando o recusa pelo caminho de sempre;
/// `Err` com o motivo quando o descritor não é um canal de eventos que o
/// processo que pede escuta.
pub fn canal_do_pedido(notify: Option<Json>) -> Result<Option<Canal>, &'static str> {
    let Some(valor) = notify else {
        return Ok(None);
    };
    let Some(crate::autorizacao::Pedinte::Processo(fio)) = crate::autorizacao::pedinte() else {
        return Ok(None);
    };
    let recusar = || {
        RECUSADAS.fetch_add(1, Ordering::Relaxed);
        Err(RECUSA)
    };
    let Some(descritor) = valor.as_u64() else {
        return recusar();
    };
    let alvo = crate::fios::com_descritores_de(fio, |t| t.alvo(descritor)).flatten();
    let Some(crate::usuario::descritores::Alvo::Eventos { chave }) = alvo else {
        return recusar();
    };
    // O filho de um `fork` tem o descritor do pai, e não o canal: o canal
    // tem um ouvinte só.
    if !crate::eventos::e_ouvinte(chave, fio) {
        return recusar();
    }
    Ok(Some(Canal { chave, dono: fio }))
}

/// O nome do canal, para o registro da designação.
pub fn nome_do_canal(canal: Canal) -> alloc::string::String {
    crate::eventos::nome_de(canal.chave).unwrap_or_default()
}

/// Designa `obj` ao `canal`, depois da operação que o criou ou aceitou: dali
/// em diante, o kernel avisa. A ponta de quem abriu quer saber da abertura.
/// O nível de agora é avaliado na hora — o objeto pode já estar pronto.
fn designar(obj: Objeto, canal: Canal, quem_abriu: bool) {
    let d = match obj {
        Objeto::Endpoint(_) => Designacao::do_endpoint(),
        Objeto::Ponta { .. } => Designacao::da_ponta(quem_abriu),
    };
    com_designacoes(|t| {
        t.insert(
            obj,
            Entrada {
                canal,
                d,
                avisado_em: 0,
            },
        );
    });
    avaliar(obj);
}

/// Designa a ponta do fluxo `n` do dono do `canal`.
pub fn designar_ponta(n: u64, canal: Canal, quem_abriu: bool) {
    designar(
        Objeto::Ponta {
            fluxo: n,
            fio: canal.dono,
        },
        canal,
        quem_abriu,
    );
}

/// Designa o endpoint `n`, do dono do `canal`.
pub fn designar_endpoint(n: u64, canal: Canal) {
    designar(Objeto::Endpoint(n), canal, false);
}

/// O dono `fio` largou o objeto — fechou o fluxo, retirou o endpoint —, ou
/// a operação dele ouviu o fim: nada mais a avisar. Só o dono larga.
pub fn largar(obj: Objeto, fio: u64) {
    if QUANTAS.load(Ordering::Acquire) == 0 {
        return;
    }
    com_designacoes(|t| {
        if t.get(&obj).is_some_and(|e| obj.dono(e.canal) == fio) {
            t.remove(&obj);
        }
    });
}

/// O objeto acabou e o dono já sabe: sai, sem aviso.
fn sair(obj: Objeto) {
    com_designacoes(|t| {
        t.remove(&obj);
    });
}

/// O processo `fio` acabou, ou trocou de imagem: as designações dele saem —
/// a imagem nova não ouve os avisos da anterior.
pub fn largar_do_processo(fio: u64) {
    if QUANTAS.load(Ordering::Acquire) == 0 {
        return;
    }
    com_designacoes(|t| t.retain(|obj, e| obj.dono(e.canal) != fio));
}

/// Marca uma mudança, com a trava de quem mudou na mão; quem acorda as
/// esperas, fora dela, chama [`processar`].
fn marcar(x: Tocado) {
    if QUANTAS.load(Ordering::Acquire) == 0 {
        return;
    }
    crate::arch::sem_interrupcoes(|| {
        let mut m = TOCADOS.lock();
        if m.contains(&x) {
            return;
        }
        if m.len() >= MARCAS {
            TRANSBORDOU.store(true, Ordering::Release);
            return;
        }
        m.push(x);
    });
}

/// O fluxo `n` mudou: dado, espaço, a abertura, o fim — as duas pontas.
pub fn tocar_fluxo(n: u64) {
    marcar(Tocado::Fluxo(n));
}

/// O endpoint `n` mudou: um pedido de fluxo chegou, ou saiu.
pub fn tocar_endpoint(n: u64) {
    marcar(Tocado::Endpoint(n));
}

/// A malha mudou — uma entrega chegou, um endpoint fechou: os endpoints
/// designados são avaliados de novo.
pub fn tocar_endpoints() {
    marcar(Tocado::Endpoints);
}

/// Fora de qualquer trava: avalia os objetos marcados, e publica o que a
/// conta mandar.
pub fn processar() {
    if QUANTAS.load(Ordering::Acquire) == 0 {
        // Nenhuma designação: as marcas não servem a ninguém.
        if TRANSBORDOU.swap(false, Ordering::AcqRel) {
            crate::arch::sem_interrupcoes(|| TOCADOS.lock().clear());
        }
        return;
    }
    let marcas = crate::arch::sem_interrupcoes(|| core::mem::take(&mut *TOCADOS.lock()));
    let tudo = TRANSBORDOU.swap(false, Ordering::AcqRel);
    if marcas.is_empty() && !tudo {
        return;
    }
    let objetos: Vec<Objeto> = com_designacoes(|t| {
        t.keys()
            .copied()
            .filter(|obj| {
                tudo || marcas.iter().any(|m| match (m, obj) {
                    (Tocado::Fluxo(n), Objeto::Ponta { fluxo, .. }) => n == fluxo,
                    (Tocado::Endpoint(n), Objeto::Endpoint(e)) => n == e,
                    (Tocado::Endpoints, Objeto::Endpoint(_)) => true,
                    _ => false,
                })
            })
            .collect()
    });
    for obj in objetos {
        avaliar(obj);
    }
}

/// O dono `fio` operou sobre o objeto, pelo gate: o aviso está consumido, e
/// o nível de agora rearma. `esbarrou` diz que a escrita não coube inteira.
/// A operação de outro não consome nada.
pub fn operou(obj: Objeto, fio: u64, esbarrou: bool) {
    if QUANTAS.load(Ordering::Acquire) == 0 {
        return;
    }
    let existe = com_designacoes(|t| match t.get_mut(&obj) {
        Some(e) if obj.dono(e.canal) == fio => {
            if e.avisado_em != 0 {
                crate::metricas::AVISO.somar(crate::metricas::desde(e.avisado_em));
                e.avisado_em = 0;
            }
            e.d.operou(esbarrou);
            true
        }
        _ => false,
    });
    if existe {
        avaliar(obj);
    }
}

/// O nível do objeto agora, ou `None` quando ele acabou para um dono que já
/// sabe — e então não há o que avisar.
fn nivel(obj: Objeto) -> Option<u8> {
    match obj {
        Objeto::Ponta { fluxo, fio } => match crate::fluxo::prontidao_da_ponta(fluxo, fio) {
            politica::fluxo::Prontidao::Vivo(b) => Some(b),
            politica::fluxo::Prontidao::Acabou { ja_sabe: false } => Some(bits::FIM),
            politica::fluxo::Prontidao::Acabou { ja_sabe: true } => None,
        },
        Objeto::Endpoint(n) => {
            let (entrega, fim) = crate::malha::prontidao_do_endpoint(n);
            if fim {
                return Some(bits::FIM);
            }
            let mut b = 0;
            if entrega {
                b |= bits::ENTREGA;
            }
            if crate::fluxo::tem_pedido_em(n) {
                b |= bits::PEDIDO;
            }
            Some(b)
        }
    }
}

/// A conta de um objeto: o nível de agora — perguntado fora da trava das
/// designações —, e o aviso, se é hora, publicado com ela na mão.
fn avaliar(obj: Objeto) {
    if com_designacoes(|t| !t.contains_key(&obj)) {
        return;
    }
    let Some(n) = nivel(obj) else {
        // Acabou, e o dono já sabe: a designação sai, sem aviso.
        sair(obj);
        return;
    };
    com_designacoes(|t| {
        let Some(e) = t.get_mut(&obj) else {
            return;
        };
        let antes = e.d.situacao();
        match e.d.mudou(n) {
            Some(a) => publicar(t, obj, a, false),
            None => {
                if e.d.diria(n) != 0 && matches!(antes, Situacao::Avisado | Situacao::Devido(_)) {
                    COALESCIDOS.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });
}

/// Publica o aviso `a` de `obj` no canal da designação, com a tabela das
/// designações na mão, e diz à conta o desfecho.
fn publicar(t: &mut BTreeMap<Objeto, Entrada>, obj: Objeto, a: Aviso, de_novo: bool) {
    let Some(x) = t.get_mut(&obj) else {
        return;
    };
    let (ta, tb, tc) = politica::aviso::campos(obj.tipo(), obj.numero(), a.bits);
    let e = Evento {
        tipo: evento::tipo::MALHA,
        a: ta,
        b: tb,
        c: tc,
    };
    // Um aviso deste objeto que ainda espera na fila — publicado antes de
    // uma operação do dono, e não lido — recebe os bits de agora: o canal
    // tem no máximo um aviso de cada objeto, por mais que o dono opere.
    let juntar = |na_fila: &mut Evento, novo: &Evento| {
        let mesmo = na_fila.tipo == novo.tipo && na_fila.a == novo.a && na_fila.b == novo.b;
        if mesmo {
            na_fila.c |= novo.c;
        }
        mesmo
    };
    match crate::eventos::publicar_em_juntando(x.canal.chave, e, juntar) {
        Ok(como) => {
            match como {
                crate::eventos::Publicado::Novo => PUBLICADOS.fetch_add(1, Ordering::Relaxed),
                crate::eventos::Publicado::Junto => JUNTADOS.fetch_add(1, Ordering::Relaxed),
            };
            if de_novo {
                ENTREGUES_DEPOIS.fetch_add(1, Ordering::Relaxed);
            }
            if x.avisado_em == 0 {
                x.avisado_em = crate::arch::ciclos().max(1);
            }
            x.d.publicado(a);
            if x.d.acabou() {
                t.remove(&obj);
            }
        }
        Err(crate::eventos::NaoPublicado::Cheio) => {
            DEVIDOS.fetch_add(1, Ordering::Relaxed);
            x.d.cheio(a);
        }
        Err(crate::eventos::NaoPublicado::SemOuvinte) => {
            // O dono fechou o canal, ou morreu: nada mais.
            LARGADOS.fetch_add(1, Ordering::Relaxed);
            t.remove(&obj);
        }
    }
}

/// A passada do coletor de fios: as marcas que sobraram, e os avisos que o
/// canal cheio deixou devidos.
pub fn passada_do_coletor() {
    if QUANTAS.load(Ordering::Acquire) == 0 {
        return;
    }
    processar();
    com_designacoes(|t| {
        let devidos: Vec<(Objeto, Aviso)> = t
            .iter_mut()
            .filter_map(|(obj, e)| e.d.retentar().map(|a| (*obj, a)))
            .collect();
        for (obj, a) in devidos {
            publicar(t, obj, a, true);
        }
    });
}

/// O que se mede do aviso, para `security.metrics`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Medidas {
    /// As designações vivas.
    pub designacoes: usize,
    /// Os avisos publicados.
    pub publicados: u64,
    /// Os avisos que se juntaram a um do mesmo objeto ainda na fila.
    pub juntados: u64,
    /// As mudanças que não avisaram porque já havia um aviso.
    pub coalescidos: u64,
    /// Os avisos que acharam o canal cheio e ficaram devidos.
    pub devidos: u64,
    /// Os devidos entregues numa nova tentativa.
    pub entregues_depois: u64,
    /// As designações que caíram porque o canal sumiu.
    pub largados: u64,
    /// Os `notify` recusados: o canal não é do processo que pede.
    pub recusados: u64,
}

pub fn medidas() -> Medidas {
    Medidas {
        designacoes: QUANTAS.load(Ordering::Acquire),
        publicados: PUBLICADOS.load(Ordering::Relaxed),
        juntados: JUNTADOS.load(Ordering::Relaxed),
        coalescidos: COALESCIDOS.load(Ordering::Relaxed),
        devidos: DEVIDOS.load(Ordering::Relaxed),
        entregues_depois: ENTREGUES_DEPOIS.load(Ordering::Relaxed),
        largados: LARGADOS.load(Ordering::Relaxed),
        recusados: RECUSADAS.load(Ordering::Relaxed),
    }
}

/// Só para a suíte: se `obj` está designado, e onde a conta dele está.
#[cfg(feature = "modo-teste")]
pub fn situacao_de_teste(obj: Objeto) -> Option<Situacao> {
    com_designacoes(|t| t.get(&obj).map(|e| e.d.situacao()))
}

/// Só para a suíte: as designações de um processo.
#[cfg(feature = "modo-teste")]
pub fn designacoes_de_teste(fio: u64) -> usize {
    com_designacoes(|t| t.iter().filter(|(o, e)| o.dono(e.canal) == fio).count())
}

/// Destrava as tabelas à força, para uso exclusivo do caminho de falha
/// fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução.
pub unsafe fn destravar() {
    unsafe {
        DESIGNACOES.force_unlock();
        TOCADOS.force_unlock();
    }
}
