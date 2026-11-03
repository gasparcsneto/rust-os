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
//! dono consome o aviso e rearma ([`operou`]) — e a operação do dono que
//! não passa, recusada pelo gate, pela reconfirmação ou pelo próprio
//! comando, também o consome, com o rearme pelo coletor, um tempo depois,
//! que dobra a cada recusa seguida ([`recusada`],
//! [`recusado_pelo_gate`]); até lá, só o que é novo no objeto avisa — o
//! que a operação recusada já encontrou não, por mudança nenhuma de outro
//! objeto —, e a vaga que um fluxo do processo deixa na cota dele avisa,
//! uma vez, o pedido que ele não pôde aceitar ([`vaga`]): a recusa que
//! responde a esse aviso espaça como as outras. O objeto que já acabou não
//! espera o rearme: o fim sai na hora, uma vez. A operação do dono que não
//! mudou nada no objeto — o aceite sem pedido, a recepção sem entrega nova
//! — consome sem desfazer o rearme marcado ([`consumiu`]); e a recepção
//! que releu o que já tinha lido, com entrega pendente ainda lá, conta como
//! a que não passa. O coletor de fios tenta de novo o que ficou devido
//! ([`passada_do_coletor`]).
//!
//! # O que fica guardado
//!
//! Uma designação por objeto vivo — as cotas limitam os objetos de um
//! processo. Do objeto que acabou, só o fim que ainda não foi dito: o que
//! acaba com um aviso ainda não consumido junta o fim ao evento desse
//! aviso, se ele ainda espera na fila, e a designação sai na hora; se o
//! dono já o tirou da fila, o fim espera a operação dele. O que acaba com o
//! canal cheio guarda o fim devido. Os dois juntos, até
//! [`ACABADOS_POR_PROCESSO`] por processo: passado disso, cai o de menor
//! chave — os endpoints antes das pontas e, entre os do mesmo tipo, o mais
//! antigo.
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
//! registro de execução do comando que a criou, na mesma cadeia, ligado à
//! decisão dele; cada operação que segue é decidida e gravada, e os avisos
//! contam nas medidas ([`medidas`]). Não atravessa o enlace: cada Duke
//! avisa os processos dele. Não persiste.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::agent::json::Json;
use crate::trava::Mutex;
use politica::aviso::{ACABADOS_POR_PROCESSO, Aviso, Designacao, Situacao, bits};
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
/// endpoint, os endpoints todos — a malha mudou —, ou a cota de fluxos do
/// processo — um fluxo dele acabou, e há uma vaga.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tocado {
    Fluxo(u64),
    Endpoint(u64),
    Endpoints,
    Vaga(u64),
}

struct Entrada {
    canal: Canal,
    d: Designacao,
    /// Os ciclos em que o último aviso foi publicado, até a operação do dono
    /// que o consome: a latência do aviso ([`crate::metricas::AVISO`]). Zero
    /// sem aviso esperando.
    avisado_em: u64,
    /// Quando o coletor reavalia o objeto, em ms desde o boot, depois de
    /// uma operação recusada ter consumido o aviso ([`recusada`]). Zero sem
    /// rearme marcado.
    rearmar_em: u64,
    /// As operações do dono recusadas em seguida, desde a última que
    /// passou: o rearme dobra a cada uma
    /// ([`politica::aviso::espera_depois_da_recusa`]).
    recusas: u32,
    /// O nível que a última operação recusada encontrou: até o rearme, só o
    /// que não estava nele avisa
    /// ([`politica::aviso::novo_depois_da_recusa`]). A vaga na cota do
    /// processo o limpa — era o que o aceite recusado esperava.
    recusado: u8,
    /// Uma vaga na cota do processo chegou — ou as marcas transbordaram, e
    /// a marca dela pode ter sido a que não coube ([`processar`]) —, e desde
    /// então nenhum aviso do objeto saiu no canal, nem operação do dono
    /// passou: a recusa que vier antes — a vaga chegou com um aviso ainda
    /// não consumido, ou no meio da operação — não espaça, e o aviso da vaga
    /// sai, uma vez. O aviso publicado a tira ([`publicar`]), também o do
    /// rearme: a recusa seguinte já é a resposta a ele, e espaça. O rearme
    /// que não publica — o aviso de antes ainda não consumido — não a tira
    /// ([`passada_do_coletor`]).
    vaga: bool,
}

/// As designações guardadas: as dos objetos vivos e as dos que já acabaram
/// com o fim ainda por dizer ou por ouvir (no teto de
/// [`ACABADOS_POR_PROCESSO`] por processo).
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

/// O nome do canal, para o registro da designação: só letras, dígitos e
/// `-_.:/` — o resto vira `_`. O nome é texto do processo, e no detalhe da
/// auditoria ele não pode imitar o que vem depois dele (`; decisao N`).
pub fn nome_do_canal(canal: Canal) -> alloc::string::String {
    crate::eventos::nome_de(canal.chave)
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '/') {
                c
            } else {
                '_'
            }
        })
        .collect()
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
                rearmar_em: 0,
                recusas: 0,
                recusado: 0,
                vaga: false,
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

/// O processo `fio` trocou de imagem: as designações saem, e os avisos que
/// ainda esperavam na fila dos canais dele também — a imagem nova herda os
/// descritores, e não deve ouvir os avisos da anterior.
pub fn trocou_de_imagem(fio: u64) {
    largar_do_processo(fio);
    crate::eventos::descartar(fio, TIPO_DO_AVISO);
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
        #[cfg(feature = "modo-teste")]
        if transbordada_de_teste(x) {
            TRANSBORDOU.store(true, Ordering::Release);
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

/// Um fluxo do processo `fio` acabou, e a cota de fluxos dele tem uma vaga:
/// os endpoints dele são avaliados de novo, e o pedido que ele não pôde
/// aceitar por falta de vaga avisa, sem esperar o rearme da recusa — uma
/// vez: a recusa que responde a esse aviso espaça como as outras.
pub fn vaga(fio: u64) {
    marcar(Tocado::Vaga(fio));
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
        let mut objetos = Vec::new();
        for (obj, e) in t.iter_mut() {
            let dono = obj.dono(e.canal);
            // A vaga do dono: a marca dela, ou o transbordo — a marca que
            // não coube pode ter sido a dela, e perdê-la deixaria o pedido
            // mudo até o rearme da recusa, que dobra até um minuto. No
            // transbordo, cada endpoint conta como talvez com uma vaga: no
            // máximo um aviso a mais por endpoint, sem giro — o aviso
            // publicado tira a marca, e a recusa que responde a ele espaça.
            let vaga = matches!(obj, Objeto::Endpoint(_))
                && (tudo || marcas.contains(&Tocado::Vaga(dono)));
            if vaga {
                // A vaga é o que o aceite recusado pela cota esperava: o
                // pedido que ainda espera avisa de novo. A marca fica até um
                // aviso do objeto sair (`publicar`): com o objeto livre, o
                // desta conta; com um aviso ainda não consumido, o que sai
                // depois da operação que o consome — e a recusa dele, que
                // veio antes do aviso da vaga, não espaça. O rearme que não
                // publica não a tira.
                e.recusado = 0;
                e.vaga = true;
            }
            let tocado = vaga
                || marcas.iter().any(|m| match (m, obj) {
                    (Tocado::Fluxo(n), Objeto::Ponta { fluxo, .. }) => n == fluxo,
                    (Tocado::Endpoint(n), Objeto::Endpoint(x)) => n == x,
                    (Tocado::Endpoints, Objeto::Endpoint(_)) => true,
                    _ => false,
                });
            if tudo || tocado {
                objetos.push(*obj);
            }
        }
        objetos
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
    #[cfg(feature = "modo-teste")]
    let velha = conta_velha_de_teste(obj);
    let existe = com_designacoes(|t| match t.get_mut(&obj) {
        Some(e) if obj.dono(e.canal) == fio => {
            consumir(e, esbarrou);
            // A operação reavalia agora: o rearme marcado por uma recusa
            // não tem mais o que fazer, e a conta das recusas recomeça.
            e.rearmar_em = 0;
            e.recusas = 0;
            e.recusado = 0;
            e.vaga = false;
            true
        }
        _ => false,
    });
    #[cfg(feature = "modo-teste")]
    if let Some((n, geracao)) = velha.filter(|_| existe) {
        avaliar_com(obj, n, geracao);
    }
    if existe {
        avaliar(obj);
    }
}

/// O dono operou sobre o objeto, pelo gate, sem mudar nada nele — o aceite
/// sem pedido na fila, a recepção sem entrega nova —: o aviso está
/// consumido, e o nível de agora rearma; mas o rearme espaçado por uma
/// recusa continua marcado — a operação que não fez nada não o desfaz, e
/// até ele só o novo avisa.
pub fn consumiu(obj: Objeto, fio: u64) {
    if QUANTAS.load(Ordering::Acquire) == 0 {
        return;
    }
    let existe = com_designacoes(|t| match t.get_mut(&obj) {
        Some(e) if obj.dono(e.canal) == fio => {
            consumir(e, false);
            true
        }
        _ => false,
    });
    if existe {
        avaliar(obj);
    }
}

/// O aviso da entrada `e` está consumido: a latência dele vai às medidas, e
/// a conta rearma.
fn consumir(e: &mut Entrada, esbarrou: bool) {
    if e.avisado_em != 0 {
        crate::metricas::AVISO.somar(crate::metricas::desde(e.avisado_em));
        e.avisado_em = 0;
    }
    e.d.operou(esbarrou);
}

/// A operação do dono `fio` sobre `obj` não passou — recusada pelo gate,
/// pela reconfirmação dentro da decisão, ou pelo próprio comando (a cota
/// cheia, o estado do objeto) —, ou passou sem conseguir nada, com o que
/// esperava ainda lá (a recepção que releu as entregas já lidas). Ela
/// consome o aviso, como a que passa (a regra de `docs/SDK.md`): senão o
/// objeto ficaria mudo, com um aviso que nada consome. Mas o que ainda está
/// pronto, e a operação não conseguiu fazer, não avisa de novo na hora —
/// voltaria a ser tentado e recusado num giro —: o coletor reavalia depois
/// de [`politica::aviso::espera_depois_da_recusa`], que dobra a cada
/// recusa seguida, até um minuto, e até lá só o que é novo no objeto avisa
/// ([`politica::aviso::novo_depois_da_recusa`]). Uma recusa com um rearme
/// já marcado não o empurra: fica o prazo mais cedo. Não esperam: o objeto
/// que já acabou — o fim não gira: sai uma vez, e a designação com ele —,
/// e a recusa que veio antes do aviso de uma vaga nova na cota do processo
/// — a vaga chegou com um aviso ainda não consumido, ou no meio da operação
/// —: o pedido avisa de novo, uma vez. A recusa que vem depois de o aviso
/// da vaga sair é a resposta a ele, e espaça: a mesma vaga não avisa duas
/// vezes. E a conta é refeita depois da trava, sempre: o que mudou entre a
/// pergunta do nível e a trava — o objeto que acabou, um bit novo — não
/// espera o rearme.
pub fn recusada(obj: Objeto, fio: u64) {
    if QUANTAS.load(Ordering::Acquire) == 0 {
        return;
    }
    #[cfg(feature = "modo-teste")]
    {
        let fio_da_vaga = VAGA_NA_RECUSA.swap(0, Ordering::AcqRel);
        if fio_da_vaga != 0 {
            vaga(fio_da_vaga);
            processar();
            if REARME_NA_RECUSA.swap(false, Ordering::AcqRel) {
                vencer_o_rearme_de_teste(obj);
                passada_do_coletor();
            }
        }
    }
    // O nível que a operação recusada encontrou — perguntado fora da trava
    // das designações.
    let n = nivel(obj);
    #[cfg(feature = "modo-teste")]
    if FIM_NA_RECUSA.swap(false, Ordering::AcqRel) {
        crate::fluxo::vencer_de_teste(u64::MAX);
    }
    let agora = crate::tempo::uptime_ms();
    // `Some(true)`: o que ela encontrou pronto espera o rearme.
    let espacou = com_designacoes(|t| {
        let e = t.get_mut(&obj)?;
        if obj.dono(e.canal) != fio {
            return None;
        }
        consumir(e, false);
        let vaga = core::mem::take(&mut e.vaga);
        let Some(n) = n.filter(|b| *b & bits::FIM == 0 && !vaga) else {
            return Some(false);
        };
        e.recusas = e.recusas.saturating_add(1);
        e.recusado = n;
        let quando = agora
            .saturating_add(politica::aviso::espera_depois_da_recusa(e.recusas))
            .max(1);
        e.rearmar_em = if e.rearmar_em == 0 {
            quando
        } else {
            e.rearmar_em.min(quando)
        };
        Some(true)
    });
    // A conta de agora, também depois da recusa espaçada: o filtro cala o
    // que ela encontrou, e o que mudou depois do nível — o fim, um bit novo
    // — sai.
    if espacou.is_some() {
        avaliar(obj);
    }
}

/// O gate recusou um pedido de `chamador` antes de qualquer operação — a
/// taxa, a contenção, a política: se é a operação do dono sobre um objeto
/// designado, ela foi recusada ([`recusada`]).
pub fn recusado_pelo_gate(chamador: crate::autorizacao::Chamador, nome: &str, params: Json) {
    if QUANTAS.load(Ordering::Acquire) == 0 {
        return;
    }
    let crate::autorizacao::Chamador::Processo { fio, .. } = chamador else {
        return;
    };
    if let Some(obj) = objeto_do_pedido(nome, params, fio) {
        recusada(obj, fio);
    }
}

/// O objeto que o pedido `nome` do processo `fio` opera como dono: a ponta
/// dele no fluxo do parâmetro `stream`, ou o endpoint do parâmetro
/// `endpoint` de quem aceita, recebe ou retira. O de outro não é dele: a
/// designação só é consumida pelo dono.
fn objeto_do_pedido(nome: &str, params: Json, fio: u64) -> Option<Objeto> {
    let numero = |parametro: &str| {
        params
            .member(parametro)
            .and_then(|v| v.as_str())
            .and_then(politica::aviso::numero_do_id)
    };
    match nome {
        "stream.read" | "stream.write" | "stream.finish" | "stream.close" | "stream.status" => {
            Some(Objeto::Ponta {
                fluxo: numero(crate::fluxo::PARAMETRO)?,
                fio,
            })
        }
        "stream.accept" | "fabric.recv" | "fabric.withdraw" => {
            Some(Objeto::Endpoint(numero("endpoint")?))
        }
        _ => None,
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
///
/// A geração da designação vai junto com o nível: uma operação do dono
/// entre a pergunta e a trava — outro núcleo, a conta atrasada — muda a
/// geração, e esta conta não publica o nível de antes dela — o `FIM` que a
/// operação já ouviu, o dado que ela já leu. A operação refaz a conta, com
/// o nível de depois: nada se perde.
fn avaliar(obj: Objeto) {
    let Some(geracao) = com_designacoes(|t| t.get(&obj).map(|e| e.d.geracao())) else {
        return;
    };
    let Some(n) = nivel(obj) else {
        // Acabou, e o dono já sabe: a designação sai, sem aviso.
        sair(obj);
        return;
    };
    avaliar_com(obj, n, geracao);
}

/// A parte da conta com a trava das designações: o aviso de `obj` pelo
/// nível `n`, perguntado quando a designação estava na geração `geracao`.
fn avaliar_com(obj: Objeto, n: u8, geracao: u32) {
    com_designacoes(|t| {
        let Some(e) = t.get_mut(&obj) else {
            return;
        };
        if e.d.geracao() != geracao {
            return;
        }
        // Depois de uma recusa, até o rearme, o que a operação recusada
        // já encontrou não avisa de novo — voltaria a ser recusado, e a
        // mudança de outro objeto não o faz pronto de novo —: só o novo,
        // o que o dono ouviria.
        if e.rearmar_em != 0 && !e.d.novo_depois_da_recusa(n, e.recusado) {
            return;
        }
        let antes = e.d.situacao();
        let canal = e.canal;
        let aviso = e.d.mudou(n);
        if aviso.is_none()
            && e.d.diria(n) != 0
            && matches!(antes, Situacao::Avisado | Situacao::Devido(_))
        {
            COALESCIDOS.fetch_add(1, Ordering::Relaxed);
        }
        match aviso {
            Some(a) => publicar(t, obj, a, false),
            // Acabou com um aviso ainda não consumido: o fim se junta ao
            // evento dele, se ainda espera na fila, e a designação sai;
            // senão o fim espera a operação do dono.
            None if e.d.fim_na_espera() && juntar_o_fim(canal, obj) => {
                e.d.juntou_o_fim();
                t.remove(&obj);
            }
            None => {}
        }
        // O fim que espera — devido, ou na espera do dono —: o teto do
        // processo.
        if t.get(&obj).is_some_and(|e| e.d.guarda_o_fim()) {
            conter_os_acabados(t, obj.dono(canal));
        }
    });
}

/// O tipo do evento de um aviso — o único lugar do kernel que o nomeia.
const TIPO_DO_AVISO: u32 = evento::tipo::MALHA;

/// O evento do aviso de `obj` com os bits `b`: montado só aqui, pela conta
/// de [`politica::aviso`] — o tipo do objeto, o número dele e os bits, e
/// nada mais.
fn evento_do_aviso(obj: Objeto, b: u8) -> Evento {
    let (a, n, c) = politica::aviso::campos(obj.tipo(), obj.numero(), b);
    Evento {
        tipo: TIPO_DO_AVISO,
        a,
        b: n,
        c,
    }
}

/// Um aviso deste objeto que ainda espera na fila — publicado antes de uma
/// operação do dono, e não lido — recebe os bits do novo: o canal tem no
/// máximo um aviso de cada objeto, por mais que o dono opere.
fn juntar_eventos(na_fila: &mut Evento, novo: &Evento) -> bool {
    let mesmo = na_fila.tipo == novo.tipo && na_fila.a == novo.a && na_fila.b == novo.b;
    if mesmo {
        na_fila.c |= novo.c;
    }
    mesmo
}

/// O objeto acabou com um aviso ainda não consumido: o `FIM` junta-se ao
/// evento dele que ainda espera na fila do canal, se espera — o dono lê os
/// dois juntos —, e nenhum evento novo entra. Diz se juntou.
fn juntar_o_fim(canal: Canal, obj: Objeto) -> bool {
    let fim = evento_do_aviso(obj, bits::FIM);
    let juntou = crate::eventos::juntar_na_fila(canal.chave, &fim, juntar_eventos);
    if juntou {
        JUNTADOS.fetch_add(1, Ordering::Relaxed);
    }
    juntou
}

/// O teto das designações acabadas do processo `dono`
/// ([`ACABADOS_POR_PROCESSO`]): passado dele, a de menor chave — o fim
/// devido, ou o fim na espera, de um objeto que já acabou; os endpoints
/// antes das pontas e, entre as do mesmo tipo, a mais antiga — cai, contada
/// com as designações largadas. As dos objetos vivos ficam sempre: as cotas as
/// limitam.
fn conter_os_acabados(t: &mut BTreeMap<Objeto, Entrada>, dono: u64) {
    loop {
        let acabadas = || {
            t.iter()
                .filter(|(o, e)| o.dono(e.canal) == dono && e.d.guarda_o_fim())
                .map(|(o, _)| *o)
        };
        if acabadas().count() <= ACABADOS_POR_PROCESSO {
            return;
        }
        let Some(velha) = acabadas().next() else {
            return;
        };
        t.remove(&velha);
        LARGADOS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Publica o aviso `a` de `obj` no canal da designação, com a tabela das
/// designações na mão, e diz à conta o desfecho.
fn publicar(t: &mut BTreeMap<Objeto, Entrada>, obj: Objeto, a: Aviso, de_novo: bool) {
    let Some(x) = t.get_mut(&obj) else {
        return;
    };
    let e = evento_do_aviso(obj, a.bits);
    match crate::eventos::publicar_em_juntando(x.canal.chave, e, juntar_eventos) {
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
            // O aviso está no canal: a vaga que a marca guardava foi dita.
            // A recusa seguinte é a resposta a ele — ou uma operação que já
            // estava a caminho, e que o dono refaz ao lê-lo —, e espaça como
            // as outras: a mesma vaga não avisa duas vezes. Sob a trava em
            // que a recusa toma a marca: ou ela a toma antes, e o aviso que
            // ela refaz é o da vaga, ou a acha limpa. O canal cheio não a
            // tira — o aviso devido ainda não foi dito.
            x.vaga = false;
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

/// A passada do coletor de fios: as marcas que sobraram, os avisos que o
/// canal cheio deixou devidos, e o rearme dos objetos cujo aviso uma
/// operação recusada consumiu ([`recusada`]) — no prazo, tudo o que ainda
/// está pronto avisa. A marca de uma vaga fica: se o rearme publica, o
/// aviso dela sai, e [`publicar`] a tira; se não publica — o aviso de antes
/// ainda não foi consumido —, ela fica para a recusa que vier, que não
/// espaça, e o aviso da vaga sai logo depois dela.
pub fn passada_do_coletor() {
    if QUANTAS.load(Ordering::Acquire) == 0 {
        return;
    }
    processar();
    let agora = crate::tempo::uptime_ms();
    let rearmar: Vec<Objeto> = com_designacoes(|t| {
        let devidos: Vec<(Objeto, Aviso)> = t
            .iter_mut()
            .filter_map(|(obj, e)| e.d.retentar().map(|a| (*obj, a)))
            .collect();
        for (obj, a) in devidos {
            publicar(t, obj, a, true);
        }
        t.iter_mut()
            .filter(|(_, e)| e.rearmar_em != 0 && agora >= e.rearmar_em)
            .map(|(obj, e)| {
                e.rearmar_em = 0;
                e.recusado = 0;
                *obj
            })
            .collect()
    });
    // Fora da trava das designações: a conta pergunta o nível às tabelas.
    for obj in rearmar {
        avaliar(obj);
    }
}

/// O que se mede do aviso, para `security.metrics`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Medidas {
    /// As designações guardadas — também as dos objetos que já acabaram,
    /// com o fim ainda por dizer ou por ouvir.
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
    /// As designações que caíram porque o canal sumiu, ou porque passaram
    /// do teto das acabadas do processo.
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

/// Só para a suíte: se a designação de `obj` guarda o fim de um objeto que
/// já acabou — devido, ou na espera da operação do dono.
#[cfg(feature = "modo-teste")]
pub fn guarda_o_fim_de_teste(obj: Objeto) -> bool {
    com_designacoes(|t| t.get(&obj).is_some_and(|e| e.d.guarda_o_fim()))
}

/// Só para a suíte: no próximo fecho de um fluxo por um dono que tem a
/// designação da ponta, a conta da ponta é feita entre o fecho e o largar —
/// com ela ainda designada, como uma operação do par ou o coletor a fariam
/// nessa janela. Quem fechou já sabe do fim: a conta só tira a designação.
#[cfg(feature = "modo-teste")]
static CONTA_NO_FECHO: AtomicBool = AtomicBool::new(false);

/// Só para a suíte: arma a conta no próximo fecho ([`CONTA_NO_FECHO`]).
#[cfg(feature = "modo-teste")]
pub fn contar_no_proximo_fecho_de_teste() {
    CONTA_NO_FECHO.store(true, Ordering::Release);
}

/// O ponto da conta no fecho: quem fecha passa por aqui antes de largar.
#[cfg(feature = "modo-teste")]
pub fn antes_de_largar_no_fecho_de_teste(obj: Objeto) {
    if CONTA_NO_FECHO.swap(false, Ordering::AcqRel) {
        avaliar(obj);
    }
}

/// Só para a suíte: o processo cuja cota de fluxos ganha uma vaga no meio
/// da próxima operação recusada — entre a recusa e a conta dela, como um
/// fluxo dele que acabasse nessa janela —; zero, nenhum.
#[cfg(feature = "modo-teste")]
static VAGA_NA_RECUSA: AtomicU64 = AtomicU64::new(0);

/// Só para a suíte: arma a vaga no meio da próxima recusa
/// ([`VAGA_NA_RECUSA`]); zero desarma.
#[cfg(feature = "modo-teste")]
pub fn vaga_na_proxima_recusa_de_teste(fio: u64) {
    REARME_NA_RECUSA.store(false, Ordering::Release);
    VAGA_NA_RECUSA.store(fio, Ordering::Release);
}

/// Só para a suíte: com a vaga no meio da próxima recusa
/// ([`VAGA_NA_RECUSA`]), logo depois dela o rearme do objeto da recusa
/// vence, e o coletor passa — como o rearme da recusa anterior que caísse
/// nessa janela.
#[cfg(feature = "modo-teste")]
static REARME_NA_RECUSA: AtomicBool = AtomicBool::new(false);

/// Só para a suíte: arma a vaga e o rearme no meio da próxima recusa
/// ([`VAGA_NA_RECUSA`], [`REARME_NA_RECUSA`]); zero desarma.
#[cfg(feature = "modo-teste")]
pub fn vaga_e_rearme_na_proxima_recusa_de_teste(fio: u64) {
    REARME_NA_RECUSA.store(fio != 0, Ordering::Release);
    VAGA_NA_RECUSA.store(fio, Ordering::Release);
}

/// Só para a suíte: o rearme de `obj` vence agora — o coletor que passar
/// o acha no prazo, também se nenhum estava marcado.
#[cfg(feature = "modo-teste")]
fn vencer_o_rearme_de_teste(obj: Objeto) {
    com_designacoes(|t| {
        if let Some(e) = t.get_mut(&obj) {
            e.rearmar_em = 1;
        }
    });
}

/// Só para a suíte: o processo cuja próxima marca de vaga acha as marcas
/// cheias — como se outras [`MARCAS`] tivessem chegado antes dela, entre
/// duas passadas —, e é largada, com o transbordo de pé; zero, nenhum.
/// Encher as marcas de verdade, pela suíte, seria uma corrida com o
/// coletor, que as processa a cada tique.
#[cfg(feature = "modo-teste")]
static VAGA_TRANSBORDADA: AtomicU64 = AtomicU64::new(0);

/// Só para a suíte: arma o transbordo na próxima marca de vaga do processo
/// `fio` ([`VAGA_TRANSBORDADA`]); zero desarma.
#[cfg(feature = "modo-teste")]
pub fn transbordar_a_vaga_de_teste(fio: u64) {
    VAGA_TRANSBORDADA.store(fio, Ordering::Release);
}

/// Só para a suíte: depois de [`transbordar_a_vaga_de_teste`], se a marca
/// da vaga já foi largada no transbordo.
#[cfg(feature = "modo-teste")]
pub fn vaga_transbordou_de_teste() -> bool {
    VAGA_TRANSBORDADA.load(Ordering::Acquire) == 0
}

/// Só para a suíte, com a trava das marcas na mão: se `x` é a marca de
/// vaga que o transbordo armado larga ([`VAGA_TRANSBORDADA`]).
#[cfg(feature = "modo-teste")]
fn transbordada_de_teste(x: Tocado) -> bool {
    match x {
        Tocado::Vaga(fio) => {
            fio != 0
                && VAGA_TRANSBORDADA
                    .compare_exchange(fio, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
        }
        _ => false,
    }
}

/// Só para a suíte: na próxima operação recusada, os fluxos acabam
/// ([`crate::fluxo::vencer_de_teste`]) entre a pergunta do nível e a trava
/// das designações — como a inatividade, a revogação ou o fim do processo
/// do par acabariam o fluxo nessa janela.
#[cfg(feature = "modo-teste")]
static FIM_NA_RECUSA: AtomicBool = AtomicBool::new(false);

/// Só para a suíte: arma o fim no meio da próxima recusa
/// ([`FIM_NA_RECUSA`]).
#[cfg(feature = "modo-teste")]
pub fn acabar_na_proxima_recusa_de_teste() {
    FIM_NA_RECUSA.store(true, Ordering::Release);
}

/// Só para a suíte: na próxima operação do dono que passa, a conta de outro
/// núcleo chega logo depois dela — com o nível guardado aqui, perguntado
/// antes da operação, e a geração de antes dela. Zero desarma.
#[cfg(feature = "modo-teste")]
static NIVEL_VELHO: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Só para a suíte: arma a conta atrasada ([`NIVEL_VELHO`]) com o nível
/// `n`.
#[cfg(feature = "modo-teste")]
pub fn conta_atrasada_na_proxima_operacao_de_teste(n: u8) {
    NIVEL_VELHO.store(n, Ordering::Release);
}

/// Só para a suíte: a conta atrasada armada, com a geração de agora — a de
/// antes da operação que vai consumir o aviso.
#[cfg(feature = "modo-teste")]
fn conta_velha_de_teste(obj: Objeto) -> Option<(u8, u32)> {
    let n = NIVEL_VELHO.swap(0, Ordering::AcqRel);
    if n == 0 {
        return None;
    }
    com_designacoes(|t| t.get(&obj).map(|e| (n, e.d.geracao())))
}

/// Só para a suíte: desarma todos os pontos da suíte deste módulo — o caso
/// que falha antes de usar o seu não o deixa armado para o caso seguinte.
#[cfg(feature = "modo-teste")]
pub fn desarmar_de_teste() {
    VAGA_NA_RECUSA.store(0, Ordering::Release);
    REARME_NA_RECUSA.store(false, Ordering::Release);
    VAGA_TRANSBORDADA.store(0, Ordering::Release);
    FIM_NA_RECUSA.store(false, Ordering::Release);
    NIVEL_VELHO.store(0, Ordering::Release);
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
