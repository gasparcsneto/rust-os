//! Os casos `orcamento:` — o orçamento da vez da tarefa `programas`
//! (`nativo::servir_com`): cada vez tira da fila dos pedidos dos processos
//! no máximo o orçamento — os pedidos, ou o tempo —, executa de novo os
//! suspensos cuja espera acabou, e cede o executor.
//!
//! - **A ordem e a conta** ([`em_ordem`], [`o_que_morre_na_fila`],
//!   [`o_suspenso_vivo`]): pedidos de processos de verdade — o `anonimo`,
//!   que pede um `system.info` e sai —, postos na fila numa ordem
//!   conhecida, sem ninguém atender, e atendidos em vezes pequenas, com um
//!   chegando entre elas: cada um decidido uma vez, na ordem da fila, pela
//!   auditoria; o fio que morre com o pedido na fila entre duas vezes,
//!   largado sem chegar ao gate; e os suspensos de dois processos vivos,
//!   executados de novo na vez com a fila cheia, uma vez cada, na ordem.
//! - **O ceder** ([`sempre_cheia`], [`logo_depois`], [`o_suspenso`],
//!   [`estaciona_com_a_fila_vazia`]): o laço da tarefa num executor de
//!   teste, ao lado de uma vizinha. A vizinha repõe a fila a cada volta
//!   dela: a fila nunca esvazia, e a vizinha anda a cada vez da tarefa, que
//!   tira no máximo o orçamento. O pedido que chega logo depois da vez — no
//!   `seguir` do laço — fica para a vez seguinte, depois da vizinha. O
//!   suspenso pronto sai na vez seguinte, com a fila cheia. E, com a fila
//!   vazia, a tarefa estaciona — não volta à fila de prontas a cada volta
//!   da vizinha — até o pedido a acordar.
//! - **O tempo** ([`o_tempo`]): o vencido ainda atende um; zero vale um;
//!   sem tempo, a conta; a chamada da suíte, com o orçamento de produção; a
//!   unidade — nanossegundos, na régua de [`crate::metricas`]; e o tempo da
//!   vez inteira, e não o de cada pedido.
//! - **A carga de verdade** ([`o_laco_com_carga`], [`dois_titulares`],
//!   [`pela_taxa`]): o `incansavel` de uma pessoa no laço da tarefa, com a
//!   vizinha — nenhuma vez passa do orçamento —; o de duas pessoas ao mesmo
//!   tempo, em vezes de dois; e com a taxa apertada, em vezes de um. Cada filho confere o `id`
//!   de cada resposta e diz a conta; o caso a compara com a do kernel:
//!   nenhum pedido sem resposta, nenhum atendido duas vezes, e as recusas
//!   pela taxa — e a auditoria delas — como sem o orçamento.
//!
//! As filas falsas são de ids de fios que não existem: largados sem chegar
//! ao gate, e contados no orçamento da vez como qualquer outro — a régua
//! determinística do ceder.
//!
//! # O tamanho
//!
//! O kernel de teste de depuração do x86_64 mora perto do teto do
//! iniciador: as esperas são por `&dyn Fn`, numa instância só ([`ate`]).

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst};

use super::Resultado;
use crate::autorizacao::Autoridade;
use crate::nativo::{self, OrcamentoDaVez};
use crate::tarefas::Tarefa;
use crate::tarefas::executor::Executor;

// ---------------------------------------------------------------------------
// As esperas, o log e as contas
// ---------------------------------------------------------------------------

/// Dois pedidos por vez, sem tempo.
const DOIS: OrcamentoDaVez = OrcamentoDaVez {
    pedidos: 2,
    tempo_ns: u64::MAX,
};

/// Um pedido por vez, sem tempo.
const UM: OrcamentoDaVez = OrcamentoDaVez {
    pedidos: 1,
    tempo_ns: u64::MAX,
};

/// O maior número de pedidos que uma vez da espera atendeu — ver [`ate`].
static MAIOR_NA_ESPERA: AtomicUsize = AtomicUsize::new(0);

/// Espera `cond` por até `teto` tiques, cedendo a CPU a cada volta — o
/// processo pode estar neste núcleo —, e, com um `orcamento`, atendendo uma
/// vez dele por volta, como a suíte atende no lugar do executor; a maior
/// vez fica em [`MAIOR_NA_ESPERA`]. A condição é conferida de novo depois
/// da última vez.
fn ate(cond: &dyn Fn() -> bool, teto: u64, orcamento: Option<OrcamentoDaVez>) -> Resultado {
    let limite = crate::tempo::ticks().saturating_add(teto);
    loop {
        if cond() {
            return Ok(());
        }
        if crate::tempo::ticks() >= limite {
            return Err("a condicao do caso nao se cumpriu dentro do teto");
        }
        if let Some(o) = orcamento {
            MAIOR_NA_ESPERA.fetch_max(nativo::atender_com(o), SeqCst);
        }
        crate::fios::ceder();
    }
}

/// Quantas linhas de programa desde o registro `desde` dizem `procurada` —
/// no anel inteiro do log, de cento e vinte e oito.
fn linhas(desde: u64, procurada: &str) -> usize {
    let mut n = 0;
    crate::log::ultimos(128, crate::log::Level::Trace, |r| {
        n += usize::from(r.seq >= desde && r.subsistema == "usuario" && r.mensagem() == procurada);
    });
    n
}

/// Quantos processos saíram com `codigo` desde o registro `desde`.
fn saidas(desde: u64, codigo: i64) -> usize {
    linhas(
        desde,
        &alloc::format!("processo encerrou com codigo {codigo}"),
    )
}

/// O fio `fio` terminou e largou o núcleo, ou já saiu da tabela.
fn parado(fio: u64) -> bool {
    matches!(crate::fios::retrato_de_teste(fio), Some(r) if r.parado)
        || !crate::fios::na_tabela_de_teste(fio)
}

/// O começo de todo caso: a fila dos pedidos vazia, nenhum suspenso,
/// ninguém de fora do caso pedindo, e as contas zeradas.
///
/// Os casos conferem contas exatas — os pedidos atendidos, o que cada vez
/// tirou —, e um pedido de fora do caso as mudaria: um processo esquecido
/// por um caso anterior que ainda pede, ou o suspenso de um processo vivo,
/// que uma vez executaria quando a espera dele acabasse. O suspenso acaba
/// no prazo dele — de no máximo `rede::espera::PRAZO_MAXIMO_MS` —, e o
/// caso espera a lista esvaziar; depois, por dois tiques a fila tem de
/// continuar vazia, e uma vez não pode atender ninguém.
fn comecar() -> Resultado {
    nativo::esvaziar_de_teste();
    let hz = u64::from(crate::tempo::frequencia_hz());
    let prazo = crate::rede::espera::PRAZO_MAXIMO_MS.saturating_mul(hz) / 1_000 + 100;
    ate(&|| nativo::suspensos_de_teste() == 0, prazo, Some(UM))
        .map_err(|_| "um suspenso de fora do caso nao acabou no prazo dele")?;
    if nativo::pendentes_de_teste() != 0 {
        return Err("a fila dos pedidos nao esvaziou antes do caso");
    }
    let limite = crate::tempo::ticks().saturating_add(2);
    while crate::tempo::ticks() < limite {
        crate::fios::ceder();
    }
    if nativo::pendentes_de_teste() != 0 || nativo::atender_pendentes() != 0 {
        return Err("alguem de fora do caso pede durante o caso");
    }
    PAROU_NO_TETO.store(false, SeqCst);
    PARAR.store(false, SeqCst);
    VOLTAS.store(0, SeqCst);
    MAIOR.store(0, SeqCst);
    MENOR.store(usize::MAX, SeqCst);
    RESTO.store(usize::MAX, SeqCst);
    REPOSTOS.store(0, SeqCst);
    COM_SUSPENSO.store(false, SeqCst);
    FICOU.store(false, SeqCst);
    FALHOU.store(false, SeqCst);
    MAIOR_NA_ESPERA.store(0, SeqCst);
    Ok(())
}

// ---------------------------------------------------------------------------
// A ordem e a conta, com o `anonimo`
// ---------------------------------------------------------------------------

/// O código do `anonimo` (`programas/src/bin/anonimo.rs`): o `system.info`
/// que ele pede foi recusado pelo manifesto que ele não tem — a resposta
/// do pedido dele —, e o arquivo também. Um pedido só ao registro.
const DO_ANONIMO: i64 = 76;

/// Lança um `anonimo`, como o sistema, e espera o pedido dele chegar à fila
/// sem atendê-la: `na_fila` é quantos estão lá depois dele. O fio.
fn anonimo_na_fila(na_fila: usize) -> Result<u64, &'static str> {
    let programa = alloc::format!("{}/anonimo", crate::usuario::DIRETORIO_DOS_COMPILADOS);
    let fio = crate::usuario::lancar(Some(&programa))?;
    ate(&|| nativo::pendentes_de_teste() >= na_fila, 600, None)
        .map_err(|_| "o pedido do anonimo nao chegou a fila")?;
    if nativo::pendentes_de_teste() != na_fila {
        return Err("a fila tem um pedido que nao e do caso");
    }
    Ok(fio)
}

/// Uma vez de `pedidos`, sem tempo: `atendidos` chegam a um comando, e
/// `sobram` ficam na fila.
fn vez(pedidos: usize, atendidos: usize, sobram: usize) -> Resultado {
    let n = nativo::atender_com(OrcamentoDaVez {
        pedidos,
        tempo_ns: u64::MAX,
    });
    let fila = nativo::pendentes_de_teste();
    if n != atendidos || fila != sobram {
        crate::log_error!(
            "teste",
            "a vez de {} atendeu {} (esperado {}) e deixou {} na fila (esperado {})",
            pedidos,
            n,
            atendidos,
            fila,
            sobram
        );
        return Err("a vez nao atendeu o que o orcamento manda");
    }
    Ok(())
}

/// O pedido de cada fio de `fios` foi decidido uma vez depois do registro
/// `desde`, e na ordem de `fios`.
fn uma_vez_em_ordem(fios: &[u64], desde: u64) -> Resultado {
    let mut anterior = desde;
    for &fio in fios {
        let decididos: Vec<u64> = super::decisoes_do_processo(fio, "system.info", "")
            .iter()
            .map(|&(seq, _, _)| seq)
            .filter(|&seq| seq > desde)
            .collect();
        if decididos.len() != 1 {
            crate::log_error!("teste", "o fio {}: {} decisoes", fio, decididos.len());
            return Err("o pedido de um processo do caso nao foi decidido uma vez");
        }
        if decididos[0] <= anterior {
            return Err("os pedidos nao foram decididos na ordem da fila");
        }
        anterior = decididos[0];
    }
    Ok(())
}

/// A fila anda em ordem através das vezes: quatro pedidos postos numa
/// ordem conhecida — cada processo só é lançado com o pedido do anterior
/// já na fila —, atendidos em vezes de dois, com um quinto chegando entre a
/// primeira e a segunda. Cada vez atende o que o orçamento manda e deixa o
/// resto na fila, no lugar; cada pedido é decidido uma vez, na ordem da
/// fila — o quinto depois dos quatro —, e cada processo sai com a resposta
/// do pedido dele.
pub(super) fn em_ordem() -> Resultado {
    comecar()?;
    let desde_no_log = crate::log::total_emitidos();
    let desde = super::seq_da_auditoria();
    let (atendidos, _) = nativo::estatisticas();
    let r = (|| -> Resultado {
        let mut fios = Vec::new();
        for na_fila in 1..=4 {
            fios.push(anonimo_na_fila(na_fila)?);
        }
        vez(2, 2, 2)?;
        fios.push(anonimo_na_fila(3)?);
        vez(2, 2, 1)?;
        vez(2, 1, 0)?;
        ate(&|| saidas(desde_no_log, DO_ANONIMO) >= 5, 600, None)
            .map_err(|_| "um anonimo nao saiu com a resposta do pedido dele")?;
        uma_vez_em_ordem(&fios, desde)?;
        if nativo::estatisticas().0 - atendidos != 5 {
            return Err("os pedidos do caso nao foram atendidos uma vez cada");
        }
        Ok(())
    })();
    nativo::esvaziar_de_teste();
    r
}

/// O fio que morre com o pedido na fila entre duas vezes: três pedidos na
/// fila, e a primeira vez, de um, atende o primeiro. O segundo processo é
/// encerrado pelo `process.terminate`, pedido ao gate como o sistema, e
/// morre com o pedido na fila. A vez seguinte tira o id dele, que conta no orçamento, e o larga
/// sem chegar ao gate; a outra atende o terceiro. Nada do morto foi
/// decidido nem respondido, e os outros dois saem com a resposta deles, na
/// ordem.
pub(super) fn o_que_morre_na_fila() -> Resultado {
    comecar()?;
    let desde_no_log = crate::log::total_emitidos();
    let desde = super::seq_da_auditoria();
    let (atendidos, _) = nativo::estatisticas();
    let r = (|| -> Resultado {
        let primeiro = anonimo_na_fila(1)?;
        let morto = anonimo_na_fila(2)?;
        let terceiro = anonimo_na_fila(3)?;
        vez(1, 1, 2)?;
        // O término pelo gate, como o sistema: o `process.terminate` de
        // sempre.
        let r = super::fs_pedir(
            super::sistema_aqui(),
            "process.terminate",
            &alloc::format!(r#"{{"process":{morto}}}"#),
        );
        if !r.contains(r#""state":"terminating""#) {
            crate::log_error!("teste", "{}", r);
            return Err("o termino do processo com o pedido na fila foi recusado");
        }
        ate(&|| parado(morto), 600, None).map_err(|_| "o processo encerrado nao parou")?;
        if nativo::pendentes_de_teste() != 2 {
            return Err("o pedido do processo encerrado saiu da fila sem uma vez");
        }
        // Tirado e largado: a vez de um acaba nele, sem atender ninguém.
        vez(1, 0, 1)?;
        vez(1, 1, 0)?;
        ate(&|| saidas(desde_no_log, DO_ANONIMO) >= 2, 600, None)
            .map_err(|_| "um anonimo vivo nao saiu com a resposta do pedido dele")?;
        if !super::decisoes_do_processo(morto, "system.info", "").is_empty() {
            return Err("o pedido do processo que morreu na fila chegou ao gate");
        }
        uma_vez_em_ordem(&[primeiro, terceiro], desde)?;
        if nativo::estatisticas().0 - atendidos != 2 {
            return Err("o kernel respondeu ao processo que morreu na fila");
        }
        Ok(())
    })();
    nativo::esvaziar_de_teste();
    r
}

/// O suspenso de um processo vivo sai na vez, com a fila cheia, uma vez: o
/// pedido de dois `anonimo`, tomado da fila como a vez tomaria e guardado
/// como suspenso — o que uma vez faz quando o comando suspende —, com a
/// espera já acabada ([`espera_acabada`]); depois, cinco ids na fila. Uma
/// vez de dois tira dois ids e executa de novo os dois suspensos, na ordem
/// em que suspenderam: cada processo sai com a resposta do pedido dele, o
/// pedido de cada um é decidido uma vez, na ordem, e o kernel atendeu dois
/// — nem a vez seguinte, nem a chamada do caso, os executam de novo. Com a
/// fila cheia, o suspenso não espera a fila esvaziar.
pub(super) fn o_suspenso_vivo() -> Resultado {
    comecar()?;
    let desde_no_log = crate::log::total_emitidos();
    let desde = super::seq_da_auditoria();
    let (atendidos, _) = nativo::estatisticas();
    let antes = nativo::suspensos_de_teste();
    let r = (|| -> Resultado {
        let mut fios = Vec::new();
        for _ in 0..2 {
            let fio = anonimo_na_fila(1)?;
            let Some((id, pedido, _)) = nativo::tomar_de_teste() else {
                return Err("o pedido do anonimo nao foi tomado da fila");
            };
            if id != fio {
                return Err("a fila deu o pedido de outro fio");
            }
            let linha = core::str::from_utf8(pedido.como_bytes())
                .map_err(|_| "o pedido do anonimo nao e texto")?;
            let espera = espera_acabada().ok_or("a espera do suspenso nao acabou")?;
            nativo::suspender_de_teste(fio, linha, espera);
            fios.push(fio);
        }
        if nativo::suspensos_de_teste() != antes + 2 {
            return Err("os pedidos do caso nao ficaram suspensos");
        }
        if !repor(5) {
            return Err("a fila dos pedidos encheu");
        }
        let n = nativo::atender_com(DOIS);
        let (fila, suspensos) = (nativo::pendentes_de_teste(), nativo::suspensos_de_teste());
        if n != 2 || fila != 3 || suspensos != antes {
            crate::log_error!(
                "teste",
                "a vez de dois atendeu {} (esperado 2), deixou {} na fila (esperado 3) e {} suspensos (esperado {})",
                n,
                fila,
                suspensos,
                antes
            );
            return Err("a vez com a fila cheia nao executou de novo os suspensos prontos");
        }
        ate(&|| saidas(desde_no_log, DO_ANONIMO) >= 2, 600, None)
            .map_err(|_| "um anonimo suspenso nao saiu com a resposta do pedido dele")?;
        if nativo::atender_com(DOIS) != 0 {
            return Err("a vez seguinte atendeu de novo um suspenso ja executado");
        }
        uma_vez_em_ordem(&fios, desde)?;
        if nativo::estatisticas().0 - atendidos != 2 {
            return Err("os suspensos do caso nao foram atendidos uma vez cada");
        }
        Ok(())
    })();
    nativo::esvaziar_de_teste();
    r
}

// ---------------------------------------------------------------------------
// O ceder: o laço da tarefa num executor de teste
// ---------------------------------------------------------------------------

/// O primeiro id falso: nenhum fio chega perto.
const FALSO: u64 = u64::MAX - (1 << 32);

/// Quantos ids falsos já saíram — cada um é novo.
static FALSOS: AtomicU64 = AtomicU64::new(0);

/// O laço da tarefa num executor de teste para quando a vizinha acaba.
static PARAR: AtomicBool = AtomicBool::new(false);

/// As voltas da vizinha.
static VOLTAS: AtomicUsize = AtomicUsize::new(0);

/// O maior e o menor número de ids — ou de pedidos — que a tarefa tirou
/// entre duas voltas da vizinha, numa vez dela; e a menor ocupação da fila
/// que a vizinha viu.
static MAIOR: AtomicUsize = AtomicUsize::new(0);
static MENOR: AtomicUsize = AtomicUsize::new(usize::MAX);
static RESTO: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Os ids que o `seguir` do laço repôs — ver [`seguir_repondo`].
static REPOSTOS: AtomicUsize = AtomicUsize::new(0);

/// O caso pede à vizinha o suspenso pronto; ele ficou depois de uma vez da
/// tarefa; quantos havia antes dele.
static COM_SUSPENSO: AtomicBool = AtomicBool::new(false);
static FICOU: AtomicBool = AtomicBool::new(false);
static SUSPENSOS_ANTES: AtomicUsize = AtomicUsize::new(0);

/// A vizinha não conseguiu montar o caso: a fila encheu, ou a espera do
/// suspenso não acabou.
static FALHOU: AtomicBool = AtomicBool::new(false);

/// O pai da carga do laço: a vizinha para quando ele sai.
static PAI: AtomicU64 = AtomicU64::new(0);

/// A vizinha da carga parou no teto, e não porque o pai saiu: o laço da
/// tarefa não levou a carga até o fim.
static PAROU_NO_TETO: AtomicBool = AtomicBool::new(false);

/// Quantas voltas a vizinha dá.
const VOLTAS_DA_VIZINHA: usize = 12;

/// Quantos ids a vizinha repõe a cada volta: um a mais que o orçamento
/// [`DOIS`] — a fila cresce um por volta, e nunca esvazia.
const POR_VOLTA: usize = 3;

/// A volta em que a vizinha deixa o suspenso pronto, quando o caso pede.
const VOLTA_DO_SUSPENSO: usize = 4;

/// Até quantos ids o [`seguir_repondo`] repõe: muito mais que as voltas da
/// vizinha.
const REPOSICOES: usize = 64;

/// Um id de fio que não existe, novo a cada chamada.
fn falso() -> u64 {
    FALSO + FALSOS.fetch_add(1, SeqCst)
}

/// O `seguir` do laço: até a vizinha acabar.
fn seguir() -> bool {
    !PARAR.load(SeqCst)
}

/// Põe `n` ids falsos na fila, acordando a tarefa. Falso se ela encheu.
fn repor(n: usize) -> bool {
    (0..n).all(|_| nativo::enfileirar_e_acordar_de_teste(falso()))
}

/// O fim da vizinha: o laço para, e um id acorda a tarefa se ela espera a
/// fila — ela o tira, cede e vê o fim.
fn parar_o_laco() {
    PARAR.store(true, SeqCst);
    let _ = nativo::enfileirar_e_acordar_de_teste(falso());
}

/// Uma espera já acabada, para um suspenso de teste: a do caminho da
/// auditoria, que acaba quando ele tem lugar, ou no prazo, de um tique.
/// `None` se não acabou em cinco tiques.
fn espera_acabada() -> Option<crate::rede::espera::Espera> {
    use crate::autorizacao::Principal;
    use crate::rede::espera::Espera;
    let espera = Espera::pela_auditoria(Principal::Sistema, 10)?;
    let limite = crate::tempo::ticks().saturating_add(5);
    while espera.conferir(None).is_none() {
        if crate::tempo::ticks() >= limite {
            return None;
        }
        core::hint::spin_loop();
    }
    Some(espera)
}

/// Deixa com a tarefa um pedido suspenso de um fio que não existe, com a
/// espera já acabada ([`espera_acabada`]). Na vez seguinte, a tarefa o tira
/// da lista e o larga — não há a quem responder. Falso se a espera não
/// acabou.
fn suspender_pronto() -> bool {
    let Some(espera) = espera_acabada() else {
        return false;
    };
    SUSPENSOS_ANTES.store(nativo::suspensos_de_teste(), SeqCst);
    nativo::suspender_de_teste(falso(), "{}", espera);
    true
}

/// A vizinha: a cada volta, confere quantos ids a tarefa tirou da fila desde
/// a volta anterior — uma vez dela —, repõe [`POR_VOLTA`] e cede. Com
/// [`COM_SUSPENSO`], deixa com a tarefa o suspenso pronto na volta
/// [`VOLTA_DO_SUSPENSO`], e confere na seguinte que ele saiu.
async fn vizinha() {
    let mut posta: Option<usize> = None;
    for volta in 0..VOLTAS_DA_VIZINHA {
        let agora = nativo::pendentes_de_teste();
        if let Some(depois_de_por) = posta {
            let tirados = depois_de_por.saturating_sub(agora);
            MAIOR.fetch_max(tirados, SeqCst);
            MENOR.fetch_min(tirados, SeqCst);
            RESTO.fetch_min(agora, SeqCst);
        }
        if COM_SUSPENSO.load(SeqCst) {
            if volta == VOLTA_DO_SUSPENSO + 1
                && nativo::suspensos_de_teste() > SUSPENSOS_ANTES.load(SeqCst)
            {
                FICOU.store(true, SeqCst);
            }
            if volta == VOLTA_DO_SUSPENSO && !suspender_pronto() {
                FALHOU.store(true, SeqCst);
            }
        }
        if !repor(POR_VOLTA) {
            FALHOU.store(true, SeqCst);
            break;
        }
        posta = Some(nativo::pendentes_de_teste());
        VOLTAS.fetch_add(1, SeqCst);
        crate::tarefas::ceder().await;
    }
    parar_o_laco();
}

/// O laço da tarefa — o de produção, `nativo::servir_com` — num executor de
/// teste, com o orçamento [`DOIS`], ao lado da [`vizinha`]; e as contas
/// dela.
fn com_a_vizinha(com_suspenso: bool) -> Resultado {
    comecar()?;
    COM_SUSPENSO.store(com_suspenso, SeqCst);
    let mut executor = Executor::novo();
    executor.lancar(Tarefa::nova("vizinha", vizinha()));
    executor.lancar(Tarefa::nova(
        "programas de teste",
        nativo::servir_com(DOIS, seguir),
    ));
    let rodou = executor.rodar_ate_esvaziar(64);
    nativo::esvaziar_de_teste();
    rodou?;
    if FALHOU.load(SeqCst) || VOLTAS.load(SeqCst) != VOLTAS_DA_VIZINHA {
        return Err("a vizinha nao montou o caso");
    }
    let (maior, menor, resto) = (MAIOR.load(SeqCst), MENOR.load(SeqCst), RESTO.load(SeqCst));
    crate::log_info!(
        "teste",
        "orcamento: entre duas voltas da vizinha, a tarefa tirou de {} a {} ids, com ao menos {} na fila",
        menor,
        maior,
        resto
    );
    if resto == 0 {
        return Err("a vizinha so voltou com a fila vazia: a tarefa nao cedeu com pedidos na fila");
    }
    if maior > DOIS.pedidos {
        return Err("uma vez da tarefa tirou da fila mais que o orcamento");
    }
    if menor == 0 {
        return Err("a tarefa nao andou entre duas voltas da vizinha");
    }
    if FICOU.load(SeqCst) {
        return Err("o suspenso pronto ficou depois de uma vez da tarefa com a fila cheia");
    }
    Ok(())
}

/// Com a fila sempre cheia, a tarefa cede a cada vez: a vizinha repõe três
/// ids a cada volta — um a mais que o orçamento —, e a fila nunca esvazia.
/// Entre duas voltas dela a tarefa tirou um ou dois — andou, e não passou
/// do orçamento —, e a vizinha deu todas as voltas com a fila cheia. Sem o
/// ceder, ou sem o orçamento, a tarefa só devolve o executor com a fila
/// vazia.
pub(super) fn sempre_cheia() -> Resultado {
    com_a_vizinha(false)
}

/// O suspenso pronto sai na vez seguinte, com a fila cheia: na quinta
/// volta, a vizinha deixa com a tarefa um suspenso cuja espera já acabou;
/// na sexta — depois de uma vez da tarefa, com a fila sempre cheia —, ele
/// saiu. Os suspensos não passam fome atrás de uma fila que não esvazia.
pub(super) fn o_suspenso() -> Resultado {
    com_a_vizinha(true)
}

/// O `seguir` do laço que repõe: a cada volta do laço — logo depois de
/// cada cessão, antes de a tarefa olhar a fila —, se ela está vazia, um
/// pedido chega. Até [`REPOSICOES`].
fn seguir_repondo() -> bool {
    if PARAR.load(SeqCst) {
        return false;
    }
    if nativo::pendentes_de_teste() == 0 && REPOSTOS.load(SeqCst) < REPOSICOES {
        REPOSTOS.fetch_add(1, SeqCst);
        if !nativo::enfileirar_e_acordar_de_teste(falso()) {
            FALHOU.store(true, SeqCst);
        }
    }
    true
}

/// A vizinha que só olha: a cada volta, quantos pedidos chegaram pelo
/// [`seguir_repondo`] desde a volta anterior — um por vez da tarefa.
async fn vizinha_que_olha() {
    let mut antes = REPOSTOS.load(SeqCst);
    for _ in 0..VOLTAS_DA_VIZINHA {
        crate::tarefas::ceder().await;
        let agora = REPOSTOS.load(SeqCst);
        MAIOR.fetch_max(agora - antes, SeqCst);
        MENOR.fetch_min(agora - antes, SeqCst);
        antes = agora;
        VOLTAS.fetch_add(1, SeqCst);
    }
    parar_o_laco();
}

/// O pedido que chega logo depois da vez fica para a vez seguinte: a cada
/// volta do laço, o `seguir` põe um pedido na fila vazia — o que chega
/// enquanto a tarefa cede, ou logo depois de ela esvaziar a fila. A tarefa
/// atende um por vez, e entre duas voltas da vizinha chegou um, e só um. A
/// vez que esvaziou a fila e não cedesse — que só cedesse com o orçamento
/// acabado — emendaria noutra no pedido seguinte, e a vizinha veria todos
/// de uma vez.
pub(super) fn logo_depois() -> Resultado {
    comecar()?;
    let mut executor = Executor::novo();
    executor.lancar(Tarefa::nova("vizinha", vizinha_que_olha()));
    executor.lancar(Tarefa::nova(
        "programas de teste",
        nativo::servir_com(DOIS, seguir_repondo),
    ));
    let rodou = executor.rodar_ate_esvaziar(64);
    nativo::esvaziar_de_teste();
    rodou?;
    if FALHOU.load(SeqCst) || VOLTAS.load(SeqCst) != VOLTAS_DA_VIZINHA {
        return Err("a vizinha nao montou o caso");
    }
    let (maior, menor) = (MAIOR.load(SeqCst), MENOR.load(SeqCst));
    if maior > 1 {
        crate::log_error!("teste", "{} pedidos entre duas voltas da vizinha", maior);
        return Err("a vez emendou na seguinte com o pedido que chegou logo depois dela");
    }
    if menor == 0 {
        return Err("a tarefa nao andou entre duas voltas da vizinha");
    }
    Ok(())
}

/// A vizinha que só cede: [`VOLTAS_DA_VIZINHA`] voltas sem pôr nada na
/// fila, e o fim do laço.
async fn vizinha_que_cede() {
    for _ in 0..VOLTAS_DA_VIZINHA {
        VOLTAS.fetch_add(1, SeqCst);
        crate::tarefas::ceder().await;
    }
    parar_o_laco();
}

/// Com a fila vazia, a tarefa estaciona — no `ProximoPedido`, sem se
/// acordar — e o pedido a acorda: o laço de produção ao lado de uma vizinha
/// que só cede. Pelos avanços do executor: a vizinha anda uma vez por volta
/// e mais a que acaba; a tarefa, três — a que estaciona, a que o id do fim
/// acorda (ela o tira e cede) e a que sai. Uma tarefa que não estacionasse
/// voltaria à fila de prontas a cada volta da vizinha, presa no mesmo
/// `.await`: na produção, o núcleo do executor ocupado com a máquina
/// ociosa. E sem o despertar, o id do fim ficaria na fila, e o laço não
/// acabaria.
pub(super) fn estaciona_com_a_fila_vazia() -> Resultado {
    comecar()?;
    let antes = crate::tarefas::executor::estatisticas().avancos;
    let mut executor = Executor::novo();
    executor.lancar(Tarefa::nova("vizinha", vizinha_que_cede()));
    executor.lancar(Tarefa::nova(
        "programas de teste",
        nativo::servir_com(DOIS, seguir),
    ));
    let rodou = executor.rodar_ate_esvaziar(64);
    let avancos = crate::tarefas::executor::estatisticas()
        .avancos
        .saturating_sub(antes);
    let sobrou = nativo::pendentes_de_teste();
    nativo::esvaziar_de_teste();
    rodou?;
    if VOLTAS.load(SeqCst) != VOLTAS_DA_VIZINHA {
        return Err("a vizinha nao deu todas as voltas");
    }
    if sobrou != 0 {
        return Err("o id do fim nao acordou a tarefa estacionada");
    }
    // A vizinha, uma por volta e a que acaba; a tarefa, três; e dois de
    // folga, para um despertar sem pedido. A que não estaciona anda uma vez
    // a mais por volta da vizinha.
    let teto = VOLTAS_DA_VIZINHA as u64 + 1 + 3 + 2;
    crate::log_info!(
        "teste",
        "orcamento: com a fila vazia, {} avancos do executor (teto {})",
        avancos,
        teto
    );
    if avancos > teto {
        return Err(
            "com a fila vazia, a tarefa nao estacionou: voltou a fila de prontas a cada volta",
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// O tempo
// ---------------------------------------------------------------------------

/// A régua do tempo da vez: três tiques — de vinte a trinta milissegundos
/// —, medidos por [`crate::metricas`]; e o tempo da vez que começou antes
/// deles vence com quatro quintos do que ela mediu, e não com cinco
/// quartos. As contas correm sem as interrupções; se a máquina parou entre
/// elas — o hospedeiro tirou o núcleo do QEMU —, mede de novo, até três
/// vezes.
fn a_regua_do_tempo() -> Resultado {
    let vence = |inicio: u64, tempo_ns: u64| {
        OrcamentoDaVez {
            pedidos: 1,
            tempo_ns,
        }
        .venceu_de_teste(inicio)
    };
    for _ in 0..3 {
        let inicio = crate::arch::ciclos();
        let limite = crate::tempo::ticks().saturating_add(3);
        while crate::tempo::ticks() < limite {
            crate::fios::ceder();
        }
        let (passou, cedo, tarde, depois) = crate::arch::sem_interrupcoes(|| {
            let passou = crate::metricas::nanos(crate::metricas::desde(inicio));
            let tarde = vence(inicio, passou / 4 * 5);
            let cedo = vence(inicio, passou / 5 * 4);
            let depois = crate::metricas::nanos(crate::metricas::desde(inicio));
            (passou, cedo, tarde, depois)
        });
        if !(10_000_000..=2_000_000_000).contains(&passou) {
            crate::log_error!("teste", "tres tiques mediram {} ns", passou);
            return Err("a regua do tempo da vez nao mede tres tiques");
        }
        if depois >= passou / 4 * 5 {
            continue;
        }
        if !cedo || tarde {
            return Err("o tempo da vez nao vence na regua de crate::metricas");
        }
        return Ok(());
    }
    Err("a maquina parou em toda medida do tempo da vez")
}

/// O tempo e a conta da vez: com o tempo já vencido, a vez ainda atende um
/// — toda vez anda, e o tempo nunca é conferido antes do primeiro —; zero
/// pedidos vale um; sem tempo, a conta manda; e a chamada da suíte
/// (`atender_pendentes`) é uma vez do orçamento de produção — ao menos um, e
/// no máximo `nativo::PEDIDOS_POR_VEZ`.
///
/// E a unidade do tempo: o orçamento de produção está em nanossegundos;
/// o tempo da vez vence na régua de [`crate::metricas`] — depois de três
/// tiques, o tempo que ela mediu vence com quatro quintos dele, e não com
/// cinco quartos —; e cinquenta milissegundos bastam a oito ids falsos,
/// que custam microssegundos. Um orçamento lido em ciclos, ou em
/// microssegundos, não passa. E o tempo é o da vez inteira, desde o
/// primeiro id, e não o de cada pedido ([`o_tempo_da_vez_inteira`]).
pub(super) fn o_tempo() -> Resultado {
    comecar()?;
    let r = (|| -> Resultado {
        let tirados = |orcamento: OrcamentoDaVez| -> usize {
            let antes = nativo::pendentes_de_teste();
            nativo::atender_com(orcamento);
            antes.saturating_sub(nativo::pendentes_de_teste())
        };
        if nativo::ORCAMENTO_DA_VEZ.tempo_ns != nativo::TEMPO_POR_VEZ_US.saturating_mul(1_000) {
            return Err("o tempo da vez de producao nao esta em nanossegundos");
        }
        a_regua_do_tempo()?;
        let por_vez = nativo::PEDIDOS_POR_VEZ;
        if !repor(por_vez.saturating_add(16).min(150)) {
            return Err("a fila dos pedidos encheu");
        }
        let vencido = OrcamentoDaVez {
            pedidos: 8,
            tempo_ns: 0,
        };
        if tirados(vencido) != 1 {
            return Err("com o tempo vencido, a vez nao atendeu exatamente um");
        }
        let zero = OrcamentoDaVez {
            pedidos: 0,
            tempo_ns: u64::MAX,
        };
        if tirados(zero) != 1 {
            return Err("um orcamento de zero pedidos nao atendeu um");
        }
        let tres = OrcamentoDaVez {
            pedidos: 3,
            tempo_ns: u64::MAX,
        };
        if tirados(tres) != 3 {
            return Err("sem tempo, a vez nao atendeu a conta do orcamento");
        }
        // Sem as interrupções, nenhuma outra tarefa toma o núcleo no meio.
        let cinquenta = OrcamentoDaVez {
            pedidos: 8,
            tempo_ns: 50_000_000,
        };
        if crate::arch::sem_interrupcoes(|| tirados(cinquenta)) != 8 {
            return Err("cinquenta milissegundos nao bastaram a oito ids falsos");
        }
        let antes = nativo::pendentes_de_teste();
        nativo::atender_pendentes();
        let n = antes.saturating_sub(nativo::pendentes_de_teste());
        if n == 0 || n > por_vez {
            crate::log_error!(
                "teste",
                "a chamada da suite tirou {} de {}, com o orcamento de {}",
                n,
                antes,
                por_vez
            );
            return Err("a chamada da suite nao e uma vez do orcamento de producao");
        }
        o_tempo_da_vez_inteira(&tirados)
    })();
    nativo::esvaziar_de_teste();
    r
}

/// Quantos ids falsos a vez do [`o_tempo_da_vez_inteira`] tem na fila — bem
/// menos que a capacidade dela.
const SOMADOS: usize = 64;

/// O tempo é o da vez inteira, e não o de cada pedido: sem tempo,
/// [`SOMADOS`] ids falsos custam `inteira` — o menor de três —, e a vez com
/// um quarto disso corta antes do fim. Um tempo contado de novo a cada
/// pedido nunca venceria: cada id custa uma fração de `inteira`. Sem as
/// interrupções; e até três tentativas, contra o hospedeiro que tira o
/// núcleo do QEMU no meio de uma medida.
fn o_tempo_da_vez_inteira(tirados: &dyn Fn(OrcamentoDaVez) -> usize) -> Resultado {
    let sem_tempo = OrcamentoDaVez {
        pedidos: SOMADOS,
        tempo_ns: u64::MAX,
    };
    for _ in 0..3 {
        nativo::esvaziar_de_teste();
        let mut inteira = u64::MAX;
        for _ in 0..3 {
            if !repor(SOMADOS) {
                return Err("a fila dos pedidos encheu");
            }
            let (n, custo) = crate::arch::sem_interrupcoes(|| {
                let inicio = crate::arch::ciclos();
                let n = tirados(sem_tempo);
                (n, crate::metricas::nanos(crate::metricas::desde(inicio)))
            });
            if n != SOMADOS {
                return Err("sem tempo, a vez nao tirou todos os ids falsos");
            }
            inteira = inteira.min(custo);
        }
        if !repor(SOMADOS) {
            return Err("a fila dos pedidos encheu");
        }
        let quarto = OrcamentoDaVez {
            pedidos: SOMADOS,
            tempo_ns: inteira / 4,
        };
        let n = crate::arch::sem_interrupcoes(|| tirados(quarto));
        if n < SOMADOS {
            crate::log_info!(
                "teste",
                "orcamento: {} ids falsos em {} ns; com um quarto disso, a vez tirou {}",
                SOMADOS,
                inteira,
                n
            );
            return Ok(());
        }
    }
    Err("o tempo da vez nao e o da vez inteira: com um quarto do tempo dos ids, ela tirou todos")
}

// ---------------------------------------------------------------------------
// A carga de verdade, com o `incansavel`
// ---------------------------------------------------------------------------

/// O pedido do `incansavel`, no armazém — ver
/// `programas/src/bin/incansavel.rs`.
const PEDIDO: &str = "/armazem/compartilhado/incansavel";

/// O código do pai do `incansavel` com todos os filhos acabados, e o de
/// cada filho.
const DO_PAI: i64 = 80;
const DO_FILHO: i64 = 60;

/// O teto de uma carga, em tiques: um segundo de pedidos, e o resto é a
/// máquina mais lenta da matriz.
const TETO_DA_CARGA: u64 = 3_000;

/// O fio que grava e apaga o pedido, como o sistema.
const QUEM_GRAVA: u64 = 7_199_998;

/// Grava o pedido do `incansavel`, como o sistema: `filhos` por pai, por um
/// segundo — o menor —, pedindo.
fn gravar_o_pedido(filhos: u64) -> Resultado {
    super::diretorios_acima(PEDIDO)?;
    let versao = super::versao_no_armazem(PEDIDO);
    let r = super::fs_pedir(
        super::sistema_no_armazem(QUEM_GRAVA),
        "fs.write",
        &alloc::format!(
            r#"{{"path":"{PEDIDO}","content":"processos {filhos}\nduracao_ms 1000\nmodo pedir\n","expect_version":{versao}}}"#
        ),
    );
    if !super::fs_ok(&r) {
        crate::log_error!("teste", "{}", r);
        return Err("o pedido do incansavel nao foi gravado");
    }
    Ok(())
}

/// Apaga o pedido do `incansavel`: o armazém volta a ser o de antes.
fn apagar_o_pedido() {
    let versao = super::versao_no_armazem(PEDIDO);
    if versao > 0 {
        let _ = super::fs_pedir(
            super::sistema_no_armazem(QUEM_GRAVA),
            "fs.delete",
            &alloc::format!(r#"{{"path":"{PEDIDO}","expect_version":{versao}}}"#),
        );
    }
}

/// Uma pessoa operadora numa sessão aberta agora, no Terminal `console`: um
/// titular da carga, com a cota e o balde da taxa dele.
fn titular(console: u16, nome: &str) -> Autoridade {
    let sessao = crate::pessoas::sessao_de_teste(
        crate::pessoas::Console::Terminal(console),
        nome,
        "operador",
    );
    Autoridade::Pessoa { sessao }
}

/// Lança o `incansavel` como `titular`: o fio do pai.
fn lancar_a_carga(titular: Autoridade) -> Result<u64, &'static str> {
    let programa = alloc::format!("{}/incansavel", crate::usuario::DIRETORIO_DOS_COMPILADOS);
    crate::usuario::lancar_como(Some(&programa), titular)
}

/// As contas do kernel no começo de uma carga.
#[derive(Clone, Copy)]
struct Antes {
    log: u64,
    atendidos: u64,
    invalidos: u64,
    pela_taxa: u64,
}

impl Antes {
    fn agora() -> Antes {
        let (atendidos, invalidos) = nativo::estatisticas();
        Antes {
            log: crate::log::total_emitidos(),
            atendidos,
            invalidos,
            pela_taxa: crate::metricas::decisoes_de(politica::Codigo::RateLimit),
        }
    }
}

/// O que um filho do `incansavel` disse no fim.
#[derive(Clone, Copy, Debug, Default)]
struct Conta {
    pedidos: u64,
    respostas: u64,
    permitidos: u64,
    pela_taxa: u64,
}

/// O fio e a conta de uma linha de programa, se é a do fim de um filho do
/// `incansavel`: `incansavel <fio>: <p> pedidos, <q> respostas, <a> ALLOW,
/// <r> RATE_LIMIT, de <x> a <y> ms`.
fn conta_da_linha(linha: &str) -> Option<(u64, Conta)> {
    let (fio, contas) = linha.strip_prefix("incansavel ")?.split_once(": ")?;
    let fio = fio.parse().ok()?;
    let mut c = Conta::default();
    let mut vistos = 0;
    for parte in contas.split(", ") {
        let Some((n, nome)) = parte.split_once(' ') else {
            continue;
        };
        let Ok(n) = n.parse::<u64>() else {
            continue;
        };
        let campo = match nome {
            "pedidos" => &mut c.pedidos,
            "respostas" => &mut c.respostas,
            "ALLOW" => &mut c.permitidos,
            "RATE_LIMIT" => &mut c.pela_taxa,
            _ => continue,
        };
        *campo = n;
        vistos += 1;
    }
    (vistos == 4).then_some((fio, c))
}

/// As contas dos filhos do `incansavel` desde o registro `desde`, no anel
/// inteiro do log.
fn contas_dos_filhos(desde: u64) -> Vec<(u64, Conta)> {
    let mut contas = Vec::new();
    crate::log::ultimos(128, crate::log::Level::Trace, |r| {
        if r.seq >= desde
            && r.subsistema == "usuario"
            && let Some(conta) = conta_da_linha(r.mensagem())
        {
            contas.push(conta);
        }
    });
    contas
}

/// Confere uma carga que acabou: `pais` pais, de `filhos` filhos cada.
/// Todo filho disse a conta e saiu com [`DO_FILHO`] — cada resposta era a
/// do pedido dele: ele confere o `id`, e sai com outro código na primeira
/// de outro —, e todo pedido teve uma resposta, ALLOW ou RATE_LIMIT. O
/// kernel atendeu exatamente os pedidos dos filhos e o relógio de cada pai
/// — nem um a menos, que seria perdido, nem um a mais, que seria atendido
/// duas vezes —, sem nenhum inválido, e recusou pela taxa exatamente o que
/// os filhos ouviram. Devolve as contas.
fn conferir_a_carga(
    antes: Antes,
    pais: u64,
    filhos: u64,
) -> Result<Vec<(u64, Conta)>, &'static str> {
    if saidas(antes.log, DO_PAI) != pais as usize
        || saidas(antes.log, DO_FILHO) != (pais * filhos) as usize
    {
        return Err("um processo da carga nao saiu com o codigo dele");
    }
    let contas = contas_dos_filhos(antes.log);
    if contas.len() as u64 != pais * filhos {
        return Err("nem todo filho do incansavel disse a conta");
    }
    let (mut pedidos, mut pela_taxa) = (0, 0);
    for (fio, c) in &contas {
        if c.pedidos == 0 || c.respostas != c.pedidos || c.permitidos + c.pela_taxa != c.respostas {
            crate::log_error!("teste", "o filho {}: {:?}", fio, c);
            return Err("um filho do incansavel nao recebeu uma resposta por pedido");
        }
        pedidos += c.pedidos;
        pela_taxa += c.pela_taxa;
    }
    let (atendidos, invalidos) = nativo::estatisticas();
    let atendidos = atendidos - antes.atendidos;
    let recusados = crate::metricas::decisoes_de(politica::Codigo::RateLimit) - antes.pela_taxa;
    if atendidos != pedidos + pais || invalidos != antes.invalidos || recusados != pela_taxa {
        crate::log_error!(
            "teste",
            "o kernel atendeu {} e recusou pela taxa {}; os filhos fizeram {} e ouviram {} recusas, e os pais pediram {}",
            atendidos,
            recusados,
            pedidos,
            pela_taxa,
            pais
        );
        return Err("o kernel atendeu outra conta que a dos processos: pedido perdido ou repetido");
    }
    Ok(contas)
}

/// A vizinha da carga: a cada volta, quantos pedidos a tarefa atendeu desde
/// a anterior — numa vez dela —; para quando o pai da carga sai, ou no
/// teto.
async fn vizinha_da_carga() {
    let limite = crate::tempo::ticks().saturating_add(TETO_DA_CARGA);
    let mut antes = nativo::estatisticas().0;
    loop {
        crate::tarefas::ceder().await;
        let agora = nativo::estatisticas().0;
        MAIOR.fetch_max((agora - antes) as usize, SeqCst);
        antes = agora;
        let voltas = VOLTAS.fetch_add(1, SeqCst) + 1;
        // O pai, de tempos em tempos: a tabela de fios tem trava.
        if voltas.is_multiple_of(64) && parado(PAI.load(SeqCst)) {
            break;
        }
        if crate::tempo::ticks() >= limite {
            PAROU_NO_TETO.store(true, SeqCst);
            break;
        }
    }
    parar_o_laco();
}

/// O laço da tarefa com os processos de um titular pedindo: o `incansavel`
/// de uma pessoa — dois filhos pedindo sem parar, noutros núcleos — e a
/// tarefa num executor de teste, em vezes de um, ao lado de uma vizinha que
/// cede a cada volta. Entre duas voltas da vizinha a tarefa atendeu no
/// máximo um pedido — uma vez dela, mesmo com os dois filhos na fila —, e a
/// carga acaba conferida: cada filho com a resposta de cada pedido dele, e
/// o kernel com a conta deles.
pub(super) fn o_laco_com_carga() -> Resultado {
    comecar()?;
    crate::pessoas::esquecer_registradas();
    let r = (|| -> Resultado {
        gravar_o_pedido(2)?;
        let dona = titular(61, "orcamento-laco");
        let antes = Antes::agora();
        PAI.store(lancar_a_carga(dona)?, SeqCst);
        let mut executor = Executor::novo();
        executor.lancar(Tarefa::nova("vizinha", vizinha_da_carga()));
        executor.lancar(Tarefa::nova(
            "programas de teste",
            nativo::servir_com(UM, seguir),
        ));
        let rodou = executor.rodar_ate_esvaziar(64);
        // Se a vizinha parou no teto, a suíte atende o resto.
        ate(
            &|| saidas(antes.log, DO_PAI) >= 1,
            TETO_DA_CARGA,
            Some(nativo::ORCAMENTO_DA_VEZ),
        )
        .map_err(|_| "a carga do laco nao acabou")?;
        rodou?;
        if PAROU_NO_TETO.load(SeqCst) {
            return Err("a tarefa do laco nao levou a carga ate o fim");
        }
        let maior = MAIOR.load(SeqCst);
        crate::log_info!(
            "teste",
            "orcamento: {} voltas da vizinha, no maximo {} pedido entre duas",
            VOLTAS.load(SeqCst),
            maior
        );
        if maior > UM.pedidos {
            return Err("entre duas voltas da vizinha a tarefa atendeu mais que o orcamento");
        }
        conferir_a_carga(antes, 1, 2)?;
        Ok(())
    })();
    nativo::esvaziar_de_teste();
    apagar_o_pedido();
    crate::pessoas::esquecer_registradas();
    r
}

/// Os processos de dois titulares pedem ao mesmo tempo: duas pessoas, cada
/// uma com o `incansavel` de dois filhos, e a suíte atendendo em vezes de
/// dois — menos que os pedidos dos dois titulares juntos na fila, e a vez
/// corta no meio deles. Nenhum pedido sem resposta, nenhum atendido duas
/// vezes, nenhuma resposta trocada — cada filho confere o `id` de cada
/// resposta —, e nenhuma vez passou do orçamento.
pub(super) fn dois_titulares() -> Resultado {
    comecar()?;
    crate::pessoas::esquecer_registradas();
    let r = (|| -> Resultado {
        gravar_o_pedido(2)?;
        let ana = titular(62, "orcamento-ana");
        let bia = titular(63, "orcamento-bia");
        let antes = Antes::agora();
        lancar_a_carga(ana)?;
        lancar_a_carga(bia)?;
        ate(
            &|| saidas(antes.log, DO_PAI) >= 2,
            TETO_DA_CARGA,
            Some(DOIS),
        )
        .map_err(|_| "a carga dos dois titulares nao acabou")?;
        if MAIOR_NA_ESPERA.load(SeqCst) > DOIS.pedidos {
            return Err("uma vez de dois pedidos atendeu mais de dois");
        }
        conferir_a_carga(antes, 2, 2)?;
        Ok(())
    })();
    nativo::esvaziar_de_teste();
    apagar_o_pedido();
    crate::pessoas::esquecer_registradas();
    r
}

/// O que a auditoria diz das recusas pela taxa dos processos `fios` depois
/// do registro `desde`: a primeira recusa de cada série vale uma, e o
/// registro da soma — gravado quando um pedido passa de novo — vale a série
/// inteira, a primeira com ela. A série de uma recusa só tem a primeira.
fn recusas_na_auditoria(fios: &[u64], desde: u64) -> u64 {
    let prefixos: Vec<String> = fios
        .iter()
        .map(|fio| alloc::format!("pelo processo {fio} ("))
        .collect();
    crate::autorizacao::com_auditoria(|c| {
        let (mut primeiras, mut somas, mut somadas) = (0u64, 0u64, 0u64);
        for r in c.ultimos(crate::autorizacao::CAPACIDADE_DA_AUDITORIA) {
            let e = &r.evento;
            if r.seq <= desde
                || e.codigo != politica::Codigo::RateLimit
                || !prefixos.iter().any(|p| e.detalhe.starts_with(p.as_str()))
            {
                continue;
            }
            if e.detalhe.ends_with("taxa do papel esgotada") {
                primeiras += 1;
            } else if let Some(n) = e
                .detalhe
                .strip_suffix(" pedidos recusados por taxa")
                .and_then(|d| d.rsplit(' ').next())
                .and_then(|n| n.parse::<u64>().ok())
            {
                somas += 1;
                somadas += n;
            }
        }
        somadas + primeiras.saturating_sub(somas)
    })
    .unwrap_or(0)
}

/// As recusas pela taxa, sob o orçamento: com a taxa do operador apertada
/// — duas fichas por segundo —, quase todo pedido da carga ouve
/// `RATE_LIMIT`, e a suíte atende em vezes de um. Nenhuma vez passa de um —
/// a recusa conta no orçamento como um pedido atendido —; a conta fecha
/// como sem o orçamento; e a auditoria das recusas também: a primeira de
/// cada série gravada, as outras somadas num registro quando um pedido
/// passa, e a soma é o que os filhos ouviram.
pub(super) fn pela_taxa() -> Resultado {
    comecar()?;
    let texto = politica::PADRAO.replace("taxa operador 50 100", "taxa operador 2 2");
    if texto == politica::PADRAO {
        return Err("a politica padrao nao tem a taxa do operador");
    }
    let apertada = politica::Politica::ler(&texto).map_err(|_| "a politica do caso nao vale")?;
    crate::pessoas::esquecer_registradas();
    let r = super::com_a_politica(apertada, || -> Resultado {
        gravar_o_pedido(2)?;
        let dona = titular(64, "orcamento-taxa");
        let antes = Antes::agora();
        let desde = super::seq_da_auditoria();
        let pai = lancar_a_carga(dona)?;
        ate(&|| saidas(antes.log, DO_PAI) >= 1, TETO_DA_CARGA, Some(UM))
            .map_err(|_| "a carga com a taxa apertada nao acabou")?;
        if MAIOR_NA_ESPERA.load(SeqCst) > UM.pedidos {
            return Err("uma vez de um pedido atendeu mais de um");
        }
        let contas = conferir_a_carga(antes, 1, 2)?;
        let ouvidas: u64 = contas.iter().map(|(_, c)| c.pela_taxa).sum();
        if ouvidas == 0 {
            return Err("a taxa apertada nao recusou nenhum pedido da carga");
        }
        let mut fios: Vec<u64> = contas.iter().map(|&(fio, _)| fio).collect();
        fios.push(pai);
        let gravadas = recusas_na_auditoria(&fios, desde);
        if gravadas != ouvidas {
            crate::log_error!(
                "teste",
                "a auditoria soma {} recusas pela taxa, e os filhos ouviram {}",
                gravadas,
                ouvidas
            );
            return Err("a auditoria das recusas pela taxa nao soma o que os filhos ouviram");
        }
        Ok(())
    });
    nativo::esvaziar_de_teste();
    apagar_o_pedido();
    crate::pessoas::esquecer_registradas();
    r
}
