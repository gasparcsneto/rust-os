//! Os casos `adocao:` — a reconstrução da auditoria no boot: a cadeia que o
//! journal refaz, e a do boot continuada nela, com a trava da auditoria
//! (ver `autorizacao::adotar_auditoria` e "A reconstrução da auditoria no
//! boot (B4)", em `docs/PERSISTENCIA.md`).
//!
//! A reabertura da suíte (`com_a_persistencia_fechada`) é o caminho do boot
//! inteiro: o journal lido e reposto, a âncora conferida, a adoção, o
//! registro de boot. Os casos conferem, sem medir tempo — os limites só
//! livram um fio preso, e a rajada que não chega à adoção reprova —:
//!
//! - que a cadeia adotada é a que a conta de antes daria — a do journal,
//!   refeita por `repor` e `pular` direto do disco, continuada por
//!   `continuar_com` com os eventos que a cadeia do boot tinha logo antes
//!   da adoção —, registro a registro, com o anel do journal pela metade,
//!   com o anel do journal cheio, depois de uma compactação, com uma
//!   lacuna, com o boot de um registro e o boot com o anel cheio, e no boot
//!   seguinte; e que a adotada do journal vazio do primeiro boot da suíte
//!   começa na gênese, no registro 1, se verifica e é a que o journal tem;
//!   que os setores que o journal tinha antes do boot continuam os mesmos,
//!   byte a byte, e o que o boot gravou é a cadeia continuada;
//! - que nada se pede nem se devolve ao alocador com a trava da auditoria
//!   na mão durante a adoção, nem com a da cadeia refeita durante a
//!   reposição — com o anel do journal cheio, a lacuna que o esvazia e o
//!   anel do boot cheio —, pela conta do próprio alocador, com os controles
//!   positivos das duas travas;
//! - que o registro do boot que alguém segura — um ponteiro forte ou uma
//!   referência fraca — não muda, e o da cadeia adotada é uma cópia;
//! - que a gravada troca com a cadeia: o `audit.head` e o `audit.tail`
//!   logo antes da adoção mostram a cadeia do boot com a gravada de antes,
//!   e nunca com a do journal; e logo depois, a adotada com a do journal,
//!   e nunca com a de antes;
//! - e que produtores em outros núcleos durante a reabertura — em rajada,
//!   disputando a trava, na hora da adoção — não perdem, não repetem e não
//!   desordenam nada — conferido pelo journal —, e um leitor noutro núcleo
//!   nunca vê a cadeia que não se verifica, a esvaziada, a que muda sem
//!   andar, nem a gravada adiante dela.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};

use super::{
    Resultado, a_cadeia_do_journal_confere, chamar, com_a_persistencia_fechada,
    nucleos_secundarios, todos_do_journal,
};
use crate::agent::json::Json;
use crate::autorizacao::alocacoes_sob_a_auditoria_de_teste as alocacoes;
use crate::persistencia::{self, AuditoriaNoJournal};
use politica::auditoria::{Cadeia, Evento};

/// A capacidade do anel da auditoria.
const CAPACIDADE: usize = crate::autorizacao::CAPACIDADE_DA_AUDITORIA;

/// Um registro do kernel na auditoria; o número dele.
fn auditar(metodo: &str, detalhe: &str) -> u64 {
    crate::autorizacao::auditar_do_kernel(metodo, "", politica::Codigo::Allow, detalhe)
}

/// O anel da auditoria cheio, e tudo gravado.
fn anel_cheio_e_gravado() -> Resultado {
    for i in 0..CAPACIDADE {
        auditar("teste.adocao.enche", &alloc::format!("{i}"));
    }
    gravar_tudo()
}

/// Grava a auditoria até a gravada alcançar a última sequência.
fn gravar_tudo() -> Resultado {
    for _ in 0..64 {
        let ultima = crate::autorizacao::com_auditoria(|c| c.ultima_seq()).unwrap_or(0);
        if persistencia::auditoria_gravada() >= ultima {
            return Ok(());
        }
        persistencia::gravar_auditoria()?;
    }
    Err("a auditoria nao chegou inteira ao journal")
}

// ---------------------------------------------------------------------------
// A reabertura, com o que a cadeia do boot tinha logo antes da adoção
// ---------------------------------------------------------------------------

/// Os eventos que a cadeia do boot tinha logo antes da adoção — o que o
/// gancho da suíte viu.
static VISTOS: crate::trava::Mutex<Option<Vec<Evento>>> = crate::trava::Mutex::new(None);

/// O gancho de antes da adoção: copia os eventos da cadeia do boot. Copia
/// os eventos, e não os ponteiros: um ponteiro segurado faria a adoção
/// copiar o registro, e o caminho conferido seria o outro.
fn ver_o_boot() {
    let eventos = crate::autorizacao::com_auditoria(|c| {
        c.ultimos(usize::MAX)
            .map(|r| r.evento.clone())
            .collect::<Vec<_>>()
    })
    .unwrap_or_default();
    crate::arch::sem_interrupcoes(|| *VISTOS.lock() = Some(eventos));
}

/// O resumo dos setores `[inicio, inicio + n)` da partição de estado — os
/// bytes cifrados, como estão no disco —, lidos de pedaço em pedaço.
fn resumo_dos_setores(inicio: u64, n: u64) -> Result<[u8; 32], &'static str> {
    let mut resumo = [0u8; 32];
    let mut lido = 0;
    while lido < n {
        let pedaco = (n - lido).min(64);
        let bytes = persistencia::setores_crus_de_teste(inicio + lido, pedaco)?;
        let mut junto = Vec::with_capacity(64);
        junto.extend_from_slice(&resumo);
        junto.extend_from_slice(&politica::auditoria::resumo_dos_parametros(&bytes));
        resumo = politica::auditoria::resumo_dos_parametros(&junto);
        lido += pedaco;
    }
    Ok(resumo)
}

/// Reabre a persistência como o boot — com a auditoria recomeçada antes,
/// se `recomecar`, como num boot de verdade —, e confere a cadeia adotada
/// com a da conta de antes: a do journal, refeita do disco por `repor` e
/// `pular`, continuada por `continuar_com` com os eventos que a cadeia do
/// boot tinha logo antes da adoção. E que o journal que havia antes do boot
/// continua no disco byte a byte, e o que o boot gravou depois é a cadeia
/// continuada.
fn reabrir_e_conferir(caso: &str, recomecar: bool) -> Resultado {
    let do_journal = persistencia::auditoria_do_journal_de_teste()?;
    let ate = do_journal.ultima_seq();
    let registros_antes = todos_do_journal()?;
    let (inicio, usados) = persistencia::extensao_do_journal_de_teste()?;
    let setores_antes = resumo_dos_setores(inicio, usados)?;
    crate::arch::sem_interrupcoes(|| *VISTOS.lock() = None);
    persistencia::antes_da_adocao_de_teste(Some(ver_o_boot));
    com_a_persistencia_fechada(|| {
        if recomecar {
            crate::autorizacao::recomecar_a_auditoria_de_teste();
        }
    });
    persistencia::antes_da_adocao_de_teste(None);
    let boot = crate::arch::sem_interrupcoes(|| VISTOS.lock().take())
        .ok_or("a reabertura nao chegou a adocao")?;
    if persistencia::estado() != persistencia::Estado::Disponivel {
        crate::log_error!("teste", "{}: {:?}", caso, persistencia::estado());
        return Err("a reabertura deixou a persistencia indisponivel");
    }
    if crate::autorizacao::copiados_na_adocao_de_teste() != 0 {
        return Err("a adocao copiou um registro do boot que ninguem segurava");
    }
    // A conta de antes.
    let mut do_boot = Cadeia::nova(CAPACIDADE);
    for e in &boot {
        do_boot.anexar(e.clone());
    }
    let mut esperada = do_journal;
    esperada.continuar_com(&do_boot);
    confere_com_a_esperada(&esperada, caso)?;
    // O que o journal tinha antes do boot continua no disco, byte a byte —
    // a não ser que o boot tenha compactado, e a região seja outra.
    let (inicio_depois, _) = persistencia::extensao_do_journal_de_teste()?;
    if inicio_depois == inicio {
        if resumo_dos_setores(inicio, usados)? != setores_antes {
            crate::log_error!("teste", "{}: setores {}..{}", caso, inicio, inicio + usados);
            return Err("o boot mudou os setores que o journal ja tinha");
        }
        // E registro a registro, decifrados: o cabeçalho de cada um e o
        // conteúdo onde a leitura da suíte o guarda nas duas — ela só guarda
        // o dos últimos (`persistencia::CONTEUDOS_DE_TESTE`), e o registro
        // que o boot gravou empurra a janela dela.
        let registros_depois = todos_do_journal()?;
        if registros_depois.len() < registros_antes.len() {
            return Err("o journal perdeu registros no boot");
        }
        for (a, d) in registros_antes.iter().zip(&registros_depois) {
            let mesmo_cabecalho = (a.sequencia, a.ancora, a.nonce, a.tipo, a.geracao)
                == (d.sequencia, d.ancora, d.nonce, d.tipo, d.geracao)
                && (a.versao_da_politica, a.tempo) == (d.versao_da_politica, d.tempo);
            let mesmo_conteudo =
                a.conteudo.is_empty() || d.conteudo.is_empty() || a.conteudo == d.conteudo;
            if !mesmo_cabecalho || !mesmo_conteudo {
                crate::log_error!("teste", "{}: registro {} do journal", caso, a.sequencia);
                return Err("o boot mudou os registros que o journal ja tinha");
            }
        }
        // O que o boot gravou: a auditoria dos registros novos é a cadeia
        // continuada, na ordem, depois da do journal.
        let mut proxima = ate + 1;
        for r in &registros_depois[registros_antes.len()..] {
            for (seq, evento) in super::auditoria_do_registro(r)? {
                let Some(e) = esperada.registro(seq) else {
                    if seq <= esperada.ultima_seq() {
                        return Err("o boot gravou um registro que a janela esperada perdeu");
                    }
                    proxima = seq + 1;
                    continue;
                };
                if seq != proxima || e.evento != evento {
                    crate::log_error!("teste", "{}: gravado {} e esperado {}", caso, seq, proxima);
                    return Err("o boot gravou outra auditoria que a continuada");
                }
                proxima += 1;
            }
        }
        if esperada.ultima_seq() > ate && proxima == ate + 1 {
            return Err("o boot nao gravou nada da cadeia continuada");
        }
    } else {
        crate::log_info!(
            "teste",
            "{}: o boot compactou; os setores mudaram de regiao",
            caso
        );
    }
    a_cadeia_do_journal_confere()
}

/// A cadeia adotada é a `esperada` em cada registro que as duas janelas
/// ainda têm — a sequência, o evento, o anterior e o elo —, tem o último
/// dela, e se verifica inteira; a gravada é a do journal ou depois, e não
/// passa da cadeia.
fn confere_com_a_esperada(esperada: &Cadeia, caso: &str) -> Resultado {
    let r = crate::autorizacao::com_auditoria(|c| {
        if c.verificar().is_err() {
            return Err("a cadeia adotada nao se verifica");
        }
        if c.ultima_seq() < esperada.ultima_seq() {
            return Err("a cadeia adotada e mais curta que a da conta de antes");
        }
        match c.registro(esperada.ultima_seq()) {
            Some(a) if Some(a) == esperada.ultimos(1).next() => {}
            Some(_) => return Err("o ultimo registro da conta de antes nao e o da adotada"),
            None if esperada.guardados() == 0 => {}
            None => return Err("a adotada perdeu o ultimo registro da conta de antes"),
        }
        let mut comparados = 0u64;
        for e in esperada.ultimos(usize::MAX) {
            if let Some(a) = c.registro(e.seq) {
                if a != e {
                    crate::log_error!("teste", "registro {}", e.seq);
                    return Err("um registro da cadeia adotada nao e o da conta de antes");
                }
                comparados += 1;
            }
        }
        if persistencia::auditoria_gravada() > c.ultima_seq() {
            return Err("a gravada passou da cadeia adotada");
        }
        Ok(comparados)
    })
    .ok_or("sem auditoria")?;
    match r {
        Ok(n) => {
            crate::log_info!(
                "teste",
                "{}: {} registros da adotada iguais aos da conta de antes, ate {}",
                caso,
                n,
                esperada.ultima_seq()
            );
            Ok(())
        }
        Err(e) => {
            crate::log_error!("teste", "{}", caso);
            Err(e)
        }
    }
}

/// O journal com poucos registros de auditoria — o do boot da suíte, no
/// segundo caso dela, logo depois do do compositor —: o anel que ele refaz
/// fica pela metade, e a cadeia
/// adotada é a da conta de antes.
///
/// Antes, o journal vazio: o boot da suíte abriu um disco sem journal e sem
/// âncora, e adotou a cadeia que nada refez — a da gênese, vazia —
/// continuada com a dele. A cadeia de agora é essa: começa na gênese, no
/// registro 1, e se verifica; e o que o journal tem dela, desde o 1, é o
/// mesmo, registro a registro.
pub(super) fn o_journal_com_poucos_registros() -> Resultado {
    let do_journal = persistencia::auditoria_do_journal_de_teste()?;
    let vazio = crate::autorizacao::com_auditoria(|c| {
        let primeira = c.ultimos(usize::MAX).next().map(|r| r.seq);
        if c.ancora() != politica::auditoria::GENESE || primeira != Some(1) {
            return Err("a cadeia adotada do journal vazio nao comeca na genese, no 1");
        }
        if c.verificar().is_err() {
            return Err("a cadeia adotada do journal vazio nao se verifica");
        }
        if do_journal.ancora() != politica::auditoria::GENESE {
            return Err("o journal do boot da suite nao comeca na genese");
        }
        for e in do_journal.ultimos(usize::MAX) {
            if c.registro(e.seq) != Some(e) {
                crate::log_error!("teste", "registro {} do journal", e.seq);
                return Err("o journal nao tem a cadeia adotada do journal vazio");
            }
        }
        Ok(())
    })
    .ok_or("sem auditoria")?;
    vazio?;
    if do_journal.guardados() == 0 || do_journal.guardados() >= CAPACIDADE {
        crate::log_error!("teste", "{} no anel do journal", do_journal.guardados());
        return Err("o journal do comeco da suite nao tem o anel pela metade");
    }
    reabrir_e_conferir("o journal do boot da suite, com o anel pela metade", true)
}

/// A cadeia adotada é a do journal continuada com a do boot, registro a
/// registro, pela conta de antes: com o anel do journal cheio e o boot de
/// um registro; com o boot com o anel cheio, o da suíte; depois da
/// compactação; com uma lacuna no journal; e no boot seguinte, depois de
/// gravar.
pub(super) fn a_cadeia_adotada_e_a_do_journal_continuada() -> Resultado {
    anel_cheio_e_gravado()?;
    reabrir_e_conferir("o boot de um registro e o anel do journal cheio", true)?;
    anel_cheio_e_gravado()?;
    reabrir_e_conferir("o boot com o anel cheio, o da suite", false)?;
    persistencia::compactar_de_teste()?;
    reabrir_e_conferir("depois da compactacao", true)?;
    // Uma lacuna: o anel perde registros antes de gravá-los, e a gravação
    // seguinte leva a lacuna e o que ele ainda tem — a reposição esvazia o
    // anel na lacuna e o enche de novo depois dela.
    let antes = persistencia::auditoria_gravada();
    for i in 0..CAPACIDADE + 300 {
        auditar("teste.adocao.perde", &alloc::format!("{i}"));
    }
    persistencia::gravar_auditoria()?;
    let mut lacunas = 0;
    persistencia::percorrer_a_auditoria_de_teste(|a| {
        if let AuditoriaNoJournal::Lacuna(_, ultima) = a
            && ultima > antes
        {
            lacunas += 1;
        }
    })?;
    if lacunas == 0 {
        return Err("o anel perdeu registros e o journal nao tem a lacuna");
    }
    reabrir_e_conferir("a lacuna no journal", true)?;
    // O boot seguinte refaz a mesma cadeia, com o que se gravou depois.
    for i in 0..50 {
        auditar("teste.adocao.depois", &alloc::format!("{i}"));
    }
    gravar_tudo()?;
    reabrir_e_conferir("o boot seguinte, depois de gravar", true)?;
    reabrir_e_conferir("o boot seguinte de novo, sem nada no meio", true)
}

// ---------------------------------------------------------------------------
// Nada pedido nem devolvido ao alocador com as travas
// ---------------------------------------------------------------------------

/// As contas da suíte veem a trava da auditoria e a da cadeia refeita: um
/// pedido e uma devolução feitos de propósito com cada uma são contados.
fn as_contas_veem_as_duas_travas() -> Resultado {
    let bloco = core::alloc::Layout::new::<[u64; 2]>();
    let alocar_e_devolver = || {
        // Direto ao alocador: por `alloc::alloc`, o LLVM poderia eliminar o
        // par alocar e devolver.
        let p = crate::heap::tentar_alocar(bloco);
        if !p.is_null() {
            // SAFETY: devolvemos o mesmo ponteiro, com o mesmo layout.
            unsafe { crate::heap::devolver(p, bloco) };
        }
        !p.is_null()
    };
    alocacoes::vigiar(crate::fios::id_atual());
    let alocou = crate::autorizacao::com_auditoria(|_| alocar_e_devolver());
    let (pedidos, devolucoes) = (alocacoes::esquecer(), alocacoes::devolucoes());
    if alocou != Some(true) || pedidos != 1 || devolucoes != 1 {
        crate::log_error!(
            "teste",
            "{} pedidos e {} devolucoes, de um",
            pedidos,
            devolucoes
        );
        return Err("as contas da suite nao veem a trava da auditoria na mao");
    }
    alocacoes::vigiar_a_reposta(crate::fios::id_atual());
    let alocou = persistencia::com_a_reposta_de_teste(alocar_e_devolver);
    let (pedidos, devolucoes) = (alocacoes::esquecer(), alocacoes::devolucoes());
    if !alocou || pedidos != 1 || devolucoes != 1 {
        crate::log_error!(
            "teste",
            "{} pedidos e {} devolucoes, de um",
            pedidos,
            devolucoes
        );
        return Err("as contas da suite nao veem a trava da cadeia refeita na mao");
    }
    // E a trava da cadeia refeita não é a da auditoria, nem o contrário.
    alocacoes::vigiar(crate::fios::id_atual());
    persistencia::com_a_reposta_de_teste(alocar_e_devolver);
    let (pedidos, devolucoes) = (alocacoes::esquecer(), alocacoes::devolucoes());
    alocacoes::vigiar_a_reposta(crate::fios::id_atual());
    crate::autorizacao::com_auditoria(|_| alocar_e_devolver());
    let (pedidos_r, devolucoes_r) = (alocacoes::esquecer(), alocacoes::devolucoes());
    if pedidos + devolucoes + pedidos_r + devolucoes_r != 0 {
        return Err("as contas de uma trava viram a outra");
    }
    Ok(())
}

/// Com a trava da auditoria na mão, a adoção não pede nem devolve memória
/// — com a cadeia do boot cheia, e o anel do journal cheio, de onde cada
/// registro continuado empurra um para fora —; e com a da cadeia refeita
/// na mão, a reposição também não — com o anel cheio, de onde cada
/// registro reposto empurra um para fora, e a lacuna que o esvazia inteiro.
/// Pela conta do próprio alocador, só da suíte.
pub(super) fn sem_memoria_com_as_travas_na_mao() -> Resultado {
    as_contas_veem_as_duas_travas()?;
    // A adoção: o boot com o anel cheio, o journal com o anel cheio.
    anel_cheio_e_gravado()?;
    for i in 0..CAPACIDADE {
        auditar("teste.adocao.boot", &alloc::format!("{i}"));
    }
    let boot = crate::autorizacao::com_auditoria(|c| c.guardados()).unwrap_or(0);
    if boot < CAPACIDADE {
        return Err("a cadeia do boot nao esta cheia");
    }
    alocacoes::vigiar(crate::fios::id_atual());
    com_a_persistencia_fechada(|| ());
    let (pedidos, devolucoes) = (alocacoes::esquecer(), alocacoes::devolucoes());
    if persistencia::estado() != persistencia::Estado::Disponivel {
        return Err("a reabertura deixou a persistencia indisponivel");
    }
    if pedidos != 0 || devolucoes != 0 {
        crate::log_error!(
            "teste",
            "{} pedidos e {} devolucoes ao alocador com a trava da auditoria, no boot",
            pedidos,
            devolucoes
        );
        return Err("a adocao pediu ou devolveu memoria com a trava da auditoria na mao");
    }
    if crate::autorizacao::copiados_na_adocao_de_teste() != 0 {
        return Err("a adocao copiou um registro do boot que ninguem segurava");
    }
    // A reposição: um journal com o anel cheio, uma lacuna e o anel cheio
    // de novo depois dela.
    anel_cheio_e_gravado()?;
    for i in 0..CAPACIDADE + 300 {
        auditar("teste.adocao.perde", &alloc::format!("{i}"));
    }
    gravar_tudo()?;
    alocacoes::vigiar_a_reposta(crate::fios::id_atual());
    com_a_persistencia_fechada(crate::autorizacao::recomecar_a_auditoria_de_teste);
    let (pedidos, devolucoes) = (alocacoes::esquecer(), alocacoes::devolucoes());
    if persistencia::estado() != persistencia::Estado::Disponivel {
        return Err("a reabertura deixou a persistencia indisponivel");
    }
    if pedidos != 0 || devolucoes != 0 {
        crate::log_error!(
            "teste",
            "{} pedidos e {} devolucoes ao alocador com a trava da cadeia refeita, no boot",
            pedidos,
            devolucoes
        );
        return Err("a reposicao pediu ou devolveu memoria com a trava da cadeia refeita na mao");
    }
    a_cadeia_do_journal_confere()
}

// ---------------------------------------------------------------------------
// O registro do boot que alguém segura
// ---------------------------------------------------------------------------

/// O registro da cadeia do boot que alguém segura — três por um ponteiro
/// forte, um só por uma referência fraca — não muda: o da cadeia adotada é
/// uma cópia, e a adoção conta as quatro. Quem segurava continua com o que
/// tinha; a referência fraca não alcança mais o dela, que a adoção soltou —
/// nada ficou preso. E a cadeia adotada é a da conta de antes.
pub(super) fn o_registro_que_alguem_segura() -> Resultado {
    anel_cheio_e_gravado()?;
    for i in 0..8 {
        auditar("teste.adocao.segurado", &alloc::format!("{i}"));
    }
    let mut segurados: Vec<Arc<politica::auditoria::Registro>> = Vec::with_capacity(3);
    let fraco = crate::autorizacao::com_auditoria(|c| {
        let mut ultimos = c.ultimos_compartilhados(4);
        let fraco = ultimos.next().map(Arc::downgrade);
        segurados.extend(ultimos.cloned());
        fraco
    })
    .flatten()
    .ok_or("o anel nao tem os registros")?;
    let antes: Vec<politica::auditoria::Registro> =
        segurados.iter().map(|r| (**r).clone()).collect();
    let do_journal = persistencia::auditoria_do_journal_de_teste()?;
    crate::arch::sem_interrupcoes(|| *VISTOS.lock() = None);
    persistencia::antes_da_adocao_de_teste(Some(ver_o_boot));
    com_a_persistencia_fechada(|| ());
    persistencia::antes_da_adocao_de_teste(None);
    let boot = crate::arch::sem_interrupcoes(|| VISTOS.lock().take())
        .ok_or("a reabertura nao chegou a adocao")?;
    let copiados = crate::autorizacao::copiados_na_adocao_de_teste();
    if copiados != 4 {
        crate::log_error!("teste", "{} copiados, de 4 segurados", copiados);
        return Err("a adocao nao copiou exatamente os registros segurados");
    }
    for (r, a) in segurados.iter().zip(&antes) {
        if **r != *a {
            return Err("o registro que alguem segurava mudou na adocao");
        }
    }
    if fraco.upgrade().is_some() {
        return Err("o registro que so a referencia fraca segurava ficou preso");
    }
    let presos = crate::autorizacao::com_auditoria(|c| {
        c.ultimos_compartilhados(usize::MAX)
            .filter(|r| segurados.iter().any(|s| Arc::ptr_eq(r, s)))
            .count()
    })
    .unwrap_or(0);
    if presos != 0 {
        return Err("o registro segurado entrou na cadeia adotada sem copia");
    }
    let mut do_boot = Cadeia::nova(CAPACIDADE);
    for e in &boot {
        do_boot.anexar(e.clone());
    }
    let mut esperada = do_journal;
    esperada.continuar_com(&do_boot);
    drop(segurados);
    confere_com_a_esperada(&esperada, "com registros do boot segurados")
}

// ---------------------------------------------------------------------------
// A gravada troca com a cadeia
// ---------------------------------------------------------------------------

/// O que o `audit.head` e o `audit.tail` disseram logo antes da adoção: a
/// sequência e a gravada do `audit.head`, a gravada do `audit.tail` e a
/// maior sequência que ele disse gravada.
static NO_MEIO: [AtomicU64; 4] = [const { AtomicU64::new(u64::MAX) }; 4];

/// O gancho de antes da adoção: pergunta ao `audit.head` e ao `audit.tail`
/// — os relatórios do gate — o que eles mostram ali.
fn perguntar_no_meio() {
    for a in &NO_MEIO {
        a.store(u64::MAX, SeqCst);
    }
    if let Ok(cabeca) = chamar("audit.head", "{}") {
        let j = Json(cabeca.as_bytes());
        if let (Some(seq), Some(gravada)) = (
            j.member("seq").and_then(|v| v.as_u64()),
            j.member("durable_seq").and_then(|v| v.as_u64()),
        ) {
            NO_MEIO[0].store(seq, SeqCst);
            NO_MEIO[1].store(gravada, SeqCst);
        }
    }
    if let Ok(cauda) = chamar("audit.tail", r#"{"count":128}"#) {
        let j = Json(cauda.as_bytes());
        if let Some(gravada) = j.member("durable_seq").and_then(|v| v.as_u64()) {
            NO_MEIO[2].store(gravada, SeqCst);
        }
        let mut maior = 0;
        if let Some(registros) = j.member("records") {
            let mut i = 0;
            while let Some(r) = registros.item(i) {
                if r.member("durable").and_then(|v| v.as_bool()) == Some(true)
                    && let Some(seq) = r.member("seq").and_then(|v| v.as_u64())
                {
                    maior = maior.max(seq);
                }
                i += 1;
            }
        }
        NO_MEIO[3].store(maior, SeqCst);
    }
}

/// O que o `audit.head` e o `audit.tail` disseram logo depois da adoção,
/// antes de o boot seguir: a sequência e a gravada do `audit.head`, e a
/// gravada do `audit.tail`.
static LOGO_DEPOIS: [AtomicU64; 3] = [const { AtomicU64::new(u64::MAX) }; 3];

/// O gancho de logo depois da adoção: pergunta de novo ao `audit.head` e ao
/// `audit.tail`.
fn perguntar_logo_depois() {
    for a in &LOGO_DEPOIS {
        a.store(u64::MAX, SeqCst);
    }
    if let Ok(cabeca) = chamar("audit.head", "{}") {
        let j = Json(cabeca.as_bytes());
        if let (Some(seq), Some(gravada)) = (
            j.member("seq").and_then(|v| v.as_u64()),
            j.member("durable_seq").and_then(|v| v.as_u64()),
        ) {
            LOGO_DEPOIS[0].store(seq, SeqCst);
            LOGO_DEPOIS[1].store(gravada, SeqCst);
        }
    }
    if let Ok(cauda) = chamar("audit.tail", r#"{"count":1}"#)
        && let Some(gravada) = Json(cauda.as_bytes())
            .member("durable_seq")
            .and_then(|v| v.as_u64())
    {
        LOGO_DEPOIS[2].store(gravada, SeqCst);
    }
}

/// A gravada troca com a cadeia, na mesma tomada da trava: logo antes da
/// adoção — o journal já refeito e confirmado —, o gate mostra a cadeia do
/// boot com a gravada de antes, e nenhum registro dela dito no disco; logo
/// depois — antes de o boot seguir —, a adotada com a gravada do journal, e
/// nunca com a de antes. Gravada antes da troca, a do journal ficava ao
/// lado da cadeia do boot, e o `audit.tail` dizia no disco registros que
/// nenhum journal tem; gravada depois, a adotada aparecia com a gravada de
/// antes.
pub(super) fn a_gravada_troca_com_a_cadeia() -> Resultado {
    anel_cheio_e_gravado()?;
    let journal = persistencia::auditoria_gravada();
    persistencia::antes_da_adocao_de_teste(Some(perguntar_no_meio));
    persistencia::depois_da_adocao_de_teste(Some(perguntar_logo_depois));
    com_a_persistencia_fechada(crate::autorizacao::recomecar_a_auditoria_de_teste);
    persistencia::antes_da_adocao_de_teste(None);
    persistencia::depois_da_adocao_de_teste(None);
    let [seq, gravada, gravada_da_cauda, maior_gravado] =
        NO_MEIO.each_ref().map(|a| a.load(SeqCst));
    if seq == u64::MAX || gravada_da_cauda == u64::MAX {
        return Err("o audit.head ou o audit.tail nao responderam no meio da abertura");
    }
    if gravada > seq || gravada_da_cauda > seq || maior_gravado > gravada_da_cauda {
        crate::log_error!(
            "teste",
            "no meio da abertura: seq {}, gravada {} (cauda {}), maior dito gravado {}, journal ate {}",
            seq,
            gravada,
            gravada_da_cauda,
            maior_gravado,
            journal
        );
        return Err(
            "no meio da abertura, o gate mostrou a gravada do journal com a cadeia do boot",
        );
    }
    if seq >= journal {
        return Err("no meio da abertura, o gate ja mostrava a cadeia adotada");
    }
    // Logo depois da adoção: a adotada, com a gravada do journal — e nunca
    // com a de antes, que a cadeia do boot tinha.
    let [seq, gravada, gravada_da_cauda] = LOGO_DEPOIS.each_ref().map(|a| a.load(SeqCst));
    if seq == u64::MAX || gravada_da_cauda == u64::MAX {
        return Err("o audit.head ou o audit.tail nao responderam logo depois da adocao");
    }
    if seq < journal
        || gravada < journal
        || gravada > seq
        || gravada_da_cauda < journal
        || gravada_da_cauda > seq
    {
        crate::log_error!(
            "teste",
            "logo depois da adocao: seq {}, gravada {} (cauda {}), journal ate {}",
            seq,
            gravada,
            gravada_da_cauda,
            journal
        );
        return Err("logo depois da adocao, o gate mostrou a adotada com a gravada de antes");
    }
    // Depois da adoção: a adotada, com a gravada do journal — ou adiante,
    // com o registro de boot.
    let cabeca = chamar("audit.head", "{}")?;
    let j = Json(cabeca.as_bytes());
    let (Some(seq), Some(gravada)) = (
        j.member("seq").and_then(|v| v.as_u64()),
        j.member("durable_seq").and_then(|v| v.as_u64()),
    ) else {
        return Err("o audit.head nao respondeu depois da abertura");
    };
    if gravada < journal || gravada > seq {
        crate::log_error!(
            "teste",
            "depois: seq {}, gravada {}, journal {}",
            seq,
            gravada,
            journal
        );
        return Err("depois da abertura, a gravada nao e a da cadeia adotada");
    }
    a_cadeia_do_journal_confere()
}

// ---------------------------------------------------------------------------
// Produtores e um leitor durante a reabertura
// ---------------------------------------------------------------------------

/// O método dos registros dos produtores; o detalhe diz o produtor e o
/// número do registro dele.
const PRODUZIDO: &str = "teste.adocao.produtor";
const PRODUTORES: u64 = 3;
/// Juntos, menos que um anel com o do boot: nada sai dele antes do journal.
const POR_PRODUTOR: u64 = 250;
const _: () = assert!(PRODUTORES * POR_PRODUTOR + 16 < CAPACIDADE as u64);
/// Quantos registros cada produtor audita antes da rajada: os que a cadeia
/// do boot tem dele quando a adoção começa.
const ANTES_DA_RAJADA: u64 = 100;
const _: () = assert!(ANTES_DA_RAJADA < POR_PRODUTOR);

/// O gancho de antes da adoção solta a rajada; quantos produtores já estão
/// nela; e se todos estavam quando o gancho deixou a adoção seguir.
static RAJADA: AtomicBool = AtomicBool::new(false);
static NA_RAJADA: AtomicU64 = AtomicU64::new(0);
static RAJADA_NA_ADOCAO: AtomicBool = AtomicBool::new(false);

static PRODUZINDO: AtomicU64 = AtomicU64::new(0);
static LENDO: AtomicU64 = AtomicU64::new(0);
static PARAR: AtomicBool = AtomicBool::new(false);
/// O que o leitor viu de errado: a cadeia que não se verifica, a gravada
/// adiante da cadeia, e a cadeia pela metade — um anel vazio com números e
/// sem a âncora de uma lacuna, ou a mesma sequência com outra cabeça.
static NAO_VERIFICOU: AtomicU64 = AtomicU64::new(0);
static GRAVADA_ADIANTE: AtomicU64 = AtomicU64::new(0);
static PELA_METADE: AtomicU64 = AtomicU64::new(0);
static LEITURAS: AtomicU64 = AtomicU64::new(0);

/// Um produtor: audita os registros dele, com o número dele e o de cada um
/// no detalhe — os primeiros cedendo de vez em quando, para a cadeia do
/// boot; o resto em rajada, sem ceder, desde a hora em que a adoção vai
/// começar: a trava da auditoria disputada por todos no momento da troca.
/// A adoção que soltasse a trava no meio — publicando a cadeia do journal
/// antes de continuá-la, ou continuando-a fora da trava — deixaria um
/// registro da rajada entrar antes dos da cadeia do boot, ou se perder.
extern "C" fn produtor(p: u64) -> ! {
    for i in 0..POR_PRODUTOR {
        if i == ANTES_DA_RAJADA {
            // A rajada espera o gancho de antes da adoção — até um limite: a
            // reabertura que não chegou lá não prende o produtor.
            let limite = crate::tempo::uptime_ms() + 60_000;
            while !RAJADA.load(SeqCst) && crate::tempo::uptime_ms() < limite {
                crate::fios::ceder();
            }
        }
        auditar(PRODUZIDO, &alloc::format!("{p} {i}"));
        if i == ANTES_DA_RAJADA {
            NA_RAJADA.fetch_add(1, SeqCst);
        } else if i < ANTES_DA_RAJADA && i % 8 == 7 {
            crate::fios::ceder();
        }
    }
    PRODUZINDO.fetch_sub(1, SeqCst);
    crate::fios::terminar()
}

/// O gancho de antes da adoção: solta a rajada e espera — até um limite —
/// todos os produtores estarem nela; a adoção começa com eles auditando.
fn soltar_a_rajada() {
    RAJADA.store(true, SeqCst);
    let limite = crate::tempo::uptime_ms() + 10_000;
    while NA_RAJADA.load(SeqCst) < PRODUTORES && crate::tempo::uptime_ms() < limite {
        crate::fios::ceder();
    }
    RAJADA_NA_ADOCAO.store(NA_RAJADA.load(SeqCst) == PRODUTORES, SeqCst);
}

/// Um leitor: até o caso mandar parar, lê a cadeia e a gravada na mesma
/// tomada da trava — como os relatórios —, e de tantas em tantas confere a
/// cadeia inteira.
///
/// E a cadeia pela metade (o achado 2 do adversário do B4): um anel vazio
/// com números e a âncora da gênese é a cadeia do boot esvaziada pela
/// continuação — a de uma lacuna tem a âncora no elo dela, e a recomeçada
/// não tem número —; e a mesma sequência com outra cabeça, a cadeia que
/// mudou sem andar. A sequência que desce é o recomeço da suíte.
extern "C" fn leitor(_: u64) -> ! {
    let mut n = 0u64;
    let mut ultimo: Option<(u64, [u8; 32])> = None;
    while !PARAR.load(SeqCst) {
        let conferir = n.is_multiple_of(16);
        let visto = crate::autorizacao::com_auditoria(|c| {
            (
                c.ultima_seq(),
                c.cabeca(),
                c.guardados() == 0
                    && c.ultima_seq() > 0
                    && c.ancora() == politica::auditoria::GENESE,
                persistencia::auditoria_gravada(),
                !conferir || c.verificar().is_ok(),
            )
        });
        if let Some((seq, cabeca, esvaziada, gravada, verifica)) = visto {
            if gravada > seq {
                GRAVADA_ADIANTE.fetch_add(1, SeqCst);
            }
            if !verifica {
                NAO_VERIFICOU.fetch_add(1, SeqCst);
            }
            let mudou_sem_andar = matches!(ultimo, Some((s, c)) if s == seq && c != cabeca);
            if esvaziada || mudou_sem_andar {
                PELA_METADE.fetch_add(1, SeqCst);
            }
            ultimo = Some((seq, cabeca));
        }
        LEITURAS.fetch_add(1, SeqCst);
        n += 1;
        crate::fios::ceder();
    }
    LENDO.fetch_sub(1, SeqCst);
    crate::fios::terminar()
}

/// Espera `vivos` chegar a zero, cedendo, até `ms` milissegundos.
fn ate_zerar(vivos: &AtomicU64, ms: u64) -> Resultado {
    let limite = crate::tempo::uptime_ms() + ms;
    while vivos.load(SeqCst) != 0 {
        if crate::tempo::uptime_ms() > limite {
            return Err("um fio do caso nao terminou");
        }
        crate::fios::ceder();
    }
    Ok(())
}

/// Produtores em outros núcleos auditam enquanto a persistência reabre, em
/// rajada na hora da adoção, e um leitor noutro núcleo lê a cadeia e a
/// gravada na mesma tomada, nessa reabertura e na seguinte, que só ele
/// acompanha: o leitor nunca vê a cadeia que não
/// se verifica, nem a gravada adiante dela; e, gravado tudo, o journal tem,
/// depois do que tinha antes do boot, cada sequência uma vez, na ordem, sem
/// lacuna, e os registros de cada produtor todos, uma vez cada, na ordem em
/// que ele os auditou — os da cadeia do boot antes dos da rajada que a
/// adoção encontrou.
pub(super) fn produtores_e_um_leitor_durante_a_reabertura() -> Resultado {
    let nucleos: Vec<usize> = nucleos_secundarios().collect();
    if nucleos.is_empty() {
        crate::log_info!("teste", "um nucleo so: os produtores rodam no da suite");
    }
    gravar_tudo()?;
    let desde = persistencia::auditoria_gravada();
    NAO_VERIFICOU.store(0, SeqCst);
    GRAVADA_ADIANTE.store(0, SeqCst);
    PELA_METADE.store(0, SeqCst);
    LEITURAS.store(0, SeqCst);
    PARAR.store(false, SeqCst);
    let no = |i: usize| nucleos.get(i % nucleos.len().max(1)).copied();
    LENDO.store(1, SeqCst);
    let leitor_nasceu = match no(PRODUTORES as usize) {
        Some(n) => crate::fios::criar_no_nucleo("adocao-leitor", leitor, 0, n),
        None => crate::fios::criar("adocao-leitor", leitor, 0),
    };
    if leitor_nasceu.is_err() {
        LENDO.store(0, SeqCst);
        return Err("o leitor do caso nao nasceu");
    }
    RAJADA.store(false, SeqCst);
    NA_RAJADA.store(0, SeqCst);
    RAJADA_NA_ADOCAO.store(false, SeqCst);
    // A primeira reabertura com os produtores no meio — nascidos com a
    // auditoria já recomeçada, como no boot: o que eles auditam vai à
    // cadeia do boot, até a adoção, e à adotada, depois; e a rajada deles,
    // solta pelo gancho de antes da adoção, disputa a trava com ela —; a
    // segunda, com tudo gravado antes, só com o leitor.
    let r = (|| -> Resultado {
        persistencia::antes_da_adocao_de_teste(Some(soltar_a_rajada));
        let primeira = com_a_persistencia_fechada(|| {
            crate::autorizacao::recomecar_a_auditoria_de_teste();
            for p in 0..PRODUTORES {
                PRODUZINDO.fetch_add(1, SeqCst);
                let nasceu = match no(p as usize) {
                    Some(n) => crate::fios::criar_no_nucleo("adocao-produtor", produtor, p, n),
                    None => crate::fios::criar("adocao-produtor", produtor, p),
                };
                if nasceu.is_err() {
                    PRODUZINDO.fetch_sub(1, SeqCst);
                    return Err("um produtor do caso nao nasceu");
                }
            }
            Ok(())
        });
        persistencia::antes_da_adocao_de_teste(None);
        // Um produtor que não nasceu não chega à rajada: o gancho espera o
        // limite dele, e a reabertura segue.
        RAJADA.store(true, SeqCst);
        primeira?;
        if persistencia::estado() != persistencia::Estado::Disponivel {
            return Err("a reabertura deixou a persistencia indisponivel");
        }
        ate_zerar(&PRODUZINDO, 120_000)?;
        if !RAJADA_NA_ADOCAO.load(SeqCst) {
            return Err("a rajada dos produtores nao chegou a adocao");
        }
        gravar_tudo()?;
        com_a_persistencia_fechada(crate::autorizacao::recomecar_a_auditoria_de_teste);
        if persistencia::estado() != persistencia::Estado::Disponivel {
            return Err("a segunda reabertura deixou a persistencia indisponivel");
        }
        Ok(())
    })();
    PARAR.store(true, SeqCst);
    let terminou = ate_zerar(&LENDO, 30_000).and(ate_zerar(&PRODUZINDO, 30_000));
    r?;
    terminou?;
    if LEITURAS.load(SeqCst) == 0 {
        return Err("o leitor nao leu nada");
    }
    if NAO_VERIFICOU.load(SeqCst) != 0 {
        return Err("o leitor viu a cadeia que nao se verifica no meio da reabertura");
    }
    if GRAVADA_ADIANTE.load(SeqCst) != 0 {
        return Err("o leitor viu a gravada adiante da cadeia no meio da reabertura");
    }
    if PELA_METADE.load(SeqCst) != 0 {
        return Err("o leitor viu a cadeia pela metade no meio da reabertura");
    }
    gravar_tudo()?;
    // O journal, depois do que tinha antes do boot.
    let mut proxima = desde + 1;
    let mut do_produtor = [0u64; PRODUTORES as usize];
    let mut erro: Option<&'static str> = None;
    persistencia::percorrer_a_auditoria_de_teste(|a| match a {
        AuditoriaNoJournal::Registro(seq, e) if seq > desde => {
            if seq != proxima {
                erro.get_or_insert("o journal pula, repete ou desordena a auditoria");
            }
            proxima = seq + 1;
            if e.metodo == PRODUZIDO {
                let lido = e
                    .detalhe
                    .split_once(' ')
                    .and_then(|(p, i)| Some((p.parse::<usize>().ok()?, i.parse::<u64>().ok()?)));
                match lido {
                    Some((p, i)) if p < PRODUTORES as usize && i == do_produtor[p] => {
                        do_produtor[p] += 1;
                    }
                    _ => {
                        erro.get_or_insert("um produtor perdeu, repetiu ou desordenou um registro");
                    }
                }
            }
        }
        AuditoriaNoJournal::Lacuna(_, ultima) if ultima > desde => {
            erro.get_or_insert("o journal tem uma lacuna depois do boot");
        }
        _ => {}
    })?;
    if let Some(e) = erro {
        return Err(e);
    }
    if do_produtor.iter().any(|n| *n != POR_PRODUTOR) {
        crate::log_error!("teste", "por produtor no journal: {:?}", do_produtor);
        return Err("o journal nao tem todos os registros de cada produtor");
    }
    crate::log_info!(
        "teste",
        "{} leituras no meio das reaberturas; {} registros no journal depois de {}",
        LEITURAS.load(SeqCst),
        proxima - desde - 1,
        desde
    );
    a_cadeia_do_journal_confere()
}
