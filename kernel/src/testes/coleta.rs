//! Os casos `coleta:` — a cópia da auditoria para o journal (ver "A
//! cópia", em `persistencia::auditoria_que_cabe`). Com a trava da auditoria
//! na mão — a do gate, que todo pedido auditado toma com as interrupções
//! mascaradas —, o coletor só copia: a lacuna e os registros que cabem no
//! registro, para dentro de um lugar reservado antes; as entradas do
//! journal são montadas com a trava solta. Era a montagem com a trava na
//! mão — quatro ou cinco alocações por registro, e outras tantas
//! devoluções — que segurava o gate por dezenas de milissegundos a cada
//! passada do coletor.
//!
//! Os casos conferem, sem depender de tempo:
//!
//! - que a cópia não pede memória nenhuma ao alocador com a trava na mão —
//!   pela conta do próprio alocador, só da suíte
//!   (`autorizacao::alocacoes_sob_a_auditoria_de_teste`) —, e que nenhuma
//!   entrada é montada com ela (`persistencia::coleta_de_teste`); antes, o
//!   controle positivo das duas contas: um pedido e uma montagem feitos de
//!   propósito com a trava na mão são contados;
//! - que cada registro copiado com a trava vira entrada — a conta feita com
//!   ela é a da montagem; em bytes, a suíte o confere em toda gravação
//!   (`coleta_de_teste::montada`);
//! - que o auditado logo depois da cópia — no ponto exato, por um gancho da
//!   suíte, e não onde o tique deixar — fica para a gravação seguinte, e
//!   vai nela, uma vez;
//! - que o anel que transborda entre a cópia e a gravação não leva o
//!   copiado, e que o que saiu sem ser copiado vira uma lacuna do tamanho
//!   dele;
//! - que a gravação que falha não anda a gravada, e a seguinte leva a mesma
//!   faixa uma vez só;
//! - que produtores em vários núcleos e três coletores ao mesmo tempo — o
//!   do kernel, um segundo e a suíte — não perdem, não repetem e não
//!   desordenam nada, e que o boot seguinte refaz a mesma cadeia;
//! - que a compactação copia o anel do mesmo jeito — inteiro o que ele tem
//!   até a gravada na tomada da cópia, medido nela —, e a cadeia continua;
//! - que o anel que perde registros entre as duas tomadas da compactação,
//!   a que mede e a que copia, deixa a base com a marca até o de antes do
//!   primeiro copiado, e o boot seguinte a adota;
//! - e que o registro que chega ao teto da auditoria não passa dele: com
//!   eventos de um tamanho escolhido para que o seguinte caiba sem os dois
//!   bytes do tamanho do campo, e não com eles, a conta do que cabe leva os
//!   dois bytes.
//!
//! Em todos, a auditoria do journal é conferida inteira depois do começo
//! do caso — cada sequência uma vez, na ordem, as lacunas onde devem estar
//! — e a cadeia refeita dele é a da memória, com o mesmo elo.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};

use super::{
    Resultado, a_cadeia_do_journal_confere, nucleos_secundarios, reposto_da_imagem,
    todos_do_journal,
};
use crate::autorizacao::alocacoes_sob_a_auditoria_de_teste as alocacoes;
use crate::persistencia::{self, AuditoriaNoJournal, coleta_de_teste};

/// A capacidade do anel da auditoria.
const CAPACIDADE: u64 = crate::autorizacao::CAPACIDADE_DA_AUDITORIA as u64;

/// O método dos registros dos produtores do caso concorrente; o detalhe
/// diz o produtor e o número do registro dele.
const PRODUZIDO: &str = "teste.coleta.produtor";

/// Quantos produtores, e quantos registros cada um audita: juntos, menos
/// que um anel — nada pode sair dele antes de algum coletor o gravar, e
/// uma lacuna ali é um erro.
const PRODUTORES: u64 = 3;
const POR_PRODUTOR: u64 = 300;
const _: () = assert!(PRODUTORES * POR_PRODUTOR < CAPACIDADE);

/// Um registro do kernel na auditoria; o número dele.
fn auditar(metodo: &str) -> u64 {
    crate::autorizacao::auditar_do_kernel(metodo, "", politica::Codigo::Allow, "coleta")
}

/// O anel cheio — a partir daí, anexar não cresce o anel, e um registro
/// anexado no meio de um caso não pede memória com a trava na mão —, e a
/// auditoria toda no journal.
fn anel_cheio_e_gravado() -> Resultado {
    let guardados = crate::autorizacao::com_auditoria(|c| c.guardados()).unwrap_or(0) as u64;
    for _ in guardados..CAPACIDADE {
        auditar("teste.coleta.enche");
    }
    persistencia::gravar_auditoria()
}

/// O primeiro registro que o anel guarda; zero sem nenhum.
fn primeiro_no_anel() -> u64 {
    crate::autorizacao::com_auditoria(|c| c.ultimos(usize::MAX).next().map(|r| r.seq))
        .flatten()
        .unwrap_or(0)
}

/// O controle positivo das contas da suíte. Com a trava da auditoria na
/// mão, um pedido ao alocador feito de propósito entra na conta do
/// alocador, e uma entrada dada por montada, na das montadas com a trava.
/// Sem isto, o "nenhum pedido" e o "nenhuma montada com a trava" dos casos
/// passariam também com as contas cegas — a conferência da ordem das travas
/// sem ver a trava da auditoria na mão, por exemplo.
fn as_contas_veem_a_trava() -> Resultado {
    let bloco = core::alloc::Layout::new::<[u64; 2]>();
    coleta_de_teste::zerar();
    alocacoes::vigiar(crate::fios::id_atual());
    let alocou = crate::autorizacao::com_auditoria(|_| {
        // Direto ao alocador: por `alloc::alloc`, o LLVM poderia eliminar o
        // par alocar e devolver.
        let p = crate::heap::tentar_alocar(bloco);
        if !p.is_null() {
            // SAFETY: devolvemos o mesmo ponteiro, com o mesmo layout.
            unsafe { crate::heap::devolver(p, bloco) };
        }
        coleta_de_teste::montou();
        !p.is_null()
    });
    let pedidos = alocacoes::esquecer();
    let devolucoes = alocacoes::devolucoes();
    let c = coleta_de_teste::contas();
    coleta_de_teste::zerar();
    if alocou != Some(true)
        || pedidos != 1
        || devolucoes != 1
        || c.montados != 1
        || c.sob_a_trava != 1
    {
        crate::log_error!(
            "teste",
            "{} pedidos e {} devolucoes ao alocador e {} montados com a trava na mao, de um",
            pedidos,
            devolucoes,
            c.sob_a_trava
        );
        return Err("as contas da suite nao veem a trava da auditoria na mao");
    }
    Ok(())
}

/// Cada registro copiado com a trava virou entrada: a conta feita com ela
/// é a da montagem, e nada do que se copiou ficou de fora. Em bytes, a
/// suíte confere o mesmo em toda gravação (`coleta_de_teste::montada`).
fn nada_copiado_de_fora(c: &coleta_de_teste::Contas) -> Resultado {
    if c.montados != c.copiados {
        crate::log_error!("teste", "{} copiados, {} montados", c.copiados, c.montados);
        return Err("a montagem descartou registros que a copia levou com a trava na mao");
    }
    Ok(())
}

/// Um item da auditoria do journal: um registro — a sequência e, se é de
/// um produtor do caso concorrente, o produtor e o número dele —, ou uma
/// lacuna, a primeira e a última.
enum Item {
    Registro(u64, Option<(u64, u64)>),
    Lacuna(u64, u64),
}

/// A auditoria do journal depois da sequência `desde`, na ordem do disco.
fn do_journal_depois_de(desde: u64) -> Result<Vec<Item>, &'static str> {
    let mut v = Vec::new();
    persistencia::percorrer_a_auditoria_de_teste(|a| match a {
        AuditoriaNoJournal::Registro(seq, e) if seq > desde => {
            v.push(Item::Registro(seq, do_produtor(&e)));
        }
        AuditoriaNoJournal::Lacuna(primeira, ultima) if ultima > desde => {
            v.push(Item::Lacuna(primeira, ultima));
        }
        _ => {}
    })?;
    Ok(v)
}

/// O produtor e o número de um registro do caso concorrente.
fn do_produtor(e: &politica::auditoria::Evento) -> Option<(u64, u64)> {
    if e.metodo != PRODUZIDO {
        return None;
    }
    let (p, i) = e.detalhe.split_once(' ')?;
    Some((p.parse().ok()?, i.parse().ok()?))
}

/// A auditoria do journal depois de `desde` segue sem pular, repetir nem
/// voltar, até `ate` pelo menos: cada registro com a sequência seguinte, e
/// cada lacuna a partir dela. Devolve as lacunas, a primeira e a última de
/// cada uma.
fn seguidos(itens: &[Item], desde: u64, ate: u64) -> Result<Vec<(u64, u64)>, &'static str> {
    let mut proxima = desde + 1;
    let mut lacunas = Vec::new();
    for item in itens {
        match *item {
            Item::Registro(seq, _) if seq == proxima => proxima += 1,
            Item::Lacuna(primeira, ultima) if primeira == proxima && ultima >= primeira => {
                lacunas.push((primeira, ultima));
                proxima = ultima + 1;
            }
            _ => {
                crate::log_error!("teste", "a auditoria do journal esperava {}", proxima);
                return Err("o journal pula, repete ou desordena a auditoria");
            }
        }
    }
    if proxima <= ate {
        crate::log_error!(
            "teste",
            "o journal vai ate {}, e nao ate {}",
            proxima - 1,
            ate
        );
        return Err("o journal nao tem a auditoria ate onde ela se diz gravada");
    }
    Ok(lacunas)
}

/// Com a trava da auditoria na mão, a cópia não pede memória nenhuma ao
/// alocador, e nenhuma entrada é montada. O que se audita logo depois da
/// cópia — o gancho da suíte, no ponto exato — entra no anel com a coleta
/// no meio, e fica para a gravação seguinte: a gravada para no último
/// copiado, e a seguinte leva os de depois, uma vez cada.
pub(super) fn a_trava_fica_solta_na_montagem() -> Resultado {
    as_contas_veem_a_trava()?;
    anel_cheio_e_gravado()?;
    let desde = persistencia::auditoria_gravada();
    let mut copiado = desde;
    for _ in 0..40 {
        copiado = auditar("teste.coleta.copiado");
    }
    coleta_de_teste::zerar();
    coleta_de_teste::anexar_depois_da_proxima_copia(30);
    alocacoes::vigiar(crate::fios::id_atual());
    let r = persistencia::gravar_auditoria();
    let pedidos = alocacoes::esquecer();
    let devolucoes = alocacoes::devolucoes();
    let c = coleta_de_teste::contas();
    let (anexado, ultimo_anexado) = coleta_de_teste::anexados();
    coleta_de_teste::zerar();
    r?;
    if pedidos != 0 || devolucoes != 0 {
        crate::log_error!(
            "teste",
            "{} pedidos e {} devolucoes ao alocador",
            pedidos,
            devolucoes
        );
        return Err(
            "a copia da auditoria pediu ou devolveu memoria com a trava da auditoria na mao",
        );
    }
    if c.copias == 0 || c.montados < 40 || c.sob_a_trava != 0 {
        crate::log_error!(
            "teste",
            "{} copias, {} montados, {} com a trava na mao",
            c.copias,
            c.montados,
            c.sob_a_trava
        );
        return Err("uma entrada da auditoria foi montada com a trava na mao");
    }
    nada_copiado_de_fora(&c)?;
    let gravada = persistencia::auditoria_gravada();
    if anexado == 0 || gravada < copiado || gravada >= anexado {
        crate::log_error!(
            "teste",
            "gravada {}; copiados ate {}; anexados de {} a {}",
            gravada,
            copiado,
            anexado,
            ultimo_anexado
        );
        return Err("a gravacao levou o anexado depois da copia, ou nao levou o copiado");
    }
    persistencia::gravar_auditoria()?;
    let gravada = persistencia::auditoria_gravada();
    if gravada < ultimo_anexado {
        return Err("o anexado no meio da coleta nao foi na gravacao seguinte");
    }
    if !seguidos(&do_journal_depois_de(desde)?, desde, gravada)?.is_empty() {
        return Err("uma lacuna no journal sem o anel ter transbordado");
    }
    a_cadeia_do_journal_confere()
}

/// O anel transborda entre a cópia e a gravação — mais que um anel inteiro
/// auditado no meio da coleta, pelo gancho: o copiado vai ao journal
/// inteiro, mesmo fora do anel; o que saiu sem ser copiado vira, na
/// gravação seguinte, uma lacuna logo depois dele, contada na auditoria
/// perdida; e a cadeia refeita do journal é a da memória.
pub(super) fn o_anel_que_transborda_no_meio_da_coleta() -> Resultado {
    as_contas_veem_a_trava()?;
    anel_cheio_e_gravado()?;
    let desde = persistencia::auditoria_gravada();
    let mut copiado = desde;
    for _ in 0..40 {
        copiado = auditar("teste.coleta.copiado");
    }
    coleta_de_teste::zerar();
    coleta_de_teste::anexar_depois_da_proxima_copia(CAPACIDADE + 25);
    let perdida = crate::metricas::AUDITORIA_PERDIDA.load(SeqCst);
    let r = persistencia::gravar_auditoria();
    let (anexado, ultimo_anexado) = coleta_de_teste::anexados();
    let c = coleta_de_teste::contas();
    coleta_de_teste::zerar();
    r?;
    // O copiado saiu do anel antes de ser montado, e foi montado inteiro.
    nada_copiado_de_fora(&c)?;
    let gravada = persistencia::auditoria_gravada();
    let frente = primeiro_no_anel();
    if anexado == 0 || gravada < copiado || gravada >= anexado || frente <= gravada + 1 {
        crate::log_error!(
            "teste",
            "gravada {}; copiados ate {}; anexados de {} a {}; o anel desde {}",
            gravada,
            copiado,
            anexado,
            ultimo_anexado,
            frente
        );
        return Err("o anel nao transbordou no meio da coleta, ou o copiado nao foi gravado");
    }
    // A gravação seguinte, com a lacuna e um anel inteiro pendente — mais
    // que um registro do journal: nenhuma cópia dela pede memória com a
    // trava na mão, nem a que não cabe toda num registro. E os lotes cheios
    // — onde a conta com a trava e a da montagem divergiriam, se
    // divergissem — levam tudo o que copiaram.
    coleta_de_teste::zerar();
    alocacoes::vigiar(crate::fios::id_atual());
    let r = persistencia::gravar_auditoria();
    let pedidos = alocacoes::esquecer();
    let devolucoes = alocacoes::devolucoes();
    let c = coleta_de_teste::contas();
    coleta_de_teste::zerar();
    r?;
    if pedidos != 0 || devolucoes != 0 {
        crate::log_error!(
            "teste",
            "{} pedidos e {} devolucoes ao alocador",
            pedidos,
            devolucoes
        );
        return Err("a copia da lacuna e do anel pediu ou devolveu memoria com a trava na mao");
    }
    if c.copias < 2 || c.sob_a_trava != 0 {
        crate::log_error!(
            "teste",
            "{} copias, {} montados com a trava na mao",
            c.copias,
            c.sob_a_trava
        );
        return Err("o anel inteiro pendente nao foi em lotes, ou foi montado com a trava");
    }
    nada_copiado_de_fora(&c)?;
    let perdidos = crate::metricas::AUDITORIA_PERDIDA.load(SeqCst) - perdida;
    let depois = persistencia::auditoria_gravada();
    let lacunas = seguidos(&do_journal_depois_de(desde)?, desde, depois)?;
    let certa = matches!(
        lacunas.as_slice(),
        [(primeira, ultima)] if *primeira == gravada + 1
            && *ultima + 1 >= frente
            && perdidos == ultima - primeira + 1
    );
    if !certa || depois < ultimo_anexado {
        crate::log_error!(
            "teste",
            "{} lacunas; {} perdidos; gravada {}; o anel desde {}",
            lacunas.len(),
            perdidos,
            gravada,
            frente
        );
        return Err("o que saiu do anel sem ser copiado nao virou a lacuna dele");
    }
    a_cadeia_do_journal_confere()
}

/// A gravação que falha depois da cópia — a da suíte, no lugar da escrita —
/// não anda a gravada nem deixa registro, e deixa a persistência
/// indisponível; de pé de novo, como o boot seguinte a deixaria, a gravação
/// seguinte leva a mesma faixa e o que veio depois, uma vez cada.
pub(super) fn a_gravacao_que_falha() -> Resultado {
    let anterior = persistencia::estado();
    let r = (|| -> Resultado {
        anel_cheio_e_gravado()?;
        let desde = persistencia::auditoria_gravada();
        let registros = todos_do_journal()?.len();
        for _ in 0..40 {
            auditar("teste.coleta.falha");
        }
        coleta_de_teste::zerar();
        coleta_de_teste::anexar_depois_da_proxima_copia(20);
        persistencia::falhar_a_proxima_gravacao_de_teste(true);
        let falhou = persistencia::gravar_auditoria();
        persistencia::falhar_a_proxima_gravacao_de_teste(false);
        let (_, ultimo_anexado) = coleta_de_teste::anexados();
        if falhou.is_ok() {
            return Err("a gravacao que falhou foi dita feita");
        }
        if persistencia::auditoria_gravada() != desde || todos_do_journal()?.len() != registros {
            return Err("a gravacao que falhou andou a gravada, ou deixou registro no journal");
        }
        if persistencia::estado() == persistencia::Estado::Disponivel {
            return Err("a gravacao que falhou deixou a persistencia disponivel");
        }
        persistencia::forcar_estado_de_teste(persistencia::Estado::Disponivel);
        persistencia::gravar_auditoria()?;
        let gravada = persistencia::auditoria_gravada();
        if ultimo_anexado == 0 || gravada < ultimo_anexado {
            return Err("a gravacao seguinte nao levou a faixa da que falhou");
        }
        if !seguidos(&do_journal_depois_de(desde)?, desde, gravada)?.is_empty() {
            return Err("uma lacuna no journal sem o anel ter transbordado");
        }
        a_cadeia_do_journal_confere()
    })();
    persistencia::falhar_a_proxima_gravacao_de_teste(false);
    coleta_de_teste::zerar();
    persistencia::forcar_estado_de_teste(anterior);
    r
}

/// Os produtores ainda auditando, e os coletores ainda gravando.
static PRODUZINDO: AtomicU64 = AtomicU64::new(0);
static COLETANDO: AtomicU64 = AtomicU64::new(0);
/// O caso manda o segundo coletor parar.
static PARAR: AtomicBool = AtomicBool::new(false);
/// As passadas do segundo coletor, e as que falharam.
static PASSADAS: AtomicU64 = AtomicU64::new(0);
static FALHAS: AtomicU64 = AtomicU64::new(0);

/// Um produtor: audita [`POR_PRODUTOR`] registros, com o número dele e o de
/// cada registro no detalhe, cedendo de vez em quando.
extern "C" fn produtor(p: u64) -> ! {
    for i in 0..POR_PRODUTOR {
        crate::autorizacao::auditar_do_kernel(
            PRODUZIDO,
            "",
            politica::Codigo::Allow,
            &alloc::format!("{p} {i}"),
        );
        if i % 8 == 7 {
            crate::fios::ceder();
        }
    }
    PRODUZINDO.fetch_sub(1, SeqCst);
    crate::fios::terminar()
}

/// Um segundo coletor: grava a auditoria sem parar — uma passada ao menos
/// —, até o caso mandar.
extern "C" fn coletor(_: u64) -> ! {
    loop {
        if persistencia::gravar_auditoria().is_err() {
            FALHAS.fetch_add(1, SeqCst);
        }
        PASSADAS.fetch_add(1, SeqCst);
        if PARAR.load(SeqCst) {
            break;
        }
        crate::fios::ceder();
    }
    COLETANDO.fetch_sub(1, SeqCst);
    crate::fios::terminar()
}

/// Um fio do caso, no núcleo `nucleo` se há um, contado em `vivos`.
fn nascer(
    nome: &'static str,
    entrada: extern "C" fn(u64) -> !,
    argumento: u64,
    nucleo: Option<usize>,
    vivos: &AtomicU64,
) -> Resultado {
    vivos.fetch_add(1, SeqCst);
    let r = match nucleo {
        Some(n) => crate::fios::criar_no_nucleo(nome, entrada, argumento, n),
        None => crate::fios::criar(nome, entrada, argumento),
    };
    if r.is_err() {
        vivos.fetch_sub(1, SeqCst);
        return Err("um fio do caso nao nasceu");
    }
    Ok(())
}

/// Espera `vivos` chegar a zero, cedendo — os fios do caso podem estar no
/// núcleo da suíte —, até `ms` milissegundos.
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

/// Produtores em vários núcleos auditando e três coletores gravando ao
/// mesmo tempo — o do kernel, solto; um segundo, noutro núcleo; e a suíte —,
/// todos pela ordem das gravações: no journal, cada sequência uma vez, na
/// ordem, sem lacuna; os registros de cada produtor todos, na ordem em que
/// ele os auditou; e a cadeia refeita do journal é a da memória — e é ela
/// que o boot seguinte refaz.
pub(super) fn produtores_e_coletores_ao_mesmo_tempo() -> Resultado {
    anel_cheio_e_gravado()?;
    let desde = persistencia::auditoria_gravada();
    let de_auditoria = persistencia::registros_de_auditoria();
    PARAR.store(false, SeqCst);
    PASSADAS.store(0, SeqCst);
    FALHAS.store(0, SeqCst);
    let nucleos: Vec<usize> = nucleos_secundarios().collect();
    let no = |i: usize| nucleos.get(i % nucleos.len().max(1)).copied();
    let r = (|| -> Resultado {
        persistencia::pausar_a_auditoria_de_teste(false);
        nascer("teste-coleta-coletor", coletor, 0, no(0), &COLETANDO)?;
        for p in 0..PRODUTORES {
            nascer(
                "teste-coleta-produtor",
                produtor,
                p,
                no(p as usize + 1),
                &PRODUZINDO,
            )?;
        }
        let limite = crate::tempo::uptime_ms() + 60_000;
        while PRODUZINDO.load(SeqCst) != 0 {
            persistencia::gravar_auditoria()?;
            if crate::tempo::uptime_ms() > limite {
                return Err("os produtores nao terminaram em 60 s");
            }
            crate::fios::ceder();
        }
        PARAR.store(true, SeqCst);
        ate_zerar(&COLETANDO, 30_000)?;
        persistencia::pausar_a_auditoria_de_teste(true);
        let fim = crate::autorizacao::ultimo_registro();
        persistencia::gravar_auditoria()?;
        let gravada = persistencia::auditoria_gravada();
        if FALHAS.load(SeqCst) != 0 || PASSADAS.load(SeqCst) == 0 || gravada < fim {
            crate::log_error!(
                "teste",
                "{} passadas do segundo coletor, {} falhas; gravada {} de {}",
                PASSADAS.load(SeqCst),
                FALHAS.load(SeqCst),
                gravada,
                fim
            );
            return Err("um coletor falhou, nao passou, ou a auditoria nao foi toda");
        }
        let itens = do_journal_depois_de(desde)?;
        if !seguidos(&itens, desde, gravada)?.is_empty() {
            return Err("uma lacuna no journal com menos que um anel auditado");
        }
        // Os de cada produtor: todos, uma vez, na ordem dele.
        let mut proximo = [0u64; PRODUTORES as usize];
        for item in &itens {
            if let Item::Registro(_, Some((p, i))) = *item {
                match proximo.get_mut(p as usize) {
                    Some(n) if *n == i => *n += 1,
                    _ => {
                        crate::log_error!(
                            "teste",
                            "produtor {}: o registro {} fora de ordem",
                            p,
                            i
                        );
                        return Err("um registro de produtor faltou, repetiu ou saiu de ordem");
                    }
                }
            }
        }
        if proximo.iter().any(|&n| n != POR_PRODUTOR) {
            return Err("faltam registros de um produtor no journal");
        }
        let escritos = persistencia::registros_de_auditoria() - de_auditoria;
        crate::log_info!(
            "teste",
            "coleta: {} registros de {} produtores em {} registros so de auditoria; {} passadas do segundo coletor",
            PRODUTORES * POR_PRODUTOR,
            PRODUTORES,
            escritos,
            PASSADAS.load(SeqCst)
        );
        a_cadeia_do_journal_confere()?;
        // O boot seguinte refaz, do journal, a mesma cadeia.
        reposto_da_imagem(persistencia::abrir);
        if persistencia::estado() != persistencia::Estado::Disponivel {
            return Err("o boot seguinte nao abriu o journal da coleta concorrente");
        }
        a_cadeia_do_journal_confere()
    })();
    PARAR.store(true, SeqCst);
    let _ = ate_zerar(&PRODUZINDO, 30_000);
    let _ = ate_zerar(&COLETANDO, 30_000);
    persistencia::pausar_a_auditoria_de_teste(true);
    r
}

/// A compactação copia o anel como o coletor: sem pedir memória com a
/// trava da auditoria na mão, e montando as entradas da base fora dela. A
/// base leva, inteiro, o que o anel tem até a gravada na tomada da cópia —
/// medido nela, pela suíte. E o anel que transborda logo depois da cópia
/// não tira da base os registros copiados: a cadeia refeita do journal
/// continua a da memória.
pub(super) fn a_compactacao_copia_fora_da_trava() -> Resultado {
    as_contas_veem_a_trava()?;
    for i in 0..CAPACIDADE + 100 {
        auditar("teste.coleta.compactada");
        if i % 100 == 99 {
            persistencia::gravar_auditoria()?;
        }
    }
    persistencia::gravar_auditoria()?;
    let gravada = persistencia::auditoria_gravada();
    // Uns pendentes, que não estão no journal: a base não os leva — a
    // gravação seguinte, sim.
    for _ in 0..10 {
        auditar("teste.coleta.pendente");
    }
    let no_anel =
        crate::autorizacao::com_auditoria(|c| c.guardados_ate(gravada).count()).unwrap_or(0) as u64;
    coleta_de_teste::zerar();
    alocacoes::vigiar(crate::fios::id_atual());
    let r = persistencia::compactar_de_teste();
    let pedidos = alocacoes::esquecer();
    let devolucoes = alocacoes::devolucoes();
    let c = coleta_de_teste::contas();
    let (_, _, na_copia) = coleta_de_teste::compactada();
    coleta_de_teste::zerar();
    r?;
    if pedidos != 0 || devolucoes != 0 {
        crate::log_error!(
            "teste",
            "{} pedidos e {} devolucoes ao alocador",
            pedidos,
            devolucoes
        );
        return Err("a compactacao pediu ou devolveu memoria com a trava da auditoria na mao");
    }
    if c.copias != 1 || c.montados == 0 || c.sob_a_trava != 0 {
        crate::log_error!(
            "teste",
            "{} copias, {} montados de {} no anel, {} com a trava na mao",
            c.copias,
            c.montados,
            no_anel,
            c.sob_a_trava
        );
        return Err("a compactacao montou a auditoria da base com a trava na mao");
    }
    nada_copiado_de_fora(&c)?;
    // Inteiro: tantos quantos o anel tinha até a gravada na tomada da
    // cópia. A medida do caso, de antes, é a mesma com a suíte quieta — e o
    // anel, até lá, só perde registros pela frente.
    if c.copiados != na_copia || na_copia > no_anel {
        crate::log_error!(
            "teste",
            "{} copiados; {} no anel na copia, {} antes",
            c.copiados,
            na_copia,
            no_anel
        );
        return Err("a base nao levou inteiro o que o anel tinha ate a gravada na copia");
    }
    // A base vai até a gravada, e nem um além: a cadeia do journal termina
    // nela.
    a_cadeia_do_journal_confere()?;
    persistencia::gravar_auditoria()?;
    a_cadeia_do_journal_confere()?;
    let gravada = persistencia::auditoria_gravada();
    // Um anel inteiro auditado logo depois da cópia: os copiados saem do
    // anel antes de a base ser escrita, e vão nela assim mesmo.
    coleta_de_teste::zerar();
    coleta_de_teste::anexar_depois_da_proxima_copia(CAPACIDADE);
    let r = persistencia::compactar_de_teste();
    let c = coleta_de_teste::contas();
    coleta_de_teste::zerar();
    r?;
    nada_copiado_de_fora(&c)?;
    if primeiro_no_anel() <= gravada {
        return Err("o anel nao transbordou no meio da compactacao");
    }
    persistencia::gravar_auditoria()?;
    a_cadeia_do_journal_confere()
}

/// Quantos registros a suíte audita entre as duas tomadas da compactação,
/// no caso do anel que perde registros ali.
const ENTRE_AS_TOMADAS: u64 = 5;

/// O anel perde registros entre as duas tomadas da compactação — a que
/// mede e a que copia —: com ele cheio, os auditados ali, pelo gancho da
/// suíte, tiram da frente os mais antigos, que a medida contou. A cópia
/// leva, inteiro, o que o anel ainda tem até a gravada na tomada dela —
/// medido nela —, e a marca da base parte do primeiro copiado: a base é a
/// marca de 1 ao de antes dele, e os copiados, dele à gravada, um a um. A
/// cadeia refeita dela é a da memória, e o boot seguinte a adota — um
/// registro fora de sequência a deixaria recusada.
pub(super) fn o_anel_que_perde_registros_entre_as_tomadas() -> Resultado {
    as_contas_veem_a_trava()?;
    anel_cheio_e_gravado()?;
    coleta_de_teste::zerar();
    coleta_de_teste::anexar_entre_as_tomadas_da_proxima_compactacao(ENTRE_AS_TOMADAS);
    alocacoes::vigiar(crate::fios::id_atual());
    let r = persistencia::compactar_de_teste();
    let pedidos = alocacoes::esquecer();
    let devolucoes = alocacoes::devolucoes();
    let c = coleta_de_teste::contas();
    let (gravada, medidos, no_anel) = coleta_de_teste::compactada();
    let (anexado, _) = coleta_de_teste::anexados();
    coleta_de_teste::zerar();
    r?;
    if pedidos != 0 || devolucoes != 0 {
        crate::log_error!(
            "teste",
            "{} pedidos e {} devolucoes ao alocador",
            pedidos,
            devolucoes
        );
        return Err("a compactacao pediu ou devolveu memoria com a trava da auditoria na mao");
    }
    // Os auditados entre as tomadas tiraram da frente registros que a
    // medida contou: na tomada da cópia, o anel tem menos até a gravada.
    if anexado <= gravada || no_anel == 0 || no_anel + ENTRE_AS_TOMADAS > medidos {
        crate::log_error!(
            "teste",
            "gravada {}; {} medidos, {} no anel na copia; anexados desde {}",
            gravada,
            medidos,
            no_anel,
            anexado
        );
        return Err("o anel nao perdeu registros entre as duas tomadas da compactacao");
    }
    if c.copias != 1 || c.sob_a_trava != 0 {
        crate::log_error!(
            "teste",
            "{} copias, {} montados com a trava na mao",
            c.copias,
            c.sob_a_trava
        );
        return Err("a compactacao montou a auditoria da base com a trava na mao");
    }
    nada_copiado_de_fora(&c)?;
    if c.copiados != no_anel {
        crate::log_error!("teste", "{} copiados de {} no anel", c.copiados, no_anel);
        return Err("a base nao levou inteiro o que o anel tinha ate a gravada na copia");
    }
    a_base_e(gravada + 1 - no_anel, gravada)?;
    a_cadeia_do_journal_confere()?;
    // O boot seguinte adota a base.
    reposto_da_imagem(persistencia::abrir);
    if persistencia::estado() != persistencia::Estado::Disponivel {
        return Err("o boot seguinte nao abriu o journal da base");
    }
    a_cadeia_do_journal_confere()
}

/// A auditoria da base que a compactação acabou de escrever — a região
/// nova só tem ela —, lida do disco: a marca de 1 a `primeiro - 1`, e os
/// registros de `primeiro` em diante, um a um, até `ate` pelo menos.
fn a_base_e(primeiro: u64, ate: u64) -> Resultado {
    // Zero: a marca ainda não veio.
    let mut proximo: u64 = 0;
    let mut certa = true;
    persistencia::percorrer_a_auditoria_de_teste(|a| match a {
        AuditoriaNoJournal::Compactada(1, ultima) if proximo == 0 && ultima == primeiro - 1 => {
            proximo = primeiro;
        }
        AuditoriaNoJournal::Registro(seq, _) if proximo != 0 && seq == proximo => proximo += 1,
        _ => certa = false,
    })?;
    if !certa || proximo <= ate {
        crate::log_error!(
            "teste",
            "a base de {} a {} vai ate {}",
            primeiro,
            ate,
            proximo.saturating_sub(1)
        );
        return Err("a base nao e a marca ate o primeiro copiado, e os copiados ate a gravada");
    }
    Ok(())
}

/// O método dos registros do caso do teto.
const NO_TETO: &str = "teste.coleta.teto";

/// O que um evento pode ocupar no conteúdo de um registro, com o tamanho do
/// campo, para o caso do teto: o teto mais um byte é um número inteiro
/// deles — 16 385 = 5 × 29 × 113, e 145 = 5 × 29. O caso usa o menor que
/// cabe o evento de um caractere de detalhe.
const POR_EVENTO_NO_TETO: [usize; 2] = [113, 145];
const _: () = {
    let mut i = 0;
    while i < POR_EVENTO_NO_TETO.len() {
        assert!(
            (persistencia::MAIOR_AUDITORIA_POR_REGISTRO + 1).is_multiple_of(POR_EVENTO_NO_TETO[i])
        );
        i += 1;
    }
};

/// O registro só de auditoria que chega ao teto. Cada entrada vai no
/// conteúdo como um campo, com o tamanho na frente, em dois bytes; com
/// eventos que ocupam, cada um, um divisor do teto mais um byte, o último
/// que cabe deixa sobrando um byte a menos que o seguinte precisa — ele
/// caberia sem os dois bytes do tamanho, e não cabe com eles. O caso
/// confere que nenhum registro passa do teto e que ao menos um fica cheio,
/// com um evento a menos que isso, no teto menos o que um evento ocupa mais
/// um byte; a auditoria do journal segue inteira, e a cadeia refeita dele é
/// a da memória.
///
/// O tamanho de um evento no conteúdo é medido, e não contado aqui: um
/// registro com um evento só, de um caractere de detalhe; o detalhe dos do
/// caso completa o que falta até o tamanho escolhido, um byte por
/// caractere.
pub(super) fn o_registro_que_chega_ao_teto() -> Resultado {
    const TETO: usize = persistencia::MAIOR_AUDITORIA_POR_REGISTRO;
    persistencia::gravar_auditoria()?;
    let antes = todos_do_journal()?.len();
    crate::autorizacao::auditar_do_kernel(NO_TETO, "", politica::Codigo::Allow, "t");
    persistencia::gravar_auditoria()?;
    let novos = todos_do_journal()?.split_off(antes);
    let um_so = match novos.as_slice() {
        [r] if r.tipo == diario::estado::tipo::AUDITORIA => Some(r),
        _ => None,
    };
    let Some(r) = um_so.filter(|r| persistencia::entradas_de_teste(r).is_ok_and(|e| e.len() == 1))
    else {
        crate::log_error!("teste", "{} registros novos", novos.len());
        return Err("o registro de um evento so nao foi o unico gravado");
    };
    let com_um = r.conteudo.len();
    let Some(por_evento) = POR_EVENTO_NO_TETO.into_iter().find(|&n| n >= com_um) else {
        crate::log_error!("teste", "o evento de um caractere ocupa {} bytes", com_um);
        return Err("o evento do caso do teto nao cabe nos tamanhos escolhidos");
    };
    let detalhe = "t".repeat(1 + por_evento - com_um);
    let por_registro = (TETO + 1) / por_evento - 1;

    let desde = persistencia::auditoria_gravada();
    let antes = todos_do_journal()?.len();
    let mut ultimo = desde;
    // Três registros cheios, pelo menos, e menos que um anel: nada sai dele
    // antes de chegar ao disco.
    for _ in 0..3 * (por_registro + 1) {
        ultimo =
            crate::autorizacao::auditar_do_kernel(NO_TETO, "", politica::Codigo::Allow, &detalhe);
    }
    persistencia::gravar_auditoria()?;
    let novos = todos_do_journal()?.split_off(antes);
    if novos
        .iter()
        .any(|r| r.tipo != diario::estado::tipo::AUDITORIA)
    {
        return Err("um registro que nao e so de auditoria no meio do caso do teto");
    }
    if let Some(r) = novos.iter().find(|r| r.conteudo.len() > TETO) {
        crate::log_error!(
            "teste",
            "{} bytes de auditoria num registro, com {} por evento",
            r.conteudo.len(),
            por_evento
        );
        return Err(
            "um registro levou mais auditoria que o teto: a conta do que cabe sem os dois bytes do tamanho do campo",
        );
    }
    let cheios = novos
        .iter()
        .filter(|r| r.conteudo.len() == por_registro * por_evento)
        .count();
    if cheios == 0 {
        crate::log_error!(
            "teste",
            "{} registros novos; {} bytes por evento",
            novos.len(),
            por_evento
        );
        return Err("nenhum registro chegou ao teto: o caso nao passou pela fronteira");
    }
    crate::log_info!(
        "teste",
        "coleta: {} bytes por evento; {} de {} registros com {} eventos, {} bytes",
        por_evento,
        cheios,
        novos.len(),
        por_registro,
        por_registro * por_evento
    );
    let gravada = persistencia::auditoria_gravada();
    if gravada < ultimo {
        return Err("a auditoria do caso do teto nao foi toda ao journal");
    }
    if !seguidos(&do_journal_depois_de(desde)?, desde, gravada)?.is_empty() {
        return Err("uma lacuna no journal sem o anel ter transbordado");
    }
    a_cadeia_do_journal_confere()
}
