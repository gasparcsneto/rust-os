//! Os casos `coleta:` — a cópia da auditoria para o journal (ver "A
//! cópia", em `persistencia::auditoria_que_cabe`). Com a trava da auditoria
//! na mão — a do gate, que todo pedido auditado toma com as interrupções
//! mascaradas —, o coletor só copia: a lacuna e os ponteiros — os `Arc` do
//! anel — dos registros que cabem no registro, para um lugar reservado
//! antes; a codificação e as entradas do journal são feitas com a trava
//! solta. Era a montagem com a trava na mão — quatro ou cinco alocações por
//! registro, e outras tantas devoluções — que segurava o gate por dezenas
//! de milissegundos a cada passada do coletor; e, depois dela, a
//! codificação, que ainda copiava o texto de cada registro com a trava.
//!
//! Os casos conferem, sem depender de tempo:
//!
//! - que a cópia não pede nem devolve memória nenhuma ao alocador com a
//!   trava na mão — pela conta do próprio alocador, só da suíte
//!   (`autorizacao::alocacoes_sob_a_auditoria_de_teste`) —, e que nenhuma
//!   entrada é montada com ela (`persistencia::coleta_de_teste`); antes, o
//!   controle positivo das duas contas: um pedido e uma montagem feitos de
//!   propósito com a trava na mão são contados;
//! - que cada ponteiro copiado com a trava vira entrada, e entra no
//!   registro — a conta feita com ela é a da montagem; em bytes, a suíte o
//!   confere em toda gravação (`coleta_de_teste::montada`);
//! - que o auditado logo depois da cópia — no ponto exato, por um gancho da
//!   suíte, e não onde o tique deixar — fica para a gravação seguinte, e
//!   vai nela, uma vez;
//! - que o anel que transborda entre a cópia e a gravação não leva o
//!   copiado — inteiro para quem segura o ponteiro dele, e devolvido pela
//!   cópia, que solta o último ponteiro dele com a trava solta —, e que o
//!   que saiu sem ser copiado vira uma lacuna do tamanho dele;
//! - que um registro do journal cheio de registros mínimos — os cinco
//!   textos vazios: o maior lote de ponteiros que a cópia pode copiar —
//!   cabe no lugar reservado antes da trava;
//! - que a gravação que falha não anda a gravada, e a seguinte leva a mesma
//!   faixa uma vez só;
//! - que produtores em vários núcleos e três coletores ao mesmo tempo — o
//!   do kernel, um segundo e a suíte — não perdem, não repetem e não
//!   desordenam nada, e que o boot seguinte refaz a mesma cadeia;
//! - que a compactação copia o anel do mesmo jeito, numa tomada só —
//!   inteiro o que ele tem até a gravada na tomada, contado nela —, e a
//!   cadeia continua; e que o anel que transborda logo depois da tomada não
//!   tira da base os copiados, que a compactação solta depois de pô-los
//!   nela;
//! - que o anel que perde registros entre a leitura da gravada e a tomada
//!   da compactação deixa a base com a marca até o de antes do primeiro
//!   copiado, e o boot seguinte a adota;
//! - que a compactação com o anel sem nenhum gravado deixa a base só com a
//!   marca até a gravada, com o elo guardado do último gravado, e a
//!   gravação seguinte continua dela pela lacuna;
//! - que produtores sem folga, três coletores e compactações seguidas — o
//!   anel dando a volta debaixo delas — deixam cada base inteira e o
//!   journal seguido, com as lacunas do anel, e o boot seguinte refaz a
//!   mesma cadeia;
//! - e que o registro que chega ao teto da auditoria não passa dele: com
//!   eventos de um tamanho escolhido para que o seguinte caiba sem os dois
//!   bytes do tamanho do campo, e não com eles, a conta do que cabe leva os
//!   dois bytes.
//!
//! Em todos, a auditoria do journal é conferida inteira depois do começo
//! do caso — cada sequência uma vez, na ordem, as lacunas onde devem estar
//! — e a cadeia refeita dele é a da memória, com o mesmo elo.

use alloc::sync::{Arc, Weak};
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

/// O registro `seq` do anel, por uma referência fraca — que não o segura —;
/// `None` se ele não está no anel. Quando ninguém mais o segura, ela não o
/// alcança mais: quem o soltou por último o devolveu.
fn do_anel(seq: u64) -> Option<Weak<politica::auditoria::Registro>> {
    crate::autorizacao::com_auditoria(|c| {
        c.compartilhados_depois_de(seq.saturating_sub(1))
            .next()
            .filter(|r| r.seq == seq)
            .map(Arc::downgrade)
    })
    .flatten()
}

/// Nenhum pedido e nenhuma devolução ao alocador com a trava na mão;
/// senão, `erro`.
fn sem_memoria_com_a_trava(pedidos: u64, devolucoes: u64, erro: &'static str) -> Resultado {
    if pedidos != 0 || devolucoes != 0 {
        crate::log_error!(
            "teste",
            "{} pedidos e {} devolucoes ao alocador",
            pedidos,
            devolucoes
        );
        return Err(erro);
    }
    Ok(())
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

/// Cada ponteiro copiado com a trava virou entrada, e entrou no registro —
/// ou na base: a conta feita com ela é a da montagem, e nada do que se
/// copiou ficou de fora. Em bytes, a suíte confere o mesmo em toda gravação
/// (`coleta_de_teste::montada`).
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
/// inteiro, mesmo fora do anel — a coleta segura o ponteiro dele —, e é
/// devolvido depois, por ela, com a trava solta; o que saiu sem ser
/// copiado vira, na gravação seguinte, uma lacuna logo depois dele, contada
/// na auditoria perdida; e a cadeia refeita do journal é a da memória.
pub(super) fn o_anel_que_transborda_no_meio_da_coleta() -> Resultado {
    as_contas_veem_a_trava()?;
    anel_cheio_e_gravado()?;
    let desde = persistencia::auditoria_gravada();
    let mut copiado = desde;
    for _ in 0..40 {
        copiado = auditar("teste.coleta.copiado");
    }
    // O primeiro que a coleta vai copiar, sem segurá-lo.
    let primeiro = do_anel(desde + 1).ok_or("o primeiro pendente nao esta no anel")?;
    coleta_de_teste::zerar();
    coleta_de_teste::anexar_depois_da_proxima_copia(CAPACIDADE + 25);
    let perdida = crate::metricas::AUDITORIA_PERDIDA.load(SeqCst);
    alocacoes::vigiar(crate::fios::id_atual());
    let r = persistencia::gravar_auditoria();
    let pedidos = alocacoes::esquecer();
    let devolucoes = alocacoes::devolucoes();
    let (anexado, ultimo_anexado) = coleta_de_teste::anexados();
    let c = coleta_de_teste::contas();
    coleta_de_teste::zerar();
    r?;
    sem_memoria_com_a_trava(
        pedidos,
        devolucoes,
        "a coleta com o anel transbordando pediu ou devolveu memoria com a trava na mao",
    )?;
    // O copiado saiu do anel antes de ser montado, e foi montado inteiro.
    nada_copiado_de_fora(&c)?;
    // E foi devolvido: ninguém mais o segura. O anel o deixou no meio da
    // coleta, e a coleta, que o segurava por último, o soltou depois de
    // montá-lo — com a trava solta, que as contas acima não viram devolução
    // nenhuma com ela.
    if primeiro.upgrade().is_some() {
        return Err("o copiado que saiu do anel no meio da coleta nao foi devolvido");
    }
    // E quem o devolveu foi a coleta: o anel deixou cada copiado no meio
    // dela, e o ponteiro dela era o último de cada um.
    if c.montados == 0 || c.soltos_por_ultimo != c.montados {
        crate::log_error!(
            "teste",
            "{} montados, {} soltos por ultimo pela coleta",
            c.montados,
            c.soltos_por_ultimo
        );
        return Err("a coleta nao soltou por ultimo os copiados que o anel deixou no meio dela");
    }
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
/// Quantos registros cada produtor audita no caso que roda; quantos os
/// produtores já auditaram; e, no caso das compactações sob carga, em
/// quantos pontos da produção cada produtor espera uma compactação começar
/// — zero, em nenhum —, e quantas já começaram.
static POR_PRODUTOR_DO_CASO: AtomicU64 = AtomicU64::new(POR_PRODUTOR);
static PRODUZIDOS: AtomicU64 = AtomicU64::new(0);
static PAUSAS_DO_CASO: AtomicU64 = AtomicU64::new(0);
static COMPACTADAS: AtomicU64 = AtomicU64::new(0);
/// O caso manda o segundo coletor parar.
static PARAR: AtomicBool = AtomicBool::new(false);
/// As passadas do segundo coletor, e as que falharam.
static PASSADAS: AtomicU64 = AtomicU64::new(0);
static FALHAS: AtomicU64 = AtomicU64::new(0);

/// Um produtor: audita os registros do caso ([`POR_PRODUTOR_DO_CASO`]), com
/// o número dele e o de cada registro no detalhe, cedendo de vez em quando.
/// Com pausas ([`PAUSAS_DO_CASO`]), divide a produção em uma parte a mais
/// que elas e, no fim de cada parte menos a última, espera a compactação
/// daquela parte começar — até o caso mandar parar, ou 30 s.
extern "C" fn produtor(p: u64) -> ! {
    let n = POR_PRODUTOR_DO_CASO.load(SeqCst);
    let pausas = PAUSAS_DO_CASO.load(SeqCst);
    let parte = n / (pausas + 1);
    for i in 0..n {
        if pausas > 0 && parte > 0 && i > 0 && i.is_multiple_of(parte) && i / parte <= pausas {
            let limite = crate::tempo::uptime_ms() + 30_000;
            while COMPACTADAS.load(SeqCst) < i / parte
                && !PARAR.load(SeqCst)
                && crate::tempo::uptime_ms() < limite
            {
                crate::fios::ceder();
            }
        }
        crate::autorizacao::auditar_do_kernel(
            PRODUZIDO,
            "",
            politica::Codigo::Allow,
            &alloc::format!("{p} {i}"),
        );
        PRODUZIDOS.fetch_add(1, SeqCst);
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
    POR_PRODUTOR_DO_CASO.store(POR_PRODUTOR, SeqCst);
    PRODUZIDOS.store(0, SeqCst);
    PAUSAS_DO_CASO.store(0, SeqCst);
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

/// A compactação copia o anel como o coletor, numa tomada só: sem pedir nem
/// devolver memória com a trava da auditoria na mão, e codificando e
/// montando as entradas da base fora dela. A base leva, inteiro, o que o
/// anel tem até a gravada na tomada — contado nela, pela suíte. E o anel
/// que transborda logo depois da tomada não tira da base os registros
/// copiados: a compactação segura os ponteiros deles, os põe na base — lida
/// do disco, a marca e os copiados até a gravada — e os devolve depois,
/// com a trava solta; a cadeia refeita do journal continua a da memória.
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
    let (_, na_copia) = coleta_de_teste::compactada();
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
    // O anel guarda todos os copiados: a compactação não solta o último
    // ponteiro de nenhum — o controle da conta de baixo.
    if c.soltos_por_ultimo != 0 {
        crate::log_error!(
            "teste",
            "{} soltos por ultimo com o anel inteiro",
            c.soltos_por_ultimo
        );
        return Err("a compactacao contou como ultimo um ponteiro que o anel ainda guarda");
    }
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
    // Um anel inteiro auditado logo depois da tomada: os copiados saem do
    // anel antes de a base ser escrita, e vão nela assim mesmo — a
    // compactação, que os segura por último, os solta depois de pô-los na
    // base, com a trava solta.
    let mais_velho = do_anel(primeiro_no_anel()).ok_or("o anel da auditoria esta vazio")?;
    coleta_de_teste::zerar();
    coleta_de_teste::anexar_depois_da_proxima_copia(CAPACIDADE);
    alocacoes::vigiar(crate::fios::id_atual());
    let r = persistencia::compactar_de_teste();
    let pedidos = alocacoes::esquecer();
    let devolucoes = alocacoes::devolucoes();
    let c = coleta_de_teste::contas();
    let (na_compactacao, no_anel) = coleta_de_teste::compactada();
    coleta_de_teste::zerar();
    r?;
    sem_memoria_com_a_trava(
        pedidos,
        devolucoes,
        "a compactacao com o anel transbordando pediu ou devolveu memoria com a trava na mao",
    )?;
    nada_copiado_de_fora(&c)?;
    if primeiro_no_anel() <= gravada {
        return Err("o anel nao transbordou no meio da compactacao");
    }
    if mais_velho.upgrade().is_some() {
        return Err("o copiado que saiu do anel no meio da compactacao nao foi devolvido");
    }
    if c.soltos_por_ultimo != c.montados {
        crate::log_error!(
            "teste",
            "{} montados, {} soltos por ultimo pela compactacao",
            c.montados,
            c.soltos_por_ultimo
        );
        return Err(
            "a compactacao nao soltou por ultimo os copiados que o anel deixou no meio dela",
        );
    }
    if na_compactacao != gravada || no_anel == 0 || c.copiados != no_anel {
        crate::log_error!(
            "teste",
            "gravada {} (na compactacao {}); {} copiados de {} no anel",
            gravada,
            na_compactacao,
            c.copiados,
            no_anel
        );
        return Err("a base nao levou inteiro o que o anel tinha ate a gravada na tomada");
    }
    // A base, lida do disco: a marca até o de antes do primeiro copiado, e
    // os copiados — que o anel já não tem — até a gravada.
    a_base_e(gravada + 1 - no_anel, gravada)?;
    persistencia::gravar_auditoria()?;
    a_cadeia_do_journal_confere()
}

/// Quantos registros mínimos o caso do registro cheio deles audita: mais
/// que cabem num registro do journal.
const MINIMOS: u64 = 300;

/// O maior lote de ponteiros de uma cópia do coletor: quantos registros
/// mínimos cabem num registro do journal
/// ([`persistencia::MAIOR_AUDITORIA_POR_REGISTRO`], 16 KiB) — cada um com o
/// menor codificado ([`politica::auditoria::MENOR_CODIFICADO`]), o envelope
/// da entrada (o tipo, com o tamanho na frente, e o tamanho da codificação:
/// seis bytes) e os dois bytes do tamanho do campo: 71 bytes, 230 num
/// registro. A conta é a da suíte, e não a da cópia: uma cópia que contasse
/// errado levaria outro lote.
const MAIOR_LOTE: u64 = (persistencia::MAIOR_AUDITORIA_POR_REGISTRO
    / (2 + 6 + politica::auditoria::MENOR_CODIFICADO)) as u64;

/// Quantas vezes, ao todo, o caso do registro cheio de registros mínimos
/// tenta um lote inteiro: o que outro fio audita junto com os mínimos o
/// deixa menor se passar do mínimo, somado, em mais de 54 bytes — o que
/// sobra num registro de 230 mínimos.
const TENTATIVAS_DOS_MINIMOS: u32 = 4;

/// Um registro do journal cheio de registros mínimos — os cinco textos
/// vazios, o menor codificado —, o maior lote de ponteiros que uma cópia do
/// coletor pode copiar ([`MAIOR_LOTE`]): o lugar reservado antes da trava,
/// pela conta do menor codificado, cabe todos, e nada é pedido nem
/// devolvido ao alocador com ela. Um lugar menor que o lote faria o vetor
/// crescer com a trava na mão — os lotes dos outros casos, de registros
/// maiores, não chegam lá. A cópia leva os mínimos em lotes — o maior, de
/// [`MAIOR_LOTE`] —, cada um montado inteiro, e o journal segue sem pular
/// nem repetir. O que outro fio audita junto com os mínimos, se passar do
/// mínimo, somado, em mais de 54 bytes, deixa o lote menor: o caso tenta de
/// novo — até quatro tentativas ao todo —, e reprova sem nenhuma com o lote
/// inteiro; e um lote maior que a conta reprova logo.
pub(super) fn um_registro_cheio_de_registros_minimos() -> Resultado {
    as_contas_veem_a_trava()?;
    for tentativa in 1..=TENTATIVAS_DOS_MINIMOS {
        anel_cheio_e_gravado()?;
        let desde = persistencia::auditoria_gravada();
        let mut ultimo = desde;
        for _ in 0..MINIMOS {
            ultimo = crate::autorizacao::auditar_minimo_de_teste();
        }
        coleta_de_teste::zerar();
        alocacoes::vigiar(crate::fios::id_atual());
        let r = persistencia::gravar_auditoria();
        let pedidos = alocacoes::esquecer();
        let devolucoes = alocacoes::devolucoes();
        let c = coleta_de_teste::contas();
        coleta_de_teste::zerar();
        r?;
        sem_memoria_com_a_trava(
            pedidos,
            devolucoes,
            "a copia de registros minimos pediu ou devolveu memoria com a trava na mao",
        )?;
        nada_copiado_de_fora(&c)?;
        if c.maior_copia > MAIOR_LOTE || c.copias < 2 || c.sob_a_trava != 0 {
            crate::log_error!(
                "teste",
                "{} copias, a maior de {} registros (o lote inteiro e de {}); {} montados com a trava na mao",
                c.copias,
                c.maior_copia,
                MAIOR_LOTE,
                c.sob_a_trava
            );
            return Err(if c.maior_copia > MAIOR_LOTE {
                "a copia dos registros minimos passou do lote que cabe num registro do journal"
            } else {
                "os registros minimos nao encheram um registro do journal"
            });
        }
        let gravada = persistencia::auditoria_gravada();
        if gravada < ultimo {
            crate::log_error!("teste", "gravada {} de {}", gravada, ultimo);
            return Err("os registros minimos nao foram todos gravados");
        }
        let lacunas = seguidos(&do_journal_depois_de(desde)?, desde, ultimo)?;
        if !lacunas.is_empty() {
            return Err("o journal dos registros minimos tem uma lacuna");
        }
        if c.maior_copia == MAIOR_LOTE {
            return a_cadeia_do_journal_confere();
        }
        crate::log_info!(
            "teste",
            "tentativa {}: o maior lote foi de {} registros, e nao {} -- outro fio auditou no meio",
            tentativa,
            c.maior_copia,
            MAIOR_LOTE
        );
    }
    Err("os registros minimos nao encheram um registro do journal em nenhuma tentativa")
}

/// Quantos registros a suíte audita logo antes da tomada da compactação,
/// no caso do anel que perde registros ali.
const ANTES_DA_TOMADA: u64 = 5;

/// O anel perde registros entre a leitura da gravada e a tomada da
/// compactação: com ele cheio, os auditados ali, pelo gancho da suíte,
/// tiram da frente os mais antigos, de até a gravada. A cópia leva, inteiro,
/// o que o anel ainda tem até a gravada na tomada — contado nela —, e a
/// marca da base parte do primeiro copiado: a base é a marca de 1 ao de
/// antes dele, e os copiados, dele à gravada, um a um. A cadeia refeita
/// dela é a da memória, e o boot seguinte a adota — um registro fora de
/// sequência a deixaria recusada.
pub(super) fn o_anel_que_perde_registros_antes_da_tomada() -> Resultado {
    as_contas_veem_a_trava()?;
    anel_cheio_e_gravado()?;
    coleta_de_teste::zerar();
    coleta_de_teste::anexar_antes_da_tomada_da_proxima_compactacao(ANTES_DA_TOMADA);
    alocacoes::vigiar(crate::fios::id_atual());
    let r = persistencia::compactar_de_teste();
    let pedidos = alocacoes::esquecer();
    let devolucoes = alocacoes::devolucoes();
    let c = coleta_de_teste::contas();
    let (gravada, no_anel) = coleta_de_teste::compactada();
    let (anexado, ultimo_anexado) = coleta_de_teste::anexados();
    coleta_de_teste::zerar();
    r?;
    sem_memoria_com_a_trava(
        pedidos,
        devolucoes,
        "a compactacao pediu ou devolveu memoria com a trava da auditoria na mao",
    )?;
    // Os auditados antes da tomada tiraram da frente registros de até a
    // gravada: na tomada, o anel tem até ela menos que um anel inteiro.
    if anexado <= gravada || no_anel == 0 || no_anel + ANTES_DA_TOMADA > CAPACIDADE {
        crate::log_error!(
            "teste",
            "gravada {}; {} no anel na tomada; anexados desde {}",
            gravada,
            no_anel,
            anexado
        );
        return Err("o anel nao perdeu registros antes da tomada da compactacao");
    }
    // A cópia começa no primeiro que o anel tinha na tomada — contado sem a
    // conta da cópia: o anel cheio, logo depois do último que o gancho
    // auditou, guarda os `CAPACIDADE` até ele.
    let primeiro_na_tomada = (ultimo_anexado + 1).saturating_sub(CAPACIDADE);
    if gravada + 1 - no_anel != primeiro_na_tomada {
        crate::log_error!(
            "teste",
            "a copia desde {}; o anel desde {} na tomada",
            gravada + 1 - no_anel,
            primeiro_na_tomada
        );
        return Err("a copia da compactacao nao comecou no primeiro que o anel tinha na tomada");
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
        return Err("a base nao levou inteiro o que o anel tinha ate a gravada na tomada");
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

/// Quantos registros, além de um anel inteiro, a suíte audita sem gravar
/// antes da compactação do caso sem nenhum gravado no anel: os primeiros
/// depois da gravada saem do anel sem chegar ao journal.
const PERDIDOS_ANTES_DA_COMPACTACAO: u64 = 10;

/// A compactação com o anel sem nenhum registro até a gravada: mais que um
/// anel inteiro auditado depois dela, sem gravar, tirou da frente todos os
/// gravados — e os primeiros depois deles. A cópia não leva nada, e a base
/// é só a marca, de 1 à gravada, com o elo que a persistência guarda do
/// último gravado, lido do disco. A gravação seguinte continua dela: a
/// lacuna do que saiu do anel sem chegar ao journal, logo depois da
/// gravada e contada na auditoria perdida, e o resto. A cadeia refeita do
/// journal é a da memória, e o boot seguinte a adota.
pub(super) fn a_compactacao_sem_nenhum_gravado_no_anel() -> Resultado {
    as_contas_veem_a_trava()?;
    anel_cheio_e_gravado()?;
    let gravada = persistencia::auditoria_gravada();
    let elo = persistencia::elo_gravado_de_teste();
    while primeiro_no_anel() <= gravada + PERDIDOS_ANTES_DA_COMPACTACAO {
        auditar("teste.coleta.sem_gravado");
    }
    let perdida = crate::metricas::AUDITORIA_PERDIDA.load(SeqCst);
    // A compactação e a leitura da região com a ordem das gravações na
    // mão: nenhum gravador entra entre as duas.
    persistencia::em_ordem(|| -> Resultado {
        coleta_de_teste::zerar();
        alocacoes::vigiar(crate::fios::id_atual());
        let r = persistencia::compactar_de_teste();
        let pedidos = alocacoes::esquecer();
        let devolucoes = alocacoes::devolucoes();
        let c = coleta_de_teste::contas();
        let (na_compactacao, no_anel) = coleta_de_teste::compactada();
        coleta_de_teste::zerar();
        r?;
        sem_memoria_com_a_trava(
            pedidos,
            devolucoes,
            "a compactacao sem nenhum gravado no anel pediu ou devolveu memoria com a trava na mao",
        )?;
        if na_compactacao != gravada
            || no_anel != 0
            || c.copias != 1
            || c.copiados != 0
            || c.montados != 0
        {
            crate::log_error!(
                "teste",
                "gravada {} (na compactacao {}); {} no anel; {} copias, {} copiados, {} montados",
                gravada,
                na_compactacao,
                no_anel,
                c.copias,
                c.copiados,
                c.montados
            );
            return Err("a compactacao sem nenhum gravado no anel copiou alguma coisa");
        }
        // A base é só a marca, de 1 à gravada, com o elo do último gravado.
        let mut so_a_marca = true;
        persistencia::percorrer_a_auditoria_de_teste(|a| {
            if !matches!(a, AuditoriaNoJournal::Compactada(1, u) if u == gravada) {
                so_a_marca = false;
            }
        })?;
        if !so_a_marca || persistencia::marca_da_base_de_teste()? != Some((1, gravada, elo)) {
            return Err(
                "a base sem nenhum gravado no anel nao e so a marca ate a gravada, com o elo dela",
            );
        }
        Ok(())
    })?;
    // A gravação seguinte continua da marca: a lacuna do que saiu do anel
    // sem chegar ao journal, logo depois da gravada, e o resto.
    persistencia::gravar_auditoria()?;
    let depois = persistencia::auditoria_gravada();
    let perdidos = crate::metricas::AUDITORIA_PERDIDA.load(SeqCst) - perdida;
    let lacunas = seguidos(&do_journal_depois_de(gravada)?, gravada, depois)?;
    let certa = matches!(
        lacunas.as_slice(),
        [(primeira, ultima)] if *primeira == gravada + 1
            && *ultima >= gravada + PERDIDOS_ANTES_DA_COMPACTACAO
            && perdidos == ultima - primeira + 1
    );
    if !certa {
        crate::log_error!(
            "teste",
            "{} lacunas; {} perdidos; gravada {}",
            lacunas.len(),
            perdidos,
            gravada
        );
        return Err("o que saiu do anel antes da compactacao nao virou a lacuna depois da marca");
    }
    a_cadeia_do_journal_confere()?;
    // O boot seguinte adota a base, e a lacuna depois dela.
    reposto_da_imagem(persistencia::abrir);
    if persistencia::estado() != persistencia::Estado::Disponivel {
        return Err("o boot seguinte nao abriu o journal da base sem nenhum gravado");
    }
    a_cadeia_do_journal_confere()
}

/// Quantos registros cada produtor audita no caso das compactações sob
/// carga — juntos, três anéis ao menos —, e quantas compactações o caso
/// faz enquanto eles auditam.
const POR_PRODUTOR_SOB_CARGA: u64 = 1200;
const _: () = assert!(PRODUTORES * POR_PRODUTOR_SOB_CARGA >= 3 * CAPACIDADE);
const COMPACTACOES_SOB_CARGA: u64 = 3;

/// A compactação `k` do caso sob carga, com a ordem das gravações na mão
/// do começo ao fim — nenhum coletor grava entre ela e a leitura da base —
/// e este fio vigiado: nada pedido nem devolvido ao alocador com a trava na
/// mão, a cópia inteira e montada fora dela, e a base, lida do disco, a
/// marca até o de antes do primeiro copiado e os copiados até a gravada.
/// Os produtores, parados à espera dela, voltam a auditar noutros núcleos
/// quando ela começa; e o gancho da suíte audita um anel inteiro logo
/// depois da tomada: o anel tira da frente os copiados entre a tomada e a
/// base — com certeza, e não só se os produtores forem rápidos —, e a
/// compactação os devolve depois de pô-los nela.
fn compactar_sob_carga(k: u64) -> Resultado {
    persistencia::em_ordem(|| -> Resultado {
        // O mais velho do anel, com os produtores ainda parados.
        let mais_velho = do_anel(primeiro_no_anel()).ok_or("o anel da auditoria esta vazio")?;
        coleta_de_teste::zerar();
        // Um anel inteiro auditado logo depois da tomada, pelo gancho: o
        // anel dá a volta entre a tomada e a base, com os produtores
        // auditando também.
        coleta_de_teste::anexar_depois_da_proxima_copia(CAPACIDADE);
        COMPACTADAS.store(k, SeqCst);
        alocacoes::vigiar(crate::fios::id_atual());
        let r = persistencia::compactar_de_teste();
        let pedidos = alocacoes::esquecer();
        let devolucoes = alocacoes::devolucoes();
        let c = coleta_de_teste::contas();
        let (gravada, no_anel) = coleta_de_teste::compactada();
        coleta_de_teste::zerar();
        r?;
        sem_memoria_com_a_trava(
            pedidos,
            devolucoes,
            "uma compactacao sob carga pediu ou devolveu memoria com a trava na mao",
        )?;
        if c.copias != 1 || c.sob_a_trava != 0 || c.copiados != no_anel {
            crate::log_error!(
                "teste",
                "{} copias; {} copiados de {} no anel; {} montados com a trava na mao",
                c.copias,
                c.copiados,
                no_anel,
                c.sob_a_trava
            );
            return Err("uma compactacao sob carga nao copiou inteiro o anel ate a gravada");
        }
        nada_copiado_de_fora(&c)?;
        // Os copiados saíram do anel antes da base, e a compactação, que os
        // segurava por último, os devolveu depois de pô-los nela.
        if mais_velho.upgrade().is_some() || c.soltos_por_ultimo != c.montados {
            crate::log_error!(
                "teste",
                "{} montados, {} soltos por ultimo pela compactacao",
                c.montados,
                c.soltos_por_ultimo
            );
            return Err("uma compactacao sob carga nao devolveu os copiados que o anel deixou");
        }
        a_base_e(gravada + 1 - no_anel, gravada)
    })
}

/// Produtores em vários núcleos auditando sem folga — três anéis, juntos,
/// parados só no fim de cada parte, até a compactação dela começar —, três
/// coletores — o do kernel, solto; um segundo, noutro núcleo; e a suíte — e
/// compactações seguidas no meio: o anel dá a volta debaixo dos coletores e
/// das compactações, e uma compactação segura os ponteiros dos copiados
/// enquanto escreve a base. Cada base é inteira ([`compactar_sob_carga`]);
/// o journal segue da marca da última sem pular, repetir nem voltar — com
/// as lacunas do que o anel perdeu, e os registros de cada produtor na
/// ordem dele —; e a cadeia refeita do journal é a da memória, e é ela que
/// o boot seguinte refaz.
pub(super) fn compactacoes_com_produtores_e_coletores() -> Resultado {
    anel_cheio_e_gravado()?;
    let perdida = crate::metricas::AUDITORIA_PERDIDA.load(SeqCst);
    PARAR.store(false, SeqCst);
    PASSADAS.store(0, SeqCst);
    FALHAS.store(0, SeqCst);
    POR_PRODUTOR_DO_CASO.store(POR_PRODUTOR_SOB_CARGA, SeqCst);
    PRODUZIDOS.store(0, SeqCst);
    PAUSAS_DO_CASO.store(COMPACTACOES_SOB_CARGA, SeqCst);
    COMPACTADAS.store(0, SeqCst);
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
        // Cada compactação, quando os produtores chegam ao fim de uma parte
        // e esperam por ela.
        let parte = PRODUTORES * (POR_PRODUTOR_SOB_CARGA / (COMPACTACOES_SOB_CARGA + 1));
        let mut compactacoes = 0;
        let limite = crate::tempo::uptime_ms() + 60_000;
        while PRODUZINDO.load(SeqCst) != 0 {
            persistencia::gravar_auditoria()?;
            if compactacoes < COMPACTACOES_SOB_CARGA
                && PRODUZIDOS.load(SeqCst) >= (compactacoes + 1) * parte
            {
                compactacoes += 1;
                compactar_sob_carga(compactacoes)?;
            }
            if crate::tempo::uptime_ms() > limite {
                return Err("os produtores nao terminaram em 60 s");
            }
            crate::fios::ceder();
        }
        if compactacoes != COMPACTACOES_SOB_CARGA {
            crate::log_error!(
                "teste",
                "{} compactacoes de {}",
                compactacoes,
                COMPACTACOES_SOB_CARGA
            );
            return Err("as compactacoes nao aconteceram com os produtores auditando");
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
        // O journal, da marca da última base em diante: seguido, com as
        // lacunas do anel.
        let (_, marca, _) =
            persistencia::marca_da_base_de_teste()?.ok_or("a regiao nao comeca por uma base")?;
        let itens = do_journal_depois_de(marca)?;
        let lacunas = seguidos(&itens, marca, gravada)?;
        let perdidos = crate::metricas::AUDITORIA_PERDIDA.load(SeqCst) - perdida;
        let nas_lacunas: u64 = lacunas.iter().map(|(p, u)| u - p + 1).sum();
        if nas_lacunas > perdidos {
            crate::log_error!(
                "teste",
                "{} nas lacunas do journal; {} perdidos",
                nas_lacunas,
                perdidos
            );
            return Err("uma lacuna no journal que a auditoria perdida nao contou");
        }
        // Os de cada produtor: na ordem dele, sem repetir — os que saíram do
        // anel sem chegar ao journal estão nas lacunas.
        let mut ultimos = [None::<u64>; PRODUTORES as usize];
        for item in &itens {
            if let Item::Registro(_, Some((p, i))) = *item {
                let Some(ultimo) = ultimos.get_mut(p as usize) else {
                    return Err("um registro de um produtor que o caso nao tem");
                };
                if ultimo.is_some_and(|u| i <= u) {
                    crate::log_error!("teste", "produtor {}: o registro {} fora de ordem", p, i);
                    return Err("um registro de produtor repetiu ou saiu de ordem no journal");
                }
                *ultimo = Some(i);
            }
        }
        crate::log_info!(
            "teste",
            "coleta: {} registros de {} produtores sem folga; {} compactacoes; {} lacunas no journal desde a ultima, {} registros perdidos; {} passadas do segundo coletor",
            PRODUTORES * POR_PRODUTOR_SOB_CARGA,
            PRODUTORES,
            compactacoes,
            lacunas.len(),
            perdidos,
            PASSADAS.load(SeqCst)
        );
        a_cadeia_do_journal_confere()?;
        // O boot seguinte refaz, do journal, a mesma cadeia.
        reposto_da_imagem(persistencia::abrir);
        if persistencia::estado() != persistencia::Estado::Disponivel {
            return Err("o boot seguinte nao abriu o journal das compactacoes sob carga");
        }
        a_cadeia_do_journal_confere()
    })();
    PARAR.store(true, SeqCst);
    let _ = ate_zerar(&PRODUZINDO, 30_000);
    let _ = ate_zerar(&COLETANDO, 30_000);
    persistencia::pausar_a_auditoria_de_teste(true);
    POR_PRODUTOR_DO_CASO.store(POR_PRODUTOR, SeqCst);
    PAUSAS_DO_CASO.store(0, SeqCst);
    r
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
