//! Os casos `recolhimento:` — a ordem do recolhimento. A busca do próximo
//! morto começa no cursor e dá a volta pela tabela (ver "A ordem do
//! recolhimento" em `fios::recolher_terminados`): um titular que faz nascer
//! e morrer processos sem parar não segura os mortos de outro — o achado
//! A1-1. Antes do cursor, a busca começava sempre na vaga 0, e o nascimento
//! toma a primeira vaga vazia: o laço de um titular repunha os mortos dele
//! nas vagas de baixo que o recolhimento acabava de esvaziar, e os mortos
//! de outro, em vagas mais altas, esperavam enquanto o laço durasse.
//!
//! Três casos — o do laço de outro titular, o da tabela cheia e o do
//! encerramento — seguram o coletor do kernel ([`ColetorSegurado`]) e dão
//! um recolhimento por vez (`fios::recolher_um_de_teste`, o mesmo passo do
//! coletor) e, logo depois do que tira o morto do laço, um passo do laço: é
//! a ordem pior para os outros mortos — o laço repõe um morto embaixo entre
//! dois recolhimentos —, e o caso a escolhe, em vez de esperar que o tique
//! a dê. Com a busca voltando a começar na vaga 0, eles reprovam sempre, e
//! não por acaso. O da passada confere a mesma ordem na passada de produção
//! inteira (`fios::recolher_terminados_de_teste`), e não só no passo: os
//! mortos que podem sair quando ela começa saem nela, a partir do cursor. O
//! dos dois coletores solta tudo ao mesmo tempo — o coletor do kernel, um
//! segundo coletor e o laço de um titular — e encerra no meio dele os
//! processos de outro: confere que os mortos do outro saem com o laço
//! andando, que nada se perde, nada sai duas vezes e nenhuma vaga sobra; e
//! não a ordem, que o tique decide.
//!
//! Os titulares são pessoas de papel operador, com a cota em [`COTA`]: os
//! mortos de cada um contam na cota dele até o recolhimento (a 14.1,
//! alternativa 1). O laço é o `colhedor` dos casos `zumbis:` — bifurca, o
//! filho sai na hora, e colhe —, ou um `ola` que sai na hora.
//!
//! # O tamanho
//!
//! O kernel de teste de depuração do x86_64 mora perto do teto do
//! iniciador (`MAIOR_KERNEL`, 32 MiB), e o arquivo leva a tabela de
//! símbolos: cada instância genérica custa o código e um nome comprido.
//! Daí as esperas por `fn`, com uma instância só de `esperar_ate`
//! ([`ate`]); os laços simples no lugar dos adaptadores de iterador; o
//! passo a passo comum aos dois casos do laço ([`ate_sairem`]); e os
//! nomes curtos.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst};

use super::vagas::ColetorSegurado;
use super::zumbis::{
    BIFURCAR, Bifurcou, CANAL, COLHER, Colhedor, DO_FILHO, limpar, operador, politica_com_a_cota,
};
use super::{Resultado, esperar_ate, nucleos_secundarios, sem_mortos_por_recolher};
use crate::autorizacao::Autoridade;
use crate::fios::MAX_FIOS;
use protocolo::usuario::erro;
use protocolo::usuario::evento::{Evento, tipo};

/// A cota de processos dos titulares dos casos: o colhedor e três mortos.
const COTA: u32 = 4;

/// Quantos recolhimentos um caso do laço dá, no máximo, até os mortos do
/// outro titular saírem: com o cursor, bastam o do laço e um por morto; com
/// a busca na vaga 0, nenhum número basta.
const PASSOS: usize = 12;

// ---------------------------------------------------------------------------
// As esperas e o passo a passo
// ---------------------------------------------------------------------------

/// Espera `cond(x)` até 600 tiques; falha com `erro`. A única instância de
/// `esperar_ate` do módulo. A condição é conferida mais uma vez depois do
/// prazo: `esperar_ate` desiste sem conferi-la quando o prazo vence com o
/// fio da suíte dentro de `nativo::atender_pendentes`, servindo os pedidos
/// dos processos — medido em [`dois_coletores`], com a busca de antes do
/// cursor: uma chamada durou 569 tiques —, e a espera reprovava com a
/// condição já cumprida.
fn ate(cond: fn(u64) -> bool, x: u64, erro: &'static str) -> Resultado {
    match esperar_ate(|| cond(x), 600) {
        Err(_) if !cond(x) => Err(erro),
        _ => Ok(()),
    }
}

/// O fio `id` terminou e largou o núcleo.
fn esta_parado(id: u64) -> bool {
    matches!(crate::fios::retrato_de_teste(id), Some(r) if r.parado)
}

/// O fio `id` saiu da tabela.
fn fora_da_tabela(id: u64) -> bool {
    !crate::fios::na_tabela_de_teste(id)
}

/// Espera o fio `id` terminar e largar o núcleo.
fn parado(id: u64) -> Resultado {
    ate(esta_parado, id, "o processo do caso nao largou o nucleo")
}

/// A vaga do fio `id`.
fn vaga_de(id: u64) -> Result<usize, &'static str> {
    match crate::fios::retrato_de_teste(id) {
        Some(r) => Ok(r.vaga),
        None => Err("um fio do caso saiu da tabela com o coletor segurado"),
    }
}

/// Algum dos `ids` ainda está na tabela.
fn algum_na_tabela(ids: &[u64]) -> bool {
    for &id in ids {
        if crate::fios::na_tabela_de_teste(id) {
            return true;
        }
    }
    false
}

/// A morte de cada um dos `ids` foi solta uma vez.
fn uma_vez(ids: &[u64]) -> Resultado {
    for &id in ids {
        if crate::fios::limpezas_de(id) != Some(1) {
            return Err("a morte de um recolhido nao foi solta uma vez");
        }
    }
    Ok(())
}

/// O cursor passou para depois da `vaga` que o recolhimento acabou de
/// esvaziar.
fn cursor_depois_de(vaga: usize) -> bool {
    crate::fios::cursor_do_recolhimento_de_teste() == (vaga + 1) % MAX_FIOS
}

/// A primeira vaga vazia — a que o laço vai tomar — está na vaga `ate` ou
/// abaixo dela. Senão, um nascimento de fora do caso tomou a que o
/// recolhimento acabou de esvaziar, e o caso diz isso, e não o cursor.
fn vaga_do_laco(ate: usize) -> Resultado {
    match crate::fios::primeira_vaga_vazia_de_teste() {
        Some(v) if v <= ate => Ok(()),
        _ => Err("um nascimento de fora do caso tomou a vaga recolhida"),
    }
}

/// Um recolhimento, o mesmo passo do coletor: a vaga e o id do morto.
fn recolher() -> Result<(usize, u64), &'static str> {
    match crate::fios::recolher_um_de_teste() {
        Some(recolhido) => Ok(recolhido),
        None => Err("o recolhimento nao achou morto nenhum"),
    }
}

/// Um `ola` do `titular`, que sai na hora: o id dele, parado.
fn ola_morto(titular: Autoridade) -> Result<u64, &'static str> {
    let ola = alloc::format!("{}/ola", crate::usuario::DIRETORIO_DOS_COMPILADOS);
    let Ok(id) = crate::usuario::lancar_como(Some(&ola), titular) else {
        return Err("o ola nao nasceu");
    };
    parado(id)?;
    Ok(id)
}

/// O colhedor bifurca: o filho, já zumbi.
fn filho(c: &Colhedor) -> Result<u64, &'static str> {
    match c.bifurcar()? {
        Bifurcou::Filho(f) => Ok(f),
        Bifurcou::Erro(_) => Err("o colhedor nao bifurcou dentro da cota"),
    }
}

/// O colhedor colhe o `filho`, que fica na tabela, morto, à espera do
/// coletor.
fn colher(c: &Colhedor, filho: u64) -> Resultado {
    match c.colher()? {
        Ok((f, DO_FILHO)) if f == filho => parado(filho),
        _ => Err("o colhedor nao colheu o filho com o codigo dele"),
    }
}

/// O começo de todo caso: sem zumbi nem morto por recolher, ninguém vigiado
/// e a cota do operador em [`COTA`].
fn comecar() -> Resultado {
    if crate::fios::colheita().1 != 0 {
        return Err("a tabela ja tinha zumbi antes do caso comecar");
    }
    sem_mortos_por_recolher();
    crate::fios::vigiar_a_limpeza(u64::MAX);
    politica_com_a_cota(COTA)
}

/// O fim de todo caso: ninguém vigiado, o colhedor fora, e a política e as
/// pessoas como eram.
fn terminar(colhedor: Option<u64>) {
    crate::fios::vigiar_a_limpeza(u64::MAX);
    limpar(colhedor);
}

/// O passo a passo dos casos do laço, com o coletor do kernel segurado. O
/// morto do laço (`do_laco`, de A) está na vaga de baixo, e os mortos de B
/// (`de_b`), acima dela; o caso vigia a limpeza de cada um de B, põe o
/// cursor no fim da tabela e dá um recolhimento por vez até os de B saírem.
/// Quando sai o morto do laço, o `laco` anda — repõe um morto, que cai na
/// vaga de baixo ou abaixo dela, atrás do cursor, e passa a ser o do laço.
/// Um morto de fora do caso — um fio de um caso anterior que saiu no meio —
/// sai como os outros. Falha se os de B não saem em [`PASSOS`]
/// recolhimentos; e, se saem, confere que o cursor passou, a cada
/// recolhimento, para depois da vaga recolhida, que o laço andou, e que a
/// morte de cada um de B foi solta uma vez.
fn ate_sairem(
    de_b: &[u64],
    mut do_laco: u64,
    laco: &mut dyn FnMut() -> Result<u64, &'static str>,
) -> Resultado {
    let de_baixo = vaga_de(do_laco)?;
    for &m in de_b {
        if vaga_de(m)? <= de_baixo {
            return Err("um morto de B nao ficou acima da vaga do laco");
        }
        crate::fios::vigiar_tambem(m);
    }
    crate::fios::por_o_cursor_de_teste(MAX_FIOS - 1);
    let mut passos = 0;
    let mut voltas = 0;
    let mut cursor_parado = false;
    while algum_na_tabela(de_b) {
        if passos == PASSOS {
            return Err("os mortos de B esperaram o laco de A");
        }
        passos += 1;
        let (vaga, id) = recolher()?;
        cursor_parado |= !cursor_depois_de(vaga);
        if id == do_laco {
            vaga_do_laco(de_baixo)?;
            do_laco = laco()?;
            if vaga_de(do_laco)? > de_baixo {
                return Err("o morto novo do laco nao caiu na vaga de baixo");
            }
            voltas += 1;
        }
    }
    crate::log_info!(
        "teste",
        "recolhimento: o laco na vaga {}; {} recolhimentos, {} voltas do laco",
        de_baixo,
        passos,
        voltas
    );
    if cursor_parado {
        return Err("o cursor nao passou para depois da vaga recolhida");
    }
    if voltas == 0 {
        return Err("o laco de A nao andou entre os recolhimentos");
    }
    uma_vez(de_b)
}

// ---------------------------------------------------------------------------
// recolhimento: os mortos de um titular saem com o laco de outro
// ---------------------------------------------------------------------------

/// O laço de A — o colhedor bifurca e colhe; o filho colhido guarda a vaga
/// até o recolhimento — e dois mortos de B, dois `ola` que saíram, em vagas
/// acima da do laço. Com o coletor do kernel segurado, o caso põe o cursor
/// no fim da tabela e dá um recolhimento por vez ([`ate_sairem`]): o
/// primeiro dá a volta e tira o morto de A; A bifurca e colhe de novo — o
/// filho novo cai embaixo, na vaga que acabou de esvaziar —; e os dois
/// mortos de B saem nos recolhimentos seguintes. A morte de cada um é solta
/// uma vez. Com a busca começando na vaga 0, cada recolhimento tirava o
/// morto novo de A, e os de B esperavam enquanto o laço durasse.
pub(super) fn laco_de_outro() -> Resultado {
    comecar()?;
    let a = operador(0, "pessoa-do-laco");
    let b = operador(1, "pessoa-dos-mortos");
    let mut fio = None;
    let r = (|| -> Resultado {
        let c = Colhedor::lancar(a)?;
        fio = Some(c.fio);
        let _segurado = ColetorSegurado::segurar();
        // O primeiro filho de A, zumbi, toma a vaga vazia de baixo: os
        // mortos de B nascem acima dela.
        let primeiro = filho(&c)?;
        let de_b = [ola_morto(b)?, ola_morto(b)?];
        colher(&c, primeiro)?;
        ate_sairem(&de_b, primeiro, &mut || {
            let novo = filho(&c)?;
            colher(&c, novo)?;
            Ok(novo)
        })
    })();
    terminar(fio);
    r
}

// ---------------------------------------------------------------------------
// recolhimento: a tabela cheia da a volta
// ---------------------------------------------------------------------------

/// Um fio do kernel que sai assim que roda.
extern "C" fn morre_na_hora(_argumento: u64) -> ! {
    crate::fios::terminar()
}

/// Com o coletor do kernel segurado, fios do kernel que saem na hora enchem
/// a tabela, e o colhedor de A não bifurca: não há vaga. O caso põe o cursor
/// perto do fim da tabela e dá um recolhimento por vez; depois de cada um
/// dos três primeiros, A bifurca e colhe — o filho cai na única vaga vazia,
/// a que acabou de esvaziar, e fica nela, morto. Os mortos da tabela saem
/// numa volta só, em ordem, do cursor ao fim e do começo até antes dele, e
/// antes de qualquer morto novo do laço; a morte de cada um já foi solta,
/// uma vez, quando a vaga dele volta; e os mortos do laço saem na volta
/// seguinte. Com a busca na vaga 0, o filho de A tomava a vaga mais baixa
/// e era o próximo recolhido.
pub(super) fn tabela_cheia() -> Resultado {
    comecar()?;
    let a = operador(0, "pessoa-do-laco");
    let mut fio = None;
    let r = (|| -> Resultado {
        let c = Colhedor::lancar(a)?;
        fio = Some(c.fio);
        let _segurado = ColetorSegurado::segurar();
        let mut da_tabela = Vec::new();
        while da_tabela.len() <= MAX_FIOS {
            let Ok(id) = crate::fios::criar("teste-recolhimento-morto", morre_na_hora, 0) else {
                break;
            };
            crate::fios::vigiar_tambem(id.numero());
            da_tabela.push(id.numero());
        }
        for &m in &da_tabela {
            parado(m)?;
        }
        if c.bifurcar()? != Bifurcou::Erro(erro::SEM_VAGA_DE_FIO) {
            return Err("a tabela nao ficou cheia de mortos");
        }
        let inicio = MAX_FIOS - 2;
        crate::fios::por_o_cursor_de_teste(inicio);
        let mut do_laco = Vec::new();
        let mut passos = 0;
        let mut ultima = 0;
        let mut cursor_parado = false;
        while algum_na_tabela(&da_tabela) {
            let (vaga, id) = recolher()?;
            // Uma volta, em ordem: contadas a partir do início, as vagas
            // recolhidas só crescem — e uma volta não passa da tabela.
            let posicao = (vaga + MAX_FIOS - inicio) % MAX_FIOS;
            if passos > 0 && posicao <= ultima {
                return Err("o recolhimento nao deu a volta pela tabela em ordem");
            }
            passos += 1;
            ultima = posicao;
            cursor_parado |= !cursor_depois_de(vaga);
            if do_laco.contains(&id) {
                return Err("um morto novo do laco saiu antes dos mortos da tabela");
            }
            if da_tabela.contains(&id) && crate::fios::limpezas_de(id) != Some(1) {
                return Err("a vaga voltou sem a morte do recolhido solta uma vez");
            }
            if do_laco.len() + 1 < COTA as usize {
                vaga_do_laco(vaga)?;
                let novo = filho(&c)?;
                if vaga_de(novo)? != vaga {
                    return Err("o filho de A nao caiu na vaga que o recolhimento esvaziou");
                }
                colher(&c, novo)?;
                crate::fios::vigiar_tambem(novo);
                do_laco.push(novo);
            }
        }
        crate::log_info!(
            "teste",
            "recolhimento: {} mortos encheram a tabela; {} recolhimentos na volta",
            da_tabela.len(),
            passos
        );
        if cursor_parado {
            return Err("o cursor nao passou para depois da vaga recolhida");
        }
        for _ in 0..MAX_FIOS {
            if !algum_na_tabela(&do_laco) || crate::fios::recolher_um_de_teste().is_none() {
                break;
            }
        }
        if algum_na_tabela(&do_laco) {
            return Err("os mortos do laco nao sairam na volta seguinte");
        }
        uma_vez(&da_tabela)?;
        uma_vez(&do_laco)
    })();
    terminar(fio);
    r
}

// ---------------------------------------------------------------------------
// recolhimento: a passada recolhe a partir do cursor
// ---------------------------------------------------------------------------

/// Segura de pé o fio do meio do caso da passada ([`de_pe`]).
static DE_PE: AtomicBool = AtomicBool::new(false);

/// Um fio do kernel que fica de pé até o caso o soltar: guarda a vaga do
/// meio, entre os dois mortos da passada.
extern "C" fn de_pe(_argumento: u64) -> ! {
    while DE_PE.load(SeqCst) {
        crate::fios::descansar_ate_a_interrupcao();
    }
    crate::fios::terminar()
}

/// Um fio do kernel do caso da passada, que roda `entrada`: o id dele.
fn fio_do_caso(entrada: extern "C" fn(u64) -> !) -> Result<u64, &'static str> {
    match crate::fios::criar("teste-recolhimento-passada", entrada, 0) {
        Ok(id) => Ok(id.numero()),
        Err(_) => Err("um fio do caso nao nasceu"),
    }
}

/// A passada do coletor, a de produção — o corpo de `recolher_terminados`
/// (`fios::recolher_terminados_de_teste`), com o coletor do kernel
/// segurado: dois fios do kernel que saem na hora e, entre as vagas deles,
/// um que fica de pé ([`de_pe`]); o cursor na vaga do morto de cima. Uma
/// passada recolhe os dois mortos — o que pode sair quando ela começa sai
/// nela —, a partir do cursor e dando a volta: o de cima, depois o de
/// baixo; e o cursor fica logo depois da vaga de baixo. O fio de pé separa
/// essa vaga da de cima: o cursor parado, ou devolvido onde estava, também
/// reprova. Com o cursor zerado a cada recolhimento da passada, ou com a
/// busca de antes, a ordem era a das vagas, e o cursor ficava depois da de
/// cima, em zero ou parado; com uma passada que recolhe um só, o de baixo
/// ficava. Os casos do laço conferem a ordem no passo; este, na passada.
pub(super) fn a_passada() -> Resultado {
    comecar()?;
    DE_PE.store(true, SeqCst);
    let mut meio = 0;
    let r = (|| -> Resultado {
        let _segurado = ColetorSegurado::segurar();
        let baixo = fio_do_caso(morre_na_hora)?;
        meio = fio_do_caso(de_pe)?;
        let alto = fio_do_caso(morre_na_hora)?;
        let mortos = [baixo, alto];
        for &m in &mortos {
            crate::fios::vigiar_tambem(m);
            parado(m)?;
        }
        let (a, m, b) = (vaga_de(baixo)?, vaga_de(meio)?, vaga_de(alto)?);
        if !(a < m && m < b) {
            return Err("as vagas do caso nao ficaram em ordem");
        }
        crate::fios::por_o_cursor_de_teste(b);
        crate::fios::recolher_terminados_de_teste();
        if algum_na_tabela(&mortos) {
            return Err("a passada nao recolheu os mortos que podiam sair");
        }
        if !cursor_depois_de(a) {
            return Err("a passada nao recolheu a partir do cursor");
        }
        uma_vez(&mortos)
    })();
    DE_PE.store(false, SeqCst);
    if meio != 0 {
        let _ = parado(meio);
    }
    terminar(None);
    r
}

// ---------------------------------------------------------------------------
// recolhimento: o encerramento no meio do laco
// ---------------------------------------------------------------------------

/// O laço de A é o do `user.run`: um `ola` que sai na hora, um depois do
/// outro, cada um na vaga vazia de baixo. B lança o colhedor, que bifurca
/// dois filhos — zumbis — acima da vaga do laço, e é encerrado no meio,
/// pelo caminho do `process.terminate` (`contencao::encerrar_processo`): o
/// colhedor morre, e os filhos deixam de ser zumbis — o pai acabou. Com o
/// coletor segurado, um recolhimento por vez, alternando com o laço
/// ([`ate_sairem`]): os três mortos de B saem logo depois do primeiro morto
/// do laço, e a morte de cada um é solta uma vez.
pub(super) fn encerramento() -> Resultado {
    comecar()?;
    let a = operador(0, "pessoa-do-laco");
    let b = operador(1, "pessoa-encerrada");
    let mut fio = None;
    let r = (|| -> Resultado {
        let _segurado = ColetorSegurado::segurar();
        let primeiro = ola_morto(a)?;
        let c = Colhedor::lancar(b)?;
        fio = Some(c.fio);
        let de_b = [c.fio, filho(&c)?, filho(&c)?];
        if crate::contencao::encerrar_processo(c.fio).is_err() {
            return Err("o encerramento foi recusado");
        }
        for &m in &de_b {
            parado(m)?;
            if crate::fios::zumbi_de_teste(m) {
                return Err("um filho do encerrado seguiu zumbi");
            }
        }
        ate_sairem(&de_b, primeiro, &mut || ola_morto(a))
    })();
    terminar(fio);
    r
}

// ---------------------------------------------------------------------------
// recolhimento: dois coletores e o laco ao mesmo tempo
// ---------------------------------------------------------------------------

static PARAR: AtomicBool = AtomicBool::new(false);
static VIVOS: AtomicUsize = AtomicUsize::new(0);
static PASSADAS: AtomicU64 = AtomicU64::new(0);

/// Quantos passos o laço de A dá, no máximo — um de bifurcar e um de
/// colher por tique em que o fio dele roda: ele divide o núcleo com o
/// segundo coletor e não roda em todo tique, e o laço dura mais tiques que
/// isso. É só o teto de segurança do trabalho do caso: cada passo do
/// colhedor é uma linha na serial e na tela, com as interrupções
/// mascaradas, e um laço sem teto prendeu a suíte na CI 444 (ver `zumbis: a
/// cota vale com tudo ao mesmo tempo`). Quem para o laço é o caso, com
/// [`PARAR`], logo depois de os mortos de B saírem e de A bifurcar mais uma
/// vez; o teto fica longe disso. Com 150, o laço acabava antes do
/// encerramento de B quando o fio da suíte demorava a chegar a ele, e o
/// caso reprovava sem defeito nenhum no recolhimento — na CI 456, com o
/// código certo. Com 3000, a folga era pouca: numa rodada das campanhas
/// das mutações, o caso só parou o laço mais de 3010 tiques depois de
/// lançá-lo — o fio da suíte levou 2498 tiques, 25 segundos, até o
/// encerramento de B, e os mortos dele, mais 512 para sair.
const TIQUES_DO_LACO: u64 = 10_000;

/// O corpo dos fios do caso: `passo` no máximo uma vez por tique, até
/// [`PARAR`] ou `teto` passos, descansando entre um tique e outro — sem o
/// ritmo do tique, o fio que descansa cede a vez ao outro fio do caso no
/// mesmo núcleo, e os dois giram sem parar.
fn a_cada_tique(teto: u64, passo: fn()) {
    let mut ultimo = crate::tempo::ticks();
    let mut dados = 0;
    while !PARAR.load(SeqCst) && dados < teto {
        let agora = crate::tempo::ticks();
        if agora != ultimo {
            ultimo = agora;
            dados += 1;
            passo();
        }
        crate::fios::descansar_ate_a_interrupcao();
    }
    VIVOS.fetch_sub(1, SeqCst);
}

/// Uma passada do segundo coletor.
fn passada() {
    crate::fios::recolher_terminados();
    PASSADAS.fetch_add(1, SeqCst);
}

/// Um passo do laço de A: bifurcar e colher, no canal do colhedor, sem
/// esperar a resposta — se a fila dele tem lugar.
fn passo_do_laco() {
    for a in [BIFURCAR, COLHER] {
        let _ = crate::eventos::publicar(
            CANAL,
            Evento {
                tipo: tipo::ACAO,
                a,
                ..Default::default()
            },
        );
    }
}

/// O segundo coletor: recolhe ao mesmo tempo que o do kernel, dividindo o
/// cursor com ele.
extern "C" fn outro_coletor(_argumento: u64) -> ! {
    a_cada_tique(u64::MAX, passada);
    crate::fios::terminar()
}

/// O laço de A, até [`TIQUES_DO_LACO`].
extern "C" fn alimentar_o_laco(_argumento: u64) -> ! {
    a_cada_tique(TIQUES_DO_LACO, passo_do_laco);
    crate::fios::terminar()
}

/// Um fio do caso, no `nucleo`, contado em [`VIVOS`] até sair.
fn no_nucleo(nome: &'static str, entrada: extern "C" fn(u64) -> !, nucleo: usize) -> Resultado {
    VIVOS.fetch_add(1, SeqCst);
    if crate::fios::criar_no_nucleo(nome, entrada, 0, nucleo).is_err() {
        VIVOS.fetch_sub(1, SeqCst);
        return Err("um fio do caso nao nasceu");
    }
    Ok(())
}

/// Os fios do caso terminaram.
fn sem_os_fios_do_caso(_: u64) -> bool {
    VIVOS.load(SeqCst) == 0
}

/// O kernel já contou `n` bifurcações.
fn bifurcacoes_ate(n: u64) -> bool {
    crate::usuario::estatisticas_de_processo().0 >= n
}

/// Quantas bifurcações o kernel contou.
fn bifurcacoes() -> u64 {
    crate::usuario::estatisticas_de_processo().0
}

/// O coletor recolheu os mortos, e as vagas livres voltaram — pelo menos as
/// `livres` de antes.
fn vagas_de_volta(livres: u64) -> bool {
    sem_mortos_por_recolher();
    crate::fios::vagas_livres_de_teste() as u64 >= livres
}

/// Tudo solto, ao mesmo tempo. B ocupa a cota inteira com processos de pé —
/// [`COTA`] `encerravel`, e o seguinte é recusado pela cota —; e então o
/// coletor do kernel e um segundo coletor, um fio da suíte noutro núcleo,
/// dividem o cursor, e o colhedor de A bifurca e colhe sem parar, um passo
/// por tique. Com o laço de A andando, B é encerrado pelo caminho do
/// `process.terminate` (`contencao::encerrar_processo`): os mortos de B saem
/// da tabela, a cota dele volta a zero, e o laço de A segue andando depois.
/// No fim, a morte de cada um de B foi solta uma vez — nenhuma perdida,
/// nenhuma em dobro, com dois coletores —, e não sobra morto, zumbi nem
/// vaga. A ordem do recolhimento, quem a confere são os casos passo a passo
/// e o da passada: solto, o tique decide quem anda primeiro, e os coletores
/// são mais rápidos que o laço.
pub(super) fn dois_coletores() -> Resultado {
    let Some(nucleo) = nucleos_secundarios().next() else {
        crate::log_info!("teste", "um nucleo so: nada corre ao mesmo tempo");
        return Ok(());
    };
    comecar()?;
    let livres_antes = crate::fios::vagas_livres_de_teste();
    let a = operador(0, "pessoa-do-laco");
    let b = operador(1, "pessoa-encerrada");
    let encerravel = alloc::format!("{}/encerravel", crate::usuario::DIRETORIO_DOS_COMPILADOS);
    PARAR.store(false, SeqCst);
    VIVOS.store(0, SeqCst);
    PASSADAS.store(0, SeqCst);
    let mut fio = None;
    let r = (|| -> Resultado {
        let c = Colhedor::lancar(a)?;
        fio = Some(c.fio);
        let mut de_b = Vec::new();
        for _ in 0..COTA {
            let Ok(id) = crate::usuario::lancar_como(Some(&encerravel), b) else {
                return Err("um processo de B nao nasceu");
            };
            crate::fios::vigiar_tambem(id);
            de_b.push(id);
        }
        if crate::usuario::lancar_como(Some(&encerravel), b) != Err(crate::fios::COTA_ESGOTADA) {
            return Err("B passou da cota antes do laco");
        }
        let antes = bifurcacoes();
        let comeco = crate::tempo::ticks();
        no_nucleo("teste-recolhimento-coletor", outro_coletor, nucleo)?;
        no_nucleo("teste-recolhimento-laco", alimentar_o_laco, nucleo)?;
        ate(bifurcacoes_ate, antes + 4, "o laco de A nao andou")?;
        for &id in &de_b {
            if crate::contencao::encerrar_processo(id).is_err() {
                return Err("o encerramento de B foi recusado");
            }
        }
        let no_encerramento = bifurcacoes();
        let encerrado = crate::tempo::ticks();
        for &id in &de_b {
            ate(fora_da_tabela, id, "um morto de B esperou o laco de A")?;
        }
        let na_saida = bifurcacoes();
        let sairam = crate::tempo::ticks();
        if crate::fios::contas_da_cota_de_teste(b) != (0, 0) {
            return Err("a cota de B nao voltou com os mortos dele recolhidos");
        }
        ate(
            bifurcacoes_ate,
            na_saida + 1,
            "o laco de A parou com os mortos de B",
        )?;
        PARAR.store(true, SeqCst);
        ate(sem_os_fios_do_caso, 0, "um fio do caso nao parou")?;
        c.encerrar()?;
        crate::log_info!(
            "teste",
            "recolhimento: o laco de A andou {} tiques e {} bifurcacoes ate o encerramento de B; \
             os mortos de B sairam em {} tiques, com {} bifurcacoes de A no meio; {} passadas do \
             segundo coletor",
            encerrado - comeco,
            no_encerramento - antes,
            sairam - encerrado,
            na_saida - no_encerramento,
            PASSADAS.load(SeqCst)
        );
        if PASSADAS.load(SeqCst) == 0 {
            return Err("o segundo coletor nao passou");
        }
        uma_vez(&de_b)?;
        ate(
            vagas_de_volta,
            livres_antes as u64,
            "sobrou vaga ocupada depois do fim",
        )
    })();
    PARAR.store(true, SeqCst);
    let _ = ate(sem_os_fios_do_caso, 0, "");
    terminar(fio);
    r
}
