//! Os casos do que muda no meio do nascimento de um processo, e do fio que
//! para a máquina: três das correções de implementação, sem semântica nova,
//! do item *A soma das cotas de processos e a cota por sessão*, no README.
//!
//! - (1) O fio `energia` nasce no boot, parado, e o `system.reboot` só o
//!   acorda. Nascia a cada pedido, depois de o registro ir ao journal: com a
//!   tabela de fios cheia, o pedido gravado falhava sem parar a máquina.
//! - (3) A contenção de quem bifurca é conferida de novo no nascimento do
//!   filho, antes de ele poder rodar: um `process.isolate` no meio do `fork`
//!   não deixa nascer um filho livre de um processo isolado.
//! - (4) O `process.terminate` de um processo que ainda nasce chega ao fio
//!   definitivo: ele morre no primeiro ponto seguro, e o contador dos
//!   términos pendentes volta ao que era — também quando a vaga volta sem
//!   ele nascer.
//!
//! A janela da (3) e da (4) é a de copiar um espaço e mapear uma pilha, e um
//! pedido de outro fio só cai nela por acaso. Os casos a abrem no ponto
//! exato, pelo gancho do meio do nascimento
//! (`fios::no_meio_do_nascimento_de_teste`): o que os handlers de
//! `process.isolate` e de `process.terminate` fazem depois do gate —
//! `contencao::conter` e `contencao::encerrar_processo` — roda ali, com a
//! vaga do processo reservada e antes da última palavra de quem o cria. O
//! gancho roda no fio de quem cria — o do comando, num `user.run`; o do
//! processo, dentro da chamada, num `fork` —, uma vez.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};

use super::{
    ENCERRAVEL_FILHO, Encerravel, Resultado, encerrar_os_encerraveis, energia_entregue,
    esperar_ate, esperar_cedendo, fs_numero, fs_pedir, fs_texto, linhas_do_programa,
    linhas_que_comecam, operador_que_lanca, registros_depois, sistema_aqui,
};
use crate::contencao::Alvo;
use protocolo::usuario::erro;

// ---------------------------------------------------------------------------
// (1) o fio da energia, com a tabela de fios cheia
// ---------------------------------------------------------------------------

/// Os fios que enchem a tabela: cedem até o caso soltá-los.
static SOLTAR: AtomicBool = AtomicBool::new(false);
/// Quantos ainda não saíram.
static OCUPANTES: AtomicU64 = AtomicU64::new(0);

extern "C" fn ocupante(_argumento: u64) -> ! {
    while !SOLTAR.load(SeqCst) {
        crate::fios::ceder();
    }
    OCUPANTES.fetch_sub(1, SeqCst);
    crate::fios::terminar()
}

/// O fio `energia` da tabela — o número e o estado —, se há um, e só um.
fn fio_da_energia() -> Option<(u64, &'static str)> {
    let mut achados = 0;
    let mut visto = None;
    crate::fios::com_inscricoes(|i| {
        if i.nome == "energia" {
            achados += 1;
            visto = Some((i.id, i.estado));
        }
    });
    if achados == 1 { visto } else { None }
}

/// A correção (1): com a tabela de fios cheia — fios do kernel até não
/// haver vaga —, o `system.reboot` do sistema é aceito, com o registro no
/// journal, e o fio `energia`, o do boot, que esperava parado, chega ao fim
/// da ação e volta a esperar: nenhum fio nasce para o pedido. Antes, o
/// pedido gravado no journal criava o fio, e com a tabela cheia a resposta
/// era "nao ha vaga livre para outro fio", com a máquina seguindo.
pub(super) fn energia_o_reinicio_com_a_tabela_de_fios_cheia() -> Resultado {
    let _ = crate::energia::executada_de_teste();
    // O fio do boot, parado: o caso anterior pode tê-lo deixado voltando à
    // espera.
    let parado = |f: Option<(u64, &'static str)>| f.is_some_and(|(_, e)| e == "waiting");
    let _ = esperar_cedendo(|| parado(fio_da_energia()), 300);
    let antes = fio_da_energia();
    let livres_antes = crate::fios::vagas_livres_de_teste();
    SOLTAR.store(false, SeqCst);
    OCUPANTES.store(0, SeqCst);
    let mut criados = 0usize;
    let mut outra = None;
    for _ in 0..crate::fios::MAX_FIOS {
        match crate::fios::criar("teste-tabela-cheia", ocupante, 0) {
            Ok(_) => {
                OCUPANTES.fetch_add(1, SeqCst);
                criados += 1;
            }
            Err(motivo) if motivo.contains("vaga") => break,
            Err(motivo) => {
                outra = Some(motivo);
                break;
            }
        }
    }
    let resultado = (|| -> Resultado {
        if let Some(motivo) = outra {
            crate::log_error!("teste", "a criacao recusou: {}", motivo);
            return Err("um fio nao nasceu por outro motivo que a falta de vaga");
        }
        if criados == 0 || crate::fios::vagas_livres_de_teste() != 0 {
            return Err("a tabela de fios nao encheu");
        }
        let segura = crate::energia::Segura::de_teste();
        let r = fs_pedir(sistema_aqui(), "system.reboot", "{}");
        let cheia = crate::fios::vagas_livres_de_teste() == 0;
        let aceito = fs_numero(&r, "record").is_some()
            && fs_texto(&r, "state").as_deref() == Some("rebooting");
        drop(segura);
        let entregue = if aceito { energia_entregue() } else { None };
        crate::log_info!(
            "teste",
            "energia: {} fios encheram a tabela; o system.reboot {}; entregue {:?}",
            criados,
            if aceito { "aceito" } else { r.as_str() },
            entregue
        );
        if !aceito {
            return Err("com a tabela de fios cheia, o system.reboot nao foi aceito");
        }
        if !cheia {
            return Err("a tabela de fios nao ficou cheia durante o pedido");
        }
        if entregue != Some(crate::energia::Acao::Reiniciar) {
            return Err("o reinicio com a tabela cheia nao chegou ao fim");
        }
        Ok(())
    })();
    SOLTAR.store(true, SeqCst);
    let sairam = esperar_cedendo(|| OCUPANTES.load(SeqCst) == 0, 600)
        .map_err(|_| "os fios que enchiam a tabela nao sairam");
    let recolhidos = esperar_cedendo(|| crate::fios::vagas_livres_de_teste() >= livres_antes, 600)
        .map_err(|_| "as vagas dos fios que enchiam a tabela nao voltaram");
    resultado?;
    sairam?;
    recolhidos?;
    // O fio é o do boot, parado de novo: o mesmo antes e depois.
    let _ = esperar_cedendo(|| parado(fio_da_energia()), 300);
    let depois = fio_da_energia();
    if !parado(antes) || !parado(depois) || antes.map(|f| f.0) != depois.map(|f| f.0) {
        crate::log_error!(
            "teste",
            "o fio da energia: antes {:?}, depois {:?}",
            antes,
            depois
        );
        return Err("o fio da energia nao e o do boot, parado");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// (3) e (4): o que muda no meio do nascimento
// ---------------------------------------------------------------------------

/// O processo que o gancho isola — quem bifurca —, ou zero.
static ISOLAR: AtomicU64 = AtomicU64::new(0);
/// Se o gancho isolou.
static ISOLOU: AtomicBool = AtomicBool::new(false);
/// O fio que o gancho viu nascer, ou zero.
static NASCENDO: AtomicU64 = AtomicU64::new(0);
/// O estado que o pedido de término do processo que nascia respondeu.
static ESTAVA: crate::trava::Mutex<&'static str> = crate::trava::Mutex::new("");

fn estava() -> &'static str {
    crate::arch::sem_interrupcoes(|| *ESTAVA.lock())
}

/// Arma o gancho do meio do nascimento com `f`, do zero.
fn armar(f: fn(u64), isolar: u64) {
    ISOLOU.store(false, SeqCst);
    NASCENDO.store(0, SeqCst);
    ISOLAR.store(isolar, SeqCst);
    crate::arch::sem_interrupcoes(|| *ESTAVA.lock() = "");
    crate::fios::no_meio_do_nascimento_de_teste(Some(f));
}

/// Isola quem bifurca, como o handler de `process.isolate` faz depois do
/// gate.
fn isolar_o_pai() {
    let pai = ISOLAR.swap(0, SeqCst);
    if pai != 0 && crate::contencao::conter(&Alvo::Processo(pai)).is_ok_and(|f| f.mudou) {
        ISOLOU.store(true, SeqCst);
    }
}

/// Encerra o processo `fio`, que nasce, como o handler de
/// `process.terminate` faz depois do gate, e guarda o que o pedido
/// respondeu.
fn encerrar(fio: u64) {
    let estava = crate::contencao::encerrar_processo(fio).map_or("recusado", |f| f.estava);
    crate::arch::sem_interrupcoes(|| *ESTAVA.lock() = estava);
}

// Os ganchos: o fio que nasce é dito por último — o caso que espera por ele
// acha o resto já feito, mesmo com o gancho rodando noutro núcleo, dentro
// do `fork` do pai.

/// No meio do nascimento do filho: isola quem bifurca.
fn isolar_quem_bifurca(filho: u64) {
    isolar_o_pai();
    NASCENDO.store(filho, SeqCst);
}

/// No meio do nascimento: encerra o processo que nasce.
fn encerrar_quem_nasce(fio: u64) {
    encerrar(fio);
    NASCENDO.store(fio, SeqCst);
}

/// No meio do nascimento do filho: encerra o filho que nasce e isola quem
/// bifurca, no mesmo instante.
fn encerrar_o_filho_e_isolar_o_pai(filho: u64) {
    encerrar(filho);
    isolar_o_pai();
    NASCENDO.store(filho, SeqCst);
}

/// A linha do `encerravel` cujo `fork` foi recusado.
fn bifurcar_negado() -> alloc::string::String {
    alloc::format!("encerravel: bifurcar devolveu {}", erro::NEGADO)
}

/// A correção (3): o `encerravel` bifurca, e o gancho do meio do nascimento
/// o isola depois de o gate deixar o `fork` passar — com o espaço copiado e
/// a vaga do filho reservada. O filho não nasce: a chamada ouve `NEGADO`, a
/// recusa vai à auditoria como a do gate (`process.fork`,
/// `DENY_CONTAINED`, "processo isolado"), sem o registro do nascimento, a
/// vaga volta, e o pai sai com o código do `fork` recusado. Sem a
/// conferência no nascimento, o filho de um processo isolado nascia livre —
/// e dizia `encerravel: filho <id>`.
pub(super) fn contencao_o_isolado_no_meio_do_fork_nao_ganha_filho() -> Resultado {
    crate::pessoas::esquecer_registradas();
    let resultado = (|| -> Resultado {
        let e = Encerravel::lancar(operador_que_lanca(146, "isolado-no-fork"))?;
        let cabeca = crate::autorizacao::ultimo_registro();
        armar(isolar_quem_bifurca, e.fio);
        Encerravel::passo(ENCERRAVEL_FILHO, 0)?;
        let ouviu = e.esperar_linha(&bifurcar_negado(), 1);
        crate::fios::no_meio_do_nascimento_de_teste(None);
        let filho = NASCENDO.load(SeqCst);
        crate::log_info!(
            "teste",
            "contencao: o pai {} isolado no meio do nascimento de {}: isolou {}, linhas do filho {}",
            e.fio,
            filho,
            ISOLOU.load(SeqCst),
            linhas_que_comecam(e.desde, "encerravel: filho")
        );
        if !ISOLOU.load(SeqCst) || filho == 0 {
            return Err("o gancho nao isolou quem bifurcava no meio do nascimento");
        }
        if linhas_que_comecam(e.desde, "encerravel: filho") != 0 {
            return Err("o filho de quem foi isolado no meio do fork nasceu");
        }
        ouviu?;
        if crate::fios::na_tabela_de_teste(filho) {
            return Err("a vaga do filho que nao nasceu nao voltou");
        }
        let recusas = registros_depois(cabeca, |ev| {
            ev.metodo == "process.fork"
                && ev.codigo == politica::Codigo::DenyContained
                && ev.detalhe == "processo isolado"
        });
        let nascimentos = registros_depois(cabeca, |ev| {
            ev.metodo == "process.fork" && ev.codigo == politica::Codigo::Allow
        });
        if recusas.len() != 1 || !nascimentos.is_empty() {
            crate::log_error!(
                "teste",
                "{} recusa(s), {} nascimento(s) gravados",
                recusas.len(),
                nascimentos.len()
            );
            return Err("a auditoria nao diz so a recusa do filho do isolado");
        }
        e.esperar_linha("processo encerrou com codigo 3", 1)
    })();
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// A correção (4): o `process.terminate` de um processo que ainda nasce —
/// pelo gancho, com a vaga reservada — diz que ele estava `spawning`, e o
/// processo morre no primeiro ponto seguro, sem rodar o programa: o
/// lançado pelo `user.run` não diz `encerravel: pronto`; o filho de um
/// `fork` não diz `encerravel: filho`, e o pai o colhe morto. O contador
/// dos términos pendentes volta ao que era, e os terminados crescem um por
/// processo.
/// Sem levar a marca ao fio definitivo, o processo seguia — o lançado abria
/// o canal e dizia `pronto` — e o contador ficava em um para sempre: toda
/// chamada de sistema passava a tomar a trava do escalonador.
pub(super) fn processos_o_encerrado_que_ainda_nasce_morre() -> Resultado {
    crate::pessoas::esquecer_registradas();
    let resultado = (|| -> Resultado {
        let quem = operador_que_lanca(147, "nascendo-operador");
        let (pendentes_antes, terminados_antes) = crate::fios::terminos();
        // O lançado pelo `user.run`: o gancho roda no fio do comando.
        let desde = crate::log::total_emitidos();
        armar(encerrar_quem_nasce, 0);
        let dir = crate::usuario::DIRETORIO_DOS_COMPILADOS;
        let r = fs_pedir(
            quem,
            "user.run",
            &alloc::format!(r#"{{"path":"{dir}/encerravel"}}"#),
        );
        crate::fios::no_meio_do_nascimento_de_teste(None);
        let lancado = fs_numero(&r, "thread_id").ok_or_else(|| {
            crate::log_error!("teste", "{}", r);
            "o user.run nao lancou o encerravel"
        })?;
        if NASCENDO.load(SeqCst) != lancado || estava() != "spawning" {
            crate::log_error!(
                "teste",
                "o gancho viu {} ({}); o lancado e {}",
                NASCENDO.load(SeqCst),
                estava(),
                lancado
            );
            return Err("o termino do processo que nascia nao respondeu spawning");
        }
        Encerravel::morreu(lancado, desde)?;
        if linhas_do_programa(desde, "encerravel: pronto") != 0 {
            return Err("o processo encerrado ao nascer rodou o programa");
        }
        // O filho de um `fork`: o gancho roda no fio do pai, dentro da
        // chamada.
        let e = Encerravel::lancar(quem)?;
        armar(encerrar_quem_nasce, 0);
        Encerravel::passo(ENCERRAVEL_FILHO, 0)?;
        let viu = esperar_ate(|| NASCENDO.load(SeqCst) != 0, 600);
        crate::fios::no_meio_do_nascimento_de_teste(None);
        viu.map_err(|_| "o gancho nao viu o filho nascer")?;
        let filho = NASCENDO.load(SeqCst);
        if estava() != "spawning" {
            return Err("o termino do filho que nascia nao respondeu spawning");
        }
        Encerravel::morreu(filho, e.desde)?;
        e.esperar_linha(&alloc::format!("encerravel: colheu {filho} morto"), 1)?;
        if linhas_que_comecam(e.desde, "encerravel: filho") != 0 {
            return Err("o filho encerrado ao nascer rodou o programa");
        }
        let (pendentes, terminados) = crate::fios::terminos();
        if pendentes != pendentes_antes || terminados != terminados_antes + 2 {
            crate::log_error!(
                "teste",
                "pendentes {} (antes {}), terminados {} (antes {})",
                pendentes,
                pendentes_antes,
                terminados,
                terminados_antes
            );
            return Err("os contadores do termino nao fecham com os que nasciam");
        }
        Ok(())
    })();
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// A correção (4), na vaga que volta: o filho encerrado no meio do
/// nascimento e o pai isolado no mesmo instante. A conferência do
/// nascimento recusa o filho (a (3)), e a vaga volta com a marca do
/// término: a marca sai com ela. O contador dos pendentes volta ao que era,
/// e nenhum processo morreu por término — o filho não chegou a existir. Sem
/// descontar a marca na devolução da vaga — a mesma da pilha que não se
/// mapeia —, o contador ficava em um para sempre.
pub(super) fn processos_o_termino_do_filho_que_nao_nasce_sai_com_a_vaga() -> Resultado {
    crate::pessoas::esquecer_registradas();
    let resultado = (|| -> Resultado {
        let (pendentes_antes, terminados_antes) = crate::fios::terminos();
        let e = Encerravel::lancar(operador_que_lanca(148, "vaga-operador"))?;
        armar(encerrar_o_filho_e_isolar_o_pai, e.fio);
        Encerravel::passo(ENCERRAVEL_FILHO, 0)?;
        let ouviu = e.esperar_linha(&bifurcar_negado(), 1);
        crate::fios::no_meio_do_nascimento_de_teste(None);
        let filho = NASCENDO.load(SeqCst);
        if estava() != "spawning" || !ISOLOU.load(SeqCst) {
            crate::log_error!(
                "teste",
                "o filho {} estava {}; isolou {}",
                filho,
                estava(),
                ISOLOU.load(SeqCst)
            );
            return Err("o gancho nao encerrou o filho e isolou o pai no meio do nascimento");
        }
        ouviu?;
        if filho == 0 || crate::fios::na_tabela_de_teste(filho) {
            return Err("a vaga do filho que nao nasceu nao voltou");
        }
        let (pendentes, terminados) = crate::fios::terminos();
        if pendentes != pendentes_antes || terminados != terminados_antes {
            crate::log_error!(
                "teste",
                "pendentes {} (antes {}), terminados {} (antes {})",
                pendentes,
                pendentes_antes,
                terminados,
                terminados_antes
            );
            return Err("o termino do filho que nao nasceu ficou pendente");
        }
        Ok(())
    })();
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}
