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

/// Quem pede, como a auditoria grava o pedido de um processo vivo:
/// `pelo processo N (<programa>)`. Tirado enquanto ele vive — o
/// `encerravel` cujo `fork` é recusado sai logo depois.
fn pelo_processo(fio: u64) -> Result<alloc::string::String, &'static str> {
    let (_, programa) = crate::fios::processo(fio).ok_or("o processo que pede nao esta vivo")?;
    Ok(alloc::format!(
        "pelo processo {fio} ({})",
        programa.descricao()
    ))
}

/// O detalhe que uma recusa de `pelo` com `texto` grava: quem pede na
/// frente, abreviado só acima do teto, pela regra de todo registro.
fn detalhe_por(pelo: &str, texto: &str) -> alloc::string::String {
    politica::auditoria::detalhe_composto(Some(pelo), texto, "")
}

/// A correção (3): o `encerravel` bifurca, e o gancho do meio do nascimento
/// o isola depois de o gate deixar o `fork` passar — com o espaço copiado e
/// a vaga do filho reservada. O filho não nasce: a chamada ouve `NEGADO`, a
/// recusa vai à auditoria como a do gate (`process.fork`,
/// `DENY_CONTAINED`, "processo isolado", com o processo que bifurcou na
/// frente), sem o registro do nascimento, a vaga volta, e o pai sai com o
/// código do `fork` recusado. Sem a conferência no nascimento, o filho de
/// um processo isolado nascia livre — e dizia `encerravel: filho <id>`.
pub(super) fn contencao_o_isolado_no_meio_do_fork_nao_ganha_filho() -> Resultado {
    crate::pessoas::esquecer_registradas();
    let resultado = (|| -> Resultado {
        let e = Encerravel::lancar(operador_que_lanca(146, "isolado-no-fork"))?;
        let esperado = detalhe_por(&pelo_processo(e.fio)?, "processo isolado");
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
                && ev.detalhe == esperado
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

// ---------------------------------------------------------------------------
// O adversario da soma das cotas: a janela da (3) no `user.run` de um
// processo, pela interface nativa
// ---------------------------------------------------------------------------

/// No meio do nascimento do lancado: encerra quem pede o `user.run`, como o
/// handler de `process.terminate` faz depois do gate — isola antes, e pede
/// o fim.
fn encerrar_quem_pede(lancado: u64) {
    let pede = ISOLAR.swap(0, SeqCst);
    if pede != 0 && crate::contencao::encerrar_processo(pede).is_ok_and(|f| f.isolamento.mudou) {
        ISOLOU.store(true, SeqCst);
    }
    NASCENDO.store(lancado, SeqCst);
}

/// O `encerravel` P, lancado por `quem`, pede `user.run` de outro
/// `encerravel` pela interface nativa — o gate o decide com o fio de P,
/// solto, como a tarefa `programas` faria; o programa declara `process.run`,
/// que o `encerravel` nao declara —, e `gancho` contem P no meio do
/// nascimento do lancado. `Ok(P)` se nada nasceu e a vaga voltou; `Err`
/// com `defeito` se o lancado nasceu, depois de dizer o que P e o lancado
/// ouvem do gate pelo mesmo pedido.
fn user_run_de_quem_e_contido_no_meio(
    quem: crate::autorizacao::Chamador,
    gancho: fn(u64),
    como: &str,
    defeito: &'static str,
) -> Result<Encerravel, &'static str> {
    use crate::autorizacao::{Chamador, Programa};
    let e = Encerravel::lancar(quem)?;
    let (autoridade, _) =
        crate::fios::processo(e.fio).ok_or("o encerravel que pede nao esta vivo")?;
    let pede = Chamador::Processo {
        fio: e.fio,
        autoridade,
        programa: Programa::Imagem {
            manifesto: Some(super::manifesto_de_teste(
                "pedinte",
                "process.run system.read",
            )),
            resumo: [0xab; 32],
            editor: None,
        },
    };
    armar(gancho, e.fio);
    let dir = crate::usuario::DIRETORIO_DOS_COMPILADOS;
    let r = fs_pedir(
        pede,
        "user.run",
        &alloc::format!(r#"{{"path":"{dir}/encerravel"}}"#),
    );
    crate::fios::no_meio_do_nascimento_de_teste(None);
    let nascendo = NASCENDO.load(SeqCst);
    let lancado = fs_numero(&r, "thread_id");
    crate::log_info!(
        "teste",
        "contencao: {} {} no meio do user.run: contido {}, nascendo {}, lancado {:?}",
        e.fio,
        como,
        ISOLOU.load(SeqCst),
        nascendo,
        lancado
    );
    if !ISOLOU.load(SeqCst) || nascendo == 0 {
        crate::log_error!("teste", "{}", r);
        return Err("o gancho nao conteve quem pedia no meio do nascimento");
    }
    if let Some(q) = lancado {
        // O defeito: o lancado nasceu do pedido de um processo ja contido.
        // O que cada um ouve agora do gate, pelo mesmo pedido.
        let _ = e.esperar_linha("encerravel: pronto", 2);
        let isolado = crate::contencao::contido(&Alvo::Processo(q));
        let de_p = super::decisao_do_envelope(&fs_pedir(pede, "system.uptime", "{}"));
        let de_q = crate::fios::processo(q).map(|(a, p)| {
            super::decisao_do_envelope(&fs_pedir(
                Chamador::Processo {
                    fio: q,
                    autoridade: a,
                    programa: p,
                },
                "system.uptime",
                "{}",
            ))
        });
        crate::log_error!(
            "teste",
            "o lancado {} nasceu do user.run de {}, {} no meio: o lancado esta isolado? {}; {} ouve {}; o lancado ouve {:?}",
            q,
            e.fio,
            como,
            isolado,
            e.fio,
            de_p,
            de_q
        );
        return Err(defeito);
    }
    if crate::fios::na_tabela_de_teste(nascendo) {
        return Err("a vaga do lancado que nao nasceu nao voltou");
    }
    Ok(e)
}

/// O adversario da soma das cotas: a janela que a correcao (3) fecha no
/// `fork`, aberta no `user.run` que um processo pede pela interface nativa.
/// O gate decide o `user.run` com o fio de quem pede, e o nascimento do
/// lancado nao confere de novo: `permitir_processo`, no handler, pergunta
/// pelo fio de agora — o da tarefa `programas`, e nao o processo —, e o
/// `criar_processo` nao tem ultima palavra que recuse. O gancho do meio do
/// nascimento contem quem pede depois do gate e antes de o lancado poder
/// rodar — o `process.isolate` de outro fio na janela de ler o codigo e
/// mapear a pilha; depois, o `process.terminate`, que isola antes. O pedido
/// em curso de quem foi contido nao deve concluir — "isolado, um pedido em
/// curso e recusado no ponto de commit", e "o que ele pediu antes de morrer
/// nao pode terminar de acontecer depois do termino"
/// (`contencao::encerrar_processo`) —: nenhum processo nasce, como no
/// `fork` (`contencao: o isolado no meio do fork nao ganha filho`), a vaga
/// volta, e o encerrado morre. Sem a conferencia no nascimento, o lancado
/// nasce livre, com a autoridade de quem pediu, e o gate deixa a ele o que
/// recusa a quem pediu.
pub(super) fn contencao_o_isolado_no_meio_do_user_run_nao_lanca() -> Resultado {
    crate::pessoas::esquecer_registradas();
    let resultado = (|| -> Resultado {
        let quem = operador_que_lanca(149, "isolado-no-run");
        user_run_de_quem_e_contido_no_meio(
            quem,
            isolar_quem_bifurca,
            "isolado",
            "o processo isolado no meio do user.run lancou um processo livre",
        )?;
        let p = user_run_de_quem_e_contido_no_meio(
            quem,
            encerrar_quem_pede,
            "encerrado",
            "o processo encerrado no meio do user.run lancou um processo livre",
        )?;
        Encerravel::morreu(p.fio, p.desde)
    })();
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// A pessoa cuja credencial o gancho suspende — os oito bytes dela —, ou
/// zero.
static PESSOA: AtomicU64 = AtomicU64::new(0);

/// No meio do nascimento do filho: suspende a credencial da pessoa de quem
/// bifurca, como o handler de `credential.suspend` faz depois do gate.
fn suspender_a_pessoa_de_quem_bifurca(filho: u64) {
    let pessoa = PESSOA.swap(0, SeqCst);
    if pessoa != 0
        && crate::contencao::conter(&Alvo::Pessoa(sigilo::pessoas::IdPessoa(
            pessoa.to_le_bytes(),
        )))
        .is_ok_and(|f| f.mudou)
    {
        ISOLOU.store(true, SeqCst);
    }
    NASCENDO.store(filho, SeqCst);
}

/// O adversario da soma das cotas: a outra metade da correcao (3), que o
/// caso do isolado nao exercita. A conferencia do nascimento recusa com
/// `DENY_CREDENTIAL` tambem: a credencial da pessoa que lancou o
/// `encerravel`, suspensa pelo gancho depois de o gate deixar o `fork`
/// passar, nao deixa nascer o filho — `NEGADO` na chamada, a recusa uma vez
/// na auditoria (`process.fork`, `DENY_CREDENTIAL`, "credencial suspensa",
/// com o processo que bifurcou na frente), sem o registro do nascimento, e
/// a vaga de volta.
pub(super) fn contencao_a_credencial_suspensa_no_meio_do_fork_nao_ganha_filho() -> Resultado {
    crate::pessoas::esquecer_registradas();
    let mut suspensa = None;
    let resultado = (|| -> Resultado {
        let quem = operador_que_lanca(150, "credencial-no-fork");
        let crate::autorizacao::Chamador::Pessoa(sessao) = quem else {
            return Err("o operador do caso nao e uma pessoa");
        };
        let pessoa = crate::pessoas::dona_da_sessao(sessao).ok_or("a sessao nao tem dona")?;
        let e = Encerravel::lancar(quem)?;
        let esperado = detalhe_por(&pelo_processo(e.fio)?, "credencial suspensa");
        let cabeca = crate::autorizacao::ultimo_registro();
        armar(suspender_a_pessoa_de_quem_bifurca, 0);
        PESSOA.store(u64::from_le_bytes(pessoa.0), SeqCst);
        suspensa = Some(pessoa);
        Encerravel::passo(ENCERRAVEL_FILHO, 0)?;
        let ouviu = e.esperar_linha(&bifurcar_negado(), 1);
        crate::fios::no_meio_do_nascimento_de_teste(None);
        let filho = NASCENDO.load(SeqCst);
        if !ISOLOU.load(SeqCst) || filho == 0 {
            return Err("o gancho nao suspendeu a credencial no meio do nascimento");
        }
        if linhas_que_comecam(e.desde, "encerravel: filho") != 0 {
            return Err("o filho de quem teve a credencial suspensa no meio do fork nasceu");
        }
        ouviu?;
        if crate::fios::na_tabela_de_teste(filho) {
            return Err("a vaga do filho que nao nasceu nao voltou");
        }
        let recusas = registros_depois(cabeca, |ev| {
            ev.metodo == "process.fork"
                && ev.codigo == politica::Codigo::DenyCredential
                && ev.detalhe == esperado
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
            return Err("a auditoria nao diz so a recusa da credencial no nascimento");
        }
        Ok(())
    })();
    PESSOA.store(0, SeqCst);
    crate::fios::no_meio_do_nascimento_de_teste(None);
    if let Some(pessoa) = suspensa {
        let _ = crate::contencao::soltar(&Alvo::Pessoa(pessoa));
    }
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// O adversario da soma das cotas: o fio `energia` do boot, acordado sem
/// pedido nenhum — o despertar espurio de quem acorda um fio pelo numero
/// (`fios::acordar`) —, nao age: volta a esperar, sem acao a caminho e sem
/// nada entregue ao firmware. E o pedido seguinte ainda o acorda, e chega
/// ao fim: o despertador que ficou e o dele.
pub(super) fn energia_o_despertar_sem_pedido_nao_age() -> Resultado {
    let _ = crate::energia::executada_de_teste();
    let parado = |f: Option<(u64, &'static str)>| f.is_some_and(|(_, e)| e == "waiting");
    esperar_cedendo(|| parado(fio_da_energia()), 300)
        .map_err(|_| "o fio da energia nao esta parado antes do caso")?;
    let (fio, _) = fio_da_energia().ok_or("sem o fio da energia")?;
    for _ in 0..8 {
        if !crate::fios::acordar(fio) {
            return Err("o fio da energia nao esta vivo");
        }
        esperar_cedendo(|| parado(fio_da_energia()), 300)
            .map_err(|_| "o fio da energia acordado sem pedido nao voltou a esperar")?;
    }
    if crate::energia::pedida().is_some() || crate::energia::executada_de_teste().is_some() {
        return Err("o despertar sem pedido pos uma acao a caminho");
    }
    let segura = crate::energia::Segura::de_teste();
    let r = fs_pedir(sistema_aqui(), "system.reboot", "{}");
    drop(segura);
    if fs_texto(&r, "state").as_deref() != Some("rebooting") {
        crate::log_error!("teste", "{}", r);
        return Err("o system.reboot depois dos despertares nao foi aceito");
    }
    if energia_entregue() != Some(crate::energia::Acao::Reiniciar) {
        return Err("o reinicio depois dos despertares nao chegou ao fim");
    }
    esperar_cedendo(|| parado(fio_da_energia()), 300)
        .map_err(|_| "o fio da energia nao voltou a esperar depois do reinicio")?;
    if fio_da_energia().map(|f| f.0) != Some(fio) {
        return Err("o fio da energia nao e o mesmo do boot");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Os achados do adversario da soma das cotas, corrigidos: a ultima palavra
// do nascimento do `user.run`, e a reconferencia inteira do `fork`
// ---------------------------------------------------------------------------

/// O programa com que o `encerravel` P pede pela interface nativa nos casos
/// abaixo: um que declara `process.run`, que o `encerravel` nao declara —
/// como em `user_run_de_quem_e_contido_no_meio`.
fn programa_que_pede() -> crate::autorizacao::Programa {
    crate::autorizacao::Programa::Imagem {
        manifesto: Some(super::manifesto_de_teste(
            "pedinte",
            "process.run system.read",
        )),
        resumo: [0xab; 32],
        editor: None,
    }
}

/// A sessao de pessoa que o gancho encerra — os oito bytes dela —, ou zero.
static SESSAO: AtomicU64 = AtomicU64::new(0);

/// No meio do nascimento: a pessoa de quem pede sai — o `logout` dela, no
/// mesmo instante.
fn sair_quem_pede(nascendo: u64) {
    let sessao = SESSAO.swap(0, SeqCst);
    if sessao != 0 && crate::pessoas::sair(crate::pessoas::IdSessao(sessao.to_le_bytes())) {
        ISOLOU.store(true, SeqCst);
    }
    NASCENDO.store(nascendo, SeqCst);
}

/// Arma o gancho que encerra a sessao de `quem`, uma pessoa.
fn armar_a_saida(quem: crate::autorizacao::Chamador) -> Resultado {
    let crate::autorizacao::Chamador::Pessoa(sessao) = quem else {
        return Err("quem lanca no caso nao e uma pessoa");
    };
    armar(sair_quem_pede, 0);
    SESSAO.store(u64::from_le_bytes(sessao.0), SeqCst);
    Ok(())
}

/// O que um `user.run` recusado na ultima palavra do nascimento responde:
/// nada lancado, com o codigo e o motivo da recusa.
fn nao_lancou_com(r: &str, codigo: &str, motivo: &str) -> Resultado {
    if fs_numero(r, "thread_id").is_some()
        || !r.contains(r#""launched":false"#)
        || fs_texto(r, "code").as_deref() != Some(codigo)
        || fs_texto(r, "error").as_deref() != Some(motivo)
    {
        crate::log_error!("teste", "{}", r);
        return Err("o user.run recusado no nascimento nao respondeu o codigo da recusa");
    }
    Ok(())
}

/// A recusa do nascimento na auditoria: uma so, depois de `cabeca`, como a
/// execucao da decisao do `user.run` — o metodo, o caminho, o codigo, e o
/// detalhe `<quem pede: >motivo; decisao N` —, e nenhum `processo N
/// lancado`.
fn so_a_recusa_do_user_run(
    cabeca: u64,
    caminho: &str,
    codigo: politica::Codigo,
    detalhe: &str,
) -> Resultado {
    let prefixo = alloc::format!("{detalhe}; decisao ");
    let recusas = registros_depois(cabeca, |ev| {
        ev.metodo == "user.run"
            && ev.recurso == caminho
            && ev.codigo == codigo
            && ev.detalhe.starts_with(&prefixo)
    });
    let lancados = registros_depois(cabeca, |ev| {
        ev.metodo == "user.run"
            && ev.codigo == politica::Codigo::Allow
            && ev.detalhe.contains(" lancado")
    });
    if recusas.len() != 1 || !lancados.is_empty() {
        crate::log_error!(
            "teste",
            "{} recusa(s) `{}`, {} lancamento(s) gravados",
            recusas.len(),
            detalhe,
            lancados.len()
        );
        return Err("a auditoria nao diz so a recusa do user.run no nascimento");
    }
    Ok(())
}

/// A correcao do achado 1 do adversario, na resposta e na auditoria: o
/// `user.run` que o `encerravel` P pede pela interface nativa, com P
/// isolado pelo gancho no meio do nascimento do lancado. A ultima palavra
/// do nascimento decide o comando de novo (`autorizacao::reconfirmar`, pelo
/// processo do pedido, e nao pelo executor) e recusa: quem pediu ouve
/// `launched: false`, com `DENY_CONTAINED` e "processo isolado"; a
/// auditoria grava a recusa uma vez, como a execucao da decisao do
/// `user.run` — o caminho, e P na frente do motivo —, sem nenhum `processo
/// N lancado`, e a vaga volta. Sem a ultima palavra, o lancado nascia livre
/// (`contencao: o isolado no meio do user.run nao lanca`).
pub(super) fn contencao_a_recusa_do_user_run_no_nascimento_diz_o_codigo() -> Resultado {
    crate::pessoas::esquecer_registradas();
    let resultado = (|| -> Resultado {
        let e = Encerravel::lancar(operador_que_lanca(151, "recusa-do-run"))?;
        let (autoridade, _) =
            crate::fios::processo(e.fio).ok_or("o encerravel que pede nao esta vivo")?;
        let programa = programa_que_pede();
        let pelo = alloc::format!("pelo processo {} ({})", e.fio, programa.descricao());
        let pede = crate::autorizacao::Chamador::Processo {
            fio: e.fio,
            autoridade,
            programa,
        };
        let caminho = alloc::format!("{}/encerravel", crate::usuario::DIRETORIO_DOS_COMPILADOS);
        let cabeca = crate::autorizacao::ultimo_registro();
        armar(isolar_quem_bifurca, e.fio);
        let r = fs_pedir(
            pede,
            "user.run",
            &alloc::format!(r#"{{"path":"{caminho}"}}"#),
        );
        crate::fios::no_meio_do_nascimento_de_teste(None);
        let nascendo = NASCENDO.load(SeqCst);
        crate::log_info!(
            "teste",
            "contencao: o user.run de {}, isolado no meio do nascimento de {}: {}",
            e.fio,
            nascendo,
            r
        );
        if !ISOLOU.load(SeqCst) || nascendo == 0 {
            return Err("o gancho nao isolou quem pedia no meio do nascimento");
        }
        nao_lancou_com(&r, "DENY_CONTAINED", "processo isolado")?;
        if crate::fios::na_tabela_de_teste(nascendo) {
            return Err("a vaga do lancado que nao nasceu nao voltou");
        }
        let detalhe = detalhe_por(&pelo, "processo isolado");
        so_a_recusa_do_user_run(cabeca, &caminho, politica::Codigo::DenyContained, &detalhe)
    })();
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// O achado 4 do adversario, no `user.run`: a ultima palavra do nascimento
/// e o comando inteiro decidido de novo, e nao so a contencao. A pessoa
/// pede `user.run` pelo console, e sai — o `logout` — no meio do
/// nascimento do lancado, pelo gancho. Recusado: `DENY_NOT_AUTHENTICATED`,
/// "sessao de pessoa que acabou", na resposta e uma vez na auditoria, como
/// a execucao da decisao; nada nasce, e a vaga volta. Sem a ultima
/// palavra, o processo de quem saiu nascia — sem papel, recusado em cada
/// pedido, so ocupando a vaga.
pub(super) fn contencao_quem_sai_no_meio_do_user_run_nao_lanca() -> Resultado {
    crate::pessoas::esquecer_registradas();
    let resultado = (|| -> Resultado {
        let quem = operador_que_lanca(152, "sai-no-run");
        let caminho = alloc::format!("{}/encerravel", crate::usuario::DIRETORIO_DOS_COMPILADOS);
        let cabeca = crate::autorizacao::ultimo_registro();
        armar_a_saida(quem)?;
        let r = fs_pedir(
            quem,
            "user.run",
            &alloc::format!(r#"{{"path":"{caminho}"}}"#),
        );
        crate::fios::no_meio_do_nascimento_de_teste(None);
        let nascendo = NASCENDO.load(SeqCst);
        crate::log_info!(
            "teste",
            "contencao: a pessoa saiu no meio do nascimento de {}: {}",
            nascendo,
            r
        );
        if !ISOLOU.load(SeqCst) || nascendo == 0 {
            return Err("o gancho nao encerrou a sessao no meio do nascimento");
        }
        nao_lancou_com(&r, "DENY_NOT_AUTHENTICATED", "sessao de pessoa que acabou")?;
        if crate::fios::na_tabela_de_teste(nascendo) {
            return Err("a vaga do lancado que nao nasceu nao voltou");
        }
        so_a_recusa_do_user_run(
            cabeca,
            &caminho,
            politica::Codigo::DenyNotAuthenticated,
            "sessao de pessoa que acabou",
        )
    })();
    SESSAO.store(0, SeqCst);
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// O achado 4 do adversario, no `fork`: o nascimento do filho refaz as
/// perguntas do gate sobre quem bifurca, e nao so a contencao — menos a
/// conta (`autorizacao::reconfirmar_bifurcacao`). A pessoa que lancou o
/// `encerravel` sai no meio do nascimento do filho, pelo gancho, dentro do
/// `fork`: sem sessao, sem papel. O filho nao nasce — `NEGADO` na chamada,
/// a recusa uma vez na auditoria como a do gate (`process.fork`,
/// `DENY_ROLE`, "sem papel, nenhum processo", com o processo que bifurcou
/// na frente), sem o registro do nascimento — e a vaga volta. Antes, so a
/// contencao era conferida de novo, e o filho de quem saiu nascia sem
/// papel, recusado em cada pedido, so ocupando a vaga.
pub(super) fn contencao_quem_sai_no_meio_do_fork_nao_ganha_filho() -> Resultado {
    crate::pessoas::esquecer_registradas();
    let resultado = (|| -> Resultado {
        let quem = operador_que_lanca(153, "sai-no-fork");
        let e = Encerravel::lancar(quem)?;
        let esperado = detalhe_por(&pelo_processo(e.fio)?, "sem papel, nenhum processo");
        let cabeca = crate::autorizacao::ultimo_registro();
        armar_a_saida(quem)?;
        Encerravel::passo(ENCERRAVEL_FILHO, 0)?;
        let ouviu = e.esperar_linha(&bifurcar_negado(), 1);
        crate::fios::no_meio_do_nascimento_de_teste(None);
        let filho = NASCENDO.load(SeqCst);
        if !ISOLOU.load(SeqCst) || filho == 0 {
            return Err("o gancho nao encerrou a sessao no meio do nascimento");
        }
        if linhas_que_comecam(e.desde, "encerravel: filho") != 0 {
            return Err("o filho de quem saiu no meio do fork nasceu");
        }
        ouviu?;
        if crate::fios::na_tabela_de_teste(filho) {
            return Err("a vaga do filho que nao nasceu nao voltou");
        }
        let recusas = registros_depois(cabeca, |ev| {
            ev.metodo == "process.fork"
                && ev.codigo == politica::Codigo::DenyRole
                && ev.detalhe == esperado
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
            return Err("a auditoria nao diz so a recusa de quem saiu no nascimento");
        }
        e.esperar_linha("processo encerrou com codigo 3", 1)
    })();
    SESSAO.store(0, SeqCst);
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}
