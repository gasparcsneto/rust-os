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
//!
//! E os latentes do adversário só de leitura das correções, no fim do
//! arquivo: a última palavra que pergunta se quem pede acabou ou tem o fim
//! pedido, e a confiança no editor; o desconhecido que recusa em vez de
//! passar; o `fork` com o journal recusado; a resposta do `user.run`
//! recusado nas perguntas do gate, com o código e o motivo de verdade — pelo
//! gancho de antes delas (`autorizacao::antes_do_gate_do_lancamento_de_teste`);
//! e as lacunas de cobertura: o editor recusado no nascimento do `fork`, e a
//! chave revogada e a política nova no nascimento do `user.run`.
//!
//! E os achados do adversário do lote A do #448, no fim do arquivo: a
//! confiança no editor do código que vai rodar, perguntada de novo na
//! última palavra do nascimento — pelo `user.run` e pelo kernel fora de um
//! comando —; e o lançamento só pelo comando decidido para `process.run`,
//! pelo gancho da verificação do armazém (`armazem::no_meio_da_verificacao_de_teste`),
//! dentro de um `fs.verify` decidido. O detalhe de quem acabou — "processo
//! encerrado", e não "processo isolado" — e a resposta sem a explicação do
//! comando às recusas sobre quem pede ficam nos casos acima que as
//! conferem.

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

/// A resposta de um `user.run` recusado nas perguntas sobre quem pede um
/// processo — a cota, quem acabou, a contencao, o editor e o papel de quem
/// pede —, no gate ou na ultima palavra, nao traz a explicacao do comando:
/// ela le o papel e a permissao com que o gate decidiu o comando, e estas
/// recusas nao sao ela — a cota sairia "o seu papel nao permite
/// process.run", a sessao que acabou com o papel de antes, e o encerrado
/// com "um administrador pode libera-la" (o achado 5 do adversario do lote
/// A; ver `usuario::NaoLancou::PorQuemPede`).
fn sem_a_explicacao(r: &str) -> Resultado {
    if r.contains(r#""explain""#) {
        crate::log_error!("teste", "{}", r);
        return Err("a recusa de quem pede no user.run veio com a explicacao do comando");
    }
    Ok(())
}

/// A resposta de um `user.run` recusado na ultima palavra, pelo comando
/// decidido de novo, traz a explicacao dele, com a razao `razao`: e a
/// decisao do comando, feita de novo.
fn com_a_explicacao(r: &str, razao: &str) -> Resultado {
    if !r.contains(&alloc::format!(r#""reason":"{razao}""#)) {
        crate::log_error!("teste", "esperava a explicacao {}: {}", razao, r);
        return Err("a recusa do comando decidido de novo no user.run nao veio explicada");
    }
    Ok(())
}

/// Se `ev` grava a recusa de `pelo` com `motivo` como a execucao de uma
/// decisao a grava (`autorizacao::citando`): o detalhe composto pela regra
/// de todo registro, com a citacao da decisao que ele mesmo cita.
fn e_a_execucao_de(ev: &politica::auditoria::Evento, pelo: Option<&str>, motivo: &str) -> bool {
    let Some(decisao) = super::decisao_executada(&ev.detalhe) else {
        return false;
    };
    let citacao = alloc::format!("; decisao {decisao}");
    ev.detalhe == politica::auditoria::detalhe_composto(pelo, motivo, &citacao)
}

/// A recusa do nascimento na auditoria: uma so, depois de `cabeca`, como a
/// execucao da decisao do `user.run` — o metodo, o caminho, o codigo, e o
/// detalhe `<quem pede: >motivo; decisao N`, com `pelo` na frente quando
/// quem pede e um processo —, e nenhum `processo N lancado`.
///
/// # O detalhe esperado, composto com a citacao
///
/// O kernel compoe o detalhe da execucao inteiro, com a citacao, e acima
/// do teto (`politica::auditoria::MAIOR_DETALHE`) a descricao do programa
/// de quem pede encolhe: `(pedinte abababababababab)` vira `(?
/// abababababababab)` — 16 digitos do resumo desde o A9-RESUMO; eram 8, e
/// as medidas abaixo sao de entao. Se cabe
/// ou nao depende dos digitos do fio de quem pede e do numero da decisao,
/// que crescem com os casos que rodaram antes na mesma maquina. O esperado
/// sai da mesma regra, com a citacao do proprio registro
/// ([`e_a_execucao_de`]). Composto sem ela, e conferido pelo comeco, so
/// casava enquanto o detalhe inteiro cabia: na suite inteira do x86 (a CI
/// 509, em release), o fio 10283 e a decisao 95053 levavam a recusa da
/// chave revogada — o motivo mais longo — a 97 bytes, e nenhum registro
/// casava; nas partes, com o fio de 4 digitos, eram 96, e cabia.
fn so_a_recusa_do_user_run(
    cabeca: u64,
    caminho: &str,
    codigo: politica::Codigo,
    pelo: Option<&str>,
    motivo: &str,
) -> Resultado {
    let candidatas = registros_depois(cabeca, |ev| {
        ev.metodo == "user.run" && ev.recurso == caminho && ev.codigo == codigo
    });
    let recusas = candidatas
        .iter()
        .filter(|(_, ev)| e_a_execucao_de(ev, pelo, motivo))
        .count();
    let lancados = registros_depois(cabeca, |ev| {
        ev.metodo == "user.run"
            && ev.codigo == politica::Codigo::Allow
            && ev.detalhe.contains(" lancado")
    });
    if recusas != 1 || !lancados.is_empty() {
        for (seq, ev) in &candidatas {
            crate::log_error!("teste", "registro {} do user.run: {}", seq, ev.detalhe);
        }
        crate::log_error!(
            "teste",
            "{} recusa(s) de `{}` com `{}`, {} lancamento(s) gravados",
            recusas,
            pelo.unwrap_or(""),
            motivo,
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
        // O comando decidido de novo: a explicacao dele — o isolado, que um
        // administrador pode soltar.
        com_a_explicacao(&r, "DENY_CONTAINED")?;
        if crate::fios::na_tabela_de_teste(nascendo) {
            return Err("a vaga do lancado que nao nasceu nao voltou");
        }
        so_a_recusa_do_user_run(
            cabeca,
            &caminho,
            politica::Codigo::DenyContained,
            Some(pelo.as_str()),
            "processo isolado",
        )
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
        // O comando decidido de novo: a explicacao dele — entrar de novo.
        com_a_explicacao(&r, "DENY_NOT_AUTHENTICATED")?;
        if crate::fios::na_tabela_de_teste(nascendo) {
            return Err("a vaga do lancado que nao nasceu nao voltou");
        }
        so_a_recusa_do_user_run(
            cabeca,
            &caminho,
            politica::Codigo::DenyNotAuthenticated,
            None,
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

// ---------------------------------------------------------------------------
// Os latentes do adversario so de leitura das correcoes da soma das cotas:
// quem pede que acabou ou tem o fim pedido, o desconhecido que recusa, o
// `fork` com o journal recusado, a resposta do `user.run` recusado no gate,
// e as lacunas de cobertura do nascimento
// ---------------------------------------------------------------------------

/// O caminho do `encerravel` da imagem.
fn caminho_do_encerravel() -> alloc::string::String {
    alloc::format!("{}/encerravel", crate::usuario::DIRETORIO_DOS_COMPILADOS)
}

/// O `encerravel` do programa de `caminho`, lancado por `quem` pelo
/// `user.run`, e pronto.
fn encerravel_de(
    quem: crate::autorizacao::Chamador,
    caminho: &str,
) -> Result<Encerravel, &'static str> {
    let desde = crate::log::total_emitidos();
    let r = fs_pedir(
        quem,
        "user.run",
        &alloc::format!(r#"{{"path":"{caminho}"}}"#),
    );
    let fio = fs_numero(&r, "thread_id").ok_or_else(|| {
        crate::log_error!("teste", "{}", r);
        "o user.run nao lancou o encerravel do caso"
    })?;
    let e = Encerravel { fio, desde };
    e.esperar_linha("encerravel: pronto", 1)?;
    Ok(e)
}

/// O chamador que pede como o `encerravel` `e`, com `programa` — o que o
/// gate decide para o pedido nativo.
fn como(
    e: &Encerravel,
    programa: crate::autorizacao::Programa,
) -> Result<crate::autorizacao::Chamador, &'static str> {
    let (autoridade, _) =
        crate::fios::processo(e.fio).ok_or("o encerravel que pede nao esta vivo")?;
    Ok(crate::autorizacao::Chamador::Processo {
        fio: e.fio,
        autoridade,
        programa,
    })
}

/// Um gancho do meio do nascimento: recebe o fio que nasce.
type Gancho = fn(u64);

/// A recusa de quem pede e acabou, ou tem o fim pedido: o codigo do isolado
/// e o detalhe do que aconteceu (`contencao::PROCESSO_ENCERRADO`). Escrita
/// aqui, e nao lida da constante do kernel: os casos conferem o que o
/// registro diz, e nao a constante por ela mesma.
const ENCERRADO: (politica::Codigo, &str) = (politica::Codigo::DenyContained, "processo encerrado");

/// O processo cujo fim o gancho pede, ou zero.
static ENCERRAR: AtomicU64 = AtomicU64::new(0);

/// A politica que o gancho poe no meio, guardada antes: um gancho e uma
/// funcao sem estado.
static POLITICA_DO_MEIO: crate::trava::Mutex<Option<politica::Politica>> =
    crate::trava::Mutex::new(None);

/// O estado da persistencia de antes do journal recusado por um gancho,
/// para voltar.
static ESTADO_ANTERIOR: crate::trava::Mutex<Option<crate::persistencia::Estado>> =
    crate::trava::Mutex::new(None);

/// Recusa o journal, como um disco anterior a ancora, e guarda o estado de
/// antes.
fn recusar_o_journal() {
    let anterior = crate::persistencia::forcar_estado_de_teste(
        crate::persistencia::Estado::Recusada("recusado pela suite"),
    );
    crate::arch::sem_interrupcoes(|| {
        ESTADO_ANTERIOR.lock().get_or_insert(anterior);
    });
}

/// Devolve o estado da persistencia de antes do journal recusado.
fn devolver_o_journal() {
    if let Some(anterior) = crate::arch::sem_interrupcoes(|| ESTADO_ANTERIOR.lock().take()) {
        crate::persistencia::forcar_estado_de_teste(anterior);
    }
}

/// Poe a politica guardada em [`POLITICA_DO_MEIO`], se ha uma; devolve se
/// pos.
fn por_a_politica_do_meio() -> bool {
    match crate::arch::sem_interrupcoes(|| POLITICA_DO_MEIO.lock().take()) {
        Some(p) => {
            crate::autorizacao::restaurar_politica(p);
            true
        }
        None => false,
    }
}

/// A recusa de um `fork` uma vez na auditoria, depois de `cabeca` — o
/// `process.fork` com `codigo` e o detalhe `esperado`, como o gate grava —,
/// e nenhuma bifurcacao permitida.
fn so_a_recusa_do_fork(cabeca: u64, codigo: politica::Codigo, esperado: &str) -> Resultado {
    let recusas = registros_depois(cabeca, |ev| {
        ev.metodo == "process.fork" && ev.codigo == codigo && ev.detalhe == esperado
    });
    let nascimentos = registros_depois(cabeca, |ev| {
        ev.metodo == "process.fork" && ev.codigo == politica::Codigo::Allow
    });
    if recusas.len() != 1 || !nascimentos.is_empty() {
        crate::log_error!(
            "teste",
            "{} recusa(s) `{}`, {} nascimento(s) gravados",
            recusas.len(),
            esperado,
            nascimentos.len()
        );
        return Err("a auditoria nao diz so a recusa do fork");
    }
    Ok(())
}

/// Prende o processo `fio` ao nucleo em que a suite roda agora, de dentro
/// de um gancho, antes de lhe pedir o fim: o pedido o acorda, mas ele so
/// roda neste nucleo, e a suite nao cede entre o gancho e a pergunta
/// seguinte — a ultima palavra do nascimento, ou as perguntas do gate.
/// Ate la ele segue vivo, com o fim pedido: a pergunta acha quem vai acabar
/// e ainda nao acabou, como com o teto de isolados cheio. Solto, ele morria
/// no nucleo dele em microssegundos, antes da pergunta, que achava o morto
/// — e a pergunta pelo fim pedido nao era exercitada (a mutacao MC1, em
/// que so o morto conta, sobrevivia a estes casos). Quando a suite der a
/// vez, ele roda aqui e morre.
fn prender_ao_nucleo_de_agora(fio: u64) -> bool {
    crate::fios::fixar(
        fio,
        Some(crate::arch::sem_interrupcoes(crate::nucleos::atual)),
    )
}

/// No meio do nascimento do lancado: pede o fim de quem pede, sem isolar —
/// o `process.terminate` com o teto de isolados cheio, que pede o fim mesmo
/// assim (`contencao::encerrar_processo`) —, com quem pede preso ao nucleo
/// da suite ([`prender_ao_nucleo_de_agora`]): vivo, com o fim pedido, na
/// ultima palavra.
fn pedir_o_fim_de_quem_pede(nascendo: u64) {
    let pede = ENCERRAR.swap(0, SeqCst);
    if pede != 0
        && prender_ao_nucleo_de_agora(pede)
        && crate::fios::pedir_termino(pede).is_ok()
        && !crate::contencao::contido(&Alvo::Processo(pede))
    {
        ISOLOU.store(true, SeqCst);
    }
    NASCENDO.store(nascendo, SeqCst);
}

/// No meio do nascimento do lancado: encerra quem pede — isola e pede o
/// fim —, espera ele morrer, e a poda tira o isolamento do morto: a ultima
/// palavra ja nao o acha isolado.
fn encerrar_e_podar_quem_pede(nascendo: u64) {
    let pede = ENCERRAR.swap(0, SeqCst);
    if pede != 0
        && crate::contencao::encerrar_processo(pede).is_ok_and(|f| f.isolamento.mudou)
        && esperar_cedendo(|| !crate::fios::vivo(pede), 600).is_ok()
    {
        // Quem lista os contidos poda os mortos.
        let _ = crate::contencao::lista();
        if !crate::contencao::contido(&Alvo::Processo(pede)) {
            ISOLOU.store(true, SeqCst);
        }
    }
    NASCENDO.store(nascendo, SeqCst);
}

/// O latente (1) do adversario so de leitura, no `user.run` que um processo
/// pede pela interface nativa: a ultima palavra do nascimento perguntava
/// pela contencao de quem pede, e nao se ele ainda pede. Com o teto de
/// isolados cheio, o `process.terminate` pede o fim sem isolar; e o
/// isolamento do encerrado que morreu sai na poda. Os dois, pelo gancho do
/// meio do nascimento do lancado: o fim pedido sem o isolamento, com quem
/// pede ainda vivo na ultima palavra — preso ao nucleo da suite —; e o
/// encerrado que morreu e foi podado antes da ultima palavra, ainda na
/// tabela — o coletor segurado. Cada um exercita uma metade da pergunta
/// (`fios::encerrado`): o fim pedido, e a vida. Nos dois, a
/// ultima palavra recusa com o codigo do isolado e o detalhe de quem acabou
/// (`DENY_CONTAINED`, "processo encerrado" — o achado 3 do adversario do
/// lote A: o registro dizia "processo isolado" de quem nao foi isolado),
/// quem pediu ouve o codigo, sem a explicacao do comando — "um
/// administrador pode libera-la" nao vale para quem acabou (o achado 5) —,
/// a recusa vai uma vez a auditoria como a execucao da decisao do
/// `user.run`, nada nasce, a vaga volta, e o encerrado morre. Sem a
/// pergunta, o lancado nascia do pedido de quem ja tinha sido encerrado.
pub(super) fn contencao_o_encerrado_sem_o_isolamento_no_meio_do_user_run_nao_lanca() -> Resultado {
    crate::pessoas::esquecer_registradas();
    let resultado = (|| -> Resultado {
        let quem = operador_que_lanca(155, "encerrado-no-run");
        let caminho = caminho_do_encerravel();
        // O morto podado, com o coletor segurado: ele fica na tabela, morto,
        // até a última palavra — recolhido, a pergunta acharia o fio fora
        // dela, que também é o de quem acabou, e não exercitaria o morto.
        let ganchos: [(Gancho, &str, bool); 2] = [
            (
                pedir_o_fim_de_quem_pede,
                "com o fim pedido sem o isolamento",
                false,
            ),
            (encerrar_e_podar_quem_pede, "morto e podado", true),
        ];
        for (gancho, como_acabou, segurar) in ganchos {
            let e = Encerravel::lancar(quem)?;
            let programa = programa_que_pede();
            let pelo = alloc::format!("pelo processo {} ({})", e.fio, programa.descricao());
            let pede = como(&e, programa)?;
            let _segurado = segurar.then(super::vagas::ColetorSegurado::segurar);
            let cabeca = crate::autorizacao::ultimo_registro();
            armar(gancho, 0);
            ENCERRAR.store(e.fio, SeqCst);
            let r = fs_pedir(
                pede,
                "user.run",
                &alloc::format!(r#"{{"path":"{caminho}"}}"#),
            );
            // Vivo aqui, quem pediu estava vivo na pergunta: a morte nao volta.
            // Morto, nada se conclui: a recusa, gravada antes, pode ceder a vez.
            let vivo_na_resposta = crate::fios::vivo(e.fio);
            crate::fios::no_meio_do_nascimento_de_teste(None);
            ENCERRAR.store(0, SeqCst);
            let nascendo = NASCENDO.load(SeqCst);
            crate::log_info!(
                "teste",
                "contencao: o user.run de {}, {} no meio do nascimento de {} (vivo na resposta: {}): {}",
                e.fio,
                como_acabou,
                nascendo,
                vivo_na_resposta,
                r
            );
            if !ISOLOU.load(SeqCst) || nascendo == 0 {
                return Err("o gancho nao encerrou quem pedia, sem o isolamento, no meio");
            }
            let (codigo, motivo) = ENCERRADO;
            nao_lancou_com(&r, codigo.nome(), motivo)?;
            sem_a_explicacao(&r)?;
            if crate::fios::na_tabela_de_teste(nascendo) {
                return Err("a vaga do lancado que nao nasceu nao voltou");
            }
            so_a_recusa_do_user_run(cabeca, &caminho, codigo, Some(pelo.as_str()), motivo)?;
            Encerravel::morreu(e.fio, e.desde)?;
        }
        Ok(())
    })();
    ENCERRAR.store(0, SeqCst);
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// No meio do nascimento do filho, dentro do `fork`: pede o fim de quem
/// bifurca, sem isolar.
fn pedir_o_fim_de_quem_bifurca(filho: u64) {
    let pai = ENCERRAR.swap(0, SeqCst);
    if pai != 0 && crate::fios::pedir_termino(pai).is_ok() {
        ISOLOU.store(true, SeqCst);
    }
    NASCENDO.store(filho, SeqCst);
}

/// O latente (1) na ultima palavra do `fork`: o fim de quem bifurca pedido
/// no meio do nascimento do filho, sem o isolamento — o teto de isolados
/// cheio. A ultima palavra pergunta, alem da contencao, se quem bifurca
/// ainda pede: o filho nao nasce, a recusa vai uma vez a auditoria como a
/// do gate (`process.fork`, `DENY_CONTAINED`, "processo encerrado", com o
/// processo que bifurcou), a vaga volta, e o pai morre no ponto seguro da
/// volta da chamada. Sem a pergunta, nascia o filho de quem ja ia acabar.
pub(super) fn contencao_o_encerrado_sem_o_isolamento_no_meio_do_fork_nao_ganha_filho() -> Resultado
{
    crate::pessoas::esquecer_registradas();
    let resultado = (|| -> Resultado {
        let e = Encerravel::lancar(operador_que_lanca(156, "encerrado-no-fork"))?;
        let esperado = detalhe_por(&pelo_processo(e.fio)?, ENCERRADO.1);
        let cabeca = crate::autorizacao::ultimo_registro();
        armar(pedir_o_fim_de_quem_bifurca, 0);
        ENCERRAR.store(e.fio, SeqCst);
        Encerravel::passo(ENCERRAVEL_FILHO, 0)?;
        let morreu = Encerravel::morreu(e.fio, e.desde);
        crate::fios::no_meio_do_nascimento_de_teste(None);
        ENCERRAR.store(0, SeqCst);
        let filho = NASCENDO.load(SeqCst);
        crate::log_info!(
            "teste",
            "contencao: o fim de {} pedido no meio do nascimento de {}: pedido {}, linhas do filho {}",
            e.fio,
            filho,
            ISOLOU.load(SeqCst),
            linhas_que_comecam(e.desde, "encerravel: filho")
        );
        if !ISOLOU.load(SeqCst) || filho == 0 {
            return Err("o gancho nao pediu o fim de quem bifurcava no meio do nascimento");
        }
        if linhas_que_comecam(e.desde, "encerravel: filho") != 0 {
            return Err("o filho de quem teve o fim pedido no meio do fork nasceu");
        }
        morreu?;
        if crate::fios::na_tabela_de_teste(filho) {
            return Err("a vaga do filho que nao nasceu nao voltou");
        }
        so_a_recusa_do_fork(cabeca, politica::Codigo::DenyContained, &esperado)
    })();
    ENCERRAR.store(0, SeqCst);
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// No meio do nascimento do filho, dentro do `fork`: o journal recusado.
fn recusar_o_journal_no_meio(filho: u64) {
    recusar_o_journal();
    ISOLOU.store(true, SeqCst);
    NASCENDO.store(filho, SeqCst);
}

/// O item 3 do pedido: o gate do `fork` nao perguntava pelas revogacoes que
/// o journal recusado perdeu — o `reconfirmar` pergunta, e o gate de todo
/// comando e de toda chamada de sistema tambem: com o journal recusado,
/// nenhuma credencial vale. O processo de uma pessoa bifurcava. Agora as
/// perguntas sobre quem pede um processo o fazem, com o mesmo codigo e o
/// mesmo motivo: no gate — o journal recusado antes do `fork` — e na
/// ultima palavra — recusado no meio do nascimento do filho, pelo gancho.
/// Nos dois, o filho nao nasce, a chamada ouve `NEGADO`, e a recusa vai uma
/// vez a auditoria (`process.fork`, `DENY_NOT_AUTHENTICATED`, "journal
/// recusado: as revogacoes nao se sabem", com o processo que bifurcou).
pub(super) fn contencao_o_fork_com_o_journal_recusado_nao_ganha_filho() -> Resultado {
    const MOTIVO: &str = "journal recusado: as revogacoes nao se sabem";
    crate::pessoas::esquecer_registradas();
    let resultado = (|| -> Resultado {
        let quem = operador_que_lanca(157, "journal-no-fork");
        // No gate: o journal recusado antes do `fork`.
        let e = Encerravel::lancar(quem)?;
        let esperado = detalhe_por(&pelo_processo(e.fio)?, MOTIVO);
        let cabeca = crate::autorizacao::ultimo_registro();
        recusar_o_journal();
        let ouviu = Encerravel::passo(ENCERRAVEL_FILHO, 0)
            .and_then(|_| e.esperar_linha(&bifurcar_negado(), 1));
        devolver_o_journal();
        ouviu?;
        if linhas_que_comecam(e.desde, "encerravel: filho") != 0 {
            return Err("com o journal recusado, o processo de uma pessoa bifurcou");
        }
        so_a_recusa_do_fork(cabeca, politica::Codigo::DenyNotAuthenticated, &esperado)?;
        e.esperar_linha("processo encerrou com codigo 3", 1)?;
        // Na ultima palavra: recusado no meio do nascimento do filho.
        let e = Encerravel::lancar(quem)?;
        let esperado = detalhe_por(&pelo_processo(e.fio)?, MOTIVO);
        let cabeca = crate::autorizacao::ultimo_registro();
        armar(recusar_o_journal_no_meio, 0);
        let ouviu = Encerravel::passo(ENCERRAVEL_FILHO, 0)
            .and_then(|_| e.esperar_linha(&bifurcar_negado(), 1));
        crate::fios::no_meio_do_nascimento_de_teste(None);
        devolver_o_journal();
        let filho = NASCENDO.load(SeqCst);
        if !ISOLOU.load(SeqCst) || filho == 0 {
            return Err("o gancho nao recusou o journal no meio do nascimento");
        }
        if linhas_que_comecam(e.desde, "encerravel: filho") != 0 {
            return Err("com o journal recusado no meio, o filho nasceu");
        }
        ouviu?;
        if crate::fios::na_tabela_de_teste(filho) {
            return Err("a vaga do filho que nao nasceu nao voltou");
        }
        so_a_recusa_do_fork(cabeca, politica::Codigo::DenyNotAuthenticated, &esperado)?;
        e.esperar_linha("processo encerrou com codigo 3", 1)
    })();
    crate::fios::no_meio_do_nascimento_de_teste(None);
    devolver_o_journal();
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// No meio do nascimento do filho, dentro do `fork`: a politica do caso sem
/// a confianca do operador no editor.
fn tirar_a_confianca_de_quem_bifurca(filho: u64) {
    if por_a_politica_do_meio() {
        ISOLOU.store(true, SeqCst);
    }
    NASCENDO.store(filho, SeqCst);
}

/// A lacuna de cobertura do adversario: a confianca no editor, que a ultima
/// palavra do `fork` pergunta de novo desde o `6cea470`, sem um caso. O
/// `encerravel` selado pelo editor do caso, lancado por uma pessoa
/// operadora — cujo papel confia nele —, bifurca; e o gancho tira a
/// confianca do operador no meio do nascimento do filho, depois do gate. O
/// filho nao nasce, a chamada ouve `NEGADO`, e a recusa vai uma vez a
/// auditoria como a do gate (`process.fork`, `DENY_POLICY`, "o papel nao
/// confia no editor caso", com o processo que bifurcou), sem o registro do
/// nascimento; a vaga volta.
pub(super) fn contencao_o_editor_recusado_no_meio_do_fork_nao_ganha_filho() -> Resultado {
    crate::pessoas::esquecer_registradas();
    let resultado = super::com_editores_do_caso(|| {
        let encerravel = crate::vfs::ler_tudo(&caminho_do_encerravel())
            .map_err(|_| "o encerravel da imagem nao se leu")?;
        let caminho = alloc::format!("{}/encerravel-caso", super::CODIGO_INSTALADO);
        super::gravar_codigo(
            &caminho,
            &sigilo::codigo::selar(&encerravel, &super::EDITOR_DO_CASO.0),
        )?;
        let e = encerravel_de(operador_que_lanca(158, "editor-no-fork"), &caminho)?;
        let pelo = pelo_processo(e.fio)?;
        if !pelo.ends_with(&alloc::format!(" de {})", super::EDITOR_DO_CASO.1)) {
            crate::log_error!("teste", "{}", pelo);
            return Err("o encerravel do caso nao e o selado pelo editor do caso");
        }
        let esperado = detalhe_por(
            &pelo,
            &politica::procedencia::nao_confiado(super::EDITOR_DO_CASO.1),
        );
        let sem = super::politica_sem_a_confianca_do_operador()?;
        crate::arch::sem_interrupcoes(|| *POLITICA_DO_MEIO.lock() = Some(sem));
        let cabeca = crate::autorizacao::ultimo_registro();
        armar(tirar_a_confianca_de_quem_bifurca, 0);
        Encerravel::passo(ENCERRAVEL_FILHO, 0)?;
        let ouviu = e.esperar_linha(&bifurcar_negado(), 1);
        crate::fios::no_meio_do_nascimento_de_teste(None);
        let filho = NASCENDO.load(SeqCst);
        if !ISOLOU.load(SeqCst) || filho == 0 {
            return Err("o gancho nao tirou a confianca no editor no meio do nascimento");
        }
        if linhas_que_comecam(e.desde, "encerravel: filho") != 0 {
            return Err("o filho do codigo sem a confianca no editor nasceu");
        }
        ouviu?;
        if crate::fios::na_tabela_de_teste(filho) {
            return Err("a vaga do filho que nao nasceu nao voltou");
        }
        so_a_recusa_do_fork(cabeca, politica::Codigo::DenyPolicy, &esperado)?;
        e.esperar_linha("processo encerrou com codigo 3", 1)
    });
    crate::arch::sem_interrupcoes(|| *POLITICA_DO_MEIO.lock() = None);
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// O programa com que o `encerravel` P pede pela interface nativa no caso
/// do editor: um que declara `process.run`, de fora da imagem, selado pelo
/// editor do caso.
fn programa_selado_que_pede() -> crate::autorizacao::Programa {
    crate::autorizacao::Programa::Imagem {
        manifesto: Some(super::manifesto_de_teste(
            "pedinte",
            "process.run system.read",
        )),
        resumo: [0xab; 32],
        editor: Some(sigilo::codigo::publica_do_editor(&super::EDITOR_DO_CASO.0)),
    }
}

/// No meio do nascimento do lancado: a politica do caso sem a confianca do
/// operador no editor do programa de quem pede.
fn tirar_a_confianca_de_quem_pede(nascendo: u64) {
    if por_a_politica_do_meio() {
        ISOLOU.store(true, SeqCst);
    }
    NASCENDO.store(nascendo, SeqCst);
}

/// O latente (2) do adversario so de leitura: a reconfirmacao nao refazia
/// a confianca no editor do programa de quem pede, que o gate pergunta. O
/// `encerravel` P de uma pessoa operadora pede `user.run` pela interface
/// nativa como um programa selado pelo editor do caso, em quem o papel
/// confia; o gancho tira a confianca do operador no meio do nascimento do
/// lancado, depois do gate. A ultima palavra decide o comando de novo, com a
/// confianca de agora, e recusa: `DENY_POLICY`, "o papel nao confia no
/// editor", na resposta e uma vez na auditoria, como a execucao da decisao
/// — o editor esta na descricao do programa de quem pede —; nada nasce, e a
/// vaga volta.
pub(super) fn contencao_o_editor_recusado_no_meio_do_user_run_nao_lanca() -> Resultado {
    const MOTIVO: &str = "o papel nao confia no editor";
    crate::pessoas::esquecer_registradas();
    let resultado = super::com_editores_do_caso(|| {
        let e = Encerravel::lancar(operador_que_lanca(167, "editor-no-run"))?;
        let programa = programa_selado_que_pede();
        let pelo = alloc::format!("pelo processo {} ({})", e.fio, programa.descricao());
        if !pelo.ends_with(&alloc::format!(" de {})", super::EDITOR_DO_CASO.1)) {
            crate::log_error!("teste", "{}", pelo);
            return Err("o programa que pede nao e o selado pelo editor do caso");
        }
        let pede = como(&e, programa)?;
        let sem = super::politica_sem_a_confianca_do_operador()?;
        crate::arch::sem_interrupcoes(|| *POLITICA_DO_MEIO.lock() = Some(sem));
        let caminho = caminho_do_encerravel();
        let cabeca = crate::autorizacao::ultimo_registro();
        armar(tirar_a_confianca_de_quem_pede, 0);
        let r = fs_pedir(
            pede,
            "user.run",
            &alloc::format!(r#"{{"path":"{caminho}"}}"#),
        );
        crate::fios::no_meio_do_nascimento_de_teste(None);
        let nascendo = NASCENDO.load(SeqCst);
        crate::log_info!(
            "teste",
            "contencao: a confianca tirada no meio do nascimento de {}: {}",
            nascendo,
            r
        );
        if !ISOLOU.load(SeqCst) || nascendo == 0 {
            return Err("o gancho nao tirou a confianca no editor no meio do nascimento");
        }
        nao_lancou_com(&r, "DENY_POLICY", MOTIVO)?;
        if crate::fios::na_tabela_de_teste(nascendo) {
            return Err("a vaga do lancado que nao nasceu nao voltou");
        }
        so_a_recusa_do_user_run(
            cabeca,
            &caminho,
            politica::Codigo::DenyPolicy,
            Some(pelo.as_str()),
            MOTIVO,
        )
    });
    crate::arch::sem_interrupcoes(|| *POLITICA_DO_MEIO.lock() = None);
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// A chave do agente que o gancho revoga no meio do `user.run`.
const SEMENTE_DA_CHAVE_REVOGADA: [u8; 32] = [0x6d; 32];

/// No meio do nascimento do lancado: revoga a chave do agente de quem pede.
fn revogar_a_chave_de_quem_pede(nascendo: u64) {
    if crate::identidade::revogar(&sigilo::publica_de(&SEMENTE_DA_CHAVE_REVOGADA)).is_ok() {
        ISOLOU.store(true, SeqCst);
    }
    NASCENDO.store(nascendo, SeqCst);
}

/// A lacuna de cobertura do adversario: a chave revogada no nascimento do
/// `user.run`. O `encerravel` P de um agente pede `user.run` pela interface
/// nativa, e o gancho revoga a chave do agente no meio do nascimento do
/// lancado, depois do gate. A ultima palavra decide o comando de novo, nao
/// acha o agente nem o papel dele, e recusa: `DENY_ROLE`, "sem papel, ou
/// papel que a politica nao tem", na resposta e uma vez na auditoria, como a
/// execucao da decisao; nada nasce, e a vaga volta. Com o motivo mais longo
/// dos casos do nascimento, o detalhe da execucao passa do teto quando o fio
/// de quem pede e a decisao somam dez digitos — na suite inteira do x86 —,
/// e a descricao do programa de quem pede encolhe: a conferencia compoe o
/// esperado como o kernel ([`so_a_recusa_do_user_run`]).
pub(super) fn contencao_a_chave_revogada_no_meio_do_user_run_nao_lanca() -> Resultado {
    const MOTIVO: &str = "sem papel, ou papel que a politica nao tem";
    let chave = sigilo::publica_de(&SEMENTE_DA_CHAVE_REVOGADA);
    crate::identidade::registrar_agente_de_teste(chave, "revogada-no-run", "operador");
    let agente = crate::autorizacao::Autoridade::Sessao {
        sessao: 3,
        chave: Some(chave),
    };
    let resultado = (|| -> Resultado {
        let caminho = caminho_do_encerravel();
        let desde = crate::log::total_emitidos();
        let fio = crate::usuario::lancar_como(Some(&caminho), agente)?;
        let e = Encerravel { fio, desde };
        e.esperar_linha("encerravel: pronto", 1)?;
        let programa = programa_que_pede();
        let pelo = alloc::format!("pelo processo {} ({})", e.fio, programa.descricao());
        let pede = como(&e, programa)?;
        let cabeca = crate::autorizacao::ultimo_registro();
        armar(revogar_a_chave_de_quem_pede, 0);
        let r = fs_pedir(
            pede,
            "user.run",
            &alloc::format!(r#"{{"path":"{caminho}"}}"#),
        );
        crate::fios::no_meio_do_nascimento_de_teste(None);
        let nascendo = NASCENDO.load(SeqCst);
        crate::log_info!(
            "teste",
            "contencao: a chave de {} revogada no meio do nascimento de {}: {}",
            e.fio,
            nascendo,
            r
        );
        if !ISOLOU.load(SeqCst) || nascendo == 0 {
            return Err("o gancho nao revogou a chave no meio do nascimento");
        }
        nao_lancou_com(&r, "DENY_ROLE", MOTIVO)?;
        if crate::fios::na_tabela_de_teste(nascendo) {
            return Err("a vaga do lancado que nao nasceu nao voltou");
        }
        so_a_recusa_do_user_run(
            cabeca,
            &caminho,
            politica::Codigo::DenyRole,
            Some(pelo.as_str()),
            MOTIVO,
        )
    })();
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::identidade::esquecer_registrados();
    resultado
}

/// No meio do nascimento do lancado: a politica nova, sem `process.run` —
/// a guardada em [`POLITICA_DO_MEIO`].
fn tirar_o_process_run(nascendo: u64) {
    if por_a_politica_do_meio() {
        ISOLOU.store(true, SeqCst);
    }
    NASCENDO.store(nascendo, SeqCst);
}

/// A lacuna de cobertura do adversario: a politica nova no nascimento do
/// `user.run`. Uma pessoa pede `user.run` pelo console, e o gancho troca a
/// politica por uma sem `process.run` no meio do nascimento do lancado,
/// depois do gate. A ultima palavra decide o comando de novo, pela politica
/// de agora, e recusa: `DENY_PERMISSION`, "o papel nao tem a permissao", na
/// resposta e uma vez na auditoria, como a execucao da decisao; nada
/// nasce, e a vaga volta. A politica de antes volta no fim.
pub(super) fn contencao_a_politica_nova_no_meio_do_user_run_nao_lanca() -> Resultado {
    const MOTIVO: &str = "o papel nao tem a permissao";
    crate::pessoas::esquecer_registradas();
    let antes = crate::autorizacao::com_politica(|p| p.clone());
    let resultado = (|| -> Resultado {
        let quem = operador_que_lanca(159, "politica-no-run");
        let caminho = caminho_do_encerravel();
        let sem = super::politica_sem_o_process_run()?;
        crate::arch::sem_interrupcoes(|| *POLITICA_DO_MEIO.lock() = Some(sem));
        let cabeca = crate::autorizacao::ultimo_registro();
        armar(tirar_o_process_run, 0);
        let r = fs_pedir(
            quem,
            "user.run",
            &alloc::format!(r#"{{"path":"{caminho}"}}"#),
        );
        crate::fios::no_meio_do_nascimento_de_teste(None);
        crate::autorizacao::restaurar_politica(antes.clone());
        let nascendo = NASCENDO.load(SeqCst);
        crate::log_info!(
            "teste",
            "contencao: a politica nova no meio do nascimento de {}: {}",
            nascendo,
            r
        );
        if !ISOLOU.load(SeqCst) || nascendo == 0 {
            return Err("o gancho nao trocou a politica no meio do nascimento");
        }
        nao_lancou_com(&r, "DENY_PERMISSION", MOTIVO)?;
        if crate::fios::na_tabela_de_teste(nascendo) {
            return Err("a vaga do lancado que nao nasceu nao voltou");
        }
        so_a_recusa_do_user_run(
            cabeca,
            &caminho,
            politica::Codigo::DenyPermission,
            None,
            MOTIVO,
        )
    })();
    crate::arch::sem_interrupcoes(|| *POLITICA_DO_MEIO.lock() = None);
    crate::fios::no_meio_do_nascimento_de_teste(None);
    crate::autorizacao::restaurar_politica(antes);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// O `user.run` de `quem`, com `gancho` antes das perguntas do gate sobre
/// quem pede um processo (`autorizacao::antes_do_gate_do_lancamento_de_teste`):
/// recusado ali, depois do gate do comando. A resposta diz que nada foi
/// lancado, com o `code` e o `error` da recusa de verdade, e sem a
/// explicacao do comando ([`sem_a_explicacao`]); e a recusa vai uma vez a
/// auditoria como as perguntas a gravam — `process.run`, com quem pede e o
/// detalhe que termina em `auditado`.
fn recusado_nas_perguntas_do_gate(
    quem: crate::autorizacao::Chamador,
    gancho: Option<fn()>,
    codigo: politica::Codigo,
    motivo: &str,
    auditado: &str,
) -> Resultado {
    let caminho = caminho_do_encerravel();
    let cabeca = crate::autorizacao::ultimo_registro();
    crate::autorizacao::antes_do_gate_do_lancamento_de_teste(gancho);
    let r = fs_pedir(
        quem,
        "user.run",
        &alloc::format!(r#"{{"path":"{caminho}"}}"#),
    );
    crate::autorizacao::antes_do_gate_do_lancamento_de_teste(None);
    crate::log_info!("teste", "contencao: o user.run recusado no gate: {}", r);
    if super::decisao_do_envelope(&r) != "ALLOW"
        || fs_numero(&r, "thread_id").is_some()
        || !r.contains(r#""launched":false"#)
        || fs_texto(&r, "code").as_deref() != Some(codigo.nome())
        || fs_texto(&r, "error").as_deref() != Some(motivo)
    {
        crate::log_error!("teste", "esperava {} `{}`: {}", codigo.nome(), motivo, r);
        return Err("o user.run recusado no gate nao respondeu o codigo e o motivo da recusa");
    }
    sem_a_explicacao(&r)?;
    let gravadas = registros_depois(cabeca, |ev| {
        ev.metodo == "process.run" && ev.codigo == codigo && ev.detalhe.ends_with(auditado)
    });
    if gravadas.len() != 1 {
        crate::log_error!(
            "teste",
            "{} registro(s) `process.run` {} `{}`",
            gravadas.len(),
            codigo.nome(),
            auditado
        );
        return Err("a recusa das perguntas do gate nao foi gravada uma vez");
    }
    Ok(())
}

/// O item 4 do pedido: o `user.run` recusado nas perguntas do gate sobre
/// quem pede um processo (`autorizacao::permitir_processo`) respondia "a
/// cota de processos do papel de quem lanca esta esgotada", sem o codigo,
/// qualquer que fosse a recusa. Agora a resposta traz o codigo e o motivo
/// de verdade, como a da ultima palavra — e sem a explicacao do comando,
/// que nao e ela (o achado 5 do adversario do lote A): a da cota dizia "o
/// seu papel nao permite process.run", a da pessoa que saiu, o papel de
/// antes, e a do encerrado, "um administrador pode libera-la". Uma recusa
/// de cada, depois do gate do comando — pelo gancho de antes das perguntas,
/// a mudanca que chega de outro nucleo entre o gate e o handler; a cota,
/// sem gancho:
///
/// - a pessoa que sai: `DENY_ROLE`, "sem papel, nenhum processo";
/// - a credencial suspensa: `DENY_CREDENTIAL`, "credencial suspensa";
/// - o journal recusado: `DENY_NOT_AUTHENTICATED`;
/// - o processo que pede, com o fim pedido: `DENY_CONTAINED`, "processo
///   encerrado" — o codigo do isolado, com o detalhe de quem acabou;
/// - a confianca no editor do programa que pede, tirada: `DENY_POLICY`, "o
///   papel nao confia no editor" — a auditoria leva o nome dele;
/// - a cota esgotada: `DENY_POLICY`, a cota esgotada — a auditoria leva a
///   contagem.
pub(super) fn contencao_a_recusa_do_user_run_no_gate_diz_o_codigo() -> Resultado {
    use politica::Codigo;
    fn sair() {
        let sessao = SESSAO.swap(0, SeqCst);
        if sessao != 0 {
            crate::pessoas::sair(crate::pessoas::IdSessao(sessao.to_le_bytes()));
        }
    }
    fn suspender() {
        let pessoa = PESSOA.swap(0, SeqCst);
        if pessoa != 0 {
            let _ = crate::contencao::conter(&Alvo::Pessoa(sigilo::pessoas::IdPessoa(
                pessoa.to_le_bytes(),
            )));
        }
    }
    // Com quem pede preso ao nucleo da suite: vivo, com o fim pedido, nas
    // perguntas do gate (ver `prender_ao_nucleo_de_agora`).
    fn pedir_o_fim() {
        let pede = ENCERRAR.swap(0, SeqCst);
        if pede != 0 && prender_ao_nucleo_de_agora(pede) {
            let _ = crate::fios::pedir_termino(pede);
        }
    }
    fn tirar_a_confianca() {
        let _ = por_a_politica_do_meio();
    }
    crate::pessoas::esquecer_registradas();
    let mut suspensa = None;
    let resultado = (|| -> Resultado {
        // A pessoa que sai.
        let quem = operador_que_lanca(160, "sai-no-gate");
        let crate::autorizacao::Chamador::Pessoa(sessao) = quem else {
            return Err("quem lanca no caso nao e uma pessoa");
        };
        SESSAO.store(u64::from_le_bytes(sessao.0), SeqCst);
        recusado_nas_perguntas_do_gate(
            quem,
            Some(sair),
            Codigo::DenyRole,
            "sem papel, nenhum processo",
            "sem papel, nenhum processo",
        )?;
        // A credencial suspensa.
        let quem = operador_que_lanca(161, "suspensa-no-gate");
        let crate::autorizacao::Chamador::Pessoa(sessao) = quem else {
            return Err("quem lanca no caso nao e uma pessoa");
        };
        let pessoa = crate::pessoas::dona_da_sessao(sessao).ok_or("a sessao nao tem dona")?;
        PESSOA.store(u64::from_le_bytes(pessoa.0), SeqCst);
        suspensa = Some(pessoa);
        recusado_nas_perguntas_do_gate(
            quem,
            Some(suspender),
            Codigo::DenyCredential,
            "credencial suspensa",
            "credencial suspensa",
        )?;
        // O journal recusado.
        let quem = operador_que_lanca(162, "journal-no-gate");
        let r = recusado_nas_perguntas_do_gate(
            quem,
            Some(recusar_o_journal),
            Codigo::DenyNotAuthenticated,
            "journal recusado: as revogacoes nao se sabem",
            "journal recusado: as revogacoes nao se sabem",
        );
        devolver_o_journal();
        r?;
        // O processo que pede, com o fim pedido.
        let quem = operador_que_lanca(163, "fim-no-gate");
        let e = Encerravel::lancar(quem)?;
        let programa = programa_que_pede();
        let pelo = alloc::format!("pelo processo {} ({})", e.fio, programa.descricao());
        let pede = como(&e, programa)?;
        ENCERRAR.store(e.fio, SeqCst);
        let (encerrado, motivo) = ENCERRADO;
        recusado_nas_perguntas_do_gate(
            pede,
            Some(pedir_o_fim),
            encerrado,
            motivo,
            &detalhe_por(&pelo, motivo),
        )?;
        crate::log_info!(
            "teste",
            "contencao: quem pediu, com o fim pedido, vivo na resposta do gate: {}",
            crate::fios::vivo(e.fio)
        );
        Encerravel::morreu(e.fio, e.desde)?;
        // A confianca no editor do programa que pede, tirada.
        super::com_editores_do_caso(|| {
            let quem = operador_que_lanca(164, "editor-no-gate");
            let e = Encerravel::lancar(quem)?;
            let programa = programa_selado_que_pede();
            let pelo = alloc::format!("pelo processo {} ({})", e.fio, programa.descricao());
            let pede = como(&e, programa)?;
            let sem = super::politica_sem_a_confianca_do_operador()?;
            crate::arch::sem_interrupcoes(|| *POLITICA_DO_MEIO.lock() = Some(sem));
            recusado_nas_perguntas_do_gate(
                pede,
                Some(tirar_a_confianca),
                Codigo::DenyPolicy,
                "o papel nao confia no editor",
                &detalhe_por(
                    &pelo,
                    &politica::procedencia::nao_confiado(super::EDITOR_DO_CASO.1),
                ),
            )
        })?;
        // A cota esgotada: com a cota do operador em um, o primeiro processo
        // da pessoa a ocupa.
        let um = super::politica_trocada(&[("processos operador 8", "processos operador 1")])?;
        super::com_a_politica(um, || {
            let quem = operador_que_lanca(165, "cota-no-gate");
            let _e = Encerravel::lancar(quem)?;
            recusado_nas_perguntas_do_gate(
                quem,
                None,
                Codigo::DenyPolicy,
                crate::fios::COTA_ESGOTADA,
                "cota de processos do papel: 1 de 1",
            )
        })
    })();
    SESSAO.store(0, SeqCst);
    PESSOA.store(0, SeqCst);
    ENCERRAR.store(0, SeqCst);
    crate::arch::sem_interrupcoes(|| *POLITICA_DO_MEIO.lock() = None);
    crate::autorizacao::antes_do_gate_do_lancamento_de_teste(None);
    devolver_o_journal();
    if let Some(pessoa) = suspensa {
        let _ = crate::contencao::soltar(&Alvo::Pessoa(pessoa));
    }
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// O latente (4) do adversario: os dois "desconhecido, passa" da ultima
/// palavra recusam em vez de supor.
///
/// - O pedido de um processo sem o programa que o gate decidiu — a suite
///   pede como o processo, sem decisao (`autorizacao::como_processo_de_teste`)
///   —: as perguntas sobre quem pede um processo nao supoem "sem imagem", que
///   passava pela confianca no editor sem pergunta; recusam como fora de um
///   comando autorizado (`ERROR`), com quem pede na auditoria.
/// - O lancamento do `user.run` fora de um comando decidido: a ultima
///   palavra recusa (`ERROR`, "fora de um comando autorizado"), em nome do
///   kernel na auditoria, e nada nasce.
/// - E a excecao, pelo que ela e: o kernel que lanca por conta propria, fora
///   de um comando — o boot, a suite —, lanca.
pub(super) fn contencao_o_desconhecido_na_ultima_palavra_e_recusado() -> Resultado {
    use politica::Codigo;
    const MOTIVO: &str = "fora de um comando autorizado";
    crate::pessoas::esquecer_registradas();
    let resultado = (|| -> Resultado {
        let caminho = caminho_do_encerravel();
        // O pedido de um processo sem o programa decidido.
        let e = Encerravel::lancar(operador_que_lanca(166, "desconhecido"))?;
        let (autoridade, _) =
            crate::fios::processo(e.fio).ok_or("o encerravel que pede nao esta vivo")?;
        let cabeca = crate::autorizacao::ultimo_registro();
        let r = crate::autorizacao::como_processo_de_teste(e.fio, autoridade, || {
            crate::autorizacao::permitir_processo(autoridade, "process.run")
        });
        if r != Err((Codigo::Error, MOTIVO)) {
            crate::log_error!("teste", "{:?}", r);
            return Err("o pedido de um processo sem o programa decidido nao foi recusado");
        }
        let pelo = alloc::format!("pelo processo {} (sem imagem)", e.fio);
        let esperado = detalhe_por(&pelo, MOTIVO);
        if registros_depois(cabeca, |ev| {
            ev.metodo == "process.run" && ev.codigo == Codigo::Error && ev.detalhe == esperado
        })
        .len()
            != 1
        {
            return Err("a recusa do pedido sem o programa decidido nao foi gravada uma vez");
        }
        // O lancamento do comando, fora de um comando decidido.
        let cabeca = crate::autorizacao::ultimo_registro();
        let livres = crate::fios::vagas_livres_de_teste();
        let lancado = crate::usuario::lancar_conferido(
            Some(&caminho),
            crate::autorizacao::Autoridade::Sistema,
        );
        if !matches!(
            lancado,
            Err(crate::usuario::NaoLancou::Recusado(Codigo::Error, MOTIVO))
        ) {
            crate::log_error!("teste", "{:?}", lancado);
            return Err("o lancamento do user.run fora de um comando decidido nao foi recusado");
        }
        let do_kernel = registros_depois(cabeca, |ev| {
            ev.metodo == "process.run"
                && ev.recurso == caminho
                && ev.agente == "kernel"
                && ev.codigo == Codigo::Error
                && ev.detalhe == MOTIVO
        });
        let nascidos = registros_depois(cabeca, |ev| {
            ev.metodo == "process.run" && ev.detalhe.contains(" lancado")
        });
        if do_kernel.len() != 1 || !nascidos.is_empty() {
            return Err("a recusa fora de um comando nao foi gravada em nome do kernel, so ela");
        }
        if esperar_cedendo(|| crate::fios::vagas_livres_de_teste() >= livres, 300).is_err() {
            return Err("a vaga do lancamento recusado nao voltou");
        }
        // A excecao: o kernel, fora de um comando, lanca.
        let desde = crate::log::total_emitidos();
        let fio = crate::usuario::lancar_pelo_kernel(
            Some(&caminho),
            crate::autorizacao::Autoridade::Sistema,
        )
        .map_err(|n| {
            crate::log_error!("teste", "{:?}", n);
            "o kernel fora de um comando nao lancou"
        })?;
        Encerravel { fio, desde }.esperar_linha("encerravel: pronto", 1)
    })();
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

// ---------------------------------------------------------------------------
// Os achados do adversario do lote A do #448: a confianca no editor do
// codigo que vai rodar, perguntada de novo no nascimento, e o lancamento so
// pelo comando decidido para `process.run`
// ---------------------------------------------------------------------------

/// O `encerravel` da imagem, selado pelo editor do caso e gravado no
/// armazem em `caminho`, onde mora o codigo instalado.
fn gravar_o_encerravel_selado(caminho: &str) -> Resultado {
    let encerravel = crate::vfs::ler_tudo(&caminho_do_encerravel())
        .map_err(|_| "o encerravel da imagem nao se leu")?;
    super::gravar_codigo(
        caminho,
        &sigilo::codigo::selar(&encerravel, &super::EDITOR_DO_CASO.0),
    )
}

/// O achado 1 do adversario do lote A, no nascimento do `user.run`: a
/// conferencia do codigo pergunta a confianca no editor do selo antes de
/// ler o resto e de mapear a pilha, e a ultima palavra do nascimento so
/// decidia o comando de novo — um `policy.apply` que tirasse o editor do
/// papel no meio nao parava o nascimento. O `encerravel` selado pelo editor
/// do caso, gravado no armazem; uma pessoa operadora, cujo papel confia
/// nele, pede o `user.run` dele pelo console, e o gancho do meio do
/// nascimento tira a confianca do operador no editor, depois da
/// conferencia. A ultima palavra pergunta a confianca de novo, pela regra
/// da conferencia, e recusa: `DENY_POLICY`, "o papel nao confia no editor",
/// na resposta, com a explicacao da procedencia — e o codigo que o comando
/// decidido manda rodar —; e uma vez na auditoria, como a execucao da
/// decisao do `user.run`, com o editor no motivo, como a conferencia o
/// grava. Nada nasce, e a vaga volta.
pub(super) fn contencao_a_confianca_no_editor_do_codigo_tirada_no_meio_do_user_run_nao_lanca()
-> Resultado {
    use politica::procedencia::{Falta, nao_confiado};
    crate::pessoas::esquecer_registradas();
    let resultado = super::com_editores_do_caso(|| {
        let caminho = alloc::format!("{}/encerravel-run", super::CODIGO_INSTALADO);
        gravar_o_encerravel_selado(&caminho)?;
        let quem = operador_que_lanca(168, "editor-do-codigo");
        let sem = super::politica_sem_a_confianca_do_operador()?;
        crate::arch::sem_interrupcoes(|| *POLITICA_DO_MEIO.lock() = Some(sem));
        let cabeca = crate::autorizacao::ultimo_registro();
        armar(tirar_a_confianca_de_quem_pede, 0);
        let r = fs_pedir(
            quem,
            "user.run",
            &alloc::format!(r#"{{"path":"{caminho}"}}"#),
        );
        crate::fios::no_meio_do_nascimento_de_teste(None);
        let nascendo = NASCENDO.load(SeqCst);
        crate::log_info!(
            "teste",
            "contencao: a confianca no editor do codigo tirada no meio do nascimento de {}: {}",
            nascendo,
            r
        );
        if !ISOLOU.load(SeqCst) || nascendo == 0 {
            return Err("o gancho nao tirou a confianca no editor no meio do nascimento");
        }
        nao_lancou_com(&r, "DENY_POLICY", Falta::NaoConfiado.motivo())?;
        com_a_explicacao(&r, "DENY_PROVENANCE")?;
        if crate::fios::na_tabela_de_teste(nascendo) {
            return Err("a vaga do lancado que nao nasceu nao voltou");
        }
        so_a_recusa_do_user_run(
            cabeca,
            &caminho,
            politica::Codigo::DenyPolicy,
            None,
            &nao_confiado(super::EDITOR_DO_CASO.1),
        )
    });
    crate::arch::sem_interrupcoes(|| *POLITICA_DO_MEIO.lock() = None);
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// O achado 1 do adversario do lote A, no lancamento do kernel por conta
/// propria, fora de um comando: a mesma pergunta, com a recusa gravada em
/// nome do kernel. O sistema lanca o `encerravel` selado pelo editor do caso
/// (`usuario::lancar_pelo_kernel`) — o papel `sistema` confia nele, e a
/// conferencia passa —, e o gancho do meio do nascimento tira a confianca do
/// sistema no editor. Recusado: quem lancou ouve `DENY_POLICY`, "o papel nao
/// confia no editor"; a auditoria grava a recusa uma vez, em nome do
/// kernel — `process.run`, o caminho e o motivo com o editor —, sem nenhum
/// `processo N lancado`. Nada nasce, e a vaga volta.
pub(super) fn contencao_a_confianca_no_editor_do_codigo_tirada_no_meio_do_lancamento_do_kernel_nao_lanca()
-> Resultado {
    use politica::Codigo;
    use politica::procedencia::{Falta, nao_confiado};
    let resultado = super::com_editores_do_caso(|| {
        let caminho = alloc::format!("{}/encerravel-kernel", super::CODIGO_INSTALADO);
        gravar_o_encerravel_selado(&caminho)?;
        // O sistema sem a confianca no editor do caso; o operador e o
        // administrador com ela.
        let sem = super::politica_trocada(&[
            (
                "editores operador bancada",
                "editores operador bancada caso",
            ),
            (
                "editores administrador bancada",
                "editores administrador bancada caso",
            ),
        ])?;
        crate::arch::sem_interrupcoes(|| *POLITICA_DO_MEIO.lock() = Some(sem));
        let cabeca = crate::autorizacao::ultimo_registro();
        armar(tirar_a_confianca_de_quem_pede, 0);
        let lancado = crate::usuario::lancar_pelo_kernel(
            Some(&caminho),
            crate::autorizacao::Autoridade::Sistema,
        );
        crate::fios::no_meio_do_nascimento_de_teste(None);
        let nascendo = NASCENDO.load(SeqCst);
        crate::log_info!(
            "teste",
            "contencao: o lancamento do kernel, com a confianca tirada no meio do nascimento de {}: {:?}",
            nascendo,
            lancado
        );
        if !ISOLOU.load(SeqCst) || nascendo == 0 {
            return Err("o gancho nao tirou a confianca no editor no meio do nascimento");
        }
        if !matches!(
            lancado,
            Err(crate::usuario::NaoLancou::Recusado(Codigo::DenyPolicy, m))
                if m == Falta::NaoConfiado.motivo()
        ) {
            return Err(
                "o lancamento do kernel do codigo sem a confianca no editor nao foi recusado",
            );
        }
        if crate::fios::na_tabela_de_teste(nascendo) {
            return Err("a vaga do lancado que nao nasceu nao voltou");
        }
        let gravado = nao_confiado(super::EDITOR_DO_CASO.1);
        let do_kernel = registros_depois(cabeca, |ev| {
            ev.metodo == "process.run"
                && ev.recurso == caminho
                && ev.agente == "kernel"
                && ev.codigo == Codigo::DenyPolicy
                && ev.detalhe == gravado
        });
        let nascidos = registros_depois(cabeca, |ev| {
            ev.metodo == "process.run" && ev.detalhe.contains(" lancado")
        });
        if do_kernel.len() != 1 || !nascidos.is_empty() {
            crate::log_error!(
                "teste",
                "{} recusa(s) em nome do kernel, {} lancamento(s)",
                do_kernel.len(),
                nascidos.len()
            );
            return Err("a recusa do lancamento do kernel nao foi gravada em nome dele, so ela");
        }
        Ok(())
    });
    crate::arch::sem_interrupcoes(|| *POLITICA_DO_MEIO.lock() = None);
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    resultado
}

/// O arquivo que a verificacao do caso abaixo confere — e o caminho dele no
/// armazem, como a verificacao o diz.
const VERIFICADO: &str = "/armazem/compartilhado/lanca-na-verificacao.txt";
const VERIFICADO_NO_ARMAZEM: &str = "compartilhado/lanca-na-verificacao.txt";

/// O que os dois lancamentos de dentro do `fs.verify` ouviram — o do
/// `user.run` e o do kernel —: `None`, nao tentado; `Ok`, o fio lancado;
/// `Err`, o codigo e o motivo da recusa.
type Ouvido = Option<Result<u64, (politica::Codigo, &'static str)>>;
static NO_COMANDO_ERRADO: crate::trava::Mutex<[Ouvido; 2]> = crate::trava::Mutex::new([None, None]);

/// Na verificacao do `fs.verify` — um comando que o gate decidiu para
/// `fs.read`, e nao para `process.run` —, sem trava nenhuma na mao: lanca o
/// `encerravel` pelo lancamento do `user.run` e pelo do kernel, uma vez, e
/// guarda o que cada um ouviu.
fn lancar_no_comando_errado(caminho: &str) {
    use crate::usuario::NaoLancou;
    if caminho != VERIFICADO_NO_ARMAZEM
        || crate::arch::sem_interrupcoes(|| NO_COMANDO_ERRADO.lock()[0].is_some())
    {
        return;
    }
    let ouvido = |r: Result<u64, NaoLancou>| -> Ouvido {
        Some(match r {
            Ok(fio) => Ok(fio),
            Err(NaoLancou::Recusado(c, m) | NaoLancou::PorQuemPede(c, m)) => Err((c, m)),
            Err(NaoLancou::Fio(m)) => Err((politica::Codigo::Error, m)),
            Err(NaoLancou::Codigo(_)) => Err((politica::Codigo::Error, "o codigo nao se leu")),
        })
    };
    let programa = caminho_do_encerravel();
    let do_comando = ouvido(crate::usuario::lancar_conferido(
        Some(&programa),
        crate::autorizacao::autoridade_atual(),
    ));
    let do_kernel = ouvido(crate::usuario::lancar_pelo_kernel(
        Some(&programa),
        crate::autorizacao::Autoridade::Sistema,
    ));
    crate::arch::sem_interrupcoes(|| *NO_COMANDO_ERRADO.lock() = [do_comando, do_kernel]);
}

/// O achado 6 do adversario do lote A: a ultima palavra do nascimento, num
/// comando decidido, decidia o comando de novo pela permissao **dele** — e
/// um comando que nao e o `user.run`, cujo handler chamasse o lancamento,
/// passaria: o processo nasceria sem decisao nenhuma de `process.run`. O
/// `fs.verify` do sistema e decidido pelo gate para `fs.read`, e a
/// verificacao chama, sem trava na mao, o gancho da suite — o lugar de um
/// handler que lancasse. Ali dentro, o lancamento do `user.run`
/// (`usuario::lancar_conferido`) e o do kernel (`usuario::lancar_pelo_kernel`)
/// sao recusados como fora de um comando autorizado (`ERROR`) — dentro de
/// um comando o lancamento e dele, diga quem lanca o que disser —, cada
/// recusa vai a auditoria como a execucao da decisao do `fs.verify`, e nada
/// nasce. Sem a pergunta pela permissao, os dois lancavam com a autoridade
/// do sistema.
pub(super) fn contencao_o_lancamento_num_comando_que_nao_e_o_user_run_e_recusado() -> Resultado {
    use politica::Codigo;
    const FORA: (Codigo, &str) = (Codigo::Error, "fora de um comando autorizado");
    let sistema = sistema_aqui();
    let resultado = (|| -> Resultado {
        super::diretorios_acima(VERIFICADO)?;
        let r = super::fs_gravar(
            sistema,
            VERIFICADO,
            super::versao_no_armazem(VERIFICADO),
            "o arquivo que a verificacao confere",
        );
        if fs_numero(&r, "version").is_none() {
            crate::log_error!("teste", "{}", r);
            return Err("o arquivo do caso nao foi gravado");
        }
        crate::arch::sem_interrupcoes(|| *NO_COMANDO_ERRADO.lock() = [None, None]);
        let livres = crate::fios::vagas_livres_de_teste();
        let cabeca = crate::autorizacao::ultimo_registro();
        crate::armazem::no_meio_da_verificacao_de_teste(Some(lancar_no_comando_errado));
        let r = fs_pedir(
            sistema,
            "fs.verify",
            &alloc::format!(r#"{{"path":"{VERIFICADO}"}}"#),
        );
        crate::armazem::no_meio_da_verificacao_de_teste(None);
        let ouvidos = crate::arch::sem_interrupcoes(|| *NO_COMANDO_ERRADO.lock());
        crate::log_info!(
            "teste",
            "contencao: os lancamentos dentro do fs.verify ouviram {:?}: {}",
            ouvidos,
            r
        );
        if super::decisao_do_envelope(&r) != "ALLOW" {
            return Err("o fs.verify do caso nao foi decidido pelo gate");
        }
        for ouvido in ouvidos {
            match ouvido {
                Some(Err(recusa)) if recusa == FORA => {}
                None => return Err("a verificacao nao chegou ao arquivo do caso"),
                Some(Ok(_)) => {
                    return Err("o lancamento num comando que nao e o user.run lancou um processo");
                }
                Some(Err(_)) => {
                    return Err(
                        "o lancamento num comando que nao e o user.run foi recusado por outro motivo",
                    );
                }
            }
        }
        let programa = caminho_do_encerravel();
        let recusas = registros_depois(cabeca, |ev| {
            ev.metodo == "fs.verify"
                && ev.recurso == programa
                && ev.codigo == Codigo::Error
                && ev
                    .detalhe
                    .contains("fora de um comando autorizado; decisao ")
        });
        let nascidos = registros_depois(cabeca, |ev| ev.detalhe.contains(" lancado"));
        if recusas.len() != 2 || !nascidos.is_empty() {
            crate::log_error!(
                "teste",
                "{} recusa(s) na execucao do fs.verify, {} lancamento(s)",
                recusas.len(),
                nascidos.len()
            );
            return Err(
                "as recusas dos lancamentos nao foram gravadas como a execucao do fs.verify, so elas",
            );
        }
        if esperar_cedendo(|| crate::fios::vagas_livres_de_teste() >= livres, 300).is_err() {
            return Err("as vagas dos lancamentos recusados nao voltaram");
        }
        Ok(())
    })();
    crate::armazem::no_meio_da_verificacao_de_teste(None);
    crate::arch::sem_interrupcoes(|| *NO_COMANDO_ERRADO.lock() = [None, None]);
    encerrar_os_encerraveis();
    resultado
}
