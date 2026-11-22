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
//!
//! E os achados do adversário da integração `f018bee..2c39e80` (o lote A3
//! do #448), no fim do arquivo: a última palavra do nascimento amarra a
//! autoridade e o caminho do lançamento aos do comando — de dentro de um
//! `user.run`, pelo gancho de antes das perguntas do gate, também com a
//! autoridade de outra pessoa —, e a mesma pergunta vem antes, no começo
//! do lançamento, sem ler o código — o caminho que não existe, de dentro
//! do `user.run` e com o trinco fechado (o adversário do lote A3) —; o
//! registro do nascimento diz o editor pelo nome que a última palavra
//! perguntou — pelo gancho do meio do nascimento, que troca o nome —; o
//! `user.run` permitido que não lança grava o desfecho — o caminho que não
//! existe, e o fio que não nasce, com a tabela de fios cheia —; e o kernel
//! que não lança mais por conta própria depois do boot, que um comando
//! ainda lança.
//!
//! E os do lote A4 (o #466 e o #467), no fim do arquivo: a recusa das
//! perguntas sobre quem pede dentro de um `user.run` ganha o desfecho do
//! comando — a execução da decisão, com o mesmo código e, abaixo do teto,
//! o mesmo detalhe, além da recusa do gate, que continua como era —,
//! também a da cota
//! contada de novo no nascimento, pelo gancho de antes dele
//! (`autorizacao::antes_do_nascimento_do_lancamento_de_teste`); fora de um
//! comando, só a do gate. A imagem que se lê e não se carrega — o que não é
//! ELF, o manifesto que não se lê — é recusada antes de o fio nascer, com o
//! desfecho. E a que não se mapeia no fio novo — a falha armada do
//! mapeamento, pelo gancho do meio do nascimento — grava o desfecho depois
//! do `processo N lancado`, em nome de quem o gate decidiu; nenhum desfecho
//! guardado fica vivo depois (`autorizacao::desfechos_vivos_de_teste`).
//!
//! E os do lote A5 — achados do adversário do lote A4 —, no fim do arquivo:
//! a conferência da imagem com teto, sem medir tempo — a tabela de
//! segmentos de entradas demais e as notas acima do orçamento recusadas
//! pelo motivo novo, a imagem de muitas notas do adversário também, e o
//! `ola` no teto, que lança —; e o segmento vazio com o destino no teto do
//! espaço do usuário, que ganhava a página de cima dele, recusado — e o
//! mesmo segmento vazio dentro do espaço, que lança.
//!
//! E os do lote A6 — achados do adversário e do revisor do lote A5 —, no
//! fim do arquivo: o motivo de duas recusas que os do lote A5 não fixavam —
//! as notas acima do orçamento, recusadas antes de o achador ler o
//! segmento, e o segmento que acaba no teto, que invade a pilha —; e a
//! imagem cujos segmentos pedem, somados, mais páginas que o espaço do
//! programa, recusada pela conta pura, sem carregar — e a do teto, que se
//! confere.

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

/// Enche a tabela de fios com fios do kernel que cedem até o caso soltá-los
/// ([`esvaziar_a_tabela`]). `Ok` com quantos nasceram; `Err` com o motivo
/// de um que não nasceu por outra coisa que a falta de vaga — os que
/// nasceram antes dele continuam contados, e saem do mesmo jeito.
fn encher_a_tabela() -> Result<usize, &'static str> {
    SOLTAR.store(false, SeqCst);
    OCUPANTES.store(0, SeqCst);
    let mut criados = 0usize;
    for _ in 0..crate::fios::MAX_FIOS {
        match crate::fios::criar("teste-tabela-cheia", ocupante, 0) {
            Ok(_) => {
                OCUPANTES.fetch_add(1, SeqCst);
                criados += 1;
            }
            Err(motivo) if motivo.contains("vaga") => break,
            Err(motivo) => return Err(motivo),
        }
    }
    Ok(criados)
}

/// Solta os fios que enchiam a tabela ([`encher_a_tabela`]), e espera eles
/// saírem e as vagas voltarem a `livres`.
fn esvaziar_a_tabela(livres: usize) -> Resultado {
    SOLTAR.store(true, SeqCst);
    let sairam = esperar_cedendo(|| OCUPANTES.load(SeqCst) == 0, 600)
        .map_err(|_| "os fios que enchiam a tabela nao sairam");
    let recolhidos = esperar_cedendo(|| crate::fios::vagas_livres_de_teste() >= livres, 600)
        .map_err(|_| "as vagas dos fios que enchiam a tabela nao voltaram");
    sairam.and(recolhidos)
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
    let cheia = encher_a_tabela();
    let resultado = (|| -> Resultado {
        let criados = cheia.map_err(|motivo| {
            crate::log_error!("teste", "a criacao recusou: {}", motivo);
            "um fio nao nasceu por outro motivo que a falta de vaga"
        })?;
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
    let esvaziada = esvaziar_a_tabela(livres_antes);
    resultado?;
    esvaziada?;
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

/// O desfecho do `user.run` de `caminho` na auditoria, depois de `cabeca`:
/// a decisao do comando (`ALLOW`) uma vez, e uma execucao dela com `codigo`
/// e o detalhe `<pelo: >gravado; decisao D` ([`so_a_recusa_do_user_run`]),
/// que cita essa decisao — nem outra, nem a seguinte —; e nenhum `processo
/// N lancado`.
fn o_desfecho_do_user_run(
    cabeca: u64,
    caminho: &str,
    codigo: politica::Codigo,
    pelo: Option<&str>,
    gravado: &str,
) -> Resultado {
    use politica::Codigo;
    so_a_recusa_do_user_run(cabeca, caminho, codigo, pelo, gravado)?;
    let decisoes = registros_depois(cabeca, |ev| {
        ev.metodo == "user.run"
            && ev.recurso == caminho
            && ev.codigo == Codigo::Allow
            && super::decisao_executada(&ev.detalhe).is_none()
    });
    let execucoes = registros_depois(cabeca, |ev| {
        ev.metodo == "user.run"
            && ev.recurso == caminho
            && ev.codigo == codigo
            && e_a_execucao_de(ev, pelo, gravado)
    });
    match (&decisoes[..], &execucoes[..]) {
        ([(d, _)], [(e, ev)]) if super::decisao_executada(&ev.detalhe) == Some(*d) && d < e => {
            Ok(())
        }
        _ => {
            crate::log_error!(
                "teste",
                "{} decisao(oes) do user.run; execucoes {:?}",
                decisoes.len(),
                execucoes
                    .iter()
                    .map(|(n, ev)| (n, &ev.detalhe))
                    .collect::<alloc::vec::Vec<_>>()
            );
            Err("o desfecho do user.run nao cita a decisao do comando")
        }
    }
}

/// O `user.run` de `quem`, com `gancho` antes das perguntas do gate sobre
/// quem pede um processo (`autorizacao::antes_do_gate_do_lancamento_de_teste`):
/// recusado ali, depois do gate do comando. A resposta diz que nada foi
/// lancado, com o `code` e o `error` da recusa de verdade, e sem a
/// explicacao do comando ([`sem_a_explicacao`]); a recusa vai uma vez a
/// auditoria como as perguntas a gravam — `process.run`, com quem pede
/// (`pelo`, se e um processo) na frente do detalhe `gravado` —; e, desde o
/// lote A4 (o #466), o `ALLOW` do comando ganha o desfecho: uma execucao da
/// decisao do `user.run`, com o mesmo codigo e, abaixo do teto, o mesmo
/// detalhe — o editor
/// pelo nome, a contagem da cota —, citando-a ([`o_desfecho_do_user_run`]).
fn recusado_nas_perguntas_do_gate(
    quem: crate::autorizacao::Chamador,
    gancho: Option<fn()>,
    codigo: politica::Codigo,
    motivo: &str,
    pelo: Option<&str>,
    gravado: &str,
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
    // A recusa do gate, como ele a grava: o detalhe como o kernel o compoe
    // — quem pede na frente, abreviado so acima do teto —, inteiro.
    let auditado = politica::auditoria::detalhe_composto(pelo, gravado, "");
    let gravadas = registros_depois(cabeca, |ev| {
        ev.metodo == "process.run" && ev.codigo == codigo && ev.detalhe == auditado
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
    // E o desfecho do `user.run` (o #466).
    o_desfecho_do_user_run(cabeca, &caminho, codigo, pelo, gravado)
        .map_err(|_| "a recusa de quem pede no user.run ficou sem o desfecho")
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
///
/// E, desde o lote A4 (o #466), cada recusa vai a auditoria duas vezes,
/// cada registro uma vez: a do gate, como ele a grava — `process.run`, com
/// quem pede —, e o desfecho do `user.run` — a execucao da decisao do
/// comando, com o mesmo codigo e, abaixo do teto, o mesmo detalhe,
/// citando-a. Antes, o
/// `ALLOW` do comando ficava sem nada que o citasse.
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
            None,
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
            None,
            "credencial suspensa",
        )?;
        // O journal recusado.
        let quem = operador_que_lanca(162, "journal-no-gate");
        let r = recusado_nas_perguntas_do_gate(
            quem,
            Some(recusar_o_journal),
            Codigo::DenyNotAuthenticated,
            "journal recusado: as revogacoes nao se sabem",
            None,
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
            Some(&pelo),
            motivo,
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
                Some(&pelo),
                &politica::procedencia::nao_confiado(super::EDITOR_DO_CASO.1),
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
                None,
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
/// - O lancamento do `user.run` fora de um comando decidido: a pergunta da
///   ultima palavra sobre o lancamento recusa (`ERROR`, "fora de um comando
///   autorizado") — desde o achado 2 do adversario do lote A3 do #448, ja
///   no comeco do lancamento —, em nome do kernel na auditoria, e nada
///   nasce.
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
            Err(NaoLancou::Fio(m) | NaoLancou::Imagem(m)) => Err((politica::Codigo::Error, m)),
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

// ---------------------------------------------------------------------------
// Os achados do adversario da integracao `f018bee..2c39e80` (o lote A3 do
// #448): a ultima palavra amarrada a autoridade e ao caminho do comando, o
// nome do editor de agora no nascimento, o desfecho do `user.run` que nao
// lanca, e o kernel que nao lanca mais por conta propria depois do boot
// ---------------------------------------------------------------------------

/// O que os lancamentos de dentro do `user.run` do operador ouviram: o do
/// sistema (`usuario::lancar_como_sistema`); o do comando com outro
/// caminho; o do comando com outra autoridade — a do sistema, e a de outra
/// pessoa, da mesma especie —; o do exemplo embutido; e os dois de um
/// caminho que nao existe, pelo comando e pelo sistema. `None`, nao
/// tentado; `Ok`, o fio que nasceu; `Err`, o motivo da recusa.
static DE_DENTRO: crate::trava::Mutex<[Option<Result<u64, &'static str>>; 7]> =
    crate::trava::Mutex::new([None; 7]);

/// A sessao da outra pessoa do caso abaixo — os oito bytes dela —, com que
/// o gancho lanca de dentro do `user.run` do operador.
static OUTRA_PESSOA: AtomicU64 = AtomicU64::new(0);

/// Um caminho que o papel do operador alcanca — `/bin` — e que nao existe.
const CAMINHO_QUE_NAO_EXISTE: &str = "/bin/nao-existe";

/// O motivo de um lancamento recusado, ou o fio que nasceu.
fn ouvido_de(r: Result<u64, crate::usuario::NaoLancou>) -> Result<u64, &'static str> {
    use crate::usuario::NaoLancou;
    r.map_err(|n| match n {
        NaoLancou::Recusado(_, m)
        | NaoLancou::PorQuemPede(_, m)
        | NaoLancou::Fio(m)
        | NaoLancou::Imagem(m) => m,
        NaoLancou::Codigo(_) => "o codigo nao se leu",
    })
}

/// O `ola` da imagem: o outro caminho, que o gate nao decidiu.
fn caminho_do_ola() -> alloc::string::String {
    alloc::format!("{}/ola", crate::usuario::DIRETORIO_DOS_COMPILADOS)
}

/// Antes das perguntas do gate sobre quem pede, dentro do `user.run` do
/// operador (`autorizacao::antes_do_gate_do_lancamento_de_teste`): lanca de
/// dentro do comando sete vezes, e guarda o que cada lancamento ouviu. E a
/// prova de conceito do adversario — o lancamento como o sistema —, as
/// formas do `lancar_conferido` — outro caminho, a autoridade do sistema, e
/// a de outra pessoa —, o exemplo embutido, e os dois de um caminho que o
/// gate nao decidiu e que nao existe — pelo comando e pelo sistema —, que
/// so a pergunta do comeco do lancamento recusa antes de ler o arquivo.
fn lancar_de_dentro_do_user_run() {
    let decidido = caminho_do_encerravel();
    let atual = crate::autorizacao::autoridade_atual();
    let outra = crate::autorizacao::Autoridade::Pessoa {
        sessao: crate::pessoas::IdSessao(OUTRA_PESSOA.load(SeqCst).to_le_bytes()),
    };
    let ouvidos = [
        crate::usuario::lancar_como_sistema(Some(&decidido)),
        ouvido_de(crate::usuario::lancar_conferido(
            Some(&caminho_do_ola()),
            atual,
        )),
        ouvido_de(crate::usuario::lancar_conferido(
            Some(&decidido),
            crate::autorizacao::Autoridade::Sistema,
        )),
        ouvido_de(crate::usuario::lancar_conferido(Some(&decidido), outra)),
        ouvido_de(crate::usuario::lancar_conferido(None, atual)),
        ouvido_de(crate::usuario::lancar_conferido(
            Some(CAMINHO_QUE_NAO_EXISTE),
            atual,
        )),
        crate::usuario::lancar_como_sistema(Some(CAMINHO_QUE_NAO_EXISTE)),
    ];
    crate::arch::sem_interrupcoes(|| *DE_DENTRO.lock() = ouvidos.map(Some));
}

/// O item 2 do lote A3 do #448: a ultima palavra do nascimento, num
/// comando decidido, refazia a decisao do comando, mas nao olhava a
/// autoridade nem o caminho do processo que nasce. Dentro do `user.run` de
/// uma pessoa operadora, o gancho de antes das perguntas do gate lanca como
/// o sistema o `encerravel` — o mesmo caminho que o comando decidiu —, e
/// pelo lancamento do `user.run` outro programa, o mesmo com a autoridade
/// do sistema e com a de outra pessoa operadora — a mesma especie de
/// autoridade, outro titular —, e o exemplo embutido. Os cinco recusados
/// como fora de um comando autorizado (`ERROR`), cada um na auditoria como
/// a execucao da decisao do operador, com o caminho que tentou; so o do
/// `user.run` nasce — um `processo N lancado` —, e age como o operador.
/// Antes, os quatro de entao nasciam, dois com a autoridade do sistema, e
/// todos com o nascimento gravado como a execucao da decisao do operador.
///
/// E o achado 2 do adversario do lote A3: a amarracao valia so no
/// nascimento, e um lancamento de um caminho que o gate nao decidiu e que
/// nao existe — pelo comando, e como o sistema — perguntava sobre quem pede
/// com a autoridade dele e lia o arquivo, e a leitura que falhava ia a
/// auditoria como a execucao da decisao do operador ("nao encontrado"). Os
/// dois sao recusados como fora de um comando autorizado ja no comeco do
/// lancamento, e gravados como a ultima palavra grava a recusa dela: nenhum
/// registro do caminho diz outra coisa.
pub(super) fn contencao_o_lancamento_de_dentro_do_user_run_so_nasce_com_a_autoridade_e_o_caminho()
-> Resultado {
    use politica::Codigo;
    const FORA: &str = "fora de um comando autorizado";
    const NASCERAM: [&str; 7] = [
        "o lancamento como sistema de dentro do user.run nasceu",
        "o lancamento de outro caminho de dentro do user.run nasceu",
        "o lancamento com outra autoridade de dentro do user.run nasceu",
        "o lancamento com a autoridade de outra pessoa de dentro do user.run nasceu",
        "o exemplo embutido de dentro do user.run nasceu",
        "o lancamento de um caminho que nao existe de dentro do user.run nasceu",
        "o lancamento como sistema de um caminho que nao existe de dentro do user.run nasceu",
    ];
    crate::pessoas::esquecer_registradas();
    crate::arch::sem_interrupcoes(|| *DE_DENTRO.lock() = [None; 7]);
    let resultado = (|| -> Resultado {
        let quem = operador_que_lanca(170, "lanca-de-dentro");
        let crate::autorizacao::Chamador::Pessoa(sessao) = quem else {
            return Err("quem lanca no caso nao e uma pessoa");
        };
        let crate::autorizacao::Chamador::Pessoa(outra) = operador_que_lanca(175, "outra-pessoa")
        else {
            return Err("a outra pessoa do caso nao e uma pessoa");
        };
        OUTRA_PESSOA.store(u64::from_le_bytes(outra.0), SeqCst);
        let decidido = caminho_do_encerravel();
        let cabeca = crate::autorizacao::ultimo_registro();
        crate::autorizacao::antes_do_gate_do_lancamento_de_teste(Some(
            lancar_de_dentro_do_user_run,
        ));
        let r = fs_pedir(
            quem,
            "user.run",
            &alloc::format!(r#"{{"path":"{decidido}"}}"#),
        );
        crate::autorizacao::antes_do_gate_do_lancamento_de_teste(None);
        let ouvidos = crate::arch::sem_interrupcoes(|| *DE_DENTRO.lock());
        crate::log_info!(
            "teste",
            "contencao: os lancamentos de dentro do user.run ouviram {:?}: {}",
            ouvidos,
            r
        );
        let fio = fs_numero(&r, "thread_id").ok_or("o user.run do operador nao lancou")?;
        for (ouvido, nasceu) in ouvidos.iter().zip(NASCERAM) {
            match ouvido {
                Some(Err(m)) if *m == FORA => {}
                None => return Err("o gancho nao lancou de dentro do user.run"),
                Some(Ok(_)) => return Err(nasceu),
                Some(Err(_)) => {
                    return Err(
                        "um lancamento de dentro do user.run foi recusado por outro motivo",
                    );
                }
            }
        }
        // As sete recusas, como a execucao da decisao do operador, com o
        // caminho de cada uma; e um nascimento so, o do `user.run`.
        let mut recursos: alloc::vec::Vec<alloc::string::String> = registros_depois(cabeca, |ev| {
            ev.metodo == "user.run" && ev.codigo == Codigo::Error && e_a_execucao_de(ev, None, FORA)
        })
        .into_iter()
        .map(|(_, ev)| ev.recurso)
        .collect();
        recursos.sort();
        let mut esperados = alloc::vec![
            decidido.clone(),
            decidido.clone(),
            decidido.clone(),
            caminho_do_ola(),
            alloc::string::String::from("<exemplo embutido>"),
            alloc::string::String::from(CAMINHO_QUE_NAO_EXISTE),
            alloc::string::String::from(CAMINHO_QUE_NAO_EXISTE),
        ];
        esperados.sort();
        // E o caminho que nao existe so nas duas recusas: nada o leu, e
        // nenhuma pergunta sobre quem pede o gravou.
        let do_que_nao_existe = registros_depois(cabeca, |ev| ev.recurso == CAMINHO_QUE_NAO_EXISTE);
        if do_que_nao_existe.len() != 2 {
            for (seq, ev) in &do_que_nao_existe {
                crate::log_error!("teste", "registro {}: {} {}", seq, ev.metodo, ev.detalhe);
            }
            return Err("o caminho que nao existe foi lido, ou gravado por outro motivo");
        }
        let lancados = registros_depois(cabeca, |ev| {
            ev.codigo == Codigo::Allow && ev.detalhe.contains(" lancado")
        });
        let nasceu = alloc::format!("processo {fio} lancado");
        let so_o_do_user_run = matches!(
            &lancados[..],
            [(_, ev)] if ev.metodo == "user.run" && e_a_execucao_de(ev, None, &nasceu)
        );
        if recursos != esperados || !so_o_do_user_run {
            crate::log_error!(
                "teste",
                "recusas de {:?}; {} lancamento(s)",
                recursos,
                lancados.len()
            );
            return Err("a auditoria nao diz as sete recusas e um nascimento so, o do user.run");
        }
        // O que nasceu age como o operador.
        match crate::fios::processo(fio) {
            Some((crate::autorizacao::Autoridade::Pessoa { sessao: s }, _)) if s == sessao => {
                Ok(())
            }
            outro => {
                crate::log_error!("teste", "{:?}", outro.map(|(a, _)| a));
                Err("o processo do user.run nao age como o operador")
            }
        }
    })();
    crate::autorizacao::antes_do_gate_do_lancamento_de_teste(None);
    crate::arch::sem_interrupcoes(|| *DE_DENTRO.lock() = [None; 7]);
    OUTRA_PESSOA.store(0, SeqCst);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// O registro de editores com o do caso renomeado, que o gancho poe no
/// meio do nascimento: um gancho e uma funcao sem estado.
static EDITORES_DO_MEIO: crate::trava::Mutex<Option<alloc::vec::Vec<crate::identidade::Editor>>> =
    crate::trava::Mutex::new(None);

/// O nome com que o editor do caso volta ao registro no meio do nascimento.
const NOME_NOVO: &str = "caso-novo";

/// No meio do nascimento do lancado: a chave do editor do caso sai do
/// registro e volta com outro nome — o registro trocado de uma vez.
fn renomear_o_editor(nascendo: u64) {
    if let Some(novos) = crate::arch::sem_interrupcoes(|| EDITORES_DO_MEIO.lock().take()) {
        crate::identidade::trocar_editores_de_teste(novos);
        ISOLOU.store(true, SeqCst);
    }
    NASCENDO.store(nascendo, SeqCst);
}

/// O item 4 do lote A3 do #448: a ultima palavra do nascimento pergunta de
/// novo a confianca no editor do codigo, e a pergunta devolve o nome dele
/// de agora — que o registro do nascimento descartava, gravando o da
/// conferencia. O `encerravel` selado pelo editor do caso, no armazem; uma
/// pessoa operadora, cujo papel confia no editor pelos dois nomes — "caso"
/// e "caso-novo" —, pede o `user.run` dele, e o gancho do meio do
/// nascimento troca o nome da chave no registro, depois da conferencia. O
/// processo nasce, e o registro do nascimento diz o editor pelo nome de
/// agora — `processo N lancado: codigo R de caso-novo` —, como a execucao
/// da decisao. Antes, dizia `de caso`.
pub(super) fn codigo_o_nascimento_grava_o_nome_do_editor_de_agora() -> Resultado {
    use crate::identidade::Editor;
    crate::pessoas::esquecer_registradas();
    let resultado = super::com_editores_do_caso(|| {
        let caminho = alloc::format!("{}/encerravel-renomeado", super::CODIGO_INSTALADO);
        gravar_o_encerravel_selado(&caminho)?;
        let resumo = crate::vfs::ler_tudo(&caminho_do_encerravel())
            .map(|b| politica::auditoria::comeco_do_resumo(&sigilo::codigo::resumo(&b)))
            .map_err(|_| "o encerravel da imagem nao se leu")?;
        let dois_nomes = super::politica_trocada(&[
            ("editores sistema bancada", "editores sistema bancada caso"),
            (
                "editores operador bancada",
                "editores operador bancada caso caso-novo",
            ),
            (
                "editores administrador bancada",
                "editores administrador bancada caso",
            ),
        ])?;
        super::com_a_politica(dois_nomes, || {
            let quem = operador_que_lanca(171, "editor-renomeado");
            // O registro de agora, com o editor do caso renomeado, pronto
            // para o gancho.
            let chave = sigilo::codigo::publica_do_editor(&super::EDITOR_DO_CASO.0);
            let agora = crate::identidade::trocar_editores_de_teste(alloc::vec::Vec::new());
            let renomeados: alloc::vec::Vec<Editor> = agora
                .iter()
                .map(|e| Editor {
                    chave: e.chave,
                    nome: if e.chave == chave {
                        NOME_NOVO.into()
                    } else {
                        e.nome.clone()
                    },
                })
                .collect();
            crate::identidade::trocar_editores_de_teste(agora);
            crate::arch::sem_interrupcoes(|| *EDITORES_DO_MEIO.lock() = Some(renomeados));
            let cabeca = crate::autorizacao::ultimo_registro();
            armar(renomear_o_editor, 0);
            let r = fs_pedir(
                quem,
                "user.run",
                &alloc::format!(r#"{{"path":"{caminho}"}}"#),
            );
            crate::fios::no_meio_do_nascimento_de_teste(None);
            crate::log_info!(
                "teste",
                "codigo: o editor renomeado no meio do nascimento: {}",
                r
            );
            if !ISOLOU.load(SeqCst) {
                return Err("o gancho nao renomeou o editor no meio do nascimento");
            }
            let fio = fs_numero(&r, "thread_id")
                .ok_or("o user.run do codigo com o editor renomeado nao lancou")?;
            let esperado = alloc::format!("processo {fio} lancado: codigo {resumo} de {NOME_NOVO}");
            let nascimentos = registros_depois(cabeca, |ev| {
                ev.metodo == "user.run"
                    && ev.codigo == politica::Codigo::Allow
                    && ev.detalhe.contains(" lancado")
            });
            match &nascimentos[..] {
                [(_, ev)] if e_a_execucao_de(ev, None, &esperado) => Ok(()),
                outros => {
                    crate::log_error!("teste", "esperado `{}`", esperado);
                    for (seq, ev) in outros {
                        crate::log_error!("teste", "registro {}: {}", seq, ev.detalhe);
                    }
                    Err(
                        "o registro do nascimento nao diz o nome do editor que a ultima palavra viu",
                    )
                }
            }
        })
    });
    crate::arch::sem_interrupcoes(|| *EDITORES_DO_MEIO.lock() = None);
    crate::fios::no_meio_do_nascimento_de_teste(None);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// O item 5 do lote A3 do #448, a leitura: o `user.run` de um caminho que o
/// papel alcanca e que nao existe — o operador alcanca `/bin` — e permitido
/// pelo gate, e o arquivo nao se le. A execucao da decisao diz por que,
/// como o `exec` diz o mesmo caso: `ERROR`, "nao encontrado", citando a
/// decisao; e quem pediu ouve que nada foi lancado, com o motivo. Fora de
/// um comando, o mesmo lancamento pelo kernel grava a recusa em nome dele.
/// Antes, nenhum dos dois gravava nada: o `ALLOW` ficava sem desfecho.
pub(super) fn contencao_o_user_run_de_um_caminho_que_nao_existe_grava_o_desfecho() -> Resultado {
    use politica::Codigo;
    const CAMINHO: &str = "/bin/nao-existe";
    let motivo = crate::vfs::Erro::NaoEncontrado.motivo();
    crate::pessoas::esquecer_registradas();
    let resultado = (|| -> Resultado {
        let quem = operador_que_lanca(172, "caminho-que-nao-existe");
        let cabeca = crate::autorizacao::ultimo_registro();
        let r = fs_pedir(
            quem,
            "user.run",
            &alloc::format!(r#"{{"path":"{CAMINHO}"}}"#),
        );
        if super::decisao_do_envelope(&r) != "ALLOW"
            || fs_numero(&r, "thread_id").is_some()
            || !r.contains(r#""launched":false"#)
            || fs_texto(&r, "error").as_deref() != Some(motivo)
        {
            crate::log_error!("teste", "{}", r);
            return Err("o user.run de um caminho que nao existe nao respondeu a leitura recusada");
        }
        let decisoes = registros_depois(cabeca, |ev| {
            ev.metodo == "user.run" && ev.recurso == CAMINHO && ev.codigo == Codigo::Allow
        });
        let execucoes = registros_depois(cabeca, |ev| {
            ev.metodo == "user.run"
                && ev.recurso == CAMINHO
                && ev.codigo == Codigo::Error
                && e_a_execucao_de(ev, None, motivo)
        });
        let cita = match (&decisoes[..], &execucoes[..]) {
            ([(d, _)], [(_, ev)]) => super::decisao_executada(&ev.detalhe) == Some(*d),
            _ => false,
        };
        if !cita {
            crate::log_error!(
                "teste",
                "{} decisao(oes), {} execucao(oes)",
                decisoes.len(),
                execucoes.len()
            );
            return Err("o user.run permitido de um caminho que nao existe ficou sem o desfecho");
        }
        // Fora de um comando: em nome do kernel.
        let cabeca = crate::autorizacao::ultimo_registro();
        let fora = crate::usuario::lancar_pelo_kernel(
            Some(CAMINHO),
            crate::autorizacao::Autoridade::Sistema,
        );
        if !matches!(
            fora,
            Err(crate::usuario::NaoLancou::Codigo(
                crate::usuario::codigo::Recusa::Leitura(crate::vfs::Erro::NaoEncontrado)
            ))
        ) {
            crate::log_error!("teste", "{:?}", fora);
            return Err("o lancamento do kernel de um caminho que nao existe nao foi recusado");
        }
        let do_kernel = registros_depois(cabeca, |ev| {
            ev.metodo == "process.run"
                && ev.recurso == CAMINHO
                && ev.agente == "kernel"
                && ev.codigo == Codigo::Error
                && ev.detalhe == motivo
        });
        if do_kernel.len() != 1 {
            return Err("a leitura recusada fora de um comando nao foi gravada em nome do kernel");
        }
        Ok(())
    })();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// O item 5 do lote A3 do #448, o fio: com a tabela de fios cheia — fios
/// do kernel ate nao haver vaga, sem caminho so de teste no codigo de
/// producao —, o `user.run` de uma pessoa operadora e permitido, o codigo
/// se le, e o fio nao nasce. A execucao da decisao diz por que: `ERROR`,
/// com o motivo da falta de vaga, citando a decisao; quem pediu ouve o
/// mesmo motivo. Fora de um comando, o lancamento pelo kernel grava em nome
/// dele. Antes, nada se gravava. As vagas voltam no fim.
pub(super) fn contencao_o_user_run_cujo_fio_nao_nasce_grava_o_desfecho() -> Resultado {
    use politica::Codigo;
    crate::pessoas::esquecer_registradas();
    let quem = operador_que_lanca(173, "fio-que-nao-nasce");
    let caminho = caminho_do_encerravel();
    let livres = crate::fios::vagas_livres_de_teste();
    let cheia = encher_a_tabela();
    let resultado = (|| -> Resultado {
        let criados = cheia.map_err(|motivo| {
            crate::log_error!("teste", "a criacao recusou: {}", motivo);
            "um fio nao nasceu por outro motivo que a falta de vaga"
        })?;
        if criados == 0 || crate::fios::vagas_livres_de_teste() != 0 {
            return Err("a tabela de fios nao encheu");
        }
        let cabeca = crate::autorizacao::ultimo_registro();
        let r = fs_pedir(
            quem,
            "user.run",
            &alloc::format!(r#"{{"path":"{caminho}"}}"#),
        );
        let motivo = fs_texto(&r, "error").unwrap_or_default();
        if super::decisao_do_envelope(&r) != "ALLOW"
            || fs_numero(&r, "thread_id").is_some()
            || !r.contains(r#""launched":false"#)
            || !motivo.contains("vaga")
        {
            crate::log_error!("teste", "{}", r);
            return Err("o user.run com a tabela cheia nao respondeu a falta de vaga");
        }
        let decisoes = registros_depois(cabeca, |ev| {
            ev.metodo == "user.run" && ev.recurso == caminho && ev.codigo == Codigo::Allow
        });
        let execucoes = registros_depois(cabeca, |ev| {
            ev.metodo == "user.run"
                && ev.recurso == caminho
                && ev.codigo == Codigo::Error
                && e_a_execucao_de(ev, None, &motivo)
        });
        let lancados = registros_depois(cabeca, |ev| ev.detalhe.contains(" lancado"));
        let cita = match (&decisoes[..], &execucoes[..]) {
            ([(d, _)], [(_, ev)]) => super::decisao_executada(&ev.detalhe) == Some(*d),
            _ => false,
        };
        if !cita || !lancados.is_empty() {
            crate::log_error!(
                "teste",
                "{} decisao(oes), {} execucao(oes), {} lancamento(s)",
                decisoes.len(),
                execucoes.len(),
                lancados.len()
            );
            return Err("o user.run permitido cujo fio nao nasceu ficou sem o desfecho");
        }
        // Fora de um comando: em nome do kernel.
        let cabeca = crate::autorizacao::ultimo_registro();
        let fora = crate::usuario::lancar_pelo_kernel(
            Some(&caminho),
            crate::autorizacao::Autoridade::Sistema,
        );
        if !matches!(&fora, Err(crate::usuario::NaoLancou::Fio(m)) if *m == motivo) {
            crate::log_error!("teste", "{:?}", fora);
            return Err("o lancamento do kernel com a tabela cheia nao ouviu a falta de vaga");
        }
        let do_kernel = registros_depois(cabeca, |ev| {
            ev.metodo == "process.run"
                && ev.recurso == caminho
                && ev.agente == "kernel"
                && ev.codigo == Codigo::Error
                && ev.detalhe == motivo
        });
        if do_kernel.len() != 1 {
            return Err(
                "o fio que nao nasceu fora de um comando nao foi gravado em nome do kernel",
            );
        }
        Ok(())
    })();
    let esvaziada = esvaziar_a_tabela(livres);
    crate::pessoas::esquecer_registradas();
    resultado.and(esvaziada)
}

/// O trinco do boot (o item 1 do lote A3 do #448): fora da suite, o
/// `main.rs` fecha os lancamentos do kernel por conta propria depois dos
/// dois dele, o servidor de janelas e o Terminal. O caso os fecha: o
/// lancamento do kernel fora de um comando — pelo `lancar_pelo_kernel` e
/// pelo do sistema — e recusado como fora de um comando autorizado, em
/// nome do kernel, e nada nasce; o `user.run` de uma pessoa operadora, um
/// comando decidido, lanca como sempre. Reabertos — o que so a suite faz
/// —, o kernel lanca de novo.
///
/// E o achado 2 do adversario do lote A3: o trinco valia so no nascimento,
/// e o lancamento do kernel de um caminho que nao existe lia o arquivo e
/// gravava "nao encontrado" em nome do kernel — o trinco nem chegava a
/// recusar. Recusado ja no comeco do lancamento, como fora de um comando
/// autorizado, e o caminho so nessa recusa.
pub(super) fn contencao_depois_do_boot_o_kernel_nao_lanca_por_conta_propria() -> Resultado {
    use politica::Codigo;
    const FORA: &str = "fora de um comando autorizado";
    crate::pessoas::esquecer_registradas();
    let caminho = caminho_do_encerravel();
    let livres = crate::fios::vagas_livres_de_teste();
    let cabeca = crate::autorizacao::ultimo_registro();
    crate::autorizacao::fechar_os_lancamentos_do_kernel();
    let pelo_kernel =
        crate::usuario::lancar_pelo_kernel(Some(&caminho), crate::autorizacao::Autoridade::Sistema);
    let como_sistema = crate::usuario::lancar_como_sistema(Some(&caminho));
    let do_que_nao_existe = crate::usuario::lancar_pelo_kernel(
        Some(CAMINHO_QUE_NAO_EXISTE),
        crate::autorizacao::Autoridade::Sistema,
    );
    let do_comando = Encerravel::lancar(operador_que_lanca(174, "lanca-com-o-trinco"));
    crate::autorizacao::reabrir_os_lancamentos_do_kernel_de_teste();
    let resultado = (|| -> Resultado {
        crate::log_info!(
            "teste",
            "contencao: com os lancamentos do kernel fechados: {:?}, {:?}, {:?}",
            pelo_kernel,
            como_sistema,
            do_que_nao_existe
        );
        if !matches!(
            pelo_kernel,
            Err(crate::usuario::NaoLancou::Recusado(Codigo::Error, m)) if m == FORA
        ) || como_sistema != Err(FORA)
        {
            return Err("depois do boot, o kernel lancou por conta propria");
        }
        if !matches!(
            do_que_nao_existe,
            Err(crate::usuario::NaoLancou::Recusado(Codigo::Error, m)) if m == FORA
        ) {
            return Err("depois do boot, o kernel leu o caminho que lancaria por conta propria");
        }
        let do_kernel = registros_depois(cabeca, |ev| {
            ev.metodo == "process.run"
                && ev.recurso == caminho
                && ev.agente == "kernel"
                && ev.codigo == Codigo::Error
                && ev.detalhe == FORA
        });
        if do_kernel.len() != 2 {
            return Err("as recusas do kernel depois do boot nao foram gravadas em nome dele");
        }
        let do_que_nao_existe = registros_depois(cabeca, |ev| ev.recurso == CAMINHO_QUE_NAO_EXISTE);
        if !matches!(
            &do_que_nao_existe[..],
            [(_, ev)] if ev.metodo == "process.run"
                && ev.agente == "kernel"
                && ev.codigo == Codigo::Error
                && ev.detalhe == FORA
        ) {
            return Err("o caminho que nao existe nao ficou so na recusa do kernel depois do boot");
        }
        // O comando decidido lanca, com os lancamentos do kernel fechados:
        // um nascimento so, o dele.
        let e = do_comando?;
        let nascidos = registros_depois(cabeca, |ev| ev.detalhe.contains(" lancado"));
        let nasceu = alloc::format!("processo {} lancado", e.fio);
        if !matches!(
            &nascidos[..],
            [(_, ev)] if ev.metodo == "user.run" && e_a_execucao_de(ev, None, &nasceu)
        ) {
            return Err("com os lancamentos do kernel fechados, o user.run nao lancou so o dele");
        }
        encerrar_os_encerraveis();
        if esperar_cedendo(|| crate::fios::vagas_livres_de_teste() >= livres, 300).is_err() {
            return Err("as vagas dos lancamentos recusados nao voltaram");
        }
        // Reabertos, na suite: o kernel lanca de novo.
        let desde = crate::log::total_emitidos();
        let fio = crate::usuario::lancar_pelo_kernel(
            Some(&caminho),
            crate::autorizacao::Autoridade::Sistema,
        )
        .map_err(|n| {
            crate::log_error!("teste", "{:?}", n);
            "reabertos os lancamentos, o kernel nao lancou"
        })?;
        Encerravel { fio, desde }.esperar_linha("encerravel: pronto", 1)
    })();
    crate::autorizacao::reabrir_os_lancamentos_do_kernel_de_teste();
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

// ---------------------------------------------------------------------------
// O lote A4: o desfecho das recusas sobre quem pede, dentro de um `user.run`
// (o #466), e o da imagem que nao se carrega — antes do nascimento — ou que
// nao se mapeia — depois dele (o #467)
// ---------------------------------------------------------------------------

/// O titular cuja cota o gancho de antes do nascimento ocupa, e o fio que a
/// ocupa ate o caso solta-lo.
static TITULAR_DA_COTA: crate::trava::Mutex<Option<crate::autorizacao::Autoridade>> =
    crate::trava::Mutex::new(None);
/// Se o processo que ocupa a cota pode sair.
static SOLTAR_A_COTA: AtomicBool = AtomicBool::new(true);
/// O processo que ocupa a cota, ou zero.
static OCUPANTE_DA_COTA: AtomicU64 = AtomicU64::new(0);

/// O processo que ocupa a cota do titular: cede ate o caso solta-lo.
extern "C" fn ocupante_da_cota(_argumento: u64) -> ! {
    while !SOLTAR_A_COTA.load(SeqCst) {
        crate::fios::ceder();
    }
    crate::fios::terminar()
}

/// O gancho de antes do nascimento do lancamento: um processo do mesmo
/// titular nasce — com uma cota folgada, para ele nascer —, e a conta do
/// nascimento do lancado, com a cota do gate, acha a cota cheia.
fn ocupar_a_cota() {
    let Some(titular) = crate::arch::sem_interrupcoes(|| *TITULAR_DA_COTA.lock()) else {
        return;
    };
    SOLTAR_A_COTA.store(false, SeqCst);
    match crate::fios::criar_processo(
        crate::fios::NOME_DO_PROCESSO,
        ocupante_da_cota,
        0,
        titular,
        64,
        &|_| Ok(()),
    ) {
        Ok(id) => OCUPANTE_DA_COTA.store(id.numero(), SeqCst),
        Err(_) => SOLTAR_A_COTA.store(true, SeqCst),
    }
}

/// Solta o processo que ocupava a cota de `titular`, e espera a cota dele
/// voltar a zero — o morto recolhido.
fn soltar_a_cota(titular: crate::autorizacao::Autoridade) -> Resultado {
    SOLTAR_A_COTA.store(true, SeqCst);
    OCUPANTE_DA_COTA.store(0, SeqCst);
    esperar_ate(|| crate::fios::ocupacao_na_cota(titular, 1).is_none(), 600)
        .map_err(|_| "o processo que ocupava a cota nao saiu, ou nao foi recolhido")
}

/// O #466 na cota contada de novo no nascimento: com a cota do operador em
/// um, a pessoa pede o `user.run` do `encerravel`; o gate do comando deixa,
/// as perguntas sobre quem pede passam — nenhum processo dela —, e o gancho
/// de antes do nascimento faz nascer um processo do mesmo titular. A conta
/// do nascimento recusa (`NaoNasceu::Cota`): quem pediu ouve `DENY_POLICY`,
/// a cota esgotada, sem a explicacao do comando; a auditoria grava a recusa
/// da cota uma vez, como o gate a grava (`process.run`, "cota de processos
/// do papel: 1 de 1"), e o desfecho do `user.run` uma vez, com o mesmo
/// detalhe, citando a decisao; nada nasce. Fora de um comando — o
/// lancamento pelo kernel, com a autoridade da pessoa e o mesmo gancho —,
/// so a recusa da cota: nenhum registro em nome do kernel, porque nao ha
/// `ALLOW` a fechar. Antes do lote A4, o `user.run` ficava sem desfecho.
pub(super) fn contencao_a_cota_contada_de_novo_no_nascimento_do_user_run_grava_o_desfecho()
-> Resultado {
    use politica::Codigo;
    const COTA: &str = "cota de processos do papel: 1 de 1";
    crate::pessoas::esquecer_registradas();
    let caminho = caminho_do_encerravel();
    let um = super::politica_trocada(&[("processos operador 8", "processos operador 1")])?;
    let resultado = super::com_a_politica(um, || {
        let quem = operador_que_lanca(176, "cota-no-nascimento");
        let crate::autorizacao::Chamador::Pessoa(sessao) = quem else {
            return Err("quem lanca no caso nao e uma pessoa");
        };
        let titular = crate::autorizacao::Autoridade::Pessoa { sessao };
        crate::arch::sem_interrupcoes(|| *TITULAR_DA_COTA.lock() = Some(titular));
        let livres = crate::fios::vagas_livres_de_teste();

        // Dentro de um comando: a recusa do gate e o desfecho do `user.run`.
        let cabeca = crate::autorizacao::ultimo_registro();
        crate::autorizacao::antes_do_nascimento_do_lancamento_de_teste(Some(ocupar_a_cota));
        let r = fs_pedir(
            quem,
            "user.run",
            &alloc::format!(r#"{{"path":"{caminho}"}}"#),
        );
        crate::autorizacao::antes_do_nascimento_do_lancamento_de_teste(None);
        let ocupou = OCUPANTE_DA_COTA.load(SeqCst) != 0;
        crate::log_info!(
            "teste",
            "contencao: o user.run com a cota ocupada antes do nascimento: {}",
            r
        );
        soltar_a_cota(titular)?;
        if !ocupou {
            return Err("o gancho nao ocupou a cota antes do nascimento");
        }
        nao_lancou_com(&r, "DENY_POLICY", crate::fios::COTA_ESGOTADA)?;
        sem_a_explicacao(&r)?;
        let do_gate = registros_depois(cabeca, |ev| {
            ev.metodo == "process.run" && ev.codigo == Codigo::DenyPolicy && ev.detalhe == COTA
        });
        if do_gate.len() != 1 {
            crate::log_error!("teste", "{} recusa(s) da cota", do_gate.len());
            return Err("a recusa da cota no nascimento nao foi gravada uma vez");
        }
        o_desfecho_do_user_run(cabeca, &caminho, Codigo::DenyPolicy, None, COTA)
            .map_err(|_| "a cota contada de novo no nascimento deixou o user.run sem o desfecho")?;

        // Fora de um comando: so a recusa do gate.
        let cabeca = crate::autorizacao::ultimo_registro();
        crate::autorizacao::antes_do_nascimento_do_lancamento_de_teste(Some(ocupar_a_cota));
        let fora = crate::usuario::lancar_pelo_kernel(Some(&caminho), titular);
        crate::autorizacao::antes_do_nascimento_do_lancamento_de_teste(None);
        let ocupou = OCUPANTE_DA_COTA.load(SeqCst) != 0;
        soltar_a_cota(titular)?;
        if !ocupou {
            return Err("o gancho nao ocupou a cota antes do nascimento do kernel");
        }
        if !matches!(
            fora,
            Err(crate::usuario::NaoLancou::PorQuemPede(Codigo::DenyPolicy, m))
                if m == crate::fios::COTA_ESGOTADA
        ) {
            crate::log_error!("teste", "{:?}", fora);
            return Err("o lancamento do kernel com a cota cheia no nascimento nao ouviu a cota");
        }
        let do_gate = registros_depois(cabeca, |ev| {
            ev.metodo == "process.run" && ev.codigo == Codigo::DenyPolicy && ev.detalhe == COTA
        });
        let do_kernel = registros_depois(cabeca, |ev| {
            ev.agente == "kernel" && ev.metodo == "process.run"
        });
        let lancados = registros_depois(cabeca, |ev| ev.detalhe.contains(" lancado"));
        if do_gate.len() != 1 || !do_kernel.is_empty() || !lancados.is_empty() {
            crate::log_error!(
                "teste",
                "{} recusa(s) da cota, {} registro(s) em nome do kernel, {} lancamento(s)",
                do_gate.len(),
                do_kernel.len(),
                lancados.len()
            );
            return Err(
                "a recusa de quem pede fora de um comando ganhou um registro em nome do kernel",
            );
        }
        if esperar_ate(|| crate::fios::vagas_livres_de_teste() >= livres, 600).is_err() {
            return Err("as vagas do caso da cota nao voltaram");
        }
        Ok(())
    });
    crate::autorizacao::antes_do_nascimento_do_lancamento_de_teste(None);
    crate::arch::sem_interrupcoes(|| *TITULAR_DA_COTA.lock() = None);
    SOLTAR_A_COTA.store(true, SeqCst);
    OCUPANTE_DA_COTA.store(0, SeqCst);
    encerrar_os_encerraveis();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// Um `user.run` de `caminho` por `quem`, recusado antes do nascimento com
/// `motivo`: a resposta — a decisao do comando, nada lancado, o motivo —, e
/// na auditoria a decisao (`ALLOW`) e uma execucao dela, `ERROR` com o
/// motivo, citando-a; nenhum `processo N lancado`.
fn nao_carrega(quem: crate::autorizacao::Chamador, caminho: &str, motivo: &str) -> Resultado {
    let cabeca = crate::autorizacao::ultimo_registro();
    let r = fs_pedir(
        quem,
        "user.run",
        &alloc::format!(r#"{{"path":"{caminho}"}}"#),
    );
    crate::log_info!("teste", "contencao: o user.run de `{}`: {}", caminho, r);
    // As duas diferencas, cada uma com a mensagem dela: lancou — o fio, ou o
    // `launched: true` —, ou nao lancou e recusou com outro motivo — ou nao
    // decidiu `ALLOW` —, e o log diz qual.
    if fs_numero(&r, "thread_id").is_some() || r.contains(r#""launched":true"#) {
        crate::log_error!("teste", "esperava `{}`: {}", motivo, r);
        return Err("o user.run de uma imagem que nao se carrega lancou");
    }
    if super::decisao_do_envelope(&r) != "ALLOW"
        || !r.contains(r#""launched":false"#)
        || fs_texto(&r, "error").as_deref() != Some(motivo)
    {
        crate::log_error!(
            "teste",
            "recusou com {:?}, decidido {}, e nao com `{}`: {}",
            fs_texto(&r, "error"),
            super::decisao_do_envelope(&r),
            motivo,
            r
        );
        return Err("o user.run de uma imagem que nao se carrega recusou com outro motivo");
    }
    o_desfecho_do_user_run(cabeca, caminho, politica::Codigo::Error, None, motivo)
        .map_err(|_| "o user.run de uma imagem que nao se carrega ficou sem o desfecho")?;
    let lancados = registros_depois(cabeca, |ev| ev.detalhe.contains(" lancado"));
    if !lancados.is_empty() {
        return Err("o user.run de uma imagem que nao se carrega gravou um nascimento");
    }
    Ok(())
}

/// O `ola` da imagem com o primeiro byte do texto do manifesto trocado: o
/// cabecalho deixa de ser o desta versao, e o manifesto nao se le.
fn ola_de_manifesto_estragado() -> Result<alloc::vec::Vec<u8>, &'static str> {
    let ola = super::ola_da_imagem()?;
    let inicio = {
        let elf = crate::usuario::elf::validar(&ola)?;
        let texto = elf.manifesto().ok_or("o ola nao tem manifesto")?;
        texto.as_ptr() as usize - ola.as_ptr() as usize
    };
    let mut estragado = ola.clone();
    estragado[inicio] ^= 0x20;
    Ok(estragado)
}

/// O #467, antes do nascimento: a imagem que se le e nao se carrega. Com
/// os editores do caso, no armazem: o `ola` selado lanca e sai (o
/// controle); oitenta bytes que nao sao ELF, selados pelo editor do caso —
/// a procedencia passa, a imagem nao —, e o `ola` com o cabecalho do
/// manifesto estragado, selado, nao lancam: `launched: false`, com o motivo
/// do carregador, e a auditoria com a decisao e o desfecho, `ERROR`,
/// citando-a; nada nasce. Fora de um comando, o lancamento pelo kernel
/// ouve `NaoLancou::Imagem` e grava o desfecho em nome dele. Antes do lote
/// A4, o fio nascia, o nascimento ia a auditoria como "processo N lancado",
/// quem pediu ouvia `launched: true`, e o fio novo morria com o erro so no
/// log.
pub(super) fn contencao_o_user_run_de_uma_imagem_que_nao_se_carrega_grava_o_desfecho() -> Resultado
{
    use politica::Codigo;
    const NAO_E_ELF: &str = "nao e um ELF64 little-endian";
    let manifesto_ruim = politica::manifesto::Erro::Cabecalho.motivo();
    crate::pessoas::esquecer_registradas();
    let livres = crate::fios::vagas_livres_de_teste();
    let resultado = super::com_editores_do_caso(|| {
        let selado = |bytes: &[u8]| sigilo::codigo::selar(bytes, &super::EDITOR_DO_CASO.0);
        let quem = operador_que_lanca(177, "imagem-que-nao-carrega");

        // O controle: o `ola` selado lanca e sai com o codigo dele.
        let bom = alloc::format!("{}/ola-que-carrega", super::CODIGO_INSTALADO);
        super::gravar_codigo(&bom, &selado(&super::ola_da_imagem()?))?;
        let desde = crate::log::total_emitidos();
        let r = fs_pedir(quem, "user.run", &alloc::format!(r#"{{"path":"{bom}"}}"#));
        if fs_numero(&r, "thread_id").is_none() {
            crate::log_error!("teste", "{}", r);
            return Err("o ola selado do caso nao lancou");
        }
        super::saida_do_processo(desde, super::SAIDA_DO_OLA)?;

        // O que nao e ELF.
        let nao_elf = alloc::format!("{}/nao-e-elf", super::CODIGO_INSTALADO);
        super::gravar_codigo(&nao_elf, &selado(&[b'x'; 80]))?;
        nao_carrega(quem, &nao_elf, NAO_E_ELF)?;

        // O manifesto que nao se le.
        let ruim = alloc::format!("{}/ola-de-manifesto-ruim", super::CODIGO_INSTALADO);
        super::gravar_codigo(&ruim, &selado(&ola_de_manifesto_estragado()?))?;
        nao_carrega(quem, &ruim, manifesto_ruim)?;

        // Fora de um comando: em nome do kernel.
        let cabeca = crate::autorizacao::ultimo_registro();
        let fora = crate::usuario::lancar_pelo_kernel(
            Some(&nao_elf),
            crate::autorizacao::Autoridade::Sistema,
        );
        if !matches!(&fora, Err(crate::usuario::NaoLancou::Imagem(m)) if *m == NAO_E_ELF) {
            crate::log_error!("teste", "{:?}", fora);
            return Err("o lancamento do kernel de uma imagem que nao e ELF nao foi recusado");
        }
        let do_kernel = registros_depois(cabeca, |ev| {
            ev.metodo == "process.run"
                && ev.recurso == nao_elf
                && ev.agente == "kernel"
                && ev.codigo == Codigo::Error
                && ev.detalhe == NAO_E_ELF
        });
        let lancados = registros_depois(cabeca, |ev| ev.detalhe.contains(" lancado"));
        if do_kernel.len() != 1 || !lancados.is_empty() {
            crate::log_error!(
                "teste",
                "{} registro(s) em nome do kernel, {} lancamento(s)",
                do_kernel.len(),
                lancados.len()
            );
            return Err("a imagem recusada fora de um comando nao foi gravada em nome do kernel");
        }
        Ok(())
    });
    let vagas = esperar_ate(|| crate::fios::vagas_livres_de_teste() >= livres, 600)
        .map_err(|_| "as vagas do caso da imagem que nao se carrega nao voltaram");
    crate::pessoas::esquecer_registradas();
    resultado.and(vagas)
}

/// O gancho do meio do nascimento: a falha do mapeamento armada para o fio
/// que nasce — `programa::Trocada::mapear` a pergunta, no fio novo.
fn falhar_o_mapeamento(fio: u64) {
    crate::usuario::falha_da_troca_de_teste::armar(
        fio,
        crate::usuario::falha_da_troca_de_teste::Etapa::Mapeamento,
    );
    NASCENDO.store(fio, SeqCst);
}

/// O #467, depois do nascimento: a memoria que falta ao mapear a imagem no
/// fio novo — a falha armada no gancho do meio do nascimento, para o fio
/// que nasce. O `user.run` do `ola` pela pessoa ja respondeu `launched:
/// true`; o fio N morre sem rodar, e a auditoria tem a decisao, o
/// nascimento de N e o desfecho — `ERROR`, o motivo do mapeamento, em nome
/// de quem o gate decidiu, citando a decisao —, nessa ordem, como o `exec`
/// que falha depois do ponto sem volta. Fora de um comando, o nascimento e
/// o desfecho em nome do kernel. E nenhum desfecho guardado fica vivo: nem
/// o dos dois que falharam, nem o de um `ola` que entra e sai. Antes do
/// lote A4, nada se gravava: o erro ficava so no log.
pub(super) fn contencao_o_user_run_cuja_imagem_nao_se_mapeia_grava_o_desfecho() -> Resultado {
    use crate::usuario::falha_da_troca_de_teste::{MAPEAMENTO, desarmar};
    use politica::Codigo;
    crate::pessoas::esquecer_registradas();
    let vivos = crate::autorizacao::desfechos_vivos_de_teste();
    let caminho = caminho_do_ola();
    let resultado = (|| -> Resultado {
        // Dentro de um comando: em nome de quem o gate decidiu.
        let quem = operador_que_lanca(178, "imagem-que-nao-mapeia");
        let cabeca = crate::autorizacao::ultimo_registro();
        armar(falhar_o_mapeamento, 0);
        let r = fs_pedir(
            quem,
            "user.run",
            &alloc::format!(r#"{{"path":"{caminho}"}}"#),
        );
        crate::fios::no_meio_do_nascimento_de_teste(None);
        crate::log_info!(
            "teste",
            "contencao: o user.run do ola que nao se mapeia: {}",
            r
        );
        let fio = fs_numero(&r, "thread_id").ok_or("o user.run do ola nao nasceu")?;
        if NASCENDO.load(SeqCst) != fio {
            return Err("o gancho nao armou a falha do mapeamento para o fio que nasceu");
        }
        esperar_ate(|| !crate::fios::vivo(fio), 600)
            .map_err(|_| "o fio que nao mapeou nao morreu")?;
        let decisoes = registros_depois(cabeca, |ev| {
            ev.metodo == "user.run"
                && ev.recurso == caminho
                && ev.codigo == Codigo::Allow
                && super::decisao_executada(&ev.detalhe).is_none()
        });
        let nasceu = alloc::format!("processo {fio} lancado");
        let nascimentos = registros_depois(cabeca, |ev| {
            ev.metodo == "user.run"
                && ev.codigo == Codigo::Allow
                && e_a_execucao_de(ev, None, &nasceu)
        });
        let execucoes = registros_depois(cabeca, |ev| {
            ev.metodo == "user.run"
                && ev.recurso == caminho
                && ev.codigo == Codigo::Error
                && e_a_execucao_de(ev, None, MAPEAMENTO)
        });
        let certo = match (&decisoes[..], &nascimentos[..], &execucoes[..]) {
            ([(d, _)], [(n, nev)], [(e, ev)]) => {
                super::decisao_executada(&nev.detalhe) == Some(*d)
                    && super::decisao_executada(&ev.detalhe) == Some(*d)
                    && d < n
                    && n < e
            }
            _ => false,
        };
        if !certo {
            crate::log_error!(
                "teste",
                "{} decisao(oes), {} nascimento(s), {} execucao(oes) `ERROR`",
                decisoes.len(),
                nascimentos.len(),
                execucoes.len()
            );
            for (seq, ev) in registros_depois(cabeca, |ev| ev.recurso == caminho) {
                crate::log_error!(
                    "teste",
                    "registro {}: {} {} {} {}",
                    seq,
                    ev.agente,
                    ev.metodo,
                    ev.codigo.nome(),
                    ev.detalhe
                );
            }
            return Err(
                "o user.run cuja imagem nao se mapeou ficou sem o desfecho depois do nascimento",
            );
        }

        // Fora de um comando: em nome do kernel, depois do nascimento.
        let cabeca = crate::autorizacao::ultimo_registro();
        armar(falhar_o_mapeamento, 0);
        let fora = crate::usuario::lancar_pelo_kernel(
            Some(&caminho),
            crate::autorizacao::Autoridade::Sistema,
        );
        crate::fios::no_meio_do_nascimento_de_teste(None);
        let fio = fora.map_err(|n| {
            crate::log_error!("teste", "{:?}", n);
            "o lancamento do kernel do ola nao nasceu"
        })?;
        if NASCENDO.load(SeqCst) != fio {
            return Err("o gancho nao armou a falha do mapeamento para o fio do kernel");
        }
        esperar_ate(|| !crate::fios::vivo(fio), 600)
            .map_err(|_| "o fio do kernel que nao mapeou nao morreu")?;
        let do_kernel = registros_depois(cabeca, |ev| {
            ev.metodo == "process.run" && ev.recurso == caminho && ev.agente == "kernel"
        });
        let nasceu = alloc::format!("processo {fio} lancado");
        let em_ordem = matches!(
            &do_kernel[..],
            [(_, n), (_, e)] if n.codigo == Codigo::Allow
                && n.detalhe == nasceu
                && e.codigo == Codigo::Error
                && e.detalhe == MAPEAMENTO
        );
        if !em_ordem {
            for (seq, ev) in &do_kernel {
                crate::log_error!(
                    "teste",
                    "registro {} do kernel: {} {}",
                    seq,
                    ev.codigo.nome(),
                    ev.detalhe
                );
            }
            return Err(
                "a imagem que nao se mapeou fora de um comando nao foi gravada em nome do kernel",
            );
        }

        // E um `ola` que entra e sai: nenhum desfecho fica vivo — nem o dos
        // dois que falharam, nem o dele.
        let desde = crate::log::total_emitidos();
        let r = fs_pedir(
            quem,
            "user.run",
            &alloc::format!(r#"{{"path":"{caminho}"}}"#),
        );
        let fio = fs_numero(&r, "thread_id").ok_or("o ola do controle nao lancou")?;
        super::saida_do_processo(desde, super::SAIDA_DO_OLA)?;
        esperar_ate(|| !crate::fios::vivo(fio), 600).map_err(|_| "o ola do controle nao saiu")?;
        let agora = crate::autorizacao::desfechos_vivos_de_teste();
        if agora != vivos {
            crate::log_error!(
                "teste",
                "desfechos vivos: {} antes, {} depois",
                vivos,
                agora
            );
            return Err(
                "o desfecho do lancamento ficou vivo depois de o processo entrar ou morrer",
            );
        }
        Ok(())
    })();
    crate::fios::no_meio_do_nascimento_de_teste(None);
    desarmar();
    crate::pessoas::esquecer_registradas();
    resultado
}

// ---------------------------------------------------------------------------
// O lote A5: o teto da tabela de segmentos e o orcamento das notas, e a
// pagina de cima do segmento vazio no teto
// ---------------------------------------------------------------------------

/// Uma entrada da tabela de segmentos do ELF64: o tipo, as flags, onde o
/// conteudo comeca no arquivo, o destino — o endereco virtual e o fisico —,
/// quanto vem do arquivo e quanto ocupa na memoria; o alinhamento, uma
/// pagina.
fn entrada_de_segmento(
    tipo: u32,
    flags: u32,
    deslocamento: u64,
    destino: u64,
    no_arquivo: u64,
    na_memoria: u64,
) -> [u8; 56] {
    let mut e = [0u8; 56];
    e[0..4].copy_from_slice(&tipo.to_le_bytes());
    e[4..8].copy_from_slice(&flags.to_le_bytes());
    e[8..16].copy_from_slice(&deslocamento.to_le_bytes());
    e[16..24].copy_from_slice(&destino.to_le_bytes());
    e[24..32].copy_from_slice(&destino.to_le_bytes());
    e[32..40].copy_from_slice(&no_arquivo.to_le_bytes());
    e[40..48].copy_from_slice(&na_memoria.to_le_bytes());
    e[48..56].copy_from_slice(&4096u64.to_le_bytes());
    e
}

/// As entradas da tabela de segmentos de `elf`, como estao no arquivo.
fn entradas_de(elf: &[u8]) -> Result<alloc::vec::Vec<[u8; 56]>, &'static str> {
    const CORTADO: &str = "o ELF do caso nao tem a tabela de segmentos inteira";
    let pedaco = |de: usize, ate: usize| elf.get(de..ate).ok_or(CORTADO);
    let mut tabela = [0u8; 8];
    tabela.copy_from_slice(pedaco(32, 40)?);
    let mut quantas = [0u8; 2];
    quantas.copy_from_slice(pedaco(56, 58)?);
    let tabela = u64::from_le_bytes(tabela) as usize;
    (0..u16::from_le_bytes(quantas) as usize)
        .map(|i| {
            let de = tabela + 56 * i;
            let mut entrada = [0u8; 56];
            entrada.copy_from_slice(pedaco(de, de + 56)?);
            Ok(entrada)
        })
        .collect()
}

/// Onde [`com_a_tabela`] poe a tabela de segmentos de `elf`: no fim dele,
/// alinhada a 8.
fn onde_vai_a_tabela(elf: &[u8]) -> usize {
    elf.len().next_multiple_of(8)
}

/// `elf` com a tabela de segmentos trocada por `entradas`, posta no fim do
/// arquivo ([`onde_vai_a_tabela`]) — o `e_phoff` e o `e_phnum` apontando
/// para ela —, e `depois` logo em seguida. O resto nao muda: os segmentos
/// das entradas copiadas apontam para os mesmos bytes.
fn com_a_tabela(elf: &[u8], entradas: &[[u8; 56]], depois: &[u8]) -> alloc::vec::Vec<u8> {
    let mut v = elf.to_vec();
    v.resize(onde_vai_a_tabela(elf), 0);
    let tabela = v.len() as u64;
    v[32..40].copy_from_slice(&tabela.to_le_bytes());
    v[56..58].copy_from_slice(&(entradas.len() as u16).to_le_bytes());
    for e in entradas {
        v.extend_from_slice(e);
    }
    v.extend_from_slice(depois);
    v
}

/// Uma nota que nao e do Duke — o dono `GNU`, o tipo 3 — de `tamanho`
/// bytes, multiplo de 4 e de pelo menos 16: o cabecalho, o dono e o
/// conteudo zerado. O achador do manifesto a pula.
fn nota_de_outro(tamanho: usize) -> alloc::vec::Vec<u8> {
    let mut n = alloc::vec::Vec::with_capacity(tamanho);
    n.extend_from_slice(&4u32.to_le_bytes());
    n.extend_from_slice(&((tamanho - 16) as u32).to_le_bytes());
    n.extend_from_slice(&3u32.to_le_bytes());
    n.extend_from_slice(b"GNU\0");
    n.resize(tamanho, 0);
    n
}

/// O lote A5, no teto da tabela de segmentos e no orcamento das notas (o
/// achado A1 do adversario do lote A4): a conferencia da imagem roda no fio
/// de quem lanca, e o `elf::validar` percorria a tabela inteira — o
/// `e_phnum` ate 65535 — e lia as notas de cada `PT_NOTE`, sem teto. Pela
/// conta pura, sem medir tempo: a imagem do adversario — `PT_NOTE` que
/// apontam todos para a propria tabela, cada entrada lida como uma nota de
/// 56 bytes — com 4096 entradas, recusada pela tabela grande demais, e com
/// o teto de entradas (`elf::MAX_ENTRADAS`), pelo orcamento das notas
/// (`elf::ORCAMENTO_DAS_NOTAS`); o `ola` com a tabela no teto — as entradas
/// a mais vazias — se confere, e com uma a mais, nao; com as notas no
/// orcamento — um `PT_NOTE` a mais, com uma nota que nao e do Duke —, se
/// confere, e com quatro bytes a mais, nao. E pelo `user.run`, com os
/// editores do caso: o `ola` com a tabela no teto lanca e sai com o codigo
/// dele; o de uma entrada a mais e o de quatro bytes de notas a mais nao
/// lancam — `launched: false` com o motivo, o desfecho na auditoria, e
/// nenhum nascimento. Antes do lote A5, a imagem de muitas notas so era
/// recusada depois da conta inteira, e o `ola` de entradas demais lancava.
pub(super) fn contencao_a_imagem_de_entradas_ou_notas_demais_nao_se_carrega() -> Resultado {
    use crate::usuario::elf::{MAX_ENTRADAS, ORCAMENTO_DAS_NOTAS, validar};
    const GRANDE_DEMAIS: &str = "tabela de segmentos grande demais";
    const NOTAS_DEMAIS: &str = "segmentos de notas grandes demais";
    const PT_NOTE: u32 = protocolo::usuario::manifesto::SEGMENTO_DE_NOTAS;
    crate::pessoas::esquecer_registradas();
    let livres = crate::fios::vagas_livres_de_teste();
    let ola = super::ola_da_imagem()?;
    let originais = entradas_de(&ola)?;
    // O `ola` com `n` entradas: as dele, e as vazias (`PT_NULL`) que faltam.
    let com_entradas = |n: usize| {
        let mut entradas = originais.clone();
        entradas.resize(n, [0u8; 56]);
        com_a_tabela(&ola, &entradas, &[])
    };
    // O `ola` com as notas dele e mais um `PT_NOTE` de `extra` bytes, logo
    // depois da tabela.
    let com_notas = |extra: usize| {
        let mut entradas = originais.clone();
        let onde = onde_vai_a_tabela(&ola) + 56 * (entradas.len() + 1);
        entradas.push(entrada_de_segmento(
            PT_NOTE,
            4,
            onde as u64,
            0,
            extra as u64,
            extra as u64,
        ));
        com_a_tabela(&ola, &entradas, &nota_de_outro(extra))
    };
    // As notas do `ola`: o que os `PT_NOTE` dele leem.
    let do_ola: usize = originais
        .iter()
        .filter(|e| e[0..4] == PT_NOTE.to_le_bytes())
        .map(|e| {
            let mut tamanho = [0u8; 8];
            tamanho.copy_from_slice(&e[32..40]);
            u64::from_le_bytes(tamanho) as usize
        })
        .sum();
    // A imagem do adversario: o cabecalho do `ola` e `n` entradas `PT_NOTE`,
    // cada uma com a tabela inteira como notas. Lida como nota, cada entrada
    // tem o tamanho do dono no tipo (4) e o do conteudo nas flags (40): 56
    // bytes, a entrada inteira. Nenhuma entrada carregavel.
    let do_adversario = |n: usize| {
        let mut v = ola[..64].to_vec();
        v[32..40].copy_from_slice(&64u64.to_le_bytes());
        v[56..58].copy_from_slice(&(n as u16).to_le_bytes());
        for _ in 0..n {
            v.extend_from_slice(&entrada_de_segmento(PT_NOTE, 40, 64, 0, 56 * n as u64, 0));
        }
        v
    };

    // A conta pura.
    for (nome, bytes, esperado) in [
        (
            "o ola com a tabela no teto",
            com_entradas(MAX_ENTRADAS),
            None,
        ),
        (
            "o ola com uma entrada a mais",
            com_entradas(MAX_ENTRADAS + 1),
            Some(GRANDE_DEMAIS),
        ),
        (
            "o ola com as notas no orcamento",
            com_notas(ORCAMENTO_DAS_NOTAS - do_ola),
            None,
        ),
        (
            "o ola com quatro bytes de notas a mais",
            com_notas(ORCAMENTO_DAS_NOTAS - do_ola + 4),
            Some(NOTAS_DEMAIS),
        ),
        (
            "a imagem do adversario, de 4096 entradas",
            do_adversario(4096),
            Some(GRANDE_DEMAIS),
        ),
        (
            "a imagem do adversario, no teto de entradas",
            do_adversario(MAX_ENTRADAS),
            Some(NOTAS_DEMAIS),
        ),
    ] {
        let visto = validar(&bytes).err();
        if visto != esperado {
            crate::log_error!("teste", "{}: {:?}, e nao {:?}", nome, visto, esperado);
            return Err("a conferencia do ELF nao tem o teto da tabela ou o orcamento das notas");
        }
    }

    // Pelo `user.run`.
    let resultado = super::com_editores_do_caso(|| {
        let selado = |bytes: &[u8]| sigilo::codigo::selar(bytes, &super::EDITOR_DO_CASO.0);
        let quem = operador_que_lanca(187, "a5-entradas-e-notas");
        // O controle: o `ola` com a tabela no teto lanca e sai.
        let no_teto = alloc::format!("{}/ola-com-a-tabela-no-teto", super::CODIGO_INSTALADO);
        super::gravar_codigo(&no_teto, &selado(&com_entradas(MAX_ENTRADAS)))?;
        let desde = crate::log::total_emitidos();
        let r = fs_pedir(
            quem,
            "user.run",
            &alloc::format!(r#"{{"path":"{no_teto}"}}"#),
        );
        if fs_numero(&r, "thread_id").is_none() {
            crate::log_error!("teste", "{}", r);
            return Err("o ola com a tabela no teto nao lancou");
        }
        super::saida_do_processo(desde, super::SAIDA_DO_OLA)?;
        // Uma entrada a mais, e quatro bytes de notas a mais.
        for (nome, bytes, motivo) in [
            (
                "ola-de-entradas-demais",
                com_entradas(MAX_ENTRADAS + 1),
                GRANDE_DEMAIS,
            ),
            (
                "ola-de-notas-demais",
                com_notas(ORCAMENTO_DAS_NOTAS - do_ola + 4),
                NOTAS_DEMAIS,
            ),
        ] {
            let caminho = alloc::format!("{}/{nome}", super::CODIGO_INSTALADO);
            super::gravar_codigo(&caminho, &selado(&bytes))?;
            nao_carrega(quem, &caminho, motivo)?;
        }
        Ok(())
    });
    let vagas = esperar_ate(|| crate::fios::vagas_livres_de_teste() >= livres, 600)
        .map_err(|_| "as vagas do caso das entradas e das notas nao voltaram");
    crate::pessoas::esquecer_registradas();
    resultado.and(vagas)
}

/// O lote A5, na pagina de cima do teto (o pre-existente 1 do adversario do
/// lote A4): um `PT_LOAD` vazio — nada do arquivo, nada na memoria — com o
/// destino no `TETO` passava pelo `elf::validar`, porque a faixa vazia
/// `[TETO, TETO)` cabe no espaco do usuario, e ganhava a pagina
/// `[TETO, TETO + 4 KiB)`: uma pagina de usuario acima do teto declarado,
/// ainda na entrada de topo do processo, que a morte dele devolve, mas que
/// a copia na escrita e a conferencia das faixas das chamadas nao tomam por
/// do usuario. O `ola` com esse segmento a mais nao lanca — `launched:
/// false` com o motivo, o desfecho na auditoria, e nenhum nascimento. E o
/// controle: o `ola` com o mesmo segmento vazio dentro do espaco do
/// programa lanca e sai com o codigo dele — o que se recusa e a pagina
/// fora, e nao o segmento vazio.
pub(super) fn contencao_o_segmento_vazio_no_teto_nao_ganha_a_pagina_de_cima() -> Resultado {
    const FORA: &str = "um segmento quer paginas fora do espaco do usuario";
    crate::pessoas::esquecer_registradas();
    let livres = crate::fios::vagas_livres_de_teste();
    let ola = super::ola_da_imagem()?;
    let originais = entradas_de(&ola)?;
    // O `ola` com um `PT_LOAD` vazio, so de leitura, em `destino`.
    let com_o_vazio_em = |destino: u64| {
        let mut entradas = originais.clone();
        entradas.push(entrada_de_segmento(1, 4, 0, destino, 0, 0));
        com_a_tabela(&ola, &entradas, &[])
    };
    let resultado = super::com_editores_do_caso(|| {
        let selado = |bytes: &[u8]| sigilo::codigo::selar(bytes, &super::EDITOR_DO_CASO.0);
        let quem = operador_que_lanca(188, "a5-vazio-no-teto");
        // O controle: o vazio a 48 MiB do comeco, entre o programa e o que
        // o `mapear` da.
        let dentro = alloc::format!("{}/ola-com-o-vazio-dentro", super::CODIGO_INSTALADO);
        let no_espaco = com_o_vazio_em(crate::usuario::BASE + 0x0300_0000);
        super::gravar_codigo(&dentro, &selado(&no_espaco))?;
        let desde = crate::log::total_emitidos();
        let r = fs_pedir(
            quem,
            "user.run",
            &alloc::format!(r#"{{"path":"{dentro}"}}"#),
        );
        if fs_numero(&r, "thread_id").is_none() {
            crate::log_error!("teste", "{}", r);
            return Err("o ola com o segmento vazio dentro do espaco nao lancou");
        }
        super::saida_do_processo(desde, super::SAIDA_DO_OLA)?;
        // O vazio no `TETO`.
        let no_teto = alloc::format!("{}/ola-com-o-vazio-no-teto", super::CODIGO_INSTALADO);
        super::gravar_codigo(&no_teto, &selado(&com_o_vazio_em(crate::usuario::TETO)))?;
        nao_carrega(quem, &no_teto, FORA)
    });
    let vagas = esperar_ate(|| crate::fios::vagas_livres_de_teste() >= livres, 600)
        .map_err(|_| "as vagas do caso do segmento vazio no teto nao voltaram");
    crate::pessoas::esquecer_registradas();
    resultado.and(vagas)
}

// ---------------------------------------------------------------------------
// O lote A6: o motivo de duas recusas da conferencia da imagem que os casos
// do lote A5 nao fixavam, e o teto das paginas da imagem
// ---------------------------------------------------------------------------

/// O lote A6, nos motivos que os casos do lote A5 nao fixavam (o I2 do
/// adversario do lote A5, e a observacao do revisor dele sobre a mutacao
/// PG3), a partir do caso que o adversario propos:
///
/// - o orcamento das notas vem antes de ler cada `PT_NOTE`: o `ola` com um
///   `PT_NOTE` a mais, quatro bytes acima do orcamento, cuja nota diz ter o
///   dobro do segmento de conteudo, ouve "segmentos de notas grandes
///   demais", e nao o erro do achador, "nota passa do fim do segmento", que
///   so sairia se o segmento fosse lido antes. Com o orcamento depois da
///   leitura (a mutacao EL6), um `PT_NOTE` de um MiB de notas de 12 bytes
///   custava 87 382 voltas do achador antes da recusa, contra no maximo
///   341, e o caso do lote A5 passava igual;
/// - o segmento que acaba no `TETO` invade a pilha: o `ola` com um
///   `PT_LOAD` em `[TETO - 4 KiB, TETO)`, pelo `user.run`, nao lanca e
///   ouve "um segmento invade a pilha do processo" — na resposta e no
///   desfecho na auditoria, sem nascimento (`nao_carrega`). Com o limite de
///   cima da faixa com `>=` (a PG3), o motivo vira "um segmento quer
///   paginas fora do espaco do usuario", e o caso do lote A5 passava igual.
pub(super) fn contencao_o_orcamento_vem_antes_e_o_teto_invade_a_pilha() -> Resultado {
    use crate::usuario::elf::{ORCAMENTO_DAS_NOTAS, validar};
    const NOTAS_DEMAIS: &str = "segmentos de notas grandes demais";
    const PILHA: &str = "um segmento invade a pilha do processo";
    const PT_NOTE: u32 = protocolo::usuario::manifesto::SEGMENTO_DE_NOTAS;
    crate::pessoas::esquecer_registradas();
    let livres = crate::fios::vagas_livres_de_teste();
    let ola = super::ola_da_imagem()?;
    let originais = entradas_de(&ola)?;
    // As notas do `ola`: o que os `PT_NOTE` dele leem.
    let do_ola: usize = originais
        .iter()
        .filter(|e| e[0..4] == PT_NOTE.to_le_bytes())
        .map(|e| {
            let mut tamanho = [0u8; 8];
            tamanho.copy_from_slice(&e[32..40]);
            u64::from_le_bytes(tamanho) as usize
        })
        .sum();
    // Um `PT_NOTE` a mais, quatro bytes acima do orcamento, logo depois da
    // tabela, cuja nota diz ter o dobro do segmento de conteudo: o achador a
    // recusaria com "nota passa do fim do segmento".
    let extra = ORCAMENTO_DAS_NOTAS - do_ola + 4;
    let mut nota = alloc::vec::Vec::with_capacity(extra);
    nota.extend_from_slice(&4u32.to_le_bytes());
    nota.extend_from_slice(&((2 * extra) as u32).to_le_bytes());
    nota.extend_from_slice(&3u32.to_le_bytes());
    nota.extend_from_slice(b"GNU\0");
    nota.resize(extra, 0);
    let mut com_a_nota = originais.clone();
    let onde = onde_vai_a_tabela(&ola) + 56 * (com_a_nota.len() + 1);
    com_a_nota.push(entrada_de_segmento(
        PT_NOTE,
        4,
        onde as u64,
        0,
        extra as u64,
        extra as u64,
    ));
    let visto = validar(&com_a_tabela(&ola, &com_a_nota, &nota)).err();
    if visto != Some(NOTAS_DEMAIS) {
        crate::log_error!("teste", "a nota acima do orcamento: {:?}", visto);
        return Err("o orcamento das notas nao vem antes de ler o segmento");
    }

    // O segmento que acaba no `TETO`, pelo `user.run`.
    let resultado = super::com_editores_do_caso(|| {
        let selado = |bytes: &[u8]| sigilo::codigo::selar(bytes, &super::EDITOR_DO_CASO.0);
        let quem = operador_que_lanca(189, "a6-pilha-no-teto");
        let mut no_fim = originais.clone();
        no_fim.push(entrada_de_segmento(
            1,
            4,
            0,
            crate::usuario::TETO - 4096,
            0,
            4096,
        ));
        let caminho = alloc::format!("{}/ola-que-acaba-no-teto", super::CODIGO_INSTALADO);
        super::gravar_codigo(&caminho, &selado(&com_a_tabela(&ola, &no_fim, &[])))?;
        nao_carrega(quem, &caminho, PILHA)
    });
    let vagas = esperar_ate(|| crate::fios::vagas_livres_de_teste() >= livres, 600)
        .map_err(|_| "as vagas do caso do orcamento e da pilha nao voltaram");
    crate::pessoas::esquecer_registradas();
    resultado.and(vagas)
}

/// O lote A6, no teto das paginas da imagem (o achado B4 do adversario do
/// lote A5): a conferencia tinha teto, e a carga nao — o terceiro passo
/// zera e mapeia o que os segmentos pedem, no `exec` dentro da chamada, com
/// as interrupcoes mascaradas, e um `.bss` de quase todo o espaco do
/// usuario, num arquivo de uma pagina, passava. A soma das paginas dos
/// segmentos fica no espaco que o mapa do usuario da ao programa
/// (`programa::MAX_PAGINAS_DA_IMAGEM`, 64 MiB). Pela conta pura
/// (`programa::conferir_a_imagem_de_teste`), sem carregar nada — a imagem
/// no teto pede metade da maquina da bancada: o `ola` com um `PT_LOAD`
/// vazio a mais, que leva a soma ao teto, se confere; com uma pagina a
/// mais, nao; dois segmentos que cabem, cada um, e passam juntos, nao — o
/// teto e da soma —; e o `.bss` ate a guarda da pilha, nao. Antes do lote
/// A6, as tres passavam.
pub(super) fn contencao_a_imagem_de_paginas_demais_nao_se_confere() -> Resultado {
    use crate::usuario::programa::{MAX_PAGINAS_DA_IMAGEM, conferir_a_imagem_de_teste};
    const DEMAIS: &str = "os segmentos pedem paginas demais";
    const PAGINA: u64 = 4096;
    let ola = super::ola_da_imagem()?;
    let originais = entradas_de(&ola)?;
    // As paginas dos segmentos carregaveis do `ola`, como a conferencia as
    // conta — da pagina do destino a que cobre o fim, pelo menos uma —, e
    // onde elas acabam.
    let campo = |e: &[u8; 56], de: usize| {
        let mut v = [0u8; 8];
        v.copy_from_slice(&e[de..de + 8]);
        u64::from_le_bytes(v)
    };
    let mut do_ola = 0u64;
    let mut fim_do_ola = 0u64;
    for e in originais.iter().filter(|e| e[0..4] == 1u32.to_le_bytes()) {
        let (destino, na_memoria) = (campo(e, 16), campo(e, 40));
        let primeira = destino & !(PAGINA - 1);
        let ultima = (destino + na_memoria).div_ceil(PAGINA) * PAGINA;
        do_ola += (ultima.max(primeira + PAGINA) - primeira) / PAGINA;
        fim_do_ola = fim_do_ola.max(ultima);
    }
    // Os segmentos a mais, so de leitura e vazios no arquivo, um depois do
    // outro, a partir de 16 MiB do comeco: longe do `ola`.
    let longe = crate::usuario::BASE + 0x0100_0000;
    if fim_do_ola > longe {
        return Err("o ola do caso passa de 16 MiB do comeco do espaco do usuario");
    }
    let com = |segmentos: &[u64]| {
        let mut entradas = originais.clone();
        let mut destino = longe;
        for &paginas in segmentos {
            entradas.push(entrada_de_segmento(1, 4, 0, destino, 0, paginas * PAGINA));
            destino += paginas * PAGINA;
        }
        com_a_tabela(&ola, &entradas, &[])
    };
    let falta = MAX_PAGINAS_DA_IMAGEM - do_ola;
    let metade = MAX_PAGINAS_DA_IMAGEM / 2 + 1;
    let ate_a_guarda =
        (crate::usuario::TETO - (protocolo::usuario::PAGINAS_DA_PILHA + 1) * PAGINA - longe)
            / PAGINA;
    for (nome, bytes, esperado) in [
        ("o ola no teto das paginas", com(&[falta]), None),
        (
            "o ola com uma pagina a mais",
            com(&[falta + 1]),
            Some(DEMAIS),
        ),
        (
            "dois segmentos que passam juntos",
            com(&[metade, metade]),
            Some(DEMAIS),
        ),
        (
            "o .bss ate a guarda da pilha",
            com(&[ate_a_guarda]),
            Some(DEMAIS),
        ),
    ] {
        let visto = conferir_a_imagem_de_teste(&bytes).err();
        if visto != esperado {
            crate::log_error!("teste", "{}: {:?}, e nao {:?}", nome, visto, esperado);
            return Err("a conferencia da imagem nao tem o teto das paginas");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// O lote A7: a guarda do desfecho de um lancamento, nas duas compilacoes
// ---------------------------------------------------------------------------

/// O lote A7, na guarda do `DesfechoDoLancamento` (o I2 do adversario do
/// lote A6): com um codigo que permite, nas duas compilacoes, o desfecho nao
/// grava nada, diz no log do kernel e devolve zero. Ate o lote A6, a guarda
/// era um `debug_assert!`: na depuracao, o kernel parava; em release, um
/// `ALLOW` com `processo N lancado` ia a auditoria em nome do kernel
/// (`process.run`), e o NSF lia o nascimento de N. Pelo embrulho da suite
/// (`autorizacao::gravar_um_desfecho_de_teste`), fora de um comando — o
/// caminho do kernel —: o `ALLOW` devolve zero, nao deixa registro, e o log
/// diz. Pelo outro caminho, o de dentro de um comando (`gravar_no_comando`),
/// que fora de um nao grava nada de qualquer jeito, o log diz tambem: a
/// guarda e uma so, e uma que valesse so num dos dois reprovaria aqui. O
/// controle — o mesmo desfecho com `ERROR`, gravado depois — grava, e o
/// NSF, que o leu, nao acha o nascimento.
pub(super) fn contencao_o_desfecho_que_permite_nao_grava() -> Resultado {
    use politica::Codigo;
    use seguranca::evento::Tipo;
    const RECURSO: &str = "/a7/o-desfecho-que-permite";
    // Um fio que nao existe: os da maquina ficam muito abaixo.
    const FILHO: u64 = 4_000_000_007;
    let lancado = alloc::format!("processo {FILHO} lancado");
    super::com_o_nsf(|| {
        let desde = crate::log::total_emitidos();
        let permitido = crate::autorizacao::gravar_um_desfecho_de_teste(
            RECURSO,
            Codigo::Allow,
            &lancado,
            false,
        );
        let no_comando =
            crate::autorizacao::gravar_um_desfecho_de_teste(RECURSO, Codigo::Allow, &lancado, true);
        let mut disse = 0;
        crate::log::ultimos(64, crate::log::Level::Trace, |r| {
            disse += (r.seq >= desde
                && r.subsistema == "autorizacao"
                && r.mensagem().contains(RECURSO)
                && r.mensagem().contains("veio com ALLOW")) as usize;
        });
        let controle = crate::autorizacao::gravar_um_desfecho_de_teste(
            RECURSO,
            Codigo::Error,
            "o controle do desfecho que permite",
            false,
        );
        crate::log_info!(
            "teste",
            "contencao: o desfecho com ALLOW devolveu {} fora do comando e {} pelo caminho do \
             comando, e o log disse {} vez(es); o controle, com ERROR, foi o registro {}",
            permitido,
            no_comando,
            disse,
            controle
        );
        if permitido != 0 || no_comando != 0 {
            return Err("o desfecho de um lancamento gravou um codigo que permite");
        }
        if super::registro_que(|e| e.detalhe.contains(&lancado)).is_some() {
            return Err("o desfecho com ALLOW deixou registro na auditoria");
        }
        if disse != 2 {
            return Err(
                "o desfecho recusado nao disse no log, uma vez em cada caminho, o que recusou",
            );
        }
        if controle == 0 {
            return Err("o desfecho com ERROR nao gravou: o caso nao conferiu nada");
        }
        let e = super::registro_numero(controle).ok_or("o registro do controle saiu do anel")?;
        if e.codigo != Codigo::Error || e.metodo != "process.run" || e.recurso != RECURSO {
            crate::log_error!("teste", "{:?}", e);
            return Err("o controle nao foi gravado como o desfecho do kernel");
        }
        let _ = crate::seguranca::passo();
        let _ = crate::seguranca::passo();
        let visto = crate::seguranca::com_motor_de_teste(|m| {
            (
                m.evento(controle).is_some(),
                m.eventos()
                    .any(|ev| ev.tipo == Tipo::Nascimento { filho: FILHO }),
            )
        });
        match visto {
            Some((true, false)) => Ok(()),
            Some((true, true)) => Err("o NSF achou o nascimento de um desfecho que permite"),
            _ => Err("o NSF nao leu o controle: o caso nao conferiu nada"),
        }
    })
}

// ---------------------------------------------------------------------------
// O lote A8 (o T1 do adversario do lote A7): o desfecho dentro de um comando
// ---------------------------------------------------------------------------

/// O detalhe que o gancho tenta gravar com o `ALLOW`, dentro do comando.
const LANCADO_NO_COMANDO: &str = "processo 4000000009 lancado";
/// O caminho do `user.run` do caso: o operador alcanca `/bin`, e ele nao
/// existe.
const CAMINHO_DO_DESFECHO_NO_COMANDO: &str = "/bin/nao-existe";
/// O que o gancho devolveu, pelo `gravar` e pelo `gravar_no_comando`
/// (`u64::MAX`: o gancho nao rodou).
static NO_COMANDO_GRAVAR: AtomicU64 = AtomicU64::new(u64::MAX);
static NO_COMANDO_GRAVAR_NO_COMANDO: AtomicU64 = AtomicU64::new(u64::MAX);
/// O controle positivo do gancho, desde o lote A9 (o I2 do adversario do
/// lote A8): o numero do registro que ele grava com `ERROR` pelo
/// `gravar_no_comando` -- que so grava dentro de um comando, e fora devolve
/// zero -- (`u64::MAX`: o gancho nao rodou).
static NO_COMANDO_CONTROLE: AtomicU64 = AtomicU64::new(u64::MAX);
/// O detalhe do controle positivo do gancho.
const CONTROLE_NO_COMANDO: &str = "controle: o gancho rodou dentro do comando";

/// O gancho de antes das perguntas do gate sobre quem pede: roda no
/// lancamento do `user.run`, dentro do comando, e tenta gravar o desfecho
/// com `ALLOW` e `processo N lancado` pelos dois caminhos.
fn o_desfecho_que_permite_no_comando() {
    NO_COMANDO_GRAVAR.store(
        crate::autorizacao::gravar_um_desfecho_de_teste(
            CAMINHO_DO_DESFECHO_NO_COMANDO,
            politica::Codigo::Allow,
            LANCADO_NO_COMANDO,
            false,
        ),
        SeqCst,
    );
    NO_COMANDO_GRAVAR_NO_COMANDO.store(
        crate::autorizacao::gravar_um_desfecho_de_teste(
            CAMINHO_DO_DESFECHO_NO_COMANDO,
            politica::Codigo::Allow,
            LANCADO_NO_COMANDO,
            true,
        ),
        SeqCst,
    );
    NO_COMANDO_CONTROLE.store(
        crate::autorizacao::gravar_um_desfecho_de_teste(
            CAMINHO_DO_DESFECHO_NO_COMANDO,
            politica::Codigo::Error,
            CONTROLE_NO_COMANDO,
            true,
        ),
        SeqCst,
    );
}

/// O lote A8, pelo T1 do adversario do lote A7, sobre o caso do I2: a guarda
/// do desfecho tambem dentro de um comando -- o caminho da execucao da
/// decisao, em que o `ALLOW` iria em nome de quem o gate decidiu, e o NSF
/// leria o nascimento. O caso do lote A7 so alcanca o desfecho fora de um
/// comando: uma guarda so ali (`&& self.execucao.is_none()`, a DG4) passava
/// nele, e em toda a suite, porque nenhum chamador de verdade passa um codigo
/// que permite. Pelo gancho de antes das perguntas do gate sobre quem pede,
/// no `user.run` de um caminho que nao existe: os dois caminhos devolvem
/// zero, o log diz uma vez em cada, nada com `processo 4000000009 lancado`
/// vai a auditoria, o `user.run` grava o desfecho dele -- `ERROR`, a leitura
/// -- e o NSF, que o leu, nao acha o nascimento.
///
/// E, desde o lote A9 (o I2 do adversario do lote A8), o controle positivo
/// de que o gancho rodou dentro do comando: o gancho e de quem o toma
/// primeiro, e um lancamento de fora de um comando que o tomasse daria zero
/// nos dois caminhos -- tambem com a DG4. O mesmo embrulho grava, pelo
/// `gravar_no_comando`, um `ERROR`, que so dentro de um comando se grava, e
/// tem de sair como a execucao do `user.run` do caso.
///
/// E, desde o lote A10 (o IN1 do adversario do lote A9), do `user.run` do
/// caso, e nao de um qualquer: o recurso do controle e o que o proprio
/// gancho passa, e o metodo vem da decisao do comando do fio -- o controle
/// provava que o gancho rodou dentro de **um** `user.run` decidido. Agora a
/// decisao que o controle cita (`; decisao N`) e a que a execucao do caso
/// cita, e o registro dela e o `ALLOW` do `user.run` do caminho do caso,
/// tomado depois que o caso comecou.
pub(super) fn contencao_o_desfecho_que_permite_nao_grava_no_comando() -> Resultado {
    use politica::Codigo;
    use seguranca::evento::Tipo;
    NO_COMANDO_GRAVAR.store(u64::MAX, SeqCst);
    NO_COMANDO_GRAVAR_NO_COMANDO.store(u64::MAX, SeqCst);
    NO_COMANDO_CONTROLE.store(u64::MAX, SeqCst);
    crate::pessoas::esquecer_registradas();
    let resultado = super::com_o_nsf(|| {
        let quem = operador_que_lanca(181, "desfecho-no-comando");
        let desde = crate::log::total_emitidos();
        let cabeca = crate::autorizacao::ultimo_registro();
        crate::autorizacao::antes_do_gate_do_lancamento_de_teste(Some(
            o_desfecho_que_permite_no_comando,
        ));
        let r = fs_pedir(
            quem,
            "user.run",
            &alloc::format!(r#"{{"path":"{CAMINHO_DO_DESFECHO_NO_COMANDO}"}}"#),
        );
        crate::autorizacao::antes_do_gate_do_lancamento_de_teste(None);
        let mut disse = 0;
        crate::log::ultimos(256, crate::log::Level::Trace, |l| {
            disse += (l.seq >= desde
                && l.subsistema == "autorizacao"
                && l.mensagem().contains(CAMINHO_DO_DESFECHO_NO_COMANDO)
                && l.mensagem().contains("veio com ALLOW")) as usize;
        });
        let gravar = NO_COMANDO_GRAVAR.load(SeqCst);
        let no_comando = NO_COMANDO_GRAVAR_NO_COMANDO.load(SeqCst);
        let controle_do_gancho = NO_COMANDO_CONTROLE.load(SeqCst);
        crate::log_info!(
            "teste",
            "contencao: dentro do comando, o desfecho com ALLOW devolveu {} pelo gravar e {} pelo \
             gravar_no_comando, o controle com ERROR gravou o registro {}, e o log disse {} \
             vez(es): {}",
            gravar,
            no_comando,
            controle_do_gancho,
            disse,
            r
        );
        if gravar == u64::MAX || no_comando == u64::MAX || controle_do_gancho == u64::MAX {
            return Err("o gancho nao rodou dentro do user.run: o caso nao conferiu nada");
        }
        // O controle positivo: o `ERROR` pelo `gravar_no_comando` so se grava
        // dentro de um comando, e sai como a execucao do `user.run` do caso.
        if controle_do_gancho == 0 {
            return Err(
                "o controle do gancho com ERROR nao gravou: o gancho rodou fora de um comando, e \
                 o caso nao conferiu o desfecho dentro dele",
            );
        }
        let decisao_do_controle = match super::registro_numero(controle_do_gancho) {
            Some(e)
                if e.metodo == "user.run"
                    && e.recurso == CAMINHO_DO_DESFECHO_NO_COMANDO
                    && e.codigo == Codigo::Error
                    && e.detalhe.contains(CONTROLE_NO_COMANDO) =>
            {
                super::decisao_executada(&e.detalhe)
            }
            Some(e) => {
                crate::log_error!("teste", "{:?}", e);
                return Err(
                    "o controle do gancho nao saiu como a execucao do user.run do caso: o gancho \
                     rodou noutro comando",
                );
            }
            None => return Err("o registro do controle do gancho saiu do anel"),
        };
        if gravar != 0 || no_comando != 0 {
            return Err(
                "dentro de um comando, o desfecho de um lancamento gravou um codigo que permite",
            );
        }
        if super::registro_que(|e| e.detalhe.contains(LANCADO_NO_COMANDO)).is_some() {
            return Err("dentro de um comando, o desfecho com ALLOW deixou registro na auditoria");
        }
        if disse != 2 {
            return Err(
                "dentro de um comando, o desfecho recusado nao disse no log, uma vez em cada \
                 caminho, o que recusou",
            );
        }
        // O controle: o desfecho de verdade do `user.run` -- `ERROR`, a
        // leitura --, gravado depois do gancho.
        let execucoes = registros_depois(cabeca, |ev| {
            ev.metodo == "user.run"
                && ev.recurso == CAMINHO_DO_DESFECHO_NO_COMANDO
                && ev.codigo == Codigo::Error
                && !ev.detalhe.contains(CONTROLE_NO_COMANDO)
        });
        let Some((controle, execucao)) = execucoes.last() else {
            return Err("o user.run do caso ficou sem o desfecho: o caso nao conferiu nada");
        };
        let controle = *controle;
        // Desde o lote A10, o controle do gancho e o do `user.run` do caso: a
        // decisao que ele cita e a que a execucao do caso cita, e o registro
        // dela e o `ALLOW` do `user.run` do caminho do caso, tomado depois que
        // o caso comecou -- e nao a de outro `user.run` que tomasse o gancho.
        let decisao_do_caso = super::decisao_executada(&execucao.detalhe);
        crate::log_info!(
            "teste",
            "contencao: o controle do gancho cita a decisao {:?}, e a execucao do user.run do \
             caso, a {:?}",
            decisao_do_controle,
            decisao_do_caso
        );
        let Some(decisao) = decisao_do_caso.filter(|_| decisao_do_controle == decisao_do_caso)
        else {
            return Err(
                "o controle do gancho nao cita a decisao do user.run do caso: o gancho rodou \
                 noutro comando",
            );
        };
        match super::registro_numero(decisao) {
            Some(d)
                if decisao > cabeca
                    && d.metodo == "user.run"
                    && d.recurso == CAMINHO_DO_DESFECHO_NO_COMANDO
                    && d.codigo == Codigo::Allow => {}
            Some(d) => {
                crate::log_error!("teste", "{:?}", d);
                return Err(
                    "a decisao que o controle cita nao e o ALLOW do user.run do caso, tomado \
                     depois que ele comecou",
                );
            }
            None => return Err("o registro da decisao do user.run do caso saiu do anel"),
        }
        let _ = crate::seguranca::passo();
        let _ = crate::seguranca::passo();
        let visto = crate::seguranca::com_motor_de_teste(|m| {
            (
                m.evento(controle).is_some(),
                m.eventos().any(|ev| {
                    ev.tipo
                        == Tipo::Nascimento {
                            filho: 4_000_000_009,
                        }
                }),
            )
        });
        match visto {
            Some((true, false)) => Ok(()),
            Some((true, true)) => {
                Err("o NSF achou o nascimento de um desfecho que permite, dentro de um comando")
            }
            _ => Err("o NSF nao leu o controle: o caso nao conferiu nada"),
        }
    });
    crate::autorizacao::antes_do_gate_do_lancamento_de_teste(None);
    crate::pessoas::esquecer_registradas();
    resultado
}
