//! Os casos da decisão de novo no ponto sem volta do `exec` — o F4 do
//! adversário do AE-1, e os achados do adversário do lote A do #448.
//!
//! O `executar` decide `process.run` sobre o caminho antes de ler o
//! arquivo; depois lê, confere o código e prepara a imagem — o tempo do
//! arquivo —, e só então troca. Uma revogação, uma política nova ou uma
//! contenção que chegue nesse meio não parava a troca, que seguia com o
//! `ALLOW` de antes. Agora a decisão é feita de novo imediatamente antes de
//! trocar (`autorizacao::DecisaoDoProcesso::reconfirmar_com_o_codigo`):
//! quem é ponta de fluxo, com a ordem das gravações na mão — tomada sem
//! esperar —; quem não é, sem ela, e sem esperá-la. Recusada, nada se
//! troca: o processo segue com a imagem dele, ouve `NEGADO`, e a recusa vai
//! à auditoria como a execução da decisão do gate, em nome de quem ela
//! decidiu. A decisão de novo pergunta também o que a do gate não via: a
//! confiança no editor da imagem nova, que a conferência do código
//! perguntou antes de preparar, e o fim pedido sem o isolamento — o
//! processo que o tem morre na volta da chamada, sem a troca.
//!
//! A janela é a do tempo do arquivo, e uma mudança de outro fio só cai nela
//! por acaso. Os casos a abrem no ponto exato, pela pausa da troca
//! (`usuario::pausa_da_troca_de_teste`): o processo `fluxos`, preso a um
//! núcleo que não é o da suíte, para no handler — decidido, com a imagem
//! preparada, antes da decisão de novo e da ordem —, a suíte faz a mudança
//! de fora, como um comando de outro núcleo faria, e o solta. Cada caso
//! roda com quem é ponta de um fluxo e com quem não é. A pausa gira com as
//! interrupções mascaradas: com um núcleo só, não há onde a suíte rodar, e
//! os casos dizem isso e passam.
//!
//! # A volta pausada adiada
//!
//! Quem é ponta pode ter a volta pausada adiada: o coletor toma a ordem
//! entre a conferência do começo da chamada e a tomada sem esperar, a volta
//! fica `CONFLICT`, "adiada", e a seguinte decide pelo gate — que já vê a
//! mudança e recusa ele mesmo, antes do ponto sem volta — sem a decisão de
//! novo. Essa rodada não exercitou o que o caso confere: uma troca sem a
//! decisão de novo também passaria por ela. Ela não conta: a rodada se
//! repete, com processos novos, até [`TENTATIVAS`] vezes, e o caso reprova
//! se nenhuma passou pela decisão de novo.

use super::*;
use crate::contencao::Alvo;
use crate::usuario::pausa_da_troca_de_teste as pausa;

/// O que a troca devolve recusada pela decisão de novo: o `NEGADO` do gate.
const NEGADO: i64 = protocolo::usuario::erro::NEGADO;

/// O que a troca devolve recusada pela conferência do código, antes do
/// ponto sem volta: o editor em quem o papel não confia.
const EDITOR_NAO_CONFIADO: i64 = protocolo::usuario::erro::EDITOR_NAO_CONFIADO;

/// Um passo que o `fluxos` não conhece: ele diz que não conhece, e segue
/// escutando — a prova de que a imagem de antes ainda roda.
const PASSO_DESCONHECIDO: i64 = 99;

/// A chave do agente do caso da revogação.
const SEMENTE_DO_AGENTE: [u8; 32] = [0x6e; 32];

/// Quantas vezes, no máximo, a rodada se repete até a volta pausada passar
/// pela decisão de novo — ver "A volta pausada adiada", no começo.
const TENTATIVAS: usize = 4;

/// O `b` do passo [`TROCAR`] para o código selado — o mesmo do `fluxos`.
/// Também o caso do #471, em `fluxo.rs`, troca para ele.
pub(super) const PARA_O_SELADO: i64 = 2;

/// Onde o `fluxos` procura o código selado — o mesmo caminho do programa.
pub(super) const SELADO: &str = "/armazem/compartilhado/codigo/ola-selado";

/// A imagem nova da troca.
#[derive(Clone, Copy)]
enum Destino {
    /// O `ola` do disco dos programas: da imagem, sem selo.
    Ola,
    /// O `ola` selado pelo editor do caso, que o caso grava no armazém
    /// ([`SELADO`]): de fora da imagem.
    Selado,
}

impl Destino {
    /// O `b` do passo [`TROCAR`].
    fn passo(self) -> i64 {
        match self {
            Destino::Ola => 0,
            Destino::Selado => PARA_O_SELADO,
        }
    }

    /// O caminho, como o gate o decide.
    fn caminho(self) -> String {
        match self {
            Destino::Ola => format!("{}/ola", crate::usuario::DIRETORIO_DOS_COMPILADOS),
            Destino::Selado => String::from(SELADO),
        }
    }
}

/// O que uma rodada espera da troca parada no meio.
#[derive(Clone, Copy)]
enum Espera<'a> {
    /// Sem mudança no meio: a troca de sempre.
    Troca,
    /// A decisão de novo recusa, com o código e o motivo, e a imagem de
    /// antes segue; adiada a volta pausada, a seguinte recusa a mesma
    /// mudança antes do ponto sem volta, como [`Antes`] diz.
    Recusa(Codigo, &'a str, Antes),
    /// O fim pedido no meio, sem o isolamento: a decisão de novo recusa,
    /// `DENY_CONTAINED`, "processo encerrado", e o processo morre na volta
    /// da chamada, sem a troca.
    Encerrado,
}

/// Quem recusa a mudança na volta seguinte a uma adiada, antes do ponto
/// sem volta — a decisão de novo não roda nela.
#[derive(Clone, Copy)]
enum Antes {
    /// O gate, no começo da chamada: `NEGADO`, a decisão com o código e o
    /// motivo, e nenhuma execução.
    Gate,
    /// A conferência do código, depois do gate: o processo ouve o erro
    /// dela, e a execução da decisão leva o código e o motivo.
    Conferencia(i64),
}

/// O núcleo onde o processo para, se há um além do da suíte.
fn nucleo_da_pausa() -> Option<usize> {
    crate::testes::outro_nucleo()
}

/// A troca de `c` para `destino`, parada no meio pela pausa: decidida, com
/// a imagem preparada, antes do ponto sem volta. Lá, a suíte faz `mudar` —
/// de fora, como outro fio —, e solta. Devolve de quando o passo começou.
fn trocar_com_a_pausa(
    c: &Ponta,
    nucleo: usize,
    destino: Destino,
    mudar: impl FnOnce() -> Resultado,
) -> Result<u64, &'static str> {
    if !crate::fios::fixar(c.fio(), Some(nucleo)) {
        return Err("o processo nao foi preso a outro nucleo");
    }
    pausa::armar(c.fio());
    let desde = match c.ditar(TROCAR, destino.passo()) {
        Ok(d) => d,
        Err(e) => {
            pausa::soltar();
            return Err(e);
        }
    };
    if esperar_cedendo(pausa::parada, TETO_DA_MALHA).is_err() {
        pausa::soltar();
        return Err("a troca nao parou antes do ponto sem volta");
    }
    let mudado = mudar();
    pausa::soltar();
    mudado?;
    Ok(desde)
}

/// A recusa da troca de `c` para `destino`, com `codigo` e `motivo` — e,
/// adiada a volta pausada, a de quem recusa `antes` —, depois de
/// `desde_o_pedido`: nada foi trocado; o processo segue vivo com a imagem
/// de antes, e ela ainda roda. Devolve se a volta pausada passou pela
/// decisão de novo:
///
/// - sim: a chamada devolveu `NEGADO`, e a última decisão do gate — a da
///   volta pausada, sem nenhuma adiada antes — tem a execução dela com o
///   código e o motivo da recusa, gravada em nome de quem ela decidiu e
///   citando-a;
/// - não: a volta pausada foi adiada — o coletor com a ordem entre a
///   conferência do começo da chamada e a tomada sem esperar (a CI 437) —,
///   cada adiada dita pela execução dela, e a seguinte recusou a mesma
///   mudança antes do ponto sem volta (`antes`): a mesma recusa, feita onde
///   a janela acaba, mas sem a decisão de novo — a rodada não conta (ver "A
///   volta pausada adiada", no começo).
fn recusada_no_ponto_sem_volta(
    c: &Ponta,
    desde: u64,
    desde_o_pedido: u64,
    trocas: u64,
    destino: Destino,
    (codigo, motivo, antes): (Codigo, &str, Antes),
) -> Result<bool, &'static str> {
    let devolveu = dito_na_malha(desde, "fluxos: trocar devolveu ")?;
    if trocas_feitas() != trocas {
        return Err("a troca recusada no ponto sem volta trocou a imagem");
    }
    if crate::fios::processo(c.fio()).map(|(_, p)| p) != Some(c.p.programa) {
        return Err("o processo da troca recusada nao segue com a imagem de antes");
    }
    let ouviu = |erro: i64| devolveu == format!("{erro}");
    let (decisoes, execucoes) = registros_de_troca_para(desde_o_pedido, &destino.caminho());
    let dita = |e: &Registro, d: &politica::auditoria::Evento, numero: u64| {
        execucao_da_troca(e, codigo, c.fio(), motivo, numero)
            && em_nome_da_decisao(d, &e.1, motivo, numero)
    };
    let exercida = match tirar_as_adiadas(&decisoes, &execucoes, c.fio()) {
        // A decisão de novo, na volta pausada: a execução da última decisão,
        // que permitiu, com a recusa.
        Some((0, (numero, d), [e])) if d.codigo == Codigo::Allow && dita(e, d, *numero) => {
            ouviu(NEGADO).then_some(true)
        }
        // A volta pausada adiada, e a seguinte recusou antes do ponto sem
        // volta, sem a decisão de novo.
        Some((adiadas, (numero, d), resto)) if adiadas >= 1 => {
            crate::log_info!(
                "teste",
                "a volta pausada foi adiada ({} voltas adiadas): a seguinte recusou antes do ponto sem volta, `{}`",
                adiadas,
                d.detalhe
            );
            let recusou = match (antes, resto) {
                (Antes::Gate, []) => {
                    ouviu(NEGADO) && d.codigo == codigo && d.detalhe.ends_with(motivo)
                }
                (Antes::Conferencia(erro), [e]) => {
                    ouviu(erro) && d.codigo == Codigo::Allow && dita(e, d, *numero)
                }
                _ => false,
            };
            recusou.then_some(false)
        }
        _ => None,
    };
    let Some(exercida) = exercida else {
        crate::log_error!(
            "teste",
            "trocar devolveu {}; decisoes {:?}; execucoes {:?}",
            devolveu,
            decisoes,
            execucoes
        );
        return Err("a recusa da troca nao esta na auditoria como a execucao da decisao");
    };
    // A imagem de antes ainda roda: o `fluxos` escuta e responde.
    let desde = c.ditar(PASSO_DESCONHECIDO, 0)?;
    let dito = dito_na_malha(desde, "fluxos: passo desconhecido ")?;
    if dito != format!("{PASSO_DESCONHECIDO}") {
        return Err("o processo da troca recusada nao segue respondendo");
    }
    Ok(exercida)
}

/// A troca de `c` com o fim pedido no meio, sem o isolamento, depois de
/// `desde_o_pedido`: o processo morre na volta da chamada — sem dizer o que
/// ela devolveu —, nada foi trocado, e a última decisão do gate tem a
/// execução dela com a recusa da decisão de novo, `DENY_CONTAINED`,
/// "processo encerrado", em nome de quem ela decidiu e citando-a. Devolve
/// se a volta pausada passou pela decisão de novo: não, se ela foi adiada —
/// a execução dela diz `CONFLICT`, "adiada", e o processo morreu na volta,
/// antes de decidir de novo.
fn encerrado_no_ponto_sem_volta(
    c: &Ponta,
    desde: u64,
    desde_o_pedido: u64,
    trocas: u64,
    destino: Destino,
) -> Result<bool, &'static str> {
    // O detalhe escrito aqui, e não lido da constante: o caso confere o que
    // o registro diz, e não a constante por ela mesma.
    let (codigo, motivo) = (Codigo::DenyContained, "processo encerrado");
    esperar_ate(|| !crate::fios::vivo(c.fio()), TETO_DA_MALHA)
        .map_err(|_| "o processo com o fim pedido no meio da troca nao morreu")?;
    if trocas_feitas() != trocas {
        return Err("a troca de quem teve o fim pedido no meio trocou a imagem");
    }
    if linhas_que_comecam(desde, "fluxos: trocar devolveu") != 0 {
        return Err("o processo com o fim pedido seguiu rodando depois da troca recusada");
    }
    let (decisoes, execucoes) = registros_de_troca_para(desde_o_pedido, &destino.caminho());
    let exercida = match tirar_as_adiadas(&decisoes, &execucoes, c.fio()) {
        Some((0, (numero, d), [e])) if d.codigo == Codigo::Allow => {
            if execucao_da_troca(e, codigo, c.fio(), motivo, *numero)
                && em_nome_da_decisao(d, &e.1, motivo, *numero)
            {
                Some(true)
            } else if execucao_da_troca(e, Codigo::Conflict, c.fio(), ADIADA_PELA_ORDEM, *numero)
                && em_nome_da_decisao(d, &e.1, ADIADA_PELA_ORDEM, *numero)
            {
                crate::log_info!(
                    "teste",
                    "a volta pausada foi adiada: o processo morreu na volta, antes de decidir de novo"
                );
                Some(false)
            } else {
                None
            }
        }
        _ => None,
    };
    exercida.ok_or_else(|| {
        crate::log_error!(
            "teste",
            "decisoes {:?}; execucoes {:?}",
            decisoes,
            execucoes
        );
        "a recusa da troca do encerrado nao esta na auditoria como a execucao da decisao"
    })
}

/// O fluxo `id` não acabou pela troca: nenhum fim `o programa mudou`
/// gravado depois de `antes`.
fn sem_o_fim_da_troca(antes: u64, id: &str) -> Resultado {
    let recurso = format!("fluxo:{id}");
    if registros_depois(antes, |e| {
        e.metodo == "stream.end"
            && e.recurso == recurso
            && e.detalhe.starts_with("o programa mudou")
    })
    .is_empty()
    {
        Ok(())
    } else {
        Err("a troca recusada encerrou o fluxo como quem mudou de programa")
    }
}

/// Uma rodada de um caso, com quem é ponta de um fluxo (`ponta`) ou com
/// quem não é: lança o `fluxos` C — e, ponta, o A, com o fluxo de A a C —
/// com `autoridade`, para a troca de C para `destino` no meio, faz `mudar`
/// e confere o que `espera` diz. `desfazer` roda no fim, também quando a
/// rodada falha. Devolve se a volta pausada passou pela decisão de novo —
/// ver "A volta pausada adiada", no começo; a troca de sempre passa sempre:
/// a adiada é seguida de uma que decide de novo, e troca.
fn rodada(
    autoridade: Autoridade,
    ponta: bool,
    nucleo: usize,
    destino: Destino,
    mudar: impl FnOnce(&Ponta) -> Resultado,
    espera: Espera,
    desfazer: impl FnOnce(&Ponta),
) -> Result<bool, &'static str> {
    let antes = crate::autorizacao::ultimo_registro();
    let a = if ponta {
        Some(Ponta::lancar(autoridade)?)
    } else {
        None
    };
    let c = match Ponta::lancar(autoridade) {
        Ok(c) => c,
        Err(e) => {
            return encerrar_todas(Err(e), &a.iter().collect::<Vec<_>>()).map(|_| false);
        }
    };
    let mut trocou = false;
    let r = (|| -> Result<bool, &'static str> {
        let id = match &a {
            Some(a) => {
                let id = aberto(a, &c)?;
                if !crate::fluxo::processo_e_ponta(c.fio()) {
                    return Err("o processo do caso nao virou ponta do fluxo");
                }
                Some(id)
            }
            None => {
                if crate::fluxo::processo_e_ponta(c.fio()) {
                    return Err("o processo do caso e ponta de um fluxo");
                }
                None
            }
        };
        let trocas = trocas_feitas();
        let desde_o_pedido = crate::autorizacao::ultimo_registro();
        let desde = trocar_com_a_pausa(&c, nucleo, destino, || mudar(&c))?;
        match espera {
            Espera::Recusa(codigo, motivo, quem_recusa_antes) => {
                let exercida = recusada_no_ponto_sem_volta(
                    &c,
                    desde,
                    desde_o_pedido,
                    trocas,
                    destino,
                    (codigo, motivo, quem_recusa_antes),
                )?;
                if let Some(id) = &id {
                    sem_o_fim_da_troca(antes, id)?;
                }
                Ok(exercida)
            }
            Espera::Encerrado => {
                let exercida =
                    encerrado_no_ponto_sem_volta(&c, desde, desde_o_pedido, trocas, destino)?;
                if let Some(id) = &id {
                    sem_o_fim_da_troca(antes, id)?;
                }
                Ok(exercida)
            }
            Espera::Troca => {
                // A troca de sempre: o `ola` roda e sai com o código dele,
                // e o fluxo de quem era ponta acaba com ela.
                esperar_ate(|| trocas_feitas() == trocas + 1, TETO_DA_MALHA)
                    .map_err(|_| "sem mudanca no meio, a troca nao aconteceu")?;
                trocou = true;
                esperar_ate(
                    || {
                        linhas_do_programa(desde, &format!("processo encerrou com codigo {SAIDA}"))
                            == 1
                    },
                    TETO_DA_MALHA,
                )
                .map_err(|_| "o programa trocado nao terminou")?;
                if let Some(id) = &id {
                    fim_gravado(antes, id, "o programa mudou; ida 0; volta 0; desc 0")?;
                }
                // A decisão que trocou não tem execução: a imagem nova rodou,
                // e é o que ela permitiu.
                let (decisoes, execucoes) =
                    registros_de_troca_para(desde_o_pedido, &destino.caminho());
                match tirar_as_adiadas(&decisoes, &execucoes, c.fio()) {
                    Some((_, (_, d), [])) if d.codigo == Codigo::Allow => Ok(true),
                    _ => {
                        crate::log_error!(
                            "teste",
                            "decisoes {:?}; execucoes {:?}",
                            decisoes,
                            execucoes
                        );
                        Err("a troca sem mudanca no meio nao e so a decisao que permitiu")
                    }
                }
            }
        }
    })();
    pausa::soltar();
    desfazer(&c);
    // O C que trocou já saiu, com o `ola`; o encerrado no meio já morreu;
    // o que não trocou segue o `fluxos`, e sai pelo fim pedido.
    let mut pontas: Vec<&Ponta> = a.iter().collect();
    if !trocou && crate::fios::processo(c.fio()).map(|(_, p)| p) == Some(c.p.programa) {
        pontas.push(&c);
    }
    let exercida = r.as_ref().is_ok_and(|e| *e);
    encerrar_todas(r.map(|_| ()), &pontas).map(|_| exercida)
}

/// As duas rodadas de um caso — quem é ponta de fluxo, e quem não é —, cada
/// uma repetida até a volta pausada passar pela decisão de novo, no máximo
/// [`TENTATIVAS`] vezes (ver "A volta pausada adiada", no começo).
fn as_duas_rodadas(
    nome: &str,
    autoridade: impl Fn() -> Autoridade,
    destino: Destino,
    mudar: fn(&Ponta) -> Resultado,
    espera: Espera,
    desfazer: fn(&Ponta),
) -> Resultado {
    let Some(nucleo) = nucleo_da_pausa() else {
        crate::log_info!(
            "teste",
            "um nucleo so: a pausa no handler precisa de outro nucleo ({})",
            nome
        );
        return Ok(());
    };
    com_os_fluxos(|| {
        for ponta in [true, false] {
            let como = if ponta { "ponta de fluxo" } else { "sem fluxo" };
            let mut exercida = false;
            for tentativa in 1..=TENTATIVAS {
                crate::log_info!("teste", "troca: {}, {}, rodada {}", nome, como, tentativa);
                if rodada(
                    autoridade(),
                    ponta,
                    nucleo,
                    destino,
                    mudar,
                    espera,
                    desfazer,
                )? {
                    exercida = true;
                    break;
                }
            }
            if !exercida {
                crate::log_error!(
                    "teste",
                    "troca: {}, {}: as {} rodadas tiveram a volta pausada adiada",
                    nome,
                    como,
                    TENTATIVAS
                );
                return Err("nenhuma rodada passou pela decisao de novo no ponto sem volta");
            }
        }
        Ok(())
    })
}

/// O caso de controle: a mesma troca, parada no meio pela mesma pausa, sem
/// mudança nenhuma — a decisão de novo permite, e a troca acontece como
/// sempre: o `ola` roda e sai com o código dele, o fluxo de quem era ponta
/// acaba com `o programa mudou`, e a decisão do gate não tem execução.
pub(in crate::testes) fn troca_sem_mudanca_no_meio_a_troca_acontece() -> Resultado {
    as_duas_rodadas(
        "sem mudanca",
        || pessoa("bia", 340).1,
        Destino::Ola,
        |_| Ok(()),
        Espera::Troca,
        |_| {},
    )
}

/// A chave do agente que lançou o processo, revogada no meio da troca —
/// depois da decisão do gate, com a imagem preparada —: a decisão de novo
/// não acha o agente nem o papel dele, e recusa como o gate recusaria
/// (`DENY_ROLE`, "sem papel, ou papel que a politica nao tem"). Para quem é
/// ponta, a revogação toma a ordem das gravações e acaba o fluxo antes de
/// a troca a tomar; a troca a toma depois, e vê a revogação. Sem a decisão
/// de novo, a imagem nova rodava com o `ALLOW` de antes. O registro volta
/// ao da imagem no fim — também quando uma rodada falha antes da revogação.
pub(in crate::testes) fn troca_a_chave_revogada_no_meio_nao_troca_a_imagem() -> Resultado {
    fn agente() -> Autoridade {
        let chave = sigilo::publica_de(&SEMENTE_DO_AGENTE);
        crate::identidade::registrar_agente_de_teste(chave, "troca-k", "operador");
        Autoridade::Sessao {
            sessao: 3,
            chave: Some(chave),
        }
    }
    let r = as_duas_rodadas(
        "a chave revogada",
        agente,
        Destino::Ola,
        |_| {
            crate::identidade::revogar(&sigilo::publica_de(&SEMENTE_DO_AGENTE))
                .map(|_| ())
                .map_err(|_| "a chave do agente nao foi revogada")
        },
        Espera::Recusa(
            Codigo::DenyRole,
            "sem papel, ou papel que a politica nao tem",
            Antes::Gate,
        ),
        |_| {},
    );
    crate::identidade::esquecer_registrados();
    r
}

/// A rodada da ponta com a volta pausada adiada à força — a ordem tomada
/// sem esperar ouve, uma vez, que está com outro fio
/// (`persistencia::com_outro_uma_vez_de_teste`), armado no meio, depois de
/// `mudar` —: a volta seguinte recusa pelo gate, sem a decisão de novo, e a
/// rodada não conta como exercitada (ver "A volta pausada adiada", no
/// começo). Contada, uma troca sem a decisão de novo passaria por ela.
fn a_volta_adiada_nao_conta(
    nome: &str,
    autoridade: Autoridade,
    mudar: fn(&Ponta) -> Resultado,
    espera: Espera,
    desfazer: fn(&Ponta),
) -> Resultado {
    let Some(nucleo) = nucleo_da_pausa() else {
        return Ok(());
    };
    crate::log_info!("teste", "troca: {}, ponta de fluxo, adiada a forca", nome);
    let r = com_os_fluxos(|| {
        let exercida = rodada(
            autoridade,
            true,
            nucleo,
            Destino::Ola,
            |c| {
                mudar(c)?;
                crate::persistencia::com_outro_uma_vez_de_teste(c.fio());
                Ok(())
            },
            espera,
            desfazer,
        )?;
        if exercida {
            return Err("a rodada com a volta pausada adiada contou como a decisao de novo");
        }
        Ok(())
    });
    crate::persistencia::desarmar_com_outro_de_teste();
    r
}

/// A política nova sem `process.run`, no meio da troca: a decisão de novo
/// recusa como o gate recusaria (`DENY_PERMISSION`, "o papel nao tem a
/// permissao"), e a imagem de antes segue. E a rodada da ponta com a volta
/// pausada adiada à força — a seguinte recusa pelo gate — não conta como a
/// decisão de novo ([`a_volta_adiada_nao_conta`]): é o que faz o caso
/// reprovar a troca sem ela também quando o coletor adia a volta. A
/// política volta no fim.
pub(in crate::testes) fn troca_a_politica_nova_no_meio_nao_troca_a_imagem() -> Resultado {
    static ANTES: crate::trava::Mutex<Option<politica::Politica>> = crate::trava::Mutex::new(None);
    fn sem_o_process_run(_: &Ponta) -> Resultado {
        let sem = crate::testes::politica_sem_o_process_run()?;
        crate::autorizacao::restaurar_politica(sem);
        Ok(())
    }
    fn a_de_antes(_: &Ponta) {
        if let Some(p) = crate::arch::sem_interrupcoes(|| ANTES.lock().clone()) {
            crate::autorizacao::restaurar_politica(p);
        }
    }
    const RECUSA: Espera = Espera::Recusa(
        Codigo::DenyPermission,
        "o papel nao tem a permissao",
        Antes::Gate,
    );
    let antes = crate::autorizacao::com_politica(|p| p.clone());
    crate::arch::sem_interrupcoes(|| *ANTES.lock() = Some(antes.clone()));
    let r = as_duas_rodadas(
        "a politica nova",
        || pessoa("bia", 341).1,
        Destino::Ola,
        sem_o_process_run,
        RECUSA,
        a_de_antes,
    )
    .and_then(|_| {
        a_volta_adiada_nao_conta(
            "a politica nova",
            pessoa("bia", 341).1,
            sem_o_process_run,
            RECUSA,
            a_de_antes,
        )
    });
    crate::arch::sem_interrupcoes(|| *ANTES.lock() = None);
    crate::autorizacao::restaurar_politica(antes);
    r
}

/// O processo isolado no meio da troca — o `process.isolate` de outro
/// núcleo, depois da decisão do gate —: a decisão de novo recusa como o
/// gate recusaria (`DENY_CONTAINED`, "processo isolado"). O isolamento é
/// solto no fim, para o processo sair pelo fim pedido.
pub(in crate::testes) fn troca_o_processo_isolado_no_meio_nao_troca_a_imagem() -> Resultado {
    let (codigo, motivo) = crate::contencao::PROCESSO_ISOLADO;
    as_duas_rodadas(
        "o processo isolado",
        || pessoa("bia", 342).1,
        Destino::Ola,
        |c| {
            if crate::contencao::conter(&Alvo::Processo(c.fio())).is_ok_and(|f| f.mudou) {
                Ok(())
            } else {
                Err("o processo da troca nao foi isolado")
            }
        },
        Espera::Recusa(codigo, motivo, Antes::Gate),
        |c| {
            let _ = crate::contencao::soltar(&Alvo::Processo(c.fio()));
        },
    )
}

/// O achado 1 do adversário do lote A: a confiança no editor da imagem
/// nova, tirada no meio da troca. O `fluxos` de uma pessoa operadora troca
/// para o `ola` selado pelo editor do caso, gravado no armazém — o papel
/// confia nele, e a conferência do código, no começo da chamada, passa —;
/// parado no meio, a política perde a confiança do operador no editor, e a
/// troca segue. A decisão de novo pergunta a confiança no editor da imagem
/// nova, pela regra da conferência, e recusa: `DENY_POLICY`, "o papel nao
/// confia no editor caso" — o editor no motivo, como a conferência o grava
/// —, o processo ouve `NEGADO` e segue com a imagem de antes. Sem a
/// pergunta, o código de um editor que o papel já não confia entrava no
/// processo, com os descritores dele. Adiada a volta pausada, a seguinte
/// recusa na conferência do código (`EDITOR_NAO_CONFIADO`), e a rodada se
/// repete. A confiança volta entre as rodadas, e a política e o registro
/// de editores, no fim.
pub(in crate::testes) fn troca_a_confianca_no_editor_da_imagem_nova_tirada_no_meio_nao_troca_a_imagem()
-> Resultado {
    static DO_CASO: crate::trava::Mutex<Option<politica::Politica>> =
        crate::trava::Mutex::new(None);
    let motivo = politica::procedencia::nao_confiado(crate::testes::EDITOR_DO_CASO.1);
    let r = crate::testes::com_editores_do_caso(|| {
        let ola = crate::testes::ola_da_imagem()?;
        crate::testes::gravar_codigo(
            SELADO,
            &sigilo::codigo::selar(&ola, &crate::testes::EDITOR_DO_CASO.0),
        )?;
        let do_caso = crate::autorizacao::com_politica(|p| p.clone());
        crate::arch::sem_interrupcoes(|| *DO_CASO.lock() = Some(do_caso));
        as_duas_rodadas(
            "a confianca no editor da imagem nova",
            || pessoa("bia", 343).1,
            Destino::Selado,
            |_| {
                let sem = crate::testes::politica_sem_a_confianca_do_operador()?;
                crate::autorizacao::restaurar_politica(sem);
                Ok(())
            },
            Espera::Recusa(
                Codigo::DenyPolicy,
                &motivo,
                Antes::Conferencia(EDITOR_NAO_CONFIADO),
            ),
            |_| {
                if let Some(p) = crate::arch::sem_interrupcoes(|| DO_CASO.lock().clone()) {
                    crate::autorizacao::restaurar_politica(p);
                }
            },
        )
    });
    crate::arch::sem_interrupcoes(|| *DO_CASO.lock() = None);
    r
}

/// O achado 2 do adversário do lote A: o fim pedido sem o isolamento — o
/// `process.terminate` com o teto de isolados cheio, que só pede o fim —,
/// no meio da troca. O gate não recusa quem não foi isolado, e a decisão de
/// novo não perguntava se quem chama ainda pede: a troca acontecia, os
/// fluxos da ponta acabavam com "o programa mudou", e o processo morria na
/// volta sem rodar a imagem nova. Agora ela pergunta, como a reconfirmação
/// dos comandos, e recusa: nada trocado, a execução da decisão
/// `DENY_CONTAINED`, "processo encerrado", o processo morto na volta da
/// chamada e, na rodada da ponta, nenhum fim "o programa mudou".
pub(in crate::testes) fn troca_o_fim_pedido_sem_o_isolamento_no_meio_nao_troca_a_imagem()
-> Resultado {
    as_duas_rodadas(
        "o fim pedido sem o isolamento",
        || pessoa("bia", 344).1,
        Destino::Ola,
        |c| {
            crate::fios::pedir_termino(c.fio())
                .map_err(|_| "o fim do processo da troca nao foi pedido")?;
            if crate::contencao::contido(&Alvo::Processo(c.fio())) {
                return Err("o processo da troca foi isolado com o fim pedido");
            }
            Ok(())
        },
        Espera::Encerrado,
        |_| {},
    )
}

/// A decisão de outro fio, que o fio do caso decide de novo.
static DE_OUTRO_FIO: crate::trava::Mutex<Option<crate::autorizacao::DecisaoDoProcesso>> =
    crate::trava::Mutex::new(None);

/// O que a decisão de novo respondeu no outro fio: zero, nada ainda; um,
/// permitiu; dois, recusou como fora de uma decisão autorizada; três,
/// outra coisa.
static DE_NOVO_NO_OUTRO_FIO: AtomicU8 = AtomicU8::new(0);

/// O fio do caso: decide de novo a decisão de outro fio, diz o que ouviu,
/// e acaba.
extern "C" fn decidir_de_novo_no_outro_fio(_: u64) -> ! {
    let decisao = crate::arch::sem_interrupcoes(|| DE_OUTRO_FIO.lock().take());
    let ouviu = match decisao.map(|d| d.reconfirmar_com_o_codigo(None)) {
        Some(Ok(())) => 1,
        Some(Err((Codigo::Error, m))) if m == "fora de um comando autorizado" => 2,
        _ => 3,
    };
    DE_NOVO_NO_OUTRO_FIO.store(ouviu, SeqCst);
    crate::fios::terminar()
}

/// O ponto 7 do adversário do lote A: a decisão de novo é presa à decisão
/// que o gate tomou — o fio que a pediu e o `ALLOW`. Pelo fio da suíte,
/// com a autoridade do sistema e sem programa, como o gate decide uma
/// chamada de sistema:
///
/// - o controle: a decisão permitida, feita de novo no mesmo fio, permite;
/// - a mesma decisão, feita de novo por outro fio — com a mesma autoridade,
///   que a conta do gate permitiria —, é recusada como fora de uma decisão
///   autorizada (`ERROR`, "fora de um comando autorizado");
/// - a decisão recusada — sob a política sem `process.run` —, feita de novo
///   com a política de volta, que a conta do gate agora permitiria, continua
///   recusada, pelo mesmo par: uma recusa não vira permissão por ter sido
///   feita de novo depois.
pub(in crate::testes) fn troca_a_decisao_de_novo_so_vale_no_fio_que_decidiu_e_sobre_um_allow()
-> Resultado {
    use crate::autorizacao::autorizar_processo_com_decisao as decidir;
    use politica::Permissao;
    let fora = (Codigo::Error, String::from("fora de um comando autorizado"));
    let caminho = Destino::Ola.caminho();
    let de_novo = |d: &crate::autorizacao::DecisaoDoProcesso| {
        d.reconfirmar_com_o_codigo(None)
            .map_err(|(c, m)| (c, m.into_owned()))
    };
    // O controle, no mesmo fio.
    let d = decidir(Permissao::ProcessRun, &caminho, "process.exec");
    if !d.codigo().permite() {
        return Err("o gate nao permitiu a chamada do fio da suite");
    }
    if de_novo(&d) != Ok(()) {
        crate::log_error!("teste", "{:?}", de_novo(&d));
        return Err("a decisao permitida, feita de novo no mesmo fio, nao permitiu");
    }
    // A mesma decisão, por outro fio.
    DE_NOVO_NO_OUTRO_FIO.store(0, SeqCst);
    crate::arch::sem_interrupcoes(|| *DE_OUTRO_FIO.lock() = Some(d));
    crate::fios::criar("teste-de-novo-noutro-fio", decidir_de_novo_no_outro_fio, 0)?;
    esperar_cedendo(|| DE_NOVO_NO_OUTRO_FIO.load(SeqCst) != 0, TETO_DA_MALHA)
        .map_err(|_| "o outro fio nao decidiu de novo")?;
    crate::arch::sem_interrupcoes(|| *DE_OUTRO_FIO.lock() = None);
    match DE_NOVO_NO_OUTRO_FIO.load(SeqCst) {
        2 => {}
        1 => return Err("a decisao de outro fio foi feita de novo, e permitiu"),
        _ => return Err("a decisao de outro fio foi recusada por outro motivo"),
    }
    // A recusa, feita de novo com a política de volta.
    let sem = crate::testes::politica_sem_o_process_run()?;
    let recusada = crate::testes::com_a_politica(sem, || {
        Ok(decidir(Permissao::ProcessRun, &caminho, "process.exec"))
    })?;
    if recusada.codigo().permite() {
        return Err("a politica sem process.run permitiu a chamada");
    }
    if !decidir(Permissao::ProcessRun, &caminho, "process.exec")
        .codigo()
        .permite()
    {
        return Err("com a politica de volta, o gate nao permitiu a chamada");
    }
    if de_novo(&recusada) != Err(fora) {
        crate::log_error!("teste", "{:?}", de_novo(&recusada));
        return Err("a decisao recusada, feita de novo, nao continuou recusada");
    }
    Ok(())
}
