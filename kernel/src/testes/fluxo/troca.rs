//! Os casos da decisão de novo no ponto sem volta do `exec` — o F4 do
//! adversário do AE-1.
//!
//! O `executar` decide `process.run` sobre o caminho antes de ler o
//! arquivo; depois lê, confere o código e prepara a imagem — o tempo do
//! arquivo —, e só então troca. Uma revogação, uma política nova ou uma
//! contenção que chegue nesse meio não parava a troca, que seguia com o
//! `ALLOW` de antes. Agora a decisão é feita de novo imediatamente antes de
//! trocar (`autorizacao::DecisaoDoProcesso::reconfirmar`): quem é ponta de
//! fluxo, com a ordem das gravações na mão — tomada sem esperar —; quem não
//! é, sem ela, e sem esperá-la. Recusada, nada se troca: o processo segue
//! com a imagem dele, ouve `NEGADO`, e a recusa vai à auditoria como a
//! execução da decisão do gate, em nome de quem ela decidiu.
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

use super::*;
use crate::contencao::Alvo;
use crate::usuario::pausa_da_troca_de_teste as pausa;

/// O que a troca devolve recusada pela decisão de novo: o `NEGADO` do gate.
const NEGADO: i64 = protocolo::usuario::erro::NEGADO;

/// Um passo que o `fluxos` não conhece: ele diz que não conhece, e segue
/// escutando — a prova de que a imagem de antes ainda roda.
const PASSO_DESCONHECIDO: i64 = 99;

/// A chave do agente do caso da revogação.
const SEMENTE_DO_AGENTE: [u8; 32] = [0x6e; 32];

/// O núcleo onde o processo para, se há um além do da suíte.
fn nucleo_da_pausa() -> Option<usize> {
    crate::testes::outro_nucleo()
}

/// A troca de `c` para o `ola`, parada no meio pela pausa: decidida, com a
/// imagem preparada, antes do ponto sem volta. Lá, a suíte faz `mudar` — de
/// fora, como outro fio —, e solta. Devolve de quando o passo começou.
fn trocar_com_a_pausa(
    c: &Ponta,
    nucleo: usize,
    mudar: impl FnOnce() -> Resultado,
) -> Result<u64, &'static str> {
    if !crate::fios::fixar(c.fio(), Some(nucleo)) {
        return Err("o processo nao foi preso a outro nucleo");
    }
    pausa::armar(c.fio());
    let desde = match c.ditar(TROCAR, 0) {
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

/// A recusa da troca de `c`, pela decisão de novo, com `codigo` e
/// `motivo`, depois de `desde_o_pedido`: a chamada devolveu `NEGADO`; nada
/// foi trocado; o processo segue vivo com a imagem de antes, e ela ainda
/// roda; e a decisão do gate tem a execução dela com o código e o motivo da
/// recusa, gravada em nome de quem ela decidiu e citando-a.
///
/// Quem é ponta pode ter voltas adiadas antes — o coletor com a ordem entre
/// a conferência do começo da chamada e a tomada sem esperar (a CI 437) —,
/// cada uma dita pela execução dela; e a volta depois de uma adiada decide
/// de novo pelo gate, que já vê a mudança e recusa ele mesmo: as duas são a
/// mesma recusa, feita onde a janela acaba.
fn recusada_no_ponto_sem_volta(
    c: &Ponta,
    desde: u64,
    desde_o_pedido: u64,
    trocas: u64,
    codigo: Codigo,
    motivo: &str,
) -> Resultado {
    let devolveu = dito_na_malha(desde, "fluxos: trocar devolveu ")?;
    if devolveu != format!("{NEGADO}") {
        crate::log_error!("teste", "trocar devolveu {}", devolveu);
        return Err("a troca recusada no ponto sem volta nao devolveu NEGADO");
    }
    if trocas_feitas() != trocas {
        return Err("a troca recusada no ponto sem volta trocou a imagem");
    }
    if crate::fios::processo(c.fio()).map(|(_, p)| p) != Some(c.p.programa) {
        return Err("o processo da troca recusada nao segue com a imagem de antes");
    }
    let (decisoes, execucoes) = registros_de_troca(desde_o_pedido);
    let dita = match tirar_as_adiadas(&decisoes, &execucoes, c.fio()) {
        // A decisão de novo, no ponto sem volta: a execução da última
        // decisão, que permitiu, com a recusa.
        Some((adiadas, (numero, d), [e])) if d.codigo == Codigo::Allow => {
            crate::log_info!(
                "teste",
                "a decisao {} recusada no ponto sem volta, depois de {} voltas adiadas",
                numero,
                adiadas
            );
            execucao_da_troca(e, codigo, c.fio(), motivo, *numero)
                && em_nome_da_decisao(d, &e.1, motivo, *numero)
        }
        // A volta depois de uma adiada: o gate recusou ele mesmo.
        Some((adiadas, (_, d), [])) if adiadas >= 1 => {
            crate::log_info!(
                "teste",
                "o gate recusou depois de {} voltas adiadas: {}",
                adiadas,
                d.detalhe
            );
            d.codigo == codigo && d.detalhe.ends_with(motivo)
        }
        _ => false,
    };
    if !dita {
        crate::log_error!(
            "teste",
            "decisoes {:?}; execucoes {:?}",
            decisoes,
            execucoes
        );
        return Err("a recusa da troca nao esta na auditoria como a execucao da decisao");
    }
    // A imagem de antes ainda roda: o `fluxos` escuta e responde.
    let desde = c.ditar(PASSO_DESCONHECIDO, 0)?;
    let dito = dito_na_malha(desde, "fluxos: passo desconhecido ")?;
    if dito != format!("{PASSO_DESCONHECIDO}") {
        return Err("o processo da troca recusada nao segue respondendo");
    }
    Ok(())
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
/// com `autoridade`, para a troca de C no meio, faz `mudar` e, se
/// `recusa`, confere a recusa com o código e o motivo dela; sem, confere a
/// troca de sempre. `desfazer` roda no fim, também quando a rodada falha.
fn rodada(
    autoridade: Autoridade,
    ponta: bool,
    nucleo: usize,
    mudar: impl FnOnce(&Ponta) -> Resultado,
    recusa: Option<(Codigo, &str)>,
    desfazer: impl FnOnce(&Ponta),
) -> Resultado {
    let antes = crate::autorizacao::ultimo_registro();
    let a = if ponta {
        Some(Ponta::lancar(autoridade)?)
    } else {
        None
    };
    let c = match Ponta::lancar(autoridade) {
        Ok(c) => c,
        Err(e) => return encerrar_todas(Err(e), &a.iter().collect::<Vec<_>>()),
    };
    let mut trocou = false;
    let r = (|| -> Resultado {
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
        let desde = trocar_com_a_pausa(&c, nucleo, || mudar(&c))?;
        match recusa {
            Some((codigo, motivo)) => {
                recusada_no_ponto_sem_volta(&c, desde, desde_o_pedido, trocas, codigo, motivo)?;
                if let Some(id) = &id {
                    sem_o_fim_da_troca(antes, id)?;
                }
                Ok(())
            }
            None => {
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
                let (decisoes, execucoes) = registros_de_troca(desde_o_pedido);
                match tirar_as_adiadas(&decisoes, &execucoes, c.fio()) {
                    Some((_, (_, d), [])) if d.codigo == Codigo::Allow => Ok(()),
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
    // O C que trocou já saiu, com o `ola`; o que não trocou segue o
    // `fluxos`, e sai pelo fim pedido.
    let mut pontas: Vec<&Ponta> = a.iter().collect();
    if !trocou && crate::fios::processo(c.fio()).map(|(_, p)| p) == Some(c.p.programa) {
        pontas.push(&c);
    }
    encerrar_todas(r, &pontas)
}

/// As duas rodadas de um caso: quem é ponta de fluxo, e quem não é.
fn as_duas_rodadas(
    nome: &str,
    autoridade: impl Fn() -> Autoridade,
    mudar: fn(&Ponta) -> Resultado,
    recusa: Option<(Codigo, &str)>,
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
            crate::log_info!(
                "teste",
                "troca: {}, {}",
                nome,
                if ponta { "ponta de fluxo" } else { "sem fluxo" }
            );
            rodada(autoridade(), ponta, nucleo, mudar, recusa, desfazer)?;
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
        |_| Ok(()),
        None,
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
        |_| {
            crate::identidade::revogar(&sigilo::publica_de(&SEMENTE_DO_AGENTE))
                .map(|_| ())
                .map_err(|_| "a chave do agente nao foi revogada")
        },
        Some((
            Codigo::DenyRole,
            "sem papel, ou papel que a politica nao tem",
        )),
        |_| {},
    );
    crate::identidade::esquecer_registrados();
    r
}

/// A política nova sem `process.run`, no meio da troca: a decisão de novo
/// recusa como o gate recusaria (`DENY_PERMISSION`, "o papel nao tem a
/// permissao"), e a imagem de antes segue. A política volta no fim.
pub(in crate::testes) fn troca_a_politica_nova_no_meio_nao_troca_a_imagem() -> Resultado {
    static ANTES: crate::trava::Mutex<Option<politica::Politica>> = crate::trava::Mutex::new(None);
    let antes = crate::autorizacao::com_politica(|p| p.clone());
    crate::arch::sem_interrupcoes(|| *ANTES.lock() = Some(antes.clone()));
    let r = as_duas_rodadas(
        "a politica nova",
        || pessoa("bia", 341).1,
        |_| {
            let sem = crate::testes::politica_sem_o_process_run()?;
            crate::autorizacao::restaurar_politica(sem);
            Ok(())
        },
        Some((Codigo::DenyPermission, "o papel nao tem a permissao")),
        |_| {
            if let Some(p) = crate::arch::sem_interrupcoes(|| ANTES.lock().clone()) {
                crate::autorizacao::restaurar_politica(p);
            }
        },
    );
    crate::arch::sem_interrupcoes(|| *ANTES.lock() = None);
    crate::autorizacao::restaurar_politica(antes);
    r
}

/// O processo isolado no meio da troca — o `process.isolate` de outro
/// núcleo, depois da decisão do gate —: a decisão de novo recusa como o
/// gate recusaria (`DENY_CONTAINED`, "processo isolado"). O isolamento é
/// solto no fim, para o processo sair pelo fim pedido.
pub(in crate::testes) fn troca_o_processo_isolado_no_meio_nao_troca_a_imagem() -> Resultado {
    as_duas_rodadas(
        "o processo isolado",
        || pessoa("bia", 342).1,
        |c| {
            if crate::contencao::conter(&Alvo::Processo(c.fio())).is_ok_and(|f| f.mudou) {
                Ok(())
            } else {
                Err("o processo da troca nao foi isolado")
            }
        },
        Some(crate::contencao::PROCESSO_ISOLADO),
        |c| {
            let _ = crate::contencao::soltar(&Alvo::Processo(c.fio()));
        },
    )
}
