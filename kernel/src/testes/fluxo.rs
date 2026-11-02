//! Os casos dos fluxos da malha — o DN-2, na modalidade local.
//!
//! Um fluxo é um canal ordenado de bytes, nos dois sentidos, entre dois
//! processos do mesmo titular: aberto contra um endpoint da malha, aceito
//! pelo dono dele, e cada escrita e cada leitura decididas pelo gate. A
//! suíte lança o programa `fluxos` — uma ponta que oferece a intenção e
//! atende passos — e pede, também, **como** cada processo, pela mesma
//! função do gate: o que ela confere é o que um programa ouviria.

use super::{
    ContasDoPlano, NaMalha, Resultado, TETO_DA_MALHA, com_a_malha, de_base64, decisao_do_envelope,
    desfecho_na_malha, diretorios_acima, dito_na_malha, encerrar_na_malha, encerrar_o_correio,
    energia_entregue, esperar_ate, esperar_cedendo, fs_numero, fs_ok, fs_pedir, fs_texto,
    gravado_na_malha, linhas_do_programa, nada_gravado_com, passo_na_malha, pedido_rpc,
    pessoa_da_sessao, politica_sem, politica_trocada, registros_depois, simulado_na_malha,
    sistema_aqui, sistema_no_armazem, versao_no_armazem,
};
use crate::agent::json::Json;
use crate::autorizacao::{Autoridade, Chamador};
use crate::pessoas::Console;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst};
use politica::Codigo;

pub(in crate::testes) mod par;

/// A intenção que o `fluxos` oferece.
const INTENCAO: &str = "imagem.compartilhar";

/// O código com que o `fluxos` sai no fim pedido.
const SAIDA: i64 = 61;

/// Os passos do `fluxos`.
const MANDAR: i64 = 1;
const RECEBER: i64 = 2;
const TROCAR: i64 = 3;
const BIFURCAR: i64 = 4;

/// O byte `i` do padrão determinístico — o mesmo do programa.
fn padrao(i: usize) -> u8 {
    ((i * 7 + 3) % 251) as u8
}

/// O FNV-1a de 64 bits — o mesmo do programa.
pub(in crate::testes) fn resumo(bytes: impl Iterator<Item = u8>) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Uma ponta de fluxo em execução: o programa `fluxos`, o endpoint que ele
/// abriu e o canal por onde a suíte dita os passos.
struct Ponta {
    p: NaMalha,
    endpoint: String,
    canal: String,
}

impl Ponta {
    /// Lança o `fluxos` com `autoridade` e espera ele dizer o endpoint.
    fn lancar(autoridade: Autoridade) -> Result<Ponta, &'static str> {
        let (p, endpoint) = NaMalha::lancar("fluxos", autoridade, "fluxos: pronto ")?;
        let canal = format!("teste-fluxos-{}", p.fio);
        Ok(Ponta { p, endpoint, canal })
    }

    /// O chamador que pede como este processo.
    fn quem(&self) -> Chamador {
        self.p.chamador()
    }

    fn fio(&self) -> u64 {
        self.p.fio
    }

    /// Dita o passo `a`, com `b`, sem esperar o que ele diz: devolve de
    /// quando o passo começou.
    fn ditar(&self, a: i64, b: i64) -> Result<u64, &'static str> {
        use protocolo::usuario::evento::{Evento, tipo};
        let desde = crate::log::total_emitidos();
        crate::eventos::publicar(
            &self.canal,
            Evento {
                tipo: tipo::ACAO,
                a,
                b,
                ..Default::default()
            },
        )
        .map_err(|_| "o canal da ponta nao recebeu o passo")?;
        Ok(desde)
    }

    /// Pede o fim do programa e espera ele sair.
    fn encerrar(&self) -> Resultado {
        encerrar_na_malha(&self.canal, SAIDA)
    }
}

/// Encerra as pontas, todas — também quando uma falha —, e devolve a
/// primeira falha, depois da do caso.
fn encerrar_todas(r: Resultado, pontas: &[&Ponta]) -> Resultado {
    let fins: Vec<Resultado> = pontas.iter().map(|p| p.encerrar()).collect();
    r?;
    fins.into_iter().collect()
}

/// Uma pessoa operadora numa sessão de teste: a sessão e a autoridade.
fn pessoa(nome: &str, terminal: u16) -> (crate::pessoas::IdSessao, Autoridade) {
    let sessao = crate::pessoas::sessao_de_teste(Console::Terminal(terminal), nome, "operador");
    (sessao, Autoridade::Pessoa { sessao })
}

/// O chamador de um processo vivo, como o kernel o tem agora.
pub(in crate::testes) fn chamador_de(fio: u64) -> Option<Chamador> {
    let (autoridade, programa) = crate::fios::processo(fio)?;
    Some(Chamador::Processo {
        fio,
        autoridade,
        programa,
    })
}

/// `stream.open` de `quem` ao `endpoint`, com a intenção dos casos.
pub(in crate::testes) fn abrir(quem: Chamador, endpoint: &str) -> String {
    fs_pedir(
        quem,
        "stream.open",
        &format!(r#"{{"endpoint":"{endpoint}","intent":"{INTENCAO}"}}"#),
    )
}

/// `stream.accept` de `quem` no `endpoint`, sem esperar.
pub(in crate::testes) fn aceitar(quem: Chamador, endpoint: &str) -> String {
    fs_pedir(
        quem,
        "stream.accept",
        &format!(r#"{{"endpoint":"{endpoint}"}}"#),
    )
}

/// `stream.write` de `quem`, com `dados` no anexo — como um processo
/// manda.
pub(in crate::testes) fn escrever(quem: Chamador, id: &str, dados: &[u8]) -> String {
    crate::nativo::responder_com_anexo_de_teste(
        quem,
        &pedido_rpc("stream.write", &format!(r#"{{"stream":"{id}"}}"#)),
        dados,
    )
}

/// `stream.read` de `quem`, até `max` bytes, sem esperar.
pub(in crate::testes) fn ler(quem: Chamador, id: &str, max: usize) -> String {
    fs_pedir(
        quem,
        "stream.read",
        &format!(r#"{{"stream":"{id}","max":{max}}}"#),
    )
}

/// Um comando que só nomeia o fluxo: `stream.finish`, `stream.close`,
/// `stream.status`.
pub(in crate::testes) fn sobre(quem: Chamador, metodo: &str, id: &str) -> String {
    fs_pedir(quem, metodo, &format!(r#"{{"stream":"{id}"}}"#))
}

/// Os bytes e o fim de uma leitura que passou.
pub(in crate::testes) fn lidos(r: &str) -> Option<(Vec<u8>, bool)> {
    if !fs_ok(r) {
        return None;
    }
    let bytes = de_base64(&fs_texto(r, "content")?)?;
    let fim = Json(r.as_bytes())
        .member("result")?
        .member("end")?
        .as_bool()?;
    Some((bytes, fim))
}

/// A leitura de `quem` devolve `dados` e `fim`.
pub(in crate::testes) fn ler_e_conferir(
    quem: Chamador,
    id: &str,
    max: usize,
    dados: &[u8],
    fim: bool,
    erro: &'static str,
) -> Resultado {
    let r = ler(quem, id, max);
    match lidos(&r) {
        Some((d, f)) if d == dados && f == fim => Ok(()),
        _ => {
            crate::log_error!(
                "teste",
                "esperava {} bytes e fim {}: {}",
                dados.len(),
                fim,
                r
            );
            Err(erro)
        }
    }
}

/// A escrita passou e pôs `n` bytes.
pub(in crate::testes) fn escrito(r: &str, n: u64, erro: &'static str) -> Resultado {
    if fs_ok(r) && fs_numero(r, "written") == Some(n) {
        return Ok(());
    }
    crate::log_error!("teste", "esperava {} escritos: {}", n, r);
    Err(erro)
}

/// O comando passou.
pub(in crate::testes) fn feito(r: &str, erro: &'static str) -> Resultado {
    if fs_ok(r) {
        return Ok(());
    }
    crate::log_error!("teste", "{}", r);
    Err(erro)
}

/// O desfecho é `codigo` — o do gate, ou o do comando.
pub(in crate::testes) fn recusado(r: &str, codigo: &str, erro: &'static str) -> Resultado {
    if desfecho_na_malha(r) == codigo {
        return Ok(());
    }
    crate::log_error!("teste", "esperava {}: {}", codigo, r);
    Err(erro)
}

/// O comando foi autorizado pelo gate e recusado pelo fluxo, com `codigo`
/// e o motivo `motivo`.
pub(in crate::testes) fn recusado_com(
    r: &str,
    codigo: &str,
    motivo: &str,
    erro: &'static str,
) -> Resultado {
    if decisao_do_envelope(r) == "ALLOW"
        && !fs_ok(r)
        && fs_texto(r, "code").as_deref() == Some(codigo)
        && fs_texto(r, "error").as_deref() == Some(motivo)
    {
        return Ok(());
    }
    crate::log_error!("teste", "esperava {} `{}`: {}", codigo, motivo, r);
    Err(erro)
}

/// Um fluxo de `a` ao endpoint de `b`, aceito por `b`: o id.
fn aberto(a: &Ponta, b: &Ponta) -> Result<String, &'static str> {
    let id = pedido(a.quem(), b)?;
    let r = aceitar(b.quem(), &b.endpoint);
    if !fs_ok(&r) || fs_texto(&r, "stream").as_deref() != Some(id.as_str()) {
        crate::log_error!("teste", "{}", r);
        return Err("o dono do endpoint nao aceitou o fluxo pedido");
    }
    Ok(id)
}

/// Um pedido de `quem` ao endpoint de `b`, que fica esperando o aceite: o
/// id.
fn pedido(quem: Chamador, b: &Ponta) -> Result<String, &'static str> {
    let r = abrir(quem, &b.endpoint);
    if !fs_ok(&r) || fs_texto(&r, "state").as_deref() != Some("pending") {
        crate::log_error!("teste", "{}", r);
        return Err("o pedido de fluxo nao foi aceito pelo gate");
    }
    fs_texto(&r, "stream").ok_or("o pedido de fluxo nao trouxe o id")
}

/// O estado do fluxo `id` para `quem`: o `state` e o `reason`.
pub(in crate::testes) fn estado(quem: Chamador, id: &str) -> (Option<String>, Option<String>) {
    let r = sobre(quem, "stream.status", id);
    (fs_texto(&r, "state"), fs_texto(&r, "reason"))
}

/// O fluxo `id` acabou, com o detalhe `detalhe` gravado em nome do kernel
/// depois de `antes` — espera o registro: o encerramento grava fora da
/// trava da tabela.
pub(in crate::testes) fn fim_gravado(antes: u64, id: &str, detalhe: &str) -> Resultado {
    let recurso = format!("fluxo:{id}");
    esperar_ate(
        || {
            !registros_depois(antes, |e| {
                e.metodo == "stream.end"
                    && e.recurso == recurso
                    && e.codigo == Codigo::Allow
                    && e.agente == "kernel"
                    && e.detalhe == detalhe
            })
            .is_empty()
        },
        TETO_DA_MALHA,
    )
    .map_err(|_| {
        crate::log_error!("teste", "esperava o fim de {}: `{}`", id, detalhe);
        "o fim do fluxo nao foi gravado com o motivo e as contas"
    })
}

/// O fluxo `id` acabou com um motivo que começa com `motivo`.
pub(in crate::testes) fn fim_gravado_com(antes: u64, id: &str, motivo: &str) -> Resultado {
    let recurso = format!("fluxo:{id}");
    esperar_ate(
        || {
            !registros_depois(antes, |e| {
                e.metodo == "stream.end" && e.recurso == recurso && e.detalhe.starts_with(motivo)
            })
            .is_empty()
        },
        TETO_DA_MALHA,
    )
    .map_err(|_| {
        crate::log_error!("teste", "esperava o fim de {} com `{}`", id, motivo);
        "o fim do fluxo nao foi gravado com o motivo"
    })
}

/// Nada vivo na tabela — espera o que um gancho encerra fora da trava.
pub(in crate::testes) fn nada_vivo(erro: &'static str) -> Resultado {
    esperar_ate(|| crate::fluxo::contagem() == (0, 0), TETO_DA_MALHA).map_err(|_| {
        crate::log_error!("teste", "vivos: {:?}", crate::fluxo::contagem());
        erro
    })
}

/// Roda `f` com as tabelas da malha e dos fluxos vazias, e as deixa vazias
/// e coerentes; as pessoas e os agentes da suíte voltam ao que a imagem
/// diz.
fn com_os_fluxos(f: impl FnOnce() -> Resultado) -> Resultado {
    crate::fluxo::esvaziar_de_teste();
    com_a_malha(|| {
        let r = f();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        let coerente = crate::fluxo::coerente();
        crate::fluxo::esvaziar_de_teste();
        r?;
        if !coerente {
            return Err("a tabela de fluxos ficou incoerente");
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// FS01 — o caminho inteiro, entre programas
// ---------------------------------------------------------------------------

/// O caminho inteiro, entre dois programas: o `fluxos` B aceita no
/// endpoint dele; o A procura quem oferece a intenção, abre, manda 1 MiB,
/// termina o sentido dele e lê tudo o que volta; o B lê tudo, diz de quem
/// veio — o programa e o resumo da imagem que o kernel conferiu —, devolve
/// os mesmos bytes e termina. Os resumos conferem nos dois sentidos, o
/// fluxo acaba `concluido` com as contas na auditoria, e nada fica vivo.
pub(super) fn fluxo_entre_programas() -> Resultado {
    const N: usize = 1024 * 1024;
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 301);
        let antes = crate::autorizacao::ultimo_registro();
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            // Quem recebe grava fora do papel: nada fica no armazém.
            let desde = b.ditar(RECEBER, 1)?;
            a.ditar(MANDAR, (N / 1024) as i64)?;
            let recebi = dito_na_malha(desde, "fluxos: recebi ")?;
            let devolvi = dito_na_malha(desde, "fluxos: devolvi ")?;
            let mandei = dito_na_malha(desde, "fluxos: mandei ")?;
            let h = resumo((0..N).map(padrao));
            if recebi != format!("{N} {h:016x} de fluxos {}", a.p.resumo8()) {
                crate::log_error!("teste", "{}", recebi);
                return Err("quem recebeu nao leu os bytes, ou nao viu o programa que abriu");
            }
            if devolvi != format!("{N}") || mandei != format!("{N} voltou {N} {h:016x}") {
                crate::log_error!("teste", "{} {}", devolvi, mandei);
                return Err("o sentido de volta nao trouxe os mesmos bytes");
            }
            fim_gravado(
                antes,
                &primeiro_id_aberto(antes)?,
                &format!("concluido; ida {N}; volta {N}; desc 0"),
            )?;
            nada_vivo("o fluxo concluido ficou vivo")
        })();
        encerrar_todas(r, &[&a, &b])
    })
}

/// O id do primeiro fluxo aberto depois de `antes`, pelo registro da
/// execução do aceite.
fn primeiro_id_aberto(antes: u64) -> Result<String, &'static str> {
    registros_depois(antes, |e| {
        e.metodo == "stream.accept"
            && e.recurso.starts_with("fluxo:")
            && e.detalhe.contains("aberto; versao")
    })
    .first()
    .and_then(|(_, e)| {
        e.recurso
            .strip_prefix("fluxo:")
            .and_then(|r| r.split(" ; ").next())
            .map(String::from)
    })
    .ok_or("o aceite nao foi gravado com o fluxo")
}

// ---------------------------------------------------------------------------
// FS02 — terminar um sentido
// ---------------------------------------------------------------------------

/// Cada sentido termina sozinho: quem terminou não escreve mais, quem lê
/// recebe o resto e depois o fim; o outro sentido continua, e o estado diz
/// cada um. Os dois terminados e lidos até o fim: o fluxo acaba
/// `concluido`, e a lápide diz isso às duas pontas.
pub(super) fn fluxo_terminar_um_sentido() -> Resultado {
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 302);
        let antes = crate::autorizacao::ultimo_registro();
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let id = aberto(&a, &b)?;
            escrito(&escrever(a.quem(), &id, b"ida-1"), 5, "a ida nao entrou")?;
            escrito(
                &escrever(b.quem(), &id, b"volta-1"),
                7,
                "a volta nao entrou",
            )?;
            feito(
                &sobre(a.quem(), "stream.finish", &id),
                "quem abriu nao terminou o sentido dele",
            )?;
            recusado_com(
                &escrever(a.quem(), &id, b"ida-2"),
                "CONFLICT",
                "o sentido ja acabou",
                "o sentido terminado aceitou mais bytes",
            )?;
            ler_e_conferir(
                b.quem(),
                &id,
                100,
                b"ida-1",
                true,
                "quem le nao recebeu o resto e o fim",
            )?;
            ler_e_conferir(b.quem(), &id, 100, b"", true, "o fim nao continuou dito")?;
            // O outro sentido continua.
            escrito(
                &escrever(b.quem(), &id, b"volta-2"),
                7,
                "o outro sentido parou",
            )?;
            ler_e_conferir(
                a.quem(),
                &id,
                100,
                b"volta-1volta-2",
                false,
                "a volta nao chegou na ordem",
            )?;
            let r = sobre(a.quem(), "stream.status", &id);
            if fs_texto(&r, "state").as_deref() != Some("open")
                || fs_texto(&r, "sending").as_deref() != Some("finished")
                || fs_texto(&r, "receiving").as_deref() != Some("open")
                || fs_numero(&r, "written") != Some(5)
                || fs_numero(&r, "read") != Some(14)
                || !r.contains(&format!(
                    r#""program":"fluxos","digest":"{}"#,
                    sigilo::hex(&b.p.resumo())
                ))
            {
                crate::log_error!("teste", "{}", r);
                return Err("o estado nao disse cada sentido e a outra ponta");
            }
            feito(
                &sobre(b.quem(), "stream.finish", &id),
                "quem aceitou nao terminou",
            )?;
            ler_e_conferir(a.quem(), &id, 100, b"", true, "o fim da volta nao chegou")?;
            fim_gravado(antes, &id, "concluido; ida 5; volta 14; desc 0")?;
            nada_vivo("o fluxo concluido ficou vivo")?;
            // A lápide diz o fim a cada ponta — numa operação, ou no
            // estado —, e sai quando as duas souberam: depois disso, o id
            // não é mais de ninguém.
            recusado_com(
                &ler(a.quem(), &id, 10),
                "CONFLICT",
                "concluido",
                "o fluxo concluido ainda foi lido",
            )?;
            if estado(a.quem(), &id) != (Some("closed".into()), Some("concluido".into()))
                || estado(b.quem(), &id) != (Some("closed".into()), Some("concluido".into()))
            {
                return Err("a lapide nao disse o fim as duas pontas");
            }
            recusado(
                &sobre(a.quem(), "stream.status", &id),
                "DENY_RESOURCE",
                "a lapide ficou depois de as duas pontas saberem",
            )
        })();
        encerrar_todas(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// FS03 — fechar com dados pendentes
// ---------------------------------------------------------------------------

/// `close` com dados nos dois buffers: o que quem fechou já escreveu
/// continua legível pela outra ponta, até o fim; o que estava para ele ler
/// sai zerado e entra na conta dos descartados. Quem fechou não lê nem
/// escreve mais, e a outra ponta não escreve num sentido que ninguém lê. A
/// auditoria grava as contas — e o motivo.
pub(super) fn fluxo_fechar_com_dados_pendentes() -> Resultado {
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 303);
        let antes = crate::autorizacao::ultimo_registro();
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let id = aberto(&a, &b)?;
            let ida: Vec<u8> = (0..3000).map(padrao).collect();
            let volta: Vec<u8> = (0..2000).map(|i| padrao(i + 11)).collect();
            escrito(&escrever(a.quem(), &id, &ida), 3000, "a ida nao entrou")?;
            escrito(&escrever(b.quem(), &id, &volta), 2000, "a volta nao entrou")?;
            ler_e_conferir(
                b.quem(),
                &id,
                1000,
                &ida[..1000],
                false,
                "o comeco da ida nao chegou",
            )?;
            feito(
                &sobre(a.quem(), "stream.close", &id),
                "quem abriu nao fechou",
            )?;
            if estado(a.quem(), &id) != (Some("closed".into()), Some("fechado pela ponta".into())) {
                return Err("quem fechou nao viu o fluxo fechado para ele");
            }
            for r in [
                ler(a.quem(), &id, 10),
                escrever(a.quem(), &id, b"x"),
                sobre(a.quem(), "stream.close", &id),
            ] {
                recusado_com(
                    &r,
                    "CONFLICT",
                    "fechado pela ponta",
                    "quem fechou ainda usou o fluxo",
                )?;
            }
            recusado_com(
                &escrever(b.quem(), &id, b"x"),
                "CONFLICT",
                "fechado pela ponta",
                "a outra ponta escreveu num sentido que ninguem le",
            )?;
            ler_e_conferir(
                b.quem(),
                &id,
                4096,
                &ida[1000..],
                true,
                "o que quem fechou escreveu nao continuou legivel ate o fim",
            )?;
            fim_gravado(
                antes,
                &id,
                "fechado pela ponta; ida 3000; volta 2000; desc 2000",
            )?;
            nada_vivo("o fluxo fechado ficou vivo")
        })();
        encerrar_todas(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// FS04 — sem a permissão
// ---------------------------------------------------------------------------

/// O gate decide cada lado: o manifesto que não declara `fabric.stream`, o
/// papel que não a tem, a intenção fora da política e a de forma inválida,
/// a sessão que não é processo, a política que tira a permissão — cada um
/// com o código dele. O endpoint que não oferece a intenção, e o dono que
/// não receberia fluxo — o `correio`, que só declara `fabric.offer` —,
/// são a mesma recusa de um endpoint que não existe. E quem aceita no
/// endpoint de outro processo não alcança nada.
pub(super) fn fluxo_sem_a_permissao() -> Resultado {
    com_os_fluxos(|| {
        let (sessao, bia) = pessoa("bia", 304);
        let dora = crate::pessoas::sessao_de_teste(Console::Terminal(305), "dora", "observador");
        let b = Ponta::lancar(bia)?;
        let (correio, do_correio) = NaMalha::lancar("correio", bia, "correio: endpoint ")?;
        let antes_da_politica = crate::autorizacao::com_politica(|p| p.clone());
        let r = (|| -> Resultado {
            let quem_abre = simulado_na_malha(7_910_401, bia, "fabric.stream");
            let abrir_com = |quem: Chamador, endpoint: &str, intencao: &str| {
                fs_pedir(
                    quem,
                    "stream.open",
                    &format!(r#"{{"endpoint":"{endpoint}","intent":"{intencao}"}}"#),
                )
            };
            let casos = [
                // O manifesto que não declara, e o papel que não tem.
                (
                    abrir(
                        simulado_na_malha(7_910_402, bia, "fabric.offer fabric.send"),
                        &b.endpoint,
                    ),
                    "DENY_PERMISSION",
                ),
                (
                    abrir(
                        simulado_na_malha(
                            7_910_403,
                            Autoridade::Pessoa { sessao: dora },
                            "fabric.stream",
                        ),
                        &b.endpoint,
                    ),
                    "DENY_PERMISSION",
                ),
                // A intenção fora da política, e as de forma inválida.
                (
                    abrir_com(quem_abre, &b.endpoint, "imagem.apagar"),
                    "DENY_RESOURCE",
                ),
                (abrir_com(quem_abre, &b.endpoint, "imagem.*"), "intent"),
                (abrir_com(quem_abre, &b.endpoint, "Imagem.ver"), "intent"),
                // Só um processo abre e aceita: a sessão da pessoa, não.
                (
                    abrir(Chamador::Pessoa(sessao), &b.endpoint),
                    "DENY_PERMISSION",
                ),
                (
                    aceitar(Chamador::Pessoa(sessao), &b.endpoint),
                    "DENY_PERMISSION",
                ),
                // A intenção que o endpoint não oferece: um endpoint que não
                // existe.
                (
                    abrir_com(quem_abre, &b.endpoint, "pdf.anotar"),
                    "DENY_RESOURCE",
                ),
                // O dono que não receberia fluxo: o mesmo.
                (abrir(quem_abre, &do_correio), "DENY_RESOURCE"),
                // Aceitar no endpoint de outro processo do titular: o gate
                // não o resolve para quem pede. E o programa que não
                // declara `fabric.stream` nem chega ao recurso.
                (aceitar(quem_abre, &b.endpoint), "DENY_RESOURCE"),
                (aceitar(correio.chamador(), &b.endpoint), "DENY_PERMISSION"),
            ];
            for (i, (r, esperado)) in casos.iter().enumerate() {
                if desfecho_na_malha(r) != *esperado {
                    crate::log_error!("teste", "caso {}: {} e nao {}", i, r, esperado);
                    return Err("um lado do fluxo nao foi decidido com o codigo dele");
                }
            }
            if crate::fluxo::contagem() != (0, 0) {
                return Err("uma abertura recusada deixou um pedido");
            }
            // A política sem `fabric.stream`: nem abre, nem aceita.
            let id = pedido(quem_abre, &b)?;
            politica_sem("fabric.stream");
            let abrir_sem = abrir(quem_abre, &b.endpoint);
            let aceitar_sem = aceitar(b.quem(), &b.endpoint);
            crate::autorizacao::restaurar_politica(antes_da_politica.clone());
            recusado(
                &abrir_sem,
                "DENY_PERMISSION",
                "a politica sem a permissao abriu",
            )?;
            recusado(
                &aceitar_sem,
                "DENY_PERMISSION",
                "a politica sem a permissao aceitou",
            )?;
            if crate::fluxo::contagem() != (1, 1) {
                return Err("a recusa do aceite mexeu no pedido");
            }
            // Com a política de volta, o pedido continua lá — o abridor
            // simulado não existe, e o aceite o recusa pela reconfirmação.
            let r = aceitar(b.quem(), &b.endpoint);
            if !fs_ok(&r) || !r.contains(r#""stream":null"#) {
                crate::log_error!("teste", "{}", r);
                return Err("o pedido de quem nao existe foi aceito");
            }
            if estado(quem_abre, &id).1.as_deref() != Some("quem abriu nao pode mais") {
                return Err("o pedido de quem nao existe nao acabou pela reconfirmacao");
            }
            Ok(())
        })();
        crate::autorizacao::restaurar_politica(antes_da_politica);
        let fim_do_correio = encerrar_o_correio(bia, &do_correio);
        let r = encerrar_todas(r, &[&b]);
        r.and(fim_do_correio)
    })
}

// ---------------------------------------------------------------------------
// FS05 — o de outro, o forjado, o de outra época
// ---------------------------------------------------------------------------

/// O id de um fluxo não é capacidade: o processo de outro titular, outro
/// processo do mesmo titular, um id forjado, um de outra época e um
/// malformado ouvem o mesmo `DENY_RESOURCE` do gate, em cada comando, com o
/// mesmo motivo gravado — e o fluxo de verdade segue intacto.
pub(super) fn fluxo_o_id_nao_e_capacidade() -> Resultado {
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 306);
        let (_, caio) = pessoa("caio", 307);
        let antes = crate::autorizacao::ultimo_registro();
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let c = Ponta::lancar(caio)?;
        let r = (|| -> Resultado {
            let id = aberto(&a, &b)?;
            escrito(
                &escrever(a.quem(), &id, b"de verdade"),
                10,
                "a escrita do dono nao entrou",
            )?;
            let (epoca, n) = id.split_once(':').ok_or("o id nao tem epoca")?;
            let n: u64 = n.parse().map_err(|_| "o id nao tem numero")?;
            let forjado = format!("{epoca}:{}", n + 1000);
            let de_outra_epoca = format!("0011223344556677:{n}");
            let outro = simulado_na_malha(7_910_501, bia, "fabric.stream");
            let tentativas: [(Chamador, &str); 5] = [
                (c.quem(), &id),
                (outro, &id),
                (a.quem(), &forjado),
                (a.quem(), &de_outra_epoca),
                (a.quem(), "nada"),
            ];
            for (quem, alvo) in tentativas {
                let pedidos = [
                    escrever(quem, alvo, b"x"),
                    ler(quem, alvo, 10),
                    sobre(quem, "stream.finish", alvo),
                    sobre(quem, "stream.close", alvo),
                    sobre(quem, "stream.status", alvo),
                ];
                for r in &pedidos {
                    if decisao_do_envelope(r) != "DENY_RESOURCE" {
                        crate::log_error!("teste", "{}: {}", alvo, r);
                        return Err("um id que nao e de quem pede resolveu no gate");
                    }
                }
            }
            // Abrir no endpoint de outro titular, ou aceitar nele: o mesmo.
            recusado(
                &abrir(c.quem(), &b.endpoint),
                "DENY_RESOURCE",
                "outro titular abriu no endpoint",
            )?;
            recusado(
                &aceitar(c.quem(), &b.endpoint),
                "DENY_RESOURCE",
                "outro titular aceitou no endpoint",
            )?;
            // Cada recusa do gate grava o mesmo motivo exato.
            let recusas = registros_depois(antes, |e| {
                e.metodo.starts_with("stream.") && e.codigo == Codigo::DenyResource
            });
            let fora = recusas
                .iter()
                .filter(|(_, e)| {
                    e.metodo != "stream.open"
                        && e.metodo != "stream.accept"
                        && !e.detalhe.contains("o fluxo nao existe para quem pede")
                })
                .count();
            if recusas.len() < 25 || fora != 0 {
                crate::log_error!(
                    "teste",
                    "{} recusas, {} com outro motivo",
                    recusas.len(),
                    fora
                );
                return Err("as recusas de um id alheio nao gravaram o mesmo motivo");
            }
            // O fluxo de verdade segue: nada do que os outros pediram o
            // tocou.
            if crate::fluxo::contagem() != (1, 0) {
                return Err("um pedido alheio mexeu no fluxo");
            }
            ler_e_conferir(
                b.quem(),
                &id,
                100,
                b"de verdade",
                false,
                "o fluxo de verdade perdeu os bytes",
            )
        })();
        encerrar_todas(r, &[&a, &b, &c])
    })
}

// ---------------------------------------------------------------------------
// FS06 — o prazo do aceite e o endpoint que fecha
// ---------------------------------------------------------------------------

/// O pedido que ninguém aceita vence no prazo do aceite — e só nele —,
/// gravado com o motivo; quem abriu vê `prazo do aceite`. O endpoint que
/// fecha com pedidos na fila os encerra, e a espera de quem aceitava por
/// ele acaba com ele.
pub(super) fn fluxo_o_prazo_do_aceite_e_o_endpoint() -> Resultado {
    use crate::rede::espera::Desfecho;
    use politica::fluxo::PRAZO_DO_ACEITE_MS;
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 308);
        let antes = crate::autorizacao::ultimo_registro();
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let id = pedido(a.quem(), &b)?;
            let agora = crate::tempo::uptime_ms();
            crate::fluxo::vencer_de_teste(agora + PRAZO_DO_ACEITE_MS - 2_000);
            if crate::fluxo::contagem() != (1, 1) {
                return Err("o pedido venceu antes do prazo do aceite");
            }
            crate::fluxo::vencer_de_teste(agora + PRAZO_DO_ACEITE_MS + 1);
            nada_vivo("o pedido nao venceu no prazo do aceite")?;
            fim_gravado(antes, &id, "prazo do aceite; ida 0; volta 0; desc 0")?;
            if estado(a.quem(), &id) != (Some("closed".into()), Some("prazo do aceite".into())) {
                return Err("quem abriu nao viu o prazo do aceite");
            }
            let r = aceitar(b.quem(), &b.endpoint);
            if !fs_ok(&r) || !r.contains(r#""stream":null"#) {
                crate::log_error!("teste", "{}", r);
                return Err("o pedido vencido foi aceito");
            }
            // A espera do aceite: armada sem pedido, e acaba com um.
            let linha = pedido_rpc(
                "stream.accept",
                &format!(r#"{{"endpoint":"{}","wait":5000}}"#, b.endpoint),
            );
            let Err(espera) = crate::nativo::responder_suspensivel_de_teste(b.quem(), &linha)
            else {
                return Err("o aceite sem pedido nao esperou");
            };
            if espera.conferir(None).is_some() {
                return Err("a espera do aceite acabou sem pedido");
            }
            let id = pedido(a.quem(), &b)?;
            if espera.conferir(None) != Some(Desfecho::Chegou) {
                return Err("o pedido nao acabou a espera do aceite");
            }
            drop(espera);
            // O endpoint fecha com o pedido na fila: o pedido acaba.
            feito(
                &fs_pedir(
                    b.quem(),
                    "fabric.withdraw",
                    &format!(r#"{{"endpoint":"{}"}}"#, b.endpoint),
                ),
                "o dono nao retirou o endpoint",
            )?;
            nada_vivo("o pedido sobreviveu ao endpoint")?;
            fim_gravado(antes, &id, "o endpoint fechou; ida 0; volta 0; desc 0")?;
            if estado(a.quem(), &id).1.as_deref() != Some("o endpoint fechou") {
                return Err("quem abriu nao viu o endpoint fechado");
            }
            // A espera de quem aceita num endpoint que fecha: acaba.
            let r = fs_pedir(
                b.quem(),
                "fabric.offer",
                &format!(r#"{{"intent":"{INTENCAO}"}}"#),
            );
            let outro = fs_texto(&r, "endpoint").ok_or("o dono nao abriu outro endpoint")?;
            let linha = pedido_rpc(
                "stream.accept",
                &format!(r#"{{"endpoint":"{outro}","wait":5000}}"#),
            );
            let Err(espera) = crate::nativo::responder_suspensivel_de_teste(b.quem(), &linha)
            else {
                return Err("o aceite no endpoint novo nao esperou");
            };
            feito(
                &fs_pedir(
                    b.quem(),
                    "fabric.withdraw",
                    &format!(r#"{{"endpoint":"{outro}"}}"#),
                ),
                "o dono nao retirou o endpoint novo",
            )?;
            if espera.conferir(None) != Some(Desfecho::Sumiu) {
                return Err("a espera do aceite nao acabou com o endpoint");
            }
            Ok(())
        })();
        encerrar_todas(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// FS07 — a reconfirmação na abertura efetiva
// ---------------------------------------------------------------------------

/// O processo que o gancho de teste isola.
static ISOLAR: AtomicU64 = AtomicU64::new(0);

/// O gancho: isola [`ISOLAR`] dentro da ordem, uma vez.
fn isolar_no_meio() {
    let _ = crate::contencao::conter(&crate::contencao::Alvo::Processo(ISOLAR.load(SeqCst)));
    crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
}

/// O gancho: a política sem `fabric.stream`, uma vez.
fn sem_fluxo_no_meio() {
    politica_sem("fabric.stream");
    crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
}

/// A abertura efetiva é o aceite, e ele reconfirma as duas decisões: quem
/// abriu e foi isolado entre o pedido e o aceite — antes, ou no meio do
/// aceite, dentro da ordem — não abre nada, e o pedido acaba com `quem
/// abriu nao pode mais`; a política que muda no meio recusa o aceitante, e
/// o pedido continua na fila até um aceite que a política deixe.
pub(super) fn fluxo_a_reconfirmacao_no_aceite() -> Resultado {
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 309);
        let antes = crate::autorizacao::ultimo_registro();
        let antes_da_politica = crate::autorizacao::com_politica(|p| p.clone());
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let alvo = crate::contencao::Alvo::Processo(a.fio());
        let r = (|| -> Resultado {
            for no_meio in [false, true] {
                let id = pedido(a.quem(), &b)?;
                if no_meio {
                    ISOLAR.store(a.fio(), SeqCst);
                    crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(isolar_no_meio));
                } else {
                    crate::contencao::conter(&alvo)?;
                }
                let r = aceitar(b.quem(), &b.endpoint);
                crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
                let _ = crate::contencao::soltar(&alvo);
                if !fs_ok(&r) || !r.contains(r#""stream":null"#) {
                    crate::log_error!("teste", "{}", r);
                    return Err("o pedido de quem foi isolado abriu");
                }
                fim_gravado(
                    antes,
                    &id,
                    "quem abriu nao pode mais; ida 0; volta 0; desc 0",
                )?;
                if estado(a.quem(), &id).1.as_deref() != Some("quem abriu nao pode mais") {
                    return Err("quem abriu nao viu a reconfirmacao recusar");
                }
            }
            nada_vivo("um pedido recusado no aceite ficou vivo")?;
            // A política muda no meio do aceite: o aceitante é recusado, e
            // o pedido fica.
            let id = pedido(a.quem(), &b)?;
            crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(sem_fluxo_no_meio));
            let r = aceitar(b.quem(), &b.endpoint);
            crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
            crate::autorizacao::restaurar_politica(antes_da_politica.clone());
            if decisao_do_envelope(&r) != "ALLOW" || desfecho_na_malha(&r) != "DENY_PERMISSION" {
                crate::log_error!("teste", "{}", r);
                return Err("a politica mudada no meio nao recusou o aceite");
            }
            if crate::fluxo::contagem() != (1, 1) {
                return Err("o aceite recusado mexeu no pedido");
            }
            let r = aceitar(b.quem(), &b.endpoint);
            if fs_texto(&r, "stream").as_deref() != Some(id.as_str()) {
                crate::log_error!("teste", "{}", r);
                return Err("o pedido nao abriu com a politica de volta");
            }
            Ok(())
        })();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        crate::autorizacao::restaurar_politica(antes_da_politica);
        let _ = crate::contencao::soltar(&alvo);
        encerrar_todas(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// FS08 — o plano de dados
// ---------------------------------------------------------------------------

/// Ler e escrever por um fluxo aberto, vivo e de quem pede são o plano de
/// dados: decididos e gravados, sem gastar a ficha da taxa. O pedido sobre
/// o fluxo de outro, o pedido sobre um fluxo que ainda não abriu e o fecho
/// seguem o caminho deles. Com o caminho da auditoria cheio, a escrita com
/// `wait` é adiada — nem decidida, nem executada — e passa quando ele anda;
/// sem `wait`, gasta a ficha.
pub(super) fn fluxo_o_plano_de_dados() -> Resultado {
    use crate::oleoduto::TETO;
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 310);
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let id = aberto(&a, &b)?;
            let antes = ContasDoPlano::agora();
            escrito(
                &escrever(a.quem(), &id, b"plano"),
                5,
                "a escrita nao entrou",
            )?;
            ler_e_conferir(
                b.quem(),
                &id,
                16,
                b"plano",
                false,
                "a leitura nao trouxe a escrita",
            )?;
            let d = ContasDoPlano::desde(antes);
            if d.dados != 2 || d.controle != 0 || d.pela_taxa != 0 {
                crate::log_error!("teste", "{:?}", d);
                return Err("ler e escrever por um fluxo aberto nao foram o plano de dados");
            }
            // O fluxo de outro processo: a ficha.
            let antes = ContasDoPlano::agora();
            let r = escrever(
                simulado_na_malha(7_910_801, bia, "fabric.stream"),
                &id,
                b"x",
            );
            recusado(&r, "DENY_RESOURCE", "o fluxo de outro processo foi escrito")?;
            let d = ContasDoPlano::desde(antes);
            if d.controle != 1 || d.dados != 0 {
                crate::log_error!("teste", "{:?}", d);
                return Err("o pedido sobre o fluxo de outro nao gastou a ficha");
            }
            // O fluxo que ainda não abriu: a ficha, e o conflito.
            let pendente = pedido(a.quem(), &b)?;
            let antes = ContasDoPlano::agora();
            recusado_com(
                &escrever(a.quem(), &pendente, b"x"),
                "CONFLICT",
                "o fluxo ainda nao abriu",
                "o pedido pendente foi escrito",
            )?;
            let d = ContasDoPlano::desde(antes);
            if d.controle != 1 || d.dados != 0 {
                crate::log_error!("teste", "{:?}", d);
                return Err("o pedido sobre um fluxo pendente nao gastou a ficha");
            }
            // O fecho: o plano dele.
            let antes = ContasDoPlano::agora();
            feito(&sobre(a.quem(), "stream.finish", &id), "o fecho nao passou")?;
            if ContasDoPlano::desde(antes).fecho != 1 {
                return Err("terminar o sentido nao foi o plano do fecho");
            }
            // O caminho da auditoria cheio: a escrita com `wait` é adiada. O
            // atraso simulado é a cabeça menos o consumidor: com poucos
            // registros desde o boot — a suíte filtrada —, a cabeça fica
            // abaixo do teto, e o caminho nunca enche.
            while crate::autorizacao::ultimo_registro() < TETO + 16 {
                crate::autorizacao::auditar_do_kernel("teste.caminho", "", Codigo::Allow, "");
            }
            let cabeca = crate::autorizacao::ultimo_registro();
            crate::oleoduto::consumidor_de_teste(Some(cabeca.saturating_sub(TETO)));
            let r = (|| -> Resultado {
                let antes = ContasDoPlano::agora();
                let linha = pedido_rpc(
                    "stream.write",
                    &format!(r#"{{"stream":"{id}","wait":2000}}"#),
                );
                let espera = match crate::nativo::responder_suspensivel_com_anexo_de_teste(
                    b.quem(),
                    &linha,
                    b"adiada",
                ) {
                    Err(espera) => espera,
                    Ok(r) => {
                        crate::log_error!("teste", "{}", r);
                        return Err("a escrita com o caminho cheio nao foi adiada");
                    }
                };
                let d = ContasDoPlano::desde(antes);
                if d.adiados != 1 || d.dados != 0 {
                    crate::log_error!("teste", "{:?}", d);
                    return Err("a escrita adiada foi decidida");
                }
                ler_e_conferir(
                    a.quem(),
                    &id,
                    100,
                    b"",
                    false,
                    "a escrita adiada foi executada",
                )?;
                // O caminho anda: a espera acaba, e a reexecução passa.
                crate::oleoduto::consumidor_de_teste(Some(crate::autorizacao::ultimo_registro()));
                if espera.conferir(None).is_none() {
                    return Err("o caminho andou e a espera nao acabou");
                }
                drop(espera);
                let r = crate::nativo::responder_com_anexo_de_teste(b.quem(), &linha, b"adiada");
                escrito(&r, 6, "a reexecucao da escrita adiada nao passou")?;
                // Sem `wait`, com o caminho cheio: a ficha.
                let cabeca = crate::autorizacao::ultimo_registro();
                crate::oleoduto::consumidor_de_teste(Some(cabeca.saturating_sub(TETO)));
                let antes = ContasDoPlano::agora();
                escrito(
                    &escrever(b.quem(), &id, b"sem"),
                    3,
                    "a escrita sem wait nao passou",
                )?;
                let d = ContasDoPlano::desde(antes);
                if d.pela_taxa != 1 || d.controle != 1 {
                    crate::log_error!("teste", "{:?}", d);
                    return Err("a escrita sem wait com o caminho cheio nao gastou a ficha");
                }
                Ok(())
            })();
            crate::oleoduto::consumidor_de_teste(None);
            r?;
            ler_e_conferir(
                a.quem(),
                &id,
                100,
                b"adiadasem",
                false,
                "a volta nao trouxe as escritas",
            )
        })();
        crate::oleoduto::consumidor_de_teste(None);
        encerrar_todas(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// FS09 — a contrapressão e as esperas
// ---------------------------------------------------------------------------

/// O buffer cheio não aceita mais: sem `wait`, zero bytes; com `wait`, o
/// escritor espera — uma espera por sentido — até o leitor abrir espaço. O
/// leitor sem nada espera um dado, o fim, ou o aborto; e quem aceita
/// espera um pedido.
pub(super) fn fluxo_a_contrapressao() -> Resultado {
    use crate::fluxo::Aguardo;
    use crate::rede::espera::Desfecho;
    use politica::fluxo::BUFFER_DO_SENTIDO;
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 311);
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let id = aberto(&a, &b)?;
            let n = crate::fluxo::numero_de_teste(&id).ok_or("o id nao e deste boot")?;
            let cheio: Vec<u8> = (0..BUFFER_DO_SENTIDO).map(padrao).collect();
            escrito(
                &escrever(a.quem(), &id, &cheio),
                BUFFER_DO_SENTIDO as u64,
                "o buffer nao coube inteiro",
            )?;
            escrito(
                &escrever(a.quem(), &id, b"mais"),
                0,
                "o buffer cheio aceitou mais",
            )?;
            let linha = pedido_rpc(
                "stream.write",
                &format!(r#"{{"stream":"{id}","wait":5000}}"#),
            );
            let Err(espera) =
                crate::nativo::responder_suspensivel_com_anexo_de_teste(a.quem(), &linha, b"mais")
            else {
                return Err("o escritor com o buffer cheio nao esperou");
            };
            let aguardo = Aguardo::Escrever {
                id: n,
                fio: a.fio(),
            };
            if !crate::fluxo::tem_espera_de_teste(aguardo) || espera.conferir(None).is_some() {
                return Err("a espera de escrita nao ficou armada");
            }
            let segunda =
                crate::nativo::responder_suspensivel_com_anexo_de_teste(a.quem(), &linha, b"mais")
                    .map_err(|_| "a segunda espera no mesmo sentido suspendeu")?;
            recusado(
                &segunda,
                "CONFLICT",
                "a segunda espera no mesmo sentido nao foi recusada",
            )?;
            ler_e_conferir(
                b.quem(),
                &id,
                1000,
                &cheio[..1000],
                false,
                "o leitor nao leu",
            )?;
            if espera.conferir(None) != Some(Desfecho::Coube) {
                return Err("o espaco aberto nao acabou a espera do escritor");
            }
            drop(espera);
            if crate::fluxo::tem_espera_de_teste(aguardo) {
                return Err("a espera largada nao desarmou");
            }
            escrito(
                &crate::nativo::responder_com_anexo_de_teste(a.quem(), &linha, b"mais"),
                4,
                "a reexecucao nao escreveu o que coube",
            )?;
            let mut resto = cheio[1000..].to_vec();
            resto.extend_from_slice(b"mais");
            ler_e_conferir(
                b.quem(),
                &id,
                BUFFER_DO_SENTIDO,
                &resto,
                false,
                "o resto nao veio na ordem",
            )?;
            // O leitor sem nada espera um dado.
            let linha = pedido_rpc(
                "stream.read",
                &format!(r#"{{"stream":"{id}","wait":5000}}"#),
            );
            let leitura = Aguardo::Ler {
                id: n,
                fio: b.fio(),
            };
            let Err(espera) = crate::nativo::responder_suspensivel_de_teste(b.quem(), &linha)
            else {
                return Err("o leitor sem nada nao esperou");
            };
            if !crate::fluxo::tem_espera_de_teste(leitura) {
                return Err("a espera de leitura nao ficou armada");
            }
            escrito(
                &escrever(a.quem(), &id, b"acorda"),
                6,
                "a escrita que acorda nao entrou",
            )?;
            if espera.conferir(None) != Some(Desfecho::Chegou) {
                return Err("o dado nao acabou a espera do leitor");
            }
            drop(espera);
            ler_e_conferir(
                b.quem(),
                &id,
                100,
                b"acorda",
                false,
                "o dado que acordou nao veio",
            )?;
            // O fim também acorda.
            let Err(espera) = crate::nativo::responder_suspensivel_de_teste(b.quem(), &linha)
            else {
                return Err("o leitor sem nada nao esperou de novo");
            };
            feito(
                &sobre(a.quem(), "stream.finish", &id),
                "o escritor nao terminou",
            )?;
            if espera.conferir(None) != Some(Desfecho::Chegou) {
                return Err("o fim nao acabou a espera do leitor");
            }
            drop(espera);
            ler_e_conferir(
                b.quem(),
                &id,
                100,
                b"",
                true,
                "o fim nao veio depois da espera",
            )?;
            // O aborto: a espera sai com o fluxo.
            let Err(espera) = crate::nativo::responder_suspensivel_de_teste(
                a.quem(),
                &pedido_rpc(
                    "stream.read",
                    &format!(r#"{{"stream":"{id}","wait":5000}}"#),
                ),
            ) else {
                return Err("quem abriu nao esperou a volta");
            };
            crate::fluxo::canal_acabou(politica::mensagens::Canal::Processo(b.fio()));
            if espera.conferir(None) != Some(Desfecho::Sumiu) {
                return Err("o aborto nao acabou a espera");
            }
            drop(espera);
            nada_vivo("o fluxo abortado ficou vivo")
        })();
        encerrar_todas(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// FS10 — as cotas
// ---------------------------------------------------------------------------

/// As cotas, cada uma com o código e o motivo dela, sem nada criado: o
/// quinto fluxo de um processo, o quinto pedido num endpoint, o nono de um
/// titular, o décimo sétimo da máquina — e o quinto fluxo aberto de quem
/// aceita, cujo pedido fica na fila. Quem abre aqui é simulado: o pedido
/// não precisa de processo vivo, e o aceite não chega a ele.
pub(super) fn fluxo_as_cotas() -> Resultado {
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 312);
        let (_, caio) = pessoa("caio", 313);
        let (_, edu) = pessoa("edu", 314);
        let b = Ponta::lancar(bia)?;
        let c = Ponta::lancar(bia)?;
        let d = Ponta::lancar(caio)?;
        let e = Ponta::lancar(caio)?;
        let f = Ponta::lancar(edu)?;
        let r = (|| -> Resultado {
            let simulado =
                |n: u64, quem: Autoridade| simulado_na_malha(7_911_000 + n, quem, "fabric.stream");
            let cota = |r: &str, motivo: &str| -> Resultado {
                if decisao_do_envelope(r) == "ALLOW"
                    && fs_texto(r, "code").as_deref() == Some("DENY_POLICY")
                    && fs_texto(r, "error").as_deref() == Some(motivo)
                {
                    return Ok(());
                }
                crate::log_error!("teste", "esperava `{}`: {}", motivo, r);
                Err("uma cota nao recusou com o motivo dela")
            };
            // Quatro de um processo; o quinto, não.
            for _ in 0..4 {
                pedido(simulado(1, bia), &b)?;
            }
            cota(
                &abrir(simulado(1, bia), &c.endpoint),
                "o processo ja tem 4 fluxos",
            )?;
            // O endpoint com quatro na fila; o quinto pedido, não.
            cota(
                &abrir(simulado(2, bia), &b.endpoint),
                "o endpoint ja tem 4 pedidos na fila",
            )?;
            // Oito do titular; o nono, não.
            for _ in 0..4 {
                pedido(simulado(2, bia), &c)?;
            }
            cota(
                &abrir(simulado(3, bia), &c.endpoint),
                "o titular ja tem 8 fluxos",
            )?;
            // Dezesseis na máquina; o décimo sétimo, não.
            for _ in 0..4 {
                pedido(simulado(4, caio), &d)?;
                pedido(simulado(5, caio), &e)?;
            }
            cota(
                &abrir(simulado(6, edu), &f.endpoint),
                "ja ha 16 fluxos na maquina",
            )?;
            if crate::fluxo::contagem() != (16, 16) {
                crate::log_error!("teste", "{:?}", crate::fluxo::contagem());
                return Err("uma recusa de cota criou, ou tirou, um pedido");
            }
            // Um sai, e cabe outro.
            crate::fluxo::esvaziar_de_teste();
            let a = Ponta::lancar(bia)?;
            let r = (|| -> Resultado {
                // Quem aceita também conta: com quatro abertos, o quinto
                // aceite é recusado, e o pedido fica na fila.
                for _ in 0..4 {
                    aberto(&a, &b)?;
                }
                let id = pedido(c.quem(), &b)?;
                cota(
                    &aceitar(b.quem(), &b.endpoint),
                    "o processo ja tem 4 fluxos",
                )?;
                if crate::fluxo::contagem() != (5, 1)
                    || estado(c.quem(), &id).0.as_deref() != Some("pending")
                {
                    return Err("o aceite recusado pela cota mexeu no pedido");
                }
                Ok(())
            })();
            encerrar_todas(r, &[&a])
        })();
        encerrar_todas(r, &[&b, &c, &d, &e, &f])
    })
}

// ---------------------------------------------------------------------------
// FS11 — a morte, a troca de imagem e a bifurcação
// ---------------------------------------------------------------------------

/// O processo é a ponta: o que acaba leva os fluxos dele — `o processo
/// acabou`, com o que estava no buffer descartado e contado —, menos o de
/// que ele já saiu: fechado, o que ele escreveu segue legível pela outra
/// ponta até o fim, como no fecho, mesmo depois da morte; o que troca
/// de imagem também — `o programa mudou`: a outra ponta viu outro
/// programa —; e o filho de uma bifurcação não herda nada — o id do pai
/// não resolve para ele, e o fluxo do pai segue.
pub(super) fn fluxo_a_morte_a_troca_e_a_bifurcacao() -> Resultado {
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 315);
        let antes = crate::autorizacao::ultimo_registro();
        let a = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            // A morte de quem aceitou, com bytes no caminho.
            let b = Ponta::lancar(bia)?;
            let id = match aberto(&a, &b) {
                Ok(id) => id,
                Err(e) => return encerrar_todas(Err(e), &[&b]),
            };
            let r = escrito(
                &escrever(a.quem(), &id, b"em transito"),
                11,
                "a escrita nao entrou",
            );
            encerrar_todas(r, &[&b])?;
            fim_gravado(antes, &id, "o processo acabou; ida 11; volta 0; desc 11")?;
            recusado_com(
                &ler(a.quem(), &id, 10),
                "CONFLICT",
                "o processo acabou",
                "quem ficou nao viu o fim pela morte da outra ponta",
            )?;
            // A morte de quem já fechou: a ponta não era mais dele — o que
            // escreveu segue legível pela outra, até o fim, como no fecho.
            let g = Ponta::lancar(bia)?;
            let id = match aberto(&a, &g) {
                Ok(id) => id,
                Err(e) => return encerrar_todas(Err(e), &[&g]),
            };
            let r = escrito(
                &escrever(g.quem(), &id, b"antes do fim"),
                12,
                "a escrita de quem ia fechar nao entrou",
            )
            .and_then(|()| {
                feito(
                    &sobre(g.quem(), "stream.close", &id),
                    "quem ia morrer nao fechou",
                )
            });
            let retirado = format!("endpoint:{}", g.endpoint);
            encerrar_todas(r, &[&g])?;
            // O gancho do fim do processo já passou pelos fluxos quando o
            // endpoint dele sai.
            esperar_ate(
                || {
                    !registros_depois(antes, |e| {
                        e.metodo == "fabric.withdraw" && e.recurso == retirado
                    })
                    .is_empty()
                },
                TETO_DA_MALHA,
            )
            .map_err(|_| "o endpoint de quem morreu nao saiu")?;
            ler_e_conferir(
                a.quem(),
                &id,
                100,
                b"antes do fim",
                true,
                "a morte de quem ja tinha fechado levou o que ele escreveu",
            )?;
            fim_gravado(antes, &id, "fechado pela ponta; ida 0; volta 12; desc 0")?;
            // A troca de imagem de quem aceitou.
            let c = Ponta::lancar(bia)?;
            let id = match aberto(&a, &c) {
                Ok(id) => id,
                Err(e) => return encerrar_todas(Err(e), &[&c]),
            };
            let desde = c.ditar(TROCAR, 0)?;
            dito_na_malha(desde, "fluxos: trocando")?;
            fim_gravado(antes, &id, "o programa mudou; ida 0; volta 0; desc 0")?;
            esperar_ate(
                || linhas_do_programa(desde, &format!("processo encerrou com codigo {SAIDA}")) == 1,
                TETO_DA_MALHA,
            )
            .map_err(|_| "o programa trocado nao terminou")?;
            if estado(a.quem(), &id).1.as_deref() != Some("o programa mudou") {
                return Err("quem ficou nao viu a troca de imagem");
            }
            // A bifurcação de quem abriu: o filho não herda.
            let d = Ponta::lancar(bia)?;
            let r = (|| -> Resultado {
                let id = aberto(&a, &d)?;
                let (desde, filho) = passo_na_malha(&a.canal, BIFURCAR, 0, "fluxos: filho ")?;
                let filho: u64 = filho.parse().map_err(|_| "o pai nao disse o filho")?;
                dito_na_malha(desde, &format!("fluxos: sou o filho {filho}"))?;
                // O filho escuta o canal dele só depois de dizer quem é: até
                // o `pronto` dele, o fim que se publicasse ali não teria
                // ouvinte, e se perderia.
                dito_na_malha(desde, &format!("fluxos: pronto {}", a.endpoint))?;
                let r = (|| -> Resultado {
                    let do_filho = chamador_de(filho).ok_or("o filho nao esta vivo")?;
                    for r in [
                        escrever(do_filho, &id, b"herdado"),
                        ler(do_filho, &id, 10),
                        sobre(do_filho, "stream.status", &id),
                        sobre(do_filho, "stream.close", &id),
                    ] {
                        if decisao_do_envelope(&r) != "DENY_RESOURCE" {
                            crate::log_error!("teste", "{}", r);
                            return Err("o filho alcancou o fluxo do pai");
                        }
                    }
                    escrito(
                        &escrever(a.quem(), &id, b"do pai"),
                        6,
                        "o fluxo do pai parou com o filho",
                    )?;
                    ler_e_conferir(
                        d.quem(),
                        &id,
                        10,
                        b"do pai",
                        false,
                        "o fluxo do pai perdeu bytes",
                    )
                })();
                let fim = encerrar_na_malha(&format!("teste-fluxos-{filho}"), SAIDA);
                r.and(fim)
            })();
            encerrar_todas(r, &[&d])
        })();
        encerrar_todas(r, &[&a])
    })
}

// ---------------------------------------------------------------------------
// FS12 — a revogação e a política nova
// ---------------------------------------------------------------------------

/// O fluxo nunca é autorização permanente: a pessoa revogada e a chave
/// revogada levam os fluxos — abertos e pedidos — na hora, gravados com o
/// motivo; e a política nova vale na decisão seguinte: a escrita que ela
/// recusa encerra o fluxo, e a leitura recusada pela intenção que saiu
/// também.
pub(super) fn fluxo_a_revogacao_e_a_politica_nova() -> Resultado {
    const SEMENTE: [u8; 32] = [0x7f; 32];
    com_os_fluxos(|| {
        let antes = crate::autorizacao::ultimo_registro();
        // A pessoa revogada.
        let (sessao, edu) = pessoa("edu", 316);
        let id_edu = pessoa_da_sessao(sessao)?;
        let a = Ponta::lancar(edu)?;
        let b = Ponta::lancar(edu)?;
        let r = (|| -> Resultado {
            let id = aberto(&a, &b)?;
            let pendente = pedido(a.quem(), &b)?;
            crate::pessoas::revogar_pessoa(id_edu).map_err(|_| "a pessoa nao foi revogada")?;
            nada_vivo("a pessoa revogada deixou um fluxo")?;
            fim_gravado(antes, &id, "revogado; ida 0; volta 0; desc 0")?;
            fim_gravado(antes, &pendente, "revogado; ida 0; volta 0; desc 0")
        })();
        encerrar_todas(r, &[&a, &b])?;
        // A chave do agente revogada.
        let chave = sigilo::publica_de(&SEMENTE);
        crate::identidade::registrar_agente_de_teste(chave, "fluxo-k", "operador");
        let agente = Autoridade::Sessao {
            sessao: 3,
            chave: Some(chave),
        };
        let a = Ponta::lancar(agente)?;
        let b = Ponta::lancar(agente)?;
        let r = (|| -> Resultado {
            let id = aberto(&a, &b)?;
            escrito(
                &escrever(a.quem(), &id, b"ate aqui"),
                8,
                "a escrita do agente nao entrou",
            )?;
            crate::identidade::revogar(&chave).map_err(|_| "a chave nao foi revogada")?;
            nada_vivo("a chave revogada deixou um fluxo")?;
            fim_gravado(antes, &id, "revogado; ida 8; volta 0; desc 8")?;
            if decisao_do_envelope(&ler(b.quem(), &id, 10)) == "ALLOW" {
                return Err("o processo da chave revogada ainda leu");
            }
            Ok(())
        })();
        encerrar_todas(r, &[&a, &b])?;
        // A política nova, no meio de um fluxo aberto.
        let (_, bia) = pessoa("bia", 317);
        let antes_da_politica = crate::autorizacao::com_politica(|p| p.clone());
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let id = aberto(&a, &b)?;
            escrito(
                &escrever(a.quem(), &id, b"antes"),
                5,
                "a escrita de antes nao entrou",
            )?;
            politica_sem("fabric.stream");
            let r = escrever(a.quem(), &id, b"depois");
            crate::autorizacao::restaurar_politica(antes_da_politica.clone());
            recusado(
                &r,
                "DENY_PERMISSION",
                "a politica nova nao recusou a escrita",
            )?;
            nada_vivo("a escrita recusada pela politica deixou o fluxo vivo")?;
            fim_gravado_com(antes, &id, "DENY_PERMISSION: ")?;
            let r = ler(b.quem(), &id, 10);
            if desfecho_na_malha(&r) != "CONFLICT"
                || !fs_texto(&r, "error").is_some_and(|m| m.starts_with("DENY_PERMISSION"))
            {
                crate::log_error!("teste", "{}", r);
                return Err("a outra ponta nao viu o fim pela politica");
            }
            // A intenção que sai da política: a leitura recusada encerra.
            let id = aberto(&a, &b)?;
            let sem_a_intencao = politica_trocada(&[(
                "recurso operador fabric.stream intencao:imagem.compartilhar intencao:pdf.anotar",
                "recurso operador fabric.stream intencao:pdf.anotar",
            )])?;
            crate::autorizacao::restaurar_politica(sem_a_intencao);
            let r = ler(b.quem(), &id, 10);
            crate::autorizacao::restaurar_politica(antes_da_politica.clone());
            recusado(&r, "DENY_RESOURCE", "a intencao fora da politica foi lida")?;
            nada_vivo("a leitura recusada pela intencao deixou o fluxo vivo")?;
            fim_gravado_com(antes, &id, "DENY_RESOURCE: ")
        })();
        crate::autorizacao::restaurar_politica(antes_da_politica);
        encerrar_todas(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// FS13 — o desligamento
// ---------------------------------------------------------------------------

/// Com o reinício a caminho, nada abre nem é aceito — `CONFLICT`, com o
/// motivo —, os vivos e os pedidos acabam com `desligando`, gravados, e a
/// espera de quem lia acaba com eles. O reinício chega ao fim.
pub(super) fn fluxo_o_desligamento() -> Resultado {
    use crate::rede::espera::Desfecho;
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 318);
        let antes = crate::autorizacao::ultimo_registro();
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let c = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let id = aberto(&a, &b)?;
            let pendente = pedido(c.quem(), &b)?;
            let Err(espera) = crate::nativo::responder_suspensivel_de_teste(
                b.quem(),
                &pedido_rpc(
                    "stream.read",
                    &format!(r#"{{"stream":"{id}","wait":5000}}"#),
                ),
            ) else {
                return Err("o leitor sem nada nao esperou");
            };
            let _ = crate::energia::executada_de_teste();
            let r = fs_pedir(sistema_aqui(), "system.reboot", "{}");
            if fs_texto(&r, "state").as_deref() != Some("rebooting") {
                crate::log_error!("teste", "{}", r);
                return Err("o reinicio nao foi pedido");
            }
            let motivo = "a maquina esta reiniciando ou desligando";
            let abrir_agora = abrir(a.quem(), &b.endpoint);
            let aceitar_agora = aceitar(b.quem(), &b.endpoint);
            let feitos = esperar_ate(|| crate::fluxo::contagem() == (0, 0), 600);
            let acabou = espera.conferir(None);
            drop(espera);
            let entregue = energia_entregue();
            recusado_com(
                &abrir_agora,
                "CONFLICT",
                motivo,
                "com a maquina indo, um fluxo abriu",
            )?;
            recusado_com(
                &aceitar_agora,
                "CONFLICT",
                motivo,
                "com a maquina indo, um fluxo foi aceito",
            )?;
            feitos.map_err(|_| "com a maquina indo, um fluxo ficou vivo")?;
            if acabou != Some(Desfecho::Sumiu) {
                return Err("a espera do leitor nao acabou com o desligamento");
            }
            fim_gravado(antes, &id, "desligando; ida 0; volta 0; desc 0")?;
            fim_gravado(antes, &pendente, "desligando; ida 0; volta 0; desc 0")?;
            if entregue != Some(crate::energia::Acao::Reiniciar) {
                return Err("o reinicio nao chegou ao fim");
            }
            Ok(())
        })();
        encerrar_todas(r, &[&a, &b, &c])
    })
}

// ---------------------------------------------------------------------------
// FS14 — a inatividade
// ---------------------------------------------------------------------------

/// O fluxo aberto em que nada anda acaba `ocioso` no prazo da
/// inatividade — e não antes —, com o que estava no buffer descartado e
/// contado; um dado que anda adia o prazo.
pub(super) fn fluxo_a_inatividade() -> Resultado {
    use politica::fluxo::OCIOSO_MS;
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 319);
        let antes = crate::autorizacao::ultimo_registro();
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let id = aberto(&a, &b)?;
            escrito(&escrever(a.quem(), &id, b"x"), 1, "a escrita nao entrou")?;
            let agora = crate::tempo::uptime_ms();
            crate::fluxo::vencer_de_teste(agora + OCIOSO_MS - 2_000);
            if crate::fluxo::contagem() != (1, 0) {
                return Err("o fluxo acabou ocioso antes do prazo");
            }
            crate::fluxo::vencer_de_teste(agora + OCIOSO_MS + 2_000);
            nada_vivo("o fluxo parado nao acabou ocioso")?;
            fim_gravado(antes, &id, "ocioso; ida 1; volta 0; desc 1")?;
            if estado(b.quem(), &id) != (Some("closed".into()), Some("ocioso".into())) {
                return Err("a ponta nao viu o fim pela inatividade");
            }
            Ok(())
        })();
        encerrar_todas(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// FS15 — a auditoria e a proveniência
// ---------------------------------------------------------------------------

/// Cada passo de um fluxo é uma decisão gravada, com o processo e o
/// programa que pediu; a execução do pedido e do aceite grava o id, o
/// endpoint e a intenção; o fim é gravado em nome do kernel, com o motivo
/// e as contas. Nenhum registro carrega o conteúdo, e tudo cabe no teto do
/// recurso e do detalhe.
pub(super) fn fluxo_a_auditoria_sem_o_conteudo() -> Resultado {
    use politica::auditoria::MAIOR_DETALHE;
    const SEGREDO: &[u8] = b"conteudo-do-fluxo-que-nao-vai-para-a-auditoria";
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 320);
        let antes = crate::autorizacao::ultimo_registro();
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            let id = aberto(&a, &b)?;
            let n = SEGREDO.len() as u64;
            escrito(&escrever(a.quem(), &id, SEGREDO), n, "a escrita nao entrou")?;
            ler_e_conferir(
                b.quem(),
                &id,
                100,
                SEGREDO,
                false,
                "a leitura nao trouxe a escrita",
            )?;
            feito(
                &sobre(a.quem(), "stream.finish", &id),
                "quem abriu nao terminou",
            )?;
            feito(
                &sobre(b.quem(), "stream.finish", &id),
                "quem aceitou nao terminou",
            )?;
            ler_e_conferir(b.quem(), &id, 100, b"", true, "o fim da ida nao veio")?;
            ler_e_conferir(a.quem(), &id, 100, b"", true, "o fim da volta nao veio")?;
            fim_gravado(antes, &id, &format!("concluido; ida {n}; volta 0; desc 0"))?;
            let fluxo = format!("fluxo:{id}");
            let intencao = format!("intencao:{INTENCAO}");
            let execucao = format!("{fluxo} ; endpoint:{} ; {intencao}", b.endpoint);
            let pelo = |p: &Ponta| format!("pelo processo {} (fluxos {}", p.fio(), p.p.resumo8());
            let decisao = |metodo: &str, p: &Ponta| {
                gravado_na_malha(antes, metodo, &intencao, Codigo::Allow, &pelo(p))
            };
            let gravados = [
                decisao("stream.open", &a),
                gravado_na_malha(
                    antes,
                    "stream.open",
                    &execucao,
                    Codigo::Allow,
                    "pedido; politica ",
                ),
                decisao("stream.accept", &b),
                gravado_na_malha(
                    antes,
                    "stream.accept",
                    &execucao,
                    Codigo::Allow,
                    "aberto; versao 2",
                ),
                decisao("stream.write", &a),
                decisao("stream.read", &b),
                decisao("stream.finish", &a),
                decisao("stream.finish", &b),
            ];
            if let Some(i) = gravados.iter().position(|g| !g) {
                crate::log_error!("teste", "registro {} nao achado", i);
                return Err("um passo do fluxo nao foi gravado com o processo e o programa");
            }
            if !nada_gravado_com(antes, "conteudo-do-fluxo") {
                return Err("o conteudo do fluxo foi para a auditoria");
            }
            let fora_do_teto = registros_depois(antes, |e| {
                e.metodo.starts_with("stream.")
                    && (e.detalhe.len() > MAIOR_DETALHE
                        || e.recurso.len() > crate::autorizacao::MAIOR_RECURSO)
            });
            if !fora_do_teto.is_empty() {
                crate::log_error!("teste", "{:?}", fora_do_teto);
                return Err("um registro do fluxo passou do teto");
            }
            // A execução do pedido traz a versão da política com que foi
            // decidido, e a da decisão.
            let pedido = registros_depois(antes, |e| {
                e.metodo == "stream.open" && e.recurso == execucao
            });
            match pedido.as_slice() {
                [(_, e)] if e.detalhe.contains("; decisao ") => Ok(()),
                _ => {
                    crate::log_error!("teste", "{:?}", pedido);
                    Err("a execucao do pedido nao foi gravada uma vez, com a decisao")
                }
            }
        })();
        encerrar_todas(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// FS16 — os bytes não autorizam
// ---------------------------------------------------------------------------

/// Apaga `caminho` do armazém, se ele está lá — o que um caso antes deixou.
fn apagar_do_armazem(caminho: &str) -> Resultado {
    let v = versao_no_armazem(caminho);
    if v == 0 {
        return Ok(());
    }
    let r = fs_pedir(
        sistema_no_armazem(7_911_999),
        "fs.delete",
        &format!(r#"{{"path":"{caminho}","expect_version":{v}}}"#),
    );
    if !fs_ok(&r) {
        crate::log_error!("teste", "{}", r);
        return Err("o caso nao apagou o arquivo de antes");
    }
    Ok(())
}

/// O que se lê de um fluxo é entrada, e não autoridade: quem aceitou grava
/// o que leu pelo papel dele — no armazém compartilhado, sim; fora dele,
/// `DENY_RESOURCE`; sem `fs.write` na política, `DENY_PERMISSION` —, e a
/// gravação é decisão dele, gravada em nome dele.
pub(super) fn fluxo_os_bytes_nao_autorizam() -> Resultado {
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 321);
        let antes = crate::autorizacao::ultimo_registro();
        let antes_da_politica = crate::autorizacao::com_politica(|p| p.clone());
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let caminho = format!("/armazem/compartilhado/fluxo-{}", b.fio());
        let r = (|| -> Resultado {
            // O armazém não cria pai de passagem: numa suíte filtrada, o
            // compartilhado ainda pode não existir.
            diretorios_acima(&caminho)?;
            apagar_do_armazem(&caminho)?;
            let h = resumo((0..4096).map(padrao));
            let rodada = |fora: i64| -> Result<String, &'static str> {
                let desde = b.ditar(RECEBER, fora)?;
                a.ditar(MANDAR, 4)?;
                let gravar = dito_na_malha(desde, "fluxos: gravar ")?;
                let mandei = dito_na_malha(desde, "fluxos: mandei ")?;
                if mandei != format!("4096 voltou 4096 {h:016x}") {
                    crate::log_error!("teste", "{}", mandei);
                    return Err("o fluxo da rodada nao ida e volta inteiro");
                }
                Ok(gravar)
            };
            if rodada(1)? != "DENY_RESOURCE" {
                return Err("o que se leu de um fluxo gravou fora do papel de quem leu");
            }
            if rodada(0)? != "ALLOW" {
                return Err("quem leu nao gravou pelo papel dele");
            }
            let gravado = registros_depois(antes, |e| {
                e.metodo == "fs.write" && e.recurso == caminho && e.codigo == Codigo::Allow
            });
            // A decisão do gate e a execução que a cita — as duas em nome de
            // quem leu, e de mais ninguém.
            let dele = format!("pelo processo {} (fluxos", b.fio());
            let certo = match gravado.as_slice() {
                [(decisao, d), (_, x)] => {
                    d.detalhe.starts_with(&dele)
                        && !d.detalhe.contains("decisao ")
                        && x.detalhe.starts_with(&dele)
                        && x.detalhe.ends_with(&format!("; decisao {decisao}"))
                }
                _ => false,
            };
            if !certo {
                crate::log_error!("teste", "{:?}", gravado);
                return Err("a gravacao nao foi decisao de quem leu, gravada em nome dele");
            }
            politica_sem("fs.write");
            let sem = rodada(0);
            crate::autorizacao::restaurar_politica(antes_da_politica.clone());
            if sem? != "DENY_PERMISSION" {
                return Err("sem fs.write, o que se leu de um fluxo foi gravado");
            }
            Ok(())
        })();
        crate::autorizacao::restaurar_politica(antes_da_politica);
        let apagado = apagar_do_armazem(&caminho);
        encerrar_todas(r, &[&a, &b]).and(apagado)
    })
}

// ---------------------------------------------------------------------------
// FS17 — as corridas
// ---------------------------------------------------------------------------

/// O processo cujo fim o gancho de teste simula.
static ACABAR: AtomicU64 = AtomicU64::new(0);

/// O gancho: o canal do processo [`ACABAR`] acaba — como no fim dele —,
/// dentro da ordem, uma vez.
fn acabar_no_meio() {
    crate::malha::canal_acabou(politica::mensagens::Canal::Processo(ACABAR.load(SeqCst)));
    crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
}

/// A chave que o gancho de teste revoga.
const SEMENTE_DA_CORRIDA: [u8; 32] = [0x7e; 32];

/// O gancho: a chave [`SEMENTE_DA_CORRIDA`] revogada, uma vez.
fn revogar_no_meio() {
    let _ = crate::identidade::revogar(&sigilo::publica_de(&SEMENTE_DA_CORRIDA));
    crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
}

/// As corridas com a ordem na mão — o gancho roda entre a decisão do gate
/// e a mudança na tabela:
///
/// - abrir × retirar: o endpoint some no meio da abertura, e ela é a
///   recusa de um endpoint que não existe, sem pedido nenhum;
/// - aceitar × morte: quem abriu acaba no meio do aceite, e o pedido acaba
///   com ele — o aceite não abre nada;
/// - aceitar × revogação: a chave dos dois revogada no meio do aceite — ele
///   é recusado, e o pedido acaba `revogado`;
/// - escrever × política, e ler × política: a política nova no meio; a
///   reconfirmação recusa, e o fluxo acaba como na recusa do gate.
pub(super) fn fluxo_corridas_no_meio() -> Resultado {
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 322);
        let antes = crate::autorizacao::ultimo_registro();
        let antes_da_politica = crate::autorizacao::com_politica(|p| p.clone());
        // abrir × retirar.
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            ACABAR.store(b.fio(), SeqCst);
            crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(acabar_no_meio));
            let r = abrir(a.quem(), &b.endpoint);
            crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
            if decisao_do_envelope(&r) != "ALLOW" || desfecho_na_malha(&r) != "DENY_RESOURCE" {
                crate::log_error!("teste", "{}", r);
                return Err("a abertura contra o endpoint que sumiu no meio nao foi recusada");
            }
            if crate::fluxo::contagem() != (0, 0) {
                return Err("a abertura contra o endpoint que sumiu deixou um pedido");
            }
            // aceitar × morte de quem abriu.
            let c = Ponta::lancar(bia)?;
            let r = (|| -> Resultado {
                let id = pedido(a.quem(), &c)?;
                ACABAR.store(a.fio(), SeqCst);
                crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(acabar_no_meio));
                let r = aceitar(c.quem(), &c.endpoint);
                crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
                if !fs_ok(&r) || !r.contains(r#""stream":null"#) {
                    crate::log_error!("teste", "{}", r);
                    return Err("o aceite abriu o pedido de quem acabou no meio");
                }
                fim_gravado(antes, &id, "o processo acabou; ida 0; volta 0; desc 0")
            })();
            encerrar_todas(r, &[&c])
        })();
        encerrar_todas(r, &[&a, &b])?;
        // aceitar × revogação.
        let chave = sigilo::publica_de(&SEMENTE_DA_CORRIDA);
        crate::identidade::registrar_agente_de_teste(chave, "fluxo-corrida", "operador");
        let agente = Autoridade::Sessao {
            sessao: 3,
            chave: Some(chave),
        };
        let a = Ponta::lancar(agente)?;
        let b = Ponta::lancar(agente)?;
        let r = (|| -> Resultado {
            let id = pedido(a.quem(), &b)?;
            crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(revogar_no_meio));
            let r = aceitar(b.quem(), &b.endpoint);
            crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
            if decisao_do_envelope(&r) != "ALLOW" || fs_ok(&r) {
                crate::log_error!("teste", "{}", r);
                return Err("o aceite passou com a chave revogada no meio");
            }
            nada_vivo("o pedido da chave revogada no meio ficou vivo")?;
            fim_gravado(antes, &id, "revogado; ida 0; volta 0; desc 0")
        })();
        encerrar_todas(r, &[&a, &b])?;
        // escrever × política, ler × política.
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            for ler_no_meio in [false, true] {
                let id = aberto(&a, &b)?;
                escrito(
                    &escrever(a.quem(), &id, b"antes"),
                    5,
                    "a escrita de antes nao entrou",
                )?;
                crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(sem_fluxo_no_meio));
                let r = if ler_no_meio {
                    ler(b.quem(), &id, 10)
                } else {
                    escrever(a.quem(), &id, b"no meio")
                };
                crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
                crate::autorizacao::restaurar_politica(antes_da_politica.clone());
                if decisao_do_envelope(&r) != "ALLOW" || desfecho_na_malha(&r) != "DENY_PERMISSION"
                {
                    crate::log_error!("teste", "{}", r);
                    return Err("a politica mudada no meio nao recusou o plano de dados");
                }
                nada_vivo("a recusa da reconfirmacao deixou o fluxo vivo")?;
                fim_gravado_com(antes, &id, "DENY_PERMISSION: ")?;
                let gravado = format!("fluxo:{id}");
                let contas =
                    registros_depois(antes, |e| e.metodo == "stream.end" && e.recurso == gravado);
                if !contas
                    .iter()
                    .any(|(_, e)| e.detalhe.ends_with("; ida 5; volta 0; desc 5"))
                {
                    crate::log_error!("teste", "{:?}", contas);
                    return Err("a recusa no meio executou a operacao");
                }
            }
            Ok(())
        })();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        crate::autorizacao::restaurar_politica(antes_da_politica);
        encerrar_todas(r, &[&a, &b])
    })
}

/// O id do fluxo das corridas com fios, e os fios das duas pontas.
static ID_DA_CORRIDA: crate::trava::Mutex<String> = crate::trava::Mutex::new(String::new());
static FIO_A: AtomicU64 = AtomicU64::new(0);
static FIO_B: AtomicU64 = AtomicU64::new(0);
/// O que o fio da corrida viu no fim: 1 a recusa esperada, 2 outra coisa.
static VISTO: AtomicU64 = AtomicU64::new(0);
/// Quantos bytes passaram, e quantos fios acabaram.
static PASSOU: AtomicU64 = AtomicU64::new(0);
static PRONTOS: AtomicUsize = AtomicUsize::new(0);
/// A largada dos fios que correm juntos.
static LARGADA: AtomicBool = AtomicBool::new(false);

fn id_da_corrida() -> String {
    crate::arch::sem_interrupcoes(|| ID_DA_CORRIDA.lock().clone())
}

/// Um fio que escreve no fluxo da corrida até a escrita ser recusada.
extern "C" fn escritor_da_corrida(_: u64) -> ! {
    let id = id_da_corrida();
    if let Some(quem) = chamador_de(FIO_A.load(SeqCst)) {
        for _ in 0..4096 {
            let r = escrever(quem, &id, &[0x33; 512]);
            if fs_ok(&r) {
                PASSOU.fetch_add(fs_numero(&r, "written").unwrap_or(0), SeqCst);
            } else if desfecho_na_malha(&r) == "RATE_LIMIT" {
                // A ficha é passageira: tenta de novo.
            } else {
                let esperado = fs_texto(&r, "error").as_deref() == Some("fechado pela ponta");
                VISTO.store(if esperado { 1 } else { 2 }, SeqCst);
                if !esperado {
                    crate::log_error!("teste", "{}", r);
                }
                break;
            }
            crate::fios::ceder();
        }
    }
    PRONTOS.fetch_add(1, SeqCst);
    crate::fios::terminar()
}

/// Um fio que lê o fluxo da corrida até a leitura ser recusada.
extern "C" fn leitor_da_corrida(_: u64) -> ! {
    let id = id_da_corrida();
    if let Some(quem) = chamador_de(FIO_B.load(SeqCst)) {
        for _ in 0..4096 {
            let r = ler(quem, &id, 512);
            if let Some((d, _)) = lidos(&r) {
                PASSOU.fetch_add(d.len() as u64, SeqCst);
            } else if desfecho_na_malha(&r) == "RATE_LIMIT" {
                // A ficha é passageira: tenta de novo.
            } else {
                let esperado = fs_texto(&r, "error").as_deref() == Some("o processo acabou");
                VISTO.store(if esperado { 1 } else { 2 }, SeqCst);
                if !esperado {
                    crate::log_error!("teste", "{}", r);
                }
                break;
            }
            crate::fios::ceder();
        }
    }
    PRONTOS.fetch_add(1, SeqCst);
    crate::fios::terminar()
}

/// Um fio que fecha o fluxo da corrida, pela ponta `qual`, na largada.
extern "C" fn fechador_da_corrida(qual: u64) -> ! {
    let id = id_da_corrida();
    let fio = if qual == 0 {
        FIO_A.load(SeqCst)
    } else {
        FIO_B.load(SeqCst)
    };
    while !LARGADA.load(SeqCst) {
        core::hint::spin_loop();
    }
    if let Some(quem) = chamador_de(fio) {
        let r = sobre(quem, "stream.close", &id);
        if fs_ok(&r) {
            PASSOU.fetch_add(1, SeqCst);
        } else {
            crate::log_error!("teste", "{}", r);
        }
    }
    PRONTOS.fetch_add(1, SeqCst);
    crate::fios::terminar()
}

/// Prepara uma corrida no fluxo `id` entre `a` e `b`.
fn largar(id: &str, a: &Ponta, b: &Ponta) {
    crate::arch::sem_interrupcoes(|| *ID_DA_CORRIDA.lock() = String::from(id));
    FIO_A.store(a.fio(), SeqCst);
    FIO_B.store(b.fio(), SeqCst);
    VISTO.store(0, SeqCst);
    PASSOU.store(0, SeqCst);
    PRONTOS.store(0, SeqCst);
    LARGADA.store(false, SeqCst);
}

/// As corridas de fios de verdade, cada operação pelo gate:
///
/// - escrever × fechar: um fio escreve sem parar enquanto a outra ponta
///   fecha; a escrita seguinte ouve `fechado pela ponta`, e o fluxo acaba
///   com o que ficou no buffer contado;
/// - ler × abortar: um fio lê sem parar enquanto quem escreve acaba; a
///   leitura seguinte ouve `o processo acabou`;
/// - fechar × fechar: as duas pontas fecham ao mesmo tempo; os dois fechos
///   passam, e o fim é gravado uma vez.
pub(super) fn fluxo_corridas_ao_mesmo_tempo() -> Resultado {
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 323);
        let antes = crate::autorizacao::ultimo_registro();
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            // escrever × fechar.
            let id = aberto(&a, &b)?;
            largar(&id, &a, &b);
            crate::fios::criar("teste-fluxo", escritor_da_corrida, 0)?;
            esperar_cedendo(|| PASSOU.load(SeqCst) >= 4096, TETO_DA_MALHA)
                .map_err(|_| "o fio escritor nao escreveu")?;
            feito(
                &sobre(b.quem(), "stream.close", &id),
                "a outra ponta nao fechou",
            )?;
            esperar_cedendo(|| PRONTOS.load(SeqCst) == 1, TETO_DA_MALHA)
                .map_err(|_| "o fio escritor nao acabou")?;
            if VISTO.load(SeqCst) != 1 {
                return Err("o escritor nao ouviu o fecho da outra ponta");
            }
            ler_e_conferir(
                a.quem(),
                &id,
                10,
                b"",
                true,
                "quem escrevia nao viu o fim da volta",
            )?;
            fim_gravado_com(antes, &id, "fechado pela ponta; ida ")?;
            nada_vivo("o fluxo fechado durante a escrita ficou vivo")?;
            if !crate::fluxo::coerente() {
                return Err("escrever e fechar juntos deixaram a tabela incoerente");
            }
            // ler × abortar.
            let id = aberto(&a, &b)?;
            largar(&id, &a, &b);
            crate::fios::criar("teste-fluxo", leitor_da_corrida, 0)?;
            for _ in 0..8 {
                escrito(
                    &escrever(a.quem(), &id, &[0x44; 256]),
                    256,
                    "a escrita no meio da leitura nao entrou",
                )?;
                crate::fios::ceder();
            }
            crate::fluxo::canal_acabou(politica::mensagens::Canal::Processo(a.fio()));
            esperar_cedendo(|| PRONTOS.load(SeqCst) == 1, TETO_DA_MALHA)
                .map_err(|_| "o fio leitor nao acabou")?;
            if VISTO.load(SeqCst) != 1 {
                return Err("o leitor nao ouviu o aborto");
            }
            fim_gravado_com(antes, &id, "o processo acabou; ida 2048; volta 0; desc ")?;
            nada_vivo("o fluxo abortado durante a leitura ficou vivo")?;
            // fechar × fechar.
            let id = aberto(&a, &b)?;
            largar(&id, &a, &b);
            crate::fios::criar("teste-fluxo", fechador_da_corrida, 0)?;
            crate::fios::criar("teste-fluxo", fechador_da_corrida, 1)?;
            LARGADA.store(true, SeqCst);
            esperar_cedendo(|| PRONTOS.load(SeqCst) == 2, TETO_DA_MALHA)
                .map_err(|_| "os fios que fecham nao acabaram")?;
            if PASSOU.load(SeqCst) != 2 {
                return Err("um dos fechos ao mesmo tempo foi recusado");
            }
            nada_vivo("o fluxo fechado pelas duas pontas ficou vivo")?;
            fim_gravado(antes, &id, "fechado pela ponta; ida 0; volta 0; desc 0")?;
            let fins = registros_depois(antes, |e| {
                e.metodo == "stream.end" && e.recurso == format!("fluxo:{id}")
            });
            if fins.len() != 1 {
                return Err("o fim dos fechos ao mesmo tempo foi gravado mais de uma vez");
            }
            Ok(())
        })();
        encerrar_todas(r, &[&a, &b])
    })
}

/// Quantos pedidos o fio da corrida com o desligamento abriu, e se ele viu
/// a recusa.
static ABRIU: AtomicU64 = AtomicU64::new(0);

/// Um fio que abre e fecha pedidos até a abertura ser recusada.
extern "C" fn abridor_da_corrida(_: u64) -> ! {
    let endpoint = id_da_corrida();
    if let Some(quem) = chamador_de(FIO_A.load(SeqCst)) {
        for _ in 0..400 {
            let r = abrir(quem, &endpoint);
            if fs_ok(&r) {
                ABRIU.fetch_add(1, SeqCst);
                if let Some(id) = fs_texto(&r, "stream") {
                    let _ = sobre(quem, "stream.close", &id);
                }
            } else if desfecho_na_malha(&r) != "RATE_LIMIT" {
                let esperado = fs_texto(&r, "error").as_deref()
                    == Some("a maquina esta reiniciando ou desligando");
                VISTO.store(if esperado { 1 } else { 2 }, SeqCst);
                if !esperado {
                    crate::log_error!("teste", "{}", r);
                }
                break;
            }
            crate::fios::ceder();
        }
    }
    PRONTOS.fetch_add(1, SeqCst);
    crate::fios::terminar()
}

/// abrir × desligar: um fio abre e fecha pedidos sem parar, e o reinício é
/// pedido no meio. Depois da resposta do reinício, nenhuma abertura passa;
/// os pedidos que abriram antes acabaram — fechados, ou pelo desligamento
/// —, e nada fica vivo.
pub(super) fn fluxo_abrir_e_desligar_ao_mesmo_tempo() -> Resultado {
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 324);
        let a = Ponta::lancar(bia)?;
        let b = Ponta::lancar(bia)?;
        let r = (|| -> Resultado {
            largar(&b.endpoint, &a, &b);
            ABRIU.store(0, SeqCst);
            crate::fios::criar("teste-fluxo", abridor_da_corrida, 0)?;
            esperar_cedendo(|| ABRIU.load(SeqCst) >= 3, TETO_DA_MALHA)
                .map_err(|_| "o fio nao abriu pedidos")?;
            let _ = crate::energia::executada_de_teste();
            let r = fs_pedir(sistema_aqui(), "system.reboot", "{}");
            let abertos = ABRIU.load(SeqCst);
            let pronto = esperar_cedendo(|| PRONTOS.load(SeqCst) == 1, TETO_DA_MALHA);
            let feitos = esperar_ate(|| crate::fluxo::contagem() == (0, 0), 600);
            let entregue = energia_entregue();
            if fs_texto(&r, "state").as_deref() != Some("rebooting") {
                crate::log_error!("teste", "{}", r);
                return Err("o reinicio nao foi pedido");
            }
            pronto.map_err(|_| "o fio que abre nao acabou")?;
            if VISTO.load(SeqCst) != 1 || ABRIU.load(SeqCst) > abertos + 1 {
                crate::log_error!("teste", "{} {}", abertos, ABRIU.load(SeqCst));
                return Err("com o reinicio a caminho, um pedido abriu");
            }
            feitos.map_err(|_| "com a maquina indo, um pedido ficou vivo")?;
            if entregue != Some(crate::energia::Acao::Reiniciar) {
                return Err("o reinicio nao chegou ao fim");
            }
            Ok(())
        })();
        encerrar_todas(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// FS18 — muitos fluxos ao mesmo tempo
// ---------------------------------------------------------------------------

/// Quantos bytes cada fluxo leva.
const POR_FLUXO: usize = 48 * 1024;

/// Os fluxos do caso: o id, quem escreve e quem lê.
static FLUXOS: crate::trava::Mutex<Vec<(String, u64, u64)>> = crate::trava::Mutex::new(Vec::new());
/// Quantas falhas os fios viram.
static FALHAS: AtomicU64 = AtomicU64::new(0);

/// O byte `i` do fluxo `k`.
fn padrao_de(k: usize, i: usize) -> u8 {
    padrao(i + 13 * k)
}

/// Uma falha de um fio, com o que ele viu.
fn falhou(o_que: &str, r: &str) {
    crate::log_error!("teste", "{}: {}", o_que, r);
    FALHAS.fetch_add(1, SeqCst);
}

/// O fio `2k` escreve o fluxo `k` inteiro, termina e lê a volta até o
/// fim; o `2k + 1` lê a ida até o fim, conferindo o resumo, e termina a
/// volta.
extern "C" fn ponta_de_muitos(qual: u64) -> ! {
    let k = (qual / 2) as usize;
    let escreve = qual % 2 == 0;
    let alvo = crate::arch::sem_interrupcoes(|| FLUXOS.lock().get(k).cloned());
    let feito = (|| -> Option<()> {
        let (id, abridor, aceitante) = alvo?;
        let quem = chamador_de(if escreve { abridor } else { aceitante })?;
        if escreve {
            let dados: Vec<u8> = (0..POR_FLUXO).map(|i| padrao_de(k, i)).collect();
            let mut feito = 0;
            while feito < POR_FLUXO {
                let fim = (feito + 4096).min(POR_FLUXO);
                let r = escrever(quem, &id, &dados[feito..fim]);
                match fs_numero(&r, "written") {
                    Some(n) if fs_ok(&r) => feito += n as usize,
                    _ if desfecho_na_malha(&r) == "RATE_LIMIT" => {}
                    _ => {
                        falhou("escrever", &r);
                        return None;
                    }
                }
                crate::fios::ceder();
            }
            let r = sobre(quem, "stream.finish", &id);
            if !fs_ok(&r) {
                falhou("terminar a ida", &r);
                return None;
            }
        }
        // Lê o sentido dele até o fim.
        let mut lido = Vec::new();
        loop {
            let r = ler(quem, &id, 16 * 1024);
            match lidos(&r) {
                Some((d, fim)) => {
                    lido.extend_from_slice(&d);
                    if fim {
                        break;
                    }
                }
                None if desfecho_na_malha(&r) == "RATE_LIMIT" => {}
                None => {
                    falhou("ler", &r);
                    return None;
                }
            }
            crate::fios::ceder();
        }
        if escreve {
            if !lido.is_empty() {
                falhou("a volta", "trouxe bytes");
            }
        } else {
            let esperado = resumo((0..POR_FLUXO).map(|i| padrao_de(k, i)));
            if lido.len() != POR_FLUXO || resumo(lido.iter().copied()) != esperado {
                falhou("a ida", "nao veio inteira, na ordem");
            }
            let r = sobre(quem, "stream.finish", &id);
            if !fs_ok(&r) {
                falhou("terminar a volta", &r);
            }
        }
        Some(())
    })();
    if feito.is_none() {
        FALHAS.fetch_add(1, SeqCst);
    }
    PRONTOS.fetch_add(1, SeqCst);
    crate::fios::terminar()
}

/// Muitos fluxos e muitas escritas ao mesmo tempo: quatro processos em
/// anel, um fluxo de cada um ao seguinte, e um fio por ponta — oito fios
/// lendo e escrevendo pelo gate, cada byte conferido. A tabela fica
/// coerente o tempo todo, cada fluxo acaba `concluido`, com as contas, e
/// nada fica vivo.
pub(super) fn fluxo_muitos_ao_mesmo_tempo() -> Resultado {
    const PONTAS: usize = 4;
    com_os_fluxos(|| {
        let (_, bia) = pessoa("bia", 325);
        let antes = crate::autorizacao::ultimo_registro();
        let mut pontas = Vec::new();
        for _ in 0..PONTAS {
            match Ponta::lancar(bia) {
                Ok(p) => pontas.push(p),
                Err(e) => {
                    let todas: Vec<&Ponta> = pontas.iter().collect();
                    return encerrar_todas(Err(e), &todas);
                }
            }
        }
        let r = (|| -> Resultado {
            let mut fluxos = Vec::new();
            for k in 0..PONTAS {
                let (a, b) = (&pontas[k], &pontas[(k + 1) % PONTAS]);
                fluxos.push((aberto(a, b)?, a.fio(), b.fio()));
            }
            let ids: Vec<String> = fluxos.iter().map(|(id, _, _)| id.clone()).collect();
            crate::arch::sem_interrupcoes(|| *FLUXOS.lock() = fluxos);
            FALHAS.store(0, SeqCst);
            PRONTOS.store(0, SeqCst);
            for qual in 0..(2 * PONTAS) as u64 {
                crate::fios::criar("teste-fluxo", ponta_de_muitos, qual)?;
            }
            let mut incoerente = false;
            let fim = esperar_cedendo(
                || {
                    incoerente |= !crate::fluxo::coerente();
                    PRONTOS.load(SeqCst) == 2 * PONTAS
                },
                6 * TETO_DA_MALHA,
            );
            fim.map_err(|_| "os fios dos fluxos nao acabaram")?;
            if FALHAS.load(SeqCst) != 0 {
                return Err("um fio viu um fluxo falhar");
            }
            if incoerente {
                return Err("a tabela de fluxos ficou incoerente no meio");
            }
            for id in &ids {
                fim_gravado(
                    antes,
                    id,
                    &format!("concluido; ida {POR_FLUXO}; volta 0; desc 0"),
                )?;
            }
            nada_vivo("um dos muitos fluxos ficou vivo")
        })();
        crate::arch::sem_interrupcoes(|| FLUXOS.lock().clear());
        let todas: Vec<&Ponta> = pontas.iter().collect();
        encerrar_todas(r, &todas)
    })
}
