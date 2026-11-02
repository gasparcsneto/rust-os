//! Os casos do aviso da malha (DS-1) — o DN-3.
//!
//! Um processo pede, no mesmo pedido que cria ou aceita um objeto da malha,
//! que o kernel o avise no canal de eventos dele quando o objeto ficar
//! pronto. A suíte lança o programa `avisado` — um processo que espera só no
//! canal dele e diz, no log, cada aviso que chega — e conduz o resto de
//! dois jeitos: dita passos ao programa, para o caminho inteiro pelo runtime
//! (`programas::laco`, `programas::fluxo`), ou pede **como** o processo,
//! pela mesma função do gate, para os passos que precisam ser exatos. O que
//! ela confere é o que o kernel publicou, quando e quantas vezes, e que cada
//! operação que segue um aviso continua sendo um pedido decidido pelo gate.

use super::fluxo::{
    abrir, aceitar, chamador_de, escrever, escrito, estado, feito, fim_gravado, fim_gravado_com,
    ler, ler_e_conferir, lidos, nada_vivo, recusado, sobre,
};
use super::{
    NaMalha, Resultado, TETO_DA_MALHA, com_a_malha, decisao_do_envelope, desfecho_na_malha,
    ditas_na_malha, dito_na_malha, encerrar_na_malha, energia_entregue, esperar_ate,
    esperar_cedendo, fs_ok, fs_pedir, fs_texto, gravado_na_malha, linhas_do_programa,
    mandar_na_malha, politica_sem, politica_trocada, registros_depois, sistema_aqui,
};
use crate::autorizacao::{Autoridade, Chamador};
use crate::aviso::Objeto;
use crate::pessoas::Console;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering::SeqCst};
use politica::Codigo;
use protocolo::usuario::evento::{Evento, malha, tipo};

/// A intenção que o `avisado` oferece.
const INTENCAO: &str = "imagem.compartilhar";

/// O código com que o `avisado` sai no fim pedido.
const SAIDA: i64 = 61;

/// Os passos do `avisado`.
pub(in crate::testes) const ABRIR: i64 = 1;
const ACEITAR: i64 = 2;
const LER: i64 = 3;
const ESCREVER: i64 = 4;
const TROCAR: i64 = 9;
const BIFURCAR: i64 = 10;
const RUIM: i64 = 12;
const PAUSAR: i64 = 13;
pub(in crate::testes) const DUPLEX: i64 = 14;
const BLOQUEANTE: i64 = 15;
const CONTAR: i64 = 16;
pub(in crate::testes) const MANDAR_LACO: i64 = 17;
pub(in crate::testes) const RECEBER_LACO: i64 = 18;
pub(in crate::testes) const MANDAR_BLOQ: i64 = 19;
pub(in crate::testes) const RECEBER_BLOQ: i64 = 20;
const OUTRO_CANAL: i64 = 21;
const FECHAR_OUTRO: i64 = 22;

/// O buffer de um sentido.
const BUFFER: usize = politica::fluxo::BUFFER_DO_SENTIDO;

/// Quanto esperar, em tiques, para dizer que um aviso **não** veio: o aviso
/// sai na mudança, ou no máximo um tique depois, pelo coletor.
const SOSSEGO: u64 = 30;

/// Uma pessoa operadora numa sessão de teste: a sessão e a autoridade.
pub(in crate::testes) fn pessoa(
    nome: &str,
    terminal: u16,
) -> (crate::pessoas::IdSessao, Autoridade) {
    let sessao = crate::pessoas::sessao_de_teste(Console::Terminal(terminal), nome, "operador");
    (sessao, Autoridade::Pessoa { sessao })
}

/// Um `avisado` em execução: o programa, o endpoint que ele ofereceu com o
/// aviso, o descritor do canal dele e o nome do canal.
pub(in crate::testes) struct Avisado {
    p: NaMalha,
    pub(in crate::testes) endpoint: String,
    pub(in crate::testes) descritor: u64,
    pub(in crate::testes) canal: String,
}

/// Um aviso, como o `avisado` o disse: o tipo do objeto, o número e os
/// bits — crus, como vieram no evento.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::testes) struct Visto {
    tipo: String,
    numero: u64,
    bits: i64,
}

impl Avisado {
    /// Lança o `avisado` com `autoridade` e espera ele dizer o endpoint e o
    /// descritor do canal.
    pub(in crate::testes) fn lancar(autoridade: Autoridade) -> Result<Avisado, &'static str> {
        let (p, resto) = NaMalha::lancar("avisado", autoridade, "avisado: pronto ")?;
        let (endpoint, d) = resto
            .split_once(' ')
            .ok_or("o avisado nao disse o descritor")?;
        let descritor = d
            .parse()
            .map_err(|_| "o descritor do avisado nao e numero")?;
        let canal = format!("teste-avisado-{}", p.fio);
        Ok(Avisado {
            endpoint: String::from(endpoint),
            descritor,
            canal,
            p,
        })
    }

    /// O chamador que pede como este processo.
    pub(in crate::testes) fn quem(&self) -> Chamador {
        self.p.chamador()
    }

    pub(in crate::testes) fn fio(&self) -> u64 {
        self.p.fio
    }

    /// O número do endpoint dele — o do aviso.
    pub(in crate::testes) fn numero_do_endpoint(&self) -> u64 {
        politica::aviso::numero_do_id(&self.endpoint).unwrap_or(u64::MAX)
    }

    /// A ponta dele no fluxo `n`, como o kernel a designa.
    pub(in crate::testes) fn ponta(&self, n: u64) -> Objeto {
        Objeto::Ponta {
            fluxo: n,
            fio: self.p.fio,
        }
    }

    /// O começo das linhas dele.
    fn prefixo(&self) -> String {
        format!("avisado {}: ", self.p.fio)
    }

    /// Dita o passo `a`, com `b` e `c`: devolve de quando o passo começou.
    pub(in crate::testes) fn ditar(&self, a: i64, b: i64, c: i64) -> Result<u64, &'static str> {
        self.publicar(Evento {
            tipo: tipo::ACAO,
            a,
            b,
            c,
        })
    }

    /// Publica `e` no canal dele, como o kernel publicaria: devolve de quando.
    fn publicar(&self, e: Evento) -> Result<u64, &'static str> {
        let desde = crate::log::total_emitidos();
        crate::eventos::publicar(&self.canal, e).map_err(|_| "o canal do avisado nao recebeu")?;
        Ok(desde)
    }

    /// A primeira linha dele, desde `desde`, que começa com `resto`: o que
    /// vem depois.
    pub(in crate::testes) fn dito(&self, desde: u64, resto: &str) -> Result<String, &'static str> {
        dito_na_malha(desde, &format!("{}{resto}", self.prefixo()))
    }

    /// Os avisos que ele disse desde `desde`.
    pub(in crate::testes) fn avisos(&self, desde: u64) -> Vec<Visto> {
        ditas_na_malha(desde, &format!("{}aviso ", self.prefixo()))
            .into_iter()
            .filter_map(|l| {
                let mut p = l.split(' ');
                Some(Visto {
                    tipo: String::from(p.next()?),
                    numero: p.next()?.parse().ok()?,
                    bits: p.next()?.parse().ok()?,
                })
            })
            .collect()
    }

    /// Os avisos do objeto `tipo` `numero` que ele disse desde `desde`.
    pub(in crate::testes) fn avisos_de(&self, desde: u64, tipo: &str, numero: u64) -> Vec<i64> {
        self.avisos(desde)
            .into_iter()
            .filter(|v| v.tipo == tipo && v.numero == numero)
            .map(|v| v.bits)
            .collect()
    }

    /// Espera o aviso `tipo` `numero` com `bits` dito desde `desde`.
    pub(in crate::testes) fn esperar_aviso(
        &self,
        desde: u64,
        tipo: &str,
        numero: u64,
        bits: i64,
    ) -> Resultado {
        let r = esperar_ate(
            || self.avisos_de(desde, tipo, numero).contains(&bits),
            TETO_DA_MALHA,
        );
        if r.is_err() {
            crate::log_error!(
                "teste",
                "esperava o aviso {} {} {} de {}; vieram {:?}",
                tipo,
                numero,
                bits,
                self.p.fio,
                self.avisos(desde)
            );
            return Err("o aviso esperado nao veio");
        }
        Ok(())
    }

    /// Os avisos do objeto `tipo` `numero` que ele disse desde `desde`,
    /// depois do sossego: o que veio, e só.
    pub(in crate::testes) fn avisos_depois_do_sossego(
        &self,
        desde: u64,
        tipo: &str,
        numero: u64,
    ) -> Vec<i64> {
        let _ = esperar_ate(|| false, SOSSEGO);
        self.avisos_de(desde, tipo, numero)
    }

    /// Pede o fim do programa e espera ele sair.
    pub(in crate::testes) fn encerrar(&self) -> Resultado {
        encerrar_na_malha(&self.canal, SAIDA)
    }
}

/// Encerra os programas, todos — também quando um falha —, e devolve a
/// primeira falha, depois da do caso.
pub(in crate::testes) fn encerrar_todos(r: Resultado, quem: &[&Avisado]) -> Resultado {
    let fins: Vec<Resultado> = quem.iter().map(|p| p.encerrar()).collect();
    r?;
    fins.into_iter().collect()
}

/// Roda `f` com a malha e os fluxos limpos, e confere no fim que a tabela
/// dos fluxos ficou coerente e nenhuma designação sobrou: os processos
/// acabaram, e as deles saíram.
pub(in crate::testes) fn com_os_avisos(f: impl FnOnce() -> Resultado) -> Resultado {
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
        if esperar_ate(|| crate::aviso::medidas().designacoes == 0, TETO_DA_MALHA).is_err() {
            crate::log_error!(
                "teste",
                "sobraram {} designacoes",
                crate::aviso::medidas().designacoes
            );
            return Err("uma designacao sobrou depois de o processo acabar");
        }
        Ok(())
    })
}

/// O número de um fluxo que o `avisado` disse — `abri <n>`, `aceitei <n>`.
pub(in crate::testes) fn numero(dito: &str) -> Result<u64, &'static str> {
    dito.trim()
        .parse()
        .map_err(|_| "o avisado nao disse o numero do fluxo")
}

/// O número de um id de fluxo deste boot.
pub(in crate::testes) fn numero_do_fluxo(id: &str) -> Result<u64, &'static str> {
    crate::fluxo::numero_de_teste(id).ok_or("o id do fluxo nao e deste boot")
}

/// `stream.open` de `a` ao `endpoint`, com o aviso no canal dele.
pub(in crate::testes) fn abrir_avisando(a: &Avisado, endpoint: &str) -> String {
    fs_pedir(
        a.quem(),
        "stream.open",
        &format!(
            r#"{{"endpoint":"{endpoint}","intent":"{INTENCAO}","notify":{}}}"#,
            a.descritor
        ),
    )
}

/// `stream.accept` de `b` no endpoint dele, sem esperar, com o aviso no
/// canal dele.
pub(in crate::testes) fn aceitar_avisando(b: &Avisado) -> String {
    fs_pedir(
        b.quem(),
        "stream.accept",
        &format!(
            r#"{{"endpoint":"{}","notify":{}}}"#,
            b.endpoint, b.descritor
        ),
    )
}

/// Um fluxo de `a` ao endpoint de `b`, aceito por `b`, pedido como os
/// processos — cada ponta com o aviso, ou sem: o id e o número.
pub(in crate::testes) fn aberto(
    a: &Avisado,
    b: &Avisado,
    avisar_a: bool,
    avisar_b: bool,
) -> Result<(String, u64), &'static str> {
    let r = if avisar_a {
        abrir_avisando(a, &b.endpoint)
    } else {
        abrir(a.quem(), &b.endpoint)
    };
    let id = fs_texto(&r, "stream").ok_or_else(|| {
        crate::log_error!("teste", "{}", r);
        "o pedido de fluxo nao passou"
    })?;
    let r = if avisar_b {
        aceitar_avisando(b)
    } else {
        aceitar(b.quem(), &b.endpoint)
    };
    if fs_texto(&r, "stream").as_deref() != Some(id.as_str()) {
        crate::log_error!("teste", "{}", r);
        return Err("o dono do endpoint nao aceitou o fluxo pedido");
    }
    Ok((id.clone(), numero_do_fluxo(&id)?))
}

/// Os dois `avisado` com um fluxo aberto entre eles pelos passos do
/// programa — o runtime inteiro —, os dois com o aviso: o de `a` abriu, o
/// de `b` aceitou. Confere no caminho o aviso do pedido no endpoint de `b`
/// e o da abertura na ponta de `a`. Devolve o número.
fn aberto_pelos_programas(a: &Avisado, b: &Avisado) -> Result<u64, &'static str> {
    let desde_b = crate::log::total_emitidos();
    let desde = a.ditar(ABRIR, 1, 0)?;
    let n = numero(&a.dito(desde, "abri ")?)?;
    b.esperar_aviso(desde_b, "endpoint", b.numero_do_endpoint(), malha::PEDIDO)?;
    let desde_a = crate::log::total_emitidos();
    let desde = b.ditar(ACEITAR, 1, 0)?;
    if numero(&b.dito(desde, "aceitei ")?)? != n {
        return Err("o avisado aceitou outro fluxo");
    }
    a.esperar_aviso(desde_a, "fluxo", n, malha::GRAVAVEL)?;
    Ok(n)
}

/// Como [`aberto_pelos_programas`], com `a` abrindo no endpoint de `b`
/// pelo número — com outros `avisado` oferecendo a mesma intenção, o
/// primeiro que a descoberta acha pode não ser o de `b`.
pub(in crate::testes) fn aberto_pelos_programas_em(
    a: &Avisado,
    b: &Avisado,
) -> Result<u64, &'static str> {
    let desde_a = crate::log::total_emitidos();
    let desde = a.ditar(ABRIR, 1, b.numero_do_endpoint() as i64)?;
    let n = numero(&a.dito(desde, "abri ")?)?;
    let desde = b.ditar(ACEITAR, 1, 0)?;
    if numero(&b.dito(desde, "aceitei ")?)? != n {
        return Err("o avisado aceitou outro fluxo");
    }
    a.esperar_aviso(desde_a, "fluxo", n, malha::GRAVAVEL)?;
    Ok(n)
}

/// Os bytes que uma leitura de `quem` trouxe, ou a falha.
fn lido(quem: Chamador, id: &str, max: usize) -> Result<(Vec<u8>, bool), &'static str> {
    let r = ler(quem, id, max);
    lidos(&r).ok_or_else(|| {
        crate::log_error!("teste", "{}", r);
        "a leitura nao passou"
    })
}

// ---------------------------------------------------------------------------
// NS01 — o dado avisa, uma vez
// ---------------------------------------------------------------------------

/// O caminho do aviso, de ponta a ponta, pelo runtime: o pedido de fluxo
/// avisa o endpoint de quem aceita; a abertura avisa quem abriu
/// (`GRAVAVEL`); o dado avisa quem lê (`LEGIVEL`) **uma vez** — mais dado,
/// com o aviso ainda não consumido, não avisa de novo —; a leitura que
/// esvazia consome, e nada mais vem até o dado seguinte, que avisa de novo.
pub(super) fn aviso_o_dado_avisa_uma_vez() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 401);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let n = aberto_pelos_programas(&a, &b)?;
            // O dado avisa quem lê.
            let desde_b = crate::log::total_emitidos();
            let desde = a.ditar(ESCREVER, n as i64, 100)?;
            a.dito(desde, &format!("escrevi {n} 100"))?;
            b.esperar_aviso(desde_b, "fluxo", n, malha::LEGIVEL)?;
            // Mais dado, com o aviso não consumido: nada.
            let desde = a.ditar(ESCREVER, n as i64, 50)?;
            a.dito(desde, &format!("escrevi {n} 50"))?;
            if b.avisos_depois_do_sossego(desde_b, "fluxo", n).len() != 1 {
                crate::log_error!("teste", "{:?}", b.avisos(desde_b));
                return Err("o dado com o aviso nao consumido avisou de novo");
            }
            // A leitura consome: lê os 150, e nada mais vem.
            let desde_b = crate::log::total_emitidos();
            let desde = b.ditar(LER, n as i64, 1000)?;
            let li = b.dito(desde, &format!("li {n} "))?;
            if !li.starts_with("150 0 ") {
                crate::log_error!("teste", "li {}", li);
                return Err("a leitura nao trouxe o que foi escrito");
            }
            if !b.avisos_depois_do_sossego(desde_b, "fluxo", n).is_empty() {
                return Err("a leitura que esvaziou ainda avisou");
            }
            // O dado seguinte avisa de novo.
            let desde_b = crate::log::total_emitidos();
            let desde = a.ditar(ESCREVER, n as i64, 10)?;
            a.dito(desde, &format!("escrevi {n} 10"))?;
            b.esperar_aviso(desde_b, "fluxo", n, malha::LEGIVEL)
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS01b — um aviso de cada objeto no canal
// ---------------------------------------------------------------------------

/// Cada operação do dono rearma, e o nível de agora avisa de novo — mas o
/// canal tem **um** aviso de cada objeto: com o processo sem ler o canal,
/// três leituras que deixam dado no fluxo não enchem a fila; o aviso que
/// já esperava nela recebe os bits de agora, e a medida conta os juntados.
/// Quando o processo volta ao canal, vê um aviso só.
pub(super) fn aviso_um_aviso_de_cada_objeto_no_canal() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 424);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let (id, n) = aberto(&a, &b, false, true)?;
            let desde = b.ditar(PAUSAR, 3000, 0)?;
            b.dito(desde, "pausando")?;
            let na_fila = || crate::eventos::estado(&b.canal).map_or(0, |e| e.na_fila);
            let antes = (na_fila(), crate::aviso::medidas());
            escrito(
                &escrever(a.quem(), &id, &[0x33; 400]),
                400,
                "a escrita nao entrou",
            )?;
            for _ in 0..3 {
                let (d, fim) = lido(b.quem(), &id, 100)?;
                if d.len() != 100 || fim {
                    return Err("a leitura do dono nao trouxe os 100");
                }
            }
            let depois = crate::aviso::medidas();
            if na_fila() != antes.0 + 1 {
                crate::log_error!("teste", "na fila {} antes {}", na_fila(), antes.0);
                return Err("o canal ficou com mais de um aviso do mesmo objeto");
            }
            if depois.juntados < antes.1.juntados + 3 || depois.publicados != antes.1.publicados + 1
            {
                crate::log_error!("teste", "{:?} -> {:?}", antes.1, depois);
                return Err("os avisos juntados nao foram contados");
            }
            // De volta ao canal: um aviso só, o de agora — ainda há dado.
            b.esperar_aviso(desde, "fluxo", n, malha::LEGIVEL)?;
            if b.avisos_depois_do_sossego(desde, "fluxo", n) != [malha::LEGIVEL] {
                crate::log_error!("teste", "{:?}", b.avisos(desde));
                return Err("o processo viu mais de um aviso do mesmo objeto");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS02 — o espaço avisa quem esbarrou
// ---------------------------------------------------------------------------

/// `GRAVAVEL` é de quem esbarrou no cheio: encher o buffer com uma escrita
/// que coube inteira não pede o espaço; a escrita que não coube pede; a
/// leitura do outro lado devolve o espaço e avisa quem esbarrou — uma vez,
/// por mais que o outro leia —; e a escrita seguinte, que cabe, não pede
/// mais nada.
pub(super) fn aviso_o_espaco_avisa_quem_esbarrou() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 402);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let desde_a = crate::log::total_emitidos();
            let (id, n) = aberto(&a, &b, true, true)?;
            a.esperar_aviso(desde_a, "fluxo", n, malha::GRAVAVEL)?;
            // Enche: coube inteira — quem não esbarrou não quer o espaço.
            let desde_a = crate::log::total_emitidos();
            escrito(
                &escrever(a.quem(), &id, &[0x5a; BUFFER]),
                BUFFER as u64,
                "a escrita que enche nao entrou inteira",
            )?;
            for _ in 0..3 {
                let (d, _) = lido(b.quem(), &id, 100)?;
                if d.len() != 100 {
                    return Err("a leitura do outro lado nao trouxe os 100");
                }
            }
            if !a.avisos_depois_do_sossego(desde_a, "fluxo", n).is_empty() {
                crate::log_error!("teste", "{:?}", a.avisos(desde_a));
                return Err("quem nao esbarrou foi avisado do espaco");
            }
            // Esbarra: enche de novo, e a escrita seguinte não cabe.
            escrito(
                &escrever(a.quem(), &id, &[0x5b; 300]),
                300,
                "a escrita que completa nao entrou",
            )?;
            escrito(
                &escrever(a.quem(), &id, b"mais"),
                0,
                "a escrita no cheio entrou",
            )?;
            if !a.avisos_depois_do_sossego(desde_a, "fluxo", n).is_empty() {
                return Err("o espaco avisou antes de haver espaco");
            }
            // O outro lê: o espaço volta, e quem esbarrou ouve — uma vez.
            let desde_a = crate::log::total_emitidos();
            lido(b.quem(), &id, 1000)?;
            a.esperar_aviso(desde_a, "fluxo", n, malha::GRAVAVEL)?;
            lido(b.quem(), &id, 1000)?;
            lido(b.quem(), &id, 1000)?;
            if a.avisos_depois_do_sossego(desde_a, "fluxo", n) != [malha::GRAVAVEL] {
                crate::log_error!("teste", "{:?}", a.avisos(desde_a));
                return Err("o espaco avisou mais de uma vez");
            }
            // Escreve o que cabe: não esbarrou, e o espaço que volta não
            // avisa mais.
            let desde_a = crate::log::total_emitidos();
            escrito(
                &escrever(a.quem(), &id, b"cabe"),
                4,
                "a escrita que cabe nao entrou",
            )?;
            lido(b.quem(), &id, 1000)?;
            if !a.avisos_depois_do_sossego(desde_a, "fluxo", n).is_empty() {
                crate::log_error!("teste", "{:?}", a.avisos(desde_a));
                return Err("o espaco avisou quem nao esbarrou de novo");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS03 — o fim do sentido, o fecho e o aborto
// ---------------------------------------------------------------------------

/// O fim avisa como o dado: o `finish` do par dá `LEGIVEL` — o fim do
/// sentido é lido —, e depois de lido nada mais; o `close` do par com dado
/// no caminho dá `LEGIVEL`, a leitura traz o dado e o fim, e quem tinha
/// esbarrado no cheio ouve `GRAVAVEL` — a escrita seguinte diz o motivo. O
/// aborto — a morte do par — dá `FIM`, uma vez, e a operação seguinte ouve
/// o motivo; depois dela, nada.
pub(super) fn aviso_o_fim_do_sentido_o_fecho_e_o_aborto() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 403);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            // O fim do sentido.
            let (id, n) = aberto(&a, &b, false, true)?;
            let desde_b = crate::log::total_emitidos();
            escrito(&escrever(a.quem(), &id, b"ola"), 3, "a escrita nao entrou")?;
            b.esperar_aviso(desde_b, "fluxo", n, malha::LEGIVEL)?;
            ler_e_conferir(
                b.quem(),
                &id,
                100,
                b"ola",
                false,
                "a leitura nao trouxe o ola",
            )?;
            let desde_b = crate::log::total_emitidos();
            feito(
                &sobre(a.quem(), "stream.finish", &id),
                "o finish nao passou",
            )?;
            b.esperar_aviso(desde_b, "fluxo", n, malha::LEGIVEL)?;
            ler_e_conferir(b.quem(), &id, 100, b"", true, "a leitura nao trouxe o fim")?;
            if b.avisos_depois_do_sossego(desde_b, "fluxo", n) != [malha::LEGIVEL] {
                crate::log_error!("teste", "{:?}", b.avisos(desde_b));
                return Err("o fim do sentido lido ainda avisou");
            }
            // O par fecha: o sentido dele já foi lido, e o de `b` não tem
            // mais quem leia — o fluxo acabou, e `b`, que não ouviu o
            // motivo, ouve `FIM`; o `close` dele diz o motivo, e nada mais.
            let desde_b = crate::log::total_emitidos();
            feito(
                &sobre(a.quem(), "stream.close", &id),
                "o close de a nao passou",
            )?;
            b.esperar_aviso(desde_b, "fluxo", n, malha::FIM)?;
            let r = sobre(b.quem(), "stream.close", &id);
            if desfecho_na_malha(&r) != "CONFLICT"
                || fs_texto(&r, "error").as_deref() != Some(politica::fluxo::motivo::FECHADO)
            {
                crate::log_error!("teste", "{}", r);
                return Err("o close depois do FIM nao disse o motivo");
            }
            if b.avisos_depois_do_sossego(desde_b, "fluxo", n) != [malha::FIM] {
                crate::log_error!("teste", "{:?}", b.avisos(desde_b));
                return Err("o fim do fluxo avisou mais de uma vez");
            }
            // O fecho do par com dado no caminho e `b` esperando espaço: o
            // dado avisa; a leitura traz o dado e o fim do sentido, e o
            // aviso seguinte — o fim do fluxo, ou o espaço do sentido que
            // ninguém mais lê — leva `b` à escrita, que diz o motivo.
            let (id, n) = aberto(&a, &b, true, true)?;
            escrito(
                &escrever(b.quem(), &id, &[0x11; BUFFER]),
                BUFFER as u64,
                "a escrita que enche nao entrou",
            )?;
            escrito(
                &escrever(b.quem(), &id, b"x"),
                0,
                "a escrita no cheio entrou",
            )?;
            let desde_b = crate::log::total_emitidos();
            escrito(
                &escrever(a.quem(), &id, b"tchau"),
                5,
                "a escrita nao entrou",
            )?;
            feito(&sobre(a.quem(), "stream.close", &id), "o close nao passou")?;
            b.esperar_aviso(desde_b, "fluxo", n, malha::LEGIVEL)?;
            let desde_b = crate::log::total_emitidos();
            ler_e_conferir(
                b.quem(),
                &id,
                100,
                b"tchau",
                true,
                "a leitura nao trouxe o tchau",
            )?;
            esperar_ate(
                || {
                    b.avisos_de(desde_b, "fluxo", n)
                        .iter()
                        .any(|v| v & (malha::FIM | malha::GRAVAVEL) != 0)
                },
                TETO_DA_MALHA,
            )
            .map_err(|_| {
                crate::log_error!("teste", "{:?}", b.avisos(desde_b));
                "depois do fim lido, o fecho do par nao levou b a operar"
            })?;
            let r = escrever(b.quem(), &id, b"y");
            if desfecho_na_malha(&r) != "CONFLICT"
                || fs_texto(&r, "error").as_deref() != Some(politica::fluxo::motivo::FECHADO)
            {
                crate::log_error!("teste", "{}", r);
                return Err("a escrita depois do fecho do par nao disse o motivo");
            }
            if crate::aviso::situacao_de_teste(b.ponta(n)).is_some() {
                return Err("a escrita que ouviu o fim nao largou a designacao");
            }
            let desde_b = crate::log::total_emitidos();
            let _ = sobre(b.quem(), "stream.close", &id);
            if !b.avisos_depois_do_sossego(desde_b, "fluxo", n).is_empty() {
                return Err("o fluxo acabado ainda avisou");
            }
            // O aborto: a morte de quem abriu, com a outra ponta livre.
            let c = Avisado::lancar(bia)?;
            let r = (|| -> Resultado {
                let (id, n) = aberto(&c, &b, false, true)?;
                let desde_b = crate::log::total_emitidos();
                escrito(&escrever(c.quem(), &id, b"z"), 1, "a escrita nao entrou")?;
                b.esperar_aviso(desde_b, "fluxo", n, malha::LEGIVEL)?;
                ler_e_conferir(b.quem(), &id, 100, b"z", false, "a leitura nao trouxe o z")?;
                let desde_b = crate::log::total_emitidos();
                c.encerrar()?;
                b.esperar_aviso(desde_b, "fluxo", n, malha::FIM)?;
                let r = ler(b.quem(), &id, 100);
                if desfecho_na_malha(&r) != "CONFLICT"
                    || fs_texto(&r, "error").as_deref() != Some("o processo acabou")
                {
                    crate::log_error!("teste", "{}", r);
                    return Err("a leitura depois do FIM nao ouviu o motivo");
                }
                if b.avisos_depois_do_sossego(desde_b, "fluxo", n) != [malha::FIM] {
                    crate::log_error!("teste", "{:?}", b.avisos(desde_b));
                    return Err("o aborto avisou mais de uma vez, ou depois do fim");
                }
                Ok(())
            })();
            if r.is_err() {
                let _ = c.encerrar();
            }
            r
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS04 — o endpoint
// ---------------------------------------------------------------------------

/// O endpoint oferecido com o aviso: o pedido de fluxo dá `PEDIDO` — um
/// só para dois pedidos —, o aceite pelo gate consome e rearma com o que
/// ficou na fila; a entrega dá `ENTREGA`, o `fabric.recv` pelo gate consome,
/// e a entrega seguinte avisa de novo.
pub(super) fn aviso_o_endpoint_avisa_o_pedido_e_a_entrega() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 404);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let e = b.numero_do_endpoint();
            let desde = crate::log::total_emitidos();
            let primeiro = fs_texto(&abrir(a.quem(), &b.endpoint), "stream")
                .ok_or("o primeiro pedido nao passou")?;
            b.esperar_aviso(desde, "endpoint", e, malha::PEDIDO)?;
            let segundo = fs_texto(&abrir(a.quem(), &b.endpoint), "stream")
                .ok_or("o segundo pedido nao passou")?;
            if b.avisos_depois_do_sossego(desde, "endpoint", e) != [malha::PEDIDO] {
                crate::log_error!("teste", "{:?}", b.avisos(desde));
                return Err("dois pedidos avisaram duas vezes");
            }
            // O aceite consome; ficou um na fila: avisa de novo.
            let desde = crate::log::total_emitidos();
            if fs_texto(&aceitar(b.quem(), &b.endpoint), "stream") != Some(primeiro) {
                return Err("o aceite nao pegou o primeiro pedido");
            }
            b.esperar_aviso(desde, "endpoint", e, malha::PEDIDO)?;
            let desde = crate::log::total_emitidos();
            if fs_texto(&aceitar(b.quem(), &b.endpoint), "stream") != Some(segundo) {
                return Err("o aceite nao pegou o segundo pedido");
            }
            if !b.avisos_depois_do_sossego(desde, "endpoint", e).is_empty() {
                return Err("a fila vazia ainda avisou");
            }
            // A entrega.
            let desde = crate::log::total_emitidos();
            if !fs_ok(&mandar_na_malha(a.quem(), &b.endpoint, "um", 9_401_001)) {
                return Err("a entrega nao passou");
            }
            b.esperar_aviso(desde, "endpoint", e, malha::ENTREGA)?;
            let recebidas = fs_pedir(
                b.quem(),
                "fabric.recv",
                &format!(r#"{{"endpoint":"{}"}}"#, b.endpoint),
            );
            if !fs_ok(&recebidas) || !recebidas.contains("\"um\"") {
                crate::log_error!("teste", "{}", recebidas);
                return Err("o fabric.recv nao trouxe a entrega");
            }
            if b.avisos_depois_do_sossego(desde, "endpoint", e) != [malha::ENTREGA] {
                crate::log_error!("teste", "{:?}", b.avisos(desde));
                return Err("a entrega lida ainda avisou");
            }
            let desde = crate::log::total_emitidos();
            if !fs_ok(&mandar_na_malha(a.quem(), &b.endpoint, "dois", 9_401_002)) {
                return Err("a segunda entrega nao passou");
            }
            b.esperar_aviso(desde, "endpoint", e, malha::ENTREGA)
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS05 — um canal só
// ---------------------------------------------------------------------------

/// Um processo, um canal: o endpoint, três fluxos e os outros eventos — os
/// passos da suíte, um tipo que o laço não conhece, um aviso de um tipo de
/// objeto que ele não conhece, os `TESTE` — chegam no mesmo `ler_eventos`, e
/// o laço passa por todos sem parar no que não conhece.
pub(super) fn aviso_um_canal_so() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 405);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let desde = crate::log::total_emitidos();
            let mut fluxos = Vec::new();
            for _ in 0..3 {
                fluxos.push(aberto(&a, &b, false, true)?);
            }
            b.esperar_aviso(desde, "endpoint", b.numero_do_endpoint(), malha::PEDIDO)?;
            let desde = crate::log::total_emitidos();
            escrito(
                &escrever(a.quem(), &fluxos[0].0, b"1"),
                1,
                "a escrita nao entrou",
            )?;
            b.publicar(Evento {
                tipo: tipo::MALHA,
                a: 7,
                b: 1,
                c: malha::LEGIVEL,
            })?;
            b.publicar(Evento {
                tipo: 99,
                a: 5,
                ..Default::default()
            })?;
            escrito(
                &escrever(a.quem(), &fluxos[1].0, b"2"),
                1,
                "a escrita nao entrou",
            )?;
            b.publicar(Evento {
                tipo: tipo::TESTE,
                ..Default::default()
            })?;
            escrito(
                &escrever(a.quem(), &fluxos[2].0, b"3"),
                1,
                "a escrita nao entrou",
            )?;
            for (_, n) in &fluxos {
                b.esperar_aviso(desde, "fluxo", *n, malha::LEGIVEL)?;
            }
            b.dito(desde, "evento 99 5")?;
            let contados = b.ditar(CONTAR, 0, 0)?;
            if b.dito(contados, "testes ")? != "1" {
                return Err("o laco nao contou o TESTE");
            }
            if b.avisos(desde)
                .iter()
                .any(|v| v.tipo != "fluxo" && v.tipo != "endpoint")
            {
                return Err("o laco disse um aviso de um tipo que nao conhece");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS06 — os dois sentidos ao mesmo tempo
// ---------------------------------------------------------------------------

/// Os dois sentidos, 64 KiB de cada lado, ao mesmo tempo, guiados só pelo
/// laço: cada lado escreve o que cabe, lê o que há e dorme no canal — sem
/// impasse, e os bytes conferem. O controle: o estilo do DN-2, que escreve
/// tudo esperando espaço antes de ler, nos mesmos números, vence o prazo dos
/// dois lados.
pub(super) fn aviso_os_dois_sentidos_sem_impasse() -> Resultado {
    const N: usize = 64 * 1024;
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 406);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let n = aberto_pelos_programas(&a, &b)?;
            let desde = a.ditar(DUPLEX, n as i64, N as i64)?;
            b.ditar(DUPLEX, n as i64, N as i64)?;
            let esperado = format!("{n} {N} {:016x} ", super::fluxo::resumo((0..N).map(padrao)));
            for p in [&a, &b] {
                let d = p.dito(desde, "duplex ")?;
                if !d.starts_with(&esperado) {
                    crate::log_error!("teste", "{}: {} e nao {}", p.fio(), d, esperado);
                    return Err("os dois sentidos pelo laco nao trouxeram os bytes");
                }
            }
            // O controle, num fluxo novo.
            let desde_a = crate::log::total_emitidos();
            let desde = a.ditar(ABRIR, 1, 0)?;
            let m = numero(&a.dito(desde, "abri ")?)?;
            let desde = b.ditar(ACEITAR, 1, 0)?;
            if numero(&b.dito(desde, "aceitei ")?)? != m {
                return Err("o avisado aceitou outro fluxo");
            }
            a.esperar_aviso(desde_a, "fluxo", m, malha::GRAVAVEL)?;
            let desde = a.ditar(BLOQUEANTE, m as i64, N as i64)?;
            b.ditar(BLOQUEANTE, m as i64, N as i64)?;
            for p in [&a, &b] {
                if p.dito(desde, "bloqueante ")? != format!("{m} prazo") {
                    return Err("o estilo bloqueante nos dois sentidos nao venceu o prazo");
                }
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

/// O byte `i` do padrão do `avisado`.
pub(in crate::testes) fn padrao(i: usize) -> u8 {
    ((i * 7 + 3) % 251) as u8
}

// ---------------------------------------------------------------------------
// NS07 — sem notify, tudo como antes
// ---------------------------------------------------------------------------

/// Sem `notify`, nada muda: o fluxo de dois processos sem o aviso anda como
/// no DN-2, sem designação e sem evento nenhum; e o mesmo processo tem, ao
/// mesmo tempo, um fluxo com o aviso e outro sem — só o primeiro avisa.
pub(super) fn aviso_sem_notify_tudo_como_antes() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 407);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let antes = crate::aviso::medidas();
            let (sem, n) = aberto(&a, &b, false, false)?;
            let (com, m) = aberto(&a, &b, false, true)?;
            if crate::aviso::situacao_de_teste(b.ponta(n)).is_some()
                || crate::aviso::situacao_de_teste(a.ponta(n)).is_some()
            {
                return Err("o fluxo sem notify foi designado");
            }
            if crate::aviso::situacao_de_teste(b.ponta(m)).is_none() {
                return Err("o fluxo com notify nao foi designado");
            }
            let desde = crate::log::total_emitidos();
            escrito(
                &escrever(a.quem(), &sem, b"sem"),
                3,
                "a escrita sem aviso nao entrou",
            )?;
            escrito(
                &escrever(a.quem(), &com, b"com"),
                3,
                "a escrita com aviso nao entrou",
            )?;
            b.esperar_aviso(desde, "fluxo", m, malha::LEGIVEL)?;
            if !b.avisos_depois_do_sossego(desde, "fluxo", n).is_empty() {
                return Err("o fluxo sem notify avisou");
            }
            ler_e_conferir(
                b.quem(),
                &sem,
                10,
                b"sem",
                false,
                "o fluxo sem aviso nao andou",
            )?;
            ler_e_conferir(
                b.quem(),
                &com,
                10,
                b"com",
                false,
                "o fluxo com aviso nao andou",
            )?;
            // Dois avisos de endpoint (os pedidos) e um de fluxo; nada mais.
            let depois = crate::aviso::medidas();
            if depois.publicados - antes.publicados > 4 {
                crate::log_error!("teste", "{:?} -> {:?}", antes, depois);
                return Err("o fluxo sem notify publicou");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS08 — o canal que o processo não escuta
// ---------------------------------------------------------------------------

/// O filho de um `fork` tem o descritor do canal do pai, e não o canal: o
/// `notify` com ele é recusado — `INVALID_ARGUMENT`, sem dizer de quem é o
/// canal —, nenhum fluxo é criado, nenhuma designação é do filho, e a
/// recusa vai à auditoria como a execução da decisão.
pub(super) fn aviso_o_canal_que_o_processo_nao_escuta() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 408);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let antes = crate::autorizacao::ultimo_registro();
            let recusados = crate::aviso::medidas().recusados;
            let desde = a.ditar(BIFURCAR, 0, 0)?;
            let filho: u64 = a
                .dito(desde, "filho ")?
                .parse()
                .map_err(|_| "o pai nao disse o filho")?;
            let pediu = dito_na_malha(desde, &format!("avisado {filho}: filho pediu "))?;
            if pediu != "INVALID_ARGUMENT" {
                crate::log_error!("teste", "o filho ouviu {}", pediu);
                return Err("o filho designou o canal do pai");
            }
            if crate::fluxo::contagem() != (0, 0) {
                return Err("o pedido recusado criou um fluxo");
            }
            if crate::aviso::designacoes_de_teste(filho) != 0 {
                return Err("o filho tem uma designacao");
            }
            if crate::aviso::medidas().recusados <= recusados {
                return Err("a recusa do notify nao foi contada");
            }
            esperar_ate(
                || {
                    gravado_na_malha(
                        antes,
                        "stream.open",
                        &format!("intencao:{INTENCAO}"),
                        Codigo::InvalidArgument,
                        crate::aviso::RECUSA,
                    )
                },
                TETO_DA_MALHA,
            )
            .map_err(|_| "a recusa do notify nao foi gravada")?;
            esperar_ate(
                || linhas_do_programa(desde, &format!("processo encerrou com codigo {SAIDA}")) == 1,
                TETO_DA_MALHA,
            )
            .map_err(|_| "o filho nao terminou")?;
            // O pai, com o mesmo descritor, designa: o canal é dele.
            let (_, n) = aberto(&a, &b, true, false)?;
            if crate::aviso::situacao_de_teste(a.ponta(n)).is_none() {
                return Err("o pai nao designou o canal dele");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS09 — o descritor que não é canal
// ---------------------------------------------------------------------------

/// `notify` com o que não é um canal de eventos do processo: o descritor do
/// log, um que não existe, um número negativo, um texto. Os três primeiros
/// são recusados pelo comando — `INVALID_ARGUMENT`, nada criado —; o texto,
/// pela forma do parâmetro, no registro, com o nome dele. E um comando que
/// não conhece `notify` o recusa pelo nome — nunca o ignora.
pub(super) fn aviso_o_descritor_que_nao_e_canal() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 409);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            for d in [1, 999] {
                let desde = a.ditar(RUIM, d, 0)?;
                if a.dito(desde, "ruim ")? != "INVALID_ARGUMENT" {
                    return Err("o notify que nao e canal foi aceito");
                }
            }
            let com = |notify: &str| {
                fs_pedir(
                    a.quem(),
                    "stream.open",
                    &format!(
                        r#"{{"endpoint":"{}","intent":"{INTENCAO}","notify":{notify}}}"#,
                        b.endpoint
                    ),
                )
            };
            if desfecho_na_malha(&com("-1")) == "ALLOW" {
                return Err("o notify negativo foi aceito");
            }
            if decisao_do_envelope(&com(r#""laco""#)) != "notify" {
                return Err("o notify de texto nao foi recusado pela forma");
            }
            if crate::fluxo::contagem() != (0, 0) {
                return Err("um notify recusado criou um fluxo");
            }
            // O comando que não conhece o parâmetro recusa pelo nome.
            let (id, _) = aberto(&a, &b, false, false)?;
            let r = fs_pedir(
                a.quem(),
                "stream.read",
                &format!(r#"{{"stream":"{id}","notify":{}}}"#, a.descritor),
            );
            if decisao_do_envelope(&r) != "notify" || !r.contains("-32602") {
                crate::log_error!("teste", "{}", r);
                return Err("o comando sem notify nao o recusou pelo nome");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS10 — a recusa do gate não designa
// ---------------------------------------------------------------------------

/// `notify` num pedido que o gate recusa: a recusa de sempre, com o código
/// de sempre — a política sem `fabric.stream`, a intenção fora dela, a
/// política sem `fabric.offer` —, nenhuma designação, nenhum aviso.
pub(super) fn aviso_a_recusa_do_gate_nao_designa() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 410);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let antes_da_politica = crate::autorizacao::com_politica(|p| p.clone());
        let r = (|| -> Resultado {
            let designacoes = crate::aviso::medidas().designacoes;
            let publicados = crate::aviso::medidas().publicados;
            politica_sem("fabric.stream");
            let abrir_sem = abrir_avisando(&a, &b.endpoint);
            let aceitar_sem = aceitar_avisando(&b);
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
            let sem_a_intencao = politica_trocada(&[(
                "recurso operador fabric.stream intencao:imagem.compartilhar intencao:pdf.anotar",
                "recurso operador fabric.stream intencao:pdf.anotar",
            )])?;
            crate::autorizacao::restaurar_politica(sem_a_intencao);
            let fora = abrir_avisando(&a, &b.endpoint);
            crate::autorizacao::restaurar_politica(antes_da_politica.clone());
            recusado(&fora, "DENY_RESOURCE", "a intencao fora da politica abriu")?;
            politica_sem("fabric.offer");
            let oferecer = fs_pedir(
                a.quem(),
                "fabric.offer",
                &format!(r#"{{"intent":"pdf.anotar","notify":{}}}"#, a.descritor),
            );
            crate::autorizacao::restaurar_politica(antes_da_politica.clone());
            recusado(
                &oferecer,
                "DENY_PERMISSION",
                "a politica sem a permissao ofereceu",
            )?;
            // O aceite recusado nomeando um endpoint que ninguém designou —
            // oferecido sem `notify`, para outra intenção: continua sem
            // designação.
            let r = fs_pedir(b.quem(), "fabric.offer", r#"{"intent":"pdf.anotar"}"#);
            let outro = fs_texto(&r, "endpoint").ok_or("o dono nao abriu outro endpoint")?;
            if outro == b.endpoint {
                return Err("a oferta da outra intencao devolveu o mesmo endpoint");
            }
            let numero =
                politica::aviso::numero_do_id(&outro).ok_or("o endpoint novo nao tem numero")?;
            if crate::aviso::situacao_de_teste(Objeto::Endpoint(numero)).is_some() {
                return Err("a oferta sem notify designou o endpoint");
            }
            politica_sem("fabric.stream");
            let aceitar_no_outro = fs_pedir(
                b.quem(),
                "stream.accept",
                &format!(r#"{{"endpoint":"{outro}","notify":{}}}"#, b.descritor),
            );
            crate::autorizacao::restaurar_politica(antes_da_politica.clone());
            recusado(
                &aceitar_no_outro,
                "DENY_PERMISSION",
                "a politica sem a permissao aceitou no endpoint sem aviso",
            )?;
            if crate::aviso::situacao_de_teste(Objeto::Endpoint(numero)).is_some() {
                return Err("o aceite recusado designou o endpoint que nomeou");
            }
            feito(
                &fs_pedir(
                    b.quem(),
                    "fabric.withdraw",
                    &format!(r#"{{"endpoint":"{outro}"}}"#),
                ),
                "o dono nao retirou o endpoint sem aviso",
            )?;
            if crate::fluxo::contagem() != (0, 0) {
                return Err("um pedido recusado criou um fluxo");
            }
            let m = crate::aviso::medidas();
            if m.designacoes != designacoes || m.publicados != publicados {
                crate::log_error!("teste", "{:?}", m);
                return Err("um pedido recusado pelo gate designou ou avisou");
            }
            Ok(())
        })();
        crate::autorizacao::restaurar_politica(antes_da_politica);
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS11 — a revogação entre o aviso e a leitura
// ---------------------------------------------------------------------------

/// O aviso chega, e antes da leitura a pessoa é revogada: a leitura que
/// segue o aviso é recusada, ou ouve o fim — nunca traz o dado. O aviso
/// não carregou nada: só o tipo, o número e os bits.
pub(super) fn aviso_a_revogacao_entre_o_aviso_e_a_leitura() -> Resultado {
    com_os_avisos(|| {
        let (sessao, edu) = pessoa("edu", 411);
        let id_edu = super::pessoa_da_sessao(sessao)?;
        let a = Avisado::lancar(edu)?;
        let b = Avisado::lancar(edu)?;
        let r = (|| -> Resultado {
            let (id, n) = aberto(&a, &b, false, true)?;
            let desde = crate::log::total_emitidos();
            escrito(
                &escrever(a.quem(), &id, b"segredo"),
                7,
                "a escrita nao entrou",
            )?;
            b.esperar_aviso(desde, "fluxo", n, malha::LEGIVEL)?;
            crate::pessoas::revogar_pessoa(id_edu).map_err(|_| "a pessoa nao foi revogada")?;
            nada_vivo("a pessoa revogada deixou um fluxo")?;
            let r = ler(b.quem(), &id, 100);
            if fs_ok(&r) || r.contains("c2VncmVkbw") {
                crate::log_error!("teste", "{}", r);
                return Err("a leitura depois da revogacao trouxe o dado");
            }
            // O pedido do endpoint de `b` pode ser contado depois de
            // `desde` — o processo escreve o aviso quando roda —, e a
            // revogação fecha o endpoint (`FIM`): cada tipo com os seus bits.
            let conhecidos = |tipo: &str| match tipo {
                "fluxo" => malha::LEGIVEL | malha::FIM,
                "endpoint" => malha::PEDIDO | malha::ENTREGA | malha::FIM,
                _ => 0,
            };
            if b.avisos(desde)
                .iter()
                .any(|v| v.bits == 0 || v.bits & !conhecidos(&v.tipo) != 0)
            {
                return Err("o aviso levou mais que os bits");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS12 — o evento só tem o tipo, o número e os bits
// ---------------------------------------------------------------------------

/// O que o evento leva, conferido contra um fluxo que levou bytes
/// conhecidos: o tipo `MALHA`; `a`, o tipo do objeto; `b`, o número do id —
/// o mesmo que o processo já tem —; `c`, só bits conhecidos. Nenhum campo
/// vem dos bytes: o padrão do fluxo foi escolhido para que qualquer pedaço
/// dele, posto em `b` ou `c`, diferisse do esperado.
pub(super) fn aviso_o_evento_so_tem_tipo_numero_e_bits() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 412);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let (id, n) = aberto(&a, &b, true, true)?;
            let desde = crate::log::total_emitidos();
            let bytes: Vec<u8> = (0u8..64).map(|i| 0xe0 | (i & 0x1f)).collect();
            escrito(&escrever(a.quem(), &id, &bytes), 64, "a escrita nao entrou")?;
            b.esperar_aviso(desde, "fluxo", n, malha::LEGIVEL)?;
            ler_e_conferir(
                b.quem(),
                &id,
                100,
                &bytes,
                false,
                "a leitura nao trouxe os bytes",
            )?;
            feito(
                &sobre(a.quem(), "stream.finish", &id),
                "o finish nao passou",
            )?;
            // O fim do sentido avisa de novo: o segundo aviso do fluxo — e,
            // depois do sossego, nenhum outro.
            esperar_ate(|| b.avisos_de(desde, "fluxo", n).len() >= 2, TETO_DA_MALHA)
                .map_err(|_| "o fim do sentido nao avisou")?;
            let _ = esperar_ate(|| false, SOSSEGO);
            let vistos = b.avisos(desde);
            for v in &vistos {
                let conhecido = match v.tipo.as_str() {
                    "fluxo" => {
                        v.numero == n
                            && v.bits & !(malha::LEGIVEL | malha::GRAVAVEL | malha::FIM) == 0
                    }
                    "endpoint" => {
                        v.numero == b.numero_do_endpoint()
                            && v.bits & !(malha::PEDIDO | malha::ENTREGA | malha::FIM) == 0
                    }
                    _ => false,
                };
                if !conhecido || v.bits == 0 {
                    crate::log_error!("teste", "{:?}", v);
                    return Err("um aviso levou o que nao e tipo, numero e bits");
                }
            }
            if vistos.iter().filter(|v| v.tipo == "fluxo").count() != 2 {
                crate::log_error!("teste", "{:?}", vistos);
                return Err("o fluxo nao avisou o dado e o fim, uma vez cada");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS13 — cada processo no seu canal
// ---------------------------------------------------------------------------

/// Dois processos, dois canais: o dado que `a` escreve avisa só `b`; o que
/// `b` escreve avisa só `a`; e um terceiro processo, com o canal dele e o
/// endpoint designado, nunca ouve nada do fluxo dos outros.
pub(super) fn aviso_cada_processo_no_seu_canal() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 413);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let c = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let desde = crate::log::total_emitidos();
            let (id, n) = aberto(&a, &b, true, true)?;
            a.esperar_aviso(desde, "fluxo", n, malha::GRAVAVEL)?;
            let desde = crate::log::total_emitidos();
            escrito(
                &escrever(a.quem(), &id, b"de a"),
                4,
                "a escrita de a nao entrou",
            )?;
            b.esperar_aviso(desde, "fluxo", n, malha::LEGIVEL)?;
            if !a.avisos_depois_do_sossego(desde, "fluxo", n).is_empty() {
                return Err("o dado de a avisou o canal de a");
            }
            let desde = crate::log::total_emitidos();
            escrito(
                &escrever(b.quem(), &id, b"de b"),
                4,
                "a escrita de b nao entrou",
            )?;
            a.esperar_aviso(desde, "fluxo", n, malha::LEGIVEL)?;
            if b.avisos_de(desde, "fluxo", n)
                .iter()
                .any(|v| *v != malha::LEGIVEL)
            {
                return Err("o dado de b avisou o canal de b");
            }
            if !c.avisos(0).is_empty() {
                crate::log_error!("teste", "{:?}", c.avisos(0));
                return Err("o terceiro processo ouviu o fluxo dos outros");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b, &c])
    })
}

// ---------------------------------------------------------------------------
// NS14 — só processo designa
// ---------------------------------------------------------------------------

/// A sessão de uma pessoa e um agente pedindo com `notify`: a recusa de
/// sempre — só um processo abre, aceita e oferece —, com o mesmo código que
/// sem o `notify`, e nada designado.
pub(super) fn aviso_so_processo_designa() -> Resultado {
    com_os_avisos(|| {
        let (sessao, bia) = pessoa("bia", 414);
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let designacoes = crate::aviso::medidas().designacoes;
            let quem = [
                Chamador::Pessoa(sessao),
                Chamador::Sessao(crate::agent::sessao::SERIAL),
            ];
            for q in quem {
                for (metodo, sem, com) in [
                    (
                        "stream.open",
                        format!(r#"{{"endpoint":"{}","intent":"{INTENCAO}"}}"#, b.endpoint),
                        format!(
                            r#"{{"endpoint":"{}","intent":"{INTENCAO}","notify":3}}"#,
                            b.endpoint
                        ),
                    ),
                    (
                        "stream.accept",
                        format!(r#"{{"endpoint":"{}"}}"#, b.endpoint),
                        format!(r#"{{"endpoint":"{}","notify":3}}"#, b.endpoint),
                    ),
                    (
                        "fabric.offer",
                        String::from(r#"{"intent":"pdf.anotar"}"#),
                        String::from(r#"{"intent":"pdf.anotar","notify":3}"#),
                    ),
                ] {
                    let sem = desfecho_na_malha(&fs_pedir(q, metodo, &sem));
                    let com = desfecho_na_malha(&fs_pedir(q, metodo, &com));
                    if sem == "ALLOW" || sem != com {
                        crate::log_error!("teste", "{} sem {} com {}", metodo, sem, com);
                        return Err("o notify mudou a recusa de quem nao e processo");
                    }
                }
            }
            if crate::aviso::medidas().designacoes != designacoes {
                return Err("quem nao e processo designou");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&b])
    })
}

// ---------------------------------------------------------------------------
// NS15 — a política que tira a permissão no meio
// ---------------------------------------------------------------------------

/// A política tira `fabric.stream` com o fluxo aberto. Com o dado avisado e
/// ainda não lido, a leitura de quem recebeu o aviso é a primeira operação
/// depois da política nova: o aviso não leva autoridade — o gate a recusa,
/// o dado não sai, e o fluxo acaba com o motivo do gate. Noutro fluxo, a
/// escrita seguinte é recusada pelo gate, o fluxo acaba com o motivo do
/// gate, e a outra ponta — livre, sem aviso pendente — recebe `FIM`; a
/// leitura dela ouve o motivo; e nada mais vem.
pub(super) fn aviso_a_politica_que_tira_a_permissao() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 415);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let antes_da_politica = crate::autorizacao::com_politica(|p| p.clone());
        let r = (|| -> Resultado {
            // A leitura avisada, primeira depois da política nova.
            let antes = crate::autorizacao::ultimo_registro();
            let (id, n) = aberto(&a, &b, true, true)?;
            let desde = crate::log::total_emitidos();
            escrito(
                &escrever(a.quem(), &id, b"avisado"),
                7,
                "a escrita nao entrou",
            )?;
            b.esperar_aviso(desde, "fluxo", n, malha::LEGIVEL)?;
            politica_sem("fabric.stream");
            let r = ler(b.quem(), &id, 10);
            crate::autorizacao::restaurar_politica(antes_da_politica.clone());
            recusado(
                &r,
                "DENY_PERMISSION",
                "a leitura avisada passou pela politica nova",
            )?;
            if fs_texto(&r, "content").is_some() {
                return Err("a leitura recusada trouxe o dado");
            }
            // A recusa é a decisão do gate, gravada como tal: a
            // reconfirmação dentro da operação é a segunda conferência, e
            // não a única.
            let lidas = registros_depois(antes, |e| e.metodo == "stream.read");
            if lidas.is_empty() || lidas.iter().any(|(_, e)| e.codigo == Codigo::Allow) {
                crate::log_error!("teste", "{:?}", lidas);
                return Err("a leitura avisada nao foi recusada pela decisao do gate");
            }
            fim_gravado_com(antes, &id, "DENY_PERMISSION: ")?;
            a.esperar_aviso(desde, "fluxo", n, malha::FIM)?;
            // A escrita, primeira depois da política nova, noutro fluxo.
            let antes = crate::autorizacao::ultimo_registro();
            let (id, n) = aberto(&a, &b, true, true)?;
            let desde = crate::log::total_emitidos();
            politica_sem("fabric.stream");
            let r = escrever(a.quem(), &id, b"depois");
            crate::autorizacao::restaurar_politica(antes_da_politica.clone());
            recusado(
                &r,
                "DENY_PERMISSION",
                "a politica nova nao recusou a escrita",
            )?;
            fim_gravado_com(antes, &id, "DENY_PERMISSION: ")?;
            b.esperar_aviso(desde, "fluxo", n, malha::FIM)?;
            let r = ler(b.quem(), &id, 10);
            if desfecho_na_malha(&r) != "CONFLICT"
                || !fs_texto(&r, "error").is_some_and(|m| m.starts_with("DENY_PERMISSION"))
            {
                crate::log_error!("teste", "{}", r);
                return Err("a outra ponta nao ouviu o motivo do gate");
            }
            if b.avisos_depois_do_sossego(desde, "fluxo", n) != [malha::FIM] {
                crate::log_error!("teste", "{:?}", b.avisos(desde));
                return Err("o fim pela politica avisou mais de uma vez");
            }
            Ok(())
        })();
        crate::autorizacao::restaurar_politica(antes_da_politica);
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS16 — o fim contra a leitura
// ---------------------------------------------------------------------------

/// O fio que aborta o fluxo da corrida.
static ABORTAR: AtomicU64 = AtomicU64::new(0);
static ABORTOU: AtomicUsize = AtomicUsize::new(0);

extern "C" fn abortador(_: u64) -> ! {
    let fio = ABORTAR.load(SeqCst);
    crate::fluxo::canal_acabou(politica::mensagens::Canal::Processo(fio));
    ABORTOU.fetch_add(1, SeqCst);
    crate::fios::terminar()
}

/// O fim do fluxo e a leitura da outra ponta ao mesmo tempo, muitas vezes:
/// o `FIM` sai no máximo uma vez, e nunca depois de a leitura ouvir o fim —
/// a operação que ouve o motivo larga a designação pela mesma trava em que
/// o aviso é publicado: ou o aviso já estava no canal, ou não sai mais.
pub(super) fn aviso_o_fim_contra_a_leitura() -> Resultado {
    const VEZES: usize = 12;
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 416);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            for i in 0..VEZES {
                let (id, n) = aberto(&a, &b, false, true)?;
                let desde = crate::log::total_emitidos();
                escrito(&escrever(a.quem(), &id, b"x"), 1, "a escrita nao entrou")?;
                b.esperar_aviso(desde, "fluxo", n, malha::LEGIVEL)?;
                ler_e_conferir(b.quem(), &id, 10, b"x", false, "a leitura nao trouxe o x")?;
                ABORTAR.store(a.fio(), SeqCst);
                let antes = ABORTOU.load(SeqCst);
                crate::fios::criar("teste-aviso", abortador, i as u64)?;
                // Lê até ouvir o fim.
                let mut fim = false;
                esperar_cedendo(
                    || {
                        let r = ler(b.quem(), &id, 10);
                        fim = desfecho_na_malha(&r) == "CONFLICT";
                        fim
                    },
                    TETO_DA_MALHA,
                )
                .map_err(|_| "a leitura nao ouviu o fim")?;
                let publicados = crate::aviso::medidas().publicados;
                esperar_cedendo(|| ABORTOU.load(SeqCst) > antes, TETO_DA_MALHA)
                    .map_err(|_| "o fio que aborta nao acabou")?;
                let _ = esperar_ate(|| false, 5);
                if crate::aviso::medidas().publicados != publicados {
                    return Err("um aviso foi publicado depois de a leitura ouvir o fim");
                }
                if crate::aviso::situacao_de_teste(b.ponta(n)).is_some() {
                    return Err("a designacao ficou depois do fim ouvido");
                }
                let vistos = b.avisos_depois_do_sossego(desde, "fluxo", n);
                if vistos.iter().filter(|v| **v & malha::FIM != 0).count() > 1 {
                    crate::log_error!("teste", "{:?}", vistos);
                    return Err("o fim avisou mais de uma vez");
                }
            }
            // O fecho de quem tem a designação, com a conta da ponta caindo
            // entre o fecho e o largar — o que uma operação do par, ou o
            // coletor, faria nessa janela: quem fechou já sabe do fim, e
            // nada é publicado para ele.
            let (id, n) = aberto(&a, &b, false, true)?;
            let _ = esperar_ate(|| false, SOSSEGO);
            let publicados = crate::aviso::medidas().publicados;
            crate::aviso::contar_no_proximo_fecho_de_teste();
            feito(
                &sobre(b.quem(), "stream.close", &id),
                "o dono nao fechou o fluxo",
            )?;
            let _ = esperar_ate(|| false, SOSSEGO);
            if crate::aviso::medidas().publicados != publicados {
                return Err("quem fechou foi avisado do fim que ja sabia");
            }
            if crate::aviso::situacao_de_teste(b.ponta(n)).is_some() {
                return Err("a designacao ficou depois do fecho");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS17 — a troca de imagem
// ---------------------------------------------------------------------------

/// O `exec` larga as designações do processo antes de a imagem nova
/// começar: o endpoint e a ponta saem da tabela, o par que escreve depois
/// não avisa ninguém, e a imagem nova não ouve aviso nenhum da anterior.
pub(super) fn aviso_a_troca_de_imagem_larga_as_designacoes() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 417);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let (id, n) = aberto(&a, &b, false, true)?;
            if crate::aviso::designacoes_de_teste(b.fio()) != 2 {
                return Err("o endpoint e a ponta nao estavam designados");
            }
            let publicados = crate::aviso::medidas().publicados;
            let desde = b.ditar(TROCAR, 0, 0)?;
            b.dito(desde, "trocando")?;
            esperar_ate(
                || crate::aviso::designacoes_de_teste(b.fio()) == 0,
                TETO_DA_MALHA,
            )
            .map_err(|_| "a troca de imagem nao largou as designacoes")?;
            // O canal da imagem velha — se ainda existe — não recebe nada
            // do que o par faz depois da troca.
            let no_canal = || crate::eventos::estado(&b.canal).map(|e| e.publicados);
            let antes_no_canal = no_canal();
            let _ = escrever(a.quem(), &id, b"para a imagem velha");
            let _ = abrir(a.quem(), &b.endpoint);
            let _ = esperar_ate(|| false, SOSSEGO);
            if crate::aviso::medidas().publicados != publicados {
                return Err("um aviso foi publicado para a imagem trocada");
            }
            if no_canal().is_some() && no_canal() != antes_no_canal {
                return Err("o canal da imagem trocada recebeu um aviso");
            }
            esperar_ate(
                || linhas_do_programa(desde, &format!("processo encerrou com codigo {SAIDA}")) == 1,
                TETO_DA_MALHA,
            )
            .map_err(|_| "a imagem nova nao terminou")?;
            if estado(a.quem(), &id).1.as_deref() != Some("o programa mudou") {
                return Err("o fluxo nao acabou com a troca de imagem");
            }
            let _ = n;
            Ok(())
        })();
        // `b` já saiu.
        encerrar_todos(r, &[&a])
    })
}

// ---------------------------------------------------------------------------
// NS18 — a morte e o canal sem ouvinte
// ---------------------------------------------------------------------------

/// A morte do processo larga as designações dele — nada é publicado no
/// canal que sumiu —; e a designação cujo canal ficou sem ouvinte — o
/// processo, vivo, fechou o descritor — cai na primeira publicação, contada
/// nas medidas, e nada fica tentando.
pub(super) fn aviso_a_morte_e_o_canal_sem_ouvinte() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 418);
        let a = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            // A morte: as designações de `b` saem com ele.
            let b = Avisado::lancar(bia)?;
            let (id, _) = match aberto(&a, &b, false, true) {
                Ok(x) => x,
                Err(e) => return encerrar_todos(Err(e), &[&b]),
            };
            b.encerrar()?;
            esperar_ate(
                || crate::aviso::designacoes_de_teste(b.fio()) == 0,
                TETO_DA_MALHA,
            )
            .map_err(|_| "a morte nao largou as designacoes")?;
            let publicados = crate::aviso::medidas().publicados;
            let _ = escrever(a.quem(), &id, b"para ninguem");
            let _ = esperar_ate(|| false, SOSSEGO);
            if crate::aviso::medidas().publicados != publicados {
                return Err("um aviso foi publicado para o processo morto");
            }
            // O canal sem ouvinte: o processo vive, o canal designado não.
            let c = Avisado::lancar(bia)?;
            let r = (|| -> Resultado {
                let desde = c.ditar(OUTRO_CANAL, 0, 0)?;
                let d2: u64 = c
                    .dito(desde, "outro ")?
                    .parse()
                    .map_err(|_| "o avisado nao disse o outro descritor")?;
                let r = abrir(a.quem(), &c.endpoint);
                let id = fs_texto(&r, "stream").ok_or("o pedido nao passou")?;
                let r = fs_pedir(
                    c.quem(),
                    "stream.accept",
                    &format!(r#"{{"endpoint":"{}","notify":{d2}}}"#, c.endpoint),
                );
                if fs_texto(&r, "stream").as_deref() != Some(id.as_str()) {
                    crate::log_error!("teste", "{}", r);
                    return Err("o aceite com o outro canal nao passou");
                }
                let n = numero_do_fluxo(&id)?;
                if crate::aviso::situacao_de_teste(c.ponta(n)).is_none() {
                    return Err("o outro canal nao foi designado");
                }
                let vaga = crate::eventos::vaga_de_teste(&format!("teste-avisado-{}-2", c.fio()))
                    .ok_or("o outro canal nao esta aberto")?;
                let desde = c.ditar(FECHAR_OUTRO, d2 as i64, 0)?;
                if c.dito(desde, "fechei_outro ")? != "0" {
                    return Err("o avisado nao fechou o outro canal");
                }
                // A vaga do canal fechado volta a ser de alguém — canais da
                // suíte, até um cair nela: a designação guarda a geração do
                // canal que acabou, e o canal novo na mesma vaga não é dele.
                let ouvinte = crate::fios::id_atual();
                let mut da_suite: Vec<crate::eventos::Chave> = Vec::new();
                while !da_suite.iter().any(|k| k.vaga == vaga) {
                    let nome = format!("teste-vaga-{}", da_suite.len());
                    match crate::eventos::escutar(nome.as_bytes(), ouvinte) {
                        Ok(k) => da_suite.push(k),
                        Err(_) => break,
                    }
                }
                let r = (|| -> Resultado {
                    if !da_suite.iter().any(|k| k.vaga == vaga) {
                        return Err("a vaga do canal fechado nao voltou a ser de ninguem");
                    }
                    let largados = crate::aviso::medidas().largados;
                    escrito(
                        &escrever(a.quem(), &id, b"sem canal"),
                        9,
                        "a escrita nao entrou",
                    )?;
                    esperar_ate(
                        || crate::aviso::situacao_de_teste(c.ponta(n)).is_none(),
                        TETO_DA_MALHA,
                    )
                    .map_err(|_| "a designacao sem ouvinte nao caiu")?;
                    if crate::aviso::medidas().largados <= largados {
                        return Err("a designacao sem ouvinte nao foi contada");
                    }
                    let cruzou = da_suite.iter().any(|k| {
                        crate::eventos::nome_de(*k)
                            .and_then(|nome| crate::eventos::estado(&nome))
                            .is_some_and(|e| e.publicados > 0)
                    });
                    if cruzou {
                        return Err("o aviso cruzou para o canal novo na mesma vaga");
                    }
                    Ok(())
                })();
                for k in da_suite {
                    crate::eventos::largar(k, ouvinte);
                }
                r?;
                // Nada mais tenta: o dado seguinte não acha designação.
                let publicados = crate::aviso::medidas().publicados;
                escrito(
                    &escrever(a.quem(), &id, b"de novo"),
                    7,
                    "a escrita nao entrou",
                )?;
                let _ = esperar_ate(|| false, SOSSEGO);
                if crate::aviso::medidas().publicados != publicados {
                    return Err("o canal sem ouvinte continuou recebendo tentativas");
                }
                Ok(())
            })();
            encerrar_todos(r, &[&c])
        })();
        encerrar_todos(r, &[&a])
    })
}

// ---------------------------------------------------------------------------
// NS19 — o canal cheio
// ---------------------------------------------------------------------------

/// O canal cheio — a suíte o enche de `TESTE` enquanto o processo está
/// parado — deixa o aviso devido; o coletor tenta de novo, e o aviso chega
/// uma vez, depois de o processo esvaziar o canal.
pub(super) fn aviso_o_canal_cheio_deixa_devido() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 419);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let (id, n) = aberto(&a, &b, false, true)?;
            let antes = crate::aviso::medidas();
            let desde = b.ditar(PAUSAR, 3000, 0)?;
            b.dito(desde, "pausando")?;
            let mut postos = 0;
            while b
                .publicar(Evento {
                    tipo: tipo::TESTE,
                    ..Default::default()
                })
                .is_ok()
            {
                postos += 1;
                if postos > crate::eventos::CAPACIDADE {
                    return Err("o canal nao encheu");
                }
            }
            escrito(
                &escrever(a.quem(), &id, b"cheio"),
                5,
                "a escrita nao entrou",
            )?;
            esperar_ate(
                || crate::aviso::medidas().devidos > antes.devidos,
                TETO_DA_MALHA,
            )
            .map_err(|_| "o aviso no canal cheio nao ficou devido")?;
            b.esperar_aviso(desde, "fluxo", n, malha::LEGIVEL)?;
            if b.avisos_depois_do_sossego(desde, "fluxo", n) != [malha::LEGIVEL] {
                crate::log_error!("teste", "{:?}", b.avisos(desde));
                return Err("o aviso devido chegou mais de uma vez");
            }
            let depois = crate::aviso::medidas();
            if depois.entregues_depois <= antes.entregues_depois {
                return Err("a entrega do devido nao foi contada");
            }
            let contados = b.ditar(CONTAR, 0, 0)?;
            if b.dito(contados, "testes ")? != format!("{postos}") {
                return Err("o processo nao leu os eventos que encheram o canal");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS20 — quatro fluxos ao mesmo tempo
// ---------------------------------------------------------------------------

/// Os fios que escrevem nos quatro fluxos ao mesmo tempo.
static ESCRITAS: crate::trava::Mutex<Vec<(u64, String)>> = crate::trava::Mutex::new(Vec::new());
static ESCREVERAM: AtomicUsize = AtomicUsize::new(0);

extern "C" fn escritor(k: u64) -> ! {
    let alvo = crate::arch::sem_interrupcoes(|| ESCRITAS.lock().get(k as usize).cloned());
    if let Some((fio, id)) = alvo
        && let Some(quem) = chamador_de(fio)
    {
        for _ in 0..4 {
            let _ = escrever(quem, &id, &[k as u8; 64]);
            crate::fios::ceder();
        }
    }
    ESCREVERAM.fetch_add(1, SeqCst);
    crate::fios::terminar()
}

/// Quatro fluxos de um processo, escritos ao mesmo tempo por quatro fios:
/// um aviso de cada, nunca de um no lugar do outro; as leituras em qualquer
/// ordem, cada uma rearmando só o seu; e o dado que chega depois de uma
/// leitura avisa de novo aquele fluxo, e só ele.
pub(super) fn aviso_quatro_fluxos_ao_mesmo_tempo() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 420);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let mut fluxos = Vec::new();
            for _ in 0..4 {
                fluxos.push(aberto(&a, &b, false, true)?);
            }
            crate::arch::sem_interrupcoes(|| {
                *ESCRITAS.lock() = fluxos.iter().map(|(id, _)| (a.fio(), id.clone())).collect()
            });
            ESCREVERAM.store(0, SeqCst);
            let desde = crate::log::total_emitidos();
            for k in 0..4 {
                crate::fios::criar("teste-aviso", escritor, k)?;
            }
            esperar_cedendo(|| ESCREVERAM.load(SeqCst) == 4, TETO_DA_MALHA)
                .map_err(|_| "os fios que escrevem nao acabaram")?;
            for (_, n) in &fluxos {
                b.esperar_aviso(desde, "fluxo", *n, malha::LEGIVEL)?;
            }
            for (_, n) in &fluxos {
                if b.avisos_depois_do_sossego(desde, "fluxo", *n) != [malha::LEGIVEL] {
                    crate::log_error!("teste", "{}: {:?}", n, b.avisos(desde));
                    return Err("um fluxo avisou mais de uma vez, ou nenhuma");
                }
            }
            // As leituras na ordem inversa: cada uma rearma o seu.
            for (k, (id, _)) in fluxos.iter().enumerate().rev() {
                let (d, _) = lido(b.quem(), id, 1000)?;
                if d.len() != 256 || d.iter().any(|x| *x != k as u8) {
                    return Err("um fluxo trouxe o dado de outro");
                }
            }
            let desde = crate::log::total_emitidos();
            escrito(
                &escrever(a.quem(), &fluxos[2].0, b"so este"),
                7,
                "a escrita nao entrou",
            )?;
            b.esperar_aviso(desde, "fluxo", fluxos[2].1, malha::LEGIVEL)?;
            let _ = esperar_ate(|| false, SOSSEGO);
            if b.avisos(desde)
                .iter()
                .any(|v| v.tipo == "fluxo" && v.numero != fluxos[2].1)
            {
                return Err("o dado de um fluxo avisou outro");
            }
            Ok(())
        })();
        crate::arch::sem_interrupcoes(|| ESCRITAS.lock().clear());
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS21 — dois processos sob carga
// ---------------------------------------------------------------------------

/// Dois pares de processos, cada um no seu canal, os dois sentidos de cada
/// fluxo cheios ao mesmo tempo pelo laço: os bytes conferem dos quatro
/// lados, e nenhum canal ouviu o fluxo do outro par.
pub(super) fn aviso_dois_pares_sob_carga() -> Resultado {
    const N: usize = 48 * 1024;
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 421);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let c = Avisado::lancar(bia)?;
        let d = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let n = aberto_pelos_programas_em(&a, &b)?;
            let m = aberto_pelos_programas_em(&c, &d)?;
            let desde = crate::log::total_emitidos();
            for (p, f) in [(&a, n), (&b, n), (&c, m), (&d, m)] {
                p.ditar(DUPLEX, f as i64, N as i64)?;
            }
            let h = super::fluxo::resumo((0..N).map(padrao));
            for (p, f) in [(&a, n), (&b, n), (&c, m), (&d, m)] {
                let dito = p.dito(desde, "duplex ")?;
                if !dito.starts_with(&format!("{f} {N} {h:016x} ")) {
                    crate::log_error!("teste", "{}: {}", p.fio(), dito);
                    return Err("um lado sob carga nao trouxe os bytes");
                }
            }
            for (p, outro) in [(&a, m), (&b, m), (&c, n), (&d, n)] {
                if !p.avisos_de(0, "fluxo", outro).is_empty() {
                    return Err("um canal ouviu o fluxo do outro par");
                }
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b, &c, &d])
    })
}

// ---------------------------------------------------------------------------
// NS22 — o desligamento
// ---------------------------------------------------------------------------

/// Com o reinício a caminho, os fluxos que avisam acabam com `desligando`
/// e cada ponta livre ouve `FIM`; nada novo abre nem é aceito — `CONFLICT`
/// —, e o `notify` desses pedidos não designa nada.
pub(super) fn aviso_o_desligamento_avisa_o_fim() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 422);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let antes = crate::autorizacao::ultimo_registro();
            let desde = crate::log::total_emitidos();
            let (id, n) = aberto(&a, &b, true, true)?;
            // A abertura avisa quem abriu; a operação consome o aviso — com
            // um aviso não consumido, o seguinte não sai, nem o do fim: é a
            // operação que o consome que ouve o motivo.
            a.esperar_aviso(desde, "fluxo", n, malha::GRAVAVEL)?;
            if estado(a.quem(), &id).0.as_deref() != Some("open") {
                return Err("o fluxo nao abriu");
            }
            let desde = crate::log::total_emitidos();
            let _ = crate::energia::executada_de_teste();
            let r = fs_pedir(sistema_aqui(), "system.reboot", "{}");
            if fs_texto(&r, "state").as_deref() != Some("rebooting") {
                crate::log_error!("teste", "{}", r);
                return Err("o reinicio nao foi pedido");
            }
            let designacoes = crate::aviso::designacoes_de_teste(a.fio());
            let abrir_agora = abrir_avisando(&a, &b.endpoint);
            let aceitar_agora = aceitar_avisando(&b);
            let entregue = energia_entregue();
            for r in [&abrir_agora, &aceitar_agora] {
                if desfecho_na_malha(r) != "CONFLICT" {
                    crate::log_error!("teste", "{}", r);
                    return Err("com a maquina indo, um fluxo abriu ou foi aceito");
                }
            }
            if crate::aviso::designacoes_de_teste(a.fio()) > designacoes {
                return Err("o notify no desligamento designou");
            }
            fim_gravado(antes, &id, "desligando; ida 0; volta 0; desc 0")?;
            a.esperar_aviso(desde, "fluxo", n, malha::FIM)?;
            b.esperar_aviso(desde, "fluxo", n, malha::FIM)?;
            if entregue != Some(crate::energia::Acao::Reiniciar) {
                return Err("o reinicio nao chegou ao fim");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS32 — o fim com o aviso não consumido
// ---------------------------------------------------------------------------

/// Acorda o `parado` — parado no passo `PAUSAR`, que espera uma entrega no
/// endpoint dele —: `quem` lhe manda uma.
fn acordar_o_parado(quem: &Avisado, parado: &Avisado, nonce: u64) -> Resultado {
    let r = mandar_na_malha(quem.quem(), &parado.endpoint, "acorda", nonce);
    if !fs_ok(&r) {
        crate::log_error!("teste", "{}", r);
        return Err("a entrega que acorda nao foi mandada");
    }
    Ok(())
}

/// O objeto que acaba com um aviso que o dono ainda não consumiu não avisa
/// o fim de novo — no máximo um aviso não consumido por objeto —, e nada
/// fica guardado sem teto para um dono que não opera:
///
/// - com o aviso ainda na fila (`a` parado), o fim se junta ao evento dele,
///   e a designação sai na hora: `a`, de volta, lê um aviso só de cada
///   fluxo, com a abertura e o fim juntos;
/// - com o aviso já tirado da fila e nenhuma operação de `a`, o fim espera
///   a operação dele — no máximo `ACABADOS_POR_PROCESSO` designações
///   acabadas; as que passam disso caem, contadas com as largadas. A
///   operação de `a` que ouve o fim tira a designação, sem aviso nenhum (a
///   que não o ouve, e acabou com o fluxo, recebe o `FIM` em seguida: o
///   NS03);
/// - com o canal cheio, o fim fica devido, no mesmo teto; com o canal
///   esvaziando, os devidos saem, e as designações com eles.
pub(super) fn aviso_o_fim_com_o_aviso_nao_consumido() -> Resultado {
    use politica::aviso::{ACABADOS_POR_PROCESSO, Situacao};
    // Quanto `a` fica parado, no máximo: a entrega que o acorda vem antes.
    const PARADO_MS: i64 = 120_000;
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 432);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            // O aviso ainda na fila: o fim se junta a ele. `a` fica parado
            // até a entrega que o acorda.
            let antes = crate::aviso::medidas();
            let desde_pausa = a.ditar(PAUSAR, PARADO_MS, 0)?;
            a.dito(desde_pausa, "pausando")?;
            let mut juntos = Vec::new();
            for _ in 0..3 {
                let (_, n) = aberto(&a, &b, true, false)?;
                esperar_ate(
                    || crate::aviso::situacao_de_teste(a.ponta(n)) == Some(Situacao::Avisado),
                    TETO_DA_MALHA,
                )
                .map_err(|_| "o aviso da abertura nao saiu")?;
                crate::fluxo::vencer_de_teste(u64::MAX);
                esperar_ate(
                    || crate::aviso::situacao_de_teste(a.ponta(n)).is_none(),
                    TETO_DA_MALHA,
                )
                .map_err(|_| "o fim junto ao aviso da fila nao largou a designacao")?;
                juntos.push(n);
            }
            if crate::aviso::medidas().juntados < antes.juntados + 3 {
                return Err("o fim nao se juntou ao aviso que esperava na fila");
            }
            if crate::aviso::designacoes_de_teste(a.fio()) != 1 {
                return Err("sobraram designacoes dos fluxos cujo fim se juntou");
            }
            acordar_o_parado(&b, &a, 9_432_001)?;
            a.dito(desde_pausa, "voltei")?;
            for &n in &juntos {
                let _ = esperar_ate(
                    || !a.avisos_de(desde_pausa, "fluxo", n).is_empty(),
                    TETO_DA_MALHA,
                );
                if a.avisos_depois_do_sossego(desde_pausa, "fluxo", n)
                    != [malha::GRAVAVEL | malha::FIM]
                {
                    crate::log_error!("teste", "{:?}", a.avisos(desde_pausa));
                    return Err("o fim junto nao veio no aviso que esperava, uma vez");
                }
            }
            // O aviso já fora da fila, e `a` sem operar: o fim espera, até o
            // teto do processo.
            let antes = crate::aviso::medidas();
            let mut na_espera = Vec::new();
            for _ in 0..ACABADOS_POR_PROCESSO + 4 {
                let desde = crate::log::total_emitidos();
                let (id, n) = aberto(&a, &b, true, false)?;
                a.esperar_aviso(desde, "fluxo", n, malha::GRAVAVEL)?;
                crate::fluxo::vencer_de_teste(u64::MAX);
                esperar_ate(
                    || crate::aviso::guarda_o_fim_de_teste(a.ponta(n)),
                    TETO_DA_MALHA,
                )
                .map_err(|_| "o fim com o aviso fora da fila nao ficou na espera")?;
                if a.avisos_depois_do_sossego(desde, "fluxo", n) != [malha::GRAVAVEL] {
                    crate::log_error!("teste", "{:?}", a.avisos(desde));
                    return Err("o fim avisou com o aviso anterior nao consumido");
                }
                na_espera.push((id, n));
            }
            if crate::aviso::designacoes_de_teste(a.fio()) != 1 + ACABADOS_POR_PROCESSO {
                crate::log_error!(
                    "teste",
                    "{} designacoes",
                    crate::aviso::designacoes_de_teste(a.fio())
                );
                return Err("as designacoes acabadas passaram do teto do processo");
            }
            if crate::aviso::medidas().largados < antes.largados + 4 {
                return Err("as designacoes acabadas acima do teto nao foram contadas");
            }
            let (caidos, guardados) = na_espera.split_at(4);
            if caidos
                .iter()
                .any(|(_, n)| crate::aviso::situacao_de_teste(a.ponta(*n)).is_some())
                || guardados
                    .iter()
                    .any(|(_, n)| !crate::aviso::guarda_o_fim_de_teste(a.ponta(*n)))
            {
                return Err("o teto nao tirou as designacoes acabadas mais antigas");
            }
            // A operação de `a` consome o aviso e ouve o fim: a designação
            // sai, sem aviso.
            let desde = crate::log::total_emitidos();
            for (id, n) in guardados {
                feito(
                    &sobre(a.quem(), "stream.status", id),
                    "o status do fluxo acabado nao passou",
                )?;
                if crate::aviso::situacao_de_teste(a.ponta(*n)).is_some() {
                    return Err("a operacao que ouviu o fim nao tirou a designacao");
                }
            }
            for (_, n) in guardados {
                if !a.avisos_depois_do_sossego(desde, "fluxo", *n).is_empty() {
                    return Err("o fim ouvido pela operacao ainda avisou");
                }
            }
            if crate::aviso::designacoes_de_teste(a.fio()) != 1 {
                return Err("sobraram designacoes dos fluxos cujo fim foi ouvido");
            }
            // O canal de `a` cheio: o fim fica devido, no mesmo teto.
            let antes = crate::aviso::medidas();
            let desde_pausa = a.ditar(PAUSAR, PARADO_MS, 0)?;
            a.dito(desde_pausa, "pausando")?;
            let mut postos = 0;
            while a
                .publicar(Evento {
                    tipo: tipo::TESTE,
                    ..Default::default()
                })
                .is_ok()
            {
                postos += 1;
                if postos > crate::eventos::CAPACIDADE {
                    return Err("o canal nao encheu");
                }
            }
            let mut devidos = Vec::new();
            for _ in 0..ACABADOS_POR_PROCESSO + 4 {
                let (_, n) = aberto(&a, &b, true, false)?;
                crate::fluxo::vencer_de_teste(u64::MAX);
                esperar_ate(
                    || {
                        crate::aviso::guarda_o_fim_de_teste(a.ponta(n))
                            && matches!(
                                crate::aviso::situacao_de_teste(a.ponta(n)),
                                Some(Situacao::Devido(_))
                            )
                    },
                    TETO_DA_MALHA,
                )
                .map_err(|_| "o fim no canal cheio nao ficou devido")?;
                devidos.push(n);
            }
            if crate::aviso::designacoes_de_teste(a.fio()) != 1 + ACABADOS_POR_PROCESSO {
                crate::log_error!(
                    "teste",
                    "{} designacoes",
                    crate::aviso::designacoes_de_teste(a.fio())
                );
                return Err("os fins devidos passaram do teto do processo");
            }
            if crate::aviso::medidas().largados < antes.largados + 4 {
                return Err("os fins devidos acima do teto nao foram contados");
            }
            // `a` volta a ler o canal: os fins que ficaram devidos saem, uma
            // vez cada, e as designações deles com eles.
            acordar_o_parado(&b, &a, 9_432_002)?;
            esperar_ate(
                || crate::aviso::designacoes_de_teste(a.fio()) == 1,
                TETO_DA_MALHA,
            )
            .map_err(|_| "os fins devidos nao sairam quando o canal esvaziou")?;
            for &n in &devidos[4..] {
                let vistos = a.avisos_depois_do_sossego(desde_pausa, "fluxo", n);
                if vistos.len() != 1 || vistos[0] & malha::FIM == 0 {
                    crate::log_error!("teste", "{} {:?}", n, vistos);
                    return Err("o fim devido nao saiu uma vez");
                }
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS33 — a recusa do gate consome o aviso
// ---------------------------------------------------------------------------

/// O gancho da reconfirmação que tira `fabric.offer` da política entre a
/// decisão e a operação.
fn tirar_a_oferta() {
    politica_sem("fabric.offer");
}

/// A operação do dono, decidida pelo gate, consome o aviso também quando a
/// decisão é a recusa: senão o objeto ficaria mudo. O aceite de `b`,
/// recusado pela política nova, consome o aviso do pedido; com a política
/// de volta, o pedido que ainda espera avisa de novo pelo coletor, sem
/// mudança nenhuma no endpoint, e o aceite passa. E a recepção que a
/// reconfirmação recusa, dentro da decisão, também consome: a entrega que
/// ainda espera avisa de novo.
pub(super) fn aviso_a_recusa_do_gate_consome_o_aviso() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 433);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let antes_da_politica = crate::autorizacao::com_politica(|p| p.clone());
        let r = (|| -> Resultado {
            let e = b.numero_do_endpoint();
            let desde = crate::log::total_emitidos();
            let pedido = abrir(a.quem(), &b.endpoint);
            let id = fs_texto(&pedido, "stream").ok_or_else(|| {
                crate::log_error!("teste", "{}", pedido);
                "o pedido de fluxo nao passou"
            })?;
            b.esperar_aviso(desde, "endpoint", e, malha::PEDIDO)?;
            // Daqui em diante, o aviso do pedido só pode ser o de novo.
            let desde = crate::log::total_emitidos();
            politica_sem("fabric.stream");
            let r = aceitar(b.quem(), &b.endpoint);
            crate::autorizacao::restaurar_politica(antes_da_politica.clone());
            recusado(
                &r,
                "DENY_PERMISSION",
                "a politica nova nao recusou o aceite",
            )?;
            b.esperar_aviso(desde, "endpoint", e, malha::PEDIDO)
                .map_err(|_| "a recusa do gate deixou o endpoint mudo")?;
            let r = aceitar(b.quem(), &b.endpoint);
            if fs_texto(&r, "stream").as_deref() != Some(id.as_str()) {
                crate::log_error!("teste", "{}", r);
                return Err("o aceite depois do aviso de novo nao passou");
            }
            // A recepção recusada na reconfirmação.
            let desde = crate::log::total_emitidos();
            if !fs_ok(&mandar_na_malha(a.quem(), &b.endpoint, "um", 9_433_001)) {
                return Err("a entrega nao foi mandada");
            }
            b.esperar_aviso(desde, "endpoint", e, malha::ENTREGA)?;
            // A recepção recusada rearma na hora — a operação do dono
            // consome o aviso, e a entrega ainda espera —: o aviso de novo
            // pode vir antes de a recusa voltar ao teste.
            let desde = crate::log::total_emitidos();
            crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(tirar_a_oferta));
            let r = fs_pedir(
                b.quem(),
                "fabric.recv",
                &format!(r#"{{"endpoint":"{}"}}"#, b.endpoint),
            );
            crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
            crate::autorizacao::restaurar_politica(antes_da_politica.clone());
            if fs_ok(&r) {
                crate::log_error!("teste", "{}", r);
                return Err("a reconfirmacao nao recusou a recepcao");
            }
            b.esperar_aviso(desde, "endpoint", e, malha::ENTREGA)
                .map_err(|_| "a recepcao recusada deixou o endpoint mudo")?;
            Ok(())
        })();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        crate::autorizacao::restaurar_politica(antes_da_politica);
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS34 — quem retira ou fecha
// ---------------------------------------------------------------------------

/// O gancho da reconfirmação que tira `fabric.stream` da política entre a
/// decisão e a operação.
fn tirar_o_fluxo() {
    politica_sem("fabric.stream");
}

/// Quem retira um endpoint que designou não é avisado do fim dele — sabe,
/// porque o retirou. E o fecho que a reconfirmação recusa deixa o fluxo
/// vivo, e com ele a designação: o dado que chega depois avisa.
pub(super) fn aviso_quem_retira_ou_fecha() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 434);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let antes_da_politica = crate::autorizacao::com_politica(|p| p.clone());
        let r = (|| -> Resultado {
            let r = fs_pedir(
                b.quem(),
                "fabric.offer",
                &format!(r#"{{"intent":"pdf.anotar","notify":{}}}"#, b.descritor),
            );
            let outro = fs_texto(&r, "endpoint").ok_or_else(|| {
                crate::log_error!("teste", "{}", r);
                "a oferta com o aviso nao passou"
            })?;
            let n = politica::aviso::numero_do_id(&outro).ok_or("o id do endpoint")?;
            if crate::aviso::situacao_de_teste(Objeto::Endpoint(n)).is_none() {
                return Err("o endpoint oferecido com o aviso nao foi designado");
            }
            let desde = crate::log::total_emitidos();
            let r = fs_pedir(
                b.quem(),
                "fabric.withdraw",
                &format!(r#"{{"endpoint":"{outro}"}}"#),
            );
            if !fs_ok(&r) {
                crate::log_error!("teste", "{}", r);
                return Err("a retirada nao passou");
            }
            if !b.avisos_depois_do_sossego(desde, "endpoint", n).is_empty() {
                return Err("quem retirou o endpoint foi avisado do fim dele");
            }
            if crate::aviso::situacao_de_teste(Objeto::Endpoint(n)).is_some() {
                return Err("a retirada deixou a designacao");
            }
            // O fecho recusado na reconfirmação.
            let (id, n) = aberto(&a, &b, false, true)?;
            crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(tirar_o_fluxo));
            let r = sobre(b.quem(), "stream.close", &id);
            crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
            crate::autorizacao::restaurar_politica(antes_da_politica.clone());
            if fs_ok(&r) {
                crate::log_error!("teste", "{}", r);
                return Err("a reconfirmacao nao recusou o fecho");
            }
            if estado(a.quem(), &id).0.as_deref() != Some("open") {
                return Err("o fecho recusado fechou o fluxo");
            }
            let desde = crate::log::total_emitidos();
            escrito(&escrever(a.quem(), &id, b"vivo"), 4, "a escrita nao entrou")?;
            b.esperar_aviso(desde, "fluxo", n, malha::LEGIVEL)
                .map_err(|_| "o fecho recusado largou a designacao do fluxo vivo")?;
            Ok(())
        })();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        crate::autorizacao::restaurar_politica(antes_da_politica);
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS35 — o nome do canal no registro da designação
// ---------------------------------------------------------------------------

/// O nome do canal é texto do processo: no registro da designação, ele vai
/// só com letras, dígitos e `-_.:/`, e não imita o que vem depois dele no
/// detalhe da auditoria — a citação da decisão.
pub(super) fn aviso_o_nome_do_canal_no_registro() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 435);
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let chave = crate::eventos::escutar(b"x; decisao 1", b.fio())
                .map_err(|_| "o canal de nome estranho nao abriu")?;
            let d = crate::fios::com_descritores_de(b.fio(), |t| {
                t.instalar(crate::usuario::descritores::Alvo::Eventos { chave })
            })
            .flatten()
            .ok_or("o descritor do canal nao foi instalado")?;
            let antes = crate::autorizacao::ultimo_registro();
            let r = fs_pedir(
                b.quem(),
                "fabric.offer",
                &format!(r#"{{"intent":"pdf.anotar","notify":{d}}}"#),
            );
            let outro = fs_texto(&r, "endpoint").ok_or_else(|| {
                crate::log_error!("teste", "{}", r);
                "a oferta com o aviso nao passou"
            })?;
            let registros = registros_depois(antes, |e| e.detalhe.contains("aviso no canal"));
            let ok = registros
                .iter()
                .any(|(_, e)| e.detalhe.contains("aviso no canal x__decisao_1"));
            if !ok
                || registros
                    .iter()
                    .any(|(_, e)| e.detalhe.contains("x; decisao 1"))
            {
                crate::log_error!("teste", "{:?}", registros);
                return Err("o nome do canal entrou cru no registro da designacao");
            }
            let _ = fs_pedir(
                b.quem(),
                "fabric.withdraw",
                &format!(r#"{{"endpoint":"{outro}"}}"#),
            );
            crate::eventos::largar(chave, b.fio());
            Ok(())
        })();
        encerrar_todos(r, &[&b])
    })
}

// ---------------------------------------------------------------------------
// NS36 — a troca de imagem tira os avisos da fila
// ---------------------------------------------------------------------------

/// A imagem nova herda os descritores, e o canal: os avisos da malha que a
/// imagem anterior não leu saem da fila na troca. A fila de `b`, parado,
/// recebe a troca, quinze eventos de teste — a primeira leitura do laço
/// leva dezesseis — e o aviso do dado: a troca acontece com o aviso ainda
/// na fila, e ele sai dela.
pub(super) fn aviso_a_troca_de_imagem_tira_os_avisos_da_fila() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 436);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let (id, _) = aberto(&a, &b, false, true)?;
            let desde = b.ditar(PAUSAR, 3000, 0)?;
            b.dito(desde, "pausando")?;
            b.ditar(TROCAR, 0, 0)?;
            for _ in 0..15 {
                b.publicar(Evento {
                    tipo: tipo::TESTE,
                    ..Default::default()
                })?;
            }
            let descartados = crate::eventos::descartados_de_teste();
            escrito(
                &escrever(a.quem(), &id, b"velho"),
                5,
                "a escrita nao entrou",
            )?;
            esperar_ate(
                || crate::eventos::estado(&b.canal).is_some_and(|e| e.na_fila == 17),
                TETO_DA_MALHA,
            )
            .map_err(|_| "o aviso do dado nao entrou na fila depois da troca")?;
            b.dito(desde, "trocando")?;
            esperar_ate(
                || crate::eventos::descartados_de_teste() > descartados,
                TETO_DA_MALHA,
            )
            .map_err(|_| "o aviso da imagem anterior ficou na fila da nova")?;
            esperar_ate(
                || linhas_do_programa(desde, &format!("processo encerrou com codigo {SAIDA}")) == 1,
                TETO_DA_MALHA,
            )
            .map_err(|_| "a imagem nova nao terminou")?;
            Ok(())
        })();
        // `b` já saiu.
        encerrar_todos(r, &[&a])
    })
}
