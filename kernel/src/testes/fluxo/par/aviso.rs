//! Os casos do aviso da malha (DS-1) entre dois Dukes — NS23 a NS25.
//!
//! O par falso da suíte faz o outro Duke, como nos casos do fluxo remoto:
//! [`ParQueAceita`] do outro lado de um fluxo que sai, [`DeLa`] abrindo um
//! que chega. A ponta daqui é um `avisado`, designada no pedido dela. Nada
//! do aviso atravessa a linha: cada Duke avisa os processos dele, e o que o
//! par faz — `dados`, `credito`, `fim`, o `fechar` — acorda os mesmos pontos
//! que acordam as esperas, e agora também avisam.

use super::*;
use crate::testes::aviso::{Avisado, aceitar_avisando, encerrar_todos, numero_do_fluxo};
use protocolo::usuario::evento::malha;

/// Um fluxo chegando de lá ao endpoint de `b`, aceito por `b` com o aviso:
/// a sessão de lá, o id daqui e o número.
fn chegando_avisado(b: &Avisado, v: u8) -> Result<(DeLa, String, u64), &'static str> {
    let mut la = DeLa::novo(v, geracao(), DO_PAR);
    la.apertar()?.map_err(|m| {
        crate::log_error!("teste", "{}", m);
        "o aperto do fluxo foi recusado"
    })?;
    la.abrir_com(RELACAO, &b.endpoint)?;
    esperar_no_par(|| crate::fluxo::contagem().1 == 1, TETO)
        .map_err(|_| "o pedido do par nao chegou a tabela daqui")?;
    let r = aceitar_avisando(b);
    let id = fs_texto(&r, "stream").ok_or_else(|| {
        crate::log_error!("teste", "{}", r);
        "o processo daqui nao aceitou o pedido do par com o aviso"
    })?;
    if la.aceito()? != id {
        return Err("o aceito nao disse o id do fluxo daqui");
    }
    let n = numero_do_fluxo(&id)?;
    Ok((la, id, n))
}

// ---------------------------------------------------------------------------
// NS23 — a suspensão e o esquecimento
// ---------------------------------------------------------------------------

/// Um fluxo remoto que avisa, e o dispositivo suspenso: o fluxo acaba com
/// o motivo, a ponta daqui ouve `FIM`, e a leitura diz o motivo. E a
/// relação esquecida pela pessoa — `device.forget` —: o mesmo, com o
/// motivo dela.
pub(in crate::testes) fn aviso_a_suspensao_e_o_esquecimento() -> Resultado {
    use politica::fluxo::motivo;
    com_o_par(|| {
        let (bia, sessao, _) = bia_relacionada("dispositivo")?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let (mut la, id, n) = chegando_avisado(&b, VAGA)?;
            let desde = crate::log::total_emitidos();
            admin("device.suspend", r#"{"device":"dispositivo:par"}"#, None)?;
            match la.esperar_o_fim()? {
                Some(m) if m == motivo::DISPOSITIVO_SUSPENSO => {}
                outro => {
                    crate::log_error!("teste", "{:?}", outro);
                    return Err("a suspensao nao encerrou o fluxo com o motivo");
                }
            }
            b.esperar_aviso(desde, "fluxo", n, malha::FIM)?;
            let r = ler(b.quem(), &id, 10);
            if fs_texto(&r, "error").as_deref() != Some(motivo::DISPOSITIVO_SUSPENSO) {
                crate::log_error!("teste", "{}", r);
                return Err("a leitura depois do FIM nao ouviu a suspensao");
            }
            crate::contencao::esquecer_de_teste();
            // A relação esquecida.
            let (mut la, id, n) = chegando_avisado(&b, VAGA + 1)?;
            let desde = crate::log::total_emitidos();
            let r = fs_pedir(
                Chamador::Pessoa(sessao),
                "device.forget",
                &format!(r#"{{"device":"dispositivo:{NOME_DO_PAR}"}}"#),
            );
            if !r.contains(r#""forgotten":true"#) {
                crate::log_error!("teste", "{}", r);
                return Err("device.forget nao passou");
            }
            match la.esperar_o_fim()? {
                Some(m) if m == motivo::RELACAO => {}
                outro => {
                    crate::log_error!("teste", "{:?}", outro);
                    return Err("a relacao esquecida nao encerrou o fluxo dela");
                }
            }
            b.esperar_aviso(desde, "fluxo", n, malha::FIM)?;
            let r = ler(b.quem(), &id, 10);
            if fs_texto(&r, "error").as_deref() != Some(motivo::RELACAO) {
                crate::log_error!("teste", "{}", r);
                return Err("a leitura depois do FIM nao ouviu o esquecimento");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&b])
    })
}

// ---------------------------------------------------------------------------
// NS24 — o fluxo saindo
// ---------------------------------------------------------------------------

/// Um processo daqui abre um fluxo ao Duke de lá, com o aviso: o `aceito`
/// de lá — a abertura efetiva — dá `GRAVAVEL` a quem abriu; os `dados` de
/// lá dão `LEGIVEL`; a escrita que esbarra no buffer, com o crédito de lá
/// gasto, pede o espaço, e o `credito` de lá — que deixa a sessão mandar o
/// que esperava — o devolve: `GRAVAVEL`.
pub(in crate::testes) fn aviso_o_fluxo_saindo_para_outro_duke() -> Resultado {
    com_o_par(|| {
        let (bia, _, _) = bia_relacionada("dispositivo")?;
        let a = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let r = fs_pedir(
                a.quem(),
                "stream.open",
                &format!(
                    r#"{{"endpoint":"e0e0e0e0e0e0e0e0:3","intent":"{INTENCAO}","device":"dispositivo:{NOME_DO_PAR}","notify":{}}}"#,
                    a.descritor
                ),
            );
            feito(&r, "o pedido de fluxo ao par com o aviso nao passou")?;
            let id = fs_texto(&r, "stream").ok_or("sem id")?;
            let n = numero_do_fluxo(&id)?;
            lancar_a_sessao_saindo(n)?;
            let mut la = ParQueAceita::novo(DO_PAR);
            la.aceitar_o_aperto()?;
            let _abrir = la.mensagem()?;
            let desde = crate::log::total_emitidos();
            la.mandar(&Mensagem::Aceito("e0e0e0e0e0e0e0e0:9"))?;
            la.credito = CREDITO;
            a.esperar_aviso(desde, "fluxo", n, malha::GRAVAVEL)?;
            // A operação consome o aviso: sem ela, o próximo não sai.
            if estado(a.quem(), &id).0.as_deref() != Some("open") {
                return Err("o fluxo ao par nao abriu");
            }
            // Os dados de lá.
            let desde = crate::log::total_emitidos();
            la.mandar(&Mensagem::Dados(b"de la"))?;
            a.esperar_aviso(desde, "fluxo", n, malha::LEGIVEL)?;
            ler_e_conferir(
                a.quem(),
                &id,
                100,
                b"de la",
                false,
                "a leitura nao trouxe o de la",
            )?;
            // O crédito de lá gasto: os primeiros 16 KiB vão, e chegam lá.
            for pedaco in vec![0x5a; politica::fluxo::BUFFER_DO_SENTIDO].chunks(4096) {
                escrito(
                    &escrever(a.quem(), &id, pedaco),
                    pedaco.len() as u64,
                    "a ponta daqui nao escreveu dentro do credito",
                )?;
            }
            let mut chegou = 0;
            while chegou < politica::fluxo::BUFFER_DO_SENTIDO {
                match Mensagem::ler(&la.mensagem()?) {
                    Some(Mensagem::Dados(d)) => chegou += d.len(),
                    outra => {
                        crate::log_error!("teste", "{:?}", outra);
                        return Err("o que o credito deixa nao chegou ao par");
                    }
                }
            }
            // Os 16 KiB seguintes ficam aqui, sem crédito; a escrita
            // seguinte esbarra.
            escrito(
                &escrever(a.quem(), &id, &[0x5b; politica::fluxo::BUFFER_DO_SENTIDO]),
                politica::fluxo::BUFFER_DO_SENTIDO as u64,
                "a escrita sem credito nao entrou no buffer",
            )?;
            let desde = crate::log::total_emitidos();
            escrito(
                &escrever(a.quem(), &id, b"x"),
                0,
                "a escrita no cheio entrou",
            )?;
            let _ = esperar_ate(|| false, 30);
            if !a.avisos_de(desde, "fluxo", n).is_empty() {
                return Err("o espaco avisou sem o credito de la");
            }
            // O crédito de lá: a sessão manda, o buffer esvazia, quem
            // esbarrou ouve.
            la.mandar(&Mensagem::Credito(4096))?;
            a.esperar_aviso(desde, "fluxo", n, malha::GRAVAVEL)?;
            match Mensagem::ler(&la.mensagem()?) {
                Some(Mensagem::Dados(d)) if !d.is_empty() && d.iter().all(|x| *x == 0x5b) => {}
                outra => {
                    crate::log_error!("teste", "{:?}", outra);
                    return Err("o credito de la nao deixou a sessao mandar o que esperava");
                }
            }
            Ok(())
        })();
        encerrar_todos(r, &[&a])
    })
}

// ---------------------------------------------------------------------------
// NS25 — o fluxo chegando
// ---------------------------------------------------------------------------

/// O Duke de lá abre um fluxo ao `avisado` daqui: o pedido avisa o
/// endpoint (`PEDIDO`); a ponta aceita com o aviso ouve os `dados` de lá
/// (`LEGIVEL`) e o `fim` de lá (`LEGIVEL`, o fim do sentido), como uma
/// local. O que vai à linha são só as mensagens do fluxo — o `fim` daqui —,
/// e nenhum aviso.
pub(in crate::testes) fn aviso_o_fluxo_chegando_de_outro_duke() -> Resultado {
    com_o_par(|| {
        let (bia, _, _) = bia_relacionada("dispositivo")?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let desde = crate::log::total_emitidos();
            let (mut la, id, n) = chegando_avisado(&b, VAGA)?;
            b.esperar_aviso(desde, "endpoint", b.numero_do_endpoint(), malha::PEDIDO)?;
            let desde = crate::log::total_emitidos();
            la.mandar(&Mensagem::Dados(b"de la"))?;
            b.esperar_aviso(desde, "fluxo", n, malha::LEGIVEL)?;
            ler_e_conferir(
                b.quem(),
                &id,
                100,
                b"de la",
                false,
                "a leitura nao trouxe o de la",
            )?;
            let desde = crate::log::total_emitidos();
            la.mandar(&Mensagem::Fim)?;
            b.esperar_aviso(desde, "fluxo", n, malha::LEGIVEL)?;
            ler_e_conferir(
                b.quem(),
                &id,
                100,
                b"",
                true,
                "a leitura nao trouxe o fim de la",
            )?;
            feito(
                &sobre(b.quem(), "stream.finish", &id),
                "o fim daqui nao passou",
            )?;
            // A linha leva o fluxo, e só: o fim daqui — e um crédito, se
            // houver —, nunca um aviso.
            loop {
                match Mensagem::ler(&la.mensagem()?) {
                    Some(Mensagem::Credito(_)) => {}
                    Some(Mensagem::Fim) => break,
                    outra => {
                        crate::log_error!("teste", "{:?}", outra);
                        return Err("a linha levou o que nao e do fluxo");
                    }
                }
            }
            if la.esperar_o_fim()?.is_some() {
                return Err("o fluxo concluido terminou com fechar");
            }
            Ok(())
        })();
        encerrar_todos(r, &[&b])
    })
}
