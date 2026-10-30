//! Os casos dos dispositivos relacionados e do enlace entre eles — o
//! estágio 1 de B-E1/B-E2.
//!
//! Um dispositivo relacionado é outro Duke, pela chave dele, ligado a uma
//! pessoa desta máquina por uma relação que um administrador cria e revoga
//! com prova. Aqui a suíte faz o papel do administrador — com a credencial
//! de teste — e o do outro dispositivo, com chaves de teste: a privada de
//! um Duke de verdade nunca sai da máquina dele.

use super::{ADMIN_DE_TESTE, Resultado, executar_admin_com, registros_do_journal};
use alloc::string::String;
use alloc::vec::Vec;
use politica::Codigo;

/// Os últimos `n` registros da auditoria.
fn ultimos_registros(n: usize) -> Vec<politica::auditoria::Registro> {
    crate::autorizacao::com_auditoria(|c| c.ultimos(n).cloned().collect()).unwrap_or_default()
}

/// Os parâmetros de `agent.register` com a chave pública `chave`.
fn registro_de_agente(chave: &[u8; 32], nome: &str, papel: &str) -> String {
    alloc::format!(
        r#"{{"key":"{}","name":"{nome}","role":"{papel}"}}"#,
        sigilo::hex(chave)
    )
}

/// A chave privada do dispositivo de teste `n`: fixa, e de ninguém mais.
pub(super) fn privada_de_dispositivo(n: u8) -> [u8; 32] {
    [0xD0 + n; 32]
}

/// A chave pública do dispositivo de teste `n`.
pub(super) fn chave_de_dispositivo(n: u8) -> [u8; 32] {
    sigilo::publica_de(&privada_de_dispositivo(n))
}

/// Os parâmetros de `device.register`.
fn registro_de_dispositivo(
    chave: &[u8; 32],
    nome: &str,
    pessoa: sigilo::pessoas::IdPessoa,
    papel: &str,
    endereco: Option<&str>,
    relacao: Option<&str>,
) -> String {
    let mut p = alloc::format!(
        r#"{{"key":"{}","name":"{nome}","person":"{}","role":"{papel}""#,
        sigilo::hex(chave),
        pessoa.texto()
    );
    if let Some(e) = endereco {
        p.push_str(&alloc::format!(r#","address":"{e}""#));
    }
    if let Some(r) = relacao {
        p.push_str(&alloc::format!(r#","relation":"{r}""#));
    }
    p.push('}');
    p
}

/// Roda `f` com o administrador de teste registrado e o registro de
/// dispositivos vazio, e devolve tudo ao que era: nenhum caso herda
/// dispositivo, lápide, suspensão, pessoa ou administrador de outro.
pub(super) fn com_dispositivos_de_teste(f: impl FnOnce() -> Resultado) -> Resultado {
    crate::dispositivos::esquecer_de_teste();
    crate::contencao::esquecer_de_teste();
    crate::identidade::registrar_administrador_de_teste(
        sigilo::publica_de(&ADMIN_DE_TESTE),
        "administrador",
    );
    let resultado = f();
    crate::dispositivos::esquecer_de_teste();
    crate::contencao::esquecer_de_teste();
    crate::identidade::esquecer_registrados();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// Uma operação administrativa de teste, e o desfecho que as regras
/// mandam: executada (`None`) ou recusada com o código.
fn admin(comando: &str, params: &str, recusa: Option<&str>) -> Result<String, &'static str> {
    let r = executar_admin_com(0, &ADMIN_DE_TESTE, comando, params, params)?;
    let certo = match recusa {
        Some(codigo) => {
            r.contains(r#""executed":false"#) && r.contains(&alloc::format!(r#""code":"{codigo}""#))
        }
        None => r.contains(r#""executed":true"#),
    };
    if !certo {
        crate::log_error!("teste", "{} {}: {}", comando, params, r);
        return Err("uma operacao de dispositivo nao teve o desfecho que as regras mandam");
    }
    Ok(r)
}

/// O administrador relaciona outro dispositivo a uma pessoa, com prova: a
/// relação entra no registro, vai ao journal como a linha inteira — o
/// resultado, e não o pedido —, num registro só, com a decisão; e a
/// reposição do journal a traz de volta igual. O identificador sorteado
/// volta na resposta, para o administrador do outro lado registrar o
/// mesmo; e o segundo lado, com o identificador dado, fica igual.
pub(super) fn dispositivos_o_administrador_relaciona_com_prova() -> Resultado {
    com_dispositivos_de_teste(|| {
        let bia = crate::pessoas::registrar_de_teste("bia-disp", "operador", b"senha de teste");
        let k = chave_de_dispositivo(1);
        let antes = registros_do_journal()?.len();
        let p = registro_de_dispositivo(
            &k,
            "par",
            bia,
            "dispositivo",
            Some("tcp:10.0.2.100:7071"),
            None,
        );
        let r = admin("device.register", &p, None)?;
        let d = crate::dispositivos::por_nome("par").ok_or("a relacao nao entrou no registro")?;
        let [rel] = d.relacoes.as_slice() else {
            return Err("o dispositivo nao tem exatamente a relacao registrada");
        };
        if d.chave != k
            || rel.pessoa != bia.0
            || rel.papel != "dispositivo"
            || rel.endereco.as_deref() != Some("tcp:10.0.2.100:7071")
        {
            crate::log_error!("teste", "{:?}", d);
            return Err("a relacao registrada nao e a pedida");
        }
        let id = politica::dispositivos::id_texto(&rel.id);
        if rel.id == [0; 16] || !r.contains(&id) {
            crate::log_error!("teste", "{}", r);
            return Err("o identificador sorteado nao voltou na resposta");
        }
        // No journal: um registro, com a linha inteira da relação.
        let depois = registros_do_journal()?;
        if depois.len() != antes + 1 {
            return Err("o registro do dispositivo nao foi exatamente um registro no journal");
        }
        let ultimo = depois.last().ok_or("journal vazio")?;
        let entradas = diario::estado::ler_campos(&ultimo.conteudo)?;
        let linha = politica::dispositivos::linha(&k, "par", rel);
        let esperada = crate::persistencia::entrada_de_teste(
            diario::estado::tipo::DISPOSITIVO_REGISTRADO,
            &[linha.as_bytes()],
        );
        if !entradas.contains(&esperada.as_slice()) {
            return Err("o journal nao traz a linha da relacao registrada");
        }
        // A decisão, na auditoria: o administrador, a operação, e o recurso
        // — o dispositivo e a relação.
        let recurso = alloc::format!("dispositivo:par ; relacao:{id}");
        let decidida = ultimos_registros(16).into_iter().any(|e| {
            e.evento.metodo == "device.register"
                && e.evento.codigo == Codigo::Allow
                && e.evento.recurso == recurso
                && e.evento.agente == crate::identidade::ADMINISTRADOR_DE_TESTE
        });
        if !decidida {
            return Err("a decisao do registro nao esta na auditoria");
        }
        // A reposição traz a mesma relação de volta.
        crate::dispositivos::esquecer_de_teste();
        crate::persistencia::em_ordem(|| crate::persistencia::reaplicar_de_teste(ultimo))?;
        if crate::dispositivos::por_nome("par").as_ref() != Some(&d) {
            return Err("a reposicao do journal nao trouxe a mesma relacao");
        }
        // O outro lado: a mesma relação, com o identificador dado.
        crate::dispositivos::esquecer_de_teste();
        let p = registro_de_dispositivo(&k, "par", bia, "dispositivo", None, Some(&id));
        admin("device.register", &p, None)?;
        let d2 = crate::dispositivos::por_nome("par").ok_or("o segundo lado nao entrou")?;
        if d2.relacoes.len() != 1
            || d2.relacoes[0].id != rel.id
            || d2.relacoes[0].endereco.is_some()
        {
            return Err("o segundo lado nao ficou com o identificador dado");
        }
        if !crate::dispositivos::coerente() {
            return Err("o registro de dispositivos ficou incoerente");
        }
        Ok(())
    })
}

/// O que o registro recusa: a chave deste Duke, a de um agente, a de um
/// administrador; a pessoa que não existe; o papel que é teto, ou que não
/// cabe no do administrador; o endereço que não é TCP na forma normal; o
/// nome fora da regra; o nome de outro dispositivo; a mesma pessoa duas
/// vezes; o identificador repetido. Cada recusa com o código dela — e
/// nada muda, nem no registro nem no journal.
pub(super) fn dispositivos_as_recusas_do_registro() -> Resultado {
    super::com_agentes_de_teste(|| {
        com_dispositivos_de_teste(|| {
            let bia =
                crate::pessoas::registrar_de_teste("bia-recusas", "operador", b"senha de teste");
            let caio =
                crate::pessoas::registrar_de_teste("caio-recusas", "operador", b"senha de teste");
            let k = chave_de_dispositivo(2);
            admin(
                "device.register",
                &registro_de_dispositivo(&k, "par", bia, "dispositivo", None, None),
                None,
            )?;
            let id = politica::dispositivos::id_texto(
                &crate::dispositivos::por_nome("par")
                    .ok_or("sem o primeiro")?
                    .relacoes[0]
                    .id,
            );
            let retrato = crate::dispositivos::relacoes();
            let antes = registros_do_journal()?.len();
            let duke = crate::identidade::publica_do_duke().ok_or("o Duke nao tem chave")?;
            let agente = sigilo::publica_de(&super::chave_de_teste(1));
            let administrador = sigilo::publica_de(&ADMIN_DE_TESTE);
            let outra = chave_de_dispositivo(3);
            let ninguem = sigilo::pessoas::IdPessoa([0x5A; 8]);
            let casos: [(String, &str); 12] = [
                (
                    registro_de_dispositivo(&duke, "eu", bia, "dispositivo", None, None),
                    "DENY_POLICY",
                ),
                (
                    registro_de_dispositivo(&agente, "agente", bia, "dispositivo", None, None),
                    "DENY_POLICY",
                ),
                (
                    registro_de_dispositivo(&administrador, "adm", bia, "dispositivo", None, None),
                    "DENY_POLICY",
                ),
                (
                    registro_de_dispositivo(&outra, "outro", ninguem, "dispositivo", None, None),
                    "INVALID_ARGUMENT",
                ),
                (
                    registro_de_dispositivo(&outra, "outro", bia, "administrador", None, None),
                    "DENY_POLICY",
                ),
                (
                    registro_de_dispositivo(&outra, "outro", bia, "sistema", None, None),
                    "DENY_POLICY",
                ),
                (
                    registro_de_dispositivo(
                        &outra,
                        "outro",
                        bia,
                        "dispositivo",
                        Some("udp:10.0.2.2:69"),
                        None,
                    ),
                    "INVALID_ARGUMENT",
                ),
                (
                    registro_de_dispositivo(&outra, "Outro*", bia, "dispositivo", None, None),
                    "INVALID_ARGUMENT",
                ),
                (
                    registro_de_dispositivo(&outra, "par", bia, "dispositivo", None, None),
                    "INVALID_ARGUMENT",
                ),
                (
                    registro_de_dispositivo(&k, "par", bia, "dispositivo", None, None),
                    "INVALID_ARGUMENT",
                ),
                (
                    registro_de_dispositivo(&outra, "outro", caio, "dispositivo", None, Some(&id)),
                    "INVALID_ARGUMENT",
                ),
                (
                    registro_de_dispositivo(&k, "renomeado", caio, "dispositivo", None, None),
                    "INVALID_ARGUMENT",
                ),
            ];
            for (params, codigo) in &casos {
                admin("device.register", params, Some(codigo))?;
            }
            if crate::dispositivos::relacoes() != retrato {
                return Err("uma recusa mudou o registro de dispositivos");
            }
            if registros_do_journal()?.len() != antes {
                return Err("uma recusa gravou no journal");
            }
            // A outra pessoa, no mesmo dispositivo, com o mesmo nome: vale.
            admin(
                "device.register",
                &registro_de_dispositivo(&k, "par", caio, "dispositivo", None, None),
                None,
            )?;
            if crate::dispositivos::por_nome("par").map(|d| d.relacoes.len()) != Some(2) {
                return Err("a segunda pessoa nao ganhou a relacao dela");
            }
            Ok(())
        })
    })
}

/// A revogação é o dispositivo inteiro, e permanente: as relações das duas
/// pessoas saem, a chave ganha a lápide — gravada no journal —, e ela não
/// volta: nem como dispositivo, com outro nome ou outra pessoa, nem como
/// agente. A reposição do journal a mantém revogada, mesmo repondo depois
/// o registro de antes dela. O outro dispositivo da mesma pessoa não é
/// tocado.
pub(super) fn dispositivos_a_revogacao_e_permanente() -> Resultado {
    com_dispositivos_de_teste(|| {
        let bia = crate::pessoas::registrar_de_teste("bia-revoga", "operador", b"senha de teste");
        let caio = crate::pessoas::registrar_de_teste("caio-revoga", "operador", b"senha de teste");
        let k = chave_de_dispositivo(4);
        let fica = chave_de_dispositivo(5);
        let inicio = registros_do_journal()?.len();
        for pessoa in [bia, caio] {
            admin(
                "device.register",
                &registro_de_dispositivo(&k, "par", pessoa, "dispositivo", None, None),
                None,
            )?;
        }
        admin(
            "device.register",
            &registro_de_dispositivo(&fica, "par-2", bia, "dispositivo", None, None),
            None,
        )?;
        let r = admin("device.revoke", r#"{"name":"par"}"#, None)?;
        if !r.contains(r#""relations":2"#) {
            crate::log_error!("teste", "{}", r);
            return Err("a revogacao nao tirou as duas relacoes");
        }
        if crate::dispositivos::dispositivo(&k).is_some()
            || !crate::dispositivos::lapides().contains(&k)
            || crate::dispositivos::dispositivo(&fica).is_none()
        {
            return Err("a revogacao nao tirou so o dispositivo revogado, com a lapide");
        }
        let registros = registros_do_journal()?;
        let revogacao = registros.last().ok_or("journal vazio")?;
        let esperada = crate::persistencia::entrada_de_teste(
            diario::estado::tipo::DISPOSITIVO_REVOGADO,
            &[&k],
        );
        if !diario::estado::ler_campos(&revogacao.conteudo)?.contains(&esperada.as_slice()) {
            return Err("a lapide do dispositivo nao foi ao journal");
        }
        // Não volta.
        for params in [
            registro_de_dispositivo(&k, "par", bia, "dispositivo", None, None),
            registro_de_dispositivo(&k, "outro-nome", caio, "dispositivo", None, None),
        ] {
            admin("device.register", &params, Some("DENY_POLICY"))?;
        }
        let como_agente = registro_de_agente(&k, "ex-dispositivo", "observador");
        admin("agent.register", &como_agente, Some("DENY_POLICY"))?;
        admin(
            "device.revoke",
            r#"{"name":"par"}"#,
            Some("INVALID_ARGUMENT"),
        )?;
        // A reposição: tudo desde o começo do caso, e o registro de antes
        // da lápide de novo depois dela — a lápide vence.
        crate::dispositivos::esquecer_de_teste();
        crate::persistencia::em_ordem(|| -> Resultado {
            for r in &registros[inicio..] {
                crate::persistencia::reaplicar_de_teste(r)?;
            }
            crate::persistencia::reaplicar_de_teste(&registros[inicio])?;
            Ok(())
        })?;
        if crate::dispositivos::dispositivo(&k).is_some()
            || !crate::dispositivos::lapides().contains(&k)
            || crate::dispositivos::por_nome("par-2").map(|d| d.chave) != Some(fica)
        {
            return Err("a reposicao do journal nao manteve a revogacao e o resto");
        }
        if !crate::dispositivos::coerente() {
            return Err("o registro de dispositivos ficou incoerente");
        }
        Ok(())
    })
}

/// Uma chave, uma espécie de principal: a chave de um agente não vira
/// dispositivo, e a de um dispositivo não vira agente — nem a de um
/// revogado.
pub(super) fn dispositivos_uma_chave_uma_especie() -> Resultado {
    com_dispositivos_de_teste(|| {
        let bia = crate::pessoas::registrar_de_teste("bia-especie", "operador", b"senha de teste");
        let agente = chave_de_dispositivo(6);
        admin(
            "agent.register",
            &registro_de_agente(&agente, "agente-especie", "observador"),
            None,
        )?;
        admin(
            "device.register",
            &registro_de_dispositivo(&agente, "par", bia, "dispositivo", None, None),
            Some("DENY_POLICY"),
        )?;
        let dispositivo = chave_de_dispositivo(7);
        admin(
            "device.register",
            &registro_de_dispositivo(&dispositivo, "par", bia, "dispositivo", None, None),
            None,
        )?;
        admin(
            "agent.register",
            &registro_de_agente(&dispositivo, "agente-dispositivo", "observador"),
            Some("DENY_POLICY"),
        )?;
        if crate::identidade::agente(&dispositivo).is_some()
            || crate::dispositivos::dispositivo(&agente).is_some()
        {
            return Err("uma chave ficou nos dois registros");
        }
        Ok(())
    })
}

/// A suspensão é a contenção do dispositivo: reversível, volátil, pelo
/// gate — com o dispositivo como recurso enumerado — e pela prova. Fora do
/// alcance, `DENY_RESOURCE`; dentro do alcance e sem registro, a mesma
/// recusa, com o motivo na auditoria. A lista das contenções a mostra, e a
/// revogação a esquece: a chave não volta para herdá-la.
pub(super) fn dispositivos_a_suspensao_e_reversivel() -> Resultado {
    use crate::autorizacao::Chamador;
    com_dispositivos_de_teste(|| {
        let bia = crate::pessoas::registrar_de_teste("bia-suspensa", "operador", b"senha de teste");
        let k = chave_de_dispositivo(8);
        admin(
            "device.register",
            &registro_de_dispositivo(&k, "par", bia, "dispositivo", None, None),
            None,
        )?;
        let serial = Chamador::Sessao(crate::agent::sessao::SERIAL);
        let pedir = |metodo: &str, alvo: &str| {
            crate::nativo::responder_de_teste(
                serial,
                &super::pedido_rpc(metodo, &alloc::format!(r#"{{"device":"{alvo}"}}"#)),
            )
        };
        let r = pedir("device.suspend", "dispositivo:par");
        if !r.contains(r#""state":"suspended""#) || !crate::contencao::dispositivo_suspenso(&k) {
            crate::log_error!("teste", "{}", r);
            return Err("o sistema nao suspendeu o dispositivo pelo gate");
        }
        let r = pedir("device.suspend", "dispositivo:par");
        if !r.contains(r#""state":"already_suspended""#) {
            return Err("suspender o suspenso nao disse que ja estava");
        }
        let lista =
            crate::nativo::responder_de_teste(serial, &super::pedido_rpc("containment.list", "{}"));
        if !lista.contains(&alloc::format!("device:{}", sigilo::hex(&k))) {
            return Err("a lista das contencoes nao mostra o dispositivo suspenso");
        }
        let r = pedir("device.resume", "dispositivo:par");
        if !r.contains(r#""state":"resumed""#) || crate::contencao::dispositivo_suspenso(&k) {
            return Err("o dispositivo nao foi retomado");
        }
        // Fora do alcance do papel, e dentro dele sem registro: a mesma
        // recusa.
        for alvo in [
            "dispositivo:intruso",
            "dispositivo:par-2",
            "dispositivo:*",
            "par",
        ] {
            let r = pedir("device.suspend", alvo);
            if !r.contains("DENY_RESOURCE") {
                crate::log_error!("teste", "{}: {}", alvo, r);
                return Err(
                    "a suspensao alcancou um dispositivo fora do alcance, ou que nao existe",
                );
            }
        }
        // Pela prova também, e a revogação a esquece.
        admin("device.suspend", r#"{"device":"dispositivo:par"}"#, None)?;
        if !crate::contencao::dispositivo_suspenso(&k) {
            return Err("a prova nao suspendeu o dispositivo");
        }
        admin(
            "device.suspend",
            r#"{"device":"dispositivo:intruso"}"#,
            Some("DENY_RESOURCE"),
        )?;
        admin(
            "device.revoke",
            &alloc::format!(r#"{{"key":"{}"}}"#, sigilo::hex(&k)),
            None,
        )?;
        if crate::contencao::dispositivo_suspenso(&k) {
            return Err("a revogacao nao esqueceu a suspensao");
        }
        Ok(())
    })
}
