//! Os casos dos dispositivos relacionados e do enlace entre eles — o
//! estágio 1 de B-E1/B-E2.
//!
//! Um dispositivo relacionado é outro Duke, pela chave dele, ligado a uma
//! pessoa desta máquina por uma relação que um administrador cria e revoga
//! com prova. Aqui a suíte faz o papel do administrador — com a credencial
//! de teste — e o do outro dispositivo, com chaves de teste: a privada de
//! um Duke de verdade nunca sai da máquina dele.

use super::{
    ADMIN_DE_TESTE, Resultado, executar_admin_com, registros_depois, registros_do_journal,
};
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

// ---------------------------------------------------------------------
// O enlace: o destino — o respondedor das vagas, com o gate e a malha
// daqui — e a origem — o pedido, a tabela e a conversa do serviço.
// ---------------------------------------------------------------------

use crate::autorizacao::Autoridade;
use crate::enlace::{Lado, Ponta};
use crate::pessoas::Console;
use protocolo::json::Json;
use sigilo::quadro::{self, Leitor, Tipo};

/// A relação dos casos do enlace — o mesmo identificador nos dois lados.
const RELACAO: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

/// A relação de outro dispositivo, que o par não pode dizer.
const OUTRA_RELACAO: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";

/// O resumo do programa que o par de teste atesta.
const PROGRAMA_ATESTADO: [u8; 32] = [0xab; 32];

/// O motivo, na auditoria, da recusa de um comando de fora do conjunto
/// fechado pedido de outro dispositivo.
pub(super) const FORA_DO_CONJUNTO: &str = "de outro dispositivo so chega o conjunto fechado";

/// A primeira vaga do enlace.
pub(super) const VAGA: u8 = crate::rede::canal::VAGAS + 1;

/// A ponta de teste de uma vaga do enlace: guarda o que o respondedor
/// manda, a chave que ele confirmou e se ele encerrou.
#[derive(Default)]
pub(super) struct PontaDeTeste {
    saida: Vec<u8>,
    confirmada: Option<[u8; 32]>,
    pub(super) encerrou: bool,
}

impl Ponta for PontaDeTeste {
    fn mandar(&mut self, q: &[u8]) -> bool {
        if self.encerrou {
            return false;
        }
        self.saida.extend_from_slice(q);
        true
    }

    fn confirmar(&mut self, chave: [u8; 32]) {
        self.confirmada = Some(chave);
    }

    fn encerrar(&mut self) {
        self.encerrou = true;
    }

    fn par(&self) -> String {
        String::from("tcp 10.0.2.200:40000")
    }
}

/// Outro Duke, do lado de lá de uma vaga do enlace: a suíte, com a chave de
/// teste dele, falando com o respondedor de verdade — o aperto, os
/// quadros, a cifra.
pub(super) struct Par {
    pub(super) lado: Lado,
    pub(super) ponta: PontaDeTeste,
    leitor: Leitor,
    transporte: Option<sigilo::Transporte>,
    /// O quadro da primeira mensagem do último aperto, para repetir.
    primeira: Vec<u8>,
}

impl Par {
    pub(super) fn novo(v: u8, geracao: u64) -> Par {
        let mut lado = Lado::nova(v, 0);
        lado.conexao(geracao);
        Par {
            lado,
            ponta: PontaDeTeste::default(),
            leitor: Leitor::novo(),
            transporte: None,
            primeira: Vec::new(),
        }
    }

    fn empurrar(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.lado.receber(b, &mut self.ponta);
        }
    }

    /// Os quadros que o respondedor mandou desde a última leitura.
    fn quadros(&mut self) -> Result<Vec<(Tipo, Vec<u8>)>, &'static str> {
        let saida = core::mem::take(&mut self.ponta.saida);
        let mut v = Vec::new();
        for b in saida {
            match self.leitor.empurrar(b) {
                Ok(Some((t, c))) => v.push((t, c.to_vec())),
                Ok(None) => {}
                Err(_) => return Err("o respondedor mandou um quadro que nao se le"),
            }
        }
        Ok(v)
    }

    /// O aperto com a chave `privada` e a época `epoca`: `Ok(Ok)` com a
    /// resposta aberta, `Ok(Err)` com a recusa em claro.
    pub(super) fn apertar(
        &mut self,
        privada: &[u8; 32],
        epoca: [u8; 8],
    ) -> Result<Result<(), String>, &'static str> {
        let duke = crate::identidade::publica_do_duke().ok_or("o Duke nao tem chave")?;
        let carga = alloc::format!(r#"{{"epoch":"{}"}}"#, sigilo::hex_de(&epoca));
        let mut buf = alloc::vec![0u8; 1024];
        let efemera = crate::aleatorio::chave().map_err(|_| "sem entropia")?;
        let (n, aguardando) = sigilo::Iniciador::novo(sigilo::PROLOGO_DO_ENLACE, privada, &duke)
            .escrever(efemera, carga.as_bytes(), &mut buf)
            .map_err(|_| "o aperto do par nao se escreveu")?;
        let q = quadro::montar(Tipo::InicioEnlace, &buf[..n]).map_err(|_| "quadro grande")?;
        self.primeira = q.clone();
        self.empurrar(&q);
        match self.quadros()?.as_slice() {
            [(Tipo::Resposta, corpo)] => {
                let mut lixo = alloc::vec![0u8; corpo.len()];
                let (_, t) = aguardando
                    .ler(corpo, &mut lixo)
                    .map_err(|_| "a resposta do aperto nao abriu")?;
                self.transporte = Some(t);
                Ok(Ok(()))
            }
            [(Tipo::Recusa, motivo)] => Ok(Err(String::from_utf8_lossy(motivo).into_owned())),
            outro => {
                crate::log_error!("teste", "{} quadro(s) em resposta ao aperto", outro.len());
                Err("o respondedor nao respondeu o aperto com um quadro so")
            }
        }
    }

    /// Cifra e manda `claro` num quadro de dados.
    pub(super) fn mandar_dados(&mut self, claro: &[u8]) -> Result<(), &'static str> {
        let t = self.transporte.as_mut().ok_or("o par nao tem transporte")?;
        let mut c = alloc::vec![0u8; claro.len() + 64];
        let n = t
            .cifrar(claro, &mut c)
            .map_err(|_| "o pedido nao se cifrou")?;
        let q = quadro::montar(Tipo::Dados, &c[..n]).map_err(|_| "quadro grande")?;
        self.empurrar(&q);
        Ok(())
    }

    /// Um pedido pelo enlace, pela relação `relacao`: `Ok(Ok)` com o
    /// envelope que o gate daqui escreveu, `Ok(Err)` com a recusa em claro
    /// de quem encerrou o enlace.
    pub(super) fn pedir(
        &mut self,
        relacao: &str,
        metodo: &str,
        params: &str,
    ) -> Result<Result<String, String>, &'static str> {
        let msg = alloc::format!(
            "{{\"relation\":\"{relacao}\",\"program\":\"{}\",\"rpc\":{}}}\n",
            sigilo::hex(&PROGRAMA_ATESTADO),
            super::pedido_rpc(metodo, params)
        );
        self.mandar_dados(msg.as_bytes())?;
        let mut texto = Vec::new();
        for (tipo, corpo) in self.quadros()? {
            match tipo {
                Tipo::Dados => {
                    let t = self.transporte.as_mut().ok_or("o par nao tem transporte")?;
                    let mut claro = alloc::vec![0u8; corpo.len()];
                    let n = t
                        .decifrar(&corpo, &mut claro)
                        .map_err(|_| "a resposta do respondedor nao abriu")?;
                    texto.extend_from_slice(&claro[..n]);
                }
                Tipo::Recusa => return Ok(Err(String::from_utf8_lossy(&corpo).into_owned())),
                _ => return Err("o respondedor mandou um quadro fora de ordem"),
            }
        }
        if texto.last() != Some(&b'\n') {
            return Ok(Err(String::from("sem resposta")));
        }
        texto.pop();
        String::from_utf8(texto)
            .map(Ok)
            .map_err(|_| "a resposta nao e texto")
    }

    /// Um pedido que tem de ser respondido: o envelope.
    fn respondido(&mut self, metodo: &str, params: &str) -> Result<String, &'static str> {
        self.pedir(RELACAO, metodo, params)?.map_err(|m| {
            crate::log_error!("teste", "{}: {}", metodo, m);
            "o enlace caiu num pedido que devia ser respondido"
        })
    }
}

/// O código de um envelope: `ALLOW` se o resultado diz `ok`, o da recusa do
/// gate, ou o `code` do resultado.
pub(super) fn codigo_do_envelope(envelope: &str) -> String {
    let j = Json(envelope.as_bytes());
    if let Some(e) = j.member("error") {
        return e
            .member("data")
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_default();
    }
    let r = j.member("result");
    if r.and_then(|r| r.member("ok")).and_then(|v| v.as_bool()) == Some(true) {
        return String::from("ALLOW");
    }
    r.and_then(|r| r.member("code"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_default()
}

/// Roda `f` com a malha, os dispositivos e o enlace vazios, e confere no
/// fim que a tabela do enlace, o registro e a malha não quebraram as regras
/// deles.
pub(super) fn com_o_enlace(f: impl FnOnce() -> Resultado) -> Resultado {
    super::com_a_malha(|| {
        com_dispositivos_de_teste(|| {
            crate::enlace::esvaziar_de_teste();
            crate::autorizacao::esquecer_apertos_do_enlace_de_teste();
            let r = f();
            let coerente = crate::enlace::coerente() && crate::dispositivos::coerente();
            crate::enlace::esvaziar_de_teste();
            crate::autorizacao::esquecer_apertos_do_enlace_de_teste();
            r?;
            if !coerente {
                return Err("o enlace ou o registro de dispositivos ficou incoerente");
            }
            Ok(())
        })
    })
}

/// Relaciona o dispositivo de teste `n`, como `nome`, à pessoa `pessoa`,
/// com o papel `papel` e a relação `relacao`.
pub(super) fn relacionar(
    pessoa: sigilo::pessoas::IdPessoa,
    nome: &str,
    n: u8,
    papel: &str,
    relacao: &str,
) -> Result<(), &'static str> {
    let p = registro_de_dispositivo(
        &chave_de_dispositivo(n),
        nome,
        pessoa,
        papel,
        Some("tcp:10.0.2.100:7071"),
        Some(relacao),
    );
    admin("device.register", &p, None).map(|_| ())
}

/// A pessoa `nome` com uma sessão aberta: a sessão e o identificador.
pub(super) fn pessoa_com_sessao(
    nome: &str,
    papel: &str,
) -> Result<(crate::pessoas::IdSessao, sigilo::pessoas::IdPessoa), &'static str> {
    let sessao = crate::pessoas::sessao_de_teste(Console::Terminal(41), nome, papel);
    let id = crate::pessoas::dona_da_sessao(sessao).ok_or("a sessao de teste nao tem pessoa")?;
    Ok((sessao, id))
}

/// A política padrão com `de` trocado por `para`, posta em vigor. O caso
/// volta à do disco no fim — ver `com_a_malha`.
pub(super) fn politica_com(de: &str, para: &str) -> Resultado {
    let texto = politica::PADRAO.replace(de, para);
    if texto == politica::PADRAO {
        return Err("a troca da politica do caso nao achou o trecho");
    }
    let p = politica::Politica::ler(&texto).map_err(|_| "a politica do caso nao se le")?;
    crate::autorizacao::trocar_politica(p);
    Ok(())
}

/// O impostor de `autoridade`, oferecendo a intenção dos casos: ele não lê
/// o que chega, e as entregas ficam pendentes. O endpoint.
pub(super) fn endpoint_que_nao_le(autoridade: Autoridade) -> Result<String, &'static str> {
    super::NaMalha::lancar("impostor", autoridade, "impostor: pronto")?;
    let (_, endpoint) = super::passo_na_malha(
        super::CANAL_DO_IMPOSTOR,
        super::IMPOSTOR_OFERECER,
        0,
        "impostor: endpoint ",
    )?;
    Ok(endpoint)
}

/// O par relacionado entrega à malha daqui, de ponta a ponta: o aperto com
/// o prólogo do enlace e a chave no registro de dispositivos; a confirmação
/// pelo primeiro quadro que abre; a descoberta, a entrega e o estado pelo
/// gate daqui, como o dispositivo — a pessoa da relação ∩ a relação ∩ o
/// teto `remoto` —; o correio da pessoa recebe e sabe de que dispositivo
/// veio; e a auditoria grava o aperto, cada decisão com o dispositivo, a
/// relação e o programa que a origem atesta, sem o corpo.
pub(super) fn enlace_o_par_entrega_pela_malha_daqui() -> Resultado {
    com_o_enlace(|| {
        let (sessao, bia) = pessoa_com_sessao("bia", "operador")?;
        relacionar(bia, "par", 1, "dispositivo", RELACAO)?;
        let antes = crate::autorizacao::ultimo_registro();
        let (_correio, endpoint) = super::NaMalha::lancar(
            "correio",
            Autoridade::Pessoa { sessao },
            "correio: endpoint ",
        )?;
        let r = (|| -> Resultado {
            let mut par = Par::novo(VAGA, 1_000_001);
            par.apertar(&privada_de_dispositivo(1), [1; 8])?
                .map_err(|_| "o respondedor recusou o aperto do par relacionado")?;
            // Respondido não é confirmado: nada ainda é do par.
            if par.ponta.confirmada.is_some()
                || !registros_depois(antes, |e| e.metodo == "link.open").is_empty()
            {
                return Err("o aperto do enlace contou antes da confirmacao");
            }
            let intent = alloc::format!(r#"{{"intent":"{}"}}"#, super::INTENCAO_DA_MALHA);
            let achei = par.respondido("fabric.discover", &intent)?;
            if par.ponta.confirmada != Some(chave_de_dispositivo(1))
                || codigo_do_envelope(&achei) != "ALLOW"
                || !achei.contains(&endpoint)
            {
                crate::log_error!("teste", "{}", achei);
                return Err("o par nao achou o correio da pessoa da relacao");
            }
            let desde = crate::log::total_emitidos();
            let mandada = par.respondido(
                "fabric.send",
                &alloc::format!(
                    r#"{{"endpoint":"{endpoint}","intent":"{}","body":"foto-remota","nonce":1}}"#,
                    super::INTENCAO_DA_MALHA
                ),
            )?;
            let id = super::fs_texto(&mandada, "id").ok_or("a entrega remota nao tem id")?;
            let recebi = super::dito_na_malha(desde, "correio: recebi ")?;
            if recebi != "foto-remota de dispositivo:par" {
                crate::log_error!("teste", "{}", recebi);
                return Err("o correio nao recebeu do dispositivo que mandou");
            }
            let mut estado = String::new();
            let mut ultimo = 0;
            super::esperar_ate(
                || {
                    // Um pedido a cada dez tiques: a taxa da relação não se
                    // gasta em perguntas.
                    let agora = crate::tempo::ticks();
                    if agora < ultimo + 10 {
                        return false;
                    }
                    ultimo = agora;
                    estado = par
                        .respondido("fabric.status", &alloc::format!(r#"{{"id":"{id}"}}"#))
                        .unwrap_or_default();
                    estado.contains(r#""reply":"guardada:foto-remota""#)
                },
                super::TETO_DA_MALHA,
            )
            .map_err(|_| {
                crate::log_error!("teste", "{}", estado);
                "o par nao viu a confirmacao com a resposta"
            })?;
            // A auditoria: o aperto, e cada decisão como o dispositivo.
            let aperto = registros_depois(antes, |e| {
                e.metodo == "link.open"
                    && e.codigo == Codigo::Allow
                    && e.agente == "par"
                    && e.titular == politica::auditoria::Titular::Dispositivo
                    && e.detalhe.starts_with("aperto completo")
            });
            let pelo = "pela relacao 5a5a5a5a, atestado abababab";
            let decididos = registros_depois(antes, |e| {
                e.titular == politica::auditoria::Titular::Dispositivo
                    && e.agente == "par"
                    && e.papel == "dispositivo"
                    && e.detalhe.starts_with(pelo)
            });
            let metodos: Vec<&str> = decididos.iter().map(|(_, e)| e.metodo.as_str()).collect();
            let entrega = alloc::format!("entrega:{id}");
            let executada = super::gravado_na_malha(
                antes,
                "fabric.send",
                &alloc::format!("{entrega} ; endpoint:{endpoint}"),
                Codigo::Allow,
                "aceita, pendente",
            );
            if aperto.len() != 1
                || !metodos.contains(&"fabric.discover")
                || !metodos.contains(&"fabric.send")
                || !metodos.contains(&"fabric.status")
                || !executada
            {
                crate::log_error!(
                    "teste",
                    "{} aperto(s), {:?}, {}",
                    aperto.len(),
                    metodos,
                    executada
                );
                return Err(
                    "o enlace nao foi gravado com o dispositivo, a relacao e o programa atestado",
                );
            }
            if !super::nada_gravado_com(antes, "foto-remota") {
                return Err("a auditoria gravou o corpo de uma entrega remota");
            }
            // Nenhum registro do enlace chega ao teto do detalhe: um que
            // chegasse teria o motivo cortado.
            let cortados = registros_depois(antes, |e| {
                e.titular == politica::auditoria::Titular::Dispositivo
                    && e.detalhe.len() >= politica::auditoria::MAIOR_DETALHE
            });
            if !cortados.is_empty() {
                crate::log_error!("teste", "{:?}", cortados[0].1.detalhe);
                return Err("um registro do enlace foi cortado no teto do detalhe");
            }
            Ok(())
        })();
        super::encerrar_o_correio(Autoridade::Pessoa { sessao }, &endpoint)?;
        r
    })
}

/// Só o conjunto fechado da malha chega de outro dispositivo: oferecer,
/// ler, confirmar, retirar e qualquer comando fora da malha são recusados
/// pelo gate, e gravados, cada um pelo motivo dele; um pedido de lá com
/// `device` não vai a um terceiro; com a relação, a pessoa e o teto
/// `remoto` permitindo um comando de fora, ele ainda não chega; e a relação
/// de outro par não é dele.
pub(super) fn enlace_so_o_conjunto_fechado() -> Resultado {
    com_o_enlace(|| {
        let (_, bia) = pessoa_com_sessao("bia", "operador")?;
        relacionar(bia, "par", 1, "dispositivo", RELACAO)?;
        let (_, caio) = pessoa_com_sessao("caio", "operador")?;
        relacionar(caio, "outro", 2, "dispositivo", OUTRA_RELACAO)?;
        let antes = crate::autorizacao::ultimo_registro();
        let mut par = Par::novo(VAGA, 1_000_002);
        par.apertar(&privada_de_dispositivo(1), [2; 8])?
            .map_err(|_| "o respondedor recusou o aperto do par relacionado")?;
        let intent = super::INTENCAO_DA_MALHA;
        let fora = [
            ("fabric.offer", alloc::format!(r#"{{"intent":"{intent}"}}"#)),
            ("fabric.recv", String::from(r#"{"endpoint":"x:1"}"#)),
            ("fabric.ack", String::from(r#"{"id":"x:1"}"#)),
            ("fabric.withdraw", String::from(r#"{"endpoint":"x:1"}"#)),
            ("fs.read", String::from(r#"{"path":"/etc/duke/politica"}"#)),
            ("agent.ping", String::from("{}")),
            ("person.registry", String::from("{}")),
            (
                "fabric.discover",
                alloc::format!(r#"{{"intent":"{intent}","device":"dispositivo:par"}}"#),
            ),
        ];
        for (metodo, params) in &fora {
            let r = par.respondido(metodo, params)?;
            if codigo_do_envelope(&r) != "DENY_PERMISSION" {
                crate::log_error!("teste", "{}: {}", metodo, r);
                return Err("um comando fora do conjunto fechado passou para outro dispositivo");
            }
        }
        let gravados = registros_depois(antes, |e| {
            e.codigo == Codigo::DenyPermission
                && e.titular == politica::auditoria::Titular::Dispositivo
                && e.agente == "par"
        });
        if gravados.len() != fora.len() {
            crate::log_error!("teste", "{} de {}", gravados.len(), fora.len());
            return Err("as recusas do conjunto fechado nao foram todas gravadas");
        }
        // Cada recusa pelo motivo dela, inteiro — e não pelo de outra camada
        // que recusasse o mesmo (o papel da relação, o da pessoa, o teto, o
        // endpoint que é de um processo): fora do conjunto fechado, o
        // conjunto fechado; com `device`, nada vai a um terceiro. E nenhum
        // registro cortado no teto do detalhe: o motivo cabe com a relação e
        // o programa atestado.
        for (metodo, params) in &fora {
            let motivo = if params.contains(r#""device""#) {
                "um pedido de outro dispositivo nao vai a um terceiro"
            } else {
                FORA_DO_CONJUNTO
            };
            if !gravados.iter().any(|(_, e)| {
                e.metodo == *metodo
                    && e.detalhe.ends_with(motivo)
                    && e.detalhe.len() < politica::auditoria::MAIOR_DETALHE
            }) {
                crate::log_error!("teste", "{}: sem `{}`", metodo, motivo);
                return Err("um comando de outro dispositivo nao foi recusado pelo motivo dele");
            }
        }
        // A relação, a pessoa e o teto `remoto` permitindo um comando de
        // fora da malha: ele ainda não chega — o conjunto fechado é do gate,
        // e não da política.
        crate::autorizacao::trocar_politica(super::politica_trocada(&[
            (
                "papel dispositivo fabric.send\n",
                "papel dispositivo fabric.send random.read\n",
            ),
            (
                "papel remoto fabric.send\n",
                "papel remoto fabric.send random.read\n",
            ),
        ])?);
        let antes = crate::autorizacao::ultimo_registro();
        let r = par.respondido("random.read", r#"{"bytes":8}"#)?;
        let fechado = registros_depois(antes, |e| {
            e.metodo == "random.read" && e.detalhe.ends_with(FORA_DO_CONJUNTO)
        });
        if codigo_do_envelope(&r) != "DENY_PERMISSION" || fechado.len() != 1 {
            crate::log_error!("teste", "{}", r);
            return Err("um comando fora do conjunto fechado passou com a politica deixando");
        }
        // A relação de outro par: o pedido não autentica.
        let r = par
            .pedir(
                OUTRA_RELACAO,
                "fabric.discover",
                &alloc::format!(r#"{{"intent":"{intent}"}}"#),
            )?
            .map_err(|_| "o enlace caiu na relacao de outro")?;
        if codigo_do_envelope(&r) != "DENY_NOT_AUTHENTICATED" {
            crate::log_error!("teste", "{}", r);
            return Err("o par falou pela relacao de outro dispositivo");
        }
        // Uma linha fora do protocolo encerra o enlace.
        par.mandar_dados(b"{\"rpc\":1}\n")?;
        if !par.lado.encerrada() || !par.ponta.encerrou {
            return Err("uma linha fora do protocolo do enlace nao encerrou a sessao");
        }
        Ok(())
    })
}

/// A autoridade de quem pede de outro dispositivo é a interseção: sem a
/// linha `remoto`, nada passa; a relação sem a permissão, nem a pessoa sem
/// ela, também não; e a pessoa revogada leva a relação junto.
pub(super) fn enlace_a_autoridade_composta() -> Resultado {
    com_o_enlace(|| {
        let (_, bia) = pessoa_com_sessao("bia", "operador")?;
        relacionar(bia, "par", 1, "dispositivo", RELACAO)?;
        let intent = alloc::format!(r#"{{"intent":"{}"}}"#, super::INTENCAO_DA_MALHA);
        let pedir = |epoca: u8| -> Result<String, &'static str> {
            let mut par = Par::novo(VAGA + 1, 1_000_010 + u64::from(epoca));
            par.apertar(&privada_de_dispositivo(1), [epoca; 8])?
                .map_err(|_| "o respondedor recusou o aperto do par relacionado")?;
            par.respondido("fabric.discover", &intent)
        };
        let r = pedir(1)?;
        if codigo_do_envelope(&r) != "ALLOW" {
            crate::log_error!("teste", "{}", r);
            return Err("o par relacionado nao descobriu com a politica padrao");
        }
        // Sem a linha `remoto`: o teto vazio recusa tudo.
        politica_com("remoto remoto\n", "")?;
        let r = pedir(2)?;
        if codigo_do_envelope(&r) != "DENY_ROLE" {
            crate::log_error!("teste", "{}", r);
            return Err("sem a linha remoto, um pedido de outro dispositivo passou");
        }
        crate::autorizacao::carregar();
        // O teto sem a intenção.
        politica_com(
            "recurso remoto fabric.send intencao:imagem.compartilhar intencao:pdf.anotar",
            "recurso remoto fabric.send intencao:pdf.anotar",
        )?;
        let r = pedir(3)?;
        if codigo_do_envelope(&r) != "DENY_RESOURCE" {
            crate::log_error!("teste", "{}", r);
            return Err("o teto remoto sem a intencao deixou passar");
        }
        crate::autorizacao::carregar();
        // A relação sem a intenção.
        politica_com(
            "recurso dispositivo fabric.send intencao:imagem.compartilhar intencao:pdf.anotar",
            "recurso dispositivo fabric.send intencao:pdf.anotar",
        )?;
        let r = pedir(4)?;
        if codigo_do_envelope(&r) != "DENY_RESOURCE" {
            crate::log_error!("teste", "{}", r);
            return Err("o papel da relacao sem a intencao deixou passar");
        }
        crate::autorizacao::carregar();
        // A pessoa sem a intenção.
        politica_com(
            "recurso operador fabric.send intencao:imagem.compartilhar intencao:pdf.anotar",
            "recurso operador fabric.send intencao:pdf.anotar",
        )?;
        let antes = crate::autorizacao::ultimo_registro();
        let r = pedir(5)?;
        let explicada = !registros_depois(antes, |e| {
            e.codigo == Codigo::DenyResource
                && e.detalhe
                    .contains("o papel da pessoa da relacao nao permite")
        })
        .is_empty();
        if codigo_do_envelope(&r) != "DENY_RESOURCE" || !explicada {
            crate::log_error!("teste", "{}", r);
            return Err("o papel da pessoa sem a intencao deixou passar, ou nao se disse");
        }
        crate::autorizacao::carregar();
        // A pessoa revogada: a relação não autentica mais.
        crate::pessoas::revogar_pessoa(bia).map_err(|_| "a pessoa nao se revogou")?;
        let r = pedir(6)?;
        if codigo_do_envelope(&r) != "DENY_NOT_AUTHENTICATED" {
            crate::log_error!("teste", "{}", r);
            return Err("a relacao de uma pessoa revogada ainda pediu");
        }
        Ok(())
    })
}

/// O aperto do enlace confere o registro de dispositivos, e só ele: a chave
/// desconhecida, a de um agente e a do dispositivo suspenso são recusadas,
/// com a chave alegada na auditoria; o início do aperto do agente não abre
/// a vaga do enlace; e a primeira mensagem repetida responde, mas não
/// confirma — quem repete não tem a efêmera, e o quadro dele não abre.
pub(super) fn enlace_o_aperto_confere_o_registro() -> Resultado {
    com_o_enlace(|| {
        let (_, bia) = pessoa_com_sessao("bia", "operador")?;
        relacionar(bia, "par", 1, "dispositivo", RELACAO)?;
        let antes = crate::autorizacao::ultimo_registro();
        // Fora do registro.
        let mut p = Par::novo(VAGA, 1_000_020);
        match p.apertar(&privada_de_dispositivo(7), [1; 8])? {
            Err(m) if m == "chave fora do registro de dispositivos" => {}
            outro => {
                crate::log_error!("teste", "{:?}", outro);
                return Err("uma chave fora do registro de dispositivos fez o aperto do enlace");
            }
        }
        // A de um agente — de outra espécie de principal.
        let agente = sigilo::publica_de(&[0x7a; 32]);
        crate::identidade::registrar_agente_de_teste(agente, "agente-enlace", "operador");
        let mut p = Par::novo(VAGA, 1_000_021);
        match p.apertar(&[0x7a; 32], [1; 8])? {
            Err(m) if m == "chave fora do registro de dispositivos" => {}
            outro => {
                crate::log_error!("teste", "{:?}", outro);
                return Err("a chave de um agente fez o aperto do enlace");
            }
        }
        // O início do aperto do agente, na vaga do enlace.
        let mut p = Par::novo(VAGA, 1_000_022);
        p.empurrar(&quadro::montar(Tipo::Inicio, &[0u8; 96]).map_err(|_| "quadro")?);
        if !p.ponta.encerrou || !p.lado.encerrada() {
            return Err("o inicio do aperto do agente nao encerrou a vaga do enlace");
        }
        let recusas = registros_depois(antes, |e| {
            e.metodo == "link.open" && e.codigo == Codigo::DenyNotAuthenticated
        });
        let alegadas: Vec<Option<[u8; 32]>> = recusas.iter().map(|(_, e)| e.chave).collect();
        if recusas.len() != 3
            || !alegadas.contains(&Some(chave_de_dispositivo(7)))
            || !alegadas.contains(&Some(agente))
        {
            crate::log_error!("teste", "{} recusa(s)", recusas.len());
            return Err("as recusas do aperto do enlace nao foram gravadas com a chave alegada");
        }
        // A primeira mensagem repetida: responde, não confirma, e o quadro de
        // quem a repete não abre.
        let mut original = Par::novo(VAGA, 1_000_023);
        original
            .apertar(&privada_de_dispositivo(1), [3; 8])?
            .map_err(|_| "o aperto do par relacionado foi recusado")?;
        let primeira = original.primeira.clone();
        let mut repetido = Par::novo(VAGA + 1, 1_000_024);
        repetido.empurrar(&primeira);
        let respondeu = matches!(repetido.quadros()?.as_slice(), [(Tipo::Resposta, _)]);
        // Quem repete manda um quadro de dados com a cifra da sessão original.
        repetido.transporte = original.transporte.take();
        repetido.mandar_dados(b"{}\n")?;
        if !respondeu || repetido.ponta.confirmada.is_some() || !repetido.lado.encerrada() {
            return Err("a primeira mensagem repetida confirmou um enlace");
        }
        Ok(())
    })
}

/// O nonce do canal remoto é da (chave, relação, época da origem): o mesmo
/// pedido com o mesmo nonce é o reenvio — o mesmo id, nada criado —; o
/// mesmo nonce com outro corpo, e um nonce velho, são replay; e outra época
/// — o boot seguinte da origem — é uma janela nova.
pub(super) fn enlace_o_replay_e_o_reenvio() -> Resultado {
    com_o_enlace(|| {
        let (sessao, bia) = pessoa_com_sessao("bia", "operador")?;
        relacionar(bia, "par", 1, "dispositivo", RELACAO)?;
        let endpoint = endpoint_que_nao_le(Autoridade::Pessoa { sessao })?;
        let r = (|| -> Resultado {
            let mandar = |par: &mut Par, corpo: &str, nonce: u64| {
                par.respondido(
                    "fabric.send",
                    &alloc::format!(
                        r#"{{"endpoint":"{endpoint}","intent":"{}","body":"{corpo}","nonce":{nonce}}}"#,
                        super::INTENCAO_DA_MALHA
                    ),
                )
            };
            let mut par = Par::novo(VAGA, 1_000_030);
            par.apertar(&privada_de_dispositivo(1), [4; 8])?
                .map_err(|_| "o aperto do par relacionado foi recusado")?;
            let a = mandar(&mut par, "um", 5)?;
            let b = mandar(&mut par, "um", 5)?;
            let c = mandar(&mut par, "dois", 5)?;
            let d = mandar(&mut par, "tres", 4)?;
            let ida = super::fs_texto(&a, "id");
            let idb = super::fs_texto(&b, "id");
            if ida.is_none()
                || ida != idb
                || !b.contains(r#""duplicate":true"#)
                || codigo_do_envelope(&c) != "DENY_REPLAY"
                || codigo_do_envelope(&d) != "DENY_REPLAY"
            {
                crate::log_error!("teste", "{} | {} | {} | {}", a, b, c, d);
                return Err("o reenvio ou o replay pelo enlace nao foi o da janela");
            }
            // Outro enlace na mesma época: a mesma janela — o reenvio depois de
            // uma queda é reconhecido.
            let mut de_novo = Par::novo(VAGA + 1, 1_000_031);
            de_novo
                .apertar(&privada_de_dispositivo(1), [4; 8])?
                .map_err(|_| "o aperto do par relacionado foi recusado")?;
            let e = mandar(&mut de_novo, "um", 5)?;
            // Outra época: a janela é nova, e o nonce 1 vale.
            let mut outro_boot = Par::novo(VAGA + 2, 1_000_032);
            outro_boot
                .apertar(&privada_de_dispositivo(1), [5; 8])?
                .map_err(|_| "o aperto do par relacionado foi recusado")?;
            let f = mandar(&mut outro_boot, "quatro", 1)?;
            if super::fs_texto(&e, "id") != ida || codigo_do_envelope(&f) != "ALLOW" {
                crate::log_error!("teste", "{} | {}", e, f);
                return Err(
                    "a janela do canal remoto nao atravessou a reconexao, ou a epoca nova herdou a velha",
                );
            }
            Ok(())
        })();
        super::encerrar_na_malha(super::CANAL_DO_IMPOSTOR, super::SAIDA_DO_IMPOSTOR)?;
        r
    })
}

/// A revogação do dispositivo, com o enlace de pé: a sessão cai na hora,
/// com a recusa em claro; a entrega viva que ele mandou é anulada, para a
/// auditoria; um quadro dele depois não é executado; e um aperto novo da
/// mesma chave é recusado — a lápide vale para o enlace também.
pub(super) fn enlace_a_revogacao_derruba_e_anula() -> Resultado {
    com_o_enlace(|| {
        let (sessao, bia) = pessoa_com_sessao("bia", "operador")?;
        relacionar(bia, "par", 1, "dispositivo", RELACAO)?;
        let endpoint = endpoint_que_nao_le(Autoridade::Pessoa { sessao })?;
        let r = (|| -> Resultado {
            let mut par = Par::novo(VAGA, 1_000_040);
            par.apertar(&privada_de_dispositivo(1), [6; 8])?
                .map_err(|_| "o aperto do par relacionado foi recusado")?;
            let mandada = par.respondido(
                "fabric.send",
                &alloc::format!(
                    r#"{{"endpoint":"{endpoint}","intent":"{}","body":"pendente","nonce":1}}"#,
                    super::INTENCAO_DA_MALHA
                ),
            )?;
            let id = super::fs_texto(&mandada, "id").ok_or("a entrega remota nao tem id")?;
            if crate::malha::contagem().1 != 1 {
                return Err("a entrega remota nao ficou viva");
            }
            let antes = crate::autorizacao::ultimo_registro();
            admin(
                "device.revoke",
                &alloc::format!(r#"{{"key":"{}"}}"#, sigilo::hex(&chave_de_dispositivo(1))),
                None,
            )?;
            if crate::malha::contagem().1 != 0 {
                return Err("a entrega viva do dispositivo revogado nao foi anulada");
            }
            let anulada = super::gravado_na_malha(
                antes,
                "fabric.void",
                &alloc::format!("entrega:{id}"),
                Codigo::Allow,
                "anulada: dispositivo revogado",
            );
            if !anulada {
                return Err("a anulacao da entrega remota nao foi gravada");
            }
            // O pedido depois da revogação: a sessão já caiu por fora.
            let depois = par.pedir(
                RELACAO,
                "fabric.discover",
                &alloc::format!(r#"{{"intent":"{}"}}"#, super::INTENCAO_DA_MALHA),
            )?;
            if depois.is_ok() || !par.lado.encerrada() {
                crate::log_error!("teste", "{:?}", depois);
                return Err("o enlace do dispositivo revogado ainda atendeu");
            }
            let mut de_novo = Par::novo(VAGA + 1, 1_000_041);
            match de_novo.apertar(&privada_de_dispositivo(1), [6; 8])? {
                Err(m) if m == "chave fora do registro de dispositivos" => Ok(()),
                outro => {
                    crate::log_error!("teste", "{:?}", outro);
                    Err("a chave revogada fez o aperto do enlace de novo")
                }
            }
        })();
        super::encerrar_na_malha(super::CANAL_DO_IMPOSTOR, super::SAIDA_DO_IMPOSTOR)?;
        r
    })
}

/// A suspensão, pelo gate — `device.suspend` do sistema —: o enlace cai, a
/// entrega viva dele é anulada, o aperto novo é recusado como credencial
/// suspensa; retomado, ele volta a entrar e a pedir. Não é revogação: a
/// relação continua no registro.
pub(super) fn enlace_a_suspensao_derruba_e_volta() -> Resultado {
    com_o_enlace(|| {
        let (sessao, bia) = pessoa_com_sessao("bia", "operador")?;
        relacionar(bia, "par", 1, "dispositivo", RELACAO)?;
        let endpoint = endpoint_que_nao_le(Autoridade::Pessoa { sessao })?;
        let r = (|| -> Resultado {
            let mut par = Par::novo(VAGA, 1_000_050);
            par.apertar(&privada_de_dispositivo(1), [7; 8])?
                .map_err(|_| "o aperto do par relacionado foi recusado")?;
            par.respondido(
                "fabric.send",
                &alloc::format!(
                    r#"{{"endpoint":"{endpoint}","intent":"{}","body":"pendente","nonce":1}}"#,
                    super::INTENCAO_DA_MALHA
                ),
            )?;
            let sistema = crate::autorizacao::Chamador::Processo {
                fio: 7_897_001,
                autoridade: Autoridade::Sistema,
                programa: crate::autorizacao::Programa::Kernel,
            };
            let r = super::fs_pedir(sistema, "device.suspend", r#"{"device":"dispositivo:par"}"#);
            if !r.contains(r#""contained":true"#) {
                crate::log_error!("teste", "{}", r);
                return Err("o sistema nao suspendeu o dispositivo pelo gate");
            }
            if crate::malha::contagem().1 != 0
                || crate::enlace::sessoes()
                    .iter()
                    .any(|(_, k, _)| *k == chave_de_dispositivo(1))
            {
                return Err("a suspensao nao derrubou o enlace e anulou a entrega viva");
            }
            let depois = par.pedir(
                RELACAO,
                "fabric.discover",
                &alloc::format!(r#"{{"intent":"{}"}}"#, super::INTENCAO_DA_MALHA),
            )?;
            if depois.is_ok() || !par.lado.encerrada() {
                return Err("o enlace do dispositivo suspenso ainda atendeu");
            }
            let mut suspenso = Par::novo(VAGA + 1, 1_000_051);
            match suspenso.apertar(&privada_de_dispositivo(1), [7; 8])? {
                Err(m) if m == "dispositivo suspenso" => {}
                outro => {
                    crate::log_error!("teste", "{:?}", outro);
                    return Err("o dispositivo suspenso fez o aperto do enlace");
                }
            }
            if crate::dispositivos::por_nome("par").is_none() {
                return Err("a suspensao tirou a relacao do registro");
            }
            let r = super::fs_pedir(sistema, "device.resume", r#"{"device":"dispositivo:par"}"#);
            if !r.contains(r#""contained":false"#) {
                crate::log_error!("teste", "{}", r);
                return Err("o sistema nao retomou o dispositivo");
            }
            let mut retomado = Par::novo(VAGA + 2, 1_000_052);
            retomado
                .apertar(&privada_de_dispositivo(1), [7; 8])?
                .map_err(|_| "o dispositivo retomado nao entrou")?;
            let r = retomado.respondido(
                "fabric.discover",
                &alloc::format!(r#"{{"intent":"{}"}}"#, super::INTENCAO_DA_MALHA),
            )?;
            if codigo_do_envelope(&r) != "ALLOW" {
                crate::log_error!("teste", "{}", r);
                return Err("o dispositivo retomado nao pediu");
            }
            Ok(())
        })();
        super::encerrar_na_malha(super::CANAL_DO_IMPOSTOR, super::SAIDA_DO_IMPOSTOR)?;
        r
    })
}

/// A revogação entre a decisão do gate e o commit: a entrega remota foi
/// decidida com a relação de pé, e a reconfirmação, com a ordem das
/// gravações na mão, a acha revogada — nada é criado na malha.
pub(super) fn enlace_a_reconfirmacao_no_commit() -> Resultado {
    fn revogar_no_meio() {
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        let _ = crate::dispositivos::revogar(&chave_de_dispositivo(1));
        crate::enlace::dispositivo_revogado(&chave_de_dispositivo(1));
    }
    com_o_enlace(|| {
        let (sessao, bia) = pessoa_com_sessao("bia", "operador")?;
        relacionar(bia, "par", 1, "dispositivo", RELACAO)?;
        let endpoint = endpoint_que_nao_le(Autoridade::Pessoa { sessao })?;
        let r = (|| -> Resultado {
            let mut par = Par::novo(VAGA, 1_000_060);
            par.apertar(&privada_de_dispositivo(1), [8; 8])?
                .map_err(|_| "o aperto do par relacionado foi recusado")?;
            let antes = crate::autorizacao::ultimo_registro();
            crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(revogar_no_meio));
            let r = par.pedir(
                RELACAO,
                "fabric.send",
                &alloc::format!(
                    r#"{{"endpoint":"{endpoint}","intent":"{}","body":"no-meio","nonce":1}}"#,
                    super::INTENCAO_DA_MALHA
                ),
            )?;
            crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
            let decidida = super::gravado_na_malha(
                antes,
                "fabric.send",
                "intencao:imagem.compartilhar",
                Codigo::Allow,
                "pela relacao 5a5a5a5a",
            );
            let recusada = !registros_depois(antes, |e| {
                e.metodo == "fabric.send"
                    && e.codigo == Codigo::DenyNotAuthenticated
                    && e.detalhe.contains("nao esta mais ativa")
            })
            .is_empty();
            if !decidida || !recusada || crate::malha::contagem().1 != 0 {
                crate::log_error!("teste", "{:?} {} {}", r, decidida, recusada);
                return Err("a revogacao no meio nao recusou a entrega remota no commit");
            }
            Ok(())
        })();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        super::encerrar_na_malha(super::CANAL_DO_IMPOSTOR, super::SAIDA_DO_IMPOSTOR)?;
        r
    })
}

/// O outro Duke do lado de lá do serviço de enlace, na suíte: a chave de
/// teste dele, o respondedor do `sigilo` com o prólogo do enlace, e o que
/// ele viu — a chave de quem apertou, a mensagem e a linha. Responde com
/// `resposta`, ou recusa o aperto.
struct ParQueResponde {
    privada: [u8; 32],
    resposta: Option<String>,
    leitor: Leitor,
    transporte: Option<sigilo::Transporte>,
    saida: Vec<u8>,
    viu_chave: Option<[u8; 32]>,
    viu_mensagem: String,
}

impl ParQueResponde {
    fn novo(privada: [u8; 32], resposta: Option<&str>) -> ParQueResponde {
        ParQueResponde {
            privada,
            resposta: resposta.map(String::from),
            leitor: Leitor::novo(),
            transporte: None,
            saida: Vec::new(),
            viu_chave: None,
            viu_mensagem: String::new(),
        }
    }
}

impl crate::enlace::Via for ParQueResponde {
    fn mandar(&mut self, bytes: &[u8]) -> Result<(), (Codigo, &'static str)> {
        for &b in bytes {
            let Ok(Some((tipo, corpo))) = self.leitor.empurrar(b) else {
                continue;
            };
            let corpo = corpo.to_vec();
            match tipo {
                Tipo::InicioEnlace => {
                    let mut carga = alloc::vec![0u8; corpo.len()];
                    let Ok((_, recebido)) =
                        sigilo::Respondedor::novo(sigilo::PROLOGO_DO_ENLACE, &self.privada)
                            .ler(&corpo, &mut carga)
                    else {
                        self.saida
                            .extend(quadro::montar(Tipo::Recusa, b"nao abriu").unwrap_or_default());
                        continue;
                    };
                    self.viu_chave = Some(recebido.remota());
                    if self.resposta.is_none() {
                        self.saida
                            .extend(quadro::montar(Tipo::Recusa, b"recusado").unwrap_or_default());
                        continue;
                    }
                    let mut r = alloc::vec![0u8; 256];
                    if let Ok((n, t)) = recebido.escrever([0x44; 32], b"{}", &mut r) {
                        self.transporte = Some(t);
                        self.saida
                            .extend(quadro::montar(Tipo::Resposta, &r[..n]).unwrap_or_default());
                    }
                }
                Tipo::Dados => {
                    let Some(t) = self.transporte.as_mut() else {
                        continue;
                    };
                    let mut claro = alloc::vec![0u8; corpo.len()];
                    let Ok(n) = t.decifrar(&corpo, &mut claro) else {
                        continue;
                    };
                    self.viu_mensagem
                        .push_str(&String::from_utf8_lossy(&claro[..n]));
                    if self.viu_mensagem.ends_with('\n') {
                        let texto =
                            alloc::format!("{}\n", self.resposta.clone().unwrap_or_default());
                        let mut c = alloc::vec![0u8; texto.len() + 64];
                        if let Ok(n) = t.cifrar(texto.as_bytes(), &mut c) {
                            self.saida
                                .extend(quadro::montar(Tipo::Dados, &c[..n]).unwrap_or_default());
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn receber(&mut self, _prazo_ms: u64) -> Result<Vec<u8>, (Codigo, &'static str)> {
        Ok(core::mem::take(&mut self.saida))
    }
}

/// A privada do par de teste da origem.
const PAR_DA_ORIGEM: [u8; 32] = [0xe1; 32];

/// A origem de ponta a ponta, com o par de teste do outro lado: a pessoa
/// pede com `device`, o gate decide as duas permissões, o pedido entra na
/// tabela e o comando suspende; o serviço leva — o aperto com a chave do
/// Duke e o prólogo do enlace, a relação, o programa atestado e a linha sem
/// o `device`, com o nonce do enlace —, a resposta volta, quem esperava
/// acorda e, executado de novo pelo gate, lê o que o par disse. A entrega
/// que ele mandou resolve depois, para `fabric.status`, só para ele.
pub(super) fn enlace_a_origem_decide_e_leva() -> Resultado {
    com_o_enlace(|| {
        let (sessao, bia) = pessoa_com_sessao("bia", "operador")?;
        let par = sigilo::publica_de(&PAR_DA_ORIGEM);
        let p = registro_de_dispositivo(
            &par,
            "par",
            bia,
            "dispositivo",
            Some("tcp:10.0.2.100:7071"),
            Some(RELACAO),
        );
        admin("device.register", &p, None)?;
        let quem = crate::autorizacao::Chamador::Pessoa(sessao);
        let antes = crate::autorizacao::ultimo_registro();
        let linha = super::pedido_rpc(
            "fabric.send",
            &alloc::format!(
                r#"{{"device":"dispositivo:par","endpoint":"e:1","intent":"{}","body":"ola","nonce":7}}"#,
                super::INTENCAO_DA_MALHA
            ),
        );
        let espera = match crate::nativo::responder_suspensivel_de_teste(quem, &linha) {
            Err(e) => e,
            Ok(r) => {
                crate::log_error!("teste", "{}", r);
                return Err("o pedido a outro dispositivo nao suspendeu");
            }
        };
        let decidida = super::gravado_na_malha(
            antes,
            "fabric.send",
            "intencao:imagem.compartilhar ; dispositivo:par",
            Codigo::Allow,
            "",
        );
        if !decidida || espera.conferir(None).is_some() {
            return Err("o pedido a outro dispositivo nao foi decidido com as duas permissoes");
        }
        let t = crate::enlace::tomar().ok_or("o pedido nao entrou na fila do enlace")?;
        let mut via = ParQueResponde::novo(
            PAR_DA_ORIGEM,
            Some(
                r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"id":"ep:3","version":1,"duplicate":false}}"#,
            ),
        );
        crate::enlace::levar_pela_via_de_teste(&t, &mut via);
        let mensagem = Json(via.viu_mensagem.trim_end().as_bytes());
        let rpc = mensagem
            .member("rpc")
            .ok_or("a mensagem do enlace nao tem a linha")?;
        let params = rpc.member("params").ok_or("a linha nao tem parametros")?;
        let certa = via.viu_chave == crate::identidade::publica_do_duke()
            && mensagem.member("relation").and_then(|v| v.as_str()) == Some(RELACAO)
            && mensagem.member("program").and_then(|v| v.as_str())
                == Some(sigilo::hex(&[0; 32]).as_str())
            && rpc.member("method").and_then(|v| v.as_str()) == Some("fabric.send")
            && params.member("device").is_none()
            && params.member("nonce").and_then(|v| v.as_u64()) == Some(1);
        if !certa {
            crate::log_error!("teste", "{}", via.viu_mensagem);
            return Err("o servico nao levou ao par o pedido decidido, com a chave do Duke");
        }
        if espera.conferir(None) != Some(crate::rede::espera::Desfecho::Chegou) {
            return Err("quem esperava nao acordou com a resposta do par");
        }
        drop(espera);
        let r = crate::nativo::responder_de_teste(quem, &linha);
        let res = Json(r.as_bytes()).member("result");
        let ok = res.and_then(|r| r.member("ok")).and_then(|v| v.as_bool()) == Some(true)
            && res
                .and_then(|r| r.member("device"))
                .and_then(|v| v.as_str())
                == Some("dispositivo:par")
            && res
                .and_then(|r| r.member("remote"))
                .and_then(|r| r.member("id"))
                .and_then(|v| v.as_str())
                == Some("ep:3");
        if !ok {
            crate::log_error!("teste", "{}", r);
            return Err("a reexecucao nao leu a resposta do par");
        }
        // O estado da entrega: resolve só para quem mandou — a pessoa; um
        // processo dela não a alcança, e um id inventado também não.
        let estado = |q, id: &str| {
            let linha = super::pedido_rpc(
                "fabric.status",
                &alloc::format!(r#"{{"device":"dispositivo:par","id":"{id}"}}"#),
            );
            match crate::nativo::responder_suspensivel_de_teste(q, &linha) {
                Ok(r) => codigo_do_envelope(&r),
                Err(_) => String::from("SUSPENSO"),
            }
        };
        let processo = super::simulado_na_malha(
            7_897_100,
            Autoridade::Pessoa { sessao },
            "fabric.send fabric.remote",
        );
        if estado(quem, "ep:3") != "SUSPENSO"
            || estado(processo, "ep:3") != "DENY_RESOURCE"
            || estado(quem, "ep:999") != "DENY_RESOURCE"
        {
            return Err("a entrega remota resolveu para quem nao a mandou");
        }
        Ok(())
    })
}

/// A origem recusa no gate daqui: a pessoa sem `fabric.send`, a pessoa com
/// ela e sem `fabric.remote`, o dispositivo de outra pessoa, o agente — que
/// não age por uma pessoa —, o manifesto sem `fabric.remote`, o dispositivo
/// suspenso; e o replay do nonce do processo, sem gastar nonce do enlace.
/// Cada recusa é da decisão: a reconfirmação no commit recusaria o mesmo,
/// mas depois de o gate ter deixado — e nenhuma decisão permite.
pub(super) fn enlace_a_origem_recusa() -> Resultado {
    com_o_enlace(|| {
        let (sessao, bia) = pessoa_com_sessao("bia", "operador")?;
        let (sessao_eva, _) = pessoa_com_sessao("eva", "observador")?;
        let (_, caio) = pessoa_com_sessao("caio", "operador")?;
        let par = sigilo::publica_de(&PAR_DA_ORIGEM);
        admin(
            "device.register",
            &registro_de_dispositivo(
                &par,
                "par",
                bia,
                "dispositivo",
                Some("tcp:10.0.2.100:7071"),
                Some(RELACAO),
            ),
            None,
        )?;
        admin(
            "device.register",
            &registro_de_dispositivo(
                &chave_de_dispositivo(3),
                "par-2",
                caio,
                "dispositivo",
                None,
                Some(OUTRA_RELACAO),
            ),
            None,
        )?;
        let mandar = |q, device: &str, nonce: u64, corpo: &str| {
            let linha = super::pedido_rpc(
                "fabric.send",
                &alloc::format!(
                    r#"{{"device":"{device}","endpoint":"e:1","intent":"{}","body":"{corpo}","nonce":{nonce}}}"#,
                    super::INTENCAO_DA_MALHA
                ),
            );
            match crate::nativo::responder_suspensivel_de_teste(q, &linha) {
                Ok(r) => codigo_do_envelope(&r),
                Err(_) => String::from("SUSPENSO"),
            }
        };
        let pessoa = crate::autorizacao::Chamador::Pessoa(sessao);
        let agente_chave = sigilo::publica_de(&[0x7b; 32]);
        crate::identidade::registrar_agente_de_teste(agente_chave, "agente-origem", "operador");
        let agente = super::simulado_na_malha(
            7_897_200,
            Autoridade::Sessao {
                sessao: 3,
                chave: Some(agente_chave),
            },
            "fabric.send fabric.remote",
        );
        let sem_manifesto =
            super::simulado_na_malha(7_897_201, Autoridade::Pessoa { sessao }, "fabric.send");
        let casos = [
            (
                crate::autorizacao::Chamador::Pessoa(sessao_eva),
                "dispositivo:par",
                "DENY_PERMISSION",
            ),
            (pessoa, "dispositivo:par-2", "DENY_RESOURCE"),
            (pessoa, "dispositivo:nenhum", "DENY_RESOURCE"),
            (pessoa, "par", "INVALID_ARGUMENT"),
            (agente, "dispositivo:par", "DENY_PERMISSION"),
            (sem_manifesto, "dispositivo:par", "DENY_PERMISSION"),
        ];
        let antes = crate::autorizacao::ultimo_registro();
        for (n, (q, device, codigo)) in casos.iter().enumerate() {
            let c = mandar(*q, device, 10 + n as u64, "x");
            if c != *codigo {
                crate::log_error!("teste", "{} {}: {} (esperava {})", n, device, c, codigo);
                return Err("a origem nao recusou um pedido a outro dispositivo que devia recusar");
            }
        }
        // A pessoa com `fabric.send` e sem `fabric.remote`: a primeira
        // permissão passa, a segunda não.
        let sem_remote = super::politica_trocada(&[
            (
                "fabric.offer fabric.send fabric.remote device.pair device.forget\nrecurso operador",
                "fabric.offer fabric.send device.pair device.forget\nrecurso operador",
            ),
            (
                "recurso operador fabric.remote dispositivo:par dispositivo:par-2\n",
                "",
            ),
        ])?;
        let c = super::com_a_politica(sem_remote, || {
            Ok(mandar(pessoa, "dispositivo:par", 16, "x"))
        })?;
        if c != "DENY_PERMISSION" {
            crate::log_error!("teste", "sem fabric.remote: {}", c);
            return Err("a pessoa sem fabric.remote falou com outro dispositivo");
        }
        if crate::enlace::pedidos() != 0 {
            return Err("um pedido recusado entrou na fila do enlace");
        }
        if !registros_depois(antes, |e| {
            e.metodo == "fabric.send" && e.codigo == Codigo::Allow
        })
        .is_empty()
        {
            return Err("a origem deixou na decisao um pedido que so o commit recusou");
        }
        // O replay do nonce do processo: o primeiro entra, o mesmo nonce com
        // outro corpo e um velho param aqui.
        if mandar(pessoa, "dispositivo:par", 20, "um") != "SUSPENSO"
            || mandar(pessoa, "dispositivo:par", 20, "dois") != "DENY_REPLAY"
            || mandar(pessoa, "dispositivo:par", 19, "tres") != "DENY_REPLAY"
            || crate::enlace::pedidos() != 1
        {
            return Err("o replay do nonce do processo nao parou na origem");
        }
        // O dispositivo suspenso: nada daqui vai a ele, e o que esperava falha.
        let sistema = crate::autorizacao::Chamador::Processo {
            fio: 7_897_202,
            autoridade: Autoridade::Sistema,
            programa: crate::autorizacao::Programa::Kernel,
        };
        super::fs_pedir(sistema, "device.suspend", r#"{"device":"dispositivo:par"}"#);
        let suspenso = crate::autorizacao::ultimo_registro();
        if mandar(pessoa, "dispositivo:par", 21, "quatro") != "DENY_CREDENTIAL"
            || mandar(pessoa, "dispositivo:par", 20, "um") != "DENY_CREDENTIAL"
        {
            return Err("um pedido ao dispositivo suspenso passou na origem");
        }
        if !registros_depois(suspenso, |e| {
            e.metodo == "fabric.send" && e.codigo == Codigo::Allow
        })
        .is_empty()
        {
            return Err("a origem deixou na decisao um pedido ao dispositivo suspenso");
        }
        Ok(())
    })
}

/// A revogação com um pedido a caminho: o pedido falha com o motivo, quem
/// esperava acorda, e o pedido executado de novo é recusado pelo gate — o
/// dispositivo não existe mais para quem pede. O serviço não leva o que
/// saiu do caminho.
pub(super) fn enlace_a_origem_e_a_revogacao() -> Resultado {
    com_o_enlace(|| {
        let (sessao, bia) = pessoa_com_sessao("bia", "operador")?;
        let par = sigilo::publica_de(&PAR_DA_ORIGEM);
        admin(
            "device.register",
            &registro_de_dispositivo(
                &par,
                "par",
                bia,
                "dispositivo",
                Some("tcp:10.0.2.100:7071"),
                Some(RELACAO),
            ),
            None,
        )?;
        let quem = crate::autorizacao::Chamador::Pessoa(sessao);
        let linha = super::pedido_rpc(
            "fabric.discover",
            &alloc::format!(
                r#"{{"device":"dispositivo:par","intent":"{}"}}"#,
                super::INTENCAO_DA_MALHA
            ),
        );
        let espera = crate::nativo::responder_suspensivel_de_teste(quem, &linha)
            .err()
            .ok_or("o pedido a outro dispositivo nao suspendeu")?;
        let t = crate::enlace::tomar().ok_or("o pedido nao entrou na fila")?;
        admin("device.revoke", r#"{"name":"par"}"#, None)?;
        if espera.conferir(None) != Some(crate::rede::espera::Desfecho::Chegou) {
            return Err("quem esperava o dispositivo revogado nao acordou");
        }
        // O serviço, com o pedido na mão, não chega ao par.
        let mut via = ParQueResponde::novo(PAR_DA_ORIGEM, Some("{}"));
        crate::enlace::levar_pela_via_de_teste(&t, &mut via);
        if !via.viu_mensagem.is_empty() {
            return Err("o servico levou ao par um pedido que a revogacao tirou do caminho");
        }
        drop(espera);
        let r = crate::nativo::responder_de_teste(quem, &linha);
        if codigo_do_envelope(&r) != "DENY_RESOURCE" {
            crate::log_error!("teste", "{}", r);
            return Err("o pedido ao dispositivo revogado, executado de novo, nao foi recusado");
        }
        Ok(())
    })
}

/// O par de teste da origem que, ao receber o aperto, faz `no_aperto`
/// antes de responder: o que muda no meio da conversa do serviço.
struct ParQueMexeNoAperto<F: FnOnce()> {
    par: ParQueResponde,
    no_aperto: Option<F>,
}

impl<F: FnOnce()> crate::enlace::Via for ParQueMexeNoAperto<F> {
    fn mandar(&mut self, bytes: &[u8]) -> Result<(), (Codigo, &'static str)> {
        if let Some(f) = self.no_aperto.take() {
            f();
        }
        self.par.mandar(bytes)
    }

    fn receber(&mut self, prazo_ms: u64) -> Result<Vec<u8>, (Codigo, &'static str)> {
        self.par.receber(prazo_ms)
    }
}

/// A revogação no meio do aperto do serviço: o pedido sai do caminho
/// depois de o serviço o tomar e de o aperto partir, e antes de a linha
/// partir — o par vê o aperto e nada mais, e quem esperava acorda.
pub(super) fn enlace_a_origem_e_a_revogacao_no_aperto() -> Resultado {
    com_o_enlace(|| {
        let (sessao, bia) = pessoa_com_sessao("bia", "operador")?;
        let par = sigilo::publica_de(&PAR_DA_ORIGEM);
        admin(
            "device.register",
            &registro_de_dispositivo(
                &par,
                "par",
                bia,
                "dispositivo",
                Some("tcp:10.0.2.100:7071"),
                Some(RELACAO),
            ),
            None,
        )?;
        let quem = crate::autorizacao::Chamador::Pessoa(sessao);
        let linha = super::pedido_rpc(
            "fabric.discover",
            &alloc::format!(
                r#"{{"device":"dispositivo:par","intent":"{}"}}"#,
                super::INTENCAO_DA_MALHA
            ),
        );
        let espera = crate::nativo::responder_suspensivel_de_teste(quem, &linha)
            .err()
            .ok_or("o pedido a outro dispositivo nao suspendeu")?;
        let t = crate::enlace::tomar().ok_or("o pedido nao entrou na fila")?;
        let revogou = core::cell::Cell::new(false);
        let mut via = ParQueMexeNoAperto {
            par: ParQueResponde::novo(PAR_DA_ORIGEM, Some("{}")),
            no_aperto: Some(|| {
                revogou.set(admin("device.revoke", r#"{"name":"par"}"#, None).is_ok());
            }),
        };
        crate::enlace::levar_pela_via_de_teste(&t, &mut via);
        if !revogou.get() || via.par.viu_chave != crate::identidade::publica_do_duke() {
            return Err("a revogacao nao aconteceu no meio do aperto do servico");
        }
        if !via.par.viu_mensagem.is_empty() {
            crate::log_error!("teste", "{}", via.par.viu_mensagem);
            return Err(
                "o servico levou ao par um pedido que a revogacao no aperto tirou do caminho",
            );
        }
        if espera.conferir(None) != Some(crate::rede::espera::Desfecho::Chegou) {
            return Err("quem esperava o dispositivo revogado no aperto nao acordou");
        }
        Ok(())
    })
}

/// A origem reconfirma no commit: o pedido a outro dispositivo foi
/// decidido com tudo de pé, e entre a decisão e a entrada na fila do
/// enlace — com a ordem das gravações na mão — a política perde
/// `fabric.remote`, ou o dispositivo é revogado. A reconfirmação recusa:
/// nada entra na fila, e quem pediu tem a recusa, e não a espera.
pub(super) fn enlace_a_origem_reconfirma_no_commit() -> Resultado {
    fn tirar_o_remote_no_meio() {
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        if let Ok(p) = super::politica_trocada(&[
            (
                "fabric.offer fabric.send fabric.remote device.pair device.forget\nrecurso operador",
                "fabric.offer fabric.send device.pair device.forget\nrecurso operador",
            ),
            (
                "recurso operador fabric.remote dispositivo:par dispositivo:par-2\n",
                "",
            ),
        ]) {
            crate::autorizacao::trocar_politica(p);
        }
    }
    fn revogar_no_meio() {
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        let par = sigilo::publica_de(&PAR_DA_ORIGEM);
        let _ = crate::dispositivos::revogar(&par);
        crate::enlace::dispositivo_revogado(&par);
    }
    com_o_enlace(|| {
        let (sessao, bia) = pessoa_com_sessao("bia", "operador")?;
        admin(
            "device.register",
            &registro_de_dispositivo(
                &sigilo::publica_de(&PAR_DA_ORIGEM),
                "par",
                bia,
                "dispositivo",
                Some("tcp:10.0.2.100:7071"),
                Some(RELACAO),
            ),
            None,
        )?;
        let quem = crate::autorizacao::Chamador::Pessoa(sessao);
        let politica = crate::autorizacao::com_politica(|p| p.clone());
        // A revogação por último: ela é para sempre.
        let meios: [(fn(), &str, &str); 2] = [
            (tirar_o_remote_no_meio, "DENY_PERMISSION", ""),
            (
                revogar_no_meio,
                "DENY_RESOURCE",
                "nao existe mais para quem pede",
            ),
        ];
        let r = (|| -> Resultado {
            for (n, (meio, codigo, motivo)) in meios.iter().enumerate() {
                let antes = crate::autorizacao::ultimo_registro();
                crate::autorizacao::antes_da_reconfirmacao_de_teste(Some(*meio));
                let linha = super::pedido_rpc(
                    "fabric.send",
                    &alloc::format!(
                        r#"{{"device":"dispositivo:par","endpoint":"e:1","intent":"{}","body":"no-meio","nonce":{}}}"#,
                        super::INTENCAO_DA_MALHA,
                        n + 1
                    ),
                );
                let c = match crate::nativo::responder_suspensivel_de_teste(quem, &linha) {
                    Ok(r) => codigo_do_envelope(&r),
                    Err(_) => String::from("SUSPENSO"),
                };
                crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
                crate::autorizacao::restaurar_politica(politica.clone());
                let decidida = !registros_depois(antes, |e| {
                    e.metodo == "fabric.send" && e.codigo == Codigo::Allow
                })
                .is_empty();
                let recusada = !registros_depois(antes, |e| {
                    e.metodo == "fabric.send"
                        && e.codigo.nome() == *codigo
                        && e.detalhe.contains(motivo)
                })
                .is_empty();
                if c != *codigo || !decidida || !recusada || crate::enlace::pedidos() != 0 {
                    crate::log_error!(
                        "teste",
                        "{}: {} {} {} {}",
                        n,
                        c,
                        decidida,
                        recusada,
                        crate::enlace::pedidos()
                    );
                    return Err("a origem nao reconfirmou no commit o pedido a outro dispositivo");
                }
            }
            Ok(())
        })();
        crate::autorizacao::antes_da_reconfirmacao_de_teste(None);
        r
    })
}

/// Três enlaces do mesmo dispositivo, cada um de um fio e de uma época,
/// mandando ao mesmo tempo, e a revogação no meio: nada do que foi aceito
/// passa da metade, nada vive depois dela — tudo anulado —, e a malha, a
/// tabela do enlace e o registro continuam coerentes.
pub(super) fn enlace_mandar_e_revogar_ao_mesmo_tempo() -> Resultado {
    use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst};
    const FIOS: u64 = 3;
    const VOLTAS: u64 = 8;
    static PRONTOS: AtomicUsize = AtomicUsize::new(0);
    static ACEITAS_DEPOIS: AtomicUsize = AtomicUsize::new(0);
    static METADE: AtomicU64 = AtomicU64::new(0);
    static REVOGADA: AtomicBool = AtomicBool::new(false);
    static ENDPOINT: crate::trava::Mutex<String> = crate::trava::Mutex::new(String::new());
    extern "C" fn mandar(qual: u64) -> ! {
        let endpoint = crate::arch::sem_interrupcoes(|| ENDPOINT.lock().clone());
        let mut par = Par::novo(VAGA + qual as u8, 2_000_000 + qual);
        let apertou = matches!(
            par.apertar(&privada_de_dispositivo(1), [0x40 + qual as u8; 8]),
            Ok(Ok(()))
        );
        for volta in 1..=VOLTAS {
            if !apertou {
                break;
            }
            if volta == VOLTAS / 2 + 1 {
                while !REVOGADA.load(SeqCst) {
                    crate::fios::ceder();
                }
            }
            let r = par.pedir(
                RELACAO,
                "fabric.send",
                &alloc::format!(
                    r#"{{"endpoint":"{endpoint}","intent":"{}","body":"junto","nonce":{volta}}}"#,
                    super::INTENCAO_DA_MALHA
                ),
            );
            let aceita = matches!(&r, Ok(Ok(e)) if super::fs_ok(e));
            if volta > VOLTAS / 2 && aceita {
                ACEITAS_DEPOIS.fetch_add(1, SeqCst);
            }
            if volta <= VOLTAS / 2 {
                METADE.fetch_add(1, SeqCst);
            }
            crate::fios::ceder();
        }
        PRONTOS.fetch_add(1, SeqCst);
        crate::fios::terminar()
    }
    com_o_enlace(|| {
        let (sessao, bia) = pessoa_com_sessao("bia", "operador")?;
        relacionar(bia, "par", 1, "dispositivo", RELACAO)?;
        let endpoint = endpoint_que_nao_le(Autoridade::Pessoa { sessao })?;
        let r = (|| -> Resultado {
            crate::arch::sem_interrupcoes(|| *ENDPOINT.lock() = endpoint.clone());
            PRONTOS.store(0, SeqCst);
            ACEITAS_DEPOIS.store(0, SeqCst);
            METADE.store(0, SeqCst);
            REVOGADA.store(false, SeqCst);
            for qual in 0..FIOS {
                crate::fios::criar("teste-enlace", mandar, qual)?;
            }
            // Com a primeira metade de todos fora, a revogação — com envios
            // em curso nos três enlaces.
            super::esperar_ate(
                || METADE.load(SeqCst) >= FIOS * VOLTAS / 2,
                6 * super::TETO_DA_MALHA,
            )
            .map_err(|_| "os enlaces nao mandaram a primeira metade")?;
            admin("device.revoke", r#"{"name":"par"}"#, None)?;
            REVOGADA.store(true, SeqCst);
            super::esperar_ate(
                || PRONTOS.load(SeqCst) == FIOS as usize,
                6 * super::TETO_DA_MALHA,
            )
            .map_err(|_| "os fios do enlace nao terminaram")?;
            if ACEITAS_DEPOIS.load(SeqCst) != 0 {
                return Err("uma entrega remota foi aceita depois da revogacao");
            }
            if crate::malha::contagem().1 != 0 {
                return Err("uma entrega do dispositivo revogado ficou viva");
            }
            if !crate::malha::coerente() || !crate::enlace::coerente() {
                return Err("a malha ou o enlace ficou incoerente com a revogacao no meio");
            }
            Ok(())
        })();
        REVOGADA.store(true, SeqCst);
        super::encerrar_na_malha(super::CANAL_DO_IMPOSTOR, super::SAIDA_DO_IMPOSTOR)?;
        r
    })
}
