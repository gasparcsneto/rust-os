//! A bancada do enlace entre dispositivos: `cargo xtask enlace`.
//!
//! Duas máquinas de pé ao mesmo tempo — cada uma com o disco, o TPM e a
//! chave do Duke dela —, ligadas pela rede do emulador e por nada mais: a
//! origem conecta a `10.0.2.100:7071`, o `guestfwd` dela roda a ponte da
//! bancada (`xtask/bancada/ponte.py`) até uma porta do hospedeiro, e o
//! `hostfwd` do destino leva essa porta à 7071 dele. O resto — o registro de
//! dispositivos, a pessoa, o programa, o enlace, o gate de cada lado — é o
//! que um Duke faz com o outro, sem atalho.
//!
//! Em cada par, numa ordem só, porque cada passo parte do anterior:
//!
//! 1. o administrador registra a relação nos dois, com prova: a mesma
//!    relação, a chave do Duke do outro, a pessoa de desenvolvimento de cada
//!    um, o papel `dispositivo`; o endereço, só na origem;
//! 2. a pessoa entra no Terminal das duas pelo teclado — o `sendkey` do
//!    monitor —, lança o `correio` no destino e o `carteiro` na origem; o
//!    carteiro procura, manda, reenvia com o mesmo nonce e pergunta o
//!    estado, e o correio recebe e confirma. Confere-se o que cada um disse
//!    e a auditoria dos dois lados: a decisão de cada pedido daqui, o
//!    serviço do enlace conectando pelo gate, o aperto lá, as decisões de lá
//!    com a relação e o programa que a origem atesta;
//! 3. a suspensão no destino: o aperto recusado lá; e a volta;
//! 4. a suspensão na origem: o pedido recusado aqui, sem rede; e a volta;
//! 5. o corte de energia do destino: a relação volta do journal, e o enlace
//!    funciona sem registro novo;
//! 6. a revogação no destino: o enlace recusado, o registro de novo
//!    recusado pela lápide — também depois de outro corte —, e a porta do
//!    enlace fechada, sem relação;
//! 7. a revogação na origem: o pedido recusado aqui, sem rede.
//!
//! Os pares: `x86_64>aarch64`, `aarch64>x86_64`, `x86_64>x86_64` e
//! `aarch64>aarch64` — todos, ou os que `DUKE_PARES` escolhe, separados por
//! `|`. Duas máquinas da mesma arquitetura não dividem nada: cada uma tem a
//! raiz de estado dela — ver [`super::na_raiz`].

use std::collections::BTreeMap;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use super::persistencia::{self as p, Ligada};
use super::{Ambiente, Arquitetura, Artefato, chaves};

/// Como cada Duke chama o outro no registro de dispositivos.
pub(crate) const NOME: &str = "par";

/// O dispositivo, como a pessoa e o programa o pedem — o `PAR` do
/// carteiro.
pub(crate) const DISPOSITIVO: &str = "dispositivo:par";

/// O papel da relação nos dois: o da política padrão.
pub(crate) const PAPEL: &str = "dispositivo";

/// O endereço do destino, como a origem o registra: a ponte da bancada. É o
/// que a linha `recurso enlace net.connect` da política padrão enumera.
pub(crate) const ENDERECO: &str = "tcp:10.0.2.100:7071";

/// A porta do enlace no hóspede: `rede::canal::PORTA_DO_ENLACE`.
pub(crate) const PORTA_DO_ENLACE: u16 = 7071;

/// A intenção que o correio oferece e o carteiro procura.
const INTENCAO: &str = "imagem.compartilhar";

/// O código de saída do carteiro depois da confirmação de lá, e o da
/// recusa (`programas/src/bin/carteiro.rs`).
const CARTEIRO_CONFIRMOU: i64 = 44;
pub(crate) const CARTEIRO_RECUSADO: i64 = 45;

/// Quanto esperar um programa lançado dizer o que se espera dele: cada
/// pedido do carteiro é um enlace novo, com o aperto, entre duas máquinas
/// emuladas.
const ESPERA_PELO_PROGRAMA: Duration = Duration::from_secs(180);

/// O respiro entre dois lançamentos do carteiro: o Duke de lá conta os
/// apertos de cada vaga numa janela de dez segundos (`apertos 10 10000` na
/// política padrão), e um lançamento faz até seis.
const JANELA_DOS_APERTOS: Duration = Duration::from_secs(11);

/// Quanto esperar o gate decidir o `user.run` de uma linha digitada, e
/// quantas vezes digitá-la — ver [`DePe::lancar`].
const ESPERA_PELO_LANCAMENTO: Duration = Duration::from_secs(20);
const VEZES_DE_DIGITAR: usize = 3;

/// Os pares, na ordem em que rodam: origem e destino.
const PARES: [(Arquitetura, Arquitetura); 4] = [
    (Arquitetura::X86_64, Arquitetura::Aarch64),
    (Arquitetura::Aarch64, Arquitetura::X86_64),
    (Arquitetura::X86_64, Arquitetura::X86_64),
    (Arquitetura::Aarch64, Arquitetura::Aarch64),
];

// ---------------------------------------------------------------------------
// As máquinas
// ---------------------------------------------------------------------------

/// Uma das duas máquinas, ainda desligada.
pub(crate) struct Maquina {
    /// `origem` ou `destino`: como a bancada a chama, e o nome da raiz dela.
    papel: &'static str,
    arch: Arquitetura,
    /// A raiz de estado dela: sockets, TPM, variáveis da UEFI.
    raiz: PathBuf,
    disco: PathBuf,
    artefato: Artefato,
    /// A chave privada do Duke dela, que vai na imagem.
    privada: [u8; 32],
    /// As opções da rede da ponta do enlace dela.
    encaminhamento: String,
}

impl Maquina {
    /// Compila o kernel de `arch` e monta o disco dela, com a chave do Duke
    /// `privada` no lugar da da bancada. Uma raiz de estado nova, e com ela
    /// um TPM novo.
    pub(crate) fn nova(
        papel: &'static str,
        arch: Arquitetura,
        release: bool,
        privada: [u8; 32],
        encaminhamento: String,
    ) -> Result<Maquina, String> {
        let base = super::raiz_do_projeto().join("target").join("enlace");
        let raiz = base.join(papel);
        let _ = std::fs::remove_dir_all(&raiz);
        std::fs::create_dir_all(&raiz).map_err(|e| format!("{}: {e}", raiz.display()))?;
        // O disco logo depois da compilação: no x86, a ESP e o slot A vêm
        // do disco de testes, onde a compilação de cada arquitetura põe o
        // iniciador e o kernel dela.
        let compilado = super::build(arch, release, false)?;
        let disco = base.join(format!("{papel}.img"));
        let chave = (
            "etc/duke/privado/chave".to_string(),
            format!("{}\n", sigilo::hex(&privada)).into_bytes(),
        );
        let artefato = super::disco_de_testes_com(&compilado, &disco, vec![chave])?;
        Ok(Maquina {
            papel,
            arch,
            raiz,
            disco,
            artefato,
            privada,
            encaminhamento,
        })
    }

    pub(crate) fn publica(&self) -> [u8; 32] {
        sigilo::publica_de(&self.privada)
    }

    /// Liga a máquina, na raiz dela, e abre o teclado.
    pub(crate) fn ligar(&self) -> Result<DePe, String> {
        super::na_raiz(&self.raiz, || {
            let m = Ligada::subir_com(
                self.arch,
                &self.artefato,
                Ambiente::ligar(self.arch, None)?
                    .com_disco(self.disco.clone())
                    .com_encaminhamento(self.encaminhamento.clone()),
            )?;
            let teclado = super::senha::teclado(self.arch)?;
            Ok(DePe {
                papel: self.papel,
                arch: self.arch,
                m,
                teclado,
                visto: Visto::default(),
            })
        })
    }
}

/// O que uma máquina disse e gravou, juntado a cada leitura: o log é um
/// anel de 128, e o que importa de um passo pode sair dele antes do fim do
/// passo seguinte.
#[derive(Default)]
struct Visto {
    /// O número do registro de log mais recente lido.
    ultimo_log: u64,
    /// As linhas dos programas — o subsistema `usuario` —, pelo número: o
    /// tempo de máquina dela, em ms, e o texto.
    ditas: BTreeMap<u64, (u64, String)>,
    /// Os registros da auditoria, pelo número.
    gravados: BTreeMap<u64, Gravado>,
}

/// Um registro da auditoria, com o que a bancada confere dele.
#[derive(Clone, Debug)]
pub(crate) struct Gravado {
    pub(crate) titular: String,
    pub(crate) agente: String,
    pub(crate) chave: String,
    pub(crate) papel: String,
    pub(crate) metodo: String,
    pub(crate) recurso: String,
    pub(crate) codigo: String,
    pub(crate) detalhe: String,
}

/// Uma máquina de pé: o canal da serial, o teclado, e o que ela disse e
/// gravou até agora.
pub(crate) struct DePe {
    pub(crate) papel: &'static str,
    pub(crate) arch: Arquitetura,
    pub(crate) m: Ligada,
    teclado: UnixStream,
    visto: Visto,
}

/// O valor de um campo de um objeto plano, ou nada.
fn valor(campos: &super::ObjetoPlano, nome: &str) -> String {
    campos
        .iter()
        .find(|(n, _)| n == nome)
        .and_then(|(_, v)| v.clone())
        .unwrap_or_default()
}

impl DePe {
    /// Lê o log de agora e a auditoria desde a última leitura, e junta ao
    /// que já se viu.
    pub(crate) fn ler(&mut self) -> Result<(), String> {
        let r = self.m.pedir("log.tail", r#"{"count":128}"#)?;
        for campos in super::objetos_planos(super::apos(&r, r#""records":["#).unwrap_or(""))? {
            let Ok(seq) = valor(&campos, "seq").parse::<u64>() else {
                continue;
            };
            self.visto.ultimo_log = self.visto.ultimo_log.max(seq);
            if valor(&campos, "subsystem") == "usuario" {
                let hora = valor(&campos, "uptime_ms").parse().unwrap_or(0);
                self.visto
                    .ditas
                    .insert(seq, (hora, valor(&campos, "message")));
            }
        }
        // A auditoria, em ordem e sem buraco: os primeiros 128 depois do
        // último visto, até não vir mais nada.
        loop {
            let depois = self.visto.gravados.keys().next_back().copied();
            let params = match depois {
                Some(s) => format!(r#"{{"count":128,"after":{s}}}"#),
                None => r#"{"count":128}"#.to_string(),
            };
            let r = self.m.pedir("audit.tail", &params)?;
            let registros = super::objetos_planos(super::apos(&r, r#""records":["#).unwrap_or(""))?;
            let mut novos = 0;
            for campos in registros {
                let Ok(seq) = valor(&campos, "seq").parse::<u64>() else {
                    continue;
                };
                if depois.is_some_and(|d| seq <= d) {
                    continue;
                }
                novos += 1;
                self.visto.gravados.insert(
                    seq,
                    Gravado {
                        titular: valor(&campos, "holder"),
                        agente: valor(&campos, "agent"),
                        chave: valor(&campos, "key"),
                        papel: valor(&campos, "role"),
                        metodo: valor(&campos, "method"),
                        recurso: valor(&campos, "resource"),
                        codigo: valor(&campos, "code"),
                        detalhe: valor(&campos, "detail"),
                    },
                );
            }
            if novos < 128 {
                return Ok(());
            }
        }
    }

    /// Onde a máquina está agora: o último registro de log e o último da
    /// auditoria. O que vier depois é do passo seguinte.
    pub(crate) fn marca(&mut self) -> Result<Marca, String> {
        self.ler()?;
        Ok(Marca {
            log: self.visto.ultimo_log,
            auditoria: self.visto.gravados.keys().next_back().copied().unwrap_or(0),
        })
    }

    /// Digita no teclado da máquina, no Terminal que tem o foco.
    pub(crate) fn digitar(&mut self, texto: &str) -> Result<(), String> {
        super::digitar_pelo_monitor(&mut self.teclado, texto, self.papel)
    }

    /// Espera a primeira linha de programa depois de `desde` que comece com
    /// um dos `prefixos`: qual, e o resto dela.
    fn esperar_dito(
        &mut self,
        desde: u64,
        prefixos: &[&str],
        espera: Duration,
    ) -> Result<(usize, String), String> {
        let limite = Instant::now() + espera;
        loop {
            self.ler()?;
            for linha in self.visto.ditas.range(desde + 1..).map(|(_, (_, l))| l) {
                for (i, prefixo) in prefixos.iter().enumerate() {
                    if let Some(resto) = linha.strip_prefix(prefixo) {
                        return Ok((i, resto.to_string()));
                    }
                }
            }
            if Instant::now() >= limite {
                return Err(format!(
                    "{}: nenhuma linha {prefixos:?} em {} s",
                    self.papel,
                    espera.as_secs()
                ));
            }
            std::thread::sleep(Duration::from_millis(700));
        }
    }

    /// As linhas de programa depois de `desde` que começam com `prefixo`:
    /// o resto de cada uma, em ordem.
    fn ditas(&self, desde: u64, prefixo: &str) -> Vec<String> {
        self.ditas_com_hora(desde, prefixo)
            .into_iter()
            .map(|(_, l)| l)
            .collect()
    }

    /// Como [`DePe::ditas`], com o tempo de máquina de cada linha, em ms.
    fn ditas_com_hora(&self, desde: u64, prefixo: &str) -> Vec<(u64, String)> {
        self.visto
            .ditas
            .range(desde + 1..)
            .filter_map(|(_, (h, l))| l.strip_prefix(prefixo).map(|r| (*h, r.to_string())))
            .collect()
    }

    /// Os registros da auditoria depois de `desde`.
    pub(crate) fn gravados(&self, desde: u64) -> impl Iterator<Item = &Gravado> {
        self.visto.gravados.range(desde + 1..).map(|(_, g)| g)
    }

    /// Uma operação administrativa, provada pelo administrador da imagem:
    /// a resposta.
    pub(crate) fn administrar(&mut self, comando: &str, params: &str) -> Result<String, String> {
        let chaves = chaves::Chaves::garantir()?;
        p::administrar(&mut self.m, &chaves.administrador, comando, params)
    }

    /// Como [`DePe::administrar`], e a operação tem de ter sido executada.
    pub(crate) fn executar(&mut self, comando: &str, params: &str) -> Result<(), String> {
        let r = self.administrar(comando, params)?;
        if p::executou(&r) {
            Ok(())
        } else {
            Err(format!(
                "{}: `{comando}` nao foi executado\n  {r}",
                self.papel
            ))
        }
    }

    /// O registro de dispositivos, como `device.registry` o mostra.
    pub(crate) fn registro(&mut self) -> Result<String, String> {
        self.m.pedir("device.registry", "{}")
    }

    /// A pessoa de desenvolvimento entra no Terminal, pelo teclado.
    pub(crate) fn entrar(&mut self) -> Result<(), String> {
        let (_, _, senha) = chaves::Chaves::garantir()?.pessoa_dev();
        super::senha::terminal_atendendo(&mut self.m, &mut self.teclado)?;
        let codigo = super::senha::entrar(
            &mut self.m,
            &mut self.teclado,
            chaves::NOME_DA_PESSOA_DEV,
            &senha,
        )?;
        if codigo != "ALLOW" {
            return Err(format!("{}: a pessoa nao entrou ({codigo})", self.papel));
        }
        Ok(())
    }

    /// A pessoa lança `programa` pelo Terminal: `user.run`, digitado.
    ///
    /// E espera o gate decidir o `user.run` dele. O teclado do emulador perde
    /// tecla com a máquina ocupada — duas de pé no mesmo hospedeiro —, e a
    /// linha estragada o interpretador recusa sem chegar ao gate: sem a
    /// decisão gravada, digita de novo, depois de uma linha vazia que encerra
    /// o que tiver ficado pela metade. Só digita de novo quem não viu o
    /// `user.run` decidido: o programa não roda duas vezes.
    fn lancar(&mut self, programa: &str) -> Result<(), String> {
        let caminho = format!("/programas/{}/{programa}", self.arch.nome());
        for vez in 0..VEZES_DE_DIGITAR {
            let desde = self.marca()?.auditoria;
            if vez > 0 {
                println!(
                    "  [enlace]   {}: o user.run de {caminho} nao chegou ao gate; digitando de novo",
                    self.papel
                );
                self.digitar("\n")?;
            }
            self.digitar(&format!("user.run {{\"path\":\"{caminho}\"}}\n"))?;
            let limite = Instant::now() + ESPERA_PELO_LANCAMENTO;
            loop {
                self.ler()?;
                let decidido = self
                    .visto
                    .gravados
                    .range(desde + 1..)
                    .map(|(_, g)| g)
                    .find(|g| g.metodo == "user.run" && g.recurso == caminho);
                if let Some(g) = decidido {
                    if g.codigo != "ALLOW" {
                        return Err(format!(
                            "{}: user.run {caminho}: {} {}",
                            self.papel, g.codigo, g.detalhe
                        ));
                    }
                    return Ok(());
                }
                if Instant::now() >= limite {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        Err(format!(
            "{}: o user.run de {caminho} nao chegou ao gate em {VEZES_DE_DIGITAR} vezes",
            self.papel
        ))
    }

    /// O log das duas máquinas, para a falha: as últimas linhas de
    /// programa, e os últimos registros da auditoria.
    pub(crate) fn mostrar(&mut self) {
        let _ = self.ler();
        println!("  [enlace]   {} ({}):", self.papel, self.arch.nome());
        let ditas: Vec<&String> = self.visto.ditas.values().map(|(_, l)| l).collect();
        for l in &ditas[ditas.len().saturating_sub(20)..] {
            println!("  [{}] {l}", self.papel);
        }
        let gravados: Vec<&Gravado> = self.visto.gravados.values().collect();
        for g in &gravados[gravados.len().saturating_sub(30)..] {
            println!(
                "  [{} auditoria] {} {} {} {} {} | {}",
                self.papel, g.titular, g.agente, g.metodo, g.recurso, g.codigo, g.detalhe
            );
        }
    }
}

/// Onde uma máquina estava: o último registro de log e o último da
/// auditoria.
#[derive(Clone, Copy)]
pub(crate) struct Marca {
    pub(crate) log: u64,
    pub(crate) auditoria: u64,
}

// ---------------------------------------------------------------------------
// O carteiro
// ---------------------------------------------------------------------------

/// Um lançamento do carteiro: o que ele disse, sem o prefixo, com o tempo
/// de máquina de cada linha, e o código de saída.
pub(crate) struct Corrida {
    linhas: Vec<String>,
    horas: Vec<(u64, String)>,
    /// O tempo de máquina em que o processo entrou no anel sem privilégio.
    comeco: Option<u64>,
    codigo: i64,
}

impl Corrida {
    /// O resto da primeira linha que começa com `prefixo`.
    pub(crate) fn dito(&self, prefixo: &str) -> Option<&str> {
        self.linhas.iter().find_map(|l| l.strip_prefix(prefixo))
    }

    pub(crate) fn texto(&self) -> String {
        self.linhas.join(" | ")
    }

    /// O tempo de máquina da primeira linha que começa com `prefixo`.
    fn hora(&self, prefixo: &str) -> Option<u64> {
        self.horas
            .iter()
            .find_map(|(h, l)| l.starts_with(prefixo).then_some(*h))
    }

    /// Quanto cada pedido ao par levou, em ms, pelo log da origem: a procura
    /// (desde a entrada do processo), a entrega, o reenvio e a primeira
    /// pergunta do estado — cada um com o gate daqui, o serviço, a conexão
    /// pela ponte, o aperto, o gate de lá e a malha de lá.
    fn tempos(&self) -> Option<[u64; 4]> {
        let marcos = [
            self.comeco?,
            self.hora("achei ")?,
            self.hora("mandei ")?,
            self.hora("reenvio ")?,
            self.hora("estado ")?,
        ];
        Some([
            marcos[1].checked_sub(marcos[0])?,
            marcos[2].checked_sub(self.hora("mandando ")?)?,
            marcos[3].checked_sub(marcos[2])?,
            marcos[4].checked_sub(marcos[3])?,
        ])
    }
}

/// O par de pé: as duas máquinas, a relação e o resumo do carteiro.
pub(crate) struct Par {
    pub(crate) origem: DePe,
    pub(crate) destino: DePe,
    /// A chave pública de cada Duke.
    pub(crate) da_origem: [u8; 32],
    pub(crate) da_destino: [u8; 32],
    pub(crate) relacao: String,
    pub(crate) pessoa: String,
    /// O começo do resumo da imagem do carteiro, como o destino grava o
    /// programa atestado.
    pub(crate) atestado: String,
    /// O fim do último lançamento do carteiro.
    pub(crate) ultimo: Option<Instant>,
    /// Quanto levou cada pedido de cada entrega — ver [`Corrida::tempos`].
    pub(crate) medidas: Vec<[u64; 4]>,
}

impl Par {
    /// A pessoa lança o carteiro na origem, e ele diz até o fim. Antes, o
    /// respiro da janela dos apertos.
    pub(crate) fn carteiro(&mut self) -> Result<Corrida, String> {
        if let Some(ultimo) = self.ultimo {
            let pronto = ultimo + JANELA_DOS_APERTOS;
            let agora = Instant::now();
            if pronto > agora {
                std::thread::sleep(pronto - agora);
            }
        }
        let desde = self.origem.marca()?.log;
        self.origem.lancar("carteiro")?;
        let fim = self
            .origem
            .esperar_dito(desde, &["carteiro: fim "], ESPERA_PELO_PROGRAMA);
        self.ultimo = Some(Instant::now());
        let (_, codigo) = fim?;
        let codigo = codigo
            .trim()
            .parse()
            .map_err(|_| format!("o carteiro saiu com `{codigo}`"))?;
        let comeco = self
            .origem
            .ditas_com_hora(desde, "entrando em userspace")
            .last()
            .map(|(h, _)| *h);
        Ok(Corrida {
            linhas: self.origem.ditas(desde, "carteiro: "),
            horas: self.origem.ditas_com_hora(desde, "carteiro: "),
            comeco,
            codigo,
        })
    }

    /// O carteiro manda, de ponta a ponta: a entrega chega ao correio do
    /// destino, com o dispositivo, o reenvio devolve o mesmo id, e a
    /// resposta do correio volta. E a auditoria dos dois lados conta o
    /// caminho: aqui, o pedido decidido com `fabric.remote` e o serviço do
    /// enlace conectando pelo gate; lá, o aperto do dispositivo e as
    /// decisões pela relação, com o programa atestado.
    pub(crate) fn entrega(&mut self, endpoint: &str) -> Result<String, String> {
        let antes_o = self.origem.marca()?;
        let antes_d = self.destino.marca()?;
        let c = self.carteiro()?;
        if c.codigo != CARTEIRO_CONFIRMOU {
            return Err(format!(
                "o carteiro nao chegou a confirmacao ({}): {}",
                c.codigo,
                c.texto()
            ));
        }
        let candidato = c.dito("candidato correio ").unwrap_or("");
        if !candidato.ends_with(&format!(" {endpoint}")) {
            return Err(format!(
                "o carteiro nao achou o correio de la ({endpoint}): {}",
                c.texto()
            ));
        }
        let corpo = c
            .dito("mandando ")
            .ok_or_else(|| format!("o carteiro nao disse o corpo: {}", c.texto()))?
            .to_string();
        if c.dito("reenvio igual").is_none() {
            return Err(format!(
                "o reenvio com o mesmo nonce nao devolveu o mesmo id: {}",
                c.texto()
            ));
        }
        let estado = c.dito("estado ").unwrap_or("");
        if estado != format!("acked guardada:{corpo}") {
            return Err(format!(
                "a resposta do correio nao voltou ao carteiro: {}",
                c.texto()
            ));
        }
        // O destino: o correio recebeu do dispositivo, uma vez.
        self.destino.ler()?;
        let recebidas = self.destino.ditas(antes_d.log, "correio: recebi ");
        let esperada = format!("{corpo} de {DISPOSITIVO}");
        if recebidas.iter().filter(|r| **r == esperada).count() != 1 {
            return Err(format!(
                "o correio de la nao recebeu `{esperada}` uma vez: {recebidas:?}"
            ));
        }
        // A auditoria do destino: o aperto do dispositivo, pela chave dele,
        // e cada pedido decidido pela relação, com o programa atestado.
        let da_origem = sigilo::hex(&self.da_origem);
        let aperto = self.destino.gravados(antes_d.auditoria).any(|g| {
            g.metodo == "link.open"
                && g.codigo == "ALLOW"
                && g.titular == "device"
                && g.agente == NOME
                && g.chave == da_origem
                && g.detalhe.starts_with("aperto completo")
        });
        if !aperto {
            return Err("o destino nao gravou o aperto do dispositivo".into());
        }
        let pela = format!("pela relacao {}", &self.relacao[..8]);
        let atestado = format!("atestado {}", self.atestado);
        for metodo in ["fabric.discover", "fabric.send", "fabric.status"] {
            let decidido = self.destino.gravados(antes_d.auditoria).any(|g| {
                g.metodo == metodo
                    && g.codigo == "ALLOW"
                    && g.titular == "device"
                    && g.agente == NOME
                    && g.papel == PAPEL
                    && g.chave == da_origem
                    && g.detalhe.starts_with(&pela)
                    && g.detalhe.contains(&atestado)
            });
            if !decidido {
                return Err(format!(
                    "o destino nao gravou `{metodo}` do dispositivo pela relacao, com o programa atestado ({atestado})"
                ));
            }
        }
        // E a origem: o pedido decidido com as duas permissões, o serviço
        // do enlace conectando ao par pelo gate, e a resposta lida.
        self.origem.ler()?;
        let decidido = self.origem.gravados(antes_o.auditoria).any(|g| {
            g.metodo == "fabric.send"
                && g.codigo == "ALLOW"
                && g.recurso == format!("intencao:{INTENCAO} ; {DISPOSITIVO}")
        });
        let conectou = self.origem.gravados(antes_o.auditoria).any(|g| {
            g.metodo == "net.connect"
                && g.codigo == "ALLOW"
                && g.titular == "service"
                && g.recurso == ENDERECO
        });
        let respondido = self
            .origem
            .gravados(antes_o.auditoria)
            .any(|g| g.metodo == "fabric.send" && g.detalhe.contains("respondido pelo par"));
        if !(decidido && conectou && respondido) {
            return Err(format!(
                "a origem nao gravou o caminho inteiro: decidido {decidido}, conectou {conectou}, respondido {respondido}"
            ));
        }
        if let Some(t) = c.tempos() {
            self.medidas.push(t);
        }
        Ok(format!(
            "{corpo} chegou ao correio de la e voltou `guardada`; o reenvio deu o mesmo id"
        ))
    }

    /// O carteiro é recusado no primeiro pedido — na procura —, com `codigo`
    /// e um motivo que começa com `motivo`: o que o gate daqui diz a quem
    /// pede, ou o que o enlace diz do par.
    fn recusado(&mut self, codigo: &str, motivo: &str) -> Result<Corrida, String> {
        let c = self.carteiro()?;
        let recusa = c.dito("procurar ").unwrap_or("");
        if c.codigo != CARTEIRO_RECUSADO || !recusa.starts_with(&format!("{codigo} {motivo}")) {
            return Err(format!(
                "o carteiro nao foi recusado com {codigo} ({motivo}): {}",
                c.texto()
            ));
        }
        Ok(c)
    }

    /// Nada do último lançamento chegou à rede: a origem não conectou, e o
    /// destino não viu aperto nenhum.
    fn sem_rede(&mut self, antes_o: Marca, antes_d: Marca) -> Result<(), String> {
        self.origem.ler()?;
        self.destino.ler()?;
        // O serviço do enlace conectando ao par — e não o de hora, que
        // conecta às fontes dele o tempo todo.
        if self
            .origem
            .gravados(antes_o.auditoria)
            .any(|g| g.metodo == "net.connect" && g.recurso == ENDERECO)
        {
            return Err("o servico do enlace conectou, e o pedido tinha sido recusado aqui".into());
        }
        if self
            .destino
            .gravados(antes_d.auditoria)
            .any(|g| g.metodo == "link.open")
        {
            return Err("o destino viu um aperto, e o pedido tinha sido recusado na origem".into());
        }
        Ok(())
    }

    /// O destino recusou o aperto da chave da origem, com `codigo` e um
    /// detalhe que começa com `motivo`.
    fn aperto_recusado(
        &mut self,
        antes_d: Marca,
        codigo: &str,
        motivo: &str,
    ) -> Result<(), String> {
        self.destino.ler()?;
        let da_origem = sigilo::hex(&self.da_origem);
        let recusado = self.destino.gravados(antes_d.auditoria).any(|g| {
            g.metodo == "link.open"
                && g.codigo == codigo
                && g.titular == "anonymous"
                && g.chave == da_origem
                && g.detalhe.starts_with(motivo)
        });
        if !recusado {
            return Err(format!(
                "o destino nao gravou o aperto recusado ({codigo}, {motivo})"
            ));
        }
        if self
            .destino
            .gravados(antes_d.auditoria)
            .any(|g| g.titular == "device" && g.metodo.starts_with("fabric."))
        {
            return Err("um pedido do dispositivo recusado chegou ao gate do destino".into());
        }
        Ok(())
    }

    /// A recusa do último lançamento no gate da origem: a decisão do
    /// primeiro pedido — a procura —, com `codigo` e o `detalhe`.
    fn recusado_aqui(&mut self, antes_o: Marca, codigo: &str, detalhe: &str) -> Result<(), String> {
        self.origem.ler()?;
        let recusado = self.origem.gravados(antes_o.auditoria).any(|g| {
            g.metodo == "fabric.discover"
                && g.codigo == codigo
                && g.recurso.ends_with(DISPOSITIVO)
                && g.detalhe.contains(detalhe)
        });
        if recusado {
            Ok(())
        } else {
            Err(format!(
                "a origem nao gravou a procura recusada ({codigo}, {detalhe})"
            ))
        }
    }

    /// Se o destino escuta a porta do enlace — com uma relação, e só com
    /// ela —, e o registro dele diz a relação quando escuta.
    pub(crate) fn destino_escuta(&mut self, deve: bool) -> Result<(), String> {
        let registro = self.destino.registro()?;
        let escuta = registro.contains(r#""listening":true"#);
        let relacionado =
            registro.contains(&self.relacao) && registro.contains(&sigilo::hex(&self.da_origem));
        if escuta != deve || relacionado != deve {
            return Err(format!(
                "o destino {} escutar o enlace, com a relacao no registro\n  {registro}",
                if deve { "devia" } else { "nao devia" }
            ));
        }
        Ok(())
    }

    /// O registro da chave da origem no destino, de novo: recusado pela
    /// lápide, e o registro sem ela.
    fn registro_com_lapide(&mut self, pessoa: &str, relacao: &str) -> Result<(), String> {
        let params = format!(
            r#"{{"key":"{}","name":"{NOME}","person":"{pessoa}","role":"{PAPEL}","relation":"{relacao}"}}"#,
            sigilo::hex(&self.da_origem)
        );
        let r = self.destino.administrar("device.register", &params)?;
        if p::executou(&r) || !r.contains("a lapide nao se desfaz") {
            return Err(format!(
                "o destino aceitou de novo a chave revogada, ou recusou por outro motivo\n  {r}"
            ));
        }
        Ok(())
    }

    /// As medidas das entregas: a mediana, o menor e o maior de cada pedido.
    fn resumo_das_medidas(&self) -> String {
        let nomes = ["procurar", "mandar", "reenviar", "estado"];
        let partes: Vec<String> = (0..4)
            .map(|i| {
                let mut v: Vec<u64> = self.medidas.iter().map(|m| m[i]).collect();
                v.sort_unstable();
                match (v.first(), v.get(v.len() / 2), v.last()) {
                    (Some(menor), Some(meio), Some(maior)) => {
                        format!("{} {meio} ms ({menor}-{maior})", nomes[i])
                    }
                    _ => format!("{} sem medida", nomes[i]),
                }
            })
            .collect();
        format!(
            "{} entregas, cada pedido ao par com um enlace novo — mediana (menor-maior), pelo log da origem: {}",
            self.medidas.len(),
            partes.join(", ")
        )
    }

    /// O correio do destino, lançado pela pessoa: o endpoint.
    pub(crate) fn correio(&mut self) -> Result<String, String> {
        let desde = self.destino.marca()?.log;
        self.destino.lancar("correio")?;
        match self.destino.esperar_dito(
            desde,
            &["correio: endpoint ", "correio: oferecer "],
            ESPERA_PELO_PROGRAMA,
        )? {
            (0, endpoint) => Ok(endpoint),
            (_, codigo) => Err(format!("o correio nao ofereceu: {codigo}")),
        }
    }

    /// Corta a energia do destino e o liga de novo, no mesmo disco e no
    /// mesmo TPM: o que voltar, voltou do journal.
    fn religar_o_destino(&mut self, maquina: &Maquina) -> Result<(), String> {
        self.destino.m.cortar()?;
        self.destino = maquina.ligar()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Um par
// ---------------------------------------------------------------------------

/// O registro da relação em `quem`: a chave do Duke do outro, a pessoa, a
/// relação, e o endereço, se houver.
fn registrar(
    quem: &mut DePe,
    outro: &[u8; 32],
    pessoa: &str,
    relacao: &str,
    endereco: Option<&str>,
) -> Result<(), String> {
    let mut params = format!(
        r#"{{"key":"{}","name":"{NOME}","person":"{pessoa}","role":"{PAPEL}","relation":"{relacao}""#,
        sigilo::hex(outro)
    );
    if let Some(e) = endereco {
        params.push_str(&format!(r#","address":"{e}""#));
    }
    params.push('}');
    quem.executar("device.register", &params)
}

/// Uma porta livre do hospedeiro, para o `hostfwd` do destino.
pub(crate) fn porta_livre() -> Result<u16, String> {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| format!("nenhuma porta livre no hospedeiro para o enlace: {e}"))
}

/// O resumo da imagem do carteiro de `arch` — o que o kernel de lá calcula
/// ao carregá-la —, nos oito primeiros dígitos, como a auditoria do
/// destino o grava.
pub(crate) fn atestado_do_carteiro(arch: Arquitetura) -> Result<String, String> {
    let caminho = super::raiz_do_projeto()
        .join("programas/target")
        .join(arch.alvo())
        .join("release/carteiro");
    let bytes = std::fs::read(&caminho).map_err(|e| format!("{}: {e}", caminho.display()))?;
    Ok(sigilo::hex(&politica::manifesto::resumo_da_imagem(&bytes))[..8].to_string())
}

/// Os passos de um par, em ordem: o que cada um conferiu.
fn um_par(origem: Arquitetura, destino: Arquitetura, release: bool) -> Result<Vec<String>, String> {
    let porta = porta_livre()?;
    let ponte = super::raiz_do_projeto().join(super::canal_tcp::PONTE);
    let ponte = ponte.display().to_string();
    if ponte.contains([',', ' ']) {
        return Err(format!(
            "o caminho da ponte nao cabe na opcao do emulador: {ponte}"
        ));
    }
    let a = Maquina::nova(
        "origem",
        origem,
        release,
        super::aleatorios()?,
        format!("guestfwd=tcp:10.0.2.100:{PORTA_DO_ENLACE}-cmd:python3 {ponte} {porta}"),
    )?;
    let b = Maquina::nova(
        "destino",
        destino,
        release,
        super::aleatorios()?,
        format!("hostfwd=tcp:127.0.0.1:{porta}-:{PORTA_DO_ENLACE}"),
    )?;
    let (id, _, _) = chaves::Chaves::garantir()?.pessoa_dev();
    let mut relacao = [0u8; 16];
    relacao.copy_from_slice(&super::aleatorios()?[..16]);
    let mut par = Par {
        da_origem: a.publica(),
        da_destino: b.publica(),
        relacao: sigilo::hex_de(&relacao),
        pessoa: sigilo::pessoas::IdPessoa(id).texto(),
        atestado: atestado_do_carteiro(origem)?,
        ultimo: None,
        medidas: Vec::new(),
        origem: a.ligar()?,
        destino: b.ligar()?,
    };
    let mut feitos = Vec::new();
    let r = passos(&mut par, &b, &mut feitos);
    if r.is_err() {
        par.origem.mostrar();
        par.destino.mostrar();
    }
    let (origem, destino) = (par.origem, par.destino);
    let _ = origem.m.cortar_a_energia();
    let _ = destino.m.cortar_a_energia();
    r.map(|()| feitos)
}

/// Os passos, sobre o par de pé. `b` é a máquina do destino, para religá-la
/// depois de cada corte.
fn passos(par: &mut Par, b: &Maquina, feitos: &mut Vec<String>) -> Result<(), String> {
    // 1. O registro, com prova, nos dois.
    let (da_origem, da_destino) = (par.da_origem, par.da_destino);
    let (pessoa, relacao) = (par.pessoa.clone(), par.relacao.clone());
    registrar(&mut par.destino, &da_origem, &pessoa, &relacao, None)?;
    registrar(
        &mut par.origem,
        &da_destino,
        &pessoa,
        &relacao,
        Some(ENDERECO),
    )?;
    par.destino_escuta(true)?;
    feitos.push(format!(
        "a relacao {} registrada com prova nos dois; o destino escuta a {PORTA_DO_ENLACE}",
        &relacao[..8]
    ));

    // 2. A pessoa nos dois Terminais; o correio lá, o carteiro aqui.
    par.destino.entrar()?;
    par.origem.entrar()?;
    let endpoint = par.correio()?;
    feitos.push(par.entrega(&endpoint)?);

    // 3. A suspensão no destino: o aperto recusado lá, e a volta.
    let suspenso = format!(r#"{{"device":"{DISPOSITIVO}"}}"#);
    par.destino.executar("device.suspend", &suspenso)?;
    let antes_d = par.destino.marca()?;
    par.recusado("DENY_NOT_AUTHENTICATED", "o par recusou o aperto")?;
    par.aperto_recusado(antes_d, "DENY_CREDENTIAL", "dispositivo suspenso")?;
    par.destino.executar("device.resume", &suspenso)?;
    par.entrega(&endpoint)?;
    feitos.push(
        "suspenso no destino: o aperto recusado la (DENY_CREDENTIAL), nada ao gate de la; retomado, a entrega volta"
            .into(),
    );

    // 4. A suspensão na origem: recusado aqui, sem rede, e a volta.
    par.origem.executar("device.suspend", &suspenso)?;
    let (antes_o, antes_d) = (par.origem.marca()?, par.destino.marca()?);
    par.recusado("DENY_CREDENTIAL", "operacao negada pela politica")?;
    par.recusado_aqui(antes_o, "DENY_CREDENTIAL", "dispositivo suspenso")?;
    par.sem_rede(antes_o, antes_d)?;
    par.origem.executar("device.resume", &suspenso)?;
    par.entrega(&endpoint)?;
    feitos.push(
        "suspenso na origem: recusado no gate daqui (DENY_CREDENTIAL), sem conexao nem aperto; retomado, a entrega volta"
            .into(),
    );

    // 5. O corte de energia do destino: a relação volta do journal, e o
    //    enlace funciona sem registro novo.
    par.religar_o_destino(b)?;
    par.destino_escuta(true)?;
    par.destino.entrar()?;
    let endpoint = par.correio()?;
    par.entrega(&endpoint)?;
    feitos.push(
        "o destino cortado e religado: a relacao voltou do journal, e a entrega funciona sem registro novo"
            .into(),
    );

    // 6. A revogação no destino: o enlace recusado, nada ao gate de lá, o
    //    registro de novo recusado pela lápide — também depois de outro
    //    corte —, e a porta do enlace fechada.
    let antes_d = par.destino.marca()?;
    par.destino
        .executar("device.revoke", &format!(r#"{{"name":"{NOME}"}}"#))?;
    par.destino_escuta(false)?;
    // A origem ainda tem a relação: o pedido vai, e o destino não atende.
    // Quem pediu ouve um desfecho — o par mudo, no prazo da conversa —, e
    // não um pedido ainda a caminho.
    let c = par.carteiro()?;
    let recusa = c.dito("procurar ").unwrap_or("");
    if c.codigo != CARTEIRO_RECUSADO || !recusa.starts_with("ERROR ") {
        return Err(format!(
            "revogado no destino, o carteiro nao ouviu um desfecho na procura: {}",
            c.texto()
        ));
    }
    par.destino.ler()?;
    if par
        .destino
        .gravados(antes_d.auditoria)
        .any(|g| g.titular == "device" && g.metodo.starts_with("fabric."))
    {
        return Err("revogado, um pedido do dispositivo chegou ao gate do destino".into());
    }
    // Sem relação nenhuma, a porta do enlace não escuta: o SYN da origem não
    // entra, e não há aperto a gravar — nem recusado.
    if par
        .destino
        .gravados(antes_d.auditoria)
        .any(|g| g.metodo == "link.open")
    {
        return Err(
            "sem relacao, o destino ainda fez um aperto: a porta do enlace devia estar fechada"
                .into(),
        );
    }
    par.registro_com_lapide(&pessoa, &relacao)?;
    par.religar_o_destino(b)?;
    par.registro_com_lapide(&pessoa, &relacao)?;
    par.destino_escuta(false)?;
    feitos.push(format!(
        "revogado no destino: a procura recusada ({}), nada ao gate de la, a porta do enlace fechada; o registro de novo recusado pela lapide, tambem depois do corte",
        c.dito("procurar ").unwrap_or("")
    ));

    // 7. A revogação na origem: recusado aqui, sem rede.
    par.origem
        .executar("device.revoke", &format!(r#"{{"name":"{NOME}"}}"#))?;
    let (antes_o, antes_d) = (par.origem.marca()?, par.destino.marca()?);
    par.recusado("DENY_RESOURCE", "operacao negada pela politica")?;
    par.recusado_aqui(
        antes_o,
        "DENY_RESOURCE",
        "o dispositivo nao existe para quem pede",
    )?;
    par.sem_rede(antes_o, antes_d)?;
    feitos.push(
        "revogado na origem: recusado no gate daqui (DENY_RESOURCE), sem conexao nem aperto".into(),
    );
    feitos.push(par.resumo_das_medidas());
    Ok(())
}

/// `cargo xtask enlace`: os pares escolhidos, um de cada vez.
pub(crate) fn enlace(release: bool) -> Result<ExitCode, String> {
    let filtro = std::env::var("DUKE_PARES").ok();
    let nome = |(o, d): &(Arquitetura, Arquitetura)| format!("{}>{}", o.nome(), d.nome());
    let escolhidos: Vec<(Arquitetura, Arquitetura)> = PARES
        .iter()
        .filter(|par| {
            filtro
                .as_deref()
                .is_none_or(|f| f.split('|').any(|p| p.trim() == nome(par)))
        })
        .copied()
        .collect();
    if escolhidos.is_empty() {
        return Err(format!(
            "DUKE_PARES nao escolhe par nenhum; os pares: {}",
            PARES.iter().map(nome).collect::<Vec<_>>().join("|")
        ));
    }
    println!(
        "[xtask] enlace: {} pares, duas maquinas de pe em cada",
        escolhidos.len()
    );
    let mut falhas = 0;
    for par in &escolhidos {
        let (origem, destino) = *par;
        println!("[xtask] enlace: {}", nome(par));
        let comeco = Instant::now();
        match um_par(origem, destino, release) {
            Ok(feitos) => {
                for f in feitos {
                    println!("  [enlace] ok  {}: {f}", nome(par));
                }
                println!(
                    "  [enlace] ok  {}: o par inteiro em {} s",
                    nome(par),
                    comeco.elapsed().as_secs()
                );
            }
            Err(motivo) => {
                falhas += 1;
                println!("  [enlace] FALHOU  {}: {motivo}", nome(par));
            }
        }
    }
    let base = super::raiz_do_projeto().join("target").join("enlace");
    for papel in ["origem", "destino"] {
        let _ = std::fs::remove_file(base.join(format!("{papel}.img")));
    }
    if falhas > 0 {
        println!("\n[xtask] enlace: {falhas} par(es) falharam");
        return Ok(ExitCode::FAILURE);
    }
    println!("\n[xtask] enlace: todos os pares passaram");
    Ok(ExitCode::SUCCESS)
}
