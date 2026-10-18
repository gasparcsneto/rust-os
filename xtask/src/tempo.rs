//! A bancada de tempo (desenho §15.2): o Roughtime de verdade, pela
//! infraestrutura nativa, de ponta a ponta — uma máquina por cenário.
//!
//! # O caminho
//!
//! O fio `hora` do kernel pede cada passo ao gate, como o serviço que é
//! (`time.request`, `net.connect`, `net.send`, `net.recv`, `time.sync`,
//! `net.close`). O pedido sai pela placa de rede, atravessa a rede do
//! emulador e chega ao servidor do hospedeiro ([`super::servidor_de_hora`]),
//! outro processo, com outro código. A resposta volta pelo mesmo caminho, e o
//! tratador de `time.sync` a confere, junta as fontes no quórum e move o
//! civil pela disciplina. A auditoria grava cada passo, e o NSF a lê.
//!
//! # O que ela tem que a suíte não tem
//!
//! A suíte confere cada resposta ruim com servidores de dentro da máquina,
//! que interceptam os quadros antes da placa (`rede/bancada_hora.rs`), e
//! nenhum caso dela move a hora além do normal. Aqui os pedidos saem da
//! máquina, e a hora se move: o RTC começa atrasado ou adiantado, as fontes
//! pulam, calam, atrasam, divergem e voltam, e uma máquina sobe sobre o piso
//! de outra.
//!
//! # Nenhuma autoridade nova
//!
//! A bancada fala com a máquina pelo canal da serial, como a fumaça. O que
//! ela muda dentro da máquina — uma regra do firewall, uma linha da
//! política, a confirmação de um salto — passa pelo gate, com o papel de
//! quem pede e, onde a política pede, com a prova do administrador. O
//! servidor de hora não fala com o kernel: responde a quem lhe pergunta,
//! como qualquer servidor.
//!
//! # O que se mede
//!
//! De cada máquina: o tempo da rede (o endereço do DHCP, no log) até a
//! primeira sincronização, a conferência das respostas (`verify_ns` do
//! `system.info time`), o RTT de cada resposta aceita (a auditoria), e, do
//! lado do hospedeiro, quanto cada rodada levou. O resumo sai no fim.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use protocolo::json::Json;

use super::persistencia::Ligada;
use super::servidor_de_hora::{self, Desfecho, Modo, ServidorDeHora};
use super::{
    Arquitetura, Artefato, ExitCode, ObjetoPlano, apos, build, campo_simples, chaves,
    objetos_planos, zerar_o_estado,
};

/// Quanto esperar a primeira sincronização de uma máquina com as fontes
/// honestas desde a subida do canal.
const ATE_SINCRONIZAR: Duration = Duration::from_secs(60);

/// O intervalo entre rodadas depois de sincronizar — o do serviço. Os
/// cenários que esperam a próxima rodada contam com ele, e com folga.
const SINCRONIZADO: Duration = Duration::from_secs(64);

/// Um cenário: um nome que se lê como afirmação, e a função que a confere.
struct Cenario {
    nome: &'static str,
    rodar: fn(&mut Bancada) -> Result<String, String>,
}

/// Os cenários, na ordem em que rodam. Cada um começa com o estado zerado e
/// o servidor recém-subido.
const CENARIOS: &[Cenario] = &[
    Cenario {
        nome: "as fontes honestas sincronizam o civil pela rede, numa rodada",
        rodar: as_fontes_honestas,
    },
    Cenario {
        nome: "o caminho de Merkle de um lote fecha pelo fio, em qualquer profundidade",
        rodar: o_lote,
    },
    Cenario {
        nome: "uma fonte que pula sozinha fica de fora do acordo, marcada, e o civil segue as outras",
        rodar: uma_fonte_divergente,
    },
    Cenario {
        nome: "o atraso alarga a incerteza, e a resposta depois do prazo e perdida",
        rodar: o_atraso,
    },
    Cenario {
        nome: "o relogio atrasado uma hora salta para a frente em duas rodadas",
        rodar: o_relogio_atrasado,
    },
    Cenario {
        nome: "o relogio adiantado dois minutos volta no civil; o logico espera sem voltar, e o NSF nao contem por taxa",
        rodar: o_relogio_adiantado_dois_minutos,
    },
    Cenario {
        nome: "o relogio adiantado um dia volta no civil; o logico fica no piso",
        rodar: o_relogio_adiantado_um_dia,
    },
    Cenario {
        nome: "o piso de um boot adiantado segura o logico do boot seguinte, e nada volta",
        rodar: o_piso_de_outro_boot,
    },
    Cenario {
        nome: "as fontes pulam dez minutos: duas rodadas, e o salto alem do envelope",
        rodar: as_fontes_pulam_dez_minutos,
    },
    Cenario {
        nome: "o salto para tras e o de dois dias ficam pendentes, e so a prova da rodada aplica",
        rodar: os_saltos_pendentes,
    },
    Cenario {
        nome: "a perda de uma, duas e tres fontes, e a volta absorvida aos poucos",
        rodar: a_perda_e_a_recuperacao,
    },
    Cenario {
        nome: "o firewall barra uma fonte e duas: o quorum segue com as outras, e depois nao",
        rodar: o_firewall,
    },
    Cenario {
        nome: "a politica tira time.sync no meio da rodada: a rodada recusada nao move nada",
        rodar: a_revogacao_no_meio_da_rodada,
    },
    Cenario {
        nome: "com o teto do registro baixado, a hora vence sem as fontes",
        rodar: a_hora_vence,
    },
    // Por último: meia hora de máquina.
    Cenario {
        nome: "sem acordo por mais que a janela, a hora fica em holdover, e volta com as fontes",
        rodar: o_holdover,
    },
];

/// O que cada cenário tem: a máquina a subir, o servidor, e as medidas.
struct Bancada<'a> {
    nome: &'static str,
    arch: Arquitetura,
    release: bool,
    artefato: &'a Artefato,
    servidor: ServidorDeHora,
    medidas: &'a mut Medidas,
}

/// As medidas de todos os cenários, para o resumo do fim.
#[derive(Default)]
struct Medidas {
    /// Do endereço do DHCP à primeira sincronização, em ms do relógio do
    /// kernel, do boot até ela, e a rodada em que ela veio.
    primeira: Vec<(u64, u64, u64)>,
    /// A conferência de cada máquina: quantas, a média e a maior, em ns.
    conferencia: Vec<(u64, u64, u64)>,
    /// O RTT das respostas aceitas, pela auditoria.
    rtt_ms: Vec<u64>,
    /// As rodadas completas, pelo diário do servidor: do pedido da primeira
    /// fonte à resposta da última, e os vãos entre a resposta de uma fonte e
    /// o pedido da seguinte — o trabalho do kernel entre elas.
    rodadas: Vec<(Duration, Vec<Duration>)>,
    /// As rodadas pelo relógio do kernel, de cada máquina: o cenário,
    /// quantas, a média, a maior e a média da espera pelas fontes, em ns.
    do_kernel: Vec<(&'static str, u64, u64, u64, u64)>,
    /// Quanto o servidor levou em cada resposta, fora o atraso do modo: a
    /// conferência do pedido, a árvore e a assinatura. Está dentro do RTT.
    servidor: Vec<Duration>,
}

/// `cargo xtask tempo`: roda os cenários e diz quais passaram.
pub(crate) fn tempo(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    let artefato = build(arch, release, false)?;
    println!(
        "[xtask] tempo: {} cenarios, cada um com o estado zerado e as fontes de hora do hospedeiro ({})",
        CENARIOS.len(),
        arch.nome()
    );
    // O mesmo filtro da bancada de persistência: pedaços do nome separados
    // por `|`; vale o cenário que tiver qualquer um deles.
    let filtro = std::env::var("DUKE_CENARIOS").ok();
    let escolhido = |c: &&Cenario| {
        filtro
            .as_deref()
            .is_none_or(|f| f.split('|').any(|p| c.nome.contains(p)))
    };
    let mut medidas = Medidas::default();
    let mut falhas = 0;
    for cenario in CENARIOS.iter().filter(escolhido) {
        zerar_o_estado(arch)?;
        let servidor = ServidorDeHora::subir()?;
        let mut bancada = Bancada {
            nome: cenario.nome,
            arch,
            release,
            artefato: &artefato,
            servidor,
            medidas: &mut medidas,
        };
        let resultado = (cenario.rodar)(&mut bancada);
        let eventos = bancada.servidor.eventos();
        bancada.medidas.rodadas.extend(rodadas_completas(&eventos));
        bancada
            .medidas
            .servidor
            .extend(eventos.iter().filter_map(|e| {
                match e.desfecho {
                    Desfecho::Respondido { atraso_ms, .. } => e
                        .saida?
                        .checked_sub(e.chegada)?
                        .checked_sub(Duration::from_millis(atraso_ms)),
                    _ => None,
                }
            }));
        match resultado {
            Ok(detalhe) => println!("  [tempo] ok  {}: {detalhe}", cenario.nome),
            Err(motivo) => {
                falhas += 1;
                println!(
                    "  [tempo] FALHOU  {}: {motivo}\n    o servidor: {}",
                    cenario.nome,
                    resumo_do_diario(&eventos)
                );
            }
        }
    }
    zerar_o_estado(arch)?;
    medidas.imprimir();
    if falhas > 0 {
        println!("\n[xtask] tempo: {falhas} cenario(s) falharam");
        return Ok(ExitCode::FAILURE);
    }
    println!("\n[xtask] tempo: todos os cenarios passaram");
    Ok(ExitCode::SUCCESS)
}

impl Bancada<'_> {
    /// Liga a máquina, com o RTC em `deslocamento_s` da hora do hospedeiro.
    fn subir(&self, deslocamento_s: Option<i64>) -> Result<Ligada, String> {
        let data =
            deslocamento_s.map(|d| data_de(servidor_de_hora::agora_ms().div_euclid(1000) + d));
        Ligada::subir(self.arch, self.artefato, data.as_deref())
    }

    /// As medidas desta máquina: a conferência, os RTT da auditoria, as
    /// rodadas pelo relógio do kernel e — se as fontes responderam desde o
    /// boot, e a primeira sincronização não esperou a bancada — o tempo até
    /// ela.
    fn medir(&mut self, m: &mut Ligada, honestas_desde_o_boot: bool) -> Result<(), String> {
        let h = hora(m)?;
        let (registros, _) = auditoria(m, 0)?;
        // A rodada do primeiro acordo: com as fontes honestas desde o boot
        // e o RTC na hora, é a da primeira sincronização.
        let rodada = fechamentos(&registros)
            .iter()
            .find(|f| f.do_servico && f.desfecho == "acordo")
            .map_or(0, |f| f.rodada);
        if honestas_desde_o_boot
            && let (Some(primeira), Some(rede)) = (h.primeira_ms, uptime_do_dhcp(m)?)
        {
            self.medidas
                .primeira
                .push((primeira.saturating_sub(rede), primeira, rodada));
        }
        self.medidas.conferencia.push(h.conferencia);
        if h.rodada_ns.0 > 0 {
            self.medidas.do_kernel.push((
                self.nome,
                h.rodada_ns.0,
                h.rodada_ns.1,
                h.rodada_ns.2,
                h.espera_media_ns,
            ));
        }
        self.medidas.rtt_ms.extend(
            registros
                .iter()
                .filter(|r| do_servico(r) && campo(r, "method") == "time.sync")
                .filter_map(|r| {
                    let d = detalhe(r);
                    apos(&d, " rtt ").and_then(|v| v.parse::<u64>().ok())
                }),
        );
        Ok(())
    }
}

/// O objeto `time` do `system.info`, lido.
#[derive(Clone, Debug, Default)]
struct Hora {
    /// A hora do hospedeiro no meio do pedido.
    hospedeiro_ms: i64,
    uptime_ms: u64,
    rtc_s: Option<u64>,
    estado: String,
    civil_ms: u64,
    incerteza_ms: Option<u64>,
    pendente_ms: Option<i64>,
    rodada_pendente: Option<u64>,
    marcas: Vec<String>,
    alem_do_envelope: bool,
    logico: u64,
    adiantado_ms: u64,
    fechadas: u64,
    com_acordo: u64,
    sem_acordo: u64,
    perdidas: u64,
    confirmadas: u64,
    ultima: Option<Ultima>,
    primeira_ms: Option<u64>,
    deriva_ppm: u64,
    /// Quantas conferências, a média e a maior, em ns.
    conferencia: (u64, u64, u64),
    /// As rodadas pelo relógio do kernel: quantas, a média e a maior, em
    /// ns; e a média da espera pelas fontes nelas.
    rodada_ns: (u64, u64, u64),
    espera_media_ns: u64,
}

/// A última rodada fechada, como o `system.info` a diz.
#[derive(Clone, Debug, Default)]
struct Ultima {
    numero: u64,
    do_servico: bool,
    desfecho: String,
    cobertura: Option<u64>,
    incerteza_ms: Option<u64>,
    aceitas: u64,
    efeito: String,
    vereditos: Vec<(String, String)>,
}

impl Hora {
    /// Quanto o civil está à frente da hora do hospedeiro.
    fn desvio_ms(&self) -> i64 {
        self.civil_ms as i64 - self.hospedeiro_ms
    }

    /// Quanto o lógico está à frente da hora do hospedeiro, em segundos.
    fn logico_desvio_s(&self) -> i64 {
        self.logico as i64 - self.hospedeiro_ms.div_euclid(1000)
    }

    fn marcado(&self, marca: &str) -> bool {
        self.marcas.iter().any(|m| m == marca)
    }

    /// Com as fontes na hora do hospedeiro, a hora dele está dentro da
    /// incerteza que o civil diz — com a folga da ida e volta da serial.
    fn hora_dentro_da_incerteza(&self) -> bool {
        self.incerteza_ms
            .is_some_and(|u| self.desvio_ms().unsigned_abs() <= u + 100)
    }
}

impl std::fmt::Display for Hora {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} civil {:+}ms u {:?} logico {:+}s marcas {:?}",
            self.estado,
            self.desvio_ms(),
            self.incerteza_ms,
            self.logico_desvio_s(),
            self.marcas
        )?;
        if let Some(p) = self.pendente_ms {
            write!(f, " pendente {p:+}ms (r{:?})", self.rodada_pendente)?;
        }
        write!(
            f,
            "; rodadas {} ({} com acordo, {} sem, {} perdidas)",
            self.fechadas, self.com_acordo, self.sem_acordo, self.perdidas
        )?;
        if let Some(u) = &self.ultima {
            write!(
                f,
                "; a ultima r{} {} {} {:?}",
                u.numero, u.desfecho, u.efeito, u.vereditos
            )?;
        }
        Ok(())
    }
}

/// O tempo da máquina, pelo `system.info`.
fn hora(m: &mut Ligada) -> Result<Hora, String> {
    let antes = servidor_de_hora::agora_ms();
    let r = m.pedir("system.info", "{}")?;
    let depois = servidor_de_hora::agora_ms();
    ler_a_hora(&r, antes + (depois - antes) / 2)
        .ok_or_else(|| format!("o system.info nao diz o tempo como se espera\n  {r}"))
}

fn ler_a_hora(r: &str, hospedeiro_ms: i64) -> Option<Hora> {
    let topo = Json(r.as_bytes()).member("result")?;
    let t = topo.member("time")?;
    let numero = |j: Json, nome: &str| j.member(nome).and_then(|v| v.as_u64());
    let texto = |j: Json, nome: &str| {
        j.member(nome)
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_default()
    };
    let com_sinal = |j: Json, nome: &str| -> Option<i64> {
        j.member(nome)
            .filter(|v| !v.is_null())
            .and_then(|v| v.raw_str()?.trim().parse().ok())
    };
    let rodadas = t.member("rounds")?;
    let ultima = rodadas.member("last").filter(|u| !u.is_null()).map(|u| {
        let mut vereditos = Vec::new();
        if let Some(fontes) = u.member("sources") {
            let mut i = 0;
            while let Some(f) = fontes.item(i) {
                vereditos.push((texto(f, "name"), texto(f, "verdict")));
                i += 1;
            }
        }
        Ultima {
            numero: numero(u, "number").unwrap_or(0),
            do_servico: u.member("by_service").and_then(|v| v.as_bool()) == Some(true),
            desfecho: texto(u, "outcome"),
            cobertura: numero(u, "coverage"),
            incerteza_ms: numero(u, "uncertainty_ms"),
            aceitas: numero(u, "accepted").unwrap_or(0),
            efeito: texto(u, "effect"),
            vereditos,
        }
    });
    let mut marcas = Vec::new();
    if let Some(lista) = t.member("marks") {
        let mut i = 0;
        while let Some(marca) = lista.item(i) {
            marcas.extend(marca.as_str().map(String::from));
            i += 1;
        }
    }
    let conferencia = t.member("verify_ns")?;
    let medida = |nome: &str| -> (u64, u64, u64) {
        t.member(nome).map_or((0, 0, 0), |m| {
            (
                numero(m, "count").unwrap_or(0),
                numero(m, "mean").unwrap_or(0),
                numero(m, "max").unwrap_or(0),
            )
        })
    };
    Some(Hora {
        hospedeiro_ms,
        uptime_ms: numero(topo, "uptime_ms")?,
        rtc_s: numero(topo, "rtc"),
        estado: texto(t, "state"),
        civil_ms: numero(t, "civil_ms")?,
        incerteza_ms: numero(t, "uncertainty_ms"),
        pendente_ms: com_sinal(t, "pending_ms"),
        rodada_pendente: numero(t, "pending_round"),
        marcas,
        alem_do_envelope: t.member("beyond_envelope").and_then(|v| v.as_bool()) == Some(true),
        logico: numero(t, "logical")?,
        adiantado_ms: numero(t, "ahead_ms").unwrap_or(0),
        fechadas: numero(rodadas, "closed")?,
        com_acordo: numero(rodadas, "with_agreement")?,
        sem_acordo: numero(rodadas, "without_agreement")?,
        perdidas: numero(rodadas, "lost")?,
        confirmadas: numero(rodadas, "confirmed_jumps")?,
        ultima,
        primeira_ms: numero(rodadas, "first_sync_uptime_ms"),
        deriva_ppm: t
            .member("counter")
            .and_then(|c| numero(c, "drift_ppm"))
            .unwrap_or(0),
        conferencia: (
            numero(conferencia, "count")?,
            numero(conferencia, "mean")?,
            numero(conferencia, "max")?,
        ),
        rodada_ns: medida("round_ns"),
        espera_media_ns: medida("round_wait_ns").1,
    })
}

/// Lê o tempo até `pronto` dizer que sim, a cada meio segundo, até `prazo`.
/// Cada leitura passa a `ver`, que confere o que tem de valer o tempo todo.
fn esperar(
    m: &mut Ligada,
    prazo: Duration,
    o_que: &str,
    ver: &mut dyn FnMut(&Hora) -> Result<(), String>,
    pronto: &dyn Fn(&Hora) -> bool,
) -> Result<Hora, String> {
    esperar_a_cada(m, Duration::from_millis(500), prazo, o_que, ver, pronto)
}

/// Como [`esperar`], lendo a cada `passo`: numa espera de meia hora, uma
/// leitura a cada meio segundo seriam milhares de registros a mais na
/// auditoria, e o NSF lendo todos.
fn esperar_a_cada(
    m: &mut Ligada,
    passo: Duration,
    prazo: Duration,
    o_que: &str,
    ver: &mut dyn FnMut(&Hora) -> Result<(), String>,
    pronto: &dyn Fn(&Hora) -> bool,
) -> Result<Hora, String> {
    let fim = Instant::now() + prazo;
    loop {
        let h = hora(m)?;
        ver(&h)?;
        if pronto(&h) {
            return Ok(h);
        }
        if Instant::now() > fim {
            return Err(format!(
                "{o_que}: nao aconteceu em {} s; o tempo ficou em {h}",
                prazo.as_secs()
            ));
        }
        std::thread::sleep(passo);
    }
}

/// O que vale o tempo todo: o lógico nunca volta, de uma leitura à outra.
struct NadaVolta {
    logico: u64,
}

impl NadaVolta {
    fn novo() -> NadaVolta {
        NadaVolta { logico: 0 }
    }

    fn ver(&mut self, h: &Hora) -> Result<(), String> {
        if h.logico < self.logico {
            return Err(format!(
                "o logico voltou: {} depois de {}",
                h.logico, self.logico
            ));
        }
        self.logico = h.logico;
        Ok(())
    }
}

/// O uptime do kernel quando o DHCP deu o endereço, pelo log.
fn uptime_do_dhcp(m: &mut Ligada) -> Result<Option<u64>, String> {
    let r = m.pedir("log.tail", r#"{"count":1024,"min_level":"info"}"#)?;
    let registros = Json(r.as_bytes())
        .member("result")
        .and_then(|x| x.member("records"))
        .ok_or_else(|| format!("o log.tail nao respondeu com registros\n  {r}"))?;
    let mut i = 0;
    while let Some(registro) = registros.item(i) {
        if registro
            .member("message")
            .and_then(|v| v.as_str())
            .is_some_and(|t| t.contains("pelo DHCP"))
        {
            return Ok(registro.member("uptime_ms").and_then(|v| v.as_u64()));
        }
        i += 1;
    }
    Ok(None)
}

/// O valor de um campo de um registro, ou vazio.
fn campo(r: &ObjetoPlano, nome: &str) -> String {
    r.iter()
        .find(|(n, _)| n == nome)
        .and_then(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// O registro é do serviço de hora, pelo gate, como ele mesmo.
fn do_servico(r: &ObjetoPlano) -> bool {
    campo(r, "holder") == "service" && campo(r, "agent") == "hora" && campo(r, "role") == "tempo"
}

/// Os registros da auditoria depois de `depois`, até a cabeça de agora, e a
/// cabeça. Em páginas: cada `audit.tail` também é gravado, e quem lesse até
/// a página vazia nunca chegaria lá.
fn auditoria(m: &mut Ligada, depois: u64) -> Result<(Vec<ObjetoPlano>, u64), String> {
    let fim: u64 = campo_simples(&m.pedir("audit.head", "{}")?, "seq")
        .and_then(|v| v.parse().ok())
        .ok_or("audit.head sem seq")?;
    let mut registros = Vec::new();
    let mut ultimo = depois;
    while ultimo < fim {
        let cauda = m.pedir("audit.tail", &format!(r#"{{"count":64,"after":{ultimo}}}"#))?;
        let pagina =
            objetos_planos(apos(&cauda, r#""records":["#).ok_or("audit.tail sem registros")?)?;
        let Some(seq) = pagina
            .last()
            .map(|r| campo(r, "seq"))
            .and_then(|s| s.parse::<u64>().ok())
        else {
            break;
        };
        ultimo = seq;
        registros.extend(pagina);
    }
    Ok((registros, fim))
}

/// O fechamento de uma rodada, pela auditoria: o registro de `time.sync` com
/// o recurso `civil ...`.
#[derive(Clone, Debug)]
struct Fechamento {
    rodada: u64,
    desfecho: String,
    /// `cobertura/aceitas` no acordo; `maior/chaves` sem quórum.
    contagem: String,
    desvio_ms: Option<i64>,
    incerteza_ms: Option<u64>,
    efeito: String,
    recurso: String,
    codigo: String,
    do_servico: bool,
}

/// O detalhe de um registro de execução, sem o que o kernel acrescenta: o
/// processo de quem pediu, no começo (`pelo processo N (kernel): `), e a
/// decisão que autorizou, no fim (`; decisao N`).
fn detalhe(r: &ObjetoPlano) -> String {
    let d = campo(r, "detail");
    let d = match d.split_once("): ") {
        Some((antes, depois)) if antes.starts_with("pelo processo ") => depois,
        _ => d.as_str(),
    };
    d.split("; decisao ").next().unwrap_or_default().to_string()
}

fn fechamentos(registros: &[ObjetoPlano]) -> Vec<Fechamento> {
    registros
        .iter()
        .filter(|r| campo(r, "method") == "time.sync" && campo(r, "resource").starts_with("civil "))
        .filter_map(|r| {
            let detalhe = detalhe(r);
            let partes: Vec<&str> = detalhe.split(' ').collect();
            let rodada = partes.first()?.strip_prefix('r')?.parse().ok()?;
            let desfecho = partes.get(1)?.to_string();
            let contagem = partes
                .get(2)
                .filter(|p| p.contains('/'))
                .map_or(String::new(), |p| p.to_string());
            let desvio_ms = partes
                .iter()
                .find_map(|p| p.strip_prefix('d').and_then(|v| v.parse().ok()));
            let incerteza_ms = partes
                .iter()
                .find_map(|p| p.strip_prefix('u').and_then(|v| v.parse().ok()));
            Some(Fechamento {
                rodada,
                desfecho,
                contagem,
                desvio_ms,
                incerteza_ms,
                efeito: partes.last()?.to_string(),
                recurso: campo(r, "resource"),
                codigo: campo(r, "code"),
                do_servico: do_servico(r),
            })
        })
        .collect()
}

/// Os vereditos de cada fonte, pela auditoria: o nome da fonte e o detalhe.
/// São os registros de execução de `time.sync` do serviço que dizem o que a
/// entrega deu — e não a decisão do gate, cujo recurso é o id do pedido.
fn vereditos(registros: &[ObjetoPlano]) -> Vec<(String, String)> {
    registros
        .iter()
        .filter(|r| {
            let d = detalhe(r);
            do_servico(r)
                && campo(r, "method") == "time.sync"
                && ["aceita ", "recusada ", "sem_resposta", "vencida"]
                    .iter()
                    .any(|v| d.starts_with(v))
        })
        .map(|r| {
            let recurso = campo(r, "resource");
            let fonte = recurso.split(' ').next().unwrap_or_default().to_string();
            (fonte, detalhe(r))
        })
        .collect()
}

/// Os registros de `time.sync` em poucas linhas — o titular, o papel, o
/// código, o recurso e o detalhe —, para o motivo de uma falha.
fn amostra_de_time_sync(registros: &[ObjetoPlano]) -> String {
    let deles: Vec<String> = registros
        .iter()
        .filter(|r| campo(r, "method") == "time.sync")
        .map(|r| {
            format!(
                "{}/{}/{} {} `{}` `{}`",
                campo(r, "holder"),
                campo(r, "agent"),
                campo(r, "role"),
                campo(r, "code"),
                campo(r, "resource"),
                campo(r, "detail")
            )
        })
        .collect();
    format!(
        "{} registros de time.sync de {}; os ultimos: {}",
        deles.len(),
        registros.len(),
        deles[deles.len().saturating_sub(8)..].join(" | ")
    )
}

/// Uma data `AAAA-MM-DDTHH:MM:SS` do RTC, de um instante em segundos desde a
/// época Unix.
fn data_de(unix_s: i64) -> String {
    let dias = unix_s.div_euclid(86_400);
    let s = unix_s.rem_euclid(86_400);
    // O calendário civil a partir dos dias (o algoritmo de Howard Hinnant).
    let z = dias + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let dia = doy - (153 * mp + 2) / 5 + 1;
    let mes = if mp < 10 { mp + 3 } else { mp - 9 };
    let ano = yoe + era * 400 + i64::from(mes <= 2);
    format!(
        "{ano:04}-{mes:02}-{dia:02}T{:02}:{:02}:{:02}",
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

/// As rodadas completas do diário: as três fontes, na ordem, cada uma
/// respondida. A duração vai do pedido da primeira à resposta da última; os
/// vãos, da resposta de uma fonte ao pedido da seguinte.
fn rodadas_completas(eventos: &[servidor_de_hora::Evento]) -> Vec<(Duration, Vec<Duration>)> {
    let mut rodadas = Vec::new();
    let mut atual: Vec<&servidor_de_hora::Evento> = Vec::new();
    let mut ordenados: Vec<&servidor_de_hora::Evento> = eventos.iter().collect();
    ordenados.sort_by_key(|e| e.chegada);
    for e in ordenados {
        if e.fonte == 0 {
            atual.clear();
        }
        if e.fonte != atual.len() {
            atual.clear();
            continue;
        }
        if !matches!(e.desfecho, Desfecho::Respondido { .. }) || e.saida.is_none() {
            atual.clear();
            continue;
        }
        atual.push(e);
        if atual.len() == servidor_de_hora::FONTES {
            let inicio = atual[0].chegada;
            let fim = atual[atual.len() - 1].saida.unwrap_or(inicio);
            let vaos = atual
                .windows(2)
                .filter_map(|par| par[1].chegada.checked_sub(par[0].saida?))
                .collect();
            rodadas.push((fim.saturating_sub(inicio), vaos));
            atual.clear();
        }
    }
    rodadas
}

/// O diário do servidor em uma linha: quantos pedidos cada fonte recebeu, e
/// o que fez com eles.
fn resumo_do_diario(eventos: &[servidor_de_hora::Evento]) -> String {
    let mut partes = Vec::new();
    for (i, (nome, _)) in chaves::FONTES_DE_HORA.iter().enumerate() {
        let desta: Vec<_> = eventos.iter().filter(|e| e.fonte == i).collect();
        let respondidos = desta
            .iter()
            .filter(|e| matches!(e.desfecho, Desfecho::Respondido { .. }))
            .count();
        let descartados = desta
            .iter()
            .filter(|e| e.desfecho == Desfecho::Descartado)
            .count();
        let ignorados: Vec<_> = desta
            .iter()
            .filter_map(|e| match &e.desfecho {
                Desfecho::Ignorado(m) => Some(*m),
                _ => None,
            })
            .collect();
        partes.push(format!(
            "{nome}: {} datagramas, {respondidos} respondidos, {descartados} descartados, ignorados {ignorados:?}",
            desta.len()
        ));
    }
    partes.join("; ")
}

impl Medidas {
    fn imprimir(&self) {
        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        if !self.primeira.is_empty() {
            let rede: Vec<u64> = self.primeira.iter().map(|p| p.0).collect();
            let boot: Vec<u64> = self.primeira.iter().map(|p| p.1).collect();
            let mut rodadas: BTreeMap<u64, usize> = BTreeMap::new();
            for p in &self.primeira {
                *rodadas.entry(p.2).or_default() += 1;
            }
            let rodadas: Vec<String> = rodadas
                .iter()
                .map(|(r, n)| format!("{n} na r{r}"))
                .collect();
            println!(
                "  [tempo] medido  primeira sincronizacao depois do endereco do DHCP: media {} ms, maior {} ms, menor {} ms; {} ms do boot em media; {} maquinas: {}",
                media(&rede),
                rede.iter().max().unwrap_or(&0),
                rede.iter().min().unwrap_or(&0),
                media(&boot),
                rede.len(),
                rodadas.join(", ")
            );
        }
        if let Some(&(n, media_ns, maior_ns)) = self.conferencia.iter().max_by_key(|c| c.0) {
            let total: u64 = self.conferencia.iter().map(|c| c.0).sum();
            let medias: Vec<u64> = self.conferencia.iter().map(|c| c.1).collect();
            println!(
                "  [tempo] medido  conferencia de uma resposta (duas Ed25519 estritas e o resto): media {} us entre as maquinas ({total} conferencias); na de mais conferencias, {n}: media {} us, maior {} us",
                media(&medias) / 1000,
                media_ns / 1000,
                maior_ns / 1000
            );
        }
        if !self.rtt_ms.is_empty() {
            let mut rtt = self.rtt_ms.clone();
            rtt.sort_unstable();
            println!(
                "  [tempo] medido  RTT das respostas aceitas (pela auditoria): mediana {} ms, maior {} ms, {} respostas",
                rtt[rtt.len() / 2],
                rtt[rtt.len() - 1],
                rtt.len()
            );
        }
        for (nome, n, media, maior, espera) in &self.do_kernel {
            println!(
                "  [tempo] medido  rodadas pelo relogio do kernel, em `{}`: {n}, media {:.1} ms (a maior {:.1} ms), das quais {:.1} ms esperando as fontes: {:.1} ms de kernel por rodada",
                nome.split(':').next().unwrap_or(nome),
                *media as f64 / 1e6,
                *maior as f64 / 1e6,
                *espera as f64 / 1e6,
                media.saturating_sub(*espera) as f64 / 1e6
            );
        }
        if !self.servidor.is_empty() {
            let mut v: Vec<f64> = self.servidor.iter().map(|d| ms(*d)).collect();
            v.sort_by(f64::total_cmp);
            println!(
                "  [tempo] medido  o servidor, do pedido a resposta (fora o atraso do modo; o xtask de depuracao assina): mediana {:.1} ms, maior {:.1} ms, {} respostas",
                v[v.len() / 2],
                v[v.len() - 1],
                v.len()
            );
        }
        if !self.rodadas.is_empty() {
            let mut duracoes: Vec<f64> = self.rodadas.iter().map(|r| ms(r.0)).collect();
            duracoes.sort_by(f64::total_cmp);
            let vaos: Vec<f64> = self
                .rodadas
                .iter()
                .flat_map(|r| r.1.iter().map(|v| ms(*v)))
                .collect();
            let media_dos_vaos = vaos.iter().sum::<f64>() / vaos.len().max(1) as f64;
            println!(
                "  [tempo] medido  rodada de tres fontes, do hospedeiro: mediana {:.1} ms, maior {:.1} ms, {} rodadas; entre a resposta de uma fonte e o pedido da seguinte, {:.1} ms em media",
                duracoes[duracoes.len() / 2],
                duracoes[duracoes.len() - 1],
                duracoes.len(),
                media_dos_vaos
            );
        }
    }
}

fn media(v: &[u64]) -> u64 {
    v.iter()
        .sum::<u64>()
        .checked_div(v.len() as u64)
        .unwrap_or(0)
}

/// Uma operação administrativa pela serial, com a prova do administrador da
/// imagem — o mesmo caminho da fumaça: o desafio, a prova sobre o comando e
/// os parâmetros, e a execução pelo gate.
fn administrar(m: &mut Ligada, comando: &str, params: &str) -> Result<String, String> {
    let chaves = chaves::Chaves::garantir()?;
    let desafio = m.pedir("admin.challenge", "{}")?;
    let pedido = super::pedido_administrativo(&chaves, 0, &desafio, comando, params, params)?;
    m.pedir("admin.execute", &pedido)
}

/// O tempo como o NSF o leu da auditoria, e o que ele detectou.
#[derive(Debug)]
struct DoNsf {
    estado: Option<String>,
    marcas: Vec<String>,
    aceitas: u64,
    sem_resposta: u64,
    deteccoes: u64,
    incidentes_abertos: u64,
}

fn nsf(m: &mut Ligada) -> Result<DoNsf, String> {
    let r = m.pedir("security.status", "{}")?;
    let s = Json(r.as_bytes())
        .member("result")
        .ok_or_else(|| format!("o security.status nao respondeu\n  {r}"))?;
    let t = s
        .member("time")
        .ok_or_else(|| format!("o security.status nao diz o tempo\n  {r}"))?;
    let numero = |j: Json, nome: &str| j.member(nome).and_then(|v| v.as_u64()).unwrap_or(0);
    let mut marcas = Vec::new();
    if let Some(lista) = t.member("marks") {
        let mut i = 0;
        while let Some(marca) = lista.item(i) {
            marcas.extend(marca.as_str().map(String::from));
            i += 1;
        }
    }
    Ok(DoNsf {
        estado: t.member("state").and_then(|v| v.as_str()).map(String::from),
        marcas,
        aceitas: numero(t, "accepted"),
        sem_resposta: numero(t, "no_response"),
        deteccoes: numero(s, "detections"),
        incidentes_abertos: numero(s, "incidents_open"),
    })
}

/// Espera o NSF ler a auditoria até o estado `estado` do tempo. Ele sabe do
/// estado pelo registro da rodada que fecha (desenho §9.1): uma transição
/// que acontece entre duas rodadas — a hora que vence sem fonte nenhuma —
/// só chega a ele com a rodada seguinte, até um intervalo depois.
fn nsf_em(m: &mut Ligada, estado: &str, prazo: Duration) -> Result<DoNsf, String> {
    nsf_ate(m, prazo, &format!("o estado {estado}"), &|n| {
        n.estado.as_deref() == Some(estado)
    })
}

/// Espera o NSF chegar a `pronto`: ele lê a auditoria em voltas, atrás da
/// cabeça, e o que ele conta é o que já leu.
fn nsf_ate(
    m: &mut Ligada,
    prazo: Duration,
    o_que: &str,
    pronto: &dyn Fn(&DoNsf) -> bool,
) -> Result<DoNsf, String> {
    let fim = Instant::now() + prazo;
    loop {
        let n = nsf(m)?;
        if pronto(&n) {
            return Ok(n);
        }
        if Instant::now() > fim {
            return Err(format!("o NSF nao chegou a {o_que}: {n:?}"));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Espera a rodada seguinte à `depois_de`-ésima fechar.
fn proxima(
    m: &mut Ligada,
    nada_volta: &mut NadaVolta,
    depois_de: u64,
    prazo: Duration,
) -> Result<Hora, String> {
    esperar(
        m,
        prazo,
        "a proxima rodada",
        &mut |h| nada_volta.ver(h),
        &|h| h.fechadas > depois_de,
    )
}

/// Espera o primeiro acordo, com as fontes como estão.
fn sincronizar(m: &mut Ligada, nada_volta: &mut NadaVolta) -> Result<Hora, String> {
    esperar(
        m,
        ATE_SINCRONIZAR,
        "a sincronizacao",
        &mut |h| nada_volta.ver(h),
        &|h| h.estado == "sincronizado",
    )
    .map_err(|motivo| com_os_vereditos(m, motivo))
}

/// O motivo de uma falha, com o que a auditoria tem das entregas. O
/// veredito final de uma fonte é `sem_resposta` também quando as respostas
/// dela foram recusadas — uma recusa não consome o pedido, e quem está no
/// caminho não queima o pedido mandando lixo antes da resposta verdadeira —;
/// o nome da recusa só está no registro de cada entrega.
fn com_os_vereditos(m: &mut Ligada, motivo: String) -> String {
    match auditoria(m, 0) {
        Ok((registros, _)) => format!(
            "{motivo}; as entregas na auditoria: {}",
            resumo_dos_vereditos(&registros)
        ),
        Err(e) => format!("{motivo}; (a auditoria nao se leu: {e})"),
    }
}

/// Quantas entregas do serviço deram cada veredito — `aceita`,
/// `recusada <motivo>`, `sem_resposta`, `vencida` —, pela auditoria.
fn resumo_dos_vereditos(registros: &[ObjetoPlano]) -> String {
    let mut contas: BTreeMap<String, usize> = BTreeMap::new();
    for (_, d) in vereditos(registros) {
        let nome: Vec<&str> = d.split(' ').take(2).collect();
        let nome = if nome.first() == Some(&"recusada") {
            nome.join(" ")
        } else {
            nome[0].to_string()
        };
        *contas.entry(nome).or_default() += 1;
    }
    if contas.is_empty() {
        return "nenhuma".into();
    }
    contas
        .iter()
        .map(|(v, n)| format!("{v}: {n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Espera o último registro da auditoria que não é leitura chegar ao
/// journal: o piso do relógio lógico vai junto — ver a bancada de
/// persistência, que espera do mesmo jeito.
fn esperar_a_auditoria_gravada(m: &mut Ligada) -> Result<(), String> {
    let fim = Instant::now() + Duration::from_secs(30);
    loop {
        let r = m.pedir("audit.tail", r#"{"count":32}"#)?;
        let registros =
            objetos_planos(apos(&r, r#""records":["#).ok_or("audit.tail sem registros")?)?;
        let leitura = |r: &ObjetoPlano| {
            (campo(r, "method") == "audit.tail" && campo(r, "holder") == "serial")
                || campo(r, "holder") == "service"
        };
        if registros
            .iter()
            .rev()
            .find(|r| !leitura(r))
            .is_some_and(|r| campo(r, "durable") == "true")
        {
            return Ok(());
        }
        if Instant::now() > fim {
            return Err("a auditoria nao foi ao journal em 30 s".into());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Os pedidos que a fonte `i` recebeu até agora.
fn pedidos_de(b: &Bancada, i: usize) -> usize {
    b.servidor.eventos().iter().filter(|e| e.fonte == i).count()
}

/// Espera a fonte `i` receber mais um pedido além dos `ja` que tinha, e
/// devolve quando ele chegou, na régua do servidor.
fn esperar_pedido(b: &Bancada, i: usize, ja: usize, prazo: Duration) -> Result<Duration, String> {
    let fim = Instant::now() + prazo;
    loop {
        let eventos = b.servidor.eventos();
        let deles: Vec<_> = eventos.iter().filter(|e| e.fonte == i).collect();
        if deles.len() > ja {
            return Ok(deles[ja].chegada);
        }
        if Instant::now() > fim {
            return Err(format!(
                "a fonte {i} nao recebeu o pedido seguinte em {} s",
                prazo.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Quando cada pedido de uma fonte chegou, na régua do servidor.
fn chegadas(b: &Bancada, i: usize) -> Vec<Duration> {
    let mut v: Vec<Duration> = b
        .servidor
        .eventos()
        .iter()
        .filter(|e| e.fonte == i)
        .map(|e| e.chegada)
        .collect();
    v.sort();
    v
}

/// Uma imagem de testes com o registro de fontes acrescido de `linha` —
/// para o cenário que baixa o teto da incerteza. O resto é o da imagem de
/// sempre: os programas, as chaves, a política, a âncora TLS. Mora num
/// diretório dela, em `target/tempo/`, com os arquivos de trabalho dela:
/// o disco de testes não muda. No x86, o iniciador e o kernel vão para a ESP
/// dela, como o build faz com o de testes.
fn imagem_com(b: &Bancada, linha: &str) -> Result<(std::path::PathBuf, Artefato), String> {
    let dir = super::raiz_do_projeto().join("target").join("tempo");
    let caminho = dir.join("disco.img");
    let chaves = chaves::Chaves::garantir()?;
    let mut arquivos = super::programas_do_disco()?;
    let mut da_imagem = chaves.arquivos()?;
    let politica = politica::Politica::ler(politica::PADRAO)
        .map_err(|e| format!("a politica da imagem nao se le: {}", e.motivo()))?;
    for (nome, conteudo) in da_imagem.iter_mut() {
        if nome == "etc/duke/tempo" {
            conteudo.extend_from_slice(linha.as_bytes());
            let texto = String::from_utf8_lossy(conteudo).to_string();
            let registro = hora::registro::Registro::ler(&texto)
                .map_err(|e| format!("o registro com `{}` nao se le: {e}", linha.trim()))?;
            super::conferir_o_tempo_da_imagem(&registro, &politica)?;
        }
    }
    arquivos.extend(da_imagem);
    arquivos.push((
        super::tls::ANCORA_NA_IMAGEM.to_string(),
        super::tls::ancora()?,
    ));
    super::montar_disco(&caminho, &arquivos)?;
    let artefato = match b.artefato {
        Artefato::Binario(img) => Artefato::Binario(img.clone()),
        Artefato::Disco(_) => {
            let perfil = if b.release { "release" } else { "debug" };
            let elf = super::raiz_do_projeto()
                .join("kernel")
                .join("target")
                .join(b.arch.alvo())
                .join(perfil)
                .join(super::NOME_DO_BINARIO);
            let efi = super::build_do_iniciador(b.arch, b.release)?;
            super::instalar_iniciador(b.arch, &caminho, &efi, &super::kernel_para_a_esp(&elf)?)?;
            Artefato::Disco(caminho.clone())
        }
    };
    Ok((caminho, artefato))
}

// ---------------------------------------------------------------------------
// Os cenários
// ---------------------------------------------------------------------------

/// O caso de todo dia: o RTC na hora do hospedeiro, as três fontes honestas.
/// O civil sincroniza pela rede numa rodada — o desvio cabe no raio —, o
/// lógico anda com ele, e a rodada seguinte, 64 s depois, não move nada.
fn as_fontes_honestas(b: &mut Bancada) -> Result<String, String> {
    let mut m = b.subir(None)?;
    let mut nada_volta = NadaVolta::novo();
    let h = sincronizar(&mut m, &mut nada_volta)?;
    let u = h.ultima.clone().unwrap_or_default();
    if !h.hora_dentro_da_incerteza()
        || h.logico_desvio_s().abs() > 2
        || !h.marcas.is_empty()
        || u.desfecho != "acordo"
        || u.cobertura != Some(3)
        || u.aceitas != 3
        || !matches!(u.efeito.as_str(), "nada" | "gradual")
        || !u.vereditos.iter().all(|(_, v)| v == "aceita")
        || !u.do_servico
    {
        return Err(format!("a primeira sincronizacao nao foi a esperada: {h}"));
    }
    let primeira = h.fechadas;
    // A rodada seguinte, no intervalo de sincronizado.
    let depois = esperar(
        &mut m,
        SINCRONIZADO + Duration::from_secs(30),
        "a rodada seguinte",
        &mut |h| nada_volta.ver(h),
        &|h| h.fechadas > primeira,
    )?;
    let u2 = depois.ultima.clone().unwrap_or_default();
    if depois.estado != "sincronizado"
        || !depois.hora_dentro_da_incerteza()
        || u2.cobertura != Some(3)
        || !matches!(u2.efeito.as_str(), "nada" | "gradual")
    {
        return Err(format!("a rodada seguinte moveu o que nao devia: {depois}"));
    }
    // Pela auditoria: cada passo do serviço pelo gate, ALLOW, e os vereditos.
    let (registros, _) = auditoria(&mut m, 0)?;
    let passos = [
        "time.request",
        "net.connect",
        "net.send",
        "net.recv",
        "time.sync",
        "net.close",
    ];
    for passo in passos {
        if !registros
            .iter()
            .any(|r| do_servico(r) && campo(r, "method") == passo && campo(r, "code") == "ALLOW")
        {
            return Err(format!(
                "a auditoria nao tem o servico de hora em {passo}, ALLOW"
            ));
        }
    }
    let aceitas = vereditos(&registros)
        .iter()
        .filter(|(_, d)| d.starts_with("aceita midp ") && d.contains(" radi 1 "))
        .count();
    let fechadas: Vec<Fechamento> = fechamentos(&registros)
        .into_iter()
        .filter(|f| f.do_servico && f.desfecho == "acordo")
        .collect();
    if aceitas < 6 || fechadas.len() < 2 || fechadas.iter().any(|f| f.contagem != "3/3") {
        return Err(format!(
            "a auditoria nao tem as duas rodadas com as tres fontes aceitas: {aceitas} aceitas, {fechadas:?}; {}",
            amostra_de_time_sync(&registros)
        ));
    }
    // O que uma rodada grava: as decisões e as execuções de cada passo, os
    // vereditos e o fechamento — tudo do serviço, nas duas rodadas.
    let por_rodada = registros.iter().filter(|r| do_servico(r)).count() / fechadas.len();
    // O NSF leu o mesmo: o estado e as seis respostas aceitas das duas
    // rodadas, sem incidente.
    let n = nsf_ate(
        &mut m,
        Duration::from_secs(20),
        "sincronizado, com as seis respostas aceitas",
        &|n| n.estado.as_deref() == Some("sincronizado") && n.aceitas >= 6,
    )?;
    if n.incidentes_abertos > 0 {
        return Err(format!("o NSF abriu um incidente na sincronizacao: {n:?}"));
    }
    // O servidor: só pedidos de 1024 bytes, todos respondidos.
    let eventos = b.servidor.eventos();
    if eventos.iter().any(|e| e.tamanho != 1024)
        || eventos
            .iter()
            .any(|e| !matches!(e.desfecho, Desfecho::Respondido { .. }))
    {
        return Err(format!(
            "o servidor recebeu o que nao era um pedido do kernel: {}",
            resumo_do_diario(&eventos)
        ));
    }
    b.medir(&mut m, true)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "sincronizado na rodada {} ({} {}, u {} ms), o civil a {:+} ms do hospedeiro, dentro dos {} ms que ele diz; a seguinte, r{}, {}; {} pedidos, todos respondidos; {por_rodada} registros do servico na auditoria por rodada; o NSF viu sincronizado",
        u.numero,
        u.desfecho,
        u.efeito,
        u.incerteza_ms.unwrap_or(0),
        h.desvio_ms(),
        h.incerteza_ms.unwrap_or(0),
        u2.numero,
        u2.efeito,
        eventos.len()
    ))
}

/// O RTC uma hora atrás, num disco novo. Com as fontes caladas, o civil é o
/// RTC e o lógico anda com ele. Quando elas respondem, o desvio de +1 h é
/// grande demais para o ajuste gradual: um candidato numa rodada, e o salto
/// na seguinte, que concorda — o primeiro acordo troca a hora do RTC pela
/// autenticada. O lógico salta junto, para a frente.
fn o_relogio_atrasado(b: &mut Bancada) -> Result<String, String> {
    b.servidor.todas(Modo::CALADA);
    let mut m = b.subir(Some(-3_600))?;
    let mut nada_volta = NadaVolta::novo();
    let antes = hora(&mut m)?;
    nada_volta.ver(&antes)?;
    let rtc_atras = antes
        .rtc_s
        .map(|r| r as i64 - antes.hospedeiro_ms.div_euclid(1000));
    if antes.estado != "rtc"
        || !rtc_atras.is_some_and(|d| (-3_610..=-3_590).contains(&d))
        || !(-3_610_000..=-3_590_000).contains(&antes.desvio_ms())
        || (antes.logico as i64 - (antes.civil_ms / 1000) as i64).abs() > 2
    {
        return Err(format!(
            "antes das fontes, o civil nao era o RTC uma hora atras (o RTC a {rtc_atras:?} s): {antes}"
        ));
    }
    let (_, cabeca) = auditoria(&mut m, 0)?;
    b.servidor.todas(Modo::HONESTA);
    let depois = esperar(
        &mut m,
        Duration::from_secs(120),
        "o salto",
        &mut |h| nada_volta.ver(h),
        &|h| h.estado == "sincronizado",
    )?;
    if !depois.hora_dentro_da_incerteza()
        || depois.logico_desvio_s().abs() > 2
        || depois.alem_do_envelope
    {
        return Err(format!("depois do salto, o civil nao e a hora: {depois}"));
    }
    let (registros, _) = auditoria(&mut m, cabeca)?;
    let rodadas: Vec<Fechamento> = fechamentos(&registros)
        .into_iter()
        .filter(|f| f.do_servico && f.desfecho == "acordo")
        .collect();
    let candidato = rodadas.iter().position(|f| f.efeito == "candidato");
    let salto = rodadas.iter().position(|f| f.efeito == "salto");
    let perto_de_uma_hora = |f: &Fechamento| {
        f.desvio_ms
            .is_some_and(|d| (3_590_000..=3_610_000).contains(&d))
    };
    match (candidato, salto) {
        (Some(c), Some(s))
            if s == c + 1 && perto_de_uma_hora(&rodadas[c]) && perto_de_uma_hora(&rodadas[s]) => {}
        _ => {
            return Err(format!(
                "a auditoria nao tem o candidato e o salto de +1 h em rodadas seguidas: {rodadas:?}; {}",
                amostra_de_time_sync(&registros)
            ));
        }
    }
    let s = &rodadas[salto.unwrap_or(0)];
    if !s.recurso.contains(" rtc>sincronizado") || s.codigo != "ALLOW" {
        return Err(format!(
            "o salto nao levou o estado de rtc a sincronizado: {s:?}"
        ));
    }
    b.medir(&mut m, false)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "antes, o civil a {:+} s (rtc); r{} candidato d{:+} ms, r{} salto d{:+} ms; depois, o civil a {:+} ms e o logico a {:+} s do hospedeiro",
        antes.desvio_ms() / 1000,
        rodadas[candidato.unwrap_or(0)].rodada,
        rodadas[candidato.unwrap_or(0)].desvio_ms.unwrap_or(0),
        s.rodada,
        s.desvio_ms.unwrap_or(0),
        depois.desvio_ms(),
        depois.logico_desvio_s()
    ))
}

/// O caminho de Merkle de verdade: cada fonte responde dentro de um lote —
/// a primeira numa árvore de 2 folhas, a segunda de 8, a terceira de 64 —,
/// com o pedido na última folha, e o kernel sobe pelo caminho até a raiz
/// assinada. É a leitura do `INDX` com caminho não vazio (desenho §16),
/// aqui contra uma árvore escrita à parte da do pacote `hora`.
fn o_lote(b: &mut Bancada) -> Result<String, String> {
    for (i, lote) in [2u32, 8, 64].into_iter().enumerate() {
        b.servidor.modo(
            i,
            Modo {
                lote,
                ..Modo::HONESTA
            },
        );
    }
    let mut m = b.subir(None)?;
    let mut nada_volta = NadaVolta::novo();
    let h = sincronizar(&mut m, &mut nada_volta)?;
    let u = h.ultima.clone().unwrap_or_default();
    if u.cobertura != Some(3)
        || !u.vereditos.iter().all(|(_, v)| v == "aceita")
        || !h.hora_dentro_da_incerteza()
    {
        return Err(format!("as respostas em lote nao foram todas aceitas: {h}"));
    }
    let eventos = b.servidor.eventos();
    for (i, lote) in [2u32, 8, 64].into_iter().enumerate() {
        if !eventos.iter().any(|e| {
            e.fonte == i
                && matches!(e.desfecho, Desfecho::Respondido { lote: l, indice, .. } if l == lote && indice == lote - 1)
        }) {
            return Err(format!(
                "a fonte {i} nao respondeu no lote de {lote}: {}",
                resumo_do_diario(&eventos)
            ));
        }
    }
    b.medir(&mut m, true)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "r{} acordo 3/3 com caminhos de 1, 3 e 6 resumos e o INDX 1, 7 e 63; o civil a {:+} ms",
        u.numero,
        h.desvio_ms()
    ))
}

/// Uma fonte que pula sozinha: a segunda, dez minutos à frente desde o
/// boot. As outras duas concordam; a do salto, autêntica, fica de fora do
/// acordo e marcada, e o civil segue as duas. Quando ela volta, a marca sai.
fn uma_fonte_divergente(b: &mut Bancada) -> Result<String, String> {
    b.servidor.modo(
        1,
        Modo {
            deslocamento_ms: 600_000,
            ..Modo::HONESTA
        },
    );
    let mut m = b.subir(None)?;
    let mut nada_volta = NadaVolta::novo();
    let h = sincronizar(&mut m, &mut nada_volta)?;
    let u = h.ultima.clone().unwrap_or_default();
    if !h.hora_dentro_da_incerteza()
        || !h.marcado("divergente")
        || u.cobertura != Some(2)
        || u.aceitas != 3
        || !u.vereditos.iter().all(|(_, v)| v == "aceita")
    {
        return Err(format!(
            "a fonte que pulou nao ficou de fora, marcada, com o civil nas outras: {h}"
        ));
    }
    let (registros, _) = auditoria(&mut m, 0)?;
    let marcada = fechamentos(&registros)
        .into_iter()
        .find(|f| f.do_servico && f.rodada == u.numero);
    if !marcada
        .as_ref()
        .is_some_and(|f| f.recurso.contains(" divergente") && f.contagem == "2/3")
    {
        return Err(format!(
            "a auditoria nao marcou a rodada divergente: {marcada:?}; {}",
            amostra_de_time_sync(&registros)
        ));
    }
    let nsf_antes = nsf_em(&mut m, "sincronizado", Duration::from_secs(20))?;
    b.servidor.modo(1, Modo::HONESTA);
    let depois = proxima(
        &mut m,
        &mut nada_volta,
        h.fechadas,
        SINCRONIZADO + Duration::from_secs(30),
    )?;
    let u2 = depois.ultima.clone().unwrap_or_default();
    if depois.marcado("divergente") || u2.cobertura != Some(3) || depois.desvio_ms().abs() > 2_000 {
        return Err(format!("a fonte voltou e a marca nao saiu: {depois}"));
    }
    b.medir(&mut m, true)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "r{} acordo 2/3, divergente, o civil a {:+} ms; o NSF viu {:?}; r{} acordo 3/3 sem a marca",
        u.numero,
        h.desvio_ms(),
        nsf_antes.marcas,
        u2.numero
    ))
}

/// O atraso da rede, de verdade: depois de sincronizar, a primeira fonte
/// responde em 800 ms, a segunda em 1500 ms, e a terceira em 2500 ms —
/// depois do prazo do pedido. O RTT medido pelo kernel cresce com o atraso,
/// e com ele o intervalo de cada amostra; a resposta atrasada demais chega
/// a um pedido que já se fechou, sem resposta, e a rodada fecha com as
/// outras duas.
fn o_atraso(b: &mut Bancada) -> Result<String, String> {
    let mut m = b.subir(None)?;
    let mut nada_volta = NadaVolta::novo();
    let h = sincronizar(&mut m, &mut nada_volta)?;
    let (_, cabeca) = auditoria(&mut m, 0)?;
    for (i, atraso_ms) in [800u64, 1_500, 2_500].into_iter().enumerate() {
        b.servidor.modo(
            i,
            Modo {
                atraso_ms,
                ..Modo::HONESTA
            },
        );
    }
    let depois = proxima(
        &mut m,
        &mut nada_volta,
        h.fechadas,
        SINCRONIZADO + Duration::from_secs(30),
    )?;
    let u = depois.ultima.clone().unwrap_or_default();
    let (registros, _) = auditoria(&mut m, cabeca)?;
    let deles = vereditos(&registros);
    let rtt = |fonte: &str| -> Option<u64> {
        deles
            .iter()
            .find(|(f, d)| f == fonte && d.starts_with("aceita "))
            .and_then(|(_, d)| apos(d, " rtt ")?.parse().ok())
    };
    let (a, bb) = (rtt("bancada-a"), rtt("bancada-b"));
    let sem_resposta_c = deles
        .iter()
        .any(|(f, d)| f == "bancada-c" && d == "sem_resposta");
    if u.cobertura != Some(2)
        || !a.is_some_and(|r| (800..1_100).contains(&r))
        || !bb.is_some_and(|r| (1_500..1_800).contains(&r))
        || !sem_resposta_c
        || depois.desvio_ms().abs() > 2_000
    {
        return Err(format!(
            "o atraso nao deu o RTT e a perda esperados: a {a:?} ms, b {bb:?} ms, c sem resposta {sem_resposta_c}; {depois}; {deles:?}"
        ));
    }
    // A resposta da terceira saiu, depois do prazo: o kernel não a
    // entregou a nada, e nenhum registro a mais apareceu por ela.
    let eventos = b.servidor.eventos();
    let saiu_tarde = eventos.iter().any(|e| {
        e.fonte == 2
            && matches!(e.desfecho, Desfecho::Respondido { .. })
            && e.saida
                .zip(Some(e.chegada))
                .is_some_and(|(s, c)| s - c >= Duration::from_millis(2_500))
    });
    if !saiu_tarde {
        return Err(format!(
            "a resposta atrasada da terceira fonte nao saiu: {}",
            resumo_do_diario(&eventos)
        ));
    }
    b.medir(&mut m, true)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "r{} acordo 2/2 com RTT {} e {} ms, u {} ms (antes, u {} ms); a terceira respondeu em 2,5 s, e o kernel ja tinha fechado o pedido: sem_resposta",
        u.numero,
        a.unwrap_or(0),
        bb.unwrap_or(0),
        u.incerteza_ms.unwrap_or(0),
        h.ultima.as_ref().and_then(|u| u.incerteza_ms).unwrap_or(0)
    ))
}

/// Faz um operador (o agente da porta 2) tentar, devagar, três métodos que o
/// papel dele não dá — um a cada `espaco`. O NSF tem uma regra para três
/// métodos recusados numa janela de 30 s: espaçados assim, eles não cabem
/// numa janela no relógio de verdade. Devolve as detecções novas e se o
/// agente continuou atendido.
fn sondar_devagar(
    b: &Bancada,
    m: &mut Ligada,
    espaco: Duration,
) -> Result<(u64, u64, bool), String> {
    let antes = nsf(m)?;
    let mut agente = super::AgenteNaPorta::conectar(b.arch, 2)?;
    for (i, metodo) in ["audit.tail", "policy.show", "security.status"]
        .iter()
        .enumerate()
    {
        if i > 0 {
            std::thread::sleep(espaco);
        }
        let r = agente.pedir(metodo, "{}")?;
        if !super::recusado_com(&r, "DENY_PERMISSION") {
            return Err(format!("o operador nao foi recusado em {metodo}\n  {r}"));
        }
    }
    // O NSF lê a auditoria em voltas: a última recusa já foi lida quando a
    // contagem dele passa dela.
    std::thread::sleep(Duration::from_secs(3));
    let r = agente.pedir("agent.ping", "{}")?;
    let atendido = !r.contains("DENY_CONTAINED") && r.contains("\"result\"");
    drop(agente);
    let depois = nsf(m)?;
    Ok((
        depois.deteccoes.saturating_sub(antes.deteccoes),
        depois
            .incidentes_abertos
            .saturating_sub(antes.incidentes_abertos),
        atendido,
    ))
}

/// O RTC dois minutos à frente, num disco novo. Com as fontes caladas, o
/// civil é o RTC, e o lógico, empurrado por ele, anda junto. Quando elas
/// respondem, o primeiro acordo traz o civil de volta — em duas rodadas —,
/// e o lógico **para**: está à frente do civil, marcado `adiantado`, e não
/// volta. Parado, ele congela os carimbos da auditoria, que é o que as
/// janelas do NSF contam: uma sondagem lenta, que no relógio de verdade não
/// cabe numa janela, não pode virar contenção. Uns dois minutos depois o
/// civil alcança o lógico, e os dois andam juntos de novo.
fn o_relogio_adiantado_dois_minutos(b: &mut Bancada) -> Result<String, String> {
    b.servidor.todas(Modo::CALADA);
    let mut m = b.subir(Some(120))?;
    let mut nada_volta = NadaVolta::novo();
    let antes = hora(&mut m)?;
    nada_volta.ver(&antes)?;
    if antes.estado != "rtc"
        || !(110_000..=130_000).contains(&antes.desvio_ms())
        || (antes.logico as i64 - (antes.civil_ms / 1000) as i64).abs() > 2
    {
        return Err(format!(
            "antes das fontes, o civil nao era o RTC dois minutos a frente: {antes}"
        ));
    }
    let (_, cabeca) = auditoria(&mut m, 0)?;
    b.servidor.todas(Modo::HONESTA);
    let h = esperar(
        &mut m,
        Duration::from_secs(120),
        "a volta do civil",
        &mut |h| nada_volta.ver(h),
        &|h| h.estado == "sincronizado",
    )?;
    if h.desvio_ms().abs() > 2_000
        || !h.marcado("adiantado")
        || !(60_000..=125_000).contains(&h.adiantado_ms)
    {
        return Err(format!(
            "o civil nao voltou, ou o logico nao ficou adiantado: {h}"
        ));
    }
    let (registros, _) = auditoria(&mut m, cabeca)?;
    let rodadas: Vec<Fechamento> = fechamentos(&registros)
        .into_iter()
        .filter(|f| f.do_servico && f.desfecho == "acordo")
        .collect();
    let perto = |f: &Fechamento| {
        f.desvio_ms
            .is_some_and(|d| (-130_000..=-110_000).contains(&d))
    };
    let c = rodadas
        .iter()
        .position(|f| f.efeito == "candidato" && perto(f));
    let s = rodadas.iter().position(|f| f.efeito == "salto" && perto(f));
    if !matches!((c, s), (Some(c), Some(s)) if s == c + 1)
        || !rodadas[s.unwrap_or(0)].recurso.contains(" adiantado")
    {
        return Err(format!(
            "a auditoria nao tem a volta de -2 min em duas rodadas, com o logico adiantado: {rodadas:?}"
        ));
    }
    // Parado: dez segundos depois, o mesmo lógico, e o civil andou.
    let parado = hora(&mut m)?;
    std::thread::sleep(Duration::from_secs(10));
    let ainda = hora(&mut m)?;
    nada_volta.ver(&ainda)?;
    if ainda.logico != parado.logico || ainda.civil_ms < parado.civil_ms + 9_000 {
        return Err(format!(
            "o logico nao ficou parado enquanto o civil andava: {parado} e depois {ainda}"
        ));
    }
    // Com o lógico parado, a sondagem lenta: três recusas a 35 s uma da
    // outra, todas com o mesmo carimbo. O desenho (§9.3): enquanto o lógico
    // está parado, as detecções continuam registradas, e a contenção
    // automática por taxa não acontece. A suspensão dela é do NSF com as
    // regras de tempo; o que se confere aqui é o que vale hoje: o operador
    // continua atendido.
    let (_, antes_da_sondagem) = auditoria(&mut m, 0)?;
    let (deteccoes, incidentes, atendido) = sondar_devagar(b, &mut m, Duration::from_secs(35))?;
    let parado_ainda = hora(&mut m)?;
    nada_volta.ver(&parado_ainda)?;
    // As três recusas, 70 s de ponta a ponta, com o mesmo carimbo: o
    // lógico estava parado durante a sondagem inteira.
    let (sondagem, _) = auditoria(&mut m, antes_da_sondagem)?;
    let carimbos_da_sondagem: Vec<String> = sondagem
        .iter()
        .filter(|r| campo(r, "holder") == "agent" && campo(r, "code") == "DENY_PERMISSION")
        .map(|r| campo(r, "ts_ms"))
        .collect();
    if carimbos_da_sondagem.len() != 3
        || carimbos_da_sondagem
            .iter()
            .any(|c| *c != carimbos_da_sondagem[0])
    {
        return Err(format!(
            "a sondagem nao aconteceu toda com o logico parado: os carimbos das recusas {carimbos_da_sondagem:?}"
        ));
    }
    if !atendido {
        return Err(format!(
            "com o logico parado, a sondagem lenta virou contencao: {deteccoes} deteccoes e {incidentes} incidentes novos, e o agente nao foi atendido; o tempo: {parado_ainda}"
        ));
    }
    let andando = esperar(
        &mut m,
        Duration::from_secs(150),
        "o logico andar de novo",
        &mut |h| nada_volta.ver(h),
        &|h| !h.marcado("adiantado"),
    )?;
    if (andando.logico as i64 - (andando.civil_ms / 1000) as i64).abs() > 1 {
        return Err(format!(
            "o civil passou o lógico e os dois nao andam juntos: {andando}"
        ));
    }
    // Os carimbos da auditoria nunca desceram.
    let (todos, _) = auditoria(&mut m, 0)?;
    let carimbos: Vec<u64> = todos
        .iter()
        .filter_map(|r| campo(r, "ts_ms").parse().ok())
        .collect();
    if let Some(w) = carimbos.windows(2).find(|w| w[1] < w[0]) {
        return Err(format!(
            "um carimbo da auditoria desceu: {} depois de {}",
            w[1], w[0]
        ));
    }
    b.medir(&mut m, false)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "antes, o civil a {:+} s (rtc); r{} candidato e r{} salto de -2 min; o logico parou {} s a frente; a sondagem lenta com ele parado (tres recusas a 35 s) deu {deteccoes} deteccao(oes) e {incidentes} incidente(s), e nenhuma contencao; voltou a andar com o civil; {} carimbos da auditoria, nenhum desceu",
        antes.desvio_ms() / 1000,
        rodadas[c.unwrap_or(0)].rodada,
        rodadas[s.unwrap_or(0)].rodada,
        h.adiantado_ms / 1000,
        carimbos.len()
    ))
}

/// O RTC um dia à frente: a mesma volta do civil, e o lógico fica no piso,
/// um dia à frente, marcado — sem andar, porque o civil está atrás dele.
fn o_relogio_adiantado_um_dia(b: &mut Bancada) -> Result<String, String> {
    b.servidor.todas(Modo::CALADA);
    let mut m = b.subir(Some(86_400))?;
    let mut nada_volta = NadaVolta::novo();
    let antes = hora(&mut m)?;
    nada_volta.ver(&antes)?;
    if antes.estado != "rtc" || !(86_390_000..=86_410_000).contains(&antes.desvio_ms()) {
        return Err(format!(
            "antes das fontes, o civil nao era o RTC um dia a frente: {antes}"
        ));
    }
    b.servidor.todas(Modo::HONESTA);
    let h = esperar(
        &mut m,
        Duration::from_secs(120),
        "a volta do civil",
        &mut |h| nada_volta.ver(h),
        &|h| h.estado == "sincronizado",
    )?;
    if h.desvio_ms().abs() > 2_000
        || !h.marcado("adiantado")
        || !(86_300_000..=86_410_000).contains(&h.adiantado_ms)
        || !(86_300..=86_410).contains(&h.logico_desvio_s())
    {
        return Err(format!(
            "o civil nao voltou um dia, ou o logico nao ficou no piso: {h}"
        ));
    }
    std::thread::sleep(Duration::from_secs(10));
    let ainda = hora(&mut m)?;
    nada_volta.ver(&ainda)?;
    if ainda.logico != h.logico {
        return Err(format!(
            "o logico andou com o civil atras dele: {h} e depois {ainda}"
        ));
    }
    let n = nsf_em(&mut m, "sincronizado", Duration::from_secs(20))?;
    if !n.marcas.iter().any(|m| m == "adiantado") {
        return Err(format!("o NSF nao viu o logico adiantado: {n:?}"));
    }
    b.medir(&mut m, false)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "o civil voltou um dia em duas rodadas, sincronizado a {:+} ms; o logico ficou {} s a frente, parado; o NSF viu {:?}",
        h.desvio_ms(),
        h.logico_desvio_s(),
        n.marcas
    ))
}

/// Um boot com o RTC uma hora à frente, sem fontes: o lógico anda uma hora
/// à frente, e o journal guarda o piso. O boot seguinte sobe com o RTC
/// certo e as fontes honestas: o civil sincroniza na hora, e o lógico fica
/// no piso do outro boot, adiantado, parado, até o civil passar dele.
fn o_piso_de_outro_boot(b: &mut Bancada) -> Result<String, String> {
    b.servidor.todas(Modo::CALADA);
    let mut m = b.subir(Some(3_600))?;
    let antes = hora(&mut m)?;
    if antes.estado != "rtc" || !(3_590..=3_610).contains(&antes.logico_desvio_s()) {
        return Err(format!(
            "o primeiro boot nao subiu uma hora a frente: {antes}"
        ));
    }
    esperar_a_auditoria_gravada(&mut m)?;
    m.cortar_a_energia()?;
    b.servidor.todas(Modo::HONESTA);
    let mut m = b.subir(None)?;
    let mut nada_volta = NadaVolta::novo();
    let h = sincronizar(&mut m, &mut nada_volta)?;
    if h.desvio_ms().abs() > 2_000
        || !h.marcado("adiantado")
        || !(3_400..=3_610).contains(&h.logico_desvio_s())
        || h.logico < antes.logico
    {
        return Err(format!(
            "o logico do segundo boot nao ficou no piso do primeiro: {h}; o primeiro deixou {}",
            antes.logico
        ));
    }
    std::thread::sleep(Duration::from_secs(10));
    let ainda = hora(&mut m)?;
    nada_volta.ver(&ainda)?;
    if ainda.logico != h.logico {
        return Err(format!(
            "o logico andou abaixo do piso: {h} e depois {ainda}"
        ));
    }
    b.medir(&mut m, false)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "o primeiro boot deixou o logico em {:+} s; no segundo, o civil sincronizou a {:+} ms e o logico ficou no piso, {:+} s, parado",
        antes.logico_desvio_s(),
        h.desvio_ms(),
        h.logico_desvio_s()
    ))
}

/// Sincronizada, a máquina vê as três fontes pularem dez minutos. O desvio
/// passa do limiar do ajuste gradual: um candidato, e o salto na rodada
/// seguinte, que concorda — marcado além do envelope, porque o contador não
/// o explica. O lógico salta junto, para a frente.
fn as_fontes_pulam_dez_minutos(b: &mut Bancada) -> Result<String, String> {
    let mut m = b.subir(None)?;
    let mut nada_volta = NadaVolta::novo();
    sincronizar(&mut m, &mut nada_volta)?;
    let (_, cabeca) = auditoria(&mut m, 0)?;
    b.servidor.todas(Modo {
        deslocamento_ms: 600_000,
        ..Modo::HONESTA
    });
    let h = esperar(
        &mut m,
        SINCRONIZADO + Duration::from_secs(40),
        "o salto de dez minutos",
        &mut |h| nada_volta.ver(h),
        &|h| (598_000..=602_000).contains(&h.desvio_ms()),
    )?;
    if !h.alem_do_envelope
        || !(598..=602).contains(&h.logico_desvio_s())
        || h.estado != "sincronizado"
    {
        return Err(format!(
            "o salto nao foi marcado alem do envelope, ou o logico nao veio: {h}"
        ));
    }
    let (registros, _) = auditoria(&mut m, cabeca)?;
    let rodadas: Vec<Fechamento> = fechamentos(&registros)
        .into_iter()
        .filter(|f| f.do_servico && f.desfecho == "acordo")
        .collect();
    let perto = |f: &Fechamento| {
        f.desvio_ms
            .is_some_and(|d| (598_000..=602_000).contains(&d))
    };
    let c = rodadas
        .iter()
        .position(|f| f.efeito == "candidato" && perto(f));
    let s = rodadas
        .iter()
        .position(|f| f.efeito == "salto_alem" && perto(f));
    if !matches!((c, s), (Some(c), Some(s)) if s == c + 1) {
        return Err(format!(
            "a auditoria nao tem o candidato e o salto alem do envelope em rodadas seguidas: {rodadas:?}"
        ));
    }
    b.medir(&mut m, true)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "r{} candidato d{:+} ms, r{} salto_alem; o civil a {:+} ms e o logico a {:+} s do hospedeiro",
        rodadas[c.unwrap_or(0)].rodada,
        rodadas[c.unwrap_or(0)].desvio_ms.unwrap_or(0),
        rodadas[s.unwrap_or(0)].rodada,
        h.desvio_ms(),
        h.logico_desvio_s()
    ))
}

/// Os saltos que só uma pessoa aplica. Sincronizada, a máquina vê as fontes
/// voltarem dez minutos: depois da primeira sincronização e fora do
/// envelope, o salto para trás fica pendente, e nada se move. As fontes
/// voltam à hora, e o pendente sai. Depois elas pulam dois dias à frente,
/// além do teto: pendente de novo. `time.confirm` não é comando; com a
/// prova e a rodada de outro pendente, nada; com a prova e a rodada dele,
/// o salto se aplica.
fn os_saltos_pendentes(b: &mut Bancada) -> Result<String, String> {
    let mut m = b.subir(None)?;
    let mut nada_volta = NadaVolta::novo();
    sincronizar(&mut m, &mut nada_volta)?;
    b.servidor.todas(Modo {
        deslocamento_ms: -600_000,
        ..Modo::HONESTA
    });
    let atras = esperar(
        &mut m,
        SINCRONIZADO + Duration::from_secs(40),
        "o pendente para tras",
        &mut |h| nada_volta.ver(h),
        &|h| h.pendente_ms.is_some(),
    )?;
    if !atras
        .pendente_ms
        .is_some_and(|p| (-602_000..=-598_000).contains(&p))
        || atras.desvio_ms().abs() > 2_000
        || !atras.marcado("pendente")
    {
        return Err(format!(
            "o salto para tras nao ficou pendente, com o civil parado: {atras}"
        ));
    }
    b.servidor.todas(Modo::HONESTA);
    let limpo = esperar(
        &mut m,
        SINCRONIZADO + Duration::from_secs(40),
        "o pendente sair",
        &mut |h| nada_volta.ver(h),
        &|h| h.fechadas > atras.fechadas,
    )?;
    if limpo.pendente_ms.is_some() || limpo.marcado("pendente") || limpo.desvio_ms().abs() > 2_000 {
        return Err(format!("as fontes voltaram e o pendente ficou: {limpo}"));
    }
    b.servidor.todas(Modo {
        deslocamento_ms: 172_800_000,
        ..Modo::HONESTA
    });
    let frente = esperar(
        &mut m,
        Duration::from_secs(2 * 64 + 40),
        "o pendente de dois dias",
        &mut |h| nada_volta.ver(h),
        &|h| h.pendente_ms.is_some(),
    )?;
    let Some(rodada) = frente.rodada_pendente else {
        return Err(format!(
            "o pendente de dois dias nao diz a rodada: {frente}"
        ));
    };
    if !frente
        .pendente_ms
        .is_some_and(|p| (172_798_000..=172_802_000).contains(&p))
        || frente.desvio_ms().abs() > 2_000
    {
        return Err(format!("o salto de dois dias nao ficou pendente: {frente}"));
    }
    let comando = format!(r#"{{"round":{rodada}}}"#);
    let r = m.pedir("time.confirm", &comando)?;
    if r.contains(r#""result""#) {
        return Err(format!("time.confirm respondeu como comando\n  {r}"));
    }
    let outra = format!(r#"{{"round":{}}}"#, rodada.saturating_sub(1));
    let r = administrar(&mut m, "time.confirm", &outra)?;
    if !r.contains(r#""executed":false"#) || !r.contains(r#""code":"CONFLICT""#) {
        return Err(format!(
            "time.confirm de outra rodada fez alguma coisa\n  {r}"
        ));
    }
    let intacto = hora(&mut m)?;
    nada_volta.ver(&intacto)?;
    if intacto.desvio_ms().abs() > 2_000 || intacto.pendente_ms.is_none() {
        return Err(format!(
            "a confirmacao recusada mexeu no relogio: {intacto}"
        ));
    }
    let r = administrar(&mut m, "time.confirm", &comando)?;
    if !r.contains(r#""executed":true"#) {
        return Err(format!(
            "time.confirm da rodada r{rodada} nao executou\n  {r}"
        ));
    }
    let h = hora(&mut m)?;
    nada_volta.ver(&h)?;
    if !(172_798_000..=172_802_000).contains(&h.desvio_ms())
        || !(172_798..=172_802).contains(&h.logico_desvio_s())
        || !h.alem_do_envelope
        || h.confirmadas != 1
        || h.pendente_ms.is_some()
    {
        return Err(format!("o salto confirmado nao se aplicou como devia: {h}"));
    }
    let (registros, _) = auditoria(&mut m, 0)?;
    if !registros.iter().any(|r| {
        campo(r, "method") == "time.confirm"
            && campo(r, "code") == "ALLOW"
            && campo(r, "resource").starts_with("salto +172")
            && campo(r, "resource").contains(&format!(" r{rodada} "))
    }) {
        return Err("a auditoria nao tem o salto confirmado, com a rodada".into());
    }
    b.medir(&mut m, true)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "-10 min: pendente {:+} s, o civil parado; as fontes voltaram e ele saiu; +2 dias: pendente na r{rodada}; o comando nao existe, a prova de outra rodada e CONFLICT, e a dela aplica: o civil e o logico a {:+} s",
        atras.pendente_ms.unwrap_or(0) / 1000,
        h.desvio_ms() / 1000
    ))
}

/// A perda, fonte a fonte. A terceira já sobe calada: o primeiro acordo é de
/// duas. Depois a segunda cala, e a rodada fecha sem quórum; depois a
/// primeira, e a rodada se perde inteira. Sem acordo, nada se move, e a
/// incerteza cresce pela deriva do contador. Uma falha leva o intervalo de
/// volta a 64 s (desenho §7.6). Quando as três voltam — cinco segundos à
/// frente, o desvio acumulado de quem ficou sem hora —, o civil sincroniza
/// de novo e absorve os cinco segundos aos poucos, sem salto.
fn a_perda_e_a_recuperacao(b: &mut Bancada) -> Result<String, String> {
    b.servidor.modo(2, Modo::CALADA);
    let mut m = b.subir(None)?;
    let mut nada_volta = NadaVolta::novo();
    let h1 = sincronizar(&mut m, &mut nada_volta)?;
    let u1 = h1.ultima.clone().unwrap_or_default();
    if u1.cobertura != Some(2)
        || !u1
            .vereditos
            .iter()
            .any(|(f, v)| f == "bancada-c" && v == "sem_resposta")
    {
        return Err(format!(
            "com uma fonte calada, o acordo nao foi das outras duas: {h1}"
        ));
    }
    b.servidor.modo(1, Modo::CALADA);
    let espera = SINCRONIZADO + Duration::from_secs(40);
    let h2 = proxima(&mut m, &mut nada_volta, h1.fechadas, espera)?;
    let u2 = h2.ultima.clone().unwrap_or_default();
    if u2.desfecho != "sem_quorum" || u2.efeito != "sem_acordo" || h2.desvio_ms().abs() > 2_000 {
        return Err(format!(
            "com duas caladas, a rodada nao fechou sem quorum: {h2}"
        ));
    }
    b.servidor.modo(0, Modo::CALADA);
    let h3 = proxima(&mut m, &mut nada_volta, h2.fechadas, espera)?;
    if h3.perdidas <= h2.perdidas || h3.desvio_ms().abs() > 2_000 {
        return Err(format!("com as tres caladas, a rodada nao se perdeu: {h3}"));
    }
    // O intervalo depois de cada falha, pelos pedidos à primeira fonte: o
    // da rodada sem quórum até a perdida.
    let a = chegadas(b, 0);
    let depois_da_falha = a
        .windows(2)
        .last()
        .map(|w| w[1].saturating_sub(w[0]))
        .unwrap_or_default();
    if depois_da_falha > Duration::from_secs(64 + 15) {
        return Err(format!(
            "depois de uma rodada sem acordo, a seguinte veio em {} s; o desenho diz que uma falha volta a 64 s",
            depois_da_falha.as_secs()
        ));
    }
    // A incerteza cresce com a deriva, entre duas leituras sem acordo.
    let (i1, i2) = (h2.incerteza_ms.unwrap_or(0), h3.incerteza_ms.unwrap_or(0));
    let passou = (h3.uptime_ms - h2.uptime_ms) as f64 / 1000.0;
    let ppm = (i2 as f64 - i1 as f64) / passou * 1000.0;
    if i2 <= i1 || (ppm - h3.deriva_ppm as f64).abs() > h3.deriva_ppm as f64 * 0.25 + 20.0 {
        return Err(format!(
            "sem acordo, a incerteza nao cresceu pela deriva: de {i1} a {i2} ms em {passou:.0} s ({ppm:.0} ppm; a deriva e {} ppm)",
            h3.deriva_ppm
        ));
    }
    // Os fechamentos das rodadas sem acordo: ERROR, e o recurso diz o civil
    // parado.
    let (registros, _) = auditoria(&mut m, 0)?;
    let sem_acordo: Vec<Fechamento> = fechamentos(&registros)
        .into_iter()
        .filter(|f| f.do_servico && f.efeito == "sem_acordo")
        .collect();
    if sem_acordo.len() < 2
        || sem_acordo
            .iter()
            .any(|f| f.codigo != "ERROR" || f.incerteza_ms.is_some())
    {
        return Err(format!(
            "as rodadas sem acordo nao foram gravadas como ERROR: {sem_acordo:?}"
        ));
    }
    // O NSF contou as fontes caladas: uma na primeira rodada, duas na
    // segunda, três na terceira.
    let nsf_perda = nsf_ate(
        &mut m,
        Duration::from_secs(20),
        "as seis respostas que nao vieram",
        &|n| n.sem_resposta >= 6,
    )?;
    // A volta, cinco segundos à frente.
    b.servidor.todas(Modo {
        deslocamento_ms: 5_000,
        ..Modo::HONESTA
    });
    let h4 = proxima(&mut m, &mut nada_volta, h3.fechadas, espera)?;
    let u4 = h4.ultima.clone().unwrap_or_default();
    if h4.estado != "sincronizado" || u4.efeito != "gradual" || u4.cobertura != Some(3) {
        return Err(format!(
            "a volta das fontes nao foi um ajuste gradual: {h4}"
        ));
    }
    // Aos poucos: o civil chega aos cinco segundos sem salto e sem voltar,
    // no máximo 5% mais rápido que o hospedeiro.
    let mut anterior = h4.clone();
    let mut maior_passo = 0.0f64;
    let fim = Instant::now() + Duration::from_secs(140);
    let absorvido = loop {
        std::thread::sleep(Duration::from_secs(2));
        let h = hora(&mut m)?;
        nada_volta.ver(&h)?;
        let real = (h.hospedeiro_ms - anterior.hospedeiro_ms) as f64;
        let civil = h.civil_ms as f64 - anterior.civil_ms as f64;
        if civil < 0.0 {
            return Err(format!(
                "o civil voltou no ajuste gradual: {anterior} e depois {h}"
            ));
        }
        maior_passo = maior_passo.max((civil - real) / real);
        anterior = h.clone();
        if (4_000..=6_000).contains(&h.desvio_ms()) {
            break h;
        }
        if Instant::now() > fim {
            return Err(format!("o desvio nao foi absorvido em 140 s: {h}"));
        }
    };
    // Leitura a leitura, a ida e volta da serial pesa uns 20 ms em 2 s — daí
    // a folga até 8% —; na absorção inteira, a taxa tem de ser a do teto.
    let real = (absorvido.hospedeiro_ms - h4.hospedeiro_ms) as f64;
    let taxa = (absorvido.civil_ms as f64 - h4.civil_ms as f64 - real) / real;
    if maior_passo > 0.08 || taxa > 0.055 {
        return Err(format!(
            "o ajuste gradual correu {:.1}% mais rapido que o hospedeiro em media, e {:.1}% numa leitura; o teto e 5%",
            taxa * 100.0,
            maior_passo * 100.0
        ));
    }
    let nsf_volta = nsf_em(&mut m, "sincronizado", Duration::from_secs(20))?;
    b.medir(&mut m, false)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "uma calada: acordo 2/2; duas: sem quorum; tres: perdida; a rodada depois da falha em {} s; a incerteza cresceu {ppm:.0} ppm (deriva {} ppm); o NSF contou {} sem resposta; a volta +5 s gradual, absorvida sem salto, {:.1}% mais rapido em {:.0} s (o maior passo, {:.1}% numa leitura), o civil a {:+} ms, e o NSF viu {:?}",
        depois_da_falha.as_secs(),
        h3.deriva_ppm,
        nsf_perda.sem_resposta,
        taxa * 100.0,
        real / 1000.0,
        maior_passo * 100.0,
        absorvido.desvio_ms(),
        nsf_volta.estado
    ))
}

/// O firewall barra o destino de uma fonte, e depois o de outra, pelo gate
/// (`net.block`, da serial). O serviço de hora pede `net.connect` como
/// sempre; o firewall recusa, e nada sai da máquina para a fonte barrada —
/// o servidor não recebe mais pedido dela. Com uma barrada, o acordo é das
/// outras duas; com duas, não há quórum. Tiradas as regras, as três voltam.
fn o_firewall(b: &mut Bancada) -> Result<String, String> {
    b.servidor.todas(Modo::CALADA);
    let mut m = b.subir(None)?;
    let mut nada_volta = NadaVolta::novo();
    let barrar = |m: &mut Ligada, metodo: &str, destino: &str| -> Result<(), String> {
        let r = m.pedir(metodo, &format!(r#"{{"to":"{destino}"}}"#))?;
        if campo_simples(&r, "rule").is_none() {
            return Err(format!("{metodo} {destino} nao foi feito\n  {r}"));
        }
        Ok(())
    };
    let destinos: Vec<&str> = chaves::FONTES_DE_HORA.iter().map(|(_, d)| *d).collect();
    barrar(&mut m, "net.block", destinos[0])?;
    // Uma rodada que já estivesse no ar quando a regra entrou pediu à
    // primeira fonte antes dela, e fecharia com as outras duas se elas
    // passassem a responder agora — um acordo sem a primeira, mas pela fonte
    // calada, e não pelo firewall. As fontes só respondem depois de uma
    // rodada fechar: a seguinte começa inteira depois da regra.
    let antes = hora(&mut m)?;
    nada_volta.ver(&antes)?;
    esperar(
        &mut m,
        SINCRONIZADO + Duration::from_secs(40),
        "uma rodada depois da regra",
        &mut |h| nada_volta.ver(h),
        &|h| h.fechadas > antes.fechadas,
    )?;
    let ate_a_regra = pedidos_de(b, 0);
    b.servidor.todas(Modo::HONESTA);
    let h1 = esperar(
        &mut m,
        Duration::from_secs(120),
        "o acordo sem a fonte barrada",
        &mut |h| nada_volta.ver(h),
        &|h| h.estado == "sincronizado",
    )?;
    let u1 = h1.ultima.clone().unwrap_or_default();
    if u1.cobertura != Some(2)
        || !u1
            .vereditos
            .iter()
            .any(|(f, v)| f == "bancada-a" && v == "sem_resposta")
    {
        return Err(format!(
            "com uma fonte barrada, o acordo nao foi das outras: {h1}"
        ));
    }
    barrar(&mut m, "net.block", destinos[1])?;
    let ate_a_segunda = pedidos_de(b, 1);
    let h2 = proxima(
        &mut m,
        &mut nada_volta,
        h1.fechadas,
        SINCRONIZADO + Duration::from_secs(40),
    )?;
    let u2 = h2.ultima.clone().unwrap_or_default();
    if u2.desfecho != "sem_quorum" || h2.desvio_ms().abs() > 2_000 {
        return Err(format!(
            "com duas barradas, a rodada nao fechou sem quorum: {h2}"
        ));
    }
    if pedidos_de(b, 0) != ate_a_regra || pedidos_de(b, 1) != ate_a_segunda {
        return Err(format!(
            "um pedido chegou a uma fonte barrada: {}",
            resumo_do_diario(&b.servidor.eventos())
        ));
    }
    let (registros, _) = auditoria(&mut m, 0)?;
    let barrados = registros
        .iter()
        .filter(|r| {
            do_servico(r)
                && campo(r, "method") == "net.connect"
                && campo(r, "code") == "DENY_POLICY"
                && detalhe(r).starts_with("bloqueado pelo firewall, regra ")
                && destinos[..2].contains(&campo(r, "resource").as_str())
        })
        .count();
    if barrados < 3 {
        let conexoes: Vec<String> = registros
            .iter()
            .filter(|r| do_servico(r) && campo(r, "method") == "net.connect")
            .map(|r| {
                format!(
                    "{} {} `{}`",
                    campo(r, "code"),
                    campo(r, "resource"),
                    detalhe(r)
                )
            })
            .collect();
        return Err(format!(
            "a auditoria nao tem as conexoes do servico recusadas pelo firewall ({barrados}): {conexoes:?}"
        ));
    }
    barrar(&mut m, "net.unblock", destinos[0])?;
    barrar(&mut m, "net.unblock", destinos[1])?;
    let h3 = proxima(
        &mut m,
        &mut nada_volta,
        h2.fechadas,
        SINCRONIZADO + Duration::from_secs(40),
    )?;
    let u3 = h3.ultima.clone().unwrap_or_default();
    if u3.cobertura != Some(3) {
        return Err(format!("tiradas as regras, as tres nao voltaram: {h3}"));
    }
    b.medir(&mut m, false)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "uma barrada: r{} acordo 2/2; duas: r{} sem quorum; nenhum pedido chegou as barradas; {barrados} net.connect do servico permitidos pelo gate e barrados pelo firewall na execucao (DENY_POLICY, com a regra); sem as regras, r{} acordo 3/3",
        u1.numero, u2.numero, u3.numero
    ))
}

/// A revogação no meio de uma rodada. As três fontes demoram 1,8 s cada —
/// a rodada dura uns 5,5 s —; assim que o pedido à primeira chega ao
/// servidor, a política perde `time.sync` no papel `tempo` (`policy.write`,
/// com a prova). O próximo passo de hora do serviço, seja a entrega de uma
/// resposta, seja o pedido da fonte seguinte, ouve a recusa do gate: a
/// rodada acaba ali, a recusa fica gravada, e nada dela se aplica. Com a
/// linha de volta, a rodada seguinte fecha como sempre.
fn a_revogacao_no_meio_da_rodada(b: &mut Bancada) -> Result<String, String> {
    let mut m = b.subir(None)?;
    let mut nada_volta = NadaVolta::novo();
    let h1 = sincronizar(&mut m, &mut nada_volta)?;
    let (_, cabeca) = auditoria(&mut m, 0)?;
    b.servidor.todas(Modo {
        atraso_ms: 1_800,
        ..Modo::HONESTA
    });
    let ja = pedidos_de(b, 0);
    let chegou = esperar_pedido(b, 0, ja, SINCRONIZADO + Duration::from_secs(40))?;
    let r = administrar(
        &mut m,
        "policy.write",
        r#"{"line":"papel tempo net.connect"}"#,
    )?;
    let escrita = b.servidor.desde_o_inicio().saturating_sub(chegou);
    if !r.contains(r#""executed":true"#) {
        return Err(format!("a politica sem time.sync nao foi escrita\n  {r}"));
    }
    // A rodada inteira levaria 3 × 1,8 s: a escrita tem de cair dentro dela.
    if escrita >= Duration::from_millis(5_000) {
        return Err(format!(
            "a politica so foi escrita {} ms depois do pedido: a rodada ja tinha passado",
            escrita.as_millis()
        ));
    }
    // O que a rodada ainda faria cabe nos próximos 6 s.
    std::thread::sleep(Duration::from_secs(6));
    let depois = hora(&mut m)?;
    nada_volta.ver(&depois)?;
    if depois.fechadas != h1.fechadas || depois.desvio_ms().abs() > 2_000 {
        return Err(format!(
            "a rodada revogada fechou, ou moveu o civil: {depois}"
        ));
    }
    let (registros, _) = auditoria(&mut m, cabeca)?;
    let recusas: Vec<String> = registros
        .iter()
        .filter(|r| {
            do_servico(r)
                && ["time.sync", "time.request"].contains(&campo(r, "method").as_str())
                && campo(r, "code") == "DENY_PERMISSION"
        })
        .map(|r| campo(r, "method"))
        .collect();
    if recusas.len() != 1 || !fechamentos(&registros).is_empty() {
        return Err(format!(
            "a auditoria nao tem uma recusa de hora do servico, e so uma, sem fechamento: {recusas:?}; {}",
            amostra_de_time_sync(&registros)
        ));
    }
    // A fonte que vinha depois da recusa não foi pedida.
    let eventos = b.servidor.eventos();
    let pedidas_depois = |i: usize| {
        eventos
            .iter()
            .filter(|e| e.fonte == i && e.chegada > chegou)
            .count()
    };
    let (a_b, a_c) = (pedidas_depois(1), pedidas_depois(2));
    if a_c > 0 {
        return Err(format!(
            "a rodada seguiu depois da recusa ate a terceira fonte: {}",
            resumo_do_diario(&eventos)
        ));
    }
    let r = administrar(
        &mut m,
        "policy.write",
        r#"{"line":"papel tempo net.connect time.sync"}"#,
    )?;
    if !r.contains(r#""executed":true"#) {
        return Err(format!("a politica de volta nao foi escrita\n  {r}"));
    }
    b.servidor.todas(Modo::HONESTA);
    let h2 = proxima(
        &mut m,
        &mut nada_volta,
        h1.fechadas,
        SINCRONIZADO + Duration::from_secs(40),
    )?;
    let u2 = h2.ultima.clone().unwrap_or_default();
    if u2.cobertura != Some(3) || !h2.hora_dentro_da_incerteza() {
        return Err(format!(
            "com a linha de volta, a rodada nao fechou como sempre: {h2}"
        ));
    }
    b.medir(&mut m, true)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "a politica perdeu time.sync {} ms depois do pedido a primeira fonte (o admin.execute com a prova); o {} seguinte do servico ouviu DENY_PERMISSION, a rodada acabou ali sem fechar ({}), e o civil ficou a {:+} ms; de volta a linha, r{} acordo 3/3",
        escrita.as_millis(),
        recusas[0],
        if a_b > 0 {
            "a segunda fonte ja tinha sido pedida, a terceira nao"
        } else {
            "nenhuma outra fonte pedida"
        },
        depois.desvio_ms(),
        u2.numero
    ))
}

/// O teto da incerteza baixado para 10 s, numa imagem só deste cenário. O
/// RTC uma hora atrás, e as fontes com raio grande e resposta lenta: a
/// primeira com raio de 9 s, a segunda de 10 s, as duas em 1,7 s, e a
/// terceira calada. O salto de uma hora traz a incerteza do acordo — a da
/// primeira, que a segunda contém —, pouco abaixo do teto. Então as três
/// calam: sem acordo, a incerteza cresce pela deriva do contador, passa do
/// teto, e a hora fica `vencido`. O lógico continua andando com o civil.
fn a_hora_vence(b: &mut Bancada) -> Result<String, String> {
    let (disco, artefato) = imagem_com(b, "incerteza 10\n")?;
    b.servidor.modo(
        0,
        Modo {
            raio_s: 9,
            atraso_ms: 1_700,
            ..Modo::HONESTA
        },
    );
    b.servidor.modo(
        1,
        Modo {
            raio_s: 10,
            atraso_ms: 1_700,
            ..Modo::HONESTA
        },
    );
    b.servidor.modo(2, Modo::CALADA);
    let data = data_de(servidor_de_hora::agora_ms().div_euclid(1000) - 3_600);
    let ambiente = super::Ambiente::ligar(b.arch, Some(&data))?.com_disco(disco);
    let mut m = Ligada::subir_com(b.arch, &artefato, ambiente)?;
    let mut nada_volta = NadaVolta::novo();
    let h = esperar(
        &mut m,
        Duration::from_secs(150),
        "o salto com raio grande",
        &mut |h| nada_volta.ver(h),
        &|h| h.estado == "sincronizado",
    )?;
    let u = h.incerteza_ms.unwrap_or(0);
    if h.desvio_ms().abs() > 12_000 || !(9_000..10_000).contains(&u) {
        return Err(format!(
            "o salto nao trouxe a incerteza da primeira fonte, abaixo do teto de 10 s: {h}"
        ));
    }
    b.servidor.todas(Modo::CALADA);
    // Quanto falta para o teto, pela deriva que o kernel diz, com folga.
    let deriva = h.deriva_ppm.max(1);
    let falta_s = (10_000 - u) * 1_000_000 / deriva / 1000;
    let prazo = Duration::from_secs(falta_s + 90);
    if prazo > Duration::from_secs(1_200) {
        return Err(format!(
            "a incerteza esta longe demais do teto para esperar: {u} ms com {deriva} ppm, {falta_s} s"
        ));
    }
    let mut maior_sincronizado = 0;
    let vencido = esperar(
        &mut m,
        prazo,
        "a hora vencer",
        &mut |h| {
            if h.estado == "sincronizado" {
                maior_sincronizado = maior_sincronizado.max(h.incerteza_ms.unwrap_or(0));
            }
            nada_volta.ver(h)
        },
        &|h| h.estado == "vencido",
    )?;
    if vencido.incerteza_ms.is_none_or(|i| i <= 10_000) || maior_sincronizado > 10_000 {
        return Err(format!(
            "a hora venceu sem passar do teto, ou ficou sincronizada acima dele: {vencido} (a maior incerteza sincronizada, {maior_sincronizado} ms)"
        ));
    }
    if (vencido.logico as i64 - (vencido.civil_ms / 1000) as i64).abs() > 1 {
        return Err(format!("vencida, a hora parou o logico: {vencido}"));
    }
    let n = nsf_em(&mut m, "vencido", SINCRONIZADO + Duration::from_secs(40))?;
    b.medir(&mut m, false)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "o salto trouxe u {u} ms; caladas as fontes, a hora venceu {} s depois com u {} ms (deriva {deriva} ppm); o logico seguiu o civil; o NSF viu {:?}",
        (vencido.uptime_ms - h.uptime_ms) / 1000,
        vencido.incerteza_ms.unwrap_or(0),
        n.estado
    ))
}

/// O holdover, com o registro da imagem: depois de sincronizar, as três
/// fontes calam. A hora continua `sincronizado` pela janela do desenho
/// (2048 s depois do último acordo), com a incerteza crescendo pela deriva,
/// e uma rodada perdida a cada 64 s; passada a janela, `holdover` — abaixo
/// do teto de 60 s, longe de `vencido`. O lógico continua com o civil. As
/// fontes voltam três segundos à frente: o ajuste gradual, `sincronizado`
/// de novo, e o NSF vê a volta.
fn o_holdover(b: &mut Bancada) -> Result<String, String> {
    let mut m = b.subir(None)?;
    let mut nada_volta = NadaVolta::novo();
    let h = sincronizar(&mut m, &mut nada_volta)?;
    b.servidor.todas(Modo::CALADA);
    let janela = Duration::from_millis(hora::disciplina::Parametros::PADRAO.janela_sincronizado_ms);
    let mut anterior: Option<Hora> = None;
    let mut problema: Option<String> = None;
    let holdover = esperar_a_cada(
        &mut m,
        Duration::from_secs(15),
        janela + Duration::from_secs(180),
        "o holdover",
        &mut |l| {
            nada_volta.ver(l)?;
            if let Some(a) = &anterior
                && problema.is_none()
            {
                if l.incerteza_ms < a.incerteza_ms {
                    problema = Some(format!("a incerteza diminuiu sem acordo: {a} e depois {l}"));
                }
                if l.estado == "vencido" {
                    problema = Some(format!("a hora venceu antes do holdover: {l}"));
                }
                if (l.logico as i64 - (l.civil_ms / 1000) as i64).abs() > 1 {
                    problema = Some(format!("sem acordo, o logico se separou do civil: {l}"));
                }
            }
            anterior = Some(l.clone());
            Ok(())
        },
        &|l| l.estado == "holdover",
    )?;
    if let Some(p) = problema {
        return Err(p);
    }
    let passou = Duration::from_millis(holdover.uptime_ms - h.uptime_ms);
    if passou + Duration::from_secs(20) < janela {
        return Err(format!(
            "a hora foi a holdover {} s depois do ultimo acordo; a janela e {} s",
            passou.as_secs(),
            janela.as_secs()
        ));
    }
    // Uma rodada perdida a cada 64 s, mais a duração dela — três prazos de
    // 1,9 s —: os pedidos à primeira fonte, um por rodada, nunca se afastam
    // mais que isso. Um intervalo que dobrasse a cada falha daria cinco.
    let perdidas = holdover.perdidas - h.perdidas;
    let a = chegadas(b, 0);
    let maior_vao = a
        .windows(2)
        .map(|w| w[1].saturating_sub(w[0]))
        .max()
        .unwrap_or_default();
    if maior_vao > Duration::from_secs(64 + 15) || perdidas < passou.as_secs() / (64 + 15) {
        return Err(format!(
            "{perdidas} rodadas perdidas em {} s, e {} s entre duas: o intervalo sem acordo nao ficou em 64 s",
            passou.as_secs(),
            maior_vao.as_secs()
        ));
    }
    let n = nsf_em(&mut m, "holdover", SINCRONIZADO + Duration::from_secs(40))?;
    // A volta, três segundos à frente. O NSF sabe do holdover pelo registro
    // da rodada que fecha depois dele — calada —, e a espera acima a viu
    // fechar; uma rodada já no ar quando as fontes voltam pode ter pedido a
    // uma delas ainda calada. Vale a primeira que sincronizar, em até duas
    // rodadas.
    b.servidor.todas(Modo {
        deslocamento_ms: 3_000,
        ..Modo::HONESTA
    });
    let volta = esperar(
        &mut m,
        2 * SINCRONIZADO + Duration::from_secs(40),
        "a volta das fontes",
        &mut |h| nada_volta.ver(h),
        &|h| h.estado == "sincronizado",
    )?;
    let u = volta.ultima.clone().unwrap_or_default();
    if u.efeito != "gradual" {
        return Err(format!(
            "as fontes voltaram e o civil nao sincronizou aos poucos: {volta}"
        ));
    }
    let n2 = nsf_em(&mut m, "sincronizado", Duration::from_secs(20))?;
    b.medir(&mut m, true)?;
    m.cortar_a_energia()?;
    Ok(format!(
        "sincronizado com u {} ms; calaram as fontes: sincronizado ate a janela, holdover {} s depois do ultimo acordo, com u {} ms (o teto e 60 s), {perdidas} rodadas perdidas, no maximo {} s entre duas, o NSF viu {:?}; voltaram +3 s: r{} gradual, sincronizado, o NSF viu {:?} ({} sem resposta)",
        h.incerteza_ms.unwrap_or(0),
        passou.as_secs(),
        holdover.incerteza_ms.unwrap_or(0),
        maior_vao.as_secs(),
        n.estado,
        u.numero,
        n2.estado,
        n2.sem_resposta
    ))
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn a_data_do_rtc_sai_dos_segundos() {
        assert_eq!(data_de(0), "1970-01-01T00:00:00");
        assert_eq!(data_de(1_791_158_400), "2026-10-05T00:00:00");
        assert_eq!(data_de(951_782_400 + 3_661), "2000-02-29T01:01:01");
        assert_eq!(data_de(1_936_785_600), "2031-05-17T12:00:00");
        assert_eq!(data_de(-1), "1969-12-31T23:59:59");
    }

    #[test]
    fn o_fechamento_se_le_do_detalhe() {
        let registro = |detalhe: &str| -> ObjetoPlano {
            vec![
                ("method".into(), Some("time.sync".into())),
                (
                    "resource".into(),
                    Some("civil 1>2 logico 1>2 rtc>sincronizado".into()),
                ),
                ("detail".into(), Some(detalhe.into())),
                ("holder".into(), Some("service".into())),
                ("agent".into(), Some("hora".into())),
                ("role".into(), Some("tempo".into())),
                ("code".into(), Some("ALLOW".into())),
            ]
        };
        let f = fechamentos(&[
            registro(
                "pelo processo 5 (kernel): r12 acordo 3/3 d+3600123 u1001 candidato; decisao 77",
            ),
            registro("pelo processo 5 (kernel): r13 sem_quorum 1/1 sem_acordo; decisao 81"),
        ]);
        assert_eq!(f.len(), 2);
        assert_eq!(
            (f[0].rodada, f[0].desvio_ms, f[0].incerteza_ms),
            (12, Some(3_600_123), Some(1001))
        );
        assert_eq!(
            (f[0].contagem.as_str(), f[0].efeito.as_str()),
            ("3/3", "candidato")
        );
        assert_eq!(
            (f[1].rodada, f[1].desfecho.as_str(), f[1].efeito.as_str()),
            (13, "sem_quorum", "sem_acordo")
        );
        assert!(f[1].desvio_ms.is_none());
    }
}
