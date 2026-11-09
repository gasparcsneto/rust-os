//! A bancada da disponibilidade: quanto os pedidos dos processos de um
//! titular — ou de dois — seguram o executor do kernel — e, com ele, o canal
//! do agente de todos os outros, o pulso e a barra. É a medida da observação
//! sobre a fila dos pedidos dos processos, que a tarefa `programas`
//! (`nativo::servir_com`) atende no executor, ao lado do canal; é por ela
//! que se escolhe o orçamento da vez da tarefa (`nativo::ORCAMENTO_DA_VEZ`).
//!
//! # O que faz
//!
//! Sobe a máquina de produção — o kernel sem `modo-teste`: o executor de
//! verdade, com a tarefa `programas` ao lado das do canal — e, em cada
//! cenário:
//!
//! - sonda o canal de dois titulares que não são os da carga, um pedido de
//!   cada vez, de [`PERIODO`] em [`PERIODO`]: a serial (o `sistema`) e o TCP
//!   (a chave do agente 2); e, logo depois de a carga começar, um agente
//!   novo tenta entrar pelo TCP (a chave do agente 3) e fazer o primeiro
//!   pedido — o aperto também é atendido no executor, o da conexão que
//!   não o completa em dez segundos cai, e é o primeiro pedido que confirma
//!   a chave do aperto ao kernel;
//! - lança pela porta 1 — o agente 1, `operador`, o titular da carga —, e,
//!   num cenário de dois titulares, também pela porta 3 — o agente 3, outro
//!   `operador`, com a cota e a taxa dele —, pelo `user.run` de sempre, o
//!   programa `incansavel`, com o pedido gravado no armazém: quantos filhos
//!   por titular, por quanto tempo, que modo (`pedir`, a carga; `girar`, o
//!   controle sem fila);
//! - lê, antes e depois, os contadores que o kernel já publica:
//!   `user.stats` (os pedidos dos processos atendidos), `security.metrics`
//!   (as decisões por código) e `tasks.stats` (os avanços do executor e os
//!   bytes perdidos na entrada);
//! - confere a carga: cada filho do `incansavel` conta os pedidos e as
//!   respostas, e confere que cada resposta é a do pedido dele — o `id`; a
//!   bancada soma as contas dos filhos e as compara com as do kernel (ver
//!   [`integridade`]);
//! - acompanha duas tarefas do executor pelo que o kernel já diz: o pulso,
//!   pelo registro que ele deixa no log a cada minuto — o intervalo entre
//!   dois é o minuto mais o atraso com que o executor o rodou —; e a barra,
//!   pelo relógio dela na árvore semântica (`ui.tree`, "tempo ligado"),
//!   lido pela porta 4 (o agente 4) de [`PERIODO_DA_BARRA`] em
//!   [`PERIODO_DA_BARRA`], junto com o `system.uptime` — o atraso é o quanto
//!   o relógio desenhado fica atrás do tempo ligado;
//! - e mostra o que a carga — e a medida temporária, se o kernel a tiver —
//!   disse no log.
//!
//! Diz, por cenário e por canal, a ida e volta das sondas antes, durante e
//! depois da carga — mediana, p99 e maior — e o maior silêncio do canal: o
//! maior intervalo sem resposta nenhuma.
//!
//! O console e o enlace não têm, sem uma superfície nova, o que mostrar
//! aqui: o console só acorda com o teclado, e as vagas do enlace, com um par
//! relacionado.
//!
//! # Só mede
//!
//! Nada aqui reprova pelo número: o número é o resultado. É erro só a
//! máquina que não sobe, a carga que não é lançada, a que não acaba, e a que
//! não confere — um filho sem a resposta de um pedido, ou com a de outro, ou
//! o kernel com menos pedidos atendidos do que os processos fizeram.
//!
//! `DUKE_CARGA` escolhe os cenários, separados por vírgula: `0` é nenhuma
//! carga, `N` são N filhos pedindo, `gN` são N filhos girando, e `N:2` ou
//! `gN:2`, os mesmos N filhos em cada um de dois titulares. O padrão é
//! [`CENARIOS`]. `DUKE_REPETICOES` repete a lista inteira. `DUKE_AMOSTRAS`,
//! um caminho, acrescenta a ele cada sonda de cada cenário — o cenário, o
//! canal, quando saiu e a ida e volta, em ms desde a origem da bancada — e
//! o instante do lançamento, para ver quando o canal parou.

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use super::persistencia::Ligada;
use super::{AgenteNaPorta, Arquitetura, build, campo_simples, zerar_o_estado};

/// O período das sondas: um pedido de cada vez, de 50 em 50 ms.
const PERIODO: Duration = Duration::from_millis(50);
/// Quanto cada cenário sonda antes de lançar a carga.
const ANTES: Duration = Duration::from_secs(10);
/// Quanto a carga dura — o `duracao_ms` do pedido.
const CARGA: Duration = Duration::from_secs(20);
/// Quanto cada cenário sonda depois do fim marcado da carga.
const DEPOIS: Duration = Duration::from_secs(10);
/// O prazo de uma resposta: maior que a carga, para a sonda presa durante
/// ela voltar com a ida e volta inteira, e não com um erro.
const PRAZO: Duration = Duration::from_secs(180);
/// Quanto depois do lançamento o agente novo tenta entrar.
const ENTRADA_DEPOIS: Duration = Duration::from_secs(2);
/// O pedido da carga, no armazém — o mesmo de `incansavel`.
const PEDIDO: &str = "/armazem/compartilhado/incansavel";
/// O padrão de `DUKE_CARGA`.
const CENARIOS: &str = "0,g3,1,2,3,0";
/// O que a bancada mostra do log: as linhas da carga, pela mensagem.
const CARGA_NO_LOG: &str = "incansavel";
/// E tudo o que uma medida temporária do kernel diz, se ele a tiver: o
/// subsistema dela, que nenhum kernel publicado usa.
const MEDIDA_NO_LOG: &str = "medida";
/// Quantos titulares uma carga pode ter: o agente 1 e o agente 3.
const TITULARES: u64 = 2;
/// A porta do segundo titular da carga: o agente 3, `operador` como o 1.
const PORTA_DO_SEGUNDO: u8 = 3;
/// A porta de quem lê o relógio da barra: o agente 4, que não é titular da
/// carga nem sonda o canal.
const PORTA_DA_BARRA: u8 = 4;
/// De quanto em quanto a barra é lida: o relógio dela anda de segundo em
/// segundo.
const PERIODO_DA_BARRA: Duration = Duration::from_millis(500);
/// O intervalo do pulso, em ms — o `INTERVALO_MS` da tarefa `pulso`, em
/// `kernel/src/main.rs`.
const PULSO_MS: u64 = 60_000;
/// Quantos registros o `log.tail` devolve, no máximo: o anel inteiro.
const ANEL_DO_LOG: u64 = 128;

/// Um cenário: quantos filhos por titular, se pedem ou giram, e quantos
/// titulares — o agente 1 e, com dois, também o agente 3. Zero filhos é a
/// referência, sem carga.
#[derive(Clone, Copy, Debug)]
struct Cenario {
    filhos: u64,
    girar: bool,
    titulares: u64,
}

impl Cenario {
    fn nome(self) -> String {
        let nome = match (self.filhos, self.girar) {
            (0, _) => return "sem carga".to_string(),
            (n, false) => format!("pedir x{n}"),
            (n, true) => format!("girar x{n}"),
        };
        if self.titulares > 1 {
            format!("{nome} em {} titulares", self.titulares)
        } else {
            nome
        }
    }
}

/// Os cenários de `DUKE_CARGA`, ou os do padrão.
fn cenarios() -> Result<Vec<Cenario>, String> {
    cenarios_de(&std::env::var("DUKE_CARGA").unwrap_or_else(|_| CENARIOS.to_string()))
}

/// Os cenários de um texto como o de `DUKE_CARGA`.
fn cenarios_de(texto: &str) -> Result<Vec<Cenario>, String> {
    texto
        .split(',')
        .map(|c| {
            let c = c.trim();
            let (carga, titulares) = match c.split_once(':') {
                Some((carga, t)) => (carga, t.parse::<u64>().unwrap_or(0)),
                None => (c, 1),
            };
            if !(1..=TITULARES).contains(&titulares) {
                return Err(format!(
                    "DUKE_CARGA: `{c}`: de 1 a {TITULARES} titulares, depois do `:`"
                ));
            }
            let (girar, n) = match carga.strip_prefix('g') {
                Some(n) => (true, n),
                None => (false, carga),
            };
            let filhos: u64 = n
                .parse()
                .map_err(|_| format!("DUKE_CARGA: `{c}` nao e N nem gN"))?;
            if filhos > 7 {
                return Err(format!(
                    "DUKE_CARGA: `{c}` passa de 7 filhos, a cota do operador com o pai"
                ));
            }
            Ok(Cenario {
                filhos,
                girar,
                titulares,
            })
        })
        .collect()
}

/// Uma sonda: quando o pedido saiu, desde a origem da bancada, e a ida e
/// volta — nenhuma, se o canal devolveu erro.
#[derive(Clone, Copy, Debug)]
struct Amostra {
    saiu: Duration,
    ida_e_volta: Option<Duration>,
}

/// Sonda com `pedir` até `ate`, um pedido de cada vez, de [`PERIODO`] em
/// [`PERIODO`] — o seguinte sai logo, se o de antes demorou mais que isso.
fn sondar(
    origem: Instant,
    ate: Instant,
    amostras: &mut Vec<Amostra>,
    mut pedir: impl FnMut() -> Result<String, String>,
) {
    let mut proxima = Instant::now();
    while Instant::now() < ate {
        let saiu = Instant::now();
        let ida_e_volta = pedir().ok().map(|_| saiu.elapsed());
        amostras.push(Amostra {
            saiu: saiu - origem,
            ida_e_volta,
        });
        proxima += PERIODO;
        let agora = Instant::now();
        if proxima > agora {
            std::thread::sleep(proxima - agora);
        } else {
            proxima = agora;
        }
    }
}

/// O resumo de um canal numa janela.
#[derive(Debug, Default)]
struct Resumo {
    respostas: usize,
    erros: usize,
    p50: Duration,
    p99: Duration,
    maior: Duration,
    /// O maior intervalo sem resposta, do começo da janela até `fim` — a
    /// sonda presa conta inteira, mesmo a que saiu antes da janela.
    silencio: Duration,
}

/// O resumo das amostras que saíram em `[de, ate)`; o silêncio, das
/// respostas que chegaram em `[de, fim)`.
fn resumir(amostras: &[Amostra], de: Duration, ate: Duration, fim: Duration) -> Resumo {
    let janela: Vec<&Amostra> = amostras
        .iter()
        .filter(|a| a.saiu >= de && a.saiu < ate)
        .collect();
    let mut idas: Vec<Duration> = janela.iter().filter_map(|a| a.ida_e_volta).collect();
    idas.sort();
    let percentil = |p: usize| {
        idas.get(idas.len().saturating_sub(1) * p / 100)
            .copied()
            .unwrap_or_default()
    };
    let mut chegadas: Vec<Duration> = amostras
        .iter()
        .filter_map(|a| a.ida_e_volta.map(|r| a.saiu + r))
        .filter(|c| *c >= de && *c < fim)
        .collect();
    chegadas.sort();
    let mut silencio = Duration::ZERO;
    let mut antes = de;
    for c in chegadas.iter().copied().chain(std::iter::once(fim)) {
        silencio = silencio.max(c.saturating_sub(antes));
        antes = c;
    }
    Resumo {
        respostas: idas.len(),
        erros: janela.len() - idas.len(),
        p50: percentil(50),
        p99: percentil(99),
        maior: idas.last().copied().unwrap_or_default(),
        silencio,
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

impl std::fmt::Display for Resumo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} respostas ({} erros), ida e volta {:.1}/{:.1}/{:.1} ms (mediana/p99/maior), silencio {:.1} ms",
            self.respostas,
            self.erros,
            ms(self.p50),
            ms(self.p99),
            ms(self.maior),
            ms(self.silencio)
        )
    }
}

/// A sonda do TCP: um fio do hospedeiro com o agente 2, do começo ao fim da
/// bancada.
struct SondaTcp {
    amostras: Arc<Mutex<Vec<Amostra>>>,
    parar: Arc<AtomicBool>,
    fio: std::thread::JoinHandle<Result<(), String>>,
}

impl SondaTcp {
    /// Conecta — o aperto, antes de qualquer carga — e começa a sondar.
    fn ligar(arch: Arquitetura, origem: Instant) -> Result<SondaTcp, String> {
        let amostras = Arc::new(Mutex::new(Vec::new()));
        let parar = Arc::new(AtomicBool::new(false));
        let (pronta, esperar) = mpsc::channel::<Result<(), String>>();
        let (a, p) = (amostras.clone(), parar.clone());
        let fio = std::thread::spawn(move || -> Result<(), String> {
            let conectado = AgenteNaPorta::conectar_tcp(arch, 2).and_then(|agente| {
                agente
                    .fluxo
                    .set_read_timeout(Some(PRAZO))
                    .map_err(|e| format!("disponibilidade: o prazo do TCP: {e}"))?;
                Ok(agente)
            });
            let mut agente = match conectado {
                Ok(agente) => {
                    let _ = pronta.send(Ok(()));
                    agente
                }
                Err(e) => {
                    let _ = pronta.send(Err(e.clone()));
                    return Err(e);
                }
            };
            let mut proxima = Instant::now();
            while !p.load(Ordering::Relaxed) {
                let saiu = Instant::now();
                let ida_e_volta = agente
                    .pedir("agent.ping", "{}")
                    .ok()
                    .map(|_| saiu.elapsed());
                a.lock()
                    .map_err(|_| "disponibilidade: as amostras do TCP".to_string())?
                    .push(Amostra {
                        saiu: saiu - origem,
                        ida_e_volta,
                    });
                proxima += PERIODO;
                let agora = Instant::now();
                if proxima > agora {
                    std::thread::sleep(proxima - agora);
                } else {
                    proxima = agora;
                }
            }
            Ok(())
        });
        esperar
            .recv()
            .map_err(|_| "disponibilidade: a sonda TCP morreu antes do aperto".to_string())??;
        Ok(SondaTcp {
            amostras,
            parar,
            fio,
        })
    }

    fn amostras(&self) -> Vec<Amostra> {
        self.amostras.lock().map(|a| a.to_vec()).unwrap_or_default()
    }

    fn desligar(self) -> Result<(), String> {
        self.parar.store(true, Ordering::Relaxed);
        self.fio
            .join()
            .map_err(|_| "disponibilidade: o fio da sonda TCP morreu".to_string())?
    }
}

/// Uma leitura da barra: quando saiu, desde a origem da bancada; o tempo
/// ligado que o kernel disse logo antes; e o segundo que o relógio da barra
/// mostrava — o que a tarefa `barra` desenhou por último —, se há barra.
#[derive(Clone, Copy, Debug)]
struct AmostraDaBarra {
    saiu: Duration,
    uptime_ms: u64,
    mostrado: Option<u64>,
}

/// O segundo que o relógio da barra mostra numa resposta do `ui.tree`:
/// `ligado h:mm:ss`. `None` sem barra.
fn segundos_da_barra(r: &str) -> Option<u64> {
    let texto = super::apos(r, "\"ligado ")?.split('"').next()?;
    let mut partes = texto.split(':');
    let h: u64 = partes.next()?.parse().ok()?;
    let m: u64 = partes.next()?.parse().ok()?;
    let s: u64 = partes.next()?.parse().ok()?;
    if partes.next().is_some() {
        return None;
    }
    Some(h * 3600 + m * 60 + s)
}

/// O maior atraso do relógio da barra nas leituras que saíram em `[de,
/// ate)`: quantos segundos o relógio desenhado ficou atrás do tempo ligado.
/// Zero ou um é a barra andando — ela redesenha a cada segundo, e a leitura
/// cai em qualquer ponto dele —; mais que isso é a tarefa esperando a vez.
/// `None` sem leitura com a barra.
fn atraso_da_barra(amostras: &[AmostraDaBarra], de: Duration, ate: Duration) -> Option<u64> {
    amostras
        .iter()
        .filter(|a| a.saiu >= de && a.saiu < ate)
        .filter_map(|a| Some((a.uptime_ms / 1000).saturating_sub(a.mostrado?)))
        .max()
}

/// A leitura da barra: um fio do hospedeiro com o agente 4, do começo ao
/// fim da bancada. Só lê — `system.uptime` e `ui.tree` —, nada que a carga
/// ou as sondas usem.
struct SondaDaBarra {
    amostras: Arc<Mutex<Vec<AmostraDaBarra>>>,
    parar: Arc<AtomicBool>,
    fio: std::thread::JoinHandle<Result<(), String>>,
}

impl SondaDaBarra {
    /// Conecta pela porta 4 e começa a ler.
    fn ligar(arch: Arquitetura, origem: Instant) -> Result<SondaDaBarra, String> {
        let amostras = Arc::new(Mutex::new(Vec::new()));
        let parar = Arc::new(AtomicBool::new(false));
        let (pronta, esperar) = mpsc::channel::<Result<(), String>>();
        let (a, p) = (amostras.clone(), parar.clone());
        let fio = std::thread::spawn(move || -> Result<(), String> {
            let conectado = AgenteNaPorta::conectar(arch, PORTA_DA_BARRA).and_then(|agente| {
                agente
                    .fluxo
                    .set_read_timeout(Some(PRAZO))
                    .map_err(|e| format!("disponibilidade: o prazo da porta da barra: {e}"))?;
                Ok(agente)
            });
            let mut agente = match conectado {
                Ok(agente) => {
                    let _ = pronta.send(Ok(()));
                    agente
                }
                Err(e) => {
                    let _ = pronta.send(Err(e.clone()));
                    return Err(e);
                }
            };
            let mut proxima = Instant::now();
            while !p.load(Ordering::Relaxed) {
                let saiu = Instant::now();
                let uptime_ms = numero(&agente.pedir("system.uptime", "{}")?, "uptime_ms");
                let mostrado = segundos_da_barra(&agente.pedir("ui.tree", "{}")?);
                a.lock()
                    .map_err(|_| "disponibilidade: as amostras da barra".to_string())?
                    .push(AmostraDaBarra {
                        saiu: saiu - origem,
                        uptime_ms,
                        mostrado,
                    });
                proxima += PERIODO_DA_BARRA;
                let agora = Instant::now();
                if proxima > agora {
                    std::thread::sleep(proxima - agora);
                } else {
                    proxima = agora;
                }
            }
            Ok(())
        });
        esperar.recv().map_err(|_| {
            "disponibilidade: a leitura da barra morreu antes do aperto".to_string()
        })??;
        Ok(SondaDaBarra {
            amostras,
            parar,
            fio,
        })
    }

    fn amostras(&self) -> Vec<AmostraDaBarra> {
        self.amostras.lock().map(|a| a.to_vec()).unwrap_or_default()
    }

    fn desligar(self) -> Result<(), String> {
        self.parar.store(true, Ordering::Relaxed);
        self.fio
            .join()
            .map_err(|_| "disponibilidade: o fio da leitura da barra morreu".to_string())?
    }
}

/// O que a bancada acompanha do começo ao fim: a sonda do TCP, a leitura da
/// barra — se a porta 4 atendeu — e os pulsos que o log já mostrou, pelo
/// número do registro.
struct Sondas {
    tcp: SondaTcp,
    barra: Option<SondaDaBarra>,
    pulsos: BTreeMap<u64, u64>,
}

/// Um número de uma resposta, pelo primeiro campo com o nome.
fn numero(r: &str, campo: &str) -> u64 {
    campo_simples(r, campo)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Os contadores do kernel que a bancada compara antes e depois.
#[derive(Clone, Copy, Debug, Default)]
struct Contadores {
    pedidos_nativos: u64,
    permitidos: u64,
    pela_taxa: u64,
    avancos: u64,
    perdidos_na_entrada: u64,
}

fn contadores(m: &mut Ligada) -> Result<Contadores, String> {
    let usuario = m.pedir("user.stats", "{}")?;
    let seguranca = m.pedir("security.metrics", "{}")?;
    let tarefas = m.pedir("tasks.stats", "{}")?;
    Ok(Contadores {
        pedidos_nativos: numero(&usuario, "native_requests"),
        permitidos: numero(&seguranca, "ALLOW"),
        pela_taxa: numero(&seguranca, "RATE_LIMIT"),
        avancos: numero(&tarefas, "polls"),
        perdidos_na_entrada: numero(&tarefas, "dropped"),
    })
}

/// O que um filho do `incansavel` disse no fim: `incansavel <fio>: <p>
/// pedidos, <q> respostas, <a> ALLOW, <r> RATE_LIMIT, de <x> a <y> ms`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ContaDoFilho {
    pedidos: u64,
    respostas: u64,
    permitidos: u64,
    pela_taxa: u64,
}

/// O fio e a conta de uma mensagem do log, se ela é a do fim de um filho.
/// As do pai, as de uma falha e a de um filho que não diz as respostas não
/// são.
fn conta_do_filho(mensagem: &str) -> Option<(u64, ContaDoFilho)> {
    let (fio, contas) = mensagem.strip_prefix("incansavel ")?.split_once(": ")?;
    let fio = fio.parse().ok()?;
    let mut c = ContaDoFilho::default();
    let mut vistos = 0;
    for parte in contas.split(", ") {
        let Some((n, nome)) = parte.split_once(' ') else {
            continue;
        };
        let Ok(n) = n.parse::<u64>() else {
            continue;
        };
        let campo = match nome {
            "pedidos" => &mut c.pedidos,
            "respostas" => &mut c.respostas,
            "ALLOW" => &mut c.permitidos,
            "RATE_LIMIT" => &mut c.pela_taxa,
            _ => continue,
        };
        *campo = n;
        vistos += 1;
    }
    (vistos == 4).then_some((fio, c))
}

/// A carga conferida: o que os filhos disseram, e o que o kernel contou
/// além deles.
#[derive(Debug, Default, PartialEq, Eq)]
struct Integridade {
    filhos: usize,
    pedidos: u64,
    permitidos: u64,
    pela_taxa: u64,
    /// As recusas pela taxa além das que os filhos ouviram: a de outro
    /// principal — o agente novo, que num cenário de dois titulares é um
    /// deles, ou o relógio de um pai que esperou a ficha.
    taxa_a_mais: u64,
}

impl std::fmt::Display for Integridade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} filhos, {} pedidos, cada um com a resposta dele ({} ALLOW, {} RATE_LIMIT); o kernel atendeu exatamente esses e o relogio de cada pai, e recusou pela taxa {} a mais",
            self.filhos, self.pedidos, self.permitidos, self.pela_taxa, self.taxa_a_mais
        )
    }
}

/// Confere a carga de `c` pelas contas dos filhos e pelo que o kernel
/// contou no cenário — `nativos`, os pedidos dos processos atendidos
/// (`user.stats`), e `pela_taxa`, as recusas pela taxa (`security.metrics`).
///
/// Todo filho disse a conta e recebeu uma resposta por pedido, ALLOW ou
/// RATE_LIMIT — e cada uma era a do pedido dele: o filho confere o `id` e
/// para na primeira de outro, sem dizer a conta. O kernel atendeu
/// exatamente os pedidos dos filhos e o relógio de cada pai — menos é
/// pedido perdido; mais, um pedido atendido duas vezes, ou o de um processo
/// de fora da carga, que a máquina da bancada não tem —, e recusou pela
/// taxa ao menos o que os filhos ouviram: o agente novo divide o balde com
/// o titular da chave dele, e o relógio de um pai pode esperar a ficha. As
/// recusas a mais ficam ditas.
fn integridade(
    c: Cenario,
    contas: &[(u64, ContaDoFilho)],
    nativos: u64,
    pela_taxa: u64,
) -> Result<Integridade, String> {
    let esperados = (c.filhos * c.titulares) as usize;
    if contas.len() != esperados {
        return Err(format!(
            "disponibilidade: {} filhos disseram a conta, de {esperados}",
            contas.len()
        ));
    }
    let mut i = Integridade {
        filhos: contas.len(),
        ..Integridade::default()
    };
    for (fio, f) in contas {
        if f.respostas != f.pedidos || f.permitidos + f.pela_taxa != f.respostas {
            return Err(format!(
                "disponibilidade: o filho {fio} fez {} pedidos e recebeu {} respostas, {} ALLOW e {} RATE_LIMIT",
                f.pedidos, f.respostas, f.permitidos, f.pela_taxa
            ));
        }
        i.pedidos += f.pedidos;
        i.permitidos += f.permitidos;
        i.pela_taxa += f.pela_taxa;
    }
    let feitos = i.pedidos + c.titulares;
    if nativos != feitos {
        let o_que = if nativos < feitos {
            "pedido perdido"
        } else {
            "pedido atendido duas vezes, ou o de um processo de fora da carga"
        };
        return Err(format!(
            "disponibilidade: o kernel atendeu {nativos} pedidos dos processos, e os filhos e os pais fizeram {feitos}: {o_que}"
        ));
    }
    if pela_taxa < i.pela_taxa {
        return Err(format!(
            "disponibilidade: o kernel recusou {pela_taxa} pela taxa, e os filhos ouviram {} recusas",
            i.pela_taxa
        ));
    }
    i.taxa_a_mais = pela_taxa - i.pela_taxa;
    Ok(i)
}

/// Os registros do pulso numa resposta do `log.tail`: o número e o
/// `uptime_ms` de cada um.
fn pulsos_de(r: &str) -> Vec<(u64, u64)> {
    r.split(r#"{"seq":"#)
        .skip(1)
        .filter(|l| campo_simples(l, "subsystem").as_deref() == Some("pulso"))
        .filter_map(|l| {
            let seq = l
                .split(|c: char| !c.is_ascii_digit())
                .next()?
                .parse()
                .ok()?;
            Some((seq, numero(l, "uptime_ms")))
        })
        .collect()
}

/// O atraso de cada pulso de `pulsos` (o número do registro → o
/// `uptime_ms`) que caiu em `[de, ate)` ms: o intervalo desde o pulso
/// anterior, menos o minuto. O pulso dorme um minuto contado do registro
/// anterior; o resto é o tique, até 10 ms, e a espera pela vez no executor.
/// Dois registros seguidos com mais de um minuto e meio entre eles não são
/// um intervalo: o log deu a volta entre as leituras, e um pulso do meio
/// não foi visto.
fn atrasos_do_pulso(pulsos: &BTreeMap<u64, u64>, de: u64, ate: u64) -> Vec<(u64, u64)> {
    pulsos
        .values()
        .zip(pulsos.values().skip(1))
        .filter(|&(&antes, &agora)| {
            (de..ate).contains(&agora) && agora.saturating_sub(antes) < PULSO_MS * 3 / 2
        })
        .map(|(&antes, &agora)| (agora, agora.saturating_sub(antes).saturating_sub(PULSO_MS)))
        .collect()
}

/// O armazém compartilhado, onde fica o pedido da carga: o disco zerado
/// ainda não o tem. Criado pelo agente 1, o titular da carga.
fn armazem_compartilhado(lancador: &mut AgenteNaPorta) -> Result<(), String> {
    let estado = lancador.pedir("fs.stat", r#"{"path":"/armazem/compartilhado"}"#)?;
    if numero(&estado, "version") > 0 {
        return Ok(());
    }
    let criado = lancador.pedir("fs.mkdir", r#"{"path":"/armazem/compartilhado"}"#)?;
    if !criado.contains(r#""ok":true"#) {
        return Err(format!(
            "disponibilidade: o armazem compartilhado nao foi criado\n  {criado}"
        ));
    }
    Ok(())
}

/// Grava o pedido da carga, como o agente 1, e a lança pela porta de cada
/// titular — a 1 e, com dois, a 3: o mesmo pedido, que cada pai lê.
fn lancar(lancadores: &mut [AgenteNaPorta], arch: Arquitetura, c: Cenario) -> Result<(), String> {
    let titulares = c.titulares as usize;
    if lancadores.len() < titulares {
        return Err(format!(
            "disponibilidade: {titulares} titulares, e {} portas para lancar",
            lancadores.len()
        ));
    }
    let primeiro = &mut lancadores[0];
    let estado = primeiro.pedir("fs.stat", &format!(r#"{{"path":"{PEDIDO}"}}"#))?;
    let versao = numero(&estado, "version");
    let modo = if c.girar { "girar" } else { "pedir" };
    let gravado = primeiro.pedir(
        "fs.write",
        &format!(
            r#"{{"path":"{PEDIDO}","content":"processos {}\nduracao_ms {}\nmodo {modo}\n","expect_version":{versao}}}"#,
            c.filhos,
            CARGA.as_millis()
        ),
    )?;
    if !gravado.contains(r#""ok":true"#) {
        return Err(format!(
            "disponibilidade: o pedido da carga nao gravou\n  {gravado}"
        ));
    }
    for lancador in lancadores.iter_mut().take(titulares) {
        let lancado = lancador.pedir(
            "user.run",
            &format!(r#"{{"path":"/programas/{}/incansavel"}}"#, arch.nome()),
        )?;
        if !lancado.contains(r#""launched":true"#) {
            return Err(format!(
                "disponibilidade: o user.run nao lancou a carga\n  {lancado}"
            ));
        }
    }
    Ok(())
}

/// A mensagem de um registro do `log.tail`, ainda escapada: até a aspa que
/// a fecha — ela tem vírgulas, e o `campo_simples` pararia na primeira.
fn mensagem(registro: &str) -> Option<&str> {
    let resto = super::apos(registro, r#""message":""#)?;
    let b = resto.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some(&resto[..i]),
            _ => i += 1,
        }
    }
    None
}

/// Quantos registros o log já teve: os de um cenário são os de depois.
fn total_do_log(m: &mut Ligada) -> Result<u64, String> {
    Ok(numero(
        &m.pedir("log.tail", r#"{"count":1}"#)?,
        "total_emitted",
    ))
}

/// As linhas do log de número `desde` em diante que são da carga ou da
/// medida temporária: o uptime e a mensagem.
fn linhas_do_log(m: &mut Ligada, desde: u64) -> Result<Vec<String>, String> {
    Ok(linhas_de(&m.pedir("log.tail", r#"{"count":128}"#)?, desde))
}

/// As linhas de uma resposta do `log.tail` — ver [`linhas_do_log`].
fn linhas_de(r: &str, desde: u64) -> Vec<String> {
    r.split(r#"{"seq":"#)
        .skip(1)
        .filter(|l| {
            l.split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                .is_some_and(|seq| seq >= desde)
        })
        .filter(|l| {
            mensagem(l).is_some_and(|msg| msg.contains(CARGA_NO_LOG))
                || campo_simples(l, "subsystem").as_deref() == Some(MEDIDA_NO_LOG)
        })
        .filter_map(|l| mensagem(l).map(|msg| format!("{} ms: {msg}", numero(l, "uptime_ms"))))
        .collect()
}

/// Espera a carga acabar: o pai de cada titular diz que os filhos
/// acabaram, ou um diz que algo deu errado.
fn esperar_o_fim(m: &mut Ligada, desde: u64, c: Cenario) -> Result<Vec<String>, String> {
    let limite = Instant::now() + Duration::from_secs(60);
    let fim = format!("incansavel: os {} filhos acabaram", c.filhos);
    // As linhas de uma carga que anda: o pai que bifurcou, cada filho que
    // acabou, e o fim. Qualquer outra do `incansavel` é a falha dele.
    let normal =
        |l: &str| l.contains(" filhos, modo ") || l.contains(" pedidos, ") || l.contains(&fim);
    loop {
        let linhas = linhas_do_log(m, desde)?;
        if linhas.iter().filter(|l| l.contains(&fim)).count() as u64 >= c.titulares {
            return Ok(linhas);
        }
        if linhas
            .iter()
            .any(|l| l.contains("incansavel") && !normal(l))
        {
            return Err(format!(
                "disponibilidade: a carga falhou\n  {}",
                linhas.join("\n  ")
            ));
        }
        if Instant::now() >= limite {
            return Err(format!(
                "disponibilidade: a carga nao acabou um minuto depois do fim marcado\n  {}",
                linhas.join("\n  ")
            ));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Acrescenta a `DUKE_AMOSTRAS`, se pedido, as sondas do cenário que
/// saíram de `de` até `ate` — uma linha cada: o cenário, o canal, quando
/// saiu e a ida e volta (vazia, se o canal devolveu erro), em ms desde a
/// origem —, e a do lançamento, em `lancamento`.
fn gravar_amostras(
    c: Cenario,
    de: Duration,
    lancamento: Duration,
    ate: Duration,
    canais: &[(&str, &Vec<Amostra>)],
) -> Result<(), String> {
    let Ok(caminho) = std::env::var("DUKE_AMOSTRAS") else {
        return Ok(());
    };
    let nome = c.nome();
    let mut texto = format!("{nome},lancamento,{:.1},\n", ms(lancamento));
    for (canal, amostras) in canais {
        for a in amostras.iter().filter(|a| a.saiu >= de && a.saiu < ate) {
            let volta = a.ida_e_volta.map(|d| format!("{:.1}", ms(d)));
            texto.push_str(&format!(
                "{nome},{canal},{:.1},{}\n",
                ms(a.saiu),
                volta.unwrap_or_default()
            ));
        }
    }
    use std::io::Write;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&caminho)
        .and_then(|mut f| f.write_all(texto.as_bytes()))
        .map_err(|e| format!("disponibilidade: DUKE_AMOSTRAS em {caminho}: {e}"))
}

/// Um cenário inteiro: a referência, a carga, o depois, e o que se viu.
fn cenario(
    m: &mut Ligada,
    lancadores: &mut [AgenteNaPorta],
    sondas: &mut Sondas,
    arch: Arquitetura,
    origem: Instant,
    c: Cenario,
) -> Result<(), String> {
    println!("[xtask] disponibilidade: {}", c.nome());
    let antes = contadores(m)?;
    let desde = total_do_log(m)?;
    let inicio = Instant::now();
    let mut serial = Vec::new();
    sondar(origem, inicio + ANTES, &mut serial, || {
        m.pedir("agent.ping", "{}")
    });
    // O tempo ligado no lançamento: a régua do pulso, que o log mede nele.
    let ligado_ms = numero(&m.pedir("system.uptime", "{}")?, "uptime_ms");
    let lancamento = Instant::now();
    if c.filhos > 0 {
        lancar(lancadores, arch, c)?;
    }
    let entrada = std::thread::spawn(move || {
        std::thread::sleep(ENTRADA_DEPOIS);
        let tentou = Instant::now();
        let r = AgenteNaPorta::conectar_tcp(arch, 3)
            .and_then(|mut novo| novo.pedir("agent.ping", "{}"))
            .map(|_| ());
        (tentou.elapsed(), r)
    });
    sondar(origem, lancamento + CARGA + DEPOIS, &mut serial, || {
        m.pedir("agent.ping", "{}")
    });
    let (entrou_em, entrou) = entrada
        .join()
        .map_err(|_| "disponibilidade: o fio da entrada morreu".to_string())?;
    let linhas = if c.filhos > 0 {
        esperar_o_fim(m, desde, c)?
    } else {
        linhas_do_log(m, desde)?
    };
    let depois = contadores(m)?;
    // Os pulsos que o log ainda mostra, e se ele deu a volta desde o
    // começo do cenário: então uma linha da carga pode ter saído dele.
    let cauda = m.pedir("log.tail", &format!(r#"{{"count":{ANEL_DO_LOG}}}"#))?;
    for (seq, uptime_ms) in pulsos_de(&cauda) {
        sondas.pulsos.insert(seq, uptime_ms);
    }
    let deu_a_volta = numero(&cauda, "total_emitted").saturating_sub(desde) > ANEL_DO_LOG;

    let (i, l) = (inicio - origem, lancamento - origem);
    let (fim_da_carga, fim) = (l + CARGA, l + CARGA + DEPOIS);
    let tcp = sondas.tcp.amostras();
    for (canal, amostras) in [("serial", &serial), ("tcp", &tcp)] {
        println!("  [{canal}] antes:   {}", resumir(amostras, i, l, l));
        println!(
            "  [{canal}] durante: {}",
            resumir(
                amostras,
                l,
                fim_da_carga,
                fim_da_carga + Duration::from_secs(5)
            )
        );
        println!(
            "  [{canal}] depois:  {}",
            resumir(amostras, fim_da_carga + Duration::from_secs(2), fim, fim)
        );
    }
    gravar_amostras(c, i, l, fim, &[("serial", &serial), ("tcp", &tcp)])?;
    println!(
        "  [entrada] o agente 3 pelo TCP, {:.1} s depois do lancamento: {} em {:.1} s{}",
        ENTRADA_DEPOIS.as_secs_f64(),
        match &entrou {
            Ok(()) => "entrou".to_string(),
            Err(e) => format!("nao entrou ({e})"),
        },
        entrou_em.as_secs_f64(),
        if c.titulares > 1 && c.filhos > 0 {
            " (titular da carga tambem: o primeiro pedido pode ouvir RATE_LIMIT)"
        } else {
            ""
        }
    );
    // As outras tarefas do executor: o pulso, pelo log, e a barra, pelo
    // relógio dela.
    let carga_ms = CARGA.as_millis() as u64;
    let atrasos = atrasos_do_pulso(
        &sondas.pulsos,
        ligado_ms.saturating_sub(ANTES.as_millis() as u64),
        ligado_ms + carga_ms + DEPOIS.as_millis() as u64,
    );
    if atrasos.is_empty() {
        println!("  [pulso] nenhum pulso visto no cenario (um por minuto)");
    }
    for (em, atraso) in atrasos {
        let na_carga = (ligado_ms..ligado_ms + carga_ms).contains(&em);
        println!(
            "  [pulso] em {em} ms, {atraso} ms depois do minuto{}",
            if na_carga { " (na carga)" } else { "" }
        );
    }
    match &sondas.barra {
        Some(barra) => {
            let amostras = barra.amostras();
            let atraso = |de, ate| match atraso_da_barra(&amostras, de, ate) {
                Some(s) => format!("{s} s"),
                None => "sem leitura".to_string(),
            };
            println!(
                "  [barra] o relogio desenhado atras do tempo ligado, no maximo: antes {}, durante {}, depois {}",
                atraso(i, l),
                atraso(l, fim_da_carga),
                atraso(fim_da_carga, fim)
            );
        }
        None => println!("  [barra] sem a leitura da barra"),
    }
    if c.filhos > 0 {
        let contas: Vec<(u64, ContaDoFilho)> = linhas
            .iter()
            .filter_map(|l| conta_do_filho(l.split_once(" ms: ")?.1))
            .collect();
        if deu_a_volta && contas.len() as u64 != c.filhos * c.titulares {
            println!(
                "  [integridade] nao conferida: o log deu a volta no cenario, e so {} filhos ainda dizem a conta",
                contas.len()
            );
        } else {
            let conferida = integridade(
                c,
                &contas,
                depois.pedidos_nativos.saturating_sub(antes.pedidos_nativos),
                depois.pela_taxa.saturating_sub(antes.pela_taxa),
            )?;
            println!("  [integridade] {conferida}");
        }
    }
    let segundos = CARGA.as_secs_f64();
    println!(
        "  [kernel] {:.0} pedidos dos processos/s; {:.0} ALLOW/s e {:.0} RATE_LIMIT/s no gate (todos os titulares); {} avancos do executor; {} bytes perdidos na entrada",
        depois.pedidos_nativos.saturating_sub(antes.pedidos_nativos) as f64 / segundos,
        depois.permitidos.saturating_sub(antes.permitidos) as f64 / segundos,
        depois.pela_taxa.saturating_sub(antes.pela_taxa) as f64 / segundos,
        depois.avancos.saturating_sub(antes.avancos),
        depois
            .perdidos_na_entrada
            .saturating_sub(antes.perdidos_na_entrada)
    );
    for linha in linhas {
        println!("  [log] {linha}");
    }
    Ok(())
}

/// `cargo xtask disponibilidade`: os cenários, um depois do outro, numa
/// máquina só.
pub(crate) fn disponibilidade(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    let lista = cenarios()?;
    let repeticoes: usize = std::env::var("DUKE_REPETICOES")
        .ok()
        .and_then(|r| r.parse().ok())
        .unwrap_or(1);
    let artefato = build(arch, release, false)?;
    let _ = super::persistencia::SERIAL_DA_BANCADA
        .set(super::raiz_do_estado().join(format!("disponibilidade-{}.serial", arch.nome())));
    zerar_o_estado(arch)?;
    let mut m = Ligada::subir(arch, &artefato, None)?;
    let resultado = (|| -> Result<(), String> {
        m.esperar_respostas_por(PRAZO)?;
        // O TCP só atende com o endereço do DHCP.
        let limite = Instant::now() + Duration::from_secs(60);
        loop {
            let info = m.pedir("net.info", "{}")?;
            if info.contains(r#""address":"10.0.2.15/24""#) {
                break;
            }
            if Instant::now() >= limite {
                return Err(format!(
                    "disponibilidade: o DHCP nao deu endereco\n  {info}"
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let origem = Instant::now();
        // A porta de cada titular da carga: a 1 e, se um cenário tem dois,
        // a 3.
        let mut portas = vec![1];
        if lista.iter().any(|c| c.titulares > 1) {
            portas.push(PORTA_DO_SEGUNDO);
        }
        let mut lancadores = Vec::new();
        for porta in portas {
            let lancador = AgenteNaPorta::conectar(arch, porta)?;
            lancador
                .fluxo
                .set_read_timeout(Some(PRAZO))
                .map_err(|e| format!("disponibilidade: o prazo da porta {porta}: {e}"))?;
            lancadores.push(lancador);
        }
        armazem_compartilhado(&mut lancadores[0])?;
        let tcp = SondaTcp::ligar(arch, origem)?;
        // A barra é lida se a porta 4 atende; sem ela, o resto mede igual.
        let barra = match SondaDaBarra::ligar(arch, origem) {
            Ok(barra) => Some(barra),
            Err(e) => {
                println!("[xtask] disponibilidade: sem a leitura da barra ({e})");
                None
            }
        };
        let mut sondas = Sondas {
            tcp,
            barra,
            pulsos: BTreeMap::new(),
        };
        let mut feitos = Ok(());
        'repeticoes: for r in 0..repeticoes {
            println!(
                "[xtask] disponibilidade: rodada {} de {repeticoes} ({})",
                r + 1,
                arch.nome()
            );
            for c in &lista {
                if let Err(e) = cenario(&mut m, &mut lancadores, &mut sondas, arch, origem, *c) {
                    feitos = Err(e);
                    break 'repeticoes;
                }
            }
        }
        sondas.tcp.desligar()?;
        if let Some(barra) = sondas.barra
            && let Err(e) = barra.desligar()
        {
            println!("[xtask] disponibilidade: a leitura da barra parou ({e})");
        }
        feitos
    })();
    let corte = m.cortar_a_energia();
    resultado?;
    corte?;
    if let Some(serial) = super::persistencia::serial_do_cenario() {
        println!(
            "[xtask] disponibilidade: o log inteiro, com o uptime, em {}",
            serial.display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod testes {
    use super::*;

    fn ms_(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Sondas de `PERIODO` em `PERIODO`, de `de` até `ate`, cada uma com a
    /// ida e volta `volta`.
    fn regulares(de: u64, ate: u64, volta: u64) -> Vec<Amostra> {
        (de..ate)
            .step_by(PERIODO.as_millis() as usize)
            .map(|t| Amostra {
                saiu: ms_(t),
                ida_e_volta: Some(ms_(volta)),
            })
            .collect()
    }

    #[test]
    fn os_cenarios_do_texto() {
        let c = cenarios_de("0, g3,1,2,3,0").unwrap();
        let resumo: Vec<(u64, bool)> = c.iter().map(|c| (c.filhos, c.girar)).collect();
        assert_eq!(
            resumo,
            [
                (0, false),
                (3, true),
                (1, false),
                (2, false),
                (3, false),
                (0, false)
            ]
        );
        assert_eq!(c[1].nome(), "girar x3");
        assert_eq!(c[0].nome(), "sem carga");
        assert!(c.iter().all(|c| c.titulares == 1));
        assert!(cenarios_de("7").is_ok());
        assert!(cenarios_de("8").unwrap_err().contains("passa de 7 filhos"));
        assert!(cenarios_de("g8").unwrap_err().contains("passa de 7 filhos"));
        assert!(cenarios_de("x").unwrap_err().contains("nao e N nem gN"));
        assert!(cenarios_de("1,,2").is_err());
    }

    /// `N:2` e `gN:2`: os mesmos filhos em cada um de dois titulares — e
    /// só um ou dois, os agentes 1 e 3; o teto de filhos é o de cada um.
    #[test]
    fn os_cenarios_de_dois_titulares() {
        let c = cenarios_de("2:2, g1:2,3:1").unwrap();
        let resumo: Vec<(u64, bool, u64)> =
            c.iter().map(|c| (c.filhos, c.girar, c.titulares)).collect();
        assert_eq!(resumo, [(2, false, 2), (1, true, 2), (3, false, 1)]);
        assert_eq!(c[0].nome(), "pedir x2 em 2 titulares");
        assert_eq!(c[1].nome(), "girar x1 em 2 titulares");
        assert_eq!(c[2].nome(), "pedir x3");
        for errado in ["2:3", "2:0", "2:x", "2:"] {
            assert!(
                cenarios_de(errado).unwrap_err().contains("titulares"),
                "{errado}"
            );
        }
        assert!(
            cenarios_de("8:2")
                .unwrap_err()
                .contains("passa de 7 filhos")
        );
        assert!(cenarios_de("x:2").unwrap_err().contains("nao e N nem gN"));
    }

    /// A linha do fim de um filho do `incansavel`; as do pai, a da falha e a
    /// de um filho que não diz as respostas não são a conta de um filho.
    #[test]
    fn a_conta_de_um_filho() {
        assert_eq!(
            conta_do_filho(
                "incansavel 57: 120 pedidos, 120 respostas, 20 ALLOW, 100 RATE_LIMIT, de 10 a 20 ms"
            ),
            Some((
                57,
                ContaDoFilho {
                    pedidos: 120,
                    respostas: 120,
                    permitidos: 20,
                    pela_taxa: 100
                }
            ))
        );
        for outra in [
            "incansavel: 2 filhos, modo pedir, de 1 a 2 ms",
            "incansavel: os 2 filhos acabaram",
            "incansavel 57: a resposta do pedido 9 veio com o id Some(8)",
            "incansavel 57: ouviu DENY_CONTAINED (-32003)",
            "incansavel 57: 120 pedidos, 20 ALLOW, 100 RATE_LIMIT, de 10 a 20 ms",
        ] {
            assert_eq!(conta_do_filho(outra), None, "{outra}");
        }
    }

    /// A conferência da carga: as contas dos filhos contra as do kernel.
    #[test]
    fn a_integridade_da_carga() {
        let c = Cenario {
            filhos: 2,
            girar: false,
            titulares: 2,
        };
        let f = |pedidos: u64, permitidos: u64| ContaDoFilho {
            pedidos,
            respostas: pedidos,
            permitidos,
            pela_taxa: pedidos - permitidos,
        };
        let contas = [(1, f(10, 2)), (2, f(20, 5)), (3, f(30, 3)), (4, f(40, 4))];
        // Cem pedidos dos filhos e o relógio de cada pai: 102.
        let i = integridade(c, &contas, 102, 86).unwrap();
        assert_eq!(
            (i.filhos, i.pedidos, i.permitidos, i.pela_taxa),
            (4, 100, 14, 86)
        );
        assert_eq!(i.taxa_a_mais, 0);
        // As recusas pela taxa além das que os filhos ouviram ficam ditas, e
        // não reprovam: o agente novo divide o balde.
        let i = integridade(c, &contas, 102, 87).unwrap();
        assert_eq!(i.taxa_a_mais, 1);
        // Mais pedidos atendidos que os processos fizeram: um atendido duas
        // vezes.
        assert!(
            integridade(c, &contas, 103, 86)
                .unwrap_err()
                .contains("duas vezes")
        );
        // Menos pedidos atendidos que os processos fizeram: perdido.
        assert!(
            integridade(c, &contas, 101, 86)
                .unwrap_err()
                .contains("perdido")
        );
        // Menos recusas pela taxa que as que os filhos ouviram.
        assert!(integridade(c, &contas, 102, 85).is_err());
        // Um filho que não disse a conta: morreu antes de dizê-la (com o log
        // que deu a volta, a bancada nem chama a conferência).
        assert!(
            integridade(c, &contas[..3], 102, 86)
                .unwrap_err()
                .contains("3 filhos")
        );
        // Um pedido sem resposta: as que vieram, uma a menos que os pedidos,
        // todas ALLOW ou RATE_LIMIT — só a conta das respostas contra a dos
        // pedidos o pega.
        let mut sem = contas;
        sem[1].1.respostas = 19;
        sem[1].1.pela_taxa = 14;
        assert!(
            integridade(c, &sem, 102, 86)
                .unwrap_err()
                .contains("o filho 2")
        );
        // Uma resposta que não foi ALLOW nem RATE_LIMIT — a de outro pedido,
        // que o filho conta e com que para.
        let mut outra = contas;
        outra[2].1.permitidos = 2;
        assert!(
            integridade(c, &outra, 102, 86)
                .unwrap_err()
                .contains("o filho 3")
        );
    }

    /// Os pulsos do log, e o atraso de cada um sobre o minuto.
    #[test]
    fn os_pulsos_do_log() {
        let r = concat!(
            r#"{"records":["#,
            r#"{"seq":3,"uptime_ms":60010,"level":"debug","subsystem":"pulso","message":"vivo ha 60010 ms"},"#,
            r#"{"seq":4,"uptime_ms":61000,"level":"info","subsystem":"agent","message":"o pulso de outro"},"#,
            r#"{"seq":9,"uptime_ms":120350,"level":"debug","subsystem":"pulso","message":"vivo ha 120350 ms"},"#,
            r#"{"seq":15,"uptime_ms":240400,"level":"debug","subsystem":"pulso","message":"vivo ha 240400 ms"}"#,
            r#"],"total_emitted":15}"#
        );
        let pulsos: BTreeMap<u64, u64> = pulsos_de(r).into_iter().collect();
        assert_eq!(pulsos.len(), 3);
        // De 60,01 s a 120,35 s: 340 ms além do minuto. De 120,35 s a
        // 240,4 s há um pulso que o log não mostrou: não é intervalo.
        assert_eq!(atrasos_do_pulso(&pulsos, 0, u64::MAX), [(120_350, 340)]);
        // Só os que caíram na janela.
        assert!(atrasos_do_pulso(&pulsos, 0, 120_350).is_empty());
    }

    /// O relógio da barra no `ui.tree`, e o atraso dele sobre o tempo
    /// ligado.
    #[test]
    fn o_relogio_da_barra() {
        let r = r#"{"result":{"children":[{"id":5,"role":"text","label":"tempo ligado","value":"ligado 1:02:03","children":[]}]}}"#;
        assert_eq!(segundos_da_barra(r), Some(3723));
        assert_eq!(segundos_da_barra(r#"{"result":{"children":[]}}"#), None);
        assert_eq!(segundos_da_barra(r#""value":"ligado 1:02""#), None);
        let a = |saiu: u64, uptime_ms: u64, mostrado: Option<u64>| AmostraDaBarra {
            saiu: ms_(saiu),
            uptime_ms,
            mostrado,
        };
        let amostras = [
            a(0, 10_500, Some(10)),
            a(500, 11_000, Some(10)),
            a(1_000, 13_900, Some(11)),
            a(1_500, 14_200, None),
            a(1_600, 15_000, Some(16)),
        ];
        // Treze segundos ligados com o relógio em onze: dois atrás. O
        // relógio redesenhado entre as duas leituras não fica à frente.
        assert_eq!(atraso_da_barra(&amostras, ms_(0), ms_(2_000)), Some(2));
        assert_eq!(atraso_da_barra(&amostras, ms_(0), ms_(1_000)), Some(1));
        assert_eq!(atraso_da_barra(&amostras, ms_(1_600), ms_(2_000)), Some(0));
        // Sem barra, nada.
        assert_eq!(atraso_da_barra(&amostras, ms_(1_500), ms_(1_600)), None);
    }

    /// Sem carga: a mediana, o p99 e o maior são os da janela, e o silêncio
    /// é o período.
    #[test]
    fn o_resumo_de_um_canal_tranquilo() {
        let mut a = regulares(0, 10_000, 5);
        a[100].ida_e_volta = Some(ms_(30));
        let r = resumir(&a, ms_(0), ms_(10_000), ms_(10_000));
        assert_eq!((r.respostas, r.erros), (200, 0));
        assert_eq!(r.p50, ms_(5));
        assert_eq!(r.maior, ms_(30));
        assert_eq!(r.p99, ms_(5), "um só ponto fora não é o p99 de 200");
        // A resposta lenta abre um intervalo de 30 + 50 - 5 = 75 ms.
        assert_eq!(r.silencio, ms_(75));
    }

    /// A mediana e o p99 pelo índice: de 100 idas e voltas de 1 a 100 ms, a
    /// 50ª e a 99ª.
    #[test]
    fn a_mediana_e_o_p99_pelo_indice() {
        let a: Vec<Amostra> = (1..=100)
            .map(|i| Amostra {
                saiu: ms_(i * 50),
                ida_e_volta: Some(ms_(i)),
            })
            .collect();
        let r = resumir(&a, ms_(0), ms_(10_000), ms_(10_000));
        assert_eq!((r.p50, r.p99, r.maior), (ms_(50), ms_(99), ms_(100)));
    }

    /// A sonda presa conta: a que saiu antes da janela e só voltou dentro
    /// dela abre o silêncio desde o começo da janela, sem entrar na ida e
    /// volta da janela, que é das que saíram nela.
    #[test]
    fn a_sonda_presa_antes_da_janela_conta_no_silencio() {
        let mut a = regulares(0, 9_990, 5);
        a.push(Amostra {
            saiu: ms_(9_990),
            ida_e_volta: Some(ms_(3_000)),
        });
        a.extend(regulares(12_990, 20_000, 5));
        let r = resumir(&a, ms_(10_000), ms_(20_000), ms_(20_000));
        assert_eq!(r.silencio, ms_(2_990), "de 10 s até a volta em 12,99 s");
        assert_eq!(r.maior, ms_(5), "a presa saiu antes da janela");
        // A mesma sonda, dentro da janela, entra na ida e volta.
        let r = resumir(&a, ms_(9_000), ms_(20_000), ms_(20_000));
        assert_eq!(r.maior, ms_(3_000));
        // E o silêncio vai da última resposta antes dela, em 9,955 s.
        assert_eq!(r.silencio, ms_(12_990 - 9_955));
    }

    /// O fim da janela fecha o silêncio: um canal que parou de responder
    /// no meio dela conta até o fim, e as sondas com erro não são respostas.
    #[test]
    fn o_canal_que_para_conta_ate_o_fim() {
        let mut a = regulares(0, 5_000, 5);
        a.push(Amostra {
            saiu: ms_(5_000),
            ida_e_volta: None,
        });
        let r = resumir(&a, ms_(0), ms_(10_000), ms_(10_000));
        assert_eq!(r.erros, 1);
        assert_eq!(r.respostas, 100);
        assert_eq!(r.silencio, ms_(10_000) - ms_(4_955));
    }

    #[test]
    fn a_mensagem_vai_ate_a_aspa_que_fecha() {
        let r = r#"{"seq":7,"uptime_ms":10,"message":"a, \"b\" c","x":1}"#;
        assert_eq!(mensagem(r), Some(r#"a, \"b\" c"#));
        assert_eq!(mensagem(r#"{"seq":7,"message":"sem fim"#), None);
    }

    /// Do `log.tail`, só as linhas a partir de `desde` que são da carga
    /// (pela mensagem) ou da medida temporária (pelo subsistema).
    #[test]
    fn as_linhas_do_log_da_carga_e_da_medida() {
        let r = concat!(
            r#"{"records":["#,
            r#"{"seq":9,"uptime_ms":90,"level":"info","subsystem":"usuario","message":"incansavel: velha"},"#,
            r#"{"seq":10,"uptime_ms":100,"level":"info","subsystem":"usuario","message":"incansavel: 2 filhos, modo pedir"},"#,
            r#"{"seq":11,"uptime_ms":110,"level":"info","subsystem":"agent","message":"outra coisa"},"#,
            r#"{"seq":12,"uptime_ms":120,"level":"warn","subsystem":"medida","message":"avanco de programas: 5 us"},"#,
            r#"{"seq":13,"uptime_ms":130,"level":"warn","subsystem":"usuario","message":"medida falsa no texto"}"#,
            r#"],"total_emitted":13}"#
        );
        assert_eq!(
            linhas_de(r, 10),
            [
                "100 ms: incansavel: 2 filhos, modo pedir",
                "120 ms: avanco de programas: 5 us"
            ]
        );
    }
}
