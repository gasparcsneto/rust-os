//! A bancada da disponibilidade: quanto os pedidos dos processos de um
//! titular seguram o executor do kernel — e, com ele, o canal do agente de
//! todos os outros. É a medida da observação sobre
//! `nativo::atender_pendentes`, que atende a fila dos pedidos dos processos
//! até esvaziá-la, numa tarefa que divide o executor com o canal.
//!
//! # O que faz
//!
//! Sobe a máquina de produção — o kernel sem `modo-teste`: o executor de
//! verdade, com a tarefa `programas` ao lado das do canal — e, em cada
//! cenário:
//!
//! - sonda o canal de dois titulares que não são o da carga, um pedido de
//!   cada vez, de [`PERIODO`] em [`PERIODO`]: a serial (o `sistema`) e o TCP
//!   (a chave do agente 2); e, logo depois de a carga começar, um agente
//!   novo tenta entrar pelo TCP (a chave do agente 3) e fazer o primeiro
//!   pedido — o aperto também é atendido no executor, o da conexão que
//!   não o completa em dez segundos cai, e é o primeiro pedido que confirma
//!   a chave do aperto ao kernel;
//! - lança pela porta 1 — o agente 1, `operador`, o titular da carga —,
//!   pelo `user.run` de sempre, o programa `incansavel`, com o pedido
//!   gravado no armazém: quantos filhos, por quanto tempo, que modo
//!   (`pedir`, a carga; `girar`, o controle sem fila);
//! - lê, antes e depois, os contadores que o kernel já publica:
//!   `user.stats` (os pedidos dos processos atendidos), `security.metrics`
//!   (as decisões por código) e `tasks.stats` (os avanços do executor e os
//!   bytes perdidos na entrada);
//! - e mostra o que a carga — e a medida temporária, se o kernel a tiver —
//!   disse no log.
//!
//! Diz, por cenário e por canal, a ida e volta das sondas antes, durante e
//! depois da carga — mediana, p99 e maior — e o maior silêncio do canal: o
//! maior intervalo sem resposta nenhuma.
//!
//! # Só mede
//!
//! Nada aqui reprova pelo número: o número é o resultado. É erro só a
//! máquina que não sobe, a carga que não é lançada, ou a que não acaba.
//!
//! `DUKE_CARGA` escolhe os cenários, separados por vírgula: `0` é nenhuma
//! carga, `N` são N filhos pedindo, `gN` são N filhos girando. O padrão é
//! [`CENARIOS`]. `DUKE_REPETICOES` repete a lista inteira. `DUKE_AMOSTRAS`,
//! um caminho, acrescenta a ele cada sonda de cada cenário — o cenário, o
//! canal, quando saiu e a ida e volta, em ms desde a origem da bancada — e
//! o instante do lançamento, para ver quando o canal parou.

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

/// Um cenário: quantos filhos, e se pedem ou giram. Zero filhos é a
/// referência, sem carga.
#[derive(Clone, Copy, Debug)]
struct Cenario {
    filhos: u64,
    girar: bool,
}

impl Cenario {
    fn nome(self) -> String {
        match (self.filhos, self.girar) {
            (0, _) => "sem carga".to_string(),
            (n, false) => format!("pedir x{n}"),
            (n, true) => format!("girar x{n}"),
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
            let (girar, n) = match c.strip_prefix('g') {
                Some(n) => (true, n),
                None => (false, c),
            };
            let filhos: u64 = n
                .parse()
                .map_err(|_| format!("DUKE_CARGA: `{c}` nao e N nem gN"))?;
            if filhos > 7 {
                return Err(format!(
                    "DUKE_CARGA: `{c}` passa de 7 filhos, a cota do operador com o pai"
                ));
            }
            Ok(Cenario { filhos, girar })
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

/// Grava o pedido da carga e a lança pela porta 1, como o agente 1.
fn lancar(lancador: &mut AgenteNaPorta, arch: Arquitetura, c: Cenario) -> Result<(), String> {
    let estado = lancador.pedir("fs.stat", &format!(r#"{{"path":"{PEDIDO}"}}"#))?;
    let versao = numero(&estado, "version");
    let modo = if c.girar { "girar" } else { "pedir" };
    let gravado = lancador.pedir(
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
    let lancado = lancador.pedir(
        "user.run",
        &format!(r#"{{"path":"/programas/{}/incansavel"}}"#, arch.nome()),
    )?;
    if !lancado.contains(r#""launched":true"#) {
        return Err(format!(
            "disponibilidade: o user.run nao lancou a carga\n  {lancado}"
        ));
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

/// Espera a carga acabar: o pai diz que os filhos acabaram, ou que algo
/// deu errado.
fn esperar_o_fim(m: &mut Ligada, desde: u64, c: Cenario) -> Result<Vec<String>, String> {
    let limite = Instant::now() + Duration::from_secs(60);
    let fim = format!("incansavel: os {} filhos acabaram", c.filhos);
    // As linhas de uma carga que anda: o pai que bifurcou, cada filho que
    // acabou, e o fim. Qualquer outra do `incansavel` é a falha dele.
    let normal =
        |l: &str| l.contains(" filhos, modo ") || l.contains(" pedidos, ") || l.contains(&fim);
    loop {
        let linhas = linhas_do_log(m, desde)?;
        if linhas.iter().any(|l| l.contains(&fim)) {
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
    lancador: &mut AgenteNaPorta,
    tcp: &SondaTcp,
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
    let lancamento = Instant::now();
    if c.filhos > 0 {
        lancar(lancador, arch, c)?;
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

    let (i, l) = (inicio - origem, lancamento - origem);
    let (fim_da_carga, fim) = (l + CARGA, l + CARGA + DEPOIS);
    let tcp = tcp.amostras();
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
        "  [entrada] o agente 3 pelo TCP, {:.1} s depois do lancamento: {} em {:.1} s",
        ENTRADA_DEPOIS.as_secs_f64(),
        match &entrou {
            Ok(()) => "entrou".to_string(),
            Err(e) => format!("nao entrou ({e})"),
        },
        entrou_em.as_secs_f64()
    );
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
        let mut lancador = AgenteNaPorta::conectar(arch, 1)?;
        lancador
            .fluxo
            .set_read_timeout(Some(PRAZO))
            .map_err(|e| format!("disponibilidade: o prazo da porta 1: {e}"))?;
        armazem_compartilhado(&mut lancador)?;
        let tcp = SondaTcp::ligar(arch, origem)?;
        let mut feitos = Ok(());
        'repeticoes: for r in 0..repeticoes {
            println!(
                "[xtask] disponibilidade: rodada {} de {repeticoes} ({})",
                r + 1,
                arch.nome()
            );
            for c in &lista {
                if let Err(e) = cenario(&mut m, &mut lancador, &tcp, arch, origem, *c) {
                    feitos = Err(e);
                    break 'repeticoes;
                }
            }
        }
        tcp.desligar()?;
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
        assert!(cenarios_de("7").is_ok());
        assert!(cenarios_de("8").unwrap_err().contains("passa de 7 filhos"));
        assert!(cenarios_de("g8").unwrap_err().contains("passa de 7 filhos"));
        assert!(cenarios_de("x").unwrap_err().contains("nao e N nem gN"));
        assert!(cenarios_de("1,,2").is_err());
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
