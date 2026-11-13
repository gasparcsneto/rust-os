//! A bancada dos fluxos da malha: `cargo xtask fluxo`.
//!
//! Duas máquinas de pé ao mesmo tempo — cada uma com o disco, o TPM e a
//! chave do Duke dela —, ligadas como na bancada do enlace: a origem conecta
//! a `10.0.2.100:7071`, o `guestfwd` dela roda a ponte da bancada
//! (`xtask/bancada/ponte.py`) até o hospedeiro, e lá uma **ponte do meio**
//! ([`Meio`]) leva os bytes ao `hostfwd` do destino. A ponte do meio passa
//! tudo; ou faz o homem no meio nas conexões do fluxo, com uma chave dela;
//! ou troca um byte de um quadro de dados que a origem manda. A relação é
//! registrada pelo administrador, com prova, como na bancada do enlace; a
//! pessoa entra no Terminal de cada uma pelo teclado e lança os programas:
//! o `remetente`, o `recebedor` e o `recebedor-lento`
//! (`programas/src/bin`).
//!
//! Em cada par, numa ordem só, porque cada passo parte do anterior:
//!
//! 1. **FB01**, local, na origem: 4 MiB em cada sentido entre o `remetente`
//!    e o `recebedor` da mesma máquina; os resumos e a vazão;
//! 2. o registro da relação nos dois, e a pessoa no Terminal do destino;
//! 3. **FB02**, entre os Dukes: 4 MiB de A para B e de volta; os resumos, a
//!    vazão, e a auditoria dos dois lados — o `net.connect` do serviço de
//!    enlace e a abertura efetiva em A, o aperto, a abertura e cada `dados`
//!    decididos em B como o dispositivo, pela relação, com o programa
//!    atestado —, sem um byte do conteúdo em registro nenhum;
//! 4. **FB03**, a contrapressão: o `recebedor-lento` segura o `remetente`,
//!    e a memória de um sentido nunca passa do teto dele, nas duas
//!    máquinas (`security.metrics`);
//! 5. **FB10**, a adulteração: a ponte troca um byte de um quadro de dados;
//!    a mensagem não abre em B, o fluxo acaba com `protocolo`, e o que
//!    chegou ao `recebedor` é exatamente o padrão até ali;
//! 6. **FB09**, o homem no meio: a ponte responde à origem e chama o
//!    destino com uma chave dela; ela não abre a primeira mensagem da
//!    origem, o aperto não fecha em lado nenhum, e nada chega ao gate de B;
//! 7. **FB06**, a política: o teto `remoto` sem a intenção, posto no meio
//!    do fluxo, recusa o `dados` seguinte em B, e o fluxo acaba;
//! 8. **FB05**, a suspensão no destino e o esquecimento na origem, cada um
//!    no meio de um fluxo; a volta de cada um;
//! 9. **FB07**, o corte de energia do destino no meio: a origem ouve a
//!    conexão cair, e nada volta depois do boot;
//! 10. **FB08**, as vagas: um fluxo da origem e um de outro dispositivo da
//!     mesma pessoa abertos ao mesmo tempo; a terceira sessão de fluxo é
//!     recusada antes do aperto, e um pedido do estágio 1 e uma cerimônia
//!     do D8 ainda acham vaga;
//! 11. **FB04**, a revogação no destino no meio de um fluxo; depois na
//!     origem, e nada sai dela.
//!
//! Os pares: `x86_64>aarch64`, `aarch64>x86_64`, `x86_64>x86_64` e
//! `aarch64>aarch64` — todos, ou os que `DUKE_PARES` escolhe, separados por
//! `|`.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use sigilo::quadro::{self, Tipo};

use super::enlace::{self, DePe, Maquina, Marca, Par};
use super::{Arquitetura, chaves};

/// O nome das raízes de estado e dos discos desta bancada, em `target/`.
const BANCADA: &str = "fluxo";

/// Como cada Duke chama o outro, o dispositivo como a pessoa o pede, o
/// papel da relação e o endereço do destino: os da bancada do enlace.
const NOME: &str = enlace::NOME;
const DISPOSITIVO: &str = enlace::DISPOSITIVO;
const PAPEL: &str = enlace::PAPEL;
const ENDERECO: &str = enlace::ENDERECO;

/// O outro dispositivo da mesma pessoa que o destino conhece em FB08: a
/// bancada faz o papel dele, com uma chave dela, direto na porta do enlace
/// do destino.
const OUTRO: &str = "par-2";

/// A intenção que os programas oferecem e procuram.
const INTENCAO: &str = "imagem.compartilhar";

/// Quanto o `remetente` manda: 4 MiB.
const TAMANHO: usize = 4 * 1024 * 1024;

/// O teto de um buffer de sentido: `politica::fluxo::BUFFER_DO_SENTIDO`.
const BUFFER: u64 = politica::fluxo::BUFFER_DO_SENTIDO as u64;

/// O código de saída de cada programa com tudo feito, e o de uma falha.
const REMETENTE_OK: i64 = 52;
const REMETENTE_FALHOU: i64 = 53;
const RECEBEDOR_OK: i64 = 54;
const RECEBEDOR_FALHOU: i64 = 55;
const LENTO_OK: i64 = 56;
const LENTO_FALHOU: i64 = 57;

/// Quanto esperar cada coisa: um programa oferecer o endpoint, uma troca
/// de 4 MiB em cada sentido entre duas máquinas emuladas, e o fluxo andar
/// até a marca do meio.
const ESPERA_PELO_ENDPOINT: Duration = Duration::from_secs(120);
const ESPERA_PELA_TROCA: Duration = Duration::from_secs(1200);
const ESPERA_PELO_MEIO: Duration = Duration::from_secs(300);
const ESPERA_PELO_FIM: Duration = Duration::from_secs(300);

/// A marca do meio de um fluxo lento: quanto o `recebedor-lento` já leu.
const NO_MEIO: &str = "recebedor-lento: lidos 262144";

/// O quadro de dados da origem que a ponte adultera: o abrir é o
/// primeiro; os quatro seguintes passam.
const ADULTERADO: usize = 6;

/// Quanto a ponte do meio espera cada lado falar.
const ESPERA_NO_MEIO: Duration = Duration::from_secs(200);

/// Os pares, na ordem em que rodam: origem e destino.
pub(crate) const PARES: [(Arquitetura, Arquitetura); 4] = [
    (Arquitetura::X86_64, Arquitetura::Aarch64),
    (Arquitetura::Aarch64, Arquitetura::X86_64),
    (Arquitetura::X86_64, Arquitetura::X86_64),
    (Arquitetura::Aarch64, Arquitetura::Aarch64),
];

fn travar<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// O padrão, como os programas o geram
// ---------------------------------------------------------------------------

/// O byte `i` do padrão determinístico, com a `semente` de cada sentido:
/// `programas::fluxo::padrao`.
fn padrao(semente: u8, i: usize) -> u8 {
    (((i * 7 + 3) % 251) as u8).wrapping_add(semente)
}

/// O FNV-1a de 64 bits dos `n` primeiros bytes do padrão de `semente`, como
/// os programas o dizem.
fn resumo(semente: u8, n: usize) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for i in 0..n {
        h ^= u64::from(padrao(semente, i));
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Os primeiros bytes de cada sentido, como texto: em hexadecimal e em
/// base64. Se um deles aparecer num registro, o conteúdo vazou para a
/// auditoria.
fn agulhas_do_conteudo() -> Vec<String> {
    let mut v = Vec::new();
    for semente in [0u8, 1] {
        let bytes: Vec<u8> = (0..12).map(|i| padrao(semente, i)).collect();
        v.push(sigilo::hex_de(&bytes[..8]));
        v.push(base64(&bytes));
    }
    v
}

/// O base64 padrão, com preenchimento.
fn base64(bytes: &[u8]) -> String {
    const ALFABETO: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            if k <= c.len() {
                s.push(char::from(ALFABETO[((n >> (18 - 6 * k)) & 63) as usize]));
            } else {
                s.push('=');
            }
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Os quadros, na ponte e nas sessões cruas
// ---------------------------------------------------------------------------

/// O próximo quadro da conexão: o tipo e o corpo; nada, se ela fechou entre
/// dois quadros.
fn ler_quadro(s: &mut TcpStream) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut cab = [0u8; quadro::CABECALHO];
    let mut lidos = 0;
    while lidos < cab.len() {
        let n = s.read(&mut cab[lidos..])?;
        if n == 0 {
            return if lidos == 0 {
                Ok(None)
            } else {
                Err(std::io::ErrorKind::UnexpectedEof.into())
            };
        }
        lidos += n;
    }
    let mut corpo = vec![0u8; usize::from(u16::from_be_bytes([cab[1], cab[2]]))];
    s.read_exact(&mut corpo)?;
    Ok(Some((cab[0], corpo)))
}

/// O quadro de volta em bytes, como estava.
fn bytes_do_quadro(tipo: u8, corpo: &[u8]) -> Vec<u8> {
    let mut q = vec![tipo];
    q.extend_from_slice(&(corpo.len() as u16).to_be_bytes());
    q.extend_from_slice(corpo);
    q
}

fn escrever_quadro(s: &mut TcpStream, tipo: Tipo, corpo: &[u8]) -> Result<(), String> {
    let q = quadro::montar(tipo, corpo).map_err(|e| format!("quadro: {}", e.motivo()))?;
    s.write_all(&q)
        .map_err(|e| format!("o quadro nao saiu: {e}"))
}

/// Copia de `de` para `para` até `de` fechar; então fecha o sentido de
/// escrita de `para`, e o outro lado vê o fim.
fn copiar(mut de: TcpStream, mut para: TcpStream) {
    let mut buf = vec![0u8; 65536];
    loop {
        match de.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if para.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = para.shutdown(Shutdown::Write);
}

/// Como [`copiar`], quadro a quadro, trocando um bit no meio do corpo do
/// `n`-ésimo quadro de dados.
fn copiar_adulterando(mut de: TcpStream, mut para: TcpStream, n: usize, visto: Arc<Mutex<Visto>>) {
    let mut dados = 0;
    while let Ok(Some((tipo, mut corpo))) = ler_quadro(&mut de) {
        if tipo == Tipo::Dados as u8 {
            dados += 1;
            if dados == n && !corpo.is_empty() {
                let k = corpo.len() / 2;
                corpo[k] ^= 0x01;
                travar(&visto).adulterados += 1;
            }
        }
        if para.write_all(&bytes_do_quadro(tipo, &corpo)).is_err() {
            break;
        }
    }
    let _ = para.shutdown(Shutdown::Write);
}

// ---------------------------------------------------------------------------
// A ponte do meio
// ---------------------------------------------------------------------------

/// O que a ponte do meio faz com as conexões do fluxo — as que abrem com o
/// quadro 9. As outras, o enlace do estágio 1, ela sempre passa.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Modo {
    /// Passa os bytes nos dois sentidos, sem olhar.
    Passar,
    /// O homem no meio: atende a origem como se fosse o destino, e chama o
    /// destino com uma chave dela — ver [`no_meio`].
    NoMeio,
    /// Passa tudo, trocando um bit do `n`-ésimo quadro de dados que a
    /// origem manda.
    Adulterar(usize),
}

/// O que a ponte viu nas conexões do fluxo desde a última troca de modo.
#[derive(Clone, Debug, Default)]
struct Visto {
    /// Quantas conexões do fluxo passaram por ela.
    do_fluxo: usize,
    /// Se a primeira mensagem da origem abriu com a chave do meio — nunca
    /// deve: ela é para a chave do destino.
    abriu_a_da_origem: bool,
    /// O que o destino respondeu ao aperto do meio.
    resposta_do_destino: Option<String>,
    /// Quantos quadros de dados ela adulterou.
    adulterados: usize,
    erro: Option<String>,
}

/// A ponte do meio: escuta numa porta do hospedeiro — a que a ponte da
/// origem procura — e, a cada conexão, conecta ao `hostfwd` do destino.
struct Meio {
    porta: u16,
    modo: Arc<Mutex<Modo>>,
    visto: Arc<Mutex<Visto>>,
    parar: Arc<AtomicBool>,
}

impl Meio {
    /// Abre a porta e o fio que a atende. `porta_do_destino` é a do
    /// `hostfwd` do destino; `duke` é a chave pública dele, para o meio
    /// chamá-lo com a chave dela.
    fn ligar(porta_do_destino: u16, duke: [u8; 32]) -> Result<Meio, String> {
        let ouvinte = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|e| format!("a ponte do meio nao abriu porta: {e}"))?;
        let porta = ouvinte
            .local_addr()
            .map_err(|e| format!("a ponte do meio sem endereco: {e}"))?
            .port();
        let modo = Arc::new(Mutex::new(Modo::Passar));
        let visto = Arc::new(Mutex::new(Visto::default()));
        let parar = Arc::new(AtomicBool::new(false));
        let (m, v, p) = (modo.clone(), visto.clone(), parar.clone());
        std::thread::spawn(move || {
            for conexao in ouvinte.incoming() {
                if p.load(Ordering::Acquire) {
                    break;
                }
                let Ok(origem) = conexao else {
                    continue;
                };
                let agora = *travar(&m);
                let v = v.clone();
                std::thread::spawn(move || atender(origem, porta_do_destino, agora, v, duke));
            }
        });
        Ok(Meio {
            porta,
            modo,
            visto,
            parar,
        })
    }

    /// Muda o modo das próximas conexões, e esquece o que viu.
    fn modo(&self, modo: Modo) {
        *travar(&self.modo) = modo;
        *travar(&self.visto) = Visto::default();
    }

    fn visto(&self) -> Visto {
        travar(&self.visto).clone()
    }
}

impl Drop for Meio {
    /// O fio da porta acorda com uma conexão, vê o pedido de parar e sai.
    fn drop(&mut self) {
        self.parar.store(true, Ordering::Release);
        let _ = TcpStream::connect(("127.0.0.1", self.porta));
    }
}

/// Uma conexão da origem, no modo de quando ela chegou.
fn atender(
    origem: TcpStream,
    porta_do_destino: u16,
    modo: Modo,
    visto: Arc<Mutex<Visto>>,
    duke: [u8; 32],
) {
    let mut a = origem;
    let primeiro = if modo == Modo::Passar {
        Vec::new()
    } else {
        let _ = a.set_read_timeout(Some(ESPERA_NO_MEIO));
        let Ok(Some((tipo, corpo))) = ler_quadro(&mut a) else {
            let _ = a.shutdown(Shutdown::Both);
            return;
        };
        let _ = a.set_read_timeout(None);
        if tipo == Tipo::InicioFluxo as u8 {
            travar(&visto).do_fluxo += 1;
            if modo == Modo::NoMeio {
                if let Err(e) = no_meio(a, porta_do_destino, &corpo, &visto, &duke) {
                    travar(&visto).erro = Some(e);
                }
                return;
            }
        }
        bytes_do_quadro(tipo, &corpo)
    };
    let Ok(mut b) = TcpStream::connect(("127.0.0.1", porta_do_destino)) else {
        let _ = a.shutdown(Shutdown::Both);
        return;
    };
    if !primeiro.is_empty() && b.write_all(&primeiro).is_err() {
        return;
    }
    let (Ok(a2), Ok(b2)) = (a.try_clone(), b.try_clone()) else {
        return;
    };
    let volta = std::thread::spawn(move || copiar(b2, a2));
    match modo {
        Modo::Adulterar(n) if primeiro.first() == Some(&(Tipo::InicioFluxo as u8)) => {
            copiar_adulterando(a, b, n, visto)
        }
        _ => copiar(a, b),
    }
    let _ = volta.join();
}

/// O homem no meio, numa conexão de fluxo da origem.
///
/// A primeira mensagem do IK da origem vem cifrada para a chave do destino:
/// o meio não a abre. Ao destino ele faz um aperto dele, com uma chave dele
/// — que o registro de lá não conhece. À origem ele responde uma segunda
/// mensagem que não é do destino. Nenhum dos dois apertos fecha.
fn no_meio(
    mut a: TcpStream,
    porta_do_destino: u16,
    primeira: &[u8],
    visto: &Arc<Mutex<Visto>>,
    duke: &[u8; 32],
) -> Result<(), String> {
    let privada = super::aleatorios()?;
    let mut carga = vec![0u8; primeira.len()];
    travar(visto).abriu_a_da_origem = sigilo::Respondedor::novo(sigilo::PROLOGO_DO_FLUXO, &privada)
        .ler(primeira, &mut carga)
        .is_ok();
    let mut b = TcpStream::connect(("127.0.0.1", porta_do_destino))
        .map_err(|e| format!("o meio nao conectou ao destino: {e}"))?;
    let _ = b.set_read_timeout(Some(ESPERA_NO_MEIO));
    let mut buf = vec![0u8; 256];
    let (n, _aguardando) = sigilo::Iniciador::novo(sigilo::PROLOGO_DO_FLUXO, &privada, duke)
        .escrever(super::aleatorios()?, b"", &mut buf)
        .map_err(|e| format!("a 1a mensagem do meio: {}", e.motivo()))?;
    escrever_quadro(&mut b, Tipo::InicioFluxo, &buf[..n])?;
    let resposta = match ler_quadro(&mut b) {
        Ok(Some((t, c))) if t == Tipo::Recusa as u8 => {
            format!("recusa: {}", String::from_utf8_lossy(&c))
        }
        Ok(Some((t, _))) => format!("quadro {t}"),
        Ok(None) => "fechou".to_string(),
        Err(e) => format!("erro: {e}"),
    };
    travar(visto).resposta_do_destino = Some(resposta);
    let _ = b.shutdown(Shutdown::Both);
    // À origem, uma segunda mensagem do tamanho certo, que não é de lá.
    let mut ruido = super::aleatorios()?.to_vec();
    ruido.extend_from_slice(&super::aleatorios()?[..16]);
    escrever_quadro(&mut a, Tipo::Resposta, &ruido)?;
    let _ = a.set_read_timeout(Some(ESPERA_NO_MEIO));
    let mut lixo = [0u8; 512];
    while let Ok(n) = a.read(&mut lixo) {
        if n == 0 {
            break;
        }
    }
    let _ = a.shutdown(Shutdown::Both);
    Ok(())
}

// ---------------------------------------------------------------------------
// A sessão crua: o outro dispositivo, que a bancada faz
// ---------------------------------------------------------------------------

/// Uma sessão de fluxo do hospedeiro direto à porta do enlace do destino,
/// com a chave de um dispositivo que a bancada faz — o [`OUTRO`] de FB08.
struct Crua {
    s: TcpStream,
    t: sigilo::Transporte,
}

/// O aperto do fluxo como o dispositivo de chave `privada`: `Ok(Ok)` com a
/// sessão, `Ok(Err)` com a recusa em claro do destino.
fn apertar_cru(
    porta: u16,
    privada: &[u8; 32],
    duke: &[u8; 32],
) -> Result<Result<Crua, String>, String> {
    let mut s = TcpStream::connect(("127.0.0.1", porta))
        .map_err(|e| format!("a sessao crua nao conectou: {e}"))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(60)));
    let mut buf = vec![0u8; 256];
    let (n, aguardando) = sigilo::Iniciador::novo(sigilo::PROLOGO_DO_FLUXO, privada, duke)
        .escrever(super::aleatorios()?, b"", &mut buf)
        .map_err(|e| format!("a 1a mensagem crua: {}", e.motivo()))?;
    escrever_quadro(&mut s, Tipo::InicioFluxo, &buf[..n])?;
    match ler_quadro(&mut s) {
        Ok(Some((t, corpo))) if t == Tipo::Resposta as u8 => {
            let mut lixo = vec![0u8; corpo.len()];
            let (_, t) = aguardando
                .ler(&corpo, &mut lixo)
                .map_err(|e| format!("a 2a mensagem do destino nao abriu: {}", e.motivo()))?;
            Ok(Ok(Crua { s, t }))
        }
        Ok(Some((t, corpo))) if t == Tipo::Recusa as u8 => {
            Ok(Err(String::from_utf8_lossy(&corpo).into_owned()))
        }
        outro => Err(format!(
            "o aperto cru nao teve resposta nem recusa: {outro:?}"
        )),
    }
}

impl Crua {
    /// Cifra e manda uma mensagem do fluxo.
    fn mandar(&mut self, claro: &[u8]) -> Result<(), String> {
        let mut c = vec![0u8; claro.len() + 16];
        let n = self
            .t
            .cifrar(claro, &mut c)
            .map_err(|e| format!("nao se cifrou: {}", e.motivo()))?;
        escrever_quadro(&mut self.s, Tipo::Dados, &c[..n])
    }

    /// A próxima mensagem do fluxo, decifrada.
    fn receber(&mut self) -> Result<Vec<u8>, String> {
        match ler_quadro(&mut self.s) {
            Ok(Some((t, corpo))) if t == Tipo::Dados as u8 => {
                let mut claro = vec![0u8; corpo.len()];
                let n = self
                    .t
                    .decifrar(&corpo, &mut claro)
                    .map_err(|e| format!("uma mensagem do destino nao abriu: {}", e.motivo()))?;
                claro.truncate(n);
                Ok(claro)
            }
            Ok(Some((t, corpo))) => Err(format!(
                "o destino mandou o quadro {t}: {}",
                String::from_utf8_lossy(&corpo)
            )),
            Ok(None) => Err("o destino fechou".into()),
            Err(e) => Err(format!("a sessao crua: {e}")),
        }
    }
}

/// A mensagem `abrir` do fluxo, como a sessão de um Duke a escreve
/// (`kernel/src/fluxo/par.rs`): o tipo 1 e o JSON.
fn abrir_cru(relacao: &str, endpoint: &str) -> Vec<u8> {
    let mut v = vec![1u8];
    v.extend_from_slice(
        format!(
            r#"{{"relation":"{relacao}","program":"{}","endpoint":"{endpoint}","intent":"{INTENCAO}","epoch":"{}"}}"#,
            "ab".repeat(32),
            "0e".repeat(8)
        )
        .as_bytes(),
    );
    v
}

// ---------------------------------------------------------------------------
// Os programas
// ---------------------------------------------------------------------------

/// O que um programa disse até o fim: as linhas, sem o prefixo, com o tempo
/// de máquina de cada uma, e o código de saída.
struct Dito {
    nome: &'static str,
    linhas: Vec<(u64, String)>,
    codigo: i64,
}

impl Dito {
    /// O resto da primeira linha que começa com `prefixo`.
    fn dito(&self, prefixo: &str) -> Option<&str> {
        self.linhas
            .iter()
            .find_map(|(_, l)| l.strip_prefix(prefixo))
    }

    /// O tempo de máquina da primeira linha que começa com `prefixo`.
    fn hora(&self, prefixo: &str) -> Option<u64> {
        self.linhas
            .iter()
            .find_map(|(h, l)| l.starts_with(prefixo).then_some(*h))
    }

    fn texto(&self) -> String {
        let linhas: Vec<&str> = self.linhas.iter().map(|(_, l)| l.as_str()).collect();
        format!("{}: {}", self.nome, linhas.join(" | "))
    }

    /// O motivo do fim do fluxo, como o programa o ouviu: do
    /// `stream.status`, se ainda o viu, ou da operação que achou o fluxo
    /// acabado — o `CONFLICT` com o motivo. A lápide diz o fim uma vez a
    /// cada ponta: dito à operação, o `stream.status` seguinte já não acha o
    /// fluxo.
    fn motivo_do_fim(&self) -> &str {
        self.dito("estado closed ")
            .or_else(|| {
                self.linhas
                    .iter()
                    .find_map(|(_, l)| l.split_once(" CONFLICT ").map(|(_, m)| m))
            })
            .unwrap_or("")
    }
}

/// A pessoa lança `nome` em `quem`, que diz o endpoint dele: onde o log
/// estava antes, e o endpoint.
fn lancar_com_endpoint(quem: &mut DePe, nome: &'static str) -> Result<(u64, String), String> {
    let desde = quem.marca()?.log;
    quem.lancar(nome)?;
    let (pronto, fim) = (format!("{nome}: endpoint "), format!("{nome}: fim "));
    match quem.esperar_dito(desde, &[&pronto, &fim], ESPERA_PELO_ENDPOINT)? {
        (0, endpoint) => Ok((desde, endpoint)),
        (_, codigo) => Err(format!(
            "{}: o {nome} saiu antes de oferecer ({codigo})",
            quem.papel
        )),
    }
}

/// Espera `nome`, lançado em `quem` depois de `desde`, dizer o fim.
fn ate_o_fim(
    quem: &mut DePe,
    desde: u64,
    nome: &'static str,
    espera: Duration,
) -> Result<Dito, String> {
    let fim = format!("{nome}: fim ");
    let (_, codigo) = quem.esperar_dito(desde, &[&fim], espera)?;
    let codigo = codigo
        .trim()
        .parse()
        .map_err(|_| format!("{}: o {nome} saiu com `{codigo}`", quem.papel))?;
    Ok(Dito {
        nome,
        linhas: quem.ditas_com_hora(desde, &format!("{nome}: ")),
        codigo,
    })
}

/// Encerra, pelo `process.terminate` da serial, os processos de `quem` cujo
/// programa é um de `nomes`; espera eles saírem. Quantos eram.
pub(crate) fn encerrar(quem: &mut DePe, nomes: &[&str]) -> Result<usize, String> {
    let ids = |quem: &mut DePe| -> Result<Vec<String>, String> {
        let r = quem.m.pedir("process.list", "{}")?;
        let lista = super::objetos_planos(super::apos(&r, r#""processes":["#).unwrap_or(""))?;
        Ok(lista
            .iter()
            .filter(|p| {
                let programa = valor(p, "program");
                let nome = programa.split_whitespace().next().unwrap_or("");
                nomes.contains(&nome)
            })
            .map(|p| valor(p, "id"))
            .collect())
    };
    let vivos = ids(quem)?;
    for id in &vivos {
        let _ = quem
            .m
            .pedir("process.terminate", &format!(r#"{{"process":{id}}}"#))?;
    }
    let limite = Instant::now() + Duration::from_secs(30);
    while !ids(quem)?.is_empty() {
        if Instant::now() >= limite {
            return Err(format!(
                "{}: {nomes:?} nao sairam depois do process.terminate",
                quem.papel
            ));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Ok(vivos.len())
}

/// O valor de um campo de um objeto plano, ou nada.
fn valor(campos: &super::ObjetoPlano, nome: &str) -> String {
    campos
        .iter()
        .find(|(n, _)| n == nome)
        .and_then(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// A seção `streams` de `security.metrics`: os vivos, os remotos, o pico
/// dos buffers e o teto de cada sentido.
fn medidas_do_fluxo(quem: &mut DePe) -> Result<[u64; 4], String> {
    let r = quem.m.pedir("security.metrics", "{}")?;
    let secao = super::apos(&r, r#""streams":{"#)
        .ok_or_else(|| format!("{}: security.metrics sem os fluxos\n  {r}", quem.papel))?;
    let numero = |campo: &str| -> Result<u64, String> {
        super::apos(secao, &format!(r#""{campo}":"#))
            .and_then(|t| t.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| format!("security.metrics sem `{campo}` nos fluxos"))
    };
    Ok([
        numero("live")?,
        numero("remote")?,
        numero("buffer_peak")?,
        numero("buffer_limit")?,
    ])
}

/// A vazão de `bytes` em `ms`, em KiB/s.
fn vazao(bytes: usize, ms: u64) -> String {
    if ms == 0 {
        return "-".into();
    }
    format!("{} KiB/s", (bytes as u64 * 1000 / 1024) / ms)
}

// ---------------------------------------------------------------------------
// A bancada de um par
// ---------------------------------------------------------------------------

struct Bancada {
    par: Par,
    meio: Meio,
    porta_do_destino: u16,
    /// O programa que a origem atesta: o resumo do `remetente`, nos oito
    /// primeiros dígitos.
    remetente: String,
    /// As medidas da vazão, para o fim.
    medidas: Vec<String>,
}

impl Bancada {
    fn origem(&mut self) -> &mut DePe {
        &mut self.par.origem
    }

    fn destino(&mut self) -> &mut DePe {
        &mut self.par.destino
    }

    /// O `remetente` na origem, até o fim — lendo o destino também, a
    /// cada volta: a auditoria de cada máquina se lê enquanto acontece. O
    /// anel dela guarda só os últimos registros, e uma troca de 4 MiB
    /// passa de mil de cada lado: lida só no fim, a do destino já não
    /// teria o aperto nem a abertura.
    fn remetente(&mut self) -> Result<Dito, String> {
        let desde = self.origem().marca()?.log;
        self.origem().lancar("remetente")?;
        let fim = "remetente: fim ";
        let limite = Instant::now() + ESPERA_PELA_TROCA;
        loop {
            self.destino().ler()?;
            match self
                .origem()
                .esperar_dito(desde, &[fim], Duration::from_secs(5))
            {
                Ok(_) => break,
                Err(e) if Instant::now() >= limite => return Err(e),
                Err(_) => {}
            }
        }
        ate_o_fim(self.origem(), desde, "remetente", Duration::from_secs(5))
    }

    /// A troca inteira de 4 MiB em cada sentido, já com os dois de pé: o
    /// `remetente` em `a` e o `recebedor` em `b` — a origem e o destino, ou a
    /// origem nos dois. O que cada um disse.
    fn troca(&mut self, local: bool) -> Result<(Dito, Dito), String> {
        let (desde, endpoint) = if local {
            lancar_com_endpoint(self.origem(), "recebedor")?
        } else {
            lancar_com_endpoint(self.destino(), "recebedor")?
        };
        let r = self.remetente()?;
        let quem = if local { self.origem() } else { self.destino() };
        let rec = ate_o_fim(quem, desde, "recebedor", ESPERA_PELO_FIM)?;
        let onde = if local { "aqui" } else { "no par" };
        let ida = resumo(0, TAMANHO);
        let volta = resumo(1, TAMANHO);
        let de = if local {
            format!("remetente {}", self.remetente)
        } else {
            DISPOSITIVO.to_string()
        };
        let certo = r.codigo == REMETENTE_OK
            && r.dito(&format!("candidato {onde} recebedor "))
                .is_some_and(|e| e == endpoint)
            && r.dito("voltou ") == Some(&format!("{TAMANHO} {volta}"))
            && rec.codigo == RECEBEDOR_OK
            && rec.dito("recebi ") == Some(&format!("{TAMANHO} {ida} de {de}"))
            && rec.dito("gravar ") == Some("ALLOW")
            && rec.dito("devolvi ") == Some(&TAMANHO.to_string());
        if !certo {
            return Err(format!(
                "a troca de 4 MiB nao fechou\n  {}\n  {}",
                r.texto(),
                rec.texto()
            ));
        }
        Ok((r, rec))
    }

    /// A vazão de uma troca, pelo log da origem: a ida, do `abri` ao último
    /// `mandei`, e a volta, dali ao `voltou`.
    fn medir(&mut self, como: &str, r: &Dito) -> String {
        let marcos = (
            r.hora("abri "),
            r.hora(&format!("mandei {TAMANHO}")),
            r.hora("voltou "),
        );
        let m = match marcos {
            (Some(a), Some(b), Some(c)) if b >= a && c >= b => format!(
                "{como}: ida {} ms ({}), volta {} ms ({})",
                b - a,
                vazao(TAMANHO, b - a),
                c - b,
                vazao(TAMANHO, c - b)
            ),
            _ => format!("{como}: sem os marcos de tempo"),
        };
        self.medidas.push(m.clone());
        m
    }

    /// Um fluxo lento — o `remetente` na origem, o `recebedor-lento` no
    /// destino — até a marca do meio: os dois de pé e o fluxo aberto. Onde
    /// o log de cada um estava antes.
    fn lento_ate_o_meio(&mut self) -> Result<(u64, u64), String> {
        let (desde_b, _) = lancar_com_endpoint(self.destino(), "recebedor-lento")?;
        let desde_a = self.origem().marca()?.log;
        self.origem().lancar("remetente")?;
        self.destino()
            .esperar_dito(
                desde_b,
                &[NO_MEIO, "recebedor-lento: fim "],
                ESPERA_PELO_MEIO,
            )
            .and_then(|(i, resto)| {
                if i == 0 {
                    Ok(())
                } else {
                    Err(format!("o recebedor-lento saiu antes do meio ({resto})"))
                }
            })?;
        Ok((desde_a, desde_b))
    }

    /// Os dois programas do fluxo lento até o fim, depois de algo no meio
    /// dele: o fim de cada um.
    fn lento_ate_o_fim(&mut self, desde_a: u64, desde_b: u64) -> Result<(Dito, Dito), String> {
        let r = ate_o_fim(self.origem(), desde_a, "remetente", ESPERA_PELO_FIM)?;
        let l = ate_o_fim(self.destino(), desde_b, "recebedor-lento", ESPERA_PELO_FIM)?;
        Ok((r, l))
    }

    /// O fluxo lento acabou nos dois pelo que se fez no meio: o `remetente`
    /// ouviu do par um fim com `do_par`, e o `recebedor-lento`, um com
    /// `daqui` — ou o contrário, quando quem mexeu foi a origem.
    fn acabou_com(
        &mut self,
        r: &Dito,
        l: &Dito,
        na_origem: &str,
        no_destino: &str,
    ) -> Result<(), String> {
        let certo = r.codigo == REMETENTE_FALHOU
            && r.motivo_do_fim().contains(na_origem)
            && l.codigo == LENTO_FALHOU
            && l.motivo_do_fim().contains(no_destino);
        if certo {
            Ok(())
        } else {
            Err(format!(
                "o fluxo nao acabou com `{na_origem}` na origem e `{no_destino}` no destino\n  {}\n  {}",
                r.texto(),
                l.texto()
            ))
        }
    }

    /// `quem` gravou o fim de uma troca inteira: os 4 MiB de cada sentido,
    /// nada descartado. O motivo é `concluido`, se quem lê por último viu o
    /// fim antes de o `recebedor` fechar, ou `fechado pela ponta`, se ele
    /// fechou antes — o `recebedor` fecha depois de terminar o sentido
    /// dele, para que o que escreveu siga legível mesmo depois de ele sair.
    /// Os dois são o fim de uma troca inteira.
    fn fim_inteiro(&mut self, quem_origem: bool, desde: u64) -> Result<(), String> {
        use politica::fluxo::motivo;
        let contas = format!("; ida {TAMANHO}; volta {TAMANHO}; desc 0");
        let certos = [
            format!("{}{contas}", motivo::CONCLUIDO),
            format!("{}{contas}", motivo::FECHADO),
        ];
        let quem = if quem_origem {
            self.origem()
        } else {
            self.destino()
        };
        quem.ler()?;
        if quem
            .gravados(desde)
            .any(|g| g.metodo == "stream.end" && certos.contains(&g.detalhe))
        {
            Ok(())
        } else {
            Err(format!(
                "{}: nenhum stream.end de uma troca inteira (`{}` ou `{}`)",
                quem.papel, certos[0], certos[1]
            ))
        }
    }

    /// O destino gravou o fim do fluxo com `motivo`, pelo kernel.
    fn fim_gravado(&mut self, quem_origem: bool, desde: u64, motivo: &str) -> Result<(), String> {
        let quem = if quem_origem {
            self.origem()
        } else {
            self.destino()
        };
        quem.ler()?;
        if quem
            .gravados(desde)
            .any(|g| g.metodo == "stream.end" && g.detalhe.contains(motivo))
        {
            Ok(())
        } else {
            Err(format!("{}: nenhum stream.end com `{motivo}`", quem.papel))
        }
    }
}

// ---------------------------------------------------------------------------
// Os passos
// ---------------------------------------------------------------------------

/// FB01: local, na origem — o `remetente` e o `recebedor` da mesma máquina.
fn fb01(b: &mut Bancada) -> Result<String, String> {
    let desde = b.origem().marca()?.auditoria;
    let (r, _) = b.troca(true)?;
    b.fim_inteiro(true, desde)?;
    let m = b.medir("local", &r);
    Ok(format!(
        "FB01 local: 4 MiB em cada sentido, os resumos conferem; {m}"
    ))
}

/// FB02: entre os Dukes, com a auditoria dos dois lados.
fn fb02(b: &mut Bancada) -> Result<String, String> {
    let (antes_o, antes_d) = (b.origem().marca()?, b.destino().marca()?);
    let (r, _) = b.troca(false)?;
    let da_origem = sigilo::hex(&b.par.da_origem);
    let relacao8 = b.par.relacao[..8].to_string();
    let atestado = format!("atestado {}", b.remetente);
    // A origem: a abertura pedida ao par e a efetiva, o serviço de enlace
    // conectando pelo gate, e o fim sem nada descartado.
    b.origem().ler()?;
    let o = &b.par.origem;
    let pedido = o.gravados(antes_o.auditoria).any(|g| {
        g.metodo == "stream.open"
            && g.codigo == "ALLOW"
            && g.recurso.contains(DISPOSITIVO)
            && g.detalhe.contains("pedido ao par")
    });
    let efetivo = o.gravados(antes_o.auditoria).any(|g| {
        g.metodo == "stream.open"
            && g.agente == "kernel"
            && g.recurso.ends_with(DISPOSITIVO)
            && g.detalhe.starts_with("aberto pelo par")
    });
    let conectou = o.gravados(antes_o.auditoria).any(|g| {
        g.metodo == "net.connect"
            && g.codigo == "ALLOW"
            && g.titular == "service"
            && g.recurso == ENDERECO
    });
    let escritas_a = o
        .gravados(antes_o.auditoria)
        .filter(|g| g.metodo == "stream.write" && g.codigo == "ALLOW")
        .count();
    if !(pedido && efetivo && conectou) || escritas_a < TAMANHO / politica::fluxo::BUFFER_DO_SENTIDO
    {
        return Err(format!(
            "a origem nao gravou o caminho: pedido {pedido}, efetivo {efetivo}, conectou {conectou}, {escritas_a} escritas"
        ));
    }
    b.fim_inteiro(true, antes_o.auditoria)?;
    // O destino: o aperto pela chave do par, a abertura e cada `dados`
    // decididos como o dispositivo, pela relação, com o programa atestado.
    b.destino().ler()?;
    let d = &b.par.destino;
    let sessao = d.gravados(antes_d.auditoria).any(|g| {
        g.metodo == "stream.session"
            && g.codigo == "ALLOW"
            && g.titular == "device"
            && g.chave == da_origem
            && g.detalhe.contains(&format!("relacao {relacao8}"))
            && g.detalhe.contains(&atestado)
    });
    let pelo_par = |g: &enlace::Gravado| {
        g.codigo == "ALLOW"
            && g.titular == "device"
            && g.agente == NOME
            && g.papel == PAPEL
            && g.chave == da_origem
            && g.detalhe.starts_with(&format!("pela relacao {relacao8}"))
            && g.detalhe.contains(&atestado)
    };
    let aberto = d
        .gravados(antes_d.auditoria)
        .any(|g| g.metodo == "stream.open" && pelo_par(g));
    let dados = d
        .gravados(antes_d.auditoria)
        .filter(|g| g.metodo == "stream.write" && pelo_par(g))
        .count();
    if !(sessao && aberto) || dados < TAMANHO / politica::fluxo::BUFFER_DO_SENTIDO {
        return Err(format!(
            "o destino nao gravou o caminho do par: sessao {sessao}, aberto {aberto}, {dados} dados decididos"
        ));
    }
    // Nenhum byte do conteúdo em registro nenhum, dos dois lados.
    let agulhas = agulhas_do_conteudo();
    for (quem, desde) in [
        (&b.par.origem, antes_o.auditoria),
        (&b.par.destino, antes_d.auditoria),
    ] {
        if let Some(g) = quem.gravados(desde).find(|g| {
            agulhas
                .iter()
                .any(|a| g.detalhe.contains(a.as_str()) || g.recurso.contains(a.as_str()))
        }) {
            return Err(format!(
                "{}: o conteudo do fluxo vazou para a auditoria: {} {} | {}",
                quem.papel, g.metodo, g.recurso, g.detalhe
            ));
        }
    }
    let m = b.medir("entre os Dukes", &r);
    Ok(format!(
        "FB02 entre os Dukes: 4 MiB de A para B e de volta, os resumos conferem; A gravou o pedido, a abertura efetiva e o net.connect do servico de enlace; B gravou o aperto, a abertura e {dados} dados como o dispositivo, pela relacao, com o programa atestado; nenhum byte do conteudo na auditoria; {m}"
    ))
}

/// FB03: a contrapressão — o `recebedor-lento` segura o `remetente`, e o
/// pico dos buffers não passa do teto, nos dois.
fn fb03(b: &mut Bancada) -> Result<String, String> {
    let (desde_b, _) = lancar_com_endpoint(b.destino(), "recebedor-lento")?;
    let r = b.remetente()?;
    let l = ate_o_fim(b.destino(), desde_b, "recebedor-lento", ESPERA_PELO_FIM)?;
    let esperas: u64 = r
        .dito("esperas ")
        .and_then(|e| e.trim().parse().ok())
        .unwrap_or(0);
    let certo = r.codigo == REMETENTE_OK
        && r.dito("voltou ") == Some(&format!("0 {}", resumo(0, 0)))
        && esperas > 0
        && l.codigo == LENTO_OK
        && l.dito("recebi ")
            == Some(&format!(
                "{TAMANHO} {} de {DISPOSITIVO}",
                resumo(0, TAMANHO)
            ));
    if !certo {
        return Err(format!(
            "o fluxo lento nao fechou com a contrapressao\n  {}\n  {}",
            r.texto(),
            l.texto()
        ));
    }
    let mut picos = Vec::new();
    for na_origem in [true, false] {
        let quem = if na_origem { b.origem() } else { b.destino() };
        let [vivos, remotos, pico, teto] = medidas_do_fluxo(quem)?;
        if teto != BUFFER || pico == 0 || pico > teto || vivos != 0 || remotos != 0 {
            return Err(format!(
                "{}: os fluxos em security.metrics: {vivos} vivos, {remotos} remotos, pico {pico}, teto {teto}",
                quem.papel
            ));
        }
        picos.push(pico);
    }
    let tempo = match (r.hora("abri "), r.hora(&format!("mandei {TAMANHO}"))) {
        (Some(a), Some(c)) if c >= a => format!("{} ms ({})", c - a, vazao(TAMANHO, c - a)),
        _ => "-".into(),
    };
    b.medidas.push(format!("lento: 4 MiB em {tempo}"));
    Ok(format!(
        "FB03 contrapressao: o leitor lento segurou o remetente em {esperas} escritas; 4 MiB em {tempo}; o pico dos buffers {} (origem) e {} (destino), dentro do teto de {BUFFER}",
        picos[0], picos[1]
    ))
}

/// FB10: a ponte troca um bit de um quadro de dados da origem.
fn fb10(b: &mut Bancada) -> Result<String, String> {
    let antes_d = b.destino().marca()?.auditoria;
    b.meio.modo(Modo::Adulterar(ADULTERADO));
    let (desde_b, _) = lancar_com_endpoint(b.destino(), "recebedor")?;
    let r = b.remetente();
    let rec = ate_o_fim(b.destino(), desde_b, "recebedor", ESPERA_PELO_FIM);
    let visto = b.meio.visto();
    b.meio.modo(Modo::Passar);
    let (r, rec) = (r?, rec?);
    if visto.adulterados != 1 {
        return Err(format!("a ponte nao adulterou um quadro: {visto:?}"));
    }
    let parcial = rec.dito("parcial ").unwrap_or("");
    let (n, d) = parcial.split_once(' ').unwrap_or(("", ""));
    let n: usize = n.parse().unwrap_or(usize::MAX);
    let certo = r.codigo == REMETENTE_FALHOU
        && r.motivo_do_fim()
            .contains(politica::fluxo::motivo::PROTOCOLO)
        && rec.codigo == RECEBEDOR_FALHOU
        && rec.motivo_do_fim() == politica::fluxo::motivo::PROTOCOLO
        && n < TAMANHO
        && d == resumo(0, n);
    if !certo {
        return Err(format!(
            "o quadro adulterado nao acabou o fluxo com protocolo, ou o que chegou nao e o padrao\n  {}\n  {}",
            r.texto(),
            rec.texto()
        ));
    }
    b.fim_gravado(false, antes_d, politica::fluxo::motivo::PROTOCOLO)?;
    Ok(format!(
        "FB10 adulteracao: o {ADULTERADO}o quadro de dados da origem com um bit trocado nao abriu em B; o fluxo acabou com protocolo nos dois; o recebedor tinha lido {n} bytes, exatamente o padrao"
    ))
}

/// FB09: o homem no meio, com uma chave dele.
fn fb09(b: &mut Bancada) -> Result<String, String> {
    let antes_d = b.destino().marca()?.auditoria;
    let (desde_b, _) = lancar_com_endpoint(b.destino(), "recebedor")?;
    b.meio.modo(Modo::NoMeio);
    let r = b.remetente();
    let visto = b.meio.visto();
    b.meio.modo(Modo::Passar);
    let r = r?;
    // O recebedor de lá não recebeu nada: sai pela bancada.
    let encerrados = encerrar(b.destino(), &["recebedor"])?;
    let rec = b
        .destino()
        .ditas_com_hora(desde_b, "recebedor: aceitei ")
        .len();
    if visto.do_fluxo != 1 || visto.abriu_a_da_origem || visto.erro.is_some() {
        return Err(format!("o homem no meio nao fez o que devia: {visto:?}"));
    }
    let recusado_la = visto
        .resposta_do_destino
        .as_deref()
        .is_some_and(|r| r == "recusa: chave fora do registro de dispositivos");
    let certo = r.codigo == REMETENTE_FALHOU
        && r.motivo_do_fim() == politica::fluxo::motivo::APERTO
        && recusado_la
        && rec == 0
        && encerrados == 1;
    if !certo {
        return Err(format!(
            "o aperto com o homem no meio fechou em algum lado: {visto:?}\n  {}",
            r.texto()
        ));
    }
    b.destino().ler()?;
    let d = &b.par.destino;
    let recusa = d.gravados(antes_d).any(|g| {
        g.metodo == "stream.session"
            && g.codigo == "DENY_NOT_AUTHENTICATED"
            && g.detalhe.starts_with("chave fora do registro")
    });
    let ao_gate = d
        .gravados(antes_d)
        .any(|g| g.titular == "device" && g.metodo.starts_with("stream."));
    if !recusa || ao_gate {
        return Err(format!(
            "o destino nao gravou a recusa do aperto do meio ({recusa}), ou um pedido dele chegou ao gate ({ao_gate})"
        ));
    }
    Ok(
        "FB09 homem no meio: ele nao abriu a 1a mensagem da origem; o destino recusou a chave dele no aperto, gravado; a origem nao abriu a 2a mensagem dele e o fluxo acabou com `o aperto com o par falhou`; nada chegou ao gate de B"
            .into(),
    )
}

/// FB06: o teto `remoto` sem a intenção, posto no meio do fluxo.
fn fb06(b: &mut Bancada) -> Result<String, String> {
    let antes_d = b.destino().marca()?.auditoria;
    let (desde_a, desde_b) = b.lento_ate_o_meio()?;
    let sem = r#"{"line":"recurso remoto fabric.stream intencao:pdf.anotar"}"#;
    let com = format!(
        r#"{{"line":"recurso remoto fabric.stream intencao:{INTENCAO} intencao:pdf.anotar"}}"#
    );
    let mudou = b.destino().executar("policy.write", sem);
    let fins = mudou.and_then(|()| b.lento_ate_o_fim(desde_a, desde_b));
    b.destino().executar("policy.write", &com)?;
    let (r, l) = fins?;
    b.acabou_com(&r, &l, "par: DENY_", "DENY_")?;
    b.fim_gravado(false, antes_d, "DENY_")?;
    let recusado = b.par.destino.gravados(antes_d).any(|g| {
        g.metodo == "stream.write" && g.titular == "device" && g.codigo.starts_with("DENY_")
    });
    if !recusado {
        return Err("o destino nao gravou o dados recusado pelo teto remoto".into());
    }
    Ok(format!(
        "FB06 politica: o teto remoto sem {INTENCAO}, no meio do fluxo, recusou o dados seguinte em B ({}); o fluxo acabou nos dois; a linha voltou",
        l.motivo_do_fim()
    ))
}

/// FB05: a suspensão no destino e o esquecimento na origem, no meio.
fn fb05(b: &mut Bancada) -> Result<String, String> {
    use politica::fluxo::motivo;
    let suspenso = format!(r#"{{"device":"{DISPOSITIVO}"}}"#);
    // A suspensão, no destino.
    let antes_d = b.destino().marca()?.auditoria;
    let (desde_a, desde_b) = b.lento_ate_o_meio()?;
    b.destino().executar("device.suspend", &suspenso)?;
    let fins = b.lento_ate_o_fim(desde_a, desde_b);
    b.destino().executar("device.resume", &suspenso)?;
    let (r, l) = fins?;
    b.acabou_com(
        &r,
        &l,
        &format!("par: {}", motivo::DISPOSITIVO_SUSPENSO),
        motivo::DISPOSITIVO_SUSPENSO,
    )?;
    b.fim_gravado(false, antes_d, motivo::DISPOSITIVO_SUSPENSO)?;
    let suspenso_em_a = r.motivo_do_fim().to_string();
    // O esquecimento, na origem, pela pessoa, no Terminal.
    let antes_o = b.origem().marca()?.auditoria;
    let (desde_a, desde_b) = b.lento_ate_o_meio()?;
    let codigo = b
        .origem()
        .decidido(
            &format!(r#"device.forget {{"device":"{DISPOSITIVO}"}}"#),
            "device.forget",
            DISPOSITIVO,
        )?
        .codigo;
    let fins = b.lento_ate_o_fim(desde_a, desde_b);
    // A relação de volta na origem, pelo administrador.
    let (da_destino, pessoa, relacao) = (
        b.par.da_destino,
        b.par.pessoa.clone(),
        b.par.relacao.clone(),
    );
    enlace::registrar(b.origem(), &da_destino, &pessoa, &relacao, Some(ENDERECO))?;
    if codigo != "ALLOW" {
        return Err(format!("o device.forget da pessoa foi {codigo}"));
    }
    let (r, l) = fins?;
    b.acabou_com(
        &r,
        &l,
        motivo::RELACAO,
        &format!("par: {}", motivo::RELACAO),
    )?;
    b.fim_gravado(true, antes_o, motivo::RELACAO)?;
    Ok(format!(
        "FB05 suspensao e esquecimento: suspenso no destino, o fluxo acabou nos dois (`{suspenso_em_a}` em A); retomado; a pessoa esqueceu o par na origem, e o fluxo acabou nos dois (`{}` em B); a relacao registrada de novo",
        l.motivo_do_fim()
    ))
}

/// FB07: o corte de energia do destino no meio do fluxo.
fn fb07(b: &mut Bancada, maquina_b: &Maquina) -> Result<String, String> {
    use politica::fluxo::motivo;
    let (desde_a, _) = b.lento_ate_o_meio()?;
    b.par.religar_o_destino(maquina_b)?;
    let r = ate_o_fim(b.origem(), desde_a, "remetente", ESPERA_PELO_FIM)?;
    if r.codigo != REMETENTE_FALHOU || r.motivo_do_fim() != motivo::CONEXAO {
        return Err(format!(
            "cortado o destino, a origem nao ouviu `{}`\n  {}",
            motivo::CONEXAO,
            r.texto()
        ));
    }
    // Depois do boot, nada do fluxo voltou: nenhum registro de fluxo, nenhum
    // processo, nenhum fluxo vivo. A auditoria é persistente — os registros
    // de antes do corte voltam com o journal —, e o boot novo começa no
    // `persistence.open` dele.
    let d = b.destino();
    d.ler()?;
    let boot = d
        .ultimo_com("persistence.open")
        .ok_or("depois do boot, o destino nao gravou o persistence.open")?;
    if let Some(g) = d.gravados(boot).find(|g| g.metodo.starts_with("stream.")) {
        return Err(format!(
            "depois do boot, o destino gravou {} {} | {}",
            g.metodo, g.recurso, g.detalhe
        ));
    }
    let [vivos, ..] = medidas_do_fluxo(d)?;
    let processos = encerrar(d, &["recebedor-lento"])?;
    if vivos != 0 || processos != 0 {
        return Err(format!(
            "depois do boot, o destino tem {vivos} fluxos e {processos} recebedores"
        ));
    }
    b.par.destino_escuta(true)?;
    b.destino().entrar()?;
    Ok(format!(
        "FB07 corte: o destino cortado no meio; a origem ouviu `{}`; depois do boot, nenhum fluxo, nenhum registro de fluxo, nenhum processo — e a relacao voltou do journal",
        r.motivo_do_fim()
    ))
}

/// FB08: as vagas da 7071 entre os fluxos, o enlace e a cerimônia.
fn fb08(b: &mut Bancada) -> Result<String, String> {
    // O outro dispositivo da mesma pessoa, no destino.
    let privada = super::aleatorios()?;
    let mut rel = [0u8; 16];
    rel.copy_from_slice(&super::aleatorios()?[..16]);
    let relacao2 = sigilo::hex_de(&rel);
    let pessoa = b.par.pessoa.clone();
    b.destino().executar(
        "device.register",
        &format!(
            r#"{{"key":"{}","name":"{OUTRO}","person":"{pessoa}","role":"{PAPEL}","relation":"{relacao2}"}}"#,
            sigilo::hex(&sigilo::publica_de(&privada))
        ),
    )?;
    // Um fluxo da origem, de pé no lento.
    let (desde_a, desde_b) = b.lento_ate_o_meio()?;
    let endpoint = b
        .par
        .destino
        .ditas_com_hora(desde_b, "recebedor-lento: endpoint ")
        .first()
        .map(|(_, e)| e.clone())
        .ok_or("o endpoint do lento sumiu")?;
    let duke = b.par.da_destino;
    let porta = b.porta_do_destino;
    let r = (|| -> Result<String, String> {
        // O segundo fluxo, do outro dispositivo, aceito pelo lento na pausa.
        let mut segundo = match apertar_cru(porta, &privada, &duke)? {
            Ok(s) => s,
            Err(m) => return Err(format!("o aperto do outro dispositivo foi recusado: {m}")),
        };
        segundo.mandar(&abrir_cru(&relacao2, &endpoint))?;
        let aceito = segundo.receber()?;
        if aceito.first() != Some(&2) {
            return Err(format!(
                "o segundo fluxo nao foi aceito: {}",
                String::from_utf8_lossy(&aceito)
            ));
        }
        // A terceira sessão de fluxo: recusada antes do aperto.
        let terceira = match apertar_cru(porta, &privada, &duke)? {
            Ok(_) => return Err("a terceira sessao de fluxo fez o aperto".into()),
            Err(m) => m,
        };
        if terceira != "sessoes de fluxo demais; tente depois" {
            return Err(format!(
                "a terceira sessao foi recusada por outro motivo: {terceira}"
            ));
        }
        // Uma cerimônia do D8 acha vaga: o pedido da chave é atendido pelo
        // pareamento — sem janela aberta, a recusa dele.
        let mut c = TcpStream::connect(("127.0.0.1", porta))
            .map_err(|e| format!("a cerimonia nao conectou: {e}"))?;
        let _ = c.set_read_timeout(Some(Duration::from_secs(60)));
        escrever_quadro(&mut c, Tipo::PedidoDaChave, &[])?;
        let cerimonia = match ler_quadro(&mut c) {
            Ok(Some((t, corpo))) if t == Tipo::Recusa as u8 => {
                String::from_utf8_lossy(&corpo).into_owned()
            }
            outro => return Err(format!("a cerimonia nao foi atendida: {outro:?}")),
        };
        if cerimonia != "sem janela de pareamento aberta" {
            return Err(format!("a cerimonia nao chegou ao pareamento: {cerimonia}"));
        }
        // Um pedido do estágio 1 acha vaga: o carteiro procura no par.
        let carteiro = b.par.carteiro()?;
        let achou = carteiro
            .dito("achei ")
            .and_then(|n| n.trim().parse::<usize>().ok())
            .unwrap_or(0);
        if achou == 0 {
            return Err(format!(
                "o pedido do estagio 1 nao achou vaga: {}",
                carteiro.texto()
            ));
        }
        drop(segundo);
        Ok(format!(
            "FB08 vagas: dois fluxos abertos no destino (da origem e de {OUTRO}); a terceira sessao recusada antes do aperto (`{terceira}`); a cerimonia do D8 atendida pelo pareamento (`{cerimonia}`); o carteiro do estagio 1 achou {achou} pela vaga que sobrou"
        ))
    })();
    // O fluxo lento até o fim, como for: o da origem, até o fim.
    let fins = b.lento_ate_o_fim(desde_a, desde_b);
    let feito = r?;
    let (rr, l) = fins?;
    if rr.codigo != REMETENTE_OK || l.codigo != LENTO_OK {
        return Err(format!(
            "o fluxo da origem nao terminou bem com as vagas cheias\n  {}\n  {}",
            rr.texto(),
            l.texto()
        ));
    }
    if l.dito("aceitei mais ").is_none() {
        return Err(format!(
            "o lento nao aceitou o segundo fluxo: {}",
            l.texto()
        ));
    }
    Ok(feito)
}

/// FB04: a revogação no destino no meio do fluxo; depois na origem.
fn fb04(b: &mut Bancada) -> Result<String, String> {
    use politica::fluxo::motivo;
    let antes_d = b.destino().marca()?.auditoria;
    let (desde_a, desde_b) = b.lento_ate_o_meio()?;
    b.destino()
        .executar("device.revoke", &format!(r#"{{"name":"{NOME}"}}"#))?;
    let (r, l) = b.lento_ate_o_fim(desde_a, desde_b)?;
    b.acabou_com(
        &r,
        &l,
        &format!("par: {}", motivo::DISPOSITIVO_REVOGADO),
        motivo::DISPOSITIVO_REVOGADO,
    )?;
    let no_meio = r.motivo_do_fim().to_string();
    b.fim_gravado(false, antes_d, motivo::DISPOSITIVO_REVOGADO)?;
    // Na origem: o pedido recusado aqui, sem rede.
    b.origem()
        .executar("device.revoke", &format!(r#"{{"name":"{NOME}"}}"#))?;
    let (antes_o, antes_d): (Marca, Marca) = (b.origem().marca()?, b.destino().marca()?);
    let r = b.remetente()?;
    let recusa = r.dito("abrir ").unwrap_or("");
    if r.codigo != REMETENTE_FALHOU || !recusa.starts_with("DENY_RESOURCE ") {
        return Err(format!(
            "revogado na origem, o stream.open nao foi recusado aqui: {}",
            r.texto()
        ));
    }
    b.par.sem_rede(antes_o, antes_d)?;
    if b.par
        .destino
        .gravados(antes_d.auditoria)
        .any(|g| g.metodo.starts_with("stream."))
    {
        return Err("revogado na origem, um fluxo chegou ao destino".into());
    }
    Ok(format!(
        "FB04 revogacao: no destino, no meio, o fluxo acabou nos dois (`{no_meio}` em A); na origem, o stream.open recusado aqui ({recusa}), sem conexao nem aperto"
    ))
}

/// Os passos de um par, em ordem: cada um diz o que conferiu, na hora.
fn um_par(
    origem: Arquitetura,
    destino: Arquitetura,
    release: bool,
    nome: &str,
) -> Result<(), String> {
    let porta_do_destino = enlace::porta_livre()?;
    let ponte = super::raiz_do_projeto().join(super::canal_tcp::PONTE);
    let ponte = ponte.display().to_string();
    if ponte.contains([',', ' ']) {
        return Err(format!(
            "o caminho da ponte nao cabe na opcao do emulador: {ponte}"
        ));
    }
    let privada_b = super::aleatorios()?;
    let meio = Meio::ligar(porta_do_destino, sigilo::publica_de(&privada_b))?;
    let a = Maquina::nova(
        BANCADA,
        "origem",
        origem,
        release,
        super::aleatorios()?,
        format!(
            "guestfwd=tcp:10.0.2.100:{}-cmd:python3 {ponte} {}",
            enlace::PORTA_DO_ENLACE,
            meio.porta
        ),
    )?;
    let b = Maquina::nova(
        BANCADA,
        "destino",
        destino,
        release,
        privada_b,
        format!(
            "hostfwd=tcp:127.0.0.1:{porta_do_destino}-:{}",
            enlace::PORTA_DO_ENLACE
        ),
    )?;
    let (id, _, _) = chaves::Chaves::garantir()?.pessoa_dev();
    let mut relacao = [0u8; 16];
    relacao.copy_from_slice(&super::aleatorios()?[..16]);
    let mut bancada = Bancada {
        par: Par {
            da_origem: a.publica(),
            da_destino: b.publica(),
            relacao: sigilo::hex_de(&relacao),
            pessoa: sigilo::pessoas::IdPessoa(id).texto(),
            atestado: enlace::atestado_do_carteiro(origem)?,
            ultimo: None,
            medidas: Vec::new(),
            origem: a.ligar()?,
            destino: b.ligar()?,
        },
        meio,
        porta_do_destino,
        remetente: enlace::atestado_de(origem, "remetente")?,
        medidas: Vec::new(),
    };
    let r = passos(&mut bancada, &b, nome);
    if r.is_err() {
        bancada.par.origem.mostrar();
        bancada.par.destino.mostrar();
    }
    println!("  [fluxo]   {}", enlace::o_teclado(&a, &b));
    let Bancada { par, .. } = bancada;
    let _ = par.origem.m.cortar_a_energia();
    let _ = par.destino.m.cortar_a_energia();
    r
}

/// O armazém compartilhado de `quem`, onde o `recebedor` grava: pela
/// serial, que é o sistema.
pub(crate) fn armazem_compartilhado(quem: &mut DePe) -> Result<(), String> {
    let r = quem
        .m
        .pedir("fs.stat", r#"{"path":"/armazem/compartilhado"}"#)?;
    let existe = super::persistencia::texto_do_resultado(&r, "version")
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|v| v > 0);
    if !existe {
        let r = quem
            .m
            .pedir("fs.mkdir", r#"{"path":"/armazem/compartilhado"}"#)?;
        if r.contains(r#""error""#) {
            return Err(format!(
                "{}: o armazem compartilhado nao foi criado\n  {r}",
                quem.papel
            ));
        }
    }
    Ok(())
}

/// Os passos, sobre o par de pé. `maquina_b` é a do destino, para religá-la.
/// Cada passo feito é dito na hora, com o nome do par.
fn passos(b: &mut Bancada, maquina_b: &Maquina, nome: &str) -> Result<(), String> {
    let feito = |f: String| println!("  [fluxo] ok  {nome}: {f}");
    armazem_compartilhado(b.origem())?;
    armazem_compartilhado(b.destino())?;
    // 1. FB01, local, na origem.
    b.origem().entrar()?;
    feito(fb01(b)?);
    // 2. O registro, com prova, nos dois; a pessoa no destino.
    let (da_origem, da_destino) = (b.par.da_origem, b.par.da_destino);
    let (pessoa, relacao) = (b.par.pessoa.clone(), b.par.relacao.clone());
    enlace::registrar(b.destino(), &da_origem, &pessoa, &relacao, None)?;
    enlace::registrar(b.origem(), &da_destino, &pessoa, &relacao, Some(ENDERECO))?;
    b.par.destino_escuta(true)?;
    b.destino().entrar()?;
    feito(format!(
        "a relacao {} registrada com prova nos dois; o destino escuta a {}",
        &relacao[..8],
        enlace::PORTA_DO_ENLACE
    ));
    // 3. FB02 … 11. FB04.
    feito(fb02(b)?);
    feito(fb03(b)?);
    feito(fb10(b)?);
    feito(fb09(b)?);
    feito(fb06(b)?);
    feito(fb05(b)?);
    feito(fb07(b, maquina_b)?);
    feito(fb08(b)?);
    feito(fb04(b)?);
    feito(format!("medidas: {}", b.medidas.join("; ")));
    Ok(())
}

/// `cargo xtask fluxo`: os pares escolhidos, um de cada vez.
pub(crate) fn fluxo(release: bool) -> Result<ExitCode, String> {
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
        "[xtask] fluxo: {} pares, duas maquinas de pe em cada",
        escolhidos.len()
    );
    let mut falhas = 0;
    for par in &escolhidos {
        let (origem, destino) = *par;
        println!("[xtask] fluxo: {}", nome(par));
        super::incidente::no_cenario("fluxo", &nome(par));
        let comeco = Instant::now();
        match um_par(origem, destino, release, &nome(par)) {
            Ok(()) => {
                println!(
                    "  [fluxo] ok  {}: o par inteiro em {} s",
                    nome(par),
                    comeco.elapsed().as_secs()
                );
            }
            Err(motivo) => {
                falhas += 1;
                println!("  [fluxo] FALHOU  {}: {motivo}", nome(par));
            }
        }
    }
    let base = super::raiz_do_projeto().join("target").join(BANCADA);
    for papel in ["origem", "destino"] {
        let _ = std::fs::remove_file(base.join(format!("{papel}.img")));
    }
    if falhas > 0 {
        println!("\n[xtask] fluxo: {falhas} par(es) falharam");
        return Ok(ExitCode::FAILURE);
    }
    println!("\n[xtask] fluxo: todos os pares passaram");
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod testes {
    use super::*;

    /// O padrão e o resumo da bancada são os dos programas: o FNV-1a dos
    /// bytes do padrão, e o base64 padrão.
    #[test]
    fn o_padrao_e_o_resumo() {
        assert_eq!(padrao(0, 0), 3);
        assert_eq!(padrao(0, 1), 10);
        assert_eq!(padrao(1, 0), 4);
        assert_eq!(padrao(0, 36), ((36 * 7 + 3) % 251) as u8);
        assert_eq!(resumo(0, 0), "cbf29ce484222325");
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
        assert_eq!(base64(&[3, 10, 17, 24, 31, 38]), "AwoRGB8m");
    }

    /// A mensagem `abrir` crua tem a forma que a sessão do Duke lê: o tipo
    /// 1 e os cinco campos.
    #[test]
    fn o_abrir_cru() {
        let m = abrir_cru(&"f1".repeat(16), "e:1");
        assert_eq!(m[0], 1);
        let json = String::from_utf8(m[1..].to_vec()).unwrap();
        for campo in ["relation", "program", "endpoint", "intent", "epoch"] {
            assert!(json.contains(&format!(r#""{campo}":""#)), "{json}");
        }
    }
}
