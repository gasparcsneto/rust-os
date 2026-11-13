//! A bancada do pareamento: `cargo xtask pareamento`.
//!
//! A cerimônia de pareamento da Pessoa entre dois Dukes de pé ao mesmo tempo
//! — cada um com o disco, o TPM e a chave do Duke dele —, sem administrador
//! nenhum no caminho: a Pessoa entra no Terminal de cada um pelo teclado,
//! abre a cerimônia (`aceitar` no destino, `parear` na origem), lê o código
//! que cada tela mostra e o digita no **outro**, e confirma com a própria
//! senha. A bancada faz o papel da Pessoa, e só o dela: lê a tela pela árvore
//! semântica e digita pelo `sendkey` do monitor.
//!
//! A rede é a da bancada do enlace — a origem conecta a `10.0.2.100:7071`, o
//! `guestfwd` dela roda a ponte da bancada (`xtask/bancada/ponte.py`) até o
//! hospedeiro, e o `hostfwd` do destino leva à 7071 dele —, com uma **ponte
//! do meio** no hospedeiro entre as duas ([`Meio`]): ela passa os bytes; ou
//! faz o homem no meio, um aperto com cada lado com uma chave dela; ou passa
//! tudo menos os dados que o destino manda à origem depois do aperto.
//!
//! Em cada par, numa ordem só, porque cada passo parte do anterior:
//!
//! 1. **B02**, o código errado: a cerimônia acaba nos dois, nada gravado em
//!    nenhum; a 7071 do destino só escuta com a janela aberta;
//! 2. **B03**, o homem no meio: a ponte responde ao pedido da chave com a
//!    dela e faz um aperto com cada lado; cada tela mostra a impressão dela,
//!    os códigos não conferem, nada gravado, e a auditoria dos dois conta;
//! 3. **B01**, a cerimônia: a mesma relação nos dois, e a entrega do
//!    Estágio 1 (`carteiro` → `correio`) por ela;
//! 4. **B05**, o corte dos dois: a relação pareada volta do journal, e a
//!    entrega funciona sem nada de novo;
//! 5. **B06**, esquecer de um lado: o destino esquece, a origem não sabe de
//!    nada e passa a ouvir `DENY_NOT_AUTHENTICATED`; a origem esquece também;
//! 6. **B04**, o corte durante a cerimônia: nada em nenhum lado, e o
//!    esquecido continua esquecido; e o corte depois de um lado gravar: a
//!    meia relação aparece no `device.registry` de quem gravou, sobrevive ao
//!    corte, não serve a ninguém, e sai com `device.forget`;
//! 7. **B05**, a lápide: a chave revogada não pareia, nem depois do boot.
//!
//! Os pares: `x86_64>aarch64`, `aarch64>x86_64`, `x86_64>x86_64` e
//! `aarch64>aarch64` — todos, ou os que `DUKE_PARES` escolhe, separados por
//! `|`. A origem inicia (`parear`); o destino aceita (`aceitar`).

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use politica::pareamento as conta;
use sigilo::quadro::{self, Tipo};

use super::digitacao::{self, PROMPT, PROMPT_DA_SENHA, Tela, fim_da_tela, ultima_linha};
use super::enlace::{self, DePe, Gravado, Maquina, Par};
use super::{Arquitetura, chaves};

/// O nome das raízes de estado e dos discos desta bancada, em `target/`.
const BANCADA: &str = "pareamento";

/// Como cada Duke chama o outro, o papel da relação e o endereço do destino
/// para a origem: os da bancada do enlace, que a política padrão enumera.
const NOME: &str = enlace::NOME;
const PAPEL: &str = enlace::PAPEL;
const ENDERECO: &str = enlace::ENDERECO;

/// O outro dispositivo do destino, que o administrador registra antes de o
/// destino esquecer o par — ver [`esquecer_de_um_lado`].
const OUTRO: &str = "par-2";

/// O que a linha de cada passo da cerimônia mostra, como
/// `kernel/src/interpretador.rs` os escreve: o código do outro, e a linha da
/// cerimônia aberta. O do comando e o da senha são os de [`digitacao`].
const PROMPT_DO_CODIGO: &str = "codigo do outro: ";
const PROMPT_DO_PAREAMENTO: &str = "pareamento (linha vazia desiste): ";

/// O texto dos códigos, como `kernel/src/pareamento.rs` o escreve: a linha
/// com a impressão do par e a deste Duke, e a com o código a digitar no
/// outro.
const PAREANDO_COM: &str = "pareando com ";
const ESTE_DUKE: &str = "; este Duke e ";
const DIGITE: &str = "No outro dispositivo, digite: ";

/// Quanto esperar cada coisa: os códigos nas duas telas (o fio da origem
/// conecta pelo gate, pela ponte, e faz o aperto), o fim de uma cerimônia,
/// e a linha da cerimônia de volta à tela.
const ESPERA_PELOS_CODIGOS: Duration = Duration::from_secs(90);
const ESPERA_PELO_FIM: Duration = Duration::from_secs(90);
const ESPERA_PELA_LINHA: Duration = Duration::from_secs(20);

/// Quantas vezes abrir uma cerimônia que a de antes, ainda saindo, ocupa, e
/// o respiro entre uma e outra — ver [`Bancada::abrir`].
const VEZES_DE_ABRIR: usize = 6;
const RESPIRO_DO_CONFLITO: Duration = Duration::from_secs(3);

/// Quanto o homem no meio espera cada lado falar.
const ESPERA_NO_MEIO: Duration = Duration::from_secs(200);

/// Os pares, na ordem em que rodam: origem e destino.
const PARES: [(Arquitetura, Arquitetura); 4] = [
    (Arquitetura::X86_64, Arquitetura::Aarch64),
    (Arquitetura::Aarch64, Arquitetura::X86_64),
    (Arquitetura::X86_64, Arquitetura::X86_64),
    (Arquitetura::Aarch64, Arquitetura::Aarch64),
];

fn travar<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A impressão de uma chave, como os Dukes a mostram: os oito primeiros
/// dígitos dela (`identidade::impressao`).
fn impressao(chave: &[u8; 32]) -> String {
    sigilo::hex(chave)[..8].to_string()
}

// ---------------------------------------------------------------------------
// A ponte do meio
// ---------------------------------------------------------------------------

/// O que a ponte do meio faz com a próxima conexão da origem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Modo {
    /// Passa os bytes nos dois sentidos, sem olhar: a rede da bancada do
    /// enlace.
    Passar,
    /// O homem no meio: atende a origem como se fosse o destino, e o
    /// destino como se fosse a origem, com uma chave dela — ver [`no_meio`].
    NoMeio,
    /// Passa tudo, menos os quadros de dados do destino para a origem: o
    /// aperto fecha, os códigos aparecem, e a origem nunca ouve o
    /// `conferido` nem o `gravado` de lá.
    SegurarODestino,
}

/// O que o homem no meio viu e calculou na última cerimônia.
#[derive(Clone, Debug, Default)]
struct VistoNoMeio {
    /// A pública dele, que ele anunciou à origem e provou ao destino.
    chave: Option<[u8; 32]>,
    /// A estática que a origem provou a ele.
    da_origem: Option<[u8; 32]>,
    /// Os códigos de cada aperto, como `conta::codigos` os dá: o que o lado
    /// que aceita mostra, e o que o que inicia mostra. Com a origem, ele é
    /// quem aceita; com o destino, quem inicia.
    com_a_origem: Option<(u32, u32)>,
    com_o_destino: Option<(u32, u32)>,
    /// Os nonces dos dois apertos, em hex: o da origem e o dele.
    nonces: Vec<String>,
    /// O que cada lado disse a ele depois do aperto, aberto.
    ouviu_da_origem: Vec<String>,
    ouviu_do_destino: Vec<String>,
    /// Onde a conversa dele parou, se parou antes da hora.
    erro: Option<String>,
}

/// A ponte do meio: escuta numa porta do hospedeiro — a que a ponte da
/// origem procura — e, a cada conexão, conecta ao `hostfwd` do destino.
struct Meio {
    porta: u16,
    modo: Arc<Mutex<Modo>>,
    visto: Arc<Mutex<VistoNoMeio>>,
    parar: Arc<AtomicBool>,
}

impl Meio {
    /// Abre a porta e o fio que a atende. `porta_do_destino` é a do
    /// `hostfwd` do destino.
    fn ligar(porta_do_destino: u16) -> Result<Meio, String> {
        let ouvinte = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|e| format!("a ponte do meio nao abriu porta: {e}"))?;
        let porta = ouvinte
            .local_addr()
            .map_err(|e| format!("a ponte do meio sem endereco: {e}"))?
            .port();
        let modo = Arc::new(Mutex::new(Modo::Passar));
        let visto = Arc::new(Mutex::new(VistoNoMeio::default()));
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
                std::thread::spawn(move || match agora {
                    Modo::Passar => passar(origem, porta_do_destino, false),
                    Modo::SegurarODestino => passar(origem, porta_do_destino, true),
                    Modo::NoMeio => {
                        *travar(&v) = VistoNoMeio::default();
                        if let Err(e) = no_meio(origem, porta_do_destino, &v) {
                            travar(&v).erro = Some(e);
                        }
                    }
                });
            }
        });
        Ok(Meio {
            porta,
            modo,
            visto,
            parar,
        })
    }

    fn modo(&self, modo: Modo) {
        *travar(&self.modo) = modo;
    }

    fn visto(&self) -> VistoNoMeio {
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

/// Passa os bytes da `origem` ao destino e de volta, cada sentido no seu
/// fio, até os dois lados fecharem — como a ponte da bancada. Com
/// `segurar`, os quadros de dados do destino não chegam à origem.
fn passar(origem: TcpStream, porta_do_destino: u16, segurar: bool) {
    let Ok(destino) = TcpStream::connect(("127.0.0.1", porta_do_destino)) else {
        let _ = origem.shutdown(Shutdown::Both);
        return;
    };
    let (Ok(o), Ok(d)) = (origem.try_clone(), destino.try_clone()) else {
        return;
    };
    let volta = std::thread::spawn(move || {
        if segurar {
            copiar_sem_dados(d, o);
        } else {
            copiar(d, o);
        }
    });
    copiar(origem, destino);
    let _ = volta.join();
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

/// Como [`copiar`], quadro a quadro, sem os de dados.
fn copiar_sem_dados(mut de: TcpStream, mut para: TcpStream) {
    while let Ok(Some((tipo, corpo))) = ler_quadro(&mut de) {
        if tipo == Tipo::Dados as u8 {
            continue;
        }
        let tam = corpo.len() as u16;
        let mut q = vec![tipo];
        q.extend_from_slice(&tam.to_be_bytes());
        q.extend_from_slice(&corpo);
        if para.write_all(&q).is_err() {
            break;
        }
    }
    let _ = para.shutdown(Shutdown::Write);
}

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

fn escrever_quadro(s: &mut TcpStream, tipo: Tipo, corpo: &[u8]) -> Result<(), String> {
    let q = quadro::montar(tipo, corpo).map_err(|e| format!("quadro: {}", e.motivo()))?;
    s.write_all(&q)
        .map_err(|e| format!("a ponte do meio nao escreveu: {e}"))
}

/// O próximo quadro, que tem de ser do tipo `tipo`; o corpo.
fn esperar_quadro(s: &mut TcpStream, tipo: Tipo, de: &str) -> Result<Vec<u8>, String> {
    match ler_quadro(s) {
        Ok(Some((t, corpo))) if t == tipo as u8 => Ok(corpo),
        Ok(Some((t, corpo))) if t == Tipo::Recusa as u8 => {
            Err(format!("{de} recusou: {}", String::from_utf8_lossy(&corpo)))
        }
        Ok(Some((t, _))) => Err(format!("{de} mandou o quadro {t}, e nao o {tipo:?}")),
        Ok(None) => Err(format!("{de} fechou antes do {tipo:?}")),
        Err(e) => Err(format!("{de}: {e}")),
    }
}

/// O texto do campo `nome` de um objeto JSON plano de textos.
fn campo<'t>(json: &'t str, nome: &str) -> Option<&'t str> {
    let resto = super::apos(json, &format!(r#""{nome}":""#))?;
    resto.find('"').map(|f| &resto[..f])
}

fn dezesseis(bytes: &[u8; 32]) -> [u8; 16] {
    let mut w = [0u8; 16];
    w.copy_from_slice(&bytes[..16]);
    w
}

/// O homem no meio, numa conexão da origem.
///
/// À origem, ele é o Duke que aceita: responde ao pedido da chave com a
/// pública dele e um desafio dele, e responde à primeira mensagem do IK —
/// o aperto fecha com a chave dele, e a origem prova a dela. Ao destino, ele
/// é quem inicia: pede a chave de lá, e faz o aperto com a chave dele, o
/// compromisso de um nonce dele e o desafio de lá. Os dois nonces abertos,
/// cada lado mostra um código — do aperto com ele. Daí em diante ele só
/// ouve: não há o que passar que faça a Pessoa digitar, num lado, o código
/// que o outro calcula.
fn no_meio(
    mut a: TcpStream,
    porta_do_destino: u16,
    visto: &Arc<Mutex<VistoNoMeio>>,
) -> Result<(), String> {
    let _ = a.set_read_timeout(Some(ESPERA_NO_MEIO));
    esperar_quadro(&mut a, Tipo::PedidoDaChave, "a origem")?;
    let mut b = TcpStream::connect(("127.0.0.1", porta_do_destino))
        .map_err(|e| format!("o meio nao conectou ao destino: {e}"))?;
    let _ = b.set_read_timeout(Some(ESPERA_NO_MEIO));
    escrever_quadro(&mut b, Tipo::PedidoDaChave, &[])?;
    let anuncio = esperar_quadro(&mut b, Tipo::ChaveDoDuke, "o destino")?;
    if anuncio.len() != 32 + conta::TAM_DESAFIO {
        return Err(format!("o anuncio do destino tem {} bytes", anuncio.len()));
    }
    let mut do_destino = [0u8; 32];
    do_destino.copy_from_slice(&anuncio[..32]);
    let desafio_de_la = &anuncio[32..];

    // A chave dele, e o anúncio à origem.
    let privada = super::aleatorios()?;
    let chave = sigilo::publica_de(&privada);
    travar(visto).chave = Some(chave);
    let mut o_dele = chave.to_vec();
    o_dele.extend_from_slice(&dezesseis(&super::aleatorios()?));
    escrever_quadro(&mut a, Tipo::ChaveDoDuke, &o_dele)?;

    // O aperto com a origem: ele responde, com a chave dele.
    let primeira = esperar_quadro(&mut a, Tipo::InicioPareamento, "a origem")?;
    let mut carga = vec![0u8; primeira.len()];
    let (n, recebido) = sigilo::Respondedor::novo(sigilo::PROLOGO_DO_PAREAMENTO, &privada)
        .ler(&primeira, &mut carga)
        .map_err(|e| format!("a 1a mensagem da origem nao abriu no meio: {}", e.motivo()))?;
    travar(visto).da_origem = Some(recebido.remota());
    let carga = String::from_utf8_lossy(&carga[..n]).into_owned();
    let compromisso = campo(&carga, "commit")
        .and_then(sigilo::de_hex_fixo::<32>)
        .ok_or("a 1a mensagem da origem sem o compromisso")?;
    let mut segunda = vec![0u8; 128];
    let (m, mut com_a_origem) = recebido
        .escrever(super::aleatorios()?, b"{}", &mut segunda)
        .map_err(|e| format!("a 2a mensagem a origem: {}", e.motivo()))?;
    escrever_quadro(&mut a, Tipo::Resposta, &segunda[..m])?;

    // O aperto com o destino: ele inicia, com a chave dele, o compromisso
    // de um nonce dele e o desafio de lá.
    let nonce = super::aleatorios()?;
    let carga = format!(
        r#"{{"commit":"{}","janela":"{}"}}"#,
        sigilo::hex_de(&conta::compromisso(&nonce)),
        sigilo::hex_de(desafio_de_la)
    );
    let mut primeira = vec![0u8; 512];
    let (k, aguardando) =
        sigilo::Iniciador::novo(sigilo::PROLOGO_DO_PAREAMENTO, &privada, &do_destino)
            .escrever(super::aleatorios()?, carga.as_bytes(), &mut primeira)
            .map_err(|e| format!("a 1a mensagem ao destino: {}", e.motivo()))?;
    escrever_quadro(&mut b, Tipo::InicioPareamento, &primeira[..k])?;
    let resposta = esperar_quadro(&mut b, Tipo::Resposta, "o destino")?;
    let mut lixo = vec![0u8; resposta.len()];
    let (_, mut com_o_destino) = aguardando
        .ler(&resposta, &mut lixo)
        .map_err(|e| format!("a 2a mensagem do destino nao abriu: {}", e.motivo()))?;

    // O nonce da origem, aberto; e o dele, ao destino.
    let cifrado = esperar_quadro(&mut a, Tipo::Dados, "a origem")?;
    let mut claro = vec![0u8; cifrado.len()];
    let lido = com_a_origem
        .decifrar(&cifrado, &mut claro)
        .map_err(|e| format!("o nonce da origem nao abriu: {}", e.motivo()))?;
    let mensagem = String::from_utf8_lossy(&claro[..lido]).into_owned();
    let nonce_da_origem = campo(&mensagem, "nonce")
        .and_then(sigilo::de_hex_fixo::<32>)
        .ok_or_else(|| format!("a origem mandou `{mensagem}`, e nao o nonce"))?;
    if conta::compromisso(&nonce_da_origem) != compromisso {
        return Err("o nonce da origem nao e o do compromisso dela".into());
    }
    let dele = format!(r#"{{"nonce":"{}"}}"#, sigilo::hex_de(&nonce));
    let mut cifrado = vec![0u8; dele.len() + 16];
    let c = com_o_destino
        .cifrar(dele.as_bytes(), &mut cifrado)
        .map_err(|e| format!("o nonce ao destino: {}", e.motivo()))?;
    escrever_quadro(&mut b, Tipo::Dados, &cifrado[..c])?;
    {
        let mut v = travar(visto);
        v.com_a_origem = Some(conta::codigos(
            &com_a_origem.resumo_do_aperto(),
            &nonce_da_origem,
        ));
        v.com_o_destino = Some(conta::codigos(&com_o_destino.resumo_do_aperto(), &nonce));
        v.nonces = vec![sigilo::hex_de(&nonce_da_origem), sigilo::hex_de(&nonce)];
    }

    // Daqui em diante, só ouve os dois, até cada um fechar.
    let va = visto.clone();
    let ouvir_a_origem = std::thread::spawn(move || {
        ouvir(&mut a, &mut com_a_origem, |m| {
            travar(&va).ouviu_da_origem.push(m)
        });
    });
    ouvir(&mut b, &mut com_o_destino, |m| {
        travar(visto).ouviu_do_destino.push(m)
    });
    let _ = ouvir_a_origem.join();
    Ok(())
}

/// Lê e abre os quadros de um lado até ele fechar, e fecha a conexão.
fn ouvir(s: &mut TcpStream, t: &mut sigilo::Transporte, mut guardar: impl FnMut(String)) {
    while let Ok(Some((tipo, corpo))) = ler_quadro(s) {
        if tipo != Tipo::Dados as u8 {
            guardar(format!("quadro {tipo}"));
            continue;
        }
        let mut claro = vec![0u8; corpo.len()];
        match t.decifrar(&corpo, &mut claro) {
            Ok(n) => guardar(String::from_utf8_lossy(&claro[..n]).into_owned()),
            Err(_) => guardar("um quadro que nao abriu".into()),
        }
    }
    let _ = s.shutdown(Shutdown::Both);
}

// ---------------------------------------------------------------------------
// A Pessoa diante da tela
// ---------------------------------------------------------------------------

/// O texto do Terminal de `quem`, como a árvore semântica o publica: as
/// linhas de baixo da grade, até o teto do valor de um elemento.
fn tela(quem: &mut DePe) -> Result<String, String> {
    let arvore = quem.m.pedir("ui.tree", "{}")?;
    digitacao::texto_da_tela(&arvore, Tela::Terminal).ok_or_else(|| {
        format!(
            "{}: a arvore semantica nao mostra o Terminal\n  {}",
            quem.papel,
            &arvore[..arvore.len().min(600)]
        )
    })
}

/// Espera a tela de `quem` satisfazer `f`, e a devolve.
fn esperar_tela(
    quem: &mut DePe,
    espera: Duration,
    o_que: &str,
    f: impl Fn(&str) -> bool,
) -> Result<String, String> {
    let limite = Instant::now() + espera;
    loop {
        let t = tela(quem)?;
        if f(&t) {
            return Ok(t);
        }
        if Instant::now() >= limite {
            return Err(format!(
                "{}: {o_que}, nao em {} s; a tela:\n{}",
                quem.papel,
                espera.as_secs(),
                fim_da_tela(&t)
            ));
        }
        std::thread::sleep(Duration::from_millis(400));
    }
}

/// O que a tela de um Duke mostra quando a cerimônia chega aos códigos.
#[derive(Clone, Debug)]
struct Codigos {
    /// O código que ela manda digitar no outro, como ela o mostra.
    mostrado: String,
    /// A impressão do par, e a deste Duke.
    par: String,
    eu: String,
}

/// Os códigos na tela: a última linha pede o código do outro, e o texto mais
/// recente acima dela é o desta cerimônia.
fn codigos_na_tela(tela: &str) -> Option<Codigos> {
    let linhas: Vec<&str> = tela.lines().collect();
    if ultima_linha(tela) != PROMPT_DO_CODIGO.trim_end() {
        return None;
    }
    let i = linhas.iter().rposition(|l| l.starts_with(DIGITE))?;
    let mostrado = linhas[i][DIGITE.len()..].trim().to_string();
    conta::ler_codigo(&mostrado)?;
    let j = linhas[..i]
        .iter()
        .rposition(|l| l.starts_with(PAREANDO_COM) && l.contains(ESTE_DUKE))?;
    let (par, eu) = linhas[j][PAREANDO_COM.len()..].split_once(ESTE_DUKE)?;
    Some(Codigos {
        mostrado,
        par: par.to_string(),
        eu: eu.trim_end_matches('.').to_string(),
    })
}

/// Espera os códigos na tela de `quem`.
fn codigos(quem: &mut DePe) -> Result<Codigos, String> {
    let t = esperar_tela(quem, ESPERA_PELOS_CODIGOS, "os codigos a mostra", |t| {
        codigos_na_tela(t).is_some()
    })?;
    codigos_na_tela(&t).ok_or_else(|| format!("{}: os codigos sumiram da tela", quem.papel))
}

// ---------------------------------------------------------------------------
// A auditoria e o registro
// ---------------------------------------------------------------------------

/// Espera, na auditoria de `quem` depois de `desde`, o primeiro registro
/// que `f` aceita.
fn esperar_gravado(
    quem: &mut DePe,
    desde: u64,
    o_que: &str,
    f: impl Fn(&Gravado) -> bool,
) -> Result<Gravado, String> {
    let limite = Instant::now() + ESPERA_PELO_FIM;
    loop {
        quem.ler()?;
        if let Some(g) = quem.gravados(desde).find(|g| f(g)) {
            return Ok(g.clone());
        }
        if Instant::now() >= limite {
            return Err(format!(
                "{}: {o_que} nao foi gravado em {} s",
                quem.papel,
                ESPERA_PELO_FIM.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// O registro que conta o fim da cerimônia em `quem`, depois de `desde`: a
/// gravação da relação, ou a desfeita.
fn fim(quem: &mut DePe, desde: u64) -> Result<Gravado, String> {
    esperar_gravado(quem, desde, "o fim da cerimonia", |g| {
        g.metodo == "device.pair"
            && (g.detalhe.starts_with("pareado:") || g.detalhe.starts_with("desfeita:"))
    })
}

/// O fim é uma desfeita, por `porque`, com o par de impressão `par`.
fn desfeita(quem: &str, g: &Gravado, porque: &str, par: &str) -> Result<(), String> {
    if g.codigo == "ALLOW"
        || !g.detalhe.starts_with("desfeita: ")
        || !g.detalhe.contains(porque)
        || !g.detalhe.contains(&format!("par {par}"))
    {
        return Err(format!(
            "{quem}: o fim devia ser a desfeita ({porque}, par {par}): {} {}",
            g.codigo, g.detalhe
        ));
    }
    Ok(())
}

/// Uma relação no `device.registry`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Rel {
    relacao: String,
    pessoa: String,
    papel: String,
    endereco: Option<String>,
}

fn valor_plano(campos: &super::ObjetoPlano, nome: &str) -> Option<String> {
    campos
        .iter()
        .find(|(n, _)| n == nome)
        .and_then(|(_, v)| v.clone())
}

/// As chaves com lápide no registro, pela impressão de cada uma.
fn lapides(registro: &str) -> Vec<String> {
    let Some(lista) = super::apos(registro, r#""revoked":["#) else {
        return Vec::new();
    };
    lista[..lista.find(']').unwrap_or(lista.len())]
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// As relações do dispositivo de chave `chave` no registro.
fn relacoes(registro: &str, chave: &[u8; 32]) -> Vec<Rel> {
    let Some(dispositivos) = super::apos(registro, r#""devices":["#) else {
        return Vec::new();
    };
    let dispositivos = dispositivos
        .split(r#""revoked":"#)
        .next()
        .unwrap_or(dispositivos);
    let Some(dele) = super::apos(dispositivos, &format!(r#""key":"{}""#, sigilo::hex(chave)))
    else {
        return Vec::new();
    };
    let Some(lista) = super::apos(dele, r#""relations":["#) else {
        return Vec::new();
    };
    let lista = &lista[..lista.find(']').unwrap_or(lista.len())];
    super::objetos_planos(lista)
        .unwrap_or_default()
        .iter()
        .map(|c| Rel {
            relacao: valor_plano(c, "relation").unwrap_or_default(),
            pessoa: valor_plano(c, "person").unwrap_or_default(),
            papel: valor_plano(c, "role").unwrap_or_default(),
            endereco: valor_plano(c, "address"),
        })
        .collect()
}

/// As relações de `quem` com o dispositivo de chave `chave`.
fn relacoes_em(quem: &mut DePe, chave: &[u8; 32]) -> Result<Vec<Rel>, String> {
    Ok(relacoes(&quem.registro()?, chave))
}

/// A 7071 de `quem` escuta, ou não.
fn escuta(quem: &mut DePe, deve: bool, quando: &str) -> Result<(), String> {
    let registro = quem.registro()?;
    if registro.contains(r#""listening":true"#) != deve {
        return Err(format!(
            "{}: {quando}, a 7071 {} escutar\n  {registro}",
            quem.papel,
            if deve { "devia" } else { "nao devia" }
        ));
    }
    Ok(())
}

/// Os segredos de uma cerimônia — os códigos, com e sem o espaço, e os
/// nonces que se conhecem — não aparecem na auditoria nem no log de `quem`.
fn sem_segredo(quem: &mut DePe, segredos: &[String]) -> Result<(), String> {
    quem.ler()?;
    let log = quem.m.pedir("log.tail", r#"{"count":128}"#)?;
    for s in segredos {
        if let Some(g) = quem
            .gravados(0)
            .find(|g| tem_o_token(&g.detalhe, s) || tem_o_token(&g.recurso, s))
        {
            return Err(format!(
                "{}: o segredo `{s}` na auditoria: {} {}",
                quem.papel, g.metodo, g.detalhe
            ));
        }
        if tem_o_token(&log, s) {
            return Err(format!("{}: o segredo `{s}` no log", quem.papel));
        }
    }
    Ok(())
}

/// `token` aparece em `texto` inteiro: sem um dígito ou letra colado antes
/// ou depois — um número qualquer do log não conta.
fn tem_o_token(texto: &str, token: &str) -> bool {
    texto.match_indices(token).any(|(i, _)| {
        let antes = texto[..i].chars().next_back();
        let depois = texto[i + token.len()..].chars().next();
        !antes.is_some_and(|c| c.is_ascii_alphanumeric())
            && !depois.is_some_and(|c| c.is_ascii_alphanumeric())
    })
}

/// Os segredos de uma lista de códigos de tela: cada um como a tela o
/// mostra e sem o espaço.
fn segredos_dos_codigos(codigos: &[&str]) -> Vec<String> {
    codigos
        .iter()
        .flat_map(|c| [c.to_string(), c.replace(' ', "")])
        .collect()
}

// ---------------------------------------------------------------------------
// A bancada de um par
// ---------------------------------------------------------------------------

/// As duas máquinas, desligadas e de pé, e a ponte do meio.
struct Bancada {
    par: Par,
    a: Maquina,
    b: Maquina,
    meio: Meio,
    senha: String,
}

impl Bancada {
    fn origem(&mut self) -> &mut DePe {
        &mut self.par.origem
    }

    fn destino(&mut self) -> &mut DePe {
        &mut self.par.destino
    }

    /// As duas telas e o log das duas máquinas, para a falha.
    fn mostrar(&mut self) {
        for quem in [&mut self.par.origem, &mut self.par.destino] {
            if let Ok(t) = tela(quem) {
                println!(
                    "  [pareamento]   a tela de {}:\n{}",
                    quem.papel,
                    fim_da_tela(&t)
                );
            }
            quem.mostrar();
        }
        let v = self.meio.visto();
        if v.chave.is_some() || v.erro.is_some() {
            println!("  [pareamento]   o homem no meio: {v:?}");
        }
    }

    /// A Pessoa digita `linha` no Terminal de `quem` — `aceitar` ou
    /// `parear` —, e o gate a decide: a abertura gravada, com o detalhe que
    /// começa com `detalhe`.
    ///
    /// A cerimônia de antes ainda pode estar saindo — o fio da origem espera
    /// o outro fechar, no prazo de um fecho —, e a abertura é recusada com
    /// `CONFLICT`: a Pessoa espera um pouco e digita de novo, como a tela
    /// pede.
    fn abrir(&mut self, origem: bool, linha: &str, detalhe: &str) -> Result<(), String> {
        let quem = if origem {
            self.origem()
        } else {
            self.destino()
        };
        let recurso = format!("dispositivo:{NOME}");
        for _ in 0..VEZES_DE_ABRIR {
            let desde = quem.marca()?.auditoria;
            quem.linha(PROMPT, linha)?;
            let g = esperar_gravado(quem, desde, &format!("a abertura `{linha}`"), |g| {
                g.metodo == "device.pair" && g.recurso == recurso
            })?;
            if g.codigo == "CONFLICT" && g.detalhe.starts_with("outra cerimonia") {
                std::thread::sleep(RESPIRO_DO_CONFLITO);
                continue;
            }
            if g.codigo != "ALLOW" || !g.detalhe.starts_with(detalhe) {
                return Err(format!(
                    "{}: `{linha}` nao abriu a cerimonia: {} {}",
                    quem.papel, g.codigo, g.detalhe
                ));
            }
            return Ok(());
        }
        Err(format!(
            "{}: `{linha}` deu CONFLICT {VEZES_DE_ABRIR} vezes: a cerimonia de antes nao saiu",
            quem.papel
        ))
    }

    /// A Pessoa abre a cerimônia nos dois — `aceitar` no destino, `parear`
    /// na origem —, e os códigos aparecem nas duas telas: os da origem e os
    /// do destino.
    fn ate_os_codigos(&mut self) -> Result<(Codigos, Codigos), String> {
        self.abrir(
            false,
            &format!("aceitar {NOME} {PAPEL}"),
            &format!("janela aberta; papel {PAPEL}"),
        )?;
        self.abrir(
            true,
            &format!("parear {NOME} {ENDERECO} {PAPEL}"),
            &format!("para {ENDERECO}; papel {PAPEL}"),
        )?;
        let a = codigos(self.origem())?;
        let b = codigos(self.destino())?;
        Ok((a, b))
    }

    /// As telas mostram as chaves de verdade: cada uma, a do outro Duke e a
    /// dela.
    fn honestas(&self, a: &Codigos, b: &Codigos) -> Result<(), String> {
        let (da_origem, da_destino) = (
            impressao(&self.par.da_origem),
            impressao(&self.par.da_destino),
        );
        if a.par != da_destino || a.eu != da_origem || b.par != da_origem || b.eu != da_destino {
            return Err(format!(
                "as telas nao mostram as chaves dos dois Dukes: a origem ({da_origem}) mostra {a:?}, o destino ({da_destino}) mostra {b:?}"
            ));
        }
        Ok(())
    }

    /// A Pessoa digita em `quem` o código que a outra tela mostra, e a senha
    /// dela. O teclado do emulador perde tecla com as duas máquinas de pé, e
    /// uma linha da cerimônia não se repete: o código errado — ou fora da
    /// forma — acaba com ela nos dois lados. O código vai conferido na tela
    /// antes do Enter, e a senha, que não ecoa, pela conta das teclas do
    /// kernel — ver [`digitacao`].
    fn confirmar(&mut self, origem: bool, codigo: &str) -> Result<(), String> {
        let senha = self.senha.clone();
        let quem = if origem {
            self.origem()
        } else {
            self.destino()
        };
        quem.linha(PROMPT_DO_CODIGO, codigo)?;
        quem.senha(PROMPT_DA_SENHA, &senha)
    }

    /// A Pessoa digita em `quem` um código que não confere: não há senha a
    /// digitar depois.
    fn confirmar_so_o_codigo(&mut self, origem: bool, codigo: &str) -> Result<(), String> {
        let quem = if origem {
            self.origem()
        } else {
            self.destino()
        };
        quem.linha(PROMPT_DO_CODIGO, codigo)
    }

    /// Nenhum dos dois tem lápide para o outro: o que se esqueceu não virou
    /// revogação, nem antes nem depois do boot.
    fn sem_lapide(&mut self) -> Result<(), String> {
        let (da_origem, da_destino) = (self.par.da_origem, self.par.da_destino);
        let na_origem = lapides(&self.origem().registro()?);
        let no_destino = lapides(&self.destino().registro()?);
        if na_origem.contains(&impressao(&da_destino))
            || no_destino.contains(&impressao(&da_origem))
        {
            return Err(format!(
                "o que se esqueceu virou lapide: na origem {na_origem:?}, no destino {no_destino:?}"
            ));
        }
        Ok(())
    }

    /// Nenhum dos dois tem relação com o outro.
    fn nada_gravado(&mut self) -> Result<(), String> {
        let (da_origem, da_destino) = (self.par.da_origem, self.par.da_destino);
        let na_origem = relacoes_em(self.origem(), &da_destino)?;
        let no_destino = relacoes_em(self.destino(), &da_origem)?;
        if !na_origem.is_empty() || !no_destino.is_empty() {
            return Err(format!(
                "uma relacao ficou gravada: na origem {na_origem:?}, no destino {no_destino:?}"
            ));
        }
        Ok(())
    }

    /// A Pessoa desfaz, em `quem`, a relação dela com `nome`: o
    /// `device.forget` digitado no Terminal, decidido pelo gate.
    fn esquecer(&mut self, origem: bool, nome: &str) -> Result<Gravado, String> {
        let quem = if origem {
            self.origem()
        } else {
            self.destino()
        };
        let desde = quem.marca()?.auditoria;
        quem.linha(
            PROMPT,
            &format!(r#"device.forget {{"device":"dispositivo:{nome}"}}"#),
        )?;
        let recurso = format!("dispositivo:{nome}");
        // A decisão do gate, e o registro da execução, com o que se desfez.
        let g = esperar_gravado(quem, desde, "o device.forget", |g| {
            g.metodo == "device.forget" && g.recurso == recurso
        })?;
        if g.codigo != "ALLOW" {
            return Err(format!(
                "{}: o device.forget de {nome} foi recusado: {} {}",
                quem.papel, g.codigo, g.detalhe
            ));
        }
        esperar_gravado(quem, desde, "a execucao do device.forget", |g| {
            g.recurso == recurso && g.codigo == "ALLOW" && g.detalhe.starts_with("relacao ")
        })
    }

    /// Corta a energia de uma máquina e a liga de novo, no mesmo disco e no
    /// mesmo TPM, com a Pessoa no Terminal: o que voltar, voltou do journal.
    fn religar(&mut self, origem: bool) -> Result<(), String> {
        if origem {
            self.par.origem.m.cortar()?;
            self.par.origem = self.a.ligar()?;
            self.par.origem.entrar()
        } else {
            self.par.destino.m.cortar()?;
            self.par.destino = self.b.ligar()?;
            self.par.destino.entrar()
        }
    }

    /// A relação de cada lado, uma só e a mesma: o identificador, a Pessoa,
    /// o papel; o endereço só na origem.
    fn a_mesma_relacao(&mut self) -> Result<String, String> {
        let (da_origem, da_destino) = (self.par.da_origem, self.par.da_destino);
        let pessoa = self.par.pessoa.clone();
        let na_origem = relacoes_em(self.origem(), &da_destino)?;
        let no_destino = relacoes_em(self.destino(), &da_origem)?;
        let (Some(o), Some(d)) = (na_origem.first(), no_destino.first()) else {
            return Err(format!(
                "a relacao nao esta nos dois: na origem {na_origem:?}, no destino {no_destino:?}"
            ));
        };
        let esperada_na_origem = Rel {
            relacao: d.relacao.clone(),
            pessoa: pessoa.clone(),
            papel: PAPEL.to_string(),
            endereco: Some(ENDERECO.to_string()),
        };
        let esperada_no_destino = Rel {
            relacao: o.relacao.clone(),
            pessoa,
            papel: PAPEL.to_string(),
            endereco: None,
        };
        if na_origem != [esperada_na_origem] || no_destino != [esperada_no_destino] {
            return Err(format!(
                "as relacoes dos dois nao sao a mesma: na origem {na_origem:?}, no destino {no_destino:?}"
            ));
        }
        if o.relacao.len() != 2 * conta::TAM_RELACAO {
            return Err(format!(
                "a relacao `{}` nao tem o tamanho de uma",
                o.relacao
            ));
        }
        Ok(o.relacao.clone())
    }
}

// ---------------------------------------------------------------------------
// Os passos
// ---------------------------------------------------------------------------

/// B02 — o código errado.
///
/// A origem recebe um código que não é o que o destino mostra: a cerimônia
/// acaba lá com `o codigo nao conferiu`, o destino ouve o `desistiu` e acaba
/// também, e nada se grava em nenhum. Sem relação nenhuma, a 7071 do
/// destino só escuta enquanto a janela está aberta.
fn codigo_errado(p: &mut Bancada) -> Result<String, String> {
    escuta(p.destino(), false, "sem relacao e sem janela")?;
    let antes_a = p.origem().marca()?.auditoria;
    let antes_b = p.destino().marca()?.auditoria;
    let (a, b) = p.ate_os_codigos()?;
    p.honestas(&a, &b)?;
    escuta(p.destino(), true, "com a janela aberta")?;
    let certo = conta::ler_codigo(&b.mostrado).ok_or("o codigo do destino nao se le")?;
    let errado = conta::texto_do_codigo((certo + 1) % 100_000_000);
    p.origem().linha(PROMPT_DO_CODIGO, &errado)?;
    let (do_destino, da_origem) = (impressao(&p.par.da_destino), impressao(&p.par.da_origem));
    let fa = fim(p.origem(), antes_a)?;
    desfeita(
        "origem",
        &fa,
        conta::Motivo::CodigoErrado.texto(),
        &do_destino,
    )?;
    let fb = fim(p.destino(), antes_b)?;
    desfeita(
        "destino",
        &fb,
        conta::Motivo::OutroDesistiu.texto(),
        &da_origem,
    )?;
    p.nada_gravado()?;
    escuta(p.destino(), false, "a janela fechada, sem relacao")?;
    let segredos = segredos_dos_codigos(&[&a.mostrado, &b.mostrado]);
    sem_segredo(p.origem(), &segredos)?;
    sem_segredo(p.destino(), &segredos)?;
    Ok(format!(
        "B02 codigo errado: a origem desfez (`{}`), o destino desfez pelo outro (`{}`); nada gravado em nenhum; a 7071 do destino so escutou com a janela; nenhum codigo na auditoria ou no log",
        fa.detalhe, fb.detalhe
    ))
}

/// B03 — o homem no meio.
///
/// A ponte do meio responde ao pedido da chave da origem com a dela e faz o
/// aperto com cada lado com essa chave. Cada tela mostra a impressão dela —
/// e não a do outro Duke —, e o código de um aperto com ela: a Pessoa que
/// digita num lado o código que o outro mostra não acerta nenhum. As duas
/// cerimônias acabam com `o codigo nao conferiu`, nada se grava, e a
/// auditoria dos dois conta a chave do meio.
fn homem_no_meio(p: &mut Bancada) -> Result<String, String> {
    p.meio.modo(Modo::NoMeio);
    let r = homem_no_meio_com_a_ponte(p);
    p.meio.modo(Modo::Passar);
    r
}

fn homem_no_meio_com_a_ponte(p: &mut Bancada) -> Result<String, String> {
    let antes_a = p.origem().marca()?.auditoria;
    let antes_b = p.destino().marca()?.auditoria;
    let (a, b) = p.ate_os_codigos()?;
    let v = p.meio.visto();
    let (Some(chave), Some(com_a_origem), Some(com_o_destino)) =
        (v.chave, v.com_a_origem, v.com_o_destino)
    else {
        return Err(format!("o homem no meio nao chegou aos codigos: {v:?}"));
    };
    let dele = impressao(&chave);
    if v.da_origem != Some(p.par.da_origem) {
        return Err("a origem nao provou a chave dela ao homem no meio".into());
    }
    // Cada tela mostra a chave do meio, e o código do aperto com ele: o que
    // inicia mostra o segundo, o que aceita, o primeiro.
    if a.par != dele || b.par != dele {
        return Err(format!(
            "as telas nao mostram a chave do meio ({dele}): a origem {a:?}, o destino {b:?}"
        ));
    }
    if a.mostrado != conta::texto_do_codigo(com_a_origem.1)
        || b.mostrado != conta::texto_do_codigo(com_o_destino.0)
    {
        return Err(format!(
            "as telas nao mostram os codigos dos apertos com o meio: a origem {a:?}, o destino {b:?}, o meio {v:?}"
        ));
    }
    if com_a_origem.0 == com_o_destino.0 || com_a_origem.1 == com_o_destino.1 {
        return Err(format!(
            "os codigos dos dois apertos coincidiram (1 em 10^8): {v:?}"
        ));
    }
    // A Pessoa faz o que deve: digita em cada lado o que o outro mostra.
    p.confirmar_so_o_codigo(true, &b.mostrado)?;
    let fa = fim(p.origem(), antes_a)?;
    desfeita("origem", &fa, conta::Motivo::CodigoErrado.texto(), &dele)?;
    p.confirmar_so_o_codigo(false, &a.mostrado)?;
    let fb = fim(p.destino(), antes_b)?;
    desfeita("destino", &fb, conta::Motivo::CodigoErrado.texto(), &dele)?;
    // O destino gravou o aperto da cerimônia com a chave do meio.
    let hex_dele = sigilo::hex(&chave);
    let destino = p.destino();
    destino.ler()?;
    if !destino
        .gravados(antes_b)
        .any(|g| g.metodo == "pair.open" && g.codigo == "ALLOW" && g.chave == hex_dele)
    {
        return Err("o destino nao gravou o aperto da cerimonia com a chave do meio".into());
    }
    p.nada_gravado()?;
    let mut segredos = segredos_dos_codigos(&[
        &conta::texto_do_codigo(com_a_origem.0),
        &conta::texto_do_codigo(com_a_origem.1),
        &conta::texto_do_codigo(com_o_destino.0),
        &conta::texto_do_codigo(com_o_destino.1),
    ]);
    segredos.extend(v.nonces.iter().cloned());
    sem_segredo(p.origem(), &segredos)?;
    sem_segredo(p.destino(), &segredos)?;
    // O que os dois disseram ao meio, depois: a desistência, e nada mais.
    let v = p.meio.visto();
    let desistiu = |m: &[String]| {
        m.iter().any(|x| {
            x.contains(r#""estado":"desistiu""#) && x.contains(conta::Motivo::CodigoErrado.texto())
        }) && !m
            .iter()
            .any(|x| x.contains("conferido") || x.contains("gravado"))
    };
    if !desistiu(&v.ouviu_da_origem) || !desistiu(&v.ouviu_do_destino) {
        return Err(format!(
            "os dois deviam dizer ao meio so que desistiram: {v:?}"
        ));
    }
    Ok(format!(
        "B03 homem no meio (chave {dele}): as duas telas mostraram a impressao do meio e os codigos dos apertos com ele, que nao conferem entre si; a origem e o destino desfizeram (`{}`), nada gravado, nenhum conferido nem gravado ao meio; o destino gravou o aperto com a chave do meio; nem os codigos nem os nonces na auditoria ou no log",
        fa.detalhe
    ))
}

/// B01 — a cerimônia.
///
/// A Pessoa digita em cada lado o código que o outro mostra e a senha dela:
/// os dois gravam a mesma relação — o identificador, a Pessoa, o papel; o
/// endereço só na origem —, e as duas telas dizem que o outro gravou. Pela
/// relação pareada, a entrega do Estágio 1: o `carteiro` da origem manda ao
/// `correio` do destino, e as decisões de lá dizem a relação.
fn a_cerimonia(p: &mut Bancada) -> Result<String, String> {
    let antes_a = p.origem().marca()?.auditoria;
    let antes_b = p.destino().marca()?.auditoria;
    let (a, b) = p.ate_os_codigos()?;
    p.honestas(&a, &b)?;
    p.confirmar(true, &b.mostrado)?;
    p.confirmar(false, &a.mostrado)?;
    let fa = fim(p.origem(), antes_a)?;
    let fb = fim(p.destino(), antes_b)?;
    for (quem, g) in [("origem", &fa), ("destino", &fb)] {
        if g.codigo != "ALLOW" || !g.detalhe.starts_with("pareado: relacao ") {
            return Err(format!(
                "{quem}: a cerimonia nao gravou: {} {}",
                g.codigo, g.detalhe
            ));
        }
    }
    let relacao = p.a_mesma_relacao()?;
    let r8 = &relacao[..8];
    for (quem, g, par) in [
        ("origem", &fa, impressao(&p.par.da_destino)),
        ("destino", &fb, impressao(&p.par.da_origem)),
    ] {
        if !g
            .detalhe
            .starts_with(&format!("pareado: relacao {r8}, par {par}"))
        {
            return Err(format!(
                "{quem}: a gravacao nao diz a relacao {r8} e o par {par}: {}",
                g.detalhe
            ));
        }
    }
    let concluida = format!("relacao {r8}; o outro gravou");
    esperar_tela(p.origem(), ESPERA_PELO_FIM, "o fim concluido", |t| {
        t.contains(&concluida)
    })?;
    esperar_tela(p.destino(), ESPERA_PELO_FIM, "o fim concluido", |t| {
        t.contains(&concluida)
    })?;
    let segredos = segredos_dos_codigos(&[&a.mostrado, &b.mostrado]);
    sem_segredo(p.origem(), &segredos)?;
    sem_segredo(p.destino(), &segredos)?;
    p.par.relacao = relacao.clone();
    p.par.destino_escuta(true)?;
    let endpoint = p.par.correio()?;
    let entrega = p.par.entrega(&endpoint)?;
    Ok(format!(
        "B01 a cerimonia: a relacao {r8} gravada nos dois pela Pessoa (a mesma, com o endereco so na origem), as duas telas dizem que o outro gravou, nenhum codigo na auditoria ou no log; pela relacao pareada, {entrega}"
    ))
}

/// B05 — o corte dos dois: a relação pareada volta do journal nos dois, a
/// mesma, e a entrega funciona sem nada de novo.
fn o_corte_dos_dois(p: &mut Bancada) -> Result<String, String> {
    let antes = p.par.relacao.clone();
    p.par.origem.m.cortar()?;
    p.par.destino.m.cortar()?;
    p.par.origem = p.a.ligar()?;
    p.par.destino = p.b.ligar()?;
    p.origem().entrar()?;
    p.destino().entrar()?;
    let depois = p.a_mesma_relacao()?;
    if depois != antes {
        return Err(format!(
            "a relacao voltou outra do journal: {antes} -> {depois}"
        ));
    }
    p.par.destino_escuta(true)?;
    let endpoint = p.par.correio()?;
    p.par.entrega(&endpoint)?;
    Ok(format!(
        "B05 corte dos dois: a relacao {} voltou do journal nos dois, a mesma, e a entrega funciona sem registro novo",
        &antes[..8]
    ))
}

/// B06 — esquecer de um lado.
///
/// O destino tem outro dispositivo, registrado pelo administrador — e a
/// 7071 continua escutando depois de ele esquecer o par. A Pessoa esquece a
/// relação no destino: ela sai de lá, e só de lá; a origem não sabe de
/// nada, continua com a dela, e o pedido por ela passa a ouvir
/// `DENY_NOT_AUTHENTICATED` — o destino recusa o aperto da chave fora do
/// registro, e nada chega ao gate de lá. Depois, a Pessoa esquece na
/// origem também.
fn esquecer_de_um_lado(p: &mut Bancada) -> Result<String, String> {
    let outro = sigilo::publica_de(&super::aleatorios()?);
    let relacao_do_outro = sigilo::hex_de(&dezesseis(&super::aleatorios()?));
    let params = format!(
        r#"{{"key":"{}","name":"{OUTRO}","person":"{}","role":"{PAPEL}","relation":"{relacao_do_outro}"}}"#,
        sigilo::hex(&outro),
        p.par.pessoa
    );
    p.destino().executar("device.register", &params)?;
    let antes = p.par.relacao.clone();
    let g = p.esquecer(false, NOME)?;
    let da_origem = p.par.da_origem;
    let da_destino = p.par.da_destino;
    if !relacoes_em(p.destino(), &da_origem)?.is_empty() {
        return Err("o destino esqueceu, e a relacao continua no registro dele".into());
    }
    if relacoes_em(p.destino(), &outro)?.len() != 1 {
        return Err("o destino esqueceu o par, e o outro dispositivo saiu junto".into());
    }
    escuta(p.destino(), true, "com o outro dispositivo")?;
    let na_origem = relacoes_em(p.origem(), &da_destino)?;
    if na_origem.len() != 1 || na_origem[0].relacao != antes {
        return Err(format!(
            "o esquecimento do destino mexeu na origem: {na_origem:?}"
        ));
    }
    let antes_d = p.destino().marca()?;
    p.par
        .recusado("DENY_NOT_AUTHENTICATED", "o par recusou o aperto")?;
    p.par
        .aperto_recusado(antes_d, "DENY_NOT_AUTHENTICATED", "chave fora do registro")?;
    let ga = p.esquecer(true, NOME)?;
    if !relacoes_em(p.origem(), &da_destino)?.is_empty() {
        return Err("a origem esqueceu, e a relacao continua no registro dela".into());
    }
    Ok(format!(
        "B06 esquecer de um lado: o destino esqueceu a relacao {} (`{}`), so ela saiu dele; a origem continuou com a dela e passou a ouvir DENY_NOT_AUTHENTICATED (o destino recusou o aperto da chave fora do registro, nada ao gate de la); depois a origem esqueceu tambem (`{}`)",
        &antes[..8],
        g.detalhe,
        ga.detalhe
    ))
}

/// B04 — o corte durante a cerimônia.
///
/// Os códigos à mostra nos dois, a energia do destino cai: a origem desfaz
/// pela conexão, nada gravado nela; o destino volta sem nada da cerimônia —
/// ela era volátil —, e o que fora esquecido continua esquecido, sem lápide.
fn o_corte_durante(p: &mut Bancada) -> Result<String, String> {
    let antes_a = p.origem().marca()?.auditoria;
    let (a, b) = p.ate_os_codigos()?;
    p.honestas(&a, &b)?;
    p.par.destino.m.cortar()?;
    let fa = fim(p.origem(), antes_a)?;
    desfeita(
        "origem",
        &fa,
        conta::Motivo::Conexao.texto(),
        &impressao(&p.par.da_destino),
    )?;
    p.par.destino = p.b.ligar()?;
    p.destino().entrar()?;
    p.nada_gravado()?;
    p.sem_lapide()?;
    let registro = p.destino().registro()?;
    if registro.contains(r#""pairing":{"#) {
        return Err(format!(
            "o destino voltou do corte com uma cerimonia\n  {registro}"
        ));
    }
    Ok(format!(
        "B04 corte durante: os codigos a mostra, o destino cortado; a origem desfez (`{}`), e o destino voltou sem nada da cerimonia; o par esquecido continua esquecido",
        fa.detalhe
    ))
}

/// B04 — o corte depois de um lado gravar: a meia relação.
///
/// A ponte do meio segura o que o destino manda à origem depois do aperto.
/// A Pessoa confirma na origem e depois no destino: o destino, com o
/// `conferido` de lá, grava; a origem nunca ouve o de cá. A energia da
/// origem cai: ela volta sem nada, e o destino fica com a meia relação —
/// no `device.registry`, mesmo depois de outro corte —, que não serve a
/// ninguém: a origem não tem relação por onde pedir. A Pessoa a tira com
/// `device.forget`.
fn a_meia_relacao(p: &mut Bancada) -> Result<String, String> {
    p.meio.modo(Modo::SegurarODestino);
    let r = a_meia_relacao_com_a_ponte(p);
    p.meio.modo(Modo::Passar);
    r
}

fn a_meia_relacao_com_a_ponte(p: &mut Bancada) -> Result<String, String> {
    let antes_b = p.destino().marca()?.auditoria;
    let (a, b) = p.ate_os_codigos()?;
    p.honestas(&a, &b)?;
    p.confirmar(true, &b.mostrado)?;
    p.confirmar(false, &a.mostrado)?;
    let fb = fim(p.destino(), antes_b)?;
    if fb.codigo != "ALLOW" || !fb.detalhe.starts_with("pareado: relacao ") {
        return Err(format!(
            "o destino nao gravou com o conferido da origem: {} {}",
            fb.codigo, fb.detalhe
        ));
    }
    // A origem não ouviu o `conferido` de lá: não grava, espera.
    let da_destino = p.par.da_destino;
    let da_origem = p.par.da_origem;
    if !relacoes_em(p.origem(), &da_destino)?.is_empty() {
        return Err("a origem gravou sem o conferido do destino".into());
    }
    p.par.origem.m.cortar()?;
    esperar_tela(
        p.destino(),
        ESPERA_PELO_FIM,
        "o fim sem o aviso do outro",
        |t| t.contains("o outro nao confirmou que gravou"),
    )?;
    p.meio.modo(Modo::Passar);
    p.par.origem = p.a.ligar()?;
    p.origem().entrar()?;
    if !relacoes_em(p.origem(), &da_destino)?.is_empty() {
        return Err("a origem voltou do corte com a relacao".into());
    }
    let meia = relacoes_em(p.destino(), &da_origem)?;
    let [Rel { relacao, .. }] = &meia[..] else {
        return Err(format!("o destino nao ficou com a meia relacao: {meia:?}"));
    };
    let relacao = relacao.clone();
    // Inerte: a origem não tem relação por onde pedir — recusada no gate
    // dela, sem rede —, e o destino não tem endereço do outro.
    let antes_o = p.origem().marca()?;
    let antes_d = p.destino().marca()?;
    p.par
        .recusado("DENY_RESOURCE", "operacao negada pela politica")?;
    p.par.recusado_aqui(
        antes_o,
        "DENY_RESOURCE",
        "o dispositivo nao existe para quem pede",
    )?;
    p.par.sem_rede(antes_o, antes_d)?;
    // Sobrevive ao corte, e sai com o esquecimento da Pessoa.
    p.religar(false)?;
    if relacoes_em(p.destino(), &da_origem)? != meia {
        return Err("a meia relacao nao voltou do journal igual".into());
    }
    let g = p.esquecer(false, NOME)?;
    if !relacoes_em(p.destino(), &da_origem)?.is_empty() {
        return Err("a meia relacao continua depois do device.forget".into());
    }
    Ok(format!(
        "B04 meia relacao: o destino gravou a {} com o conferido da origem, a origem nunca ouviu o de la e foi cortada sem gravar; a meia relacao apareceu no device.registry do destino, sobreviveu ao corte, nao serviu a origem (recusada no gate dela, sem rede), e saiu com o device.forget da Pessoa (`{}`)",
        &relacao[..8],
        g.detalhe
    ))
}

/// B05 — a lápide: a chave revogada não pareia, nem depois do boot.
///
/// O administrador registra a chave da origem no destino e a revoga: a
/// lápide. A cerimônia chega ao aperto e o destino recusa a chave provada,
/// pela lápide; a origem ouve a recusa e desfaz; a janela do destino fica
/// aberta até a Pessoa desistir. Depois do corte do destino, de novo.
fn a_lapide(p: &mut Bancada) -> Result<String, String> {
    let da_origem = p.par.da_origem;
    let relacao = sigilo::hex_de(&dezesseis(&super::aleatorios()?));
    let params = format!(
        r#"{{"key":"{}","name":"{NOME}","person":"{}","role":"{PAPEL}","relation":"{relacao}"}}"#,
        sigilo::hex(&da_origem),
        p.par.pessoa
    );
    p.destino().executar("device.register", &params)?;
    p.destino()
        .executar("device.revoke", &format!(r#"{{"name":"{NOME}"}}"#))?;
    let mut feitos = Vec::new();
    for vez in ["antes do corte", "depois do corte"] {
        if vez == "depois do corte" {
            p.religar(false)?;
        }
        let antes_a = p.origem().marca()?.auditoria;
        let antes_b = p.destino().marca()?.auditoria;
        p.abrir(
            false,
            &format!("aceitar {NOME} {PAPEL}"),
            &format!("janela aberta; papel {PAPEL}"),
        )?;
        p.abrir(
            true,
            &format!("parear {NOME} {ENDERECO} {PAPEL}"),
            &format!("para {ENDERECO}; papel {PAPEL}"),
        )?;
        let hex = sigilo::hex(&da_origem);
        let aperto = esperar_gravado(p.destino(), antes_b, "o aperto recusado", |g| {
            g.metodo == "pair.open" && g.chave == hex
        })?;
        if aperto.codigo == "ALLOW" || !aperto.detalhe.starts_with("a chave foi revogada") {
            return Err(format!(
                "{vez}: o destino nao recusou a chave da origem pela lapide: {} {}",
                aperto.codigo, aperto.detalhe
            ));
        }
        let fa = fim(p.origem(), antes_a)?;
        if fa.codigo == "ALLOW" || !fa.detalhe.contains("a chave foi revogada") {
            return Err(format!(
                "{vez}: a origem nao desfez pela recusa de la: {} {}",
                fa.codigo, fa.detalhe
            ));
        }
        // A janela do destino continua aberta: a Pessoa desiste.
        esperar_tela(
            p.destino(),
            ESPERA_PELA_LINHA,
            "a linha da cerimonia",
            |t| ultima_linha(t) == PROMPT_DO_PAREAMENTO.trim_end(),
        )?;
        p.destino().enter()?;
        let fb = fim(p.destino(), antes_b)?;
        desfeita("destino", &fb, conta::Motivo::Cancelada.texto(), "-")?;
        p.nada_gravado()?;
        feitos.push(format!("{vez}: `{}` {}", aperto.codigo, aperto.detalhe));
    }
    Ok(format!(
        "B05 lapide: a chave da origem, revogada no destino, nao pareia — o destino recusou o aperto ({}); a origem desfez pela recusa, a janela de la so fechou com a Pessoa, nada gravado",
        feitos.join("; ")
    ))
}

/// Um passo da bancada: o que ele conferiu.
type Passo = fn(&mut Bancada) -> Result<String, String>;

/// Os passos, sobre as duas máquinas de pé, cada um contado quando passa.
fn passos(p: &mut Bancada, feitos: &mut Vec<String>) -> Result<(), String> {
    p.destino().entrar()?;
    p.origem().entrar()?;
    let lista: [Passo; 8] = [
        codigo_errado,
        homem_no_meio,
        a_cerimonia,
        o_corte_dos_dois,
        esquecer_de_um_lado,
        o_corte_durante,
        a_meia_relacao,
        a_lapide,
    ];
    for passo in lista {
        let comeco = Instant::now();
        let feito = passo(p)?;
        println!(
            "  [pareamento]   ({} s) {feito}",
            comeco.elapsed().as_secs()
        );
        feitos.push(feito);
    }
    Ok(())
}

/// Um par, de ponta a ponta: o que cada passo conferiu.
fn um_par(origem: Arquitetura, destino: Arquitetura, release: bool) -> Result<Vec<String>, String> {
    let porta_do_destino = enlace::porta_livre()?;
    let meio = Meio::ligar(porta_do_destino)?;
    let ponte = super::raiz_do_projeto().join(super::canal_tcp::PONTE);
    let ponte = ponte.display().to_string();
    if ponte.contains([',', ' ']) {
        return Err(format!(
            "o caminho da ponte nao cabe na opcao do emulador: {ponte}"
        ));
    }
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
        super::aleatorios()?,
        format!(
            "hostfwd=tcp:127.0.0.1:{porta_do_destino}-:{}",
            enlace::PORTA_DO_ENLACE
        ),
    )?;
    let (id, _, senha) = chaves::Chaves::garantir()?.pessoa_dev();
    let par = Par {
        da_origem: a.publica(),
        da_destino: b.publica(),
        relacao: String::new(),
        pessoa: sigilo::pessoas::IdPessoa(id).texto(),
        atestado: enlace::atestado_do_carteiro(origem)?,
        ultimo: None,
        medidas: Vec::new(),
        origem: a.ligar()?,
        destino: b.ligar()?,
    };
    let mut bancada = Bancada {
        par,
        a,
        b,
        meio,
        senha,
    };
    let mut feitos = Vec::new();
    let r = passos(&mut bancada, &mut feitos);
    if r.is_err() {
        bancada.mostrar();
    }
    println!(
        "  [pareamento]   {}",
        enlace::o_teclado(&bancada.a, &bancada.b)
    );
    let _ = bancada.par.origem.m.cortar_a_energia();
    let _ = bancada.par.destino.m.cortar_a_energia();
    r.map(|()| feitos)
}

/// `cargo xtask pareamento`: os pares escolhidos, um de cada vez.
pub(crate) fn pareamento(release: bool) -> Result<ExitCode, String> {
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
        "[xtask] pareamento: {} pares, duas maquinas de pe em cada, a Pessoa no teclado das duas",
        escolhidos.len()
    );
    let mut falhas = 0;
    for par in &escolhidos {
        let (origem, destino) = *par;
        println!("[xtask] pareamento: {}", nome(par));
        super::incidente::no_cenario("pareamento", &nome(par));
        let comeco = Instant::now();
        match um_par(origem, destino, release) {
            Ok(feitos) => {
                for f in feitos {
                    println!("  [pareamento] ok  {}: {f}", nome(par));
                }
                println!(
                    "  [pareamento] ok  {}: o par inteiro em {} s",
                    nome(par),
                    comeco.elapsed().as_secs()
                );
            }
            Err(motivo) => {
                falhas += 1;
                println!("  [pareamento] FALHOU  {}: {motivo}", nome(par));
            }
        }
    }
    let base = super::raiz_do_projeto().join("target").join(BANCADA);
    for papel in ["origem", "destino"] {
        let _ = std::fs::remove_file(base.join(format!("{papel}.img")));
    }
    if falhas > 0 {
        println!("\n[xtask] pareamento: {falhas} par(es) falharam");
        return Ok(ExitCode::FAILURE);
    }
    println!("\n[xtask] pareamento: todos os pares passaram");
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn os_codigos_saem_da_tela_so_com_a_linha_do_codigo() {
        let tela = "duke> parear par tcp:10.0.2.100:7071 dispositivo\n\
                    pareando com tcp:10.0.2.100:7071: esperando o outro Duke. Uma linha vazia desiste.\n\
                    pareamento (linha vazia desiste):\n\
                    pareando com 1a2b3c4d; este Duke e 5e6f7a8b.\n\
                    No outro dispositivo, digite: 0123 4567\n\
                    Aqui, digite so o codigo que aparece no seu outro dispositivo; ninguem mais pre\n\
                    cisa dele.\n\
                    codigo do outro:";
        let c = codigos_na_tela(tela).expect("os codigos");
        assert_eq!(c.mostrado, "0123 4567");
        assert_eq!(c.par, "1a2b3c4d");
        assert_eq!(c.eu, "5e6f7a8b");
        // Com a linha já digitada, ou de volta ao comando, não é a vez dos
        // códigos — e um texto velho na tela não conta.
        assert!(codigos_na_tela(&format!("{tela} 0123 4567")).is_none());
        assert!(codigos_na_tela(&format!("{tela}\nduke>")).is_none());
    }

    #[test]
    fn o_texto_do_terminal_sai_da_arvore_sem_escapes() {
        let arvore = r#"{"revision":3,"root":{"id":1,"role":"screen","label":"tela","children":[{"id":9,"role":"window","label":"Terminal","children":[{"id":10,"role":"text_area","label":"terminal","frame":{"x":1,"y":2,"width":3,"height":4},"value":"duke> a\n\"b\" \\ é","actions":[],"children":[]}]}]}}"#;
        assert_eq!(
            digitacao::texto_da_tela(arvore, Tela::Terminal).as_deref(),
            Some("duke> a\n\"b\" \\ é")
        );
        assert_eq!(ultima_linha("x\ncodigo do outro: "), "codigo do outro:");
    }

    #[test]
    fn as_relacoes_saem_do_registro_pela_chave() {
        let k = [7u8; 32];
        let registro = format!(
            r#"{{"devices":[{{"name":"par","key":"{}","suspended":false,"relations":[{{"relation":"00112233445566778899aabbccddeeff","person":"pessoa:1","role":"dispositivo","address":null}}]}}],"revoked":["{}"],"links":[]}}"#,
            sigilo::hex(&k),
            sigilo::hex(&[9u8; 32])
        );
        assert_eq!(
            relacoes(&registro, &k),
            vec![Rel {
                relacao: "00112233445566778899aabbccddeeff".into(),
                pessoa: "pessoa:1".into(),
                papel: "dispositivo".into(),
                endereco: None,
            }]
        );
        // A chave com lápide não é um dispositivo com relação.
        assert!(relacoes(&registro, &[9u8; 32]).is_empty());
    }

    #[test]
    fn um_segredo_conta_so_inteiro() {
        assert!(tem_o_token("desfeita: 01234567; par", "01234567"));
        assert!(!tem_o_token("uptime 9012345678", "01234567"));
        assert!(tem_o_token("codigo 0123 4567.", "0123 4567"));
    }
}
