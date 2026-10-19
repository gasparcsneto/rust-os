//! O servidor de Roughtime da bancada de tempo: as três fontes do registro
//! da imagem, de verdade, no hospedeiro — ver [`super::tempo`].
//!
//! # Onde
//!
//! Uma porta UDP do loopback para cada fonte de
//! [`super::chaves::FONTES_DE_HORA`], na ordem dele: `127.0.0.1:5319`,
//! `:5320` e `:5321`. O hóspede fala com `10.0.2.2:<porta>`, e a rede do
//! emulador leva esse endereço ao loopback do hospedeiro. Isso foi conferido
//! antes de este servidor existir, com um ouvinte que só anotava: a cada
//! rodada chegavam os três pedidos de 1024 bytes, um por fonte, na ordem do
//! registro.
//!
//! # As chaves
//!
//! A raiz de cada fonte é a privada de `target/chaves/fonte-de-hora-*.chave`,
//! a mesma cuja pública a imagem fixa em `/etc/duke/tempo`. A delegada é
//! sorteada cada vez que o servidor sobe, e nunca é gravada. A raiz assina a
//! delegação uma vez; a delegada assina cada resposta, como num servidor de
//! verdade.
//!
//! # Uma implementação à parte
//!
//! Nada aqui vem do pacote `hora`: nem o escritor de mensagens, nem a
//! árvore, nem os contextos das assinaturas. O servidor de teste dele é só
//! da suíte, e o `cargo xtask invariantes` confere. O que este servidor
//! escreve sai do formato da versão 1 escrito de novo (ver `hora::resposta`),
//! e o que o kernel confere é o que sai daqui. Um erro de código de um lado
//! só aparece. Um erro de leitura do formato que estivesse nos dois lados
//! passaria pelos dois: contra isso, só o vetor da RFC 10049, que os casos
//! daqui e os do `hora` conferem.
//!
//! # Os modos
//!
//! Cada fonte responde segundo um [`Modo`], que o cenário troca com a
//! máquina rodando: o carimbo deslocado da hora do hospedeiro, o raio, o
//! atraso da resposta, pedidos descartados, a árvore de um lote, e a
//! assinatura de uma chave que a delegação não nomeia.
//!
//! # O diário
//!
//! Cada datagrama que chega vira um [`Evento`]: quando chegou, de que fonte,
//! o tamanho, e o que o servidor fez com ele. É o lado de fora da rodada: o
//! kernel diz o que aceitou, e o diário diz o que foi mandado.

use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha512};

/// Quantas fontes: as do registro da imagem.
pub(crate) const FONTES: usize = super::chaves::FONTES_DE_HORA.len();

/// As etiquetas da versão 1, como inteiros little-endian: a ordem das
/// etiquetas numa mensagem é a destes valores.
mod etiqueta {
    const fn de(b: &[u8; 4]) -> u32 {
        u32::from_le_bytes(*b)
    }
    pub const SIG: u32 = de(b"SIG\0");
    pub const VER: u32 = de(b"VER\0");
    pub const SRV: u32 = de(b"SRV\0");
    pub const NONC: u32 = de(b"NONC");
    pub const TYPE: u32 = de(b"TYPE");
    pub const PATH: u32 = de(b"PATH");
    pub const SREP: u32 = de(b"SREP");
    pub const CERT: u32 = de(b"CERT");
    pub const INDX: u32 = de(b"INDX");
    pub const RADI: u32 = de(b"RADI");
    pub const MIDP: u32 = de(b"MIDP");
    pub const VERS: u32 = de(b"VERS");
    pub const ROOT: u32 = de(b"ROOT");
    pub const DELE: u32 = de(b"DELE");
    pub const PUBK: u32 = de(b"PUBK");
    pub const MINT: u32 = de(b"MINT");
    pub const MAXT: u32 = de(b"MAXT");
}

/// O começo de todo pacote.
const MAGICO: &[u8; 8] = b"ROUGHTIM";

/// O menor pedido que um servidor da versão 1 atende, com a moldura.
const MENOR_PEDIDO: usize = 1024;

/// O maior datagrama que se lê.
const MAIOR_DATAGRAMA: usize = 65_535;

/// A versão que este servidor fala.
const VERSAO: u32 = 1;

/// Os contextos das duas assinaturas da versão 1, com o zero no fim.
const CONTEXTO_DA_DELEGACAO: &[u8] = b"Roughtime v1 delegation signature\0";
const CONTEXTO_DA_RESPOSTA: &[u8] = b"Roughtime v1 response signature\0";

/// A janela da delegação, para cada lado da hora em que o servidor subiu: os
/// saltos dos cenários cabem nela.
const JANELA_DA_DELEGACAO_S: u64 = 30 * 86_400;

/// Quanto o fio de cada fonte espera um datagrama antes de olhar se é hora
/// de parar.
const ESPERA_DO_FIO: Duration = Duration::from_millis(100);

/// Como uma fonte responde.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Modo {
    /// Quanto o carimbo está à frente da hora do hospedeiro (atrás, se
    /// negativo), em milissegundos.
    pub deslocamento_ms: i64,
    /// O raio, em segundos.
    pub raio_s: u32,
    /// Quanto esperar antes de carimbar e responder.
    pub atraso_ms: u64,
    /// Descarta um pedido a cada tantos: 0 nenhum, 1 todos (a fonte calada).
    pub descartar_um_a_cada: u32,
    /// As folhas da árvore da resposta — o pedido e outras sorteadas —, numa
    /// potência de dois: 1 é o pedido sozinho, sem caminho.
    pub lote: u32,
    /// A resposta assinada por uma chave que a delegação não nomeia: o que
    /// mandaria quem se passa pela fonte, ou uma fonte com a chave trocada.
    /// O resto é o de uma resposta honesta.
    pub forjada: bool,
}

impl Modo {
    /// A fonte honesta: a hora do hospedeiro, um segundo de raio, sem
    /// atraso, sem perda, o pedido sozinho na árvore.
    pub const HONESTA: Modo = Modo {
        deslocamento_ms: 0,
        raio_s: 1,
        atraso_ms: 0,
        descartar_um_a_cada: 0,
        lote: 1,
        forjada: false,
    };

    /// A fonte calada: recebe e não responde.
    pub const CALADA: Modo = Modo {
        descartar_um_a_cada: 1,
        ..Modo::HONESTA
    };
}

/// O que o servidor fez com um datagrama.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Desfecho {
    /// Respondeu, com este carimbo e este raio, na posição `indice` de uma
    /// árvore de `lote` folhas, depois de esperar `atraso_ms` de propósito.
    Respondido {
        midp: u64,
        raio_s: u32,
        lote: u32,
        indice: u32,
        bytes: usize,
        atraso_ms: u64,
    },
    /// O modo mandou descartar.
    Descartado,
    /// Não era um pedido que este servidor atende: o motivo.
    Ignorado(&'static str),
}

/// Um datagrama que chegou a uma fonte.
#[derive(Clone, Debug)]
pub(crate) struct Evento {
    /// A fonte, na ordem do registro.
    pub fonte: usize,
    /// Quando chegou, desde que o servidor subiu.
    pub chegada: Duration,
    /// Quando a resposta saiu, se saiu.
    pub saida: Option<Duration>,
    pub tamanho: usize,
    pub desfecho: Desfecho,
}

/// O estado de uma fonte, com o fio dela.
struct Fonte {
    raiz: SigningKey,
    delegada: SigningKey,
    /// O `CERT` inteiro: a delegação assinada pela raiz uma vez.
    cert: Vec<u8>,
    /// Os pedidos que já chegaram, para o descarte de um a cada tantos.
    vistos: u64,
}

/// As três fontes, de pé. Descer é largar: o `Drop` para os fios.
pub(crate) struct ServidorDeHora {
    modos: Arc<Mutex<[Modo; FONTES]>>,
    diario: Arc<Mutex<Vec<Evento>>>,
    parar: Arc<AtomicBool>,
    fios: Vec<JoinHandle<()>>,
    inicio: Instant,
}

impl ServidorDeHora {
    /// Sobe as três fontes, honestas, nas portas do registro da imagem.
    pub(crate) fn subir() -> Result<ServidorDeHora, String> {
        let chaves = super::chaves::Chaves::garantir()?;
        let modos = Arc::new(Mutex::new(std::array::from_fn(|_| Modo::HONESTA)));
        let diario = Arc::new(Mutex::new(Vec::new()));
        let parar = Arc::new(AtomicBool::new(false));
        let inicio = Instant::now();
        let agora_s = agora_ms().div_euclid(1000) as u64;
        let mut fios = Vec::new();
        for (i, ((nome, destino), raiz)) in super::chaves::FONTES_DE_HORA
            .iter()
            .zip(&chaves.fontes_de_hora)
            .enumerate()
        {
            let porta = porta_de(destino)?;
            let socket = UdpSocket::bind(("127.0.0.1", porta)).map_err(|e| {
                format!(
                    "a fonte {nome} nao subiu na porta {porta} do hospedeiro ({e}): outra bancada de tempo rodando?"
                )
            })?;
            socket
                .set_read_timeout(Some(ESPERA_DO_FIO))
                .map_err(|e| format!("a fonte {nome} nao configurou a espera: {e}"))?;
            let fonte = Fonte::nova(
                SigningKey::from_bytes(raiz),
                SigningKey::from_bytes(&sorteados()?),
                agora_s.saturating_sub(JANELA_DA_DELEGACAO_S),
                agora_s.saturating_add(JANELA_DA_DELEGACAO_S),
            );
            let (modos, diario, parar) = (modos.clone(), diario.clone(), parar.clone());
            let fio = std::thread::Builder::new()
                .name(format!("fonte-{nome}"))
                .spawn(move || atender(i, socket, fonte, &modos, &diario, &parar, inicio))
                .map_err(|e| format!("o fio da fonte {nome} nao subiu: {e}"))?;
            fios.push(fio);
        }
        Ok(ServidorDeHora {
            modos,
            diario,
            parar,
            fios,
            inicio,
        })
    }

    /// Troca o modo da fonte `i`.
    pub(crate) fn modo(&self, i: usize, modo: Modo) {
        self.modos.lock().unwrap_or_else(|e| e.into_inner())[i] = modo;
    }

    /// Troca o modo das três.
    pub(crate) fn todas(&self, modo: Modo) {
        let mut modos = self.modos.lock().unwrap_or_else(|e| e.into_inner());
        for m in modos.iter_mut() {
            *m = modo.clone();
        }
    }

    /// O diário até agora.
    pub(crate) fn eventos(&self) -> Vec<Evento> {
        self.diario
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Quanto tempo desde que o servidor subiu: a régua do diário.
    pub(crate) fn desde_o_inicio(&self) -> Duration {
        self.inicio.elapsed()
    }
}

impl Drop for ServidorDeHora {
    fn drop(&mut self) {
        self.parar.store(true, Ordering::Release);
        for fio in self.fios.drain(..) {
            let _ = fio.join();
        }
    }
}

/// A hora do hospedeiro, em milissegundos desde a época Unix.
pub(crate) fn agora_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// A porta de um destino `udp:<ipv4>:<porta>` do registro.
fn porta_de(destino: &str) -> Result<u16, String> {
    destino
        .strip_prefix("udp:")
        .and_then(|d| d.rsplit_once(':'))
        .and_then(|(_, p)| p.parse().ok())
        .ok_or_else(|| format!("o destino `{destino}` nao e udp:<ipv4>:<porta>"))
}

/// Trinta e dois bytes do gerador do hospedeiro.
fn sorteados() -> Result<[u8; 32], String> {
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| format!("sem /dev/urandom para o servidor de hora: {e}"))?;
    Ok(b)
}

/// O fio de uma fonte: recebe, anota e responde, até mandarem parar.
fn atender(
    i: usize,
    socket: UdpSocket,
    mut fonte: Fonte,
    modos: &Mutex<[Modo; FONTES]>,
    diario: &Arc<Mutex<Vec<Evento>>>,
    parar: &AtomicBool,
    inicio: Instant,
) {
    let mut buffer = vec![0u8; MAIOR_DATAGRAMA];
    while !parar.load(Ordering::Acquire) {
        let (n, origem) = match socket.recv_from(&mut buffer) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let chegada = inicio.elapsed();
        let modo = modos.lock().unwrap_or_else(|e| e.into_inner())[i].clone();
        fonte.vistos += 1;
        let pedido = buffer[..n].to_vec();
        let anotar = |saida, desfecho| {
            diario
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(Evento {
                    fonte: i,
                    chegada,
                    saida,
                    tamanho: n,
                    desfecho,
                })
        };
        if modo.descartar_um_a_cada > 0
            && fonte
                .vistos
                .is_multiple_of(u64::from(modo.descartar_um_a_cada))
        {
            anotar(None, Desfecho::Descartado);
            continue;
        }
        let nonce = match conferir_o_pedido(&pedido, &fonte.raiz) {
            Ok(n) => n,
            Err(motivo) => {
                anotar(None, Desfecho::Ignorado(motivo));
                continue;
            }
        };
        let atrasa = modo.atraso_ms > 0;
        let responder = {
            let socket = socket.try_clone();
            let fonte = fonte.clone_para_responder();
            let diario = diario.clone();
            move || {
                if modo.atraso_ms > 0 {
                    std::thread::sleep(Duration::from_millis(modo.atraso_ms));
                }
                let midp = (agora_ms() + modo.deslocamento_ms).div_euclid(1000).max(0) as u64;
                let (resposta, indice) = fonte.responder(&pedido, &nonce, midp, &modo);
                let enviado = socket.ok().is_some_and(|s| enviar(&s, &resposta, origem));
                let desfecho = if enviado {
                    Desfecho::Respondido {
                        midp,
                        raio_s: modo.raio_s,
                        lote: modo.lote,
                        indice,
                        bytes: resposta.len(),
                        atraso_ms: modo.atraso_ms,
                    }
                } else {
                    Desfecho::Ignorado("a resposta nao saiu")
                };
                diario
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(Evento {
                        fonte: i,
                        chegada,
                        saida: enviado.then(|| inicio.elapsed()),
                        tamanho: n,
                        desfecho,
                    });
            }
        };
        // Com atraso, a resposta espera noutro fio: este continua recebendo,
        // e a chegada do próximo pedido é anotada quando chega.
        if atrasa {
            std::thread::spawn(responder);
        } else {
            responder();
        }
    }
}

fn enviar(socket: &UdpSocket, resposta: &[u8], para: SocketAddr) -> bool {
    socket
        .send_to(resposta, para)
        .is_ok_and(|n| n == resposta.len())
}

impl Fonte {
    fn nova(raiz: SigningKey, delegada: SigningKey, mint: u64, maxt: u64) -> Fonte {
        let dele = mensagem(vec![
            (etiqueta::PUBK, delegada.verifying_key().to_bytes().to_vec()),
            (etiqueta::MINT, mint.to_le_bytes().to_vec()),
            (etiqueta::MAXT, maxt.to_le_bytes().to_vec()),
        ]);
        let assinatura = raiz.sign(&[CONTEXTO_DA_DELEGACAO, &dele].concat());
        let cert = mensagem(vec![
            (etiqueta::SIG, assinatura.to_bytes().to_vec()),
            (etiqueta::DELE, dele),
        ]);
        Fonte {
            raiz,
            delegada,
            cert,
            vistos: 0,
        }
    }

    /// O que a resposta precisa, para outro fio: as chaves e o `CERT`.
    fn clone_para_responder(&self) -> Fonte {
        Fonte {
            raiz: self.raiz.clone(),
            delegada: self.delegada.clone(),
            cert: self.cert.clone(),
            vistos: self.vistos,
        }
    }

    /// A resposta ao pedido, com este carimbo, e a posição dele na árvore.
    fn responder(&self, pedido: &[u8], nonce: &[u8; 32], midp: u64, modo: &Modo) -> (Vec<u8>, u32) {
        let lote = modo.lote.max(1).next_power_of_two();
        // A posição do pedido no lote: a última, para o INDX ter todos os
        // bits do caminho ligados — a leitura que menos se conferiu.
        let indice = lote - 1;
        let mut folhas: Vec<[u8; 32]> = (0..lote)
            .map(|_| h(&[&[0x00], &sorteados().unwrap_or([0x5a; 32])]))
            .collect();
        folhas[indice as usize] = h(&[&[0x00], pedido]);
        let (raiz_da_arvore, caminho) = arvore(&folhas, indice as usize);
        let srep = mensagem(vec![
            (etiqueta::VER, VERSAO.to_le_bytes().to_vec()),
            (etiqueta::RADI, modo.raio_s.to_le_bytes().to_vec()),
            (etiqueta::MIDP, midp.to_le_bytes().to_vec()),
            (etiqueta::VERS, VERSAO.to_le_bytes().to_vec()),
            (etiqueta::ROOT, raiz_da_arvore.to_vec()),
        ]);
        // A forjada assina com uma chave sorteada agora: a delegação do `CERT`
        // nomeia outra.
        let forjadora;
        let assinante = if modo.forjada {
            forjadora = SigningKey::from_bytes(&sorteados().unwrap_or([0x5b; 32]));
            &forjadora
        } else {
            &self.delegada
        };
        let assinatura = assinante.sign(&[CONTEXTO_DA_RESPOSTA, &srep].concat());
        let topo = mensagem(vec![
            (etiqueta::SIG, assinatura.to_bytes().to_vec()),
            (etiqueta::NONC, nonce.to_vec()),
            (etiqueta::TYPE, 1u32.to_le_bytes().to_vec()),
            (etiqueta::PATH, caminho),
            (etiqueta::SREP, srep),
            (etiqueta::CERT, self.cert.clone()),
            (etiqueta::INDX, indice.to_le_bytes().to_vec()),
        ]);
        (emoldurar(&topo), indice)
    }
}

/// H: os 32 primeiros bytes do SHA-512 das partes.
fn h(partes: &[&[u8]]) -> [u8; 32] {
    let mut sha = Sha512::new();
    for p in partes {
        sha.update(p);
    }
    let mut r = [0u8; 32];
    r.copy_from_slice(&sha.finalize()[..32]);
    r
}

/// A raiz de uma árvore de folhas em número de potência de dois, e o caminho
/// da folha `qual`: os irmãos de baixo para cima. O nó é H(0x01 ‖ esquerdo ‖
/// direito).
fn arvore(folhas: &[[u8; 32]], qual: usize) -> ([u8; 32], Vec<u8>) {
    let mut nivel = folhas.to_vec();
    let mut posicao = qual;
    let mut caminho = Vec::new();
    while nivel.len() > 1 {
        caminho.extend_from_slice(&nivel[posicao ^ 1]);
        nivel = nivel
            .chunks(2)
            .map(|par| h(&[&[0x01], &par[0], &par[1]]))
            .collect();
        posicao /= 2;
    }
    (nivel[0], caminho)
}

/// Uma mensagem: o número de etiquetas, os deslocamentos dos valores a
/// partir do segundo, as etiquetas em ordem crescente, e os valores.
fn mensagem(mut campos: Vec<(u32, Vec<u8>)>) -> Vec<u8> {
    campos.sort_by_key(|(e, _)| *e);
    assert!(
        campos.iter().all(|(_, v)| v.len().is_multiple_of(4)),
        "todo valor de uma mensagem tem um múltiplo de quatro bytes"
    );
    let mut saida = Vec::new();
    saida.extend_from_slice(&(campos.len() as u32).to_le_bytes());
    let mut deslocamento = 0u32;
    for (_, valor) in &campos[..campos.len().saturating_sub(1)] {
        deslocamento += valor.len() as u32;
        saida.extend_from_slice(&deslocamento.to_le_bytes());
    }
    for (e, _) in &campos {
        saida.extend_from_slice(&e.to_le_bytes());
    }
    for (_, valor) in &campos {
        saida.extend_from_slice(valor);
    }
    saida
}

/// O pacote: `ROUGHTIM`, o comprimento da mensagem e a mensagem.
fn emoldurar(m: &[u8]) -> Vec<u8> {
    let mut pacote = Vec::with_capacity(12 + m.len());
    pacote.extend_from_slice(MAGICO);
    pacote.extend_from_slice(&(m.len() as u32).to_le_bytes());
    pacote.extend_from_slice(m);
    pacote
}

/// As etiquetas e os valores de uma mensagem, conferida: cabeçalho inteiro,
/// deslocamentos múltiplos de quatro e sem voltar, etiquetas crescentes.
fn ler(m: &[u8]) -> Option<Vec<(u32, &[u8])>> {
    let palavra =
        |i: usize| -> Option<u32> { Some(u32::from_le_bytes(m.get(i..i + 4)?.try_into().ok()?)) };
    let n = palavra(0)? as usize;
    if n == 0 || n > 64 || !m.len().is_multiple_of(4) {
        return None;
    }
    let valores = 8 * n;
    if valores > m.len() {
        return None;
    }
    let mut inicios = vec![0usize];
    for j in 0..n - 1 {
        inicios.push(palavra(4 + 4 * j)? as usize);
    }
    let tamanho = m.len() - valores;
    let mut campos = Vec::new();
    let mut anterior: Option<u32> = None;
    for j in 0..n {
        let e = palavra(4 + 4 * (n - 1) + 4 * j)?;
        if anterior.is_some_and(|a| e <= a) {
            return None;
        }
        anterior = Some(e);
        let (de, ate) = (inicios[j], inicios.get(j + 1).copied().unwrap_or(tamanho));
        if !de.is_multiple_of(4) || de > ate || ate > tamanho {
            return None;
        }
        campos.push((e, &m[valores + de..valores + ate]));
    }
    Some(campos)
}

/// O pedido é um que esta fonte atende: a moldura, pelo menos 1024 bytes, o
/// tipo de pedido, a versão 1 entre as oferecidas, um nonce de 32 bytes, e
/// o `SRV` desta raiz — ou nenhum. Devolve o nonce.
fn conferir_o_pedido(pacote: &[u8], raiz: &SigningKey) -> Result<[u8; 32], &'static str> {
    if pacote.len() < MENOR_PEDIDO {
        return Err("pedido curto");
    }
    if &pacote[..8] != MAGICO
        || u32::from_le_bytes(pacote[8..12].try_into().unwrap_or_default()) as usize
            != pacote.len() - 12
    {
        return Err("moldura");
    }
    let campos = ler(&pacote[12..]).ok_or("estrutura")?;
    let valor = |e: u32| campos.iter().find(|(t, _)| *t == e).map(|(_, v)| *v);
    if valor(etiqueta::TYPE) != Some(&0u32.to_le_bytes()[..]) {
        return Err("tipo");
    }
    let versoes = valor(etiqueta::VER).ok_or("sem versao")?;
    if !versoes
        .chunks(4)
        .any(|v| v == VERSAO.to_le_bytes().as_slice())
    {
        return Err("versao");
    }
    if let Some(srv) = valor(etiqueta::SRV) {
        let nosso = h(&[&[0xff], &raiz.verifying_key().to_bytes()]);
        if srv != nosso {
            return Err("srv de outra raiz");
        }
    }
    valor(etiqueta::NONC)
        .and_then(|n| n.try_into().ok())
        .ok_or("nonce")
}

#[cfg(test)]
mod testes {
    use super::*;

    fn fonte() -> Fonte {
        Fonte::nova(
            SigningKey::from_bytes(&[0x21; 32]),
            SigningKey::from_bytes(&[0x22; 32]),
            1_000_000_000,
            3_000_000_000,
        )
    }

    fn pedido_para(raiz: &SigningKey, nonce: &[u8; 32]) -> hora::pedido::Pedido {
        hora::pedido::Pedido::novo(nonce, &raiz.verifying_key().to_bytes())
    }

    /// O kernel confere com o leitor do `hora`: o que este servidor manda tem
    /// de passar por ele, com o carimbo e o raio que o modo pediu.
    #[test]
    fn a_resposta_daqui_passa_pelo_leitor_do_kernel() {
        let f = fonte();
        let nonce = [0x33; 32];
        let p = pedido_para(&f.raiz, &nonce);
        let recebido = conferir_o_pedido(p.bytes(), &f.raiz).expect("o pedido do kernel se atende");
        assert_eq!(recebido, nonce);
        let modo = Modo {
            raio_s: 7,
            ..Modo::HONESTA
        };
        let (r, indice) = f.responder(p.bytes(), &nonce, 1_791_158_400, &modo);
        assert_eq!(indice, 0);
        let prova = hora::resposta::conferir(
            &r,
            &hora::resposta::Esperado {
                nonce: &nonce,
                folha: p.folha(),
                chave_longa: &f.raiz.verifying_key().to_bytes(),
                teto_do_raio: 10,
            },
        )
        .expect("a resposta daqui fecha no leitor do kernel");
        assert_eq!((prova.midp, prova.radi), (1_791_158_400, 7));
        assert_eq!(prova.delegada, f.delegada.verifying_key().to_bytes());
    }

    /// A forjada é a resposta honesta assinada por outra chave: o leitor do
    /// kernel a recusa pela assinatura da resposta, e não por outra coisa.
    #[test]
    fn a_forjada_e_recusada_pela_assinatura_da_resposta() {
        let f = fonte();
        let nonce = [0x44; 32];
        let p = pedido_para(&f.raiz, &nonce);
        let modo = Modo {
            forjada: true,
            ..Modo::HONESTA
        };
        let (r, _) = f.responder(p.bytes(), &nonce, 1_791_158_400, &modo);
        let esperado = hora::resposta::Esperado {
            nonce: &nonce,
            folha: p.folha(),
            chave_longa: &f.raiz.verifying_key().to_bytes(),
            teto_do_raio: 10,
        };
        assert_eq!(
            hora::resposta::conferir(&r, &esperado),
            Err(hora::resposta::Recusa::AssinaturaDaResposta)
        );
        let (honesta, _) = f.responder(p.bytes(), &nonce, 1_791_158_400, &Modo::HONESTA);
        assert!(hora::resposta::conferir(&honesta, &esperado).is_ok());
    }

    /// Num lote, o pedido vai na última folha: o `INDX` com todos os bits do
    /// caminho ligados, e o caminho com um resumo por nível.
    #[test]
    fn um_lote_fecha_no_leitor_do_kernel() {
        let f = fonte();
        for lote in [2u32, 4, 8, 32] {
            let nonce = [lote as u8; 32];
            let p = pedido_para(&f.raiz, &nonce);
            let modo = Modo {
                lote,
                ..Modo::HONESTA
            };
            let (r, indice) = f.responder(p.bytes(), &nonce, 1_791_158_400, &modo);
            assert_eq!(indice, lote - 1);
            let esperado = hora::resposta::Esperado {
                nonce: &nonce,
                folha: p.folha(),
                chave_longa: &f.raiz.verifying_key().to_bytes(),
                teto_do_raio: 10,
            };
            hora::resposta::conferir(&r, &esperado)
                .unwrap_or_else(|e| panic!("lote de {lote}: {e:?}"));
            let topo = ler(&r[12..]).unwrap();
            let caminho = topo.iter().find(|(e, _)| *e == etiqueta::PATH).unwrap().1;
            assert_eq!(caminho.len(), 32 * lote.trailing_zeros() as usize);
            // Outro pedido não fecha a mesma resposta: a folha é do pacote.
            let outro = pedido_para(&f.raiz, &[0xee; 32]);
            let alheio = hora::resposta::Esperado {
                folha: outro.folha(),
                ..esperado
            };
            assert_eq!(
                hora::resposta::conferir(&r, &alheio),
                Err(hora::resposta::Recusa::OutroPedido)
            );
        }
    }

    /// A resposta ao pedido do vetor da RFC 10049 tem o desenho da resposta
    /// do vetor: as mesmas etiquetas, na mesma ordem, com os mesmos
    /// tamanhos, em cada nível. O vetor é de outra implementação.
    #[test]
    fn o_desenho_e_o_da_resposta_do_vetor_da_rfc() {
        let dados = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../hora/testdata");
        let pedido = std::fs::read(dados.join("rfc10049-pedido.104172a3")).unwrap();
        let vetor = std::fs::read(dados.join("rfc10049-resposta.104172a3")).unwrap();
        let f = fonte();
        let nonce =
            conferir_o_pedido(&pedido, &f.raiz).expect("o pedido do vetor, sem SRV, se atende");
        let (r, _) = f.responder(&pedido, &nonce, 1_791_158_400, &Modo::HONESTA);
        /// Cada etiqueta, o tamanho do valor, e as de dentro dele.
        type Desenho = Vec<(u32, usize, Vec<(u32, usize)>)>;
        fn desenho(m: &[u8]) -> Desenho {
            ler(m)
                .unwrap()
                .into_iter()
                .map(|(e, v)| {
                    let dentro = if [etiqueta::SREP, etiqueta::CERT, etiqueta::DELE].contains(&e) {
                        ler(v)
                            .unwrap()
                            .into_iter()
                            .map(|(e, v)| (e, v.len()))
                            .collect()
                    } else {
                        Vec::new()
                    };
                    (e, v.len(), dentro)
                })
                .collect()
        }
        assert_eq!(r.len(), vetor.len());
        assert_eq!(desenho(&r[12..]), desenho(&vetor[12..]));
        let cert = |m: &[u8]| {
            ler(m)
                .unwrap()
                .into_iter()
                .find(|(e, _)| *e == etiqueta::CERT)
                .unwrap()
                .1
                .to_vec()
        };
        let dele = |c: &[u8]| {
            ler(c)
                .unwrap()
                .into_iter()
                .find(|(e, _)| *e == etiqueta::DELE)
                .unwrap()
                .1
                .to_vec()
        };
        assert_eq!(
            desenho(&dele(&cert(&r[12..]))),
            desenho(&dele(&cert(&vetor[12..])))
        );
        // E o nonce do pedido volta no NONC, como no vetor.
        let nonc = |m: &[u8]| {
            ler(m)
                .unwrap()
                .into_iter()
                .find(|(e, _)| *e == etiqueta::NONC)
                .unwrap()
                .1
                .to_vec()
        };
        assert_eq!(nonc(&r[12..]), nonc(&vetor[12..]));
    }

    /// O que este servidor não atende fica sem resposta, com o motivo.
    #[test]
    fn o_pedido_que_nao_se_atende_e_ignorado() {
        let f = fonte();
        let nonce = [0x44; 32];
        let bom = pedido_para(&f.raiz, &nonce).bytes().to_vec();
        let de_outra = pedido_para(&SigningKey::from_bytes(&[0x99; 32]), &nonce);
        assert_eq!(
            conferir_o_pedido(de_outra.bytes(), &f.raiz),
            Err("srv de outra raiz")
        );
        assert_eq!(
            conferir_o_pedido(&bom[..1020], &f.raiz),
            Err("pedido curto")
        );
        let mut magico = bom.clone();
        magico[0] = b'X';
        assert_eq!(conferir_o_pedido(&magico, &f.raiz), Err("moldura"));
        // O TYPE é o quarto valor: 4 + 32 + 32 bytes depois do começo dos
        // valores, que vêm depois de 5 etiquetas (8 bytes cada) e da moldura.
        let tipo = 12 + 8 * 5 + 4 + 32 + 32;
        let mut resposta = bom.clone();
        resposta[tipo] = 1;
        assert_eq!(conferir_o_pedido(&resposta, &f.raiz), Err("tipo"));
        let versao = 12 + 8 * 5;
        let mut outra_versao = bom.clone();
        outra_versao[versao] = 2;
        assert_eq!(conferir_o_pedido(&outra_versao, &f.raiz), Err("versao"));
        assert!(conferir_o_pedido(&bom, &f.raiz).is_ok());
    }

    /// O leitor daqui recusa o que o formato proíbe.
    #[test]
    fn o_leitor_recusa_a_mensagem_torta() {
        let boa = mensagem(vec![
            (etiqueta::NONC, vec![0; 32]),
            (etiqueta::VER, vec![1, 0, 0, 0]),
        ]);
        let campos = ler(&boa).unwrap();
        assert_eq!(
            campos.iter().map(|(e, _)| *e).collect::<Vec<_>>(),
            [etiqueta::VER, etiqueta::NONC],
            "a ordem é a dos valores little-endian"
        );
        let mut fora_de_ordem = boa.clone();
        fora_de_ordem.swap(8, 12);
        fora_de_ordem.swap(9, 13);
        fora_de_ordem.swap(10, 14);
        fora_de_ordem.swap(11, 15);
        assert!(ler(&fora_de_ordem).is_none());
        let mut deslocamento_torto = boa.clone();
        deslocamento_torto[4] = 2;
        assert!(ler(&deslocamento_torto).is_none());
        assert!(ler(&boa[..boa.len() - 1]).is_none());
        assert!(ler(&[0, 0, 0, 0]).is_none());
    }

    /// As constantes daqui, escritas de novo, são as do leitor do kernel —
    /// se não fossem, um dos dois estaria lendo outro formato.
    #[test]
    fn as_constantes_sao_as_do_leitor_do_kernel() {
        assert_eq!(CONTEXTO_DA_DELEGACAO, hora::resposta::CONTEXTO_DE_DELEGACAO);
        assert_eq!(CONTEXTO_DA_RESPOSTA, hora::resposta::CONTEXTO_DE_RESPOSTA);
        assert_eq!(VERSAO, hora::pedido::VERSAO);
        assert_eq!(MENOR_PEDIDO, hora::pedido::TAMANHO);
        use hora::mensagem as m;
        for (daqui, de_la) in [
            (etiqueta::SIG, m::SIG),
            (etiqueta::VER, m::VER),
            (etiqueta::SRV, m::SRV),
            (etiqueta::NONC, m::NONC),
            (etiqueta::TYPE, m::TYPE),
            (etiqueta::PATH, m::PATH),
            (etiqueta::SREP, m::SREP),
            (etiqueta::CERT, m::CERT),
            (etiqueta::INDX, m::INDX),
            (etiqueta::RADI, m::RADI),
            (etiqueta::MIDP, m::MIDP),
            (etiqueta::VERS, m::VERS),
            (etiqueta::ROOT, m::ROOT),
            (etiqueta::DELE, m::DELE),
            (etiqueta::PUBK, m::PUBK),
            (etiqueta::MINT, m::MINT),
            (etiqueta::MAXT, m::MAXT),
        ] {
            assert_eq!(daqui.to_le_bytes(), de_la);
        }
        let raiz = SigningKey::from_bytes(&[0x21; 32]);
        assert_eq!(
            h(&[&[0xff], &raiz.verifying_key().to_bytes()]),
            hora::pedido::srv(&raiz.verifying_key().to_bytes())
        );
    }

    /// O destino do registro dá a porta, e só a forma UDP vale.
    #[test]
    fn a_porta_sai_do_destino_do_registro() {
        assert_eq!(porta_de("udp:10.0.2.2:5319"), Ok(5319));
        assert!(porta_de("tcp:10.0.2.2:5319").is_err());
        assert!(porta_de("udp:10.0.2.2").is_err());
        for (_, destino) in super::super::chaves::FONTES_DE_HORA {
            assert!(porta_de(destino).is_ok(), "{destino}");
        }
    }
}
