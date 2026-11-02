//! Um processo que espera a malha num lugar só, para a suíte: os casos
//! `aviso:` lançam este programa, ditam os passos pelo canal dele e leem, no
//! log, cada aviso que o kernel publica ali.
//!
//! O programa escuta `teste-avisado-<id>` — o laço dele —, oferece a
//! intenção [`INTENCAO`] com o aviso no mesmo canal e diz `avisado: pronto
//! <endpoint> <descritor do canal>`. Daí em diante, cada linha começa com
//! `avisado <id>: `, o id do processo — a suíte lança dois. Cada aviso da
//! malha vira uma linha `aviso <fluxo|endpoint> <numero> <bits>`; o programa não opera
//! sozinho — quem dita o que ele faz é a suíte, e assim ela vê exatamente o
//! que o kernel publicou, quando e quantas vezes. Os passos (`a` da ação,
//! `b` e `c` os argumentos):
//!
//! - [`ABRIR`]: abre um fluxo contra o outro programa que oferece a
//!   intenção — ou contra o endpoint de número `c`, se não é zero —, com o
//!   aviso se `b` é 1; diz `abri <numero>`.
//! - [`ACEITAR`]: aceita sem esperar, com o aviso se `b` é 1; diz `aceitei
//!   <numero>` ou `aceitar nada`.
//! - [`LER`]: lê até `c` bytes do fluxo `b`, sem esperar; diz `li <numero>
//!   <n> <fim> <resumo>`.
//! - [`ESCREVER`]: escreve `c` bytes do padrão no fluxo `b`, uma vez, sem
//!   esperar; diz `escrevi <numero> <k>`.
//! - [`TERMINAR`], [`FECHAR`], [`ESTADO`]: no fluxo `b`.
//! - [`RECEBER`]: `fabric.recv` no endpoint dele, sem esperar; diz `recebi
//!   <n>`.
//! - [`ENVIAR`]: uma entrega ao outro; diz `enviei`.
//! - [`TROCAR`]: troca de imagem para o `ola` — as designações saem.
//! - [`BIFURCAR`]: o filho pede um fluxo com o descritor do canal herdado
//!   do pai — que não é dele — e diz o que ouviu.
//! - [`RUIM`]: pede um fluxo com `notify` apontando o descritor `b`, que não
//!   é um canal de eventos.
//! - [`PAUSAR`]: fica `b` ms sem ler o canal — parado num `fabric.recv` —,
//!   para a suíte encher o canal.
//! - [`DUPLEX`]: manda `c` bytes do padrão no fluxo `b` e lê o que vem até o
//!   fim, ao mesmo tempo, guiado só pelos avisos — escreve o que cabe, lê o
//!   que há, e dorme no canal; diz `duplex <numero> <lidos> <resumo>
//!   <avisos> <voltas>`.
//! - [`BLOQUEANTE`]: o controle do `DUPLEX`, no estilo do DN-2 — escreve
//!   tudo esperando espaço, e só depois lê —; diz `bloqueante <numero>
//!   prazo` quando a escrita vence o prazo.
//! - [`MANDAR_LACO`] e [`RECEBER_LACO`]: só um sentido, pelo laço — manda
//!   `c` bytes e termina; lê até o fim —; dizem `mandei_laco <numero>` e
//!   `recebi_laco <numero> <lidos> <resumo>`.
//! - [`MANDAR_BLOQ`] e [`RECEBER_BLOQ`]: o mesmo, esperando em cada pedido,
//!   como no DN-2; dizem `mandei_bloq <numero>` e `recebi_bloq <numero>
//!   <lidos> <resumo>`.
//! - [`CONTAR`]: diz `testes <n>`, quantos eventos `TESTE` chegaram — a
//!   suíte enche o canal com eles, e o programa os conta calado.
//! - [`OUTRO_CANAL`]: escuta um segundo canal, `teste-avisado-<id>-2`, que
//!   ele nunca lê; diz `outro <descritor>`. [`FECHAR_OUTRO`] fecha o
//!   descritor `b`; diz `fechei_outro <r>` — o canal fica sem ouvinte, com o
//!   processo vivo.
//!
//! Cada falha diz o passo e o código, e o programa segue escutando. O
//! [`tipo::ENCERRAR`] o encerra com [`CODIGO`] — também no meio de um passo
//! que espera no laço.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "avisado",
    "fabric.offer",
    "fabric.send",
    "fabric.stream",
    "fabric.remote",
    "process.run"
);

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use programas::escreverln;

/// Diz uma linha no log, com o id do processo — a suíte lança dois e
/// separa as linhas de cada um —, sem o tamanho que `escreverln!` devolve.
macro_rules! diz {
    ($($t:tt)*) => {{
        let _ = escreverln!("avisado {}: {}", sistema::id(), format_args!($($t)*));
    }};
}
use programas::fluxo::{self, Fluxo};
use programas::laco::{Acontecimento, Laco};
use programas::malha;
use programas::nativo;
use programas::sistema;
use protocolo::usuario::evento::{Evento, tipo};

/// A intenção que ele oferece.
const INTENCAO: &str = "imagem.compartilhar";

/// Os passos.
const ABRIR: i64 = 1;
const ACEITAR: i64 = 2;
const LER: i64 = 3;
const ESCREVER: i64 = 4;
const TERMINAR: i64 = 5;
const FECHAR: i64 = 6;
const RECEBER: i64 = 7;
const ENVIAR: i64 = 8;
const TROCAR: i64 = 9;
const BIFURCAR: i64 = 10;
const ESTADO: i64 = 11;
const RUIM: i64 = 12;
const PAUSAR: i64 = 13;
const DUPLEX: i64 = 14;
const BLOQUEANTE: i64 = 15;
const CONTAR: i64 = 16;
const MANDAR_LACO: i64 = 17;
const RECEBER_LACO: i64 = 18;
const MANDAR_BLOQ: i64 = 19;
const RECEBER_BLOQ: i64 = 20;
const OUTRO_CANAL: i64 = 21;
const FECHAR_OUTRO: i64 = 22;

/// O teto do que um passo de um sentido lê: 4 MiB.
const TETO: usize = 4 * 1024 * 1024;

/// O código de saída no fim pedido — o mesmo do `ola`, a imagem da troca.
const CODIGO: i64 = 61;

/// A imagem da troca: o `ola`, do disco dos programas.
#[cfg(target_arch = "x86_64")]
const OLA: &str = "/programas/x86_64/ola";
#[cfg(target_arch = "aarch64")]
const OLA: &str = "/programas/aarch64/ola";

/// O byte `i` do padrão determinístico.
fn padrao(i: usize) -> u8 {
    ((i * 7 + 3) % 251) as u8
}

/// O FNV-1a de 64 bits.
fn resumo(bytes: &[u8]) -> u64 {
    somar(0xcbf2_9ce4_8422_2325, bytes)
}

/// Continua o FNV-1a `h` com `bytes`.
fn somar(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// O que um passo guiado pelo laço leu: quantos bytes, o resumo, quantos
/// avisos do fluxo acordaram o programa e quantas voltas ele deu.
struct Lido {
    bytes: usize,
    resumo: u64,
    avisos: u64,
    voltas: u64,
}

/// O endpoint de outro programa que oferece a intenção — não o deste.
fn o_outro(meu: &str) -> Option<String> {
    malha::descobrir(INTENCAO)
        .ok()?
        .into_iter()
        .map(|c| c.endpoint)
        .find(|e| e != meu)
}

struct Estado {
    laco: Laco,
    endpoint: String,
    fluxos: BTreeMap<u64, Fluxo>,
    /// Quantos eventos `TESTE` chegaram.
    testes: u64,
}

impl Estado {
    fn fluxo(&self, b: i64) -> Option<&Fluxo> {
        self.fluxos.get(&(b.max(0) as u64))
    }

    /// Manda `mandar` bytes do padrão no fluxo `n` — e termina o sentido —
    /// e, se `ler`, lê até o fim: escreve o que cabe, lê o que há e dorme no
    /// canal até o próximo aviso. O único lugar em que dorme é o laço.
    fn pelo_laco(&mut self, n: u64, mandar: usize, ler: bool) -> Result<Lido, String> {
        let dados: Vec<u8> = (0..mandar).map(padrao).collect();
        let mut enviados = 0;
        let mut terminei = mandar == 0;
        let mut lido = Lido {
            bytes: 0,
            resumo: 0xcbf2_9ce4_8422_2325,
            avisos: 0,
            voltas: 0,
        };
        let mut fim = !ler;
        loop {
            let f = self
                .fluxos
                .get(&n)
                .ok_or_else(|| format!("sem o fluxo {n}"))?;
            while enviados < mandar {
                match f.escrever_agora(&dados[enviados..]) {
                    Ok(0) => break,
                    Ok(k) => enviados += k,
                    Err(e) => return Err(format!("escrever {} {}", e.codigo(), e.motivo())),
                }
            }
            if enviados == mandar && !terminei {
                f.terminar()
                    .map_err(|e| format!("terminar {} {}", e.codigo(), e.motivo()))?;
                terminei = true;
            }
            while !fim {
                let (bytes, acabou) = f
                    .ler_agora(fluxo::MAIOR_PEDACO)
                    .map_err(|e| format!("ler {} {}", e.codigo(), e.motivo()))?;
                lido.bytes += bytes.len();
                lido.resumo = somar(lido.resumo, &bytes);
                fim = acabou;
                if bytes.is_empty() {
                    break;
                }
            }
            if terminei && fim {
                return Ok(lido);
            }
            lido.voltas += 1;
            for a in self.laco.esperar().map_err(|e| format!("laco {e}"))? {
                match a {
                    Acontecimento::Fluxo { numero, .. } if numero == n => lido.avisos += 1,
                    Acontecimento::Evento(Evento {
                        tipo: tipo::ENCERRAR,
                        ..
                    }) => {
                        diz!("encerrado");
                        sistema::sair(CODIGO);
                    }
                    _ => {}
                }
            }
        }
    }

    fn passo(&mut self, a: i64, b: i64, c: i64) {
        match a {
            ABRIR => {
                // `c`, quando não é zero, é o número do endpoint de destino,
                // da mesma época que o deste.
                let alvo = if c > 0 {
                    self.endpoint
                        .rsplit_once(':')
                        .map(|(epoca, _)| format!("{epoca}:{c}"))
                } else {
                    o_outro(&self.endpoint)
                };
                let Some(outro) = alvo else {
                    diz!("abrir sem o outro");
                    return;
                };
                let r = if b == 1 {
                    fluxo::abrir_avisando(&outro, INTENCAO, &self.laco)
                } else {
                    fluxo::abrir(&outro, INTENCAO)
                };
                match r {
                    Ok(f) => {
                        let n = f.numero().unwrap_or(0);
                        diz!("abri {}", n);
                        self.fluxos.insert(n, f);
                    }
                    Err(e) => diz!("abrir {} {}", e.codigo(), e.motivo()),
                }
            }
            ACEITAR => {
                let r = if b == 1 {
                    fluxo::aceitar_avisando(&self.endpoint, &self.laco)
                } else {
                    fluxo::aceitar(&self.endpoint, 0)
                };
                match r {
                    Ok(Some((f, _))) => {
                        let n = f.numero().unwrap_or(0);
                        diz!("aceitei {}", n);
                        self.fluxos.insert(n, f);
                    }
                    Ok(None) => diz!("aceitar nada"),
                    Err(e) => diz!("aceitar {} {}", e.codigo(), e.motivo()),
                }
            }
            LER => {
                let Some(f) = self.fluxo(b) else {
                    diz!("ler sem o fluxo {}", b);
                    return;
                };
                match f.ler_agora(c.max(1) as usize) {
                    Ok((bytes, fim)) => diz!(
                        "li {} {} {} {:016x}",
                        b,
                        bytes.len(),
                        fim as u8,
                        resumo(&bytes)
                    ),
                    Err(e) => diz!("ler {} {} {}", b, e.codigo(), e.motivo()),
                }
            }
            ESCREVER => {
                let Some(f) = self.fluxo(b) else {
                    diz!("escrever sem o fluxo {}", b);
                    return;
                };
                let dados: Vec<u8> = (0..c.max(0) as usize).map(padrao).collect();
                match f.escrever_agora(&dados) {
                    Ok(k) => diz!("escrevi {} {}", b, k),
                    Err(e) => diz!("escrever {} {} {}", b, e.codigo(), e.motivo()),
                }
            }
            TERMINAR | FECHAR | ESTADO => {
                let Some(f) = self.fluxo(b) else {
                    diz!("sem o fluxo {}", b);
                    return;
                };
                let r = match a {
                    TERMINAR => f.terminar().map(|_| String::from("terminei")),
                    FECHAR => f.fechar().map(|_| String::from("fechei")),
                    _ => f.estado().map(|e| format!("estado {}", e.estado)),
                };
                match r {
                    Ok(t) => diz!("{} {}", t, b),
                    Err(e) => diz!("passo {} {} {} {}", a, b, e.codigo(), e.motivo()),
                }
            }
            RECEBER => match malha::receber(&self.endpoint, None, 0) {
                Ok(v) => diz!("recebi {}", v.len()),
                Err(e) => diz!("receber {}", e.codigo()),
            },
            ENVIAR => {
                let Some(outro) = o_outro(&self.endpoint) else {
                    diz!("enviar sem o outro");
                    return;
                };
                match malha::enviar(
                    &outro,
                    INTENCAO,
                    "x",
                    sistema::id() as u64 * 1000 + c as u64,
                ) {
                    Ok(_) => diz!("enviei"),
                    Err(e) => diz!("enviar {}", e.codigo()),
                }
            }
            TROCAR => {
                diz!("trocando");
                let r = sistema::executar(OLA);
                diz!("trocar devolveu {}", r);
            }
            BIFURCAR => match sistema::bifurcar() {
                0 => {
                    // O descritor do canal veio do pai; o canal não.
                    let r = pedir_com_aviso(self.laco.descritor());
                    diz!("filho pediu {}", r);
                    sistema::sair(CODIGO);
                }
                filho if filho > 0 => diz!("filho {}", filho),
                erro => diz!("bifurcar devolveu {}", erro),
            },
            RUIM => {
                let r = pedir_com_aviso(b.max(0) as u64);
                diz!("ruim {}", r);
            }
            PAUSAR => {
                diz!("pausando");
                let _ = malha::receber(&self.endpoint, None, b.max(1) as u64);
                diz!("voltei");
            }
            DUPLEX | MANDAR_LACO | RECEBER_LACO => {
                let n = b.max(0) as u64;
                let (mandar, ler) = match a {
                    DUPLEX => (c.max(0) as usize, true),
                    MANDAR_LACO => (c.max(0) as usize, false),
                    _ => (0, true),
                };
                match self.pelo_laco(n, mandar, ler) {
                    Ok(l) if a == DUPLEX => diz!(
                        "duplex {} {} {:016x} {} {}",
                        n,
                        l.bytes,
                        l.resumo,
                        l.avisos,
                        l.voltas
                    ),
                    Ok(_) if a == MANDAR_LACO => diz!("mandei_laco {}", n),
                    Ok(l) => diz!("recebi_laco {} {} {:016x}", n, l.bytes, l.resumo),
                    Err(e) => diz!("passo {} {} {}", a, n, e),
                }
            }
            BLOQUEANTE | MANDAR_BLOQ => {
                let Some(f) = self.fluxo(b) else {
                    diz!("sem o fluxo {}", b);
                    return;
                };
                let dados: Vec<u8> = (0..c.max(0) as usize).map(padrao).collect();
                // O estilo do DN-2: cada pedido espera até 100 ms, e vinte
                // esperas vazias seguidas são o prazo.
                let r = f.escrever_tudo(&dados, 100, 20).and_then(|()| f.terminar());
                let nome = if a == BLOQUEANTE {
                    "bloqueante"
                } else {
                    "mandei_bloq"
                };
                match r {
                    Ok(()) => diz!("{} {}", nome, b),
                    Err(fluxo::Falha::Prazo) => diz!("{} {} prazo", nome, b),
                    Err(e) => diz!("{} {} {} {}", nome, b, e.codigo(), e.motivo()),
                }
            }
            RECEBER_BLOQ => {
                let Some(f) = self.fluxo(b) else {
                    diz!("sem o fluxo {}", b);
                    return;
                };
                let mut tudo = Vec::new();
                match f.ler_tudo(&mut tudo, TETO, 100, 50) {
                    Ok(()) => diz!("recebi_bloq {} {} {:016x}", b, tudo.len(), resumo(&tudo)),
                    Err(e) => diz!("recebi_bloq {} {} {}", b, e.codigo(), e.motivo()),
                }
            }
            CONTAR => diz!("testes {}", self.testes),
            OUTRO_CANAL => diz!(
                "outro {}",
                sistema::escutar(&format!("teste-avisado-{}-2", sistema::id()))
            ),
            FECHAR_OUTRO => diz!("fechei_outro {}", sistema::fechar(b.max(0) as u64)),
            outro => diz!("passo desconhecido {}", outro),
        }
    }
}

/// Um `stream.open` contra o próprio endpoint com `notify` apontando o
/// descritor `d`: o código do que o kernel respondeu.
fn pedir_com_aviso(d: u64) -> String {
    let meu = malha::oferecer(INTENCAO).unwrap_or_default();
    let alvo = o_outro(&meu).unwrap_or(meu);
    let r = nativo::pedir("stream.open", |w| {
        w.field_str("endpoint", &alvo)?;
        w.field_str("intent", INTENCAO)?;
        w.field_u64("notify", d)
    });
    match r {
        Err(e) => format!("CHAMADA {e}"),
        Ok(r) => match r.resultado() {
            Ok(res) if res.member("ok").and_then(|v| v.as_bool()) == Some(true) => {
                String::from("OK")
            }
            Ok(res) => res
                .member("code")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_default(),
            Err(recusa) => String::from(recusa.motivo.unwrap_or("ERROR")),
        },
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let laco = match Laco::com_nome(&format!("teste-avisado-{}", sistema::id())) {
        Ok(l) => l,
        Err(e) => {
            diz!("escutar devolveu {}", e);
            return 1;
        }
    };
    let endpoint = match malha::oferecer_avisando(INTENCAO, &laco) {
        Ok(e) => e,
        Err(f) => {
            diz!("oferecer {}", f.codigo());
            return 3;
        }
    };
    let _ = escreverln!("avisado: pronto {} {}", endpoint, laco.descritor());
    let mut estado = Estado {
        laco,
        endpoint,
        fluxos: BTreeMap::new(),
        testes: 0,
    };
    loop {
        let acontecimentos = match estado.laco.esperar() {
            Ok(v) => v,
            Err(e) => {
                diz!("a leitura falhou: {}", e);
                return 2;
            }
        };
        for a in acontecimentos {
            match a {
                Acontecimento::Fluxo { numero, prontidao } => {
                    diz!("aviso fluxo {} {}", numero, prontidao.bits())
                }
                Acontecimento::Endpoint { numero, prontidao } => {
                    diz!("aviso endpoint {} {}", numero, prontidao.bits())
                }
                Acontecimento::Evento(Evento { tipo: t, a, b, c }) => match t {
                    tipo::ENCERRAR => {
                        diz!("encerrado");
                        return CODIGO;
                    }
                    tipo::ACAO => estado.passo(a, b, c),
                    tipo::TESTE => estado.testes += 1,
                    _ => diz!("evento {} {}", t, a),
                },
            }
        }
    }
}
