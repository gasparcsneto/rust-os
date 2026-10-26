//! O disco hostil da bancada de persistência: um servidor NBD no
//! hospedeiro, entre o emulador e o arquivo do disco, que faz o que um disco
//! de verdade faz de pior — e que o arquivo, sozinho, não faz.
//!
//! # Por que um servidor, e não o arquivo
//!
//! A bancada corta a energia matando o emulador. O que ele já escreveu no
//! arquivo está no cache de páginas do hospedeiro, e sobrevive ao corte: uma
//! escrita que o kernel do Duke mandou e nunca descarregou chega ao arquivo
//! igual a uma descarregada. A bancada não distinguia as duas — e a promessa
//! do journal é exatamente essa diferença: o que foi confirmado foi
//! descarregado antes. Um kernel que confirmasse antes de descarregar
//! passaria em todo cenário.
//!
//! Aqui cada escrita fica num cache volátil do servidor até um `FLUSH`, e
//! só então vai ao arquivo. Cortar a energia é perder o cache: o que não
//! foi descarregado some — todo, ou uma parte, como num SSD sem capacitor
//! que já tinha gravado alguns setores do cache, em qualquer ordem.
//!
//! # As falhas
//!
//! - **O cache volátil**: sempre. O fim da conexão sem `DISC` é o corte.
//! - **O erro de mídia**: uma faixa de setores em que a leitura, ou a
//!   escrita, volta com `EIO` — o NVMe do emulador a conclui como um setor
//!   ruim ("leitura irrecuperável", "falha de escrita").
//! - **A resposta retida**: um pedido que toque uma faixa não é respondido,
//!   nunca. O controlador do emulador espera com ele, e o driver do Duke,
//!   depois do prazo do disco, desliga o dispositivo.
//!
//! # O protocolo
//!
//! O NBD *newstyle* fixo, só o que o QEMU usa: a negociação por
//! `NBD_OPT_GO` (ou o antigo `NBD_OPT_EXPORT_NAME`), sem respostas
//! estruturadas, e os comandos `READ`, `WRITE`, `FLUSH` e `DISC`. Uma
//! conexão por vez: um boot. Ver
//! <https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md>.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// O tamanho de um setor: a unidade do cache e das faixas.
const SETOR: u64 = 512;

// A negociação.
const NBDMAGIC: &[u8; 8] = b"NBDMAGIC";
const IHAVEOPT: u64 = 0x4948_4156_454F_5054;
const FLAG_FIXED_NEWSTYLE: u16 = 1;
const FLAG_NO_ZEROES: u16 = 2;
const FLAG_C_NO_ZEROES: u32 = 2;
const OPT_EXPORT_NAME: u32 = 1;
const OPT_ABORT: u32 = 2;
const OPT_INFO: u32 = 6;
const OPT_GO: u32 = 7;
const REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;
const REP_ACK: u32 = 1;
const REP_INFO: u32 = 3;
const REP_ERR_UNSUP: u32 = 0x8000_0001;
const INFO_EXPORT: u16 = 0;

// A transmissão.
const FLAG_HAS_FLAGS: u16 = 1;
const FLAG_SEND_FLUSH: u16 = 4;
const REQUEST_MAGIC: u32 = 0x2560_9513;
const SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;
const CMD_READ: u16 = 0;
const CMD_WRITE: u16 = 1;
const CMD_DISC: u16 = 2;
const CMD_FLUSH: u16 = 3;
const EIO: u32 = 5;
const EINVAL: u32 = 22;

/// O maior pedido que o servidor aceita: 32 MiB, o que o QEMU manda de
/// maior.
const MAIOR_PEDIDO: u32 = 32 * 1024 * 1024;

/// Uma faixa de setores, `[primeiro, primeiro + quantos)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Faixa {
    pub primeiro: u64,
    pub quantos: u64,
}

impl Faixa {
    /// Se o pedido de `bytes` bytes a partir do byte `de` toca a faixa.
    fn toca(&self, de: u64, bytes: u64) -> bool {
        let inicio = de / SETOR;
        let fim = (de + bytes).div_ceil(SETOR);
        inicio < self.primeiro + self.quantos && self.primeiro < fim
    }
}

/// Que pedidos uma falha alcança.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sentido {
    Leitura,
    Escrita,
}

/// O que se perde no corte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Corte {
    /// Todo o cache volátil.
    PerdeTudo,
    /// Uma parte dele, sorteada pela semente: os setores que ficam vão ao
    /// arquivo, e os outros somem — em qualquer ordem, setor a setor.
    GuardaParte(u64),
}

/// Onde a energia acaba, contado do momento em que o cenário arma: na
/// `n`-ésima escrita — depois de ela entrar no cache —, ou na `n`-ésima
/// descarga com escritas no cache — antes de ela gravar. É o corte no
/// meio de uma gravação, no ponto exato, e não onde o relógio do
/// hospedeiro deixar: matar o emulador por fora acerta, quase sempre, o
/// intervalo entre duas operações, com o cache vazio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gatilho {
    Escrita(u64),
    Descarga(u64),
}

/// O que o servidor viu, para o cenário conferir.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Contas {
    /// Quantas conexões houve — um boot cada —, e quantas já acabaram.
    pub conexoes: u64,
    pub encerradas: u64,
    pub escritas: u64,
    pub descargas: u64,
    /// Setores que estavam no cache volátil no corte, e quantos deles
    /// chegaram ao arquivo.
    pub no_corte: u64,
    pub guardados_no_corte: u64,
    /// Pedidos devolvidos com erro de mídia, e pedidos retidos.
    pub erros: u64,
    pub retidos: u64,
    /// Quantas vezes o gatilho cortou a energia.
    pub cortes: u64,
}

/// O estado do disco, dividido entre o servidor e o cenário.
struct Estado {
    arquivo: std::fs::File,
    tamanho: u64,
    /// O cache volátil: o setor e o conteúdo ainda não descarregados.
    volatil: BTreeMap<u64, [u8; SETOR as usize]>,
    corte: Corte,
    erro: Option<(Faixa, Sentido)>,
    reter: Option<(Faixa, Sentido)>,
    gatilho: Option<Gatilho>,
    contas: Contas,
}

impl Estado {
    /// Lê `destino.len()` bytes a partir de `de`: o arquivo, com o cache
    /// por cima — o que se escreveu e não se descarregou se lê de volta.
    fn ler(&self, de: u64, destino: &mut [u8]) -> std::io::Result<()> {
        self.arquivo.read_exact_at(destino, de)?;
        for (setor, conteudo) in self
            .volatil
            .range(de / SETOR..(de + destino.len() as u64).div_ceil(SETOR))
        {
            let inicio = setor * SETOR;
            for (i, byte) in conteudo.iter().enumerate() {
                let posicao = inicio + i as u64;
                if (de..de + destino.len() as u64).contains(&posicao) {
                    destino[(posicao - de) as usize] = *byte;
                }
            }
        }
        Ok(())
    }

    /// Escreve no cache volátil, setor a setor — um setor pela metade é lido
    /// do que já se vê e completado.
    fn escrever(&mut self, de: u64, origem: &[u8]) -> std::io::Result<()> {
        let primeiro = de / SETOR;
        let ultimo = (de + origem.len() as u64).div_ceil(SETOR);
        for setor in primeiro..ultimo {
            let mut conteudo = [0u8; SETOR as usize];
            self.ler(setor * SETOR, &mut conteudo)?;
            for (i, byte) in conteudo.iter_mut().enumerate() {
                let posicao = setor * SETOR + i as u64;
                if (de..de + origem.len() as u64).contains(&posicao) {
                    *byte = origem[(posicao - de) as usize];
                }
            }
            self.volatil.insert(setor, conteudo);
        }
        self.contas.escritas += 1;
        Ok(())
    }

    /// Põe o cache inteiro no arquivo.
    fn descarregar(&mut self) -> std::io::Result<()> {
        for (setor, conteudo) in std::mem::take(&mut self.volatil) {
            self.arquivo.write_all_at(&conteudo, setor * SETOR)?;
        }
        self.contas.descargas += 1;
        Ok(())
    }

    /// Conta um evento do tipo que `e_dele` reconhece no gatilho armado; se
    /// era o último, corta a energia e desarma. `true` se cortou.
    fn disparar(&mut self, e_dele: impl Fn(&Gatilho) -> bool) -> bool {
        let Some(g) = self.gatilho.filter(|g| e_dele(g)) else {
            return false;
        };
        let (Gatilho::Escrita(n) | Gatilho::Descarga(n)) = g;
        if n > 1 {
            self.gatilho = Some(match g {
                Gatilho::Escrita(_) => Gatilho::Escrita(n - 1),
                Gatilho::Descarga(_) => Gatilho::Descarga(n - 1),
            });
            return false;
        }
        self.gatilho = None;
        self.cortar();
        self.contas.cortes += 1;
        true
    }

    /// A energia acabou: o cache se perde, todo ou em parte.
    fn cortar(&mut self) {
        let volatil = std::mem::take(&mut self.volatil);
        self.contas.no_corte += volatil.len() as u64;
        if let Corte::GuardaParte(semente) = self.corte {
            let mut sorteio = semente | 1;
            for (setor, conteudo) in volatil {
                // Um xorshift: determinístico pela semente, e nada mais
                // que um sorteio de quais ficam.
                sorteio ^= sorteio << 13;
                sorteio ^= sorteio >> 7;
                sorteio ^= sorteio << 17;
                if sorteio & 1 == 1 && self.arquivo.write_all_at(&conteudo, setor * SETOR).is_ok() {
                    self.contas.guardados_no_corte += 1;
                }
            }
        }
    }
}

/// O disco hostil: o servidor de pé, num socket Unix, e o estado que o
/// cenário controla.
pub(crate) struct DiscoHostil {
    estado: Arc<Mutex<Estado>>,
    socket: PathBuf,
    /// Para o servidor no `Drop`: ele confere a cada conexão aceita.
    parar: Arc<AtomicBool>,
}

impl DiscoHostil {
    /// Põe o servidor de pé sobre o arquivo `disco`, no socket `socket`.
    pub(crate) fn servir(disco: &Path, socket: &Path, corte: Corte) -> Result<DiscoHostil, String> {
        let arquivo = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(disco)
            .map_err(|e| format!("disco hostil: não abriu {}: {e}", disco.display()))?;
        let tamanho = arquivo
            .metadata()
            .map_err(|e| format!("disco hostil: {e}"))?
            .len();
        let _ = std::fs::remove_file(socket);
        let escuta = UnixListener::bind(socket)
            .map_err(|e| format!("disco hostil: não escutou em {}: {e}", socket.display()))?;
        let estado = Arc::new(Mutex::new(Estado {
            arquivo,
            tamanho,
            volatil: BTreeMap::new(),
            corte,
            erro: None,
            reter: None,
            gatilho: None,
            contas: Contas::default(),
        }));
        let do_servidor = Arc::clone(&estado);
        let parar = Arc::new(AtomicBool::new(false));
        let parar_do_servidor = Arc::clone(&parar);
        std::thread::spawn(move || {
            for conexao in escuta.incoming() {
                if parar_do_servidor.load(Ordering::Acquire) {
                    return;
                }
                let Ok(conexao) = conexao else {
                    continue;
                };
                do_servidor.lock().expect("estado do disco").contas.conexoes += 1;
                // Uma conexão é um boot: quando ela acaba sem `DISC`, a
                // energia acabou — o emulador morreu.
                let limpo = atender(conexao, &do_servidor).unwrap_or(false);
                let mut e = do_servidor.lock().expect("estado do disco");
                if !limpo {
                    e.cortar();
                }
                e.contas.encerradas += 1;
            }
        });
        Ok(DiscoHostil {
            estado,
            socket: socket.to_path_buf(),
            parar,
        })
    }

    /// Espera a conexão de número `n` (de um) acabar — e, se ela acabou
    /// sem `DISC`, o corte ser aplicado: o emulador morre de fora, e o
    /// servidor só sabe quando o socket fecha.
    pub(crate) fn esperar_o_fim_da_conexao(&self, n: u64) -> Result<Contas, String> {
        let limite = Instant::now() + Duration::from_secs(30);
        loop {
            let contas = self.contas();
            if contas.encerradas >= n {
                return Ok(contas);
            }
            if Instant::now() >= limite {
                return Err(format!(
                    "disco hostil: a conexão {n} não acabou em 30s ({contas:?})"
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// O socket, para a linha de comando do emulador.
    pub(crate) fn socket(&self) -> &Path {
        &self.socket
    }

    /// Erro de mídia nos pedidos de `sentido` que toquem `faixa` — ou
    /// nenhum, com `None`.
    pub(crate) fn erro_em(&self, falha: Option<(Faixa, Sentido)>) {
        self.estado.lock().expect("estado do disco").erro = falha;
    }

    /// Nenhuma resposta aos pedidos de `sentido` que toquem `faixa` — ou
    /// todas, com `None`. Os já retidos continuam sem resposta.
    pub(crate) fn reter_em(&self, falha: Option<(Faixa, Sentido)>) {
        self.estado.lock().expect("estado do disco").reter = falha;
    }

    /// Arma o corte de energia: no ponto que `gatilho` diz, o servidor perde
    /// o cache e fecha a conexão — o emulador fica sem disco, e o cenário o
    /// mata depois, quando [`Contas::cortes`] subir.
    pub(crate) fn cortar_em(&self, gatilho: Gatilho) {
        self.estado.lock().expect("estado do disco").gatilho = Some(gatilho);
    }

    /// O que o servidor viu até agora.
    pub(crate) fn contas(&self) -> Contas {
        self.estado.lock().expect("estado do disco").contas
    }
}

/// Atende uma conexão até o fim. `Ok(true)` se ela acabou com `DISC`.
fn atender(mut c: UnixStream, estado: &Mutex<Estado>) -> std::io::Result<bool> {
    let tamanho = estado.lock().expect("estado do disco").tamanho;
    // A saudação do newstyle fixo.
    c.write_all(NBDMAGIC)?;
    c.write_all(&IHAVEOPT.to_be_bytes())?;
    c.write_all(&(FLAG_FIXED_NEWSTYLE | FLAG_NO_ZEROES).to_be_bytes())?;
    let sem_zeros = ler_u32(&mut c)? & FLAG_C_NO_ZEROES != 0;
    let flags = FLAG_HAS_FLAGS | FLAG_SEND_FLUSH;
    // As opções, até uma que leve à transmissão.
    loop {
        if ler_u64(&mut c)? != IHAVEOPT {
            return Ok(false);
        }
        let opcao = ler_u32(&mut c)?;
        let comprimento = ler_u32(&mut c)?;
        if comprimento > 4096 {
            return Ok(false);
        }
        let mut dados = vec![0u8; comprimento as usize];
        c.read_exact(&mut dados)?;
        match opcao {
            OPT_EXPORT_NAME => {
                c.write_all(&tamanho.to_be_bytes())?;
                c.write_all(&flags.to_be_bytes())?;
                if !sem_zeros {
                    c.write_all(&[0u8; 124])?;
                }
                break;
            }
            OPT_INFO | OPT_GO => {
                let mut info = Vec::with_capacity(12);
                info.extend_from_slice(&INFO_EXPORT.to_be_bytes());
                info.extend_from_slice(&tamanho.to_be_bytes());
                info.extend_from_slice(&flags.to_be_bytes());
                responder_opcao(&mut c, opcao, REP_INFO, &info)?;
                responder_opcao(&mut c, opcao, REP_ACK, &[])?;
                if opcao == OPT_GO {
                    break;
                }
            }
            OPT_ABORT => {
                responder_opcao(&mut c, opcao, REP_ACK, &[])?;
                return Ok(true);
            }
            _ => responder_opcao(&mut c, opcao, REP_ERR_UNSUP, &[])?,
        }
    }
    // A transmissão: um pedido por vez, respondido na ordem — menos os
    // retidos, que ficam sem resposta.
    loop {
        if ler_u32(&mut c)? != REQUEST_MAGIC {
            return Ok(false);
        }
        let _flags = ler_u16(&mut c)?;
        let tipo = ler_u16(&mut c)?;
        let cookie = ler_u64(&mut c)?;
        let de = ler_u64(&mut c)?;
        let bytes = ler_u32(&mut c)?;
        let mut carga = Vec::new();
        if tipo == CMD_WRITE {
            if bytes > MAIOR_PEDIDO {
                return Ok(false);
            }
            carga = vec![0u8; bytes as usize];
            c.read_exact(&mut carga)?;
        }
        let mut e = estado.lock().expect("estado do disco");
        let sentido = match tipo {
            CMD_READ => Some(Sentido::Leitura),
            CMD_WRITE => Some(Sentido::Escrita),
            _ => None,
        };
        let alcancado = |falha: Option<(Faixa, Sentido)>| matches!((falha, sentido), (Some((f, s)), Some(t)) if s == t && f.toca(de, u64::from(bytes)));
        if alcancado(e.reter) {
            e.contas.retidos += 1;
            continue;
        }
        let fora = de
            .checked_add(u64::from(bytes))
            .is_none_or(|fim| fim > e.tamanho);
        match tipo {
            CMD_READ => {
                let mut dados = vec![0u8; bytes as usize];
                let erro = if bytes > MAIOR_PEDIDO || fora {
                    EINVAL
                } else if alcancado(e.erro) {
                    e.contas.erros += 1;
                    EIO
                } else if e.ler(de, &mut dados).is_err() {
                    EIO
                } else {
                    0
                };
                drop(e);
                responder(&mut c, erro, cookie)?;
                if erro == 0 {
                    c.write_all(&dados)?;
                }
            }
            CMD_WRITE => {
                let erro = if fora {
                    EINVAL
                } else if alcancado(e.erro) {
                    e.contas.erros += 1;
                    EIO
                } else if e.escrever(de, &carga).is_err() {
                    EIO
                } else {
                    0
                };
                // A escrita entrou no cache; se é a do gatilho, a energia
                // acaba aqui, sem resposta.
                if erro == 0 && e.disparar(|g| matches!(g, Gatilho::Escrita(_))) {
                    return Ok(true);
                }
                drop(e);
                responder(&mut c, erro, cookie)?;
            }
            CMD_FLUSH => {
                // Uma descarga com o que perder: se é a do gatilho, a
                // energia acaba antes de ela gravar.
                if !e.volatil.is_empty() && e.disparar(|g| matches!(g, Gatilho::Descarga(_))) {
                    return Ok(true);
                }
                let erro = if e.descarregar().is_err() { EIO } else { 0 };
                drop(e);
                responder(&mut c, erro, cookie)?;
            }
            CMD_DISC => return Ok(true),
            _ => {
                drop(e);
                responder(&mut c, EINVAL, cookie)?;
            }
        }
    }
}

fn responder(c: &mut UnixStream, erro: u32, cookie: u64) -> std::io::Result<()> {
    let mut r = Vec::with_capacity(16);
    r.extend_from_slice(&SIMPLE_REPLY_MAGIC.to_be_bytes());
    r.extend_from_slice(&erro.to_be_bytes());
    r.extend_from_slice(&cookie.to_be_bytes());
    c.write_all(&r)
}

fn responder_opcao(c: &mut UnixStream, opcao: u32, tipo: u32, dados: &[u8]) -> std::io::Result<()> {
    let mut r = Vec::with_capacity(20 + dados.len());
    r.extend_from_slice(&REPLY_MAGIC.to_be_bytes());
    r.extend_from_slice(&opcao.to_be_bytes());
    r.extend_from_slice(&tipo.to_be_bytes());
    r.extend_from_slice(&(dados.len() as u32).to_be_bytes());
    r.extend_from_slice(dados);
    c.write_all(&r)
}

fn ler_u16(c: &mut UnixStream) -> std::io::Result<u16> {
    let mut b = [0u8; 2];
    c.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

fn ler_u32(c: &mut UnixStream) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    c.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

fn ler_u64(c: &mut UnixStream) -> std::io::Result<u64> {
    let mut b = [0u8; 8];
    c.read_exact(&mut b)?;
    Ok(u64::from_be_bytes(b))
}

impl Drop for DiscoHostil {
    /// O servidor para: a próxima conexão aceita o encerra — e a do próprio
    /// `Drop` é essa. O arquivo fecha com ele.
    fn drop(&mut self) {
        self.parar.store(true, Ordering::Release);
        let _ = UnixStream::connect(&self.socket);
        let _ = std::fs::remove_file(&self.socket);
    }
}
