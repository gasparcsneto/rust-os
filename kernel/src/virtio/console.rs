//! O canal local dos agentes: o `virtio-console`, com várias portas.
//!
//! # Por que ele
//!
//! Porque vários agentes operam o Duke ao mesmo tempo, e cada um precisa de
//! um canal só dele. A serial é uma: um fluxo de bytes, um cliente no
//! socket do hospedeiro. O `virtio-console` com várias portas — o recurso
//! `MULTIPORT` — é um dispositivo com uma fila de entrada e uma de saída por
//! porta, e o QEMU liga cada porta a um socket próprio no hospedeiro. Cada
//! porta é uma sessão: o kernel sabe por qual porta cada pedido chegou, e a
//! resposta volta só por ela.
//!
//! É o transporte **local** dos agentes. O remoto é o TCP, quando houver
//! rede; acima do transporte nada muda — ver [`crate::agent::sessao`].
//!
//! # Uma coisa que a serial não dava: a conexão
//!
//! A serial não enxerga quando um cliente conecta ou cai — não há linha de
//! modem entre ela e o socket —, e o canal convive com isso por um teto de
//! ociosidade e uma linha vazia que o cliente manda ao chegar. Aqui o
//! dispositivo **diz**: uma mensagem de controle `PORT_OPEN` a cada vez que
//! o outro lado de uma porta abre ou fecha. O kernel conta as aberturas — a
//! geração da porta —, e quem monta os quadros recomeça do zero numa
//! geração nova: o fragmento de quem saiu não cola no pedido de quem chegou.
//!
//! # A fila de controle
//!
//! Com `MULTIPORT`, as portas não existem de saída: o driver diz que está
//! pronto (`DEVICE_READY`), o dispositivo anuncia cada porta (`DEVICE_ADD`),
//! o driver diz que a pôs de pé (`PORT_READY`) e que a abriu do lado dele
//! (`PORT_OPEN`), e o dispositivo manda o nome dela (`PORT_NAME`) e se o
//! outro lado está aberto. Tudo em mensagens de oito bytes, numa fila de
//! controle própria.
//!
//! # A colheita
//!
//! A cada tique do relógio, como o teclado virtio — ver a nota em
//! [`crate::tempo`]: os bytes que chegaram vão para a entrada da porta, e
//! acordam a tarefa que a atende; o que foi enviado volta, e abre lugar
//! para o que espera. O envio também sai na hora em que se pede, sem
//! esperar o tique.

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Waker;

use crate::trava::Mutex;

use super::fila::Fila;
use super::transporte::{FABRICANTE, Transporte, VERSAO_1};
use crate::pci::Dispositivo;

/// Os identificadores PCI do `virtio-console`: o transicional e o moderno.
const MODELO_TRANSICIONAL: u16 = 0x1003;
const MODELO_MODERNO: u16 = 0x1043;

/// O recurso de várias portas.
const RECURSO_MULTIPORT: u64 = 1 << 1;

/// Quantas portas de agente o Duke atende: da 1 à 4. A porta 0 é a do
/// console do hospedeiro, que o Duke não usa.
pub const PORTAS: u8 = 4;

/// As filas: a de controle é a 2 e a 3; a porta `p` (a partir da 1), a
/// `2(p + 1)` para receber e a seguinte para enviar.
const CONTROLE_RX: u16 = 2;
const CONTROLE_TX: u16 = 3;

const fn fila_rx(porta: u8) -> u16 {
    2 * (porta as u16 + 1)
}

/// As mensagens de controle: `id`, `event` e `value`, oito bytes.
const DEVICE_READY: u16 = 0;
const DEVICE_ADD: u16 = 1;
const DEVICE_REMOVE: u16 = 2;
const PORT_READY: u16 = 3;
const PORT_OPEN: u16 = 6;
const PORT_NAME: u16 = 7;

/// Os buffers: cada fila tem um frame de 4 KiB para eles.
const BUFFERS_DE_CONTROLE: usize = 16;
const TAMANHO_DE_CONTROLE: usize = 256;
const BUFFERS_DA_PORTA: usize = 8;
const TAMANHO_DA_PORTA: usize = 512;
/// As mensagens que o driver manda: oito bytes cada, num frame.
const SLOTS_DE_CONTROLE_TX: usize = 32;

/// O que cabe esperando na entrada de uma porta, antes de o excedente ser
/// contado como perdido. O dobro da maior requisição do canal.
const MAIOR_ENTRADA: usize = 16 * 1024;

/// O que cabe esperando para sair por uma porta. Um cliente que não lê não
/// faz o kernel guardar resposta sem fim: o excedente é descartado e
/// contado — ver [`perdidos_na_saida`].
const MAIOR_SAIDA: usize = 256 * 1024;

/// O lado do driver de cada porta.
struct Porta {
    rx: Fila,
    tx: Fila,
    frame_rx: u64,
    base_rx: *mut u8,
    frame_tx: u64,
    base_tx: *mut u8,
    /// O dispositivo anunciou a porta.
    anunciada: bool,
    nome: [u8; 32],
    tamanho_do_nome: usize,
}

struct Console {
    transporte: Transporte,
    controle_rx: Fila,
    controle_tx: Fila,
    frame_ctrl_rx: u64,
    base_ctrl_rx: *mut u8,
    frame_ctrl_tx: u64,
    base_ctrl_tx: *mut u8,
    /// A porta `p` em `portas[p - 1]`.
    portas: [Option<Porta>; PORTAS as usize],
}

// SAFETY: os ponteiros apontam para frames que este driver aloca e nunca
// devolve, e todo acesso a eles passa pelo `Mutex` que guarda o driver — a
// mesma razão do teclado e da placa de rede.
unsafe impl Send for Console {}

static CONSOLE: Mutex<Option<Console>> = Mutex::new(None);

/// O lado do canal de cada porta: o que chegou e o que vai sair, fora da
/// tranca do driver — a tarefa que atende a porta lê daqui sem tocar nele.
struct Fluxo {
    /// O outro lado está aberto: há um agente conectado.
    aberta: bool,
    /// Quantas vezes o outro lado abriu. Um quadro que começou numa geração
    /// não continua na seguinte.
    geracao: u64,
    entrada: VecDeque<u8>,
    saida: VecDeque<u8>,
    /// Bytes que chegaram e não couberam.
    perdidos: u64,
    /// Bytes de resposta descartados: ninguém lia, ou o outro lado fechou.
    perdidos_na_saida: u64,
    despertador: Option<Waker>,
    /// Em modo de teste, a saída vai para cá, e não para o dispositivo: a
    /// suíte não tem um agente do outro lado de um socket.
    #[cfg(feature = "modo-teste")]
    captura: Option<alloc::vec::Vec<u8>>,
    /// Em modo de teste: recusar todo envio, como uma fila de saída cheia —
    /// ver [`recusar_envio`].
    #[cfg(feature = "modo-teste")]
    recusar: bool,
}

impl Fluxo {
    const fn novo() -> Fluxo {
        Fluxo {
            aberta: false,
            geracao: 0,
            entrada: VecDeque::new(),
            saida: VecDeque::new(),
            perdidos: 0,
            perdidos_na_saida: 0,
            despertador: None,
            #[cfg(feature = "modo-teste")]
            captura: None,
            #[cfg(feature = "modo-teste")]
            recusar: false,
        }
    }
}

static FLUXOS: [Mutex<Fluxo>; PORTAS as usize] = [
    Mutex::new(Fluxo::novo()),
    Mutex::new(Fluxo::novo()),
    Mutex::new(Fluxo::novo()),
    Mutex::new(Fluxo::novo()),
];

/// Quantos bytes entraram e saíram por todas as portas.
static RECEBIDOS: AtomicU64 = AtomicU64::new(0);
static ENVIADOS: AtomicU64 = AtomicU64::new(0);

fn fluxo<R>(porta: u8, f: impl FnOnce(&mut Fluxo) -> R) -> Option<R> {
    let i = porta.checked_sub(1)? as usize;
    let fluxo = FLUXOS.get(i)?;
    Some(crate::arch::sem_interrupcoes(|| f(&mut fluxo.lock())))
}

/// Um frame zerado, e por onde a CPU o alcança.
fn frame() -> Result<(u64, *mut u8), &'static str> {
    let frame = crate::frames::alocar().ok_or("sem frame para os buffers do console")?;
    let base = crate::arch::acesso_fisico(frame);
    // SAFETY: o frame acabou de ser alocado, e tem 4 KiB.
    unsafe { core::ptr::write_bytes(base, 0, 4096) };
    Ok((frame, base))
}

/// Entrega ao dispositivo, numa fila de recepção, todo buffer que ainda não
/// está com ele. A pergunta sai da tabela de descritores, como no teclado.
fn pendurar(fila: &mut Fila, frame: u64, buffers: usize, tamanho: usize) {
    for i in 0..buffers {
        let endereco = frame + (i * tamanho) as u64;
        let ja = (0..super::fila::DESCRITORES)
            .any(|p| fila.em_uso(p) && fila.endereco_do_descritor(p) == Some(endereco));
        if ja {
            continue;
        }
        if fila.submeter(&[(endereco, tamanho as u32, true)]).is_err() {
            break;
        }
    }
}

impl Console {
    fn novo(d: &Dispositivo) -> Result<Console, &'static str> {
        let transporte = Transporte::descobrir(d)?;
        let aceitos = transporte.iniciar(VERSAO_1 | RECURSO_MULTIPORT)?;
        if aceitos & RECURSO_MULTIPORT == 0 {
            transporte.abortar();
            return Err("o console nao tem varias portas");
        }
        let maximo = transporte
            .configuracao()
            .and_then(|c| c.ler_u32(4))
            .unwrap_or(0);
        if maximo <= PORTAS as u32 {
            transporte.abortar();
            return Err("o console tem menos portas que os agentes");
        }

        let controle_rx = Fila::nova(&transporte, CONTROLE_RX)?;
        let controle_tx = Fila::nova(&transporte, CONTROLE_TX)?;
        let (frame_ctrl_rx, base_ctrl_rx) = frame()?;
        let (frame_ctrl_tx, base_ctrl_tx) = frame()?;
        let mut portas: [Option<Porta>; PORTAS as usize] = [None, None, None, None];
        for p in 1..=PORTAS {
            let rx = Fila::nova(&transporte, fila_rx(p))?;
            let tx = Fila::nova(&transporte, fila_rx(p) + 1)?;
            let (frame_rx, base_rx) = frame()?;
            let (frame_tx, base_tx) = frame()?;
            portas[p as usize - 1] = Some(Porta {
                rx,
                tx,
                frame_rx,
                base_rx,
                frame_tx,
                base_tx,
                anunciada: false,
                nome: [0; 32],
                tamanho_do_nome: 0,
            });
        }

        let mut console = Console {
            transporte,
            controle_rx,
            controle_tx,
            frame_ctrl_rx,
            base_ctrl_rx,
            frame_ctrl_tx,
            base_ctrl_tx,
            portas,
        };

        // Os buffers de recepção antes do `DRIVER_OK`, como na rede: a partir
        // dele o dispositivo pode entregar, e precisa ter onde pôr.
        crate::pci::habilitar_mestre(d);
        pendurar(
            &mut console.controle_rx,
            console.frame_ctrl_rx,
            BUFFERS_DE_CONTROLE,
            TAMANHO_DE_CONTROLE,
        );
        for porta in console.portas.iter_mut().flatten() {
            pendurar(
                &mut porta.rx,
                porta.frame_rx,
                BUFFERS_DA_PORTA,
                TAMANHO_DA_PORTA,
            );
        }
        // O dono se registra antes do `DRIVER_OK`. Este driver é o que
        // mostrou por quê: ver [`super::ligar_interrupcao`].
        super::ligar_interrupcao(d, &console.transporte, super::NOME_CONSOLE);
        console.transporte.liberar();
        console.controle_rx.notificar(&console.transporte);
        for porta in console.portas.iter().flatten() {
            porta.rx.notificar(&console.transporte);
        }

        // Pronto: o dispositivo responde anunciando as portas.
        console.mandar(0, DEVICE_READY, 1);
        Ok(console)
    }

    /// Manda uma mensagem de controle.
    fn mandar(&mut self, id: u32, evento: u16, valor: u16) {
        // As mensagens já entregues voltam ao bitmap; o slot de uma que ainda
        // está com o dispositivo não é reescrito.
        while self.controle_tx.colher().is_some() {}
        let slot = (0..SLOTS_DE_CONTROLE_TX).find(|&i| {
            let endereco = self.frame_ctrl_tx + (i * 8) as u64;
            !(0..super::fila::DESCRITORES).any(|p| {
                self.controle_tx.em_uso(p)
                    && self.controle_tx.endereco_do_descritor(p) == Some(endereco)
            })
        });
        let Some(slot) = slot else {
            crate::log_warn!("virtio", "console: sem lugar para a mensagem de controle");
            return;
        };
        let mut bruto = [0u8; 8];
        bruto[0..4].copy_from_slice(&id.to_le_bytes());
        bruto[4..6].copy_from_slice(&evento.to_le_bytes());
        bruto[6..8].copy_from_slice(&valor.to_le_bytes());
        // SAFETY: o slot está dentro do frame de envio, que tem 4 KiB, e o
        // dispositivo não o tem — a busca acima confere.
        unsafe {
            core::ptr::copy_nonoverlapping(bruto.as_ptr(), self.base_ctrl_tx.add(slot * 8), 8);
        }
        let endereco = self.frame_ctrl_tx + (slot * 8) as u64;
        if self.controle_tx.submeter(&[(endereco, 8, false)]).is_ok() {
            self.controle_tx.notificar(&self.transporte);
        }
    }

    /// O que chegou na fila de controle.
    fn colher_controle(&mut self) {
        let mut colhidos = 0;
        while let Some((cabeca, escritos)) = self.controle_rx.colher() {
            colhidos += 1;
            let Some(endereco) = self.controle_rx.endereco_do_descritor(cabeca) else {
                continue;
            };
            if (escritos as usize) < 8 {
                continue;
            }
            let deslocamento = endereco.saturating_sub(self.frame_ctrl_rx) as usize;
            let tamanho = (escritos as usize).min(TAMANHO_DE_CONTROLE);
            let mut bruto = [0u8; TAMANHO_DE_CONTROLE];
            // SAFETY: o endereço veio de um descritor desta fila, todos dentro
            // do frame de controle, e `tamanho` não passa do buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.base_ctrl_rx.add(deslocamento),
                    bruto.as_mut_ptr(),
                    tamanho,
                );
            }
            let id = u32::from_le_bytes([bruto[0], bruto[1], bruto[2], bruto[3]]);
            let evento = u16::from_le_bytes([bruto[4], bruto[5]]);
            let valor = u16::from_le_bytes([bruto[6], bruto[7]]);
            self.tratar_controle(id, evento, valor, &bruto[8..tamanho]);
        }
        if colhidos > 0 {
            pendurar(
                &mut self.controle_rx,
                self.frame_ctrl_rx,
                BUFFERS_DE_CONTROLE,
                TAMANHO_DE_CONTROLE,
            );
            self.controle_rx.notificar(&self.transporte);
        }
    }

    fn tratar_controle(&mut self, id: u32, evento: u16, valor: u16, resto: &[u8]) {
        // Portas fora das nossas — a 0, do console do hospedeiro, ou uma
        // além da quarta — não são de agente nenhum.
        let Some(p) = u8::try_from(id).ok().filter(|p| (1..=PORTAS).contains(p)) else {
            return;
        };
        match evento {
            DEVICE_ADD => {
                if let Some(porta) = self.portas[p as usize - 1].as_mut() {
                    porta.anunciada = true;
                }
                self.mandar(id, PORT_READY, 1);
                // E aberta do lado de cá: o hospedeiro só manda o que chega
                // do socket a uma porta que o hóspede abriu.
                self.mandar(id, PORT_OPEN, 1);
            }
            DEVICE_REMOVE => {
                if let Some(porta) = self.portas[p as usize - 1].as_mut() {
                    porta.anunciada = false;
                }
                fechar(p);
            }
            PORT_NAME => {
                if let Some(porta) = self.portas[p as usize - 1].as_mut() {
                    // O nome pode vir com o zero de fim de uma string de C.
                    let fim = resto.iter().position(|&b| b == 0).unwrap_or(resto.len());
                    let n = fim.min(porta.nome.len());
                    porta.nome[..n].copy_from_slice(&resto[..n]);
                    porta.tamanho_do_nome = n;
                }
            }
            PORT_OPEN if valor == 1 => {
                fluxo(p, |f| {
                    f.aberta = true;
                    f.geracao += 1;
                    f.entrada.clear();
                    f.perdidos_na_saida += f.saida.len() as u64;
                    f.saida.clear();
                    if let Some(w) = f.despertador.take() {
                        w.wake();
                    }
                });
                crate::log_info!("agent", "sessao {} conectada", p);
            }
            PORT_OPEN => {
                fechar(p);
                crate::log_info!("agent", "sessao {} desconectada", p);
            }
            _ => {}
        }
    }

    /// Os bytes que chegaram pelas portas.
    fn colher_portas(&mut self) {
        for (i, porta) in self.portas.iter_mut().enumerate() {
            let Some(porta) = porta else {
                continue;
            };
            let p = i as u8 + 1;
            let mut colhidos = 0;
            while let Some((cabeca, escritos)) = porta.rx.colher() {
                colhidos += 1;
                let Some(endereco) = porta.rx.endereco_do_descritor(cabeca) else {
                    continue;
                };
                let deslocamento = endereco.saturating_sub(porta.frame_rx) as usize;
                let tamanho = (escritos as usize).min(TAMANHO_DA_PORTA);
                let mut bruto = [0u8; TAMANHO_DA_PORTA];
                // SAFETY: como na fila de controle — o descritor é desta fila,
                // dentro do frame de recepção da porta.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        porta.base_rx.add(deslocamento),
                        bruto.as_mut_ptr(),
                        tamanho,
                    );
                }
                RECEBIDOS.fetch_add(tamanho as u64, Ordering::Relaxed);
                fluxo(p, |f| receber_em(f, &bruto[..tamanho]));
            }
            if colhidos > 0 {
                pendurar(
                    &mut porta.rx,
                    porta.frame_rx,
                    BUFFERS_DA_PORTA,
                    TAMANHO_DA_PORTA,
                );
                porta.rx.notificar(&self.transporte);
            }
        }
    }

    /// Leva ao dispositivo o que espera para sair pela porta `p`, enquanto
    /// houver buffer de envio livre.
    fn bombear(&mut self, p: u8) {
        let Some(porta) = self.portas[p as usize - 1].as_mut() else {
            return;
        };
        while porta.tx.colher().is_some() {}
        let mut enviou = false;
        for slot in 0..BUFFERS_DA_PORTA {
            let endereco = porta.frame_tx + (slot * TAMANHO_DA_PORTA) as u64;
            let ocupado = (0..super::fila::DESCRITORES)
                .any(|d| porta.tx.em_uso(d) && porta.tx.endereco_do_descritor(d) == Some(endereco));
            if ocupado {
                continue;
            }
            let mut pedaco = [0u8; TAMANHO_DA_PORTA];
            let n = fluxo(p, |f| {
                let n = f.saida.len().min(TAMANHO_DA_PORTA);
                for (destino, byte) in pedaco.iter_mut().zip(f.saida.drain(..n)) {
                    *destino = byte;
                }
                n
            })
            .unwrap_or(0);
            if n == 0 {
                break;
            }
            // SAFETY: o slot está dentro do frame de envio da porta, e o
            // dispositivo não o tem — a busca acima confere.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    pedaco.as_ptr(),
                    porta.base_tx.add(slot * TAMANHO_DA_PORTA),
                    n,
                );
            }
            if porta.tx.submeter(&[(endereco, n as u32, false)]).is_err() {
                break;
            }
            ENVIADOS.fetch_add(n as u64, Ordering::Relaxed);
            enviou = true;
        }
        if enviou {
            porta.tx.notificar(&self.transporte);
        }
    }
}

/// O que chegou à porta, na entrada dela; o que não cabe é contado.
fn receber_em(f: &mut Fluxo, bytes: &[u8]) {
    for &b in bytes {
        if f.entrada.len() < MAIOR_ENTRADA {
            f.entrada.push_back(b);
        } else {
            f.perdidos += 1;
        }
    }
    if let Some(w) = f.despertador.take() {
        w.wake();
    }
}

/// O outro lado da porta fechou: o que ia sair não tem mais quem leia.
fn fechar(p: u8) {
    fluxo(p, |f| {
        f.aberta = false;
        f.perdidos_na_saida += f.saida.len() as u64;
        f.saida.clear();
        if let Some(w) = f.despertador.take() {
            w.wake();
        }
    });
    // Quem fechou levou a sessão junto: as chaves dela não servem a mais
    // ninguém, e o relatório não deve mostrar como presente um agente que
    // saiu. Fora da trava da porta — as duas nunca ficam presas juntas.
    if let Some(saiu) = crate::sessoes::esquecer(p) {
        crate::log_info!("agent", "porta {}: {} saiu", p, saiu.nome);
    }
}

/// Procura o `virtio-console` e o põe de pé.
pub fn init() {
    let mut alvo = None;
    crate::pci::com_dispositivos(|d| {
        if alvo.is_none()
            && d.fabricante == FABRICANTE
            && (d.modelo == MODELO_TRANSICIONAL || d.modelo == MODELO_MODERNO)
        {
            alvo = Some(*d);
        }
    });
    let Some(alvo) = alvo else {
        crate::log_info!(
            "virtio",
            "nenhum console virtio: so a serial atende agentes"
        );
        return;
    };
    match Console::novo(&alvo) {
        Ok(console) => {
            crate::log_info!(
                "virtio",
                "console em {:02x}.{} pronto, {} portas de agente",
                alvo.dispositivo,
                alvo.funcao,
                PORTAS
            );
            crate::arch::sem_interrupcoes(|| *CONSOLE.lock() = Some(console));
            // O anúncio das portas vem em resposta ao `DEVICE_READY`; colher
            // já, e não no primeiro tique, deixa as portas de pé antes de as
            // tarefas que as atendem começarem.
            colher();
        }
        Err(motivo) => crate::log_warn!("virtio", "console nao inicializado: {}", motivo),
    }
}

/// Recolhe o que o dispositivo entregou, e leva adiante o que espera para
/// sair. A cada tique do relógio.
pub fn colher() {
    crate::arch::sem_interrupcoes(|| {
        let mut guarda = CONSOLE.lock();
        let Some(console) = guarda.as_mut() else {
            return;
        };
        console.colher_controle();
        console.colher_portas();
        for p in 1..=PORTAS {
            console.bombear(p);
        }
    });
}

/// O driver está de pé?
pub fn presente() -> bool {
    crate::arch::sem_interrupcoes(|| CONSOLE.lock().is_some())
}

/// A porta `p` foi anunciada pelo dispositivo?
pub fn anunciada(p: u8) -> bool {
    crate::arch::sem_interrupcoes(|| {
        CONSOLE.lock().as_ref().is_some_and(|c| {
            p.checked_sub(1)
                .and_then(|i| c.portas.get(i as usize))
                .and_then(Option::as_ref)
                .is_some_and(|porta| porta.anunciada)
        })
    })
}

/// O nome que o hospedeiro deu à porta `p`, se deu.
pub fn nome(p: u8, destino: &mut [u8; 32]) -> usize {
    crate::arch::sem_interrupcoes(|| {
        let guarda = CONSOLE.lock();
        let Some(porta) = guarda
            .as_ref()
            .and_then(|c| c.portas.get(p.checked_sub(1)? as usize))
            .and_then(Option::as_ref)
        else {
            return 0;
        };
        destino.copy_from_slice(&porta.nome);
        porta.tamanho_do_nome
    })
}

/// Há um agente do outro lado da porta `p`?
pub fn aberta(p: u8) -> bool {
    fluxo(p, |f| f.aberta).unwrap_or(false)
}

/// Quantas vezes o outro lado da porta `p` abriu.
pub fn geracao(p: u8) -> u64 {
    fluxo(p, |f| f.geracao).unwrap_or(0)
}

/// Bytes que chegaram à porta `p` e não couberam na entrada.
pub fn perdidos(p: u8) -> u64 {
    fluxo(p, |f| f.perdidos).unwrap_or(0)
}

/// Bytes de resposta da porta `p` descartados: o outro lado não lia, ou
/// fechou antes de ler.
pub fn perdidos_na_saida(p: u8) -> u64 {
    fluxo(p, |f| f.perdidos_na_saida).unwrap_or(0)
}

/// Quantos bytes entraram e saíram, somando as portas.
pub fn trafego() -> (u64, u64) {
    (
        RECEBIDOS.load(Ordering::Relaxed),
        ENVIADOS.load(Ordering::Relaxed),
    )
}

/// O próximo byte da porta `p`, quando houver.
pub fn proximo_byte(p: u8) -> ProximoByte {
    ProximoByte(p)
}

/// O futuro de [`proximo_byte`].
pub struct ProximoByte(u8);

impl core::future::Future for ProximoByte {
    type Output = u8;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        contexto: &mut core::task::Context,
    ) -> core::task::Poll<u8> {
        let p = self.0;
        // O byte e o registro do despertador sob a mesma tranca: um byte que
        // chegasse entre os dois não acordaria ninguém.
        let byte = fluxo(p, |f| match f.entrada.pop_front() {
            Some(b) => Some(b),
            None => {
                if !f
                    .despertador
                    .as_ref()
                    .is_some_and(|w| w.will_wake(contexto.waker()))
                {
                    f.despertador = Some(contexto.waker().clone());
                }
                None
            }
        })
        .flatten();
        match byte {
            Some(b) => core::task::Poll::Ready(b),
            None => core::task::Poll::Pending,
        }
    }
}

/// Manda `bytes` pela porta `p`. Sem ninguém do outro lado, não há a quem:
/// são descartados, e contados. Devolve se foram aceitos.
pub fn enviar(p: u8, bytes: &[u8]) -> bool {
    // Três desfechos: na captura da suíte, na fila da porta, ou descartado.
    // O descarte é de tudo ou nada — nunca metade dos bytes —, e quem manda
    // fica sabendo: o canal cifrado depende disso, porque um quadro que não
    // saiu deixa o contador de mensagens dos dois lados desencontrado.
    let desfecho = fluxo(p, |f| {
        #[cfg(feature = "modo-teste")]
        if f.recusar {
            return None;
        }
        #[cfg(feature = "modo-teste")]
        if let Some(captura) = f.captura.as_mut() {
            captura.extend_from_slice(bytes);
            return Some(false);
        }
        if !f.aberta || f.saida.len() + bytes.len() > MAIOR_SAIDA {
            f.perdidos_na_saida += bytes.len() as u64;
            return None;
        }
        f.saida.extend(bytes.iter().copied());
        Some(true)
    })
    .flatten();
    if desfecho == Some(true) {
        crate::arch::sem_interrupcoes(|| {
            if let Some(console) = CONSOLE.lock().as_mut() {
                console.bombear(p);
            }
        });
    }
    desfecho.is_some()
}

/// Em modo de teste: a saída da porta `p` vai para uma captura que a suíte
/// lê — ver [`capturado`] —, e não ao dispositivo; ou volta a ir, com
/// `liga` falso.
#[cfg(feature = "modo-teste")]
pub fn capturar(p: u8, liga: bool) {
    fluxo(p, |f| f.captura = liga.then(alloc::vec::Vec::new));
}

/// Em modo de teste: a porta `p` passa a recusar todo envio, como faria com
/// a fila de saída cheia — ou volta a aceitar, com `liga` falso.
///
/// Existe porque a outra forma de um envio falhar, a porta fechada, leva a
/// sessão junto (ver [`fechar`]), e esconde o que o caso quer conferir: que
/// uma resposta que não saiu encerra a sessão por si só.
#[cfg(feature = "modo-teste")]
pub fn recusar_envio(p: u8, liga: bool) {
    fluxo(p, |f| f.recusar = liga);
}

/// Em modo de teste: o que o outro lado da porta `p` teria mandado, na
/// entrada dela.
#[cfg(feature = "modo-teste")]
pub fn simular(p: u8, bytes: &[u8]) {
    fluxo(p, |f| receber_em(f, bytes));
}

/// Em modo de teste: o próximo byte da entrada da porta `p`, sem esperar —
/// a suíte atende a porta sem o executor.
#[cfg(feature = "modo-teste")]
pub fn retirar(p: u8) -> Option<u8> {
    fluxo(p, |f| f.entrada.pop_front()).flatten()
}

/// Em modo de teste: o que saiu pela porta `p` desde a última vez.
#[cfg(feature = "modo-teste")]
pub fn capturado(p: u8) -> alloc::vec::Vec<u8> {
    fluxo(p, |f| {
        f.captura.as_mut().map(core::mem::take).unwrap_or_default()
    })
    .unwrap_or_default()
}

/// Em modo de teste: uma conexão nova na porta `p`, como o `PORT_OPEN` do
/// dispositivo — ou o fim dela.
#[cfg(feature = "modo-teste")]
pub fn simular_conexao(p: u8, aberta: bool) {
    if aberta {
        fluxo(p, |f| {
            f.aberta = true;
            f.geracao += 1;
            f.entrada.clear();
        });
    } else {
        fechar(p);
    }
}

/// Destrava o console à força, para uso exclusivo do caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        CONSOLE.force_unlock();
        for f in &FLUXOS {
            f.force_unlock();
        }
    }
}
