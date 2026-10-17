//! Só na suíte: os servidores de Roughtime da bancada, de dentro da máquina.
//!
//! Três fontes, nos destinos do registro da imagem — `udp:10.0.2.2:5319`,
//! `5320` e `5321`, os que a política dá ao papel `tempo` —, com chaves
//! **sorteadas** quando a suíte as liga: nenhuma chave versionada, nenhuma
//! na imagem. A suíte põe um registro de fontes com as públicas delas
//! ([`registro_de_teste`]) no lugar do da imagem, enquanto o caso dura.
//!
//! O quadro que a pilha manda passa por [`observar_saida`] depois do
//! firewall — o que o firewall barrou nunca chega aqui —; um pedido para
//! uma das fontes vai para a fila da bancada e não sai pela placa. Quem
//! responde é o fio `bancada-hora`, fora da trava da pilha: assinar uma
//! resposta custa duas assinaturas Ed25519, e com a pilha travada isso
//! seguraria a rede inteira. A resposta entra na fila do que a placa
//! recebeu e passa pelo firewall de entrada como qualquer quadro.
//!
//! São honestas por padrão: o carimbo é o civil do próprio kernel, e uma
//! rodada honesta não move o relógio. O modo de cada fonte deixa o caso
//! mentir de propósito — ver [`Modo`] —, e o deslocamento, o raio e o
//! atraso, desviar dentro das regras.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use hora::servidor_de_teste::{self, Servidor};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpAddress, IpProtocol,
    Ipv4Address, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr,
};

use crate::trava::Mutex;

/// O endereço das fontes: o roteador do emulador, como na imagem.
pub const ENDERECO: [u8; 4] = [10, 0, 2, 2];

/// As portas das três fontes, na ordem do registro.
pub const PORTAS: [u16; 3] = [5319, 5320, 5321];

/// Os nomes das fontes, na ordem do registro — os da imagem.
pub const NOMES: [&str; 3] = ["bancada-a", "bancada-b", "bancada-c"];

/// Como uma fonte responde.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Modo {
    /// A resposta certa, com o carimbo do civil mais o deslocamento.
    Honesta,
    /// Nenhuma resposta.
    Muda,
    /// A delegação assinada por outra chave longa: a fonte forjada.
    ChaveErrada,
    /// O `SREP` assinado por outra chave que não a delegada.
    RespostaMalAssinada,
    /// O `NONC` de outro pedido.
    NonceErrado,
    /// Autêntica, mas de outro pedido: a árvore não tem o nosso.
    OutroPedido,
    /// Autêntica, com o carimbo fora da janela da delegação.
    ForaDaDelegacao,
    /// Autêntica, com o raio acima do teto.
    RaioGrande,
    /// A versão errada.
    VersaoErrada,
    /// Bytes que não são Roughtime.
    Malformada,
    /// O maior datagrama que a rede traz — mais que isso não chega: a
    /// pilha não remonta fragmentos —, numa moldura que declara mais do
    /// que o maior pacote.
    Grande,
    /// A última resposta válida desta fonte, de novo.
    Repetida,
    /// Primeiro lixo, depois a resposta certa: a recusa não consome o id.
    LixoAntes,
}

/// O estado de uma fonte da bancada.
#[derive(Clone)]
struct Fonte {
    servidor: Servidor,
    modo: Modo,
    deslocamento_s: i64,
    raio: u32,
    atraso_ms: u64,
    respondidas: u64,
    ultima_valida: Option<Vec<u8>>,
}

/// Um pedido que chegou, à espera do fio da bancada.
struct Pendente {
    fonte: usize,
    pedido: Vec<u8>,
    origem: [u8; 4],
    porta: u16,
    mac_nosso: EthernetAddress,
    mac_deles: EthernetAddress,
    quando_ms: u64,
}

/// As fontes, e as sementes de que as chaves saíram — e uma semente falsa,
/// para as respostas forjadas.
struct Bancada {
    fontes: [Fonte; 3],
    falsa: [u8; 32],
}

static BANCADA: Mutex<Option<Bancada>> = Mutex::new(None);
static FILA: Mutex<Vec<Pendente>> = Mutex::new(Vec::new());
static FIO: AtomicBool = AtomicBool::new(false);

fn com<R>(f: impl FnOnce(&mut Bancada) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| BANCADA.lock().as_mut().map(f))
}

fn semente() -> [u8; 32] {
    crate::aleatorio::chave().unwrap_or([0x5a; 32])
}

/// Liga a bancada: sorteia as chaves na primeira vez, põe as três fontes
/// honestas e sobe o fio que responde. Devolve as chaves longas públicas.
pub fn ligar_de_teste() -> [[u8; 32]; 3] {
    let nova = crate::arch::sem_interrupcoes(|| BANCADA.lock().is_none());
    if nova {
        let fonte = || Fonte {
            servidor: Servidor::com_sementes(&semente(), &semente()),
            modo: Modo::Honesta,
            deslocamento_s: 0,
            raio: 2,
            atraso_ms: 0,
            respondidas: 0,
            ultima_valida: None,
        };
        let bancada = Bancada {
            fontes: [fonte(), fonte(), fonte()],
            falsa: semente(),
        };
        crate::arch::sem_interrupcoes(|| *BANCADA.lock() = Some(bancada));
    }
    if !FIO.swap(true, Ordering::AcqRel)
        && let Err(motivo) = crate::fios::criar("bancada-hora", laco, 0)
    {
        crate::log_error!("teste", "o fio da bancada de hora nao subiu: {}", motivo);
    }
    honestas_de_teste();
    com(|b| core::array::from_fn(|i| b.fontes[i].servidor.chave_longa())).unwrap_or([[0; 32]; 3])
}

/// As três fontes de volta ao normal: honestas, sem deslocamento, raio de
/// 2 s, sem atraso.
pub fn honestas_de_teste() {
    com(|b| {
        for f in &mut b.fontes {
            f.modo = Modo::Honesta;
            f.deslocamento_s = 0;
            f.raio = 2;
            f.atraso_ms = 0;
        }
    });
}

/// O modo da fonte `i`.
pub fn modo_de_teste(i: usize, modo: Modo) {
    com(|b| b.fontes[i].modo = modo);
}

/// O deslocamento do carimbo da fonte `i`, em segundos.
pub fn deslocamento_de_teste(i: usize, segundos: i64) {
    com(|b| b.fontes[i].deslocamento_s = segundos);
}

/// O raio da fonte `i`, em segundos.
pub fn raio_de_teste(i: usize, raio: u32) {
    com(|b| b.fontes[i].raio = raio);
}

/// O atraso da resposta da fonte `i`.
pub fn atraso_de_teste(i: usize, ms: u64) {
    com(|b| b.fontes[i].atraso_ms = ms);
}

/// Quantas respostas a fonte `i` já mandou.
pub fn respondidas_de_teste(i: usize) -> u64 {
    com(|b| b.fontes[i].respondidas).unwrap_or(0)
}

/// Uma resposta honesta da fonte `i` a este pedido, montada aqui — para o
/// caso entregar ele mesmo, sem a rede: a resposta de outro principal, a
/// mesma duas vezes, a que chega depois do prazo.
pub fn resposta_de_teste(i: usize, pedido: &[u8]) -> Vec<u8> {
    let Some((mut fonte, falsa)) = com(|b| (b.fontes[i].clone(), b.falsa)) else {
        return Vec::new();
    };
    fonte.modo = Modo::Honesta;
    responder(&mut fonte, &falsa, pedido)
        .pop()
        .unwrap_or_default()
}

/// O texto de um registro de fontes com as três da bancada, o quórum `k`, o
/// teto do salto e o da incerteza, em segundos.
pub fn registro_de_teste(k: u64, salto_s: u64, incerteza_s: u64) -> alloc::string::String {
    let chaves = ligar_de_teste();
    let mut texto = alloc::string::String::new();
    for (i, chave) in chaves.iter().enumerate() {
        texto.push_str(&alloc::format!(
            "fonte {} udp:10.0.2.2:{} ed25519:{}\n",
            NOMES[i],
            PORTAS[i],
            sigilo::hex(chave)
        ));
    }
    texto.push_str(&alloc::format!(
        "quorum {k}\nsalto {salto_s}\nincerteza {incerteza_s}\n"
    ));
    texto
}

/// Uma resposta da fonte `i` ao pedido `pedido`, no modo dela, como sai
/// do servidor: os datagramas, na ordem. Sem trava nenhuma — as
/// assinaturas são aqui.
fn responder(f: &mut Fonte, falsa: &[u8; 32], pedido: &[u8]) -> Vec<Vec<u8>> {
    let civil_s = crate::hora::civil::ler().map_or(0, |l| l.meio_ms / 1000);
    let midp = civil_s.saturating_add_signed(f.deslocamento_s);
    let mut s = f.servidor.clone();
    s.midp = midp;
    s.radi = f.raio;
    s.mint = midp.saturating_sub(3600);
    s.maxt = midp.saturating_add(86_400);
    let modo = f.modo;
    // A repetida: a última resposta válida desta fonte, como saiu — o nonce
    // é o de um pedido de antes.
    if modo == Modo::Repetida
        && let Some(velha) = f.ultima_valida.clone()
    {
        return alloc::vec![velha];
    }
    let mut valida = |s: &Servidor| {
        let r = s.responder(pedido);
        f.ultima_valida = Some(r.clone());
        r
    };
    match modo {
        Modo::Honesta => alloc::vec![valida(&s)],
        Modo::Muda => Vec::new(),
        Modo::ChaveErrada => {
            let mut forjado = Servidor::com_sementes(falsa, &[0x44; 32]);
            forjado.midp = midp;
            forjado.radi = s.radi;
            forjado.mint = s.mint;
            forjado.maxt = s.maxt;
            alloc::vec![forjado.responder(pedido)]
        }
        Modo::RespostaMalAssinada => {
            alloc::vec![s.com_srep_assinado_por(falsa).responder(pedido)]
        }
        Modo::NonceErrado => {
            s.nonce = Some([0x99; 32]);
            alloc::vec![s.responder(pedido)]
        }
        Modo::OutroPedido => {
            let nonce = servidor_de_teste::nonce_do_pedido(pedido);
            let mut outro = pedido.to_vec();
            let fim = outro.len() - 1;
            outro[fim] ^= 0x01;
            s.nonce = Some(nonce);
            alloc::vec![s.responder(&outro)]
        }
        Modo::ForaDaDelegacao => {
            s.mint = midp.saturating_add(100);
            s.maxt = midp.saturating_add(200);
            alloc::vec![s.responder(pedido)]
        }
        Modo::RaioGrande => {
            s.radi = crate::hora::TETO_DO_RAIO + 1;
            alloc::vec![s.responder(pedido)]
        }
        Modo::VersaoErrada => {
            s.versao = 2;
            s.vers = alloc::vec![2];
            alloc::vec![s.responder(pedido)]
        }
        Modo::Malformada => alloc::vec![alloc::vec![0x52; 48]],
        Modo::Grande => {
            let mut p = alloc::vec![0x47; crate::rede::pilha::MAIOR_DATAGRAMA];
            hora::moldura::escrever(&mut p, (hora::moldura::MAIOR_PACOTE * 4) as u32);
            alloc::vec![p]
        }
        Modo::Repetida => alloc::vec![valida(&s)],
        Modo::LixoAntes => alloc::vec![alloc::vec![0x4c; 64], valida(&s)],
    }
}

/// O fio da bancada: responde o que está na fila na hora de cada um, e
/// espera o tique seguinte bloqueado — ele vive até o fim da suíte, e um
/// fio que descansa a cada interrupção continua pronto (ver
/// `fios::bloquear_em`).
extern "C" fn laco(_argumento: u64) -> ! {
    loop {
        let agora = crate::tempo::uptime_ms();
        let prontos: Vec<Pendente> = crate::arch::sem_interrupcoes(|| {
            let mut fila = FILA.lock();
            let mut prontos = Vec::new();
            let mut i = 0;
            while i < fila.len() {
                if fila[i].quando_ms <= agora {
                    prontos.push(fila.remove(i));
                } else {
                    i += 1;
                }
            }
            prontos
        });
        for p in prontos {
            // A fonte é copiada para fora da trava: assinar é caro.
            let Some((mut fonte, falsa)) = com(|b| (b.fontes[p.fonte].clone(), b.falsa)) else {
                continue;
            };
            let datagramas = responder(&mut fonte, &falsa, &p.pedido);
            let enviados = datagramas.len() as u64;
            com(|b| {
                let f = &mut b.fontes[p.fonte];
                f.respondidas += enviados;
                if fonte.ultima_valida.is_some() {
                    f.ultima_valida = fonte.ultima_valida.take();
                }
            });
            for d in datagramas {
                injetar(&p, &d);
            }
        }
        crate::fios::bloquear_em(crate::tarefas::relogio::por_ticks(1));
    }
}

/// Põe um datagrama da fonte na fila do que a placa recebeu.
fn injetar(p: &Pendente, dados: &[u8]) {
    let udp = UdpRepr {
        src_port: PORTAS[p.fonte],
        dst_port: p.porta,
    };
    let ip = Ipv4Repr {
        src_addr: Ipv4Address::from(ENDERECO),
        dst_addr: Ipv4Address::from(p.origem),
        next_header: IpProtocol::Udp,
        payload_len: udp.header_len() + dados.len(),
        hop_limit: 64,
    };
    let eth = EthernetRepr {
        src_addr: p.mac_deles,
        dst_addr: p.mac_nosso,
        ethertype: EthernetProtocol::Ipv4,
    };
    let mut q = alloc::vec![0u8; eth.buffer_len() + ip.buffer_len() + ip.payload_len];
    let mut frame = EthernetFrame::new_unchecked(&mut q[..]);
    eth.emit(&mut frame);
    let mut ip_saida = Ipv4Packet::new_unchecked(frame.payload_mut());
    ip.emit(&mut ip_saida, &ChecksumCapabilities::default());
    let mut segmento = UdpPacket::new_unchecked(ip_saida.payload_mut());
    udp.emit(
        &mut segmento,
        &IpAddress::Ipv4(ip.src_addr),
        &IpAddress::Ipv4(ip.dst_addr),
        dados.len(),
        |d| d.copy_from_slice(dados),
        &ChecksumCapabilities::default(),
    );
    super::pilha::enfileirar_de_teste(&q);
}

/// Olha um quadro que a pilha mandou — e já passou pelo firewall. Com
/// [`super::pilha`] tomada: o pedido só entra na fila. Verdadeiro se o
/// quadro era para uma fonte da bancada, e não deve sair pela placa.
pub(super) fn observar_saida(quadro: &[u8]) -> bool {
    if crate::arch::sem_interrupcoes(|| BANCADA.lock().is_none()) {
        return false;
    }
    let Ok(eth) = EthernetFrame::new_checked(quadro) else {
        return false;
    };
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return false;
    }
    let Ok(ip) = Ipv4Packet::new_checked(eth.payload()) else {
        return false;
    };
    if ip.dst_addr().octets() != ENDERECO || ip.next_header() != IpProtocol::Udp {
        return false;
    }
    let Ok(udp) = UdpPacket::new_checked(ip.payload()) else {
        return false;
    };
    let Some(fonte) = PORTAS.iter().position(|&p| p == udp.dst_port()) else {
        return false;
    };
    let atraso = com(|b| b.fontes[fonte].atraso_ms).unwrap_or(0);
    let pendente = Pendente {
        fonte,
        pedido: udp.payload().to_vec(),
        origem: ip.src_addr().octets(),
        porta: udp.src_port(),
        mac_nosso: eth.src_addr(),
        mac_deles: eth.dst_addr(),
        quando_ms: crate::tempo::uptime_ms().saturating_add(atraso),
    };
    crate::arch::sem_interrupcoes(|| FILA.lock().push(pendente));
    true
}

/// Destrava a bancada e a fila, para o caminho de falha fatal.
///
/// # Safety
///
/// Só com os outros núcleos parados — ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe {
        BANCADA.force_unlock();
        FILA.force_unlock();
    }
}
