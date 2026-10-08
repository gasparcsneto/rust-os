//! A pilha IP: o `smoltcp` sobre a placa virtio.
//!
//! # O que é do `smoltcp` e o que é daqui
//!
//! O protocolo é dele: Ethernet, ARP, IPv4, DHCP, TCP — as somas, os
//! estados, as retransmissões. Daqui é o que o liga ao Duke:
//!
//! - o adaptador da placa ([`Adaptador`]), que entrega cada quadro colhido
//!   ao observador do ARP do diagnóstico antes de entregá-lo à pilha — a
//!   pilha é a **única** que colhe da placa, ver [`super`];
//! - o endereço, pelo DHCP do emulador, e o que `net.info` diz dele;
//! - a tabela das conexões, com o dono de cada uma — ver [`super::conexoes`]
//!   para a regra, que é de lá —, e a espera armada em cada uma — ver
//!   [`super::espera`];
//! - o fio `rede`, que faz a pilha andar.
//!
//! # Quem faz a pilha andar
//!
//! Um fio do kernel, como o coletor: sonda a pilha e descansa até a próxima
//! interrupção — dando a vez a quem estiver pronto, ver
//! [`crate::fios::descansar_ate_a_interrupcao`]. Um tique por volta é a
//! latência de quem não pede nada; quem pede — mandar, receber, conectar —
//! sonda na hora, dentro do comando, e não espera o fio.
//!
//! Um fio, e não o tique do núcleo dos dispositivos: sondar a pilha aloca
//! (a fila de vizinhos, os buffers de TCP), e o tique é um handler de
//! interrupção. E não o coletor: a passada dele grava a auditoria e
//! compacta o journal, e um disco lento não pode atrasar um ACK.
//!
//! # A trava
//!
//! Uma só, [`PILHA`], tomada com as interrupções mascaradas — como as dos
//! drivers. Dentro dela a pilha toma a da placa (para colher e transmitir)
//! e a das respostas ARP observadas: a ordem é sempre essa, e nenhuma das
//! duas toma esta.

use alloc::vec;
use alloc::vec::Vec;
use core::task::Waker;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dhcpv4, tcp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address, Ipv4Cidr};

use crate::trava::Mutex;
use crate::virtio::net::MAIOR_QUADRO;
use politica::endereco::Destino;

use super::conexoes::Dono;
use super::espera::Desfecho;

/// Quantas conexões vivas a máquina toda tem, no máximo.
pub const MAIS_CONEXOES: usize = 16;

/// Quantas conexões vivas cada dono tem, no máximo — um titular não toma a
/// tabela dos outros.
pub const CONEXOES_POR_DONO: usize = 4;

/// O buffer de cada sentido de uma conexão. O maior `net.send` cabe nele,
/// e um `net.recv` devolve no máximo isto.
pub const BUFFER_DA_CONEXAO: usize = 4096;

/// A primeira porta local das conexões de saída: o começo da faixa
/// dinâmica. Cada conexão nova pega a seguinte, dando a volta no fim.
const PRIMEIRA_PORTA: u16 = 49152;

/// O estado de uma conexão, como o agente e o programa o leem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Estado {
    /// O aperto de mão ainda não terminou.
    Conectando,
    /// Os dois sentidos abertos.
    Estabelecida,
    /// Um dos lados começou a fechar; o que já chegou ainda se lê.
    Fechando,
    /// Acabou: recusada, derrubada ou fechada dos dois lados.
    Fechada,
}

impl Estado {
    pub fn nome(self) -> &'static str {
        match self {
            Estado::Conectando => "connecting",
            Estado::Estabelecida => "established",
            Estado::Fechando => "closing",
            Estado::Fechada => "closed",
        }
    }

    fn de(s: tcp::State) -> Estado {
        match s {
            tcp::State::SynSent | tcp::State::SynReceived => Estado::Conectando,
            tcp::State::Established => Estado::Estabelecida,
            tcp::State::Closed | tcp::State::Listen => Estado::Fechada,
            _ => Estado::Fechando,
        }
    }
}

/// Uma conexão da tabela.
struct Conexao {
    /// O número que o dono usa. Cresce sem voltar: um número que já foi de
    /// uma conexão não volta a ser de outra, e um pedido atrasado não acerta
    /// a conexão nova de alguém.
    id: u64,
    dono: Dono,
    destino: Destino,
    socket: SocketHandle,
    enviados: u64,
    recebidos: u64,
    /// O número da espera armada nesta conexão, se há uma — no máximo uma,
    /// ver [`super::espera`].
    espera: Option<u64>,
    /// O último estado que uma resposta disse ao dono — a de `net.connect`,
    /// `net.send` ou `net.recv`. Uma espera só arma se o estado ainda é
    /// este: o que mudou desde a última resposta é novidade para quem pede,
    /// e a resposta a dá na hora. Sem isto, o `net.recv` que espera o
    /// aperto chegava depois de ele terminar — entre a resposta do
    /// `net.connect` e o pedido seguinte — e esperava um dado que o eco só
    /// manda quando recebe, até o prazo: medido na bancada, cinco segundos
    /// de um aperto que levou milissegundos.
    relatado: Estado,
}

/// O que `net.info` diz da pilha.
#[derive(Clone, Copy, Debug)]
pub struct Resumo {
    /// O endereço e a máscara que o DHCP deu, se deu.
    pub endereco: Option<([u8; 4], u8)>,
    pub roteador: Option<[u8; 4]>,
    pub conexoes: usize,
    /// Quantas conexões já foram abertas desde o boot.
    pub abertas: u64,
}

struct Pilha {
    iface: Interface,
    sockets: SocketSet<'static>,
    dhcp: SocketHandle,
    endereco: Option<Ipv4Cidr>,
    roteador: Option<Ipv4Address>,
    conexoes: Vec<Conexao>,
    /// Os sockets de conexões que o dono fechou e que ainda terminam o
    /// fecho com o outro lado, com o dono de cada um. Até acabarem, contam
    /// no teto do dono: um titular cujo outro lado não fecha nunca esbarra
    /// no teto dele, e não enche a tabela dos outros com fechos que não
    /// seriam de ninguém.
    ///
    /// Acabam ao chegar ao `TIME_WAIT`, e não dez segundos depois, como o
    /// `smoltcp` os guardaria: o `TIME_WAIT` existe para um segmento
    /// atrasado não cair numa conexão nova com os mesmos quatro números, e
    /// aqui cada conexão nova pega a porta local seguinte numa faixa de
    /// milhares. Guardá-los enchia a tabela da máquina com fechos já
    /// terminados — medido na suíte: titulares novos ouviam "tabela cheia"
    /// com nenhuma conexão viva de ninguém.
    fechando: Vec<(SocketHandle, Dono)>,
    proximo_id: u64,
    proxima_porta: u16,
    abertas: u64,
    /// O número da próxima espera armada. Cresce sem voltar, como o das
    /// conexões: uma espera que acabou não desarma a seguinte.
    proxima_espera: u64,
}

static PILHA: Mutex<Option<Pilha>> = Mutex::new(None);

fn com_pilha<R>(f: impl FnOnce(&mut Pilha) -> R) -> Option<R> {
    crate::arch::sem_interrupcoes(|| PILHA.lock().as_mut().map(f))
}

fn agora() -> Instant {
    Instant::from_millis(crate::tempo::uptime_ms() as i64)
}

/// A placa, vista pelo `smoltcp`.
struct Adaptador;

/// Um quadro colhido, à espera de a pilha consumi-lo.
struct Recebido {
    quadro: [u8; MAIOR_QUADRO],
    tamanho: usize,
}

/// A licença de transmitir um quadro.
struct Envio;

impl RxToken for Recebido {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.quadro[..self.tamanho])
    }
}

impl TxToken for Envio {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // A pilha não pede mais que o MTU anunciado; se pedisse, o quadro
        // seria montado e recusado pela placa, visível no log, em vez de
        // escrito fora do buffer.
        let mut quadro = vec![0u8; len];
        let r = f(&mut quadro);
        match crate::virtio::net::com_a_placa(|placa| placa.transmitir(&quadro)) {
            Some(Ok(())) | None => {}
            Some(Err(motivo)) => crate::log_warn!("rede", "quadro nao saiu: {}", motivo),
        }
        r
    }
}

impl Device for Adaptador {
    type RxToken<'a> = Recebido;
    type TxToken<'a> = Envio;

    fn receive(&mut self, _agora: Instant) -> Option<(Recebido, Envio)> {
        let mut quadro = [0u8; MAIOR_QUADRO];
        let tamanho = crate::virtio::net::com_a_placa(|placa| placa.receber(&mut quadro))??;
        if tamanho == 0 {
            return None;
        }
        // O ARP do diagnóstico olha antes — ver `super`.
        super::observar(&quadro[..tamanho]);
        Some((Recebido { quadro, tamanho }, Envio))
    }

    fn transmit(&mut self, _agora: Instant) -> Option<Envio> {
        Some(Envio)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ethernet;
        // No Ethernet o `smoltcp` conta o cabeçalho no MTU: é o quadro
        // inteiro, o mesmo teto da placa.
        c.max_transmission_unit = MAIOR_QUADRO;
        c.max_burst_size = Some(1);
        c
    }
}

/// Liga a pilha sobre a placa, se há uma com endereço, e põe o fio `rede`
/// para fazê-la andar. Depois da placa e do gerador de números: a semente
/// do TCP vem dele.
pub fn iniciar() {
    let Some(Some(mac)) = crate::virtio::net::com_a_placa(|placa| placa.mac()) else {
        crate::log_info!("rede", "sem placa com endereco: a pilha IP fica desligada");
        return;
    };
    // O `smoltcp` entra em pânico com um endereço que não é de uma placa só
    // — o bit de grupo aceso —, e o endereço vem do dispositivo. Um
    // dispositivo que publique um desses deixa a máquina sem rede, e não
    // sem boot.
    if mac[0] & 1 != 0 {
        crate::log_error!(
            "rede",
            "a placa publicou um endereco de grupo: a pilha IP fica desligada"
        );
        return;
    }
    // A semente escolhe as portas e os números de sequência iniciais. Não
    // precisa ser criptográfica — o `smoltcp` diz —, mas uma semente fixa
    // repetiria os mesmos números a cada boot. Sem entropia, o relógio.
    let mut semente = [0u8; 8];
    if crate::aleatorio::preencher(&mut semente).is_err() {
        semente = crate::tempo::uptime_ms().to_le_bytes();
    }
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    config.random_seed = u64::from_le_bytes(semente);
    let iface = Interface::new(config, &mut Adaptador, agora());
    let mut sockets = SocketSet::new(Vec::new());
    let dhcp = sockets.add(dhcpv4::Socket::new());
    let porta_inicial = PRIMEIRA_PORTA + (u16::from_le_bytes([semente[0], semente[1]]) % 4096);
    crate::arch::sem_interrupcoes(|| {
        *PILHA.lock() = Some(Pilha {
            iface,
            sockets,
            dhcp,
            endereco: None,
            roteador: None,
            conexoes: Vec::new(),
            fechando: Vec::new(),
            proximo_id: 1,
            proxima_porta: porta_inicial,
            abertas: 0,
            proxima_espera: 1,
        });
    });
    match crate::fios::criar("rede", laco, 0) {
        Ok(id) => crate::log_info!("rede", "pilha IP no ar, fio {}", id.numero()),
        Err(motivo) => crate::log_error!("rede", "o fio da rede nao subiu: {}", motivo),
    }
}

/// O fio da rede: sonda e descansa.
extern "C" fn laco(_argumento: u64) -> ! {
    loop {
        sondar();
        crate::fios::descansar_ate_a_interrupcao();
    }
}

/// Faz a pilha andar uma volta: colhe o que chegou, manda o que está
/// pronto, e atende o DHCP.
pub fn sondar() {
    let mudou = com_pilha(|p| p.sondar()).flatten();
    match mudou {
        Some(Some((ip, prefixo))) => {
            let [a, b, c, d] = ip;
            crate::log_info!(
                "rede",
                "endereco {}.{}.{}.{}/{} pelo DHCP",
                a,
                b,
                c,
                d,
                prefixo
            );
        }
        Some(None) => crate::log_warn!("rede", "o DHCP retirou o endereco"),
        None => {}
    }
}

impl Pilha {
    /// Uma volta. Devolve a mudança de endereço, se houve: `Some(Some(..))`
    /// configurado, `Some(None)` retirado.
    fn sondar(&mut self) -> Option<Option<([u8; 4], u8)>> {
        let _ = self.iface.poll(agora(), &mut Adaptador, &mut self.sockets);
        // Os que o dono fechou e já terminaram saem do conjunto — ver
        // `fechando` sobre o `TIME_WAIT`.
        let sockets = &mut self.sockets;
        self.fechando.retain(|&(h, _)| {
            let acabou = matches!(
                sockets.get::<tcp::Socket>(h).state(),
                tcp::State::Closed | tcp::State::TimeWait
            );
            if acabou {
                sockets.remove(h);
            }
            !acabou
        });
        let evento = self.sockets.get_mut::<dhcpv4::Socket>(self.dhcp).poll()?;
        match evento {
            dhcpv4::Event::Configured(c) => {
                let endereco = c.address;
                let roteador = c.router;
                self.iface.update_ip_addrs(|a| {
                    a.clear();
                    let _ = a.push(IpCidr::Ipv4(endereco));
                });
                match roteador {
                    Some(r) => {
                        let _ = self.iface.routes_mut().add_default_ipv4_route(r);
                    }
                    None => {
                        self.iface.routes_mut().remove_default_ipv4_route();
                    }
                }
                self.endereco = Some(endereco);
                self.roteador = roteador;
                Some(Some((endereco.address().octets(), endereco.prefix_len())))
            }
            dhcpv4::Event::Deconfigured => {
                self.iface.update_ip_addrs(|a| a.clear());
                self.iface.routes_mut().remove_default_ipv4_route();
                self.endereco = None;
                self.roteador = None;
                Some(None)
            }
        }
    }

    fn achar(&self, id: u64, dono: &Dono) -> Result<usize, &'static str> {
        // Uma conexão de outro titular e uma que não existe respondem o
        // mesmo: quem pergunta não descobre o que é dos outros.
        self.conexoes
            .iter()
            .position(|c| c.id == id && c.dono == *dono)
            .ok_or("conexao inexistente, ou de outro titular")
    }
}

/// O destino da conexão `id`, se ela é de `dono`. É o que o gate decide
/// num `net.send`, `net.recv` ou `net.close`.
pub fn destino_de(id: u64, dono: &Dono) -> Result<Destino, &'static str> {
    com_pilha(|p| p.achar(id, dono).map(|i| p.conexoes[i].destino))
        .unwrap_or(Err("a pilha de rede nao esta no ar"))
}

/// Abre uma conexão de `dono` para `destino`. Devolve o número dela e o
/// estado — quase sempre `connecting`: o aperto de mão segue no fio da
/// rede, e quem abriu acompanha por `net.recv`.
pub fn abrir(dono: Dono, destino: Destino) -> Result<(u64, Estado), &'static str> {
    let r = com_pilha(|p| {
        if p.endereco.is_none() {
            return Err("a rede ainda nao tem endereco (o DHCP nao respondeu)");
        }
        if p.conexoes.len() + p.fechando.len() >= MAIS_CONEXOES {
            return Err("a tabela de conexoes esta cheia");
        }
        let do_dono = p.conexoes.iter().filter(|c| c.dono == dono).count()
            + p.fechando.iter().filter(|(_, d)| *d == dono).count();
        if do_dono >= CONEXOES_POR_DONO {
            return Err("este titular ja tem o maximo de conexoes abertas");
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; BUFFER_DA_CONEXAO]),
            tcp::SocketBuffer::new(vec![0u8; BUFFER_DA_CONEXAO]),
        );
        let porta = p.proxima_porta;
        p.proxima_porta = if porta == u16::MAX {
            PRIMEIRA_PORTA
        } else {
            porta + 1
        };
        let remoto = (Ipv4Address::from(destino.ip), destino.porta);
        socket
            .connect(p.iface.context(), remoto, porta)
            .map_err(|_| "o destino nao se disca")?;
        let socket = p.sockets.add(socket);
        let id = p.proximo_id;
        p.proximo_id += 1;
        p.abertas += 1;
        // O SYN sai já, e não no próximo tique.
        let _ = p.sondar();
        let estado = Estado::de(p.sockets.get::<tcp::Socket>(socket).state());
        p.conexoes.push(Conexao {
            id,
            dono,
            destino,
            socket,
            enviados: 0,
            recebidos: 0,
            espera: None,
            relatado: estado,
        });
        Ok((id, estado))
    });
    r.unwrap_or(Err("a pilha de rede nao esta no ar"))
}

/// Manda o que couber de `dados` na conexão. Devolve quantos bytes a
/// conexão aceitou — menos que todos quando o buffer de saída está cheio —
/// e o estado.
pub fn mandar(id: u64, dono: &Dono, dados: &[u8]) -> Result<(usize, Estado), &'static str> {
    let r = com_pilha(|p| {
        let _ = p.sondar();
        let i = p.achar(id, dono)?;
        let h = p.conexoes[i].socket;
        let socket = p.sockets.get_mut::<tcp::Socket>(h);
        if !socket.may_send() {
            let estado = Estado::de(socket.state());
            p.conexoes[i].relatado = estado;
            return Ok((0, estado));
        }
        let aceitos = socket
            .send_slice(dados)
            .map_err(|_| "a conexao recusou os dados")?;
        p.conexoes[i].enviados += aceitos as u64;
        let _ = p.sondar();
        let estado = Estado::de(p.sockets.get::<tcp::Socket>(h).state());
        p.conexoes[i].relatado = estado;
        Ok((aceitos, estado))
    });
    r.unwrap_or(Err("a pilha de rede nao esta no ar"))
}

/// O que chegou na conexão, até `maximo` bytes, sem tirá-lo dela: a
/// decisão de quanto tirar é de quem lê — ver [`consumir`].
pub fn espiar(id: u64, dono: &Dono, maximo: usize) -> Result<(Vec<u8>, Estado), &'static str> {
    let r = com_pilha(|p| {
        let _ = p.sondar();
        let i = p.achar(id, dono)?;
        let socket = p.sockets.get_mut::<tcp::Socket>(p.conexoes[i].socket);
        let mut dados = vec![0u8; maximo.min(BUFFER_DA_CONEXAO)];
        let n = if socket.can_recv() {
            socket.peek_slice(&mut dados).unwrap_or(0)
        } else {
            0
        };
        dados.truncate(n);
        let estado = Estado::de(socket.state());
        p.conexoes[i].relatado = estado;
        Ok((dados, estado))
    });
    r.unwrap_or(Err("a pilha de rede nao esta no ar"))
}

/// Tira `quantos` bytes do começo do que chegou — os que [`espiar`]
/// mostrou e quem leu entregou.
pub fn consumir(id: u64, dono: &Dono, quantos: usize) -> Result<(), &'static str> {
    let r = com_pilha(|p| {
        let i = p.achar(id, dono)?;
        let socket = p.sockets.get_mut::<tcp::Socket>(p.conexoes[i].socket);
        let mut lixo = vec![0u8; quantos];
        let tirados = socket.recv_slice(&mut lixo).unwrap_or(0);
        p.conexoes[i].recebidos += tirados as u64;
        // A janela que abriu vai para o outro lado já.
        let _ = p.sondar();
        Ok(())
    });
    r.unwrap_or(Err("a pilha de rede nao esta no ar"))
}

/// Arma a espera de um `net.recv` na conexão `id` de `dono`, se não há o
/// que dizer agora. Devolve o número da espera e o estado que ela viu;
/// `None` quando já chegou dado, quando o estado não é mais o que a última
/// resposta disse ao dono — ver [`Conexao::relatado`] —, ou quando a
/// conexão está num estado de que nada mais vem — fechando ou fechada. A
/// segunda espera na mesma conexão é recusada: ver [`super::espera`].
pub fn armar(id: u64, dono: &Dono) -> Result<Option<(u64, Estado)>, &'static str> {
    let r = com_pilha(|p| {
        // O que chegou até agora conta: a espera é pelo que ainda não veio.
        let _ = p.sondar();
        let i = p.achar(id, dono)?;
        let socket = p.sockets.get::<tcp::Socket>(p.conexoes[i].socket);
        let estado = Estado::de(socket.state());
        if socket.can_recv()
            || estado != p.conexoes[i].relatado
            || !matches!(estado, Estado::Conectando | Estado::Estabelecida)
        {
            return Ok(None);
        }
        if p.conexoes[i].espera.is_some() {
            return Err("a conexao ja tem um net.recv esperando");
        }
        let numero = p.proxima_espera;
        p.proxima_espera += 1;
        p.conexoes[i].espera = Some(numero);
        Ok(Some((numero, estado)))
    });
    r.unwrap_or(Err("a pilha de rede nao esta no ar"))
}

/// A espera `numero`, armada na conexão `id` de `dono` com o estado
/// `estado`, acabou? `None` se não — e então `waker`, se veio um, fica no
/// socket: o `smoltcp` o aciona no próximo dado que entrar, na próxima
/// mudança de estado, e no fecho ou na derrubada.
///
/// Só confere: não sonda a pilha. Quem a faz andar é o fio `rede` e quem
/// pede algo a ela, e é na volta deles que o evento acontece — e acorda.
pub fn conferir_espera(
    id: u64,
    dono: &Dono,
    numero: u64,
    estado: Estado,
    waker: Option<&Waker>,
) -> Option<Desfecho> {
    com_pilha(|p| {
        let Ok(i) = p.achar(id, dono) else {
            return Some(Desfecho::Sumiu);
        };
        if p.conexoes[i].espera != Some(numero) {
            return Some(Desfecho::Sumiu);
        }
        let socket = p.sockets.get_mut::<tcp::Socket>(p.conexoes[i].socket);
        if socket.can_recv() {
            return Some(Desfecho::Chegou);
        }
        if Estado::de(socket.state()) != estado {
            return Some(Desfecho::Mudou);
        }
        if let Some(w) = waker {
            socket.register_recv_waker(w);
        }
        None
    })
    .unwrap_or(Some(Desfecho::Sumiu))
}

/// Só para a suíte: derruba o socket da conexão `id` como um `RST` do outro
/// lado o derrubaria — a conexão fica na tabela, fechada, até o dono a
/// fechar.
#[cfg(feature = "modo-teste")]
pub fn abortar_de_teste(id: u64) {
    let _ = com_pilha(|p| {
        if let Some(c) = p.conexoes.iter().find(|c| c.id == id) {
            p.sockets.get_mut::<tcp::Socket>(c.socket).abort();
        }
        let _ = p.sondar();
    });
}

/// Só para a suíte: o estado da conexão `id`, de quem for, sem que conte
/// como dito ao dono — ver [`Conexao::relatado`].
#[cfg(feature = "modo-teste")]
pub fn estado_de_teste(id: u64) -> Option<Estado> {
    com_pilha(|p| {
        let _ = p.sondar();
        p.conexoes
            .iter()
            .find(|c| c.id == id)
            .map(|c| Estado::de(p.sockets.get::<tcp::Socket>(c.socket).state()))
    })
    .flatten()
}

/// Só para a suíte: a conexão `id`, de quem for, tem uma espera armada?
#[cfg(feature = "modo-teste")]
pub fn espera_armada_de_teste(id: u64) -> bool {
    com_pilha(|p| p.conexoes.iter().any(|c| c.id == id && c.espera.is_some())).unwrap_or(false)
}

/// Desarma a espera `numero` da conexão `id` de `dono`, se ainda é ela a
/// armada.
pub fn desarmar(id: u64, dono: &Dono, numero: u64) {
    let _ = com_pilha(|p| {
        if let Ok(i) = p.achar(id, dono)
            && p.conexoes[i].espera == Some(numero)
        {
            p.conexoes[i].espera = None;
        }
    });
}

/// Fecha a conexão: o número deixa de valer na hora, e o fecho com o outro
/// lado termina no fio da rede.
pub fn fechar(id: u64, dono: &Dono) -> Result<(), &'static str> {
    let r = com_pilha(|p| {
        let i = p.achar(id, dono)?;
        let c = p.conexoes.remove(i);
        p.sockets.get_mut::<tcp::Socket>(c.socket).close();
        p.fechando.push((c.socket, c.dono));
        let _ = p.sondar();
        Ok(())
    });
    r.unwrap_or(Err("a pilha de rede nao esta no ar"))
}

/// Os donos das conexões vivas, com o número e o destino de cada uma.
pub fn donos() -> Vec<(u64, Dono, Destino)> {
    com_pilha(|p| {
        p.conexoes
            .iter()
            .map(|c| (c.id, c.dono, c.destino))
            .collect()
    })
    .unwrap_or_default()
}

/// Derruba as conexões `ids` — de donos que acabaram —, sem fecho educado:
/// do lado de cá ninguém mais as lê.
pub fn derrubar(ids: &[u64]) -> usize {
    com_pilha(|p| {
        let mut n = 0;
        p.conexoes.retain(|c| {
            if ids.contains(&c.id) {
                p.sockets.get_mut::<tcp::Socket>(c.socket).abort();
                p.fechando.push((c.socket, c.dono));
                n += 1;
                false
            } else {
                true
            }
        });
        let _ = p.sondar();
        n
    })
    .unwrap_or(0)
}

/// O que `net.info` diz da pilha. `None` se ela não está no ar.
pub fn resumo() -> Option<Resumo> {
    com_pilha(|p| Resumo {
        endereco: p.endereco.map(|c| (c.address().octets(), c.prefix_len())),
        roteador: p.roteador.map(|r| r.octets()),
        conexoes: p.conexoes.len(),
        abertas: p.abertas,
    })
}

/// Destrava a tranca da pilha à força, para uso exclusivo do caminho de
/// falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { PILHA.force_unlock() };
}
