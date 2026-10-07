//! A rede, acima do transporte de quadros.
//!
//! # Onde cada coisa mora
//!
//! [`crate::virtio::net`] transporta quadros: entrega um, recebe os que
//! chegarem, sem saber o que há dentro deles. Aqui fica o que olha para
//! dentro:
//!
//! - [`pilha`]: a pilha IP — Ethernet, ARP, IPv4, DHCP e TCP, pelo
//!   `smoltcp` —, que é a **única** que colhe quadros da placa;
//! - [`conexoes`]: a conexão TCP de saída como capacidade do registro: de
//!   quem ela é, e como o gate a decide;
//! - este arquivo: o ARP do diagnóstico — `net.arp`, a pergunta "quem
//!   atende por este endereço?" —, que não abre conexão nenhuma.
//!
//! # Por que o ARP do diagnóstico continua
//!
//! Porque é o menor diálogo completo que existe sobre Ethernet: quarenta e
//! dois bytes, nenhuma soma de verificação, e uma resposta que só pode ter
//! vindo de fora do kernel. Responde "a placa funciona?" sem depender de a
//! pilha ter endereço — e a pilha depende de a placa funcionar.
//!
//! # Um consumidor só da recepção
//!
//! Quando o ARP era a única coisa em cima da placa, ele mesmo colhia as
//! respostas. Com a pilha colhendo tudo, dois consumidores disputariam os
//! mesmos quadros e cada um perderia os do outro. A pilha entrega cada
//! quadro que colhe a [`observar`] antes de processá-lo; o ARP pergunta,
//! faz a pilha andar, e procura a resposta entre as observadas.

pub mod conexoes;
pub mod pilha;

use crate::trava::Mutex;

/// Onde cada campo começa dentro de um quadro ARP sobre Ethernet.
///
/// Escritos como deslocamentos, e não montados num `struct` com `repr(C)`,
/// porque um quadro de rede é uma sequência de bytes sem alinhamento nenhum:
/// o endereço IP de origem começa no byte 28, que não é múltiplo de quatro.
/// Um `struct` prometeria um alinhamento que o formato não tem.
mod campo {
    pub const DESTINO: usize = 0;
    pub const ORIGEM: usize = 6;
    pub const TIPO: usize = 12;
    pub const OPERACAO: usize = 20;
    pub const MAC_DE_ORIGEM: usize = 22;
    pub const IP_DE_ORIGEM: usize = 28;
    pub const MAC_DE_DESTINO: usize = 32;
    pub const IP_DE_DESTINO: usize = 38;
}

/// Quanto mede um quadro ARP sobre Ethernet.
pub const TAMANHO_DO_QUADRO: usize = 42;

/// O tipo que identifica um quadro ARP no Ethernet.
const TIPO_ARP: [u8; 2] = [0x08, 0x06];
const PEDIDO: [u8; 2] = [0x00, 0x01];
const RESPOSTA: [u8; 2] = [0x00, 0x02];

/// Quanto mede um endereço de placa, e quanto mede um endereço IPv4.
pub const TAMANHO_DO_MAC: usize = 6;
pub const TAMANHO_DO_IP: usize = 4;

/// Quanto esperar pela resposta antes de desistir, em tiques.
///
/// A resposta atravessa a fronteira para o hospedeiro e volta; no emulador
/// isso leva milissegundos. Dois segundos é a margem de uma máquina
/// carregada, e o custo de errar para cima é só uma espera que acontece
/// quando já não havia resposta.
const ESPERA_EM_TIQUES: u64 = 200;

/// Quantas respostas ARP recentes ficam guardadas para quem perguntou.
const RESPOSTAS_GUARDADAS: usize = 8;

/// As respostas ARP que a pilha colheu, com o número de ordem de cada uma:
/// quem pergunta só olha as que chegaram depois do pedido dele.
struct Observadas {
    proxima: u64,
    quadros: [(u64, [u8; TAMANHO_DO_QUADRO]); RESPOSTAS_GUARDADAS],
}

static OBSERVADAS: Mutex<Observadas> = Mutex::new(Observadas {
    proxima: 1,
    quadros: [(0, [0; TAMANHO_DO_QUADRO]); RESPOSTAS_GUARDADAS],
});

fn com_observadas<R>(f: impl FnOnce(&mut Observadas) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut OBSERVADAS.lock()))
}

/// Um quadro que a pilha colheu: se é uma resposta ARP, fica guardado para
/// [`resolver`]. Barato para o resto — dois bytes comparados.
pub(crate) fn observar(quadro: &[u8]) {
    if quadro.len() < TAMANHO_DO_QUADRO
        || quadro[campo::TIPO..campo::TIPO + 2] != TIPO_ARP
        || quadro[campo::OPERACAO..campo::OPERACAO + 2] != RESPOSTA
    {
        return;
    }
    let mut copia = [0u8; TAMANHO_DO_QUADRO];
    copia.copy_from_slice(&quadro[..TAMANHO_DO_QUADRO]);
    com_observadas(|o| {
        let n = o.proxima;
        o.proxima += 1;
        o.quadros[(n as usize) % RESPOSTAS_GUARDADAS] = (n, copia);
    });
}

/// Destrava a tranca das respostas ARP observadas à força, para uso
/// exclusivo do caminho de falha fatal. A da pilha é de [`pilha`].
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { OBSERVADAS.force_unlock() };
}

/// Monta um pedido ARP perguntando quem atende por `procurado`.
fn montar_pedido(
    nosso_mac: &[u8; TAMANHO_DO_MAC],
    nosso_ip: &[u8; TAMANHO_DO_IP],
    procurado: &[u8; TAMANHO_DO_IP],
) -> [u8; TAMANHO_DO_QUADRO] {
    let mut quadro = [0u8; TAMANHO_DO_QUADRO];

    // Ethernet: para todo mundo, porque ainda não sabemos o endereço de
    // ninguém — é justamente o que estamos perguntando.
    quadro[campo::DESTINO..campo::DESTINO + TAMANHO_DO_MAC].fill(0xFF);
    quadro[campo::ORIGEM..campo::ORIGEM + TAMANHO_DO_MAC].copy_from_slice(nosso_mac);
    quadro[campo::TIPO..campo::TIPO + 2].copy_from_slice(&TIPO_ARP);

    // ARP: Ethernet (1) sobre IPv4 (0x0800), endereços de 6 e 4 bytes.
    quadro[14..16].copy_from_slice(&[0x00, 0x01]);
    quadro[16..18].copy_from_slice(&[0x08, 0x00]);
    quadro[18] = TAMANHO_DO_MAC as u8;
    quadro[19] = TAMANHO_DO_IP as u8;
    quadro[campo::OPERACAO..campo::OPERACAO + 2].copy_from_slice(&PEDIDO);

    quadro[campo::MAC_DE_ORIGEM..campo::MAC_DE_ORIGEM + TAMANHO_DO_MAC].copy_from_slice(nosso_mac);
    quadro[campo::IP_DE_ORIGEM..campo::IP_DE_ORIGEM + TAMANHO_DO_IP].copy_from_slice(nosso_ip);
    // O MAC de destino vai zerado: é o campo que a resposta preenche.
    quadro[campo::IP_DE_DESTINO..campo::IP_DE_DESTINO + TAMANHO_DO_IP].copy_from_slice(procurado);

    quadro
}

/// Pergunta quem atende por `procurado` e espera pela resposta.
///
/// `nosso_ip` é o endereço que anunciamos como origem. Ele não precisa estar
/// configurado em lugar nenhum — não há configuração de IP neste kernel —, e
/// serve para que o outro lado saiba para onde responder.
///
/// # O que uma resposta precisa provar
///
/// Não basta chegar um quadro. A rede entrega coisas que não pedimos, e um
/// driver quebrado entregaria lixo. A resposta aceita aqui é a que confere em
/// todos os campos: é ARP, é uma resposta, vem de quem perguntamos, e é
/// endereçada a nós — na camada ARP **e** na Ethernet.
pub fn resolver(
    procurado: &[u8; TAMANHO_DO_IP],
    nosso_ip: &[u8; TAMANHO_DO_IP],
) -> Result<[u8; TAMANHO_DO_MAC], &'static str> {
    let Some(nosso_mac) = crate::virtio::net::com_a_placa(|placa| placa.mac()) else {
        return Err("nao ha placa de rede virtio nesta maquina");
    };
    let Some(nosso_mac) = nosso_mac else {
        return Err("a placa nao publicou endereco");
    };

    let pedido = montar_pedido(&nosso_mac, nosso_ip, procurado);
    // Só as respostas que chegarem daqui em diante: uma antiga, de outra
    // pergunta, não responde a esta.
    let desde = com_observadas(|o| o.proxima);
    match crate::virtio::net::com_a_placa(|placa| placa.transmitir(&pedido)) {
        Some(Ok(())) => {}
        Some(Err(motivo)) => return Err(motivo),
        None => return Err("nao ha placa de rede virtio nesta maquina"),
    }

    let limite = crate::tempo::ticks() + ESPERA_EM_TIQUES;
    loop {
        // A pilha colhe; o que for resposta ARP fica em `OBSERVADAS`.
        pilha::sondar();
        let achada = com_observadas(|o| {
            o.quadros
                .iter()
                .filter(|(n, _)| *n >= desde)
                .map(|(_, q)| *q)
                .find(|q| q[campo::IP_DE_ORIGEM..campo::IP_DE_ORIGEM + TAMANHO_DO_IP] == *procurado)
        });
        if let Some(quadro) = achada {
            return conferir_resposta(&quadro, nosso_ip, &nosso_mac);
        }
        if crate::tempo::ticks() >= limite {
            break;
        }
        if !crate::virtio::net::com_a_placa(|placa| placa.vivo()).unwrap_or(false) {
            return Err("a placa parou de responder e foi desligada");
        }
        crate::fios::ceder();
    }

    Err("nenhuma resposta ARP chegou")
}

/// O resto da conferência de uma resposta ARP de quem perguntamos.
fn conferir_resposta(
    quadro: &[u8; TAMANHO_DO_QUADRO],
    nosso_ip: &[u8; TAMANHO_DO_IP],
    nosso_mac: &[u8; TAMANHO_DO_MAC],
) -> Result<[u8; TAMANHO_DO_MAC], &'static str> {
    // Daqui para baixo é a resposta que pedimos, e tudo o que ela diz tem
    // de bater. São estas conferências que separam "recebi um quadro" de
    // "recebi a resposta a esta pergunta".
    if quadro[campo::IP_DE_DESTINO..campo::IP_DE_DESTINO + TAMANHO_DO_IP] != *nosso_ip {
        return Err("a resposta ARP e para outro endereco IP");
    }
    if quadro[campo::MAC_DE_DESTINO..campo::MAC_DE_DESTINO + TAMANHO_DO_MAC] != *nosso_mac {
        return Err("a resposta ARP e para outra placa");
    }
    if quadro[campo::DESTINO..campo::DESTINO + TAMANHO_DO_MAC] != *nosso_mac {
        return Err("o quadro Ethernet da resposta e para outra placa");
    }

    let mut dono = [0u8; TAMANHO_DO_MAC];
    dono.copy_from_slice(&quadro[campo::MAC_DE_ORIGEM..campo::MAC_DE_ORIGEM + TAMANHO_DO_MAC]);

    if dono.iter().all(|&b| b == 0) {
        return Err("a resposta ARP anuncia um endereco todo zeros");
    }

    Ok(dono)
}
