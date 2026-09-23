//! O mínimo de protocolo que existe acima do transporte de quadros.
//!
//! # Onde este arquivo começa e termina
//!
//! [`crate::virtio::net`] transporta quadros: entrega um, recebe os que
//! chegarem. Ele não sabe o que há dentro deles, e é essa ignorância que
//! permite testá-lo sem uma pilha de rede.
//!
//! Aqui mora a primeira coisa que **olha** para dentro de um quadro: ARP, o
//! protocolo que traduz um endereço IP no endereço da placa que o atende.
//!
//! # Por que ARP, e só ARP
//!
//! Porque é o menor diálogo completo que existe sobre Ethernet: quarenta e
//! dois bytes, nenhuma soma de verificação, e uma resposta que só pode ter
//! vindo de fora do kernel. É a prova de ponta a ponta mais barata que se
//! pode escrever, e é o que um agente precisa para responder "a rede
//! funciona?" sem uma pilha inteira por baixo.
//!
//! IP, UDP e TCP são outra fase. Cada um deles traz soma de verificação,
//! fragmentação e estado, e nenhum cabe num arquivo que possa ser lido de uma
//! vez.

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

/// Quantas voltas procurar pela resposta antes de desistir.
///
/// A resposta atravessa a fronteira para o hospedeiro e volta, e isso leva
/// tempo de parede que este kernel ainda não sabe medir em todo caminho. O
/// número é grande porque o custo de errar para baixo é uma resposta perdida
/// numa rede que funciona, e o de errar para cima é uma espera que só demora
/// quando já não havia resposta.
const VOLTAS_PROCURANDO: u32 = 2_000_000;

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
        return Err("nao ha placa de rede nesta maquina");
    };
    let Some(nosso_mac) = nosso_mac else {
        return Err("a placa nao publicou endereco");
    };

    let pedido = montar_pedido(&nosso_mac, nosso_ip, procurado);
    match crate::virtio::net::com_a_placa(|placa| placa.transmitir(&pedido)) {
        Some(Ok(())) => {}
        Some(Err(motivo)) => return Err(motivo),
        None => return Err("nao ha placa de rede nesta maquina"),
    }

    let mut quadro = [0u8; crate::virtio::net::MAIOR_QUADRO];

    for _ in 0..VOLTAS_PROCURANDO {
        let Some(recebido) = crate::virtio::net::com_a_placa(|placa| placa.receber(&mut quadro))
        else {
            return Err("nao ha placa de rede nesta maquina");
        };

        let Some(tamanho) = recebido else {
            core::hint::spin_loop();
            continue;
        };

        // Um quadro que não é a resposta não é falha: é tráfego que não nos
        // interessa, e numa rede há bastante dele.
        if tamanho < TAMANHO_DO_QUADRO
            || quadro[campo::TIPO..campo::TIPO + 2] != TIPO_ARP
            || quadro[campo::OPERACAO..campo::OPERACAO + 2] != RESPOSTA
            || quadro[campo::IP_DE_ORIGEM..campo::IP_DE_ORIGEM + TAMANHO_DO_IP] != *procurado
        {
            continue;
        }

        // Daqui para baixo é a resposta que pedimos, e tudo o que ela diz tem
        // de bater. São estas conferências que separam "recebi um quadro" de
        // "recebi a resposta a esta pergunta".
        if quadro[campo::IP_DE_DESTINO..campo::IP_DE_DESTINO + TAMANHO_DO_IP] != *nosso_ip {
            return Err("a resposta ARP e para outro endereco IP");
        }
        if quadro[campo::MAC_DE_DESTINO..campo::MAC_DE_DESTINO + TAMANHO_DO_MAC] != nosso_mac {
            return Err("a resposta ARP e para outra placa");
        }
        if quadro[campo::DESTINO..campo::DESTINO + TAMANHO_DO_MAC] != nosso_mac {
            return Err("o quadro Ethernet da resposta e para outra placa");
        }

        let mut dono = [0u8; TAMANHO_DO_MAC];
        dono.copy_from_slice(&quadro[campo::MAC_DE_ORIGEM..campo::MAC_DE_ORIGEM + TAMANHO_DO_MAC]);

        if dono.iter().all(|&b| b == 0) {
            return Err("a resposta ARP anuncia um endereco todo zeros");
        }

        return Ok(dono);
    }

    Err("nenhuma resposta ARP chegou")
}
