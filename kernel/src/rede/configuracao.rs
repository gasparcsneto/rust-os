//! A rede desta máquina sem DHCP: `/etc/duke/rede`, na imagem.
//!
//! # O arquivo
//!
//! ```text
//! # A rede do servidor da sala 3.
//! endereco 192.168.10.5/24
//! roteador 192.168.10.1
//! dns 192.168.10.1
//! dns 9.9.9.9
//! ```
//!
//! - `endereco`: o IPv4 e o prefixo — obrigatório, uma vez;
//! - `roteador`: a rota padrão — opcional, uma vez, outra máquina da
//!   sub-rede;
//! - `dns`: um servidor de DNS — até [`super::pilha::MAIS_DNS`].
//!
//! Sem o arquivo, a máquina pede o endereço ao DHCP, como sempre. Com ele,
//! não pede: o endereço é o do arquivo. Um arquivo que não se lê não cai
//! para o DHCP em silêncio — quem escreveu um endereço quis aquele —: a
//! pilha fica sem endereço, e o `net.info` diz a linha e o motivo.
//!
//! # O que ele não é
//!
//! Alcance. Como o DNS que o DHCP anuncia, os servidores daqui são
//! informação para quem resolve nomes, e o roteador é por onde os pacotes
//! saem: falar com qualquer destino continua sendo um `net.connect`
//! decidido pela política, destino por destino. E só a imagem o escreve: não
//! há comando que troque a rede em tempo de execução.

/// Onde está.
pub const CAMINHO: &str = "/etc/duke/rede";

/// A rede escrita no arquivo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Estatica {
    /// O endereço e o prefixo.
    pub endereco: ([u8; 4], u8),
    pub roteador: Option<[u8; 4]>,
    pub dns: [Option<[u8; 4]>; super::pilha::MAIS_DNS],
}

/// Um IPv4 escrito em quatro números de 0 a 255.
fn ipv4(texto: &str) -> Option<[u8; 4]> {
    let mut saida = [0u8; 4];
    let mut partes = texto.split('.');
    for byte in saida.iter_mut() {
        let parte = partes.next()?;
        if parte.is_empty() || parte.len() > 3 || !parte.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *byte = parte.parse().ok()?;
    }
    partes.next().is_none().then_some(saida)
}

/// Um endereço que pode ser o de uma máquina na rede: nem da faixa zero
/// (0/8, "esta rede"), nem de laço (127/8), nem de grupo (224/4), nem
/// reservado ou de difusão (240/4).
fn de_maquina(ip: [u8; 4]) -> bool {
    ip[0] != 0 && ip[0] != 127 && ip[0] < 224
}

/// Se `ip` é uma máquina da sub-rede `rede`/`prefixo`: o mesmo prefixo, e
/// nem o endereço da sub-rede nem o de difusão dela.
fn na_sub_rede(ip: [u8; 4], rede: [u8; 4], prefixo: u8) -> bool {
    let m = mascara(prefixo);
    let hospedeiro = u32::from_be_bytes(ip) & !m;
    de_maquina(ip)
        && u32::from_be_bytes(ip) & m == u32::from_be_bytes(rede) & m
        && hospedeiro != 0
        && hospedeiro != !m
}

/// A máscara de `prefixo` bits.
fn mascara(prefixo: u8) -> u32 {
    if prefixo == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefixo))
    }
}

/// Lê o arquivo. `Err` com a linha (contada a partir de 1; zero para o
/// arquivo inteiro) e o motivo.
pub fn ler(texto: &str) -> Result<Estatica, (usize, &'static str)> {
    let mut endereco = None;
    let mut roteador = None;
    let mut dns = [None; super::pilha::MAIS_DNS];
    let mut quantos_dns = 0;
    for (n, linha) in texto.lines().enumerate() {
        let n = n + 1;
        let linha = linha.trim();
        if linha.is_empty() || linha.starts_with('#') {
            continue;
        }
        let mut campos = linha.split_ascii_whitespace();
        let chave = campos.next().unwrap_or("");
        let valor = campos.next().ok_or((n, "falta o valor"))?;
        if campos.next().is_some() {
            return Err((n, "um valor so por linha"));
        }
        match chave {
            "endereco" => {
                if endereco.is_some() {
                    return Err((n, "dois enderecos"));
                }
                let (ip, prefixo) = valor
                    .split_once('/')
                    .ok_or((n, "falta o prefixo: a.b.c.d/p"))?;
                let ip = ipv4(ip).ok_or((n, "endereco que nao e IPv4"))?;
                // Só dígitos: o `parse` de um inteiro aceitaria um `+24`.
                let prefixo: u8 = Some(prefixo)
                    .filter(|p| (1..=2).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|p| p.parse().ok())
                    .filter(|p| (1..=30).contains(p))
                    .ok_or((n, "prefixo fora de 1 a 30"))?;
                if !na_sub_rede(ip, ip, prefixo) {
                    return Err((n, "endereco que nao e de uma maquina nesta sub-rede"));
                }
                endereco = Some((ip, prefixo));
            }
            "roteador" => {
                if roteador.is_some() {
                    return Err((n, "dois roteadores"));
                }
                let ip = ipv4(valor).filter(|ip| de_maquina(*ip));
                roteador = Some((ip.ok_or((n, "roteador que nao e IPv4 de maquina"))?, n));
            }
            "dns" => {
                let ip = ipv4(valor).filter(|ip| de_maquina(*ip));
                let ip = ip.ok_or((n, "dns que nao e IPv4 de maquina"))?;
                *dns.get_mut(quantos_dns)
                    .ok_or((n, "servidores de DNS demais"))? = Some(ip);
                quantos_dns += 1;
            }
            _ => return Err((n, "linha que nao e endereco, roteador nem dns")),
        }
    }
    let endereco = endereco.ok_or((0, "falta o endereco"))?;
    // O roteador é outra máquina da sub-rede: é a ela que os pacotes de
    // fora são entregues, pelo endereço de placa que o ARP dela devolve.
    if let Some((r, n)) = roteador
        && (!na_sub_rede(r, endereco.0, endereco.1) || r == endereco.0)
    {
        return Err((n, "o roteador nao e outra maquina da sub-rede do endereco"));
    }
    Ok(Estatica {
        endereco,
        roteador: roteador.map(|(r, _)| r),
        dns,
    })
}

/// O que o boot fez com o arquivo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carga {
    /// Não há arquivo: o DHCP segue.
    SemArquivo,
    /// O endereço do arquivo, sem DHCP.
    Estatica(Estatica),
    /// O arquivo não se leu: a pilha sem endereço, pela linha (zero para o
    /// arquivo inteiro) e pelo motivo.
    Invalida(usize, &'static str),
}

/// No boot, com a raiz montada: aplica o [`CAMINHO`], se ele existe.
pub fn carregar() {
    let _ = carregar_de(CAMINHO);
}

/// Aplica o arquivo em `caminho`. Sem ele, nada muda — o DHCP segue. Com
/// ele ilegível, ou de fora da imagem, a pilha fica sem endereço e diz por
/// quê. Pública pela suíte, que monta o próprio arquivo.
pub fn carregar_de(caminho: &str) -> Carga {
    let lido = match crate::vfs::ler_tudo_com_origem(caminho) {
        Err(crate::vfs::Erro::NaoEncontrado) => return Carga::SemArquivo,
        Err(e) => {
            crate::log_error!("rede", "{} nao se le: {}", caminho, e.motivo());
            Err((0, "o arquivo da rede nao se le"))
        }
        // Só a imagem escreve a rede. Hoje nada gravável alcança o /etc;
        // se um dia alcançar, o que foi gravado lá não vira o endereço da
        // máquina.
        Ok((_, origem)) if origem != crate::vfs::Origem::Imagem => {
            Err((0, "o arquivo da rede nao veio da imagem"))
        }
        Ok((bytes, _)) => core::str::from_utf8(&bytes)
            .map_err(|_| (0, "o arquivo da rede nao e texto"))
            .and_then(ler),
    };
    match lido {
        Ok(c) => {
            let ([a, b, cc, d], prefixo) = c.endereco;
            crate::log_info!(
                "rede",
                "endereco {}.{}.{}.{}/{} pelo {}, sem DHCP",
                a,
                b,
                cc,
                d,
                prefixo,
                caminho
            );
            super::pilha::fixar_estatica(&c);
            Carga::Estatica(c)
        }
        Err((linha, motivo)) => {
            crate::log_error!(
                "rede",
                "{}, linha {}: {}; a rede fica sem endereco",
                caminho,
                linha,
                motivo
            );
            super::pilha::sem_configuracao(motivo);
            Carga::Invalida(linha, motivo)
        }
    }
}
