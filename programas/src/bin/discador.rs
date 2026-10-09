//! Um programa que conversa pela rede do Duke, e confere de dentro o que a
//! rede promete a um processo:
//!
//! - a conexão é pedida ao registro — `net.connect`, com o destino inteiro
//!   —, pelo mesmo `pedir` de todo comando; o manifesto declara
//!   `net.connect`, e sem isso o gate recusaria, qualquer que fosse o papel
//!   de quem o lançou;
//! - o destino é o recurso que a política decide: o eco da bancada,
//!   `tcp:10.0.2.100:7`, está no alcance; a porta ao lado não está, e a
//!   recusa é `DENY_RESOURCE`;
//! - os bytes vão e voltam inteiros: os 256 valores de um byte, pelo anexo
//!   do pedido, e de volta em texto quando são texto e em base64 quando
//!   não são;
//! - o programa não pergunta de novo a cada volta: cada `net.recv` leva
//!   `wait`, e o fio dorme até a pilha ter o que dizer — o aperto terminar,
//!   o eco devolver. Os 256 bytes voltam em poucas leituras, e uma leitura
//!   no silêncio acaba pelo prazo, vazia, com a conexão ainda aberta;
//! - fechada, a conexão deixa de existir para o programa também:
//!   `DENY_RESOURCE`, a mesma resposta de um número que nunca existiu;
//! - e pelo UDP, a mesma capacidade com datagramas: a associação com o TFTP
//!   do emulador, `udp:10.0.2.2:69`, pede o arquivo da bancada e o recebe
//!   em dois datagramas, cada um inteiro numa leitura que espera, e
//!   confirma cada bloco.
//!
//! Lançado por alguém sem `net.connect` no papel, sai com [`SEM_REDE`]
//! depois de ouvir `DENY_PERMISSION`. Sai com [`CODIGO`] quando tudo
//! confere, e com um código menor que diz o quê, quando não.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!("discador", "net.connect");

use alloc::vec::Vec;
use programas::escreverln;
use programas::nativo::{self, Recusa};

/// O código de saída quando tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 79;

/// O código de quem foi lançado sem `net.connect` no papel.
const SEM_REDE: i64 = 71;

/// O eco da bancada — ver a política de desenvolvimento.
const ECO: &str = "tcp:10.0.2.100:7";

/// O TFTP do emulador, o destino UDP da bancada — ver a política de
/// desenvolvimento.
const TFTP: &str = "udp:10.0.2.2:69";

/// O arquivo que o TFTP da bancada serve, como o `xtask` o escreve:
/// quarenta linhas de dezesseis bytes, em dois blocos.
fn arquivo_do_tftp() -> Vec<u8> {
    (0..40)
        .flat_map(|i| alloc::format!("bancada udp {i:03}\n").into_bytes())
        .collect()
}

/// Quanto cada leitura espera, em milissegundos: o eco responde em bem
/// menos, e a espera acaba quando o dado chega.
const ESPERA_MS: u64 = 5_000;

/// Quanto dura a leitura no silêncio: a suíte vê o fio dormir nela, e
/// confere que ela acaba pelo prazo.
const SILENCIO_MS: u64 = 1_500;

/// Quantas leituras os 256 bytes podem custar. Cada uma espera o dado, e o
/// eco os devolve em poucos segmentos; perguntando de novo a cada volta,
/// como antes da espera, eram centenas.
const LEITURAS: usize = 16;

fn codigo_de(r: &nativo::Resposta) -> Option<&str> {
    match r.resultado() {
        Err(Recusa { motivo, .. }) => motivo,
        Ok(_) => None,
    }
}

fn numero(r: &nativo::Resposta, campo: &str) -> Option<u64> {
    r.resultado().ok()?.member(campo)?.as_u64()
}

fn texto<'r>(r: &'r nativo::Resposta, campo: &str) -> Option<&'r str> {
    r.resultado().ok()?.member(campo)?.as_str()
}

/// O valor de um caractere base64, ou `None` para o que não é.
fn valor(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// Base64 com preenchimento, de volta a bytes.
fn de_base64(texto: &str, saida: &mut Vec<u8>) -> Option<()> {
    let b = texto.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    for quarteto in b.chunks(4) {
        let iguais = quarteto.iter().rev().take_while(|&&c| c == b'=').count();
        let mut n = 0u32;
        for &c in &quarteto[..4 - iguais] {
            n = (n << 6) | valor(c)?;
        }
        n <<= 6 * iguais as u32;
        let tres = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        saida.extend_from_slice(&tres[..3 - iguais]);
    }
    Some(())
}

/// Os bytes do conteúdo de uma leitura: em texto, desescapado; em base64,
/// decodificado.
fn conteudo(r: &nativo::Resposta) -> Option<Vec<u8>> {
    let lido = texto(r, "content")?;
    match texto(r, "encoding")? {
        "utf-8" => {
            let mut claro = alloc::vec![0u8; lido.len()];
            let t = r
                .resultado()
                .ok()?
                .member("content")?
                .desescapar_em(&mut claro)?;
            Some(t.as_bytes().to_vec())
        }
        "base64" => {
            let mut bytes = Vec::new();
            de_base64(lido, &mut bytes)?;
            Some(bytes)
        }
        _ => None,
    }
}

/// Manda `dados` como um datagrama da associação, pelo anexo. Verdadeiro se
/// ele saiu inteiro.
fn mandar_datagrama(associacao: u64, dados: &[u8]) -> bool {
    let Ok(r) =
        nativo::pedir_com_anexo("net.send", |w| w.field_u64("connection", associacao), dados)
    else {
        return false;
    };
    let saiu = numero(&r, "sent") == Some(dados.len() as u64);
    if !saiu {
        escreverln!(
            "discador: o datagrama nao saiu: {:?} {:?}",
            codigo_de(&r),
            texto(&r, "error")
        );
    }
    saiu
}

/// O próximo datagrama da associação, numa leitura que espera: inteiro, do
/// tamanho que a resposta diz.
fn datagrama(associacao: u64) -> Option<Vec<u8>> {
    let r = nativo::pedir("net.recv", |w| {
        w.field_u64("connection", associacao)?;
        w.field_u64("wait", ESPERA_MS)
    })
    .ok()?;
    let lido = conteudo(&r);
    match (numero(&r, "datagram"), lido) {
        (Some(tamanho), Some(d)) if d.len() as u64 == tamanho => Some(d),
        (tamanho, _) => {
            escreverln!(
                "discador: a leitura UDP deu {:?} {:?} {:?}",
                tamanho,
                codigo_de(&r),
                texto(&r, "error")
            );
            None
        }
    }
}

/// O arquivo da bancada pelo TFTP do emulador: o pedido de leitura, e cada
/// bloco num datagrama, confirmado. `Err` com o código de saída.
fn pelo_udp() -> Result<(), i64> {
    let r = nativo::pedir("net.connect", |w| w.field_str("to", TFTP)).map_err(|_| 14)?;
    let (Some(associacao), Some("open")) = (numero(&r, "connection"), texto(&r, "state")) else {
        escreverln!(
            "discador: o TFTP nao abriu: {:?} {:?}",
            codigo_de(&r),
            texto(&r, "error")
        );
        return Err(14);
    };
    let mut pedido = Vec::from([0u8, 1]);
    pedido.extend_from_slice(b"bancada.txt\0octet\0");
    if !mandar_datagrama(associacao, &pedido) {
        return Err(15);
    }
    let mut arquivo = Vec::new();
    for bloco in 1..=2u16 {
        let d = datagrama(associacao).ok_or(16)?;
        let [a, b] = bloco.to_be_bytes();
        if d.len() < 4 || d[..4] != [0, 3, a, b] {
            escreverln!("discador: o bloco {} veio errado: {} bytes", bloco, d.len());
            return Err(17);
        }
        arquivo.extend_from_slice(&d[4..]);
        if !mandar_datagrama(associacao, &[0, 4, a, b]) {
            return Err(15);
        }
    }
    if arquivo != arquivo_do_tftp() {
        escreverln!(
            "discador: o arquivo do TFTP veio com {} bytes, e nao o da bancada",
            arquivo.len()
        );
        return Err(18);
    }
    let r =
        nativo::pedir("net.close", |w| w.field_u64("connection", associacao)).map_err(|_| 19)?;
    if codigo_de(&r).is_some() {
        return Err(19);
    }
    Ok(())
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    // A porta ao lado do eco: fora do alcance de qualquer papel desta
    // imagem.
    let Ok(r) = nativo::pedir("net.connect", |w| w.field_str("to", "tcp:10.0.2.100:8")) else {
        return 1;
    };
    match codigo_de(&r) {
        Some("DENY_PERMISSION") => {
            escreverln!("discador: sem net.connect no papel de quem me lancou");
            return SEM_REDE;
        }
        Some("DENY_RESOURCE") => {}
        outro => {
            escreverln!("discador: a porta ao lado deu {:?}", outro);
            return 2;
        }
    }

    let Ok(r) = nativo::pedir("net.connect", |w| w.field_str("to", ECO)) else {
        return 3;
    };
    let Some(conexao) = numero(&r, "connection") else {
        escreverln!(
            "discador: o eco nao abriu: {:?} {:?}",
            codigo_de(&r),
            texto(&r, "error")
        );
        return 3;
    };

    // O aperto: uma leitura de nada, que espera o estado sair de
    // `connecting`.
    let Ok(r) = nativo::pedir("net.recv", |w| {
        w.field_u64("connection", conexao)?;
        w.field_u64("max", 0)?;
        w.field_u64("wait", ESPERA_MS)
    }) else {
        return 11;
    };
    if texto(&r, "state") != Some("established") {
        escreverln!(
            "discador: o aperto acabou em {:?} {:?}",
            texto(&r, "state"),
            codigo_de(&r)
        );
        return 11;
    }

    // Os 256 valores de um byte, pelo anexo: metade não é texto.
    let enviado: Vec<u8> = (0..=255u8).collect();
    let mut mandados = 0usize;
    while mandados < enviado.len() {
        let resto = &enviado[mandados..];
        let Ok(r) =
            nativo::pedir_com_anexo("net.send", |w| w.field_u64("connection", conexao), resto)
        else {
            return 4;
        };
        match numero(&r, "sent") {
            Some(n) if n > 0 => mandados += n as usize,
            _ => {
                escreverln!(
                    "discador: net.send deu {:?} {:?}",
                    codigo_de(&r),
                    texto(&r, "error")
                );
                return 4;
            }
        }
    }
    let mut voltou = Vec::new();
    for _ in 0..LEITURAS {
        let Ok(r) = nativo::pedir("net.recv", |w| {
            w.field_u64("connection", conexao)?;
            w.field_u64("wait", ESPERA_MS)
        }) else {
            return 5;
        };
        let (Some(codificacao), Some(conteudo)) = (texto(&r, "encoding"), texto(&r, "content"))
        else {
            escreverln!(
                "discador: net.recv deu {:?} {:?}",
                codigo_de(&r),
                texto(&r, "error")
            );
            return 5;
        };
        match codificacao {
            // O texto vem escapado no JSON — os bytes de controle como
            // `\u0001` —, e volta ao que era pelo leitor do protocolo.
            "utf-8" => {
                let mut claro = alloc::vec![0u8; conteudo.len()];
                let Some(t) = r
                    .resultado()
                    .ok()
                    .and_then(|v| v.member("content"))
                    .and_then(|c| c.desescapar_em(&mut claro))
                else {
                    return 6;
                };
                voltou.extend_from_slice(t.as_bytes());
            }
            "base64" => {
                if de_base64(conteudo, &mut voltou).is_none() {
                    return 6;
                }
            }
            _ => return 6,
        }
        if voltou.len() >= enviado.len() {
            break;
        }
        if texto(&r, "state") == Some("closed") {
            escreverln!(
                "discador: o eco fechou com {} de {} bytes",
                voltou.len(),
                enviado.len()
            );
            return 7;
        }
    }
    if voltou.len() < enviado.len() {
        escreverln!(
            "discador: {} leituras trouxeram {} de {} bytes",
            LEITURAS,
            voltou.len(),
            enviado.len()
        );
        return 12;
    }
    if voltou != enviado {
        escreverln!(
            "discador: voltaram {} bytes, e nao os mandados",
            voltou.len()
        );
        return 8;
    }

    // No silêncio: nada vem, e a leitura acaba pelo prazo — vazia, com a
    // conexão ainda aberta. Enquanto isso o fio dorme.
    escreverln!("discador: esperando no silencio");
    let Ok(r) = nativo::pedir("net.recv", |w| {
        w.field_u64("connection", conexao)?;
        w.field_u64("wait", SILENCIO_MS)
    }) else {
        return 13;
    };
    if numero(&r, "returned") != Some(0) || texto(&r, "state") != Some("established") {
        escreverln!(
            "discador: o silencio deu {:?} {:?} {:?}",
            numero(&r, "returned"),
            texto(&r, "state"),
            codigo_de(&r)
        );
        return 13;
    }

    let Ok(r) = nativo::pedir("net.close", |w| w.field_u64("connection", conexao)) else {
        return 9;
    };
    if codigo_de(&r).is_some() {
        return 9;
    }
    // Fechada, o número não vale mais — nem para quem a abriu.
    let Ok(r) = nativo::pedir("net.recv", |w| w.field_u64("connection", conexao)) else {
        return 10;
    };
    if codigo_de(&r) != Some("DENY_RESOURCE") {
        escreverln!("discador: a conexao fechada respondeu {:?}", codigo_de(&r));
        return 10;
    }

    escreverln!("discador: 256 bytes foram e voltaram pelo eco");

    if let Err(codigo) = pelo_udp() {
        return codigo;
    }
    escreverln!("discador: o arquivo da bancada veio pelo UDP, dois datagramas inteiros");
    CODIGO
}
