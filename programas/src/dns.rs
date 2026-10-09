//! Resolver um nome, como um programa: a associação UDP com o servidor —
//! que o gate decide, como decide qualquer destino —, a pergunta, a
//! resposta, entendida com `protocolo::dns`.
//!
//! O kernel não resolve nome nenhum, e o nome não vale nada para a
//! política: o que volta é só um número na mão do programa. Para conversar
//! com ele, o programa pede `net.connect` com o destino inteiro, e o gate o
//! decide como se o número tivesse sido digitado.

use alloc::vec::Vec;

use protocolo::dns;

use crate::nativo;

/// Quanto a leitura espera a resposta, em milissegundos.
const ESPERA_MS: u64 = 3_000;

/// Por que um nome não resolveu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falha {
    /// O gate recusou a associação com o servidor — o código, se veio.
    Recusada,
    /// O nome não se escreve como nome.
    Nome(dns::Erro),
    /// A pergunta não saiu.
    Envio,
    /// Nenhuma resposta do servidor dentro do prazo — uma resposta de outra
    /// origem a associação descarta, e não chega aqui.
    SemResposta,
    /// A resposta não se lê.
    Malformada(dns::Erro),
    /// A resposta não é desta pergunta: outro número, ou outro nome.
    Desencontrada,
    /// O servidor diz que o nome não existe, ou devolveu outro erro.
    Codigo(u8),
}

/// O valor de um caractere base64.
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
fn de_base64(texto: &str) -> Option<Vec<u8>> {
    let b = texto.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let mut saida = Vec::new();
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
    Some(saida)
}

/// O datagrama de uma leitura: em texto, desescapado; em base64,
/// decodificado.
fn datagrama(r: &nativo::Resposta) -> Option<Vec<u8>> {
    let resultado = r.resultado().ok()?;
    let conteudo = resultado.member("content")?;
    match resultado.member("encoding")?.as_str()? {
        "utf-8" => {
            let mut claro = alloc::vec![0u8; conteudo.0.len()];
            Some(conteudo.desescapar_em(&mut claro)?.as_bytes().to_vec())
        }
        "base64" => de_base64(conteudo.as_str()?),
        _ => None,
    }
}

/// Resolve `nome` pelo servidor `servidor` (`udp:<ipv4>:53`): os endereços
/// IPv4 que a resposta dá a ele, ou por que não deu.
pub fn resolver(servidor: &str, nome: &str, id: u16) -> Result<Vec<[u8; 4]>, Falha> {
    let alvo = dns::Nome::de_texto(nome).map_err(Falha::Nome)?;
    let r = nativo::pedir("net.connect", |w| w.field_str("to", servidor))
        .map_err(|_| Falha::Recusada)?;
    let Some(associacao) = r
        .resultado()
        .ok()
        .and_then(|j| j.member("connection"))
        .and_then(|v| v.as_u64())
    else {
        return Err(Falha::Recusada);
    };
    let resultado = perguntar(associacao, &alvo, id);
    let _ = nativo::pedir("net.close", |w| w.field_u64("connection", associacao));
    resultado
}

fn perguntar(associacao: u64, alvo: &dns::Nome, id: u16) -> Result<Vec<[u8; 4]>, Falha> {
    let mut b = [0u8; dns::MAIOR_MENSAGEM];
    let n = dns::pergunta(id, alvo, &mut b).map_err(Falha::Nome)?;
    let enviado = nativo::pedir_com_anexo(
        "net.send",
        |w| w.field_u64("connection", associacao),
        &b[..n],
    )
    .ok()
    .and_then(|r| r.resultado().ok()?.member("sent")?.as_u64());
    if enviado != Some(n as u64) {
        return Err(Falha::Envio);
    }
    let r = nativo::pedir("net.recv", |w| {
        w.field_u64("connection", associacao)?;
        w.field_u64("wait", ESPERA_MS)
    })
    .map_err(|_| Falha::SemResposta)?;
    let resposta = datagrama(&r)
        .filter(|d| !d.is_empty())
        .ok_or(Falha::SemResposta)?;
    let m = dns::ler(&resposta).map_err(Falha::Malformada)?;
    if m.id != id || !m.resposta || m.nome() != Some(alvo) {
        return Err(Falha::Desencontrada);
    }
    if m.codigo != dns::SEM_ERRO {
        return Err(Falha::Codigo(m.codigo));
    }
    Ok(m.enderecos().to_vec())
}
