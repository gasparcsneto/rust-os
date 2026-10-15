//! A conferência de uma resposta contra o pedido que a pediu.
//!
//! O que se espera vem do registro do pedido, e não de quem entrega a
//! resposta: o nonce, a folha (o pacote inteiro do pedido) e a chave longa
//! fixada da fonte (ver [`crate::pedidos`]).
//!
//! # A resposta
//!
//! **Reproduzido**, nos dois pares de vetores:
//!
//! - no topo: `SIG` (64), `NONC` (32), `TYPE` (4, igual a 1), `PATH` (32 × k),
//!   `SREP`, `CERT` e `INDX` (4);
//! - `SREP` = {`VER` (4), `RADI` (4), `MIDP` (8), `VERS` (4 × k), `ROOT` (32)};
//! - `CERT` = {`SIG` (64), `DELE`}, e `DELE` = {`PUBK` (32), `MINT` (8),
//!   `MAXT` (8)};
//! - os inteiros são little-endian; `MIDP`, `MINT` e `MAXT` são segundos
//!   desde a época Unix, e `RADI` é segundos;
//! - o `SIG` de `CERT` é da chave longa sobre o contexto de delegação
//!   seguido dos bytes de `DELE`, como chegaram; o `SIG` do topo é da chave
//!   delegada (`PUBK`) sobre o contexto de resposta seguido dos bytes de
//!   `SREP`, como chegaram;
//! - os contextos da versão 1 são [`CONTEXTO_DE_DELEGACAO`] e
//!   [`CONTEXTO_DE_RESPOSTA`], com o zero no fim. Os dos rascunhos começam
//!   com `RoughTime`, com T maiúsculo, e não fecham as assinaturas da
//!   versão 1 — nem as da versão 1 fecham as deles.
//!
//! **Referência:** o `VERS` tem de 1 a 32 versões em ordem crescente, e
//! contém o `VER` (RFC 5.2.5); uma resposta cuja versão não foi oferecida é
//! inválida (RFC 7); `RADI` nunca é zero; etiquetas desconhecidas são
//! ignoradas também dentro de `SREP` e `DELE` (RFC 9.2).
//!
//! # A ordem das conferências
//!
//! Primeiro a forma (moldura, estrutura, tipo, nonce, versão), depois as
//! duas assinaturas, e só então o que a resposta afirma (a folha na árvore,
//! o carimbo na delegação, o raio). A ordem decide o veredito: tudo antes
//! das assinaturas é de uma resposta que pode não ser do servidor; tudo
//! depois é de uma resposta **autêntica** que não serve — uma resposta velha
//! ou de outro pedido ([`Recusa::OutroPedido`]), um carimbo fora da
//! delegação, um raio fora do teto. A auditoria e o NSF leem isso.
//!
//! Uma assinatura custa; quem forja faz este lado conferir duas por
//! resposta, e o teto de tentativas de cada pedido ([`crate::pedidos`])
//! limita quantas.
//!
//! A conferência é a estrita (`verify_strict`), como a do `sigilo`: recusa
//! chave fraca e assinatura maleável, também a da chave delegada.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::mensagem::{
    CERT, DELE, Etiqueta, INDX, MAXT, MIDP, MINT, Mensagem, NONC, PATH, PUBK, RADI, ROOT, SIG,
    SREP, TYPE, VER, VERS,
};
use crate::merkle::{self, MAIOR_CAMINHO, Resumo};
use crate::moldura::{self, MAIOR_PACOTE};
use crate::pedido::VERSAO;

/// O contexto da assinatura da delegação, versão 1 — reproduzido.
pub const CONTEXTO_DE_DELEGACAO: &[u8] = b"Roughtime v1 delegation signature\0";

/// O contexto da assinatura da resposta, versão 1 — reproduzido.
pub const CONTEXTO_DE_RESPOSTA: &[u8] = b"Roughtime v1 response signature\0";

/// O maior número de versões em `VERS` — referência.
pub const MAIS_VERSOES: usize = 32;

/// O `TYPE` de uma resposta — reproduzido.
const TIPO_RESPOSTA: u32 = 1;

/// O que se espera da resposta: vem do registro do pedido.
#[derive(Debug, Clone, Copy)]
pub struct Esperado<'a> {
    /// O nonce do pedido.
    pub nonce: &'a [u8; 32],
    /// A folha do pedido: H(0x00 ‖ o pacote inteiro).
    pub folha: &'a Resumo,
    /// A chave longa fixada da fonte a quem o pedido foi feito.
    pub chave_longa: &'a [u8; 32],
    /// O maior raio aceito, em segundos.
    pub teto_do_raio: u32,
}

/// O que uma resposta válida prova: um carimbo, assinado pela fonte depois
/// do pedido, e o que a auditoria guarda dela.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prova {
    /// O carimbo, em segundos desde a época Unix.
    pub midp: u64,
    /// O raio, em segundos: a fonte afirma que a hora estava a menos disso
    /// do carimbo quando ela o fez.
    pub radi: u32,
    /// A janela da delegação, em segundos — pode não ter prazo.
    pub mint: u64,
    pub maxt: u64,
    /// A chave delegada que assinou.
    pub delegada: [u8; 32],
    /// O resumo do pacote recebido: o que a auditoria guarda no lugar dele.
    pub resumo: Resumo,
}

/// Por que uma resposta foi recusada, na ordem em que se confere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recusa {
    /// Sem a moldura, com o comprimento errado, ou grande demais.
    Moldura,
    /// O cabeçalho, uma etiqueta que falta, ou um valor do tamanho errado.
    Estrutura,
    /// O `TYPE` não é o de uma resposta.
    Tipo,
    /// O `NONC` não é o do pedido.
    Nonce,
    /// A versão não é a 1, ou não está no `VERS`.
    Versao,
    /// A chave longa fixada não assinou esta delegação.
    AssinaturaDaDelegacao,
    /// A chave delegada não assinou este `SREP`.
    AssinaturaDaResposta,
    /// Autêntica, mas a árvore não tem o nosso pedido: uma resposta velha,
    /// ou de outro pedido.
    OutroPedido,
    /// Autêntica, mas o carimbo está fora da janela da delegação.
    ForaDaDelegacao,
    /// Autêntica, mas o raio é zero ou passa do teto.
    Raio,
}

impl Recusa {
    /// O nome estável, para a auditoria.
    pub const fn nome(self) -> &'static str {
        match self {
            Recusa::Moldura => "moldura",
            Recusa::Estrutura => "estrutura",
            Recusa::Tipo => "tipo",
            Recusa::Nonce => "nonce",
            Recusa::Versao => "versao",
            Recusa::AssinaturaDaDelegacao => "assinatura_da_delegacao",
            Recusa::AssinaturaDaResposta => "assinatura_da_resposta",
            Recusa::OutroPedido => "outro_pedido",
            Recusa::ForaDaDelegacao => "fora_da_delegacao",
            Recusa::Raio => "raio",
        }
    }

    /// A resposta era do servidor (as duas assinaturas fecharam), e o que
    /// ela afirma não serve.
    pub const fn autentica(self) -> bool {
        matches!(
            self,
            Recusa::OutroPedido | Recusa::ForaDaDelegacao | Recusa::Raio
        )
    }
}

/// Um valor de tamanho fixo, ou a recusa por estrutura.
fn fixo<const N: usize>(mensagem: &Mensagem, etiqueta: Etiqueta) -> Result<[u8; N], Recusa> {
    let valor = mensagem.valor(etiqueta).ok_or(Recusa::Estrutura)?;
    valor.try_into().map_err(|_| Recusa::Estrutura)
}

fn aninhada<'a>(
    mensagem: &Mensagem<'a>,
    etiqueta: Etiqueta,
) -> Result<(&'a [u8], Mensagem<'a>), Recusa> {
    let bytes = mensagem.valor(etiqueta).ok_or(Recusa::Estrutura)?;
    let lida = Mensagem::ler(bytes).map_err(|_| Recusa::Estrutura)?;
    Ok((bytes, lida))
}

/// A lista de `VERS`: de 1 a [`MAIS_VERSOES`] versões, crescentes. Devolve
/// se ela contém a versão 1.
fn versoes_contem_a_nossa(vers: &[u8]) -> Result<bool, Recusa> {
    if vers.is_empty() || !vers.len().is_multiple_of(4) || vers.len() / 4 > MAIS_VERSOES {
        return Err(Recusa::Estrutura);
    }
    let mut anterior: Option<u32> = None;
    let mut contem = false;
    for v in vers.as_chunks::<4>().0 {
        let versao = u32::from_le_bytes(*v);
        if anterior.is_some_and(|a| versao <= a) {
            return Err(Recusa::Estrutura);
        }
        anterior = Some(versao);
        contem |= versao == VERSAO;
    }
    Ok(contem)
}

/// O contexto e o conteúdo assinados, conferidos pela chave — a estrita.
fn assinado(chave: &[u8; 32], contexto: &[u8], conteudo: &[u8], assinatura: &[u8; 64]) -> bool {
    let Ok(chave) = VerifyingKey::from_bytes(chave) else {
        return false;
    };
    if chave.is_weak() {
        return false;
    }
    let mut mensagem = [0u8; CONTEXTO_DE_DELEGACAO.len() + MAIOR_PACOTE];
    let n = contexto.len() + conteudo.len();
    if n > mensagem.len() {
        return false;
    }
    mensagem[..contexto.len()].copy_from_slice(contexto);
    mensagem[contexto.len()..n].copy_from_slice(conteudo);
    chave
        .verify_strict(&mensagem[..n], &Signature::from_bytes(assinatura))
        .is_ok()
}

/// Confere a resposta, como chegou, contra o que se espera dela.
pub fn conferir(pacote: &[u8], esperado: &Esperado) -> Result<Prova, Recusa> {
    // A forma.
    let corpo = moldura::mensagem(pacote).map_err(|_| Recusa::Moldura)?;
    let topo = Mensagem::ler(corpo).map_err(|_| Recusa::Estrutura)?;
    let sig: [u8; 64] = fixo(&topo, SIG)?;
    let nonc: [u8; 32] = fixo(&topo, NONC)?;
    let tipo = u32::from_le_bytes(fixo(&topo, TYPE)?);
    let indx = u32::from_le_bytes(fixo(&topo, INDX)?);
    let caminho = topo.valor(PATH).ok_or(Recusa::Estrutura)?;
    if !caminho.len().is_multiple_of(32) || caminho.len() / 32 > MAIOR_CAMINHO {
        return Err(Recusa::Estrutura);
    }
    let (srep_bytes, srep) = aninhada(&topo, SREP)?;
    let ver = u32::from_le_bytes(fixo(&srep, VER)?);
    let radi = u32::from_le_bytes(fixo(&srep, RADI)?);
    let midp = u64::from_le_bytes(fixo(&srep, MIDP)?);
    let root: [u8; 32] = fixo(&srep, ROOT)?;
    let vers_contem = versoes_contem_a_nossa(srep.valor(VERS).ok_or(Recusa::Estrutura)?)?;
    let (_, cert) = aninhada(&topo, CERT)?;
    let sig_dele: [u8; 64] = fixo(&cert, SIG)?;
    let (dele_bytes, dele) = aninhada(&cert, DELE)?;
    let pubk: [u8; 32] = fixo(&dele, PUBK)?;
    let mint = u64::from_le_bytes(fixo(&dele, MINT)?);
    let maxt = u64::from_le_bytes(fixo(&dele, MAXT)?);

    if tipo != TIPO_RESPOSTA {
        return Err(Recusa::Tipo);
    }
    if nonc != *esperado.nonce {
        return Err(Recusa::Nonce);
    }
    if ver != VERSAO || !vers_contem {
        return Err(Recusa::Versao);
    }

    // As assinaturas, sobre os bytes como chegaram.
    if !assinado(
        esperado.chave_longa,
        CONTEXTO_DE_DELEGACAO,
        dele_bytes,
        &sig_dele,
    ) {
        return Err(Recusa::AssinaturaDaDelegacao);
    }
    if !assinado(&pubk, CONTEXTO_DE_RESPOSTA, srep_bytes, &sig) {
        return Err(Recusa::AssinaturaDaResposta);
    }

    // O que a resposta, autêntica, afirma.
    if merkle::raiz(*esperado.folha, caminho, indx) != Some(root) {
        return Err(Recusa::OutroPedido);
    }
    if midp < mint || midp > maxt {
        return Err(Recusa::ForaDaDelegacao);
    }
    if radi == 0 || radi > esperado.teto_do_raio {
        return Err(Recusa::Raio);
    }
    Ok(Prova {
        midp,
        radi,
        mint,
        maxt,
        delegada: pubk,
        resumo: merkle::h(&[pacote]),
    })
}

#[cfg(test)]
mod testes;
