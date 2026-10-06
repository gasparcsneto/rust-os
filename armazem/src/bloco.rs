//! Os blocos de conteúdo: como um pedaço de arquivo vai cifrado para a
//! área de dados do volume.
//!
//! # O formato
//!
//! Um bloco ocupa [`TAM_BLOCO`] bytes no disco: [`CARGA`] bytes de texto
//! cifrado e a etiqueta do Poly1305. A carga é o pedaço do arquivo, com
//! zeros depois do fim no último bloco — o tamanho do arquivo está nos
//! metadados, e é ele que diz até onde ler.
//!
//! A cifra é o XChaCha20-Poly1305 do journal, com uma chave própria do
//! armazém. O nonce é o `id` da escrita que fez o bloco — dezesseis bytes
//! sorteados por escrita — seguido do índice lógico do bloco no arquivo:
//! cada par `(id, índice)` cifra um bloco só, uma vez. Os dados associados
//! são o identificador do volume: um bloco não abre noutro volume.
//!
//! # O que isso garante
//!
//! Que o conteúdo está cifrado no disco, e que ninguém troca um bloco por
//! outro sem a leitura perceber: um bloco de outro arquivo, de outra
//! posição do mesmo arquivo, de uma versão anterior ou de outro volume tem
//! outro nonce ou outros dados associados, e não abre. O que liga o arquivo
//! ao `id` e ao bloco do disco são os metadados, que o journal autentica e
//! que a âncora do TPM protege de voltar no tempo.

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

/// O tamanho de um bloco no disco: oito setores.
pub const TAM_BLOCO: usize = 4096;
/// A etiqueta do Poly1305.
pub const ETIQUETA: usize = 16;
/// Quantos bytes do arquivo um bloco leva.
pub const CARGA: usize = TAM_BLOCO - ETIQUETA;
/// Quantos setores um bloco ocupa.
pub const SETORES_POR_BLOCO: u64 = (TAM_BLOCO / 512) as u64;

const ROTULO: &[u8; 16] = b"duke armazem v1\0";

fn nonce(id: &[u8; 16], indice: u64) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..16].copy_from_slice(id);
    n[16..].copy_from_slice(&indice.to_le_bytes());
    n
}

fn associados(volume: &[u8; 16]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[..16].copy_from_slice(ROTULO);
    a[16..].copy_from_slice(volume);
    a
}

/// Cifra `claro` — até [`CARGA`] bytes — no bloco `destino`: o pedaço
/// `indice` do arquivo, na escrita `id`, do volume `volume`.
pub fn selar(
    chave: &[u8; 32],
    volume: &[u8; 16],
    id: &[u8; 16],
    indice: u64,
    claro: &[u8],
    destino: &mut [u8; TAM_BLOCO],
) -> Result<(), &'static str> {
    if claro.len() > CARGA {
        return Err("pedaco maior que a carga de um bloco");
    }
    destino[..claro.len()].copy_from_slice(claro);
    destino[claro.len()..CARGA].fill(0);
    let aead = XChaCha20Poly1305::new(&(*chave).into());
    let etiqueta = aead
        .encrypt_inout_detached(
            &nonce(id, indice).into(),
            &associados(volume),
            (&mut destino[..CARGA]).into(),
        )
        .map_err(|_| "a cifra recusou o bloco")?;
    destino[CARGA..].copy_from_slice(&etiqueta);
    Ok(())
}

/// Abre o bloco `bloco` no lugar: devolve a carga, em claro, se ele é o
/// pedaço `indice` da escrita `id` deste volume — e nada, se não é.
pub fn abrir<'b>(
    chave: &[u8; 32],
    volume: &[u8; 16],
    id: &[u8; 16],
    indice: u64,
    bloco: &'b mut [u8; TAM_BLOCO],
) -> Result<&'b [u8], &'static str> {
    let etiqueta: [u8; ETIQUETA] = bloco[CARGA..]
        .try_into()
        .map_err(|_| "bloco sem etiqueta")?;
    let aead = XChaCha20Poly1305::new(&(*chave).into());
    aead.decrypt_inout_detached(
        &nonce(id, indice).into(),
        &associados(volume),
        (&mut bloco[..CARGA]).into(),
        &etiqueta.into(),
    )
    .map_err(|_| "o bloco nao abre: nao e este pedaco deste arquivo")?;
    Ok(&bloco[..CARGA])
}
