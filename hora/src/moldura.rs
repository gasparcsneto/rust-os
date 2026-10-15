//! A moldura de um pacote: `ROUGHTIM`, o comprimento e a mensagem.
//!
//! **Reproduzido:** os 8 bytes ASCII `ROUGHTIM`, um `uint32` little-endian
//! com o comprimento da mensagem, e a mensagem. O pedido de 1024 bytes da
//! RFC 10049 declara 1012.
//!
//! **Pendente:** o que fazer com bytes depois do comprimento declarado. A
//! referência os descarta; aqui o pacote tem de ter exatamente 12 bytes mais
//! o comprimento, e um byte a mais é recusa. O teto, [`MAIOR_PACOTE`], é o
//! maior datagrama da pilha do kernel, e não um número da RFC.

/// Os 8 primeiros bytes de todo pacote.
pub const MAGICO: [u8; 8] = *b"ROUGHTIM";

/// O mágico e o comprimento.
pub const CABECALHO: usize = 12;

/// O maior pacote que este lado lê: o maior datagrama UDP sem fragmentação
/// num quadro Ethernet, como a pilha do kernel (`MAIOR_DATAGRAMA`).
pub const MAIOR_PACOTE: usize = 1472;

/// Por que um pacote não tem moldura.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Falha {
    /// Menos que o cabeçalho.
    Curto,
    /// Maior que [`MAIOR_PACOTE`].
    Grande,
    /// Não começa com `ROUGHTIM`.
    Magico,
    /// O comprimento declarado não é o que veio.
    Comprimento,
}

/// A mensagem dentro do pacote.
pub fn mensagem(pacote: &[u8]) -> Result<&[u8], Falha> {
    if pacote.len() > MAIOR_PACOTE {
        return Err(Falha::Grande);
    }
    if pacote.len() < CABECALHO {
        return Err(Falha::Curto);
    }
    if pacote[..8] != MAGICO {
        return Err(Falha::Magico);
    }
    let declarado = u32::from_le_bytes([pacote[8], pacote[9], pacote[10], pacote[11]]);
    if declarado as usize != pacote.len() - CABECALHO {
        return Err(Falha::Comprimento);
    }
    Ok(&pacote[CABECALHO..])
}

/// Escreve a moldura de uma mensagem de `comprimento` bytes no começo de
/// `destino`, que tem de ter ao menos [`CABECALHO`] bytes.
pub fn escrever(destino: &mut [u8], comprimento: u32) {
    destino[..8].copy_from_slice(&MAGICO);
    destino[8..CABECALHO].copy_from_slice(&comprimento.to_le_bytes());
}

#[cfg(test)]
mod testes {
    use super::*;
    use std::vec::Vec;

    fn pacote(mensagem: &[u8]) -> Vec<u8> {
        let mut p = std::vec![0u8; CABECALHO];
        escrever(&mut p, mensagem.len() as u32);
        p.extend_from_slice(mensagem);
        p
    }

    #[test]
    fn a_moldura_certa_devolve_a_mensagem() {
        let p = pacote(&[1, 2, 3, 4]);
        assert_eq!(&p[..8], b"ROUGHTIM");
        assert_eq!(mensagem(&p), Ok(&[1u8, 2, 3, 4][..]));
        assert_eq!(mensagem(&pacote(&[])), Ok(&[][..]));
    }

    #[test]
    fn sem_o_magico() {
        let mut p = pacote(&[0; 8]);
        p[0] = b'r';
        assert_eq!(mensagem(&p), Err(Falha::Magico));
        let mut p = pacote(&[0; 8]);
        p[7] = b'N';
        assert_eq!(mensagem(&p), Err(Falha::Magico));
    }

    #[test]
    fn o_comprimento_tem_de_ser_exato() {
        let mut p = pacote(&[0; 8]);
        p.push(0);
        assert_eq!(mensagem(&p), Err(Falha::Comprimento), "um byte a mais");
        let mut p = pacote(&[0; 8]);
        p.pop();
        assert_eq!(mensagem(&p), Err(Falha::Comprimento), "um byte a menos");
        let mut p = pacote(&[0; 8]);
        p[11] = 0x80;
        assert_eq!(mensagem(&p), Err(Falha::Comprimento), "comprimento enorme");
    }

    #[test]
    fn curto_e_grande() {
        assert_eq!(mensagem(b"ROUGHTIM\0\0\0"), Err(Falha::Curto));
        assert_eq!(mensagem(&[]), Err(Falha::Curto));
        let cabe = pacote(&std::vec![0; MAIOR_PACOTE - CABECALHO]);
        assert!(mensagem(&cabe).is_ok(), "o maior pacote passa");
        let nao_cabe = pacote(&std::vec![0; MAIOR_PACOTE - CABECALHO + 1]);
        assert_eq!(mensagem(&nao_cabe), Err(Falha::Grande));
    }
}
