//! O cabeçalho de um slot, e onde cada parte da imagem mora nele.
//!
//! # O slot
//!
//! Uma partição crua, sem sistema de arquivos — o iniciador a lê por
//! setores, e o kernel a escreve por setores, sem um sistema de arquivos no
//! meio que precisasse ser escrito no boot:
//!
//! ```text
//!       0  cabeçalho (4 KiB)
//!    4096  kernel ELF, sem as seções de depuração
//!       …  pacote, alinhado a 4 KiB
//! ```
//!
//! # O cabeçalho
//!
//! ```text
//!    0  "DUKESLT1"           a magia
//!    8  versão     u16 LE    deste formato — hoje 1
//!   10  reservado  u16       zero
//!   12  tamanho    u32 LE    do manifesto
//!   16  assinatura 64 bytes  Ed25519 sobre o manifesto — ver `manifesto`
//!   80  chave      32 bytes  a pública que assinou
//!  112  reservado  16 bytes  zero
//!  128  manifesto  `tamanho` bytes
//!       zeros até 4096
//! ```
//!
//! Tudo o que não é campo é zero, e o leitor confere: um cabeçalho tem uma
//! escrita só, como o manifesto.

use crate::manifesto::{MAIOR_MANIFESTO, Manifesto, TAM_ASSINATURA, TAM_CHAVE};

/// O tamanho do cabeçalho.
pub const TAM_CABECALHO: usize = 4096;

/// A magia.
pub const MAGIA: [u8; 8] = *b"DUKESLT1";

/// A versão do formato do cabeçalho.
pub const VERSAO: u16 = 1;

/// Onde o manifesto começa.
const EM_MANIFESTO: usize = 128;

/// Onde o kernel começa, em bytes desde o começo do slot.
pub const KERNEL_EM: u64 = TAM_CABECALHO as u64;

/// O alinhamento do pacote.
const ALINHAMENTO: u64 = 4096;

/// Um cabeçalho lido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cabecalho<'a> {
    pub manifesto: &'a [u8],
    pub assinatura: [u8; TAM_ASSINATURA],
    pub chave: [u8; TAM_CHAVE],
}

/// Lê um cabeçalho dos primeiros [`TAM_CABECALHO`] bytes de `bloco`.
pub fn ler(bloco: &[u8]) -> Result<Cabecalho<'_>, &'static str> {
    let b = bloco
        .get(..TAM_CABECALHO)
        .ok_or("o cabecalho do slot esta incompleto")?;
    if b[..8] != MAGIA {
        return Err("o slot nao tem imagem");
    }
    if u16::from_le_bytes([b[8], b[9]]) != VERSAO {
        return Err("o cabecalho do slot e de outra versao");
    }
    if b[10..12] != [0, 0] || b[112..128].iter().any(|&x| x != 0) {
        return Err("o cabecalho do slot tem reservado sujo");
    }
    let tamanho = u32::from_le_bytes([b[12], b[13], b[14], b[15]]) as usize;
    if tamanho == 0 || tamanho > MAIOR_MANIFESTO {
        return Err("o manifesto do slot tem tamanho implausivel");
    }
    let fim = EM_MANIFESTO + tamanho;
    if b[fim..].iter().any(|&x| x != 0) {
        return Err("o cabecalho do slot tem bytes depois do manifesto");
    }
    let mut assinatura = [0u8; TAM_ASSINATURA];
    assinatura.copy_from_slice(&b[16..80]);
    let mut chave = [0u8; TAM_CHAVE];
    chave.copy_from_slice(&b[80..112]);
    Ok(Cabecalho {
        manifesto: &b[EM_MANIFESTO..fim],
        assinatura,
        chave,
    })
}

/// Monta um cabeçalho. `None` para um manifesto vazio ou grande demais.
pub fn montar(
    manifesto: &[u8],
    assinatura: &[u8; TAM_ASSINATURA],
    chave: &[u8; TAM_CHAVE],
) -> Option<[u8; TAM_CABECALHO]> {
    if manifesto.is_empty() || manifesto.len() > MAIOR_MANIFESTO {
        return None;
    }
    let mut b = [0u8; TAM_CABECALHO];
    b[..8].copy_from_slice(&MAGIA);
    b[8..10].copy_from_slice(&VERSAO.to_le_bytes());
    b[12..16].copy_from_slice(&(manifesto.len() as u32).to_le_bytes());
    b[16..80].copy_from_slice(assinatura);
    b[80..112].copy_from_slice(chave);
    b[EM_MANIFESTO..EM_MANIFESTO + manifesto.len()].copy_from_slice(manifesto);
    Some(b)
}

/// Onde o pacote começa, para um kernel de `kernel` bytes.
pub const fn pacote_em(kernel: u64) -> u64 {
    (KERNEL_EM + kernel).div_ceil(ALINHAMENTO) * ALINHAMENTO
}

/// Quantos bytes a imagem de `m` ocupa no slot, do cabeçalho ao fim do
/// pacote, arredondados ao setor. `None` se a conta transborda.
pub fn tamanho_da_imagem(m: &Manifesto) -> Option<u64> {
    let pacote = KERNEL_EM
        .checked_add(m.kernel.tamanho)?
        .checked_next_multiple_of(ALINHAMENTO)?;
    let fim = pacote.checked_add(m.pacote.tamanho)?;
    fim.checked_next_multiple_of(crate::TAM_SETOR as u64)
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn ida_e_volta() {
        let assinatura = [3u8; 64];
        let chave = [4u8; 32];
        let b = montar(b"formato 1\n", &assinatura, &chave).unwrap();
        let c = ler(&b).unwrap();
        assert_eq!(c.manifesto, b"formato 1\n");
        assert_eq!((c.assinatura, c.chave), (assinatura, chave));
    }

    #[test]
    fn recusa_o_que_nao_e_cabecalho() {
        let b = montar(b"formato 1\n", &[3; 64], &[4; 32]).unwrap();
        let mut ruins = std::vec::Vec::new();
        let mut m = b;
        m[0] ^= 1;
        ruins.push(m);
        // Outra versão do cabeçalho é outro formato de assinatura — a 1 é
        // Ed25519 com o rótulo do manifesto, e só ela: um algoritmo
        // inesperado chega como uma versão que este leitor não conhece.
        let mut v = b;
        v[8] = 2;
        ruins.push(v);
        let mut r = b;
        r[120] = 1;
        ruins.push(r);
        let mut depois = b;
        depois[4000] = 1;
        ruins.push(depois);
        let mut zero = b;
        zero[12..16].copy_from_slice(&0u32.to_le_bytes());
        ruins.push(zero);
        let mut grande = b;
        grande[12..16].copy_from_slice(&4000u32.to_le_bytes());
        ruins.push(grande);
        for ruim in &ruins {
            assert!(ler(ruim).is_err());
        }
        assert!(ler(&b[..100]).is_err());
        assert!(montar(b"", &[0; 64], &[0; 32]).is_none());
        assert!(montar(&[b'x'; 600], &[0; 64], &[0; 32]).is_none());
    }

    #[test]
    fn o_pacote_alinha_depois_do_kernel() {
        assert_eq!(pacote_em(1), 8192);
        assert_eq!(pacote_em(4096), 8192);
        assert_eq!(pacote_em(4097), 12288);
    }

    extern crate std;
}
