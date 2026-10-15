//! A árvore de Merkle da resposta.
//!
//! Um servidor assina uma raiz só para muitos pedidos. O nosso pedido é uma
//! folha da árvore, e o caminho (`PATH`) e o índice (`INDX`) levam dela até
//! a raiz (`ROOT`) que o servidor assinou.
//!
//! **Reproduzido:** H é a dos 32 primeiros bytes do SHA-512, e a folha do
//! pedido é H(0x00 ‖ o pacote inteiro do pedido, com `ROUGHTIM` e o
//! comprimento). Nos dois pares de vetores só ela fecha a raiz: a mensagem
//! sem a moldura não fecha, e o nonce sozinho, que era a folha até o
//! draft-11 e é a do protocolo legado do Google, também não.
//!
//! **Referência:** o nó é H(0x01 ‖ esquerdo ‖ direito), e a subida lê o
//! `INDX` a partir do bit menos significativo: bit 0 quer dizer que o nosso
//! lado é o esquerdo. Sobrando um bit 1 depois do caminho, a prova falha
//! (RFC 5.3.1). O caminho tem no máximo 32 resumos (RFC 5.2.4).
//!
//! **Pendente:** a ordem dos bits do `INDX` com caminho não vazio — nenhum
//! vetor com caminho e o pedido correspondente foi conferido. Uma leitura
//! errada aqui recusaria respostas válidas de quem agrupa pedidos, mas não
//! aceitaria uma folha fora da árvore: o `INDX` e o `PATH` não são
//! assinados, quem responde escolhe o que manda, e só fecha a raiz uma
//! folha que está nela.

use sha2::{Digest, Sha512};

/// Um resumo: os 32 primeiros bytes do SHA-512.
pub type Resumo = [u8; 32];

/// O maior caminho, em resumos.
pub const MAIOR_CAMINHO: usize = 32;

/// H: os 32 primeiros bytes do SHA-512 das partes, uma depois da outra.
pub fn h(partes: &[&[u8]]) -> Resumo {
    let mut contexto = Sha512::new();
    for parte in partes {
        contexto.update(parte);
    }
    let completo = contexto.finalize();
    let mut resumo = [0u8; 32];
    resumo.copy_from_slice(&completo[..32]);
    resumo
}

/// A folha de um pedido: H(0x00 ‖ o pacote inteiro, como foi mandado).
pub fn folha(pacote_do_pedido: &[u8]) -> Resumo {
    h(&[&[0x00], pacote_do_pedido])
}

/// Um nó: H(0x01 ‖ esquerdo ‖ direito).
pub fn no(esquerdo: &Resumo, direito: &Resumo) -> Resumo {
    h(&[&[0x01], esquerdo, direito])
}

/// A raiz a que a folha leva pelo caminho e pelo índice — ou nada, se o
/// caminho não é feito de resumos inteiros, passa do teto, ou se o índice
/// tem bits além do caminho.
pub fn raiz(folha: Resumo, caminho: &[u8], indice: u32) -> Option<Resumo> {
    if !caminho.len().is_multiple_of(32) || caminho.len() / 32 > MAIOR_CAMINHO {
        return None;
    }
    let mut atual = folha;
    let mut resto = indice;
    for irmao in caminho.as_chunks::<32>().0 {
        atual = if resto & 1 == 0 {
            no(&atual, irmao)
        } else {
            no(irmao, &atual)
        };
        resto >>= 1;
    }
    if resto != 0 {
        return None;
    }
    Some(atual)
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::servidor_de_teste::arvore;
    use std::vec::Vec;

    #[test]
    fn h_e_o_comeco_do_sha512() {
        let completo = Sha512::digest(b"abc");
        assert_eq!(h(&[b"abc"]), completo[..32]);
        assert_eq!(
            h(&[b"a", b"", b"bc"]),
            h(&[b"abc"]),
            "as partes se concatenam"
        );
    }

    #[test]
    fn folha_e_no_tem_prefixos_diferentes() {
        let x = [5u8; 32];
        assert_eq!(folha(b"pedido"), h(&[&[0], b"pedido"]));
        assert_eq!(no(&x, &x), h(&[&[1], &x, &x]));
        assert_ne!(folha(&[x, x].concat()), no(&x, &x));
    }

    #[test]
    fn uma_folha_so_e_a_raiz() {
        let f = folha(b"pedido");
        assert_eq!(raiz(f, &[], 0), Some(f));
        assert_eq!(raiz(f, &[], 1), None, "bit além do caminho");
        assert_eq!(raiz(f, &[], 0x8000_0000), None);
    }

    #[test]
    fn todas_as_folhas_de_uma_arvore_fecham() {
        for n in [2usize, 3, 5, 8, 13] {
            let folhas: Vec<Resumo> = (0..n).map(|i| folha(&[i as u8; 7])).collect();
            let (topo, caminhos) = arvore(&folhas);
            for i in 0..n {
                assert_eq!(
                    raiz(folhas[i], &caminhos[i], i as u32),
                    Some(topo),
                    "{n} folhas, a {i}"
                );
                // O índice de outra posição não fecha.
                let outro = (i as u32) ^ 1;
                assert_ne!(raiz(folhas[i], &caminhos[i], outro), Some(topo));
                // Um bit além do caminho falha.
                let profundidade = caminhos[i].len() / 32;
                assert_eq!(
                    raiz(folhas[i], &caminhos[i], i as u32 | (1 << profundidade)),
                    None
                );
            }
        }
    }

    #[test]
    fn a_ordem_do_no_depende_do_bit() {
        let a = folha(b"a");
        let b = folha(b"b");
        assert_eq!(
            raiz(a, &b, 0),
            Some(no(&a, &b)),
            "bit 0: o nosso é o esquerdo"
        );
        assert_eq!(
            raiz(a, &b, 1),
            Some(no(&b, &a)),
            "bit 1: o nosso é o direito"
        );
    }

    #[test]
    fn caminho_torto_ou_grande_demais() {
        let f = folha(b"x");
        assert_eq!(raiz(f, &[0; 31], 0), None);
        assert_eq!(raiz(f, &[0; 33], 0), None);
        assert!(
            raiz(f, &std::vec![0; 32 * MAIOR_CAMINHO], 0).is_some(),
            "32 resumos passam"
        );
        assert_eq!(raiz(f, &std::vec![0; 32 * (MAIOR_CAMINHO + 1)], 0), None);
        assert!(
            raiz(f, &std::vec![0; 32 * MAIOR_CAMINHO], u32::MAX).is_some(),
            "32 bits, 32 níveis"
        );
    }
}
