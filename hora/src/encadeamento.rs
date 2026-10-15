//! O nonce encadeado.
//!
//! Numa rodada, as fontes são consultadas uma depois da outra, e o nonce de
//! cada pedido deriva da resposta anterior: uma resposta posterior prova que
//! foi feita depois da anterior, e duas fontes que se contradizem deixam
//! evidência ordenada.
//!
//! **Referência:** nonce = H(o pacote da resposta anterior, inteiro e como
//! chegou, com a moldura ‖ 32 bytes aleatórios), com H a dos 32 primeiros
//! bytes do SHA-512 (RFC 8.2). O primeiro nonce de uma rodada é aleatório.
//!
//! **Pendente:** nenhum vetor confere esta fórmula, e a exportação da prova
//! (o relatório de mau comportamento, RFC 8.4.1) não é deste incremento.
//! Para ela, quem chama guarda os bytes aleatórios e as respostas da
//! rodada; aqui fica só a conta.

use crate::merkle;

/// O nonce do próximo pedido da rodada.
pub fn nonce(resposta_anterior: &[u8], aleatorio: &[u8; 32]) -> [u8; 32] {
    merkle::h(&[resposta_anterior, aleatorio])
}

#[cfg(test)]
mod testes {
    use super::*;
    use sha2::{Digest, Sha512};

    #[test]
    fn e_o_comeco_do_sha512_da_resposta_e_do_aleatorio() {
        let resposta = b"ROUGHTIM\x04\0\0\0abcd";
        let aleatorio = [9u8; 32];
        let mut contexto = Sha512::new();
        contexto.update(resposta);
        contexto.update(aleatorio);
        assert_eq!(nonce(resposta, &aleatorio)[..], contexto.finalize()[..32]);
    }

    #[test]
    fn depende_do_pacote_inteiro_e_do_aleatorio() {
        let resposta = b"ROUGHTIM\x04\0\0\0abcd";
        let base = nonce(resposta, &[1; 32]);
        assert_ne!(
            base,
            nonce(&resposta[12..], &[1; 32]),
            "sem a moldura é outro"
        );
        assert_ne!(
            base,
            nonce(resposta, &[2; 32]),
            "outro aleatório, outro nonce"
        );
        let mut outra = *resposta;
        outra[15] = b'e';
        assert_ne!(base, nonce(&outra, &[1; 32]));
    }
}
