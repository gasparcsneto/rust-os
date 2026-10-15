//! O pedido da versão 1.
//!
//! **Reproduzido:** 1024 bytes contando a moldura; `VER` com a lista de
//! versões oferecidas, `NONC` de 32 bytes, `TYPE` = 0, e `ZZZZ` com zeros
//! até completar. O pedido sem `SRV` do vetor da RFC 10049 tem exatamente
//! essas quatro etiquetas, e 940 bytes de `ZZZZ`.
//!
//! **Referência:** `SRV` = H(0xff ‖ a chave pública longa da fonte), e o
//! servidor ignora um pedido cujo `SRV` não é de uma chave dele (RFC 5.1.4 e
//! 5.2). Um pedido "deve" ter `SRV`; este sempre tem, porque a chave de cada
//! fonte é fixada na imagem.
//!
//! **Pendente:** a fórmula do `SRV` — nenhum vetor com a chave conhecida a
//! conferiu. Se ela estiver errada, o servidor ignora o pedido, e a rodada
//! fica sem resposta daquela fonte; nada é aceito por isso.
//!
//! Só a versão 1 é oferecida: nem `0x8000000c` (os rascunhos) nem `0` (o
//! legado do Google).
//!
//! O pedido sai inteiro daqui, com a [`folha`](Pedido::folha) que o kernel
//! guarda junto do id. Quem o transporta não pode mudar um byte: a folha é
//! do pacote inteiro, e uma resposta a um pedido alterado não fecha a
//! árvore.

use crate::mensagem::{NONC, SRV, TYPE, VER, ZZZZ};
use crate::merkle::{self, Resumo};
use crate::moldura::{self, CABECALHO};

/// A única versão que este lado fala: a da RFC 10049.
pub const VERSAO: u32 = 1;

/// O tamanho do pedido, com a moldura: o mínimo da RFC para o UDP.
pub const TAMANHO: usize = 1024;

/// A porta atribuída ao Roughtime pela IANA (referência; o registro de
/// fontes diz a porta de cada uma).
pub const PORTA_IANA: u16 = 5319;

/// Cinco etiquetas: oito bytes de cabeçalho cada.
const CABECALHO_DA_MENSAGEM: usize = 8 * 5;

/// `VER` (uma versão), `SRV`, `NONC` e `TYPE`.
const VALORES: usize = 4 + 32 + 32 + 4;

/// O que falta para os 1024 bytes: o `ZZZZ`.
const PREENCHIMENTO: usize = TAMANHO - CABECALHO - CABECALHO_DA_MENSAGEM - VALORES;

/// Um pedido pronto para mandar, e a folha dele.
#[derive(Clone)]
pub struct Pedido {
    bytes: [u8; TAMANHO],
    folha: Resumo,
    nonce: [u8; 32],
}

impl Pedido {
    /// O pedido da versão 1 com este nonce, para a fonte desta chave longa.
    ///
    /// O desenho é fixo: `VER`, `SRV`, `NONC`, `TYPE` e `ZZZZ`, nessa ordem
    /// (a das chaves little-endian), com os deslocamentos 4, 36, 68 e 72.
    pub fn novo(nonce: &[u8; 32], chave_longa: &[u8; 32]) -> Pedido {
        let mut bytes = [0u8; TAMANHO];
        moldura::escrever(&mut bytes, (TAMANHO - CABECALHO) as u32);
        let mut p = CABECALHO;
        let mut por = |dados: &[u8]| {
            bytes[p..p + dados.len()].copy_from_slice(dados);
            p += dados.len();
        };
        por(&5u32.to_le_bytes());
        for deslocamento in [4u32, 36, 68, 72] {
            por(&deslocamento.to_le_bytes());
        }
        for etiqueta in [VER, SRV, NONC, TYPE, ZZZZ] {
            por(&etiqueta);
        }
        por(&VERSAO.to_le_bytes());
        por(&srv(chave_longa));
        por(nonce);
        por(&0u32.to_le_bytes());
        // O `ZZZZ` já é zero: o arranjo começou zerado.
        debug_assert_eq!(p + PREENCHIMENTO, TAMANHO);
        let folha = merkle::folha(&bytes);
        Pedido {
            bytes,
            folha,
            nonce: *nonce,
        }
    }

    /// Os bytes a mandar, inteiros.
    pub fn bytes(&self) -> &[u8; TAMANHO] {
        &self.bytes
    }

    /// A folha deste pedido na árvore de uma resposta.
    pub fn folha(&self) -> &Resumo {
        &self.folha
    }

    /// O nonce deste pedido.
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
}

/// O compromisso com a chave longa da fonte: H(0xff ‖ chave).
pub fn srv(chave_longa: &[u8; 32]) -> Resumo {
    merkle::h(&[&[0xff], chave_longa])
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::mensagem::Mensagem;

    const CHAVE: [u8; 32] = [0x51; 32];
    const NONCE: [u8; 32] = [0x6e; 32];

    #[test]
    fn mil_e_vinte_e_quatro_bytes_com_a_moldura() {
        let p = Pedido::novo(&NONCE, &CHAVE);
        assert_eq!(p.bytes().len(), 1024);
        assert_eq!(PREENCHIMENTO, 900);
        assert_eq!(moldura::mensagem(p.bytes()).unwrap().len(), 1012);
    }

    #[test]
    fn as_cinco_etiquetas_em_ordem_e_os_valores() {
        let p = Pedido::novo(&NONCE, &CHAVE);
        let m = Mensagem::ler(moldura::mensagem(p.bytes()).unwrap()).unwrap();
        assert_eq!(m.quantas(), 5);
        let ordem: std::vec::Vec<_> = (0..5).map(|i| m.etiqueta(i)).collect();
        assert_eq!(ordem, [VER, SRV, NONC, TYPE, ZZZZ]);
        assert_eq!(m.valor(VER), Some(&1u32.to_le_bytes()[..]), "só a versão 1");
        assert_eq!(m.valor(SRV), Some(&srv(&CHAVE)[..]));
        assert_eq!(m.valor(NONC), Some(&NONCE[..]));
        assert_eq!(m.valor(TYPE), Some(&0u32.to_le_bytes()[..]));
        let zzzz = m.valor(ZZZZ).unwrap();
        assert_eq!(zzzz.len(), 900);
        assert!(zzzz.iter().all(|&b| b == 0), "o preenchimento é só zero");
    }

    #[test]
    fn a_folha_e_do_pacote_inteiro() {
        let p = Pedido::novo(&NONCE, &CHAVE);
        assert_eq!(*p.folha(), merkle::folha(p.bytes()));
        assert_eq!(*p.nonce(), NONCE);
        // Outra chave, o mesmo nonce: outro pacote, outra folha.
        let q = Pedido::novo(&NONCE, &[0x52; 32]);
        assert_ne!(p.folha(), q.folha());
    }

    #[test]
    fn srv_e_h_de_0xff_e_a_chave() {
        use sha2::{Digest, Sha512};
        let mut contexto = Sha512::new();
        contexto.update([0xffu8]);
        contexto.update(CHAVE);
        assert_eq!(srv(&CHAVE)[..], contexto.finalize()[..32]);
    }

    #[test]
    fn o_vetor_da_rfc_tem_o_mesmo_desenho_sem_srv() {
        // O pedido do vetor externo: VER, NONC, TYPE e ZZZZ, 1024 bytes.
        let externo = include_bytes!("../testdata/rfc10049-pedido.104172a3");
        assert_eq!(externo.len(), TAMANHO);
        let m = Mensagem::ler(moldura::mensagem(externo).unwrap()).unwrap();
        let ordem: std::vec::Vec<_> = (0..m.quantas()).map(|i| m.etiqueta(i)).collect();
        assert_eq!(ordem, [VER, NONC, TYPE, ZZZZ]);
        assert_eq!(m.valor(VER), Some(&1u32.to_le_bytes()[..]));
        assert_eq!(m.valor(TYPE), Some(&0u32.to_le_bytes()[..]));
        assert_eq!(m.valor(ZZZZ).unwrap().len(), 940);
    }
}
