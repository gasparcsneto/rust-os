//! Os casos de unidade: os bytes que a especificação fixa.
//!
//! O resto — a sessão, o HMAC, a cifra do parâmetro, os códigos de erro —
//! só se confere contra um TPM de verdade, e mora em `tests/swtpm.rs`. Até
//! o 7.6 havia aqui um TPM simulado; com a sessão autenticada, um simulado
//! escrito junto com este pacote seria o pacote concordando consigo mesmo,
//! justamente onde um byte errado não dá erro aqui e sim um TPM que recusa.

use super::*;

#[test]
fn o_startup_e_os_bytes_da_especificacao() {
    // TPM2_Startup(TPM_SU_CLEAR), o comando mais citado da especificação:
    // 80 01 | 00 00 00 0c | 00 00 01 44 | 00 00.
    let mut q = Quadro::novo(SEM_SESSOES, comando::STARTUP);
    q.u16(REINICIO_LIMPO);
    assert_eq!(
        q.fechar(),
        &[0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 0]
    );
}

#[test]
fn o_nome_muda_com_a_primeira_escrita() {
    let antes = nome_do_indice(0x0180_D0E0, atributo::DA_ANCORA);
    let depois = nome_do_indice(0x0180_D0E0, atributo::DA_ANCORA | atributo::ESCRITO);
    assert_eq!(&antes[..2], &[0x00, 0x0B]);
    assert_ne!(antes, depois);
    assert_ne!(antes, nome_do_indice(0x0180_D0E1, atributo::DA_ANCORA));
}
