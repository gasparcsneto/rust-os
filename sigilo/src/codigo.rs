//! O selo do código: a assinatura de um editor sobre um executável.
//!
//! # Para que existe
//!
//! O código da imagem roda porque é da imagem: veio com o kernel, com a
//! política e com as chaves, e quem tem a imagem tem tudo isso. O código
//! que chega depois — pela rede, gravado no armazém — não tem essa
//! procedência, e qualquer um que escreva no armazém o teria posto lá. O
//! selo é o que a dá: um **editor** assina o executável com a chave privada
//! dele, e o Duke confere com a pública, que está no registro de editores
//! da imagem. Em quais editores cada papel confia é da política — ver
//! `politica::arquivo` —; aqui é só a conta.
//!
//! # O formato
//!
//! O selo vai **no fim** do arquivo, depois do executável, sem tocar nele —
//! o arranjo das assinaturas de módulo do Linux (`~Module signature
//! appended~`): o executável continua o mesmo ELF, e o selo se separa dele
//! pelo tamanho fixo e pela [`MARCA`] no fim.
//!
//! ```text
//! [ executável ][ assinatura: 64 ][ chave pública do editor: 32 ][ MARCA: 16 ]
//! ```
//!
//! Sem a marca no fim, o arquivo não tem selo — [`Falha::SemSelo`]. Com a
//! marca, ele **diz** que tem, e o resto tem de conferir: um selo cortado,
//! uma chave que não é ponto da curva, uma assinatura que não fecha, um
//! byte do executável trocado depois de selado — todos
//! [`Falha::NaoConfere`]. Um byte a mais depois da marca a tira do fim: é
//! um arquivo sem selo, e não um selo estranho.
//!
//! # O que se assina
//!
//! O rótulo deste protocolo e o resumo BLAKE2s-256 do executável — o mesmo
//! resumo com que a auditoria nomeia o programa (ver
//! `politica::manifesto::resumo_da_imagem`). O que o editor assina é,
//! então, exatamente o que a auditoria cita; e quem confere faz uma passada
//! de BLAKE2s, que já faria para a identidade, e uma conferência Ed25519
//! sobre algumas dezenas de bytes.
//!
//! O rótulo separa esta assinatura de qualquer outra feita com a mesma
//! chave: um selo não vale como assinatura de quórum, nem uma assinatura
//! crua do resumo vale como selo.
//!
//! A conferência é a estrita (`verify_strict`), como a do quórum: recusa a
//! chave pública de ordem pequena e a assinatura maleável, para que um selo
//! válido não tenha uma segunda grafia que também valha.
//!
//! # O que o selo não diz
//!
//! Quando o código foi selado, nem se é a versão mais nova: um selo antigo
//! do mesmo editor continua conferindo. Ele prova **quem** selou **estes**
//! bytes. Se o papel de quem lança confia nesse editor, e o que o processo
//! pode depois, são da política e do manifesto.

use alloc::vec::Vec;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::TAM_CHAVE;

/// A marca no fim de um arquivo selado.
pub const MARCA: [u8; 16] = *b"~Duke selo v1~\r\n";

/// O tamanho de uma assinatura Ed25519.
pub const TAM_ASSINATURA: usize = 64;

/// O tamanho do selo inteiro: a assinatura, a chave do editor e a marca.
pub const TAM_SELO: usize = TAM_ASSINATURA + TAM_CHAVE + MARCA.len();

/// O rótulo que vai na frente do resumo assinado.
const ROTULO: &[u8] = b"Duke codigo: selo ed25519 v1";

/// Por que um arquivo não tem procedência.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falha {
    /// O arquivo não termina na marca: não traz selo nenhum.
    SemSelo,
    /// O arquivo diz que é selado, e o selo não confere com ele: cortado,
    /// com uma chave que não é ponto válido, ou o executável — ou a
    /// assinatura — mudou depois de selado.
    NaoConfere,
}

impl Falha {
    /// Uma frase curta, para o log, a auditoria e a resposta.
    pub const fn motivo(self) -> &'static str {
        match self {
            Falha::SemSelo => "o codigo nao tem selo",
            Falha::NaoConfere => "o selo nao confere com o codigo",
        }
    }
}

/// Um selo que conferiu: o executável, sem o selo, quem o selou e o resumo
/// do executável.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Conferido<'a> {
    /// Os bytes que o editor selou — e os únicos que se carregam.
    pub codigo: &'a [u8],
    /// A chave pública Ed25519 do editor.
    pub editor: [u8; TAM_CHAVE],
    /// O resumo BLAKE2s-256 de [`Conferido::codigo`].
    pub resumo: [u8; 32],
}

/// O resumo BLAKE2s-256 de um executável.
pub fn resumo(codigo: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    let mut h = blake2::Blake2s256::new();
    h.update(codigo);
    h.finalize().into()
}

/// A mensagem que o editor assina: o rótulo e o resumo.
fn mensagem(resumo: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(ROTULO.len() + resumo.len());
    m.extend_from_slice(ROTULO);
    m.extend_from_slice(resumo);
    m
}

/// A chave pública de um editor, a partir da privada: a que vai para o
/// registro de editores.
pub fn publica_do_editor(privada: &[u8; TAM_CHAVE]) -> [u8; TAM_CHAVE] {
    SigningKey::from_bytes(privada).verifying_key().to_bytes()
}

/// Se `chave` serve de chave pública de editor: um ponto da curva que não é
/// de ordem pequena. O registro recusa a que não serve — com ela, nenhum
/// selo conferiria, e o editor existiria só no nome.
pub fn chave_valida(chave: &[u8; TAM_CHAVE]) -> bool {
    VerifyingKey::from_bytes(chave).is_ok_and(|k| !k.is_weak())
}

/// Sela `codigo` com a chave privada de um editor: o executável, seguido do
/// selo. Do lado de quem publica — o `xtask`, e a suíte —, nunca do Duke,
/// que não tem chave de editor nenhuma.
pub fn selar(codigo: &[u8], privada: &[u8; TAM_CHAVE]) -> Vec<u8> {
    let chave = SigningKey::from_bytes(privada);
    let assinatura = chave.sign(&mensagem(&resumo(codigo))).to_bytes();
    let mut selado = Vec::with_capacity(codigo.len() + TAM_SELO);
    selado.extend_from_slice(codigo);
    selado.extend_from_slice(&assinatura);
    selado.extend_from_slice(&chave.verifying_key().to_bytes());
    selado.extend_from_slice(&MARCA);
    selado
}

/// Separa o executável do selo, e confere o selo.
///
/// Só a conta do selo: se o editor está no registro, e se o papel de quem
/// lança confia nele, quem chama decide depois.
pub fn conferir(arquivo: &[u8]) -> Result<Conferido<'_>, Falha> {
    if !arquivo.ends_with(&MARCA) {
        return Err(Falha::SemSelo);
    }
    // A marca está lá, e o selo tem de estar inteiro antes dela: um
    // arquivo que termina na marca e não tem espaço para o resto é um selo
    // cortado, e não um arquivo sem selo.
    let Some(inicio) = arquivo.len().checked_sub(TAM_SELO) else {
        return Err(Falha::NaoConfere);
    };
    let (codigo, selo) = arquivo.split_at(inicio);
    let mut assinatura = [0u8; TAM_ASSINATURA];
    assinatura.copy_from_slice(&selo[..TAM_ASSINATURA]);
    let mut editor = [0u8; TAM_CHAVE];
    editor.copy_from_slice(&selo[TAM_ASSINATURA..TAM_ASSINATURA + TAM_CHAVE]);
    let chave = VerifyingKey::from_bytes(&editor).map_err(|_| Falha::NaoConfere)?;
    let resumo = resumo(codigo);
    chave
        .verify_strict(&mensagem(&resumo), &Signature::from_bytes(&assinatura))
        .map_err(|_| Falha::NaoConfere)?;
    Ok(Conferido {
        codigo,
        editor,
        resumo,
    })
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::de_hex;

    /// As chaves privadas de dois editores.
    const A: [u8; 32] = [0x31; 32];
    const B: [u8; 32] = [0x32; 32];

    /// Um "executável": os bytes não importam para o selo.
    fn codigo() -> Vec<u8> {
        (0..3000u32).map(|i| (i * 7 + 3) as u8).collect()
    }

    #[test]
    fn ida_e_volta() {
        let c = codigo();
        let selado = selar(&c, &A);
        assert_eq!(selado.len(), c.len() + TAM_SELO);
        assert!(selado.starts_with(&c));
        assert!(selado.ends_with(&MARCA));
        let conferido = conferir(&selado).expect("o selo de A confere");
        assert_eq!(conferido.codigo, &c[..]);
        assert_eq!(conferido.editor, publica_do_editor(&A));
        assert_eq!(conferido.resumo, resumo(&c));
        assert!(chave_valida(&conferido.editor));
    }

    /// É Ed25519 de verdade: a pública da RFC 8032, seção 7.1, sai da
    /// privada dela.
    #[test]
    fn a_chave_da_rfc_8032() {
        let privada: [u8; 32] =
            de_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let publica: [u8; 32] =
            de_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
        assert_eq!(publica_do_editor(&privada), publica);
    }

    /// Sem a marca no fim, não há selo — nem no arquivo vazio, nem com a
    /// marca no meio, nem com um byte depois dela.
    #[test]
    fn sem_marca_no_fim_nao_ha_selo() {
        let c = codigo();
        assert_eq!(conferir(&c), Err(Falha::SemSelo));
        assert_eq!(conferir(&[]), Err(Falha::SemSelo));
        let mut no_meio = MARCA.to_vec();
        no_meio.extend_from_slice(&c);
        assert_eq!(conferir(&no_meio), Err(Falha::SemSelo));
        let mut depois = selar(&c, &A);
        depois.push(0);
        assert_eq!(conferir(&depois), Err(Falha::SemSelo));
        // A marca com um byte trocado também não é marca.
        let mut marca = selar(&c, &A);
        let ultimo = marca.len() - 1;
        marca[ultimo] ^= 1;
        assert_eq!(conferir(&marca), Err(Falha::SemSelo));
    }

    /// A marca sem espaço para o selo inteiro é um selo cortado.
    #[test]
    fn o_selo_cortado_nao_confere() {
        assert_eq!(conferir(&MARCA), Err(Falha::NaoConfere));
        let selado = selar(&codigo(), &A);
        let fim = &selado[selado.len() - TAM_SELO + 1..];
        assert!(fim.ends_with(&MARCA));
        assert_eq!(conferir(fim), Err(Falha::NaoConfere));
        // Inteiro, sobre um executável vazio, confere: o selo é do que veio
        // antes dele, mesmo que nada — carregar o vazio é recusa do ELF.
        assert!(conferir(&selar(&[], &A)).is_ok());
    }

    /// Um byte trocado em qualquer parte — o executável, a assinatura, a
    /// chave — derruba o selo.
    #[test]
    fn um_byte_trocado_derruba() {
        let c = codigo();
        let selado = selar(&c, &A);
        let n = c.len();
        let posicoes = [
            0,
            n / 2,
            n - 1,
            n,
            n + 31,
            n + 32,
            n + TAM_ASSINATURA - 1,
            n + TAM_ASSINATURA,
            n + TAM_ASSINATURA + TAM_CHAVE - 1,
        ];
        for p in posicoes {
            let mut mexido = selado.clone();
            mexido[p] ^= 1;
            assert_eq!(conferir(&mexido), Err(Falha::NaoConfere), "byte {p}");
        }
    }

    /// Trocar a chave do selo pela de outro editor, com a assinatura de A,
    /// não confere; selar de novo com B confere — e diz que é de B: quem
    /// decide se B vale é o registro e a política, não o selo.
    #[test]
    fn a_chave_e_a_assinatura_andam_juntas() {
        let c = codigo();
        let mut trocada = selar(&c, &A);
        let n = c.len();
        trocada[n + TAM_ASSINATURA..n + TAM_ASSINATURA + TAM_CHAVE]
            .copy_from_slice(&publica_do_editor(&B));
        assert_eq!(conferir(&trocada), Err(Falha::NaoConfere));
        let de_b = selar(&c, &B);
        assert_eq!(conferir(&de_b).unwrap().editor, publica_do_editor(&B));
        assert_ne!(publica_do_editor(&A), publica_do_editor(&B));
    }

    /// O selo de outro executável não vale para este, mesmo do mesmo
    /// tamanho.
    #[test]
    fn o_selo_de_outro_codigo_nao_vale() {
        let c = codigo();
        let mut outro = c.clone();
        outro[10] ^= 0x80;
        let selo_do_outro = selar(&outro, &A)[outro.len()..].to_vec();
        let mut colado = c.clone();
        colado.extend_from_slice(&selo_do_outro);
        assert_eq!(conferir(&colado), Err(Falha::NaoConfere));
    }

    /// O rótulo separa: a assinatura crua do resumo — sem ele — não é selo.
    #[test]
    fn o_rotulo_separa() {
        let c = codigo();
        let chave = SigningKey::from_bytes(&A);
        let crua = chave.sign(&resumo(&c)).to_bytes();
        let mut forjado = c.clone();
        forjado.extend_from_slice(&crua);
        forjado.extend_from_slice(&publica_do_editor(&A));
        forjado.extend_from_slice(&MARCA);
        assert_eq!(conferir(&forjado), Err(Falha::NaoConfere));
        // Nem a dos bytes do executável inteiro.
        let dos_bytes = chave.sign(&c).to_bytes();
        let n = c.len();
        forjado[n..n + TAM_ASSINATURA].copy_from_slice(&dos_bytes);
        assert_eq!(conferir(&forjado), Err(Falha::NaoConfere));
    }

    /// Sem maleabilidade: o `S` somado à ordem do grupo é a mesma conta
    /// módulo ℓ, e a conferência estrita o recusa.
    #[test]
    fn sem_segunda_grafia() {
        let c = codigo();
        let selado = selar(&c, &A);
        // ℓ = 2^252 + 27742317777372353535851937790883648493, little-endian.
        const ORDEM: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let n = c.len();
        let mut maleavel = selado.clone();
        let mut vai = 0u16;
        for i in 0..32 {
            let soma = u16::from(maleavel[n + 32 + i]) + u16::from(ORDEM[i]) + vai;
            maleavel[n + 32 + i] = soma as u8;
            vai = soma >> 8;
        }
        assert_ne!(maleavel, selado);
        assert_eq!(conferir(&maleavel), Err(Falha::NaoConfere));
    }

    /// Uma chave de ordem pequena — a identidade — não confere nada, nem a
    /// assinatura que "funcionaria" para ela; e não serve de editor.
    #[test]
    fn chave_de_ordem_pequena() {
        let c = codigo();
        let mut identidade = [0u8; 32];
        identidade[0] = 1;
        let mut assinatura = [0u8; 64];
        assinatura[0] = 1;
        let mut forjado = c.clone();
        forjado.extend_from_slice(&assinatura);
        forjado.extend_from_slice(&identidade);
        forjado.extend_from_slice(&MARCA);
        assert_eq!(conferir(&forjado), Err(Falha::NaoConfere));
        assert!(!chave_valida(&identidade));
        assert!(!chave_valida(&[0u8; 32]));
        assert!(chave_valida(&publica_do_editor(&B)));
    }

    /// Um selo por cima de outro: o de fora cobre o executável **e** o selo
    /// de dentro, que para ele são só bytes. O que se carrega é o que o de
    /// fora selou.
    #[test]
    fn selo_sobre_selo() {
        let c = codigo();
        let dentro = selar(&c, &A);
        let fora = selar(&dentro, &B);
        let conferido = conferir(&fora).unwrap();
        assert_eq!(conferido.editor, publica_do_editor(&B));
        assert_eq!(conferido.codigo, &dentro[..]);
    }
}
