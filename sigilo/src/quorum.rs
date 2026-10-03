//! O quórum: M de N credenciais de administrador assinam o mesmo pedido.
//!
//! # Para que existe
//!
//! Algumas operações não podem depender de uma credencial só — revogar a
//! credencial de outro administrador é a primeira: uma chave roubada, sozinha,
//! revogaria as dos donos legítimos e ficaria com a máquina. Elas exigem que
//! **M** credenciais distintas, de um grupo de **N**, assinem o mesmo pedido.
//! M e N são da política, por operação; este módulo é só a conta.
//!
//! # O conteúdo, um só para todos
//!
//! Cada credencial assina o **mesmo** conteúdo canônico ([`Conteudo`]): a
//! versão do formato, o número da operação, o nonce e a efêmera do desafio,
//! a sessão, a versão da política em vigor, M e N, o comando, o alvo e o
//! texto exato dos parâmetros. Cada campo de tamanho variável leva o tamanho
//! na frente, e os de tamanho fixo vão no tamanho deles — a codificação é
//! injetiva: dois conteúdos diferentes nunca viram os mesmos bytes.
//!
//! Uma assinatura feita para outro alvo, outros parâmetros, outro desafio,
//! outra sessão, outra versão da política ou outro M e N não confere: os
//! bytes assinados são outros.
//!
//! # A assinatura de cada credencial
//!
//! Ed25519 (RFC 8032): cada credencial assina, com a **chave privada dela**,
//! o rótulo deste protocolo seguido dos bytes canônicos do conteúdo. O Duke
//! confere com a **chave pública** da credencial, que está no registro de
//! administradores — e só com ela: a privada nunca sai de quem assina, e
//! nada que o Duke tem, nem o desafio que ele sorteou, produz uma
//! assinatura. É uma assinatura de verdade: qualquer um com a pública e o
//! conteúdo confere depois, sem o Duke.
//!
//! A conferência é a estrita (`verify_strict`): recusa uma chave pública de
//! ordem pequena e uma assinatura maleável — o `S` fora da faixa, ou um `R`
//! de ordem pequena —, para que uma assinatura válida não tenha uma segunda
//! grafia que também valha.
//!
//! O rótulo separa esta assinatura de qualquer outra feita com a mesma chave:
//! uma assinatura de quórum não vale para outro protocolo, nem o contrário.
//!
//! # Por que não a prova de uma credencial só
//!
//! A prova administrativa comum ([`crate::administracao`]) é um autenticador
//! de verificador designado: X25519 com a efêmera do desafio, HKDF e HMAC.
//! Só o Duke a confere — e por isso mesmo o Duke conseguiria fabricá-la. Para
//! o quórum isso não basta: a revogação de uma credencial tem de ser
//! atribuível às credenciais que a pediram, e verificável fora do Duke.

use alloc::vec::Vec;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::TAM_CHAVE;

/// A versão do formato do conteúdo. Muda se a codificação mudar: um
/// conteúdo de um formato nunca é lido como de outro.
///
/// A 2 trouxe a geração administrativa — ver [`Conteudo::geracao`].
pub const VERSAO_DO_FORMATO: u8 = 2;

/// O tamanho de uma assinatura Ed25519.
pub const TAM_ASSINATURA: usize = 64;

/// O rótulo que vai na frente do conteúdo assinado: separa esta assinatura
/// de qualquer outra feita com a mesma chave.
const ROTULO_DA_ASSINATURA: &[u8] = b"Duke quorum: assinatura ed25519 v1";

/// O que todas as credenciais de um quórum assinam — o mesmo, byte a byte.
#[derive(Clone, Copy, Debug)]
pub struct Conteudo<'a> {
    /// O número do desafio: identifica a operação, uma vez por boot.
    pub operacao: u64,
    /// O nonce do desafio.
    pub nonce: &'a [u8; 32],
    /// A sessão em que o desafio foi pedido e o pedido vai ser feito.
    pub sessao: u8,
    /// A parte pública da efêmera do desafio.
    pub efemera: &'a [u8; TAM_CHAVE],
    /// A versão da política em vigor quando o desafio foi emitido: uma
    /// mudança da política no meio do caminho derruba as assinaturas.
    pub versao_da_politica: u64,
    /// A geração administrativa quando o desafio foi emitido: quantas
    /// mudanças de autoridade o journal do Duke já registrou.
    ///
    /// Amarra a assinatura ao estado sob o qual foi dada. Uma mudança de
    /// autoridade no meio do caminho — um agente registrado, uma pessoa
    /// revogada — muda a geração e derruba as assinaturas, como a versão da
    /// política faz com uma mudança de política. E é o número que o
    /// signatário guarda para recusar assinar sobre um estado mais velho do
    /// que o que ele já viu.
    pub geracao: u64,
    /// Quantas credenciais a política exige, e de quantas.
    pub m: u8,
    pub n: u8,
    /// A operação, como vai ser executada.
    pub comando: &'a str,
    /// Sobre quem: para `admin.revoke`, a chave pública do alvo em hex.
    pub alvo: &'a str,
    /// O texto exato dos parâmetros.
    pub parametros: &'a str,
}

impl Conteudo<'_> {
    /// A codificação canônica: os fixos no tamanho deles, os variáveis com
    /// o tamanho na frente, em little-endian.
    pub fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(
            1 + 8
                + 32
                + 1
                + TAM_CHAVE
                + 8
                + 8
                + 2
                + 12
                + self.comando.len()
                + self.alvo.len()
                + self.parametros.len(),
        );
        b.push(VERSAO_DO_FORMATO);
        b.extend_from_slice(&self.operacao.to_le_bytes());
        b.extend_from_slice(self.nonce);
        b.push(self.sessao);
        b.extend_from_slice(self.efemera);
        b.extend_from_slice(&self.versao_da_politica.to_le_bytes());
        b.extend_from_slice(&self.geracao.to_le_bytes());
        b.push(self.m);
        b.push(self.n);
        for campo in [self.comando, self.alvo, self.parametros] {
            b.extend_from_slice(&(campo.len() as u32).to_le_bytes());
            b.extend_from_slice(campo.as_bytes());
        }
        b
    }

    /// A mensagem que cada credencial assina: o rótulo e os bytes
    /// canônicos.
    pub fn mensagem(&self) -> Vec<u8> {
        let mut m = Vec::from(ROTULO_DA_ASSINATURA);
        m.extend_from_slice(&self.bytes());
        m
    }
}

/// A chave pública de assinatura que corresponde à privada: a que vai para
/// o registro de administradores.
pub fn publica_de_assinatura(privada: &[u8; TAM_CHAVE]) -> [u8; TAM_CHAVE] {
    SigningKey::from_bytes(privada).verifying_key().to_bytes()
}

/// O lado de quem assina — e só ele tem a chave privada. A cópia da chave
/// que o Ed25519 monta é apagada ao sair.
pub fn assinar(privada: &[u8; TAM_CHAVE], conteudo: &Conteudo) -> [u8; TAM_ASSINATURA] {
    SigningKey::from_bytes(privada)
        .sign(&conteudo.mensagem())
        .to_bytes()
}

/// O lado do Duke: confere a assinatura com a chave **pública** da
/// credencial. Não recebe chave privada nenhuma — não há o que receber.
pub fn conferir(
    publica: &[u8; TAM_CHAVE],
    conteudo: &Conteudo,
    assinatura: &[u8; TAM_ASSINATURA],
) -> bool {
    let Ok(chave) = VerifyingKey::from_bytes(publica) else {
        return false;
    };
    chave
        .verify_strict(&conteudo.mensagem(), &Signature::from_bytes(assinatura))
        .is_ok()
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::{de_hex, de_hex_fixo};

    /// As chaves privadas de assinatura de duas credenciais.
    const A: [u8; 32] = [0x11; 32];
    const B: [u8; 32] = [0x12; 32];
    const EFEMERA: [u8; 32] = [0x22; 32];
    const OUTRA_EFEMERA: [u8; 32] = [0x23; 32];
    const NONCE: [u8; 32] = [0x44; 32];

    fn conteudo(ef: &[u8; 32]) -> Conteudo<'_> {
        Conteudo {
            operacao: 7,
            nonce: &NONCE,
            sessao: 1,
            efemera: ef,
            versao_da_politica: 3,
            geracao: 11,
            m: 2,
            n: 3,
            comando: "admin.revoke",
            alvo: "ab",
            parametros: r#"{"key":"ab","reason":"perdida"}"#,
        }
    }

    /// É Ed25519 de verdade: o primeiro vetor da RFC 8032, seção 7.1.
    #[test]
    fn o_vetor_da_rfc_8032() {
        let privada: [u8; 32] =
            de_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let publica: [u8; 32] =
            de_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
        let esperada: [u8; 64] = de_hex_fixo(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .unwrap();
        assert_eq!(publica_de_assinatura(&privada), publica);
        let chave = SigningKey::from_bytes(&privada);
        assert_eq!(chave.sign(b"").to_bytes(), esperada);
        assert!(
            VerifyingKey::from_bytes(&publica)
                .unwrap()
                .verify_strict(b"", &Signature::from_bytes(&esperada))
                .is_ok()
        );
    }

    /// Duas credenciais assinam o mesmo conteúdo; cada assinatura confere
    /// só com a pública de quem a fez — e a conferência recebe só a pública.
    #[test]
    fn duas_credenciais_o_mesmo_conteudo() {
        let ef = sigilo_publica(&EFEMERA);
        let c = conteudo(&ef);
        let (pa, pb) = (publica_de_assinatura(&A), publica_de_assinatura(&B));
        let (sa, sb) = (assinar(&A, &c), assinar(&B, &c));
        assert_ne!(sa, sb);
        assert!(conferir(&pa, &c, &sa));
        assert!(conferir(&pb, &c, &sb));
        assert!(!conferir(&pb, &c, &sa));
        assert!(!conferir(&pa, &c, &sb));
    }

    fn sigilo_publica(efemera: &[u8; 32]) -> [u8; 32] {
        crate::publica_de(efemera)
    }

    /// Cada campo, mudado sozinho, derruba a assinatura.
    #[test]
    fn cada_campo_amarra_a_assinatura() {
        let ef = sigilo_publica(&EFEMERA);
        let base = conteudo(&ef);
        let assinatura = assinar(&A, &base);
        let pa = publica_de_assinatura(&A);
        assert!(conferir(&pa, &base, &assinatura));
        let outro_nonce = [0x45; 32];
        let outra_ef = sigilo_publica(&OUTRA_EFEMERA);
        let mudancas = [
            Conteudo {
                operacao: 8,
                ..base
            },
            Conteudo {
                nonce: &outro_nonce,
                ..base
            },
            Conteudo { sessao: 2, ..base },
            Conteudo {
                efemera: &outra_ef,
                ..base
            },
            Conteudo {
                versao_da_politica: 4,
                ..base
            },
            Conteudo {
                geracao: 12,
                ..base
            },
            Conteudo { m: 1, ..base },
            Conteudo { n: 2, ..base },
            Conteudo {
                comando: "admin.revokE",
                ..base
            },
            Conteudo { alvo: "ac", ..base },
            Conteudo {
                parametros: r#"{"key":"ac","reason":"perdida"}"#,
                ..base
            },
        ];
        for (i, c) in mudancas.iter().enumerate() {
            assert!(!conferir(&pa, c, &assinatura), "a mudanca {i} passou");
        }
    }

    /// A fronteira entre alvo e parâmetros não desliza.
    #[test]
    fn a_fronteira_nao_desliza() {
        let ef = sigilo_publica(&EFEMERA);
        let a = Conteudo {
            alvo: "abc",
            parametros: "{}",
            ..conteudo(&ef)
        };
        let b = Conteudo {
            alvo: "ab",
            parametros: "c{}",
            ..conteudo(&ef)
        };
        assert_ne!(a.bytes(), b.bytes());
        let assinatura = assinar(&A, &a);
        assert!(!conferir(&publica_de_assinatura(&A), &b, &assinatura));
    }

    /// O rótulo separa: a assinatura dos bytes crus do conteúdo, sem ele,
    /// não vale como assinatura de quórum.
    #[test]
    fn o_rotulo_separa() {
        let ef = sigilo_publica(&EFEMERA);
        let c = conteudo(&ef);
        let crua = SigningKey::from_bytes(&A).sign(&c.bytes()).to_bytes();
        assert!(!conferir(&publica_de_assinatura(&A), &c, &crua));
    }

    /// Sem a chave privada, não se forja: nada do material público — a
    /// chave pública de assinatura, a chave X25519 do registro, o desafio
    /// inteiro, nem a efêmera privada que só o Duke tem — assina pela
    /// credencial.
    #[test]
    fn o_material_publico_nao_assina() {
        let ef = sigilo_publica(&EFEMERA);
        let c = conteudo(&ef);
        let pa = publica_de_assinatura(&A);
        let candidatas: [[u8; 32]; 5] = [pa, crate::publica_de(&A), NONCE, EFEMERA, ef];
        for (i, k) in candidatas.iter().enumerate() {
            assert!(
                !conferir(&pa, &c, &assinar(k, &c)),
                "a candidata {i} assinou"
            );
        }
        // Nem a assinatura de outro conteúdo, nem uma inventada.
        let outra = Conteudo { alvo: "ff", ..c };
        assert!(!conferir(&pa, &c, &assinar(&A, &outra)));
        assert!(!conferir(&pa, &c, &[0u8; 64]));
        assert!(!conferir(&pa, &c, &[0xffu8; 64]));
    }

    /// Cada bit da assinatura importa.
    #[test]
    fn um_bit_trocado_derruba() {
        let ef = sigilo_publica(&EFEMERA);
        let c = conteudo(&ef);
        let pa = publica_de_assinatura(&A);
        let assinatura = assinar(&A, &c);
        for byte in [0usize, 31, 32, 63] {
            let mut mexida = assinatura;
            mexida[byte] ^= 1;
            assert!(!conferir(&pa, &c, &mexida), "byte {byte}");
        }
    }

    /// Sem maleabilidade: o `S` somado à ordem do grupo é a mesma conta
    /// módulo ℓ, e a conferência estrita o recusa.
    #[test]
    fn sem_segunda_grafia() {
        let ef = sigilo_publica(&EFEMERA);
        let c = conteudo(&ef);
        let pa = publica_de_assinatura(&A);
        let assinatura = assinar(&A, &c);
        // ℓ = 2^252 + 27742317777372353535851937790883648493, little-endian.
        const ORDEM: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut maleavel = assinatura;
        let mut vai = 0u16;
        for i in 0..32 {
            let soma = u16::from(maleavel[32 + i]) + u16::from(ORDEM[i]) + vai;
            maleavel[32 + i] = soma as u8;
            vai = soma >> 8;
        }
        assert_ne!(maleavel, assinatura);
        assert!(!conferir(&pa, &c, &maleavel));
    }

    /// Uma chave pública de ordem pequena — a identidade — não confere
    /// nada, nem a assinatura que "funcionaria" para ela.
    #[test]
    fn chave_de_ordem_pequena_nao_confere() {
        let ef = sigilo_publica(&EFEMERA);
        let c = conteudo(&ef);
        let mut identidade = [0u8; 32];
        identidade[0] = 1;
        let mut assinatura = [0u8; 64];
        assinatura[0] = 1;
        assert!(!conferir(&identidade, &c, &assinatura));
        assert!(!conferir(&[0u8; 32], &c, &[0u8; 64]));
    }
}
