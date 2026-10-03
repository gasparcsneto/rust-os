//! O quórum: M de N credenciais de administrador provam o mesmo pedido.
//!
//! # Para que existe
//!
//! Algumas operações não podem depender de uma credencial só — revogar a
//! credencial de outro administrador é a primeira: uma chave roubada, sozinha,
//! revogaria as dos donos legítimos e ficaria com a máquina. Elas exigem que
//! **M** credenciais distintas, de um grupo de **N**, provem o mesmo pedido.
//! M e N são da política, por operação; este módulo é só a conta.
//!
//! # O conteúdo, um só para todos
//!
//! Cada credencial prova o **mesmo** conteúdo canônico ([`Conteudo`]): a
//! versão do formato, o número da operação, o nonce e a efêmera do desafio,
//! a sessão, a versão da política em vigor, M e N, o comando, o alvo e o
//! texto exato dos parâmetros. Cada campo de tamanho variável leva o tamanho
//! na frente, e os de tamanho fixo vão no tamanho deles — a codificação é
//! injetiva: dois conteúdos diferentes nunca viram os mesmos bytes. O
//! conteúdo vira um resumo BLAKE2s, e é esse resumo que cada credencial
//! cobre.
//!
//! Uma prova feita para outro alvo, outros parâmetros, outro desafio, outra
//! sessão, outra versão da política ou outro M e N não confere: o resumo é
//! outro.
//!
//! # A prova de cada credencial
//!
//! A mesma construção da prova administrativa de uma credencial só — ver
//! [`crate::administracao`] —, com rótulos próprios: o Diffie-Hellman da
//! credencial com a efêmera do desafio, um HKDF que amarra a chave ao nonce,
//! à credencial, à efêmera e ao resumo do conteúdo, e um HMAC do resumo com
//! essa chave.
//!
//! É um autenticador de **verificador designado**: só quem tem a efêmera
//! privada do desafio — o Duke — confere a prova. Prova para o Duke que a
//! credencial assinou aquele conteúdo; não prova isso a um terceiro depois,
//! como uma assinatura de chave pública (Ed25519) provaria. É a mesma
//! garantia das demais operações administrativas, e o mesmo par de chaves
//! X25519 do registro: nenhuma chave nova a distribuir.
//!
//! Os rótulos são outros que os da prova de uma credencial só: uma prova de
//! quórum não vale como prova comum, nem o contrário.

use alloc::vec::Vec;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::aperto::{dh, publica_de};
use crate::resumo::{TAM_RESUMO, hkdf_rfc5869, hmac, resumir};
use crate::{Erro, TAM_CHAVE};

/// A versão do formato do conteúdo. Muda se a codificação mudar: um
/// conteúdo de um formato nunca é lido como de outro.
pub const VERSAO_DO_FORMATO: u8 = 1;

/// Os rótulos que separam esta conta de qualquer outra com as mesmas chaves.
const ROTULO_DO_CONTEUDO: &[u8] = b"Duke quorum: conteudo v1";
const ROTULO_DA_CHAVE: &[u8] = b"Duke quorum: chave v1";
const ROTULO_DA_PROVA: &[u8] = b"Duke quorum: prova v1";

/// O que todas as credenciais de um quórum provam — o mesmo, byte a byte.
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
    /// mudança da política no meio do caminho derruba as provas.
    pub versao_da_politica: u64,
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
        b.push(self.m);
        b.push(self.n);
        for campo in [self.comando, self.alvo, self.parametros] {
            b.extend_from_slice(&(campo.len() as u32).to_le_bytes());
            b.extend_from_slice(campo.as_bytes());
        }
        b
    }

    /// O resumo do conteúdo: o que cada credencial cobre.
    pub fn resumo(&self) -> [u8; TAM_RESUMO] {
        resumir(&[ROTULO_DO_CONTEUDO, &self.bytes()])
    }

    /// A chave da prova de `credencial`, a partir do segredo do
    /// Diffie-Hellman.
    fn chave(
        &self,
        segredo: &[u8; 32],
        credencial: &[u8; TAM_CHAVE],
        resumo: &[u8; TAM_RESUMO],
    ) -> [u8; TAM_RESUMO] {
        hkdf_rfc5869(
            self.nonce,
            segredo,
            &[ROTULO_DA_CHAVE, credencial, self.efemera, resumo],
        )
    }
}

/// O lado da credencial: a prova dela sobre o conteúdo.
pub fn provar(credencial: &[u8; TAM_CHAVE], conteudo: &Conteudo) -> Result<[u8; 32], Erro> {
    let publica = publica_de(credencial);
    let resumo = conteudo.resumo();
    let mut segredo = dh(credencial, conteudo.efemera)?;
    let mut chave = conteudo.chave(&segredo, &publica, &resumo);
    let prova = hmac(&chave, &[ROTULO_DA_PROVA, &resumo]);
    segredo.zeroize();
    chave.zeroize();
    Ok(prova)
}

/// O lado do Duke: a prova de `credencial` confere sobre o conteúdo, com a
/// efêmera privada do desafio. Comparação de tempo constante.
pub fn conferir(
    efemera: &[u8; TAM_CHAVE],
    conteudo: &Conteudo,
    credencial: &[u8; TAM_CHAVE],
    prova: &[u8; 32],
) -> bool {
    if publica_de(efemera) != *conteudo.efemera {
        return false;
    }
    let Ok(mut segredo) = dh(efemera, credencial) else {
        return false;
    };
    let resumo = conteudo.resumo();
    let mut chave = conteudo.chave(&segredo, credencial, &resumo);
    let esperada = hmac(&chave, &[ROTULO_DA_PROVA, &resumo]);
    segredo.zeroize();
    chave.zeroize();
    esperada.ct_eq(prova).into()
}

#[cfg(test)]
mod testes {
    use super::*;

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
            m: 2,
            n: 3,
            comando: "admin.revoke",
            alvo: "ab",
            parametros: r#"{"key":"ab","reason":"perdida"}"#,
        }
    }

    /// Duas credenciais provam o mesmo conteúdo, cada uma com a sua prova,
    /// e cada prova confere só como da credencial que a fez.
    #[test]
    fn duas_credenciais_o_mesmo_conteudo() {
        let ef = publica_de(&EFEMERA);
        let c = conteudo(&ef);
        let (pa, pb) = (provar(&A, &c).unwrap(), provar(&B, &c).unwrap());
        assert_ne!(pa, pb);
        assert!(conferir(&EFEMERA, &c, &publica_de(&A), &pa));
        assert!(conferir(&EFEMERA, &c, &publica_de(&B), &pb));
        // A prova de A não passa como de B, nem o contrário.
        assert!(!conferir(&EFEMERA, &c, &publica_de(&B), &pa));
        assert!(!conferir(&EFEMERA, &c, &publica_de(&A), &pb));
    }

    /// Cada campo, mudado sozinho, derruba a prova.
    #[test]
    fn cada_campo_amarra_a_prova() {
        let ef = publica_de(&EFEMERA);
        let base = conteudo(&ef);
        let prova = provar(&A, &base).unwrap();
        let a = publica_de(&A);
        let outro_nonce = [0x45; 32];
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
                versao_da_politica: 4,
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
            assert!(!conferir(&EFEMERA, c, &a, &prova), "a mudanca {i} passou");
        }
    }

    /// A prova feita sobre um desafio não vale com outro: a efêmera é outra.
    #[test]
    fn outro_desafio_nao_vale() {
        let (ef, outra) = (publica_de(&EFEMERA), publica_de(&OUTRA_EFEMERA));
        let prova = provar(&A, &conteudo(&outra)).unwrap();
        assert!(!conferir(&EFEMERA, &conteudo(&ef), &publica_de(&A), &prova));
        // Nem com a efêmera privada que não é a do conteúdo.
        assert!(!conferir(
            &EFEMERA,
            &conteudo(&outra),
            &publica_de(&A),
            &prova
        ));
    }

    /// A fronteira entre alvo e parâmetros não desliza.
    #[test]
    fn a_fronteira_nao_desliza() {
        let ef = publica_de(&EFEMERA);
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
        let prova = provar(&A, &a).unwrap();
        assert!(!conferir(&EFEMERA, &b, &publica_de(&A), &prova));
    }

    /// Uma prova de quórum não vale como prova comum: os rótulos são outros.
    #[test]
    fn nao_vale_como_prova_comum() {
        let ef = publica_de(&EFEMERA);
        let c = conteudo(&ef);
        let prova = provar(&A, &c).unwrap();
        let a = publica_de(&A);
        let comum = crate::administracao::Contexto {
            nonce: &NONCE,
            sessao: c.sessao,
            administrador: &a,
            efemera: &ef,
            comando: c.comando,
            parametros: c.parametros,
        };
        assert!(!crate::administracao::conferir(&EFEMERA, &comum, &prova));
        let prova_comum = crate::administracao::provar(&A, &comum).unwrap();
        assert!(!conferir(&EFEMERA, &c, &a, &prova_comum));
    }

    /// A mesma credencial em outra grafia — o bit alto ligado, que o X25519
    /// ignora — dá o mesmo segredo; e a prova não vale para ela, porque a
    /// chave entra na derivação byte a byte. Sem isso, uma credencial
    /// valeria por duas grafias.
    #[test]
    fn outra_grafia_da_chave_nao_vale() {
        let ef = publica_de(&EFEMERA);
        let c = conteudo(&ef);
        let prova = provar(&A, &c).unwrap();
        let a = publica_de(&A);
        let mut grafia = a;
        grafia[31] |= 0x80;
        assert_ne!(grafia, a);
        assert_eq!(dh(&EFEMERA, &grafia).unwrap(), dh(&EFEMERA, &a).unwrap());
        assert!(conferir(&EFEMERA, &c, &a, &prova));
        assert!(!conferir(&EFEMERA, &c, &grafia, &prova));
    }

    /// Uma credencial de ordem baixa não confere nada.
    #[test]
    fn credencial_fraca_nao_confere() {
        let ef = publica_de(&EFEMERA);
        let c = conteudo(&ef);
        assert!(!conferir(&EFEMERA, &c, &[0u8; 32], &[0u8; 32]));
    }
}
