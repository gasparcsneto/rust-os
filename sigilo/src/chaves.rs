//! As chaves de assinatura das identidades, e o registro de domínios.
//!
//! # O que se assina
//!
//! Uma chave de assinatura de uma identidade assina sempre a mesma forma: o
//! **prefixo de um domínio registrado** seguido de um **resumo de 32
//! bytes** — e nada mais. Quem pede uma assinatura diz o nome do domínio, e
//! nunca os bytes do prefixo; o resumo é dele, e o kernel não sabe de que é.
//!
//! O prefixo é a separação de domínios: a mesma chave, assinando em dois
//! domínios, nunca produz a assinatura de um no outro. Duas mensagens de
//! domínios diferentes só seriam iguais com prefixos iguais — o resumo tem
//! sempre 32 bytes, e prefixos de tamanhos diferentes dão mensagens de
//! tamanhos diferentes —, e o registro recusa um prefixo repetido. É também
//! por isso que o resumo tem exatamente 32 bytes: com um resumo de tamanho
//! livre, `prefixo ‖ resumo` de um domínio poderia ser o de outro com um
//! prefixo mais curto.
//!
//! # O registro de domínios
//!
//! ```text
//! # comentário
//! dominio <nome> <prefixo em hexadecimal>
//! ```
//!
//! Um domínio por linha: o nome, na regra dos nomes ([`crate::registro`])
//! e com até [`MAIOR_NOME_DE_DOMINIO`] bytes, e o prefixo, de 1 a
//! [`MAIOR_PREFIXO`] bytes, em hexadecimal minúsculo.
//! Só a imagem o escreve — o `xtask` —, e o kernel o lê no boot: qual papel
//! usa qual domínio é da política, na linha `dominios`. Como o registro das
//! fontes de hora, e diferente do dos agentes, uma linha errada recusa o
//! registro inteiro: um domínio é a forma do que uma chave assina, e um
//! registro meio lido seria uma assinatura que ninguém escreveu.
//!
//! # A chave privada
//!
//! [`Privada`] é a semente Ed25519 (RFC 8032). Só o kernel a tem: nenhuma
//! função deste módulo a devolve em bytes, o `Debug` dela não a mostra, e
//! ela é apagada da memória quando sai de uso. Daqui saem só a pública, a
//! assinatura e a [`impressao`] — a que vai para a auditoria.

use alloc::string::String;
use alloc::vec::Vec;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::registro::nome_valido;

/// O maior prefixo de domínio, em bytes.
pub const MAIOR_PREFIXO: usize = 64;

/// O maior nome de domínio, em bytes — menor que o dos outros nomes: o
/// registro de uma assinatura na auditoria do kernel leva a chave, o nome
/// do domínio e o resumo inteiro, em hexadecimal, e tem de caber no teto do
/// recurso dela sem cortar o resumo.
pub const MAIOR_NOME_DE_DOMINIO: usize = 24;

/// Quantos domínios o registro tem, no máximo.
pub const MAIS_DOMINIOS: usize = 16;

/// O tamanho do resumo que se assina.
pub const TAM_RESUMO: usize = 32;

/// O tamanho de uma assinatura Ed25519.
pub const TAM_ASSINATURA: usize = 64;

/// O tamanho de uma chave pública Ed25519.
pub const TAM_PUBLICA: usize = 32;

/// O tamanho da impressão de uma chave pública, a que vai para a auditoria.
pub const TAM_IMPRESSAO: usize = 8;

/// Um domínio de assinatura: o nome, e os bytes que a assinatura leva
/// antes do resumo. Só sai de [`Dominios::ler`], que o confere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dominio {
    nome: String,
    prefixo: Vec<u8>,
}

impl Dominio {
    /// O nome, como a política e a auditoria o chamam.
    pub fn nome(&self) -> &str {
        &self.nome
    }

    /// Os bytes que a assinatura leva antes do resumo.
    pub fn prefixo(&self) -> &[u8] {
        &self.prefixo
    }
}

/// O registro de domínios, lido e conferido.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dominios {
    dominios: Vec<Dominio>,
}

/// O que há de errado numa linha do registro de domínios.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Falta {
    /// Uma linha que não começa com `dominio`.
    LinhaDesconhecida,
    /// O nome falta, está fora da regra dos nomes ou passa de
    /// [`MAIOR_NOME_DE_DOMINIO`] bytes.
    Nome,
    /// O prefixo falta, ou não é hexadecimal minúsculo de 1 a
    /// [`MAIOR_PREFIXO`] bytes.
    Prefixo,
    /// Algo depois do prefixo.
    Sobra,
    /// Um nome que outra linha já deu.
    NomeRepetido,
    /// Um prefixo que outro domínio já usa: os dois assinariam o mesmo.
    PrefixoRepetido,
    /// Mais de [`MAIS_DOMINIOS`] domínios.
    Demais,
}

/// Um erro do registro de domínios, com a linha.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErroDoRegistro {
    pub linha: usize,
    pub falta: Falta,
}

impl ErroDoRegistro {
    /// Uma frase, para o log.
    pub const fn motivo(&self) -> &'static str {
        match self.falta {
            Falta::LinhaDesconhecida => "linha que nao comeca com `dominio`",
            Falta::Nome => "nome ausente ou fora da regra",
            Falta::Prefixo => "prefixo que nao e hexadecimal minusculo de 1 a 64 bytes",
            Falta::Sobra => "algo depois do prefixo",
            Falta::NomeRepetido => "dominio com o nome de outro",
            Falta::PrefixoRepetido => "dominio com o prefixo de outro",
            Falta::Demais => "dominios demais",
        }
    }
}

impl core::fmt::Display for ErroDoRegistro {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "linha {}: {}", self.linha, self.motivo())
    }
}

/// Bytes a partir de hexadecimal minúsculo, de 1 a [`MAIOR_PREFIXO`] bytes.
/// Uma forma só: o registro que a imagem escreve é o que o kernel lê, e
/// maiúscula ou dígito ímpar é erro, e não outra grafia do mesmo prefixo.
fn prefixo_de_hex(texto: &str) -> Option<Vec<u8>> {
    let minusculo = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if texto.is_empty()
        || !texto.len().is_multiple_of(2)
        || texto.len() > 2 * MAIOR_PREFIXO
        || !texto.bytes().all(minusculo)
    {
        return None;
    }
    (0..texto.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&texto[i..i + 2], 16).ok())
        .collect()
}

impl Dominios {
    /// Lê e confere um registro inteiro. Qualquer erro o recusa, com a
    /// linha.
    pub fn ler(texto: &str) -> Result<Dominios, ErroDoRegistro> {
        let mut dominios: Vec<Dominio> = Vec::new();
        for (i, linha) in texto.lines().enumerate() {
            let erro = |falta| ErroDoRegistro {
                linha: i + 1,
                falta,
            };
            let linha = linha.trim();
            if linha.is_empty() || linha.starts_with('#') {
                continue;
            }
            let mut partes = linha.split_ascii_whitespace();
            if partes.next() != Some("dominio") {
                return Err(erro(Falta::LinhaDesconhecida));
            }
            let nome = partes
                .next()
                .filter(|n| nome_valido(n) && n.len() <= MAIOR_NOME_DE_DOMINIO)
                .ok_or(erro(Falta::Nome))?;
            let prefixo = partes
                .next()
                .and_then(prefixo_de_hex)
                .ok_or(erro(Falta::Prefixo))?;
            if partes.next().is_some() {
                return Err(erro(Falta::Sobra));
            }
            if dominios.iter().any(|d| d.nome == nome) {
                return Err(erro(Falta::NomeRepetido));
            }
            if dominios.iter().any(|d| d.prefixo == prefixo) {
                return Err(erro(Falta::PrefixoRepetido));
            }
            if dominios.len() >= MAIS_DOMINIOS {
                return Err(erro(Falta::Demais));
            }
            dominios.push(Dominio {
                nome: String::from(nome),
                prefixo,
            });
        }
        Ok(Dominios { dominios })
    }

    /// O domínio com este nome.
    pub fn dominio(&self, nome: &str) -> Option<&Dominio> {
        self.dominios.iter().find(|d| d.nome == nome)
    }

    /// Os domínios, na ordem do arquivo.
    pub fn todos(&self) -> &[Dominio] {
        &self.dominios
    }
}

/// A linha de um domínio, com a quebra no fim: a que o `xtask` escreve.
pub fn linha_de_dominio(nome: &str, prefixo: &[u8]) -> String {
    alloc::format!("dominio {nome} {}\n", crate::hex_de(prefixo))
}

/// A chave privada de uma identidade: a semente Ed25519.
///
/// Sem `Clone`, sem conversão para bytes, e apagada ao sair de uso: o
/// `SigningKey` do `ed25519-dalek` zera a semente quando é descartado.
pub struct Privada(SigningKey);

impl Privada {
    /// A chave cuja semente é `semente` — 32 bytes do gerador. A cópia que
    /// veio é apagada aqui.
    pub fn de_semente(mut semente: [u8; 32]) -> Privada {
        let chave = SigningKey::from_bytes(&semente);
        zeroize::Zeroize::zeroize(&mut semente);
        Privada(chave)
    }

    /// A chave pública.
    pub fn publica(&self) -> [u8; TAM_PUBLICA] {
        self.0.verifying_key().to_bytes()
    }

    /// A semente, emprestada a `f` — para o journal cifrado do kernel, e só
    /// para ele: é o que uma chave guardada precisa para voltar no boot. A
    /// cópia é apagada quando `f` volta; nada dela sai daqui de outro jeito.
    pub fn com_a_semente<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        let mut semente = self.0.to_bytes();
        let r = f(&semente);
        zeroize::Zeroize::zeroize(&mut semente);
        r
    }

    /// Assina `resumo` no domínio `dominio`: a assinatura Ed25519 de
    /// `prefixo ‖ resumo`.
    pub fn assinar(&self, dominio: &Dominio, resumo: &[u8; TAM_RESUMO]) -> [u8; TAM_ASSINATURA] {
        let mut mensagem = [0u8; MAIOR_PREFIXO + TAM_RESUMO];
        let n = dominio.prefixo.len();
        mensagem[..n].copy_from_slice(&dominio.prefixo);
        mensagem[n..n + TAM_RESUMO].copy_from_slice(resumo);
        self.0.sign(&mensagem[..n + TAM_RESUMO]).to_bytes()
    }
}

impl core::fmt::Debug for Privada {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Privada(..)")
    }
}

/// Se `assinatura` é a da chave `publica` sobre `resumo` no domínio
/// `dominio`. Na forma estrita: uma chave pública de ordem pequena, ou uma
/// assinatura que não é canônica, não conferem.
pub fn conferir(
    publica: &[u8; TAM_PUBLICA],
    dominio: &Dominio,
    resumo: &[u8; TAM_RESUMO],
    assinatura: &[u8; TAM_ASSINATURA],
) -> bool {
    let Ok(chave) = VerifyingKey::from_bytes(publica) else {
        return false;
    };
    let mut mensagem = Vec::with_capacity(dominio.prefixo.len() + TAM_RESUMO);
    mensagem.extend_from_slice(&dominio.prefixo);
    mensagem.extend_from_slice(resumo);
    chave
        .verify_strict(&mensagem, &Signature::from_bytes(assinatura))
        .is_ok()
}

/// A impressão de uma chave pública: os primeiros [`TAM_IMPRESSAO`] bytes
/// do BLAKE2s-256 dela. É o que a auditoria grava para dizer qual chave
/// assinou — curta, e sem nada que a chave privada não deixe saber.
pub fn impressao(publica: &[u8; TAM_PUBLICA]) -> [u8; TAM_IMPRESSAO] {
    let resumo = crate::codigo::resumo(publica);
    let mut i = [0u8; TAM_IMPRESSAO];
    i.copy_from_slice(&resumo[..TAM_IMPRESSAO]);
    i
}

#[cfg(test)]
mod testes {
    use super::*;
    use alloc::format;

    /// A semente emprestada é a da chave: a privada refeita dela tem a
    /// mesma pública e assina igual.
    #[test]
    fn a_semente_refaz_a_mesma_chave() {
        let original = Privada::de_semente([0x42; 32]);
        let refeita = original.com_a_semente(|s| Privada::de_semente(*s));
        assert_eq!(refeita.publica(), original.publica());
        let d = Dominios::ler(&linha_de_dominio("ic-request", b"\x0Aic-request"))
            .unwrap()
            .dominio("ic-request")
            .unwrap()
            .clone();
        assert_eq!(
            refeita.assinar(&d, &[7; 32]),
            original.assinar(&d, &[7; 32])
        );
        assert!(original.com_a_semente(|s| *s == [0x42; 32]));
    }

    /// Um domínio com o prefixo dado, pelo caminho de verdade: o registro.
    fn dominio(nome: &str, prefixo: &[u8]) -> Dominio {
        Dominios::ler(&linha_de_dominio(nome, prefixo))
            .unwrap()
            .dominio(nome)
            .unwrap()
            .clone()
    }

    fn de_hex(t: &str) -> Vec<u8> {
        (0..t.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap())
            .collect()
    }

    /// O vetor "SHA(abc)" da RFC 8032 (§7.1): a mensagem tem 64 bytes, e
    /// cabe na forma daqui com um prefixo de 32 e o resumo de 32. A conta é
    /// a da RFC, e não a de uma implementação.
    #[test]
    fn o_vetor_da_rfc_8032() {
        let semente: [u8; 32] =
            de_hex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
                .try_into()
                .unwrap();
        let mensagem = de_hex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        );
        let esperada = de_hex(
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589\
             09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        );
        let k = Privada::de_semente(semente);
        assert_eq!(
            k.publica().to_vec(),
            de_hex("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
        );
        let d = dominio("rfc", &mensagem[..32]);
        let resumo: [u8; 32] = mensagem[32..].try_into().unwrap();
        let assinatura = k.assinar(&d, &resumo);
        assert_eq!(assinatura.to_vec(), esperada);
        assert!(conferir(&k.publica(), &d, &resumo, &assinatura));
    }

    /// A assinatura é a do domínio: a mesma chave e o mesmo resumo em outro
    /// domínio dão outra assinatura, que não confere no primeiro; e o
    /// resumo trocado, ou a chave trocada, não conferem.
    #[test]
    fn o_dominio_separa() {
        let a = dominio("a", b"\x01a");
        let b = dominio("b", b"\x01b");
        let k = Privada::de_semente([7; 32]);
        let outra = Privada::de_semente([8; 32]);
        let r = [0x42; 32];
        let sa = k.assinar(&a, &r);
        let sb = k.assinar(&b, &r);
        assert_ne!(sa, sb);
        assert!(conferir(&k.publica(), &a, &r, &sa));
        assert!(!conferir(&k.publica(), &b, &r, &sa));
        let mut r2 = r;
        r2[31] ^= 1;
        assert!(!conferir(&k.publica(), &a, &r2, &sa));
        assert!(!conferir(&outra.publica(), &a, &r, &sa));
        let mut adulterada = sa;
        adulterada[0] ^= 1;
        assert!(!conferir(&k.publica(), &a, &r, &adulterada));
        // Determinística (RFC 8032): a mesma conta dá a mesma assinatura.
        assert_eq!(sa, k.assinar(&a, &r));
        // O prefixo do maior tamanho cabe.
        let grande = dominio("grande", &[0xab; MAIOR_PREFIXO]);
        let s = k.assinar(&grande, &r);
        assert!(conferir(&k.publica(), &grande, &r, &s));
    }

    /// Nada da chave privada sai pelo `Debug`.
    #[test]
    fn o_debug_nao_mostra_a_privada() {
        let k = Privada::de_semente([0x5a; 32]);
        let texto = format!("{k:?}");
        assert_eq!(texto, "Privada(..)");
        assert!(!texto.contains("5a") && !texto.contains("90"));
    }

    /// A impressão: oito bytes, estável, e diferente para chaves diferentes.
    #[test]
    fn a_impressao() {
        let a = Privada::de_semente([1; 32]).publica();
        let b = Privada::de_semente([2; 32]).publica();
        assert_eq!(impressao(&a), impressao(&a));
        assert_ne!(impressao(&a), impressao(&b));
        assert_eq!(impressao(&a)[..], crate::codigo::resumo(&a)[..8]);
    }

    /// O registro: a forma, os limites, e qualquer erro recusa o arquivo
    /// inteiro, com a linha.
    #[test]
    fn o_registro_de_dominios() {
        let texto = "# os dominios\n\ndominio x 0a6963\n  dominio y-2 ff  \n";
        let r = Dominios::ler(texto).unwrap();
        assert_eq!(r.todos().len(), 2);
        assert_eq!(r.dominio("x").unwrap().prefixo(), b"\x0aic");
        assert_eq!(r.dominio("y-2").unwrap().nome(), "y-2");
        assert!(r.dominio("z").is_none());
        assert_eq!(Dominios::ler("").unwrap(), Dominios::default());
        // A linha que o xtask escreve é a que se lê.
        let linha = linha_de_dominio("x", b"\x0aic");
        assert_eq!(linha, "dominio x 0a6963\n");
        assert_eq!(Dominios::ler(&linha).unwrap().dominio("x"), r.dominio("x"));
        let erro = |t: &str| Dominios::ler(t).unwrap_err();
        for (t, linha, falta) in [
            ("outra x 00", 1, Falta::LinhaDesconhecida),
            ("dominio", 1, Falta::Nome),
            ("dominio X 00", 1, Falta::Nome),
            ("dominio * 00", 1, Falta::Nome),
            ("dominio x", 1, Falta::Prefixo),
            ("dominio x 0", 1, Falta::Prefixo),
            ("dominio x 0A", 1, Falta::Prefixo),
            ("dominio x zz", 1, Falta::Prefixo),
            ("dominio x 0x00", 1, Falta::Prefixo),
            ("dominio x 00 00", 1, Falta::Sobra),
            ("dominio x 00\ndominio x 01", 2, Falta::NomeRepetido),
            ("dominio x 00\ndominio y 00", 2, Falta::PrefixoRepetido),
        ] {
            assert_eq!(erro(t), ErroDoRegistro { linha, falta }, "{t}");
        }
        // O nome: até 24 bytes.
        let n24 = "a".repeat(MAIOR_NOME_DE_DOMINIO);
        assert!(Dominios::ler(&format!("dominio {n24} 00")).is_ok());
        assert_eq!(
            erro(&format!("dominio {n24}a 00")),
            ErroDoRegistro {
                linha: 1,
                falta: Falta::Nome
            }
        );
        // O prefixo: de 1 a 64 bytes.
        let p64 = "ab".repeat(MAIOR_PREFIXO);
        assert!(Dominios::ler(&format!("dominio x {p64}")).is_ok());
        assert_eq!(erro(&format!("dominio x {p64}ab")).falta, Falta::Prefixo);
        // Até MAIS_DOMINIOS domínios.
        let muitos: String = (0..=MAIS_DOMINIOS)
            .map(|i| format!("dominio d{i} {:02x}\n", i))
            .collect();
        assert_eq!(erro(&muitos).falta, Falta::Demais);
        assert_eq!(erro(&muitos).linha, MAIS_DOMINIOS + 1);
        let cabem: String = muitos
            .lines()
            .take(MAIS_DOMINIOS)
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(Dominios::ler(&cabem).unwrap().todos().len(), MAIS_DOMINIOS);
    }
}
