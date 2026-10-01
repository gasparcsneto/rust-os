//! A prova das operações administrativas: desafio e resposta.
//!
//! # Para que existe
//!
//! Registrar um agente é dar a uma chave o direito de falar com o Duke. Isso
//! não pode depender do canal por onde o pedido chegou: a serial (sessão 0)
//! é aberta de propósito — é o canal de emergência —, e quem a alcança não
//! deve ganhar por isso o poder de pôr chaves no registro. A operação
//! administrativa carrega uma prova própria, que vale do mesmo jeito em
//! qualquer sessão.
//!
//! # O protocolo
//!
//! 1. Quem administra pede um desafio. O Duke sorteia um nonce e uma chave
//!    efêmera, guarda as duas, e devolve o nonce e a parte pública.
//! 2. Quem administra faz o Diffie-Hellman da sua chave privada de
//!    administrador com a efêmera do Duke, deriva dele a chave da prova e
//!    calcula a prova sobre o pedido.
//! 3. O Duke faz o mesmo Diffie-Hellman do outro lado — a efêmera privada
//!    com a pública do administrador, que está no registro de
//!    administradores —, deriva a mesma chave e confere.
//!
//! Só quem tem a chave privada de um administrador registrado chega à mesma
//! chave. O desafio vale uma vez, e o Duke o descarta ao conferir, acerte ou
//! erre.
//!
//! # Por que a chave é derivada, e não o segredo bruto
//!
//! O resultado do X25519 é um ponto da curva, não uma chave uniforme: tem
//! estrutura, e usá-lo direto como chave do MAC é usar uma chave que não é o
//! que o MAC supõe. Ele passa por um HKDF (RFC 5869), e a derivação já
//! **amarra** a chave ao contexto inteiro — ver [`Contexto`]:
//!
//! - o **nonce**, como sal: um desafio, uma chave;
//! - a **sessão**: a prova pedida na sessão 2 não vale na 3;
//! - as duas chaves públicas, a do administrador e a efêmera do Duke;
//! - o **comando** e os **parâmetros**, byte a byte.
//!
//! Uma prova feita para `agent.register` com um nome não serve para o mesmo
//! comando com outro nome, nem para outro comando, nem em outra sessão, nem
//! com outro desafio: em cada um desses casos a chave derivada já é outra.
//! O MAC por cima cobre o pedido de novo — é a mesma garantia por um segundo
//! caminho, e custa um HMAC.
//!
//! # Por que os pedaços levam o tamanho na frente
//!
//! Sem ele, `("agent.registe", "r{…}")` e `("agent.register", "{…}")` dariam
//! a mesma sequência de bytes. O tamanho na frente de cada campo variável
//! torna a codificação injetiva: dois contextos diferentes nunca viram os
//! mesmos bytes.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::aperto::{dh, publica_de};
use crate::resumo::{TAM_RESUMO, hkdf_rfc5869, hmac};
use crate::{Erro, TAM_CHAVE};

/// O rótulo que separa esta derivação de qualquer outra que use as mesmas
/// chaves.
const ROTULO_DA_CHAVE: &[u8] = b"Duke administracao: chave v1";

/// E o da prova.
const ROTULO_DA_PROVA: &[u8] = b"Duke administracao: prova v1";

/// O tamanho do nonce do desafio, e da prova.
pub const TAM_NONCE: usize = 32;

/// Tudo aquilo a que uma prova fica presa.
#[derive(Clone, Copy)]
pub struct Contexto<'a> {
    /// O nonce do desafio, sorteado pelo Duke.
    pub nonce: &'a [u8; TAM_NONCE],
    /// A sessão em que o desafio foi pedido e em que a prova vai ser usada.
    pub sessao: u8,
    /// A chave pública do administrador.
    pub administrador: &'a [u8; TAM_CHAVE],
    /// A chave pública efêmera do desafio.
    pub efemera: &'a [u8; TAM_CHAVE],
    /// O comando, como vai ser executado.
    pub comando: &'a str,
    /// Os parâmetros, exatamente os bytes que vão ser interpretados.
    pub parametros: &'a str,
}

impl Contexto<'_> {
    /// Chama `f` com os campos codificados, cada um precedido do tamanho
    /// quando o tamanho varia.
    fn com_campos<R>(&self, rotulo: &[u8], f: impl FnOnce(&[&[u8]]) -> R) -> R {
        let sessao = [self.sessao];
        let tam_comando = (self.comando.len() as u32).to_le_bytes();
        let tam_parametros = (self.parametros.len() as u32).to_le_bytes();
        f(&[
            rotulo,
            self.nonce,
            &sessao,
            self.administrador,
            self.efemera,
            &tam_comando,
            self.comando.as_bytes(),
            &tam_parametros,
            self.parametros.as_bytes(),
        ])
    }

    /// A chave da prova, a partir do segredo do Diffie-Hellman.
    fn chave(&self, segredo: &[u8; 32]) -> [u8; TAM_RESUMO] {
        self.com_campos(ROTULO_DA_CHAVE, |info| {
            hkdf_rfc5869(self.nonce, segredo, info)
        })
    }

    /// A prova, com a chave já derivada.
    fn prova_com(&self, chave: &[u8; TAM_RESUMO]) -> [u8; TAM_RESUMO] {
        self.com_campos(ROTULO_DA_PROVA, |campos| hmac(chave, campos))
    }
}

/// O lado de quem administra: a prova para um pedido.
pub fn provar(administrador: &[u8; TAM_CHAVE], contexto: &Contexto) -> Result<[u8; 32], Erro> {
    if publica_de(administrador) != *contexto.administrador {
        // Uma prova com uma chave e o contexto dizendo outra nunca
        // conferiria; melhor dizer o porquê aqui do que lá.
        return Err(Erro::Estado);
    }
    let mut segredo = dh(administrador, contexto.efemera)?;
    let mut chave = contexto.chave(&segredo);
    let prova = contexto.prova_com(&chave);
    segredo.zeroize();
    chave.zeroize();
    Ok(prova)
}

/// O lado do Duke: confere a prova com a efêmera privada do desafio.
///
/// A comparação é de tempo constante: uma que parasse no primeiro byte
/// diferente diria, pelo tempo, quantos bytes da prova estavam certos — e a
/// prova poderia ser montada byte a byte.
pub fn conferir(efemera: &[u8; TAM_CHAVE], contexto: &Contexto, prova: &[u8; 32]) -> bool {
    if publica_de(efemera) != *contexto.efemera {
        return false;
    }
    let Ok(mut segredo) = dh(efemera, contexto.administrador) else {
        return false;
    };
    let mut chave = contexto.chave(&segredo);
    let esperada = contexto.prova_com(&chave);
    segredo.zeroize();
    chave.zeroize();
    esperada.ct_eq(prova).into()
}

#[cfg(test)]
mod testes {
    use super::*;

    const ADMIN: [u8; 32] = [0x11; 32];
    const EFEMERA: [u8; 32] = [0x22; 32];
    const OUTRO: [u8; 32] = [0x33; 32];
    const NONCE: [u8; 32] = [0x44; 32];

    fn contexto<'a>(adm: &'a [u8; 32], ef: &'a [u8; 32]) -> Contexto<'a> {
        Contexto {
            nonce: &NONCE,
            sessao: 0,
            administrador: adm,
            efemera: ef,
            comando: "agent.register",
            parametros: r#"{"chave":"ab","nome":"x"}"#,
        }
    }

    #[test]
    fn a_prova_certa_confere() {
        let (adm, ef) = (publica_de(&ADMIN), publica_de(&EFEMERA));
        let c = contexto(&adm, &ef);
        let prova = provar(&ADMIN, &c).unwrap();
        assert!(conferir(&EFEMERA, &c, &prova));
    }

    /// Cada campo do contexto, mudado sozinho, derruba a prova.
    #[test]
    fn cada_campo_amarra_a_prova() {
        let (adm, ef) = (publica_de(&ADMIN), publica_de(&EFEMERA));
        let base = contexto(&adm, &ef);
        let prova = provar(&ADMIN, &base).unwrap();

        let outro_nonce = [0x45; 32];
        let mudancas: [Contexto; 4] = [
            Contexto {
                nonce: &outro_nonce,
                ..base
            },
            Contexto { sessao: 1, ..base },
            Contexto {
                comando: "agent.unregister",
                ..base
            },
            Contexto {
                parametros: r#"{"chave":"ab","nome":"y"}"#,
                ..base
            },
        ];
        for (i, c) in mudancas.iter().enumerate() {
            assert!(!conferir(&EFEMERA, c, &prova), "a mudanca {i} passou");
        }
    }

    /// Outra chave de administrador não produz a prova de quem está no
    /// contexto.
    #[test]
    fn outra_chave_nao_prova() {
        let (adm, ef) = (publica_de(&ADMIN), publica_de(&EFEMERA));
        let c = contexto(&adm, &ef);
        // Quem tem OUTRO calcula honestamente, mas com a sua chave.
        let outro_pub = publica_de(&OUTRO);
        let falsa = provar(
            &OUTRO,
            &Contexto {
                administrador: &outro_pub,
                ..c
            },
        )
        .unwrap();
        assert!(!conferir(&EFEMERA, &c, &falsa));
        // E não consegue nem pedir com o contexto alheio.
        assert_eq!(provar(&OUTRO, &c), Err(Erro::Estado));
    }

    /// A fronteira entre comando e parâmetros não pode deslizar.
    #[test]
    fn a_fronteira_nao_desliza() {
        let (adm, ef) = (publica_de(&ADMIN), publica_de(&EFEMERA));
        let a = Contexto {
            comando: "agent.registe",
            parametros: "r{}",
            ..contexto(&adm, &ef)
        };
        let b = Contexto {
            comando: "agent.register",
            parametros: "{}",
            ..contexto(&adm, &ef)
        };
        let prova = provar(&ADMIN, &a).unwrap();
        assert!(!conferir(&EFEMERA, &b, &prova));
    }
}
