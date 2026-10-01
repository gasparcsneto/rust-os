//! O registro de pessoas: quem existe, com que credencial, e em que estado.
//!
//! ```text
//! # id                       nome    papel     estado    credencial
//! pessoa:9f2c41d07a3b55e1    maria   operador  ativa     argon2id:m=4096,t=3,p=1:<sal>:<verificador>
//! ```
//!
//! # Pessoa não é agente
//!
//! Um agente é a chave dele. Uma pessoa é um identificador do registro, com
//! uma credencial que prova que é ela — hoje, uma senha guardada como
//! verificador Argon2id ([`crate::credencial`]). O identificador tem a forma
//! `pessoa:<16 hex>`, com um `:` que nenhum nome de agente pode ter (ver
//! [`crate::registro::nome_valido`]): escrito no log ou na auditoria, um não
//! se confunde com o outro.
//!
//! # Revogada não é apagada
//!
//! Uma pessoa revogada continua no registro, com o estado `revogada`: não
//! entra mais, e as sessões dela acabam, mas o identificador continua
//! dizendo quem foi. A auditoria de ontem aponta para alguém que ainda está
//! no registro hoje.
//!
//! Mora neste pacote pelo mesmo motivo do registro de agentes: o `xtask`
//! escreve o arquivo e o kernel o lê.

use alloc::format;
use alloc::string::{String, ToString};

use crate::credencial::Credencial;
use crate::registro::nome_valido;

/// O prefixo do identificador de uma pessoa.
pub const PREFIXO: &str = "pessoa:";

/// O identificador de uma pessoa: 8 bytes, sorteados no registro.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdPessoa(pub [u8; 8]);

impl IdPessoa {
    /// A forma escrita: `pessoa:` e 16 dígitos hexadecimais.
    pub fn texto(&self) -> String {
        format!("{PREFIXO}{}", crate::hex_de(&self.0))
    }

    /// Lê a forma escrita.
    pub fn ler(texto: &str) -> Option<IdPessoa> {
        crate::de_hex_fixo(texto.strip_prefix(PREFIXO)?).map(IdPessoa)
    }
}

/// O estado de uma pessoa no registro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Estado {
    /// Pode entrar.
    Ativa,
    /// Não entra mais. Continua no registro, para a auditoria.
    Revogada,
}

impl Estado {
    pub const fn nome(self) -> &'static str {
        match self {
            Estado::Ativa => "ativa",
            Estado::Revogada => "revogada",
        }
    }

    fn ler(texto: &str) -> Option<Estado> {
        match texto {
            "ativa" => Some(Estado::Ativa),
            "revogada" => Some(Estado::Revogada),
            _ => None,
        }
    }
}

/// Uma pessoa do registro.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pessoa {
    pub id: IdPessoa,
    pub nome: String,
    pub papel: String,
    pub estado: Estado,
    pub credencial: Credencial,
}

/// Por que uma linha não entrou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErroDeLinha {
    Id,
    Nome,
    Papel,
    Estado,
    Credencial,
    Falta,
    Sobra,
}

impl ErroDeLinha {
    pub const fn motivo(self) -> &'static str {
        match self {
            ErroDeLinha::Id => "identificador fora da forma pessoa:<16 hex>",
            ErroDeLinha::Nome => "nome fora da regra",
            ErroDeLinha::Papel => "papel fora da regra",
            ErroDeLinha::Estado => "estado que nao e ativa nem revogada",
            ErroDeLinha::Credencial => "credencial ilegivel ou de custo fora do aceitavel",
            ErroDeLinha::Falta => "falta um campo",
            ErroDeLinha::Sobra => "ha algo depois da credencial",
        }
    }
}

/// Lê uma linha do registro. `Ok(None)` para linha vazia ou comentário.
pub fn ler_linha(linha: &str) -> Result<Option<Pessoa>, ErroDeLinha> {
    let linha = linha.split('#').next().unwrap_or("").trim();
    if linha.is_empty() {
        return Ok(None);
    }
    let mut campos = linha.split_ascii_whitespace();
    let mut proximo = || campos.next().ok_or(ErroDeLinha::Falta);
    let id = IdPessoa::ler(proximo()?).ok_or(ErroDeLinha::Id)?;
    let nome = proximo()?;
    if !nome_valido(nome) {
        return Err(ErroDeLinha::Nome);
    }
    let papel = proximo()?;
    if !nome_valido(papel) {
        return Err(ErroDeLinha::Papel);
    }
    let estado = Estado::ler(proximo()?).ok_or(ErroDeLinha::Estado)?;
    let credencial = Credencial::ler(proximo()?).map_err(|_| ErroDeLinha::Credencial)?;
    if campos.next().is_some() {
        return Err(ErroDeLinha::Sobra);
    }
    Ok(Some(Pessoa {
        id,
        nome: nome.to_string(),
        papel: papel.to_string(),
        estado,
        credencial,
    }))
}

/// A linha de uma pessoa, como o registro a guarda.
pub fn linha(p: &Pessoa) -> String {
    format!(
        "{} {} {} {} {}\n",
        p.id.texto(),
        p.nome,
        p.papel,
        p.estado.nome(),
        p.credencial.escrever()
    )
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::credencial::{Custo, TAM_SAL, nova};

    fn exemplo() -> Pessoa {
        Pessoa {
            id: IdPessoa([0x9f, 0x2c, 0x41, 0xd0, 0x7a, 0x3b, 0x55, 0xe1]),
            nome: "maria".to_string(),
            papel: "operador".to_string(),
            estado: Estado::Ativa,
            credencial: nova(b"senha", [4; TAM_SAL], Custo::MINIMO).unwrap(),
        }
    }

    #[test]
    fn a_linha_vai_e_volta() {
        let p = exemplo();
        let l = linha(&p);
        assert!(l.starts_with("pessoa:9f2c41d07a3b55e1 maria operador ativa argon2id:"));
        assert_eq!(ler_linha(&l).unwrap(), Some(p));
        assert_eq!(ler_linha("  # so comentario").unwrap(), None);
    }

    /// O identificador de uma pessoa não é um nome de agente válido, e
    /// vice-versa: um não se passa pelo outro em texto.
    #[test]
    fn pessoa_e_agente_nao_se_confundem() {
        let id = exemplo().id.texto();
        assert!(!nome_valido(&id));
        assert_eq!(IdPessoa::ler("agente-1"), None);
        assert_eq!(IdPessoa::ler(&id), Some(exemplo().id));
    }

    #[test]
    fn revogada_continua_legivel() {
        let mut p = exemplo();
        p.estado = Estado::Revogada;
        assert_eq!(
            ler_linha(&linha(&p)).unwrap().unwrap().estado,
            Estado::Revogada
        );
    }

    #[test]
    fn linhas_ruins() {
        let boa = linha(&exemplo());
        let erro = |l: &str| ler_linha(l).unwrap_err();
        assert_eq!(erro(&boa.replace("pessoa:", "p:")), ErroDeLinha::Id);
        assert_eq!(erro(&boa.replace(" maria ", " Maria ")), ErroDeLinha::Nome);
        assert_eq!(erro(&boa.replace(" ativa ", " viva ")), ErroDeLinha::Estado);
        assert_eq!(
            erro(&boa.replace("argon2id", "md5")),
            ErroDeLinha::Credencial
        );
        assert_eq!(
            erro(&alloc::format!("{} x", boa.trim())),
            ErroDeLinha::Sobra
        );
        assert_eq!(erro("pessoa:9f2c41d07a3b55e1 maria"), ErroDeLinha::Falta);
    }
}
