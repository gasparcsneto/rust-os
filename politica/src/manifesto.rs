//! O manifesto de um programa: quem ele diz ser, e o que pretende fazer.
//!
//! # Para que serve
//!
//! Um processo age com a autoridade de quem o lançou — o sistema, um agente,
//! uma pessoa. Sem mais nada, todo programa que alguém lança pode tudo que
//! esse alguém pode: o visualizador de texto que um operador abre lê os
//! arquivos dele, e também manda mensagens em nome dele, e lança outros
//! programas. O manifesto é o programa dizendo, no próprio executável, o que
//! pretende exercer; a permissão efetiva do processo é a **interseção** do
//! papel de quem o lançou com o manifesto. Um programa nunca ganha nada por
//! declarar — a política continua decidindo —, e perde o que não declarou.
//!
//! # O formato
//!
//! Texto, em linhas, no conteúdo da nota `Duke` do executável (ver
//! `protocolo::usuario::manifesto`):
//!
//! ```text
//! duke-manifesto 1
//! nome visualizador
//! permite fs.read system.read
//! ```
//!
//! - a primeira linha é o cabeçalho, exato: um manifesto de outra versão é
//!   recusado, e não lido pela metade;
//! - `nome` uma vez, com o alfabeto dos nomes de papel e de agente;
//! - `permite` quantas vezes quiser, com nomes do vocabulário fechado de
//!   [`Permissao`]. Um nome fora dele recusa o manifesto inteiro, como recusa
//!   a política — `fs.raed` não é uma permissão que ninguém confere;
//! - as permissões administrativas e `debug.trigger` não se declaram: um
//!   processo nunca as exerce — são da prova de um administrador e de um
//!   canal do agente —, e declará-las é um engano que vale dizer.
//!
//! # Por que é puro
//!
//! Pelo mesmo motivo do resto deste pacote: o kernel o lê de um executável
//! que veio do disco, e a leitura é entrada hostil. Aqui ela é testada no
//! hospedeiro, linha por linha.

use crate::permissao::{Permissao, TODAS};

/// A primeira linha de todo manifesto desta versão.
pub const CABECALHO: &str = "duke-manifesto 1";

/// O maior nome de programa.
pub const MAIOR_NOME: usize = 32;

const _: () = assert!(TODAS.len() <= 64, "as permissoes nao cabem no conjunto");

/// Um conjunto de permissões, um bit por permissão.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Permissoes(u64);

impl Permissoes {
    /// Nenhuma: a de um executável sem manifesto.
    pub const NENHUMA: Permissoes = Permissoes(0);

    const fn bit(p: Permissao) -> u64 {
        1 << (p as u32)
    }

    /// Se `p` está no conjunto.
    pub const fn contem(self, p: Permissao) -> bool {
        self.0 & Self::bit(p) != 0
    }

    /// Põe `p` no conjunto.
    pub fn inserir(&mut self, p: Permissao) {
        self.0 |= Self::bit(p);
    }

    /// As permissões do conjunto, na ordem de [`TODAS`].
    pub fn iter(self) -> impl Iterator<Item = Permissao> {
        TODAS.into_iter().filter(move |&p| self.contem(p))
    }

    /// Se não há nenhuma.
    pub const fn vazio(self) -> bool {
        self.0 == 0
    }
}

/// Um manifesto lido e conferido.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Manifesto {
    nome: [u8; MAIOR_NOME],
    tamanho: u8,
    /// O que o programa declara que vai exercer.
    pub permite: Permissoes,
}

impl Manifesto {
    /// O nome que o programa declara.
    pub fn nome(&self) -> &str {
        // Só entra aqui o que passou por `nome_valido`: ASCII.
        core::str::from_utf8(&self.nome[..usize::from(self.tamanho)]).unwrap_or("?")
    }
}

/// Por que um manifesto foi recusado. A linha, quando é de uma linha,
/// contada a partir de 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Erro {
    /// Não é texto, ou não começa pelo cabeçalho desta versão.
    Cabecalho,
    /// Uma linha que não é `nome` nem `permite`.
    Linha(usize),
    /// O nome não é aceitável, ou falta.
    Nome(usize),
    /// Dois nomes.
    NomeRepetido(usize),
    /// Nenhum nome.
    SemNome,
    /// Uma permissão fora do vocabulário.
    PermissaoDesconhecida(usize),
    /// Uma permissão que um processo nunca exerce.
    PermissaoDeProcesso(usize),
}

impl Erro {
    /// A recusa, para o log.
    pub fn motivo(&self) -> &'static str {
        match self {
            Erro::Cabecalho => "o manifesto nao comeca pelo cabecalho desta versao",
            Erro::Linha(_) => "uma linha do manifesto nao e nome nem permite",
            Erro::Nome(_) => "o nome do manifesto nao e aceitavel",
            Erro::NomeRepetido(_) => "o manifesto tem dois nomes",
            Erro::SemNome => "o manifesto nao tem nome",
            Erro::PermissaoDesconhecida(_) => "o manifesto declara uma permissao que nao existe",
            Erro::PermissaoDeProcesso(_) => {
                "o manifesto declara uma permissao que um processo nao exerce"
            }
        }
    }
}

/// Uma permissão que um processo pode declarar: as administrativas são da
/// prova de um administrador, e `debug.trigger` é de um canal do agente.
pub const fn declaravel(p: Permissao) -> bool {
    !p.administrativa() && !matches!(p, Permissao::DebugTrigger)
}

/// Lê um manifesto.
pub fn ler(bytes: &[u8]) -> Result<Manifesto, Erro> {
    let texto = core::str::from_utf8(bytes).map_err(|_| Erro::Cabecalho)?;
    let mut linhas = texto.split('\n').enumerate();
    match linhas.next() {
        Some((_, primeira)) if primeira == CABECALHO => {}
        _ => return Err(Erro::Cabecalho),
    }
    let mut nome: Option<&str> = None;
    let mut permite = Permissoes::NENHUMA;
    for (i, linha) in linhas {
        let n = i + 1;
        if linha.is_empty() {
            continue;
        }
        let mut partes = linha.split(' ');
        match partes.next() {
            Some("nome") => {
                let valor = partes.next().ok_or(Erro::Nome(n))?;
                if partes.next().is_some() || !crate::arquivo::nome_valido(valor) {
                    return Err(Erro::Nome(n));
                }
                if nome.replace(valor).is_some() {
                    return Err(Erro::NomeRepetido(n));
                }
            }
            Some("permite") => {
                for p in partes {
                    let p = Permissao::de_nome(p).ok_or(Erro::PermissaoDesconhecida(n))?;
                    if !declaravel(p) {
                        return Err(Erro::PermissaoDeProcesso(n));
                    }
                    permite.inserir(p);
                }
            }
            _ => return Err(Erro::Linha(n)),
        }
    }
    let nome = nome.ok_or(Erro::SemNome)?;
    let mut bytes = [0u8; MAIOR_NOME];
    bytes[..nome.len()].copy_from_slice(nome.as_bytes());
    Ok(Manifesto {
        nome: bytes,
        tamanho: nome.len() as u8,
        permite,
    })
}

/// O resumo BLAKE2s-256 de uma imagem: a identidade do executável, que a
/// auditoria pode citar ao lado do nome que ele declara.
pub fn resumo_da_imagem(imagem: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    let mut h = blake2::Blake2s256::new();
    h.update(imagem);
    h.finalize().into()
}

#[cfg(test)]
mod testes {
    use super::*;

    fn ok(texto: &str) -> Manifesto {
        ler(texto.as_bytes()).unwrap()
    }

    #[test]
    fn le_o_nome_e_as_permissoes() {
        let m = ok("duke-manifesto 1\nnome visualizador\npermite fs.read system.read\n");
        assert_eq!(m.nome(), "visualizador");
        assert!(m.permite.contem(Permissao::FsRead));
        assert!(m.permite.contem(Permissao::SystemRead));
        assert!(!m.permite.contem(Permissao::MessageSend));
        assert_eq!(m.permite.iter().count(), 2);
    }

    #[test]
    fn permite_pode_repetir_e_pode_faltar() {
        let m = ok("duke-manifesto 1\nnome a\npermite fs.read\npermite ui.read\n");
        assert_eq!(m.permite.iter().count(), 2);
        let m = ok("duke-manifesto 1\nnome so-o-nome");
        assert!(m.permite.vazio());
        // `permite` sem nada também é nada.
        assert!(ok("duke-manifesto 1\nnome a\npermite\n").permite.vazio());
    }

    #[test]
    fn o_cabecalho_e_exato() {
        for texto in [
            "",
            "nome a\n",
            "duke-manifesto 2\nnome a\n",
            "duke-manifesto 1 \nnome a\n",
            " duke-manifesto 1\nnome a\n",
        ] {
            assert_eq!(ler(texto.as_bytes()), Err(Erro::Cabecalho), "{texto:?}");
        }
        assert_eq!(ler(&[0xff, 0xfe]), Err(Erro::Cabecalho));
    }

    #[test]
    fn o_vocabulario_e_fechado() {
        assert_eq!(
            ler(b"duke-manifesto 1\nnome a\npermite fs.raed\n"),
            Err(Erro::PermissaoDesconhecida(3))
        );
        // Dois espaços são uma permissão vazia, e vazia não existe.
        assert_eq!(
            ler(b"duke-manifesto 1\nnome a\npermite fs.read  ui.read\n"),
            Err(Erro::PermissaoDesconhecida(3))
        );
    }

    #[test]
    fn o_que_um_processo_nao_exerce_nao_se_declara() {
        for p in TODAS {
            let texto = alloc::format!("duke-manifesto 1\nnome a\npermite {}\n", p.nome());
            let lido = ler(texto.as_bytes());
            if declaravel(p) {
                assert!(lido.is_ok(), "{}", p.nome());
            } else {
                assert_eq!(lido, Err(Erro::PermissaoDeProcesso(3)), "{}", p.nome());
            }
        }
        assert!(!declaravel(Permissao::DebugTrigger));
        assert!(!declaravel(Permissao::AgentRegister));
        assert!(declaravel(Permissao::MessageSend));
    }

    #[test]
    fn o_nome_e_um_so_e_aceitavel() {
        assert_eq!(
            ler(b"duke-manifesto 1\npermite fs.read\n"),
            Err(Erro::SemNome)
        );
        assert_eq!(
            ler(b"duke-manifesto 1\nnome a\nnome b\n"),
            Err(Erro::NomeRepetido(3))
        );
        for nome in ["", "Maiusculo", "com espaco", "barra/nao", &"x".repeat(33)] {
            let texto = alloc::format!("duke-manifesto 1\nnome {nome}\n");
            assert!(
                matches!(ler(texto.as_bytes()), Err(Erro::Nome(2))),
                "{nome:?}"
            );
        }
        let m = ok(&alloc::format!(
            "duke-manifesto 1\nnome {}\n",
            "x".repeat(32)
        ));
        assert_eq!(m.nome().len(), 32);
    }

    #[test]
    fn linha_desconhecida_recusa() {
        assert_eq!(
            ler(b"duke-manifesto 1\nnome a\nconcede tudo\n"),
            Err(Erro::Linha(3))
        );
        assert_eq!(ler(b"duke-manifesto 1\nnome a\r\n"), Err(Erro::Nome(2)));
    }

    #[test]
    fn o_conjunto_tem_todas() {
        let mut todas = Permissoes::NENHUMA;
        for p in TODAS {
            assert!(!todas.contem(p));
            todas.inserir(p);
            assert!(todas.contem(p));
        }
        assert_eq!(todas.iter().count(), TODAS.len());
    }

    /// A permissão mais nova cabe no manifesto, no bit dela.
    #[test]
    fn random_read_no_manifesto() {
        let m = ok("duke-manifesto 1\nnome cifrado\npermite net.connect random.read\n");
        assert!(m.permite.contem(crate::Permissao::RandomRead));
        assert!(m.permite.contem(crate::Permissao::NetConnect));
        assert!(!m.permite.contem(crate::Permissao::FsRead));
    }

    #[test]
    fn o_resumo_e_da_imagem() {
        assert_ne!(resumo_da_imagem(b"a"), resumo_da_imagem(b"b"));
        assert_eq!(resumo_da_imagem(b"a"), resumo_da_imagem(b"a"));
    }
}
