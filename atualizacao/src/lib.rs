//! A atualização A/B do Duke: os formatos e as regras, testados no
//! hospedeiro.
//!
//! # O que é
//!
//! O disco tem dois slots, A e B. Cada um guarda uma versão inteira do
//! código que decide — o kernel e o pacote de programas e dados públicos —,
//! com um manifesto assinado por uma chave de atualização. Um slot é o que
//! roda; o outro recebe a versão nova. A versão nova só passa a ser a que
//! roda depois de bootar e se confirmar; até lá, a velha continua inteira no
//! outro slot, e qualquer falha volta para ela.
//!
//! # As peças
//!
//! - [`manifesto`]: o texto canônico que descreve uma imagem — arquitetura,
//!   versão, geração, os formatos de estado que ela lê, e o tamanho e o
//!   resumo do kernel e do pacote — e a assinatura Ed25519 sobre ele;
//! - [`cabecalho`]: os primeiros 4 KiB de um slot, com o manifesto, a
//!   assinatura e a chave que assinou;
//! - [`pacote`]: os arquivos do slot — os programas e os dados públicos —,
//!   num índice simples que o kernel monta por cima da raiz;
//! - [`controle`]: o controle de boot, que o iniciador lê antes do kernel
//!   existir: qual slot é o bom, qual está em tentativa, quantas tentativas
//!   restam;
//! - [`disco`]: as partições — o controle e os dois slots —, pelos tipos na
//!   GPT;
//! - [`estado`]: o estado da atualização que o journal guarda — a imagem
//!   ativa e, se há, a candidata —, as transições dele, e a reconciliação
//!   que o kernel faz a cada boot.
//!
//! O registro das chaves de atualização da máquina, `/etc/duke/atualizacao`,
//! tem o formato do registro de editores — `ed25519:<hex> <nome>` por
//! linha —, e o mesmo leitor, `sigilo::registro::ler_linha_de_editor`.
//!
//! # Quem decide
//!
//! O journal. Ele é ancorado no contador do TPM, e é por ele que um disco
//! devolvido a uma cópia antiga não passa: o piso de geração — a geração da
//! imagem ativa — mora nele, e não volta atrás sem que a âncora perceba. O controle de boot é um aviso
//! para o iniciador, que não lê o journal; o kernel o confere contra o
//! journal a cada boot e o regrava quando os dois discordam. Uma versão só
//! vira candidata por uma operação de quórum, no journal; só vira a ativa
//! depois de bootar, quando o kernel novo confirma a si mesmo no journal.
//!
//! # O que o iniciador confere, e o que não
//!
//! Resumos: o do manifesto contra o que o controle guarda para o slot, e o
//! do kernel contra o do manifesto. Não confere assinatura: a chave de
//! atualização está na raiz da máquina, que ele não lê, e a assinatura já
//! foi conferida pelo kernel que armou o slot — o resumo no controle é a
//! marca dessa conferência. Quem tem o disco na mão regrava o controle e o
//! iniciador junto; contra isso só o Secure Boot do firmware, que está fora
//! deste incremento.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod cabecalho;
pub mod controle;
pub mod disco;
pub mod estado;
pub mod manifesto;
pub mod pacote;

use blake2::{Blake2s256, Digest};

/// O tamanho de um resumo BLAKE2s-256.
pub const TAM_RESUMO: usize = 32;

/// O tamanho de um setor.
pub const TAM_SETOR: usize = 512;

/// Um dos dois slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    /// O outro.
    pub const fn outro(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    /// O byte com que o controle, o journal e a entrega o guardam.
    pub const fn byte(self) -> u8 {
        match self {
            Slot::A => 1,
            Slot::B => 2,
        }
    }

    /// O slot de um byte; zero e qualquer outro valor são nenhum.
    pub const fn do_byte(b: u8) -> Option<Slot> {
        match b {
            1 => Some(Slot::A),
            2 => Some(Slot::B),
            _ => None,
        }
    }

    /// O índice, para tabelas de dois.
    pub const fn indice(self) -> usize {
        match self {
            Slot::A => 0,
            Slot::B => 1,
        }
    }

    /// O nome, para o log, a auditoria e as respostas.
    pub const fn nome(self) -> &'static str {
        match self {
            Slot::A => "a",
            Slot::B => "b",
        }
    }
}

/// A arquitetura de uma imagem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arquitetura {
    X86_64,
    Aarch64,
}

impl Arquitetura {
    /// O nome no manifesto.
    pub const fn nome(self) -> &'static str {
        match self {
            Arquitetura::X86_64 => "x86_64",
            Arquitetura::Aarch64 => "aarch64",
        }
    }

    /// A arquitetura de um nome.
    pub fn do_nome(nome: &str) -> Option<Arquitetura> {
        match nome {
            "x86_64" => Some(Arquitetura::X86_64),
            "aarch64" => Some(Arquitetura::Aarch64),
            _ => None,
        }
    }
}

/// O BLAKE2s-256 de `bytes` — o mesmo resumo com que o journal encadeia os
/// registros e o selo nomeia o código.
pub fn resumo(bytes: &[u8]) -> [u8; TAM_RESUMO] {
    Blake2s256::digest(bytes).into()
}

/// Um resumo calculado por pedaços: o kernel e o iniciador leem o slot do
/// disco em partes, e não cabe pedir a imagem inteira de uma vez.
pub struct Resumidor(Blake2s256);

impl Resumidor {
    pub fn novo() -> Resumidor {
        Resumidor(Blake2s256::new())
    }

    pub fn somar(&mut self, pedaco: &[u8]) {
        self.0.update(pedaco);
    }

    pub fn terminar(self) -> [u8; TAM_RESUMO] {
        self.0.finalize().into()
    }
}

impl Default for Resumidor {
    fn default() -> Self {
        Resumidor::novo()
    }
}

/// Um resumo em hexadecimal minúsculo, num buffer fixo — sem `alloc`.
pub fn hex_do_resumo(r: &[u8; TAM_RESUMO]) -> [u8; 2 * TAM_RESUMO] {
    const DIGITOS: &[u8; 16] = b"0123456789abcdef";
    let mut s = [0u8; 2 * TAM_RESUMO];
    for (i, b) in r.iter().enumerate() {
        s[2 * i] = DIGITOS[usize::from(b >> 4)];
        s[2 * i + 1] = DIGITOS[usize::from(b & 0xF)];
    }
    s
}

/// Um resumo de um texto hexadecimal minúsculo de 64 dígitos — a única
/// grafia aceita: maiúsculas, espaços ou outro tamanho são recusados, para
/// que um resumo tenha uma escrita só.
pub fn resumo_do_hex(texto: &str) -> Option<[u8; TAM_RESUMO]> {
    let b = texto.as_bytes();
    if b.len() != 2 * TAM_RESUMO {
        return None;
    }
    let digito = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut r = [0u8; TAM_RESUMO];
    for (i, [alto, baixo]) in b.as_chunks::<2>().0.iter().enumerate() {
        r[i] = digito(*alto)? << 4 | digito(*baixo)?;
    }
    Some(r)
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn o_resumo_por_pedacos_e_o_mesmo() {
        let dados: [u8; 1000] = core::array::from_fn(|i| (i * 7) as u8);
        let mut r = Resumidor::novo();
        for pedaco in dados.chunks(77) {
            r.somar(pedaco);
        }
        assert_eq!(r.terminar(), resumo(&dados));
    }

    #[test]
    fn o_hex_tem_uma_grafia_so() {
        let r = resumo(b"duke");
        let hex = hex_do_resumo(&r);
        let texto = core::str::from_utf8(&hex).unwrap();
        assert_eq!(resumo_do_hex(texto), Some(r));
        let maiusculo: [u8; 64] = core::array::from_fn(|i| hex[i].to_ascii_uppercase());
        let maiusculo = core::str::from_utf8(&maiusculo).unwrap();
        if maiusculo != texto {
            assert_eq!(resumo_do_hex(maiusculo), None);
        }
        assert_eq!(resumo_do_hex(&texto[..62]), None);
        assert_eq!(resumo_do_hex(""), None);
    }

    #[test]
    fn os_slots_vao_e_voltam_pelo_byte() {
        for s in [Slot::A, Slot::B] {
            assert_eq!(Slot::do_byte(s.byte()), Some(s));
            assert_eq!(s.outro().outro(), s);
            assert_ne!(s.outro(), s);
        }
        assert_eq!(Slot::do_byte(0), None);
        assert_eq!(Slot::do_byte(3), None);
    }
}
