//! O manifesto de uma imagem: o que ela é, e o resumo de cada parte.
//!
//! # O formato
//!
//! Texto, sete linhas, nesta ordem, cada uma `chave valor` com um espaço só
//! e terminada em `\n`:
//!
//! ```text
//! formato 1
//! arquitetura x86_64
//! versao 2026.10.1
//! geracao 7
//! estado 1 1
//! kernel 4728328 <blake2s em hex>
//! pacote 3100000 <blake2s em hex>
//! ```
//!
//! - `formato`: o deste texto — hoje 1;
//! - `arquitetura`: `x86_64` ou `aarch64`;
//! - `versao`: o rótulo, para quem lê — de 1 a [`MAIOR_VERSAO`] caracteres
//!   de `[0-9A-Za-z._+-]`; não se compara;
//! - `geracao`: o número que o anti-rollback compara. Sobe a cada imagem
//!   publicada: uma atualização tem de ter geração **maior** que a ativa, e
//!   nenhuma imagem de geração menor que o piso da máquina roda;
//! - `estado`: o menor e o maior formato do estado persistente — o journal e
//!   o armazém — que a imagem lê e grava. A máquina recusa uma imagem que
//!   não lê o formato de agora;
//! - `kernel`, `pacote`: o tamanho em bytes e o BLAKE2s-256 de cada parte.
//!
//! # Uma grafia só
//!
//! O leitor confere que o texto é **exatamente** o que [`Manifesto::escrever_em`]
//! escreveria do que ele leu: sem espaço sobrando, sem zero à esquerda, sem
//! maiúscula no hexadecimal, sem linha a mais. Dois textos diferentes nunca
//! descrevem a mesma imagem — e o resumo do manifesto, que o quórum assina
//! e o journal guarda, nomeia uma imagem só.
//!
//! # A assinatura
//!
//! Ed25519 (RFC 8032), sobre o rótulo deste protocolo seguido do resumo
//! BLAKE2s-256 do manifesto — o arranjo do selo do código. A conferência é a
//! estrita (`verify_strict`). O rótulo separa esta assinatura de qualquer
//! outra feita com a mesma chave: uma assinatura de manifesto não vale como
//! selo, nem como quórum.

use crate::{Arquitetura, TAM_RESUMO, hex_do_resumo, resumo, resumo_do_hex};

/// O formato deste texto.
pub const FORMATO: u32 = 1;

/// O maior rótulo de versão.
pub const MAIOR_VERSAO: usize = 32;

/// O maior manifesto: as sete linhas com os maiores valores cabem com
/// folga.
pub const MAIOR_MANIFESTO: usize = 512;

/// O tamanho de uma assinatura Ed25519.
pub const TAM_ASSINATURA: usize = 64;

/// O tamanho de uma chave pública Ed25519.
pub const TAM_CHAVE: usize = 32;

/// O rótulo que vai na frente do resumo assinado.
#[cfg(feature = "conferir")]
const ROTULO: &[u8] = b"Duke atualizacao: manifesto ed25519 v1";

/// Uma parte da imagem: quantos bytes, e o resumo deles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parte {
    pub tamanho: u64,
    pub resumo: [u8; TAM_RESUMO],
}

/// Um manifesto lido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Manifesto<'a> {
    pub arquitetura: Arquitetura,
    pub versao: &'a str,
    pub geracao: u64,
    pub estado_minimo: u32,
    pub estado_maximo: u32,
    pub kernel: Parte,
    pub pacote: Parte,
}

/// Um decimal sem sinal e sem zero à esquerda.
fn numero(texto: &str) -> Option<u64> {
    let b = texto.as_bytes();
    if b.is_empty() || (b.len() > 1 && b[0] == b'0') || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    texto.parse().ok()
}

/// Se `v` segue a regra do rótulo de versão.
pub fn versao_valida(v: &str) -> bool {
    (1..=MAIOR_VERSAO).contains(&v.len())
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'+' | b'-'))
}

/// Uma parte: `<tamanho> <resumo>`.
fn parte(valor: &str) -> Option<Parte> {
    let (tamanho, r) = valor.split_once(' ')?;
    Some(Parte {
        tamanho: numero(tamanho)?,
        resumo: resumo_do_hex(r)?,
    })
}

impl<'a> Manifesto<'a> {
    /// Lê um manifesto. `Err` com a linha (contada de 1; zero para o texto
    /// inteiro) e o motivo.
    pub fn ler(bytes: &'a [u8]) -> Result<Manifesto<'a>, (usize, &'static str)> {
        if bytes.len() > MAIOR_MANIFESTO {
            return Err((0, "manifesto maior que o teto"));
        }
        let texto = core::str::from_utf8(bytes).map_err(|_| (0, "manifesto nao e texto"))?;
        if !texto.ends_with('\n') {
            return Err((0, "manifesto sem o fim de linha final"));
        }
        let mut linhas = texto[..texto.len() - 1].split('\n');
        let mut n = 0usize;
        let mut proxima = |chave: &'static str| -> Result<&'a str, (usize, &'static str)> {
            n += 1;
            let linha = linhas.next().ok_or((n, "falta uma linha"))?;
            let (k, v) = linha.split_once(' ').ok_or((n, "linha sem valor"))?;
            if k != chave {
                return Err((n, "linha fora de ordem ou desconhecida"));
            }
            Ok(v)
        };
        let formato = proxima("formato")?;
        if numero(formato) != Some(u64::from(FORMATO)) {
            return Err((1, "formato de manifesto desconhecido"));
        }
        let arquitetura =
            Arquitetura::do_nome(proxima("arquitetura")?).ok_or((2, "arquitetura desconhecida"))?;
        let versao = proxima("versao")?;
        if !versao_valida(versao) {
            return Err((3, "versao fora da regra"));
        }
        let geracao = numero(proxima("geracao")?).ok_or((4, "geracao nao e numero"))?;
        if geracao == 0 {
            return Err((4, "geracao zero"));
        }
        let (minimo, maximo) = proxima("estado")?
            .split_once(' ')
            .ok_or((5, "estado sem os dois formatos"))?;
        let minimo = numero(minimo)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or((5, "formato de estado nao e numero"))?;
        let maximo = numero(maximo)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or((5, "formato de estado nao e numero"))?;
        if minimo == 0 || maximo < minimo {
            return Err((5, "faixa de formatos de estado invalida"));
        }
        let kernel = parte(proxima("kernel")?).ok_or((6, "kernel sem tamanho e resumo"))?;
        if kernel.tamanho == 0 {
            return Err((6, "kernel vazio"));
        }
        let pacote = parte(proxima("pacote")?).ok_or((7, "pacote sem tamanho e resumo"))?;
        if linhas.next().is_some() {
            return Err((8, "linha a mais"));
        }
        let m = Manifesto {
            arquitetura,
            versao,
            geracao,
            estado_minimo: minimo,
            estado_maximo: maximo,
            kernel,
            pacote,
        };
        // A grafia: o que se leu tem de ser o que se escreveria.
        let mut canonico = [0u8; MAIOR_MANIFESTO];
        match m.escrever_em(&mut canonico) {
            Some(tamanho) if &canonico[..tamanho] == bytes => Ok(m),
            _ => Err((0, "manifesto fora da grafia canonica")),
        }
    }

    /// Escreve o texto em `destino`, devolvendo quantos bytes; `None` se não
    /// couber.
    pub fn escrever_em(&self, destino: &mut [u8]) -> Option<usize> {
        let mut w = Escrita {
            destino,
            usado: 0,
            cabe: true,
        };
        w.linha_numero("formato", u64::from(FORMATO));
        w.texto("arquitetura ");
        w.texto(self.arquitetura.nome());
        w.texto("\n");
        w.texto("versao ");
        w.texto(self.versao);
        w.texto("\n");
        w.linha_numero("geracao", self.geracao);
        w.texto("estado ");
        w.numero(u64::from(self.estado_minimo));
        w.texto(" ");
        w.numero(u64::from(self.estado_maximo));
        w.texto("\n");
        for (chave, p) in [("kernel", &self.kernel), ("pacote", &self.pacote)] {
            w.texto(chave);
            w.texto(" ");
            w.numero(p.tamanho);
            w.texto(" ");
            let hex = hex_do_resumo(&p.resumo);
            w.bytes(&hex);
            w.texto("\n");
        }
        w.cabe.then_some(w.usado)
    }

    /// O texto, inteiro.
    #[cfg(feature = "alloc")]
    pub fn escrever(&self) -> alloc::vec::Vec<u8> {
        let mut buffer = [0u8; MAIOR_MANIFESTO];
        let n = self
            .escrever_em(&mut buffer)
            .expect("um manifesto valido cabe no teto");
        buffer[..n].to_vec()
    }

    /// Se a imagem lê e grava o formato de estado `formato`.
    pub const fn le_o_estado(&self, formato: u32) -> bool {
        self.estado_minimo <= formato && formato <= self.estado_maximo
    }
}

/// Um escritor num buffer fixo, que lembra se algo não coube.
struct Escrita<'d> {
    destino: &'d mut [u8],
    usado: usize,
    cabe: bool,
}

impl Escrita<'_> {
    fn bytes(&mut self, b: &[u8]) {
        match self.destino.get_mut(self.usado..self.usado + b.len()) {
            Some(d) if self.cabe => {
                d.copy_from_slice(b);
                self.usado += b.len();
            }
            _ => self.cabe = false,
        }
    }

    fn texto(&mut self, t: &str) {
        self.bytes(t.as_bytes());
    }

    fn numero(&mut self, mut v: u64) {
        let mut digitos = [0u8; 20];
        let mut i = digitos.len();
        loop {
            i -= 1;
            digitos[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let d = digitos;
        self.bytes(&d[i..]);
    }

    fn linha_numero(&mut self, chave: &str, v: u64) {
        self.texto(chave);
        self.texto(" ");
        self.numero(v);
        self.texto("\n");
    }
}

/// O resumo de um manifesto: o que o controle de boot, o journal e o quórum
/// usam para nomear a imagem.
pub fn resumo_do_manifesto(manifesto: &[u8]) -> [u8; TAM_RESUMO] {
    resumo(manifesto)
}

/// O que se assina: o rótulo e o resumo do manifesto.
#[cfg(feature = "conferir")]
fn mensagem(manifesto: &[u8]) -> [u8; ROTULO.len() + TAM_RESUMO] {
    let mut m = [0u8; ROTULO.len() + TAM_RESUMO];
    m[..ROTULO.len()].copy_from_slice(ROTULO);
    m[ROTULO.len()..].copy_from_slice(&resumo(manifesto));
    m
}

/// Confere a assinatura de `manifesto` com a chave pública `chave`.
///
/// A estrita: recusa a chave de ordem pequena e a assinatura maleável. Uma
/// chave que não é ponto da curva também é `false`.
#[cfg(feature = "conferir")]
pub fn conferir(
    manifesto: &[u8],
    assinatura: &[u8; TAM_ASSINATURA],
    chave: &[u8; TAM_CHAVE],
) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Ok(publica) = VerifyingKey::from_bytes(chave) else {
        return false;
    };
    publica
        .verify_strict(&mensagem(manifesto), &Signature::from_bytes(assinatura))
        .is_ok()
}

/// Assina `manifesto` com a chave privada `privada` — no `xtask`, com a
/// chave de atualização de quem publica.
#[cfg(feature = "assinar")]
pub fn assinar(manifesto: &[u8], privada: &[u8; TAM_CHAVE]) -> [u8; TAM_ASSINATURA] {
    use ed25519_dalek::{Signer, SigningKey};
    SigningKey::from_bytes(privada)
        .sign(&mensagem(manifesto))
        .to_bytes()
}

/// A chave pública de uma privada de atualização.
#[cfg(feature = "assinar")]
pub fn publica_de(privada: &[u8; TAM_CHAVE]) -> [u8; TAM_CHAVE] {
    ed25519_dalek::SigningKey::from_bytes(privada)
        .verifying_key()
        .to_bytes()
}

#[cfg(test)]
mod testes {
    use super::*;

    pub(crate) fn exemplo() -> Manifesto<'static> {
        Manifesto {
            arquitetura: Arquitetura::X86_64,
            versao: "2026.10.1",
            geracao: 7,
            estado_minimo: 1,
            estado_maximo: 1,
            kernel: Parte {
                tamanho: 4_728_328,
                resumo: resumo(b"kernel"),
            },
            pacote: Parte {
                tamanho: 0,
                resumo: resumo(b""),
            },
        }
    }

    fn texto(m: &Manifesto) -> ([u8; MAIOR_MANIFESTO], usize) {
        let mut b = [0u8; MAIOR_MANIFESTO];
        let n = m.escrever_em(&mut b).unwrap();
        (b, n)
    }

    #[test]
    fn ida_e_volta() {
        let m = exemplo();
        let (b, n) = texto(&m);
        assert_eq!(Manifesto::ler(&b[..n]), Ok(m));
        let t = core::str::from_utf8(&b[..n]).unwrap();
        assert!(t.starts_with("formato 1\narquitetura x86_64\nversao 2026.10.1\ngeracao 7\n"));
    }

    #[test]
    fn recusa_o_que_nao_e_canonico() {
        let (b, n) = texto(&exemplo());
        let t = core::str::from_utf8(&b[..n]).unwrap();
        let ruins: [(&str, &str); 12] = [
            ("geracao 7\n", "geracao 07\n"),
            ("geracao 7\n", "geracao  7\n"),
            ("geracao 7\n", "geracao 0\n"),
            ("formato 1\n", "formato 2\n"),
            ("arquitetura x86_64\n", "arquitetura riscv64\n"),
            ("versao 2026.10.1\n", "versao 2026 10 1\n"),
            ("versao 2026.10.1\n", "versao \n"),
            ("estado 1 1\n", "estado 2 1\n"),
            ("estado 1 1\n", "estado 0 1\n"),
            ("kernel 4728328 ", "kernel 0 "),
            ("arquitetura x86_64\nversao", "versao"),
            ("\n", "\r\n"),
        ];
        for (de, para) in ruins {
            let ruim = t.replacen(de, para, 1);
            assert!(
                Manifesto::ler(ruim.as_bytes()).is_err(),
                "aceitou: {ruim:?}"
            );
        }
        // O hexadecimal em maiúsculas é outra grafia.
        let hex = core::str::from_utf8(&hex_do_resumo(&resumo(b"kernel")))
            .unwrap()
            .to_string();
        let ruim = t.replace(&hex, &hex.to_ascii_uppercase());
        if ruim != t {
            assert!(Manifesto::ler(ruim.as_bytes()).is_err());
        }
        // Sem o fim de linha final; com uma linha a mais.
        assert!(Manifesto::ler(&b[..n - 1]).is_err());
        let mais = alloc_concat(&b[..n], b"extra 1\n");
        assert!(Manifesto::ler(&mais).is_err());
    }

    fn alloc_concat(a: &[u8], b: &[u8]) -> std::vec::Vec<u8> {
        let mut v = a.to_vec();
        v.extend_from_slice(b);
        v
    }

    #[test]
    fn o_estado_que_a_imagem_le() {
        let mut m = exemplo();
        m.estado_minimo = 2;
        m.estado_maximo = 4;
        assert!(!m.le_o_estado(1));
        assert!(m.le_o_estado(2) && m.le_o_estado(4));
        assert!(!m.le_o_estado(5));
    }

    extern crate std;
    use std::string::ToString;
}

#[cfg(all(test, feature = "assinar"))]
mod testes_da_assinatura {
    use super::*;

    #[test]
    fn a_assinatura_confere_so_com_o_manifesto_e_a_chave() {
        let privada = [7u8; 32];
        let outra = [8u8; 32];
        let publica = publica_de(&privada);
        let manifesto = b"formato 1\n";
        let a = assinar(manifesto, &privada);
        assert!(conferir(manifesto, &a, &publica));
        assert!(!conferir(b"formato 2\n", &a, &publica));
        assert!(!conferir(manifesto, &a, &publica_de(&outra)));
        let mut trocada = a;
        trocada[10] ^= 1;
        assert!(!conferir(manifesto, &trocada, &publica));
        // A chave toda zero não é ponto válido de ordem cheia.
        assert!(!conferir(manifesto, &a, &[0u8; 32]));
        // A imagem sem assinatura: o campo zerado, como sai de um build
        // que não passou pelo `publicar`.
        assert!(!conferir(manifesto, &[0u8; TAM_ASSINATURA], &publica));
    }

    #[test]
    fn o_rotulo_separa_dos_outros_protocolos() {
        // A mesma chave, assinando o resumo cru (sem o rótulo), não faz uma
        // assinatura de manifesto.
        use ed25519_dalek::{Signer, SigningKey};
        let privada = [9u8; 32];
        let manifesto = b"formato 1\n";
        let crua = SigningKey::from_bytes(&privada)
            .sign(&resumo(manifesto))
            .to_bytes();
        assert!(!conferir(manifesto, &crua, &publica_de(&privada)));
    }
}
