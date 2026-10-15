//! Uma mensagem: o cabeçalho, as etiquetas e os valores.
//!
//! **Reproduzido**, nos dois pares de vetores:
//!
//! - o cabeçalho é um `uint32` little-endian com o número n de etiquetas;
//!   depois n − 1 deslocamentos `uint32` little-endian; depois as n
//!   etiquetas, de 4 bytes cada;
//! - os valores vêm em seguida, um depois do outro: o valor i começa no
//!   deslocamento i − 1 (o primeiro começa em zero), e o último vai até o
//!   fim da mensagem;
//! - as etiquetas vêm em ordem **estritamente crescente do valor
//!   little-endian** dos 4 bytes — `SIG\0` antes de `NONC`, ao contrário da
//!   ordem do ASCII —, e por isso uma etiqueta não se repete.
//!
//! **Referência:** os deslocamentos são múltiplos de quatro e não
//! decrescem (RFC 4.2), e uma etiqueta que este lado não conhece é ignorada,
//! no topo e dentro das mensagens aninhadas (RFC 7 e 9.2).
//!
//! **Pendente:** o teto [`MAIS_ETIQUETAS`] é nosso.
//!
//! O leitor não copia nada: cada valor é uma fatia dos bytes recebidos. As
//! assinaturas são conferidas sobre essas fatias, e nunca sobre uma
//! mensagem reescrita, que perderia as etiquetas que este lado ignora.

/// Uma etiqueta: 4 bytes ASCII.
pub type Etiqueta = [u8; 4];

pub const SIG: Etiqueta = *b"SIG\0";
pub const VER: Etiqueta = *b"VER\0";
pub const SRV: Etiqueta = *b"SRV\0";
pub const NONC: Etiqueta = *b"NONC";
pub const TYPE: Etiqueta = *b"TYPE";
pub const ZZZZ: Etiqueta = *b"ZZZZ";
pub const PATH: Etiqueta = *b"PATH";
pub const SREP: Etiqueta = *b"SREP";
pub const CERT: Etiqueta = *b"CERT";
pub const INDX: Etiqueta = *b"INDX";
pub const RADI: Etiqueta = *b"RADI";
pub const MIDP: Etiqueta = *b"MIDP";
pub const VERS: Etiqueta = *b"VERS";
pub const ROOT: Etiqueta = *b"ROOT";
pub const DELE: Etiqueta = *b"DELE";
pub const PUBK: Etiqueta = *b"PUBK";
pub const MINT: Etiqueta = *b"MINT";
pub const MAXT: Etiqueta = *b"MAXT";

/// O maior número de etiquetas numa mensagem. Uma resposta da RFC tem
/// sete no topo; o resto é folga para etiquetas novas.
pub const MAIS_ETIQUETAS: usize = 32;

/// A chave de ordenação de uma etiqueta: o valor little-endian dos 4 bytes.
pub const fn chave(etiqueta: Etiqueta) -> u32 {
    u32::from_le_bytes(etiqueta)
}

/// Por que uma mensagem não se lê.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Falha {
    /// Mais curta que o cabeçalho que ela mesma declara.
    Curta,
    /// Nenhuma etiqueta, ou mais que [`MAIS_ETIQUETAS`].
    Etiquetas,
    /// Um deslocamento que não é múltiplo de quatro, que volta, ou que
    /// passa do fim.
    Deslocamento,
    /// Etiquetas fora da ordem crescente, ou repetidas.
    Ordem,
}

/// Uma mensagem já conferida: os bytes e o número de etiquetas.
#[derive(Debug, Clone, Copy)]
pub struct Mensagem<'a> {
    bytes: &'a [u8],
    n: usize,
}

fn u32_em(bytes: &[u8], posicao: usize) -> u32 {
    u32::from_le_bytes([
        bytes[posicao],
        bytes[posicao + 1],
        bytes[posicao + 2],
        bytes[posicao + 3],
    ])
}

impl<'a> Mensagem<'a> {
    /// Confere o cabeçalho inteiro: o número de etiquetas, os deslocamentos
    /// e a ordem. Depois disso, ler um valor não falha.
    pub fn ler(bytes: &'a [u8]) -> Result<Mensagem<'a>, Falha> {
        if bytes.len() < 4 {
            return Err(Falha::Curta);
        }
        let n = u32_em(bytes, 0) as usize;
        if n == 0 || n > MAIS_ETIQUETAS {
            return Err(Falha::Etiquetas);
        }
        let cabecalho = 8 * n;
        if bytes.len() < cabecalho {
            return Err(Falha::Curta);
        }
        let valores = bytes.len() - cabecalho;
        let mut anterior = 0;
        for i in 0..n - 1 {
            let deslocamento = u32_em(bytes, 4 + 4 * i) as usize;
            if !deslocamento.is_multiple_of(4) || deslocamento < anterior || deslocamento > valores
            {
                return Err(Falha::Deslocamento);
            }
            anterior = deslocamento;
        }
        let etiquetas = 4 + 4 * (n - 1);
        for i in 1..n {
            if u32_em(bytes, etiquetas + 4 * i) <= u32_em(bytes, etiquetas + 4 * (i - 1)) {
                return Err(Falha::Ordem);
            }
        }
        Ok(Mensagem { bytes, n })
    }

    /// Quantas etiquetas a mensagem tem.
    pub fn quantas(&self) -> usize {
        self.n
    }

    /// A etiqueta i, em ordem.
    pub fn etiqueta(&self, i: usize) -> Etiqueta {
        let p = 4 + 4 * (self.n - 1) + 4 * i;
        [
            self.bytes[p],
            self.bytes[p + 1],
            self.bytes[p + 2],
            self.bytes[p + 3],
        ]
    }

    /// O valor i: uma fatia dos bytes recebidos.
    pub fn valor_em(&self, i: usize) -> &'a [u8] {
        let valores = &self.bytes[8 * self.n..];
        let comeco = if i == 0 {
            0
        } else {
            u32_em(self.bytes, 4 + 4 * (i - 1)) as usize
        };
        let fim = if i == self.n - 1 {
            valores.len()
        } else {
            u32_em(self.bytes, 4 + 4 * i) as usize
        };
        &valores[comeco..fim]
    }

    /// O valor de uma etiqueta, se ela está na mensagem.
    pub fn valor(&self, etiqueta: Etiqueta) -> Option<&'a [u8]> {
        (0..self.n)
            .find(|&i| self.etiqueta(i) == etiqueta)
            .map(|i| self.valor_em(i))
    }
}

/// Escreve uma mensagem com estes campos no começo de `destino`, em ordem
/// da [`chave`] de cada etiqueta, e devolve quantos bytes escreveu.
///
/// Recusa o que o leitor recusaria: nenhum campo ou mais que
/// [`MAIS_ETIQUETAS`], etiqueta repetida, e um valor que não seja o último
/// com comprimento fora dos múltiplos de quatro.
pub fn escrever(campos: &[(Etiqueta, &[u8])], destino: &mut [u8]) -> Result<usize, Falha> {
    let n = campos.len();
    if n == 0 || n > MAIS_ETIQUETAS {
        return Err(Falha::Etiquetas);
    }
    let mut ordem = [0usize; MAIS_ETIQUETAS];
    for (i, o) in ordem.iter_mut().enumerate().take(n) {
        *o = i;
    }
    let ordem = &mut ordem[..n];
    ordem.sort_unstable_by_key(|&i| chave(campos[i].0));
    for par in ordem.windows(2) {
        if chave(campos[par[0]].0) == chave(campos[par[1]].0) {
            return Err(Falha::Ordem);
        }
    }
    let mut total = 8 * n;
    for (posicao, &i) in ordem.iter().enumerate() {
        if posicao + 1 < n && !campos[i].1.len().is_multiple_of(4) {
            return Err(Falha::Deslocamento);
        }
        total += campos[i].1.len();
    }
    if destino.len() < total || u32::try_from(total).is_err() {
        return Err(Falha::Curta);
    }
    destino[..4].copy_from_slice(&(n as u32).to_le_bytes());
    let mut deslocamento = 0usize;
    let mut valor = 8 * n;
    for (posicao, &i) in ordem.iter().enumerate() {
        let (etiqueta, conteudo) = campos[i];
        if posicao > 0 {
            let p = 4 + 4 * (posicao - 1);
            destino[p..p + 4].copy_from_slice(&(deslocamento as u32).to_le_bytes());
        }
        let p = 4 + 4 * (n - 1) + 4 * posicao;
        destino[p..p + 4].copy_from_slice(&etiqueta);
        destino[valor..valor + conteudo.len()].copy_from_slice(conteudo);
        valor += conteudo.len();
        deslocamento += conteudo.len();
    }
    Ok(total)
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::servidor_de_teste::crua;
    use std::vec::Vec;

    fn escrita(campos: &[(Etiqueta, &[u8])]) -> Vec<u8> {
        let mut destino = std::vec![0u8; 4096];
        let n = escrever(campos, &mut destino).unwrap();
        destino.truncate(n);
        destino
    }

    #[test]
    fn a_ordem_e_pelo_valor_little_endian() {
        // `SIG\0` vale 0x00474953 e `NONC` 0x434e4f4e: SIG vem antes,
        // embora 'S' venha depois de 'N' no ASCII.
        assert!(chave(SIG) < chave(NONC));
        assert!(chave(VER) < chave(SRV));
        assert!(chave(SRV) < chave(NONC));
        assert!(chave(NONC) < chave(TYPE));
        assert!(chave(TYPE) < chave(ZZZZ));
        assert!(chave(TYPE) < chave(PATH) && chave(PATH) < chave(SREP));
        assert!(chave(SREP) < chave(CERT) && chave(CERT) < chave(INDX));
        assert!(chave(VER) < chave(RADI) && chave(RADI) < chave(MIDP));
        assert!(chave(MIDP) < chave(VERS) && chave(VERS) < chave(ROOT));
        assert!(chave(PUBK) < chave(MINT) && chave(MINT) < chave(MAXT));
        assert!(chave(SIG) < chave(DELE));
    }

    #[test]
    fn escreve_e_le_de_volta_em_ordem() {
        let m = escrita(&[
            (NONC, &[7; 32]),
            (SIG, &[1; 64]),
            (PATH, &[]),
            (TYPE, &1u32.to_le_bytes()),
        ]);
        let lida = Mensagem::ler(&m).unwrap();
        assert_eq!(lida.quantas(), 4);
        let ordem: Vec<Etiqueta> = (0..4).map(|i| lida.etiqueta(i)).collect();
        assert_eq!(ordem, [SIG, NONC, TYPE, PATH]);
        assert_eq!(lida.valor(SIG), Some(&[1u8; 64][..]));
        assert_eq!(lida.valor(NONC), Some(&[7u8; 32][..]));
        assert_eq!(lida.valor(TYPE), Some(&1u32.to_le_bytes()[..]));
        assert_eq!(lida.valor(PATH), Some(&[][..]), "um valor vazio no fim");
        assert_eq!(lida.valor(ROOT), None);
    }

    #[test]
    fn um_valor_vazio_no_meio() {
        let m = escrita(&[(TYPE, &[0; 4]), (PATH, &[]), (SREP, &[9; 8])]);
        let lida = Mensagem::ler(&m).unwrap();
        assert_eq!(lida.valor(PATH), Some(&[][..]));
        assert_eq!(lida.valor(SREP), Some(&[9u8; 8][..]));
    }

    #[test]
    fn uma_etiqueta_so() {
        let m = escrita(&[(NONC, &[3; 5])]);
        assert_eq!(m.len(), 8 + 5);
        let lida = Mensagem::ler(&m).unwrap();
        assert_eq!(
            lida.valor(NONC),
            Some(&[3u8; 5][..]),
            "o último não precisa de múltiplo de 4"
        );
    }

    #[test]
    fn o_escritor_recusa_o_que_o_leitor_recusaria() {
        let mut d = [0u8; 256];
        assert_eq!(escrever(&[], &mut d), Err(Falha::Etiquetas));
        assert_eq!(
            escrever(&[(SIG, &[0; 4]), (SIG, &[0; 4])], &mut d),
            Err(Falha::Ordem)
        );
        assert_eq!(
            escrever(&[(SIG, &[0; 3]), (NONC, &[0; 4])], &mut d),
            Err(Falha::Deslocamento)
        );
        assert_eq!(escrever(&[(SIG, &[0; 250])], &mut d), Err(Falha::Curta));
        let muitas: Vec<(Etiqueta, &[u8])> = (0..=MAIS_ETIQUETAS as u32)
            .map(|i| (i.to_le_bytes(), &[][..]))
            .collect();
        let mut grande = [0u8; 1024];
        assert_eq!(escrever(&muitas, &mut grande), Err(Falha::Etiquetas));
    }

    #[test]
    fn sem_etiquetas_ou_demais() {
        assert_eq!(
            Mensagem::ler(&0u32.to_le_bytes()).unwrap_err(),
            Falha::Etiquetas
        );
        let mut m = std::vec![0u8; 8 * 40];
        m[..4].copy_from_slice(&33u32.to_le_bytes());
        assert_eq!(Mensagem::ler(&m).unwrap_err(), Falha::Etiquetas);
        let campos: Vec<(Etiqueta, &[u8])> = (1..=MAIS_ETIQUETAS as u32)
            .map(|i| (i.to_le_bytes(), &[][..]))
            .collect();
        assert!(Mensagem::ler(&crua(&campos)).is_ok(), "o teto passa");
    }

    #[test]
    fn curta() {
        assert_eq!(Mensagem::ler(&[]).unwrap_err(), Falha::Curta);
        assert_eq!(Mensagem::ler(&[1, 0, 0]).unwrap_err(), Falha::Curta);
        // Duas etiquetas declaradas: o cabeçalho tem 16 bytes.
        let mut m = crua(&[(SIG, &[]), (NONC, &[])]);
        m.pop();
        assert_eq!(Mensagem::ler(&m).unwrap_err(), Falha::Curta);
    }

    #[test]
    fn deslocamentos() {
        let boa = crua(&[(SIG, &[0; 4]), (NONC, &[0; 4]), (TYPE, &[0; 4])]);
        assert!(Mensagem::ler(&boa).is_ok());
        let mut nao_multiplo = boa.clone();
        nao_multiplo[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            Mensagem::ler(&nao_multiplo).unwrap_err(),
            Falha::Deslocamento
        );
        let mut volta = boa.clone();
        volta[4..8].copy_from_slice(&8u32.to_le_bytes());
        volta[8..12].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(Mensagem::ler(&volta).unwrap_err(), Falha::Deslocamento);
        let mut alem = boa.clone();
        alem[8..12].copy_from_slice(&16u32.to_le_bytes());
        assert_eq!(Mensagem::ler(&alem).unwrap_err(), Falha::Deslocamento);
        let mut no_fim = boa.clone();
        no_fim[8..12].copy_from_slice(&12u32.to_le_bytes());
        assert!(
            Mensagem::ler(&no_fim).is_ok(),
            "o último vazio, no fim exato"
        );
    }

    #[test]
    fn ordem_e_repeticao() {
        let fora = crua(&[(NONC, &[0; 4]), (SIG, &[0; 4])]);
        assert_eq!(Mensagem::ler(&fora).unwrap_err(), Falha::Ordem);
        let repetida = crua(&[(SIG, &[0; 4]), (SIG, &[0; 4])]);
        assert_eq!(Mensagem::ler(&repetida).unwrap_err(), Falha::Ordem);
        // Em ordem pelo ASCII, que é a ordem big-endian: NONC < SIG.
        let ascii = crua(&[(NONC, &[0; 4]), (SIG, &[0; 4]), (TYPE, &[0; 4])]);
        assert_eq!(Mensagem::ler(&ascii).unwrap_err(), Falha::Ordem);
    }

    #[test]
    fn a_etiqueta_desconhecida_e_lida_e_ignorada() {
        let m = escrita(&[(SIG, &[1; 4]), (*b"ZZZY", &[2; 4]), (NONC, &[3; 4])]);
        let lida = Mensagem::ler(&m).unwrap();
        assert_eq!(lida.quantas(), 3);
        assert_eq!(lida.valor(SIG), Some(&[1u8; 4][..]));
        assert_eq!(lida.valor(NONC), Some(&[3u8; 4][..]));
    }
}
