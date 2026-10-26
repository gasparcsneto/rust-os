//! Onde a atualização mora no disco: as partições, pelos tipos na GPT, e o
//! leitor de GPT com que o iniciador as acha.
//!
//! # As partições
//!
//! Três, depois das que o disco já tinha — a ESP, a raiz, o estado e o
//! armazém não mudam de lugar:
//!
//! - o **controle** ([`GUID_DO_CONTROLE`]): as duas cópias do controle de
//!   boot — ver [`crate::controle`] —, em [`COPIA_EM`];
//! - o **slot A** ([`GUID_DO_SLOT_A`]) e o **slot B** ([`GUID_DO_SLOT_B`]):
//!   cada um com uma imagem — ver [`crate::cabecalho`].
//!
//! Tipos próprios, sorteados uma vez para este projeto, pela mesma razão do
//! estado e do armazém: a escrita do kernel é restrita a partições, e é o
//! tipo que diz qual é qual. Um slot que caísse por engano sobre a raiz
//! seria uma imagem escrita por cima da identidade da máquina.
//!
//! # As cópias a 4 KiB uma da outra
//!
//! Cada cópia do controle ocupa um setor de 512 bytes, mas elas moram a
//! 4 KiB de distância: num disco de setor físico de 4 KiB, duas cópias no
//! mesmo setor físico seriam rasgadas pela mesma escrita — e a segunda
//! cópia existe justamente para sobreviver ao rasgo da primeira.

use crate::Slot;

/// O tipo da partição do controle (`1A5419B5-4D97-4346-9E27-F59785FDAD02`),
/// na ordem em que a GPT o guarda: os três primeiros campos em
/// little-endian.
pub const GUID_DO_CONTROLE: [u8; 16] = [
    0xB5, 0x19, 0x54, 0x1A, 0x97, 0x4D, 0x46, 0x43, 0x9E, 0x27, 0xF5, 0x97, 0x85, 0xFD, 0xAD, 0x02,
];

/// O tipo do slot A (`A10C9098-3029-43AE-9E51-5A79888E5EC0`).
pub const GUID_DO_SLOT_A: [u8; 16] = [
    0x98, 0x90, 0x0C, 0xA1, 0x29, 0x30, 0xAE, 0x43, 0x9E, 0x51, 0x5A, 0x79, 0x88, 0x8E, 0x5E, 0xC0,
];

/// O tipo do slot B (`7DC684E7-C3BD-4BB9-AA52-E0E830668EED`).
pub const GUID_DO_SLOT_B: [u8; 16] = [
    0xE7, 0x84, 0xC6, 0x7D, 0xBD, 0xC3, 0xB9, 0x4B, 0xAA, 0x52, 0xE0, 0xE8, 0x30, 0x66, 0x8E, 0xED,
];

/// Os mesmos três, como o `sgdisk` os escreve.
pub const TEXTO_DO_CONTROLE: &str = "1A5419B5-4D97-4346-9E27-F59785FDAD02";
pub const TEXTO_DO_SLOT_A: &str = "A10C9098-3029-43AE-9E51-5A79888E5EC0";
pub const TEXTO_DO_SLOT_B: &str = "7DC684E7-C3BD-4BB9-AA52-E0E830668EED";

/// O tipo de um slot.
pub const fn guid_do_slot(slot: Slot) -> [u8; 16] {
    match slot {
        Slot::A => GUID_DO_SLOT_A,
        Slot::B => GUID_DO_SLOT_B,
    }
}

/// Onde mora cada cópia do controle, em bytes desde o começo da partição.
pub const COPIA_EM: [u64; 2] = [0, 4096];

/// O menor bloco de leitura que cobre uma cópia: um setor.
pub const TAM_DA_COPIA: usize = crate::TAM_SETOR;

/// Uma faixa de blocos do disco: o primeiro e quantos — no tamanho de
/// bloco do disco.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Faixa {
    pub primeiro: u64,
    pub blocos: u64,
}

impl Faixa {
    /// O bloco onde mora o byte `deslocamento` da faixa, se ele está dentro
    /// dela e cai no começo de um bloco de `tamanho` bytes.
    pub fn bloco_de(&self, deslocamento: u64, tamanho: u64) -> Option<u64> {
        if tamanho == 0 || !deslocamento.is_multiple_of(tamanho) {
            return None;
        }
        let relativo = deslocamento / tamanho;
        (relativo < self.blocos).then(|| self.primeiro + relativo)
    }

    /// Quantos bytes a faixa tem, em blocos de `tamanho`.
    pub fn bytes(&self, tamanho: u64) -> Option<u64> {
        self.blocos.checked_mul(tamanho)
    }
}

/// As partições da atualização num disco.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Particoes {
    pub controle: Option<Faixa>,
    pub slots: [Option<Faixa>; 2],
}

impl Particoes {
    /// Se o disco tem a atualização: o controle e os dois slots.
    pub fn completas(&self) -> bool {
        self.controle.is_some() && self.slots.iter().all(Option::is_some)
    }

    pub fn slot(&self, s: Slot) -> Option<Faixa> {
        self.slots[s.indice()]
    }

    /// Anota uma entrada da GPT, se ela é de uma das três. A primeira de
    /// cada tipo vale; uma segunda do mesmo tipo é um disco ambíguo, e
    /// `Err`.
    pub fn anotar(&mut self, e: &Entrada) -> Result<(), &'static str> {
        let lugar = match e.tipo {
            GUID_DO_CONTROLE => &mut self.controle,
            GUID_DO_SLOT_A => &mut self.slots[0],
            GUID_DO_SLOT_B => &mut self.slots[1],
            _ => return Ok(()),
        };
        if lugar.is_some() {
            return Err("o disco tem duas particoes do mesmo tipo da atualizacao");
        }
        *lugar = Some(e.faixa);
        Ok(())
    }
}

/// O que a GPT diz de onde estão as entradas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gpt {
    /// O bloco da primeira entrada.
    pub entradas_em: u64,
    pub quantas: u32,
    /// Quantos bytes cada entrada ocupa.
    pub tamanho: u32,
}

/// O teto de entradas — o do kernel: um disco de verdade diz 128.
pub const MAIS_ENTRADAS: u32 = 1024;

impl Gpt {
    /// Lê o cabeçalho da GPT, do bloco 1 de um disco de blocos de
    /// `tamanho_do_bloco` bytes. Os campos que viram conta de endereço são
    /// conferidos aqui, antes de qualquer conta.
    pub fn ler(bloco: &[u8], tamanho_do_bloco: u64) -> Result<Gpt, &'static str> {
        let b = bloco.get(..92).ok_or("cabecalho da gpt cortado")?;
        if &b[..8] != b"EFI PART" {
            return Err("o disco nao tem gpt");
        }
        let u64_em = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap_or([0; 8]));
        let u32_em = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap_or([0; 4]));
        let entradas_em = u64_em(72);
        let quantas = u32_em(80);
        let tamanho = u32_em(84);
        if entradas_em < 2 {
            return Err("as entradas da gpt estariam sobre o cabecalho");
        }
        if quantas == 0 || quantas > MAIS_ENTRADAS {
            return Err("a gpt declara um numero implausivel de entradas");
        }
        if !matches!(tamanho, 128 | 256 | 512)
            || u64::from(tamanho) > tamanho_do_bloco
            || !tamanho_do_bloco.is_multiple_of(u64::from(tamanho))
        {
            return Err("as entradas da gpt tem tamanho fora da especificacao");
        }
        let por_bloco = tamanho_do_bloco / u64::from(tamanho);
        let blocos = u64::from(quantas).div_ceil(por_bloco);
        entradas_em
            .checked_add(blocos)
            .ok_or("as entradas da gpt passam do fim do disco")?;
        Ok(Gpt {
            entradas_em,
            quantas,
            tamanho,
        })
    }

    /// Quantos blocos as entradas ocupam.
    pub fn blocos(&self, tamanho_do_bloco: u64) -> u64 {
        u64::from(self.quantas).div_ceil(tamanho_do_bloco / u64::from(self.tamanho))
    }
}

/// Uma entrada da GPT: o tipo e a faixa.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entrada {
    pub tipo: [u8; 16],
    pub faixa: Faixa,
}

/// Lê uma entrada. `None` para uma entrada vazia — tipo todo zero — ou
/// impossível — o último bloco antes do primeiro.
pub fn entrada(bytes: &[u8]) -> Option<Entrada> {
    let b = bytes.get(..56)?;
    let mut tipo = [0u8; 16];
    tipo.copy_from_slice(&b[..16]);
    if tipo == [0; 16] {
        return None;
    }
    let primeiro = u64::from_le_bytes(b[32..40].try_into().ok()?);
    let ultimo = u64::from_le_bytes(b[40..48].try_into().ok()?);
    let blocos = ultimo.checked_sub(primeiro)?.checked_add(1)?;
    Some(Entrada {
        tipo,
        faixa: Faixa { primeiro, blocos },
    })
}

#[cfg(test)]
mod testes {
    use super::*;

    fn cabecalho(entradas_em: u64, quantas: u32, tamanho: u32) -> [u8; 512] {
        let mut b = [0u8; 512];
        b[..8].copy_from_slice(b"EFI PART");
        b[72..80].copy_from_slice(&entradas_em.to_le_bytes());
        b[80..84].copy_from_slice(&quantas.to_le_bytes());
        b[84..88].copy_from_slice(&tamanho.to_le_bytes());
        b
    }

    #[test]
    fn o_cabecalho_da_gpt_e_conferido_antes_das_contas() {
        assert_eq!(
            Gpt::ler(&cabecalho(2, 128, 128), 512),
            Ok(Gpt {
                entradas_em: 2,
                quantas: 128,
                tamanho: 128
            })
        );
        assert_eq!(
            Gpt::ler(&cabecalho(2, 128, 128), 512).unwrap().blocos(512),
            32
        );
        assert_eq!(
            Gpt::ler(&cabecalho(2, 128, 128), 4096)
                .unwrap()
                .blocos(4096),
            4
        );
        assert!(Gpt::ler(&cabecalho(1, 128, 128), 512).is_err());
        assert!(Gpt::ler(&cabecalho(2, 0, 128), 512).is_err());
        assert!(Gpt::ler(&cabecalho(2, 5000, 128), 512).is_err());
        assert!(Gpt::ler(&cabecalho(2, 128, 100), 512).is_err());
        assert!(Gpt::ler(&cabecalho(2, 128, 1024), 512).is_err());
        assert!(Gpt::ler(&cabecalho(u64::MAX, 128, 128), 512).is_err());
        let mut sem = cabecalho(2, 128, 128);
        sem[0] = b'X';
        assert!(Gpt::ler(&sem, 512).is_err());
        assert!(Gpt::ler(&[0u8; 50], 512).is_err());
    }

    fn com_tipo(tipo: [u8; 16], primeiro: u64, ultimo: u64) -> [u8; 128] {
        let mut e = [0u8; 128];
        e[..16].copy_from_slice(&tipo);
        e[32..40].copy_from_slice(&primeiro.to_le_bytes());
        e[40..48].copy_from_slice(&ultimo.to_le_bytes());
        e
    }

    #[test]
    fn as_particoes_sao_achadas_pelo_tipo() {
        let mut p = Particoes::default();
        assert!(!p.completas());
        for (tipo, primeiro) in [
            (GUID_DO_CONTROLE, 100),
            (GUID_DO_SLOT_A, 200),
            (GUID_DO_SLOT_B, 300),
            ([7u8; 16], 400),
        ] {
            let e = entrada(&com_tipo(tipo, primeiro, primeiro + 9)).unwrap();
            p.anotar(&e).unwrap();
        }
        assert!(p.completas());
        assert_eq!(
            p.slot(Slot::B),
            Some(Faixa {
                primeiro: 300,
                blocos: 10
            })
        );
        assert_eq!(p.controle.map(|f| f.primeiro), Some(100));
        // Duas do mesmo tipo: ambíguo.
        let outra = entrada(&com_tipo(GUID_DO_SLOT_A, 900, 909)).unwrap();
        assert!(p.anotar(&outra).is_err());
        // Vazia, e impossível.
        assert_eq!(entrada(&[0u8; 128]), None);
        assert_eq!(entrada(&com_tipo(GUID_DO_SLOT_A, 10, 9)), None);
        assert_eq!(guid_do_slot(Slot::B), GUID_DO_SLOT_B);
    }

    #[test]
    fn os_guids_batem_com_o_texto() {
        // O texto, na ordem da GPT: os três primeiros campos invertidos.
        fn do_texto(t: &str) -> [u8; 16] {
            let h: std::vec::Vec<u8> = t
                .split('-')
                .collect::<std::string::String>()
                .as_bytes()
                .chunks(2)
                .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
                .collect();
            let mut g = [0u8; 16];
            g[..4].copy_from_slice(&[h[3], h[2], h[1], h[0]]);
            g[4..6].copy_from_slice(&[h[5], h[4]]);
            g[6..8].copy_from_slice(&[h[7], h[6]]);
            g[8..].copy_from_slice(&h[8..]);
            g
        }
        assert_eq!(do_texto(TEXTO_DO_CONTROLE), GUID_DO_CONTROLE);
        assert_eq!(do_texto(TEXTO_DO_SLOT_A), GUID_DO_SLOT_A);
        assert_eq!(do_texto(TEXTO_DO_SLOT_B), GUID_DO_SLOT_B);
    }

    #[test]
    fn a_faixa_so_aceita_o_que_cai_dentro_e_alinhado() {
        let f = Faixa {
            primeiro: 1000,
            blocos: 16,
        };
        assert_eq!(f.bloco_de(0, 512), Some(1000));
        assert_eq!(f.bloco_de(4096, 512), Some(1008));
        assert_eq!(f.bloco_de(4096, 4096), Some(1001));
        assert_eq!(f.bloco_de(100, 512), None);
        assert_eq!(f.bloco_de(16 * 512, 512), None);
        assert_eq!(f.bloco_de(0, 0), None);
        assert_eq!(f.bytes(512), Some(8192));
        // As duas cópias do controle em blocos diferentes, num disco de
        // setor de 512 e num de 4 KiB.
        for tamanho in [512, 4096] {
            let a = f.bloco_de(COPIA_EM[0], tamanho);
            let b = f.bloco_de(COPIA_EM[1], tamanho);
            assert!(a.is_some() && b.is_some() && a != b);
        }
    }

    extern crate std;
}
