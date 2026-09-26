//! O CRC-32 que a UEFI usa nos cabeçalhos das tabelas.
//!
//! # Por que uma segunda implementação, se o kernel já tem um crc32
//!
//! Porque não é o mesmo. O kernel tem o **crc32c**, de polinômio
//! `0x82F6_3B78`, que é o que o Btrfs exige. A UEFI usa o CRC-32 do Ethernet,
//! de polinômio `0xEDB8_8320`. Dois nomes parecidos, duas tabelas diferentes,
//! e usar um no lugar do outro dá um número plausível que nunca confere.
//!
//! # Por que calcular, se os serviços de boot oferecem `CalculateCrc32`
//!
//! Porque perguntar ao firmware se a tabela dele está certa não confere nada:
//! um deslocamento errado da nossa parte faria o firmware calcular o CRC de
//! outros bytes e dizer que está tudo bem. A conferência só tem valor se as
//! duas pontas forem independentes — o firmware escreveu, nós conferimos.
//!
//! É a mesma regra que o resto do projeto segue quando manda o `llvm-readelf`
//! olhar os ELFs que ele mesmo montou.

/// O polinômio do CRC-32, na forma refletida.
const POLINOMIO: u32 = 0xEDB8_8320;

/// A tabela de 256 entradas, gerada em tempo de compilação.
const TABELA: [u32; 256] = {
    let mut tabela = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut valor = i as u32;
        let mut bit = 0;
        while bit < 8 {
            valor = if valor & 1 != 0 {
                (valor >> 1) ^ POLINOMIO
            } else {
                valor >> 1
            };
            bit += 1;
        }
        tabela[i] = valor;
        i += 1;
    }
    tabela
};

/// Uma soma em andamento, para quem não tem os bytes num pedaço só.
///
/// O cabeçalho de uma tabela da UEFI é justamente esse caso: o campo do CRC
/// entra na conta como zeros, então a tabela é somada em três partes — o que
/// vem antes dele, quatro zeros, e o que vem depois. Copiar tudo para um
/// buffer daria no mesmo e exigiria um buffer que o iniciador ainda não tem
/// como alocar quando faz esta conferência.
pub struct Parcial(u32);

impl Parcial {
    pub fn nova() -> Parcial {
        Parcial(!0)
    }

    pub fn somar(&mut self, dados: &[u8]) {
        for byte in dados {
            self.0 = (self.0 >> 8) ^ TABELA[((self.0 ^ *byte as u32) & 0xFF) as usize];
        }
    }

    pub fn terminar(&self) -> u32 {
        !self.0
    }
}
