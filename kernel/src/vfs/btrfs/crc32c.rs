//! O crc32c, que é a soma de verificação que o Btrfs usa por padrão.
//!
//! # Por que não o crc32 de sempre
//!
//! Porque são polinômios diferentes. O CRC-32 do zip e do Ethernet usa
//! `0xEDB88320` refletido; o crc32c — o de Castagnoli — usa `0x82F63B78`, e
//! foi escolhido pelo Btrfs por detectar melhor os erros em rajada que um
//! disco produz. Calcular um e comparar com o outro rejeita todo bloco do
//! sistema de arquivos, e a mensagem seria "corrompido" para um disco
//! perfeitamente íntegro.
//!
//! # Por que uma tabela
//!
//! Porque o volume é grande. Um nó do Btrfs tem 16 KiB, e a versão bit a bit
//! faz oito voltas por byte — cento e trinta mil operações por nó, contra os
//! cem microssegundos que custa lê-lo do disco. A tabela troca isso por uma
//! busca e um deslocamento por byte, ao preço de um kilobyte de `static`.
//!
//! A tabela é construída em tempo de compilação. Escrevê-la à mão seria
//! duzentos e cinquenta e seis constantes que ninguém consegue conferir
//! olhando; gerá-la é a mesma aritmética, num lugar onde o erro aparece.

/// O polinômio de Castagnoli, na forma refletida.
const POLINOMIO: u32 = 0x82F6_3B78;

/// A tabela: para cada byte possível, o resto que ele produz.
const TABELA: [u32; 256] = {
    let mut tabela = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut resto = i as u32;
        let mut bit = 0;
        while bit < 8 {
            resto = if resto & 1 != 0 {
                (resto >> 1) ^ POLINOMIO
            } else {
                resto >> 1
            };
            bit += 1;
        }
        tabela[i] = resto;
        i += 1;
    }
    tabela
};

/// A soma de um bloco, no formato que o Btrfs grava.
///
/// O valor inicial e o final são complementados, que é a convenção deste CRC
/// e o que o `btrfs-progs` faz em `btrfs_csum_final`. Sem os dois, o número
/// sai diferente do gravado no disco para todo bloco.
pub fn somar(dados: &[u8]) -> u32 {
    let mut resto = !0u32;
    for byte in dados {
        resto = (resto >> 8) ^ TABELA[((resto ^ u32::from(*byte)) & 0xFF) as usize];
    }
    !resto
}
