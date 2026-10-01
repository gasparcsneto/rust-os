//! A credencial de uma pessoa: o verificador de uma senha, por Argon2id.
//!
//! # O que o registro guarda
//!
//! Nunca a senha. Guarda o **verificador**: o Argon2id da senha com um sal
//! aleatório da pessoa e um custo escrito junto. Quem tem o registro não tem
//! a senha, e para testar palpites precisa pagar o custo do Argon2id por
//! palpite — em memória, que é o que encarece um ataque em hardware próprio.
//!
//! # A forma escrita
//!
//! Uma palavra só, sem espaço, para caber numa coluna do registro:
//!
//! ```text
//! argon2id:m=4096,t=3,p=1:<sal, 32 hex>:<verificador, 64 hex>
//! ```
//!
//! O tipo vem primeiro de propósito. Hoje há um tipo de credencial; uma
//! credencial de dispositivo — uma chave pública com desafio-resposta —
//! entra como outro tipo, ao lado deste, sem mudar o que uma pessoa é:
//! ver [`Credencial`].
//!
//! # Comparar sem dizer quanto acertou
//!
//! O verificador calculado é comparado ao guardado em tempo constante: o
//! tempo da comparação não diz quantos bytes coincidiram.

use alloc::format;
use alloc::string::String;

use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub use argon2::Block;

/// O tamanho do sal, em bytes.
pub const TAM_SAL: usize = 16;

/// O tamanho do verificador, em bytes.
pub const TAM_VERIFICADOR: usize = 32;

/// O custo do Argon2id: memória em KiB, passadas e paralelismo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Custo {
    pub memoria_kib: u32,
    pub passadas: u32,
    pub paralelismo: u32,
}

impl Custo {
    /// O custo das credenciais novas. 4 MiB e três passadas: o que cabe na
    /// máquina de 128 MiB do Duke sem segurar o login por segundos no
    /// emulador. Fica escrito em cada credencial, então subir este número
    /// não invalida as que existem.
    pub const PADRAO: Custo = Custo {
        memoria_kib: 4096,
        passadas: 3,
        paralelismo: 1,
    };

    /// O menor custo que uma credencial pode declarar. Abaixo disso o
    /// verificador vira um resumo rápido, e o registro, uma lista de senhas
    /// a um passo de distância.
    pub const MINIMO: Custo = Custo {
        memoria_kib: 1024,
        passadas: 2,
        paralelismo: 1,
    };

    /// O maior que o kernel aceita calcular: um registro com um custo
    /// absurdo seria um jeito de travar o login.
    pub const MAXIMO: Custo = Custo {
        memoria_kib: 16 * 1024,
        passadas: 10,
        paralelismo: 1,
    };

    /// Se o custo está entre o mínimo e o máximo.
    pub fn aceitavel(&self) -> bool {
        (Self::MINIMO.memoria_kib..=Self::MAXIMO.memoria_kib).contains(&self.memoria_kib)
            && (Self::MINIMO.passadas..=Self::MAXIMO.passadas).contains(&self.passadas)
            && self.paralelismo == 1
    }

    /// Quantos blocos de 1 KiB o cálculo precisa.
    pub fn blocos(&self) -> usize {
        self.memoria_kib as usize
    }

    fn parametros(&self) -> Result<Params, Erro> {
        if !self.aceitavel() {
            return Err(Erro::Custo);
        }
        Params::new(
            self.memoria_kib,
            self.passadas,
            self.paralelismo,
            Some(TAM_VERIFICADOR),
        )
        .map_err(|_| Erro::Custo)
    }
}

/// Por que uma credencial não foi lida ou calculada.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// O custo está fora do aceitável.
    Custo,
    /// A forma escrita não é de uma credencial conhecida.
    Formato,
    /// A memória de trabalho não tem o tamanho do custo.
    Memoria,
    /// O Argon2id recusou o cálculo.
    Calculo,
}

impl Erro {
    pub const fn motivo(self) -> &'static str {
        match self {
            Erro::Custo => "custo do argon2id fora do aceitavel",
            Erro::Formato => "credencial em forma desconhecida",
            Erro::Memoria => "memoria de trabalho do tamanho errado",
            Erro::Calculo => "o argon2id recusou o calculo",
        }
    }
}

/// Uma credencial de pessoa.
///
/// Um tipo só hoje. Uma credencial de dispositivo entra como outra variante
/// — o registro da pessoa, a sessão e a política não mudam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credencial {
    /// Uma senha, guardada como o verificador Argon2id dela.
    Senha {
        custo: Custo,
        sal: [u8; TAM_SAL],
        verificador: [u8; TAM_VERIFICADOR],
    },
}

impl Credencial {
    /// Lê a forma escrita.
    pub fn ler(texto: &str) -> Result<Credencial, Erro> {
        let mut partes = texto.split(':');
        if partes.next() != Some("argon2id") {
            return Err(Erro::Formato);
        }
        let custo = ler_custo(partes.next().ok_or(Erro::Formato)?)?;
        let sal = crate::de_hex_fixo::<TAM_SAL>(partes.next().ok_or(Erro::Formato)?)
            .ok_or(Erro::Formato)?;
        let verificador =
            crate::de_hex_fixo::<TAM_VERIFICADOR>(partes.next().ok_or(Erro::Formato)?)
                .ok_or(Erro::Formato)?;
        if partes.next().is_some() {
            return Err(Erro::Formato);
        }
        if !custo.aceitavel() {
            return Err(Erro::Custo);
        }
        Ok(Credencial::Senha {
            custo,
            sal,
            verificador,
        })
    }

    /// A forma escrita.
    pub fn escrever(&self) -> String {
        match self {
            Credencial::Senha {
                custo,
                sal,
                verificador,
            } => format!(
                "argon2id:m={},t={},p={}:{}:{}",
                custo.memoria_kib,
                custo.passadas,
                custo.paralelismo,
                crate::hex_de(sal),
                crate::hex_de(verificador)
            ),
        }
    }

    /// Quantos blocos de memória de trabalho conferir esta credencial pede.
    pub fn blocos(&self) -> usize {
        match self {
            Credencial::Senha { custo, .. } => custo.blocos(),
        }
    }

    /// Confere uma senha, com memória de trabalho de quem chama — o kernel,
    /// que não tem heap para 4 MiB. Falso também se o cálculo falhar.
    pub fn conferir_com_memoria(&self, senha: &[u8], memoria: &mut [Block]) -> bool {
        match self {
            Credencial::Senha {
                custo,
                sal,
                verificador,
            } => match verificador_com_memoria(senha, sal, *custo, memoria) {
                Ok(mut calculado) => {
                    let igual = bool::from(calculado.ct_eq(verificador));
                    calculado.zeroize();
                    igual
                }
                Err(_) => false,
            },
        }
    }

    /// Confere uma senha, com memória do heap. Para quem tem heap: o
    /// hospedeiro.
    pub fn conferir(&self, senha: &[u8]) -> bool {
        let mut memoria = alloc::vec![Block::default(); self.blocos()];
        let igual = self.conferir_com_memoria(senha, &mut memoria);
        apagar(&mut memoria);
        igual
    }
}

/// Faz a credencial de uma senha, com sal dado. Para quem registra: o
/// administrador no hospedeiro — o kernel nunca recebe a senha num registro,
/// só o verificador.
pub fn nova(senha: &[u8], sal: [u8; TAM_SAL], custo: Custo) -> Result<Credencial, Erro> {
    let mut memoria = alloc::vec![Block::default(); custo.blocos()];
    let verificador = verificador_com_memoria(senha, &sal, custo, &mut memoria);
    apagar(&mut memoria);
    Ok(Credencial::Senha {
        custo,
        sal,
        verificador: verificador?,
    })
}

/// O verificador de uma senha.
pub fn verificador_com_memoria(
    senha: &[u8],
    sal: &[u8; TAM_SAL],
    custo: Custo,
    memoria: &mut [Block],
) -> Result<[u8; TAM_VERIFICADOR], Erro> {
    let parametros = custo.parametros()?;
    if memoria.len() != custo.blocos() {
        return Err(Erro::Memoria);
    }
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, parametros);
    let mut saida = [0u8; TAM_VERIFICADOR];
    argon
        .hash_password_into_with_memory(senha, sal, &mut saida, memoria)
        .map_err(|_| Erro::Calculo)?;
    Ok(saida)
}

/// Zera a memória de trabalho: ela guardou estados intermediários do
/// cálculo da senha.
pub fn apagar(memoria: &mut [Block]) {
    // Pelo `Zeroize` do bloco, que o compilador não tira por ver a memória
    // morrer logo depois.
    for bloco in memoria.iter_mut() {
        bloco.zeroize();
    }
}

fn ler_custo(texto: &str) -> Result<Custo, Erro> {
    let mut custo = Custo {
        memoria_kib: 0,
        passadas: 0,
        paralelismo: 0,
    };
    let mut vistos = 0;
    for campo in texto.split(',') {
        let (nome, valor) = campo.split_once('=').ok_or(Erro::Formato)?;
        let valor: u32 = valor.parse().map_err(|_| Erro::Formato)?;
        match nome {
            "m" => custo.memoria_kib = valor,
            "t" => custo.passadas = valor,
            "p" => custo.paralelismo = valor,
            _ => return Err(Erro::Formato),
        }
        vistos += 1;
    }
    if vistos != 3 {
        return Err(Erro::Formato);
    }
    Ok(custo)
}

#[cfg(test)]
mod testes {
    use super::*;

    /// O custo mínimo, para os testes correrem depressa.
    const RAPIDO: Custo = Custo::MINIMO;

    #[test]
    fn a_senha_certa_confere_e_a_errada_nao() {
        let c = nova(b"correta", [7; TAM_SAL], RAPIDO).unwrap();
        assert!(c.conferir(b"correta"));
        assert!(!c.conferir(b"Correta"));
        assert!(!c.conferir(b""));
    }

    #[test]
    fn o_sal_muda_o_verificador() {
        let a = nova(b"x", [1; TAM_SAL], RAPIDO).unwrap();
        let b = nova(b"x", [2; TAM_SAL], RAPIDO).unwrap();
        assert_ne!(a, b);
    }

    /// A forma escrita vai e volta, e não traz a senha.
    #[test]
    fn a_forma_escrita_vai_e_volta() {
        let c = nova(b"segredo-de-teste", [9; TAM_SAL], RAPIDO).unwrap();
        let texto = c.escrever();
        assert!(texto.starts_with("argon2id:m=1024,t=2,p=1:"));
        assert!(!texto.contains("segredo"));
        assert_eq!(Credencial::ler(&texto).unwrap(), c);
    }

    /// O cálculo é determinístico e o custo faz parte dele: a mesma senha,
    /// sal e custo dão sempre o mesmo verificador, e outro custo dá outro. O
    /// Argon2id em si é o do RustCrypto, conferido lá contra os vetores da
    /// RFC 9106; aqui se confere a composição.
    #[test]
    fn o_custo_entra_no_verificador() {
        let a = nova(b"x", [3; TAM_SAL], RAPIDO).unwrap();
        let a2 = nova(b"x", [3; TAM_SAL], RAPIDO).unwrap();
        let b = nova(
            b"x",
            [3; TAM_SAL],
            Custo {
                passadas: 3,
                ..RAPIDO
            },
        )
        .unwrap();
        assert_eq!(a, a2);
        assert_ne!(a, b);
    }

    #[test]
    fn recusa_custo_e_forma_ruins() {
        assert_eq!(
            nova(
                b"x",
                [0; TAM_SAL],
                Custo {
                    memoria_kib: 8,
                    ..RAPIDO
                }
            ),
            Err(Erro::Custo)
        );
        let boa = nova(b"x", [0; TAM_SAL], RAPIDO).unwrap().escrever();
        assert_eq!(
            Credencial::ler(&boa.replace("m=1024", "m=8")),
            Err(Erro::Custo)
        );
        assert_eq!(
            Credencial::ler(&boa.replace("argon2id", "argon2i")),
            Err(Erro::Formato)
        );
        assert_eq!(
            Credencial::ler(&alloc::format!("{boa}:extra")),
            Err(Erro::Formato)
        );
        assert_eq!(Credencial::ler("argon2id:m=1024"), Err(Erro::Formato));
    }

    #[test]
    fn memoria_do_tamanho_errado_nao_calcula() {
        let mut pouca = alloc::vec![Block::default(); 10];
        assert_eq!(
            verificador_com_memoria(b"x", &[0; TAM_SAL], RAPIDO, &mut pouca),
            Err(Erro::Memoria)
        );
    }
}
