//! A marca da imagem: `/etc/duke/imagem` — de onde veio o disco da máquina.
//!
//! ```text
//! # A marca da imagem.
//! tipo producao
//! nome sala-3
//! id 6f1c0e2a9b7d4c3e8a5f0b1d2c3e4f50
//! ```
//!
//! - `tipo`: `producao`, a imagem de `cargo xtask provisionar`, montada do
//!   que o operador trouxe e com uma chave do Duke nova; ou
//!   `desenvolvimento`, a de `cargo xtask build`, com as chaves, a política
//!   e a pessoa da bancada — chaves cujas privadas estão no `target/` de
//!   quem compilou;
//! - `nome`: o nome da máquina, na regra dos nomes de agente;
//! - `id`: dezesseis bytes sorteados quando a imagem foi montada, em
//!   hexadecimal — duas imagens de mesmo nome não têm o mesmo.
//!
//! Cada campo uma vez, os três obrigatórios.
//!
//! Mora neste pacote, e não no kernel, pela mesma razão dos registros: o
//! `xtask` escreve o arquivo e o kernel o lê, e um formato com dois lados é
//! um formato que só um leitor pode definir.
//!
//! # O que ela não é
//!
//! Autoridade. O kernel a mostra — no log do boot e no `system.info` — e não
//! decide nada por ela: quem pode o quê continua sendo a política, sobre as
//! identidades dos registros. Ela existe para que uma máquina de bancada não
//! passe por uma de produção diante de quem a opera.

use alloc::string::{String, ToString};

use crate::registro::nome_valido;

/// De onde a imagem veio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tipo {
    /// Montada do material do operador.
    Producao,
    /// A da bancada, com as chaves de desenvolvimento.
    Desenvolvimento,
}

impl Tipo {
    /// O nome no arquivo.
    pub const fn nome(self) -> &'static str {
        match self {
            Tipo::Producao => "producao",
            Tipo::Desenvolvimento => "desenvolvimento",
        }
    }

    /// O nome estável, para o `system.info`.
    pub const fn em_ingles(self) -> &'static str {
        match self {
            Tipo::Producao => "production",
            Tipo::Desenvolvimento => "development",
        }
    }
}

/// A marca lida.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Marca {
    pub tipo: Tipo,
    pub nome: String,
    pub id: [u8; 16],
}

/// Lê o arquivo. `Err` com a linha (contada de 1; zero para o arquivo
/// inteiro) e o motivo.
pub fn ler(texto: &str) -> Result<Marca, (usize, &'static str)> {
    let (mut tipo, mut nome, mut id) = (None, None, None);
    for (n, linha) in texto.lines().enumerate() {
        let n = n + 1;
        let linha = linha.trim();
        if linha.is_empty() || linha.starts_with('#') {
            continue;
        }
        let mut campos = linha.split_ascii_whitespace();
        let chave = campos.next().unwrap_or("");
        let valor = campos.next().ok_or((n, "falta o valor"))?;
        if campos.next().is_some() {
            return Err((n, "um valor so por linha"));
        }
        match chave {
            "tipo" if tipo.is_none() => {
                tipo = Some(match valor {
                    "producao" => Tipo::Producao,
                    "desenvolvimento" => Tipo::Desenvolvimento,
                    _ => return Err((n, "tipo que nao e producao nem desenvolvimento")),
                });
            }
            "nome" if nome.is_none() => {
                if !nome_valido(valor) {
                    return Err((n, "nome fora da regra"));
                }
                nome = Some(valor.to_string());
            }
            "id" if id.is_none() => {
                id = Some(
                    crate::de_hex_fixo::<16>(valor)
                        .ok_or((n, "id que nao tem 32 digitos hexadecimais"))?,
                );
            }
            "tipo" | "nome" | "id" => return Err((n, "campo repetido")),
            _ => return Err((n, "linha que nao e tipo, nome nem id")),
        }
    }
    Ok(Marca {
        tipo: tipo.ok_or((0, "falta o tipo"))?,
        nome: nome.ok_or((0, "falta o nome"))?,
        id: id.ok_or((0, "falta o id"))?,
    })
}

/// O arquivo de uma marca, como [`ler`] o lê.
pub fn escrever(m: &Marca) -> String {
    alloc::format!(
        "# A marca da imagem: de onde veio o disco desta maquina.\ntipo {}\nnome {}\nid {}\n",
        m.tipo.nome(),
        m.nome,
        crate::hex_de(&m.id)
    )
}

#[cfg(test)]
mod testes {
    use super::*;

    fn marca(tipo: Tipo) -> Marca {
        Marca {
            tipo,
            nome: "sala-3".to_string(),
            id: [0x5a; 16],
        }
    }

    #[test]
    fn ida_e_volta() {
        for tipo in [Tipo::Producao, Tipo::Desenvolvimento] {
            let m = marca(tipo);
            assert_eq!(ler(&escrever(&m)), Ok(m));
        }
    }

    #[test]
    fn recusa_o_que_falta_e_o_que_sobra() {
        let id = "id 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
        assert_eq!(ler(""), Err((0, "falta o tipo")));
        assert_eq!(
            ler(&alloc::format!("tipo producao\n{id}")),
            Err((0, "falta o nome"))
        );
        assert_eq!(ler("tipo producao\nnome a"), Err((0, "falta o id")));
        assert_eq!(
            ler(&alloc::format!(
                "tipo producao\ntipo producao\nnome a\n{id}"
            )),
            Err((2, "campo repetido"))
        );
        assert_eq!(
            ler(&alloc::format!("tipo bancada\nnome a\n{id}")),
            Err((1, "tipo que nao e producao nem desenvolvimento"))
        );
        assert_eq!(
            ler(&alloc::format!("tipo producao\nnome Sala\n{id}")),
            Err((2, "nome fora da regra"))
        );
        assert_eq!(
            ler("tipo producao\nnome a\nid 5a5a"),
            Err((3, "id que nao tem 32 digitos hexadecimais"))
        );
        assert_eq!(
            ler(&alloc::format!("tipo producao extra\nnome a\n{id}")),
            Err((1, "um valor so por linha"))
        );
        assert_eq!(
            ler(&alloc::format!("tipo producao\nnome a\n{id}\nchave x")),
            Err((4, "linha que nao e tipo, nome nem id"))
        );
    }

    #[test]
    fn comentarios_e_linhas_vazias_passam() {
        let texto = "# a marca\n\ntipo desenvolvimento\n  nome   bancada  \nid 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a\n";
        let m = ler(texto).expect("a marca");
        assert_eq!(
            (m.tipo, m.nome.as_str()),
            (Tipo::Desenvolvimento, "bancada")
        );
    }
}
