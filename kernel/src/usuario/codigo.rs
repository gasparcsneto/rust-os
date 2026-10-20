//! O código que vai virar processo, lido e conferido num lugar só.
//!
//! # Duas portas, uma regra
//!
//! Código vira processo por duas portas: `user.run`, o lançamento pelo
//! canal, pelo interpretador ou pelo boot ([`super::lancar_como`]), e a
//! chamada `executar`, com que um processo troca a própria imagem. As duas
//! passam por [`obter`], e a regra é uma só:
//!
//! - o código da **imagem** — os programas embutidos, a raiz do disco —
//!   roda como sempre rodou: veio com o kernel, a política e as chaves;
//! - o código **gravado** em tempo de execução — o armazém, onde chega o
//!   que veio pela rede — só roda com o selo de um editor do registro em
//!   que o papel de quem lança confia (ver `sigilo::codigo` e a linha
//!   `editores` da política).
//!
//! A origem é a da montagem que a leitura percorreu ([`crate::vfs::Origem`]),
//! e não o caminho escrito: um caminho do armazém não vira da imagem por
//! ter outra grafia.
//!
//! # O que é conferido é o que roda
//!
//! [`obter`] lê o arquivo **uma vez**, confere o selo sobre esses bytes e
//! devolve esses bytes — sem o selo — a quem vai carregar. Ninguém relê o
//! arquivo entre a conferência e a carga: quem trocasse o arquivo no
//! armazém depois de conferido trocaria um arquivo que ninguém mais lê.
//!
//! # Antes, o gate
//!
//! Quem chama já passou pelo gate — `process.run` sobre o caminho —, e só
//! depois lê: conferir um selo não é motivo para ler o que o papel não
//! alcança. A recusa daqui é a execução recusando o que o gate deixou, e
//! vai para a auditoria como tal, com a decisão — ver quem chama.

use alloc::string::String;
use alloc::vec::Vec;

use politica::procedencia::Falta;

use crate::autorizacao::Autoridade;

/// O código pronto para carregar.
pub struct Codigo {
    /// Os bytes do executável — sem o selo, para o código de fora da imagem.
    pub imagem: Vec<u8>,
    /// O selo do código de fora da imagem; nenhum para o da imagem.
    pub selo: Option<Selo>,
}

/// Quem selou o código de fora da imagem, e o quê.
pub struct Selo {
    /// A chave do editor: vai para o programa do fio, e cada pedido do
    /// processo pergunta de novo se o papel confia nela.
    pub editor: [u8; 32],
    /// O nome do editor no registro, para a auditoria.
    pub nome: String,
    /// O resumo BLAKE2s do que o editor selou — a identidade do programa.
    pub resumo: [u8; 32],
}

/// Por que o código não vai rodar.
#[derive(Debug)]
pub enum Recusa {
    /// O arquivo não se leu.
    Leitura(crate::vfs::Erro),
    /// O arquivo é de fora da imagem e não prova de onde veio: o que falta,
    /// e o motivo, como a auditoria o grava.
    Procedencia(Falta, String),
}

impl Recusa {
    /// O motivo, para o log e para a resposta.
    pub fn motivo(&self) -> &str {
        match self {
            Recusa::Leitura(e) => e.motivo(),
            Recusa::Procedencia(_, motivo) => motivo,
        }
    }

    /// O erro que `executar` devolve ao processo.
    pub fn erro(&self) -> i64 {
        use super::erro;
        match self {
            // O programa existe e cabe no teto: faltou o heap, agora.
            Recusa::Leitura(crate::vfs::Erro::SemMemoria) => erro::SEM_MEMORIA,
            Recusa::Leitura(_) => erro::PROGRAMA_DESCONHECIDO,
            Recusa::Procedencia(Falta::SemSelo, _) => erro::SEM_SELO,
            Recusa::Procedencia(Falta::NaoConfere, _) => erro::SELO_NAO_CONFERE,
            Recusa::Procedencia(Falta::EditorDesconhecido | Falta::NaoConfiado, _) => {
                erro::EDITOR_NAO_CONFIADO
            }
        }
    }
}

/// Lê o código de `caminho` e o confere para rodar com a autoridade
/// `autoridade` — ver o começo do módulo.
pub fn obter(caminho: &str, autoridade: Autoridade) -> Result<Codigo, Recusa> {
    let (mut bytes, origem) = crate::vfs::ler_tudo_com_origem(caminho).map_err(Recusa::Leitura)?;
    if origem == crate::vfs::Origem::Imagem {
        return Ok(Codigo {
            imagem: bytes,
            selo: None,
        });
    }
    // A conferência, medida — o custo do código de fora da imagem, que o
    // `security.metrics` diz: o selo e a confiança, sem a leitura.
    let inicio = crate::arch::ciclos();
    let conferido = conferir(&bytes, autoridade);
    crate::metricas::CODIGO.somar(crate::metricas::desde(inicio));
    let (selo, tamanho) = conferido?;
    // Os bytes que o selo cobre, e só eles: o selo não é carregado.
    bytes.truncate(tamanho);
    Ok(Codigo {
        imagem: bytes,
        selo: Some(selo),
    })
}

/// O selo de `bytes`, e se o papel de `autoridade` confia em quem o selou:
/// o selo e o tamanho do executável que ele cobre.
fn conferir(bytes: &[u8], autoridade: Autoridade) -> Result<(Selo, usize), Recusa> {
    let (editor, resumo, tamanho) = match sigilo::codigo::conferir(bytes) {
        Ok(c) => (c.editor, c.resumo, c.codigo.len()),
        Err(sigilo::codigo::Falha::SemSelo) => {
            return Err(procedencia(Falta::SemSelo));
        }
        Err(sigilo::codigo::Falha::NaoConfere) => {
            return Err(procedencia(Falta::NaoConfere));
        }
    };
    // O papel de agora: o mesmo que o gate perguntaria no próximo pedido
    // do processo.
    let papel = crate::autorizacao::papel_da_autoridade(autoridade);
    let nome = crate::autorizacao::confianca_no_editor(papel.as_deref(), &editor)
        .map_err(|(f, motivo)| Recusa::Procedencia(f, motivo))?;
    Ok((
        Selo {
            editor,
            nome,
            resumo,
        },
        tamanho,
    ))
}

fn procedencia(f: Falta) -> Recusa {
    Recusa::Procedencia(f, String::from(f.motivo()))
}
