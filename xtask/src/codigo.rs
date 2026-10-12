//! O código que chega pela rede: os programas publicados, selados, e a
//! bancada que os serve.
//!
//! # Publicados, e não da imagem
//!
//! Um programa publicado ([`PUBLICADOS`]) é compilado com os outros, e
//! **não** vai para a imagem: o único jeito de ele chegar ao Duke é pela
//! rede, do servidor HTTP da bancada — `GET /codigo/<arquitetura>/<nome>`,
//! claro ou atrás do TLS —, selado por um editor. É o que o instalador
//! baixa, grava no armazém e executa, e o que a fumaça grava pelo canal.
//!
//! # As variantes
//!
//! Cada publicado sai em cinco arquivos, um para cada resposta que o Duke
//! tem de dar ([`VARIANTES`]):
//!
//! | arquivo | o que é | o Duke |
//! |---|---|---|
//! | `<nome>` | selado pelo editor `bancada` | roda, para quem confia nele |
//! | `<nome>-sem-selo` | o ELF cru | `CODE_UNSIGNED` |
//! | `<nome>-adulterado` | selado por `bancada`, e um byte do código trocado depois | `CODE_TAMPERED` |
//! | `<nome>-estranho` | selado por uma chave fora do registro | `CODE_UNTRUSTED` |
//! | `<nome>-outro` | selado por `outro`, do registro, em quem nenhum papel confia | `CODE_UNTRUSTED` |
//!
//! # As chaves
//!
//! As privadas dos editores ficam em `target/chaves/`, como as dos agentes:
//! fora do repositório e fora da imagem. A imagem recebe só as públicas de
//! `bancada` e `outro`, no registro de editores, `/etc/duke/editores`; a de
//! `estranho` não está em lugar nenhum dela — é o editor que o Duke não
//! conhece.

use std::path::{Path, PathBuf};

use super::Arquitetura;

/// Os programas publicados: compilados, fora da imagem, servidos selados.
pub(crate) const PUBLICADOS: &[&str] = &["vindo"];

/// Os editores do registro da imagem, pelo nome: `bancada`, em que a
/// política de desenvolvimento confia, e `outro`, em que nenhum papel
/// confia.
pub(crate) const EDITOR_DA_BANCADA: &str = "bancada";
pub(crate) const EDITOR_DE_FORA: &str = "outro";

/// As variantes de cada publicado: o sufixo do arquivo, e o que o Duke
/// responde a ele — `None` é rodar.
pub(crate) const VARIANTES: [(&str, Option<&str>); 5] = [
    ("", None),
    ("-sem-selo", Some("CODE_UNSIGNED")),
    ("-adulterado", Some("CODE_TAMPERED")),
    ("-estranho", Some("CODE_UNTRUSTED")),
    ("-outro", Some("CODE_UNTRUSTED")),
];

/// O diretório que o servidor HTTP da bancada serve em `/codigo`.
pub(crate) fn diretorio() -> PathBuf {
    super::tls::diretorio().join("codigo")
}

/// O ELF de um publicado, como o build dos programas o deixou.
fn elf(arch: Arquitetura, nome: &str) -> Result<Vec<u8>, String> {
    let caminho = super::raiz_do_projeto()
        .join("programas")
        .join("target")
        .join(arch.alvo())
        .join("release")
        .join(nome);
    std::fs::read(&caminho).map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))
}

/// A variante `sufixo` de `codigo`, com as chaves privadas dos três
/// editores.
fn variante(
    codigo: &[u8],
    sufixo: &str,
    chaves: &super::chaves::Chaves,
) -> Result<Vec<u8>, String> {
    use sigilo::codigo::selar;
    Ok(match sufixo {
        "" => selar(codigo, &chaves.editor_da_bancada),
        "-sem-selo" => codigo.to_vec(),
        "-adulterado" => {
            // Um byte do meio do código, trocado depois de selado: o ELF
            // continua se lendo, e o selo não confere mais.
            let mut selado = selar(codigo, &chaves.editor_da_bancada);
            let meio = codigo.len() / 2;
            selado[meio] ^= 0x01;
            selado
        }
        "-estranho" => selar(codigo, &chaves.editor_estranho),
        "-outro" => selar(codigo, &chaves.editor_de_fora),
        outro => return Err(format!("variante desconhecida `{outro}`")),
    })
}

/// O que cada variante tem de ser, conferido aqui: a selada pela bancada
/// confere e diz `bancada`; a sem selo não tem selo; a adulterada não
/// confere; as de outros editores conferem, com a chave deles. Uma bancada
/// que servisse outra coisa provaria o que não devia.
fn conferir(bytes: &[u8], sufixo: &str, chaves: &super::chaves::Chaves) -> Result<(), String> {
    use sigilo::codigo::{Falha, conferir, publica_do_editor};
    let editor = |privada: &[u8; 32]| Ok(publica_do_editor(privada));
    let esperado: Result<[u8; 32], Falha> = match sufixo {
        "" => editor(&chaves.editor_da_bancada),
        "-sem-selo" => Err(Falha::SemSelo),
        "-adulterado" => Err(Falha::NaoConfere),
        "-estranho" => editor(&chaves.editor_estranho),
        "-outro" => editor(&chaves.editor_de_fora),
        outro => return Err(format!("variante desconhecida `{outro}`")),
    };
    let visto = conferir(bytes).map(|c| c.editor);
    if visto != esperado {
        return Err(format!(
            "a variante `{sufixo}` deu {visto:?}, e devia dar {esperado:?}"
        ));
    }
    Ok(())
}

/// Grava `bytes` em `caminho` sem que um leitor veja metade: num arquivo
/// ao lado, e depois o nome. O servidor da bancada lê a cada pedido, e as
/// duas arquiteturas podem publicar ao mesmo tempo.
fn gravar(caminho: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporario = caminho.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&temporario, bytes)
        .map_err(|e| format!("não foi possível gravar {}: {e}", temporario.display()))?;
    std::fs::rename(&temporario, caminho)
        .map_err(|e| format!("não foi possível pôr {} no lugar: {e}", caminho.display()))
}

/// Publica os programas de `arch` na bancada: cada variante de cada um,
/// conferida antes de ir para o lugar. Os programas já estão compilados —
/// quem chama montou o disco antes, e o disco os compila.
pub(crate) fn publicar(arch: Arquitetura) -> Result<PathBuf, String> {
    let chaves = super::chaves::Chaves::garantir()?;
    let dir = diretorio().join(arch.nome());
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("não foi possível criar {}: {e}", dir.display()))?;
    for nome in PUBLICADOS {
        let codigo = elf(arch, nome)?;
        for (sufixo, _) in VARIANTES {
            let bytes = variante(&codigo, sufixo, &chaves)?;
            conferir(&bytes, sufixo, &chaves).map_err(|e| format!("{nome}: {e}"))?;
            gravar(&dir.join(format!("{nome}{sufixo}")), &bytes)?;
        }
    }
    Ok(dir)
}

/// Os bytes de uma variante publicada, como a bancada a serve: para a
/// fumaça gravar pelo canal o mesmo que o instalador baixaria.
pub(crate) fn publicado(arch: Arquitetura, arquivo: &str) -> Result<Vec<u8>, String> {
    let caminho = diretorio().join(arch.nome()).join(arquivo);
    std::fs::read(&caminho).map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))
}
