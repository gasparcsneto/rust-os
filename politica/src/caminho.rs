//! Caminhos: a forma normal, e quando um está dentro de outro.
//!
//! # Por que mora aqui
//!
//! Porque a política limita recursos por prefixo de caminho, e a conferência
//! só vale se o caminho conferido for **o mesmo** que o sistema de arquivos
//! vai percorrer. Duas normalizações — uma no VFS, outra na política — são
//! duas respostas para "que caminho é este", e a diferença entre elas é por
//! onde um `/dados/../etc` passaria. O VFS do kernel usa esta mesma função.

use alloc::string::String;

/// Um caminho absoluto sem barras repetidas, sem `.` e sem barra final.
///
/// `None` para um caminho relativo ou com `..`. O `..` é recusado, e não
/// resolvido: uma conferência pelo caminho escrito só é sólida se o caminho
/// escrito for o percorrido.
pub fn normalizar(caminho: &str) -> Option<String> {
    if !caminho.starts_with('/') {
        return None;
    }
    let mut saida = String::from("/");
    for parte in caminho.split('/').filter(|p| !p.is_empty() && *p != ".") {
        if parte == ".." {
            return None;
        }
        if saida.len() > 1 {
            saida.push('/');
        }
        saida.push_str(parte);
    }
    Some(saida)
}

/// `caminho` está em `prefixo` — é ele, ou está abaixo dele —, os dois já
/// normalizados. `/dados` contém `/dados/x`, e não `/dadosx`.
pub fn dentro_de(caminho: &str, prefixo: &str) -> bool {
    if prefixo == "/" {
        return true;
    }
    caminho
        .strip_prefix(prefixo)
        .is_some_and(|resto| resto.is_empty() || resto.starts_with('/'))
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn forma_normal() {
        assert_eq!(normalizar("/a//b/./c/").as_deref(), Some("/a/b/c"));
        assert_eq!(normalizar("/").as_deref(), Some("/"));
        assert_eq!(normalizar("a/b"), None);
        assert_eq!(normalizar("/a/../b"), None);
    }

    #[test]
    fn fronteira_de_componente() {
        assert!(dentro_de("/dados", "/dados"));
        assert!(dentro_de("/dados/x", "/dados"));
        assert!(!dentro_de("/dadosx", "/dados"));
        assert!(dentro_de("/qualquer", "/"));
    }
}
