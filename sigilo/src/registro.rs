//! O formato dos arquivos de chaves autorizadas.
//!
//! ```text
//! # comentário
//! 9f2c...64 dígitos hexadecimais...  agente-1  operador
//! ```
//!
//! Uma chave por linha: a pública, em hexadecimal, o nome que vai aparecer
//! nos relatórios e o papel, que a política define. O papel é opcional no
//! formato e não na prática: uma chave sem papel autentica e não pode nada —
//! é a política que diz o que cada papel pode, e sem papel não há o que
//! dizer. É o formato do `authorized_keys` do OpenSSH reduzido ao que se usa
//! aqui.
//!
//! O arquivo dos administradores tem um campo a mais, opcional: a chave
//! pública de **assinatura** da credencial, `ed25519:<64 hex>`. A chave da
//! primeira coluna é a X25519 da prova de uma credencial só; a de assinatura
//! é a Ed25519 com que ela assina um quórum — ver [`crate::quorum`]. Duas
//! chaves, e não uma usada para as duas contas: misturar Diffie-Hellman e
//! assinatura na mesma chave é o tipo de atalho que só se prova seguro com
//! uma análise que este projeto não fez. Só as públicas ficam no arquivo; as
//! privadas ficam com quem assina.
//!
//! ```text
//! 9f2c...64 hex...  administrador  administrador  ed25519:5e1a...64 hex...
//! ```
//!
//! Mora neste pacote, e não no kernel, porque são dois lados: o `xtask`
//! escreve o arquivo na imagem e o kernel o lê. Um formato escrito por um e
//! lido por outro é o lugar clássico de divergência silenciosa — um espaço a
//! mais, e a chave de um agente some do registro sem erro nenhum.

use alloc::string::String;

use crate::{TAM_CHAVE, de_hex, hex};

/// O maior nome de agente.
pub const MAIOR_NOME: usize = 32;

/// Um nome de agente aceitável: letras minúsculas, dígitos, `-`, `_` e `.`.
///
/// Curto e sem espaço porque ele vai para o log e para a barra: um nome
/// com quebra de linha ou com sequência de controle seria um jeito de um
/// agente escrever no log o que quisesse. O nome vem do registro, e não do
/// agente — mas quem registra pode errar, e a regra vale para os dois
/// caminhos de registro.
pub fn nome_valido(nome: &str) -> bool {
    !nome.is_empty()
        && nome.len() <= MAIOR_NOME
        && nome
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
}

/// Por que uma linha não entrou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErroDeLinha {
    /// A chave não tem 64 dígitos hexadecimais.
    Chave,
    /// Falta o nome, ou ele tem caracteres fora da regra.
    Nome,
    /// O papel tem caracteres fora da regra.
    Papel,
    /// Há algo depois do papel — ou, no arquivo dos administradores, algo
    /// que não é a chave de assinatura.
    Sobra,
    /// A chave de assinatura não é `ed25519:` com 64 dígitos hexadecimais.
    Assinatura,
    /// O nome é o reservado — ver [`EDITOR_DESCONHECIDO`].
    Reservado,
}

impl ErroDeLinha {
    /// Uma frase curta, para o log.
    pub const fn motivo(self) -> &'static str {
        match self {
            ErroDeLinha::Chave => "chave que nao tem 64 digitos hexadecimais",
            ErroDeLinha::Nome => "nome ausente ou fora da regra",
            ErroDeLinha::Papel => "papel fora da regra",
            ErroDeLinha::Sobra => "algo depois do papel",
            ErroDeLinha::Assinatura => "chave de assinatura que nao e ed25519 com 64 digitos",
            ErroDeLinha::Reservado => "nome reservado ao editor que o registro nao tem",
        }
    }
}

/// Uma entrada lida: a chave, o nome e o papel, se houver.
pub type Entrada<'a> = ([u8; TAM_CHAVE], &'a str, Option<&'a str>);

/// Lê uma linha. `Ok(None)` para linha vazia ou comentário.
pub fn ler_linha(linha: &str) -> Result<Option<Entrada<'_>>, ErroDeLinha> {
    let linha = linha.trim();
    if linha.is_empty() || linha.starts_with('#') {
        return Ok(None);
    }
    let mut partes = linha.split_ascii_whitespace();
    let chave = partes.next().and_then(de_hex).ok_or(ErroDeLinha::Chave)?;
    let nome = partes
        .next()
        .filter(|n| nome_valido(n))
        .ok_or(ErroDeLinha::Nome)?;
    let papel = match partes.next() {
        Some(p) if nome_valido(p) => Some(p),
        Some(_) => return Err(ErroDeLinha::Papel),
        None => None,
    };
    if partes.next().is_some() {
        return Err(ErroDeLinha::Sobra);
    }
    Ok(Some((chave, nome, papel)))
}

/// O prefixo da chave de assinatura de um administrador.
pub const PREFIXO_DE_ASSINATURA: &str = "ed25519:";

/// Uma entrada do arquivo dos administradores: a de [`ler_linha`] e a chave
/// pública de assinatura, se houver.
pub type EntradaDeAdministrador<'a> = (
    [u8; TAM_CHAVE],
    &'a str,
    Option<&'a str>,
    Option<[u8; TAM_CHAVE]>,
);

/// Lê uma linha do arquivo dos administradores: a de um agente, e depois do
/// papel, opcional, a chave de assinatura `ed25519:<hex>`.
pub fn ler_linha_de_administrador(
    linha: &str,
) -> Result<Option<EntradaDeAdministrador<'_>>, ErroDeLinha> {
    let linha = linha.trim();
    if linha.is_empty() || linha.starts_with('#') {
        return Ok(None);
    }
    // As três primeiras colunas são as de uma linha comum; a quarta, se
    // houver, é a chave de assinatura, e nada vem depois dela.
    let mut colunas = linha.split_ascii_whitespace();
    let comum: alloc::vec::Vec<&str> = colunas.by_ref().take(3).collect();
    // A linha comum é conferida pela regra de sempre; a chave sai dela, e o
    // nome e o papel, já conferidos, da linha original.
    let unida = comum.join(" ");
    let (chave, _, _) = ler_linha(&unida)?.ok_or(ErroDeLinha::Chave)?;
    let assinatura = match colunas.next() {
        None => None,
        Some(a) => Some(
            a.strip_prefix(PREFIXO_DE_ASSINATURA)
                .and_then(de_hex)
                .ok_or(ErroDeLinha::Assinatura)?,
        ),
    };
    if colunas.next().is_some() {
        return Err(ErroDeLinha::Sobra);
    }
    Ok(Some((chave, comum[1], comum.get(2).copied(), assinatura)))
}

/// A linha de um administrador, com a chave de assinatura.
pub fn linha_de_administrador(
    chave: &[u8; TAM_CHAVE],
    nome: &str,
    papel: &str,
    assinatura: &[u8; TAM_CHAVE],
) -> String {
    alloc::format!(
        "{} {nome} {papel} {PREFIXO_DE_ASSINATURA}{}\n",
        hex(chave),
        hex(assinatura)
    )
}

/// Uma entrada do registro de editores: a chave pública Ed25519 com que o
/// editor sela, e o nome dele.
pub type EntradaDeEditor<'a> = ([u8; TAM_CHAVE], &'a str);

/// O nome com que a auditoria diz o editor de uma chave que o registro não
/// tem — `<nome> <resumo> de desconhecido`, na descrição do programa. É
/// reservado no registro de editores: nenhum editor se chama assim, e
/// [`ler_linha_de_editor`] recusa a linha que tenta. Sem isso, o editor
/// registrado com esse nome não se distinguia, na auditoria, da chave que
/// ninguém registrou. O formato da linha não muda.
///
/// Só no registro de editores. O registro de chaves de atualização tem o
/// mesmo formato e não tem a reserva ([`ler_linha_de_atualizacao`]): o
/// nome de uma chave de atualização não vai à descrição de um programa, e
/// uma máquina de antes da reserva, com uma chave de atualização com esse
/// nome, ficaria presa à versão que roda — o kernel recusa o registro
/// inteiro por uma linha que não se lê antes da chave que assinou (ver
/// [`chave_de_atualizacao`]).
///
/// A migração: no registro de editores, a linha antiga com esse nome é
/// pulada com um aviso, como as outras linhas erradas, e o editor some — o
/// código dele deixa de rodar até a linha ganhar outro nome (falha
/// fechada). No de atualização, nada muda.
pub const EDITOR_DESCONHECIDO: &str = "desconhecido";

/// Lê uma linha do registro de editores — `ed25519:<hex> <nome>` — ver
/// [`crate::codigo`]: a de [`ler_linha_de_atualizacao`], e o nome
/// [`EDITOR_DESCONHECIDO`] recusado: [`ErroDeLinha::Reservado`].
pub fn ler_linha_de_editor(linha: &str) -> Result<Option<EntradaDeEditor<'_>>, ErroDeLinha> {
    let entrada = ler_linha_de_atualizacao(linha)?;
    if entrada.is_some_and(|(_, nome)| nome == EDITOR_DESCONHECIDO) {
        return Err(ErroDeLinha::Reservado);
    }
    Ok(entrada)
}

/// Lê uma linha do registro de chaves de atualização,
/// `/etc/duke/atualizacao` — o formato do de editores, `ed25519:<hex>
/// <nome>`, sem a reserva do nome (ver [`EDITOR_DESCONHECIDO`]). A chave
/// tem o prefixo de sempre, e tem de servir de chave Ed25519 de quem
/// assina: uma que não é ponto da curva, ou que é de ordem pequena, é
/// recusada aqui, e não descoberta na primeira assinatura que não confere.
pub fn ler_linha_de_atualizacao(linha: &str) -> Result<Option<EntradaDeEditor<'_>>, ErroDeLinha> {
    let linha = linha.trim();
    if linha.is_empty() || linha.starts_with('#') {
        return Ok(None);
    }
    let mut partes = linha.split_ascii_whitespace();
    let chave = partes
        .next()
        .and_then(|c| c.strip_prefix(PREFIXO_DE_ASSINATURA))
        .and_then(de_hex)
        .filter(crate::codigo::chave_valida)
        .ok_or(ErroDeLinha::Assinatura)?;
    let nome = partes
        .next()
        .filter(|n| nome_valido(n))
        .ok_or(ErroDeLinha::Nome)?;
    if partes.next().is_some() {
        return Err(ErroDeLinha::Sobra);
    }
    Ok(Some((chave, nome)))
}

/// O nome, no registro de chaves de atualização `texto`, da chave
/// `publica` — a busca que o kernel faz antes de conferir a assinatura de
/// uma imagem dos slots, e que o `xtask` faz igual. A primeira linha com a
/// chave dá o nome; `Ok(None)` se nenhuma a tem. Uma linha que não se lê
/// antes dela recusa o registro inteiro — o número dela, contado de 1, e o
/// porquê —: um registro meio lido seria uma confiança que ninguém
/// escreveu. As linhas depois da que achou não são lidas.
pub fn chave_de_atualizacao<'a>(
    texto: &'a str,
    publica: &[u8; TAM_CHAVE],
) -> Result<Option<&'a str>, (usize, ErroDeLinha)> {
    for (i, linha) in texto.lines().enumerate() {
        match ler_linha_de_atualizacao(linha) {
            Ok(Some((chave, nome))) if chave == *publica => return Ok(Some(nome)),
            Ok(_) => {}
            Err(e) => return Err((i + 1, e)),
        }
    }
    Ok(None)
}

/// A linha de um editor, com a quebra no fim.
pub fn linha_de_editor(chave: &[u8; TAM_CHAVE], nome: &str) -> String {
    alloc::format!("{PREFIXO_DE_ASSINATURA}{} {nome}\n", hex(chave))
}

/// A linha de uma entrada, com a quebra no fim.
pub fn linha(chave: &[u8; TAM_CHAVE], nome: &str, papel: Option<&str>) -> String {
    match papel {
        Some(p) => alloc::format!("{} {nome} {p}\n", hex(chave)),
        None => alloc::format!("{} {nome}\n", hex(chave)),
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn ida_e_volta() {
        let chave = [0xab; 32];
        let l = linha(&chave, "agente-1", Some("operador"));
        assert_eq!(
            ler_linha(&l),
            Ok(Some((chave, "agente-1", Some("operador"))))
        );
        let l = linha(&chave, "agente-1", None);
        assert_eq!(ler_linha(&l), Ok(Some((chave, "agente-1", None))));
    }

    #[test]
    fn comentario_e_vazia_nao_sao_entrada() {
        assert_eq!(ler_linha("   "), Ok(None));
        assert_eq!(ler_linha("# administradores"), Ok(None));
    }

    #[test]
    fn linhas_erradas_dizem_por_que() {
        let k = hex(&[1; 32]);
        assert_eq!(ler_linha("abc nome"), Err(ErroDeLinha::Chave));
        assert_eq!(ler_linha(&k), Err(ErroDeLinha::Nome));
        assert_eq!(
            ler_linha(&alloc::format!("{k} a Papel")),
            Err(ErroDeLinha::Papel)
        );
        assert_eq!(
            ler_linha(&alloc::format!("{k} Nome")),
            Err(ErroDeLinha::Nome)
        );
        assert_eq!(
            ler_linha(&alloc::format!("{k} a\u{1b}[2J")),
            Err(ErroDeLinha::Nome)
        );
        assert_eq!(
            ler_linha(&alloc::format!("{k} a b c")),
            Err(ErroDeLinha::Sobra)
        );
    }

    #[test]
    fn administrador_com_assinatura() {
        let (chave, assinatura) = ([0xab; 32], [0xcd; 32]);
        let l = linha_de_administrador(&chave, "adm", "administrador", &assinatura);
        assert_eq!(
            ler_linha_de_administrador(&l),
            Ok(Some((
                chave,
                "adm",
                Some("administrador"),
                Some(assinatura)
            )))
        );
        // Sem a chave de assinatura, a linha comum continua valendo.
        let l = linha(&chave, "adm", Some("administrador"));
        assert_eq!(
            ler_linha_de_administrador(&l),
            Ok(Some((chave, "adm", Some("administrador"), None)))
        );
        let k = hex(&chave);
        for ruim in [
            alloc::format!("{k} adm administrador ed25519:zz"),
            alloc::format!("{k} adm administrador {}", hex(&assinatura)),
            alloc::format!("{k} adm administrador x25519:{}", hex(&assinatura)),
        ] {
            assert_eq!(
                ler_linha_de_administrador(&ruim),
                Err(ErroDeLinha::Assinatura),
                "{ruim}"
            );
        }
        assert_eq!(
            ler_linha_de_administrador(&alloc::format!(
                "{k} adm administrador ed25519:{} sobra",
                hex(&assinatura)
            )),
            Err(ErroDeLinha::Sobra)
        );
    }

    #[test]
    fn editor_ida_e_volta_e_recusas() {
        let chave = crate::codigo::publica_do_editor(&[0x41; 32]);
        let l = linha_de_editor(&chave, "bancada");
        assert_eq!(ler_linha_de_editor(&l), Ok(Some((chave, "bancada"))));
        assert_eq!(ler_linha_de_editor("# editores"), Ok(None));
        assert_eq!(ler_linha_de_editor("  "), Ok(None));
        let k = hex(&chave);
        // Sem o prefixo, com outro prefixo, com hex torto.
        for ruim in [
            alloc::format!("{k} bancada"),
            alloc::format!("x25519:{k} bancada"),
            alloc::format!("ed25519:{} bancada", &k[..62]),
        ] {
            assert_eq!(
                ler_linha_de_editor(&ruim),
                Err(ErroDeLinha::Assinatura),
                "{ruim}"
            );
        }
        // Uma chave de ordem pequena — a identidade — não é de editor.
        let mut identidade = [0u8; 32];
        identidade[0] = 1;
        assert_eq!(
            ler_linha_de_editor(&linha_de_editor(&identidade, "fraco")),
            Err(ErroDeLinha::Assinatura)
        );
        assert_eq!(
            ler_linha_de_editor(&alloc::format!("ed25519:{k}")),
            Err(ErroDeLinha::Nome)
        );
        assert_eq!(
            ler_linha_de_editor(&alloc::format!("ed25519:{k} Bancada")),
            Err(ErroDeLinha::Nome)
        );
        assert_eq!(
            ler_linha_de_editor(&alloc::format!("ed25519:{k} bancada sobra")),
            Err(ErroDeLinha::Sobra)
        );
    }

    /// O nome que a auditoria dá à chave fora do registro é reservado: a
    /// linha que o usa é recusada, e um nome que só o contém não.
    #[test]
    fn o_editor_desconhecido_e_reservado() {
        let chave = crate::codigo::publica_do_editor(&[0x41; 32]);
        assert_eq!(
            ler_linha_de_editor(&linha_de_editor(&chave, EDITOR_DESCONHECIDO)),
            Err(ErroDeLinha::Reservado)
        );
        assert!(nome_valido(EDITOR_DESCONHECIDO));
        assert!(!ErroDeLinha::Reservado.motivo().is_empty());
        for parecido in ["desconhecido-1", "o-desconhecido", "desconhecid"] {
            assert_eq!(
                ler_linha_de_editor(&linha_de_editor(&chave, parecido)),
                Ok(Some((chave, parecido))),
                "{parecido}"
            );
        }
    }

    /// O registro de chaves de atualização tem o formato do de editores e
    /// as recusas dele, menos a reserva do nome: a linha com
    /// `desconhecido` se lê.
    #[test]
    fn a_linha_de_atualizacao_nao_tem_a_reserva() {
        let chave = crate::codigo::publica_do_editor(&[0x41; 32]);
        assert_eq!(
            ler_linha_de_atualizacao(&linha_de_editor(&chave, EDITOR_DESCONHECIDO)),
            Ok(Some((chave, EDITOR_DESCONHECIDO)))
        );
        assert_eq!(
            ler_linha_de_atualizacao(&linha_de_editor(&chave, "publicador-1")),
            Ok(Some((chave, "publicador-1")))
        );
        assert_eq!(ler_linha_de_atualizacao("# chaves"), Ok(None));
        let k = hex(&chave);
        for (ruim, erro) in [
            (alloc::format!("{k} bancada"), ErroDeLinha::Assinatura),
            (alloc::format!("ed25519:{k}"), ErroDeLinha::Nome),
            (alloc::format!("ed25519:{k} Bancada"), ErroDeLinha::Nome),
            (
                alloc::format!("ed25519:{k} bancada sobra"),
                ErroDeLinha::Sobra,
            ),
        ] {
            assert_eq!(ler_linha_de_atualizacao(&ruim), Err(erro), "{ruim}");
        }
        let mut identidade = [0u8; 32];
        identidade[0] = 1;
        assert_eq!(
            ler_linha_de_atualizacao(&linha_de_editor(&identidade, "fraco")),
            Err(ErroDeLinha::Assinatura)
        );
    }

    /// A busca da chave que assinou uma imagem dos slots: o registro de uma
    /// máquina de antes da reserva, com uma chave `desconhecido` antes da
    /// que assinou — ou sendo ela —, continua achando a chave. Uma linha
    /// errada antes dela recusa o registro; depois, não é lida.
    #[test]
    fn a_busca_da_chave_de_atualizacao() {
        let reservada = crate::codigo::publica_do_editor(&[0x41; 32]);
        let assinou = crate::codigo::publica_do_editor(&[0x42; 32]);
        let fora = crate::codigo::publica_do_editor(&[0x43; 32]);
        let texto = alloc::format!(
            "# as chaves\n{}{}",
            linha_de_editor(&reservada, EDITOR_DESCONHECIDO),
            linha_de_editor(&assinou, "bancada"),
        );
        assert_eq!(chave_de_atualizacao(&texto, &assinou), Ok(Some("bancada")));
        assert_eq!(
            chave_de_atualizacao(&texto, &reservada),
            Ok(Some(EDITOR_DESCONHECIDO))
        );
        assert_eq!(chave_de_atualizacao(&texto, &fora), Ok(None));
        assert_eq!(chave_de_atualizacao("", &assinou), Ok(None));
        // A primeira linha com a chave dá o nome.
        let repetida = alloc::format!(
            "{}{}",
            linha_de_editor(&assinou, "primeira"),
            linha_de_editor(&assinou, "segunda"),
        );
        assert_eq!(
            chave_de_atualizacao(&repetida, &assinou),
            Ok(Some("primeira"))
        );
        // A linha errada antes da chave recusa o registro, com o número
        // dela; depois da chave, não é lida.
        let errada = alloc::format!("ed25519:{} Torto\n", hex(&fora));
        let antes = alloc::format!("{errada}{texto}");
        assert_eq!(
            chave_de_atualizacao(&antes, &assinou),
            Err((1, ErroDeLinha::Nome))
        );
        let depois = alloc::format!("{texto}{errada}");
        assert_eq!(chave_de_atualizacao(&depois, &assinou), Ok(Some("bancada")));
        assert_eq!(
            chave_de_atualizacao(&depois, &fora),
            Err((4, ErroDeLinha::Nome))
        );
        // O registro de editores, lido com a mesma linha, recusa a
        // reservada — e só ela.
        assert_eq!(
            ler_linha_de_editor(texto.lines().nth(1).unwrap()),
            Err(ErroDeLinha::Reservado)
        );
    }

    #[test]
    fn nome_no_limite() {
        assert!(nome_valido(&"a".repeat(MAIOR_NOME)));
        assert!(!nome_valido(&"a".repeat(MAIOR_NOME + 1)));
    }
}
