//! O SDK da malha no `xtask` (DN-3): o contrato público da interface
//! nativa (DS-2), conferido contra as fontes, e as ferramentas de quem faz
//! um programa fora do repositório.
//!
//! # O contrato
//!
//! `sdk/contrato.txt` é a lista conferida do contrato v2: as chamadas de
//! mecanismo, os erros, os tipos de evento, os bits do aviso da malha, os
//! tetos do envelope, os códigos de recusa e os comandos da malha com os
//! parâmetros. [`conferir_o_contrato`] — parte do `cargo xtask invariantes`
//! — a compara com o `protocolo`, com o registro de comandos do kernel e
//! com os códigos da política (o NI03 da especificação):
//!
//! - o que a lista tem e a fonte não tem, ou tem com outro valor, outro
//!   tipo, outra obrigatoriedade, reprova — tirar, renomear ou mudar o
//!   sentido de um nome do contrato é quebrá-lo;
//! - o que a fonte tem, dentro do contrato, e a lista não — uma chamada, um
//!   erro, um tipo de evento, um bit, um código, um parâmetro de um comando
//!   da malha, um comando `fabric.*` ou `stream.*` — reprova até entrar na
//!   lista: crescer é decisão revisada, e não acaso.
//!
//! E duas regras do aviso nas fontes (NI01 e NI02): só `kernel/src/aviso.rs`
//! publica o tipo `MALHA`, montado só pela conta de `politica::aviso`; e
//! nenhum byte de fluxo nem corpo de entrega chega a ele.
//!
//! # As ferramentas
//!
//! - `cargo xtask selar <privada do editor> <elf> [--saida <arquivo>]`: sela
//!   um programa com a chave de um editor (`sigilo::codigo::selar`) — recusa
//!   o ELF sem manifesto legível e o já selado, confere o selo que produziu
//!   e diz o resumo. Lê só a chave do editor que recebe: nenhuma de
//!   dispositivo, de Pessoa ou do Duke. O kernel continua sem selar nada.
//! - `cargo xtask sdk-conferir <elf>`: o manifesto, a nota no lugar, o
//!   tamanho abaixo do teto de leitura do kernel, o selo — se há — e o
//!   resumo BLAKE2s que a auditoria vai citar.
//! - `cargo xtask sdk-fora [--arch A]`: o `sdk/modelo` copiado para fora do
//!   workspace, compilado contra o `programas` por caminho, conferido,
//!   selado pelo editor `bancada` e com as variantes que o Duke recusa — o
//!   NX01 a NX03, e o programa que a suíte instala e roda (NS28).

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use super::Arquitetura;

/// Onde mora a lista do contrato.
pub(crate) const CONTRATO: &str = "sdk/contrato.txt";

/// Onde mora o modelo de projeto.
pub(crate) const MODELO: &str = "sdk/modelo";

/// O nome do programa do modelo — o do manifesto dele, e o do executável.
pub(crate) const NOME_DO_MODELO: &str = "modelo";

// ---------------------------------------------------------------------------
// A lista do contrato
// ---------------------------------------------------------------------------

/// As listas de nomes com valor do contrato.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Lista {
    Chamada,
    Erro,
    Evento,
    Malha,
    Nativo,
    Codigo,
}

impl Lista {
    fn de(palavra: &str) -> Option<Lista> {
        Some(match palavra {
            "chamada" => Lista::Chamada,
            "erro" => Lista::Erro,
            "evento" => Lista::Evento,
            "malha" => Lista::Malha,
            "nativo" => Lista::Nativo,
            "codigo" => Lista::Codigo,
            _ => return None,
        })
    }

    fn nome(self) -> &'static str {
        match self {
            Lista::Chamada => "chamada",
            Lista::Erro => "erro",
            Lista::Evento => "evento",
            Lista::Malha => "malha",
            Lista::Nativo => "nativo",
            Lista::Codigo => "codigo",
        }
    }

    /// Se a fonte tem de ter só o que a lista tem: os tetos do envelope são
    /// os dois do contrato, entre outras constantes que não são.
    fn fechada(self) -> bool {
        self != Lista::Nativo
    }
}

/// Os tipos de parâmetro que o contrato conhece.
const TIPOS: [&str; 5] = ["inteiro", "texto", "intencao", "booleano", "lista"];

/// Um parâmetro de um comando do contrato.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Param {
    pub comando: String,
    pub nome: String,
    pub tipo: String,
    pub obrigatorio: bool,
}

/// A lista do contrato, lida.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Contrato {
    pub versao: i64,
    pub valores: Vec<(Lista, String, i64)>,
    pub comandos: Vec<String>,
    pub params: Vec<Param>,
}

fn nome_de_constante(n: &str) -> bool {
    !n.is_empty()
        && n.bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

fn nome_de_comando(n: &str) -> bool {
    let mut partes = n.split('.');
    let (Some(a), Some(b), None) = (partes.next(), partes.next(), partes.next()) else {
        return false;
    };
    [a, b].iter().all(|p| {
        !p.is_empty()
            && p.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
    })
}

fn nome_de_parametro(n: &str) -> bool {
    !n.is_empty()
        && n.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

/// Lê a lista do contrato. Uma linha que não se lê, um nome repetido, um
/// parâmetro de comando não declarado, a versão ausente: tudo reprova, com
/// o número da linha — uma lista que se lê pela metade conferiria a metade.
pub(crate) fn ler_contrato(texto: &str) -> Result<Contrato, String> {
    let mut c = Contrato::default();
    let mut versao = None;
    for (i, linha) in texto.lines().enumerate() {
        let n = i + 1;
        let linha = linha.trim();
        if linha.is_empty() || linha.starts_with('#') {
            continue;
        }
        let campos: Vec<&str> = linha.split_whitespace().collect();
        let erro = |motivo: &str| Err(format!("{CONTRATO}:{n}: {motivo}: `{linha}`"));
        match campos.as_slice() {
            ["versao", v] => {
                if versao.is_some() {
                    return erro("a versão repetida");
                }
                let Ok(v) = v.parse::<i64>() else {
                    return erro("a versão não é número");
                };
                versao = Some(v);
            }
            [lista, nome, valor] if Lista::de(lista).is_some() => {
                let lista = Lista::de(lista).unwrap_or(Lista::Nativo);
                if !nome_de_constante(nome) {
                    return erro("o nome não é de constante");
                }
                let Ok(valor) = valor.parse::<i64>() else {
                    return erro("o valor não é número");
                };
                if c.valores.iter().any(|(l, x, _)| *l == lista && x == nome) {
                    return erro("o nome repetido");
                }
                c.valores.push((lista, String::from(*nome), valor));
            }
            ["comando", nome] => {
                if !nome_de_comando(nome) {
                    return erro("o nome não é de comando");
                }
                if c.comandos.iter().any(|x| x == nome) {
                    return erro("o comando repetido");
                }
                c.comandos.push(String::from(*nome));
            }
            ["param", comando, nome, tipo, obrigatorio] => {
                if !c.comandos.iter().any(|x| x == comando) {
                    return erro("o parâmetro de um comando que a lista ainda não declarou");
                }
                if !nome_de_parametro(nome) {
                    return erro("o nome não é de parâmetro");
                }
                if !TIPOS.contains(tipo) {
                    return erro("o tipo não é um dos do contrato");
                }
                let obrigatorio = match *obrigatorio {
                    "obrigatorio" => true,
                    "opcional" => false,
                    _ => return erro("nem obrigatorio, nem opcional"),
                };
                if c.params
                    .iter()
                    .any(|p| p.comando == *comando && p.nome == *nome)
                {
                    return erro("o parâmetro repetido");
                }
                c.params.push(Param {
                    comando: String::from(*comando),
                    nome: String::from(*nome),
                    tipo: String::from(*tipo),
                    obrigatorio,
                });
            }
            _ => return erro("a linha não é de nenhuma forma da lista"),
        }
    }
    c.versao = versao.ok_or_else(|| format!("{CONTRATO}: sem a linha `versao`"))?;
    Ok(c)
}

// ---------------------------------------------------------------------------
// As fontes
// ---------------------------------------------------------------------------

/// O que as fontes dizem, nos termos da lista.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Fontes {
    pub versao: i64,
    pub valores: Vec<(Lista, String, i64)>,
    /// Os comandos do registro, com os parâmetros.
    pub comandos: Vec<(String, Vec<Param>)>,
}

/// O bloco que começa em `abertura` — a chave dela incluída — até a chave
/// que a fecha.
fn bloco<'t>(texto: &'t str, abertura: &str) -> Option<&'t str> {
    let de = texto.find(abertura)?;
    let inicio = de + abertura.rfind('{')?;
    let mut nivel = 0i64;
    for (i, c) in texto[inicio..].char_indices() {
        match c {
            '{' => nivel += 1,
            '}' => {
                nivel -= 1;
                if nivel == 0 {
                    return Some(&texto[inicio..inicio + i + 1]);
                }
            }
            _ => {}
        }
    }
    None
}

/// O valor de uma expressão de constante simples: inteiros (com `_`), o
/// sinal, `*`, `<<`, `+` e parênteses — o que as constantes do contrato
/// usam.
fn avaliar(expr: &str) -> Option<i64> {
    fn soma(t: &[char], i: &mut usize) -> Option<i64> {
        let mut v = termo(t, i)?;
        while *i < t.len() && t[*i] == '+' {
            *i += 1;
            v = v.checked_add(termo(t, i)?)?;
        }
        Some(v)
    }
    fn termo(t: &[char], i: &mut usize) -> Option<i64> {
        let mut v = fator(t, i)?;
        loop {
            if *i < t.len() && t[*i] == '*' {
                *i += 1;
                v = v.checked_mul(fator(t, i)?)?;
            } else if *i + 1 < t.len() && t[*i] == '<' && t[*i + 1] == '<' {
                *i += 2;
                v = v.checked_shl(u32::try_from(fator(t, i)?).ok()?)?;
            } else {
                return Some(v);
            }
        }
    }
    fn fator(t: &[char], i: &mut usize) -> Option<i64> {
        match t.get(*i)? {
            '-' => {
                *i += 1;
                fator(t, i)?.checked_neg()
            }
            '(' => {
                *i += 1;
                let v = soma(t, i)?;
                (t.get(*i) == Some(&')')).then_some(())?;
                *i += 1;
                Some(v)
            }
            c if c.is_ascii_digit() => {
                let mut v: i64 = 0;
                while let Some(c) = t.get(*i).filter(|c| c.is_ascii_digit() || **c == '_') {
                    if *c != '_' {
                        v = v.checked_mul(10)?.checked_add(c.to_digit(10)? as i64)?;
                    }
                    *i += 1;
                }
                Some(v)
            }
            _ => None,
        }
    }
    let t: Vec<char> = expr.chars().filter(|c| !c.is_whitespace()).collect();
    let mut i = 0;
    let v = soma(&t, &mut i)?;
    (i == t.len()).then_some(v)
}

/// As constantes `pub const NOME: TIPO = EXPR;` de um bloco, na ordem.
fn constantes(bloco: &str) -> Result<Vec<(String, i64)>, String> {
    let mut v = Vec::new();
    for linha in bloco.lines() {
        let Some(resto) = linha.trim().strip_prefix("pub const ") else {
            continue;
        };
        let (nome, resto) = resto
            .split_once(':')
            .ok_or_else(|| format!("constante ilegível: `{linha}`"))?;
        let (_, expr) = resto
            .split_once('=')
            .ok_or_else(|| format!("constante sem valor: `{linha}`"))?;
        let expr = expr.trim().trim_end_matches(';');
        let valor =
            avaliar(expr).ok_or_else(|| format!("o valor de `{nome}` não se avalia: `{expr}`"))?;
        v.push((String::from(nome.trim()), valor));
    }
    Ok(v)
}

/// O tipo de um `TipoParam` do registro, nos termos da lista.
fn tipo_da_fonte(tipo: &str) -> String {
    match tipo {
        "Inteiro" => String::from("inteiro"),
        "Texto" => String::from("texto"),
        "Booleano" => String::from("booleano"),
        "Lista" => String::from("lista"),
        "Formatado(Formato::Intencao)" => String::from("intencao"),
        outro => format!("outro:{outro}"),
    }
}

/// O texto entre aspas logo depois de `marca`, em `texto`.
fn depois_de<'t>(texto: &'t str, marca: &str) -> Option<&'t str> {
    let de = texto.find(marca)? + marca.len();
    let resto = &texto[de..];
    let ate = resto.find('"')?;
    Some(&resto[..ate])
}

/// Os comandos da tabela `COMANDOS` do registro, com os parâmetros.
fn comandos_do_registro(texto: &str) -> Result<Vec<(String, Vec<Param>)>, String> {
    let de = texto
        .find("pub static COMANDOS")
        .ok_or("a tabela COMANDOS não foi encontrada")?;
    let ate = texto[de..]
        .find("\n];\n")
        .ok_or("o fim da tabela COMANDOS não foi encontrado")?;
    let tabela = &texto[de..de + ate];
    let mut comandos = Vec::new();
    for bloco in tabela.split("Command {").skip(1) {
        let nome = depois_de(bloco, "nome: \"").ok_or("um comando sem nome")?;
        let mut params = Vec::new();
        for spec in bloco.split("ParamSpec {").skip(1) {
            let p = depois_de(spec, "nome: \"").ok_or("um parâmetro sem nome")?;
            let tipo = spec
                .split_once("tipo: TipoParam::")
                .and_then(|(_, r)| r.split_once(",\n"))
                .map(|(t, _)| t.trim())
                .ok_or_else(|| format!("{nome}.{p}: o tipo não se lê"))?;
            let obrigatorio = spec
                .split_once("obrigatorio: ")
                .map(|(_, r)| r.starts_with("true"))
                .ok_or_else(|| format!("{nome}.{p}: a obrigatoriedade não se lê"))?;
            params.push(Param {
                comando: String::from(nome),
                nome: String::from(p),
                tipo: tipo_da_fonte(tipo),
                obrigatorio,
            });
        }
        comandos.push((String::from(nome), params));
    }
    Ok(comandos)
}

/// Os códigos da política: o valor de cada variante e o nome dela.
fn codigos_da_politica(texto: &str) -> Result<Vec<(String, i64)>, String> {
    let enumeracao = bloco(texto, "pub enum Codigo {").ok_or("o enum Codigo não foi encontrado")?;
    let nomes = bloco(texto, "pub const fn nome(self) -> &'static str {")
        .ok_or("Codigo::nome não foi encontrado")?;
    let mut v = Vec::new();
    for linha in enumeracao.lines() {
        let linha = linha.trim();
        let Some((variante, valor)) = linha.trim_end_matches(',').split_once(" = ") else {
            continue;
        };
        let valor = avaliar(valor).ok_or_else(|| format!("Codigo::{variante} sem valor"))?;
        let nome = depois_de(nomes, &format!("Codigo::{variante} => \""))
            .ok_or_else(|| format!("Codigo::{variante} sem nome"))?;
        v.push((String::from(nome), valor));
    }
    Ok(v)
}

/// Lê as fontes que o contrato confere, na raiz `raiz`.
pub(crate) fn ler_fontes(raiz: &Path) -> Result<Fontes, String> {
    let ler = |arquivo: &str| {
        std::fs::read_to_string(raiz.join(arquivo))
            .map_err(|e| format!("não foi possível ler {arquivo}: {e}"))
    };
    let usuario = ler("protocolo/src/usuario.rs")?;
    let registro = ler("kernel/src/agent/commands.rs")?;
    let codigo = ler("politica/src/codigo.rs")?;
    let modulo = |abertura: &str| {
        bloco(&usuario, abertura).ok_or_else(|| format!("`{abertura}` não foi encontrado"))
    };
    let evento = modulo("pub mod evento {")?;
    let mut valores = Vec::new();
    for (lista, texto) in [
        (Lista::Chamada, modulo("pub mod numero {")?),
        (Lista::Erro, modulo("pub mod erro {")?),
        (
            Lista::Evento,
            bloco(evento, "pub mod tipo {").ok_or("`evento::tipo` não foi encontrado")?,
        ),
        (
            Lista::Malha,
            bloco(evento, "pub mod malha {").ok_or("`evento::malha` não foi encontrado")?,
        ),
        (Lista::Nativo, modulo("pub mod nativo {")?),
    ] {
        for (nome, valor) in constantes(texto)? {
            valores.push((lista, nome, valor));
        }
    }
    let versao = valores
        .iter()
        .find(|(l, n, _)| *l == Lista::Nativo && n == "VERSAO")
        .map(|(_, _, v)| *v)
        .ok_or("`nativo::VERSAO` não foi encontrada")?;
    valores.retain(|(l, n, _)| !(*l == Lista::Nativo && n == "VERSAO"));
    for (nome, valor) in codigos_da_politica(&codigo)? {
        valores.push((Lista::Codigo, nome, valor));
    }
    Ok(Fontes {
        versao,
        valores,
        comandos: comandos_do_registro(&registro)?,
    })
}

/// Se um comando da fonte está dentro do contrato por ser da malha.
fn da_malha(comando: &str) -> bool {
    comando.starts_with("fabric.") || comando.starts_with("stream.")
}

/// O que não bate entre a lista e as fontes — vazio, se tudo bate.
pub(crate) fn conferir_contrato(c: &Contrato, f: &Fontes) -> Vec<String> {
    let mut fora = Vec::new();
    if c.versao != f.versao {
        fora.push(format!(
            "a lista é da versão {} e o protocolo diz `nativo::VERSAO` = {}",
            c.versao, f.versao
        ));
    }
    for (lista, nome, valor) in &c.valores {
        match f.valores.iter().find(|(l, n, _)| l == lista && n == nome) {
            None => fora.push(format!(
                "{} {nome}: está no contrato e saiu da fonte",
                lista.nome()
            )),
            Some((_, _, v)) if v != valor => fora.push(format!(
                "{} {nome}: o contrato diz {valor} e a fonte, {v}",
                lista.nome()
            )),
            Some(_) => {}
        }
    }
    for (lista, nome, valor) in &f.valores {
        if lista.fechada() && !c.valores.iter().any(|(l, n, _)| l == lista && n == nome) {
            fora.push(format!(
                "{} {nome} = {valor}: está na fonte e não no contrato — o que cresce entra na lista, revisado",
                lista.nome()
            ));
        }
    }
    for comando in &c.comandos {
        let Some((_, params)) = f.comandos.iter().find(|(n, _)| n == comando) else {
            fora.push(format!(
                "comando {comando}: está no contrato e saiu do registro"
            ));
            continue;
        };
        let da_lista: Vec<&Param> = c.params.iter().filter(|p| &p.comando == comando).collect();
        for p in &da_lista {
            match params.iter().find(|x| x.nome == p.nome) {
                None => fora.push(format!(
                    "param {comando} {}: está no contrato e saiu do registro",
                    p.nome
                )),
                Some(x) if x.tipo != p.tipo || x.obrigatorio != p.obrigatorio => {
                    fora.push(format!(
                        "param {comando} {}: o contrato diz {} {}, o registro diz {} {}",
                        p.nome,
                        p.tipo,
                        if p.obrigatorio {
                            "obrigatorio"
                        } else {
                            "opcional"
                        },
                        x.tipo,
                        if x.obrigatorio {
                            "obrigatorio"
                        } else {
                            "opcional"
                        }
                    ))
                }
                Some(_) => {}
            }
        }
        for x in params {
            if !da_lista.iter().any(|p| p.nome == x.nome) {
                fora.push(format!(
                    "param {comando} {} {}: está no registro e não no contrato",
                    x.nome, x.tipo
                ));
            }
        }
    }
    for (comando, _) in &f.comandos {
        if da_malha(comando) && !c.comandos.contains(comando) {
            fora.push(format!(
                "comando {comando}: um comando da malha que não está no contrato"
            ));
        }
    }
    fora
}

/// O aviso da malha nas fontes (NI01 e NI02).
pub(crate) fn conferir_o_aviso(raiz: &Path) -> Vec<String> {
    let mut fora = Vec::new();
    // NI01: o tipo `MALHA` só é publicado por `kernel::aviso`, e lá, uma vez,
    // montado pela conta pura.
    let mut arquivos = Vec::new();
    juntar_rs(&raiz.join("kernel/src"), &mut arquivos);
    for arquivo in &arquivos {
        let relativo = arquivo.strip_prefix(raiz).unwrap_or(arquivo);
        let rel = relativo.to_string_lossy();
        if rel.starts_with("kernel/src/testes") {
            continue;
        }
        let Ok(texto) = std::fs::read_to_string(arquivo) else {
            continue;
        };
        let vezes = super::fora_de_comentario(&texto, "tipo::MALHA");
        if rel == "kernel/src/aviso.rs" {
            if vezes != 1 {
                fora.push(format!(
                    "{rel}: `tipo::MALHA` aparece {vezes}x, e devia uma"
                ));
            }
            if super::fora_de_comentario(&texto, "politica::aviso::campos(") != 1 {
                fora.push(format!(
                    "{rel}: o evento do aviso não é montado uma vez, pela conta de politica::aviso"
                ));
            }
            // NI02: nada do conteúdo — o buffer de um fluxo, o corpo de uma
            // entrega, uma leitura — chega ao construtor do aviso.
            for proibido in [
                ".anel",
                "corpo",
                "conteudo",
                "body",
                "content",
                "tirar_para_o_par",
                "fluxo::ler(",
                "malha::receber(",
                "Lida",
            ] {
                if super::fora_de_comentario(&texto, proibido) > 0 {
                    fora.push(format!(
                        "{rel}: `{proibido}` no aviso — o conteúdo não chega a ele"
                    ));
                }
            }
        } else if vezes > 0 {
            fora.push(format!(
                "{rel}: publica `tipo::MALHA` — só kernel::aviso publica o aviso da malha"
            ));
        }
    }
    fora
}

fn juntar_rs(dir: &Path, saida: &mut Vec<PathBuf>) {
    let Ok(entradas) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entradas.flatten() {
        let p = e.path();
        if p.is_dir() {
            juntar_rs(&p, saida);
        } else if p.extension().is_some_and(|x| x == "rs") {
            saida.push(p);
        }
    }
}

/// As linhas que valem de um `config.toml`: sem os comentários e as linhas
/// vazias.
fn linhas_que_valem(texto: &str) -> Vec<&str> {
    texto
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// O modelo de projeto anda com o `programas`: o script de ligação é o dos
/// programas da imagem — os mesmos bytes —, as opções de compilação são as
/// mesmas, linha a linha (os comentários de cada um são dele), e o
/// toolchain é o canal do repositório, com os dois alvos dos programas.
fn conferir_o_modelo(raiz: &Path) -> Vec<String> {
    let mut fora = Vec::new();
    let ler = |arquivo: &str| std::fs::read_to_string(raiz.join(arquivo)).ok();
    match (ler("sdk/modelo/usuario.ld"), ler("programas/usuario.ld")) {
        (Some(a), Some(b)) if a == b => {}
        (Some(_), Some(_)) => fora.push(String::from(
            "sdk/modelo/usuario.ld: diverge de programas/usuario.ld — o modelo liga como os programas",
        )),
        _ => fora.push(String::from(
            "sdk/modelo/usuario.ld ou programas/usuario.ld: não se lê",
        )),
    }
    match (
        ler("sdk/modelo/.cargo/config.toml"),
        ler("programas/.cargo/config.toml"),
    ) {
        (Some(a), Some(b)) if linhas_que_valem(&a) == linhas_que_valem(&b) => {}
        (Some(_), Some(_)) => fora.push(String::from(
            "sdk/modelo/.cargo/config.toml: as opções divergem das de programas/.cargo/config.toml — o modelo compila como os programas",
        )),
        _ => fora.push(String::from(
            "sdk/modelo/.cargo/config.toml ou programas/.cargo/config.toml: não se lê",
        )),
    }
    // O toolchain: o canal do repositório, e os dois alvos dos programas.
    let canal = |texto: &str| {
        linhas_que_valem(texto)
            .into_iter()
            .find(|l| l.starts_with("channel"))
            .map(String::from)
    };
    match (
        ler("sdk/modelo/rust-toolchain.toml"),
        ler("rust-toolchain.toml"),
    ) {
        (Some(a), Some(b)) => {
            if canal(&a).is_none() || canal(&a) != canal(&b) {
                fora.push(String::from(
                    "sdk/modelo/rust-toolchain.toml: o canal não é o do rust-toolchain.toml da raiz",
                ));
            }
            let valem = linhas_que_valem(&a).join("\n");
            for alvo in [Arquitetura::X86_64.alvo(), Arquitetura::Aarch64.alvo()] {
                if !valem.contains(&format!("\"{alvo}\"")) {
                    fora.push(format!(
                        "sdk/modelo/rust-toolchain.toml: falta o alvo `{alvo}`"
                    ));
                }
            }
        }
        _ => fora.push(String::from(
            "sdk/modelo/rust-toolchain.toml ou rust-toolchain.toml: não se lê",
        )),
    }
    fora
}

/// O contrato, o aviso e o modelo, conferidos nas fontes — parte do
/// `cargo xtask invariantes`.
pub(crate) fn conferir_o_contrato() -> Result<ExitCode, String> {
    let raiz = super::raiz_do_projeto();
    let texto = std::fs::read_to_string(raiz.join(CONTRATO))
        .map_err(|e| format!("não foi possível ler {CONTRATO}: {e}"))?;
    let contrato = ler_contrato(&texto)?;
    let fontes = ler_fontes(&raiz)?;
    let mut fora = conferir_contrato(&contrato, &fontes);
    fora.extend(conferir_o_aviso(&raiz));
    fora.extend(conferir_o_modelo(&raiz));
    if !fora.is_empty() {
        eprintln!("[xtask] o contrato público (DS-2) não bate com as fontes:");
        for f in &fora {
            eprintln!("  {f}");
        }
        return Ok(ExitCode::FAILURE);
    }
    println!(
        "[xtask] o contrato público v{}: {} nomes, {} comandos da malha e {} parâmetros batem com o protocolo, o registro e a política; só kernel::aviso publica o aviso, sem conteúdo; o modelo compila como os programas",
        contrato.versao,
        contrato.valores.len(),
        contrato.comandos.len(),
        contrato.params.len()
    );
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// O executável: o manifesto, o selo, o resumo
// ---------------------------------------------------------------------------

/// O manifesto de um ELF64: o do segmento de notas, pelo mesmo achador que
/// o kernel usa, lido pela mesma conta da política.
pub(crate) fn manifesto_do_elf(bytes: &[u8]) -> Result<politica::manifesto::Manifesto, String> {
    use protocolo::usuario::manifesto::{SEGMENTO_DE_NOTAS, achar};
    let u16_em = |i: usize| {
        bytes
            .get(i..i + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
    };
    let u32_em = |i: usize| {
        bytes
            .get(i..i + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let u64_em = |i: usize| {
        bytes
            .get(i..i + 8)
            .and_then(|b| b.try_into().ok())
            .map(|b: [u8; 8]| u64::from_le_bytes(b) as usize)
    };
    if bytes.get(..4) != Some(b"\x7fELF") || bytes.get(4) != Some(&2) || bytes.get(5) != Some(&1) {
        return Err(String::from("não é um ELF64 little-endian"));
    }
    let (Some(phoff), Some(tamanho), Some(quantos)) = (u64_em(0x20), u16_em(0x36), u16_em(0x38))
    else {
        return Err(String::from("o cabeçalho do ELF está cortado"));
    };
    let mut achado = None;
    for k in 0..quantos {
        let ph = phoff + k * tamanho;
        let (Some(tipo), Some(inicio), Some(n)) = (u32_em(ph), u64_em(ph + 8), u64_em(ph + 32))
        else {
            return Err(String::from("um cabeçalho de programa está cortado"));
        };
        if tipo != SEGMENTO_DE_NOTAS {
            continue;
        }
        let notas = bytes
            .get(inicio..inicio.saturating_add(n))
            .ok_or("o segmento de notas passa do fim do arquivo")?;
        if let Some(m) = achar(notas)? {
            if achado.is_some() {
                return Err(String::from("dois manifestos"));
            }
            achado = Some(m);
        }
    }
    let texto = achado.ok_or("sem manifesto: falta `programas::manifesto!`")?;
    politica::manifesto::ler(texto).map_err(|e| format!("o manifesto não se lê: {e:?}"))
}

/// Uma chave privada de editor, em hexadecimal, num arquivo.
fn ler_privada(caminho: &Path) -> Result<[u8; 32], String> {
    let texto = std::fs::read_to_string(caminho)
        .map_err(|e| format!("não foi possível ler {}: {e}", caminho.display()))?;
    sigilo::de_hex(texto.trim())
        .ok_or_else(|| format!("{} não tem uma chave em hexadecimal", caminho.display()))
}

/// Sela `elf` com a `privada` de um editor: o executável selado, conferido.
pub(crate) fn selado(elf: &[u8], privada: &[u8; 32]) -> Result<Vec<u8>, String> {
    use sigilo::codigo::{Falha, conferir, publica_do_editor, selar};
    match conferir(elf) {
        Err(Falha::SemSelo) => {}
        Ok(_) => return Err(String::from("o executável já está selado")),
        Err(f) => {
            return Err(format!(
                "o executável tem o que parece um selo, e ele não confere: {}",
                f.motivo()
            ));
        }
    }
    let m = manifesto_do_elf(elf)?;
    let s = selar(elf, privada);
    let c = conferir(&s).map_err(|f| format!("o selo produzido não confere: {}", f.motivo()))?;
    if c.codigo != elf || c.editor != publica_do_editor(privada) {
        return Err(String::from(
            "o selo produzido não guarda o executável inteiro, ou não é deste editor",
        ));
    }
    let _ = m;
    Ok(s)
}

/// `cargo xtask selar <privada> <elf> [--saida <arquivo>]`.
pub(crate) fn selar(privada: &Path, elf: &Path, saida: Option<&Path>) -> Result<ExitCode, String> {
    let chave = ler_privada(privada)?;
    let bytes =
        std::fs::read(elf).map_err(|e| format!("não foi possível ler {}: {e}", elf.display()))?;
    let m = manifesto_do_elf(&bytes)?;
    let s = selado(&bytes, &chave)?;
    let destino = saida
        .map(Path::to_path_buf)
        .unwrap_or_else(|| elf.with_extension("selado"));
    std::fs::write(&destino, &s)
        .map_err(|e| format!("não foi possível gravar {}: {e}", destino.display()))?;
    println!(
        "[xtask] selado: {} — programa `{}`, editor {}, resumo {}",
        destino.display(),
        m.nome(),
        sigilo::hex(&sigilo::codigo::publica_do_editor(&chave)),
        sigilo::hex(&sigilo::codigo::resumo(&bytes))
    );
    Ok(ExitCode::SUCCESS)
}

/// O que se diz de um executável: o nome, o que declara, o tamanho, o
/// resumo e o editor.
pub(crate) fn descrever(bytes: &[u8]) -> Result<String, String> {
    use sigilo::codigo::{Falha, conferir, resumo};
    let (codigo, editor) = match conferir(bytes) {
        Ok(c) => (c.codigo, Some(c.editor)),
        Err(Falha::SemSelo) => (bytes, None),
        Err(f) => return Err(format!("o selo não confere: {}", f.motivo())),
    };
    let m = manifesto_do_elf(codigo)?;
    let teto = protocolo::usuario::MAIOR_EXECUTAVEL as usize;
    if bytes.len() > teto {
        return Err(format!(
            "{} bytes passam do maior executável que o kernel lê, {teto}",
            bytes.len()
        ));
    }
    let permite: Vec<&str> = m.permite.iter().map(|p| p.nome()).collect();
    Ok(format!(
        "programa `{}`, permite [{}], {} bytes de {teto}, resumo {}, {}",
        m.nome(),
        permite.join(" "),
        bytes.len(),
        sigilo::hex(&resumo(codigo)),
        match editor {
            Some(e) => format!("selado pelo editor {}", sigilo::hex(&e)),
            None => String::from("sem selo — da imagem, ou para selar"),
        }
    ))
}

/// `cargo xtask sdk-conferir <elf>`.
pub(crate) fn sdk_conferir(elf: &Path) -> Result<ExitCode, String> {
    let bytes =
        std::fs::read(elf).map_err(|e| format!("não foi possível ler {}: {e}", elf.display()))?;
    match descrever(&bytes) {
        Ok(d) => {
            println!("[xtask] {}: {d}", elf.display());
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("[xtask] {}: {e}", elf.display());
            Ok(ExitCode::FAILURE)
        }
    }
}

// ---------------------------------------------------------------------------
// O modelo, compilado fora do workspace
// ---------------------------------------------------------------------------

/// Onde o modelo é copiado e compilado: fora de todo workspace — o
/// `Cargo.toml` dele declara o seu.
pub(crate) fn diretorio_de_fora() -> PathBuf {
    super::raiz_do_projeto().join("target").join("sdk-fora")
}

/// O modelo compilado e selado de `arch`, como a bancada o serve.
pub(crate) fn modelo_compilado(arch: Arquitetura) -> PathBuf {
    diretorio_de_fora().join(arch.nome()).join(NOME_DO_MODELO)
}

/// Grava `bytes` em `caminho` só se o que está lá é outra coisa: a data do
/// arquivo copiado não muda à toa, e o cargo não recompila o que não mudou.
fn gravar_se_mudou(caminho: &Path, bytes: &[u8]) -> Result<(), String> {
    if std::fs::read(caminho).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    if let Some(pai) = caminho.parent() {
        std::fs::create_dir_all(pai)
            .map_err(|e| format!("não foi possível criar {}: {e}", pai.display()))?;
    }
    std::fs::write(caminho, bytes)
        .map_err(|e| format!("não foi possível gravar {}: {e}", caminho.display()))
}

/// Os arquivos de `de`, com o caminho relativo a ele.
fn arquivos_de(de: &Path, relativo: &Path, saida: &mut Vec<PathBuf>) -> Result<(), String> {
    for e in std::fs::read_dir(de.join(relativo)).map_err(|e| format!("{}: {e}", de.display()))? {
        let e = e.map_err(|e| e.to_string())?;
        let r = relativo.join(e.file_name());
        if e.path().is_dir() {
            arquivos_de(de, &r, saida)?;
        } else {
            saida.push(r);
        }
    }
    Ok(())
}

/// Copia o modelo para fora do workspace, como faria quem o copia, e aponta
/// o `programas` e o `protocolo` pelo caminho absoluto deste checkout. As
/// versões das dependências são as do `programas` — o `Cargo.lock` dele
/// vai junto —, e o cargo resolve só o que é do modelo. Devolve a pasta.
pub(crate) fn copiar_o_modelo() -> Result<PathBuf, String> {
    let raiz = super::raiz_do_projeto();
    let copia = diretorio_de_fora().join("projeto");
    let mut arquivos = Vec::new();
    arquivos_de(&raiz.join(MODELO), Path::new(""), &mut arquivos)?;
    for relativo in &arquivos {
        let origem = raiz.join(MODELO).join(relativo);
        let mut bytes = std::fs::read(&origem)
            .map_err(|e| format!("não foi possível ler {}: {e}", origem.display()))?;
        if relativo == Path::new("Cargo.toml") {
            let texto = String::from_utf8_lossy(&bytes).into_owned();
            let raiz_texto = raiz.to_string_lossy();
            let trocado = texto
                .replace("../../programas", &format!("{raiz_texto}/programas"))
                .replace("../../protocolo", &format!("{raiz_texto}/protocolo"));
            if trocado == texto {
                return Err(format!(
                    "{MODELO}/Cargo.toml não aponta o programas e o protocolo por `../../`"
                ));
            }
            bytes = trocado.into_bytes();
        }
        gravar_se_mudou(&copia.join(relativo), &bytes)?;
    }
    let trava = raiz.join("programas").join("Cargo.lock");
    let trava = std::fs::read(&trava)
        .map_err(|e| format!("não foi possível ler {}: {e}", trava.display()))?;
    if !copia.join("Cargo.lock").is_file() {
        gravar_se_mudou(&copia.join("Cargo.lock"), &trava)?;
    }
    Ok(copia)
}

/// Compila o modelo copiado para fora do workspace ([`copiar_o_modelo`])
/// para `arch`, em release, com a pasta de compilação de quem o copiou.
/// Devolve o executável cru, como saiu do compilador.
pub(crate) fn compilar_o_modelo(arch: Arquitetura) -> Result<Vec<u8>, String> {
    let copia = copiar_o_modelo()?;
    println!(
        "[xtask] compilando o modelo do SDK fora do workspace ({}, release)...",
        arch.nome()
    );
    let alvo = diretorio_de_fora().join("target");
    let mut cargo = Command::new(env!("CARGO"));
    cargo
        .current_dir(&copia)
        .args(["build", "--release", "--target", arch.alvo()]);
    // Como no build dos programas: o que o cargo exporta para o xtask
    // descreve o build do xtask, e as opções do modelo são as do
    // `.cargo/config.toml` dele.
    for var in ["CARGO_ENCODED_RUSTFLAGS", "RUSTFLAGS"] {
        cargo.env_remove(var);
    }
    let estado = cargo
        .env("CARGO_TARGET_DIR", &alvo)
        .status()
        .map_err(|e| format!("não foi possível invocar o cargo: {e}"))?;
    if !estado.success() {
        return Err(format!("o modelo não compilou para {}", arch.nome()));
    }
    let elf = alvo.join(arch.alvo()).join("release").join(NOME_DO_MODELO);
    std::fs::read(&elf).map_err(|e| format!("não foi possível ler {}: {e}", elf.display()))
}

/// `cargo xtask sdk-fora [--arch A]`: o NX01 a NX03 — o modelo de fora
/// compila, confere e sela, e a cópia adulterada depois do selo não
/// confere. Deixa o ELF e o selado em `target/sdk-fora/<arquitetura>/`; a
/// bancada da suíte publica o modelo com as variantes dela (ver
/// [`super::codigo`]).
pub(crate) fn sdk_fora(arch: Arquitetura) -> Result<ExitCode, String> {
    use sigilo::codigo::{Falha, conferir};
    let elf = compilar_o_modelo(arch)?;
    let d = descrever(&elf)?;
    let m = manifesto_do_elf(&elf)?;
    if m.nome() != NOME_DO_MODELO {
        return Err(format!(
            "o manifesto do modelo diz `{}`, e não `{NOME_DO_MODELO}`",
            m.nome()
        ));
    }
    println!("[xtask] modelo ({}): {d}", arch.nome());
    let chaves = super::chaves::Chaves::garantir()?;
    let s = selado(&elf, &chaves.editor_da_bancada)?;
    let mut adulterado = s.clone();
    adulterado[elf.len() / 2] ^= 0x01;
    if conferir(&adulterado).map(|c| c.editor) != Err(Falha::NaoConfere) {
        return Err(String::from(
            "o modelo adulterado depois de selado ainda confere",
        ));
    }
    let pasta = modelo_compilado(arch);
    let pasta = pasta.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(pasta)
        .map_err(|e| format!("não foi possível criar {}: {e}", pasta.display()))?;
    std::fs::write(pasta.join(format!("{NOME_DO_MODELO}.elf")), &elf)
        .map_err(|e| format!("não foi possível gravar o modelo: {e}"))?;
    std::fs::write(modelo_compilado(arch), &s)
        .map_err(|e| format!("não foi possível gravar o modelo selado: {e}"))?;
    println!(
        "[xtask] modelo ({}): selado pelo editor bancada, o adulterado recusado — {}",
        arch.nome(),
        modelo_compilado(arch).display()
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod testes {
    use super::*;

    /// Um ELF64 mínimo com o segmento de notas — com o manifesto `texto`,
    /// ou vazio.
    fn elf_de_teste(texto: Option<&str>) -> Vec<u8> {
        let notas: Vec<u8> = match texto {
            Some(t) => {
                let alinhar = |n: usize| (n + 3) & !3;
                let mut n = Vec::new();
                n.extend_from_slice(&5u32.to_le_bytes());
                n.extend_from_slice(&(t.len() as u32).to_le_bytes());
                n.extend_from_slice(&1u32.to_le_bytes());
                n.extend_from_slice(b"Duke\0\0\0\0");
                n.extend_from_slice(t.as_bytes());
                n.resize(12 + 8 + alinhar(t.len()), 0);
                n
            }
            None => Vec::new(),
        };
        let mut e = vec![0u8; 64 + 56];
        e[..4].copy_from_slice(b"\x7fELF");
        e[4] = 2;
        e[5] = 1;
        e[6] = 1;
        e[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        e[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        e[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
        let ph = 64;
        e[ph..ph + 4].copy_from_slice(&4u32.to_le_bytes());
        e[ph + 8..ph + 16].copy_from_slice(&((64 + 56) as u64).to_le_bytes());
        e[ph + 32..ph + 40].copy_from_slice(&(notas.len() as u64).to_le_bytes());
        e.extend_from_slice(&notas);
        // O "código": bytes que não são nada, depois das notas.
        e.extend((0..300u32).map(|i| (i * 7) as u8));
        e
    }

    /// NH10: `selar` recusa o ELF sem manifesto e o já selado; o selo que
    /// produz é aceito por `sigilo::codigo::conferir`, com o editor certo; e
    /// os bytes antes do selo são o ELF intacto.
    #[test]
    fn nh10_selar() {
        let privada = [0x42u8; 32];
        let sem = elf_de_teste(None);
        assert!(selado(&sem, &privada).unwrap_err().contains("manifesto"));
        assert!(selado(b"nao e elf", &privada).is_err());
        let com = elf_de_teste(Some(
            "duke-manifesto 1\nnome modelo\npermite fabric.stream\n",
        ));
        let m = manifesto_do_elf(&com).unwrap();
        assert_eq!(m.nome(), "modelo");
        let s = selado(&com, &privada).unwrap();
        let c = sigilo::codigo::conferir(&s).unwrap();
        assert_eq!(c.codigo, &com[..]);
        assert_eq!(&s[..com.len()], &com[..]);
        assert_eq!(c.editor, sigilo::codigo::publica_do_editor(&privada));
        assert!(selado(&s, &privada).unwrap_err().contains("selado"));
        let d = descrever(&s).unwrap();
        assert!(
            d.contains("`modelo`") && d.contains("selado pelo editor"),
            "{d}"
        );
        // Adulterado: o selo não confere, e a descrição o diz.
        let mut a = s.clone();
        a[10] ^= 1;
        assert!(descrever(&a).unwrap_err().contains("selo"));
    }

    const LISTA: &str = "versao 2\n\
        chamada SAIR 0\n\
        chamada PEDIR 17\n\
        evento MALHA 9\n\
        comando stream.open\n\
        param stream.open endpoint texto obrigatorio\n\
        param stream.open notify inteiro opcional\n";

    fn fontes() -> Fontes {
        Fontes {
            versao: 2,
            valores: vec![
                (Lista::Chamada, String::from("SAIR"), 0),
                (Lista::Chamada, String::from("PEDIR"), 17),
                (Lista::Evento, String::from("MALHA"), 9),
            ],
            comandos: vec![(
                String::from("stream.open"),
                vec![
                    Param {
                        comando: String::from("stream.open"),
                        nome: String::from("endpoint"),
                        tipo: String::from("texto"),
                        obrigatorio: true,
                    },
                    Param {
                        comando: String::from("stream.open"),
                        nome: String::from("notify"),
                        tipo: String::from("inteiro"),
                        obrigatorio: false,
                    },
                ],
            )],
        }
    }

    /// NH11: a lista se lê; cada forma de linha malformada reprova com o
    /// número dela.
    #[test]
    fn nh11_a_lista_do_contrato() {
        let c = ler_contrato(LISTA).unwrap();
        assert_eq!(c.versao, 2);
        assert_eq!(c.valores.len(), 3);
        assert_eq!(c.params.len(), 2);
        assert!(conferir_contrato(&c, &fontes()).is_empty());
        for ruim in [
            "versao dois\n",
            "versao 2\nchamada sair 0\n",
            "versao 2\nchamada SAIR zero\n",
            "versao 2\nchamada SAIR 0\nchamada SAIR 1\n",
            "versao 2\nparam stream.open x texto obrigatorio\n",
            "versao 2\ncomando stream.open\nparam stream.open x real obrigatorio\n",
            "versao 2\ncomando stream.open\nparam stream.open x texto talvez\n",
            "versao 2\ncomando Stream\n",
            "versao 2\nqualquer coisa\n",
            "chamada SAIR 0\n",
        ] {
            assert!(ler_contrato(ruim).is_err(), "aceitou: {ruim}");
        }
        // E a lista de verdade, a do repositório, se lê.
        let raiz = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let texto = std::fs::read_to_string(raiz.join(CONTRATO)).unwrap();
        assert_eq!(ler_contrato(&texto).unwrap().versao, 2);
    }

    /// N23 (o exemplar de teste): a conferência acusa o parâmetro tirado, o
    /// tipo mudado, a obrigatoriedade mudada, o parâmetro acrescentado sem a
    /// lista, a chamada renumerada, o comando da malha novo e a versão que
    /// não subiu.
    #[test]
    fn n23_a_conferencia_acusa_o_que_mudou() {
        let c = ler_contrato(LISTA).unwrap();
        let mut f = fontes();
        f.comandos[0].1.retain(|p| p.nome != "notify");
        assert!(
            conferir_contrato(&c, &f)
                .iter()
                .any(|x| x.contains("notify") && x.contains("saiu"))
        );
        let mut f = fontes();
        f.comandos[0].1[1].tipo = String::from("texto");
        assert!(!conferir_contrato(&c, &f).is_empty());
        let mut f = fontes();
        f.comandos[0].1[1].obrigatorio = true;
        assert!(!conferir_contrato(&c, &f).is_empty());
        let mut f = fontes();
        f.comandos[0].1.push(Param {
            comando: String::from("stream.open"),
            nome: String::from("prioridade"),
            tipo: String::from("inteiro"),
            obrigatorio: false,
        });
        assert!(
            conferir_contrato(&c, &f)
                .iter()
                .any(|x| x.contains("prioridade"))
        );
        let mut f = fontes();
        f.valores[1].2 = 18;
        assert!(
            conferir_contrato(&c, &f)
                .iter()
                .any(|x| x.contains("PEDIR"))
        );
        let mut f = fontes();
        f.valores.push((Lista::Chamada, String::from("NOVA"), 20));
        assert!(conferir_contrato(&c, &f).iter().any(|x| x.contains("NOVA")));
        let mut f = fontes();
        f.comandos
            .push((String::from("stream.reabrir"), Vec::new()));
        assert!(
            conferir_contrato(&c, &f)
                .iter()
                .any(|x| x.contains("stream.reabrir"))
        );
        let mut f = fontes();
        f.versao = 1;
        assert!(
            conferir_contrato(&c, &f)
                .iter()
                .any(|x| x.contains("VERSAO"))
        );
    }

    /// As fontes de verdade se leem, e a lista do repositório bate com elas
    /// — a mesma conferência do `cargo xtask invariantes`.
    #[test]
    fn o_contrato_do_repositorio_bate_com_as_fontes() {
        let raiz = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let c = ler_contrato(&std::fs::read_to_string(raiz.join(CONTRATO)).unwrap()).unwrap();
        let f = ler_fontes(&raiz).unwrap();
        assert_eq!(conferir_contrato(&c, &f), Vec::<String>::new());
        assert_eq!(conferir_o_aviso(&raiz), Vec::<String>::new());
    }

    #[test]
    fn as_expressoes_das_constantes() {
        assert_eq!(avaliar("60 * 1024"), Some(61_440));
        assert_eq!(avaliar("1 << 4"), Some(16));
        assert_eq!(avaliar("-14"), Some(-14));
        assert_eq!(avaliar("16 * 1024 * 1024"), Some(16 * 1024 * 1024));
        assert_eq!(avaliar("(1 << 2) + 1"), Some(5));
        assert_eq!(avaliar("1_000"), Some(1000));
        assert_eq!(avaliar("ALGO"), None);
        assert_eq!(avaliar("1 +"), None);
    }
}
