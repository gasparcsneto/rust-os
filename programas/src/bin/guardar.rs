//! Um programa que guarda dados no armazém do Duke — ver
//! `docs/ARMAZENAMENTO.md` —, e confere de dentro o que o armazém promete a
//! um processo:
//!
//! - escreve pelo mesmo `pedir` de todo comando, e o manifesto declara
//!   `fs.write`: sem isso, o gate recusaria, qualquer que fosse o papel de
//!   quem o lançou;
//! - a versão: gravar contra uma versão velha é `CONFLICT`, com a de agora;
//! - lê o que gravou pelo `abrir` e `ler` de sempre;
//! - um descritor aberto num conteúdo que mudou recebe `MUDOU`, e nunca
//!   metade de um conteúdo e metade de outro;
//! - fora do armazém, `DENY_RESOURCE`: `fs.write` não alcança o resto da
//!   árvore em papel nenhum;
//! - os diretórios são explícitos: o programa cria o seu antes de gravar
//!   dentro dele, e nada é criado de passagem;
//! - o conteúdo binário vai fora do JSON, no anexo do pedido
//!   (`PEDIR_COM_ANEXO`), e volta byte a byte pela leitura de sempre.
//!
//! Lançado por alguém sem `fs.write` no papel, sai com [`SEM_ESCRITA`]
//! depois de ouvir `DENY_PERMISSION`. Sai com [`CODIGO`] quando tudo
//! confere, e com um código menor que diz o quê, quando não.

#![no_std]
#![no_main]

programas::manifesto!("guardar", "fs.read", "fs.write");

use programas::escreverln;
use programas::nativo::{self, Recusa};
use programas::sistema::{self, erro};

/// O código de saída quando tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 77;

/// O código de quem foi lançado sem `fs.write` no papel: o gate recusou, e
/// o programa diz que entendeu.
const SEM_ESCRITA: i64 = 70;

const DIRETORIO: &str = "/armazem/compartilhado/programa";
const CAMINHO: &str = "/armazem/compartilhado/programa/nota.txt";
const BINARIO: &str = "/armazem/compartilhado/programa/bytes.bin";

fn codigo_de(r: &nativo::Resposta) -> Option<&str> {
    match r.resultado() {
        Err(Recusa { motivo, .. }) => motivo,
        Ok(v) => v.member("code").and_then(|c| c.as_str()),
    }
}

fn erro(r: &nativo::Resposta) -> Option<&str> {
    r.resultado().ok()?.member("error")?.as_str()
}

fn numero(r: &nativo::Resposta, campo: &str) -> Option<u64> {
    r.resultado().ok()?.member(campo)?.as_u64()
}

fn ok(r: &nativo::Resposta) -> bool {
    r.resultado()
        .ok()
        .and_then(|v| v.member("ok"))
        .and_then(|v| v.as_bool())
        == Some(true)
}

fn gravar(versao: u64, texto: &str) -> Result<nativo::Resposta, i64> {
    nativo::pedir("fs.write", |w| {
        w.field_str("path", CAMINHO)?;
        w.field_str("content", texto)?;
        w.field_u64("expect_version", versao)
    })
}

/// O conteúdo do arquivo, pelo descritor `d`, do começo.
fn ler_tudo(d: u64, destino: &mut [u8]) -> i64 {
    sistema::ler(d, destino)
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    // A versão de agora — 0 se o arquivo ainda não existe.
    let Ok(estado) = nativo::pedir("fs.stat", |w| w.field_str("path", CAMINHO)) else {
        return 1;
    };
    // Sem `fs.read` no papel, não se sabe a versão: tenta-se criar, e o gate
    // diz o que o papel tem.
    let antes = match numero(&estado, "version") {
        Some(v) => v,
        None if codigo_de(&estado) == Some("DENY_PERMISSION") => 0,
        None => {
            escreverln!("guardar: fs.stat deu {:?}", codigo_de(&estado));
            return 1;
        }
    };

    // O diretório, explícito: sem ele a gravação seria recusada — o pai
    // tem de existir. Já existir, de uma volta anterior, não é erro.
    let Ok(r) = nativo::pedir("fs.mkdir", |w| w.field_str("path", DIRETORIO)) else {
        return 1;
    };
    if codigo_de(&r) == Some("DENY_PERMISSION") {
        escreverln!("guardar: sem fs.write no papel de quem me lancou");
        return SEM_ESCRITA;
    }
    if !ok(&r) && erro(&r) != Some("ja ha algo nesse caminho") {
        escreverln!("guardar: o mkdir deu {:?} {:?}", codigo_de(&r), erro(&r));
        return 1;
    }

    // Gravar: pelo gate, contra a versão lida.
    let Ok(r) = gravar(antes, "primeira linha\n") else {
        return 2;
    };
    if codigo_de(&r) == Some("DENY_PERMISSION") {
        escreverln!("guardar: sem fs.write no papel de quem me lancou");
        return SEM_ESCRITA;
    }
    if !ok(&r) {
        escreverln!("guardar: a gravacao deu {:?}", codigo_de(&r));
        return 2;
    }
    let Some(v1) = numero(&r, "version") else {
        return 2;
    };
    escreverln!("guardar: gravado na versao {}", v1);

    // A versão velha: conflito, com a de agora.
    let Ok(r) = gravar(antes, "de quem leu antes\n") else {
        return 3;
    };
    if codigo_de(&r) != Some("CONFLICT") || numero(&r, "current_version") != Some(v1) {
        escreverln!("guardar: a versao velha deu {:?}", codigo_de(&r));
        return 3;
    }
    escreverln!("guardar: a versao velha e conflito");

    // Ler pelo descritor, como qualquer arquivo.
    let d = sistema::abrir(CAMINHO);
    if d < 0 {
        escreverln!("guardar: abrir deu {}", d);
        return 4;
    }
    let mut buffer = [0u8; 64];
    let n = ler_tudo(d as u64, &mut buffer);
    if n < 0 || &buffer[..n as usize] != b"primeira linha\n" {
        escreverln!("guardar: a leitura deu {}", n);
        return 4;
    }
    escreverln!("guardar: lido o que foi gravado");

    // Mudado por baixo do descritor aberto: o descritor é do conteúdo de
    // antes, que não existe mais.
    let d2 = sistema::abrir(CAMINHO);
    if d2 < 0 {
        return 5;
    }
    let Ok(r) = nativo::pedir("fs.append", |w| {
        w.field_str("path", CAMINHO)?;
        w.field_str("content", "segunda linha\n")?;
        w.field_u64("expect_version", v1)
    }) else {
        return 5;
    };
    if !ok(&r) {
        escreverln!("guardar: o acrescimo deu {:?}", codigo_de(&r));
        return 5;
    }
    if ler_tudo(d2 as u64, &mut buffer) != erro::MUDOU {
        escreverln!("guardar: o descritor velho leu o conteudo novo");
        return 6;
    }
    sistema::fechar(d2 as u64);
    sistema::fechar(d as u64);
    let d3 = sistema::abrir(CAMINHO);
    let n = ler_tudo(d3 as u64, &mut buffer);
    if n < 0 || &buffer[..n as usize] != b"primeira linha\nsegunda linha\n" {
        return 6;
    }
    sistema::fechar(d3 as u64);
    escreverln!("guardar: o descritor velho diz que mudou");

    // Fora do alcance: `fs.write` não alcança nada fora do armazém, em papel
    // nenhum — nem no do sistema.
    let Ok(r) = nativo::pedir("fs.write", |w| {
        w.field_str("path", "/dados/fora-do-alcance.txt")?;
        w.field_str("content", "x")?;
        w.field_u64("expect_version", 0)
    }) else {
        return 7;
    };
    if codigo_de(&r) != Some("DENY_RESOURCE") {
        escreverln!("guardar: fora do alcance deu {:?}", codigo_de(&r));
        return 7;
    }
    escreverln!("guardar: fora do alcance e recusado");

    // Binário, fora do JSON: todos os bytes, o zero e o 0xFF incluídos, no
    // anexo do pedido; e de volta pela leitura de sempre.
    let mut bytes = [0u8; 600];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37);
    }
    let Ok(estado) = nativo::pedir("fs.stat", |w| w.field_str("path", BINARIO)) else {
        return 8;
    };
    let versao = numero(&estado, "version").unwrap_or(0);
    let Ok(r) = nativo::pedir_com_anexo(
        "fs.write",
        |w| {
            w.field_str("path", BINARIO)?;
            w.field_u64("expect_version", versao)
        },
        &bytes,
    ) else {
        return 8;
    };
    if !ok(&r) || numero(&r, "size") != Some(bytes.len() as u64) {
        escreverln!("guardar: o anexo deu {:?} {:?}", codigo_de(&r), erro(&r));
        return 8;
    }
    let d = sistema::abrir(BINARIO);
    if d < 0 {
        return 8;
    }
    let mut lido = [0u8; 700];
    let n = ler_tudo(d as u64, &mut lido);
    sistema::fechar(d as u64);
    if n < 0 || lido[..n as usize] != bytes[..] {
        escreverln!("guardar: o binario voltou diferente ({} bytes)", n);
        return 8;
    }
    escreverln!("guardar: o binario foi e voltou pelo anexo");

    escreverln!("guardar conferido: o armazem pelo mesmo gate");
    CODIGO
}

extern crate alloc;
