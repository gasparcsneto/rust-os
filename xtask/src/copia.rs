//! A bancada da cópia de segurança e da restauração: `cargo xtask copia`.
//!
//! Tudo pelo caminho de verdade: um agente numa porta da máquina — o canal
//! cifrado, pelo gate — faz a cópia, a baixa em pedaços para um arquivo do
//! hospedeiro, envia de volta por `fs.draft` e restaura, com as mesmas
//! funções do `cargo xtask operar --copia` e `--restaurar`. O hospedeiro só
//! guarda bytes que não sabe abrir. Cada cenário numa máquina nova:
//!
//! - a volta inteira, com o corte de energia: a cópia sai cifrada, presa a
//!   esta máquina, sem nada em claro; a árvore muda; a cópia volta numa
//!   confirmação; depois do corte, o boot seguinte tem a árvore da cópia, a
//!   restauração com a decisão de volta do journal, a cadeia da auditoria
//!   e o volume conferindo;
//! - a autoridade não volta: a chave revogada depois da cópia continua
//!   revogada depois da restauração e do corte, e a árvore restaurada é de
//!   quem restaurou;
//! - a máquina reinstalada — o journal novo, outra instalação, a mesma
//!   identidade da imagem — recusa a cópia de antes, e nada muda;
//! - a queda em cada fronteira da cópia e da restauração: no boot seguinte
//!   a árvore é inteira a de antes ou inteira a da cópia — a da cópia
//!   exatamente quando a confirmação está no journal —, o volume confere,
//!   e a restauração seguinte vale;
//! - a imagem de produção, com a identidade nascida no TPM: o agente do
//!   operador copia e restaura, e a restauração sobrevive ao corte; outra
//!   máquina de produção — outra identidade, outro TPM — recusa a cópia, e
//!   a primeira continua a aceitá-la.

use std::path::PathBuf;
use std::process::ExitCode;

use super::persistencia::{self as p, Ligada};
use super::{AgenteNaPorta, Ambiente, Arquitetura, Artefato, chaves, producao};

/// A subárvore dos cenários: no armazém compartilhado, onde o operador
/// escreve e restaura.
const RAIZ: &str = "/armazem/compartilhado/bancada-copia";

/// As portas de dois agentes operadores na imagem de desenvolvimento.
const OPERADOR: u8 = 2;
const OUTRO_OPERADOR: u8 = 3;

/// Base64 (RFC 4648, com `=`) de volta a bytes: o `content` de um
/// `fs.backup` ou de um `fs.read`. `None` para o que não é base64.
pub(crate) fn de_base64(texto: &str) -> Option<Vec<u8>> {
    let valor = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let b = texto.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let mut saida = Vec::with_capacity(b.len() / 4 * 3);
    for quatro in b.chunks(4) {
        let iguais = quatro.iter().rev().take_while(|&&c| c == b'=').count();
        if iguais > 2 {
            return None;
        }
        let mut n = 0u32;
        for &c in &quatro[..4 - iguais] {
            n = (n << 6) | valor(c)?;
        }
        n <<= 6 * iguais as u32;
        let tres = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        saida.extend_from_slice(&tres[..3 - iguais]);
    }
    Some(saida)
}

/// A bancada: as duas compilações do kernel — sem e com os pontos de
/// queda: a segunda só depois dos cenários da primeira, porque substitui a
/// primeira no disco de testes —, e o molde de produção, com a privada do
/// agente operador dele.
struct Bancada {
    arch: Arquitetura,
    dev: Artefato,
    quedas: Option<Artefato>,
    producao: Option<(PathBuf, [u8; 32])>,
}

/// Um cenário: um nome que se lê como afirmação, e a função que a confere.
struct Cenario {
    nome: &'static str,
    quedas: bool,
    producao: bool,
    rodar: fn(&Bancada) -> Result<String, String>,
}

const CENARIOS: &[Cenario] = &[
    Cenario {
        nome: "a copia sai cifrada para esta maquina, volta numa confirmacao, e o corte nao a desfaz",
        quedas: false,
        producao: false,
        rodar: a_volta_sobrevive_ao_corte,
    },
    Cenario {
        nome: "a copia nao traz autoridade: a chave revogada depois dela continua revogada",
        quedas: false,
        producao: false,
        rodar: a_autoridade_nao_volta,
    },
    Cenario {
        nome: "a maquina reinstalada, com a mesma identidade da imagem, recusa a copia de antes",
        quedas: false,
        producao: false,
        rodar: a_reinstalada_recusa,
    },
    Cenario {
        nome: "a imagem de producao: o operador copia e restaura, e outra maquina recusa a copia",
        quedas: false,
        producao: true,
        rodar: a_producao_copia_e_restaura,
    },
    // Por último: a compilação com os pontos de queda substitui a outra no
    // disco de testes.
    Cenario {
        nome: "a queda em cada fronteira: no boot seguinte, a arvore e inteira a de antes ou a da copia",
        quedas: true,
        producao: false,
        rodar: as_quedas,
    },
];

// ---------------------------------------------------------------------------
// A árvore, pelo agente
// ---------------------------------------------------------------------------

/// Os arquivos da árvore e o conteúdo de cada um: um texto, um vazio e um
/// binário de alguns blocos num subdiretório.
fn arvore() -> Vec<(String, Vec<u8>)> {
    let binario: Vec<u8> = (0..10_000u32).map(|i| (i * 13 % 251) as u8).collect();
    vec![
        (format!("{RAIZ}/a.txt"), b"o texto da bancada".to_vec()),
        (format!("{RAIZ}/vazio"), Vec::new()),
        (format!("{RAIZ}/sub/b.bin"), binario),
    ]
}

/// O resultado deu certo; senão, o erro com a resposta.
fn exigir(r: &str, o_que: &str) -> Result<(), String> {
    if r.contains(r#""ok":true"#) {
        Ok(())
    } else {
        Err(format!("{o_que}\n  {r}"))
    }
}

/// A versão de `c` agora — 0 se não há nó lá.
fn versao(agente: &mut AgenteNaPorta, c: &str) -> Result<u64, String> {
    let r = agente.pedir("fs.stat", &format!(r#"{{"path":"{c}"}}"#))?;
    p::texto_do_resultado(&r, "version")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("o fs.stat de {c} nao diz a versao\n  {r}"))
}

/// Planta a árvore, pelo agente: o armazém compartilhado, se falta, o
/// diretório, o subdiretório e os arquivos.
fn plantar(agente: &mut AgenteNaPorta) -> Result<(), String> {
    if versao(agente, "/armazem/compartilhado")? == 0 {
        let r = agente.pedir("fs.mkdir", r#"{"path":"/armazem/compartilhado"}"#)?;
        exigir(&r, "o armazem compartilhado nao foi criado")?;
    }
    for d in [RAIZ.to_string(), format!("{RAIZ}/sub")] {
        let r = agente.pedir("fs.mkdir", &format!(r#"{{"path":"{d}"}}"#))?;
        exigir(&r, "um diretorio da arvore nao foi criado")?;
    }
    for (c, conteudo) in arvore() {
        let r = if conteudo.is_empty() {
            agente.pedir(
                "fs.write",
                &format!(r#"{{"path":"{c}","content":"","expect_version":0}}"#),
            )?
        } else {
            agente.pedir_com_anexo(
                "fs.write",
                &format!(r#"{{"path":"{c}","expect_version":0}}"#),
                &conteudo,
            )?
        };
        exigir(&r, "um arquivo da arvore nao foi gravado")?;
    }
    Ok(())
}

/// Muda a árvore depois da cópia: o texto reescrito, o vazio apagado, um
/// arquivo novo e o subdiretório com outro nome.
fn mudar(agente: &mut AgenteNaPorta) -> Result<(), String> {
    let a = format!("{RAIZ}/a.txt");
    let v = versao(agente, &a)?;
    let r = agente.pedir(
        "fs.write",
        &format!(r#"{{"path":"{a}","content":"outra coisa","expect_version":{v}}}"#),
    )?;
    exigir(&r, "o texto nao mudou")?;
    let vazio = format!("{RAIZ}/vazio");
    let v = versao(agente, &vazio)?;
    let r = agente.pedir(
        "fs.delete",
        &format!(r#"{{"path":"{vazio}","expect_version":{v}}}"#),
    )?;
    exigir(&r, "o vazio nao saiu")?;
    let r = agente.pedir(
        "fs.write",
        &format!(r#"{{"path":"{RAIZ}/novo.txt","content":"novo","expect_version":0}}"#),
    )?;
    exigir(&r, "o novo nao entrou")?;
    let sub = format!("{RAIZ}/sub");
    let v = versao(agente, &sub)?;
    let r = agente.pedir(
        "fs.rename",
        &format!(r#"{{"path":"{sub}","to":"{RAIZ}/sub2","expect_version":{v}}}"#),
    )?;
    exigir(&r, "o subdiretorio nao mudou de nome")
}

/// O que a árvore tem em cada caminho que os cenários tocam: o tipo e o
/// conteúdo, lido pelo agente em pedaços do `fs.read`.
fn retrato(agente: &mut AgenteNaPorta) -> Result<Vec<(String, String, Vec<u8>)>, String> {
    let caminhos = [
        String::from(RAIZ),
        format!("{RAIZ}/a.txt"),
        format!("{RAIZ}/vazio"),
        format!("{RAIZ}/novo.txt"),
        format!("{RAIZ}/sub"),
        format!("{RAIZ}/sub/b.bin"),
        format!("{RAIZ}/sub2"),
        format!("{RAIZ}/sub2/b.bin"),
    ];
    let mut v = Vec::new();
    for c in caminhos {
        let r = agente.pedir("fs.stat", &format!(r#"{{"path":"{c}"}}"#))?;
        let tipo = p::texto_do_resultado(&r, "type")
            .ok_or_else(|| format!("o fs.stat de {c} nao diz o tipo\n  {r}"))?;
        let mut conteudo = Vec::new();
        if tipo == "file" {
            let tamanho: usize = p::texto_do_resultado(&r, "size")
                .and_then(|t| t.parse().ok())
                .ok_or_else(|| format!("o fs.stat de {c} nao diz o tamanho\n  {r}"))?;
            while conteudo.len() < tamanho {
                let r = agente.pedir(
                    "fs.read",
                    &format!(r#"{{"path":"{c}","offset":{},"max":4096}}"#, conteudo.len()),
                )?;
                let texto = p::texto_do_resultado(&r, "content")
                    .ok_or_else(|| format!("o fs.read de {c} nao trouxe conteudo\n  {r}"))?;
                let pedaco = match p::texto_do_resultado(&r, "encoding").as_deref() {
                    Some("base64") => de_base64(&texto)
                        .ok_or_else(|| format!("o fs.read de {c} nao e base64\n  {r}"))?,
                    _ => texto.into_bytes(),
                };
                if pedaco.is_empty() {
                    return Err(format!("o fs.read de {c} parou antes do fim\n  {r}"));
                }
                conteudo.extend_from_slice(&pedaco);
            }
        }
        v.push((c, tipo, conteudo));
    }
    Ok(v)
}

/// O armazém compartilhado inteiro confere: cada bloco de cada versão viva
/// abre, e nenhum está livre no mapa.
fn verificar(agente: &mut AgenteNaPorta) -> Result<(), String> {
    let r = agente.pedir("fs.verify", r#"{"path":"/armazem/compartilhado"}"#)?;
    exigir(&r, "o armazem nao confere")
}

/// A forma de uma cópia vista de fora: setores inteiros, a magia, a
/// pública desta máquina no setor em claro — e nada da árvore em claro.
fn conferir_a_forma(bytes: &[u8], publica: &[u8; 32]) -> Result<(), String> {
    if !bytes.len().is_multiple_of(512) || !bytes.starts_with(b"DUKECOP1") {
        return Err("a copia baixada nao tem a forma de uma copia".into());
    }
    if &bytes[16..48] != publica {
        return Err("o setor em claro da copia nao diz a publica desta maquina".into());
    }
    for (c, conteudo) in arvore() {
        if conteudo.len() >= 16 && bytes.windows(16).any(|w| w == &conteudo[..16]) {
            return Err(format!("o conteudo de {c} saiu em claro na copia"));
        }
    }
    Ok(())
}

/// A persistência disponível — nada recusado.
fn de_pe(m: &mut Ligada) -> Result<(), String> {
    let estado = p::persistencia_de(m)?;
    if estado.estado != "available" {
        return Err(format!(
            "a persistencia nao esta disponivel: {} ({})",
            estado.estado, estado.motivo
        ));
    }
    Ok(())
}

/// O registro da restauração da cópia `id` na auditoria, de volta do
/// journal: a execução, com a decisão do gate, durável.
fn restauracao_no_journal(m: &mut Ligada, id: &str) -> Result<bool, String> {
    let restaurada = format!("restaurada a copia {}", &id[..16]);
    Ok(p::cauda_da_auditoria(m)?.iter().any(|r| {
        r.metodo == "fs.restore"
            && r.codigo == "ALLOW"
            && r.duravel
            && r.detalhe.starts_with(&restaurada)
            && r.detalhe.contains("; decisao ")
    }))
}

/// O identificador da cópia que a resposta do `fs.backup` diz.
fn id_da_copia(feita: &str) -> Result<String, String> {
    p::texto_do_resultado(feita, "id")
        .filter(|id| id.len() == 64)
        .ok_or_else(|| format!("a copia nao diz o identificador\n  {feita}"))
}

// ---------------------------------------------------------------------------
// Os cenários
// ---------------------------------------------------------------------------

/// A volta inteira: o operador planta a árvore e a copia; a cópia baixada
/// tem a forma certa e nada em claro; a árvore muda; a cópia volta, numa
/// confirmação, e a árvore é a de antes. Depois do corte de energia: a
/// restauração de volta do journal com a decisão, a cadeia da auditoria se
/// verifica, a árvore é a da cópia e o volume confere.
fn a_volta_sobrevive_ao_corte(b: &Bancada) -> Result<String, String> {
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let antes = (|| -> Result<_, String> {
        de_pe(&mut m)?;
        let publica = p::identidade_com_origem(&mut m, "image")?;
        let mut agente = AgenteNaPorta::conectar(b.arch, OPERADOR)?;
        plantar(&mut agente)?;
        let original = retrato(&mut agente)?;
        let (bytes, feita) = producao::copia_baixada(&mut agente, RAIZ)?;
        let id = id_da_copia(&feita)?;
        conferir_a_forma(&bytes, &publica)?;
        mudar(&mut agente)?;
        if retrato(&mut agente)? == original {
            return Err("o cenario nao mudou a arvore".into());
        }
        let v = versao(&mut agente, RAIZ)?;
        let r = producao::copia_restaurada(&mut agente, RAIZ, &bytes, v)?;
        exigir(&r, "a restauracao foi recusada")?;
        if retrato(&mut agente)? != original {
            return Err("a arvore restaurada nao e a da copia".into());
        }
        Ok((id, original, bytes.len()))
    })();
    m.cortar_a_energia()?;
    let (id, original, tamanho) = antes?;
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let depois = (|| -> Result<String, String> {
        de_pe(&mut m)?;
        if !restauracao_no_journal(&mut m, &id)? {
            return Err("a restauracao, com a decisao, nao voltou do journal".into());
        }
        p::auditoria_verifica(&mut m)?;
        let mut agente = AgenteNaPorta::conectar(b.arch, OPERADOR)?;
        if retrato(&mut agente)? != original {
            return Err("depois do corte, a arvore nao e a da copia".into());
        }
        verificar(&mut agente)?;
        Ok(format!(
            "a copia {} ({tamanho} bytes, cifrada, presa a esta maquina) voltou numa confirmacao; depois do corte, a arvore, a auditoria e o volume conferem",
            &id[..16]
        ))
    })();
    m.cortar_a_energia()?;
    depois
}

/// A autoridade não volta: o agente da porta 3 planta e copia; a chave dele
/// é revogada pelo administrador; o da porta 2 restaura a cópia. A árvore
/// volta, e é de quem restaurou; depois do corte, a chave revogada continua
/// sem entrar, e a revogação continua no journal.
fn a_autoridade_nao_volta(b: &Bancada) -> Result<String, String> {
    let chaves = chaves::Chaves::garantir()?;
    let revogado = sigilo::publica_de(&chaves.do_agente(OUTRO_OPERADOR));
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let antes = (|| -> Result<_, String> {
        de_pe(&mut m)?;
        let mut tres = AgenteNaPorta::conectar(b.arch, OUTRO_OPERADOR)?;
        plantar(&mut tres)?;
        let original = retrato(&mut tres)?;
        let (bytes, _) = producao::copia_baixada(&mut tres, RAIZ)?;
        drop(tres);
        let r = p::administrar(
            &mut m,
            &chaves.administrador,
            "agent.revoke",
            &format!(r#"{{"key":"{}"}}"#, sigilo::hex(&revogado)),
        )?;
        if !p::executou(&r) {
            return Err(format!("a revogacao do agente nao foi executada\n  {r}"));
        }
        let mut dois = AgenteNaPorta::conectar(b.arch, OPERADOR)?;
        mudar(&mut dois)?;
        let v = versao(&mut dois, RAIZ)?;
        let r = producao::copia_restaurada(&mut dois, RAIZ, &bytes, v)?;
        exigir(&r, "a restauracao foi recusada")?;
        if retrato(&mut dois)? != original {
            return Err("a arvore restaurada nao e a da copia".into());
        }
        let dono = p::texto_do_resultado(
            &dois.pedir("fs.stat", &format!(r#"{{"path":"{RAIZ}/a.txt"}}"#))?,
            "owner",
        )
        .unwrap_or_default();
        let esperado = format!(
            "agente:{}",
            sigilo::hex(&sigilo::publica_de(&chaves.do_agente(OPERADOR)))
        );
        if dono != esperado {
            return Err(format!(
                "o arquivo restaurado e de {dono}, e nao de quem restaurou"
            ));
        }
        Ok(original)
    })();
    m.cortar_a_energia()?;
    let original = antes?;
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let depois = (|| -> Result<String, String> {
        de_pe(&mut m)?;
        if AgenteNaPorta::conectar(b.arch, OUTRO_OPERADOR)
            .and_then(|mut a| a.pedir("agent.session", "{}"))
            .is_ok_and(|r| r.contains(r#""agent":"agente-3""#))
        {
            return Err("depois da restauracao e do corte, a chave revogada entrou".into());
        }
        if !p::cauda_da_auditoria(&mut m)?
            .iter()
            .any(|r| r.metodo == "agent.revoke" && r.codigo == "ALLOW" && r.duravel)
        {
            return Err("a revogacao nao esta no journal".into());
        }
        let mut dois = AgenteNaPorta::conectar(b.arch, OPERADOR)?;
        if retrato(&mut dois)? != original {
            return Err("depois do corte, a arvore nao e a da copia".into());
        }
        Ok(
            "a arvore voltou, de quem restaurou; a chave revogada depois da copia segue sem entrar"
                .into(),
        )
    })();
    m.cortar_a_energia()?;
    depois
}

/// A máquina reinstalada: o journal zerado — outra instalação — sobre a
/// mesma imagem, com a mesma identidade. A cópia de antes é recusada: ela
/// é de outra instalação, e nada muda no armazém novo.
fn a_reinstalada_recusa(b: &Bancada) -> Result<String, String> {
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let antes = (|| -> Result<_, String> {
        de_pe(&mut m)?;
        let publica = p::identidade_com_origem(&mut m, "image")?;
        let mut agente = AgenteNaPorta::conectar(b.arch, OPERADOR)?;
        plantar(&mut agente)?;
        let (bytes, _) = producao::copia_baixada(&mut agente, RAIZ)?;
        Ok((publica, bytes))
    })();
    m.cortar_a_energia()?;
    let (publica, bytes) = antes?;
    super::zerar_o_estado(b.arch)?;
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let depois = (|| -> Result<String, String> {
        de_pe(&mut m)?;
        if p::identidade_com_origem(&mut m, "image")? != publica {
            return Err("a imagem reinstalada tem outra identidade".into());
        }
        let mut agente = AgenteNaPorta::conectar(b.arch, OPERADOR)?;
        let r = producao::copia_restaurada(&mut agente, RAIZ, &bytes, 0)?;
        if r.contains(r#""ok":true"#)
            || p::texto_do_resultado(&r, "error").as_deref()
                != Some("a copia e de outra instalacao")
        {
            return Err(format!(
                "a copia de antes da reinstalacao nao foi recusada como de outra instalacao\n  {r}"
            ));
        }
        if versao(&mut agente, RAIZ)? != 0 {
            return Err("a copia recusada deixou algo no armazem novo".into());
        }
        Ok("a mesma identidade, outra instalacao: a copia de antes recusada, o armazem novo intacto".into())
    })();
    m.cortar_a_energia()?;
    depois
}

/// Uma queda: o ponto e o tipo do plano, se a escrita sem descarga se
/// perde, se a restauração vale depois, e como se lê. O ponto zero é o
/// corte depois da resposta.
type Queda = (u8, u16, bool, bool, &'static str);

const QUEDAS: [Queda; 12] = [
    (
        p::ponto::COPIA_NO_MEIO,
        0,
        false,
        false,
        "a copia pela metade: o setor em claro e a primeira parte no rascunho",
    ),
    (
        p::ponto::RESTAURACAO_CONFERIDA,
        0,
        false,
        false,
        "a copia conferida inteira, o conteudo em blocos livres, nada preparado",
    ),
    (
        p::ponto::RESTAURACAO_NA_PRIMEIRA_PARTE,
        0,
        false,
        false,
        "a primeira parte da base na outra regiao do volume",
    ),
    (
        p::ponto::RESTAURACAO_NA_BASE,
        0,
        false,
        false,
        "a base inteira descarregada, a confirmacao nao comecada",
    ),
    (
        p::ponto::ANTES_DA_ESCRITA,
        p::tipo::ARMAZEM,
        false,
        false,
        "a confirmacao montada, nada escrito",
    ),
    (
        p::ponto::DEPOIS_DA_ESCRITA,
        p::tipo::ARMAZEM,
        false,
        true,
        "a confirmacao escrita, e no disco",
    ),
    (
        p::ponto::DEPOIS_DA_ESCRITA,
        p::tipo::ARMAZEM,
        true,
        false,
        "a confirmacao escrita, e perdida sem a descarga",
    ),
    (
        p::ponto::DEPOIS_DA_DESCARGA,
        p::tipo::ARMAZEM,
        false,
        true,
        "a confirmacao descarregada, o contador ainda nao",
    ),
    (
        p::ponto::DEPOIS_DO_INCREMENTO,
        p::tipo::ARMAZEM,
        false,
        true,
        "o contador avancado, sem a leitura de volta",
    ),
    (
        p::ponto::DEPOIS_DO_CONTADOR,
        p::tipo::ARMAZEM,
        false,
        true,
        "o contador conferido, a memoria ainda nao",
    ),
    (
        p::ponto::RESTAURACAO_GRAVADA,
        0,
        false,
        true,
        "confirmada e em vigor, a resposta nao dada",
    ),
    (0, 0, false, true, "depois da resposta"),
];

/// A queda em cada fronteira, sobre a compilação com os pontos de queda.
/// No primeiro boot, sem plano, o operador planta e copia, e muda a
/// árvore; no segundo, com o plano, envia a cópia e restaura — ou, no
/// ponto da cópia, copia de novo —, e a energia cai no ponto; no terceiro,
/// sem plano, a persistência está de pé, a árvore é inteira a mudada ou
/// inteira a da cópia — a da cópia exatamente quando o caso diz que a
/// restauração vale, e então com o registro dela de volta do journal —, o
/// volume confere, e a restauração seguinte vale.
fn as_quedas(b: &Bancada) -> Result<String, String> {
    let quedas = b
        .quedas
        .as_ref()
        .ok_or("sem a compilacao com os pontos de queda")?;
    let disco = super::disco_de_testes()?;
    let mut feitos = Vec::new();
    for (ponto, tipo, perder, vale, caso) in QUEDAS {
        super::zerar_o_estado(b.arch)?;
        let mut m = Ligada::subir(b.arch, quedas, None)?;
        let preparada = (|| -> Result<_, String> {
            de_pe(&mut m)?;
            let mut agente = AgenteNaPorta::conectar(b.arch, OPERADOR)?;
            plantar(&mut agente)?;
            let original = retrato(&mut agente)?;
            let (bytes, feita) = producao::copia_baixada(&mut agente, RAIZ)?;
            mudar(&mut agente)?;
            let mudada = retrato(&mut agente)?;
            Ok((original, mudada, bytes, id_da_copia(&feita)?))
        })();
        m.cortar_a_energia()?;
        let (original, mudada, bytes, id) = preparada.map_err(|e| format!("{caso}: {e}"))?;
        if ponto != 0 {
            p::plano(
                &disco,
                p::Plano {
                    ponto,
                    tipo,
                    gravacao: 1,
                    ..p::Plano::default()
                },
            )?;
        }
        let m = Ligada::subir(b.arch, quedas, None)?;
        // O agente fica conectado até a queda: com a sessão fechada, o
        // pedido mandado não chega a rodar.
        let mandado = (|| -> Result<AgenteNaPorta, String> {
            let mut agente = AgenteNaPorta::conectar(b.arch, OPERADOR)?;
            if ponto == p::ponto::COPIA_NO_MEIO {
                let (_, quadro) =
                    agente.quadro_do_pedido("fs.backup", &format!(r#"{{"path":"{RAIZ}"}}"#))?;
                agente.mandar(&quadro)?;
                return Ok(agente);
            }
            let rascunho = producao::copia_enviada(&mut agente, RAIZ, &bytes)?;
            let v = versao(&mut agente, RAIZ)?;
            let params = format!(r#"{{"path":"{RAIZ}","draft":{rascunho},"expect_version":{v}}}"#);
            if ponto == 0 {
                let r = agente.pedir("fs.restore", &params)?;
                exigir(&r, "a restauracao foi recusada")?;
                return Ok(agente);
            }
            let (_, quadro) = agente.quadro_do_pedido("fs.restore", &params)?;
            agente.mandar(&quadro)?;
            Ok(agente)
        })();
        let conectado = match mandado {
            Ok(agente) => agente,
            Err(e) => {
                m.cortar_a_energia()?;
                return Err(format!("{caso}: {e}"));
            }
        };
        if ponto == 0 {
            m.cortar_a_energia()?;
        } else {
            let caiu = m.esperar_a_queda()?;
            if caiu != ponto {
                return Err(format!("{caso}: caiu no ponto {caiu}, e nao no {ponto}"));
            }
        }
        drop(conectado);
        p::sem_plano(&disco)?;
        if perder {
            p::perder_o_ultimo_registro(&disco, None)?;
        }
        let mut m = Ligada::subir(b.arch, quedas, None)?;
        let depois = (|| -> Result<(), String> {
            de_pe(&mut m)?;
            let no_journal = restauracao_no_journal(&mut m, &id)?;
            if no_journal != vale {
                return Err(format!(
                    "a restauracao {} no journal, e o caso diz que ela {}",
                    if no_journal { "esta" } else { "nao esta" },
                    if vale { "vale" } else { "nao vale" }
                ));
            }
            let mut agente = AgenteNaPorta::conectar(b.arch, OPERADOR)?;
            let agora = retrato(&mut agente)?;
            let esperada = if vale { &original } else { &mudada };
            if &agora != esperada {
                return Err(format!(
                    "a arvore nao e inteira a {}",
                    if vale { "da copia" } else { "de antes" }
                ));
            }
            verificar(&mut agente)?;
            // E a restauração seguinte vale.
            let v = versao(&mut agente, RAIZ)?;
            let r = producao::copia_restaurada(&mut agente, RAIZ, &bytes, v)?;
            exigir(&r, "depois da queda, a restauracao seguinte foi recusada")?;
            if retrato(&mut agente)? != original {
                return Err("depois da queda, a restauracao seguinte nao pos a arvore".into());
            }
            verificar(&mut agente)
        })();
        m.cortar_a_energia()?;
        depois.map_err(|e| format!("{caso}: {e}"))?;
        feitos.push(if vale { "a da copia" } else { "a de antes" });
    }
    Ok(format!(
        "{} quedas, em cada uma a arvore inteira: {}",
        QUEDAS.len(),
        feitos.join(", ")
    ))
}

/// A imagem de produção: o molde — a política do exemplo, a identidade que
/// nasce no TPM no primeiro boot, um agente operador. O operador copia,
/// muda, restaura pelo `operar`, e a árvore sobrevive ao corte. Outra
/// máquina do mesmo molde — outro TPM, outra identidade — recusa a cópia;
/// a primeira, de volta com o TPM dela, continua a aceitá-la.
fn a_producao_copia_e_restaura(b: &Bancada) -> Result<String, String> {
    let (molde, operador) = b.producao.as_ref().ok_or("sem o molde de producao")?;
    let raiz = super::raiz_do_estado();
    let disco_a = raiz.join(format!("copia-producao-a-{}.img", b.arch.nome()));
    let disco_b = raiz.join(format!("copia-producao-b-{}.img", b.arch.nome()));
    let tpm_a = raiz.join(format!("copia-tpm-a-{}", b.arch.nome()));
    for d in [&disco_a, &disco_b] {
        std::fs::copy(molde, d).map_err(|e| format!("nao foi possivel copiar o molde: {e}"))?;
    }
    let ligar = |disco: &PathBuf| {
        Ligada::subir_com(
            b.arch,
            &Artefato::Disco(disco.clone()),
            Ambiente::ligar(b.arch, None)?.com_disco(disco.clone()),
        )
    };
    let resultado = (|| -> Result<String, String> {
        // A máquina A: a identidade nasce; o operador copia, muda e restaura.
        let mut m = ligar(&disco_a)?;
        let a = (|| -> Result<_, String> {
            de_pe(&mut m)?;
            let publica = p::identidade_com_origem(&mut m, "born")?;
            let mut agente = AgenteNaPorta::conectar_com_publica(b.arch, 1, operador, &publica)?;
            plantar(&mut agente)?;
            let original = retrato(&mut agente)?;
            let (bytes, _) = producao::copia_baixada(&mut agente, RAIZ)?;
            conferir_a_forma(&bytes, &publica)?;
            mudar(&mut agente)?;
            let v = versao(&mut agente, RAIZ)?;
            let r = producao::copia_restaurada(&mut agente, RAIZ, &bytes, v)?;
            exigir(&r, "na producao, a restauracao foi recusada")?;
            Ok((publica, original, bytes))
        })();
        m.cortar_a_energia()?;
        let (publica, original, bytes) = a?;
        let mut m = ligar(&disco_a)?;
        let depois = (|| -> Result<(), String> {
            de_pe(&mut m)?;
            if p::identidade_com_origem(&mut m, "sealed")? != publica {
                return Err("depois do corte, a maquina A tem outra identidade".into());
            }
            let mut agente = AgenteNaPorta::conectar_com_publica(b.arch, 1, operador, &publica)?;
            if retrato(&mut agente)? != original {
                return Err("depois do corte, a arvore da producao nao e a da copia".into());
            }
            verificar(&mut agente)
        })();
        m.cortar_a_energia()?;
        depois?;
        // A máquina B: outro TPM, outra identidade, o mesmo molde.
        super::guardar_o_tpm(b.arch, &tpm_a)?;
        let mut m = ligar(&disco_b)?;
        let outra = (|| -> Result<(), String> {
            de_pe(&mut m)?;
            let publica_b = p::identidade_com_origem(&mut m, "born")?;
            if publica_b == publica {
                return Err("a outra maquina nasceu com a mesma identidade".into());
            }
            let mut agente = AgenteNaPorta::conectar_com_publica(b.arch, 1, operador, &publica_b)?;
            let r = producao::copia_restaurada(&mut agente, RAIZ, &bytes, 0)?;
            if r.contains(r#""ok":true"#)
                || p::texto_do_resultado(&r, "error").as_deref()
                    != Some("a copia e de outra maquina")
            {
                return Err(format!(
                    "a outra maquina nao recusou a copia como de outra maquina\n  {r}"
                ));
            }
            // A mesma cópia com a pública de B no setor em claro: a recusa
            // passa a ser da cifra. A chave da cópia é da identidade que a
            // fez, e B não a tem — o rótulo não é o que a protege.
            let mut com_a_de_b = bytes.clone();
            com_a_de_b[16..48].copy_from_slice(&publica_b);
            let r = producao::copia_restaurada(&mut agente, RAIZ, &com_a_de_b, 0)?;
            if r.contains(r#""ok":true"#)
                || p::texto_do_resultado(&r, "error").as_deref()
                    != Some("a copia nao abre nesta maquina")
            {
                return Err(format!(
                    "com a publica de B no setor em claro, a outra maquina nao recusou pela cifra\n  {r}"
                ));
            }
            if versao(&mut agente, RAIZ)? != 0 {
                return Err("a copia recusada deixou algo na outra maquina".into());
            }
            Ok(())
        })();
        m.cortar_a_energia()?;
        super::repor_o_tpm(b.arch, &tpm_a)?;
        outra?;
        // A primeira, com o TPM dela, continua a aceitar a cópia.
        let mut m = ligar(&disco_a)?;
        let de_volta = (|| -> Result<(), String> {
            de_pe(&mut m)?;
            let mut agente = AgenteNaPorta::conectar_com_publica(b.arch, 1, operador, &publica)?;
            mudar(&mut agente)?;
            let v = versao(&mut agente, RAIZ)?;
            let r = producao::copia_restaurada(&mut agente, RAIZ, &bytes, v)?;
            exigir(&r, "a maquina A recusou a propria copia")?;
            if retrato(&mut agente)? != original {
                return Err("a maquina A nao pos a arvore da propria copia".into());
            }
            Ok(())
        })();
        m.cortar_a_energia()?;
        de_volta?;
        Ok(format!(
            "a copia de {} volta na propria maquina e sobrevive ao corte; a outra maquina, outra identidade, a recusa, e nem com a propria publica no setor em claro a abre",
            &sigilo::hex(&publica)[..8]
        ))
    })();
    let _ = std::fs::remove_file(&disco_a);
    let _ = std::fs::remove_file(&disco_b);
    let _ = std::fs::remove_dir_all(&tpm_a);
    resultado
}

/// O molde de produção da bancada: o de [`super::botao::molde_de_producao`],
/// com um agente operador a mais, cuja privada fica aqui.
fn molde(arch: Arquitetura) -> Result<(PathBuf, [u8; 32]), String> {
    let (privada, linha, _) = producao::chave_nova("agente", "operador-1", Some("operador"))?;
    let operador = producao::chave_de_agente_de_texto(&privada)?;
    let sistema = producao::chave_nova("agente", "sistema-1", Some("sistema"))?.1;
    let molde = super::botao::molde_de_producao_com(
        arch,
        "copia",
        |t| Ok(t.to_string()),
        &format!("{sistema}{linha}"),
    )?;
    Ok((molde, operador))
}

/// `cargo xtask copia`: roda os cenários e diz quais passaram.
pub(crate) fn copia(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    // Um filtro opcional pelo nome, como o da persistência: pedaços do nome
    // separados por `|`.
    let filtro = std::env::var("DUKE_CENARIOS").ok();
    let escolhido = |c: &Cenario| {
        filtro
            .as_deref()
            .is_none_or(|f| f.split('|').any(|p| c.nome.contains(p)))
    };
    let escolhidos: Vec<&Cenario> = CENARIOS.iter().filter(|c| escolhido(c)).collect();
    // A compilação sem os pontos de queda primeiro: é a que o molde de
    // produção copia do disco de testes.
    let dev = super::build(arch, release, false)?;
    let _ = p::SERIAL_DA_BANCADA
        .set(super::raiz_do_estado().join(format!("copia-{}.serial", arch.nome())));
    let mut bancada = Bancada {
        arch,
        dev,
        quedas: None,
        producao: if escolhidos.iter().any(|c| c.producao) {
            Some(molde(arch)?)
        } else {
            None
        },
    };
    println!(
        "[xtask] copia: {} cenarios, cada um numa maquina nova ({})",
        escolhidos.len(),
        arch.nome()
    );
    let mut falhas = 0;
    for cenario in escolhidos {
        if cenario.quedas && bancada.quedas.is_none() {
            bancada.quedas = Some(super::build_com(arch, release, &[p::FEATURE_DE_QUEDAS])?);
        }
        super::zerar_o_estado(arch)?;
        if let (None, Some(serial)) = (std::env::var_os("DUKE_BANCADA_LOG"), p::serial_do_cenario())
        {
            let _ = std::fs::write(serial, b"");
        }
        match (cenario.rodar)(&bancada) {
            Ok(detalhe) => println!("  [copia] ok  {}: {detalhe}", cenario.nome),
            Err(motivo) => {
                falhas += 1;
                println!("  [copia] FALHOU  {}: {motivo}", cenario.nome);
                p::mostrar_o_fim_da_serial();
            }
        }
    }
    super::zerar_o_estado(arch)?;
    if let Some((molde, _)) = &bancada.producao {
        let _ = std::fs::remove_file(molde);
    }
    if falhas > 0 {
        println!("\n[xtask] copia: {falhas} cenario(s) falharam");
        return Ok(ExitCode::FAILURE);
    }
    println!("\n[xtask] copia: todos os cenarios passaram");
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn o_base64_volta() {
        assert_eq!(de_base64("").as_deref(), Some(&[][..]));
        assert_eq!(de_base64("Zg==").as_deref(), Some(&b"f"[..]));
        assert_eq!(de_base64("Zm8=").as_deref(), Some(&b"fo"[..]));
        assert_eq!(de_base64("Zm9v").as_deref(), Some(&b"foo"[..]));
        assert_eq!(de_base64("AP8A").as_deref(), Some(&[0, 255, 0][..]));
        assert!(de_base64("Zm9").is_none());
        assert!(de_base64("Zm9*").is_none());
        assert!(de_base64("Z===").is_none());
    }

    #[test]
    fn a_arvore_tem_um_binario_de_varios_blocos() {
        let a = arvore();
        assert!(a.iter().any(|(_, c)| c.is_empty()));
        assert!(a.iter().any(|(_, c)| c.len() > 2 * 4080));
    }
}
