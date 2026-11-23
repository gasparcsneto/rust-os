//! As partes de uma rodada, do lado do hospedeiro: a variável `DUKE_PARTE`,
//! lida pelas bancadas que se dividem entre máquinas da CI — a de
//! persistência, a de tempo e a da atualização — e pela suíte do kernel — o
//! `cargo xtask test`, também com `--video virtio`, e o `cargo xtask
//! iniciador` do ARM, que roda a suíte pelo firmware —; e o anúncio da parte
//! que a suíte faz no começo da saída, conferido no fim.
//!
//! A regra da divisão — `k/n`, o item `i` na parte `k` sse `i % n == k - 1`
//! — é a de [`protocolo::partes`], a mesma conta que o kernel faz.
//!
//! # A parte chega ao kernel pela compilação
//!
//! O kernel não lê linha de comando, e não deve ler `DUKE_PARTE`: um valor
//! esquecido no shell filtraria a suíte em silêncio. A parte vai em
//! [`DA_SUITE`], que o `xtask` põe só no build da suíte — a partir do
//! `DUKE_PARTE` dele, já conferido — e tira do ambiente de todo outro build
//! (ver `ambiente_do_kernel`, no `main.rs`). O ELF muda com ela, e a
//! proveniência a registra.
//!
//! # E volta pela saída
//!
//! O kernel anuncia, na primeira linha da suíte, a parte que roda — ou que
//! roda a suíte inteira —, e o placar do fim conta os casos que rodaram. O
//! `xtask` confere os dois contra o que pediu ([`conferir_a_suite`]): um ELF
//! de outra compilação, que rodasse outra parte ou a suíte inteira, não passa
//! por esta.
//!
//! E confere que nenhum caso disse `FALHOU` ([`e_um_caso_que_falhou`])
//! quando o placar diz que todos passaram. O placar e o código de saída do
//! emulador vêm do mesmo laço que roda os casos: um laço que dissesse a
//! falha e não a contasse daria os dois de uma suíte que passou, e os
//! controles da suíte não veem o veredito do próprio laço (o informativo 1
//! do adversário do kernel da rodada 8; desde o lote ICACHE-7). Desde o lote
//! ICACHE-8, o kernel confere também, antes do placar, a conta do laço — os
//! casos e os que reprovaram — contra a da função por onde ele roda cada
//! caso, e reprova esse laço ali: esta conferência é a segunda, de fora.

use protocolo::partes::{ErroDaParte, Parte};

/// A variável da parte, nas bancadas e na suíte: `k/n`.
pub(crate) const VARIAVEL: &str = "DUKE_PARTE";

/// A variável da compilação da suíte que leva a parte ao kernel — o
/// `option_env!` de `kernel/src/testes.rs`.
pub(crate) const DA_SUITE: &str = "DUKE_PARTE_DA_SUITE";

/// A parte desta rodada, de [`VARIAVEL`] — ou nenhuma, sem a variável.
pub(crate) fn pedida() -> Result<Option<Parte>, String> {
    pedida_de(std::env::var_os(VARIAVEL).as_deref())
}

/// [`pedida`], do valor da variável: um valor que não é texto também não
/// se lê, e não vira a rodada inteira.
fn pedida_de(valor: Option<&std::ffi::OsStr>) -> Result<Option<Parte>, String> {
    match valor {
        None => Ok(None),
        Some(valor) => match valor.to_str() {
            Some(texto) => parte_da_rodada(Some(texto)),
            None => Err(format!(
                "{VARIAVEL}={}: não é texto",
                valor.to_string_lossy()
            )),
        },
    }
}

/// A parte da rodada pedida em `DUKE_PARTE`: `k/n`, com `1 <= k <= n` — ou
/// nenhuma, sem a variável. A CI divide as bancadas longas e a suíte entre
/// máquinas por ela (`.github/workflows/ci.yml`). Um valor que não se lê é
/// um erro: uma parte mal escrita não pode virar "nenhum cenário" nem
/// "todos" em silêncio.
pub(crate) fn parte_da_rodada(valor: Option<&str>) -> Result<Option<Parte>, String> {
    let Some(valor) = valor else {
        return Ok(None);
    };
    Parte::ler(valor).map(Some).map_err(|erro| {
        // O motivo do `protocolo` é ASCII — o kernel o escreve na serial —,
        // e o daqui, o do `xtask`, com os acentos dele.
        let motivo = match erro {
            ErroDaParte::Forma => "esperava a parte e o total, como 1/2",
            ErroDaParte::Faixa => "a parte vai de 1 ao total, e o total não é zero",
        };
        format!("{VARIAVEL}={valor}: {motivo}")
    })
}

/// O item de índice `i` — a posição dele na tabela inteira da bancada — é
/// da `parte`: `i % n == k - 1`; sem parte, todos. Todo item cai em
/// exatamente uma parte, e um item novo entra numa delas sem mexer na CI.
pub(crate) fn na_parte(i: usize, parte: Option<Parte>) -> bool {
    protocolo::partes::na_parte(i, parte)
}

/// Os cenários de uma bancada que rodam nesta rodada, na ordem da tabela: os
/// de `normais` e os de `de_queda` — que rodam sobre outra compilação do
/// kernel, e por isso vêm em lista à parte. O índice de um cenário é a
/// posição dele em todos, os de queda depois dos normais; rodam os da
/// `parte` que o `filtro` de `DUKE_CENARIOS` escolhe — pedaços do nome
/// separados por `|`, e vale o cenário que tiver qualquer um deles. Uma
/// lista vazia é uma compilação que não precisa acontecer.
pub(crate) fn da_rodada<'a, C>(
    normais: &'a [C],
    de_queda: &'a [C],
    nome: impl Fn(&C) -> &str,
    parte: Option<Parte>,
    filtro: Option<&str>,
) -> (Vec<&'a C>, Vec<&'a C>) {
    let escolhido = |c: &C| filtro.is_none_or(|f| f.split('|').any(|p| nome(c).contains(p)));
    let de = |cenarios: &'a [C], primeiro: usize| -> Vec<&'a C> {
        cenarios
            .iter()
            .enumerate()
            .filter(|&(i, c)| escolhido(c) && na_parte(primeiro + i, parte))
            .map(|(_, c)| c)
            .collect()
    };
    (de(normais, 0), de(de_queda, normais.len()))
}

/// O cabeçalho de uma bancada com `total` cenários na `parte`: quantos
/// rodam, e de quantos.
pub(crate) fn descrever(parte: Option<Parte>, total: usize) -> String {
    match parte {
        None => format!("{total} cenarios"),
        Some(p) => format!(
            "a parte {} de {} — {} dos {total} cenarios",
            p.k(),
            p.n(),
            p.quantos(total)
        ),
    }
}

/// O que a suíte anunciou na primeira linha dela: a parte, quantos casos
/// roda e quantos tem a suíte inteira.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Anuncio {
    pub(crate) parte: Option<Parte>,
    pub(crate) rodados: usize,
    pub(crate) total: usize,
}

/// O anúncio de uma linha da saída da suíte, se ela é o anúncio:
/// `  suite de testes :: <arquitetura> :: <total> casos`, a suíte inteira,
/// ou `  suite de testes :: <arquitetura> :: parte <k> de <n>: <rodados> de
/// <total> casos` — como `testes::executar_todos` a escreve.
pub(crate) fn ler_o_anuncio(linha: &str) -> Option<Anuncio> {
    let (_, resto) = linha.trim_end().split_once("suite de testes :: ")?;
    let (_arquitetura, resto) = resto.split_once(" :: ")?;
    let numero = |texto: &str| texto.parse::<usize>().ok();
    match resto.strip_prefix("parte ") {
        None => {
            let total = numero(resto.strip_suffix(" casos")?)?;
            Some(Anuncio {
                parte: None,
                rodados: total,
                total,
            })
        }
        Some(resto) => {
            let (k, resto) = resto.split_once(" de ")?;
            let (n, resto) = resto.split_once(": ")?;
            let (rodados, resto) = resto.split_once(" de ")?;
            let total = numero(resto.strip_suffix(" casos")?)?;
            Some(Anuncio {
                parte: Some(Parte::nova(numero(k)?, numero(n)?)?),
                rodados: numero(rodados)?,
                total,
            })
        }
    }
}

/// O placar do fim da suíte, `  <passaram> de <rodados> passaram`, se a
/// linha é ele — reconhecido campo a campo, como `conferir_a_suite` do
/// iniciador o reconhece.
pub(crate) fn ler_o_placar(linha: &str) -> Option<(usize, usize)> {
    let mut campos = linha.split_whitespace();
    let passaram = campos.next()?.parse().ok()?;
    (campos.next()? == "de").then_some(())?;
    let rodados = campos.next()?.parse().ok()?;
    (campos.next()? == "passaram" && campos.next().is_none()).then_some((passaram, rodados))
}

/// Se a linha é a de um caso que reprovou: a que leva o ` FALHOU -- ` com
/// que `testes::executar_todos` termina a linha do caso — `  <nome>  FALHOU
/// -- <motivo>`, com um espaço só antes do `FALHOU` quando o nome passa da
/// coluna, e com o `\r` do fim ou sem ele —, onde quer que ela comece. O
/// começo da linha pode trazer o que o caso, ou o console, escreveu sem fim
/// de linha antes dela: `console: o log humano chega a tela` escreve um `X`,
/// e o console físico, o `duke> ` do prompt. Pelo recuo, a linha desse caso
/// escaparia.
///
/// Só o laço escreve o ` FALHOU -- ` — e o caso do estouro da pilha, que
/// encerra o emulador com falha —: o resumo do fim, que o kernel só escreve
/// quando conta alguma falha, diz `falhou:`, e nenhuma linha do log o leva.
/// Uma que o citasse reprovaria a suíte — o lado seguro. O andamento do
/// `cargo xtask test` reconhece o caso que reprovou por esta mesma regra
/// (`termina_um_caso`, no `main.rs`).
pub(crate) fn e_um_caso_que_falhou(linha: &str) -> bool {
    linha.contains(" FALHOU -- ")
}

/// Confere, nas linhas da saída de uma suíte que passou, que ela rodou a
/// parte `pedida` — ou a suíte inteira, sem parte: o anúncio diz a parte
/// pedida, e o placar conta exatamente os casos anunciados, todos passando
/// —, e que nenhum caso disse `FALHOU` ([`e_um_caso_que_falhou`]).
///
/// Sem anúncio, ou com outro, o ELF que rodou não é o desta compilação — ou
/// a saída se perdeu —, e o verde não diz nada sobre a parte pedida.
///
/// E a linha `FALHOU` de um caso com o placar dizendo que todos passaram é
/// o laço que disse a falha e não a contou: o placar e o código de saída do
/// emulador vêm dele, e não a desmentem. Com a mutação do adversário do
/// kernel da rodada 8 — o laço que diz `FALHOU` e soma zero —, a suíte com
/// cinco casos reprovados dava "29 de 29 passaram", o emulador saía com
/// sucesso, e o `cargo xtask test` dizia que todos passaram.
pub(crate) fn conferir_a_suite<'a>(
    pedida: Option<Parte>,
    linhas: impl IntoIterator<Item = &'a str>,
) -> Result<Anuncio, String> {
    let mut anuncios = Vec::new();
    let mut placares = Vec::new();
    let mut falharam = Vec::new();
    for linha in linhas {
        if let Some(a) = ler_o_anuncio(linha) {
            anuncios.push(a);
        } else if let Some(p) = ler_o_placar(linha) {
            placares.push(p);
        } else if e_um_caso_que_falhou(linha) {
            falharam.push(linha.trim());
        }
    }
    let pedido = pedida.map_or_else(
        || String::from("a suíte inteira"),
        |p| format!("a parte {p}"),
    );
    let anunciada = |a: &Anuncio| {
        a.parte.map_or_else(
            || String::from("a suíte inteira"),
            |p| format!("a parte {p}"),
        )
    };
    let [anuncio] = anuncios.as_slice() else {
        return Err(if anuncios.is_empty() {
            format!(
                "pediu {pedido}, e a suíte não se anunciou: a saída não tem a linha `suite de testes :: ...`"
            )
        } else {
            format!(
                "pediu {pedido}, e a suíte se anunciou {} vezes — a máquina subiu de novo no meio?",
                anuncios.len()
            )
        });
    };
    if anuncio.parte != pedida {
        return Err(format!(
            "pediu {pedido}, e o kernel anunciou {}: o ELF que rodou não é o desta compilação",
            anunciada(anuncio)
        ));
    }
    let esperado = anuncio
        .parte
        .map_or(anuncio.total, |p| p.quantos(anuncio.total));
    if anuncio.parte.is_some() && anuncio.rodados < esperado {
        // A conta exata é do kernel, que sabe o tamanho da cauda: a fatia
        // da tabela do meio mais a cauda inteira. Ela nunca é menor que a
        // regra aplicada ao total — a cauda tem ao menos tantos quantos a
        // regra tiraria dela —, e um anúncio menor é outra regra.
        return Err(format!(
            "o kernel anunciou {} casos para {}, menos que os {esperado} da regra sobre {}",
            anuncio.rodados,
            anunciada(anuncio),
            anuncio.total
        ));
    }
    match placares.as_slice() {
        [(passaram, rodados)] if *passaram == anuncio.rodados && *rodados == anuncio.rodados => {
            if falharam.is_empty() {
                Ok(*anuncio)
            } else {
                Err(format!(
                    "o placar diz que os {rodados} casos passaram, e {} caso(s) disseram \
                     `FALHOU` na serial — o laço disse a falha e não a contou:\n      {}",
                    falharam.len(),
                    falharam.join("\n      ")
                ))
            }
        }
        [(passaram, rodados)] => Err(format!(
            "o kernel anunciou {} casos, e o placar diz {passaram} de {rodados}",
            anuncio.rodados
        )),
        [] => Err("a suíte não chegou ao placar".into()),
        _ => Err(format!(
            "a saída tem {} placares — a suíte rodou mais de uma vez?",
            placares.len()
        )),
    }
}

/// As matrizes de [`VARIAVEL`] nos workflows: em cada job que a tira da
/// matriz (`DUKE_PARTE: ${{ matrix.<chave> }}`), as entradas de um mesmo
/// grupo — as mesmas [`CHAVES_DO_GRUPO`] — têm as partes `1/n` a `n/n`,
/// cada uma uma vez, com o mesmo `n`.
///
/// Uma parte que falta deixaria casos sem rodar na CI, em silêncio — a
/// divisão é do `xtask` e do kernel, e cada máquina só vê a sua —; uma
/// repetida rodaria a mesma fatia duas vezes; um `n` misturado partiria a
/// mesma tabela de duas maneiras, com casos de fora. E a parte vem sempre
/// da matriz: um `DUKE_PARTE` fixo rodaria uma parte só.
pub(crate) fn conferir_as_matrizes() -> Result<std::process::ExitCode, String> {
    let dir = crate::raiz_do_projeto().join(".github/workflows");
    let mut nomes: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| format!("não foi possível ler {}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
        .collect();
    nomes.sort();
    let mut grupos = Vec::new();
    let mut fora = Vec::new();
    for nome in &nomes {
        let texto = std::fs::read_to_string(dir.join(nome))
            .map_err(|e| format!("não foi possível ler .github/workflows/{nome}: {e}"))?;
        let (g, f) = matrizes_com_partes(nome, &texto);
        grupos.extend(g);
        fora.extend(f);
    }
    if fora.is_empty() {
        println!(
            "[xtask] as partes da CI: {} grupos, cada um com as partes 1/n a n/n, uma vez cada",
            grupos.len()
        );
        Ok(std::process::ExitCode::SUCCESS)
    } else {
        for f in &fora {
            println!("[xtask] {f}");
        }
        Ok(std::process::ExitCode::FAILURE)
    }
}

/// As chaves de uma entrada da matriz que dizem o que se divide em partes:
/// a arquitetura e o tipo de rodada. As outras são da parte — o rótulo, a
/// fumaça que só a segunda roda —, e não separam um grupo. Uma chave nova
/// que separe grupos e não esteja aqui junta dois deles, e a conferência
/// acusa as partes repetidas: o lado seguro.
const CHAVES_DO_GRUPO: [&str; 2] = ["arch", "tipo"];

/// Uma linha de YAML que não é vazia nem comentário: o recuo e o texto.
fn linhas_do_yaml(texto: &str) -> Vec<(usize, &str)> {
    texto
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|l| (l.len() - l.trim_start().len(), l.trim()))
        .collect()
}

/// A chave e o valor de uma linha `chave: valor` — o `- ` de um item tirado,
/// e o valor sem o comentário do fim nem as aspas.
fn chave_e_valor(texto: &str) -> Option<(&str, &str)> {
    let texto = texto.strip_prefix("- ").unwrap_or(texto);
    let (chave, valor) = texto.split_once(':')?;
    let chave = chave.trim();
    let de_yaml = !chave.is_empty()
        && chave
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    let valor = valor.split(" #").next().unwrap_or("").trim();
    de_yaml.then_some((chave, valor.trim_matches(|c| c == '"' || c == '\'')))
}

/// Uma entrada da matriz: as chaves e os valores, na ordem em que vêm.
type Entrada = Vec<(String, String)>;

/// As partes de um grupo: o valor escrito na matriz e a parte lida dele.
type PartesDoGrupo = Vec<(String, Option<Parte>)>;

/// Os grupos de partes de um workflow, descritos, e o que não confere.
fn matrizes_com_partes(nome: &str, texto: &str) -> (Vec<String>, Vec<String>) {
    let linhas = linhas_do_yaml(texto);
    let mut grupos = Vec::new();
    let mut fora = Vec::new();
    let Some(inicio) = linhas.iter().position(|&(r, t)| r == 0 && t == "jobs:") else {
        return (grupos, fora);
    };
    // Cada job: uma chave sem valor no recuo dos jobs, até a próxima — e
    // os jobs, até a próxima chave do topo.
    let corpo = &linhas[inicio + 1..];
    let fim = corpo
        .iter()
        .position(|&(r, _)| r == 0)
        .unwrap_or(corpo.len());
    let corpo = &corpo[..fim];
    let Some(recuo) = corpo.first().map(|&(r, _)| r) else {
        return (grupos, fora);
    };
    let mut comecos: Vec<usize> = corpo
        .iter()
        .enumerate()
        .filter(|(_, (r, _))| *r == recuo)
        .map(|(i, _)| i)
        .collect();
    comecos.push(corpo.len());
    for par in comecos.windows(2) {
        let job = &corpo[par[0]..par[1]];
        let nome_do_job = job[0].1.trim_end_matches(':');
        let onde = format!("{nome}/{nome_do_job}");
        let (grupos_do_job, fora_do_job) = partes_do_job(&onde, job);
        grupos.extend(grupos_do_job);
        fora.extend(fora_do_job);
    }
    (grupos, fora)
}

/// Os grupos de partes de um job, e o que não confere.
fn partes_do_job(onde: &str, job: &[(usize, &str)]) -> (Vec<String>, Vec<String>) {
    let mut grupos = Vec::new();
    let mut fora = Vec::new();
    // A chave da matriz que vai em DUKE_PARTE.
    let mut chaves: Vec<&str> = Vec::new();
    for &(_, t) in job {
        let Some((VARIAVEL, valor)) = chave_e_valor(t) else {
            continue;
        };
        let chave = valor
            .strip_prefix("${{")
            .and_then(|v| v.strip_suffix("}}"))
            .map(str::trim)
            .and_then(|v| v.strip_prefix("matrix."))
            .filter(|c| !c.is_empty() && !c.contains(char::is_whitespace));
        match chave {
            Some(c) if !chaves.contains(&c) => chaves.push(c),
            Some(_) => {}
            None => fora.push(format!(
                "{onde}: `{VARIAVEL}: {valor}` — a parte vem da matriz, `${{{{ matrix.<chave> }}}}`; \
                 fixa, o job rodaria uma parte só"
            )),
        }
    }
    let chave = match chaves.as_slice() {
        [] => return (grupos, fora),
        [c] => *c,
        _ => {
            fora.push(format!(
                "{onde}: `{VARIAVEL}` tirado de mais de uma chave da matriz: {}",
                chaves.join(", ")
            ));
            return (grupos, fora);
        }
    };
    let entradas = match entradas_da_matriz(job) {
        Ok(e) => e,
        Err(e) => {
            fora.push(format!("{onde}: {e}"));
            return (grupos, fora);
        }
    };
    // O grupo de cada entrada com a parte: as chaves do grupo, na ordem.
    let mut por_grupo: Vec<(Entrada, PartesDoGrupo)> = Vec::new();
    for entrada in &entradas {
        let Some((_, valor)) = entrada.iter().find(|(k, _)| k == chave) else {
            continue;
        };
        let grupo: Entrada = entrada
            .iter()
            .filter(|(k, _)| k != chave && CHAVES_DO_GRUPO.contains(&k.as_str()))
            .cloned()
            .collect();
        let parte = Parte::ler(valor).ok();
        if parte.is_none() {
            fora.push(format!(
                "{onde}: `{chave}: {valor}` não é uma parte `k/n` que se leia"
            ));
        }
        match por_grupo.iter_mut().find(|(g, _)| *g == grupo) {
            Some((_, partes)) => partes.push((valor.clone(), parte)),
            None => por_grupo.push((grupo, vec![(valor.clone(), parte)])),
        }
    }
    if por_grupo.is_empty() {
        fora.push(format!(
            "{onde}: `{VARIAVEL}` vem de `matrix.{chave}`, e nenhuma entrada da matriz a tem"
        ));
    }
    for (grupo, partes) in &por_grupo {
        let rotulo = grupo
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ");
        let lidas: Vec<Parte> = partes.iter().filter_map(|(_, p)| *p).collect();
        if lidas.len() != partes.len() {
            continue;
        }
        let n = lidas[0].n();
        let escritas = || {
            partes
                .iter()
                .map(|(v, _)| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        if lidas.iter().any(|p| p.n() != n) {
            fora.push(format!(
                "{onde} ({rotulo}): as partes {} não têm o mesmo total",
                escritas()
            ));
            continue;
        }
        let mut ks: Vec<usize> = lidas.iter().map(|p| p.k()).collect();
        ks.sort_unstable();
        if ks != (1..=n).collect::<Vec<_>>() {
            fora.push(format!(
                "{onde} ({rotulo}): as partes {} não são de 1/{n} a {n}/{n}, uma vez cada — \
                 uma que falta deixa casos sem rodar, uma repetida roda a mesma fatia de novo",
                escritas()
            ));
            continue;
        }
        grupos.push(format!("{onde} ({rotulo}): {n}"));
    }
    (grupos, fora)
}

/// As entradas da matriz de um job: a lista do `include`, ou o produto dos
/// eixos `chave: [a, b]`. Um `exclude`, ou os dois juntos, a conferência não
/// lê, e diz.
fn entradas_da_matriz(job: &[(usize, &str)]) -> Result<Vec<Entrada>, String> {
    let Some(m) = job.iter().position(|&(_, t)| t == "matrix:") else {
        return Err("tem a parte da matriz, e não tem `matrix:`".into());
    };
    let recuo = job[m].0;
    let bloco: Vec<(usize, &str)> = job[m + 1..]
        .iter()
        .take_while(|&&(r, _)| r > recuo)
        .copied()
        .collect();
    let Some(passo) = bloco.first().map(|&(r, _)| r) else {
        return Err("`matrix:` vazia".into());
    };
    let mut eixos: Vec<(String, Vec<String>)> = Vec::new();
    let mut incluidas: Vec<Entrada> = Vec::new();
    let mut i = 0;
    while i < bloco.len() {
        let (r, t) = bloco[i];
        i += 1;
        if r != passo {
            continue;
        }
        let Some((chave, valor)) = chave_e_valor(t) else {
            return Err(format!("`{t}` na matriz não se lê"));
        };
        match chave {
            "exclude" => return Err("um `exclude` na matriz — a conferência não o lê".into()),
            "include" => {
                let itens: Vec<(usize, &str)> = bloco[i..]
                    .iter()
                    .take_while(|&&(ri, _)| ri > passo)
                    .copied()
                    .collect();
                i += itens.len();
                let mut atual: Option<(usize, Entrada)> = None;
                for (ri, ti) in itens {
                    let Some((k, v)) = chave_e_valor(ti) else {
                        return Err(format!("`{ti}` no `include` não se lê"));
                    };
                    let par = (k.to_string(), v.to_string());
                    match &mut atual {
                        Some((r0, e)) if !ti.starts_with("- ") && ri > *r0 => e.push(par),
                        _ if ti.starts_with("- ") => {
                            if let Some((_, e)) = atual.take() {
                                incluidas.push(e);
                            }
                            atual = Some((ri, vec![par]));
                        }
                        _ => return Err(format!("`{ti}` no `include` fora de um item")),
                    }
                }
                if let Some((_, e)) = atual {
                    incluidas.push(e);
                }
            }
            _ => {
                let valores: Vec<String> = match valor
                    .strip_prefix('[')
                    .and_then(|v| v.strip_suffix(']'))
                {
                    Some(lista) => lista
                        .split(',')
                        .map(|v| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
                        .filter(|v| !v.is_empty())
                        .collect(),
                    None if valor.is_empty() => {
                        let itens: Vec<String> = bloco[i..]
                            .iter()
                            .take_while(|&&(ri, _)| ri > passo)
                            .map(|&(_, ti)| ti.strip_prefix("- ").unwrap_or(ti).trim().to_string())
                            .collect();
                        i += itens.len();
                        itens
                    }
                    None => vec![valor.to_string()],
                };
                eixos.push((chave.to_string(), valores));
            }
        }
    }
    if !eixos.is_empty() && !incluidas.is_empty() {
        return Err("a matriz tem eixos e `include` juntos — a conferência não a lê".into());
    }
    if incluidas.is_empty() {
        let mut produto: Vec<Entrada> = vec![Vec::new()];
        for (chave, valores) in &eixos {
            produto = produto
                .iter()
                .flat_map(|e| {
                    valores.iter().map(move |v| {
                        let mut nova = e.clone();
                        nova.push((chave.clone(), v.clone()));
                        nova
                    })
                })
                .collect();
        }
        return Ok(produto);
    }
    Ok(incluidas)
}

#[cfg(test)]
mod testes {
    use super::*;

    fn parte(k: usize, n: usize) -> Option<Parte> {
        Some(Parte::nova(k, n).unwrap())
    }

    #[test]
    fn a_parte_mal_escrita_e_recusada() {
        assert_eq!(parte_da_rodada(None), Ok(None));
        assert_eq!(parte_da_rodada(Some("1/2")), Ok(parte(1, 2)));
        assert_eq!(parte_da_rodada(Some("2/2")), Ok(parte(2, 2)));
        assert_eq!(parte_da_rodada(Some(" 1 / 1 ")), Ok(parte(1, 1)));
        for ruim in ["", "1", "a/b", "1/2/3", "-1/2"] {
            let erro = parte_da_rodada(Some(ruim)).unwrap_err();
            assert_eq!(
                erro,
                format!("DUKE_PARTE={ruim}: esperava a parte e o total, como 1/2")
            );
        }
        for fora in ["0/2", "3/2", "1/0"] {
            let erro = parte_da_rodada(Some(fora)).unwrap_err();
            assert_eq!(
                erro,
                format!("DUKE_PARTE={fora}: a parte vai de 1 ao total, e o total não é zero")
            );
        }
    }

    #[test]
    fn a_variavel_que_nao_e_texto_e_recusada() {
        use std::ffi::OsStr;
        assert_eq!(pedida_de(None), Ok(None));
        assert_eq!(pedida_de(Some(OsStr::new("2/3"))), Ok(parte(2, 3)));
        assert!(pedida_de(Some(OsStr::new("2 de 3"))).is_err());
        assert!(
            pedida_de(Some(OsStr::new(""))).is_err(),
            "a variável vazia não é a rodada inteira"
        );
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let erro = pedida_de(Some(OsStr::from_bytes(b"1/\xff"))).unwrap_err();
            assert!(erro.contains("não é texto"), "{erro}");
        }
    }

    const NORMAIS: [&str; 6] = ["a1", "b2", "c3", "d4", "e5", "f6"];
    const DE_QUEDA: [&str; 4] = ["q7", "r8", "s9", "t10"];

    fn rodada(
        parte: Option<Parte>,
        filtro: Option<&str>,
    ) -> (Vec<&'static str>, Vec<&'static str>) {
        let (n, q) = da_rodada(&NORMAIS, &DE_QUEDA, |c| c, parte, filtro);
        (
            n.into_iter().copied().collect(),
            q.into_iter().copied().collect(),
        )
    }

    #[test]
    fn a_rodada_de_cada_parte_e_a_fatia_da_tabela_inteira() {
        // Sem parte nem filtro, todos, na ordem.
        assert_eq!(rodada(None, None), (NORMAIS.to_vec(), DE_QUEDA.to_vec()));
        for n in 1..=12 {
            let mut normais = Vec::new();
            let mut de_queda = Vec::new();
            for k in 1..=n {
                let (a, b) = rodada(parte(k, n), None);
                normais.extend(a);
                de_queda.extend(b);
            }
            // Cada um em exatamente uma parte: a união, sem repetição, é a
            // tabela inteira.
            normais.sort_unstable();
            de_queda.sort_unstable();
            let (mut todos_n, mut todos_q) = (NORMAIS.to_vec(), DE_QUEDA.to_vec());
            todos_n.sort_unstable();
            todos_q.sort_unstable();
            assert_eq!((normais, de_queda), (todos_n, todos_q), "{n} partes");
        }
        // O índice dos de queda continua o dos normais: na parte 1 de 3, os
        // de índice 0, 3, 6 e 9 — dois normais e dois de queda.
        assert_eq!(
            rodada(parte(1, 3), None),
            (vec!["a1", "d4"], vec!["q7", "t10"])
        );
        assert_eq!(rodada(parte(3, 3), None), (vec!["c3", "f6"], vec!["s9"]));
        // Uma parte sem nenhum de queda não pede a compilação deles.
        assert_eq!(rodada(parte(6, 10), None), (vec!["f6"], vec![]));
        assert_eq!(rodada(parte(7, 10), None), (vec![], vec!["q7"]));
    }

    #[test]
    fn o_filtro_pelo_nome_vale_dentro_da_parte() {
        assert_eq!(rodada(None, Some("b2|r8")), (vec!["b2"], vec!["r8"]));
        // "b2" é da parte 2 de 2 (índice 1), "r8" também (índice 7).
        assert_eq!(rodada(parte(1, 2), Some("b2|r8")), (vec![], vec![]));
        assert_eq!(rodada(parte(2, 2), Some("b2|r8")), (vec!["b2"], vec!["r8"]));
        assert_eq!(rodada(None, Some("nenhum")), (vec![], vec![]));
    }

    #[test]
    fn o_cabecalho_da_bancada_diz_quantos_da_parte() {
        assert_eq!(descrever(None, 60), "60 cenarios");
        assert_eq!(
            descrever(parte(1, 3), 60),
            "a parte 1 de 3 — 20 dos 60 cenarios"
        );
        assert_eq!(
            descrever(parte(2, 3), 20),
            "a parte 2 de 3 — 7 dos 20 cenarios"
        );
        assert_eq!(
            descrever(parte(3, 3), 20),
            "a parte 3 de 3 — 6 dos 20 cenarios"
        );
    }

    #[test]
    fn o_anuncio_da_suite_se_le() {
        assert_eq!(
            ler_o_anuncio("  suite de testes :: x86_64 :: 989 casos"),
            Some(Anuncio {
                parte: None,
                rodados: 989,
                total: 989
            })
        );
        assert_eq!(
            ler_o_anuncio("  suite de testes :: aarch64 :: parte 2 de 40: 31 de 987 casos\r"),
            Some(Anuncio {
                parte: parte(2, 40),
                rodados: 31,
                total: 987
            })
        );
        for nao in [
            "",
            "  suite de testes :: x86_64",
            "  suite de testes :: x86_64 :: casos",
            "  suite de testes :: x86_64 :: parte 0 de 2: 1 de 3 casos",
            "  suite de testes :: x86_64 :: parte 3 de 2: 1 de 3 casos",
            "  suite de testes :: x86_64 :: parte 1 de 2 1 de 3 casos",
            "  suite de testes :: x86_64 :: parte um de 2: 1 de 3 casos",
            "  memoria: clonar compartilha sem copiar     ok",
        ] {
            assert_eq!(ler_o_anuncio(nao), None, "{nao}");
        }
    }

    #[test]
    fn o_placar_se_le_campo_a_campo() {
        assert_eq!(ler_o_placar("  31 de 31 passaram"), Some((31, 31)));
        assert_eq!(ler_o_placar("  30 de 31 passaram\r"), Some((30, 31)));
        assert_eq!(ler_o_placar("janela de MMIO em 0x1000"), None);
        assert_eq!(ler_o_placar("  31 de 31 passaram, quase"), None);
        // Nada depois do placar: a linha é ele inteira.
        assert_eq!(ler_o_placar("  31 de 31 passaram agora"), None);
        assert_eq!(ler_o_placar("  31 de 31"), None);
    }

    fn saida(linhas: &[&'static str]) -> Vec<&'static str> {
        linhas.to_vec()
    }

    #[test]
    fn a_suite_que_rodou_a_parte_pedida_passa() {
        let s = saida(&[
            "=====",
            "  suite de testes :: x86_64 :: parte 1 de 40: 32 de 989 casos",
            "  json: desescapa os substitutos    ok",
            "-----",
            "  32 de 32 passaram",
            "  pilha: estouro e detectado        ok",
        ]);
        assert_eq!(
            conferir_a_suite(parte(1, 40), s.iter().copied()),
            Ok(Anuncio {
                parte: parte(1, 40),
                rodados: 32,
                total: 989
            })
        );
        let inteira = saida(&[
            "  suite de testes :: aarch64 :: 987 casos",
            "  987 de 987 passaram",
        ]);
        assert!(conferir_a_suite(None, inteira.iter().copied()).is_ok());
    }

    #[test]
    fn a_suite_de_outra_parte_ou_sem_anuncio_reprova() {
        let da_parte = saida(&[
            "  suite de testes :: x86_64 :: parte 2 de 40: 31 de 989 casos",
            "  31 de 31 passaram",
        ]);
        // Outra parte, e a inteira, contra um ELF da parte 2 de 40.
        let erro = conferir_a_suite(parte(1, 40), da_parte.iter().copied()).unwrap_err();
        assert!(
            erro.contains("a parte 1/40") && erro.contains("a parte 2/40"),
            "{erro}"
        );
        let erro = conferir_a_suite(None, da_parte.iter().copied()).unwrap_err();
        assert!(erro.contains("a suíte inteira"), "{erro}");
        // A inteira contra quem pediu uma parte.
        let inteira = saida(&[
            "  suite de testes :: x86_64 :: 989 casos",
            "  989 de 989 passaram",
        ]);
        assert!(conferir_a_suite(parte(1, 2), inteira.iter().copied()).is_err());
        // Sem anúncio.
        let muda = saida(&["  989 de 989 passaram"]);
        assert!(conferir_a_suite(None, muda.iter().copied()).is_err());
        // Dois anúncios: a máquina subiu duas vezes.
        let duas = saida(&[
            "  suite de testes :: x86_64 :: 989 casos",
            "  suite de testes :: x86_64 :: 989 casos",
            "  989 de 989 passaram",
        ]);
        assert!(conferir_a_suite(None, duas.iter().copied()).is_err());
    }

    #[test]
    fn o_placar_tem_de_contar_os_anunciados() {
        let a = "  suite de testes :: x86_64 :: parte 1 de 2: 500 de 989 casos";
        // O placar de outra contagem, nenhum, ou dois.
        for placar in [
            vec!["  499 de 500 passaram"],
            vec!["  989 de 989 passaram"],
            vec![],
            vec!["  500 de 500 passaram", "  500 de 500 passaram"],
        ] {
            let mut s = vec![a];
            s.extend(placar.iter().copied());
            assert!(
                conferir_a_suite(parte(1, 2), s.iter().copied()).is_err(),
                "{s:?}"
            );
        }
        let mut s = vec![a];
        s.push("  500 de 500 passaram");
        assert!(conferir_a_suite(parte(1, 2), s.iter().copied()).is_ok());
    }

    #[test]
    fn o_anuncio_menor_que_a_fatia_da_regra_reprova() {
        // A parte 1 de 2 de 989 tem 495 pela regra; 400 é outra conta.
        let s = saida(&[
            "  suite de testes :: x86_64 :: parte 1 de 2: 400 de 989 casos",
            "  400 de 400 passaram",
        ]);
        let erro = conferir_a_suite(parte(1, 2), s.iter().copied()).unwrap_err();
        assert!(erro.contains("menos que os 495"), "{erro}");
    }

    /// As linhas dos casos que reprovaram na rodada do adversário do kernel
    /// da rodada 8 no ARM, com o laço que diz `FALHOU` e não conta: o nome
    /// mais curto que a coluna e o mais longo que ela.
    const FALHARAM_NA_RODADA_8: [&str; 5] = [
        "  senha: a prova, a nova e a desistencia     FALHOU -- a troca nao gravou o desfecho esperado, uma vez",
        "  senha: so a propria, com a sessao e a permissao FALHOU -- um segredo, ou um pedaco dele, foi para a auditoria",
        "  consoles: nada antes do login              FALHOU -- um segredo, ou um pedaco dele, foi para a auditoria",
        "  consoles: sem ninguem, o comando vai a auditoria sem o resumo dos parametros; com alguem, com ele FALHOU -- um segredo, ou um pedaco dele, foi para a auditoria",
        "  consoles: o log diz executado so depois da decisao do gate, o adiado uma vez, e a recusa e o parametro invalido em linha propria FALHOU -- o parametro invalido nao foi gravado uma vez",
    ];

    /// A linha de um caso que reprovou é a que `testes::executar_todos`
    /// escreve, com o `\r` do fim ou sem ele, e com o que o caso ou o console
    /// escreveram sem fim de linha antes dela — o `X` de `console: o log
    /// humano chega a tela`, o `duke> ` do prompt —; e não a de um caso que
    /// passou, a do log, a do resumo do fim, o anúncio nem o placar.
    #[test]
    fn a_linha_de_um_caso_que_reprovou_se_le() {
        for sim in FALHARAM_NA_RODADA_8 {
            assert!(e_um_caso_que_falhou(sim), "{sim}");
            assert!(e_um_caso_que_falhou(&format!("{sim}\r")), "{sim}");
        }
        for sim in [
            "X  console: o log humano chega a tela         FALHOU -- a tela fisica sumiu",
            "duke>   consoles: nada antes do login              FALHOU -- um segredo, ou um pedaco dele, foi para o log",
        ] {
            assert!(e_um_caso_que_falhou(sim), "{sim}");
        }
        for nao in [
            "",
            "  memoria: clonar compartilha sem copiar     ok",
            "X  console: o log humano chega a tela         ok",
            "[ 1374]   681780ms info  teste    10.0.2.2 responde: ok",
            "  falhou: senha: a prova, a nova e a desistencia -- a troca nao gravou o desfecho esperado, uma vez",
            "  suite de testes :: aarch64 :: 29 casos",
            "  29 de 29 passaram",
        ] {
            assert!(!e_um_caso_que_falhou(nao), "{nao}");
        }
    }

    /// A linha `FALHOU` de um caso reprova a suíte cujo placar diz que todos
    /// passaram — inteira ou numa parte —, e o erro diz as linhas: é a saída
    /// do laço que diz a falha e não a conta (o informativo 1 do adversário
    /// do kernel da rodada 8, com as linhas da rodada dele). Uma linha só
    /// basta; sem elas, a mesma saída passa.
    #[test]
    fn a_linha_falhou_de_um_caso_reprova_com_o_placar_cheio() {
        let com = |anuncio: &'static str, falharam: &[&'static str], placar: &'static str| {
            let mut s = vec![
                anuncio,
                "  suite: o laco reprova o caso que a conferencia reprova ok",
            ];
            s.extend_from_slice(falharam);
            s.push(placar);
            s.push("  pilha: estouro e detectado                 ok");
            s
        };
        let inteira = "  suite de testes :: aarch64 :: 29 casos";
        let s = com(inteira, &FALHARAM_NA_RODADA_8, "  29 de 29 passaram");
        let erro = conferir_a_suite(None, s.iter().copied()).unwrap_err();
        assert!(
            erro.contains("os 29 casos passaram") && erro.contains("5 caso(s)"),
            "{erro}"
        );
        for linha in FALHARAM_NA_RODADA_8 {
            assert!(erro.contains(linha.trim()), "{erro}");
        }
        // Numa parte, o mesmo.
        let da_parte = "  suite de testes :: x86_64 :: parte 2 de 3: 10 de 28 casos";
        let s = com(da_parte, &FALHARAM_NA_RODADA_8, "  10 de 10 passaram");
        let erro = conferir_a_suite(parte(2, 3), s.iter().copied()).unwrap_err();
        assert!(erro.contains("os 10 casos passaram"), "{erro}");
        // Uma linha só, com o `\r` do fim e com o que o caso escreveu sem fim
        // de linha antes dela.
        let s = com(
            inteira,
            &["X  console: o log humano chega a tela         FALHOU -- a tela fisica sumiu\r"],
            "  29 de 29 passaram\r",
        );
        let erro = conferir_a_suite(None, s.iter().copied()).unwrap_err();
        assert!(
            erro.contains("1 caso(s)")
                && erro.contains("X  console: o log humano chega a tela")
                && !erro.contains('\r'),
            "{erro}"
        );
        // Sem as linhas `FALHOU`, as mesmas saídas passam.
        let s = com(inteira, &[], "  29 de 29 passaram");
        assert!(conferir_a_suite(None, s.iter().copied()).is_ok());
        let s = com(da_parte, &[], "  10 de 10 passaram");
        assert!(conferir_a_suite(parte(2, 3), s.iter().copied()).is_ok());
    }

    /// A parte vai para a compilação da suíte, e só para ela: sem parte, a
    /// variável sai do ambiente do cargo — um valor herdado de um shell não
    /// chega ao kernel —; com ela, vai com o texto `k/n`. E uma parte numa
    /// compilação sem `modo-teste` é recusada antes do cargo.
    #[test]
    fn a_parte_so_vai_para_a_compilacao_da_suite() {
        use std::ffi::{OsStr, OsString};
        let ambiente = |p: Option<Parte>| -> Vec<(OsString, Option<OsString>)> {
            let mut cargo = std::process::Command::new("cargo");
            super::super::ambiente_do_kernel(&mut cargo, p);
            cargo
                .get_envs()
                .map(|(k, v)| (k.to_owned(), v.map(OsStr::to_owned)))
                .collect()
        };
        let sem = ambiente(None);
        assert!(sem.contains(&(OsString::from(DA_SUITE), None)), "{sem:?}");
        let com = ambiente(parte(2, 3));
        assert!(
            com.contains(&(OsString::from(DA_SUITE), Some(OsString::from("2/3")))),
            "{com:?}"
        );
        // E o que o cargo exporta para o `xtask` sai nos dois.
        for var in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR"] {
            assert!(sem.contains(&(OsString::from(var), None)), "{var}");
            assert!(com.contains(&(OsString::from(var), None)), "{var}");
        }
        let fora = super::super::compilar_o_kernel_com(
            super::super::Arquitetura::X86_64,
            false,
            &[],
            None,
            parte(1, 2),
        );
        assert!(fora.is_err_and(|e| e.contains("modo-teste")));
    }

    /// O nome da variável da compilação é o mesmo dos dois lados: o
    /// `option_env!` do kernel e a constante daqui. Divergindo, o kernel não
    /// receberia a parte, rodaria a suíte inteira — e o anúncio reprovaria,
    /// mas só depois de uma suíte inteira de máquina.
    #[test]
    fn o_kernel_le_a_parte_da_variavel_que_o_xtask_poe() {
        let testes =
            std::fs::read_to_string(super::super::raiz_do_projeto().join("kernel/src/testes.rs"))
                .expect("kernel/src/testes.rs");
        assert!(
            testes.contains(&format!("option_env!(\"{DA_SUITE}\")")),
            "o kernel não lê {DA_SUITE}"
        );
        assert!(
            !testes.contains("option_env!(\"DUKE_PARTE\")")
                && !testes.contains("env!(\"DUKE_PARTE\")"),
            "o kernel lê DUKE_PARTE direto"
        );
    }

    /// As partes que a CI tem hoje: cada grupo com a conta das partes. Uma
    /// mudança na matriz muda esta lista — de propósito: a conferência
    /// tem de ler cada grupo, e não achar nenhum e passar.
    #[test]
    fn a_ci_tem_as_partes_completas() {
        let ci = include_str!("../../.github/workflows/ci.yml");
        let (grupos, fora) = matrizes_com_partes("ci.yml", ci);
        assert_eq!(fora, Vec::<String>::new());
        assert_eq!(
            grupos,
            [
                "ci.yml/testes (arch=x86_64, tipo=suite): 3",
                "ci.yml/testes (arch=aarch64, tipo=suite): 3",
                "ci.yml/testes (arch=aarch64, tipo=iniciador): 2",
                "ci.yml/video (arch=x86_64): 2",
                "ci.yml/video (arch=aarch64): 2",
                "ci.yml/persistencia (arch=x86_64): 3",
                "ci.yml/persistencia (arch=aarch64): 2",
                "ci.yml/atualizacao (arch=x86_64): 2",
                "ci.yml/atualizacao (arch=aarch64): 1",
                "ci.yml/tempo (arch=x86_64): 3",
                "ci.yml/tempo (arch=aarch64): 3",
            ]
        );
    }

    /// Um job de mentira com as partes de `partes`, pela lista do `include`.
    fn com_include(partes: &[(&str, &str)]) -> String {
        let mut texto = String::from(
            "on:\n  push:\njobs:\n  lints:\n    runs-on: x\n  suite:\n    strategy:\n      matrix:\n        include:\n",
        );
        for (arch, parte) in partes {
            texto.push_str(&format!(
                "          - arch: {arch}\n            parte: suite {parte}\n            duke_parte: {parte}\n"
            ));
        }
        texto.push_str("          - arch: x86_64\n            parte: release\n");
        texto.push_str(
            "    steps:\n      - run: cargo xtask test\n        env:\n          DUKE_PARTE: ${{ matrix.duke_parte }}\n",
        );
        texto
    }

    #[test]
    fn as_partes_completas_passam() {
        let texto = com_include(&[
            ("x86_64", "1/2"),
            ("aarch64", "2/3"),
            ("x86_64", "2/2"),
            ("aarch64", "1/3"),
            ("aarch64", "3/3"),
        ]);
        let (grupos, fora) = matrizes_com_partes("w.yml", &texto);
        assert_eq!(fora, Vec::<String>::new());
        assert_eq!(
            grupos,
            [
                "w.yml/suite (arch=x86_64): 2",
                "w.yml/suite (arch=aarch64): 3"
            ]
        );
    }

    #[test]
    fn a_chave_da_parte_nao_separa_o_grupo() {
        let texto = com_include(&[("x86_64", "1/2"), ("x86_64", "2/2")]).replace(
            "duke_parte: 2/2\n",
            "duke_parte: 2/2\n            fumaca: true\n",
        );
        assert!(texto.contains("fumaca: true"));
        let (grupos, fora) = matrizes_com_partes("w.yml", &texto);
        assert_eq!(fora, Vec::<String>::new());
        assert_eq!(grupos, ["w.yml/suite (arch=x86_64): 2"]);
    }

    #[test]
    fn a_parte_que_falta_ou_se_repete_e_recusada() {
        for partes in [
            &[("x86_64", "1/3"), ("x86_64", "3/3")][..],
            &[("x86_64", "1/2"), ("x86_64", "1/2"), ("x86_64", "2/2")][..],
            &[("x86_64", "2/2")][..],
        ] {
            let (grupos, fora) = matrizes_com_partes("w.yml", &com_include(partes));
            assert!(grupos.is_empty(), "{partes:?}: {grupos:?}");
            assert_eq!(fora.len(), 1, "{partes:?}: {fora:?}");
            assert!(fora[0].contains("uma vez cada"), "{}", fora[0]);
        }
    }

    #[test]
    fn o_total_misturado_e_a_parte_ilegivel_sao_recusados() {
        let (_, fora) = matrizes_com_partes(
            "w.yml",
            &com_include(&[("x86_64", "1/2"), ("x86_64", "2/3")]),
        );
        assert_eq!(fora.len(), 1, "{fora:?}");
        assert!(fora[0].contains("não têm o mesmo total"), "{}", fora[0]);

        let (_, fora) = matrizes_com_partes(
            "w.yml",
            &com_include(&[("x86_64", "1/2"), ("x86_64", "x/2")]),
        );
        assert_eq!(fora.len(), 1, "{fora:?}");
        assert!(fora[0].contains("não é uma parte"), "{}", fora[0]);
    }

    #[test]
    fn a_parte_fixa_e_recusada() {
        let texto = com_include(&[("x86_64", "1/1")]).replace("${{ matrix.duke_parte }}", "1/2");
        let (_, fora) = matrizes_com_partes("w.yml", &texto);
        assert_eq!(fora.len(), 1, "{fora:?}");
        assert!(fora[0].contains("fixa"), "{}", fora[0]);
    }

    #[test]
    fn os_eixos_dao_o_produto() {
        let texto = "jobs:\n  tempo:\n    strategy:\n      matrix:\n        arch: [x86_64, aarch64]\n        parte: [1/3, 2/3, 3/3]\n    steps:\n      - env:\n          DUKE_PARTE: ${{ matrix.parte }}\n";
        let (grupos, fora) = matrizes_com_partes("w.yml", texto);
        assert_eq!(fora, Vec::<String>::new());
        assert_eq!(
            grupos,
            [
                "w.yml/tempo (arch=x86_64): 3",
                "w.yml/tempo (arch=aarch64): 3"
            ]
        );

        let sem = texto.replace("[1/3, 2/3, 3/3]", "[1/3, 3/3]");
        let (grupos, fora) = matrizes_com_partes("w.yml", &sem);
        assert!(grupos.is_empty());
        assert_eq!(fora.len(), 2, "{fora:?}");
    }

    #[test]
    fn a_matriz_que_nao_se_le_e_dita() {
        let texto = "jobs:\n  tempo:\n    strategy:\n      matrix:\n        parte: [1/2, 2/2]\n        exclude:\n          - parte: 2/2\n    steps:\n      - env:\n          DUKE_PARTE: ${{ matrix.parte }}\n";
        let (_, fora) = matrizes_com_partes("w.yml", texto);
        assert_eq!(fora.len(), 1, "{fora:?}");
        assert!(fora[0].contains("exclude"), "{}", fora[0]);

        let sem_matriz = "jobs:\n  tempo:\n    steps:\n      - env:\n          DUKE_PARTE: ${{ matrix.parte }}\n";
        let (_, fora) = matrizes_com_partes("w.yml", sem_matriz);
        assert_eq!(fora.len(), 1, "{fora:?}");
        assert!(fora[0].contains("matrix:"), "{}", fora[0]);
    }
}
