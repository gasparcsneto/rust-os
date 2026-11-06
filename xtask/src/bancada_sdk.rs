//! A bancada do SDK da malha: `cargo xtask sdk`.
//!
//! Duas máquinas de pé ao mesmo tempo — cada uma com o disco, o TPM e a
//! chave do Duke dela —, ligadas como na bancada do enlace: a origem conecta
//! a `10.0.2.100:7071`, o `guestfwd` dela roda a ponte da bancada
//! (`xtask/bancada/ponte.py`) até o hospedeiro, e a ponte leva os bytes ao
//! `hostfwd` do destino. A relação é registrada pelo administrador, com
//! prova, e a pessoa entra no Terminal das duas e lança os programas pelo
//! teclado. Nenhum programa daqui fala com a bancada: ela lê o log, a
//! auditoria e a árvore semântica de cada máquina.
//!
//! O programa feito fora do repositório — o `sdk/modelo`, compilado fora do
//! workspace e selado pelo editor `bancada` (`xtask/src/sdk.rs`) — **não**
//! está na imagem: um agente o grava no armazém de cada máquina pelo gate,
//! em pedaços de um rascunho (`fs.draft`), como chegaria de fora, e a pessoa
//! o roda pelo `user.run` — a conferência do selo e da confiança de sempre.
//!
//! Em cada par, numa ordem só, porque cada passo parte do anterior:
//!
//! 1. **NB05**: o modelo nas duas máquinas, falando entre si: o servidor em
//!    B; o cliente em A, com o pedido apontando o par — os 40 KiB de ida e o
//!    eco conferido —, e os pedidos dos dois dizendo que foi o selado pela
//!    `bancada`;
//! 2. **NB01**: o `eco-malha` em B, com um cliente remoto (o modelo de A) e
//!    um local (o modelo de B) ao mesmo tempo — os dois acabam, conferidos
//!    —; um segundo cliente remoto de A, com o primeiro ainda aberto, é
//!    recusado pelo teto da relação (DF-6), com o motivo;
//! 3. **NB02**: os dois sentidos entre os Dukes ao mesmo tempo, 1 MiB de
//!    cada lado — o eco do modelo de B volta enquanto o de A ainda manda —,
//!    sem impasse;
//! 4. **NB06**: as medidas — os avisos e a latência do aviso até a operação
//!    de cada máquina (`security.metrics`), e a vazão do laço contra a do
//!    estilo bloqueante do DN-2 (`remetente` e `recebedor`, cada pedido
//!    esperando);
//! 5. **NB03**: a `conversa` nas duas, e a pessoa digitando nas duas pelo
//!    teclado da máquina enquanto o fluxo corre: cada linha chega à outra,
//!    lida pela árvore semântica;
//! 6. **NB04**: a revogação em B no meio de um fluxo do modelo: `FIM` nos
//!    dois lados, e cada programa ouve o motivo.
//!
//! Os pares: `x86_64>aarch64`, `aarch64>x86_64`, `x86_64>x86_64` e
//! `aarch64>aarch64` — todos, ou os que `DUKE_PARES` escolhe, separados por
//! `|`.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use super::enlace::{self, DePe, Maquina, Par};
use super::fluxo::{PARES, armazem_compartilhado, encerrar};
use super::{Arquitetura, chaves};

/// O nome das raízes de estado e dos discos desta bancada, em `target/`.
const BANCADA: &str = "sdk";

/// Onde o modelo é instalado em cada máquina, e o pedido do cliente dele.
const CODIGO: &str = "/armazem/compartilhado/codigo";
const MODELO: &str = "/armazem/compartilhado/codigo/modelo";
const PAR_DO_MODELO: &str = "/armazem/compartilhado/modelo/par";
const PAR_DA_CONVERSA: &str = "/armazem/compartilhado/conversa/par";

/// O campo da `conversa` onde a pessoa digita, pelo rótulo dele na árvore
/// semântica (`programas/src/bin/conversa.rs`).
const CAMPO_DA_CONVERSA: &str = "mensagem";

/// Os códigos de saída do modelo: o fim pedido, o eco conferido, e a
/// pergunta que não abriu — ver `sdk/modelo/src/main.rs`.
const MODELO_ENCERRADO: i64 = 57;
const MODELO_CONFERIU: i64 = 58;

/// Quanto cada passo espera, no máximo: uma troca entre dois emuladores no
/// mesmo hospedeiro é lenta.
const ESPERA_PELO_PRONTO: Duration = Duration::from_secs(120);
const ESPERA_PELA_TROCA: Duration = Duration::from_secs(900);

/// Quantos bytes o cliente manda em cada passo.
const NB05_BYTES: usize = 40 * 1024;
const NB01_BYTES: usize = 4 * 1024 * 1024;
const NB02_BYTES: usize = 1024 * 1024;

/// O que um programa disse, desde uma marca do log: as linhas com o prefixo
/// dele, com o tempo de máquina de cada uma.
struct Dito {
    linhas: Vec<(u64, String)>,
}

impl Dito {
    fn de(quem: &DePe, desde: u64, prefixo: &str) -> Dito {
        Dito {
            linhas: quem.ditas_com_hora(desde, prefixo),
        }
    }

    /// O resto da primeira linha que começa com `prefixo`.
    fn dito(&self, prefixo: &str) -> Option<&str> {
        self.linhas
            .iter()
            .find_map(|(_, l)| l.strip_prefix(prefixo))
    }

    /// O tempo de máquina da primeira linha que começa com `prefixo`.
    fn hora(&self, prefixo: &str) -> Option<u64> {
        self.linhas
            .iter()
            .find_map(|(h, l)| l.starts_with(prefixo).then_some(*h))
    }

    fn texto(&self) -> String {
        let l: Vec<&str> = self.linhas.iter().map(|(_, l)| l.as_str()).collect();
        l.join(" | ")
    }
}

/// O resumo FNV-1a de 64 bits dos `n` primeiros bytes do padrão de semente
/// zero — o que o eco tem de trazer de volta.
fn resumo_do_padrao(n: usize) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for i in 0..n {
        h ^= u64::from(((i * 7 + 3) % 251) as u8);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// A vazão de `bytes` em `ms`, em KiB/s.
fn vazao(bytes: usize, ms: u64) -> String {
    if ms == 0 {
        return "-".into();
    }
    format!("{} KiB/s", (bytes as u64 * 1000 / 1024) / ms)
}

// ---------------------------------------------------------------------------
// O armazém de cada máquina
// ---------------------------------------------------------------------------

/// A versão de agora de `caminho` em `quem`, pela serial — zero se não
/// existe.
fn versao(quem: &mut DePe, caminho: &str) -> Result<u64, String> {
    let r = quem
        .m
        .pedir("fs.stat", &format!(r#"{{"path":"{caminho}"}}"#))?;
    Ok(super::persistencia::texto_do_resultado(&r, "version")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0))
}

/// Grava `texto` em `caminho` de `quem`, pela serial — o sistema —, com o
/// diretório de cima.
fn gravar_texto(quem: &mut DePe, caminho: &str, texto: &str) -> Result<(), String> {
    if let Some((dir, _)) = caminho.rsplit_once('/') {
        let r = quem
            .m
            .pedir("fs.mkdir", &format!(r#"{{"path":"{dir}"}}"#))?;
        if r.contains(r#""error""#) && !r.contains("ja ha algo nesse caminho") {
            return Err(format!("{}: {dir} nao foi criado\n  {r}", quem.papel));
        }
    }
    let v = versao(quem, caminho)?;
    let escapado = texto.replace('\n', "\\n");
    let r = quem.m.pedir(
        "fs.write",
        &format!(r#"{{"path":"{caminho}","content":"{escapado}","expect_version":{v}}}"#),
    )?;
    if !r.contains(r#""ok":true"#) {
        return Err(format!("{}: {caminho} nao foi gravado\n  {r}", quem.papel));
    }
    Ok(())
}

/// O modelo selado de `arch` — o mesmo que a bancada da suíte serve — no
/// armazém da `maquina`, por um agente do canal cifrado: em pedaços de um
/// rascunho, e o rascunho inteiro num `fs.write` só. O agente só grava; quem
/// roda é a pessoa.
fn instalar_o_modelo(
    maquina: &Maquina,
    quem: &mut DePe,
    arch: Arquitetura,
) -> Result<usize, String> {
    for dir in ["/armazem/compartilhado", CODIGO] {
        let r = quem
            .m
            .pedir("fs.mkdir", &format!(r#"{{"path":"{dir}"}}"#))?;
        if r.contains(r#""error""#) && !r.contains("ja ha algo nesse caminho") {
            return Err(format!("{}: {dir} nao foi criado\n  {r}", quem.papel));
        }
    }
    let selado = super::codigo::publicado(arch, super::codigo::DO_SDK)?;
    let atual = versao(quem, MODELO)?;
    let chaves = chaves::Chaves::garantir()?;
    let duke = maquina.publica();
    maquina.na_raiz(|| -> Result<(), String> {
        let mut agente =
            super::AgenteNaPorta::conectar_com_publica(arch, 1, &chaves.do_agente(1), &duke)?;
        let mut rascunho: Option<u64> = None;
        for pedaco in selado.chunks(protocolo::usuario::nativo::MAIOR_ANEXO) {
            let params = match rascunho {
                Some(n) => format!(r#"{{"path":"{MODELO}","draft":{n}}}"#),
                None => format!(r#"{{"path":"{MODELO}"}}"#),
            };
            let r = agente.pedir_com_anexo("fs.draft", &params, pedaco)?;
            let n = super::apos(&r, r#""draft":"#)
                .and_then(|t| t.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| format!("o rascunho do modelo nao andou\n  {r}"))?;
            rascunho = Some(n);
        }
        let n = rascunho.ok_or("o modelo esta vazio")?;
        let r = agente.pedir(
            "fs.write",
            &format!(r#"{{"path":"{MODELO}","expect_version":{atual},"draft":{n}}}"#),
        )?;
        if !r.contains(r#""ok":true"#) {
            return Err(format!("o modelo nao foi gravado\n  {r}"));
        }
        Ok(())
    })?;
    Ok(selado.len())
}

// ---------------------------------------------------------------------------
// Os programas
// ---------------------------------------------------------------------------

/// A pessoa lança o modelo instalado em `quem`, e ele diz que está pronto:
/// onde o log estava antes, e o endpoint.
fn modelo_pronto(quem: &mut DePe) -> Result<(u64, String), String> {
    let desde = quem.marca()?.log;
    quem.lancar_caminho(MODELO)?;
    let (i, resto) = quem.esperar_dito(
        desde,
        &["modelo: pronto ", "modelo: a pergunta nao abriu"],
        ESPERA_PELO_PRONTO,
    )?;
    if i != 0 {
        return Err(format!(
            "{}: o modelo nao ficou pronto: {resto}",
            quem.papel
        ));
    }
    let endpoint = resto.split(' ').next().unwrap_or("").to_string();
    Ok((desde, endpoint))
}

/// Espera o processo que disse `pronto` desde `desde` sair, e devolve o
/// código — `processo encerrou com codigo <n>`, a linha do kernel.
fn saida(quem: &mut DePe, desde: u64, espera: Duration) -> Result<i64, String> {
    let (_, codigo) = quem.esperar_dito(desde, &["processo encerrou com codigo "], espera)?;
    codigo
        .trim()
        .parse()
        .map_err(|_| format!("{}: codigo de saida `{codigo}`", quem.papel))
}

/// O cliente do modelo em `quem`: o pedido gravado — o dispositivo, os
/// bytes e a quem perguntar — e o modelo lançado. Devolve onde o log estava.
fn cliente(
    quem: &mut DePe,
    dispositivo: &str,
    bytes: usize,
    programa: &str,
) -> Result<u64, String> {
    gravar_texto(
        quem,
        PAR_DO_MODELO,
        &format!("{dispositivo}\n{bytes}\n{programa}\n"),
    )?;
    let desde = quem.marca()?.log;
    quem.lancar_caminho(MODELO)?;
    Ok(desde)
}

/// Espera o cliente lançado desde `desde` dizer o fim do eco, e confere —
/// pulando as linhas em `sem`, as de outro cliente do modelo na mesma
/// máquina. O código de saída é o da primeira saída depois do eco: a do
/// outro cliente, que saiu antes, não conta.
fn eco_conferido(
    quem: &mut DePe,
    desde: u64,
    bytes: usize,
    sem: &[String],
) -> Result<Dito, String> {
    let (i, resto, onde) = quem.esperar_dito_sem(
        desde,
        &[
            "modelo: eco ",
            "modelo: a pergunta acabou",
            "modelo: a pergunta nao abriu",
        ],
        sem,
        ESPERA_PELA_TROCA,
    )?;
    let dito = Dito::de(quem, desde, "modelo: ");
    let esperado = format!("{bytes} {} confere", resumo_do_padrao(bytes));
    if i != 0 || resto != esperado {
        return Err(format!(
            "{}: o eco do modelo nao conferiu ({resto}; esperado {esperado})\n  {}",
            quem.papel,
            dito.texto()
        ));
    }
    let codigo = saida(quem, onde, Duration::from_secs(30))?;
    if codigo != MODELO_CONFERIU {
        return Err(format!("{}: o cliente saiu com {codigo}", quem.papel));
    }
    Ok(dito)
}

/// O pedido do cliente apagado: o modelo lançado depois dele só serve.
fn sem_pedido(quem: &mut DePe) -> Result<(), String> {
    let v = versao(quem, PAR_DO_MODELO)?;
    if v == 0 {
        return Ok(());
    }
    let r = quem.m.pedir(
        "fs.delete",
        &format!(r#"{{"path":"{PAR_DO_MODELO}","expect_version":{v}}}"#),
    )?;
    if !r.contains(r#""ok":true"#) {
        return Err(format!(
            "{}: o pedido do modelo nao saiu\n  {r}",
            quem.papel
        ));
    }
    Ok(())
}

/// Os pedidos do modelo que `quem` gravou desde `desde` dizem que ele é o
/// de fora, selado pela `bancada`.
fn selado_pela_bancada(quem: &mut DePe, desde: u64, metodo: &str) -> Result<(), String> {
    quem.ler()?;
    if quem.gravados(desde).any(|g| {
        g.metodo == metodo
            && g.codigo == "ALLOW"
            && g.detalhe.contains("(modelo ")
            && g.detalhe.contains(" de bancada)")
    }) {
        Ok(())
    } else {
        Err(format!(
            "{}: nenhum {metodo} do modelo selado pela bancada na auditoria",
            quem.papel
        ))
    }
}

/// A seção `mesh_notices` de `security.metrics` de `quem`: os publicados,
/// os juntados, a quantidade de medidas e a média e o maior, em ns, do
/// aviso até a operação.
fn medidas_do_aviso(quem: &mut DePe) -> Result<[u64; 5], String> {
    let r = quem.m.pedir("security.metrics", "{}")?;
    let secao = super::apos(&r, r#""mesh_notices":{"#)
        .ok_or_else(|| format!("{}: security.metrics sem os avisos\n  {r}", quem.papel))?;
    let numero = |campo: &str| -> Result<u64, String> {
        super::apos(secao, &format!(r#""{campo}":"#))
            .and_then(|t| t.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| format!("security.metrics sem `{campo}` nos avisos"))
    };
    Ok([
        numero("published")?,
        numero("merged")?,
        numero("to_operation_samples")?,
        numero("to_operation_avg_ns")?,
        numero("to_operation_max_ns")?,
    ])
}

// ---------------------------------------------------------------------------
// Os passos
// ---------------------------------------------------------------------------

struct Bancada {
    par: Par,
    medidas: Vec<String>,
}

impl Bancada {
    fn origem(&mut self) -> &mut DePe {
        &mut self.par.origem
    }

    fn destino(&mut self) -> &mut DePe {
        &mut self.par.destino
    }
}

/// NB05: o modelo nas duas máquinas, falando entre si.
fn nb05(b: &mut Bancada) -> Result<String, String> {
    sem_pedido(b.destino())?;
    let antes_b = b.destino().marca()?.auditoria;
    let (desde_b, _) = modelo_pronto(b.destino())?;
    let antes_a = b.origem().marca()?.auditoria;
    let desde_a = cliente(b.origem(), enlace::DISPOSITIVO, NB05_BYTES, "modelo")?;
    let dito = eco_conferido(b.origem(), desde_a, NB05_BYTES, &[])?;
    let (_, ecoado) =
        b.destino()
            .esperar_dito(desde_b, &["modelo: ecoei "], Duration::from_secs(60))?;
    if !ecoado.ends_with(&format!(" {NB05_BYTES}")) {
        return Err(format!("o servidor do modelo nao ecoou tudo: {ecoado}"));
    }
    selado_pela_bancada(b.origem(), antes_a, "stream.open")?;
    selado_pela_bancada(b.destino(), antes_b, "fabric.offer")?;
    let ms = match (dito.hora("perguntei "), dito.hora("eco ")) {
        (Some(a), Some(z)) if z >= a => z - a,
        _ => 0,
    };
    Ok(format!(
        "NB05: o modelo de fora do repositorio, selado pela bancada, nas duas maquinas: {NB05_BYTES} bytes ida e volta conferidos em {ms} ms; os pedidos dos dois dizem `de bancada`"
    ))
}

/// NB01: o eco-malha em B com um cliente remoto e um local ao mesmo tempo,
/// e um segundo remoto recusado pelo teto da relação.
fn nb01(b: &mut Bancada) -> Result<String, String> {
    // O servidor do NB05 sai: quem ecoa agora é o eco-malha.
    encerrar(b.destino(), &["modelo"])?;
    let desde_eco = b.destino().marca()?.log;
    b.destino().lancar("eco-malha")?;
    b.destino()
        .esperar_dito(desde_eco, &["eco-malha: pronto "], ESPERA_PELO_PRONTO)?;
    // O remoto, de A, e o local, de B, ao mesmo tempo.
    let desde_r = cliente(b.origem(), enlace::DISPOSITIVO, NB01_BYTES, "eco-malha")?;
    b.origem()
        .esperar_dito(desde_r, &["modelo: perguntei "], ESPERA_PELO_PRONTO)?;
    let desde_l = cliente(b.destino(), "", NB01_BYTES, "eco-malha")?;
    // O segundo remoto, com o primeiro aberto: o teto da relação, que o
    // Duke de B aplica — a abertura sai daqui, e volta recusada de lá.
    let desde_2 = b.origem().marca()?.log;
    b.origem().lancar_caminho(MODELO)?;
    let fins = [
        "modelo: a pergunta nao abriu: ",
        "modelo: a pergunta acabou: ",
        "modelo: eco ",
    ];
    let (i, recusa) = b.origem().esperar_dito(desde_2, &fins, ESPERA_PELA_TROCA)?;
    if i == 2 || !recusa.contains("relacao") {
        return Err(format!(
            "o segundo fluxo remoto da mesma relacao nao foi recusado pelo teto dela: {recusa}"
        ));
    }
    // A recusa é do segundo cliente, e não do primeiro: os dois são o
    // modelo, na mesma máquina.
    let do_segundo = [format!("{}{recusa}", fins[i])];
    let r = eco_conferido(b.origem(), desde_r, NB01_BYTES, &do_segundo)?;
    let l = eco_conferido(b.destino(), desde_l, NB01_BYTES, &[])?;
    let ecoados = b.destino().ditas_com_hora(desde_eco, "eco-malha: ecoei ");
    if ecoados.len() < 2
        || !ecoados
            .iter()
            .all(|(_, e)| e.ends_with(&format!(" {NB01_BYTES}")))
    {
        return Err(format!(
            "o eco-malha nao ecoou os dois inteiros: {ecoados:?}"
        ));
    }
    let aceitos = b.destino().ditas_com_hora(desde_eco, "eco-malha: aceitei ");
    let remoto = aceitos.iter().any(|(_, a)| a.contains(enlace::DISPOSITIVO));
    if !remoto {
        return Err(format!(
            "o eco-malha nao disse o cliente do outro Duke: {aceitos:?}"
        ));
    }
    encerrar(b.destino(), &["eco-malha"])?;
    let tempo = |d: &Dito| match (d.hora("perguntei "), d.hora("eco ")) {
        (Some(a), Some(z)) if z >= a => z - a,
        _ => 0,
    };
    let (mr, ml) = (tempo(&r), tempo(&l));
    b.medidas.push(format!(
        "4 MiB ida e volta pelo laco: remoto {mr} ms ({}), local {ml} ms ({})",
        vazao(2 * NB01_BYTES, mr),
        vazao(2 * NB01_BYTES, ml)
    ));
    Ok(format!(
        "NB01: o eco-malha em B serviu um cliente de A e um de B ao mesmo tempo, 4 MiB ida e volta cada, conferidos; o segundo cliente remoto recusado: {}",
        recusa.trim()
    ))
}

/// NB02: 1 MiB de cada lado ao mesmo tempo, entre os Dukes.
fn nb02(b: &mut Bancada) -> Result<String, String> {
    sem_pedido(b.destino())?;
    modelo_pronto(b.destino())?;
    let desde = cliente(b.origem(), enlace::DISPOSITIVO, NB02_BYTES, "modelo")?;
    let d = eco_conferido(b.origem(), desde, NB02_BYTES, &[])?;
    encerrar(b.destino(), &["modelo"])?;
    let ms = match (d.hora("perguntei "), d.hora("eco ")) {
        (Some(a), Some(z)) if z >= a => z - a,
        _ => 0,
    };
    Ok(format!(
        "NB02: 1 MiB de A para B e o eco de B para A ao mesmo tempo, sem impasse: {ms} ms ({})",
        vazao(2 * NB02_BYTES, ms)
    ))
}

/// NB06: as medidas — o aviso nas duas máquinas, e a vazão do laço contra a
/// do estilo bloqueante do DN-2 (`remetente` e `recebedor`).
fn nb06(b: &mut Bancada) -> Result<String, String> {
    // O DN-2: o remetente de A manda 4 MiB ao recebedor de B, que lê tudo
    // e devolve — cada pedido esperando.
    let desde_b = b.destino().marca()?.log;
    b.destino().lancar("recebedor")?;
    b.destino()
        .esperar_dito(desde_b, &["recebedor: endpoint "], ESPERA_PELO_PRONTO)?;
    let desde_a = b.origem().marca()?.log;
    b.origem().lancar("remetente")?;
    b.origem()
        .esperar_dito(desde_a, &["remetente: fim "], ESPERA_PELA_TROCA)?;
    let r = Dito::de(b.origem(), desde_a, "remetente: ");
    let bloq = match (r.hora("abri "), r.hora("voltou ")) {
        (Some(a), Some(z)) if z >= a => z - a,
        _ => 0,
    };
    b.medidas.push(format!(
        "4 MiB ida e volta no estilo do DN-2 (remetente e recebedor): {bloq} ms ({})",
        vazao(2 * NB01_BYTES, bloq)
    ));
    let mut avisos = Vec::new();
    for quem in [&mut b.par.origem, &mut b.par.destino] {
        let [publicados, juntados, n, media, maior] = medidas_do_aviso(quem)?;
        if publicados == 0 || n == 0 {
            return Err(format!(
                "{}: nenhum aviso medido depois dos passos com o laco",
                quem.papel
            ));
        }
        avisos.push(format!(
            "{}: {publicados} avisos, {juntados} juntados, do aviso a operacao {} us em media e {} us o maior ({n} medidas)",
            quem.papel,
            media / 1000,
            maior / 1000
        ));
    }
    b.medidas.extend(avisos.iter().cloned());
    Ok(format!("NB06: {}", b.medidas.join("; ")))
}

/// A árvore semântica de `quem` mostra `valor` em algum elemento.
fn arvore_mostra(quem: &mut DePe, valor: &str) -> Result<bool, String> {
    let arvore = quem.m.pedir("ui.tree", "{}")?;
    Ok(arvore.contains(&format!(r#""value":"{valor}""#)))
}

/// Espera a árvore de `quem` mostrar `valor`.
fn esperar_na_arvore(quem: &mut DePe, valor: &str) -> Result<(), String> {
    let limite = Instant::now() + Duration::from_secs(120);
    while Instant::now() < limite {
        if arvore_mostra(quem, valor)? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(700));
    }
    Err(format!(
        "{}: a arvore semantica nao mostrou `{valor}`",
        quem.papel
    ))
}

/// NB03: a conversa nas duas máquinas, a pessoa digitando nas duas. A
/// tecla numa janela que não é de Terminal é de quem está entrado no
/// console físico: a pessoa entra nele primeiro, nas duas, e lança a
/// conversa de lá.
fn nb03(b: &mut Bancada, maquinas: (&Maquina, &Maquina)) -> Result<String, String> {
    b.par.origem.entrar_no_fisico(maquinas.0)?;
    b.par.destino.entrar_no_fisico(maquinas.1)?;
    gravar_texto(b.origem(), PAR_DA_CONVERSA, enlace::DISPOSITIVO)?;
    let desde_b = b.destino().marca()?.log;
    b.destino().lancar("conversa")?;
    b.destino()
        .esperar_dito(desde_b, &["conversa: pronta "], ESPERA_PELO_PRONTO)?;
    let desde_a = b.origem().marca()?.log;
    b.origem().lancar("conversa")?;
    b.origem()
        .esperar_dito(desde_a, &["conversa: pronta "], ESPERA_PELO_PRONTO)?;
    // A janela nova tem o foco: o que a pessoa digita vai ao campo dela,
    // conferido na árvore antes do Enter — ver `digitacao`.
    b.origem().no_campo(CAMPO_DA_CONVERSA, "ola de a")?;
    b.origem()
        .esperar_dito(desde_a, &["conversa: mandei ola de a"], ESPERA_PELO_PRONTO)?;
    b.destino()
        .esperar_dito(desde_b, &["conversa: recebi ola de a"], ESPERA_PELA_TROCA)?;
    esperar_na_arvore(b.destino(), "< ola de a")?;
    esperar_na_arvore(b.origem(), "> ola de a")?;
    // E de volta, pelo mesmo fluxo, enquanto ele corre.
    b.destino().no_campo(CAMPO_DA_CONVERSA, "oi de b")?;
    b.origem()
        .esperar_dito(desde_a, &["conversa: recebi oi de b"], ESPERA_PELA_TROCA)?;
    esperar_na_arvore(b.origem(), "< oi de b")?;
    let de = b
        .destino()
        .ditas_com_hora(desde_b, "conversa: aceitei de ")
        .into_iter()
        .map(|(_, d)| d)
        .next()
        .unwrap_or_default();
    if !de.starts_with(enlace::DISPOSITIVO) {
        return Err(format!("a conversa de B nao disse o outro Duke: `{de}`"));
    }
    // As janelas saem; o que se digita depois vai ao console físico, onde
    // a pessoa está entrada.
    for quem in [&mut b.par.origem, &mut b.par.destino] {
        encerrar(quem, &["conversa"])?;
    }
    Ok(format!(
        "NB03: a pessoa digitou nas duas conversas pelo teclado; cada linha chegou a outra pelo fluxo, lida pela arvore semantica; a de B aceitou de {de}"
    ))
}

/// NB04: a revogação em B no meio de um fluxo do modelo.
fn nb04(b: &mut Bancada) -> Result<String, String> {
    sem_pedido(b.destino())?;
    let (desde_b, _) = modelo_pronto(b.destino())?;
    let desde_a = cliente(b.origem(), enlace::DISPOSITIVO, NB01_BYTES, "modelo")?;
    b.origem()
        .esperar_dito(desde_a, &["modelo: perguntei "], ESPERA_PELO_PRONTO)?;
    // Algum dado já passou: o servidor aceitou.
    b.destino()
        .esperar_dito(desde_b, &["modelo: aceitei "], ESPERA_PELO_PRONTO)?;
    b.destino().executar(
        "device.revoke",
        &format!(r#"{{"name":"{}"}}"#, enlace::NOME),
    )?;
    let (i, fim_a) = b.origem().esperar_dito(
        desde_a,
        &["modelo: a pergunta acabou: ", "modelo: eco "],
        ESPERA_PELA_TROCA,
    )?;
    if i != 0 {
        return Err(format!("o cliente nao ouviu o fim pela revogacao: {fim_a}"));
    }
    let numero = Dito::de(b.destino(), desde_b, "modelo: aceitei ")
        .dito("")
        .and_then(|l| l.split(' ').next().map(String::from))
        .unwrap_or_default();
    let (_, fim_b) = b.destino().esperar_dito(
        desde_b,
        &[&format!("modelo: {numero} acabou: ")],
        ESPERA_PELA_TROCA,
    )?;
    encerrar(b.destino(), &["modelo"])?;
    let codigo = saida(b.origem(), desde_a, Duration::from_secs(30))?;
    if codigo == MODELO_CONFERIU || codigo == MODELO_ENCERRADO {
        return Err(format!("o cliente saiu com {codigo} depois da revogacao"));
    }
    Ok(format!(
        "NB04: revogado em B no meio de 4 MiB: A ouviu `{}`, B ouviu `{}`",
        fim_a.trim(),
        fim_b.trim()
    ))
}

// ---------------------------------------------------------------------------
// Um par
// ---------------------------------------------------------------------------

fn passos(
    b: &mut Bancada,
    maquinas: (&Maquina, &Maquina),
    archs: (Arquitetura, Arquitetura),
    nome: &str,
) -> Result<(), String> {
    let feito = |f: String| println!("  [sdk] ok  {nome}: {f}");
    armazem_compartilhado(b.origem())?;
    armazem_compartilhado(b.destino())?;
    let bytes_a = instalar_o_modelo(maquinas.0, b.origem(), archs.0)?;
    let bytes_b = instalar_o_modelo(maquinas.1, b.destino(), archs.1)?;
    feito(format!(
        "o modelo selado pela bancada no armazem das duas, por um agente, em pedacos: {bytes_a} e {bytes_b} bytes"
    ));
    let (da_origem, da_destino) = (b.par.da_origem, b.par.da_destino);
    let (pessoa, relacao) = (b.par.pessoa.clone(), b.par.relacao.clone());
    enlace::registrar(b.destino(), &da_origem, &pessoa, &relacao, None)?;
    enlace::registrar(
        b.origem(),
        &da_destino,
        &pessoa,
        &relacao,
        Some(enlace::ENDERECO),
    )?;
    b.par.destino_escuta(true)?;
    b.origem().entrar()?;
    b.destino().entrar()?;
    feito(format!(
        "a relacao {} registrada com prova nos dois; a pessoa no Terminal das duas",
        &relacao[..8]
    ));
    feito(nb05(b)?);
    feito(nb01(b)?);
    feito(nb02(b)?);
    feito(nb06(b)?);
    feito(nb03(b, maquinas)?);
    feito(nb04(b)?);
    Ok(())
}

fn um_par(
    origem: Arquitetura,
    destino: Arquitetura,
    release: bool,
    nome: &str,
) -> Result<(), String> {
    let porta = enlace::porta_livre()?;
    let ponte = super::raiz_do_projeto().join(super::canal_tcp::PONTE);
    let ponte = ponte.display().to_string();
    if ponte.contains([',', ' ']) {
        return Err(format!(
            "o caminho da ponte nao cabe na opcao do emulador: {ponte}"
        ));
    }
    let a = Maquina::nova(
        BANCADA,
        "origem",
        origem,
        release,
        super::aleatorios()?,
        format!(
            "guestfwd=tcp:10.0.2.100:{}-cmd:python3 {ponte} {porta}",
            enlace::PORTA_DO_ENLACE
        ),
    )?;
    let b = Maquina::nova(
        BANCADA,
        "destino",
        destino,
        release,
        super::aleatorios()?,
        format!("hostfwd=tcp:127.0.0.1:{porta}-:{}", enlace::PORTA_DO_ENLACE),
    )?;
    // O modelo das duas arquiteturas, compilado fora do workspace e selado,
    // onde a bancada da suíte o serve — depois dos discos, que compilam os
    // programas publicados com os outros.
    for arch in [origem, destino] {
        super::codigo::publicar(arch)?;
    }
    let (id, _, _) = chaves::Chaves::garantir()?.pessoa_dev();
    let mut relacao = [0u8; 16];
    relacao.copy_from_slice(&super::aleatorios()?[..16]);
    let mut bancada = Bancada {
        par: Par {
            da_origem: a.publica(),
            da_destino: b.publica(),
            relacao: sigilo::hex_de(&relacao),
            pessoa: sigilo::pessoas::IdPessoa(id).texto(),
            atestado: enlace::atestado_do_carteiro(origem)?,
            ultimo: None,
            medidas: Vec::new(),
            origem: a.ligar()?,
            destino: b.ligar()?,
        },
        medidas: Vec::new(),
    };
    let r = passos(&mut bancada, (&a, &b), (origem, destino), nome);
    if r.is_err() {
        bancada.par.origem.mostrar();
        bancada.par.destino.mostrar();
    }
    println!("  [sdk]   {}", enlace::o_teclado(&a, &b));
    let Bancada { par, .. } = bancada;
    let _ = par.origem.m.cortar_a_energia();
    let _ = par.destino.m.cortar_a_energia();
    r
}

/// `cargo xtask sdk`: os pares escolhidos, um de cada vez.
pub(crate) fn sdk(release: bool) -> Result<ExitCode, String> {
    let filtro = std::env::var("DUKE_PARES").ok();
    let nome = |(o, d): &(Arquitetura, Arquitetura)| format!("{}>{}", o.nome(), d.nome());
    let escolhidos: Vec<(Arquitetura, Arquitetura)> = PARES
        .iter()
        .filter(|par| {
            filtro
                .as_deref()
                .is_none_or(|f| f.split('|').any(|p| p.trim() == nome(par)))
        })
        .copied()
        .collect();
    if escolhidos.is_empty() {
        return Err(format!(
            "DUKE_PARES nao escolhe par nenhum; os pares: {}",
            PARES.iter().map(nome).collect::<Vec<_>>().join("|")
        ));
    }
    println!(
        "[xtask] sdk: {} pares, duas maquinas de pe em cada",
        escolhidos.len()
    );
    let mut falhas = 0;
    for par in &escolhidos {
        let (origem, destino) = *par;
        println!("[xtask] sdk: {}", nome(par));
        let comeco = Instant::now();
        match um_par(origem, destino, release, &nome(par)) {
            Ok(()) => println!(
                "  [sdk] ok  {}: o par inteiro em {} s",
                nome(par),
                comeco.elapsed().as_secs()
            ),
            Err(motivo) => {
                falhas += 1;
                println!("  [sdk] FALHOU  {}: {motivo}", nome(par));
            }
        }
    }
    let base = super::raiz_do_projeto().join("target").join(BANCADA);
    for papel in ["origem", "destino"] {
        let _ = std::fs::remove_file(base.join(format!("{papel}.img")));
    }
    if falhas > 0 {
        println!("\n[xtask] sdk: {falhas} par(es) falharam");
        return Ok(ExitCode::FAILURE);
    }
    println!("\n[xtask] sdk: todos os pares passaram");
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod testes {
    use super::*;

    /// O resumo da bancada é o do modelo e do `avisado`: o FNV-1a do padrão
    /// de semente zero.
    #[test]
    fn o_resumo_do_padrao() {
        assert_eq!(resumo_do_padrao(0), "cbf29ce484222325");
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in [3u8, 10, 17] {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        assert_eq!(resumo_do_padrao(3), format!("{h:016x}"));
        assert_eq!(vazao(1024, 1000), "1 KiB/s");
        assert_eq!(vazao(1, 0), "-");
    }
}
