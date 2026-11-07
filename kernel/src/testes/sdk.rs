//! Os casos do SDK da malha (DN-3): os exemplos rodando — o servidor de
//! vários clientes e a janela com o fluxo, cada um num laço só —, o
//! programa feito fora do repositório, selado, instalado e rodado, o
//! contrato v2 como um agente o lê, e as medidas do laço.
//!
//! Nenhum caso aqui prova autoridade nova: o SDK não tem nenhuma. O que
//! eles conferem é que um programa escrito só com o runtime público — o
//! laço, os fluxos, as mensagens — anda pelos avisos, pedindo cada passo ao
//! gate, e que o que o contrato diz é o que o kernel faz.

use super::aviso::{
    ABRIR, Avisado, DUPLEX, ESCREVER, FECHAR, MANDAR_BLOQ, MANDAR_LACO, RECEBER_BLOQ, RECEBER_LACO,
    aberto_pelos_programas_em, com_os_avisos, encerrar_todos, numero, padrao, pessoa,
};
use super::{
    CODIGO_INSTALADO, DO_MODELO, Instalador, NaMalha, PUBLICADOS, Resultado, TETO_DA_MALHA, chamar,
    com_a_bancada_http, decisoes_do_processo, diretorios_acima, ditas_na_malha, dito_na_malha,
    encerrar_na_malha, esperar_ate, fs_no_armazem, fs_ok, fs_pedir, registro_que,
    versao_no_armazem,
};
use crate::agent::json::Json;
use crate::autorizacao::{Autoridade, Chamador};
use crate::pessoas::Console;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use politica::Codigo;
use protocolo::usuario::evento::malha;

/// O código com que o `eco-malha` sai no fim pedido.
const SAIDA_DO_ECO: i64 = 47;

/// O código com que a `conversa` sai no fim pedido.
const SAIDA_DA_CONVERSA: i64 = 59;

/// Os códigos do modelo do SDK: o fim pedido, e o do cliente com o eco
/// conferido — ver `sdk/modelo/src/main.rs`.
const SAIDA_DO_MODELO: i64 = 57;
const SAIDA_DO_ECO_DO_MODELO: i64 = 58;

/// Quantos bytes o cliente do modelo manda.
const TAMANHO_DO_MODELO: usize = 40 * 1024;

/// O pedido do cliente do modelo, e o diretório dele.
const PAR_DO_MODELO: &str = "/armazem/compartilhado/modelo/par";
const DIRETORIO_DO_MODELO: &str = "/armazem/compartilhado/modelo";

// ---------------------------------------------------------------------------
// NS26 — o eco-malha com três clientes
// ---------------------------------------------------------------------------

/// O `eco-malha` — um processo, uma espera só, no laço — serve três
/// clientes ao mesmo tempo. Cada cliente abre um fluxo contra o endpoint
/// dele, com o aviso; o eco aceita cada um pelo aviso do pedido; e os três
/// mandam e leem o eco ao mesmo tempo, guiados só pelos avisos, nos dois
/// sentidos. Todos os bytes voltam, na ordem; cada aceite foi um pedido do
/// processo do eco, decidido pelo gate.
pub(super) fn sdk_o_eco_serve_tres_clientes() -> Resultado {
    const N: usize = 48 * 1024;
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 440);
        let (eco, pronto) = NaMalha::lancar("eco-malha", bia, "eco-malha: pronto ")?;
        let (endpoint, canal) = pronto
            .split_once(' ')
            .ok_or("o eco-malha nao disse o canal")?;
        let canal = String::from(canal);
        let r = (|| -> Resultado {
            let do_eco = politica::aviso::numero_do_id(endpoint)
                .ok_or("o endpoint do eco-malha nao tem numero")?;
            let clientes = [
                Avisado::lancar(bia)?,
                Avisado::lancar(bia)?,
                Avisado::lancar(bia)?,
            ];
            let r = (|| -> Resultado {
                let desde_do_eco = crate::log::total_emitidos();
                let mut fluxos = Vec::new();
                for c in &clientes {
                    let desde = c.ditar(ABRIR, 1, do_eco as i64)?;
                    let n = numero(&c.dito(desde, "abri ")?)?;
                    // O eco aceita pelo aviso do pedido; a abertura chega
                    // ao cliente como `GRAVAVEL`.
                    c.esperar_aviso(desde, "fluxo", n, malha::GRAVAVEL)?;
                    fluxos.push(n);
                }
                // O aviso da abertura sai no aceite, antes de o eco dizer
                // que aceitou: a linha dele pode vir depois.
                let aceitou_todos = || {
                    let aceitos = ditas_na_malha(desde_do_eco, "eco-malha: aceitei ");
                    fluxos.iter().all(|n| {
                        aceitos
                            .iter()
                            .any(|l| l.starts_with(&format!("{n} de avisado ")))
                    })
                };
                if esperar_ate(aceitou_todos, TETO_DA_MALHA).is_err() {
                    crate::log_error!(
                        "teste",
                        "aceitos {:?}, fluxos {:?}",
                        ditas_na_malha(desde_do_eco, "eco-malha: aceitei "),
                        fluxos
                    );
                    return Err("o eco-malha nao disse quem aceitou");
                }
                // Os três ao mesmo tempo, nos dois sentidos.
                let desde = crate::log::total_emitidos();
                for (c, n) in clientes.iter().zip(&fluxos) {
                    c.ditar(DUPLEX, *n as i64, N as i64)?;
                }
                let resumo = super::fluxo::resumo((0..N).map(padrao));
                for (c, n) in clientes.iter().zip(&fluxos) {
                    let d = c.dito(desde, "duplex ")?;
                    if !d.starts_with(&format!("{n} {N} {resumo:016x} ")) {
                        crate::log_error!("teste", "{}: {}", c.fio(), d);
                        return Err("um cliente do eco-malha nao recebeu o eco inteiro");
                    }
                }
                for n in &fluxos {
                    let ecoado = dito_na_malha(desde, &format!("eco-malha: ecoei {n} "))?;
                    if ecoado != format!("{N}") {
                        crate::log_error!("teste", "ecoei {}: {}", n, ecoado);
                        return Err("o eco-malha nao ecoou tudo de um cliente");
                    }
                }
                // Um processo só, e cada aceite foi um pedido dele.
                let aceites = decisoes_do_processo(eco.fio, "stream.accept", "");
                if aceites
                    .iter()
                    .filter(|(_, c, _)| *c == Codigo::Allow)
                    .count()
                    < fluxos.len()
                {
                    crate::log_error!("teste", "{:?}", aceites);
                    return Err("os aceites do eco-malha nao passaram pelo gate");
                }
                Ok(())
            })();
            let refs: Vec<&Avisado> = clientes.iter().collect();
            encerrar_todos(r, &refs)
        })();
        let fim = encerrar_na_malha(&canal, SAIDA_DO_ECO);
        r.and(fim)
    })
}

// ---------------------------------------------------------------------------
// NS27 — a conversa: a janela e o fluxo no mesmo laço
// ---------------------------------------------------------------------------

/// A camada da janela da conversa — uma que não seja `outra` —, quando ela
/// aparece na árvore.
fn janela_da_conversa(outra: Option<u32>) -> Result<u32, &'static str> {
    let mut achada = None;
    let _ = esperar_ate(
        || {
            crate::grafico::camadas(|c| {
                if achada.is_none()
                    && Some(c.id) != outra
                    && c.nome == crate::superficies::NOME_DA_CAMADA
                    && crate::superficies::com_descricao(c.id, |d| d.titulo == "Conversa")
                        == Some(true)
                {
                    achada = Some(c.id);
                }
            });
            achada.is_some()
        },
        600,
    );
    achada.ok_or("a janela da conversa nao apareceu na arvore")
}

/// O identificador do elemento `rotulo` da janela `camada`.
fn elemento(camada: u32, rotulo: &str) -> Result<u32, &'static str> {
    let indice = crate::superficies::com_descricao(camada, |d| {
        d.elementos.iter().position(|e| e.rotulo == rotulo)
    })
    .flatten()
    .ok_or("a conversa nao descreveu um elemento")?;
    crate::ui::id_do_elemento(camada, indice).ok_or("sem identificador")
}

/// O que a janela `camada` mostra no elemento `rotulo`.
fn valor_de(camada: u32, rotulo: &str) -> Option<String> {
    crate::superficies::com_descricao(camada, |d| {
        d.elementos
            .iter()
            .find(|e| e.rotulo == rotulo)
            .and_then(|e| e.valor.clone())
    })
    .flatten()
}

/// Se alguma linha da janela `camada` mostra `texto`.
fn mostra(camada: u32, texto: &str) -> bool {
    (0..6).any(|i| valor_de(camada, &format!("linha {i}")).as_deref() == Some(texto))
}

/// Digita `texto` no campo da janela `camada` e confirma — pela árvore,
/// como um agente, que é como a suíte injeta a entrada.
fn digitar(camada: u32, texto: &str) -> Resultado {
    use crate::ui::{Acao, Origem};
    let campo = elemento(camada, "mensagem")?;
    crate::ui::agir(campo, Acao::DefinirValor, Some(texto), Origem::Agente(0))?;
    esperar_ate(
        || valor_de(camada, "mensagem").as_deref() == Some(texto),
        600,
    )
    .map_err(|_| "o texto nao chegou ao campo da conversa")?;
    crate::ui::agir(campo, Acao::Confirmar, None, Origem::Agente(0))?;
    Ok(())
}

/// A `conversa`: duas janelas da mesma Pessoa neste Duke. A entrada de
/// cada janela — o texto e o Enter, injetados pela árvore — e os avisos do
/// fluxo e do endpoint chegam no mesmo canal: a primeira mensagem acha a
/// outra conversa, abre o fluxo e espera a abertura; a outra aceita pelo
/// aviso do pedido, mostra o que chegou, e responde pelo mesmo fluxo.
pub(super) fn sdk_a_conversa_janela_e_fluxo_no_mesmo_laco() -> Resultado {
    if crate::tela::tela_fisica().is_none() {
        return super::sem_framebuffer();
    }
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 441);
        let (a, pronta_a) = NaMalha::lancar("conversa", bia, "conversa: pronta ")?;
        let canal_a = String::from(pronta_a.split_once(' ').map_or("", |(_, c)| c));
        let r = (|| -> Resultado {
            let janela_a = janela_da_conversa(None)?;
            let (b, pronta_b) = NaMalha::lancar("conversa", bia, "conversa: pronta ")?;
            let canal_b = String::from(pronta_b.split_once(' ').map_or("", |(_, c)| c));
            let r = (|| -> Resultado {
                let janela_b = janela_da_conversa(Some(janela_a))?;
                let desde = crate::log::total_emitidos();
                digitar(janela_a, "ola de a")?;
                dito_na_malha(desde, "conversa: abri ")?;
                dito_na_malha(desde, "conversa: mandei ola de a")?;
                let de = dito_na_malha(desde, "conversa: aceitei de ")?;
                if !de.starts_with("conversa ") {
                    crate::log_error!("teste", "aceitei de {}", de);
                    return Err("a conversa nao disse que o fluxo veio da outra conversa");
                }
                dito_na_malha(desde, "conversa: recebi ola de a")?;
                esperar_ate(|| mostra(janela_b, "< ola de a"), 600)
                    .map_err(|_| "a janela da outra conversa nao mostrou a mensagem")?;
                if !mostra(janela_a, "> ola de a") {
                    return Err("a janela de quem mandou nao mostrou a mensagem");
                }
                // A resposta, pelo mesmo fluxo, no outro sentido.
                let desde = crate::log::total_emitidos();
                digitar(janela_b, "oi de b")?;
                dito_na_malha(desde, "conversa: mandei oi de b")?;
                dito_na_malha(desde, "conversa: recebi oi de b")?;
                esperar_ate(|| mostra(janela_a, "< oi de b"), 600)
                    .map_err(|_| "a resposta nao apareceu na janela de quem perguntou")?;
                if ditas_na_malha(desde, "conversa: abri ").len()
                    + ditas_na_malha(desde, "conversa: o fluxo acabou").len()
                    != 0
                {
                    return Err("a resposta abriu outro fluxo, ou o primeiro acabou");
                }
                // Cada uma escreveu e leu pelo gate.
                for (p, metodo) in [(a.fio, "stream.write"), (b.fio, "stream.read")] {
                    let d = decisoes_do_processo(p, metodo, "");
                    if !d.iter().any(|(_, c, _)| *c == Codigo::Allow) {
                        return Err("a conversa nao pediu o fluxo ao gate");
                    }
                }
                Ok(())
            })();
            let fim = encerrar_na_malha(&canal_b, SAIDA_DA_CONVERSA);
            r.and(fim)
        })();
        let fim = encerrar_na_malha(&canal_a, SAIDA_DA_CONVERSA);
        r.and(fim)
    })
}

// ---------------------------------------------------------------------------
// NS28 — o programa feito fora do repositório
// ---------------------------------------------------------------------------

/// A posição do arquivo `i` do modelo na lista do instalador.
fn do_modelo(i: usize) -> usize {
    PUBLICADOS.len() + i
}

/// Grava o pedido do cliente do modelo, vazio — o outro modelo está neste
/// Duke —, como a pessoa.
fn gravar_o_par(pessoa: Chamador) -> Resultado {
    let r = fs_pedir(
        pessoa,
        "fs.mkdir",
        r#"{"path":"/armazem/compartilhado/modelo"}"#,
    );
    if !fs_ok(&r) && !r.contains("ja ha algo nesse caminho") {
        crate::log_error!("teste", "{}", r);
        return Err("o diretorio do modelo nao foi criado");
    }
    let (versao, _) = fs_no_armazem(PAR_DO_MODELO);
    let r = fs_pedir(
        pessoa,
        "fs.write",
        &format!(r#"{{"path":"{PAR_DO_MODELO}","content":"","expect_version":{versao}}}"#),
    );
    if !fs_ok(&r) {
        crate::log_error!("teste", "{}", r);
        return Err("o pedido do cliente do modelo nao foi gravado");
    }
    Ok(())
}

/// Apaga o pedido do cliente do modelo.
fn apagar_o_par(pessoa: Chamador) {
    let (versao, _) = fs_no_armazem(PAR_DO_MODELO);
    let _ = fs_pedir(
        pessoa,
        "fs.delete",
        &format!(r#"{{"path":"{PAR_DO_MODELO}","expect_version":{versao}}}"#),
    );
}

/// Apaga o que o caso instalou — os arquivos do modelo e o diretório do
/// pedido —, como a pessoa: o armazém volta a ser o de antes. A cópia do
/// armazém inteiro, perto do fim da suíte, leva cada byte dele ao heap do
/// kernel.
fn apagar_o_instalado(pessoa: Chamador) -> Resultado {
    let caminhos = DO_MODELO
        .iter()
        .map(|nome| ("fs.delete", format!("{CODIGO_INSTALADO}/{nome}")))
        .chain([("fs.rmdir", String::from(DIRETORIO_DO_MODELO))]);
    for (metodo, caminho) in caminhos {
        let versao = versao_no_armazem(&caminho);
        if versao == 0 {
            continue;
        }
        let r = fs_pedir(
            pessoa,
            metodo,
            &format!(r#"{{"path":"{caminho}","expect_version":{versao}}}"#),
        );
        if !fs_ok(&r) {
            crate::log_error!("teste", "{}", r);
            return Err("o que o caso instalou nao foi apagado");
        }
    }
    Ok(())
}

/// O programa feito fora do repositório — o `sdk/modelo`, copiado para
/// fora do workspace, compilado contra o `programas`, selado pelo editor
/// `bancada` e servido pela bancada — chega ao Duke como qualquer código de
/// fora: o instalador o baixa e o grava no armazém, pelo gate. Roda pela
/// mesma conferência de sempre:
///
/// - o selado roda, pelo `user.run` da pessoa: oferece a intenção com o
///   aviso e serve pelo laço;
/// - uma segunda cópia, com o pedido do cliente no armazém, roda pelo
///   instalador: acha a primeira, abre um fluxo com o aviso, manda 40 KiB,
///   lê o eco até o fim e o confere — os dois andando só pelos avisos;
/// - as variantes sem selo, adulterada, de editor estranho e de editor em
///   quem o papel não confia são recusadas na troca de imagem, como as do
///   `vindo`;
/// - os pedidos dele dizem de onde ele veio: o editor `bancada`.
pub(super) fn sdk_o_programa_de_fora_do_repositorio() -> Resultado {
    o_programa_de_fora(false)
}

/// NS55 — o mesmo caso, com a corrida das CIs 445 e 447 aberta de propósito: o
/// coletor segurado do cliente do modelo até a última variante. O
/// instalador colhe o cliente e bifurca a variante seguinte antes da
/// passada do coletor — com as vagas vazias abaixo da do cliente tampadas,
/// para a variante cair nela se ela pudesse ser escolhida. Ela não pode: o
/// cliente colhido guarda a vaga, e a morte dele, até o coletor passar;
/// solto, a morte é solta uma vez, e nenhuma designação sobra.
pub(super) fn sdk_o_programa_de_fora_do_repositorio_com_o_coletor_segurado() -> Resultado {
    o_programa_de_fora(true)
}

/// O caso do programa de fora do repositório, com ou sem o coletor
/// segurado durante o cliente e as variantes.
fn o_programa_de_fora(segurar: bool) -> Resultado {
    use protocolo::usuario::erro;
    com_a_bancada_http(|| {
        com_os_avisos(|| {
            let sessao =
                crate::pessoas::sessao_de_teste(Console::Terminal(83), "sdk-fora", "operador");
            let pessoa = Chamador::Pessoa(sessao);
            let instalador = Instalador::lancar(Autoridade::Pessoa { sessao })?;
            let mut canal_do_servidor = None;
            let r = (|| -> Resultado {
                for i in 0..DO_MODELO.len() {
                    instalador.baixar(do_modelo(i))?;
                }
                // O servidor: o selado, pelo `user.run` da pessoa.
                let desde = crate::log::total_emitidos();
                let r = fs_pedir(
                    pessoa,
                    "user.run",
                    &format!(r#"{{"path":"{CODIGO_INSTALADO}/modelo"}}"#),
                );
                if !r.contains(r#""launched":true"#) {
                    crate::log_error!("teste", "{}", r);
                    return Err("o user.run nao rodou o modelo selado pela bancada");
                }
                let pronto = dito_na_malha(desde, "modelo: pronto ")?;
                let (_, canal) = pronto.split_once(' ').ok_or("o modelo nao disse o canal")?;
                canal_do_servidor = Some(String::from(canal));

                // O cliente: a mesma imagem, com o pedido no armazém.
                gravar_o_par(pessoa)?;
                let segurado = segurar.then(super::vagas::ColetorSegurado::segurar);
                let desde = crate::log::total_emitidos();
                instalador.rodar(do_modelo(0), SAIDA_DO_ECO_DO_MODELO)?;
                let eco = dito_na_malha(desde, "modelo: eco ")?;
                if !eco.starts_with(&format!("{TAMANHO_DO_MODELO} ")) || !eco.ends_with(" confere")
                {
                    crate::log_error!("teste", "eco {}", eco);
                    return Err("o cliente do modelo nao conferiu o eco");
                }
                let ecoado = dito_na_malha(desde, "modelo: ecoei ")?;
                if !ecoado.ends_with(&format!(" {TAMANHO_DO_MODELO}")) {
                    crate::log_error!("teste", "ecoei {}", ecoado);
                    return Err("o servidor do modelo nao ecoou tudo");
                }

                // Com o coletor segurado, o cliente — colhido pelo instalador
                // — está na tabela, com a morte devida; as vagas vazias de
                // baixo ficam tampadas.
                let mut tampas = super::vagas::Tampas::novas();
                let mut cliente = None;
                if segurado.is_some() {
                    let c = crate::fios::filho_parado_de_teste(instalador.fio)
                        .ok_or("o cliente do modelo nao ficou na tabela")?;
                    let vaga = crate::fios::retrato_de_teste(c)
                        .ok_or("o cliente do modelo sem vaga")?
                        .vaga;
                    crate::fios::vigiar_a_limpeza(c);
                    tampas.tapar_abaixo(vaga)?;
                    cliente = Some((c, vaga));
                }

                // As variantes: recusadas na troca de imagem, como sempre.
                for (i, codigo) in [
                    (1, erro::SEM_SELO),
                    (2, erro::SELO_NAO_CONFERE),
                    (3, erro::EDITOR_NAO_CONFIADO),
                    (4, erro::EDITOR_NAO_CONFIADO),
                ] {
                    instalador.rodar(do_modelo(i), codigo)?;
                }

                if let Some((c, vaga)) = cliente {
                    if crate::fios::retrato_de_teste(c).map(|r| r.vaga) != Some(vaga) {
                        return Err("uma variante ficou com a vaga do cliente antes da limpeza");
                    }
                    if crate::fios::limpezas_vigiadas() != 0 {
                        return Err("a morte do cliente foi solta com o coletor segurado");
                    }
                    drop(segurado);
                    tampas.soltar();
                    super::vagas::recolhido(c)?;
                    if crate::fios::limpezas_vigiadas() != 1 {
                        return Err("a morte do cliente do modelo nao foi solta uma vez");
                    }
                }

                // O que rodou pediu, e cada pedido diz de onde veio.
                for metodo in ["fabric.offer", "stream.open", "stream.accept"] {
                    registro_que(|e| {
                        e.metodo == metodo
                            && e.codigo == Codigo::Allow
                            && e.detalhe.contains("(modelo ")
                            && e.detalhe.contains(" de bancada)")
                    })
                    .ok_or("um pedido do modelo nao diz quem o selou")?;
                }
                Ok(())
            })();
            crate::fios::vigiar_a_limpeza(u64::MAX);
            apagar_o_par(pessoa);
            let fim_do_servidor = match &canal_do_servidor {
                Some(c) => encerrar_na_malha(c, SAIDA_DO_MODELO),
                None => Ok(()),
            };
            let fim = instalador.encerrar();
            let limpo = apagar_o_instalado(pessoa);
            r.and(fim_do_servidor).and(fim).and(limpo)
        })
    })
}

// ---------------------------------------------------------------------------
// NS29 e NS30 — o contrato, como um agente o lê
// ---------------------------------------------------------------------------

/// A lista conferida do contrato público — a mesma que o `cargo xtask
/// invariantes` confere contra as fontes.
const CONTRATO: &str = include_str!("../../../sdk/contrato.txt");

/// O tipo de um parâmetro do contrato, como o `agent.describe` o escreve.
fn tipo_descrito(tipo: &str) -> &'static str {
    match tipo {
        "inteiro" => "integer",
        "texto" | "intencao" => "string",
        "booleano" => "boolean",
        "lista" => "array",
        _ => "?",
    }
}

/// Um parâmetro de um comando do contrato: o nome, o tipo como o
/// `agent.describe` o escreve, e se é obrigatório.
type Parametro = (String, &'static str, bool);

/// Os comandos da malha da lista do contrato, com os parâmetros.
fn comandos_do_contrato() -> Vec<(String, Vec<Parametro>)> {
    let mut v: Vec<(String, Vec<Parametro>)> = Vec::new();
    for linha in CONTRATO.lines() {
        let campos: Vec<&str> = linha.split_whitespace().collect();
        match campos.as_slice() {
            ["comando", nome] => v.push((String::from(*nome), Vec::new())),
            ["param", comando, nome, tipo, obrigatorio] => {
                if let Some((_, ps)) = v.iter_mut().find(|(c, _)| c == comando) {
                    ps.push((
                        String::from(*nome),
                        tipo_descrito(tipo),
                        *obrigatorio == "obrigatorio",
                    ));
                }
            }
            _ => {}
        }
    }
    v
}

/// O `agent.describe` — o que um agente lê para descobrir o canal — diz,
/// de cada comando da malha, exatamente os parâmetros do contrato: os
/// nomes, os tipos e a obrigatoriedade. Nenhum comando `fabric.*` ou
/// `stream.*` fora da lista, e nenhum da lista faltando.
pub(super) fn sdk_o_describe_confere_com_o_contrato() -> Resultado {
    let texto = chamar("agent.describe", "{}")?;
    let descrito = Json(texto.as_bytes());
    let comandos = descrito
        .member("commands")
        .ok_or("o agent.describe nao listou os comandos")?;
    let contrato = comandos_do_contrato();
    if contrato.len() != 15 {
        return Err("a lista do contrato nao tem os quinze comandos da malha");
    }
    let mut vistos = 0;
    let mut i = 0;
    while let Some(c) = comandos.item(i) {
        i += 1;
        let Some(nome) = c.member("name").and_then(|v| v.as_str()) else {
            return Err("um comando descrito sem nome");
        };
        if !nome.starts_with("fabric.") && !nome.starts_with("stream.") {
            continue;
        }
        let Some((_, esperados)) = contrato.iter().find(|(n, _)| n == nome) else {
            crate::log_error!("teste", "{} esta no describe e nao no contrato", nome);
            return Err("um comando da malha descrito fora do contrato");
        };
        vistos += 1;
        let params = c.member("params").ok_or("um comando descrito sem params")?;
        let mut descritos = Vec::new();
        let mut j = 0;
        while let Some(p) = params.item(j) {
            j += 1;
            let nome_p = p.member("name").and_then(|v| v.as_str()).unwrap_or("");
            let tipo = p.member("type").and_then(|v| v.as_str()).unwrap_or("");
            let obrigatorio = p.member("required").and_then(|v| v.as_bool()) == Some(true);
            descritos.push((String::from(nome_p), String::from(tipo), obrigatorio));
        }
        let iguais = descritos.len() == esperados.len()
            && esperados.iter().all(|(n, t, o)| {
                descritos
                    .iter()
                    .any(|(dn, dt, dob)| dn == n && dt == t && dob == o)
            });
        if !iguais {
            crate::log_error!(
                "teste",
                "{}: descrito {:?}, contrato {:?}",
                nome,
                descritos,
                esperados
            );
            return Err("os parametros descritos nao sao os do contrato");
        }
    }
    if vistos != contrato.len() {
        return Err("um comando do contrato nao esta no agent.describe");
    }
    Ok(())
}

/// O `system.info` diz a versão da interface nativa: a 2, a do contrato —
/// e a lista do contrato é da mesma versão.
pub(super) fn sdk_o_system_info_diz_a_interface_2() -> Resultado {
    let info = chamar("system.info", "{}")?;
    let versao = Json(info.as_bytes())
        .member("native_interface")
        .and_then(|v| v.as_u64());
    if versao != Some(2) {
        crate::log_error!("teste", "{}", info);
        return Err("o system.info nao diz native_interface 2");
    }
    if versao != Some(protocolo::usuario::nativo::VERSAO as u64) {
        return Err("o system.info nao diz a versao do protocolo");
    }
    if !CONTRATO.lines().any(|l| l.trim() == "versao 2") {
        return Err("a lista do contrato nao e da versao 2");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// NS31 — as medidas
// ---------------------------------------------------------------------------

/// Espera a linha `prefixo` de `p` e devolve os milissegundos desde
/// `inicio` (em ciclos) até ela.
fn medido(
    p: &Avisado,
    desde: u64,
    prefixo: &str,
    inicio: u64,
) -> Result<(String, u64), &'static str> {
    let dito = p.dito(desde, prefixo)?;
    let ms = crate::metricas::nanos(crate::metricas::desde(inicio)) / 1_000_000;
    Ok((dito, ms.max(1)))
}

/// As medidas do laço, num Duke: a latência do aviso — do aviso publicado
/// à operação do dono que o consome, medida pelo kernel em cada aviso —, e
/// a vazão de 1 MiB num sentido entre dois processos, pelo laço e no estilo
/// bloqueante do DN-2. O caso reprova se algo não chega inteiro, ou se a
/// latência não foi medida; os números vão para o log.
pub(super) fn sdk_as_medidas_do_laco() -> Resultado {
    const N: usize = 1024 * 1024;
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 442);
        let a = Avisado::lancar(bia)?;
        let b = Avisado::lancar(bia)?;
        let r = (|| -> Resultado {
            let resumo = super::fluxo::resumo((0..N).map(padrao));
            crate::metricas::AVISO.zerar();
            // Pelo laço: quem manda escreve o que cabe e dorme no canal;
            // quem lê lê o que há e dorme no canal.
            let n = aberto_pelos_programas_em(&a, &b)?;
            let inicio = crate::arch::ciclos();
            let desde = b.ditar(RECEBER_LACO, n as i64, 0)?;
            a.ditar(MANDAR_LACO, n as i64, N as i64)?;
            let (dito, laco_ms) = medido(&b, desde, "recebi_laco ", inicio)?;
            if dito != format!("{n} {N} {resumo:016x}") {
                crate::log_error!("teste", "recebi_laco {}", dito);
                return Err("o MiB pelo laco nao chegou inteiro");
            }
            a.dito(desde, "mandei_laco ")?;
            let (avisos, media, maior) = crate::metricas::AVISO.ler();

            // No estilo do DN-2, num fluxo novo: cada pedido espera.
            let m = aberto_pelos_programas_em(&a, &b)?;
            let inicio = crate::arch::ciclos();
            let desde = b.ditar(RECEBER_BLOQ, m as i64, 0)?;
            a.ditar(MANDAR_BLOQ, m as i64, N as i64)?;
            let (dito, bloq_ms) = medido(&b, desde, "recebi_bloq ", inicio)?;
            if dito != format!("{m} {N} {resumo:016x}") {
                crate::log_error!("teste", "recebi_bloq {}", dito);
                return Err("o MiB bloqueante nao chegou inteiro");
            }
            a.dito(desde, "mandei_bloq ")?;

            if avisos == 0 {
                return Err("a latencia do aviso nao foi medida");
            }
            crate::log_info!(
                "teste",
                "o aviso ate a operacao: {} avisos, {} us em media, {} us o maior",
                avisos,
                crate::metricas::nanos(media) / 1000,
                crate::metricas::nanos(maior) / 1000
            );
            crate::log_info!(
                "teste",
                "1 MiB num sentido: pelo laco {} ms ({} KiB/s), bloqueante {} ms ({} KiB/s)",
                laco_ms,
                1024 * 1000 / laco_ms,
                bloq_ms,
                1024 * 1000 / bloq_ms
            );
            Ok(())
        })();
        encerrar_todos(r, &[&a, &b])
    })
}

// ---------------------------------------------------------------------------
// NS37 — o laço sobe com o nome tomado
// ---------------------------------------------------------------------------

/// O nome do canal do laço é previsível — `laco-<id>` —, e outro processo
/// pode tomá-lo antes: o laço tenta os seguintes, e o programa sobe. A
/// suíte toma os nomes dos próximos ids antes de lançar o `eco-malha`, que
/// sobe com o primeiro nome livre dele. Oito nomes de um fio só passam do
/// teto da chamada: a suíte os toma sem ele.
pub(super) fn sdk_o_laco_sobe_com_o_nome_tomado() -> Resultado {
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 441);
        let eu = crate::fios::id_atual();
        let primeiro = crate::fios::proximo_id_de_teste();
        let tomados: Vec<crate::eventos::Chave> = (primeiro..primeiro + 8)
            .filter_map(|id| {
                crate::eventos::escutar_sem_teto(format!("laco-{id}").as_bytes(), eu).ok()
            })
            .collect();
        let r = (|| -> Resultado {
            if tomados.len() != 8 {
                return Err("os nomes dos proximos lacos nao foram tomados");
            }
            let (eco, pronto) = NaMalha::lancar("eco-malha", bia, "eco-malha: pronto ")?;
            let (_, canal) = pronto
                .split_once(' ')
                .ok_or("o eco-malha nao disse o canal")?;
            let r = if canal == format!("laco-{}-1", eco.fio) {
                Ok(())
            } else {
                crate::log_error!("teste", "{} {}", eco.fio, canal);
                Err("o eco-malha nao subiu com o nome seguinte ao tomado")
            };
            let fim = encerrar_na_malha(canal, SAIDA_DO_ECO);
            r.and(fim)
        })();
        for chave in tomados {
            crate::eventos::largar(chave, eu);
        }
        r
    })
}

// ---------------------------------------------------------------------------
// NS44 — o eco-malha fecha o fluxo que o cliente largou
// ---------------------------------------------------------------------------

/// Um cliente enche o sentido de volta sem ler o eco, manda mais e fecha:
/// o `eco-malha`, que escoa o que deve antes de ler, ouve que o sentido
/// dele acabou — e fecha o fluxo antes de largar o cliente. O fluxo sai da
/// tabela na hora, e a vaga da cota do eco volta; sem o fecho, ele ficaria
/// vivo, contado na cota, até vencer a inatividade.
pub(super) fn sdk_o_eco_fecha_o_fluxo_largado() -> Resultado {
    const BUFFER: i64 = politica::fluxo::BUFFER_DO_SENTIDO as i64;
    com_os_avisos(|| {
        let (_, bia) = pessoa("bia", 4440);
        let (eco, pronto) = NaMalha::lancar("eco-malha", bia, "eco-malha: pronto ")?;
        let (endpoint, canal) = pronto
            .split_once(' ')
            .ok_or("o eco-malha nao disse o canal")?;
        let canal = String::from(canal);
        let r = (|| -> Resultado {
            let do_eco = politica::aviso::numero_do_id(endpoint)
                .ok_or("o endpoint do eco-malha nao tem numero")?;
            let c = Avisado::lancar(bia)?;
            let r = (|| -> Resultado {
                let desde = c.ditar(ABRIR, 1, do_eco as i64)?;
                let n = numero(&c.dito(desde, "abri ")?)?;
                c.esperar_aviso(desde, "fluxo", n, malha::GRAVAVEL)?;
                // Três buffers, sem ler o eco: o de volta enche, o eco
                // guarda o que não coube e para de ler, e o terceiro fica
                // no sentido de ida, sem ser lido.
                for _ in 0..3 {
                    let desde = c.ditar(ESCREVER, n as i64, BUFFER)?;
                    c.dito(desde, "escrevi ")?;
                    let _ = esperar_ate(|| false, 30);
                }
                if crate::fluxo::contagem().0 != 1 {
                    crate::log_error!("teste", "{:?}", crate::fluxo::contagem());
                    return Err("o fluxo do cliente nao estava vivo antes do fecho");
                }
                let desde = c.ditar(FECHAR, n as i64, 0)?;
                c.dito(desde, "fechei ")?;
                // O eco ouve que o sentido dele acabou, e fecha.
                if esperar_ate(|| crate::fluxo::contagem().0 == 0, TETO_DA_MALHA).is_err() {
                    crate::log_error!("teste", "{:?}", crate::fluxo::contagem());
                    return Err("o eco-malha largou o cliente sem fechar o fluxo");
                }
                Ok(())
            })();
            encerrar_todos(r, &[&c])
        })();
        let _ = eco;
        let fim = encerrar_na_malha(&canal, SAIDA_DO_ECO);
        r.and(fim)
    })
}

// ---------------------------------------------------------------------------
// NS47 — o copiador fecha o fluxo de cada cópia
// ---------------------------------------------------------------------------

/// Uma cópia entre dois copiadores deste Duke: o que recebe sobe primeiro;
/// o que manda acha o pedido de envio, manda o arquivo e fecha o fluxo; o
/// que recebe grava o arquivo, pelo `fs.write` dele, e fecha. O conteúdo
/// chega inteiro, e o fluxo sai da tabela na hora — não fica vivo, contado
/// nas cotas, até vencer a inatividade.
pub(super) fn sdk_o_copiador_fecha_cada_copia() -> Resultado {
    const BASE: &str = "/armazem/compartilhado/copiador";
    const ORIGEM: &str = "/armazem/compartilhado/copiador/origem.txt";
    const PEDIDO: &str = "/armazem/compartilhado/copiador/enviar";
    const RECEBIDOS: &str = "/armazem/compartilhado/copiador/recebidos";
    const RECEBIDO: &str = "/armazem/compartilhado/copiador/recebidos/origem.txt";
    const CONTEUDO: &str = "ola, copiador";
    /// O código com que o `copiador` sai no fim pedido.
    const SAIDA_DO_COPIADOR: i64 = 53;
    com_os_avisos(|| {
        let (sessao, bia) = pessoa("bia", 4470);
        let quem = Chamador::Pessoa(sessao);
        let gravar = |caminho: &str, conteudo: &str| -> Resultado {
            let versao = versao_no_armazem(caminho);
            let r = fs_pedir(
                quem,
                "fs.write",
                &format!(
                    r#"{{"path":"{caminho}","content":"{conteudo}","expect_version":{versao}}}"#
                ),
            );
            if !fs_ok(&r) {
                crate::log_error!("teste", "{}", r);
                return Err("um arquivo do copiador nao foi gravado");
            }
            Ok(())
        };
        let r = (|| -> Resultado {
            // O `/armazem/compartilhado` pode não existir ainda, com o caso
            // rodando sozinho: o armazém não cria pai de passagem.
            diretorios_acima(BASE)?;
            let r = fs_pedir(quem, "fs.mkdir", &format!(r#"{{"path":"{BASE}"}}"#));
            if !fs_ok(&r) && !r.contains("ja ha algo nesse caminho") {
                crate::log_error!("teste", "{}", r);
                return Err("o diretorio do copiador nao foi criado");
            }
            gravar(ORIGEM, CONTEUDO)?;
            let (_, pronto) = NaMalha::lancar("copiador", bia, "copiador: pronto ")?;
            let (_, recebe) = pronto
                .split_once(' ')
                .ok_or("o copiador que recebe nao disse o canal")?;
            let recebe = String::from(recebe);
            let r = (|| -> Resultado {
                gravar(PEDIDO, ORIGEM)?;
                let desde = crate::log::total_emitidos();
                let (_, pronto) = NaMalha::lancar("copiador", bia, "copiador: pronto ")?;
                let (_, manda) = pronto
                    .split_once(' ')
                    .ok_or("o copiador que manda nao disse o canal")?;
                let manda = String::from(manda);
                let r = (|| -> Resultado {
                    dito_na_malha(desde, "copiador: mandei ")?;
                    dito_na_malha(desde, "copiador: recebi ")?;
                    let (_, recebido) = fs_no_armazem(RECEBIDO);
                    if recebido.as_deref() != Some(CONTEUDO.as_bytes()) {
                        crate::log_error!("teste", "{:?}", recebido);
                        return Err("o copiador nao gravou o que recebeu");
                    }
                    if esperar_ate(|| crate::fluxo::contagem().0 == 0, TETO_DA_MALHA).is_err() {
                        crate::log_error!("teste", "{:?}", crate::fluxo::contagem());
                        return Err("o copiador largou o fluxo da copia sem fechar");
                    }
                    Ok(())
                })();
                r.and(encerrar_na_malha(&manda, SAIDA_DO_COPIADOR))
            })();
            r.and(encerrar_na_malha(&recebe, SAIDA_DO_COPIADOR))
        })();
        // O armazém volta a ser o de antes.
        let caminhos = [
            ("fs.delete", PEDIDO),
            ("fs.delete", ORIGEM),
            ("fs.delete", RECEBIDO),
            ("fs.rmdir", RECEBIDOS),
            ("fs.rmdir", BASE),
        ];
        let mut limpo = Ok(());
        for (metodo, caminho) in caminhos {
            let versao = versao_no_armazem(caminho);
            if versao == 0 {
                continue;
            }
            let r = fs_pedir(
                quem,
                metodo,
                &format!(r#"{{"path":"{caminho}","expect_version":{versao}}}"#),
            );
            if !fs_ok(&r) {
                crate::log_error!("teste", "{}", r);
                limpo = Err("o que o caso do copiador gravou nao foi apagado");
            }
        }
        r.and(limpo)
    })
}
