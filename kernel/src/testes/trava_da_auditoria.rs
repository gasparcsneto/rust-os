//! Os casos `trava:` — o tempo que a trava da auditoria fica na mão de quem
//! lê o anel e de quem anexa a ele.
//!
//! A trava da auditoria é a do gate: todo pedido auditado a toma, com as
//! interrupções mascaradas, para anexar o registro da decisão dele. Três
//! caminhos a seguravam além da conta do elo — `audit.tail`, que copiava até
//! 128 registros com ela; `audit.verify`, que refazia o anel inteiro com ela;
//! e o anexar, que devolvia ao alocador, com ela, o registro que saía pela
//! ponta do anel cheio. O anel guarda agora cada registro num `Arc` que não
//! muda depois de entrar (ver "O anel e a trava de quem o guarda", em
//! `politica::auditoria`): quem lê copia só os ponteiros, para um vetor
//! reservado antes, e lê, escreve e refaz elos com a trava solta; quem anexa
//! pede a memória do registro antes dela (`Preparado`) e solta o que saiu
//! pela ponta depois.
//!
//! Os casos conferem, sem depender de tempo nem de sorte:
//!
//! - que `audit.tail`, pelo gate, com o anel cheio e a cadeia mais longa que
//!   ele, mostra exatamente os registros que o contrato do comando diz para
//!   cada `after` — zero, os que o anel já descartou, o que a própria leitura
//!   empurrou para fora, a fronteira do primeiro guardado, o meio, o fim,
//!   além dele, `u64::MAX` — e cada `count` — 0, 1, 128, 129, `u64::MAX`,
//!   ausente —, e sem `after`: em ordem, seguidos, cada um igual ao do anel,
//!   com o elo refeito, o anterior encadeado e o `durable` da gravada. O
//!   esperado sai do anel da hora do handler, que é o de antes do pedido mais
//!   a decisão dele — o gate a grava antes do handler —, e da API de leitura
//!   do anel; se mais alguém auditou no meio, a leitura se repete;
//! - que `audit.head` e `audit.verify` da mesma hora dizem a mesma cabeça e o
//!   anel inteiro conferido a partir da âncora; que, pelo gate, a cabeça
//!   inclui a decisão do próprio pedido; e o anel no limite — 1023, 1024 e
//!   1025 registros, numa cadeia local da mesma capacidade, porque a global
//!   não recomeça —: `anexar` e `anexar_preparado` fazem a mesma cadeia, o
//!   que sai pela ponta sai só no 1025, a âncora passa a ser o elo dele, e a
//!   fotografia dos `Arc` confere como `audit.verify` a confere — e acusa o
//!   registro adulterado;
//! - que a resposta de `audit.verify` é a de sempre nos três ramos — a cadeia
//!   que confere, a que não confere e a que não existe —; que, com memória
//!   para a fotografia, a conta é a dela, fora da trava; e que, pela conta
//!   com a trava — sem memória para a fotografia, com um lugar menor que o
//!   anel e no post-mortem —, ele dá a mesma resposta, sem pedir nem
//!   devolver memória com ela. O caminho de cada `audit.verify` é contado só
//!   na suíte (`agent::commands::verificacao_de_teste`), e os casos levam à
//!   conta com a trava sem estilhaçar o heap nem entrar no post-mortem;
//! - que, com a trava na mão, nada pede nem devolve memória ao alocador: o
//!   registro anexado pelo gate ao anel cheio, um pedido inteiro pelo gate —
//!   `audit.head`, `audit.tail` de 128 com e sem `after`, `audit.verify`, a
//!   declaração ancorada numa decisão —, o anel que cresce do zero ao cheio,
//!   e a política lida de novo com a cadeia de pé. Pela conta do próprio
//!   alocador, só da suíte
//!   (`autorizacao::alocacoes_sob_a_auditoria_de_teste`), com os controles:
//!   o pedido e a devolução feitos de propósito com a trava na mão são
//!   contados; os de fora dela, os de outro fio e os de depois da vigia,
//!   não; e cada vigia começa do zero. E o registro que saiu foi mesmo
//!   devolvido — depois;
//! - que a âncora de uma declaração tem de estar na janela: com o primeiro
//!   guardado sendo uma decisão do mesmo processo, a decisão zero e uma de
//!   antes dele não ancoram, e ele ancora;
//! - que o registro que sai pela ponta deixa o elo como âncora, que quem
//!   anexou soltou a parte dele, e que quem segura o `Arc` dele continua
//!   lendo o mesmo registro sem mudar nada no anel;
//! - que, com produtores em vários núcleos auditando e, ao mesmo tempo, um
//!   leitor que acompanha a cadeia como o NSF — `audit.tail` depois do
//!   último lido, de 64 em 64 — e outro que pede `audit.verify` em laço,
//!   cada leitura vem em ordem, seguida, sem repetir o que já foi lido; o
//!   salto só acontece quando o anel descartou o que não foi lido a tempo, e
//!   começa no primeiro guardado da hora; e todo `audit.verify` confere o
//!   anel inteiro. E que o journal tem cada registro uma vez, na ordem, os de
//!   cada produtor na ordem dele, com o elo de cada número igual ao que o
//!   leitor viu, e a cabeça de cada verificação é o elo de um registro da
//!   hora dela;
//! - que, com o anel dando a volta três vezes e vários fios pedindo
//!   `audit.verify` sem parar, toda resposta confere o anel inteiro; que a
//!   memória que as fotografias seguram não passa de um anel por fio; e que,
//!   no fim, ela volta ao patamar — o que sai pela ponta não vaza;
//! - e, com três coletores e uma compactação no meio — os produtores parados
//!   na metade até ela começar —, que a base é a marca e os copiados até a
//!   gravada, o journal segue dela sem lacuna, e a cadeia refeita dele é a da
//!   memória.
//!
//! O que nenhum caso distingue, por dar a mesma resposta: a posição do
//! `after` achada pelo filtro em vez de pela distância ao primeiro guardado.
//! Só a medida do tempo com a trava a separa. A conta do `audit.verify`
//! feita com a trava em vez de fora dela, que também dá a mesma resposta, a
//! conta de cada caminho separa.

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};

use politica::Codigo;
use politica::auditoria::{
    Cadeia, Evento, GENESE, Lacuna, MAIOR_DETALHE, Preparado, Registro, Titular,
};

use super::{
    Buffer, Resultado, a_cadeia_do_journal_confere, chamar, conferir, declaracoes_desde, escrita,
    fs_pedir, nucleos_secundarios, sistema_aqui,
};
use crate::agent::commands::verificacao_de_teste as verificacao;
use crate::agent::json::{Json, JsonWriter};
use crate::autorizacao::alocacoes_sob_a_auditoria_de_teste as alocacoes;
use crate::persistencia::{self, AuditoriaNoJournal};

/// A capacidade do anel da auditoria.
const CAPACIDADE: u64 = crate::autorizacao::CAPACIDADE_DA_AUDITORIA as u64;

/// O `count` de `audit.tail` quando o pedido não diz, e o teto dele: o
/// contrato do comando, como a descrição do parâmetro o escreve.
const CAUDA_PADRAO: u64 = 32;
const MAIOR_CAUDA: u64 = 128;

/// Quantos registros, ao menos, já saíram do anel quando um caso começa: a
/// cauda com `after` antes do primeiro guardado tem o que pular.
const SAIDOS: u64 = 64;

/// Quantas vezes um caso repete um pedido cuja hora não foi a prevista —
/// alguém mais auditou no meio —, ou que a taxa recusou.
const TENTATIVAS: usize = 5;

/// O teto da espera por uma ficha da taxa do sistema, em milissegundos. A
/// taxa não é do caso: um caso anterior pode tê-la gasto.
const TETO_DA_TAXA_MS: u64 = 10_000;

/// Os métodos dos registros dos casos.
const ENCHE: &str = "teste.trava.enche";
const PENDENTE: &str = "teste.trava.pendente";
const VIGIADO: &str = "teste.trava.vigiado";
const SAI: &str = "teste.trava.sai";
const LOCAL: &str = "teste.trava.local";
const PRODUZIDO: &str = "teste.trava.produtor";

/// Quantos registros o caso da cauda audita depois do último gravado: o
/// `durable` muda no meio das leituras.
const PENDENTES: u64 = 40;

/// O lugar da fotografia de `audit.verify`: um ponteiro por registro do
/// anel cheio.
const FOTOGRAFIA: usize =
    crate::autorizacao::CAPACIDADE_DA_AUDITORIA * core::mem::size_of::<Arc<Registro>>();

// ---------------------------------------------------------------------------
// O anel, como os casos o veem
// ---------------------------------------------------------------------------

/// O anel num instante: o primeiro guardado, o último número e quantos
/// guardados.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Anel {
    primeiro: u64,
    ultimo: u64,
    guardados: u64,
}

impl Anel {
    /// O anel cheio depois de um registro a mais: o mais velho saiu pela
    /// ponta, e o novo é o último.
    fn andado(self) -> Anel {
        Anel {
            primeiro: self.primeiro + 1,
            ultimo: self.ultimo + 1,
            guardados: self.guardados,
        }
    }
}

/// O anel agora. Nada aqui pede memória.
fn anel() -> Anel {
    crate::autorizacao::com_auditoria(|c| Anel {
        primeiro: c
            .ultimos(usize::MAX)
            .next()
            .map_or(c.ultima_seq() + 1, |r| r.seq),
        ultimo: c.ultima_seq(),
        guardados: c.guardados() as u64,
    })
    .unwrap_or(Anel {
        primeiro: 1,
        ultimo: 0,
        guardados: 0,
    })
}

/// O anel inteiro, como os `Arc` dele, e a âncora — da mesma tomada da
/// trava, como `audit.verify` a tira: com ela, só os ponteiros, para um
/// vetor reservado antes.
fn fotografia() -> (Vec<Arc<Registro>>, [u8; 32]) {
    let mut f = Vec::with_capacity(crate::autorizacao::CAPACIDADE_DA_AUDITORIA);
    let ancora = crate::autorizacao::com_auditoria(|c| {
        f.extend(c.ultimos_compartilhados(usize::MAX).cloned());
        c.ancora()
    })
    .unwrap_or(GENESE);
    (f, ancora)
}

/// O anel que uma fotografia mostra.
fn anel_da(f: &[Arc<Registro>]) -> Anel {
    match (f.first(), f.last()) {
        (Some(a), Some(b)) => Anel {
            primeiro: a.seq,
            ultimo: b.seq,
            guardados: f.len() as u64,
        },
        _ => Anel {
            primeiro: 0,
            ultimo: 0,
            guardados: 0,
        },
    }
}

/// O primeiro registro que o anel guarda; zero sem nenhum.
fn primeiro_no_anel() -> u64 {
    crate::autorizacao::com_auditoria(|c| c.ultimos(usize::MAX).next().map(|r| r.seq))
        .flatten()
        .unwrap_or(0)
}

/// Um registro do kernel na auditoria, pelo `auditar` do gate; o número dele.
fn auditar(metodo: &str, detalhe: &str) -> u64 {
    crate::autorizacao::auditar_do_kernel(metodo, "", Codigo::Allow, detalhe)
}

/// Audita `n` registros de enchimento, todos iguais; o journal acompanha:
/// nada sai do anel sem ter sido gravado, e o caso seguinte não herda uma
/// lacuna.
fn auditar_enchendo(n: u64, detalhe: &str) -> Resultado {
    for i in 1..=n {
        auditar(ENCHE, detalhe);
        if i.is_multiple_of(256) {
            persistencia::gravar_auditoria()?;
        }
    }
    persistencia::gravar_auditoria()
}

/// O anel cheio, com registros que já saíram dele — a cadeia mais longa que
/// o anel —, e a auditoria toda no journal.
fn anel_cheio_com_saidos() -> Resultado {
    let mut auditados = 0u64;
    loop {
        let a = anel();
        if a.guardados == CAPACIDADE && a.primeiro > SAIDOS {
            break;
        }
        if auditados > CAPACIDADE + SAIDOS {
            crate::log_error!(
                "teste",
                "o anel guarda {} de {}, a partir do {}",
                a.guardados,
                CAPACIDADE,
                a.primeiro
            );
            return Err("o anel da auditoria nao encheu");
        }
        auditar(ENCHE, "enche o anel");
        auditados += 1;
        if auditados.is_multiple_of(256) {
            persistencia::gravar_auditoria()?;
        }
    }
    persistencia::gravar_auditoria()
}

/// Um campo numérico de um objeto JSON.
fn numero(j: Json<'_>, campo: &str) -> Option<u64> {
    j.member(campo).and_then(|v| v.as_u64())
}

/// Um campo de texto de um objeto JSON, cru — os campos conferidos aqui são
/// hexadecimais e palavras, sem escape.
fn texto<'a>(j: Json<'a>, campo: &str) -> Option<&'a str> {
    j.member(campo).and_then(|v| v.as_str())
}

/// Os `audit.verify` desde as contas `antes` passaram pela fotografia, com
/// a conta fora da trava — o heap tem lugar para ela —, e nenhum pela conta
/// com a trava.
fn pela_fotografia(antes: (u64, u64)) -> Resultado {
    let depois = verificacao::contas();
    if depois.0 <= antes.0 || depois.1 != antes.1 {
        crate::log_error!(
            "teste",
            "audit.verify (pela fotografia, com a trava) de {:?} para {:?}",
            antes,
            depois
        );
        return Err("com memoria para a fotografia, o audit.verify fez a conta com a trava");
    }
    Ok(())
}

/// A resposta de `audit.verify` diz o anel inteiro conferido, sem falha.
fn confere_o_anel_inteiro(j: Json<'_>) -> bool {
    j.member("ok").and_then(|v| v.as_bool()) == Some(true)
        && numero(j, "checked") == Some(CAPACIDADE)
        && j.member("failed_at").is_none()
}

/// O elo de um registro em oito bytes, para as marcas dos casos
/// concorrentes: nunca zero (o ainda não visto) nem [`SALTADO`].
fn marca(elo: &[u8; 32]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&elo[..8]);
    u64::from_le_bytes(b) % (u64::MAX - 1) + 1
}

// ---------------------------------------------------------------------------
// Os pedidos pelo gate
// ---------------------------------------------------------------------------

/// O que um pedido pelo gate deu.
enum PeloGate {
    /// O resultado do comando, o JSON cru.
    Resultado(String),
    /// A recusa pela taxa do papel: o pedido pode ser repetido.
    Taxa,
    /// Outra recusa, ou um erro — escrito no log.
    Recusa,
}

/// Um pedido inteiro pelo gate, como um processo do sistema deste fio — a
/// validação, a decisão, o registro dela e o handler, como `fs_pedir` faz
/// para os outros casos.
fn pedir_ao_gate(metodo: &str, params: &str) -> PeloGate {
    let envelope = fs_pedir(sistema_aqui(), metodo, params);
    let j = Json(envelope.as_bytes());
    if let Some(r) = j.member("result").and_then(|r| r.raw_str()) {
        return PeloGate::Resultado(String::from(r));
    }
    if j.member("error").and_then(|e| texto(e, "data")) == Some("RATE_LIMIT") {
        TAXADAS.fetch_add(1, SeqCst);
        return PeloGate::Taxa;
    }
    crate::log_error!("teste", "{} {}: {}", metodo, params, envelope);
    PeloGate::Recusa
}

/// [`pedir_ao_gate`], esperando a ficha quando a taxa recusa, até
/// [`TETO_DA_TAXA_MS`] ou até `desistir`: `Ok(None)` quando desistiu.
fn pelo_gate_ate(
    metodo: &str,
    params: &str,
    desistir: impl Fn() -> bool,
) -> Result<Option<String>, &'static str> {
    let limite = crate::tempo::uptime_ms() + TETO_DA_TAXA_MS;
    loop {
        match pedir_ao_gate(metodo, params) {
            PeloGate::Resultado(r) => return Ok(Some(r)),
            PeloGate::Recusa => return Err("o gate recusou um pedido do caso"),
            PeloGate::Taxa if desistir() => return Ok(None),
            PeloGate::Taxa if crate::tempo::uptime_ms() > limite => {
                return Err("a taxa do sistema recusou um pedido do caso ate o teto da espera");
            }
            PeloGate::Taxa => esperar_ms(2),
        }
    }
}

/// [`pelo_gate_ate`], sem desistir.
fn pelo_gate(metodo: &str, params: &str) -> Result<String, &'static str> {
    pelo_gate_ate(metodo, params, || false)?.ok_or("o pedido do caso desistiu sem ninguem mandar")
}

/// Espera `ms` milissegundos, cedendo.
fn esperar_ms(ms: u64) {
    let ate = crate::tempo::uptime_ms() + ms;
    while crate::tempo::uptime_ms() < ate {
        crate::fios::ceder();
    }
}

/// Se o registro `r` é a decisão do pedido `metodo` com `params` que este
/// fio fez pelo gate: `ALLOW`, do sistema, com o resumo dos parâmetros e o
/// processo deste fio no detalhe.
fn e_decisao_deste_fio(r: &Registro, metodo: &str, params: &str) -> bool {
    let e = &r.evento;
    let deste_fio = alloc::format!("pelo processo {} (", crate::fios::id_atual());
    e.metodo == metodo
        && e.codigo == Codigo::Allow
        && e.titular == Titular::Sistema
        && e.parametros == politica::auditoria::resumo_dos_parametros(params.as_bytes())
        && e.detalhe.starts_with(&deste_fio)
}

/// [`e_decisao_deste_fio`], conferido: o registro anexado num pedido do
/// caso é a decisão dele.
fn e_a_decisao_do_caso(r: &Registro, metodo: &str, params: &str) -> Resultado {
    if !e_decisao_deste_fio(r, metodo, params) {
        crate::log_error!("teste", "registro {}: {:?}", r.seq, r.evento);
        return Err("o registro anexado no pedido nao e a decisao do pedido do caso");
    }
    Ok(())
}

/// A decisão mais recente, no anel, de um pedido `metodo` sem parâmetros
/// que este fio fez pelo gate.
fn decisao_deste_fio(metodo: &str) -> Option<u64> {
    let (anel, _) = fotografia();
    anel.iter()
        .rev()
        .find(|r| e_decisao_deste_fio(r, metodo, "{}"))
        .map(|r| r.seq)
}

/// O resultado de um pedido pelo gate, com o anel e a âncora logo depois
/// dele.
struct ComADecisao {
    resultado: String,
    anel: Vec<Arc<Registro>>,
    ancora: [u8; 32],
}

/// Um pedido sem parâmetros pelo gate, numa hora em que só ele audita: o
/// anel depois dele é o de antes com a decisão dele no fim — o último da
/// fotografia —, e o mais velho a menos. Se mais alguém auditou no meio, de
/// novo.
fn pelo_gate_com_a_decisao(metodo: &str) -> Result<ComADecisao, &'static str> {
    for _ in 0..TENTATIVAS {
        let antes = anel();
        let resultado = match pedir_ao_gate(metodo, "{}") {
            PeloGate::Resultado(r) => r,
            PeloGate::Taxa => {
                esperar_ms(5);
                continue;
            }
            PeloGate::Recusa => return Err("o gate recusou um pedido do caso"),
        };
        let (anel, ancora) = fotografia();
        if anel_da(&anel) != antes.andado() {
            continue;
        }
        e_a_decisao_do_caso(
            anel.last().ok_or("o anel da auditoria esta vazio")?,
            metodo,
            "{}",
        )?;
        return Ok(ComADecisao {
            resultado,
            anel,
            ancora,
        });
    }
    Err("a auditoria nao ficou quieta em nenhuma tentativa do pedido pelo gate")
}

// ---------------------------------------------------------------------------
// audit.tail em cada posição
// ---------------------------------------------------------------------------

/// Uma leitura do caso da cauda: o que ela é, o `after` — dado o anel da hora
/// do handler — e o `count`.
struct Leitura {
    o_que: &'static str,
    depois: fn(Anel) -> Option<u64>,
    quantos: Option<u64>,
}

/// Os parâmetros de `audit.tail`, sem o que o pedido não diz.
fn parametros(depois: Option<u64>, quantos: Option<u64>) -> String {
    match (depois, quantos) {
        (Some(a), Some(n)) => alloc::format!(r#"{{"after":{a},"count":{n}}}"#),
        (Some(a), None) => alloc::format!(r#"{{"after":{a}}}"#),
        (None, Some(n)) => alloc::format!(r#"{{"count":{n}}}"#),
        (None, None) => String::from("{}"),
    }
}

/// Os números que `audit.tail` tem de mostrar com o anel `h`, pelo contrato
/// do comando: com `after`, os seguintes a ele — a partir do primeiro
/// guardado, se o anel já descartou os de antes —, até `count`; sem, os
/// últimos `count`. O `count` tem teto, e um padrão.
fn esperados(h: Anel, depois: Option<u64>, quantos: Option<u64>) -> Vec<u64> {
    let n = quantos.unwrap_or(CAUDA_PADRAO).min(MAIOR_CAUDA);
    if n == 0 {
        return Vec::new();
    }
    let de = match depois {
        Some(a) => a.saturating_add(1).max(h.primeiro),
        None => h.ultimo.saturating_sub(n - 1).max(h.primeiro),
    };
    if de > h.ultimo {
        return Vec::new();
    }
    (de..=h.ultimo).take(n as usize).collect()
}

/// Os registros de `registros`, um a um, são os de `compartilhados` — os
/// mesmos objetos, na mesma ordem, e nenhum a mais de um lado; os números
/// vão para `seqs`, que tem o lugar reservado.
fn mesmos_registros<'a>(
    registros: impl Iterator<Item = &'a Registro>,
    mut compartilhados: impl Iterator<Item = &'a Arc<Registro>>,
    seqs: &mut Vec<u64>,
) -> bool {
    for r in registros {
        match compartilhados.next() {
            Some(a) if core::ptr::eq(&**a, r) => seqs.push(r.seq),
            _ => return false,
        }
    }
    compartilhados.next().is_none()
}

/// Os números que a API de leitura do anel dá para a leitura — a que o
/// journal usa, `guardados_depois_de` e `ultimos` —, e se os `Arc` que os
/// relatórios copiam com a trava, `compartilhados_depois_de` e
/// `ultimos_compartilhados`, são os mesmos registros.
fn pela_api(depois: Option<u64>, quantos: Option<u64>) -> (Vec<u64>, bool) {
    let n = quantos.unwrap_or(CAUDA_PADRAO).min(MAIOR_CAUDA) as usize;
    let mut seqs = Vec::with_capacity(n);
    let mesmos = crate::autorizacao::com_auditoria(|c| match depois {
        Some(a) => mesmos_registros(
            c.guardados_depois_de(a).take(n),
            c.compartilhados_depois_de(a).take(n),
            &mut seqs,
        ),
        None => mesmos_registros(c.ultimos(n), c.ultimos_compartilhados(n), &mut seqs),
    })
    .unwrap_or(false);
    (seqs, mesmos)
}

/// Um registro como `audit.tail` o mostrou: o que entra no elo, lido como o
/// NSF o lê (`seguranca::evento::Registro::do_json`), e os dois campos que
/// não entram, o `result` e o `durable`.
struct Mostrado {
    r: seguranca::evento::Registro,
    resultado: String,
    duravel: bool,
}

/// Os objetos de um array JSON, numa passada só — `Json::item` volta ao
/// começo do array a cada índice. Strings e contêineres aninhados são
/// pulados inteiros, como no leitor do protocolo.
struct Objetos<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Iterator for Objetos<'a> {
    type Item = Json<'a>;

    fn next(&mut self) -> Option<Json<'a>> {
        let b = self.b;
        // Até o começo do próximo objeto, no nível do array: o `[`, as
        // vírgulas e os espaços ficam para trás, e o `]` é o fim.
        while self.i < b.len() && b[self.i] != b'{' {
            if b[self.i] == b']' {
                self.i = b.len();
                return None;
            }
            self.i += 1;
        }
        let inicio = self.i;
        let mut profundidade = 0usize;
        let mut na_string = false;
        let mut escapado = false;
        while self.i < b.len() {
            let c = b[self.i];
            self.i += 1;
            if na_string {
                if escapado {
                    escapado = false;
                } else if c == b'\\' {
                    escapado = true;
                } else if c == b'"' {
                    na_string = false;
                }
                continue;
            }
            match c {
                b'"' => na_string = true,
                b'{' | b'[' => profundidade += 1,
                b'}' | b']' => {
                    profundidade = profundidade.saturating_sub(1);
                    if profundidade == 0 {
                        return Some(Json(&b[inicio..self.i]));
                    }
                }
                _ => {}
            }
        }
        None
    }
}

/// O `records` de um resultado de `audit.tail`, registro a registro.
fn registros_do_resultado(resultado: &str) -> Result<Objetos<'_>, &'static str> {
    let lista = Json(resultado.as_bytes())
        .member("records")
        .ok_or("o audit.tail nao trouxe records")?;
    Ok(Objetos { b: lista.0, i: 0 })
}

/// O `durable_seq` e os registros de um resultado de `audit.tail`.
fn cauda_mostrada(resultado: &str) -> Result<(u64, Vec<Mostrado>), &'static str> {
    let duravel_ate = numero(Json(resultado.as_bytes()), "durable_seq")
        .ok_or("o audit.tail nao disse o durable_seq")?;
    let mut v = Vec::new();
    for o in registros_do_resultado(resultado)? {
        let r = seguranca::evento::Registro::do_json(o)?;
        let resultado = texto(o, "result").ok_or("um registro do audit.tail sem result")?;
        let duravel = o
            .member("durable")
            .and_then(|d| d.as_bool())
            .ok_or("um registro do audit.tail sem durable")?;
        v.push(Mostrado {
            r,
            resultado: String::from(resultado),
            duravel,
        });
    }
    Ok((duravel_ate, v))
}

/// O que o `durable` mostrou ao longo do caso da cauda: o último gravado,
/// gravado, e o seguinte, não — os dois lados da fronteira.
#[derive(Default)]
struct Fronteira {
    gravado: bool,
    nao_gravado: bool,
}

/// Cada registro mostrado é o do anel com o mesmo número — todos os campos
/// que entram no elo, o anterior e o elo —, o elo refeito confere, o
/// anterior é o elo do mostrado antes dele — o do primeiro, o do registro
/// antes dele no anel, ou a âncora, se ele é o primeiro guardado —, o
/// `result` é o do código, e o `durable` é o da gravada.
fn conferir_com_o_anel(
    mostrados: &[Mostrado],
    anel: &[Arc<Registro>],
    ancora: [u8; 32],
    duravel_ate: u64,
    fronteira: &mut Fronteira,
) -> Resultado {
    let primeiro = anel.first().map_or(0, |r| r.seq);
    let mut anterior: Option<[u8; 32]> = None;
    for m in mostrados {
        let i =
            m.r.seq
                .checked_sub(primeiro)
                .ok_or("um registro mostrado ja tinha saido do anel na hora do handler")?
                as usize;
        let r = anel
            .get(i)
            .filter(|r| r.seq == m.r.seq)
            .ok_or("um registro mostrado nao esta no anel da hora do handler")?;
        let antes = match anterior {
            Some(e) => e,
            None if i == 0 => ancora,
            None => anel[i - 1].elo,
        };
        if r.evento != m.r.evento_da_cadeia() || r.anterior != m.r.anterior || r.elo != m.r.elo {
            crate::log_error!(
                "teste",
                "registro {}: no anel {:?}; mostrado {:?}",
                r.seq,
                r.evento,
                m.r
            );
            return Err("um registro do audit.tail nao e o do anel");
        }
        if m.r.anterior != antes || !m.r.elo_confere() {
            crate::log_error!("teste", "registro {}: o elo nao refaz", r.seq);
            return Err("um registro do audit.tail nao refaz o elo, ou nao continua o anterior");
        }
        if m.resultado != r.evento.codigo.resultado() {
            return Err("o result de um registro do audit.tail nao e o do codigo dele");
        }
        if m.duravel != (m.r.seq <= duravel_ate) {
            crate::log_error!(
                "teste",
                "registro {}: durable {}, gravada {}",
                m.r.seq,
                m.duravel,
                duravel_ate
            );
            return Err("o durable de um registro do audit.tail nao e o da gravada");
        }
        fronteira.gravado |= m.r.seq == duravel_ate && m.duravel;
        fronteira.nao_gravado |= m.r.seq == duravel_ate + 1 && !m.duravel;
        anterior = Some(m.r.elo);
    }
    Ok(())
}

/// Uma leitura do caso da cauda, pelo gate, conferida contra o anel da
/// hora do handler — o de antes do pedido com a decisão dele no fim e o
/// mais velho a menos. Se a hora não foi essa — alguém mais auditou, ou
/// gravou, no meio —, de novo.
fn ler_a_cauda(l: &Leitura, fronteira: &mut Fronteira) -> Resultado {
    for _ in 0..TENTATIVAS {
        let antes = anel();
        if antes.guardados != CAPACIDADE {
            return Err("o anel nao esta cheio no caso da cauda");
        }
        let h = antes.andado();
        let depois = (l.depois)(h);
        let params = parametros(depois, l.quantos);
        let gravada = persistencia::auditoria_gravada();
        let resultado = match pedir_ao_gate("audit.tail", &params) {
            PeloGate::Resultado(r) => r,
            PeloGate::Taxa => {
                esperar_ms(5);
                continue;
            }
            PeloGate::Recusa => return Err("o gate recusou o audit.tail do caso"),
        };
        // A API do anel logo depois do pedido, e a fotografia depois dela: se
        // o anel da fotografia ainda é o da hora do handler, a API também o
        // leu.
        let (api, mesmos) = pela_api(depois, l.quantos);
        let (anel_depois, ancora) = fotografia();
        if anel_da(&anel_depois) != h || persistencia::auditoria_gravada() != gravada {
            crate::log_info!(
                "teste",
                "trava: {}: a auditoria andou no meio da leitura; de novo",
                l.o_que
            );
            continue;
        }
        e_a_decisao_do_caso(
            anel_depois.last().ok_or("o anel da auditoria esta vazio")?,
            "audit.tail",
            &params,
        )?;
        let esperado = esperados(h, depois, l.quantos);
        if api != esperado || !mesmos {
            crate::log_error!(
                "teste",
                "{} ({}): a API do anel deu {:?}, o contrato {:?}",
                l.o_que,
                params,
                api,
                esperado
            );
            return Err("a API de leitura do anel nao da o que o contrato do audit.tail diz");
        }
        let (duravel_ate, mostrados) = cauda_mostrada(&resultado)?;
        if duravel_ate != gravada {
            return Err("o durable_seq do audit.tail nao e a auditoria gravada");
        }
        let seqs: Vec<u64> = mostrados.iter().map(|m| m.r.seq).collect();
        if seqs != esperado {
            crate::log_error!(
                "teste",
                "{} ({}): mostrou {:?}, o contrato {:?}",
                l.o_que,
                params,
                seqs,
                esperado
            );
            return Err("o audit.tail nao mostrou os registros que o contrato diz");
        }
        return conferir_com_o_anel(&mostrados, &anel_depois, ancora, gravada, fronteira);
    }
    crate::log_error!("teste", "trava: {}", l.o_que);
    Err("a auditoria nao ficou quieta em nenhuma tentativa de uma leitura do caso da cauda")
}

/// `audit.tail`, pelo gate, com o anel cheio e a cadeia mais longa que ele:
/// cada `after` e cada `count` mostram exatamente os registros do contrato,
/// iguais aos do anel, encadeados, com o elo refeito e o `durable` da
/// gravada — que passa no meio das leituras.
pub(super) fn a_cauda_em_cada_posicao() -> Resultado {
    if persistencia::estado() != persistencia::Estado::Disponivel {
        return Err("a persistencia nao esta disponivel: o caso da cauda confere o durable");
    }
    anel_cheio_com_saidos()?;
    for _ in 0..PENDENTES {
        auditar(PENDENTE, "ainda nao gravado");
    }
    // O `after` de cada leitura, dado o anel da hora do handler: o
    // `primeiro` já é o seguinte ao que a decisão do próprio pedido
    // empurrou para fora, e o `ultimo` é ela.
    let leituras: [Leitura; 21] = [
        Leitura {
            o_que: "after 0, sem count",
            depois: |_| Some(0),
            quantos: None,
        },
        Leitura {
            o_que: "after 0, count 129",
            depois: |_| Some(0),
            quantos: Some(129),
        },
        Leitura {
            o_que: "after antes do primeiro guardado, ja descartado",
            depois: |h| Some(h.primeiro.saturating_sub(10)),
            quantos: Some(4),
        },
        Leitura {
            o_que: "after o que a propria leitura empurrou para fora",
            depois: |h| Some(h.primeiro.saturating_sub(2)),
            quantos: Some(1),
        },
        Leitura {
            o_que: "after o de antes do primeiro guardado",
            depois: |h| Some(h.primeiro - 1),
            quantos: Some(3),
        },
        Leitura {
            o_que: "after o primeiro guardado, count 0",
            depois: |h| Some(h.primeiro),
            quantos: Some(0),
        },
        Leitura {
            o_que: "after o primeiro guardado, count u64::MAX",
            depois: |h| Some(h.primeiro),
            quantos: Some(u64::MAX),
        },
        Leitura {
            o_que: "after no meio do anel",
            depois: |h| Some(h.primeiro + (h.ultimo - h.primeiro) / 2),
            quantos: Some(64),
        },
        Leitura {
            o_que: "after o ultimo menos cinco, count 3",
            depois: |h| Some(h.ultimo - 5),
            quantos: Some(3),
        },
        Leitura {
            o_que: "after o ultimo menos cinco, sem count",
            depois: |h| Some(h.ultimo - 5),
            quantos: None,
        },
        Leitura {
            o_que: "after o ultimo menos um, count 1",
            depois: |h| Some(h.ultimo - 1),
            quantos: Some(1),
        },
        Leitura {
            o_que: "after o ultimo menos um, sem count",
            depois: |h| Some(h.ultimo - 1),
            quantos: None,
        },
        Leitura {
            o_que: "after o ultimo",
            depois: |h| Some(h.ultimo),
            quantos: None,
        },
        Leitura {
            o_que: "after alem do ultimo",
            depois: |h| Some(h.ultimo + 1),
            quantos: Some(128),
        },
        Leitura {
            o_que: "after muito alem do ultimo",
            depois: |h| Some(h.ultimo + 1000),
            quantos: None,
        },
        Leitura {
            o_que: "after u64::MAX",
            depois: |_| Some(u64::MAX),
            quantos: Some(128),
        },
        Leitura {
            o_que: "sem after, sem count",
            depois: |_| None,
            quantos: None,
        },
        Leitura {
            o_que: "sem after, count 0",
            depois: |_| None,
            quantos: Some(0),
        },
        Leitura {
            o_que: "sem after, count 1",
            depois: |_| None,
            quantos: Some(1),
        },
        Leitura {
            o_que: "sem after, count 128",
            depois: |_| None,
            quantos: Some(128),
        },
        Leitura {
            o_que: "sem after, count 129",
            depois: |_| None,
            quantos: Some(129),
        },
    ];
    let mut fronteira = Fronteira::default();
    for l in &leituras {
        ler_a_cauda(l, &mut fronteira)?;
    }
    if !fronteira.gravado || !fronteira.nao_gravado {
        return Err("nenhuma leitura do caso mostrou a fronteira do durable");
    }
    // O que o caso auditou vai ao journal: o caso seguinte não herda uma
    // lacuna.
    persistencia::gravar_auditoria()
}

// ---------------------------------------------------------------------------
// audit.verify e audit.head, e o anel no limite
// ---------------------------------------------------------------------------

/// `audit.head` e `audit.verify`, pelo handler — sem a decisão do gate no
/// meio —, numa hora em que ninguém audita: a mesma cabeça, que é o elo do
/// último do anel; o anel inteiro conferido a partir da âncora, que é a do
/// anel; e o `stored` e o `checked`, o anel cheio. A conta foi a da
/// fotografia, fora da trava. Se alguém auditou no meio, de novo.
fn cabeca_e_verificacao_na_mesma_hora() -> Resultado {
    for _ in 0..TENTATIVAS {
        let antes = anel();
        let contas = verificacao::contas();
        let cabeca = chamar("audit.head", "{}")?;
        let verificada = chamar("audit.verify", "{}")?;
        pela_fotografia(contas)?;
        let (f, ancora) = fotografia();
        if anel_da(&f) != antes {
            continue;
        }
        let ultimo = f.last().ok_or("o anel da auditoria esta vazio")?;
        let elo = sigilo::hex(&ultimo.elo);
        let h = Json(cabeca.as_bytes());
        let v = Json(verificada.as_bytes());
        let cabeca_certa = numero(h, "seq") == Some(ultimo.seq)
            && texto(h, "head") == Some(elo.as_str())
            && texto(h, "anchor") == Some(sigilo::hex(&ancora).as_str())
            && numero(h, "stored") == Some(f.len() as u64)
            && numero(h, "capacity") == Some(CAPACIDADE)
            && numero(h, "durable_seq") == Some(persistencia::auditoria_gravada());
        let verificacao_certa = confere_o_anel_inteiro(v)
            && texto(v, "head") == Some(elo.as_str())
            && numero(v, "checked") == numero(h, "stored");
        // A conta do caso, ao lado: a fotografia confere da âncora à cabeça.
        let refeita = politica::auditoria::verificar(ancora, f.iter().map(|r| &**r));
        if !cabeca_certa || !verificacao_certa || refeita != Ok(ultimo.elo) {
            crate::log_error!(
                "teste",
                "audit.head {}; audit.verify {}",
                cabeca,
                verificada
            );
            return Err(
                "audit.head e audit.verify da mesma hora nao dizem a cabeca e o anel inteiro conferido da ancora",
            );
        }
        return Ok(());
    }
    Err("a auditoria nao ficou quieta entre o audit.head e o audit.verify em nenhuma tentativa")
}

/// `audit.verify` e `audit.head` pelo gate: a decisão do próprio pedido
/// entra antes do handler, e a cabeça que ele diz é o elo dela; o anel
/// conferido é o inteiro, e a âncora, a do anel depois do pedido.
fn verificacao_e_cabeca_pelo_gate() -> Resultado {
    let v = pelo_gate_com_a_decisao("audit.verify")?;
    let decisao = v.anel.last().ok_or("o anel da auditoria esta vazio")?;
    let j = Json(v.resultado.as_bytes());
    if !confere_o_anel_inteiro(j) || texto(j, "head") != Some(sigilo::hex(&decisao.elo).as_str()) {
        crate::log_error!("teste", "audit.verify: {}", v.resultado);
        return Err("o audit.verify pelo gate nao conferiu o anel inteiro ate a decisao dele");
    }
    let h = pelo_gate_com_a_decisao("audit.head")?;
    let decisao = h.anel.last().ok_or("o anel da auditoria esta vazio")?;
    let j = Json(h.resultado.as_bytes());
    if numero(j, "seq") != Some(decisao.seq)
        || texto(j, "head") != Some(sigilo::hex(&decisao.elo).as_str())
        || texto(j, "anchor") != Some(sigilo::hex(&h.ancora).as_str())
        || numero(j, "stored") != Some(CAPACIDADE)
    {
        crate::log_error!("teste", "audit.head: {}", h.resultado);
        return Err("o audit.head pelo gate nao disse a decisao dele como cabeca");
    }
    Ok(())
}

/// A cada quantos registros das cadeias locais o tempo volta — o anel o
/// sobe ao do anterior —, e o detalhe passa do teto.
const VOLTA_O_TEMPO: u64 = 97;
const PASSA_DO_TETO: u64 = 101;

/// O detalhe que passa do teto: caracteres de dois bytes, com o teto caindo
/// no meio de um.
fn detalhe_longo() -> String {
    // O `ç` começa nos bytes de paridade contrária à do teto: o teto cai
    // sempre no segundo byte de um.
    let mut d = String::from(if MAIOR_DETALHE.is_multiple_of(2) {
        "a"
    } else {
        ""
    });
    for _ in 0..MAIOR_DETALHE {
        d.push('\u{e7}');
    }
    d
}

/// O detalhe longo como o anel o guarda: o maior começo dele, até o teto,
/// que termina numa fronteira de caractere.
fn detalhe_cortado() -> String {
    let d = detalhe_longo();
    let mut fim = MAIOR_DETALHE;
    while !d.is_char_boundary(fim) {
        fim -= 1;
    }
    String::from(&d[..fim])
}

/// O evento `i` das cadeias locais.
fn evento_local(i: u64) -> Evento {
    Evento {
        ts_ms: if i.is_multiple_of(VOLTA_O_TEMPO) {
            i * 10 - 25
        } else {
            i * 10
        },
        titular: Titular::Kernel,
        sessao: crate::autorizacao::SESSAO_DA_PESSOA,
        sessao_de_pessoa: None,
        agente: String::from("kernel"),
        chave: None,
        papel: String::new(),
        metodo: String::from(LOCAL),
        recurso: String::new(),
        codigo: Codigo::Allow,
        parametros: politica::auditoria::resumo_dos_parametros(&i.to_le_bytes()),
        detalhe: if i.is_multiple_of(PASSA_DO_TETO) {
            detalhe_longo()
        } else {
            alloc::format!("{i}")
        },
    }
}

/// As duas cadeias locais com `n` registros — `a` por `anexar`, `b` por
/// `anexar_preparado` —, no limite do anel: o mesmo tamanho, o mesmo
/// primeiro guardado, a mesma âncora — a gênese até sair o primeiro, e o
/// elo dele depois —, a mesma lacuna para o journal, a mesma cabeça e os
/// mesmos registros; a fotografia dos `Arc` confere como `audit.verify` a
/// confere, e acusa o registro adulterado no primeiro guardado e no último;
/// e as duas famílias de leitura dão os mesmos registros, da âncora em
/// diante.
fn no_limite(a: &Cadeia, b: &Cadeia, n: u64, elo_do_primeiro: [u8; 32]) -> Resultado {
    let guardados = n.min(CAPACIDADE);
    let primeiro = n - guardados + 1;
    let ancora = if n > CAPACIDADE {
        elo_do_primeiro
    } else {
        GENESE
    };
    for c in [a, b] {
        let lacuna = c.lacuna_depois_de(0);
        let lacuna_certa = if n > CAPACIDADE {
            lacuna
                == Some(Lacuna {
                    primeira: 1,
                    ultima: primeiro - 1,
                    elo: ancora,
                })
        } else {
            lacuna.is_none()
        };
        if c.guardados() as u64 != guardados
            || c.ultima_seq() != n
            || c.ancora() != ancora
            || c.ultimos(usize::MAX).next().map(|r| r.seq) != Some(primeiro)
            || c.verificar() != Ok(c.cabeca())
            || !lacuna_certa
        {
            crate::log_error!(
                "teste",
                "{} registros: {} guardados, ultimo {}",
                n,
                c.guardados(),
                c.ultima_seq()
            );
            return Err(
                "a cadeia local no limite do anel nao tem o tamanho, a ancora ou a lacuna dele",
            );
        }
    }
    if a.cabeca() != b.cabeca() || !a.ultimos(usize::MAX).eq(b.ultimos(usize::MAX)) {
        return Err("anexar e anexar_preparado fizeram cadeias diferentes");
    }
    let tirada: Vec<Arc<Registro>> = b.ultimos_compartilhados(usize::MAX).cloned().collect();
    let refeita = politica::auditoria::verificar(b.ancora(), tirada.iter().map(|r| &**r));
    if tirada.len() as u64 != guardados || refeita != Ok(b.cabeca()) {
        return Err("a fotografia dos Arc no limite do anel nao confere como a cadeia");
    }
    for k in [0, tirada.len() - 1] {
        let mut adulterada = tirada.clone();
        let mut r = Registro::clone(&adulterada[k]);
        r.evento.detalhe.push('x');
        let seq = r.seq;
        adulterada[k] = Arc::new(r);
        if politica::auditoria::verificar(b.ancora(), adulterada.iter().map(|r| &**r)) != Err(seq) {
            return Err("a fotografia com um registro adulterado conferiu, ou acusou outro");
        }
    }
    let mut seqs = Vec::with_capacity(crate::autorizacao::CAPACIDADE_DA_AUDITORIA);
    if !mesmos_registros(
        b.guardados_depois_de(0),
        b.compartilhados_depois_de(0),
        &mut seqs,
    ) || seqs.first() != Some(&primeiro)
        || seqs.len() as u64 != guardados
    {
        return Err(
            "depois de zero, os compartilhados nao sao os guardados, do primeiro guardado em diante",
        );
    }
    Ok(())
}

/// O anel no limite, em duas cadeias locais da capacidade da auditoria —
/// a global não recomeça —: 1023, 1024 e 1025 registros. `anexar_preparado`
/// devolve o que sai pela ponta só no 1025, e o que sai é o primeiro, só
/// com a referência de quem o recebeu; o detalhe acima do teto é cortado
/// numa fronteira de caractere, e o tempo que voltava sobe ao do anterior,
/// pelos dois caminhos.
fn o_anel_no_limite() -> Resultado {
    let mut a = Cadeia::nova(crate::autorizacao::CAPACIDADE_DA_AUDITORIA);
    let mut b = Cadeia::nova(crate::autorizacao::CAPACIDADE_DA_AUDITORIA);
    let mut elo_do_primeiro = GENESE;
    for i in 1..=CAPACIDADE + 1 {
        let e = evento_local(i);
        let na = a.anexar(e.clone());
        let (nb, saiu) = b.anexar_preparado(Preparado::novo(e));
        if na != i || nb != i {
            return Err("as duas cadeias locais numeraram diferente");
        }
        if i == 1 {
            elo_do_primeiro = b.cabeca();
        }
        let saiu_certo = match &saiu {
            None => i <= CAPACIDADE,
            Some(s) => {
                i == CAPACIDADE + 1
                    && s.seq == 1
                    && s.elo == elo_do_primeiro
                    && b.ancora() == s.elo
                    && Arc::strong_count(s) == 1
            }
        };
        if !saiu_certo {
            crate::log_error!(
                "teste",
                "registro {}: saiu {:?}",
                i,
                saiu.as_ref().map(|s| s.seq)
            );
            return Err("anexar_preparado devolveu o que saiu pela ponta fora da hora, ou outro");
        }
        if i >= CAPACIDADE - 1 {
            no_limite(&a, &b, i, elo_do_primeiro)?;
        }
    }
    let cortado = detalhe_cortado();
    if cortado.len() >= MAIOR_DETALHE {
        return Err("o detalhe do caso nao passa do teto no meio de um caractere");
    }
    for c in [&a, &b] {
        for k in (VOLTA_O_TEMPO..=CAPACIDADE).step_by(VOLTA_O_TEMPO as usize) {
            if c.registro(k).map(|r| r.evento.ts_ms) != Some((k - 1) * 10) {
                return Err("o tempo de um registro voltou, ou nao subiu ao do anterior");
            }
        }
        for k in (PASSA_DO_TETO..=CAPACIDADE).step_by(PASSA_DO_TETO as usize) {
            if c.registro(k).map(|r| r.evento.detalhe.as_str()) != Some(cortado.as_str()) {
                return Err("o detalhe acima do teto nao foi cortado na fronteira de caractere");
            }
        }
    }
    Ok(())
}

/// `audit.verify` e `audit.head` com o anel cheio — na mesma hora, pelo
/// handler, e pelo gate, com a decisão do próprio pedido —, e o anel no
/// limite da capacidade, numa cadeia local.
pub(super) fn a_verificacao_e_a_cabeca_no_limite() -> Resultado {
    anel_cheio_com_saidos()?;
    cabeca_e_verificacao_na_mesma_hora()?;
    verificacao_e_cabeca_pelo_gate()?;
    o_anel_no_limite()?;
    persistencia::gravar_auditoria()
}

// ---------------------------------------------------------------------------
// A resposta do audit.verify: os ramos, e sem memória para a fotografia
// ---------------------------------------------------------------------------

/// Os três ramos da resposta de `audit.verify`, pela função que o handler
/// usa para escrevê-la: a cadeia que confere, com a cabeça e quantos
/// conferiu; a que não confere, com o número do primeiro que não confere e
/// nada mais; e a que não existe.
fn os_ramos_da_resposta() -> Resultado {
    let casos = [
        (
            Some((Ok([0xab; 32]), 5)),
            alloc::format!(
                r#"{{"ok":true,"head":"{}","checked":5}}"#,
                sigilo::hex(&[0xab; 32])
            ),
        ),
        (
            Some((Err(7), 3)),
            String::from(r#"{"ok":false,"failed_at":7}"#),
        ),
        (
            None,
            String::from(r#"{"error":"a auditoria nao foi iniciada"}"#),
        ),
    ];
    for (r, esperado) in casos {
        let mut buffer = Buffer::novo();
        {
            let mut w = JsonWriter::new(&mut buffer);
            escrita(crate::agent::commands::escrever_verificacao(&mut w, r))?;
        }
        conferir(&buffer, &esperado)?;
    }
    Ok(())
}

/// O lugar da fotografia que nenhum heap do kernel tem: o dobro do maior.
const LUGAR_QUE_NAO_HA: usize =
    2 * crate::heap::HEAP_MAXIMO / core::mem::size_of::<Arc<Registro>>();

/// O lugar da fotografia menor que o anel cheio: a reserva é dada, mas não
/// cabe o anel.
const LUGAR_MENOR_QUE_O_ANEL: usize = 4;

/// Roda `f` com o caminho de `audit.verify` trocado — o lugar da
/// fotografia, e o post-mortem visto só por ele —, e o destroca depois,
/// sempre.
fn com_o_caminho_trocado<R>(lugar: Option<usize>, post_mortem: bool, f: impl FnOnce() -> R) -> R {
    verificacao::trocar_o_lugar(lugar);
    verificacao::como_no_post_mortem(post_mortem);
    let r = f();
    verificacao::trocar_o_lugar(None);
    verificacao::como_no_post_mortem(false);
    r
}

/// `audit.verify` pelo gate com o caminho trocado: a mesma resposta — o
/// anel inteiro conferido, com a cabeça que inclui a decisão do próprio
/// pedido —, pela conta com a trava na mão, como antes: a conta desse
/// caminho subiu, e a da fotografia não; e, com a trava na mão, nada pediu
/// nem devolveu memória. Com `recusada`, o alocador recusou a reserva da
/// fotografia.
fn verificar_com_a_trava(
    caminho: &str,
    lugar: Option<usize>,
    post_mortem: bool,
    recusada: bool,
) -> Resultado {
    for _ in 0..TENTATIVAS {
        let antes = anel();
        let falhas = crate::heap::estatisticas().falhas;
        let (fotografias, com_a_trava) = verificacao::contas();
        let (pedido, pedidos, devolucoes) = com_o_caminho_trocado(lugar, post_mortem, || {
            vigiado(|| pedir_ao_gate("audit.verify", "{}"))
        });
        let verificada = match pedido {
            PeloGate::Resultado(r) => r,
            PeloGate::Taxa => {
                esperar_ms(5);
                continue;
            }
            PeloGate::Recusa => return Err("o gate recusou o audit.verify do caminho trocado"),
        };
        let recusas = crate::heap::estatisticas().falhas - falhas;
        let contas = verificacao::contas();
        let (ultimo, cabeca) = crate::autorizacao::com_auditoria(|c| (c.ultima_seq(), c.cabeca()))
            .ok_or("a auditoria nao existe")?;
        if ultimo != antes.ultimo + 1 {
            continue;
        }
        let j = Json(verificada.as_bytes());
        if !confere_o_anel_inteiro(j) || texto(j, "head") != Some(sigilo::hex(&cabeca).as_str()) {
            crate::log_error!("teste", "{}: audit.verify: {}", caminho, verificada);
            return Err("pela conta com a trava, o audit.verify nao deu a mesma resposta");
        }
        if contas.0 != fotografias || contas.1 <= com_a_trava {
            crate::log_error!(
                "teste",
                "{}: (pela fotografia, com a trava) de {:?} para {:?}",
                caminho,
                (fotografias, com_a_trava),
                contas
            );
            return Err("o audit.verify do caminho trocado nao fez a conta com a trava");
        }
        if recusada && recusas == 0 {
            return Err("o alocador nao recusou a reserva de uma fotografia maior que o heap");
        }
        return sem_memoria_com_a_trava(
            caminho,
            pedidos,
            devolucoes,
            "o audit.verify pela conta com a trava pediu ou devolveu memoria com ela na mao",
        );
    }
    Err("a auditoria nao ficou quieta em nenhuma tentativa do audit.verify do caminho trocado")
}

/// A conta com a trava nos três caminhos que levam a ela, sem estilhaçar o
/// heap do kernel nem entrar no post-mortem: sem memória para a fotografia —
/// o alocador recusa a reserva de verdade, de um lugar maior que o heap —;
/// com um lugar menor que o anel, que faria o vetor crescer com a trava; e
/// no post-mortem, visto só por `audit.verify`, sem reserva nenhuma.
fn a_verificacao_pela_conta_com_a_trava() -> Resultado {
    verificar_com_a_trava(
        "sem memoria para a fotografia",
        Some(LUGAR_QUE_NAO_HA),
        false,
        true,
    )?;
    verificar_com_a_trava(
        "um lugar menor que o anel",
        Some(LUGAR_MENOR_QUE_O_ANEL),
        false,
        false,
    )?;
    verificar_com_a_trava("no post-mortem", None, true, false)
}

/// A resposta de `audit.verify` nos três ramos, e a mesma resposta pela
/// conta com a trava, nos três caminhos que levam a ela.
pub(super) fn a_resposta_do_verify_em_cada_ramo_e_pela_conta_com_a_trava() -> Resultado {
    os_ramos_da_resposta()?;
    anel_cheio_com_saidos()?;
    a_verificacao_pela_conta_com_a_trava()?;
    persistencia::gravar_auditoria()
}

// ---------------------------------------------------------------------------
// As contas da trava
// ---------------------------------------------------------------------------

/// Roda `f` com este fio vigiado; devolve o que `f` devolveu, e os pedidos e
/// as devoluções ao alocador que ele fez com a trava da auditoria na mão. A
/// vigia acaba antes de devolver, sempre.
fn vigiado<R>(f: impl FnOnce() -> R) -> (R, u64, u64) {
    alocacoes::vigiar(crate::fios::id_atual());
    let r = f();
    let pedidos = alocacoes::esquecer();
    (r, pedidos, alocacoes::devolucoes())
}

/// Nenhum pedido e nenhuma devolução com a trava na mão; senão, `erro`.
fn sem_memoria_com_a_trava(
    o_que: &str,
    pedidos: u64,
    devolucoes: u64,
    erro: &'static str,
) -> Resultado {
    if pedidos != 0 || devolucoes != 0 {
        crate::log_error!(
            "teste",
            "{}: {} pedidos e {} devolucoes ao alocador com a trava da auditoria na mao",
            o_que,
            pedidos,
            devolucoes
        );
        return Err(erro);
    }
    Ok(())
}

/// Um pedido e uma devolução direto ao alocador — por `alloc::alloc`, o LLVM
/// poderia eliminar o par. Verdadeiro se o alocador deu o bloco.
fn par_ao_alocador() -> bool {
    let bloco = Layout::new::<[u64; 2]>();
    let p = crate::heap::tentar_alocar(bloco);
    if !p.is_null() {
        // SAFETY: devolvemos o mesmo ponteiro, com o mesmo layout.
        unsafe { crate::heap::devolver(p, bloco) };
    }
    !p.is_null()
}

/// O par do outro fio do controle: 1 se ele o fez com a trava na mão, 2 se
/// o alocador não deu o bloco; zero enquanto não fez.
static PAR_DO_OUTRO: AtomicU64 = AtomicU64::new(0);

extern "C" fn par_de_outro_fio(_: u64) -> ! {
    let alocou = crate::autorizacao::com_auditoria(|_| par_ao_alocador()) == Some(true);
    PAR_DO_OUTRO.store(if alocou { 1 } else { 2 }, SeqCst);
    crate::fios::terminar()
}

/// Os controles das contas da suíte. Com a trava da auditoria na mão, um
/// pedido e uma devolução feitos de propósito, direto ao alocador, entram
/// cada um na sua conta; a vigia seguinte começa do zero; sem a trava, nada
/// conta; com ela, mas vigiando um fio que não é este, nada conta; o par
/// feito por outro fio, com a trava na mão dele, não conta na vigia deste;
/// e, depois da vigia, nada mais entra. Sem isto, o "nenhum pedido e
/// nenhuma devolução" dos casos passaria também com as contas cegas.
fn as_contas_veem_a_trava() -> Resultado {
    let eu = crate::fios::id_atual();
    alocacoes::vigiar(eu);
    let com_a_trava = crate::autorizacao::com_auditoria(|_| par_ao_alocador());
    let contas_com_a_trava = (alocacoes::esquecer(), alocacoes::devolucoes());
    alocacoes::vigiar(eu);
    let contas_da_seguinte = (alocacoes::esquecer(), alocacoes::devolucoes());
    alocacoes::vigiar(eu);
    let sem_a_trava = par_ao_alocador();
    let contas_sem_a_trava = (alocacoes::esquecer(), alocacoes::devolucoes());
    // Um fio que não existe: `u64::MAX - 1` nunca é o número de um fio.
    alocacoes::vigiar(u64::MAX - 1);
    let de_outro_vigiado = crate::autorizacao::com_auditoria(|_| par_ao_alocador());
    let contas_de_outro_vigiado = (alocacoes::esquecer(), alocacoes::devolucoes());
    // Outro fio de verdade, com a trava na mão dele, enquanto este é o
    // vigiado.
    PAR_DO_OUTRO.store(0, SeqCst);
    alocacoes::vigiar(eu);
    let nasceu = crate::fios::criar("teste-trava-par", par_de_outro_fio, 0).is_ok();
    let limite = crate::tempo::uptime_ms() + 10_000;
    while nasceu && PAR_DO_OUTRO.load(SeqCst) == 0 && crate::tempo::uptime_ms() < limite {
        crate::fios::ceder();
    }
    let contas_do_outro_fio = (alocacoes::esquecer(), alocacoes::devolucoes());
    let depois = crate::autorizacao::com_auditoria(|_| par_ao_alocador());
    let contas_depois = (alocacoes::esquecer(), alocacoes::devolucoes());
    if !nasceu || PAR_DO_OUTRO.load(SeqCst) != 1 {
        return Err("o outro fio do controle nao fez o par com a trava na mao");
    }
    if com_a_trava != Some(true)
        || !sem_a_trava
        || de_outro_vigiado != Some(true)
        || depois != Some(true)
    {
        return Err("o alocador nao deu o bloco do controle das contas");
    }
    if contas_com_a_trava != (1, 1)
        || contas_da_seguinte != (0, 0)
        || contas_sem_a_trava != (0, 0)
        || contas_de_outro_vigiado != (0, 0)
        || contas_do_outro_fio != (0, 0)
        || contas_depois != (0, 0)
    {
        crate::log_error!(
            "teste",
            "(pedidos, devolucoes): com a trava {:?}, na vigia seguinte {:?}, sem a trava {:?}, vigiando outro {:?}, do outro fio {:?}, depois da vigia {:?}",
            contas_com_a_trava,
            contas_da_seguinte,
            contas_sem_a_trava,
            contas_de_outro_vigiado,
            contas_do_outro_fio,
            contas_depois
        );
        return Err("as contas da suite nao veem a trava da auditoria na mao, ou veem fora dela");
    }
    Ok(())
}

/// O anel que cresce do zero ao cheio, numa cadeia local da capacidade da
/// auditoria, anexado pelo caminho do gate — o registro preparado antes, e
/// `anexar_preparado` com a trava da auditoria na mão, a de verdade —, não
/// pede nem devolve memória com ela: `Cadeia::nova` reservou o anel
/// inteiro, e o que sai pela ponta volta a quem anexou. E o controle:
/// `anexar` — que solta ali mesmo o que sai — ao anel cheio, com a trava na
/// mão, devolve memória, e as contas veem.
fn o_anel_que_cresce_nao_pede_memoria() -> Resultado {
    let mut c = Cadeia::nova(crate::autorizacao::CAPACIDADE_DA_AUDITORIA);
    alocacoes::vigiar(crate::fios::id_atual());
    let mut certo = true;
    for i in 1..=CAPACIDADE + 1 {
        let p = Preparado::novo(evento_local(i));
        match crate::autorizacao::com_auditoria(|_| c.anexar_preparado(p)) {
            // O que saiu é solto aqui, com a trava solta.
            Some((seq, saiu)) if seq == i && saiu.is_none() == (i <= CAPACIDADE) => drop(saiu),
            _ => {
                certo = false;
                break;
            }
        }
    }
    let pedidos = alocacoes::esquecer();
    let devolucoes = alocacoes::devolucoes();
    if !certo {
        return Err("o anel local que cresce numerou errado, ou devolveu o que saiu fora da hora");
    }
    sem_memoria_com_a_trava(
        "o anel que cresce do zero ao cheio",
        pedidos,
        devolucoes,
        "anexar ao anel que cresce pediu ou devolveu memoria com a trava: o anel nao foi reservado inteiro na criacao",
    )?;
    let e = evento_local(CAPACIDADE + 2);
    let (seq, _, devolucoes) = vigiado(|| crate::autorizacao::com_auditoria(|_| c.anexar(e)));
    if seq != Some(CAPACIDADE + 2) || devolucoes == 0 {
        return Err(
            "anexar ao anel cheio com a trava na mao nao devolveu memoria: as contas nao veem as devolucoes do anel",
        );
    }
    Ok(())
}

/// Um pedido pelo gate com este fio vigiado, repetido se a taxa recusou: o
/// resultado, e os pedidos e as devoluções com a trava na mão.
fn vigiado_pelo_gate(metodo: &str, params: &str) -> Result<(String, u64, u64), &'static str> {
    for _ in 0..TENTATIVAS {
        let (r, pedidos, devolucoes) = vigiado(|| pedir_ao_gate(metodo, params));
        match r {
            PeloGate::Resultado(r) => return Ok((r, pedidos, devolucoes)),
            PeloGate::Taxa => esperar_ms(5),
            PeloGate::Recusa => return Err("o gate recusou um pedido do caso"),
        }
    }
    Err("a taxa do sistema recusou um pedido do caso em todas as tentativas")
}

/// Com a trava da auditoria na mão, nada pede nem devolve memória ao
/// alocador: o anel que cresce do zero ao cheio; o registro anexado pelo
/// gate ao anel cheio — e o que saiu dele é devolvido de fato, depois —;
/// os pedidos inteiros pelo gate, a decisão e o handler: `audit.head`,
/// `audit.tail` de 128 com e sem `after`, `audit.verify` — pela fotografia
/// —, e a declaração ancorada numa decisão, que lê o registro dela; e a
/// política lida de novo, com a cadeia de pé.
pub(super) fn nada_se_pede_nem_se_devolve_com_a_trava() -> Resultado {
    as_contas_veem_a_trava()?;
    o_anel_que_cresce_nao_pede_memoria()?;
    anel_cheio_com_saidos()?;

    // O registro anexado pelo gate ao anel cheio. O mais velho sai pela
    // ponta, e ninguém mais o segura: o caso guarda só uma referência fraca,
    // que não o mantém vivo.
    let antes = anel();
    let mais_velho: Option<Weak<Registro>> = crate::autorizacao::com_auditoria(|c| {
        c.ultimos_compartilhados(usize::MAX)
            .next()
            .map(Arc::downgrade)
    })
    .flatten();
    let mais_velho = mais_velho.ok_or("o anel da auditoria esta vazio")?;
    let liberacoes = crate::heap::estatisticas().liberacoes;
    let (seq, pedidos, devolucoes) = vigiado(|| auditar(VIGIADO, "anexado com o fio vigiado"));
    let depois = anel();
    sem_memoria_com_a_trava(
        "o registro anexado pelo gate",
        pedidos,
        devolucoes,
        "o registro anexado pelo gate ao anel cheio pediu ou devolveu memoria com a trava da auditoria na mao",
    )?;
    // Pela ponta, um a um: o anel continua cheio, e andou ao menos o
    // registro do caso — o coletor do kernel pode ter auditado um prazo
    // vencido no meio.
    if seq <= antes.ultimo
        || depois.ultimo < seq
        || depois.primeiro <= antes.primeiro
        || depois.ultimo - depois.primeiro + 1 != CAPACIDADE
        || depois.guardados != CAPACIDADE
    {
        return Err("o anexar ao anel cheio nao tirou o mais velho pela ponta");
    }
    // Devolvido de fato: nenhuma referência forte sobrou — nem no anel, nem
    // com quem anexou —, e o alocador contou as devoluções.
    if mais_velho.upgrade().is_some() {
        return Err("o registro que saiu pela ponta nao foi devolvido: alguem ainda o segura");
    }
    drop(mais_velho);
    if crate::heap::estatisticas().liberacoes <= liberacoes {
        return Err("o alocador nao contou a devolucao do registro que saiu pela ponta");
    }

    // Os pedidos inteiros pelo gate: a decisão de cada um entra no anel
    // cheio, e o handler lê com a trava.
    let (cabeca, pedidos, devolucoes) = vigiado_pelo_gate("audit.head", "{}")?;
    sem_memoria_com_a_trava(
        "audit.head pelo gate",
        pedidos,
        devolucoes,
        "um audit.head pelo gate pediu ou devolveu memoria com a trava da auditoria na mao",
    )?;
    if numero(Json(cabeca.as_bytes()), "stored") != Some(CAPACIDADE) {
        return Err("o audit.head pelo gate nao viu o anel cheio");
    }
    let primeiro = anel().primeiro;
    let caudas = [
        alloc::format!(r#"{{"after":{},"count":128}}"#, primeiro + 100),
        String::from(r#"{"count":128}"#),
    ];
    for params in &caudas {
        let (cauda, pedidos, devolucoes) = vigiado_pelo_gate("audit.tail", params)?;
        sem_memoria_com_a_trava(
            params,
            pedidos,
            devolucoes,
            "um audit.tail de 128 pelo gate pediu ou devolveu memoria com a trava da auditoria na mao",
        )?;
        if registros_do_resultado(&cauda)?.count() != MAIOR_CAUDA as usize {
            return Err("o audit.tail de 128 do caso nao trouxe 128 registros");
        }
    }
    let contas = verificacao::contas();
    let (verificada, pedidos, devolucoes) = vigiado_pelo_gate("audit.verify", "{}")?;
    pela_fotografia(contas)?;
    sem_memoria_com_a_trava(
        "audit.verify pelo gate",
        pedidos,
        devolucoes,
        "um audit.verify pelo gate pediu ou devolveu memoria com a trava da auditoria na mao",
    )?;
    if !confere_o_anel_inteiro(Json(verificada.as_bytes())) {
        crate::log_error!("teste", "audit.verify: {}", verificada);
        return Err("o audit.verify vigiado nao conferiu o anel inteiro");
    }

    // A declaração ancorada na decisão do audit.head deste fio: o handler
    // lê o registro dela com a trava.
    let d =
        decisao_deste_fio("audit.head").ok_or("a decisao do audit.head do caso saiu do anel")?;
    let params = alloc::format!(
        r#"{{"event":"teste.trava","subject":"ancora","outcome":"ok","decision":{d}}}"#
    );
    let (declarada, pedidos, devolucoes) = vigiado_pelo_gate("audit.declare", &params)?;
    sem_memoria_com_a_trava(
        "audit.declare ancorada numa decisao",
        pedidos,
        devolucoes,
        "a declaracao ancorada numa decisao pediu ou devolveu memoria com a trava da auditoria na mao",
    )?;
    let j = Json(declarada.as_bytes());
    let ancorada = alloc::format!("ancorada em {d} audit.head");
    let gravada = numero(j, "record").and_then(|n| {
        crate::autorizacao::com_auditoria(|c| {
            c.registro(n).map(|r| r.evento.detalhe.contains(&ancorada))
        })
        .flatten()
    });
    if j.member("declared").and_then(|x| x.as_bool()) != Some(true) || gravada != Some(true) {
        crate::log_error!("teste", "audit.declare: {}", declarada);
        return Err("a declaracao ancorada na decisao do caso nao foi gravada com a ancora");
    }

    // A política lida de novo com a cadeia de pé: a cadeia nova que
    // `carregar` faz sobra, e é solta fora da trava; e o registro da carga
    // entra no anel cheio como os do gate.
    let antes = anel();
    let ((), pedidos, devolucoes) = vigiado(crate::autorizacao::carregar);
    sem_memoria_com_a_trava(
        "carregar com a cadeia de pe",
        pedidos,
        devolucoes,
        "carregar a politica com a cadeia de pe pediu ou devolveu memoria com a trava da auditoria na mao",
    )?;
    if anel().ultimo <= antes.ultimo {
        return Err("carregar a politica nao gravou o registro da carga");
    }
    persistencia::gravar_auditoria()
}

// ---------------------------------------------------------------------------
// A âncora de uma declaração fora da janela
// ---------------------------------------------------------------------------

/// Uma decisão `ALLOW` deste fio — um `audit.head` pelo gate — em segundo no
/// anel: o pedido seguinte grava a decisão dele antes do handler, o mais
/// velho sai, e ela é o primeiro guardado na hora do handler. Devolve o
/// número dela; `None` se mais alguém auditou no meio, e ela não ficou em
/// segundo.
fn decisao_em_segundo_no_anel() -> Result<Option<u64>, &'static str> {
    pelo_gate("audit.head", "{}")?;
    let d0 = decisao_deste_fio("audit.head")
        .ok_or("a decisao do audit.head do caso nao esta no anel")?;
    let depois_dela = anel().ultimo - d0;
    let Some(faltam) = (CAPACIDADE - 2).checked_sub(depois_dela) else {
        return Ok(None);
    };
    auditar_enchendo(faltam, "empurra a decisao para a frente do anel")?;
    let segundo =
        crate::autorizacao::com_auditoria(|c| c.ultimos(usize::MAX).nth(1).map(|r| r.seq))
            .flatten();
    Ok((segundo == Some(d0)).then_some(d0))
}

/// Uma declaração deste fio ancorada na decisão `ancora`, com a decisão
/// `d0` em segundo no anel: a resposta, se a hora foi a prevista — a decisão
/// da declaração e o registro dela entraram, e nada mais, e `d0` foi o
/// primeiro guardado na hora do handler —, e quantas declarações a
/// auditoria gravou.
fn declarar_com_a_decisao_na_frente(
    d0: u64,
    ancora: u64,
) -> Result<Option<(String, usize)>, &'static str> {
    let antes = anel();
    let params = alloc::format!(
        r#"{{"event":"teste.trava","subject":"janela","outcome":"ok","decision":{ancora}}}"#
    );
    let r = pelo_gate("audit.declare", &params)?;
    let depois = anel();
    if depois.ultimo != antes.ultimo + 2 || depois.primeiro != d0 + 1 {
        return Ok(None);
    }
    Ok(Some((r, declaracoes_desde(antes.ultimo))))
}

/// A âncora pedida por uma declaração, dada a decisão que ficou em primeiro
/// guardado.
type AncoraDe = fn(u64) -> u64;

/// A âncora de uma declaração tem de estar na janela da auditoria. Com o
/// primeiro guardado — na hora do handler — sendo uma decisão `ALLOW` do
/// mesmo processo, a decisão zero e uma de antes dele são
/// `INVALID_ARGUMENT`, com o motivo da janela, e nada é declarado: a
/// posição do primeiro guardado não é a âncora pedida. E ele mesmo ancora.
pub(super) fn a_ancora_fora_da_janela() -> Resultado {
    anel_cheio_com_saidos()?;
    let fora: [(&str, AncoraDe); 2] = [
        ("a decisao zero", |_| 0),
        ("uma decisao de antes do primeiro guardado", |d0| d0 - 5),
    ];
    for (o_que, ancora) in fora {
        let mut conferida = false;
        for _ in 0..TENTATIVAS {
            let Some(d0) = decisao_em_segundo_no_anel()? else {
                continue;
            };
            let Some((r, declaradas)) = declarar_com_a_decisao_na_frente(d0, ancora(d0))? else {
                continue;
            };
            let j = Json(r.as_bytes());
            if j.member("declared").and_then(|x| x.as_bool()) != Some(false)
                || texto(j, "code") != Some(Codigo::InvalidArgument.nome())
                || texto(j, "error") != Some("a decisao nao esta na janela da auditoria")
                || declaradas != 0
            {
                crate::log_error!("teste", "{}: {}", o_que, r);
                return Err("uma ancora fora da janela da auditoria foi aceita");
            }
            conferida = true;
            break;
        }
        if !conferida {
            return Err(
                "a auditoria nao ficou quieta em nenhuma tentativa da ancora fora da janela",
            );
        }
    }
    for _ in 0..TENTATIVAS {
        let Some(d0) = decisao_em_segundo_no_anel()? else {
            continue;
        };
        let Some((r, declaradas)) = declarar_com_a_decisao_na_frente(d0, d0)? else {
            continue;
        };
        let j = Json(r.as_bytes());
        let ancorada = alloc::format!("ancorada em {d0} audit.head");
        let gravada = numero(j, "record").and_then(|n| {
            crate::autorizacao::com_auditoria(|c| {
                c.registro(n).map(|r| r.evento.detalhe.contains(&ancorada))
            })
            .flatten()
        });
        if j.member("declared").and_then(|x| x.as_bool()) != Some(true)
            || declaradas != 1
            || gravada != Some(true)
        {
            crate::log_error!("teste", "a decisao {} na frente do anel: {}", d0, r);
            return Err("o primeiro guardado, uma decisao do mesmo processo, nao ancorou");
        }
        return persistencia::gravar_auditoria();
    }
    Err("a auditoria nao ficou quieta em nenhuma tentativa da ancora no primeiro guardado")
}

// ---------------------------------------------------------------------------
// O registro que sai pela ponta
// ---------------------------------------------------------------------------

/// Com o anel cheio, o caso segura o `Arc` do mais velho, e um registro é
/// anexado pelo gate: o mais velho sai do anel — o primeiro guardado passa a
/// ser o seguinte, que continua a cadeia do elo dele, e a âncora é o elo
/// dele —, os outros guardados são os mesmos objetos, na mesma ordem, com o
/// novo no fim; quem anexou soltou a parte dele — só o caso e a fotografia
/// de antes o seguram —; o `Arc` guardado continua lendo o mesmo registro; e
/// a cadeia continua conferindo, pelo handler e pelo gate. Se mais alguém
/// auditou no meio, de novo.
pub(super) fn o_registro_que_sai_pela_ponta() -> Resultado {
    anel_cheio_com_saidos()?;
    for _ in 0..TENTATIVAS {
        if o_mais_velho_sai_pela_ponta()? {
            return persistencia::gravar_auditoria();
        }
    }
    Err("a auditoria nao ficou quieta em nenhuma tentativa do registro que sai pela ponta")
}

/// Uma tentativa de [`o_registro_que_sai_pela_ponta`]: falso se a hora não
/// foi a prevista — alguém mais auditou entre a fotografia de antes e a de
/// depois.
fn o_mais_velho_sai_pela_ponta() -> Result<bool, &'static str> {
    let (antes, _) = fotografia();
    let mais_velho = antes
        .first()
        .cloned()
        .ok_or("o anel da auditoria esta vazio")?;
    let copia = Registro::clone(&mais_velho);
    // Três donos: o anel, a fotografia e o caso. Outro, só de quem leu ou
    // anexou no meio.
    if Arc::strong_count(&mais_velho) != 3 {
        crate::log_info!(
            "teste",
            "trava: o mais velho tem {} donos; de novo",
            Arc::strong_count(&mais_velho)
        );
        return Ok(false);
    }
    let (seq, pedidos, devolucoes) = vigiado(|| auditar(SAI, "o mais velho sai pela ponta"));
    sem_memoria_com_a_trava(
        "o anexar com o mais velho seguro pelo caso",
        pedidos,
        devolucoes,
        "o registro anexado pelo gate pediu ou devolveu memoria com a trava da auditoria na mao",
    )?;
    let (depois, ancora) = fotografia();
    if anel_da(&depois) != anel_da(&antes).andado() || depois.last().map(|r| r.seq) != Some(seq) {
        return Ok(false);
    }
    let o_mesmo_anel_andado = depois.len() == antes.len()
        && antes[1..]
            .iter()
            .zip(depois.iter())
            .all(|(x, y)| Arc::ptr_eq(x, y))
        && depois.last().map(|r| r.seq) == Some(seq);
    if !o_mesmo_anel_andado {
        return Err(
            "o anel depois do anexar nao e o de antes sem o mais velho e com o novo no fim",
        );
    }
    let primeiro = depois[0].seq;
    if primeiro != copia.seq + 1 || ancora != copia.elo || depois[0].anterior != copia.elo {
        return Err(
            "a ancora nao e o elo do que saiu pela ponta, ou o primeiro guardado nao continua dele",
        );
    }
    if crate::autorizacao::com_auditoria(|c| c.registro(copia.seq).is_some()) != Some(false) {
        return Err("o registro que saiu pela ponta ainda se acha no anel pelo numero");
    }
    // Quem anexou soltou o que saiu: sobram a fotografia de antes e o caso.
    if Arc::strong_count(&mais_velho) != 2 {
        crate::log_error!("teste", "{} donos", Arc::strong_count(&mais_velho));
        return Err("o registro que saiu pela ponta ficou com o anel ou com quem anexou");
    }
    drop(antes);
    if Arc::strong_count(&mais_velho) != 1 || *mais_velho != copia {
        return Err("o Arc guardado do que saiu nao le mais o mesmo registro, ou tem outro dono");
    }
    // Segurar o Arc não segura o registro na janela: a cauda depois do de
    // antes dele começa no primeiro guardado.
    let seguinte = crate::autorizacao::com_auditoria(|c| {
        c.compartilhados_depois_de(copia.seq - 1)
            .next()
            .map(|r| r.seq)
    })
    .flatten();
    if seguinte != Some(primeiro) {
        return Err("a cauda depois do que saiu nao comeca no primeiro guardado");
    }
    drop(depois);
    cabeca_e_verificacao_na_mesma_hora()?;
    let v = pelo_gate("audit.verify", "{}")?;
    if !confere_o_anel_inteiro(Json(v.as_bytes())) {
        crate::log_error!("teste", "audit.verify: {}", v);
        return Err("o audit.verify pelo gate nao confere depois que o mais velho saiu");
    }
    drop(mais_velho);
    Ok(true)
}

// ---------------------------------------------------------------------------
// Os fios dos casos concorrentes
// ---------------------------------------------------------------------------

/// Quantos produtores, e quantos registros cada um audita, nos casos dos
/// leitores: juntos, mais que um anel — o anel dá a volta no meio deles.
const PRODUTORES: u64 = 3;
const POR_PRODUTOR: u64 = 400;
const _: () = assert!(PRODUTORES * POR_PRODUTOR > CAPACIDADE);

/// Quantos registros cada leitura do acompanhante pede: o lote do NSF.
const LOTE: u64 = 64;

/// De quantos em quantos registros novos o verificador verifica.
const INTERVALO_DA_VERIFICACAO: u64 = 16;

/// Quantos registros podem esperar o journal: quem audita nos casos
/// concorrentes espera enquanto há isso, ou mais, por gravar. Com meio
/// anel, nenhum registro sai do anel sem ter sido gravado, e o journal tem
/// todos: é ele que confere o que os leitores viram.
const FOLGA: u64 = CAPACIDADE / 2;

/// Quantos registros antes do primeiro guardado o acompanhante começa: os
/// que o anel já tinha descartado, e que a primeira leitura pula.
const ANTES_DO_ANEL: u64 = 10;

/// As marcas do acompanhante, uma por número, da base dele em diante: o
/// anel do começo, a produção e, com folga, as decisões dos leitores.
const JANELA: usize = 4096;
const _: () =
    assert!(ANTES_DO_ANEL + CAPACIDADE + PRODUTORES * POR_PRODUTOR + 1024 <= JANELA as u64);

/// A marca de um número que o acompanhante pulou: o anel o tinha
/// descartado.
const SALTADO: u64 = u64::MAX;

/// Quantas cabeças do verificador o caso guarda para conferir no journal.
const MAIS_CABECAS: usize = 256;

/// Os fios ainda vivos de cada papel, os registros produzidos e quantos
/// cada produtor audita no caso.
static PRODUZINDO: AtomicU64 = AtomicU64::new(0);
static PRODUZIDOS: AtomicU64 = AtomicU64::new(0);
static POR_PRODUTOR_DO_CASO: AtomicU64 = AtomicU64::new(0);
static ACOMPANHANDO: AtomicU64 = AtomicU64::new(0);
static VERIFICANDO: AtomicU64 = AtomicU64::new(0);
static COLETANDO: AtomicU64 = AtomicU64::new(0);
/// O caso desistiu: todos param.
static PARAR: AtomicBool = AtomicBool::new(false);
/// Os produtores passam da metade: a compactação começou, ou o caso não
/// compacta.
static NO_MEIO: AtomicBool = AtomicBool::new(false);
static PARAR_DE_VERIFICAR: AtomicBool = AtomicBool::new(false);
/// O acompanhante alcança a cabeça e para.
static ALCANCAR_E_PARAR: AtomicBool = AtomicBool::new(false);
static PARAR_DE_COLETAR: AtomicBool = AtomicBool::new(false);
/// O que os fios viram fora da regra — o porquê vai para o log.
static FALHAS: AtomicU64 = AtomicU64::new(0);
/// As contas dos casos, para o relatório e para o mínimo de cada leitor.
static LEITURAS: AtomicU64 = AtomicU64::new(0);
static SALTOS: AtomicU64 = AtomicU64::new(0);
static SALTADOS: AtomicU64 = AtomicU64::new(0);
static VERIFICACOES: AtomicU64 = AtomicU64::new(0);
static TAXADAS: AtomicU64 = AtomicU64::new(0);
static PASSADAS: AtomicU64 = AtomicU64::new(0);
static FALHAS_DO_COLETOR: AtomicU64 = AtomicU64::new(0);
/// O número antes do primeiro que o acompanhante lê, e o último que ele leu.
static BASE: AtomicU64 = AtomicU64::new(0);
static LIDO_FINAL: AtomicU64 = AtomicU64::new(0);
/// O que o acompanhante viu de cada número depois da base: zero, nada; a
/// [`marca`] do elo que a leitura mostrou; ou [`SALTADO`].
static LIDOS: [AtomicU64; JANELA] = [const { AtomicU64::new(0) }; JANELA];
/// As cabeças das verificações: a marca, e os números entre os quais o
/// registro dela tem de estar.
static CABECAS: [[AtomicU64; 3]; MAIS_CABECAS] =
    [const { [const { AtomicU64::new(0) }; 3] }; MAIS_CABECAS];
static CABECAS_GUARDADAS: AtomicU64 = AtomicU64::new(0);

/// O estado dos fios dos casos, do zero.
fn zerar_os_fios() {
    for c in [
        &PRODUZINDO,
        &PRODUZIDOS,
        &POR_PRODUTOR_DO_CASO,
        &ACOMPANHANDO,
        &VERIFICANDO,
        &COLETANDO,
        &FALHAS,
        &LEITURAS,
        &SALTOS,
        &SALTADOS,
        &VERIFICACOES,
        &TAXADAS,
        &PASSADAS,
        &FALHAS_DO_COLETOR,
        &BASE,
        &LIDO_FINAL,
        &CABECAS_GUARDADAS,
    ] {
        c.store(0, SeqCst);
    }
    for b in [
        &PARAR,
        &NO_MEIO,
        &PARAR_DE_VERIFICAR,
        &ALCANCAR_E_PARAR,
        &PARAR_DE_COLETAR,
    ] {
        b.store(false, SeqCst);
    }
    for l in &LIDOS {
        l.store(0, SeqCst);
    }
    for c in &CABECAS {
        for x in c {
            x.store(0, SeqCst);
        }
    }
}

/// Todos param e saem, mesmo na falha, e o coletor do kernel volta à pausa
/// da suíte.
fn parar_os_fios() {
    PARAR.store(true, SeqCst);
    NO_MEIO.store(true, SeqCst);
    PARAR_DE_VERIFICAR.store(true, SeqCst);
    ALCANCAR_E_PARAR.store(true, SeqCst);
    PARAR_DE_COLETAR.store(true, SeqCst);
    for vivos in [&PRODUZINDO, &ACOMPANHANDO, &VERIFICANDO, &COLETANDO] {
        let _ = ate_zerar(vivos, 30_000);
    }
    persistencia::pausar_a_auditoria_de_teste(true);
}

/// Um fio viu o que não devia: o porquê no log, e a conta.
fn falhou(quem: &str, motivo: &str) {
    crate::log_error!("teste", "trava: {}: {}", quem, motivo);
    FALHAS.fetch_add(1, SeqCst);
}

/// Espera o journal levar o bastante do anel para a folga voltar. Falso se
/// o caso mandou parar.
fn esperar_a_folga() -> bool {
    loop {
        if PARAR.load(SeqCst) {
            return false;
        }
        let pendentes =
            crate::autorizacao::ultimo_registro().saturating_sub(persistencia::auditoria_gravada());
        if pendentes < FOLGA {
            return true;
        }
        crate::fios::ceder();
    }
}

/// Grava a auditoria quando metade da [`FOLGA`] espera o journal, como o
/// coletor do kernel com o anel: registros grandes, e o journal da suíte —
/// onde a compactação está pausada — não cresce com um registro de poucos
/// eventos a cada volta de quem espera. Quem audita só espera com a folga
/// inteira pendente: a gravação vem antes, e ninguém fica preso.
fn gravar_com_folga() -> Resultado {
    let pendentes =
        crate::autorizacao::ultimo_registro().saturating_sub(persistencia::auditoria_gravada());
    if pendentes >= FOLGA / 2 {
        persistencia::gravar_auditoria()?;
    }
    Ok(())
}

/// Marca o número `seq` com `valor`, uma vez só: o acompanhante que lê ou
/// pula o mesmo número duas vezes repetiu.
fn marcar(seq: u64, valor: u64) -> Resultado {
    let base = BASE.load(SeqCst);
    let i = seq
        .checked_sub(base + 1)
        .map(|i| i as usize)
        .filter(|&i| i < JANELA)
        .ok_or("um numero lido fora da janela de marcas do caso")?;
    if LIDOS[i].compare_exchange(0, valor, SeqCst, SeqCst).is_err() {
        return Err("o acompanhante leu ou pulou duas vezes o mesmo numero");
    }
    Ok(())
}

/// Um produtor: audita os registros do caso, com o número dele e o de cada
/// registro no detalhe, respeitando a folga e cedendo de vez em quando; na
/// metade, espera o caso dizer que passou dela.
extern "C" fn produtor(p: u64) -> ! {
    let quantos = POR_PRODUTOR_DO_CASO.load(SeqCst);
    for i in 0..quantos {
        if i == quantos / 2 {
            while !NO_MEIO.load(SeqCst) && !PARAR.load(SeqCst) {
                crate::fios::ceder();
            }
        }
        if !esperar_a_folga() {
            break;
        }
        crate::autorizacao::auditar_do_kernel(
            PRODUZIDO,
            "",
            Codigo::Allow,
            &alloc::format!("{p} {i}"),
        );
        PRODUZIDOS.fetch_add(1, SeqCst);
        if i % 8 == 7 {
            crate::fios::ceder();
        }
    }
    PRODUZINDO.fetch_sub(1, SeqCst);
    crate::fios::terminar()
}

/// Uma leitura do acompanhante, conferida: não vazia — a decisão dela é
/// posterior ao último lido —, no máximo o lote, em ordem, seguida, sem
/// nada já lido, cada registro com o elo refeito e o anterior encadeado. Se
/// ela continua a anterior, o primeiro tem por anterior o elo do último
/// lido; se pulou, o anel tinha descartado o que ela pulou, e o primeiro é
/// o primeiro guardado da hora do handler: entre o primeiro do anel de
/// antes do pedido e o de depois, e o de antes dele já não está no anel.
fn ler_um_lote(
    lido: &mut u64,
    ultimo_elo: &mut Option<[u8; 32]>,
    antes: u64,
    depois: u64,
    registros: &[seguranca::evento::Registro],
) -> Resultado {
    let primeiro = registros
        .first()
        .ok_or("uma leitura do acompanhante veio vazia, com a decisao dela depois do lido")?;
    if registros.len() as u64 > LOTE {
        return Err("uma leitura do acompanhante trouxe mais que o count");
    }
    if primeiro.seq <= *lido {
        crate::log_error!(
            "teste",
            "lido {}; a leitura comeca em {}",
            lido,
            primeiro.seq
        );
        return Err("uma leitura do acompanhante repetiu o que ele ja tinha lido");
    }
    if primeiro.seq > *lido + 1 {
        let ainda = crate::autorizacao::com_auditoria(|c| c.registro(primeiro.seq - 1).is_some())
            .unwrap_or(false);
        if !(antes..=depois).contains(&primeiro.seq) || ainda {
            crate::log_error!(
                "teste",
                "lido {}; a leitura comeca em {}; o anel ia de {} a {} em volta dela",
                lido,
                primeiro.seq,
                antes,
                depois
            );
            return Err(
                "o salto de uma leitura nao e o do anel: o primeiro depois dele nao e o primeiro guardado",
            );
        }
        for s in *lido + 1..primeiro.seq {
            marcar(s, SALTADO)?;
        }
        SALTOS.fetch_add(1, SeqCst);
        SALTADOS.fetch_add(primeiro.seq - *lido - 1, SeqCst);
    } else if ultimo_elo.is_some_and(|e| e != primeiro.anterior) {
        return Err("uma leitura do acompanhante nao continua o elo da anterior");
    }
    let mut seq = primeiro.seq;
    let mut anterior = primeiro.anterior;
    for r in registros {
        if r.seq != seq {
            crate::log_error!("teste", "esperado {}, veio {}", seq, r.seq);
            return Err("uma leitura do acompanhante veio fora de ordem, com buraco ou repetida");
        }
        if r.anterior != anterior || !r.elo_confere() {
            crate::log_error!("teste", "registro {}: o elo nao refaz", r.seq);
            return Err(
                "um registro lido pelo acompanhante nao refaz o elo, ou nao continua o anterior",
            );
        }
        marcar(r.seq, marca(&r.elo))?;
        anterior = r.elo;
        seq += 1;
    }
    *lido = seq - 1;
    *ultimo_elo = Some(anterior);
    Ok(())
}

/// O acompanhante: lê a cadeia como o NSF — `audit.tail` depois do último
/// lido, de [`LOTE`] em [`LOTE`] —, a primeira vez de antes do primeiro
/// guardado, depois quando há meio lote novo, e no fim até a cabeça.
fn acompanhar() -> Resultado {
    let base = BASE.load(SeqCst);
    let mut lido = base;
    let mut ultimo_elo: Option<[u8; 32]> = None;
    loop {
        if PARAR.load(SeqCst) {
            return Ok(());
        }
        let alcancar = ALCANCAR_E_PARAR.load(SeqCst);
        let cabeca = crate::autorizacao::ultimo_registro();
        if alcancar && lido >= cabeca {
            LIDO_FINAL.store(lido, SeqCst);
            return Ok(());
        }
        if !alcancar && lido != base && cabeca < lido + LOTE / 2 {
            crate::fios::ceder();
            continue;
        }
        if !alcancar && !esperar_a_folga() {
            return Ok(());
        }
        let antes = primeiro_no_anel();
        let params = alloc::format!(r#"{{"after":{lido},"count":{LOTE}}}"#);
        let Some(resultado) = pelo_gate_ate("audit.tail", &params, || PARAR.load(SeqCst))? else {
            return Ok(());
        };
        let depois = primeiro_no_anel();
        let mut registros = Vec::new();
        for o in registros_do_resultado(&resultado)? {
            registros.push(seguranca::evento::Registro::do_json(o)?);
        }
        LEITURAS.fetch_add(1, SeqCst);
        ler_um_lote(&mut lido, &mut ultimo_elo, antes, depois, &registros)?;
    }
}

extern "C" fn acompanhante(_: u64) -> ! {
    if let Err(motivo) = acompanhar() {
        falhou("acompanhante", motivo);
    }
    ACOMPANHANDO.fetch_sub(1, SeqCst);
    crate::fios::terminar()
}

/// Guarda a cabeça de uma verificação, com os números entre os quais o
/// registro dela tem de estar — as primeiras [`MAIS_CABECAS`].
fn guardar_cabeca(m: u64, de: u64, ate: u64) {
    let i = CABECAS_GUARDADAS.fetch_add(1, SeqCst) as usize;
    if let Some(c) = CABECAS.get(i) {
        c[0].store(m, SeqCst);
        c[1].store(de, SeqCst);
        c[2].store(ate, SeqCst);
    }
}

/// O verificador do caso dos leitores: `audit.verify` em laço — a cada
/// [`INTERVALO_DA_VERIFICACAO`] registros novos, e uma vez ao menos —, cada
/// um com o anel inteiro conferido; a cabeça de cada um fica guardada para
/// o journal conferir: o elo de um registro entre o seguinte ao último de
/// antes do pedido — a decisão dele — e o último de depois.
fn verificar_em_laco() -> Resultado {
    let mut visto = 0u64;
    let mut feitas = 0u64;
    loop {
        if PARAR.load(SeqCst) {
            return Ok(());
        }
        let parar = PARAR_DE_VERIFICAR.load(SeqCst);
        if parar && feitas > 0 {
            return Ok(());
        }
        if !parar
            && feitas > 0
            && crate::autorizacao::ultimo_registro() < visto + INTERVALO_DA_VERIFICACAO
        {
            crate::fios::ceder();
            continue;
        }
        if !parar && !esperar_a_folga() {
            return Ok(());
        }
        let de = crate::autorizacao::com_auditoria(|c| c.ultima_seq()).unwrap_or(0) + 1;
        let Some(r) = pelo_gate_ate("audit.verify", "{}", || PARAR.load(SeqCst))? else {
            return Ok(());
        };
        let ate = crate::autorizacao::com_auditoria(|c| c.ultima_seq()).unwrap_or(0);
        let j = Json(r.as_bytes());
        let cabeca = texto(j, "head").and_then(sigilo::de_hex);
        let (true, Some(cabeca)) = (confere_o_anel_inteiro(j), cabeca) else {
            crate::log_error!("teste", "audit.verify: {}", r);
            return Err("um audit.verify no meio dos produtores nao conferiu o anel inteiro");
        };
        guardar_cabeca(marca(&cabeca), de, ate);
        VERIFICACOES.fetch_add(1, SeqCst);
        feitas += 1;
        visto = ate;
    }
}

extern "C" fn verificador(_: u64) -> ! {
    if let Err(motivo) = verificar_em_laco() {
        falhou("verificador", motivo);
    }
    VERIFICANDO.fetch_sub(1, SeqCst);
    crate::fios::terminar()
}

/// Um verificador do caso do transbordo: `audit.verify` sem parar — uma vez
/// ao menos —, cada um com o anel inteiro conferido.
fn verificar_sem_parar() -> Resultado {
    let mut feitas = 0u64;
    loop {
        if PARAR.load(SeqCst) {
            return Ok(());
        }
        let parar = PARAR_DE_VERIFICAR.load(SeqCst);
        if parar && feitas > 0 {
            return Ok(());
        }
        if !parar && !esperar_a_folga() {
            return Ok(());
        }
        let Some(r) = pelo_gate_ate("audit.verify", "{}", || PARAR.load(SeqCst))? else {
            return Ok(());
        };
        if !confere_o_anel_inteiro(Json(r.as_bytes())) {
            crate::log_error!("teste", "audit.verify: {}", r);
            return Err("um audit.verify com o anel transbordando nao conferiu o anel inteiro");
        }
        VERIFICACOES.fetch_add(1, SeqCst);
        feitas += 1;
        crate::fios::ceder();
    }
}

extern "C" fn verificador_do_transbordo(_: u64) -> ! {
    if let Err(motivo) = verificar_sem_parar() {
        falhou("verificador do transbordo", motivo);
    }
    VERIFICANDO.fetch_sub(1, SeqCst);
    crate::fios::terminar()
}

/// Um segundo coletor: grava a auditoria sem parar — uma passada ao menos
/// —, até o caso mandar.
extern "C" fn coletor(_: u64) -> ! {
    loop {
        if persistencia::gravar_auditoria().is_err() {
            FALHAS_DO_COLETOR.fetch_add(1, SeqCst);
        }
        PASSADAS.fetch_add(1, SeqCst);
        if PARAR_DE_COLETAR.load(SeqCst) || PARAR.load(SeqCst) {
            break;
        }
        crate::fios::ceder();
    }
    COLETANDO.fetch_sub(1, SeqCst);
    crate::fios::terminar()
}

/// Um fio do caso, no núcleo `nucleo` se há um, contado em `vivos`.
fn nascer(
    nome: &'static str,
    entrada: extern "C" fn(u64) -> !,
    argumento: u64,
    nucleo: Option<usize>,
    vivos: &AtomicU64,
) -> Resultado {
    vivos.fetch_add(1, SeqCst);
    let r = match nucleo {
        Some(n) => crate::fios::criar_no_nucleo(nome, entrada, argumento, n),
        None => crate::fios::criar(nome, entrada, argumento),
    };
    if r.is_err() {
        vivos.fetch_sub(1, SeqCst);
        return Err("um fio do caso nao nasceu");
    }
    Ok(())
}

/// Espera `vivos` chegar a zero, cedendo, até `ms` milissegundos.
fn ate_zerar(vivos: &AtomicU64, ms: u64) -> Resultado {
    let limite = crate::tempo::uptime_ms() + ms;
    while vivos.load(SeqCst) != 0 {
        if crate::tempo::uptime_ms() > limite {
            return Err("um fio do caso nao terminou");
        }
        crate::fios::ceder();
    }
    Ok(())
}

/// [`ate_zerar`], gravando a auditoria enquanto espera — com
/// [`gravar_com_folga`] —: quem ainda audita pode estar esperando a folga.
fn ate_zerar_gravando(vivos: &AtomicU64, ms: u64) -> Resultado {
    let limite = crate::tempo::uptime_ms() + ms;
    while vivos.load(SeqCst) != 0 {
        gravar_com_folga()?;
        if crate::tempo::uptime_ms() > limite {
            return Err("um fio do caso nao terminou");
        }
        crate::fios::ceder();
    }
    Ok(())
}

/// O produtor e o número de um registro de produtor dos casos.
fn do_produtor(e: &Evento) -> Option<(u64, u64)> {
    if e.metodo != PRODUZIDO {
        return None;
    }
    let (p, i) = e.detalhe.split_once(' ')?;
    Some((p.parse().ok()?, i.parse().ok()?))
}

// ---------------------------------------------------------------------------
// O journal contra o que os leitores viram
// ---------------------------------------------------------------------------

/// A conferência do journal, e do que os leitores viram contra ele. Refaz a
/// cadeia do journal a partir da âncora do começo do caso — o elo de antes
/// do primeiro guardado —, número a número: cada um uma vez, na ordem, sem
/// lacuna; os de cada produtor na ordem dele; e a marca do elo de cada
/// número, para o que o acompanhante leu e para as cabeças das
/// verificações.
struct Conferidor {
    /// A base das marcas do acompanhante.
    base: u64,
    /// O primeiro guardado no começo do caso: de onde a conferência refaz.
    inicio: u64,
    /// O próximo número que o journal tem de trazer, e o elo refeito do de
    /// antes dele.
    proximo: u64,
    anterior: [u8; 32],
    /// A marca do elo refeito de cada número, da base em diante.
    esperado: Vec<u64>,
    /// O próximo registro de cada produtor, e o número do último deles.
    por_produtor: [u64; PRODUTORES as usize],
    ultimo_produzido: u64,
}

impl Conferidor {
    fn novo(base: u64, inicio: u64, ancora: [u8; 32]) -> Conferidor {
        Conferidor {
            base,
            inicio,
            proximo: inicio,
            anterior: ancora,
            esperado: alloc::vec![0; JANELA],
            por_produtor: [0; PRODUTORES as usize],
            ultimo_produzido: 0,
        }
    }

    /// Uma passada pela auditoria da região atual do journal. Com
    /// `compactada`, a gravada da compactação do caso: a região é a que ela
    /// deixou, e começa pela marca da base, com os copiados seguidos até a
    /// gravada — que a passada de antes dela já conferiu —, e o journal
    /// continua do seguinte a ela.
    fn percorrer(&mut self, compactada: Option<u64>) -> Resultado {
        let mut erro: Option<&'static str> = None;
        let mut viu_a_marca = false;
        let mut na_base: Option<u64> = None;
        persistencia::percorrer_a_auditoria_de_teste(|a| {
            if erro.is_none() {
                erro = self
                    .item(a, compactada, &mut viu_a_marca, &mut na_base)
                    .err();
            }
        })?;
        if let Some(e) = erro {
            return Err(e);
        }
        if compactada.is_some() && !viu_a_marca {
            return Err("a regiao da compactacao do caso nao comeca pela marca da base");
        }
        Ok(())
    }

    fn item(
        &mut self,
        a: AuditoriaNoJournal,
        compactada: Option<u64>,
        viu_a_marca: &mut bool,
        na_base: &mut Option<u64>,
    ) -> Resultado {
        match a {
            AuditoriaNoJournal::Compactada(primeira, ultima) => match compactada {
                // A marca da base da compactação do caso: de 1 ao de antes
                // do primeiro copiado, que não passa da gravada.
                Some(gravada) if !*viu_a_marca && primeira == 1 && ultima <= gravada => {
                    *viu_a_marca = true;
                    *na_base = Some(ultima + 1);
                    Ok(())
                }
                Some(_) => Err("a marca da base da compactacao do caso nao e a esperada"),
                // A de uma compactação de antes do caso.
                None if ultima < self.inicio => Ok(()),
                None => Err("uma marca de compactacao no meio da auditoria do caso"),
            },
            AuditoriaNoJournal::Lacuna(_, ultima) if ultima < self.inicio && na_base.is_none() => {
                Ok(())
            }
            AuditoriaNoJournal::Lacuna(primeira, ultima) => {
                crate::log_error!("teste", "lacuna de {} a {} no journal", primeira, ultima);
                Err(
                    "uma lacuna no journal com a folga do caso: um registro saiu do anel sem ser gravado",
                )
            }
            AuditoriaNoJournal::Registro(seq, e) => self.registro(seq, &e, na_base),
        }
    }

    fn registro(&mut self, seq: u64, e: &Evento, na_base: &mut Option<u64>) -> Resultado {
        if seq < self.proximo {
            // Antes do começo do caso, ou já conferido: os copiados da base
            // da compactação do caso vêm seguidos.
            if let Some(n) = na_base.as_mut() {
                if seq != *n {
                    return Err("a base da compactacao do caso pula ou repete a auditoria");
                }
                *n += 1;
            }
            return Ok(());
        }
        if let Some(n) = na_base.take()
            && n != seq
        {
            crate::log_error!(
                "teste",
                "a base vai ate {}; o journal segue em {}",
                n - 1,
                seq
            );
            return Err("a base da compactacao do caso nao vai ate a gravada");
        }
        if seq != self.proximo {
            crate::log_error!(
                "teste",
                "o journal esperava {} e trouxe {}",
                self.proximo,
                seq
            );
            return Err("o journal pula, repete ou desordena a auditoria do caso");
        }
        let elo = politica::auditoria::elo(&self.anterior, seq, e);
        if let Some((p, i)) = do_produtor(e) {
            match self.por_produtor.get_mut(p as usize) {
                Some(n) if *n == i => *n += 1,
                _ => {
                    crate::log_error!("teste", "produtor {}: o registro {} fora de ordem", p, i);
                    return Err(
                        "um registro de produtor faltou, repetiu ou saiu de ordem no journal",
                    );
                }
            }
            self.ultimo_produzido = seq;
        }
        if let Some(m) = seq
            .checked_sub(self.base + 1)
            .and_then(|i| self.esperado.get_mut(i as usize))
        {
            *m = marca(&elo);
        }
        self.anterior = elo;
        self.proximo += 1;
        Ok(())
    }

    /// O fim da conferência: o journal vai até a gravada; os produtores
    /// estão todos nele; e a cadeia refeita dele, do começo do caso à
    /// gravada, termina no elo que a memória tem para ela — e no que a
    /// persistência guarda do último gravado.
    fn terminar(&self, gravada: u64) -> Resultado {
        if self.proximo != gravada + 1 {
            crate::log_error!(
                "teste",
                "o journal vai ate {}; a gravada e {}",
                self.proximo - 1,
                gravada
            );
            return Err("o journal nao tem a auditoria do caso ate a gravada");
        }
        if self.por_produtor.iter().any(|&n| n != POR_PRODUTOR) {
            return Err("faltam registros de um produtor no journal");
        }
        let na_memoria =
            crate::autorizacao::com_auditoria(|c| c.registro(gravada).map(|r| r.elo)).flatten();
        if na_memoria != Some(self.anterior)
            || persistencia::elo_gravado_de_teste() != self.anterior
        {
            return Err("a cadeia refeita do journal nao termina no elo da memoria");
        }
        Ok(())
    }

    /// O acompanhante foi até depois do último produzido, e cada número até
    /// onde ele foi está marcado: os de antes do anel do começo, pulados; os
    /// outros, pulados ou com a marca do elo que o journal refaz.
    fn conferir_o_acompanhante(&self) -> Resultado {
        let lido = LIDO_FINAL.load(SeqCst);
        if !(self.ultimo_produzido..self.proximo).contains(&lido) {
            crate::log_error!(
                "teste",
                "o acompanhante foi ate {}; o ultimo produzido e {}, e o journal vai ate {}",
                lido,
                self.ultimo_produzido,
                self.proximo - 1
            );
            return Err("o acompanhante nao alcancou a cabeca depois dos produtores");
        }
        for s in self.base + 1..=lido {
            let i = (s - self.base - 1) as usize;
            let visto = LIDOS.get(i).map_or(0, |l| l.load(SeqCst));
            let esperado = self.esperado.get(i).copied().unwrap_or(0);
            let certo = if s < self.inicio {
                visto == SALTADO
            } else {
                visto == SALTADO || (visto != 0 && visto == esperado)
            };
            if !certo {
                crate::log_error!(
                    "teste",
                    "numero {}: o acompanhante marcou {:x}, o journal refaz {:x}",
                    s,
                    visto,
                    esperado
                );
                return Err(
                    "o que o acompanhante leu nao e o que o journal tem, ou ele deixou um numero sem ler nem pular",
                );
            }
        }
        Ok(())
    }

    /// A cabeça de cada verificação guardada é o elo de um registro entre os
    /// números da hora dela.
    fn conferir_as_cabecas(&self) -> Resultado {
        let guardadas = (CABECAS_GUARDADAS.load(SeqCst) as usize).min(MAIS_CABECAS);
        for c in &CABECAS[..guardadas] {
            let [m, de, ate] = [0, 1, 2].map(|k| c[k].load(SeqCst));
            let achou = (de..=ate).any(|s| {
                s > self.base && self.esperado.get((s - self.base - 1) as usize) == Some(&m)
            });
            if !achou {
                crate::log_error!(
                    "teste",
                    "a cabeca {:x} nao e o elo de nenhum registro de {} a {}",
                    m,
                    de,
                    ate
                );
                return Err("a cabeca de um audit.verify nao e o elo de um registro da hora dele");
            }
        }
        Ok(())
    }
}

/// A compactação no meio dos produtores e dos leitores, com a ordem das
/// gravações na mão do começo ao fim: a auditoria toda ao journal, a
/// primeira passada da conferência — pela região que a compactação vai
/// deixar para trás —, e a compactação. Nenhum outro coletor grava entre a
/// passada e a base. Os produtores passam da metade quando ela começa.
/// Devolve a gravada na compactação.
fn compactar_no_meio(conferidor: &mut Conferidor) -> Result<u64, &'static str> {
    NO_MEIO.store(true, SeqCst);
    persistencia::em_ordem(|| -> Result<u64, &'static str> {
        persistencia::gravar_auditoria()?;
        let gravada = persistencia::auditoria_gravada();
        conferidor.percorrer(None)?;
        if conferidor.proximo != gravada + 1 {
            crate::log_error!(
                "teste",
                "a primeira passada foi ate {}; a gravada e {}",
                conferidor.proximo - 1,
                gravada
            );
            return Err("a primeira passada da conferencia nao chegou a gravada");
        }
        persistencia::compactar_de_teste()?;
        Ok(gravada)
    })
}

// ---------------------------------------------------------------------------
// Produtores e leitores ao mesmo tempo
// ---------------------------------------------------------------------------

/// Produtores em vários núcleos e os dois leitores pelo gate, ao mesmo
/// tempo, com a suíte gravando a auditoria — e, com `compactar`, um segundo
/// coletor, o do kernel solto, e a compactação no meio. Ao fim, o journal
/// confere inteiro e confere o que os leitores viram.
fn produtores_e_leitores(compactar: bool) -> Resultado {
    if persistencia::estado() != persistencia::Estado::Disponivel {
        return Err("a persistencia nao esta disponivel: o caso confere o journal");
    }
    anel_cheio_com_saidos()?;
    zerar_os_fios();
    POR_PRODUTOR_DO_CASO.store(POR_PRODUTOR, SeqCst);
    NO_MEIO.store(!compactar, SeqCst);
    let (no_comeco, ancora) = fotografia();
    let inicio = no_comeco
        .first()
        .map(|r| r.seq)
        .ok_or("o anel da auditoria esta vazio")?;
    drop(no_comeco);
    let base = inicio - ANTES_DO_ANEL - 1;
    BASE.store(base, SeqCst);
    let mut conferidor = Conferidor::novo(base, inicio, ancora);
    let nucleos: Vec<usize> = nucleos_secundarios().collect();
    let no = |i: usize| nucleos.get(i % nucleos.len().max(1)).copied();
    let r = (|| -> Resultado {
        if compactar {
            persistencia::pausar_a_auditoria_de_teste(false);
            nascer("teste-trava-coletor", coletor, 0, no(5), &COLETANDO)?;
        }
        nascer(
            "teste-trava-acompanhante",
            acompanhante,
            0,
            no(0),
            &ACOMPANHANDO,
        )?;
        nascer(
            "teste-trava-verificador",
            verificador,
            0,
            no(1),
            &VERIFICANDO,
        )?;
        for p in 0..PRODUTORES {
            nascer(
                "teste-trava-produtor",
                produtor,
                p,
                no(p as usize + 2),
                &PRODUZINDO,
            )?;
        }
        let mut compactada = None;
        let limite = crate::tempo::uptime_ms() + 60_000;
        while PRODUZINDO.load(SeqCst) != 0 {
            gravar_com_folga()?;
            if compactar
                && compactada.is_none()
                && PRODUZIDOS.load(SeqCst) >= PRODUTORES * (POR_PRODUTOR / 2)
            {
                compactada = Some(compactar_no_meio(&mut conferidor)?);
            }
            if crate::tempo::uptime_ms() > limite {
                crate::log_error!(
                    "teste",
                    "{} registros produzidos de {}",
                    PRODUZIDOS.load(SeqCst),
                    PRODUTORES * POR_PRODUTOR
                );
                return Err("os produtores nao terminaram em 60 s");
            }
            crate::fios::ceder();
        }
        if compactar && compactada.is_none() {
            return Err("a compactacao nao aconteceu no meio dos produtores");
        }
        PARAR_DE_VERIFICAR.store(true, SeqCst);
        ate_zerar_gravando(&VERIFICANDO, 30_000)?;
        ALCANCAR_E_PARAR.store(true, SeqCst);
        ate_zerar_gravando(&ACOMPANHANDO, 30_000)?;
        if compactar {
            PARAR_DE_COLETAR.store(true, SeqCst);
            ate_zerar_gravando(&COLETANDO, 30_000)?;
            persistencia::pausar_a_auditoria_de_teste(true);
            if FALHAS_DO_COLETOR.load(SeqCst) != 0 || PASSADAS.load(SeqCst) == 0 {
                return Err("o segundo coletor falhou, ou nao passou");
            }
        }
        if FALHAS.load(SeqCst) != 0 {
            return Err("um leitor do caso viu o que nao devia (o log diz o que)");
        }
        if LEITURAS.load(SeqCst) == 0 || VERIFICACOES.load(SeqCst) == 0 {
            return Err("um leitor do caso nao leu");
        }
        if SALTOS.load(SeqCst) == 0 {
            return Err(
                "o acompanhante nao pulou o que o anel ja tinha descartado quando ele comecou",
            );
        }
        let fim = crate::autorizacao::com_auditoria(|c| c.ultima_seq()).unwrap_or(0);
        persistencia::gravar_auditoria()?;
        let gravada = persistencia::auditoria_gravada();
        if gravada < fim {
            return Err("a auditoria do caso nao foi toda ao journal");
        }
        conferidor.percorrer(compactada)?;
        conferidor.terminar(gravada)?;
        conferidor.conferir_o_acompanhante()?;
        conferidor.conferir_as_cabecas()?;
        crate::log_info!(
            "teste",
            "trava: {} registros de {} produtores; {} leituras do acompanhante, {} saltos ({} registros pulados); {} verificacoes; {} recusas por taxa; {} passadas do segundo coletor",
            PRODUTORES * POR_PRODUTOR,
            PRODUTORES,
            LEITURAS.load(SeqCst),
            SALTOS.load(SeqCst),
            SALTADOS.load(SeqCst),
            VERIFICACOES.load(SeqCst),
            TAXADAS.load(SeqCst),
            PASSADAS.load(SeqCst)
        );
        a_cadeia_do_journal_confere()
    })();
    parar_os_fios();
    r
}

/// Produtores em vários núcleos auditando e, ao mesmo tempo, o acompanhante
/// e o verificador pelo gate, com a suíte gravando: cada leitura em ordem,
/// seguida, sem repetir, o salto só o do anel, toda verificação do anel
/// inteiro; e o journal com cada registro uma vez, na ordem, com o elo que
/// os leitores viram.
pub(super) fn produtores_e_leitores_ao_mesmo_tempo() -> Resultado {
    produtores_e_leitores(false)
}

/// O mesmo, com três coletores — a suíte, um segundo e o do kernel — e uma
/// compactação no meio: a base é a marca e os copiados até a gravada, o
/// journal segue dela sem lacuna, e a cadeia refeita dele é a da memória.
pub(super) fn leitores_coletores_e_a_compactacao_no_meio() -> Resultado {
    produtores_e_leitores(true)
}

// ---------------------------------------------------------------------------
// O anel transbordando sob verificações
// ---------------------------------------------------------------------------

/// Quantos produtores e registros o caso do transbordo tem — três anéis, ao
/// menos —, e quantos fios pedem `audit.verify` ao mesmo tempo.
const PRODUTORES_DO_TRANSBORDO: u64 = 2;
const POR_PRODUTOR_DO_TRANSBORDO: u64 = 1600;
const _: () = assert!(PRODUTORES_DO_TRANSBORDO * POR_PRODUTOR_DO_TRANSBORDO >= 3 * CAPACIDADE);
const VERIFICADORES: u64 = 4;

/// A folga de memória do caso do transbordo, além do que as fotografias
/// podem segurar: o journal sendo gravado e os pedidos pelo gate.
const FOLGA_DE_MEMORIA: usize = 512 * 1024;

/// O quanto a memória pode ficar acima do patamar no fim do caso do
/// transbordo — o que uma gravação ou um pedido deixam no kernel. Os
/// registros que passaram pelo anel no caso são milhares: o vazamento de
/// cada um que saiu passaria disso já com algumas centenas deles.
const SOBRA_DE_MEMORIA: usize = 64 * 1024;

/// A memória de um anel cheio: uma cadeia local da capacidade da
/// auditoria, cheia de registros do tamanho dos do caso, medida pelo
/// alocador e solta.
fn medir_um_anel() -> usize {
    let antes = crate::heap::estatisticas().alocado;
    let mut c = Cadeia::nova(crate::autorizacao::CAPACIDADE_DA_AUDITORIA);
    for i in 1..=CAPACIDADE {
        c.anexar(evento_local(i));
    }
    let depois = crate::heap::estatisticas().alocado;
    drop(c);
    depois.saturating_sub(antes)
}

/// Vários fios pedindo `audit.verify` sem parar, pelo gate, enquanto
/// produtores em outros núcleos auditam três anéis: toda resposta confere o
/// anel inteiro. A memória que as fotografias seguram não passa de um anel e
/// uma fotografia por fio — pela maior conta do alocador vista no caso, e
/// pelo pico dele, se o pico de antes não passava disso —, e, no fim, com o
/// anel cheio de novo de registros do mesmo tamanho, a memória volta ao
/// patamar: o que saiu pela ponta foi devolvido, e nada vazou.
pub(super) fn o_anel_transbordando_sob_verificacoes() -> Resultado {
    if persistencia::estado() != persistencia::Estado::Disponivel {
        return Err("a persistencia nao esta disponivel: o caso grava a auditoria");
    }
    anel_cheio_com_saidos()?;
    // O anel cheio de registros do mesmo tamanho: o patamar.
    auditar_enchendo(CAPACIDADE, "enche o anel")?;
    let um_anel = medir_um_anel();
    let antes = crate::heap::estatisticas();
    let patamar = antes.alocado;
    let teto = patamar + VERIFICADORES as usize * (um_anel + FOTOGRAFIA) + FOLGA_DE_MEMORIA;
    zerar_os_fios();
    POR_PRODUTOR_DO_CASO.store(POR_PRODUTOR_DO_TRANSBORDO, SeqCst);
    NO_MEIO.store(true, SeqCst);
    let nucleos: Vec<usize> = nucleos_secundarios().collect();
    let no = |i: u64| nucleos.get(i as usize % nucleos.len().max(1)).copied();
    let mut maior_alocado = patamar;
    let r = (|| -> Resultado {
        for v in 0..VERIFICADORES {
            nascer(
                "teste-trava-verificador",
                verificador_do_transbordo,
                v,
                no(v),
                &VERIFICANDO,
            )?;
        }
        for p in 0..PRODUTORES_DO_TRANSBORDO {
            nascer(
                "teste-trava-produtor",
                produtor,
                p,
                no(VERIFICADORES + p),
                &PRODUZINDO,
            )?;
        }
        let limite = crate::tempo::uptime_ms() + 60_000;
        while PRODUZINDO.load(SeqCst) != 0 {
            gravar_com_folga()?;
            maior_alocado = maior_alocado.max(crate::heap::estatisticas().alocado);
            if crate::tempo::uptime_ms() > limite {
                return Err("os produtores do transbordo nao terminaram em 60 s");
            }
            crate::fios::ceder();
        }
        PARAR_DE_VERIFICAR.store(true, SeqCst);
        ate_zerar_gravando(&VERIFICANDO, 30_000)?;
        if FALHAS.load(SeqCst) != 0 {
            return Err("um verificador do transbordo viu o que nao devia (o log diz o que)");
        }
        if VERIFICACOES.load(SeqCst) < VERIFICADORES {
            return Err("um verificador do transbordo nao verificou");
        }
        let pico = crate::heap::estatisticas().pico;
        if maior_alocado > teto || pico > antes.pico.max(teto) {
            crate::log_error!(
                "teste",
                "patamar {}; um anel {}; maior alocado {}; pico {} (antes {}); teto {}",
                patamar,
                um_anel,
                maior_alocado,
                pico,
                antes.pico,
                teto
            );
            return Err(
                "as fotografias do audit.verify seguraram mais que um anel e uma fotografia por fio",
            );
        }
        // O anel cheio de novo de registros do mesmo tamanho: a memória do
        // anel é a do patamar, e o que sobrar é o que vazou.
        auditar_enchendo(CAPACIDADE, "enche o anel")?;
        let alocado = crate::heap::estatisticas().alocado;
        if alocado > patamar + SOBRA_DE_MEMORIA {
            crate::log_error!(
                "teste",
                "patamar {}; no fim {}; {} verificacoes",
                patamar,
                alocado,
                VERIFICACOES.load(SeqCst)
            );
            return Err("a memoria nao voltou ao patamar: o que saiu do anel nao foi devolvido");
        }
        crate::log_info!(
            "teste",
            "trava: {} registros com {} verificadores; {} verificacoes; {} recusas por taxa; patamar {}, maior alocado {}, um anel {}",
            PRODUTORES_DO_TRANSBORDO * POR_PRODUTOR_DO_TRANSBORDO,
            VERIFICADORES,
            VERIFICACOES.load(SeqCst),
            TAXADAS.load(SeqCst),
            patamar,
            maior_alocado,
            um_anel
        );
        Ok(())
    })();
    parar_os_fios();
    r
}
