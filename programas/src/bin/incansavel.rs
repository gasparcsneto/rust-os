//! A carga da bancada da disponibilidade: processos de um titular que pedem
//! ao sistema sem parar, para medir de fora quanto a fila dos pedidos dos
//! processos segura o executor do kernel — e, com ele, o canal do agente, o
//! console e as outras tarefas — de todos os outros titulares.
//!
//! O programa não tem argumentos — `user.run` não os passa. O que ele faz
//! vem de um arquivo do armazém, [`PEDIDO`], que quem o lança grava antes
//! (`fs.write`), uma linha `<chave> <valor>` por chave:
//!
//! - `processos`: quantos filhos pedem ao mesmo tempo, de 1 a
//!   [`MAIS_FILHOS`] — a cota de processos do papel conta o pai também;
//! - `duracao_ms`: por quanto tempo, pelo relógio das respostas, de
//!   [`MENOR_DURACAO_MS`] a [`MAIOR_DURACAO_MS`];
//! - `modo`: `pedir`, a carga; ou `girar`, o controle — os mesmos filhos
//!   ocupando a CPU sem pedir, a não ser o relógio de tempos em tempos —,
//!   que separa o efeito da fila do efeito de núcleos ocupados.
//!
//! Sem o arquivo: um filho, vinte segundos, `pedir`. O arquivo se lê pelo
//! `abrir`, uma decisão do gate com a autoridade de quem lançou.
//!
//! # O pedido
//!
//! `system.uptime`, o handler mais barato do registro, com `system.read`,
//! que o manifesto declara. É exercício de autoridade: paga a ficha da taxa
//! do principal de quem lançou, e a taxa se esgota em menos de um segundo.
//! Daí em diante quase todo pedido passa pelo gate inteiro e ouve
//! `RATE_LIMIT` — e a taxa grava na auditoria só a primeira recusa de cada
//! série, e soma as outras num registro quando um pedido passa de novo. É o
//! caminho mais barato pelo gate que não grava um registro por pedido: a
//! auditoria da carga fica presa à taxa do papel, e não ao ritmo do
//! programa. Os pedidos que passam trazem o `uptime_ms`, e é por eles que
//! cada filho sabe a hora de parar.
//!
//! Nada aqui concede nada: cada pedido é decidido pelo gate, com o papel de
//! quem lançou, a cada vez, e limitado pelo manifesto.
//!
//! # O que diz
//!
//! O pai, depois de bifurcar: `incansavel: <n> filhos, modo <modo>, de
//! <inicio> a <fim> ms`. Cada filho, no fim: `incansavel <fio>: <pedidos>
//! pedidos, <a> ALLOW, <r> RATE_LIMIT, de <primeiro> a <ultimo> ms`. O pai
//! espera todos e sai com [`CODIGO`]. Um filho que ouve outra coisa que
//! `ALLOW` ou `RATE_LIMIT` — o processo contido, a sessão que acabou — diz
//! o que ouviu e para na hora: a carga nunca gira para sempre sem relógio.

#![no_std]
#![no_main]

programas::manifesto!("incansavel", "system.read", "fs.read");

use programas::escreverln;
use programas::nativo;
use programas::sistema::{self, erro};

/// Todos os filhos acabaram a carga. A bancada o procura.
const CODIGO: i64 = 80;
/// Um filho acabou a carga dele.
const DO_FILHO: i64 = 60;

/// O pedido não se leu, ou não se entendeu.
const PEDIDO_INVALIDO: i64 = 25;
/// O relógio não respondeu antes de bifurcar.
const SEM_RELOGIO: i64 = 26;
/// Uma bifurcação foi recusada.
const SEM_FILHO: i64 = 27;
/// Um filho não acabou com [`DO_FILHO`].
const FILHO_FALHOU: i64 = 28;
/// Um filho ouviu outra coisa que `ALLOW` ou `RATE_LIMIT`, e parou.
const OUVIU_OUTRA: i64 = 29;

/// O pedido da bancada, no armazém compartilhado: o `operador` o grava e o
/// lê.
const PEDIDO: &str = "/armazem/compartilhado/incansavel";

/// Quantos filhos, no máximo: a cota de processos do `operador` é oito, e o
/// pai conta.
const MAIS_FILHOS: u64 = 7;
const MENOR_DURACAO_MS: u64 = 1_000;
const MAIOR_DURACAO_MS: u64 = 120_000;

/// O que cabe no arquivo do pedido.
const MAIOR_PEDIDO: usize = 256;

/// No modo `girar`, as voltas entre uma olhada no relógio e a seguinte:
/// poucas olhadas por segundo, para o controle não virar carga.
const VOLTAS_POR_OLHADA: u64 = 1 << 24;

/// Quantas vezes o pai tenta o relógio antes de desistir: a ficha da taxa
/// pode estar no fim, logo depois da carga de antes.
const TENTATIVAS_DO_RELOGIO: u32 = 1_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Modo {
    Pedir,
    Girar,
}

impl Modo {
    fn nome(self) -> &'static str {
        match self {
            Modo::Pedir => "pedir",
            Modo::Girar => "girar",
        }
    }
}

/// O que a bancada pediu.
struct Pedido {
    filhos: u64,
    duracao_ms: u64,
    modo: Modo,
}

/// Lê [`PEDIDO`]; sem o arquivo, o padrão.
fn ler_o_pedido() -> Result<Pedido, &'static str> {
    let mut pedido = Pedido {
        filhos: 1,
        duracao_ms: 20_000,
        modo: Modo::Pedir,
    };
    let d = sistema::abrir(PEDIDO);
    if d == erro::NAO_ENCONTRADO {
        return Ok(pedido);
    }
    if d < 0 {
        return Err("o pedido nao abriu");
    }
    let mut bytes = [0u8; MAIOR_PEDIDO];
    let mut n = 0;
    let lido = loop {
        if n == bytes.len() {
            break Err("o pedido passa do tamanho");
        }
        let r = sistema::ler(d as u64, &mut bytes[n..]);
        if r < 0 {
            break Err("o pedido nao se leu");
        }
        if r == 0 {
            break Ok(());
        }
        n += r as usize;
    };
    sistema::fechar(d as u64);
    lido?;
    let texto = core::str::from_utf8(&bytes[..n]).map_err(|_| "o pedido nao e texto")?;
    for linha in texto.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (chave, valor) = linha.split_once(' ').ok_or("linha sem valor")?;
        let valor = valor.trim();
        match chave {
            "processos" => pedido.filhos = valor.parse().map_err(|_| "processos nao e numero")?,
            "duracao_ms" => {
                pedido.duracao_ms = valor.parse().map_err(|_| "duracao_ms nao e numero")?
            }
            "modo" => {
                pedido.modo = match valor {
                    "pedir" => Modo::Pedir,
                    "girar" => Modo::Girar,
                    _ => return Err("modo desconhecido"),
                }
            }
            _ => return Err("chave desconhecida"),
        }
    }
    if !(1..=MAIS_FILHOS).contains(&pedido.filhos) {
        return Err("processos fora de 1 a 7");
    }
    if !(MENOR_DURACAO_MS..=MAIOR_DURACAO_MS).contains(&pedido.duracao_ms) {
        return Err("duracao_ms fora de 1000 a 120000");
    }
    Ok(pedido)
}

/// O que um filho viu.
#[derive(Default)]
struct Conta {
    pedidos: u64,
    permitidos: u64,
    pela_taxa: u64,
    /// O `uptime_ms` da primeira e da última resposta que o trouxe.
    primeiro_ms: u64,
    ultimo_ms: u64,
    /// Ouviu outra coisa que `ALLOW` ou `RATE_LIMIT`: o código.
    outra: Option<i64>,
}

/// Um `system.uptime`, contado em `c`: `Some(true)` quando a hora passou de
/// `fim_ms`, `Some(false)` para seguir, `None` para parar — ouviu outra
/// coisa que `ALLOW` ou `RATE_LIMIT`, e disse o quê.
fn um_pedido(c: &mut Conta, fim_ms: u64) -> Option<bool> {
    c.pedidos += 1;
    let r = match nativo::pedir("system.uptime", |_| Ok(())) {
        Ok(r) => r,
        Err(e) => {
            escreverln!("incansavel {}: o pedido devolveu {}", sistema::id(), e);
            c.outra = Some(e);
            return None;
        }
    };
    match r.resultado() {
        Ok(resultado) => {
            c.permitidos += 1;
            let ms = resultado
                .member("uptime_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if c.primeiro_ms == 0 {
                c.primeiro_ms = ms;
            }
            c.ultimo_ms = ms;
            Some(ms >= fim_ms)
        }
        Err(recusa) if recusa.motivo == Some("RATE_LIMIT") => {
            c.pela_taxa += 1;
            Some(false)
        }
        Err(recusa) => {
            escreverln!(
                "incansavel {}: ouviu {} ({})",
                sistema::id(),
                recusa.motivo.unwrap_or("?"),
                recusa.codigo
            );
            c.outra = Some(recusa.codigo);
            None
        }
    }
}

/// A vida de um filho: pede — ou gira, e olha o relógio de tempos em
/// tempos — até `fim_ms`, e diz quanto pediu.
fn filho(modo: Modo, fim_ms: u64) -> i64 {
    let mut c = Conta::default();
    let mut x = 0u64;
    loop {
        if modo == Modo::Girar {
            for _ in 0..VOLTAS_POR_OLHADA {
                x = core::hint::black_box(x.wrapping_add(1));
            }
        }
        // Passou da hora, ou ouviu outra coisa: para.
        if um_pedido(&mut c, fim_ms) != Some(false) {
            break;
        }
    }
    escreverln!(
        "incansavel {}: {} pedidos, {} ALLOW, {} RATE_LIMIT, de {} a {} ms",
        sistema::id(),
        c.pedidos,
        c.permitidos,
        c.pela_taxa,
        c.primeiro_ms,
        c.ultimo_ms
    );
    if c.outra.is_some() {
        OUVIU_OUTRA
    } else {
        DO_FILHO
    }
}

/// O relógio, pelo gate, insistindo enquanto a ficha não volta.
fn agora_ms() -> Option<u64> {
    for _ in 0..TENTATIVAS_DO_RELOGIO {
        match nativo::uptime_ms() {
            0 => sistema::ceder(),
            ms => return Some(ms),
        }
    }
    None
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let pedido = match ler_o_pedido() {
        Ok(p) => p,
        Err(motivo) => {
            escreverln!("incansavel: {}", motivo);
            return PEDIDO_INVALIDO;
        }
    };
    let Some(inicio) = agora_ms() else {
        escreverln!("incansavel: o relogio nao respondeu");
        return SEM_RELOGIO;
    };
    // O fim vai para os filhos na cópia da memória: todos param juntos.
    let fim = inicio + pedido.duracao_ms;
    let mut filhos = 0;
    while filhos < pedido.filhos {
        match sistema::bifurcar() {
            0 => sistema::sair(filho(pedido.modo, fim)),
            id if id > 0 => filhos += 1,
            e => {
                escreverln!("incansavel: bifurcar devolveu {}", e);
                break;
            }
        }
    }
    escreverln!(
        "incansavel: {} filhos, modo {}, de {} a {} ms",
        filhos,
        pedido.modo.nome(),
        inicio,
        fim
    );
    let mut falhas = 0;
    for _ in 0..filhos {
        match sistema::esperar(0) {
            Ok((_, Some(DO_FILHO))) => {}
            Ok((id, codigo)) => {
                escreverln!("incansavel: o filho {} acabou com {:?}", id, codigo);
                falhas += 1;
            }
            Err(e) => {
                escreverln!("incansavel: esperar devolveu {}", e);
                return FILHO_FALHOU;
            }
        }
    }
    if filhos < pedido.filhos {
        return SEM_FILHO;
    }
    if falhas > 0 {
        return FILHO_FALHOU;
    }
    escreverln!("incansavel: os {} filhos acabaram", filhos);
    CODIGO
}
