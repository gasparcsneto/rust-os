//! Os comandos que o kernel expõe ao agente.
//!
//! Esta é a superfície de introspecção da fase 0. Cada entrada de
//! [`COMANDOS`] é simultaneamente a implementação e a documentação formal do
//! comando — ver [`super::registry`].
//!
//! Nenhum comando aqui sabe em que arquitetura está rodando: todos consultam
//! [`crate::machine`] e [`crate::arch`], que os backends preencheram no boot.
//! É isso que faz a mesma resposta JSON sair de um x86 e de um ARM.
//!
//! Convenção de nomes: `<subsistema>.<ação>`. O agrupamento por prefixo deixa
//! a listagem de `agent.describe` legível e prepara o terreno para as fases
//! seguintes (`process.list`, `fs.stat`, `irq.stats`).

use core::fmt;

use super::json::{Json, JsonWriter};
use super::registry::{Command, ParamSpec, TipoParam};

/// A tabela de comandos do kernel.
pub static COMANDOS: &[Command] = &[
    Command {
        nome: "agent.ping",
        resumo: "Verifica se o canal do agente esta vivo e responsivo.",
        params: &[],
        handler: ping,
    },
    Command {
        nome: "agent.describe",
        resumo: "Lista todos os comandos disponiveis com seus parametros. \
                 Chame isto primeiro para descobrir a superficie do sistema.",
        params: &[],
        handler: describe,
    },
    Command {
        nome: "system.info",
        resumo: "Identificacao do kernel, arquitetura, CPU e video.",
        params: &[],
        handler: system_info,
    },
    Command {
        nome: "memory.stats",
        resumo: "Totais agregados de memoria fisica.",
        params: &[],
        handler: memory_stats,
    },
    Command {
        nome: "memory.regions",
        resumo: "Lista as regioes do mapa de memoria fisica da maquina.",
        params: &[
            ParamSpec {
                nome: "limit",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Numero maximo de regioes a retornar (padrao: todas).",
            },
            ParamSpec {
                nome: "usable_only",
                tipo: TipoParam::Booleano,
                obrigatorio: false,
                descricao: "Se verdadeiro, retorna apenas regioes utilizaveis.",
            },
        ],
        handler: memory_regions,
    },
    Command {
        nome: "log.tail",
        resumo: "Retorna os registros de log mais recentes, de forma estruturada.",
        params: &[
            ParamSpec {
                nome: "count",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Quantos registros examinar, do mais recente para tras (padrao: 32).",
            },
            ParamSpec {
                nome: "min_level",
                tipo: TipoParam::Texto,
                obrigatorio: false,
                descricao: "Severidade minima: error, warn, info, debug ou trace (padrao: trace).",
            },
        ],
        handler: log_tail,
    },
];

// ---------------------------------------------------------------------------
// agent.*
// ---------------------------------------------------------------------------

fn ping(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.field_bool("pong", true)?;
    w.field_str("arch", crate::arch::nome())?;
    // Devolver o contador de log dá ao agente uma medida barata de progresso:
    // comparando duas chamadas dá para saber se o kernel esteve ativo no
    // intervalo, mesmo sem termos um timer ainda.
    w.field_u64("log_seq", crate::log::total_emitidos())?;
    w.end_object()
}

fn describe(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.field_str("protocol", "jsonrpc-2.0")?;
    w.field_str("transport", "serial-ndjson")?;
    w.field_str("kernel", env!("CARGO_PKG_NAME"))?;
    w.field_str("version", env!("CARGO_PKG_VERSION"))?;
    w.field_str("arch", crate::arch::nome())?;

    w.key("commands")?;
    w.begin_array()?;
    for cmd in COMANDOS {
        w.begin_object()?;
        w.field_str("name", cmd.nome)?;
        w.field_str("summary", cmd.resumo)?;
        w.key("params")?;
        w.begin_array()?;
        for spec in cmd.params {
            w.begin_object()?;
            w.field_str("name", spec.nome)?;
            w.field_str("type", spec.tipo.nome())?;
            w.field_bool("required", spec.obrigatorio)?;
            w.field_str("description", spec.descricao)?;
            w.end_object()?;
        }
        w.end_array()?;
        w.end_object()?;
    }
    w.end_array()?;
    w.end_object()
}

// ---------------------------------------------------------------------------
// system.*
// ---------------------------------------------------------------------------

fn system_info(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.field_str("arch", crate::arch::nome())?;
    w.field_str("kernel", env!("CARGO_PKG_NAME"))?;
    w.field_str("version", env!("CARGO_PKG_VERSION"))?;
    w.field_str("phase", "0")?;

    let cpu = crate::arch::identificar_cpu();
    w.field_str("cpu_vendor", cpu.como_str())?;

    w.key("framebuffer")?;
    match crate::machine::video() {
        Some(v) => {
            w.begin_object()?;
            w.field_u64("width", v.largura)?;
            w.field_u64("height", v.altura)?;
            w.field_u64("stride", v.stride)?;
            w.field_u64("bytes_per_pixel", v.bytes_por_pixel)?;
            w.field_str("pixel_format", v.formato)?;
            w.end_object()?;
        }
        None => w.null_value()?,
    }

    w.field_u64("log_records", crate::log::total_emitidos())?;
    w.end_object()
}

// ---------------------------------------------------------------------------
// memory.*
// ---------------------------------------------------------------------------

fn memory_stats(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    let (utilizavel, total, regioes) = crate::machine::estatisticas();

    w.begin_object()?;
    w.field_u64("usable_bytes", utilizavel)?;
    w.field_u64("total_bytes", total)?;
    w.field_u64("region_count", regioes as u64)?;
    // Se o mapa não coube na tabela, dizemos — um agente não tem como
    // desconfiar sozinho de um número que parece plausível.
    w.field_u64("dropped_regions", crate::machine::regioes_descartadas() as u64)?;
    w.end_object()
}

fn memory_regions(params: Json, w: &mut JsonWriter) -> fmt::Result {
    let limite = params
        .member("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    let so_utilizaveis = params
        .member("usable_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    w.begin_object()?;
    w.key("regions")?;
    w.begin_array()?;

    // `com_regioes` empresta cada região só durante a chamada, então
    // serializamos na hora em vez de copiar para uma lista intermediária —
    // que exigiria a alocação que ainda não temos.
    let mut emitidas = 0u64;
    let mut erro: Option<fmt::Error> = None;

    crate::machine::com_regioes(|regiao| {
        if erro.is_some() || emitidas >= limite {
            return;
        }
        if so_utilizaveis && regiao.tipo != crate::machine::TipoRegiao::Utilizavel {
            return;
        }

        let resultado = (|| -> fmt::Result {
            w.begin_object()?;
            w.field_u64("start", regiao.inicio)?;
            w.field_u64("end", regiao.fim)?;
            w.field_u64("size", regiao.tamanho())?;
            w.field_str("kind", regiao.tipo.nome())?;
            w.end_object()
        })();

        match resultado {
            Ok(()) => emitidas += 1,
            Err(e) => erro = Some(e),
        }
    });

    w.end_array()?;
    w.field_u64("count", emitidas)?;
    w.end_object()?;

    match erro {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// log.*
// ---------------------------------------------------------------------------

fn log_tail(params: Json, w: &mut JsonWriter) -> fmt::Result {
    let quantidade = params
        .member("count")
        .and_then(|v| v.as_u64())
        .unwrap_or(32)
        .min(u32::MAX as u64) as usize;

    let nivel_minimo = params
        .member("min_level")
        .and_then(|v| v.as_str())
        .and_then(crate::log::Level::de_nome)
        .unwrap_or(crate::log::Level::Trace);

    w.begin_object()?;
    w.key("records")?;
    w.begin_array()?;

    let mut erro: Option<fmt::Error> = None;
    crate::log::ultimos(quantidade, nivel_minimo, |registro| {
        if erro.is_some() {
            return;
        }
        let resultado = (|| -> fmt::Result {
            w.begin_object()?;
            w.field_u64("seq", registro.seq)?;
            w.field_str("level", registro.level.nome())?;
            w.field_str("subsystem", registro.subsistema)?;
            w.field_str("message", registro.mensagem())?;
            w.end_object()
        })();
        if let Err(e) = resultado {
            erro = Some(e);
        }
    });

    w.end_array()?;
    w.field_u64("total_emitted", crate::log::total_emitidos())?;
    w.end_object()?;

    match erro {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
