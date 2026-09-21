//! Os comandos que o kernel expõe ao agente.
//!
//! Esta é a superfície de introspecção da fase 0. Cada entrada de
//! [`COMANDOS`] é simultaneamente a implementação e a documentação formal do
//! comando — ver [`super::registry`].
//!
//! Convenção de nomes: `<subsistema>.<ação>`. O agrupamento por prefixo deixa
//! a listagem de `agent.describe` legível e prepara o terreno para as fases
//! seguintes (`process.list`, `fs.stat`, `irq.stats`).

use core::fmt;

use bootloader_api::info::{MemoryRegionKind, PixelFormat};

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
        resumo: "Identificacao do kernel, CPU e video.",
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
        resumo: "Lista as regioes do mapa de memoria fisica entregue pelo bootloader.",
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
    // Devolver o contador de log dá ao agente uma medida barata de progresso:
    // comparando duas chamadas dá para saber se o kernel esteve ativo no
    // intervalo, mesmo sem termos um timer ainda.
    w.field_u64("log_seq", crate::log::total_emitidos())?;
    w.end_object()
}

fn describe(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.field_str("protocol", "jsonrpc-2.0")?;
    w.field_str("transport", "serial-com2-ndjson")?;
    w.field_str("kernel", env!("CARGO_PKG_NAME"))?;
    w.field_str("version", env!("CARGO_PKG_VERSION"))?;

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
    w.field_str("arch", "x86_64")?;
    w.field_str("kernel", env!("CARGO_PKG_NAME"))?;
    w.field_str("version", env!("CARGO_PKG_VERSION"))?;
    w.field_str("phase", "0")?;

    let mut vendor = [0u8; 12];
    ler_vendor_cpu(&mut vendor);
    w.field_str(
        "cpu_vendor",
        core::str::from_utf8(&vendor).unwrap_or("desconhecido"),
    )?;

    w.key("framebuffer")?;
    match crate::boot::com(|info| info.framebuffer.as_ref().map(|fb| fb.info())).flatten() {
        Some(fb) => {
            w.begin_object()?;
            w.field_u64("width", fb.width as u64)?;
            w.field_u64("height", fb.height as u64)?;
            w.field_u64("stride", fb.stride as u64)?;
            w.field_u64("bytes_per_pixel", fb.bytes_per_pixel as u64)?;
            w.field_str("pixel_format", nome_formato_pixel(fb.pixel_format))?;
            w.end_object()?;
        }
        None => w.null_value()?,
    }

    w.field_u64("log_records", crate::log::total_emitidos())?;
    w.end_object()
}

/// Lê a string de fabricante da CPU via `CPUID` folha 0.
///
/// Os 12 caracteres vêm espalhados em três registradores, e a ordem
/// EBX-EDX-ECX não é um engano: é literalmente como a Intel especificou.
fn ler_vendor_cpu(destino: &mut [u8; 12]) {
    // `__cpuid` é seguro: `CPUID` faz parte da linha de base do x86_64, então
    // o compilador sabe que a instrução sempre existe no alvo e não há
    // pré-condição para o chamador garantir.
    let r = core::arch::x86_64::__cpuid(0);
    destino[0..4].copy_from_slice(&r.ebx.to_le_bytes());
    destino[4..8].copy_from_slice(&r.edx.to_le_bytes());
    destino[8..12].copy_from_slice(&r.ecx.to_le_bytes());
}

fn nome_formato_pixel(formato: PixelFormat) -> &'static str {
    match formato {
        PixelFormat::Rgb => "rgb",
        PixelFormat::Bgr => "bgr",
        PixelFormat::U8 => "grayscale8",
        // `PixelFormat` é `non_exhaustive`: versões futuras do bootloader
        // podem adicionar variantes, e o kernel precisa continuar compilando.
        _ => "desconhecido",
    }
}

// ---------------------------------------------------------------------------
// memory.*
// ---------------------------------------------------------------------------

fn memory_stats(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    let dados = crate::boot::com(|info| {
        let mut utilizavel = 0u64;
        let mut total = 0u64;
        let mut regioes = 0u64;
        for regiao in info.memory_regions.iter() {
            let tamanho = regiao.end - regiao.start;
            total += tamanho;
            regioes += 1;
            if regiao.kind == MemoryRegionKind::Usable {
                utilizavel += tamanho;
            }
        }
        (utilizavel, total, regioes)
    });

    w.begin_object()?;
    match dados {
        Some((utilizavel, total, regioes)) => {
            w.field_bool("available", true)?;
            w.field_u64("usable_bytes", utilizavel)?;
            w.field_u64("total_bytes", total)?;
            w.field_u64("region_count", regioes)?;
        }
        None => {
            // Um handler não pode falhar (ver `registry::Handler`), então uma
            // condição de indisponibilidade vira um campo do resultado. Isso
            // é melhor para o agente do que um erro de protocolo: a resposta
            // continua estruturada e diz exatamente o que houve.
            w.field_bool("available", false)?;
            w.field_str("reason", "boot info ainda nao registrado")?;
        }
    }
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

    let emitidas = crate::boot::com(|info| -> Result<u64, fmt::Error> {
        let mut n = 0u64;
        for regiao in info.memory_regions.iter() {
            if n >= limite {
                break;
            }
            if so_utilizaveis && regiao.kind != MemoryRegionKind::Usable {
                continue;
            }
            w.begin_object()?;
            w.field_u64("start", regiao.start)?;
            w.field_u64("end", regiao.end)?;
            w.field_u64("size", regiao.end - regiao.start)?;
            w.field_str("kind", nome_tipo_regiao(regiao.kind))?;
            w.end_object()?;
            n += 1;
        }
        Ok(n)
    });

    w.end_array()?;
    match emitidas {
        Some(Ok(n)) => w.field_u64("count", n)?,
        _ => w.field_u64("count", 0)?,
    }
    w.end_object()
}

fn nome_tipo_regiao(tipo: MemoryRegionKind) -> &'static str {
    match tipo {
        MemoryRegionKind::Usable => "usable",
        MemoryRegionKind::Bootloader => "bootloader",
        MemoryRegionKind::UnknownUefi(_) => "uefi-reserved",
        MemoryRegionKind::UnknownBios(_) => "bios-reserved",
        _ => "desconhecido",
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

    // `ultimos` empresta o registro só durante a chamada, então serializamos
    // na hora em vez de copiar para uma lista intermediária — que, de novo,
    // exigiria alocação que ainda não temos.
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
