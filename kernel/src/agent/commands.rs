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
        nome: "memory.frames",
        resumo: "Estado do alocador de frames de memoria fisica.",
        params: &[],
        handler: memory_frames,
    },
    Command {
        nome: "heap.stats",
        resumo: "Estado do heap do kernel, incluindo fragmentacao.",
        params: &[],
        handler: heap_stats,
    },
    Command {
        nome: "paging.translate",
        resumo: "Resolve um endereco virtual para fisico usando as tabelas de pagina ativas.",
        params: &[ParamSpec {
            nome: "address",
            tipo: TipoParam::Inteiro,
            obrigatorio: true,
            descricao: "Endereco virtual a traduzir, em decimal.",
        }],
        handler: paging_translate,
    },
    Command {
        nome: "system.uptime",
        resumo: "Tempo desde o boot, em ticks do timer e em milissegundos.",
        params: &[],
        handler: system_uptime,
    },
    Command {
        nome: "tasks.stats",
        resumo: "Estado do escalonador cooperativo e da fila de entrada.",
        params: &[],
        handler: tasks_stats,
    },
    Command {
        nome: "tasks.list",
        resumo: "Tarefas ja lancadas, com id, nome e se ainda estao vivas.",
        params: &[],
        handler: tasks_list,
    },
    Command {
        nome: "threads.stats",
        resumo: "Estado do escalonador preemptivo: fios vivos, trocas de contexto e preempcoes.",
        params: &[],
        handler: threads_stats,
    },
    Command {
        nome: "threads.list",
        resumo: "Fios de execucao do kernel, com id, nome, estado e quantas vezes rodaram.",
        params: &[],
        handler: threads_list,
    },
    Command {
        nome: "user.run",
        resumo: "Lanca o programa de exemplo no anel sem privilegio, num fio proprio. \
                 Nao espera o fim: consulte `user.stats` depois.",
        params: &[],
        handler: user_run,
    },
    Command {
        nome: "user.stats",
        resumo: "Chamadas de sistema atendidas, recusadas e o ultimo codigo de saida.",
        params: &[],
        handler: user_stats,
    },
    Command {
        nome: "irq.stats",
        resumo: "Contadores de interrupcoes de hardware por linha.",
        params: &[],
        handler: irq_stats,
    },
    Command {
        nome: "traps.stats",
        resumo: "Contadores de excecoes por tipo e detalhes da ultima falha.",
        params: &[],
        handler: traps_stats,
    },
    Command {
        nome: "debug.trigger",
        resumo: "Dispara uma excecao de proposito, para autoteste. \
                 `kind`: \"breakpoint\" e recuperavel; \"fatal\" mata o kernel \
                 e o deixa em modo post-mortem.",
        params: &[ParamSpec {
            nome: "kind",
            tipo: TipoParam::Texto,
            obrigatorio: true,
            descricao: "`breakpoint`: recuperavel, o kernel segue vivo. \
                        `fatal`: provoca uma falha irrecuperavel de proposito; \
                        o kernel entra em modo post-mortem e passa a responder \
                        apenas o relatorio da falha.",
        }],
        handler: debug_trigger,
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

    w.field_u64("uptime_ms", crate::tempo::uptime_ms())?;
    w.field_u64("log_records", crate::log::total_emitidos())?;

    // Como um estouro de pilha se manifesta nesta máquina. Serve para
    // correlação: um agente que veja este nome aparecer em `traps.stats`
    // depois de uma falha sabe que foi a pilha, e não outra coisa.
    w.key("stack_guard")?;
    w.begin_object()?;
    w.field_str("mechanism", "guard-page")?;
    w.field_str("fault", crate::arch::falha_de_estouro_de_pilha())?;
    w.end_object()?;

    w.end_object()
}

fn system_uptime(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    let hz = crate::tempo::frequencia_hz();

    w.begin_object()?;
    w.field_u64("ticks", crate::tempo::ticks())?;
    w.field_u64("uptime_ms", crate::tempo::uptime_ms())?;
    w.field_u64("timer_hz", hz as u64)?;
    // Sem timer, `uptime_ms` é zero e seria indistinguível de "acabou de
    // bootar". Este campo remove a ambiguidade.
    w.field_bool("timer_active", hz > 0)?;
    w.end_object()
}

fn memory_frames(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    let (livres, rastreados) = crate::frames::estatisticas();

    w.begin_object()?;
    w.field_u64("frame_size", crate::frames::TAMANHO_FRAME)?;
    w.field_u64("base", crate::frames::base())?;
    w.field_u64("tracked", rastreados as u64)?;
    w.field_u64("free", livres as u64)?;
    w.field_u64("used", (rastreados - livres) as u64)?;
    w.field_u64("free_bytes", livres as u64 * crate::frames::TAMANHO_FRAME)?;
    w.end_object()
}

// ---------------------------------------------------------------------------
// heap.*
// ---------------------------------------------------------------------------

fn heap_stats(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    let e = crate::heap::estatisticas();

    w.begin_object()?;
    w.field_u64("total_bytes", e.total as u64)?;
    w.field_u64("allocated_bytes", e.alocado as u64)?;
    w.field_u64("free_bytes", e.livre as u64)?;
    w.field_u64("free_blocks", e.blocos_livres as u64)?;
    // A medida honesta de fragmentacao: quando o maior bloco fica muito menor
    // que o total livre, ha memoria de sobra mas nenhuma peca grande o
    // bastante para um pedido maior.
    w.field_u64("largest_free_block", e.maior_bloco as u64)?;
    w.field_u64("allocations", e.alocacoes)?;
    w.field_u64("deallocations", e.liberacoes)?;
    w.field_u64("failures", e.falhas)?;
    w.end_object()
}

// ---------------------------------------------------------------------------
// paging.*
// ---------------------------------------------------------------------------

fn paging_translate(params: Json, w: &mut JsonWriter) -> fmt::Result {
    // O registro já garantiu que é inteiro; o `unwrap_or` cobre o impossível.
    let virtual_ = params
        .member("address")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    w.begin_object()?;
    w.field_u64("virtual", virtual_)?;
    match crate::arch::traduzir(virtual_) {
        Some(fisico) => {
            w.field_bool("mapped", true)?;
            w.field_u64("physical", fisico)?;
        }
        None => {
            // Um endereço sem tradução não é erro: é informação, e uma das
            // mais úteis que o agente pode pedir ao investigar uma falha de
            // pagina.
            w.field_bool("mapped", false)?;
            w.key("physical")?;
            w.null_value()?;
        }
    }
    w.end_object()
}

// ---------------------------------------------------------------------------
// irq.*
// ---------------------------------------------------------------------------

fn irq_stats(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.field_u64("total", crate::irq::total())?;

    w.key("lines")?;
    w.begin_array()?;
    let mut erro: Option<fmt::Error> = None;
    crate::irq::com_contadores(|linha, nome, total| {
        if erro.is_some() {
            return;
        }
        let resultado = (|| -> fmt::Result {
            w.begin_object()?;
            w.field_u64("line", linha as u64)?;
            w.field_str("name", nome)?;
            w.field_u64("count", total)?;
            w.end_object()
        })();
        if let Err(e) = resultado {
            erro = Some(e);
        }
    });
    w.end_array()?;
    w.end_object()?;

    match erro {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// tasks.*
// ---------------------------------------------------------------------------

fn tasks_stats(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    let (lancadas, concluidas, avancos, despertares) = crate::tarefas::executor::estatisticas();
    let (ocupacao, capacidade, descartados) = crate::tarefas::entrada::estatisticas();

    w.begin_object()?;
    w.field_u64("spawned", lancadas)?;
    w.field_u64("completed", concluidas)?;
    w.field_u64("alive", lancadas.saturating_sub(concluidas))?;
    // Quantas vezes uma tarefa foi efetivamente avancada. A razao entre isto
    // e `wakes` diz se o executor esta trabalhando ou girando: com wakers
    // funcionando, os dois numeros andam juntos.
    w.field_u64("polls", avancos)?;
    w.field_u64("wakes", despertares)?;

    w.key("input")?;
    w.begin_object()?;
    w.field_u64("queued", ocupacao as u64)?;
    w.field_u64("capacity", capacidade as u64)?;
    // Byte descartado e requisicao corrompida. Um valor diferente de zero
    // aqui explica um erro de JSON que de outra forma pareceria inexplicavel.
    w.field_u64("dropped", descartados)?;
    w.end_object()?;

    w.end_object()
}

fn tasks_list(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.key("tasks")?;
    w.begin_array()?;

    let mut erro: Option<fmt::Error> = None;
    crate::tarefas::executor::com_inventario(|inscricao| {
        if erro.is_some() {
            return;
        }
        let resultado = (|| -> fmt::Result {
            w.begin_object()?;
            w.field_u64("id", inscricao.id)?;
            w.field_str("name", inscricao.nome)?;
            w.field_bool("alive", inscricao.viva)?;
            w.end_object()
        })();
        if let Err(e) = resultado {
            erro = Some(e);
        }
    });

    w.end_array()?;
    w.end_object()?;

    match erro {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// user.*
// ---------------------------------------------------------------------------

fn user_run(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    match crate::usuario::lancar_exemplo() {
        Ok(id) => {
            w.field_bool("launched", true)?;
            w.field_u64("thread_id", id)?;
        }
        Err(motivo) => {
            w.field_bool("launched", false)?;
            w.field_str("error", motivo)?;
        }
    }
    w.end_object()
}

fn user_stats(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    let (chamadas, recusadas, bytes) = crate::usuario::estatisticas();

    w.begin_object()?;
    w.field_u64("syscalls", chamadas)?;
    // Recusadas sao pedidos que o kernel se negou a atender: numero de chamada
    // desconhecido, ou um ponteiro que nao pertence ao processo. Um valor que
    // sobe sozinho denuncia um processo tentando alcancar o que nao e dele.
    w.field_u64("rejected", recusadas)?;
    w.field_u64("bytes_written", bytes)?;

    w.key("last_exit")?;
    match crate::usuario::ultima_saida() {
        Some(codigo) => w.i64_value(codigo)?,
        None => w.null_value()?,
    }

    w.field_u64("user_base", crate::usuario::BASE)?;
    w.field_u64("user_top", crate::usuario::TETO)?;
    // O codigo que o programa de exemplo devolve. Publicado para que quem
    // chama `user.run` possa conferir que o `last_exit` veio dele, e nao de
    // um processo anterior ou de uma falha.
    w.field_u64(
        "example_exit_code",
        crate::usuario::exemplo::CODIGO_DE_SAIDA as u64,
    )?;
    w.end_object()
}

// ---------------------------------------------------------------------------
// threads.*
// ---------------------------------------------------------------------------

fn threads_stats(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    let (vivos, trocas, quanta_vencidos) = crate::fios::estatisticas();

    w.begin_object()?;
    w.field_u64("alive", vivos as u64)?;
    w.field_u64("context_switches", trocas)?;
    // Um quantum vence sem gerar troca quando nao ha outro fio pronto, entao
    // comparar os dois numeros diz se o sistema tem concorrencia de verdade ou
    // um fio so. Muitas trocas e poucos vencimentos significa que os fios
    // cedem sozinhos; o contrario, que alguem segura a CPU ate o timer tira-la.
    w.field_u64("quantum_expirations", quanta_vencidos)?;
    w.field_u64("quantum_ticks", crate::fios::QUANTUM_EM_TIQUES as u64)?;
    w.field_u64("max_threads", crate::fios::MAX_FIOS as u64)?;
    w.end_object()
}

fn threads_list(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.key("threads")?;
    w.begin_array()?;

    let mut erro: Option<fmt::Error> = None;
    crate::fios::com_inscricoes(|inscricao| {
        if erro.is_some() {
            return;
        }
        let resultado = (|| -> fmt::Result {
            w.begin_object()?;
            w.field_u64("id", inscricao.id)?;
            w.field_str("name", inscricao.nome)?;
            w.field_str("state", inscricao.estado)?;
            w.field_u64("scheduled", inscricao.escalonamentos)?;
            w.end_object()
        })();
        if let Err(e) = resultado {
            erro = Some(e);
        }
    });

    w.end_array()?;
    w.end_object()?;

    match erro {
        Some(e) => Err(e),
        None => Ok(()),
    }
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
    w.field_u64(
        "dropped_regions",
        crate::machine::regioes_descartadas() as u64,
    )?;
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
// traps.* e debug.*
// ---------------------------------------------------------------------------

fn traps_stats(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.field_u64("total", crate::traps::total())?;
    // Diferente de zero significa que uma excecao aconteceu dentro de uma
    // secao critica de `traps`: o total esta certo, mas `by_type` e `last`
    // perderam essa falha. Aparece aqui para nao sumir em silencio.
    w.field_u64("details_lost", crate::traps::detalhes_perdidos())?;

    w.key("by_type")?;
    w.begin_array()?;
    let mut erro: Option<fmt::Error> = None;
    crate::traps::com_contadores(|nome, total| {
        if erro.is_some() {
            return;
        }
        let resultado = (|| -> fmt::Result {
            w.begin_object()?;
            w.field_str("name", nome)?;
            w.field_u64("count", total)?;
            w.end_object()
        })();
        if let Err(e) = resultado {
            erro = Some(e);
        }
    });
    w.end_array()?;

    w.key("last")?;
    match crate::traps::ultima() {
        Some(falha) => {
            w.begin_object()?;
            w.field_u64("seq", falha.seq)?;
            w.field_str("name", falha.nome)?;
            w.field_u64("pc", falha.pc)?;
            w.key("address")?;
            match falha.endereco {
                Some(endereco) => w.u64_value(endereco)?,
                None => w.null_value()?,
            }
            // O código de erro vai cru: qualquer decodificação nossa perderia
            // bits que podem importar, e o agente tem o manual da arquitetura.
            w.field_u64("raw_code", falha.codigo)?;
            w.end_object()?;
        }
        None => w.null_value()?,
    }

    w.end_object()?;

    match erro {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn debug_trigger(params: Json, w: &mut JsonWriter) -> fmt::Result {
    // `kind` é obrigatório e já foi validado como texto pelo registro, mas o
    // *valor* ainda pode ser qualquer coisa — validação de domínio é do
    // handler.
    let tipo = params.member("kind").and_then(|v| v.as_str()).unwrap_or("");

    w.begin_object()?;
    match tipo {
        "breakpoint" => {
            let antes = crate::traps::total();

            // Se o tratamento de exceções estiver quebrado, o kernel morre
            // nesta linha e o agente recebe um timeout em vez de resposta —
            // que também é um resultado informativo.
            crate::arch::disparar_breakpoint();

            w.field_str("triggered", "breakpoint")?;
            // Chegar aqui é a prova: o handler rodou e devolveu o controle.
            w.field_bool("survived", true)?;
            w.field_u64("traps_before", antes)?;
            w.field_u64("traps_after", crate::traps::total())?;
        }
        "fatal" => {
            // Uma falha *de verdade*, da qual nao se volta.
            //
            // Existe porque o modo post-mortem era a unica parte do kernel sem
            // forma de ser exercitada de fora: ate aqui, provoca-lo exigia
            // recompilar com um defeito plantado a mao. E e o caminho que
            // fecha o ciclo com `cargo xtask simbolo`, traduzindo em arquivo e
            // linha o `pc` que `traps.stats` passa a reportar.
            //
            // Agendamos em vez de falhar aqui. A serializacao e em streaming:
            // neste ponto o envelope JSON-RPC esta aberto e o `\n` que fecha o
            // quadro ainda nao saiu. Falhar agora deixaria o cliente esperando
            // para sempre por uma linha que nunca se completa. O laco dispara
            // a falha depois de a resposta estar inteira no fio.
            super::agendar_falha_fatal();

            w.field_str("scheduled", "fatal")?;
            w.field_bool("survived", false)?;
            w.field_str(
                "warning",
                "o kernel falha logo apos esta resposta e entra em modo post-mortem",
            )?;
        }
        outro => {
            w.field_bool("survived", true)?;
            w.field_str("error", "tipo de excecao nao suportado")?;
            w.field_str("requested", outro)?;
            w.field_str("supported", "breakpoint, fatal")?;
        }
    }
    w.end_object()
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
            w.field_u64("uptime_ms", registro.uptime_ms)?;
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
