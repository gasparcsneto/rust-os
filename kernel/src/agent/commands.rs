//! Os comandos que o kernel expõe ao agente.
//!
//! A superfície do sistema, para o agente e para quem digita no console — o
//! interpretador despacha por esta mesma tabela. Cada entrada de
//! [`COMANDOS`] é simultaneamente a implementação e a documentação formal do
//! comando — ver [`super::registry`].
//!
//! Nenhum comando aqui sabe em que arquitetura está rodando: todos consultam
//! [`crate::machine`] e [`crate::arch`], que os backends preencheram no boot.
//! É isso que faz a mesma resposta JSON sair de um x86 e de um ARM.
//!
//! Convenção de nomes: `<subsistema>.<ação>`. O agrupamento por prefixo deixa
//! a listagem de `agent.describe` legível, e um agente que descobre `fs.list`
//! já sabe onde procurar `fs.read`.

use core::fmt;

use super::json::{Json, JsonWriter};
use super::registry::{Acesso, Command, Mais, ParamSpec, TipoParam};
use politica::Permissao;

/// A tabela de comandos do kernel.
pub static COMANDOS: &[Command] = &[
    Command {
        nome: "agent.ping",
        resumo: "Verifica se o canal do agente esta vivo e responsivo.",
        params: &[],
        acesso: Acesso::Exige(Permissao::AgentRead),
        recurso: None,
        mais: Mais::Nada,
        handler: ping,
    },
    Command {
        nome: "agent.session",
        resumo: "A sessao deste pedido: o numero que o kernel deu ao canal por onde ele \
                 chegou, e o transporte. E o numero que o log registra como quem agiu.",
        params: &[],
        acesso: Acesso::Exige(Permissao::AgentRead),
        recurso: None,
        mais: Mais::Nada,
        handler: agent_session,
    },
    Command {
        nome: "agent.sessions",
        resumo: "As sessoes do canal do agente: a serial, e cada porta do console virtio, \
                 com o nome, se ha um agente conectado, quantas conexoes ja houve e os \
                 bytes perdidos na entrada e na saida.",
        params: &[],
        acesso: Acesso::Exige(Permissao::AgentRead),
        recurso: None,
        mais: Mais::Nada,
        handler: agent_sessions,
    },
    Command {
        nome: "agent.list",
        resumo: "Os agentes conectados agora, para os agentes se verem: a porta, o nome, \
                 o papel, ha quanto tempo esta conectado, quantos arrendamentos tem, o \
                 ultimo comando que passou pela decisao e a ultima acao (um comando que \
                 muda o estado), cada um com ha quanto tempo. E quem agiu por ultimo na \
                 maquina, e o texto que a barra mostra. Nunca os parametros de ninguem.",
        params: &[],
        acesso: Acesso::Exige(Permissao::AgentRead),
        recurso: None,
        mais: Mais::Nada,
        handler: agent_list,
    },
    Command {
        nome: "agent.registry",
        resumo: "Quem pode entrar pelas portas: a chave publica do Duke e cada agente \
                 registrado, com o nome, a chave e de onde veio (a imagem, ou um registro \
                 administrativo, gravado no journal).",
        params: &[],
        acesso: Acesso::Exige(Permissao::AgentRead),
        recurso: None,
        mais: Mais::Nada,
        handler: agent_registry,
    },
    Command {
        nome: "person.registry",
        resumo: "Quem pode entrar pelos consoles: cada pessoa registrada, com o \
                 identificador, o nome, o papel, o estado (ativa ou revogada, que fica no \
                 registro) e as sessoes abertas, com o console de cada uma. Sem credencial.",
        params: &[],
        acesso: Acesso::Exige(Permissao::AgentRead),
        recurso: None,
        mais: Mais::Nada,
        handler: person_registry,
    },
    Command {
        nome: "admin.challenge",
        resumo: "Um desafio para uma operacao administrativa nesta sessao: numero, nonce e \
                 chave efemera. Vale uma tentativa, por pouco tempo; pedir outro descarta \
                 o anterior. Com `for`, um desafio de quorum para aquela operacao, com a \
                 versao da politica, M e N.",
        params: &[ParamSpec {
            nome: "for",
            tipo: TipoParam::Texto,
            obrigatorio: false,
            descricao: "A operacao de quorum para que o desafio e pedido: admin.revoke",
        }],
        acesso: Acesso::PorProva,
        recurso: None,
        mais: Mais::Nada,
        handler: admin_challenge,
    },
    Command {
        nome: "admin.execute",
        resumo: "Executa uma operacao administrativa com a prova de um administrador sobre \
                 o desafio, a sessao, o comando e o texto exato dos parametros, ate 1024 \
                 bytes. As operacoes e o limite estao em agent.registry.",
        params: &[
            ParamSpec {
                nome: "challenge",
                tipo: TipoParam::Inteiro,
                obrigatorio: true,
                descricao: "O numero do desafio, de admin.challenge",
            },
            ParamSpec {
                nome: "command",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "A operacao administrativa",
            },
            ParamSpec {
                nome: "params",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "Os parametros da operacao, como texto JSON: o texto exato coberto pela prova",
            },
            ParamSpec {
                nome: "admin",
                tipo: TipoParam::Texto,
                obrigatorio: false,
                descricao: "A chave publica do administrador, em hex",
            },
            ParamSpec {
                nome: "proof",
                tipo: TipoParam::Texto,
                obrigatorio: false,
                descricao: "A prova, em hex",
            },
            ParamSpec {
                nome: "signatures",
                tipo: TipoParam::Texto,
                obrigatorio: false,
                descricao: "Numa operacao de quorum, no lugar de admin e proof: \
                            `chave:prova,chave:prova`, em hex, uma por credencial",
            },
        ],
        acesso: Acesso::PorProva,
        recurso: Some("command"),
        mais: Mais::Nada,
        handler: admin_execute,
    },
    Command {
        nome: "agent.describe",
        resumo: "Lista todos os comandos disponiveis com seus parametros. \
                 Chame isto primeiro para descobrir a superficie do sistema.",
        params: &[],
        acesso: Acesso::Exige(Permissao::AgentRead),
        recurso: None,
        mais: Mais::Nada,
        handler: describe,
    },
    Command {
        nome: "system.info",
        resumo: "Identificacao do kernel, arquitetura, CPU e video.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: system_info,
    },
    Command {
        nome: "memory.stats",
        resumo: "Totais agregados de memoria fisica e de MMIO mapeado.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
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
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: memory_regions,
    },
    Command {
        nome: "memory.frames",
        resumo: "Estado do alocador de frames de memoria fisica.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: memory_frames,
    },
    Command {
        nome: "heap.stats",
        resumo: "Estado do heap do kernel, incluindo fragmentacao.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
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
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: Some("address"),
        mais: Mais::Nada,
        handler: paging_translate,
    },
    Command {
        nome: "system.uptime",
        resumo: "Tempo desde o boot, em ticks do timer e em milissegundos.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: system_uptime,
    },
    Command {
        nome: "tasks.stats",
        resumo: "Estado do escalonador cooperativo e da fila de entrada.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: tasks_stats,
    },
    Command {
        nome: "tasks.list",
        resumo: "Tarefas ja lancadas, com id, nome e se ainda estao vivas.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: tasks_list,
    },
    Command {
        nome: "threads.stats",
        resumo: "Estado do escalonador preemptivo: fios vivos, trocas de contexto e preempcoes.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: threads_stats,
    },
    Command {
        nome: "threads.list",
        resumo: "Fios de execucao do kernel, com id, nome, estado e quantas vezes rodaram.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: threads_list,
    },
    Command {
        nome: "user.run",
        resumo: "Lanca um programa no anel sem privilegio, num fio proprio. \
                 Sem `path`, lanca o exemplo embutido. \
                 Nao espera o fim: consulte `user.stats` depois.",
        params: &[ParamSpec {
            nome: "path",
            tipo: TipoParam::Texto,
            obrigatorio: false,
            descricao: "Caminho do programa na arvore de arquivos, por exemplo \
                        `/bin/leitor` (padrao: o exemplo embutido).",
        }],
        acesso: Acesso::Exige(Permissao::ProcessRun),
        recurso: Some("path"),
        mais: Mais::Nada,
        handler: user_run,
    },
    Command {
        nome: "user.stats",
        resumo: "Chamadas de sistema atendidas e recusadas, bifurcacoes, trocas de \
                 imagem, saidas e o ultimo codigo de saida.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: user_stats,
    },
    Command {
        nome: "pci.list",
        resumo: "Dispositivos encontrados no barramento PCI, com fabricante, \
                 modelo e o que cada um faz.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: pci_list,
    },
    Command {
        nome: "disk.info",
        resumo: "Capacidade e estado do disco virtio, se houver um.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: disk_info,
    },
    Command {
        nome: "disk.read",
        resumo: "Le um setor de 512 bytes do disco e o devolve em hexadecimal.",
        params: &[
            ParamSpec {
                nome: "sector",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Numero do setor a ler (padrao: 0).",
            },
            ParamSpec {
                nome: "length",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Quantos bytes do setor mostrar (padrao: 64, maximo: 512).",
            },
        ],
        acesso: Acesso::Exige(Permissao::FsRawRead),
        recurso: Some("sector"),
        mais: Mais::Nada,
        handler: disk_read,
    },
    Command {
        nome: "net.info",
        resumo: "Endereco e contadores da placa de rede, se houver uma.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: net_info,
    },
    Command {
        nome: "net.arp",
        resumo: "Pergunta quem atende por um endereco IPv4 e espera a resposta.",
        params: &[
            ParamSpec {
                nome: "ip",
                tipo: TipoParam::Texto,
                obrigatorio: false,
                descricao: "IPv4 procurado, em decimal com pontos (padrao: 10.0.2.2).",
            },
            ParamSpec {
                nome: "from",
                tipo: TipoParam::Texto,
                obrigatorio: false,
                descricao: "IPv4 anunciado como origem (padrao: 10.0.2.15).",
            },
        ],
        acesso: Acesso::Exige(Permissao::NetSend),
        recurso: Some("ip"),
        mais: Mais::Nada,
        handler: net_arp,
    },
    Command {
        nome: "video.sample",
        resumo: "Amostra a tela numa grade de cores, para o agente conferir o que foi desenhado.",
        params: &[
            ParamSpec {
                nome: "columns",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Colunas da grade (padrao: 16, maximo: 64).",
            },
            ParamSpec {
                nome: "rows",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Linhas da grade (padrao: 8, maximo: 64).",
            },
        ],
        acesso: Acesso::Exige(Permissao::UiRead),
        recurso: None,
        mais: Mais::Nada,
        handler: video_sample,
    },
    Command {
        nome: "display.info",
        resumo: "A pilha grafica: qual adaptador esta ativo, as telas dele, as camadas do \
                 compositor de baixo para cima, quanta memoria as superficies seguram, o ultimo \
                 retangulo que chegou a tela e, num adaptador que so mostra o que se manda, o \
                 que atravessou para o dispositivo.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: display_info,
    },
    Command {
        nome: "ui.tree",
        resumo: "A arvore semantica do que esta na tela: cada elemento com papel, rotulo, valor, \
                 moldura e as acoes que aceita. Leia isto em vez de amostrar pixels.",
        params: &[],
        acesso: Acesso::Exige(Permissao::UiRead),
        recurso: None,
        mais: Mais::Nada,
        handler: ui_tree,
    },
    Command {
        nome: "ui.act",
        resumo: "Age sobre um elemento da arvore semantica pelo mesmo caminho de quem esta na \
                 frente da maquina. Acoes: press, confirm, cancel, set_value.",
        params: &[
            ParamSpec {
                nome: "id",
                tipo: TipoParam::Inteiro,
                obrigatorio: true,
                descricao: "O id do elemento, como `ui.tree` o publica.",
            },
            ParamSpec {
                nome: "action",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "Uma das acoes que o elemento aceita, como `ui.tree` as lista.",
            },
            ParamSpec {
                nome: "value",
                tipo: TipoParam::Texto,
                obrigatorio: false,
                descricao: "O valor novo, para `set_value`.",
            },
            ParamSpec {
                nome: "expect_version",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "A versao do campo que voce leu em `ui.tree`. Se ele mudou desde \
                            entao, CONFLICT, e nada muda.",
            },
        ],
        acesso: Acesso::Exige(Permissao::UiAct),
        recurso: Some("id"),
        mais: Mais::Nada,
        handler: ui_act,
    },
    Command {
        nome: "ui.claim",
        resumo: "Arrenda um campo da arvore para a sua sessao: ninguem mais o edita ou confirma \
                 ate voce soltar, o prazo vencer ou a sua sessao acabar. Editar um campo livre \
                 ja o arrenda; confirmar pede o arrendamento. Sem preempcao: o campo de outro \
                 e CONFLICT.",
        params: &[
            ParamSpec {
                nome: "id",
                tipo: TipoParam::Inteiro,
                obrigatorio: true,
                descricao: "O id do campo, como `ui.tree` o publica.",
            },
            ParamSpec {
                nome: "ttl_ms",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "O prazo, de 1000 a 300000 ms; 30000 se ausente. A atividade o renova.",
            },
        ],
        acesso: Acesso::Exige(Permissao::UiAct),
        recurso: Some("id"),
        mais: Mais::Nada,
        handler: ui_claim,
    },
    Command {
        nome: "ui.release",
        resumo: "Solta o arrendamento de um campo, se for seu.",
        params: &[ParamSpec {
            nome: "id",
            tipo: TipoParam::Inteiro,
            obrigatorio: true,
            descricao: "O id do campo, como `ui.tree` o publica.",
        }],
        acesso: Acesso::Exige(Permissao::UiAct),
        recurso: Some("id"),
        mais: Mais::Nada,
        handler: ui_release,
    },
    Command {
        nome: "message.send",
        resumo: "Manda uma mensagem a outro titular: um agente pelo nome, `pessoa:<id>`, \
                 `serial` ou `admin:<nome>`. Quem manda e a sua sessao, nunca um parametro. \
                 O papel do destinatario e o recurso da decisao: so os papeis do alcance do seu. \
                 O corpo e texto opaco, ate 512 bytes. O `nonce` cresce a cada pedido da \
                 sessao; o mesmo pedido com o mesmo nonce devolve o mesmo id.",
        params: &[
            ParamSpec {
                nome: "to",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "O destinatario: nome de agente, `pessoa:<16 hex>`, `serial` ou \
                            `admin:<nome>`.",
            },
            ParamSpec {
                nome: "body",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "O texto, ate 512 bytes. O kernel nao o interpreta.",
            },
            ParamSpec {
                nome: "nonce",
                tipo: TipoParam::Inteiro,
                obrigatorio: true,
                descricao: "Maior que o ultimo desta sessao; o mesmo de um pedido igual e o \
                            reenvio dele.",
            },
            ParamSpec {
                nome: "ttl_ms",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "O prazo, ate 3600000 ms; 600000 se ausente.",
            },
        ],
        acesso: Acesso::Exige(Permissao::MessageSend),
        recurso: Some("to"),
        mais: Mais::Nada,
        handler: message_send,
    },
    Command {
        nome: "message.read",
        resumo: "Le a sua caixa, em ordem de aceitacao. Ler nao consome: a mensagem fica ate \
                 o `message.ack`. Sempre a caixa da sua sessao.",
        params: &[
            ParamSpec {
                nome: "after",
                tipo: TipoParam::Texto,
                obrigatorio: false,
                descricao: "So as depois deste id.",
            },
            ParamSpec {
                nome: "max",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Quantas, de 1 a 32; 8 se ausente.",
            },
        ],
        acesso: Acesso::Exige(Permissao::MessageRead),
        recurso: None,
        mais: Mais::Nada,
        handler: message_read,
    },
    Command {
        nome: "message.ack",
        resumo: "Confirma uma mensagem da sua caixa, ja lida: ela sai da caixa.",
        params: &[
            ParamSpec {
                nome: "id",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "O id da mensagem.",
            },
            ParamSpec {
                nome: "expect_version",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "A versao lida; outra e CONFLICT.",
            },
        ],
        acesso: Acesso::Exige(Permissao::MessageRead),
        recurso: Some("id"),
        mais: Mais::Nada,
        handler: message_ack,
    },
    Command {
        nome: "message.cancel",
        resumo: "Cancela uma mensagem que voce mandou, enquanto ninguem a leu.",
        params: &[
            ParamSpec {
                nome: "id",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "O id da mensagem.",
            },
            ParamSpec {
                nome: "expect_version",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "A versao conhecida; outra e CONFLICT.",
            },
        ],
        // A permissão sobre as próprias mensagens, e não a de mandar: o
        // recurso de `message.send` é sempre um destinatário, e aqui é um
        // id. Só quem mandou cancela — a tabela confere —, e só antes da
        // primeira leitura.
        acesso: Acesso::Exige(Permissao::MessageRead),
        recurso: Some("id"),
        mais: Mais::Nada,
        handler: message_cancel,
    },
    Command {
        nome: "message.status",
        resumo: "O estado de uma mensagem que voce mandou ou recebeu.",
        params: &[ParamSpec {
            nome: "id",
            tipo: TipoParam::Texto,
            obrigatorio: true,
            descricao: "O id da mensagem.",
        }],
        acesso: Acesso::Exige(Permissao::MessageRead),
        recurso: Some("id"),
        mais: Mais::Nada,
        handler: message_status,
    },
    Command {
        nome: "disk.partitions",
        resumo: "A tabela de particoes do disco, lida da GPT.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: disk_partitions,
    },
    Command {
        nome: "btrfs.chunks",
        resumo: "O mapa de pedacos do Btrfs e a raiz da arvore de pedacos, lida por endereco logico.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: btrfs_chunks,
    },
    Command {
        nome: "btrfs.info",
        resumo: "O superbloco do sistema de arquivos da particao de dados.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: btrfs_info,
    },
    Command {
        nome: "fs.mounts",
        resumo: "O que esta montado na arvore de arquivos, e de que tipo.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: fs_mounts,
    },
    Command {
        nome: "fs.read",
        resumo: "Le um arquivo da arvore e devolve o conteudo como texto.",
        params: &[
            ParamSpec {
                nome: "path",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "Caminho absoluto do arquivo.",
            },
            ParamSpec {
                nome: "offset",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "De que byte comecar (padrao: 0).",
            },
            ParamSpec {
                nome: "max",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Quantos bytes devolver (padrao: 256, maximo: 4096).",
            },
        ],
        acesso: Acesso::Exige(Permissao::FsRead),
        recurso: Some("path"),
        mais: Mais::Nada,
        handler: fs_read,
    },
    Command {
        nome: "fs.list",
        resumo: "Lista um diretorio da arvore de arquivos.",
        params: &[ParamSpec {
            nome: "path",
            tipo: TipoParam::Texto,
            obrigatorio: false,
            descricao: "Caminho absoluto do diretorio (padrao: /bin).",
        }],
        acesso: Acesso::Exige(Permissao::FsRead),
        recurso: Some("path"),
        mais: Mais::Nada,
        handler: fs_list,
    },
    Command {
        nome: "fs.stat",
        resumo: "O que um caminho do armazem e agora: o tipo, a versao, o tamanho e o \
                 arrendamento.",
        params: &[ParamSpec {
            nome: "path",
            tipo: TipoParam::Texto,
            obrigatorio: true,
            descricao: "Caminho absoluto, abaixo de /armazem.",
        }],
        acesso: Acesso::Exige(Permissao::FsRead),
        recurso: Some("path"),
        mais: Mais::Nada,
        handler: fs_stat,
    },
    Command {
        nome: "fs.write",
        resumo: "Grava um arquivo no armazem, contra a versao que voce leu: 0 cria (e recusa se ja existe), N substitui (e recusa se a versao nao e N). O conteudo vem de `content` (texto), de `draft` (um rascunho de fs.draft) ou do anexo do pedido (binario, ate 60 KiB). O pai tem de existir. Confirmado so depois de gravado. CONFLICT diz se foi a versao ou o arrendamento de outro titular.",
        params: &[
            ParamSpec {
                nome: "path",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "Caminho absoluto, abaixo de /armazem.",
            },
            ParamSpec {
                nome: "content",
                tipo: TipoParam::Texto,
                obrigatorio: false,
                descricao: "O conteudo inteiro, em texto.",
            },
            ParamSpec {
                nome: "draft",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "O rascunho a gravar inteiro, de fs.draft.",
            },
            ParamSpec {
                nome: "expect_version",
                tipo: TipoParam::Inteiro,
                obrigatorio: true,
                descricao: "A versao que voce leu; 0 para criar.",
            },
            ParamSpec {
                nome: "attachment",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Numa porta de agente: quantos bytes de anexo vieram nos quadros de anexo antes deste pedido. Um processo manda o anexo pela chamada PEDIR_COM_ANEXO, sem este campo.",
            },
        ],
        acesso: Acesso::Exige(Permissao::FsWrite),
        recurso: Some("path"),
        mais: Mais::Nada,
        handler: fs_write,
    },
    Command {
        nome: "fs.append",
        resumo: "Acrescenta ao fim de um arquivo do armazem que existe, contra a versao de agora. O que se acrescenta vem de `content` (texto) ou do anexo do pedido (binario).",
        params: &[
            ParamSpec {
                nome: "path",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "Caminho absoluto, abaixo de /armazem.",
            },
            ParamSpec {
                nome: "content",
                tipo: TipoParam::Texto,
                obrigatorio: false,
                descricao: "O texto a acrescentar.",
            },
            ParamSpec {
                nome: "expect_version",
                tipo: TipoParam::Inteiro,
                obrigatorio: true,
                descricao: "A versao de agora.",
            },
            ParamSpec {
                nome: "attachment",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Numa porta de agente: quantos bytes de anexo vieram nos quadros de anexo antes deste pedido. Um processo manda o anexo pela chamada PEDIR_COM_ANEXO, sem este campo.",
            },
        ],
        acesso: Acesso::Exige(Permissao::FsWrite),
        recurso: Some("path"),
        mais: Mais::Nada,
        handler: fs_append,
    },
    Command {
        nome: "fs.delete",
        resumo: "Apaga um arquivo do armazem, contra a versao de agora.",
        params: &[
            ParamSpec {
                nome: "path",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "Caminho absoluto, abaixo de /armazem.",
            },
            ParamSpec {
                nome: "expect_version",
                tipo: TipoParam::Inteiro,
                obrigatorio: true,
                descricao: "A versao de agora.",
            },
        ],
        acesso: Acesso::Exige(Permissao::FsWrite),
        recurso: Some("path"),
        mais: Mais::Nada,
        handler: fs_delete,
    },
    Command {
        nome: "fs.mkdir",
        resumo: "Cria um diretorio no armazem. O pai tem de existir; nada e criado de passagem.",
        params: &[ParamSpec {
            nome: "path",
            tipo: TipoParam::Texto,
            obrigatorio: true,
            descricao: "Caminho absoluto, abaixo de /armazem.",
        }],
        acesso: Acesso::Exige(Permissao::FsWrite),
        recurso: Some("path"),
        mais: Mais::Nada,
        handler: fs_mkdir,
    },
    Command {
        nome: "fs.rmdir",
        resumo: "Remove um diretorio vazio do armazem, contra a versao de agora.",
        params: &[
            ParamSpec {
                nome: "path",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "Caminho absoluto, abaixo de /armazem.",
            },
            ParamSpec {
                nome: "expect_version",
                tipo: TipoParam::Inteiro,
                obrigatorio: true,
                descricao: "A versao de agora.",
            },
        ],
        acesso: Acesso::Exige(Permissao::FsWrite),
        recurso: Some("path"),
        mais: Mais::Nada,
        handler: fs_rmdir,
    },
    Command {
        nome: "fs.rename",
        resumo: "Move um arquivo ou diretorio do armazem (com tudo abaixo) para `to`, que nao pode existir, num pai que existe, e nao pode estar abaixo da origem. O gate decide `fs.write` nos dois caminhos; os arrendamentos de tudo abaixo de cada um contam. Cada no movido ganha versao nova.",
        params: &[
            ParamSpec {
                nome: "path",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "Caminho absoluto, abaixo de /armazem.",
            },
            ParamSpec {
                nome: "to",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "O caminho de destino, abaixo de /armazem.",
            },
            ParamSpec {
                nome: "expect_version",
                tipo: TipoParam::Inteiro,
                obrigatorio: true,
                descricao: "A versao de agora.",
            },
        ],
        acesso: Acesso::Exige(Permissao::FsWrite),
        recurso: Some("path"),
        mais: Mais::Parametro("to"),
        handler: fs_rename,
    },
    Command {
        nome: "fs.batch",
        resumo: "Um lote de mutacoes do armazem, tudo ou nada, num registro e numa confirmacao: `ops` e uma lista de objetos com `op` (write, append, delete, mkdir, rmdir, rename), `path`, `to` (rename), `expect_version`, e o conteudo em `content` (texto), `draft`, ou `offset`/`length` no anexo do pedido. Cada operacao ve as anteriores. O gate decide `fs.write` em todos os caminhos. Ate 32 operacoes.",
        params: &[
            ParamSpec {
                nome: "ops",
                tipo: TipoParam::Lista,
                obrigatorio: true,
                descricao: "As operacoes, em ordem.",
            },
            ParamSpec {
                nome: "attachment",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Numa porta de agente: quantos bytes de anexo vieram nos quadros de anexo antes deste pedido. Um processo manda o anexo pela chamada PEDIR_COM_ANEXO, sem este campo.",
            },
        ],
        acesso: Acesso::Exige(Permissao::FsWrite),
        recurso: None,
        mais: Mais::Lote("ops"),
        handler: fs_batch,
    },
    Command {
        nome: "fs.draft",
        resumo: "Acrescenta o anexo do pedido (ou `content`) a um rascunho para `path` — cria um sem `draft`. Os blocos vao para o volume ja, e contam na sua cota; fs.write com `draft` grava o rascunho inteiro num lote so. Um rascunho sem uso some em 5 minutos.",
        params: &[
            ParamSpec {
                nome: "path",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "Caminho absoluto, abaixo de /armazem.",
            },
            ParamSpec {
                nome: "draft",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "O rascunho a continuar; sem ele, um novo.",
            },
            ParamSpec {
                nome: "content",
                tipo: TipoParam::Texto,
                obrigatorio: false,
                descricao: "Texto, em vez do anexo.",
            },
            ParamSpec {
                nome: "attachment",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Numa porta de agente: quantos bytes de anexo vieram nos quadros de anexo antes deste pedido. Um processo manda o anexo pela chamada PEDIR_COM_ANEXO, sem este campo.",
            },
        ],
        acesso: Acesso::Exige(Permissao::FsWrite),
        recurso: Some("path"),
        mais: Mais::Nada,
        handler: fs_draft,
    },
    Command {
        nome: "fs.discard",
        resumo: "Descarta um rascunho seu, com os blocos dele.",
        params: &[
            ParamSpec {
                nome: "path",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "Caminho absoluto, abaixo de /armazem.",
            },
            ParamSpec {
                nome: "draft",
                tipo: TipoParam::Inteiro,
                obrigatorio: true,
                descricao: "O rascunho.",
            },
        ],
        acesso: Acesso::Exige(Permissao::FsWrite),
        recurso: Some("path"),
        mais: Mais::Nada,
        handler: fs_discard,
    },
    Command {
        nome: "fs.claim",
        resumo: "Arrenda um arquivo do armazem para a sua sessao: ninguem mais o muda ate voce \
                 soltar, o prazo vencer ou a sua sessao acabar. Opcional; a versao continua \
                 sendo exigida. Sem preempcao: o de outro e CONFLICT.",
        params: &[
            ParamSpec {
                nome: "path",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "Caminho absoluto do arquivo, abaixo de /armazem (pode nao existir \
                            ainda).",
            },
            ParamSpec {
                nome: "ttl_ms",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "O prazo, de 1000 a 300000 ms; 30000 se ausente. A atividade o renova.",
            },
        ],
        acesso: Acesso::Exige(Permissao::FsWrite),
        recurso: Some("path"),
        mais: Mais::Nada,
        handler: fs_claim,
    },
    Command {
        nome: "fs.release",
        resumo: "Solta o arrendamento de um arquivo do armazem, se for seu.",
        params: &[ParamSpec {
            nome: "path",
            tipo: TipoParam::Texto,
            obrigatorio: true,
            descricao: "Caminho absoluto do arquivo, abaixo de /armazem.",
        }],
        acesso: Acesso::Exige(Permissao::FsWrite),
        recurso: Some("path"),
        mais: Mais::Nada,
        handler: fs_release,
    },
    Command {
        nome: "keyboard.read",
        resumo: "O que foi digitado no teclado da maquina, e os contadores dele. Tira da fila o que devolve.",
        params: &[ParamSpec {
            nome: "max",
            tipo: TipoParam::Inteiro,
            obrigatorio: false,
            descricao: "Quantos caracteres tirar da fila (padrao: 64, maximo: 64).",
        }],
        acesso: Acesso::Exige(Permissao::KeyboardRead),
        recurso: None,
        mais: Mais::Nada,
        handler: keyboard_read,
    },
    Command {
        nome: "irq.stats",
        resumo: "Contadores de interrupcoes de hardware por linha.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: irq_stats,
    },
    Command {
        nome: "traps.stats",
        resumo: "Contadores de excecoes por tipo e detalhes da ultima falha.",
        params: &[],
        acesso: Acesso::Exige(Permissao::SystemRead),
        recurso: None,
        mais: Mais::Nada,
        handler: traps_stats,
    },
    Command {
        nome: "debug.trigger",
        resumo: "Dispara uma excecao de proposito, para autoteste. \
                 `kind`: \"breakpoint\" e recuperavel; \"fatal\" mata o kernel \
                 e o deixa em modo post-mortem; \"hang_core\" trava um nucleo \
                 com as interrupcoes desligadas.",
        params: &[
            ParamSpec {
                nome: "kind",
                tipo: TipoParam::Texto,
                obrigatorio: true,
                descricao: "`breakpoint`: recuperavel, o kernel segue vivo. \
                            `fatal`: provoca uma falha irrecuperavel de proposito; \
                            o kernel entra em modo post-mortem e passa a responder \
                            apenas o relatorio da falha. \
                            `hang_core`: trava o nucleo `core` com as interrupcoes \
                            desligadas, por `ms` milissegundos (zero: para sempre).",
            },
            ParamSpec {
                nome: "core",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Para `hang_core`: o nucleo a travar. O primeiro, o \
                            do canal, e recusado.",
            },
            ParamSpec {
                nome: "ms",
                tipo: TipoParam::Inteiro,
                obrigatorio: false,
                descricao: "Para `hang_core`: por quanto tempo; zero ou ausente \
                            trava para sempre. Teto de dez minutos.",
            },
        ],
        acesso: Acesso::Exige(Permissao::DebugTrigger),
        recurso: Some("kind"),
        mais: Mais::Nada,
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
        acesso: Acesso::Exige(Permissao::LogRead),
        recurso: None,
        mais: Mais::Nada,
        handler: log_tail,
    },
    Command {
        nome: "audit.tail",
        resumo: "Os registros mais recentes da auditoria encadeada, com tudo o que entra no \
                 elo: quem, o que, o codigo, o BLAKE2s dos parametros, o elo anterior e o \
                 proprio. Basta para refazer a cadeia fora da maquina.",
        params: &[ParamSpec {
            nome: "count",
            tipo: TipoParam::Inteiro,
            obrigatorio: false,
            descricao: "Quantos registros, do mais recente para tras (padrao: 32, teto: 128).",
        }],
        acesso: Acesso::Exige(Permissao::AuditRead),
        recurso: None,
        mais: Mais::Nada,
        handler: audit_tail,
    },
    Command {
        nome: "audit.head",
        resumo: "A cabeca da auditoria: o elo do ultimo registro, para ancorar fora da \
                 maquina, com o numero dele, a ancora da janela guardada e quantos ha nela.",
        params: &[],
        acesso: Acesso::Exige(Permissao::AuditRead),
        recurso: None,
        mais: Mais::Nada,
        handler: audit_head,
    },
    Command {
        nome: "audit.verify",
        resumo: "Refaz a cadeia guardada a partir da ancora e diz se cada elo confere; se \
                 nao, o primeiro registro que nao confere.",
        params: &[],
        acesso: Acesso::Exige(Permissao::AuditRead),
        recurso: None,
        mais: Mais::Nada,
        handler: audit_verify,
    },
    Command {
        nome: "policy.show",
        resumo: "A politica em vigor: cada papel com as permissoes, os recursos e a taxa; o \
                 papel da serial e o da autoridade local (o console e os processos do \
                 sistema); o limite de apertos; e se ela veio do disco ou e a de emergencia.",
        params: &[],
        acesso: Acesso::Exige(Permissao::PolicyRead),
        recurso: None,
        mais: Mais::Nada,
        handler: policy_show,
    },
];

// ---------------------------------------------------------------------------
// agent.*
// ---------------------------------------------------------------------------

fn agent_session(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    // A sessão do canal que pediu. Uma pessoa no interpretador e um
    // processo não falam por canal: não têm sessão a descrever.
    let Some(sessao) = crate::autorizacao::sessao_do_canal() else {
        w.begin_object()?;
        w.key("session")?;
        w.null_value()?;
        w.field_str("error", "quem pediu nao fala por um canal do agente")?;
        return w.end_object();
    };
    let canal = if sessao == super::sessao::SERIAL {
        super::sessao::Canal::Serial
    } else {
        super::sessao::Canal::Porta(sessao)
    };
    w.begin_object()?;
    w.field_u64("session", sessao as u64)?;
    w.field_str("transport", canal.transporte())?;
    escrever_identidade(w, sessao)?;
    w.end_object()
}

/// Quem está numa sessão: numa porta, o agente que provou a chave; na
/// serial, ninguém — ela é aberta, o canal de emergência.
fn escrever_identidade(w: &mut JsonWriter, sessao: u8) -> fmt::Result {
    if sessao == super::sessao::SERIAL {
        w.field_bool("authenticated", false)?;
        w.field_bool("emergency", true)?;
        let papel = crate::autorizacao::com_politica(|p| alloc::string::String::from(p.serial()));
        return w.field_str("role", &papel);
    }
    match crate::sessoes::identidade(sessao) {
        Some(id) => {
            w.field_bool("authenticated", true)?;
            w.field_str("agent", &id.nome)?;
            w.field_str("key", &sigilo::hex(&id.chave))?;
            w.key("role")?;
            // O papel de agora, e não o do aperto: uma atribuição vale na
            // hora — ver [`crate::autorizacao`].
            match crate::identidade::papel_do_agente(&id.chave) {
                Some(papel) => w.str_value(&papel)?,
                None => w.null_value()?,
            }
            w.field_u64("since_ms", id.desde_ms)
        }
        None => w.field_bool("authenticated", false),
    }
}

// ---------------------------------------------------------------------------
// audit.* e policy.*
// ---------------------------------------------------------------------------

/// O teto de `audit.tail`: a resposta inteira é montada na memória antes de
/// sair por uma porta, e cada registro tem perto de quinhentos bytes.
const MAIOR_CAUDA_DA_AUDITORIA: u64 = 128;

fn audit_tail(params: Json, w: &mut JsonWriter) -> fmt::Result {
    let n = params
        .member("count")
        .and_then(|v| v.as_u64())
        .unwrap_or(32)
        .min(MAIOR_CAUDA_DA_AUDITORIA) as usize;
    // Copiados, e a trava solta antes de escrever: a escrita vai ao canal,
    // e o canal não é lugar de segurar a trava da auditoria.
    let registros =
        crate::autorizacao::com_auditoria(|c| politica::auditoria::copiar(c.ultimos(n)))
            .unwrap_or_default();
    // Até onde a cadeia está no journal: o que vem depois ainda é só da
    // memória, e uma queda de energia o leva.
    let gravada = crate::persistencia::auditoria_gravada();
    w.begin_object()?;
    w.field_u64("durable_seq", gravada)?;
    w.key("records")?;
    w.begin_array()?;
    for r in &registros {
        let e = &r.evento;
        w.begin_object()?;
        w.field_u64("seq", r.seq)?;
        w.field_u64("ts_ms", e.ts_ms)?;
        w.field_str("holder", e.titular.nome())?;
        w.field_u64("session", u64::from(e.sessao))?;
        w.key("person_session")?;
        match &e.sessao_de_pessoa {
            Some(s) => w.str_value(&sigilo::hex_de(s))?,
            None => w.null_value()?,
        }
        w.field_str("agent", &e.agente)?;
        w.key("key")?;
        match &e.chave {
            Some(k) => w.str_value(&sigilo::hex(k))?,
            None => w.null_value()?,
        }
        w.field_str("role", &e.papel)?;
        w.field_str("method", &e.metodo)?;
        w.field_str("resource", &e.recurso)?;
        w.field_str("result", e.codigo.resultado())?;
        w.field_str("code", e.codigo.nome())?;
        w.field_str("params", &sigilo::hex(&e.parametros))?;
        w.field_str("detail", &e.detalhe)?;
        w.field_str("prev", &sigilo::hex(&r.anterior))?;
        w.field_str("link", &sigilo::hex(&r.elo))?;
        w.field_bool("durable", r.seq <= gravada)?;
        w.end_object()?;
    }
    w.end_array()?;
    w.end_object()
}

fn audit_head(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    let estado = crate::autorizacao::com_auditoria(|c| {
        (c.ultima_seq(), c.cabeca(), c.ancora(), c.guardados())
    });
    w.begin_object()?;
    match estado {
        Some((seq, cabeca, ancora, guardados)) => {
            w.field_u64("seq", seq)?;
            w.field_str("head", &sigilo::hex(&cabeca))?;
            w.field_str("anchor", &sigilo::hex(&ancora))?;
            w.field_u64("stored", guardados as u64)?;
            w.field_u64(
                "capacity",
                crate::autorizacao::CAPACIDADE_DA_AUDITORIA as u64,
            )?;
            w.field_u64("durable_seq", crate::persistencia::auditoria_gravada())?;
        }
        None => w.field_str("error", "a auditoria nao foi iniciada")?,
    }
    w.end_object()
}

fn audit_verify(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    let r = crate::autorizacao::com_auditoria(|c| (c.verificar(), c.guardados()));
    w.begin_object()?;
    match r {
        Some((Ok(cabeca), guardados)) => {
            w.field_bool("ok", true)?;
            w.field_str("head", &sigilo::hex(&cabeca))?;
            w.field_u64("checked", guardados as u64)?;
        }
        Some((Err(seq), _)) => {
            w.field_bool("ok", false)?;
            w.field_u64("failed_at", seq)?;
        }
        None => w.field_str("error", "a auditoria nao foi iniciada")?,
    }
    w.end_object()
}

fn policy_show(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    let politica = crate::autorizacao::com_politica(Clone::clone);
    w.begin_object()?;
    w.field_str("path", crate::autorizacao::CAMINHO_DA_POLITICA)?;
    w.field_bool("from_disk", crate::autorizacao::politica_do_disco())?;
    w.field_str("serial_role", politica.serial())?;
    w.field_str("local_role", politica.local())?;
    let apertos = politica.apertos();
    w.key("handshakes")?;
    w.begin_object()?;
    w.field_u64("max", u64::from(apertos.quantos))?;
    w.field_u64("window_ms", apertos.janela_ms)?;
    w.end_object()?;
    w.key("roles")?;
    w.begin_array()?;
    for papel in politica.papeis() {
        w.begin_object()?;
        w.field_str("name", &papel.nome)?;
        w.key("includes")?;
        w.begin_array()?;
        for incluido in &papel.inclui {
            w.str_value(incluido)?;
        }
        w.end_array()?;
        w.key("permissions")?;
        w.begin_array()?;
        for p in papel.permissoes() {
            w.str_value(p.nome())?;
        }
        w.end_array()?;
        w.key("resources")?;
        w.begin_object()?;
        for (p, prefixos) in &papel.recursos {
            w.key(p.nome())?;
            w.begin_array()?;
            for prefixo in prefixos {
                w.str_value(prefixo)?;
            }
            w.end_array()?;
        }
        w.end_object()?;
        w.key("rate")?;
        w.begin_object()?;
        w.field_u64("per_second", u64::from(papel.taxa.por_segundo))?;
        w.field_u64("burst", u64::from(papel.taxa.rajada))?;
        w.end_object()?;
        w.end_object()?;
    }
    w.end_array()?;
    w.end_object()
}

fn admin_challenge(params: Json, w: &mut JsonWriter) -> fmt::Result {
    let para = params.member("for").and_then(|v| v.as_str());
    super::administracao::desafiar(para, w)
}

/// Os parâmetros são lidos aqui, como os de todo comando; quem confere a
/// prova e executa é [`super::administracao`].
fn admin_execute(params: Json, w: &mut JsonWriter) -> fmt::Result {
    let mut buffer = [0u8; super::administracao::MAIORES_PARAMETROS];
    let pedido = super::administracao::Pedido {
        desafio: params.member("challenge").and_then(|v| v.as_u64()),
        comando: params.member("command").and_then(|v| v.as_str()),
        parametros: params
            .member("params")
            .and_then(|v| v.desescapar_em(&mut buffer)),
        administrador: params
            .member("admin")
            .and_then(|v| v.as_str())
            .and_then(sigilo::de_hex),
        prova: params
            .member("proof")
            .and_then(|v| v.as_str())
            .and_then(sigilo::de_hex),
        assinaturas: params.member("signatures").and_then(|v| v.as_str()),
    };
    super::administracao::executar(pedido, w)
}

fn agent_registry(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.key("duke_key")?;
    match crate::identidade::publica_do_duke() {
        Some(k) => w.str_value(&sigilo::hex(&k))?,
        None => w.null_value()?,
    }
    w.key("agents")?;
    w.begin_array()?;
    for a in crate::identidade::agentes() {
        w.begin_object()?;
        w.field_str("name", &a.nome)?;
        w.field_str("key", &sigilo::hex(&a.chave))?;
        w.key("role")?;
        match &a.papel {
            Some(papel) => w.str_value(papel)?,
            None => w.null_value()?,
        }
        w.field_str("origin", a.origem.como_str())?;
        w.end_object()?;
    }
    w.end_array()?;
    w.field_u64(
        "administrators",
        crate::identidade::quantos_administradores() as u64,
    )?;
    w.key("admin_operations")?;
    w.begin_array()?;
    for (nome, _) in super::administracao::operacoes() {
        w.str_value(nome)?;
    }
    w.end_array()?;
    w.field_u64(
        "admin_max_params",
        super::administracao::MAIORES_PARAMETROS as u64,
    )?;
    w.end_object()
}

fn person_registry(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.key("persons")?;
    w.begin_array()?;
    for p in crate::pessoas::resumos() {
        w.begin_object()?;
        w.field_str("id", &p.id.texto())?;
        w.field_str("name", &p.nome)?;
        w.field_str("role", &p.papel)?;
        w.field_str("state", p.estado.nome())?;
        w.key("sessions")?;
        w.begin_array()?;
        for (id, console, desde) in &p.sessoes {
            w.begin_object()?;
            w.field_str("session", &id.texto())?;
            w.field_str("console", &console.texto())?;
            w.field_u64("since_ms", *desde)?;
            w.end_object()?;
        }
        w.end_array()?;
        w.end_object()?;
    }
    w.end_array()?;
    w.end_object()
}

fn agent_sessions(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    use crate::virtio::console;
    w.begin_object()?;
    w.key("current")?;
    match crate::autorizacao::sessao_do_canal() {
        Some(s) => w.u64_value(s as u64)?,
        None => w.null_value()?,
    }
    w.key("sessions")?;
    w.begin_array()?;
    w.begin_object()?;
    w.field_u64("session", super::sessao::SERIAL as u64)?;
    w.field_str("transport", "serial")?;
    escrever_identidade(w, super::sessao::SERIAL)?;
    w.field_u64("lost_in", super::sessao::Canal::Serial.perdidos())?;
    w.end_object()?;
    for p in 1..=console::PORTAS {
        if !console::anunciada(p) {
            continue;
        }
        let mut nome = [0u8; 32];
        let n = console::nome(p, &mut nome);
        w.begin_object()?;
        w.field_u64("session", p as u64)?;
        w.field_str("transport", "virtio-console")?;
        w.field_str("name", core::str::from_utf8(&nome[..n]).unwrap_or(""))?;
        w.field_bool("connected", console::aberta(p))?;
        w.field_u64("connections", console::geracao(p))?;
        w.field_u64("lost_in", console::perdidos(p))?;
        w.field_u64("lost_out", console::perdidos_na_saida(p))?;
        escrever_identidade(w, p)?;
        w.end_object()?;
    }
    w.end_array()?;
    let (recusados, encerradas) = crate::sessoes::contadores();
    w.field_u64("handshakes_refused", recusados)?;
    w.field_u64("sessions_ended", encerradas)?;
    let (recebidos, enviados) = console::trafego();
    w.field_u64("console_bytes_in", recebidos)?;
    w.field_u64("console_bytes_out", enviados)?;
    w.end_object()
}

/// `agent.list`: quem está conectado, e o que cada um fez por último.
///
/// O comando e o momento, e nunca os parâmetros: o que um agente pediu é
/// dele — a auditoria guarda o resumo, e só quem tem `audit.read` o lê. E
/// nada das caixas de mensagem dos outros: quantas mensagens um tem diria
/// quem fala com quem.
fn agent_list(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    let agora = crate::tempo::uptime_ms();
    // Um comando e o momento dele, como `{method, ago_ms}`, ou `null`.
    let feito = |w: &mut JsonWriter, chave: &str, f: Option<(&str, u64)>| -> fmt::Result {
        w.key(chave)?;
        match f {
            Some((metodo, quando)) => {
                w.begin_object()?;
                w.field_str("method", metodo)?;
                w.field_u64("ago_ms", agora.saturating_sub(quando))?;
                w.end_object()
            }
            None => w.null_value(),
        }
    };
    let conectados: alloc::vec::Vec<_> = crate::atividade::conectados().collect();
    w.begin_object()?;
    w.field_u64("connected", conectados.len() as u64)?;
    w.key("agents")?;
    w.begin_array()?;
    for (p, id) in &conectados {
        let uso = crate::atividade::uso(*p, &id.chave);
        w.begin_object()?;
        w.field_u64("session", u64::from(*p))?;
        w.field_str("name", &id.nome)?;
        match crate::identidade::papel_do_agente(&id.chave) {
            Some(papel) => w.field_str("role", &papel)?,
            None => {
                w.key("role")?;
                w.null_value()?;
            }
        }
        w.field_u64("connected_ms", agora.saturating_sub(id.desde_ms))?;
        w.field_u64(
            "leases",
            crate::coordenacao::quantos_do_agente(*p, id.chave) as u64,
        )?;
        feito(w, "last_command", uso.and_then(|u| u.comando))?;
        feito(w, "last_action", uso.and_then(|u| u.acao))?;
        w.end_object()?;
    }
    w.end_array()?;
    w.key("last")?;
    match crate::atividade::ultima() {
        Some(a) => {
            w.begin_object()?;
            w.field_str("actor", &a.rotulo)?;
            w.field_str("role", &a.papel)?;
            w.field_str("method", a.metodo)?;
            w.field_u64("ago_ms", agora.saturating_sub(a.quando_ms))?;
            w.end_object()?;
        }
        None => w.null_value()?,
    }
    if let Some((_, texto)) = crate::barra::indicador_na_tela() {
        w.field_str("indicator", &texto)?;
    }
    w.end_object()
}

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

    // O que o cliente deve fazer ao conectar, e por que ninguém além dele pode
    // fazer. O kernel não enxerga a conexão — não há linha de modem entre ele
    // e a serial —, então um pedaço de requisição deixado por quem desconectou
    // antes cola no primeiro pedido de quem chega. Uma linha vazia fecha esse
    // pedaço; se não havia nenhum, não custa nada.
    //
    // Vai em `describe`, e não só num comentário, porque este canal existe
    // para ser descoberto em tempo de execução: uma convenção que só está na
    // documentação é uma convenção que o agente não tem como seguir.
    w.key("on_connect")?;
    w.begin_object()?;
    w.field_str(
        "send",
        core::str::from_utf8(crate::agent::LIMPAR_AO_CONECTAR).unwrap_or("\\n"),
    )?;
    w.field_str(
        "why",
        "fecha um quadro que o cliente anterior possa ter deixado pela metade",
    )?;
    // E o que fazer com o que vier em resposta a isso.
    w.field_str(
        "expect",
        "pode vir um quadro de erro referente ao lixo anterior; case respostas por id e ignore o que nao pediu",
    )?;
    w.end_object()?;

    w.key("commands")?;
    w.begin_array()?;
    for cmd in crate::agent::registry::todos() {
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
    // A última fase completa do roteiro. Era um "0" escrito aqui à mão, e
    // continuou dizendo isso por cinco fases — ver [`crate::FASE`].
    w.field_str("phase", crate::FASE)?;
    // A versão da interface nativa — o que um programa do Duke pode pedir
    // pelo registro, e como. Ver `docs/INTERFACE.md`.
    w.field_u64(
        "native_interface",
        protocolo::usuario::nativo::VERSAO as u64,
    )?;

    let cpu = crate::arch::identificar_cpu();
    w.field_str("cpu_vendor", cpu.como_str())?;

    // Os núcleos, e o pulso de cada um. É por aqui que um agente responde
    // "um núcleo travou?" sem perguntar nada ao núcleo travado: um núcleo
    // cujo `ticks` parou de crescer está com as interrupções desligadas há
    // esse tempo todo. Tudo atômico, sem trava — ver `crate::nucleos`.
    w.field_u64("cores_online", crate::nucleos::ligados() as u64)?;
    w.field_u64("cores_beyond_limit", crate::nucleos::descartados() as u64)?;
    // Quantas vezes um núcleo mandou os outros largarem uma tradução do
    // kernel, e quantas vezes precisou reenviar o aviso a quem demorava a
    // confirmar. No ARM são sempre zero: lá o hardware difunde a
    // invalidação.
    w.field_u64(
        "remote_tlb_invalidations",
        crate::arch::invalidacoes_remotas(),
    )?;
    w.field_u64("remote_tlb_resends", crate::arch::reavisos_remotos())?;
    // Depois de uma falha fatal: quais núcleos pararam a pedido do caminho
    // de falha, e quais não responderam — como máscaras de bits.
    // Quantas vezes um núcleo acordou outro que dormia sem trabalho.
    w.field_u64("core_wakeups_sent", crate::nucleos::cutucoes())?;
    let (parados, sem_resposta) = crate::nucleos::parada_do_fim();
    w.field_u64("fatal_stopped_mask", parados as u64)?;
    w.field_u64("fatal_unanswered_mask", sem_resposta as u64)?;
    w.key("cores")?;
    w.begin_array()?;
    let mut erro: Option<fmt::Error> = None;
    crate::nucleos::com_nucleos(|n| {
        if erro.is_some() {
            return;
        }
        let resultado = (|| -> fmt::Result {
            w.begin_object()?;
            w.field_u64("index", n.indice as u64)?;
            w.field_str("state", n.estado.nome())?;
            w.field_u64("hardware_id", n.hardware)?;
            w.field_u64("ticks", n.tiques)?;
            w.end_object()
        })();
        if let Err(e) = resultado {
            erro = Some(e);
        }
    });
    if let Some(e) = erro {
        return Err(e);
    }
    w.end_array()?;

    w.key("framebuffer")?;
    match crate::tela::tela_fisica() {
        Some(t) => {
            w.begin_object()?;
            w.field_u64("width", t.largura as u64)?;
            w.field_u64("height", t.altura as u64)?;
            w.field_u64("stride", t.stride as u64)?;
            w.field_u64("bytes_per_pixel", t.bytes_por_pixel as u64)?;
            w.field_str("pixel_format", t.formato.como_str())?;
            w.end_object()?;
        }
        None => w.null_value()?,
    }

    w.field_u64("uptime_ms", crate::tempo::uptime_ms())?;
    // O relógio de parede, cru: o que o RTC diz, em segundos desde 1970.
    // Cru de propósito — o tempo que vale para prazos é o lógico, que a
    // persistência mantém e nunca volta; este é o que o hardware diz.
    w.key("rtc")?;
    match crate::relogio::agora() {
        Some(s) => w.u64_value(s)?,
        None => w.null_value()?,
    }
    // A persistência: se as operações de autoridade podem acontecer agora,
    // e por que não; a geração administrativa, que um signatário de quórum
    // compara com a maior que já viu; a âncora do TPM; e o tempo lógico,
    // que nunca volta.
    w.key("persistence")?;
    w.begin_object()?;
    let (estado, geracao, ancora, registros, boots) = crate::persistencia::relatorio();
    w.field_str("state", estado.como_str())?;
    w.field_str("reason", estado.motivo())?;
    w.field_u64("generation", geracao)?;
    w.key("anchor")?;
    match ancora {
        Some(a) => w.u64_value(a)?,
        None => w.null_value()?,
    }
    w.field_u64("records", registros)?;
    w.field_u64(
        "audit_records",
        crate::persistencia::registros_de_auditoria(),
    )?;
    w.field_u64(
        "audit_durable_seq",
        crate::persistencia::auditoria_gravada(),
    )?;
    // A região do journal e quanto dela está ocupado: a compactação
    // acontece com três quartos.
    let (regiao, compactacoes, usados, setores) = crate::persistencia::regiao();
    w.field_u64("region", regiao as u64)?;
    w.field_u64("region_used", usados)?;
    w.field_u64("region_sectors", setores)?;
    w.field_u64("compactions", compactacoes)?;
    // O TPM: por qual interface, e a impressão da EK com que o journal
    // fala — os oito primeiros bytes do ponto, para distinguir um TPM de
    // outro sem expor nada que importe.
    w.field_str("tpm_interface", crate::tpm::interface().unwrap_or("none"))?;
    let mut impressao = [0u8; 16];
    let ek = crate::persistencia::ponto_da_ek()
        .map(|p| {
            for (i, b) in p[..8].iter().enumerate() {
                impressao[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
                impressao[2 * i + 1] = b"0123456789abcdef"[(b & 0xF) as usize];
            }
            core::str::from_utf8(&impressao).unwrap_or("")
        })
        .unwrap_or("");
    w.field_str("tpm_ek", ek)?;
    w.field_u64("boots", boots)?;
    w.field_u64("clock", crate::persistencia::agora())?;
    // O que o disco confirmou: escritas e descargas. É de fora que se vê
    // uma operação de autoridade terminar numa descarga.
    let (escritas, descargas) =
        crate::virtio::blk::com_o_disco(|d| d.contadores()).unwrap_or((0, 0));
    w.field_u64("disk_writes", escritas)?;
    w.field_u64("disk_flushes", descargas)?;
    w.end_object()?;
    w.field_u64("log_records", crate::log::total_emitidos())?;
    // Bytes que a porta serial nao conseguiu enviar. Diferente de zero aqui
    // quer dizer que o que se le do log esta incompleto, e e a unica forma de
    // saber disso: a espera por espaco na FIFO tem teto — sem ele o kernel
    // travaria — e o que nao coube dentro do teto e descartado.
    w.field_u64(
        "log_bytes_dropped",
        crate::serial::bytes_de_saida_perdidos(),
    )?;

    // Como um estouro de pilha se manifesta nesta máquina. Serve para
    // correlação: um agente que veja este nome aparecer em `traps.stats`
    // depois de uma falha sabe que foi a pilha, e não outra coisa.
    w.key("stack_guard")?;
    w.begin_object()?;
    w.field_str("mechanism", "guard-page")?;
    w.field_str("fault", crate::arch::falha_de_estouro_de_pilha())?;
    w.end_object()?;

    // De onde vêm as chaves efêmeras. Sem fonte, o gerador não é semeado e
    // as portas de agente recusam o aperto de mão: este campo é o que diz
    // por quê, de dentro da serial, que continua aberta.
    w.key("entropy")?;
    w.begin_object()?;
    w.field_str("source", "virtio-rng")?;
    w.field_bool("present", crate::virtio::entropia::presente())?;
    w.field_bool("generator_seeded", crate::aleatorio::semeado())?;
    match crate::virtio::entropia::entregues() {
        Some(n) => w.field_u64("bytes_delivered", n)?,
        None => {
            w.key("bytes_delivered")?;
            w.null_value()?
        }
    }
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

    // A cópia na escrita quebra a equivalência entre "frame usado" e "uma
    // página apontando para ele": depois de um `fork`, um frame serve dois
    // espaços de endereços. Sem estes campos, um agente vendo `used` parado
    // enquanto dois processos rodam não teria como saber se a memória está
    // sendo compartilhada ou se a contabilidade está errada.
    let (compartilhadas, resolvidas, copiadas) =
        crate::paginacao::estatisticas_de_copia_na_escrita();
    w.key("copy_on_write")?;
    w.begin_object()?;
    w.field_u64("shared_frames", crate::frames::compartilhados() as u64)?;
    w.field_u64("pages_shared", compartilhadas)?;
    w.field_u64("faults_resolved", resolvidas)?;
    // A diferença entre `faults_resolved` e `copies` é o que a cópia na
    // escrita economizou: uma resolução sem cópia é um frame de 4 KiB que
    // não foi alocado nem preenchido.
    w.field_u64("copies", copiadas)?;
    w.end_object()?;

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
// net.*
// ---------------------------------------------------------------------------

fn net_info(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;

    let dados = crate::virtio::net::com_a_placa(|placa| (placa.mac(), placa.contadores()));

    match dados {
        Some((mac, (transmitidos, recebidos))) => {
            w.field_bool("present", true)?;

            // O endereco vai como texto no formato em que se le um MAC, e nao
            // como seis numeros. Um agente que precise compara-lo compara uma
            // string; um humano que o leia reconhece o que esta vendo.
            w.key("mac")?;
            match mac {
                Some(mac) => escrever_mac(w, &mac)?,
                None => w.null_value()?,
            }

            w.field_u64("frames_sent", transmitidos)?;
            w.field_u64("frames_received", recebidos)?;
            w.field_u64("max_frame", crate::virtio::net::MAIOR_QUADRO as u64)?;
        }
        None => w.field_bool("present", false)?,
    }

    w.end_object()
}

/// O roteador da rede em modo usuario do QEMU, e o endereco que ela da ao
/// hospede.
///
/// Padroes, e nao constantes do protocolo: sao o que ha do outro lado na
/// maquina de testes, e e util que `net.arp` sem parametro nenhum ja faca uma
/// pergunta com resposta. Quem estiver noutra rede passa os dois.
const ROTEADOR_PADRAO: [u8; 4] = [10, 0, 2, 2];
const ORIGEM_PADRAO: [u8; 4] = [10, 0, 2, 15];

/// Interpreta um IPv4 em decimal com pontos.
///
/// Escrito a mao porque sao quatro numeros e tres pontos, e porque o que
/// importa e recusar o que nao e isso: um octeto acima de 255, um campo
/// vazio, pontos a mais ou a menos. Um parser permissivo aqui produziria um
/// endereco plausivel a partir de uma string errada.
fn interpretar_ipv4(texto: &str) -> Option<[u8; 4]> {
    let mut octetos = [0u8; 4];
    let mut quantos = 0;

    for parte in texto.split('.') {
        if quantos == 4 || parte.is_empty() || parte.len() > 3 {
            return None;
        }
        let mut valor = 0u16;
        for byte in parte.bytes() {
            if !byte.is_ascii_digit() {
                return None;
            }
            valor = valor * 10 + (byte - b'0') as u16;
        }
        if valor > 255 {
            return None;
        }
        octetos[quantos] = valor as u8;
        quantos += 1;
    }

    (quantos == 4).then_some(octetos)
}

fn net_arp(params: Json, w: &mut JsonWriter) -> fmt::Result {
    let procurado = params
        .member("ip")
        .and_then(|v| v.as_str())
        .map(interpretar_ipv4);
    let origem = params
        .member("from")
        .and_then(|v| v.as_str())
        .map(interpretar_ipv4);

    w.begin_object()?;

    // Um endereco malformado e recusado antes de tocar a placa. Tratar o
    // ilegivel como o padrao faria o comando responder sobre um endereco que
    // ninguem pediu.
    let (Some(procurado), Some(origem)) = (
        procurado.unwrap_or(Some(ROTEADOR_PADRAO)),
        origem.unwrap_or(Some(ORIGEM_PADRAO)),
    ) else {
        w.field_bool("ok", false)?;
        w.field_str("error", "endereco IPv4 malformado")?;
        return w.end_object();
    };

    w.key("ip")?;
    escrever_ipv4(w, &procurado)?;

    match crate::rede::resolver(&procurado, &origem) {
        Ok(mac) => {
            w.field_bool("ok", true)?;
            w.key("mac")?;
            escrever_mac(w, &mac)?;
        }
        Err(motivo) => {
            w.field_bool("ok", false)?;
            w.field_str("error", motivo)?;
        }
    }

    w.end_object()
}

/// Escreve um IPv4 em decimal com pontos.
fn escrever_ipv4(w: &mut JsonWriter, ip: &[u8; 4]) -> fmt::Result {
    w.begin_str()?;
    for (indice, octeto) in ip.iter().enumerate() {
        if indice > 0 {
            w.push_char('.')?;
        }
        // Tres digitos bastam para um octeto, e o zero a esquerda e omitido.
        let mut restante = *octeto;
        let mut digitos = [0u8; 3];
        let mut quantos = 0;
        loop {
            digitos[quantos] = restante % 10;
            quantos += 1;
            restante /= 10;
            if restante == 0 {
                break;
            }
        }
        for digito in digitos[..quantos].iter().rev() {
            w.push_char((b'0' + digito) as char)?;
        }
    }
    w.end_str()
}

/// Escreve um endereco de placa no formato em que um MAC se le.
fn escrever_mac(w: &mut JsonWriter, mac: &[u8]) -> fmt::Result {
    w.begin_str()?;
    for (indice, byte) in mac.iter().enumerate() {
        if indice > 0 {
            w.push_char(':')?;
        }
        escrever_byte_hex(w, *byte)?;
    }
    w.end_str()
}

// ---------------------------------------------------------------------------
// video.*
// ---------------------------------------------------------------------------

/// Tamanho padrao da grade de amostragem.
///
/// Dezesseis por oito cabe numa tela de terminal e ja distingue as regioes
/// grandes de uma tela — um banner no topo, um fundo, uma faixa de cor. Quem
/// precisar de detalhe pede mais.
const COLUNAS_PADRAO: u64 = 16;
const LINHAS_PADRAO: u64 = 8;
/// Teto da grade. Sessenta e quatro por sessenta e quatro sao quatro mil
/// cores, ja perto do que vale mandar por um canal serial.
const MAX_GRADE: u64 = 64;

/// Amostra a tela numa grade de cores.
///
/// # Por que uma grade, e nao os pixels
///
/// Porque um agente nao tem olhos, e porque a tela inteira sao milhoes de
/// pixels que nao cabem numa resposta. O que ele precisa responder e "foi
/// desenhado o que eu mandei desenhar?", e para isso uma amostra grosseira
/// basta: ela distingue um fundo de uma faixa, e um retangulo de nada.
///
/// A amostra e por ponto, e nao por media da regiao. A media suavizaria
/// justamente a borda entre duas cores, que e o que se quer enxergar.
/// O mapa de pedaços, e o primeiro nó lido por endereço lógico.
///
/// Os dois juntos porque é o segundo que prova o primeiro: o endereço da raiz
/// da árvore de pedaços vem do superbloco em forma lógica, e só dá para
/// lê-lo depois de o mapa traduzir. Um nó que volta com a soma certa e o
/// endereço que ele mesmo afirma é a tradução tendo funcionado.
fn btrfs_chunks(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;

    let tabela = match crate::particoes::varrer() {
        Ok(t) => t,
        Err(motivo) => {
            w.field_str("error", motivo)?;
            return w.end_object();
        }
    };
    let Some(particao) = tabela.primeira(crate::particoes::Tipo::Dados) else {
        w.field_str("error", "nao ha particao de dados no disco")?;
        return w.end_object();
    };

    let volume = match crate::vfs::btrfs::Volume::abrir(particao.primeiro) {
        Ok(v) => v,
        Err(motivo) => {
            w.field_str("error", motivo)?;
            return w.end_object();
        }
    };

    w.key("chunks")?;
    w.begin_array()?;
    for pedaco in volume.mapa.iter() {
        w.begin_object()?;
        w.field_u64("logical", pedaco.logico)?;
        w.field_u64("length", pedaco.tamanho)?;
        w.field_u64("physical", pedaco.fisico)?;
        w.field_u64("type", pedaco.tipo)?;
        w.field_u64("stripes", u64::from(pedaco.faixas))?;
        w.end_object()?;
    }
    w.end_array()?;

    let mut bloco = alloc::vec![0u8; volume.superbloco.tamanho_de_no as usize];

    // A raiz da árvore de raízes, e não mais a de pedaços: ela mora em
    // metadados, cujo pedaço tem endereço lógico e físico diferentes. Lê-la é
    // a tradução funcionando de verdade, e não por coincidência de disposição.
    match volume.ler_no(volume.superbloco.raiz, &mut bloco) {
        Ok(cabecalho) => {
            w.key("root_tree_node")?;
            w.begin_object()?;
            w.field_u64("logical", cabecalho.endereco)?;
            w.field_u64(
                "physical",
                volume.mapa.traduzir(cabecalho.endereco).unwrap_or(0),
            )?;
            w.field_u64("generation", cabecalho.geracao)?;
            w.field_u64("owner", cabecalho.dono)?;
            w.field_u64("items", u64::from(cabecalho.itens))?;
            w.field_u64("level", u64::from(cabecalho.nivel))?;
            w.end_object()?;

            // E as raízes das outras árvores, percorridas pela árvore de
            // raízes inteira — que pode ter mais de um nível, e tem assim
            // que o sistema de arquivos passa de um punhado de arquivos.
            // Ler só o nó de topo mostraria as raízes do primeiro nó e
            // omitiria as outras, sem nenhum sinal de que faltou algo.
            let mut raizes = alloc::vec::Vec::new();
            let percurso = volume.percorrer(
                volume.superbloco.raiz,
                crate::vfs::btrfs::folha::Chave {
                    objeto: 0,
                    tipo: 0,
                    offset: 0,
                },
                |item| {
                    if item.chave.tipo == crate::vfs::btrfs::folha::tipo::RAIZ {
                        raizes.push((
                            item.chave.objeto,
                            crate::vfs::btrfs::raiz_da_arvore(item.dados).unwrap_or(0),
                        ));
                    }
                    crate::vfs::btrfs::Passo::Segue
                },
            );

            w.key("roots")?;
            w.begin_array()?;
            for (arvore, bytenr) in &raizes {
                w.begin_object()?;
                w.field_u64("tree", *arvore)?;
                w.field_u64("bytenr", *bytenr)?;
                // O nível de cada árvore, que é o que diz se a descida está
                // sendo exercitada de verdade ou se tudo cabe numa folha.
                w.field_u64(
                    "level",
                    u64::from(volume.nivel_da_arvore(*bytenr).unwrap_or(0)),
                )?;
                w.end_object()?;
            }
            w.end_array()?;
            if let Err(motivo) = percurso {
                w.field_str("roots_error", motivo)?;
            }
        }
        Err(motivo) => w.field_str("error", motivo)?,
    }

    w.end_object()
}

/// O superbloco do Btrfs da partição de dados.
///
/// Todo campo aqui tem um valor conhecido do lado de fora: um
/// `btrfs inspect-internal dump-super` sobre a mesma imagem imprime os
/// mesmos números. É o que torna esta resposta uma conferência e não uma
/// afirmação — se o leitor errar um deslocamento, os dois discordam.
fn btrfs_info(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;

    let tabela = match crate::particoes::varrer() {
        Ok(t) => t,
        Err(motivo) => {
            w.field_str("error", motivo)?;
            return w.end_object();
        }
    };
    let Some(particao) = tabela.primeira(crate::particoes::Tipo::Dados) else {
        w.field_str("error", "nao ha particao de dados no disco")?;
        return w.end_object();
    };

    w.field_u64("partition_first_sector", particao.primeiro)?;

    // O bloco vai no heap: quatro kilobytes na pilha de uma tarefa do
    // executor seriam metade de uma pilha de fio.
    let mut bloco = alloc::vec![0u8; 4096];
    match crate::vfs::btrfs::do_disco(particao.primeiro, &mut bloco) {
        Ok(sb) => {
            w.field_str("label", crate::vfs::btrfs::rotulo(&bloco))?;
            w.field_u64("generation", sb.geracao)?;
            w.field_u64("root", sb.raiz)?;
            w.field_u64("root_level", u64::from(sb.nivel_da_raiz))?;
            w.field_u64("chunk_root", sb.raiz_dos_pedacos)?;
            w.field_u64("chunk_root_level", u64::from(sb.nivel_da_raiz_dos_pedacos))?;
            w.field_u64("total_bytes", sb.total)?;
            w.field_u64("bytes_used", sb.usado)?;
            w.field_u64("sectorsize", u64::from(sb.tamanho_de_setor))?;
            w.field_u64("nodesize", u64::from(sb.tamanho_de_no))?;
            w.field_u64(
                "sys_chunk_array_size",
                u64::from(sb.tamanho_do_vetor_de_pedacos),
            )?;
        }
        Err(motivo) => w.field_str("error", motivo)?,
    }

    w.end_object()
}

/// A tabela de partições.
///
/// A primeira pergunta de quem vai montar qualquer coisa: o que existe neste
/// disco, e onde. Os números saem do mesmo lugar que um `sgdisk -p` do lado
/// de fora reporta, o que torna a resposta conferível sem confiar em nós.
fn disk_partitions(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;

    match crate::particoes::varrer() {
        Ok(tabela) => {
            w.key("partitions")?;
            w.begin_array()?;
            for (numero, particao) in tabela.iter().enumerate() {
                w.begin_object()?;
                // Numeradas a partir de um, como toda ferramenta de
                // particionamento numera.
                w.field_u64("number", numero as u64 + 1)?;
                w.field_u64("first_sector", particao.primeiro)?;
                w.field_u64("sectors", particao.setores)?;
                w.field_str("type", particao.tipo.como_str())?;
                w.end_object()?;
            }
            w.end_array()?;
        }
        Err(motivo) => w.field_str("error", motivo)?,
    }

    w.end_object()
}

/// O que está montado.
///
/// A resposta mais curta do canal, e a que responde à primeira pergunta de
/// quem vai investigar qualquer coisa de arquivo: existe alguém servindo este
/// caminho?
fn fs_mounts(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.key("mounts")?;
    w.begin_array()?;
    let mut erro = Ok(());
    crate::vfs::com_montagens(|em, tipo| {
        if erro.is_err() {
            return;
        }
        erro = (|| {
            w.begin_object()?;
            w.field_str("at", em)?;
            w.field_str("type", tipo)?;
            w.end_object()
        })();
    });
    erro?;
    w.end_array()?;
    w.end_object()
}

/// Quantos bytes uma leitura de arquivo devolve por padrão, e no máximo.
///
/// O teto existe porque a resposta é uma linha do canal: um arquivo de
/// megabytes viraria um quadro que o enquadrador do outro lado recusa.
///
/// É o teto que obriga o `offset` a existir. Sem ele, um arquivo maior que
/// quatro kilobytes seria inalcançável do quinto kilobyte em diante — e a
/// resposta diria `size` sem que houvesse como chegar lá.
const BYTES_PADRAO: u64 = 256;
const BYTES_MAX: u64 = 4096;

/// Lê um arquivo da árvore.
///
/// # Por que o conteúdo sai como texto
///
/// Porque quem pergunta é um agente ou uma pessoa, e os dois leem texto. O
/// que não for UTF-8 válido é substituído em vez de recusado: um arquivo
/// binário devolve algo legível sobre o que ele **não** é, em vez de um erro
/// que não distingue "não existe" de "não é texto".
fn fs_read(params: Json, w: &mut JsonWriter) -> fmt::Result {
    let Some(caminho) = params.member("path").and_then(|v| v.as_str()) else {
        w.begin_object()?;
        w.field_str("error", "falta o parametro `path`")?;
        return w.end_object();
    };
    let max = params
        .member("max")
        .and_then(|v| v.as_u64())
        .unwrap_or(BYTES_PADRAO)
        .clamp(1, BYTES_MAX) as usize;
    let de = params
        .member("offset")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    w.begin_object()?;
    w.field_str("path", caminho)?;

    match crate::vfs::ler_tudo(caminho) {
        Ok(conteudo) => {
            w.field_u64("size", conteudo.len() as u64)?;
            // Um `offset` além do fim devolve zero bytes, e não erro: é a
            // resposta certa para quem está lendo em partes e chegou ao fim.
            let de = de.min(conteudo.len());
            let quanto = max.min(conteudo.len() - de);
            w.field_u64("offset", de as u64)?;
            w.field_u64("returned", quanto as u64)?;
            w.key("content")?;
            w.begin_str()?;
            // Um arquivo pode não ser texto — os programas embutidos em
            // `/bin` são ELF. Dizer isso é melhor que despejar bytes que o
            // JSON não sabe carregar, e melhor que recusar a leitura: quem
            // perguntou fica sabendo o tamanho e que o conteúdo é binário.
            match core::str::from_utf8(&conteudo[de..de + quanto]) {
                Ok(texto) => w.push_str(texto)?,
                Err(_) => w.push_str("<bytes que nao sao utf-8>")?,
            }
            w.end_str()?;
        }
        Err(motivo) => w.field_str("error", motivo.motivo())?,
    }

    w.end_object()
}

/// Lista um diretório.
///
/// # Por que o erro vem no corpo, e não como erro de protocolo
///
/// Porque um caminho que não existe é uma resposta legítima a uma pergunta
/// bem formada, e não uma requisição inválida. Um agente explorando a árvore
/// vai bater em caminhos que não existem o tempo todo; transformar isso em
/// `-32602` faria ele ter de distinguir "perguntei errado" de "não tem".
fn fs_list(params: Json, w: &mut JsonWriter) -> fmt::Result {
    let caminho = params
        .member("path")
        .and_then(|v| v.as_str())
        .unwrap_or(crate::vfs::DIRETORIO_DOS_PROGRAMAS);

    w.begin_object()?;
    w.field_str("path", caminho)?;

    let mut escrita = Ok(());
    let mut aberto = false;
    let resultado = crate::vfs::listar(caminho, |entrada| {
        if escrita.is_err() {
            return;
        }
        escrita = (|| {
            if !aberto {
                w.key("entries")?;
                w.begin_array()?;
                aberto = true;
            }
            w.begin_object()?;
            w.field_str("name", &entrada.nome)?;
            w.field_str(
                "type",
                match entrada.tipo {
                    crate::vfs::Tipo::Arquivo => "file",
                    crate::vfs::Tipo::Diretorio => "dir",
                },
            )?;
            w.end_object()
        })();
    });
    escrita?;

    match resultado {
        Ok(()) => {
            if !aberto {
                w.key("entries")?;
                w.begin_array()?;
            }
            w.end_array()?;
        }
        Err(motivo) => {
            // O array não é aberto quando a listagem falha: uma lista vazia
            // e uma listagem que não aconteceu são coisas diferentes, e
            // devolver `[]` nas duas apagaria a diferença.
            w.field_str("error", motivo.motivo())?;
        }
    }

    w.end_object()
}

// ---------------------------------------------------------------------------
// O armazém: ver crate::armazem e docs/ARMAZENAMENTO.md. O gate já decidiu
// `fs.write` (ou `fs.read`) e o alcance do caminho; os handlers não decidem
// de novo — dizem o arrendamento, a versão, a persistência e o resultado.
// ---------------------------------------------------------------------------

/// Escreve a recusa de uma mutação do armazém: o código, qual conflito e o
/// que o explica — a versão de agora, ou quem tem o arrendamento.
fn recusa_do_armazem(w: &mut JsonWriter, caminho: &str, f: crate::armazem::Falha) -> fmt::Result {
    use crate::armazem::Falha;
    w.field_bool("ok", false)?;
    w.field_str("code", f.codigo().nome())?;
    if let Some(c) = f.conflito() {
        w.field_str("conflict", c)?;
    }
    match f {
        Falha::Versao { atual } => w.field_u64("current_version", atual)?,
        Falha::Arrendamento(_) => {
            if let Some((_, s)) = crate::armazem::situacao(caminho)
                && let Some(a) = s.arrendamento
            {
                w.key("lease")?;
                escrever_arrendamento(w, &a)?;
            }
        }
        _ => {}
    }
    w.field_str("error", f.motivo())?;
    w.end_object()
}

/// O texto de um parâmetro, desescapado num buffer de quem chama — que o
/// zera depois: o conteúdo de um arquivo não fica no heap. O desescapado
/// nunca é maior que o escrito.
fn buffer_do_texto(valor: Option<Json>) -> alloc::vec::Vec<u8> {
    alloc::vec![0u8; valor.map_or(0, |b| b.0.len())]
}

/// Escreve a resposta de um lote feito: cada operação com o caminho, a
/// versão e o tamanho do destino.
fn feito(w: &mut JsonWriter, caminhos: &[&str], feitas: &[crate::armazem::Feita]) -> fmt::Result {
    w.field_bool("ok", true)?;
    if let ([caminho], [f]) = (caminhos, feitas) {
        w.field_str("path", caminho)?;
        w.field_u64("version", f.versao)?;
        w.field_u64("size", f.tamanho)?;
    } else {
        w.key("results")?;
        w.begin_array()?;
        for (c, f) in caminhos.iter().zip(feitas) {
            w.begin_object()?;
            w.field_str("path", c)?;
            w.field_u64("version", f.versao)?;
            w.field_u64("size", f.tamanho)?;
            w.end_object()?;
        }
        w.end_array()?;
    }
    // Só há sucesso confirmado: o armazém não muda só em memória.
    w.field_bool("durable", true)?;
    w.end_object()
}

/// Faz um lote e escreve a resposta. `caminhos` é o destino de cada
/// operação, para a resposta e para a recusa.
fn mutar(w: &mut JsonWriter, pedidos: &[crate::armazem::Pedido], caminhos: &[&str]) -> fmt::Result {
    match crate::armazem::mudar(pedidos) {
        Ok(feitas) => feito(w, caminhos, &feitas),
        Err((i, f)) => {
            if pedidos.len() > 1 {
                w.field_u64("op", i as u64)?;
            }
            recusa_do_armazem(w, caminhos.get(i).copied().unwrap_or(""), f)
        }
    }
}

/// Uma recusa de um pedido que não chegou ao armazém: o conteúdo que não se
/// entende, um lote malformado — gravada como o resultado do comando.
fn invalido(w: &mut JsonWriter, caminho: &str, motivo: &'static str) -> fmt::Result {
    let f = crate::armazem::Falha::Caminho(motivo);
    crate::autorizacao::auditar_execucao(caminho, f.codigo(), f.motivo());
    recusa_do_armazem(w, caminho, f)
}

/// A versão esperada do pedido. Ausente, nenhuma versão confere — mas o
/// registro já recusou: o parâmetro é obrigatório.
fn versao_esperada(valor: Option<Json>) -> u64 {
    valor.and_then(|v| v.as_u64()).unwrap_or(u64::MAX)
}

/// O conteúdo de uma gravação: `content` (texto, desescapado em `buffer`),
/// `draft` (um rascunho), ou o anexo — exatamente um. `Err` com o motivo.
fn fonte<'b>(
    texto: Option<Json<'b>>,
    rascunho: Option<Json>,
    buffer: &'b mut alloc::vec::Vec<u8>,
    anexo: &'b [u8],
) -> Result<crate::armazem::Fonte<'b>, &'static str> {
    use crate::armazem::Fonte;
    let quantos = usize::from(texto.is_some())
        + usize::from(rascunho.is_some())
        + usize::from(!anexo.is_empty());
    if quantos != 1 {
        return Err("o conteudo vem de exatamente um: content, draft ou o anexo");
    }
    if let Some(t) = texto {
        *buffer = buffer_do_texto(Some(t));
        return t
            .desescapar_em(buffer)
            .map(|c| Fonte::Bytes(c.as_bytes()))
            .ok_or("o conteudo nao e texto");
    }
    if let Some(r) = rascunho {
        return r
            .as_u64()
            .map(Fonte::Rascunho)
            .ok_or("o rascunho nao e um numero");
    }
    Ok(Fonte::Bytes(anexo))
}

fn fs_write(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let caminho = params.member("path").and_then(|v| v.as_str()).unwrap_or("");
    let esperada = versao_esperada(params.member("expect_version"));
    let mut anexo = crate::autorizacao::tirar_anexo();
    let mut buffer = alloc::vec::Vec::new();
    let fonte = anexo_declarado(params.member("attachment"), &anexo).and_then(|()| {
        fonte(
            params.member("content"),
            params.member("draft"),
            &mut buffer,
            &anexo,
        )
    });
    let r = match fonte {
        Ok(fonte) => mutar(
            w,
            &[crate::armazem::Pedido::Gravar {
                caminho,
                esperada,
                fonte,
            }],
            &[caminho],
        ),
        Err(m) => invalido(w, caminho, m),
    };
    politica::sigiloso::zerar_bloco(&mut buffer);
    politica::sigiloso::zerar_bloco(&mut anexo);
    r
}

fn fs_append(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let caminho = params.member("path").and_then(|v| v.as_str()).unwrap_or("");
    let esperada = versao_esperada(params.member("expect_version"));
    let mut anexo = crate::autorizacao::tirar_anexo();
    let mut buffer = alloc::vec::Vec::new();
    let fonte = anexo_declarado(params.member("attachment"), &anexo)
        .and_then(|()| fonte(params.member("content"), None, &mut buffer, &anexo));
    let r = match fonte {
        Ok(crate::armazem::Fonte::Bytes(mais)) => mutar(
            w,
            &[crate::armazem::Pedido::Acrescentar {
                caminho,
                esperada,
                mais,
            }],
            &[caminho],
        ),
        Ok(_) => invalido(w, caminho, "um acrescimo nao vem de um rascunho"),
        Err(m) => invalido(w, caminho, m),
    };
    politica::sigiloso::zerar_bloco(&mut buffer);
    politica::sigiloso::zerar_bloco(&mut anexo);
    r
}

fn fs_delete(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let caminho = params.member("path").and_then(|v| v.as_str()).unwrap_or("");
    let esperada = versao_esperada(params.member("expect_version"));
    mutar(
        w,
        &[crate::armazem::Pedido::Apagar { caminho, esperada }],
        &[caminho],
    )
}

fn fs_mkdir(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let caminho = params.member("path").and_then(|v| v.as_str()).unwrap_or("");
    mutar(
        w,
        &[crate::armazem::Pedido::CriarDiretorio { caminho }],
        &[caminho],
    )
}

fn fs_rmdir(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let caminho = params.member("path").and_then(|v| v.as_str()).unwrap_or("");
    let esperada = versao_esperada(params.member("expect_version"));
    mutar(
        w,
        &[crate::armazem::Pedido::RemoverDiretorio { caminho, esperada }],
        &[caminho],
    )
}

fn fs_rename(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let de = params.member("path").and_then(|v| v.as_str()).unwrap_or("");
    let para = params.member("to").and_then(|v| v.as_str()).unwrap_or("");
    let esperada = versao_esperada(params.member("expect_version"));
    mutar(
        w,
        &[crate::armazem::Pedido::Renomear { de, para, esperada }],
        &[para],
    )
}

/// O conteúdo de uma operação de um lote: o texto (desescapado em
/// `buffer`), o rascunho, ou um pedaço do anexo.
fn fonte_do_item<'a>(
    o: &Json,
    buffer: &'a mut [u8],
    anexo: &'a [u8],
) -> Result<crate::armazem::Fonte<'a>, &'static str> {
    use crate::armazem::Fonte;
    if let Some(t) = o.member("content") {
        return t
            .desescapar_em(buffer)
            .map(|c| Fonte::Bytes(c.as_bytes()))
            .ok_or("o conteudo nao e texto");
    }
    if let Some(r) = o.member("draft") {
        return r
            .as_u64()
            .map(Fonte::Rascunho)
            .ok_or("o rascunho nao e numero");
    }
    let de = o.member("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let n = o.member("length").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    de.checked_add(n)
        .and_then(|ate| anexo.get(de..ate))
        .map(Fonte::Bytes)
        .ok_or("o pedaco do anexo nao esta no anexo")
}

/// `fs.batch`: as operações de `ops`, num lote só. O conteúdo de cada
/// gravação vem de `content`, de `draft`, ou de `offset`/`length` no anexo
/// do pedido.
fn fs_batch(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let mut anexo = crate::autorizacao::tirar_anexo();
    let lista: alloc::vec::Vec<Json> = params
        .member("ops")
        .map(|l| {
            (0..=crate::autorizacao::MAIS_OPS_POR_LOTE)
                .map_while(|i| l.item(i))
                .collect()
        })
        .unwrap_or_default();
    let primeiro = lista.first().map_or("", caminho_do_item);
    let declarado = anexo_declarado(params.member("attachment"), &anexo);
    if lista.is_empty() || lista.len() > crate::autorizacao::MAIS_OPS_POR_LOTE {
        politica::sigiloso::zerar_bloco(&mut anexo);
        return invalido(w, primeiro, "um lote tem de 1 a 32 operacoes");
    }
    if let Err(m) = declarado {
        politica::sigiloso::zerar_bloco(&mut anexo);
        return invalido(w, primeiro, m);
    }
    // Os textos desescapados, cada um no seu buffer — zerados no fim.
    let mut buffers: alloc::vec::Vec<alloc::vec::Vec<u8>> =
        lista.iter().map(buffer_do_item).collect();
    let mut caminhos: alloc::vec::Vec<&str> = alloc::vec::Vec::with_capacity(lista.len());
    let mut pedidos: alloc::vec::Vec<crate::armazem::Pedido> =
        alloc::vec::Vec::with_capacity(lista.len());
    let mut motivo: Option<&'static str> = None;
    for (o, buffer) in lista.iter().zip(buffers.iter_mut()) {
        match pedido_do_item(o, buffer, &anexo) {
            Ok((p, destino)) => {
                caminhos.push(destino);
                pedidos.push(p);
            }
            Err(m) => {
                motivo = Some(m);
                break;
            }
        }
    }
    let r = match motivo {
        Some(m) => {
            w.field_u64("op", pedidos.len() as u64)?;
            invalido(w, primeiro, m)
        }
        None => mutar(w, &pedidos, &caminhos),
    };
    drop(pedidos);
    for b in &mut buffers {
        politica::sigiloso::zerar_bloco(b);
    }
    politica::sigiloso::zerar_bloco(&mut anexo);
    r
}

/// O caminho de uma operação de um lote — os campos de cada operação são
/// dela, e não do pedido: o lote declara só `ops` e `attachment`.
fn caminho_do_item<'a>(o: &Json<'a>) -> &'a str {
    o.member("path").and_then(|v| v.as_str()).unwrap_or("")
}

/// O buffer onde o texto de uma operação de um lote é desescapado.
fn buffer_do_item(o: &Json) -> alloc::vec::Vec<u8> {
    buffer_do_texto(o.member("content"))
}

/// Uma operação de um lote, e o caminho de destino dela — o de um rename
/// é o `to`.
fn pedido_do_item<'a>(
    o: &Json<'a>,
    buffer: &'a mut [u8],
    anexo: &'a [u8],
) -> Result<(crate::armazem::Pedido<'a>, &'a str), &'static str> {
    use crate::armazem::{Fonte, Pedido};
    let caminho = caminho_do_item(o);
    let para = o.member("to").and_then(|v| v.as_str()).unwrap_or("");
    let esperada = versao_esperada(o.member("expect_version"));
    let op = o.member("op").and_then(|v| v.as_str()).unwrap_or("");
    let pedido = match op {
        "write" => Pedido::Gravar {
            caminho,
            esperada,
            fonte: fonte_do_item(o, buffer, anexo)?,
        },
        "append" => match fonte_do_item(o, buffer, anexo)? {
            Fonte::Bytes(mais) => Pedido::Acrescentar {
                caminho,
                esperada,
                mais,
            },
            Fonte::Rascunho(_) => return Err("um acrescimo nao vem de um rascunho"),
        },
        "delete" => Pedido::Apagar { caminho, esperada },
        "mkdir" => Pedido::CriarDiretorio { caminho },
        "rmdir" => Pedido::RemoverDiretorio { caminho, esperada },
        "rename" => {
            return Ok((
                Pedido::Renomear {
                    de: caminho,
                    para,
                    esperada,
                },
                para,
            ));
        }
        _ => return Err("operacao desconhecida num lote"),
    };
    Ok((pedido, caminho))
}

/// O `attachment` que o pedido declara confere com o anexo que chegou. No
/// canal do agente a sessão já conferiu antes do gate; aqui é a mesma regra
/// do lado de quem usa o anexo — e um processo, que manda o anexo pela
/// chamada de sistema, não o declara.
fn anexo_declarado(declarado: Option<Json>, anexo: &[u8]) -> Result<(), &'static str> {
    match declarado.map(|v| v.as_u64()) {
        None => Ok(()),
        Some(Some(n)) if n == anexo.len() as u64 => Ok(()),
        Some(_) => Err("o anexo nao confere com attachment"),
    }
}

/// `fs.draft`: o anexo — ou `content` — vai para um rascunho do caminho.
fn fs_draft(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let caminho = params.member("path").and_then(|v| v.as_str()).unwrap_or("");
    let numero = params.member("draft").and_then(|v| v.as_u64());
    let mut anexo = crate::autorizacao::tirar_anexo();
    let mut buffer = buffer_do_texto(params.member("content"));
    let dados: Result<&[u8], &'static str> = match params.member("content") {
        _ if anexo_declarado(params.member("attachment"), &anexo).is_err() => {
            Err("o anexo nao confere com attachment")
        }
        Some(_) if !anexo.is_empty() => Err("o conteudo vem do anexo ou de content, nao dos dois"),
        Some(t) => t
            .desescapar_em(&mut buffer)
            .map(str::as_bytes)
            .ok_or("o conteudo nao e texto"),
        None => Ok(&anexo),
    };
    let r = match dados {
        Err(m) => invalido(w, caminho, m),
        Ok(d) => match crate::armazem::rascunho(caminho, numero, d) {
            Ok((n, tamanho)) => {
                w.field_bool("ok", true)?;
                w.field_u64("draft", n)?;
                w.field_u64("size", tamanho)?;
                w.end_object()
            }
            Err(f) => recusa_do_armazem(w, caminho, f),
        },
    };
    politica::sigiloso::zerar_bloco(&mut buffer);
    politica::sigiloso::zerar_bloco(&mut anexo);
    r
}

fn fs_discard(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let caminho = params.member("path").and_then(|v| v.as_str()).unwrap_or("");
    let numero = params.member("draft").and_then(|v| v.as_u64()).unwrap_or(0);
    match crate::armazem::descartar(numero) {
        Ok(()) => {
            w.field_bool("ok", true)?;
            w.end_object()
        }
        Err(f) => recusa_do_armazem(w, caminho, f),
    }
}

fn fs_stat(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let caminho = params.member("path").and_then(|v| v.as_str()).unwrap_or("");
    let Some((normal, s)) = crate::armazem::situacao(caminho) else {
        w.field_bool("ok", false)?;
        w.field_str("code", politica::Codigo::InvalidArgument.nome())?;
        w.field_str("error", "o caminho nao e do armazem")?;
        return w.end_object();
    };
    w.field_bool("ok", true)?;
    w.field_str("path", &normal)?;
    w.field_str(
        "type",
        match s.tipo {
            Some(::armazem::Tipo::Arquivo) => "file",
            Some(::armazem::Tipo::Diretorio) => "dir",
            None => "none",
        },
    )?;
    w.field_u64("version", s.versao)?;
    w.field_u64("size", s.tamanho)?;
    if let Some(d) = &s.dono {
        w.field_str("owner", d)?;
    }
    if let Some(a) = s.arrendamento {
        w.key("lease")?;
        escrever_arrendamento(w, &a)?;
    }
    // O que é de quem pergunta: o uso e a cota dele no armazém.
    if let Some((uso, cota, rascunhos)) = crate::armazem::uso_de_quem_pede() {
        w.key("quota")?;
        w.begin_object()?;
        w.field_u64("used_bytes", uso.bytes)?;
        w.field_u64("used_objects", uso.objetos)?;
        w.field_u64("draft_bytes", rascunhos)?;
        w.field_u64("max_bytes", cota.bytes)?;
        w.field_u64("max_objects", cota.objetos)?;
        w.end_object()?;
    }
    if let Some((total, livres)) = crate::volume::ocupacao() {
        w.field_u64("volume_free_blocks", livres)?;
        w.field_u64("volume_blocks", total)?;
    }
    w.end_object()
}

fn fs_claim(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let caminho = params.member("path").and_then(|v| v.as_str()).unwrap_or("");
    let prazo = params
        .member("ttl_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(crate::coordenacao::PRAZO_PADRAO_MS);
    match crate::armazem::arrendar(caminho, prazo) {
        Ok(a) => {
            w.field_bool("ok", true)?;
            w.key("lease")?;
            escrever_arrendamento(w, &a)?;
        }
        Err((codigo, motivo)) => {
            w.field_bool("ok", false)?;
            w.field_str("code", codigo.nome())?;
            if codigo == politica::Codigo::Conflict {
                w.field_str("conflict", "lease")?;
                if let Some((_, s)) = crate::armazem::situacao(caminho)
                    && let Some(a) = s.arrendamento
                {
                    w.key("lease")?;
                    escrever_arrendamento(w, &a)?;
                }
            }
            w.field_str("error", motivo)?;
        }
    }
    w.end_object()
}

fn fs_release(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let caminho = params.member("path").and_then(|v| v.as_str()).unwrap_or("");
    match crate::armazem::soltar(caminho) {
        Ok(()) => w.field_bool("ok", true)?,
        Err((codigo, motivo)) => {
            w.field_bool("ok", false)?;
            w.field_str("code", codigo.nome())?;
            w.field_str("error", motivo)?;
        }
    }
    w.end_object()
}

/// Quantos caracteres uma leitura de teclado devolve por padrão, e no máximo.
///
/// O teto é o tamanho da fila do teclado: pedir mais do que cabe nela não
/// devolveria mais, e o número serve para quem lê saber que uma resposta
/// cheia pode ter deixado algo para trás.
const TECLAS_PADRAO: u64 = 64;
const TECLAS_MAX: u64 = 64;

/// O que foi digitado, e o suficiente para saber se falta alguma coisa.
///
/// # O que este comando lê, e o que ele não lê
///
/// Lê o **histórico**, e não a fila que o interpretador consome. As duas são
/// escritas juntas, e a distinção existe porque o teclado tem dono: quem está
/// na frente da máquina. Um comando que tirasse da fila do interpretador não
/// observaria o que foi digitado — roubaria. Ver a nota em
/// [`crate::teclado`].
///
/// Tira do histórico em vez de espiar porque um teclado é um fluxo, e espiar
/// sem consumir faria a próxima leitura devolver as mesmas teclas. O preço é
/// que a resposta é a única cópia; por isso os contadores vêm junto —
/// `dropped` diz se houve perda, o que nenhuma releitura revelaria.
fn keyboard_read(params: Json, w: &mut JsonWriter) -> fmt::Result {
    let max = params
        .member("max")
        .and_then(|v| v.as_u64())
        .unwrap_or(TECLAS_PADRAO)
        .clamp(1, TECLAS_MAX);

    w.begin_object()?;
    w.field_u64("pressed", crate::teclado::pressionadas())?;
    w.field_u64("dropped", crate::teclado::descartados())?;

    // O texto sai como string escrita aos pedaços: um caractere por vez, sem
    // um buffer intermediário. Montar a string antes exigiria um array do
    // tamanho do teto e, com ele, um truncamento que nada reportaria.
    //
    // Cada leitor tem o seu cursor no histórico — a autoridade de quem pede
    // é o leitor —: dois agentes lendo não roubam um do outro, e cada um lê
    // tudo o que foi digitado desde a última leitura dele.
    w.key("text")?;
    w.begin_str()?;
    let mut lidos = 0;
    let mut escrita = Ok(());
    let leitura =
        crate::teclado::ler_para(crate::autorizacao::autoridade_atual(), max as usize, |c| {
            if escrita.is_ok() {
                escrita = w.push_char(c);
                lidos += 1;
            }
        });
    escrita?;
    w.end_str()?;

    w.field_u64("read", lidos)?;
    // Depois da leitura, e não antes: é o que sobrou, que é a pergunta útil.
    w.field_u64("waiting", leitura.esperando)?;
    // O que saiu do anel antes de este leitor ler.
    w.field_u64("missed", leitura.perdidas)?;

    // Quantos eventos o dispositivo entregou, onde há um que os conte.
    // Separa "ninguem digitou" de "chegou e nao virou caractere" — um codigo
    // que a tabela nao conhece, uma tecla estendida — e essa distincao e a
    // primeira pergunta de quem esta depurando um teclado mudo.
    if let Some(eventos) = crate::virtio::teclado::recebidos() {
        w.field_u64("device_events", eventos)?;
    }
    w.field_u64("usb_reports", crate::usb::hid::relatorios())?;

    w.end_object()
}

/// A pilha gráfica, como o agente a enxerga.
///
/// # Por que o último dano, e não uma captura
///
/// Porque é a pergunta que um agente faz de verdade depois de mandar
/// desenhar: "o que mudou?". Responder com uma captura da tela inteira obriga
/// quem pergunta a comparar dois quadros para achar a diferença — que é
/// exatamente o que o compositor já sabe e está jogando fora. Aqui ele diz.
///
/// `video.sample` continua existindo para quando a pergunta é outra: "o que
/// está na tela?".
fn display_info(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let Some(r) = crate::grafico::relatorio() else {
        // Sem pilha gráfica não é erro: a máquina pode não ter tela.
        w.field_bool("present", false)?;
        return w.end_object();
    };

    w.field_bool("present", true)?;
    w.field_str("adapter", r.adaptador)?;

    w.key("displays")?;
    w.begin_array()?;
    for tela in 0..r.telas {
        w.begin_object()?;
        w.field_u64("id", tela as u64)?;
        if tela == 0
            && let Some((largura, altura)) = r.tamanho
        {
            w.field_u64("width", largura as u64)?;
            w.field_u64("height", altura as u64)?;
        }
        w.end_object()?;
    }
    w.end_array()?;

    // As camadas do compositor, de baixo para cima: o console primeiro. A
    // posição é a da camada, que pode passar da tela.
    w.key("layers")?;
    w.begin_array()?;
    let mut resultado = Ok(());
    crate::grafico::camadas(|c| {
        if resultado.is_ok() {
            resultado = (|| {
                w.begin_object()?;
                w.field_u64("id", c.id as u64)?;
                w.field_str("name", c.nome)?;
                w.field_i64("x", c.x as i64)?;
                w.field_i64("y", c.y as i64)?;
                w.field_u64("width", c.largura as u64)?;
                w.field_u64("height", c.altura as u64)?;
                w.field_str("blend", c.mistura.nome())?;
                w.field_u64("opacity", c.opacidade as u64)?;
                w.end_object()
            })();
        }
    });
    resultado?;
    w.end_array()?;

    // O ponteiro: onde está, e quanto já se mexeu e clicou. Zero e zero numa
    // máquina sem mouse, ou num que ninguém tocou.
    let (x, y) = crate::ponteiro::posicao();
    let (cliques, movimentos) = crate::ponteiro::contadores();
    w.key("pointer")?;
    w.begin_object()?;
    w.field_u64("x", x as u64)?;
    w.field_u64("y", y as u64)?;
    w.field_u64("clicks", cliques)?;
    w.field_u64("moves", movimentos)?;
    // Quantos relatórios o mouse USB entregou: numa máquina com o PS/2 e o
    // USB, é o que diz por qual dos dois o ponteiro andou.
    w.field_u64("usb_reports", crate::usb::hid::relatorios_do_mouse())?;
    // Quantos eventos foram para o servidor de janelas, em vez de virar
    // clique do kernel: é o que diz que o ponteiro chegou às janelas.
    w.field_u64("to_windows", crate::ponteiro::para_as_janelas_contados())?;
    w.end_object()?;

    w.field_u64("surfaces", r.superficies)?;
    w.field_u64("surface_bytes", r.bytes_em_superficies)?;

    // As superfícies de processos: quantas estão vivas, quantas já foram
    // criadas e quantas o coletor tirou da tela porque o dono morreu. A
    // terceira é a que diz se um processo está morrendo com janelas abertas.
    let (vivas, criadas, recolhidas) = crate::superficies::estatisticas();
    w.key("process_surfaces")?;
    w.begin_object()?;
    w.field_u64("live", vivas)?;
    w.field_u64("created", criadas)?;
    w.field_u64("reclaimed", recolhidas)?;
    w.end_object()?;

    // Os pseudo-terminais: quem tem cada um aberto, quantos avisos de saída
    // foram entregues, quantas teclas eles digitaram, e quantos bytes da
    // saída saíram de um anel sem ninguém lê-los. O último é o que diz se um
    // Terminal está perdendo o que o console dele imprime.
    let (perdidos, avisos, digitados) = crate::pseudoterminal::estatisticas();
    w.key("terminal")?;
    w.begin_object()?;
    w.key("owners")?;
    w.begin_array()?;
    for dono in crate::pseudoterminal::donos() {
        match dono {
            Some(fio) => w.u64_value(fio)?,
            None => w.null_value()?,
        }
    }
    w.end_array()?;
    w.field_u64("notices", avisos)?;
    w.field_u64("typed", digitados)?;
    w.field_u64("dropped", perdidos)?;
    w.end_object()?;
    w.field_u64("updates", r.atualizacoes)?;

    w.key("last_damage")?;
    match r.ultimo_dano {
        Some(d) => {
            w.begin_object()?;
            w.field_u64("x", d.x as u64)?;
            w.field_u64("y", d.y as u64)?;
            w.field_u64("width", d.largura as u64)?;
            w.field_u64("height", d.altura as u64)?;
            w.end_object()?;
        }
        None => w.null_value()?,
    }

    // Num adaptador que só mostra o que se manda, a diferença entre "o
    // kernel desenhou" e "o monitor mostra" é o que foi mandado. Os três
    // números dizem se está sendo: comandos, descargas e recusas. Nulo num
    // framebuffer linear, onde a pergunta não existe.
    w.key("device")?;
    match r.dispositivo {
        Some((comandos, descargas, recusas)) => {
            w.begin_object()?;
            w.field_u64("commands", comandos)?;
            w.field_u64("flushes", descargas)?;
            w.field_u64("rejected", recusas)?;
            // O último retângulo que atravessou para o dispositivo. Ao lado
            // de `last_damage`, que é o que a pilha pediu, é o que de fato
            // foi — e numa tela de console, o que o console acabou de sujar.
            let t = crate::virtio::gpu::ultima_transferencia();
            w.key("last_transfer")?;
            w.begin_object()?;
            w.field_u64("x", t.x as u64)?;
            w.field_u64("y", t.y as u64)?;
            w.field_u64("width", t.largura as u64)?;
            w.field_u64("height", t.altura as u64)?;
            w.end_object()?;
            w.end_object()?;
        }
        None => w.null_value()?,
    }

    w.end_object()
}

// ---------------------------------------------------------------------------
// ui.*
// ---------------------------------------------------------------------------

/// Escreve a moldura de um elemento.
fn escrever_moldura(w: &mut JsonWriter, m: crate::ui::Moldura) -> fmt::Result {
    w.key("frame")?;
    w.begin_object()?;
    w.field_u64("x", m.x as u64)?;
    w.field_u64("y", m.y as u64)?;
    w.field_u64("width", m.largura as u64)?;
    w.field_u64("height", m.altura as u64)?;
    w.end_object()
}

/// Escreve a lista de ações que um elemento aceita.
fn escrever_acoes(w: &mut JsonWriter, id: u32) -> fmt::Result {
    w.key("actions")?;
    w.begin_array()?;
    for acao in crate::ui::acoes_de(id) {
        w.str_value(acao.nome())?;
    }
    w.end_array()
}

/// O texto do console, linha por linha, como está na tela.
///
/// As células vazias no meio de uma linha viram espaço; as do fim da linha e
/// as linhas vazias do fim da tela somem. É o texto que uma pessoa leria, e
/// não uma grade com lacunas.
fn escrever_texto_do_console(
    w: &mut JsonWriter,
    g: &crate::tela::console::Geometria,
) -> fmt::Result {
    use crate::tela::console::caractere;

    let ultima_linha = (0..g.linhas)
        .rev()
        .find(|&l| (0..g.colunas).any(|c| caractere(c, l).is_some()));
    w.begin_str()?;
    if let Some(ultima_linha) = ultima_linha {
        for linha in 0..=ultima_linha {
            if linha > 0 {
                w.push_char('\n')?;
            }
            let fim = (0..g.colunas)
                .rev()
                .find(|&c| caractere(c, linha).is_some())
                .map_or(0, |c| c + 1);
            for coluna in 0..fim {
                w.push_char(caractere(coluna, linha).unwrap_or(' '))?;
            }
        }
    }
    w.end_str()
}

/// A árvore semântica.
///
/// # Por que ela, e não `video.sample`
///
/// Porque a amostra responde "que cores estão onde", e o agente quase nunca
/// quer saber isso. Ele quer saber o que está escrito, o que é editável e o
/// que dá para fazer — e a amostra obriga a adivinhar as três coisas a
/// partir de pixels. A árvore as diz. A amostra continua existindo para a
/// pergunta que só os pixels respondem: se o desenho saiu.
///
/// Sem tela, `root` é nulo, e não um erro: a máquina pode legitimamente não
/// ter uma.
fn ui_tree(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    use crate::ui;

    w.begin_object()?;
    w.field_u64("revision", ui::revisao())?;
    w.key("root")?;
    let (Some(tela), Some(g)) = (ui::moldura_da_tela(), crate::tela::console::geometria()) else {
        w.null_value()?;
        return w.end_object();
    };

    w.begin_object()?;
    w.field_u64("id", ui::ID_DA_TELA as u64)?;
    w.field_str("role", ui::Papel::Tela.nome())?;
    w.field_str("label", "tela")?;
    escrever_moldura(w, tela)?;
    escrever_acoes(w, ui::ID_DA_TELA)?;
    w.key("children")?;
    w.begin_array()?;

    // O console.
    w.begin_object()?;
    w.field_u64("id", ui::ID_DO_CONSOLE as u64)?;
    w.field_str("role", ui::Papel::AreaDeTexto.nome())?;
    w.field_str("label", "console")?;
    if let Some(m) = ui::moldura_do_console() {
        escrever_moldura(w, m)?;
    }
    w.key("value")?;
    escrever_texto_do_console(w, &g)?;
    // Numa tela maior que a grade, o texto guardado é parte do desenhado. O
    // campo existe para que um texto cortado não se passe por inteiro.
    w.field_bool("value_complete", crate::tela::console::texto_completo())?;
    escrever_acoes(w, ui::ID_DO_CONSOLE)?;
    w.key("children")?;
    w.begin_array()?;

    // A linha de comando, se o interpretador estiver atendendo.
    if ui::existe(ui::ID_DA_LINHA_DE_COMANDO) {
        w.begin_object()?;
        w.field_u64("id", ui::ID_DA_LINHA_DE_COMANDO as u64)?;
        w.field_str("role", ui::Papel::CampoDeTexto.nome())?;
        w.field_str("label", "linha de comando")?;
        if let Some(m) = ui::moldura_da_linha_de_comando() {
            escrever_moldura(w, m)?;
        }
        w.key("value")?;
        crate::interpretador::com_valor(|v| w.str_value(v))?;
        escrever_coordenacao(w, ui::ID_DA_LINHA_DE_COMANDO)?;
        // É o único elemento que recebe texto, e é para ele que o teclado vai.
        w.field_bool("focused", true)?;
        escrever_acoes(w, ui::ID_DA_LINHA_DE_COMANDO)?;
        w.key("children")?;
        w.begin_array()?;
        w.end_array()?;
        w.end_object()?;
    }

    w.end_array()?;
    w.end_object()?;

    // A barra superior, com o que há nela.
    if let Some(m) = crate::barra::moldura() {
        escrever_barra(w, m)?;
    }

    // As camadas acima do console, na ordem em que estão empilhadas: a
    // última é a que está por cima. A moldura é a parte que cai na tela. A
    // da barra fica de fora — ela já está acima, com o papel dela —, e as
    // invisíveis também: ver `ui::e_janela`.
    let mut resultado = Ok(());
    crate::grafico::camadas(|c| {
        if !ui::e_janela(&c) || resultado.is_err() {
            return;
        }
        resultado = escrever_camada(w, c);
    });
    resultado?;

    w.end_array()?;
    w.end_object()?;
    w.end_object()
}

/// A barra superior e o que há nela: o nome, o botão e o relógio.
fn escrever_barra(w: &mut JsonWriter, moldura: crate::ui::Moldura) -> fmt::Result {
    use crate::ui;

    // Um elemento sem filhos, com rótulo, moldura e, se houver, valor.
    let folha = |w: &mut JsonWriter,
                 id: u32,
                 papel: ui::Papel,
                 rotulo: &str,
                 moldura: Option<ui::Moldura>,
                 valor: Option<&str>|
     -> fmt::Result {
        w.begin_object()?;
        w.field_u64("id", id as u64)?;
        w.field_str("role", papel.nome())?;
        w.field_str("label", rotulo)?;
        if let Some(m) = moldura {
            escrever_moldura(w, m)?;
        }
        if let Some(v) = valor {
            w.field_str("value", v)?;
        }
        escrever_acoes(w, id)?;
        w.key("children")?;
        w.begin_array()?;
        w.end_array()?;
        w.end_object()
    };

    w.begin_object()?;
    w.field_u64("id", ui::ID_DA_BARRA as u64)?;
    w.field_str("role", ui::Papel::BarraSuperior.nome())?;
    w.field_str("label", "barra superior")?;
    escrever_moldura(w, moldura)?;
    escrever_acoes(w, ui::ID_DA_BARRA)?;
    w.key("children")?;
    w.begin_array()?;
    folha(
        w,
        ui::ID_DO_NOME,
        ui::Papel::Texto,
        "nome",
        crate::barra::moldura_do_nome(),
        Some(crate::barra::NOME),
    )?;
    folha(
        w,
        ui::ID_DO_BOTAO_LIMPAR,
        ui::Papel::Botao,
        crate::barra::ROTULO_DO_BOTAO,
        crate::barra::moldura_do_botao(),
        None,
    )?;
    folha(
        w,
        ui::ID_DO_BOTAO_SOBRE,
        ui::Papel::Botao,
        crate::barra::ROTULO_DO_SOBRE,
        crate::barra::moldura_do_sobre(),
        None,
    )?;
    folha(
        w,
        ui::ID_DO_BOTAO_TERMINAL,
        ui::Papel::Botao,
        crate::barra::ROTULO_DO_TERMINAL,
        crate::barra::moldura_do_terminal(),
        None,
    )?;
    if let Some((m, texto)) = crate::barra::indicador_na_tela() {
        folha(
            w,
            ui::ID_DO_INDICADOR,
            ui::Papel::Texto,
            "agentes",
            Some(m),
            Some(&texto),
        )?;
    }
    if let Some((m, texto)) = crate::barra::relogio_na_tela() {
        folha(
            w,
            ui::ID_DO_RELOGIO,
            ui::Papel::Texto,
            "tempo ligado",
            Some(m),
            Some(&texto),
        )?;
    }
    w.end_array()?;
    w.end_object()
}

/// Uma camada do compositor, como elemento da árvore.
fn escrever_camada(w: &mut JsonWriter, c: crate::grafico::compositor::InfoCamada) -> fmt::Result {
    use crate::ui;

    let id = ui::id_da_camada(c.id);
    // A descrição que o processo dono deu, se é uma janela de processo e
    // ele a descreveu. Copiada para fora da tranca das superfícies: a
    // escrita da resposta não é coisa para se fazer com ela na mão.
    let descricao = crate::superficies::com_descricao(c.id, Clone::clone);
    w.begin_object()?;
    w.field_u64("id", id as u64)?;
    w.field_str("role", ui::Papel::Janela.nome())?;
    w.field_str(
        "label",
        descricao.as_ref().map_or(c.nome, |d| d.titulo.as_str()),
    )?;
    let tela = ui::moldura_da_tela();
    // Um retângulo da camada, levado à tela e recortado a ela.
    let na_tela = |x: u32, y: u32, largura: u32, altura: u32| {
        let tela = tela?;
        let d = crate::grafico::compositor::InfoCamada {
            x: c.x.saturating_add_unsigned(x),
            y: c.y.saturating_add_unsigned(y),
            largura,
            altura,
            ..c
        }
        .na_tela(tela.largura, tela.altura);
        Some(ui::Moldura {
            x: d.x,
            y: d.y,
            largura: d.largura,
            altura: d.altura,
        })
    };
    if let Some(m) = na_tela(0, 0, c.largura, c.altura) {
        escrever_moldura(w, m)?;
    }
    escrever_acoes(w, id)?;
    w.key("children")?;
    w.begin_array()?;
    for (i, e) in descricao
        .iter()
        .flat_map(|d| d.elementos.iter().enumerate())
    {
        let Some(id) = ui::id_do_elemento(c.id, i) else {
            continue;
        };
        w.begin_object()?;
        w.field_u64("id", id as u64)?;
        let papel = match e.tipo {
            crate::superficies::Tipo::Botao => ui::Papel::Botao,
            crate::superficies::Tipo::Texto => ui::Papel::Texto,
            crate::superficies::Tipo::Campo => ui::Papel::CampoDeTexto,
            crate::superficies::Tipo::Area => ui::Papel::AreaDeTexto,
        };
        w.field_str("role", papel.nome())?;
        w.field_str("label", &e.rotulo)?;
        if let Some(m) = na_tela(
            e.moldura.x,
            e.moldura.y,
            e.moldura.largura,
            e.moldura.altura,
        ) {
            escrever_moldura(w, m)?;
        }
        if let Some(v) = &e.valor {
            w.field_str("value", v)?;
        }
        if e.tipo == crate::superficies::Tipo::Campo {
            escrever_coordenacao(w, id)?;
        }
        escrever_acoes(w, id)?;
        w.key("children")?;
        w.begin_array()?;
        w.end_array()?;
        w.end_object()?;
    }
    w.end_array()?;
    w.end_object()
}

/// Age sobre um elemento da árvore.
///
/// # Por que o erro vem no corpo
///
/// Pela mesma razão de `fs.list`: um elemento que não existe mais, ou uma
/// ação que ele não aceita, é uma resposta legítima a um pedido bem formado —
/// a árvore que o agente leu pode ter mudado desde então. `-32602` fica para
/// o pedido que o registro recusa.
/// De onde vem uma ação pedida por `ui.act`, para o log e para o programa
/// que a recebe: o agente do canal que pediu, ou a pessoa que pediu no
/// interpretador. `None` para quem não é nenhum dos dois — a autoridade
/// local —: a origem de uma ação é um agente ou uma pessoa, e uma origem
/// inventada viraria, no Terminal, o Enter de alguém.
///
/// Um processo não tem origem: a origem diz ao programa dono do campo **quem**
/// agiu — o Terminal confirma a linha de uma pessoa ou de um agente pela
/// origem —, e um processo que agisse com a origem de quem o lançou
/// confirmaria em nome dele uma linha que ele não viu. Até haver uma origem
/// de programa, com o dono do campo sabendo o que fazer com ela, a ação na
/// interface não é da interface nativa. Ver `docs/INTERFACE.md`.
fn origem_do_comando() -> Option<crate::ui::Origem> {
    use crate::autorizacao::Pedinte;
    match crate::autorizacao::pedinte()? {
        Pedinte::Canal(s) => Some(crate::ui::Origem::Agente(s)),
        Pedinte::Pessoa => Some(crate::ui::Origem::Pessoa),
        Pedinte::Processo(_) | Pedinte::Kernel => None,
    }
}

fn ui_act(params: Json, w: &mut JsonWriter) -> fmt::Result {
    let id = params.member("id").and_then(|v| v.as_u64()).unwrap_or(0);
    let nome = params
        .member("action")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    w.begin_object()?;
    w.field_u64("id", id)?;
    w.field_str("action", nome)?;

    let Some(acao) = crate::ui::Acao::de_nome(nome) else {
        w.field_bool("ok", false)?;
        w.field_str(
            "error",
            "acao desconhecida; as que existem: press, confirm, cancel, set_value",
        )?;
        return w.end_object();
    };

    // O valor chega como string JSON, e uma linha de comando carrega JSON
    // nos parâmetros: as aspas vêm escapadas e precisam ser resolvidas. Do
    // tamanho do maior valor de um campo de janela: o da linha de comando é
    // menor, e ela confere o dela.
    let mut buffer = [0u8; protocolo::usuario::descricao::MAIOR_TEXTO];
    let valor = match params.member("value") {
        None => None,
        Some(v) => match v.desescapar_em(&mut buffer) {
            Some(texto) => Some(texto),
            None => {
                w.field_bool("ok", false)?;
                w.field_str(
                    "error",
                    "o valor e grande demais, ou tem um escape invalido",
                )?;
                return w.end_object();
            }
        },
    };

    let id = u32::try_from(id).unwrap_or(0);
    let esperada = params.member("expect_version").and_then(|v| v.as_u64());
    let Some(origem) = origem_do_comando() else {
        w.field_bool("ok", false)?;
        w.field_str(
            "error",
            "a acao na interface e de um agente ou de uma pessoa, e quem pediu nao e nenhum dos dois",
        )?;
        return w.end_object();
    };
    match crate::ui::agir_com_versao(
        id,
        acao,
        valor,
        origem,
        crate::coordenacao::titular_da_autoridade(crate::autorizacao::autoridade_atual()),
        esperada,
    ) {
        Ok(efeito) => {
            w.field_bool("ok", true)?;
            if let crate::ui::Efeito::Executado(comando) = efeito {
                w.field_str("executed", &comando)?;
            }
        }
        Err(recusa) => {
            w.field_bool("ok", false)?;
            if let Some(codigo) = recusa.codigo {
                w.field_str("code", codigo.nome())?;
            }
            w.field_str("error", recusa.motivo)?;
        }
    }
    // A versão do campo depois da ação: a que o próximo `expect_version`
    // diz.
    if crate::ui::e_campo(id) {
        w.field_u64(
            "version",
            crate::coordenacao::estado(&crate::coordenacao::recurso(id)).versao,
        )?;
    }
    // Depois da ação: é a revisão da árvore que o agente precisa ler de novo.
    w.field_u64("revision", crate::ui::revisao())?;
    w.end_object()
}

fn video_sample(params: Json, w: &mut JsonWriter) -> fmt::Result {
    // A amostra é do que o monitor mostra: o que outro núcleo compôs e o
    // primeiro ainda não levou à tela vai antes — ver
    // `grafico::apresentar_pendente`.
    crate::grafico::apresentar_pendente();
    let colunas = params
        .member("columns")
        .and_then(|v| v.as_u64())
        .unwrap_or(COLUNAS_PADRAO)
        .clamp(1, MAX_GRADE) as u32;
    let linhas = params
        .member("rows")
        .and_then(|v| v.as_u64())
        .unwrap_or(LINHAS_PADRAO)
        .clamp(1, MAX_GRADE) as u32;

    w.begin_object()?;

    // A tela física: o que o monitor mostra, depois do compositor. É contra
    // ela que a fumaça compara a fotografia do hospedeiro.
    let Some(tela) = crate::tela::tela_fisica() else {
        w.field_bool("present", false)?;
        return w.end_object();
    };

    w.field_bool("present", true)?;
    w.field_u64("width", tela.largura as u64)?;
    w.field_u64("height", tela.altura as u64)?;
    w.field_u64("columns", colunas as u64)?;
    w.field_u64("rows", linhas as u64)?;

    w.key("grid")?;
    w.begin_array()?;
    for linha in 0..linhas {
        // O centro de cada celula, e nao o canto: um ponto no canto de uma
        // grade grosseira cai exatamente na borda entre duas regioes, e
        // reportaria ora uma ora outra conforme o arredondamento.
        let y = (linha * 2 + 1) * tela.altura / (linhas * 2);

        w.begin_str()?;
        for coluna in 0..colunas {
            let x = (coluna * 2 + 1) * tela.largura / (colunas * 2);
            if coluna > 0 {
                w.push_char(' ')?;
            }
            match tela.ler_pixel(x, y) {
                Some(cor) => {
                    escrever_byte_hex(w, cor.r)?;
                    escrever_byte_hex(w, cor.g)?;
                    escrever_byte_hex(w, cor.b)?;
                }
                None => w.push_str("......")?,
            }
        }
        w.end_str()?;
    }
    w.end_array()?;

    w.end_object()
}

// ---------------------------------------------------------------------------
// irq.*
// ---------------------------------------------------------------------------

fn pci_list(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.field_str("mechanism", crate::arch::pci::MECANISMO)?;
    w.field_u64("count", crate::pci::total() as u64)?;

    // O teto do inventário vai na resposta porque `count` pode ser maior que o
    // que a lista traz: um agente precisa distinguir "só há isto" de "isto é o
    // que coube".
    w.field_u64("capacity", crate::pci::MAX_DISPOSITIVOS as u64)?;

    w.key("devices")?;
    w.begin_array()?;
    let mut erro = Ok(());
    crate::pci::com_dispositivos(|d| {
        if erro.is_err() {
            return;
        }
        erro = (|| {
            w.begin_object()?;
            w.field_u64("bus", d.barramento as u64)?;
            w.field_u64("device", d.dispositivo as u64)?;
            w.field_u64("function", d.funcao as u64)?;
            w.field_u64("vendor", d.fabricante as u64)?;
            w.field_u64("model", d.modelo as u64)?;
            w.field_u64("class", d.classe as u64)?;
            w.field_u64("subclass", d.subclasse as u64)?;
            w.field_u64("interface", d.interface as u64)?;
            w.field_u64("revision", d.revisao as u64)?;
            w.field_str("role", d.o_que_faz())?;
            match d.primeira_regiao() {
                Some(regiao) => {
                    w.field_u64("mmio_base", regiao.base)?;
                    w.field_u64("mmio_size", regiao.tamanho)?;
                }
                None => {
                    w.key("mmio_base")?;
                    w.null_value()?;
                }
            }
            w.end_object()
        })();
    });
    erro?;
    w.end_array()?;
    w.end_object()
}

// ---------------------------------------------------------------------------
// disk.*
// ---------------------------------------------------------------------------

/// Quantos bytes de um setor o `disk.read` mostra quando ninguém pede um
/// número.
///
/// Sessenta e quatro porque é o que cabe numa tela de terminal sem rolar e o
/// suficiente para reconhecer uma assinatura, que é o uso real: confirmar que
/// o setor lido é o setor esperado. Quem quiser o resto pede.
const BYTES_MOSTRADOS_POR_PADRAO: u64 = 64;

fn disk_info(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    match crate::virtio::blk::com_o_disco(|disco| disco.capacidade()) {
        Some(setores) => {
            w.field_bool("present", true)?;
            w.field_u64("sectors", setores)?;
            w.field_u64("sector_size", crate::virtio::blk::TAMANHO_DO_SETOR as u64)?;
            w.field_u64(
                "bytes",
                setores * crate::virtio::blk::TAMANHO_DO_SETOR as u64,
            )?;
        }
        // Ausência não é erro. A máquina pode legitimamente não ter disco, e
        // dizer isso é mais útil ao agente que um código de falha que ele
        // teria de distinguir de um disco quebrado.
        None => w.field_bool("present", false)?,
    }
    w.end_object()
}

fn disk_read(params: Json, w: &mut JsonWriter) -> fmt::Result {
    let setor = params
        .member("sector")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let mostrados = params
        .member("length")
        .and_then(|v| v.as_u64())
        .unwrap_or(BYTES_MOSTRADOS_POR_PADRAO)
        .min(crate::virtio::blk::TAMANHO_DO_SETOR as u64) as usize;

    let mut buffer = [0u8; crate::virtio::blk::TAMANHO_DO_SETOR];
    let resultado = crate::virtio::blk::com_o_disco(|disco| disco.ler_setor(setor, &mut buffer));

    w.begin_object()?;
    w.field_u64("sector", setor)?;

    match resultado {
        None => {
            w.field_bool("ok", false)?;
            w.field_str("error", "nao ha disco virtio nesta maquina")?;
        }
        Some(Err(motivo)) => {
            w.field_bool("ok", false)?;
            w.field_str("error", motivo)?;
        }
        Some(Ok(())) => {
            w.field_bool("ok", true)?;
            w.field_u64("length", mostrados as u64)?;

            // Hexadecimal e ASCII lado a lado, que é o formato em que um
            // despejo de setor se lê. O ASCII é o que deixa uma assinatura
            // saltar aos olhos; o hexadecimal é o que permite conferir os
            // bytes que não são texto.
            w.key("hex")?;
            escrever_hex(w, &buffer[..mostrados])?;
            w.key("ascii")?;
            escrever_ascii(w, &buffer[..mostrados])?;
        }
    }

    w.end_object()
}

/// Escreve os bytes como uma string hexadecimal, sem separadores.
///
/// Byte a byte, e não montando uma `String` antes, porque o escritor JSON já
/// é um fluxo: acumular 1 KiB de texto num `Vec` para escrevê-lo em seguida
/// seria alocar para nada.
fn escrever_hex(w: &mut JsonWriter, bytes: &[u8]) -> fmt::Result {
    w.begin_str()?;
    for &byte in bytes {
        escrever_byte_hex(w, byte)?;
    }
    w.end_str()
}

/// Escreve um byte como dois dígitos hexadecimais, dentro de uma string aberta.
fn escrever_byte_hex(w: &mut JsonWriter, byte: u8) -> fmt::Result {
    const DIGITOS: &[u8; 16] = b"0123456789abcdef";
    w.push_char(DIGITOS[(byte >> 4) as usize] as char)?;
    w.push_char(DIGITOS[(byte & 0xF) as usize] as char)
}

/// Escreve os bytes como texto, trocando o que não for imprimível por ponto.
fn escrever_ascii(w: &mut JsonWriter, bytes: &[u8]) -> fmt::Result {
    w.begin_str()?;
    for &byte in bytes {
        // O intervalo é o dos caracteres ASCII imprimíveis. Tudo fora dele
        // vira ponto — inclusive as aspas e a barra invertida, que exigiriam
        // escape no JSON e que ninguém procura num despejo de setor.
        let visivel = (0x20..0x7F).contains(&byte) && byte != b'"' && byte != b'\\';
        w.push_char(if visivel { byte as char } else { '.' })?;
    }
    w.end_str()
}

fn irq_stats(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    w.field_u64("total", crate::irq::total())?;
    // O total conta toda interrupcao; as linhas so contam as que cabem no
    // teto. Sem este campo a diferenca entre os dois seria um numero que nao
    // fecha e nao se explica.
    w.field_u64("beyond_line_limit", crate::irq::fora_do_teto())?;

    // Os dispositivos virtio aparecem em separado porque uma linha de PCI e
    // compartilhada: no x86 o disco e a rede caem os dois na IRQ 11, e o
    // contador daquela linha nao diz qual dos dois interrompeu. Este e o
    // unico lugar onde a resposta existe.
    w.key("virtio")?;
    w.begin_array()?;
    let mut erro = Ok(());
    crate::virtio::com_interrupcoes(|nome, linha, avisos| {
        if erro.is_err() {
            return;
        }
        erro = (|| {
            w.begin_object()?;
            w.field_str("device", nome)?;
            w.field_u64("line", linha as u64)?;
            w.field_u64("count", avisos)?;
            w.end_object()
        })();
    });
    erro?;
    w.end_array()?;

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
    let e = crate::tarefas::executor::estatisticas();
    let (ocupacao, capacidade, descartados) = crate::tarefas::entrada::estatisticas();

    w.begin_object()?;
    w.field_u64("spawned", e.lancadas)?;
    w.field_u64("completed", e.concluidas)?;
    w.field_u64("alive", e.lancadas.saturating_sub(e.concluidas))?;
    // Quantas vezes uma tarefa foi efetivamente avancada. A razao entre isto
    // e `wakes` diz se o executor esta trabalhando ou girando: com wakers
    // funcionando, os dois numeros andam juntos.
    w.field_u64("polls", e.avancos)?;
    w.field_u64("wakes", e.despertares)?;
    // Despertares que encontraram a tarefa ja enfileirada. Nao sao perda: sao
    // trabalho que nao precisou ser feito, e sao a explicacao para a distancia
    // entre `wakes` e `polls`.
    w.field_u64("wakes_coalesced", e.despertares_juntados)?;

    // A tabela de adormecidos. Quando ela lota, quem nao cabe nao dorme: pede
    // para ser acordado na hora e volta a rodar em espera ativa. Nada se
    // perde, mas o nucleo gira em vez de dormir -- e sem este numero a unica
    // prova disso era um aviso num anel de log que da a volta.
    let (dormindo, vagas) = crate::tarefas::relogio::ocupacao();
    w.key("sleepers")?;
    w.begin_object()?;
    w.field_u64("waiting", dormindo as u64)?;
    w.field_u64("capacity", vagas as u64)?;
    w.field_u64("without_slot", crate::tarefas::relogio::sem_vaga())?;
    w.end_object()?;
    // Tarefas que existem e nao rodam, porque a entrada delas nao coube na
    // fila de prontas — no lancamento ou num despertar. Diferente de zero aqui
    // explica uma tarefa parada que de outra forma pareceria apenas ociosa, e
    // sobrevive a volta do anel de log, que e onde a evidencia ficava antes.
    w.field_u64("never_scheduled", e.nunca_agendadas)?;

    w.key("input")?;
    w.begin_object()?;
    w.field_u64("queued", ocupacao as u64)?;
    w.field_u64("capacity", capacidade as u64)?;
    // Byte descartado e requisicao corrompida. Um valor diferente de zero
    // aqui explica um erro de JSON que de outra forma pareceria inexplicavel.
    w.field_u64("dropped", descartados)?;
    // Perda de outra natureza: bytes que chegaram antes de o canal existir, e
    // que a subida da porta jogou fora. Publicado aqui porque no ARM o aviso
    // equivalente no log nao tem onde ser lido -- a unica serial e este canal.
    w.field_u64(
        "dropped_before_ready",
        crate::tarefas::entrada::descartados_no_boot(),
    )?;
    w.end_object()?;

    w.end_object()
}

fn tasks_list(_params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    // O teto do inventario e quantas tarefas ficaram de fora dele, pela mesma
    // razao de `pci.list`: a lista pode ser mais curta que a verdade, e quem
    // le precisa distinguir "so ha isto" de "isto e o que coube".
    w.field_u64(
        "capacity",
        crate::tarefas::executor::capacidade_do_inventario() as u64,
    )?;
    w.field_u64(
        "omitted",
        crate::tarefas::executor::estatisticas().fora_do_inventario,
    )?;
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

fn user_run(params: Json, w: &mut JsonWriter) -> fmt::Result {
    let caminho = params.member("path").and_then(|v| v.as_str());

    w.begin_object()?;
    // O caminho e devolvido junto com a resposta: o lancamento nao espera o
    // processo, entao quem perguntar depois precisa saber a qual programa o
    // `last_exit` se refere.
    w.field_str("program", caminho.unwrap_or("<exemplo embutido>"))?;
    // Com a autoridade de quem pediu: o processo de um agente abre e executa
    // o que o papel do agente alcança — ver [`crate::autorizacao`].
    match crate::usuario::lancar_como(caminho, crate::autorizacao::autoridade_atual()) {
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
    let (bifurcacoes, trocas, saidas) = crate::usuario::estatisticas_de_processo();
    let (aberturas, leituras, bytes_lidos) = crate::usuario::estatisticas_de_arquivo();

    w.begin_object()?;
    w.field_u64("syscalls", chamadas)?;
    w.field_u64("forks", bifurcacoes)?;
    w.field_u64("execs", trocas)?;
    w.field_u64("exits", saidas)?;
    // Recusadas sao pedidos que o kernel se negou a atender: numero de chamada
    // desconhecido, ou um ponteiro que nao pertence ao processo. Um valor que
    // sobe sozinho denuncia um processo tentando alcancar o que nao e dele.
    w.field_u64("rejected", recusadas)?;
    w.field_u64("bytes_written", bytes)?;
    // A interface nativa: pedidos ao registro atendidos, e os que nem
    // chegaram a um comando — JSON quebrado, método ou parâmetro errado.
    let (pedidos, invalidos) = crate::nativo::estatisticas();
    w.field_u64("native_requests", pedidos)?;
    w.field_u64("native_invalid", invalidos)?;
    // Arquivos: quantos descritores foram abertos, quantas leituras
    // aconteceram por eles e quantos bytes vieram. `opens` sem `reads` e um
    // programa que abriu e desistiu; `reads` sem `bytes_read` e um arquivo
    // que acabou.
    w.field_u64("opens", aberturas)?;
    w.field_u64("reads", leituras)?;
    w.field_u64("bytes_read", bytes_lidos)?;
    // Memoria nova que os processos pediram por `mapear`: quantas chamadas
    // deram certo e quantas paginas elas deram, desde o boot. Paginas sem
    // mapeamentos nao existem; mapeamentos que crescem sem parar sao um
    // processo pedindo memoria que nao devolve.
    let (mapeamentos, paginas) = crate::usuario::estatisticas_de_memoria();
    w.field_u64("maps", mapeamentos)?;
    w.field_u64("pages_mapped", paginas)?;
    // Quantos descritores o fio que atende este comando tem abertos. E o do
    // canal do agente, nao o de um processo -- ele mostra os tres padrao, que
    // e o que todo fio recebe.
    w.field_u64(
        "descriptors_open",
        crate::fios::com_descritores(|t| t.abertos()).unwrap_or(0) as u64,
    )?;

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
    // Quantos fios mortos ja foram desmontados. Comparado com `alive` e com
    // `max_threads`, e o que distingue "o sistema esta parado" de "o sistema
    // criou e recolheu centenas de fios" — duas situacoes que um retrato
    // instantaneo da tabela mostra identicas.
    w.field_u64("reaped", crate::fios::recolhidos())?;
    // E os dois numeros do parentesco. `harvested` conta as colheitas de
    // `esperar`; `zombies` e quantos filhos ja terminaram e ainda guardam o
    // codigo de saida para um pai que nao perguntou.
    //
    // Um `zombies` que so cresce e o sintoma de um processo que bifurca e
    // nao espera: cada filho retem uma das vagas de fio ate o pai morrer. E
    // a unica forma de ver isso de fora, porque um retrato da tabela mostra
    // "done" para o que ja foi e para o que ainda vai ser recolhido.
    let (colhidos, zumbis) = crate::fios::colheita();
    w.field_u64("harvested", colhidos)?;
    w.field_u64("zombies", zumbis as u64)?;
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
            // Em que núcleo ele está agora, e a qual está preso, se a algum.
            w.key("core")?;
            match inscricao.nucleo {
                Some(n) => w.u64_value(n as u64)?,
                None => w.null_value()?,
            }
            w.key("pinned")?;
            match inscricao.fixo {
                Some(n) => w.u64_value(n as u64)?,
                None => w.null_value()?,
            }
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
    let mem = crate::machine::estatisticas();

    w.begin_object()?;
    w.field_u64("usable_bytes", mem.utilizavel)?;
    // RAM de verdade, que o bootloader retem e que um dia se recupera.
    w.field_u64("bootloader_bytes", mem.bootloader)?;
    // A soma do mapa inteiro, e nao quanta memoria a maquina tem: o mapa
    // descreve espaco de enderecamento, e o buraco de MMIO de uma maquina de
    // 128 MiB chega a doze gibibytes. O campo se chamava `total_bytes` e era
    // lido como memoria instalada — plausivel, e errado por duas ordens de
    // grandeza.
    w.field_u64("described_bytes", mem.descrito)?;
    w.field_u64("region_count", mem.regioes as u64)?;
    // Se o mapa não coube na tabela, dizemos — um agente não tem como
    // desconfiar sozinho de um número que parece plausível.
    w.field_u64(
        "dropped_regions",
        crate::machine::regioes_descartadas() as u64,
    )?;
    // Quanto espaco virtual ja foi entregue a registradores de dispositivo.
    // Nao sai da RAM utilizavel — e uma faixa propria —, mas e o unico numero
    // que revela um driver mapeando mais do que devia.
    w.field_u64("device_mapped_bytes", crate::mmio::reservado())?;
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
    // E a outra forma de `by_type` deixar de somar `total`: a tabela de tipos
    // encheu. A trava foi obtida, a vaga e que faltou — causa diferente, efeito
    // igual para quem le, numero proprio.
    w.field_u64("types_lost", crate::traps::tipos_perdidos())?;

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
        "hang_core" => {
            // Um núcleo travado de propósito, com as interrupções
            // desligadas — ver `nucleos::travar`. Pela mesma permissão dos
            // outros tipos, e com o tipo como recurso: uma política pode dar
            // `breakpoint` sem dar isto.
            let nucleo = params.member("core").and_then(|v| v.as_u64());
            let ms = params.member("ms").and_then(|v| v.as_u64()).unwrap_or(0);
            w.field_bool("survived", true)?;
            match nucleo {
                None => w.field_str("error", "hang_core exige `core`")?,
                Some(n) => match crate::nucleos::travar(n as usize, ms) {
                    Ok(fio) => {
                        w.field_str("triggered", "hang_core")?;
                        w.field_u64("core", n)?;
                        w.field_u64("ms", ms)?;
                        w.field_bool("forever", ms == 0)?;
                        w.field_u64("thread", fio)?;
                    }
                    Err(motivo) => w.field_str("error", motivo)?,
                },
            }
        }
        outro => {
            w.field_bool("survived", true)?;
            w.field_str("error", "tipo de excecao nao suportado")?;
            w.field_str("requested", outro)?;
            w.field_str("supported", "breakpoint, fatal, hang_core")?;
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
            // Quantos bytes da mensagem nao couberam. Zero na esmagadora maioria;
            // diferente de zero e a diferenca entre ler um fato e ler metade dele.
            if registro.perdidos() > 0 {
                w.field_u64("truncated_bytes", registro.perdidos() as u64)?;
            }
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

/// A versão de um campo e quem o tem arrendado agora — `null` se ninguém.
/// É o que um agente lê antes de editar: a versão vai no `expect_version`,
/// e o arrendamento diz se o campo é de outro.
fn escrever_coordenacao(w: &mut JsonWriter, id: u32) -> fmt::Result {
    let e = crate::coordenacao::estado(&crate::coordenacao::recurso(id));
    w.field_u64("version", e.versao)?;
    w.key("lease")?;
    match &e.arrendamento {
        Some(a) => escrever_arrendamento(w, a),
        None => w.null_value(),
    }
}

/// O arrendamento de um campo, como o relatório o escreve.
fn escrever_arrendamento(
    w: &mut JsonWriter,
    a: &politica::arrendamento::Arrendamento,
) -> fmt::Result {
    let (tipo, quem) = crate::coordenacao::descrever(&a.titular);
    w.begin_object()?;
    w.field_str("holder", tipo)?;
    w.field_str("by", &quem)?;
    w.field_u64("since_ms", a.desde_ms)?;
    w.field_u64("expires_ms", a.expira_ms)?;
    w.end_object()
}

/// O campo de `ui.claim` e `ui.release`: o elemento, se é um campo.
fn campo_do_pedido(id: Option<u64>) -> Option<u32> {
    let id = u32::try_from(id?).ok()?;
    (crate::ui::existe(id) && crate::ui::e_campo(id)).then_some(id)
}

fn ui_claim(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let Some(id) = campo_do_pedido(params.member("id").and_then(|v| v.as_u64())) else {
        w.field_bool("ok", false)?;
        return w
            .field_str("error", "nao ha campo com este id")
            .and_then(|()| w.end_object());
    };
    let Some(titular) =
        crate::coordenacao::titular_da_autoridade(crate::autorizacao::autoridade_atual())
    else {
        w.field_bool("ok", false)?;
        return w
            .field_str("error", "quem pediu nao tem titular de arrendamento")
            .and_then(|()| w.end_object());
    };
    let prazo = params
        .member("ttl_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(crate::coordenacao::PRAZO_PADRAO_MS);
    let recurso = crate::coordenacao::recurso(id);
    match crate::coordenacao::tomar(&recurso, titular, prazo) {
        Ok(a) => {
            w.field_bool("ok", true)?;
            w.key("lease")?;
            escrever_arrendamento(w, &a)?;
        }
        Err(codigo) => {
            w.field_bool("ok", false)?;
            w.field_str("code", codigo.nome())?;
            w.field_str("error", "outro titular tem o arrendamento")?;
            if let Some(a) = crate::coordenacao::estado(&recurso).arrendamento {
                w.key("lease")?;
                escrever_arrendamento(w, &a)?;
            }
        }
    }
    w.field_u64("version", crate::coordenacao::estado(&recurso).versao)?;
    w.end_object()
}

fn ui_release(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let Some(id) = campo_do_pedido(params.member("id").and_then(|v| v.as_u64())) else {
        w.field_bool("ok", false)?;
        return w
            .field_str("error", "nao ha campo com este id")
            .and_then(|()| w.end_object());
    };
    let Some(titular) =
        crate::coordenacao::titular_da_autoridade(crate::autorizacao::autoridade_atual())
    else {
        w.field_bool("ok", false)?;
        return w
            .field_str("error", "quem pediu nao tem titular de arrendamento")
            .and_then(|()| w.end_object());
    };
    match crate::coordenacao::soltar(&crate::coordenacao::recurso(id), titular) {
        Ok(()) => w.field_bool("ok", true)?,
        Err(codigo) => {
            w.field_bool("ok", false)?;
            w.field_str("code", codigo.nome())?;
            w.field_str("error", "o arrendamento nao e seu")?;
        }
    }
    w.end_object()
}

// ---------------------------------------------------------------------------
// Mensagens: ver crate::mensagens. Cada handler age pelo titular da sessão
// que pediu — nunca por um parâmetro — e o de `message.send`, sobre o
// destinatário que a decisão resolveu.
// ---------------------------------------------------------------------------

/// Escreve a recusa de uma operação de mensagem.
fn recusa_de_mensagem(w: &mut JsonWriter, codigo: politica::Codigo, motivo: &str) -> fmt::Result {
    w.field_bool("ok", false)?;
    w.field_str("code", codigo.nome())?;
    w.field_str("error", motivo)?;
    w.end_object()
}

/// O titular da sessão, ou a recusa escrita.
fn titular_de_mensagens(w: &mut JsonWriter) -> Result<crate::mensagens::Remetente, fmt::Result> {
    crate::mensagens::Remetente::da_sessao().ok_or_else(|| {
        recusa_de_mensagem(
            w,
            politica::Codigo::DenyNotAuthenticated,
            "a sessao nao tem titular de mensagens",
        )
    })
}

fn message_send(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let remetente = match titular_de_mensagens(w) {
        Ok(r) => r,
        Err(r) => return r,
    };
    // O destinatário é o que a decisão viu: o handler não o resolve de novo.
    // E confere que é o do pedido — a licença e os parâmetros são do mesmo
    // comando; se um dia não forem, nada é mandado.
    let pedido = params.member("to").and_then(|v| v.as_str());
    let Some(destino) =
        crate::autorizacao::destino_decidido().filter(|d| Some(d.texto.as_str()) == pedido)
    else {
        return recusa_de_mensagem(
            w,
            politica::Codigo::DenyResource,
            "sem destinatario decidido",
        );
    };
    let nonce = params.member("nonce").and_then(|v| v.as_u64()).unwrap_or(0);
    let prazo = params.member("ttl_ms").and_then(|v| v.as_u64());
    // O corpo desescapado nunca é maior que o escrito: um buffer do tamanho
    // do escrito sempre cabe, e o teto é conta da tabela, gravada lá.
    let bruto = params.member("body");
    let mut buffer = alloc::vec![0u8; bruto.map_or(0, |b| b.0.len())];
    let Some(corpo) = bruto.and_then(|b| b.desescapar_em(&mut buffer)) else {
        crate::autorizacao::auditar_mensagem(
            crate::autorizacao::AtorDeMensagem::Autoridade(crate::autorizacao::autoridade_atual()),
            "message.send",
            &destino.texto,
            politica::Codigo::InvalidArgument,
            "o corpo nao e texto",
        );
        return recusa_de_mensagem(w, politica::Codigo::InvalidArgument, "o corpo nao e texto");
    };
    let (resultado, duravel) = crate::mensagens::enviar(&remetente, &destino, corpo, nonce, prazo);
    match resultado {
        Ok((id, e)) => {
            w.field_bool("ok", true)?;
            w.field_str("id", &id)?;
            w.field_u64("version", e.versao)?;
            w.field_bool("duplicate", e.duplicata)?;
            w.field_str("to", &destino.texto)?;
            escrever_duravel(w, duravel)?;
            w.end_object()
        }
        Err(r) => recusa_de_mensagem(w, r.codigo(), r.motivo()),
    }
}

/// Se o que a operação mudou está no journal. `durable: true` é uma
/// promessa: a mudança está escrita, descarregada e ancorada, e não volta
/// atrás num reboot. `false` diz que ela vale só em memória, e por quê.
pub(crate) fn escrever_duravel(
    w: &mut JsonWriter,
    duravel: crate::mensagens::Duravel,
) -> fmt::Result {
    w.field_bool("durable", duravel.is_ok())?;
    if let Err(motivo) = duravel {
        w.field_str("memory_only", motivo)?;
    }
    Ok(())
}

/// O remetente de uma mensagem, como a leitura o escreve: o tipo e quem.
fn escrever_remetente(w: &mut JsonWriter, dono: politica::mensagens::Dono) -> fmt::Result {
    let (tipo, quem) = crate::mensagens::descrever(dono);
    w.key("from")?;
    w.begin_object()?;
    w.field_str("type", tipo)?;
    if let Some((campo, valor)) = quem {
        w.field_str(campo, &valor)?;
    }
    if let politica::mensagens::Dono::Agente(k) | politica::mensagens::Dono::Administrador(k) = dono
    {
        w.field_str("key", &sigilo::hex(&k))?;
    }
    w.end_object()
}

/// A leitura da caixa de `remetente`, escrita em `w` — pela sessão, aqui, e
/// pela operação administrativa, com a prova.
pub(crate) fn escrever_caixa(
    w: &mut JsonWriter,
    remetente: &crate::mensagens::Remetente,
    apos: Option<&str>,
    max: Option<u64>,
) -> Result<(), (politica::Codigo, &'static str)> {
    let max = max
        .unwrap_or(8)
        .clamp(1, politica::mensagens::TETO_POR_CAIXA as u64) as usize;
    let (lidas, duravel) = crate::mensagens::ler(remetente, apos, max);
    let (epoca, lidas) = lidas.map_err(|r| (r.codigo(), r.motivo()))?;
    let escrever = |w: &mut JsonWriter| -> fmt::Result {
        escrever_duravel(w, duravel)?;
        w.field_str("epoch", &epoca)?;
        w.key("messages")?;
        w.begin_array()?;
        for (id, l) in &lidas {
            w.begin_object()?;
            w.field_str("id", id)?;
            escrever_remetente(w, l.de)?;
            w.field_str("body", &l.corpo)?;
            w.field_u64("sent_ms", l.criada_ms)?;
            w.field_u64("expires_ms", l.expira_ms)?;
            w.field_str("state", l.estado.nome())?;
            w.field_u64("version", l.versao)?;
            w.end_object()?;
        }
        w.end_array()
    };
    escrever(w).map_err(|_| (politica::Codigo::Error, "a resposta nao foi escrita"))
}

fn message_read(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let remetente = match titular_de_mensagens(w) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let apos = params.member("after").and_then(|v| v.as_str());
    let max = params.member("max").and_then(|v| v.as_u64());
    match escrever_caixa(w, &remetente, apos, max) {
        Ok(()) => {
            w.field_bool("ok", true)?;
            w.end_object()
        }
        Err((codigo, motivo)) => recusa_de_mensagem(w, codigo, motivo),
    }
}

/// Uma transição pedida por id, e a resposta: o estado novo, ou a recusa.
fn responder_transicao(
    w: &mut JsonWriter,
    (r, duravel): (
        Result<politica::mensagens::Transicao, politica::mensagens::Recusa>,
        crate::mensagens::Duravel,
    ),
) -> fmt::Result {
    match r {
        Ok(t) => {
            w.field_bool("ok", true)?;
            w.field_str("state", t.estado.nome())?;
            w.field_u64("version", t.versao)?;
            escrever_duravel(w, duravel)?;
            w.end_object()
        }
        Err(r) => recusa_de_mensagem(w, r.codigo(), r.motivo()),
    }
}

fn message_ack(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let remetente = match titular_de_mensagens(w) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let id = params.member("id").and_then(|v| v.as_str()).unwrap_or("");
    let esperada = params.member("expect_version").and_then(|v| v.as_u64());
    responder_transicao(w, crate::mensagens::confirmar(&remetente, id, esperada))
}

fn message_cancel(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let remetente = match titular_de_mensagens(w) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let id = params.member("id").and_then(|v| v.as_str()).unwrap_or("");
    let esperada = params.member("expect_version").and_then(|v| v.as_u64());
    responder_transicao(w, crate::mensagens::cancelar(&remetente, id, esperada))
}

fn message_status(params: Json, w: &mut JsonWriter) -> fmt::Result {
    w.begin_object()?;
    let remetente = match titular_de_mensagens(w) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let id = params.member("id").and_then(|v| v.as_str()).unwrap_or("");
    let (resultado, duravel) = crate::mensagens::estado(&remetente, id);
    match resultado {
        Ok((estado, versao)) => {
            w.field_bool("ok", true)?;
            w.field_str("state", estado.nome())?;
            w.field_u64("version", versao)?;
            escrever_duravel(w, duravel)?;
            w.end_object()
        }
        Err(r) => recusa_de_mensagem(w, r.codigo(), r.motivo()),
    }
}
