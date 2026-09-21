# rust-os

Um kernel x86_64 escrito do zero em Rust, projetado desde a primeira linha
para ser operado tanto por humanos quanto por um agente.

O ponto de partida é o material de [os.phil-opp.com](https://os.phil-opp.com),
mas o objetivo vai além do tutorial: chegar a um sistema com userspace real —
processos isolados em ring 3, syscalls, drivers e sistema de arquivos.

## O que torna este OS diferente

A maioria dos kernels expõe seu estado como texto: você lê um log e tenta
deduzir o que aconteceu. Isso obriga qualquer ferramenta automatizada a
adivinhar por expressões regulares que quebram na primeira mudança de formato.

Aqui a abordagem é invertida. **O estado do sistema é legível por máquina por
construção:**

- **Canal de agente estruturado.** Um servidor JSON-RPC 2.0 roda dentro do
  kernel, falando pela COM2 — separada do console humano na COM1. Toda linha
  que sai desse canal é um objeto JSON válido. Sem ruído, sem heurística.

- **Auto-descrição.** O kernel descreve a própria superfície via
  `agent.describe`, do mesmo jeito que um servidor MCP lista suas ferramentas.
  O agente *descobre* o que pode fazer em vez de adivinhar.

- **Logging estruturado.** Todo evento é um registro tipado (nível, subsistema,
  número de sequência) num ring buffer consultável. O texto legível na COM1 é
  apenas uma renderização — não a fonte da verdade.

- **Introspecção de primeira classe.** Mapa de memória, informações de CPU e
  vídeo, histórico de log: tudo acessível de forma estruturada, em tempo de
  execução.

O canal existe desde o primeiro milissegundo do boot, antes de haver
paginação, heap ou interrupções. Essa precocidade é intencional: ele serve
para ajudar a construir e depurar as camadas que vêm depois dele.

## Começando

Requisitos: Rust nightly (instalado automaticamente pelo `rust-toolchain.toml`)
e `qemu-system-x86`.

```bash
# Compila o kernel e gera as imagens BIOS e UEFI
cargo xtask build

# Sobe o kernel no QEMU (logs da COM1 no terminal)
cargo xtask run
```

Com o kernel rodando, converse com ele de outro terminal:

```bash
$ cargo xtask agent system.info
{"jsonrpc":"2.0","id":1,"result":{"arch":"x86_64","kernel":"kernel",
 "version":"0.1.0","phase":"0","cpu_vendor":"AuthenticAMD",
 "framebuffer":{"width":1280,"height":720,"stride":1280,
 "bytes_per_pixel":3,"pixel_format":"bgr"},"log_records":5}}

$ cargo xtask agent log.tail '{"count":3,"min_level":"info"}'
$ cargo xtask agent memory.regions '{"limit":2,"usable_only":true}'

# Descobre todos os comandos disponíveis e seus parâmetros
$ cargo xtask agent agent.describe
```

## Comandos disponíveis

| Comando | Descrição |
|---|---|
| `agent.ping` | Verifica se o canal está vivo |
| `agent.describe` | Lista todos os comandos e parâmetros |
| `system.info` | Kernel, CPU e vídeo |
| `memory.stats` | Totais agregados de memória física |
| `memory.regions` | Regiões do mapa de memória (`limit`, `usable_only`) |
| `log.tail` | Registros de log estruturados (`count`, `min_level`) |

Esta tabela é gerada a partir do mesmo registro que o kernel usa para validar
chamadas — `agent.describe` sempre reflete a verdade.

## Arquitetura

```
kernel/src/
├── main.rs          ponto de entrada; sequência de boot
├── serial.rs        driver UART 16550 (COM1 humano, COM2 agente)
├── log.rs           logging estruturado em ring buffer
├── boot.rs          acesso global ao BootInfo
├── qemu.rs          encerramento do QEMU para testes automatizados
└── agent/
    ├── mod.rs       laço de atendimento e despacho
    ├── json.rs      JSON sem alocação (streaming + varredura)
    ├── protocol.rs  envelope JSON-RPC 2.0
    ├── registry.rs  registro de comandos auto-descritivo
    └── commands.rs  implementações dos comandos

xtask/src/main.rs    build system: compila, gera imagens, roda QEMU, cliente
```

Dois workspaces separados: o kernel compila para `x86_64-unknown-none`
(bare-metal) e o `xtask` para o host. Um único workspace não suporta dois
targets padrão.

O código e os comentários estão em português — o projeto é também um material
de estudo, e cada decisão não óbvia é explicada no ponto onde aparece. As
chaves do protocolo JSON-RPC ficam em inglês por serem um contrato externo
padronizado.

## Roteiro

- [x] **Fase 0 — Base.** Boot bare-metal, serial, logging estruturado, canal
      do agente.
- [ ] **Fase 0 (cont.)** — GDT, IDT, exceções, double fault com IST,
      interrupções de hardware, teclado, paginação, heap, testes no QEMU.
- [ ] **Fase 1 — Kernel de verdade.** Scheduler preemptivo, context switch,
      ring 3 com TSS, `syscall`/`sysret`, ELF loader, processos com espaços de
      endereçamento isolados.
- [ ] **Fase 2 — Drivers.** Enumeração PCI, virtio-blk, virtio-net, timer
      APIC/HPET, framebuffer gráfico.

## Licença

MIT OU Apache-2.0, a critério de quem usa.
