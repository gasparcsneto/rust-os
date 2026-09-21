# rust-os

Um kernel escrito do zero em Rust para **x86_64 e aarch64**, projetado desde
a primeira linha para ser operado tanto por humanos quanto por um agente.

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
  kernel, falando por uma porta serial dedicada. Toda linha que sai desse
  canal é um objeto JSON válido. Sem ruído, sem heurística.

- **Auto-descrição.** O kernel descreve a própria superfície via
  `agent.describe`, do mesmo jeito que um servidor MCP lista suas ferramentas.
  O agente *descobre* o que pode fazer em vez de adivinhar.

- **Logging estruturado.** Todo evento é um registro tipado (nível, subsistema,
  número de sequência, carimbo de uptime) num ring buffer consultável. O texto
  legível no console é apenas uma renderização — não a fonte da verdade.

- **Falhas sobrevividas.** Uma exceção fatal não mata o canal: o kernel entra
  em modo post-mortem e segue respondendo qual exceção ocorreu, onde e com que
  código. Um cadáver que responde à autópsia.

- **Introspecção de primeira classe.** Mapa de memória, informações de CPU e
  vídeo, histórico de log: tudo acessível de forma estruturada, em tempo de
  execução.

O canal existe desde o primeiro milissegundo do boot, antes de haver
paginação, heap ou interrupções. Essa precocidade é intencional: ele serve
para ajudar a construir e depurar as camadas que vêm depois dele.

No ARM isso deixa de ser conveniência e vira necessidade. A máquina `virt` do
emulador tem **uma única** porta serial, então o canal do agente é literalmente
a única interface de depuração do sistema — não há console de texto. Os
registros de log vivem no ring buffer e saem por `log.tail`.

O port para ARM foi o teste mais duro dessa premissa, e ela passou: o primeiro
bug do boot ARM (`x0` chegando nulo, sem device tree) foi diagnosticado pelo
próprio canal, lendo `log.tail`.

## Começando

Requisitos: Rust nightly (instalado automaticamente pelo `rust-toolchain.toml`)
e os pacotes do emulador para as arquiteturas desejadas.

```bash
# x86_64 (padrão): compila e gera as imagens BIOS e UEFI
cargo xtask build
cargo xtask run

# aarch64: compila e gera a imagem arm64 crua
cargo xtask build --arch aarch64
cargo xtask run   --arch aarch64

# Suíte de testes, dentro do emulador
cargo xtask test
cargo xtask test --arch aarch64
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

# O mesmo protocolo, no kernel ARM
$ cargo xtask agent --arch aarch64 system.info
{"jsonrpc":"2.0","id":1,"result":{"arch":"aarch64","cpu_vendor":"ARM Limited",
 "framebuffer":null,"log_records":6}}
```

Os dois podem rodar ao mesmo tempo: cada arquitetura tem seu próprio socket.

## Comandos disponíveis

| Comando | Descrição |
|---|---|
| `agent.ping` | Verifica se o canal está vivo |
| `agent.describe` | Lista todos os comandos e parâmetros |
| `system.info` | Kernel, CPU, vídeo e uptime |
| `system.uptime` | Ticks do timer e milissegundos desde o boot |
| `memory.stats` | Totais agregados de memória física |
| `memory.regions` | Regiões do mapa de memória (`limit`, `usable_only`) |
| `memory.frames` | Estado do alocador de frames físicos |
| `paging.translate` | Traduz um endereço virtual para físico (`address`) |
| `irq.stats` | Contadores de interrupções de hardware por linha |
| `traps.stats` | Contadores de exceções e detalhes da última falha |
| `debug.trigger` | Dispara uma exceção de propósito, para autoteste (`kind`) |
| `log.tail` | Registros de log estruturados (`count`, `min_level`) |

Esta tabela é gerada a partir do mesmo registro que o kernel usa para validar
chamadas — `agent.describe` sempre reflete a verdade.

## Arquitetura

```
kernel/src/
├── main.rs          fluxo de boot comum às duas arquiteturas
├── machine.rs       descrição da máquina, neutra de arquitetura
├── serial.rs        papéis de console e canal do agente
├── log.rs           logging estruturado em ring buffer
├── frames.rs        alocador de frames de memória física (bitmap)
├── testes.rs        suíte de testes que roda dentro do emulador
├── traps.rs         contabilidade de exceções e modo post-mortem
├── irq.rs           contadores de interrupções de hardware
├── tempo.rs         contagem de tempo desde o boot
├── qemu.rs          encerramento do emulador para testes
├── agent/
│   ├── mod.rs       laço de atendimento e despacho
│   ├── json.rs      JSON sem alocação (streaming + varredura)
│   ├── protocol.rs  envelope JSON-RPC 2.0
│   ├── registry.rs  registro de comandos auto-descritivo
│   └── commands.rs  implementações dos comandos
└── arch/
    ├── mod.rs        seleção da arquitetura em tempo de compilação
    ├── x86_64/
    │   ├── mod.rs    entrada via crate `bootloader`, CPUID, portas de I/O
    │   ├── gdt.rs    GDT, TSS e pilha dedicada ao double fault
    │   ├── idt.rs    IDT e handlers de exceção e interrupção
    │   ├── pic.rs    controlador 8259 e timer PIT
    │   ├── paginacao.rs  assume as tabelas de página do bootloader
    │   └── uart.rs   UART 16550 por port-mapped I/O
    └── aarch64/
        ├── mod.rs     boot em assembly, cabeçalho de imagem arm64, MIDR_EL1
        ├── vetores.rs tabela de vetores de exceção (VBAR_EL1)
        ├── gic.rs     GIC v2 e timer genérico do ARM
        ├── mmu.rs     tabelas de tradução e ativação da MMU
        ├── uart.rs    PL011 por memory-mapped I/O
        ├── fdt.rs     leitor de device tree escrito à mão
        └── linker.ld  layout de memória e símbolos de boot

xtask/src/main.rs    build system: compila, gera imagens, roda o emulador
```

**Como as duas arquiteturas convivem.** Cada backend em `arch/` traduz o que
recebeu do firmware para as estruturas neutras de `machine.rs` durante o boot.
Daí para baixo, nenhuma linha do kernel sabe em que processador está rodando —
é por isso que a mesma resposta JSON sai dos dois.

O contraste no caminho de boot é grande:

| | x86_64 | aarch64 |
|---|---|---|
| Carga | crate `bootloader` (BIOS + UEFI) | protocolo de boot do arm64 |
| Artefato | imagem de disco | binário cru, cabeçalho de 64 bytes |
| Chegamos em | long mode, com pilha e paginação | MMU desligada, sem pilha |
| Mapa de memória | struct `BootInfo` pronta | device tree, parseado por nós |
| Seriais | duas UARTs 16550 (port I/O) | uma PL011 (MMIO) |
| Exceções | IDT de ponteiros, contexto salvo pela CPU | vetores de código, contexto salvo à mão |
| Interrupções | PIC 8259 + timer PIT | GIC v2 + timer genérico |
| MMU | já ligada pelo bootloader | desligada; nós a acendemos |
| Acesso à memória física | mapeada num deslocamento | identidade |
| Encerrar emulador | `isa-debug-exit` | semihosting |

Dois workspaces separados: o kernel compila bare-metal e o `xtask` para o
host. Um único workspace não suporta dois targets padrão.

## Testes

Os testes do kernel **não** rodam com `cargo test`: o harness padrão do Rust
depende da `std` e de um sistema operacional que colete os resultados, e aqui
nós somos o sistema operacional.

Em vez disso o kernel é seu próprio harness. Compilado com a feature
`modo-teste`, ele troca o laço do agente por um executor que roda a suíte,
imprime o relatório e encerra o emulador com um código de saída — por
`isa-debug-exit` no x86, por semihosting no ARM.

A vantagem é que os testes rodam no mesmo ambiente que o kernel de verdade,
em bare-metal, nas duas arquiteturas. Não há simulação nem mocks: quando o
teste do relógio verifica que o tempo avança, ele está esperando uma
interrupção de hardware de verdade.

```
$ cargo xtask test --arch aarch64
  suite de testes :: aarch64 :: 27 casos
  ...
  excecao: breakpoint retomado               ok
  timer: relogio avanca                      ok
  27 de 27 passaram
```

O CI roda formatação, clippy nas cinco configurações, e a suíte nas duas
arquiteturas em debug e release.

## Idioma

O código e os comentários estão em português — o projeto é também um material
de estudo, e cada decisão não óbvia é explicada no ponto onde aparece. As
chaves do protocolo JSON-RPC ficam em inglês por serem um contrato externo
padronizado.

## Roteiro

- [x] **Fase 0 — Base.** Boot bare-metal em x86_64 e aarch64, serial,
      logging estruturado, canal do agente, abstração de arquitetura.
- [x] **Fase 0 — Exceções e interrupções.** GDT/TSS/IDT e vetores EL1,
      double fault com pilha dedicada, PIC e GIC, timer a 100 Hz nas duas
      arquiteturas, modo post-mortem.
- [x] **Fase 0 — Testes e CI.** 27 casos rodando em bare-metal nas duas
      arquiteturas, em debug e release, com formatação e lints no CI.
- [x] **Fase 0 — Memória física e paginação.** Alocador de frames por bitmap,
      MMU ligada do zero no ARM com mapa de identidade, controle das tabelas
      do bootloader no x86, e uma API de mapeamento comum às duas.
- [ ] **Fase 0 (cont.)** — heap, que destrava `alloc` no kernel.
- [ ] **Fase 1 — Kernel de verdade.** Scheduler preemptivo, context switch,
      ring 3 com TSS, `syscall`/`sysret`, ELF loader, processos com espaços de
      endereçamento isolados.
- [ ] **Fase 2 — Drivers.** Enumeração PCI, virtio-blk, virtio-net, timer
      APIC/HPET, framebuffer gráfico.

## Licença

MIT OU Apache-2.0, a critério de quem usa.
