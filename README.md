# Duke

Um kernel escrito do zero em Rust para **x86_64 e aarch64**, projetado desde
a primeira linha para ser operado tanto por humanos quanto por um agente.

O ponto de partida é o material de [os.phil-opp.com](https://os.phil-opp.com),
mas o objetivo vai além do tutorial: chegar a um sistema com userspace real —
processos isolados em ring 3, syscalls, drivers e sistema de arquivos.

O nome aparece onde importa para quem depura: é o prefixo de todo símbolo do
binário (`duke::fios::selecionar`), o nome do ELF que o depurador carrega e o
campo `kernel` que o canal do agente reporta em `agent.describe` e
`system.info`.

## O que torna o Duke diferente

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

Hoje ele é uma **tarefa assíncrona**: a UART interrompe quando chega um byte,
o handler só move os bytes para uma fila e aciona o waker, e todo o trabalho
de verdade acontece fora dele. Entre uma requisição e outra o núcleo fica
parado — não em espera ativa, nem acordando a cada 10 ms para conferir.

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

# Depuração
cargo xtask debug                    # sobe congelado, esperando gdb/lldb
cargo xtask simbolo 0xffff8000...    # endereço -> arquivo, linha e função
cargo xtask asm consumir_pilha       # o que o otimizador realmente gerou
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
| `system.info` | Kernel, CPU, vídeo, uptime e mecanismo de guarda da pilha |
| `system.uptime` | Ticks do timer e milissegundos desde o boot |
| `memory.stats` | Totais agregados de memória física |
| `memory.regions` | Regiões do mapa de memória (`limit`, `usable_only`) |
| `memory.frames` | Estado do alocador de frames físicos |
| `paging.translate` | Traduz um endereço virtual para físico (`address`) |
| `heap.stats` | Estado do heap, incluindo fragmentação |
| `tasks.stats` | Escalonador cooperativo e fila de entrada do canal |
| `threads.stats` | Escalonador preemptivo: trocas de contexto e quanta |
| `threads.list` | Fios de execução do kernel, com estado e vezes escalonado |
| `user.run` | Lança o programa de exemplo no anel sem privilégio |
| `user.stats` | Chamadas de sistema atendidas, recusadas e último código de saída |
| `tasks.list` | Tarefas lançadas, com id, nome e se estão vivas |
| `irq.stats` | Contadores de interrupções de hardware por linha |
| `traps.stats` | Contadores de exceções e detalhes da última falha |
| `debug.trigger` | Dispara uma exceção de propósito (`kind`: `breakpoint` ou `fatal`) |
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
├── paginacao.rs     fachada segura de mapeamento
├── heap.rs          alocador do kernel: lista livre ordenada com fusão
├── testes.rs        suíte de testes que roda dentro do emulador
├── fios/
│   ├── mod.rs       escalonador preemptivo: fios, rodízio e quantum
│   └── pilha.rs     pilhas de fio, cada uma com sua guard page
├── usuario/
│   ├── mod.rs       ABI das chamadas de sistema e validação de ponteiros
│   ├── programa.rs  mapeia o processo e desce de privilégio
│   └── exemplo.rs   dois programas mínimos, em assembly
├── tarefas/
│   ├── mod.rs       tarefa, identidade e o `yield` explícito
│   ├── executor.rs  escalonador cooperativo com suporte a wakers
│   ├── fila.rs      fila de capacidade fixa, escrita de dentro de handlers
│   ├── relogio.rs   o futuro que espera o tempo passar
│   └── entrada.rs   bytes do canal do agente, entregues por interrupção
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

xtask/src/main.rs    build system: compila, gera imagens, roda o emulador,
                     conecta depurador e traduz endereços em símbolos

docs/DEPURACAO.md    o ferramental de depuração, e o que não se aplica aqui
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
| Pilha de exceção | IST, índice no TSS | `SP_EL1`, trocado por hardware |
| Guard page da pilha | instalada pelo bootloader | construída antes de ligar a MMU |
| Interrupções | PIC 8259 + timer PIT | GIC v2 + timer genérico |
| Serial do agente | UART 16550 na IRQ 3 | PL011 no INTID 33 (SPI 1) |
| Dormir sem corrida | `sti; hlt`, par atômico | `wfi` acorda com IRQ mascarada |
| Troca de contexto | troca de pilha (`rsp`) | troca do quadro de exceção |
| Ceder a vez | chamada de função comum | `svc`, pelo mesmo caminho da preempção |
| Sem privilégio | ring 3 | EL0 |
| Chamada de sistema | `syscall`/`sysret` | `svc`, na tabela de vetores |
| Pilha na entrada | trocada à mão (`syscall` não troca) | `SP_EL1`, trocada pelo hardware |
| MMU | já ligada pelo bootloader | desligada; nós a acendemos |
| Acesso à memória física | mapeada num deslocamento | identidade |
| Encerrar emulador | `isa-debug-exit` | semihosting |

Dois workspaces separados: o kernel compila bare-metal e o `xtask` para o
host. Um único workspace não suporta dois targets padrão.

**O que vem de crate e o que é escrito à mão.** O critério é um só: montar
palavras de configuração a partir de deslocamentos lidos de um manual é onde
um erro não gera mensagem nenhuma — gera uma máquina sutilmente errada. Isso
vai para biblioteca. Protocolo e estrutura ficam explícitos.

| | de crate | escrito à mão |
|---|---|---|
| x86_64 | GDT, TSS, IDT, tabelas de página, portas de I/O (`x86_64`); boot (`bootloader`); UART (`uart_16550`) | PIC 8259 e timer PIT |
| aarch64 | registradores de sistema (`aarch64-cpu`); blocos de MMIO (`tock-registers`) | boot, tabela de vetores, descritores de página, leitor de device tree |

**O mapa do espaço virtual.** Cada região do kernel tem uma entrada da tabela
de topo só dela, separada da do usuário. Não é organização por gosto: dar uma
tabela de tradução a cada processo é copiar as entradas de topo do kernel para
a tabela nova e deixar as do usuário de fora — o que só funciona se nenhuma
entrada servir aos dois lados.

As duas arquiteturas chegam lá por caminhos diferentes, porque a granularidade
de uma entrada de topo difere em 512 vezes:

| | x86_64 (512 GiB por entrada) | aarch64 (1 GiB por entrada) |
|---|---|---|
| Imagem do kernel | `0xFFFF_8000_0000_0000` | `0x4008_0000` |
| Memória física mapeada | `0xFFFF_8800_0000_0000` | identidade |
| Heap | `0xFFFF_9000_0000_0000` | 64 GiB |
| Pilhas de fio | `0xFFFF_9800_0000_0000` | 128 GiB |
| Espaço do usuário | 4 GiB | 4 GiB |

No x86 a regra é a clássica — metade alta para o kernel, metade baixa para o
usuário —, e o endereço da memória física deixou de ser escolhido pelo
bootloader: ele caía em 2 TiB, dentro da metade que agora é do usuário. Fixá-lo
tem o mesmo benefício que fixar a base do kernel teve para a simbolização.

No ARM não existe metade alta (o `TCR_EL1` deste kernel configura 39 bits e
desliga as buscas por TTBR1), mas também não é preciso: com entradas de 1 GiB,
as regiões já caem em entradas distintas sem sair dos endereços baixos.

A separação é conferida em tempo de compilação. Mover uma constante para uma
entrada já ocupada não quebra nada visível até um processo carregar e o kernel
sumir de baixo dele — então o erro aparece no build, com o nome da região que
colidiu.

**Onde o `unsafe` pode morar.** Um kernel não tem como eliminá-lo: falar com
hardware, assembly e registradores de sistema exigem sair das garantias do
compilador. O que dá para fazer é mantê-lo concentrado, e hoje cerca de três
quartos dele vive em `arch/`; quase todo o resto está no alocador e na
paginação. A lógica portátil — escalonador, executor, log, despacho de
chamadas — é praticamente toda Rust seguro.

O canal do agente é o caso em que isso deixou de ser hábito e virou regra:
`agent/` inteiro carrega `#![deny(unsafe_code)]`. É o código que processa
entrada vinda de fora da máquina e o único subsistema grande que não fala com
hardware — não há motivo legítimo para `unsafe` ali, então nada de legítimo é
bloqueado, e o compilador impede que a próxima mudança desfaça isso em
silêncio.

## Multitarefa cooperativa

O kernel roda suas tarefas com `async`/`await` e um executor próprio. Não é
uma conveniência de sintaxe: `async`/`await` **é** multitarefa cooperativa,
com outro vocabulário.

| multitarefa cooperativa | `async`/`await` |
|---|---|
| tarefa | `Future` |
| ceder a CPU | devolver `Poll::Pending` |
| estado salvo à mão | campos da máquina de estados gerada pelo compilador |
| escalonador | executor |

É por isso que uma tarefa aqui não tem pilha própria: o que sobreviveria na
pilha entre dois `.await` o compilador guarda na struct que ele gera. Dá para
ter muitas tarefas sem pagar uma pilha por cada uma — o oposto do modelo
preemptivo com threads, que vem na fase 1.

O executor usa *wakers* de verdade. Uma tarefa que devolve `Pending` não é
consultada de novo até alguém avisar: o handler da serial avisa quando chega
um byte, o do timer avisa quando um prazo vence. Entre os dois, o núcleo
dorme. O comando `tasks.stats` mostra a conta — `polls` fica na casa das
dezenas depois de minutos no ar, não dos milhões.

A versão ingênua desse executor (fila circular, repolla todo mundo) passaria
em quase todos os testes da suíte. O caso `tarefa: adormecida nao gira` existe
exatamente para reprovar essa versão: ele conta os avanços de uma tarefa que
dorme cinco tiques e exige que sejam poucos.

## Multitarefa preemptiva

O executor cooperativo resolve concorrência de I/O, mas depende de todo mundo
cooperar: uma tarefa que entre num laço longo sem `.await` trava as outras.
Para o que não se pode confiar que ceda, existe o escalonador preemptivo —
**fios de execução**, cada um com sua pilha, trocados à força pelo timer.

As duas convivem, com a divisão usual: o executor cooperativo roda dentro de
**um** fio.

O caso `fios: preemptam sem cooperar` é o que separa uma coisa da outra. Dois
fios rodam um laço apertado sem `.await`, sem `ceder`, sem chamada de sistema
nenhuma. Num escalonador cooperativo, o primeiro rodaria para sempre:

```
[   15]  1020ms info  teste  fios avancaram 294315 e 296655 em 9 trocas
```

Cada fio tem pilha própria, mapeada em páginas com uma **guard page** logo
abaixo. Um `Box<[u8]>` seria uma linha de código e a decisão errada: estourar
uma pilha de heap não produz falha, produz uma escrita silenciosa no bloco
vizinho. Com a guard page, o estouro vira falha de página no instante em que
acontece, com o endereço no relatório.

O mecanismo de troca difere entre as arquiteturas, e a diferença é deliberada.
No x86 o quadro de interrupção é empilhado na pilha do próprio fio, então
trocar de fio é trocar de pilha. No ARM as exceções rodam numa pilha separada
(`SP_EL1`) — é o que dá a detecção de estouro de graça — e trocar essa pilha
destruiria a propriedade; lá o contexto completo já está no quadro de exceção,
e trocar de fio é trocar o quadro. Ceder de propósito passa por `svc`
justamente para cair nesse mesmo caminho, e é a instrução que as chamadas de
sistema vão usar na etapa seguinte.

**Preempção muda a regra das travas.** Um spinlock não é reentrante: um fio
preemptado segurando uma trava faz o próximo girar para sempre. Por isso todo
acesso a estado compartilhado neste kernel passa por `sem_interrupcoes`, que
desliga a preempção junto — `frames`, `machine`, `heap` e o próprio
escalonador.

## Userspace

Até a multitarefa preemptiva, todo código do kernel era igualmente poderoso:
qualquer função podia escrever em qualquer endereço. Ring 3 (x86) e EL0 (ARM)
mudam isso no hardware — o processo executa num modo em que instruções
privilegiadas não funcionam e só alcança as páginas marcadas como dele.

```
$ cargo xtask agent user.run
{"launched":true,"thread_id":7}

$ cargo xtask agent log.tail '{"count":3}'
... info  "usuario" "ola do anel 3"
... error "usuario" "diagnostico de userspace"
... info  "usuario" "processo encerrou com codigo 42"
```

As chamadas de sistema são quatro: `sair`, `escrever`, `id` e `ceder`.

O programa é um punhado de bytes de instrução copiados para uma página — não
um ELF. Um carregador de ELF é outra coisa difícil, e depurar duas de uma vez
é o jeito mais confiável de não entender nenhuma. Assim a travessia de
privilégio fica sozinha em cena: se algo falhar, foi ela.

**A proteção é testada, não presumida.** Existe um segundo programa que tenta
ler a memória do kernel. O caso `usuario: nao alcanca o kernel` exige duas
coisas ao mesmo tempo: que ele **não consiga** — se conseguisse, seguiria e
sairia com o código dele — e que a tentativa mate **só o processo**. A prova
da segunda é que o teste chega ao fim e reporta.

**`escrever` recebe um descritor, e não um destino fixo.** A assinatura é
`escrever(descritor, ptr, tamanho)`: 1 é a saída comum, 2 a de erro, e 0 fica
reservado para leitura — escrever nele é erro. Hoje os dois destinos abertos
vão para o log do kernel, em níveis diferentes, e é essa diferença que as duas
linhas acima mostram.

A indireção existe agora justamente porque ainda não é necessária. O destino
pode crescer depois sem quebrar ninguém — um arquivo, um socket, outro
processo. A *assinatura* não: acrescentar o argumento quando já houvesse
programas de usuário significaria quebrar todos eles.

**Todo argumento de chamada de sistema é hostil até prova em contrário.** Um
ponteiro vindo do usuário pode apontar para dentro do kernel; um comprimento
pode transbordar na soma. O kernel não desreferencia nada antes de conferir
que a faixa inteira está no espaço do usuário **e** mapeada — faixa por faixa,
página por página, com aritmética saturante.

O que ainda não existe é isolamento *entre* processos: eles compartilham o
espaço de endereços do kernel, e por isso só cabe um por vez. O que já existe
é a separação de **privilégio**. Uma tabela de tradução por processo é o passo
seguinte.

**"Um por vez" é imposto, não combinado.** Carregar um programa começa
desmapeando o que estiver no espaço do usuário, então dois hospedeiros
concorrentes arrancariam o chão um do outro — e o desfecho ruim não é o
processo morrer, é o primeiro estar dentro de uma chamada de sistema e ler a
memória do usuário depois de ela sumir, o que é uma falha de página com o
kernel no comando. O espaço pertence a um fio até esse fio morrer, e um
segundo `user.run` recebe a recusa na própria resposta.

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
  suite de testes :: aarch64 :: 57 casos
  ...
  excecao: breakpoint retomado               ok
  timer: relogio avanca                      ok
  tarefa: waker acorda bloqueada             ok
  57 de 57 passaram
```

O CI roda formatação, clippy nas cinco configurações, e a suíte nas duas
arquiteturas em debug e release.

## Depuração

Um kernel não pode ser depurado como um programa comum: não há processo para
anexar, e sanitizers, Miri e profilers dependem justamente do sistema
operacional que nós somos. O projeto resolve isso em duas frentes.

**De dentro**, o kernel se descreve — é o que o canal do agente existe para
fazer. `log.tail` diz o que aconteceu e em que ordem; `traps.stats` diz onde
ele morreu; e o modo post-mortem mantém o canal vivo depois de uma exceção
fatal. `debug.trigger` com `kind: "fatal"` provoca uma falha de propósito,
para exercitar esse caminho sem plantar um defeito no código.

**De fora**, pelo emulador. O QEMU implementa o protocolo de depuração remota
do GDB, o que dá breakpoint, passo a passo, pilha de chamadas e variáveis
locais em bare-metal, desde a primeira instrução — inclusive no trecho de boot
anterior à existência do canal.

```bash
$ cargo xtask agent traps.stats
{"result":{"last":{"name":"page_fault","pc":18446603336221253026,…}}}

$ cargo xtask simbolo 18446603336221253026
0xffff80000000dda2
  core::ptr::write_volatile::<u64>
      …/core/src/ptr/mod.rs:2269:9
  inlinado em kernel::arch::x86_64::disparar_falha_fatal
      kernel/src/arch/x86_64/mod.rs:337:14
```

Detalhes, e a lista honesta do que **não** funciona num kernel (Miri, ASan,
TSan, Tokio, `perf`) com o motivo de cada um, em [`docs/DEPURACAO.md`](docs/DEPURACAO.md).

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
- [x] **Fase 0 — Testes e CI.** A suíte roda em bare-metal nas duas
      arquiteturas, em debug e release, com formatação e lints no CI.
- [x] **Fase 0 — Memória física e paginação.** Alocador de frames por bitmap,
      MMU ligada do zero no ARM com mapa de identidade, controle das tabelas
      do bootloader no x86, e uma API de mapeamento comum às duas.
- [x] **Fase 0 — Heap.** Alocador próprio com lista livre ordenada e fusão de
      blocos adjacentes. `Box`, `Vec` e `String` disponíveis no kernel.
      **Fase 0 completa.**
- [x] **Fase 1 — Multitarefa cooperativa.** Executor com `async`/`await` e
      suporte real a wakers, serial do agente dirigida por interrupção nas
      duas arquiteturas, e um núcleo que dorme de verdade quando não há
      trabalho.
- [x] **Fase 1 — Scheduler preemptivo.** Fios de execução com pilha própria e
      guard page, troca de contexto nas duas arquiteturas, rodízio por quantum
      e preempção pelo timer.
- [x] **Fase 1 — Ring 3 e chamadas de sistema.** Processos em ring 3 e EL0,
      `syscall`/`sysret` e `svc`, páginas de usuário, validação de ponteiros e
      falha de processo que não derruba o kernel.
- [ ] **Fase 1 — Processos isolados.** Uma tabela de tradução por processo,
      carregador de ELF, `fork`/`exec`.
- [ ] **Fase 2 — Drivers.** Enumeração PCI, virtio-blk, virtio-net, timer
      APIC/HPET, framebuffer gráfico.

## Licença

MIT OU Apache-2.0, a critério de quem usa.
