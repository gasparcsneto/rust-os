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
  kernel, falando por uma porta serial dedicada. Toda linha que o kernel
  escreve nesse canal é um objeto JSON válido. Sem ruído, sem heurística —
  com uma ressalva que é da máquina, e não dele: no x86, antes de o kernel
  existir, o firmware escreve nas duas seriais. Um cliente reconhece a
  resposta pelo `id`, e não por ser a primeira linha.

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

- **Uma superfície, três portas.** O que uma pessoa digita no console é
  despachado pelo **mesmo** registro que o canal do agente publica, com os
  mesmos handlers — só muda a renderização. Um interpretador com comandos
  próprios seria uma segunda superfície a manter, e as duas divergiriam na
  primeira que alguém esquecesse de atualizar: uma pessoa e um agente vendo
  máquinas diferentes. É a mesma inversão que o log estruturado defende — o
  texto legível é uma renderização, não a fonte da verdade.

O canal existe desde o primeiro milissegundo do boot, antes de haver
paginação, heap ou interrupções. Essa precocidade é intencional: ele serve
para ajudar a construir e depurar as camadas que vêm depois dele.

Hoje ele é uma **tarefa assíncrona**: a UART interrompe quando chega um byte,
o handler só move os bytes para uma fila e aciona o waker, e todo o trabalho
de verdade acontece fora dele. Entre uma requisição e outra o núcleo fica
parado — não em espera ativa, nem acordando a cada 10 ms para conferir.

No ARM isso deixa de ser conveniência e vira necessidade. A máquina `virt` do
emulador tem **uma única** porta serial, e ela é do canal do agente: não sobra
uma segunda para ecoar log em texto, como o x86 tem. Por um bom tempo o canal
foi literalmente a única interface do sistema ali, e os registros só saíam por
`log.tail`.

Hoje sai também na tela. O kernel desenha nela o mesmo texto que manda ao
console humano — na tela que o firmware deixou configurada, quando o boot é
pela UEFI, ou num adaptador que ele próprio programa, quando é pela imagem
crua do ARM. Uma pessoa sentada na frente da máquina tem a mesma leitura nas
duas arquiteturas, sem depender de um terminal no hospedeiro.

O port para ARM foi o teste mais duro dessa premissa, e ela passou: o primeiro
bug do boot ARM (`x0` chegando nulo, sem device tree) foi diagnosticado pelo
próprio canal, lendo `log.tail`.

## Começando

Requisitos: Rust nightly (instalado automaticamente pelo `rust-toolchain.toml`)
e os pacotes do emulador para as arquiteturas desejadas.

```bash
# x86_64 (padrão): compila e põe o iniciador e o kernel na ESP do disco
cargo xtask build
cargo xtask run

# aarch64: compila e gera a imagem arm64 crua (a suíte e o `run` sobem por
# ela; o boot pela UEFI no ARM é o que `cargo xtask iniciador` exercita)
cargo xtask build --arch aarch64
cargo xtask run   --arch aarch64

# Suíte de testes, dentro do emulador
cargo xtask test
cargo xtask test --arch aarch64

# A máquina que só tem virtio-gpu, sem tela linear nenhuma
cargo xtask run  --video virtio
cargo xtask test --arch aarch64 --video virtio

# Depuração
cargo xtask debug                    # sobe congelado, esperando gdb/lldb
cargo xtask simbolo 0xffff8000...    # endereço -> arquivo, linha e função
cargo xtask asm consumir_pilha       # o que o otimizador realmente gerou
cargo xtask elf                      # confere os ELFs de usuário por fora
cargo xtask invariantes              # regras de fonte: SAFETY, parâmetros do agente, README
```

Com o kernel rodando, converse com ele de outro terminal:

```bash
$ cargo xtask agent system.info
{"jsonrpc":"2.0","id":1,"result":{"arch":"x86_64","kernel":"duke",
 "version":"0.1.0","phase":"5","cpu_vendor":"AuthenticAMD",
 "framebuffer":{"width":1280,"height":800,"stride":1280,
 "bytes_per_pixel":4,"pixel_format":"bgr"},"uptime_ms":1160,...}}

$ cargo xtask agent log.tail '{"count":3,"min_level":"info"}'
$ cargo xtask agent memory.regions '{"limit":2,"usable_only":true}'

# Descobre todos os comandos disponíveis e seus parâmetros
$ cargo xtask agent agent.describe

# O mesmo protocolo, no kernel ARM
$ cargo xtask agent --arch aarch64 system.info
{"jsonrpc":"2.0","id":1,"result":{"arch":"aarch64","kernel":"duke",
 "version":"0.1.0","phase":"5","cpu_vendor":"ARM Limited",
 "framebuffer":{"width":1280,"height":720,"stride":1280,
 "bytes_per_pixel":4,"pixel_format":"bgr"},"uptime_ms":1730,...}}
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
| `user.run` | Lança um programa no anel sem privilégio (`path`; padrão: o exemplo) |
| `user.stats` | Chamadas atendidas e recusadas, arquivos abertos e lidos, último código de saída |
| `tasks.list` | Tarefas lançadas, com id, nome e se estão vivas |
| `irq.stats` | Contadores de interrupções de hardware por linha |
| `traps.stats` | Contadores de exceções e detalhes da última falha |
| `debug.trigger` | Dispara uma exceção de propósito (`kind`: `breakpoint` ou `fatal`) |
| `pci.list` | Dispositivos do barramento PCI, com fabricante, modelo e função |
| `disk.info` | Capacidade e estado do disco virtio, se houver um |
| `disk.read` | Lê um setor de 512 bytes e o devolve em hexadecimal (`sector`, `length`) |
| `disk.partitions` | A tabela de partições do disco, lida da GPT |
| `btrfs.info` | O superbloco do Btrfs da partição de dados |
| `btrfs.chunks` | O mapa de pedaços e a raiz da árvore de pedaços |
| `fs.mounts` | O que está montado na árvore de arquivos, e de que tipo |
| `fs.list` | Lista um diretório da árvore (`path`) |
| `fs.read` | Lê um arquivo da árvore e devolve o conteúdo (`path`, `offset`, `max`) |
| `net.info` | Endereço e contadores da placa de rede, se houver uma |
| `net.arp` | Pergunta quem atende por um IPv4 e espera a resposta (`ip`, `from`) |
| `video.sample` | Amostra a tela numa grade de cores (`columns`, `rows`) |
| `display.info` | A pilha gráfica: adaptador ativo, telas, as camadas do compositor, memória das superfícies, o último retângulo que chegou à tela e, no virtio-gpu, o que atravessou para o dispositivo |
| `ui.tree` | A árvore semântica do que está na tela: papel, rótulo, valor, moldura e ações de cada elemento |
| `ui.act` | Age sobre um elemento pelo mesmo caminho de quem está na frente da máquina (`id`, `action`, `value`) |
| `keyboard.read` | O que foi digitado no teclado da máquina, e os contadores dele (`max`) |
| `log.tail` | Registros de log estruturados (`count`, `min_level`) |

Esta tabela é escrita à mão e **conferida** contra o registro que o kernel usa
para validar chamadas: `cargo xtask invariantes` reprova a diferença nas duas
direções. Dizia-se aqui que ela era gerada e que refletia sempre a verdade —
seis comandos tinham entrado no kernel sem passar por ela. A verdade continua
sendo `agent.describe`, que é gerado de fato; esta tabela é uma cópia que
agora não pode divergir em silêncio.

## Arquitetura

```
kernel/src/
├── main.rs          fluxo de boot comum às duas arquiteturas
├── machine.rs       descrição da máquina, neutra de arquitetura
├── serial.rs        papéis de console e canal do agente
├── log.rs           logging estruturado em ring buffer
├── frames.rs        alocador de frames de memória física (bitmap)
├── paginacao.rs     fachada segura de mapeamento
├── mmio.rs          como o kernel alcança a memória de um dispositivo
├── heap.rs          alocador do kernel: lista livre ordenada com fusão
├── interpretador.rs operar o Duke digitando
├── barra.rs         a barra superior: o nome, o primeiro botão e o tempo ligado
├── ponteiro.rs      o mouse: onde ele está, o cursor, e o clique
├── eventos.rs       canais de eventos: o kernel publica, um processo escuta e dorme
├── ui.rs            a árvore semântica: o que está na tela, e o que se faz com cada coisa
├── teclado.rs       o que uma pessoa digita chega ao kernel
├── pci.rs           enumeração do barramento PCI
├── particoes.rs     a tabela de partições GPT do disco
├── rede.rs          o mínimo de protocolo acima do transporte de quadros
├── traps.rs         contabilidade de exceções e modo post-mortem
├── irq.rs           contadores de interrupções de hardware
├── tempo.rs         contagem de tempo desde o boot
├── qemu.rs          encerramento do emulador para testes
├── testes.rs        suíte de testes que roda dentro do emulador
├── tela/
│   ├── mod.rs       o framebuffer: desenhar na tela
│   ├── bochs.rs     o adaptador de vídeo do QEMU, programado do zero
│   └── console.rs   o console de texto: o que uma pessoa lê na tela
├── grafico/         a pilha gráfica, no desenho do Redox
│   ├── mod.rs       o trait de adaptador e o que o agente enxerga dele
│   ├── compositor.rs  as camadas, e a tela que elas deixam ver
│   ├── dano.rs      o retângulo que mudou, com o recorte que não dá a volta
│   ├── linear.rs    buffer de fundo sobre um framebuffer (porte do vesad)
│   ├── virtio.rs    a superfície que é um recurso do virtio-gpu
│   └── memoria.rs   as páginas de uma superfície, fora do heap
├── fios/
│   ├── mod.rs       escalonador preemptivo: fios, rodízio e quantum
│   └── pilha.rs     pilhas de fio, cada uma com sua guard page
├── usuario/
│   ├── mod.rs       ABI das chamadas de sistema e validação de ponteiros
│   ├── elf.rs       leitor de ELF64: o formato em que um programa chega
│   ├── programa.rs  mapeia o processo e desce de privilégio
│   ├── descritores.rs  a tabela de descritores de um processo
│   └── exemplo.rs   seis programas mínimos, em assembly
├── tarefas/
│   ├── mod.rs       tarefa, identidade e o `yield` explícito
│   ├── executor.rs  escalonador cooperativo com suporte a wakers
│   ├── fila.rs      fila de capacidade fixa, escrita de dentro de handlers
│   ├── relogio.rs   o futuro que espera o tempo passar
│   └── entrada.rs   bytes do canal do agente, entregues por interrupção
├── vfs/
│   ├── mod.rs       um nome de caminho, muitos sistemas de arquivos
│   ├── programas.rs os programas embutidos, vistos como sistema de arquivos
│   └── btrfs/
│       ├── mod.rs      Btrfs, somente leitura
│       ├── pedacos.rs  endereço lógico para deslocamento no disco
│       ├── arvore.rs   inodes, diretórios e extensões
│       ├── interno.rs  os ponteiros de um nó interno, e por onde descer
│       ├── folha.rs    os itens de uma folha
│       └── crc32c.rs   a soma de verificação que o Btrfs usa por padrão
├── virtio/
│   ├── mod.rs       dispositivos virtio
│   ├── transporte.rs  achar os registradores de um dispositivo, e ligá-lo
│   ├── fila.rs      a virtqueue split: o canal por onde os pedidos passam
│   ├── blk.rs       o disco
│   ├── net.rs       a placa de rede
│   ├── gpu.rs       o vídeo que só mostra o que se manda (porte do virtio-gpud)
│   └── teclado.rs   o teclado e o tablet do ARM, por virtio
├── usb/
│   ├── mod.rs       o barramento por onde entram os periféricos de verdade
│   ├── xhci.rs      o controlador xHCI: a porta de entrada do USB
│   └── hid.rs       os relatórios de um teclado e de um mouse USB, traduzidos
├── agent/
│   ├── mod.rs       laço de atendimento e despacho
│   ├── json.rs      JSON sem alocação (streaming + varredura)
│   ├── protocol.rs  envelope JSON-RPC 2.0
│   ├── registry.rs  registro de comandos auto-descritivo
│   └── commands.rs  implementações dos comandos
└── arch/
    ├── mod.rs        seleção da arquitetura em tempo de compilação
    ├── x86_64/
    │   ├── mod.rs    entrada pelo iniciador UEFI, CPUID, portas de I/O
    │   ├── gdt.rs    GDT, TSS e pilha dedicada ao double fault
    │   ├── idt.rs    IDT e handlers de exceção e interrupção
    │   ├── mouse.rs  o mouse PS/2, pela porta auxiliar do 8042
    │   ├── pic.rs    controlador 8259 e timer PIT
    │   ├── apic.rs   o APIC local: o timer por núcleo do x86 moderno
    │   ├── paginacao.rs  assume as tabelas de página do iniciador
    │   ├── contexto.rs   troca de contexto
    │   ├── usuario.rs    entrada em ring 3 e chamadas de sistema
    │   ├── pci.rs    acesso ao espaço de configuração PCI
    │   └── uart.rs   UART 16550 por port-mapped I/O
    └── aarch64/
        ├── mod.rs      boot em assembly, cabeçalho de imagem arm64, MIDR_EL1
        ├── vetores.rs  tabela de vetores de exceção (VBAR_EL1)
        ├── gic.rs      GIC v2 e timer genérico do ARM
        ├── mmu.rs      tabelas de tradução e ativação da MMU
        ├── contexto.rs troca de contexto
        ├── usuario.rs  entrada em EL0 e chamadas de sistema
        ├── pci.rs      acesso ao espaço de configuração PCI
        ├── uart.rs     PL011 por memory-mapped I/O
        ├── fdt.rs      leitor de device tree escrito à mão
        └── linker.ld   layout de memória e símbolos de boot

iniciador/src/       a aplicação UEFI que o firmware carrega da ESP
├── main.rs          confere as tabelas da UEFI, abre o kernel e relata
├── efi.rs           as tabelas e os protocolos, declarados à mão
├── elf.rs           o pedaço do ELF64 que um carregador precisa entender
├── carga.rs         copia os segmentos, reloca e desenha o mapa
├── paginas.rs       as quatro tabelas de tradução, e como percorrê-las
├── salto.rs         a saída dos serviços de boot, e a entrega da máquina
├── crc32.rs         o CRC-32 que a UEFI usa nos cabeçalhos das tabelas
├── fdt.rs           o mínimo de device tree para conferir um endereço
└── alvo/
    ├── mod.rs       o que muda de uma arquitetura para a outra
    ├── x86_64.rs    o que o Duke precisa saber sobre o x86_64
    └── aarch64.rs   o que o Duke precisa saber sobre o aarch64

protocolo/src/       as ABIs: do iniciador com o kernel, e do kernel com os programas
├── lib.rs           o que é entregue ao kernel, com mágica e versão
├── mapa.rs          onde cada coisa mora no espaço virtual
└── usuario.rs       as chamadas de sistema, os erros e o mapa do espaço do usuário

programas/           os programas de usuário, compilados à parte do kernel
├── usuario.ld       o mapa de um programa: três segmentos a partir de BASE
└── src/
    ├── lib.rs       o runtime: a entrada, o pânico e o contrato do `principal`
    ├── sistema.rs   as chamadas de sistema, uma função por chamada
    ├── monte.rs     o monte do processo, sobre `mapear`
    ├── saida.rs     uma linha formatada por chamada de `escrever`
    └── bin/
        ├── ola.rs        o primeiro programa em Rust: monte, formatação e pilha
        ├── memoria.rs    confere `mapear` e o monte do lado de quem pede
        ├── ponteiros.rs  pede ao kernel que escreva no código, e confere a recusa
        └── eco.rs        escuta um canal de eventos e diz o que chega

xtask/src/
└── main.rs          a ferramenta de build, teste e diagnóstico do projeto
```

**Como as duas arquiteturas convivem.** Cada backend em `arch/` traduz o que
recebeu do firmware para as estruturas neutras de `machine.rs` durante o boot.
Daí para baixo, nenhuma linha do kernel sabe em que processador está rodando —
é por isso que a mesma resposta JSON sai dos dois.

O contraste no caminho de boot é grande:

| | x86_64 | aarch64 |
|---|---|---|
| Carga | `iniciador/`, aplicação UEFI deste projeto | protocolo de imagem crua do arm64, ou o mesmo `iniciador/` |
| Artefato | imagem de disco, com o iniciador e o kernel na ESP | binário cru, cabeçalho de 64 bytes; o ELF na ESP pelo iniciador |
| Chegamos em | long mode, com pilha e paginação | MMU desligada, sem pilha |
| Mapa de memória | regiões do firmware, na `Entrega` do iniciador | device tree, parseado por nós; ou a `Entrega` |
| Seriais | duas UARTs 16550 (port I/O) | uma PL011 (MMIO) |
| Exceções | IDT de ponteiros, contexto salvo pela CPU | vetores de código, contexto salvo à mão |
| Pilha de exceção | IST, índice no TSS | `SP_EL1`, trocado por hardware |
| Guard page da pilha | instalada pelo iniciador | construída antes de ligar a MMU |
| Interrupções | PIC 8259; timer do APIC local, calibrado contra o PIT | GIC v2 + timer genérico |
| Serial do agente | UART 16550 na IRQ 3 | PL011 no INTID 33 (SPI 1) |
| Vídeo | modo posto pelo firmware e mapeado pelo iniciador | `bochs-display` no PCI, modo posto por nós; `ramfb` do firmware pela UEFI |
| Vídeo sem tela linear | `virtio-gpu` no PCI, recurso e varredura postos por nós | o mesmo dispositivo, o mesmo driver |
| Teclado | controlador 8042, scancode na IRQ 1 | `virtio-input` no PCI, evento na fila |
| Teclado USB | `qemu-xhci` no PCI, protocolo de boot do HID | o mesmo controlador, o mesmo driver |
| Mouse | PS/2, pela porta auxiliar do 8042, na IRQ 12 | `virtio-tablet` no PCI, posição absoluta |
| Mouse USB | o mesmo controlador do teclado USB, protocolo de boot | o mesmo controlador, o mesmo driver |
| Dormir sem corrida | `sti; hlt`, par atômico | `wfi` acorda com IRQ mascarada |
| Troca de contexto | troca de pilha (`rsp`) | troca do quadro de exceção |
| Ceder a vez | chamada de função comum | `svc`, pelo mesmo caminho da preempção |
| Sem privilégio | ring 3 | EL0 |
| Chamada de sistema | `syscall`/`sysret` | `svc`, na tabela de vetores |
| Pilha na entrada | trocada à mão (`syscall` não troca) | `SP_EL1`, trocada pelo hardware |
| MMU | já ligada pelo firmware; o iniciador troca as tabelas | desligada; nós a acendemos |
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
| x86_64 | GDT, TSS, IDT, tabelas de página, portas de I/O (`x86_64`); UART (`uart_16550`) | PIC 8259, timer PIT e o **boot inteiro**, do firmware ao salto |
| aarch64 | registradores de sistema (`aarch64-cpu`); blocos de MMIO (`tock-registers`) | boot, tabela de vetores, descritores de página, leitor de device tree |
| comuns | enumeração PCI (`pci_types`); glifos já rasterizados (`noto-sans-mono-bitmap`) | adaptador de vídeo, console de texto, drivers virtio, controlador xHCI e teclado HID |

A fonte é a única entrada da coluna esquerda que não entra pelo critério
acima — um glifo errado aparece na tela, não fica calado. Ela vem de crate por
outra razão: é massa de dados, e rasterizar uma fonte vetorial em tempo de
execução exigiria ponto flutuante, que o alvo `aarch64-unknown-none-softfloat`
não tem.

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
| Registradores de dispositivo | `0xFFFF_8400_0000_0000` | 192 GiB |
| Superfícies gráficas | `0xFFFF_A800_0000_0000` | 256 GiB |
| Espaço do usuário | 4 GiB | 4 GiB |

No x86 a regra é a clássica — metade alta para o kernel, metade baixa para o
usuário. Estes endereços são escolha nossa, e ficam num pacote que o kernel e
o iniciador incluem; quando quem escolhia era o crate `bootloader`, a memória
física caía em 2 TiB, dentro da metade que hoje é do usuário. Fixá-los tem o
mesmo benefício que fixar a base do kernel teve para a simbolização.

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
preemptivo com fios, que convive com ele e está descrito a seguir.

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

As chamadas de sistema são doze: `sair`, `escrever`, `id`, `ceder`,
`bifurcar`, `executar`, `abrir`, `ler`, `fechar`, `esperar`, `mapear` e
`escutar`. Os
números, os erros e o mapa do espaço do usuário moram em
`protocolo::usuario`, que o kernel e os programas incluem — uma declaração
só, pelo motivo de sempre: duas iguais são duas que podem divergir, e um
número trocado não dá erro de compilação, dá um programa que pede para ler e
escreve.

**O programa é um ELF64.** O cabeçalho diz onde a execução começa; cada
segmento diz onde quer morar, quanto traz do arquivo, quanto ocupa na memória
e com que permissões. Nada disso é confiado: cada campo é conferido antes de
virar decisão, cada soma é testada contra transbordo, e um arquivo malformado
devolve erro — nunca pânico, que num kernel é terminal.

O carregador mapeia todo segmento como gravável, copia o conteúdo, zera o que
sobra (a `.bss`) e **só então** aplica as permissões pedidas. Em nenhum
instante existe uma página que o usuário possa escrever *e* executar.
Segmentos que dividiriam uma página são recusados: permissão é propriedade da
página, e a única negociação possível seria conceder a união — que é
exatamente como se perde o `W^X`.

O ELF de exemplo é montado no mesmo bloco de assembly que contém o programa,
sem um segundo alvo de build. O arranjo tem uma fraqueza óbvia — quem escreve
o cabeçalho e quem o lê são a mesma pessoa —, e por isso `cargo xtask elf`
extrai as imagens do binário e as entrega ao `llvm-readobj`, que não tem nada
a ver com este projeto.

O programa usa endereços **absolutos** para alcançar a mensagem, e lê a
própria `.bss` antes de sair. As duas coisas são propositais: só funcionam se
o carregador tiver honrado `e_entry`, `p_vaddr` e a diferença entre `p_filesz`
e `p_memsz`. Se a `.bss` chegar com lixo, o processo sai com outro código e o
teste acusa.

**Programas em Rust, compilados à parte.** Os programas acima são montados
à mão, em assembly, dentro do kernel. O pacote `programas` é o passo que o
próprio carregador anunciava como o natural seguinte: um workspace próprio,
com um runtime mínimo — a entrada que alinha a pilha e chama o `principal`
do programa, as chamadas de sistema, um monte e a saída formatada — e um
programa por arquivo em `src/bin`.

```
... info  usuario  ola do Rust, no anel sem privilegio
... info  usuario  10000 quadrados, o ultimo 99980001
... info  usuario  processo encerrou com codigo 61
```

O `xtask` compila os dois alvos em release e põe os executáveis no disco, em
`/programas/x86_64` e `/programas/aarch64` — o disco de testes é um só para as
duas máquinas, e cada kernel procura no diretório da sua. A receita do disco
os resume pelo conteúdo inteiro, e não pelo tamanho: um executável
recompilado muda bytes sem mudar de tamanho.

Três coisas o carregador exige, e um compilador não entrega sem pedir: um
executável de **endereço fixo** (o carregador não faz relocação), que more
acima dos 4 GiB, e com um segmento por permissão em páginas separadas. No ARM
basta o modelo de código padrão; no x86 o `core` pré-compilado usa o modelo
do kernel, e o que funciona é manter o código independente de posição — que
endereça tudo relativo ao `rip` — e pedir ao ligador `--no-pie`. O script de
ligação repete o endereço de `protocolo::usuario::BASE`, porque um script
não inclui Rust; `cargo xtask elf` lê cada executável pronto com o
`llvm-readobj` e confere, contra as constantes do próprio `protocolo`, o
tipo, a entrada, os segmentos, o `W^X` e a ausência de relocações.

**`mapear`, e o monte do processo.** `mapear(endereco, tamanho)` dá memória
nova, zerada, gravável e não executável, numa faixa que o **processo**
escolhe dentro da região mapeável — como um `mmap` com endereço fixo. A
alternativa, o kernel guardar onde o monte termina como um `brk`, pediria
estado novo por processo, copiado no `fork` e zerado no `exec`. Com o
endereço vindo do processo, esse estado mora na memória dele: o `fork` o
copia e o `exec` o joga fora junto com o resto. O kernel confere a faixa
inteira antes de mapear a primeira página, e desfaz o que já tinha feito se
faltar memória no meio — tudo ou nada. Uma faixa já mapeada é recusada com
um erro próprio, e não sobrescrita.

O monte do runtime é o desenho do heap do kernel — lista livre ordenada por
endereço, com fusão — sobre páginas pedidas a `mapear` de 64 KiB em 64 KiB. E
a pilha de um processo passou de uma página para dezesseis: um programa
compilado passa de 4 KiB de pilha sem que ninguém perceba, e o que se
perceberia seria a página de guarda.

**Um vazamento que os programas do disco trouxeram.** Lançar um programa do
disco lê a imagem num `Vec` do heap do kernel, e `executar` não volta — o
`Vec` nunca era largado. Com os programas embutidos não aparecia, porque a
imagem é estática; com os do disco, cada lançamento custaria uns 20 KiB de um
heap de 1 MiB. Carregar e entrar em userspace viraram dois passos, e a imagem
é largada entre eles. O caso da suíte lança o `ola` cinco vezes e confere que
o heap cresce menos que uma imagem.

Catorze mutações nesta base, catorze reprovadas. Duas — tirar a fusão do
monte com o vizinho de cima, ou com o de baixo — só depois de o `memoria`
passar a liberar blocos fora de ordem e contar a lista livre: a rotação que
ele fazia reaproveitava sempre os mesmos blocos, e nenhuma fusão acontecia. E
uma, a pilha de volta a uma página, era reprovada pelo motivo errado — um
estouro de tempo, porque a espera do caso contava saídas e um processo morto
não sai; agora o caso diz que o programa morreu.

**Canais de eventos, e a leitura que dorme.** Por onde o servidor de janelas
vai saber do mundo — o ponteiro andou, uma tecla chegou, alguém pediu uma
ação pela árvore semântica. Um processo chama `escutar("nome")` e recebe um
descritor; `ler` nele entrega eventos inteiros, de 32 bytes cada — o tipo e
três campos, little-endian, escritos campo a campo pelo `protocolo` e não pela
memória de uma `struct` —, e **bloqueia** enquanto a fila está vazia. O kernel
publica pelo nome, e publicar acorda o ouvinte.

Bloquear reaproveita o mecanismo que o `esperar` já tinha: a chamada que não
tem o que entregar estaciona o fio sem efeito nenhum, e o backend de
arquitetura a reexecuta quando ele acorda — em laço no x86, recuando o
`ELR_EL1` no ARM. O canal marca que o ouvinte espera com a própria tranca na
mão, e quem publica toma a mesma tranca: não há janela entre "está vazio" e
"vou dormir" em que um evento se perca.

O que não cabe na fila, de sessenta e quatro, é **recusado** e contado — e
não o mais antigo jogado fora: assim o que o ouvinte recebe é sempre um
prefixo do que foi publicado. Um canal tem um ouvinte só; um filho de `fork`
herda o descritor, não o canal, e é recusado se ler. E um ouvinte que morre
sem fechar o descritor não deixa o nome preso: o canal guarda o fio do
ouvinte, e quem o procura confere se ele vive.

O programa `eco` é o outro lado do caso da suíte: com a fila vazia, a conta
de chamadas de sistema para — ele dorme, não gira; cinco eventos chegam em
ordem; setenta publicados com ele impedido de rodar enchem a fila e seis são
recusados; e a soma no fim confere quais sessenta e quatro chegaram.

**Mapeada não é gravável.** Duas chamadas escrevem num buffer que o processo
dá — `ler` e `esperar` —, e o kernel conferia só se a faixa era do processo e
estava mapeada. Uma página de código é das duas coisas, e é só de leitura: o
kernel escrevia nela pelo anel zero, a proteção de escrita do processador
recusava, e a falha era **do kernel** — fatal. Qualquer processo derrubava a
máquina com um `ler` para o endereço de uma função. O programa `ponteiros`
reproduziu (`FALHA FATAL #1: page_fault`, com o endereço acusado dentro do
código dele); agora as duas chamadas conferem, página a página, que o
processo pode escrever ali, e ele confere que o kernel recusa com
`ENDERECO_INVALIDO` e continua de pé. Uma página de cópia na escrita conta
como gravável, e é de propósito: o processo pode escrever nela, e a escrita
do kernel é resolvida como a dele seria. Três mutações, três reprovadas:
tirar a conferência do `ler` ou do `esperar` devolve a falha fatal, e deixar
de contar a marca de cópia na escrita reprova quatro casos de `fork` que
escrevem o desfecho numa página marcada.

**A proteção é testada, não presumida.** Existe um segundo programa que tenta
ler a memória do kernel. O caso `usuario: nao alcanca o kernel` exige duas
coisas ao mesmo tempo: que ele **não consiga** — se conseguisse, seguiria e
sairia com o código dele — e que a tentativa mate **só o processo**. A prova
da segunda é que o teste chega ao fim e reporta.

**`escrever` recebe um descritor, e não um destino fixo.** A assinatura é
`escrever(descritor, ptr, tamanho)`: 1 é a saída comum, 2 a de erro, e 0 fica
reservado para leitura — escrever nele é erro.

A indireção entrou antes de ser necessária, e o que ela protegia era a
*assinatura*: acrescentar o argumento depois de haver programas de usuário
significaria quebrar todos eles. Agora ela tem para onde apontar.

**A tabela de descritores é do processo.** `abrir(caminho)` resolve um nome
pelo VFS, guarda o vnode na tabela **daquele processo** e devolve um número;
`ler(descritor, ptr, tamanho)` traz os próximos bytes e avança a posição;
`fechar(descritor)` devolve a vaga.

O descritor é um número pequeno, e isso é de segurança antes de ser de
conveniência: o processo não recebe ponteiro nenhum, não sabe em que sistema
de arquivos o arquivo mora, e não tem como forjar um descritor para algo que
não abriu. Uma tabela **global** faria o contrário — dois processos abrindo
arquivos diferentes receberiam números diferentes, e o segundo leria o do
primeiro se adivinhasse o número dele.

A tabela mora dentro do `Fio`, e as duas propriedades que importam saem daí
sem uma linha para mantê-las: ela morre junto com o processo, e `bifurcar` a
herda porque duplica o fio. A alternativa — uma tabela à parte, indexada pelo
identificador — precisaria de uma remoção no caminho de saída e de outra no
caminho em que o processo morre por falha de página, que é justamente a que
ninguém lembra de escrever.

**O que ela não tem:** compartilhamento. Num Unix de verdade, pai e filho
apontam para a **mesma** descrição de arquivo aberto, e ler num avança a
posição do outro. Aqui cada um leva a própria cópia, que é o comportamento de
quem abriu o arquivo duas vezes. A diferença é observável, e está escrita no
código em vez de ser descoberta.

**O programa que prova tudo isso é o `leitor`**, em `/bin`, escrito no mesmo
assembly dos outros. Ele abre `/saudacao.txt` — um arquivo que só existe na
imagem Btrfs do disco —, bifurca, e os dois lados leem pelo mesmo número. O
pai escreve o que leu na saída, e é assim que o conteúdo do disco aparece no
log, posto lá por um processo sem privilégio:

```
$ cargo xtask agent user.run '{"path":"/bin/leitor"}'
{"program":"/bin/leitor","launched":true,"thread_id":2}

$ cargo xtask agent log.tail '{"count":4}'
... info  "usuario" "processo encerrou com codigo 34"      <- o filho
... info  "usuario" "ola do btrfs, lido pelo duke"
... info  "usuario" "processo encerrou com codigo 33"      <- o pai

$ cargo xtask agent user.stats
{"syscalls":12,"forks":1,"exits":2,"rejected":4,
 "opens":1,"reads":2,"bytes_read":58,"last_exit":33,...}
```

Os quatro `rejected` são as quatro recusas que o programa **exigiu**; os 58
bytes lidos são o arquivo inteiro duas vezes, uma por lado da bifurcação.

E ele **confere o kernel de dentro**, saindo com um código de falha se alguma
resposta não fizer sentido: se abrir um diretório não for recusado com o
motivo certo, se escrever num descritor de arquivo for aceito, se ler num
descritor de saída for aceito — ou se a leitura depois do `fechar` der certo,
que é o que denunciaria um `fechar` que não fecha. Cada uma dessas linhas
existe porque a mutação correspondente passava sem ela.

**Todo argumento de chamada de sistema é hostil até prova em contrário.** Um
ponteiro vindo do usuário pode apontar para dentro do kernel; um comprimento
pode transbordar na soma. O kernel não desreferencia nada antes de conferir
que a faixa inteira está no espaço do usuário **e** mapeada — faixa por faixa,
página por página, com aritmética saturante.

**Um processo cria outro.** `bifurcar` duplica o processo: o filho enxerga o
mesmo espaço de endereços e acorda retornando `0` de uma chamada que nunca
fez, enquanto o pai recebe o identificador dele. `executar` troca a imagem do
processo pela que o nome indicar, e não retorna para quem chamou: retorna
para o primeiro endereço do programa novo.

```
$ cargo xtask agent user.run && cargo xtask agent user.stats
{"syscalls":7,"forks":1,"execs":1,"exits":2,...}

$ cargo xtask agent log.tail '{"count":6}'
... info  "usuario" "ola do anel 3"
... error "usuario" "diagnostico de userspace"
... info  "usuario" "processo encerrou com codigo 42"      <- o pai
... info  "usuario" "processo trocou de imagem para `filho`"
... info  "usuario" "filho por exec"
... info  "usuario" "processo encerrou com codigo 24"      <- o filho
```

### O `fork` não copia página nenhuma

Bifurcar não duplica a memória: os dois espaços passam a apontar para os
mesmos frames. Toda página que o processo enxerga como gravável sai de
gravável **nos dois lados** e ganha uma marca num bit que o processador
ignora — o 9 do descritor no x86, o 55 no ARM, os dois reservados pela
arquitetura para o sistema operacional. O frame passa a ter dois donos.

A primeira escrita, de qualquer um dos lados, vira falha de página. O
tratador reconhece a marca, tira uma cópia particular do frame para quem
escreveu, devolve a escrita e **retoma a instrução**. O processo não percebe
nada além do tempo que isso levou.

São três peças, e esquecer qualquer uma produz um desfecho diferente e
igualmente ruim:

- sem contar os donos, o primeiro dos dois a morrer devolve ao alocador
  memória que o outro ainda usa;
- sem tirar a escrita do filho, ele escreve direto no frame do pai;
- **sem tirar a escrita do pai**, é o pai que escreve no frame do filho — e
  este é o lado que se esquece, porque o pai é quem está rodando e tudo
  parece funcionar até ele encostar na própria memória.

```
$ cargo xtask agent memory.frames        # depois de quatro user.run
{"frame_size":4096,"base":0,"tracked":26956,"free":24043,"used":2913,
 "free_bytes":98480128,
 "copy_on_write":{"shared_frames":0,"pages_shared":12,
                  "faults_resolved":0,"copies":0}}
```

Quatro bifurcações, doze páginas compartilhadas, **nenhuma cópia**. E
`faults_resolved` em zero não é o contador quebrado: o programa de exemplo
bifurca e o filho troca de imagem em seguida, então ninguém chega a escrever
numa página marcada. `shared_frames` volta a zero porque o `exec` larga o
espaço herdado e o pai fica dono sozinho de tudo de novo.

É o caminho comum de quase todo programa, e é exatamente onde a cópia
integral era mais cara: ela copiava o espaço inteiro para jogá-lo fora um
instante depois. A diferença entre `faults_resolved` e `copies` mede a outra
metade da economia — quando o frame tem um dono só, resolver a marca é
devolver a escrita e nada mais, sem alocar nem preencher frame nenhum.

Quem exercita a separação de verdade é a suíte, que escreve dos dois lados e
confere palavra por palavra — ver [Testes](#testes).

**O bit que não vinha de lugar nenhum.** No x86 o `WRITE_PROTECT` do `CR0`
manda o processador respeitar o bit de escrita das páginas **também no anel
zero**. Com ele desligado — que é o padrão da arquitetura — a marca protege o
processo e não protege o kernel: a chamada `ler` entrega os bytes escrevendo
no buffer do usuário, do anel zero, e numa página recém-bifurcada essa
escrita atravessaria a proteção sem falha nenhuma, aparecendo na memória do
**outro** processo. O firmware desta máquina já o deixa ligado; o kernel o
liga de novo, porque herdá-lo é depender de um firmware específico. No ARM
não há equivalente: `AP[2]` vale para EL1 do mesmo jeito que para EL0.

Pela mesma razão, o tratador de falha resolve a marca **sem perguntar de que
anel veio a escrita**. Tratar só o caso do usuário deixaria a máquina inteira
cair por causa de um programa que apenas bifurcou e leu um arquivo. Medido:
acrescentando a condição do anel, quatro casos morrem e o kernel vai a falha
fatal.

As permissões atravessam a bifurcação. Recriar tudo gravável seria mais
simples e faria o `W^X` do processo desaparecer no instante em que ele
tivesse um filho — e uma página somente leitura de verdade é compartilhada
**sem** marca, para que escrever nela continue sendo o erro que sempre foi.
A função que põe a marca recusa uma página somente leitura por isso: a
resolução devolve a escrita, e marcar código por engano abriria o buraco em
vez de fechá-lo.

O caso que só aparece na segunda geração é o neto. Depois do primeiro `fork`,
as páginas do filho estão marcadas e sem o bit de escrita; bifurcá-lo de novo
lendo só o descritor daria ao neto os dados como somente leitura, e ele
morreria na primeira escrita — longe do `fork` que causou. Quem responde "o
processo enxerga isto como gravável?" soma as duas coisas, o bit e a marca.

O nome que `exec` recebe é procurado no VFS: sem barra, em `/bin`; absoluto,
como veio. É a promessa que este README fazia quando a busca ainda era numa
tabela estática — *"o que muda é onde a busca acontece; a chamada de sistema
continua a mesma"* —, e ela foi cumprida sem que `executar` mudasse de forma.

**Quem recolhe o espaço de um processo morto.** Um fio coletor, criado junto
com o escalonador. O espaço sempre morreu no `Drop` do fio que o hospeda, mas
por muito tempo esse `Drop` só acontecia quando **outra** criação escolhia a
vaga do morto: num kernel que roda um processo de cada vez isso quase não
aparece, e num que bifurca a tabela fica com até dezesseis espaços retidos
sem nenhum dono vivo. O sintoma não é uma falha — é memória que some.

O escalonador não pode recolher sozinho: largar um espaço desmapeia páginas,
ou seja, toma as travas da paginação e do alocador de frames, e ele faria
isso com a trava dele na mão. O coletor tira **um** fio da tabela sob a
trava e o larga fora dela, uma volta por fio.

Ele dorme entre as passadas, e não cede em laço. Ceder devolveria a CPU
imediatamente sempre que não houvesse mais ninguém pronto, e o núcleo nunca
chegaria a parar — um coletor que impede a máquina de ficar ociosa custa mais
do que a memória que recupera. Esperando a interrupção, ele acorda no tique
do timer que já ia acontecer, e a latência entre um fio morrer e o espaço
dele voltar ao alocador fica em um tique.

É um fio, e não uma tarefa do executor cooperativo, por um motivo de teste: o
executor não existe em modo de teste — lá o kernel roda a suíte e encerra. Um
coletor que só existisse em produção nunca seria exercitado, e a primeira
evidência de que ele está errado viria de uma máquina em uso.

```
$ cargo xtask agent threads.stats        # depois de alguns user.run
{"alive":2,"context_switches":168,"quantum_expirations":166,
 "quantum_ticks":5,"max_threads":16,"reaped":2}
```

Os dois vivos são o fio em que o kernel já estava e o próprio coletor.
`reaped` é o que distingue "o sistema está parado" de "o sistema criou e
recolheu fios o tempo todo" — duas situações que um retrato instantâneo da
tabela mostra idênticas.

A vaga do fio **atual** nunca é recolhida, mesmo marcada como encerrada: um
fio que chamou `sair` segue executando sobre a própria pilha de kernel até
ceder a vez, e desmapeá-la ali seria tirar o chão de quem está de pé nele.
Um fio encerrado que já não é o atual nunca mais roda — o rodízio só escolhe
quem está pronto —, e é isso que torna a pilha dele segura de desmontar.

**Cada processo tem o seu espaço de endereços.** Uma tabela de tradução por
processo, montada copiando as entradas de topo do kernel — o que mantém o
kernel mapeado em todo espaço, sem o qual a instrução seguinte a uma troca não
teria tradução. A entrada do usuário nasce vazia, e é a única que difere entre
os espaços.

O efeito é que dois processos usam `0x1_0000_0000` ao mesmo tempo apontando
para memórias físicas diferentes. O escalonador instala o espaço do fio que
entra a cada troca de contexto, e compara antes de escrever: fios do kernel
compartilham o espaço, e trocar à toa custa a TLB inteira.

O espaço morre com o fio que o hospeda. É um `Drop`, e não um par
criar/destruir, porque um fio morre de várias maneiras — saindo, tomando uma
falha, ou sendo arrancado quando a vaga dele é reaproveitada — e o caminho
que se esquece de chamar `destruir` vaza tabelas até a memória acabar. Há um
caso de teste que dá dez voltas de criar-mapear-destruir e exige que o
alocador de frames volte ao número exato de antes.

## Barramento PCI

Até a fase 1, todo dispositivo que o kernel tocava tinha endereço conhecido de
antemão: UART, timer, controlador de interrupções. São peças da placa, e a
placa é sempre a mesma. Disco e rede não funcionam assim — é o primeiro momento
em que o kernel **pergunta ao hardware o que existe** em vez de já saber.

```
$ cargo xtask agent pci.list
mecanismo=port-io-cf8  count=6
  00:00.0  8086:1237  classe 06/00  ponte-hospedeira
  00:01.1  8086:7010  classe 01/01  disco-ide
  00:02.0  1234:1111  classe 03/00  video
  00:03.0  8086:100e  classe 02/00  rede

$ cargo xtask agent --arch aarch64 pci.list
mecanismo=ecam  count=4
  00:00.0  1b36:0008  classe 06/00  ponte-hospedeira
  00:01.0  1af4:1001  classe 01/00  disco-scsi  <- virtio
  00:02.0  1234:1111  classe 03/80  video
  00:03.0  1af4:1000  classe 02/00  rede        <- virtio
```

O vídeo aparece nas duas listas com o **mesmo** fabricante e modelo. Não é
coincidência: a VGA padrão da máquina `pc` e o `bochs-display` da `virt` são a
mesma implementação do emulador, com a mesma interface de programação. Um
driver só (`tela/bochs.rs`) serve as duas. Hoje ele é quem acende a tela do
ARM quando o kernel sobe pela imagem crua; nos boots pela UEFI o firmware já
deixou um modo configurado, e o kernel adota a tela que o iniciador lhe
entrega em vez de reprogramá-la.

O mecanismo difere, a enumeração não. No x86 a configuração é alcançada por um
par de portas de I/O que existe desde 1993 — não precisa ser descoberto, ao
contrário do ECAM, que exigiria ler a tabela `MCFG` da ACPI. No ARM não há
portas: a configuração é memória mapeada, e **onde** ela está é escolha da
placa. O endereço vem do device tree, pelo mesmo motivo que o mapa de memória
sempre veio.

Duas coisas custaram uma descoberta cada. O ECAM da máquina `virt` fica em
`0x40_1000_0000`, muito acima do primeiro GiB que o boot mapeia, e precisa ser
mapeado como memória de dispositivo — uma leitura de configuração servida pelo
cache devolveria um valor velho, e o barramento não avisa. E o `reg` desse nó
vem **antes** do `compatible` no blob do QEMU: a especificação não ordena as
propriedades dentro de um nó, e um leitor de passada única que espere o
`compatible` primeiro não acha nada.

Os deslocamentos do cabeçalho PCI vêm do crate `pci_types`, pelo critério que
o projeto já usava: montar palavras de configuração a partir de deslocamentos
lidos de um manual vai para biblioteca, porque errar um não gera erro — gera um
dispositivo descrito errado. O que fica aqui é decisão nossa: como varrer, o
que guardar e como reportar.

## Operar por uma pessoa

O canal do agente responde JSON por uma serial dedicada, e é ótimo para um
agente. Para alguém sentado na frente da máquina ele é ilegível — e no ARM
era a única coisa que existia. Hoje a mesma máquina atende os dois.

```
duke> system.info
{
  "kernel": "duke",
  "arch": "aarch64",
  "version": "0.1.0",
  "phase": "5",
  "cpu_vendor": "ARM Limited",
  ...
}

duke> nao.existe
comando desconhecido: nao.existe
`ajuda` lista os 35 que existem
```

**O interpretador não tem comandos próprios.** O que se digita é despachado
pelo mesmo registro que `agent.describe` publica, com os mesmos handlers. Um
conjunto próprio seria uma segunda superfície, e as duas divergiriam na
primeira que alguém esquecesse de atualizar — com uma pessoa e um agente vendo
máquinas diferentes. O que muda é só a renderização: o agente lê uma linha de
JSON compacto, a pessoa lê o mesmo JSON quebrado em linhas por um
reformatador que não interpreta nada, só conta chaves e respeita strings.

É a mesma ideia que o log estruturado defende desde o começo: o texto legível
é uma renderização, e não a fonte da verdade.

**Três caminhos de hardware, um teclado.** O `virtio-input` do ARM e o PS/2 do
x86 compartilham a numeração de teclas — os códigos do Linux foram derivados
do conjunto 1 do AT —, então uma tabela serve os dois. O USB tem numeração
própria e uma tabela de tradução, e desemboca no mesmo lugar. O que cada
driver faz é extrair o par `(código, pressionada)` do formato dele.

**O teclado tem dono.** A fila de teclas é consumida pelo interpretador, e só
por ele. `keyboard.read` lê um histórico paralelo, escrito junto e consumido
separado — porque um segundo consumidor da mesma fila não observa o que foi
digitado, rouba. Foi medido: com os dois lendo a mesma fila, a sonda recebeu
uma das três teclas que mandou.

## A árvore semântica

Um agente que opera uma interface gráfica hoje, em quase todo sistema, tira
uma captura da tela e adivinha onde está o botão. Funciona até o tema mudar ou
o texto ser traduzido, e aí quebra sem dizer por quê: ele está lendo a
renderização em vez da coisa.

O Duke publica a coisa. `ui.tree` devolve a árvore do que está na tela —
cada elemento com papel, rótulo, valor, moldura em pixels e as ações que
aceita —, e `ui.act` age sobre um elemento pelo `id`:

```
$ cargo xtask agent ui.tree
{"revision":4013,"root":{"id":1,"role":"screen","label":"tela",
 "frame":{"x":0,"y":0,"width":1280,"height":800},"actions":[],"children":[
  {"id":2,"role":"text_area","label":"console","frame":{...},
   "value":"...\nduke> ","value_complete":true,"actions":[],"children":[
    {"id":3,"role":"text_field","label":"linha de comando","frame":{...},
     "value":"","focused":true,"actions":["confirm","cancel","set_value"],
     "children":[]}]}]}}

$ cargo xtask agent ui.act '{"id":3,"action":"set_value","value":"system.uptime"}'
$ cargo xtask agent ui.act '{"id":3,"action":"confirm"}'
{"id":3,"action":"confirm","ok":true,"executed":"system.uptime","revision":4102}
```

**O desenho é o da acessibilidade do macOS**, que é público: o `AXUIElement`,
com papel, valor e ações como `AXPress` e `AXConfirm`. O vocabulário das ações
é o mesmo — `press`, `confirm`, `cancel`, `set_value` —, para que quem conhece
um reconheça o outro. Código da Apple não há nenhum aqui.

**A árvore é gerada, e não escrita à mão.** O texto do console é o que o
próprio console guardou no instante em que desenhou cada caractere; a linha de
comando é o buffer que o interpretador edita; as molduras saem da geometria da
tela. É a regra que a fase 11 do roteiro fixa para o toolkit: uma árvore
mantida ao lado da interface seria a segunda superfície que este projeto
existe para não ter. A suíte confere as duas pontas — acha na árvore o texto
que escreveu e confere, glifo por glifo, que é aquele caractere que está
desenhado naquela linha e coluna.

**Agir é passar pelo caminho da pessoa.** Confirmar a linha de comando executa
o que está nela exatamente como o Enter: pelo interpretador, que despacha pelo
registro, desenha a resposta na tela e registra no log. Quem está na frente da
máquina vê o comando aparecer e a resposta ser desenhada — nada acontece por
trás da tela. E o log diz quem foi:

```
info console  executado: system.uptime (agente)
info console  executado: agent.ping (pessoa)
```

É o começo do que a fase 12 chama de auditoria: se um agente pode fazer tudo
que uma pessoa faz, o registro precisa dizer qual dos dois fez.

**O primeiro botão.** A barra superior tem o **Limpar**, que aceita `press` —
ver a seção da barra, abaixo. As camadas do compositor também aparecem na
árvore, como `window`, mas hoje só a suíte cria alguma.

**O que ainda não há.** Consentimento: um `set_value` do agente troca o que a pessoa
estava digitando, e nada pergunta a ela antes. A árvore mostra o que está
digitado, e o log registra quem agiu, mas pedir licença é trabalho da fase 12.

**Duas coisas que ela destapou no console.** O apagar desenhava um `?` e
avançava, em vez de apagar — a linha no buffer estava certa e a tela afirmava
outra coisa. E todo registro de log era desenhado no meio do que a pessoa
estava digitando, partindo a linha em duas. Hoje o apagar apaga, e um registro
que chega durante a edição aparece acima da linha, que é redesenhada inteira.

## A tela que só mostra o que se manda

Há máquinas em que a única placa de vídeo é um `virtio-gpu`: a máquina
virtual ARM de nuvem típica, e a que o UTM monta num Mac. Sem VGA, sem
`bochs-display`, sem um modo que o firmware deixe pronto para o kernel
adotar. Numa delas, até este driver existir, o Duke subia sem tela — medido,
com a `virt` do ARM levando só um `virtio-gpu-pci`: "nenhum framebuffer nesta
maquina". A pessoa na frente dela não via nada.

**A cadeia de quem acende a tela.** A tela que o iniciador entrega, se houver
uma; senão o `bochs-display`, programado por nós; senão o `virtio-gpu`. Ele é o
último porque é o único que custa um comando por mudança, e onde há
framebuffer linear não há razão para pagar isso. O firmware não resolve por
nós: o EDK II dirige o `virtio-gpu` com um modo só de transferência, sem
buffer linear, e o iniciador recusa esse modo — com razão, porque não teria
onde o kernel escrever.

**A diferença que define o driver.** Num framebuffer linear, o que o kernel
escreve aparece: o dispositivo varre aquela memória sozinho. Aqui o kernel
escreve na memória de apoio de um recurso — RAM comum — e só o que for
transferido e depois descarregado chega ao monitor. O console continua
escrevendo sem trava, como sempre escreveu; cada escrita alarga um retângulo
sujo guardado em quatro atômicos, e o fim de cada impressão manda só esse
retângulo. Um caractere impresso atravessa como a célula dele, e não como
os quatro mebibytes da tela:

```
$ cargo xtask agent --arch aarch64 display.info
{"present":true,"adapter":"virtio-gpu",
 "displays":[{"id":0,"width":1280,"height":800}],
 "layers":[{"id":0,"name":"console","x":0,"y":0,"width":1280,"height":800}],
 "surfaces":2,"surface_bytes":8192000,"updates":14,
 "last_damage":{"x":8,"y":234,"width":34,"height":10},
 "device":{"commands":36,"flushes":16,"rejected":0,
  "last_transfer":{"x":8,"y":234,"width":34,"height":10}}}
```

`device` é nulo num framebuffer linear, onde a pergunta não existe. Aqui ele
responde a que importa: a diferença entre "o kernel desenhou" e "o monitor
mostra" é o que foi mandado, e os contadores dizem se está sendo. As duas
superfícies contadas são a tela — a memória de apoio do recurso — e a camada
do console, que o compositor põe sobre ela (ver a seção seguinte).

**Atrás do mesmo trait.** `AdaptadorVirtio` implementa o mesmo
`AdaptadorGrafico` do linear, e o compositor não sabe qual dos dois tem
embaixo. A diferença é interna: no linear o dano é copiado de um buffer de
fundo para o framebuffer; aqui o quadro do compositor **é** a memória do
recurso da tela, nada é copiado pelo kernel, e o dano é o que atravessa.
Apresentar outra superfície troca o recurso da varredura de uma vez — a troca
de página sem rasgo que uma superfície de tela cheia vai usar. Soltá-la
devolve a tela ao kernel antes de desfazer o recurso, e desfaz o recurso antes
de devolver as páginas: enquanto ele existir, o dispositivo tem o direito de
lê-las.

**Porte do `virtio-gpud` do Redox, com três mudanças.** As estruturas do
protocolo conferem com as deles (ver `THIRD_PARTY.md`); o comportamento não:

- **O dano chega ao dispositivo.** O `update_plane` do Redox transfere o
  quadro inteiro a cada atualização, qualquer que seja o dano recebido.
  Aqui a transferência e a descarga são do retângulo.
- **Uma recusa do dispositivo é um erro.** O Redox confere cada resposta com
  `assert_eq!`, e um comando recusado derruba o daemon; no kernel derrubaria
  a máquina. Aqui a recusa volta para quem pediu, com o nome que a
  especificação dá a ela, e é contada em `rejected`.
- **A espera tem teto.** Um dispositivo que não responde desliga o driver e
  vira uma linha no log, como no disco.

**Duas conferências, porque cada uma é cega para o que a outra vê.** A suíte
confere o que o kernel mandou: que escrever um caractere transfere a célula
dele e só ela, que uma superfície apresenta só o dano, que um anexo de
páginas espalhadas usa várias páginas de entradas, que uma recusa vira erro.
A fumaça confere o que o monitor mostra: fotografa a tela pelo `screendump` do
monitor do QEMU — por fora da máquina, sem passar pelo kernel — e compara
3072 pontos dela com os que `video.sample` diz ter desenhado. Falsificado, uma
mutação de cada vez:

| Mutação | Suíte | Fumaça |
|---|---|---|
| a tela nunca é descarregada | reprova | 3072 de 3072 pontos diferem |
| transferir a tela inteira, como o Redox | reprova | **passa** — a tela sai certa |
| o deslocamento da transferência ignora `x` | **passa** | 153 de 3072 diferem |
| o formato do recurso trocado | **passa** | 3072 de 3072 diferem |
| sempre fundir páginas no anexo | reprova | — |
| a resposta do dispositivo não é conferida | reprova | — |
| soltar a superfície não devolve a tela | reprova | — |
| o dano não é recortado | reprova | — |

A segunda linha é o defeito do Redox, e a fumaça não o vê porque ele não
erra a tela: só manda a tela inteira para mudar uma célula. As duas seguintes são o
contrário — o kernel acredita ter mandado certo, e só quem olha o monitor
sabe que não. A fumaça fotografa as duas máquinas de vídeo, nas duas
arquiteturas.

## O compositor

Até aqui o console era a tela: cada letra ia direto para o framebuffer. Com
janelas, isso não serve — uma letra escrita debaixo de uma janela apareceria
por cima dela até alguém redesenhá-la, e o texto piscaria por baixo de tudo.
Agora o console é uma **camada**: a de baixo. Ele continua escrevendo como
sempre, sem trava e de qualquer lugar, mas numa memória só dele; o compositor
monta a tela com o que cada camada deixa ver e entrega o resultado ao
adaptador.

**Só o retângulo que mudou.** A escrita no console alarga o mesmo retângulo
sujo que o `virtio-gpu` já usava, e o fim de cada impressão o entrega ao
compositor. Ele recompõe só ali: copia o console, depois cada camada que
cruza o retângulo, de baixo para cima, e apresenta. Uma camada opaca esconde
a de baixo inteira onde as duas se cruzam, e compô-la é copiar linhas, sem
ler o fundo.

**Transparência.** Uma camada pode ser `alpha`: o byte alto de cada pixel é
a opacidade dele (`0xAARRGGBB`), e compô-la é misturar cada pixel com o que
as camadas de baixo já deixaram no quadro. E toda camada tem uma opacidade
própria, de 0 a 255, que multiplica a dos pixels — é o que desbota uma janela
inteira sem redesenhá-la. As contas são inteiras, com arredondamento, porque
o ARM deste kernel é `softfloat`; alfa 0 dá exatamente o de baixo e 255
exatamente o de cima. O formato é o mesmo nas duas: numa camada opaca o byte
alto é ignorado, e quem já desenhava não precisou mudar nada. `display.info`
diz a mistura e a opacidade de cada camada. A suíte confere as contas
contra a fórmula escrita no caso, e não contra o próprio compositor; oito
mutações nelas, oito reprovadas.

**O quadro.** A tela é montada num quadro antes de aparecer, para que nenhuma
camada seja vista pela metade. No `virtio-gpu` o quadro é a própria memória da
tela, porque ali o monitor só vê o que se transfere; num framebuffer linear,
um buffer de fundo que o adaptador copia para o framebuffer só no retângulo
que mudou. A diferença mora em um método do trait, `superficie_da_tela`, que o
`GraphicsAdapter` do Redox não tem.

**Por baixo dele, a tela de falha.** O caminho fatal não pode confiar na
trava nem no heap do compositor, e não passa por ele: desliga o compositor,
devolve o console à tela física e pinta direto nela. A fumaça provoca uma
falha fatal pelo agente, no fim da conversa, e fotografa o monitor — 99,7%
da tela na cor de falha no ARM linear, 99,8% nas outras três máquinas; o
resto é o texto do post-mortem.

**E o post-mortem não a apaga.** O compositor desligar, e não só ficar de
lado, veio de uma medição: o canal do agente segue respondendo no
post-mortem, e um `ui.act` com `press` no botão da barra limpava o console e
redesenhava a barra por cima da tela de falha — de 99,8% da foto na cor dela
para zero, nas duas arquiteturas. Agora a interface recusa agir no
post-mortem, com o motivo, e a fumaça pede esse `press` depois da falha e
fotografa de novo. E, com o compositor desligado, a mutação que pintava a
camada do console em vez da tela física — e que passava pela sonda, porque o
compositor vivo a levava ao monitor — agora é reprovada: a camada não chega
mais a lugar nenhum. O desvio em si protege a falha que acontece dentro do
próprio compositor, e essa nenhuma sonda sabe provocar ainda.

**O agente vê as camadas.** `display.info` lista cada uma, com posição e
tamanho, de baixo para cima. Na árvore semântica, as que ficam acima do
console aparecem como `window`, com um identificador que não se repete: um
agente que guardou o de uma janela que fechou recebe "não existe", e não a
janela que veio depois.

**O que ainda não há.** Quem crie janelas em produção: a única camada de
produção é a barra superior, e o servidor de janelas vem depois. Nem
o roteamento de entrada para elas.

Conferido pela suíte — a camada de cima vence, soltá-la revela o console,
mover não deixa rastro, a ordem de empilhamento decide quem aparece, uma
letra escrita debaixo de uma camada não vaza e aparece quando ela sai, uma
camada que passa da borda é composta só no que cai dentro — e pela fumaça,
que compara a tela montada com a foto do monitor. Dez mutações, nove
reprovadas pelo caso certo; a décima é a do desvio acima.

## A barra superior

No topo da tela, por cima do console: o nome do sistema, o botão **Limpar** e
o tempo desde o boot. É uma camada do compositor — a primeira que não é da
suíte — e o console passou a começar abaixo dela. A linha de acento que
dizia "há um kernel vivo" desceu para a borda de baixo da barra.

**O primeiro `press`.** O botão limpa o console e recomeça do topo, com o que
estava digitado redesenhado no prompt. A pessoa aperta **F1**; o agente pede
`ui.act` com `press`. Os dois caminhos chegam em `ui::agir`, cada um com a
sua origem, e dali na mesma função — e o log diz quem foi:

```
info ui  agente: press no elemento 5
info ui  pessoa: press no elemento 5
```

**F1 nos três teclados.** As teclas de função não existiam: o teclado deste
kernel só entendia texto. Agora F1 a F12 chegam do 8042, do `virtio-input` e
do USB — no USB por uma tabela de tradução, conferida em tempo de
compilação. Chegam à fila do interpretador como caracteres da área de uso
privado do Unicode, os mesmos que o macOS usa para elas (`NSF1FunctionKey` é
U+F704), e não entram no histórico que `keyboard.read` devolve, que é o que
foi digitado. Pela fila, e não dentro da interrupção: limpar a tela inteira
não é trabalho para um handler.

**O relógio.** Uma tarefa do executor redesenha o tempo ligado a cada
segundo. Não é hora do dia — o kernel ainda não lê o relógio de parede. A
árvore publica o texto que está desenhado, e a suíte confere que é o mesmo,
pixel a pixel pela mesma fonte: sem isso a árvore poderia afirmar uma hora
que a tela não mostra, e foi o que uma das mutações mostrou.

```
{"id":4,"role":"menu_bar","label":"barra superior",...,"children":[
 {"id":6,"role":"static_text","label":"nome","value":"Duke",...},
 {"id":5,"role":"button","label":"Limpar","actions":["press"],...},
 {"id":7,"role":"static_text","label":"tempo ligado","value":"ligado 0:00:12",...}]}
```

Conferido pela suíte — a barra no topo e o console abaixo dela, o relógio
andando e desenhado, o `press` do agente limpando, a F1 da pessoa pelo mesmo
caminho e com a outra origem, a linha digitada sobrevivendo à limpeza — e
pela fumaça, no kernel de produção: `press` pela árvore, F1 pelo `sendkey`
do monitor nos três teclados, e o relógio andando sozinho, que só a tarefa
de produção faz. Onze mutações, onze reprovadas — duas delas só depois de os
casos que as deixavam passar serem corrigidos.

**Uma dívida que ela expôs, e que foi paga.** O console não rolava: quando
enchia, recomeçava do topo, e a última linha escrita sumia junto com a
página. A barra tirou duas linhas da página, e um caso da árvore passou a
cair exatamente nessa virada. Agora o console rola — ver a seção seguinte.

## O console rola

Quando o texto chega ao pé da tela, ele sobe uma linha e a nova entra
embaixo, como num terminal. Antes a tela recomeçava do topo, limpando: quem
lia a resposta de um comando perdia o começo dela, e a última linha escrita
sumia com a página.

A razão para não rolar era de custo — em debug, repintar a tela passa de
600 ms. O compositor mudou a conta: o console desenha numa camada em memória
comum, e rolar é mover um bloco de memória (as linhas de pixel são contíguas)
e pintar só a última linha. O compositor leva à tela o que mudou.

Duas coisas sobem junto com o texto. A grade de caracteres, para a árvore
semântica continuar descrevendo o que está na tela. E a linha de comando: o
interpretador guarda quantas rolagens havia quando o prompt foi desenhado, e
a moldura do campo desce o que a tela subiu desde então — uma impressão do
kernel no pé da tela, com o prompt aberto, não deixa a árvore apontando para
a linha errada.

Seis mutações, seis reprovadas — entre elas a de voltar a recomeçar do topo,
que o caso do registro de log, livre do paliativo que tinha ganhado, agora
pega sozinho.

## O mouse

Uma seta que segue o mouse, e o clique no botão **Limpar** — o terceiro
caminho até o mesmo `press`, depois do `ui.act` do agente e da F1:

```
info ui  pessoa: press no elemento 5
```

**Três dispositivos.** No x86, o mouse PS/2, pela porta auxiliar do mesmo
8042 do teclado, na IRQ 12: diz **quanto** andou, em pacotes de três bytes.
No ARM, que não tem 8042, o `virtio-tablet`: diz **onde** o ponteiro está,
numa escala dele que o driver lê do espaço de configuração. E, nas duas, o
mouse USB, no protocolo de boot do HID — o mesmo que o teclado USB fala, e
pela mesma razão: três bytes com significado fixo, sem interpretar o
descritor de relatório. Os três drivers traduzem para `ponteiro::relativo`
ou `ponteiro::absoluto`; daí para cima ninguém sabe qual chegou.

**O xHCI com mais de um dispositivo.** O driver USB nasceu atendendo um só —
o teclado da fase 3 —, e o mouse precisou do segundo. O que era de cada
dispositivo (porta, slot, endpoint de controle, buffer, o relatório anterior
do teclado) saiu do controlador para uma estrutura por dispositivo, e o anel
de eventos, que é um só para todos, passou a ser lido pelo slot e pelo
endpoint de cada evento: sem isso, um relatório do mouse seria lido como
tecla. Os relatórios só são pendurados depois de todos os dispositivos
configurados, para que um relatório do teclado não seja tomado pela
conclusão de um pedido de configuração do mouse.

**O cursor é uma camada.** Transparente fora da seta, pelo alfa por pixel do
compositor, e fixa no topo: uma janela trazida para a frente continua
debaixo dela. Aparece no primeiro movimento — uma máquina sem mouse não
mostra um ponteiro que ninguém move. Não entra na árvore semântica, que
descreve o que se opera, e não o que aponta; `display.info` diz onde o
ponteiro está e quantos cliques e movimentos chegaram.

**O clique vai pela fila.** O handler de interrupção só anota onde foi e
põe um caractere reservado na fila do interpretador, como a F1. Quem trata
é a tarefa do interpretador: pergunta à interface o que está debaixo do
ponteiro e, se aceitar `press`, aciona por `ui::agir`, com a origem da
pessoa.

**Uma interrupção sem byte.** A configuração do 8042 liga a IRQ 12 antes dos
comandos ao mouse, e o PIC guarda o pedido enquanto a linha está mascarada.
Ao desmascarar, ele o entrega — e ler a porta ali devolvia o último byte de
novo, o 0xFA do aceite, que tem o bit que marca o começo de um pacote. O
primeiro movimento de verdade saía fora de fase. A suíte achou isso: o
handler agora confere, no registrador de estado, que há byte e que ele veio
do mouse, e o caso confere que nenhum byte ficou pendurado.

Conferido pela suíte — as duas escalas, o cursor seguindo e ficando por
cima de uma camada nova, a transparência fora da seta, o clique no botão
limpando, os eventos do `virtio-input` e os pacotes PS/2 montados à mão — e
pela fumaça, no kernel de produção, com o QEMU mandando eventos de verdade
pelo QMP: o ponteiro vai até o botão, a seta aparece lá, e o clique limpa.
Nas seis máquinas. Nas duas com USB, a sonda confere também **por onde** o
ponteiro andou — relatórios do mouse USB contados em `display.info` —, como
a do teclado já fazia: no x86 o PS/2 continua lá, e sem essa conferência a
sonda passaria pelo mouse que o emulador escolhesse.

Doze mutações no mouse, doze reprovadas — uma delas, a de clicar ao
soltar, só pelo caso do PS/2 até o caso do clique passar a conferir a fila
no apertar, e esse roda também no ARM.

O mouse USB trouxe mais onze, contando as do post-mortem (ver "O
compositor"). Nove reprovadas. Uma delas — o pedido de relatório cortado em
três bytes — só depois de a sonda do teclado passar a segurar duas teclas
juntas (`d-e`): com uma tecla de cada vez, três bytes bastam. Das duas que
sobram, uma declara um slot só ao controlador, e o do emulador não cobra o
limite; a outra tira o desligamento do compositor na falha, que hoje é a
segunda trava — a primeira, a recusa da interface, é reprovada sozinha.

## Sistema de arquivos

A camada que o Unix chamou de VFS: um *vnode* (um objeto do sistema de
arquivos visto de memória), uma *montagem* (um sistema pendurado num ponto da
árvore) e a tabela de operações que cada sistema preenche. A tabela de
ponteiros de função do `vnodeops` vira um `trait` — a mesma indireção, com o
compilador conferindo as assinaturas.

```
$ cargo xtask agent fs.mounts
{"mounts":[{"at":"/bin","type":"programas"},{"at":"/","type":"btrfs"}]}

$ cargo xtask agent fs.list
{"path":"/","entries":[{"name":"saudacao.txt","type":"file"},
                       {"name":"dados","type":"dir"},
                       {"name":"grande.txt","type":"file"},
                       {"name":"enche-1.txt","type":"file"}, ...]}

$ cargo xtask agent fs.read '{"path":"/dados/nota.txt"}'
{"path":"/dados/nota.txt","size":26,"offset":0,"returned":26,
 "content":"uma nota num subdiretorio\n"}
```

**A raiz vem do disco.** Os nomes acima não estão em lugar nenhum do
binário: eles foram escritos numa imagem pelo `mkfs.btrfs` do hospedeiro, e o
caminho até eles passa pela GPT, pelo superbloco com o crc32c conferido, pela
tradução de endereço lógico e por uma descida pela árvore de arquivos.

Um arquivo pequeno mora **dentro** do item de extensão — o Btrfs não gasta um
bloco inteiro com vinte e nove bytes — e lê-lo é copiar bytes que já vieram
com a folha. Um grande mora num endereço lógico, que precisa ser traduzido, e
volta em pedaços do tamanho que o driver monta. São dois caminhos de código
inteiramente diferentes, e a imagem de teste tem um arquivo de cada: o
`grande.txt` tem quarenta e oito kilobytes justamente para que a leitura venha
em três voltas em vez de uma.

### A descida pela árvore

Enquanto o disco tinha meia dúzia de arquivos, a árvore de arquivos cabia
numa folha e o leitor lia essa folha. O limite estava declarado e conferido:
um nó interno era **recusado**, em vez de lido como folha — porque os
descritores de um nó interno são outros (chave mais endereço do filho, trinta
e três bytes contra vinte e cinco) e lê-los como itens não devolve lixo
óbvio, devolve nomes de arquivo montados a partir de ponteiros.

Hoje ele desce. Num nó interno, a chave `i` é a menor chave do filho `i`, e
achar onde uma chave mora é procurar o último `i` cuja chave seja menor ou
igual a ela — por busca binária, porque um nó comporta centenas de ponteiros
e a descida acontece uma vez por folha visitada.

O erro que essa escolha esconde é de **um índice**, e ele não tem sintoma
próprio: descer pelo filho seguinte devolve uma folha cujas chaves começam
depois do alvo, e a resposta vira "este arquivo não existe" para um arquivo
que existe. Por isso o caso que o cobre usa um nó forjado, com as sete
perguntas de borda e a resposta certa sabida de cada uma — antes da primeira
chave, exatamente em cada chave, entre duas, e depois da última.

**Como o percurso atravessa folhas.** Descendo de novo: ao esgotar uma folha,
ele desce da raiz outra vez, até a primeira chave da folha seguinte. É uma
leitura de nó a mais por folha, por nível. A alternativa é o que o Btrfs de
verdade faz — guardar o caminho inteiro, um nó por nível, e subir só o
necessário para achar o irmão à direita —, que é mais rápido e custa um
buffer de nó **por nível**, vivo durante todo o percurso. A escolha aqui é a
barata em memória: um buffer só.

Onde a folha seguinte começa vem da própria descida: é a chave do ponteiro à
direita do escolhido, no nível mais baixo que tem um — a chave `i + 1` de um
nó interno é a menor da subárvore vizinha.

**Um defeito que ficou escondido, e o terceiro programa achou.** Antes, a
próxima folha era deduzida da última chave da atual: procurava-se a
sucessora dela, e uma folha cuja última chave fosse menor que o alvo era
tomada por fim da árvore. As duas coisas erram no **vão entre folhas**. Um
alvo que não existe e cai entre a última chave de uma folha e a primeira da
seguinte faz a descida aterrissar na da esquerda — o último ponteiro com
chave menor ou igual a ele —, e ali todas as chaves são menores. O percurso
parava. Medido na árvore de arquivos do disco de testes: da chave zero, ele
entregava 71 das 173 chaves. Ninguém via, porque os casos procuravam o que
estava antes do primeiro vão; apareceu quando os programas compilados
passaram a ser três por diretório e `/programas/x86_64` listou um só —
`/programas/x86_64/ola` dava "não encontrado", com o arquivo lá.

O caso que o cobre lê a árvore inteira pela **estrutura**, nó a nó e filho a
filho, sem passar pela descida, e exige que o percurso entregue exatamente as
mesmas chaves; depois, para cada vão entre duas chaves consecutivas, começa
um percurso dentro do vão e exige a segunda. A primeira versão dele tomava a
referência do próprio percurso — e passava com o defeito, conferindo só o
pedaço que o defeito deixava ver.

**A imagem foi refeita para ter por onde descer.** Com o tamanho de nó padrão
e três arquivos, a árvore continuaria numa folha só, e todo o código acima
passaria em tudo sem ser executado. A imagem do `xtask` é formatada com nós
de quatro kilobytes e leva vinte e quatro arquivos de enchimento: a árvore de
arquivos fica com nível 1 e três folhas, e os inodes dos arquivos nomeados
caem em folhas diferentes dos nomes deles.

```
$ cargo xtask test --arch aarch64 | grep 'arvore de arquivos'
info teste  arvore de arquivos: nivel 1, 3 folhas, 70 itens
```

Um caso reprova se o nível voltar a ser zero, com a mensagem dizendo o que
mudar de volta. Sem ele, uma mudança na imagem desligaria silenciosamente
todos os outros.

O tamanho de nó menor cobre uma segunda coisa de graça: ele é diferente do
padrão do `mkfs.btrfs`, então o leitor precisa **ler** o campo do superbloco
em vez de assumir dezesseis kilobytes — uma constante escondida que só
apareceria no primeiro disco formatado por outra pessoa.

**A receita que decide remontar a imagem passou a ser derivada.** Ela era uma
lista escrita à mão dos parâmetros que importam, e o tamanho de nó entrou no
`mkfs` sem entrar nela: o disco antigo ficou no lugar, e a suíte reprovou
dizendo que a árvore cabia numa folha — verdade sobre uma imagem que já não
era a do código. Agora a receita é montada a partir das mesmas funções que
montam o disco, e um caso de `cargo test -p xtask` afirma que todo argumento
do `mkfs` e todo arquivo da raiz aparecem nela.

**O que este leitor não lê, declarado:** mais de uma extensão por arquivo (um
arquivo escrito em pedaços sai truncado no primeiro), extensões comprimidas,
extensões pré-alocadas, subvolumes e os perfis RAID0/10/5/6. Cada uma delas é
uma recusa escrita no código, ou um limite anotado onde ele mora — não um
caminho que dá errado calado.

**Ele existiu antes de haver disco, e é isso que o tornou útil.** Quando o
Btrfs entrou, ele entrou por baixo desta mesma interface, sem que `executar`
mudasse: os programas embutidos continuam em `/bin` porque a montagem mais
longa ganha.

**O que não está no trait**: escrita, `abrir` e `fechar`. As chamadas de
sistema `abrir` e `fechar` existem, mas o estado que elas criam — a posição
de leitura — é do processo, e mora na tabela de descritores; o trait só
precisou de uma leitura a partir de um deslocamento. Elas descem para o trait
quando houver escrita, ou um sistema de arquivos que precise saber quantos
descritores apontam para um nó. Antes disso seriam métodos que todo sistema
implementa como `Ok(())` — e um método de trait que compila e não tem chamador
é pior que ausência: ele parece uma opção disponível, e o primeiro a usá-lo
descobre que nunca foi exercitado.

**A regra da montagem mais longa.** Com `/` e `/bin` montados, `/bin/exemplo`
pertence ao segundo. A versão errada — a primeira da lista que casar —
funciona até o dia em que houver duas montagens, e aí `executar` para de achar
os programas sem que nada aponte a causa. O caso de teste que cobre isso
precisou ser reescrito duas vezes: a primeira versão montava a raiz **depois**
de `/bin`, e aí a regra errada acertava por acidente de ordem; a segunda
mexia em `/bin` de verdade e, no dia em que a raiz do disco passou a estar
montada, falhou **no meio** — deixando `/bin` desmontado e derrubando um caso
que não tinha nada a ver. Hoje ele monta e desmonta pontos que são só dele.

## O iniciador UEFI

O x86 do Duke bootava pelo crate `bootloader`. Um programa de outra pessoa
fazia a transição para long mode, montava as tabelas de página iniciais e
entregava ao kernel uma `BootInfo` pronta — funcionava, e escondia exatamente
a parte que um kernel escrito do zero deveria mostrar.

**Ele saiu.** O `iniciador/` é uma **aplicação UEFI** deste projeto: o
firmware a carrega de `\EFI\BOOT\BOOTX64.EFI` na partição de sistema do
mesmo disco que o kernel depois lê, ela põe o kernel de pé e lhe entrega a
máquina. Não há mais bootloader de terceiros no caminho de boot do Duke.

### O mesmo programa nos dois firmwares

O iniciador compila para `x86_64-unknown-uefi` e para `aarch64-unknown-uefi`,
e roda no EDK II de verdade dos dois lados — OVMF no x86, AAVMF no ARM, que
são a mesma base de código compilada para processadores diferentes.

E é literalmente o mesmo programa. Conferir as três tabelas do firmware por
assinatura e CRC, descrever o mapa de memória, achar a tela pelo protocolo de
vídeo, seguir a corrente de três elos até a partição de sistema, ler o kernel
em pedaços de 64 KiB e validar o ELF inteiro — nada disso tem uma linha de
`cfg`. A UEFI é a mesma especificação nas duas máquinas, com as mesmas
tabelas, os mesmos GUIDs e a mesma convenção de chamada, que o compilador
traduz sozinho.

O que o módulo `alvo/` separa é o que a especificação não cobre porque não é
dela:

| | x86_64 | aarch64 |
|---|---|---|
| Serial | COM1 em `0x3F8`, por porta de I/O | PL011 em `0x0900_0000`, memória mapeada |
| Arquivo na ESP | `BOOTX64.EFI` | `BOOTAA64.EFI` |
| `e_machine` do ELF | `0x3E` | `0xB7` |
| Relocação relativa | `R_X86_64_RELATIVE` = 8 | `R_AARCH64_RELATIVE` = 1027 |
| Parar o núcleo | `hlt` | `wfi` |

O número da relocação merece uma nota. Cada arquitetura numera as próprias a
partir de um, então o `8` do x86 **existe** no ARM e quer dizer outra coisa
(`R_AARCH64_ABS16`). Aplicar a tabela de uma no ELF da outra não daria erro:
daria um punhado de escritas plausíveis nos lugares errados.

**E o ARM boota.** O mesmo comando, no outro firmware:

```
$ cargo xtask iniciador --arch aarch64
  [iniciador] vivo em aarch64, carregado pelo firmware
  [iniciador] firmware `Ubuntu distribution of EDK II` revisao 0x10000
  [iniciador] as tres tabelas conferem, por assinatura e por crc
  [iniciador] memoria: 32 descritores de 48 bytes, 192 MiB descritos, 119 MiB livres
  [iniciador] video: 800x600 bgr, buffer em 0x43d00000
  [iniciador] device tree em 0x47ef6000, pela tabela de configuracao
  [iniciador] esp: duke.elf aberto e lido, 7696200 bytes, crc 0x708a0c48
  [iniciador] elf: entrada em 0x40080000, endereco fixo
  [iniciador] carga: imagem em 0x40080000 fisico, 1516 KiB, 484368 bytes de bss
  [iniciador] saindo dos servicos de boot: 34 regioes, chave 0x50d
  [iniciador] a maquina e do Duke; saltando para 0x40080000
  [iniciador] 34 regioes, device tree em 0x47ef6000        <- o kernel
```

### O fim do caminho é o oposto nas duas máquinas

No x86 o iniciador **constrói** o mapa em que o kernel vai rodar: o firmware
entrega um mapa que não serve, e o kernel roda na metade alta do espaço.

No ARM ele **desconstrói**. A especificação da UEFI exige que uma máquina
AArch64 entregue o programa de boot com a MMU ligada e mapeada por
identidade, e esse estado sobrevive ao `ExitBootServices`. O kernel do ARM,
por outro lado, foi escrito contra o protocolo de imagem crua do arm64 desde
o primeiro dia: ele monta as próprias pilhas, zera o `.bss` e liga a MMU com
tabelas suas. Então o trabalho do iniciador é desfazer o que o firmware
deixou até chegar exatamente no estado que o kernel já sabia esperar.

Desfazer tem uma parte que não é opcional e não tem sintoma próprio:
**limpar o cache de dados por conjunto e via**, antes de desligá-lo.
Desligar o cache não o esvazia — as linhas sujas continuam lá, e uma delas
pode ser expulsa muito depois, escrevendo um valor velho por cima de memória
que o kernel já usou para outra coisa. Limpar por endereço cobriria só o que
nós escrevemos; o que precisa sair são também as linhas do firmware, que
rodou durante segundos antes de nós. A varredura percorre a geometria que o
próprio processador declara — `CLIDR_EL1` diz quantos níveis, `CCSIDR_EL1`
diz quantos conjuntos e vias em cada um — e é a única forma de alcançar
todas.

**O kernel vai para o endereço dele, e não para onde couber.** Ele é ligado
num endereço fixo e não é independente de posição como o do x86: não há
tabela de relocações para somar uma base, e os ponteiros constantes dele já
dizem `0x4008_0000`. O iniciador pede aquele endereço ao firmware com
`AllocateAddress`, que ou o dá exatamente ou recusa — e o AAVMF dá. Se um
dia recusar, a saída é tornar o kernel relocável, e a recusa diz isso em vez
de escolher sozinha. A linha `endereco fixo` do relatório é o registro do
fato, e a sonda a exige.

### Três coisas que a sonda encontrou depois de tudo funcionar

**O endereço da UART era um chute silencioso.** Ele está fixado no código
— e precisa estar, porque é por ela que o iniciador relata qualquer coisa:
para dizer que o device tree discorda, é preciso já estar falando por algum
endereço. O que mudou é que o chute deixou de ser silencioso. Assim que o
device tree aparece, o iniciador procura nele o nó compatível com
`arm,pl011` e compara:

```
  [iniciador] serial: a placa confirma a pl011 em 0x9000000
```

Numa placa em que os dois discordem, a discordância vira uma linha em vez
de virar uma serial muda. O leitor de FDT do iniciador é o mínimo para essa
pergunta — percorre o bloco de estrutura uma vez e para no primeiro nó
compatível.

**O salto sujava um registrador que não declarava.** Os dois: o do x86 faz
`xor rbp, rbp` antes do `jmp`, e o do ARM lê o `SCTLR_EL1` para um
temporário antes do `br`. Os operandos eram `in(reg)`, e o compilador pode
escolher justamente aqueles registradores — no dia em que escolhesse, o x86
saltaria para o endereço zero e o ARM para o valor do `SCTLR_EL1`. Funcionava
por sorte da alocação, e o sintoma seria um reset sem nada na tela, mudando
de lugar a cada recompilação. Os quatro operandos passaram a ter registrador
escrito à mão.

**O framebuffer podia virar memória livre.** Se a tela cai numa região que o
firmware declarou utilizável, o kernel recebe como livres as páginas que o
vídeo está lendo. A proteção entrou — e entrou **errada**: ela comparava o
endereço *virtual* da tela com o mapa de memória, que é todo físico, então
nunca casava. Rodava e não protegia nada.

O que a encontrou foi exigir da sonda que a comparação tivesse **acontecido**,
e não só que nada tivesse dado errado:

```
$ cargo xtask iniciador --arch x86_64
  [iniciador] a tela em 0x80000000 fisico cai em 0 regiao(oes) do mapa, 0 reservada(s)

$ cargo xtask iniciador --arch aarch64
  [iniciador] a tela em 0x43d00000 fisico cai em 1 regiao(oes) do mapa, 0 reservada(s)
```

Os dois números certos são **diferentes**, e é isso que a sonda afirma. No
x86 a tela é um BAR de PCI: o mapa da UEFI descreve memória, não barramento,
e zero é a resposta correta. No ARM é o `ramfb`, que é RAM comum dentro do
mapa — ali pelo menos uma região é obrigatória, e é essa metade que reprova
se a comparação parar de acontecer. Nenhum dos dois firmwares precisou da
reclassificação hoje; o relatório diz isso em vez de calar.

### Um registrador, dois protocolos

`x0` carrega o device tree quando o QEMU carrega o kernel com `-kernel`, e
uma [`Entrega`](protocolo/src/lib.rs) quando o iniciador o carrega. O kernel
distingue os dois pela magia, que não colide: uma entrega começa com
`DUKEBOOT`, um device tree com `0xd00dfeed` em big-endian.

Os dois caminhos continuam existindo de propósito. O `-kernel` é como a
suíte sobe hoje — em segundos, sem disco montado nem firmware instalado — e
fingir que ele não existe custaria isso. O dia em que o boot por UEFI for o
único, o `match` some.

No ARM o device tree não vem em registrador nenhum: ele é uma entrada da
**tabela de configuração** da UEFI, identificada por um GUID, e o iniciador
o acha e o passa dentro da entrega. Passá-lo já achado não é conveniência:
depois do `ExitBootServices` a tabela do sistema pode não estar mais
mapeada, e o kernel não teria onde procurar.

E ele só está lá com `acpi=off` na linha do QEMU. Com o padrão, o EDK II do
ARM publica só a RSDP da ACPI — foi medido, e o iniciador lista os oito
GUIDs da tabela quando não acha o que procura, justamente para que a
diferença entre "não tem" e "tem com outro GUID" não precise ser adivinhada.

### A suíte inteira roda pelo caminho da UEFI

No ARM a sonda não para na primeira linha do kernel: ela deixa a suíte
correr até o fim.

```
$ cargo xtask iniciador --arch aarch64
  [conferido] o kernel assumiu a maquina e disse `Duke iniciado em aarch64`
  [conferido] 149 casos da suite passaram sobre o mapa da UEFI
```

A diferença não é cosmética. O mapa de memória que o firmware entrega tem
trinta e três regiões; o do device tree tem uma. Tudo que depende de saber o
que é memória livre — o alocador de frames, a cópia na escrita, o coletor de
espaços, o leitor de Btrfs — roda sobre esse mapa pela primeira vez ali.
Passar no `-kernel` não dizia nada sobre passar por este caminho.

E não dizia mesmo. Na primeira vez que a suíte correu por aqui, **vinte e
nove casos reprovaram**, e nenhum deles era do kernel.

**A sonda montava uma segunda definição da máquina.** Mais curta, com
`virtio-blk-device` no lugar do `virtio-blk-pci`, sem semihosting, sem
teclado. Enquanto ela só olhava a primeira linha do kernel, a diferença não
aparecia; no dia em que a suíte rodou ali, ela reprovou dizendo que a máquina
não tinha disco, nem vídeo, nem PCI — e estava certa sobre outro computador.
A sonda passou a usar a **mesma** função que `test`, `run` e `fumaca` usam,
que agora sabe bootar o ARM pelo disco.

**E sobrou um defeito de verdade, que só este caminho expõe.** Com a máquina
certa, ainda faltavam o disco e a rede:

```
pci     janela de MMIO em 0x10000000 (barramento 0x10000000), 751 MiB
pci     BAR 4 em 0x8000000000 fica fora da janela conhecida
virtio  disco nao pode ser ligado: dispositivo sem configuracao comum
```

O kernel lia da `ranges` do device tree **só a janela de 32 bits**, e com
razão declarada: é a única em que um BAR de 32 bits cabe, e é lá que ele
põe os BARs quando é ele quem os distribui. Mas quando é o **firmware** que
distribui, os BARs de 64 bits dos dispositivos virtio vão para a janela
alta, em `0x80_0000_0000`. O kernel os lia, não sabia traduzi-los, e
concluía que o dispositivo não tinha região.

É o mesmo defeito de sempre neste projeto, com outra roupa: funciona
enquanto **nós** fazemos, quebra quando alguém fez antes. Numa placa ARM de
verdade é sempre o firmware que atribui.

O conserto separa as duas perguntas. Atribuir continua sendo só na janela de
32 bits; **ler** passa a tentar as duas. No x86 não há janela declarada
nenhuma — lá o endereço do barramento é o da CPU — e nada muda.

**A máquina do ARM ganhou uma segunda tela**, e é para o firmware. O EDK II
do ARM não tem driver de bochs, que é o adaptador que o kernel dirige: sem
um que ele saiba dirigir, o iniciador não descobre tela nenhuma e o caminho
que protege o framebuffer nunca roda. O `ramfb` é o que ele dirige, e como
não é PCI não aparece na varredura do kernel — os dois convivem sem que
nenhum dos lados precise escolher.

### A sonda do ARM, e o boot que parecia ter falhado

Ela roda as **mesmas quatro recusas** com kernels estragados de propósito —
que valem ali exatamente como valem no x86, porque o leitor de ELF é o mesmo
código.

Uma delas só passou a valer depois de um conserto que a própria rodada do
ARM revelou: o caso "um kernel de outra arquitetura" escrevia `0xB7` fixo no
campo `e_machine`, o que no ARM é copiar o valor certo por cima dele mesmo.
O iniciador aceitava o arquivo, com razão, e a rodada reprovava. O byte
agora é o da **outra** arquitetura, seja qual for a de quem está rodando.

Ela boota a compilação de **teste** do kernel, por um motivo que custou
uma investigação. O primeiro boot por UEFI no ARM pareceu ter falhado: o
iniciador dizia "a maquina e do Duke; saltando para 0x40080000" e depois
silêncio. O `-d int` do QEMU mostrou o kernel **vivo** — tomando
interrupções e tratando-as pelos vetores dele, com o `PC` dentro da imagem.

Ele estava rodando e não tinha onde falar. A máquina `virt` expõe uma PL011
só, e fora do modo de teste ela é o canal do agente: o ARM não tem console
humano, e o log de boot vai só para o anel de registros. Um kernel que não
escreve na serial é indistinguível, para uma sonda que lê a serial, de um
kernel que não subiu. No modo de teste a porta vira console, e a primeira
linha aparece.

```
$ cargo xtask iniciador
  [iniciador] vivo, carregado pelo firmware
  [iniciador] tabela do sistema confere: uefi 2.70, 120 bytes
  [iniciador] firmware `Ubuntu distribution of EDK II` revisao 0x10000
  [iniciador] as tres tabelas conferem, por assinatura e por crc
  [iniciador] memoria: 129 descritores de 48 bytes, 121 MiB livres
  [iniciador] video: 1280x800 bgr, buffer em 0x80000000
  [iniciador] esp: duke.elf aberto e lido, 7058448 bytes, crc 0x53f802c7
  [iniciador] elf: entrada em 0x863a0, independente de posicao
  [iniciador] segmento 1 em 0x0:      142116 do arquivo, 142116 na memoria, r--
  [iniciador] segmento 2 em 0x23b30:  654223 do arquivo, 654223 na memoria, r-x
  [iniciador] segmento 3 em 0xc46c0:   70840 do arquivo,  72000 na memoria, rw-
  [iniciador] segmento 4 em 0xd6b78:   52168 do arquivo, 120920 na memoria, rw-
  [iniciador] kernel: 4 segmentos, 0x0..0xf43d0, 966 KiB na memoria
  [iniciador] carga: imagem em 0x57ed000 fisico, 980 KiB,
              69912 bytes de bss zerados, 3703 relocacoes aplicadas
  [iniciador] mapa: 12 paginas de tabela, raiz em 0x576d000
  [iniciador] mapa confere: kernel, memoria fisica, identidade, pilha e video
  [iniciador] fim do relatorio
  [iniciador] saindo dos servicos de boot: 133 regioes, chave 0xb89
  [iniciador] a maquina e do Duke; saltando para 0xffff8000000d75b0

  =============================================
    Duke :: agent-native :: x86_64 :: fase 5
  =============================================
  [    0]     0ms info boot  Duke iniciado em x86_64, fase 5

  [conferido] 7058448 bytes com crc 0x53f802c7, entrada 0x863a0,
              4 segmentos e 3703 relocacoes
  [conferido] o kernel assumiu a maquina e disse `Duke iniciado em x86_64`

[xtask] iniciador: 4 kerneis estragados de proposito, que tem de ser recusados
  [recusa] ok  um kernel com a entrada fora de qualquer segmento foi recusado
  [recusa] ok  um kernel compilado para outra arquitetura foi recusado
  [recusa] ok  um arquivo que nao e um ELF foi recusado
```

**O caminho inteiro.** O firmware carrega o iniciador; ele confere as três
tabelas da UEFI, lê a máquina, abre o kernel na ESP, copia cada segmento para
onde ele pede, aplica as relocações, monta o mapa de tradução, confere o
mapa, sai dos serviços de boot e salta. A linha do kernel logo abaixo do
salto é outro programa, noutro espaço de endereços, dizendo que está de pé.

**A ordem do fim, e por que ela é essa.** Alocar tudo que ainda falta;
**depois** pedir o mapa de memória, que devolve uma *chave* junto; sair com
aquela chave; e só então trocar o `CR3` e saltar. A chave é o firmware
dizendo "este é o mapa que eu tenho agora", e ele só aceita sair se quem sai
provar que viu a versão mais recente — qualquer alocação entre a pergunta e a
saída a invalida. A especificação prevê uma segunda tentativa, e o iniciador
a faz uma vez; se a segunda também falhar, insistir seria laço.

**Copiar, relocar, mapear.** O kernel é um executável independente de
posição: foi ligado a partir do zero e carrega uma lista de 3703 lugares onde
a base de carga precisa ser somada. Sem essa passagem, todo ponteiro
constante dele aponta para a metade baixa do espaço, onde não há nada.

A conta tem duas bases, e é aí que ela erra: a relocação diz "no endereço
virtual `r_offset`, escreva `base + adendo`". A **base** é a virtual, porque
é onde o kernel vai rodar; o **lugar onde escrever** é físico, porque é onde
a imagem está agora. Confundi-las escreve o valor certo no lugar errado, ou o
errado no lugar certo — e as duas dão um kernel que boota e falha depois.

**O mapa tem a metade alta do Duke e a identidade da RAM.** A identidade não
é para o kernel: é para os poucos ciclos entre o `mov cr3` e o salto. No
instante seguinte à troca, o processador busca a próxima instrução, que está
no código do iniciador, num endereço baixo — e uma falha de página sem tabela
de exceções instalada é um triple fault, a máquina reiniciando sem nada na
tela.

As duas cobrem a mesma faixa com as mesmas permissões e começam no mesmo
deslocamento dentro da entrada de topo delas, então a tabela de nível três é
**a mesma**, apontada por duas entradas da raiz. Meia dúzia de páginas
economizadas, e uma incoerência a menos: mapas separados poderiam divergir.

**E o mapa é conferido antes de ser instalado**, porque este é o último ponto
em que dá para dizer alguma coisa. O `traduzir` desce pelos índices do
endereço como o processador faria — e não consulta uma lista do que foi
mapeado, que concordaria com quem a preencheu. Ele confere que a base do
kernel cai onde a imagem foi posta, que o byte no ponto de entrada é o mesmo
que está no arquivo, que a memória física começa no zero, que o **código do
próprio iniciador** está na identidade, que a pilha está mapeada e que a
página de guarda dela **não** está.

**E a identidade precisa ser executável.** Foi o que faltou na primeira
tentativa de saltar: a identidade estava lá, mas marcada como **não
executável**. O mapa estava certo e a
permissão não, e o sintoma é o mesmo. Ela executa agora, e o kernel a larga
ao assumir as tabelas — com isso a entrada de topo volta a ser do espaço do
usuário, e desreferenciar zero dentro do kernel volta a ser uma falha em vez
de uma leitura do primeiro frame da máquina.

**O que o kernel recebe é uma `struct` de um pacote que os dois incluem.** O
`protocolo/` tem a entrega — mapa de memória, deslocamento físico, geometria
do vídeo — e as constantes do espaço virtual. Elas já estiveram declaradas
nos dois lados, com um teste do `xtask` exigindo que batessem; agora há um
lugar só, e a divergência deixou de ser uma coisa que um teste evita para ser
uma coisa que não pode acontecer.

A entrega carrega uma magia, uma versão e o próprio tamanho antes de qualquer
conteúdo, e o kernel confere os três antes de ler o resto. Uma ESP é um
sistema de arquivos: nada impede alguém de copiar um `.efi` novo sobre um
kernel velho, e um mapa de memória lido com deslocamento errado não dá erro —
dá um alocador que entrega páginas do firmware.

**A `.bss` é suja de propósito antes de ser zerada.** A UEFI não promete
páginas limpas, mas este firmware as entrega limpas — então apagar o
zeramento não mudava nada, e a conferência passava. Medido por mutação. Agora
o destino é preenchido com `0xA5` antes, e se o zerar sumir a conferência
encontra o byte e diz onde. O que está em jogo são os globais do kernel:
entregá-los com o que o dono anterior da página deixou dá um kernel que às
vezes boota.

**Como ele acha o kernel.** Seguindo uma corrente de três elos, porque o
firmware não diz "aqui está o seu disco": ele diz qual **imagem** está
rodando, a imagem sabe de qual **dispositivo** veio, e o dispositivo oferece
o **sistema de arquivos**. Numa máquina com dois discos bootáveis, a
diferença entre isso e "abrir a primeira ESP que aparecer" é carregar o
kernel de outra instalação.

**E como se sabe que ele leu o arquivo certo, inteiro.** Por um CRC-32 que ele
calcula sobre os bytes que chegaram à memória e imprime no relatório; o
`xtask` calcula o mesmo CRC sobre o mesmo arquivo no hospedeiro e compara. Sem
isso, "leu o kernel" e "leu o começo do kernel" seriam indistinguíveis daqui:
o buffer tem o tamanho do arquivo aconteça o que acontecer, e o cabeçalho ELF
está nos primeiros sessenta e quatro bytes.

Foi preciso ir além. Pedindo os sete mebibytes numa chamada só, este firmware
os devolve inteiros — então o laço de leitura dava uma volta e trocá-lo por
uma chamada não reprovava nada. Ele passou a pedir em pedaços de 64 KiB, dá
cento e oito voltas, e parar na primeira agora quebra o CRC. É o mesmo remédio
que o `grande.txt` do Btrfs recebeu, pelo mesmo diagnóstico.

**O leitor de ELF é conferido contra o `llvm-readobj`.** O iniciador e o
`xtask` são o mesmo projeto: conferir a leitura dele contra um número que eu
mesmo escrevi faria as duas metades concordarem no erro. O `llvm-readobj` lê o
mesmo arquivo que foi para a ESP e diz o ponto de entrada e quantos segmentos
carregáveis existem — e é com ele que a leitura do iniciador tem de bater.

É o `llvm-readobj` e não o `llvm-readelf` porque é esse que o componente
`llvm-tools` do `rustup` entrega; os dois são o mesmo binário do LLVM com
nomes diferentes. Pedir o segundo funcionava na minha máquina por acidente, já
que o pacote `llvm` do Ubuntu põe um `/usr/bin/llvm-readelf` — e num runner
limpo ele não existe. Foi assim que a primeira execução deste passo na CI
falhou, depois de o iniciador ter feito todo o trabalho dele certo.

**E as recusas são exercitadas com kernels estragados de propósito.** As
conferências do leitor não são falsificáveis contra um arquivo bom: desligar a
que exige que o ponto de entrada caia dentro de um segmento não reprovava
nada, porque o kernel de verdade sempre passa nela. Cada caso adultera uma
cópia do kernel num byte, põe na ESP e exige a recusa **pelo motivo certo** —
recusar pelo motivo errado manda quem depura procurar no lugar errado. E o
iniciador tem de sobreviver à recusa e desligar: um travamento ali é tão
defeito quanto aceitar o arquivo.

O corte é o mesmo método que o xHCI e o Btrfs seguiram aqui: cada etapa é
confirmada por um relatório antes de a seguinte ser escrita. Num bootloader
isso vale dobrado, porque um erro não produz um teste vermelho — produz uma
máquina que não liga, sem nada na tela e sem ninguém para perguntar.

**As tabelas e os protocolos da UEFI são declarados à mão**, e não vêm de um
crate. Trocar o
`bootloader` por um `uefi` seria trocar uma dependência por outra no lugar
exato onde este projeto quer saber o que está acontecendo. O que está no
`efi.rs` é a categoria que este projeto já escreve à mão em todo lugar —
protocolo e estrutura, transcrição de um documento público, sem aritmética de
bits a acertar.

**Como um erro de transcrição aparece.** É a pergunta que importa, porque um
campo no deslocamento errado não dá erro de compilação. Três coisas o
denunciam, e as três são conferidas antes de qualquer ponteiro ser chamado: a
**assinatura** de oito bytes que cada tabela carrega; o **CRC-32** do
cabeçalho, que o firmware calculou e nós recalculamos; e a **revisão**, que
tem de fazer sentido como versão da UEFI.

Foram medidas por mutação. Trocar de lugar os dois conjuntos de serviços na
tabela do sistema faz a assinatura dos serviços de boot sair como `RUNTSERV`;
calcular o CRC sem zerar o campo dele faz o CRC não conferir; ler o nome do
firmware um campo adiante devolve uma string vazia. Cada uma dessas reprova.

O primeiro erro de transcrição deste código foi exatamente do tipo que elas
existem para pegar, e custou uma execução: o GUID do sistema de arquivos
escrito como `0964e5b2` em vez de `964e5b22`. O primeiro campo de um GUID tem
oito dígitos hexadecimais, e um zero na frente desloca todos eles — o valor
continua sendo um `u32` plausível, e o firmware responde "protocolo não
suportado" sobre um handle que suporta o protocolo.

**E o que as conferências não pegam, o relatório pega.** Uma tabela válida não
garante que o campo número trinta esteja certo — o que garante é chamá-lo e
olhar o que volta. Por isso o `xtask` não confere só a presença das linhas:
ele lê os números. Pedimos 128 MiB ao emulador, então "121 MiB livres" é uma
afirmação; "3 MiB livres" — que foi o que saiu quando percorri o mapa de
memória com o passo errado — é um defeito.

**O passo do mapa de memória não é o tamanho da struct.** A UEFI devolve o
tamanho de cada descritor junto com o mapa, e o firmware tem direito de
acrescentar campos no fim. Não é hipótese: o EDK II que roda aqui declara
descritores de **48** bytes, e o formato documentado tem 40. Percorrer de
`size_of` em `size_of` sai do compasso no segundo descritor e lê o mapa
inteiro deslocado — com números plausíveis, porque os campos vizinhos também
são endereços e contagens.

**O relatório sai pela serial, e não pelo console do firmware.** O console é
um serviço de boot, e o trabalho deste programa termina depois de
`ExitBootServices` — exatamente onde esse console deixa de existir. A UART não
depende de ninguém, e é a mesma COM1 que o kernel abre logo em seguida: o
iniciador fala pelo canal em que o Duke já fala.

**E o `cargo xtask iniciador` é a sonda que afirma tudo isso.** Cinco boots no
firmware: um com o kernel de verdade, que só passa quando o kernel fala do outro
lado do salto, e quatro com kerneis estragados de propósito, que têm de ser
recusados pelo motivo certo.

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
$ cargo xtask test --arch aarch64 --video virtio
  suite de testes :: aarch64 :: 182 casos
  ...
  memoria: clonar compartilha sem copiar     ok
  memoria: fork do fork mantem a escrita     ok
  ...
  video: escrever descarrega so o que sujou  ok
  video: superficie apresenta so o dano      ok
  ...
  182 de 182 passaram
```

A mesma suíte roda nas duas máquinas de vídeo — `--video linear`, o padrão, e
`--video virtio` —, porque são dois caminhos de tela no kernel, e cada caso
que depende do adaptador confere o da máquina em que está.

O CI roda formatação, lints, as conferências de fonte de `cargo xtask
invariantes`, os testes do `xtask`, a conferência dos ELFs, o boot pela UEFI,
as sondas de fumaça contra o kernel de produção, e a suíte nas duas
arquiteturas em debug e release — e, nas duas, a suíte e a fumaça também na
máquina que só tem `virtio-gpu`.

**Por que o QEMU.** É a bancada do Duke, e continua sendo — decisão tomada
depois de comparar as alternativas. É a mesma do Redox, cujo caminho de todo
dia é o `make qemu`; o Linux testa nele, o emulador do Android e o UTM do Mac
são construídos sobre ele. O kernel não depende dele: fala com dispositivos
— VGA, `bochs-display`, virtio, xHCI, PL011 —, e o QEMU só os imita. O que é
dele de verdade é a bancada: o código de saída da suíte, o `screendump` e o
`sendkey` da fumaça.

Dois limites conhecidos, e o que fazer com cada um. A velocidade: sem
aceleração, o QEMU interpreta cada instrução, e com interface gráfica e
vários núcleos isso vai pesar — a resposta é o KVM no Linux e o HVF no Mac,
que ele já suporta, ligados por uma opção do `xtask` quando for preciso. A
fidelidade: o QEMU é bem-comportado demais, e tempos, caches e tabelas ACPI
com defeito de fábrica só aparecem em hardware de verdade. Esse limite
nenhum emulador resolve.

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
  inlinado em duke::arch::x86_64::disparar_falha_fatal
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
      do iniciador no x86, e uma API de mapeamento comum às duas.
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
- [x] **Fase 1 — Processos isolados.** Uma tabela de tradução por processo,
      carregador de ELF64 com validação de tudo que vem do arquivo, e
      `fork`/`exec` — hoje com cópia na escrita, contagem de donos por frame e
      resolução da falha nos dois anéis.
      **Fase 1 completa.**
- [x] **Fase 2 — Drivers.** Enumeração PCI, virtio-blk, virtio-net,
      roteamento de interrupção de PCI, timer do APIC local e framebuffer
      gráfico.
      **Fase 2 completa.**
- [x] **Fase 3 — Operação por uma pessoa.** O Duke precisa ser operável por
      alguém sentado na frente dele, nas duas arquiteturas, e não só por um
      agente pelo canal serial. Feito: framebuffer no ARM, por um driver do
      adaptador que as duas máquinas do QEMU expõem com os mesmos
      identificadores (`1234:1111`), e console de texto sobre ele: o mesmo
      texto que vai para o console humano é desenhado na tela, pelo mesmo
      funil, nas duas arquiteturas. Teclado no x86 (PS/2) e no ARM
      (virtio-input), e teclado USB por um driver xHCI próprio — três
      caminhos de hardware, o mesmo `abCde` no fim. E o interpretador, que
      despacha o que se digita pelo **mesmo** registro de comandos que o canal
      do agente publica.
      **Fase 3 completa.**
- [x] **Fase 4 — Sistema de arquivos.** A promessa da abertura, cumprida: o disco de
      testes é uma GPT de verdade, com uma ESP em FAT32 e uma raiz em Btrfs montadas pelas ferramentas do hospedeiro; e o
      VFS, com os programas embutidos servidos em `/bin`; e a leitura do disco
      em blocos de 16 KiB numa ida só, que é o tamanho de um nó de Btrfs; a
      tabela de partições; o superbloco do Btrfs, com crc32c conferido; e a
      tradução de endereço lógico para o disco; e a leitura dos itens de uma
      folha, que completa o mapa de pedaços e alcança a árvore de raízes; e a
      árvore de arquivos, com a raiz do disco montada em `/`, busca por nome,
      listagem de diretório e leitura de arquivo embutido e com extensão; e a
      tabela de descritores por processo, com `abrir`, `ler` e `fechar`
      exercitados por um programa sem privilégio que lê um arquivo do disco.
      E o **bootloader UEFI próprio**: o `iniciador/` é carregado pelo
      firmware a partir da ESP, confere as três tabelas da UEFI, lê a
      máquina, abre o `duke.elf` na mesma partição com o CRC conferido de
      fora, copia os segmentos, aplica as relocações, monta o mapa de
      tradução e o confere, sai dos serviços de boot e salta. O crate
      `bootloader` saiu. E a descida pela árvore do Btrfs, que tirou o
      limite de "uma folha" e fez o leitor atravessar nós internos — com a
      imagem de teste refeita para ter níveis de verdade. E o `fork` com
      cópia na escrita, com contagem de donos por frame; e um fio coletor
      que recolhe o espaço de endereços do processo morto sem esperar a vaga
      dele ser reaproveitada. **Fase 4 completa.**
- [x] **Fase 5 — O iniciador nas duas máquinas.** O `iniciador/` compila
      para `aarch64-unknown-uefi`, sobe no AAVMF e **boota o kernel**: ele
      confere as tabelas do firmware, descreve a memória e a tela, acha o
      device tree na tabela de configuração, abre o kernel na ESP, valida o
      ELF, copia a imagem para o endereço em que ela é ligada, sai dos
      serviços de boot, limpa o cache por conjunto e via, desliga a MMU e
      salta. Tudo até a validação do ELF é o mesmo código do x86, sem uma
      linha de `cfg`. O kernel distingue os dois protocolos de boot pela
      magia em `x0`, e o `-kernel` continua funcionando.
      **Fase 5 completa.**

- [ ] **Fase 6 — Vários núcleos.** Primeiro, e não no meio: fazer SMP depois
      da pilha gráfica significa reescrever o travamento dela inteiro. Partida
      dos APs, dados por CPU, IPI, e *TLB shootdown* — que é onde a
      invalidação hoje inofensiva de `com_descritor_da_folha` deixa de ser
      propriedade do chamador e vira obrigação da função. `threads.list` passa
      a dizer em que núcleo cada fio está, e a exigência que não pode ser
      negociada é esta: o canal continua respondendo quando **um** núcleo
      trava, porque é exatamente aí que alguém precisa dele.
- [ ] **Fase 7 — ABI compatível com Linux.** Não é preferência, é o que decide
      o projeto: ninguém porta um navegador para uma ABI nova, e sem navegador
      não há desktop. Um subconjunto compatível herda o software que já
      existe. E traz junto uma fronteira que é melhor dizer agora do que
      descobrir depois: um binário de Linux fala `syscall` direto e **não**
      passa pelo registro. O registro governa o sistema; o programa é um
      convidado dentro dele. O que o agente enxerga de um convidado é o que o
      sistema sabe sobre ele — não o que ele está pensando.
- [ ] **Fase 8 — Escrita em disco.** Um sistema de arquivos log-estruturado
      próprio, com journaling e `fsync` honesto. O Btrfs fica somente leitura,
      para imagens: escrever nele é uma B-tree com cópia na escrita, somas de
      verificação e transações — dos sistemas de arquivos mais difíceis que
      existem, por um ganho que um log-estruturado entrega por um décimo do
      trabalho.
- [ ] **Fase 9 — Rede e TLS.** IP, UDP, TCP, DHCP e TLS. Com `smoltcp` em vez
      de escrever a pilha: escrever TCP do zero é um a dois anos-pessoa e não
      diferencia o Duke em nada. O ARP que existe hoje era a prova de ponta a
      ponta mais barata possível, e cumpriu o papel dela.
- [ ] **Fase 10 — GPU, composição e a árvore semântica.** Começou antes da
      6, pela parte que não depende de vários núcleos. Feito: a pilha gráfica
      no desenho do Redox — um trait de adaptador que o compositor usa sem
      saber o que está embaixo, o retângulo de dano com o recorte que não dá a
      volta, o adaptador linear sobre o framebuffer, e `display.info` dizendo
      ao agente o que chegou à tela; o virtio-gpu como segundo adaptador atrás
      do mesmo trait, que também acende a tela das máquinas que não têm outro;
      e a árvore semântica, adiantada — `ui.tree` e `ui.act`, no desenho da
      acessibilidade do macOS, gerada do que está na tela e agindo pelo mesmo
      caminho da pessoa. O que o virtio-gpu 2D trouxe foi retângulo de dano e
      troca de página sem rasgo — não aceleração, que este texto chegou a
      prometer: medido, o framebuffer linear já pinta a tela cheia em 7 ms em
      release, com folga para 60 Hz. A faixa das superfícies devolvendo o
      endereço virtual quando uma superfície sai — antes, ela só subia, e uma
      superfície por janela a esgotaria. E o compositor, com ordem de
      empilhamento, camadas opacas e transparentes, e o console como a
      camada de baixo. E a barra superior, com o primeiro elemento que
      aceita `press` — pela árvore e pela F1, pelo mesmo caminho. E o console
      rolando, em vez de recomeçar do topo. E o mouse — PS/2 no x86,
      `virtio-tablet` no ARM, USB nas duas —, com o cursor como camada transparente fixa no
      topo e o clique no mesmo botão. E o servidor de janelas, em userspace
      como o do Redox — o kernel compõe e tem os drivers, o servidor decide
      janelas, decoração, foco e roteamento —, começou pela base: programas
      de usuário em Rust, compilados à parte, com monte e `mapear`. A
      seguir: a leitura que bloqueia e o canal de eventos, as superfícies do
      compositor para processos, o servidor, a árvore semântica atravessando
      a fronteira, e a primeira janela, o "Sobre o Duke" pela barra. Mais
      adiante, o console como uma janela (o Terminal) e a tipografia.
      E aqui a inversão do projeto encontra a interface gráfica. O servidor de
      janelas publica uma **árvore semântica** — que janelas existem, que
      controles, o que cada um faz — e os pixels são a renderização dela, do
      mesmo jeito que o texto do console é a renderização de um registro
      tipado. O agente opera por essa árvore, e não por captura de tela: nada
      de adivinhar botão por pixel, que é como a automação de interface
      funciona em toda parte hoje e é por isso que ela quebra a cada tema
      novo. Acessibilidade e teste automatizado de interface caem no colo,
      porque são a mesma árvore lida por outro consumidor.
- [ ] **Fase 11 — Toolkit e linguagem visual.** O "jeito" do sistema mora
      aqui, não no kernel. Cada widget declara o que é e o que faz, e a árvore
      semântica da fase 10 é **gerada** disso em vez de escrita à mão — senão
      ela vira a segunda superfície que este projeto existe para não ter.
- [ ] **Fase 12 — Consentimento e auditoria.** Se um agente pode fazer tudo
      que uma pessoa faz, o modelo de permissão precisa ser **mais** forte que
      o de um desktop comum, e não mais fraco. Três coisas: quem pediu — a
      pessoa na frente da máquina ou o agente pelo canal —, o que foi feito, e
      um registro que a pessoa possa ler depois e desfazer. Junto com o resto
      do que um desktop precisa: assinatura de código, sandbox por aplicativo,
      cadeia de boot confiável.
- [ ] **Fase 13 — Hardware real e distribuição.** Instalador, atualização A/B
      com rollback, imagens assinadas, ACPI de verdade, NVMe, placa de rede
      real, watchdog. É onde projetos assim costumam morrer, e é por isso que
      vem por último: até aqui o emulador é hardware suficiente.

## Licença

MIT OU Apache-2.0, a critério de quem usa.

Partes da pilha gráfica são porte de código do Redox OS, sob MIT, com o
aviso de copyright deles — ver [`THIRD_PARTY.md`](THIRD_PARTY.md).
