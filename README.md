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
emulador tem **uma única** porta serial, e ela é do canal do agente: não sobra
uma segunda para ecoar log em texto, como o x86 tem. Por um bom tempo o canal
foi literalmente a única interface do sistema ali, e os registros só saíam por
`log.tail`.

Hoje sai também na tela. O kernel programa o adaptador de vídeo por conta
própria e desenha nele o mesmo texto que manda ao console humano — o que dá a
uma pessoa sentada na frente da máquina a mesma leitura nas duas
arquiteturas, sem depender de um terminal no hospedeiro.

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
cargo xtask elf                      # confere os ELFs de usuário por fora
```

Com o kernel rodando, converse com ele de outro terminal:

```bash
$ cargo xtask agent system.info
{"jsonrpc":"2.0","id":1,"result":{"arch":"x86_64","kernel":"duke",
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
 "framebuffer":{"width":1280,"height":720,"stride":1280,
 "bytes_per_pixel":4,"pixel_format":"bgr"},"log_records":8}}
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
| `disk.partitions` | A tabela de partições do disco, lida da GPT |
| `btrfs.info` | O superbloco do Btrfs da partição de dados |
| `btrfs.chunks` | O mapa de pedaços e a raiz da árvore de pedaços |
| `fs.mounts` | O que está montado na árvore de arquivos, e de que tipo |
| `fs.list` | Lista um diretório da árvore (`path`) |
| `fs.read` | Lê um arquivo da árvore e devolve o conteúdo (`path`, `offset`, `max`) |
| `keyboard.read` | O que foi digitado no teclado da máquina, e os contadores dele (`max`) |
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
    │   ├── mod.rs    entrada pelo iniciador UEFI, CPUID, portas de I/O
    │   ├── gdt.rs    GDT, TSS e pilha dedicada ao double fault
    │   ├── idt.rs    IDT e handlers de exceção e interrupção
    │   ├── pic.rs    controlador 8259 e timer PIT
    │   ├── paginacao.rs  assume as tabelas de página do iniciador
    │   └── uart.rs   UART 16550 por port-mapped I/O
    └── aarch64/
        ├── mod.rs     boot em assembly, cabeçalho de imagem arm64, MIDR_EL1
        ├── vetores.rs tabela de vetores de exceção (VBAR_EL1)
        ├── gic.rs     GIC v2 e timer genérico do ARM
        ├── mmu.rs     tabelas de tradução e ativação da MMU
        ├── uart.rs    PL011 por memory-mapped I/O
        ├── fdt.rs     leitor de device tree escrito à mão
        └── linker.ld  layout de memória e símbolos de boot

iniciador/src/       a aplicação UEFI que o firmware carrega da ESP
├── main.rs          confere as tabelas da UEFI, abre o kernel e relata
├── efi.rs           as tabelas e os protocolos, declarados à mão
├── elf.rs           o pedaço do ELF64 que um carregador precisa entender
├── carga.rs         copia os segmentos, reloca e desenha o mapa
├── paginas.rs       as quatro tabelas de tradução, e como percorrê-las
└── salto.rs         a saida dos servicos de boot, e a entrega da maquina

protocolo/src/       a ABI entre o iniciador e o kernel
├── lib.rs           o que e entregue ao kernel, com magica e versao
└── mapa.rs          onde cada coisa mora no espaço virtual
├── serial.rs        a COM1, que sobrevive ao fim dos serviços de boot
└── crc32.rs         o CRC-32 do Ethernet, que confere os cabeçalhos

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
| Carga | `iniciador/`, aplicação UEFI deste projeto | protocolo de boot do arm64 |
| Artefato | imagem de disco | binário cru, cabeçalho de 64 bytes |
| Chegamos em | long mode, com pilha e paginação | MMU desligada, sem pilha |
| Mapa de memória | struct `BootInfo` pronta | device tree, parseado por nós |
| Seriais | duas UARTs 16550 (port I/O) | uma PL011 (MMIO) |
| Exceções | IDT de ponteiros, contexto salvo pela CPU | vetores de código, contexto salvo à mão |
| Pilha de exceção | IST, índice no TSS | `SP_EL1`, trocado por hardware |
| Guard page da pilha | instalada pelo iniciador | construída antes de ligar a MMU |
| Interrupções | PIC 8259 + timer PIT | GIC v2 + timer genérico |
| Serial do agente | UART 16550 na IRQ 3 | PL011 no INTID 33 (SPI 1) |
| Vídeo | VGA da máquina `pc`, modo posto pelo firmware e mapeado pelo iniciador | `bochs-display` no PCI, modo posto por nós |
| Teclado | controlador 8042, scancode na IRQ 1 | `virtio-input` no PCI, evento na fila |
| Teclado USB | `qemu-xhci` no PCI, protocolo de boot do HID | o mesmo controlador, o mesmo driver |
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

As chamadas de sistema são nove: `sair`, `escrever`, `id`, `ceder`, `bifurcar`,
`executar`, `abrir`, `ler` e `fechar`.

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
mesma implementação do emulador, com a mesma interface de programação. É por
isso que um driver só (`tela/bochs.rs`) acende a tela nas duas arquiteturas,
em vez de virtio-gpu de um lado e outra coisa do outro.

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
  "phase": "0",
  "cpu_vendor": "ARM Limited",
  ...
}

duke> nao.existe
comando desconhecido: nao.existe
`ajuda` lista os 26 que existem
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
ele pega a última chave dela, calcula a sucessora e desce da raiz outra vez.
É uma leitura de nó a mais por folha, por nível. A alternativa é o que o
Btrfs de verdade faz — guardar o caminho inteiro, um nó por nível, e subir só
o necessário para achar o irmão à direita —, que é mais rápido e custa um
buffer de nó **por nível**, vivo durante todo o percurso. A escolha aqui é a
barata em memória: um buffer só.

A sucessora de uma chave não é somar um. Os três campos têm pesos
diferentes, e somar ao último funciona em todo caso menos nos dois em que ele
satura — que é exatamente onde o percurso pararia cedo, perdendo entradas de
um diretório sem erro nenhum.

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

**O que não está lá**: escrita, `abrir` e `fechar`. Entram quando houver quem
os chame. Um método de trait que compila e não tem chamador é pior que
ausência — ele parece uma opção disponível, e o primeiro a usá-lo descobre que
nunca foi exercitado.

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

**Onde o ARM para hoje, e por quê.** O iniciador do ARM sobe no AAVMF, faz
tudo que está acima, confere a tabela de relocações do kernel entrada por
entrada — e então **recusa saltar**, em voz alta:

```
$ cargo xtask iniciador --arch aarch64
  [iniciador] vivo em aarch64, carregado pelo firmware
  [iniciador] firmware `Ubuntu distribution of EDK II` revisao 0x10000
  [iniciador] as tres tabelas conferem, por assinatura e por crc
  [iniciador] memoria: 33 descritores de 48 bytes, 192 MiB descritos, 122 MiB livres
  [iniciador] video: 800x600 bgr, 800 pixels por linha, buffer em 0x43d00000
  [iniciador] esp: duke.elf aberto e lido, 5830616 bytes, crc 0xe2fe991d
  [iniciador] elf: 5830616 bytes, entrada em 0x40080000, endereco fixo
  [iniciador] kernel: 3 segmentos, 0x40080000..0x401ab000, 717 KiB do arquivo
  [iniciador] fim do relatorio
  [iniciador] ERRO o salto no aarch64 ainda nao existe
```

O que falta é justamente o que a UEFI não padroniza: montar as tabelas no
formato VMSAv8, programar `MAIR_EL1` e `TCR_EL1`, trocar o `TTBR` com as
barreiras que a arquitetura exige, e entregar ao kernel o device tree que
hoje ele recebe em `x0` pelo protocolo de imagem crua do arm64. Esse último
item é o que torna a etapa maior do que parece — ela não é só escrever o
iniciador, é trocar o protocolo de boot do lado do kernel.

A linha `endereco fixo` do relatório é o registro disso: o kernel do ARM é
ligado num endereço fixo e não tem relocação nenhuma, porque quem o carrega
hoje não reloca nada. A próxima etapa vai ter de respeitar aquele endereço
ou tornar o kernel relocável, e a sonda exige a linha para que a escolha não
seja feita por acidente.

**A sonda do ARM não é a do x86 com menos linhas.** Ela exige o relatório até
a validação do ELF, exige a recusa explícita do salto, e roda as **mesmas
quatro recusas** com kernels estragados de propósito — que valem ali
exatamente como valem no x86, porque o leitor de ELF é o mesmo código.

Uma delas só passou a valer depois de um conserto: o caso "um kernel de outra
arquitetura" escrevia `0xB7` fixo no campo `e_machine`, o que no ARM é copiar
o valor certo por cima dele mesmo. O iniciador aceitava o arquivo, com razão,
e a rodada reprovava. O byte agora é o da **outra** arquitetura, seja qual
for a de quem está rodando.

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
    Duke :: agent-native :: x86_64 :: fase 0
  =============================================
  [    0]     0ms info boot  Duke iniciado em x86_64, fase 0

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

**A identidade da RAM não é para o kernel.** É para os poucos ciclos entre o
`mov cr3` e o salto: no instante seguinte à troca, o processador busca a
próxima instrução no código do iniciador, que mora num endereço baixo. Sem
ela, a busca falha — e uma falha de página sem tabela de exceções instalada é
um triple fault, a máquina reiniciando sem nada na tela.

Foi exatamente o que aconteceu na primeira tentativa de saltar: a identidade
estava lá, mas marcada como **não executável**. O mapa estava certo e a
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

**O ARM continua fora.** Lá o boot é o protocolo de imagem crua do arm64, que
não precisa de bootloader nenhum — o QEMU lê o cabeçalho de 64 bytes, deposita
a imagem e salta. Um iniciador UEFI para aarch64 é a mesma aplicação com outro
alvo e outro firmware, e é o passo seguinte natural desta peça.

**E o `cargo xtask iniciador` é a sonda que afirma tudo isso.** Cinco boots no
OVMF: um com o kernel de verdade, que só passa quando o kernel fala do outro
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
$ cargo xtask test --arch aarch64
  suite de testes :: aarch64 :: 145 casos
  ...
  memoria: clonar compartilha sem copiar     ok
  memoria: fork do fork mantem a escrita     ok
  fios: o coletor nao recolhe quem esta de pe ok
  145 de 145 passaram
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
- [ ] **Fase 3 — Operação por uma pessoa.** O Duke precisa ser operável por
      alguém sentado na frente dele, nas duas arquiteturas, e não só por um
      agente pelo canal serial. Feito: framebuffer no ARM, por um driver do
      adaptador que as duas máquinas do QEMU expõem com os mesmos
      identificadores (`1234:1111`), e console de texto sobre ele: o mesmo
      texto que vai para o console humano é desenhado na tela, pelo mesmo
      funil, nas duas arquiteturas. Falta: teclado no x86 (PS/2) e no ARM
      (virtio-input), e teclado USB por um driver xHCI próprio — três
      caminhos de hardware, o mesmo `abC` no fim. E o interpretador, que
      despacha o que se digita pelo **mesmo** registro de comandos que o canal
      do agente publica.
      **Fase 3 completa.**
- [ ] **Fase 4 — Sistema de arquivos.** A promessa da abertura que falta
      cumprir. Feito: o disco de testes é uma GPT de verdade, com uma ESP em
      FAT32 e uma raiz em Btrfs montadas pelas ferramentas do hospedeiro; e o
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
- [ ] **Fase 5 — O iniciador nas duas máquinas.** O `iniciador/` já compila
      para `aarch64-unknown-uefi` e sobe no AAVMF: ele confere as tabelas do
      firmware, descreve a memória e a tela, abre o kernel na ESP e valida o
      ELF inteiro — o mesmo código do x86, sem uma linha de `cfg`, porque a
      UEFI é a mesma especificação nas duas. Falta o que ela não padroniza:
      as tabelas no formato VMSAv8, o `MAIR_EL1` e o `TCR_EL1`, a troca do
      `TTBR` com as barreiras da arquitetura, e a entrega ao kernel — que
      exige trocar, do lado dele, o protocolo de imagem crua do arm64 pela
      `Entrega`, com o device tree vindo da tabela de configuração da UEFI
      em vez de `x0`.

## Licença

MIT OU Apache-2.0, a critério de quem usa.
