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

Requisitos: Rust nightly (instalado automaticamente pelo `rust-toolchain.toml`),
os pacotes do emulador para as arquiteturas desejadas e o `swtpm`, que é o TPM
2.0 das máquinas de teste — a âncora da persistência, ver
[`docs/PERSISTENCIA.md`](docs/PERSISTENCIA.md).

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
cargo xtask persistencia             # vários boots sobre o mesmo disco e o mesmo TPM
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

Vários agentes podem operar a mesma máquina ao mesmo tempo, cada um no seu
canal — a serial é a sessão 0, e as portas do console virtio, as sessões 1
a 4. Uma porta só fala depois do aperto de mão cifrado, com a chave do
agente dela; o `xtask` gera as chaves em `target/chaves/` na primeira vez e
as grava na imagem — ver [Vários agentes](#vários-agentes):

```bash
$ cargo xtask agent --canal 2 agent.session
{"jsonrpc":"2.0","id":1,"result":{"session":2,"transport":"virtio-console",
 "authenticated":true,"agent":"agente-2","key":"…","since_ms":4210}}
```

## Comandos disponíveis

| Comando | Descrição |
|---|---|
| `agent.ping` | Verifica se o canal está vivo |
| `agent.describe` | Lista todos os comandos e parâmetros |
| `agent.session` | A sessão deste pedido: o número que o kernel deu ao canal, o transporte e quem provou a chave |
| `agent.sessions` | As sessões: a serial e cada porta do console virtio, conectada ou não, quem está nela, as perdas e as recusas |
| `agent.list` | Os agentes conectados agora: a porta, o nome, o papel, há quanto tempo, quantos arrendamentos, o último comando e a última ação, cada um com há quanto tempo; quem agiu por último e o texto da barra — nunca parâmetros |
| `agent.registry` | Quem pode entrar pelas portas: a chave do Duke e cada agente registrado, com a origem |
| `person.registry` | Quem pode entrar pelos consoles: cada pessoa, com identificador, nome, papel, estado e sessões abertas — sem credencial |
| `admin.challenge` | Um desafio de uso único para uma operação administrativa nesta sessão |
| `admin.execute` | Uma operação administrativa com a prova de um administrador (`challenge`, `command`, `params`, `admin`, `proof`): `agent.register`, `agent.revoke`, `policy.assign`, `policy.write`, `person.register`, `person.revoke`, `credential.rotate`, `session.revoke`, `lease.revoke`, `message.send`, `message.read`, `message.ack`, `message.purge`, `message.purge_mailbox`; e, com as assinaturas de um quórum em `signatures`, `admin.revoke` |
| `audit.tail` | Os registros mais recentes da auditoria encadeada, com o que basta para refazer cada elo, e quais já estão no journal (`count`) |
| `audit.head` | A cabeça da auditoria — o elo do último registro, para ancorar fora da máquina —, a âncora e quantos há |
| `audit.verify` | Refaz a cadeia guardada a partir da âncora e diz se cada elo confere |
| `policy.show` | A política em vigor: papéis, permissões, recursos, taxas, o papel da serial e se veio do disco |
| `system.info` | Kernel, CPU, vídeo, uptime, o RTC e mecanismo de guarda da pilha |
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
| `debug.trigger` | Dispara uma exceção de propósito (`kind`: `breakpoint`, `fatal`, `stack_overflow`, `hang_core`; no ARM também `stack_overflow_edge`) |
| `pci.list` | Dispositivos do barramento PCI, com fabricante, modelo e função |
| `disk.info` | Capacidade e estado do disco virtio, se houver um |
| `disk.read` | Lê um setor de 512 bytes e o devolve em hexadecimal (`sector`, `length`) |
| `disk.partitions` | A tabela de partições do disco, lida da GPT |
| `btrfs.info` | O superbloco do Btrfs da partição de dados |
| `btrfs.chunks` | O mapa de pedaços e a raiz da árvore de pedaços |
| `fs.mounts` | O que está montado na árvore de arquivos, e de que tipo |
| `fs.list` | Lista um diretório da árvore (`path`) |
| `fs.read` | Lê um arquivo da árvore e devolve o conteúdo (`path`, `offset`, `max`): em `utf-8` quando o arquivo inteiro é texto — o corte recua até o fim de um caractere —, em `base64` quando não |
| `fs.stat` | O que um caminho do armazém é agora: o tipo, a versão, o tamanho, o dono e o arrendamento; e o uso e a cota de quem pede, e a ocupação do volume (`path`) |
| `fs.write` | Grava um arquivo no armazém contra a versão lida (`path`, `expect_version`: 0 cria), com o conteúdo de exatamente um: `content` (texto), `draft` (um rascunho) ou o anexo (binário, declarado em `attachment` no canal); confirmado só depois do commit |
| `fs.append` | Acrescenta ao fim de um arquivo do armazém, contra a versão de agora (`path`, `content` ou o anexo, `attachment`, `expect_version`) |
| `fs.delete` | Apaga um arquivo do armazém, contra a versão de agora (`path`, `expect_version`) |
| `fs.mkdir` | Cria um diretório no armazém, num pai que existe (`path`) |
| `fs.rmdir` | Remove um diretório vazio do armazém, contra a versão de agora (`path`, `expect_version`) |
| `fs.rename` | Move um arquivo ou uma árvore do armazém; o gate decide os dois caminhos, e cada nó movido ganha versão nova (`path`, `to`, `expect_version`) |
| `fs.batch` | Até 32 operações num lote só — tudo ou nada, um commit (`ops`: `op`, `path`, `to`, `expect_version`, `content`, `draft`, `offset`/`length` no anexo; `attachment`) |
| `fs.draft` | Acrescenta o anexo (ou `content`) a um rascunho de um caminho, para um arquivo maior que um anexo (`path`, `draft`, `content`, `attachment`) |
| `fs.discard` | Descarta um rascunho seu, com os blocos dele (`path`, `draft`) |
| `fs.claim` | Arrenda um arquivo do armazém para esta sessão (`path`, `ttl_ms`); sem preempção |
| `fs.release` | Solta o arrendamento desta sessão num arquivo do armazém (`path`) |
| `net.info` | Endereço e contadores da placa de rede, se houver uma |
| `net.arp` | Pergunta quem atende por um IPv4 e espera a resposta (`ip`, `from`) |
| `video.sample` | Amostra a tela numa grade de cores (`columns`, `rows`) |
| `display.info` | A pilha gráfica: adaptador ativo, telas, as camadas do compositor, memória das superfícies, o último retângulo que chegou à tela e, no virtio-gpu, o que atravessou para o dispositivo |
| `ui.tree` | A árvore semântica do que está na tela: papel, rótulo, valor, moldura e ações de cada elemento; de cada campo, a versão e o arrendamento |
| `ui.act` | Age sobre um elemento pelo mesmo caminho de quem está na frente da máquina (`id`, `action`, `value`, `expect_version`) |
| `ui.claim` | Arrenda um campo para esta sessão, por um prazo (`id`, `ttl_ms`) |
| `ui.release` | Solta o arrendamento desta sessão num campo (`id`) |
| `message.send` | Manda uma mensagem a outro titular, como a sessão que pede (`to`, `body`, `nonce`, `ttl_ms`) |
| `message.read` | Lê a caixa da sessão, em ordem, sem consumir (`after`, `max`) |
| `message.ack` | Confirma uma mensagem lida: ela sai da caixa (`id`, `expect_version`) |
| `message.cancel` | Cancela uma mensagem mandada, enquanto ninguém a leu (`id`, `expect_version`) |
| `message.status` | O estado de uma mensagem mandada ou recebida (`id`) |
| `keyboard.read` | O que foi digitado no teclado da máquina desde a última leitura de quem pede, e os contadores dele (`max`) |
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
├── identidade.rs    quem é quem: a chave do Duke, os agentes, os administradores e os desafios
├── pessoas.rs       quem entra pelos consoles: o registro, as credenciais e as sessões
├── persistencia.rs  o journal na partição de estado, ancorado no TPM: o estado de autoridade que sobrevive ao boot
├── coordenacao.rs   versões e arrendamentos: quem edita cada campo agora
├── mensagens.rs     as mensagens entre titulares: um recurso, pelo mesmo ponto de decisão
├── armazem.rs       o armazém montado em /armazem: o lote, do gate ao commit — reconfirmação, arrendamento, cota, rascunhos, cada um no seu lugar
├── volume.rs        o volume do armazém na partição própria: blocos cifrados, o journal dos metadados, o ponto de commit no de estado
├── nativo.rs        a interface nativa: o registro como API dos programas, pelo mesmo gate
├── atividade.rs     quem está agindo: os agentes conectados e quem agiu por último
├── autorizacao.rs   o ponto único de decisão: papel, permissão, recurso, taxa e auditoria
├── sessoes.rs       quem está em cada porta, e as chaves do transporte cifrado dela
├── aleatorio.rs     o gerador de números aleatórios, semeado pelo virtio-rng
├── barra.rs         a barra superior: o nome, os botões, quem está agindo e o tempo ligado
├── ponteiro.rs      o mouse: onde ele está, o cursor, e o clique
├── eventos.rs       canais de eventos: o kernel publica, um processo escuta e dorme
├── superficies.rs   as camadas do compositor que são de processos, e quem é dono de cada uma
├── pseudoterminal.rs o interpretador visto de um processo: escrever é digitar, ler é a saída
├── ui.rs            a árvore semântica: o que está na tela, e o que se faz com cada coisa
├── teclado.rs       o que uma pessoa digita chega ao kernel
├── pci.rs           enumeração do barramento PCI
├── particoes.rs     a tabela de partições GPT do disco: ESP, raiz e a de estado
├── rede.rs          o mínimo de protocolo acima do transporte de quadros
├── traps.rs         contabilidade de exceções e modo post-mortem
├── nucleos.rs       os vários núcleos: quem ligou, o pulso de cada um, o aviso e o travamento de propósito
├── trava.rs         a trava justa, por senha, que todo o kernel usa
├── ordem_das_travas.rs  só na suíte: a ordem das travas, conferida a cada `lock` — nenhum par em duas ordens
├── irq.rs           contadores de interrupções de hardware
├── tempo.rs         contagem de tempo desde o boot
├── relogio.rs       o relógio de parede: o RTC (CMOS no x86, PL031 no ARM)
├── tpm.rs           o TPM 2.0 pelas interfaces TIS e CRB: o transporte da âncora
├── qemu.rs          encerramento do emulador para testes
├── quedas.rs        quedas de energia em pontos exatos, só na compilação da bancada
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
│   ├── console.rs   o canal local dos agentes: uma porta do console virtio por agente
│   ├── entropia.rs  a fonte de entropia: o virtio-rng
│   └── teclado.rs   o teclado e o tablet do ARM, por virtio
├── usb/
│   ├── mod.rs       o barramento por onde entram os periféricos de verdade
│   ├── xhci.rs      o controlador xHCI: a porta de entrada do USB
│   └── hid.rs       os relatórios de um teclado e de um mouse USB, traduzidos
├── agent/
│   ├── mod.rs       laço de atendimento e despacho
│   ├── json.rs      o JSON do canal: o de `protocolo::json`, o mesmo dos programas
│   ├── protocol.rs  envelope JSON-RPC 2.0
│   ├── registry.rs  registro de comandos auto-descritivo
│   ├── sessao.rs    as sessões: um agente por canal, e quem está agindo
│   ├── seguro.rs    a sessão cifrada de uma porta: quadros, aperto de mão, decifrar
│   ├── administracao.rs  as operações administrativas, e a prova que cada uma exige
│   └── commands.rs  implementações dos comandos
└── arch/
    ├── mod.rs        seleção da arquitetura em tempo de compilação
    ├── x86_64/
    │   ├── mod.rs    entrada pelo iniciador UEFI, CPUID, portas de I/O
    │   ├── gdt.rs    GDT, um TSS por núcleo e as pilhas de emergência
    │   ├── acpi.rs   as tabelas da ACPI: a MADT, que lista os núcleos
    │   ├── smp.rs    a partida dos outros núcleos, o descarte de tradução e a parada, por NMI
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
        ├── gic.rs      GIC v2, timer genérico e os avisos entre núcleos (SGI)
        ├── smp.rs      a partida dos outros núcleos pelo PSCI, e a parada
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
├── json.rs          JSON sem alocação (streaming + varredura), do kernel e dos programas
├── mapa.rs          onde cada coisa mora no espaço virtual
└── usuario.rs       as chamadas de sistema, os erros e o mapa do espaço do usuário

tipografia/src/      a fonte e o desenho de texto, dos dois lados da fronteira
└── lib.rs           os estilos, os glifos, a mistura e a escrita numa memória de pixels

sigilo/src/          o canal seguro, dos dois lados da conversa
├── lib.rs           a identidade é a chave, e por que o Noise
├── aperto.rs        o aperto Noise_IK_25519_ChaChaPoly_BLAKE2s, e o transporte
├── cifra.rs         o estado de uma cifra: a chave e o contador
├── resumo.rs        o BLAKE2s, o HMAC e os dois HKDF
├── administracao.rs a prova de uma operação administrativa, presa ao contexto
├── quorum.rs        M de N credenciais provando o mesmo conteúdo canônico
├── gerador.rs       ChaCha20 com apagamento rápido da chave
├── credencial.rs    o verificador Argon2id de uma senha, conferido em tempo constante
├── pessoas.rs       o identificador de uma pessoa e o formato do registro delas
├── quadro.rs        como as mensagens se delimitam no fluxo da porta
└── registro.rs      o formato dos arquivos de chaves autorizadas

politica/src/        a política de autorização, a mesma no kernel e no hospedeiro
├── lib.rs           a cadeia de decisão, e a política padrão da imagem
├── permissao.rs     o vocabulário fechado de permissões, e quais são sensíveis
├── codigo.rs        os códigos de decisão: ALLOW, DENY_*, RATE_LIMIT, INVALID_ARGUMENT, ERROR
├── arquivo.rs       o formato, a validação, a decisão, as regras de mudança e o texto que volta igual
├── caminho.rs       a forma normal dos caminhos, a mesma do VFS
├── taxa.rs          o balde de pedidos e a janela de apertos de mão
├── arrendamento.rs  a versão e o arrendamento de cada recurso compartilhado
├── mensagens.rs     as caixas, os estados, as cotas e os nonces das mensagens
├── manifesto.rs     o manifesto de um programa: o nome, o que ele exerce, e o resumo da imagem
├── sigiloso.rs      o texto que sai da memória zerado: o corpo e a resposta que o leva
└── auditoria.rs     os registros e a cadeia de elos BLAKE2s

armazem/src/         o armazém como conta pura: caminhos, diretórios, versões, donos e cotas; preparar e aplicar um lote
├── lib.rs           a árvore de arquivos e diretórios, a versão do armazém inteiro, o lote inteiro ou nada
├── bloco.rs         o bloco de 4 KiB do volume: XChaCha20-Poly1305 com o id do conteúdo e o índice no nonce
├── mapa.rs          os blocos em uso, refeitos dos metadados no boot; reservar e soltar faixas
├── registro.rs      as entradas do journal dos metadados: nós, extensões, movimentos, a geometria do volume
└── testes.rs        criar, substituir, renomear, os diretórios, as cotas, os lotes sorteados e a reposição

diario/src/          o journal da persistência: registros cifrados, encadeados e ancorados
├── lib.rs           o formato, a leitura que confere cada registro, o escritor, o julgamento contra a âncora e o relógio que não volta
├── estado.rs        o que os registros do estado administrativo dizem: resultados, e não pedidos
└── testes.rs        o journal cortado em cada setor, cada bit trocado, registros de outro journal e fora de ordem

ancora/src/          a âncora da persistência: um contador monotônico num TPM 2.0
├── lib.rs           os comandos do TPM byte a byte, a sessão HMAC salgada pela EK, e o que um contador ausente ou estranho quer dizer
├── cripto.rs        o KDFa, o KDFe, o sal por ECDH em P-256 e a cifra de parâmetro, como a especificação do TPM os compõe
└── testes.rs        os bytes que a especificação fixa; `tests/swtpm.rs`, a sessão contra o swtpm, com um interposto no barramento

aparencia/src/       a linguagem visual, dos dois lados da fronteira
└── lib.rs           a paleta, onde cada cor vai, as medidas e os estilos de texto pelo uso

toolkit/src/         os widgets: desenho e árvore semântica do mesmo estado
├── lib.rs           a regra, e o que existe
├── arvore.rs        o trait, e as viagens pela árvore: desenhar, descrever, achar
├── interface.rs     a árvore de uma janela e o foco: o aperto, a tecla e a ação do agente
├── widgets.rs       o texto, o botão, o campo, a coluna e a linha
├── area.rs          a área de texto: a grade do Terminal, que redesenha só a linha que mudou
├── tela.rs          a memória de pixels onde os widgets desenham
└── testes.rs        o layout, o desenho e a descrição, conferidos no hospedeiro

programas/           os programas de usuário, compilados à parte do kernel
├── usuario.ld       o mapa de um programa: três segmentos a partir de BASE, e a nota do manifesto
└── src/
    ├── lib.rs       o runtime: a entrada, o pânico e o contrato do `principal`
    ├── sistema.rs   as chamadas de sistema, uma função por chamada
    ├── nativo.rs    a interface nativa: pedir ao sistema um comando do registro
    ├── manifesto.rs `manifesto!`: o que o programa declara, numa nota do executável
    ├── monte.rs     o monte do processo, sobre `mapear`
    ├── saida.rs     uma linha formatada por chamada de `escrever`
    ├── desenho.rs   retângulos e texto, com a fonte do console
    ├── superficie.rs uma camada do compositor com os pixels no processo
    ├── janela.rs    a moldura, o arrasto e a caixa de fechar, e a interface dentro dela
    └── bin/
        ├── ola.rs        o primeiro programa em Rust: monte, formatação e pilha
        ├── memoria.rs    confere `mapear` e o monte do lado de quem pede
        ├── ponteiros.rs  pede ao kernel que escreva no código, e confere a recusa
        ├── autoridade.rs confere de dentro que o processo age com o papel de quem o lançou
        ├── eco.rs        escuta um canal de eventos e diz o que chega
        ├── cedente.rs    cede a vez duas mil vezes, em várias cópias, e confere que voltou inteiro
        ├── janelas.rs    o servidor de janelas: moldura, foco, arrasto, ordem e fechar
        ├── superficie.rs desenha numa superfície, bifurca, fecha e sai sem fechar
        ├── herdeira.rs   depois de um `exec`, fecha a superfície herdada sem perder a sua
        ├── cobrir.rs     um programa hostil: pinta uma barra falsa e tenta pô-la sobre a do kernel
        ├── pseudo.rs     digita no interpretador pelo pseudo-terminal, e lê a resposta
        ├── entrada.rs    uma janela fora do servidor, com o canal de entrada dela
        ├── formulario.rs dois campos e dois botões do toolkit, que o agente preenche
        ├── nativo.rs     um programa nativo: confere de dentro o que a interface nativa promete
        ├── contido.rs    declara só `system.read`, e confere que o manifesto limita o resto
        ├── anonimo.rs    o único sem manifesto: não exerce nada, nem lançado pelo sistema
        ├── guardar.rs    guarda no armazém pelo `pedir`: a versão, o conflito, a leitura pelo descritor e o `MUDOU`
        ├── legado.rs     pede, não busca a resposta e troca de imagem: a nova não a encontra
        └── terminal.rs   o Terminal: o interpretador numa janela, pelo pseudo-terminal

xtask/src/
├── main.rs          a ferramenta de build, teste e diagnóstico do projeto
└── persistencia.rs  a bancada de persistência: a mesma máquina em vários boots, com corte de energia
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

A consequência no ARM é uma regra: **nada troca de fio de dentro de um
handler**. Lá a pilha de exceção é do núcleo, e um `svc` de dentro de uma
chamada de sistema salvaria o fio com os quadros do handler nela; retomado
noutro núcleo, ele voltaria pela pilha de exceção daquele, acima do topo, e
no mesmo núcleo, depois de outro fio ter feito igual, pelos quadros do
outro — devolvendo ao processo o quadro de usuário alheio. A chamada
`ceder` fazia exatamente isso: foi o "estouro" que o CI viu uma vez (a
leitura logo acima do topo da pilha do núcleo 1, que é a guarda da vaga
seguinte), reproduzido em 150 ms com várias cópias de um programa que
cede em laço (`usuario: varios processos cedem em varios nucleos`). Agora
uma chamada que quer dar a vez só pede (`fios::pedir_cessao`), e o handler
troca sobre o quadro de fora, como a preempção; e `ceder_cpu` com `SPSel=1`
— de dentro de um handler — é um pânico que diz quem chamou, e não uma
corrupção que aparece longe.

**Preempção muda a regra das travas.** Um spinlock não é reentrante: um fio
preemptado segurando uma trava faz o próximo girar para sempre. Por isso todo
acesso a estado compartilhado neste kernel passa por `sem_interrupcoes`, que
desliga a preempção junto — `frames`, `machine`, `heap` e o próprio
escalonador.

## Vários núcleos

O kernel liga todos os núcleos que a máquina descreve e que o controlador de
interrupções dela alcança — até sessenta e quatro, um por bit de uma
máscara; o GICv2 do ARM endereça oito, e o xAPIC do x86 identificadores até
254, e cada limite mora no driver do controlador —, e a bancada roda com quatro (`-smp 4`; `DUKE_NUCLEOS=1` volta a um só, e a suíte passa
dos dois jeitos). No x86 a lista vem da tabela MADT da ACPI — o iniciador
entrega o endereço da RSDP junto com o mapa da memória — e cada núcleo
acorda por INIT-SIPI-SIPI num trampolim de modo real abaixo de 1 MiB. No ARM
ela vem do device tree, e cada núcleo acorda pelo `CPU_ON` do PSCI. Os dois
caminhos terminam no mesmo lugar: um fio ocioso próprio, o timer do núcleo
ligado com a contagem que o primeiro mediu, e o escalonador.

```
[   41]  2450ms info  smp  4 nucleo(s) descrito(s) pelo hardware
[   42]  2590ms info  smp  nucleo 1 ligado (hardware 0x1), fio ocioso na vaga 2
[   45]  2780ms info  smp  4 de 4 nucleo(s) ligado(s)
```

**O que é de cada núcleo.** O fio atual, o quantum e o ocioso, no
escalonador; a pilha de interrupção e as pilhas de emergência (falha dupla e
NMI), num TSS por núcleo no x86; a pilha de kernel da chamada de sistema,
alcançada pelo `GS` só nas quatro instruções da entrada. No ARM toda exceção —
a interrupção, a falha e a chamada de sistema, com o comando inteiro que um
processo pede — roda na pilha de exceção do núcleo (`SP_EL1`): 60 KiB da
área de pilhas, com uma página de guarda embaixo, em todos os núcleos. O
primeiro também: a do linker script só serve ao boot, e ele troca para a
da área de pilhas antes de os outros ligarem. A entrada dos vetores confere,
antes de empilhar o quadro, que ele cabe — que nem o primeiro nem o último
byte dele caem na página de guarda —, e um estouro recomeça o handler no
topo da **própria** vaga e relata `estouro_da_pilha_de_excecao` com o `pc`
de quem estourou. Sem isso o `stp` da entrada falhava na guarda, a falha
entrava de novo 272 bytes abaixo, umas quinze vezes, até o quadro ser
escrito no topo da vaga vizinha — a pilha de exceção de outro núcleo,
viva. A fumaça estoura uma de propósito (`debug.trigger` com
`stack_overflow`) nas duas arquiteturas: no ARM o endereço acusado é a
guarda da vaga do núcleo do canal, e o `pc` é o da função que afunda; no
x86 quem relata é a falha dupla, na pilha da IST. No ARM, num segundo boot,
também a borda (`stack_overflow_edge`): `sp` a 16 bytes da base da guarda,
onde só a metade da conferência que olha o último byte do quadro pega o
estouro. A suíte mede a marca
d'água de cada pilha de exceção e diz qual caso desceu mais (`pilhas: a de
excecao de cada nucleo tem folga`). Quem precisa saber
em que núcleo está pergunta a um registrador que o processo não alcança — o
`TR` no x86, o `TPIDR_EL1` no ARM.

**Um fio nunca roda em dois núcleos.** O escalonador marca o núcleo que
pegou o fio, e só solta a marca depois de a troca de contexto ter saído da
pilha dele — no fim da troca, e não no começo: até ali o núcleo antigo ainda
está usando aquela pilha. É a propriedade de que todo o resto depende, e o
caso `smp: um fio nunca roda em dois nucleos` a confere com fios soltos
passando por todos os núcleos.

**O relógio anda uma vez por tique, por qualquer núcleo vivo.** Cada núcleo
tem o timer dele, que preempta os fios dele, e todo tique é oferecido ao
relógio: ele anda pelo núcleo que não viu ninguém andar desde o próprio
tique anterior. Com quatro núcleos avançando todos, o tempo correria quatro
vezes mais depressa; com só um, pararia junto com ele — e os prazos das
mensagens, dos arrendamentos e o piso do relógio da persistência com ele.
O caso `smp: o relogio anda sem o nucleo dos dispositivos` trava o núcleo
dos dispositivos de interrupções mascaradas e mede, de outro núcleo, o
relógio andando.

**O núcleo dos dispositivos.** As interrupções dos dispositivos chegam a
um núcleo só, o de boot (`NUCLEO_DOS_DISPOSITIVOS`): é nele que o tique
recolhe o que eles deixaram e que a tela é apresentada — o framebuffer é
um dispositivo, e apresentar de outro núcleo custava cem vezes mais no
emulador. Não é uma autoridade: nada do gate, da política ou da auditoria
pergunta em que núcleo está.

**Avisos entre núcleos.** Três: acordar um núcleo ocioso quando um fio fica
pronto; derrubar uma tradução do kernel em todos os núcleos antes de o frame
voltar ao alocador; e parar todos no caminho da falha fatal, para o
relatório sair de um núcleo só. No x86 os dois últimos vão por NMI, que
atravessa a máscara — um núcleo girando com as interrupções desligadas
ainda é parado. No ARM a invalidação da TLB é difundida pelo próprio
hardware (`tlbi …is`), e a parada vai por SGI, que **não** atravessa a
máscara: um núcleo mascarado fica de fora, e o relatório o lista em
`fatal_unanswered_mask`.

**As travas são justas.** O `spin::Mutex` é um teste-e-troca: ganha quem
chegar primeiro naquele instante, e um núcleo que solta e pede de novo ganha
quase sempre. Medido: um processo num núcleo secundário escrevendo no log,
contra a suíte no primeiro lendo o mesmo anel em laço, levava um quarto de
segundo por linha. A trava do kernel ([`kernel/src/trava.rs`](kernel/src/trava.rs))
é por senha, FIFO; e o destravamento de emergência do caminho fatal abandona
a fila em vez de entregar a vez a um núcleo que já foi parado.

**Os dispositivos são do primeiro núcleo.** As interrupções de dispositivo —
teclado, disco, rede, o canal do agente — continuam no PIC (no x86) e no
GIC com o destino do primeiro, e a tela também: um núcleo secundário compõe
no buffer de fundo e pede ao primeiro que apresente. Medido no emulador: a
cópia para a memória de vídeo saindo de um núcleo secundário custava 1,2
bilhão de ciclos por quadro cheio, contra 9 milhões para compor — cem vezes
mais lenta. O eco do Terminal passou de 280 ms por linha a menos de 20.

### O canal com um núcleo travado

É a exigência que o roteiro pôs na fase: o canal continua respondendo
quando **um** núcleo trava. O `debug.trigger` com `kind:"hang_core"` trava
um núcleo de propósito — um fio fixo nele girando com as interrupções
desligadas, até um prazo ou para sempre —, pelo mesmo gate, com a mesma
permissão dos outros gatilhos, e recusa o primeiro núcleo, que é o do canal.
A fumaça trava o último núcleo para sempre e confere, pelo canal: vinte
`ping` respondidos; o pulso do núcleo travado parado e o dos outros
andando; o fio `travado` no `threads.list`, no núcleo dele; e trocas de
contexto continuando. Depois, a sonda de falha fatal confere que o núcleo
travado foi parado (x86, por NMI) ou listado como sem resposta (ARM).

### O que só aparece com vários núcleos

Uma estrutura que estava certa com um núcleo não está certa com vários só
por compilar. O que esta fase encontrou, e corrigiu na camada responsável:

- **A autoridade do comando era do sistema inteiro.** Uma variável global
  dizia em nome de quem o comando em curso agia; fora de um comando, ela
  dizia `sistema`. Com vários núcleos, um fio em outro núcleo que
  perguntasse durante um comando recebia a autoridade do agente que o pediu
  — e, fora dele, a máxima. Agora ela é do fio que executa o comando, e
  qualquer outro recebe a de ninguém.
- **A cota de processos se ultrapassava por um a cada núcleo.** O gate
  contava os processos vivos do titular e o escalonador reservava a vaga
  depois, em outra seção crítica; uma chamada de sistema roda com as
  interrupções mascaradas, e com um núcleo nada cabia entre as duas. Agora a
  cota é conferida de novo na mesma seção crítica que reserva a vaga, e a
  recusa vai para a auditoria do mesmo jeito.
- **O coletor fechava o console do dono seguinte.** O pseudo-terminal
  largava a vaga de um dono morto sob a trava e fechava o console dele
  depois; um `abrir` em outro núcleo, no meio, abria o console para o dono
  novo, e o fechamento atrasado o fechava — ou zerava o console antes do
  fechamento, e a sessão da pessoa do Terminal morto ficava viva, sem
  console. A vaga agora tem um estado *em troca*, que ninguém toma nem usa,
  e reabrir um console encerra a sessão que tivesse sobrado.
- **O login entrava no console de outro Terminal.** A senha sai do
  console, a conferência — um Argon2id — roda fora da trava, e o resultado
  era posto no console sem perguntar se ele ainda era o mesmo. Se o
  Terminal morria no meio, o coletor fechava o console, um Terminal novo
  abria a mesma vaga, e a sessão da pessoa aparecia no console do processo
  novo, já entrada. A janela existia com um núcleo — o coletor também
  preempta o executor —, mas era estreita; com vários, ela é a conferência
  inteira. Agora o console conta as aberturas, o login entra só na que lhe
  deu a senha, e a sessão de um login atrasado acaba, gravada.
- **Um núcleo lento era dado como perdido, e seguia rodando.** A derrubada
  de uma tradução do kernel esperava a confirmação dos outros núcleos até
  um teto, e depois desistia: o núcleo que não confirmou saía da conta dos
  ligados, e quem pediu devolvia o frame ao alocador. A premissa — quem
  não responde a uma NMI não está rodando nada — não vale para um núcleo
  só lento, como uma CPU virtual sem CPU do hospedeiro por um tempo: ele
  voltava, seguia rodando fios com a tradução velha, escrevia num frame
  que já era de outro e, fora da conta, não recebia mais descarte nenhum.
  Agora a espera reenvia o aviso e, passado um prazo muito maior que o de
  qualquer resposta, para o sistema pelo caminho da falha fatal. Um núcleo
  travado com as interrupções mascaradas continua respondendo — a NMI
  atravessa a máscara —, então isso não custa o requisito do núcleo
  travado.
- **O `ui.tree` e uma janela se redesenhando travavam um ao outro.** O
  percurso das camadas chamava quem pediu com a trava do compositor na
  mão, e o `ui.tree` pedia ali a descrição de cada janela às superfícies —
  compositor, depois superfícies. Uma superfície que se pinta faz o
  contrário. Com um núcleo, as duas ordens nunca se cruzavam; com vários, o
  executor e o Terminal redesenhando a linha que o agente acabara de
  digitar seguravam uma cada um e esperavam a outra para sempre, com as
  interrupções do primeiro núcleo mascaradas — e o canal morria. Visto na
  fumaça do x86 em release, na integração contínua. O percurso agora copia
  as camadas e chama quem pediu com a trava solta.
- **`esperar` devolvia o zero de "ainda não" como resposta.** Sem filho
  para colher, a chamada põe o pai em espera e o backend a reexecuta quando
  ele acorda — e o backend decidia isso perguntando se o fio **ainda**
  estava esperando. Com um núcleo, nada o acordava entre as duas coisas;
  com vários, o filho sai em outro núcleo exatamente ali, o pai já está
  pronto, e o zero chegava ao processo: `esperar` dizendo que colheu o
  filho 0, sem código (visto na suíte do ARM em release). Agora a chamada
  pede a reexecução, junto com a espera e sob a mesma trava, e o backend
  pergunta isso a ela. Vale também para a leitura de um canal vazio.
- **A preempção dependia de ganhar um `try_lock`.** O timer descontava o
  quantum de cada núcleo dentro da tabela do escalonador, por `try_lock` —
  um handler não pode esperar pela trava. Com vários núcleos, um fio que
  cede em laço num núcleo toma e solta a trava sem parar, o `try_lock` dos
  outros perde quase sempre, e o quantum deles não anda: o fio que ocupava
  um deles nunca mais era preemptado. Visto na suíte como um lançador fixo
  num núcleo, **pronto**, por segundos, com o núcleo vivo. O quantum agora
  é um atômico de cada núcleo, que só ele toca, fora da trava.
- **O relógio de parede era lido por duas portas sem trava.** No x86, o RTC
  é um par índice/valor, e só a máscara de interrupções separava um acesso
  do outro. A auditoria lê o relógio a cada decisão do gate, de qualquer
  núcleo; dois núcleos decidindo juntos trocavam o índice um do outro. O
  sintoma medido foi um lançamento parado por mais de três segundos — o
  bit de "atualizando" lido de outro registrador —, e o risco era pior: uma
  leitura misturada que passasse pela conferência levaria o piso do relógio
  da persistência, que nunca volta, para uma data errada. O par de portas
  da configuração PCI tinha o mesmo defeito. Os dois têm trava agora.
- **O retângulo sujo da tela era quatro atômicos.** Quem descarregava lia
  as quatro coordenadas uma a uma, e outro núcleo alargando no meio deixava
  parte de uma escrita fora da tela até a escrita seguinte. Agora é uma
  palavra só.
- **A profundidade do log sob trava era global.** Ela conta quantas travas o
  fio segura ao registrar, para recusar o que poderia travar em si mesmo; um
  contador do sistema inteiro contava as travas dos outros núcleos.
- **O comando do APIC tem duas metades.** Escrever o destino e o comando são
  duas escritas; uma interrupção no meio que mandasse outro aviso trocava o
  destino do primeiro. Agora a dupla é escrita com as interrupções
  mascaradas.
- **As linhas de dispositivo do ARM iam à interface 0 do GIC.** Escrita como
  `0b1`, e não como a interface que o núcleo de boot lê no distribuidor: no
  QEMU elas coincidem, numa placa que bootasse por outra interface as
  interrupções iriam a um núcleo que não as trata.
- **O pseudo-terminal perdia texto disputado.** A saída tomava o anel por
  `try_lock`, e com um núcleo só ele nunca estava tomado; com vários estava,
  e o texto sumia.
- **No ARM, a tela de falha esperava o núcleo mascarado.** A parada dava a
  quem não responde à SGI um prazo de cem milhões de voltas, e um núcleo
  mascarado nunca responde: o prazo corria inteiro, sempre. No kernel de
  depuração sob o QEMU sem aceleração, mais de cinco segundos — a fumaça
  desistia antes de a tela de falha chegar ao monitor. O prazo agora é um
  quarto de segundo no contador do timer genérico, que anda com as IRQs
  mascaradas.
- **Uma medida ruim do APIC custava os outros núcleos.** A calibração do
  timer do APIC é conferida contra o PIT, e uma conferência reprovada
  deixava o PIT como relógio — com um núcleo só, um timer pior e mais nada.
  Com vários, sem APIC não há como acordar os outros, e a máquina de quatro
  núcleos subia com um. Medido numa campanha de mutações, com o hospedeiro
  ocupado: "o APIC disparou 14 vezes onde 20 eram esperadas". A
  conferência existe para pegar erro de unidade, que se repete; agora são
  três medidas antes de desistir.
- **O coletor devolvia a vaga antes de desmontar o morto.** A pilha de
  kernel de cada vaga mora num endereço fixo dela, e quem a desmapeia é o
  morto ao ser largado — fora da trava. O coletor deixava a vaga vazia
  nesse intervalo, e uma criação em outro núcleo a escolhia e ia mapear a
  pilha nova por cima da velha: "endereço virtual já mapeado". Era a falha
  intermitente da cópia na escrita em dois núcleos, que ficou sem
  explicação até uma campanha de mutações a reproduzir no caso da criação
  concorrente. Agora a vaga fica reservada até o morto sair, e o caso
  `fios: o coletor segura a vaga ate desmontar` abre a janela de propósito.

E o que foi conferido e está certo, com o caso que o prova: a cópia na
escrita com os dois donos escrevendo juntos (`smp: copia na escrita em dois
nucleos` — 498 cópias para 256 páginas divididas em oito voltas: muitas
vezes os dois leram "dois donos" ao mesmo tempo, e cada um viu só as
próprias escritas); a gravação no journal, que já era serializada por fio
dono e não pela máscara; a tradução de um processo, que nenhum outro núcleo
guarda depois de trocar de raiz.

### Mutações

Vinte e quatro mutações dirigidas à sincronização desta fase, cada uma
contra a suíte inteira com quatro núcleos (uma, a do prazo da parada no
ARM, contra a fumaça do ARM): **dezesseis reprovadas, oito sobreviventes**.
Três das reprovadas só reprovam porque a campanha mostrou que passavam, e
ganharam caso determinístico — com um gancho só de teste que abre a janela
de propósito, em vez de esperar o acaso acertá-la: o coletor do
pseudo-terminal largando a vaga como livre, o `abrir` aceitando a vaga em
troca, e o quantum que só anda com a trava do escalonador livre. A campanha
achou também dois defeitos de verdade (o coletor de fios devolvendo a vaga
antes de desmontar o morto, e a calibração do APIC derrubando os outros
núcleos) e um caso que falhava por acaso (o do zumbi).

As oito que passavam foram investigadas uma a uma, na fase 8: cada uma
reproduzida, classificada por um caso, e mutada de novo. **Nenhuma era
defeito do código; as oito eram caso faltando**, e as oito agora reprovam
— cada uma só pelo caso dela (364 de 365 na suíte mutada). Os casos são
determinísticos: um gancho só da suíte (`#[cfg(feature = "modo-teste")]`)
abre a janela de propósito, em vez de esperar o acaso acertá-la, e nenhum
deles muda o caminho de produção nem trata um núcleo de um jeito especial.

| Mutação | Era | O caso que a reprova |
|---|---|---|
| Marcar um descritor do kernel sem avisar os outros núcleos | contrato sem chamador: nenhum código de hoje marca página do kernel | `paginacao: marcar no kernel avisa todos` — marca uma página do heap como compartilhada (a marca não muda permissão) e confere que o pedido de descarte chegou aos outros núcleos (só x86: no ARM a invalidação é difundida pelo hardware) |
| A trava sem fila (`try_lock` em laço) | caso não determinístico: a inanição era estatística | `trava: justa entre nucleos` — um fio em cada outro núcleo pede a trava em ordem conhecida; soltada, entram na ordem em que pediram, em 24 voltas |
| Reabrir o console esquecendo a sessão | caso faltando | `consoles: reabrir encerra a sessao` |
| A saída do pseudo-terminal por `try_lock` | caso faltando: precisava de dois núcleos no mesmo anel | `pty: a saida espera o anel` — outro núcleo segura o anel enquanto este imprime; o texto tem de estar lá |
| Criar um fio sem acordar os núcleos ociosos | caso faltando: o efeito é latência | `smp: o fio novo acorda o ocioso` — medido em tiques do próprio núcleo, em oito tentativas, a partir do tique em que o cutucão saiu: com ele o fio roda no mesmo tique, sem ele no seguinte. Medido antes desde o começo da criação, o caso passou a falhar quando a conferência da ordem das travas entrou na suíte — criar um fio toma dezenas de travas, e a criação cruzava o tique do alvo —, sem que o despertar tivesse mudado |
| O tique sem descarregar o console | caso faltando: o efeito é latência | `tela: o tique leva o que ficou` — escreve com o compositor ocupado, solta, e espera dois tiques sem escrever |
| A reexecução decidida pelo estado do fio (x86) | caso não determinístico: a janela não era acertada | `fios: a reexecucao e da chamada` — o processo `contido` para entre a chamada voltar e a pergunta; o pedido é atendido nessa hora; ele tem de receber a resposta |
| O `soltar` liberando o frame fora da trava | caso faltando | `frames: soltar libera na mesma secao` — uma pausa na entrada de `liberar`, para um frame só; outro núcleo compartilha o frame nessa hora |

O que fica de fora — o núcleo dos dispositivos, os tetos dos controladores
de interrupção, a decisão de uma ação sem commit — está abaixo, com a razão
de cada um; nenhum dos casos novos o contorna.

### A ordem das travas, conferida

Duas ordens de travas são um impasse esperando dois núcleos chegarem ao
mesmo tempo — e a suíte, num emulador com poucos núcleos, quase nunca os faz
chegar. Por isso a ordem não depende de revisão nem de sorte: na compilação
da suíte, cada `lock` passa por uma conferência
([`ordem_das_travas`](kernel/src/ordem_das_travas.rs)). Cada trava é uma
classe; cada núcleo guarda a pilha das que tem na mão; pedir `B` com `A` na
mão acrescenta a aresta `A → B` a um grafo, e uma aresta que fecharia um
ciclo — `B → A`, ou `B → C → A` — é registrada como inversão, com onde cada
uma foi pedida pela primeira vez e onde o ciclo se fechou. A ordem das
gravações do journal, que é do fio e não do núcleo, entra no grafo como
uma classe também. O último caso da suíte, `travas: nenhuma inversao de
ordem`, falha com a primeira inversão de qualquer caso anterior, em
qualquer arquitetura e número de núcleos; `travas: a conferencia ve a
inversao` confere o conferidor, com duas, três travas e a ordem das
gravações. Na suíte do x86 com quatro núcleos: cem classes, perto de cento
e setenta arestas, nenhuma inversão, e nenhum ponto cego (classe fora da
tabela, pilha além da altura, trava solta fora do núcleo que a tinha).

A ordem não vê o impasse de uma trava só: uma classe tomada com as
interrupções ligadas num lugar e mascaradas noutro. Quem a tem com elas
ligadas pode ser interrompido no meio — por um handler que a pede, ou pela
preempção, que põe no núcleo um fio que a pede mascarado —, e quem pede
mascarado gira para sempre, porque quem a tem só volta pelo núcleo que ele
não solta. A mesma conferência guarda com que interrupções cada classe foi
tomada (e com quais foi solta), e uma classe nos dois modos reprova o
último caso, com onde. Uma classe só de fios, sempre com elas ligadas, não
tem o problema e não reprova. A primeira rodada achou quatro, todas reais:
a ligação do disco, do TPM e da placa de rede (`*X.lock() = Some(..)` no
boot, com elas ligadas, contra o resto do driver, mascarado) e o ajudante
da suíte que segura a trava de `traps`. E nenhuma trava escapa da
conferência: do pacote `spin` o kernel só tem o `Once`; uma `spin::Mutex`
não compila.

### O que fica de fora

- Os dispositivos e o executor do canal moram no núcleo dos dispositivos,
  e ele travado com as interrupções mascaradas cala o canal — o relógio, não.
  Levar as linhas de interrupção para outro núcleo quando ele para pede
  reprogramar o IOAPIC e o distribuidor do GIC em pleno voo, e um executor
  que migre de núcleo; nenhum dos dois existe.
- No ARM, a parada no caminho fatal não alcança um núcleo mascarado (GICv2
  sem FIQ nem NMI); ele é relatado, não parado.
- Toda operação que muda estado durável tem um ponto de commit — o
  registro dela no journal, com a ordem das gravações na mão —, e lá a
  autoridade é decidida de novo, pela política e pelo registro de agora: o
  lote do armazém, e o envio, a leitura (que entrega), a confirmação e o
  cancelamento de uma mensagem. As revogações gravam com a mesma ordem, e
  por isso a operação ou as vê e é recusada, ou vem antes delas inteira
  (`armazem: revogacao no meio da operacao`, `mensagens: revogacao no meio
  da operacao`). Uma ação sem estado a confirmar — um clique na interface,
  a leitura de uma tecla — vale como decidida no gate: ela acontece numa
  chamada, e uma revogação que chega durante ela vale como chegada logo
  depois.
- Sessenta e quatro núcleos no máximo — um por bit da máscara —; oito no
  ARM, pelo GICv2; e no x86 só os de identificador de APIC até 254, sem
  x2APIC.
- Um núcleo que não responde à partida é dado como falho e fica de fora, e
  a vaga do fio ocioso que lhe tinha sido preparada fica presa até o
  próximo boot: ele ainda pode acordar tarde, e acorda na pilha dela antes
  de ver que foi dado como falho e se recolher — devolvê-la seria dar a
  outro fio uma pilha que um núcleo ainda usa.

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

As chamadas de sistema são dezenove: `sair`, `escrever`, `id`, `ceder`,
`bifurcar`, `executar`, `abrir`, `ler`, `fechar`, `esperar`, `mapear`,
`escutar`, `superficie`, `controlar`, `descrever`, `terminal`, `valor` — e
`pedir` e `resposta`, que abrem o resto do sistema ao programa (ver
[Interface nativa](#interface-nativa)). Os
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

Onze mutações nos canais, onze reprovadas. E um defeito que elas não
cobriam, achado ao escrever as superfícies, que têm o mesmo arranjo: a
chave de um descritor era só a vaga do canal, e a vaga é reaproveitada. O
pai fecha um canal cujo descritor o filho herdou; o filho escuta outro
canal, que cai na mesma vaga; e o descritor herdado passava a alcançar o
canal novo — o ouvinte conferia, porque agora é o filho. Fechá-lo largava
o canal que o filho acabara de abrir. A chave ganhou uma geração que nenhum
outro canal recebe, e o `eco` confere o cenário inteiro.

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

**Superfícies do compositor, com os pixels no processo.** A janela do
servidor de janelas, antes de haver servidor. `superficie(tamanho, endereco)`
cria uma camada do compositor e mapeia os pixels dela no processo, no
endereço que ele escolhe — os **mesmos** frames que o compositor lê ao
compor, mapeados dos dois lados. O processo desenha escrevendo na memória, e
diz onde escreveu com `controlar(descritor, DANO, retângulo)`; o compositor
recompõe só aquilo. Nada é copiado entre os dois lados: é o arranjo do
Orbital, o compositor do Redox. `controlar` também move a camada, a traz
para a frente, muda a opacidade e a mistura. Ela nasce **invisível**: uma
camada que aparecesse ao nascer mostraria preto até o primeiro desenho.

Cada frame tem dois donos contados — a memória da camada e o espaço do
processo —, e cada lado solta o seu: o frame volta ao alocador com o último,
em qualquer ordem. Por isso a memória das superfícies passou a **soltar**
os frames, e não a liberá-los: liberar entregaria ao alocador pixels que o
processo ainda desenha.

Três coisas o `fork` e a morte pediam, e cada uma falharia em silêncio:

- **o `fork` não leva a superfície ao filho.** Levaria como cópia na
  escrita, como toda página gravável — e a primeira escrita do **pai** depois
  de bifurcar iria para uma cópia particular: a janela congelaria na tela sem
  erro nenhum. As páginas de superfície carregam uma marca no descritor, no
  bit do software vizinho ao da cópia na escrita, e o `fork` as pula. O filho
  herda o descritor e é recusado se o usar;
- **um descritor herdado não alcança a superfície seguinte na mesma vaga.**
  O pai fecha, a vaga fica livre, o filho cria a própria superfície e ela cai
  ali: o descritor herdado passaria a controlar a janela nova do filho, e
  fechá-lo a fecharia. A chave de um descritor é a vaga **e** uma geração
  que nenhuma outra superfície recebe;
- **o dono que morre sem fechar.** Um processo morto não fecha os
  descritores, e ninguém procuraria a camada dele: ela ficaria na tela. O
  coletor de fios tira as camadas de dono morto na mesma volta em que
  desmonta os fios.

Fechar tira a camada da tela **e** os pixels do processo — uma janela aberta
e fechada mil vezes não pode custar mil superfícies de memória até o processo
sair. Só o mapeamento que ainda aponta para os frames da camada é desfeito:
depois de um `exec`, o mesmo endereço pode ser memória do programa novo. O
runtime tem um tipo `Superficie` que escolhe o endereço na metade de cima da
região mapeável, acima de onde o monte chega, e devolve a faixa quando é
largado.

O programa `superficie` é o outro lado do caso da suíte: confere as recusas
da ABI, pinta, bifurca, pinta de novo — a suíte procura na tela a cor de
**depois** do `fork` —, fecha a primeira e sai sem fechar a segunda. Um
filho dele cria uma superfície e troca de imagem pelo `herdeira`, que põe a
dele no **mesmo endereço** e fecha o que herdou: sem a conferência do frame,
fechar a herdada arrancaria a memória da nova. E esse filho morre sem ser
colhido — um zumbi, com o espaço de pé —, que é a ordem em que a camada
solta os frames antes do espaço: liberar ali, em vez de soltar, entregaria a
outro dono memória que o zumbi ainda mapeia. O
`display.info` ganhou `process_surfaces`: vivas, criadas e recolhidas de
donos mortos. Treze mutações nas superfícies, treze reprovadas. Duas delas —
liberar em vez de soltar, e desfazer o espelho sem conferir o frame — só
reprovam pelos cenários do zumbi e do `exec`, escritos para elas depois de
ver que nenhum caso passava por aquelas ordens.

**O servidor de janelas, no espaço do usuário.** O programa `janelas` é o
servidor: o kernel o lança do disco no boot, quando há compositor, e ele
dorme na leitura do canal `janelas` até haver o que fazer. A divisão é a
aprovada — **o kernel compõe, o servidor decide**. O kernel guarda as
camadas, desenha o cursor e a barra, e leva à tela o que mudou; o servidor
decide o que é uma janela, desenha a moldura dela com a mesma fonte do
console, e responde ao que a pessoa faz: foco, arrastar pela barra de
título, trazer para a frente e fechar pela caixa da ponta direita.

O que atravessa a fronteira é pouco, e é tudo evento de 32 bytes no mesmo
canal:

- **o ponteiro**, só quando o que está debaixo dele é a superfície de um
  processo — o kernel pergunta ao compositor qual camada cobre o ponto, sem
  contar o cursor nem as invisíveis. Um aperto sobre uma janela **captura** o
  ponteiro até soltar: arrastando depressa, ele sai da janela antes de ela
  acompanhar, e sem a captura o resto do arrasto viraria clique do kernel;
- **as teclas**, enquanto uma janela tem o foco. O servidor o pedia com
  `controlar(FOCO)` — desde o Terminal, é o kernel que o dá, no aperto do
  botão; ver abaixo —; um clique fora de toda janela o devolve ao kernel, e
  o servidor é avisado para apagar a barra de título. Se o servidor morrer com
  o foco, a tecla segue para o console em vez de sumir, e o coletor devolve
  o foco ao kernel na volta seguinte;
- **os pedidos de abrir** uma janela, com o tamanho da tela para
  posicioná-la, e o de **encerrar**.

O caso da suíte lança o servidor e o opera pelas mesmas funções que os
drivers chamam: abre uma janela e confere a barra acesa na tela; digita, e a
tecla não chega ao console; arrasta pela barra e confere a camada onde o
ponteiro a levou; abre uma segunda e traz a primeira para a frente com um
clique; clica fora, e a barra apaga e a tecla volta ao console; fecha pela
caixa; e encerra o servidor, que não fica vivo para os casos seguintes. O
`display.info` ganhou `to_windows`, os eventos de ponteiro que foram para o
servidor em vez de virar clique do kernel.

Catorze mutações na etapa, treze reprovadas — depois de o caso ser relido
contra elas e reforçado: o arrasto que o comentário dizia sair da janela
andava 50 pixels numa janela de 320, e a captura não era testada. A que
passou tirava a devolução do foco quando a tecla não tem quem a escute; o
coletor já a faz no tique seguinte, e a tecla segue para o console de
qualquer jeito. Era o mesmo efeito escrito duas vezes, e saiu.

**A árvore semântica atravessa a fronteira.** Uma janela do servidor é uma
camada de processo, e o kernel não sabe o que há nela — só o servidor sabe.
Então o servidor **diz**: `descrever(descritor, texto)` manda o que a janela
é, uma linha por coisa, com os campos separados por tabulação — o título,
a caixa de fechar como botão, o conteúdo como texto, cada um com o
identificador que o servidor deu e o retângulo na superfície. O kernel lê
tudo ou recusa tudo: uma descrição com uma linha que ele não entende
deixaria a árvore descrevendo o que não está na tela. Um rótulo ou valor com
tabulação, quebra de linha ou barra invertida vai escapado, e a volta é
conferida inteira — o servidor escapa, o kernel resolve, e o JSON escapa de
novo.

A descrição é gerada do mesmo estado que o desenho, a cada vez que ele
muda. Em `ui.tree`, a janela aparece com o título como rótulo, e os
elementos como filhos, com a moldura **na tela** — a da camada somada ao
retângulo que o servidor deu. O identificador de um elemento é derivado da
camada e da posição dele na descrição, e não guardado: vale enquanto a
janela vive, e o de uma janela que fechou não aponta para a seguinte.

`ui.act press` num botão descrito vira um evento `ACAO` no canal, com o
identificador do servidor; o servidor faz o que o clique faria. A caixa de
fechar fecha pelos dois caminhos — o do agente e o da pessoa —, e o log diz
quem foi. O caso da suíte lê a árvore do `ui.tree` de verdade, digita na
janela e espera o que digitou no valor, confere que o que não é botão não
aceita `press`, e fecha a janela pelo botão da árvore. Outro caso confere
o parser: a descrição válida lida como escrita, e oito formas de texto que
o kernel não entende, recusadas. Doze mutações, onze reprovadas. A que passa tira o aviso de que
a árvore mudou quando a descrição muda; ela muda sempre junto com um
desenho e uma linha do servidor no console, que avisam também, e o caso
não consegue separar um aviso do outro.

**A primeira janela: "Sobre o Duke".** A barra ganhou o segundo botão,
**Sobre**, e ele é o primeiro do kernel cujo efeito mora do outro lado da
fronteira: o `press` — pelo clique, pela F2 ou pelo agente, os três pelo
mesmo caminho — publica um pedido de abrir no canal das janelas, e o
servidor abre a janela, desenha e a descreve. Sem servidor no ar, o `press`
é recusado com o motivo, em vez de ser aceito sem que nada aconteça. A
janela é uma só: pedir de novo a traz para a frente. O texto dela diz o que
o Duke é e em que arquitetura está rodando — com acento, desde a
tipografia, abaixo.

A fumaça a opera como uma pessoa: leva o mouse da máquina ao botão pela
moldura que a árvore publica, clica, espera a janela aparecer na árvore,
arrasta pela barra de título e confere a moldura nova, e fecha pela caixa.
Pelos drivers de verdade, e pelo servidor lançado no boot de produção.
Oito mutações na etapa, oito reprovadas — uma delas, tirar o botão do
desenho, só depois de o caso conferir o pixel do botão: o clique e a árvore
usam a moldura, e passavam sem ele.

**A corrida do foco.** A matriz reprovou o caso da etapa 4 uma vez em
poucas no x86, e o motivo era real. Um clique numa janela faz o servidor
pedir o foco; se a pessoa clica fora antes de o pedido chegar, o kernel via
o foco consigo, nem avisava o servidor, e o pedido atrasado ficava com o
foco — o servidor achando que não o tinha, e o kernel mandando as teclas
para ele, para serem jogadas fora. Agora o kernel avisa em todo clique fora
das janelas, e o servidor, avisado, solta o foco pela superfície. O caso
provoca a corrida de propósito — os dois cliques com as interrupções
mascaradas, para o servidor recebê-los no mesmo lote —, e desfazer
qualquer das duas metades o reprova. A mesma matriz achou que o caso não
cabia na tela de 800 por 600 que a UEFI entrega no ARM: a caixa de fechar
da janela arrastada caía fora da tela.

E a matriz seguinte pegou a árvore mostrando uma janela **invisível**. O
servidor descreve a janela antes de posicioná-la e mostrá-la — é o que
evita um retângulo preto na tela —, e a árvore publicava a camada na
origem, com opacidade zero. A fumaça, lendo a moldura como um agente leria,
levou o mouse à barra de título dela e clicou no botão da barra superior
que estava ali de verdade. A árvore descreve a tela: uma camada invisível
não está nela, nem para `ui.tree` nem para `ui.act`.

**A tipografia.** Até aqui a fonte vivia em dois lugares: o console e a
barra do kernel a declaravam de um jeito, o servidor de janelas de outro. E
os dois já tinham divergido — a mistura da cobertura do glifo com o fundo
truncava num lado e arredondava no outro, e a mesma letra saía com pixels
diferentes numa janela e no console. Agora ela mora no pacote `tipografia`,
`no_std` como o `protocolo`, que os dois lados incluem: os estilos, os
glifos, o substituto de uma letra que a fonte não tem, a mistura e a escrita
numa memória de pixels.

O que ela trouxe de novo:

- **as letras do português.** A fonte tinha só o latim básico, e `ação`
  saía `a??o` — o texto do sistema era escrito sem acento para não sair `?`.
  O bloco Latin-1 entrou, e com ele `á`, `ã`, `ç`, `é`, `ô` e as outras. O
  "Sobre o Duke" passou a ser escrito como se escreve;
- **o negrito**, para o que se lê primeiro: o nome na barra e o título de
  cada janela;
- **um tamanho de título**, de 24 pixels, para o cabeçalho de uma janela —
  o "Duke" no alto do "Sobre o Duke".

O custo foi medido, e mudou uma decisão. Com as duas alturas, a tipografia
somava ao kernel x86 em release 593 KiB de texto e dados; a altura de 24
era dois terços disso, e só os programas a usam. Ela ficou atrás de uma
feature que o kernel não liga, e o acréscimo caiu para 200 KiB no x86 e 85
KiB no ARM. O servidor de janelas, que usa as duas, foi de 59 para 329 KiB
no disco do x86.

O teclado continua o americano: as letras acentuadas aparecem, mas ainda
não se digitam. A suíte confere `ação é útil` no console pixel a pixel
contra o glifo de cada letra — e a conferência recusa uma letra que a fonte
não tem, então o substituto não passaria por ela —, a grade guardando as
letras acentuadas, e o nome na barra contra o desenho em negrito, com o
regular conferido como diferente. O pacote tem os próprios testes, no
hospedeiro: os glifos do português nos três estilos, o substituto, as
dimensões e a mistura, exata nos extremos e arredondando no meio.

**O Terminal.** A primeira janela de trabalho, e a primeira parte da fase
11. O console era a camada de baixo do compositor, desenhada pelo kernel;
o Terminal é um programa, com a janela dele, e o interpretador do outro
lado de um descritor. Não há um segundo interpretador: o console continua
embaixo, desenhando o mesmo texto — é o fundo, e a reserva, o que se vê no
boot antes de o Terminal subir e o que a tela de falha cobre. Veio em
quatro etapas.

**O pseudo-terminal.** `terminal(canal)` abre o interpretador visto de um
processo, e devolve um descritor. Escrever nele é digitar: cada caractere
entra na fila do teclado que o interpretador lê, como se tivesse sido
digitado na máquina — só texto, a quebra de linha e o apagar, porque a
mesma fila carrega F1, F2 e o clique, e um processo não aperta botões do
kernel por ali. Ler é a saída: tudo o que passa pelo `_print` vai também
para um anel de 16 KiB, desde o boot, e o Terminal começa mostrando o que
aconteceu antes dele. A leitura não bloqueia — o processo espera no canal
de eventos, onde o kernel avisa com `SAIDA`, e assim espera o teclado, o
ponteiro e a saída num lugar só. O aviso é dado pelo coletor de fios, e
não pelo `_print`: o `_print` roda dentro da tranca do escalonador, e
publicar ali acordaria o ouvinte tomando a mesma tranca. Um dono de cada
vez, com uma geração na chave, como os canais e as superfícies; o dono
morto não segura o pseudo-terminal. `display.info` ganhou `terminal`: o
dono, os avisos, as teclas digitadas e os bytes que saíram do anel sem
ninguém lê-los.

Com as pessoas, o Terminal deixou de ser outra janela sobre o mesmo
interpretador: cada um tem um pseudo-terminal e um console seus, com a
sessão de quem entrou nele — ver [Consoles](#consoles).

**Cada superfície recebe a sua entrada.** Com dois processos com janela,
a entrada não podia ir sempre ao servidor. `controlar(fd, ENTRADA, canal)`
aponta a entrada de uma superfície para um canal que o processo escuta —
o ponteiro sobre ela, as teclas com o foco nela, o foco perdido e as ações
da árvore vão para lá; sem escolher, vão para o canal das janelas. Um
canal que o processo não escuta é recusado, inclusive o que um filho
herdou do pai. E o kernel passou a dar o foco no aperto do botão, em vez
de esperar o dono pedi-lo: o pedido atrasado era o que fazia um clique
fora ser desfeito — a corrida da etapa 6 —, e o servidor agora só pede o
foco para a janela que acabou de abrir. Quem perde o foco é avisado no
canal dele, e só quando ele sai para outro canal.

**A janela vai para o runtime.** A moldura, a barra de título, a caixa de
fechar e o arrasto moravam no servidor; o Terminal seria a segunda cópia.
`programas::janela` é a janela uma vez só, e o servidor passou a usá-la
sem mudar um pixel nem um elemento da árvore.

**O programa.** Uma grade de 80 por 24, e o cursor na última: o kernel manda texto, a quebra, o retorno e o apagar —
que volta uma coluna sem apagar, porque o interpretador apaga escrevendo
um espaço por cima. O kernel o lança no boot, ao lado do servidor, com o
foco. Depois, o botão **Terminal** da barra, com a F3: com um Terminal no
ar, o pedido vai a ele, e ele vem para a frente; sem nenhum, vai ao
servidor, que o lança bifurcando duas vezes — o servidor nunca espera
ninguém, e um filho direto viraria zumbi.

A fumaça fecha o caminho da pessoa: digita `agent.ping` no teclado da
máquina e confere, pela árvore, que o Terminal mostra a linha depois do
prompt e a resposta. Foi ela que achou teclas perdidas no ARM emulado, a
vinte milissegundos por tecla. Na primeira versão, o Terminal redesenhava
a grade inteira a cada eco, e chegaram `agent.` e o Enter — o `ping` se
perdeu. Redesenhando só a linha que mudou, a perda ficou mais rara, e não
sumiu: duas fumaças em cinco. A outra metade era do driver. A colheita do
teclado virtio tinha oito posições, que são duas teclas — e não quatro,
como o comentário dizia: soltar também é evento. Um registro temporário em
cada colheita mostrou a perda coincidindo com os oito buffers cheios, e
nenhuma fumaça sem perda com uma colheita cheia. Com trinta e duas
posições nas filas virtio, quatro fumaças seguidas no ARM, e nenhuma
colheita perto do teto.

Trinta e oito mutações nas quatro etapas, e as trinta e oito reprovadas —
quatro delas só depois de o caso ser reforçado, cada uma mostrando o que
ele não perguntava. A escrita que pulava o que não coube na fila, em vez de
parar, dava a mesma conta para uma linha só de texto. Abrir sem avisar do
que já estava no anel passava porque o programa lê logo ao abrir. Tirar a
captura do ponteiro no movimento passava porque o soltar levava a posição
final, e o caso só olhava o fim do arrasto. E o servidor voltar a pedir o
foco no aperto passava com uma janela só: com dois processos, o pedido
atrasado tomava o foco do outro, e o foco ficava com ninguém — o caso
provoca essa corrida agora.

**O toolkit.** A segunda parte da fase 11, e a regra dela: uma janela não
se descreve à mão. Até aqui, o servidor de janelas e o Terminal desenhavam
e, ao lado, escreviam a descrição para a árvore semântica — duas contas
para o mesmo retângulo, e bastava uma mudar para o agente ler o que não
estava na tela. Agora cada janela é uma árvore de widgets, e o desenho e a
descrição saem dela pelo mesmo percurso, na mesma ordem, com as mesmas
áreas. Veio em seis etapas.

**A linguagem visual.** O pacote `aparencia`, dos dois lados da fronteira:
a paleta pelo nome — a noite, a ardósia, o aço, o acento, a névoa —, os
papéis de cada cor, as medidas e os estilos de texto. O botão de uma
janela é o botão da barra do kernel porque os dois leem o mesmo token. Um
teste confere o contraste de cada par texto-fundo pela conta da WCAG — 4,5
para o texto, 3 para o que só tem de ser visto, como o cursor e a borda do
foco. O primeiro acento dava 3,22 ao título da janela com o foco, e ficou
um tempo registrado como exceção; ele escureceu de `3A8FD0` para `2B73B0`,
e o título foi a 4,64 sem o cursor sumir sobre a noite. A suíte confere a
tela contra a paleta pelo nome, e não contra as constantes do kernel: uma
troca de cor mudava os dois lados da conferência, e passava.

**Os widgets.** O pacote `toolkit`: o rótulo, o botão, o campo de texto, a
área de texto, e a coluna e a linha que os põem um depois do outro. Cada um
sabe o tamanho que pede, se desenha na área que recebe, e diz o que é. A
descrição que o toolkit gera é lida de volta, nos testes do hospedeiro,
pelo **mesmo** leitor que o kernel usa, do `protocolo`.

**Três caminhos, uma chegada.** O aperto do ponteiro vai ao widget mais
fundo sob ele, e lhe dá o foco; o Tab leva o foco adiante; o Enter e o
espaço acionam o botão com o foco; e o `press` do agente chega ao widget
pelo identificador que a árvore publicou. Os três chegam ao mesmo
`tratar`, e o "OK" do agente é o "OK" da pessoa. O anel do botão e o
cursor do campo só aparecem na janela com o foco — é onde a tecla vai
cair.

**O campo, e o caminho do agente até ele.** O `set_value` traz um texto
que não cabe num evento de 32 bytes. Ele espera no kernel, numa fila da
superfície de no máximo quatro, e o processo, avisado por uma ação,
o tira com a chamada `valor` — a décima sexta. Uma fila, e não um lugar
só: dois campos definidos antes de o processo rodar trocariam de valor. Se
o aviso não chega, o texto sai da fila junto com ele. O buffer do `ui.act`
passou a ter o tamanho do maior valor da árvore, 512 bytes.

**As janelas do Duke.** O "Sobre o Duke" ganhou um **OK**; a janela de
teste virou um formulário, com um campo e o **Limpar**; e a grade do
Terminal virou a `AreaDeTexto`, um widget que o programa escreve de fora e
que redesenha só a linha do cursor enquanto não rola — o que a fumaça do
ARM exige. No runtime, toda janela tem uma interface: a janela vazia, a
tela crua da moldura e o escritor da descrição ficaram privados. E
`cargo xtask invariantes` confere que nenhum programa pega a memória de
pixels, chama `descrever` ou escreve um elemento, fora a moldura do
runtime e três programas que conferem a ABI crua do kernel — cada um com
o motivo escrito ao lado.

**Pelos dois caminhos.** Cada caso confere o que a pessoa faz e o que o
agente faz. O programa `formulario` — dois campos, dois botões — é o outro
lado de um caso da suíte que o preenche pelo `ui.tree` e pelo `ui.act` de
verdade, e pelo teclado. A fumaça faz o mesmo de fora: lança o formulário
pelo `user.run`, preenche os campos e aperta o OK pelo canal do agente,
digita no mesmo campo e confirma com o Enter pelo teclado da máquina, e o
fecha pela caixa com o mouse — como fecha o "Sobre o Duke" pelo OK.

**O Terminal, pelo agente.** O Terminal era a única janela em que o
agente lia e não fazia: a pessoa digitava nele, e o agente, para digitar
no mesmo interpretador, ia pela linha de comando do console do kernel —
outro caminho. Agora a grade do Terminal tem uma `LinhaDeComando` do
toolkit: na árvore, a grade é uma área de texto e a linha é um campo dentro
dela, o mesmo par que o console publica. O valor da linha é lido da grade
— o que vem depois do prompt, até o cursor, inclusive quando quebra na
borda —, e é, portanto, o que a pessoa vê, seja quem for que digitou. O
`set_value`, o `cancel` e o `confirm` do agente viram o que o Terminal
digita no pseudo-terminal, pelo mesmo caminho das teclas da pessoa.

Duas coisas no interpretador tornaram isso possível sem adivinhar nada.
Apagar a linha inteira — o Ctrl-U dos terminais —, para trocar o que está
digitado sem saber quantas letras há. E um Enter do agente, um caractere
da área de uso privado que nenhum teclado produz: o que chega pelo
pseudo-terminal vem pela fila do teclado, e sem ele um comando que o
agente executou pelo Terminal ficaria no log como da pessoa. O caso da
suíte e a fumaça conferem os dois: o agente digita, esvazia, digita de
novo e executa, e o log diz `executado: agent.ping (agente 3)` — o número
da sessão do agente, que o Terminal leva junto com o Enter. Um processo
com o pseudo-terminal pode escrever o Enter do agente sem ter sido pedido
— atribuir ao agente o que a pessoa fez é o erro menos grave, e o registro
que a pessoa confira é da fase 12.

Noventa e seis mutações nas seis etapas, e as noventa e seis reprovadas —
várias só depois de o caso ser reforçado. Seis das oito da
linguagem visual passavam: a suíte conferia a tela contra as constantes
do kernel, e as constantes vinham do token mutado. No campo, seis das
dezoito do hospedeiro passavam, e cada uma virou uma pergunta nova — o
apagar no meio do texto, o teto ao digitar, o corte no meio de uma letra.
Na migração, a janela um pixel mais curta passava porque nenhum caso media
o tamanho de uma janela; e as duzentas linhas que o Terminal guardava
passavam porque nada as lia — foram tiradas, em vez de testadas.

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

Mas dormir não é sair da vez. Quem espera a interrupção continua sendo o
fio atual: o tique o acorda, desconta um do quantum e o devolve a ele, que
volta a dormir — até o quinto. Com outros fios prontos no mesmo núcleo, o
coletor segurava o núcleo parado por uma fatia inteira a cada volta do
rodízio, e o laço do executor, com a fila vazia, fazia o mesmo a qualquer
processo de usuário. Com um núcleo só, cinquenta milissegundos parados por
volta: as cópias do `cedente` levavam minutos. Com vários, os outros
núcleos escondiam. Os dois agora passam por
`fios::descansar_ate_a_interrupcao` (o executor, pela mesma pergunta, ao
lado do teste atômico da fila dele): havendo outro fio pronto neste
núcleo, cedem; só dormem quando não há ninguém — o que mantém o motivo
acima. O coletor faz uma passada por tique, no máximo, como fazia
dormindo. `fios: quem nao tem o que fazer da a vez` prende o coletor e um
fio que cede no mesmo núcleo, em qualquer número de núcleos, e mede.

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

## Interface nativa

O Duke não imita outro sistema. Um programa do Duke fala a língua do
sistema — o registro de comandos, o mesmo que a pessoa fala pelo
interpretador e o agente pelo canal —, pelo mesmo ponto de decisão, com a
autoridade de quem o lançou, na mesma auditoria. Não há números de chamada
do Linux, nem `errno`, nem `/proc`, nem tradutor. O desenho inteiro, com o
que a análise encontrou no caminho, está em
[`docs/INTERFACE.md`](docs/INTERFACE.md).

**Duas camadas.** As chamadas de mecanismo — memória, processo,
descritores, eventos, superfícies — continuam pequenas e binárias. O resto —
mensagens, arrendamentos, auditoria, árvore semântica, estado — chega por
uma chamada só: `pedir` leva um pedido JSON-RPC ao registro, e `resposta`
busca o envelope, que é o do canal, com o mesmo código de recusa. O JSON é
um só, em `protocolo::json`, para o kernel e para os programas; o cliente
tipado é `programas::nativo`:

```rust
let r = programas::nativo::pedir("message.send", |w| {
    w.field_str("to", "serial")?;
    w.field_str("body", "oi")?;
    w.field_u64("nonce", 1)
})?;
```

**O comando não roda na chamada de sistema.** A chamada roda com as
interrupções mascaradas — e, no ARM, na pilha de exceção do núcleo —, e um
handler do registro pode ir ao disco e ao TPM. Então `pedir` deixa o pedido
no fio e o põe a esperar; a tarefa `programas` do executor o atende, onde os
comandos sempre rodaram, e acorda o fio com a resposta. A resposta fica no
fio até ser buscada: o comando já teve efeito, e ela pode não caber no
buffer do programa.

**Quem pediu e por quem.** O gate decide um pedido de processo como
`Chamador::Processo`: a autoridade é a de quem o lançou, procurada a cada
decisão (uma pessoa que sai leva o processo junto), e a auditoria diz
"pelo processo N (nome resumo)". O que é de um canal — a prova
administrativa e `debug.trigger` — é recusado a um processo. Um processo não
age na interface (`ui.act`): a origem de uma ação diz ao dono do campo quem
agiu, e um processo com a origem de quem o lançou confirmaria em nome dele
uma linha que ele não viu. As mensagens de um processo saem da caixa de quem
o lançou, mas contam os nonces na janela do processo. A taxa é do principal
— a chave do agente —, e não da vaga da sessão.

**O manifesto.** Cada executável declara, numa nota ELF, quem é e o que
pretende exercer:

```rust
programas::manifesto!("visualizador", "fs.read", "system.read");
```

A permissão efetiva do processo é o papel de quem o lançou **interseção** o
manifesto: um programa nunca tem mais que quem o lançou, e pode ter menos.
Sem manifesto, nada — nem lançado pelo sistema. O manifesto é lido antes do
ponto de não retorno do `executar` (um ilegível recusa a imagem, não vale
como vazio), e troca junto com o espaço de endereços: a imagem nova nunca
roda com o manifesto da anterior.

**O que a releitura e as mutações mostraram.** Dezoito mutações dirigidas
à interface — tirar a recusa do que é de um canal, ignorar o manifesto no
`pedir` e nas chamadas de sistema, dar tudo a quem não tem manifesto, fazer
o processo nascer como fio do kernel, não herdar o manifesto no `fork`, não
trocá-lo no `executar`, dar origem de pessoa ao processo, gastar os nonces
do agente, um balde só, perder a resposta que não cabe, tratar a
reexecução como pedido novo, não achar a nota, aceitar o manifesto
ilegível, não esquecer a janela de nonces, tirar a taxa do programa de uma
pessoa, deixar a resposta atravessar o `executar`, tirar a taxa do pedido
quebrado —, e as dezoito reprovadas. Duas só depois de um caso novo: a da
reexecução passava pela suíte inteira, porque nenhum caso acordava um fio
no meio de um pedido; e a da recusa de `debug.trigger` derrubava o kernel
em vez de reprovar o caso, porque o caso pedia a falha `fatal`. A releitura
achou três defeitos de verdade, corrigidos com o caso que os reprova: a
resposta não buscada atravessava o `executar` — a imagem nova lia o que só
a anterior podia pedir —; o programa de uma pessoa pedia sem taxa; e o
pedido quebrado ia para a auditoria sem passar por balde nenhum. A fumaça
roda `contido` e `anonimo` no kernel de produção, pela tarefa `programas`
do executor de verdade — que a suíte não tem —, nas duas arquiteturas.

## Armazenamento nativo

Os programas, os agentes e as pessoas guardam dados no **armazém**: uma
árvore de arquivos e diretórios montada em `/armazem`, gravável, com versão
por objeto, arrendamento para quem edita e cota por dono, numa **partição
própria** do disco. O desenho inteiro, com o porquê de cada escolha, está
em [`docs/ARMAZENAMENTO.md`](docs/ARMAZENAMENTO.md).

Não há um segundo sistema de autorização, nem uma segunda API. Escrever é
pedir um comando do registro — pelo canal, pelo interpretador ou pelo
`pedir` de um programa —, e o comando passa pelo mesmo gate e vai para a
mesma auditoria. Cada conceito num lugar só, com a sua recusa:

| Conceito | Onde | Recusa |
|---|---|---|
| Autorização | o gate: `fs.write` no papel ∩ manifesto do programa | `DENY_PERMISSION` |
| Alcance de caminho | o gate, sobre **cada** caminho do pedido: os dois de um rename, todos os de um lote | `DENY_RESOURCE` |
| Reconfirmação | no ponto de commit: a sessão, o papel e a política de agora ainda dão a autoridade? | a recusa de agora |
| Arrendamento | a coordenação, recurso `fs:<caminho>` — só o arrendamento | `CONFLICT` (`lease`) |
| Versão | o armazém: a da última mudança, de um contador do armazém inteiro | `CONFLICT` (`version`) |
| Cota | o armazém, com a linha `armazem <papel> <bytes> <objetos>` da política, por dono | `DENY_QUOTA` |
| Persistência | o volume do armazém, confirmado por um registro do journal de estado | `ERROR`, e nada muda |
| Auditoria | a decisão, e o que o comando fez, no mesmo registro que o commit | — |

```text
$ cargo xtask agent fs.mkdir '{"path":"/armazem/compartilhado/notas"}'
{"ok":true,"path":"/armazem/compartilhado/notas","version":1,"size":0,"durable":true}
$ cargo xtask agent fs.write '{"path":"/armazem/compartilhado/notas/a.txt","content":"um","expect_version":0}'
{"ok":true,"path":"/armazem/compartilhado/notas/a.txt","version":2,"size":2,"durable":true}
$ cargo xtask agent fs.write '{"path":"/armazem/compartilhado/notas/a.txt","content":"dois","expect_version":0}'
{"ok":false,"code":"CONFLICT","conflict":"version","current_version":2,"error":"a versao esperada nao e a de agora"}
```

**A partição própria.** O conteúdo vai em blocos cifrados de 4 KiB numa
partição GPT só do armazém (`duke-armazem`), com um journal de metadados
próprio; o driver do disco tem duas janelas de escrita, e o `xtask` confere
que só a persistência escreve na de estado e só o volume na do armazém.
Encher o volume não enche o journal das credenciais. O journal de estado
guarda, do armazém, uma entrada só: qual registro do journal do armazém
vale — e esse registro, ancorado no TPM, é o **ponto de commit**. Uma queda
antes dele deixa blocos e um registro que o boot não confirma, e que ficam
livres; nada de um lote pela metade parece confirmado.

**Diretórios, renomear, lotes, binário.** Diretórios são explícitos
(`fs.mkdir`, `fs.rmdir` vazio); `fs.rename` move um arquivo ou uma árvore,
com o gate decidindo os dois caminhos e cada nó movido recebendo versão
nova; `fs.batch` faz até 32 operações num lote só — tudo ou nada, um
registro e um avanço do contador do TPM. O conteúdo binário vai fora do
JSON, num **anexo** — pela chamada `PEDIR_COM_ANEXO` de um processo, ou em
quadros de anexo da sessão cifrada de um agente, declarados em
`"attachment"` —, e o que passa de 60 KiB vai por um rascunho (`fs.draft`).

**A política dá, e só ela.** A padrão escreve `fs.write` para o `sistema`
em `/armazem` e para o `operador` em `/armazem/compartilhado`, e a cota de
cada um; o observador não escreve. O papel do administrador é um teto — o
que ele pode delegar — e nenhuma sessão o exerce. O `sistema` não arrenda:
o arrendamento de uma pessoa vale contra ele, e só o `lease.revoke` de um
administrador, com a prova, o quebra.

**A leitura é a de sempre.** `fs.read`, `fs.list` e o `abrir` dos processos,
pelo VFS, sob `fs.read`, com o conteúdo lido do volume bloco a bloco. O nó
de um arquivo é a versão dele: um descritor aberto antes de uma mudança
recebe `MUDOU` (-17), e nunca metade de um conteúdo e metade de outro.

O programa [`guardar`](programas/src/bin/guardar.rs) faz o caminho inteiro
de dentro: declara `fs.read` e `fs.write` no manifesto, cria o diretório
dele, grava, ouve o conflito de versão, lê pelo descritor, vê o `MUDOU`, é
recusado fora do alcance de quem o lançou, e manda binário pelo anexo.

### O que as mutações mostraram

Na fase 8, com o armazém ainda no journal de estado: dezesseis mutações dirigidas ao armazém, cada uma contra a suíte inteira
com quatro núcleos (as da conta pura e da política, contra os testes do
hospedeiro antes): **dezesseis reprovadas**, cada uma pelo caso do conceito
que ela tira — o arrendamento que não confere, a persistência que não é
exigida antes, aplicar antes de gravar, a mutação fora da ordem das
gravações (reprovada pelo caso de vários núcleos no mesmo arquivo), o
titular de qualquer um, a versão que não confere, a base fora da ordem das
versões ou sem a próxima versão, o nó velho lendo o conteúdo novo, o
resultado auditado em nome do kernel, o diretório arrendado, o sistema
escrevendo na árvore inteira, o handler que não audita o que fez, a
gravação sem o conteúdo, o `lease.revoke` que não acha o caminho e os
filhos fora da ordem dos nomes. Três delas os casos não viam — achado ao
escrever a campanha, antes de rodá-la —, e os casos ganharam a
conferência: nenhum anúncio de mudança na auditoria sem persistência, um
arquivo de versão nova num nome que vem antes, e o que o comando fez em
nome da pessoa, pelo processo. Uma (a mutação fora da ordem das gravações)
só a pega o caso de vários núcleos, e é reprovada com quatro.

### O que mudou desde a fase 8

A dívida que a fase 8 deixou — o armazém no journal de estado com tetos de
16 KiB, 256 arquivos e 512 KiB; só texto; sem renomear nem diretórios
explícitos; sem cota por titular; uma mutação por registro e por avanço do
TPM; e o caso da reposição que compactava antes de conferir — foi resolvida
na arquitetura, e não com números maiores: partição própria com o commit
ancorado no journal de estado, anexo binário e rascunhos, diretórios e
rename decididos nos dois caminhos, cotas por dono na política, lotes, e
uma reposição que reconstrói a imagem limpa com o journal inteiro. O que
ficou, e por quê, está no fim de [`docs/ARMAZENAMENTO.md`](docs/ARMAZENAMENTO.md).

### As mutações das limitações resolvidas

Vinte e cinco mutações, uma por propriedade que a resolução das
limitações criou ou passou a depender, cada uma contra os testes do
hospedeiro do pacote dela e então contra a suíte inteira com quatro
núcleos: **vinte e cinco reprovadas**, cada uma pelo caso — ou teste do
hospedeiro — da propriedade que ela tira.

| Mutação | Reprovada por |
|---|---|
| a inversão de duas travas não é registrada | `travas: a conferencia ve a inversao` |
| a ordem das gravações fora do grafo | `travas: a conferencia ve a inversao` |
| a suíte esvazia as mensagens sem o journal | `reconstrucao: imagem limpa e journal inteiro` |
| a sessão exerce o teto | `mensagens: sem atalho na autorizacao` |
| o teto é atribuível | `teto: o administrador delega e nao exerce` |
| a serial pode ter o teto | `politica`: `nenhum_teto_e_exercido` |
| o sistema decide sem a política (curinga) | `politica`: `caminho_sem_alcance_nao_e_tudo_na_decisao` |
| sem a linha da política, o sistema ainda escreve no armazém | `politica`: `a_matriz_aprovada` |
| o driver escreve fora da janela | `armazem: o volume e da particao propria`, `disco: recusa escrita fora da janela` |
| o volume repõe além da âncora confirmada | `armazem: gravacao que falha nao vale` e as reposições |
| o volume não confere o elo confirmado | `armazem: o volume so vale confirmado` |
| o lote vale sem o commit | `armazem: gravacao que falha nao vale` |
| sem reconfirmação no commit do lote | `armazem: revogacao no meio da operacao` |
| o gate decide só o primeiro caminho | `armazem: diretorios e renomear` (o rename escapa do alcance) |
| o movido guarda a versão velha | `armazem`: `renomear_um_arquivo` |
| a cota não é conferida | `armazem`: `a_cota_e_do_lote_e_de_quem_pede` |
| todos os agentes são um dono só | `armazem: a cota e de cada dono` (a disputa) |
| o lote passa por cima da operação recusada | `armazem`: `conteudo_incoerente_e_recusado` |
| o canal não confere o anexo declarado | `armazem: o agente manda binario no anexo` |
| o commit do armazém não avança o contador do TPM | `diario`: `a_auditoria_nao_gasta_o_contador` |
| a mensagem não reconfirma no commit | `mensagens: revogacao no meio da operacao` |
| a operação administrativa não reconfirma | `admin: revogacao no meio da operacao` |
| a reconfirmação decide o destinatário como caminho | `mensagens: o remetente vem da sessao` |
| só o núcleo dos dispositivos anda o relógio | `smp: o relogio anda sem o nucleo dos dispositivos` |
| todo núcleo anda o relógio | `smp: o relogio anda uma vez por tique` |

### As mutações da auditoria seguinte

Dezessete mutações contra o que a auditoria do estado depois das
limitações corrigiu — a cessão de dentro do handler, o estouro na guarda,
a compactação sem fila, as travas nos dois modos, o `fs.read`, o
silêncio do canal e o fio ocioso que segurava o núcleo —, cada uma contra
a suíte de quatro núcleos ou a fumaça da arquitetura dela: **dezessete
reprovadas**.

| Mutação | Reprovada por |
|---|---|
| a chamada `ceder` cede de dentro do handler (ARM) | o pânico de `ceder_cpu`, que aponta `usuario/mod.rs` |
| o mesmo, sem a guarda de `ceder_cpu` (ARM) | `usuario: varios processos cedem em varios nucleos` — a falha `0x96000007` do CI |
| a cessão pedida nunca é dada (ARM) | `usuario: varios processos cedem em varios nucleos` (as trocas) |
| a cessão pedida nunca é dada (x86) | o mesmo caso |
| a entrada dos vetores sem a conferência da pilha | a fumaça do ARM: relatado como `data_abort` |
| a conferência sem o último byte do quadro | a fumaça do ARM, no estouro da borda: o post-mortem não responde |
| quem toma a ordem não compacta | `compactacao: a base que nao cabe, a regiao que enche, e o coletor` |
| o coletor não compacta | o mesmo caso |
| a trava tomada com as interrupções ligadas não é anotada | `travas: a conferencia ve a inversao` |
| a trava segurada com elas ligadas não é anotada | o mesmo caso |
| o disco ligado com as interrupções ligadas | `travas: nenhuma inversao de ordem` |
| `fs.read` decide texto pelo pedaço | `armazem: fs.read devolve o que esta no arquivo` |
| o pedaço de texto sem o caractere inteiro | o mesmo caso |
| o base64 sem o preenchimento | o mesmo caso |
| o silêncio do canal nunca marcado | `agente: o silencio e medido na chegada` |
| o coletor dorme com outros prontos (x86) | `fios: quem nao tem o que fazer da a vez` — cem cessões em 500 tiques |
| `ha_outro_pronto` sempre falso (ARM) | o mesmo caso, os mesmos 500 tiques |

Duas mudaram a suíte antes de reprovar como deviam. Só o núcleo dos
dispositivos andando o relógio era pega pelo limite de andamento, dez
minutos depois, e não pelo caso: o fio que mede esperava o relógio parado;
agora o prazo dele é o timer do próprio núcleo. E a da suíte que esvazia as
mensagens sem o journal, numa primeira rodada com a bancada carregada,
reprovou por um caso de coordenação; refeita sem carga, só o da
reconstrução.

## Vários agentes

O Duke atende vários agentes ao mesmo tempo, cada um numa **sessão**: um
canal com o seu quadro sendo montado, a sua tarefa e a sua saída. O pedido
de um não cola no do outro, e a resposta de um não sai pelo canal do outro.
O número da sessão é dado pelo kernel, pelo canal por onde o pedido chegou
— e não dito pelo agente —, e é ele que o log registra como quem agiu:

```
info ui       agente 2: confirm no elemento 3
info console  executado: agent.ping (agente 2)
```

**Os canais.** A serial continua sendo a sessão 0, e a de emergência: a
única que responde no modo post-mortem. Os agentes têm, além dela, o
transporte local: o `virtio-console` com várias portas — o recurso
`MULTIPORT` —, cada porta num socket próprio no hospedeiro, as sessões 1 a
4. O driver faz o aperto de mão do `MULTIPORT` pela fila de controle: diz
que está pronto, o dispositivo anuncia cada porta, o driver a põe de pé e a
abre do lado dele, e o hospedeiro manda o nome dela. `agent.session` diz a
um agente qual é a sessão dele; `agent.sessions` lista todas, com quem está
conectado e o que se perdeu.

**Uma coisa que a serial não dava: a conexão.** A serial não enxerga quando
um cliente conecta ou cai, e convive com isso por um teto de ociosidade e
uma linha vazia que o cliente manda ao chegar. A porta enxerga: o
dispositivo avisa cada abertura, e o quadro que estava pela metade fica com
quem saiu. Uma resposta para uma porta sem ninguém do outro lado é
descartada e contada, e uma que ninguém lê não cresce sem fim.

**Acima do transporte.** O enquadramento, o JSON-RPC e os comandos não
sabem por onde os bytes vieram: perguntam ao canal da sessão. É o que deixa
o próximo transporte — o TCP, quando houver rede, e o vsock, para as máquinas
virtuais — entrar como mais um caso, sem mudar nada em cima. São sete
etapas: o transporte e as sessões; o canal seguro, abaixo; depois a camada
de controle (política, auditoria encadeada, limites, revogação), os
conflitos entre agentes, as mensagens entre eles, o indicador na barra, e
os testes com os quatro ao mesmo tempo.

**Quatro ao mesmo tempo.** Cada etapa tem os casos dela; a última confere o
que só aparece com todos juntos. Na suíte, quatro agentes — três
operadores e um sistema, como na imagem — com os pedidos intercalados:
todos chegam antes de qualquer um ser atendido, e as portas são atendidas
em ordens diferentes a cada rodada.

- **A disputa por um campo:** os quatro pedem a linha de comando; um a
  toma, os outros três ouvem `CONFLICT`; os quatro tentam escrever, e só o
  dono escreve.
- **Todos para todos:** cada um manda uma mensagem a cada um dos outros,
  em três rodadas intercaladas; cada caixa tem exatamente três, uma de cada
  remetente, na ordem de aceitação, sem duplicata, e o reenvio devolve o
  mesmo id.
- **A revogação no meio:** a chave do dono do campo é revogada; o
  arrendamento sai, as mensagens dele — mandadas e por receber — são
  anuladas, a barra conta três, ele é recusado, e os outros seguem: o
  campo vai para o próximo que pedir.
- **No fim,** a cadeia da auditoria confere, nenhum recurso tem dois
  arrendamentos, e a tabela de mensagens está coerente.

Na fumaça, o mesmo pelas portas de verdade: quatro fios do hospedeiro,
soltos juntos por uma barreira, mandando cada um a cada outro; cada caixa
com uma de cada, em ordem; `agent.list` vendo os quatro; e a auditoria
conferida pela porta de papel `sistema`. A barreira tem prazo: um fio que
falha não deixa os outros esperando, e a fumaça falha com o motivo dele
em vez de pendurar.

### O canal seguro

**A identidade é a chave.** Um agente é a sua chave pública X25519. Ele não
declara nome nem senha: prova, no aperto de mão, que tem a privada que
corresponde à pública, e o nome que o log e os relatórios mostram vem do
registro do Duke, não dele.

**O aperto: `Noise_IK_25519_ChaChaPoly_BLAKE2s`.** O padrão do WireGuard. O
agente já conhece a chave pública do Duke — foi provisionada —, então basta
uma ida e volta; a chave do agente viaja cifrada desde a primeira mensagem;
e os dois lados se autenticam. Depois dele, cada mensagem vai cifrada com
ChaCha20-Poly1305 e um contador: uma mensagem adulterada, repetida ou fora
de ordem não abre, e a sessão acaba ali — o contador não sabe mais onde o
outro lado está, e tentar adivinhar seria abrir a porta para quem está no
meio. Uma conexão nova recomeça do aperto. Na porta, as mensagens vão em
quadros com o tamanho na frente (o JSON por linha continua por dentro): uma
mensagem cifrada tem qualquer byte, inclusive `\n`.

**Uma implementação, conferida por fora.** O Noise está no pacote `sigilo`,
usado pelo kernel e pelo cliente do `xtask` — a mesma conta dos dois lados.
E uma implementação só concorda consigo mesma mesmo errada, então os testes
do `sigilo` conferem os vetores publicados do padrão — um deles gerado pela
Cacophony, em Haskell — e conversam com o `snow`, outra implementação em
Rust, nos dois papéis. As primitivas são do RustCrypto e do dalek, e no
kernel vão sem SIMD: os registradores de SIMD são do processo interrompido,
e este kernel não os salva.

**Autenticado não é autorizado.** Uma chave que completa o aperto ainda
precisa estar no registro, ou recebe uma recusa — com o motivo, em claro.
O registro vem da imagem: o `xtask` gera as chaves em `target/chaves/` (fora
do repositório: uma chave privada versionada é pública) e grava no disco as
públicas dos agentes, em `/etc/duke/agentes`, a dos administradores, e a
privada do Duke em `/etc/duke/privado/`, que o VFS recusa a qualquer caminho
que não seja o do kernel — nem um processo, nem o `fs.read` de um agente a
alcançam. As chaves efêmeras vêm de um gerador ChaCha20 com apagamento rápido
da chave, semeado pelo `virtio-rng`; sem entropia, as portas recusam o aperto
em vez de gerar chaves que alguém reproduza.

**A serial continua aberta.** É o canal de emergência, independente do Noise
— e o único que responde no modo post-mortem, quando fazer criptografia
seria pedir ao heap e ao escalonador, que podem ser o que quebrou. O nível
de acesso dela é configurável na política — a linha `serial` —, e é o de
`sistema` na imagem de desenvolvimento.

**Operações administrativas têm autenticação própria.** Registrar um agente
(`agent.register`, gravado no journal da partição de estado — ver
[`docs/PERSISTENCIA.md`](docs/PERSISTENCIA.md))
não é um comando que se chame: vai embrulhado em `admin.execute`, com a
prova de um administrador. O Duke dá um desafio — um nonce e uma chave
efêmera —, o administrador faz o Diffie-Hellman da chave dele com a efêmera,
e o segredo **não** vira chave direto: passa por um HKDF que amarra a chave
ao nonce, à sessão, às duas chaves públicas, ao comando e ao texto exato dos
parâmetros. A prova feita para um pedido não serve para outro nome, outro
comando, outra sessão ou outro desafio, e o desafio vale uma tentativa, por
trinta segundos. Vale em qualquer sessão — inclusive na serial, que é aberta
e por isso mesmo não pode registrar ninguém sem prova.

Os parâmetros vão até **1 KiB**, e todos sob a prova: o texto inteiro entra
na derivação e no HMAC, byte a byte — nada sai dele para caber. É o que o
pedido maior precisa: o `message.send` do administrador com o corpo cheio,
512 bytes, que com o teto antigo de 512 de parâmetros não cabia. Como o
texto vai escapado dentro do JSON de `admin.execute`, a linha do pedido foi
para 4 KiB: o pior escape de um texto válido, `\uXXXX` para o que não é
ASCII, triplica o tamanho, e 3 KiB mais o envelope cabem. Um pedido com
1025 bytes de parâmetros é recusado antes de gastar o desafio; uma linha
além do quadro, com um erro, sem derrubar a sessão. O `agent.registry` diz
o limite, `admin_max_params`. O texto desescapado aceita também o par de
substitutos UTF-16 de um caractere fora do plano básico — um emoji escrito
como `\ud83d\ude00` era recusado como parâmetro inválido.

**Revogar um administrador exige quórum: 2 de 3.** O administrador de
verdade é a credencial — a chave que prova —, e não um papel: o papel
`administrador` é o teto do que ela delega, e nenhuma sessão — de agente
ou de pessoa — o exerce (`DENY_ROLE`); ver [O teto não é posse](#o-teto-não-é-posse). A
imagem tem um grupo de três credenciais, e `admin.revoke` tira uma delas só
com a prova de **duas outras**: uma chave roubada, sozinha, não revoga as
dos donos legítimos. O M e o N são da política, por operação — a linha
`quorum admin.revoke 2 3` —, só da imagem: o `policy.write` não a muda, e o
`xtask` não gera uma imagem cujo grupo não tenha o N que a política diz.

**O quórum tem piso.** O de `admin.revoke` é invariante da política: pelo
menos 2 credenciais e pelo menos dois terços do grupo — 2 de 3, 3 de 4 ou
4 de 5 cabem; 2 de 4 ou 3 de 5, em que uma minoria revogaria as outras,
não. O piso é conferido na validação de toda política, por qualquer
caminho: a imagem que o violasse nem é gerada, o boot com uma política
abaixo dele fica com a de emergência (que está no piso), e uma mudança que
o baixasse é recusada — mesmo que o `policy.write` um dia aceitasse a
linha `quorum`, o que hoje não acontece.

O caminho é o de toda operação administrativa, com M credenciais no lugar
de uma: `admin.challenge` com `{"for":"admin.revoke"}` dá um desafio de
quórum — que diz a versão da política, M e N, e vale dois minutos, para as
assinaturas serem juntadas —; cada credencial assina o **mesmo** conteúdo
canônico (`sigilo::quorum::Conteudo`: a versão do formato, o número da
operação, o nonce e a efêmera do desafio, a sessão, a versão da política,
M, N, o comando, o alvo e o texto exato dos parâmetros, cada campo
variável com o tamanho na frente); e `admin.execute` leva as assinaturas
em `signatures`, `credencial:assinatura,...`. A assinatura é **Ed25519**
(RFC 8032), sobre um rótulo próprio seguido dos bytes canônicos: cada
credencial assina com a chave **privada** dela, que fica com quem assina —
no desenvolvimento, em `target/chaves/`, fora do repositório e da imagem —,
e o Duke confere com a **pública**, que está no registro de
administradores (`ed25519:<hex>`, ao lado da chave X25519 da credencial). A
chave que confere vem do registro, pela credencial, e nunca do pedido; o
Duke não tem nem precisa de chave privada nenhuma para conferir, e nada do
que ele tem produz uma assinatura. A conferência é a estrita: sem chave de
ordem pequena, sem segunda grafia de uma assinatura válida. Qualquer um com
a pública confere depois, fora do Duke — a fumaça confere as dela no
hospedeiro antes de mandá-las.

O kernel confere, nesta ordem: o formato; o desafio, que sai de qualquer
jeito e tem de ser de quórum para esta operação, sob a política de agora;
cada assinatura sobre o conteúdo, de credencial do grupo, ativa, uma vez
só — uma que não confere derruba o pedido inteiro —; M delas; o papel de
cada uma com `admin.revoke`, pela mesma decisão de toda operação
administrativa; o alvo existe, não está revogado e não assina a própria
revogação; e restam ao menos M ativas — conferido e marcado numa seção
só. A revogação vale na hora: a credencial não prova, não assina e não
recebe mais nada, as mensagens vivas dela são anuladas, e **todos os
desafios pendentes saem** — de qualquer sessão: um desafio não é de uma
chave, e quem estava no meio pede outro, sobre o estado novo. É também a
regra da concorrência: o pedido atendido primeiro decide, e o outro é
recusado. Uma operação da credencial que já estava em curso — a prova
conferida, a operação ainda não feita — é decidida de novo antes de tocar
em qualquer coisa, com a ordem das gravações na mão: ela vê a revogação e
é recusada (`DENY_NOT_AUTHENTICATED`), ou vem antes dela inteira; o mesmo
vale para uma política nova que tire a permissão do papel. O que a
credencial fez antes fica na auditoria; a revogação
grava cada assinatura, com a chave inteira de quem assinou, e o desfecho,
com o alvo, o desafio, a versão da política e o motivo. Nenhum papel — nem
o `sistema`, nem a serial — substitui o quórum, e não há operação de
recuperação que o contorne. **A revogação sobrevive ao reboot**: a lápide
vai para o journal da partição de estado antes de a resposta sair, ancorada
num contador do TPM, e o boot a aplica por cima da imagem — uma imagem que
traga de volta a credencial revogada não a reabilita. As assinaturas do
quórum cobrem também a geração administrativa: uma mudança de autoridade
entre o desafio e o pedido as derruba. Ver
[`docs/PERSISTENCIA.md`](docs/PERSISTENCIA.md).

Medido: um aperto de mão leva, com os dois lados dentro da suíte em debug,
de 30 a 70 ms — eram 210 antes de as primitivas serem compiladas otimizadas
mesmo no build de depuração.

**O Terminal também.** Um agente que digita no Terminal pela linha de
comando da janela chega ao interpretador pelo pseudo-terminal, como uma
pessoa — e o interpretador precisa saber qual agente foi. A ação que chega
ao Terminal diz a sessão de quem a pediu, e o Terminal digita o Enter
daquele agente: um caractere da área de uso privado por sessão. O log diz
`(agente 2)`, e não só `(agente)`.

A suíte atende as portas à mão — põe bytes na entrada de cada uma e
confere a saída —, com um agente de teste que faz o aperto de mão inteiro:
os pedidos intercalados entre duas portas, um pedido partido em dois
quadros cifrados, uma conexão nova no meio de um quadro, o `ui.act` de uma
porta chegando ao log com o número dela, uma chave fora do registro, um
quadro adulterado, um quadro repetido, a chave do Duke fora do alcance do
VFS, o gerador semeado, e o registro administrativo com e sem a prova
certa. A fumaça passa pelo dispositivo de verdade, com o cliente do `xtask`:
quatro agentes, em quatro fios do hospedeiro, cinquenta pedidos cada, ao
mesmo tempo, cada um recebendo só as respostas dele; o agente da porta 2
executando um comando no Terminal, com o log dizendo `agente 2`; as recusas
chegando ao hospedeiro; e um agente registrado pela serial, com a prova do
administrador, entrando pela porta logo depois.

### A política

O canal seguro diz **quem** pede; a política diz **o que** cada um pode. A
cadeia é uma só, e cada elo tem um dono:

```
identidade → sessão → papel → permissão → operação
```

A identidade é a chave que provou o aperto (ou a serial, que é aberta); a
sessão, o canal por onde o pedido chegou; o papel vem do registro — uma
terceira coluna em `/etc/duke/agentes` —, e a política, em
`/etc/duke/politica`, diz o que cada papel pode. Cada comando declara a
permissão que exige e, quando ela é sobre um caminho, de qual parâmetro sai
o recurso. A decisão é uma conta só, no pacote `politica`, e o kernel a
chama num lugar só: `autorizacao::autorizar`.

**Papéis, e não listas por agente.** Quatro na imagem: `observador` observa
o sistema e a tela, e não lê arquivos; `operador` observa e age — a tela,
programas de `/bin` e `/programas`, arquivos de `/dados`, `/bin` e
`/programas`; `sistema` é a autoridade máxima — a da serial e dos
processos do sistema; `administrador` é o teto do que um
administrador delega. Um papel pode incluir outro (`@observador`), mas as
permissões **sensíveis** — `fs.read`, `fs.raw_read`, `keyboard.read`,
`debug.trigger`, `terminal.attach`, as administrativas — não atravessam a
inclusão: cada papel que as tem as escreve. Não há curinga: `*` é um erro de
leitura. Quatro agentes ou quatrocentos, a política continua do tamanho dos
papéis.

**O sistema é o máximo, e enumerado.** O papel `sistema` não inclui outro e
não é um passe livre: lista cada permissão pelo nome — tudo, menos as
administrativas (que são do administrador, com a prova) e as de escrita
(que nenhuma operação usa) —, e o alcance de cada uma de caminho numa linha
`recurso`, `/`. A autoridade local — os processos do sistema: o servidor de
janelas, o Terminal — tem o papel da linha `local` da política, e decide
pela mesma conta e grava na mesma auditoria que qualquer agente: não há `ALLOW` por ser
sistema. Uma linha de `policy.write` não encolhe o papel da serial nem o da
autoridade local.

**Recursos por caminho.** `fs.read` e `process.run` têm o alcance escrito
numa linha `recurso`, sempre: sem ela a política é recusada, porque "sem
limite" seria um curinga escrito pela ausência. O alcance inteiro também se
escreve — `/`. O caminho é conferido na forma normal — a mesma função que o VFS
usa, do pacote `politica` —, um `..` é recusado e não resolvido, e um
prefixo vale em fronteira de componente: `/dados` contém `/dados/x`, e não
`/dadosx`. O diretório reservado do kernel não é recurso de papel nenhum,
nem do `sistema`.

**Nenhum outro caminho.** O canal (serial e portas) e o interpretador
pedem a mesma decisão e só a licença que ela devolve chama o handler — o
`cargo xtask invariantes` reprova uma chamada `(…handler)(` em qualquer
outro arquivo. O interpretador valida os parâmetros como o canal; a pessoa
num console decide pelo papel dela no registro, pela sessão que abriu — ver
[Pessoas](#pessoas) —, e um agente que confirma uma linha no Terminal
decide como a sessão dele. Todo processo carrega a autoridade de quem o
lançou — a do sistema, a da pessoa ou a do agente (`user.run`) —, e o
`fork` a herda: as chamadas `abrir` e `executar`
decidem com esse papel, e prender-se ao pseudo-terminal é a permissão
`terminal.attach`, que só o `sistema` enumera — um processo de agente não o
abre, nem quando a janela do Terminal está fechada. O papel é procurado a
cada decisão: uma revogação vale também para o processo que já roda.

**A única exceção é o boot.** Antes de haver política, o kernel lê a sua
chave privada, o registro e a própria política. A leitura do diretório
reservado só é chamada pela identidade, e as duas cargas só pelo boot — o
`cargo xtask invariantes` confere os dois —, e nenhum comando, chamada de
sistema, console, serial ou pseudo-terminal as alcança.

**Tudo vai para a auditoria.** Permitido ou não, cada decisão vira um
registro: número, o tempo lógico em milissegundos (o RTC com o piso do
journal — ver [Persistência](#persistência)), o tipo de titular (kernel,
sistema, serial, agente, pessoa, administrador ou ninguém ainda), sessão,
sessão de pessoa, identificador, chave pública, papel, método, recurso,
código e um BLAKE2s dos parâmetros. O titular e a sessão de pessoa entram no
elo: um registro de pessoa não vira um de agente trocando um texto. Os
parâmetros não entram — podem trazer o que um agente escreveu, ou uma prova
administrativa. Cada registro carrega o elo do anterior, e o seu é o
BLAKE2s do anterior com a codificação dele; mudar, tirar ou reordenar um
registro muda todos os elos dali para a frente. Na memória, a cadeia mora
num anel de mil e vinte e quatro registros; o que sai pela ponta deixa o elo
como âncora. No disco, ela vai inteira para o journal, e atravessa o boot
com os mesmos números e elos. `audit.head` dá a cabeça para ancorar fora da
máquina, e a fumaça refaz a cauda no hospedeiro com o mesmo pacote. Uma enxurrada recusada por
taxa grava o primeiro e soma os seguintes, para não empurrar para fora o
que importa.

**Os códigos.** `ALLOW`, `DENY_NOT_AUTHENTICATED`, `DENY_ROLE`,
`DENY_PERMISSION`, `DENY_RESOURCE`, `DENY_POLICY`, `RATE_LIMIT`,
`INVALID_ARGUMENT` e `ERROR`. Uma recusa chega ao agente como o erro
JSON-RPC `-32010` (ou `-32011`, para a taxa), com o código no `data`.

**Taxa.** Cada papel tem um balde — pedidos por segundo e rajada —, por
sessão e por chave: reconectar não enche o balde. O aperto de mão tem o seu
limite por porta, contado antes de qualquer conta: cada aperto custa ao
Duke duas trocas Diffie-Hellman, e quem não tem chave registrada pode
pedi-los à vontade.

**Administrar: prova e papel, os dois.** As operações administrativas —
`agent.register`, `agent.revoke`, `policy.assign`, `policy.write`, e as de
pessoas (ver adiante) — só
existem dentro de `admin.execute`, depois da prova do administrador; e a
prova não basta: o papel do administrador, na política, precisa ter a
permissão. Ele é o **teto** do que o administrador delega:

- registra e atribui só papéis que cabem no dele, e só mexe em agentes cujo
  papel de agora também cabe — não rebaixa nem revoga quem pode mais;
- não muda o papel da sessão de onde pede, nem revoga a chave dela, nem
  registra a própria chave como agente;
- não edita o próprio papel, o de outro administrador, o da sessão de onde
  pede, nem um papel que algum desses inclua.

Revogar derruba na hora as sessões vivas da chave, com uma recusa em claro.
`policy.write` muda uma linha — de papel, de recurso ou de taxa — **em
memória**: o disco é só de leitura. A política nova passa pela mesma
validação do arquivo e entra inteira, numa troca só; vale na decisão
seguinte. Uma linha inválida, ou que tire de quem administra a autoridade
de administrar, é recusada, e a política velha fica.

**Sem política no disco, a embutida.** Se `/etc/duke/politica` falta ou não
se lê, vale a de emergência, embutida no kernel: o mesmo `sistema`, do mesmo
texto da padrão, para a serial e a autoridade local — a autoridade máxima
não encolhe, e não vira curinga —, e o mesmo `administrador`, para quem tem
a prova recuperar a política em memória. Os outros papéis não existem nela:
um agente de papel `operador` ou `observador` é recusado; um de papel
`sistema` continua o que era — ninguém ganha nem perde papel na emergência.

A suíte confere a matriz pelo canal cifrado, linha a linha, e o que a
auditoria gravou de cada uma; a taxa; a revogação derrubando a sessão; cada
regra de quem administra, pela operação de verdade; a cadeia refeita a
partir do que `audit.tail` mostra; um fio e dois programas lançados como
um operador — o que abre `/saudacao.txt` é recusado, o que pede o
pseudo-terminal também —; a pessoa e um processo do sistema recusados
quando a política dá à autoridade local um papel menor; a política de
emergência mantendo o `sistema`; e o aperto auditado e limitado. A fumaça faz o mesmo por fora, com o cliente do `xtask`, e refaz
no hospedeiro a cadeia inteira que o kernel mostrou.

### Pessoas

Uma pessoa não é um agente com outra chave. É uma entidade do registro, com
identidade persistente e credencial própria:

```
pessoa registrada → autenticação → sessão → papel → permissões
```

**Registro ≠ autenticação ≠ autorização.** Estar registrada não abre nada.
Autenticar — provar, num console, que é ela — cria uma **sessão de pessoa**,
e não dá permissão nenhuma: cada pedido da sessão passa pelo mesmo ponto de
decisão dos agentes, com o papel que o registro dá à pessoa agora. Pessoa e
agente estão no mesmo nível, abaixo do `sistema`; a pessoa da imagem de
desenvolvimento é `operador`.

**O registro.** Em `/etc/duke/privado/pessoas`, no diretório reservado, uma
linha por pessoa: `pessoa:<16 hex>`, nome, papel, estado (`ativa` ou
`revogada`) e a credencial. O identificador tem um `:` que nenhum nome de
agente pode ter, e a auditoria grava o tipo de titular no elo: os dois não
se confundem nem em texto nem na cadeia.

**A credencial é um verificador Argon2id**, nunca a senha:
`argon2id:m=4096,t=3,p=1:<sal>:<verificador>`. O custo vai escrito em cada
uma, entre um mínimo (1 MiB, 2 passadas) e um máximo que o kernel aceita
calcular (16 MiB, 10 passadas). A memória de trabalho sai do alocador de
frames — o heap tem 4 MiB — e é zerada antes de voltar. A comparação é em
tempo constante, e um nome desconhecido paga o mesmo Argon2id, contra uma
credencial que não confere com nada: o tempo da recusa não diz se o nome
existe. A forma começa pelo tipo: uma credencial de dispositivo ou de chave
pública entra como outro tipo, sem mudar o que uma pessoa é.

**Sessões.** O número da sessão é sorteado no login; a sessão diz qual
pessoa e em qual console — o físico ou um Terminal. A mesma pessoa em dois
consoles tem duas sessões, com a mesma identidade; duas pessoas no mesmo
console, uma depois da outra, também são duas. Cada console tem um limite de
tentativas (cinco por minuto), conferido antes do cálculo. A resposta a quem
erra não diz se foi o nome ou a senha; a auditoria diz, e grava contra quem
— um nome que não é de ninguém não é gravado, porque pode ser uma senha
digitada no lugar errado. A serial não tem pessoa: é o canal de controle e
emergência.

**Mudar o registro é administrar.** Quatro operações, dentro de
`admin.execute`, com a prova e com a permissão de mesmo nome no papel do
administrador — o mesmo teto dos agentes: ele não alcança uma pessoa de
papel maior que o dele.

- `person.register` registra com o **verificador**, calculado fora: a senha
  nunca viaja nem é guardada; uma senha no lugar da credencial é recusada.
- `person.revoke` revoga a pessoa: ela não entra mais, as sessões dela
  acabam na hora, e o registro fica, com o estado `revogada` — a auditoria de
  ontem continua apontando para alguém. O nome continua dela.
- `credential.rotate` troca a credencial: a mesma pessoa, o mesmo
  identificador; a senha velha não entra mais, e as sessões abertas
  continuam — encerrá-las é a operação seguinte, de propósito separada.
- `session.revoke` acaba uma sessão, sem tocar na pessoa, que pode entrar de
  novo.

O que elas mudam vai para o journal, e sobrevive ao reboot.

**A pessoa de desenvolvimento.** A imagem de desenvolvimento e de testes
traz uma pessoa, `dev`, para quem roda o Duke aqui ter com quem entrar — um
mecanismo explícito de desenvolvimento, e não um login automático: a senha
ainda se digita. O identificador, o sal e a senha saem de 32 bytes sorteados
em `target/chaves/pessoa-dev.chave`, fora do repositório; a senha fica em
`target/chaves/pessoa-dev.senha`, e a imagem tem só o verificador.

A suíte confere a pessoa da imagem e o registro fora do alcance do canal;
duas pessoas no mesmo console e a mesma pessoa em dois, com a auditoria de
cada login e saída; as recusas — senha errada, nome desconhecido, senha
longa demais — e o limite de tentativas de um console sem prender outro; e
os seis estados — registrada, autenticada, sessão ativa, credencial válida,
sessão revogada, pessoa revogada — pelas operações de verdade, com a prova,
sem que um se passe pelo outro.

### Consoles

O console não é a identidade: é onde uma pessoa entra. Há o console
físico — o teclado e a tela da máquina — e um para cada Terminal aberto,
pelo pseudo-terminal dele. Cada um tem a sua linha, o seu modo e a sua
sessão:

```
pessoa → sessão → console → comando → decisão → auditoria
```

A saída de cada console vai para o lugar dele — a do físico para a tela e a
COM1, a de um Terminal para o anel do pseudo-terminal dele —, e o que se
digita num não aparece no outro. O log do kernel continua no console
físico. Fechar o Terminal, ou o processo dele morrer, fecha o console e
acaba a sessão de quem estava nele.

**Antes do login, nada além de entrar.** Um console sem ninguém aceita
`login` e `ajuda` — a ajuda diz só como entrar. Todo o resto — um comando,
conhecido ou não, uma tecla de função, um clique na barra — é
`DENY_NOT_AUTHENTICATED`, gravado com o console. Não há login automático.

**Entrar.** `login` pede o nome e a senha (`login nome` pede só a senha).
A senha não ecoa, não aparece na árvore semântica — o valor da linha
fica vazio —, e o buffer dela é apagado depois da conferência. Enquanto um
console pede senha, nada entra no histórico que `keyboard.read` devolve: o
kernel não sabe para qual janela uma tecla vai virar senha, então não grava
tecla nenhuma. Um agente não edita nem confirma a linha que pede nome ou
senha, e não confirma `login` nem `logout`: o login é de quem está no
teclado.

**Depois do login**, cada comando decide pelo papel da pessoa **agora**. A
sessão que acaba por fora — `session.revoke`, a pessoa revogada — acaba no
console no comando seguinte, que é recusado, e o console volta a pedir o
login. As teclas de função e o clique na barra decidem `ui.act` com a
sessão de quem está no console físico. Um processo lançado pela pessoa
(`user.run`) carrega a autoridade da sessão dela, procurada a cada decisão.

Um agente que confirma uma linha num console continua sendo ele mesmo: age
como a sessão dele, com o papel dele, entrado alguém no console ou não.

A suíte confere, num console sem ninguém, os comandos e a F2 recusados e
gravados, e a ajuda atendida; o login de verdade — o nome, a senha sem eco
na árvore e fora do histórico, o comando gravado como da pessoa, o que o
papel dela não deixa recusado, o `logout`; duas pessoas no mesmo console e
a mesma pessoa no físico e num Terminal ao mesmo tempo, com linhas e
sessões independentes; a sessão revogada voltando ao login; um fio lançado
pela pessoa decidindo pelo papel dela, e por nada depois da revogação; e
os pseudo-terminais — um console por instância, a saída de um que não vai
para o outro, a sessão que acaba quando o Terminal fecha ou morre. A fumaça
entra pelo teclado da máquina com a pessoa da imagem: no Terminal, depois
de ver o comando antes do login recusado e gravado, e com a senha fora do
histórico; e no console físico, depois de um clique fora das janelas —
duas sessões, a mesma identidade.

### Coordenação

Pessoas e agentes dividem a mesma tela, e a mesma tela não aceita dois
donos ao mesmo tempo. Cada recurso compartilhado tem uma **versão**, que só
sobe com uma mudança que valeu, e no máximo um **arrendamento**: quem o tem,
desde quando e até quando. Hoje são recursos a linha de comando do console
físico e cada campo de texto de uma janela.

**Foco ≠ autoridade ≠ arrendamento.** Ter `ui.act` no papel deixa pedir; não
dá a posse de nada. Ter o foco diz para onde a tecla vai; não diz que ela
pode mudar o campo. E o arrendamento diz quem edita agora; não substitui a
decisão. Um pedido passa pelos três, nessa ordem: o ponto de decisão, a
versão, o arrendamento.

**Versão.** `ui.act` aceita `expect_version`: se a versão não é mais a que
quem pede leu, a resposta é `CONFLICT` (JSON-RPC `-32012`), nada muda e a
recusa vai para a auditoria. A resposta de uma mudança traz a versão nova;
`ui.tree` mostra a versão e o arrendamento de cada campo.

**Arrendamento.** `ui.claim` arrenda um campo livre por um prazo (de 1 a
300 segundos; 30 sem `ttl_ms`), ligado à sessão e à identidade de quem
pede; `ui.release` o solta. Editar um campo livre o arrenda por 60 segundos,
e editar de novo renova; confirmar exige o arrendamento — sem ele,
`DENY_LEASE` — e o solta depois. No campo de outro, editar ou arrendar é
`CONFLICT`, sem tirar ninguém: não há preempção. O arrendamento acaba
quando vence, quando a sessão acaba — o `logout`, a porta que cai —, quando
a chave ou a pessoa é revogada, e quando um administrador o revoga.

**A pessoa pelo mesmo caminho.** A primeira tecla de uma pessoa na linha
livre a arrenda para a sessão dela, uma vez na auditoria, e cada tecla
renova; uma tecla na linha de outro é `CONFLICT`, gravada, e não muda
nada. Numa janela, o campo é o que a descrição dela declara na linha
`foco <id>` — o toolkit a escreve —, e o kernel confere o arrendamento
desse campo antes de entregar a tecla: dois agentes trabalham em campos
diferentes da mesma janela, e a pessoa num terceiro. Pessoa e agente estão
no mesmo nível: a mesma decisão, a mesma auditoria, os mesmos
arrendamentos, nenhuma prioridade de um sobre o outro.

**O sistema não passa por cima.** O papel `sistema` é a autoridade máxima,
e um arrendamento de outro vale contra ele como contra qualquer um. Tirar
um arrendamento é uma operação administrativa explícita — `lease.revoke`,
dentro de `admin.execute`, com a prova e a permissão de mesmo nome —,
gravada em nome de quem o tinha e de quem o tirou.

**A auditoria grava** cada arrendamento tomado, solto, recusado, vencido e
invalidado, cada `CONFLICT` de versão, cada confirmação sem arrendamento, e
a mudança que valeu.

**O teclado tem um cursor por leitor.** `keyboard.read` lê do histórico —
as últimas 256 teclas — a partir do cursor de quem pede: dois agentes lendo
recebem as mesmas teclas, sem roubar um do outro, e quem ficou para trás
além do anel recebe `missed`, quantas perdeu.

**A cota de processos.** Cada papel tem um teto de processos vivos — a
linha `processos <papel> <n>`, de 1 a 64, 4 sem ela; na imagem, 32 para o
`sistema`, 8 para o operador e o administrador, 2 para o observador —,
contado por titular: uma sessão de agente, uma de pessoa, o sistema. O
processo além da cota — lançado ou bifurcado — não nasce, e a recusa vai
para a auditoria.

O `cargo xtask invariantes` confere que só o canal chama
`ui::agir_com_versao`, que só a administração revoga um arrendamento, e que
a linha do interpretador só muda pela árvore. A suíte confere os cenários
de concorrência entre dois agentes — duas leituras e uma mudança, exclusivo
até soltar, revogado, vencido, confirmação com a versão velha —; pessoa
contra agente, agente contra pessoa, duas pessoas, o `logout` e o
`lease.revoke` com e sem a prova; os campos de uma janela, com o foco
declarado; dois leitores do teclado; e a cota de processos, lançada e
bifurcada. A tabela do pacote `politica` confere, no hospedeiro, que nunca
há dois arrendamentos num recurso, que nenhum sobrevive à revogação, e que
a versão só sobe com uma mudança que valeu.

### Mensagens

Uma mensagem entre titulares — agente, pessoa, serial, administrador — é um
**recurso do sistema**, e não um canal privilegiado. Mandar, ler, confirmar,
cancelar e consultar são comandos do registro, e passam por
`autorizacao::autorizar` → `decidir` como qualquer outro.

**Quem pode.** `message.send`, `message.read`, `message.purge` e
`message.purge_mailbox` são permissões sensíveis: não atravessam
`@inclusão`, cada papel que as tem as escreve. `message.read` é sobre as próprias mensagens — ler e confirmar
a caixa, consultar o estado, cancelar a que mandou e ninguém leu. O recurso
de `message.send` é o **papel do destinatário** —
`papel:<nome>` —, e o alcance de cada papel é enumerado numa linha
`recurso`, sem curinga. Na imagem: o `sistema` alcança observador, operador,
sistema e administrador; o `operador`, operador e sistema; o `observador`
só lê; o `administrador`, o teto do que delega — operador, sistema e ele
mesmo. **Só o sistema e o próprio administrador alcançam o
administrador.** O alcance a ele está no teto, para que o do sistema e o do
administrador sejam representáveis; e ainda assim nenhum `policy.write` o
dá a outro papel — a mudança que daria a um papel que não é o local o
alcance ao papel do administrador é recusada, e o observador nem chega a
mandar. O alcance novo, de resto, tem de caber no teto.

É um **invariante do boot**, e não só uma escolha da imagem padrão. O
kernel o confere ao ler a política do disco: uma política que dê o alcance
ao administrador a outro papel não vigora — vale a de emergência, como
para uma política malformada, e a auditoria grava o motivo. Os papéis
protegidos são o `administrador` e os das chaves do registro de
administradores. O `xtask` confere o mesmo antes de pôr a política na
imagem, e uma imagem que o viole nem é gerada. O `sistema` não tem
passe: lê só a própria caixa, e decide pelo alcance que enumera.

O alcance ao `administrador` é o de um destino: uma sessão não exerce o
papel `administrador` — é um teto, e não uma posse; ver
[O teto não é posse](#o-teto-não-é-posse).

### O teto não é posse

O papel `administrador`, e o de cada credencial do registro de
administradores, é um **teto**: o conjunto do que um administrador pode
delegar (`Politica::cabe_em`). Ele existe na política para que a delegação
seja representável — o operador tem de caber nele para ser atribuível,
e por isso o teto tem, por exemplo, o alcance de `/armazem/compartilhado`.
Ter o teto não é exercê-lo. A cadeia é

```text
teto → permissões possíveis → política → gate → operação
```

e o teto só entra no primeiro elo:

- **nenhuma sessão o exerce.** O gate recusa, com `DENY_ROLE`, toda decisão
  de uma sessão — de agente ou de pessoa — cujo papel é um teto, antes de
  olhar a permissão; o mesmo para os processos que ela lança e para o
  `ui.act`;
- **ninguém o atribui.** `agent.register`, `policy.assign` e
  `person.register` recusam um papel de teto, com a prova e tudo;
- **nem a serial nem a autoridade local o têm.** Uma política em que
  `serial` ou `local` é um papel de teto não vigora — o boot usa a de
  emergência e audita o motivo —, e o `xtask` não gera uma imagem assim,
  nem uma em que um agente da imagem tenha o papel `administrador`.

O que um administrador faz, faz pela prova da credencial, nas operações
administrativas — e nada além delas.

**Quem manda é a sessão.** O remetente nunca vem dos parâmetros: o kernel o
deriva da sessão autenticada — a chave do aperto, a sessão de pessoa, a
serial. O comando não declara `from`, a validação recusa o campo, e o
`xtask invariantes` confere que nenhuma função de mensagem o lê. O
destinatário é resolvido **na decisão** — o papel dele é o recurso —, e o
handler recebe pela licença o destinatário decidido, sem resolvê-lo de novo.
A pessoa manda pelo interpretador, com o mesmo comando e a mesma decisão.

**A chave do administrador, só com prova.** A chave que assina provas
nunca abre sessão. Ela manda, lê e confirma por `admin.execute` —
`message.send`, `message.read`, `message.ack` —, com a prova, decidido
pelo papel dela, com o mesmo alcance e as mesmas cotas. Como o papel dela é
o `administrador`, o sistema e o administrador a alcançam (`admin:<nome>`);
a caixa dela se lê só pela prova. `message.purge` tira a mensagem de outro,
também só com prova.

**Esvaziar uma caixa inteira** é outra operação, com outra permissão:
`message.purge_mailbox`, `{"mailbox": endereço}` — o endereço de um envio:
`serial`, `pessoa:<id>`, `admin:<nome>` ou o nome de um agente. É
destrutiva de outro tamanho — tudo o que alguém ia ler, de uma vez —, e
quem pode tirar uma mensagem não esvazia a caixa por isso: a permissão é
própria, sensível e administrativa, e o papel que a tem a escreve. O
caminho é o de toda operação administrativa — credencial, desafio, prova,
a decisão pelo papel do administrador, e só então a caixa —, sem atalho:
não é comando de sessão, e nenhuma recusa toca a caixa. As vencidas saem
como vencidas, antes. A auditoria grava cada mensagem tirada com o id, em
nome do administrador, ligada ao desafio da operação; e o desfecho, com a
caixa e quantas saíram, a permissão que valeu e o mesmo desafio. Um
titular revogado não tem caixa: a revogação já anulou o que ele ia
receber.

**Estados.** Uma mensagem aceita é `pending`; a primeira leitura a faz
`delivered`; o `ack` de quem recebeu a tira (`acked`). Ler **não consome**:
uma resposta perdida se relê, com o mesmo id — entrega pelo menos uma vez,
com id estável para descartar a duplicata. Quem mandou cancela só antes da
primeira leitura (`canceled`). Saem também por revogação (`voided`), pelo
prazo (`expired`) e pelo `message.purge` (`purged`). Cada transição tem
versão, e `expect_version` diferente é `CONFLICT`. Ao sair, o corpo é
zerado; fica uma lápide curta para o `message.status`, e a auditoria. O
prazo vence na consulta: uma mensagem cujo prazo passou é `expired` no
`message.status` na hora, e não quando o coletor passar.

**O corpo sai da memória zerado** — o guardado na caixa e cada cópia
dele: a que a leitura devolve, e o texto da resposta que a leva até o fio,
montado num texto que zera cada bloco que larga ao crescer (um `String`
comum devolveria o bloco antigo ao alocador com o corpo dentro). Zera o
bloco inteiro, a capacidade e não só o comprimento, com escrita volátil
— ver `politica::sigiloso`. Os testes no hospedeiro conferem com um
alocador que olha cada bloco ao ser devolvido.

**Replay e duplicata.** O transporte cifrado já não deixa um quadro se
repetir. Acima dele, cada pedido de `message.send` traz um `nonce` que só
cresce na sessão: o mesmo nonce com o mesmo conteúdo é o reenvio — o mesmo
id, nada criado —; um nonce velho, ou o mesmo com outro conteúdo, é
`DENY_REPLAY`. Uma sessão nova conta do zero.

**Ordem e cotas.** A caixa se lê em ordem de aceitação, com cursor
`after`. Corpo até 512 bytes; prazo de 10 minutos, até 60. As cotas são da
política, por papel — `mensagens <papel> <por remetente> <por caixa>`: a de
remetente é a do papel de quem manda, somando todas as caixas; a de caixa,
a do papel de quem recebe. De 1 até os tetos da tabela, 32 e 64; sem a
linha, 8 e 32. Uma linha fora da faixa recusa a política inteira — no boot
vale a de emergência, e o `xtask` nem gera a imagem —, e o `policy.write`
as muda dentro dela, sem tocar num papel protegido. O total, 128 vivas, é
da imagem: é a memória que as mensagens podem ocupar, e vale por cima de
qualquer cota. Mandar vence os prazos antes de contar: uma vencida não
ocupa vaga. A recusa não gasta id nem nonce.

**Revogação.** A chave ou a pessoa revogada tem anuladas, na hora, as
mensagens vivas que mandou e as que ia receber — cada anulação gravada. A
mesma chave de volta ao registro encontra a caixa vazia. O fim de uma
sessão não anula nada: a caixa é da identidade. Um envio, uma leitura, um
`ack` ou um cancelamento que o gate decidiu antes da revogação é decidido
de novo quando muda a tabela, com a ordem das gravações na mão — a mesma
da revogação —: ou ele vem antes dela inteiro, e é anulado com o resto, ou
a vê e é recusado. Nenhuma mensagem de um titular revogado nasce depois
das anulações.

**Destinatário inexistente**, revogado ou sem papel: `DENY_RESOURCE`, a
mesma resposta de um destinatário fora do alcance; a auditoria grava o
motivo exato. A permissão vem antes: quem não pode mandar ouve
`DENY_PERMISSION`, e não descobre quem existe. Um id alheio responde como
um que não existe.

**Auditoria.** Cada decisão, cada recusa e cada transição — aceita,
reenvio, entregue, confirmada, cancelada, anulada, vencida, tirada —, com
o id e a versão. Nunca o corpo: o kernel não o interpreta, e a auditoria
guarda o resumo dos parâmetros.

As mensagens moram em memória: o disco é só leitura, e um boot as perde. A
época no id deixa isso explícito — um id de outro boot não é de mensagem
nenhuma.

A suíte confere, pelo canal de verdade, cada categoria que as mutações
procuram: o remetente da sessão e o `from` recusado; o observador, o
alcance do operador, o administrador alcançado só pelo sistema e por ele
mesmo, e o titular com papel administrador que recebe; o reenvio e o replay;
a anulação pela revogação, de chave e de pessoa; o destinatário
inexistente e revogado; ler sem consumir, o `ack` e o cancelamento; a
ordem; as cotas, as da política e o prazo; o vazamento entre sessões; o
administrador por prova; e esvaziar a caixa — sem a permissão própria, com a credencial
errada, com a prova de outra caixa ou de outra operação, a prova repetida,
o alvo inexistente e o revogado, e o que a auditoria grava. A tabela pura tem os mesmos testes no hospedeiro, com as
cotas de caixa e de total.

### Quem está agindo

A pessoa diante da tela precisa saber que não está sozinha. A barra
superior mostra, o tempo todo, quantos agentes estão conectados e quem
agiu por último:

```
Duke  [Limpar (F1)] [Sobre (F2)] [Terminal (F3)]  agentes: 2 · último: teste-1 (operador)   ligado 0:04:12
```

**A conta é feita na decisão.** `autorizacao` registra quem passou —
depois do `ALLOW`, e só dele — e mais ninguém registra: o `xtask
invariantes` confere. Não há como agir sem passar por lá, então não há como
agir sem aparecer. Uma recusa não conta: quem foi recusado não agiu.

**Agir é mudar alguma coisa.** O "último" é quem exerceu por último uma
permissão que muda o estado — `Permissao::muda_estado`, um `match`
exaustivo no vocabulário, testado no hospedeiro: uma permissão nova não
compila sem alguém dizer de que lado fica. Ler a árvore, o log ou a caixa
não é agir; `message.ack` e `message.cancel` vão com `message.read`, e
mexem só nas mensagens do próprio titular. A pessoa entra pelo mesmo
critério — o comando no interpretador, a tecla de função, o clique num
botão da barra — como `pessoa:<nome>`; o administrador pela prova, como
`admin:<nome>`. Um nome de agente não tem `:`, e por isso não se passa por
nenhum dos dois. A tecla digitada numa linha não conta: quem digita está
diante da tela, e o arrendamento da linha já diz de quem ela é. O processo
do sistema não aparece: age por quem o lançou, que apareceu ao lançá-lo.

**Os agentes se veem.** `agent.list` — com `agent.read`, a mesma permissão
de `agent.sessions` — lista cada agente conectado: a porta, o nome, o papel
de agora, há quanto tempo está conectado, quantos arrendamentos tem, o
**último comando** que passou pela decisão (leitura ou não) e a **última
ação**, cada um com há quanto tempo. E quem agiu por último na máquina, e o
texto da barra. Nunca os parâmetros de ninguém, e nada das caixas de
mensagem dos outros — quantas mensagens um tem diria quem fala com quem.
Uma sessão nova não herda o que a anterior fez, nem com a mesma chave; uma
chave revogada sai da conta na hora, antes de a porta cair.

**Na árvore**, o indicador é um `static_text` da barra (id 10), com o texto
que está desenhado — o agente lê o que a pessoa vê. Um texto que não cabe
é cortado com reticências; o `agent.list` tem o resto.

**Ninguém cobre a barra.** Um indicador que um processo pudesse cobrir não
valeria nada: uma janela por cima desenharia uma barra falsa, e receberia o
clique de quem acreditasse nela. Por isso, três defesas, cada uma conferida
sozinha:

- a barra fica **fixa no topo** das camadas — só o cursor, fixado depois,
  fica acima; uma janela trazida para a frente entra abaixo dela;
- nenhuma superfície de processo **ocupa a faixa**: ela nasce abaixo da
  barra, e um `MOVER` para cima dela a para na borda —
  `superficie::PRIMEIRA_LINHA` na ABI, conferida contra a altura da barra
  ao compilar. O pedido é aceito, e o `y` não: um programa que põe a janela
  em `(0, 0)` continua funcionando. O runtime de janelas faz a mesma conta,
  para o ponteiro, que chega em coordenadas da tela, cair no lugar certo;
- o **ponteiro na faixa é da barra**, mesmo que uma janela chegasse lá.

A suíte roda um programa hostil, `cobrir`, que pinta uma barra falsa e
tenta pô-la sobre a do kernel — sem mover, e pedindo `y = -40`. Confere
onde as duas pararam, que a barra continua acima delas na pilha, que a
faixa mostra a barra; e, levando uma à força ao topo, que a barra ainda
aparece por cima e o ponteiro ali ainda não vai à janela.

### Persistência

O que muda o estado de autoridade em tempo de execução sobrevive ao reboot:
`agent.register`, `agent.revoke`, `policy.assign`, `policy.write`,
`person.register`, `person.revoke`, `credential.rotate`, `session.revoke` e
`admin.revoke`. Cada uma vira um registro num journal na partição de estado
do disco — cifrado, encadeado ao anterior e **ancorado** num contador
monotônico do TPM —, gravado e descarregado **antes** de a resposta sair. O
registro guarda o resultado (o agente, a política inteira, a lápide), e não
o pedido; o boot o reaplica por cima da imagem, antes de abrir as portas.

- **A lápide vence a imagem.** Uma credencial administrativa revogada
  continua revogada em todo boot, mesmo com a imagem trazendo a chave de
  volta.
- **Um disco antigo não passa.** O contador do TPM sabe quantos registros
  têm de existir. Um disco devolvido a uma cópia anterior, um registro
  confirmado estragado, um TPM limpo: o journal é recusado.
- **Sem persistência confiável, nenhuma credencial administrativa é
  aceita** — nem para o que não muda autoridade: sem o journal confirmado,
  o kernel não sabe quais foram revogadas. Não há exceção para o `sistema`
  nem para a serial. Numa máquina sem TPM e sem journal, os agentes e as
  pessoas continuam sendo atendidos.
- **Com o journal recusado, nenhuma credencial vale.** Um disco antigo ou
  estragado pode ter perdido a revogação de qualquer agente ou pessoa: só
  a serial e o `sistema`, que não têm credencial, continuam.
- **As mensagens também sobrevivem.** Cada mudança de uma mensagem — a
  aceita, a entregue, a confirmada, a vencida — vai para o journal antes
  da resposta, que diz `"durable": true`. Sem persistência, a mensagem vai
  só em memória, e a resposta diz `"durable": false` e por quê, em
  `memory_only`. Os prazos correm no tempo lógico, e os ids continuam os
  mesmos de um boot para o outro.
- **A auditoria também.** Cada registro do journal leva os registros da
  cadeia da auditoria que ainda não estão no disco, e a decisão que
  autorizou uma mudança de autoridade vai no mesmo registro que a mudança:
  as duas entram juntas, ou nenhuma. O que não muda estado — uma leitura,
  uma recusa — vai no próximo registro, ou num só de auditoria que o
  coletor grava a cada dois segundos — e que **não avança o contador do
  TPM**: o contador é a monotonicidade do estado de segurança, e um
  registro só de auditoria não muda estado. Avançam a abertura, cada boot,
  cada operação de autoridade, cada mudança de mensagem e o fecho de cada
  compactação. O preço: os registros só de auditoria depois do último que
  avançou não têm a proteção do contador, e um disco devolvido a antes
  deles passa — sem que nenhum estado protegido volte: um registro só de
  auditoria só leva auditoria (o journal não monta nem lê outro), e
  nenhuma decisão lê a cadeia da auditoria — `cargo xtask invariantes`
  confere. `audit.tail` diz `durable` em cada
  registro; o boot refaz a cadeia do journal e continua dela. Com o journal
  recusado, a cadeia recomeça só em memória, e a recusa é o primeiro
  registro dela.
- **O tempo lógico não volta.** O RTC, com um piso que é o tempo do último
  registro gravado.
- **O journal se compacta sem esquecer.** A partição tem duas regiões, e o
  journal vive numa. Passados três quartos dela, o boot ou o coletor — só
  num ponto seguro, sem gravação pendente — escrevem na outra uma base: a
  história inteira da autoridade, com cada mudança ao lado da decisão que
  a autorizou, as mensagens vivas e as lápides, e a cadeia da auditoria
  continuando. A base só vale com o fecho no disco e um avanço do contador
  do TPM: uma queda em qualquer ponto deixa valendo a região antiga ou a
  nova, inteira, e a antiga fica recusada assim que o contador anda. Uma
  revogação nunca sai da base. Quem compacta é quem toma a ordem das
  gravações num ponto seguro — o coletor, e também qualquer operação que a
  tome de fora: a ordem não tem fila, e o coletor podia perdê-la para quem
  grava sem parar até a região encher (`compactacao e a regiao cheia`
  confere os dois, cada um sozinho). Uma operação que não cabe na região
  cheia — a base que não cabe na outra — falha fechada, e a persistência
  fica indisponível até o boot compactar.
- **A senha do contador não passa pelo barramento.** Todo comando ao
  contador vai por uma sessão HMAC salgada com a chave de endosso (EK) do
  TPM: o comando prova a senha sem levá-la, a resposta tem de provar que
  veio do TPM daquela sessão, e a senha nova, na criação, vai cifrada.
  Uma resposta adulterada, repetida de antes ou forjada não vira valor.
  Não há autoridade nova: a senha é a mesma, derivada da chave do Duke, e
  o contador continua só um contador.
- **O TPM é o mesmo.** A EK fica fixada no journal — na abertura, em cada
  boot e no fecho de cada base. Outro TPM, ou outro chip respondendo no
  lugar deste, é recusado antes de qualquer comando ao contador. Isto diz
  que o TPM é o mesmo do primeiro boot, e não que ele é genuíno: a EK não
  é conferida contra o certificado do fabricante, e a primeira confiança
  depende de o primeiro boot acontecer com o barramento intacto.
- **A senha nova vai cifrada, e autenticada.** O AES-128-CFB do parâmetro
  é feito antes do `cpHash`, e o HMAC da sessão cobre o texto cifrado
  inteiro: mexido no caminho, o TPM o recusa antes de decifrar.
- **Sem o TPM, um journal não se confirma.** Um disco com journal numa
  máquina sem TPM — o TPM tirado, com uma cópia antiga do disco — é
  recusado, e não só indisponível: nada confirmaria que o disco é o
  atual. Qualquer falha do TPM no boot também é recusa.
- **Um avanço que não se sabe se aconteceu** — a resposta perdida ou
  adulterada — é decidido por uma leitura autenticada, por uma sessão
  nova: andou, e a operação vale; não andou, e o registro é desfeito no
  disco e a operação falha; não se sabe, e a persistência fica
  indisponível até o boot seguinte decidir pela âncora.

`system.info` diz o estado (`persistence`), a geração administrativa, a
âncora, a região, quanto dela está usado, quantas compactações houve, a
interface do TPM (`tpm_interface`: TIS ou CRB) e o começo da EK
(`tpm_ek`). A bancada `cargo xtask persistencia` sobe a mesma máquina várias
vezes, corta a energia, devolve fotografias antigas do disco, estraga o
journal, limpa o TPM, devolve o TPM a um estado anterior, tira o TPM da
máquina, avança o contador por fora, troca a interface do TPM e volta o
relógio — e, numa compilação própria do kernel, derruba a energia em cada
fronteira entre o disco e o TPM: antes e depois da escrita, da descarga,
do incremento do contador e da leitura de volta — numa operação, numa
mensagem e num registro só de auditoria —, entre a chave do TPM e o
contador no boot, no meio da criação da âncora, e em cada fronteira de uma
compactação; e enche a região até a operação que não cabe. O desenho, os requisitos e o que
falta estão em [`docs/PERSISTENCIA.md`](docs/PERSISTENCIA.md).

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
info console  executado: system.uptime (agente 0)
info console  executado: agent.ping (pessoa)
```

É o começo do que a fase 12 chama de auditoria: se um agente pode fazer tudo
que uma pessoa faz, o registro precisa dizer qual dos dois fez.

**O primeiro botão.** A barra superior tem o **Limpar**, que aceita `press` —
ver a seção da barra, abaixo. As janelas também aparecem na árvore, como
`window`, com os widgets delas: o servidor de janelas e o Terminal as
montam com o toolkit, e a descrição é gerada deles — ver o toolkit, em
Userspace.

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

**O que veio depois.** Quem crie janelas em produção: o servidor de
janelas e o Terminal, com o roteamento da entrada de cada superfície ao
processo dono dela — ver Userspace.

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
    Duke :: agent-native :: x86_64 :: fase 6
  =============================================
  [    0]     0ms info boot  Duke iniciado em x86_64, fase 6

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

- [x] **Fase 6 — Vários núcleos.** Primeiro, e não no meio: fazer SMP depois
      da pilha gráfica significaria reescrever o travamento dela inteiro.
      Partida dos núcleos pela MADT (INIT-SIPI-SIPI) e pela árvore de
      dispositivos (PSCI), dados por CPU, timers por núcleo, um escalonador
      com posse do fio por núcleo e afinidade; avisos entre núcleos para
      acordar, derrubar traduções (`com_descritor_da_folha` passou a avisar os
      outros núcleos ela mesma) e parar todos no caminho fatal; travas justas
      por senha. `threads.list` diz em que núcleo cada fio está. E a
      exigência que não se negociava: com **um** núcleo travado para sempre,
      o canal continua respondendo — provado pela fumaça nas duas
      arquiteturas. O estado global foi auditado com vários núcleos, e o que
      só aparece com eles está em [Vários núcleos](#vários-núcleos).
      **Fase 6 completa.**
- [x] **Fase 7 — Interface nativa.** Os programas do Duke são do Duke: não
      há ABI do Linux, nem camada que imite outro sistema por baixo. Um
      programa fala a língua do sistema — o registro de comandos, o mesmo
      que a pessoa fala pelo interpretador e o agente pelo canal —, pelo
      mesmo gate, com a autoridade de quem o lançou, na mesma auditoria. As
      chamadas de mecanismo (memória, processo, descritores, eventos,
      superfícies) ficam pequenas e binárias; o resto do sistema —
      mensagens, arrendamentos, auditoria, árvore semântica, estado — chega
      ao programa por `pedir` e `resposta`, atendido pela tarefa `programas`
      do executor. Antes de abrir o registro, o comando passou a saber quem
      o pediu em qualquer fio (a sessão global saiu, a taxa é do principal,
      a prova administrativa é do canal). E cada programa declara, numa nota
      do próprio executável, o que pretende fazer: a permissão efetiva é a
      do papel de quem o lançou **interseção** a do manifesto — um programa
      nunca tem mais que quem o lançou, e pode ter menos; sem manifesto,
      nada. Ver [Interface nativa](#interface-nativa) e
      [`docs/INTERFACE.md`](docs/INTERFACE.md). **Fase 7 completa.**
- [x] **Fase 8 — Armazenamento nativo.** Um armazém log-estruturado
      próprio, com journaling e `fsync` honesto — o journal da persistência,
      cifrado, encadeado e ancorado no TPM, compactado em duas regiões —,
      montado em `/armazem` e exposto como capacidades do registro
      (`fs.write`, `fs.append`, `fs.delete`, `fs.claim`, `fs.release`,
      `fs.stat`), sob `fs.write` e o alcance de caminho da política, com
      versão por objeto, arrendamento para quem edita, e cada gravação
      confirmada só depois de escrita, descarregada e ancorada. Sem
      autorização paralela: o mesmo `pedir`, o mesmo gate, a mesma cadeia da
      auditoria — e a decisão no mesmo registro do journal que a mudança. A
      capacidade nova é concedida por linhas escritas da política, a
      ninguém por código. O Btrfs fica somente leitura, para imagens:
      escrever nele é uma B-tree com cópia na escrita, somas de verificação
      e transações — dos sistemas de arquivos mais difíceis que existem, por
      um ganho que um log-estruturado entrega por um décimo do trabalho. O
      armazém tem tetos (16 KiB por arquivo, 256 arquivos, 512 KiB): é para
      os dados de programas e agentes, e divide a partição com o estado de
      autoridade. Ver [Armazenamento nativo](#armazenamento-nativo) e
      [`docs/ARMAZENAMENTO.md`](docs/ARMAZENAMENTO.md). **Fase 8 completa.**
- [ ] **Fase 9 — Rede nativa.** IP, UDP, TCP, DHCP e TLS. Com `smoltcp` em
      vez de escrever a pilha: escrever TCP do zero é um a dois anos-pessoa
      e não diferencia o Duke em nada. O que diferencia é o lado de cima: um
      programa não abre um socket do Unix, pede uma conexão ao registro,
      com o destino como recurso da política, e cada conexão vai para a
      auditoria. O canal do agente por TCP vira mais um transporte de
      sessão. O ARP que existe hoje era a prova de ponta a ponta mais
      barata possível, e cumpriu o papel dela.
- [x] **Fase 10 — GPU, composição e a árvore semântica.** Começou antes da
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
      de usuário em Rust, compilados à parte, com monte e `mapear`; a leitura
      que bloqueia e o canal de eventos; as superfícies do compositor com os
      pixels no processo; e o servidor, lançado no boot, com moldura, foco,
      arrasto, ordem e fechar, e o ponteiro e o teclado roteados a ele pelo
      kernel; e a árvore semântica atravessando a fronteira — o servidor
      descreve cada janela, e o `press` do agente chega a ele pelo mesmo
      caminho do clique; e a primeira janela, o "Sobre o Duke", pelo botão
      **Sobre** da barra, pela F2 ou pelo agente — aberta, arrastada e
      fechada pelo mouse de verdade na fumaça; e a tipografia — uma fonte
      num lugar só, para o kernel e os programas, com as letras do português,
      negrito e um tamanho de título. O console como janela é a fase 11 —
      e ela começou por aí.
      E aqui a inversão do projeto encontra a interface gráfica. O servidor de
      janelas publica uma **árvore semântica** — que janelas existem, que
      controles, o que cada um faz — e os pixels são a renderização dela, do
      mesmo jeito que o texto do console é a renderização de um registro
      tipado. O agente opera por essa árvore, e não por captura de tela: nada
      de adivinhar botão por pixel, que é como a automação de interface
      funciona em toda parte hoje e é por isso que ela quebra a cada tema
      novo. Acessibilidade e teste automatizado de interface caem no colo,
      porque são a mesma árvore lida por outro consumidor.
- [x] **Fase 11 — Toolkit, linguagem visual e o Terminal.** O "jeito" do
      sistema mora aqui, não no kernel. Cada widget declara o que é e o que
      faz, e a árvore semântica da fase 10 é **gerada** disso em vez de
      escrita à mão — senão ela vira a segunda superfície que este projeto
      existe para não ter. E o console vira uma janela: o **Terminal**, um
      programa do servidor de janelas, com o interpretador do outro lado de
      um canal — em vez da camada de baixo do compositor, desenhada pelo
      kernel. É a primeira janela de trabalho, e a que tira do kernel a
      última coisa que ele desenha para uma pessoa além da barra e do
      cursor. Começou pelo Terminal, que já existe: o pseudo-terminal no
      kernel, a entrada de cada janela indo ao processo dono dela, a janela
      do runtime compartilhada com o servidor, e o programa, lançado no
      boot e pelo botão da barra. O console do kernel ficou como fundo e
      reserva. Depois, o toolkit: a linguagem visual num pacote dos dois
      lados da fronteira, os widgets que se desenham e se descrevem do mesmo
      estado, o campo de texto com o caminho do agente até ele, e as janelas
      do Duke refeitas com eles — nenhuma descrita à mão, e uma conferência
      que impede a próxima de ser.
- [ ] **Fase 12 — Consentimento e auditoria.** Se um agente pode fazer tudo
      que uma pessoa faz, o modelo de permissão precisa ser **mais** forte que
      o de um desktop comum, e não mais fraco. Três coisas: quem pediu — a
      pessoa na frente da máquina ou o agente pelo canal —, o que foi feito, e
      um registro que a pessoa possa ler depois e desfazer. Junto com o resto
      do que um desktop precisa: assinatura de código e cadeia de boot
      confiável. O sandbox por aplicativo é o manifesto da fase 7.
- [ ] **Fase 13 — Hardware real e distribuição.** Instalador, atualização A/B
      com rollback, imagens assinadas, ACPI de verdade, NVMe, placa de rede
      real, watchdog. É onde projetos assim costumam morrer, e é por isso que
      vem por último: até aqui o emulador é hardware suficiente.

## Licença

MIT OU Apache-2.0, a critério de quem usa.

Partes da pilha gráfica são porte de código do Redox OS, sob MIT, com o
aviso de copyright deles — ver [`THIRD_PARTY.md`](THIRD_PARTY.md).
